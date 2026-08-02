//! The **Merge agent** — incremental, LLM-driven deduplication of reviewed
//! findings into canonical audit findings.
//!
//! The `review-findings` workflow drains reviewed findings one at a time;
//! for each, this agent compares it against the canonicals accumulated so
//! far and decides "fold into canonical N" or "start a new canonical". The
//! decision is persisted as a `finding_merge` edge (and, on a new cluster, a
//! `report_finding` row) by [`RepoDatabase::commit_finding_merge`]. There is
//! no embedding / vector step — the agent reads the normalized
//! `root_cause` / `description` (and may confirm against source) and judges
//! sameness directly, mirroring the historical-KG `FindingMerger`.
//!
//! Reuses the reflection [`drive_agent_loop`] driver, the shared
//! `ProjectIndex` tools, and the `AttemptHandle` / `emit_*` pattern.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use color_eyre::eyre::{Result, WrapErr};
use knowdit_repo_model::{LoadedReportFinding, RepoDatabase, ReviewedFinding};
use llmy::agent::tool::ToolBox;
use llmy::agent::tools::files::{FindFileTool, GrepDirectoryTool, ListDirectoryTool, ReadFileTool};
use llmy::client::client::LLM;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::reflect::agent_loop::{AttemptHandle, GraderOptions, drive_agent_loop};
use crate::spec::{
    LookupCallGraphTool, LookupStateVariableXrefsTool, ProjectIndex, ReadContractSourceTool,
    ReadFunctionSourceTool,
};

/// One existing canonical as the Merge agent sees it. The `report_finding_id`
/// is the value the agent returns when it decides to fold the new finding in.
#[derive(Debug, Clone, Serialize)]
pub struct MergeCandidate {
    pub report_finding_id: i32,
    pub title: String,
    pub severity: String,
    pub root_cause: String,
    pub description: String,
    /// Non-authoritative hint only (may be hallucinated); the agent judges on
    /// `root_cause` / `description`.
    pub primary_contract: String,
    pub primary_function: String,
}

impl From<&LoadedReportFinding> for MergeCandidate {
    fn from(c: &LoadedReportFinding) -> Self {
        Self {
            report_finding_id: c.id,
            title: c.title.clone(),
            severity: c.severity.as_str().to_string(),
            root_cause: c.root_cause.clone(),
            description: c.description.clone(),
            primary_contract: c.primary_contract.clone(),
            primary_function: c.primary_function.clone(),
        }
    }
}

/// The new reviewed finding being placed, plus the canonicals it is compared
/// against (one token-budgeted chunk of them). Serialized verbatim as the
/// agent's user prompt.
#[derive(Debug, Clone, Serialize)]
pub struct MergeInput {
    pub reflection_id: i32,
    pub title: String,
    pub severity: String,
    pub root_cause: String,
    pub description: String,
    pub location: String,
    pub primary_contract: String,
    pub primary_function: String,
    /// Canonicals to compare against. Empty for the very first finding; one
    /// chunk's worth when the full set is split across the context window.
    pub candidates: Vec<MergeCandidate>,
}

impl MergeInput {
    /// Frame one reviewed finding against the current canonical set.
    pub fn new(finding: &ReviewedFinding, candidates: &[LoadedReportFinding]) -> Self {
        Self {
            reflection_id: finding.reflection_id,
            title: finding.title.clone(),
            severity: finding.severity.as_str().to_string(),
            root_cause: finding.root_cause.clone(),
            description: finding.description.clone(),
            location: finding.location.clone(),
            primary_contract: finding.primary_contract.clone(),
            primary_function: finding.primary_function.clone(),
            candidates: candidates.iter().map(MergeCandidate::from).collect(),
        }
    }

    /// Same finding framing with a different candidate subset (one chunk).
    fn with_candidates(&self, candidates: Vec<MergeCandidate>) -> Self {
        Self {
            candidates,
            ..self.clone()
        }
    }
}

/// The merge decision captured from the agent.
#[derive(Debug, Clone)]
pub struct MergeChoice {
    /// `Some(canonical_id)` to fold in; `None` to start a new canonical.
    pub merge_into: Option<i32>,
    pub reasoning: String,
    pub steps: usize,
}

/// The Merge agent. Holds the shared `ProjectIndex` (for optional
/// source-confirmation tools) and the agent knobs.
pub struct MergeAgent {
    llm: LLM,
    project_index: Arc<ProjectIndex>,
    repo_root: PathBuf,
    language_prompt_prefix: String,
    options: GraderOptions,
    /// Fraction of the model's max input used as the candidate-chunk budget.
    /// Candidates beyond what fits are split into further chunks; in practice
    /// most projects' canonical sets fit in one chunk (single LLM call).
    window_ratio: f64,
}

impl MergeAgent {
    /// Build a Merge agent, loading the project graphs once. The workflow
    /// constructs this once and reuses it across the whole drain.
    pub async fn new(
        repo: &RepoDatabase,
        repo_root: &Path,
        language_prompt_prefix: String,
        llm: &LLM,
        options: GraderOptions,
        window_ratio: f64,
    ) -> Result<Self> {
        let call_graph = repo
            .load_call_graph()
            .await
            .wrap_err("merge agent: failed to load project call graph")?;
        let storage_graph = repo
            .load_storage_graph()
            .await
            .wrap_err("merge agent: failed to load project storage graph")?;
        let inheritance_graph = repo
            .load_inheritance_graph()
            .await
            .wrap_err("merge agent: failed to load project inheritance graph")?;
        let project_index = Arc::new(ProjectIndex::build(
            call_graph,
            storage_graph,
            inheritance_graph,
        ));
        Ok(Self {
            llm: llm.clone(),
            project_index,
            repo_root: repo_root.to_path_buf(),
            language_prompt_prefix,
            options,
            window_ratio: window_ratio.clamp(0.05, 1.0),
        })
    }

    /// Decide where the reviewed finding goes against the FULL canonical set.
    /// Empty set → new canonical (no LLM). Otherwise the candidates are packed
    /// into token-budgeted chunks: usually one chunk (a single LLM call); when
    /// the set overflows the window, each chunk is asked independently and a
    /// final tie-break picks among cross-chunk matches.
    pub async fn decide(&self, input: &MergeInput) -> Result<MergeChoice> {
        if input.candidates.is_empty() {
            return Ok(MergeChoice {
                merge_into: None,
                reasoning: "first finding — no existing canonical to merge into".to_string(),
                steps: 0,
            });
        }
        let chunks = self.pack_candidate_chunks(input);
        if chunks.len() <= 1 {
            return self.decide_one(input, "").await;
        }

        // Multi-chunk: ask each chunk in isolation, collect the matches.
        let mut matched_ids: Vec<i32> = Vec::new();
        let mut steps = 0usize;
        for (i, chunk) in chunks.iter().enumerate() {
            let sub = input.with_candidates(chunk.clone());
            let choice = self.decide_one(&sub, &format!("-c{i}")).await?;
            steps += choice.steps;
            if let Some(id) = choice.merge_into {
                matched_ids.push(id);
            }
        }
        match matched_ids.len() {
            0 => Ok(MergeChoice {
                merge_into: None,
                reasoning: format!("no match across {} chunk(s)", chunks.len()),
                steps,
            }),
            1 => Ok(MergeChoice {
                merge_into: Some(matched_ids[0]),
                reasoning: "single cross-chunk match".to_string(),
                steps,
            }),
            _ => {
                // Tie-break: re-ask over only the matched candidates.
                let finalists: Vec<MergeCandidate> = input
                    .candidates
                    .iter()
                    .filter(|c| matched_ids.contains(&c.report_finding_id))
                    .cloned()
                    .collect();
                let sub = input.with_candidates(finalists);
                let choice = self.decide_one(&sub, "-final").await?;
                Ok(MergeChoice {
                    merge_into: choice.merge_into,
                    reasoning: format!(
                        "tie-break among {} matches: {}",
                        matched_ids.len(),
                        choice.reasoning
                    ),
                    steps: steps + choice.steps,
                })
            }
        }
    }

    /// One merge decision over a single chunk of candidates. `cache_disc`
    /// disambiguates the llmy cache key across chunks of the same finding.
    async fn decide_one(&self, input: &MergeInput, cache_disc: &str) -> Result<MergeChoice> {
        let valid_ids: Arc<BTreeSet<i32>> = Arc::new(
            input
                .candidates
                .iter()
                .map(|c| c.report_finding_id)
                .collect(),
        );
        let attempt: AttemptHandle<RawMerge> = AttemptHandle::new();
        let tools = build_merge_toolbox(&self.project_index, &self.repo_root, &attempt, valid_ids);
        let user_prompt = serde_json::to_string_pretty(input)
            .wrap_err("merge agent: failed to serialize MergeInput")?;
        let cache_suffix = format!("merge-r{:06}{cache_disc}", input.reflection_id);
        let system_prompt = super::prompt::merge_system(&self.language_prompt_prefix);
        let steps = drive_agent_loop(
            &self.project_index,
            &self.llm,
            &self.options,
            system_prompt,
            user_prompt,
            &cache_suffix,
            tools,
            &attempt,
        )
        .await?;
        let raw = attempt
            .take()
            .await
            .expect("drive_agent_loop returns only when attempt is set");
        Ok(MergeChoice {
            merge_into: raw.merge_into,
            reasoning: raw.reasoning,
            steps,
        })
    }

    /// Greedily pack the candidates into chunks whose rendered token cost
    /// stays under `window_ratio × max_input`, reserving room for the system
    /// prompt plus the finding framing that rides along in every chunk.
    fn pack_candidate_chunks(&self, input: &MergeInput) -> Vec<Vec<MergeCandidate>> {
        let finding_only = input.with_candidates(Vec::new());
        let reserve =
            super::CandidateChunker::tokens_of(&self.llm, super::prompt::MERGE_SYSTEM_TEMPLATE)
                + serde_json::to_string(&finding_only)
                    .map(|s| super::CandidateChunker::tokens_of(&self.llm, &s))
                    .unwrap_or(0)
                + 2048;
        super::CandidateChunker::new(&self.llm, self.window_ratio, reserve).chunk(&input.candidates)
    }

    /// The project graphs this agent loaded, so a sibling dedup agent built
    /// for the same run reuses them instead of paying a second full load.
    pub fn project_index(&self) -> &Arc<ProjectIndex> {
        &self.project_index
    }
}

fn build_merge_toolbox(
    project_index: &Arc<ProjectIndex>,
    repo_root: &Path,
    attempt: &AttemptHandle<RawMerge>,
    valid_ids: Arc<BTreeSet<i32>>,
) -> ToolBox {
    let mut tools = ToolBox::new();
    tools.add_tool(LookupCallGraphTool {
        project: project_index.clone(),
    });
    tools.add_tool(LookupStateVariableXrefsTool {
        project: project_index.clone(),
    });
    tools.add_tool(ReadContractSourceTool {
        project: project_index.clone(),
    });
    tools.add_tool(ReadFunctionSourceTool {
        project: project_index.clone(),
    });
    tools.add_tool(ReadFileTool::new(repo_root.to_path_buf()));
    tools.add_tool(ListDirectoryTool::new_root(repo_root.to_path_buf()));
    tools.add_tool(FindFileTool::new(repo_root.to_path_buf()));
    tools.add_tool(GrepDirectoryTool::new(repo_root.to_path_buf()));
    tools.add_tool(EmitMergeDecisionTool {
        attempt: attempt.clone(),
        valid_ids,
    });
    tools
}

// ---------------------------------------------------------------------------
// emit_merge_decision tool
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct RawMerge {
    merge_into: Option<i32>,
    reasoning: String,
}

#[derive(Debug, Clone, Deserialize, JsonSchema)]
struct EmitMergeDecisionArgs {
    /// The `report_finding_id` of the canonical this finding is the SAME
    /// underlying bug as, or null to start a new canonical. Must be one of
    /// the candidate ids shown, or null.
    merge_into: Option<i32>,
    /// Why this is (or is not) the same underlying bug as the chosen
    /// canonical — cite the shared (or differing) root cause.
    reasoning: String,
}

#[derive(Debug, Clone)]
#[llmy::agent::tool(
    arguments = EmitMergeDecisionArgs,
    invoke = invoke,
    description = "Commit the dedup decision for this finding and end the agent run. Call EXACTLY once. Set merge_into to a candidate's report_finding_id only when it is the SAME underlying bug (same root cause / same defect), else null for a new canonical. Prefer a NEW canonical when in doubt.",
    name = "emit_merge_decision",
)]
struct EmitMergeDecisionTool {
    attempt: AttemptHandle<RawMerge>,
    valid_ids: Arc<BTreeSet<i32>>,
}

impl EmitMergeDecisionTool {
    async fn invoke(
        &self,
        args: EmitMergeDecisionArgs,
    ) -> std::result::Result<String, llmy::agent::LLMYError> {
        if let Some(id) = args.merge_into
            && !self.valid_ids.contains(&id)
        {
            return Ok(format!(
                "error: merge_into={id} is not one of the candidate report_finding_ids; \
                 pass a shown id or null"
            ));
        }
        if args.reasoning.trim().is_empty() {
            return Ok("error: reasoning must be non-empty".to_string());
        }
        match self
            .attempt
            .try_set(RawMerge {
                merge_into: args.merge_into,
                reasoning: args.reasoning,
            })
            .await
        {
            Ok(()) => {
                Ok("ok: merge decision committed; the runtime will end the agent now".to_string())
            }
            Err(_) => Ok("error: emit_merge_decision already called".to_string()),
        }
    }
}
