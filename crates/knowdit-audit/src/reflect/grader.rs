//! Phase 1 of reflection: the **verdict grader** agent.
//!
//! Classifies one violated `harness_run` into one of five
//! [`ReflectionResult`] verdicts. Severity (when verdict is
//! `ValidFinding`) is decided by a separate
//! [`super::severity_grader::SeverityGrader`] in Phase 2 — this
//! agent's `EmitVerdictTool` deliberately does NOT carry a severity
//! field.
//!
//! Verdict order in the system prompt is set by check cost: cheap
//! lookups first (`IncompleteSpecification` from a missing contract),
//! deeper reads last (`ValidFinding` requires reading the violating
//! function source).
//!
//! Both `VerdictGrader` and `SeverityGrader` share the project
//! lookup tools (`lookup_call_graph` / `lookup_state_variable_xrefs` /
//! `read_contract_source` / `read_function_source`) loaded out of
//! `crate::spec`; the shared agent-loop driver lives in
//! [`super::agent_loop`].

use std::path::{Path, PathBuf};
use std::sync::Arc;

use color_eyre::eyre::{Result, WrapErr};
use knowdit_repo_model::{ProjectProfile, ReflectionResult, RepoDatabase};
use llmy::agent::tool::ToolBox;
use llmy::agent::tools::files::{FindFileTool, GrepDirectoryTool, ListDirectoryTool, ReadFileTool};
use llmy::client::client::LLM;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::spec::{
    LookupCallGraphTool, LookupStateVariableXrefsTool, ProjectIndex, ReadContractSourceTool,
    ReadFunctionSourceTool,
};
use crate::types::AuditSpecification;

use super::agent_loop::{
    AttemptHandle, CoverageSummary, GraderOptions, RunSummary, drive_agent_loop,
};
use super::prompt::verdict_system;

/// Single per-`harness_run` grading task. All fields owned so the
/// input crosses async boundaries by clone — no lifetime params on
/// this struct or on [`VerdictGrader::grade`].
#[derive(Debug, Clone, Serialize)]
pub struct VerdictInput {
    pub run_id: i32,
    pub spec_id: i32,
    pub spec: AuditSpecification,
    pub harness_source: String,
    pub finding_title: Option<String>,
    pub run: RunSummary,
    pub coverage_summary: Option<CoverageSummary>,
    /// Number of ancestor reflections in this code_gen's regen
    /// lineage already classified `IncompleteStep`. Drives the
    /// "two strikes → escalate to IncompleteSpecification" rule.
    pub prior_incomplete_step_count: u32,
    /// Snapshot of the project profile (subsystems + core components)
    /// when the profile phase has already run for this project, else
    /// `None`. The grader uses it as the cheapest source of design
    /// intent when deciding `ExpectedViolation` — a reached
    /// `post_attack` state that conflicts with a documented invariant
    /// in the profile is evidence AGAINST `ExpectedViolation`.
    pub project_profile: Option<ProjectProfile>,
}

/// Verdict captured by [`EmitVerdictTool`]. The 5-class
/// [`GraderVerdict`] excludes `Suspect` at the type level (`Suspect`
/// is reserved for inline gates).
#[derive(Debug, Clone)]
pub struct VerdictOutput {
    pub result: ReflectionResult,
    pub reason: String,
    pub steps: usize,
}

/// The verdict grader agent. Owns its `LLM` clone (cheap), the
/// `ProjectIndex` (Arc-shared with the agent's tools), and the
/// per-CLI-invocation [`GraderOptions`]. Built once via [`Self::new`]
/// and reused across every harness_run graded — the project index is
/// loaded once, not per call.
pub struct VerdictGrader {
    llm: LLM,
    project_index: Arc<ProjectIndex>,
    /// Repository root on disk. Threaded into [`build_verdict_toolbox`]
    /// so the agent's `read_file` / `list_dir` / `find_file` / `grep`
    /// tools sandbox to this directory.
    repo_root: PathBuf,
    /// Loaded once on grader construction, then cloned into every
    /// [`VerdictInput`] handed to the agent. `None` when the profile
    /// phase hasn't run yet (older DBs).
    project_profile: Option<ProjectProfile>,
    /// Pre-rendered Markdown block describing the project's
    /// source language; verbatim-prepended to the verdict
    /// system prompt at grade time. The audit crate never names
    /// a non-Solidity language; the consumer binary fills this in.
    language_prompt_prefix: String,
    options: GraderOptions,
}

impl VerdictGrader {
    /// Build a grader. Loads the project call graph + storage graph
    /// once; subsequent [`Self::grade`] calls are pure compute over
    /// already-resident state.
    pub async fn new(
        repo: &RepoDatabase,
        repo_root: &Path,
        language_prompt_prefix: String,
        llm: &LLM,
        options: GraderOptions,
    ) -> Result<Self> {
        let call_graph = repo
            .load_call_graph()
            .await
            .wrap_err("verdict grader: failed to load project call graph")?;
        let storage_graph = repo
            .load_storage_graph()
            .await
            .wrap_err("verdict grader: failed to load project storage graph")?;
        let inheritance_graph = repo
            .load_inheritance_graph()
            .await
            .wrap_err("verdict grader: failed to load project inheritance graph")?;
        let project_index = Arc::new(ProjectIndex::build(
            call_graph,
            storage_graph,
            inheritance_graph,
        ));
        let project_profile = repo
            .get_project_profile()
            .await
            .wrap_err("verdict grader: failed to read project profile")?;
        Ok(Self {
            llm: llm.clone(),
            project_index,
            repo_root: repo_root.to_path_buf(),
            project_profile,
            language_prompt_prefix,
            options,
        })
    }

    /// The language prompt prefix this grader was configured
    /// with. Used by
    /// [`super::severity_grader::SeverityGrader::new_with_index`]
    /// to inherit the same prefix without re-reading project
    /// metadata.
    pub fn language_prompt_prefix(&self) -> &str {
        &self.language_prompt_prefix
    }

    /// Skip the project-index reload when the caller already has one
    /// (e.g. the severity grader loads its own index from the same
    /// repo). Used by [`super::severity_grader::SeverityGrader::new_with_index`].
    pub fn project_index(&self) -> &Arc<ProjectIndex> {
        &self.project_index
    }

    /// Grade one violated `harness_run`. Returns `Err` only on
    /// agent / tool wiring failures or when the agent exhausts its
    /// step budget without emitting a verdict — the caller MUST NOT
    /// persist a row in those cases (resume safety: re-running picks
    /// the run back up and llmy cache reuses prior agent steps).
    pub async fn grade(&self, input: &VerdictInput) -> Result<VerdictOutput> {
        let attempt: AttemptHandle<RawVerdict> = AttemptHandle::new();
        let tools = build_verdict_toolbox(&self.project_index, &self.repo_root, &attempt);
        // Inject the cached profile so VerdictInputs constructed by
        // callers without DB access still carry the project's design
        // intent — saves an extra DB round-trip and keeps the agent
        // input one self-contained JSON blob.
        let mut input = input.clone();
        if input.project_profile.is_none() {
            input.project_profile = self.project_profile.clone();
        }
        let user_prompt = serde_json::to_string_pretty(&input)
            .wrap_err("verdict grader: failed to serialize VerdictInput")?;
        let cache_suffix = format!("verdict-r{:06}-s{:06}", input.run_id, input.spec_id);
        let steps = drive_agent_loop(
            &self.project_index,
            &self.llm,
            &self.options,
            // The language prefix is prepended to the system
            // prompt by `verdict_system`; this crate never
            // branches on a closed-set language enum.
            verdict_system(&self.language_prompt_prefix),
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
        Ok(VerdictOutput {
            result: raw.classification.into(),
            reason: raw.rationale,
            steps,
        })
    }
}

fn build_verdict_toolbox(
    project_index: &Arc<ProjectIndex>,
    repo_root: &Path,
    attempt: &AttemptHandle<RawVerdict>,
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
    // Repository-level IO so the agent can survey READMEs, docs/,
    // interface NatSpec, audit reports, test sidecar notes, etc. —
    // anything the KG doesn't index. All four are sandboxed to
    // `repo_root` by llmy.
    tools.add_tool(ReadFileTool::new(repo_root.to_path_buf()));
    tools.add_tool(ListDirectoryTool::new_root(repo_root.to_path_buf()));
    tools.add_tool(FindFileTool::new(repo_root.to_path_buf()));
    tools.add_tool(GrepDirectoryTool::new(repo_root.to_path_buf()));
    tools.add_tool(EmitVerdictTool {
        attempt: attempt.clone(),
    });
    tools
}

// ---------------------------------------------------------------------------
// emit_verdict tool
// ---------------------------------------------------------------------------

/// 5-class verdict the agent is allowed to emit. Defined locally
/// (instead of reusing the 6-variant [`ReflectionResult`]) so the
/// agent can't emit `Suspect` — that's reserved for inline gates.
/// serde + JsonSchema do all the parsing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
pub enum GraderVerdict {
    ValidFinding,
    ExpectedViolation,
    OutOfScope,
    IncompleteStep,
    IncompleteSpecification,
}

impl From<GraderVerdict> for ReflectionResult {
    fn from(v: GraderVerdict) -> Self {
        match v {
            GraderVerdict::ValidFinding => Self::ValidFinding,
            GraderVerdict::ExpectedViolation => Self::ExpectedViolation,
            GraderVerdict::OutOfScope => Self::OutOfScope,
            GraderVerdict::IncompleteStep => Self::IncompleteStep,
            GraderVerdict::IncompleteSpecification => Self::IncompleteSpecification,
        }
    }
}

#[derive(Debug, Clone)]
struct RawVerdict {
    classification: GraderVerdict,
    rationale: String,
}

#[derive(Debug, Clone, Deserialize, JsonSchema)]
struct EmitVerdictArgs {
    /// The 5-class verdict. The agent must pick exactly one.
    classification: GraderVerdict,
    /// Concrete one-paragraph reason. Must cite specific function /
    /// contract names from the counter-example or `spec.sequence`
    /// (the system prompt rejects vague rationales).
    rationale: String,
}

#[derive(Debug, Clone)]
#[llmy::agent::tool(
    arguments = EmitVerdictArgs,
    invoke = invoke,
    description = "Commit the final 5-class classification for this harness_run and end the agent run. Call EXACTLY once, AFTER gathering enough evidence via the lookup_call_graph / lookup_state_variable_xrefs / read_contract_source / read_function_source tools. Severity (for ValidFinding) is decided by a separate downstream agent — do NOT include it here.",
    name = "emit_verdict",
)]
struct EmitVerdictTool {
    attempt: AttemptHandle<RawVerdict>,
}

impl EmitVerdictTool {
    async fn invoke(
        &self,
        args: EmitVerdictArgs,
    ) -> std::result::Result<String, llmy::agent::LLMYError> {
        if args.rationale.trim().is_empty() {
            return Ok("error: rationale must be non-empty".to_string());
        }
        match self
            .attempt
            .try_set(RawVerdict {
                classification: args.classification,
                rationale: args.rationale,
            })
            .await
        {
            Ok(()) => Ok("ok: verdict committed; the runtime will end the agent now".to_string()),
            Err(_) => Ok("error: emit_verdict already called for this run".to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn emit_verdict_args_typed_enum() {
        let s = r#"{"classification":"ValidFinding","rationale":"x"}"#;
        let args: EmitVerdictArgs = serde_json::from_str(s).unwrap();
        assert_eq!(args.classification, GraderVerdict::ValidFinding);
    }

    #[test]
    fn emit_verdict_args_unknown_classification_rejected() {
        let s = r#"{"classification":"valid_vuln","rationale":"x"}"#;
        assert!(serde_json::from_str::<EmitVerdictArgs>(s).is_err());
    }

    #[test]
    fn grader_verdict_to_reflection_result() {
        for (gv, want) in [
            (GraderVerdict::ValidFinding, ReflectionResult::ValidFinding),
            (
                GraderVerdict::ExpectedViolation,
                ReflectionResult::ExpectedViolation,
            ),
            (GraderVerdict::OutOfScope, ReflectionResult::OutOfScope),
            (
                GraderVerdict::IncompleteStep,
                ReflectionResult::IncompleteStep,
            ),
            (
                GraderVerdict::IncompleteSpecification,
                ReflectionResult::IncompleteSpecification,
            ),
        ] {
            let r: ReflectionResult = gv.into();
            assert_eq!(r, want);
        }
    }
}
