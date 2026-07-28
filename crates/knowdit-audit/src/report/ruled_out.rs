//! The **ruled-out conclusion deduplicator** — incremental, LLM-driven
//! clustering of the verdict grader's rejections.
//!
//! Every time the grader closes a direction (`ExpectedViolation` /
//! `OutOfScope`) it records the project fact that settled it. Those facts are
//! what later agents need in order to stop walking into the same wall, but the
//! raw stream is heavily redundant: one fact is typically re-established by
//! many independent links. This agent folds each new rejection into the
//! conclusion set as it arrives, persisted as a `ruled_out_merge` edge — the
//! same incremental placement [`super::merge::MergeAgent`] performs over
//! confirmed findings, and the reason both can run inside the streaming
//! pipeline rather than as an end-of-run batch.
//!
//! Unlike the finding merger this agent gets no source-inspection tools. It
//! judges two already-written claims for sameness, and it runs once per
//! rejection — the volume that makes the redundancy worth removing in the
//! first place is also what makes an exploratory tool budget here expensive.

use std::collections::BTreeSet;
use std::sync::Arc;

use color_eyre::eyre::{Result, WrapErr};
use knowdit_repo_model::{PendingRuledOut, RuledOutConclusion};
use llmy::agent::tool::ToolBox;
use llmy::client::client::LLM;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::reflect::agent_loop::{AttemptHandle, GraderOptions, drive_agent_loop};
use crate::spec::ProjectIndex;

use super::CandidateChunker;
use super::merge::MergeChoice;

/// One conclusion already in the set, as the agent sees it. `reflection_id` is
/// the value the agent returns to fold the new rejection in.
#[derive(Debug, Clone, Serialize)]
pub struct ConclusionCandidate {
    pub reflection_id: i32,
    pub claim: String,
    pub evidence: String,
    /// How many rejections this conclusion already covers — shown so the agent
    /// can see which conclusions are the load-bearing ones.
    pub covers_rejections: usize,
}

impl From<&RuledOutConclusion> for ConclusionCandidate {
    fn from(c: &RuledOutConclusion) -> Self {
        Self {
            reflection_id: c.id,
            claim: c.claim.clone(),
            evidence: c.evidence.clone(),
            covers_rejections: c.occurrences,
        }
    }
}

/// The rejection being placed plus the conclusions it is compared against
/// (one token-budgeted chunk of them). Serialized verbatim as the user prompt.
#[derive(Debug, Clone, Serialize)]
pub struct ConclusionMergeInput {
    pub reflection_id: i32,
    pub verdict: String,
    pub claim: String,
    pub evidence: String,
    pub candidates: Vec<ConclusionCandidate>,
}

impl ConclusionMergeInput {
    /// Frame one pending rejection against the current conclusion set.
    pub fn new(pending: &PendingRuledOut, candidates: &[RuledOutConclusion]) -> Self {
        Self {
            reflection_id: pending.reflection_id,
            verdict: pending.result.as_str().to_string(),
            claim: pending.claim.clone(),
            evidence: pending.evidence.clone(),
            candidates: candidates.iter().map(ConclusionCandidate::from).collect(),
        }
    }

    /// Same rejection framing with a different candidate subset (one chunk).
    fn with_candidates(&self, candidates: Vec<ConclusionCandidate>) -> Self {
        Self {
            candidates,
            ..self.clone()
        }
    }
}

/// The ruled-out conclusion deduplicator. Built once per run and reused across
/// the whole drain.
pub struct RuledOutMerger {
    llm: LLM,
    /// Only used to satisfy the shared agent loop's memory construction; this
    /// agent has no source-inspection tools of its own, so the graphs are
    /// borrowed from whichever agent already loaded them.
    project_index: Arc<ProjectIndex>,
    language_prompt_prefix: String,
    options: GraderOptions,
    window_ratio: f64,
}

impl RuledOutMerger {
    /// Share an already-loaded [`ProjectIndex`] rather than reloading the
    /// project graphs — the caller builds this alongside the finding merger.
    pub fn new(
        project_index: Arc<ProjectIndex>,
        language_prompt_prefix: String,
        llm: &LLM,
        options: GraderOptions,
        window_ratio: f64,
    ) -> Self {
        Self {
            llm: llm.clone(),
            project_index,
            language_prompt_prefix,
            options,
            window_ratio: window_ratio.clamp(0.05, 1.0),
        }
    }

    /// Decide where one rejection goes against the FULL conclusion set. Empty
    /// set → new conclusion (no LLM). Otherwise the candidates are packed into
    /// token-budgeted chunks: usually one chunk (a single call); when the set
    /// overflows the window, each chunk is asked independently and a final
    /// tie-break picks among cross-chunk matches.
    pub async fn decide(&self, input: &ConclusionMergeInput) -> Result<MergeChoice> {
        if input.candidates.is_empty() {
            return Ok(MergeChoice {
                merge_into: None,
                reasoning: "first rejection — no existing conclusion to fold into".to_string(),
                steps: 0,
            });
        }
        let chunks = self.pack_candidate_chunks(input);
        if chunks.len() <= 1 {
            return self.decide_one(input, "").await;
        }

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
                let finalists: Vec<ConclusionCandidate> = input
                    .candidates
                    .iter()
                    .filter(|c| matched_ids.contains(&c.reflection_id))
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

    /// One placement decision over a single chunk of candidates. `cache_disc`
    /// disambiguates the llmy cache key across chunks of the same rejection.
    async fn decide_one(
        &self,
        input: &ConclusionMergeInput,
        cache_disc: &str,
    ) -> Result<MergeChoice> {
        let valid_ids: Arc<BTreeSet<i32>> =
            Arc::new(input.candidates.iter().map(|c| c.reflection_id).collect());
        let attempt: AttemptHandle<RawConclusionMerge> = AttemptHandle::new();
        let mut tools = ToolBox::new();
        tools.add_tool(EmitConclusionMergeTool {
            attempt: attempt.clone(),
            valid_ids,
        });
        let user_prompt = serde_json::to_string_pretty(input)
            .wrap_err("ruled-out merger: failed to serialize ConclusionMergeInput")?;
        let cache_suffix = format!("ruledout-r{:06}{cache_disc}", input.reflection_id);
        let system_prompt = super::prompt::ruled_out_system(&self.language_prompt_prefix);
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

    fn pack_candidate_chunks(&self, input: &ConclusionMergeInput) -> Vec<Vec<ConclusionCandidate>> {
        let rejection_only = input.with_candidates(Vec::new());
        let reserve = CandidateChunker::tokens_of(
            &self.llm,
            super::prompt::RULED_OUT_SYSTEM_TEMPLATE,
        ) + serde_json::to_string(&rejection_only)
            .map(|s| CandidateChunker::tokens_of(&self.llm, &s))
            .unwrap_or(0)
            + 2048;
        CandidateChunker::new(&self.llm, self.window_ratio, reserve).chunk(&input.candidates)
    }
}

// ---------------------------------------------------------------------------
// emit_conclusion_merge tool
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct RawConclusionMerge {
    merge_into: Option<i32>,
    reasoning: String,
}

#[derive(Debug, Clone, Deserialize, JsonSchema)]
struct EmitConclusionMergeArgs {
    /// The `reflection_id` of the conclusion asserting the SAME project fact,
    /// or null to record this as a new distinct conclusion. Must be one of the
    /// candidate ids shown, or null.
    merge_into: Option<i32>,
    /// Why this asserts (or does not assert) the same project fact as the
    /// chosen conclusion — name the shared or differing fact.
    reasoning: String,
}

#[derive(Debug, Clone)]
#[llmy::agent::tool(
    arguments = EmitConclusionMergeArgs,
    invoke = invoke,
    description = "Commit the dedup decision for this rejection and end the agent run. Call EXACTLY once. Set merge_into to a candidate's reflection_id only when it asserts the SAME project fact, else null for a new distinct conclusion. Prefer a NEW conclusion when in doubt.",
    name = "emit_conclusion_merge",
)]
struct EmitConclusionMergeTool {
    attempt: AttemptHandle<RawConclusionMerge>,
    valid_ids: Arc<BTreeSet<i32>>,
}

impl EmitConclusionMergeTool {
    async fn invoke(
        &self,
        args: EmitConclusionMergeArgs,
    ) -> std::result::Result<String, llmy::agent::LLMYError> {
        if let Some(id) = args.merge_into
            && !self.valid_ids.contains(&id)
        {
            return Ok(format!(
                "error: merge_into={id} is not one of the candidate reflection_ids; \
                 pass a shown id or null"
            ));
        }
        if args.reasoning.trim().is_empty() {
            return Ok("error: reasoning must be non-empty".to_string());
        }
        match self
            .attempt
            .try_set(RawConclusionMerge {
                merge_into: args.merge_into,
                reasoning: args.reasoning,
            })
            .await
        {
            Ok(()) => {
                Ok("ok: merge decision committed; the runtime will end the agent now".to_string())
            }
            Err(_) => Ok("error: emit_conclusion_merge already called".to_string()),
        }
    }
}
