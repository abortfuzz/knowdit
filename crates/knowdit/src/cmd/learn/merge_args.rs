//! CLI knobs for the agent-driven learn pipeline (categorize / extract /
//! merge). One flag per knob — no env reads, no hidden constants — and the
//! whole struct boils down to two helper accessors that produce
//! [`AgentRunOptions`] and [`MergeChunkingOptions`] for the pipeline.

use clap::Args;
use color_eyre::eyre::{Result, ensure};
use knowdit_kg::agent_runner::AgentRunOptions;
use knowdit_kg::agents::MergeChunkingOptions;

#[derive(Args, Debug, Clone)]
pub struct MergeCliArgs {
    /// Hard cap on agent steps for a single per-chunk learn-pipeline
    /// agent (categorize, extract semantics, extract findings, semantic
    /// merge, finding merge). Each `emit_*` tool call counts as one step.
    #[arg(long, default_value_t = 60)]
    pub max_agent_steps: usize,

    /// Soft cap on the rendered token cost of the existing-canonical
    /// candidates section in a single merge prompt. The chunker packs
    /// canonicals (with their merged-away children) greedily until adding
    /// the next candidate would exceed this budget. Larger budgets fewer
    /// chunks (cheaper but bigger prompts); smaller budgets more chunks
    /// (more LLM calls, smaller prompts).
    #[arg(long, default_value_t = 50_000)]
    pub merge_chunk_candidate_token_budget: usize,

    /// Maximum number of merge agents (one per candidate chunk) running
    /// in parallel during a single project's merge phase. `1` falls back
    /// to sequential execution.
    #[arg(long, default_value_t = 1)]
    pub merge_concurrency: usize,
}

impl MergeCliArgs {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.max_agent_steps > 0,
            "max_agent_steps must be greater than zero",
        );
        ensure!(
            self.merge_chunk_candidate_token_budget >= 1024,
            "merge_chunk_candidate_token_budget must be at least 1024 tokens",
        );
        ensure!(
            self.merge_concurrency > 0,
            "merge_concurrency must be greater than zero",
        );
        Ok(())
    }

    pub fn to_agent_options(&self) -> AgentRunOptions {
        AgentRunOptions::new(self.max_agent_steps)
    }

    pub fn to_chunking_options(&self) -> MergeChunkingOptions {
        MergeChunkingOptions::new(
            self.merge_chunk_candidate_token_budget,
            self.merge_concurrency,
        )
    }
}
