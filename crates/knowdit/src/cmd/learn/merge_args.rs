//! CLI knobs for the agent-driven learn pipeline (categorize / extract /
//! merge). One flag per knob — no env reads, no hidden constants — and the
//! whole struct boils down to two helper accessors that produce
//! [`AgentRunOptions`] and [`MergeChunkingOptions`] for the pipeline.

use clap::Args;
use color_eyre::eyre::{Result, ensure};
use knowdit_kg::agent_runner::AgentRunOptions;
use knowdit_kg::agents::{MergeChunkingOptions, MergeFieldGuard};

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

    /// Maximum number of merge agents (one per work unit) running in
    /// parallel during a single project's merge phase. `1` falls back
    /// to sequential execution. A work unit is one (new-item batch ×
    /// candidate chunk) pair.
    #[arg(long, default_value_t = 1)]
    pub merge_concurrency: usize,

    /// Hard count cap on new items (semantics/findings) per merge agent.
    /// New items are first batched to fit the model's context window
    /// automatically; this cap closes a batch early so an agent never has
    /// to emit more decisions than its step budget allows. Larger sources
    /// (e.g. a whole KG merged in via `merge-kg`) split into batches that
    /// fan out across `--merge-concurrency`. Keep it below
    /// `--max-agent-steps` (one emit per item, plus a few finalize steps).
    #[arg(long, default_value_t = 40)]
    pub merge_new_item_batch_size: usize,

    /// Fraction (0,1] of the model's context window a single prompt may fill
    /// — governs categorize / extract chunking and the merge agents' new-item
    /// batching. Lower = more, smaller prompts with sharper attention.
    #[arg(long, default_value_t = knowdit_kg::learn::DEFAULT_CONTEXT_WINDOW_UTILIZATION)]
    pub context_window_utilization: f64,

    /// Upper bound (chars) on a canonical `updated_*` merge field. On merge the
    /// agent's proposed replacement stays a concise concrete representative;
    /// values above this are rejected at the tool boundary so the agent
    /// re-emits a tighter one. Per-raw detail lives on the raw child nodes.
    #[arg(long, default_value_t = 2_000)]
    pub merge_field_max_chars: usize,

    /// Below this current length a canonical field is too thin to protect, so
    /// any non-empty replacement is accepted. At or above it, the shrink guard
    /// below applies.
    #[arg(long, default_value_t = 160)]
    pub merge_field_concrete_floor: usize,

    /// Reject a replacement shorter than this fraction of an already-substantial
    /// current value — the signature of over-generalization (a rich description
    /// collapsing into "improper access control"). Range (0, 1].
    #[arg(long, default_value_t = 0.6)]
    pub merge_field_min_shrink_ratio: f64,

    /// Upper bound (chars) on a merge edge's required `appended_*` note — the
    /// one-or-two-sentence summary of how a folded raw extends the canonical.
    /// Values above this are rejected at the tool boundary so the agent re-emits
    /// a tighter note.
    #[arg(long, default_value_t = 600)]
    pub merge_field_appended_max_chars: usize,
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
        ensure!(
            self.merge_new_item_batch_size > 0,
            "merge_new_item_batch_size must be greater than zero",
        );
        ensure!(
            self.context_window_utilization > 0.0 && self.context_window_utilization <= 1.0,
            "context_window_utilization must be in (0, 1]",
        );
        ensure!(
            self.merge_field_max_chars > 0,
            "merge_field_max_chars must be greater than zero",
        );
        ensure!(
            self.merge_field_min_shrink_ratio > 0.0 && self.merge_field_min_shrink_ratio <= 1.0,
            "merge_field_min_shrink_ratio must be in (0, 1]",
        );
        ensure!(
            self.merge_field_appended_max_chars > 0,
            "merge_field_appended_max_chars must be greater than zero",
        );
        Ok(())
    }

    pub fn to_agent_options(&self) -> AgentRunOptions {
        AgentRunOptions::new(self.max_agent_steps)
            .with_context_window_utilization(self.context_window_utilization)
    }

    pub fn to_chunking_options(&self) -> MergeChunkingOptions {
        MergeChunkingOptions::new(
            self.merge_chunk_candidate_token_budget,
            self.merge_concurrency,
            self.merge_new_item_batch_size,
            MergeFieldGuard {
                max_chars: self.merge_field_max_chars,
                concrete_floor: self.merge_field_concrete_floor,
                min_shrink_ratio: self.merge_field_min_shrink_ratio,
                appended_max_chars: self.merge_field_appended_max_chars,
            },
        )
    }
}
