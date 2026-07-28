//! Report phase for the `review-findings` workflow.
//!
//! After streamloop has produced raw `valid_finding` rows and the Review
//! agent (in [`crate::reflect::review_grader`]) has graded each into a
//! structured, client-facing `finding_review` (title / severity / description
//! / location / impact / recommendation), this module's single agent finishes
//! the dedup:
//!
//! * [`merge::MergeAgent`] — incrementally deduplicates reviewed findings into
//!   canonical `report_finding` rows (+ `finding_merge` edges).
//! * [`ruled_out::RuledOutMerger`] — the same incremental placement over the
//!   *rejections*: the conclusions the verdict grader reached about why a
//!   direction is not a bug, folded into a deduplicated set (+
//!   `ruled_out_merge` edges) so later agents inherit them instead of
//!   re-deriving each one dozens of times.
//!
//! There is no separate Writer agent: the client report is rendered directly
//! from each cluster's representative member (its review for the prose + its
//! existing `harness_source` for the proof-of-concept).
//! [`render::render_markdown_report`] turns the canonicals into the
//! `audit_report.md` deliverable (no LLM). The orchestration that wires
//! Review → Merge → export over a project DB lives in the `knowdit` binary's
//! `workflow review-findings` command (shared with streamloop).

pub mod merge;
mod prompt;
pub mod render;
pub mod ruled_out;

use llmy::client::client::LLM;
use serde::Serialize;

/// Greedy token-budgeted packer for a dedup agent's candidate list.
///
/// Both dedup agents show one new item against everything accumulated so far,
/// and both face the same problem once a long audit has accumulated more
/// candidates than fit beside the system prompt. Packing them into
/// window-sized chunks (rather than truncating) keeps the comparison complete:
/// each chunk is asked independently and the caller reconciles the answers.
/// In practice a project's candidate set fits in one chunk and the multi-chunk
/// path never runs — it exists so that a long audit degrades into more calls
/// rather than into silently unseen candidates.
pub(crate) struct CandidateChunker {
    llm: LLM,
    /// Tokens available for candidates alone, after the caller's reserve for
    /// the system prompt and the item being placed.
    budget: usize,
}

impl CandidateChunker {
    /// `window_ratio` is the fraction of the model's max input the whole
    /// prompt may occupy; `reserve` is what the non-candidate part of that
    /// prompt already costs.
    pub(crate) fn new(llm: &LLM, window_ratio: f64, reserve: usize) -> Self {
        let window = (llm.model.config.max_input() as f64 * window_ratio.clamp(0.05, 1.0)) as usize;
        Self {
            llm: llm.clone(),
            budget: window.saturating_sub(reserve).max(1024),
        }
    }

    /// Token cost of one rendered string under this model's tokenizer.
    /// Exposed so callers can price their own reserve with the same tokenizer
    /// the packing uses.
    pub(crate) fn tokens_of(llm: &LLM, text: &str) -> usize {
        llm.model.config.count_tokens_lossy(text)
    }

    /// Split `items` into chunks that each fit the budget. An item larger than
    /// the whole budget still gets its own chunk rather than being dropped.
    pub(crate) fn chunk<T: Serialize + Clone>(&self, items: &[T]) -> Vec<Vec<T>> {
        let mut chunks: Vec<Vec<T>> = Vec::new();
        let mut current: Vec<T> = Vec::new();
        let mut current_tokens = 0usize;
        for item in items {
            let cost = serde_json::to_string(item)
                .map(|s| Self::tokens_of(&self.llm, &s))
                .unwrap_or(64);
            if !current.is_empty() && current_tokens + cost > self.budget {
                chunks.push(std::mem::take(&mut current));
                current_tokens = 0;
            }
            current.push(item.clone());
            current_tokens += cost;
        }
        if !current.is_empty() {
            chunks.push(current);
        }
        chunks
    }
}
