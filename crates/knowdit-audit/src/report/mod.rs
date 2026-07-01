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
