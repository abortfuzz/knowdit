//! `learn retro-link` subcommand. Patches a specific corner of the
//! `(finding, canonical_semantic)` link grid that the regular global
//! `learn link` pass can't reach.
//!
//! # Why this command exists — responsibility table
//!
//! Each (finding, canonical_semantic) pair in the historical KG must be
//! judged by the LLM exactly once. Two separate passes cover the four
//! quadrants of "is the finding/semantic newly admitted this run or
//! already in the KG":
//!
//! | | **new finding** (this learn run) | **old finding** (already in `finding_link_status`) |
//! |---|---|---|
//! | **new canonical semantic** (this learn run) | `learn link` | **`learn retro-link`** |
//! | **old canonical semantic** (already in the KG) | `learn link` | covered by that finding's earlier learn run |
//!
//! `learn link` ([`crate::cmd::learn::link::LinkArgs`]) iterates findings
//! that do NOT yet have a `finding_link_status` row and judges them against
//! [`HistoricalDatabase::all_canonical_semantic_link_candidates`] — i.e.
//! every canonical in the KG, old or new. So both "new finding × old
//! canonical" and "new finding × new canonical" land here naturally.
//!
//! `learn retro-link` covers the one remaining quadrant — **already-linked
//! findings against canonicals that were just introduced**. `learn link`
//! skips already-linked findings by design (`finding_link_status` is the
//! skip-list), so without `learn retro-link` this quadrant would silently
//! go un-judged in the incremental flow.
//!
//! `workflow learn`'s module doc labels these passes "Phase 2" (retro-link)
//! and "Phase 3" (link) for its own staging story; that labeling is local
//! to `workflow learn` and isn't part of the cross-command contract here.
//!
//! # When to call it
//!
//! - **Incremental learn** (`workflow learn` on top of an already-linked
//!   KG): MUST run this between admission and `learn link`. The new project
//!   introduces both new findings AND new canonicals, and the existing
//!   linked findings need a chance to bind to those new canonicals.
//!
//! - **Bulk learn** (`learn moves` / `learn c4` / `learn projects` on a
//!   fresh KG): NOT needed. There are no "old findings" yet — every
//!   finding flows through `learn link` and is judged against the full
//!   canonical set in one sweep. Running retro-link here is a no-op modulo
//!   budget burn.
//!
//! # Implementation note: the `pending_semantic` queue
//!
//! [`HistoricalDatabase::write_project_completed`] enqueues every
//! `MergeAction::New` canonical into `pending_semantic`. retro-link reads
//! the queue, fans out the LLM judgement over `pending × already_linked`,
//! then truncates the queue. The queue is just the mechanism for "which
//! canonicals are new this run"; the conceptual responsibility table
//! above is the invariant the queue serves.
use crate::cmd::learn::finding_link_args::FindingLinkCliArgs;
use clap::Args;
use color_eyre::eyre::Result;
use knowdit_kg::db::HistoricalDatabase;
use llmy::clap::OpenAISetup;
use llmy::client::client::LLM;

/// Knobs for the retro-link phase. Long flag carries a
/// `--retro-link-*` prefix to disambiguate from
/// [`crate::cmd::learn::link::LinkSharedArgs`] when both are
/// flattened into the same parse tree (e.g. `workflow learn`).
#[derive(Args, Clone, Debug)]
pub struct RetroLinkSharedArgs {
    /// Number of finding batches to link concurrently. Retro-link
    /// currently runs serially per batch; this is reserved for
    /// future fan-out.
    #[arg(long = "retro-link-concurrency", default_value_t = 1)]
    pub retro_link_concurrency: usize,
}

#[derive(Args)]
pub struct RetroLinkArgs {
    #[command(flatten)]
    pub llm: OpenAISetup,

    #[command(flatten)]
    pub finding_link: FindingLinkCliArgs,

    #[command(flatten)]
    pub shared: RetroLinkSharedArgs,
}

impl RetroLinkArgs {
    /// CLI entry: build the LLM from clap, delegate to
    /// [`Self::retro_link`].
    pub async fn run(self, db: &HistoricalDatabase) -> Result<()> {
        self.finding_link.validate()?;
        let llm = self.llm.clone().to_llm().await;
        Self::retro_link(db, &llm, &self.finding_link, &self.shared).await
    }

    /// In-process entry: re-link existing globally-linked findings
    /// against pending canonical semantics. No `&self` — every knob
    /// comes from `finding_link` + `shared`.
    pub async fn retro_link(
        db: &HistoricalDatabase,
        llm: &LLM,
        finding_link: &FindingLinkCliArgs,
        shared: &RetroLinkSharedArgs,
    ) -> Result<()> {
        let options = finding_link.to_options(shared.retro_link_concurrency);
        knowdit_kg::link::retro_link_pending_semantics(db, llm, options).await?;
        Ok(())
    }
}
