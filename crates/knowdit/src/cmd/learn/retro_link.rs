//! `learn retro-link` subcommand. Re-link existing globally-linked findings
//! against the canonical semantics queued in `pending_semantic` (typically
//! the canonicals introduced by recently-admitted projects). After the LLM
//! decides which new edges to add, the pending queue is cleared.
//!
//! Use this in the incremental `learn-new-project` flow between admission
//! and the standard global `learn link` pass so that prior projects' findings
//! get a chance to attach to the new project's canonical semantics.
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
