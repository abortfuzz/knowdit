use crate::cmd::learn::finding_link_args::FindingLinkCliArgs;
use clap::Args;
use color_eyre::eyre::Result;
use knowdit_kg::db::HistoricalDatabase;
use llmy::clap::OpenAISetup;
use llmy::client::client::LLM;

/// Knobs for the intra-project finding-to-semantic link phase. Long
/// flags carry a `--link-*` prefix so flattening alongside
/// [`crate::cmd::learn::retro_link::RetroLinkSharedArgs`] in the
/// `workflow learn` orchestrator does not collide on the
/// `concurrency` / `include_unlinked` field names.
#[derive(Args, Clone, Debug)]
pub struct LinkSharedArgs {
    /// Number of findings to link concurrently.
    #[arg(long = "link-concurrency", default_value_t = 1)]
    pub link_concurrency: usize,

    /// Also include already-processed findings whose canonical target
    /// still has no semantic links.
    #[arg(long = "link-include-unlinked", default_value_t = false)]
    pub link_include_unlinked: bool,

    /// **Destructive**: before linking, drop every existing
    /// `semantic_finding_link` + `finding_link_status` row so all
    /// findings go back to "pending" and are re-graded by the
    /// current link rubric. Use after upgrading the linker (e.g. the
    /// Low/Medium/High `LinkStrength` rollout) to retrofit older
    /// KG databases that pre-date the change. Leaves
    /// `historical_finding` / `historical_semantic` /
    /// `pending_semantic` untouched — only link rows are wiped.
    #[arg(long = "link-reset-existing", default_value_t = false)]
    pub link_reset_existing: bool,
}

#[derive(Args)]
pub struct LinkArgs {
    #[command(flatten)]
    pub llm: OpenAISetup,

    #[command(flatten)]
    pub finding_link: FindingLinkCliArgs,

    #[command(flatten)]
    pub shared: LinkSharedArgs,
}

impl LinkArgs {
    /// CLI entry: build the LLM from clap, delegate to
    /// [`Self::link`].
    pub async fn run(self, db: &HistoricalDatabase) -> Result<()> {
        self.finding_link.validate()?;
        let llm = self.llm.clone().to_llm().await;
        Self::link(db, &llm, &self.finding_link, &self.shared).await
    }

    /// In-process entry: run intra-project finding-to-semantic
    /// linking against an already-opened KG + LLM. No `&self` —
    /// every knob comes from `finding_link` + `shared`.
    pub async fn link(
        db: &HistoricalDatabase,
        llm: &LLM,
        finding_link: &FindingLinkCliArgs,
        shared: &LinkSharedArgs,
    ) -> Result<()> {
        if shared.link_reset_existing {
            let (deleted_links, deleted_statuses) = db.clear_finding_link_progress().await?;
            tracing::warn!(
                deleted_links,
                deleted_statuses,
                "--link-reset-existing: wiped existing finding links; \
                 every finding will be re-graded by the current rubric"
            );
        }
        let mut options = finding_link.to_options(shared.link_concurrency);
        options.include_unlinked = shared.link_include_unlinked;
        knowdit_kg::learn::link_pending_findings(db, llm, options).await?;
        Ok(())
    }
}
