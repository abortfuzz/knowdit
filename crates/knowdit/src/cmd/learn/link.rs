use crate::cmd::learn::finding_link_args::FindingLinkCliArgs;
use clap::Args;
use color_eyre::eyre::Result;
use knowdit_kg::db::HistoricalDatabase;
use llmy::clap::OpenAISetup;
use llmy::client::client::LLM;
use std::collections::HashSet;

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

    /// Keep re-running the linker until every processed finding has
    /// at least one `semantic_finding_link` row — or the LLM client
    /// hits its billing cap (the error propagates and stops the
    /// loop). After the first iteration, `--link-include-unlinked`
    /// is forced on for every subsequent retry so processed-but-
    /// unlinked findings get another shot. A no-progress guard
    /// stops the loop when two consecutive iterations leave the
    /// SAME set of findings unlinked (an LLM that refuses to link
    /// a finding twice in a row won't link it on a third try
    /// either; better to surface and let the operator look).
    #[arg(long = "until-all-linked", default_value_t = false)]
    pub until_all_linked: bool,
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
    ///
    /// With `--until-all-linked`, repeatedly invokes
    /// [`knowdit_kg::learn::link_pending_findings`] until every
    /// processed finding has at least one `semantic_finding_link`
    /// row, or the LLM client errors (billing cap, network, etc.),
    /// or a no-progress iteration is detected. Without the flag,
    /// runs exactly once and exits — leftover unlinked findings
    /// surface as a warning inside `link_pending_findings`.
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

        if !shared.until_all_linked {
            knowdit_kg::learn::link_pending_findings(db, llm, options).await?;
            return Ok(());
        }

        // --until-all-linked loop. Each iteration runs the full
        // linker pass; after each, query the set of processed
        // findings that still have no `semantic_finding_link` row
        // and decide whether to retry. The set is keyed by finding
        // id so we can detect a no-progress fixed point (same
        // findings unlinked twice in a row → LLM has converged on
        // "no link" and we should stop instead of burning budget).
        let mut iteration: usize = 1;
        let mut prev_unlinked: Option<HashSet<i32>> = None;
        loop {
            tracing::info!(
                "--until-all-linked: iteration {iteration} \
                 (include_unlinked={})",
                options.include_unlinked,
            );
            knowdit_kg::learn::link_pending_findings(db, llm, options).await?;

            let unlinked: HashSet<i32> = db
                .list_processed_findings_without_semantic_links()
                .await?
                .into_iter()
                .collect();
            if unlinked.is_empty() {
                tracing::info!(
                    "--until-all-linked: every processed finding has at least \
                     one semantic_finding_link row after {iteration} iteration(s); \
                     stopping",
                );
                return Ok(());
            }

            if let Some(prev) = &prev_unlinked
                && prev == &unlinked
            {
                tracing::warn!(
                    "--until-all-linked: {} finding(s) still unlinked and the last \
                     iteration produced no new links (same set as the previous \
                     iteration); stopping to avoid burning budget on findings the \
                     LLM has converged on `no-link` for. Inspect them manually: {}{}",
                    unlinked.len(),
                    unlinked
                        .iter()
                        .take(20)
                        .map(|id| format!("finding-{id}"))
                        .collect::<Vec<_>>()
                        .join(", "),
                    if unlinked.len() > 20 {
                        format!(" and {} more", unlinked.len() - 20)
                    } else {
                        String::new()
                    },
                );
                return Ok(());
            }

            tracing::info!(
                "--until-all-linked: {} finding(s) still unlinked after iteration \
                 {iteration}; restarting with include_unlinked=true",
                unlinked.len(),
            );
            prev_unlinked = Some(unlinked);
            // Force-on for retries: even if the operator launched
            // without `--link-include-unlinked`, the second pass
            // through MUST include processed-but-unlinked findings
            // or the loop is pointless.
            options.include_unlinked = true;
            iteration += 1;
        }
    }
}
