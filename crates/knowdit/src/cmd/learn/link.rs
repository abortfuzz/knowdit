use crate::cmd::learn::finding_link_args::FindingLinkCliArgs;
use clap::Args;
use color_eyre::eyre::Result;
use knowdit_kg::db::HistoricalDatabase;
use knowdit_kg_model::db::operation_history::OperationType;
use llmy::clap::OpenAISetup;
use llmy::client::client::LLM;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// Knobs for the intra-project finding-to-semantic link phase. Long
/// flags carry a `--link-*` prefix so flattening alongside
/// [`crate::cmd::learn::retro_link::RetroLinkSharedArgs`] in the
/// `workflow learn` orchestrator does not collide on the
/// `concurrency` / `include_unlinked` field names.
#[derive(Args, Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct LinkSharedArgs {
    /// Number of findings to link concurrently.
    #[arg(long = "link-concurrency", default_value_t = 1)]
    pub link_concurrency: usize,

    /// Force a re-link of findings that have ALREADY been through the global
    /// cross-project linker (normally skipped). Normal runs don't need this —
    /// the linker automatically picks up every finding not yet globally linked.
    /// Combine with `--link-reset-existing` for a clean re-link.
    #[arg(long = "link-include-unlinked", default_value_t = false)]
    pub link_include_unlinked: bool,

    /// **Destructive**: before linking, reset link progress so all findings go
    /// back to "pending" and are re-graded by the current rubric. Clears every
    /// `finding_link_status` row and, by default, the GLOBAL cross-project links
    /// — but KEEPS the cheap, high-confidence in-project links (finding →
    /// own-project semantic, written at extraction time). Add
    /// `--reset-in-project-link` to wipe those too. Leaves `historical_*` /
    /// `pending_semantic` untouched — only link rows are affected.
    #[arg(long = "link-reset-existing", default_value_t = false)]
    pub link_reset_existing: bool,

    /// Only meaningful together with `--link-reset-existing`: ALSO delete the
    /// in-project links (finding → own-project semantic, created at extraction
    /// time). Without this, `--link-reset-existing` keeps them and just re-runs
    /// the global cross-project linking on top.
    #[arg(long = "reset-in-project-link", default_value_t = false)]
    pub reset_in_project_link: bool,

    /// Keep re-running the global linker until every finding has been through it
    /// (recorded in `finding_link_status`) — or the LLM client hits its billing
    /// cap (the error propagates and stops the loop). A no-progress guard stops
    /// the loop when two consecutive iterations leave the SAME set of findings
    /// unprocessed (an LLM that won't link a finding twice in a row won't on a
    /// third try either; better to surface it than burn budget).
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

/// Non-sensitive argument payload persisted to `operation_history` for a
/// `link` run: the finding-link tuning knobs plus the link-phase shared flags,
/// combined into one JSON object. Deliberately excludes [`OpenAISetup`] (LLM
/// credentials) — the audit log never stores secrets.
#[derive(Serialize, Deserialize)]
struct LinkOperationArgs {
    finding_link: FindingLinkCliArgs,
    shared: LinkSharedArgs,
}

impl LinkArgs {
    /// CLI entry: build the LLM from clap, delegate to
    /// [`Self::link`].
    pub async fn run(self, db: &HistoricalDatabase) -> Result<()> {
        self.finding_link.validate()?;
        let llm = self.llm.clone().to_llm().await;
        Self::link(
            db,
            &llm,
            &self.finding_link,
            &self.shared,
            self.finding_link.link_context_window_utilization,
        )
        .await?;
        // Recorded only after linking committed, so an interrupted run leaves
        // no operation_history row; deduped on (type, args) by `record_operation`.
        let args = serde_json::to_value(LinkOperationArgs {
            finding_link: self.finding_link,
            shared: self.shared,
        })?;
        db.record_operation(OperationType::Link, args).await?;
        Ok(())
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
        context_window_utilization: f64,
    ) -> Result<()> {
        if shared.link_reset_existing {
            let (deleted_links, deleted_statuses) = db
                .clear_finding_link_progress(shared.reset_in_project_link)
                .await?;
            tracing::warn!(
                deleted_links,
                deleted_statuses,
                reset_in_project = shared.reset_in_project_link,
                "--link-reset-existing: cleared finding-link progress ({}); \
                 every finding will be re-graded by the current rubric",
                if shared.reset_in_project_link {
                    "including in-project links"
                } else {
                    "keeping in-project links"
                },
            );
        } else if shared.reset_in_project_link {
            tracing::warn!(
                "--reset-in-project-link has no effect without --link-reset-existing; ignoring"
            );
        }
        let mut options = finding_link.to_options(shared.link_concurrency);
        options.include_unlinked = shared.link_include_unlinked;
        options.context_window_utilization = context_window_utilization;

        if !shared.until_all_linked {
            options.link_pending_findings(db, llm).await?;
            return Ok(());
        }

        // --until-all-linked loop. Each iteration runs the full global linker
        // pass; after each, query the findings still NOT recorded in
        // `finding_link_status` (i.e. not yet run through the global
        // cross-project linker — in-project links do NOT count as linked here)
        // and decide whether to keep going. The set is keyed by finding id so a
        // no-progress fixed point (same findings still unprocessed twice in a
        // row) stops the loop instead of burning budget.
        let mut iteration: usize = 1;
        let mut prev_pending: Option<HashSet<i32>> = None;
        loop {
            tracing::info!("--until-all-linked: iteration {iteration}");
            options.link_pending_findings(db, llm).await?;

            let pending: HashSet<i32> = db
                .list_pending_findings_for_linking()
                .await?
                .into_iter()
                .map(|finding| finding.finding_id)
                .collect();
            if pending.is_empty() {
                tracing::info!(
                    "--until-all-linked: every finding has been through the global \
                     linker after {iteration} iteration(s); stopping",
                );
                return Ok(());
            }

            if let Some(prev) = &prev_pending
                && prev == &pending
            {
                tracing::warn!(
                    "--until-all-linked: {} finding(s) still not globally linked and \
                     the last iteration made no progress (same set as the previous \
                     iteration); stopping to avoid burning budget. Inspect them \
                     manually: {}{}",
                    pending.len(),
                    pending
                        .iter()
                        .take(20)
                        .map(|id| format!("finding-{id}"))
                        .collect::<Vec<_>>()
                        .join(", "),
                    if pending.len() > 20 {
                        format!(" and {} more", pending.len() - 20)
                    } else {
                        String::new()
                    },
                );
                return Ok(());
            }

            tracing::info!(
                "--until-all-linked: {} finding(s) still not globally linked after \
                 iteration {iteration}; continuing",
                pending.len(),
            );
            prev_pending = Some(pending);
            iteration += 1;
        }
    }
}
