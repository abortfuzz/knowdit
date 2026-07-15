//! `knowdit workflow learn` — single-process orchestrator for
//! admitting one new project into a non-empty historical KG.
//!
//! Three sequential phases share one [`HistoricalDatabase`] handle
//! and one [`LLM`]:
//!
//! 1. **Categorize + extract + dedup-merge** (per project).
//!    Drives `ProjectData::categorize_and_extract` then
//!    `ProjectData::merge_and_write` — the merge agent dedups every
//!    extracted semantic / finding against existing KG canonicals.
//!    Resume-safe: skipped entirely if `is_completed(&db)` is true.
//!    Side effect: phase 1 enqueues all newly-introduced canonical
//!    semantics into `pending_semantic` for phase 2 to consume.
//! 2. **Retro link** ([`RetroLinkArgs::retro_link`]). Re-run the
//!    finding-to-semantic linker on **prior** projects'
//!    globally-linked findings against the canonical semantics
//!    newly admitted in phase 1. Runs **before** phase 3 so the
//!    `finding_link_status` set still excludes the new project's
//!    findings — no wasted LLM call on new-finding × new-semantic
//!    (phase 3 covers that pair).
//! 3. **Intra-project link** ([`LinkArgs::link`]). Run the LLM
//!    finding-to-semantic linker over the global pending queue so
//!    the new project's just-extracted findings attach to whichever
//!    canonical semantics (their own + every prior project's)
//!    match. With phase 2 already done, this pass is the sole
//!    consumer of the new findings, and the candidate set still
//!    presents every canonical (so new finding × old semantic and
//!    new finding × new semantic both land here).
//!
//! Bi-directional coverage:
//!   - **new finding → old semantic**: phase 3 (sees every canonical
//!     as a candidate).
//!   - **new finding → new semantic**: phase 3 (same).
//!   - **old finding → new semantic**: phase 2 (retro-link consumes
//!     the `pending_semantic` queue against existing
//!     `finding_link_status` rows — i.e. only prior projects'
//!     findings at this point, since phase 3 has not yet promoted
//!     the new findings into that table).
//!
//! Every per-phase knob lives in a phase-scoped `<Phase>SharedArgs`
//! clap struct reused by the standalone CLI subcommands
//! (`learn link`, `learn retro-link`); the merge/extract knobs come
//! from [`MergeCliArgs`] / [`FindingLinkCliArgs`] (same source used
//! by `learn projects` / `learn c4` / `learn moves`). No hardcoded
//! defaults float around the body of this module — every cap /
//! threshold / budget lands as a `default_value_t` on a clap field
//! exactly once.

use clap::Args;
use color_eyre::eyre::{Result, WrapErr};
use knowdit_kg::project_loader::ProjectData;
use llmy::client::client::LLM;

use crate::cli::HistoricalDatabaseArgs;
use crate::cmd::learn::finding_link_args::FindingLinkCliArgs;
use crate::cmd::learn::link::{LinkArgs, LinkSharedArgs};
use crate::cmd::learn::merge_args::MergeCliArgs;
use crate::cmd::learn::retro_link::{RetroLinkArgs, RetroLinkSharedArgs};

#[derive(Args, Debug, Clone)]
pub struct WorkflowLearnArgs {
    /// Project to learn. Format: `name:path` or
    /// `name:path:platform_id`. The path is the repo root; the name
    /// becomes the project entity key in the historical KG.
    #[arg(long = "project", short = 'p')]
    pub project: String,

    /// Historical KG connection. Same flag (`--database-url`,
    /// `DATABASE_URL`) as the standalone `learn` commands.
    #[command(flatten)]
    pub kg: HistoricalDatabaseArgs,

    /// Knobs for the categorize / extract / merge agents.
    /// Shared with `learn projects` / `learn c4` / `learn moves`.
    #[command(flatten)]
    pub merge: MergeCliArgs,

    /// Token budgets + agent caps for the finding-to-semantic
    /// linker. One instance covers both the intra-project link
    /// (phase 2) and retro link (phase 3) — they run on the same
    /// KG with the same prompt shape.
    #[command(flatten)]
    pub finding_link: FindingLinkCliArgs,

    /// Phase-2 retro-link knobs (`--retro-link-concurrency`).
    #[command(flatten)]
    pub retro_link: RetroLinkSharedArgs,

    /// Phase-3 link knobs (`--link-concurrency`,
    /// `--link-include-unlinked`).
    #[command(flatten)]
    pub link: LinkSharedArgs,
}

impl WorkflowLearnArgs {
    pub async fn run(self, primary_llm: &LLM) -> Result<()> {
        self.merge.validate()?;
        self.finding_link.validate()?;
        let kg = self.kg.connect_init().await?;

        // ----- Phase 1: categorize + extract + dedup-merge --------
        let project = ProjectData::from_path_spec(&self.project)
            .await
            .wrap_err_with(|| format!("failed to load project '{}'", self.project))?;
        if project.is_completed(&kg).await? {
            tracing::info!(
                "Project {} already in KG — skipping phase 1 (extract+merge)",
                project.display_id()
            );
        } else {
            tracing::info!(
                "Phase 1: categorize + extract + dedup-merge for {}",
                project.display_id()
            );
            let agent_options = self.merge.to_agent_options();
            let chunking = self.merge.to_chunking_options();
            let extract = project
                .categorize_and_extract(primary_llm, &agent_options, None)
                .await?;

            // Compose Phase 1c admission + pending_semantic enqueue
            // in ONE transaction: write_project_completed_txn returns
            // this project's newly-introduced canonical ids, which
            // we immediately enqueue for Phase 2 retro-link via
            // enqueue_pending_canonical_semantics_txn. A kill
            // between the two writes rolls both back. The
            // single-step `merge_and_write` wrapper is reserved for
            // bulk learn paths that don't run retro-link.
            let txn = kg.begin().await?;
            let new_canonicals = project
                .merge_and_write_txn(&txn, &kg, primary_llm, &extract, &agent_options, chunking)
                .await?;
            let enqueued = kg
                .enqueue_pending_canonical_semantics_txn(&txn, &new_canonicals)
                .await?;
            txn.commit().await?;
            tracing::info!(
                "Phase 1: enqueued {} new canonical semantic(s) for Phase 2 retro-link \
                 (of {} newly introduced)",
                enqueued,
                new_canonicals.len(),
            );
        }

        // ----- Phase 2: retro link --------------------------------
        // Runs before phase 3 so the new project's findings are not
        // yet in `finding_link_status`. That keeps the candidate set
        // here strictly to prior projects' findings, avoiding the
        // wasted LLM round-trip of re-checking the new project's
        // findings against its own new semantics (phase 3 covers
        // that pair).
        tracing::info!(
            "Phase 2: retro-link prior-project findings against new canonical semantics"
        );
        RetroLinkArgs::retro_link(
            &kg,
            primary_llm,
            &self.finding_link,
            &self.retro_link,
            self.merge.context_window_utilization,
        )
        .await?;

        // ----- Phase 3: intra-project finding→semantic link -------
        tracing::info!("Phase 3: link new findings against every canonical semantic");
        LinkArgs::link(
            &kg,
            primary_llm,
            &self.finding_link,
            &self.link,
            self.merge.context_window_utilization,
        )
        .await?;

        tracing::info!("workflow learn complete for {}", self.project);
        Ok(())
    }
}
