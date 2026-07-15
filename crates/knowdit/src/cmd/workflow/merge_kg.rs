//! `knowdit workflow merge-kg` — merge another historical KG into this one
//! with semantic dedup. Thin CLI wrapper over [`knowdit_kg::merge_kg`]: opens
//! the source (read-only) and destination KGs, threads the shared merge /
//! finding-link knobs, and runs the merge.

use clap::{Args, ValueEnum};
use color_eyre::eyre::{Result, WrapErr};
use knowdit_kg::db::HistoricalDatabase;
use knowdit_kg::merge_kg::{LinkMode, MergeKgOptions, merge_kg};
use llmy::client::client::LLM;

use crate::cli::HistoricalDatabaseArgs;
use crate::cmd::learn::finding_link_args::FindingLinkCliArgs;
use crate::cmd::learn::merge_args::MergeCliArgs;

#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
pub enum LinkModeArg {
    /// Only the destination's pre-import canonicals are offered as ③b
    /// candidates; overlapping concepts rely on the dedup fold. (Cheapest.)
    Residual,
    /// Present every canonical to ③b — safety net against imperfect folding.
    Full,
    /// Skip the ③b link pass entirely.
    Off,
}

impl From<LinkModeArg> for LinkMode {
    fn from(arg: LinkModeArg) -> Self {
        match arg {
            LinkModeArg::Residual => LinkMode::Residual,
            LinkModeArg::Full => LinkMode::Full,
            LinkModeArg::Off => LinkMode::Off,
        }
    }
}

#[derive(Args, Debug, Clone)]
pub struct MergeKgArgs {
    /// Source KG to merge FROM (read-only). `sqlite://`, `mysql://`,
    /// `postgres://`.
    #[arg(long = "from")]
    pub from: String,

    /// Stable label identifying this source KG, used as the resume key. Re-run
    /// the SAME command (same `--source-key`) after an interruption and the
    /// merge continues instead of re-importing. Kept separate from `--from`
    /// because a connection string can carry credentials; pick a short name
    /// like `sherlock-v4`.
    #[arg(long = "source-key")]
    pub source_key: String,

    /// Destination KG to merge INTO (`--database-url` / `DATABASE_URL`).
    #[command(flatten)]
    pub kg: HistoricalDatabaseArgs,

    /// Knobs for the categorize / extract / merge agents. Shared with
    /// `learn` / `workflow learn`; only the merge caps apply here.
    #[command(flatten)]
    pub merge: MergeCliArgs,

    /// Token budgets + agent caps for the cross-seam finding→semantic linker
    /// (both ③a retro-link and ③b link).
    #[command(flatten)]
    pub finding_link: FindingLinkCliArgs,

    /// Concurrency for the cross-seam link passes.
    #[arg(long, default_value_t = 1)]
    pub link_concurrency: usize,

    /// Skip the ③a retro-link pass (destination findings × source's new
    /// canonical semantics).
    #[arg(long, default_value_t = false)]
    pub no_retro_link: bool,

    /// Scope of the ③b link pass (source's new findings × destination's
    /// semantics).
    #[arg(long, value_enum, default_value_t = LinkModeArg::Residual)]
    pub link_mode: LinkModeArg,
}

impl MergeKgArgs {
    pub async fn run(self, llm: &LLM) -> Result<()> {
        self.merge.validate()?;
        self.finding_link.validate()?;

        let dst = self.kg.connect_init().await?;
        let src = HistoricalDatabase::connect(&self.from)
            .await
            .wrap_err_with(|| format!("failed to connect to source KG at {}", self.from))?;

        // The merge agents pick up `--context-window-utilization` via
        // `to_agent_options`; thread the same knob into the ③a/③b link passes.
        let mut link = self.finding_link.to_options(self.link_concurrency);
        link.context_window_utilization = self.merge.context_window_utilization;

        let options = MergeKgOptions {
            merge_agent: self.merge.to_agent_options(),
            merge_chunking: self.merge.to_chunking_options(),
            link,
            run_retro_link: !self.no_retro_link,
            link_mode: self.link_mode.into(),
            source_key: self.source_key.clone(),
        };

        let report = merge_kg(&src, &dst, llm, options).await?;

        tracing::info!(
            "merge-kg complete: {} project(s) imported; semantics +{} new / {} folded; \
             findings +{} new / {} folded; {} link(s) carried; retro_linked={} linked={}",
            report.projects_imported,
            report.new_semantics,
            report.folded_semantics,
            report.new_findings,
            report.folded_findings,
            report.carried_links,
            report.retro_linked,
            report.linked,
        );
        Ok(())
    }
}
