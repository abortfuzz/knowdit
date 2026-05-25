//! `agentic fuzz` subcommand: synthesize Foundry fuzzing harnesses for the
//! generated `AuditSpecification`s and run forge against them.
//!
//! Reads `specification` rows from the per-project SQLite database, runs an
//! LLM agent per spec to produce a `.sol` harness, invokes the configured
//! `forge` binary (test + coverage), and persists outcomes to `code_gen` /
//! `harness_run` / `line_coverage`. Resume-safe: a re-run skips specs whose
//! `code_gen` row is already `Completed` unless `--fuzz-regenerate` is set.

use std::path::Path;

use clap::Args;
use color_eyre::eyre::{Result, WrapErr};
use knowdit_audit::harness::forge::ForgeBackend;
use knowdit_audit::harness::solidity::{FuzzOutcome, SolidityFuzzGenerator};
use knowdit_repo_model::RepoDatabase;
use llmy::client::client::LLM;

use super::fuzz_common::{FuzzOptionsBuild, HarnessSharedArgs};
use crate::cli::{DatabaseArgs, LoadedRepoDatabase, ProjectArgs};

/// Fuzz-only knobs (the harness backend itself lives in
/// [`HarnessSharedArgs`], shared with `agentic regen`).
#[derive(Args, Clone, Debug)]
pub struct FuzzSharedArgs {
    /// Cap on number of specs processed in this run. `0` means no cap.
    #[arg(long = "fuzz-max-specs", default_value_t = 0)]
    pub fuzz_max_specs: usize,

    /// Number of specs processed in parallel.
    #[arg(long = "fuzz-concurrency", default_value_t = 1)]
    pub fuzz_concurrency: usize,

    /// Regenerate every harness from scratch — clears `code_gen`,
    /// `harness_run`, and `line_coverage` at the start. Default is
    /// to skip any spec whose `code_gen` row is already `Completed`.
    #[arg(long = "fuzz-regenerate", default_value_t = false)]
    pub fuzz_regenerate: bool,
}

#[derive(Args)]
pub struct FuzzArgs {
    #[command(flatten)]
    pub project: ProjectArgs,

    #[command(flatten)]
    pub db: DatabaseArgs,

    /// Forge backend + per-spec agent budget + Gate 2 threshold.
    /// Shared with `agentic regen` and `workflow autoloop`.
    #[command(flatten)]
    pub harness: HarnessSharedArgs,

    #[command(flatten)]
    pub shared: FuzzSharedArgs,
}

impl FuzzArgs {
    /// CLI entry: open the project DB, build the forge backend,
    /// delegate to [`Self::fuzz`], print one-line summary.
    pub async fn run(self, llm: &LLM) -> Result<()> {
        let LoadedRepoDatabase { spec, repo, .. } = self
            .project
            .to_repo_database(self.db.database_path.clone())
            .await?;
        let backend = self.harness.to_forge_backend()?;
        // Preflight the forge environment before any harness-codegen
        // agent runs, so misconfigured projects fail with forge's own
        // error message instead of burning LLM steps.
        self.harness
            .preflight(&backend, &spec.root)
            .await
            .wrap_err("forge environment preflight failed")?;
        let outcome = Self::fuzz(
            &repo,
            llm,
            &spec.name,
            &spec.root,
            &self.harness,
            &self.shared,
            &backend,
        )
        .await?;
        println!(
            "Fuzz finished: processed={} completed={} abandoned={} error={} violated={} skipped_resumed={}",
            outcome.processed_count,
            outcome.completed_count,
            outcome.abandoned_count,
            outcome.error_count,
            outcome.violated_count,
            outcome.skipped_resumed,
        );
        Ok(())
    }

    /// In-process entry: synthesize Foundry harnesses for every
    /// pending `specification` row in `repo` and drive forge against
    /// them. `backend` is the already-resolved forge runtime (the
    /// caller builds it once with `HarnessSharedArgs::to_forge_backend`
    /// and threads it through, so the `forge coverage --help` probe
    /// runs only once across an autoloop cycle).
    pub async fn fuzz(
        repo: &RepoDatabase,
        llm: &LLM,
        project_name: &str,
        repo_root: &Path,
        harness: &HarnessSharedArgs,
        shared: &FuzzSharedArgs,
        backend: &ForgeBackend,
    ) -> Result<FuzzOutcome> {
        let options = harness.to_fuzz_options(FuzzOptionsBuild {
            repo_root: repo_root.to_path_buf(),
            default_cache_key: format!("{}-knowdit-fuzz", project_name),
            max_specs: shared.fuzz_max_specs,
            concurrency: shared.fuzz_concurrency,
            regenerate: shared.fuzz_regenerate,
            via_ir: harness.harness_via_ir,
        });
        SolidityFuzzGenerator::new(repo, llm, &options, backend.clone())
            .run()
            .await
    }
}
