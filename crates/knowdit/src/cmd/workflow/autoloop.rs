//! `knowdit workflow autoloop` — single-process orchestrator that
//! chains the audit pipeline (call-graph → extract-semantics →
//! map-semantics → loop { gen-specs → fuzz → reflect → regen → dump
//! valid findings }) inside one Rust process.
//!
//! Every phase has both a CLI entry (`<Args>::run`) and an
//! in-process entry (`<Args>::<verb>`, e.g. `FuzzArgs::fuzz`). This
//! module wires the in-process entries together, sharing one
//! [`RepoDatabase`], one [`HistoricalDatabase`], and (typically) one
//! [`LLM`] across the whole run. `reflect` is the exception — it
//! uses its own LLM (`OPT_*` env vars), so a more powerful model
//! can be slotted in as the false-positive gate while the cheaper
//! model handles the bulk fuzzing.
//!
//! Every per-phase knob lives in a phase-scoped `<Phase>SharedArgs`
//! clap struct used by both the standalone CLI subcommand and by
//! this autoloop — there are no hardcoded `60`, `40`, `5` constants
//! floating around. Default values are set with `default_value_t`
//! on the SharedArgs fields exactly once.
//!
//! Crash-safety: every phase's `<verb>` entry already skips rows
//! that landed in a prior invocation, so an interrupted autoloop
//! just re-enters whichever phase still has work. The output folder
//! is overwritten only when `--force-clean-output` is set;
//! otherwise the existing folder is reused so the per-cycle
//! summaries from a previous run remain visible.

use std::path::{Path, PathBuf};

use clap::Args;
use color_eyre::eyre::{Result, WrapErr, eyre};
use knowdit_audit::harness::solidity::FuzzOutcome;
use knowdit_audit::mapper::MapperOutcome;
use knowdit_audit::spec::SpecGenOutcome;
use knowdit_repo_model::LoadedValidFinding;
use llmy::clap::OptOpenAISetup;
use llmy::client::client::LLM;
use serde::Serialize;

use crate::cmd::audit::extract_semantics::{ExtractSemanticsArgs, ExtractSemanticsSharedArgs};
use crate::cmd::audit::fuzz::{FuzzArgs, FuzzSharedArgs};
use crate::cmd::audit::fuzz_common::HarnessSharedArgs;
use crate::cmd::audit::gen_specs::{GenSpecsArgs, GenSpecsSharedArgs};
use crate::cmd::audit::map_semantics::{MapSemanticsArgs, MapSemanticsSharedArgs};
use crate::cmd::audit::profile::{ProfileArgs, ProfileSharedArgs};
use crate::cmd::audit::reflect::{ReflectArgs, ReflectSharedArgs, ReflectStats};
use crate::cmd::audit::regen::{RegenArgs, RegenSharedArgs, RegenStats};
use crate::cmd::solidity::SolidityCallGraphStaticArgs;

#[derive(Args, Debug, Clone)]
pub struct AutoloopArgs {
    /// Project spec. Forwarded verbatim to every phase that talks
    /// to the project DB.
    #[command(flatten)]
    pub project: crate::cli::ProjectArgs,

    /// Per-project SQLite override.
    #[command(flatten)]
    pub db: crate::cli::DatabaseArgs,

    /// Historical KG database. Consumed by `map-semantics`.
    #[command(flatten)]
    pub kg: crate::cli::HistoricalDatabaseArgs,

    /// Project-compile backend choice plus its underlying option groups
    /// (`--project-backend` / `--foundry-profile` / `--via-ir` / `--src` /
    /// `--hardhat-artifacts-dir`). Used only when the call-graph table is
    /// empty and we need to rebuild it before the loop starts.
    #[command(flatten)]
    pub backend: crate::cli::ProjectBackendCliOptions,

    /// Optional secondary LLM used **only** by `reflect`. Flags are
    /// `--opt-openai-url`, `--opt-openai-key`, `--opt-model`, etc.
    /// (env vars `OPT_OPENAI_*`). When `--opt-model` is unset,
    /// `may_llm` returns `None` and the reflect phase falls back to
    /// the primary LLM. Splitting the model means the FP gate can
    /// run on a more capable instance while the bulk loop stays on
    /// a cheaper one.
    #[command(flatten)]
    pub reflect_llm: OptOpenAISetup,

    #[command(flatten)]
    pub extract: ExtractSemanticsSharedArgs,

    #[command(flatten)]
    pub profile: ProfileSharedArgs,

    #[command(flatten)]
    pub map: MapSemanticsSharedArgs,

    #[command(flatten)]
    pub gen_specs: GenSpecsSharedArgs,

    /// Forge backend + harness-agent knobs. One instance shared by
    /// both `fuzz` and `regen` phases.
    #[command(flatten)]
    pub harness: HarnessSharedArgs,

    #[command(flatten)]
    pub fuzz: FuzzSharedArgs,

    #[command(flatten)]
    pub reflect: ReflectSharedArgs,

    #[command(flatten)]
    pub regen: RegenSharedArgs,

    /// Hard ceiling on the number of (gen-specs → fuzz → reflect →
    /// regen) iterations. The loop also exits early when a cycle
    /// produces no new specs, no completed harnesses, no graded
    /// runs, AND no regen attempts — the natural fixed point.
    #[arg(long, default_value_t = 8)]
    pub max_cycles: usize,

    /// Where per-cycle summaries + valid-finding dumps land.
    #[arg(short, long)]
    pub output_folder: PathBuf,

    /// Overwrite an existing `--output-folder`. Without this flag,
    /// an existing folder is reused so prior cycle dumps remain
    /// alongside new ones — matches the resume semantics of every
    /// individual phase.
    #[arg(short, long)]
    pub force_clean_output: bool,
}

impl AutoloopArgs {
    pub async fn run(mut self, primary_llm: &LLM) -> Result<()> {
        self.prepare_output_folder()?;
        // Autoloop owns one `--via-ir` switch at the top level; mirror
        // it onto the shared harness args so the standalone fuzz /
        // regen entries we delegate to pick it up without the user
        // having to also pass `--harness-via-ir`.
        self.harness.harness_via_ir = self.backend.foundry.via_ir;
        // Resolve the forge runtime once for the entire autoloop run.
        // This is the preflight check (errors out if no forge is
        // reachable) AND the source of truth for both fuzz and regen
        // inside the cycle loop — they share the same backend so the
        // `forge coverage --help` probe runs only once per pipeline
        // invocation, not once per phase per cycle.
        let forge_backend = self.harness.to_forge_backend()?;

        let loaded = self
            .project
            .to_repo_database(self.db.database_path.clone())
            .await?;
        let kg = self.kg.connect().await?;
        let spec_name = loaded.spec.name.clone();
        let repo_root = loaded.spec.root.clone();
        let repo = loaded.repo;

        // Preflight the forge environment NOW, before any LLM stage
        // touches the project. Misconfigured projects fail in seconds
        // here instead of after hours of extract/map/spec-gen.
        tracing::info!("[autoloop preflight] verifying forge environment");
        self.harness
            .preflight(&forge_backend, &repo_root)
            .await
            .wrap_err("forge environment preflight failed — fix the project's foundry config / forge-std install and re-run")?;
        tracing::info!("[autoloop preflight] forge environment OK");

        let cg = repo.load_call_graph().await?;
        if cg.contracts.is_empty() {
            tracing::info!("No contracts in call graph — running static call-graph phase");
            SolidityCallGraphStaticArgs::update_call_graph(&repo, &repo_root, &self.backend)
                .await?;
        }
        let cg = repo.load_call_graph().await?;
        if cg.contracts.is_empty() {
            return Err(eyre!(
                "no available contracts found after call-graph rebuild"
            ));
        }

        let reflect_llm = self
            .reflect_llm
            .clone()
            .may_llm()
            .await
            .map_err(|err| eyre!("failed to build reflect LLM: {err}"))?
            .unwrap_or_else(|| primary_llm.clone());

        let project_data = self.project.to_project_data().await?;
        let semantics = ExtractSemanticsArgs::extract_semantics(
            &repo,
            primary_llm,
            &project_data,
            &self.extract,
        )
        .await?;
        tracing::info!(
            "Project has {} extract-semantic(s) available for mapping",
            semantics.len()
        );

        // Profile phase (plan §5.4 / §1.1): runs once between extract
        // and map. Resume-safe via `get_project_profile()` inside the
        // generator — if a profile is already cached, this is a cheap
        // DB read.
        let profile =
            ProfileArgs::profile(&repo, primary_llm, &spec_name, &repo_root, &self.profile).await?;
        tracing::info!(
            "Profile ready: {} subsystem(s), {} core component(s)",
            profile.subsystems.len(),
            profile.core_components.len(),
        );

        let match_set = repo.load_semantic_match_results().await?;
        if match_set.matches.is_empty() {
            tracing::info!("No mapped semantics yet — running map-semantics phase");
            let outcome: MapperOutcome =
                MapSemanticsArgs::map_semantics(&repo, &kg, primary_llm, &spec_name, &self.map)
                    .await?;
            tracing::info!(
                "Mapper finished: {} matched pair(s) (High={}/Medium={}/Low={}), {} unmatched extract(s)",
                outcome.matched_pair_count,
                outcome.strength_counts.high,
                outcome.strength_counts.medium,
                outcome.strength_counts.low,
                outcome.unmatched_extract_count,
            );
        }

        for cycle in 1..=self.max_cycles {
            tracing::info!("Audit loop cycle {cycle}");

            let spec_outcome: SpecGenOutcome =
                GenSpecsArgs::gen_specs(&repo, primary_llm, &spec_name, &self.gen_specs).await?;
            tracing::info!(
                "Cycle {cycle} gen-specs: {} link(s), {} built, {} abandoned, {} spec(s)",
                spec_outcome.link_count,
                spec_outcome.built_link_count,
                spec_outcome.abandoned_link_count,
                spec_outcome.total_specs,
            );

            let fuzz_outcome: FuzzOutcome = FuzzArgs::fuzz(
                &repo,
                primary_llm,
                &spec_name,
                &repo_root,
                &self.harness,
                &self.fuzz,
                &forge_backend,
            )
            .await?;
            tracing::info!(
                "Cycle {cycle} fuzz: processed={} completed={} violated={}",
                fuzz_outcome.processed_count,
                fuzz_outcome.completed_count,
                fuzz_outcome.violated_count,
            );

            let reflect_stats: ReflectStats =
                ReflectArgs::reflect(&repo, &reflect_llm, &spec_name, &self.reflect).await?;
            tracing::info!(
                "Cycle {cycle} reflect: graded={} valid={} expected={} oos={} incomplete={}",
                reflect_stats.graded,
                reflect_stats.valid_finding,
                reflect_stats.expected_violation,
                reflect_stats.out_of_scope,
                reflect_stats.incomplete_step + reflect_stats.incomplete_spec,
            );

            let regen_stats: RegenStats = RegenArgs::regen(
                &repo,
                primary_llm,
                &spec_name,
                &repo_root,
                &self.harness,
                &self.regen,
                &forge_backend,
            )
            .await?;
            tracing::info!(
                "Cycle {cycle} regen: codegen={} spec={} escalated={}",
                regen_stats.codegen_regen,
                regen_stats.spec_regen,
                regen_stats.escalated_chain_depth,
            );

            let valid_findings = repo.load_valid_findings().await?;
            let cycle_summary = CycleSummary {
                cycle,
                gen_specs: (&spec_outcome).into(),
                fuzz: (&fuzz_outcome).into(),
                reflect: (&reflect_stats).into(),
                regen: (&regen_stats).into(),
                valid_finding_total: valid_findings.len(),
            };
            cycle_summary.write_to(&self.output_folder, &valid_findings)?;

            let did_work = spec_outcome.total_specs > 0
                || fuzz_outcome.completed_count > 0
                || reflect_stats.graded > 0
                || regen_stats.codegen_regen + regen_stats.spec_regen > 0;
            if !did_work {
                tracing::info!(
                    "Cycle {cycle} produced no new specs / completions / verdicts / regens; \
                     reached fixed point — exiting"
                );
                break;
            }
        }
        Ok(())
    }

    /// Wipe / create the `--output-folder`. Reused on resume runs
    /// when `--force-clean-output` is unset — existing cycle dumps
    /// are kept so prior runs remain visible alongside new ones.
    fn prepare_output_folder(&self) -> Result<()> {
        let out = &self.output_folder;
        if out.exists() {
            if self.force_clean_output {
                std::fs::remove_dir_all(out)
                    .wrap_err_with(|| format!("failed to clean output folder {}", out.display()))?;
            } else {
                tracing::info!(
                    "Reusing existing output folder {} (pass --force-clean-output to wipe)",
                    out.display()
                );
            }
        }
        std::fs::create_dir_all(out)
            .wrap_err_with(|| format!("failed to create output folder {}", out.display()))?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Per-cycle artifacts
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
struct CycleSummary {
    cycle: usize,
    gen_specs: SpecCounts,
    fuzz: FuzzCounts,
    reflect: ReflectCounts,
    regen: RegenCounts,
    /// Cumulative across all cycles so far — not just this cycle.
    valid_finding_total: usize,
}

#[derive(Debug, Serialize)]
struct SpecCounts {
    link_count: usize,
    built_link_count: usize,
    abandoned_link_count: usize,
    total_specs: usize,
}
impl From<&SpecGenOutcome> for SpecCounts {
    fn from(o: &SpecGenOutcome) -> Self {
        Self {
            link_count: o.link_count,
            built_link_count: o.built_link_count,
            abandoned_link_count: o.abandoned_link_count,
            total_specs: o.total_specs,
        }
    }
}

#[derive(Debug, Serialize)]
struct FuzzCounts {
    processed: usize,
    completed: usize,
    abandoned: usize,
    error: usize,
    violated: usize,
    skipped_resumed: usize,
}
impl From<&FuzzOutcome> for FuzzCounts {
    fn from(o: &FuzzOutcome) -> Self {
        Self {
            processed: o.processed_count,
            completed: o.completed_count,
            abandoned: o.abandoned_count,
            error: o.error_count,
            violated: o.violated_count,
            skipped_resumed: o.skipped_resumed,
        }
    }
}

#[derive(Debug, Serialize)]
struct ReflectCounts {
    examined: usize,
    graded: usize,
    valid_finding: usize,
    expected_violation: usize,
    out_of_scope: usize,
    incomplete_step: usize,
    incomplete_spec: usize,
    severity_high: usize,
    severity_medium: usize,
    severity_low: usize,
}
impl From<&ReflectStats> for ReflectCounts {
    fn from(s: &ReflectStats) -> Self {
        Self {
            examined: s.examined,
            graded: s.graded,
            valid_finding: s.valid_finding,
            expected_violation: s.expected_violation,
            out_of_scope: s.out_of_scope,
            incomplete_step: s.incomplete_step,
            incomplete_spec: s.incomplete_spec,
            severity_high: s.severity_high,
            severity_medium: s.severity_medium,
            severity_low: s.severity_low,
        }
    }
}

#[derive(Debug, Serialize)]
struct RegenCounts {
    examined: usize,
    codegen_regen: usize,
    spec_regen: usize,
    escalated_chain_depth: usize,
    errors: usize,
}
impl From<&RegenStats> for RegenCounts {
    fn from(s: &RegenStats) -> Self {
        Self {
            examined: s.examined,
            codegen_regen: s.codegen_regen,
            spec_regen: s.spec_regen,
            escalated_chain_depth: s.escalated_chain_depth,
            errors: s.errors,
        }
    }
}

impl CycleSummary {
    /// Dump this cycle's summary JSON + a snapshot of every valid
    /// finding under `<output>/cycle_<n>/`. The PoC harness source
    /// is also written verbatim as `finding_<reflection_id>.sol` so
    /// a human reviewer can drop it into a forge project immediately.
    fn write_to(&self, output_folder: &Path, valid_findings: &[LoadedValidFinding]) -> Result<()> {
        let cycle_dir = output_folder.join(format!("cycle_{:03}", self.cycle));
        std::fs::create_dir_all(&cycle_dir)
            .wrap_err_with(|| format!("failed to create {}", cycle_dir.display()))?;
        std::fs::write(
            cycle_dir.join("summary.json"),
            serde_json::to_string_pretty(self)?,
        )?;

        let findings_dir = cycle_dir.join("valid_findings");
        if !valid_findings.is_empty() {
            std::fs::create_dir_all(&findings_dir)
                .wrap_err_with(|| format!("failed to create {}", findings_dir.display()))?;
        }
        let mut digest: Vec<FindingDigest> = Vec::with_capacity(valid_findings.len());
        for vf in valid_findings {
            std::fs::write(
                findings_dir.join(format!("finding_{}.sol", vf.reflection_id)),
                &vf.harness_source,
            )?;
            std::fs::write(
                findings_dir.join(format!("finding_{}.json", vf.reflection_id)),
                serde_json::to_string_pretty(vf)?,
            )?;
            digest.push(FindingDigest {
                reflection_id: vf.reflection_id,
                spec_id: vf.spec_id,
                severity: vf.severity.clone(),
                verdict_reason: vf.verdict_reason.clone(),
                severity_reason: vf.severity_reason.clone(),
                harness_relative_path: vf.harness_relative_path.clone(),
            });
        }
        std::fs::write(
            cycle_dir.join("findings.json"),
            serde_json::to_string_pretty(&digest)?,
        )?;
        Ok(())
    }
}

#[derive(Debug, Serialize)]
struct FindingDigest {
    reflection_id: i32,
    spec_id: i32,
    severity: String,
    verdict_reason: String,
    severity_reason: String,
    harness_relative_path: String,
}
