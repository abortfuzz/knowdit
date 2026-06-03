//! `knowdit workflow streamloop` — bounded per-link pipeline.
//!
//! The CLI runs the one-shot prologue (project DB / KG / call-graph /
//! extract-semantics / profile / map-semantics / spec-stream prep) once,
//! then hands the prepared [`SpecGenStream`] to [`LinkScheduler`]. The
//! scheduler keeps `--stream-link-concurrency` link pipelines flowing at
//! once: each link claims one [`PlannedLinkWork`], runs **gen-spec →
//! (fuzz → reflect → regen)\* → snapshot** independently, and as soon
//! as one finishes the scheduler advances the next planned link onto
//! the freed worker slot.
//!
//! Resume safety lives at two layers:
//!
//! * **Project DB**: every phase (spec gen, fuzz, reflect, regen) already
//!   has its own skip-if-done logic, so re-running the same streamloop
//!   never replays committed work.
//! * **On-disk snapshots**: written atomically per link into
//!   `<output>/summaries/link_summary_NNNN.json` (4-digit zero-padded
//!   ordinal for natural `ls` order). The file appears only after
//!   the link's pipeline converged or hit `--max-inner-cycles-per-batch`.
//!   A crash mid-link leaves the DB consistent and at most a
//!   `link_summary_NNNN.json.tmp` file (ignored by the next run).
//!   Already-snapshotted links short-circuit on resume so we don't
//!   spend LLM tokens re-running converged work.

use std::path::PathBuf;
use std::sync::Arc;

use clap::Args;
use color_eyre::eyre::{Result, WrapErr, eyre};
use knowdit_audit::harness::forge::ForgeBackend;
use knowdit_audit::harness::solidity::SolidityHarnessGenerator;
use knowdit_audit::mapper::MapperOutcome;
use knowdit_audit::spec::{
    LinkKey, LinkSpecOutcome, LinkSpecStatus, PlannedLinkWork, SpecGenOptions, SpecGenStream,
    SpecificationGenerator,
};
use knowdit_audit::types::AuditSpecification;
use knowdit_kg_model::db::semantic_finding_link;
use knowdit_repo_model::{CodeGenStatus, LoadedValidFinding, RepoDatabase, SemanticMatch};
use llmy::clap::OptOpenAISetup;
use llmy::client::client::LLM;
use serde::Serialize;
use tokio::sync::Mutex;
use tokio::task::JoinSet;

use crate::cmd::audit::extract_semantics::{ExtractSemanticsArgs, ExtractSemanticsSharedArgs};
use crate::cmd::audit::fuzz::FuzzSharedArgs;
use crate::cmd::audit::fuzz_common::{FuzzOptionsBuild, HarnessSharedArgs};
use crate::cmd::audit::gen_specs::GenSpecsSharedArgs;
use crate::cmd::audit::map_semantics::{MapSemanticsArgs, MapSemanticsSharedArgs};
use crate::cmd::audit::profile::{ProfileArgs, ProfileSharedArgs};
use crate::cmd::audit::reflect::{ReflectArgs, ReflectSharedArgs};
use crate::cmd::audit::regen::{RegenArgs, RegenSharedArgs};
use crate::cmd::solidity::SolidityCallGraphStaticArgs;

#[derive(Args, Debug, Clone)]
pub struct StreamloopArgs {
    #[command(flatten)]
    pub project: crate::cli::ProjectArgs,

    #[command(flatten)]
    pub db: crate::cli::DatabaseArgs,

    #[command(flatten)]
    pub kg: crate::cli::HistoricalDatabaseArgs,

    #[command(flatten)]
    pub backend: crate::cli::ProjectBackendCliOptions,

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

    #[command(flatten)]
    pub harness: HarnessSharedArgs,

    #[command(flatten)]
    pub fuzz: FuzzSharedArgs,

    #[command(flatten)]
    pub reflect: ReflectSharedArgs,

    #[command(flatten)]
    pub regen: RegenSharedArgs,

    /// Safety cap on how many fuzz → reflect → regen lineage passes one
    /// link's pipeline may run before it is summarized and the worker
    /// slot is released. Prevents a single pathological spec from
    /// monopolizing one of the `--stream-link-concurrency` workers.
    #[arg(long, default_value_t = 8)]
    pub max_inner_cycles_per_batch: usize,

    /// Number of link pipelines kept active at once. Raising this lets
    /// quick links snapshot while a slow link is still fuzzing in
    /// another worker. Defaults to `1` when omitted. Typed `Option`
    /// so `--default-concurrency` can fill it in only when the user
    /// didn't pass an explicit value.
    #[arg(long)]
    pub stream_link_concurrency: Option<usize>,

    /// Fallback concurrency for every sub-phase
    /// (`--gen-specs-concurrency`, `--fuzz-concurrency`,
    /// `--reflect-concurrency`, `--regen-concurrency`,
    /// `--stream-link-concurrency`) when that per-phase flag is left
    /// unset. Per-phase flags ALWAYS win when present, so it's safe
    /// to combine `-d 4` with e.g. `--fuzz-concurrency 1` to crank
    /// everything except fuzz.
    #[arg(short = 'd', long)]
    pub default_concurrency: Option<usize>,

    /// llmy cache-key prefix used when each link runs its own
    /// `fuzz_one_existing_spec`. Defaults to
    /// `{project_name}-knowdit-fuzz` (same convention as `agentic fuzz`).
    #[arg(long)]
    pub stream_fuzz_cache_key: Option<String>,

    /// Output folder for per-link `summary.json` files. The directory
    /// layout is deterministic on `(extract, historical, finding)`, so
    /// re-running with the same folder safely resumes — links whose
    /// `summary.json` is already present are skipped end-to-end.
    #[arg(short, long)]
    pub output_folder: PathBuf,

    /// `rm -rf` the output folder before the run. Off by default so
    /// resume works.
    #[arg(short, long)]
    pub force_clean_output: bool,
}

impl StreamloopArgs {
    pub async fn run(mut self, primary_llm: &LLM) -> Result<()> {
        self.apply_default_concurrency();
        tracing::info!("[streamloop stage 1/8] preparing output folder");
        self.prepare_output_folder()?;
        self.harness.harness_via_ir = self.backend.foundry.via_ir;
        let forge_backend = self.harness.to_forge_backend()?;

        tracing::info!("[streamloop stage 2/8] loading project DB and connecting to KG");
        let loaded = self
            .project
            .to_repo_database(self.db.database_path.clone())
            .await?;
        let kg = self.kg.connect().await?;
        let spec_name = loaded.spec.name.clone();
        let repo_root = loaded.spec.root.clone();
        let repo = loaded.repo;
        tracing::info!(
            "[streamloop stage 2/8] DB ready (project={}, repo_root={})",
            spec_name,
            repo_root.display(),
        );

        tracing::info!("[streamloop preflight] verifying forge environment");
        self.harness
            .preflight(&forge_backend, &repo_root)
            .await
            .wrap_err("forge environment preflight failed — fix the project's foundry config / forge-std install and re-run")?;
        tracing::info!("[streamloop preflight] forge environment OK");

        tracing::info!("[streamloop stage 3/8] loading call graph");
        let cg = repo.load_call_graph().await?;
        if cg.contracts.is_empty() {
            tracing::info!(
                "[streamloop stage 3/8] no contracts in call graph — running static call-graph phase"
            );
            SolidityCallGraphStaticArgs::update_call_graph(&repo, &repo_root, &self.backend)
                .await?;
        }
        let cg = repo.load_call_graph().await?;
        if cg.contracts.is_empty() {
            return Err(eyre!(
                "no available contracts found after call-graph rebuild"
            ));
        }
        tracing::info!(
            "[streamloop stage 3/8] call graph ready: {} contract(s)",
            cg.contracts.len()
        );

        let reflect_llm = self
            .reflect_llm
            .clone()
            .may_llm()
            .await
            .map_err(|err| eyre!("failed to build reflect LLM: {err}"))?
            .unwrap_or_else(|| primary_llm.clone());

        tracing::info!("[streamloop stage 4/8] extracting project semantics");
        let project_data = self.project.to_project_data().await?;
        let semantics = ExtractSemanticsArgs::extract_semantics(
            &repo,
            primary_llm,
            &project_data,
            &self.extract,
        )
        .await?;
        tracing::info!(
            "[streamloop stage 4/8] extracted {} project semantic(s)",
            semantics.len()
        );

        tracing::info!("[streamloop stage 5/8] building project profile");
        let profile =
            ProfileArgs::profile(&repo, primary_llm, &spec_name, &repo_root, &self.profile).await?;
        tracing::info!(
            "[streamloop stage 5/8] profile ready: {} subsystem(s), {} core component(s)",
            profile.subsystems.len(),
            profile.core_components.len(),
        );

        tracing::info!("[streamloop stage 6/8] mapping extract↔historical semantics");
        let match_set = repo.load_semantic_match_results().await?;
        if match_set.matches.is_empty() {
            let outcome: MapperOutcome =
                MapSemanticsArgs::map_semantics(&repo, &kg, primary_llm, &spec_name, &self.map)
                    .await?;
            tracing::info!(
                "[streamloop stage 6/8] mapper finished: {} matched pair(s) (H/M/L = {}/{}/{}), {} unmatched",
                outcome.matched_pair_count,
                outcome.strength_counts.high,
                outcome.strength_counts.medium,
                outcome.strength_counts.low,
                outcome.unmatched_extract_count,
            );
        } else {
            tracing::info!(
                "[streamloop stage 6/8] mapper output already present: {} matched pair(s) — skipping",
                match_set.matches.len(),
            );
        }

        tracing::info!("[streamloop stage 7/8] preparing spec-gen stream");
        let gen_options = build_spec_options(&spec_name, &self.gen_specs);
        let stream = match SpecificationGenerator::new()
            .prepare_stream(&repo, &gen_options)
            .await?
        {
            Some(s) => s,
            None => {
                tracing::warn!(
                    "[streamloop stage 7/8] no pending links after planner/resume filters — nothing to do"
                );
                return Ok(());
            }
        };

        tracing::info!(
            "[streamloop stage 8/8] running bounded link pipeline: {} link(s), active_limit={}",
            stream.total_links(),
            self.stream_link_concurrency.unwrap_or(1).max(1),
        );
        let fuzz_cache_key = self
            .stream_fuzz_cache_key
            .clone()
            .unwrap_or_else(|| format!("{}-knowdit-fuzz", spec_name));
        let ctx = Arc::new(LinkContext {
            repo,
            primary_llm: primary_llm.clone(),
            reflect_llm,
            spec_name,
            repo_root,
            forge_backend,
            harness: self.harness.clone(),
            fuzz: self.fuzz.clone(),
            reflect: self.reflect.clone(),
            regen: self.regen.clone(),
            output_folder: self.output_folder.clone(),
            max_inner_cycles: self.max_inner_cycles_per_batch.max(1),
            fuzz_cache_key,
        });
        let scheduler = LinkScheduler {
            ctx,
            concurrency: self.stream_link_concurrency.unwrap_or(1).max(1),
        };
        let stats = scheduler.run(stream).await?;
        tracing::info!(
            "Streamloop finished: processed_links={} built_specs={} abandoned_links={} skipped_resumed={}",
            stats.processed_links,
            stats.built_specs,
            stats.abandoned_links,
            stats.skipped_resumed,
        );
        Ok(())
    }

    /// Fill in every per-phase concurrency knob that the user did
    /// NOT pass explicitly with `--default-concurrency`. Per-phase
    /// values that ARE present win — `-d 4 --fuzz-concurrency 1`
    /// runs fuzz serially with everything else at 4.
    fn apply_default_concurrency(&mut self) {
        let Some(d) = self.default_concurrency else {
            return;
        };
        let d = d.max(1);
        self.gen_specs.gen_specs_concurrency.get_or_insert(d);
        self.fuzz.fuzz_concurrency.get_or_insert(d);
        self.reflect.reflect_concurrency.get_or_insert(d);
        self.regen.regen_concurrency.get_or_insert(d);
        self.stream_link_concurrency.get_or_insert(d);
        tracing::info!(
            "[streamloop] --default-concurrency={d} fills in gen-specs={} fuzz={} reflect={} regen={} stream-link={} (explicit per-phase flags win)",
            self.gen_specs.gen_specs_concurrency.unwrap_or(1),
            self.fuzz.fuzz_concurrency.unwrap_or(1),
            self.reflect.reflect_concurrency.unwrap_or(1),
            self.regen.regen_concurrency.unwrap_or(1),
            self.stream_link_concurrency.unwrap_or(1),
        );
    }

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

fn build_spec_options(project_name: &str, shared: &GenSpecsSharedArgs) -> SpecGenOptions {
    SpecGenOptions {
        max_agent_steps: shared.gen_specs_max_agent_steps,
        max_specs_per_link: shared.gen_specs_max_specs_per_link,
        compact_context_threshold_tokens: shared.gen_specs_compact_context_threshold_tokens,
        cache_key: shared
            .gen_specs_cache_key
            .clone()
            .unwrap_or_else(|| format!("{}-knowdit-spec", project_name)),
        debug_prefix: shared.gen_specs_debug_prefix.clone(),
        llm_settings: None,
        max_links: (shared.gen_specs_max_links > 0).then_some(shared.gen_specs_max_links),
        max_findings_per_historical: (shared.gen_specs_max_findings_per_historical > 0)
            .then_some(shared.gen_specs_max_findings_per_historical),
        max_links_per_extract: (shared.gen_specs_max_links_per_extract > 0)
            .then_some(shared.gen_specs_max_links_per_extract),
        concurrency: 1,
        regenerate: shared.gen_specs_regenerate,
        min_strength: shared.gen_specs_min_strength.into(),
        min_link_strength: shared.gen_specs_min_link_strength.into(),
    }
}

// ---------------------------------------------------------------------------
// Per-link execution context
// ---------------------------------------------------------------------------

/// Immutable per-run context shared by every link pipeline. Built once
/// at the bottom of `StreamloopArgs::run` and cloned via `Arc` into each
/// worker. Everything a single link needs to drive itself end-to-end —
/// repo handle, both LLMs, forge backend, the four phase arg-sets, and
/// the resolved `fuzz_cache_key` — lives here.
struct LinkContext {
    repo: RepoDatabase,
    primary_llm: LLM,
    reflect_llm: LLM,
    spec_name: String,
    repo_root: PathBuf,
    forge_backend: ForgeBackend,
    harness: HarnessSharedArgs,
    fuzz: FuzzSharedArgs,
    reflect: ReflectSharedArgs,
    regen: RegenSharedArgs,
    output_folder: PathBuf,
    max_inner_cycles: usize,
    fuzz_cache_key: String,
}

impl LinkContext {
    /// Drive one claimed link end-to-end. Short-circuits at the top
    /// if the per-link snapshot already exists for that ordinal — a
    /// previous run already converged it, and re-running would burn
    /// LLM tokens for no new output.
    async fn run_link(self: Arc<Self>, work: PlannedLinkWork) -> Result<LinkTally> {
        let key = work.link_key();
        let ordinal = work.ordinal();
        let total = work.total_links();
        let snapshot_path = self.snapshot_path(ordinal);

        if snapshot_path.exists() {
            tracing::info!(
                "[streamloop link {ordinal:04}/{total}] resume hit: {} already exists — skipping",
                snapshot_path.display(),
            );
            return Ok(LinkTally::skipped());
        }

        let link_started = std::time::Instant::now();
        tracing::info!(
            "[streamloop link {ordinal:04}/{total}] gen-specs: starting (extract={}, hist={}, find={})",
            key.extract_id,
            key.historical_id,
            key.finding_id,
        );
        let gen_specs_started = std::time::Instant::now();
        let outcome = work.run(&self.repo, &self.primary_llm).await;
        tracing::info!(
            "[streamloop link {ordinal:04}/{total}] gen-specs: finished — status={} {} spec(s) committed, {} step(s), {} compaction(s) ({})",
            snapshot_status(outcome.status),
            outcome.specifications.len(),
            outcome.steps,
            outcome.compact_count,
            fmt_elapsed(gen_specs_started.elapsed()),
        );

        let mut drain = LinkDrainCounts::default();
        let mut code_gen_ids: Vec<i32> = Vec::new();
        let mut cycles_run = 0usize;

        if !outcome.specifications.is_empty() {
            let mut active: Vec<i32> = outcome.specification_ids.clone();
            for cycle in 1..=self.max_inner_cycles {
                if active.is_empty() {
                    break;
                }
                active = self
                    .advance_cycle(ordinal, cycle, &active, &mut drain, &mut code_gen_ids)
                    .await?;
                cycles_run = cycle;
            }
        } else {
            tracing::info!(
                "[streamloop link {ordinal:04}/{total}] no committed specs — writing terminal summary",
            );
        }

        self.write_snapshot(ordinal, total, &key, &outcome, &drain, &code_gen_ids)?;
        self.dump_valid_findings().await?;
        tracing::info!(
            "[streamloop link {ordinal:04}/{total}] DONE — {} cycle(s), {} codegen(s), \
             fuzz[completed/violated]={}/{}, reflect_graded={}, regen[codegen/spec]={}/{} ({} total)",
            cycles_run,
            code_gen_ids.len(),
            drain.fuzz_completed,
            drain.fuzz_violated,
            drain.reflect_graded,
            drain.regen_codegen,
            drain.regen_spec,
            fmt_elapsed(link_started.elapsed()),
        );
        Ok(LinkTally::from_outcome(&outcome))
    }

    /// Mirror every `valid_finding` row in the DB to disk under
    /// `<output_folder>/valid_findings/finding_{reflection_id}.json`,
    /// one file per reflection. Idempotent: existing files are left
    /// untouched so the dozens of concurrent link tasks don't keep
    /// re-serializing the same finding. The on-disk shape is
    /// [`OnDiskFinding`] — the raw [`LoadedValidFinding`] row is
    /// flattened in, and two extra fields are added on top: the
    /// parsed [`AuditSpecification`] (so readers don't need a second
    /// JSON parse) and the `(extract_id, historical_id, finding_id)`
    /// link triple that produced the spec, with both halves of the
    /// link's strength / evidence pair (fetched via
    /// [`RepoDatabase::load_link_for_spec`]). Writes go through
    /// tmp+rename so a crash mid-write can't leave a half-finding on
    /// disk.
    async fn dump_valid_findings(&self) -> Result<()> {
        let dir = self.output_folder.join("valid_findings");
        std::fs::create_dir_all(&dir)
            .wrap_err_with(|| format!("failed to create {}", dir.display()))?;
        let findings = self
            .repo
            .load_valid_findings()
            .await
            .wrap_err("failed to load valid_findings for streamloop dump")?;
        for loaded in findings {
            let final_path = dir.join(format!("finding_{}.json", loaded.reflection_id));
            if final_path.exists() {
                continue;
            }
            let reflection_id = loaded.reflection_id;
            let spec_id = loaded.spec_id;
            let link = self.repo.load_link_for_spec(spec_id).await?;
            let on_disk = OnDiskFinding::build(loaded, link);
            let tmp_path = dir.join(format!("finding_{}.json.tmp", reflection_id));
            let body = serde_json::to_string_pretty(&on_disk)
                .wrap_err("failed to JSON-serialize valid finding")?;
            std::fs::write(&tmp_path, body)
                .wrap_err_with(|| format!("failed to write {}", tmp_path.display()))?;
            std::fs::rename(&tmp_path, &final_path).wrap_err_with(|| {
                format!(
                    "failed to atomically rename {} → {}",
                    tmp_path.display(),
                    final_path.display()
                )
            })?;
        }
        Ok(())
    }

    /// One fuzz → reflect → regen iteration for the link's currently
    /// active `spec_id`s. Returns the **next round's** active spec ids
    /// (the regen-produced `child_specs`); empty when the link has
    /// converged.
    async fn advance_cycle(
        &self,
        ordinal: usize,
        cycle: usize,
        active_spec_ids: &[i32],
        drain: &mut LinkDrainCounts,
        code_gen_ids: &mut Vec<i32>,
    ) -> Result<Vec<i32>> {
        let cycle_started = std::time::Instant::now();
        tracing::info!(
            "[streamloop link {ordinal:04}] cycle {cycle}/{}: starting with {} active spec(s)",
            self.max_inner_cycles,
            active_spec_ids.len(),
        );
        let produced = self
            .fuzz_active_specs(ordinal, cycle, active_spec_ids, drain)
            .await?;
        code_gen_ids.extend(produced.iter().copied());

        self.reflect_produced_codegens(ordinal, cycle, &produced, drain)
            .await?;

        let (children, child_code_gens) = self
            .regen_active_specs(ordinal, cycle, active_spec_ids, drain)
            .await?;
        code_gen_ids.extend(child_code_gens);
        tracing::info!(
            "[streamloop link {ordinal:04}] cycle {cycle}/{}: finished — {} spec(s) feed into next cycle ({} total)",
            self.max_inner_cycles,
            children.len(),
            fmt_elapsed(cycle_started.elapsed()),
        );
        Ok(children)
    }

    async fn fuzz_active_specs(
        &self,
        ordinal: usize,
        cycle: usize,
        active_spec_ids: &[i32],
        drain: &mut LinkDrainCounts,
    ) -> Result<Vec<i32>> {
        let total = active_spec_ids.len();
        tracing::info!(
            "[streamloop link {ordinal:04}] cycle {cycle}/{}: fuzz {} spec(s) starting",
            self.max_inner_cycles,
            total,
        );
        let phase_started = std::time::Instant::now();
        let fuzz_options = self.harness.to_fuzz_options(FuzzOptionsBuild {
            repo_root: self.repo_root.clone(),
            default_cache_key: self.fuzz_cache_key.clone(),
            max_specs: 0,
            concurrency: self.fuzz.fuzz_concurrency.unwrap_or(1).max(1),
            regenerate: self.fuzz.fuzz_regenerate,
            via_ir: self.harness.harness_via_ir,
        });
        let fuzz_generator = SolidityHarnessGenerator::new(
            self.harness.harness_mode.into(),
            &self.repo,
            &self.primary_llm,
            &fuzz_options,
            self.forge_backend.clone(),
        );
        let mut produced = Vec::new();
        let mut completed = 0usize;
        let mut violated = 0usize;
        for (idx, &spec_id) in active_spec_ids.iter().enumerate() {
            let spec_started = std::time::Instant::now();
            tracing::info!(
                "[streamloop link {ordinal:04}] cycle {cycle}/{} fuzz {}/{}: starting spec_id={spec_id}",
                self.max_inner_cycles,
                idx + 1,
                total,
            );
            if let Some(fuzzed) = fuzz_generator.fuzz_one_existing_spec(spec_id).await? {
                let was_completed = matches!(fuzzed.status, CodeGenStatus::Completed);
                drain.fuzz_completed += usize::from(was_completed);
                drain.fuzz_violated += usize::from(fuzzed.any_violation);
                completed += usize::from(was_completed);
                violated += usize::from(fuzzed.any_violation);
                produced.push(fuzzed.code_gen_id);
                tracing::info!(
                    "[streamloop link {ordinal:04}] cycle {cycle}/{} fuzz {}/{} done: spec_id={spec_id} code_gen_id={} status={:?} violated={} ({})",
                    self.max_inner_cycles,
                    idx + 1,
                    total,
                    fuzzed.code_gen_id,
                    fuzzed.status,
                    fuzzed.any_violation,
                    fmt_elapsed(spec_started.elapsed()),
                );
            } else {
                tracing::info!(
                    "[streamloop link {ordinal:04}] cycle {cycle}/{} fuzz {}/{} skipped: spec_id={spec_id} (no fuzzable codegen) ({})",
                    self.max_inner_cycles,
                    idx + 1,
                    total,
                    fmt_elapsed(spec_started.elapsed()),
                );
            }
        }
        tracing::info!(
            "[streamloop link {ordinal:04}] cycle {cycle}/{}: fuzz finished — {}/{} completed, {}/{} violated, produced {} codegen(s) ({})",
            self.max_inner_cycles,
            completed,
            total,
            violated,
            total,
            produced.len(),
            fmt_elapsed(phase_started.elapsed()),
        );
        Ok(produced)
    }

    async fn reflect_produced_codegens(
        &self,
        ordinal: usize,
        cycle: usize,
        produced: &[i32],
        drain: &mut LinkDrainCounts,
    ) -> Result<()> {
        tracing::info!(
            "[streamloop link {ordinal:04}] cycle {cycle}/{}: reflect {} codegen(s) starting",
            self.max_inner_cycles,
            produced.len(),
        );
        let phase_started = std::time::Instant::now();
        let stats = ReflectArgs::reflect_code_gens(
            &self.repo,
            &self.reflect_llm,
            &self.spec_name,
            &self.repo_root,
            &self.reflect,
            produced,
        )
        .await?;
        drain.reflect_graded += stats.graded;
        tracing::info!(
            "[streamloop link {ordinal:04}] cycle {cycle}/{}: reflect finished — \
             graded={} valid={} expected={} suspect={} incomplete_step={} incomplete_spec={} out_of_scope={} \
             severity[H/M/L]={}/{}/{} ({})",
            self.max_inner_cycles,
            stats.graded,
            stats.valid_finding,
            stats.expected_violation,
            stats.graded.saturating_sub(
                stats.valid_finding
                    + stats.expected_violation
                    + stats.incomplete_step
                    + stats.incomplete_spec
                    + stats.out_of_scope
            ),
            stats.incomplete_step,
            stats.incomplete_spec,
            stats.out_of_scope,
            stats.severity_high,
            stats.severity_medium,
            stats.severity_low,
            fmt_elapsed(phase_started.elapsed()),
        );
        Ok(())
    }

    async fn regen_active_specs(
        &self,
        ordinal: usize,
        cycle: usize,
        active_spec_ids: &[i32],
        drain: &mut LinkDrainCounts,
    ) -> Result<(Vec<i32>, Vec<i32>)> {
        tracing::info!(
            "[streamloop link {ordinal:04}] cycle {cycle}/{}: regen scoped to {} spec(s) starting",
            self.max_inner_cycles,
            active_spec_ids.len(),
        );
        let phase_started = std::time::Instant::now();
        let (stats, child_specs, child_code_gens) = RegenArgs::regen_specs(
            &self.repo,
            &self.primary_llm,
            &self.spec_name,
            &self.repo_root,
            &self.harness,
            &self.regen,
            &self.forge_backend,
            active_spec_ids,
        )
        .await?;
        drain.regen_codegen += stats.codegen_regen;
        drain.regen_spec += stats.spec_regen;
        tracing::info!(
            "[streamloop link {ordinal:04}] cycle {cycle}/{}: regen finished — \
             examined={} codegen_regen={} spec_regen={} escalated_chain_depth={} skipped_no_pair={} skipped_abandoned={} errors={} \
             → {} child spec(s), {} child codegen(s) ({})",
            self.max_inner_cycles,
            stats.examined,
            stats.codegen_regen,
            stats.spec_regen,
            stats.escalated_chain_depth,
            stats.skipped_no_pair,
            stats.skipped_abandoned_spec,
            stats.errors,
            child_specs.len(),
            child_code_gens.len(),
            fmt_elapsed(phase_started.elapsed()),
        );
        Ok((child_specs, child_code_gens))
    }

    /// On-disk path for one link's summary file. Deterministic on
    /// the link's 1-based queue ordinal — flat layout under
    /// `summaries/` instead of one directory per `(extract, hist,
    /// find)` triple. The `(extract, hist, find)` triple itself is
    /// still serialized INSIDE the JSON for traceability.
    ///
    /// 4-digit zero pad makes `ls` sort the files in queue order
    /// without `sort -n`. With >9999 links the names still sort
    /// correctly lexicographically — they just grow a digit.
    fn snapshot_path(&self, ordinal: usize) -> PathBuf {
        self.output_folder
            .join("summaries")
            .join(format!("link_summary_{ordinal:04}.json"))
    }

    /// Atomic write: serialize →
    /// `link_summary_NNNN.json.tmp` → `rename` →
    /// `link_summary_NNNN.json`. A crash mid-write leaves at most a
    /// `.tmp` file that the next run ignores; presence of the final
    /// file is the resume marker.
    fn write_snapshot(
        &self,
        ordinal: usize,
        total: usize,
        key: &LinkKey,
        outcome: &LinkSpecOutcome,
        drain: &LinkDrainCounts,
        code_gen_ids: &[i32],
    ) -> Result<()> {
        let dir = self.output_folder.join("summaries");
        std::fs::create_dir_all(&dir)
            .wrap_err_with(|| format!("failed to create {}", dir.display()))?;
        let snapshot = LinkSnapshot {
            ordinal,
            total_links: total,
            extract_id: key.extract_id,
            historical_id: key.historical_id,
            finding_id: key.finding_id,
            status: snapshot_status(outcome.status),
            committed_spec_count: outcome.specifications.len(),
            specification_ids: outcome.specification_ids.clone(),
            code_gen_ids: code_gen_ids.to_vec(),
            abort_reason: outcome.abort_reason.clone(),
            steps: outcome.steps,
            compact_count: outcome.compact_count,
            drain: drain.clone(),
        };
        let final_path = self.snapshot_path(ordinal);
        let tmp_path = final_path.with_extension("json.tmp");
        let body = serde_json::to_string_pretty(&snapshot)
            .wrap_err("failed to JSON-serialize link snapshot")?;
        std::fs::write(&tmp_path, body)
            .wrap_err_with(|| format!("failed to write {}", tmp_path.display()))?;
        std::fs::rename(&tmp_path, &final_path).wrap_err_with(|| {
            format!(
                "failed to atomically rename {} → {}",
                tmp_path.display(),
                final_path.display()
            )
        })?;
        Ok(())
    }
}

/// Human-readable elapsed duration via `chrono::Duration`. Picks the
/// right unit bucket so a 2-minute phase reads as `2m07s` instead of
/// `127.3s`. Backed by chrono because we already pull it transitively
/// — keeps the arithmetic on a real duration type.
///
/// - sub-minute: `"12.345s"`
/// - sub-hour:   `"2m07s"`
/// - longer:     `"1h05m12s"`
fn fmt_elapsed(d: std::time::Duration) -> String {
    let cd = chrono::Duration::from_std(d).unwrap_or_else(|_| chrono::Duration::zero());
    let h = cd.num_hours();
    let m = cd.num_minutes() % 60;
    let s = cd.num_seconds() % 60;
    let ms = (cd.num_milliseconds() % 1000).abs();
    if h > 0 {
        format!("{h}h{m:02}m{s:02}s")
    } else if cd.num_minutes() > 0 {
        format!("{m}m{s:02}s")
    } else {
        format!("{s}.{ms:03}s")
    }
}

fn snapshot_status(s: LinkSpecStatus) -> &'static str {
    match s {
        LinkSpecStatus::Built => "built",
        LinkSpecStatus::Abandoned => "abandoned",
    }
}

// ---------------------------------------------------------------------------
// Scheduler
// ---------------------------------------------------------------------------

/// Bounded-concurrency dispatcher. Pops one `PlannedLinkWork` at a time
/// from the shared stream, spawns a task per claim, and keeps up to
/// `concurrency` tasks active via [`JoinSet`]. Stats roll up from each
/// per-link `LinkTally` as workers finish.
struct LinkScheduler {
    ctx: Arc<LinkContext>,
    concurrency: usize,
}

impl LinkScheduler {
    async fn run(self, stream: SpecGenStream) -> Result<StreamStats> {
        let total = stream.total_links();
        let stream = Arc::new(Mutex::new(stream));
        let mut tasks: JoinSet<Result<LinkTally>> = JoinSet::new();
        let mut stats = StreamStats::default();
        let mut launched = 0usize;

        loop {
            while tasks.len() < self.concurrency {
                let work = stream.lock().await.pop_next_work();
                let Some(work) = work else { break };
                let ctx = self.ctx.clone();
                let ordinal = work.ordinal();
                tracing::info!(
                    "[streamloop scheduler] launching link {ordinal:04}/{total} (active={}/{})",
                    tasks.len() + 1,
                    self.concurrency,
                );
                tasks.spawn(async move { ctx.run_link(work).await });
                launched += 1;
            }
            let Some(joined) = tasks.join_next().await else {
                break;
            };
            match joined {
                Ok(Ok(tally)) => stats.merge(tally),
                Ok(Err(err)) => {
                    tracing::error!("link pipeline failed: {err:#}");
                    stats.errors += 1;
                }
                Err(join_err) => {
                    tracing::error!("link pipeline task panicked: {join_err:#}");
                    stats.errors += 1;
                }
            }
        }
        tracing::info!(
            "[streamloop scheduler] launched {launched} link pipeline(s); processed_links={} skipped_resumed={}",
            stats.processed_links,
            stats.skipped_resumed,
        );
        Ok(stats)
    }
}

// ---------------------------------------------------------------------------
// Stats / snapshot types
// ---------------------------------------------------------------------------

#[derive(Default, Debug)]
struct StreamStats {
    processed_links: usize,
    skipped_resumed: usize,
    built_specs: usize,
    abandoned_links: usize,
    errors: usize,
}

impl StreamStats {
    fn merge(&mut self, tally: LinkTally) {
        match tally {
            LinkTally::Resumed => {
                self.skipped_resumed += 1;
            }
            LinkTally::Ran { specs, abandoned } => {
                self.processed_links += 1;
                self.built_specs += specs;
                if abandoned {
                    self.abandoned_links += 1;
                }
            }
        }
    }
}

/// Per-link outcome surfaced to the scheduler. `Resumed` = snapshot
/// already on disk, no LLM work done; `Ran` = link's pipeline actually
/// executed and `specs` / `abandoned` reflect what the gen-spec phase
/// produced.
enum LinkTally {
    Resumed,
    Ran { specs: usize, abandoned: bool },
}

impl LinkTally {
    fn skipped() -> Self {
        Self::Resumed
    }

    fn from_outcome(outcome: &LinkSpecOutcome) -> Self {
        Self::Ran {
            specs: outcome.specifications.len(),
            abandoned: matches!(outcome.status, LinkSpecStatus::Abandoned),
        }
    }
}

#[derive(Clone, Debug, Default, Serialize)]
struct LinkDrainCounts {
    fuzz_completed: usize,
    fuzz_violated: usize,
    reflect_graded: usize,
    regen_codegen: usize,
    regen_spec: usize,
}

#[derive(Debug, Serialize)]
struct LinkSnapshot {
    ordinal: usize,
    total_links: usize,
    extract_id: i32,
    historical_id: i32,
    finding_id: i32,
    status: &'static str,
    committed_spec_count: usize,
    specification_ids: Vec<i32>,
    code_gen_ids: Vec<i32>,
    abort_reason: Option<String>,
    steps: usize,
    compact_count: usize,
    drain: LinkDrainCounts,
}

/// On-disk shape of a `valid_finding` row written to
/// `<output_folder>/valid_findings/finding_{reflection_id}.json`.
///
/// Wraps the raw [`LoadedValidFinding`] row via `#[serde(flatten)]` so
/// every column shows up at the top level of the JSON file unchanged,
/// and adds two fields on top:
///
/// * `specification`: the parsed [`AuditSpecification`] (nested
///   objects in place of `loaded.specification_json`'s escaped
///   string). `None` only if the column fails to parse — shouldn't
///   happen, we wrote it ourselves, and the raw string is still
///   reachable as `specification_json` in the flattened section.
/// * `link`: the `(extract, historical, finding)` triple from
///   [`RepoDatabase::load_link_for_spec`], with both halves' strength
///   / evidence pair.
#[derive(Debug, Serialize)]
struct OnDiskFinding {
    #[serde(flatten)]
    loaded: LoadedValidFinding,
    specification: Option<AuditSpecification>,
    /// The mapper's `semantic_matched` row that ties this spec's
    /// project extract to the chosen historical semantic. `None` only
    /// when [`RepoDatabase::load_link_for_spec`] couldn't recover the
    /// link chain.
    extract_match: Option<SemanticMatch>,
    /// The KG-side `semantic_finding_link::Model` that ties the chosen
    /// historical semantic to the finding.
    link: Option<semantic_finding_link::Model>,
}

impl OnDiskFinding {
    fn build(
        loaded: LoadedValidFinding,
        pair: Option<(SemanticMatch, semantic_finding_link::Model)>,
    ) -> Self {
        let specification =
            serde_json::from_str::<AuditSpecification>(&loaded.specification_json).ok();
        let (extract_match, link) = match pair {
            Some((m, l)) => (Some(m), Some(l)),
            None => (None, None),
        };
        Self {
            loaded,
            specification,
            extract_match,
            link,
        }
    }
}
