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
//! Resume is **DB-driven**. The project DB is the single source of
//! truth for "what work this project has done". On every run,
//! [`SpecGenStream::prepare_stream`] consults
//! [`RepoDatabase::link_resume_state`] per candidate link:
//!
//! * `NotStarted` (no spec rows for this `(extract, finding)`) →
//!   keep in the queue, run gen-spec from scratch.
//! * `Partial` (spec rows exist but no code_gen yet) → keep,
//!   tagged with the existing `spec_ids` so the gen-spec agent is
//!   skipped and the inner fuzz/reflect/regen cycle picks up from
//!   those rows.
//! * `Built` (≥1 code_gen exists for any spec of this link) → drop
//!   from the queue. Standalone `audit reflect / regen` can still
//!   drive any remaining pending state.
//!
//! The on-disk `<output>/summaries/link_summary_e{E}_h{H}_f{F}.json`
//! files are per-link reports — written atomically (tmp + rename) so
//! a crash mid-write leaves at most a `.tmp` sibling — but streamloop
//! never reads them back. Stale summary files from earlier code (the
//! old ordinal-named layout) are harmless and can be deleted at any
//! time.

use std::path::PathBuf;
use std::sync::Arc;

use clap::Args;
use color_eyre::eyre::{Result, WrapErr, eyre};
use knowdit_audit::harness::HarnessBackend;
use knowdit_audit::mapper::MapperOutcome;
use knowdit_audit::spec::{
    BillingExhausted, LinkKey, LinkSource, LinkSpecOutcome, LinkSpecStatus, PlannedLinkWork,
    SpecGenOptions, SpecGenStream, SpecificationGenerator, billing_exhaustion,
};
use knowdit_audit::types::AuditSpecification;
use knowdit_kg::db::HistoricalDatabase;
use knowdit_project::{ProjectData, SourceLanguage};
use knowdit_repo_model::{CodeGenStatus, FindingProvenance, LoadedValidFinding, RepoDatabase};
use llmy::clap::OptOpenAISetup;
use llmy::client::billing::TokenUsage;
use llmy::client::client::LLM;
use llmy::client::rust_decimal::Decimal;
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
use crate::cmd::workflow::review_findings;
use crate::cmd::workflow::utils::write_json_atomic;

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

    /// After the link pipeline finishes, run the `review-findings` report
    /// phase (review → dedup-merge → write → export `audit_report.md`) into
    /// the same output folder. Off by default; run it standalone via
    /// `workflow review-findings` to iterate on the report without re-fuzzing.
    #[arg(short = 'r', long = "review-findings", default_value_t = false)]
    pub review_findings: bool,

    #[command(flatten)]
    pub review: crate::cmd::workflow::review_findings::ReviewFindingsSharedArgs,
}

impl StreamloopArgs {
    pub async fn run(mut self, primary_llm: &LLM) -> Result<()> {
        self.apply_default_concurrency();
        // Validate --mapper-extra-categories up front so a typo aborts before
        // any LLM work instead of mid-pipeline at the map phase.
        self.map.extra_categories()?;
        tracing::info!("[streamloop stage 1/8] preparing output folder");
        self.prepare_output_folder()?;
        self.harness.harness_via_ir = self.backend.foundry.via_ir;

        tracing::info!("[streamloop stage 2/8] loading project DB and connecting to KG");
        let loaded = self
            .project
            .to_repo_database(self.db.database_path.clone())
            .await?;
        let kg = self.kg.connect_init_for_consumer().await?;
        let spec_name = loaded.spec.name.clone();
        let repo_root = loaded.spec.root.clone();
        let repo = loaded.repo;
        tracing::info!(
            "[streamloop stage 2/8] DB ready (project={}, repo_root={})",
            spec_name,
            repo_root.display(),
        );

        let reflect_llm = self
            .reflect_llm
            .clone()
            .may_llm()
            .await
            .map_err(|err| eyre!("failed to build reflect LLM: {err}"))?
            .unwrap_or_else(|| primary_llm.clone());

        let project_data = self.project.to_project_data().await?;

        // Profile is the **only** language-dispatch input streamloop
        // honors. It runs before any harness construction / CG ingest;
        // its declared `language` then drives every subsequent branch
        // (HarnessBackend constructor, CG ingest path, downstream
        // phase prompt prefixes). The file-extension auto-detect on
        // `project_data.language` is *not* read at this layer — if
        // profile says Move on a project that looks Solidity by
        // file extensions (or vice versa), the LLM judgment wins.
        tracing::info!(
            "[streamloop stage 3/8] running profile (language discovery + project framing)"
        );
        // `profile` is the first scoped global phase; `extract` / `mapper` are
        // scoped inside the backend runners, per-link scopes under root.
        let profile_llm = primary_llm.scope(Some("profile".to_string()), None);
        let profile =
            ProfileArgs::profile(&repo, &profile_llm, &spec_name, &repo_root, &self.profile)
                .await?;
        tracing::info!(
            "[streamloop stage 3/8] profile ready: language={:?}, {} subsystem(s), {} core component(s)",
            profile.language,
            profile.subsystems.len(),
            profile.core_components.len(),
        );

        // Branch the entire backend + CG ingest path on
        // `profile.language`. The two arms build different
        // [`HarnessBackend`] impls (SolidityHarness vs MovyHarness)
        // and call different CG ingest paths
        // (`SolidityCallGraphStaticArgs::update_call_graph` vs
        // `MoveExtractor::ingest_to_db`). Post-CG work
        // ([`Self::run_with_backend`]) is generic over
        // `B: HarnessBackend`.
        let mut usage = match profile.language {
            SourceLanguage::Solidity => {
                let harness_backend = self.harness.to_solidity_harness(FuzzOptionsBuild {
                    repo_root: repo_root.clone(),
                    default_cache_key: self
                        .stream_fuzz_cache_key
                        .clone()
                        .unwrap_or_else(|| format!("{}-knowdit-fuzz", spec_name)),
                    max_specs: 0,
                    concurrency: self.fuzz.fuzz_concurrency.unwrap_or(1).max(1),
                    regenerate: self.fuzz.fuzz_regenerate,
                    via_ir: self.harness.harness_via_ir,
                })?;
                tracing::info!("[streamloop preflight] verifying forge environment");
                harness_backend.preflight(&repo_root).await.wrap_err(
                    "forge environment preflight failed — fix the project's foundry config / \
                     forge-std install and re-run",
                )?;
                tracing::info!("[streamloop preflight] forge environment OK");

                tracing::info!("[streamloop stage 3/8] loading call graph (Solidity)");
                let cg = repo.load_call_graph().await?;
                if cg.contracts.is_empty() {
                    tracing::info!(
                        "[streamloop stage 3/8] no contracts in call graph — running static call-graph phase"
                    );
                    SolidityCallGraphStaticArgs::update_call_graph(
                        &repo,
                        &repo_root,
                        &self.backend,
                    )
                    .await?;
                }
                let cg = repo.load_call_graph().await?;
                if cg.contracts.is_empty() {
                    return Err(eyre!(
                        "no available contracts found after Solidity call-graph rebuild"
                    ));
                }
                tracing::info!(
                    "[streamloop stage 3/8] call graph ready: {} contract(s)",
                    cg.contracts.len()
                );
                self.run_with_backend(
                    harness_backend,
                    primary_llm.clone(),
                    reflect_llm,
                    repo,
                    repo_root,
                    spec_name,
                    project_data,
                    &kg,
                )
                .await
            }
            SourceLanguage::Move => Err(eyre!("Move language not supported in this build")),
        }?;

        // Stamp the profile phase + run total, then write the centralized
        // per-link / per-phase token + USD report. This write happens even on a
        // billing abort, so the partial spend (and the abort reason) is on disk
        // before we bail.
        usage.profile = PhaseUsage::snapshot(&profile_llm);
        usage.finalize_total();
        usage
            .write(&self.output_folder)
            .wrap_err("failed to write run usage report")?;
        tracing::info!(
            "[streamloop] usage: run total ${} ({} input + {} output tokens) across {} link(s) → {}/usage/run_usage.json",
            usage.run_total.usd,
            usage.run_total.tokens.input_tokens,
            usage.run_total.tokens.output_tokens,
            usage.links.len(),
            self.output_folder.display(),
        );

        // A billing-cap exhaustion is run-fatal: surface it as an error (non-zero
        // exit) instead of letting the run report success after silently
        // abandoning the rest of the queue.
        if let Some(abort) = &usage.billing_abort {
            return Err(eyre!(
                "billing cap exhausted: scope `{}` hit cap ${} (spent ${}); run aborted after \
                 {} processed link(s). Partial usage written to {}/usage/run_usage.json — raise \
                 the cap or narrow the link set and re-run (resume is DB-driven).",
                abort.scope.as_deref().unwrap_or("root"),
                abort.cap,
                abort.current,
                usage.links.len(),
                self.output_folder.display(),
            ));
        }
        Ok(())
    }

    /// Backend-generic post-ingest pipeline. Profile + CG ingest
    /// have already run; this drives extract-semantics → map →
    /// gen-specs → scheduler. Generic over `B: HarnessBackend`
    /// for backend operations. The language-context prompt prefix
    /// comes from `harness_backend.prompt_prefix()`, not from
    /// `ProjectProfile` — so this function takes no profile.
    async fn run_with_backend<B>(
        &self,
        harness_backend: B,
        primary_llm: LLM,
        reflect_llm: LLM,
        repo: RepoDatabase,
        repo_root: PathBuf,
        spec_name: String,
        project_data: ProjectData,
        kg: &HistoricalDatabase,
    ) -> Result<RunUsageReport>
    where
        B: HarnessBackend + Clone + Send + Sync + 'static,
    {
        // Global-phase billing scopes (llmy 0.16). `extract` / `mapper` each
        // bill their own scope; per-link scopes are children of root created in
        // `LinkContext::run_link`. `profile` is scoped by the caller (`run`).
        let extract_llm = primary_llm.scope(Some("extract".to_string()), None);
        let mapper_llm = primary_llm.scope(Some("mapper".to_string()), None);

        tracing::info!("[streamloop stage 4/8] extracting project semantics");
        let semantics = ExtractSemanticsArgs::extract_semantics(
            &repo,
            &extract_llm,
            &project_data,
            &self.extract,
        )
        .await?;
        tracing::info!(
            "[streamloop stage 4/8] extracted {} project semantic(s)",
            semantics.len()
        );
        self.warn_if_only_others(&semantics);

        // Prefix dispatch lives on the harness backend (each
        // language's wording sits next to its `HarnessBackend`
        // impl). Source it once and thread through the LLM-driven
        // phases: mapper, spec-gen, and the per-link reflect path
        // via `LinkContext`.
        let language_prompt_prefix = harness_backend.prompt_prefix().to_string();

        tracing::info!("[streamloop stage 6/8] mapping extract↔historical semantics");
        let match_set = repo.load_semantic_match_results().await?;
        if match_set.matches.is_empty() {
            let outcome: MapperOutcome = MapSemanticsArgs::map_semantics(
                &repo,
                kg,
                &mapper_llm,
                &spec_name,
                language_prompt_prefix.clone(),
                &self.map,
            )
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

        // Stages 7–8 (prepare spec-gen stream → bounded gen-specs → fuzz →
        // reflect → regen pipeline) are shared with `external-validate` via
        // [`run_link_pipeline`]; only the upstream way links land in the DB
        // differs (LLM mapper here, JSON ingest there).
        let gen_options = self.gen_specs.build_spec_options(
            &spec_name,
            language_prompt_prefix.clone(),
            LinkSource::Mapper,
        );
        // When `--review-findings` is set, the link pipeline drains review +
        // merge after each completed link and finalizes (writer + export) at
        // the end — all via the shared report context.
        let report_cfg = if self.review_findings {
            Some(review_findings::ReportInlineCfg {
                scope_override: review_findings::resolve_scope_override(
                    self.review.scope_file.as_deref(),
                )?,
                options: self.review.grader_options(&spec_name),
                window_ratio: self.review.review_context_window_ratio,
                concurrency: self.review.review_concurrency.unwrap_or(1).max(1),
            })
        } else {
            None
        };
        let mut usage = LinkPipelineInputs {
            backend: harness_backend,
            primary_llm,
            reflect_llm,
            repo,
            repo_root,
            spec_name,
            language_prompt_prefix,
            gen_options,
            harness: self.harness.clone(),
            reflect: self.reflect.clone(),
            regen: self.regen.clone(),
            output_folder: self.output_folder.clone(),
            max_inner_cycles: self.max_inner_cycles_per_batch.max(1),
            concurrency: self.stream_link_concurrency.unwrap_or(1).max(1),
            report_cfg,
        }
        .run()
        .await?;
        usage.extract = PhaseUsage::snapshot(&extract_llm);
        usage.mapper = PhaseUsage::snapshot(&mapper_llm);
        Ok(usage)
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
        self.map.map_concurrency.get_or_insert(d);
        self.gen_specs.gen_specs_concurrency.get_or_insert(d);
        self.fuzz.fuzz_concurrency.get_or_insert(d);
        self.reflect.reflect_concurrency.get_or_insert(d);
        self.regen.regen_concurrency.get_or_insert(d);
        self.stream_link_concurrency.get_or_insert(d);
        self.review.review_concurrency.get_or_insert(d);
        tracing::info!(
            "[streamloop] --default-concurrency={d} fills in map={} gen-specs={} fuzz={} reflect={} regen={} stream-link={} (explicit per-phase flags win)",
            self.map.map_concurrency.unwrap_or(1),
            self.gen_specs.gen_specs_concurrency.unwrap_or(1),
            self.fuzz.fuzz_concurrency.unwrap_or(1),
            self.reflect.reflect_concurrency.unwrap_or(1),
            self.regen.regen_concurrency.unwrap_or(1),
            self.stream_link_concurrency.unwrap_or(1),
        );
    }

    /// After extract-semantics, if the project auto-classified into *only*
    /// `Others` (no Lending/Dexes/Services/… signal) and the user did not
    /// already widen the pool with `--mapper-extra-categories`, warn: an
    /// Others-only project pulls only Others-category historical knowledge,
    /// which can miss cross-domain findings (e.g. a P2P-escrow project's
    /// signature-without-deadline bug lives under `Services` historically).
    fn warn_if_only_others(&self, semantics: &[knowdit_kg_model::ExtractedSemantic]) {
        use knowdit_kg_model::category::DeFiCategory;
        let only_others =
            !semantics.is_empty() && semantics.iter().all(|s| s.category == DeFiCategory::Others);
        if only_others && self.map.mapper_extra_categories.is_none() {
            tracing::warn!(
                "[streamloop] project auto-classified into ONLY `Others` — the Knowledge Mapper \
                 will pull only Others-category historical semantics and may miss cross-domain \
                 findings. If you know the protocol's domain (e.g. it uses signatures / escrow / \
                 a service-like flow), re-run with `--mapper-extra-categories Services` (comma-\
                 separated for several, e.g. `Services,Dexes`) to widen the candidate pool."
            );
        }
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

// ---------------------------------------------------------------------------
// Per-link execution context
// ---------------------------------------------------------------------------

/// Immutable per-run context shared by every link pipeline. Built once
/// at the bottom of `StreamloopArgs::run` and cloned via `Arc` into each
/// worker. Everything a single link needs to drive itself end-to-end —
/// repo handle, both LLMs, harness backend, the four phase arg-sets, and
/// the resolved `fuzz_cache_key` — lives here.
///
/// Generic over `B: HarnessBackend` so the same per-link orchestration
/// drives both Solidity (`SolidityHarness`) and Sui Move
/// (`MovyHarness`) runs. The concrete `B` is chosen at the top of
/// `StreamloopArgs::run` based on the detected
/// [`SourceLanguage`] (Stage 7 of plan_move_lang.md).
struct LinkContext<B: HarnessBackend + Clone + 'static> {
    repo: RepoDatabase,
    primary_llm: LLM,
    reflect_llm: LLM,
    spec_name: String,
    repo_root: PathBuf,
    /// Bundled harness backend + per-pass options. Construction
    /// (forge probe vs movy probe), preflight, and the inner
    /// `fuzz_one_existing_spec` all dispatch through the
    /// [`HarnessBackend`] impl so the per-link pipeline never has to
    /// branch on language.
    harness_backend: B,
    /// Original CLI args — kept because regen still consumes a few
    /// fields (`harness_debug_prefix`, `harness_via_ir`, etc.) that
    /// don't have a home on the backend handle. Trim once a `Move`
    /// path lands and we settle on the smallest shared surface.
    harness: HarnessSharedArgs,
    reflect: ReflectSharedArgs,
    regen: RegenSharedArgs,
    output_folder: PathBuf,
    max_inner_cycles: usize,
    /// Frozen prompt prefix sourced once from
    /// `harness_backend.prompt_prefix()` at link-pipeline start.
    /// Reflection threads this into the grader system prompt without
    /// having to round-trip through the backend per call.
    language_prompt_prefix: String,
}

impl<B: HarnessBackend + Clone + 'static> LinkContext<B> {
    /// Drive one claimed link end-to-end. Resume is now DB-driven:
    /// [`SpecGenStream::prepare_stream`] already filtered out
    /// previously-built links and tagged previously-partial ones with
    /// their existing `spec_ids`, so every claim reaching `run_link`
    /// is either fresh (`NotStarted`) or resuming the inner cycle
    /// (`Partial`). The on-disk `summaries/link_summary_*.json` file
    /// is just a per-link report, not a resume marker.
    /// Returns a tiny [`LinkTally`] so the scheduler can roll up
    /// `StreamStats` without the full [`LinkSpecOutcome`] crossing
    /// the JoinSet boundary.
    async fn run_link(self: Arc<Self>, work: PlannedLinkWork) -> Result<LinkTally> {
        let key = work.link_key();
        let ordinal = work.ordinal();
        let total = work.total_links();

        let link_started = std::time::Instant::now();
        tracing::info!(
            "[streamloop link {ordinal:04}/{total}] gen-specs: starting (extract={}, hist={}, find={})",
            key.extract_id,
            key.historical_id,
            key.finding_id,
        );
        // Per-link billing scopes (llmy 0.16): spec/codegen/regen bill the
        // primary tree, reflect bills the reflect tree; every phase call below
        // goes through its scope so the snapshot is exact under concurrency.
        let scopes = LinkScopes::new(&self.primary_llm, &self.reflect_llm, ordinal);

        let gen_specs_started = std::time::Instant::now();
        // `?` here only fires on a billing-cap exhaustion (run-fatal); a
        // per-link agent failure comes back as an `Abandoned` outcome.
        let outcome = work.run(&self.repo, &scopes.spec).await?;
        tracing::info!(
            "[streamloop link {ordinal:04}/{total}] gen-specs: finished — status={} {} spec(s) usable, {} step(s), {} compaction(s) ({})",
            snapshot_status(outcome.status),
            outcome.specification_ids.len(),
            outcome.steps,
            outcome.compact_count,
            humantime::format_duration(gen_specs_started.elapsed()),
        );

        let mut drain = LinkDrainCounts::default();
        let mut code_gen_ids: Vec<i32> = Vec::new();
        let mut cycles_run = 0usize;

        // Gate on `specification_ids` rather than `specifications`:
        // resumed Partial links arrive with empty parsed specs but
        // non-empty ids — those ids drive the cycle.
        if !outcome.specification_ids.is_empty() {
            let mut active: Vec<i32> = outcome.specification_ids.clone();
            for cycle in 1..=self.max_inner_cycles {
                if active.is_empty() {
                    break;
                }
                active = self
                    .advance_cycle(
                        ordinal,
                        cycle,
                        &active,
                        &mut drain,
                        &mut code_gen_ids,
                        &scopes,
                    )
                    .await?;
                cycles_run = cycle;
            }
        } else {
            tracing::info!(
                "[streamloop link {ordinal:04}/{total}] no committed specs — writing terminal summary",
            );
        }

        let usage = scopes.report();
        self.write_snapshot(
            ordinal,
            total,
            &key,
            &outcome,
            &drain,
            &code_gen_ids,
            &usage,
        )?;
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
            humantime::format_duration(link_started.elapsed()),
        );
        Ok(LinkTally {
            specs: outcome.specification_ids.len(),
            abandoned: matches!(outcome.status, LinkSpecStatus::Abandoned),
            usage_row: LinkUsageRow {
                ordinal,
                extract_id: key.extract_id,
                historical_id: key.historical_id,
                finding_id: key.finding_id,
                usage,
            },
        })
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
            let provenance = self.repo.load_provenance_for_spec(loaded.spec_id).await?;
            let on_disk = OnDiskFinding::build(loaded, provenance);
            write_json_atomic(&final_path, &on_disk)?;
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
        scopes: &LinkScopes,
    ) -> Result<Vec<i32>> {
        let cycle_started = std::time::Instant::now();
        tracing::info!(
            "[streamloop link {ordinal:04}] cycle {cycle}/{}: starting with {} active spec(s)",
            self.max_inner_cycles,
            active_spec_ids.len(),
        );
        let produced = self
            .fuzz_active_specs(ordinal, cycle, active_spec_ids, drain, &scopes.codegen)
            .await?;
        code_gen_ids.extend(produced.iter().copied());

        self.reflect_produced_codegens(ordinal, cycle, &produced, drain, &scopes.reflect)
            .await?;

        let (children, child_code_gens) = self
            .regen_active_specs(ordinal, cycle, active_spec_ids, drain, &scopes.regen)
            .await?;
        code_gen_ids.extend(child_code_gens);
        tracing::info!(
            "[streamloop link {ordinal:04}] cycle {cycle}/{}: finished — {} spec(s) feed into next cycle ({} total)",
            self.max_inner_cycles,
            children.len(),
            humantime::format_duration(cycle_started.elapsed()),
        );
        Ok(children)
    }

    async fn fuzz_active_specs(
        &self,
        ordinal: usize,
        cycle: usize,
        active_spec_ids: &[i32],
        drain: &mut LinkDrainCounts,
        codegen_llm: &LLM,
    ) -> Result<Vec<i32>> {
        let total = active_spec_ids.len();
        tracing::info!(
            "[streamloop link {ordinal:04}] cycle {cycle}/{}: fuzz {} spec(s) starting",
            self.max_inner_cycles,
            total,
        );
        let phase_started = std::time::Instant::now();
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
            if let Some(fuzzed) = self
                .harness_backend
                .fuzz_one_existing_spec(&self.repo, codegen_llm, spec_id)
                .await?
            {
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
                    humantime::format_duration(spec_started.elapsed()),
                );
            } else {
                tracing::info!(
                    "[streamloop link {ordinal:04}] cycle {cycle}/{} fuzz {}/{} skipped: spec_id={spec_id} (no fuzzable codegen) ({})",
                    self.max_inner_cycles,
                    idx + 1,
                    total,
                    humantime::format_duration(spec_started.elapsed()),
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
            humantime::format_duration(phase_started.elapsed()),
        );
        Ok(produced)
    }

    async fn reflect_produced_codegens(
        &self,
        ordinal: usize,
        cycle: usize,
        produced: &[i32],
        drain: &mut LinkDrainCounts,
        reflect_llm: &LLM,
    ) -> Result<()> {
        tracing::info!(
            "[streamloop link {ordinal:04}] cycle {cycle}/{}: reflect {} codegen(s) starting",
            self.max_inner_cycles,
            produced.len(),
        );
        let phase_started = std::time::Instant::now();
        let stats = ReflectArgs::reflect_code_gens(
            &self.repo,
            reflect_llm,
            &self.spec_name,
            &self.repo_root,
            self.language_prompt_prefix.clone(),
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
            humantime::format_duration(phase_started.elapsed()),
        );
        Ok(())
    }

    async fn regen_active_specs(
        &self,
        ordinal: usize,
        cycle: usize,
        active_spec_ids: &[i32],
        drain: &mut LinkDrainCounts,
        regen_llm: &LLM,
    ) -> Result<(Vec<i32>, Vec<i32>)> {
        tracing::info!(
            "[streamloop link {ordinal:04}] cycle {cycle}/{}: regen scoped to {} spec(s) starting",
            self.max_inner_cycles,
            active_spec_ids.len(),
        );
        let phase_started = std::time::Instant::now();
        let (stats, child_specs, child_code_gens) = RegenArgs::regen_specs(
            &self.harness_backend,
            &self.repo,
            regen_llm,
            &self.spec_name,
            &self.harness,
            &self.regen,
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
            humantime::format_duration(phase_started.elapsed()),
        );
        Ok((child_specs, child_code_gens))
    }

    /// On-disk path for one link's summary file. Content-keyed on
    /// the link's `(extract, historical, finding)` identity so the
    /// same link lands at the same path across runs regardless of
    /// resume-induced ordinal drift.
    ///
    /// Streamloop only ever WRITES this file — resume decisions come
    /// from the DB via [`RepoDatabase::link_resume_state`]. The file
    /// is a per-link report for humans, not a resume marker.
    fn snapshot_path(&self, key: &LinkKey) -> PathBuf {
        self.output_folder.join("summaries").join(format!(
            "link_summary_e{}_h{}_f{}.json",
            key.extract_id, key.historical_id, key.finding_id
        ))
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
        usage: &LinkUsageReport,
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
            committed_spec_count: outcome.specification_ids.len(),
            specification_ids: outcome.specification_ids.clone(),
            code_gen_ids: code_gen_ids.to_vec(),
            abort_reason: outcome.abort_reason.clone(),
            steps: outcome.steps,
            compact_count: outcome.compact_count,
            drain: drain.clone(),
            usage: usage.clone(),
        };
        let final_path = self.snapshot_path(key);
        write_json_atomic(&final_path, &snapshot)
    }
}

fn snapshot_status(s: LinkSpecStatus) -> &'static str {
    match s {
        LinkSpecStatus::Built => "built",
        LinkSpecStatus::Abandoned => "abandoned",
    }
}

// ---------------------------------------------------------------------------
// Per-link / per-phase token + USD accounting (llmy 0.16 scope API)
// ---------------------------------------------------------------------------

/// One billing scope's accumulated tokens + USD, read from
/// [`LLM::node_snapshot`]. `node_snapshot` already aggregates a scope's
/// children, so a link scope's `total` includes all its phase children.
#[derive(Debug, Clone, Default, Serialize)]
pub(crate) struct PhaseUsage {
    /// Reused from llmy (Serialize + `saturating_add`); `#[serde(flatten)]`
    /// keeps the JSON flat (`input_tokens` … alongside `usd`). We deliberately
    /// don't wrap the whole `TokenBilling`: its `cap` is the same global cap on
    /// every scope (noise per phase) and can't be summed.
    #[serde(flatten)]
    tokens: TokenUsage,
    usd: Decimal,
}

impl PhaseUsage {
    pub(crate) fn snapshot(llm: &LLM) -> Self {
        let b = llm.node_snapshot();
        Self {
            tokens: b.tokens,
            usd: b.current,
        }
    }

    fn add(&mut self, other: &Self) {
        self.tokens = self.tokens.saturating_add(other.tokens);
        self.usd += other.usd;
    }

    fn sum<'a>(parts: impl IntoIterator<Item = &'a Self>) -> Self {
        let mut out = Self::default();
        for p in parts {
            out.add(p);
        }
        out
    }
}

/// One link's token/USD breakdown. `total` = the link's primary scope +
/// reflect scope (reflect can be a separate billing tree when a distinct
/// reflect model is configured); the per-phase fields are read from the
/// link's child scopes.
#[derive(Debug, Clone, Default, Serialize)]
pub(crate) struct LinkUsageReport {
    total: PhaseUsage,
    spec: PhaseUsage,
    codegen: PhaseUsage,
    regen: PhaseUsage,
    reflect: PhaseUsage,
}

/// A per-link row for the centralized run usage file.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct LinkUsageRow {
    ordinal: usize,
    extract_id: i32,
    historical_id: i32,
    finding_id: i32,
    #[serde(flatten)]
    usage: LinkUsageReport,
}

/// Centralized run-level usage report written to
/// `<output_folder>/usage/run_usage.json`. `run_total` is the sum of every
/// named scope (global phases + per-link totals), so it does not depend on the
/// root-snapshot / reflect-tree identity.
#[derive(Debug, Clone, Default, Serialize)]
pub(crate) struct RunUsageReport {
    run_total: PhaseUsage,
    pub(crate) profile: PhaseUsage,
    pub(crate) extract: PhaseUsage,
    pub(crate) mapper: PhaseUsage,
    pub(crate) links: Vec<LinkUsageRow>,
    /// Present only when the run aborted on a billing-cap exhaustion. Recorded
    /// in the report so the on-disk `run_usage.json` shows *why* the run stopped
    /// (which scope, the cap, and how much was spent) alongside the partial
    /// per-link spend collected before the abort.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) billing_abort: Option<BillingExhausted>,
}

impl RunUsageReport {
    /// Compute `run_total` = profile + extract + mapper + Σ(per-link totals).
    pub(crate) fn finalize_total(&mut self) {
        let mut total = PhaseUsage::sum([&self.profile, &self.extract, &self.mapper]);
        for row in &self.links {
            total.add(&row.usage.total);
        }
        self.run_total = total;
    }

    /// Write to `<output_folder>/usage/run_usage.json` (atomic tmp+rename).
    pub(crate) fn write(&self, output_folder: &std::path::Path) -> Result<()> {
        let dir = output_folder.join("usage");
        std::fs::create_dir_all(&dir)
            .wrap_err_with(|| format!("failed to create {}", dir.display()))?;
        let final_path = dir.join("run_usage.json");
        write_json_atomic(&final_path, self)
    }
}

/// The per-link billing scopes (llmy 0.16). `link` / `link_reflect` are the
/// roll-up scopes (on the primary and reflect billing trees respectively); the
/// rest are the per-phase children billed by each phase. Created once per link;
/// every call in a phase goes through its scope so the snapshot is exact even
/// under concurrent links.
struct LinkScopes {
    link: LLM,
    link_reflect: LLM,
    spec: LLM,
    codegen: LLM,
    regen: LLM,
    reflect: LLM,
}

impl LinkScopes {
    fn new(primary: &LLM, reflect: &LLM, ordinal: usize) -> Self {
        let link = primary.scope(Some(format!("link-{ordinal:04}")), None);
        let link_reflect = reflect.scope(Some(format!("link-{ordinal:04}")), None);
        let spec = link.scope(Some("spec".to_string()), None);
        let codegen = link.scope(Some("codegen".to_string()), None);
        let regen = link.scope(Some("regen".to_string()), None);
        let reflect = link_reflect.scope(Some("reflect".to_string()), None);
        Self {
            link,
            link_reflect,
            spec,
            codegen,
            regen,
            reflect,
        }
    }

    fn report(&self) -> LinkUsageReport {
        LinkUsageReport {
            total: PhaseUsage::sum([
                &PhaseUsage::snapshot(&self.link),
                &PhaseUsage::snapshot(&self.link_reflect),
            ]),
            spec: PhaseUsage::snapshot(&self.spec),
            codegen: PhaseUsage::snapshot(&self.codegen),
            regen: PhaseUsage::snapshot(&self.regen),
            reflect: PhaseUsage::snapshot(&self.reflect),
        }
    }
}


// ---------------------------------------------------------------------------
// Scheduler
// ---------------------------------------------------------------------------

/// Bounded-concurrency dispatcher. Pops one `PlannedLinkWork` at a time
/// from the shared stream, spawns a task per claim, and keeps up to
/// `concurrency` tasks active via [`JoinSet`]. Stats roll up from each
/// `(specs_built, abandoned)` per worker as they finish.
struct LinkScheduler<B: HarnessBackend + Clone + 'static> {
    ctx: Arc<LinkContext<B>>,
    concurrency: usize,
    /// When set, review + merge are drained into it after each completed link
    /// (serial — this runs in the scheduler's single-threaded join loop, so no
    /// lock is needed). Returned to the caller to finalize.
    report: Option<review_findings::ReportContext>,
}

impl<B: HarnessBackend + Clone + 'static> LinkScheduler<B> {
    async fn run(
        mut self,
        stream: SpecGenStream,
    ) -> Result<(StreamStats, Option<review_findings::ReportContext>)> {
        let total = stream.total_links();
        let stream = Arc::new(Mutex::new(stream));
        // Per-link return = [`LinkTally`]. The full
        // `LinkSpecOutcome` carries `Vec<AuditSpecification>` plus
        // other heavy fields the scheduler doesn't need, so
        // `run_link` collapses it to the two counters this loop cares
        // about before crossing the JoinSet boundary.
        let mut tasks: JoinSet<Result<LinkTally>> = JoinSet::new();
        let mut stats = StreamStats::default();
        let mut launched = 0usize;

        loop {
            // Stop claiming new links once a billing cap has been hit — every
            // launch would just fast-fail the pre-flight `check_cap`. In-flight
            // tasks are still drained below.
            while stats.billing_abort.is_none() && tasks.len() < self.concurrency {
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
                Ok(Ok(tally)) => {
                    stats.processed_links += 1;
                    stats.built_specs += tally.specs;
                    if tally.abandoned {
                        stats.abandoned_links += 1;
                    }
                    stats.link_usages.push(tally.usage_row);
                    // Drain review + merge for whatever findings this link
                    // produced. Serial (we're in the single-threaded join
                    // loop) so the merge accumulator needs no lock. A drain
                    // failure is logged, not fatal to the fuzz run.
                    if let Some(report) = self.report.as_mut() {
                        if let Err(err) = report.review_pending().await {
                            tracing::error!("[streamloop] inline review drain failed: {err:#}");
                        }
                        if let Err(err) = report.merge_pending().await {
                            tracing::error!("[streamloop] inline merge drain failed: {err:#}");
                        }
                    }
                }
                Ok(Err(err)) => {
                    // A billing-cap exhaustion is run-fatal: record it, stop
                    // launching, and drain remaining tasks. Any other error is a
                    // per-link failure the run can survive.
                    if let Some(billing) = billing_exhaustion(&err) {
                        if stats.billing_abort.is_none() {
                            tracing::error!(
                                "[streamloop scheduler] 💸 billing cap exhausted (scope {}, cap ${}, spent ${}) — stopping link launch, draining {} in-flight",
                                billing.scope.as_deref().unwrap_or("root"),
                                billing.cap,
                                billing.current,
                                tasks.len(),
                            );
                            stats.billing_abort = Some(billing);
                        }
                    } else {
                        tracing::error!("link pipeline failed: {err:#}");
                        stats.errors += 1;
                    }
                }
                Err(join_err) => {
                    tracing::error!("link pipeline task panicked: {join_err:#}");
                    stats.errors += 1;
                }
            }
        }
        tracing::info!(
            "[streamloop scheduler] launched {launched} link pipeline(s); processed_links={}",
            stats.processed_links,
        );
        Ok((stats, self.report))
    }
}

// ---------------------------------------------------------------------------
// Shared post-mapper pipeline
// ---------------------------------------------------------------------------

/// Inputs for the post-mapper link pipeline (gen-specs → fuzz → reflect →
/// regen). Shared by `streamloop` (after its LLM Knowledge Mapper) and
/// `external-validate` (after its JSON ingest): by the time either calls this,
/// the project DB holds mapper-output rows and the rest is identical
/// DB-driven work.
pub(crate) struct LinkPipelineInputs<B: HarnessBackend + Clone + Send + Sync + 'static> {
    pub(crate) backend: B,
    pub(crate) primary_llm: LLM,
    pub(crate) reflect_llm: LLM,
    pub(crate) repo: RepoDatabase,
    pub(crate) repo_root: PathBuf,
    pub(crate) spec_name: String,
    pub(crate) language_prompt_prefix: String,
    pub(crate) gen_options: SpecGenOptions,
    pub(crate) harness: HarnessSharedArgs,
    pub(crate) reflect: ReflectSharedArgs,
    pub(crate) regen: RegenSharedArgs,
    pub(crate) output_folder: PathBuf,
    pub(crate) max_inner_cycles: usize,
    pub(crate) concurrency: usize,
    /// When set, the pipeline drains review + merge after each completed link
    /// and finalizes (writer + export) at the end. `None` for plain runs and
    /// for `external-validate` (which has its own reporting).
    pub(crate) report_cfg: Option<review_findings::ReportInlineCfg>,
}

impl<B: HarnessBackend + Clone + Send + Sync + 'static> LinkPipelineInputs<B> {
    /// Prepare the spec-gen stream from the DB and drive the bounded
    /// [`LinkScheduler`] (gen-specs → fuzz → reflect → regen) over it. Returns a
    /// [`RunUsageReport`] with `links` + `billing_abort` populated; the caller
    /// fills the global-phase scopes (`profile` / `extract` / `mapper`) it owns
    /// and then finalizes / writes the report.
    pub(crate) async fn run(self) -> Result<RunUsageReport> {
        let LinkPipelineInputs {
            backend,
            primary_llm,
            reflect_llm,
            repo,
            repo_root,
            spec_name,
            language_prompt_prefix,
            gen_options,
            harness,
            reflect,
            regen,
            output_folder,
            max_inner_cycles,
            concurrency,
            report_cfg,
        } = self;
        let concurrency = concurrency.max(1);

        tracing::info!("[link pipeline] preparing spec-gen stream");
        let stream = match SpecificationGenerator::new()
            .prepare_stream(&repo, &gen_options)
            .await?
        {
            Some(s) => s,
            None => {
                tracing::warn!(
                    "[link pipeline] no pending links after planner/resume filters — nothing to do"
                );
                return Ok(RunUsageReport::default());
            }
        };

        tracing::info!(
            "[link pipeline] running bounded pipeline: {} link(s), active_limit={}",
            stream.total_links(),
            concurrency,
        );
        // Build the shared report context up front (when enabled), using
        // clones — the scheduler drains review + merge into it after each
        // completed link, and we finalize (writer + export) once the pipeline
        // drains.
        let report = match report_cfg {
            Some(cfg) => Some(
                review_findings::ReportContext::build(cfg.into_run(
                    repo.clone(),
                    primary_llm.clone(),
                    spec_name.clone(),
                    repo_root.clone(),
                    language_prompt_prefix.clone(),
                    output_folder.clone(),
                ))
                .await?,
            ),
            None => None,
        };
        // `language_prompt_prefix` flows into LinkContext too so the per-link
        // reflect path can prepend it to the grader system prompt without
        // re-walking the harness backend each call.
        let ctx = Arc::new(LinkContext {
            repo,
            primary_llm,
            reflect_llm,
            spec_name,
            repo_root,
            harness_backend: backend,
            harness,
            reflect,
            regen,
            output_folder,
            max_inner_cycles: max_inner_cycles.max(1),
            language_prompt_prefix,
        });
        let scheduler = LinkScheduler {
            ctx,
            concurrency,
            report,
        };
        let (stats, report) = scheduler.run(stream).await?;
        if let Some(mut report) = report {
            report
                .finalize()
                .await
                .wrap_err("review-findings finalize (export) failed")?;
            tracing::info!(
                "[link pipeline] review-findings: reviewed={} canonicals={}",
                report.stats.reviewed,
                report.stats.canonicals,
            );
        }
        tracing::info!(
            "[link pipeline] finished: processed_links={} built_specs={} abandoned_links={}",
            stats.processed_links,
            stats.built_specs,
            stats.abandoned_links,
        );
        Ok(RunUsageReport {
            links: stats.link_usages,
            billing_abort: stats.billing_abort,
            ..Default::default()
        })
    }
}

// ---------------------------------------------------------------------------
// Stats / snapshot types
// ---------------------------------------------------------------------------

/// Resume is DB-driven now: links the scheduler dispatches always run
/// some real work (gen-spec or, for resumed Partial links, the inner
/// cycle from the existing specs). So there's no "skipped" bucket —
/// `processed_links` is also the launch count.
#[derive(Default, Debug)]
struct StreamStats {
    processed_links: usize,
    built_specs: usize,
    abandoned_links: usize,
    errors: usize,
    /// Per-link token/USD rows collected for the centralized usage report.
    link_usages: Vec<LinkUsageRow>,
    /// Set when a link pipeline failed with a billing-cap exhaustion. The
    /// scheduler stops launching new links and drains the in-flight ones; the
    /// run then aborts with a clear error instead of silently "finishing".
    billing_abort: Option<BillingExhausted>,
}

/// Minimal per-link summary returned by [`LinkContext::run_link`] —
/// just the two counters the scheduler folds into `StreamStats`.
/// Lives as its own struct (rather than a `(usize, bool)` tuple) so
/// the field names show up at every read site.
struct LinkTally {
    specs: usize,
    abandoned: bool,
    usage_row: LinkUsageRow,
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
    /// Per-phase token + USD spend for this link (llmy 0.16 scopes).
    usage: LinkUsageReport,
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
/// * `provenance`: the self-contained `(extract, historical semantic,
///   historical finding)` chain with FULL content + both graded edges
///   (mapper match + KG link), from
///   [`RepoDatabase::load_provenance_for_spec`] — so the file explains its
///   origin without the historical KG database.
#[derive(Debug, Serialize, serde::Deserialize)]
pub(crate) struct OnDiskFinding {
    #[serde(flatten)]
    loaded: LoadedValidFinding,
    specification: Option<AuditSpecification>,
    /// Self-contained origin chain: the project extract semantic, the
    /// historical semantic it matched, and the historical finding that
    /// motivated the spec — each with full content (not just ids) — plus the
    /// mapper match + KG link strength/evidence. `None` only when the spec or
    /// one of the content rows couldn't be recovered.
    provenance: Option<FindingProvenance>,
    /// The complete unique (deduplicated) finding this raw finding was folded
    /// into by the `review-findings` report phase — the full canonical plus
    /// every cluster member, embedded inline. `None` until (and unless) the
    /// report phase merges it; stamped in place on disk by
    /// [`crate::cmd::workflow::review_findings::ReportContext`].
    #[serde(default)]
    pub(crate) merged_to: Option<crate::cmd::workflow::review_findings::OnDiskUniqueFinding>,
}

impl OnDiskFinding {
    fn build(loaded: LoadedValidFinding, provenance: Option<FindingProvenance>) -> Self {
        let specification =
            serde_json::from_str::<AuditSpecification>(&loaded.specification_json).ok();
        Self {
            loaded,
            specification,
            provenance,
            merged_to: None,
        }
    }
}
