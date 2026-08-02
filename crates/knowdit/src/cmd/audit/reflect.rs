//! `agentic reflect` subcommand: outer-loop triage of fuzzed harnesses.
//!
//! Gates 1 and 2 fire **inline** inside the `run_forge` tool during
//! `agentic fuzz`, so by the time a `code_gen` row reaches `Completed`
//! its setUp passed, its revert rate is sane, and (when a coverage run
//! happened) coverage is above the configured fidelity threshold.
//!
//! For every `Completed` `code_gen` whose forge runs reported
//! `violated == true`, we run a TWO-AGENT pipeline per violated run:
//!
//! 1. [`VerdictGrader`] — 5-class classification
//!    (`OutOfScope` / `ExpectedViolation` / `ValidFinding` /
//!    `IncompleteStep` / `IncompleteSpecification`).
//! 2. [`SeverityGrader`] — only when verdict 1 is `ValidFinding`.
//!    Decides High / Medium / Low using project-source inspection.
//!
//! Both agent outputs are co-written **atomically** to `reflection`
//! (+ optional `valid_finding`) by
//! [`RepoDatabase::insert_reflection_with_finding`]. A crash mid-
//! pipeline leaves zero rows; resume is automatic via
//! `has_reflection(run_id)` skip + llmy cache hits.

use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

use clap::Args;
use color_eyre::eyre::{Result, WrapErr};
use knowdit_audit::harness::solidity::SolidityHarness;
use knowdit_audit::reflect::GraderPair;
use knowdit_audit::reflect::agent_loop::{CoverageSummary, GraderOptions, RunSummary};
use knowdit_audit::reflect::coverage_audit;
use knowdit_audit::reflect::grader::{VerdictInput, VerdictOutput};
use knowdit_audit::reflect::severity_grader::{SeverityInput, SeverityOutput};
use knowdit_audit::types::AuditSpecification;
use knowdit_repo_model::{
    CodeGenStatus, LoadedCodeGen, LoadedHarnessRun, LoadedSpecification, ReflectionRecord,
    ReflectionResult, RepoDatabase, SourceLanguage, ValidFindingRecord,
};
use llmy::client::client::LLM;

use crate::cli::{DatabaseArgs, LoadedRepoDatabase, ProjectArgs};

/// Knobs for the reflect phase. Long-flag names carry a
/// `--reflect-*` / `--grader-*` prefix so flattening alongside other
/// phase `SharedArgs` in the autoloop doesn't trip clap's
/// duplicate-arg check.
#[derive(Args, Clone, Debug)]
pub struct ReflectSharedArgs {
    /// Skip both grader agents. Dry-run mode — counts violated runs
    /// that *would* have been graded and exits.
    #[arg(long = "reflect-skip-grader", default_value_t = false)]
    pub reflect_skip_grader: bool,

    /// Debug-prefix forwarded to llmy for LLM-call dumps.
    #[arg(long = "reflect-debug-prefix", default_value = "reflect")]
    pub reflect_debug_prefix: Option<String>,

    /// Cap on number of violated runs reflected in this invocation.
    /// `0` means no cap.
    #[arg(long = "reflect-max-runs", default_value_t = 0)]
    pub reflect_max_runs: usize,

    /// Maximum agent steps per `VerdictGrader::grade` /
    /// `SeverityGrader::grade` call before forced finalize. Each
    /// grader gets up to this many steps independently; the severity
    /// grader's budget only applies when verdict is `ValidFinding`.
    #[arg(long = "grader-max-agent-steps", default_value_t = 40)]
    pub grader_max_agent_steps: usize,

    /// **Destructive**: at the start of the run, wipe every existing
    /// `reflection` + `valid_finding` row in the project DB so every
    /// violated `harness_run` is graded again from scratch. The
    /// underlying `code_gen` / `harness_run` / `line_coverage` /
    /// `*_regen` rows are NOT touched — only verdicts are reset.
    /// Use this to re-grade with a different model (e.g. switch
    /// `.env` from `gpt-5.4-mini` to `gpt-5.4`) and compare.
    #[arg(long = "allow-redo-reflect", default_value_t = false)]
    pub allow_redo_reflect: bool,

    /// Worker count for grading. Each pending `(verdict, severity)`
    /// pipeline runs as its own task; with `>1` they execute in
    /// parallel against the shared `GraderPair` (one ProjectIndex +
    /// one LLM client). DB writes are atomic per-run, so concurrent
    /// workers don't race. Defaults to `1` (serial) when omitted.
    /// Typed `Option` so streamloop's `--default-concurrency` can
    /// tell "user passed it" from "default kicked in" — an explicit
    /// value wins over `-d`.
    #[arg(long = "reflect-concurrency")]
    pub reflect_concurrency: Option<usize>,
}

#[derive(Args)]
pub struct ReflectArgs {
    #[command(flatten)]
    pub project: ProjectArgs,

    #[command(flatten)]
    pub db: DatabaseArgs,

    #[command(flatten)]
    pub shared: ReflectSharedArgs,
}

impl ReflectArgs {
    /// CLI entry: open the project DB, delegate to [`Self::reflect`],
    /// print the verbose per-class counter line.
    pub async fn run(self, llm: &LLM) -> Result<()> {
        let LoadedRepoDatabase { spec, repo, .. } = self
            .project
            .to_repo_database(self.db.database_path.clone(), self.db.variant_render_cap)
            .await?;
        let stats = Self::reflect(&repo, llm, &spec.name, &spec.root, &self.shared).await?;
        println!(
            "Reflect finished: examined={} violated_runs={} graded={} valid_finding={} expected={} out_of_scope={} incomplete_step={} incomplete_spec={} severity_high={} severity_medium={} severity_low={} skipped_resumed={} skipped_non_completed={} skipped_unviolated={} verdict_errors={} severity_errors={}",
            stats.examined,
            stats.violated_runs,
            stats.graded,
            stats.valid_finding,
            stats.expected_violation,
            stats.out_of_scope,
            stats.incomplete_step,
            stats.incomplete_spec,
            stats.severity_high,
            stats.severity_medium,
            stats.severity_low,
            stats.skipped_resumed,
            stats.skipped_non_completed,
            stats.skipped_unviolated,
            stats.verdict_errors,
            stats.severity_errors,
        );
        Ok(())
    }

    /// In-process entry: triage every still-pending violated run
    /// through the verdict + severity graders. The autoloop passes a
    /// *separate*, typically more powerful LLM here than the one
    /// used for spec/fuzz/regen — the verdict grader is the FP gate,
    /// so giving it a smarter model is worth the extra cost. No
    /// `&self`: every knob comes from `shared`.
    pub async fn reflect(
        repo: &RepoDatabase,
        llm: &LLM,
        project_name: &str,
        repo_root: &Path,
        shared: &ReflectSharedArgs,
    ) -> Result<ReflectStats> {
        // Reflect needs the language for verdict + severity grader
        // prompt prefix. Source from the persisted profile —
        // workflow drivers always run profile first; the standalone
        // CLI fails fast here if profile is missing.
        let profile = repo.get_project_profile().await?.ok_or_else(|| {
            color_eyre::eyre::eyre!(
                "Reflect requires a ProjectProfile; run `knowdit agentic profile` for \
                 project '{project_name}' first (or let `workflow streamloop` run the \
                 profile phase)."
            )
        })?;
        // Standalone CLI: Solidity-only path (see map-semantics).
        if profile.language != SourceLanguage::Solidity {
            return Err(color_eyre::eyre::eyre!(
                "standalone `agentic reflect` only supports Solidity projects; use `workflow streamloop` for other languages"
            ));
        }
        let language_prompt_prefix = SolidityHarness::PROMPT_PREFIX.to_string();
        if shared.allow_redo_reflect {
            let cleared = repo.clear_reflections_for_redo().await?;
            tracing::warn!(
                cleared_reflections = cleared.reflections,
                cleared_valid_findings = cleared.valid_findings,
                "--allow-redo-reflect: wiped existing reflections; \
                 *_regen lineage triggered_by_reflection_id may now dangle"
            );
        }
        let grader_options = GraderOptions {
            max_agent_steps: shared.grader_max_agent_steps,
            debug_prefix: shared.reflect_debug_prefix.clone(),
            llm_settings: None,
        };
        let runner = ReflectionRunner::load(
            repo.clone(),
            repo_root,
            llm.clone(),
            language_prompt_prefix,
            grader_options,
            shared.reflect_skip_grader,
            shared.reflect_concurrency.unwrap_or(1).max(1),
        )
        .await?;
        runner.run(shared.reflect_max_runs).await
    }

    /// Scheduler entry: reflect only violated runs whose owning
    /// `code_gen.id` is in `code_gen_ids`. This is the streaming
    /// counterpart to [`Self::reflect`] — it skips the global pending
    /// barrier so a scheduler can advance one link's lineage without
    /// waiting for unrelated work to finish grading.
    pub async fn reflect_code_gens(
        repo: &RepoDatabase,
        llm: &LLM,
        repo_root: &Path,
        language_prompt_prefix: String,
        shared: &ReflectSharedArgs,
        code_gen_ids: &[i32],
    ) -> Result<ReflectStats> {
        if code_gen_ids.is_empty() {
            return Ok(ReflectStats::default());
        }
        let grader_options = GraderOptions {
            max_agent_steps: shared.grader_max_agent_steps,
            debug_prefix: shared.reflect_debug_prefix.clone(),
            llm_settings: None,
        };
        let runner = ReflectionRunner::load(
            repo.clone(),
            repo_root,
            llm.clone(),
            language_prompt_prefix,
            grader_options,
            shared.reflect_skip_grader,
            shared.reflect_concurrency.unwrap_or(1).max(1),
        )
        .await?;
        runner.run_code_gens(code_gen_ids).await
    }
}

/// One unit of work for the grader dispatch — a violated run that
/// has cleared every "skip" filter and needs a verdict (+ optional
/// severity) pass. Cloned out of the loaded slices so the worker
/// pool can take ownership without borrowing the shared runner.
#[derive(Clone)]
struct WorkItem {
    code_gen: LoadedCodeGen,
    run: LoadedHarnessRun,
}

/// Per-item result from a pool worker. Carries the partial counter
/// deltas the merge step will fold into the live `ReflectStats`.
struct ReflectOutcome {
    stats: ReflectStats,
}

fn merge_outcome(dst: &mut ReflectStats, src: ReflectOutcome) {
    let ReflectStats {
        examined,
        violated_runs,
        graded,
        valid_finding,
        expected_violation,
        out_of_scope,
        incomplete_step,
        incomplete_spec,
        severity_high,
        severity_medium,
        severity_low,
        skipped_resumed,
        skipped_non_completed,
        skipped_unviolated,
        verdict_errors,
        severity_errors,
    } = src.stats;
    dst.examined += examined;
    dst.violated_runs += violated_runs;
    dst.graded += graded;
    dst.valid_finding += valid_finding;
    dst.expected_violation += expected_violation;
    dst.out_of_scope += out_of_scope;
    dst.incomplete_step += incomplete_step;
    dst.incomplete_spec += incomplete_spec;
    dst.severity_high += severity_high;
    dst.severity_medium += severity_medium;
    dst.severity_low += severity_low;
    dst.skipped_resumed += skipped_resumed;
    dst.skipped_non_completed += skipped_non_completed;
    dst.skipped_unviolated += skipped_unviolated;
    dst.verdict_errors += verdict_errors;
    dst.severity_errors += severity_errors;
}

/// Aggregate counters for one reflect invocation. Captures the
/// 5-class verdict distribution and the 3-tier severity distribution.
#[derive(Default, Debug)]
pub struct ReflectStats {
    pub examined: usize,
    pub violated_runs: usize,
    pub graded: usize,
    pub valid_finding: usize,
    pub expected_violation: usize,
    pub out_of_scope: usize,
    pub incomplete_step: usize,
    pub incomplete_spec: usize,
    pub severity_high: usize,
    pub severity_medium: usize,
    pub severity_low: usize,
    pub skipped_resumed: usize,
    pub skipped_non_completed: usize,
    pub skipped_unviolated: usize,
    pub verdict_errors: usize,
    pub severity_errors: usize,
}

/// Owns everything the per-run loop needs. Built once per CLI
/// invocation; loads the spec map + code_gens once, builds both
/// graders via [`GraderPair`] (which shares one `ProjectIndex`).
/// Held inside an `Arc` so concurrent workers can share the loaded
/// state without re-cloning the call graph for every task.
struct ReflectionRunner {
    repo: RepoDatabase,
    graders: Option<GraderPair>,
    /// Specs kept as raw JSON `Value` so the grader path is language-agnostic
    /// (Solidity `AuditSpecification` and Move `MoveAuditSpecification` both
    /// flow through unchanged — the grader serializes the spec for the LLM and
    /// never introspects its fields). The Solidity-only coverage gate
    /// re-derives the typed `AuditSpecification` via `from_value` on demand.
    spec_by_id: HashMap<i32, serde_json::Value>,
    code_gens: Vec<LoadedCodeGen>,
    concurrency: usize,
}

impl ReflectionRunner {
    async fn load(
        repo: RepoDatabase,
        repo_root: &Path,
        llm: llmy::client::client::LLM,
        language_prompt_prefix: String,
        grader_options: GraderOptions,
        skip_grader: bool,
        concurrency: usize,
    ) -> Result<Self> {
        let specs = repo.load_specifications().await?;
        let spec_by_id = decode_specs(&specs)?;
        let code_gens = repo.load_code_gens().await?;
        let graders = if skip_grader {
            None
        } else {
            Some(
                GraderPair::new(
                    &repo,
                    repo_root,
                    language_prompt_prefix,
                    &llm,
                    grader_options,
                )
                .await?,
            )
        };
        Ok(Self {
            repo,
            graders,
            spec_by_id,
            code_gens,
            concurrency: concurrency.max(1),
        })
    }

    /// Walk every loaded `code_gen` + its runs, tally the
    /// skip-the-grader counters inline, and collect the remaining
    /// `(code_id, run_id)` pairs that actually need a grader pass.
    /// One sequential DB-fanout pass per call — concurrent grading
    /// runs against the returned queue.
    async fn collect_work(
        &self,
        max_runs: usize,
        stats: &mut ReflectStats,
    ) -> Result<Vec<WorkItem>> {
        let mut queue = Vec::new();
        for code_gen in &self.code_gens {
            if !matches!(code_gen.core.status, CodeGenStatus::Completed) {
                stats.skipped_non_completed += 1;
                continue;
            }
            let runs = self.repo.load_runs_for_code_gen(code_gen.id).await?;
            for run in runs {
                if max_runs > 0 && stats.examined + queue.len() >= max_runs {
                    return Ok(queue);
                }
                if !run.violated {
                    stats.skipped_unviolated += 1;
                    continue;
                }
                stats.violated_runs += 1;
                if self.repo.has_reflection(run.id).await? {
                    stats.skipped_resumed += 1;
                    continue;
                }
                if self.graders.is_none() {
                    tracing::debug!(
                        run_id = run.id,
                        code_id = code_gen.id,
                        spec_id = code_gen.core.spec_id,
                        "violated run; skip_grader=true, no row written"
                    );
                    continue;
                }
                queue.push(WorkItem {
                    code_gen: code_gen.clone(),
                    run,
                });
            }
        }
        Ok(queue)
    }

    async fn run(self, max_runs: usize) -> Result<ReflectStats> {
        let mut stats = ReflectStats::default();
        let queue = self.collect_work(max_runs, &mut stats).await?;
        let total = queue.len();
        if total == 0 {
            return Ok(stats);
        }
        let concurrency = self.concurrency.min(total);
        tracing::info!(
            total_to_grade = total,
            concurrency,
            "reflect: starting grader dispatch"
        );

        let me = Arc::new(self);
        if concurrency <= 1 {
            for item in queue {
                me.reflect_one_logged(&item, &mut stats).await;
            }
            return Ok(stats);
        }

        // Worker pool: shared mutex-guarded LIFO of pending work,
        // mpsc back-channel for per-item outcomes. Same shape as
        // the fuzz pool so the two phases behave identically under
        // concurrency.
        let queue: Arc<tokio::sync::Mutex<Vec<WorkItem>>> =
            Arc::new(tokio::sync::Mutex::new(queue.into_iter().rev().collect()));
        let (tx, mut rx) = tokio::sync::mpsc::channel::<ReflectOutcome>(concurrency * 2);
        let mut handles = Vec::with_capacity(concurrency);
        for _ in 0..concurrency {
            let queue = queue.clone();
            let tx = tx.clone();
            let me = me.clone();
            handles.push(tokio::spawn(async move {
                loop {
                    let next = {
                        let mut q = queue.lock().await;
                        q.pop()
                    };
                    let Some(item) = next else {
                        break;
                    };
                    let outcome = me.reflect_one_for_pool(&item).await;
                    if tx.send(outcome).await.is_err() {
                        break;
                    }
                }
            }));
        }
        drop(tx);
        while let Some(outcome) = rx.recv().await {
            merge_outcome(&mut stats, outcome);
        }
        for h in handles {
            let _ = h.await;
        }
        Ok(stats)
    }

    /// Streaming-scheduler entry: walk the runner's preloaded `code_gens`,
    /// keep only the ones whose id appears in `code_gen_ids`, and run the
    /// same concurrent grader dispatch as [`Self::run`]. Skip filters
    /// (`skipped_non_completed` / `skipped_unviolated` / `skipped_resumed`)
    /// still fire so callers can tell why scoped work was skipped.
    async fn run_code_gens(self, code_gen_ids: &[i32]) -> Result<ReflectStats> {
        let wanted: std::collections::HashSet<i32> = code_gen_ids.iter().copied().collect();
        let mut stats = ReflectStats::default();
        let queue = self.collect_work_for_code_gens(&wanted, &mut stats).await?;
        let total = queue.len();
        if total == 0 {
            return Ok(stats);
        }
        let concurrency = self.concurrency.min(total);
        tracing::info!(
            total_to_grade = total,
            concurrency,
            "reflect: starting targeted grader dispatch"
        );

        let me = Arc::new(self);
        if concurrency <= 1 {
            for item in queue {
                me.reflect_one_logged(&item, &mut stats).await;
            }
            return Ok(stats);
        }

        let queue: Arc<tokio::sync::Mutex<Vec<WorkItem>>> =
            Arc::new(tokio::sync::Mutex::new(queue.into_iter().rev().collect()));
        let (tx, mut rx) = tokio::sync::mpsc::channel::<ReflectOutcome>(concurrency * 2);
        let mut handles = Vec::with_capacity(concurrency);
        for _ in 0..concurrency {
            let queue = queue.clone();
            let tx = tx.clone();
            let me = me.clone();
            handles.push(tokio::spawn(async move {
                loop {
                    let next = {
                        let mut q = queue.lock().await;
                        q.pop()
                    };
                    let Some(item) = next else {
                        break;
                    };
                    let outcome = me.reflect_one_for_pool(&item).await;
                    if tx.send(outcome).await.is_err() {
                        break;
                    }
                }
            }));
        }
        drop(tx);
        while let Some(outcome) = rx.recv().await {
            merge_outcome(&mut stats, outcome);
        }
        for h in handles {
            let _ = h.await;
        }
        Ok(stats)
    }

    async fn collect_work_for_code_gens(
        &self,
        wanted: &std::collections::HashSet<i32>,
        stats: &mut ReflectStats,
    ) -> Result<Vec<WorkItem>> {
        let mut queue = Vec::new();
        for code_gen in &self.code_gens {
            if !wanted.contains(&code_gen.id) {
                continue;
            }
            if !matches!(code_gen.core.status, CodeGenStatus::Completed) {
                stats.skipped_non_completed += 1;
                continue;
            }
            let runs = self.repo.load_runs_for_code_gen(code_gen.id).await?;
            for run in runs {
                if !run.violated {
                    stats.skipped_unviolated += 1;
                    continue;
                }
                stats.violated_runs += 1;
                if self.repo.has_reflection(run.id).await? {
                    stats.skipped_resumed += 1;
                    continue;
                }
                if self.graders.is_none() {
                    tracing::debug!(
                        run_id = run.id,
                        code_id = code_gen.id,
                        spec_id = code_gen.core.spec_id,
                        "violated run; skip_grader=true, no row written"
                    );
                    continue;
                }
                queue.push(WorkItem {
                    code_gen: code_gen.clone(),
                    run,
                });
            }
        }
        Ok(queue)
    }

    /// Serial-path wrapper: drive `reflect_one` against the live
    /// `stats` accumulator. Mirrors the legacy pre-concurrency
    /// behavior so concurrency=1 stays bit-identical.
    async fn reflect_one_logged(&self, item: &WorkItem, stats: &mut ReflectStats) {
        stats.examined += 1;
        let graders = self
            .graders
            .as_ref()
            .expect("collect_work filters out skip_grader");
        if let Err(err) = self
            .reflect_one(graders, &item.code_gen, &item.run, stats)
            .await
        {
            tracing::error!(
                run_id = item.run.id,
                code_id = item.code_gen.id,
                "reflection pipeline failed: {err:#}"
            );
        }
    }

    /// Concurrent-path wrapper: produce an owned `ReflectOutcome`
    /// instead of mutating a shared accumulator. Pool driver merges.
    async fn reflect_one_for_pool(&self, item: &WorkItem) -> ReflectOutcome {
        let mut stats = ReflectStats::default();
        stats.examined = 1;
        let graders = self
            .graders
            .as_ref()
            .expect("collect_work filters out skip_grader");
        if let Err(err) = self
            .reflect_one(graders, &item.code_gen, &item.run, &mut stats)
            .await
        {
            tracing::error!(
                run_id = item.run.id,
                code_id = item.code_gen.id,
                "reflection pipeline failed: {err:#}"
            );
        }
        ReflectOutcome { stats }
    }

    /// Two-phase pipeline for one violated run: verdict grader →
    /// (if ValidFinding) severity grader → atomic write. Each phase
    /// is a separate member fn so the data flow reads top-down.
    async fn reflect_one(
        &self,
        graders: &GraderPair,
        code_gen: &LoadedCodeGen,
        run: &LoadedHarnessRun,
        stats: &mut ReflectStats,
    ) -> Result<()> {
        let v_input = self.build_verdict_input(code_gen, run).await?;
        let verdict = match graders.verdict.grade(&v_input).await {
            Ok(v) => v,
            Err(err) => {
                tracing::error!(run_id = run.id, "verdict grader failed: {err:#}");
                stats.verdict_errors += 1;
                return Ok(());
            }
        };

        let severity = if matches!(verdict.result, ReflectionResult::ValidFinding) {
            let s_input = self.build_severity_input(&v_input, &verdict);
            match graders.severity.grade(&s_input).await {
                Ok(s) => Some(s),
                Err(err) => {
                    tracing::error!(run_id = run.id, "severity grader failed: {err:#}");
                    stats.severity_errors += 1;
                    return Ok(());
                }
            }
        } else {
            None
        };

        self.persist(run, &verdict, severity.as_ref()).await?;
        Self::tally(&verdict, severity.as_ref(), stats);
        Ok(())
    }

    async fn build_verdict_input(
        &self,
        code_gen: &LoadedCodeGen,
        run: &LoadedHarnessRun,
    ) -> Result<VerdictInput> {
        let spec = self
            .spec_by_id
            .get(&code_gen.core.spec_id)
            .ok_or_else(|| {
                color_eyre::eyre::eyre!(
                    "code_gen {} references missing spec_id={}",
                    code_gen.id,
                    code_gen.core.spec_id
                )
            })?
            .clone();

        let coverage_rows = self.repo.load_coverage_for_code_gen(code_gen.id).await?;
        let coverage_summary = if coverage_rows.is_empty() {
            None
        } else {
            // Coverage fidelity is a Solidity-only gate; re-derive the typed
            // spec from the stored JSON (Move never reaches here — it produces
            // no coverage rows).
            let typed: AuditSpecification =
                serde_json::from_value(spec.clone()).wrap_err_with(|| {
                    format!(
                        "coverage gate expected a Solidity AuditSpecification for spec_id={}",
                        code_gen.core.spec_id
                    )
                })?;
            let cg = self.repo.load_call_graph().await?;
            let report = coverage_audit::collect_report(&typed, &coverage_rows, &cg);
            Some(CoverageSummary {
                fidelity: report.fidelity,
                hit_fns: report.hit_fns,
                expected_fns: report.expected_fns,
                missed_step_labels: report.missed_step_labels(),
            })
        };

        let prior_incomplete_step_count =
            self.repo.prior_incomplete_step_count(code_gen.id).await?;

        Ok(VerdictInput {
            run_id: run.id,
            spec_id: code_gen.core.spec_id,
            spec,
            harness_source: code_gen.core.harness_source.clone(),
            finding_title: None,
            run: run_summary_of(run),
            coverage_summary,
            prior_incomplete_step_count,
            // `VerdictGrader::grade` fills the cached profile in if
            // this is `None`; we leave it `None` here so callers
            // without DB access don't need to load it themselves.
            project_profile: None,
        })
    }

    fn build_severity_input(
        &self,
        v_input: &VerdictInput,
        verdict: &VerdictOutput,
    ) -> SeverityInput {
        SeverityInput {
            run_id: v_input.run_id,
            spec_id: v_input.spec_id,
            spec: v_input.spec.clone(),
            harness_source: v_input.harness_source.clone(),
            finding_title: v_input.finding_title.clone(),
            run: v_input.run.clone(),
            coverage_summary: v_input.coverage_summary.clone(),
            verdict_reason: verdict.reason.clone(),
        }
    }

    /// Atomic single-transaction write of reflection (+ optional
    /// valid_finding) for one run. Resume safety: a failure here
    /// rolls back; the next reflect pass sees the run as still pending.
    async fn persist(
        &self,
        run: &LoadedHarnessRun,
        verdict: &VerdictOutput,
        severity: Option<&SeverityOutput>,
    ) -> Result<()> {
        let reflection = ReflectionRecord {
            run_id: run.id,
            spec_id: run_spec_id(run, &self.code_gens),
            result: verdict.result,
            reason: verdict.reason.clone(),
            ruled_out_claim: verdict.ruled_out_claim.clone(),
            ruled_out_evidence: verdict.ruled_out_evidence.clone(),
        };
        let finding = severity.map(|s| ValidFindingRecord {
            severity: s.severity,
            severity_reason: s.severity_reason.clone(),
        });
        self.repo
            .insert_reflection_with_finding(&reflection, finding.as_ref())
            .await?;
        tracing::info!(
            run_id = run.id,
            verdict = ?verdict.result,
            verdict_steps = verdict.steps,
            severity = ?severity.map(|s| s.severity),
            severity_steps = severity.map(|s| s.steps),
            "graded violated run"
        );
        Ok(())
    }

    fn tally(verdict: &VerdictOutput, severity: Option<&SeverityOutput>, stats: &mut ReflectStats) {
        stats.graded += 1;
        match verdict.result {
            ReflectionResult::ValidFinding => stats.valid_finding += 1,
            ReflectionResult::ExpectedViolation => stats.expected_violation += 1,
            ReflectionResult::OutOfScope => stats.out_of_scope += 1,
            ReflectionResult::IncompleteStep => stats.incomplete_step += 1,
            ReflectionResult::IncompleteSpecification => stats.incomplete_spec += 1,
            ReflectionResult::Suspect => {
                tracing::warn!("verdict grader emitted Suspect (should be impossible)");
            }
        }
        if let Some(s) = severity {
            use knowdit_kg_model::audit_finding::FindingSeverity as F;
            match s.severity {
                F::High => stats.severity_high += 1,
                F::Medium => stats.severity_medium += 1,
                F::Low => stats.severity_low += 1,
            }
        }
    }
}

/// Look up the owning code_gen.spec_id for a run. The runs and
/// code_gens slices are joined by `run.code_id == code_gen.id`.
fn run_spec_id(run: &LoadedHarnessRun, code_gens: &[LoadedCodeGen]) -> i32 {
    code_gens
        .iter()
        .find(|cg| cg.id == run.code_id)
        .map(|cg| cg.core.spec_id)
        .expect("loaded run must have a matching loaded code_gen")
}

fn run_summary_of(run: &LoadedHarnessRun) -> RunSummary {
    RunSummary {
        kind: format!("{}", run.kind),
        exit_code: run.exit_code,
        violated: run.violated,
        stdout_tail: tail_str(&run.stdout, 4_000),
        counterexample_json: run
            .sequence_json
            .as_deref()
            .and_then(|s| serde_json::from_str(s).ok()),
    }
}

fn decode_specs(specs: &[LoadedSpecification]) -> Result<HashMap<i32, serde_json::Value>> {
    let mut out = HashMap::with_capacity(specs.len());
    for spec in specs {
        let parsed: serde_json::Value = serde_json::from_str(&spec.specification_json)
            .wrap_err_with(|| {
                format!("failed to parse specification.json for spec_id={}", spec.id)
            })?;
        out.insert(spec.id, parsed);
    }
    Ok(out)
}

/// Take the last `max_bytes` of `s`, byte-aligned to a UTF-8 boundary.
/// Suitable for forge stdout tails — last K bytes carry the invariant
/// verdict and counter-example dump.
fn tail_str(s: &str, max_bytes: usize) -> String {
    if s.len() <= max_bytes {
        return s.to_string();
    }
    let mut start = s.len() - max_bytes;
    while start < s.len() && !s.is_char_boundary(start) {
        start += 1;
    }
    s[start..].to_string()
}
