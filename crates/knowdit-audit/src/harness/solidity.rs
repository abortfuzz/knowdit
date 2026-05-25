//! Foundry fuzzing harness generator.
//!
//! ## Data flow
//! ```text
//!     LinkInput (extract semantic + historical + finding + spec JSON)
//!         │
//!         ▼
//!     [`HarnessAttempt`] in-memory state for one agent run:
//!         · LLM-driven exploration (memory + read tools)
//!         · `write_harness_file` tool stages a `.sol` on disk
//!         · `run_forge` tool invokes [`ForgeRunner`] (test or coverage)
//!         · `finalize` ends the agent
//!         │
//!         ▼
//!     Persistence (one DB transaction per finalized link):
//!         · `code_gen` row
//!         · 0..N `harness_run` rows (one per forge invocation)
//!         · 0..N `line_coverage` rows from coverage runs
//! ```
//!
//! Resume-safe: every spec's outcome is committed in a single transaction
//! at finalize time. Killing the process mid-link loses only that link.
//! Re-running with default `regenerate=false` skips specs whose `code_gen`
//! row is already `Completed`.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use color_eyre::eyre::{Result, WrapErr};
use knowdit_kg_model::ExtractedSemantic;
use knowdit_repo_model::{
    CodeGenCore, CodeGenRecord, CodeGenStatus, CoverageEntry, HarnessRunRecord,
    HistoricalSemanticRecord, RepoDatabase, RunKind, SemanticMatchSet,
};
use llmy::agent::StepResult;
use llmy::agent::tool::ToolBox;
use llmy::client::client::LLM;
use llmy::client::settings::LLMSettings;
use llmy::harness::Agent;
use schemars::JsonSchema;
use serde::Deserialize;
use tokio::sync::Mutex;

use super::forge::{ForgeBackend, ForgeRunner};
use super::solidity_prompt::{ProjectConventions, build_system_prompt, build_user_prompt};
use crate::spec::{
    LinkInput, LookupCallGraphTool, LookupStateVariableXrefsTool, ProjectIndex,
    ReadContractSourceTool, ReadFunctionSourceTool, build_link_inputs, build_link_memory,
    spec_memory_criteria,
};
use crate::types::AuditSpecification;

// =============================================================================
// Options + outcome types
// =============================================================================

/// Configuration knobs for one fuzz pass. Every value must come from the CLI
/// (no hidden env reads).
#[derive(Debug, Clone)]
pub struct FuzzOptions {
    /// Repository root on disk (`out_git/contracts/<id>/...`).
    pub repo_root: PathBuf,
    /// Where to write `.sol` harness files. Resolved by [`Self::resolve_harness_dir`]
    /// when None — `<repo>/test/knowdit_harness` if the repo is Foundry,
    /// otherwise `<repo>/knowdit_harness`.
    pub harness_dir: Option<PathBuf>,
    /// Path to the `forge` binary. `None` selects docker mode (see
    /// [`Self::docker_image`]); `Some(path)` selects local mode and runs
    /// that binary directly. There is intentionally no `"forge"` default —
    /// callers must opt in to local mode by passing the binary explicitly.
    pub forge_bin: Option<PathBuf>,
    /// Docker image used when [`Self::forge_bin`] is `None`. Defaults to
    /// `lazymio/knowdit:foundry`.
    pub docker_image: String,
    /// Per-invocation memory ceiling, in bytes. `None` disables the cap.
    /// In local mode this is enforced via cgroup v2 (when available);
    /// in docker mode it's plumbed through `--memory` / `--memory-swap`.
    pub forge_mem_cap_bytes: Option<u64>,
    /// Hard timeout per forge subprocess (seconds).
    pub forge_timeout_secs: u64,
    /// `--fuzz-runs` for the test invocation.
    pub forge_test_runs: u64,
    /// `--fuzz-runs` for the coverage invocation (usually smaller, since
    /// `forge coverage` is much slower per sample).
    pub forge_coverage_runs: u64,
    /// Hard cap on agent steps across all restarts for one spec.
    pub max_agent_steps: usize,
    /// Per-link cap; 0 = unbounded.
    pub max_specs: usize,
    /// Worker pool size.
    pub concurrency: usize,
    /// When true, clear `code_gen` / `harness_run` / `line_coverage` and
    /// reprocess every spec from scratch.
    pub regenerate: bool,
    /// `llmy` cache key prefix.
    pub cache_key: String,
    /// Optional debug-prefix forwarded to `llmy` for LLM-call dumps.
    pub debug_prefix: Option<String>,
    /// Optional override for the `LLMSettings` (mostly to forward
    /// reasoning_effort, temperature, etc.). None lets `llmy` defaults apply.
    pub llm_settings: Option<LLMSettings>,
    /// When the agent's approximate context size hits this many tokens
    /// the orchestrator drops the conversation and restarts a fresh
    /// agent (with a small "previous attempt" bootstrap). `None` means
    /// "never restart on tokens" — only the step budget terminates.
    pub window_restart_threshold_tokens: Option<usize>,
    /// Maximum number of agent restarts per spec. Once exhausted the
    /// spec is abandoned even if the step budget still has room.
    pub max_restarts: usize,
    /// Gate 2 fidelity threshold passed to the inline coverage gate that
    /// runs inside `run_forge`. Same semantic as `agentic reflect`'s
    /// `--gate2-fidelity-threshold`. Defaults to 0.5 in the CLI layer.
    pub gate2_fidelity_threshold: f64,
    /// The project is built with `viaIR = true`. Affects `forge
    /// coverage`: when the runtime supports `--force-via-ir`, the
    /// coverage subcommand opts in (sacrificing some line-mapping
    /// accuracy for compile parity with the project's viaIR build);
    /// when not, coverage runs WITHOUT viaIR and may fail to
    /// compile via-IR-only projects — the agent prompt is told
    /// this is expected and not to keep retrying.
    pub via_ir: bool,
}

impl FuzzOptions {
    /// Resolve [`Self::harness_dir`] given an inspection of the repo root.
    /// Returns the absolute path the agent should write harness files to.
    ///
    /// When `foundry.toml` exists, we honor its `test = '<dir>'` directive so
    /// `forge` actually picks our harness file up — projects like Panoptic
    /// configure `test = 'test/foundry'` and will silently ignore files we
    /// drop into the conventional `test/`. Falls through to `<repo>/test/` if
    /// `foundry.toml` has no explicit `test` directive, and finally to
    /// `<repo>/` if no foundry config exists at all.
    pub fn resolve_harness_dir(&self) -> PathBuf {
        if let Some(dir) = &self.harness_dir {
            return dir.clone();
        }
        let foundry_toml = self.repo_root.join("foundry.toml");
        if foundry_toml.exists() {
            if let Ok(text) = std::fs::read_to_string(&foundry_toml) {
                if let Some(test_subdir) = parse_foundry_test_dir(&text) {
                    return self.repo_root.join(test_subdir).join("knowdit_harness");
                }
            }
            // foundry.toml exists but no explicit `test = ...`; default test/.
            return self.repo_root.join("test").join("knowdit_harness");
        }
        self.repo_root.join("knowdit_harness")
    }
}

/// Best-effort parse of foundry.toml's `[profile.default]` (or top-level)
/// `test = '<path>'` directive. Returns the path string verbatim. Tolerates
/// missing key, comments, and other profiles.
pub(super) fn parse_foundry_test_dir(toml_text: &str) -> Option<String> {
    let mut in_default = false;
    for raw in toml_text.lines() {
        let line = raw.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            in_default = matches!(line, "[profile.default]" | "[default]");
            continue;
        }
        // The directive may live in the `[profile.default]` table or at the
        // top of the file before any `[...]` header — treat both as
        // "default profile".
        if in_default || !toml_text.contains("[profile.default]") {
            if let Some(rest) = line.strip_prefix("test") {
                let rest = rest.trim_start();
                if let Some(rest) = rest.strip_prefix('=') {
                    let val = rest.trim().trim_matches(|c| c == '\'' || c == '"');
                    if !val.is_empty() {
                        return Some(val.to_string());
                    }
                }
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parses_foundry_test_dir() {
        let toml = "[profile.default]\nsrc = 'contracts'\ntest = 'test/foundry'\nout = 'out'\n";
        assert_eq!(
            parse_foundry_test_dir(toml).as_deref(),
            Some("test/foundry")
        );
    }
    #[test]
    fn missing_test_dir_returns_none() {
        let toml = "[profile.default]\nsrc = 'contracts'\nout = 'out'\n";
        assert!(parse_foundry_test_dir(toml).is_none());
    }
    #[test]
    fn ignores_other_profiles() {
        let toml = "[profile.default]\nsrc = 'a'\n[profile.ci]\ntest = 'never'\n";
        assert!(parse_foundry_test_dir(toml).is_none());
    }
}

/// Top-level outcome: counts + per-link records (in DB, not returned in
/// memory — we only return summary numbers).
#[derive(Debug, Default)]
pub struct FuzzOutcome {
    pub processed_count: usize,
    pub completed_count: usize,
    pub abandoned_count: usize,
    pub error_count: usize,
    pub violated_count: usize,
    pub skipped_resumed: usize,
}

/// What one agent run produced for one link, before persistence.
#[derive(Debug)]
struct LinkFuzzOutcome {
    spec_id: i32,
    code_gen: CodeGenRecord,
    coverage_per_run: Vec<Vec<CoverageEntry>>,
    /// Whether at least one of the `code_gen.runs` had `violated == true`.
    any_violation: bool,
}

/// Why the orchestrator stopped iterating for one spec. Mapped to
/// [`CodeGenStatus`] downstream, but kept separate so we can fold the
/// "no violation but the loop ran cleanly" / "no violation and we ran
/// out of restarts" distinction without forcing a new DB enum value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LoopOutcome {
    /// `forge test` reported `violated=true` at least once.
    Violation,
    /// Reached `max_agent_steps` without a violation.
    StepsExhausted,
    /// Reached `max_restarts` without a violation. Maps to `Completed`
    /// when forge actually ran at least once (we have something to
    /// hand off to reflect/regen), otherwise `Abandoned`.
    RestartsExhausted,
    /// `Agent::step` itself errored (LLM 5xx, deserialize failure, …).
    /// Stored verbatim in `final_reason`.
    AgentError,
}

// =============================================================================
// Parsers
// =============================================================================

/// Structured digest of one `forge test --json` invocation. Captures the
/// runtime signals that drive Gate 1 inline (setUp success, fuzzer
/// effective-call count, counter-example contract+function decoding)
/// instead of just `violated`.
#[derive(Debug, Clone, Default)]
pub struct ForgeTestSummary {
    /// True if any test in any suite has `reason` containing "failed to set
    /// up" — forge's canonical phrasing for setUp() reverts. The harness
    /// compiled, but the invariant body never executed.
    pub setup_failed: bool,
    /// First non-empty `reason` field seen on a Failure status. Useful for
    /// telling the agent *why* setUp failed.
    pub failure_reason: Option<String>,
    /// Sum of `TestKind::Invariant.calls` across suites — total invariant
    /// fuzz calls actually issued by forge.
    pub total_calls: i64,
    /// Sum of `TestKind::Invariant.reverts` across suites.
    pub total_reverts: i64,
    /// True iff at least one test produced a non-empty counter-example
    /// sequence.
    pub violated: bool,
    /// Decoded counter-example calls (forge already does the ABI decoding
    /// for us in JSON output) — empty when no violation.
    pub counterexample_calls: Vec<CounterCall>,
    /// The original counter-example JSON for storage in `harness_run.sequence_json`.
    pub counterexample_json: Option<serde_json::Value>,
}

/// One decoded call from a counter-example sequence (`BaseCounterExample`
/// in forge). Field names are forge's `--json` output verbatim.
#[derive(Debug, Clone, Default)]
pub struct CounterCall {
    pub contract: Option<String>,
    pub function: Option<String>,
    pub args: Option<String>,
}

impl ForgeTestSummary {
    pub fn revert_rate(&self) -> f64 {
        if self.total_calls == 0 {
            0.0
        } else {
            self.total_reverts as f64 / self.total_calls as f64
        }
    }
}

impl std::fmt::Display for ForgeTestSummary {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "calls={} reverts={} revert_rate={:.3} violated={} setup_failed={}",
            self.total_calls,
            self.total_reverts,
            self.revert_rate(),
            self.violated,
            self.setup_failed,
        )?;
        if let Some(reason) = &self.failure_reason {
            write!(f, " failure_reason={reason:?}")?;
        }
        if !self.counterexample_calls.is_empty() {
            let preview = self
                .counterexample_calls
                .iter()
                .take(3)
                .map(|c| {
                    format!(
                        "{}::{}",
                        c.contract.as_deref().unwrap_or("?"),
                        c.function.as_deref().unwrap_or("?"),
                    )
                })
                .collect::<Vec<_>>()
                .join(",");
            write!(
                f,
                " counterexample={}[{}{}]",
                self.counterexample_calls.len(),
                preview,
                if self.counterexample_calls.len() > 3 {
                    ",…"
                } else {
                    ""
                }
            )?;
        }
        Ok(())
    }
}

/// Parse `forge test --json` stdout into a [`ForgeTestSummary`] via the
/// typed mirror in [`super::forge_json`]. Best-effort: when stdout
/// isn't a JSON suite map (compile errors, mixed text mode), serde
/// returns an error and we fall back to a default summary — Gate 1
/// then sees `setup_failed=false, calls=0` and passes, leaving the
/// agent to react to the raw exit code instead.
pub fn parse_forge_test_summary(stdout: &str) -> ForgeTestSummary {
    use super::forge_json::{CounterExample, SuiteMap, TestStatus};

    let mut summary = ForgeTestSummary::default();
    let suites: SuiteMap = serde_json::from_str(stdout.trim()).unwrap_or_default();
    for suite in suites.values() {
        for (test_name, tr) in &suite.test_results {
            if let Some(stats) = tr.invariant_stats() {
                summary.total_calls += stats.calls;
                summary.total_reverts += stats.reverts;
            }
            if tr.is_setup_failure(test_name) {
                summary.setup_failed = true;
            }
            if tr.status == TestStatus::Failure {
                if let Some(reason) = &tr.reason {
                    if !reason.is_empty() && summary.failure_reason.is_none() {
                        summary.failure_reason = Some(reason.clone());
                    }
                }
            }
            let counterexample = tr.counterexample.as_ref().or_else(|| {
                tr.invariant_failures
                    .iter()
                    .find_map(|failure| failure.counterexample.as_ref())
            });
            if let Some(CounterExample::Sequence(_orig, calls)) = counterexample {
                if !calls.is_empty() {
                    summary.violated = true;
                    summary.counterexample_json = serde_json::to_value(counterexample).ok();
                    for call in calls {
                        summary.counterexample_calls.push(CounterCall {
                            contract: call.contract_name.clone(),
                            function: call.func_name.clone(),
                            args: call.args.clone(),
                        });
                    }
                }
            }
        }
    }
    summary
}

/// Parse a minimal subset of LCOV: every `DA:<line>,<hits>` after a
/// `SF:<source-file-path>` block. Path is taken verbatim from the SF line.
fn parse_lcov(text: &str) -> Vec<CoverageEntry> {
    let mut current_file: Option<String> = None;
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.trim_end();
        if let Some(rest) = line.strip_prefix("SF:") {
            current_file = Some(rest.trim().to_string());
        } else if line == "end_of_record" {
            current_file = None;
        } else if let Some(rest) = line.strip_prefix("DA:") {
            let Some(file) = &current_file else { continue };
            let mut parts = rest.split(',');
            let (Some(line_str), Some(hits_str)) = (parts.next(), parts.next()) else {
                continue;
            };
            let Ok(line_num) = line_str.trim().parse::<i32>() else {
                continue;
            };
            let Ok(hits) = hits_str.trim().parse::<i64>() else {
                continue;
            };
            out.push(CoverageEntry {
                relative_contract_path: file.clone(),
                line_number: line_num,
                hit_count: hits,
            });
        }
    }
    out
}

// =============================================================================
// Per-link mutable state during the agent run
// =============================================================================

/// In-memory accumulator for one agent run. Tools mutate this through an
/// `Arc<Mutex>` handle so the agent's tool-call loop can share state across
/// turns. The orchestrator drains this into a [`CodeGenRecord`] when the
/// outer loop terminates (violation found / steps exhausted / restarts
/// exhausted). There is no in-agent `finalize` tool — the agent just
/// keeps iterating until the orchestrator stops it.
#[derive(Debug, Default)]
struct HarnessAttempt {
    /// Latest source the agent wrote via `write_harness_file`.
    harness_source: String,
    /// Filename relative to `harness_dir` (e.g. `Test_42.t.sol`).
    harness_filename: Option<String>,
    /// Each completed forge run, in order. A single `run_forge` tool
    /// call may push two entries: one test run, plus (when the test
    /// produced calls > 0 and exited cleanly) one coverage run we
    /// fired automatically right after.
    runs: Vec<RecordedRun>,
    /// Coverage entries parsed from coverage runs, indexed by the
    /// `coverage_idx` field on the corresponding [`RecordedRun`].
    coverage: Vec<Vec<CoverageEntry>>,
    /// True the first time a forge test run reported `violated=true`.
    /// The orchestrator polls this between steps and exits the loop
    /// as soon as it flips.
    violation_observed: bool,
    /// Latest auto-coverage gate verdict. `true` when the most recent
    /// coverage run hit the gate2 fidelity threshold; `false` when it
    /// failed or no coverage has run yet. Used by restart bootstrap to
    /// summarise progress.
    last_gate_passed: bool,
    /// `calls` counter from the most recent test run. Surface for
    /// restart bootstrap so the next agent knows whether the harness
    /// was actually exercising the project.
    last_test_calls: u64,
    /// Number of agent restarts so far. Incremented by the
    /// orchestrator when it drops conversation and re-spawns.
    restarts: usize,
}

#[derive(Debug, Clone)]
struct RecordedRun {
    record: HarnessRunRecord,
    /// Index into `HarnessAttempt::coverage` if this run produced lcov rows.
    coverage_idx: Option<usize>,
}

#[derive(Clone)]
struct AttemptHandle(Arc<Mutex<HarnessAttempt>>);

impl std::fmt::Debug for AttemptHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AttemptHandle")
    }
}

impl AttemptHandle {
    fn new() -> Self {
        Self(Arc::new(Mutex::new(HarnessAttempt::default())))
    }

    async fn snapshot(&self) -> HarnessAttempt {
        self.0.lock().await.clone()
    }
}

// HarnessAttempt is Clone for snapshot purposes (small).
impl Clone for HarnessAttempt {
    fn clone(&self) -> Self {
        Self {
            harness_source: self.harness_source.clone(),
            harness_filename: self.harness_filename.clone(),
            runs: self.runs.clone(),
            coverage: self.coverage.clone(),
            violation_observed: self.violation_observed,
            last_gate_passed: self.last_gate_passed,
            last_test_calls: self.last_test_calls,
            restarts: self.restarts,
        }
    }
}

// =============================================================================
// Agent tools
// =============================================================================

#[derive(Debug, Clone, Deserialize, JsonSchema)]
struct WriteHarnessArgs {
    /// Filename, just the base (no directory). e.g. `"Test_42.t.sol"`.
    /// Re-using the same name overwrites the file on disk.
    filename: String,
    /// Full Solidity source. Should contain the handler contract(s) and
    /// the invariant test contract together.
    content: String,
}

#[derive(Debug, Clone)]
#[llmy::agent::tool(
    arguments = WriteHarnessArgs,
    invoke = invoke,
    description = "Write (or overwrite) a Solidity test file under the harness directory. The file should contain the handler contract(s) plus the invariant test contract — everything for this spec in one .sol. Returns the absolute path written. Re-call to update the file after a forge compile error.",
    name = "write_harness_file",
)]
struct WriteHarnessTool {
    attempt: AttemptHandle,
    /// Absolute path of the harness directory.
    harness_dir: PathBuf,
}

impl WriteHarnessTool {
    async fn invoke(
        &self,
        args: WriteHarnessArgs,
    ) -> std::result::Result<String, llmy::agent::LLMYError> {
        if args.filename.is_empty() || args.filename.contains('/') || args.filename.contains('\\') {
            return Ok(
                "error: filename must be a basename (no directory separators) and non-empty"
                    .to_string(),
            );
        }
        if args.content.trim().is_empty() {
            return Ok("error: content must be non-empty".to_string());
        }
        let path = self.harness_dir.join(&args.filename);
        if let Some(parent) = path.parent() {
            if let Err(e) = tokio::fs::create_dir_all(parent).await {
                return Ok(format!(
                    "error: failed to create harness dir {}: {e}",
                    parent.display()
                ));
            }
        }
        if let Err(e) = tokio::fs::write(&path, &args.content).await {
            return Ok(format!("error: failed to write {}: {e}", path.display()));
        }
        let mut state = self.attempt.0.lock().await;
        state.harness_source = args.content;
        state.harness_filename = Some(args.filename.clone());
        Ok(format!(
            "ok: wrote {} bytes to {}",
            state.harness_source.len(),
            path.display()
        ))
    }
}

#[derive(Debug, Clone, Deserialize, JsonSchema)]
struct RunForgeArgs {
    /// Match-contract argument; pass the test contract name (e.g.
    /// `"Test_42"`) to scope the run to your harness.
    match_contract: String,
    /// Optional `--match-test` filter.
    #[serde(default)]
    match_test: Option<String>,
    /// Optional `--fuzz-seed`. Forwarded to forge for determinism if set.
    #[serde(default)]
    seed: Option<i64>,
}

#[derive(Debug, Clone)]
#[llmy::agent::tool(
    arguments = RunForgeArgs,
    invoke = invoke,
    description = "Run `forge test --json -vvvvvv` against the harness; if the test exits cleanly and actually exercises the harness (calls > 0) the orchestrator immediately follows up with `forge coverage --report lcov` server-side and the result includes the coverage gate verdict. Use this whenever you finish a `write_harness_file` and want to know how it ran. Returns gate verdicts plus the captured exit codes and tails of stdout/stderr.",
    name = "run_forge",
)]
struct RunForgeTool {
    attempt: AttemptHandle,
    runner: ForgeRunner,
    test_runs: u64,
    coverage_runs: u64,
    /// `--match-path` glob (relative to forge cwd) that scopes the compile
    /// graph to just this spec's per-spec subdirectory. Without this, forge
    /// pulls every sibling .sol into the compile graph and one bad concurrent
    /// harness breaks every other.
    match_path_glob: String,
    /// Spec the harness is supposed to be exercising. Drives runtime Gate 1
    /// (counter-example overlap with `spec.sequence`) and Gate 2 (coverage
    /// fidelity vs `spec.sequence`).
    spec: Arc<crate::types::AuditSpecification>,
    /// Project-wide call graph used by Gate 2 for `spec.sequence` →
    /// (file, line range) lookup.
    callgraph: Arc<knowdit_repo_model::cg::CallGraph>,
    /// Gate 2 fidelity threshold (same semantic as `agentic reflect`'s
    /// `--gate2-fidelity-threshold`). Below this, the coverage gate flags.
    gate2_fidelity_threshold: f64,
    /// The fuzz pass was started with viaIR enabled (project's `viaIR`
    /// solc setting). When `true` AND the backend supports
    /// `forge coverage --force-via-ir`, the coverage subcommand opts
    /// in; when `true` AND the backend lacks the flag, coverage runs
    /// without viaIR and may fail to compile (expected; prompt warns
    /// the agent).
    via_ir: bool,
}

impl RunForgeTool {
    async fn invoke(
        &self,
        args: RunForgeArgs,
    ) -> std::result::Result<String, llmy::agent::LLMYError> {
        // 1) forge test ------------------------------------------------
        let test_argv = self.build_test_argv(&args);
        let test_out = match self.runner.run(&test_argv).await {
            Ok(o) => o,
            Err(e) => return Ok(format!("error: forge test spawn failed: {e:#}")),
        };
        let test_summary = parse_forge_test_summary(&test_out.stdout);
        let test_record = HarnessRunRecord {
            kind: RunKind::Test,
            seed: args.seed,
            runs: self.test_runs as i64,
            forge_args: test_argv.clone(),
            exit_code: test_out.exit_code,
            stdout: truncate_str(&test_out.stdout, 200_000),
            stderr: truncate_str(&test_out.stderr, 200_000),
            duration_ms: test_out.duration_ms,
            violated: test_summary.violated,
            sequence: test_summary.counterexample_json.clone(),
        };
        let test_gate_verdict = match crate::reflect::runtime_audit::run(&test_summary, &self.spec)
        {
            crate::reflect::AuditOutcome::Fail { reason, .. } => {
                Some(format!("[GATE 1 FAILED — runtime] {reason}"))
            }
            _ => None,
        };

        // 2) decide if coverage is worth chasing ----------------------
        // No point spending coverage's much slower instrumentation when
        // the test didn't compile or exercised zero call paths — the
        // coverage gate would just report 0 hits with no signal.
        let run_coverage =
            test_out.exit_code == 0 && test_summary.total_calls > 0 && !test_out.timed_out;
        let mut cov_summary: Option<CoverageBlock> = None;
        if run_coverage {
            let cov_argv = self.build_coverage_argv(&args);
            match self.runner.run(&cov_argv).await {
                Ok(out) => {
                    let lcov_path = self.runner.work_dir().join("lcov.info");
                    let coverage = match tokio::fs::read_to_string(&lcov_path).await {
                        Ok(text) => parse_lcov(&text),
                        Err(_) => Vec::new(),
                    };
                    let gate = if coverage.is_empty() {
                        Some(
                            "[GATE 2 FAILED — coverage] no lcov rows produced (forge coverage ran \
                             but emitted nothing)"
                                .to_string(),
                        )
                    } else {
                        let thresholds = crate::reflect::AuditThresholds {
                            gate2_fidelity_threshold: self.gate2_fidelity_threshold,
                        };
                        match crate::reflect::coverage_audit::run(
                            &self.spec,
                            &coverage,
                            &self.callgraph,
                            &thresholds,
                        ) {
                            crate::reflect::AuditOutcome::Fail { reason, .. } => {
                                Some(format!("[GATE 2 FAILED — coverage] {reason}"))
                            }
                            _ => None,
                        }
                    };
                    let cov_record = HarnessRunRecord {
                        kind: RunKind::Coverage,
                        seed: args.seed,
                        runs: self.coverage_runs as i64,
                        forge_args: cov_argv.clone(),
                        exit_code: out.exit_code,
                        stdout: truncate_str(&out.stdout, 200_000),
                        stderr: truncate_str(&out.stderr, 200_000),
                        duration_ms: out.duration_ms,
                        violated: false,
                        sequence: None,
                    };
                    cov_summary = Some(CoverageBlock {
                        record: cov_record,
                        coverage,
                        gate_verdict: gate,
                        timed_out: out.timed_out,
                    });
                }
                Err(e) => {
                    tracing::warn!("auto-coverage spawn failed: {e:#}");
                }
            }
        }

        // 3) record everything in shared state ------------------------
        let mut state = self.attempt.0.lock().await;
        state.runs.push(RecordedRun {
            record: test_record.clone(),
            coverage_idx: None,
        });
        if test_summary.violated {
            state.violation_observed = true;
        }
        state.last_test_calls = test_summary.total_calls.max(0) as u64;
        if let Some(block) = &cov_summary {
            let coverage_idx = if !block.coverage.is_empty() {
                state.coverage.push(block.coverage.clone());
                Some(state.coverage.len() - 1)
            } else {
                None
            };
            state.runs.push(RecordedRun {
                record: block.record.clone(),
                coverage_idx,
            });
            state.last_gate_passed = block.gate_verdict.is_none() && !block.coverage.is_empty();
        } else {
            // No coverage run → gate is not "passed" (we have no evidence).
            state.last_gate_passed = false;
        }
        drop(state);

        // 4) format unified feedback ----------------------------------
        let mut sections: Vec<String> = Vec::new();

        if let Some(v) = &test_gate_verdict {
            sections.push(v.clone());
        }
        if test_summary.violated {
            sections.push(
                "[SUCCESS — violation observed] forge test reproduced the spec invariant. The \
                 orchestrator will terminate after this turn."
                    .to_string(),
            );
        } else if test_summary.total_calls == 0 {
            sections.push(
                "[NO-OP] forge test ran but produced 0 calls. Common causes: (a) `No tests found \
                 in project` — your harness is outside the project's configured test path; (b) \
                 `setUp()` reverted before any sequence call ran; (c) `--match-test` filter \
                 excluded every test. Fix the discovery / setUp issue and call run_forge again."
                    .to_string(),
            );
        }
        sections.push(format!(
            "ok: forge test exit={}{} duration_ms={}. runtime: setup_failed={} calls={} \
             reverts={} revert_rate={:.3} violated={}",
            test_record.exit_code,
            if test_out.timed_out { " [TIMEOUT]" } else { "" },
            test_record.duration_ms,
            test_summary.setup_failed,
            test_summary.total_calls,
            test_summary.total_reverts,
            test_summary.revert_rate(),
            test_summary.violated,
        ));
        sections.push(format!(
            "--- forge test stdout (last 4K) ---\n{}",
            tail_str(&test_record.stdout, 4_000)
        ));
        sections.push(format!(
            "--- forge test stderr (last 4K) ---\n{}",
            tail_str(&test_record.stderr, 4_000)
        ));

        if let Some(block) = &cov_summary {
            if let Some(v) = &block.gate_verdict {
                sections.push(v.clone());
            }
            sections.push(format!(
                "ok: forge coverage exit={}{} duration_ms={}. runtime: {} lcov rows",
                block.record.exit_code,
                if block.timed_out { " [TIMEOUT]" } else { "" },
                block.record.duration_ms,
                block.coverage.len(),
            ));
            sections.push(format!(
                "--- forge coverage stdout (last 4K) ---\n{}",
                tail_str(&block.record.stdout, 4_000)
            ));
        } else if run_coverage {
            // We tried but spawn failed — already logged above.
            sections.push(
                "note: orchestrator attempted to run forge coverage but the spawn failed; \
                 coverage gate skipped this turn."
                    .to_string(),
            );
        } else {
            sections.push(
                "note: forge coverage was skipped this turn (no clean exit + calls > 0). Fix \
                 the test run first; coverage runs automatically once it's clean."
                    .to_string(),
            );
        }

        let coverage_summary = match &cov_summary {
            Some(b) => format!(
                "coverage_exit={} lcov_rows={} gate2={}",
                b.record.exit_code,
                b.coverage.len(),
                if b.gate_verdict.is_none() && !b.coverage.is_empty() {
                    "pass"
                } else {
                    "fail"
                },
            ),
            None if run_coverage => "coverage=spawn_failed".to_string(),
            None => "coverage=skipped".to_string(),
        };
        tracing::info!(
            target: "knowdit_audit::harness::run_forge",
            match_contract = %args.match_contract,
            match_test = ?args.match_test,
            test_exit = test_out.exit_code,
            test_timed_out = test_out.timed_out,
            test_duration_ms = test_record.duration_ms,
            gate1 = if test_gate_verdict.is_none() { "pass" } else { "fail" },
            "run_forge: {} | {}",
            test_summary,
            coverage_summary,
        );

        Ok(sections.join("\n"))
    }

    fn build_test_argv(&self, args: &RunForgeArgs) -> Vec<String> {
        let mut argv = vec![
            "test".to_string(),
            "--json".to_string(),
            "-vvvvvv".to_string(),
            "--fuzz-runs".to_string(),
            self.test_runs.to_string(),
            "--match-contract".to_string(),
            args.match_contract.clone(),
        ];
        if let Some(t) = &args.match_test {
            argv.push("--match-test".to_string());
            argv.push(t.clone());
        }
        argv.push("--match-path".to_string());
        argv.push(self.match_path_glob.clone());
        if let Some(seed) = args.seed {
            argv.push("--fuzz-seed".to_string());
            argv.push(seed.to_string());
        }
        argv
    }

    fn build_coverage_argv(&self, args: &RunForgeArgs) -> Vec<String> {
        let mut argv = vec![
            "coverage".to_string(),
            "--report".to_string(),
            "lcov".to_string(),
            "--fuzz-runs".to_string(),
            self.coverage_runs.to_string(),
        ];
        if self.via_ir && self.runner.features().coverage_force_via_ir {
            argv.push("--force-via-ir".to_string());
        }
        argv.push("--match-contract".to_string());
        argv.push(args.match_contract.clone());
        if let Some(t) = &args.match_test {
            argv.push("--match-test".to_string());
            argv.push(t.clone());
        }
        argv.push("--match-path".to_string());
        argv.push(self.match_path_glob.clone());
        if let Some(seed) = args.seed {
            argv.push("--fuzz-seed".to_string());
            argv.push(seed.to_string());
        }
        argv
    }
}

/// Intermediate bundle held inside `RunForgeTool::invoke` between the
/// coverage spawn and the eventual feedback assembly. Kept local so we
/// don't widen the `HarnessAttempt` API just to carry transient values.
struct CoverageBlock {
    record: HarnessRunRecord,
    coverage: Vec<CoverageEntry>,
    gate_verdict: Option<String>,
    timed_out: bool,
}

// ---- list_test_files ----

#[derive(Debug, Clone, Deserialize, JsonSchema)]
struct ListTestFilesArgs {
    /// Optional substring filter on the relative path. Use `""` (or omit)
    /// to list everything.
    #[serde(default)]
    filter: Option<String>,
}

#[derive(Debug, Clone)]
#[llmy::agent::tool(
    arguments = ListTestFilesArgs,
    invoke = invoke,
    description = "List existing project test/script files (Foundry .t.sol, Hardhat .ts/.js, etc.) under the repo's `test/`, `script/`, `scripts/`, and `deploy/` directories. Use this to find existing setUp() / deployment patterns to imitate before writing your harness's setUp(). Returns relative paths.",
    name = "list_test_files",
)]
struct ListTestFilesTool {
    repo_root: PathBuf,
}

impl ListTestFilesTool {
    async fn invoke(
        &self,
        args: ListTestFilesArgs,
    ) -> std::result::Result<String, llmy::agent::LLMYError> {
        let mut found: Vec<PathBuf> = Vec::new();
        for sub in ["test", "script", "scripts", "deploy", "deployments"] {
            let dir = self.repo_root.join(sub);
            if !dir.is_dir() {
                continue;
            }
            walk_collect(&dir, &mut found, 0);
        }
        let filter = args.filter.unwrap_or_default();
        let mut out = String::new();
        for p in &found {
            let rel = p
                .strip_prefix(&self.repo_root)
                .unwrap_or(p)
                .to_string_lossy()
                .into_owned();
            if !filter.is_empty() && !rel.contains(&filter) {
                continue;
            }
            out.push_str("- ");
            out.push_str(&rel);
            out.push('\n');
        }
        if out.is_empty() {
            return Ok(format!(
                "no test files found{}",
                if filter.is_empty() {
                    String::new()
                } else {
                    format!(" matching `{filter}`")
                }
            ));
        }
        Ok(format!("ok: {} file(s)\n{out}", found.len()))
    }
}

fn walk_collect(dir: &Path, out: &mut Vec<PathBuf>, depth: usize) {
    if depth > 6 {
        return;
    }
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let p = entry.path();
        if p.is_dir() {
            // Skip noisy dependency dirs.
            if let Some(name) = p.file_name().and_then(|s| s.to_str()) {
                if matches!(
                    name,
                    "node_modules" | "lib" | "out" | "cache" | "artifacts" | ".git"
                ) {
                    continue;
                }
            }
            walk_collect(&p, out, depth + 1);
            continue;
        }
        if let Some(ext) = p.extension().and_then(|s| s.to_str()) {
            if matches!(ext, "sol" | "ts" | "js" | "json") {
                out.push(p);
            }
        }
    }
}

pub(super) fn truncate_str(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!(
            "{} … [{} bytes truncated]",
            &s[..max.min(s.len())],
            s.len().saturating_sub(max)
        )
    }
}

fn tail_str(s: &str, n: usize) -> String {
    if s.len() <= n {
        s.to_string()
    } else {
        format!("…[{} bytes earlier]\n{}", s.len() - n, &s[s.len() - n..])
    }
}

// =============================================================================
// Per-link agent run
// =============================================================================

async fn run_one_spec(
    link: &LinkInput,
    spec: &AuditSpecification,
    spec_id: i32,
    project_index: &Arc<ProjectIndex>,
    llm: &LLM,
    options: &FuzzOptions,
    forge_runner: &ForgeRunner,
    harness_dir: &Path,
    project_conventions: &ProjectConventions,
    // `prior_feedback`: when `Some`, this is a regen attempt — the agent's
    // system prompt gets a "Prior attempt feedback" section so it knows
    // the previous run produced an unacceptable harness and what
    // specifically to fix. `None` for first attempts (`agentic fuzz`).
    prior_feedback: Option<&str>,
) -> Result<LinkFuzzOutcome> {
    let attempt = AttemptHandle::new();

    // Each spec gets its own subdirectory so concurrent agents don't
    // contaminate each other's compile graph (forge compiles every .sol it
    // sees in its scope; one bad sibling poisons all other invocations).
    let per_spec_dir = harness_dir.join(format!("spec_{spec_id}"));
    tokio::fs::create_dir_all(&per_spec_dir)
        .await
        .wrap_err_with(|| format!("failed to create per-spec dir {}", per_spec_dir.display()))?;
    // Path of per_spec_dir relative to the forge cwd so we can build a
    // safe `--match-path` filter that scopes forge's compile graph to JUST
    // this spec's file. Canonicalize the per-spec dir first — `harness_dir`
    // is canonicalized in `prepare_runtime`, but a stale relative path
    // sneaking through here would silently feed forge a doubly-rooted
    // match-path and every test would come back "No tests found".
    let canonical_per_spec =
        std::fs::canonicalize(&per_spec_dir).unwrap_or_else(|_| per_spec_dir.clone());
    let per_spec_dir_rel = canonical_per_spec
        .strip_prefix(forge_runner.work_dir())
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|_| {
            tracing::warn!(
                spec_id,
                per_spec_dir = %canonical_per_spec.display(),
                work_dir = %forge_runner.work_dir().display(),
                "per_spec_dir is not under forge work_dir; --match-path will likely miss every harness file"
            );
            canonical_per_spec.clone()
        });

    // Tools are owned by the Agent, so on restart we have to build a
    // fresh ToolBox. Everything inside is cheaply cloneable
    // (Arc / shared handles), so rebuilding is just a few Arc bumps.
    let scoped_runner = forge_runner.clone().with_test_dir(per_spec_dir.clone());
    let match_path_glob = format!(
        "{}/*",
        per_spec_dir_rel.to_string_lossy().trim_end_matches('/')
    );
    let spec_arc = Arc::new(spec.clone());
    let callgraph_arc = Arc::new(project_index.call_graph.clone());
    let make_tools = || -> ToolBox {
        let mut tools = ToolBox::new();
        tools.add_tool(LookupCallGraphTool {
            project: project_index.clone(),
        });
        tools.add_tool(LookupStateVariableXrefsTool {
            project: project_index.clone(),
        });
        tools.add_tool(ReadContractSourceTool {
            project: project_index.clone(),
        });
        tools.add_tool(ReadFunctionSourceTool {
            project: project_index.clone(),
        });
        tools.add_tool(WriteHarnessTool {
            attempt: attempt.clone(),
            harness_dir: per_spec_dir.clone(),
        });
        tools.add_tool(RunForgeTool {
            attempt: attempt.clone(),
            runner: scoped_runner.clone(),
            test_runs: options.forge_test_runs,
            coverage_runs: options.forge_coverage_runs,
            match_path_glob: match_path_glob.clone(),
            spec: spec_arc.clone(),
            callgraph: callgraph_arc.clone(),
            gate2_fidelity_threshold: options.gate2_fidelity_threshold,
            via_ir: options.via_ir,
        });
        tools.add_tool(ListTestFilesTool {
            repo_root: options.repo_root.clone(),
        });
        tools.add_tool(llmy::agent::tools::files::ReadFileTool::new(
            options.repo_root.clone(),
        ));
        tools
    };

    let memory = build_link_memory(project_index)?;
    let cache_key_base = format!("{}-spec{}", options.cache_key, spec_id);
    let debug_prefix = options
        .debug_prefix
        .as_ref()
        .map(|p| format!("{p}-spec{spec_id}"));
    let coverage_via_ir_unsupported =
        options.via_ir && !forge_runner.features().coverage_force_via_ir;
    let base_system_prompt = build_system_prompt(
        link,
        spec,
        spec_id,
        harness_dir,
        project_conventions,
        coverage_via_ir_unsupported,
    );
    let memory_criteria = spec_memory_criteria();
    let user_prompt = build_user_prompt(spec_id);

    // Compose the system prompt for the current "attempt window" — base
    // + (optional) regen feedback + (optional) restart bootstrap. Called
    // once per agent spawn.
    let compose_system_prompt = |restart_count: usize,
                                 last_filename: Option<String>,
                                 last_calls: u64,
                                 last_gate_passed: bool|
     -> String {
        let mut sys = base_system_prompt.clone();
        if let Some(feedback) = prior_feedback {
            sys.push_str("\n\n## Prior attempt feedback (this is a regen)\n\n");
            sys.push_str(feedback);
            sys.push_str(
                "\n\nFix the specific issue above. Don't repeat the same mistake — \
                 read the project source and model the deployment topology faithfully.",
            );
        }
        if restart_count > 0 {
            sys.push_str(&super::solidity_prompt::build_restart_bootstrap(
                last_filename.as_deref(),
                last_calls,
                last_gate_passed,
                restart_count - 1,
            ));
        }
        sys
    };

    // Orchestrator state machine ---------------------------------------
    // Loop invariant: `attempt` accumulates every forge run across
    // restarts; only the agent's conversation context is dropped on
    // restart. Termination: violation observed, step budget exhausted,
    // restart budget exhausted, or hard LLMY error.
    let mut total_steps = 0usize;
    let loop_outcome: LoopOutcome;
    let mut last_error: Option<String> = None;

    'outer: loop {
        let restart_count = attempt.0.lock().await.restarts;
        let (last_filename, last_calls, last_gate_passed) = {
            let st = attempt.0.lock().await;
            (
                st.harness_filename.clone(),
                st.last_test_calls,
                st.last_gate_passed,
            )
        };
        let sys = compose_system_prompt(restart_count, last_filename, last_calls, last_gate_passed);
        let cache_key = if restart_count == 0 {
            cache_key_base.clone()
        } else {
            format!("{cache_key_base}-restart{restart_count}")
        };
        let mut agent =
            Agent::with_memory(sys, make_tools(), cache_key, &memory, &memory_criteria).await;

        let step_res = agent
            .step_with_user(
                user_prompt.clone(),
                llm,
                debug_prefix.as_deref(),
                options.llm_settings.clone(),
            )
            .await;
        let mut step = match step_res {
            Ok(s) => s,
            Err(e) => {
                last_error = Some(format!("initial step (restart {restart_count}): {e}"));
                loop_outcome = LoopOutcome::AgentError;
                break 'outer;
            }
        };
        total_steps += 1;

        // Inner per-restart loop --------------------------------------
        loop {
            if attempt.0.lock().await.violation_observed {
                loop_outcome = LoopOutcome::Violation;
                break 'outer;
            }
            if total_steps >= options.max_agent_steps {
                tracing::warn!(
                    "spec {spec_id}: step budget exhausted (max_agent_steps={})",
                    options.max_agent_steps
                );
                loop_outcome = LoopOutcome::StepsExhausted;
                break 'outer;
            }
            // Agent self-stopped (Stop variant). Without a finalize
            // tool this only happens when the model emits an empty
            // assistant turn with no tool calls. Treat it the same as
            // window-blow → restart with a fresh conversation.
            if matches!(step, StepResult::Stop(_)) {
                tracing::warn!(
                    "spec {spec_id}: agent stopped with no tool call at step {total_steps}; restarting"
                );
                break;
            }
            // Window check before issuing the next step.
            if let Some(threshold) = options.window_restart_threshold_tokens {
                if let Some(used) = agent.approx_context_tokens(&llm.model.config) {
                    if used >= threshold {
                        tracing::info!(
                            "spec {spec_id}: window threshold reached \
                             (used={used}, threshold={threshold}); restarting agent"
                        );
                        break;
                    }
                }
            }
            let next = agent
                .step(llm, debug_prefix.as_deref(), options.llm_settings.clone())
                .await;
            step = match next {
                Ok(s) => s,
                Err(e) => {
                    last_error = Some(format!("step {total_steps}: {e}"));
                    loop_outcome = LoopOutcome::AgentError;
                    break 'outer;
                }
            };
            total_steps += 1;
        }
        // Falling out of the inner loop → request a restart.
        let mut st = attempt.0.lock().await;
        st.restarts += 1;
        if st.restarts > options.max_restarts {
            loop_outcome = LoopOutcome::RestartsExhausted;
            break 'outer;
        }
    }

    let snapshot = attempt.snapshot().await;

    // Decide CodeGenStatus from orchestrator outcome + observed runs.
    let has_runs = !snapshot.runs.is_empty();
    let (code_gen_status, final_reason) = match &loop_outcome {
        LoopOutcome::Violation => (
            CodeGenStatus::Completed,
            format!(
                "violation observed after {total_steps} step(s), {} restart(s)",
                snapshot.restarts
            ),
        ),
        LoopOutcome::StepsExhausted => (
            CodeGenStatus::StepsExhausted,
            format!(
                "step budget {} exhausted (restarts={}, runs={})",
                options.max_agent_steps,
                snapshot.restarts,
                snapshot.runs.len()
            ),
        ),
        LoopOutcome::RestartsExhausted => (
            if has_runs {
                CodeGenStatus::Completed
            } else {
                CodeGenStatus::Abandoned
            },
            format!(
                "restart budget {} exhausted (steps={total_steps}, runs={})",
                options.max_restarts,
                snapshot.runs.len()
            ),
        ),
        LoopOutcome::AgentError => (
            CodeGenStatus::AgentError,
            last_error
                .clone()
                .unwrap_or_else(|| "agent error".to_string()),
        ),
    };

    // The orchestrator's `RunForgeTool` now auto-runs coverage right
    // after every clean test, so there's no separate fallback step:
    // whatever's in `snapshot.runs` already contains both kinds. We
    // just flatten the (test, coverage) interleaving into the two
    // parallel vectors persistence expects.
    let (runs, coverage_per_run): (Vec<HarnessRunRecord>, Vec<Vec<CoverageEntry>>) = {
        let mut rs = Vec::with_capacity(snapshot.runs.len());
        let mut covs = Vec::with_capacity(snapshot.runs.len());
        for r in &snapshot.runs {
            rs.push(r.record.clone());
            covs.push(
                r.coverage_idx
                    .and_then(|i| snapshot.coverage.get(i).cloned())
                    .unwrap_or_default(),
            );
        }
        (rs, covs)
    };

    let any_violation = runs.iter().any(|r| r.violated);

    let harness_relative = snapshot
        .harness_filename
        .as_deref()
        .map(|f| {
            // Path relative to repo_root if possible; otherwise just filename.
            let abs = harness_dir.join(f);
            abs.strip_prefix(&options.repo_root)
                .map(|p| p.to_string_lossy().into_owned())
                .unwrap_or_else(|_| abs.to_string_lossy().into_owned())
        })
        .unwrap_or_default();

    let code_gen = CodeGenRecord {
        core: CodeGenCore {
            spec_id,
            harness_relative_path: harness_relative,
            harness_source: snapshot.harness_source,
            status: code_gen_status,
            final_reason,
            agent_steps: total_steps as i32,
        },
        runs,
    };

    Ok(LinkFuzzOutcome {
        spec_id,
        code_gen,
        coverage_per_run,
        any_violation,
    })
}

// =============================================================================
// Public orchestrator
// =============================================================================

/// Top-level runner. Holds an open `RepoDatabase` reference plus owned
/// (cloned) copies of the `LLM` handle and `FuzzOptions`, so [`Self::run`]
/// is a self-method with no parameters. Pulls all specs from the DB,
/// expands them into per-spec fuzz tasks, round-robin's them by
/// `semantic_id`, dispatches to a worker pool, and persists each
/// finalized link in its own DB transaction.
pub struct SolidityFuzzGenerator {
    repo: RepoDatabase,
    llm: LLM,
    options: FuzzOptions,
    /// Forge runtime + probed feature flags. Constructed once by
    /// the caller (CLI fuzz/regen Args, or the autoloop preflight)
    /// and threaded through so the backend probe (currently:
    /// `forge coverage --help` → `--force-via-ir`) runs exactly
    /// once per pipeline invocation.
    backend: ForgeBackend,
}

/// Per-invocation runtime built once by [`SolidityFuzzGenerator::prepare_runtime`]
/// and reused across `run` (full sweep) and `regen_one_spec` (single-spec
/// regen). Owns every cross-spec piece of state the agent loop needs.
struct FuzzRuntime {
    project_index: Arc<ProjectIndex>,
    link_by_pair: BTreeMap<(i32, i32), LinkInput>,
    harness_dir: PathBuf,
    forge_runner: ForgeRunner,
    project_conventions: Arc<ProjectConventions>,
}

/// Result of one [`SolidityFuzzGenerator::regen_one_spec`] call —
/// the new code_gen row's id plus enough disposition info for the
/// regen orchestrator to log a one-line summary per attempt.
#[derive(Debug, Clone)]
pub struct RegenOutcome {
    pub new_code_gen_id: i32,
    pub status: CodeGenStatus,
    pub any_violation: bool,
}

/// In-memory output of [`SolidityFuzzGenerator::regen_codegen_with_explicit_spec`] —
/// the agent's code_gen + coverage per run, **not yet persisted**. Used
/// by the spec-regen path so the caller can flow it into
/// `repo.write_full_spec_regen` together with the new specification in
/// one atomic transaction.
#[derive(Debug, Clone)]
pub struct CodegenRegenInMemory {
    pub code_gen: CodeGenRecord,
    pub coverage_per_run: Vec<Vec<CoverageEntry>>,
    pub status: CodeGenStatus,
    pub any_violation: bool,
}

impl SolidityFuzzGenerator {
    /// Build a generator from already-resolved resources. `backend`
    /// must come from a single [`ForgeBackend::new`] call shared
    /// across the whole pipeline invocation (e.g. the autoloop
    /// constructs once and passes the same backend into both fuzz
    /// and regen entries so the `forge coverage --help` probe runs
    /// exactly once per run). Repo / LLM clones are shallow (Arc
    /// underneath).
    pub fn new(
        repo: &RepoDatabase,
        llm: &LLM,
        options: &FuzzOptions,
        backend: ForgeBackend,
    ) -> Self {
        // Heads-up once per pass: if the project uses viaIR but the
        // forge runtime can't pass it through to coverage, coverage
        // compiles may fail and the prompt is told to expect it.
        if options.via_ir && !backend.features.coverage_force_via_ir {
            tracing::warn!(
                "fuzz pass: project requested viaIR but `forge coverage --force-via-ir` \
                 is unsupported on this backend; coverage runs may fail to compile. \
                 The per-spec prompt tells the agent this is expected."
            );
        }
        Self {
            repo: repo.clone(),
            llm: llm.clone(),
            options: options.clone(),
            backend,
        }
    }

    pub async fn run(&self) -> Result<FuzzOutcome> {
        let repo = &self.repo;
        let options = &self.options;
        let runtime = self.prepare_runtime().await?;
        let FuzzRuntime {
            project_index,
            link_by_pair,
            harness_dir,
            forge_runner,
            project_conventions,
        } = runtime;

        let specs = repo
            .load_specifications()
            .await
            .wrap_err("failed to load specifications")?;

        // Resume vs regenerate
        if options.regenerate {
            repo.clear_fuzz_tables()
                .await
                .wrap_err("failed to clear fuzz tables for --regenerate")?;
            tracing::info!(
                "Fuzz: --regenerate set, cleared code_gen / harness_run / line_coverage"
            );
        }
        let already_done = if options.regenerate {
            std::collections::HashSet::new()
        } else {
            repo.loaded_completed_code_gen_spec_ids()
                .await
                .wrap_err("failed to load already-fuzzed spec ids")?
        };

        let mut tasks: Vec<FuzzTask> = Vec::new();
        let mut skipped_resumed = 0usize;
        let mut skipped_no_link = 0usize;
        let mut skipped_parse = 0usize;
        for s in specs {
            if already_done.contains(&s.id) {
                skipped_resumed += 1;
                continue;
            }
            let Some(link) = link_by_pair.get(&(s.semantic_id, s.finding_id)) else {
                skipped_no_link += 1;
                continue;
            };
            let spec: AuditSpecification = match serde_json::from_str(&s.specification_json) {
                Ok(v) => v,
                Err(e) => {
                    tracing::warn!(
                        "Skipping spec id={} (extract={}, finding={}): JSON parse failed: {e}",
                        s.id,
                        s.semantic_id,
                        s.finding_id
                    );
                    skipped_parse += 1;
                    continue;
                }
            };
            tasks.push(FuzzTask {
                spec_id: s.id,
                semantic_id: s.semantic_id,
                link: link.clone(),
                spec,
            });
        }
        if skipped_resumed > 0 || skipped_no_link > 0 || skipped_parse > 0 {
            tracing::info!(
                "Fuzz: skipping {skipped_resumed} resumed + {skipped_no_link} no-link + {skipped_parse} parse-error spec(s)"
            );
        }

        // Round-robin by semantic_id.
        tasks = round_robin_tasks(tasks);
        if let Some(cap) = (options.max_specs > 0).then_some(options.max_specs) {
            if tasks.len() > cap {
                tracing::info!(
                    "Fuzz: truncating tasks {} → {} (--max-specs)",
                    tasks.len(),
                    cap
                );
                tasks.truncate(cap);
            }
        }
        let total = tasks.len();
        if total == 0 {
            tracing::warn!("Fuzz: no specs to process");
            return Ok(FuzzOutcome {
                skipped_resumed,
                ..FuzzOutcome::default()
            });
        }
        tracing::info!(
            "Fuzz: {total} spec(s) to process across {} semantic(s) (concurrency={})",
            tasks
                .iter()
                .map(|t| t.semantic_id)
                .collect::<BTreeSet<_>>()
                .len(),
            options.concurrency.max(1),
        );

        let outcome = self
            .dispatch(
                tasks,
                project_index,
                &forge_runner,
                &harness_dir,
                total,
                project_conventions,
            )
            .await?;
        Ok(FuzzOutcome {
            skipped_resumed,
            ..outcome
        })
    }

    /// Build everything except the per-spec task list — project index,
    /// link map, harness dir, forge runner, project conventions. Shared
    /// by [`Self::run`] (full sweep) and [`Self::regen_one_spec`]
    /// (single-spec regen via `agentic regen`).
    async fn prepare_runtime(&self) -> Result<FuzzRuntime> {
        let repo = &self.repo;
        let options = &self.options;
        // Project index (call graph + storage graph) — same shape spec.rs uses.
        let call_graph = repo
            .load_call_graph()
            .await
            .wrap_err("failed to load project call graph")?;
        let storage_graph = repo
            .load_storage_graph()
            .await
            .wrap_err("failed to load project storage graph")?;
        let inheritance_graph = repo
            .load_inheritance_graph()
            .await
            .wrap_err("failed to load project inheritance graph")?;
        let project_index = Arc::new(ProjectIndex::build(
            call_graph,
            storage_graph,
            inheritance_graph,
        ));

        // Rebuild LinkInputs from the persisted matches so each spec
        // can resolve back to its (extract_id, finding_id) origin.
        let extracted = repo
            .load_project_semantics()
            .await
            .wrap_err("failed to load extracted project semantics")?;
        let extracted_by_id: BTreeMap<i32, ExtractedSemantic> = extracted
            .into_iter()
            .enumerate()
            .map(|(i, sem)| ((i as i32) + 1, sem))
            .collect();
        let match_set: SemanticMatchSet = repo
            .load_semantic_match_results()
            .await
            .wrap_err("failed to load Knowledge Mapper output")?;
        let historical_by_id: BTreeMap<i32, HistoricalSemanticRecord> = match_set
            .historicals
            .iter()
            .map(|r| (r.semantic.id, r.clone()))
            .collect();
        let link_inputs =
            build_link_inputs(&match_set.matches, &extracted_by_id, &historical_by_id);
        let mut link_by_pair: BTreeMap<(i32, i32), LinkInput> = BTreeMap::new();
        for li in link_inputs {
            link_by_pair
                .entry((li.extract_id, li.finding_id))
                .or_insert(li);
        }

        // Harness dir and forge runner.
        let harness_dir = options.resolve_harness_dir();
        tokio::fs::create_dir_all(&harness_dir)
            .await
            .wrap_err_with(|| format!("failed to create harness_dir {}", harness_dir.display()))?;
        // Canonicalize once we know the dir exists. `ForgeRunner::new` does
        // the same trick for `work_dir`; we mirror it here so the
        // `per_spec_dir.strip_prefix(work_dir)` in `run_one_spec` can
        // actually succeed and produce a forge-relative `--match-path`.
        // Without this, a CLI invocation like `-p simple:./eval_refactor/simple/`
        // ends up with `harness_dir` relative and `work_dir` absolute, the
        // strip fails, and we feed forge a doubly-rooted path that misses
        // every harness file ("No tests found in project").
        let harness_dir = std::fs::canonicalize(&harness_dir).unwrap_or(harness_dir);
        let forge_work_dir = if options.repo_root.join("foundry.toml").exists() {
            options.repo_root.clone()
        } else {
            harness_dir.clone()
        };
        let forge_runner = ForgeRunner::new(
            self.backend.clone(),
            forge_work_dir,
            Duration::from_secs(options.forge_timeout_secs),
        );
        // (Preflight is now done at the orchestrator level — top of
        // streamloop / autoloop / standalone fuzz / standalone regen —
        // before any LLM stage runs. By the time we reach
        // prepare_runtime the environment has already been verified.)
        let project_conventions = Arc::new(ProjectConventions::load(&options.repo_root).await);

        Ok(FuzzRuntime {
            project_index,
            link_by_pair,
            harness_dir,
            forge_runner,
            project_conventions,
        })
    }

    /// Regenerate a single `code_gen` row for an existing spec, with a
    /// prior-attempt feedback message injected into the agent's system
    /// prompt. Used by `agentic regen` when grader output is
    /// `Suspect` or `IncompleteStep`. Returns the new `code_gen.id` so
    /// the caller can write a `code_gen_regen` lineage row.
    pub async fn regen_one_spec(
        &self,
        spec_id: i32,
        prior_feedback: String,
    ) -> Result<RegenOutcome> {
        let runtime = self.prepare_runtime().await?;
        let specs = self
            .repo
            .load_specifications()
            .await
            .wrap_err("failed to load specifications for regen")?;
        let spec_row = specs.into_iter().find(|s| s.id == spec_id).ok_or_else(|| {
            color_eyre::eyre::eyre!("spec_id={spec_id} not in specification table")
        })?;
        let link = runtime
            .link_by_pair
            .get(&(spec_row.semantic_id, spec_row.finding_id))
            .cloned()
            .ok_or_else(|| {
                color_eyre::eyre::eyre!(
                    "no LinkInput for spec {spec_id} (extract={}, finding={})",
                    spec_row.semantic_id,
                    spec_row.finding_id
                )
            })?;
        let spec: AuditSpecification = serde_json::from_str(&spec_row.specification_json)
            .wrap_err_with(|| {
                format!("failed to parse specification.json for spec_id={spec_id}")
            })?;

        let lo = run_one_spec(
            &link,
            &spec,
            spec_id,
            &runtime.project_index,
            &self.llm,
            &self.options,
            &runtime.forge_runner,
            &runtime.harness_dir,
            &runtime.project_conventions,
            Some(&prior_feedback),
        )
        .await?;

        let (new_code_id, _run_ids) = self
            .repo
            .write_code_gen_with_runs(&lo.code_gen, &lo.coverage_per_run)
            .await
            .wrap_err_with(|| format!("failed to persist regen code_gen for spec_id={spec_id}"))?;
        Ok(RegenOutcome {
            new_code_gen_id: new_code_id,
            status: lo.code_gen.core.status,
            any_violation: lo.any_violation,
        })
    }

    /// Run codegen for an in-memory `AuditSpecification` that has not yet
    /// been persisted. Used by the spec-regen path: the caller has just
    /// produced a new spec via `SpecificationGenerator::regen_one_link`
    /// but doesn't want to insert it until the entire pipeline succeeds,
    /// so a crash anywhere below leaves no dirty rows.
    ///
    /// `synthetic_spec_id` is fed only to the LLM cache key and the
    /// per-spec disk directory — the DB never sees it. Pass `-reflection_id`
    /// so each regen attempt has a distinct (negative, never colliding
    /// with real spec ids) namespace.
    pub async fn regen_codegen_with_explicit_spec(
        &self,
        extract_id: i32,
        finding_id: i32,
        spec: AuditSpecification,
        synthetic_spec_id: i32,
        prior_feedback: String,
    ) -> Result<CodegenRegenInMemory> {
        let runtime = self.prepare_runtime().await?;
        let link = runtime
            .link_by_pair
            .get(&(extract_id, finding_id))
            .cloned()
            .ok_or_else(|| {
                color_eyre::eyre::eyre!(
                    "no LinkInput for (extract={extract_id}, finding={finding_id}) — \
                     spec regen produced a spec for a pair not in the current matches"
                )
            })?;
        let lo = run_one_spec(
            &link,
            &spec,
            synthetic_spec_id,
            &runtime.project_index,
            &self.llm,
            &self.options,
            &runtime.forge_runner,
            &runtime.harness_dir,
            &runtime.project_conventions,
            Some(&prior_feedback),
        )
        .await?;
        Ok(CodegenRegenInMemory {
            status: lo.code_gen.core.status,
            any_violation: lo.any_violation,
            code_gen: lo.code_gen,
            coverage_per_run: lo.coverage_per_run,
        })
    }

    async fn dispatch(
        &self,
        tasks: Vec<FuzzTask>,
        project_index: Arc<ProjectIndex>,
        forge_runner: &ForgeRunner,
        harness_dir: &Path,
        total: usize,
        project_conventions: Arc<ProjectConventions>,
    ) -> Result<FuzzOutcome> {
        // Concurrency-1 path: linear loop, easier to reason about.
        let mut outcome = FuzzOutcome::default();
        let concurrency = self.options.concurrency.max(1);
        if concurrency == 1 {
            for (idx, task) in tasks.into_iter().enumerate() {
                let label = format!(
                    "spec {}/{} id={} extract={} finding={}",
                    idx + 1,
                    total,
                    task.spec_id,
                    task.link.extract_id,
                    task.link.finding_id
                );
                tracing::info!("Fuzz starting {label}");
                let res = run_one_spec(
                    &task.link,
                    &task.spec,
                    task.spec_id,
                    &project_index,
                    &self.llm,
                    &self.options,
                    forge_runner,
                    harness_dir,
                    &project_conventions,
                    None,
                )
                .await;
                self.persist(res, &label, &mut outcome).await;
            }
            return Ok(outcome);
        }

        // Concurrency > 1
        let indexed: Vec<(usize, FuzzTask)> = tasks.into_iter().enumerate().rev().collect();
        let queue: Arc<Mutex<Vec<(usize, FuzzTask)>>> = Arc::new(Mutex::new(indexed));
        let (tx, mut rx) =
            tokio::sync::mpsc::channel::<(usize, Result<LinkFuzzOutcome>, String)>(concurrency * 2);
        let mut handles = Vec::with_capacity(concurrency);
        for _ in 0..concurrency {
            let queue = queue.clone();
            let project_index = project_index.clone();
            let llm = self.llm.clone();
            let options = self.options.clone();
            let forge_runner = forge_runner.clone();
            let harness_dir = harness_dir.to_path_buf();
            let conv = project_conventions.clone();
            let tx = tx.clone();
            handles.push(tokio::spawn(async move {
                loop {
                    let next = {
                        let mut q = queue.lock().await;
                        q.pop()
                    };
                    let Some((idx, task)) = next else {
                        break;
                    };
                    let label = format!(
                        "spec {}/{} id={} extract={} finding={}",
                        idx + 1,
                        total,
                        task.spec_id,
                        task.link.extract_id,
                        task.link.finding_id
                    );
                    tracing::info!("Fuzz starting {label}");
                    let res = run_one_spec(
                        &task.link,
                        &task.spec,
                        task.spec_id,
                        &project_index,
                        &llm,
                        &options,
                        &forge_runner,
                        &harness_dir,
                        &conv,
                        None,
                    )
                    .await;
                    if tx.send((idx, res, label)).await.is_err() {
                        break;
                    }
                }
            }));
        }
        drop(tx);
        while let Some((_idx, res, label)) = rx.recv().await {
            self.persist(res, &label, &mut outcome).await;
        }
        for h in handles {
            let _ = h.await;
        }
        Ok(outcome)
    }

    async fn persist(&self, res: Result<LinkFuzzOutcome>, label: &str, outcome: &mut FuzzOutcome) {
        outcome.processed_count += 1;
        let lo = match res {
            Ok(lo) => lo,
            Err(e) => {
                tracing::error!("{label}: agent failed: {e:#}");
                outcome.error_count += 1;
                // Record an AgentError row so resume can see we've tried.
                let stub = CodeGenRecord {
                    core: CodeGenCore {
                        spec_id: -1, // unknown — caller will fill
                        harness_relative_path: String::new(),
                        harness_source: String::new(),
                        status: CodeGenStatus::AgentError,
                        final_reason: format!("agent error: {e:#}"),
                        agent_steps: 0,
                    },
                    runs: Vec::new(),
                };
                let _ = stub; // can't write without spec_id; skip stubbing
                return;
            }
        };
        let success = matches!(lo.code_gen.core.status, CodeGenStatus::Completed);
        let abandoned = matches!(lo.code_gen.core.status, CodeGenStatus::Abandoned)
            || matches!(lo.code_gen.core.status, CodeGenStatus::StepsExhausted);
        let violated = lo.any_violation;
        match self
            .repo
            .write_code_gen_with_runs(&lo.code_gen, &lo.coverage_per_run)
            .await
        {
            Ok((code_id, run_ids)) => {
                tracing::info!(
                    "{label}: persisted code_gen={} runs={:?} status={} violated={violated}",
                    code_id,
                    run_ids,
                    lo.code_gen.core.status
                );
            }
            Err(e) => {
                tracing::error!("{label}: persist failed: {e:#}");
                outcome.error_count += 1;
                return;
            }
        }
        if success {
            outcome.completed_count += 1;
        } else if abandoned {
            outcome.abandoned_count += 1;
        }
        if violated {
            outcome.violated_count += 1;
        }
    }
}

struct FuzzTask {
    spec_id: i32,
    semantic_id: i32,
    link: LinkInput,
    spec: AuditSpecification,
}

fn round_robin_tasks(tasks: Vec<FuzzTask>) -> Vec<FuzzTask> {
    let mut by_sem: BTreeMap<i32, VecDeque<FuzzTask>> = BTreeMap::new();
    for t in tasks {
        by_sem.entry(t.semantic_id).or_default().push_back(t);
    }
    let total: usize = by_sem.values().map(|q| q.len()).sum();
    let mut out: Vec<FuzzTask> = Vec::with_capacity(total);
    while !by_sem.is_empty() {
        let keys: Vec<i32> = by_sem.keys().copied().collect();
        for k in keys {
            if let Some(q) = by_sem.get_mut(&k) {
                if let Some(t) = q.pop_front() {
                    out.push(t);
                }
                if q.is_empty() {
                    by_sem.remove(&k);
                }
            }
        }
    }
    out
}
