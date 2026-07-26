//! Shared data types + parsers + small helpers used by both Solidity
//! harness modes ([`super::harness`] handler-invariant; [`super::poc`]
//! deterministic PoC). Anything here must be free of mode-specific
//! agent / prompt logic.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use knowdit_repo_model::{CodeGenRecord, CoverageEntry, HarnessRunRecord, RunKind};
use llmy::client::settings::LLMSettings;
use tokio::sync::Mutex;

/// Monotonic process-local counter that uniquifies the per-spec scratch
/// dir inside the agent runtime. Two concurrent regen attempts on the
/// same `spec_id` would otherwise share `harness_dir/spec_{id}/` and
/// race on harness file writes + forge's build cache. `Relaxed` is
/// fine — we only need uniqueness, not ordering between writes.
pub(super) static SPEC_ATTEMPT_COUNTER: AtomicU64 = AtomicU64::new(0);

pub(super) fn next_attempt_id() -> u64 {
    SPEC_ATTEMPT_COUNTER.fetch_add(1, Ordering::Relaxed)
}

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
    /// Hard timeout for a `forge test` subprocess (seconds).
    pub forge_timeout_secs: u64,
    /// Hard timeout for a `forge coverage` subprocess (seconds). Coverage now
    /// runs after every test attempt, so this bounds what a hopeless or hung
    /// attempt can cost; kept below `forge_timeout_secs` because coverage is
    /// evidence, not the verdict.
    pub forge_coverage_timeout_secs: u64,
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
    /// Recursion budget for the `list_test_files` agent tool's directory
    /// scan. Wired from `--harness-list-test-files-max-depth`. 0 disables
    /// the scan entirely.
    pub list_test_files_max_depth: usize,
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
                // Prefer `[profile.default].test` over the legacy
                // top-level `[default].test`. Both writes target the
                // conventional default profile only; if a project
                // pins a non-default profile we'd need a CLI flag.
                if let Ok(cfg) = toml::from_str::<knowdit_project::foundry::FoundryToml>(&text) {
                    let test_subdir = cfg
                        .profile
                        .get("default")
                        .and_then(|p| p.test.clone())
                        .or(cfg.default.test);
                    if let Some(sub) = test_subdir {
                        return self.repo_root.join(sub).join("knowdit_harness");
                    }
                }
            }
            // foundry.toml exists but no explicit `test = ...`; default test/.
            return self.repo_root.join("test").join("knowdit_harness");
        }
        self.repo_root.join("knowdit_harness")
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

/// What one agent run produced for one link, before persistence. Crossed
/// the mode boundary: both [`super::harness`] and [`super::poc`] return
/// this type so the caller can persist them identically.
#[derive(Debug)]
pub struct LinkFuzzOutcome {
    pub spec_id: i32,
    pub code_gen: CodeGenRecord,
    pub coverage_per_run: Vec<Vec<CoverageEntry>>,
    /// Whether at least one of the `code_gen.runs` had `violated == true`.
    pub any_violation: bool,
}

/// Why the orchestrator stopped iterating for one spec. Mapped to
/// [`knowdit_repo_model::CodeGenStatus`] downstream, but kept separate
/// so we can fold the "no violation but the loop ran cleanly" / "no
/// violation and we ran out of restarts" distinction without forcing a
/// new DB enum value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum LoopOutcome {
    Violation,
    StepsExhausted,
    RestartsExhausted,
    AgentError,
}

// =============================================================================
// Forge JSON parsers
// =============================================================================

/// Structured digest of one `forge test --json` invocation. Captures the
/// runtime signals that drive Gate 1 inline (setUp success, fuzzer
/// effective-call count, counter-example contract+function decoding)
/// instead of just `violated`.
///
/// Two flavors of violation:
///
/// * **Invariant counter-example** (handler+invariant mode): forge's
///   fuzzer found an input sequence that breaks the invariant. Surfaces
///   as `counterexample_calls.non_empty()` + `violated=true`.
/// * **Deterministic test failure** (PoC mode): the agent wrote a
///   `function test_…()` whose body deterministically reproduces the
///   attack and asserts with reason starting `KNOWDIT_POST_ATTACK_REACHED:`.
///   Surfaces as `deterministic_test_failure=true` + `violated=true`,
///   without a counterexample sequence.
#[derive(Debug, Clone, Default)]
pub struct ForgeTestSummary {
    pub setup_failed: bool,
    pub failure_reason: Option<String>,
    pub total_calls: i64,
    pub total_reverts: i64,
    pub violated: bool,
    pub counterexample_calls: Vec<CounterCall>,
    pub counterexample_json: Option<serde_json::Value>,
    /// True iff this run was a deterministic `test_…` PoC that
    /// reverted with the `KNOWDIT_POST_ATTACK_REACHED:` prefix. The
    /// reflect Gate 1 (sequence-coverage check) skips runs flagged
    /// deterministic — by construction there's no counterexample
    /// sequence to validate.
    pub deterministic_test_failure: bool,
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

impl ForgeTestSummary {
    /// Parse `forge test --json` stdout into a [`ForgeTestSummary`].
    /// Best-effort: when stdout isn't a JSON suite map (compile errors,
    /// mixed text mode), serde returns an error and we fall back to a
    /// default summary — Gate 1 then sees `setup_failed=false, calls=0`
    /// and passes, leaving the agent to react to the raw exit code.
    pub fn parse(stdout: &str) -> Self {
        use crate::harness::forge_json::SuiteMap;
        serde_json::from_str::<SuiteMap>(stdout.trim())
            .map(Self::from)
            .unwrap_or_default()
    }
}

impl From<crate::harness::forge_json::SuiteMap> for ForgeTestSummary {
    /// Reduce a deserialized `SuiteMap` into the summary. Splitting
    /// this out keeps [`ForgeTestSummary::parse`] a one-liner and lets
    /// callers that already have a `SuiteMap` (e.g. tests, future
    /// callers replaying a captured run) skip the JSON layer.
    fn from(suites: crate::harness::forge_json::SuiteMap) -> Self {
        use crate::harness::forge_json::{CounterExample, TestStatus};

        let mut summary = Self::default();
        for suite in suites.values() {
            for (test_name, tr) in &suite.test_results {
                if let Some(stats) = tr.invariant_stats() {
                    summary.total_calls += stats.calls;
                    summary.total_reverts += stats.reverts;
                }
                if tr.is_setup_failure(test_name) {
                    summary.setup_failed = true;
                }
                if tr.status == TestStatus::Failure
                    && let Some(reason) = &tr.reason
                    && !reason.is_empty()
                    && summary.failure_reason.is_none()
                {
                    summary.failure_reason = Some(reason.clone());
                }
                let counterexample = tr.counterexample.as_ref().or_else(|| {
                    tr.invariant_failures
                        .iter()
                        .find_map(|failure| failure.counterexample.as_ref())
                });
                if let Some(CounterExample::Sequence(_orig, calls)) = counterexample
                    && !calls.is_empty()
                {
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
                // Deterministic PoC violation: a `test_…` function (not
                // invariant) reverted with the magic prefix. The PoC
                // agent is told to use this exact prefix on its
                // post-attack assertion so we can distinguish "intended
                // exploit reproduction" from "random revert".
                if test_name.starts_with("test")
                    && !tr.is_setup_failure(test_name)
                    && tr
                        .reason
                        .as_deref()
                        .is_some_and(is_deterministic_violation_reason)
                {
                    summary.violated = true;
                    summary.deterministic_test_failure = true;
                }
            }
        }
        summary
    }
}

/// String form callers can paste into prompts.
pub(super) const POC_VIOLATION_MARKER: &str = "KNOWDIT_POST_ATTACK_REACHED:";

/// `KNOWDIT_POST_ATTACK_REACHED:` is the contract between the PoC
/// agent's `require(..., "KNOWDIT_POST_ATTACK_REACHED: <reason>")`
/// assertion and the orchestrator's "this is a real violation" gate.
/// Kept as a substring check (not a prefix) so the agent can prepend
/// `vm.expectRevert` framing without breaking detection.
pub(super) fn is_deterministic_violation_reason(reason: &str) -> bool {
    reason.contains(POC_VIOLATION_MARKER)
}

/// Parse a minimal subset of LCOV: every `DA:<line>,<hits>` after a
/// `SF:<source-file-path>` block. Path is taken verbatim from the SF line.
pub(super) fn parse_lcov(text: &str) -> Vec<CoverageEntry> {
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
            // lcov's `DA:` lists every *instrumented* line, scoring the ones a
            // run never reached as `,0` — on real harnesses that is ~88% of the
            // records. A zero says only "this particular harness didn't walk
            // here", which no consumer wants: Gate 2 filters `hit_count > 0`
            // itself, and so does every downstream reader. Keeping them cost
            // ~6x the rows in `line_coverage` (623k rows encoding 5.4k distinct
            // positions) and forced any per-file lookup to wade through them,
            // so drop them at the parse boundary and let the table mean exactly
            // "this line was executed".
            if hits <= 0 {
                continue;
            }
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
// Agent state held inside each mode's runtime
// =============================================================================

/// In-memory accumulator for one agent run. Tools mutate this through an
/// `Arc<Mutex>` handle so the agent's tool-call loop can share state across
/// turns. Both modes use the same shape — harness writes a Solidity file
/// and runs forge; PoC writes a deterministic test and runs forge. The
/// orchestrator drains this into a `CodeGenRecord` when the loop ends.
#[derive(Debug, Default, Clone)]
pub(super) struct HarnessAttempt {
    pub harness_source: String,
    pub harness_filename: Option<String>,
    pub runs: Vec<RecordedRun>,
    pub coverage: Vec<Vec<CoverageEntry>>,
    pub violation_observed: bool,
    pub last_gate_passed: bool,
    pub last_test_calls: u64,
    pub restarts: usize,
}

#[derive(Debug, Clone)]
pub(super) struct RecordedRun {
    pub record: HarnessRunRecord,
    pub coverage_idx: Option<usize>,
}

#[derive(Clone)]
pub(super) struct AttemptHandle(pub(super) Arc<Mutex<HarnessAttempt>>);

impl std::fmt::Debug for AttemptHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AttemptHandle")
    }
}

impl AttemptHandle {
    pub(super) fn new() -> Self {
        Self(Arc::new(Mutex::new(HarnessAttempt::default())))
    }

    pub(super) async fn snapshot(&self) -> HarnessAttempt {
        self.0.lock().await.clone()
    }

    /// Validate `filename` is a basename + write `content` to
    /// `dest_dir/filename`, then stamp the new source + filename onto
    /// the underlying `HarnessAttempt` so the agent loop's restart
    /// bootstrap can reference it. Errors are returned as `Ok(String)`
    /// rather than propagated — the agent sees the failure as a normal
    /// tool result and can re-issue with a corrected filename.
    pub(super) async fn write_agent_file(
        &self,
        dest_dir: &Path,
        filename: &str,
        content: &str,
    ) -> std::result::Result<String, llmy::agent::LLMYError> {
        if filename.is_empty() || filename.contains('/') || filename.contains('\\') {
            return Ok(
                "error: filename must be a basename (no directory separators) and non-empty"
                    .to_string(),
            );
        }
        if content.trim().is_empty() {
            return Ok("error: content must be non-empty".to_string());
        }
        let path = dest_dir.join(filename);
        if let Some(parent) = path.parent()
            && let Err(e) = tokio::fs::create_dir_all(parent).await
        {
            return Ok(format!(
                "error: failed to create harness dir {}: {e}",
                parent.display()
            ));
        }
        if let Err(e) = tokio::fs::write(&path, content).await {
            return Ok(format!("error: failed to write {}: {e}", path.display()));
        }
        let mut state = self.0.lock().await;
        state.harness_source = content.to_string();
        state.harness_filename = Some(filename.to_string());
        Ok(format!(
            "ok: wrote {} bytes to {}",
            state.harness_source.len(),
            path.display()
        ))
    }
}

// =============================================================================
// Small string + filesystem helpers (shared between modes)
// =============================================================================

// =============================================================================
// Project conventions — shared by both mode prompts
// =============================================================================

/// Excerpt of the project's foundry config + remapping conventions,
/// loaded once per [`super::runtime::FuzzRuntime`] and surfaced into
/// every mode's system prompt so the agent picks the right import
/// paths and test-contract layout.
#[derive(Debug, Clone, Default)]
pub(super) struct ProjectConventions {
    foundry_toml_excerpt: String,
    remappings_txt: String,
    sample_test_filenames: Vec<String>,
    sample_test_imports: String,
}

impl ProjectConventions {
    pub(super) fn foundry_toml_excerpt(&self) -> &str {
        &self.foundry_toml_excerpt
    }
    pub(super) fn remappings_txt(&self) -> &str {
        &self.remappings_txt
    }
    pub(super) fn sample_test_filenames(&self) -> &[String] {
        &self.sample_test_filenames
    }
    pub(super) fn sample_test_imports(&self) -> &str {
        &self.sample_test_imports
    }

    pub(super) async fn load(repo_root: &Path) -> Self {
        let mut me = Self::default();
        if let Ok(text) = tokio::fs::read_to_string(repo_root.join("foundry.toml")).await {
            me.foundry_toml_excerpt = truncate_str(&text, 4_096);
        }
        if let Ok(text) = tokio::fs::read_to_string(repo_root.join("remappings.txt")).await {
            me.remappings_txt = truncate_str(&text, 4_096);
        }
        // Prefer `[profile.default].test`, then legacy top-level
        // `[default].test`, falling back to the conventional `test/`.
        let test_dir =
            toml::from_str::<knowdit_project::foundry::FoundryToml>(&me.foundry_toml_excerpt)
                .ok()
                .and_then(|cfg| {
                    cfg.profile
                        .get("default")
                        .and_then(|p| p.test.clone())
                        .or(cfg.default.test)
                })
                .map(|td| repo_root.join(td))
                .unwrap_or_else(|| repo_root.join("test"));
        let mut tests: Vec<PathBuf> = Vec::new();
        if let Ok(mut entries) = tokio::fs::read_dir(&test_dir).await {
            while let Ok(Some(e)) = entries.next_entry().await {
                let p = e.path();
                if p.extension().and_then(|s| s.to_str()) == Some("sol") {
                    tests.push(p);
                }
            }
            if let Ok(mut top) = tokio::fs::read_dir(&test_dir).await {
                while let Ok(Some(e)) = top.next_entry().await {
                    let p = e.path();
                    if p.is_dir()
                        && let Ok(mut sub) = tokio::fs::read_dir(&p).await
                    {
                        while let Ok(Some(e2)) = sub.next_entry().await {
                            let p2 = e2.path();
                            if p2.extension().and_then(|s| s.to_str()) == Some("sol") {
                                tests.push(p2);
                            }
                        }
                    }
                }
            }
        }
        tests.sort();
        tests.dedup();
        me.sample_test_filenames = tests
            .iter()
            .take(8)
            .filter_map(|p| p.file_name().and_then(|s| s.to_str()).map(String::from))
            .collect();
        if let Some(first) = tests.first()
            && let Ok(text) = tokio::fs::read_to_string(first).await
        {
            // Tree-sitter–based header extractor: every byte
            // before the first contract / interface / library
            // declaration. Catches block comments, multi-line
            // imports, and weird pragma split-lines that the
            // previous `line.starts_with(...)` scan would
            // mis-classify.
            let header = knowdit_sol::header::extract_header(&text).unwrap_or_default();
            me.sample_test_imports = truncate_str(&header, 2_048);
        }
        me
    }
}

/// `~max`-byte prefix of `s` + "[N bytes truncated]" suffix — stored
/// verbatim in `HarnessRunRecord.stdout/stderr` and surfaced downstream to
/// the reflect grader. The cut is snapped DOWN to the nearest UTF-8 char
/// boundary so slicing forge trace output (which contains multi-byte box
/// characters like `┗`/`━`) never panics.
pub(super) fn truncate_str(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_string();
    }
    let mut end = max;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    format!("{} … [{} bytes truncated]", &s[..end], s.len() - end)
}

/// Last `~n` bytes of `s` with a "…[N bytes earlier]" marker — only used
/// when assembling agent-facing tool feedback. The cut is snapped UP to the
/// nearest UTF-8 char boundary so slicing forge trace output (which contains
/// multi-byte box characters like `┗`/`━`) never panics.
pub(super) fn tail_str(s: &str, n: usize) -> String {
    if s.len() <= n {
        return s.to_string();
    }
    let cut = s.len() - n;
    let mut start = cut;
    while start < s.len() && !s.is_char_boundary(start) {
        start += 1;
    }
    format!("…[{} bytes earlier]\n{}", cut, &s[start..])
}

/// Re-export of the kg::audit_finding map type used by the runtime
/// summary builders. Kept here so the rest of the module doesn't need
/// to re-import.
#[allow(dead_code)]
pub(super) type RunByKind = HashMap<RunKind, Vec<HarnessRunRecord>>;

#[cfg(test)]
mod truncate_tests {
    use super::{tail_str, truncate_str};

    /// Build a string whose byte length forces the cut at `cut_byte` to land
    /// inside a 3-byte box character (`┗` = bytes `E2 94 97`), reproducing the
    /// forge-trace panic.
    fn box_line(repeat: usize) -> String {
        "┗".repeat(repeat)
    }

    #[test]
    fn tail_str_snaps_to_char_boundary() {
        // 10 × '┗' = 30 bytes. n=20 → cut at byte 10, which is mid-'┗'
        // (boundaries are multiples of 3). Must not panic, and the result
        // must be valid UTF-8 starting at a real char.
        let s = box_line(10);
        let out = tail_str(&s, 20);
        assert!(out.contains("bytes earlier"));
        assert!(out.ends_with(&box_line(6))); // snapped up: 12..30 = 6 chars
    }

    #[test]
    fn truncate_str_snaps_to_char_boundary() {
        // max=10 lands mid-'┗'; snap down to byte 9 = 3 chars kept.
        let s = box_line(10);
        let out = truncate_str(&s, 10);
        assert!(out.contains("bytes truncated"));
        assert!(out.starts_with(&box_line(3)));
    }

    #[test]
    fn short_strings_pass_through() {
        let s = "┗━┛";
        assert_eq!(tail_str(s, 1_000), s);
        assert_eq!(truncate_str(s, 1_000), s);
    }
}
