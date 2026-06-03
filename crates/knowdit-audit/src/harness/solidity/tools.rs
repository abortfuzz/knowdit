//! Solidity-layer agent tools, both shared between the two harness
//! modes. Each tool struct is a `llmy::agent::tool!`-generated type
//! plumbed through [`super::runtime`]'s `AgentLoopState::build_toolbox`.
//!
//! Why one file: the tool types are small data holders + an `invoke`
//! async fn; keeping them together (away from the agent loop and the
//! mode-specific prompts) makes it easy to find every place the agent
//! is allowed to touch.
//!
//! Three tools live here today:
//!
//! * [`WriteHarnessFileTool`] — writes (or overwrites) the per-spec
//!   `.sol` harness file and stamps the new source/filename onto the
//!   shared [`AttemptHandle`] so the orchestrator can persist it as
//!   `CodeGenRecord.harness_source` and reference it from the restart
//!   bootstrap.
//! * [`RunForgeTool`] — runs `forge test --json`, parses the digest,
//!   auto-chases coverage when the test ran cleanly, and emits Gate 1
//!   / Gate 2 verdicts back to the agent in one combined tool result.
//! * [`ListTestFilesTool`] — depth-limited recursive scan of the
//!   project's `test/` / `script/` / `scripts/` / `deploy/` /
//!   `deployments/` directories so the agent can imitate existing
//!   setUp patterns.

use std::path::PathBuf;
use std::sync::Arc;

use knowdit_repo_model::{CoverageEntry, HarnessRunRecord, RunKind};
use schemars::JsonSchema;
use serde::Deserialize;

use super::utils::{
    AttemptHandle, ForgeTestSummary, RecordedRun, parse_lcov, tail_str, truncate_str,
};
use crate::harness::forge::ForgeRunner;
use crate::types::AuditSpecification;

// =============================================================================
// write_harness_file
// =============================================================================

#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub(super) struct WriteHarnessFileArgs {
    /// Filename, just the base (no directory). e.g. `"Test_42.t.sol"`.
    /// Re-using the same name overwrites the file on disk.
    filename: String,
    /// Full Solidity source. The required file shape is described by
    /// the system prompt.
    content: String,
}

#[derive(Debug, Clone)]
#[llmy::agent::tool(
    arguments = WriteHarnessFileArgs,
    invoke = invoke,
    description = "Write (or overwrite) the Solidity test file under the per-spec harness directory. The required file shape is dictated entirely by the system prompt — this tool just writes the bytes you provide and remembers the filename for restart bookkeeping. Re-call to update the file after a forge compile error.",
    name = "write_harness_file",
)]
pub(super) struct WriteHarnessFileTool {
    pub(super) attempt: AttemptHandle,
    pub(super) harness_dir: PathBuf,
}

impl WriteHarnessFileTool {
    async fn invoke(
        &self,
        args: WriteHarnessFileArgs,
    ) -> std::result::Result<String, llmy::agent::LLMYError> {
        self.attempt
            .write_agent_file(&self.harness_dir, &args.filename, &args.content)
            .await
    }
}

// =============================================================================
// run_forge
// =============================================================================

#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub(super) struct RunForgeArgs {
    pub(super) match_contract: String,
    #[serde(default)]
    pub(super) match_test: Option<String>,
    #[serde(default)]
    pub(super) seed: Option<i64>,
}

#[derive(Debug, Clone)]
#[llmy::agent::tool(
    arguments = RunForgeArgs,
    invoke = invoke,
    description = "Run `forge test --json -vvvvvv` against the harness; if the test exits cleanly and actually exercises the harness (calls > 0, or a deterministic test_… function ran) the orchestrator immediately follows up with `forge coverage --report lcov` server-side and the result includes the coverage gate verdict. Use this whenever you finish writing the harness file. Returns gate verdicts plus the captured exit codes and tails of stdout/stderr.",
    name = "run_forge",
)]
pub(super) struct RunForgeTool {
    pub(super) attempt: AttemptHandle,
    pub(super) runner: ForgeRunner,
    pub(super) test_runs: u64,
    pub(super) coverage_runs: u64,
    pub(super) match_path_glob: String,
    pub(super) spec: Arc<AuditSpecification>,
    pub(super) callgraph: Arc<knowdit_repo_model::cg::CallGraph>,
    pub(super) gate2_fidelity_threshold: f64,
    pub(super) via_ir: bool,
}

impl RunForgeTool {
    async fn invoke(
        &self,
        args: RunForgeArgs,
    ) -> std::result::Result<String, llmy::agent::LLMYError> {
        let test_argv = self.build_test_argv(&args);
        let test_out = match self.runner.run(&test_argv).await {
            Ok(o) => o,
            Err(e) => return Ok(format!("error: forge test spawn failed: {e:#}")),
        };
        let test_summary = ForgeTestSummary::parse(&test_out.stdout);
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

        // Coverage worth chasing? Both modes benefit: handler-invariant
        // needs it for Gate 2; PoC mode runs it as evidence that the
        // deterministic test actually exercised project lines (helps
        // the reflect grader judge ValidFinding vs hallucination).
        let run_coverage = test_out.exit_code == 0
            && (test_summary.total_calls > 0 || test_summary.deterministic_test_failure)
            && !test_out.timed_out;
        let mut cov_summary: Option<CoverageBlockBundle> = None;
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
                    } else if test_summary.deterministic_test_failure {
                        // PoC mode: coverage is informational, not gated.
                        None
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
                    cov_summary = Some(CoverageBlockBundle {
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
            state.last_gate_passed = false;
        }
        drop(state);

        let mut sections: Vec<String> = Vec::new();
        if let Some(v) = &test_gate_verdict {
            sections.push(v.clone());
        }
        if test_summary.violated {
            let kind = if test_summary.deterministic_test_failure {
                "deterministic test reverted with KNOWDIT_POST_ATTACK_REACHED"
            } else {
                "invariant counter-example produced"
            };
            sections.push(format!(
                "[SUCCESS — violation observed] {kind}. The orchestrator will terminate after \
                 this turn."
            ));
        } else if test_summary.total_calls == 0 && !test_summary.deterministic_test_failure {
            sections.push(
                "[NO-OP] forge test ran but produced 0 calls AND no deterministic test_… revert. \
                 Common causes: (a) `No tests found in project` — your harness is outside the \
                 project's configured test path; (b) `setUp()` reverted before any sequence call \
                 ran; (c) `--match-test` filter excluded every test. Fix the discovery / setUp \
                 issue and call run_forge again."
                    .to_string(),
            );
        }
        sections.push(format!(
            "ok: forge test exit={}{} duration_ms={}. runtime: setup_failed={} calls={} \
             reverts={} revert_rate={:.3} violated={} deterministic_violation={}",
            test_record.exit_code,
            if test_out.timed_out { " [TIMEOUT]" } else { "" },
            test_record.duration_ms,
            test_summary.setup_failed,
            test_summary.total_calls,
            test_summary.total_reverts,
            test_summary.revert_rate(),
            test_summary.violated,
            test_summary.deterministic_test_failure,
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
            sections.push(
                "note: orchestrator attempted to run forge coverage but the spawn failed; \
                 coverage gate skipped this turn."
                    .to_string(),
            );
        } else {
            sections.push(
                "note: forge coverage was skipped this turn (no clean exit or no project \
                 execution). Fix the test run first."
                    .to_string(),
            );
        }

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
/// coverage spawn and the eventual feedback assembly.
struct CoverageBlockBundle {
    record: HarnessRunRecord,
    coverage: Vec<CoverageEntry>,
    gate_verdict: Option<String>,
    timed_out: bool,
}

// =============================================================================
// list_test_files
// =============================================================================

#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub(super) struct ListTestFilesArgs {
    #[serde(default)]
    pub(super) filter: Option<String>,
}

#[derive(Debug, Clone)]
#[llmy::agent::tool(
    arguments = ListTestFilesArgs,
    invoke = invoke,
    description = "List existing project test/script files (Foundry .t.sol, Hardhat .ts/.js, etc.) under the repo's `test/`, `script/`, `scripts/`, and `deploy/` directories. Use this to find existing setUp() / deployment patterns to imitate before writing your harness's setUp(). Returns relative paths.",
    name = "list_test_files",
)]
pub(super) struct ListTestFilesTool {
    pub(super) repo_root: PathBuf,
    /// Recursion budget passed to [`walk_collect`]. Wired from
    /// `FuzzOptions::list_test_files_max_depth`.
    pub(super) max_depth: usize,
}

/// Vendored / build-output directory names skipped during the
/// `list_test_files` scan. Hardcoded because they're project-tooling
/// conventions (npm, foundry, hardhat), not knowdit knobs.
const LIST_TEST_FILES_SKIP_DIRS: &[&str] =
    &["node_modules", "lib", "out", "cache", "artifacts", ".git"];

/// File extensions the `list_test_files` scan collects. Anything the
/// agent might want to imitate when authoring a harness setUp(): solidity
/// test sources, hardhat ts/js tests, deploy-script json metadata.
const LIST_TEST_FILES_COLLECT_EXTS: &[&str] = &["sol", "ts", "js", "json"];

impl ListTestFilesTool {
    async fn invoke(
        &self,
        args: ListTestFilesArgs,
    ) -> std::result::Result<String, llmy::agent::LLMYError> {
        let accept_dir = |dir: &std::path::Path| -> bool {
            dir.file_name()
                .and_then(|n| n.to_str())
                .map(|name| !LIST_TEST_FILES_SKIP_DIRS.contains(&name))
                .unwrap_or(true)
        };
        let accept_file = |file: &std::path::Path| -> bool {
            file.extension()
                .and_then(|e| e.to_str())
                .map(|ext| LIST_TEST_FILES_COLLECT_EXTS.contains(&ext))
                .unwrap_or(false)
        };
        let mut found: Vec<PathBuf> = Vec::new();
        for sub in ["test", "script", "scripts", "deploy", "deployments"] {
            let dir = self.repo_root.join(sub);
            if !dir.is_dir() {
                continue;
            }
            match knowdit_project::scope::walk_files(
                &dir,
                &accept_dir,
                &accept_file,
                Some(self.max_depth),
            ) {
                Ok(set) => found.extend(set),
                Err(e) => {
                    tracing::warn!(dir = %dir.display(), "list_test_files: walk failed: {e:#}");
                }
            }
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
