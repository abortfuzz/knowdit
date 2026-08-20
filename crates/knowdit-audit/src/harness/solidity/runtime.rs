//! Solidity-layer forge driver + agent-loop orchestration.
//!
//! This module owns everything that doesn't depend on **which kind of
//! Solidity file the agent is writing**:
//!
//! * [`FuzzRuntime::new`] — per-invocation runtime (project index,
//!   link table, harness dir, forge runner) built once per
//!   [`SolidityFuzzGenerator`].
//! * [`PerSpecScratch::new`] — per-spec scratch dir with the AtomicU64
//!   uniquification, the matching `--match-path` glob, and a scoped
//!   forge runner bundled together.
//! * [`RunForgeTool`] + [`ListTestFilesTool`] — agent tools both modes
//!   register.
//! * [`run_agent_loop`] — the shared agent loop. Mode-specific bits
//!   (which write tool, which prompt) are dispatched via a single
//!   `match HarnessKind` into [`super::harness`] (handler+invariant)
//!   or [`super::poc`] (deterministic PoC).
//! * [`SolidityFuzzGenerator`] — the public sweep / regen entry. Holds
//!   the [`HarnessKind`] field that decides per-spec which mode runs.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use color_eyre::eyre::{Result, WrapErr};
use knowdit_kg_model::ExtractedSemantic;
use knowdit_repo_model::{
    CodeGenCore, CodeGenRecord, CodeGenStatus, CoverageEntry, HarnessRunRecord,
    HistoricalSemanticRecord, RepoDatabase, SemanticMatchSet,
};
use llmy::agent::{LLMYError, StepResult};
use llmy::agent::tool::ToolBox;
use llmy::agent::tools::memory::AgentMemoryContext;
use llmy::client::client::LLM;
use llmy::harness::Agent;
use llmy::harness::memory::AgentMemorySystemPromptCriteria;
use tokio::task::JoinSet;

use super::tools::{ListTestFilesTool, RunForgeTool, WriteHarnessFileTool};
use super::utils::{
    AttemptHandle, FuzzOptions, FuzzOutcome, LinkFuzzOutcome, LoopOutcome, ProjectConventions,
    next_attempt_id,
};
use super::{HarnessKind, harness as handler_mode, poc as poc_mode};
use crate::harness::forge::{ForgeBackend, ForgeRunner, ForgeTimeouts};
use crate::spec::{
    LinkInput, LookupCallGraphTool, LookupStateVariableXrefsTool, MemoryScope, ProjectIndex,
    ReadContractSourceTool, ReadFunctionSourceTool, spec_memory_criteria,
};
use crate::types::AuditSpecification;

// =============================================================================
// FuzzRuntime — built once per invocation
// =============================================================================

pub(super) struct FuzzRuntime {
    pub(super) project_index: Arc<ProjectIndex>,
    pub(super) link_by_pair: BTreeMap<(i32, i32), LinkInput>,
    pub(super) harness_dir: PathBuf,
    pub(super) forge_runner: ForgeRunner,
    pub(super) project_conventions: Arc<ProjectConventions>,
}

impl FuzzRuntime {
    /// Build the per-invocation runtime: project index, link-by-pair
    /// table, harness dir + forge runner, project conventions. Shared
    /// by [`SolidityFuzzGenerator::run`] (full sweep) and the three
    /// single-spec entries (`fuzz_one_existing_spec`, `regen_one_spec`,
    /// `regen_codegen_with_explicit_spec`).
    pub(super) async fn new(
        repo: &RepoDatabase,
        options: &FuzzOptions,
        backend: &ForgeBackend,
    ) -> Result<Self> {
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
            LinkInput::build_all(&match_set.matches, &extracted_by_id, &historical_by_id);
        let mut link_by_pair: BTreeMap<(i32, i32), LinkInput> = BTreeMap::new();
        for li in link_inputs {
            link_by_pair
                .entry((li.extract_id, li.finding_id))
                .or_insert(li);
        }

        let harness_dir = options.resolve_harness_dir();
        tokio::fs::create_dir_all(&harness_dir)
            .await
            .wrap_err_with(|| format!("failed to create harness_dir {}", harness_dir.display()))?;
        let harness_dir = std::fs::canonicalize(&harness_dir).unwrap_or(harness_dir);
        let forge_work_dir = if options.repo_root.join("foundry.toml").exists() {
            options.repo_root.clone()
        } else {
            harness_dir.clone()
        };
        let forge_runner = ForgeRunner::new(
            backend.clone(),
            forge_work_dir,
            ForgeTimeouts {
                test: Duration::from_secs(options.forge_timeout_secs),
                coverage: Duration::from_secs(options.forge_coverage_timeout_secs),
            },
        );
        let project_conventions = Arc::new(ProjectConventions::load(&options.repo_root).await);

        Ok(Self {
            project_index,
            link_by_pair,
            harness_dir,
            forge_runner,
            project_conventions,
        })
    }
}

/// Per-spec scratch directory bundle: the unique dir on disk where the
/// agent writes harness files, the matching `--match-path` glob that
/// scopes forge's compile graph to just that dir, and a scoped
/// [`ForgeRunner`] whose `test-dir` is set accordingly. Built by
/// [`Self::new`] once per agent attempt.
pub(super) struct PerSpecScratch {
    pub(super) per_spec_dir: PathBuf,
    pub(super) match_path_glob: String,
    pub(super) scoped_runner: ForgeRunner,
}

impl PerSpecScratch {
    /// Allocate a fresh per-spec scratch directory. Concurrent regen
    /// attempts on the same `spec_id` each get a distinct dir via the
    /// `pid_counter` suffix so they don't race on forge's build cache.
    pub(super) async fn new(
        spec_id: i32,
        harness_dir: &Path,
        forge_runner: &ForgeRunner,
    ) -> Result<Self> {
        let attempt_id = next_attempt_id();
        let per_spec_dir = harness_dir.join(format!(
            "spec_{spec_id}_{}_{}",
            std::process::id(),
            attempt_id
        ));
        tokio::fs::create_dir_all(&per_spec_dir)
            .await
            .wrap_err_with(|| {
                format!("failed to create per-spec dir {}", per_spec_dir.display())
            })?;
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
        let scoped_runner = forge_runner.clone().with_test_dir(per_spec_dir.clone());
        let match_path_glob = format!(
            "{}/*",
            per_spec_dir_rel.to_string_lossy().trim_end_matches('/')
        );
        Ok(Self {
            per_spec_dir,
            match_path_glob,
            scoped_runner,
        })
    }
}

// =============================================================================
// HarnessKind mode-dispatch methods
// =============================================================================

/// Per-mode behavior selectors. Each method matches `self` once and
/// forwards to the matching module's implementation. Kept on the enum
/// rather than as free functions so callers read as `kind.foo(...)`.
impl HarnessKind {
    pub(super) fn build_system_prompt(
        self,
        link: &LinkInput,
        spec: &AuditSpecification,
        spec_id: i32,
        harness_dir: &Path,
        conv: &ProjectConventions,
        coverage_via_ir_unsupported: bool,
    ) -> String {
        match self {
            Self::Handler => handler_mode::build_system_prompt(
                link,
                spec,
                spec_id,
                harness_dir,
                conv,
                coverage_via_ir_unsupported,
            ),
            Self::Poc => poc_mode::build_system_prompt(
                link,
                spec,
                spec_id,
                harness_dir,
                conv,
                coverage_via_ir_unsupported,
            ),
        }
    }

    pub(super) fn build_user_prompt(self, spec_id: i32) -> String {
        match self {
            Self::Handler => handler_mode::build_user_prompt(spec_id),
            Self::Poc => poc_mode::build_user_prompt(spec_id),
        }
    }

    pub(super) fn build_restart_bootstrap(
        self,
        last_filename: Option<&str>,
        last_calls: u64,
        last_gate_passed: bool,
        attempt_seq: usize,
        refused: bool,
    ) -> String {
        match self {
            Self::Handler => handler_mode::build_restart_bootstrap(
                last_filename,
                last_calls,
                last_gate_passed,
                attempt_seq,
                refused,
            ),
            Self::Poc => poc_mode::build_restart_bootstrap(
                last_filename,
                last_calls,
                last_gate_passed,
                attempt_seq,
                refused,
            ),
        }
    }
}

// Agent tools live in `super::tools`; the runtime constructs them in
// `AgentLoopState::build_toolbox` below.

/// Result of one restart attempt's inner step loop. Drives the outer
/// loop's "spawn another attempt vs return verdict" decision in
/// [`AgentLoopState::spawn_attempts_until_done`].
enum AttemptOutcome {
    Violation,
    StepsExhausted,
    AgentError(String),
    NeedsRestart,
    /// A provider content refusal ended the attempt. Distinct from
    /// `NeedsRestart` so the outer loop can bill it against its own budget:
    /// the refusal is not the agent's work going wrong, and billing it as an
    /// ordinary restart would let a filter spike eat the entire restart
    /// budget without the agent ever having mis-stepped.
    FilteredRestart,
}

/// Fields snapshotted out of the shared `HarnessAttempt` mutex between
/// restarts. Pulled into a named struct so the snapshot helper has a
/// clear return type instead of a 4-tuple.
struct RestartSnapshot {
    restart_count: usize,
    last_filename: Option<String>,
    last_calls: u64,
    last_gate_passed: bool,
}

/// Everything one spec's agent loop needs, packaged into one struct so
/// the loop body can read as a method body rather than a 200-line
/// function with captured locals. Built once by [`Self::new`] at the
/// top of [`HarnessKind::run_agent_loop`], then consumed by
/// [`Self::drive`] which contains the actual outer/inner loop.
struct AgentLoopState {
    kind: HarnessKind,
    spec_id: i32,
    harness_dir: PathBuf,
    options: FuzzOptions,
    project_index: Arc<ProjectIndex>,
    spec_arc: Arc<AuditSpecification>,
    callgraph_arc: Arc<knowdit_repo_model::cg::CallGraph>,
    // Per-spec scratch dir + scoped forge runner allocated by
    // `prepare_per_spec_dir`. Same `attempt` handle is cloned into
    // every mode-specific tool registered in `build_toolbox`.
    attempt: AttemptHandle,
    per_spec_dir: PathBuf,
    scoped_runner: ForgeRunner,
    match_path_glob: String,
    // Pre-built immutable prompt bundle used unchanged across every
    // restart inside `drive`. Only the restart bootstrap
    // (composed on the fly by `compose_system_prompt`) changes per
    // attempt.
    base_system_prompt: String,
    user_prompt: String,
    prior_feedback: Option<String>,
    debug_prefix: Option<String>,
    memory: AgentMemoryContext,
    memory_criteria: AgentMemorySystemPromptCriteria,
    /// Shared vocabulary neutralizer for content-refusal repair (cheap to
    /// construct once per spec loop; the regex table is the whole cost).
    neutralizer: crate::sanitize::Neutralizer,
}

impl AgentLoopState {
    async fn new(
        kind: HarnessKind,
        link: &LinkInput,
        spec: &AuditSpecification,
        spec_id: i32,
        project_index: &Arc<ProjectIndex>,
        options: &FuzzOptions,
        forge_runner: &ForgeRunner,
        harness_dir: &Path,
        project_conventions: &ProjectConventions,
        prior_feedback: Option<&str>,
    ) -> Result<Self> {
        let scratch = PerSpecScratch::new(spec_id, harness_dir, forge_runner).await?;
        let coverage_via_ir_unsupported =
            options.via_ir && !forge_runner.features().coverage_force_via_ir;
        let base_system_prompt = kind.build_system_prompt(
            link,
            spec,
            spec_id,
            harness_dir,
            project_conventions,
            coverage_via_ir_unsupported,
        );
        let user_prompt = kind.build_user_prompt(spec_id);
        let memory = project_index.build_link_memory(MemoryScope::WholeProject)?;
        let memory_criteria = spec_memory_criteria();
        let debug_prefix = options
            .debug_prefix
            .as_ref()
            .map(|p| format!("{p}-spec{spec_id}"));
        Ok(Self {
            kind,
            spec_id,
            harness_dir: harness_dir.to_path_buf(),
            options: options.clone(),
            project_index: project_index.clone(),
            spec_arc: Arc::new(spec.clone()),
            callgraph_arc: Arc::clone(&project_index.call_graph),
            attempt: AttemptHandle::new(),
            per_spec_dir: scratch.per_spec_dir,
            scoped_runner: scratch.scoped_runner,
            match_path_glob: scratch.match_path_glob,
            base_system_prompt,
            user_prompt,
            prior_feedback: prior_feedback.map(String::from),
            debug_prefix,
            memory,
            memory_criteria,
            neutralizer: crate::sanitize::Neutralizer::new(),
        })
    }

    fn build_toolbox(&self) -> ToolBox {
        let mut tools = ToolBox::new();
        tools.add_tool(LookupCallGraphTool {
            project: self.project_index.clone(),
        });
        tools.add_tool(LookupStateVariableXrefsTool {
            project: self.project_index.clone(),
        });
        tools.add_tool(ReadContractSourceTool {
            project: self.project_index.clone(),
        });
        tools.add_tool(ReadFunctionSourceTool {
            project: self.project_index.clone(),
        });
        // Single write tool for both modes — the system prompt tells
        // the agent which file shape to produce.
        tools.add_tool(WriteHarnessFileTool {
            attempt: self.attempt.clone(),
            harness_dir: self.per_spec_dir.clone(),
        });
        tools.add_tool(RunForgeTool {
            attempt: self.attempt.clone(),
            runner: self.scoped_runner.clone(),
            test_runs: self.options.forge_test_runs,
            coverage_runs: self.options.forge_coverage_runs,
            match_path_glob: self.match_path_glob.clone(),
            spec: self.spec_arc.clone(),
            callgraph: self.callgraph_arc.clone(),
            gate2_fidelity_threshold: self.options.gate2_fidelity_threshold,
            via_ir: self.options.via_ir,
        });
        tools.add_tool(ListTestFilesTool {
            repo_root: self.options.repo_root.clone(),
            max_depth: self.options.list_test_files_max_depth,
        });
        tools.add_tool(llmy::agent::tools::files::ReadFileTool::new(
            self.options.repo_root.clone(),
        ));
        tools
    }

    /// Compose the system prompt for one agent spawn. `base_system_prompt`
    /// is the static mode-specific text; this method stamps on the
    /// optional regen-feedback block + the restart bootstrap (which
    /// depend on per-attempt state).
    fn compose_system_prompt(
        &self,
        restart_count: usize,
        last_filename: Option<&str>,
        last_calls: u64,
        last_gate_passed: bool,
        refused: bool,
    ) -> String {
        let mut sys = self.base_system_prompt.clone();
        if let Some(feedback) = self.prior_feedback.as_deref() {
            sys.push_str("\n\n## Prior attempt feedback (this is a regen)\n\n");
            sys.push_str(feedback);
            sys.push_str(
                "\n\nFix the specific issue above. Don't repeat the same mistake — \
                 read the project source and model the deployment topology faithfully.",
            );
        }
        if restart_count > 0 || refused {
            sys.push_str(&self.kind.build_restart_bootstrap(
                last_filename,
                last_calls,
                last_gate_passed,
                restart_count.saturating_sub(1),
                refused,
            ));
        }
        sys
    }

    /// Run the agent until violation observed, step / restart budget
    /// exhausted, or hard agent error. Consumes `self` because the
    /// final `LinkFuzzOutcome` only needs the accumulated
    /// `HarnessAttempt` snapshot, not the loop's prompt/memory state.
    async fn drive(self, llm: &LLM) -> Result<LinkFuzzOutcome> {
        let mut total_steps = 0usize;
        let (loop_outcome, last_error) =
            self.spawn_attempts_until_done(llm, &mut total_steps).await;
        self.finalize(loop_outcome, total_steps, last_error).await
    }

    /// Outer loop: keep spawning fresh agents (each a "restart attempt")
    /// until one of them produces a terminal outcome. The agent's
    /// internal stepping happens inside [`Self::run_one_attempt`]; this
    /// method only handles attempt setup + the restart-budget check.
    async fn spawn_attempts_until_done(
        &self,
        llm: &LLM,
        total_steps: &mut usize,
    ) -> (LoopOutcome, Option<String>) {
        // Content-refusal restarts run on their own budget: a refusal says
        // nothing about the agent's work (the request never reached the
        // model), so it shouldn't spend the ordinary restart allowance — but
        // a spec whose data sits permanently on the wrong side of the filter
        // must not loop forever either.
        let mut filter_restarts = 0usize;
        let mut last_was_filtered = false;
        loop {
            let snap = self.snapshot_restart_state().await;
            // The bootstrap's "restart #N" should count refusals too — they
            // are restarts from the model's point of view — even though they
            // draw on their own budget.
            let attempt_no = snap.restart_count + filter_restarts;
            let sys = self.compose_system_prompt(
                attempt_no,
                snap.last_filename.as_deref(),
                snap.last_calls,
                snap.last_gate_passed,
                last_was_filtered,
            );
            let mut agent = Agent::with_memory(
                sys,
                self.build_toolbox(),
                None,
                &self.memory,
                &self.memory_criteria,
            )
            .await;

            match self
                .run_one_attempt(llm, &mut agent, attempt_no, total_steps)
                .await
            {
                AttemptOutcome::Violation => return (LoopOutcome::Violation, None),
                AttemptOutcome::StepsExhausted => return (LoopOutcome::StepsExhausted, None),
                AttemptOutcome::AgentError(e) => return (LoopOutcome::AgentError, Some(e)),
                AttemptOutcome::FilteredRestart => {
                    filter_restarts += 1;
                    last_was_filtered = true;
                    if filter_restarts > self.options.max_filter_restarts {
                        tracing::warn!(
                            "spec {}: content-filter restart budget ({}) exhausted; \
                             giving up on this spec",
                            self.spec_id,
                            self.options.max_filter_restarts
                        );
                        return (
                            LoopOutcome::AgentError,
                            Some(format!(
                                "provider content filter refused the request across \
                                 {filter_restarts} fresh-conversation restart(s)"
                            )),
                        );
                    }
                }
                AttemptOutcome::NeedsRestart => {
                    last_was_filtered = false;
                    let mut st = self.attempt.0.lock().await;
                    st.restarts += 1;
                    if st.restarts > self.options.max_restarts {
                        return (LoopOutcome::RestartsExhausted, None);
                    }
                }
            }
        }
    }

    /// Snapshot the live `HarnessAttempt` fields the next system-prompt
    /// composition needs.
    async fn snapshot_restart_state(&self) -> RestartSnapshot {
        let st = self.attempt.0.lock().await;
        RestartSnapshot {
            restart_count: st.restarts,
            last_filename: st.harness_filename.clone(),
            last_calls: st.last_test_calls,
            last_gate_passed: st.last_gate_passed,
        }
    }

    /// Handle one content-filter refusal of `agent`'s current step: rewrite
    /// the accumulated conversation into the neutral register and retry the
    /// step once. `neutralized` latches so a conversation only gets one
    /// repair; a refusal after it returns [`AttemptOutcome::FilteredRestart`]
    /// for a clean-slate retry instead.
    async fn repair_refused_step_once(
        &self,
        err: LLMYError,
        agent: &mut Agent,
        llm: &LLM,
        neutralized: &mut bool,
        step_no: usize,
    ) -> std::result::Result<StepResult, AttemptOutcome> {
        if *neutralized {
            tracing::info!(
                "spec {}: step {step_no} refused again after neutralization; \
                 restarting with a fresh conversation",
                self.spec_id
            );
            return Err(AttemptOutcome::FilteredRestart);
        }
        *neutralized = true;
        let touched = self.neutralizer.neutralize_agent_context(agent);
        tracing::info!(
            "spec {}: step {step_no} refused by the provider's content filter \
             ({err}); neutralized {touched} message(s) in place, retrying the step",
            self.spec_id
        );
        agent
            .step(
                llm,
                self.debug_prefix.as_deref(),
                self.options.llm_settings.clone(),
            )
            .await
            .map_err(|e| {
                if e.filtered().is_some() {
                    AttemptOutcome::FilteredRestart
                } else {
                    AttemptOutcome::AgentError(format!(
                        "step {step_no} after neutralization: {e}"
                    ))
                }
            })
    }

    /// Inner loop: drive the agent forward one step at a time until it
    /// hits one of the four terminal conditions encoded in
    /// [`AttemptOutcome`]. `total_steps` is the cumulative step counter
    /// shared across restarts so the step budget is per-spec, not
    /// per-attempt.
    async fn run_one_attempt(
        &self,
        llm: &LLM,
        agent: &mut Agent,
        restart_count: usize,
        total_steps: &mut usize,
    ) -> AttemptOutcome {
        // One in-place repair per conversation: neutralize the accumulated
        // offensive-register vocabulary and retry the refused step once.
        // A second refusal falls through to a fresh-conversation restart —
        // after a full rewrite there is nothing left to repair, and the
        // refusal is the spike-or-content lottery again.
        let mut neutralized = false;
        let step_res = agent
            .step_with_user(
                self.user_prompt.clone(),
                llm,
                self.debug_prefix.as_deref(),
                self.options.llm_settings.clone(),
            )
            .await;
        let mut step = match step_res {
            Ok(s) => s,
            // A content refusal is a verdict on the conversation, not on the
            // spec: the same bytes pass or fail depending on when they are
            // sent, and the conversation only gets more offensive-looking to
            // the filter as exploit-shaped tool output accumulates. Repair in
            // place first (keeps the work); a fresh attempt re-reads the
            // harness file from disk and drops the narration entirely.
            Err(e) if e.filtered().is_some() => {
                match self.repair_refused_step_once(e, agent, llm, &mut neutralized, *total_steps)
                    .await
                {
                    Ok(s) => s,
                    Err(outcome) => return outcome,
                }
            }
            Err(e) => {
                return AttemptOutcome::AgentError(format!(
                    "initial step (restart {restart_count}): {e}"
                ));
            }
        };
        *total_steps += 1;

        loop {
            if self.attempt.0.lock().await.violation_observed {
                return AttemptOutcome::Violation;
            }
            if *total_steps >= self.options.max_agent_steps {
                tracing::warn!(
                    "spec {}: step budget exhausted (max_agent_steps={})",
                    self.spec_id,
                    self.options.max_agent_steps
                );
                return AttemptOutcome::StepsExhausted;
            }
            if matches!(step, StepResult::Stop(_)) {
                tracing::warn!(
                    "spec {}: agent stopped with no tool call at step {}; restarting",
                    self.spec_id,
                    *total_steps
                );
                return AttemptOutcome::NeedsRestart;
            }
            if let Some(threshold) = self.options.window_restart_threshold_tokens
                && let Some(used) = agent.approx_context_tokens(&llm.model.config)
                && used >= threshold
            {
                tracing::info!(
                    "spec {}: window threshold reached \
                             (used={used}, threshold={threshold}); restarting agent",
                    self.spec_id
                );
                return AttemptOutcome::NeedsRestart;
            }
            let next = agent
                .step(
                    llm,
                    self.debug_prefix.as_deref(),
                    self.options.llm_settings.clone(),
                )
                .await;
            step = match next {
                Ok(s) => s,
                // Content refusal mid-conversation: repair in place once,
                // then fall back to a clean restart — see the initial-step
                // arm for why.
                Err(e) if e.filtered().is_some() => {
                    match self.repair_refused_step_once(e, agent, llm, &mut neutralized, *total_steps)
                        .await
                    {
                        Ok(s) => s,
                        Err(outcome) => return outcome,
                    }
                }
                Err(e) => {
                    return AttemptOutcome::AgentError(format!("step {}: {e}", *total_steps));
                }
            };
            *total_steps += 1;
        }
    }

    /// Drain the attempt snapshot into a `LinkFuzzOutcome` for
    /// persistence. Pulled out of `drive` so the loop body itself
    /// stays focused on agent stepping; this method has the
    /// LoopOutcome → CodeGenStatus mapping + harness-path computation
    /// + the (runs, coverage_per_run) split.
    async fn finalize(
        self,
        loop_outcome: LoopOutcome,
        total_steps: usize,
        last_error: Option<String>,
    ) -> Result<LinkFuzzOutcome> {
        let snapshot = self.attempt.snapshot().await;
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
                    self.options.max_agent_steps,
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
                    self.options.max_restarts,
                    snapshot.runs.len()
                ),
            ),
            LoopOutcome::AgentError => (
                CodeGenStatus::AgentError,
                last_error.unwrap_or_else(|| "agent error".to_string()),
            ),
        };

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
                let abs = self.harness_dir.join(f);
                abs.strip_prefix(&self.options.repo_root)
                    .map(|p| p.to_string_lossy().into_owned())
                    .unwrap_or_else(|_| abs.to_string_lossy().into_owned())
            })
            .unwrap_or_default();

        let code_gen = CodeGenRecord {
            core: CodeGenCore {
                spec_id: self.spec_id,
                harness_relative_path: harness_relative,
                harness_source: snapshot.harness_source,
                status: code_gen_status,
                final_reason,
                agent_steps: total_steps as i32,
            },
            runs,
        };

        Ok(LinkFuzzOutcome {
            spec_id: self.spec_id,
            code_gen,
            coverage_per_run,
            any_violation,
        })
    }
}

impl HarnessKind {
    /// Drive one spec through the mode's agent loop. Everything beyond
    /// the per-spec setup lives on [`AgentLoopState`]; this method is
    /// a thin shim that builds the state and hands it to `drive`.
    pub(super) async fn run_agent_loop(
        self,
        link: &LinkInput,
        spec: &AuditSpecification,
        spec_id: i32,
        project_index: &Arc<ProjectIndex>,
        llm: &LLM,
        options: &FuzzOptions,
        forge_runner: &ForgeRunner,
        harness_dir: &Path,
        project_conventions: &ProjectConventions,
        prior_feedback: Option<&str>,
    ) -> Result<LinkFuzzOutcome> {
        AgentLoopState::new(
            self,
            link,
            spec,
            spec_id,
            project_index,
            options,
            forge_runner,
            harness_dir,
            project_conventions,
            prior_feedback,
        )
        .await?
        .drive(llm)
        .await
    }
}

// =============================================================================
// Mode-generic public types
// =============================================================================

/// Result of [`FuzzGenerator::regen_one_spec`].
#[derive(Debug, Clone)]
pub struct RegenOutcome {
    pub new_code_gen_id: i32,
    pub status: CodeGenStatus,
    pub any_violation: bool,
}

/// In-memory output of [`FuzzGenerator::regen_codegen_with_explicit_spec`].
#[derive(Debug, Clone)]
pub struct CodegenRegenInMemory {
    pub code_gen: CodeGenRecord,
    pub coverage_per_run: Vec<Vec<CoverageEntry>>,
    pub status: CodeGenStatus,
    pub any_violation: bool,
}

/// Result of [`FuzzGenerator::fuzz_one_existing_spec`]. The
/// `code_gen` row + its `harness_run` rows are already persisted to the
/// project DB.
#[derive(Debug, Clone)]
pub struct FuzzOneOutcome {
    pub spec_id: i32,
    pub code_gen_id: i32,
    pub run_ids: Vec<i32>,
    pub status: CodeGenStatus,
    pub any_violation: bool,
}

// =============================================================================
// Public generator
// =============================================================================

/// Top-level fuzz/regen driver. The `kind` field selects which
/// test-authoring mode each spec runs through — handler+invariant
/// (default; current behavior) or deterministic-PoC (new). Both modes
/// produce [`LinkFuzzOutcome`] / [`FuzzOneOutcome`], so downstream
/// callers never branch on mode.
pub struct SolidityHarnessGenerator {
    repo: RepoDatabase,
    llm: LLM,
    options: FuzzOptions,
    backend: ForgeBackend,
    kind: HarnessKind,
}

impl SolidityHarnessGenerator {
    pub fn new(
        kind: HarnessKind,
        repo: &RepoDatabase,
        llm: &LLM,
        options: &FuzzOptions,
        backend: ForgeBackend,
    ) -> Self {
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
            kind,
        }
    }

    pub async fn run(&self) -> Result<FuzzOutcome> {
        let runtime = FuzzRuntime::new(&self.repo, &self.options, &self.backend).await?;
        let FuzzRuntime {
            project_index,
            link_by_pair,
            harness_dir,
            forge_runner,
            project_conventions,
        } = runtime;

        let specs = self
            .repo
            .load_specifications()
            .await
            .wrap_err("failed to load specifications")?;

        if self.options.regenerate {
            self.repo
                .clear_fuzz_tables()
                .await
                .wrap_err("failed to clear fuzz tables for --regenerate")?;
            tracing::info!(
                "Fuzz: --regenerate set, cleared code_gen / harness_run / line_coverage"
            );
        }
        let already_done = if self.options.regenerate {
            std::collections::HashSet::new()
        } else {
            self.repo
                .loaded_completed_code_gen_spec_ids()
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

        tasks = round_robin_tasks(tasks);
        if let Some(cap) = (self.options.max_specs > 0).then_some(self.options.max_specs)
            && tasks.len() > cap
        {
            tracing::info!(
                "Fuzz: truncating tasks {} → {} (--max-specs)",
                tasks.len(),
                cap
            );
            tasks.truncate(cap);
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
            self.options.concurrency.max(1),
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

    pub async fn fuzz_one_existing_spec(&self, spec_id: i32) -> Result<Option<FuzzOneOutcome>> {
        if !self.options.regenerate {
            let already_done = self
                .repo
                .loaded_completed_code_gen_spec_ids()
                .await
                .wrap_err("failed to load already-fuzzed spec ids")?;
            if already_done.contains(&spec_id) {
                tracing::info!(spec_id, "fuzz_one_existing_spec: skipping resumed spec");
                return Ok(None);
            }
        }
        let (link, spec, runtime) = self.load_spec_link(spec_id).await?;
        let lo = self
            .kind
            .run_agent_loop(
                &link,
                &spec,
                spec_id,
                &runtime.project_index,
                &self.llm,
                &self.options,
                &runtime.forge_runner,
                &runtime.harness_dir,
                &runtime.project_conventions,
                None,
            )
            .await?;
        let status = lo.code_gen.core.status;
        let any_violation = lo.any_violation;
        let (code_gen_id, run_ids) = self
            .repo
            .write_code_gen_with_runs(&lo.code_gen, &lo.coverage_per_run)
            .await
            .wrap_err_with(|| format!("failed to persist code_gen for spec_id={spec_id}"))?;
        tracing::info!(
            spec_id,
            code_gen_id,
            ?status,
            any_violation,
            "fuzz_one_existing_spec: persisted code_gen"
        );
        Ok(Some(FuzzOneOutcome {
            spec_id,
            code_gen_id,
            run_ids,
            status,
            any_violation,
        }))
    }

    pub async fn regen_one_spec(
        &self,
        spec_id: i32,
        prior_feedback: String,
    ) -> Result<RegenOutcome> {
        let (link, spec, runtime) = self.load_spec_link(spec_id).await?;
        let lo = self
            .kind
            .run_agent_loop(
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

    pub async fn regen_codegen_with_explicit_spec(
        &self,
        extract_id: i32,
        finding_id: i32,
        spec: AuditSpecification,
        synthetic_spec_id: i32,
        prior_feedback: String,
    ) -> Result<CodegenRegenInMemory> {
        let runtime = FuzzRuntime::new(&self.repo, &self.options, &self.backend).await?;
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
        let lo = self
            .kind
            .run_agent_loop(
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

    /// Common (link, spec, runtime) lookup for the single-spec entries.
    async fn load_spec_link(
        &self,
        spec_id: i32,
    ) -> Result<(LinkInput, AuditSpecification, FuzzRuntime)> {
        let runtime = FuzzRuntime::new(&self.repo, &self.options, &self.backend).await?;
        let specs = self
            .repo
            .load_specifications()
            .await
            .wrap_err("failed to load specifications")?;
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
        Ok((link, spec, runtime))
    }

    /// Drive the fuzz pass with the `learn::run_full` worker-pool
    /// pattern: async_channel pushes one `FuzzTask` per worker recv,
    /// mpsc streams `(Result<LinkFuzzOutcome>, label)` back to the
    /// main task for sequential DB persistence. `concurrency == 1`
    /// short-circuits to a plain `for` loop so we don't pay channel
    /// setup for serial runs.
    async fn dispatch(
        &self,
        tasks: Vec<FuzzTask>,
        project_index: Arc<ProjectIndex>,
        forge_runner: &ForgeRunner,
        harness_dir: &Path,
        total: usize,
        project_conventions: Arc<ProjectConventions>,
    ) -> Result<FuzzOutcome> {
        let mut outcome = FuzzOutcome::default();
        let concurrency = self.options.concurrency.max(1);

        if concurrency == 1 {
            for (idx, task) in tasks.into_iter().enumerate() {
                let label = task_label(&task, idx, total);
                tracing::info!("Fuzz starting {label}");
                let res = self
                    .kind
                    .run_agent_loop(
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

        let (tx, rx) = async_channel::bounded::<(usize, FuzzTask)>(tasks.len() + 1);
        let (out_tx, mut out_rx) =
            tokio::sync::mpsc::channel::<(Result<LinkFuzzOutcome>, String)>(concurrency + 1);

        let mut workers = JoinSet::new();
        for _ in 0..concurrency {
            let rx = rx.clone();
            let out = out_tx.clone();
            let project_index = project_index.clone();
            let llm = self.llm.clone();
            let options = self.options.clone();
            let forge_runner = forge_runner.clone();
            let harness_dir = harness_dir.to_path_buf();
            let conv = project_conventions.clone();
            let kind = self.kind;
            workers.spawn(async move {
                while let Ok((idx, task)) = rx.recv().await {
                    let label = task_label(&task, idx, total);
                    tracing::info!("Fuzz starting {label}");
                    let res = kind
                        .run_agent_loop(
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
                    out.send((res, label))
                        .await
                        .expect("fuzz result receiver kept alive");
                }
            });
        }
        drop(out_tx);
        drop(rx);

        for (idx, task) in tasks.into_iter().enumerate() {
            tx.send((idx, task)).await.expect("workers kept alive");
        }
        drop(tx);

        while let Some((res, label)) = out_rx.recv().await {
            self.persist(res, &label, &mut outcome).await;
        }
        while let Some(joined) = workers.join_next().await {
            if let Err(err) = joined {
                tracing::error!("fuzz worker task failed: {err:#}");
            }
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

/// One-line tag identifying a task in the fuzz pass log. Used by both
/// the serial and concurrent dispatch paths so the same `Fuzz starting
/// …` message format appears in either mode.
fn task_label(task: &FuzzTask, idx: usize, total: usize) -> String {
    format!(
        "spec {}/{} id={} extract={} finding={}",
        idx + 1,
        total,
        task.spec_id,
        task.link.extract_id,
        task.link.finding_id
    )
}

pub(super) struct FuzzTask {
    pub(super) spec_id: i32,
    pub(super) semantic_id: i32,
    pub(super) link: LinkInput,
    pub(super) spec: AuditSpecification,
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
