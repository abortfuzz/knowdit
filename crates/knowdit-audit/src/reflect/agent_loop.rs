//! Shared infrastructure for the two reflection agents
//! ([`super::grader::VerdictGrader`] and
//! [`super::severity_grader::SeverityGrader`]).
//!
//! Both agents follow the same shape:
//! 1. build a `ToolBox` containing the project lookup/read tools plus
//!    one agent-specific `emit_*` tool that writes the verdict into an
//!    [`AttemptHandle`];
//! 2. drive the agent loop until the attempt handle is filled or the
//!    step budget is exhausted;
//! 3. return the captured verdict.
//!
//! The pieces shared between the two graders live here so neither
//! reimplements the loop or the budget bookkeeping:
//!
//! - [`GraderOptions`]: clap-fed knobs (steps / debug prefix). Both
//!   graders take this same struct.
//! - [`AttemptHandle<T>`]: typed handle the `emit_*` tool writes into;
//!   the loop polls it per step.
//! - [`RunSummary`] / [`CoverageSummary`]: the shared shape of one
//!   harness_run + coverage digest the agents see in their input
//!   payload.
//! - [`drive_agent_loop`]: the actual step / step-budget
//!   loop, generic over the verdict type.

use std::sync::Arc;

use color_eyre::eyre::{Result, WrapErr};
use llmy::agent::StepResult;
use llmy::agent::tool::ToolBox;
use llmy::client::client::LLM;
use llmy::client::settings::LLMSettings;
use llmy::harness::Agent;
use serde::Serialize;
use tokio::sync::Mutex;

use crate::spec::{MemoryScope, ProjectIndex, spec_memory_criteria};

/// 80% of the model's max input tokens — same default as
/// `SpecificationGenerator` and `SolidityFuzzGenerator`.
/// Tunables shared by both reflection agents. All fields owned, no
/// lifetimes; constructed by the CLI layer (clap derive in
/// `ReflectArgs`); never reads constants or env vars itself.
#[derive(Debug, Clone)]
pub struct GraderOptions {
    /// Maximum agent steps per `grade()` call before forced finalize.
    pub max_agent_steps: usize,
    /// Optional debug prefix forwarded to llmy for LLM-call dumps.
    pub debug_prefix: Option<String>,
    /// Optional per-call llmy settings (reasoning_effort, temperature, …).
    pub llm_settings: Option<LLMSettings>,
}

/// One harness_run digest as the agents see it in their JSON input.
/// Single struct shared between [`super::grader::VerdictInput`] and
/// [`super::severity_grader::SeverityInput`] — both agents need the
/// same per-run information.
#[derive(Debug, Clone, Serialize)]
pub struct RunSummary {
    pub kind: String,
    pub exit_code: i32,
    pub violated: bool,
    pub stdout_tail: String,
    pub counterexample_json: Option<serde_json::Value>,
}

/// Aggregated Gate 2 view of how much of `spec.sequence` actually got
/// exercised at the line-coverage level. Same struct used by both
/// agents.
#[derive(Debug, Clone, Serialize)]
pub struct CoverageSummary {
    pub fidelity: f64,
    pub hit_fns: usize,
    pub expected_fns: usize,
    pub missed_step_labels: Vec<String>,
}

/// Typed in-flight attempt state shared between an agent and its
/// orchestrator. Owned, cloneable handle to a shared `Mutex` — no
/// lifetime params anywhere. The `emit_*` tool fills the inner
/// `Option<T>`; the loop polls [`Self::is_set`] to know when the
/// agent is done.
#[derive(Debug)]
pub struct AttemptHandle<T> {
    inner: Arc<Mutex<Option<T>>>,
}

// Manual `Clone` so we don't require `T: Clone` — the handle
// itself is just an `Arc`, regardless of `T`.
impl<T> Clone for AttemptHandle<T> {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

impl<T> Default for AttemptHandle<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> AttemptHandle<T> {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(None)),
        }
    }

    /// True if a prior tool call already filled this handle. The
    /// loop's terminate condition.
    pub async fn is_set(&self) -> bool {
        self.inner.lock().await.is_some()
    }

    /// Atomically set the inner value if empty. Returns `Err` when a
    /// prior call already wrote — the `emit_*` tool surfaces this to
    /// the agent so it knows it tried to commit twice.
    pub async fn try_set(&self, value: T) -> std::result::Result<(), &'static str> {
        let mut g = self.inner.lock().await;
        if g.is_some() {
            return Err("already set");
        }
        *g = Some(value);
        Ok(())
    }

    /// Take the value out (consuming). Used after the loop terminates.
    pub async fn take(&self) -> Option<T> {
        self.inner.lock().await.take()
    }
}

/// Drive an agent loop until [`AttemptHandle::is_set`] flips, the
/// agent calls `Stop`, or the step budget is exhausted. Returns the
/// step count (the caller pulls the verdict out of the handle).
///
/// Generic over the verdict type so both [`VerdictGrader`] and
/// [`SeverityGrader`] reuse the loop body byte-for-byte.
///
/// Resume safety: this fn writes nothing to the DB. Agent crashes /
/// step-budget exhaustion bubble out as `Err` and the caller
/// **must not** persist a row in those cases.
pub async fn drive_agent_loop<T: Send + Sync + 'static>(
    project_index: &Arc<ProjectIndex>,
    llm: &LLM,
    options: &GraderOptions,
    system_prompt: String,
    user_prompt: String,
    debug_suffix: &str,
    tools: ToolBox,
    attempt: &AttemptHandle<T>,
) -> Result<usize> {
    let memory = project_index.build_link_memory(MemoryScope::WholeProject)?;

    let debug_prefix = options
        .debug_prefix
        .as_ref()
        .map(|p| format!("{p}-{debug_suffix}"));

    let mut agent =
        Agent::with_memory(system_prompt, tools, None, &memory, &spec_memory_criteria()).await;

    let mut step = agent
        .step_with_user(
            user_prompt,
            llm,
            debug_prefix.as_deref(),
            options.llm_settings.clone(),
        )
        .await
        .wrap_err("reflection agent failed on initial step")?;
    let mut steps = 1usize;

    while !attempt.is_set().await {
        if matches!(step, StepResult::Stop(_)) {
            return Err(color_eyre::eyre::eyre!(
                "reflection agent stopped at step {steps} without emitting a verdict \
                 (debug_suffix={debug_suffix})"
            ));
        }
        if steps >= options.max_agent_steps {
            return Err(color_eyre::eyre::eyre!(
                "reflection agent exhausted max_agent_steps={} without emitting a verdict \
                 (debug_suffix={debug_suffix}); raise --grader-max-agent-steps and retry",
                options.max_agent_steps,
            ));
        }
        steps += 1;
        step = agent
            .step(llm, debug_prefix.as_deref(), options.llm_settings.clone())
            .await
            .wrap_err_with(|| format!("reflection agent failed at step {steps}"))?;
    }

    Ok(steps)
}
