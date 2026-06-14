//! Generic primitives for "tool-call agent loops" used across the KG learn
//! pipeline (categorize / extract semantics / extract findings / merge
//! semantics / merge findings).
//!
//! ## Data flow
//!
//! Each LLM step previously asked the model to emit one big JSON document
//! per chunk. That worked for tiny chunks but broke down when a single
//! response would have to enumerate dozens of items: the model occasionally
//! emits structurally invalid JSON (forgets a `,`, doubles a key, miscloses
//! a bracket), and the entire chunk's worth of work is wasted.
//!
//! The replacement: spin up one `llmy::harness::Agent` per chunk (without
//! memory) and give it exactly two tools:
//!
//! - **emit-one-item** — the agent calls this once per record it has
//!   produced (one DeFi semantic, one finding, one merge decision, …). The
//!   tool implementation simply pushes the record into an
//!   [`AgentChunkBuffer`].
//! - **finalize** — the agent calls this when the chunk is fully covered.
//!   That terminates the step loop on this side; we then drain the buffer
//!   and ship the items downstream.
//!
//! No JSON parsing of free-form responses; no "max-N-entries-per-response"
//! tricks; one call per item, so partial progress is never thrown away.
//!
//! This module supplies the *plumbing*: the generic per-item buffer, the
//! step-loop driver, and the run options. Per-workflow tools (with their
//! workflow-specific argument shapes) live in [`crate::agents`].

use std::sync::Arc;

use llmy::agent::StepResult;
use llmy::agent::tool::ToolBox;
use llmy::client::client::LLM;
use llmy::client::settings::LLMSettings;
use llmy::harness::{Agent, AgentConfig};
use thiserror::Error;
use tokio::sync::Mutex;

use crate::error::{KgError, Result};

/// Tunables shared by every agent-style chunk run.
///
/// Surfaced 1:1 from CLI by the caller; this struct does NOT read any
/// `std::env` variable. The `Default` impl exists only as a single
/// well-known starting point for code paths that haven't been updated to
/// thread the CLI knob through (currently: the deprecated `knowdit-spec`
/// crate). Production callers should always override via
/// [`AgentRunOptions::new`].
#[derive(Debug, Clone)]
pub struct AgentRunOptions {
    /// Hard cap on the number of agent steps before we force-abandon the
    /// chunk. The initial `step_with_user` counts as step 1. Values < 1
    /// are clamped to 1.
    pub max_agent_steps: usize,
    /// Optional debug prefix forwarded to llmy. When set, llmy persists
    /// every request/response pair under
    /// `$LLM_DEBUG/<pid>/<prefix>-<NNN>.{json,xml}`.
    pub debug_prefix: Option<String>,
    /// Optional per-call llmy settings. When `None`, llmy reads the
    /// process-level defaults (which the parent CLI populated from clap).
    pub llm_settings: Option<LLMSettings>,
}

impl Default for AgentRunOptions {
    fn default() -> Self {
        // Single source of truth for the fallback step cap. Keep in sync
        // with the clap default in `MergeCliArgs::max_agent_steps` /
        // `ExtractSemanticsArgs::max_agent_steps` (both default to 60).
        Self::new(60)
    }
}

impl AgentRunOptions {
    pub fn new(max_agent_steps: usize) -> Self {
        Self {
            max_agent_steps: max_agent_steps.max(1),
            debug_prefix: None,
            llm_settings: None,
        }
    }

    pub fn with_debug_prefix(mut self, prefix: impl Into<String>) -> Self {
        self.debug_prefix = Some(prefix.into());
        self
    }

    pub fn with_llm_settings(mut self, settings: LLMSettings) -> Self {
        self.llm_settings = Some(settings);
        self
    }

    /// Build a child `AgentRunOptions` with `debug_prefix` extended by
    /// `scope`. Clones the rest of the fields so the original options
    /// stays usable for sibling phases.
    pub fn scoped(&self, scope: &str) -> Self {
        let prefix = match self.debug_prefix.as_deref() {
            Some(p) if !p.is_empty() => format!("{p}-{scope}"),
            _ => scope.to_string(),
        };
        Self {
            max_agent_steps: self.max_agent_steps,
            debug_prefix: Some(prefix),
            llm_settings: self.llm_settings.clone(),
        }
    }
}

/// Outcome reported by [`AgentChunkRunner::run`] (or the workflow runners).
#[derive(Debug, Clone)]
pub struct AgentRunOutcome {
    /// Number of agent steps consumed (>= 1 because the initial
    /// `step_with_user` counts).
    pub steps: usize,
    /// `Some(reason)` if the loop ended without the agent invoking the
    /// finalize tool — usually "agent stopped silently" or "exceeded
    /// max_agent_steps". Callers may downgrade this to a warning since the
    /// items already in the buffer remain valid.
    pub early_stop_reason: Option<String>,
    /// Free-form summary string the agent passed to the finalize tool, if
    /// the tool was actually called.
    pub finalize_summary: Option<String>,
}

/// Generic per-chunk accumulator. Tool implementations push items in via
/// [`AgentChunkBuffer::push`]; the matching finalize tool calls
/// [`AgentChunkBuffer::finalize`] to break the agent step loop. The driver
/// drains items via [`AgentChunkBuffer::drain`] once the loop exits.
///
/// `T` is the workflow's record type (e.g. `ExtractedSemantic`,
/// `ExtractedFinding`, `MergeDecisionRecord`, …).
#[derive(Debug)]
pub struct AgentChunkBuffer<T> {
    items: Mutex<Vec<T>>,
    state: Mutex<BufferState>,
}

#[derive(Debug, Clone, Default)]
struct BufferState {
    finalized: bool,
    finalize_summary: Option<String>,
}

#[derive(Debug, Error)]
pub enum AgentBufferError {
    #[error("buffer is already finalized; subsequent tool calls are ignored")]
    AlreadyFinalized,
}

impl<T> Default for AgentChunkBuffer<T> {
    fn default() -> Self {
        Self {
            items: Mutex::new(Vec::new()),
            state: Mutex::new(BufferState::default()),
        }
    }
}

impl<T> AgentChunkBuffer<T> {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Append a record. Returns an error (visible to the agent as a tool
    /// result string) if the buffer has already been finalized.
    pub async fn push(&self, item: T) -> std::result::Result<(), AgentBufferError> {
        if self.state.lock().await.finalized {
            return Err(AgentBufferError::AlreadyFinalized);
        }
        self.items.lock().await.push(item);
        Ok(())
    }

    /// Push and synthesize the tool-result string in one shot. `label`
    /// names the record kind (e.g. `"semantic"`) for the success message.
    /// On failure (already finalized) returns the error message intended
    /// for the LLM.
    pub async fn push_with_message(&self, item: T, label: &str) -> String {
        match self.push(item).await {
            Ok(()) => format!("ok: recorded {label} #{}", self.len().await),
            Err(err) => format!("error: {err}"),
        }
    }

    /// Mark the buffer finalized; subsequent `push` and `finalize` calls
    /// will fail. The agent's step loop polls [`Self::is_finalized`] to
    /// decide when to exit.
    pub async fn finalize(
        &self,
        summary: Option<String>,
    ) -> std::result::Result<(), AgentBufferError> {
        let mut state = self.state.lock().await;
        if state.finalized {
            return Err(AgentBufferError::AlreadyFinalized);
        }
        state.finalized = true;
        state.finalize_summary = summary;
        Ok(())
    }

    /// Finalize and synthesize the tool-result string in one shot. `label`
    /// names the workflow (e.g. `"semantic extraction"`) for the success
    /// message.
    pub async fn finalize_with_message(&self, summary: Option<String>, label: &str) -> String {
        match self.finalize(summary).await {
            Ok(()) => format!(
                "ok: {label} finalized with {} item(s). Stop now.",
                self.len().await
            ),
            Err(err) => format!("error: {err}"),
        }
    }

    pub async fn is_finalized(&self) -> bool {
        self.state.lock().await.finalized
    }

    /// Snapshot the count without taking the items.
    pub async fn len(&self) -> usize {
        self.items.lock().await.len()
    }

    /// Move all collected items out of the buffer. The buffer is left
    /// empty (but still in finalized-state); intended to be called once,
    /// after the step loop ends.
    pub async fn drain(&self) -> Vec<T> {
        std::mem::take(&mut *self.items.lock().await)
    }

    /// Return the finalize summary the agent reported (if the agent
    /// actually called the finalize tool). Cloned so the buffer can stay
    /// borrowed.
    pub async fn finalize_summary(&self) -> Option<String> {
        self.state.lock().await.finalize_summary.clone()
    }
}

/// Step-loop driver. Caller assembles the [`ToolBox`] (which must include
/// at least one finalize-capable tool that flips the buffer's `finalized`
/// flag) and the system / user prompts; this method spins up an agent
/// without memory and pumps it until the buffer is finalized, the agent
/// stops on its own, or `max_agent_steps` is exhausted.
///
/// `LLM` is `Clone`, `AgentRunOptions` is `Clone`, and prompts/keys are
/// already owned `String`s — no lifetimes needed.
pub struct AgentChunkRunner<T> {
    pub llm: LLM,
    pub options: AgentRunOptions,
    pub buffer: Arc<AgentChunkBuffer<T>>,
    pub tools: ToolBox,
    pub system_prompt: String,
    pub user_prompt: String,
    pub cache_key: String,
    pub label: String,
}

impl<T> AgentChunkRunner<T> {
    pub async fn run(self) -> Result<AgentRunOutcome> {
        let AgentChunkRunner {
            llm,
            options,
            buffer,
            tools,
            system_prompt,
            user_prompt,
            cache_key,
            label,
        } = self;

        // Sequential tool calls: every agent routed through this driver
        // exposes `emit_* … finalize_*` tools, where a same-turn parallel
        // `finalize` can win the buffer lock and make the concurrent
        // `emit` hit `AlreadyFinalized` — silently dropping that record.
        // Forcing sequential execution makes emit-before-finalize hold.
        let mut agent = Agent::new_with_config(
            system_prompt,
            tools,
            cache_key,
            AgentConfig::default().sequential_toolcall(),
        );

        let initial = agent
            .step_with_user(
                user_prompt,
                &llm,
                options.debug_prefix.as_deref(),
                options.llm_settings.clone(),
            )
            .await
            .map_err(|err| KgError::other(format!("{label} agent initial step failed: {err}")))?;

        let mut step = initial;
        let mut steps: usize = 1;
        let mut early_stop: Option<String> = None;

        while !buffer.is_finalized().await {
            if matches!(step, StepResult::Stop(_)) {
                early_stop = Some("agent stopped without calling finalize".to_string());
                break;
            }
            if steps >= options.max_agent_steps {
                early_stop = Some(format!(
                    "agent exceeded max_agent_steps={}",
                    options.max_agent_steps
                ));
                break;
            }
            step = agent
                .step(
                    &llm,
                    options.debug_prefix.as_deref(),
                    options.llm_settings.clone(),
                )
                .await
                .map_err(|err| {
                    KgError::other(format!("{label} agent step #{steps} failed: {err}"))
                })?;
            steps += 1;
        }

        let summary = buffer.finalize_summary().await;
        if let Some(reason) = early_stop.as_ref() {
            tracing::warn!(
                "{} agent: {} (collected {} item(s))",
                label,
                reason,
                buffer.len().await,
            );
        }
        Ok(AgentRunOutcome {
            steps,
            early_stop_reason: early_stop,
            finalize_summary: summary,
        })
    }
}
