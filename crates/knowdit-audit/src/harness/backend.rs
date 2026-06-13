//! `HarnessBackend` — the seam between language-agnostic
//! orchestrators (`agentic fuzz`, `agentic regen`, `workflow
//! streamloop`, `workflow autoloop`) and the per-language harness
//! synthesis + execution stack. Solidity / Foundry is the
//! open-source impl shipped with this crate; additional impls
//! (e.g. additional language backends) plug in by implementing
//! this trait.
//!
//! Design notes:
//!
//! * Construction holds **settings** — which mode, where the
//!   runtime binary lives, any per-pass options equivalent to
//!   [`solidity::FuzzOptions`]. Per-call resources (`RepoDatabase`,
//!   `LLM`, the spec the caller wants regenerated) flow through
//!   method arguments. This matches how callers already thread
//!   `repo` / `llm` today.
//!
//! * No `dyn`, no callbacks — `impl Future<…> + Send` so the trait
//!   monomorphizes at every call site. Orchestrators are written as
//!   `fn run<B: HarnessBackend>(backend: &B, …)`.
//!
//! * The four entry methods exist because each granularity is
//!   independently used downstream:
//!     - `fuzz_sweep` — `agentic fuzz` / streamloop scheduler sweep.
//!     - `fuzz_one_existing_spec` — streamloop's per-spec scheduler
//!       launches one spec at a time after gen-specs.
//!     - `regen_codegen_for_spec` — `agentic regen` and streamloop's
//!       regen drain consume pending reflections.
//!     - `codegen_for_in_memory_spec` — spec-regen produces a new
//!       spec that hasn't been persisted yet; codegen runs against it
//!       and both rows commit atomically via
//!       [`knowdit_repo_model::RepoDatabase::write_full_spec_regen`].

use std::future::Future;
use std::path::Path;

use color_eyre::eyre::Result;
use knowdit_repo_model::RepoDatabase;
use llmy::client::client::LLM;

use crate::harness::solidity::{CodegenRegenInMemory, FuzzOneOutcome, FuzzOutcome, RegenOutcome};
use crate::types::AuditSpecification;

/// Per-language harness backend. See module docs for the seam
/// rationale.
///
/// Returned futures are `+ Send` so orchestrators can spawn them on
/// `tokio::task::JoinSet`. Backends that don't need cross-thread
/// async still get monomorphized into a Send future at every call.
pub trait HarnessBackend: Send + Sync {
    /// Markdown language-context block this backend wants
    /// prepended to every audit-phase agent system prompt
    /// (mapper / spec-gen / verdict / severity / spec-regen)
    /// when this backend is the runtime. Each language's
    /// backend impl owns the wording for *that* language —
    /// Solidity's prefix lives next to `SolidityHarness`,
    /// other languages' prefixes live next to their respective
    /// `HarnessBackend` impls.
    fn prompt_prefix(&self) -> &'static str;

    /// Smoke-test the runtime environment (forge binary / docker /
    /// cgroup / external runtime binary) before any LLM-heavy
    /// phase touches it.
    /// On failure the error embeds the runtime's own stdout/stderr
    /// so the user reads the actual diagnostic rather than
    /// "preflight failed".
    fn preflight(&self, repo_root: &Path) -> impl Future<Output = Result<()>> + Send;

    /// Drive the full multi-spec sweep: load pending specs from the
    /// DB, codegen + execute each, persist the per-spec
    /// `code_gen` / `harness_run` / `line_coverage` rows. Resume-safe
    /// — previously-completed `code_gen` rows short-circuit unless
    /// the backend was configured to regenerate from scratch.
    fn fuzz_sweep(
        &self,
        repo: &RepoDatabase,
        llm: &LLM,
    ) -> impl Future<Output = Result<FuzzOutcome>> + Send;

    /// Codegen + execute one specific `spec_id`. Returns `None` when
    /// the spec already has a completed `code_gen` row and the
    /// backend isn't in regenerate mode (matches the streamloop
    /// scheduler's "skip resumed" semantic).
    fn fuzz_one_existing_spec(
        &self,
        repo: &RepoDatabase,
        llm: &LLM,
        spec_id: i32,
    ) -> impl Future<Output = Result<Option<FuzzOneOutcome>>> + Send;

    /// Regen the codegen for an existing `spec_id`, threading prior
    /// reflection feedback into the agent's system prompt. Persists
    /// a new `code_gen` row + `code_gen_regen` lineage edge.
    fn regen_codegen_for_spec(
        &self,
        repo: &RepoDatabase,
        llm: &LLM,
        spec_id: i32,
        prior_feedback: String,
    ) -> impl Future<Output = Result<RegenOutcome>> + Send;

    /// Codegen against an in-memory spec that hasn't been persisted
    /// yet — used by spec-regen, which mints a fresh spec and wants
    /// to attach codegen before the atomic `write_full_spec_regen`
    /// commits both the spec row and the codegen row in one
    /// transaction.
    fn codegen_for_in_memory_spec(
        &self,
        repo: &RepoDatabase,
        llm: &LLM,
        extract_id: i32,
        finding_id: i32,
        spec: AuditSpecification,
        synthetic_spec_id: i32,
        prior_feedback: String,
    ) -> impl Future<Output = Result<CodegenRegenInMemory>> + Send;
}
