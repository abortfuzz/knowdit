//! Reflection: post-fuzz triage of synthesized harnesses.
//!
//! Two layers:
//!
//! * **Inline gates** (run inside the `run_forge` agent tool, see
//!   [`runtime_audit`] + [`coverage_audit`]). Gate 1 and Gate 2 fire as
//!   part of the agent's tool result every time forge is invoked, so a
//!   harness with a failed setUp / 99% revert rate / poor coverage gets
//!   immediate feedback and the fuzz agent can fix it within its step
//!   budget.
//!
//! * **Outer triage** (`agentic reflect`). For every violated
//!   `harness_run`, two specialist agents run in sequence:
//!     1. [`grader::VerdictGrader`] — classifies the violation into one
//!        of five [`ReflectionResult`] verdicts via on-demand
//!        project-source inspection (`lookup_call_graph`,
//!        `read_function_source`, …).
//!     2. [`severity_grader::SeverityGrader`] — only when verdict 1 is
//!        `ValidFinding`. Identifies which on-chain state variables
//!        represent project liquidity, then argues whether the
//!        counter-example trace fully drains them (High), partially
//!        drains / griefs / DOSes (Medium), or only causes a
//!        non-exploitable edge case (Low).
//!
//! Both verdicts are co-written **atomically** to `reflection` +
//! `valid_finding` so a crash mid-pipeline leaves zero rows. See
//! [`RepoDatabase::insert_reflection_with_finding`] for the contract.

pub mod agent_loop;
pub mod coverage_audit;
pub mod grader;
mod prompt;
pub mod runtime_audit;
pub mod severity_grader;

use color_eyre::eyre::Result;
use knowdit_repo_model::{ReflectionResult, RepoDatabase};
use llmy::client::client::LLM;

use self::agent_loop::GraderOptions;
use self::grader::VerdictGrader;
use self::severity_grader::SeverityGrader;

/// Bundle of the two reflection agents — built together so they share
/// one loaded `ProjectIndex` (cuts the call_graph + storage_graph load
/// from twice per CLI invocation to once). The bundle is the public
/// entry point the CLI uses; `ProjectIndex` itself stays internal to
/// the audit crate.
pub struct GraderPair {
    pub verdict: VerdictGrader,
    pub severity: SeverityGrader,
}

impl GraderPair {
    pub async fn new(
        repo: &RepoDatabase,
        repo_root: &std::path::Path,
        llm: &LLM,
        options: GraderOptions,
    ) -> Result<Self> {
        let verdict = VerdictGrader::new(repo, repo_root, llm, options.clone()).await?;
        let severity = SeverityGrader::new_with_index(
            llm,
            repo_root,
            verdict.project_index().clone(),
            options,
        );
        Ok(Self { verdict, severity })
    }
}

/// Tunable thresholds for the coverage gate. Gate 1 has no threshold —
/// its signals are spec-driven booleans (setUp_failed, revert_rate,
/// counter-example overlap). Threaded into the inline gates by reference;
/// never read from globals or env vars.
#[derive(Debug, Clone, Copy)]
pub struct AuditThresholds {
    /// Gate 2: harness fails if `hit_fns / expected_fns` is strictly
    /// less than this. `0.5` = "more than half of `spec.sequence`'s
    /// functions never got executed".
    pub gate2_fidelity_threshold: f64,
}

impl Default for AuditThresholds {
    fn default() -> Self {
        Self {
            gate2_fidelity_threshold: 0.5,
        }
    }
}

/// Outcome of one gate. `Pass` means the gate had nothing to flag;
/// `Fail` carries a human-readable reason that becomes the agent-facing
/// `[GATE N FAILED]` line in the `run_forge` tool result.
#[derive(Debug, Clone)]
pub enum AuditOutcome {
    Pass,
    Fail { gate: GateKind, reason: String },
}

impl AuditOutcome {
    pub fn is_fail(&self) -> bool {
        matches!(self, Self::Fail { .. })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GateKind {
    Static,
    Coverage,
    Grader,
}

impl GateKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Static => "gate1_static",
            Self::Coverage => "gate2_coverage",
            Self::Grader => "gate3_grader",
        }
    }
}

/// One reflection-row to write. The result is determined by the LLM
/// grader (Gate 3) — Gates 1/2 no longer write reflection rows since
/// they fire inline during fuzz instead of post-hoc.
#[derive(Debug, Clone)]
pub struct ReflectionDraft {
    pub result: ReflectionResult,
    pub reason: String,
}
