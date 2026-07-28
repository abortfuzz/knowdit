use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};
use std::fmt;

/// Verdict produced by the Finding Reflector when reviewing one
/// `harness_run`. Five variants come from the LLM verdict grader
/// (Gate 3); `Suspect` is written by the static / coverage gates
/// (Gate 1 / Gate 2) when the harness fails their checks even
/// without a forge violation.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, EnumIter, DeriveActiveEnum, Serialize, Deserialize,
)]
#[sea_orm(rs_type = "String", db_type = "String(StringLen::N(32))")]
pub enum ReflectionResult {
    /// The violation falls outside the project's auditing scope (e.g. excluded by README rules).
    #[sea_orm(string_value = "OutOfScope")]
    OutOfScope,
    /// The specification itself was incomplete or inaccurate; regenerate the spec.
    #[sea_orm(string_value = "IncompleteSpecification")]
    IncompleteSpecification,
    /// One of the call-sequence steps was incomplete; regenerate the harness.
    #[sea_orm(string_value = "IncompleteStep")]
    IncompleteStep,
    /// The violation matches the spec but is expected (e.g. `onlyOwner` revert).
    #[sea_orm(string_value = "ExpectedViolation")]
    ExpectedViolation,
    /// The violation is a real, in-scope vulnerability worth reporting.
    /// When this verdict lands, a sibling `valid_finding` row carries
    /// the severity tier + severity rationale (separate agent).
    #[sea_orm(string_value = "ValidFinding")]
    ValidFinding,
    /// Static (Gate 1) or coverage (Gate 2) audit fail — harness looks
    /// fake / disconnected from project code; recommend codegen regen.
    #[sea_orm(string_value = "Suspect")]
    Suspect,
}

impl ReflectionResult {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::OutOfScope => "OutOfScope",
            Self::IncompleteSpecification => "IncompleteSpecification",
            Self::IncompleteStep => "IncompleteStep",
            Self::ExpectedViolation => "ExpectedViolation",
            Self::ValidFinding => "ValidFinding",
            Self::Suspect => "Suspect",
        }
    }

    /// Whether this verdict means a regen should follow. Drives the
    /// `pending_reflections` query. The three terminal verdicts
    /// (`ValidFinding`, `ExpectedViolation`, `OutOfScope`) close the
    /// (semantic, finding) pair.
    pub fn requires_regen(&self) -> bool {
        matches!(
            self,
            Self::IncompleteSpecification | Self::IncompleteStep | Self::Suspect
        )
    }

    /// Whether this verdict requires a *spec* regen as opposed to a
    /// codegen-only regen. Only `IncompleteSpecification` does.
    pub fn requires_spec_regen(&self) -> bool {
        matches!(self, Self::IncompleteSpecification)
    }

    /// Whether this verdict closes the direction with a judgement about the
    /// PROJECT rather than about the harness — the two cases whose reasoning
    /// stays true for every later agent, and therefore the two that carry a
    /// reusable [`Model::ruled_out_claim`].
    ///
    /// `IncompleteSpecification` / `IncompleteStep` / `Suspect` are execution
    /// failures: a re-run may well succeed, so replaying them would steer later
    /// agents away from ground that was never actually cleared. `ValidFinding`
    /// closes the direction too, but it is already replayed to downstream
    /// agents as a canonical report finding.
    pub fn rules_out_direction(&self) -> bool {
        matches!(self, Self::ExpectedViolation | Self::OutOfScope)
    }
}

impl fmt::Display for ReflectionResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A reflection record — one verdict per [`super::harness_run`].
/// Severity (when `result == ValidFinding`) lives in the sibling
/// [`super::valid_finding`] table written atomically by
/// `RepoDatabase::insert_reflection_with_finding`.
///
/// `run_id` is `UNIQUE` so a re-run of `agentic reflect` either skips
/// (verdict already committed) or retries cleanly (no half-written
/// state from a prior crashed agent loop).
#[sea_orm::model]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, DeriveEntityModel)]
#[sea_orm(table_name = "reflection")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i32,
    #[sea_orm(unique, indexed)]
    pub run_id: i32,
    #[sea_orm(indexed)]
    pub spec_id: i32,
    #[sea_orm(indexed)]
    pub result: ReflectionResult,
    #[sea_orm(column_type = "Text")]
    pub reason: String,
    /// Reusable statement of the project fact that makes assertions of this
    /// shape not-a-bug. Deliberately split from `reason`: `reason` argues THIS
    /// run's verdict (which functions were covered, what the trace did),
    /// whereas this field is written for a *later* agent that never sees the
    /// run — it states the fact alone, so the same ground is not re-argued.
    /// Populated for the two verdicts that close a direction
    /// (`ExpectedViolation` / `OutOfScope`); `None` for the rest.
    #[sea_orm(column_type = "Text", nullable)]
    pub ruled_out_claim: Option<String>,
    /// Where the claim can be re-checked, in whatever form this project
    /// actually offers: a documentation line, a source comment, an
    /// access-control modifier or `require`, a test that asserts the
    /// behaviour. `None` when the grader found no anchor worth citing.
    #[sea_orm(column_type = "Text", nullable)]
    pub ruled_out_evidence: Option<String>,

    #[sea_orm(belongs_to, from = "run_id", to = "id")]
    pub harness_run: HasOne<super::harness_run::Entity>,
    #[sea_orm(belongs_to, from = "spec_id", to = "id")]
    pub specification: HasOne<super::specification::Entity>,
}

impl ActiveModelBehavior for ActiveModel {}
