//! Per-raw-finding structured audit review.
//!
//! One row per `valid_finding` (keyed 1:1 on its `reflection_id`) that the
//! `review-findings` workflow's Review agent has graded into a
//! client-facing shape: a `title`, a re-graded [`ReviewSeverity`], the
//! normalized `root_cause` / `description` the Merge agent clusters on, and
//! the on-disk `location`. A missing row means "this raw finding has not
//! been reviewed yet"; a re-review overwrites in place (`INSERT OR REPLACE`
//! on the `reflection_id` primary key), so there is never a transient
//! half-reviewed state.
//!
//! `severity` is the Review agent's own judgment — the fuzz-time
//! `valid_finding.severity` is NOT trusted (the severity grader
//! over-produces `Medium`). [`ReviewSeverity::ReviewedOutOfScope`] folds
//! the "real bug but excluded by audit scope / project assumptions"
//! disposition (out-of-scope contract, trusted-admin action,
//! fee-on-transfer on a mock token, …) into the severity field, so there is
//! no separate disposition column.

use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

/// Re-graded severity tier the Review agent emits. Extends the fuzz-time
/// `{High, Medium, Low}` with `Informational` (real but no / negligible
/// impact) and `ReviewedOutOfScope` (real bug, but outside the audit scope
/// or excluded by the project's stated assumptions). Ordered by report
/// weight via [`ReviewSeverity::rank`] so a canonical's severity can be
/// reconciled as the max over its merged members.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, EnumIter, DeriveActiveEnum, Serialize, Deserialize,
)]
#[sea_orm(rs_type = "String", db_type = "String(StringLen::N(20))")]
pub enum ReviewSeverity {
    #[sea_orm(string_value = "High")]
    High,
    #[sea_orm(string_value = "Medium")]
    Medium,
    #[sea_orm(string_value = "Low")]
    Low,
    #[sea_orm(string_value = "Informational")]
    Informational,
    #[sea_orm(string_value = "ReviewedOutOfScope")]
    ReviewedOutOfScope,
}

impl ReviewSeverity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::High => "High",
            Self::Medium => "Medium",
            Self::Low => "Low",
            Self::Informational => "Informational",
            Self::ReviewedOutOfScope => "ReviewedOutOfScope",
        }
    }

    /// Whether this finding belongs in the client report body. Everything
    /// except `ReviewedOutOfScope` is reportable; OOS findings are kept for
    /// traceability (and dedup) but rendered to an appendix at most.
    pub fn is_reportable(&self) -> bool {
        !matches!(self, Self::ReviewedOutOfScope)
    }

    /// Report weight used to reconcile a canonical's severity as the max
    /// across its merged members. `ReviewedOutOfScope` ranks below the
    /// reportable tiers so a single in-scope member lifts the cluster out
    /// of OOS.
    pub fn rank(&self) -> u8 {
        match self {
            Self::High => 5,
            Self::Medium => 4,
            Self::Low => 3,
            Self::Informational => 2,
            Self::ReviewedOutOfScope => 1,
        }
    }
}

#[sea_orm::model]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, DeriveEntityModel)]
#[sea_orm(table_name = "finding_review")]
pub struct Model {
    /// The raw finding this review grades. Shares the `valid_finding` /
    /// `reflection` identity 1:1; not auto-incremented.
    #[sea_orm(primary_key, auto_increment = false)]
    pub reflection_id: i32,
    /// Concise, client-facing, project-specific title.
    #[sea_orm(column_type = "Text")]
    pub title: String,
    /// Re-graded severity (NOT the fuzz-time `valid_finding.severity`).
    #[sea_orm(indexed)]
    pub severity: ReviewSeverity,
    /// Scope / severity rationale. Required for `ReviewedOutOfScope`
    /// (cite the excluding scope rule or assumption).
    #[sea_orm(column_type = "Text")]
    pub review_reason: String,
    /// One-line normalized root cause — the primary key the Merge agent
    /// clusters on.
    #[sea_orm(column_type = "Text")]
    pub root_cause: String,
    /// Normalized, project-terms description — the body the Merge agent
    /// compares and the seed for the canonical's client description.
    #[sea_orm(column_type = "Text")]
    pub description: String,
    /// Primary affected location (`Contract.function` + `file:line`).
    #[sea_orm(column_type = "Text")]
    pub location: String,
    /// Client-facing impact statement (what is lost/broken, who can trigger
    /// it). Produced by the Review agent; carried straight into the report.
    #[sea_orm(column_type = "Text")]
    pub impact: String,
    /// Client-facing remediation guidance. Produced by the Review agent.
    #[sea_orm(column_type = "Text")]
    pub recommendation: String,
    /// Primary affected contract name. Report metadata + a non-authoritative
    /// hint to the Merge agent — NEVER a bucketing key (the agent can
    /// hallucinate it, so candidate selection uses token chunking, not this).
    #[sea_orm(column_type = "Text")]
    pub primary_contract: String,
    /// Primary affected function name. Same metadata/hint role as
    /// `primary_contract`; not a bucketing key.
    #[sea_orm(column_type = "Text")]
    pub primary_function: String,
    /// Impact argument carried over from the severity reasoning.
    #[sea_orm(column_type = "Text")]
    pub severity_reason: String,

    #[sea_orm(belongs_to, from = "reflection_id", to = "id")]
    pub reflection: HasOne<super::reflection::Entity>,
}

impl ActiveModelBehavior for ActiveModel {}
