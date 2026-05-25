//! Domain value type for an audit finding extracted from a project's
//! historical reports. Shared between the LLM extraction pipeline (which
//! produces these via tool calls) and the persistence layer in
//! `knowdit-kg`. Derives `JsonSchema` so it can serve directly as a tool's
//! `ARGUMENTS` shape — no duplicate "Args" struct needed.
use schemars::JsonSchema;
use sea_orm::ActiveValue::Set;
use serde::{Deserialize, Serialize};

use crate::audit_finding::FindingSeverity;
use crate::db::audit_finding;
use crate::finding_category::VulnerabilityCategory;

#[derive(Debug, Deserialize, Serialize, Clone, JsonSchema)]
pub struct ExtractedFinding {
    /// Original report title for this finding.
    pub title: String,
    /// Severity bucket: High | Medium | Low.
    pub severity: FindingSeverity,
    /// Top-level vulnerability category from the taxonomy.
    pub category: VulnerabilityCategory,
    /// Subcategory (must match a taxonomy entry under `category`).
    pub subcategory: String,
    /// Technical/economic root cause (project-agnostic prose).
    pub root_cause: String,
    /// Abstract description of the vulnerable pattern + impact.
    pub description: String,
    /// Code patterns / state assumptions that trigger the bug.
    pub patterns: String,
    /// How attackers typically exploit this in practice.
    pub exploits: String,
}

impl ExtractedFinding {
    /// Build an `ActiveModel` ready to insert into `audit_finding`. The
    /// `(category, subcategory)` pair is not stored on this row — it is
    /// represented by an `audit_finding_category` link to a
    /// `finding_category` taxonomy entry, and the project-provenance link
    /// MUST be written to `project_finding` by the caller. There is no
    /// scalar `project_id` column on `audit_finding`.
    pub fn to_active_model(&self) -> audit_finding::ActiveModel {
        audit_finding::ActiveModel {
            title: Set(self.title.clone()),
            severity: Set(self.severity),
            root_cause: Set(self.root_cause.clone()),
            description: Set(self.description.clone()),
            patterns: Set(self.patterns.clone()),
            exploits: Set(self.exploits.clone()),
            ..Default::default()
        }
    }

    /// Reconstruct from a stored `audit_finding` row plus the resolved taxonomy
    /// entry (which lives in `finding_category`, joined via
    /// `audit_finding_category`).
    pub fn from_model(
        model: audit_finding::Model,
        category: VulnerabilityCategory,
        subcategory: String,
    ) -> Self {
        Self {
            title: model.title,
            severity: model.severity,
            category,
            subcategory,
            root_cause: model.root_cause,
            description: model.description,
            patterns: model.patterns,
            exploits: model.exploits,
        }
    }
}
