//! Mirror of `knowdit_kg_model::db::audit_finding` stored in the per-project
//! repo database. See [`super::historical_semantic`] for the rationale.
use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

use knowdit_kg_model::audit_finding::FindingSeverity;
use knowdit_kg_model::db::audit_finding;

#[sea_orm::model]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, DeriveEntityModel)]
#[sea_orm(table_name = "historical_finding")]
pub struct Model {
    /// Stable id from the historical knowledge graph.
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: i32,
    #[sea_orm(column_type = "Text")]
    pub title: String,
    pub severity: FindingSeverity,
    #[sea_orm(column_type = "Text")]
    pub root_cause: String,
    #[sea_orm(column_type = "Text")]
    pub description: String,
    #[sea_orm(column_type = "Text")]
    pub patterns: String,
    #[sea_orm(column_type = "Text")]
    pub exploits: String,
}

impl ActiveModelBehavior for ActiveModel {}

impl From<audit_finding::Model> for Model {
    fn from(finding: audit_finding::Model) -> Self {
        Self {
            id: finding.id,
            title: finding.title,
            severity: finding.severity,
            root_cause: finding.root_cause,
            description: finding.description,
            patterns: finding.patterns,
            exploits: finding.exploits,
        }
    }
}

impl From<Model> for audit_finding::Model {
    fn from(finding: Model) -> Self {
        Self {
            id: finding.id,
            title: finding.title,
            severity: finding.severity,
            root_cause: finding.root_cause,
            description: finding.description,
            patterns: finding.patterns,
            exploits: finding.exploits,
        }
    }
}
