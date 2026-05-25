//! Mirror of `knowdit_kg_model::db::semantic_finding_link` stored in the
//! per-project repo database. Links each `historical_semantic` row to the
//! `historical_finding` rows that the kg associated with it.
//!
//! Carries `strength` + `evidence` straight from the KG side so downstream
//! consumers (gen-specs etc.) can filter by `strength.rank()` without
//! cross-DB joins — see `plan_link.md` §7.2.
use sea_orm::entity::prelude::*;

use knowdit_kg_model::db::semantic_finding_link;

#[sea_orm::model]
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize, DeriveEntityModel)]
#[sea_orm(table_name = "historical_semantic_finding_link")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub historical_semantic_id: i32,
    #[sea_orm(primary_key, auto_increment = false)]
    pub historical_finding_id: i32,
    /// Mirrored from KG's `semantic_finding_link.strength`.
    #[sea_orm(indexed)]
    pub strength: knowdit_kg_model::link_strength::LinkStrength,
    /// Mirrored from KG's `semantic_finding_link.evidence`.
    #[sea_orm(column_type = "Text")]
    pub evidence: String,

    #[sea_orm(belongs_to, from = "historical_semantic_id", to = "id")]
    pub historical_semantic: Option<super::historical_semantic::Entity>,
    #[sea_orm(belongs_to, from = "historical_finding_id", to = "id")]
    pub historical_finding: Option<super::historical_finding::Entity>,
}

impl ActiveModelBehavior for ActiveModel {}

impl From<semantic_finding_link::Model> for Model {
    fn from(link: semantic_finding_link::Model) -> Self {
        Self {
            historical_semantic_id: link.semantic_node_id,
            historical_finding_id: link.audit_finding_id,
            strength: link.strength,
            evidence: link.evidence,
        }
    }
}

impl From<Model> for semantic_finding_link::Model {
    fn from(link: Model) -> Self {
        Self {
            semantic_node_id: link.historical_semantic_id,
            audit_finding_id: link.historical_finding_id,
            strength: link.strength,
            evidence: link.evidence,
        }
    }
}
