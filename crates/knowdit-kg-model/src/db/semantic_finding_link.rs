//! KG-side `(semantic_node, audit_finding)` edge — one row per pair
//! emitted by the link agent. The agent produces a strength label
//! per pair AND a free-form evidence rationale; both land here. The
//! composite primary key `(semantic_node_id, audit_finding_id)`
//! enforces uniqueness without needing a separate UNIQUE index.
//!
//! The rubric that decides `strength` lives in the linker's system prompt
//! (`knowdit-kg/src/prompts.rs`), not here — this table only stores the
//! verdict.

use sea_orm::entity::prelude::*;

#[sea_orm::model]
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize, DeriveEntityModel)]
#[sea_orm(table_name = "semantic_finding_link")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub semantic_node_id: i32,
    #[sea_orm(primary_key, auto_increment = false)]
    pub audit_finding_id: i32,
    /// Link agent's strength tier for this pair (High / Medium / Low).
    /// Indexed so downstream read APIs can filter by strength.rank()
    /// efficiently.
    #[sea_orm(indexed)]
    pub strength: crate::link_strength::LinkStrength,
    /// Free-form rationale the agent emitted alongside the strength
    /// label. Length floors are enforced at the agent tool handler
    /// (40+ chars for High/Medium, 15+ for Low). Useful for human
    /// audit and downstream prompt-building consumers.
    #[sea_orm(column_type = "Text")]
    pub evidence: String,

    #[sea_orm(belongs_to, from = "semantic_node_id", to = "id")]
    pub semantic_node: Option<super::semantic_node::Entity>,
    #[sea_orm(belongs_to, from = "audit_finding_id", to = "id")]
    pub audit_finding: Option<super::audit_finding::Entity>,
}

impl ActiveModelBehavior for ActiveModel {}
