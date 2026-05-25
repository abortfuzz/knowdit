//! Semantics that the historical KG has admitted but not yet cross-linked
//! against the corpus of already-linked findings.
//!
//! Lifecycle (used by the "learn-new-project" CLI):
//! 1. When a new project is admitted (after categorize → extract → in-project
//!    linking → merge), every newly-introduced canonical semantic id is
//!    inserted here.
//! 2. The retro-link phase iterates each row in `finding_link_status` (i.e.
//!    findings that have already gone through global linking on a previous
//!    pass) and asks the LLM whether each pending-semantic relates to it,
//!    appending links to `semantic_finding_link` as needed.
//! 3. After retro-link finishes, this table is truncated and pending findings
//!    flow through normal global linking — which now will see the new
//!    semantics naturally because they are canonical at that point.
use sea_orm::entity::prelude::*;

#[sea_orm::model]
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize, DeriveEntityModel)]
#[sea_orm(table_name = "pending_semantic")]
pub struct Model {
    /// References `semantic_node.id`. Always a canonical id in practice
    /// (newly-introduced semantics never start out merged-away).
    #[sea_orm(primary_key, auto_increment = false)]
    pub semantic_node_id: i32,

    #[sea_orm(belongs_to, from = "semantic_node_id", to = "id")]
    pub semantic_node: Option<super::semantic_node::Entity>,
}

impl ActiveModelBehavior for ActiveModel {}
