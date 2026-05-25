//! Many-to-many between historical projects and semantic-graph nodes.
//!
//! Replaces the old `semantic_node.project_id` column. A canonical (merged)
//! semantic node may participate in many historical projects, so the
//! provenance link lives in this side table instead of being scalar on the
//! semantic row. Each row records "project P contributed (or shares) semantic
//! S". The same `(project_id, semantic_node_id)` pair must not be inserted
//! twice — the composite primary key enforces that.
//!
//! Note: `semantic_node_id` here may reference either a canonical node or a
//! merged-away (raw) node. Consumers that need only canonical visibility
//! should resolve through `semantic_merge`.
use sea_orm::entity::prelude::*;

#[sea_orm::model]
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize, DeriveEntityModel)]
#[sea_orm(table_name = "project_semantic")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub project_id: i32,
    #[sea_orm(primary_key, auto_increment = false)]
    pub semantic_node_id: i32,

    #[sea_orm(belongs_to, from = "project_id", to = "id")]
    pub project: Option<super::project::Entity>,
    #[sea_orm(belongs_to, from = "semantic_node_id", to = "id")]
    pub semantic_node: Option<super::semantic_node::Entity>,
}

impl ActiveModelBehavior for ActiveModel {}
