//! Many-to-many between semantic-graph nodes and the DeFi categories they
//! cover beyond their primary `semantic_node.category`.
//!
//! Category-recall secondary-category table: when a raw semantic with
//! category X folds into a canonical with category Y (X≠Y, X≠`Others`),
//! the canonical gains one row here so category-scoped candidate pools
//! (`existing_semantics_for_categories`) still surface it for X.
//!
//! The composite primary key makes each (node, category) pair unique.
use sea_orm::entity::prelude::*;

#[sea_orm::model]
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize, DeriveEntityModel)]
#[sea_orm(table_name = "semantic_node_category")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub semantic_node_id: i32,
    #[sea_orm(primary_key, auto_increment = false)]
    pub category_id: i32,

    #[sea_orm(belongs_to, from = "semantic_node_id", to = "id")]
    pub semantic_node: Option<super::semantic_node::Entity>,
    #[sea_orm(belongs_to, from = "category_id", to = "id")]
    pub category: Option<super::category::Entity>,
}

impl ActiveModelBehavior for ActiveModel {}
