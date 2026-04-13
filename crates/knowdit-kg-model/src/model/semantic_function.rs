use sea_orm::entity::prelude::*;

/// Links a semantic node to a specific function in the originating project
#[sea_orm::model]
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize, DeriveEntityModel)]
#[sea_orm(table_name = "semantic_function")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i32,
    pub semantic_node_id: i32,
    /// Qualified function name, e.g. "Pool.swap" or "swap(address,uint256)"
    pub function_name: String,
    /// Source file path relative to project root
    pub contract_path: String,

    #[sea_orm(belongs_to, from = "semantic_node_id", to = "id")]
    pub semantic_node: HasOne<super::semantic_node::Entity>,
}

impl ActiveModelBehavior for ActiveModel {}
