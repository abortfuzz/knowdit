//! Mirror of `knowdit_kg_model::db::semantic_node` stored in the per-project
//! repo database. The historical knowledge graph and the project database
//! are separate stores; once the Knowledge Mapper has identified relevant
//! historical semantics, we copy their rows into the project database so
//! downstream agents can read them without re-querying the historical KG.
use sea_orm::entity::prelude::*;

use knowdit_kg_model::category::DeFiCategory;
use knowdit_kg_model::db::semantic_node;

#[sea_orm::model]
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize, DeriveEntityModel)]
#[sea_orm(table_name = "historical_semantic")]
pub struct Model {
    /// Stable id from the historical knowledge graph (no auto-increment so
    /// the kg id is preserved).
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: i32,
    #[sea_orm(column_type = "Text")]
    pub name: String,
    #[sea_orm(column_type = "Text")]
    pub definition: String,
    #[sea_orm(column_type = "Text")]
    pub description: String,
    pub category: DeFiCategory,
}

impl ActiveModelBehavior for ActiveModel {}

impl From<semantic_node::Model> for Model {
    fn from(node: semantic_node::Model) -> Self {
        Self {
            id: node.id,
            name: node.name,
            definition: node.definition,
            description: node.description,
            category: node.category,
        }
    }
}

impl From<Model> for semantic_node::Model {
    fn from(node: Model) -> Self {
        Self {
            id: node.id,
            name: node.name,
            definition: node.definition,
            description: node.description,
            category: node.category,
        }
    }
}
