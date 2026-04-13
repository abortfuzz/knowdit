use sea_orm::entity::prelude::*;

use super::category::DeFiCategory;

#[sea_orm::model]
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize, DeriveEntityModel)]
#[sea_orm(table_name = "semantic_node")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i32,
    /// Short canonical name, e.g. "Constant Product AMM Swap"
    #[sea_orm(column_type = "Text")]
    pub name: String,
    #[sea_orm(column_type = "Text")]
    pub definition: String,
    #[sea_orm(column_type = "Text")]
    pub description: String,
    /// The primary DeFi business category of this semantic.
    pub category: DeFiCategory,
    /// The project that originally introduced this semantic
    pub project_id: i32,

    #[sea_orm(belongs_to, from = "project_id", to = "id")]
    pub project: HasOne<super::project::Entity>,
    #[sea_orm(has_many)]
    pub functions: HasMany<super::semantic_function::Entity>,
    #[sea_orm(has_many, via = "semantic_finding_link")]
    pub findings: HasMany<super::audit_finding::Entity>,
}

impl ActiveModelBehavior for ActiveModel {}
