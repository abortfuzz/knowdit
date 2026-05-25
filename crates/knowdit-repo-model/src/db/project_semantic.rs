use knowdit_kg_model::category::DeFiCategory;
use sea_orm::entity::prelude::*;

#[sea_orm::model]
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize, DeriveEntityModel)]
#[sea_orm(table_name = "project_semantic")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i32,
    #[sea_orm(column_type = "Text")]
    pub name: String,
    pub category: DeFiCategory,
    #[sea_orm(column_type = "Text")]
    pub definition: String,
    #[sea_orm(column_type = "Text")]
    pub description: String,

    #[sea_orm(has_many)]
    pub functions: HasMany<super::project_semantic_function::Entity>,
}

impl ActiveModelBehavior for ActiveModel {}
