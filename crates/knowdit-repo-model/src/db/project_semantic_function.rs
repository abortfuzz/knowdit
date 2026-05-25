use sea_orm::entity::prelude::*;

#[sea_orm::model]
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize, DeriveEntityModel)]
#[sea_orm(table_name = "project_semantic_function")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i32,
    #[sea_orm(indexed)]
    pub semantic_id: i32,
    #[sea_orm(column_type = "Text")]
    pub name: String,
    #[sea_orm(column_type = "Text")]
    pub contract: String,
    #[sea_orm(column_type = "Text", nullable)]
    pub signature: Option<String>,

    #[sea_orm(belongs_to, from = "semantic_id", to = "id")]
    pub semantic: HasOne<super::project_semantic::Entity>,
}

impl ActiveModelBehavior for ActiveModel {}
