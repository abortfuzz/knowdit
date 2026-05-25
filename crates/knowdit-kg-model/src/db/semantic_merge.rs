use sea_orm::entity::prelude::*;

#[sea_orm::model]
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize, DeriveEntityModel)]
#[sea_orm(table_name = "semantic_merge")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub from_semantic_id: i32,
    #[sea_orm(primary_key, auto_increment = false)]
    pub to_semantic_id: i32,
}

impl ActiveModelBehavior for ActiveModel {}
