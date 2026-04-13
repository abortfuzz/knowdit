use sea_orm::entity::prelude::*;

/// Junction table: which categories a project belongs to
#[sea_orm::model]
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize, DeriveEntityModel)]
#[sea_orm(table_name = "project_category")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub project_id: i32,
    #[sea_orm(primary_key, auto_increment = false)]
    pub category_id: i32,

    #[sea_orm(belongs_to, from = "project_id", to = "id")]
    pub project: Option<super::project::Entity>,
    #[sea_orm(belongs_to, from = "category_id", to = "id")]
    pub category: Option<super::category::Entity>,
}

impl ActiveModelBehavior for ActiveModel {}
