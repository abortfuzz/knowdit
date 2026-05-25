use sea_orm::entity::prelude::*;

/// 1:1 relation table mapping projects to their platform-specific IDs.
/// Extracted from project.platform_id to avoid a unique nullable column.
#[sea_orm::model]
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize, DeriveEntityModel)]
#[sea_orm(table_name = "project_platform")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i32,
    /// The project this maps to (unique — at most one platform ID per project)
    #[sea_orm(unique)]
    pub project_id: i32,
    /// Platform-specific ID, e.g. "c4-420" for Code4rena contest 420
    pub platform_id: String,

    #[sea_orm(belongs_to, from = "project_id", to = "id")]
    pub project: HasOne<super::project::Entity>,
}

impl ActiveModelBehavior for ActiveModel {}
