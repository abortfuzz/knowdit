use sea_orm::entity::prelude::*;

#[sea_orm::model]
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize, DeriveEntityModel)]
#[sea_orm(table_name = "project")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i32,
    #[sea_orm(column_type = "Text")]
    pub name: String,
    /// "pending" or "completed" — tracks whether semantic extraction is done
    pub status: String,

    #[sea_orm(has_one)]
    pub platform: HasOne<super::project_platform::Entity>,
    #[sea_orm(has_many, via = "project_category")]
    pub categories: HasMany<super::category::Entity>,
    // NOTE: legacy direct `has_many semantic_nodes / audit_findings` removed.
    // The new joins live through `project_semantic` / `project_finding`. They
    // will be added back as `via = ...` relations once the legacy `project_id`
    // columns on those rows go away (see the corresponding entity files).
}

impl ActiveModelBehavior for ActiveModel {}
