use sea_orm::entity::prelude::*;

#[sea_orm::model]
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize, DeriveEntityModel)]
#[sea_orm(table_name = "semantic_merge")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub from_semantic_id: i32,
    #[sea_orm(primary_key, auto_increment = false)]
    pub to_semantic_id: i32,
    /// One-or-two-sentence note, produced at merge time, describing how the raw
    /// child (`from_semantic_id`) *extends* the canonical (`to_semantic_id`)
    /// beyond the canonical's own concrete-representative description. Lets
    /// downstream rendering keep the canonical concise while still surfacing
    /// each merged variant's concrete delta.
    #[sea_orm(column_type = "Text")]
    pub appended_description: String,
}

impl ActiveModelBehavior for ActiveModel {}
