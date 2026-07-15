//! Mirror of `knowdit_kg_model::db::finding_merge` stored in the per-project
//! repo database. Records that a raw child finding (`from_finding_id`) was
//! folded into a canonical (`to_finding_id`) in the historical KG, carrying the
//! merge-time `appended_*` notes (the child's concrete delta for each mutable
//! field). Lets downstream rendering surface each merged variant beneath the
//! bounded canonical fields without re-querying the historical KG.
use sea_orm::entity::prelude::*;

#[sea_orm::model]
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize, DeriveEntityModel)]
#[sea_orm(table_name = "historical_finding_merge")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub from_finding_id: i32,
    #[sea_orm(primary_key, auto_increment = false)]
    pub to_finding_id: i32,
    #[sea_orm(column_type = "Text")]
    pub appended_description: String,
    #[sea_orm(column_type = "Text")]
    pub appended_patterns: String,
    #[sea_orm(column_type = "Text")]
    pub appended_exploits: String,
}

impl ActiveModelBehavior for ActiveModel {}
