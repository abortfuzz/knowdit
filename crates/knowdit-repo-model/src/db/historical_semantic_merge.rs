//! Mirror of `knowdit_kg_model::db::semantic_merge` stored in the per-project
//! repo database. Records that a raw child semantic (`from_semantic_id`) was
//! folded into a canonical (`to_semantic_id`) in the historical KG, carrying
//! the merge-time `appended_description` note (the child's concrete delta).
//! Lets downstream rendering surface each merged variant beneath the bounded
//! canonical description without re-querying the historical KG.
use sea_orm::entity::prelude::*;

#[sea_orm::model]
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize, DeriveEntityModel)]
#[sea_orm(table_name = "historical_semantic_merge")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub from_semantic_id: i32,
    #[sea_orm(primary_key, auto_increment = false)]
    pub to_semantic_id: i32,
    #[sea_orm(column_type = "Text")]
    pub appended_description: String,
}

impl ActiveModelBehavior for ActiveModel {}
