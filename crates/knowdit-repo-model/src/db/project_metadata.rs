//! Per-project KV store. One row per `(key, value)` pair. The
//! `value` column carries opaque JSON serialised by callers — the
//! schema does not care what shape it has.
//!
//! Used today for:
//!   - `key = "profile"`: serialized `ProjectProfile` (the autoloop
//!     profile phase's output; consumed by the Knowledge Mapper).
//!
//! Future per-DB metadata (KG version fingerprint, last-mapper-run
//! timestamp, autoloop billing cumulative, …) goes here too — new
//! key, no new table.
use sea_orm::entity::prelude::*;

#[sea_orm::model]
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize, DeriveEntityModel)]
#[sea_orm(table_name = "project_metadata")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub key: String,
    #[sea_orm(column_type = "Text")]
    pub value: String,
}

impl ActiveModelBehavior for ActiveModel {}
