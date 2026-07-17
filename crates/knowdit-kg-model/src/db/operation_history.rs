//! Append-only audit log of top-level `knowdit learn` operations that mutate
//! the historical knowledge graph (currently `c4learn` and `link`).
//!
//! One row per DISTINCT `(type, args)`: the row is written only after the
//! operation's real work has fully committed, and the write is deduplicated on
//! `(type, args)` so re-running the same operation with byte-identical
//! arguments never appends a second row. `args` deliberately carries ONLY the
//! operation's tuning knobs (serialized from its CLI arg struct) — never LLM
//! credentials, filesystem paths, or any other sensitive input.
use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};
use std::fmt;

/// Discriminator for [`Model`], stored as its lowercase string value. New
/// variants are added on request only — this enum is intentionally NOT
/// extended speculatively.
#[derive(Debug, Clone, Copy, PartialEq, Eq, EnumIter, DeriveActiveEnum, Serialize, Deserialize)]
#[sea_orm(rs_type = "String", db_type = "String(StringLen::N(32))")]
pub enum OperationType {
    /// `knowdit learn c4` — bulk-admit Code4rena projects into the KG.
    #[sea_orm(string_value = "c4learn")]
    C4Learn,
    /// `knowdit learn sherlock` — bulk-admit Sherlock contests into the KG.
    #[sea_orm(string_value = "sherlocklearn")]
    SherlockLearn,
    /// `knowdit learn link` — global finding-to-semantic linking pass.
    #[sea_orm(string_value = "link")]
    Link,
}

impl OperationType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::C4Learn => "c4learn",
            Self::SherlockLearn => "sherlocklearn",
            Self::Link => "link",
        }
    }
}

impl fmt::Display for OperationType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[sea_orm::model]
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize, DeriveEntityModel)]
#[sea_orm(table_name = "operation_history")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i32,

    /// Wall-clock time (UTC) the operation completed and this row was written.
    pub datetime: DateTimeUtc,

    /// Which operation this row records — see [`OperationType`].
    #[sea_orm(column_name = "type")]
    pub operation_type: OperationType,

    /// The operation's tuning knobs, serialized from its CLI arg struct.
    /// Non-sensitive by construction (no credentials, no paths).
    #[sea_orm(column_type = "Json")]
    pub args: Json,
}

impl ActiveModelBehavior for ActiveModel {}
