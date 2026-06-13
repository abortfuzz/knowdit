//! `move_struct_ability` — many-to-many between a struct and the
//! Move abilities it carries (`copy` / `drop` / `store` / `key`).
//!
//! Why a relation table instead of a CSV column on `move_struct`:
//! audit queries reverse this lookup ("find every `key`-able struct
//! in the package", "which structs lack `store`?") and a JOIN on an
//! indexed enum column is the right shape for that.
//!
//! Stored as a `String(N(8))` `DeriveActiveEnum` so the abilities
//! survive serde round-trips and adding a future ability (Aptos
//! has a couple of extensions on the roadmap) doesn't require a
//! schema migration — only a code update.

use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};
use std::fmt;

#[sea_orm::model]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, DeriveEntityModel)]
#[sea_orm(table_name = "move_struct_ability")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i32,
    /// FK to `move_struct.id`. Indexed for the forward lookup
    /// ("what abilities does struct X have?").
    #[sea_orm(indexed)]
    pub struct_id: i32,
    /// The ability tag. Indexed for the reverse lookup ("which
    /// structs have ability A?").
    #[sea_orm(indexed)]
    pub ability: MoveAbility,

    #[sea_orm(belongs_to, from = "struct_id", to = "id")]
    pub move_struct: HasOne<super::move_struct::Entity>,
}

impl ActiveModelBehavior for ActiveModel {}

/// One of Move's four built-in struct abilities, stored as its
/// lowercase string name in the DB. Lives here (rather than on
/// `move_struct`) because the values are persisted on this table.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    EnumIter,
    DeriveActiveEnum,
    Serialize,
    Deserialize,
)]
#[sea_orm(rs_type = "String", db_type = "String(StringLen::N(8))")]
pub enum MoveAbility {
    /// Value can be copied implicitly.
    #[sea_orm(string_value = "copy")]
    Copy,
    /// Value may go out of scope without explicit consumption.
    #[sea_orm(string_value = "drop")]
    Drop,
    /// Value can be nested inside other Move structs.
    #[sea_orm(string_value = "store")]
    Store,
    /// Sui object marker — owned by an address, eligible for
    /// `transfer` / `share_object` / `freeze_object` / dynamic
    /// fields. The single most audit-relevant ability.
    #[sea_orm(string_value = "key")]
    Key,
}

impl MoveAbility {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Copy => "copy",
            Self::Drop => "drop",
            Self::Store => "store",
            Self::Key => "key",
        }
    }

    pub fn parse(token: &str) -> Option<Self> {
        match token.trim().to_ascii_lowercase().as_str() {
            "copy" => Some(Self::Copy),
            "drop" => Some(Self::Drop),
            "store" => Some(Self::Store),
            "key" => Some(Self::Key),
            _ => None,
        }
    }

    /// Stable sort key. Matches the historical Move ability
    /// declaration order (`Copy < Drop < Store < Key`) so the
    /// load path returns abilities deterministically regardless of
    /// row insertion order in `move_struct_ability`.
    pub fn canonical_order(&self) -> u8 {
        match self {
            Self::Copy => 0,
            Self::Drop => 1,
            Self::Store => 2,
            Self::Key => 3,
        }
    }
}

impl fmt::Display for MoveAbility {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}
