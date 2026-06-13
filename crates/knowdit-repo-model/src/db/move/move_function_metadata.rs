//! Move-specific per-function metadata (`move_function_metadata`
//! table).
//!
//! 1:1 with rows in the `function` table — `function_id` is both
//! primary key and foreign key. Only populated for Move functions;
//! Solidity functions never get a row here so the existing
//! `function` table stays uncluttered.
//!
//! Visibility encodes the trust boundary for audit prompts. Sui
//! 2024 introduced `public(package)` to replace the legacy
//! `public(friend)` model; we keep both variants so older codebases
//! aren't downgraded to a less precise label.

use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};
use std::fmt;

#[sea_orm::model]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, DeriveEntityModel)]
#[sea_orm(table_name = "move_function_metadata")]
pub struct Model {
    /// PK + FK to `function.id`. `auto_increment = false` because
    /// the function row gets its ID from the call-graph writer; we
    /// reuse that ID rather than allocate a new one.
    #[sea_orm(primary_key, auto_increment = false)]
    pub function_id: i32,
    pub visibility: MoveVisibility,
    /// Whether the function is a Sui `entry fun`. Entry functions
    /// are PTB targets — audit prompts use this to identify the
    /// attack surface.
    pub is_entry: bool,
    /// JSON-encoded `Vec<MoveGenericParam>` (same shape as
    /// [`super::move_struct::Model::generic_params`]).
    #[sea_orm(column_type = "Text")]
    pub generic_params: String,

    #[sea_orm(belongs_to, from = "function_id", to = "id")]
    pub function: HasOne<super::super::function::Entity>,
}

impl ActiveModelBehavior for ActiveModel {}

/// Move function visibility. Kept as `DeriveActiveEnum` (TEXT column
/// width 20) so adding a future variant requires a code update but
/// not a schema migration.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, EnumIter, DeriveActiveEnum, Serialize, Deserialize,
)]
#[sea_orm(rs_type = "String", db_type = "String(StringLen::N(20))")]
pub enum MoveVisibility {
    /// `public fun` — callable from any module / PTB top level.
    #[sea_orm(string_value = "Public")]
    Public,
    /// Sui 2024+: `public(package) fun` — only callable from
    /// modules in the same on-chain package (i.e. same address
    /// prefix on `contract.path`).
    #[sea_orm(string_value = "PublicPackage")]
    PublicPackage,
    /// Legacy Diem / pre-2024 Sui: `public(friend) fun` — only
    /// callable from modules declared as friends. Audit precision
    /// degrades for code using this: we don't track the friend
    /// list itself in v1 (no `move_friend` table), so the prompt
    /// only knows "some friend can call this".
    #[sea_orm(string_value = "PublicFriend")]
    PublicFriend,
    /// No visibility annotation in source — module-private.
    #[sea_orm(string_value = "Private")]
    Private,
}

impl MoveVisibility {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Public => "Public",
            Self::PublicPackage => "PublicPackage",
            Self::PublicFriend => "PublicFriend",
            Self::Private => "Private",
        }
    }

    /// Parse from the spelling movy uses on disk. Tolerant to whitespace
    /// + case so a hand-authored fixture works in tests.
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "public" => Some(Self::Public),
            "publicpackage" | "public_package" | "public(package)" => Some(Self::PublicPackage),
            "publicfriend" | "public_friend" | "public(friend)" => Some(Self::PublicFriend),
            "private" => Some(Self::Private),
            _ => None,
        }
    }
}

impl fmt::Display for MoveVisibility {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}
