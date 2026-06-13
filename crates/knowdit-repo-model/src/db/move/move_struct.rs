//! Move struct definitions (`move_struct` table).
//!
//! Filled by `movy analysis export-repo-info`. Holds every
//! struct in the package — both `key`-able Sui objects and plain
//! value types — so spec-gen / harness prompts can reference any
//! struct by name. Abilities live in a separate relation table
//! ([`super::move_struct_ability`]) so audit prompts can JOIN
//! reverse-lookup "which structs carry `key`?".
//!
//! `contract_id` references the `contract` table (Move modules
//! share the `contract` table with Solidity contracts since both
//! the call-graph and storage layers already key on it). UNIQUE on
//! `(contract_id, name)` because no Move module can re-declare a
//! struct name.

use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

#[sea_orm::model]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, DeriveEntityModel)]
#[sea_orm(table_name = "move_struct")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i32,
    /// References `contract.id` — the Move module that declares this
    /// struct. Indexed for "list every struct in this module" queries.
    #[sea_orm(indexed)]
    pub contract_id: i32,
    #[sea_orm(column_type = "Text")]
    pub name: String,
    /// JSON-encoded `Vec<MoveGenericParam>`. Not queried at the SQL
    /// layer, so a relation table would be over-modeling.
    #[sea_orm(column_type = "Text")]
    pub generic_params: String,
    /// JSON-encoded `Vec<MoveField>`. Field types are short text;
    /// audit prompts read them verbatim.
    #[sea_orm(column_type = "Text")]
    pub fields: String,

    #[sea_orm(belongs_to, from = "contract_id", to = "id")]
    pub contract: HasOne<super::super::contract::Entity>,
}

impl ActiveModelBehavior for ActiveModel {}
