//! Move-language value types (analogue to [`crate::cg`] for the
//! Solidity call-graph and [`crate::storage`] for the storage
//! graph).
//!
//! v1 surface = **package structure only**: what modules / structs
//! / functions exist, plus per-function Move-specific metadata
//! (visibility, `entry`-ness, generic constraints) and per-struct
//! attributes (abilities, fields, generic params). Persisted by
//! movy's `analysis export-package-structure` CLI into the
//! [`crate::db::move_struct`] and
//! [`crate::db::move_function_metadata`] tables. See
//! [`MovePackageStructure`] for the in-memory shape and
//! [`crate::RepoDatabase::write_package_structure`] /
//! [`crate::RepoDatabase::load_package_structure`] for the
//! persistence boundary.
//!
//! There is intentionally **no** "Sui object flow" graph
//! analogous to Solidity's StorageGraph. Move's static typing
//! already exposes object usage in function signatures + bytecode
//! locals, so the same query ("which functions touch this
//! struct?") is recoverable from [`crate::cg::CallGraph`] +
//! [`MoveStruct`] without a separate pre-computed table. Audit
//! prompts pull this signal on demand rather than from a denormalised
//! schema. (plan_move_lang.md §10 records the decision.)
//!
//! Writer pattern matches the Solidity-side graph writers:
//! `clear + bulk insert` inside one transaction so a partial write
//! either lands wholly or rolls back. Re-running an analysis fully
//! replaces the prior snapshot.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

pub use crate::db::r#move::move_function_metadata::MoveVisibility;
pub use crate::db::r#move::move_struct_ability::MoveAbility;

/// A Move struct, populated for every struct definition in the
/// package — both `key`-able Sui objects and plain value types.
///
/// `abilities` is set-semantics — Move's four abilities are
/// unordered. Persisted in the
/// [`crate::db::move_struct_ability`] relation table (one row per
/// `(struct_id, ability)`), so `load_package_structure` returns
/// abilities sorted by [`MoveAbility::canonical_order`] regardless
/// of insertion order. The writer dedupes on input.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoveStruct {
    /// Caller-assigned struct ID. Movy walks the package in a
    /// deterministic order so re-running produces the same IDs;
    /// `write_package_structure` honors them verbatim.
    pub id: i32,
    /// `contract.id` of the Move module that declares this struct.
    pub contract_id: i32,
    pub name: String,
    pub abilities: Vec<MoveAbility>,
    pub generic_params: Vec<MoveGenericParam>,
    pub fields: Vec<MoveField>,
}

impl MoveStruct {
    /// `key` ability ⇒ this struct is a Sui object. Audit prompts
    /// use this to know whether the struct can be transferred /
    /// shared / dynamic-field-attached.
    pub fn is_sui_object(&self) -> bool {
        self.abilities.contains(&MoveAbility::Key)
    }
}

/// One generic parameter on a struct or function declaration. The
/// `phantom` flag matters for type-compat reasoning even when the
/// parameter doesn't appear in runtime layout.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoveGenericParam {
    pub name: String,
    /// Required abilities for the type argument (e.g. `T: key+store`).
    pub constraints: Vec<MoveAbility>,
    pub phantom: bool,
}

/// One field of a struct. `type_repr` is the source-level type
/// string (e.g. `"vector<Coin<T>>"`) — audit prompts read it
/// verbatim; we don't try to parse it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoveField {
    pub name: String,
    pub type_repr: String,
}

/// Per-function metadata that doesn't fit in the language-neutral
/// `function` table.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoveFunctionMetadata {
    pub function_id: i32,
    pub visibility: MoveVisibility,
    pub is_entry: bool,
    pub generic_params: Vec<MoveGenericParam>,
}

/// Per-package Move structure: function metadata + struct
/// definitions. Written into the project DB as a single
/// transaction by
/// [`crate::RepoDatabase::write_package_structure`].
///
/// `function_metadata` references existing rows in the `function`
/// table. Movy's `export-repo-info` walks the package once and
/// writes the CG + this structure in the same invocation, so the
/// `function` rows the metadata references are always there. (FK
/// is also enforced at the SQL layer as a safety net.)
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MovePackageStructure {
    pub function_metadata: Vec<MoveFunctionMetadata>,
    pub structs: Vec<MoveStruct>,
}

impl MovePackageStructure {
    /// Index structs by their assigned ID for downstream consumers
    /// that join against [`ObjectFlowEdge::struct_id`].
    pub fn structs_by_id(&self) -> BTreeMap<i32, &MoveStruct> {
        self.structs.iter().map(|s| (s.id, s)).collect()
    }

    /// Group structs by the module they live in.
    pub fn structs_by_contract(&self) -> BTreeMap<i32, Vec<&MoveStruct>> {
        let mut out: BTreeMap<i32, Vec<&MoveStruct>> = BTreeMap::new();
        for s in &self.structs {
            out.entry(s.contract_id).or_default().push(s);
        }
        out
    }

    /// Index per-function metadata by `function_id` (the 1:1 key).
    pub fn function_metadata_by_id(&self) -> BTreeMap<i32, &MoveFunctionMetadata> {
        self.function_metadata
            .iter()
            .map(|m| (m.function_id, m))
            .collect()
    }
}
