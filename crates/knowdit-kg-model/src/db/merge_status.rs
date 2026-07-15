//! Progress marker for `merge-kg` (merging another KG into this one), so an
//! interrupted merge resumes on re-run instead of re-importing (duplicating).
//!
//! One row per merge invocation (multiple sources / re-merges → multiple
//! rows). A row is created inside the same transaction as the import, so
//! "import committed ⟺ a row exists". [`MergePhase`] advances as each stage
//! completes; a resume picks up the latest row whose phase is not yet
//! [`MergePhase::Link`] and runs only its unfinished stages.
use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};
use std::fmt;

/// Stage cursor for one merge. Ordered `Imported < Retro < Link`, so a resume
/// can gate each stage with a simple comparison (`phase < Retro` ⇒ retro-link
/// still owed). Stored as its lowercase string value.
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
#[sea_orm(rs_type = "String", db_type = "String(StringLen::N(16))")]
pub enum MergePhase {
    /// The global merge + import transaction committed.
    #[sea_orm(string_value = "imported")]
    Imported,
    /// The ③a retro-link pass finished.
    #[sea_orm(string_value = "retro")]
    Retro,
    /// The ③b link pass finished — merge fully complete.
    #[sea_orm(string_value = "link")]
    Link,
}

impl MergePhase {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Imported => "imported",
            Self::Retro => "retro",
            Self::Link => "link",
        }
    }
}

impl fmt::Display for MergePhase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[sea_orm::model]
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize, DeriveEntityModel)]
#[sea_orm(table_name = "merge_status")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i32,

    /// Caller-provided stable label for the source KG (the `--source-key`
    /// flag). Not the connection string — that can carry credentials.
    pub source_key: String,

    /// `max(semantic_node.id)` in the destination captured just before this
    /// merge's import (`None` if the destination held no semantics yet).
    /// Persisted so the ③b `Residual` candidate scope (`id <= ceiling` =
    /// destination-native) stays correct across a resume, where recomputing it
    /// would include already-imported source semantics.
    pub native_sem_ceiling: Option<i32>,

    /// The last completed stage — see [`MergePhase`].
    pub phase: MergePhase,
}

impl ActiveModelBehavior for ActiveModel {}
