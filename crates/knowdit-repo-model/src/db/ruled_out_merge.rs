//! Merge edge: one row per rejection that has been folded into a ruled-out
//! conclusion.
//!
//! Unlike [`super::finding_merge`] there is no separate canonical table — the
//! conclusion text (`reflection.ruled_out_claim`) already lives on the
//! rejection itself, so the cluster's representative row IS the canonical and
//! the edge is self-referential. The deduplicated conclusion set is therefore
//! `SELECT DISTINCT to_reflection_id`, and the first rejection to establish a
//! conclusion points at itself.
//!
//! `from_reflection_id` is UNIQUE — a rejection belongs to exactly one
//! conclusion. That constraint doubles as the incremental drain cursor: the
//! pending queue is "closed-direction verdicts carrying a claim that have no
//! row here yet". Both columns are indexed so the edge walks both ways.

use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

#[sea_orm::model]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, DeriveEntityModel)]
#[sea_orm(table_name = "ruled_out_merge")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i32,
    /// The rejection being placed. UNIQUE: it joins exactly one conclusion.
    #[sea_orm(unique, indexed)]
    pub from_reflection_id: i32,
    /// The representative rejection whose `ruled_out_claim` is this cluster's
    /// canonical wording. Equals `from_reflection_id` for the rejection that
    /// established the conclusion.
    #[sea_orm(indexed)]
    pub to_reflection_id: i32,

    #[sea_orm(belongs_to, from = "from_reflection_id", to = "id")]
    pub reflection: HasOne<super::reflection::Entity>,
}

impl ActiveModelBehavior for ActiveModel {}
