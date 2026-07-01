//! Merge edge: one row per raw finding that has been folded into a
//! canonical [`super::report_finding`].
//!
//! `from_reflection_id` is UNIQUE — a raw finding belongs to exactly one
//! canonical. Both columns are indexed so the edge walks both ways:
//! raw → canonical (Merge agent's idempotent "already merged?" check) and
//! canonical → raws (Writer / provenance lookup). The presence of an edge
//! is the SOLE "this raw finding is merged" signal; there is deliberately
//! no boolean flag on [`super::finding_review`].

use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

#[sea_orm::model]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, DeriveEntityModel)]
#[sea_orm(table_name = "finding_merge")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i32,
    /// The raw finding's `finding_review.reflection_id`. UNIQUE: a raw
    /// finding maps to exactly one canonical.
    #[sea_orm(unique, indexed)]
    pub from_reflection_id: i32,
    /// The canonical `report_finding.id` this raw finding was folded into.
    #[sea_orm(indexed)]
    pub to_report_finding_id: i32,

    #[sea_orm(belongs_to, from = "from_reflection_id", to = "reflection_id")]
    pub finding_review: HasOne<super::finding_review::Entity>,
    #[sea_orm(belongs_to, from = "to_report_finding_id", to = "id")]
    pub report_finding: HasOne<super::report_finding::Entity>,
}

impl ActiveModelBehavior for ActiveModel {}
