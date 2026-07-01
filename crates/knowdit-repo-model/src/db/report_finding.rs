//! Canonical (deduplicated) audit finding — one row per cluster of raw
//! findings. Pure cluster IDENTITY: seeded once by the Merge agent from the
//! cluster's representative [`super::finding_review`] and never half-filled.
//!
//! There is no separate "writeup" stage and no nullable columns. The
//! client-facing report (impact / location / recommendation / PoC) is NOT
//! stored here — it is derived at export time from the cluster's chosen
//! representative member (its `finding_review` for the prose + its
//! `code_gen.harness_source` for the proof-of-concept). Cluster membership
//! lives in [`super::finding_merge`] edges.

use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

#[sea_orm::model]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, DeriveEntityModel)]
#[sea_orm(table_name = "report_finding")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i32,
    /// Canonical title — seeded from the representative member at merge
    /// time and identity-locked thereafter.
    #[sea_orm(column_type = "Text")]
    pub title: String,
    /// Reconciled severity = max [`super::finding_review::ReviewSeverity`]
    /// over the cluster members.
    #[sea_orm(indexed)]
    pub severity: super::finding_review::ReviewSeverity,
    /// Canonical root cause (identity-locked) — the Merge agent's cluster key.
    #[sea_orm(column_type = "Text")]
    pub root_cause: String,
    /// Normalized description the Merge agent compares against. The client
    /// report renders the chosen representative member's description, not
    /// this one.
    #[sea_orm(column_type = "Text")]
    pub description: String,
    /// Primary affected contract, seeded from the representative member.
    #[sea_orm(column_type = "Text")]
    pub primary_contract: String,
    /// Primary affected function, seeded from the representative member.
    #[sea_orm(column_type = "Text")]
    pub primary_function: String,
}

impl ActiveModelBehavior for ActiveModel {}
