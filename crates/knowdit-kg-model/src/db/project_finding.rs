//! Many-to-many between historical projects and audit findings.
//!
//! Replaces the old `audit_finding.project_id` column. A merged finding can
//! be the target of merges from multiple originating projects, so provenance
//! is recorded as a separate edge rather than a scalar on the finding row.
//!
//! `audit_finding_id` may reference either a canonical or merged-away finding;
//! consumers that need only canonical visibility resolve through
//! `finding_merge`.
use sea_orm::entity::prelude::*;

#[sea_orm::model]
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize, DeriveEntityModel)]
#[sea_orm(table_name = "project_finding")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub project_id: i32,
    #[sea_orm(primary_key, auto_increment = false)]
    pub audit_finding_id: i32,

    #[sea_orm(belongs_to, from = "project_id", to = "id")]
    pub project: Option<super::project::Entity>,
    #[sea_orm(belongs_to, from = "audit_finding_id", to = "id")]
    pub audit_finding: Option<super::audit_finding::Entity>,
}

impl ActiveModelBehavior for ActiveModel {}
