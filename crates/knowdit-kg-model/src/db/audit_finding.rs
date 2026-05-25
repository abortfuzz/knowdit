use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

pub use crate::audit_finding::FindingSeverity;

/// One audit-finding node.
///
/// A row here is one of:
/// - **Canonical**: no outgoing `finding_merge` edge points away from
///   `self.id`. Canonical findings are the targets the global-link path
///   writes against and the rows the mapper returns.
/// - **Raw / merged-away**: a row in `finding_merge` has
///   `from_finding_id = self.id`. The finding has been folded into another
///   canonical finding and is kept as historical provenance. Raw findings
///   may still carry `semantic_finding_link` rows from the in-project
///   linking step (run before merge collapses anything).
///
/// Project provenance is recorded in the `project_finding` join table —
/// a canonical merged finding may receive contributions from many
/// historical projects. There is intentionally no scalar `project_id`
/// column here.
#[sea_orm::model]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, DeriveEntityModel)]
#[sea_orm(table_name = "audit_finding")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i32,
    #[sea_orm(column_type = "Text")]
    pub title: String,
    pub severity: FindingSeverity,
    #[sea_orm(column_type = "Text")]
    pub root_cause: String,
    #[sea_orm(column_type = "Text")]
    pub description: String,
    #[sea_orm(column_type = "Text")]
    pub patterns: String,
    #[sea_orm(column_type = "Text")]
    pub exploits: String,

    #[sea_orm(has_many, via = "audit_finding_category")]
    pub finding_categories: HasMany<super::finding_category::Entity>,
    #[sea_orm(has_many, via = "semantic_finding_link")]
    pub semantic_nodes: HasMany<super::semantic_node::Entity>,
    #[sea_orm(has_many, via = "project_finding")]
    pub projects: HasMany<super::project::Entity>,
}

impl ActiveModelBehavior for ActiveModel {}
