use sea_orm::entity::prelude::*;

use super::category::DeFiCategory;

/// One node in the semantic graph.
///
/// A row here is one of:
/// - **Canonical**: no outgoing `semantic_merge` edge points away from
///   `self.id`. Canonical rows are the targets returned to LLM linkers and
///   the per-finding mapper, and are the only nodes that participate in
///   global-link writes to `semantic_finding_link`.
/// - **Raw / merged-away**: there is a row in `semantic_merge` with
///   `from_semantic_id = self.id`. The node has been folded into another
///   canonical node and is retained as historical provenance. Raw rows can
///   still hold `semantic_finding_link` rows produced by the in-project
///   linking step (which runs before merge collapses anything).
///
/// Project provenance is recorded in the `project_semantic` join table —
/// a canonical merged node can originate from many historical projects, so
/// the column-on-row form did not fit. There is intentionally no scalar
/// `project_id` here.
#[sea_orm::model]
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize, DeriveEntityModel)]
#[sea_orm(table_name = "semantic_node")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i32,
    /// Short canonical name, e.g. "Constant Product AMM Swap"
    #[sea_orm(column_type = "Text")]
    pub name: String,
    #[sea_orm(column_type = "Text")]
    pub definition: String,
    #[sea_orm(column_type = "Text")]
    pub description: String,
    /// The primary DeFi business category of this semantic.
    pub category: DeFiCategory,

    #[sea_orm(has_many)]
    pub functions: HasMany<super::semantic_function::Entity>,
    #[sea_orm(has_many, via = "semantic_finding_link")]
    pub findings: HasMany<super::audit_finding::Entity>,
    #[sea_orm(has_many, via = "project_semantic")]
    pub projects: HasMany<super::project::Entity>,
}

impl ActiveModelBehavior for ActiveModel {}
