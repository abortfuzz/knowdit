use knowdit_kg_model::audit_finding::FindingSeverity;
use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

/// One row per `reflection` whose `result == ValidFinding`. Carries the
/// dedicated severity-grader-agent output (severity tier + the
/// agent's structured rationale for that tier). Co-written with the
/// `reflection` row in a single SQLite transaction
/// (`RepoDatabase::insert_reflection_with_finding`) — there is no
/// transient state where a `ValidFinding` reflection exists without
/// a matching `valid_finding`.
///
/// `reflection_id` is `UNIQUE` so a duplicated insert is caught by the
/// DB even under concurrent reflection runs.
#[sea_orm::model]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, DeriveEntityModel)]
#[sea_orm(table_name = "valid_finding")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i32,
    #[sea_orm(unique, indexed)]
    pub reflection_id: i32,
    pub severity: FindingSeverity,
    #[sea_orm(column_type = "Text")]
    pub severity_reason: String,

    #[sea_orm(belongs_to, from = "reflection_id", to = "id")]
    pub reflection: HasOne<super::reflection::Entity>,
}

impl ActiveModelBehavior for ActiveModel {}
