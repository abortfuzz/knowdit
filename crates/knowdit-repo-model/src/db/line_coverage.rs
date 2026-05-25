use sea_orm::entity::prelude::*;

/// One source line that the fuzzer marked as covered, scoped to a single
/// [`super::harness_run`] (`run_id`) — the coverage layer joins many
/// rows back to the run and the spec.
#[sea_orm::model]
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize, DeriveEntityModel)]
#[sea_orm(table_name = "line_coverage")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i32,
    #[sea_orm(indexed)]
    pub run_id: i32,
    #[sea_orm(column_type = "Text", indexed)]
    pub relative_contract_path: String,
    #[sea_orm(indexed)]
    pub line_number: i32,
    /// Total hits the fuzzer recorded for this line (lcov `DA:line,hits`).
    pub hit_count: i64,

    #[sea_orm(belongs_to, from = "run_id", to = "id")]
    pub run: HasOne<super::harness_run::Entity>,
}

impl ActiveModelBehavior for ActiveModel {}
