use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

/// One spec-regeneration event. The new specification row is the `child`,
/// the spec that was rewritten is the `parent`. PK on `child_spec_id`
/// enforces a one-to-one chain (a given spec was regenerated from at most
/// one parent).
///
/// `triggered_by_reflection_id` is mandatory: every spec regen is driven
/// by a `reflection` row whose `result == IncompleteSpecification` (or by
/// a chain-depth escalation that itself wrote one).
///
/// FKs are intentionally not declared via `belongs_to`: SeaORM's
/// `#[sea_orm::model]` derive auto-generates one `Relation` variant per
/// target entity, and we have two FKs that both point at
/// [`super::specification::Entity`] (parent + child) — declaring both
/// would produce duplicate variant names. The repo layer joins
/// explicitly when needed.
#[sea_orm::model]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, DeriveEntityModel)]
#[sea_orm(table_name = "specification_regen")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub child_spec_id: i32,
    #[sea_orm(indexed)]
    pub parent_spec_id: i32,
    /// Free-text summary written by the regen scheduler — usually a
    /// condensation of `reflection.reason`, but may incorporate
    /// chain-depth escalation context.
    #[sea_orm(column_type = "Text")]
    pub reason: String,
    #[sea_orm(indexed)]
    pub triggered_by_reflection_id: i32,
}

impl ActiveModelBehavior for ActiveModel {}
