use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

/// One codegen-regeneration event. The new code_gen row is the `child`,
/// the previous attempt is the `parent`. PK on `child_code_gen_id`
/// enforces a one-to-one chain (each code_gen has at most one parent).
///
/// May be cross-spec: when a spec regen produces a new code_gen on the
/// new spec, this row records `parent_code_gen_id` of the prior code_gen
/// (which lived under the old spec) so the reflection-driven feedback
/// chain stays unbroken.
///
/// `triggered_by_reflection_id` is mandatory: every codegen regen is
/// driven by a `reflection` row (Gate 1/2 → `Suspect`, Gate 3 →
/// `IncompleteStep` / `IncompleteSpecification`).
///
/// FKs intentionally not declared via `belongs_to` — see the same note
/// on [`super::specification_regen`].
#[sea_orm::model]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, DeriveEntityModel)]
#[sea_orm(table_name = "code_gen_regen")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub child_code_gen_id: i32,
    #[sea_orm(indexed)]
    pub parent_code_gen_id: i32,
    #[sea_orm(column_type = "Text")]
    pub reason: String,
    #[sea_orm(indexed)]
    pub triggered_by_reflection_id: i32,
}

impl ActiveModelBehavior for ActiveModel {}
