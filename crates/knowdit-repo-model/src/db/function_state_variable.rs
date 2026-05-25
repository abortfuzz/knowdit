use sea_orm::entity::prelude::*;

// Note: no foreign-key constraint on `function_id`. The agent storage path can run standalone
// (without prior call-graph persistence), so the `function` table may not be populated when
// these rows are inserted. `state_variable_id` keeps its FK because the storage path always
// writes state_variable rows in the same transaction.
#[sea_orm::model]
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize, DeriveEntityModel)]
#[sea_orm(table_name = "function_state_variable")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i32,
    #[sea_orm(indexed)]
    pub function_id: i32,
    #[sea_orm(indexed)]
    pub state_variable_id: i32,
    pub is_write: bool,
    #[sea_orm(column_type = "Text", nullable)]
    pub description: Option<String>,

    #[sea_orm(belongs_to, from = "state_variable_id", to = "id")]
    pub state_variable: HasOne<super::state_variable::Entity>,
}

impl ActiveModelBehavior for ActiveModel {}
