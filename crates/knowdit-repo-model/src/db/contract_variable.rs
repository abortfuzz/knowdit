use sea_orm::entity::prelude::*;

// Note: no foreign-key constraint on `contract_id`. Solc occasionally marks `state_variable=true`
// on declarations that end up in libraries or interface-shaped definitions (which we store in
// `interface`); rather than filter those out, we leave referential integrity as a soft contract
// the consumer can join against `contract` or `interface` as needed.
#[sea_orm::model]
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize, DeriveEntityModel)]
#[sea_orm(table_name = "contract_variable")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i32,
    #[sea_orm(indexed)]
    pub contract_id: i32,
    pub state_variable_id: i32,
    #[sea_orm(column_type = "Text", nullable)]
    pub description: Option<String>,

    #[sea_orm(belongs_to, from = "state_variable_id", to = "id")]
    pub state_variable: HasOne<super::state_variable::Entity>,
}

impl ActiveModelBehavior for ActiveModel {}
