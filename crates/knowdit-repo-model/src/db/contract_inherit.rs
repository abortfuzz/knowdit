use sea_orm::entity::prelude::*;

// Note: no foreign-key constraints. `contract_id` and `inherited_id` may refer to either a
// `contract` or an `interface` row (Solidity contracts inherit from both); the consumer joins
// against the appropriate table.
#[sea_orm::model]
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize, DeriveEntityModel)]
#[sea_orm(table_name = "contract_inherit")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub contract_id: i32,
    #[sea_orm(primary_key, auto_increment = false, indexed)]
    pub inherited_id: i32,
}

impl ActiveModelBehavior for ActiveModel {}
