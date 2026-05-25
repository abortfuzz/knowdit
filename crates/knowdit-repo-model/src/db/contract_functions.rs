use sea_orm::entity::prelude::*;

#[sea_orm::model]
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize, DeriveEntityModel)]
#[sea_orm(table_name = "contract_functions")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i32,
    #[sea_orm(indexed)]
    pub contract_id: i32,
    #[sea_orm(indexed)]
    pub function_id: i32,

    #[sea_orm(belongs_to, from = "contract_id", to = "id")]
    pub contract: HasOne<super::contract::Entity>,
    #[sea_orm(belongs_to, from = "function_id", to = "id")]
    pub function: HasOne<super::function::Entity>,
}

impl ActiveModelBehavior for ActiveModel {}
