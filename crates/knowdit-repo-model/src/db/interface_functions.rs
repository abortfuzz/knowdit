use sea_orm::entity::prelude::*;

#[sea_orm::model]
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize, DeriveEntityModel)]
#[sea_orm(table_name = "interface_functions")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i32,
    #[sea_orm(indexed)]
    pub interface_id: i32,
    #[sea_orm(indexed)]
    pub function_id: i32,

    #[sea_orm(belongs_to, from = "interface_id", to = "id")]
    pub interface: HasOne<super::interface::Entity>,
    #[sea_orm(belongs_to, from = "function_id", to = "id")]
    pub function: HasOne<super::function::Entity>,
}

impl ActiveModelBehavior for ActiveModel {}
