use sea_orm::entity::prelude::*;

#[sea_orm::model]
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize, DeriveEntityModel)]
#[sea_orm(table_name = "function_call")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i32,
    #[sea_orm(indexed)]
    pub lhs_id: i32,
    #[sea_orm(indexed)]
    pub rhs_id: i32,
    #[sea_orm(column_type = "Text", nullable)]
    pub description: Option<String>,

    #[sea_orm(belongs_to, from = "lhs_id", to = "id", relation_enum = "Lhs")]
    pub lhs: HasOne<super::function::Entity>,
    #[sea_orm(belongs_to, from = "rhs_id", to = "id", relation_enum = "Rhs")]
    pub rhs: HasOne<super::function::Entity>,
}

impl ActiveModelBehavior for ActiveModel {}
