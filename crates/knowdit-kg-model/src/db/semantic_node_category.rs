use sea_orm::entity::prelude::*;

#[sea_orm::model]
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "semantic_node_category")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub semantic_node_id: i32,
    #[sea_orm(primary_key, auto_increment = false)]
    pub category_id: i32,

    #[sea_orm(belongs_to, from = "semantic_node_id", to = "id")]
    pub semantic_node: Option<super::semantic_node::Entity>,
    #[sea_orm(belongs_to, from = "category_id", to = "id")]
    pub category: Option<super::category::Entity>,
}

impl ActiveModelBehavior for ActiveModel {}
