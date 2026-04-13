use sea_orm::entity::prelude::*;

#[sea_orm::model]
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize, DeriveEntityModel)]
#[sea_orm(table_name = "semantic_finding_link")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub semantic_node_id: i32,
    #[sea_orm(primary_key, auto_increment = false)]
    pub audit_finding_id: i32,

    #[sea_orm(belongs_to, from = "semantic_node_id", to = "id")]
    pub semantic_node: Option<super::semantic_node::Entity>,
    #[sea_orm(belongs_to, from = "audit_finding_id", to = "id")]
    pub audit_finding: Option<super::audit_finding::Entity>,
}

impl ActiveModelBehavior for ActiveModel {}
