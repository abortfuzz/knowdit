use sea_orm::entity::prelude::*;

#[sea_orm::model]
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize, DeriveEntityModel)]
#[sea_orm(table_name = "audit_finding_category")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub audit_finding_id: i32,
    #[sea_orm(primary_key, auto_increment = false)]
    pub finding_category_id: i32,

    #[sea_orm(belongs_to, from = "audit_finding_id", to = "id")]
    pub audit_finding: Option<super::audit_finding::Entity>,
    #[sea_orm(belongs_to, from = "finding_category_id", to = "id")]
    pub finding_category: Option<super::finding_category::Entity>,
}

impl ActiveModelBehavior for ActiveModel {}
