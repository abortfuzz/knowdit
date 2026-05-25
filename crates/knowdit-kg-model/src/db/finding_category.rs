use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

pub use crate::finding_category::VulnerabilityCategory;

#[sea_orm::model]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, DeriveEntityModel)]
#[sea_orm(table_name = "finding_category")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i32,
    pub category: VulnerabilityCategory,
    pub name: String,
    #[sea_orm(column_type = "Text")]
    pub description: String,
    #[sea_orm(has_many, via = "audit_finding_category")]
    pub audit_findings: HasMany<super::audit_finding::Entity>,
}

impl ActiveModelBehavior for ActiveModel {}
