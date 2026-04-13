use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, EnumIter, DeriveActiveEnum, Serialize, Deserialize,
)]
#[sea_orm(rs_type = "String", db_type = "String(StringLen::N(16))")]
pub enum FindingSeverity {
    #[sea_orm(string_value = "High")]
    High,
    #[sea_orm(string_value = "Medium")]
    Medium,
    #[sea_orm(string_value = "Low")]
    Low,
}

impl FindingSeverity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::High => "High",
            Self::Medium => "Medium",
            Self::Low => "Low",
        }
    }

    pub fn rank(&self) -> u8 {
        match self {
            Self::High => 3,
            Self::Medium => 2,
            Self::Low => 1,
        }
    }

    pub fn max(self, other: Self) -> Self {
        if self.rank() >= other.rank() {
            self
        } else {
            other
        }
    }
}

impl fmt::Display for FindingSeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[sea_orm::model]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, DeriveEntityModel)]
#[sea_orm(table_name = "audit_finding")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i32,
    #[sea_orm(column_type = "Text")]
    pub title: String,
    pub severity: FindingSeverity,
    #[sea_orm(column_type = "Text")]
    pub root_cause: String,
    #[sea_orm(column_type = "Text")]
    pub description: String,
    #[sea_orm(column_type = "Text")]
    pub patterns: String,
    #[sea_orm(column_type = "Text")]
    pub exploits: String,
    pub project_id: i32,

    #[sea_orm(belongs_to, from = "project_id", to = "id")]
    pub project: HasOne<super::project::Entity>,
    #[sea_orm(has_many, via = "audit_finding_category")]
    pub finding_categories: HasMany<super::finding_category::Entity>,
    #[sea_orm(has_many, via = "semantic_finding_link")]
    pub semantic_nodes: HasMany<super::semantic_node::Entity>,
}

impl ActiveModelBehavior for ActiveModel {}
