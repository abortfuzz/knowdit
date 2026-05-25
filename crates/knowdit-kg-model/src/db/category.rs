use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

pub use crate::category::DeFiCategory;

/// Global DeFi business type categories (Lending, DEX, Yield, etc.)
#[sea_orm::model]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, DeriveEntityModel)]
#[sea_orm(table_name = "category")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i32,
    #[sea_orm(unique)]
    pub name: DeFiCategory,

    #[sea_orm(has_many, via = "project_category")]
    pub projects: HasMany<super::project::Entity>,
}

impl ActiveModelBehavior for ActiveModel {}
