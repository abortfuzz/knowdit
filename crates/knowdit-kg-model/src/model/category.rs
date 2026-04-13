use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};
use std::fmt;

/// Concrete DeFi category enum shared by extraction logic and SeaORM models.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    EnumIter,
    DeriveActiveEnum,
    Serialize,
    Deserialize,
)]
#[sea_orm(rs_type = "String", db_type = "String(StringLen::N(32))")]
pub enum DeFiCategory {
    #[sea_orm(string_value = "Lending")]
    Lending,
    #[sea_orm(string_value = "Dexes")]
    Dexes,
    #[sea_orm(string_value = "Yield")]
    Yield,
    #[sea_orm(string_value = "Services")]
    Services,
    #[sea_orm(string_value = "Derivatives")]
    Derivatives,
    #[serde(rename = "Yield Aggregator")]
    #[sea_orm(string_value = "Yield Aggregator")]
    YieldAggregator,
    #[serde(rename = "Real World Assets")]
    #[sea_orm(string_value = "Real World Assets")]
    RealWorldAssets,
    #[sea_orm(string_value = "Stablecoins")]
    Stablecoins,
    #[sea_orm(string_value = "Indexes")]
    Indexes,
    #[sea_orm(string_value = "Insurance")]
    Insurance,
    #[serde(rename = "NFT Marketplace")]
    #[sea_orm(string_value = "NFT Marketplace")]
    NftMarketplace,
    #[serde(rename = "NFT Lending")]
    #[sea_orm(string_value = "NFT Lending")]
    NftLending,
    #[serde(rename = "Cross Chain")]
    #[sea_orm(string_value = "Cross Chain")]
    CrossChain,
    #[sea_orm(string_value = "Others")]
    Others,
}

impl DeFiCategory {
    pub const ALL: &[DeFiCategory] = &[
        Self::Lending,
        Self::Dexes,
        Self::Yield,
        Self::Services,
        Self::Derivatives,
        Self::YieldAggregator,
        Self::RealWorldAssets,
        Self::Stablecoins,
        Self::Indexes,
        Self::Insurance,
        Self::NftMarketplace,
        Self::NftLending,
        Self::CrossChain,
        Self::Others,
    ];

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Lending => "Lending",
            Self::Dexes => "Dexes",
            Self::Yield => "Yield",
            Self::Services => "Services",
            Self::Derivatives => "Derivatives",
            Self::YieldAggregator => "Yield Aggregator",
            Self::RealWorldAssets => "Real World Assets",
            Self::Stablecoins => "Stablecoins",
            Self::Indexes => "Indexes",
            Self::Insurance => "Insurance",
            Self::NftMarketplace => "NFT Marketplace",
            Self::NftLending => "NFT Lending",
            Self::CrossChain => "Cross Chain",
            Self::Others => "Others",
        }
    }
}

impl fmt::Display for DeFiCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

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
