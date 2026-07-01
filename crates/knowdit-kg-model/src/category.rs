use schemars::JsonSchema;
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
    JsonSchema,
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

    /// Parse a category from its display name, tolerant of case and of
    /// space/underscore/hyphen separators (so `services`, `Real World Assets`,
    /// `real-world-assets`, `NFT_Marketplace` all resolve). Returns `None` for
    /// an unknown name.
    pub fn parse(s: &str) -> Option<Self> {
        let norm = |x: &str| {
            x.trim()
                .to_ascii_lowercase()
                .replace(['_', '-'], " ")
                .split_whitespace()
                .collect::<Vec<_>>()
                .join(" ")
        };
        let target = norm(s);
        Self::ALL
            .iter()
            .copied()
            .find(|c| norm(c.as_str()) == target)
    }
}

impl fmt::Display for DeFiCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod parse_tests {
    use super::DeFiCategory;

    #[test]
    fn parses_case_and_separator_insensitive() {
        assert_eq!(
            DeFiCategory::parse("Services"),
            Some(DeFiCategory::Services)
        );
        assert_eq!(
            DeFiCategory::parse("services"),
            Some(DeFiCategory::Services)
        );
        assert_eq!(
            DeFiCategory::parse("  SERVICES "),
            Some(DeFiCategory::Services)
        );
        assert_eq!(
            DeFiCategory::parse("real_world_assets"),
            Some(DeFiCategory::RealWorldAssets)
        );
        assert_eq!(
            DeFiCategory::parse("Real World Assets"),
            Some(DeFiCategory::RealWorldAssets)
        );
        assert_eq!(
            DeFiCategory::parse("nft-marketplace"),
            Some(DeFiCategory::NftMarketplace)
        );
    }

    #[test]
    fn rejects_unknown() {
        assert_eq!(DeFiCategory::parse("Sevices"), None);
        assert_eq!(DeFiCategory::parse(""), None);
    }
}
