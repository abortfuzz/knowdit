use schemars::JsonSchema;
use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    EnumIter,
    DeriveActiveEnum,
    Serialize,
    Deserialize,
    JsonSchema,
)]
#[sea_orm(rs_type = "String", db_type = "String(StringLen::N(32))")]
pub enum VulnerabilityCategory {
    #[serde(rename = "Access Control")]
    #[sea_orm(string_value = "Access Control")]
    AccessControl,
    #[sea_orm(string_value = "Arithmetic")]
    Arithmetic,
    #[serde(rename = "Block Manipulation")]
    #[sea_orm(string_value = "Block Manipulation")]
    BlockManipulation,
    #[sea_orm(string_value = "Cryptographic")]
    Cryptographic,
    #[serde(rename = "Denial of Services")]
    #[sea_orm(string_value = "Denial of Services")]
    DenialOfServices,
    #[sea_orm(string_value = "Reentrancy")]
    Reentrancy,
    #[serde(rename = "Storage & Memory")]
    #[sea_orm(string_value = "Storage & Memory")]
    StorageAndMemory,
}

impl VulnerabilityCategory {
    pub const ALL: &[VulnerabilityCategory] = &[
        Self::AccessControl,
        Self::Arithmetic,
        Self::BlockManipulation,
        Self::Cryptographic,
        Self::DenialOfServices,
        Self::Reentrancy,
        Self::StorageAndMemory,
    ];

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::AccessControl => "Access Control",
            Self::Arithmetic => "Arithmetic",
            Self::BlockManipulation => "Block Manipulation",
            Self::Cryptographic => "Cryptographic",
            Self::DenialOfServices => "Denial of Services",
            Self::Reentrancy => "Reentrancy",
            Self::StorageAndMemory => "Storage & Memory",
        }
    }
}

impl fmt::Display for VulnerabilityCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}
