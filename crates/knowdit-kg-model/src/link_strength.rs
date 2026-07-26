//! Strength tier emitted by the KG link agent for one
//! `(semantic_node, audit_finding)` edge. Independent of mapper's
//! `MatchStrength` (which lives in `knowdit-repo-model`): the two are
//! scored by different agents with different rubrics and evolve
//! independently. The enum shape happens to match for now; keeping
//! them as separate types so a future divergence is a type-level
//! signal rather than a silent semantic shift.
//!
//! The rubric the linker applies lives in the linker's own system prompt
//! (`knowdit-kg/src/prompts.rs`); this enum is only its storage form.

use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, EnumIter, DeriveActiveEnum, Serialize, Deserialize,
)]
#[sea_orm(rs_type = "String", db_type = "String(StringLen::N(16))")]
pub enum LinkStrength {
    #[sea_orm(string_value = "High")]
    High,
    #[sea_orm(string_value = "Medium")]
    Medium,
    #[sea_orm(string_value = "Low")]
    Low,
}

impl LinkStrength {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::High => "High",
            Self::Medium => "Medium",
            Self::Low => "Low",
        }
    }

    /// Stable rank (High > Medium > Low). Used to filter and sort
    /// matches in downstream consumers.
    pub fn rank(&self) -> u8 {
        match self {
            Self::High => 3,
            Self::Medium => 2,
            Self::Low => 1,
        }
    }

    /// True if `self` meets the minimum required strength tier.
    pub fn at_least(&self, minimum: LinkStrength) -> bool {
        self.rank() >= minimum.rank()
    }

    /// Parse from the literal strings the link agent emits in tool
    /// arguments. Case-insensitive.
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "high" => Some(Self::High),
            "medium" | "med" => Some(Self::Medium),
            "low" => Some(Self::Low),
            _ => None,
        }
    }
}

impl fmt::Display for LinkStrength {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}
