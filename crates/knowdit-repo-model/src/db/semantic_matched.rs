//! Edge connecting one extracted project semantic (`project_semantic`) to a
//! historical semantic (`historical_semantic`) that the Knowledge Mapper
//! decided is a fuzzy behavioural match. Each matched pair becomes one row.
//!
//! v2 mapper additions:
//!   - `strength`: project-relevance label (High/Medium/Low). Drives
//!     downstream filtering in spec-gen and regen retry budget.
//!   - `evidence`: short rationale emitted by mapper along with the
//!     strength label.
//!   - DB-level UNIQUE on `(extract_id, historical_id)` so re-emission
//!     of the same pair is rejected by the DB rather than the
//!     application layer. The unique index is created manually in
//!     `RepoDatabase::init_schema` because SeaORM's derive doesn't
//!     express compound unique indexes cleanly.
use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};
use std::fmt;

/// Mapper-emitted strength label per `(extract, historical)` pair.
///
/// Encodes how relevant the historical semantic is to *this* project,
/// judged on the historical semantic's `definition`/`description`
/// versus the project's profile + extracted semantics. The rubric itself
/// lives in the mapper's system prompt (`knowdit-audit/src/mapper.rs`).
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, EnumIter, DeriveActiveEnum, Serialize, Deserialize,
)]
#[sea_orm(rs_type = "String", db_type = "String(StringLen::N(16))")]
pub enum MatchStrength {
    #[sea_orm(string_value = "High")]
    High,
    #[sea_orm(string_value = "Medium")]
    Medium,
    #[sea_orm(string_value = "Low")]
    Low,
}

impl MatchStrength {
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
    pub fn at_least(&self, minimum: MatchStrength) -> bool {
        self.rank() >= minimum.rank()
    }

    /// Parse from the literal strings the mapper agent emits in tool
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

impl fmt::Display for MatchStrength {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[sea_orm::model]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, DeriveEntityModel)]
#[sea_orm(table_name = "semantic_matched")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i32,
    /// References `project_semantic.id`.
    #[sea_orm(indexed)]
    pub extract_id: i32,
    /// References `historical_semantic.id`.
    #[sea_orm(indexed)]
    pub historical_id: i32,
    /// Mapper-emitted project-relevance label.
    #[sea_orm(indexed)]
    pub strength: MatchStrength,
    /// Short rationale (>= 40 chars per mapper handler validation).
    #[sea_orm(column_type = "Text")]
    pub evidence: String,

    #[sea_orm(belongs_to, from = "extract_id", to = "id")]
    pub extract: Option<super::project_semantic::Entity>,
    #[sea_orm(belongs_to, from = "historical_id", to = "id")]
    pub historical: Option<super::historical_semantic::Entity>,
}

impl ActiveModelBehavior for ActiveModel {}
