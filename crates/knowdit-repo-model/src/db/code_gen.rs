use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};
use std::fmt;

/// Final disposition of a fuzzing-harness synthesis attempt for one
/// [`super::specification`]. A row in `code_gen` is the *agent-level*
/// outcome; the actual `forge` invocations are recorded as
/// [`super::harness_run`] rows that reference this one via FK.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, EnumIter, DeriveActiveEnum, Serialize, Deserialize,
)]
#[sea_orm(rs_type = "String", db_type = "String(StringLen::N(32))")]
pub enum CodeGenStatus {
    /// Agent finalized successfully — at least one harness was written and
    /// at least one forge run completed (with or without violation).
    #[sea_orm(string_value = "Completed")]
    Completed,
    /// Agent finalized via `abandoned` after reading code (e.g. the spec
    /// references contracts/state that genuinely don't exist).
    #[sea_orm(string_value = "Abandoned")]
    Abandoned,
    /// Agent ran out of `--max-agent-steps` without finalizing.
    #[sea_orm(string_value = "StepsExhausted")]
    StepsExhausted,
    /// The agent itself failed (LLM error, internal panic, etc.).
    #[sea_orm(string_value = "AgentError")]
    AgentError,
}

impl CodeGenStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Completed => "Completed",
            Self::Abandoned => "Abandoned",
            Self::StepsExhausted => "StepsExhausted",
            Self::AgentError => "AgentError",
        }
    }

    /// Whether a successful resume should skip a spec with a row in this
    /// state. Only `Completed` counts as "done" — abandoned/error states
    /// retry on a future run.
    pub fn counts_as_resumable_skip(&self) -> bool {
        matches!(self, Self::Completed)
    }
}

impl fmt::Display for CodeGenStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One harness-synthesis attempt for a given [`super::specification`].
///
/// Stores the relative-to-repo-root path of the synthesized `.sol` file
/// (the source itself lives on disk and is also embedded for resilience),
/// plus the agent's final status / reason / step count. The forge runs
/// against this harness are linked via [`super::harness_run`].
#[sea_orm::model]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, DeriveEntityModel)]
#[sea_orm(table_name = "code_gen")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i32,
    #[sea_orm(indexed)]
    pub spec_id: i32,
    /// Path to the synthesized `.sol` file, relative to the repository root.
    /// Empty when the agent abandoned before writing any file.
    #[sea_orm(column_type = "Text")]
    pub harness_relative_path: String,
    /// Latest harness source the agent wrote (mirrors the file on disk;
    /// kept here for resilience if the working tree is recreated).
    #[sea_orm(column_type = "Text")]
    pub harness_source: String,
    pub status: CodeGenStatus,
    /// Agent-supplied explanation of the final status (always populated).
    #[sea_orm(column_type = "Text")]
    pub final_reason: String,
    /// How many agent steps were consumed before finalize.
    pub agent_steps: i32,

    #[sea_orm(belongs_to, from = "spec_id", to = "id")]
    pub specification: HasOne<super::specification::Entity>,
    #[sea_orm(has_many)]
    pub runs: HasMany<super::harness_run::Entity>,
}

impl ActiveModelBehavior for ActiveModel {}
