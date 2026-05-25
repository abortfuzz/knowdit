use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};
use std::fmt;

/// What kind of forge invocation produced this run.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, EnumIter, DeriveActiveEnum, Serialize, Deserialize,
)]
#[sea_orm(rs_type = "String", db_type = "String(StringLen::N(16))")]
pub enum RunKind {
    /// `forge test --json -vvvvvv ...` — produces invariant pass/fail and trace.
    #[sea_orm(string_value = "Test")]
    Test,
    /// `forge coverage --report lcov ...` — produces coverage data.
    #[sea_orm(string_value = "Coverage")]
    Coverage,
}

impl RunKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Test => "Test",
            Self::Coverage => "Coverage",
        }
    }
}

impl fmt::Display for RunKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One concrete forge invocation that ran against a synthesized harness.
///
/// Both successful and failing invocations get a row — the agent uses
/// `stderr` (compile errors / human trace) as feedback. Only `Test` runs
/// can produce `violated == true`; coverage runs always set `violated = false`
/// and contribute to `line_coverage` rows via FK.
#[sea_orm::model]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, DeriveEntityModel)]
#[sea_orm(table_name = "harness_run")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i32,
    #[sea_orm(indexed)]
    pub code_id: i32,
    pub kind: RunKind,
    /// Optional fuzz seed forwarded with `--fuzz-seed`. None means
    /// forge picked its own.
    pub seed: Option<i64>,
    /// `--fuzz-runs <N>` actually passed to forge.
    pub runs: i64,
    /// JSON-serialized argument vector forge was invoked with (excluding
    /// the binary path itself), so we can reproduce the run later.
    #[sea_orm(column_type = "Text")]
    pub forge_args: String,
    /// Process exit code. -1 indicates we killed it on timeout.
    pub exit_code: i32,
    #[sea_orm(column_type = "Text")]
    pub stdout: String,
    #[sea_orm(column_type = "Text")]
    pub stderr: String,
    pub duration_ms: i64,
    /// True only for `Test` runs that observed an invariant failure.
    pub violated: bool,
    /// Counter-example call sequence parsed from forge `--json` output;
    /// JSON array of `{sender, addr, contract_name, signature, args}`
    /// entries. NULL when no violation or parse failed.
    #[sea_orm(column_type = "Text", nullable)]
    pub sequence_json: Option<String>,

    #[sea_orm(belongs_to, from = "code_id", to = "id")]
    pub code_gen: HasOne<super::code_gen::Entity>,
    #[sea_orm(has_many)]
    pub coverage: HasMany<super::line_coverage::Entity>,
}

impl ActiveModelBehavior for ActiveModel {}
