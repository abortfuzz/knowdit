//! Per-chunk extraction progress marker so an interrupted learn / workflow
//! resumes from the last completed chunk instead of re extracting from scratch
//!
//! One row per (project_key, stage, chunk_idx). `chunk_json` stores the
//! serialised JSON array of extracted items for this chunk, so resume can
//! reload them without re running the LLM. Rows are INSERTed immediately
//! after each chunk's LLM call
//!
//! After the merge+write transaction commits, extraction_chunk rows are
//! deleted ; they were only needed to survive a crash during extraction
//!
//! Invalidation: `model` and `content_hash` are stored. On resume the first
//! chunk's row is checked against current values; a mismatch deletes all rows
//! for (project_key, stage) and restarts from zero

use sea_orm::entity::prelude::*;

#[sea_orm::model]
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize, DeriveEntityModel)]
#[sea_orm(table_name = "extraction_chunk")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i32,

    /// Stable project identifier (eg `c4-70`)
    pub project_key: String,

    /// Extraction stage: "categorize", "semantics", or "findings"
    pub stage: String,

    /// Zero-based chunk index within this stage
    pub chunk_idx: i32,

    /// LLM model id string at extraction time. Changing models invalidates.
    pub model: String,

    /// Content hash covering source text + prompt suffix.
    pub content_hash: String,

    /// The extracted items as a JSON array string. Deserialised on resume.
    pub chunk_json: String,
}

impl ActiveModelBehavior for ActiveModel {}
