//! `knowdit learn reclassify-others` — one-shot LLM maintenance pass.
//!
//! Re-classifies every canonical semantic node parked in the `Others`
//! catch-all into a real DeFi category (including the newer `Tokens` /
//! `Governance` / `Custody` / `Privacy` buckets). Dry-run by default:
//! prints the decisions without writing. `--apply` auto-snapshots the DB,
//! writes all decisions in ONE transaction, and records the operation in
//! `operation_history`.

use clap::Args;
use color_eyre::eyre::{Context, Result};
use knowdit_kg::db::HistoricalDatabase;
use knowdit_kg::learn;
use knowdit_kg_model::category::DeFiCategory;
use knowdit_kg_model::db::operation_history::OperationType;
use llmy::clap::OpenAISetup;
use std::path::PathBuf;

#[derive(Args, Debug, Clone)]
pub struct ReclassifyOthersArgs {
    #[command(flatten)]
    pub llm: OpenAISetup,

    /// Maximum nodes per LLM batch.
    #[arg(long, default_value_t = 20)]
    pub batch_size: usize,

    /// Write the decisions into the KG. Without this flag the run only
    /// prints what it WOULD change.
    #[arg(long)]
    pub apply: bool,

    /// Skip the automatic pre-apply SQL snapshot (NOT recommended).
    #[arg(long)]
    pub no_snapshot: bool,

    /// Fraction (0,1] of the model's context window a single reclassify
    /// prompt may fill.
    #[arg(long, default_value_t = knowdit_kg::learn::DEFAULT_CONTEXT_WINDOW_UTILIZATION)]
    pub context_window_utilization: f64,
}

#[derive(serde::Serialize)]
struct ReclassifyOperationArgs {
    batch_size: usize,
    applied: bool,
    updated: usize,
    snapshot_path: Option<String>,
}

impl ReclassifyOthersArgs {
    /// CLI entry: the enclosing `LearnCommand` passes the connected DB and
    /// its URL (for the auto-snapshot path) in.
    pub async fn run(self, db: &HistoricalDatabase, database_url: &str) -> Result<()> {
        let llm = self.llm.clone().to_llm().await;
        let decisions =
            learn::reclassify_others(db, &llm, self.batch_size, self.context_window_utilization)
                .await
                .wrap_err("reclassify-others LLM pass failed")?;

        if decisions.is_empty() {
            tracing::info!("No decisions produced; nothing to apply.");
            return Ok(());
        }

        // Dry-run table: id | old | new | name.
        let nodes_by_id = db
            .canonical_semantics_in_category(DeFiCategory::Others)
            .await?;
        let name_by_id: std::collections::HashMap<i32, String> =
            nodes_by_id.into_iter().map(|n| (n.id, n.name)).collect();
        tracing::info!(
            "Reclassification decisions for {} node(s) (mode: {})",
            decisions.len(),
            if self.apply { "apply" } else { "dry-run" },
        );
        for decision in &decisions {
            let name = name_by_id
                .get(&decision.semantic_id)
                .map(String::as_str)
                .unwrap_or("<unknown>");
            tracing::info!(
                "sem-{} | {} -> {} | {}",
                decision.semantic_id,
                "Others",
                decision.category,
                name,
            );
        }

        if !self.apply {
            tracing::info!(
                "Dry-run complete — {} decision(s) NOT written. Re-run with --apply to commit.",
                decisions.len(),
            );
            return Ok(());
        }

        let snapshot_path = if self.no_snapshot {
            None
        } else {
            let path = remap_snapshot_path(database_url)?;
            let sql = db.export_sql_snapshot().await?;
            std::fs::write(&path, sql).wrap_err_with(|| {
                format!("failed to write pre-apply snapshot to {}", path.display())
            })?;
            tracing::info!("Pre-apply snapshot written to {}", path.display());
            Some(path)
        };

        let pairs: Vec<(i32, DeFiCategory)> = decisions
            .iter()
            .filter_map(|d| DeFiCategory::parse(&d.category).map(|cat| (d.semantic_id, cat)))
            .collect();
        let updated = db.reclassify_semantic_categories(&pairs).await?;
        tracing::info!("Reclassification applied: {updated} node(s) updated.");

        let operation_args = serde_json::to_value(ReclassifyOperationArgs {
            batch_size: self.batch_size,
            applied: true,
            updated,
            snapshot_path: snapshot_path.map(|p| p.display().to_string()),
        })
        .wrap_err("failed to serialize reclassify args for operation history")?;
        db.record_operation(OperationType::ReclassifyOthers, operation_args)
            .await?;

        tracing::info!(
            "Run `knowdit db remap-links` afterwards to carry any secondary categories triggered by the reclassification (idempotent)."
        );
        Ok(())
    }
}

/// Snapshot path next to the SQLite DB file:
/// `<db-file>.reclassify-backup-<unix-epoch-seconds>.sql`.
fn remap_snapshot_path(database_url: &str) -> Result<PathBuf> {
    let file = database_url
        .strip_prefix("sqlite://")
        .or_else(|| database_url.strip_prefix("sqlite:"))
        .ok_or_else(|| {
            color_eyre::eyre::eyre!(
                "cannot derive a snapshot path from non-SQLite URL '{}' — \
                 pass --no-snapshot and back up the database yourself",
                database_url
            )
        })?;
    let file = file.split('?').next().unwrap_or(file);
    let path = PathBuf::from(file);
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let mut name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "kg.db".to_string());
    name.push_str(&format!(".reclassify-backup-{timestamp}.sql"));
    Ok(path.with_file_name(name))
}
