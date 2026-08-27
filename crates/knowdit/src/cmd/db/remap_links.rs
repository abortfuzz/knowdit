//! `knowdit db remap-links` — one-time integrity sweep for the historical KG.
//!
//! Iterates every `semantic_merge` / `finding_merge` row and moves all
//! `semantic_finding_link` / `semantic_function` / `project_semantic` /
//! `project_finding` rows off the merge sources onto their canonicals, inside
//! ONE transaction. A post-loop assertion verifies zero rows still reference
//! a merge source; any violation aborts and the transaction rolls back.
//!
//! Safety guarantees:
//! - a SQL snapshot of the DB is written next to the DB file before the
//!   remap runs (skip with `--no-snapshot` at your own risk);
//! - the merge tables themselves are never touched — they stay as history;
//! - nothing is deleted: rows are MOVED (copied + source deleted), and
//!   collisions resolve by strongest-strength-wins.

use clap::Args;
use color_eyre::eyre::{Context, Result};
use knowdit_kg_model::db::operation_history::OperationType;
use std::path::PathBuf;

#[derive(Args, Debug, Clone)]
pub struct RemapLinksArgs {
    #[command(flatten)]
    pub database: crate::cli::HistoricalDatabaseArgs,

    /// Skip the automatic pre-remap SQL snapshot (NOT recommended — the
    /// snapshot is the rollback path if anything goes wrong).
    #[arg(long)]
    pub no_snapshot: bool,
}

#[derive(serde::Serialize)]
struct RemapLinksOperationArgs {
    snapshot_written: bool,
    snapshot_path: Option<String>,
}

impl RemapLinksArgs {
    pub async fn run(self) -> Result<()> {
        let db = self.database.connect().await?;

        // Pre-flight: refuse to remap on top of pre-existing corruption
        // (dangling FKs). Partial-link / pending-semantic warnings are
        // tolerated — this command must be runnable on a mid-learn DB.
        let validation = db.validate_db(false).await?;
        let corruption: Vec<String> = validation
            .remaining_issues
            .iter()
            .filter(|issue| {
                !matches!(
                    issue.table,
                    "finding_link_status" | "pending_semantic" | "merge_status"
                )
            })
            .map(|issue| issue.to_string())
            .collect();
        if !corruption.is_empty() {
            return Err(color_eyre::eyre::eyre!(
                "historical KG failed pre-flight integrity check ({} issue(s)); \
                 refusing to remap on top of corruption:\n{}",
                corruption.len(),
                corruption.join("\n")
            ));
        }

        // Automatic snapshot: the rollback path.
        let snapshot_path = if self.no_snapshot {
            None
        } else {
            let path = remap_snapshot_path(&self.database.database_url)?;
            let sql = db.export_sql_snapshot().await?;
            std::fs::write(&path, sql).wrap_err_with(|| {
                format!("failed to write pre-remap snapshot to {}", path.display())
            })?;
            tracing::info!("Pre-remap snapshot written to {}", path.display());
            Some(path)
        };

        let report = db.remap_all_merge_links().await?;

        tracing::info!(
            "Remap complete: {} semantic merge row(s) and {} finding merge row(s) processed",
            report.semantic_merges_processed,
            report.finding_merges_processed,
        );
        tracing::info!(
            "semantic side: {} link(s) moved, {} link(s) collided, {} function(s) moved, \
             {} function(s) deduplicated, {} provenance row(s) moved, {} secondary categor(y/ies) added",
            report.semantic.links_moved,
            report.semantic.links_collided,
            report.semantic.functions_moved,
            report.semantic.functions_skipped_dup,
            report.semantic.provenance_moved,
            report.semantic.secondary_categories_added,
        );
        tracing::info!(
            "finding side: {} link(s) moved, {} link(s) collided, {} provenance row(s) moved",
            report.finding.links_moved,
            report.finding.links_collided,
            report.finding.provenance_moved,
        );

        let operation_args = serde_json::to_value(RemapLinksOperationArgs {
            snapshot_written: snapshot_path.is_some(),
            snapshot_path: snapshot_path.map(|p| p.display().to_string()),
        })
        .wrap_err("failed to serialize remap args for operation history")?;
        db.record_operation(OperationType::RemapLinks, operation_args)
            .await?;

        tracing::info!("Remap-links operation recorded in operation_history.");
        Ok(())
    }
}

/// Snapshot path next to the SQLite DB file:
/// `<db-file>.remap-backup-<unix-epoch-seconds>.sql`.
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
    name.push_str(&format!(".remap-backup-{timestamp}.sql"));
    Ok(path.with_file_name(name))
}
