use crate::cmd::db_snapshot_format::DbSnapshotFormat;
use clap::Args;
use color_eyre::eyre::Result;
use knowdit_kg::db::DatabaseGraph;
use std::path::PathBuf;

#[derive(Args, Debug)]
pub struct SnapshotDbArgs {
    /// Output path for the snapshot
    #[arg(short, long, default_value = "knowdit.snapshot.sql")]
    output: PathBuf,

    /// Snapshot format. If omitted, infer from the output suffix and default to SQL.
    #[arg(long, value_enum)]
    format: Option<DbSnapshotFormat>,
}

pub async fn run(db: &DatabaseGraph, args: SnapshotDbArgs) -> Result<()> {
    let format = DbSnapshotFormat::resolve_output_format(&args.output, args.format);
    let snapshot = match format {
        DbSnapshotFormat::Sql => db.export_sql_snapshot().await?,
        DbSnapshotFormat::Json => db.export_json_snapshot().await?,
    };
    std::fs::write(&args.output, snapshot)?;
    match format {
        DbSnapshotFormat::Sql => tracing::info!(
            "Database SQL snapshot exported to {}",
            args.output.display()
        ),
        DbSnapshotFormat::Json => tracing::info!(
            "KnowledgeGraph JSON snapshot exported to {}",
            args.output.display()
        ),
    }
    Ok(())
}
