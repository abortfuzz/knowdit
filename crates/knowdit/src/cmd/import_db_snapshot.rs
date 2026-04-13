use crate::cmd::db_snapshot_format::DbSnapshotFormat;
use clap::Args;
use color_eyre::eyre::Result;
use knowdit_kg::db::DatabaseGraph;
use std::path::PathBuf;

#[derive(Args, Debug)]
pub struct ImportDbSnapshotArgs {
    /// Input snapshot file to import
    #[arg(short, long)]
    input: PathBuf,

    /// Snapshot format. If omitted, infer from the input suffix.
    #[arg(long, value_enum)]
    format: Option<DbSnapshotFormat>,
}

pub async fn run(db: &DatabaseGraph, args: ImportDbSnapshotArgs) -> Result<()> {
    let format = DbSnapshotFormat::resolve_input_format(&args.input, args.format)?;
    let snapshot = std::fs::read_to_string(&args.input)?;
    let imported_count = match format {
        DbSnapshotFormat::Sql => db.import_sql_snapshot(&snapshot).await?,
        DbSnapshotFormat::Json => db.import_json_snapshot(&snapshot).await?,
    };
    match format {
        DbSnapshotFormat::Sql => tracing::info!(
            "Imported {} SQL statement(s) from {}",
            imported_count,
            args.input.display()
        ),
        DbSnapshotFormat::Json => tracing::info!(
            "Imported {} KnowledgeGraph row(s) from {}",
            imported_count,
            args.input.display()
        ),
    }
    Ok(())
}
