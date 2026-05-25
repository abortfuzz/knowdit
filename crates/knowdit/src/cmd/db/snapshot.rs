use crate::cli::HistoricalDatabaseArgs;
use crate::cmd::db::snapshot_format::DbSnapshotFormat;
use clap::Args;
use color_eyre::eyre::Result;
use std::path::PathBuf;

#[derive(Args, Debug)]
pub struct SnapshotArgs {
    #[command(flatten)]
    pub database: HistoricalDatabaseArgs,

    /// Output path for the snapshot
    #[arg(short, long, default_value = "knowdit.snapshot.sql")]
    pub output: PathBuf,

    /// Snapshot format. If omitted, infer from the output suffix and default to SQL.
    #[arg(long, value_enum)]
    pub format: Option<DbSnapshotFormat>,
}

impl SnapshotArgs {
    pub async fn run(self) -> Result<()> {
        let db = self.database.connect().await?;
        let format = DbSnapshotFormat::resolve_output_format(&self.output, self.format);
        let snapshot = match format {
            DbSnapshotFormat::Sql => db.export_sql_snapshot().await?,
            DbSnapshotFormat::Json => db.export_json_snapshot().await?,
        };
        std::fs::write(&self.output, snapshot)?;
        match format {
            DbSnapshotFormat::Sql => tracing::info!(
                "Database SQL snapshot exported to {}",
                self.output.display()
            ),
            DbSnapshotFormat::Json => tracing::info!(
                "KnowledgeGraph JSON snapshot exported to {}",
                self.output.display()
            ),
        }
        Ok(())
    }
}
