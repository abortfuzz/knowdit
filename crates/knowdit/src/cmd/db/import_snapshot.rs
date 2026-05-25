use crate::cli::HistoricalDatabaseArgs;
use crate::cmd::db::snapshot_format::DbSnapshotFormat;
use clap::Args;
use color_eyre::eyre::Result;
use std::path::PathBuf;

#[derive(Args, Debug)]
pub struct ImportSnapshotArgs {
    #[command(flatten)]
    pub database: HistoricalDatabaseArgs,

    /// Input snapshot file to import
    #[arg(short, long)]
    pub input: PathBuf,

    /// Snapshot format. If omitted, infer from the input suffix.
    #[arg(long, value_enum)]
    pub format: Option<DbSnapshotFormat>,
}

impl ImportSnapshotArgs {
    pub async fn run(self) -> Result<()> {
        let db = self.database.connect().await?;
        let format = DbSnapshotFormat::resolve_input_format(&self.input, self.format)?;
        let snapshot = std::fs::read_to_string(&self.input)?;
        let imported_count = match format {
            DbSnapshotFormat::Sql => db.import_sql_snapshot(&snapshot).await?,
            DbSnapshotFormat::Json => db.import_json_snapshot(&snapshot).await?,
        };
        match format {
            DbSnapshotFormat::Sql => tracing::info!(
                "Imported {} SQL statement(s) from {}",
                imported_count,
                self.input.display()
            ),
            DbSnapshotFormat::Json => tracing::info!(
                "Imported {} KnowledgeGraph row(s) from {}",
                imported_count,
                self.input.display()
            ),
        }
        Ok(())
    }
}
