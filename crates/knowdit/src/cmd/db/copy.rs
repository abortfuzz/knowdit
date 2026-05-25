//! `knowdit db copy` — direct historical-KG database copy that
//! bypasses the SQL-snapshot round-trip.
//!
//! Default mode merges src rows into dst's existing schema:
//! auto-increment IDs are reassigned on insert and every FK is
//! rewritten through an in-memory id map so the dst's existing
//! rows are preserved and the FK constraints stay intact. Pass
//! `--fresh` to instead drop and recreate dst's schema before
//! the copy (source IDs are then preserved 1:1).

use clap::Args;
use color_eyre::eyre::{Result, WrapErr};
use knowdit_kg::db::HistoricalDatabase;

#[derive(Args, Debug, Clone)]
pub struct CopyArgs {
    /// Source database URL (sqlite://, mysql://, postgres://).
    #[arg(short, long = "src-db")]
    pub src_db: String,

    /// Destination database URL. Schema is created automatically if
    /// missing; existing rows are preserved (and FKs renumbered)
    /// unless `--fresh` is passed.
    #[arg(short, long = "dst-db")]
    pub dst_db: String,

    /// Drop the destination's existing schema and recreate it empty
    /// before copying. Source IDs are then preserved 1:1. Without
    /// this flag, src rows are appended on top of dst and every
    /// auto-increment PK is reassigned (FKs rewritten accordingly).
    #[arg(short, long)]
    pub fresh: bool,
}

impl CopyArgs {
    pub async fn run(self) -> Result<()> {
        let src = HistoricalDatabase::connect(&self.src_db)
            .await
            .wrap_err_with(|| format!("failed to connect to source DB at {}", self.src_db))?;
        let dst = HistoricalDatabase::connect(&self.dst_db)
            .await
            .wrap_err_with(|| format!("failed to connect to destination DB at {}", self.dst_db))?;
        let copied = if self.fresh {
            src.clobber_into(&dst).await?
        } else {
            dst.init().await?;
            src.merge_into(&dst).await?
        };
        tracing::info!(
            "Copied {} row(s) from {} into {} (mode: {})",
            copied,
            self.src_db,
            self.dst_db,
            if self.fresh { "fresh" } else { "merge" }
        );
        Ok(())
    }
}
