use color_eyre::eyre::Result;
use knowdit_kg::db::DatabaseGraph;

pub async fn run(db: &DatabaseGraph) -> Result<()> {
    tracing::info!("Database initialized successfully.");
    // init_db is already called before any command, so just log
    let _ = db; // suppress unused warning
    Ok(())
}
