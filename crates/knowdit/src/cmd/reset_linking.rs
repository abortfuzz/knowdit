use clap::Args;
use color_eyre::eyre::Result;
use knowdit_kg::db::DatabaseGraph;

#[derive(Args, Debug, Default)]
pub struct ResetLinkingArgs {}

pub async fn run(db: &DatabaseGraph, _args: ResetLinkingArgs) -> Result<()> {
    let (deleted_links, deleted_statuses) = db.clear_finding_link_progress().await?;
    tracing::info!(
        "Cleared {} semantic-finding link(s) and {} finding-link status row(s)",
        deleted_links,
        deleted_statuses
    );
    Ok(())
}
