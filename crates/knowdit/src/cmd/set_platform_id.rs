use clap::Args;
use color_eyre::eyre::{Result, eyre};
use knowdit_kg::db::DatabaseGraph;

#[derive(Args)]
pub struct SetPlatformIdArgs {
    /// Project ID (numeric auto-increment ID)
    project_id: i32,

    /// Platform ID (e.g. "c4-420", "sherlock-123")
    platform_id: String,
}

pub async fn run(db: &DatabaseGraph, args: SetPlatformIdArgs) -> Result<()> {
    let project = db
        .get_project_by_id(args.project_id)
        .await?
        .ok_or_else(|| eyre!("Project with ID {} not found", args.project_id))?;

    db.set_platform_id(args.project_id, &args.platform_id)
        .await?;

    println!(
        "Set platform ID for project [{}] '{}': {}",
        project.id, project.name, args.platform_id
    );
    Ok(())
}
