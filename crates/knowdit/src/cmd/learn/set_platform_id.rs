use clap::Args;
use color_eyre::eyre::{Result, eyre};
use knowdit_kg::db::HistoricalDatabase;

#[derive(Args)]
pub struct SetPlatformIdArgs {
    /// Project ID (numeric auto-increment ID)
    pub project_id: i32,

    /// Platform ID (e.g. "c4-420", "sherlock-123")
    pub platform_id: String,
}

impl SetPlatformIdArgs {
    pub async fn run(self, db: &HistoricalDatabase) -> Result<()> {
        let project = db
            .get_project_by_id(self.project_id)
            .await?
            .ok_or_else(|| eyre!("Project with ID {} not found", self.project_id))?;

        db.set_platform_id(self.project_id, &self.platform_id)
            .await?;

        println!(
            "Set platform ID for project [{}] '{}': {}",
            project.id, project.name, self.platform_id
        );
        Ok(())
    }
}
