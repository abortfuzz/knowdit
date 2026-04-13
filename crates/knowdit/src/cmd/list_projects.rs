use color_eyre::eyre::Result;
use knowdit_kg::db::DatabaseGraph;

pub async fn run(db: &DatabaseGraph) -> Result<()> {
    let projects = db.list_completed_projects().await?;
    if projects.is_empty() {
        println!("No completed projects.");
    } else {
        println!("Completed projects:");
        println!("{}", "=".repeat(60));
        for (p, pp) in &projects {
            let platform_str = pp.as_ref().map(|pp| pp.platform_id.as_str()).unwrap_or("-");
            println!("  [{}] {} (platform_id: {})", p.id, p.name, platform_str);
        }
        println!("\nTotal: {} projects", projects.len());
    }
    Ok(())
}
