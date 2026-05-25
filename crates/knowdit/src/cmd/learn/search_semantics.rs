use clap::Args;
use color_eyre::eyre::Result;
use knowdit_kg::db::HistoricalDatabase;

#[derive(Args)]
pub struct SearchSemanticsArgs {
    /// Search query keyword
    pub query: String,
}

impl SearchSemanticsArgs {
    pub async fn run(self, db: &HistoricalDatabase) -> Result<()> {
        let results = db.search_semantics(&self.query).await?;
        if results.is_empty() {
            println!("No semantics found matching '{}'", self.query);
        } else {
            println!("Search results for '{}':", self.query);
            println!("{}", "=".repeat(60));
            for (node, proj_name) in &results {
                println!("\n[{}] {} (from: {})", node.id, node.name, proj_name);
                println!("  Definition: {}", node.definition);
                println!(
                    "  Description: {}",
                    &node.description[..node.description.len().min(200)]
                );
            }
            println!("\nTotal: {} results", results.len());
        }
        Ok(())
    }
}
