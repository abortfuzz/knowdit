use clap::Args;
use color_eyre::eyre::Result;
use knowdit_kg::db::DatabaseGraph;

#[derive(Args)]
pub struct SearchSemanticsArgs {
    /// Search query keyword
    query: String,
}

pub async fn run(db: &DatabaseGraph, args: SearchSemanticsArgs) -> Result<()> {
    let results = db.search_semantics(&args.query).await?;
    if results.is_empty() {
        println!("No semantics found matching '{}'", args.query);
    } else {
        println!("Search results for '{}':", args.query);
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
