use clap::Args;
use color_eyre::eyre::{Result, eyre};
use knowdit_kg::db::DatabaseGraph;
use std::path::PathBuf;
use std::process::Command;

#[derive(Args)]
pub struct ExportDotArgs {
    /// Output .dot file path
    #[arg(short, long, default_value = "knowdit-kg.dot")]
    output: PathBuf,
}

pub async fn run(db: &DatabaseGraph, args: ExportDotArgs) -> Result<()> {
    let kg = db.load_knowledge_graph().await?;
    let dot = kg.export_dot();
    std::fs::write(&args.output, &dot)?;
    let pdf_output = args.output.with_extension("pdf");
    let png_output = args.output.with_extension("png");

    println!("Knowledge graph exported to {}", args.output.display());

    if graphviz_dot_available() {
        let status = Command::new("dot")
            .arg("-Tpdf")
            .arg(&args.output)
            .arg("-o")
            .arg(&pdf_output)
            .status()?;

        if !status.success() {
            return Err(eyre!("Graphviz 'dot' failed with status {status}"));
        }

        println!("Knowledge graph PDF exported to {}", pdf_output.display());
    }

    println!(
        "Render PNG with: dot -Tpng {} -o {}",
        args.output.display(),
        png_output.display()
    );
    Ok(())
}

fn graphviz_dot_available() -> bool {
    Command::new("dot")
        .arg("-V")
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false)
}
