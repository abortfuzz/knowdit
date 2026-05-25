use clap::Args;
use color_eyre::eyre::{Result, eyre};
use knowdit_kg::db::HistoricalDatabase;
use std::path::{Path, PathBuf};
use std::process::Command;

#[derive(Args)]
pub struct ExportDotArgs {
    /// Output .dot file path
    #[arg(short, long, default_value = "knowdit-kg.dot")]
    pub output: PathBuf,
}

impl ExportDotArgs {
    pub async fn run(self, db: &HistoricalDatabase) -> Result<()> {
        let kg = db.load_knowledge_graph().await?;
        let dot = kg.export_dot();
        write_dot_and_maybe_pdf("Knowledge graph", &self.output, &dot)
    }
}

pub fn write_dot_and_maybe_pdf(label: &str, output: &Path, dot: &str) -> Result<()> {
    std::fs::write(output, dot)?;
    let pdf_output = output.with_extension("pdf");
    let png_output = output.with_extension("png");

    println!("{} exported to {}", label, output.display());

    if graphviz_dot_available() {
        let status = Command::new("dot")
            .arg("-Tpdf")
            .arg(output)
            .arg("-o")
            .arg(&pdf_output)
            .status()?;

        if !status.success() {
            return Err(eyre!("Graphviz 'dot' failed with status {status}"));
        }

        println!("{} PDF exported to {}", label, pdf_output.display());
    }

    println!(
        "Render PNG with: dot -Tpng {} -o {}",
        output.display(),
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
