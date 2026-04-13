use clap::Args;
use color_eyre::eyre::{Result, ensure};
use knowdit_kg::db::DatabaseGraph;
use std::path::PathBuf;

const HTML_OUTPUT_FILE_NAME: &str = "index.html";
const GRAPH_DATA_OUTPUT_FILE_NAME: &str = "knowdit-kg.graph.js";
const DETAILS_OUTPUT_FILE_NAME: &str = "knowdit-kg.details.js";
const DEFAULT_VIEWPORT_EDGE_LIMIT: usize = 500;
const DEFAULT_SEMANTIC_ROWS: usize = 15;
const DEFAULT_FINDING_ROWS: usize = 15;

#[derive(Args)]
pub struct ExportHtmlArgs {
    /// Output directory
    #[arg(short, long, default_value = "knowdit-kg")]
    output: PathBuf,

    /// Maximum number of edges rendered in the current view
    #[arg(long, default_value_t = DEFAULT_VIEWPORT_EDGE_LIMIT)]
    viewport_edge_limit: usize,

    /// Arrange project nodes into this many rows before starting a new column.
    /// When omitted, rows are auto-computed from the combined semantic and
    /// finding row counts so both sides keep a similar vertical span.
    #[arg(long)]
    project_rows: Option<usize>,

    /// Arrange semantic nodes into this many rows before starting a new column
    #[arg(long, default_value_t = DEFAULT_SEMANTIC_ROWS)]
    semantic_rows: usize,

    /// Arrange finding nodes into this many rows before starting a new column
    #[arg(long, default_value_t = DEFAULT_FINDING_ROWS)]
    finding_rows: usize,
}

pub async fn run(db: &DatabaseGraph, args: ExportHtmlArgs) -> Result<()> {
    ensure!(
        args.viewport_edge_limit > 0,
        "Viewport edge limit must be greater than zero"
    );
    if let Some(project_rows) = args.project_rows {
        ensure!(project_rows > 0, "Project rows must be greater than zero");
    }
    ensure!(
        args.semantic_rows > 0,
        "Semantic rows must be greater than zero"
    );
    ensure!(
        args.finding_rows > 0,
        "Finding rows must be greater than zero"
    );
    let kg = db.load_knowledge_graph().await?;
    let project_rows = args.project_rows.unwrap_or_else(|| {
        auto_project_rows(kg.projects.len(), args.semantic_rows, args.finding_rows)
    });
    let paths = export_paths(args.output);

    if let Ok(metadata) = std::fs::metadata(&paths.output_dir) {
        ensure!(
            metadata.is_dir(),
            "Output path {} exists and is not a directory",
            paths.output_dir.display()
        );
    }
    std::fs::create_dir_all(&paths.output_dir)?;

    let assets = kg.export_html(
        GRAPH_DATA_OUTPUT_FILE_NAME,
        DETAILS_OUTPUT_FILE_NAME,
        args.viewport_edge_limit,
        project_rows,
        args.semantic_rows,
        args.finding_rows,
    )?;
    std::fs::write(&paths.html_output, assets.html)?;
    std::fs::write(&paths.graph_data_output, assets.graph_data_js)?;
    std::fs::write(&paths.details_output, assets.details_js)?;

    println!(
        "Interactive knowledge graph exported under {}",
        paths.output_dir.display()
    );
    println!("Open {}", paths.html_output.display());
    println!(
        "Graph data written to {}",
        paths.graph_data_output.display()
    );
    println!(
        "Selection details written to {}",
        paths.details_output.display()
    );
    println!(
        "Current-view edge limit set to {}",
        args.viewport_edge_limit
    );
    println!("Project rows set to {}", project_rows);
    println!("Semantic rows set to {}", args.semantic_rows);
    println!("Finding rows set to {}", args.finding_rows);
    println!("Keep the exported files together in that directory when opening in a browser.");
    Ok(())
}

fn auto_project_rows(project_count: usize, semantic_rows: usize, finding_rows: usize) -> usize {
    let combined_rows = semantic_rows.saturating_add(finding_rows).max(1);

    if project_count == 0 {
        1
    } else {
        combined_rows.min(project_count)
    }
}

struct ExportPaths {
    output_dir: PathBuf,
    html_output: PathBuf,
    graph_data_output: PathBuf,
    details_output: PathBuf,
}

fn export_paths(output_dir: PathBuf) -> ExportPaths {
    ExportPaths {
        html_output: output_dir.join(HTML_OUTPUT_FILE_NAME),
        graph_data_output: output_dir.join(GRAPH_DATA_OUTPUT_FILE_NAME),
        details_output: output_dir.join(DETAILS_OUTPUT_FILE_NAME),
        output_dir,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn export_paths_write_files_inside_output_directory() {
        let paths = export_paths(PathBuf::from("artifacts/export-html"));

        assert_eq!(paths.output_dir, PathBuf::from("artifacts/export-html"));
        assert_eq!(
            paths.html_output,
            PathBuf::from("artifacts/export-html/index.html")
        );
        assert_eq!(
            paths.graph_data_output,
            PathBuf::from("artifacts/export-html/knowdit-kg.graph.js")
        );
        assert_eq!(
            paths.details_output,
            PathBuf::from("artifacts/export-html/knowdit-kg.details.js")
        );
    }

    #[test]
    fn auto_project_rows_follows_combined_semantic_and_finding_rows() {
        assert_eq!(auto_project_rows(400, 15, 15), 30);
        assert_eq!(auto_project_rows(12, 15, 15), 12);
        assert_eq!(auto_project_rows(0, 15, 15), 1);
    }
}
