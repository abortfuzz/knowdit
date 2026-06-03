use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

use clap::Args;
use color_eyre::eyre::{Result, WrapErr, ensure};
use knowdit_repo_model::{
    RepoDatabase,
    cg::{CallGraph, CallGraphDotOptions},
};
use serde::Serialize;

#[derive(Args, Debug, Clone)]
pub struct MovyCliArgs {
    /// Path to the movy CLI binary.
    #[arg(
        long = "movy-path",
        env = "MOVY_PATH",
        default_value = "movy",
        alias = "movy-bin"
    )]
    pub path: PathBuf,
}

impl MovyCliArgs {
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }
}

#[derive(Args, Debug, Clone)]
pub struct ExtractMoveArgs {
    #[command(flatten)]
    pub movy: MovyCliArgs,

    /// Move package root containing Move.toml.
    #[arg(long, default_value = ".")]
    pub package_root: PathBuf,

    /// Build in test mode before extracting modules/functions.
    #[arg(long)]
    pub test_mode: bool,

    /// Write extracted modules/functions JSON to this file. Prints to stdout when omitted.
    #[arg(long, short = 'o')]
    pub output: Option<PathBuf>,
}

#[derive(Args, Debug, Clone)]
pub struct MoveCallGraphArgs {
    #[command(flatten)]
    pub movy: MovyCliArgs,

    #[command(flatten)]
    pub project: crate::cli::ProjectArgs,

    #[command(flatten)]
    pub db: crate::cli::DatabaseArgs,

    /// Build in test mode before analyzing the package call graph.
    #[arg(long)]
    pub test_mode: bool,
}

#[derive(Args, Debug, Clone)]
pub struct MoveExportCallGraphDotArgs {
    #[command(flatten)]
    pub project: crate::cli::ProjectArgs,

    #[command(flatten)]
    pub db: crate::cli::DatabaseArgs,

    /// Output .dot file path.
    #[arg(long, short = 'o', default_value = "knowdit-move-callgraph.dot")]
    pub output: PathBuf,

    /// Include call graph functions that have no incoming or outgoing edges.
    #[arg(long)]
    pub include_isolated_nodes: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct MoveExtractionResult {
    pub package_root: PathBuf,
    pub search_roots: Vec<PathBuf>,
    pub test_mode: bool,
    pub modules: Vec<ExtractedMoveModule>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ExtractedMoveModule {
    pub id: i32,
    pub module_id: String,
    pub relative_file_path: PathBuf,
    pub functions: Vec<ExtractedMoveFunction>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ExtractedMoveFunction {
    pub id: i32,
    pub name: String,
    pub visibility: String,
    pub args: String,
    pub returns: String,
}

impl ExtractMoveArgs {
    pub async fn run(self) -> Result<()> {
        let package_root = canonical_move_package_root(&self.package_root)?;
        let call_graph =
            load_movy_call_graph_from_database(self.movy.path(), &package_root, self.test_mode)
                .await?;
        let extraction = extraction_from_call_graph(package_root, self.test_mode, &call_graph);
        let json = serde_json::to_string_pretty(&extraction)
            .wrap_err("failed to serialize Move extraction result")?;

        if let Some(output) = self.output {
            if let Some(parent) = output
                .parent()
                .filter(|parent| !parent.as_os_str().is_empty())
            {
                tokio::fs::create_dir_all(parent).await.wrap_err_with(|| {
                    format!("failed to create output directory {}", parent.display())
                })?;
            }
            tokio::fs::write(&output, json).await.wrap_err_with(|| {
                format!("failed to write extraction JSON to {}", output.display())
            })?;
            tracing::info!("Wrote Move extraction JSON to {}", output.display());
        } else {
            println!("{json}");
        }

        Ok(())
    }
}

impl MoveCallGraphArgs {
    pub async fn run(self) -> Result<()> {
        let crate::cli::LoadedRepoDatabase {
            spec,
            database_path,
            repo,
        } = self
            .project
            .to_repo_database(self.db.database_path.clone())
            .await?;
        let package_root = canonical_move_package_root(&spec.root)?;

        tracing::info!(
            "Building Move callgraph for {} via {} analysis export-call-graph...",
            package_root.display(),
            self.movy.path().display()
        );
        run_movy_export_call_graph_to_database(
            self.movy.path(),
            &package_root,
            self.test_mode,
            &RepoDatabase::sqlite_url_for(&database_path),
        )?;

        let call_graph = repo.load_call_graph().await?;
        let counts = call_graph.counts();
        tracing::info!(
            "Wrote Move callgraph to {}: {} module nodes, {} functions, {} calls",
            database_path.display(),
            counts.container_count,
            counts.function_count,
            counts.call_count
        );
        println!(
            "Wrote callgraph to {} (modules={}, functions={}, calls={})",
            database_path.display(),
            counts.container_count,
            counts.function_count,
            counts.call_count
        );

        Ok(())
    }
}

impl MoveExportCallGraphDotArgs {
    pub async fn run(self) -> Result<()> {
        let crate::cli::LoadedRepoDatabase {
            database_path,
            repo,
            ..
        } = self
            .project
            .to_repo_database(self.db.database_path.clone())
            .await?;
        let call_graph = repo.load_call_graph().await?;
        let dot = call_graph.export_dot_with_options(CallGraphDotOptions {
            include_isolated_nodes: self.include_isolated_nodes,
        });
        crate::cmd::learn::export_dot::write_dot_and_maybe_pdf(
            "Move call graph",
            &self.output,
            &dot,
        )?;

        let counts = call_graph.counts();
        tracing::info!(
            "Exported Move callgraph from {}: {} module nodes, {} functions, {} calls",
            database_path.display(),
            counts.container_count,
            counts.function_count,
            counts.call_count
        );

        Ok(())
    }
}

fn canonical_move_package_root(package_root: &Path) -> Result<PathBuf> {
    let package_root = package_root.canonicalize().wrap_err_with(|| {
        format!(
            "failed to canonicalize Move package root {}",
            package_root.display()
        )
    })?;
    ensure!(
        package_root.is_dir(),
        "Move package root {} is not a directory",
        package_root.display()
    );
    ensure!(
        package_root.join("Move.toml").is_file(),
        "Move package root {} does not contain Move.toml",
        package_root.display()
    );
    Ok(package_root)
}

async fn load_movy_call_graph_from_database(
    path: &Path,
    package_root: &Path,
    test_mode: bool,
) -> Result<CallGraph> {
    let database = TemporarySqliteDatabase::new()?;
    let database_url = RepoDatabase::sqlite_url_for(&database.path);
    let repo = RepoDatabase::open_sqlite(database.path.clone()).await?;
    repo.init_schema().await?;

    run_movy_export_call_graph_to_database(path, package_root, test_mode, &database_url)?;
    repo.load_call_graph().await
}

fn run_movy_export_call_graph_to_database(
    path: &Path,
    package_root: &Path,
    test_mode: bool,
    database_url: &str,
) -> Result<()> {
    run_movy_export_call_graph(path, package_root, test_mode, database_url)?;
    Ok(())
}

fn run_movy_export_call_graph(
    path: &Path,
    package_root: &Path,
    test_mode: bool,
    database_url: &str,
) -> Result<std::process::Output> {
    let mut command = Command::new(path);

    command
        .arg("analysis")
        .arg("export-call-graph")
        .arg("--package")
        .arg(package_root)
        .arg("--database-url")
        .arg(database_url);
    if test_mode {
        command.arg("--test-mode");
    }

    let output = command.output().wrap_err_with(|| {
        format!(
            "failed to execute movy binary {} for call graph export",
            path.display()
        )
    })?;
    ensure!(
        output.status.success(),
        "movy call graph export failed with status {}:\nstdout:\n{}\nstderr:\n{}",
        output
            .status
            .code()
            .map(|code| code.to_string())
            .unwrap_or_else(|| "<terminated by signal>".to_string()),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(output)
}

struct TemporarySqliteDatabase {
    path: PathBuf,
}

impl TemporarySqliteDatabase {
    fn new() -> Result<Self> {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .wrap_err("system clock is before UNIX_EPOCH")?
            .as_nanos();
        Ok(Self {
            path: std::env::temp_dir().join(format!(
                "knowdit-movy-callgraph-{}-{unique}.sqlite3",
                std::process::id()
            )),
        })
    }
}

impl Drop for TemporarySqliteDatabase {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
        let _ = fs::remove_file(self.path.with_extension("sqlite3-shm"));
        let _ = fs::remove_file(self.path.with_extension("sqlite3-wal"));
    }
}

fn extraction_from_call_graph(
    package_root: PathBuf,
    test_mode: bool,
    call_graph: &CallGraph,
) -> MoveExtractionResult {
    let mut next_function_id = 1;
    let modules = call_graph
        .contracts
        .values()
        .map(|contract| {
            let functions = contract
                .functions
                .iter()
                .map(|function| {
                    let id = next_function_id;
                    next_function_id += 1;
                    ExtractedMoveFunction {
                        id,
                        name: function.name.clone(),
                        visibility: extracted_function_visibility(function),
                        args: function.args.clone(),
                        returns: extracted_function_returns(function),
                    }
                })
                .collect();

            ExtractedMoveModule {
                id: contract.id,
                module_id: contract.name.clone(),
                relative_file_path: contract.relative_file_path.clone(),
                functions,
            }
        })
        .collect();

    MoveExtractionResult {
        search_roots: vec![package_root.clone()],
        package_root,
        test_mode,
        modules,
    }
}

fn extracted_function_visibility(function: &knowdit_repo_model::cg::Function) -> String {
    let Some(description) = &function.description else {
        return String::new();
    };
    let signature_start = format!(" {}(", function.name);
    description
        .split_once(&signature_start)
        .map(|(visibility, _)| visibility.to_string())
        .unwrap_or_default()
}

fn extracted_function_returns(function: &knowdit_repo_model::cg::Function) -> String {
    let Some(description) = &function.description else {
        return String::new();
    };
    let signature_start = format!("{}(", function.name);
    let Some((_, after_name)) = description.split_once(&signature_start) else {
        return String::new();
    };
    after_name
        .split_once("): ")
        .map(|(_, returns)| returns.to_string())
        .unwrap_or_default()
}
