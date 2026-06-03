use std::path::{Path, PathBuf};

use clap::Args;
use color_eyre::eyre::{Result, WrapErr, ensure};
use knowdit_agents::{
    cg::{CallGraphAgentConfig, analyze_repo_call_graph},
    storage::{StorageAgentConfig, analyze_repo_storage},
};
use knowdit_repo_model::{
    cg::{CallGraph, CallGraphDotOptions, Contract, Function, Interface},
    storage::StorageDotOptions,
};
use knowdit_sol::cg::{
    ExtractedContract, SolidityCallableKind, SolidityContractKind, SolidityExtractionConfig,
    extract_repo_contracts_functions,
};
use llmy::clap::OpenAISetup;

use crate::cmd::audit::extract_semantics::load_or_extract_project_semantics;

#[derive(Args, Debug, Clone)]
pub struct SoliditySourceCliArgs {
    /// Solidity repository root.
    #[arg(long, default_value = ".")]
    pub repo_root: PathBuf,

    /// Glob patterns included while collecting Solidity sources for tree-sitter.
    #[arg(
        short = 'i',
        long = "tree-sitter-include-glob",
        value_delimiter = ',',
        default_value = "**/*.sol"
    )]
    pub tree_sitter_include_globs: Vec<String>,

    /// Glob patterns excluded while collecting Solidity sources for tree-sitter.
    #[arg(
        short = 'x',
        long = "tree-sitter-exclude-glob",
        value_delimiter = ',',
        default_value = ".git,.git/**,**/.git,**/.git/**"
    )]
    pub tree_sitter_exclude_globs: Vec<String>,
}

#[derive(Args, Debug, Clone)]
pub struct SolidityAnalysisScopeCliArgs {
    /// Glob patterns included in callgraph analysis scope. Overrides
    /// scope.txt + the default `**/*.sol` fallback when set.
    #[arg(long = "analysis-scope-glob", value_delimiter = ',')]
    pub analysis_scope_globs: Vec<String>,

    /// Glob patterns excluded from callgraph analysis scope.
    #[arg(
        long = "analysis-scope-exclude-glob",
        value_delimiter = ',',
        default_value = ".git,.git/**,**/.git,**/.git/**,\
                         target,target/**,**/target,**/target/**,\
                         node_modules,node_modules/**,**/node_modules,**/node_modules/**,\
                         artifacts,artifacts/**,**/artifacts,**/artifacts/**,\
                         cache,cache/**,**/cache,**/cache/**,\
                         build,build/**,**/build,**/build/**"
    )]
    pub analysis_scope_exclude_globs: Vec<String>,

    /// Do not read scope.txt when choosing the callgraph analysis scope.
    #[arg(long)]
    pub ignore_scope_file: bool,
}

impl SolidityAnalysisScopeCliArgs {
    /// Resolve the include-glob list with precedence:
    /// 1. explicit `--analysis-scope-glob` flags;
    /// 2. `scope.txt` at the repo root (unless `--ignore-scope-file`);
    /// 3. the same fallback that the tree-sitter source list uses
    ///    (`**/*.sol`). Not a one-line helper — keeping it as a member
    ///    fn so the precedence rules live next to the data.
    fn resolve_include_globs(&self, repo_root: &Path) -> Result<Vec<String>> {
        if !self.analysis_scope_globs.is_empty() {
            return Ok(self.analysis_scope_globs.clone());
        }
        if !self.ignore_scope_file
            && let Some(scope_globs) = knowdit_project::read_scope_txt(repo_root)?
            && !scope_globs.is_empty()
        {
            return Ok(scope_globs);
        }
        Ok(vec!["**/*.sol".to_string()])
    }
}

#[derive(Args, Debug, Clone)]
pub struct ExtractSolidityArgs {
    #[command(flatten)]
    pub source: SoliditySourceCliArgs,

    #[command(flatten)]
    pub scope: SolidityAnalysisScopeCliArgs,

    /// Write extracted contracts/functions JSON to this file. Prints to stdout when omitted.
    #[arg(long, short = 'o')]
    pub output: Option<PathBuf>,
}

#[derive(Args, Debug, Clone)]
pub struct SolidityCallGraphArgs {
    #[command(flatten)]
    pub llm: OpenAISetup,

    #[command(flatten)]
    pub project: crate::cli::ProjectArgs,

    #[command(flatten)]
    pub db: crate::cli::DatabaseArgs,

    #[command(flatten)]
    pub source: SoliditySourceCliArgs,

    #[command(flatten)]
    pub scope: SolidityAnalysisScopeCliArgs,

    /// Maximum llmy steps for each per-callable callgraph agent.
    #[arg(long, default_value_t = 64)]
    pub max_agent_steps: usize,

    /// Compact per-callable agent context when it reaches this approximate token count.
    #[arg(long)]
    pub compact_context_threshold_tokens: Option<usize>,

    /// llmy prompt cache key prefix for callgraph analysis.
    #[arg(long, default_value = "knowdit-sol-cg")]
    pub cache_key: String,
}

#[derive(Args, Debug, Clone)]
pub struct SolidityStorageGraphArgs {
    #[command(flatten)]
    pub llm: OpenAISetup,

    #[command(flatten)]
    pub project: crate::cli::ProjectArgs,

    #[command(flatten)]
    pub db: crate::cli::DatabaseArgs,

    #[command(flatten)]
    pub source: SoliditySourceCliArgs,

    #[command(flatten)]
    pub scope: SolidityAnalysisScopeCliArgs,

    /// Maximum llmy steps per contract.
    #[arg(long, default_value_t = 32)]
    pub max_agent_steps: usize,

    /// llmy prompt cache key prefix for storage analysis.
    #[arg(long, default_value = "knowdit-sol-storage")]
    pub cache_key: String,
}

#[derive(Args, Debug, Clone)]
pub struct SolidityCallGraphStaticArgs {
    #[command(flatten)]
    pub project: crate::cli::ProjectArgs,

    #[command(flatten)]
    pub db: crate::cli::DatabaseArgs,

    #[command(flatten)]
    pub backend: crate::cli::ProjectBackendCliOptions,
}

#[derive(Args, Debug, Clone)]
pub struct SolidityExportCallGraphDotArgs {
    #[command(flatten)]
    pub project: crate::cli::ProjectArgs,

    #[command(flatten)]
    pub db: crate::cli::DatabaseArgs,

    /// Output .dot file path.
    #[arg(long, short = 'o', default_value = "knowdit-sol-callgraph.dot")]
    pub output: PathBuf,

    /// Include callgraph functions that have no incoming or outgoing edges.
    #[arg(long)]
    pub include_isolated_nodes: bool,
}

#[derive(Args, Debug, Clone)]
pub struct SolidityExportStateVariableDotArgs {
    #[command(flatten)]
    pub project: crate::cli::ProjectArgs,

    #[command(flatten)]
    pub db: crate::cli::DatabaseArgs,

    /// Output .dot file path.
    #[arg(long, short = 'o', default_value = "knowdit-sol-storage.dot")]
    pub output: PathBuf,

    /// Include state variables that no function reads or writes.
    #[arg(long)]
    pub include_isolated_state_variables: bool,
}

impl ExtractSolidityArgs {
    pub async fn run(self) -> Result<()> {
        let config = build_solidity_extraction_config(&self.source, &self.scope)?;
        let extraction = extract_repo_contracts_functions(&config).await?;
        let json = serde_json::to_string_pretty(&extraction)
            .wrap_err("failed to serialize Solidity extraction result")?;

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
            tracing::info!("Wrote Solidity extraction JSON to {}", output.display());
        } else {
            println!("{json}");
        }

        Ok(())
    }
}

impl SolidityCallGraphArgs {
    pub async fn run(self) -> Result<()> {
        ensure!(
            self.max_agent_steps > 0,
            "max_agent_steps must be greater than zero"
        );

        let crate::cli::LoadedRepoDatabase { spec, repo, .. } = self
            .project
            .to_repo_database(self.db.database_path.clone())
            .await?;
        let extraction_config = build_solidity_extraction_config(&self.source, &self.scope)?;

        tracing::info!("Loading project...");
        let project_data = knowdit_project::ProjectData::from_relative_paths(
            &spec.name,
            &extraction_config.repo_root,
            knowdit_project::SourceLanguage::Solidity,
            spec.platform_id.as_deref(),
            &extraction_config.analysis_source_files,
        )
        .await?;

        let llm = self.llm.clone().to_llm().await;
        let agent_options = knowdit_kg::agent_runner::AgentRunOptions::new(self.max_agent_steps);
        // The LLM-driven callgraph agent has no CLI knob for the
        // per-chunk input budget; fall back to the model's default
        // (~80% of max_input) by passing None through.
        let semantics =
            load_or_extract_project_semantics(&repo, &llm, &project_data, None, &agent_options)
                .await?;

        let config = CallGraphAgentConfig::new(
            extraction_config,
            self.max_agent_steps,
            3,
            self.compact_context_threshold_tokens,
            self.cache_key.clone(),
            Some("llm-sol-cg".to_string()),
            Some(self.llm.settings()),
        );

        let result = analyze_repo_call_graph(&llm, config, &semantics).await?;
        repo.write_call_graph(&result.call_graph).await?;

        let counts = result.call_graph.counts();
        let database_url = repo.redacted_url();
        tracing::info!(
            "Wrote Solidity callgraph to {}: {} contract/interface nodes, {} functions, {} calls",
            database_url,
            counts.container_count,
            counts.function_count,
            counts.call_count
        );
        println!(
            "Wrote callgraph to {} (contract_interfaces={}, functions={}, calls={})",
            database_url, counts.container_count, counts.function_count, counts.call_count
        );

        Ok(())
    }
}

impl SolidityStorageGraphArgs {
    pub async fn run(self) -> Result<()> {
        ensure!(
            self.max_agent_steps > 0,
            "max_agent_steps must be greater than zero"
        );

        let crate::cli::LoadedRepoDatabase { repo, .. } = self
            .project
            .to_repo_database(self.db.database_path.clone())
            .await?;
        let extraction_config = build_solidity_extraction_config(&self.source, &self.scope)?;

        let llm = self.llm.clone().to_llm().await;
        let config = StorageAgentConfig::new(
            extraction_config,
            self.max_agent_steps,
            self.cache_key.clone(),
            Some("llm-sol-storage".to_string()),
            Some(self.llm.settings()),
        );
        let result = analyze_repo_storage(&llm, config).await?;

        // Persist a callgraph skeleton (contracts + functions, no call edges) so downstream queries
        // can join `function_state_variable.function_id` against the `function` table.
        let skeleton = build_callgraph_skeleton_from_extraction(&result.extracted_contracts);
        repo.write_call_graph(&skeleton).await?;
        repo.write_storage_graph(&result.storage_graph).await?;
        repo.write_inheritance_graph(&result.inheritance_graph)
            .await?;

        let database_url = repo.redacted_url();
        let storage = &result.storage_graph;
        let inheritance = &result.inheritance_graph;
        tracing::info!(
            "Wrote Solidity storage analysis (LLM agent) to {}: {} state vars, {} contract->parent edges, {} contract-variable rows, {} function read/write rows; {} agent steps",
            database_url,
            storage.state_variables.len(),
            inheritance.len(),
            storage.contract_variables.len(),
            storage.function_state_variables.len(),
            result.steps,
        );
        println!(
            "Wrote storage analysis to {} (state_vars={}, inherits={}, contract_vars={}, fn_state_vars={}, steps={})",
            database_url,
            storage.state_variables.len(),
            inheritance.len(),
            storage.contract_variables.len(),
            storage.function_state_variables.len(),
            result.steps,
        );

        Ok(())
    }
}

fn build_callgraph_skeleton_from_extraction(contracts: &[ExtractedContract]) -> CallGraph {
    let mut out_contracts: std::collections::BTreeMap<i32, Contract> =
        std::collections::BTreeMap::new();
    let mut out_interfaces: std::collections::BTreeMap<i32, Interface> =
        std::collections::BTreeMap::new();
    for c in contracts {
        let functions: Vec<Function> = c
            .functions
            .iter()
            .map(|f| Function {
                id: f.id,
                name: f.name.clone(),
                args: f.args.clone(),
                relative_file_path: f.relative_file_path.clone(),
                loc: f.chunk.loc,
                content: if matches!(c.kind, SolidityContractKind::Interface) {
                    None
                } else {
                    Some(f.chunk.content.clone())
                },
                calls: Vec::new(),
                description: None,
            })
            .collect();
        match c.kind {
            SolidityContractKind::Interface => {
                out_interfaces.insert(
                    c.id,
                    Interface {
                        id: c.id,
                        name: c.name.clone(),
                        relative_file_path: c.relative_file_path.clone(),
                        chunk: c.chunk.clone(),
                        functions,
                        description: None,
                    },
                );
            }
            SolidityContractKind::Contract | SolidityContractKind::Library => {
                out_contracts.insert(
                    c.id,
                    Contract {
                        id: c.id,
                        name: c.name.clone(),
                        relative_file_path: c.relative_file_path.clone(),
                        chunk: c.chunk.clone(),
                        functions,
                        description: None,
                    },
                );
            }
        }
    }
    let _ = SolidityCallableKind::Function;
    CallGraph {
        contracts: out_contracts,
        interfaces: out_interfaces,
    }
}

impl SolidityCallGraphStaticArgs {
    /// CLI entry: opens the per-project DB, delegates to
    /// [`Self::update_call_graph`], and prints the summary lines that
    /// the user sees on stdout.
    pub async fn run(self) -> Result<()> {
        let crate::cli::LoadedRepoDatabase {
            spec,
            database_path,
            repo,
        } = self
            .project
            .to_repo_database(self.db.database_path.clone())
            .await?;
        let (cg, sg) = Self::update_call_graph(&repo, &spec.root, &self.backend).await?;
        let url = database_path.display();
        println!(
            "Wrote callgraph to {url} (contracts={}, interfaces={}, functions={}, calls={})",
            cg.contract_count, cg.interface_count, cg.function_count, cg.call_count,
        );
        println!(
            "Wrote storage analysis to {url} (state_vars={}, inherits={}, contract_vars={}, fn_state_vars={})",
            sg.state_variable_count,
            sg.contract_inherit_count,
            sg.contract_variable_count,
            sg.function_state_variable_count,
        );
        Ok(())
    }

    /// In-process entry: build the static call-graph + storage graph
    /// for the project at `repo_root` and persist both into `repo`.
    /// Designed to be called from orchestrators (the autoloop) that
    /// already own a [`RepoDatabase`] handle and want to avoid the CLI
    /// boilerplate of [`Self::run`].
    pub async fn update_call_graph(
        repo: &knowdit_repo_model::RepoDatabase,
        repo_root: &Path,
        backend: &crate::cli::ProjectBackendCliOptions,
    ) -> Result<(
        knowdit_project::StaticCallGraphResult,
        knowdit_project::StorageAnalysisResult,
    )> {
        let resolved = backend.resolve(repo_root);
        tracing::info!(
            "Compiling Solidity project at {} (backend={})...",
            repo_root.display(),
            resolved.kind_label(),
        );

        let (call_graph, storage) = match resolved {
            crate::cli::ResolvedProjectBackend::Forge(opts) => {
                let project =
                    knowdit_project::FoundryProject::build(repo_root.to_path_buf(), opts).await?;
                repo.write_call_graph(project.call_graph()).await?;
                repo.write_storage_graph(project.storage_graph()).await?;
                repo.write_inheritance_graph(project.inheritance_graph())
                    .await?;
                (
                    project.call_graph_result().clone(),
                    project.storage_result().clone(),
                )
            }
            crate::cli::ResolvedProjectBackend::Hardhat(opts) => {
                let project =
                    knowdit_project::HardhatProject::build(repo_root.to_path_buf(), opts).await?;
                repo.write_call_graph(project.call_graph()).await?;
                repo.write_storage_graph(project.storage_graph()).await?;
                repo.write_inheritance_graph(project.inheritance_graph())
                    .await?;
                (
                    project.call_graph_result().clone(),
                    project.storage_result().clone(),
                )
            }
        };

        tracing::info!(
            "Wrote static Solidity callgraph: {} contracts/libs, {} interfaces, {} functions, {} calls",
            call_graph.contract_count,
            call_graph.interface_count,
            call_graph.function_count,
            call_graph.call_count
        );
        tracing::info!(
            "Wrote storage analysis: {} state vars, {} contract→parent edges, {} contract-variable rows, {} function read/write rows",
            storage.state_variable_count,
            storage.contract_inherit_count,
            storage.contract_variable_count,
            storage.function_state_variable_count,
        );
        Ok((call_graph, storage))
    }
}

impl SolidityExportStateVariableDotArgs {
    pub async fn run(self) -> Result<()> {
        let crate::cli::LoadedRepoDatabase {
            database_path,
            repo,
            ..
        } = self
            .project
            .to_repo_database(self.db.database_path.clone())
            .await?;
        let storage = repo.load_storage_graph().await?;
        let dot = repo
            .export_storage_dot(
                &storage,
                StorageDotOptions {
                    include_isolated_state_variables: self.include_isolated_state_variables,
                },
            )
            .await?;
        crate::cmd::learn::export_dot::write_dot_and_maybe_pdf(
            "Solidity storage read/write graph",
            &self.output,
            &dot,
        )?;

        tracing::info!(
            "Exported Solidity storage R/W graph from {}: {} state vars, {} fn read/write rows",
            database_path.display(),
            storage.state_variables.len(),
            storage.function_state_variables.len(),
        );
        Ok(())
    }
}

impl SolidityExportCallGraphDotArgs {
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
            "Solidity call graph",
            &self.output,
            &dot,
        )?;

        let counts = call_graph.counts();
        tracing::info!(
            "Exported Solidity callgraph from {}: {} contract/interface nodes, {} functions, {} calls",
            database_path.display(),
            counts.container_count,
            counts.function_count,
            counts.call_count
        );

        Ok(())
    }
}

fn build_solidity_extraction_config(
    source: &SoliditySourceCliArgs,
    scope: &SolidityAnalysisScopeCliArgs,
) -> Result<SolidityExtractionConfig> {
    let repo_root = source.repo_root.canonicalize().wrap_err_with(|| {
        format!(
            "failed to canonicalize repo root {}",
            source.repo_root.display()
        )
    })?;
    ensure!(
        repo_root.is_dir(),
        "repo root {} is not a directory",
        repo_root.display()
    );

    // Tree-sitter source set: every .sol file under repo_root that
    // passes the user's include/exclude globs. Built via
    // `ProjectScope` so the walk + glob filter logic lives in one
    // place across the codebase.
    let tree_include: Vec<&str> = source
        .tree_sitter_include_globs
        .iter()
        .map(String::as_str)
        .collect();
    let tree_exclude: Vec<&str> = source
        .tree_sitter_exclude_globs
        .iter()
        .map(String::as_str)
        .collect();
    let tree_scope = knowdit_project::ProjectScope::build_from_patterns(
        repo_root.clone(),
        &tree_include,
        &tree_exclude,
    )?;
    ensure!(
        !tree_scope.is_empty(),
        "no Solidity source files found under {} for tree-sitter includes {:?} and excludes {:?}",
        repo_root.display(),
        source.tree_sitter_include_globs,
        source.tree_sitter_exclude_globs
    );

    // Analysis source set: narrow the tree-sitter set with the
    // analysis-scope globs (scope.txt / CLI overrides / `**/*.sol`
    // fallback).
    let analysis_scope_globs = scope.resolve_include_globs(&repo_root)?;
    let analysis_include: Vec<&str> = analysis_scope_globs.iter().map(String::as_str).collect();
    let analysis_exclude: Vec<&str> = scope
        .analysis_scope_exclude_globs
        .iter()
        .map(String::as_str)
        .collect();
    let analysis_scope = tree_scope.filter_by_patterns(&analysis_include, &analysis_exclude)?;
    ensure!(
        !analysis_scope.is_empty(),
        "no Solidity source files remain in callgraph analysis scope under {} for includes {:?} and excludes {:?}",
        repo_root.display(),
        analysis_scope_globs,
        scope.analysis_scope_exclude_globs
    );

    Ok(SolidityExtractionConfig::new(
        repo_root,
        tree_scope.paths().iter().cloned().collect(),
        analysis_scope.paths().iter().cloned().collect(),
    ))
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;

    struct TempRepo {
        path: PathBuf,
    }

    impl TempRepo {
        fn new() -> Self {
            let unique = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("system clock should be after unix epoch")
                .as_nanos();
            let path = std::env::temp_dir().join(format!(
                "knowdit-cli-sol-test-{}-{unique}",
                std::process::id()
            ));
            fs::create_dir_all(&path).expect("failed to create temp repo");
            Self { path }
        }

        fn write(&self, relative_path: &str, content: &str) {
            let path = self.path.join(relative_path);
            fs::create_dir_all(path.parent().expect("test path should have parent"))
                .expect("failed to create parent directory");
            fs::write(path, content).expect("failed to write test file");
        }
    }

    impl Drop for TempRepo {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    fn source_args(repo: &TempRepo) -> SoliditySourceCliArgs {
        // Mirror the clap defaults — when constructed via `clap::parse`
        // these get populated from `default_value`, but direct
        // construction in tests has to spell them out.
        SoliditySourceCliArgs {
            repo_root: repo.path.clone(),
            tree_sitter_include_globs: vec!["**/*.sol".to_string()],
            tree_sitter_exclude_globs: [".git", ".git/**", "**/.git", "**/.git/**"]
                .into_iter()
                .map(str::to_string)
                .collect(),
        }
    }

    fn scope_args(ignore_scope_file: bool) -> SolidityAnalysisScopeCliArgs {
        SolidityAnalysisScopeCliArgs {
            analysis_scope_globs: Vec::new(),
            analysis_scope_exclude_globs: [
                ".git",
                ".git/**",
                "**/.git",
                "**/.git/**",
                "target",
                "target/**",
                "**/target",
                "**/target/**",
                "node_modules",
                "node_modules/**",
                "**/node_modules",
                "**/node_modules/**",
                "artifacts",
                "artifacts/**",
                "**/artifacts",
                "**/artifacts/**",
                "cache",
                "cache/**",
                "**/cache",
                "**/cache/**",
                "build",
                "build/**",
                "**/build",
                "**/build/**",
            ]
            .into_iter()
            .map(str::to_string)
            .collect(),
            ignore_scope_file,
        }
    }

    #[test]
    fn extraction_config_uses_scope_txt_by_default() {
        let repo = TempRepo::new();
        repo.write("src/App.sol", "contract App {}");
        repo.write("src/Other.sol", "contract Other {}");
        repo.write("node_modules/Dep.sol", "contract Dep {}");
        repo.write("target/Generated.sol", "contract Generated {}");
        repo.write(".git/Ignored.sol", "contract Ignored {}");
        repo.write("scope.txt", "src/App.sol\n");

        let config = build_solidity_extraction_config(&source_args(&repo), &scope_args(false))
            .expect("extraction config should build");

        assert!(config.source_files.contains(&PathBuf::from("src/App.sol")));
        assert!(
            config
                .source_files
                .contains(&PathBuf::from("node_modules/Dep.sol"))
        );
        assert!(
            !config
                .source_files
                .contains(&PathBuf::from(".git/Ignored.sol"))
        );
        assert_eq!(
            config.analysis_source_files,
            vec![PathBuf::from("src/App.sol")]
        );
    }

    #[test]
    fn extraction_config_can_ignore_scope_txt() {
        let repo = TempRepo::new();
        repo.write("src/App.sol", "contract App {}");
        repo.write("src/Other.sol", "contract Other {}");
        repo.write("node_modules/Dep.sol", "contract Dep {}");
        repo.write("target/Generated.sol", "contract Generated {}");
        repo.write("scope.txt", "src/App.sol\n");

        let config = build_solidity_extraction_config(&source_args(&repo), &scope_args(true))
            .expect("extraction config should build");

        assert_eq!(
            config.analysis_source_files,
            vec![PathBuf::from("src/App.sol"), PathBuf::from("src/Other.sol")]
        );
    }
}
