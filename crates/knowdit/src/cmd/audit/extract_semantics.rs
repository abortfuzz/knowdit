use clap::Args;
use color_eyre::eyre::Result;
use knowdit_kg::agent_runner::AgentRunOptions;
use knowdit_kg::learn::ExtractedSemantic;
use knowdit_project::ProjectData;
use knowdit_repo_model::RepoDatabase;
use llmy::client::client::LLM;
use std::path::PathBuf;

use crate::cli::{DatabaseArgs, LoadedRepoDatabase, ProjectArgs};

/// Knobs for the extract-semantics phase. Flattened by both the CLI
/// `agentic extract-semantics` subcommand and `workflow autoloop`,
/// so every default value is centralized here via `default_value_t`.
#[derive(Args, Clone, Debug)]
pub struct ExtractSemanticsSharedArgs {
    /// Optional override for the per-chunk *input* token budget passed
    /// to `extract_semantics`. Defaults to ~80% of the model's
    /// `max_input`.
    #[arg(long = "extract-chunk-input-budget")]
    pub extract_chunk_input_budget: Option<usize>,

    /// Hard cap on agent steps for the categorize / extract-semantic
    /// agents. Each `emit_*` tool call counts as one step.
    #[arg(long = "extract-max-agent-steps", default_value_t = 60)]
    pub extract_max_agent_steps: usize,

    /// Fraction (0,1] of the model's context window a single categorize /
    /// extract prompt may fill. Lower = more, smaller prompts with sharper
    /// attention. Prefixed to stay collision-free when co-flattened.
    #[arg(
        long = "extract-context-window-utilization",
        default_value_t = knowdit_kg::learn::DEFAULT_CONTEXT_WINDOW_UTILIZATION
    )]
    pub extract_context_window_utilization: f64,
}

#[derive(Args)]
pub struct ExtractSemanticsArgs {
    #[command(flatten)]
    pub project: ProjectArgs,

    #[command(flatten)]
    pub db: DatabaseArgs,

    #[command(flatten)]
    pub shared: ExtractSemanticsSharedArgs,

    /// Optional JSON dump of the extracted semantics for human
    /// inspection. The canonical source of truth is still the project
    /// DB; omit this flag when you don't need the file. CLI-only —
    /// the autoloop manages its own dumps.
    #[arg(long)]
    pub out: Option<PathBuf>,
}

impl ExtractSemanticsArgs {
    /// CLI entry: open the repo DB + load the project corpus from
    /// disk, then delegate to [`Self::extract_semantics`].
    pub async fn run(self, llm: &LLM) -> Result<()> {
        let project = self.project.to_project_data().await?;
        let LoadedRepoDatabase { repo, .. } = self
            .project
            .to_repo_database(self.db.database_path.clone(), self.db.variant_render_cap)
            .await?;
        let semantics = Self::extract_semantics(&repo, llm, &project, &self.shared).await?;
        if let Some(out) = self.out.as_ref() {
            if let Some(parent) = out.parent().filter(|parent| !parent.as_os_str().is_empty()) {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::write(out, serde_json::to_string_pretty(&semantics)?)?;
            tracing::info!("Semantic specs written to {}", out.display());
        }
        Ok(())
    }

    /// In-process entry: load already-extracted semantics from the
    /// repo DB, or run the LLM-driven extractor when the table is
    /// empty. All knobs come from `shared`, all heavy resources from
    /// the caller — no `&self`.
    pub async fn extract_semantics(
        repo: &RepoDatabase,
        llm: &LLM,
        project: &ProjectData,
        shared: &ExtractSemanticsSharedArgs,
    ) -> Result<Vec<ExtractedSemantic>> {
        let agent_options = AgentRunOptions::new(shared.extract_max_agent_steps)
            .with_context_window_utilization(shared.extract_context_window_utilization);
        load_or_extract_project_semantics(
            repo,
            llm,
            project,
            shared.extract_chunk_input_budget,
            &agent_options,
        )
        .await
    }
}

/// Load already-extracted semantics from the project DB, or — when
/// the table is empty — run the LLM-driven semantic extractor and
/// persist the result. The extraction goes through the legacy
/// `knowdit_kg::project_loader::ProjectData` shape because the agent
/// loop and its prompt helpers still live there; the caller's
/// `&knowdit_project::ProjectData` is adapted at this boundary via
/// `ProjectData::from_project_view` and the in-memory bridge stays
/// local to this fn.
pub(crate) async fn load_or_extract_project_semantics(
    repo: &RepoDatabase,
    llm: &LLM,
    project: &ProjectData,
    extract_chunk_input_budget: Option<usize>,
    agent_options: &AgentRunOptions,
) -> Result<Vec<ExtractedSemantic>> {
    let existing = repo.load_project_semantics().await?;
    if !existing.is_empty() {
        tracing::info!(
            "Loaded {} project semantics for {} from project database",
            existing.len(),
            project.display_id()
        );
        return Ok(existing);
    }

    tracing::info!(
        "No project semantics found for {}; extracting semantics before analysis",
        project.display_id()
    );
    let legacy = knowdit_kg::project_loader::ProjectData::from_project_view(project);
    let extract = legacy
        .categorize_and_extract_semantics(llm, agent_options, extract_chunk_input_budget)
        .await?;
    repo.replace_project_semantics(&extract.semantics).await?;
    tracing::info!(
        "Wrote {} project semantics for {} to project database",
        extract.semantics.len(),
        project.display_id()
    );
    Ok(extract.semantics)
}
