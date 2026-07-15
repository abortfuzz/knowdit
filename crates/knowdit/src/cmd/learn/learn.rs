use crate::cmd::learn::finding_link_args::FindingLinkCliArgs;
use crate::cmd::learn::merge_args::MergeCliArgs;
use clap::{Args, ValueEnum};
use color_eyre::eyre::{Result, WrapErr};
use knowdit_kg::db::HistoricalDatabase;
use knowdit_kg::error::KgError;
use knowdit_kg::learn::{ExtractResult, FindingLinkOptions};
use knowdit_kg::project_loader::{MovePlatform, ProjectData};
use llmy::clap::OpenAISetup;
use std::collections::HashMap;
use std::path::PathBuf;
use tokio::sync::mpsc;
use tokio::task::JoinSet;

#[derive(Args)]
pub struct LearnArgs {
    #[command(flatten)]
    pub llm: OpenAISetup,

    /// Project directories to learn. Format: "name:path" or "name:path:platform_id"
    #[arg(long = "project", short = 'p')]
    pub projects: Vec<String>,

    /// Number of projects to categorize+extract concurrently (merge is always serial)
    #[arg(long, default_value_t = 1)]
    pub concurrency: usize,

    /// Run finding-to-semantic linking after all projects are written
    #[arg(long)]
    pub link: bool,

    #[command(flatten)]
    pub merge: MergeCliArgs,

    #[command(flatten)]
    pub finding_link: FindingLinkCliArgs,
}

#[derive(Args)]
pub struct LearnC4Args {
    #[command(flatten)]
    pub llm: OpenAISetup,

    /// Code4rena data directory (expects audits/ and contracts/ subdirs)
    #[arg(long)]
    pub c4_dir: PathBuf,

    /// Specific Code4rena contest IDs to process
    #[arg(long, value_delimiter = ',')]
    pub c4_ids: Vec<u32>,

    /// Code4rena contest IDs to skip. Applied after `--c4-ids`
    /// selection (or the full discovered set when `--c4-ids` is
    /// empty) and before `--limit` truncates. Useful for resuming
    /// past projects that previously failed to load or were already
    /// learned out-of-band.
    #[arg(long, value_delimiter = ',')]
    pub skip_ids: Vec<u32>,

    /// Maximum number of C4 projects to process (when no --c4-ids given)
    #[arg(long, default_value_t = 5)]
    pub limit: usize,

    /// Number of projects to categorize+extract concurrently (merge is always serial)
    #[arg(long, default_value_t = 1)]
    pub concurrency: usize,

    /// Run finding-to-semantic linking after all projects are written
    #[arg(long)]
    pub link: bool,

    #[command(flatten)]
    pub merge: MergeCliArgs,

    #[command(flatten)]
    pub finding_link: FindingLinkCliArgs,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum MovePlatformArg {
    Aptos,
    Sui,
}

impl From<MovePlatformArg> for MovePlatform {
    fn from(value: MovePlatformArg) -> Self {
        match value {
            MovePlatformArg::Aptos => MovePlatform::Aptos,
            MovePlatformArg::Sui => MovePlatform::Sui,
        }
    }
}

#[derive(Args)]
pub struct LearnMovesArgs {
    #[command(flatten)]
    pub llm: OpenAISetup,

    /// Move dataset directory (expects _codebase_apt/_codebase_sui and vulnerability dirs)
    #[arg(long, default_value = "moves")]
    pub moves_dir: PathBuf,

    /// Specific Move project commit hashes to process
    #[arg(long, value_delimiter = ',')]
    pub commits: Vec<String>,

    /// Restrict the dataset to specific Move ecosystems
    #[arg(long, value_enum, value_delimiter = ',')]
    pub platforms: Vec<MovePlatformArg>,

    /// Number of projects to categorize+extract concurrently (merge is always serial)
    #[arg(long, default_value_t = 1)]
    pub concurrency: usize,

    /// Run finding-to-semantic linking after all projects are written
    #[arg(long)]
    pub link: bool,

    #[command(flatten)]
    pub merge: MergeCliArgs,

    #[command(flatten)]
    pub finding_link: FindingLinkCliArgs,
}

impl LearnArgs {
    pub async fn run(self, db: &HistoricalDatabase) -> Result<()> {
        self.merge.validate()?;
        self.finding_link.validate()?;

        let llm = self.llm.clone().to_llm().await;
        let mut all_projects = Vec::new();

        for spec in &self.projects {
            match ProjectData::from_path_spec(spec).await {
                Ok(data) => all_projects.push(data),
                Err(e) => tracing::error!("Failed to load project '{}': {}", spec, e),
            }
        }

        run_pipeline(
            db,
            &llm,
            all_projects,
            self.concurrency,
            self.link,
            self.merge.to_agent_options(),
            self.merge.to_chunking_options(),
            self.finding_link.to_options(self.concurrency),
        )
        .await
    }
}

impl LearnC4Args {
    pub async fn run(self, db: &HistoricalDatabase) -> Result<()> {
        self.merge.validate()?;
        self.finding_link.validate()?;

        let llm = self.llm.clone().to_llm().await;
        let mut all_projects = Vec::new();

        let contest_ids: Vec<u32> = if !self.c4_ids.is_empty() {
            self.c4_ids
        } else {
            let mut all = knowdit_kg::project_loader::list_contest_ids(&self.c4_dir)?;
            all.sort_unstable_by(|a, b| b.cmp(a));
            all.into_iter().collect()
        };

        let skip: std::collections::HashSet<u32> = self.skip_ids.iter().copied().collect();
        let contest_ids: Vec<u32> = contest_ids
            .into_iter()
            .filter(|id| {
                if skip.contains(id) {
                    tracing::info!("Skipping c4 contest {} (in --skip-ids)", id);
                    false
                } else {
                    true
                }
            })
            .collect();

        for c4id in &contest_ids {
            match ProjectData::from_c4(&self.c4_dir, *c4id).await {
                Ok(data) => all_projects.push(data),
                Err(e) => tracing::error!("Failed to load c4 project {}: {}", c4id, e),
            }
        }

        run_pipeline(
            db,
            &llm,
            all_projects,
            self.concurrency,
            self.link,
            self.merge.to_agent_options(),
            self.merge.to_chunking_options(),
            self.finding_link.to_options(self.concurrency),
        )
        .await
    }
}

impl LearnMovesArgs {
    pub async fn run(self, db: &HistoricalDatabase) -> Result<()> {
        self.merge.validate()?;
        self.finding_link.validate()?;

        let llm = self.llm.clone().to_llm().await;
        let platforms: Vec<MovePlatform> = self.platforms.iter().copied().map(Into::into).collect();
        let audit_reports =
            knowdit_kg::project_loader::load_move_audit_reports(&self.moves_dir, &platforms)?;
        let discovered =
            knowdit_kg::project_loader::list_move_projects(&self.moves_dir, &platforms)?;
        let mut all_projects = Vec::new();

        if !self.commits.is_empty() {
            let mut by_commit: HashMap<String, knowdit_kg::project_loader::MoveProjectDescriptor> =
                discovered
                    .into_iter()
                    .map(|project| (project.commit_hash.clone(), project))
                    .collect();

            for commit_hash in &self.commits {
                match by_commit.remove(commit_hash) {
                    Some(project) => {
                        let report = audit_reports.get(&project.commit_hash).cloned();
                        all_projects.push(
                            ProjectData::from_move_snapshot(
                                &project.name,
                                &project.root_dir,
                                &project.commit_hash,
                                report,
                            )
                            .await?,
                        );
                    }
                    None => tracing::error!(
                        "Move project commit {} not found under {}",
                        commit_hash,
                        self.moves_dir.display()
                    ),
                }
            }
        } else {
            for project in discovered.into_iter() {
                let report = audit_reports.get(&project.commit_hash).cloned();
                match ProjectData::from_move_snapshot(
                    &project.name,
                    &project.root_dir,
                    &project.commit_hash,
                    report,
                )
                .await
                {
                    Ok(project) => {
                        all_projects.push(project);
                    }
                    Err(e) => {
                        tracing::warn!("Skipping {} due to {}", project.root_dir.display(), e);
                    }
                }
            }
        }

        run_pipeline(
            db,
            &llm,
            all_projects,
            self.concurrency,
            self.link,
            self.merge.to_agent_options(),
            self.merge.to_chunking_options(),
            self.finding_link.to_options(self.concurrency),
        )
        .await
    }
}

#[derive(Args)]
pub struct LearnSherlockArgs {
    #[command(flatten)]
    pub llm: OpenAISetup,

    /// sherlock-scrape output directory (expects metadata/, source/, reports/)
    #[arg(long)]
    pub sherlock_dir: PathBuf,

    /// Specific Sherlock contest IDs to process (default: all discovered)
    #[arg(long, value_delimiter = ',')]
    pub sherlock_ids: Vec<u32>,

    /// Contest IDs to skip, applied after --sherlock-ids / discovery
    #[arg(long, value_delimiter = ',')]
    pub skip_ids: Vec<u32>,

    /// Max contests to process (0 = no limit). Applied after skip.
    #[arg(long, default_value_t = 0)]
    pub limit: usize,

    /// Projects to categorize+extract concurrently (merge is always serial)
    #[arg(long, default_value_t = 1)]
    pub concurrency: usize,

    /// Run finding-to-semantic linking after all projects are written
    #[arg(long)]
    pub link: bool,

    #[command(flatten)]
    pub merge: MergeCliArgs,

    #[command(flatten)]
    pub finding_link: FindingLinkCliArgs,
}

impl LearnSherlockArgs {
    pub async fn run(self, db: &HistoricalDatabase) -> Result<()> {
        self.merge.validate()?;
        self.finding_link.validate()?;

        let llm = self.llm.clone().to_llm().await;

        let mut ids: Vec<u32> = if !self.sherlock_ids.is_empty() {
            self.sherlock_ids.clone()
        } else {
            // Discover contests by their `metadata/<id>.json` files.
            let meta_dir = self.sherlock_dir.join("metadata");
            let mut all = Vec::new();
            for entry in std::fs::read_dir(&meta_dir)
                .wrap_err_with(|| format!("failed to read {}", meta_dir.display()))?
            {
                let path = entry?.path();
                if path.extension().and_then(|ext| ext.to_str()) == Some("json")
                    && let Some(id) = path
                        .file_stem()
                        .and_then(|stem| stem.to_str())
                        .and_then(|stem| stem.parse::<u32>().ok())
                {
                    all.push(id);
                }
            }
            all.sort_unstable();
            all
        };
        let skip: std::collections::HashSet<u32> = self.skip_ids.iter().copied().collect();
        ids.retain(|id| !skip.contains(id));
        if self.limit > 0 && ids.len() > self.limit {
            ids.truncate(self.limit);
        }

        let mut all_projects = Vec::new();
        for id in &ids {
            match ProjectData::from_sherlock(&self.sherlock_dir, *id).await {
                Ok(Some(data)) => all_projects.push(data),
                Ok(None) => {
                    tracing::info!("Skipping sherlock contest {} (no scope / unsupported)", id)
                }
                Err(e) => tracing::error!("Failed to load sherlock contest {}: {}", id, e),
            }
        }
        tracing::info!(
            "Loaded {} ingestible sherlock contest(s)",
            all_projects.len()
        );

        run_pipeline(
            db,
            &llm,
            all_projects,
            self.concurrency,
            self.link,
            self.merge.to_agent_options(),
            self.merge.to_chunking_options(),
            self.finding_link.to_options(self.concurrency),
        )
        .await
    }
}

/// Shared pipeline: categorize+extract concurrently, then merge+write each
/// project serially as soon as extraction finishes.
async fn run_pipeline(
    db: &HistoricalDatabase,
    llm: &llmy::client::client::LLM,
    all_projects: Vec<ProjectData>,
    concurrency: usize,
    link: bool,
    agent_options: knowdit_kg::agent_runner::AgentRunOptions,
    merge_chunking: knowdit_kg::agents::MergeChunkingOptions,
    link_options: FindingLinkOptions,
) -> Result<()> {
    if all_projects.is_empty() {
        tracing::warn!("No projects to process.");
        return Ok(());
    }

    // Filter out already-completed projects
    let mut pending = Vec::new();
    for p in all_projects {
        match p.is_completed(db).await {
            Ok(true) => {
                tracing::info!("Project {} already completed, skipping", p.display_id());
            }
            Ok(false) => pending.push(p),
            Err(e) => tracing::error!("Error checking project {}: {}", p.display_id(), e),
        }
    }

    if pending.is_empty() {
        tracing::info!("All projects already completed.");
        if link {
            link_options.link_pending_findings(db, llm).await?;
        }
        return Ok(());
    }

    tracing::info!(
        "Will process {} projects (concurrency={}): {:?}",
        pending.len(),
        concurrency,
        pending.iter().map(|p| p.display_id()).collect::<Vec<_>>()
    );

    if concurrency <= 1 {
        for project in pending {
            match project
                .categorize_and_extract(llm, &agent_options, None)
                .await
            {
                Ok(extract) => {
                    if let Err(e) = project
                        .merge_and_write(db, llm, &extract, &agent_options, merge_chunking)
                        .await
                    {
                        tracing::error!(
                            "Failed to merge/write project {}: {}",
                            project.display_id(),
                            e
                        );
                    }
                }
                Err(e) => {
                    tracing::error!(
                        "Skipping merge for project {} (extract failed: {})",
                        project.display_id(),
                        e
                    );
                }
            }
        }
    } else {
        let (tx, rx) = async_channel::bounded::<ProjectData>(pending.len() + 1);
        let (out_tx, mut out_rx) =
            mpsc::channel::<Result<(ProjectData, ExtractResult)>>(concurrency + 1);

        let mut handles = JoinSet::new();
        for _ in 0..concurrency {
            let rx = rx.clone();
            let out = out_tx.clone();
            let llm = llm.clone();
            let extract_opts = agent_options.clone();
            handles.spawn(async move {
                while let Ok(project) = rx.recv().await {
                    let res = project
                        .categorize_and_extract(&llm, &extract_opts, None)
                        .await?;
                    out.send(Ok((project, res)))
                        .await
                        .expect("can not send out project");
                }
                Ok::<_, KgError>(())
            });
        }
        drop(out_tx);
        drop(rx);

        for project in pending {
            tx.send(project).await.expect("fail to send out");
        }

        drop(tx);
        while let Some(handle) = out_rx.recv().await {
            let (project, extract_res): (ProjectData, ExtractResult) = handle?;

            project
                .merge_and_write(db, llm, &extract_res, &agent_options, merge_chunking)
                .await?;
        }
    }

    if link {
        link_options.link_pending_findings(db, llm).await?;
    }

    tracing::info!("Learning complete.");
    Ok(())
}
