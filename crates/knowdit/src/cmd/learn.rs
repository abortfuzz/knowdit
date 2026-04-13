use crate::cmd::finding_link_args::FindingLinkCliArgs;
use crate::cmd::merge_args::MergeCliArgs;
use clap::{Args, ValueEnum};
use color_eyre::eyre::Result;
use knowdit_kg::db::DatabaseGraph;
use knowdit_kg::error::KgError;
use knowdit_kg::learn::{
    ExtractResult, FindingLinkOptions, MergeRetryOptions, link_pending_findings,
};
use knowdit_kg::project_loader::{MovePlatform, ProjectData};
use llmy::clap::OpenAISetup;
use std::collections::HashMap;
use std::path::PathBuf;
use tokio::sync::mpsc;
use tokio::task::JoinSet;

#[derive(Args)]
pub struct LearnArgs {
    /// Project directories to learn. Format: "name:path" or "name:path:platform_id"
    #[arg(long = "project", short = 'p')]
    projects: Vec<String>,

    /// Number of projects to categorize+extract concurrently (merge is always serial)
    #[arg(long, default_value_t = 1)]
    concurrency: usize,

    /// Run finding-to-semantic linking after all projects are written
    #[arg(long)]
    link: bool,

    #[command(flatten)]
    merge: MergeCliArgs,

    #[command(flatten)]
    finding_link: FindingLinkCliArgs,
}

#[derive(Args)]
pub struct LearnC4Args {
    /// Code4rena data directory (expects audits/ and contracts/ subdirs)
    #[arg(long)]
    c4_dir: PathBuf,

    /// Specific Code4rena contest IDs to process
    #[arg(long, value_delimiter = ',')]
    c4_ids: Vec<u32>,

    /// Maximum number of C4 projects to process (when no --c4-ids given)
    #[arg(long, default_value_t = 5)]
    limit: usize,

    /// Number of projects to categorize+extract concurrently (merge is always serial)
    #[arg(long, default_value_t = 1)]
    concurrency: usize,

    /// Run finding-to-semantic linking after all projects are written
    #[arg(long)]
    link: bool,

    #[command(flatten)]
    merge: MergeCliArgs,

    #[command(flatten)]
    finding_link: FindingLinkCliArgs,
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
    /// Move dataset directory (expects _codebase_apt/_codebase_sui and vulnerability dirs)
    #[arg(long, default_value = "moves")]
    moves_dir: PathBuf,

    /// Specific Move project commit hashes to process
    #[arg(long, value_delimiter = ',')]
    commits: Vec<String>,

    /// Restrict the dataset to specific Move ecosystems
    #[arg(long, value_enum, value_delimiter = ',')]
    platforms: Vec<MovePlatformArg>,

    /// Maximum number of Move projects to process (when no --commits given)
    #[arg(long, default_value_t = 5)]
    limit: usize,

    /// Number of projects to categorize+extract concurrently (merge is always serial)
    #[arg(long, default_value_t = 1)]
    concurrency: usize,

    /// Run finding-to-semantic linking after all projects are written
    #[arg(long)]
    link: bool,

    #[command(flatten)]
    merge: MergeCliArgs,

    #[command(flatten)]
    finding_link: FindingLinkCliArgs,
}

pub async fn run_learn(db: &DatabaseGraph, llm_setup: &OpenAISetup, args: LearnArgs) -> Result<()> {
    args.merge.validate()?;
    args.finding_link.validate()?;

    let llm = llm_setup.clone().to_llm();
    let mut all_projects = Vec::new();

    for spec in &args.projects {
        let parts: Vec<&str> = spec.splitn(3, ':').collect();
        let (name, path, platform_id) = match parts.len() {
            2 => (parts[0], parts[1], None),
            3 => (parts[0], parts[1], Some(parts[2])),
            _ => {
                tracing::error!(
                    "Invalid project spec '{}'. Use 'name:path' or 'name:path:platform_id'",
                    spec
                );
                continue;
            }
        };
        match ProjectData::from_dir(name, &PathBuf::from(path), platform_id) {
            Ok(data) => all_projects.push(data),
            Err(e) => tracing::error!("Failed to load project '{}': {}", name, e),
        }
    }

    run_pipeline(
        db,
        &llm,
        all_projects,
        args.concurrency,
        args.link,
        args.merge.to_options(),
        args.finding_link.to_options(args.concurrency),
    )
    .await
}

pub async fn run_learn_c4(
    db: &DatabaseGraph,
    llm_setup: &OpenAISetup,
    args: LearnC4Args,
) -> Result<()> {
    args.merge.validate()?;
    args.finding_link.validate()?;

    let llm = llm_setup.clone().to_llm();
    let mut all_projects = Vec::new();

    let contest_ids: Vec<u32> = if !args.c4_ids.is_empty() {
        args.c4_ids
    } else {
        let mut all = knowdit_kg::project_loader::list_contest_ids(&args.c4_dir)?;
        all.sort_unstable_by(|a, b| b.cmp(a));
        all.into_iter().take(args.limit).collect()
    };

    for c4id in &contest_ids {
        match ProjectData::from_c4(&args.c4_dir, *c4id) {
            Ok(data) => all_projects.push(data),
            Err(e) => tracing::error!("Failed to load c4 project {}: {}", c4id, e),
        }
    }

    run_pipeline(
        db,
        &llm,
        all_projects,
        args.concurrency,
        args.link,
        args.merge.to_options(),
        args.finding_link.to_options(args.concurrency),
    )
    .await
}

pub async fn run_learn_moves(
    db: &DatabaseGraph,
    llm_setup: &OpenAISetup,
    args: LearnMovesArgs,
) -> Result<()> {
    args.merge.validate()?;
    args.finding_link.validate()?;

    let llm = llm_setup.clone().to_llm();
    let platforms: Vec<MovePlatform> = args.platforms.iter().copied().map(Into::into).collect();
    let audit_reports =
        knowdit_kg::project_loader::load_move_audit_reports(&args.moves_dir, &platforms)?;
    let discovered = knowdit_kg::project_loader::list_move_projects(&args.moves_dir, &platforms)?;
    let mut all_projects = Vec::new();

    if !args.commits.is_empty() {
        let mut by_commit: HashMap<String, knowdit_kg::project_loader::MoveProjectDescriptor> =
            discovered
                .into_iter()
                .map(|project| (project.commit_hash.clone(), project))
                .collect();

        for commit_hash in &args.commits {
            match by_commit.remove(commit_hash) {
                Some(project) => {
                    let report = audit_reports.get(&project.commit_hash).cloned();
                    all_projects.push(project.into_project_data(report)?);
                }
                None => tracing::error!(
                    "Move project commit {} not found under {}",
                    commit_hash,
                    args.moves_dir.display()
                ),
            }
        }
    } else {
        for project in discovered.into_iter().take(args.limit) {
            let report = audit_reports.get(&project.commit_hash).cloned();
            all_projects.push(project.into_project_data(report)?);
        }
    }

    run_pipeline(
        db,
        &llm,
        all_projects,
        args.concurrency,
        args.link,
        args.merge.to_options(),
        args.finding_link.to_options(args.concurrency),
    )
    .await
}

/// Shared pipeline: categorize+extract concurrently, then merge+write each
/// project serially as soon as extraction finishes.
async fn run_pipeline(
    db: &DatabaseGraph,
    llm: &llmy::client::client::LLM,
    all_projects: Vec<ProjectData>,
    concurrency: usize,
    link: bool,
    merge_options: MergeRetryOptions,
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
            link_pending_findings(db, llm, link_options).await?;
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
            match project.categorize_and_extract(llm).await {
                Ok(extract) => {
                    if let Err(e) = project
                        .merge_and_write(db, llm, &extract, merge_options)
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
            handles.spawn(async move {
                while let Ok(project) = rx.recv().await {
                    let res = project.categorize_and_extract(&llm).await?;
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
                .merge_and_write(db, llm, &extract_res, merge_options)
                .await?;
        }
    }

    if link {
        link_pending_findings(db, llm, link_options).await?;
    }

    tracing::info!("Learning complete.");
    Ok(())
}
