use std::io::IsTerminal;

use clap::{Parser, Subcommand};
use knowdit_kg::db::DatabaseGraph;
use llmy::clap::OpenAISetup;

mod cmd;
mod ingest;

#[derive(Parser)]
#[command(name = "knowdit", about = "DeFi audit knowledge graph builder")]
struct KnowditCommand {
    #[command(subcommand)]
    command: Commands,

    /// Database connection URL (supports sqlite://, mysql://, postgres://).
    #[arg(
        long,
        env = "DATABASE_URL",
        default_value = "sqlite://knowdit.db?mode=rwc"
    )]
    database_url: String,

    #[command(flatten)]
    llm: OpenAISetup,
}

#[derive(Subcommand)]
enum Commands {
    /// Process projects to extract DeFi semantics into the knowledge graph
    Learn(cmd::learn::LearnArgs),

    /// Process Code4rena projects from the out_train directory
    LearnC4(cmd::learn::LearnC4Args),

    /// Process Move projects from the moves dataset
    LearnMoves(cmd::learn::LearnMovesArgs),

    /// Link pending audit findings to DeFi semantics
    Link(cmd::link::LinkArgs),

    /// Clear finding-to-semantic linking progress for rerunning link experiments
    ResetLinking(cmd::reset_linking::ResetLinkingArgs),

    /// Validate database referential integrity; optionally repair dangling relation rows
    ValidateDb(cmd::validate_db::ValidateDbArgs),

    /// Assign a platform ID to an existing project
    SetPlatformId(cmd::set_platform_id::SetPlatformIdArgs),

    /// List all DeFi semantics for a given project
    ListSemantics(cmd::list_semantics::ListSemanticsArgs),

    /// Search semantics by keyword
    SearchSemantics(cmd::search_semantics::SearchSemanticsArgs),

    /// List all completed projects
    ListProjects,

    /// Initialize the database (creates tables and seeds categories)
    InitDb,

    /// Export the current database as a SQL or JSON snapshot
    SnapshotDb(cmd::snapshot_db::SnapshotDbArgs),

    /// Import a SQL or JSON snapshot into the current database
    ImportDbSnapshot(cmd::import_db_snapshot::ImportDbSnapshotArgs),

    /// Export knowledge graph as DOT file for visualization
    ExportDot(cmd::export_dot::ExportDotArgs),

    /// Export knowledge graph as an interactive HTML graph
    ExportHtml(cmd::export_html::ExportHtmlArgs),
}

impl Commands {
    fn requires_initialized_db(&self) -> bool {
        !matches!(self, Self::SnapshotDb(_) | Self::ImportDbSnapshot(_))
    }
}

async fn main_entry(cmd: KnowditCommand) -> color_eyre::Result<()> {
    let db = DatabaseGraph::connect(&cmd.database_url).await?;
    if cmd.command.requires_initialized_db() {
        db.init().await?;
    }

    match cmd.command {
        Commands::Learn(args) => cmd::learn::run_learn(&db, &cmd.llm, args).await?,
        Commands::LearnC4(args) => cmd::learn::run_learn_c4(&db, &cmd.llm, args).await?,
        Commands::LearnMoves(args) => cmd::learn::run_learn_moves(&db, &cmd.llm, args).await?,
        Commands::Link(args) => cmd::link::run(&db, &cmd.llm, args).await?,
        Commands::ResetLinking(args) => cmd::reset_linking::run(&db, args).await?,
        Commands::ValidateDb(args) => cmd::validate_db::run(&db, args).await?,
        Commands::SetPlatformId(args) => cmd::set_platform_id::run(&db, args).await?,
        Commands::ListSemantics(args) => cmd::list_semantics::run(&db, args).await?,
        Commands::SearchSemantics(args) => cmd::search_semantics::run(&db, args).await?,
        Commands::ListProjects => cmd::list_projects::run(&db).await?,
        Commands::InitDb => cmd::init_db::run(&db).await?,
        Commands::SnapshotDb(args) => cmd::snapshot_db::run(&db, args).await?,
        Commands::ImportDbSnapshot(args) => cmd::import_db_snapshot::run(&db, args).await?,
        Commands::ExportDot(args) => cmd::export_dot::run(&db, args).await?,
        Commands::ExportHtml(args) => cmd::export_html::run(&db, args).await?,
    }

    Ok(())
}

fn main() {
    let use_colors = std::io::stdout().is_terminal()
        && std::io::stderr().is_terminal()
        && std::env::var("NO_COLOR") == Err(std::env::VarError::NotPresent);
    if use_colors {
        color_eyre::install().expect("init color_eyre");
    } else {
        color_eyre::config::HookBuilder::new()
            .theme(color_eyre::config::Theme::new())
            .install()
            .expect("init no color color_eyre");
    }
    if let Ok(dot_file) = std::env::var("DOT") {
        dotenvy::from_path(dot_file).expect("can not read dotenvy");
    } else {
        let _ = dotenvy::dotenv();
    }
    let sub = tracing_subscriber::FmtSubscriber::builder()
        .with_env_filter(
            tracing_subscriber::EnvFilter::builder()
                .with_default_directive(tracing::Level::INFO.into())
                .from_env()
                .expect("env contains non-utf8"),
        )
        .with_ansi(use_colors)
        .finish();
    tracing::subscriber::set_global_default(sub).expect("can not set default tracing");

    let cmd = KnowditCommand::parse();

    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("can not build tokio")
        .block_on(main_entry(cmd))
        .expect("main entry failed");
}
