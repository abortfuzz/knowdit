//! Library surface for the `knowdit` binary. Other programs can embed
//! the same CLI tree by depending on this crate and constructing /
//! dispatching [`KnowditCommand`] (or any of its sub-commands)
//! directly.

use clap::{Args, Parser, Subcommand};
use llmy::clap::OpenAISetup;

use crate::cli::HistoricalDatabaseArgs;

pub mod cli;
pub mod cmd;

#[derive(Parser)]
#[command(name = "knowdit", about = "DeFi audit knowledge graph builder")]
pub struct KnowditCommand {
    #[command(subcommand)]
    pub command: KnowditSubCommands,
}

#[derive(Subcommand)]
pub enum KnowditSubCommands {
    /// Learn reusable historical audit experience into the historical database
    Learn(LearnCommand),

    /// Non-LLM project tooling: Solidity tree-sitter / AST extraction and Move callgraph extraction
    Static(StaticCommand),

    /// Run project-specific agentic (LLM-driven) audit workflows against a project database
    Agentic(AgenticCommand),

    /// End-to-end pipeline orchestrators that chain multiple agentic + static phases
    Workflow(WorkflowCommand),

    /// Historical-KG database tools: snapshot in/out and direct DB-to-DB copy (no LLM)
    Db(DbCommand),
}

#[derive(Args)]
pub struct WorkflowCommand {
    // No `HistoricalDatabaseArgs` here — only the autoloop's
    // map-semantics phase actually needs the KG and it flattens its
    // own copy on `AutoloopArgs`.
    #[command(flatten)]
    pub llm: OpenAISetup,

    #[command(subcommand)]
    pub command: WorkflowCommands,
}

#[derive(Subcommand)]
pub enum WorkflowCommands {
    /// One-shot orchestrator: chains `static solidity call-graph` →
    /// `agentic extract-semantics` → `agentic map-semantics` →
    /// `agentic gen-specs` → `agentic fuzz` → `agentic reflect`,
    /// sharing one global LLM budget across phases.
    Autoloop(cmd::workflow::autoloop::AutoloopArgs),

    /// Streamed orchestrator: process links in round-robin extract
    /// order and immediately run downstream codegen / reflect / regen
    /// after each committed spec.
    Streamloop(cmd::workflow::streamloop::StreamloopArgs),

    /// Admit one new project into the historical KG: categorize +
    /// extract + dedup-merge, then retro-link prior findings
    /// against the new canonical semantics, then link the new
    /// findings against every canonical. One LLM budget shared
    /// across all three phases.
    Learn(cmd::workflow::learn::WorkflowLearnArgs),
}

/// `knowdit db ...` — non-LLM tools that operate on the historical
/// KG database itself (snapshots and direct DB-to-DB copy). Lives
/// outside `learn` because none of these need an LLM, and outside
/// `workflow` because `workflow` flattens an `OpenAISetup` that
/// these subcommands don't need.
#[derive(Args)]
pub struct DbCommand {
    #[command(subcommand)]
    pub command: DbCommands,
}

#[derive(Subcommand)]
pub enum DbCommands {
    /// Export the historical KG as a SQL or JSON snapshot file
    Snapshot(cmd::db::snapshot::SnapshotArgs),

    /// Import a SQL or JSON snapshot file into the historical KG
    ImportSnapshot(cmd::db::import_snapshot::ImportSnapshotArgs),

    /// Copy every row of every historical-KG table from `--src-db`
    /// into `--dst-db`. By default merges into dst's existing
    /// schema (auto-incr PKs reassigned, FKs rewritten); pass
    /// `--fresh` to instead drop and recreate dst's schema first.
    Copy(cmd::db::copy::CopyArgs),
}

// ---------------------------------------------------------------------------
// `knowdit static ...` — non-LLM commands
// ---------------------------------------------------------------------------

#[derive(Args)]
pub struct StaticCommand {
    #[command(subcommand)]
    pub command: StaticCommands,
}

#[derive(Subcommand)]
pub enum StaticCommands {
    /// Solidity tree-sitter / AST extraction tools (no LLM)
    Solidity(StaticSolidityCommand),

    /// Move package extraction and call-graph tools (no LLM)
    Move(StaticMoveCommand),
}

#[derive(Args)]
pub struct LearnCommand {
    #[command(flatten)]
    pub database: HistoricalDatabaseArgs,

    #[command(subcommand)]
    pub command: LearnCommands,
}

#[derive(Subcommand)]
pub enum LearnCommands {
    /// Learn historical experience from explicit project directories
    Projects(cmd::learn::learn::LearnArgs),

    /// Learn historical experience from Code4rena projects in an out_train directory
    C4(cmd::learn::learn::LearnC4Args),

    /// Learn historical experience from Move projects in the moves dataset
    Moves(cmd::learn::learn::LearnMovesArgs),

    /// Link pending historical audit findings to learned DeFi semantics
    Link(cmd::learn::link::LinkArgs),

    /// Retro-link previously-linked findings against semantics queued in
    /// `pending_semantic` (typically run after admitting a new project to
    /// the historical KG, before the regular `link` pass)
    RetroLink(cmd::learn::retro_link::RetroLinkArgs),

    /// Validate historical database referential integrity; optionally repair dangling rows
    ValidateDb(cmd::learn::validate_db::ValidateDbArgs),

    /// Assign a platform ID to an existing historical project
    SetPlatformId(cmd::learn::set_platform_id::SetPlatformIdArgs),

    /// List all learned DeFi semantics for a historical project
    ListSemantics(cmd::learn::list_semantics::ListSemanticsArgs),

    /// Search learned historical semantics by keyword
    SearchSemantics(cmd::learn::search_semantics::SearchSemanticsArgs),

    /// List all completed historical projects
    ListProjects,

    /// Initialize the historical experience database
    InitDb,

    /// Export the historical knowledge graph as DOT for visualization
    ExportDot(cmd::learn::export_dot::ExportDotArgs),

    /// Export the historical knowledge graph as an interactive HTML graph
    ExportHtml(cmd::learn::export_html::ExportHtmlArgs),
}

#[derive(Args)]
pub struct StaticSolidityCommand {
    #[command(subcommand)]
    pub command: StaticSolidityCommands,
}

#[derive(Subcommand)]
pub enum StaticSolidityCommands {
    /// Extract Solidity contracts and functions as JSON via tree-sitter
    Extract(cmd::solidity::ExtractSolidityArgs),

    /// Build a static Solidity callgraph AND state-variable read/write analysis from the solc
    /// AST and write both to the project database
    CallGraph(cmd::solidity::SolidityCallGraphStaticArgs),

    /// Export the stored Solidity callgraph from the project database as DOT/PDF
    ExportCallGraphDot(cmd::solidity::SolidityExportCallGraphDotArgs),

    /// Export the stored Solidity state-variable read/write graph (populated by `call-graph`) as DOT/PDF
    ExportStateVariableDot(cmd::solidity::SolidityExportStateVariableDotArgs),
}

#[derive(Args)]
pub struct StaticMoveCommand {
    #[command(subcommand)]
    pub command: StaticMoveCommands,
}

#[derive(Subcommand)]
pub enum StaticMoveCommands {
    /// Extract Move modules and functions as JSON
    Extract(cmd::r#move::ExtractMoveArgs),

    /// Build a Move package and analyze its call graph into the project database
    CallGraph(cmd::r#move::MoveCallGraphArgs),

    /// Export the stored Move callgraph from the project database as DOT/PDF
    ExportCallGraphDot(cmd::r#move::MoveExportCallGraphDotArgs),
}

// ---------------------------------------------------------------------------
// `knowdit agentic ...` — LLM-driven workflows
// ---------------------------------------------------------------------------

#[derive(Args)]
pub struct AgenticCommand {
    // No `HistoricalDatabaseArgs` flatten here — only `MapSemantics`
    // needs the KG and it flattens its own copy. Every other agentic
    // subcommand operates against the per-project SQLite only.
    #[command(flatten)]
    pub llm: OpenAISetup,

    #[command(subcommand)]
    pub command: AgenticCommands,
}

#[derive(Subcommand)]
pub enum AgenticCommands {
    /// LLM-driven Solidity workflows
    Solidity(AgenticSolidityCommand),

    /// Select and localize semantic specifications from a scope corpus
    ExtractSemantics(cmd::audit::extract_semantics::ExtractSemanticsArgs),

    /// Build a per-project ProjectProfile (domain summary, subsystems,
    /// core components, out-of-scope notes) consumed by the Knowledge
    /// Mapper. Resume-safe: skips if a profile is already cached
    /// unless `--profile-regenerate` is set.
    Profile(cmd::audit::profile::ProfileArgs),

    /// Knowledge Mapper: fuzzy-match the project's extracted semantics
    /// against the historical knowledge graph and persist matched
    /// historical semantics + findings into the project database.
    MapSemantics(cmd::audit::map_semantics::MapSemanticsArgs),

    /// Specification Generator: for each (extract, historical, finding) link
    /// from the Knowledge Mapper, run a memory-equipped agent to derive
    /// project-specific AuditSpecifications.
    GenSpecs(cmd::audit::gen_specs::GenSpecsArgs),

    /// Fuzzing Harness Generator: synthesize a Foundry harness for each
    /// AuditSpecification and drive `forge` against it.
    Fuzz(cmd::audit::fuzz::FuzzArgs),

    /// Reflection: post-fuzz triage of synthesized harnesses through the
    /// Gate 1 (static) + Gate 2 (coverage) stack, marking suspect
    /// harnesses for regen.
    Reflect(cmd::audit::reflect::ReflectArgs),

    /// Regen: consume the pending-reflection queue, regenerate code_gens
    /// (and, when escalated, specs) with the prior reflection feedback
    /// fed back into the agent's system prompt.
    Regen(cmd::audit::regen::RegenArgs),
}

#[derive(Args)]
pub struct AgenticSolidityCommand {
    #[command(subcommand)]
    pub command: AgenticSolidityCommands,
}

#[derive(Subcommand)]
pub enum AgenticSolidityCommands {
    /// LLM agent: analyze Solidity semantics and callgraph into the project database
    CallGraph(cmd::solidity::SolidityCallGraphArgs),

    /// LLM agent: analyze Solidity storage read/write per function (tree-sitter only)
    StorageGraph(cmd::solidity::SolidityStorageGraphArgs),
}

// ---------------------------------------------------------------------------
// Dispatch — every level of the CLI tree has a `run` method that
// owns the dispatch for that level. Same `verb` everywhere keeps
// embedders fluent: `KnowditCommand::parse().run().await?` runs the
// whole tree; calling a sub-level directly (e.g.
// `WorkflowCommand::run`) gives finer-grained reuse.
// ---------------------------------------------------------------------------

impl KnowditCommand {
    pub async fn run(self) -> color_eyre::Result<()> {
        self.command.run().await
    }
}

impl KnowditSubCommands {
    pub async fn run(self) -> color_eyre::Result<()> {
        match self {
            KnowditSubCommands::Learn(command) => command.run().await,
            KnowditSubCommands::Static(command) => command.run().await,
            KnowditSubCommands::Agentic(command) => command.run().await,
            KnowditSubCommands::Workflow(command) => command.run().await,
            KnowditSubCommands::Db(command) => command.run().await,
        }
    }
}

impl WorkflowCommand {
    pub async fn run(self) -> color_eyre::Result<()> {
        let Self {
            llm: llm_setup,
            command,
        } = self;
        let llm = llm_setup.to_llm().await;
        match command {
            WorkflowCommands::Autoloop(args) => args.run(&llm).await?,
            WorkflowCommands::Streamloop(args) => args.run(&llm).await?,
            WorkflowCommands::Learn(args) => args.run(&llm).await?,
        }
        Ok(())
    }
}

impl DbCommand {
    pub async fn run(self) -> color_eyre::Result<()> {
        match self.command {
            DbCommands::Snapshot(args) => args.run().await,
            DbCommands::ImportSnapshot(args) => args.run().await,
            DbCommands::Copy(args) => args.run().await,
        }
    }
}

impl StaticCommand {
    pub async fn run(self) -> color_eyre::Result<()> {
        match self.command {
            StaticCommands::Solidity(command) => command.run().await,
            StaticCommands::Move(command) => command.run().await,
        }
    }
}

impl LearnCommand {
    pub async fn run(self) -> color_eyre::Result<()> {
        let Self { database, command } = self;
        let db = database.connect_init().await?;
        match command {
            LearnCommands::Projects(args) => args.run(&db).await?,
            LearnCommands::C4(args) => args.run(&db).await?,
            LearnCommands::Moves(args) => args.run(&db).await?,
            LearnCommands::Link(args) => args.run(&db).await?,
            LearnCommands::RetroLink(args) => args.run(&db).await?,
            LearnCommands::ValidateDb(args) => args.run(&db).await?,
            LearnCommands::SetPlatformId(args) => args.run(&db).await?,
            LearnCommands::ListSemantics(args) => args.run(&db).await?,
            LearnCommands::SearchSemantics(args) => args.run(&db).await?,
            LearnCommands::ListProjects => cmd::learn::list_projects::run(&db).await?,
            LearnCommands::InitDb => cmd::learn::init_db::run(&db).await?,
            LearnCommands::ExportDot(args) => args.run(&db).await?,
            LearnCommands::ExportHtml(args) => args.run(&db).await?,
        }
        Ok(())
    }
}

impl StaticSolidityCommand {
    pub async fn run(self) -> color_eyre::Result<()> {
        match self.command {
            StaticSolidityCommands::Extract(args) => args.run().await?,
            StaticSolidityCommands::CallGraph(args) => args.run().await?,
            StaticSolidityCommands::ExportCallGraphDot(args) => args.run().await?,
            StaticSolidityCommands::ExportStateVariableDot(args) => args.run().await?,
        }
        Ok(())
    }
}

impl StaticMoveCommand {
    pub async fn run(self) -> color_eyre::Result<()> {
        match self.command {
            StaticMoveCommands::Extract(args) => args.run().await?,
            StaticMoveCommands::CallGraph(args) => args.run().await?,
            StaticMoveCommands::ExportCallGraphDot(args) => args.run().await?,
        }
        Ok(())
    }
}

impl AgenticCommand {
    pub async fn run(self) -> color_eyre::Result<()> {
        let Self {
            llm: llm_setup,
            command,
        } = self;
        // One shared LLM per top-level invocation. `LLM` wraps an
        // `Arc<LLMInner>` so passing `&llm` (or cheap clones)
        // downstream is free; reusing the same instance also lets
        // the autoloop / future multi-phase orchestrators enforce
        // one global billing cap.
        let llm = llm_setup.to_llm().await;
        match command {
            AgenticCommands::Solidity(command) => command.run().await?,
            AgenticCommands::ExtractSemantics(args) => args.run(&llm).await?,
            AgenticCommands::Profile(args) => args.run(&llm).await?,
            AgenticCommands::MapSemantics(args) => args.run(&llm).await?,
            AgenticCommands::GenSpecs(args) => args.run(&llm).await?,
            AgenticCommands::Fuzz(args) => args.run(&llm).await?,
            AgenticCommands::Reflect(args) => args.run(&llm).await?,
            AgenticCommands::Regen(args) => args.run(&llm).await?,
        }
        Ok(())
    }
}

impl AgenticSolidityCommand {
    pub async fn run(self) -> color_eyre::Result<()> {
        match self.command {
            AgenticSolidityCommands::CallGraph(args) => args.run().await?,
            AgenticSolidityCommands::StorageGraph(args) => args.run().await?,
        }
        Ok(())
    }
}
