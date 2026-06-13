//! Clap helpers shared by every CLI subcommand that operates on a
//! project + per-project SQLite database. Two independent flattened
//! arg structs, one for each concern:
//!
//! * [`ProjectArgs`] owns `--project name:path[:platform_id]` and
//!   exposes three escalating loaders (`to_project_spec` → no I/O,
//!   `to_project_data` → walk source corpus, `to_repo_database` →
//!   open SQLite + init schema + register project).
//! * [`DatabaseArgs`] owns just `--database-path` so the override
//!   can be wired up independently and forwarded as an argument.
//!
//! Every subcommand flattens both and calls whichever combination
//! it needs — the boilerplate stops here.

use std::path::{Path, PathBuf};

use clap::{Args, ValueEnum};
use color_eyre::eyre::{Result, WrapErr};
use knowdit_kg::db::HistoricalDatabase;
use knowdit_project::{FoundryOptions, HardhatOptions, ProjectData, ProjectSpec};
use knowdit_repo_model::RepoDatabase;

/// `--project name:path[:platform_id]`. Sole owner of the project
/// spec at the CLI surface. All "what does this project look like"
/// questions get answered through one of the three `to_*` methods,
/// each of which is strictly heavier than the previous one.
#[derive(Args, Debug, Clone)]
pub struct ProjectArgs {
    /// Project spec in the form `name:path` or `name:path:platform_id`.
    /// `path` is the repo root; `name` is the project entity key in
    /// the SQLite DB.
    #[arg(long = "project", short = 'p')]
    pub project: String,
}

/// `--database-path`. The optional per-project SQLite override that
/// pairs with [`ProjectArgs`]. Kept as its own struct so subcommands
/// flatten it independently — and the override flows into
/// [`ProjectArgs::to_repo_database`] as a parameter instead of
/// living on either struct as a redundant field.
#[derive(Args, Debug, Clone, Default)]
pub struct DatabaseArgs {
    /// Per-project SQLite path. Defaults to
    /// `<project_root>/knowdit.sqlite3`.
    #[arg(short = 'r', long, env = "REPO_DATABASE_PATH")]
    pub database_path: Option<PathBuf>,
}

/// Result of [`ProjectArgs::to_repo_database`]: the parsed project
/// spec, the resolved SQLite path, and an opened-and-initialised
/// [`RepoDatabase`] handle (schema migrated, project entity
/// registered).
pub struct LoadedRepoDatabase {
    pub spec: ProjectSpec,
    pub database_path: PathBuf,
    pub repo: RepoDatabase,
}

/// `--foundry-profile` / `--via-ir` / `--src` — flattened into any
/// subcommand that drives a `FoundryProject::build`. Owns the
/// CLI-side mirror of [`knowdit_project::FoundryOptions`] and the
/// one conversion method.
#[derive(Args, Debug, Clone)]
pub struct FoundryCliOptions {
    /// Foundry profile to read from `foundry.toml`
    /// (the `<name>` in `[profile.<name>]`). Defaults to `default`;
    /// projects like silo-finance keep their src config in a named
    /// profile (e.g. `core`) — pass that name here to reach it.
    #[arg(long = "foundry-profile", default_value = "default")]
    pub profile: String,

    /// Enable solc's IR-based codegen (`viaIR = true`). Required by
    /// projects that hit "Stack too deep" with the legacy codegen.
    #[arg(short = 'i', long = "via-ir")]
    pub via_ir: bool,

    /// Override the contracts source dir (relative to the project
    /// root, or absolute). When unset: read from
    /// `[profile.<profile>].src` → `[default].src` → first existing
    /// of `src/` / `contracts/`.
    #[arg(long = "src")]
    pub src: Option<PathBuf>,
}

impl Default for FoundryCliOptions {
    fn default() -> Self {
        // Mirrors the clap `default_value`s — used by in-process
        // callers (e.g. the autoloop) that construct this struct
        // directly rather than going through clap parsing.
        Self {
            profile: "default".to_string(),
            via_ir: false,
            src: None,
        }
    }
}

impl FoundryCliOptions {
    /// Translate the clap args into the runtime
    /// [`FoundryOptions`] consumed by
    /// `knowdit_project::FoundryProject::build`.
    pub fn to_foundry_options(&self) -> FoundryOptions {
        FoundryOptions {
            src: self.src.clone(),
            profile: self.profile.clone(),
            via_ir: self.via_ir,
        }
    }
}

/// `--hardhat-artifacts-dir` — flattened next to [`FoundryCliOptions`]
/// in any subcommand that drives a project compile. Mirrors
/// [`knowdit_project::HardhatOptions`].
#[derive(Args, Debug, Clone, Default)]
pub struct HardhatCliOptions {
    /// Override the Hardhat artifacts directory (the parent of
    /// `build-info/`). Defaults to `artifacts/` relative to the
    /// project root. Absolute paths are kept verbatim.
    #[arg(long = "hardhat-artifacts-dir")]
    pub artifacts_dir: Option<PathBuf>,
}

impl HardhatCliOptions {
    pub fn to_hardhat_options(&self) -> HardhatOptions {
        HardhatOptions {
            artifacts_dir: self.artifacts_dir.clone(),
        }
    }

    /// Path that auto-detection probes to decide if this looks like a
    /// Hardhat layout: `<repo_root>/<artifacts_dir or 'artifacts'>/build-info/`.
    fn build_info_dir(&self, repo_root: &Path) -> PathBuf {
        let artifacts = self
            .artifacts_dir
            .clone()
            .map(|p| {
                if p.is_absolute() {
                    p
                } else {
                    repo_root.join(p)
                }
            })
            .unwrap_or_else(|| repo_root.join("artifacts"));
        artifacts.join("build-info")
    }
}

/// Which static-analysis backend to use for the project compile. `Auto`
/// picks Hardhat when `<repo_root>/artifacts/build-info/` exists (so a
/// previous `npx hardhat compile` is honoured), otherwise drives solc
/// via `foundry-compilers` (the Forge-style path).
#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum ProjectBackendKind {
    Auto,
    Forge,
    Hardhat,
}

/// `--project-backend` plus the Foundry / Hardhat option groups it
/// dispatches over. Flatten *this* (instead of [`FoundryCliOptions`]
/// directly) into any subcommand that builds the call-graph: it keeps
/// the existing `--foundry-profile` / `--via-ir` / `--src` flags and
/// adds `--project-backend` + `--hardhat-artifacts-dir`.
#[derive(Args, Debug, Clone)]
pub struct ProjectBackendCliOptions {
    /// Which compile pipeline to use. `auto` (the default) detects
    /// `<repo_root>/artifacts/build-info/` and uses Hardhat when
    /// present, otherwise falls back to Forge.
    #[arg(long = "project-backend", value_enum, default_value_t = ProjectBackendKind::Auto)]
    pub project_backend: ProjectBackendKind,

    #[command(flatten)]
    pub foundry: FoundryCliOptions,

    #[command(flatten)]
    pub hardhat: HardhatCliOptions,
}

impl Default for ProjectBackendCliOptions {
    fn default() -> Self {
        Self {
            project_backend: ProjectBackendKind::Auto,
            foundry: FoundryCliOptions::default(),
            hardhat: HardhatCliOptions::default(),
        }
    }
}

/// Resolved backend choice plus its options. Returned by
/// [`ProjectBackendCliOptions::resolve`] after the auto-detect runs;
/// downstream code dispatches on this enum.
pub enum ResolvedProjectBackend {
    Forge(FoundryOptions),
    Hardhat(HardhatOptions),
}

impl ResolvedProjectBackend {
    pub fn kind_label(&self) -> &'static str {
        match self {
            Self::Forge(_) => "forge",
            Self::Hardhat(_) => "hardhat",
        }
    }
}

impl ProjectBackendCliOptions {
    /// Materialize the final backend choice. `Forge` / `Hardhat` are
    /// passed through verbatim; `Auto` probes
    /// `<repo_root>/artifacts/build-info/` and selects Hardhat when it
    /// exists, otherwise Forge.
    pub fn resolve(&self, repo_root: &Path) -> ResolvedProjectBackend {
        let kind = match self.project_backend {
            ProjectBackendKind::Forge => ProjectBackendKind::Forge,
            ProjectBackendKind::Hardhat => ProjectBackendKind::Hardhat,
            ProjectBackendKind::Auto => {
                if self.hardhat.build_info_dir(repo_root).is_dir() {
                    ProjectBackendKind::Hardhat
                } else {
                    ProjectBackendKind::Forge
                }
            }
        };
        match kind {
            ProjectBackendKind::Hardhat => {
                ResolvedProjectBackend::Hardhat(self.hardhat.to_hardhat_options())
            }
            ProjectBackendKind::Forge | ProjectBackendKind::Auto => {
                ResolvedProjectBackend::Forge(self.foundry.to_foundry_options())
            }
        }
    }
}

/// `--database-url` — the historical knowledge-graph database (sqlite,
/// mysql, postgres). Lives next to [`ProjectArgs`] / [`DatabaseArgs`]
/// because every `learn` / `agentic-with-kg` subcommand needs the
/// same connect + init dance and this is the single place that
/// dance is defined.
#[derive(Args, Debug, Clone)]
pub struct HistoricalDatabaseArgs {
    /// Historical experience database URL (supports sqlite://,
    /// mysql://, postgres://).
    #[arg(long, env = "DATABASE_URL")]
    pub database_url: String,

    /// Consumer-only override: skip the partial-link integrity
    /// check that [`Self::connect_init_for_consumer`] runs at
    /// startup. The check refuses to open a historical KG that has
    /// `semantic_finding_link` rows for findings missing a
    /// `finding_link_status` row — that state means a prior
    /// `workflow learn` was killed mid-link, and consuming it would
    /// pull in mid-flight strength values that the linker hasn't
    /// finalized.
    ///
    /// Writers (`learn` / `workflow learn`) bypass the check by
    /// going through [`Self::connect_init`] directly — they expect
    /// to operate on partial DBs (that's exactly how resume works).
    #[arg(long, default_value_t = false)]
    pub force_allow_partial_historical: bool,
}

impl HistoricalDatabaseArgs {
    /// Open a connection to the historical KG without running
    /// schema migration. Use this for snapshot import/export paths
    /// that manage their own schema state.
    pub async fn connect(&self) -> Result<HistoricalDatabase> {
        HistoricalDatabase::connect(&self.database_url)
            .await
            .wrap_err_with(|| {
                format!(
                    "failed to connect to historical KG at {}",
                    self.database_url
                )
            })
    }

    /// Open + run `init()` (creates tables, seeds category rows).
    /// **Writer-side entry point** — used by every `learn` /
    /// `workflow learn` path. Does NOT run the partial-link
    /// integrity check; writers must be able to operate on a
    /// partial DB to resume an interrupted run.
    pub async fn connect_init(&self) -> Result<HistoricalDatabase> {
        let db = self.connect().await?;
        db.init()
            .await
            .wrap_err("failed to init historical KG schema")?;
        Ok(db)
    }

    /// Consumer-side entry point — used by `workflow streamloop`,
    /// `workflow autoloop`, and `agentic map-semantics`. Same
    /// connect + init as [`Self::connect_init`], then runs
    /// `validate_db(false)` and refuses to return a DB whose
    /// integrity report has any issues. The operator can override
    /// with `--force-allow-partial-historical` when they explicitly
    /// want to consume a known-partial DB.
    ///
    /// Why this is a separate method (not a flag-gated behaviour
    /// on `connect_init`): writers always need to bypass the
    /// check, so making it conditional on a CLI flag would force
    /// every `learn` invocation to carry the flag. Two methods is
    /// the simplest split — the call site declares its intent.
    pub async fn connect_init_for_consumer(&self) -> Result<HistoricalDatabase> {
        // Consumers only ever READ the historical KG (the mapper pulls
        // canonical semantics + linked findings; nothing here writes
        // back). So initialize the schema only when it is actually
        // missing — a brand-new DB. Against a pre-populated DB we must
        // NOT run `init()`: its CREATE TABLE / ALTER are redundant
        // there and are denied outright when the KG is exposed through
        // a SELECT-only grant (e.g. a read-only MySQL replica). The
        // writer entry point [`Self::connect_init`] is unchanged —
        // writers always have, and need, full privileges.
        let db = self.connect().await?;
        if !db.schema_is_initialized().await? {
            db.init()
                .await
                .wrap_err("failed to init historical KG schema")?;
        }
        if self.force_allow_partial_historical {
            return Ok(db);
        }
        let report = db
            .validate_db(false)
            .await
            .wrap_err("failed to run historical KG integrity check")?;
        if !report.is_clean() {
            let lines = report
                .remaining_issues
                .iter()
                .map(|i| format!("  - {}", i))
                .collect::<Vec<_>>()
                .join("\n");
            return Err(color_eyre::eyre::eyre!(
                "Historical KG at {} failed its integrity check ({} issue(s)):\n\
                 {}\n\n\
                 If this looks like an interrupted `workflow learn` run, finish \
                 it by re-running `knowdit workflow learn` against the same \
                 project. If you intentionally want to consume the partial DB, \
                 re-run with `--force-allow-partial-historical`.",
                self.database_url,
                report.remaining_issues.len(),
                lines,
            ));
        }
        Ok(db)
    }
}

impl ProjectArgs {
    /// Parse the `--project` spec into its three components. No
    /// filesystem I/O — the cheapest of the three loaders.
    pub fn to_project_spec(&self) -> Result<ProjectSpec> {
        ProjectSpec::parse(&self.project)
            .wrap_err_with(|| format!("failed to parse --project `{}`", self.project))
    }

    /// Walk the project's source tree into memory and return a
    /// [`ProjectData`]. Auto-detects Solidity vs Move from the
    /// extensions present under the spec's `path`.
    pub async fn to_project_data(&self) -> Result<ProjectData> {
        ProjectData::from_source_dir_spec(&self.project)
            .await
            .wrap_err_with(|| format!("failed to load --project `{}`", self.project))
    }

    /// Open the per-project SQLite database, migrate the schema,
    /// and register the project entity. `db_override` is the value
    /// of `--database-path` (forwarded from the sibling
    /// [`DatabaseArgs`]); `None` means "use the default
    /// `<project_root>/knowdit.sqlite3`".
    pub async fn to_repo_database(
        &self,
        db_override: Option<PathBuf>,
    ) -> Result<LoadedRepoDatabase> {
        let spec = self.to_project_spec()?;
        let database_path = RepoDatabase::default_sqlite_path(&spec.root, db_override);
        let repo = RepoDatabase::open_sqlite(database_path.clone())
            .await
            .wrap_err_with(|| format!("failed to open project DB {}", database_path.display()))?;
        repo.init_schema()
            .await
            .wrap_err("failed to init project DB schema")?;
        repo.ensure_project(&spec.name)
            .await
            .wrap_err("failed to ensure project entity")?;
        Ok(LoadedRepoDatabase {
            spec,
            database_path,
            repo,
        })
    }
}
