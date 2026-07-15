//! Per-project ("repo") database handle.
//!
//! Every read or write against a project-scoped SQLite/MySQL database goes
//! through [`RepoDatabase`]. Treat it as the single boundary between domain
//! types (`CallGraph`, `StorageGraph`, `ExtractedSemantic`, …) and persistence —
//! callers should not touch raw `DatabaseConnection` values themselves.
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use color_eyre::eyre::{ContextCompat, Result, WrapErr, ensure};
use knowdit_kg_model::{ExtractedFunction, ExtractedSemantic, db::project as project_model};
use sea_orm::{
    ActiveValue::Set, ConnectionTrait, Database, DatabaseBackend, DatabaseConnection, EntityTrait,
    QueryOrder, Schema, TransactionTrait,
};

use crate::cg::{
    CallGraph, Contract, FileChunk, Function, FunctionCall, Interface, location_from_db,
    location_to_db,
};
pub use crate::db::code_gen::CodeGenStatus;
pub use crate::db::finding_review::ReviewSeverity;
pub use crate::db::harness_run::RunKind;
use crate::db::r#move::{
    move_function_metadata as move_function_metadata_model, move_struct as move_struct_model,
    move_struct_ability as move_struct_ability_model,
};
pub use crate::db::reflection::ReflectionResult;
pub use crate::db::semantic_matched::MatchStrength;
use crate::db::{
    code_gen as code_gen_model, code_gen_regen as code_gen_regen_model, contract as contract_model,
    contract_functions as contract_functions_model, contract_inherit as contract_inherit_model,
    contract_variable as contract_variable_model, finding_merge as finding_merge_model,
    finding_review as finding_review_model, function as function_model,
    function_call as function_call_model, function_state_variable as function_state_variable_model,
    harness_run as harness_run_model, historical_finding as historical_finding_model,
    historical_finding_merge as historical_finding_merge_model,
    historical_semantic as historical_semantic_model,
    historical_semantic_finding_link as historical_semantic_finding_link_model,
    historical_semantic_merge as historical_semantic_merge_model, interface as interface_model,
    interface_functions as interface_functions_model, line_coverage as line_coverage_model,
    project_metadata as project_metadata_model, project_semantic as project_semantic_model,
    project_semantic_function as project_semantic_function_model, reflection as reflection_model,
    report_finding as report_finding_model, semantic_matched as semantic_matched_model,
    specification as specification_model, specification_regen as specification_regen_model,
    state_variable as state_variable_model, valid_finding as valid_finding_model,
};
use crate::inheritance::{ContractInherit, InheritanceGraph};
use crate::move_lang::{
    MoveAbility, MoveField, MoveFunctionMetadata, MoveGenericParam, MovePackageStructure,
    MoveStruct,
};
use crate::storage::{
    ContractVariable, FunctionStateVariable, StateVariable, StorageDotOptions, StorageGraph,
    dot_escape,
};

/// Handle to a single project database.
///
/// `Clone` is shallow: SeaORM's `DatabaseConnection` wraps a connection pool
/// behind an `Arc`, so cloning shares the same pool rather than re-opening.
#[derive(Clone)]
pub struct RepoDatabase {
    db: DatabaseConnection,
    url: String,
    path: Option<PathBuf>,
    /// Cap on merged-variant notes folded into each mirrored canonical's
    /// `rendered_*` by [`Self::load_semantic_match_results`]. Defaults to
    /// [`crate::DEFAULT_VARIANT_RENDER_CAP`]; override via
    /// [`Self::with_variant_render_cap`].
    variant_render_cap: usize,
}

impl RepoDatabase {
    /// Resolve the SQLite path used by the `static` subcommands: explicit
    /// override if supplied, otherwise `<repo_root>/knowdit.sqlite3`.
    pub fn default_sqlite_path(repo_root: &Path, override_path: Option<PathBuf>) -> PathBuf {
        override_path.unwrap_or_else(|| repo_root.join("knowdit.sqlite3"))
    }

    /// Build the `sqlite://...?mode=rwc` URL for a filesystem path.
    pub fn sqlite_url_for(path: &Path) -> String {
        format!("sqlite://{}?mode=rwc", path.display())
    }

    async fn connect(url: &str) -> Result<DatabaseConnection> {
        let db = Database::connect(url)
            .await
            .wrap_err_with(|| format!("failed to connect to project database {url}"))?;
        if db.get_database_backend() == DatabaseBackend::Sqlite {
            db.execute_unprepared("PRAGMA journal_mode=WAL;")
                .await
                .wrap_err("failed to enable SQLite WAL mode for project database")?;
            db.execute_unprepared("PRAGMA foreign_keys=ON;")
                .await
                .wrap_err("failed to enable SQLite foreign keys for project database")?;
        }
        Ok(db)
    }

    /// Open from any database URL (sqlite, mysql, postgres). Configures SQLite
    /// pragmas (WAL + foreign keys) as a side effect when applicable.
    pub async fn open_url(url: impl Into<String>) -> Result<Self> {
        let url = url.into();
        let db = Self::connect(&url).await?;
        Ok(Self {
            db,
            url,
            path: None,
            variant_render_cap: crate::DEFAULT_VARIANT_RENDER_CAP,
        })
    }

    /// Set the merged-variant render cap used by
    /// [`Self::load_semantic_match_results`] (builder style).
    pub fn with_variant_render_cap(mut self, cap: usize) -> Self {
        self.variant_render_cap = cap;
        self
    }

    /// Open from a SQLite path (creates the file if missing). Equivalent to
    /// `open_url(sqlite_url_for(&path))` but remembers the path for display.
    pub async fn open_sqlite(path: PathBuf) -> Result<Self> {
        let url = Self::sqlite_url_for(&path);
        let db = Self::connect(&url).await?;
        Ok(Self {
            db,
            url,
            path: Some(path),
            variant_render_cap: crate::DEFAULT_VARIANT_RENDER_CAP,
        })
    }

    /// Borrow the underlying SeaORM connection. Avoid using this from outside
    /// the crate — prefer the typed methods on [`RepoDatabase`].
    pub fn connection(&self) -> &DatabaseConnection {
        &self.db
    }

    /// The raw URL the database was opened with (may contain credentials).
    pub fn url(&self) -> &str {
        &self.url
    }

    /// The SQLite path, when [`RepoDatabase`] was opened via [`Self::open_sqlite`].
    pub fn path(&self) -> Option<&Path> {
        self.path.as_deref()
    }

    /// URL with username and password stripped for log-safe display. Falls
    /// back to a placeholder if the URL fails to parse.
    pub fn redacted_url(&self) -> String {
        let Ok(mut parsed) = url::Url::parse(&self.url) else {
            return "<unparseable database url>".to_string();
        };
        if !parsed.username().is_empty() {
            let _ = parsed.set_username("");
        }
        if parsed.password().is_some() {
            let _ = parsed.set_password(None);
        }
        parsed.to_string()
    }

    /// Create every table this crate owns (call graph, storage graph, project
    /// semantics) plus the project identity table from `knowdit-kg-model`.
    /// All `CREATE TABLE` statements use `IF NOT EXISTS`. Older v9-era
    /// DBs that still carry the legacy `reflection.code_id` column are
    /// detected up-front and dropped (with a `WARN`) before the new
    /// `run_id` schema is created — the legacy rows are Gate 1/2
    /// pre-inline-gates artifacts and are not worth migrating.
    pub async fn init_schema(&self) -> Result<()> {
        self.drop_legacy_reflection_if_present().await?;
        self.drop_legacy_specification_if_present().await?;

        let schema = Schema::new(self.db.get_database_backend());
        let tables = vec![
            schema.create_table_from_entity(project_semantic_model::Entity),
            schema.create_table_from_entity(project_semantic_function_model::Entity),
            schema.create_table_from_entity(contract_model::Entity),
            schema.create_table_from_entity(interface_model::Entity),
            schema.create_table_from_entity(function_model::Entity),
            schema.create_table_from_entity(contract_functions_model::Entity),
            schema.create_table_from_entity(interface_functions_model::Entity),
            schema.create_table_from_entity(function_call_model::Entity),
            schema.create_table_from_entity(state_variable_model::Entity),
            schema.create_table_from_entity(contract_inherit_model::Entity),
            schema.create_table_from_entity(contract_variable_model::Entity),
            schema.create_table_from_entity(function_state_variable_model::Entity),
            schema.create_table_from_entity(historical_semantic_model::Entity),
            schema.create_table_from_entity(historical_finding_model::Entity),
            schema.create_table_from_entity(historical_semantic_merge_model::Entity),
            schema.create_table_from_entity(historical_finding_merge_model::Entity),
            schema.create_table_from_entity(historical_semantic_finding_link_model::Entity),
            schema.create_table_from_entity(semantic_matched_model::Entity),
            schema.create_table_from_entity(project_metadata_model::Entity),
            schema.create_table_from_entity(specification_model::Entity),
            schema.create_table_from_entity(code_gen_model::Entity),
            schema.create_table_from_entity(harness_run_model::Entity),
            schema.create_table_from_entity(reflection_model::Entity),
            schema.create_table_from_entity(valid_finding_model::Entity),
            // Report tables (`review-findings` workflow). Ordered after
            // reflection: finding_review references reflection; finding_merge
            // references both finding_review and report_finding.
            schema.create_table_from_entity(finding_review_model::Entity),
            schema.create_table_from_entity(report_finding_model::Entity),
            schema.create_table_from_entity(finding_merge_model::Entity),
            // Lineage tables — must come after their referenced parents
            // (specification / code_gen / reflection) to keep the FK
            // ordering happy on backends that enforce it.
            schema.create_table_from_entity(specification_regen_model::Entity),
            schema.create_table_from_entity(code_gen_regen_model::Entity),
            schema.create_table_from_entity(line_coverage_model::Entity),
            schema.create_table_from_entity(project_model::Entity),
            // Move-only tables. Created on every backend (incl. OSS
            // Solidity-only builds) so the schema stays uniform; the
            // Solidity write paths never populate them and they stay
            // empty.
            schema.create_table_from_entity(move_struct_model::Entity),
            schema.create_table_from_entity(move_struct_ability_model::Entity),
            schema.create_table_from_entity(move_function_metadata_model::Entity),
        ];

        for mut table in tables {
            table.if_not_exists();
            self.db
                .execute(&table)
                .await
                .wrap_err("failed to create project database schema")?;
        }

        // Compound UNIQUE on semantic_matched (extract_id,
        // historical_id). SeaORM's `DeriveEntityModel` doesn't
        // express compound unique constraints on the entity, so build
        // the index via the SeaQuery index builder. Dialect-agnostic;
        // emits the right CREATE UNIQUE INDEX IF NOT EXISTS for every
        // backend.
        let unique_match_idx = sea_orm::sea_query::Index::create()
            .if_not_exists()
            .name("ux_semantic_matched_extract_historical")
            .table(semantic_matched_model::Entity)
            .col(semantic_matched_model::Column::ExtractId)
            .col(semantic_matched_model::Column::HistoricalId)
            .unique()
            .to_owned();
        self.db
            .execute(&unique_match_idx)
            .await
            .wrap_err("failed to create UNIQUE index on semantic_matched")?;

        // Compound INDEX (NOT UNIQUE — multiple rows per
        // (E, H, F) is legitimate: one gen-spec call can emit
        // multiple AuditSpecifications, and regen children share
        // their parent's triple) on `specification` for fast
        // `link_resume_state` lookups.
        let spec_link_idx = sea_orm::sea_query::Index::create()
            .if_not_exists()
            .name("ix_specification_extract_historical_finding")
            .table(specification_model::Entity)
            .col(specification_model::Column::SemanticId)
            .col(specification_model::Column::HistoricalId)
            .col(specification_model::Column::FindingId)
            .to_owned();
        self.db
            .execute(&spec_link_idx)
            .await
            .wrap_err("failed to create compound index on specification")?;

        // UNIQUE on (contract_id, name) for `move_struct`. A Move
        // module can't declare two structs with the same name; the
        // unique constraint lets `INSERT OR REPLACE` / `on_conflict`
        // produce idempotent re-runs of `export-repo-info`.
        let move_struct_uniq = sea_orm::sea_query::Index::create()
            .if_not_exists()
            .name("ux_move_struct_contract_name")
            .table(move_struct_model::Entity)
            .col(move_struct_model::Column::ContractId)
            .col(move_struct_model::Column::Name)
            .unique()
            .to_owned();
        self.db
            .execute(&move_struct_uniq)
            .await
            .wrap_err("failed to create UNIQUE index on move_struct")?;

        // UNIQUE on (struct_id, ability) for `move_struct_ability`.
        // A struct can't carry the same ability twice; this also
        // gates the writer's bulk-insert from accidentally
        // duplicating rows.
        let move_ability_uniq = sea_orm::sea_query::Index::create()
            .if_not_exists()
            .name("ux_move_struct_ability_struct_ability")
            .table(move_struct_ability_model::Entity)
            .col(move_struct_ability_model::Column::StructId)
            .col(move_struct_ability_model::Column::Ability)
            .unique()
            .to_owned();
        self.db
            .execute(&move_ability_uniq)
            .await
            .wrap_err("failed to create UNIQUE index on move_struct_ability")?;

        Ok(())
    }

    /// Detect the legacy `reflection.code_id` column. If present, the DB
    /// was created before reflection became per-`harness_run`; drop it
    /// (along with any lineage rows pointing at it) so the new
    /// per-run schema can be created cleanly. This is sqlite-only —
    /// MySQL deployments don't have legacy v9 reflections.
    async fn drop_legacy_reflection_if_present(&self) -> Result<()> {
        if self.db.get_database_backend() != sea_orm::DatabaseBackend::Sqlite {
            return Ok(());
        }
        use sea_orm::{FromQueryResult, Statement};
        #[derive(FromQueryResult)]
        struct ColInfo {
            name: String,
        }
        let columns = ColInfo::find_by_statement(Statement::from_string(
            sea_orm::DatabaseBackend::Sqlite,
            "PRAGMA table_info(reflection)".to_string(),
        ))
        .all(&self.db)
        .await
        .wrap_err("failed to introspect reflection table for legacy schema check")?;
        let has_legacy_code_id = columns.iter().any(|c| c.name == "code_id");
        let has_run_id = columns.iter().any(|c| c.name == "run_id");
        if !columns.is_empty() && has_legacy_code_id && !has_run_id {
            tracing::warn!(
                "reflection table has legacy `code_id` column; dropping reflection + valid_finding + *_regen \
                 rows referencing it (this is a one-time migration; v9-era reflections were Gate 1/2 stubs \
                 superseded by inline fuzz gates)"
            );
            for sql in [
                "DROP TABLE IF EXISTS valid_finding",
                "DROP TABLE IF EXISTS code_gen_regen",
                "DROP TABLE IF EXISTS specification_regen",
                "DROP TABLE IF EXISTS reflection",
            ] {
                self.db.execute_unprepared(sql).await.wrap_err_with(|| {
                    format!("failed to drop legacy table during migration: {sql}")
                })?;
            }
        }
        Ok(())
    }

    /// Detect the pre-v? `specification` schema (no `historical_id`
    /// column). If found, drop `specification` and **every table that
    /// transitively references a spec** so the new schema can be
    /// created cleanly. Mirrors [`Self::drop_legacy_reflection_if_present`]
    /// in spirit: a one-time destructive SQLite-only migration; MySQL
    /// deployments don't have legacy rows.
    ///
    /// Tables dropped (downstream-of-spec):
    /// * `valid_finding` (FK → reflection)
    /// * `code_gen_regen` (refs code_gen)
    /// * `specification_regen` (refs specification)
    /// * `reflection` (FK → spec + harness_run)
    /// * `line_coverage` (FK → harness_run)
    /// * `harness_run` (FK → code_gen)
    /// * `code_gen` (FK → spec)
    /// * `specification` (the table we're migrating)
    ///
    /// Upstream tables (`project_semantic`, `semantic_matched`,
    /// `historical_*`, call graph / storage / inheritance) are
    /// preserved — they're pre-spec-phase, not affected by the column
    /// addition.
    async fn drop_legacy_specification_if_present(&self) -> Result<()> {
        if self.db.get_database_backend() != sea_orm::DatabaseBackend::Sqlite {
            return Ok(());
        }
        use sea_orm::{FromQueryResult, Statement};
        #[derive(FromQueryResult)]
        struct ColInfo {
            name: String,
        }
        let columns = ColInfo::find_by_statement(Statement::from_string(
            sea_orm::DatabaseBackend::Sqlite,
            "PRAGMA table_info(specification)".to_string(),
        ))
        .all(&self.db)
        .await
        .wrap_err("failed to introspect specification table for legacy schema check")?;
        let has_historical_id = columns.iter().any(|c| c.name == "historical_id");
        if !columns.is_empty() && !has_historical_id {
            tracing::warn!(
                "specification table lacks `historical_id` column; dropping it together with \
                 every table that references a spec (code_gen / harness_run / reflection / \
                 valid_finding / *_regen / line_coverage). One-time SQLite-only migration — the \
                 next run will repopulate these tables from scratch via the streamloop pipeline."
            );
            // Order matters where FKs are enforced: children before
            // parents. SQLite is permissive but we keep the order
            // consistent with FK ordering for clarity.
            for sql in [
                "DROP TABLE IF EXISTS valid_finding",
                "DROP TABLE IF EXISTS code_gen_regen",
                "DROP TABLE IF EXISTS specification_regen",
                "DROP TABLE IF EXISTS reflection",
                "DROP TABLE IF EXISTS line_coverage",
                "DROP TABLE IF EXISTS harness_run",
                "DROP TABLE IF EXISTS code_gen",
                "DROP TABLE IF EXISTS specification",
            ] {
                self.db.execute_unprepared(sql).await.wrap_err_with(|| {
                    format!("failed to drop legacy table during specification migration: {sql}")
                })?;
            }
        }
        Ok(())
    }

    /// Ensure this database is dedicated to `project_name`. Inserts the
    /// project identity row if the table is empty; rejects mismatched names
    /// and any state where multiple projects coexist in one database.
    pub async fn ensure_project(&self, project_name: &str) -> Result<()> {
        let projects = project_model::Entity::find()
            .order_by_asc(project_model::Column::Id)
            .all(&self.db)
            .await
            .wrap_err("failed to load project identity rows from project database")?;

        ensure!(
            projects.len() <= 1,
            "project database contains multiple projects ({}): {}; use one project database per project",
            projects.len(),
            projects
                .iter()
                .map(|project| format!("{}:{}", project.id, project.name))
                .collect::<Vec<_>>()
                .join(", ")
        );

        if let Some(project) = projects.first() {
            ensure!(
                project.name == project_name,
                "project database belongs to project '{}' (id={}) but current project is '{}'; use a different --database-url or clear the project database",
                project.name,
                project.id,
                project_name
            );
            return Ok(());
        }

        project_model::Entity::insert(project_model::ActiveModel {
            name: Set(project_name.to_string()),
            status: Set("pending".to_string()),
            ..Default::default()
        })
        .exec(&self.db)
        .await
        .wrap_err_with(|| {
            format!("failed to write project identity '{project_name}' to project database")
        })?;

        Ok(())
    }

    /// Load the per-project semantic snapshot.
    pub async fn load_project_semantics(&self) -> Result<Vec<ExtractedSemantic>> {
        let semantic_rows = project_semantic_model::Entity::find()
            .order_by_asc(project_semantic_model::Column::Id)
            .all(&self.db)
            .await
            .wrap_err("failed to load project_semantic rows")?;
        let function_rows = project_semantic_function_model::Entity::find()
            .order_by_asc(project_semantic_function_model::Column::SemanticId)
            .order_by_asc(project_semantic_function_model::Column::Id)
            .all(&self.db)
            .await
            .wrap_err("failed to load project_semantic_function rows")?;

        let mut semantics = semantic_rows
            .into_iter()
            .map(|row| {
                (
                    row.id,
                    ExtractedSemantic {
                        name: row.name,
                        category: row.category,
                        definition: row.definition,
                        description: row.description,
                        functions: Vec::new(),
                    },
                )
            })
            .collect::<BTreeMap<_, _>>();

        for row in function_rows {
            let semantic = semantics.get_mut(&row.semantic_id).wrap_err_with(|| {
                format!(
                    "project_semantic_function row {} references missing project semantic {}",
                    row.id, row.semantic_id
                )
            })?;
            semantic.functions.push(ExtractedFunction {
                name: row.name,
                contract: row.contract,
                signature: row.signature,
            });
        }

        Ok(semantics.into_values().collect())
    }

    /// Replace the per-project semantic snapshot. Destructive — clears every
    /// `project_semantic{,_function}` row before inserting `semantics`.
    pub async fn replace_project_semantics(&self, semantics: &[ExtractedSemantic]) -> Result<()> {
        let txn = self
            .db
            .begin()
            .await
            .wrap_err("failed to begin project semantic write transaction")?;

        project_semantic_function_model::Entity::delete_many()
            .exec(&txn)
            .await
            .wrap_err("failed to clear project_semantic_function rows")?;
        project_semantic_model::Entity::delete_many()
            .exec(&txn)
            .await
            .wrap_err("failed to clear project_semantic rows")?;

        let mut next_function_id: i32 = 1;
        for (index, semantic) in semantics.iter().enumerate() {
            let semantic_id = (index + 1) as i32;
            project_semantic_model::Entity::insert(project_semantic_model::ActiveModel {
                id: Set(semantic_id),
                name: Set(semantic.name.clone()),
                category: Set(semantic.category),
                definition: Set(semantic.definition.clone()),
                description: Set(semantic.description.clone()),
            })
            .exec(&txn)
            .await
            .wrap_err_with(|| format!("failed to insert project semantic {}", semantic_id))?;

            for function in &semantic.functions {
                let function_id = next_function_id;
                next_function_id += 1;
                project_semantic_function_model::Entity::insert(
                    project_semantic_function_model::ActiveModel {
                        id: Set(function_id),
                        semantic_id: Set(semantic_id),
                        name: Set(function.name.clone()),
                        contract: Set(function.contract.clone()),
                        signature: Set(function.signature.clone()),
                    },
                )
                .exec(&txn)
                .await
                .wrap_err_with(|| {
                    format!("failed to insert project semantic function {}", function_id)
                })?;
            }
        }

        txn.commit()
            .await
            .wrap_err("failed to commit project semantic write transaction")?;
        Ok(())
    }

    /// Read the call graph from this project's database.
    pub async fn load_call_graph(&self) -> Result<CallGraph> {
        let db = &self.db;
        let contract_rows = contract_model::Entity::find()
            .order_by_asc(contract_model::Column::Id)
            .all(db)
            .await
            .wrap_err("failed to load contracts from database")?;
        let interface_rows = interface_model::Entity::find()
            .order_by_asc(interface_model::Column::Id)
            .all(db)
            .await
            .wrap_err("failed to load interfaces from database")?;
        let function_rows = function_model::Entity::find()
            .order_by_asc(function_model::Column::Id)
            .all(db)
            .await
            .wrap_err("failed to load functions from database")?;
        let call_rows = function_call_model::Entity::find()
            .order_by_asc(function_call_model::Column::Id)
            .all(db)
            .await
            .wrap_err("failed to load function calls from database")?;
        let contract_function_rows = contract_functions_model::Entity::find()
            .order_by_asc(contract_functions_model::Column::ContractId)
            .order_by_asc(contract_functions_model::Column::FunctionId)
            .all(db)
            .await
            .wrap_err("failed to load contract/function links from database")?;
        let interface_function_rows = interface_functions_model::Entity::find()
            .order_by_asc(interface_functions_model::Column::InterfaceId)
            .order_by_asc(interface_functions_model::Column::FunctionId)
            .all(db)
            .await
            .wrap_err("failed to load interface/function links from database")?;

        let mut contracts = BTreeMap::new();
        for row in contract_rows {
            let loc = location_from_db(
                "contract",
                row.id,
                row.start_line,
                row.start_column,
                row.end_line,
                row.end_column,
            )?;
            contracts.insert(
                row.id,
                Contract {
                    id: row.id,
                    name: row.name,
                    relative_file_path: PathBuf::from(row.relative_file_path),
                    chunk: FileChunk {
                        loc,
                        content: row.content,
                    },
                    functions: Vec::new(),
                    description: row.description,
                },
            );
        }

        let mut interfaces = BTreeMap::new();
        for row in interface_rows {
            let loc = location_from_db(
                "interface",
                row.id,
                row.start_line,
                row.start_column,
                row.end_line,
                row.end_column,
            )?;
            interfaces.insert(
                row.id,
                Interface {
                    id: row.id,
                    name: row.name,
                    relative_file_path: PathBuf::from(row.relative_file_path),
                    chunk: FileChunk {
                        loc,
                        content: row.content,
                    },
                    functions: Vec::new(),
                    description: row.description,
                },
            );
        }

        let mut functions = BTreeMap::new();
        for row in function_rows {
            let loc = location_from_db(
                "function",
                row.id,
                row.start_line,
                row.start_column,
                row.end_line,
                row.end_column,
            )?;
            functions.insert(
                row.id,
                Function {
                    id: row.id,
                    name: row.name,
                    args: row.args,
                    relative_file_path: PathBuf::from(row.relative_file_path),
                    loc,
                    content: row.content,
                    calls: Vec::new(),
                    description: row.description,
                },
            );
        }

        for row in call_rows {
            ensure!(
                functions.contains_key(&row.rhs_id),
                "function_call row {} references missing rhs function {}",
                row.id,
                row.rhs_id
            );

            let call = FunctionCall {
                id: row.id,
                from_id: row.lhs_id,
                to_id: row.rhs_id,
                description: row.description,
            };
            let function = functions.get_mut(&row.lhs_id).wrap_err_with(|| {
                format!(
                    "function_call row {} references missing lhs function {}",
                    row.id, row.lhs_id
                )
            })?;
            function.calls.push(call);
        }

        for row in contract_function_rows {
            let function = functions.get(&row.function_id).cloned().wrap_err_with(|| {
                format!(
                    "contract_functions row {} references missing function {}",
                    row.id, row.function_id
                )
            })?;
            let contract = contracts.get_mut(&row.contract_id).wrap_err_with(|| {
                format!(
                    "contract_functions row {} references missing contract {}",
                    row.id, row.contract_id
                )
            })?;
            contract.functions.push(function);
        }

        for row in interface_function_rows {
            let function = functions.get(&row.function_id).cloned().wrap_err_with(|| {
                format!(
                    "interface_functions row {} references missing function {}",
                    row.id, row.function_id
                )
            })?;
            let interface = interfaces.get_mut(&row.interface_id).wrap_err_with(|| {
                format!(
                    "interface_functions row {} references missing interface {}",
                    row.id, row.interface_id
                )
            })?;
            interface.functions.push(function);
        }

        for contract in contracts.values_mut() {
            contract.functions.sort_by_key(|function| {
                (
                    function.loc.start_line,
                    function.loc.start_column,
                    function.id,
                )
            });
        }
        for interface in interfaces.values_mut() {
            interface.functions.sort_by_key(|function| {
                (
                    function.loc.start_line,
                    function.loc.start_column,
                    function.id,
                )
            });
        }

        Ok(CallGraph {
            contracts,
            interfaces,
        })
    }

    /// Replace the stored call graph with `call_graph`.
    pub async fn write_call_graph(&self, call_graph: &CallGraph) -> Result<()> {
        let txn = self
            .db
            .begin()
            .await
            .wrap_err("failed to begin callgraph write transaction")?;

        function_call_model::Entity::delete_many()
            .exec(&txn)
            .await
            .wrap_err("failed to clear function_call rows")?;
        contract_functions_model::Entity::delete_many()
            .exec(&txn)
            .await
            .wrap_err("failed to clear contract_functions rows")?;
        interface_functions_model::Entity::delete_many()
            .exec(&txn)
            .await
            .wrap_err("failed to clear interface_functions rows")?;
        function_model::Entity::delete_many()
            .exec(&txn)
            .await
            .wrap_err("failed to clear function rows")?;
        contract_model::Entity::delete_many()
            .exec(&txn)
            .await
            .wrap_err("failed to clear contract rows")?;
        interface_model::Entity::delete_many()
            .exec(&txn)
            .await
            .wrap_err("failed to clear interface rows")?;

        let mut inserted_function_ids = BTreeSet::new();
        let mut contract_function_id = 1;
        let mut interface_function_id = 1;

        for contract in call_graph.contracts.values() {
            let (start_line, start_column, end_line, end_column) =
                location_to_db("contract", contract.id, &contract.chunk.loc)?;
            contract_model::Entity::insert(contract_model::ActiveModel {
                id: Set(contract.id),
                name: Set(contract.name.clone()),
                relative_file_path: Set(contract.relative_file_path.to_string_lossy().to_string()),
                start_line: Set(start_line),
                start_column: Set(start_column),
                end_line: Set(end_line),
                end_column: Set(end_column),
                content: Set(contract.chunk.content.clone()),
                description: Set(contract.description.clone()),
            })
            .exec(&txn)
            .await
            .wrap_err_with(|| format!("failed to insert contract {}", contract.id))?;

            for function in &contract.functions {
                if inserted_function_ids.insert(function.id) {
                    let (start_line, start_column, end_line, end_column) =
                        location_to_db("function", function.id, &function.loc)?;
                    function_model::Entity::insert(function_model::ActiveModel {
                        id: Set(function.id),
                        name: Set(function.name.clone()),
                        args: Set(function.args.clone()),
                        relative_file_path: Set(function
                            .relative_file_path
                            .to_string_lossy()
                            .to_string()),
                        start_line: Set(start_line),
                        start_column: Set(start_column),
                        end_line: Set(end_line),
                        end_column: Set(end_column),
                        content: Set(function.content.clone()),
                        description: Set(function.description.clone()),
                    })
                    .exec(&txn)
                    .await
                    .wrap_err_with(|| format!("failed to insert function {}", function.id))?;
                }

                contract_functions_model::Entity::insert(contract_functions_model::ActiveModel {
                    id: Set(contract_function_id),
                    contract_id: Set(contract.id),
                    function_id: Set(function.id),
                })
                .exec(&txn)
                .await
                .wrap_err_with(|| {
                    format!(
                        "failed to link contract {} to function {}",
                        contract.id, function.id
                    )
                })?;
                contract_function_id += 1;
            }
        }

        for interface in call_graph.interfaces.values() {
            let (start_line, start_column, end_line, end_column) =
                location_to_db("interface", interface.id, &interface.chunk.loc)?;
            interface_model::Entity::insert(interface_model::ActiveModel {
                id: Set(interface.id),
                name: Set(interface.name.clone()),
                relative_file_path: Set(interface.relative_file_path.to_string_lossy().to_string()),
                start_line: Set(start_line),
                start_column: Set(start_column),
                end_line: Set(end_line),
                end_column: Set(end_column),
                content: Set(interface.chunk.content.clone()),
                description: Set(interface.description.clone()),
            })
            .exec(&txn)
            .await
            .wrap_err_with(|| format!("failed to insert interface {}", interface.id))?;

            for function in &interface.functions {
                if inserted_function_ids.insert(function.id) {
                    let (start_line, start_column, end_line, end_column) =
                        location_to_db("function", function.id, &function.loc)?;
                    function_model::Entity::insert(function_model::ActiveModel {
                        id: Set(function.id),
                        name: Set(function.name.clone()),
                        args: Set(function.args.clone()),
                        relative_file_path: Set(function
                            .relative_file_path
                            .to_string_lossy()
                            .to_string()),
                        start_line: Set(start_line),
                        start_column: Set(start_column),
                        end_line: Set(end_line),
                        end_column: Set(end_column),
                        content: Set(function.content.clone()),
                        description: Set(function.description.clone()),
                    })
                    .exec(&txn)
                    .await
                    .wrap_err_with(|| format!("failed to insert function {}", function.id))?;
                }

                interface_functions_model::Entity::insert(interface_functions_model::ActiveModel {
                    id: Set(interface_function_id),
                    interface_id: Set(interface.id),
                    function_id: Set(function.id),
                })
                .exec(&txn)
                .await
                .wrap_err_with(|| {
                    format!(
                        "failed to link interface {} to function {}",
                        interface.id, function.id
                    )
                })?;
                interface_function_id += 1;
            }
        }

        for contract in call_graph.contracts.values() {
            for function in &contract.functions {
                for call in &function.calls {
                    function_call_model::Entity::insert(function_call_model::ActiveModel {
                        id: Set(call.id),
                        lhs_id: Set(call.from_id),
                        rhs_id: Set(call.to_id),
                        description: Set(call.description.clone()),
                    })
                    .exec(&txn)
                    .await
                    .wrap_err_with(|| format!("failed to insert function_call {}", call.id))?;
                }
            }
        }

        for interface in call_graph.interfaces.values() {
            for function in &interface.functions {
                for call in &function.calls {
                    function_call_model::Entity::insert(function_call_model::ActiveModel {
                        id: Set(call.id),
                        lhs_id: Set(call.from_id),
                        rhs_id: Set(call.to_id),
                        description: Set(call.description.clone()),
                    })
                    .exec(&txn)
                    .await
                    .wrap_err_with(|| format!("failed to insert function_call {}", call.id))?;
                }
            }
        }

        txn.commit()
            .await
            .wrap_err("failed to commit callgraph write transaction")?;
        Ok(())
    }

    /// Read the storage graph from this project's database.
    pub async fn load_storage_graph(&self) -> Result<StorageGraph> {
        let db = &self.db;
        let mut graph = StorageGraph::default();

        let svs = state_variable_model::Entity::find()
            .order_by_asc(state_variable_model::Column::Id)
            .all(db)
            .await
            .wrap_err("failed to load state_variable rows")?;
        for sv in svs {
            graph.state_variables.insert(
                sv.id,
                StateVariable {
                    id: sv.id,
                    name: sv.name,
                    type_name: sv.type_name,
                    relative_file_path: PathBuf::from(sv.relative_file_path),
                    loc: crate::cg::FileLocation {
                        start_line: sv.start_line as usize,
                        start_column: sv.start_column as usize,
                        end_line: sv.end_line as usize,
                        end_column: sv.end_column as usize,
                    },
                    content: sv.content,
                },
            );
        }

        let cvs = contract_variable_model::Entity::find()
            .order_by_asc(contract_variable_model::Column::Id)
            .all(db)
            .await
            .wrap_err("failed to load contract_variable rows")?;
        for cv in cvs {
            graph.contract_variables.push(ContractVariable {
                contract_id: cv.contract_id,
                state_variable_id: cv.state_variable_id,
                description: cv.description,
            });
        }

        let fsvs = function_state_variable_model::Entity::find()
            .order_by_asc(function_state_variable_model::Column::Id)
            .all(db)
            .await
            .wrap_err("failed to load function_state_variable rows")?;
        for fsv in fsvs {
            graph.function_state_variables.push(FunctionStateVariable {
                function_id: fsv.function_id,
                state_variable_id: fsv.state_variable_id,
                is_write: fsv.is_write,
                description: fsv.description,
            });
        }

        Ok(graph)
    }

    /// Replace the stored storage graph with `storage`.
    pub async fn write_storage_graph(&self, storage: &StorageGraph) -> Result<()> {
        let txn = self
            .db
            .begin()
            .await
            .wrap_err("failed to begin storage write transaction")?;

        function_state_variable_model::Entity::delete_many()
            .exec(&txn)
            .await
            .wrap_err("failed to clear function_state_variable rows")?;
        contract_variable_model::Entity::delete_many()
            .exec(&txn)
            .await
            .wrap_err("failed to clear contract_variable rows")?;
        state_variable_model::Entity::delete_many()
            .exec(&txn)
            .await
            .wrap_err("failed to clear state_variable rows")?;

        for sv in storage.state_variables.values() {
            state_variable_model::Entity::insert(state_variable_model::ActiveModel {
                id: Set(sv.id),
                name: Set(sv.name.clone()),
                type_name: Set(sv.type_name.clone()),
                relative_file_path: Set(sv.relative_file_path.to_string_lossy().to_string()),
                start_line: Set(sv.loc.start_line as i32),
                start_column: Set(sv.loc.start_column as i32),
                end_line: Set(sv.loc.end_line as i32),
                end_column: Set(sv.loc.end_column as i32),
                content: Set(sv.content.clone()),
            })
            .exec(&txn)
            .await
            .wrap_err_with(|| format!("failed to insert state_variable {}", sv.id))?;
        }

        let mut next_cv_id = 1i32;
        for cv in &storage.contract_variables {
            contract_variable_model::Entity::insert(contract_variable_model::ActiveModel {
                id: Set(next_cv_id),
                contract_id: Set(cv.contract_id),
                state_variable_id: Set(cv.state_variable_id),
                description: Set(cv.description.clone()),
            })
            .exec(&txn)
            .await
            .wrap_err_with(|| {
                format!(
                    "failed to insert contract_variable contract={} sv={}",
                    cv.contract_id, cv.state_variable_id
                )
            })?;
            next_cv_id += 1;
        }

        let mut next_fsv_id = 1i32;
        for fsv in &storage.function_state_variables {
            function_state_variable_model::Entity::insert(
                function_state_variable_model::ActiveModel {
                    id: Set(next_fsv_id),
                    function_id: Set(fsv.function_id),
                    state_variable_id: Set(fsv.state_variable_id),
                    is_write: Set(fsv.is_write),
                    description: Set(fsv.description.clone()),
                },
            )
            .exec(&txn)
            .await
            .wrap_err_with(|| {
                format!(
                    "failed to insert function_state_variable function={} sv={}",
                    fsv.function_id, fsv.state_variable_id
                )
            })?;
            next_fsv_id += 1;
        }

        txn.commit()
            .await
            .wrap_err("failed to commit storage write transaction")?;
        Ok(())
    }

    /// Load every `is`-clause edge into an [`InheritanceGraph`]. Cheap
    /// (one table scan, no joins) — call it any time both call-graph
    /// and inheritance facts are needed (e.g. interface dispatch
    /// resolution via [`crate::cg::CallGraph::resolve_interface_function`]).
    pub async fn load_inheritance_graph(&self) -> Result<InheritanceGraph> {
        let rows = contract_inherit_model::Entity::find()
            .all(&self.db)
            .await
            .wrap_err("failed to load contract_inherit rows")?;
        let inherits = rows
            .into_iter()
            .map(|r| ContractInherit {
                contract_id: r.contract_id,
                inherited_id: r.inherited_id,
            })
            .collect();
        Ok(InheritanceGraph::new(inherits))
    }

    /// Replace every stored inheritance edge with the contents of
    /// `graph`. Independent of the storage / call-graph write paths so
    /// each piece can be refreshed in isolation.
    pub async fn write_inheritance_graph(&self, graph: &InheritanceGraph) -> Result<()> {
        let txn = self
            .db
            .begin()
            .await
            .wrap_err("failed to begin inheritance write transaction")?;
        contract_inherit_model::Entity::delete_many()
            .exec(&txn)
            .await
            .wrap_err("failed to clear contract_inherit rows")?;
        for inh in &graph.inherits {
            contract_inherit_model::Entity::insert(contract_inherit_model::ActiveModel {
                contract_id: Set(inh.contract_id),
                inherited_id: Set(inh.inherited_id),
            })
            .exec(&txn)
            .await
            .wrap_err_with(|| {
                format!(
                    "failed to insert contract_inherit ({}, {})",
                    inh.contract_id, inh.inherited_id
                )
            })?;
        }
        txn.commit()
            .await
            .wrap_err("failed to commit inheritance write transaction")?;
        Ok(())
    }

    /// Render the storage graph as a Graphviz DOT string. Loads contract /
    /// interface / function rows on top of `storage` so labels include
    /// human-readable names.
    pub async fn export_storage_dot(
        &self,
        storage: &StorageGraph,
        options: StorageDotOptions,
    ) -> Result<String> {
        let db = &self.db;
        let contracts = contract_model::Entity::find()
            .order_by_asc(contract_model::Column::Id)
            .all(db)
            .await
            .wrap_err("failed to load contracts for storage DOT export")?;
        let interfaces = interface_model::Entity::find()
            .order_by_asc(interface_model::Column::Id)
            .all(db)
            .await
            .wrap_err("failed to load interfaces for storage DOT export")?;
        let functions = function_model::Entity::find()
            .order_by_asc(function_model::Column::Id)
            .all(db)
            .await
            .wrap_err("failed to load functions for storage DOT export")?;

        let mut contract_name_by_id: HashMap<i32, String> = HashMap::new();
        for c in &contracts {
            contract_name_by_id.insert(c.id, c.name.clone());
        }
        for i in &interfaces {
            contract_name_by_id.insert(i.id, i.name.clone());
        }

        let mut function_label_by_id: HashMap<i32, String> = HashMap::new();
        for f in &functions {
            function_label_by_id.insert(f.id, f.name.clone());
        }

        let mut declaring_contract: HashMap<i32, i32> = HashMap::new();
        for cv in &storage.contract_variables {
            declaring_contract
                .entry(cv.state_variable_id)
                .or_insert(cv.contract_id);
        }

        let touched_state_vars: BTreeSet<i32> = storage
            .function_state_variables
            .iter()
            .map(|fsv| fsv.state_variable_id)
            .collect();
        let touching_functions: BTreeSet<i32> = storage
            .function_state_variables
            .iter()
            .map(|fsv| fsv.function_id)
            .collect();

        let mut out = String::new();
        writeln!(out, "digraph StorageRW {{").unwrap();
        writeln!(out, "  rankdir=LR;").unwrap();
        writeln!(out, "  node [fontname=Helvetica];").unwrap();
        writeln!(out, "  edge [fontname=Helvetica, fontsize=10];").unwrap();

        for sv in storage.state_variables.values() {
            if !options.include_isolated_state_variables && !touched_state_vars.contains(&sv.id) {
                continue;
            }
            let owner = declaring_contract
                .get(&sv.id)
                .and_then(|cid| contract_name_by_id.get(cid))
                .map(|n| n.as_str())
                .unwrap_or("?");
            let label = format!("{}.{}\\n{}", owner, sv.name, sv.type_name);
            writeln!(
                out,
                "  sv{} [shape=box, style=\"filled\", fillcolor=\"#fff2cc\", label=\"{}\"];",
                sv.id,
                dot_escape(&label)
            )
            .unwrap();
        }

        for fid in &touching_functions {
            let label = function_label_by_id
                .get(fid)
                .map(|s| s.as_str())
                .unwrap_or("?");
            writeln!(
                out,
                "  fn{} [shape=ellipse, label=\"{}\"];",
                fid,
                dot_escape(label)
            )
            .unwrap();
        }

        for fsv in &storage.function_state_variables {
            if fsv.is_write {
                writeln!(
                    out,
                    "  fn{} -> sv{} [color=\"#cc0000\", label=\"W\"];",
                    fsv.function_id, fsv.state_variable_id
                )
                .unwrap();
            } else {
                writeln!(
                    out,
                    "  fn{} -> sv{} [color=\"#1f4faf\", style=dashed, label=\"R\"];",
                    fsv.function_id, fsv.state_variable_id
                )
                .unwrap();
            }
        }

        writeln!(out, "}}").unwrap();
        Ok(out)
    }
}

/// One `(finding, strength, evidence)` triple inside a
/// [`HistoricalSemanticRecord`]. Carries the KG link's strength + evidence
/// alongside the finding so the mirror write in
/// [`RepoDatabase::write_semantic_match_results`] can populate
/// `historical_semantic_finding_link.strength` / `evidence` without a second
/// pass against the KG.
/// One raw finding folded into a canonical in the historical KG, mirrored into
/// the project DB with the merge-edge `appended_*` notes (its concrete delta).
#[derive(Debug, Clone)]
pub struct HistoricalFindingChild {
    pub finding: knowdit_kg_model::db::audit_finding::Model,
    pub appended_description: String,
    pub appended_patterns: String,
    pub appended_exploits: String,
}

/// One raw semantic folded into a canonical, mirrored with its merge-edge note.
#[derive(Debug, Clone)]
pub struct HistoricalSemanticChild {
    pub node: knowdit_kg_model::db::semantic_node::Model,
    pub appended_description: String,
}

#[derive(Debug, Clone)]
pub struct HistoricalLinkedFinding {
    pub finding: knowdit_kg_model::db::audit_finding::Model,
    pub strength: knowdit_kg_model::link_strength::LinkStrength,
    pub evidence: String,
    /// Raw findings folded into `finding` (write path: mapper populates them so
    /// the mirror carries children + edges). Empty on the read path.
    pub raw_children: Vec<HistoricalFindingChild>,
    /// `finding`'s fields rendered with their merged-variant deltas (read path:
    /// `load_semantic_match_results` populates them). Empty on the write path;
    /// fall back to the raw field when empty.
    pub rendered_description: String,
    pub rendered_patterns: String,
    pub rendered_exploits: String,
}

/// One historical semantic identified by the Knowledge Mapper, together with
/// the historical findings the kg associates with it. Each finding carries
/// the KG link's `strength` + `evidence` because both columns are mirrored
/// into the project RepoDB (`historical_semantic_finding_link.strength` /
/// `evidence`) for downstream gen-specs filtering.
#[derive(Debug, Clone)]
pub struct HistoricalSemanticRecord {
    pub semantic: knowdit_kg_model::db::semantic_node::Model,
    pub findings: Vec<HistoricalLinkedFinding>,
    /// Raw semantics folded into `semantic` (write path: mapper populates them).
    /// Empty on the read path.
    pub raw_children: Vec<HistoricalSemanticChild>,
    /// `semantic.description` rendered with its merged-variant deltas (read
    /// path: `load_semantic_match_results` populates it). Empty on the write
    /// path; fall back to `semantic.description` when empty.
    pub rendered_description: String,
}

/// One mapper-emitted match between a project extract and a historical
/// semantic, with the v2 mapper's `strength` label and free-form
/// `evidence` rationale.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SemanticMatch {
    pub extract_id: i32,
    pub historical_id: i32,
    pub strength: MatchStrength,
    pub evidence: String,
}

/// Self-contained provenance for one finding: a thin bundle of the actual
/// project-DB rows (the existing sea_orm `Model`s, serialized to their scalar
/// columns — relation fields are stripped by `#[sea_orm::model]`) that explain
/// where a spec's finding came from, so an on-disk finding JSON needs no KG
/// database to be understood. Built by
/// [`RepoDatabase::load_provenance_for_spec`].
///
/// Reuses the row models directly rather than re-declaring their fields:
/// `extract` / `historical_semantic` / `historical_finding` carry the full
/// content; `semantic_match` / `finding_link` are the two graded edges
/// (`strength` + `evidence`) and are `Option` because a spec can outlive its
/// mapper / link rows.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FindingProvenance {
    /// The project semantic (extract) row the spec was generated from.
    pub extract: project_semantic_model::Model,
    /// Mapper match on the `(extract, historical)` pair.
    pub semantic_match: Option<semantic_matched_model::Model>,
    /// The historical (KG) semantic the extract was matched to.
    pub historical_semantic: historical_semantic_model::Model,
    /// KG link on the `(historical_semantic, historical_finding)` edge.
    pub finding_link: Option<historical_semantic_finding_link_model::Model>,
    /// The historical (KG) finding that motivated the spec.
    pub historical_finding: historical_finding_model::Model,
}

/// Aggregate output of one Knowledge Mapper pass, ready to be written into a
/// project database via [`RepoDatabase::write_semantic_match_results`].
#[derive(Debug, Clone, Default)]
pub struct SemanticMatchSet {
    /// Historical semantics referenced by `matches`, with their findings.
    pub historicals: Vec<HistoricalSemanticRecord>,
    /// Matched pairs the mapper emitted, with per-pair strength label
    /// and rationale (v2 mapper).
    pub matches: Vec<SemanticMatch>,
}

/// Per-project profile produced by the autoloop `profile` phase and
/// consumed by the Knowledge Mapper. Serialised as JSON into the
/// `project_metadata` row with `key = "profile"`. The shape is shared
/// between the profile generator (which writes it) and the mapper
/// (which reads it back), so this struct is the single source of
/// truth for both sides.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ProjectProfile {
    /// Project source language, declared by the profile agent
    /// after reading the project sources. This is the
    /// **authoritative** language signal downstream phases
    /// (mapper / spec / reflect / regen) consume — by the time
    /// any of them runs, the profile row exists and its
    /// `language` field is the one source of truth. The
    /// project-load auto-detector
    /// (`knowdit_project::ProjectData::language`) is still used
    /// **before profile completes** (for harness backend
    /// selection + CG ingest path), but the profile-agent
    /// declaration overrides it for prompt purposes.
    pub language: crate::SourceLanguage,
    /// ~200-word prose paragraph describing what this project IS.
    pub domain_summary: String,
    /// LLM-chosen short labels for the mechanisms / subsystems the
    /// project implements, each with a one-sentence mechanism summary
    /// the mapper can match against historical semantics. There is no
    /// canonical vocabulary — `name` is free-form, `summary` carries
    /// the actual matchable signal.
    pub subsystems: Vec<ProjectSubsystem>,
    /// Main in-scope contracts with their one-sentence role.
    pub core_components: Vec<ProjectComponent>,
    /// Free prose listing subdomains the project explicitly does NOT
    /// have (e.g. "no lending market, no AMM positions"). Used by the
    /// mapper to confidently emit Low when the historical's mechanism
    /// is excluded by the project.
    pub out_of_scope_notes: String,
    /// Files the profile-gen agent actually opened via `read_file`.
    pub source_files_read: Vec<String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ProjectSubsystem {
    pub name: String,
    pub summary: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ProjectComponent {
    pub name: String,
    pub path: String,
    pub role: String,
}

/// Reserved `project_metadata.key` for the [`ProjectProfile`] payload.
pub const METADATA_KEY_PROFILE: &str = "profile";

impl RepoDatabase {
    /// Replace the per-project mapper output: clears every
    /// `historical_semantic`, `historical_finding`,
    /// `historical_semantic_finding_link`, and `semantic_matched` row before
    /// inserting the contents of `set`. Cross-DB ids from the historical kg
    /// are preserved verbatim.
    pub async fn write_semantic_match_results(&self, set: &SemanticMatchSet) -> Result<()> {
        use std::collections::BTreeSet;

        let txn = self
            .db
            .begin()
            .await
            .wrap_err("failed to begin semantic-match write transaction")?;

        semantic_matched_model::Entity::delete_many()
            .exec(&txn)
            .await
            .wrap_err("failed to clear semantic_matched rows")?;
        historical_semantic_finding_link_model::Entity::delete_many()
            .exec(&txn)
            .await
            .wrap_err("failed to clear historical_semantic_finding_link rows")?;
        historical_finding_model::Entity::delete_many()
            .exec(&txn)
            .await
            .wrap_err("failed to clear historical_finding rows")?;
        historical_semantic_model::Entity::delete_many()
            .exec(&txn)
            .await
            .wrap_err("failed to clear historical_semantic rows")?;
        historical_semantic_merge_model::Entity::delete_many()
            .exec(&txn)
            .await
            .wrap_err("failed to clear historical_semantic_merge rows")?;
        historical_finding_merge_model::Entity::delete_many()
            .exec(&txn)
            .await
            .wrap_err("failed to clear historical_finding_merge rows")?;

        let mut inserted_finding_ids = BTreeSet::new();
        let mut inserted_semantic_ids = BTreeSet::new();
        for record in &set.historicals {
            let mirror: historical_semantic_model::Model = record.semantic.clone().into();
            historical_semantic_model::Entity::insert(historical_semantic_model::ActiveModel {
                id: Set(mirror.id),
                name: Set(mirror.name),
                definition: Set(mirror.definition),
                description: Set(mirror.description),
                category: Set(mirror.category),
            })
            .exec(&txn)
            .await
            .wrap_err_with(|| {
                format!(
                    "failed to insert historical_semantic {}",
                    record.semantic.id
                )
            })?;
            inserted_semantic_ids.insert(record.semantic.id);

            for linked in &record.findings {
                let finding = &linked.finding;
                if inserted_finding_ids.insert(finding.id) {
                    let mirror: historical_finding_model::Model = finding.clone().into();
                    historical_finding_model::Entity::insert(
                        historical_finding_model::ActiveModel {
                            id: Set(mirror.id),
                            title: Set(mirror.title),
                            severity: Set(mirror.severity),
                            root_cause: Set(mirror.root_cause),
                            description: Set(mirror.description),
                            patterns: Set(mirror.patterns),
                            exploits: Set(mirror.exploits),
                        },
                    )
                    .exec(&txn)
                    .await
                    .wrap_err_with(|| {
                        format!("failed to insert historical_finding {}", finding.id)
                    })?;
                }

                historical_semantic_finding_link_model::Entity::insert(
                    historical_semantic_finding_link_model::ActiveModel {
                        historical_semantic_id: Set(record.semantic.id),
                        historical_finding_id: Set(finding.id),
                        strength: Set(linked.strength),
                        evidence: Set(linked.evidence.clone()),
                    },
                )
                .exec(&txn)
                .await
                .wrap_err_with(|| {
                    format!(
                        "failed to link historical_semantic {} to historical_finding {}",
                        record.semantic.id, finding.id
                    )
                })?;

                // Mirror the raw findings folded into this canonical + their
                // merge-edge notes (child rows deduped across the whole set).
                for child in &linked.raw_children {
                    if inserted_finding_ids.insert(child.finding.id) {
                        let m: historical_finding_model::Model = child.finding.clone().into();
                        historical_finding_model::Entity::insert(
                            historical_finding_model::ActiveModel {
                                id: Set(m.id),
                                title: Set(m.title),
                                severity: Set(m.severity),
                                root_cause: Set(m.root_cause),
                                description: Set(m.description),
                                patterns: Set(m.patterns),
                                exploits: Set(m.exploits),
                            },
                        )
                        .exec(&txn)
                        .await
                        .wrap_err_with(|| {
                            format!(
                                "failed to insert historical_finding child {}",
                                child.finding.id
                            )
                        })?;
                    }
                    historical_finding_merge_model::Entity::insert(
                        historical_finding_merge_model::ActiveModel {
                            from_finding_id: Set(child.finding.id),
                            to_finding_id: Set(finding.id),
                            appended_description: Set(child.appended_description.clone()),
                            appended_patterns: Set(child.appended_patterns.clone()),
                            appended_exploits: Set(child.appended_exploits.clone()),
                        },
                    )
                    .exec(&txn)
                    .await
                    .wrap_err_with(|| {
                        format!(
                            "failed to insert historical_finding_merge {}→{}",
                            child.finding.id, finding.id
                        )
                    })?;
                }
            }

            // Mirror the raw semantics folded into this canonical + their edges.
            for child in &record.raw_children {
                if inserted_semantic_ids.insert(child.node.id) {
                    let m: historical_semantic_model::Model = child.node.clone().into();
                    historical_semantic_model::Entity::insert(
                        historical_semantic_model::ActiveModel {
                            id: Set(m.id),
                            name: Set(m.name),
                            definition: Set(m.definition),
                            description: Set(m.description),
                            category: Set(m.category),
                        },
                    )
                    .exec(&txn)
                    .await
                    .wrap_err_with(|| {
                        format!(
                            "failed to insert historical_semantic child {}",
                            child.node.id
                        )
                    })?;
                }
                historical_semantic_merge_model::Entity::insert(
                    historical_semantic_merge_model::ActiveModel {
                        from_semantic_id: Set(child.node.id),
                        to_semantic_id: Set(record.semantic.id),
                        appended_description: Set(child.appended_description.clone()),
                    },
                )
                .exec(&txn)
                .await
                .wrap_err_with(|| {
                    format!(
                        "failed to insert historical_semantic_merge {}→{}",
                        child.node.id, record.semantic.id
                    )
                })?;
            }
        }

        for m in &set.matches {
            semantic_matched_model::Entity::insert(semantic_matched_model::ActiveModel {
                extract_id: Set(m.extract_id),
                historical_id: Set(m.historical_id),
                strength: Set(m.strength),
                evidence: Set(m.evidence.clone()),
                ..Default::default()
            })
            .exec(&txn)
            .await
            .wrap_err_with(|| {
                format!(
                    "failed to insert semantic_matched extract={} historical={} strength={}",
                    m.extract_id, m.historical_id, m.strength
                )
            })?;
        }

        txn.commit()
            .await
            .wrap_err("failed to commit semantic-match write transaction")?;
        Ok(())
    }

    /// Render a mirrored canonical semantic's `description` followed by up to
    /// `cap` merged-variant notes (`historical_semantic_merge.appended_description`),
    /// so a consumer sees the bounded representative plus each folded raw's
    /// concrete delta. Returns `""` if the canonical is absent.
    pub async fn render_semantic_description(
        &self,
        semantic_id: i32,
        cap: usize,
    ) -> Result<String> {
        let Some(canonical) = historical_semantic_model::Entity::find_by_id(semantic_id)
            .one(&self.db)
            .await
            .wrap_err("failed to load historical_semantic for render")?
        else {
            return Ok(String::new());
        };
        let notes = self.semantic_merge_notes(semantic_id).await?;
        Ok(knowdit_kg_model::render::render_with_variants(
            &canonical.description,
            &notes,
            cap,
        ))
    }

    /// Render a mirrored canonical finding's `(description, patterns, exploits)`,
    /// each followed by up to `cap` merged-variant notes from
    /// `historical_finding_merge`. Returns empty strings if the canonical is absent.
    pub async fn render_finding_fields(
        &self,
        finding_id: i32,
        cap: usize,
    ) -> Result<(String, String, String)> {
        use sea_orm::{ColumnTrait, QueryFilter};
        let Some(canonical) = historical_finding_model::Entity::find_by_id(finding_id)
            .one(&self.db)
            .await
            .wrap_err("failed to load historical_finding for render")?
        else {
            return Ok((String::new(), String::new(), String::new()));
        };
        let edges = historical_finding_merge_model::Entity::find()
            .filter(historical_finding_merge_model::Column::ToFindingId.eq(finding_id))
            .all(&self.db)
            .await
            .wrap_err("failed to load historical_finding_merge for render")?;
        let notes = |pick: fn(&historical_finding_merge_model::Model) -> &str| -> Vec<String> {
            edges
                .iter()
                .map(|e| pick(e).trim().to_string())
                .filter(|n| !n.is_empty())
                .collect()
        };
        use knowdit_kg_model::render::render_with_variants;
        Ok((
            render_with_variants(
                &canonical.description,
                &notes(|e| &e.appended_description),
                cap,
            ),
            render_with_variants(&canonical.patterns, &notes(|e| &e.appended_patterns), cap),
            render_with_variants(&canonical.exploits, &notes(|e| &e.appended_exploits), cap),
        ))
    }

    /// Non-empty `appended_description` notes of the raws folded into
    /// `semantic_id` (via `historical_semantic_merge`).
    async fn semantic_merge_notes(&self, semantic_id: i32) -> Result<Vec<String>> {
        use sea_orm::{ColumnTrait, QueryFilter};
        Ok(historical_semantic_merge_model::Entity::find()
            .filter(historical_semantic_merge_model::Column::ToSemanticId.eq(semantic_id))
            .all(&self.db)
            .await
            .wrap_err("failed to load historical_semantic_merge for render")?
            .into_iter()
            .map(|e| e.appended_description.trim().to_string())
            .filter(|n| !n.is_empty())
            .collect())
    }

    /// Read the previously written mapper output back into memory. Returns
    /// historical semantics paired with their findings, plus the matched
    /// `(extract_id, historical_id)` pairs. The merged-variant notes folded into
    /// each record's `rendered_*` are capped at `self.variant_render_cap`
    /// (configured via [`Self::with_variant_render_cap`]).
    pub async fn load_semantic_match_results(&self) -> Result<SemanticMatchSet> {
        use knowdit_kg_model::render::render_with_variants;
        use std::collections::{BTreeMap, BTreeSet};

        let variant_render_cap = self.variant_render_cap;

        let semantic_rows = historical_semantic_model::Entity::find()
            .order_by_asc(historical_semantic_model::Column::Id)
            .all(&self.db)
            .await
            .wrap_err("failed to load historical_semantic rows")?;
        let finding_rows = historical_finding_model::Entity::find()
            .order_by_asc(historical_finding_model::Column::Id)
            .all(&self.db)
            .await
            .wrap_err("failed to load historical_finding rows")?;
        let link_rows = historical_semantic_finding_link_model::Entity::find()
            .all(&self.db)
            .await
            .wrap_err("failed to load historical_semantic_finding_link rows")?;
        let match_rows = semantic_matched_model::Entity::find()
            .order_by_asc(semantic_matched_model::Column::Id)
            .all(&self.db)
            .await
            .wrap_err("failed to load semantic_matched rows")?;

        let findings_by_id: BTreeMap<i32, knowdit_kg_model::db::audit_finding::Model> =
            finding_rows
                .into_iter()
                .map(|row| (row.id, row.into()))
                .collect();

        // Merge edges: which rows are folded-away children (excluded from the
        // canonical record set) and the per-canonical variant notes to render.
        let sem_merge_rows = historical_semantic_merge_model::Entity::find()
            .all(&self.db)
            .await
            .wrap_err("failed to load historical_semantic_merge rows")?;
        let mut sem_child_ids: BTreeSet<i32> = BTreeSet::new();
        let mut sem_notes: BTreeMap<i32, Vec<String>> = BTreeMap::new();
        for e in sem_merge_rows {
            sem_child_ids.insert(e.from_semantic_id);
            let note = e.appended_description.trim().to_string();
            if !note.is_empty() {
                sem_notes.entry(e.to_semantic_id).or_default().push(note);
            }
        }
        let find_merge_rows = historical_finding_merge_model::Entity::find()
            .all(&self.db)
            .await
            .wrap_err("failed to load historical_finding_merge rows")?;
        let mut find_notes: BTreeMap<i32, (Vec<String>, Vec<String>, Vec<String>)> =
            BTreeMap::new();
        for e in find_merge_rows {
            let entry = find_notes.entry(e.to_finding_id).or_default();
            let d = e.appended_description.trim();
            if !d.is_empty() {
                entry.0.push(d.to_string());
            }
            let p = e.appended_patterns.trim();
            if !p.is_empty() {
                entry.1.push(p.to_string());
            }
            let x = e.appended_exploits.trim();
            if !x.is_empty() {
                entry.2.push(x.to_string());
            }
        }

        // Index by semantic_id → Vec<(finding_id, strength, evidence)> so we
        // preserve the per-link strength/evidence columns when materialising
        // HistoricalLinkedFinding entries.
        let mut links_for_semantic: BTreeMap<
            i32,
            Vec<(i32, knowdit_kg_model::link_strength::LinkStrength, String)>,
        > = BTreeMap::new();
        for link in link_rows {
            links_for_semantic
                .entry(link.historical_semantic_id)
                .or_default()
                .push((link.historical_finding_id, link.strength, link.evidence));
        }

        let no_notes: (Vec<String>, Vec<String>, Vec<String>) = Default::default();
        let mut historicals = Vec::new();
        for row in semantic_rows {
            let semantic_id = row.id;
            // Skip folded-away children — they are mirrored for provenance but
            // are not matched canonicals, so they must not become records (that
            // would fan out spurious LinkInputs downstream).
            if sem_child_ids.contains(&semantic_id) {
                continue;
            }
            let semantic: knowdit_kg_model::db::semantic_node::Model = row.into();
            let rendered_description = render_with_variants(
                &semantic.description,
                sem_notes
                    .get(&semantic_id)
                    .map(Vec::as_slice)
                    .unwrap_or(&[]),
                variant_render_cap,
            );
            let findings = links_for_semantic
                .remove(&semantic_id)
                .unwrap_or_default()
                .into_iter()
                .filter_map(|(fid, strength, evidence)| {
                    findings_by_id.get(&fid).cloned().map(|finding| {
                        let (dn, pn, xn) = find_notes.get(&fid).unwrap_or(&no_notes);
                        HistoricalLinkedFinding {
                            rendered_description: render_with_variants(
                                &finding.description,
                                dn,
                                variant_render_cap,
                            ),
                            rendered_patterns: render_with_variants(
                                &finding.patterns,
                                pn,
                                variant_render_cap,
                            ),
                            rendered_exploits: render_with_variants(
                                &finding.exploits,
                                xn,
                                variant_render_cap,
                            ),
                            raw_children: Vec::new(),
                            finding,
                            strength,
                            evidence,
                        }
                    })
                })
                .collect();
            historicals.push(HistoricalSemanticRecord {
                semantic,
                findings,
                raw_children: Vec::new(),
                rendered_description,
            });
        }

        let matches = match_rows
            .into_iter()
            .map(|row| SemanticMatch {
                extract_id: row.extract_id,
                historical_id: row.historical_id,
                strength: row.strength,
                evidence: row.evidence,
            })
            .collect();

        Ok(SemanticMatchSet {
            historicals,
            matches,
        })
    }

    // -----------------------------------------------------------------
    // project_metadata: generic per-DB KV store. ProjectProfile lives
    // here under `key = METADATA_KEY_PROFILE`; future per-DB metadata
    // (KG version fingerprint, etc.) can plug into the same table
    // without new migrations.
    // -----------------------------------------------------------------

    /// Read one metadata value as raw JSON. Returns `None` if `key` has
    /// no row.
    pub async fn get_metadata(&self, key: &str) -> Result<Option<serde_json::Value>> {
        let row = project_metadata_model::Entity::find_by_id(key.to_string())
            .one(&self.db)
            .await
            .wrap_err_with(|| format!("failed to load project_metadata row '{key}'"))?;
        let Some(row) = row else { return Ok(None) };
        let parsed = serde_json::from_str(&row.value).wrap_err_with(|| {
            format!("project_metadata '{key}' is not valid JSON: {}", row.value)
        })?;
        Ok(Some(parsed))
    }

    /// Upsert one metadata value via SeaORM's
    /// `Entity::insert(...).on_conflict(...)`. SeaORM emits the
    /// correct dialect (`INSERT OR REPLACE` on SQLite,
    /// `INSERT ... ON DUPLICATE KEY UPDATE` on MySQL) for the same
    /// builder call, so we don't hand-roll dialect-specific SQL.
    /// Single statement → atomic → satisfies plan §1.5 "no dirty data
    /// on interrupt".
    pub async fn set_metadata(&self, key: &str, value: &serde_json::Value) -> Result<()> {
        let serialized = serde_json::to_string(value)
            .wrap_err_with(|| format!("failed to serialise project_metadata '{key}'"))?;
        project_metadata_model::Entity::insert(project_metadata_model::ActiveModel {
            key: Set(key.to_string()),
            value: Set(serialized),
        })
        .on_conflict(
            sea_orm::sea_query::OnConflict::column(project_metadata_model::Column::Key)
                .update_column(project_metadata_model::Column::Value)
                .to_owned(),
        )
        .exec(&self.db)
        .await
        .wrap_err_with(|| format!("failed to write project_metadata '{key}'"))?;
        Ok(())
    }

    /// Typed read of the [`ProjectProfile`] payload from
    /// `project_metadata` row `key = "profile"`. Returns `None` when
    /// no profile has been written for this DB yet (autoloop profile
    /// phase resume signal).
    pub async fn get_project_profile(&self) -> Result<Option<ProjectProfile>> {
        let Some(value) = self.get_metadata(METADATA_KEY_PROFILE).await? else {
            return Ok(None);
        };
        let profile: ProjectProfile = serde_json::from_value(value)
            .wrap_err("project_metadata 'profile' value is not a valid ProjectProfile")?;
        Ok(Some(profile))
    }

    /// Typed write of the [`ProjectProfile`] payload. Single atomic
    /// `INSERT OR REPLACE`, so a profile-gen agent that crashes
    /// mid-run leaves no partial row behind (plan §1.5).
    pub async fn set_project_profile(&self, profile: &ProjectProfile) -> Result<()> {
        let value =
            serde_json::to_value(profile).wrap_err("failed to serialise ProjectProfile to JSON")?;
        self.set_metadata(METADATA_KEY_PROFILE, &value).await
    }
}

/// One audit specification row, ready to be written to the project DB.
///
/// Carries the full `(extract, historical, finding)` triple of the
/// link that produced the spec — writers persist all three so the
/// link's identity survives across runs (see the doc on
/// [`super::db::specification::Model`] for the design rationale).
#[derive(Debug, Clone)]
pub struct SpecificationRecord {
    /// `project_semantic.id`.
    pub semantic_id: i32,
    /// `historical_semantic.id` — which historical the gen-spec agent
    /// used as its prompt context.
    pub historical_id: i32,
    /// `historical_finding.id` (cross-DB; not enforced).
    pub finding_id: i32,
    /// JSON-serialized `AuditSpecification` payload.
    pub specification_json: String,
}

/// Loaded specification row.
#[derive(Debug, Clone)]
pub struct LoadedSpecification {
    pub id: i32,
    pub semantic_id: i32,
    pub historical_id: i32,
    pub finding_id: i32,
    pub specification_json: String,
}

/// Resume state of a streamloop link, derived purely from DB rows.
/// Returned by [`RepoDatabase::link_resume_state`].
///
/// streamloop / autoloop consult this once per candidate link and
/// dispatch accordingly:
///
/// * [`Self::NotStarted`] — run the gen-spec agent from scratch.
/// * [`Self::Partial`] — skip gen-spec, feed `spec_ids` straight into
///   the fuzz / reflect / regen inner cycle.
/// * [`Self::Built`] — drop the link end-to-end; nothing more to do
///   in streamloop's view (standalone `audit reflect / regen` can
///   still drive any remaining pending state).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LinkResumeState {
    NotStarted,
    Partial { spec_ids: Vec<i32> },
    Built,
}

impl RepoDatabase {
    /// Replace every row in the `specification` table with the supplied
    /// records, atomically. Pass an empty slice to clear without inserting.
    pub async fn write_specifications(&self, records: &[SpecificationRecord]) -> Result<()> {
        let txn = self
            .db
            .begin()
            .await
            .wrap_err("failed to begin specification write transaction")?;
        specification_model::Entity::delete_many()
            .exec(&txn)
            .await
            .wrap_err("failed to clear specification rows")?;
        for record in records {
            specification_model::Entity::insert(specification_model::ActiveModel {
                semantic_id: Set(record.semantic_id),
                historical_id: Set(record.historical_id),
                finding_id: Set(record.finding_id),
                specification: Set(record.specification_json.clone()),
                ..Default::default()
            })
            .exec(&txn)
            .await
            .wrap_err_with(|| {
                format!(
                    "failed to insert specification semantic={} finding={}",
                    record.semantic_id, record.finding_id
                )
            })?;
        }
        txn.commit()
            .await
            .wrap_err("failed to commit specification write transaction")?;
        Ok(())
    }

    /// Append specification rows without clearing existing ones. Used by
    /// gen-specs to commit each link's results as soon as the link
    /// finishes, so a later cap or kill does not lose work.
    pub async fn append_specifications(&self, records: &[SpecificationRecord]) -> Result<Vec<i32>> {
        if records.is_empty() {
            return Ok(Vec::new());
        }
        let txn = self
            .db
            .begin()
            .await
            .wrap_err("failed to begin specification append transaction")?;
        let mut ids = Vec::with_capacity(records.len());
        for record in records {
            let inserted = specification_model::Entity::insert(specification_model::ActiveModel {
                semantic_id: Set(record.semantic_id),
                historical_id: Set(record.historical_id),
                finding_id: Set(record.finding_id),
                specification: Set(record.specification_json.clone()),
                ..Default::default()
            })
            .exec(&txn)
            .await
            .wrap_err_with(|| {
                format!(
                    "failed to insert specification semantic={} finding={}",
                    record.semantic_id, record.finding_id
                )
            })?;
            ids.push(inserted.last_insert_id);
        }
        txn.commit()
            .await
            .wrap_err("failed to commit specification append transaction")?;
        Ok(ids)
    }

    /// Insert a single specification row in one transaction and return
    /// the new auto-increment `specification.id`. Used by `agentic regen`
    /// when it needs to thread the new spec id into a `specification_regen`
    /// lineage row.
    pub async fn insert_specification(&self, record: &SpecificationRecord) -> Result<i32> {
        let inserted = specification_model::Entity::insert(specification_model::ActiveModel {
            semantic_id: Set(record.semantic_id),
            finding_id: Set(record.finding_id),
            specification: Set(record.specification_json.clone()),
            ..Default::default()
        })
        .exec(&self.db)
        .await
        .wrap_err_with(|| {
            format!(
                "failed to insert specification semantic={} finding={}",
                record.semantic_id, record.finding_id
            )
        })?;
        Ok(inserted.last_insert_id)
    }

    /// Atomic full-pipeline write for one `IncompleteSpecification` regen
    /// attempt. Inserts (in this order, in one SQLite transaction):
    ///
    /// 1. New `specification` row (returns `child_spec_id`)
    /// 2. `code_gen` row referencing `child_spec_id`
    /// 3. Per-run `harness_run` rows (with `coverage_per_run` lining up 1:1)
    /// 4. Per-run `line_coverage` rows for any non-empty coverage payload
    /// 5. `specification_regen` lineage row (parent_spec → child_spec)
    /// 6. `code_gen_regen` lineage row (parent_code_gen → child_code_gen)
    ///
    /// Either all six land or none do — if any insert fails, the txn
    /// rolls back and the operator's DB stays at the pre-regen state.
    /// The caller passes the in-memory spec object (its `spec_id` field
    /// is ignored; the writer assigns the freshly-inserted one) and the
    /// in-memory code_gen record (its `core.spec_id` is overwritten with
    /// the new spec id before insert).
    pub async fn write_full_spec_regen(
        &self,
        new_spec: &SpecificationRecord,
        new_code_gen: &CodeGenRecord,
        coverage_per_run: &[Vec<CoverageEntry>],
        parent_spec_id: i32,
        parent_code_gen_id: i32,
        triggered_by_reflection_id: i32,
        spec_regen_reason: &str,
        code_gen_regen_reason: &str,
    ) -> Result<FullSpecRegenIds> {
        ensure!(
            coverage_per_run.is_empty() || coverage_per_run.len() == new_code_gen.runs.len(),
            "coverage_per_run must match runs.len() (got {} vs {})",
            coverage_per_run.len(),
            new_code_gen.runs.len()
        );
        let txn = self
            .db
            .begin()
            .await
            .wrap_err("failed to begin spec-regen transaction")?;

        // 1. Insert new specification.
        let spec_inserted = specification_model::Entity::insert(specification_model::ActiveModel {
            semantic_id: Set(new_spec.semantic_id),
            historical_id: Set(new_spec.historical_id),
            finding_id: Set(new_spec.finding_id),
            specification: Set(new_spec.specification_json.clone()),
            ..Default::default()
        })
        .exec(&txn)
        .await
        .wrap_err_with(|| {
            format!(
                "failed to insert regen specification semantic={} finding={}",
                new_spec.semantic_id, new_spec.finding_id
            )
        })?;
        let child_spec_id = spec_inserted.last_insert_id;

        // 2. Insert code_gen pointing at the new spec.
        let cg_inserted = code_gen_model::Entity::insert(code_gen_model::ActiveModel {
            spec_id: Set(child_spec_id),
            harness_relative_path: Set(new_code_gen.core.harness_relative_path.clone()),
            harness_source: Set(new_code_gen.core.harness_source.clone()),
            status: Set(new_code_gen.core.status),
            final_reason: Set(new_code_gen.core.final_reason.clone()),
            agent_steps: Set(new_code_gen.core.agent_steps),
            ..Default::default()
        })
        .exec(&txn)
        .await
        .wrap_err_with(|| format!("failed to insert regen code_gen for spec={child_spec_id}"))?;
        let child_code_gen_id = cg_inserted.last_insert_id;

        // 3-4. harness_run + line_coverage.
        for (idx, run) in new_code_gen.runs.iter().enumerate() {
            let forge_args_json = serde_json::to_string(&run.forge_args)
                .wrap_err("failed to JSON-serialize forge_args")?;
            let sequence_json = run
                .sequence
                .as_ref()
                .map(serde_json::to_string)
                .transpose()
                .wrap_err("failed to JSON-serialize counter-example sequence")?;
            let run_inserted = harness_run_model::Entity::insert(harness_run_model::ActiveModel {
                code_id: Set(child_code_gen_id),
                kind: Set(run.kind),
                seed: Set(run.seed),
                runs: Set(run.runs),
                forge_args: Set(forge_args_json),
                exit_code: Set(run.exit_code),
                stdout: Set(run.stdout.clone()),
                stderr: Set(run.stderr.clone()),
                duration_ms: Set(run.duration_ms),
                violated: Set(run.violated),
                sequence_json: Set(sequence_json),
                ..Default::default()
            })
            .exec(&txn)
            .await
            .wrap_err_with(|| {
                format!(
                    "failed to insert harness_run #{idx} for regen code_gen={child_code_gen_id}"
                )
            })?;
            let run_id = run_inserted.last_insert_id;

            if let Some(entries) = coverage_per_run.get(idx) {
                for entry in entries {
                    line_coverage_model::Entity::insert(line_coverage_model::ActiveModel {
                        run_id: Set(run_id),
                        relative_contract_path: Set(entry.relative_contract_path.clone()),
                        line_number: Set(entry.line_number),
                        hit_count: Set(entry.hit_count),
                        ..Default::default()
                    })
                    .exec(&txn)
                    .await
                    .wrap_err_with(|| {
                        format!(
                            "failed to insert line_coverage for regen run_id={run_id} path={}",
                            entry.relative_contract_path
                        )
                    })?;
                }
            }
        }

        // 5. specification_regen lineage.
        specification_regen_model::Entity::insert(specification_regen_model::ActiveModel {
            child_spec_id: Set(child_spec_id),
            parent_spec_id: Set(parent_spec_id),
            reason: Set(spec_regen_reason.to_string()),
            triggered_by_reflection_id: Set(triggered_by_reflection_id),
        })
        .exec(&txn)
        .await
        .wrap_err("failed to insert specification_regen lineage row")?;

        // 6. code_gen_regen lineage.
        code_gen_regen_model::Entity::insert(code_gen_regen_model::ActiveModel {
            child_code_gen_id: Set(child_code_gen_id),
            parent_code_gen_id: Set(parent_code_gen_id),
            reason: Set(code_gen_regen_reason.to_string()),
            triggered_by_reflection_id: Set(triggered_by_reflection_id),
        })
        .exec(&txn)
        .await
        .wrap_err("failed to insert code_gen_regen lineage row")?;

        txn.commit()
            .await
            .wrap_err("failed to commit spec-regen transaction")?;
        Ok(FullSpecRegenIds {
            child_spec_id,
            child_code_gen_id,
        })
    }

    /// Clear every row in the `specification` table.
    pub async fn clear_specifications(&self) -> Result<()> {
        specification_model::Entity::delete_many()
            .exec(&self.db)
            .await
            .wrap_err("failed to clear specification rows")?;
        Ok(())
    }

    /// Return the set of `(semantic_id, finding_id)` pairs that already
    /// have at least one specification row in the project DB. Used by
    /// gen-specs to skip already-processed links.
    pub async fn loaded_specification_pairs(
        &self,
    ) -> Result<std::collections::HashSet<(i32, i32)>> {
        let rows = specification_model::Entity::find()
            .all(&self.db)
            .await
            .wrap_err("failed to load specification rows for pair index")?;
        Ok(rows
            .into_iter()
            .map(|row| (row.semantic_id, row.finding_id))
            .collect())
    }

    /// Per-link resume state for one `(extract, historical, finding)`
    /// triple. Used by streamloop / autoloop to decide whether a link
    /// needs gen-spec from scratch, can skip straight into the
    /// fuzz/reflect/regen cycle with existing spec rows, or has
    /// already been fully processed.
    ///
    /// The three states are derived from rows in `specification` and
    /// `code_gen`:
    ///
    /// * No spec rows                       → [`LinkResumeState::NotStarted`]
    /// * Spec rows but no code_gen rows     → [`LinkResumeState::Partial`]
    /// * Spec rows AND ≥1 code_gen for any  → [`LinkResumeState::Built`]
    ///
    /// "Built" here means "the link was given a fair fuzz attempt".
    /// Downstream regen / reflect can still drive these links via
    /// their own pending queues; streamloop won't re-enter the link
    /// at gen-spec.
    ///
    /// Keyed on the full `(E, H, F)` triple so sibling LinkInputs that
    /// share `(E, F)` but differ in `H` get independent states — each
    /// sibling resumes only the spec rows IT authored, no
    /// cross-contamination of cycle work.
    pub async fn link_resume_state(
        &self,
        extract_id: i32,
        historical_id: i32,
        finding_id: i32,
    ) -> Result<LinkResumeState> {
        use sea_orm::{ColumnTrait, QueryFilter};

        let specs = specification_model::Entity::find()
            .filter(specification_model::Column::SemanticId.eq(extract_id))
            .filter(specification_model::Column::HistoricalId.eq(historical_id))
            .filter(specification_model::Column::FindingId.eq(finding_id))
            .order_by_asc(specification_model::Column::Id)
            .all(&self.db)
            .await
            .wrap_err_with(|| {
                format!(
                    "failed to load specification rows for ({extract_id}, {historical_id}, {finding_id})"
                )
            })?;
        if specs.is_empty() {
            return Ok(LinkResumeState::NotStarted);
        }
        let spec_ids: Vec<i32> = specs.iter().map(|s| s.id).collect();

        let any_codegen = code_gen_model::Entity::find()
            .filter(code_gen_model::Column::SpecId.is_in(spec_ids.clone()))
            .one(&self.db)
            .await
            .wrap_err_with(|| {
                format!(
                    "failed to query code_gen rows for specs of ({extract_id}, {historical_id}, {finding_id})"
                )
            })?
            .is_some();

        Ok(if any_codegen {
            LinkResumeState::Built
        } else {
            LinkResumeState::Partial { spec_ids }
        })
    }

    /// Read every specification row from the project database.
    pub async fn load_specifications(&self) -> Result<Vec<LoadedSpecification>> {
        let rows = specification_model::Entity::find()
            .order_by_asc(specification_model::Column::Id)
            .all(&self.db)
            .await
            .wrap_err("failed to load specification rows")?;
        Ok(rows
            .into_iter()
            .map(|row| LoadedSpecification {
                id: row.id,
                semantic_id: row.semantic_id,
                historical_id: row.historical_id,
                finding_id: row.finding_id,
                specification_json: row.specification,
            })
            .collect())
    }
}

// ---------------------------------------------------------------------------
// Fuzzing harness records (`code_gen` + `harness_run` + `line_coverage`)
// ---------------------------------------------------------------------------

/// A single forge subprocess outcome to persist as a [`super::db::harness_run`] row.
#[derive(Debug, Clone)]
pub struct HarnessRunRecord {
    pub kind: RunKind,
    pub seed: Option<i64>,
    pub runs: i64,
    pub forge_args: Vec<String>,
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
    pub duration_ms: i64,
    pub violated: bool,
    /// Counter-example call sequence parsed from forge `--json`. Stored as
    /// JSON-string in the DB; pass [`serde_json::Value`] here so the layer
    /// above doesn't have to pre-serialize.
    pub sequence: Option<serde_json::Value>,
}

/// Shared payload of a `code_gen` row — every column except the
/// auto-increment `id` and the `harness_run` children. Both the
/// write-side ([`CodeGenRecord`]) and the read-side ([`LoadedCodeGen`])
/// embed this so the field set stays in lockstep.
#[derive(Debug, Clone)]
pub struct CodeGenCore {
    pub spec_id: i32,
    pub harness_relative_path: String,
    pub harness_source: String,
    pub status: CodeGenStatus,
    pub final_reason: String,
    pub agent_steps: i32,
}

/// A finalized harness-synthesis attempt to persist as a
/// [`super::db::code_gen`] row. `runs` carries every forge invocation tied
/// to this attempt; the writer hooks them up via FK in one transaction.
#[derive(Debug, Clone)]
pub struct CodeGenRecord {
    pub core: CodeGenCore,
    pub runs: Vec<HarnessRunRecord>,
}

/// A coverage entry parsed from lcov, scoped to a single
/// [`super::db::harness_run`].
#[derive(Debug, Clone)]
pub struct CoverageEntry {
    pub relative_contract_path: String,
    pub line_number: i32,
    pub hit_count: i64,
}

#[derive(Debug, Clone)]
pub struct LoadedCodeGen {
    pub id: i32,
    pub core: CodeGenCore,
}

impl RepoDatabase {
    /// Persist one finalized harness attempt and its forge runs in a single
    /// transaction. Optional per-run coverage rows are also inserted.
    /// Returns the inserted `code_gen.id` plus the `harness_run.id`s in the
    /// same order as `record.runs`.
    pub async fn write_code_gen_with_runs(
        &self,
        record: &CodeGenRecord,
        coverage_per_run: &[Vec<CoverageEntry>],
    ) -> Result<(i32, Vec<i32>)> {
        ensure!(
            coverage_per_run.is_empty() || coverage_per_run.len() == record.runs.len(),
            "coverage_per_run must match runs.len() (got {} vs {})",
            coverage_per_run.len(),
            record.runs.len()
        );
        let txn = self
            .db
            .begin()
            .await
            .wrap_err("failed to begin code_gen+runs transaction")?;
        let inserted = code_gen_model::Entity::insert(code_gen_model::ActiveModel {
            spec_id: Set(record.core.spec_id),
            harness_relative_path: Set(record.core.harness_relative_path.clone()),
            harness_source: Set(record.core.harness_source.clone()),
            status: Set(record.core.status),
            final_reason: Set(record.core.final_reason.clone()),
            agent_steps: Set(record.core.agent_steps),
            ..Default::default()
        })
        .exec(&txn)
        .await
        .wrap_err_with(|| format!("failed to insert code_gen for spec={}", record.core.spec_id))?;
        let code_id = inserted.last_insert_id;

        let mut run_ids = Vec::with_capacity(record.runs.len());
        for (idx, run) in record.runs.iter().enumerate() {
            let forge_args_json = serde_json::to_string(&run.forge_args)
                .wrap_err("failed to JSON-serialize forge_args")?;
            let sequence_json = run
                .sequence
                .as_ref()
                .map(serde_json::to_string)
                .transpose()
                .wrap_err("failed to JSON-serialize counter-example sequence")?;
            let run_inserted = harness_run_model::Entity::insert(harness_run_model::ActiveModel {
                code_id: Set(code_id),
                kind: Set(run.kind),
                seed: Set(run.seed),
                runs: Set(run.runs),
                forge_args: Set(forge_args_json),
                exit_code: Set(run.exit_code),
                stdout: Set(run.stdout.clone()),
                stderr: Set(run.stderr.clone()),
                duration_ms: Set(run.duration_ms),
                violated: Set(run.violated),
                sequence_json: Set(sequence_json),
                ..Default::default()
            })
            .exec(&txn)
            .await
            .wrap_err_with(|| {
                format!("failed to insert harness_run #{idx} for code_gen={code_id}")
            })?;
            let run_id = run_inserted.last_insert_id;
            run_ids.push(run_id);

            if let Some(entries) = coverage_per_run.get(idx) {
                for entry in entries {
                    line_coverage_model::Entity::insert(line_coverage_model::ActiveModel {
                        run_id: Set(run_id),
                        relative_contract_path: Set(entry.relative_contract_path.clone()),
                        line_number: Set(entry.line_number),
                        hit_count: Set(entry.hit_count),
                        ..Default::default()
                    })
                    .exec(&txn)
                    .await
                    .wrap_err_with(|| {
                        format!(
                            "failed to insert line_coverage for run_id={run_id} path={}",
                            entry.relative_contract_path
                        )
                    })?;
                }
            }
        }

        txn.commit()
            .await
            .wrap_err("failed to commit code_gen+runs transaction")?;
        Ok((code_id, run_ids))
    }

    /// Return the set of `spec_id`s that already have a `Completed`
    /// `code_gen` row — used by `gen-fuzz` to skip already-fuzzed specs on
    /// resume.
    pub async fn loaded_completed_code_gen_spec_ids(
        &self,
    ) -> Result<std::collections::HashSet<i32>> {
        let rows = code_gen_model::Entity::find()
            .all(&self.db)
            .await
            .wrap_err("failed to load code_gen rows for resume index")?;
        Ok(rows
            .into_iter()
            .filter(|row| row.status.counts_as_resumable_skip())
            .map(|row| row.spec_id)
            .collect())
    }

    /// Clear every fuzzing-related table. Used by `--regenerate`.
    pub async fn clear_fuzz_tables(&self) -> Result<()> {
        let txn = self
            .db
            .begin()
            .await
            .wrap_err("failed to begin clear_fuzz_tables transaction")?;
        // Delete in FK order: line_coverage → harness_run → code_gen.
        line_coverage_model::Entity::delete_many()
            .exec(&txn)
            .await
            .wrap_err("failed to clear line_coverage")?;
        harness_run_model::Entity::delete_many()
            .exec(&txn)
            .await
            .wrap_err("failed to clear harness_run")?;
        code_gen_model::Entity::delete_many()
            .exec(&txn)
            .await
            .wrap_err("failed to clear code_gen")?;
        txn.commit()
            .await
            .wrap_err("failed to commit clear_fuzz_tables")?;
        Ok(())
    }

    /// Read every `code_gen` row in the project DB.
    pub async fn load_code_gens(&self) -> Result<Vec<LoadedCodeGen>> {
        let rows = code_gen_model::Entity::find()
            .order_by_asc(code_gen_model::Column::Id)
            .all(&self.db)
            .await
            .wrap_err("failed to load code_gen rows")?;
        Ok(rows
            .into_iter()
            .map(|row| LoadedCodeGen {
                id: row.id,
                core: CodeGenCore {
                    spec_id: row.spec_id,
                    harness_relative_path: row.harness_relative_path,
                    harness_source: row.harness_source,
                    status: row.status,
                    final_reason: row.final_reason,
                    agent_steps: row.agent_steps,
                },
            })
            .collect())
    }

    /// Load just enough of each `harness_run` row to drive Gate 3
    /// triage for one `code_gen` — kind, exit_code, violated, plus
    /// the counter-example sequence JSON (which the grader's prompt
    /// uses verbatim).
    pub async fn load_runs_for_code_gen(&self, code_id: i32) -> Result<Vec<LoadedHarnessRun>> {
        use sea_orm::{ColumnTrait, QueryFilter};
        let rows = harness_run_model::Entity::find()
            .filter(harness_run_model::Column::CodeId.eq(code_id))
            .order_by_asc(harness_run_model::Column::Id)
            .all(&self.db)
            .await
            .wrap_err_with(|| format!("failed to load harness_run rows for code_id={code_id}"))?;
        Ok(rows
            .into_iter()
            .map(|row| LoadedHarnessRun {
                id: row.id,
                code_id: row.code_id,
                kind: row.kind,
                exit_code: row.exit_code,
                violated: row.violated,
                stdout: row.stdout,
                stderr: row.stderr,
                sequence_json: row.sequence_json,
            })
            .collect())
    }

    /// Load every `line_coverage` row produced by `forge coverage`
    /// runs of a given `code_gen`, flattened across all of its runs.
    /// We don't dedupe across runs — Gate 2 only cares about
    /// `hit_count > 0` per `(path, line_number)`, which the union
    /// preserves.
    pub async fn load_coverage_for_code_gen(&self, code_id: i32) -> Result<Vec<CoverageEntry>> {
        use sea_orm::{ColumnTrait, FromQueryResult, QueryFilter, QuerySelect, RelationTrait};
        #[derive(FromQueryResult)]
        struct Row {
            relative_contract_path: String,
            line_number: i32,
            hit_count: i64,
        }
        let rows = line_coverage_model::Entity::find()
            .select_only()
            .column(line_coverage_model::Column::RelativeContractPath)
            .column(line_coverage_model::Column::LineNumber)
            .column(line_coverage_model::Column::HitCount)
            .join(
                sea_orm::JoinType::InnerJoin,
                line_coverage_model::Relation::HarnessRun.def(),
            )
            .filter(harness_run_model::Column::CodeId.eq(code_id))
            .into_model::<Row>()
            .all(&self.db)
            .await
            .wrap_err_with(|| format!("failed to load line_coverage for code_id={code_id}"))?;
        Ok(rows
            .into_iter()
            .map(|row| CoverageEntry {
                relative_contract_path: row.relative_contract_path,
                line_number: row.line_number,
                hit_count: row.hit_count,
            })
            .collect())
    }
}

/// Slim view of a single `harness_run` for reflection. Skips the
/// `forge_args` / `runs` / `seed` / `duration_ms` columns that gates
/// don't need, but keeps stdout/stderr + the counter-example sequence
/// since Gate 3 (LLM grader) feeds those into its prompt.
#[derive(Debug, Clone)]
pub struct LoadedHarnessRun {
    pub id: i32,
    pub code_id: i32,
    pub kind: RunKind,
    pub exit_code: i32,
    pub violated: bool,
    pub stdout: String,
    pub stderr: String,
    pub sequence_json: Option<String>,
}

/// One accepted finding, flattened from the
/// [`reflection`] + [`valid_finding`] + [`specification`] +
/// [`code_gen`] + [`harness_run`] join. The strings are the raw
/// column values — callers (`workflow autoloop` for the per-cycle
/// dump) parse them as JSON / Solidity / etc. as needed.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct LoadedValidFinding {
    pub reflection_id: i32,
    pub run_id: i32,
    pub spec_id: i32,
    pub verdict_reason: String,
    pub severity: String,
    pub severity_reason: String,
    pub specification_json: String,
    pub harness_source: String,
    pub harness_relative_path: String,
    pub run_kind: String,
    pub run_exit_code: Option<i32>,
    pub run_violated: bool,
    pub run_stdout: String,
    pub run_sequence_json: Option<String>,
}

// ============================================================================
// Report findings (`review-findings` workflow: Review → Merge → Writer)
// ============================================================================

/// One Review-agent verdict to persist into `finding_review`. Written via
/// [`RepoDatabase::insert_finding_review`], which upserts on `reflection_id`
/// so a re-review replaces in place.
#[derive(Debug, Clone)]
pub struct FindingReviewRecord {
    pub reflection_id: i32,
    pub title: String,
    pub severity: ReviewSeverity,
    pub review_reason: String,
    pub root_cause: String,
    pub description: String,
    pub location: String,
    pub impact: String,
    pub recommendation: String,
    pub primary_contract: String,
    pub primary_function: String,
    pub severity_reason: String,
}

/// A loaded `finding_review` row — the structured, client-facing shape the
/// Merge agent clusters on and the report renderer reads back per cluster
/// member (title / description / impact / location / recommendation are all
/// rendered directly; there is no separate Writer stage).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ReviewedFinding {
    pub reflection_id: i32,
    pub title: String,
    pub severity: ReviewSeverity,
    pub review_reason: String,
    pub root_cause: String,
    pub description: String,
    pub location: String,
    pub impact: String,
    pub recommendation: String,
    pub primary_contract: String,
    pub primary_function: String,
    pub severity_reason: String,
}

impl From<finding_review_model::Model> for ReviewedFinding {
    fn from(m: finding_review_model::Model) -> Self {
        Self {
            reflection_id: m.reflection_id,
            title: m.title,
            severity: m.severity,
            review_reason: m.review_reason,
            root_cause: m.root_cause,
            description: m.description,
            location: m.location,
            impact: m.impact,
            recommendation: m.recommendation,
            primary_contract: m.primary_contract,
            primary_function: m.primary_function,
            severity_reason: m.severity_reason,
        }
    }
}

/// Identity seed for a brand-new canonical, taken from the cluster's first
/// (representative) reviewed finding.
#[derive(Debug, Clone)]
pub struct ReportFindingSeed {
    pub title: String,
    pub severity: ReviewSeverity,
    pub root_cause: String,
    pub description: String,
    pub primary_contract: String,
    pub primary_function: String,
}

/// The Merge agent's decision for one raw finding, persisted atomically by
/// [`RepoDatabase::commit_finding_merge`].
#[derive(Debug, Clone)]
pub enum FindingMergeDecision {
    /// This finding starts a new canonical.
    NewCanonical(ReportFindingSeed),
    /// Fold into an existing canonical; `raise_to` lifts the canonical's
    /// severity when this member outranks it (max-reconcile).
    MergeInto {
        report_finding_id: i32,
        raise_to: Option<ReviewSeverity>,
    },
}

/// A loaded canonical `report_finding` — pure cluster identity (no nullable
/// client columns, no status). The client report is derived at export from
/// the cluster's representative member.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct LoadedReportFinding {
    pub id: i32,
    pub title: String,
    pub severity: ReviewSeverity,
    pub root_cause: String,
    pub description: String,
    pub primary_contract: String,
    pub primary_function: String,
}

impl From<report_finding_model::Model> for LoadedReportFinding {
    fn from(m: report_finding_model::Model) -> Self {
        Self {
            id: m.id,
            title: m.title,
            severity: m.severity,
            root_cause: m.root_cause,
            description: m.description,
            primary_contract: m.primary_contract,
            primary_function: m.primary_function,
        }
    }
}

/// One raw member of a canonical: its structured review, the underlying source
/// material (spec + PoC harness + forge run), and the two graded edge
/// strengths used to pick the cluster's representative — sort key
/// `(review.severity, link_strength, mapper_strength)` then shortest harness.
#[derive(Debug, Clone)]
pub struct RawFindingMember {
    pub review: ReviewedFinding,
    pub source: LoadedValidFinding,
    /// Mapper match strength on the `(extract, historical)` pair (`None` if the
    /// mapper row is gone).
    pub mapper_strength: Option<MatchStrength>,
    /// KG link strength on the `(historical, finding)` edge (`None` if the link
    /// row is gone).
    pub link_strength: Option<knowdit_kg_model::link_strength::LinkStrength>,
}

impl RawFindingMember {
    /// Descending sort key for representative selection: higher review
    /// severity, then stronger KG link, then stronger mapper match, then
    /// SHORTER harness (negated length so it sorts last-but-ascending). The
    /// member that sorts greatest is the representative.
    pub fn representative_key(&self) -> (u8, u8, u8, i64) {
        (
            self.review.severity.rank(),
            self.link_strength.map(|s| s.rank()).unwrap_or(0),
            self.mapper_strength.map(|s| s.rank()).unwrap_or(0),
            -(self.source.harness_source.len() as i64),
        )
    }
}

// ============================================================================
// Reflection + lineage (Step B)
// ============================================================================

/// One reflection verdict to persist, keyed to a single
/// [`super::db::harness_run`] row. Severity (when `result ==
/// ValidFinding`) lives separately in [`ValidFindingRecord`] and is
/// co-written via [`RepoDatabase::insert_reflection_with_finding`].
#[derive(Debug, Clone)]
pub struct ReflectionRecord {
    pub run_id: i32,
    pub spec_id: i32,
    pub result: ReflectionResult,
    pub reason: String,
}

/// Sibling severity record for a `ValidFinding` reflection. Owned by
/// the dedicated severity-grader agent (separate from the verdict
/// grader). Co-written with the parent reflection in one transaction.
#[derive(Debug, Clone)]
pub struct ValidFindingRecord {
    pub severity: knowdit_kg_model::audit_finding::FindingSeverity,
    pub severity_reason: String,
}

/// One regen lineage event. Used for both `specification_regen` and
/// `code_gen_regen` since the row shape is identical (just FK targets
/// differ). The caller picks the right writer method.
#[derive(Debug, Clone)]
pub struct RegenEventRecord {
    pub child_id: i32,
    pub parent_id: i32,
    pub reason: String,
    pub triggered_by_reflection_id: i32,
}

/// Auto-increment ids returned from a successful
/// [`RepoDatabase::write_full_spec_regen`] commit. Lets the caller
/// log / structure-up the regen lineage without re-querying.
#[derive(Debug, Clone, Copy)]
pub struct FullSpecRegenIds {
    pub child_spec_id: i32,
    pub child_code_gen_id: i32,
}

/// Counts returned from
/// [`RepoDatabase::clear_reflections_for_redo`] for log/operator
/// visibility.
#[derive(Debug, Clone, Copy)]
pub struct ReflectionWipeStats {
    pub reflections: usize,
    pub valid_findings: usize,
}

/// A reflection row from the pending-regen queue: needs a regen but
/// hasn't been consumed by either lineage table yet. The `code_id` is
/// joined in from `harness_run` so the regen scheduler still drives
/// off `code_gen` lineage even though reflection itself is per-run.
#[derive(Debug, Clone)]
pub struct PendingReflection {
    pub reflection_id: i32,
    pub run_id: i32,
    pub code_id: i32,
    pub spec_id: i32,
    pub result: ReflectionResult,
    pub reason: String,
}

impl RepoDatabase {
    /// Atomic write: one reflection row plus an optional sibling
    /// `valid_finding` row, in a single SQLite transaction. Resume
    /// safety: a crashed reflection agent leaves zero rows; on retry
    /// [`Self::has_reflection`] is still false so the agent runs again.
    /// Re-running after a successful commit hits the `UNIQUE(run_id)`
    /// constraint on `reflection` and is rejected — the caller is
    /// expected to skip via `has_reflection` first.
    pub async fn insert_reflection_with_finding(
        &self,
        reflection: &ReflectionRecord,
        finding: Option<&ValidFindingRecord>,
    ) -> Result<i32> {
        if matches!(reflection.result, ReflectionResult::ValidFinding) && finding.is_none() {
            return Err(color_eyre::eyre::eyre!(
                "insert_reflection_with_finding: ValidFinding requires a ValidFindingRecord \
                 (run_id={}, spec_id={})",
                reflection.run_id,
                reflection.spec_id
            ));
        }
        if !matches!(reflection.result, ReflectionResult::ValidFinding) && finding.is_some() {
            return Err(color_eyre::eyre::eyre!(
                "insert_reflection_with_finding: non-ValidFinding verdict cannot carry a \
                 ValidFindingRecord (run_id={}, spec_id={}, verdict={:?})",
                reflection.run_id,
                reflection.spec_id,
                reflection.result
            ));
        }

        let txn = self
            .db
            .begin()
            .await
            .wrap_err("failed to begin reflection-with-finding transaction")?;

        let inserted = reflection_model::Entity::insert(reflection_model::ActiveModel {
            run_id: Set(reflection.run_id),
            spec_id: Set(reflection.spec_id),
            result: Set(reflection.result),
            reason: Set(reflection.reason.clone()),
            ..Default::default()
        })
        .exec(&txn)
        .await
        .wrap_err_with(|| {
            format!(
                "failed to insert reflection for run_id={} spec={}",
                reflection.run_id, reflection.spec_id
            )
        })?;
        let reflection_id = inserted.last_insert_id;

        if let Some(vf) = finding {
            valid_finding_model::Entity::insert(valid_finding_model::ActiveModel {
                reflection_id: Set(reflection_id),
                severity: Set(vf.severity),
                severity_reason: Set(vf.severity_reason.clone()),
                ..Default::default()
            })
            .exec(&txn)
            .await
            .wrap_err_with(|| {
                format!(
                    "failed to insert valid_finding for reflection_id={reflection_id} \
                     run_id={}",
                    reflection.run_id
                )
            })?;
        }

        txn.commit()
            .await
            .wrap_err("failed to commit reflection-with-finding transaction")?;
        Ok(reflection_id)
    }

    /// Wipe every `reflection` + `valid_finding` row in the project DB.
    /// Used by `agentic reflect --allow-redo-reflect` so a different
    /// grader model can re-grade the same fuzz output from scratch.
    /// Code_gen / harness_run / line_coverage / `*_regen` rows are
    /// NOT touched — only verdicts are reset.
    ///
    /// `*_regen.triggered_by_reflection_id` rows will end up pointing
    /// at deleted reflection ids; that's an acceptable trade for redo
    /// (lineage records the regen *event*, the verdict that drove it
    /// is being overwritten by design). FK enforcement is temporarily
    /// disabled across the wipe to allow this.
    pub async fn clear_reflections_for_redo(&self) -> Result<ReflectionWipeStats> {
        if self.db.get_database_backend() != sea_orm::DatabaseBackend::Sqlite {
            return Err(color_eyre::eyre::eyre!(
                "clear_reflections_for_redo only supports SQLite backends"
            ));
        }
        use sea_orm::PaginatorTrait;
        let reflections_before = reflection_model::Entity::find().count(&self.db).await? as usize;
        let valid_findings_before =
            valid_finding_model::Entity::find().count(&self.db).await? as usize;
        // Disable FK enforcement just for the wipe, then re-enable. We
        // can't simply DELETE FROM reflection because *_regen rows
        // have a NOT NULL FK pointing at it.
        self.db
            .execute_unprepared("PRAGMA foreign_keys=OFF;")
            .await
            .wrap_err("failed to disable FK enforcement before reflection wipe")?;
        let wipe = async {
            self.db
                .execute_unprepared("DELETE FROM valid_finding;")
                .await
                .wrap_err("failed to wipe valid_finding")?;
            self.db
                .execute_unprepared("DELETE FROM reflection;")
                .await
                .wrap_err("failed to wipe reflection")?;
            Ok::<_, color_eyre::eyre::Error>(())
        }
        .await;
        // Re-enable FKs whether the wipe succeeded or not.
        let reenable = self
            .db
            .execute_unprepared("PRAGMA foreign_keys=ON;")
            .await
            .wrap_err("failed to re-enable FK enforcement after reflection wipe");
        wipe?;
        reenable?;
        Ok(ReflectionWipeStats {
            reflections: reflections_before,
            valid_findings: valid_findings_before,
        })
    }

    /// All [`ReflectionResult::ValidFinding`] verdicts joined with
    /// their sibling `valid_finding`, the spec they came from, the
    /// owning `code_gen` (for the harness source — the PoC), and the
    /// `harness_run` whose violation triggered the verdict. One row
    /// per accepted finding, ordered by reflection id.
    ///
    /// Consumed by `workflow autoloop` when dumping per-cycle valid
    /// findings to the output folder.
    pub async fn load_valid_findings(&self) -> Result<Vec<LoadedValidFinding>> {
        use sea_orm::{ColumnTrait, QueryFilter};

        let reflections = reflection_model::Entity::find()
            .filter(reflection_model::Column::Result.eq(ReflectionResult::ValidFinding))
            .order_by_asc(reflection_model::Column::Id)
            .all(&self.db)
            .await
            .wrap_err("failed to load ValidFinding reflections")?;
        self.load_valid_findings_for(reflections).await
    }

    /// Hydrate a pre-selected set of `ValidFinding` reflections into
    /// [`LoadedValidFinding`] rows (join spec + code_gen + harness_run).
    /// Shared by [`Self::load_valid_findings`] (all of them),
    /// [`Self::load_unreviewed_valid_findings`] (those still lacking a
    /// `finding_review`), and [`Self::load_report_finding_members`] (one
    /// canonical's cluster). Callers pass reflections already filtered to
    /// `Result == ValidFinding`; non-ValidFinding rows error on the missing
    /// `valid_finding` sibling.
    async fn load_valid_findings_for(
        &self,
        reflections: Vec<reflection_model::Model>,
    ) -> Result<Vec<LoadedValidFinding>> {
        use sea_orm::{ColumnTrait, QueryFilter};

        if reflections.is_empty() {
            return Ok(Vec::new());
        }

        let reflection_ids: Vec<i32> = reflections.iter().map(|r| r.id).collect();
        let run_ids: Vec<i32> = reflections.iter().map(|r| r.run_id).collect();
        let spec_ids: Vec<i32> = reflections.iter().map(|r| r.spec_id).collect();

        let valid_findings = valid_finding_model::Entity::find()
            .filter(valid_finding_model::Column::ReflectionId.is_in(reflection_ids))
            .all(&self.db)
            .await
            .wrap_err("failed to load valid_finding rows")?;
        let mut vf_by_reflection: HashMap<i32, valid_finding_model::Model> = valid_findings
            .into_iter()
            .map(|v| (v.reflection_id, v))
            .collect();

        let runs = harness_run_model::Entity::find()
            .filter(harness_run_model::Column::Id.is_in(run_ids))
            .all(&self.db)
            .await
            .wrap_err("failed to load harness_run rows for valid findings")?;
        let code_ids: Vec<i32> = runs.iter().map(|r| r.code_id).collect();
        let runs_by_id: HashMap<i32, harness_run_model::Model> =
            runs.into_iter().map(|r| (r.id, r)).collect();

        let code_gens = code_gen_model::Entity::find()
            .filter(code_gen_model::Column::Id.is_in(code_ids))
            .all(&self.db)
            .await
            .wrap_err("failed to load code_gen rows for valid findings")?;
        let code_gens_by_id: HashMap<i32, code_gen_model::Model> =
            code_gens.into_iter().map(|cg| (cg.id, cg)).collect();

        let specs = specification_model::Entity::find()
            .filter(specification_model::Column::Id.is_in(spec_ids))
            .all(&self.db)
            .await
            .wrap_err("failed to load specification rows for valid findings")?;
        let specs_by_id: HashMap<i32, specification_model::Model> =
            specs.into_iter().map(|s| (s.id, s)).collect();

        let mut out = Vec::with_capacity(reflections.len());
        for r in reflections {
            let vf = vf_by_reflection.remove(&r.id).ok_or_else(|| {
                color_eyre::eyre::eyre!(
                    "reflection {} has result=ValidFinding but no valid_finding row",
                    r.id
                )
            })?;
            let run = runs_by_id.get(&r.run_id).ok_or_else(|| {
                color_eyre::eyre::eyre!(
                    "reflection {} references missing harness_run {}",
                    r.id,
                    r.run_id
                )
            })?;
            let cg = code_gens_by_id.get(&run.code_id).ok_or_else(|| {
                color_eyre::eyre::eyre!(
                    "harness_run {} references missing code_gen {}",
                    run.id,
                    run.code_id
                )
            })?;
            let spec = specs_by_id.get(&r.spec_id).ok_or_else(|| {
                color_eyre::eyre::eyre!(
                    "reflection {} references missing specification {}",
                    r.id,
                    r.spec_id
                )
            })?;
            out.push(LoadedValidFinding {
                reflection_id: r.id,
                run_id: r.run_id,
                spec_id: r.spec_id,
                verdict_reason: r.reason,
                severity: vf.severity.as_str().to_string(),
                severity_reason: vf.severity_reason,
                specification_json: spec.specification.clone(),
                harness_source: cg.harness_source.clone(),
                harness_relative_path: cg.harness_relative_path.clone(),
                run_kind: run.kind.as_str().to_string(),
                run_exit_code: Some(run.exit_code),
                run_violated: run.violated,
                run_stdout: run.stdout.clone(),
                run_sequence_json: run.sequence_json.clone(),
            });
        }
        Ok(out)
    }

    /// `ValidFinding` raw findings that do NOT yet have a `finding_review`
    /// row — the Review agent's work queue. Resume-safe: a re-run only
    /// reviews what's new.
    pub async fn load_unreviewed_valid_findings(&self) -> Result<Vec<LoadedValidFinding>> {
        use sea_orm::{ColumnTrait, QueryFilter};

        let reviewed: BTreeSet<i32> = finding_review_model::Entity::find()
            .all(&self.db)
            .await
            .wrap_err("failed to load finding_review ids")?
            .into_iter()
            .map(|r| r.reflection_id)
            .collect();
        let reflections = reflection_model::Entity::find()
            .filter(reflection_model::Column::Result.eq(ReflectionResult::ValidFinding))
            .order_by_asc(reflection_model::Column::Id)
            .all(&self.db)
            .await
            .wrap_err("failed to load ValidFinding reflections")?
            .into_iter()
            .filter(|r| !reviewed.contains(&r.id))
            .collect();
        self.load_valid_findings_for(reflections).await
    }

    /// Upsert one structured review into `finding_review`, keyed on
    /// `reflection_id` (a re-review overwrites in place). Single statement:
    /// no transient partial-review state.
    pub async fn insert_finding_review(&self, rec: &FindingReviewRecord) -> Result<()> {
        use sea_orm::sea_query::OnConflict;

        let am = finding_review_model::ActiveModel {
            reflection_id: Set(rec.reflection_id),
            title: Set(rec.title.clone()),
            severity: Set(rec.severity),
            review_reason: Set(rec.review_reason.clone()),
            root_cause: Set(rec.root_cause.clone()),
            description: Set(rec.description.clone()),
            location: Set(rec.location.clone()),
            impact: Set(rec.impact.clone()),
            recommendation: Set(rec.recommendation.clone()),
            primary_contract: Set(rec.primary_contract.clone()),
            primary_function: Set(rec.primary_function.clone()),
            severity_reason: Set(rec.severity_reason.clone()),
            ..Default::default()
        };
        finding_review_model::Entity::insert(am)
            .on_conflict(
                OnConflict::column(finding_review_model::Column::ReflectionId)
                    .update_columns([
                        finding_review_model::Column::Title,
                        finding_review_model::Column::Severity,
                        finding_review_model::Column::ReviewReason,
                        finding_review_model::Column::RootCause,
                        finding_review_model::Column::Description,
                        finding_review_model::Column::Location,
                        finding_review_model::Column::Impact,
                        finding_review_model::Column::Recommendation,
                        finding_review_model::Column::PrimaryContract,
                        finding_review_model::Column::PrimaryFunction,
                        finding_review_model::Column::SeverityReason,
                    ])
                    .to_owned(),
            )
            .exec(&self.db)
            .await
            .wrap_err_with(|| {
                format!(
                    "failed to upsert finding_review for reflection {}",
                    rec.reflection_id
                )
            })?;
        Ok(())
    }

    /// Reviewed raw findings that have NOT been folded into a canonical yet
    /// (no `finding_merge` edge) — the Merge agent's drain queue. "Merged"
    /// is derived purely from edge presence; there is no boolean flag.
    pub async fn load_unmerged_finding_reviews(&self) -> Result<Vec<ReviewedFinding>> {
        let merged: BTreeSet<i32> = finding_merge_model::Entity::find()
            .all(&self.db)
            .await
            .wrap_err("failed to load finding_merge edges")?
            .into_iter()
            .map(|e| e.from_reflection_id)
            .collect();
        let reviews = finding_review_model::Entity::find()
            .order_by_asc(finding_review_model::Column::ReflectionId)
            .all(&self.db)
            .await
            .wrap_err("failed to load finding_review rows")?;
        Ok(reviews
            .into_iter()
            .filter(|r| !merged.contains(&r.reflection_id))
            .map(ReviewedFinding::from)
            .collect())
    }

    /// All canonical `report_finding` rows, ordered by id. The Merge agent
    /// compares each new raw finding against these; export reads the
    /// `Written` ones.
    pub async fn load_report_findings(&self) -> Result<Vec<LoadedReportFinding>> {
        let rows = report_finding_model::Entity::find()
            .order_by_asc(report_finding_model::Column::Id)
            .all(&self.db)
            .await
            .wrap_err("failed to load report_finding rows")?;
        Ok(rows.into_iter().map(LoadedReportFinding::from).collect())
    }

    /// Which canonical a raw finding was folded into, if any.
    pub async fn report_finding_of(&self, reflection_id: i32) -> Result<Option<i32>> {
        use sea_orm::{ColumnTrait, QueryFilter};

        let edge = finding_merge_model::Entity::find()
            .filter(finding_merge_model::Column::FromReflectionId.eq(reflection_id))
            .one(&self.db)
            .await
            .wrap_err("failed to look up finding_merge edge")?;
        Ok(edge.map(|e| e.to_report_finding_id))
    }

    /// One canonical `report_finding` by id (for incremental on-disk dumps).
    pub async fn load_report_finding(&self, id: i32) -> Result<Option<LoadedReportFinding>> {
        Ok(report_finding_model::Entity::find_by_id(id)
            .one(&self.db)
            .await
            .wrap_err("failed to load report_finding by id")?
            .map(LoadedReportFinding::from))
    }

    /// The structured reviews of one canonical's cluster members (no heavy
    /// source material). Lighter than [`Self::load_report_finding_members`];
    /// used to embed members into the on-disk unique-finding JSON.
    pub async fn load_report_finding_member_reviews(
        &self,
        report_finding_id: i32,
    ) -> Result<Vec<ReviewedFinding>> {
        use sea_orm::{ColumnTrait, QueryFilter};

        let reflection_ids: Vec<i32> = finding_merge_model::Entity::find()
            .filter(finding_merge_model::Column::ToReportFindingId.eq(report_finding_id))
            .order_by_asc(finding_merge_model::Column::FromReflectionId)
            .all(&self.db)
            .await
            .wrap_err("failed to load finding_merge edges for canonical")?
            .into_iter()
            .map(|e| e.from_reflection_id)
            .collect();
        if reflection_ids.is_empty() {
            return Ok(Vec::new());
        }
        Ok(finding_review_model::Entity::find()
            .filter(finding_review_model::Column::ReflectionId.is_in(reflection_ids))
            .order_by_asc(finding_review_model::Column::ReflectionId)
            .all(&self.db)
            .await
            .wrap_err("failed to load finding_review rows for canonical")?
            .into_iter()
            .map(ReviewedFinding::from)
            .collect())
    }

    /// The raw cluster members of one canonical: each member's structured
    /// review, its source material (spec + PoC harness + forge run), and the
    /// two graded edge strengths (mapper match + KG link) used to pick the
    /// representative. Consumed by the report renderer.
    pub async fn load_report_finding_members(
        &self,
        report_finding_id: i32,
    ) -> Result<Vec<RawFindingMember>> {
        use sea_orm::{ColumnTrait, QueryFilter};

        let reflection_ids: Vec<i32> = finding_merge_model::Entity::find()
            .filter(finding_merge_model::Column::ToReportFindingId.eq(report_finding_id))
            .all(&self.db)
            .await
            .wrap_err("failed to load finding_merge edges for canonical")?
            .into_iter()
            .map(|e| e.from_reflection_id)
            .collect();
        if reflection_ids.is_empty() {
            return Ok(Vec::new());
        }

        let mut review_by_id: HashMap<i32, ReviewedFinding> = finding_review_model::Entity::find()
            .filter(finding_review_model::Column::ReflectionId.is_in(reflection_ids.clone()))
            .all(&self.db)
            .await
            .wrap_err("failed to load finding_review rows for canonical")?
            .into_iter()
            .map(|r| (r.reflection_id, ReviewedFinding::from(r)))
            .collect();

        let reflections = reflection_model::Entity::find()
            .filter(reflection_model::Column::Id.is_in(reflection_ids))
            .all(&self.db)
            .await
            .wrap_err("failed to load reflections for canonical members")?;
        let sources = self.load_valid_findings_for(reflections).await?;

        // Strength lookup tables for representative selection: spec → its
        // (extract, historical, finding) triple, then the two edge tables
        // keyed by the relevant pair. The edge tables are per-project small;
        // loading them whole avoids per-member composite-key queries.
        let spec_ids: Vec<i32> = sources.iter().map(|s| s.spec_id).collect();
        let triple_by_spec: HashMap<i32, (i32, i32, i32)> = specification_model::Entity::find()
            .filter(specification_model::Column::Id.is_in(spec_ids))
            .all(&self.db)
            .await
            .wrap_err("failed to load specifications for canonical members")?
            .into_iter()
            .map(|s| (s.id, (s.semantic_id, s.historical_id, s.finding_id)))
            .collect();
        let mapper_by_pair: HashMap<(i32, i32), MatchStrength> =
            semantic_matched_model::Entity::find()
                .all(&self.db)
                .await
                .wrap_err("failed to load semantic_matched for member strengths")?
                .into_iter()
                .map(|m| ((m.extract_id, m.historical_id), m.strength))
                .collect();
        let link_by_pair: HashMap<(i32, i32), knowdit_kg_model::link_strength::LinkStrength> =
            historical_semantic_finding_link_model::Entity::find()
                .all(&self.db)
                .await
                .wrap_err("failed to load historical_semantic_finding_link for member strengths")?
                .into_iter()
                .map(|l| {
                    (
                        (l.historical_semantic_id, l.historical_finding_id),
                        l.strength,
                    )
                })
                .collect();

        let mut out = Vec::with_capacity(sources.len());
        for source in sources {
            let Some(review) = review_by_id.remove(&source.reflection_id) else {
                continue;
            };
            let (mapper_strength, link_strength) = match triple_by_spec.get(&source.spec_id) {
                Some(&(extract_id, historical_id, finding_id)) => (
                    mapper_by_pair.get(&(extract_id, historical_id)).copied(),
                    link_by_pair.get(&(historical_id, finding_id)).copied(),
                ),
                None => (None, None),
            };
            out.push(RawFindingMember {
                review,
                source,
                mapper_strength,
                link_strength,
            });
        }
        Ok(out)
    }

    /// Atomic: persist one Merge-agent decision for a raw finding.
    ///
    /// * `NewCanonical` → insert a `report_finding` (`status = Merged`) and
    ///   the edge.
    /// * `MergeInto` → optionally raise the canonical's severity (only when
    ///   the new member outranks it), then the edge.
    ///
    /// One transaction: an interruption leaves no edge, so the next drain
    /// re-processes the raw finding. The `UNIQUE(from_reflection_id)`
    /// constraint rejects a double-merge of the same raw finding. Returns
    /// the canonical id the finding now belongs to.
    pub async fn commit_finding_merge(
        &self,
        from_reflection_id: i32,
        decision: FindingMergeDecision,
    ) -> Result<i32> {
        use sea_orm::{ActiveModelTrait, IntoActiveModel};

        let txn = self
            .db
            .begin()
            .await
            .wrap_err("failed to begin finding-merge transaction")?;

        let to_report_finding_id = match decision {
            FindingMergeDecision::NewCanonical(seed) => {
                let inserted =
                    report_finding_model::Entity::insert(report_finding_model::ActiveModel {
                        title: Set(seed.title),
                        severity: Set(seed.severity),
                        root_cause: Set(seed.root_cause),
                        description: Set(seed.description),
                        primary_contract: Set(seed.primary_contract),
                        primary_function: Set(seed.primary_function),
                        ..Default::default()
                    })
                    .exec(&txn)
                    .await
                    .wrap_err("failed to insert new canonical report_finding")?;
                inserted.last_insert_id
            }
            FindingMergeDecision::MergeInto {
                report_finding_id,
                raise_to,
            } => {
                if let Some(sev) = raise_to {
                    let current = report_finding_model::Entity::find_by_id(report_finding_id)
                        .one(&txn)
                        .await
                        .wrap_err("failed to load merge-target canonical")?
                        .ok_or_else(|| {
                            color_eyre::eyre::eyre!(
                                "merge target report_finding {report_finding_id} not found"
                            )
                        })?;
                    if sev.rank() > current.severity.rank() {
                        let mut am = current.into_active_model();
                        am.severity = Set(sev);
                        am.update(&txn)
                            .await
                            .wrap_err("failed to raise canonical severity")?;
                    }
                }
                report_finding_id
            }
        };

        finding_merge_model::Entity::insert(finding_merge_model::ActiveModel {
            from_reflection_id: Set(from_reflection_id),
            to_report_finding_id: Set(to_report_finding_id),
            ..Default::default()
        })
        .exec(&txn)
        .await
        .wrap_err_with(|| {
            format!("failed to insert finding_merge edge for reflection {from_reflection_id}")
        })?;

        txn.commit()
            .await
            .wrap_err("failed to commit finding-merge transaction")?;
        Ok(to_report_finding_id)
    }

    /// The mapper-side match + KG-side finding link that together
    /// produced the given spec.
    ///
    /// Returns two existing types side-by-side rather than a fresh
    /// wrapper:
    ///
    /// * [`SemanticMatch`] — the project's `semantic_matched` row
    ///   linking the project extract to one historical semantic, with
    ///   the mapper's strength label and rationale.
    /// * [`knowdit_kg_model::db::semantic_finding_link::Model`] — the
    ///   KG-native link row from historical_semantic to
    ///   historical_finding, with the link agent's strength + evidence.
    ///
    /// Returns `None` only when the link tables don't have a
    /// complete chain back to this spec (e.g. `semantic_matched` was
    /// wiped without also wiping the specs).
    ///
    /// The spec row carries `historical_id` directly — no heuristic
    /// "pick strongest candidate" guess. We look up the two
    /// strength/evidence pairs by the spec's exact triple:
    /// `(extract, historical, finding)`.
    pub async fn load_link_for_spec(
        &self,
        spec_id: i32,
    ) -> Result<
        Option<(
            SemanticMatch,
            knowdit_kg_model::db::semantic_finding_link::Model,
        )>,
    > {
        use sea_orm::{ColumnTrait, QueryFilter};

        let Some(spec) = specification_model::Entity::find_by_id(spec_id)
            .one(&self.db)
            .await
            .wrap_err_with(|| format!("failed to load specification {spec_id}"))?
        else {
            return Ok(None);
        };

        let matched = semantic_matched_model::Entity::find()
            .filter(semantic_matched_model::Column::ExtractId.eq(spec.semantic_id))
            .filter(semantic_matched_model::Column::HistoricalId.eq(spec.historical_id))
            .one(&self.db)
            .await
            .wrap_err_with(|| {
                format!(
                    "failed to load semantic_matched row for (extract={}, historical={}) (spec {spec_id})",
                    spec.semantic_id, spec.historical_id
                )
            })?;
        let Some(matched) = matched else {
            return Ok(None);
        };

        let link = historical_semantic_finding_link_model::Entity::find()
            .filter(
                historical_semantic_finding_link_model::Column::HistoricalSemanticId
                    .eq(spec.historical_id),
            )
            .filter(
                historical_semantic_finding_link_model::Column::HistoricalFindingId
                    .eq(spec.finding_id),
            )
            .one(&self.db)
            .await
            .wrap_err_with(|| {
                format!(
                    "failed to load historical_semantic_finding_link for (hist={}, finding={})",
                    spec.historical_id, spec.finding_id
                )
            })?;
        let Some(link) = link else {
            return Ok(None);
        };

        Ok(Some((
            SemanticMatch {
                extract_id: matched.extract_id,
                historical_id: matched.historical_id,
                strength: matched.strength,
                evidence: matched.evidence,
            },
            link.into(),
        )))
    }

    /// Self-contained provenance for one spec's finding — the project DB rows
    /// for the extract semantic, the historical semantic it matched, and the
    /// historical finding that motivated it (FULL content, as the actual
    /// models), plus the two graded edges (mapper match + KG link). Lets an
    /// on-disk finding JSON fully explain its origin without the KG database.
    ///
    /// Returns `None` only when the spec or one of the three content rows is
    /// missing (the project DB copies all three at map / spec time, so this is
    /// effectively always `Some` for a real spec). The two edges are `Option`
    /// — a spec can outlive its mapper / link rows.
    pub async fn load_provenance_for_spec(
        &self,
        spec_id: i32,
    ) -> Result<Option<FindingProvenance>> {
        use sea_orm::{ColumnTrait, QueryFilter};

        let Some(spec) = specification_model::Entity::find_by_id(spec_id)
            .one(&self.db)
            .await
            .wrap_err_with(|| format!("failed to load specification {spec_id}"))?
        else {
            return Ok(None);
        };
        let extract = project_semantic_model::Entity::find_by_id(spec.semantic_id)
            .one(&self.db)
            .await
            .wrap_err("failed to load project_semantic for provenance")?;
        let historical_semantic = historical_semantic_model::Entity::find_by_id(spec.historical_id)
            .one(&self.db)
            .await
            .wrap_err("failed to load historical_semantic for provenance")?;
        let historical_finding = historical_finding_model::Entity::find_by_id(spec.finding_id)
            .one(&self.db)
            .await
            .wrap_err("failed to load historical_finding for provenance")?;
        let (Some(extract), Some(historical_semantic), Some(historical_finding)) =
            (extract, historical_semantic, historical_finding)
        else {
            return Ok(None);
        };

        let semantic_match = semantic_matched_model::Entity::find()
            .filter(semantic_matched_model::Column::ExtractId.eq(spec.semantic_id))
            .filter(semantic_matched_model::Column::HistoricalId.eq(spec.historical_id))
            .one(&self.db)
            .await
            .wrap_err("failed to load semantic_matched for provenance")?;
        let finding_link = historical_semantic_finding_link_model::Entity::find()
            .filter(
                historical_semantic_finding_link_model::Column::HistoricalSemanticId
                    .eq(spec.historical_id),
            )
            .filter(
                historical_semantic_finding_link_model::Column::HistoricalFindingId
                    .eq(spec.finding_id),
            )
            .one(&self.db)
            .await
            .wrap_err("failed to load historical_semantic_finding_link for provenance")?;

        Ok(Some(FindingProvenance {
            extract,
            semantic_match,
            historical_semantic,
            finding_link,
            historical_finding,
        }))
    }

    /// True if this `harness_run` already has a reflection row.
    /// Used to skip already-reflected runs during resume.
    pub async fn has_reflection(&self, run_id: i32) -> Result<bool> {
        use sea_orm::{ColumnTrait, PaginatorTrait, QueryFilter};
        let n = reflection_model::Entity::find()
            .filter(reflection_model::Column::RunId.eq(run_id))
            .count(&self.db)
            .await
            .wrap_err_with(|| format!("failed to query reflection count for run_id={run_id}"))?;
        Ok(n > 0)
    }

    /// Insert a `code_gen_regen` lineage row. Caller has already inserted
    /// the new child code_gen and the triggering reflection; this just
    /// records the parent→child edge. Single-statement, atomic.
    pub async fn insert_code_gen_regen(&self, event: &RegenEventRecord) -> Result<()> {
        code_gen_regen_model::Entity::insert(code_gen_regen_model::ActiveModel {
            child_code_gen_id: Set(event.child_id),
            parent_code_gen_id: Set(event.parent_id),
            reason: Set(event.reason.clone()),
            triggered_by_reflection_id: Set(event.triggered_by_reflection_id),
        })
        .exec(&self.db)
        .await
        .wrap_err_with(|| {
            format!(
                "failed to insert code_gen_regen child={} parent={} reflection={}",
                event.child_id, event.parent_id, event.triggered_by_reflection_id
            )
        })?;
        Ok(())
    }

    /// Insert a `specification_regen` lineage row. Same shape as
    /// [`Self::insert_code_gen_regen`] but for spec lineage.
    pub async fn insert_specification_regen(&self, event: &RegenEventRecord) -> Result<()> {
        specification_regen_model::Entity::insert(specification_regen_model::ActiveModel {
            child_spec_id: Set(event.child_id),
            parent_spec_id: Set(event.parent_id),
            reason: Set(event.reason.clone()),
            triggered_by_reflection_id: Set(event.triggered_by_reflection_id),
        })
        .exec(&self.db)
        .await
        .wrap_err_with(|| {
            format!(
                "failed to insert specification_regen child={} parent={} reflection={}",
                event.child_id, event.parent_id, event.triggered_by_reflection_id
            )
        })?;
        Ok(())
    }

    /// All reflection rows whose verdict requires regen (`Suspect`,
    /// `IncompleteStep`, `IncompleteSpecification`) AND that have not
    /// yet been consumed by either `*_regen` lineage table.
    ///
    /// The reflection row itself doubles as the "pending regen" marker
    /// — once a `*_regen` row references it via
    /// `triggered_by_reflection_id`, the reflection drops out of this
    /// query.
    pub async fn pending_reflections(&self) -> Result<Vec<PendingReflection>> {
        use sea_orm::{ColumnTrait, QueryFilter};

        // reflection is per-run; the regen scheduler still drives off
        // code_gen lineage, so we look up each reflection's owning
        // harness_run to recover `code_id`.
        let candidates = reflection_model::Entity::find()
            .filter(reflection_model::Column::Result.is_in([
                ReflectionResult::Suspect,
                ReflectionResult::IncompleteStep,
                ReflectionResult::IncompleteSpecification,
            ]))
            .order_by_asc(reflection_model::Column::Id)
            .all(&self.db)
            .await
            .wrap_err("failed to load candidate reflections for pending_reflections")?;
        if candidates.is_empty() {
            return Ok(Vec::new());
        }

        let candidate_ids: Vec<i32> = candidates.iter().map(|r| r.id).collect();
        let run_ids: Vec<i32> = candidates.iter().map(|r| r.run_id).collect();

        let runs = harness_run_model::Entity::find()
            .filter(harness_run_model::Column::Id.is_in(run_ids))
            .all(&self.db)
            .await
            .wrap_err("failed to load harness_run rows for pending_reflections")?;
        let runs_by_id: HashMap<i32, harness_run_model::Model> =
            runs.into_iter().map(|r| (r.id, r)).collect();

        // A reflection drops out of the queue the moment a `*_regen`
        // row references it via `triggered_by_reflection_id`. Two
        // bulk fetches + two HashSet membership checks replace the
        // original `NOT EXISTS (... )` correlated subqueries.
        let consumed_by_codegen: std::collections::HashSet<i32> =
            code_gen_regen_model::Entity::find()
                .filter(
                    code_gen_regen_model::Column::TriggeredByReflectionId
                        .is_in(candidate_ids.clone()),
                )
                .all(&self.db)
                .await
                .wrap_err("failed to load code_gen_regen consumption rows")?
                .into_iter()
                .map(|r| r.triggered_by_reflection_id)
                .collect();
        let consumed_by_spec: std::collections::HashSet<i32> =
            specification_regen_model::Entity::find()
                .filter(
                    specification_regen_model::Column::TriggeredByReflectionId.is_in(candidate_ids),
                )
                .all(&self.db)
                .await
                .wrap_err("failed to load specification_regen consumption rows")?
                .into_iter()
                .map(|r| r.triggered_by_reflection_id)
                .collect();

        let mut out = Vec::new();
        for r in candidates {
            if consumed_by_codegen.contains(&r.id) || consumed_by_spec.contains(&r.id) {
                continue;
            }
            let run = runs_by_id.get(&r.run_id).ok_or_else(|| {
                color_eyre::eyre::eyre!(
                    "reflection {} references missing harness_run {}",
                    r.id,
                    r.run_id
                )
            })?;
            out.push(PendingReflection {
                reflection_id: r.id,
                run_id: r.run_id,
                code_id: run.code_id,
                spec_id: r.spec_id,
                result: r.result,
                reason: r.reason,
            });
        }
        Ok(out)
    }

    /// Pending regen rows scoped to one or more specification ids. Used by
    /// streaming schedulers to keep one link's regen lineage moving without
    /// draining unrelated global work.
    pub async fn pending_reflections_for_specs(
        &self,
        spec_ids: &[i32],
    ) -> Result<Vec<PendingReflection>> {
        if spec_ids.is_empty() {
            return Ok(Vec::new());
        }
        use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};
        let rows = reflection_model::Entity::find()
            .filter(reflection_model::Column::SpecId.is_in(spec_ids.iter().copied()))
            .all(&self.db)
            .await
            .wrap_err("failed to query scoped pending reflections")?;
        let mut out = Vec::new();
        for row in rows {
            if !row.result.requires_regen() {
                continue;
            }
            let consumed_codegen = code_gen_regen_model::Entity::find()
                .filter(code_gen_regen_model::Column::TriggeredByReflectionId.eq(row.id))
                .one(&self.db)
                .await?
                .is_some();
            let consumed_spec = specification_regen_model::Entity::find()
                .filter(specification_regen_model::Column::TriggeredByReflectionId.eq(row.id))
                .one(&self.db)
                .await?
                .is_some();
            if consumed_codegen || consumed_spec {
                continue;
            }
            let run = harness_run_model::Entity::find_by_id(row.run_id)
                .one(&self.db)
                .await?
                .ok_or_else(|| {
                    color_eyre::eyre::eyre!(
                        "reflection {} references missing run_id={}",
                        row.id,
                        row.run_id
                    )
                })?;
            out.push(PendingReflection {
                reflection_id: row.id,
                run_id: row.run_id,
                code_id: run.code_id,
                spec_id: row.spec_id,
                result: row.result,
                reason: row.reason,
            });
        }
        out.sort_by_key(|r| r.reflection_id);
        Ok(out)
    }

    /// How deep the codegen regen chain is at this code_gen — i.e. how
    /// many parents you'd visit walking `parent_code_gen_id` links until
    /// a row with no parent. A fresh code_gen returns 0.
    ///
    /// Implementation walks the `code_gen_regen` table one hop at a
    /// time via the typed entity API. The lineage is tree-shaped (PK
    /// on `child_code_gen_id` ensures each code_gen has at most one
    /// parent), so depth = number of regen rows on the upward path.
    pub async fn code_gen_chain_depth(&self, code_id: i32) -> Result<u32> {
        use sea_orm::{ColumnTrait, QueryFilter};
        let mut depth = 0u32;
        let mut current = code_id;
        loop {
            let parent = code_gen_regen_model::Entity::find()
                .filter(code_gen_regen_model::Column::ChildCodeGenId.eq(current))
                .one(&self.db)
                .await
                .wrap_err_with(|| format!("failed to load code_gen_regen for child {current}"))?;
            let Some(parent) = parent else { break };
            depth += 1;
            current = parent.parent_code_gen_id;
        }
        Ok(depth)
    }

    /// How deep the spec regen chain is at this spec. Same walk as
    /// [`Self::code_gen_chain_depth`] but over `specification_regen`.
    pub async fn spec_chain_depth(&self, spec_id: i32) -> Result<u32> {
        use sea_orm::{ColumnTrait, QueryFilter};
        let mut depth = 0u32;
        let mut current = spec_id;
        loop {
            let parent = specification_regen_model::Entity::find()
                .filter(specification_regen_model::Column::ChildSpecId.eq(current))
                .one(&self.db)
                .await
                .wrap_err_with(|| {
                    format!("failed to load specification_regen for child {current}")
                })?;
            let Some(parent) = parent else { break };
            depth += 1;
            current = parent.parent_spec_id;
        }
        Ok(depth)
    }

    /// Count `IncompleteStep` reflections written against any
    /// ancestor `code_gen` in this code_gen's regen lineage. Drives
    /// the Gate 3 grader's "two strikes → escalate to spec regen" rule
    /// (`prior_incomplete_step_count >= 2 → IncompleteSpecification`).
    /// Returns 0 when this code_gen has no parent (chain root).
    ///
    /// Three typed queries:
    /// 1. Walk `code_gen_regen` upward from `code_id`, collecting
    ///    ancestor ids.
    /// 2. Load every `harness_run` whose `code_id` is in that set.
    /// 3. Count `reflection` rows with `RunId IN runs` and
    ///    `result = IncompleteStep`.
    pub async fn prior_incomplete_step_count(&self, code_id: i32) -> Result<u32> {
        use sea_orm::{ColumnTrait, PaginatorTrait, QueryFilter};

        let mut ancestors: Vec<i32> = Vec::new();
        let mut current = code_id;
        loop {
            let parent = code_gen_regen_model::Entity::find()
                .filter(code_gen_regen_model::Column::ChildCodeGenId.eq(current))
                .one(&self.db)
                .await
                .wrap_err_with(|| format!("failed to load code_gen_regen for child {current}"))?;
            let Some(parent) = parent else { break };
            ancestors.push(parent.parent_code_gen_id);
            current = parent.parent_code_gen_id;
        }
        if ancestors.is_empty() {
            return Ok(0);
        }

        let ancestor_runs = harness_run_model::Entity::find()
            .filter(harness_run_model::Column::CodeId.is_in(ancestors))
            .all(&self.db)
            .await
            .wrap_err_with(|| {
                format!("failed to load harness_runs for ancestors of code {code_id}")
            })?;
        if ancestor_runs.is_empty() {
            return Ok(0);
        }
        let run_ids: Vec<i32> = ancestor_runs.into_iter().map(|r| r.id).collect();

        let n = reflection_model::Entity::find()
            .filter(reflection_model::Column::RunId.is_in(run_ids))
            .filter(reflection_model::Column::Result.eq(ReflectionResult::IncompleteStep))
            .count(&self.db)
            .await
            .wrap_err_with(|| {
                format!(
                    "failed to count IncompleteStep reflections for ancestors of code {code_id}"
                )
            })?;
        Ok(n as u32)
    }

    // -----------------------------------------------------------------
    // Move-language schema (Stage 3a of plan_move_lang.md). Written
    // by movy CLI subprocesses, read by the audit pipeline (gen-spec /
    // mapper prompts) when language == Move. Solidity paths never
    // touch these tables; the rows stay empty in OSS builds.
    // -----------------------------------------------------------------

    /// Persist a full per-repo static-analysis snapshot —
    /// [`CallGraph`] plus [`MovePackageStructure`] — in a single
    /// orchestrated call. Composes [`Self::write_call_graph`] and
    /// [`Self::write_package_structure`] sequentially.
    ///
    /// Each underlying writer is its own crash-safe transaction
    /// (`clear all + bulk insert`); we do **not** wrap them in
    /// one outer transaction. That's intentional: each writer is
    /// independently idempotent, so a crash between them leaves
    /// the DB in a valid partial state (CG written, structure
    /// stale or empty) that the next invocation overwrites
    /// cleanly. The §0.1.D resume-safety property holds without
    /// the complexity of threading a shared transaction through
    /// two large writer paths.
    ///
    /// Movy's `analysis export-repo-info` CLI is the canonical
    /// caller. Future repo-level static analyses
    /// (type graphs, storage patterns, …) should plug in here
    /// rather than spawning more standalone export commands.
    pub async fn write_repo_info(
        &self,
        call_graph: &CallGraph,
        structure: &MovePackageStructure,
    ) -> Result<()> {
        self.write_call_graph(call_graph).await?;
        self.write_package_structure(structure).await?;
        Ok(())
    }

    /// Replace the per-package Move structure (struct definitions +
    /// per-function metadata) in one crash-safe transaction. Same
    /// `clear all + bulk insert` pattern as [`Self::write_storage_graph`]
    /// — a crash partway through rolls back; re-running fully
    /// replaces the previous snapshot.
    ///
    /// `contract` and `function` rows must already exist (they
    /// are written by [`Self::write_call_graph`], invoked as the
    /// first half of [`Self::write_repo_info`]); this method
    /// validates referential integrity at insert time by relying
    /// on the FKs SQLite enforces with `PRAGMA foreign_keys=ON`.
    pub async fn write_package_structure(&self, structure: &MovePackageStructure) -> Result<()> {
        let txn = self
            .db
            .begin()
            .await
            .wrap_err("failed to begin move package structure write transaction")?;

        // FK-safe clear order: ability rows reference move_struct,
        // function_metadata references function (independent).
        move_struct_ability_model::Entity::delete_many()
            .exec(&txn)
            .await
            .wrap_err("failed to clear move_struct_ability rows")?;
        move_function_metadata_model::Entity::delete_many()
            .exec(&txn)
            .await
            .wrap_err("failed to clear move_function_metadata rows")?;
        move_struct_model::Entity::delete_many()
            .exec(&txn)
            .await
            .wrap_err("failed to clear move_struct rows")?;

        let mut next_ability_id: i32 = 1;
        for s in &structure.structs {
            let generic_params_json =
                serde_json::to_string(&s.generic_params).wrap_err_with(|| {
                    format!(
                        "failed to serialize move_struct.generic_params for struct id={}",
                        s.id
                    )
                })?;
            let fields_json = serde_json::to_string(&s.fields).wrap_err_with(|| {
                format!(
                    "failed to serialize move_struct.fields for struct id={}",
                    s.id
                )
            })?;
            move_struct_model::Entity::insert(move_struct_model::ActiveModel {
                id: Set(s.id),
                contract_id: Set(s.contract_id),
                name: Set(s.name.clone()),
                generic_params: Set(generic_params_json),
                fields: Set(fields_json),
            })
            .exec(&txn)
            .await
            .wrap_err_with(|| {
                format!(
                    "failed to insert move_struct id={} contract={} name={}",
                    s.id, s.contract_id, s.name
                )
            })?;

            // Dedupe abilities on input so a malformed analyzer
            // emit that double-lists an ability hits a clear Rust-
            // level error rather than a cryptic UNIQUE violation.
            let mut seen: std::collections::BTreeSet<MoveAbility> =
                std::collections::BTreeSet::new();
            for ability in &s.abilities {
                if !seen.insert(*ability) {
                    continue;
                }
                move_struct_ability_model::Entity::insert(move_struct_ability_model::ActiveModel {
                    id: Set(next_ability_id),
                    struct_id: Set(s.id),
                    ability: Set(*ability),
                })
                .exec(&txn)
                .await
                .wrap_err_with(|| {
                    format!(
                        "failed to insert move_struct_ability struct_id={} ability={:?}",
                        s.id, ability
                    )
                })?;
                next_ability_id += 1;
            }
        }

        for m in &structure.function_metadata {
            let generic_params_json = serde_json::to_string(&m.generic_params).wrap_err_with(
                || {
                    format!(
                        "failed to serialize move_function_metadata.generic_params for function id={}",
                        m.function_id
                    )
                },
            )?;
            move_function_metadata_model::Entity::insert(
                move_function_metadata_model::ActiveModel {
                    function_id: Set(m.function_id),
                    visibility: Set(m.visibility),
                    is_entry: Set(m.is_entry),
                    generic_params: Set(generic_params_json),
                },
            )
            .exec(&txn)
            .await
            .wrap_err_with(|| {
                format!(
                    "failed to insert move_function_metadata function_id={}",
                    m.function_id
                )
            })?;
        }

        txn.commit()
            .await
            .wrap_err("failed to commit move package structure write transaction")?;
        Ok(())
    }

    /// Read back the Move package structure into a single in-memory
    /// snapshot. Three table scans + one in-Rust group-by; no
    /// joins. Callers that only need one slice can build dedicated
    /// queries on top of the raw SeaORM entities.
    pub async fn load_package_structure(&self) -> Result<MovePackageStructure> {
        let struct_rows = move_struct_model::Entity::find()
            .order_by_asc(move_struct_model::Column::Id)
            .all(&self.db)
            .await
            .wrap_err("failed to load move_struct rows")?;
        let ability_rows = move_struct_ability_model::Entity::find()
            .all(&self.db)
            .await
            .wrap_err("failed to load move_struct_ability rows")?;
        let metadata_rows = move_function_metadata_model::Entity::find()
            .order_by_asc(move_function_metadata_model::Column::FunctionId)
            .all(&self.db)
            .await
            .wrap_err("failed to load move_function_metadata rows")?;

        // Group abilities by struct_id; sort each list by
        // canonical order so the returned `Vec<MoveAbility>` is
        // deterministic regardless of insertion order in the DB.
        let mut abilities_by_struct: BTreeMap<i32, Vec<MoveAbility>> = BTreeMap::new();
        for row in ability_rows {
            abilities_by_struct
                .entry(row.struct_id)
                .or_default()
                .push(row.ability);
        }
        for list in abilities_by_struct.values_mut() {
            list.sort_by_key(|a| a.canonical_order());
        }

        let structs = struct_rows
            .into_iter()
            .map(|row| {
                let abilities = abilities_by_struct.remove(&row.id).unwrap_or_default();
                let generic_params: Vec<MoveGenericParam> =
                    serde_json::from_str(&row.generic_params).wrap_err_with(|| {
                        format!(
                            "failed to deserialize move_struct.generic_params for id={}",
                            row.id
                        )
                    })?;
                let fields: Vec<MoveField> =
                    serde_json::from_str(&row.fields).wrap_err_with(|| {
                        format!("failed to deserialize move_struct.fields for id={}", row.id)
                    })?;
                Ok::<_, color_eyre::eyre::Report>(MoveStruct {
                    id: row.id,
                    contract_id: row.contract_id,
                    name: row.name,
                    abilities,
                    generic_params,
                    fields,
                })
            })
            .collect::<Result<Vec<_>>>()?;

        let function_metadata = metadata_rows
            .into_iter()
            .map(|row| {
                let generic_params: Vec<MoveGenericParam> =
                    serde_json::from_str(&row.generic_params).wrap_err_with(|| {
                        format!(
                            "failed to deserialize move_function_metadata.generic_params for function_id={}",
                            row.function_id
                        )
                    })?;
                Ok::<_, color_eyre::eyre::Report>(MoveFunctionMetadata {
                    function_id: row.function_id,
                    visibility: row.visibility,
                    is_entry: row.is_entry,
                    generic_params,
                })
            })
            .collect::<Result<Vec<_>>>()?;

        Ok(MovePackageStructure {
            function_metadata,
            structs,
        })
    }
}
