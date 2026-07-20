use crate::category::DeFiCategory;
use crate::error::{KgError, Result};
use crate::knowledge_graph::KnowledgeGraph;
use crate::vulnerability::{FINDING_TAXONOMY, VulnerabilityCategory};
use itertools::Itertools;
use knowdit_kg_model::db::merge_status::MergePhase;
use knowdit_kg_model::db::operation_history::{self, OperationType};
use knowdit_kg_model::db::{
    audit_finding, audit_finding_category, category, extraction_chunk, finding_category,
    finding_link_status, finding_merge, merge_status, pending_semantic, project, project_category,
    project_finding, project_platform, project_semantic, semantic_finding_link, semantic_function,
    semantic_merge, semantic_node,
};
use knowdit_kg_model::link_strength::LinkStrength;
use sea_orm::{
    ActiveModelTrait,
    ActiveValue::{NotSet, Set},
    ColumnTrait, ConnectionTrait, DatabaseBackend, DatabaseConnection, DatabaseTransaction,
    EntityTrait, IntoActiveModel, PaginatorTrait, QueryFilter, QueryOrder, Schema, Statement,
    TransactionTrait,
    sea_query::{ForeignKey, ForeignKeyAction, TableCreateStatement},
};
use std::collections::{HashMap, HashSet};

/// Evidence-text prefix stamped on auto-generated **in-project** links (written
/// at extraction time in [`HistoricalDatabase::write_project_completed_txn`],
/// linking a finding to a semantic from the SAME project). Global cross-project
/// links carry an LLM rationale instead. This prefix is how the two kinds are
/// told apart when selectively resetting link progress
/// ([`HistoricalDatabase::clear_finding_link_progress`]).
pub(crate) const IN_PROJECT_LINK_EVIDENCE_PREFIX: &str =
    "in-project link: finding and semantic co-emitted by the extract pipeline";

/// Main database handle wrapping a SeaORM connection.
/// All knowledge-graph queries and mutations go through this struct.
#[derive(Debug, Clone)]
pub struct HistoricalDatabase {
    db: DatabaseConnection,
}

impl HistoricalDatabase {
    /// Crate-internal connection accessor (e.g. for [`crate::stats`]).
    pub(crate) fn conn(&self) -> &DatabaseConnection {
        &self.db
    }
}

/// One row to append to `semantic_finding_link`. Produced by the link
/// agent and persisted via [`HistoricalDatabase::append_semantic_finding_links`].
/// Carries the full set of columns including strength + evidence so the
/// write path has a single typed argument (no `(i32, i32, …)` tuples).
#[derive(Debug, Clone)]
pub struct LinkEdge {
    pub semantic_node_id: i32,
    pub audit_finding_id: i32,
    pub strength: LinkStrength,
    pub evidence: String,
}

/// One row returned by [`HistoricalDatabase::findings_for_semantic_ids`].
/// `canonical_semantic_id` is one of the input ids regardless of whether
/// the link's source row sat on the canonical or on a merged raw — see
/// the function's docstring for the merge-chase behaviour.
#[derive(Debug, Clone)]
pub struct LinkedFinding {
    pub canonical_semantic_id: i32,
    pub finding: audit_finding::Model,
    pub strength: LinkStrength,
    pub evidence: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DbValidationIssue {
    pub table: &'static str,
    pub row_key: String,
    pub problem: String,
}

#[derive(Debug, Clone)]
pub struct SemanticScopeSeed {
    pub name: String,
    pub category: DeFiCategory,
    pub definition: String,
    pub description: String,
    pub functions: Vec<(String, String)>,
}

#[derive(Debug, Clone)]
pub struct VulnerabilityScopeSeed {
    pub title: String,
    pub severity: String,
    pub description: String,
    pub categories: Vec<DeFiCategory>,
    pub semantic_names: Vec<String>,
}

impl std::fmt::Display for DbValidationIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[{}] {}: {}", self.table, self.row_key, self.problem)
    }
}

#[derive(Debug, Clone, Default)]
pub struct DbValidationReport {
    pub detected_issues: Vec<DbValidationIssue>,
    pub remaining_issues: Vec<DbValidationIssue>,
    pub repaired_rows: usize,
}

impl DbValidationReport {
    pub fn detected_issue_count(&self) -> usize {
        self.detected_issues.len()
    }

    pub fn remaining_issue_count(&self) -> usize {
        self.remaining_issues.len()
    }

    pub fn is_clean(&self) -> bool {
        self.remaining_issues.is_empty()
    }
}

#[derive(Debug, Clone)]
struct DetectedDbIssue {
    issue: DbValidationIssue,
    /// `None` for issues that can't be auto-fixed via row deletion.
    /// `validate_db --repair` skips these — the caller has to make a
    /// decision (e.g. partial-link state is fixed by finishing the
    /// learn run, not by deleting rows).
    repair_action: Option<DbValidationRepairAction>,
}

#[derive(Debug, Clone)]
enum DbValidationRepairAction {
    DeleteProjectPlatform {
        id: i32,
    },
    DeleteProjectCategory {
        project_id: i32,
        category_id: i32,
    },
    DeleteSemanticFunction {
        id: i32,
    },
    DeleteSemanticMerge {
        from_semantic_id: i32,
        to_semantic_id: i32,
    },
    DeleteAuditFindingCategory {
        audit_finding_id: i32,
        finding_category_id: i32,
    },
    DeleteSemanticFindingLink {
        semantic_node_id: i32,
        audit_finding_id: i32,
    },
    DeleteFindingLinkStatus {
        audit_finding_id: i32,
    },
    DeleteFindingMerge {
        from_finding_id: i32,
        to_finding_id: i32,
    },
}

impl DbValidationRepairAction {
    async fn execute(&self, conn: &impl ConnectionTrait) -> Result<u64> {
        let result = match self {
            Self::DeleteProjectPlatform { id } => {
                project_platform::Entity::delete_many()
                    .filter(project_platform::Column::Id.eq(*id))
                    .exec(conn)
                    .await?
            }
            Self::DeleteProjectCategory {
                project_id,
                category_id,
            } => {
                project_category::Entity::delete_many()
                    .filter(project_category::Column::ProjectId.eq(*project_id))
                    .filter(project_category::Column::CategoryId.eq(*category_id))
                    .exec(conn)
                    .await?
            }
            Self::DeleteSemanticFunction { id } => {
                semantic_function::Entity::delete_many()
                    .filter(semantic_function::Column::Id.eq(*id))
                    .exec(conn)
                    .await?
            }
            Self::DeleteSemanticMerge {
                from_semantic_id,
                to_semantic_id,
            } => {
                semantic_merge::Entity::delete_many()
                    .filter(semantic_merge::Column::FromSemanticId.eq(*from_semantic_id))
                    .filter(semantic_merge::Column::ToSemanticId.eq(*to_semantic_id))
                    .exec(conn)
                    .await?
            }
            Self::DeleteAuditFindingCategory {
                audit_finding_id,
                finding_category_id,
            } => {
                audit_finding_category::Entity::delete_many()
                    .filter(audit_finding_category::Column::AuditFindingId.eq(*audit_finding_id))
                    .filter(
                        audit_finding_category::Column::FindingCategoryId.eq(*finding_category_id),
                    )
                    .exec(conn)
                    .await?
            }
            Self::DeleteSemanticFindingLink {
                semantic_node_id,
                audit_finding_id,
            } => {
                semantic_finding_link::Entity::delete_many()
                    .filter(semantic_finding_link::Column::SemanticNodeId.eq(*semantic_node_id))
                    .filter(semantic_finding_link::Column::AuditFindingId.eq(*audit_finding_id))
                    .exec(conn)
                    .await?
            }
            Self::DeleteFindingLinkStatus { audit_finding_id } => {
                finding_link_status::Entity::delete_many()
                    .filter(finding_link_status::Column::AuditFindingId.eq(*audit_finding_id))
                    .exec(conn)
                    .await?
            }
            Self::DeleteFindingMerge {
                from_finding_id,
                to_finding_id,
            } => {
                finding_merge::Entity::delete_many()
                    .filter(finding_merge::Column::FromFindingId.eq(*from_finding_id))
                    .filter(finding_merge::Column::ToFindingId.eq(*to_finding_id))
                    .exec(conn)
                    .await?
            }
        };

        Ok(result.rows_affected)
    }
}

impl HistoricalDatabase {
    /// Connect to the database and return a new handle. Runs the
    /// in-place schema migrations (currently just
    /// [`Self::migrate_schema`]) so opening a pre-existing KG that
    /// predates a column addition silently upgrades to the current
    /// shape before any read hits a missing column.
    pub async fn connect(url: &str) -> Result<Self> {
        use sea_orm::{ConnectOptions, Database, DatabaseBackend};
        tracing::info!(database_url = %redact_database_url(url), "Connecting to database");
        // Size the pool explicitly. The bulk-learn merge path
        // (`merge_and_write`) opens a write transaction and then, while it
        // is still open, borrows *additional* pool connections for its
        // candidate-fetch reads inside `merge_with_existing`. sea_orm's tiny
        // SQLite default pool starves that into an "acquire connection: pool
        // timed out". A handful of connections + WAL (concurrent readers, one
        // writer) resolves it; the merge phase is serial so there's no
        // multi-writer contention.
        let mut opts = ConnectOptions::new(url.to_owned());
        opts.max_connections(32)
            .min_connections(1)
            .acquire_timeout(std::time::Duration::from_secs(60))
            .sqlx_logging(false);
        let db = Database::connect(opts).await?;
        if db.get_database_backend() == DatabaseBackend::Sqlite {
            db.execute_unprepared("PRAGMA journal_mode=WAL;").await?;
            db.execute_unprepared("PRAGMA foreign_keys=ON;").await?;
            // Wait on a busy writer rather than failing instantly (helps the
            // concurrent link phase serialize its writes under WAL).
            db.execute_unprepared("PRAGMA busy_timeout=30000;").await?;
        }
        let me = Self { db };
        me.migrate_schema().await?;
        Ok(me)
    }

    /// Open a fresh database transaction. Exposed so callers that
    /// need to compose multiple write methods atomically can drive
    /// the txn lifetime themselves — e.g. `workflow learn` admits a
    /// project via [`Self::write_project_completed_txn`] AND then
    /// enqueues its new canonicals via
    /// [`Self::enqueue_pending_canonical_semantics_txn`] in the
    /// SAME transaction, so a kill between the two steps rolls
    /// back the whole thing.
    pub async fn begin(&self) -> Result<DatabaseTransaction> {
        Ok(self.db.begin().await?)
    }

    // ── Schema / init ───────────────────────────────────────────────

    /// One-shot lifecycle setup: create tables, run idempotent
    /// schema migrations, and seed the static taxonomies. The whole
    /// thing runs inside a **single transaction** so a kill mid-init
    /// either leaves the DB completely untouched OR fully set up —
    /// never half-seeded. Without this guard, a partial seed (e.g.
    /// only 2 of 14 DeFi categories inserted before SIGKILL) would
    /// stick because both seed loops short-circuit on `if !existing
    /// .is_empty()`, and `write_project_completed` later silently
    /// drops `project_category` links for missing category names
    /// (db.rs:~2965 just `tracing::warn!` and continues).
    pub async fn init(&self) -> Result<()> {
        let txn = self.db.begin().await?;
        self.create_tables(&txn, true).await?;
        self.migrate_schema_within(&txn).await?;
        self.seed_categories_within(&txn).await?;
        self.seed_finding_categories_within(&txn).await?;
        txn.commit().await?;
        Ok(())
    }

    /// Append one row to `operation_history` recording that a top-level learn
    /// operation (`c4learn` / `link`) ran to completion, tagged with the
    /// non-sensitive arguments it used.
    ///
    /// Idempotent on `(type, args)`: if a row with the same operation type and
    /// byte-identical arguments already exists, this is a no-op. Callers invoke
    /// it ONLY after the operation's real work has committed, so an interrupted
    /// run leaves no `operation_history` row (no dirty data) and re-running the
    /// same command appends no duplicate. The existence check and the insert
    /// share one transaction so a concurrent racer can't slip a duplicate in
    /// between.
    pub async fn record_operation(
        &self,
        operation_type: OperationType,
        args: serde_json::Value,
    ) -> Result<()> {
        let txn = self.db.begin().await?;
        let duplicate = operation_history::Entity::find()
            .filter(operation_history::Column::OperationType.eq(operation_type))
            .all(&txn)
            .await?
            .into_iter()
            .any(|row| row.args == args);
        if duplicate {
            txn.commit().await?;
            return Ok(());
        }
        let recorded_at: sea_orm::prelude::DateTimeUtc = std::time::SystemTime::now().into();
        operation_history::ActiveModel {
            datetime: Set(recorded_at),
            operation_type: Set(operation_type),
            args: Set(args),
            ..Default::default()
        }
        .insert(&txn)
        .await?;
        txn.commit().await?;
        Ok(())
    }

    /// Read-only probe for whether this database already holds the
    /// historical-KG schema. Consumers (`workflow streamloop` /
    /// `autoloop`, `agentic map-semantics`) call this so they can skip
    /// the write-requiring [`Self::init`] when pointed at a
    /// pre-populated DB — including one exposed through a SELECT-only
    /// grant (e.g. a read-only MySQL replica), where the `CREATE TABLE`
    /// / `ALTER TABLE` in `init` would be denied and is unnecessary.
    /// Presence of the `project` table is the marker: every initialized
    /// KG has it, and it's the first table `create_tables` emits.
    pub async fn schema_is_initialized(&self) -> Result<bool> {
        self.table_exists("project").await
    }

    /// Backend-aware existence probe for a single table. Read-only.
    /// Lets lifecycle code tolerate a historical KG that legitimately
    /// dropped a writer-side table — e.g. a read-only v3 consumer DB
    /// with `pending_semantic` removed, where a *missing* queue table
    /// is semantically identical to a *drained* (empty) one.
    async fn table_exists(&self, table: &str) -> Result<bool> {
        let backend = self.db.get_database_backend();
        let sql = match backend {
            DatabaseBackend::MySql => format!(
                "SELECT 1 FROM information_schema.tables \
                 WHERE table_schema = DATABASE() AND table_name = {}",
                sql_string_literal(table)
            ),
            DatabaseBackend::Postgres => format!(
                "SELECT 1 FROM information_schema.tables \
                 WHERE table_schema = current_schema() AND table_name = {}",
                sql_string_literal(table)
            ),
            DatabaseBackend::Sqlite => format!(
                "SELECT 1 FROM sqlite_master \
                 WHERE type = 'table' AND name = {}",
                sql_string_literal(table)
            ),
            // `DatabaseBackend` is `#[non_exhaustive]`; for any future
            // backend we can't introspect, assume the table is present
            // so behaviour is unchanged (the caller's query runs as
            // before).
            _ => return Ok(true),
        };
        let row = self
            .db
            .query_one_raw(Statement::from_string(backend, sql))
            .await?;
        Ok(row.is_some())
    }

    /// Apply every idempotent in-place schema migration this crate
    /// knows about. SQLite-only; no-op on other backends since
    /// production deployments stick to SQLite for the historical KG.
    /// Each individual migration is itself idempotent — calling
    /// `migrate_schema` repeatedly is cheap (a few PRAGMA introspect
    /// queries) and safe.
    pub async fn migrate_schema(&self) -> Result<()> {
        self.migrate_link_strength_columns_within(&self.db).await?;
        Ok(())
    }

    /// Transaction-scoped variant of [`Self::migrate_schema`] used
    /// by [`Self::init`]'s atomic setup. Same migrations, same
    /// idempotence guarantees, but every statement lands inside the
    /// caller's transaction.
    async fn migrate_schema_within<C: ConnectionTrait>(&self, conn: &C) -> Result<()> {
        self.migrate_link_strength_columns_within(conn).await?;
        Ok(())
    }

    async fn create_tables(&self, conn: &impl ConnectionTrait, if_not_exists: bool) -> Result<()> {
        let builder = self.db.get_database_backend();
        let schema = Schema::new(builder);

        let mut semantic_merge_table = schema.create_table_from_entity(semantic_merge::Entity);
        let mut semantic_merge_from_fk = ForeignKey::create();
        semantic_merge_from_fk
            .name("fk-semantic_merge-from_semantic_id")
            .from(
                semantic_merge::Entity,
                semantic_merge::Column::FromSemanticId,
            )
            .to(semantic_node::Entity, semantic_node::Column::Id)
            .on_delete(ForeignKeyAction::Cascade)
            .on_update(ForeignKeyAction::Cascade);
        let mut semantic_merge_to_fk = ForeignKey::create();
        semantic_merge_to_fk
            .name("fk-semantic_merge-to_semantic_id")
            .from(semantic_merge::Entity, semantic_merge::Column::ToSemanticId)
            .to(semantic_node::Entity, semantic_node::Column::Id)
            .on_delete(ForeignKeyAction::Restrict)
            .on_update(ForeignKeyAction::Cascade);
        semantic_merge_table
            .foreign_key(&mut semantic_merge_from_fk)
            .foreign_key(&mut semantic_merge_to_fk);

        let mut finding_merge_table = schema.create_table_from_entity(finding_merge::Entity);
        let mut finding_merge_from_fk = ForeignKey::create();
        finding_merge_from_fk
            .name("fk-finding_merge-from_finding_id")
            .from(finding_merge::Entity, finding_merge::Column::FromFindingId)
            .to(audit_finding::Entity, audit_finding::Column::Id)
            .on_delete(ForeignKeyAction::Cascade)
            .on_update(ForeignKeyAction::Cascade);
        let mut finding_merge_to_fk = ForeignKey::create();
        finding_merge_to_fk
            .name("fk-finding_merge-to_finding_id")
            .from(finding_merge::Entity, finding_merge::Column::ToFindingId)
            .to(audit_finding::Entity, audit_finding::Column::Id)
            .on_delete(ForeignKeyAction::Restrict)
            .on_update(ForeignKeyAction::Cascade);
        finding_merge_table
            .foreign_key(&mut finding_merge_from_fk)
            .foreign_key(&mut finding_merge_to_fk);

        let tables: Vec<TableCreateStatement> = vec![
            schema.create_table_from_entity(project::Entity),
            schema.create_table_from_entity(project_platform::Entity),
            schema.create_table_from_entity(category::Entity),
            schema.create_table_from_entity(project_category::Entity),
            schema.create_table_from_entity(semantic_node::Entity),
            schema.create_table_from_entity(semantic_function::Entity),
            semantic_merge_table,
            schema.create_table_from_entity(audit_finding::Entity),
            schema.create_table_from_entity(finding_category::Entity),
            schema.create_table_from_entity(audit_finding_category::Entity),
            schema.create_table_from_entity(semantic_finding_link::Entity),
            schema.create_table_from_entity(finding_link_status::Entity),
            finding_merge_table,
            // M:N provenance + retro-link tracking introduced by the
            // historical-DB refactor.
            schema.create_table_from_entity(project_semantic::Entity),
            schema.create_table_from_entity(project_finding::Entity),
            schema.create_table_from_entity(knowdit_kg_model::db::pending_semantic::Entity),
            schema.create_table_from_entity(merge_status::Entity),
            // Append-only audit log of top-level learn operations. No FKs —
            // it references nothing and nothing references it.
            schema.create_table_from_entity(operation_history::Entity),
            // Per-chunk extraction progress markers — INSERTed immediately
            // after each chunk's LLM call, outside the merge transaction.
            schema.create_table_from_entity(extraction_chunk::Entity),
        ];

        for mut table in tables {
            if if_not_exists {
                table.if_not_exists();
            }
            conn.execute(&table).await?;
        }

        // sea-query 1.0 doesn't expose `MEDIUMTEXT` as a column type;
        // its `Text` variant maps to MySQL `TEXT` which tops out at
        // 64 KiB. LLM-generated `description` / `patterns` /
        // `exploits` blobs in this schema routinely exceed that, so
        // post-create we widen those specific columns to MEDIUMTEXT
        // (~16 MiB) on MySQL. SQLite/Postgres are unaffected — their
        // `TEXT` is unbounded — and `ALTER ... MODIFY` to a wider
        // type is a no-op on an already-widened column, so this is
        // idempotent across re-runs.
        if self.db.get_database_backend() == DatabaseBackend::MySql {
            for (table, column) in [
                ("semantic_node", "description"),
                ("audit_finding", "description"),
                ("audit_finding", "patterns"),
                ("audit_finding", "exploits"),
            ] {
                conn.execute_unprepared(&format!(
                    "ALTER TABLE `{table}` MODIFY `{column}` MEDIUMTEXT NOT NULL"
                ))
                .await?;
            }
        }

        Ok(())
    }

    pub async fn export_sql_snapshot(&self) -> Result<String> {
        let backend = self.db.get_database_backend();
        let tables = self.snapshot_table_names().await?;
        let mut snapshot = String::new();

        snapshot.push_str("-- knowdit SQL snapshot\n");
        snapshot.push_str(&format!(
            "-- backend: {}\n\n",
            snapshot_backend_name(backend)
        ));

        for table in tables.iter().rev() {
            append_sql_statement(
                &mut snapshot,
                &format!("DROP TABLE IF EXISTS {}", quote_identifier(backend, table)),
            );
        }

        if !tables.is_empty() {
            snapshot.push('\n');
        }

        for table in &tables {
            snapshot.push_str(&format!("-- Schema for {}\n", table));
            let create_sql = self.snapshot_table_create_sql(table).await?;
            append_sql_statement(&mut snapshot, &create_sql);
            snapshot.push('\n');
        }

        for table in &tables {
            let inserts = self.snapshot_table_insert_statements(table).await?;
            if inserts.is_empty() {
                continue;
            }

            snapshot.push_str(&format!("-- Data for {}\n", table));
            for insert in inserts {
                append_sql_statement(&mut snapshot, &insert);
            }
            snapshot.push('\n');
        }

        Ok(snapshot)
    }

    pub async fn export_json_snapshot(&self) -> Result<String> {
        let graph = self.load_knowledge_graph().await?;
        Ok(serde_json::to_string_pretty(&graph)?)
    }

    pub async fn import_sql_snapshot(&self, sql: &str) -> Result<usize> {
        let statements = split_sql_statements(sql);
        let mut executed = 0;

        for statement in statements {
            self.db.execute_unprepared(&statement).await?;
            executed += 1;
        }

        Ok(executed)
    }

    pub async fn import_json_snapshot(&self, json: &str) -> Result<usize> {
        let graph: KnowledgeGraph = serde_json::from_str(json)?;
        self.import_knowledge_graph(&graph).await
    }

    pub async fn import_knowledge_graph(&self, graph: &KnowledgeGraph) -> Result<usize> {
        let existing_tables = self.snapshot_table_names().await?;
        let backend = self.db.get_database_backend();
        let txn = self.db.begin().await?;

        for table in existing_tables.iter().rev() {
            txn.execute_unprepared(&format!(
                "DROP TABLE IF EXISTS {}",
                quote_identifier(backend, table)
            ))
            .await?;
        }

        self.create_tables(&txn, false).await?;

        let mut imported_rows = 0usize;

        if !graph.projects.is_empty() {
            project::Entity::insert_many(
                graph
                    .projects
                    .iter()
                    .cloned()
                    .map(|model| model.into_active_model()),
            )
            .exec(&txn)
            .await?;
            imported_rows += graph.projects.len();
        }

        if !graph.project_platforms.is_empty() {
            project_platform::Entity::insert_many(
                graph
                    .project_platforms
                    .iter()
                    .cloned()
                    .map(|model| model.into_active_model()),
            )
            .exec(&txn)
            .await?;
            imported_rows += graph.project_platforms.len();
        }

        if !graph.categories.is_empty() {
            category::Entity::insert_many(
                graph
                    .categories
                    .iter()
                    .cloned()
                    .map(|model| model.into_active_model()),
            )
            .exec(&txn)
            .await?;
            imported_rows += graph.categories.len();
        }

        if !graph.project_categories.is_empty() {
            project_category::Entity::insert_many(
                graph
                    .project_categories
                    .iter()
                    .cloned()
                    .map(|model| model.into_active_model()),
            )
            .exec(&txn)
            .await?;
            imported_rows += graph.project_categories.len();
        }

        if !graph.nodes.is_empty() {
            semantic_node::Entity::insert_many(
                graph
                    .nodes
                    .iter()
                    .cloned()
                    .map(|model| model.into_active_model()),
            )
            .exec(&txn)
            .await?;
            imported_rows += graph.nodes.len();
        }

        if !graph.semantic_functions.is_empty() {
            semantic_function::Entity::insert_many(
                graph
                    .semantic_functions
                    .iter()
                    .cloned()
                    .map(|model| model.into_active_model()),
            )
            .exec(&txn)
            .await?;
            imported_rows += graph.semantic_functions.len();
        }

        if !graph.semantic_merges.is_empty() {
            semantic_merge::Entity::insert_many(
                graph
                    .semantic_merges
                    .iter()
                    .cloned()
                    .map(|model| model.into_active_model()),
            )
            .exec(&txn)
            .await?;
            imported_rows += graph.semantic_merges.len();
        }

        if !graph.findings.is_empty() {
            audit_finding::Entity::insert_many(
                graph
                    .findings
                    .iter()
                    .cloned()
                    .map(|model| model.into_active_model()),
            )
            .exec(&txn)
            .await?;
            imported_rows += graph.findings.len();
        }

        if !graph.finding_categories.is_empty() {
            finding_category::Entity::insert_many(
                graph
                    .finding_categories
                    .iter()
                    .cloned()
                    .map(|model| model.into_active_model()),
            )
            .exec(&txn)
            .await?;
            imported_rows += graph.finding_categories.len();
        }

        if !graph.audit_finding_categories.is_empty() {
            audit_finding_category::Entity::insert_many(
                graph
                    .audit_finding_categories
                    .iter()
                    .cloned()
                    .map(|model| model.into_active_model()),
            )
            .exec(&txn)
            .await?;
            imported_rows += graph.audit_finding_categories.len();
        }

        if !graph.semantic_finding_links.is_empty() {
            semantic_finding_link::Entity::insert_many(
                graph
                    .semantic_finding_links
                    .iter()
                    .cloned()
                    .map(|model| model.into_active_model()),
            )
            .exec(&txn)
            .await?;
            imported_rows += graph.semantic_finding_links.len();
        }

        if !graph.finding_link_statuses.is_empty() {
            finding_link_status::Entity::insert_many(
                graph
                    .finding_link_statuses
                    .iter()
                    .cloned()
                    .map(|model| model.into_active_model()),
            )
            .exec(&txn)
            .await?;
            imported_rows += graph.finding_link_statuses.len();
        }

        if !graph.finding_merges.is_empty() {
            finding_merge::Entity::insert_many(
                graph
                    .finding_merges
                    .iter()
                    .cloned()
                    .map(|model| model.into_active_model()),
            )
            .exec(&txn)
            .await?;
            imported_rows += graph.finding_merges.len();
        }

        txn.commit().await?;
        Ok(imported_rows)
    }

    /// Drop every table in `dst`, recreate the schema fresh, then
    /// copy every row of every table from `self` into `dst` inside
    /// one destination-side transaction. Source IDs are preserved.
    /// Backend-agnostic: source and destination may be different
    /// SeaORM backends (sqlite ↔ mysql ↔ postgres) because all I/O
    /// goes through the ORM rather than dialect-specific SQL.
    pub async fn clobber_into(&self, dst: &HistoricalDatabase) -> Result<usize> {
        let dst_backend = dst.db.get_database_backend();
        let dst_existing = dst.snapshot_table_names().await?;
        let dst_txn = dst.db.begin().await?;

        for table in dst_existing.iter().rev() {
            dst_txn
                .execute_unprepared(&format!(
                    "DROP TABLE IF EXISTS {}",
                    quote_identifier(dst_backend, table)
                ))
                .await?;
        }
        dst.create_tables(&dst_txn, false).await?;

        let mut copied = 0usize;

        // Sqlite caps bound parameters per statement (default 32766);
        // sea_orm's `insert_many` packs every row into one statement,
        // so we split into row-batches small enough that even the
        // widest table stays comfortably under the cap.
        const BATCH_SIZE: usize = 256;
        macro_rules! copy_table {
            ($entity:path) => {{
                let rows = <$entity>::find().all(&self.db).await?;
                for chunk in rows.chunks(BATCH_SIZE) {
                    if chunk.is_empty() {
                        continue;
                    }
                    <$entity>::insert_many(
                        chunk.iter().cloned().map(|model| model.into_active_model()),
                    )
                    .exec(&dst_txn)
                    .await?;
                    copied += chunk.len();
                }
            }};
        }

        copy_table!(project::Entity);
        copy_table!(project_platform::Entity);
        copy_table!(category::Entity);
        copy_table!(project_category::Entity);
        copy_table!(semantic_node::Entity);
        copy_table!(semantic_function::Entity);
        copy_table!(semantic_merge::Entity);
        copy_table!(audit_finding::Entity);
        copy_table!(finding_category::Entity);
        copy_table!(audit_finding_category::Entity);
        copy_table!(semantic_finding_link::Entity);
        copy_table!(finding_link_status::Entity);
        copy_table!(finding_merge::Entity);
        copy_table!(project_semantic::Entity);
        copy_table!(project_finding::Entity);
        // `pending_semantic` is a writer-side retro-link queue; consumer / v3
        // source DBs legitimately drop it, and a missing table is semantically
        // an empty (drained) queue. Skip the copy instead of erroring so a
        // v3-shaped source can still be snapshotted.
        if self.table_exists("pending_semantic").await? {
            copy_table!(knowdit_kg_model::db::pending_semantic::Entity);
        }

        dst_txn.commit().await?;
        Ok(copied)
    }

    /// Append every row from `self` into `dst` without touching
    /// `dst`'s existing rows. Auto-increment PKs are reassigned on
    /// insert and every FK is rewritten through an in-memory id map
    /// so foreign-key constraints stay intact. Seeded reference
    /// tables (`category`, `finding_category`) are matched on their
    /// natural keys so the dst's `init()`-seeded rows are reused
    /// instead of duplicated. Caller is responsible for ensuring
    /// `dst.init()` has run before this is invoked.
    pub async fn merge_into(&self, dst: &HistoricalDatabase) -> Result<usize> {
        use knowdit_kg_model::db::pending_semantic;
        let txn = dst.db.begin().await?;
        let mut copied = 0usize;

        // category — seeded; match by `name`. Any extra category in
        // src gets inserted with a fresh id.
        let dst_categories = category::Entity::find().all(&txn).await?;
        let mut dst_category_by_name: HashMap<DeFiCategory, i32> =
            dst_categories.into_iter().map(|c| (c.name, c.id)).collect();
        let mut category_id_map: HashMap<i32, i32> = HashMap::new();
        for src_c in category::Entity::find().all(&self.db).await? {
            let new_id = match dst_category_by_name.get(&src_c.name) {
                Some(&id) => id,
                None => {
                    let mut am = src_c.clone().into_active_model();
                    am.id = NotSet;
                    let inserted = am.insert(&txn).await?;
                    copied += 1;
                    dst_category_by_name.insert(inserted.name, inserted.id);
                    inserted.id
                }
            };
            category_id_map.insert(src_c.id, new_id);
        }

        // finding_category — seeded; match by `(category, name)`.
        let dst_finding_categories = finding_category::Entity::find().all(&txn).await?;
        let mut dst_finding_category_by_key: HashMap<(VulnerabilityCategory, String), i32> =
            dst_finding_categories
                .into_iter()
                .map(|c| ((c.category, c.name), c.id))
                .collect();
        let mut finding_category_id_map: HashMap<i32, i32> = HashMap::new();
        for src_fc in finding_category::Entity::find().all(&self.db).await? {
            let key = (src_fc.category, src_fc.name.clone());
            let new_id = match dst_finding_category_by_key.get(&key) {
                Some(&id) => id,
                None => {
                    let mut am = src_fc.clone().into_active_model();
                    am.id = NotSet;
                    let inserted = am.insert(&txn).await?;
                    copied += 1;
                    dst_finding_category_by_key
                        .insert((inserted.category, inserted.name.clone()), inserted.id);
                    inserted.id
                }
            };
            finding_category_id_map.insert(src_fc.id, new_id);
        }

        // project — always insert fresh; the historical KG has no
        // unique constraint on project.name and intentionally
        // tolerates the same project name landing twice from
        // independent sources.
        let mut project_id_map: HashMap<i32, i32> = HashMap::new();
        for src_p in project::Entity::find().all(&self.db).await? {
            let src_id = src_p.id;
            let mut am = src_p.into_active_model();
            am.id = NotSet;
            let inserted = am.insert(&txn).await?;
            copied += 1;
            project_id_map.insert(src_id, inserted.id);
        }

        // semantic_node — same: always insert fresh, build id map.
        let mut semantic_node_id_map: HashMap<i32, i32> = HashMap::new();
        for src_sn in semantic_node::Entity::find().all(&self.db).await? {
            let src_id = src_sn.id;
            let mut am = src_sn.into_active_model();
            am.id = NotSet;
            let inserted = am.insert(&txn).await?;
            copied += 1;
            semantic_node_id_map.insert(src_id, inserted.id);
        }

        // audit_finding — same.
        let mut audit_finding_id_map: HashMap<i32, i32> = HashMap::new();
        for src_af in audit_finding::Entity::find().all(&self.db).await? {
            let src_id = src_af.id;
            let mut am = src_af.into_active_model();
            am.id = NotSet;
            let inserted = am.insert(&txn).await?;
            copied += 1;
            audit_finding_id_map.insert(src_id, inserted.id);
        }

        let remap = |map: &HashMap<i32, i32>, src_id: i32, table: &'static str| -> Result<i32> {
            map.get(&src_id).copied().ok_or_else(|| {
                KgError::other(format!(
                    "merge_into: src {} id {} has no dst mapping",
                    table, src_id
                ))
            })
        };

        // semantic_function: belongs_to semantic_node, has its own
        // auto-incr id (which we drop — the row has no inbound FKs).
        for src_sf in semantic_function::Entity::find().all(&self.db).await? {
            let new_sn_id = remap(
                &semantic_node_id_map,
                src_sf.semantic_node_id,
                "semantic_node",
            )?;
            let mut am = src_sf.into_active_model();
            am.id = NotSet;
            am.semantic_node_id = Set(new_sn_id);
            am.insert(&txn).await?;
            copied += 1;
        }

        // project_platform: belongs_to project; has its own auto-incr
        // id plus a unique constraint on project_id (so no two src
        // rows can collide here — and dst projects are fresh inserts,
        // so the unique constraint is trivially satisfied).
        for src_pp in project_platform::Entity::find().all(&self.db).await? {
            let new_project_id = remap(&project_id_map, src_pp.project_id, "project")?;
            let mut am = src_pp.into_active_model();
            am.id = NotSet;
            am.project_id = Set(new_project_id);
            am.insert(&txn).await?;
            copied += 1;
        }

        // The remaining tables are pure join rows (composite PK,
        // no auto-incr) — remap both FKs and insert.
        for src_pc in project_category::Entity::find().all(&self.db).await? {
            let new_project_id = remap(&project_id_map, src_pc.project_id, "project")?;
            let new_category_id = remap(&category_id_map, src_pc.category_id, "category")?;
            let mut am = src_pc.into_active_model();
            am.project_id = Set(new_project_id);
            am.category_id = Set(new_category_id);
            am.insert(&txn).await?;
            copied += 1;
        }

        for src_ps in project_semantic::Entity::find().all(&self.db).await? {
            let new_project_id = remap(&project_id_map, src_ps.project_id, "project")?;
            let new_sn_id = remap(
                &semantic_node_id_map,
                src_ps.semantic_node_id,
                "semantic_node",
            )?;
            let mut am = src_ps.into_active_model();
            am.project_id = Set(new_project_id);
            am.semantic_node_id = Set(new_sn_id);
            am.insert(&txn).await?;
            copied += 1;
        }

        for src_pf in project_finding::Entity::find().all(&self.db).await? {
            let new_project_id = remap(&project_id_map, src_pf.project_id, "project")?;
            let new_af_id = remap(
                &audit_finding_id_map,
                src_pf.audit_finding_id,
                "audit_finding",
            )?;
            let mut am = src_pf.into_active_model();
            am.project_id = Set(new_project_id);
            am.audit_finding_id = Set(new_af_id);
            am.insert(&txn).await?;
            copied += 1;
        }

        for src_afc in audit_finding_category::Entity::find().all(&self.db).await? {
            let new_af_id = remap(
                &audit_finding_id_map,
                src_afc.audit_finding_id,
                "audit_finding",
            )?;
            let new_fc_id = remap(
                &finding_category_id_map,
                src_afc.finding_category_id,
                "finding_category",
            )?;
            let mut am = src_afc.into_active_model();
            am.audit_finding_id = Set(new_af_id);
            am.finding_category_id = Set(new_fc_id);
            am.insert(&txn).await?;
            copied += 1;
        }

        for src_sfl in semantic_finding_link::Entity::find().all(&self.db).await? {
            let new_sn_id = remap(
                &semantic_node_id_map,
                src_sfl.semantic_node_id,
                "semantic_node",
            )?;
            let new_af_id = remap(
                &audit_finding_id_map,
                src_sfl.audit_finding_id,
                "audit_finding",
            )?;
            let mut am = src_sfl.into_active_model();
            am.semantic_node_id = Set(new_sn_id);
            am.audit_finding_id = Set(new_af_id);
            am.insert(&txn).await?;
            copied += 1;
        }

        for src_fls in finding_link_status::Entity::find().all(&self.db).await? {
            let new_af_id = remap(
                &audit_finding_id_map,
                src_fls.audit_finding_id,
                "audit_finding",
            )?;
            let mut am = src_fls.into_active_model();
            am.audit_finding_id = Set(new_af_id);
            am.insert(&txn).await?;
            copied += 1;
        }

        for src_sm in semantic_merge::Entity::find().all(&self.db).await? {
            let new_from = remap(
                &semantic_node_id_map,
                src_sm.from_semantic_id,
                "semantic_node",
            )?;
            let new_to = remap(
                &semantic_node_id_map,
                src_sm.to_semantic_id,
                "semantic_node",
            )?;
            let mut am = src_sm.into_active_model();
            am.from_semantic_id = Set(new_from);
            am.to_semantic_id = Set(new_to);
            am.insert(&txn).await?;
            copied += 1;
        }

        for src_fm in finding_merge::Entity::find().all(&self.db).await? {
            let new_from = remap(
                &audit_finding_id_map,
                src_fm.from_finding_id,
                "audit_finding",
            )?;
            let new_to = remap(&audit_finding_id_map, src_fm.to_finding_id, "audit_finding")?;
            let mut am = src_fm.into_active_model();
            am.from_finding_id = Set(new_from);
            am.to_finding_id = Set(new_to);
            am.insert(&txn).await?;
            copied += 1;
        }

        for src_psn in pending_semantic::Entity::find().all(&self.db).await? {
            let new_sn_id = remap(
                &semantic_node_id_map,
                src_psn.semantic_node_id,
                "semantic_node",
            )?;
            let mut am = src_psn.into_active_model();
            am.semantic_node_id = Set(new_sn_id);
            am.insert(&txn).await?;
            copied += 1;
        }

        txn.commit().await?;
        Ok(copied)
    }

    async fn snapshot_table_names(&self) -> Result<Vec<String>> {
        let backend = self.db.get_database_backend();
        let sql = match backend {
            DatabaseBackend::MySql => {
                "SELECT table_name FROM information_schema.tables WHERE table_schema = DATABASE() AND table_type = 'BASE TABLE' ORDER BY table_name"
            }
            DatabaseBackend::Sqlite => {
                "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
            }
            other => {
                return Err(KgError::other(format!(
                    "SQL snapshot export is not implemented for backend {other:?}"
                )));
            }
        };

        let mut tables = self.query_string_column(sql.to_string()).await?;
        tables.sort_by(|lhs, rhs| {
            snapshot_table_rank(lhs)
                .cmp(&snapshot_table_rank(rhs))
                .then_with(|| lhs.cmp(rhs))
        });
        Ok(tables)
    }

    async fn snapshot_table_create_sql(&self, table: &str) -> Result<String> {
        match self.db.get_database_backend() {
            DatabaseBackend::MySql => {
                let query = format!(
                    "SHOW CREATE TABLE {}",
                    quote_identifier(DatabaseBackend::MySql, table)
                );
                let row = self
                    .db
                    .query_one_raw(Statement::from_string(DatabaseBackend::MySql, query))
                    .await?
                    .ok_or_else(|| {
                        KgError::other(format!(
                            "table {table} disappeared while building SQL snapshot"
                        ))
                    })?;
                Ok(row.try_get_by_index(1)?)
            }
            DatabaseBackend::Sqlite => {
                let query = format!(
                    "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = {}",
                    sql_string_literal(table)
                );
                let row = self
                    .db
                    .query_one_raw(Statement::from_string(DatabaseBackend::Sqlite, query))
                    .await?
                    .ok_or_else(|| {
                        KgError::other(format!(
                            "table {table} disappeared while building SQL snapshot"
                        ))
                    })?;
                Ok(row.try_get_by_index(0)?)
            }
            other => Err(KgError::other(format!(
                "SQL snapshot export is not implemented for backend {other:?}"
            ))),
        }
    }

    async fn snapshot_table_insert_statements(&self, table: &str) -> Result<Vec<String>> {
        match self.db.get_database_backend() {
            DatabaseBackend::MySql => self.mysql_snapshot_table_insert_statements(table).await,
            DatabaseBackend::Sqlite => self.sqlite_snapshot_table_insert_statements(table).await,
            other => Err(KgError::other(format!(
                "SQL snapshot export is not implemented for backend {other:?}"
            ))),
        }
    }

    async fn sqlite_snapshot_table_insert_statements(&self, table: &str) -> Result<Vec<String>> {
        let columns = self.sqlite_snapshot_columns(table).await?;
        if columns.is_empty() {
            return Ok(Vec::new());
        }

        let table_name = quote_identifier(DatabaseBackend::Sqlite, table);
        let column_list = columns
            .iter()
            .map(|column| quote_identifier(DatabaseBackend::Sqlite, column))
            .join(", ");
        let value_expr = columns
            .iter()
            .map(|column| {
                format!(
                    "quote({})",
                    quote_identifier(DatabaseBackend::Sqlite, column)
                )
            })
            .join(" || ',' || ");
        let query = format!(
            "SELECT {} || {} || {} AS stmt FROM {}",
            sql_string_literal(&format!(
                "INSERT INTO {} ({}) VALUES (",
                table_name, column_list
            )),
            value_expr,
            sql_string_literal(");"),
            table_name,
        );

        self.query_string_column(query).await
    }

    async fn mysql_snapshot_table_insert_statements(&self, table: &str) -> Result<Vec<String>> {
        let columns = self.mysql_snapshot_columns(table).await?;
        if columns.is_empty() {
            return Ok(Vec::new());
        }

        let table_name = quote_identifier(DatabaseBackend::MySql, table);
        let column_list = columns
            .iter()
            .map(|(column, _)| quote_identifier(DatabaseBackend::MySql, column))
            .join(", ");
        let mut concat_args = vec![sql_string_literal(&format!(
            "INSERT INTO {} ({}) VALUES (",
            table_name, column_list
        ))];

        for (index, (column, data_type)) in columns.iter().enumerate() {
            if index > 0 {
                concat_args.push(sql_string_literal(","));
            }
            concat_args.push(mysql_dump_value_expr(column, data_type));
        }

        concat_args.push(sql_string_literal(");"));

        let query = format!(
            "SELECT CONCAT({}) AS stmt FROM {}",
            concat_args.join(", "),
            table_name,
        );

        self.query_string_column(query).await
    }

    async fn sqlite_snapshot_columns(&self, table: &str) -> Result<Vec<String>> {
        let query = format!(
            "SELECT name FROM pragma_table_info({}) ORDER BY cid",
            sql_string_literal(table)
        );
        self.query_string_column(query).await
    }

    async fn mysql_snapshot_columns(&self, table: &str) -> Result<Vec<(String, String)>> {
        let query = format!(
            "SELECT column_name, data_type FROM information_schema.columns WHERE table_schema = DATABASE() AND table_name = {} ORDER BY ordinal_position",
            sql_string_literal(table)
        );
        let rows = self
            .db
            .query_all_raw(Statement::from_string(DatabaseBackend::MySql, query))
            .await?;
        let mut columns = Vec::with_capacity(rows.len());

        for row in rows {
            columns.push((row.try_get_by_index(0)?, row.try_get_by_index(1)?));
        }

        Ok(columns)
    }

    async fn query_string_column(&self, sql: String) -> Result<Vec<String>> {
        let backend = self.db.get_database_backend();
        let rows = self
            .db
            .query_all_raw(Statement::from_string(backend, sql))
            .await?;
        let mut values = Vec::with_capacity(rows.len());

        for row in rows {
            values.push(row.try_get_by_index(0)?);
        }

        Ok(values)
    }

    /// Transaction-scoped seed used by [`Self::init`]. Atomicity
    /// matters: a kill mid-loop on the standalone variant would
    /// leave a partial taxonomy that the `if !existing.is_empty()`
    /// gate then refuses to re-seed, so the table is permanently
    /// short of rows. Inside the init transaction, mid-seed kill
    /// rolls back to zero rows — next run seeds from scratch.
    async fn seed_categories_within<C: ConnectionTrait>(&self, conn: &C) -> Result<()> {
        use crate::category::DeFiCategory;

        let existing = category::Entity::find().all(conn).await?;
        if !existing.is_empty() {
            return Ok(());
        }

        for cat in DeFiCategory::ALL {
            let am = category::ActiveModel {
                name: Set(*cat),
                ..Default::default()
            };
            category::Entity::insert(am).exec(conn).await?;
        }

        tracing::info!("Seeded {} DeFi categories", DeFiCategory::ALL.len());
        Ok(())
    }

    async fn seed_finding_categories_within<C: ConnectionTrait>(&self, conn: &C) -> Result<()> {
        let existing = finding_category::Entity::find().all(conn).await?;
        if !existing.is_empty() {
            return Ok(());
        }

        for entry in FINDING_TAXONOMY {
            let am = finding_category::ActiveModel {
                category: Set(entry.category),
                name: Set(entry.subcategory.to_string()),
                description: Set(entry.description.to_string()),
                ..Default::default()
            };
            finding_category::Entity::insert(am).exec(conn).await?;
        }

        tracing::info!(
            "Seeded {} vulnerability subcategories",
            FINDING_TAXONOMY.len()
        );
        Ok(())
    }

    // ── Project lookups ────────────────────────────────────────────

    /// Find a project by its platform ID (e.g. "c4-420").
    pub async fn get_project_by_platform_id(
        &self,
        platform_id: &str,
    ) -> Result<Option<project::Model>> {
        let pp = project_platform::Entity::find()
            .filter(project_platform::Column::PlatformId.eq(platform_id))
            .one(&self.db)
            .await?;
        if let Some(pp) = pp {
            Ok(project::Entity::find_by_id(pp.project_id)
                .one(&self.db)
                .await?)
        } else {
            Ok(None)
        }
    }

    pub async fn get_project_by_name(&self, name: &str) -> Result<Option<project::Model>> {
        Ok(project::Entity::find()
            .filter(project::Column::Name.eq(name))
            .one(&self.db)
            .await?)
    }

    pub async fn get_project_by_id(&self, id: i32) -> Result<Option<project::Model>> {
        Ok(project::Entity::find_by_id(id).one(&self.db).await?)
    }

    /// Check if a project with this platform_id is already completed.
    pub async fn is_project_completed(&self, platform_id: &str) -> Result<bool> {
        Ok(self
            .get_project_by_platform_id(platform_id)
            .await?
            .map(|p| p.status == "completed")
            .unwrap_or(false))
    }

    // ── Extraction Chunk Checkpointing ──────────────────────────────────

    /// Count completed extraction chunks for a (project_key, stage) pair.
    pub async fn count_extraction_chunks(
        &self,
        project_key: &str,
        stage: &str,
    ) -> Result<usize> {
        let count = extraction_chunk::Entity::find()
            .filter(extraction_chunk::Column::ProjectKey.eq(project_key))
            .filter(extraction_chunk::Column::Stage.eq(stage))
            .count(&self.db)
            .await?;
        Ok(count as usize)
    }

    /// Check whether a (project_key, stage) pair's first chunk was saved
    /// with the given model+hash. Returns true if the stage is empty (no
    /// rows yet — fresh start), or if the first chunk's stored values match.
    /// Returns false if there's a mismatch, meaning the caller should
    /// invalidate and restart.
    pub async fn extraction_chunks_match(
        &self,
        project_key: &str,
        stage: &str,
        model: &str,
        content_hash: &str,
    ) -> Result<bool> {
        let Some(first) = extraction_chunk::Entity::find()
            .filter(extraction_chunk::Column::ProjectKey.eq(project_key))
            .filter(extraction_chunk::Column::Stage.eq(stage))
            .order_by_asc(extraction_chunk::Column::ChunkIdx)
            .one(&self.db)
            .await?
        else {
            return Ok(true); // empty -> fresh start
        };
        Ok(first.model == model && first.content_hash == content_hash)
    }

    /// Delete all extraction chunk rows for (project_key, stage) —
    /// invalidates stale state after model or source change.
    pub async fn clear_extraction_chunks(
        &self,
        project_key: &str,
        stage: &str,
    ) -> Result<()> {
        extraction_chunk::Entity::delete_many()
            .filter(extraction_chunk::Column::ProjectKey.eq(project_key))
            .filter(extraction_chunk::Column::Stage.eq(stage))
            .exec(&self.db)
            .await?;
        Ok(())
    }

    /// Persist one completed extraction chunk. Committed independently of
    /// the merge transaction so a crash between chunks preserves progress.
    pub async fn save_extraction_chunk(
        &self,
        project_key: &str,
        stage: &str,
        chunk_idx: i32,
        model: &str,
        content_hash: &str,
        chunk_json: &str,
    ) -> Result<()> {
        extraction_chunk::Entity::insert(extraction_chunk::ActiveModel {
            project_key: Set(project_key.to_string()),
            stage: Set(stage.to_string()),
            chunk_idx: Set(chunk_idx),
            model: Set(model.to_string()),
            content_hash: Set(content_hash.to_string()),
            chunk_json: Set(chunk_json.to_string()),
            ..Default::default()
        })
        .exec(&self.db)
        .await?;
        Ok(())
    }

    /// Delete all extraction chunk rows for a project — call after a
    /// successful merge+write so stale chunks don't persist.
    pub async fn clear_extraction_chunks_for_project(
        &self,
        project_key: &str,
    ) -> Result<()> {
        extraction_chunk::Entity::delete_many()
            .filter(extraction_chunk::Column::ProjectKey.eq(project_key))
            .exec(&self.db)
            .await?;
        Ok(())
    }

    /// Load all completed extraction chunks for (project_key, stage),
    /// ordered by chunk_idx. Returns empty vec if none exist.
    pub async fn load_extraction_chunks(
        &self,
        project_key: &str,
        stage: &str,
    ) -> Result<Vec<extraction_chunk::Model>> {
        Ok(extraction_chunk::Entity::find()
            .filter(extraction_chunk::Column::ProjectKey.eq(project_key))
            .filter(extraction_chunk::Column::Stage.eq(stage))
            .order_by_asc(extraction_chunk::Column::ChunkIdx)
            .all(&self.db)
            .await?)
    }

    // ────────────────────────────────────────────────────────────────────

    /// Get the platform info for a project.
    pub async fn get_project_platform(
        &self,
        project_id: i32,
    ) -> Result<Option<project_platform::Model>> {
        Ok(project_platform::Entity::find()
            .filter(project_platform::Column::ProjectId.eq(project_id))
            .one(&self.db)
            .await?)
    }

    /// Set or update the platform ID for a project.
    pub async fn set_platform_id(&self, project_id: i32, platform_id: &str) -> Result<()> {
        use sea_orm::IntoActiveModel;
        let existing = project_platform::Entity::find()
            .filter(project_platform::Column::ProjectId.eq(project_id))
            .one(&self.db)
            .await?;
        if let Some(existing) = existing {
            let mut am = existing.into_active_model();
            am.platform_id = Set(platform_id.to_string());
            am.update(&self.db).await?;
        } else {
            let am = project_platform::ActiveModel {
                project_id: Set(project_id),
                platform_id: Set(platform_id.to_string()),
                ..Default::default()
            };
            project_platform::Entity::insert(am).exec(&self.db).await?;
        }
        Ok(())
    }

    // ── Read queries ────────────────────────────────────────────────

    pub async fn list_completed_projects(
        &self,
    ) -> Result<Vec<(project::Model, Option<project_platform::Model>)>> {
        let projects = project::Entity::find()
            .filter(project::Column::Status.eq("completed"))
            .all(&self.db)
            .await?;
        let mut results = Vec::new();
        for p in projects {
            let pp = project_platform::Entity::find()
                .filter(project_platform::Column::ProjectId.eq(p.id))
                .one(&self.db)
                .await?;
            results.push((p, pp));
        }
        Ok(results)
    }

    pub async fn list_semantics_by_project(
        &self,
        project_id: i32,
    ) -> Result<Vec<(semantic_node::Model, Vec<semantic_function::Model>)>> {
        // Project provenance lives in `project_semantic` since the refactor.
        // Note: a single project may attach to multiple semantic nodes
        // (canonical or merged-away — the LLM merge step doesn't strip these
        // out of the join table when it folds raw nodes).
        let semantic_ids: Vec<i32> = project_semantic::Entity::find()
            .filter(project_semantic::Column::ProjectId.eq(project_id))
            .all(&self.db)
            .await?
            .into_iter()
            .map(|row| row.semantic_node_id)
            .collect();
        if semantic_ids.is_empty() {
            return Ok(Vec::new());
        }
        let nodes = semantic_node::Entity::find()
            .filter(semantic_node::Column::Id.is_in(semantic_ids))
            .all(&self.db)
            .await?;

        let mut results = Vec::new();
        for node in nodes {
            let funcs = semantic_function::Entity::find()
                .filter(semantic_function::Column::SemanticNodeId.eq(node.id))
                .all(&self.db)
                .await?;
            results.push((node, funcs));
        }

        Ok(results)
    }

    pub async fn search_semantics(
        &self,
        query: &str,
    ) -> Result<Vec<(semantic_node::Model, String)>> {
        let nodes = semantic_node::Entity::find()
            .filter(
                sea_orm::Condition::any()
                    .add(semantic_node::Column::Name.contains(query))
                    .add(semantic_node::Column::Definition.contains(query))
                    .add(semantic_node::Column::Description.contains(query)),
            )
            .all(&self.db)
            .await?;

        // Project provenance is many-to-many now, so a node may originate
        // from multiple historical projects; we surface the lexicographically
        // earliest project name as the display label and "+N" if there are
        // more contributors.
        let mut results = Vec::new();
        for node in nodes {
            let project_ids: Vec<i32> = project_semantic::Entity::find()
                .filter(project_semantic::Column::SemanticNodeId.eq(node.id))
                .all(&self.db)
                .await?
                .into_iter()
                .map(|row| row.project_id)
                .collect();
            let label = if project_ids.is_empty() {
                "unknown".to_string()
            } else {
                let mut names: Vec<String> = project::Entity::find()
                    .filter(project::Column::Id.is_in(project_ids.clone()))
                    .all(&self.db)
                    .await?
                    .into_iter()
                    .map(|p| p.name)
                    .collect();
                names.sort();
                let primary = names
                    .first()
                    .cloned()
                    .unwrap_or_else(|| "unknown".to_string());
                if names.len() > 1 {
                    format!("{} +{}", primary, names.len() - 1)
                } else {
                    primary
                }
            };
            results.push((node, label));
        }

        Ok(results)
    }

    /// Fetch existing canonical semantic nodes (= survivors of any merge)
    /// for the given categories, paired with the raw children that have
    /// been merged into each canonical. The merge orchestrator renders
    /// each canonical with its children so the LLM's `updated_*`
    /// generalisations can take prior merges into account.
    pub async fn canonical_semantics_with_children_for_categories(
        &self,
        categories: &[crate::category::DeFiCategory],
    ) -> Result<Vec<crate::agents::CanonicalWithChildren<semantic_node::Model>>> {
        let canonicals = self.existing_semantics_for_categories(categories).await?;
        if canonicals.is_empty() {
            return Ok(Vec::new());
        }
        let canonical_ids: Vec<i32> = canonicals.iter().map(|n| n.id).collect();
        let merge_rows = semantic_merge::Entity::find()
            .filter(semantic_merge::Column::ToSemanticId.is_in(canonical_ids.clone()))
            .all(&self.db)
            .await?;
        let raw_ids: Vec<i32> = merge_rows.iter().map(|m| m.from_semantic_id).collect();
        let raws = if raw_ids.is_empty() {
            Vec::new()
        } else {
            semantic_node::Entity::find()
                .filter(semantic_node::Column::Id.is_in(raw_ids))
                .all(&self.db)
                .await?
        };
        let raws_by_id: HashMap<i32, semantic_node::Model> =
            raws.into_iter().map(|n| (n.id, n)).collect();
        let mut children_by_canonical: HashMap<i32, Vec<semantic_node::Model>> = HashMap::new();
        for row in merge_rows {
            if let Some(raw) = raws_by_id.get(&row.from_semantic_id) {
                children_by_canonical
                    .entry(row.to_semantic_id)
                    .or_default()
                    .push(raw.clone());
            }
        }
        Ok(canonicals
            .into_iter()
            .map(|c| {
                let raw_children = children_by_canonical.remove(&c.id).unwrap_or_default();
                crate::agents::CanonicalWithChildren {
                    canonical: c,
                    raw_children,
                }
            })
            .collect())
    }

    /// Fetch existing active semantic nodes for the given categories.
    /// Returns nodes that have NOT been merged away.
    pub async fn existing_semantics_for_categories(
        &self,
        categories: &[crate::category::DeFiCategory],
    ) -> Result<Vec<semantic_node::Model>> {
        let existing_node_ids: Vec<i32> = semantic_node::Entity::find()
            .filter(semantic_node::Column::Category.is_in(categories.iter().copied()))
            .all(&self.db)
            .await?
            .iter()
            .map(|node| node.id)
            .unique()
            .collect();

        let merged_away: Vec<i32> = if !existing_node_ids.is_empty() {
            semantic_merge::Entity::find()
                .filter(semantic_merge::Column::FromSemanticId.is_in(existing_node_ids.clone()))
                .all(&self.db)
                .await?
                .into_iter()
                .map(|m| m.from_semantic_id)
                .collect()
        } else {
            vec![]
        };

        let active_node_ids: Vec<i32> = existing_node_ids
            .into_iter()
            .filter(|id| !merged_away.contains(id))
            .collect();

        let nodes = if !active_node_ids.is_empty() {
            semantic_node::Entity::find()
                .filter(semantic_node::Column::Id.is_in(active_node_ids))
                .all(&self.db)
                .await?
        } else {
            vec![]
        };

        Ok(nodes)
    }

    /// Fetch every finding linked to any of `semantic_ids` via
    /// `semantic_finding_link`. Returns `(semantic_node_id, finding_model)` pairs;
    /// the same finding may appear multiple times if it is linked to multiple
    /// semantics in the input set.
    /// Findings linked to any of the given semantic ids OR to any raw
    /// (merged-away) semantic that resolves to one of those ids.
    ///
    /// Each returned tuple uses the *canonical* semantic id (one of the
    /// inputs) as the first element regardless of whether the link's source
    /// row was on the canonical or on a raw child. This lets callers reason
    /// about findings against the canonical they matched on without having
    /// to handle merge chains themselves.
    pub async fn findings_for_semantic_ids(
        &self,
        semantic_ids: &[i32],
    ) -> Result<Vec<LinkedFinding>> {
        if semantic_ids.is_empty() {
            return Ok(Vec::new());
        }

        // Chase merge children: any row in semantic_merge where the
        // canonical (to_semantic_id) is one of the requested ids contributes
        // its raw (from_semantic_id) to the search set, and we record a
        // raw → canonical mapping so the returned tuple stays canonical.
        let merge_rows = semantic_merge::Entity::find()
            .filter(semantic_merge::Column::ToSemanticId.is_in(semantic_ids.iter().copied()))
            .all(&self.db)
            .await?;

        let mut canonical_for_id: HashMap<i32, i32> = HashMap::new();
        let mut search_ids: HashSet<i32> = semantic_ids.iter().copied().collect();
        for row in &merge_rows {
            search_ids.insert(row.from_semantic_id);
            canonical_for_id.insert(row.from_semantic_id, row.to_semantic_id);
        }
        // Identity mapping for the canonical inputs themselves.
        for id in semantic_ids {
            canonical_for_id.insert(*id, *id);
        }

        // Partial-link safety is handled at the consumer's entry
        // point (`HistoricalDatabaseArgs::connect_init_for_consumer`
        // refuses to open a partial DB unless the operator opts in
        // via `--force-allow-partial-historical`). By the time this
        // query runs, the caller has either confirmed the DB is
        // fully linked or explicitly accepted the risk — no
        // additional silent filtering here.
        let links = semantic_finding_link::Entity::find()
            .filter(semantic_finding_link::Column::SemanticNodeId.is_in(search_ids.iter().copied()))
            .all(&self.db)
            .await?;

        if links.is_empty() {
            return Ok(Vec::new());
        }

        let finding_ids: Vec<i32> = links.iter().map(|l| l.audit_finding_id).unique().collect();

        let findings = audit_finding::Entity::find()
            .filter(audit_finding::Column::Id.is_in(finding_ids))
            .all(&self.db)
            .await?;
        let findings_by_id: HashMap<i32, audit_finding::Model> =
            findings.into_iter().map(|f| (f.id, f)).collect();

        let mut out = Vec::with_capacity(links.len());
        for link in links {
            let canonical_id = canonical_for_id
                .get(&link.semantic_node_id)
                .copied()
                .unwrap_or(link.semantic_node_id);
            if let Some(finding) = findings_by_id.get(&link.audit_finding_id) {
                out.push(LinkedFinding {
                    canonical_semantic_id: canonical_id,
                    finding: finding.clone(),
                    strength: link.strength,
                    evidence: link.evidence,
                });
            }
        }
        // De-duplicate (canonical_id, finding_id) pairs so callers don't see
        // the same finding twice when both raw and canonical happen to be
        // linked to it. When duplicates exist, keep the strongest row.
        out.sort_by(|a, b| {
            (a.canonical_semantic_id, a.finding.id)
                .cmp(&(b.canonical_semantic_id, b.finding.id))
                .then(b.strength.rank().cmp(&a.strength.rank()))
        });
        out.dedup_by(|a, b| {
            a.canonical_semantic_id == b.canonical_semantic_id && a.finding.id == b.finding.id
        });
        Ok(out)
    }

    pub async fn semantic_link_candidates_for_categories(
        &self,
        categories: &[crate::category::DeFiCategory],
    ) -> Result<Vec<(semantic_node::Model, i32)>> {
        if categories.is_empty() {
            return Ok(Vec::new());
        }

        let category_nodes = semantic_node::Entity::find()
            .filter(semantic_node::Column::Category.is_in(categories.iter().copied()))
            .all(&self.db)
            .await?;

        if category_nodes.is_empty() {
            return Ok(Vec::new());
        }

        let merge_map = build_merge_map(
            semantic_merge::Entity::find()
                .all(&self.db)
                .await?
                .into_iter()
                .map(|merge| (merge.from_semantic_id, merge.to_semantic_id)),
        );

        let mut nodes_by_id: HashMap<i32, semantic_node::Model> = category_nodes
            .into_iter()
            .map(|node| (node.id, node))
            .collect();
        let existing_node_ids: HashSet<i32> = nodes_by_id.keys().copied().collect();
        let missing_canonical_ids: Vec<i32> = nodes_by_id
            .values()
            .map(|node| resolve_merge_target(node.id, &merge_map))
            .filter(|canonical_id| !existing_node_ids.contains(canonical_id))
            .unique()
            .collect();

        if !missing_canonical_ids.is_empty() {
            let canonical_nodes = semantic_node::Entity::find()
                .filter(semantic_node::Column::Id.is_in(missing_canonical_ids.clone()))
                .all(&self.db)
                .await?;
            let found_canonical_ids: HashSet<i32> =
                canonical_nodes.iter().map(|node| node.id).collect();
            let unresolved_canonical_ids: Vec<i32> = missing_canonical_ids
                .into_iter()
                .filter(|canonical_id| !found_canonical_ids.contains(canonical_id))
                .collect();
            if !unresolved_canonical_ids.is_empty() {
                tracing::warn!(
                    "Ignoring dangling semantic merge target(s) while preparing finding-link candidates: {}",
                    unresolved_canonical_ids
                        .into_iter()
                        .map(|id| format!("sem-{}", id))
                        .join(", ")
                );
            }

            nodes_by_id.extend(canonical_nodes.into_iter().map(|node| (node.id, node)));
        }

        materialize_semantic_link_candidates(nodes_by_id.into_values().collect(), &merge_map)
    }

    /// All canonical semantics across every category, with merged-away aliases
    /// excluded. Linking is one-time, so this is the single candidate set we
    /// present to the LLM regardless of the pending finding's project category.
    /// For each canonical semantic id, the raw children folded into it paired
    /// with their merge-edge `appended_description` note. Used by the mapper to
    /// mirror children + edges into a project DB.
    pub async fn semantic_children_with_notes(
        &self,
        canonical_ids: &[i32],
    ) -> Result<HashMap<i32, Vec<(semantic_node::Model, String)>>> {
        if canonical_ids.is_empty() {
            return Ok(HashMap::new());
        }
        let edges = semantic_merge::Entity::find()
            .filter(semantic_merge::Column::ToSemanticId.is_in(canonical_ids.to_vec()))
            .all(&self.db)
            .await?;
        let child_ids: HashSet<i32> = edges.iter().map(|e| e.from_semantic_id).collect();
        let children: HashMap<i32, semantic_node::Model> = semantic_node::Entity::find()
            .filter(semantic_node::Column::Id.is_in(child_ids.into_iter().collect::<Vec<_>>()))
            .all(&self.db)
            .await?
            .into_iter()
            .map(|n| (n.id, n))
            .collect();
        let mut out: HashMap<i32, Vec<(semantic_node::Model, String)>> = HashMap::new();
        for e in edges {
            if let Some(child) = children.get(&e.from_semantic_id) {
                out.entry(e.to_semantic_id)
                    .or_default()
                    .push((child.clone(), e.appended_description));
            }
        }
        Ok(out)
    }

    /// For each canonical finding id, the raw children folded into it paired
    /// with their three merge-edge `appended_*` notes.
    pub async fn finding_children_with_notes(
        &self,
        canonical_ids: &[i32],
    ) -> Result<HashMap<i32, Vec<(audit_finding::Model, String, String, String)>>> {
        if canonical_ids.is_empty() {
            return Ok(HashMap::new());
        }
        let edges = finding_merge::Entity::find()
            .filter(finding_merge::Column::ToFindingId.is_in(canonical_ids.to_vec()))
            .all(&self.db)
            .await?;
        let child_ids: HashSet<i32> = edges.iter().map(|e| e.from_finding_id).collect();
        let children: HashMap<i32, audit_finding::Model> = audit_finding::Entity::find()
            .filter(audit_finding::Column::Id.is_in(child_ids.into_iter().collect::<Vec<_>>()))
            .all(&self.db)
            .await?
            .into_iter()
            .map(|f| (f.id, f))
            .collect();
        let mut out: HashMap<i32, Vec<(audit_finding::Model, String, String, String)>> =
            HashMap::new();
        for e in edges {
            if let Some(child) = children.get(&e.from_finding_id) {
                out.entry(e.to_finding_id).or_default().push((
                    child.clone(),
                    e.appended_description,
                    e.appended_patterns,
                    e.appended_exploits,
                ));
            }
        }
        Ok(out)
    }

    /// Map each canonical semantic id → the non-empty `appended_description`
    /// notes of the raws folded into it (each variant's concrete delta). Used to
    /// render a link candidate together with its merged variants.
    pub async fn semantic_merge_appended_notes(&self) -> Result<HashMap<i32, Vec<String>>> {
        let mut notes: HashMap<i32, Vec<String>> = HashMap::new();
        for merge in semantic_merge::Entity::find().all(&self.db).await? {
            let note = merge.appended_description.trim();
            if !note.is_empty() {
                notes
                    .entry(merge.to_semantic_id)
                    .or_default()
                    .push(note.to_string());
            }
        }
        Ok(notes)
    }

    pub async fn all_canonical_semantic_link_candidates(
        &self,
    ) -> Result<Vec<semantic_node::Model>> {
        let merged_away_ids: HashSet<i32> = semantic_merge::Entity::find()
            .all(&self.db)
            .await?
            .into_iter()
            .map(|merge| merge.from_semantic_id)
            .collect();
        let mut nodes: Vec<semantic_node::Model> = semantic_node::Entity::find()
            .all(&self.db)
            .await?
            .into_iter()
            .filter(|node| !merged_away_ids.contains(&node.id))
            .collect();
        nodes.sort_by_key(|node| node.id);
        Ok(nodes)
    }

    pub async fn load_semantic_scope_seed(&self) -> Result<Vec<SemanticScopeSeed>> {
        let nodes = self
            .existing_semantics_for_categories(DeFiCategory::ALL)
            .await?;
        if nodes.is_empty() {
            return Ok(Vec::new());
        }

        let node_ids = nodes.iter().map(|node| node.id).collect::<Vec<_>>();
        let mut functions_by_semantic = HashMap::<i32, Vec<(String, String)>>::new();
        for function in semantic_function::Entity::find()
            .filter(semantic_function::Column::SemanticNodeId.is_in(node_ids))
            .all(&self.db)
            .await?
        {
            functions_by_semantic
                .entry(function.semantic_node_id)
                .or_default()
                .push((function.function_name, function.contract_path));
        }

        let mut out = nodes
            .into_iter()
            .map(|node| SemanticScopeSeed {
                name: node.name,
                category: node.category,
                definition: node.definition,
                description: node.description,
                functions: functions_by_semantic.remove(&node.id).unwrap_or_default(),
            })
            .collect::<Vec<_>>();
        out.sort_by(|lhs, rhs| {
            lhs.category
                .as_str()
                .cmp(rhs.category.as_str())
                .then_with(|| lhs.name.cmp(&rhs.name))
        });
        Ok(out)
    }

    pub async fn load_vulnerability_scope_seed(&self) -> Result<Vec<VulnerabilityScopeSeed>> {
        let findings = audit_finding::Entity::find().all(&self.db).await?;
        if findings.is_empty() {
            return Ok(Vec::new());
        }

        let finding_merge_map = build_merge_map(
            finding_merge::Entity::find()
                .all(&self.db)
                .await?
                .into_iter()
                .map(|merge| (merge.from_finding_id, merge.to_finding_id)),
        );
        let semantic_merge_map = build_merge_map(
            semantic_merge::Entity::find()
                .all(&self.db)
                .await?
                .into_iter()
                .map(|merge| (merge.from_semantic_id, merge.to_semantic_id)),
        );

        let semantic_by_id = semantic_node::Entity::find()
            .all(&self.db)
            .await?
            .into_iter()
            .map(|semantic| (semantic.id, semantic))
            .collect::<HashMap<_, _>>();

        let project_category_names = category::Entity::find()
            .all(&self.db)
            .await?
            .into_iter()
            .map(|row| (row.id, row.name))
            .collect::<HashMap<_, _>>();
        let mut project_categories_by_project = HashMap::<i32, Vec<DeFiCategory>>::new();
        for link in project_category::Entity::find().all(&self.db).await? {
            if let Some(category) = project_category_names.get(&link.category_id) {
                project_categories_by_project
                    .entry(link.project_id)
                    .or_default()
                    .push(*category);
            }
        }
        for categories in project_categories_by_project.values_mut() {
            categories.sort_by_key(DeFiCategory::as_str);
            categories.dedup();
        }

        let mut findings_by_id = findings
            .into_iter()
            .map(|finding| (finding.id, finding))
            .collect::<HashMap<_, _>>();
        let active_finding_ids = findings_by_id
            .keys()
            .copied()
            .filter(|finding_id| {
                resolve_merge_target(*finding_id, &finding_merge_map) == *finding_id
            })
            .collect::<HashSet<_>>();

        // Project provenance now lives in `project_finding` (a finding may
        // have multiple originating projects after merge). For seed
        // construction we want any one project's category set as a fallback;
        // using the lowest project id is deterministic.
        let mut project_id_by_finding: HashMap<i32, i32> = HashMap::new();
        for row in project_finding::Entity::find().all(&self.db).await? {
            project_id_by_finding
                .entry(row.audit_finding_id)
                .and_modify(|cur| {
                    if row.project_id < *cur {
                        *cur = row.project_id;
                    }
                })
                .or_insert(row.project_id);
        }

        let mut semantic_names_by_finding = HashMap::<i32, HashSet<String>>::new();
        let mut semantic_categories_by_finding = HashMap::<i32, HashSet<DeFiCategory>>::new();
        for link in semantic_finding_link::Entity::find().all(&self.db).await? {
            let canonical_finding_id =
                resolve_merge_target(link.audit_finding_id, &finding_merge_map);
            if !active_finding_ids.contains(&canonical_finding_id) {
                continue;
            }

            let canonical_semantic_id =
                resolve_merge_target(link.semantic_node_id, &semantic_merge_map);
            let Some(semantic) = semantic_by_id.get(&canonical_semantic_id) else {
                continue;
            };

            semantic_names_by_finding
                .entry(canonical_finding_id)
                .or_default()
                .insert(semantic.name.clone());
            semantic_categories_by_finding
                .entry(canonical_finding_id)
                .or_default()
                .insert(semantic.category);
        }

        let mut active_ids = active_finding_ids.into_iter().collect::<Vec<_>>();
        active_ids.sort_unstable();

        let mut out = Vec::new();
        for finding_id in active_ids {
            let Some(finding) = findings_by_id.remove(&finding_id) else {
                continue;
            };

            let mut semantic_names = semantic_names_by_finding
                .remove(&finding_id)
                .unwrap_or_default()
                .into_iter()
                .collect::<Vec<_>>();
            semantic_names.sort();
            semantic_names.dedup();
            if semantic_names.is_empty() {
                continue;
            }

            let mut categories = semantic_categories_by_finding
                .remove(&finding_id)
                .unwrap_or_default()
                .into_iter()
                .collect::<Vec<_>>();
            if categories.is_empty()
                && let Some(pid) = project_id_by_finding.get(&finding_id)
            {
                categories = project_categories_by_project
                    .get(pid)
                    .cloned()
                    .unwrap_or_default();
            }
            if categories.is_empty() {
                categories.push(DeFiCategory::Others);
            }
            categories.sort_by_key(DeFiCategory::as_str);
            categories.dedup();

            out.push(VulnerabilityScopeSeed {
                title: finding.title,
                severity: finding.severity.as_str().to_string(),
                description: finding.description,
                categories,
                semantic_names,
            });
        }

        Ok(out)
    }

    /// Fetch existing canonical findings (= survivors of any merge) for
    /// the given vulnerability categories, paired with their taxonomy
    /// entry and the raw children that have been merged into each
    /// canonical. Mirrors
    /// [`Self::canonical_semantics_with_children_for_categories`].
    pub async fn canonical_findings_with_children_for_categories(
        &self,
        categories: &[VulnerabilityCategory],
    ) -> Result<Vec<crate::agents::FindingCanonicalWithTaxonomy>> {
        let canonicals = self.existing_findings_for_categories(categories).await?;
        if canonicals.is_empty() {
            return Ok(Vec::new());
        }
        let canonical_ids: Vec<i32> = canonicals.iter().map(|(f, _)| f.id).collect();
        let merge_rows = finding_merge::Entity::find()
            .filter(finding_merge::Column::ToFindingId.is_in(canonical_ids.clone()))
            .all(&self.db)
            .await?;
        let raw_ids: Vec<i32> = merge_rows.iter().map(|m| m.from_finding_id).collect();
        let raws = if raw_ids.is_empty() {
            Vec::new()
        } else {
            audit_finding::Entity::find()
                .filter(audit_finding::Column::Id.is_in(raw_ids))
                .all(&self.db)
                .await?
        };
        let raws_by_id: HashMap<i32, audit_finding::Model> =
            raws.into_iter().map(|f| (f.id, f)).collect();
        let mut children_by_canonical: HashMap<i32, Vec<audit_finding::Model>> = HashMap::new();
        for row in merge_rows {
            if let Some(raw) = raws_by_id.get(&row.from_finding_id) {
                children_by_canonical
                    .entry(row.to_finding_id)
                    .or_default()
                    .push(raw.clone());
            }
        }
        Ok(canonicals
            .into_iter()
            .map(|(canonical, category)| {
                let raw_children = children_by_canonical
                    .remove(&canonical.id)
                    .unwrap_or_default();
                crate::agents::FindingCanonicalWithTaxonomy {
                    canonical,
                    category,
                    raw_children,
                }
            })
            .collect())
    }

    pub async fn existing_findings_for_categories(
        &self,
        categories: &[VulnerabilityCategory],
    ) -> Result<Vec<(audit_finding::Model, finding_category::Model)>> {
        if categories.is_empty() {
            return Ok(Vec::new());
        }

        let category_rows = finding_category::Entity::find()
            .filter(finding_category::Column::Category.is_in(categories.iter().copied()))
            .all(&self.db)
            .await?;

        if category_rows.is_empty() {
            return Ok(Vec::new());
        }

        let category_by_id: HashMap<i32, finding_category::Model> = category_rows
            .iter()
            .cloned()
            .map(|row| (row.id, row))
            .collect();
        let category_ids: Vec<i32> = category_by_id.keys().copied().collect();

        let links = audit_finding_category::Entity::find()
            .filter(audit_finding_category::Column::FindingCategoryId.is_in(category_ids))
            .all(&self.db)
            .await?;

        if links.is_empty() {
            return Ok(Vec::new());
        }

        let finding_ids: Vec<i32> = links
            .iter()
            .map(|link| link.audit_finding_id)
            .unique()
            .collect();
        let merged_away: HashSet<i32> = finding_merge::Entity::find()
            .filter(finding_merge::Column::FromFindingId.is_in(finding_ids.clone()))
            .all(&self.db)
            .await?
            .into_iter()
            .map(|merge| merge.from_finding_id)
            .collect();

        let active_finding_ids: Vec<i32> = finding_ids
            .into_iter()
            .filter(|id| !merged_away.contains(id))
            .collect();

        if active_finding_ids.is_empty() {
            return Ok(Vec::new());
        }

        let findings: HashMap<i32, audit_finding::Model> = audit_finding::Entity::find()
            .filter(audit_finding::Column::Id.is_in(active_finding_ids.clone()))
            .all(&self.db)
            .await?
            .into_iter()
            .map(|finding| (finding.id, finding))
            .collect();

        let mut results = Vec::new();
        for link in links {
            if !active_finding_ids.contains(&link.audit_finding_id) {
                continue;
            }

            let Some(finding) = findings.get(&link.audit_finding_id) else {
                continue;
            };
            let Some(category) = category_by_id.get(&link.finding_category_id) else {
                continue;
            };

            results.push((finding.clone(), category.clone()));
        }

        results.sort_by(|lhs, rhs| lhs.0.id.cmp(&rhs.0.id));
        results.dedup_by(|lhs, rhs| lhs.0.id == rhs.0.id);
        Ok(results)
    }

    /// Findings that still need the global cross-project linker (not yet in
    /// `finding_link_status`).
    pub async fn list_pending_findings_for_linking(
        &self,
    ) -> Result<Vec<crate::learn::PendingFindingForLinking>> {
        self.list_findings_for_linking(false).await
    }

    /// List findings to feed to the global cross-project linker.
    ///
    /// A finding is "pending" until it has a row in `finding_link_status` — the
    /// marker the global linker writes when it finishes a finding. In-project
    /// links (created at extraction time) live in `semantic_finding_link` but
    /// intentionally do NOT set `finding_link_status`, so they never make a
    /// finding count as globally linked.
    ///
    /// `include_unlinked = true` additionally re-includes findings that were
    /// already globally processed (a forced re-link).
    pub async fn list_findings_for_linking(
        &self,
        include_unlinked: bool,
    ) -> Result<Vec<crate::learn::PendingFindingForLinking>> {
        let findings = audit_finding::Entity::find().all(&self.db).await?;
        if findings.is_empty() {
            return Ok(Vec::new());
        }

        let finding_merge_map = build_merge_map(
            finding_merge::Entity::find()
                .all(&self.db)
                .await?
                .into_iter()
                .map(|merge| (merge.from_finding_id, merge.to_finding_id)),
        );

        // A row in `finding_link_status` means the finding has been FULLY
        // processed by the global cross-project linker. This is the ONLY
        // authoritative "already globally linked" signal. In-project links
        // (written at extraction time into `semantic_finding_link`) are
        // intra-project only and deliberately do NOT write
        // `finding_link_status` — so a finding's mere presence in
        // `semantic_finding_link` must NOT be read as "already linked".
        let processed_ids: HashSet<i32> = finding_link_status::Entity::find()
            .all(&self.db)
            .await?
            .into_iter()
            .map(|status| status.audit_finding_id)
            .collect();

        let category_rows = finding_category::Entity::find().all(&self.db).await?;
        let category_by_id: HashMap<i32, finding_category::Model> =
            category_rows.into_iter().map(|row| (row.id, row)).collect();

        let mut finding_category_by_id = HashMap::new();
        for link in audit_finding_category::Entity::find().all(&self.db).await? {
            let category = category_by_id
                .get(&link.finding_category_id)
                .ok_or_else(|| {
                    KgError::other(format!(
                        "Missing finding category row {} for finding {}",
                        link.finding_category_id, link.audit_finding_id
                    ))
                })?;

            if finding_category_by_id
                .insert(link.audit_finding_id, category.clone())
                .is_some()
            {
                return Err(KgError::other(format!(
                    "Finding {} has multiple taxonomy links; expected exactly one",
                    link.audit_finding_id
                )));
            }
        }

        let category_rows = category::Entity::find().all(&self.db).await?;
        let project_category_names: HashMap<i32, DeFiCategory> = category_rows
            .into_iter()
            .map(|row| (row.id, row.name))
            .collect();
        let mut project_categories_by_project: HashMap<i32, Vec<DeFiCategory>> = HashMap::new();
        for link in project_category::Entity::find().all(&self.db).await? {
            let category = project_category_names
                .get(&link.category_id)
                .ok_or_else(|| {
                    KgError::other(format!(
                        "Missing DeFi category row {} for project {}",
                        link.category_id, link.project_id
                    ))
                })?;
            project_categories_by_project
                .entry(link.project_id)
                .or_default()
                .push(*category);
        }
        for categories in project_categories_by_project.values_mut() {
            categories.sort_by_key(DeFiCategory::as_str);
            categories.dedup();
        }

        // Pre-load finding → originating projects from the join table.
        // A canonical finding may have several originating projects after
        // raw siblings fold into it; we union their category lists for
        // category-aware linking context.
        let mut project_ids_by_finding: HashMap<i32, Vec<i32>> = HashMap::new();
        for row in project_finding::Entity::find().all(&self.db).await? {
            project_ids_by_finding
                .entry(row.audit_finding_id)
                .or_default()
                .push(row.project_id);
        }

        let mut pending = Vec::new();
        for finding in findings.into_iter().sorted_by_key(|finding| finding.id) {
            let canonical_id = resolve_merge_target(finding.id, &finding_merge_map);
            // A finding still needs the global cross-project linker until it is
            // recorded in `finding_link_status`. In-project links do NOT count
            // (they never set that status), so we key ONLY off it — reading
            // "has any semantic_finding_link row" here was the historical bug
            // that made every finding look already-linked once in-project
            // linking started populating that table. `include_unlinked` forces
            // re-linking of findings that were already globally processed.
            let finding_is_processed = processed_ids.contains(&finding.id);
            if finding_is_processed && !include_unlinked {
                continue;
            }

            let taxonomy = finding_category_by_id.get(&finding.id).ok_or_else(|| {
                KgError::other(format!("Finding {} is missing taxonomy", finding.id))
            })?;

            let mut categories: Vec<DeFiCategory> = Vec::new();
            if let Some(pids) = project_ids_by_finding.get(&finding.id) {
                for pid in pids {
                    if let Some(cats) = project_categories_by_project.get(pid) {
                        categories.extend(cats.iter().copied());
                    }
                }
            }
            categories.sort_by_key(DeFiCategory::as_str);
            categories.dedup();

            pending.push(crate::learn::PendingFindingForLinking {
                finding_id: finding.id,
                link_target_finding_id: canonical_id,
                categories,
                finding: crate::learn::ExtractedFinding {
                    title: finding.title,
                    severity: finding.severity,
                    category: taxonomy.category,
                    subcategory: taxonomy.name.clone(),
                    root_cause: finding.root_cause,
                    description: finding.description,
                    patterns: finding.patterns,
                    exploits: finding.exploits,
                },
            });
        }

        Ok(pending)
    }

    pub async fn write_finding_link_result(
        &self,
        result: &crate::learn::PersistedFindingLinkResult,
    ) -> Result<()> {
        self.upsert_finding_link_rows(result).await?;
        self.mark_finding_link_complete(result.finding_id).await?;
        tracing::info!(
            "Finding {} processed with {} semantic link(s) targeting finding {}",
            result.finding_id,
            result.semantic_links.len(),
            result.link_target_finding_id
        );
        Ok(())
    }

    /// Partial-commit hook for the link runner: durably persist the
    /// links discovered by ONE batch for this finding. The finding
    /// stays out of `finding_link_status` until
    /// [`mark_finding_link_complete`] runs, so downstream consumers
    /// (mapper, spec-gen) skip the still-partial sfl rows via
    /// `load_knowledge_graph`'s gate. Mid-flight crashes leave the
    /// sfl rows in place; the next pass re-emits the same edges and
    /// the strongest-strength-wins upsert is idempotent.
    pub async fn upsert_finding_link_partial(
        &self,
        result: &crate::learn::PersistedFindingLinkResult,
    ) -> Result<()> {
        self.upsert_finding_link_rows(result).await
    }

    /// Counterpart to [`Self::upsert_finding_link_partial`]: insert
    /// the `finding_link_status` row so downstream consumers start
    /// seeing the finding's links. No-op if the row already exists
    /// (resume-safe).
    pub async fn mark_finding_link_complete(&self, finding_id: i32) -> Result<()> {
        let txn = self.db.begin().await?;
        let existing = finding_link_status::Entity::find_by_id(finding_id)
            .one(&txn)
            .await?;
        if existing.is_none() {
            finding_link_status::Entity::insert(finding_link_status::ActiveModel {
                audit_finding_id: Set(finding_id),
            })
            .exec(&txn)
            .await?;
        }
        txn.commit().await?;
        Ok(())
    }

    /// Shared sfl writer: strongest-strength wins per
    /// (semantic, finding). Called by both the full and partial
    /// commit paths; partial commit may upsert the same edge
    /// multiple times across batches and the comparison guarantees
    /// no per-cycle downgrade.
    async fn upsert_finding_link_rows(
        &self,
        result: &crate::learn::PersistedFindingLinkResult,
    ) -> Result<()> {
        let txn = self.db.begin().await?;

        for link in &result.semantic_links {
            let existing = semantic_finding_link::Entity::find()
                .filter(semantic_finding_link::Column::SemanticNodeId.eq(link.semantic_id))
                .filter(
                    semantic_finding_link::Column::AuditFindingId.eq(result.link_target_finding_id),
                )
                .one(&txn)
                .await?;

            match existing {
                None => {
                    let row = semantic_finding_link::ActiveModel {
                        semantic_node_id: Set(link.semantic_id),
                        audit_finding_id: Set(result.link_target_finding_id),
                        strength: Set(link.strength),
                        evidence: Set(link.evidence.clone()),
                    };
                    semantic_finding_link::Entity::insert(row)
                        .exec(&txn)
                        .await?;
                }
                Some(existing_row) => {
                    // Strongest-strength wins on conflict. Equal-rank
                    // collisions keep the existing row to avoid
                    // unnecessary writes.
                    let existing_rank = existing_row.strength.rank();
                    let incoming_rank = link.strength.rank();
                    if incoming_rank > existing_rank {
                        let mut active: semantic_finding_link::ActiveModel = existing_row.into();
                        active.strength = Set(link.strength);
                        active.evidence = Set(link.evidence.clone());
                        active.update(&txn).await?;
                    }
                }
            }
        }

        txn.commit().await?;
        Ok(())
    }

    /// Findings that have been globally linked already (i.e., have a row in
    /// `finding_link_status`). Used by the retro-link pass to feed the LLM
    /// the set of findings that should be re-checked against newly-introduced
    /// canonical semantics queued in `pending_semantic`.
    pub async fn list_findings_with_link_status(
        &self,
    ) -> Result<Vec<crate::learn::PendingFindingForLinking>> {
        // Retro-link replays canonical semantics into the linker for
        // findings already fully processed; partial findings (sfl rows
        // without a matching `finding_link_status` row) will be
        // covered by the next `link_pending_findings` pass instead.
        let processed_ids: HashSet<i32> = finding_link_status::Entity::find()
            .all(&self.db)
            .await?
            .into_iter()
            .map(|s| s.audit_finding_id)
            .collect();
        if processed_ids.is_empty() {
            return Ok(Vec::new());
        }

        let findings = audit_finding::Entity::find()
            .filter(audit_finding::Column::Id.is_in(processed_ids.iter().copied()))
            .all(&self.db)
            .await?;
        if findings.is_empty() {
            return Ok(Vec::new());
        }

        let finding_merge_map = build_merge_map(
            finding_merge::Entity::find()
                .all(&self.db)
                .await?
                .into_iter()
                .map(|merge| (merge.from_finding_id, merge.to_finding_id)),
        );

        // Load taxonomy via audit_finding_category → finding_category.
        let category_rows = finding_category::Entity::find().all(&self.db).await?;
        let category_by_id: HashMap<i32, finding_category::Model> =
            category_rows.into_iter().map(|row| (row.id, row)).collect();
        let mut finding_taxonomy: HashMap<i32, finding_category::Model> = HashMap::new();
        for link in audit_finding_category::Entity::find().all(&self.db).await? {
            if let Some(cat) = category_by_id.get(&link.finding_category_id) {
                finding_taxonomy.insert(link.audit_finding_id, cat.clone());
            }
        }

        let mut pending = Vec::new();
        for finding in findings {
            let canonical_id = resolve_merge_target(finding.id, &finding_merge_map);
            let taxonomy = match finding_taxonomy.get(&finding.id) {
                Some(t) => t.clone(),
                None => continue,
            };
            pending.push(crate::learn::PendingFindingForLinking {
                finding_id: finding.id,
                link_target_finding_id: canonical_id,
                categories: Vec::new(), // retro-link is category-agnostic
                finding: crate::learn::ExtractedFinding {
                    title: finding.title,
                    severity: finding.severity,
                    category: taxonomy.category,
                    subcategory: taxonomy.name.clone(),
                    root_cause: finding.root_cause,
                    description: finding.description,
                    patterns: finding.patterns,
                    exploits: finding.exploits,
                },
            });
        }
        Ok(pending)
    }

    /// Currently-queued canonical semantics waiting for retro-link consideration.
    pub async fn list_pending_canonical_semantics(&self) -> Result<Vec<semantic_node::Model>> {
        let pending_ids: Vec<i32> = knowdit_kg_model::db::pending_semantic::Entity::find()
            .all(&self.db)
            .await?
            .into_iter()
            .map(|p| p.semantic_node_id)
            .collect();
        if pending_ids.is_empty() {
            return Ok(Vec::new());
        }
        Ok(semantic_node::Entity::find()
            .filter(semantic_node::Column::Id.is_in(pending_ids))
            .all(&self.db)
            .await?)
    }

    /// Append `(canonical_semantic_id, finding_id, strength, evidence)`
    /// rows to `semantic_finding_link`. Idempotent on the composite
    /// primary key: existing rows are left untouched (use a separate
    /// upsert helper if you need to overwrite strength/evidence; the
    /// current write path is append-only). Does NOT touch
    /// `finding_link_status` — retro-link is for findings already there.
    pub async fn append_semantic_finding_links(&self, edges: &[LinkEdge]) -> Result<usize> {
        if edges.is_empty() {
            return Ok(0);
        }
        let txn = self.db.begin().await?;
        let mut inserted = 0;
        for edge in edges {
            let already = semantic_finding_link::Entity::find()
                .filter(semantic_finding_link::Column::SemanticNodeId.eq(edge.semantic_node_id))
                .filter(semantic_finding_link::Column::AuditFindingId.eq(edge.audit_finding_id))
                .one(&txn)
                .await?;
            if already.is_none() {
                semantic_finding_link::Entity::insert(semantic_finding_link::ActiveModel {
                    semantic_node_id: Set(edge.semantic_node_id),
                    audit_finding_id: Set(edge.audit_finding_id),
                    strength: Set(edge.strength),
                    evidence: Set(edge.evidence.clone()),
                })
                .exec(&txn)
                .await?;
                inserted += 1;
            }
        }
        txn.commit().await?;
        Ok(inserted)
    }

    /// Empty the `pending_semantic` queue. Run after retro-link successfully
    /// processed the queued semantics against the existing finding_link_status
    /// set.
    pub async fn clear_pending_semantic_queue(&self) -> Result<usize> {
        let result = knowdit_kg_model::db::pending_semantic::Entity::delete_many()
            .exec(&self.db)
            .await?;
        Ok(result.rows_affected as usize)
    }

    pub async fn list_processed_findings_without_semantic_links(&self) -> Result<Vec<i32>> {
        // "processed" = row present in `finding_link_status`. Partial
        // findings (sfl rows but no status row) are expected to be
        // missing some links and aren't a diagnostic.
        let processed_ids: HashSet<i32> = finding_link_status::Entity::find()
            .all(&self.db)
            .await?
            .into_iter()
            .map(|status| status.audit_finding_id)
            .collect();
        if processed_ids.is_empty() {
            return Ok(Vec::new());
        }

        let finding_merge_map = build_merge_map(
            finding_merge::Entity::find()
                .all(&self.db)
                .await?
                .into_iter()
                .map(|merge| (merge.from_finding_id, merge.to_finding_id)),
        );
        let linked_ids: HashSet<i32> = semantic_finding_link::Entity::find()
            .all(&self.db)
            .await?
            .into_iter()
            .map(|link| link.audit_finding_id)
            .collect();

        let mut findings_without_links: Vec<i32> = processed_ids
            .into_iter()
            .filter(|finding_id| {
                let canonical_id = resolve_merge_target(*finding_id, &finding_merge_map);
                !linked_ids.contains(&canonical_id)
            })
            .collect();
        findings_without_links.sort_unstable();
        Ok(findings_without_links)
    }

    /// Reset finding-link progress so the global cross-project linker re-runs.
    ///
    /// There are two kinds of row in `semantic_finding_link`:
    /// - **in-project links**: written at extraction time, one per finding to a
    ///   semantic from the SAME project. They are cheap, high-confidence, and
    ///   carry the [`IN_PROJECT_LINK_EVIDENCE_PREFIX`] evidence.
    /// - **global cross-project links**: written by the global linker, linking a
    ///   finding to canonical semantics from OTHER projects; they carry an LLM
    ///   rationale.
    ///
    /// This always clears `finding_link_status` (so every finding becomes
    /// pending again). By default it deletes ONLY the global links and KEEPS the
    /// in-project links — you rarely want to re-derive those. Pass
    /// `reset_in_project = true` to wipe the in-project links too (a full clean
    /// slate). Returns `(deleted_links, deleted_statuses)`.
    pub async fn clear_finding_link_progress(&self, reset_in_project: bool) -> Result<(u64, u64)> {
        // Pre-strength-rollout KGs are missing `semantic_finding_link.strength`
        // and `.evidence`. Bringing them up to the current schema BEFORE the
        // delete lets `delete_many()` succeed even if seaorm introspects every
        // column for the DELETE.
        self.migrate_link_strength_columns().await?;
        let txn = self.db.begin().await?;

        let mut delete = semantic_finding_link::Entity::delete_many();
        if !reset_in_project {
            // Keep in-project links: delete only rows whose evidence is NOT the
            // in-project prefix (i.e. the global cross-project links).
            delete = delete.filter(
                semantic_finding_link::Column::Evidence
                    .not_like(format!("{IN_PROJECT_LINK_EVIDENCE_PREFIX}%")),
            );
        }
        let deleted_links = delete.exec(&txn).await?;
        let deleted_statuses = finding_link_status::Entity::delete_many()
            .exec(&txn)
            .await?;

        txn.commit().await?;
        Ok((deleted_links.rows_affected, deleted_statuses.rows_affected))
    }

    /// Idempotent migration: bring `semantic_finding_link` up to the
    /// current schema by adding the `strength` and `evidence` columns
    /// (introduced with the Low/Medium/High `LinkStrength` rollout) if
    /// they aren't already present. SQLite-only — every existing
    /// historical KG lives in SQLite, and `ALTER TABLE ... ADD COLUMN`
    /// is the cheapest way to bolt the new columns onto pre-existing
    /// tables without a full data migration.
    ///
    /// Safe to call from any DB lifecycle point: skips entirely on
    /// non-SQLite backends or when both columns already exist. New DBs
    /// created via `init()` get the columns directly through
    /// `create_tables`, so this method is a no-op for them.
    pub async fn migrate_link_strength_columns(&self) -> Result<()> {
        self.migrate_link_strength_columns_within(&self.db).await
    }

    /// Transaction-scoped backfill for `semantic_finding_link`'s
    /// `strength` / `evidence` columns. Same behaviour as
    /// [`Self::migrate_link_strength_columns`] but executes against
    /// the supplied connection so [`Self::init`] can run the whole
    /// lifecycle setup atomically.
    async fn migrate_link_strength_columns_within<C: ConnectionTrait>(
        &self,
        conn: &C,
    ) -> Result<()> {
        if conn.get_database_backend() != sea_orm::DatabaseBackend::Sqlite {
            return Ok(());
        }
        use sea_orm::{FromQueryResult, Statement};
        #[derive(FromQueryResult)]
        struct ColInfo {
            name: String,
        }
        let columns = ColInfo::find_by_statement(Statement::from_string(
            sea_orm::DatabaseBackend::Sqlite,
            "PRAGMA table_info(semantic_finding_link)".to_string(),
        ))
        .all(conn)
        .await?;
        if columns.is_empty() {
            return Ok(());
        }
        let has_strength = columns.iter().any(|c| c.name == "strength");
        let has_evidence = columns.iter().any(|c| c.name == "evidence");
        if has_strength && has_evidence {
            return Ok(());
        }
        tracing::warn!(
            has_strength,
            has_evidence,
            "semantic_finding_link is missing strength/evidence columns; \
             migrating in place (LinkStrength rollout backfill)"
        );
        if !has_strength {
            conn.execute_unprepared(
                "ALTER TABLE semantic_finding_link \
                 ADD COLUMN strength TEXT NOT NULL DEFAULT 'Medium'",
            )
            .await?;
        }
        if !has_evidence {
            conn.execute_unprepared(
                "ALTER TABLE semantic_finding_link \
                 ADD COLUMN evidence TEXT NOT NULL DEFAULT ''",
            )
            .await?;
        }
        conn.execute_unprepared(
            "CREATE INDEX IF NOT EXISTS \
             \"idx-semantic_finding_link-strength\" \
             ON semantic_finding_link(strength)",
        )
        .await?;
        Ok(())
    }

    pub async fn validate_db(&self, repair: bool) -> Result<DbValidationReport> {
        let detected = self.collect_db_validation_issues().await?;
        if !repair || detected.is_empty() {
            let issues = detected
                .into_iter()
                .map(|issue| issue.issue)
                .collect::<Vec<_>>();
            return Ok(DbValidationReport {
                detected_issues: issues.clone(),
                remaining_issues: issues,
                repaired_rows: 0,
            });
        }

        let txn = self.db.begin().await?;
        let mut repaired_rows = 0usize;
        for issue in &detected {
            // Some detected issues (e.g. partial-link state) have no
            // row-deletion fix — they need the linker to finish.
            // Skip those during repair; they'll resurface in
            // `remaining_issues` for the caller to act on.
            if let Some(action) = &issue.repair_action {
                repaired_rows += action.execute(&txn).await? as usize;
            }
        }
        txn.commit().await?;

        let remaining_issues = self
            .collect_db_validation_issues()
            .await?
            .into_iter()
            .map(|issue| issue.issue)
            .collect();

        Ok(DbValidationReport {
            detected_issues: detected.into_iter().map(|issue| issue.issue).collect(),
            remaining_issues,
            repaired_rows,
        })
    }

    async fn collect_db_validation_issues(&self) -> Result<Vec<DetectedDbIssue>> {
        let project_ids: HashSet<i32> = project::Entity::find()
            .all(&self.db)
            .await?
            .into_iter()
            .map(|row| row.id)
            .collect();
        let category_ids: HashSet<i32> = category::Entity::find()
            .all(&self.db)
            .await?
            .into_iter()
            .map(|row| row.id)
            .collect();
        let semantic_node_ids: HashSet<i32> = semantic_node::Entity::find()
            .all(&self.db)
            .await?
            .into_iter()
            .map(|row| row.id)
            .collect();
        let audit_finding_ids: HashSet<i32> = audit_finding::Entity::find()
            .all(&self.db)
            .await?
            .into_iter()
            .map(|row| row.id)
            .collect();
        let finding_category_ids: HashSet<i32> = finding_category::Entity::find()
            .all(&self.db)
            .await?
            .into_iter()
            .map(|row| row.id)
            .collect();

        let mut issues = Vec::new();

        for row in project_platform::Entity::find().all(&self.db).await? {
            let mut missing = Vec::new();
            if !project_ids.contains(&row.project_id) {
                missing.push(format!("missing project {}", row.project_id));
            }
            if !missing.is_empty() {
                issues.push(DetectedDbIssue {
                    issue: DbValidationIssue {
                        table: "project_platform",
                        row_key: format!("id={} (platform_id={})", row.id, row.platform_id),
                        problem: missing.join(", "),
                    },
                    repair_action: Some(DbValidationRepairAction::DeleteProjectPlatform {
                        id: row.id,
                    }),
                });
            }
        }

        for row in project_category::Entity::find().all(&self.db).await? {
            let mut missing = Vec::new();
            if !project_ids.contains(&row.project_id) {
                missing.push(format!("missing project {}", row.project_id));
            }
            if !category_ids.contains(&row.category_id) {
                missing.push(format!("missing category {}", row.category_id));
            }
            if !missing.is_empty() {
                issues.push(DetectedDbIssue {
                    issue: DbValidationIssue {
                        table: "project_category",
                        row_key: format!("project={} category={}", row.project_id, row.category_id),
                        problem: missing.join(", "),
                    },
                    repair_action: Some(DbValidationRepairAction::DeleteProjectCategory {
                        project_id: row.project_id,
                        category_id: row.category_id,
                    }),
                });
            }
        }

        for row in semantic_function::Entity::find().all(&self.db).await? {
            if !semantic_node_ids.contains(&row.semantic_node_id) {
                issues.push(DetectedDbIssue {
                    issue: DbValidationIssue {
                        table: "semantic_function",
                        row_key: format!("id={}", row.id),
                        problem: format!("missing semantic node sem-{}", row.semantic_node_id),
                    },
                    repair_action: Some(DbValidationRepairAction::DeleteSemanticFunction {
                        id: row.id,
                    }),
                });
            }
        }

        for row in semantic_merge::Entity::find().all(&self.db).await? {
            let mut missing = Vec::new();
            if !semantic_node_ids.contains(&row.from_semantic_id) {
                missing.push(format!(
                    "missing source semantic sem-{}",
                    row.from_semantic_id
                ));
            }
            if !semantic_node_ids.contains(&row.to_semantic_id) {
                missing.push(format!(
                    "missing target semantic sem-{}",
                    row.to_semantic_id
                ));
            }
            if !missing.is_empty() {
                issues.push(DetectedDbIssue {
                    issue: DbValidationIssue {
                        table: "semantic_merge",
                        row_key: format!(
                            "sem-{} -> sem-{}",
                            row.from_semantic_id, row.to_semantic_id
                        ),
                        problem: missing.join(", "),
                    },
                    repair_action: Some(DbValidationRepairAction::DeleteSemanticMerge {
                        from_semantic_id: row.from_semantic_id,
                        to_semantic_id: row.to_semantic_id,
                    }),
                });
            }
        }

        for row in audit_finding_category::Entity::find().all(&self.db).await? {
            let mut missing = Vec::new();
            if !audit_finding_ids.contains(&row.audit_finding_id) {
                missing.push(format!("missing finding {}", row.audit_finding_id));
            }
            if !finding_category_ids.contains(&row.finding_category_id) {
                missing.push(format!(
                    "missing finding_category {}",
                    row.finding_category_id
                ));
            }
            if !missing.is_empty() {
                issues.push(DetectedDbIssue {
                    issue: DbValidationIssue {
                        table: "audit_finding_category",
                        row_key: format!(
                            "finding={} category={}",
                            row.audit_finding_id, row.finding_category_id
                        ),
                        problem: missing.join(", "),
                    },
                    repair_action: Some(DbValidationRepairAction::DeleteAuditFindingCategory {
                        audit_finding_id: row.audit_finding_id,
                        finding_category_id: row.finding_category_id,
                    }),
                });
            }
        }

        for row in semantic_finding_link::Entity::find().all(&self.db).await? {
            let mut missing = Vec::new();
            if !semantic_node_ids.contains(&row.semantic_node_id) {
                missing.push(format!(
                    "missing semantic node sem-{}",
                    row.semantic_node_id
                ));
            }
            if !audit_finding_ids.contains(&row.audit_finding_id) {
                missing.push(format!("missing finding {}", row.audit_finding_id));
            }
            if !missing.is_empty() {
                issues.push(DetectedDbIssue {
                    issue: DbValidationIssue {
                        table: "semantic_finding_link",
                        row_key: format!(
                            "sem-{} -> finding-{}",
                            row.semantic_node_id, row.audit_finding_id
                        ),
                        problem: missing.join(", "),
                    },
                    repair_action: Some(DbValidationRepairAction::DeleteSemanticFindingLink {
                        semantic_node_id: row.semantic_node_id,
                        audit_finding_id: row.audit_finding_id,
                    }),
                });
            }
        }

        let finding_link_statuses = finding_link_status::Entity::find().all(&self.db).await?;
        for row in &finding_link_statuses {
            if !audit_finding_ids.contains(&row.audit_finding_id) {
                issues.push(DetectedDbIssue {
                    issue: DbValidationIssue {
                        table: "finding_link_status",
                        row_key: format!("finding-{}", row.audit_finding_id),
                        problem: format!("missing finding {}", row.audit_finding_id),
                    },
                    repair_action: Some(DbValidationRepairAction::DeleteFindingLinkStatus {
                        audit_finding_id: row.audit_finding_id,
                    }),
                });
            }
        }

        // Partial-link detection: per-batch `semantic_finding_link`
        // writes can land before the linker's final `mark_finding_link_complete`
        // call. A finding that has sfl rows but no matching
        // `finding_link_status` row is in an intermediate state —
        // either the link agent was killed mid-run, or it's still
        // running concurrently. Consumers (mapper / spec-gen) must
        // not silently see this state; `connect_init_for_consumer`
        // refuses to open the DB until the linker finishes, unless
        // the operator passes `--force-allow-partial-historical`.
        let complete_finding_ids: HashSet<i32> = finding_link_statuses
            .iter()
            .map(|s| s.audit_finding_id)
            .collect();
        let mut partial_finding_ids: HashSet<i32> = HashSet::new();
        for row in semantic_finding_link::Entity::find().all(&self.db).await? {
            // Skip rows that already fired the FK loop above — that
            // diagnostic is more specific.
            if !audit_finding_ids.contains(&row.audit_finding_id) {
                continue;
            }
            if !complete_finding_ids.contains(&row.audit_finding_id) {
                partial_finding_ids.insert(row.audit_finding_id);
            }
        }
        let mut partial_sorted: Vec<i32> = partial_finding_ids.into_iter().collect();
        partial_sorted.sort_unstable();
        for finding_id in partial_sorted {
            issues.push(DetectedDbIssue {
                issue: DbValidationIssue {
                    table: "finding_link_status",
                    row_key: format!("finding-{}", finding_id),
                    problem: format!(
                        "finding {} has semantic_finding_link rows but no finding_link_status row (partial link state — re-run `knowdit workflow learn` to finish linking)",
                        finding_id,
                    ),
                },
                repair_action: None,
            });
        }

        // Pending-retro-link detection: the `pending_semantic` queue
        // holds canonical semantic ids that Phase 1 of a learn pass
        // committed but Phase 2 (retro-link) hasn't drained yet. The
        // queue is the only signal for two distinct kill scenarios
        // the per-finding `partial_finding_ids` check misses:
        //
        //   (a) Phase 2 partial commit against findings that already
        //       have a `finding_link_status` row from a prior run —
        //       new sfl edges land for some old findings, none for
        //       others, and the per-finding partial detector doesn't
        //       fire (every involved finding has its status row).
        //
        //   (b) Phase 1 committed only new semantics with no new
        //       findings (a semantics-only project), so no sfl rows
        //       were even written — but retro-link still owes a sweep
        //       against every old finding for those new canonicals.
        //
        // In both cases, a non-empty `pending_semantic` table means
        // the linker pass is incomplete and consumers should not
        // treat the DB as canonical. Single COUNT query, fires once
        // per drain-incomplete run.
        //
        // A KG may legitimately have *dropped* this table once its
        // owning learn run was finalized (e.g. a read-only v3 consumer
        // DB). A missing queue table is identical to a drained one —
        // zero pending work — so probe for it first rather than letting
        // the COUNT error out on the absent table.
        let pending_count = if self.table_exists("pending_semantic").await? {
            pending_semantic::Entity::find().count(&self.db).await?
        } else {
            0
        };
        if pending_count > 0 {
            issues.push(DetectedDbIssue {
                issue: DbValidationIssue {
                    table: "pending_semantic",
                    row_key: format!("{} row(s)", pending_count),
                    problem: format!(
                        "{} canonical semantic(s) queued for retro-link but never drained — Phase 2 of `workflow learn` did not finish. Re-run `knowdit workflow learn` against the same project to drain the queue.",
                        pending_count,
                    ),
                },
                repair_action: None,
            });
        }

        for row in finding_merge::Entity::find().all(&self.db).await? {
            let mut missing = Vec::new();
            if !audit_finding_ids.contains(&row.from_finding_id) {
                missing.push(format!("missing source finding {}", row.from_finding_id));
            }
            if !audit_finding_ids.contains(&row.to_finding_id) {
                missing.push(format!("missing target finding {}", row.to_finding_id));
            }
            if !missing.is_empty() {
                issues.push(DetectedDbIssue {
                    issue: DbValidationIssue {
                        table: "finding_merge",
                        row_key: format!(
                            "finding-{} -> finding-{}",
                            row.from_finding_id, row.to_finding_id
                        ),
                        problem: missing.join(", "),
                    },
                    repair_action: Some(DbValidationRepairAction::DeleteFindingMerge {
                        from_finding_id: row.from_finding_id,
                        to_finding_id: row.to_finding_id,
                    }),
                });
            }
        }

        // Incomplete merges: a `merge_status` row whose phase never reached
        // `'link'` means a `merge-kg` was interrupted mid-way, so the KG is
        // half-merged (imported canonicals but link passes unfinished). Not
        // auto-repairable by row deletion — the fix is to resume the merge
        // (re-run `merge-kg` with the same `--source-key`), so `repair_action`
        // is None.
        for (id, source_key, phase) in self.list_incomplete_merges().await? {
            issues.push(DetectedDbIssue {
                issue: DbValidationIssue {
                    table: "merge_status",
                    row_key: format!("id={id} source_key={source_key}"),
                    problem: format!(
                        "incomplete merge (phase={phase}, expected 'link'); resume it by \
                         re-running merge-kg with --source-key {source_key}"
                    ),
                },
                repair_action: None,
            });
        }

        issues.sort_by(|lhs, rhs| {
            lhs.issue
                .table
                .cmp(rhs.issue.table)
                .then_with(|| lhs.issue.row_key.cmp(&rhs.issue.row_key))
                .then_with(|| lhs.issue.problem.cmp(&rhs.issue.problem))
        });

        Ok(issues)
    }

    // ── Write (atomic project completion) ───────────────────────────

    /// Atomically write a completed project with its categories, semantic nodes,
    /// functions, and merge decisions.
    /// Commit one project's full merge output to the historical KG.
    /// Begins its own transaction, calls
    /// [`Self::write_project_completed_txn`], commits, and discards
    /// the new-canonical id list. Use this when the caller doesn't
    /// need to compose additional writes inside the same
    /// transaction; bulk learn paths (`learn moves` / `learn c4` /
    /// `learn projects`) go through here because they don't run
    /// retro-link and therefore don't need to enqueue
    /// `pending_semantic`.
    pub async fn write_project_completed(
        &self,
        name: &str,
        platform_id: Option<&str>,
        categories: &[crate::category::DeFiCategory],
        semantic_merge_results: &[crate::learn::MergeResult],
        finding_merge_results: &[crate::learn::FindingMergeResult],
        in_project_links: &crate::learn::InProjectLinks,
    ) -> Result<()> {
        let txn = self.begin().await?;
        self.write_project_completed_txn(
            &txn,
            name,
            platform_id,
            categories,
            semantic_merge_results,
            finding_merge_results,
            in_project_links,
        )
        .await?;
        txn.commit().await?;
        Ok(())
    }

    /// Transaction-scoped variant of
    /// [`Self::write_project_completed`]. Writes every row this
    /// project contributes (project / project_platform /
    /// project_category / semantic_node / semantic_function /
    /// semantic_merge / project_semantic / audit_finding /
    /// project_finding / audit_finding_category / finding_merge /
    /// in-project semantic_finding_link) into the supplied
    /// transaction.
    ///
    /// Does NOT touch `pending_semantic` — that side of the
    /// "retro-link work queue" is a separate concern and only
    /// `workflow learn` (the incremental flow) calls
    /// [`Self::enqueue_pending_canonical_semantics_txn`] alongside
    /// this. See `crates/knowdit/src/cmd/learn/retro_link.rs` for
    /// the responsibility table.
    ///
    /// Returns the canonical semantic ids this project newly
    /// introduced (i.e. `MergeAction::New` entries from the
    /// supplied merge results). The caller is responsible for
    /// passing them to
    /// [`Self::enqueue_pending_canonical_semantics_txn`] if their
    /// flow runs retro-link.
    pub async fn write_project_completed_txn(
        &self,
        conn: &DatabaseTransaction,
        name: &str,
        platform_id: Option<&str>,
        categories: &[crate::category::DeFiCategory],
        semantic_merge_results: &[crate::learn::MergeResult],
        finding_merge_results: &[crate::learn::FindingMergeResult],
        in_project_links: &crate::learn::InProjectLinks,
    ) -> Result<Vec<i32>> {
        use crate::learn::{FindingMergeAction, MergeAction};

        // Upsert project — look up by platform_id first, then by name
        let existing_project = if let Some(pid) = platform_id {
            let pp = project_platform::Entity::find()
                .filter(project_platform::Column::PlatformId.eq(pid))
                .one(conn)
                .await?;
            if let Some(pp) = pp {
                project::Entity::find_by_id(pp.project_id).one(conn).await?
            } else {
                None
            }
        } else {
            project::Entity::find()
                .filter(project::Column::Name.eq(name))
                .one(conn)
                .await?
        };

        let project_id = if let Some(p) = existing_project {
            let mut am = p.into_active_model();
            am.status = Set("completed".to_string());
            let updated = am.update(conn).await?;
            updated.id
        } else {
            let am = project::ActiveModel {
                name: Set(name.to_string()),
                status: Set("completed".to_string()),
                ..Default::default()
            };
            let inserted = project::Entity::insert(am).exec(conn).await?;
            inserted.last_insert_id
        };

        // Insert platform mapping if provided and not already present
        if let Some(pid) = platform_id {
            let existing_pp = project_platform::Entity::find()
                .filter(project_platform::Column::ProjectId.eq(project_id))
                .one(conn)
                .await?;
            if existing_pp.is_none() {
                let pp = project_platform::ActiveModel {
                    project_id: Set(project_id),
                    platform_id: Set(pid.to_string()),
                    ..Default::default()
                };
                project_platform::Entity::insert(pp).exec(conn).await?;
            }
        }

        // Link project to categories
        for cat_name in categories {
            let cat = category::Entity::find()
                .filter(category::Column::Name.eq(*cat_name))
                .one(conn)
                .await?;

            if let Some(cat) = cat {
                let existing = project_category::Entity::find()
                    .filter(project_category::Column::ProjectId.eq(project_id))
                    .filter(project_category::Column::CategoryId.eq(cat.id))
                    .one(conn)
                    .await?;

                if existing.is_none() {
                    let link = project_category::ActiveModel {
                        project_id: Set(project_id),
                        category_id: Set(cat.id),
                    };
                    project_category::Entity::insert(link).exec(conn).await?;
                }
            } else {
                tracing::warn!("Category '{}' not found in DB", cat_name);
            }
        }

        // Track raw row ids per `semantic_merge_results` / `finding_merge_results`
        // index. The InProjectLinks edges reference these positions, and the
        // final block at the bottom of this transaction translates the index
        // pairs into actual `semantic_finding_link` rows.
        let mut raw_semantic_id_by_idx: Vec<i32> = Vec::with_capacity(semantic_merge_results.len());
        let mut raw_finding_id_by_idx: Vec<i32> = Vec::with_capacity(finding_merge_results.len());
        // Newly-introduced canonical semantic ids (action == New) — these
        // populate `pending_semantic` so the retro-link pass during the
        // incremental learn flow can attach existing findings to them.
        let mut new_canonical_semantic_ids: Vec<i32> = Vec::new();

        // Process merge results
        let mut new_semantic_count = 0;
        let mut merged_semantic_count = 0;

        // Inserts a project_semantic row if the (project, semantic) pair is
        // not yet present. Idempotent under the composite primary key.
        async fn upsert_project_semantic<C: ConnectionTrait>(
            txn: &C,
            project_id: i32,
            semantic_node_id: i32,
        ) -> Result<()> {
            let existing = project_semantic::Entity::find()
                .filter(project_semantic::Column::ProjectId.eq(project_id))
                .filter(project_semantic::Column::SemanticNodeId.eq(semantic_node_id))
                .one(txn)
                .await?;
            if existing.is_none() {
                project_semantic::Entity::insert(project_semantic::ActiveModel {
                    project_id: Set(project_id),
                    semantic_node_id: Set(semantic_node_id),
                })
                .exec(txn)
                .await?;
            }
            Ok(())
        }

        for result in semantic_merge_results {
            match &result.action {
                MergeAction::New => {
                    let node = semantic_node::ActiveModel {
                        name: Set(result.semantic.name.clone()),
                        category: Set(result.semantic.category),
                        definition: Set(result.semantic.definition.clone()),
                        description: Set(result.semantic.description.clone()),
                        ..Default::default()
                    };
                    let inserted = semantic_node::Entity::insert(node).exec(conn).await?;
                    let node_id = inserted.last_insert_id;

                    upsert_project_semantic(conn, project_id, node_id).await?;
                    raw_semantic_id_by_idx.push(node_id);
                    new_canonical_semantic_ids.push(node_id);

                    for func in &result.semantic.functions {
                        let f = semantic_function::ActiveModel {
                            semantic_node_id: Set(node_id),
                            function_name: Set(func.name.clone()),
                            contract_path: Set(func.contract.clone()),
                            ..Default::default()
                        };
                        semantic_function::Entity::insert(f).exec(conn).await?;
                    }

                    new_semantic_count += 1;
                }
                MergeAction::Merge {
                    target_ids,
                    updated_description,
                    appended_description,
                } => {
                    // Insert the new raw semantic once, then write one
                    // `semantic_merge` row per target canonical (multi-
                    // target merge). The canonical's `name` and
                    // `definition` are stable identity and are NEVER
                    // modified by a merge; only `description` may be
                    // replaced with the agent's generalization.
                    let node = semantic_node::ActiveModel {
                        name: Set(result.semantic.name.clone()),
                        category: Set(result.semantic.category),
                        definition: Set(result.semantic.definition.clone()),
                        description: Set(result.semantic.description.clone()),
                        ..Default::default()
                    };
                    let inserted = semantic_node::Entity::insert(node).exec(conn).await?;
                    let new_id = inserted.last_insert_id;
                    upsert_project_semantic(conn, project_id, new_id).await?;
                    raw_semantic_id_by_idx.push(new_id);

                    for func in &result.semantic.functions {
                        let f = semantic_function::ActiveModel {
                            semantic_node_id: Set(new_id),
                            function_name: Set(func.name.clone()),
                            contract_path: Set(func.contract.clone()),
                            ..Default::default()
                        };
                        semantic_function::Entity::insert(f).exec(conn).await?;
                    }

                    for target_id in target_ids {
                        let target = semantic_node::Entity::find_by_id(*target_id)
                            .one(conn)
                            .await?
                            .ok_or_else(|| {
                                KgError::other(format!(
                                    "Semantic merge target sem-{} does not exist while writing project '{}'",
                                    target_id, name
                                ))
                            })?;

                        // Project provenance grows on the canonical too:
                        // every merged-away raw contributed by some project
                        // surfaces as a project_semantic edge on the canonical.
                        upsert_project_semantic(conn, project_id, *target_id).await?;

                        let merge = semantic_merge::ActiveModel {
                            from_semantic_id: Set(new_id),
                            to_semantic_id: Set(*target_id),
                            appended_description: Set(appended_description
                                .as_deref()
                                .unwrap_or("")
                                .trim()
                                .to_string()),
                        };
                        semantic_merge::Entity::insert(merge).exec(conn).await?;

                        // Persist the agent's validated concrete-representative
                        // description (the emit tool rejects over-generalized /
                        // over-long values before they reach here); never touch
                        // name or definition. `None`/blank keeps the existing.
                        if let Some(updated) = updated_description {
                            let trimmed = updated.trim();
                            if !trimmed.is_empty() {
                                let mut am = target.into_active_model();
                                am.description = Set(trimmed.to_string());
                                am.update(conn).await?;
                            }
                        }
                    }

                    merged_semantic_count += 1;
                }
            }
        }

        let mut new_finding_count = 0;
        let mut merged_finding_count = 0;

        for result in finding_merge_results {
            let category_row = finding_category::Entity::find()
                .filter(finding_category::Column::Category.eq(result.finding.category))
                .filter(finding_category::Column::Name.eq(result.finding.subcategory.clone()))
                .one(conn)
                .await?
                .ok_or_else(|| {
                    crate::error::KgError::other(format!(
                        "Finding taxonomy entry missing for '{} / {}'",
                        result.finding.category, result.finding.subcategory
                    ))
                })?;

            let finding = audit_finding::ActiveModel {
                title: Set(result.finding.title.clone()),
                severity: Set(result.finding.severity),
                root_cause: Set(result.finding.root_cause.clone()),
                description: Set(result.finding.description.clone()),
                patterns: Set(result.finding.patterns.clone()),
                exploits: Set(result.finding.exploits.clone()),
                ..Default::default()
            };
            let inserted = audit_finding::Entity::insert(finding).exec(conn).await?;
            let finding_id = inserted.last_insert_id;
            raw_finding_id_by_idx.push(finding_id);

            // Always record the (project, raw finding) provenance edge.
            project_finding::Entity::insert(project_finding::ActiveModel {
                project_id: Set(project_id),
                audit_finding_id: Set(finding_id),
            })
            .exec(conn)
            .await?;

            let finding_category_link = audit_finding_category::ActiveModel {
                audit_finding_id: Set(finding_id),
                finding_category_id: Set(category_row.id),
            };
            audit_finding_category::Entity::insert(finding_category_link)
                .exec(conn)
                .await?;

            match &result.action {
                FindingMergeAction::New => {
                    new_finding_count += 1;
                }
                FindingMergeAction::Merge {
                    target_ids,
                    updated_description,
                    updated_patterns,
                    updated_exploits,
                    appended_description,
                    appended_patterns,
                    appended_exploits,
                } => {
                    // Multi-target merge: one finding_merge row per
                    // canonical the agent decided this raw should fold
                    // into. Canonical's `title`, `severity`, and
                    // `root_cause` are stable identity and are NEVER
                    // modified by a merge; only `description`,
                    // `patterns`, `exploits` may be replaced with the
                    // agent's generalization.
                    for target_id in target_ids {
                        let target = audit_finding::Entity::find_by_id(*target_id)
                            .one(conn)
                            .await?
                            .ok_or_else(|| {
                                KgError::other(format!(
                                    "Finding merge target finding-{} does not exist while writing project '{}'",
                                    target_id, name
                                ))
                            })?;

                        let merge = finding_merge::ActiveModel {
                            from_finding_id: Set(finding_id),
                            to_finding_id: Set(*target_id),
                            appended_description: Set(appended_description
                                .as_deref()
                                .unwrap_or("")
                                .trim()
                                .to_string()),
                            appended_patterns: Set(appended_patterns
                                .as_deref()
                                .unwrap_or("")
                                .trim()
                                .to_string()),
                            appended_exploits: Set(appended_exploits
                                .as_deref()
                                .unwrap_or("")
                                .trim()
                                .to_string()),
                        };
                        finding_merge::Entity::insert(merge).exec(conn).await?;

                        let already = project_finding::Entity::find()
                            .filter(project_finding::Column::ProjectId.eq(project_id))
                            .filter(project_finding::Column::AuditFindingId.eq(*target_id))
                            .one(conn)
                            .await?;
                        if already.is_none() {
                            project_finding::Entity::insert(project_finding::ActiveModel {
                                project_id: Set(project_id),
                                audit_finding_id: Set(*target_id),
                            })
                            .exec(conn)
                            .await?;
                        }

                        // Replace description / patterns / exploits with the
                        // agent's generalizations (each covers the canonical +
                        // this raw); never touch title / severity /
                        // root_cause. `None`/blank keeps the existing value.
                        let mut touched = false;
                        let mut am = target.into_active_model();
                        if let Some(updated) = updated_description {
                            let trimmed = updated.trim();
                            if !trimmed.is_empty() {
                                am.description = Set(trimmed.to_string());
                                touched = true;
                            }
                        }
                        if let Some(updated) = updated_patterns {
                            let trimmed = updated.trim();
                            if !trimmed.is_empty() {
                                am.patterns = Set(trimmed.to_string());
                                touched = true;
                            }
                        }
                        if let Some(updated) = updated_exploits {
                            let trimmed = updated.trim();
                            if !trimmed.is_empty() {
                                am.exploits = Set(trimmed.to_string());
                                touched = true;
                            }
                        }
                        if touched {
                            am.update(conn).await?;
                        }
                    }

                    merged_finding_count += 1;
                }
            }
        }

        // ── In-project linking → semantic_finding_link rows ────────
        // Translate each `(finding_idx, semantic_idx)` edge into a row
        // attached to the *raw* (just-inserted) finding/semantic ids.
        // After merge, raw rows still hold their links; the mapper's
        // raw-chase later surfaces them when the canonical is matched.
        let mut in_project_link_rows = 0usize;
        for (finding_idx, semantic_idx) in &in_project_links.edges {
            let raw_finding_id = *raw_finding_id_by_idx.get(*finding_idx).ok_or_else(|| {
                KgError::other(format!(
                    "in-project link references missing finding index {} for project '{}'",
                    finding_idx, name
                ))
            })?;
            let raw_semantic_id = *raw_semantic_id_by_idx.get(*semantic_idx).ok_or_else(|| {
                KgError::other(format!(
                    "in-project link references missing semantic index {} for project '{}'",
                    semantic_idx, name
                ))
            })?;
            let already = semantic_finding_link::Entity::find()
                .filter(semantic_finding_link::Column::SemanticNodeId.eq(raw_semantic_id))
                .filter(semantic_finding_link::Column::AuditFindingId.eq(raw_finding_id))
                .one(conn)
                .await?;
            if already.is_none() {
                // In-project links come from the extract pipeline's
                // co-emission of (finding, semantic) within the same
                // project. By construction this is the strongest possible
                // signal — the finding instantiates the semantic in its
                // originating project. Tag as High; evidence is synthetic
                // (no LLM rationale exists for these auto-generated edges).
                semantic_finding_link::Entity::insert(semantic_finding_link::ActiveModel {
                    semantic_node_id: Set(raw_semantic_id),
                    audit_finding_id: Set(raw_finding_id),
                    strength: Set(LinkStrength::High),
                    evidence: Set(format!(
                        "{IN_PROJECT_LINK_EVIDENCE_PREFIX} against the same project; finding \
                         instantiates the semantic in its originating codebase"
                    )),
                })
                .exec(conn)
                .await?;
                in_project_link_rows += 1;
            }
        }

        // NOTE: we do NOT write finding_link_status here. In-project links
        // are intra-project only; the global-link pass still has to attach
        // these findings to canonical semantics from OTHER projects. The
        // global linker writes finding_link_status when it has finished
        // processing each pending finding.
        //
        // We also do NOT enqueue `pending_semantic` here — that's
        // the caller's call. The incremental `workflow learn` flow
        // chains `enqueue_pending_canonical_semantics_txn` on the
        // returned id list inside the same transaction; bulk
        // callers (`learn moves` / `learn c4` / `learn projects`)
        // skip the enqueue because they never run retro-link.

        tracing::info!(
            "Project {} saved: {} new semantics, {} merged semantics, {} new findings, {} merged findings, {} in-project links; {} new canonical id(s) returned for caller-driven pending_semantic enqueue",
            platform_id.unwrap_or(name),
            new_semantic_count,
            merged_semantic_count,
            new_finding_count,
            merged_finding_count,
            in_project_link_rows,
            new_canonical_semantic_ids.len(),
        );
        Ok(new_canonical_semantic_ids)
    }

    /// Append a list of canonical semantic ids to the
    /// `pending_semantic` retro-link queue, deduping per-id against
    /// what's already enqueued. Called by `workflow learn` right
    /// after [`Self::write_project_completed_txn`] inside the SAME
    /// transaction so a kill between project commit and queue
    /// enqueue rolls both writes back.
    ///
    /// Bulk learn paths (`learn moves` / `learn c4` /
    /// `learn projects`) must NOT call this — they never run
    /// retro-link, so populating the queue would leave dead rows
    /// the validator surfaces as a partial-state issue.
    ///
    /// Returns the number of rows actually inserted (i.e. how many
    /// of the supplied ids were not already queued).
    pub async fn enqueue_pending_canonical_semantics_txn(
        &self,
        conn: &DatabaseTransaction,
        canonical_ids: &[i32],
    ) -> Result<usize> {
        let mut enqueued = 0usize;
        for canonical_id in canonical_ids {
            let already = knowdit_kg_model::db::pending_semantic::Entity::find_by_id(*canonical_id)
                .one(conn)
                .await?;
            if already.is_none() {
                knowdit_kg_model::db::pending_semantic::Entity::insert(
                    knowdit_kg_model::db::pending_semantic::ActiveModel {
                        semantic_node_id: Set(*canonical_id),
                    },
                )
                .exec(conn)
                .await?;
                enqueued += 1;
            }
        }
        Ok(enqueued)
    }

    // ── KnowledgeGraph loading ──────────────────────────────────────

    /// Load the full knowledge graph from the database into memory.
    pub async fn load_knowledge_graph(&self) -> Result<crate::knowledge_graph::KnowledgeGraph> {
        let projects = project::Entity::find()
            .filter(project::Column::Status.eq("completed"))
            .all(&self.db)
            .await?;
        let project_platforms = project_platform::Entity::find().all(&self.db).await?;
        let categories = category::Entity::find().all(&self.db).await?;
        let nodes = semantic_node::Entity::find().all(&self.db).await?;
        let semantic_functions = semantic_function::Entity::find().all(&self.db).await?;
        let project_categories = project_category::Entity::find().all(&self.db).await?;
        let project_semantics = project_semantic::Entity::find().all(&self.db).await?;
        let semantic_merges = semantic_merge::Entity::find().all(&self.db).await?;
        let findings = audit_finding::Entity::find().all(&self.db).await?;
        let finding_categories = finding_category::Entity::find().all(&self.db).await?;
        let audit_finding_categories = audit_finding_category::Entity::find().all(&self.db).await?;
        let project_findings = project_finding::Entity::find().all(&self.db).await?;
        // Raw dump — `semantic_finding_link` is NOT filtered against
        // `finding_link_status` here. This loader feeds snapshot
        // export (`export_json_snapshot`) and visualization paths
        // (`export_dot` / `export_html`), all of which want the
        // raw on-disk state to faithfully round-trip / diagnose.
        // Consumer-side partial-link safety lives at
        // `HistoricalDatabaseArgs::connect_init_for_consumer`, not
        // here. The mapper / spec-gen paths go through
        // `findings_for_semantic_ids`, not this function.
        let semantic_finding_links = semantic_finding_link::Entity::find().all(&self.db).await?;
        let finding_link_statuses = finding_link_status::Entity::find().all(&self.db).await?;
        let finding_merges = finding_merge::Entity::find().all(&self.db).await?;

        Ok(crate::knowledge_graph::KnowledgeGraph {
            projects,
            project_platforms,
            categories,
            nodes,
            semantic_functions,
            project_categories,
            project_semantics,
            semantic_merges,
            findings,
            finding_categories,
            audit_finding_categories,
            project_findings,
            semantic_finding_links,
            finding_link_statuses,
            finding_merges,
        })
    }
}

fn redact_database_url(raw_url: &str) -> String {
    let Ok(mut parsed) = url::Url::parse(raw_url) else {
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

fn build_merge_map<I>(pairs: I) -> HashMap<i32, i32>
where
    I: IntoIterator<Item = (i32, i32)>,
{
    pairs.into_iter().collect()
}

fn resolve_merge_target(id: i32, merge_map: &HashMap<i32, i32>) -> i32 {
    let mut current = id;
    let mut seen = HashSet::new();

    while let Some(next) = merge_map.get(&current).copied() {
        if !seen.insert(current) {
            break;
        }
        current = next;
    }

    current
}

fn resolve_merge_target_with_known_nodes(
    id: i32,
    merge_map: &HashMap<i32, i32>,
    known_node_ids: &HashSet<i32>,
) -> i32 {
    let mut current = id;
    let mut seen = HashSet::new();

    while let Some(next) = merge_map.get(&current).copied() {
        if !seen.insert(current) {
            break;
        }
        if !known_node_ids.contains(&next) {
            break;
        }
        current = next;
    }

    current
}

fn materialize_semantic_link_candidates(
    nodes: Vec<semantic_node::Model>,
    merge_map: &HashMap<i32, i32>,
) -> Result<Vec<(semantic_node::Model, i32)>> {
    let node_ids: HashSet<i32> = nodes.iter().map(|node| node.id).collect();
    let mut candidates = Vec::with_capacity(nodes.len());

    for node in nodes {
        let canonical_id = resolve_merge_target_with_known_nodes(node.id, merge_map, &node_ids);
        candidates.push((node, canonical_id));
    }

    candidates.sort_by(|lhs, rhs| lhs.0.id.cmp(&rhs.0.id));
    Ok(candidates)
}

const SNAPSHOT_TABLE_ORDER: &[&str] = &[
    "project",
    "project_platform",
    "category",
    "project_category",
    "semantic_node",
    "semantic_function",
    "semantic_merge",
    "audit_finding",
    "finding_category",
    "audit_finding_category",
    "semantic_finding_link",
    "finding_link_status",
    "finding_merge",
];

fn snapshot_backend_name(backend: DatabaseBackend) -> &'static str {
    match backend {
        DatabaseBackend::MySql => "mysql",
        DatabaseBackend::Sqlite => "sqlite",
        DatabaseBackend::Postgres => "postgres",
        _ => "unknown",
    }
}

fn snapshot_table_rank(table: &str) -> usize {
    SNAPSHOT_TABLE_ORDER
        .iter()
        .position(|candidate| *candidate == table)
        .unwrap_or(SNAPSHOT_TABLE_ORDER.len())
}

fn quote_identifier(backend: DatabaseBackend, identifier: &str) -> String {
    match backend {
        DatabaseBackend::MySql => format!("`{}`", identifier.replace('`', "``")),
        DatabaseBackend::Sqlite | DatabaseBackend::Postgres => {
            format!("\"{}\"", identifier.replace('"', "\"\""))
        }
        _ => format!("\"{}\"", identifier.replace('"', "\"\"")),
    }
}

fn sql_string_literal(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}

fn append_sql_statement(snapshot: &mut String, statement: &str) {
    let trimmed = statement.trim();
    if trimmed.is_empty() {
        return;
    }

    snapshot.push_str(trimmed.trim_end_matches(';'));
    snapshot.push_str(";\n");
}

fn mysql_dump_value_expr(column: &str, data_type: &str) -> String {
    let identifier = quote_identifier(DatabaseBackend::MySql, column);
    if data_type.eq_ignore_ascii_case("bit") {
        return format!(
            "CASE WHEN {identifier} IS NULL THEN 'NULL' ELSE CAST({identifier} + 0 AS CHAR) END"
        );
    }

    if is_mysql_binary_type(data_type) {
        return format!(
            "CASE WHEN {identifier} IS NULL THEN 'NULL' ELSE CONCAT('0x', HEX({identifier})) END"
        );
    }

    format!("CASE WHEN {identifier} IS NULL THEN 'NULL' ELSE QUOTE({identifier}) END")
}

fn is_mysql_binary_type(data_type: &str) -> bool {
    matches!(
        data_type.to_ascii_lowercase().as_str(),
        "binary" | "varbinary" | "blob" | "tinyblob" | "mediumblob" | "longblob"
    )
}

fn split_sql_statements(sql: &str) -> Vec<String> {
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum State {
        Normal,
        SingleQuote,
        DoubleQuote,
        Backtick,
        LineComment,
        BlockComment,
    }

    let chars: Vec<char> = sql.chars().collect();
    let mut current = String::new();
    let mut statements = Vec::new();
    let mut state = State::Normal;
    let mut index = 0;

    while index < chars.len() {
        let ch = chars[index];
        let next = chars.get(index + 1).copied();

        match state {
            State::Normal => match ch {
                '\'' => {
                    current.push(ch);
                    state = State::SingleQuote;
                }
                '"' => {
                    current.push(ch);
                    state = State::DoubleQuote;
                }
                '`' => {
                    current.push(ch);
                    state = State::Backtick;
                }
                ';' => {
                    let trimmed = current.trim();
                    if !trimmed.is_empty() {
                        statements.push(trimmed.to_string());
                    }
                    current.clear();
                }
                '-' if next == Some('-') && starts_line_comment(&chars, index) => {
                    state = State::LineComment;
                    index += 1;
                }
                '#' => {
                    state = State::LineComment;
                }
                '/' if next == Some('*') => {
                    state = State::BlockComment;
                    index += 1;
                }
                _ => current.push(ch),
            },
            State::SingleQuote => {
                current.push(ch);
                if ch == '\\' {
                    if let Some(escaped) = next {
                        current.push(escaped);
                        index += 1;
                    }
                } else if ch == '\'' {
                    if next == Some('\'') {
                        current.push('\'');
                        index += 1;
                    } else {
                        state = State::Normal;
                    }
                }
            }
            State::DoubleQuote => {
                current.push(ch);
                if ch == '\\' {
                    if let Some(escaped) = next {
                        current.push(escaped);
                        index += 1;
                    }
                } else if ch == '"' {
                    if next == Some('"') {
                        current.push('"');
                        index += 1;
                    } else {
                        state = State::Normal;
                    }
                }
            }
            State::Backtick => {
                current.push(ch);
                if ch == '`' {
                    if next == Some('`') {
                        current.push('`');
                        index += 1;
                    } else {
                        state = State::Normal;
                    }
                }
            }
            State::LineComment => {
                if ch == '\n' {
                    current.push('\n');
                    state = State::Normal;
                }
            }
            State::BlockComment => {
                if ch == '*' && next == Some('/') {
                    current.push(' ');
                    state = State::Normal;
                    index += 1;
                }
            }
        }

        index += 1;
    }

    let trimmed = current.trim();
    if !trimmed.is_empty() {
        statements.push(trimmed.to_string());
    }

    statements
}

fn starts_line_comment(chars: &[char], index: usize) -> bool {
    matches!(chars.get(index + 2), None | Some(' ' | '\t' | '\r' | '\n'))
}

// ── merge-kg: read source canonicals / import them into a destination ───
//
// These types + methods back `crate::merge_kg`, which merges one historical
// KG into another with semantic dedup. The merge *decisions* (which source
// canonical folds into which destination canonical) are computed by the
// reusable merge agents; the writer here only persists them, upholding the
// one-level `semantic_merge` / `finding_merge` invariant: every imported
// source canonical enters as a *fresh leaf* and folds via a single edge to a
// destination canonical (never a chain).

fn non_empty(s: &Option<String>) -> Option<&str> {
    s.as_deref().map(str::trim).filter(|t| !t.is_empty())
}

/// One source-KG canonical semantic prepared for import, carrying the merge
/// decision already computed by [`crate::agents::SemanticMerger`].
#[derive(Debug, Clone)]
pub struct MergeImportSemantic {
    /// Source-KG `semantic_node.id` (used only to build the src→dst id map).
    pub src_id: i32,
    pub semantic: crate::learn::ExtractedSemantic,
    /// Destination canonical ids to fold into. Empty ⇒ admit as a fresh
    /// destination canonical (this row becomes the survivor).
    pub target_ids: Vec<i32>,
    /// Full replacement description for the fold target(s); `None` keeps theirs.
    pub updated_description: Option<String>,
    /// Merge-edge note (how this raw extends the canonical), written to each
    /// `semantic_merge` edge this import creates.
    pub appended_description: Option<String>,
    /// Destination project ids contributing this semantic (provenance).
    pub provenance: Vec<i32>,
}

/// One source-KG canonical finding prepared for import.
#[derive(Debug, Clone)]
pub struct MergeImportFinding {
    pub src_id: i32,
    pub finding: crate::learn::ExtractedFinding,
    pub target_ids: Vec<i32>,
    pub updated_description: Option<String>,
    pub updated_patterns: Option<String>,
    pub updated_exploits: Option<String>,
    /// Merge-edge notes (how this raw extends the canonical's description /
    /// patterns / exploits), written to each `finding_merge` edge this import
    /// creates.
    pub appended_description: Option<String>,
    pub appended_patterns: Option<String>,
    pub appended_exploits: Option<String>,
    pub provenance: Vec<i32>,
}

/// One source-KG `semantic_finding_link` to carry over verbatim (no LLM).
/// Ids are source-KG ids; the writer remaps them through the src→dst maps
/// built while importing nodes and silently drops any edge whose endpoints
/// were not imported (e.g. a link onto a source raw node we didn't replay).
#[derive(Debug, Clone)]
pub struct MergeImportLink {
    pub src_finding_id: i32,
    pub src_semantic_id: i32,
    pub strength: LinkStrength,
    pub evidence: String,
}

/// Result of [`HistoricalDatabase::import_merged_canonicals`].
#[derive(Debug, Default)]
pub struct MergeImportOutcome {
    /// src semantic id → dst inserted row id.
    pub sem_map: HashMap<i32, i32>,
    /// src finding id → dst inserted row id.
    pub find_map: HashMap<i32, i32>,
    /// dst canonical semantic ids that were admitted as New (action == New).
    /// These feed the retro-link (③a) `pending_semantic` queue.
    pub new_canonical_semantic_ids: Vec<i32>,
    /// dst finding ids admitted as New — the ③b link pass targets these.
    pub new_finding_ids: Vec<i32>,
    /// dst finding ids that folded into an existing canonical — marked
    /// link-complete so the partial-link integrity check stays satisfied.
    pub folded_finding_ids: Vec<i32>,
    pub new_semantics: usize,
    pub folded_semantics: usize,
    pub new_findings: usize,
    pub folded_findings: usize,
    pub carried_links: usize,
    /// `merge_status.id` of the row inserted for this import (phase
    /// `'imported'`) inside the same transaction — used to advance the phase
    /// as the retro / ③b passes complete.
    pub merge_status_id: i32,
}

impl HistoricalDatabase {
    /// Largest `semantic_node.id` currently present (None if empty). Used by
    /// `merge_kg` as the source/destination boundary: every imported row gets
    /// a strictly larger auto-increment id, so `id <= this` selects exactly
    /// the destination's pre-import (native) canonicals when scoping the ③b
    /// cross-seam link candidate set.
    pub async fn max_semantic_node_id(&self) -> Result<Option<i32>> {
        Ok(semantic_node::Entity::find()
            .order_by_desc(semantic_node::Column::Id)
            .one(&self.db)
            .await?
            .map(|n| n.id))
    }

    /// Canonical semantics (not merged-away) with their functions.
    pub async fn all_canonical_semantics_with_functions(
        &self,
    ) -> Result<Vec<(semantic_node::Model, Vec<semantic_function::Model>)>> {
        let merged_away: HashSet<i32> = semantic_merge::Entity::find()
            .all(&self.db)
            .await?
            .into_iter()
            .map(|m| m.from_semantic_id)
            .collect();
        let mut out = Vec::new();
        for node in semantic_node::Entity::find().all(&self.db).await? {
            if merged_away.contains(&node.id) {
                continue;
            }
            let funcs = semantic_function::Entity::find()
                .filter(semantic_function::Column::SemanticNodeId.eq(node.id))
                .all(&self.db)
                .await?;
            out.push((node, funcs));
        }
        Ok(out)
    }

    /// Canonical findings (not merged-away) each paired with its
    /// `(category, subcategory)` taxonomy, resolved via
    /// `audit_finding_category` → `finding_category`. Findings without a
    /// taxonomy link are skipped (they cannot be reconstructed as an
    /// `ExtractedFinding`, whose `category`/`subcategory` are required).
    pub async fn all_canonical_findings_with_taxonomy(
        &self,
    ) -> Result<Vec<(audit_finding::Model, VulnerabilityCategory, String)>> {
        let merged_away: HashSet<i32> = finding_merge::Entity::find()
            .all(&self.db)
            .await?
            .into_iter()
            .map(|m| m.from_finding_id)
            .collect();
        let mut out = Vec::new();
        for finding in audit_finding::Entity::find().all(&self.db).await? {
            if merged_away.contains(&finding.id) {
                continue;
            }
            let Some(link) = audit_finding_category::Entity::find()
                .filter(audit_finding_category::Column::AuditFindingId.eq(finding.id))
                .one(&self.db)
                .await?
            else {
                continue;
            };
            let Some(cat) = finding_category::Entity::find_by_id(link.finding_category_id)
                .one(&self.db)
                .await?
            else {
                continue;
            };
            out.push((finding, cat.category, cat.name));
        }
        Ok(out)
    }

    /// Every `semantic_finding_link` row (raw dump, unfiltered).
    pub async fn all_semantic_finding_links(&self) -> Result<Vec<semantic_finding_link::Model>> {
        Ok(semantic_finding_link::Entity::find().all(&self.db).await?)
    }

    /// `semantic_node_id → [project_id]` from `project_semantic`.
    pub async fn project_semantic_provenance(&self) -> Result<HashMap<i32, Vec<i32>>> {
        let mut map: HashMap<i32, Vec<i32>> = HashMap::new();
        for row in project_semantic::Entity::find().all(&self.db).await? {
            map.entry(row.semantic_node_id)
                .or_default()
                .push(row.project_id);
        }
        Ok(map)
    }

    /// `audit_finding_id → [project_id]` from `project_finding`.
    pub async fn project_finding_provenance(&self) -> Result<HashMap<i32, Vec<i32>>> {
        let mut map: HashMap<i32, Vec<i32>> = HashMap::new();
        for row in project_finding::Entity::find().all(&self.db).await? {
            map.entry(row.audit_finding_id)
                .or_default()
                .push(row.project_id);
        }
        Ok(map)
    }

    /// Upsert a source project into this KG for merge provenance, keyed by
    /// `platform_id` when present (else by name). Returns the dst project id.
    pub async fn upsert_import_project(
        &self,
        name: &str,
        platform_id: Option<&str>,
    ) -> Result<i32> {
        let txn = self.db.begin().await?;
        let existing = if let Some(pid) = platform_id {
            match project_platform::Entity::find()
                .filter(project_platform::Column::PlatformId.eq(pid))
                .one(&txn)
                .await?
            {
                Some(pp) => project::Entity::find_by_id(pp.project_id).one(&txn).await?,
                None => None,
            }
        } else {
            project::Entity::find()
                .filter(project::Column::Name.eq(name))
                .one(&txn)
                .await?
        };
        let project_id = if let Some(p) = existing {
            p.id
        } else {
            let inserted = project::Entity::insert(project::ActiveModel {
                name: Set(name.to_string()),
                status: Set("completed".to_string()),
                ..Default::default()
            })
            .exec(&txn)
            .await?;
            let new_id = inserted.last_insert_id;
            if let Some(pid) = platform_id {
                project_platform::Entity::insert(project_platform::ActiveModel {
                    project_id: Set(new_id),
                    platform_id: Set(pid.to_string()),
                    ..Default::default()
                })
                .exec(&txn)
                .await?;
            }
            new_id
        };
        txn.commit().await?;
        Ok(project_id)
    }

    async fn upsert_project_semantic_row<C: ConnectionTrait>(
        conn: &C,
        project_id: i32,
        semantic_node_id: i32,
    ) -> Result<()> {
        if project_semantic::Entity::find()
            .filter(project_semantic::Column::ProjectId.eq(project_id))
            .filter(project_semantic::Column::SemanticNodeId.eq(semantic_node_id))
            .one(conn)
            .await?
            .is_none()
        {
            project_semantic::Entity::insert(project_semantic::ActiveModel {
                project_id: Set(project_id),
                semantic_node_id: Set(semantic_node_id),
            })
            .exec(conn)
            .await?;
        }
        Ok(())
    }

    async fn upsert_project_finding_row<C: ConnectionTrait>(
        conn: &C,
        project_id: i32,
        audit_finding_id: i32,
    ) -> Result<()> {
        if project_finding::Entity::find()
            .filter(project_finding::Column::ProjectId.eq(project_id))
            .filter(project_finding::Column::AuditFindingId.eq(audit_finding_id))
            .one(conn)
            .await?
            .is_none()
        {
            project_finding::Entity::insert(project_finding::ActiveModel {
                project_id: Set(project_id),
                audit_finding_id: Set(audit_finding_id),
            })
            .exec(conn)
            .await?;
        }
        Ok(())
    }

    /// Atomically persist Phases 1–3 of a KG merge: import the deduped source
    /// canonicals (semantics then findings), fold duplicates one level into
    /// the destination canonicals, carry provenance, then carry the source's
    /// `semantic_finding_link` edges remapped through the src→dst id maps.
    /// Enqueues the New canonical semantics for retro-link and marks folded
    /// findings link-complete. Returns the maps + counts.
    pub async fn import_merged_canonicals(
        &self,
        semantics: &[MergeImportSemantic],
        findings: &[MergeImportFinding],
        links: &[MergeImportLink],
        source_key: &str,
        native_sem_ceiling: Option<i32>,
    ) -> Result<MergeImportOutcome> {
        let txn = self.db.begin().await?;
        let mut out = MergeImportOutcome::default();

        // ---- semantics ----
        for item in semantics {
            let inserted = semantic_node::Entity::insert(semantic_node::ActiveModel {
                name: Set(item.semantic.name.clone()),
                category: Set(item.semantic.category),
                definition: Set(item.semantic.definition.clone()),
                description: Set(item.semantic.description.clone()),
                ..Default::default()
            })
            .exec(&txn)
            .await?;
            let node_id = inserted.last_insert_id;
            out.sem_map.insert(item.src_id, node_id);

            for func in &item.semantic.functions {
                semantic_function::Entity::insert(semantic_function::ActiveModel {
                    semantic_node_id: Set(node_id),
                    function_name: Set(func.name.clone()),
                    contract_path: Set(func.contract.clone()),
                    ..Default::default()
                })
                .exec(&txn)
                .await?;
            }

            if item.target_ids.is_empty() {
                out.new_canonical_semantic_ids.push(node_id);
                out.new_semantics += 1;
            } else {
                out.folded_semantics += 1;
                for target_id in &item.target_ids {
                    // One-level: node_id is a fresh leaf; target is a dst canonical.
                    semantic_merge::Entity::insert(semantic_merge::ActiveModel {
                        from_semantic_id: Set(node_id),
                        to_semantic_id: Set(*target_id),
                        appended_description: Set(non_empty(&item.appended_description)
                            .unwrap_or("")
                            .to_string()),
                    })
                    .exec(&txn)
                    .await?;
                    if let Some(updated) = non_empty(&item.updated_description)
                        && let Some(target) = semantic_node::Entity::find_by_id(*target_id)
                            .one(&txn)
                            .await?
                    {
                        // Replace the canonical's description with the merge
                        // agent's generalization; identity fields untouched.
                        let mut am = target.into_active_model();
                        am.description = Set(updated.to_string());
                        am.update(&txn).await?;
                    }
                }
            }

            for &pid in &item.provenance {
                Self::upsert_project_semantic_row(&txn, pid, node_id).await?;
                for &target_id in &item.target_ids {
                    Self::upsert_project_semantic_row(&txn, pid, target_id).await?;
                }
            }
        }

        self.enqueue_pending_canonical_semantics_txn(&txn, &out.new_canonical_semantic_ids)
            .await?;

        // ---- findings ----
        for item in findings {
            let Some(category_id) = finding_category::Entity::find()
                .filter(finding_category::Column::Category.eq(item.finding.category))
                .filter(finding_category::Column::Name.eq(item.finding.subcategory.clone()))
                .one(&txn)
                .await?
                .map(|r| r.id)
            else {
                return Err(KgError::other(format!(
                    "finding taxonomy entry missing for '{} / {}' while importing merged KG",
                    item.finding.category, item.finding.subcategory,
                )));
            };

            let inserted = audit_finding::Entity::insert(audit_finding::ActiveModel {
                title: Set(item.finding.title.clone()),
                severity: Set(item.finding.severity),
                root_cause: Set(item.finding.root_cause.clone()),
                description: Set(item.finding.description.clone()),
                patterns: Set(item.finding.patterns.clone()),
                exploits: Set(item.finding.exploits.clone()),
                ..Default::default()
            })
            .exec(&txn)
            .await?;
            let finding_id = inserted.last_insert_id;
            out.find_map.insert(item.src_id, finding_id);

            audit_finding_category::Entity::insert(audit_finding_category::ActiveModel {
                audit_finding_id: Set(finding_id),
                finding_category_id: Set(category_id),
            })
            .exec(&txn)
            .await?;

            if item.target_ids.is_empty() {
                out.new_finding_ids.push(finding_id);
                out.new_findings += 1;
            } else {
                out.folded_finding_ids.push(finding_id);
                out.folded_findings += 1;
                for target_id in &item.target_ids {
                    finding_merge::Entity::insert(finding_merge::ActiveModel {
                        from_finding_id: Set(finding_id),
                        to_finding_id: Set(*target_id),
                        appended_description: Set(non_empty(&item.appended_description)
                            .unwrap_or("")
                            .to_string()),
                        appended_patterns: Set(non_empty(&item.appended_patterns)
                            .unwrap_or("")
                            .to_string()),
                        appended_exploits: Set(non_empty(&item.appended_exploits)
                            .unwrap_or("")
                            .to_string()),
                    })
                    .exec(&txn)
                    .await?;
                    if let Some(target) = audit_finding::Entity::find_by_id(*target_id)
                        .one(&txn)
                        .await?
                    {
                        // Replace description / patterns / exploits with the
                        // merge agent's generalizations; identity untouched.
                        let mut am = target.into_active_model();
                        let mut touched = false;
                        if let Some(updated) = non_empty(&item.updated_description) {
                            am.description = Set(updated.to_string());
                            touched = true;
                        }
                        if let Some(updated) = non_empty(&item.updated_patterns) {
                            am.patterns = Set(updated.to_string());
                            touched = true;
                        }
                        if let Some(updated) = non_empty(&item.updated_exploits) {
                            am.exploits = Set(updated.to_string());
                            touched = true;
                        }
                        if touched {
                            am.update(&txn).await?;
                        }
                    }
                }
            }

            for &pid in &item.provenance {
                Self::upsert_project_finding_row(&txn, pid, finding_id).await?;
                for &target_id in &item.target_ids {
                    Self::upsert_project_finding_row(&txn, pid, target_id).await?;
                }
            }
        }

        // ---- structural link carry (verbatim, no LLM) ----
        for link in links {
            let (Some(&fid), Some(&sid)) = (
                out.find_map.get(&link.src_finding_id),
                out.sem_map.get(&link.src_semantic_id),
            ) else {
                continue;
            };
            let exists = semantic_finding_link::Entity::find()
                .filter(semantic_finding_link::Column::SemanticNodeId.eq(sid))
                .filter(semantic_finding_link::Column::AuditFindingId.eq(fid))
                .one(&txn)
                .await?
                .is_some();
            if !exists {
                semantic_finding_link::Entity::insert(semantic_finding_link::ActiveModel {
                    semantic_node_id: Set(sid),
                    audit_finding_id: Set(fid),
                    strength: Set(link.strength),
                    evidence: Set(link.evidence.clone()),
                })
                .exec(&txn)
                .await?;
                out.carried_links += 1;
            }
        }

        // Folded findings are not visited by the ③b link pass; mark them
        // link-complete so the partial-link integrity check tolerates the
        // `semantic_finding_link` rows just carried onto them.
        for &fid in &out.folded_finding_ids {
            if finding_link_status::Entity::find_by_id(fid)
                .one(&txn)
                .await?
                .is_none()
            {
                finding_link_status::Entity::insert(finding_link_status::ActiveModel {
                    audit_finding_id: Set(fid),
                })
                .exec(&txn)
                .await?;
            }
        }

        // Progress marker, written in the SAME transaction as the imported
        // data: "import committed ⟺ this row exists". A re-run finds it (via
        // `get_active_merge`) and skips straight to the resumable link passes
        // instead of re-importing (duplicating).
        let inserted = merge_status::Entity::insert(merge_status::ActiveModel {
            source_key: Set(source_key.to_string()),
            native_sem_ceiling: Set(native_sem_ceiling),
            phase: Set(MergePhase::Imported),
            ..Default::default()
        })
        .exec(&txn)
        .await?;
        out.merge_status_id = inserted.last_insert_id;

        txn.commit().await?;
        Ok(out)
    }

    /// Latest still-running merge for `source_key` (phase != `Link`), for
    /// resume detection. `None` ⇒ start a fresh merge.
    pub async fn get_active_merge(
        &self,
        source_key: &str,
    ) -> Result<Option<(i32, Option<i32>, MergePhase)>> {
        Ok(merge_status::Entity::find()
            .filter(merge_status::Column::SourceKey.eq(source_key))
            .filter(merge_status::Column::Phase.ne(MergePhase::Link))
            .order_by_desc(merge_status::Column::Id)
            .one(&self.db)
            .await?
            .map(|m| (m.id, m.native_sem_ceiling, m.phase)))
    }

    /// Advance a merge row's phase (`Imported` → `Retro` → `Link`).
    pub async fn set_merge_phase(&self, id: i32, phase: MergePhase) -> Result<()> {
        let mut am: merge_status::ActiveModel = merge_status::Entity::find_by_id(id)
            .one(&self.db)
            .await?
            .ok_or_else(|| KgError::other(format!("merge_status id={id} not found")))?
            .into();
        am.phase = Set(phase);
        am.update(&self.db).await?;
        Ok(())
    }

    /// All incomplete merges (phase != `Link`), for `validate_db` to surface a
    /// half-merged KG. Returns `(id, source_key, phase)`.
    pub async fn list_incomplete_merges(&self) -> Result<Vec<(i32, String, MergePhase)>> {
        Ok(merge_status::Entity::find()
            .filter(merge_status::Column::Phase.ne(MergePhase::Link))
            .order_by_asc(merge_status::Column::Id)
            .all(&self.db)
            .await?
            .into_iter()
            .map(|m| (m.id, m.source_key, m.phase))
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::time::{SystemTime, UNIX_EPOCH};

    fn sample_semantic_node(id: i32, category: DeFiCategory, name: &str) -> semantic_node::Model {
        semantic_node::Model {
            id,
            name: name.to_string(),
            definition: format!("Definition for {}", name),
            description: format!("Description for {}", name),
            category,
        }
    }

    #[test]
    fn redact_database_url_removes_credentials() {
        assert_eq!(
            redact_database_url("mysql://alice:secret@example.com:3306/knowdit?ssl-mode=required"),
            "mysql://example.com:3306/knowdit?ssl-mode=required"
        );
        assert_eq!(
            redact_database_url("mysql://alice@example.com/knowdit"),
            "mysql://example.com/knowdit"
        );
        assert_eq!(
            redact_database_url("sqlite:///tmp/knowdit.sqlite?mode=rwc"),
            "sqlite:///tmp/knowdit.sqlite?mode=rwc"
        );
        assert_eq!(
            redact_database_url("not a database url"),
            "<unparseable database url>"
        );
    }

    #[test]
    fn materialize_semantic_link_candidates_falls_back_to_existing_node_when_canonical_missing() {
        let merge_map = HashMap::from([(101, 8)]);

        let candidates = materialize_semantic_link_candidates(
            vec![sample_semantic_node(101, DeFiCategory::Dexes, "Alias 101")],
            &merge_map,
        )
        .expect("candidates should fall back when the canonical node is absent");

        assert_eq!(
            candidates
                .into_iter()
                .map(|(node, canonical_id)| (node.id, canonical_id, node.category))
                .collect::<Vec<_>>(),
            vec![(101, 101, DeFiCategory::Dexes)]
        );
    }

    #[test]
    fn materialize_semantic_link_candidates_accepts_cross_category_canonical_node() {
        let merge_map = HashMap::from([(101, 8)]);

        let candidates = materialize_semantic_link_candidates(
            vec![
                sample_semantic_node(101, DeFiCategory::Dexes, "Alias 101"),
                sample_semantic_node(8, DeFiCategory::Yield, "Canonical 8"),
            ],
            &merge_map,
        )
        .expect("candidates should accept canonical nodes from another category");

        assert_eq!(
            candidates
                .into_iter()
                .map(|(node, canonical_id)| (node.id, canonical_id, node.category))
                .collect::<Vec<_>>(),
            vec![(8, 8, DeFiCategory::Yield), (101, 8, DeFiCategory::Dexes),]
        );
    }

    #[test]
    fn split_sql_statements_ignores_comments_and_preserves_quoted_semicolons() {
        let sql = r#"
-- snapshot header;
CREATE TABLE "demo" ("value" TEXT);
INSERT INTO "demo" ("value") VALUES ('semi;colon');
/* block; comment */
INSERT INTO "demo" ("value") VALUES ('quote '' inside');
INSERT INTO `demo` (`value`) VALUES ('backslash \' quote');
"#;

        assert_eq!(
            split_sql_statements(sql),
            vec![
                "CREATE TABLE \"demo\" (\"value\" TEXT)",
                "INSERT INTO \"demo\" (\"value\") VALUES ('semi;colon')",
                "INSERT INTO \"demo\" (\"value\") VALUES ('quote '' inside')",
                "INSERT INTO `demo` (`value`) VALUES ('backslash \\\' quote')",
            ]
        );
    }

    #[test]
    fn materialize_semantic_link_candidates_falls_back_to_last_existing_merge_target() {
        let merge_map = HashMap::from([(101, 8), (8, 999999)]);

        let candidates = materialize_semantic_link_candidates(
            vec![
                sample_semantic_node(101, DeFiCategory::Dexes, "Alias 101"),
                sample_semantic_node(8, DeFiCategory::Yield, "Intermediate 8"),
            ],
            &merge_map,
        )
        .expect("candidates should stop at the last existing merge target");

        assert_eq!(
            candidates
                .into_iter()
                .map(|(node, canonical_id)| (node.id, canonical_id, node.category))
                .collect::<Vec<_>>(),
            vec![(8, 8, DeFiCategory::Yield), (101, 8, DeFiCategory::Dexes),]
        );
    }

    async fn create_test_db() -> (HistoricalDatabase, PathBuf) {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time should be after epoch")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "knowdit-db-test-{}-{}.sqlite",
            std::process::id(),
            unique
        ));
        let url = format!("sqlite://{}?mode=rwc", path.to_string_lossy());
        let db = HistoricalDatabase::connect(&url)
            .await
            .expect("test db should connect");
        db.init().await.expect("test db should initialize");
        (db, path)
    }

    fn cleanup_test_db(path: &Path) {
        let _ = fs::remove_file(path);
        let _ = fs::remove_file(format!("{}-wal", path.display()));
        let _ = fs::remove_file(format!("{}-shm", path.display()));
    }

    fn sample_extracted_semantic(
        name: &str,
        category: DeFiCategory,
    ) -> crate::learn::ExtractedSemantic {
        crate::learn::ExtractedSemantic {
            name: name.to_string(),
            category,
            definition: format!("def {name}"),
            description: format!("desc {name}"),
            functions: vec![crate::learn::ExtractedFunction {
                name: "f".to_string(),
                contract: "m::c".to_string(),
                signature: None,
            }],
        }
    }

    fn sample_extracted_finding(
        title: &str,
        category: VulnerabilityCategory,
        subcategory: String,
    ) -> crate::learn::ExtractedFinding {
        crate::learn::ExtractedFinding {
            title: title.to_string(),
            severity: audit_finding::FindingSeverity::High,
            category,
            subcategory,
            root_cause: "rc".to_string(),
            description: "d".to_string(),
            patterns: "p".to_string(),
            exploits: "e".to_string(),
        }
    }

    /// Exercises the mechanical merge-kg writer end-to-end (no LLM): folding a
    /// source canonical into an existing destination canonical must stay
    /// *one level*, carried links must surface under the fold via raw-chase,
    /// and folded findings must be marked link-complete.
    #[tokio::test]
    async fn import_merged_canonicals_folds_one_level_and_carries_links() {
        let (db, path) = create_test_db().await;

        // Destination provenance project + a pre-existing canonical semantic
        // (the merge target) + a pre-existing finding (a fold target).
        let dst_project = project::Entity::insert(project::ActiveModel {
            name: Set("dst-proj".to_string()),
            status: Set("completed".to_string()),
            ..Default::default()
        })
        .exec(&db.db)
        .await
        .unwrap()
        .last_insert_id;

        let existing_canonical = semantic_node::Entity::insert(semantic_node::ActiveModel {
            name: Set("AMM Swap".to_string()),
            category: Set(DeFiCategory::Dexes),
            definition: Set("x*y=k".to_string()),
            description: Set("swap".to_string()),
            ..Default::default()
        })
        .exec(&db.db)
        .await
        .unwrap()
        .last_insert_id;

        let tax = finding_category::Entity::find()
            .one(&db.db)
            .await
            .unwrap()
            .expect("seeded finding taxonomy should be non-empty");

        let existing_finding = audit_finding::Entity::insert(audit_finding::ActiveModel {
            title: Set("existing finding".to_string()),
            severity: Set(audit_finding::FindingSeverity::High),
            root_cause: Set("rc".to_string()),
            description: Set("d".to_string()),
            patterns: Set("p".to_string()),
            exploits: Set("e".to_string()),
            ..Default::default()
        })
        .exec(&db.db)
        .await
        .unwrap()
        .last_insert_id;
        audit_finding_category::Entity::insert(audit_finding_category::ActiveModel {
            audit_finding_id: Set(existing_finding),
            finding_category_id: Set(tax.id),
        })
        .exec(&db.db)
        .await
        .unwrap();

        // Decisions are pre-made here (the LLM merge agents are bypassed):
        //   sem 1000 folds into existing_canonical; sem 1001 is New.
        //   finding 2000 is New (linked in source to sem 1000);
        //   finding 2001 folds into existing_finding.
        let semantics = vec![
            MergeImportSemantic {
                src_id: 1000,
                semantic: sample_extracted_semantic("AMM Swap v2", DeFiCategory::Dexes),
                target_ids: vec![existing_canonical],
                updated_description: Some("generalized AMM swap".to_string()),
                appended_description: Some("adds an oracle-gated swap path".to_string()),
                provenance: vec![dst_project],
            },
            MergeImportSemantic {
                src_id: 1001,
                semantic: sample_extracted_semantic("Flash Loan", DeFiCategory::Dexes),
                target_ids: vec![],
                updated_description: None,
                appended_description: None,
                provenance: vec![dst_project],
            },
        ];
        let findings = vec![
            MergeImportFinding {
                src_id: 2000,
                finding: sample_extracted_finding("K broken", tax.category, tax.name.clone()),
                target_ids: vec![],
                updated_description: None,
                updated_patterns: None,
                updated_exploits: None,
                appended_description: None,
                appended_patterns: None,
                appended_exploits: None,
                provenance: vec![dst_project],
            },
            MergeImportFinding {
                src_id: 2001,
                finding: sample_extracted_finding("rounding", tax.category, tax.name.clone()),
                target_ids: vec![existing_finding],
                updated_description: None,
                updated_patterns: None,
                updated_exploits: None,
                appended_description: Some("adds fee-on-transfer rounding drift".to_string()),
                appended_patterns: Some("adds a fee-on-transfer balance check".to_string()),
                appended_exploits: Some("no new exploit vector beyond the canonical".to_string()),
                provenance: vec![dst_project],
            },
        ];
        let links = vec![MergeImportLink {
            src_finding_id: 2000,
            src_semantic_id: 1000,
            strength: LinkStrength::High,
            evidence: "carried".to_string(),
        }];

        let sem_ceiling = db.max_semantic_node_id().await.unwrap();
        let outcome = db
            .import_merged_canonicals(&semantics, &findings, &links, "test-source", sem_ceiling)
            .await
            .unwrap();

        // ── import writes the resume marker in-txn (phase Imported) ──
        assert!(outcome.merge_status_id > 0);
        let active = db.get_active_merge("test-source").await.unwrap();
        assert_eq!(
            active,
            Some((outcome.merge_status_id, sem_ceiling, MergePhase::Imported)),
            "import must record an in-progress merge_status row keyed by source_key"
        );

        let folded_sem = outcome.sem_map[&1000];
        let new_sem = outcome.sem_map[&1001];
        let new_finding = outcome.find_map[&2000];
        let folded_finding = outcome.find_map[&2001];

        assert_eq!(outcome.new_semantics, 1);
        assert_eq!(outcome.folded_semantics, 1);
        assert_eq!(outcome.new_findings, 1);
        assert_eq!(outcome.folded_findings, 1);
        assert_eq!(outcome.carried_links, 1);
        assert_eq!(outcome.new_canonical_semantic_ids, vec![new_sem]);

        // ── one-level invariant: no node is both a merge source and target ──
        let sem_merges = semantic_merge::Entity::find().all(&db.db).await.unwrap();
        let froms: HashSet<i32> = sem_merges.iter().map(|m| m.from_semantic_id).collect();
        let tos: HashSet<i32> = sem_merges.iter().map(|m| m.to_semantic_id).collect();
        assert!(
            froms.is_disjoint(&tos),
            "semantic_merge must stay one level (no chains): {sem_merges:?}"
        );
        assert_eq!(
            sem_merges,
            vec![semantic_merge::Model {
                from_semantic_id: folded_sem,
                to_semantic_id: existing_canonical,
                appended_description: "adds an oracle-gated swap path".to_string(),
            }]
        );
        assert!(
            !froms.contains(&new_sem),
            "the New semantic must be canonical"
        );

        let find_merges = finding_merge::Entity::find().all(&db.db).await.unwrap();
        assert_eq!(
            find_merges,
            vec![finding_merge::Model {
                from_finding_id: folded_finding,
                to_finding_id: existing_finding,
                appended_description: "adds fee-on-transfer rounding drift".to_string(),
                appended_patterns: "adds a fee-on-transfer balance check".to_string(),
                appended_exploits: "no new exploit vector beyond the canonical".to_string(),
            }]
        );

        // ── carried link surfaces under the folded canonical via raw-chase ──
        let linked = db
            .findings_for_semantic_ids(&[existing_canonical])
            .await
            .unwrap();
        assert_eq!(linked.len(), 1);
        assert_eq!(linked[0].finding.id, new_finding);
        assert_eq!(linked[0].canonical_semantic_id, existing_canonical);

        // ── merge REPLACES the canonical description (not append) ──
        let enriched = semantic_node::Entity::find_by_id(existing_canonical)
            .one(&db.db)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(enriched.description, "generalized AMM swap");

        // ── folded finding marked link-complete (partial-link check safe) ──
        assert!(
            finding_link_status::Entity::find_by_id(folded_finding)
                .one(&db.db)
                .await
                .unwrap()
                .is_some()
        );

        // ── provenance carried onto both the leaf and the canonical ──
        let prov: HashSet<i32> = project_semantic::Entity::find()
            .filter(project_semantic::Column::SemanticNodeId.eq(existing_canonical))
            .all(&db.db)
            .await
            .unwrap()
            .into_iter()
            .map(|r| r.project_id)
            .collect();
        assert!(prov.contains(&dst_project));

        cleanup_test_db(&path);
    }

    /// The merge-kg resume state machine at the db layer: import records an
    /// in-progress `merge_status` row, `validate_db` surfaces it as incomplete,
    /// phase advances imported → retro → link, and reaching `'link'` clears it
    /// from both `get_active_merge` (resume lookup) and `validate_db`.
    #[tokio::test]
    async fn merge_status_tracks_resume_lifecycle() {
        let (db, path) = create_test_db().await;

        // A minimal (empty-payload) import still writes the resume marker.
        let outcome = db
            .import_merged_canonicals(&[], &[], &[], "src-a", None)
            .await
            .unwrap();
        let id = outcome.merge_status_id;
        assert!(id > 0);

        // Fresh import ⇒ an active (phase != Link) merge for this source_key.
        assert_eq!(
            db.get_active_merge("src-a").await.unwrap(),
            Some((id, None, MergePhase::Imported))
        );
        assert!(db.get_active_merge("other-source").await.unwrap().is_none());
        assert_eq!(
            db.list_incomplete_merges().await.unwrap(),
            vec![(id, "src-a".to_string(), MergePhase::Imported)]
        );

        // validate_db flags the half-finished merge (not auto-repairable).
        let report = db.validate_db(false).await.unwrap();
        assert!(
            report
                .remaining_issues
                .iter()
                .any(|issue| issue.table == "merge_status"),
            "an incomplete merge must be reported by validate_db: {report:?}"
        );

        // Imported → Retro: still active, phase advanced.
        db.set_merge_phase(id, MergePhase::Retro).await.unwrap();
        assert_eq!(
            db.get_active_merge("src-a").await.unwrap(),
            Some((id, None, MergePhase::Retro))
        );

        // Retro → Link: fully complete ⇒ no longer active / incomplete / flagged.
        db.set_merge_phase(id, MergePhase::Link).await.unwrap();
        assert!(db.get_active_merge("src-a").await.unwrap().is_none());
        assert!(db.list_incomplete_merges().await.unwrap().is_empty());
        let clean = db.validate_db(false).await.unwrap();
        assert!(
            !clean
                .remaining_issues
                .iter()
                .any(|issue| issue.table == "merge_status"),
            "a completed merge must not be reported: {clean:?}"
        );

        cleanup_test_db(&path);
    }

    #[tokio::test]
    async fn validate_db_reports_and_repairs_dangling_semantic_merge() {
        let (db, path) = create_test_db().await;

        let project_id = project::Entity::insert(project::ActiveModel {
            name: Set("Validation Test Project".to_string()),
            status: Set("completed".to_string()),
            ..Default::default()
        })
        .exec(&db.db)
        .await
        .expect("project insert should succeed")
        .last_insert_id;

        let semantic_id = semantic_node::Entity::insert(semantic_node::ActiveModel {
            name: Set("Dangling Merge Source".to_string()),
            category: Set(DeFiCategory::Dexes),
            definition: Set("Definition".to_string()),
            description: Set("Description".to_string()),
            ..Default::default()
        })
        .exec(&db.db)
        .await
        .expect("semantic node insert should succeed")
        .last_insert_id;

        // Insert a deliberately-dangling merge (legacy data) to exercise
        // validate_db's repair. `PRAGMA foreign_keys` is per-connection, so
        // pin the toggle and the insert to a single pooled connection — under
        // the multi-connection pool they'd otherwise land on different
        // connections and the insert would hit the FK the toggle meant to lift.
        {
            use sea_orm::sqlx;
            let pool = db.db.get_sqlite_connection_pool();
            let mut conn = pool.acquire().await.expect("acquire pooled connection");
            sqlx::query("PRAGMA foreign_keys=OFF")
                .execute(&mut *conn)
                .await
                .expect("should disable foreign key enforcement for legacy-data test");
            sqlx::query(
                "INSERT INTO semantic_merge (from_semantic_id, to_semantic_id, appended_description) VALUES (?, ?, '')",
            )
            .bind(semantic_id)
            .bind(999999_i32)
            .execute(&mut *conn)
            .await
            .expect("dangling semantic merge insert should succeed");
            sqlx::query("PRAGMA foreign_keys=ON")
                .execute(&mut *conn)
                .await
                .expect("should re-enable foreign key enforcement after legacy-data setup");
        }

        let report = db
            .validate_db(false)
            .await
            .expect("validation should succeed");
        assert_eq!(report.detected_issue_count(), 1);
        assert_eq!(report.remaining_issue_count(), 1);
        assert_eq!(report.remaining_issues[0].table, "semantic_merge");
        assert!(
            report.remaining_issues[0]
                .problem
                .contains("missing target semantic sem-999999"),
            "unexpected issue: {}",
            report.remaining_issues[0]
        );

        let repair_report = db.validate_db(true).await.expect("repair should succeed");
        assert_eq!(repair_report.detected_issue_count(), 1);
        assert_eq!(repair_report.repaired_rows, 1);
        assert!(repair_report.is_clean());
        assert!(
            semantic_merge::Entity::find()
                .all(&db.db)
                .await
                .expect("semantic merges should load")
                .is_empty()
        );

        drop(db);
        cleanup_test_db(&path);
    }

    #[tokio::test]
    async fn write_project_completed_does_not_touch_pending_semantic() {
        // Bulk learn paths (`learn moves` / `learn c4` /
        // `learn projects`) call the single-step
        // `write_project_completed` wrapper. The bug fix splits the
        // enqueue out into a separate caller-driven step, so the
        // single-step path must NOT populate `pending_semantic`.
        // This test guards against future drift.
        let (db, path) = create_test_db().await;

        let project_id = project::Entity::insert(project::ActiveModel {
            name: Set("Bulk-mode test".to_string()),
            status: Set("pending".to_string()),
            ..Default::default()
        })
        .exec(&db.db)
        .await
        .expect("project insert should succeed")
        .last_insert_id;
        let _ = project_id;

        let semantic_extract = crate::learn::ExtractedSemantic {
            name: "TestSem".to_string(),
            category: DeFiCategory::Dexes,
            definition: "A test definition".to_string(),
            description: "A test description".to_string(),
            functions: vec![],
        };
        let merge_results = vec![crate::learn::MergeResult {
            semantic: semantic_extract,
            action: crate::learn::MergeAction::New,
        }];

        db.write_project_completed(
            "Bulk-mode test",
            None,
            &[DeFiCategory::Dexes],
            &merge_results,
            &[],
            &crate::learn::InProjectLinks::default(),
        )
        .await
        .expect("write_project_completed should succeed");

        let pending = knowdit_kg_model::db::pending_semantic::Entity::find()
            .all(&db.db)
            .await
            .expect("pending_semantic should load");
        assert_eq!(
            pending.len(),
            0,
            "single-step write_project_completed must NOT enqueue pending_semantic; \
             that's the workflow learn-only path's job. Got {} row(s)",
            pending.len(),
        );

        drop(db);
        cleanup_test_db(&path);
    }

    #[tokio::test]
    async fn write_project_completed_txn_plus_enqueue_writes_pending_semantic() {
        // Incremental `workflow learn` composes
        // `write_project_completed_txn` + `enqueue_pending_canonical_semantics_txn`
        // in one transaction. This is the path that SHOULD populate
        // `pending_semantic` for Phase 2 retro-link to consume.
        let (db, path) = create_test_db().await;

        let semantic_extract = crate::learn::ExtractedSemantic {
            name: "IncrSem".to_string(),
            category: DeFiCategory::Lending,
            definition: "Inc def".to_string(),
            description: "Inc desc".to_string(),
            functions: vec![],
        };
        let merge_results = vec![crate::learn::MergeResult {
            semantic: semantic_extract,
            action: crate::learn::MergeAction::New,
        }];

        let txn = db.begin().await.expect("begin should succeed");
        let new_canonicals = db
            .write_project_completed_txn(
                &txn,
                "Incremental test",
                None,
                &[DeFiCategory::Lending],
                &merge_results,
                &[],
                &crate::learn::InProjectLinks::default(),
            )
            .await
            .expect("write_project_completed_txn should succeed");
        assert_eq!(new_canonicals.len(), 1, "one new canonical expected");
        let enqueued = db
            .enqueue_pending_canonical_semantics_txn(&txn, &new_canonicals)
            .await
            .expect("enqueue should succeed");
        assert_eq!(enqueued, 1);
        txn.commit().await.expect("commit should succeed");

        let pending = knowdit_kg_model::db::pending_semantic::Entity::find()
            .all(&db.db)
            .await
            .expect("pending_semantic should load");
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].semantic_node_id, new_canonicals[0]);

        drop(db);
        cleanup_test_db(&path);
    }

    #[tokio::test]
    async fn validate_db_reports_pending_semantic_queue_without_repair() {
        // Non-empty `pending_semantic` means Phase 2 retro-link did
        // not finish. validator must flag it — the per-finding
        // partial detector wouldn't (no sfl rows or all involved
        // findings already in finding_link_status).
        let (db, path) = create_test_db().await;

        let semantic_id = semantic_node::Entity::insert(semantic_node::ActiveModel {
            name: Set("Pending retro-link semantic".to_string()),
            category: Set(DeFiCategory::Dexes),
            definition: Set("def".to_string()),
            description: Set("desc".to_string()),
            ..Default::default()
        })
        .exec(&db.db)
        .await
        .expect("semantic insert should succeed")
        .last_insert_id;

        knowdit_kg_model::db::pending_semantic::Entity::insert(
            knowdit_kg_model::db::pending_semantic::ActiveModel {
                semantic_node_id: Set(semantic_id),
            },
        )
        .exec(&db.db)
        .await
        .expect("pending_semantic insert should succeed");

        let report = db
            .validate_db(false)
            .await
            .expect("validation should succeed");
        assert_eq!(report.remaining_issue_count(), 1);
        assert_eq!(report.remaining_issues[0].table, "pending_semantic");
        assert!(
            report.remaining_issues[0]
                .problem
                .contains("queued for retro-link"),
            "unexpected issue: {}",
            report.remaining_issues[0]
        );

        // Repair shouldn't auto-delete pending rows — fix is to
        // re-run learn, not to silently drop semantics.
        let repair_report = db.validate_db(true).await.expect("repair should succeed");
        assert_eq!(repair_report.repaired_rows, 0);
        assert_eq!(repair_report.remaining_issue_count(), 1);

        drop(db);
        cleanup_test_db(&path);
    }

    #[tokio::test]
    async fn validate_db_reports_partial_link_without_repair() {
        // sfl row exists for finding-X but finding_link_status does not
        // → "partial link state", reported but NOT auto-repairable.
        let (db, path) = create_test_db().await;

        let semantic_id = semantic_node::Entity::insert(semantic_node::ActiveModel {
            name: Set("Partial Link Source".to_string()),
            category: Set(DeFiCategory::Dexes),
            definition: Set("Definition".to_string()),
            description: Set("Description".to_string()),
            ..Default::default()
        })
        .exec(&db.db)
        .await
        .expect("semantic node insert should succeed")
        .last_insert_id;

        let finding_id = audit_finding::Entity::insert(audit_finding::ActiveModel {
            title: Set("Partial link finding".to_string()),
            severity: Set(audit_finding::FindingSeverity::Medium),
            root_cause: Set("Cause".to_string()),
            description: Set("Description".to_string()),
            patterns: Set("Pattern".to_string()),
            exploits: Set("Exploit".to_string()),
            ..Default::default()
        })
        .exec(&db.db)
        .await
        .expect("finding insert should succeed")
        .last_insert_id;

        semantic_finding_link::Entity::insert(semantic_finding_link::ActiveModel {
            semantic_node_id: Set(semantic_id),
            audit_finding_id: Set(finding_id),
            strength: Set(LinkStrength::High),
            evidence: Set("test evidence".to_string()),
        })
        .exec(&db.db)
        .await
        .expect("sfl insert should succeed");

        // No finding_link_status row → partial state.
        let report = db
            .validate_db(false)
            .await
            .expect("validation should succeed");
        assert_eq!(report.detected_issue_count(), 1);
        assert_eq!(report.remaining_issue_count(), 1);
        assert_eq!(report.remaining_issues[0].table, "finding_link_status");
        assert!(
            report.remaining_issues[0]
                .problem
                .contains("partial link state"),
            "unexpected issue: {}",
            report.remaining_issues[0]
        );

        // Repair should NOT delete the sfl row — partial state needs the
        // linker to finish, not row deletion. `remaining_issues` stays.
        let repair_report = db.validate_db(true).await.expect("repair should succeed");
        assert_eq!(repair_report.detected_issue_count(), 1);
        assert_eq!(repair_report.repaired_rows, 0);
        assert_eq!(repair_report.remaining_issue_count(), 1);
        assert_eq!(
            semantic_finding_link::Entity::find()
                .all(&db.db)
                .await
                .expect("sfl should load")
                .len(),
            1
        );

        // Adding the fls row clears the issue.
        finding_link_status::Entity::insert(finding_link_status::ActiveModel {
            audit_finding_id: Set(finding_id),
        })
        .exec(&db.db)
        .await
        .expect("fls insert should succeed");
        let clean = db
            .validate_db(false)
            .await
            .expect("validation should succeed");
        assert!(clean.is_clean(), "{:?}", clean.remaining_issues);

        drop(db);
        cleanup_test_db(&path);
    }

    #[tokio::test]
    async fn sql_snapshot_roundtrip_restores_sqlite_database() {
        let (db, source_path) = create_test_db().await;

        let project_id = project::Entity::insert(project::ActiveModel {
            name: Set("Project 'alpha'; v1".to_string()),
            status: Set("completed".to_string()),
            ..Default::default()
        })
        .exec(&db.db)
        .await
        .expect("project insert should succeed")
        .last_insert_id;

        let semantic_id = semantic_node::Entity::insert(semantic_node::ActiveModel {
            name: Set("Liquidity Pool".to_string()),
            definition: Set("Tracks pools with newline\nand quote ' markers".to_string()),
            description: Set("Backslash \\ and semicolon ; stay intact".to_string()),
            category: Set(DeFiCategory::Dexes),
            ..Default::default()
        })
        .exec(&db.db)
        .await
        .expect("semantic insert should succeed")
        .last_insert_id;

        let finding_id = audit_finding::Entity::insert(audit_finding::ActiveModel {
            title: Set("Finding 'one'; critical path".to_string()),
            severity: Set(audit_finding::FindingSeverity::High),
            root_cause: Set("Unchecked path".to_string()),
            description: Set("Description with newline\nand quote ' text".to_string()),
            patterns: Set("Pattern A".to_string()),
            exploits: Set("Exploit B".to_string()),
            ..Default::default()
        })
        .exec(&db.db)
        .await
        .expect("finding insert should succeed")
        .last_insert_id;

        semantic_finding_link::Entity::insert(semantic_finding_link::ActiveModel {
            semantic_node_id: Set(semantic_id),
            audit_finding_id: Set(finding_id),
            strength: Set(LinkStrength::High),
            evidence: Set("test evidence".to_string()),
        })
        .exec(&db.db)
        .await
        .expect("link insert should succeed");

        let snapshot = db
            .export_sql_snapshot()
            .await
            .expect("snapshot export should succeed");
        assert!(snapshot.contains("CREATE TABLE \"project\""));
        assert!(snapshot.contains("INSERT INTO \"project\""));

        let restore_unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time should be after epoch")
            .as_nanos();
        let restore_path = std::env::temp_dir().join(format!(
            "knowdit-db-restore-test-{}-{}.sqlite",
            std::process::id(),
            restore_unique
        ));
        let restore_url = format!("sqlite://{}?mode=rwc", restore_path.to_string_lossy());
        let restored = HistoricalDatabase::connect(&restore_url)
            .await
            .expect("restore db should connect");

        let statement_count = restored
            .import_sql_snapshot(&snapshot)
            .await
            .expect("snapshot import should succeed");
        assert!(statement_count > 0);

        let restored_projects = project::Entity::find()
            .all(&restored.db)
            .await
            .expect("projects should load");
        assert!(
            restored_projects
                .iter()
                .any(|project| project.name == "Project 'alpha'; v1")
        );

        let restored_semantic = semantic_node::Entity::find_by_id(semantic_id)
            .one(&restored.db)
            .await
            .expect("semantic lookup should succeed")
            .expect("semantic should exist after restore");
        assert_eq!(
            restored_semantic.definition,
            "Tracks pools with newline\nand quote ' markers"
        );
        assert_eq!(
            restored_semantic.description,
            "Backslash \\ and semicolon ; stay intact"
        );

        let restored_finding = audit_finding::Entity::find_by_id(finding_id)
            .one(&restored.db)
            .await
            .expect("finding lookup should succeed")
            .expect("finding should exist after restore");
        assert_eq!(restored_finding.title, "Finding 'one'; critical path");
        assert_eq!(
            semantic_finding_link::Entity::find()
                .all(&restored.db)
                .await
                .expect("links should load")
                .len(),
            1
        );

        drop(restored);
        drop(db);
        cleanup_test_db(&source_path);
        cleanup_test_db(&restore_path);
    }

    #[tokio::test]
    async fn json_snapshot_roundtrip_restores_sqlite_database() {
        let (db, source_path) = create_test_db().await;

        let project_id = project::Entity::insert(project::ActiveModel {
            name: Set("Project json roundtrip".to_string()),
            status: Set("completed".to_string()),
            ..Default::default()
        })
        .exec(&db.db)
        .await
        .expect("project insert should succeed")
        .last_insert_id;

        let semantic_id = semantic_node::Entity::insert(semantic_node::ActiveModel {
            name: Set("Bridge Escrow".to_string()),
            definition: Set("Escrows funds until settlement".to_string()),
            description: Set(
                "JSON snapshot should preserve quotes ' and newlines\nverbatim".to_string(),
            ),
            category: Set(DeFiCategory::CrossChain),
            ..Default::default()
        })
        .exec(&db.db)
        .await
        .expect("semantic insert should succeed")
        .last_insert_id;

        let finding_id = audit_finding::Entity::insert(audit_finding::ActiveModel {
            title: Set("JSON snapshot finding".to_string()),
            severity: Set(audit_finding::FindingSeverity::Medium),
            root_cause: Set("Cause".to_string()),
            description: Set("Description with ; and newline\ntext".to_string()),
            patterns: Set("Pattern".to_string()),
            exploits: Set("Exploit".to_string()),
            ..Default::default()
        })
        .exec(&db.db)
        .await
        .expect("finding insert should succeed")
        .last_insert_id;

        semantic_finding_link::Entity::insert(semantic_finding_link::ActiveModel {
            semantic_node_id: Set(semantic_id),
            audit_finding_id: Set(finding_id),
            strength: Set(LinkStrength::High),
            evidence: Set("test evidence".to_string()),
        })
        .exec(&db.db)
        .await
        .expect("link insert should succeed");

        // The snapshot loader hides sfl rows whose finding has no
        // matching `finding_link_status` row (partial-commit state),
        // so for this roundtrip test we record the finding as fully
        // processed.
        finding_link_status::Entity::insert(finding_link_status::ActiveModel {
            audit_finding_id: Set(finding_id),
        })
        .exec(&db.db)
        .await
        .expect("finding-link status insert should succeed");

        let snapshot = db
            .export_json_snapshot()
            .await
            .expect("json snapshot export should succeed");
        let expected_graph = db
            .load_knowledge_graph()
            .await
            .expect("knowledge graph load should succeed");
        let parsed: KnowledgeGraph =
            serde_json::from_str(&snapshot).expect("json snapshot should parse");
        assert_eq!(parsed, expected_graph);

        let restore_unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time should be after epoch")
            .as_nanos();
        let restore_path = std::env::temp_dir().join(format!(
            "knowdit-db-json-restore-test-{}-{}.sqlite",
            std::process::id(),
            restore_unique
        ));
        let restore_url = format!("sqlite://{}?mode=rwc", restore_path.to_string_lossy());
        let restored = HistoricalDatabase::connect(&restore_url)
            .await
            .expect("restore db should connect");

        let imported_count = restored
            .import_json_snapshot(&snapshot)
            .await
            .expect("json snapshot import should succeed");
        assert!(imported_count > 0);

        let restored_project = project::Entity::find_by_id(project_id)
            .one(&restored.db)
            .await
            .expect("project lookup should succeed")
            .expect("project should exist after restore");
        assert_eq!(restored_project.name, "Project json roundtrip");

        let restored_semantic = semantic_node::Entity::find_by_id(semantic_id)
            .one(&restored.db)
            .await
            .expect("semantic lookup should succeed")
            .expect("semantic should exist after restore");
        assert_eq!(
            restored_semantic.description,
            "JSON snapshot should preserve quotes ' and newlines\nverbatim"
        );

        assert_eq!(
            semantic_finding_link::Entity::find()
                .all(&restored.db)
                .await
                .expect("links should load")
                .len(),
            1
        );
        assert_eq!(
            restored
                .load_knowledge_graph()
                .await
                .expect("restored graph load should succeed"),
            parsed
        );

        drop(restored);
        drop(db);
        cleanup_test_db(&source_path);
        cleanup_test_db(&restore_path);
    }

    #[tokio::test]
    async fn list_processed_findings_without_semantic_links_returns_processed_unlinked_findings() {
        let (db, path) = create_test_db().await;

        let project_id = project::Entity::insert(project::ActiveModel {
            name: Set("Processed Unlinked Finding Test".to_string()),
            status: Set("completed".to_string()),
            ..Default::default()
        })
        .exec(&db.db)
        .await
        .expect("project insert should succeed")
        .last_insert_id;

        let linked_finding_id = audit_finding::Entity::insert(audit_finding::ActiveModel {
            title: Set("Linked finding".to_string()),
            severity: Set(audit_finding::FindingSeverity::High),
            root_cause: Set("Cause".to_string()),
            description: Set("Description".to_string()),
            patterns: Set("Pattern".to_string()),
            exploits: Set("Exploit".to_string()),
            ..Default::default()
        })
        .exec(&db.db)
        .await
        .expect("linked finding insert should succeed")
        .last_insert_id;

        let unlinked_finding_id = audit_finding::Entity::insert(audit_finding::ActiveModel {
            title: Set("Unlinked finding".to_string()),
            severity: Set(audit_finding::FindingSeverity::Medium),
            root_cause: Set("Cause".to_string()),
            description: Set("Description".to_string()),
            patterns: Set("Pattern".to_string()),
            exploits: Set("Exploit".to_string()),
            ..Default::default()
        })
        .exec(&db.db)
        .await
        .expect("unlinked finding insert should succeed")
        .last_insert_id;

        let semantic_id = semantic_node::Entity::insert(semantic_node::ActiveModel {
            name: Set("Sample Semantic".to_string()),
            category: Set(DeFiCategory::Dexes),
            definition: Set("Definition".to_string()),
            description: Set("Description".to_string()),
            ..Default::default()
        })
        .exec(&db.db)
        .await
        .expect("semantic insert should succeed")
        .last_insert_id;

        semantic_finding_link::Entity::insert(semantic_finding_link::ActiveModel {
            semantic_node_id: Set(semantic_id),
            audit_finding_id: Set(linked_finding_id),
            strength: Set(LinkStrength::High),
            evidence: Set("test evidence".to_string()),
        })
        .exec(&db.db)
        .await
        .expect("semantic-finding link insert should succeed");

        for finding_id in [linked_finding_id, unlinked_finding_id] {
            finding_link_status::Entity::insert(finding_link_status::ActiveModel {
                audit_finding_id: Set(finding_id),
            })
            .exec(&db.db)
            .await
            .expect("finding-link status insert should succeed");
        }

        let findings_without_links = db
            .list_processed_findings_without_semantic_links()
            .await
            .expect("processed unlinked findings should load");

        assert_eq!(findings_without_links, vec![unlinked_finding_id]);

        drop(db);
        cleanup_test_db(&path);
    }

    #[tokio::test]
    async fn list_findings_for_linking_include_unlinked_reincludes_processed_unlinked_findings() {
        let (db, path) = create_test_db().await;

        let project_id = project::Entity::insert(project::ActiveModel {
            name: Set("Include Unlinked Pending Test".to_string()),
            status: Set("completed".to_string()),
            ..Default::default()
        })
        .exec(&db.db)
        .await
        .expect("project insert should succeed")
        .last_insert_id;

        let defi_category_id = category::Entity::find()
            .all(&db.db)
            .await
            .expect("categories should load")
            .into_iter()
            .find(|row| row.name == DeFiCategory::Dexes)
            .expect("dexes category should exist")
            .id;
        project_category::Entity::insert(project_category::ActiveModel {
            project_id: Set(project_id),
            category_id: Set(defi_category_id),
        })
        .exec(&db.db)
        .await
        .expect("project-category link insert should succeed");

        let finding_taxonomy_id = finding_category::Entity::find()
            .all(&db.db)
            .await
            .expect("finding taxonomy should load")
            .into_iter()
            .find(|row| {
                row.category == VulnerabilityCategory::AccessControl
                    && row.name == "Missing Input Validation"
            })
            .expect("missing-input-validation taxonomy should exist")
            .id;

        let finding_id = audit_finding::Entity::insert(audit_finding::ActiveModel {
            title: Set("Processed but unlinked finding".to_string()),
            severity: Set(audit_finding::FindingSeverity::Medium),
            root_cause: Set("Cause".to_string()),
            description: Set("Description".to_string()),
            patterns: Set("Pattern".to_string()),
            exploits: Set("Exploit".to_string()),
            ..Default::default()
        })
        .exec(&db.db)
        .await
        .expect("finding insert should succeed")
        .last_insert_id;

        audit_finding_category::Entity::insert(audit_finding_category::ActiveModel {
            audit_finding_id: Set(finding_id),
            finding_category_id: Set(finding_taxonomy_id),
        })
        .exec(&db.db)
        .await
        .expect("audit-finding taxonomy link insert should succeed");

        finding_link_status::Entity::insert(finding_link_status::ActiveModel {
            audit_finding_id: Set(finding_id),
        })
        .exec(&db.db)
        .await
        .expect("finding-link status insert should succeed");

        let default_pending = db
            .list_pending_findings_for_linking()
            .await
            .expect("default pending findings should load");
        assert!(default_pending.is_empty());

        let include_unlinked_pending = db
            .list_findings_for_linking(true)
            .await
            .expect("include-unlinked findings should load");
        assert_eq!(include_unlinked_pending.len(), 1);
        assert_eq!(include_unlinked_pending[0].finding_id, finding_id);
        assert_eq!(
            include_unlinked_pending[0].link_target_finding_id,
            finding_id
        );

        drop(db);
        cleanup_test_db(&path);
    }

    #[tokio::test]
    async fn list_pending_findings_includes_findings_with_only_in_project_links() {
        // Regression for the pending-detection fix: a finding that already
        // carries an in-project link (written at extraction time) but has NOT
        // been through the global cross-project linker (no `finding_link_status`
        // row) must still be pending. The old code wrongly treated "has any
        // semantic_finding_link row" as "already linked", which made every
        // finding vanish from the linker once in-project linking populated that
        // table.
        let (db, path) = create_test_db().await;

        let project_id = project::Entity::insert(project::ActiveModel {
            name: Set("In-project link pending test".to_string()),
            status: Set("completed".to_string()),
            ..Default::default()
        })
        .exec(&db.db)
        .await
        .expect("project insert should succeed")
        .last_insert_id;

        let defi_category_id = category::Entity::find()
            .all(&db.db)
            .await
            .expect("categories should load")
            .into_iter()
            .find(|row| row.name == DeFiCategory::Dexes)
            .expect("dexes category should exist")
            .id;
        project_category::Entity::insert(project_category::ActiveModel {
            project_id: Set(project_id),
            category_id: Set(defi_category_id),
        })
        .exec(&db.db)
        .await
        .expect("project-category link insert should succeed");

        let finding_taxonomy_id = finding_category::Entity::find()
            .all(&db.db)
            .await
            .expect("finding taxonomy should load")
            .into_iter()
            .find(|row| {
                row.category == VulnerabilityCategory::AccessControl
                    && row.name == "Missing Input Validation"
            })
            .expect("missing-input-validation taxonomy should exist")
            .id;

        let finding_id = audit_finding::Entity::insert(audit_finding::ActiveModel {
            title: Set("Finding with only an in-project link".to_string()),
            severity: Set(audit_finding::FindingSeverity::Medium),
            root_cause: Set("Cause".to_string()),
            description: Set("Description".to_string()),
            patterns: Set("Pattern".to_string()),
            exploits: Set("Exploit".to_string()),
            ..Default::default()
        })
        .exec(&db.db)
        .await
        .expect("finding insert should succeed")
        .last_insert_id;

        audit_finding_category::Entity::insert(audit_finding_category::ActiveModel {
            audit_finding_id: Set(finding_id),
            finding_category_id: Set(finding_taxonomy_id),
        })
        .exec(&db.db)
        .await
        .expect("audit-finding taxonomy link insert should succeed");

        let semantic_id = semantic_node::Entity::insert(semantic_node::ActiveModel {
            name: Set("Own-project semantic".to_string()),
            category: Set(DeFiCategory::Dexes),
            definition: Set("Definition".to_string()),
            description: Set("Description".to_string()),
            ..Default::default()
        })
        .exec(&db.db)
        .await
        .expect("semantic insert should succeed")
        .last_insert_id;

        // An in-project link (the kind written at extraction time). Crucially,
        // no `finding_link_status` row: this finding has NOT been globally linked.
        semantic_finding_link::Entity::insert(semantic_finding_link::ActiveModel {
            semantic_node_id: Set(semantic_id),
            audit_finding_id: Set(finding_id),
            strength: Set(LinkStrength::High),
            evidence: Set(format!("{IN_PROJECT_LINK_EVIDENCE_PREFIX} test")),
        })
        .exec(&db.db)
        .await
        .expect("in-project link insert should succeed");

        // Despite already having a link row, the finding is still pending for
        // the global linker (it is not in finding_link_status).
        let pending = db
            .list_pending_findings_for_linking()
            .await
            .expect("pending findings should load");
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].finding_id, finding_id);

        drop(db);
        cleanup_test_db(&path);
    }

    #[tokio::test]
    async fn list_processed_findings_without_semantic_links_respects_merged_link_targets() {
        let (db, path) = create_test_db().await;

        let project_id = project::Entity::insert(project::ActiveModel {
            name: Set("Merged Finding Link Target Test".to_string()),
            status: Set("completed".to_string()),
            ..Default::default()
        })
        .exec(&db.db)
        .await
        .expect("project insert should succeed")
        .last_insert_id;

        let source_finding_id = audit_finding::Entity::insert(audit_finding::ActiveModel {
            title: Set("Merged source finding".to_string()),
            severity: Set(audit_finding::FindingSeverity::Low),
            root_cause: Set("Cause".to_string()),
            description: Set("Description".to_string()),
            patterns: Set("Pattern".to_string()),
            exploits: Set("Exploit".to_string()),
            ..Default::default()
        })
        .exec(&db.db)
        .await
        .expect("source finding insert should succeed")
        .last_insert_id;

        let target_finding_id = audit_finding::Entity::insert(audit_finding::ActiveModel {
            title: Set("Canonical target finding".to_string()),
            severity: Set(audit_finding::FindingSeverity::High),
            root_cause: Set("Cause".to_string()),
            description: Set("Description".to_string()),
            patterns: Set("Pattern".to_string()),
            exploits: Set("Exploit".to_string()),
            ..Default::default()
        })
        .exec(&db.db)
        .await
        .expect("target finding insert should succeed")
        .last_insert_id;

        let semantic_id = semantic_node::Entity::insert(semantic_node::ActiveModel {
            name: Set("Canonical Semantic".to_string()),
            category: Set(DeFiCategory::Dexes),
            definition: Set("Definition".to_string()),
            description: Set("Description".to_string()),
            ..Default::default()
        })
        .exec(&db.db)
        .await
        .expect("semantic insert should succeed")
        .last_insert_id;

        finding_merge::Entity::insert(finding_merge::ActiveModel {
            from_finding_id: Set(source_finding_id),
            to_finding_id: Set(target_finding_id),
            appended_description: Set(String::new()),
            appended_patterns: Set(String::new()),
            appended_exploits: Set(String::new()),
        })
        .exec(&db.db)
        .await
        .expect("finding merge insert should succeed");

        semantic_finding_link::Entity::insert(semantic_finding_link::ActiveModel {
            semantic_node_id: Set(semantic_id),
            audit_finding_id: Set(target_finding_id),
            strength: Set(LinkStrength::High),
            evidence: Set("test evidence".to_string()),
        })
        .exec(&db.db)
        .await
        .expect("semantic-finding link insert should succeed");

        finding_link_status::Entity::insert(finding_link_status::ActiveModel {
            audit_finding_id: Set(source_finding_id),
        })
        .exec(&db.db)
        .await
        .expect("finding-link status insert should succeed");

        let findings_without_links = db
            .list_processed_findings_without_semantic_links()
            .await
            .expect("processed merged findings should load");

        assert!(findings_without_links.is_empty());

        drop(db);
        cleanup_test_db(&path);
    }

    /// `record_operation` is an idempotent audit log keyed on `(type, args)`:
    /// re-recording identical arguments is a no-op, while a different arg set
    /// or a different operation type yields a distinct row. Also confirms the
    /// stored `args` JSON round-trips back to the exact `Value` inserted (the
    /// basis for the in-Rust dedup comparison).
    #[tokio::test]
    async fn record_operation_dedups_on_type_and_args() {
        let (db, path) = create_test_db().await;

        let args_a = serde_json::json!({"max_agent_steps": 60, "merge_concurrency": 1});
        let args_b = serde_json::json!({"max_agent_steps": 80, "merge_concurrency": 2});

        db.record_operation(OperationType::C4Learn, args_a.clone())
            .await
            .expect("first record should insert");
        // Re-running the same operation with identical args must not duplicate.
        db.record_operation(OperationType::C4Learn, args_a.clone())
            .await
            .expect("duplicate record should be a no-op");
        // Different args under the same type is a distinct operation.
        db.record_operation(OperationType::C4Learn, args_b.clone())
            .await
            .expect("distinct args should insert");
        // Identical args under a different type is also distinct.
        db.record_operation(OperationType::Link, args_a.clone())
            .await
            .expect("distinct type should insert");

        let rows = operation_history::Entity::find()
            .all(&db.db)
            .await
            .expect("operation_history should load");
        assert_eq!(rows.len(), 3, "expected exactly three distinct rows");

        let c4_rows: Vec<_> = rows
            .iter()
            .filter(|r| r.operation_type == OperationType::C4Learn)
            .collect();
        assert_eq!(c4_rows.len(), 2);
        assert!(c4_rows.iter().any(|r| r.args == args_a));
        assert!(c4_rows.iter().any(|r| r.args == args_b));

        let link_rows: Vec<_> = rows
            .iter()
            .filter(|r| r.operation_type == OperationType::Link)
            .collect();
        assert_eq!(link_rows.len(), 1);
        assert_eq!(link_rows[0].args, args_a);

        drop(db);
        cleanup_test_db(&path);
    }
}
