use crate::category::DeFiCategory;
use crate::error::{KgError, Result};
use crate::knowledge_graph::KnowledgeGraph;
use crate::vulnerability::{FINDING_TAXONOMY, VulnerabilityCategory};
use itertools::Itertools;
use knowdit_kg_model::model::{
    audit_finding, audit_finding_category, category, finding_category, finding_link_status,
    finding_merge, project, project_category, project_platform, semantic_finding_link,
    semantic_function, semantic_merge, semantic_node,
};
use sea_orm::{
    ActiveModelTrait,
    ActiveValue::Set,
    ColumnTrait, ConnectionTrait, DatabaseBackend, DatabaseConnection, EntityTrait,
    IntoActiveModel, QueryFilter, Schema, Statement, TransactionTrait,
    sea_query::{ForeignKey, ForeignKeyAction, TableCreateStatement},
};
use std::collections::{HashMap, HashSet};

/// Main database handle wrapping a SeaORM connection.
/// All knowledge-graph queries and mutations go through this struct.
#[derive(Debug, Clone)]
pub struct DatabaseGraph {
    db: DatabaseConnection,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DbValidationIssue {
    pub table: &'static str,
    pub row_key: String,
    pub problem: String,
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
    repair_action: DbValidationRepairAction,
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

impl DatabaseGraph {
    /// Connect to the database and return a new handle.
    pub async fn connect(url: &str) -> Result<Self> {
        use sea_orm::{Database, DatabaseBackend};
        let db = Database::connect(url).await?;
        if db.get_database_backend() == DatabaseBackend::Sqlite {
            db.execute_unprepared("PRAGMA journal_mode=WAL;").await?;
            db.execute_unprepared("PRAGMA foreign_keys=ON;").await?;
        }
        Ok(Self { db })
    }

    // ── Schema / init ───────────────────────────────────────────────

    pub async fn init(&self) -> Result<()> {
        self.create_tables(&self.db, true).await?;
        self.seed_categories().await?;
        self.seed_finding_categories().await?;
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
        ];

        for mut table in tables {
            if if_not_exists {
                table.if_not_exists();
            }
            conn.execute(&table).await?;
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

    async fn seed_categories(&self) -> Result<()> {
        use crate::category::DeFiCategory;

        let existing = category::Entity::find().all(&self.db).await?;
        if !existing.is_empty() {
            return Ok(());
        }

        for cat in DeFiCategory::ALL {
            let am = category::ActiveModel {
                name: Set(*cat),
                ..Default::default()
            };
            category::Entity::insert(am).exec(&self.db).await?;
        }

        tracing::info!("Seeded {} DeFi categories", DeFiCategory::ALL.len());
        Ok(())
    }

    async fn seed_finding_categories(&self) -> Result<()> {
        let existing = finding_category::Entity::find().all(&self.db).await?;
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
            finding_category::Entity::insert(am).exec(&self.db).await?;
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
        let nodes = semantic_node::Entity::find()
            .filter(semantic_node::Column::ProjectId.eq(project_id))
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

        let mut results = Vec::new();
        for node in nodes {
            let proj = project::Entity::find_by_id(node.project_id)
                .one(&self.db)
                .await?
                .map(|p| p.name)
                .unwrap_or_else(|| "unknown".to_string());
            results.push((node, proj));
        }

        Ok(results)
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

    pub async fn list_pending_findings_for_linking(
        &self,
    ) -> Result<Vec<crate::learn::PendingFindingForLinking>> {
        self.list_findings_for_linking(false).await
    }

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

        let processed_ids: HashSet<i32> = finding_link_status::Entity::find()
            .all(&self.db)
            .await?
            .into_iter()
            .map(|status| status.audit_finding_id)
            .collect();
        let already_linked_ids: HashSet<i32> = semantic_finding_link::Entity::find()
            .all(&self.db)
            .await?
            .into_iter()
            .map(|link| link.audit_finding_id)
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

        let mut pending = Vec::new();
        for finding in findings.into_iter().sorted_by_key(|finding| finding.id) {
            let canonical_id = resolve_merge_target(finding.id, &finding_merge_map);
            let canonical_has_links = already_linked_ids.contains(&canonical_id);
            let finding_is_processed = processed_ids.contains(&finding.id);
            if include_unlinked {
                if canonical_has_links {
                    continue;
                }
            } else if finding_is_processed || already_linked_ids.contains(&finding.id) {
                continue;
            }

            let taxonomy = finding_category_by_id.get(&finding.id).ok_or_else(|| {
                KgError::other(format!("Finding {} is missing taxonomy", finding.id))
            })?;

            let mut categories = project_categories_by_project
                .get(&finding.project_id)
                .cloned()
                .unwrap_or_default();
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
        let txn = self.db.begin().await?;

        for &semantic_id in &result.semantic_ids {
            let existing = semantic_finding_link::Entity::find()
                .filter(semantic_finding_link::Column::SemanticNodeId.eq(semantic_id))
                .filter(
                    semantic_finding_link::Column::AuditFindingId.eq(result.link_target_finding_id),
                )
                .one(&txn)
                .await?;

            if existing.is_none() {
                let link = semantic_finding_link::ActiveModel {
                    semantic_node_id: Set(semantic_id),
                    audit_finding_id: Set(result.link_target_finding_id),
                };
                semantic_finding_link::Entity::insert(link)
                    .exec(&txn)
                    .await?;
            }
        }

        let status = finding_link_status::Entity::find_by_id(result.finding_id)
            .one(&txn)
            .await?;
        if status.is_none() {
            let status = finding_link_status::ActiveModel {
                audit_finding_id: Set(result.finding_id),
            };
            finding_link_status::Entity::insert(status)
                .exec(&txn)
                .await?;
        }

        txn.commit().await?;
        tracing::info!(
            "Finding {} processed with {} semantic link(s) targeting finding {}",
            result.finding_id,
            result.semantic_ids.len(),
            result.link_target_finding_id
        );
        Ok(())
    }

    pub async fn list_processed_findings_without_semantic_links(&self) -> Result<Vec<i32>> {
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

    pub async fn clear_finding_link_progress(&self) -> Result<(u64, u64)> {
        let txn = self.db.begin().await?;

        let deleted_links = semantic_finding_link::Entity::delete_many()
            .exec(&txn)
            .await?;
        let deleted_statuses = finding_link_status::Entity::delete_many()
            .exec(&txn)
            .await?;

        txn.commit().await?;
        Ok((deleted_links.rows_affected, deleted_statuses.rows_affected))
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
            repaired_rows += issue.repair_action.execute(&txn).await? as usize;
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
                    repair_action: DbValidationRepairAction::DeleteProjectPlatform { id: row.id },
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
                    repair_action: DbValidationRepairAction::DeleteProjectCategory {
                        project_id: row.project_id,
                        category_id: row.category_id,
                    },
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
                    repair_action: DbValidationRepairAction::DeleteSemanticFunction { id: row.id },
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
                    repair_action: DbValidationRepairAction::DeleteSemanticMerge {
                        from_semantic_id: row.from_semantic_id,
                        to_semantic_id: row.to_semantic_id,
                    },
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
                    repair_action: DbValidationRepairAction::DeleteAuditFindingCategory {
                        audit_finding_id: row.audit_finding_id,
                        finding_category_id: row.finding_category_id,
                    },
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
                    repair_action: DbValidationRepairAction::DeleteSemanticFindingLink {
                        semantic_node_id: row.semantic_node_id,
                        audit_finding_id: row.audit_finding_id,
                    },
                });
            }
        }

        for row in finding_link_status::Entity::find().all(&self.db).await? {
            if !audit_finding_ids.contains(&row.audit_finding_id) {
                issues.push(DetectedDbIssue {
                    issue: DbValidationIssue {
                        table: "finding_link_status",
                        row_key: format!("finding-{}", row.audit_finding_id),
                        problem: format!("missing finding {}", row.audit_finding_id),
                    },
                    repair_action: DbValidationRepairAction::DeleteFindingLinkStatus {
                        audit_finding_id: row.audit_finding_id,
                    },
                });
            }
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
                    repair_action: DbValidationRepairAction::DeleteFindingMerge {
                        from_finding_id: row.from_finding_id,
                        to_finding_id: row.to_finding_id,
                    },
                });
            }
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
    pub async fn write_project_completed(
        &self,
        name: &str,
        platform_id: Option<&str>,
        categories: &[crate::category::DeFiCategory],
        semantic_merge_results: &[crate::learn::MergeResult],
        finding_merge_results: &[crate::learn::FindingMergeResult],
    ) -> Result<()> {
        use crate::learn::{FindingMergeAction, MergeAction};

        let txn = self.db.begin().await?;

        // Upsert project — look up by platform_id first, then by name
        let existing_project = if let Some(pid) = platform_id {
            let pp = project_platform::Entity::find()
                .filter(project_platform::Column::PlatformId.eq(pid))
                .one(&txn)
                .await?;
            if let Some(pp) = pp {
                project::Entity::find_by_id(pp.project_id).one(&txn).await?
            } else {
                None
            }
        } else {
            project::Entity::find()
                .filter(project::Column::Name.eq(name))
                .one(&txn)
                .await?
        };

        let project_id = if let Some(p) = existing_project {
            let mut am = p.into_active_model();
            am.status = Set("completed".to_string());
            let updated = am.update(&txn).await?;
            updated.id
        } else {
            let am = project::ActiveModel {
                name: Set(name.to_string()),
                status: Set("completed".to_string()),
                ..Default::default()
            };
            let inserted = project::Entity::insert(am).exec(&txn).await?;
            inserted.last_insert_id
        };

        // Insert platform mapping if provided and not already present
        if let Some(pid) = platform_id {
            let existing_pp = project_platform::Entity::find()
                .filter(project_platform::Column::ProjectId.eq(project_id))
                .one(&txn)
                .await?;
            if existing_pp.is_none() {
                let pp = project_platform::ActiveModel {
                    project_id: Set(project_id),
                    platform_id: Set(pid.to_string()),
                    ..Default::default()
                };
                project_platform::Entity::insert(pp).exec(&txn).await?;
            }
        }

        // Link project to categories
        for cat_name in categories {
            let cat = category::Entity::find()
                .filter(category::Column::Name.eq(*cat_name))
                .one(&txn)
                .await?;

            if let Some(cat) = cat {
                let existing = project_category::Entity::find()
                    .filter(project_category::Column::ProjectId.eq(project_id))
                    .filter(project_category::Column::CategoryId.eq(cat.id))
                    .one(&txn)
                    .await?;

                if existing.is_none() {
                    let link = project_category::ActiveModel {
                        project_id: Set(project_id),
                        category_id: Set(cat.id),
                    };
                    project_category::Entity::insert(link).exec(&txn).await?;
                }
            } else {
                tracing::warn!("Category '{}' not found in DB", cat_name);
            }
        }

        // Process merge results
        let mut new_semantic_count = 0;
        let mut merged_semantic_count = 0;

        for result in semantic_merge_results {
            match &result.action {
                MergeAction::New => {
                    let node = semantic_node::ActiveModel {
                        name: Set(result.semantic.name.clone()),
                        category: Set(result.semantic.category),
                        definition: Set(result.semantic.definition.clone()),
                        description: Set(result.semantic.description.clone()),
                        project_id: Set(project_id),
                        ..Default::default()
                    };
                    let inserted = semantic_node::Entity::insert(node).exec(&txn).await?;
                    let node_id = inserted.last_insert_id;

                    for func in &result.semantic.functions {
                        let f = semantic_function::ActiveModel {
                            semantic_node_id: Set(node_id),
                            function_name: Set(func.name.clone()),
                            contract_path: Set(func.contract.clone()),
                            ..Default::default()
                        };
                        semantic_function::Entity::insert(f).exec(&txn).await?;
                    }

                    new_semantic_count += 1;
                }
                MergeAction::Merge {
                    target_id,
                    updated_name,
                    updated_definition,
                    updated_description,
                } => {
                    let target = semantic_node::Entity::find_by_id(*target_id)
                        .one(&txn)
                        .await?
                        .ok_or_else(|| {
                            KgError::other(format!(
                                "Semantic merge target sem-{} does not exist while writing project '{}'",
                                target_id, name
                            ))
                        })?;

                    let node = semantic_node::ActiveModel {
                        name: Set(result.semantic.name.clone()),
                        category: Set(result.semantic.category),
                        definition: Set(result.semantic.definition.clone()),
                        description: Set(result.semantic.description.clone()),
                        project_id: Set(project_id),
                        ..Default::default()
                    };
                    let inserted = semantic_node::Entity::insert(node).exec(&txn).await?;
                    let new_id = inserted.last_insert_id;

                    let merge = semantic_merge::ActiveModel {
                        from_semantic_id: Set(new_id),
                        to_semantic_id: Set(*target_id),
                    };
                    semantic_merge::Entity::insert(merge).exec(&txn).await?;

                    let mut am = target.into_active_model();
                    if let Some(name) = updated_name {
                        am.name = Set(name.clone());
                    }
                    if let Some(def) = updated_definition {
                        am.definition = Set(def.clone());
                    }
                    if let Some(desc) = updated_description {
                        am.description = Set(desc.clone());
                    }
                    am.update(&txn).await?;

                    for func in &result.semantic.functions {
                        let f = semantic_function::ActiveModel {
                            semantic_node_id: Set(new_id),
                            function_name: Set(func.name.clone()),
                            contract_path: Set(func.contract.clone()),
                            ..Default::default()
                        };
                        semantic_function::Entity::insert(f).exec(&txn).await?;
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
                .one(&txn)
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
                project_id: Set(project_id),
                ..Default::default()
            };
            let inserted = audit_finding::Entity::insert(finding).exec(&txn).await?;
            let finding_id = inserted.last_insert_id;

            let finding_category_link = audit_finding_category::ActiveModel {
                audit_finding_id: Set(finding_id),
                finding_category_id: Set(category_row.id),
            };
            audit_finding_category::Entity::insert(finding_category_link)
                .exec(&txn)
                .await?;

            match &result.action {
                FindingMergeAction::New => {
                    new_finding_count += 1;
                }
                FindingMergeAction::Merge {
                    target_id,
                    updated_severity,
                    updated_root_cause,
                    updated_description,
                    updated_patterns,
                    updated_exploits,
                } => {
                    let target = audit_finding::Entity::find_by_id(*target_id)
                        .one(&txn)
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
                    };
                    finding_merge::Entity::insert(merge).exec(&txn).await?;

                    let mut am = target.into_active_model();
                    if let Some(severity) = updated_severity {
                        am.severity = Set(*severity);
                    }
                    if let Some(root_cause) = updated_root_cause {
                        am.root_cause = Set(root_cause.clone());
                    }
                    if let Some(description) = updated_description {
                        am.description = Set(description.clone());
                    }
                    if let Some(patterns) = updated_patterns {
                        am.patterns = Set(patterns.clone());
                    }
                    if let Some(exploits) = updated_exploits {
                        am.exploits = Set(exploits.clone());
                    }
                    am.update(&txn).await?;

                    merged_finding_count += 1;
                }
            }
        }

        txn.commit().await?;
        tracing::info!(
            "Project {} saved: {} new semantics, {} merged semantics, {} new findings, {} merged findings",
            platform_id.unwrap_or(name),
            new_semantic_count,
            merged_semantic_count,
            new_finding_count,
            merged_finding_count
        );
        Ok(())
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
        let semantic_merges = semantic_merge::Entity::find().all(&self.db).await?;
        let findings = audit_finding::Entity::find().all(&self.db).await?;
        let finding_categories = finding_category::Entity::find().all(&self.db).await?;
        let audit_finding_categories = audit_finding_category::Entity::find().all(&self.db).await?;
        let semantic_finding_links = semantic_finding_link::Entity::find().all(&self.db).await?;
        let finding_merges = finding_merge::Entity::find().all(&self.db).await?;

        Ok(crate::knowledge_graph::KnowledgeGraph {
            projects,
            project_platforms,
            categories,
            nodes,
            semantic_functions,
            project_categories,
            semantic_merges,
            findings,
            finding_categories,
            audit_finding_categories,
            semantic_finding_links,
            finding_merges,
        })
    }
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
            project_id: 1,
        }
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

    async fn create_test_db() -> (DatabaseGraph, PathBuf) {
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
        let db = DatabaseGraph::connect(&url)
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
            project_id: Set(project_id),
            ..Default::default()
        })
        .exec(&db.db)
        .await
        .expect("semantic node insert should succeed")
        .last_insert_id;

        db.db
            .execute_unprepared("PRAGMA foreign_keys=OFF;")
            .await
            .expect("should disable foreign key enforcement for legacy-data test");
        semantic_merge::Entity::insert(semantic_merge::ActiveModel {
            from_semantic_id: Set(semantic_id),
            to_semantic_id: Set(999999),
        })
        .exec(&db.db)
        .await
        .expect("dangling semantic merge insert should succeed");
        db.db
            .execute_unprepared("PRAGMA foreign_keys=ON;")
            .await
            .expect("should re-enable foreign key enforcement after legacy-data setup");

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
            project_id: Set(project_id),
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
            project_id: Set(project_id),
            ..Default::default()
        })
        .exec(&db.db)
        .await
        .expect("finding insert should succeed")
        .last_insert_id;

        semantic_finding_link::Entity::insert(semantic_finding_link::ActiveModel {
            semantic_node_id: Set(semantic_id),
            audit_finding_id: Set(finding_id),
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
        let restored = DatabaseGraph::connect(&restore_url)
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
            project_id: Set(project_id),
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
            project_id: Set(project_id),
            ..Default::default()
        })
        .exec(&db.db)
        .await
        .expect("finding insert should succeed")
        .last_insert_id;

        semantic_finding_link::Entity::insert(semantic_finding_link::ActiveModel {
            semantic_node_id: Set(semantic_id),
            audit_finding_id: Set(finding_id),
        })
        .exec(&db.db)
        .await
        .expect("link insert should succeed");

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
        let restored = DatabaseGraph::connect(&restore_url)
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
            project_id: Set(project_id),
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
            project_id: Set(project_id),
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
            project_id: Set(project_id),
            ..Default::default()
        })
        .exec(&db.db)
        .await
        .expect("semantic insert should succeed")
        .last_insert_id;

        semantic_finding_link::Entity::insert(semantic_finding_link::ActiveModel {
            semantic_node_id: Set(semantic_id),
            audit_finding_id: Set(linked_finding_id),
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
            project_id: Set(project_id),
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
    async fn list_findings_for_linking_include_unlinked_skips_canonical_findings_with_links() {
        let (db, path) = create_test_db().await;

        let project_id = project::Entity::insert(project::ActiveModel {
            name: Set("Include Unlinked Canonical Link Test".to_string()),
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
            project_id: Set(project_id),
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
            project_id: Set(project_id),
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
            project_id: Set(project_id),
            ..Default::default()
        })
        .exec(&db.db)
        .await
        .expect("semantic insert should succeed")
        .last_insert_id;

        finding_merge::Entity::insert(finding_merge::ActiveModel {
            from_finding_id: Set(source_finding_id),
            to_finding_id: Set(target_finding_id),
        })
        .exec(&db.db)
        .await
        .expect("finding merge insert should succeed");

        semantic_finding_link::Entity::insert(semantic_finding_link::ActiveModel {
            semantic_node_id: Set(semantic_id),
            audit_finding_id: Set(target_finding_id),
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

        let include_unlinked_pending = db
            .list_findings_for_linking(true)
            .await
            .expect("include-unlinked findings should load");
        assert!(include_unlinked_pending.is_empty());

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
            project_id: Set(project_id),
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
            project_id: Set(project_id),
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
            project_id: Set(project_id),
            ..Default::default()
        })
        .exec(&db.db)
        .await
        .expect("semantic insert should succeed")
        .last_insert_id;

        finding_merge::Entity::insert(finding_merge::ActiveModel {
            from_finding_id: Set(source_finding_id),
            to_finding_id: Set(target_finding_id),
        })
        .exec(&db.db)
        .await
        .expect("finding merge insert should succeed");

        semantic_finding_link::Entity::insert(semantic_finding_link::ActiveModel {
            semantic_node_id: Set(semantic_id),
            audit_finding_id: Set(target_finding_id),
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
}
