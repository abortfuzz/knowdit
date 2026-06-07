use sea_orm::entity::prelude::*;

/// Project-specific auditing specification for one
/// `(extract, historical, finding)` link.
///
/// `specification` stores the JSON-serialized form of `AuditSpecification`
/// (defined in `knowdit-audit::types`), capturing setup / pre-attack /
/// post-attack invariants and the call sequence to exercise.
///
/// Note that multiple rows can share the same
/// `(semantic_id, historical_id, finding_id)` triple — by design — for
/// two reasons:
///
/// 1. One gen-spec agent call may emit multiple `AuditSpecification`s
///    (different angles on the same link); all are written as separate
///    rows under the same triple.
/// 2. Regen produces a child spec with the same triple as its parent;
///    parent and every regen descendant share `(E, H, F)`.
///
/// Therefore: no UNIQUE constraint on the triple — only a compound
/// index (built in `RepoDatabase::init_schema`) for query speed.
#[sea_orm::model]
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize, DeriveEntityModel)]
#[sea_orm(table_name = "specification")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i32,
    /// References `project_semantic.id` in this project database.
    #[sea_orm(indexed)]
    pub semantic_id: i32,
    /// References `historical_semantic.id` (mirrored into the project
    /// DB) — pinpoints which historical pattern the gen-spec agent
    /// used as context. Combined with `semantic_id` + `finding_id`
    /// this gives the full `(E, H, F)` triple the spec was authored
    /// for.
    #[sea_orm(indexed)]
    pub historical_id: i32,
    /// References `audit_finding.id` in the historical knowledge-graph
    /// database. Cross-database, so no foreign key is enforced.
    #[sea_orm(indexed)]
    pub finding_id: i32,
    /// JSON-serialized `AuditSpecification`.
    #[sea_orm(column_type = "Text")]
    pub specification: String,

    #[sea_orm(belongs_to, from = "semantic_id", to = "id")]
    pub semantic: HasOne<super::project_semantic::Entity>,
    #[sea_orm(belongs_to, from = "historical_id", to = "id")]
    pub historical: HasOne<super::historical_semantic::Entity>,
    #[sea_orm(has_many)]
    pub code_gens: HasMany<super::code_gen::Entity>,
    #[sea_orm(has_many)]
    pub reflections: HasMany<super::reflection::Entity>,
}

impl ActiveModelBehavior for ActiveModel {}
