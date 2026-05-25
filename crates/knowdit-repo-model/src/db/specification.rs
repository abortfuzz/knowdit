use sea_orm::entity::prelude::*;

/// Project-specific auditing specification for one (semantic, finding) pair.
///
/// `specification` stores the JSON-serialized form of `AuditSpecification`
/// (defined in `knowdit-audit::types`), capturing setup / pre-attack /
/// post-attack invariants and the call sequence to exercise.
#[sea_orm::model]
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize, DeriveEntityModel)]
#[sea_orm(table_name = "specification")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i32,
    /// References `project_semantic.id` in this project database.
    #[sea_orm(indexed)]
    pub semantic_id: i32,
    /// References `audit_finding.id` in the historical knowledge-graph
    /// database. Cross-database, so no foreign key is enforced.
    #[sea_orm(indexed)]
    pub finding_id: i32,
    /// JSON-serialized `AuditSpecification`.
    #[sea_orm(column_type = "Text")]
    pub specification: String,

    #[sea_orm(belongs_to, from = "semantic_id", to = "id")]
    pub semantic: HasOne<super::project_semantic::Entity>,
    #[sea_orm(has_many)]
    pub code_gens: HasMany<super::code_gen::Entity>,
    #[sea_orm(has_many)]
    pub reflections: HasMany<super::reflection::Entity>,
}

impl ActiveModelBehavior for ActiveModel {}
