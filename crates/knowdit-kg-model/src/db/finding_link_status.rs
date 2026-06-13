use sea_orm::entity::prelude::*;

#[sea_orm::model]
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize, DeriveEntityModel)]
#[sea_orm(table_name = "finding_link_status")]
pub struct Model {
    /// Presence of a row here means the finding has been fully
    /// processed by the linker (every expected context committed).
    /// Partial-commit sfl rows for a still-running finding live in
    /// `semantic_finding_link` without a matching row here, and
    /// `HistoricalDatabase::load_knowledge_graph` filters them out
    /// so downstream consumers (mapper, spec-gen) only see
    /// canonical, complete link sets.
    #[sea_orm(primary_key, auto_increment = false)]
    pub audit_finding_id: i32,

    #[sea_orm(belongs_to, from = "audit_finding_id", to = "id")]
    pub audit_finding: Option<super::audit_finding::Entity>,
}

impl ActiveModelBehavior for ActiveModel {}
