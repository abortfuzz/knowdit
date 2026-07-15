//! SeaORM entity definitions for every table the historical knowledge-graph
//! database holds. Pure value types (`DeFiCategory`, `FindingSeverity`,
//! `VulnerabilityCategory`, `ExtractedSemantic`, …) live one level up; this
//! module is purely the shape of rows in `sqlite`/`mysql` storage.
pub mod audit_finding;
pub mod audit_finding_category;
pub mod category;
pub mod finding_category;
pub mod finding_link_status;
pub mod finding_merge;
pub mod merge_status;
pub mod pending_semantic;
pub mod project;
pub mod project_category;
pub mod project_finding;
pub mod project_platform;
pub mod project_semantic;
pub mod semantic_finding_link;
pub mod semantic_function;
pub mod semantic_merge;
pub mod semantic_node;
pub mod semantic_node_category;
