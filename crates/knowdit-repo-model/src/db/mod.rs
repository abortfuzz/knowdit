//! SeaORM entity definitions for every table the project database holds. Pure value types
//! (call graph, storage graph, etc.) live one level up; this module is purely the shape of
//! rows in `sqlite`/`mysql` storage.
pub mod code_gen;
pub mod code_gen_regen;
pub mod contract;
pub mod contract_functions;
pub mod contract_inherit;
pub mod contract_variable;
pub mod function;
pub mod function_call;
pub mod function_state_variable;
pub mod harness_run;
pub mod historical_finding;
pub mod historical_semantic;
pub mod historical_semantic_finding_link;
pub mod interface;
pub mod interface_functions;
pub mod line_coverage;
pub mod project_metadata;
pub mod project_semantic;
pub mod project_semantic_function;
pub mod reflection;
pub mod semantic_matched;
pub mod specification;
pub mod specification_regen;
pub mod state_variable;
pub mod valid_finding;
