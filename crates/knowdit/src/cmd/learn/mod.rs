// Historical-experience commands. None of these talk to an LLM; they ingest, link, validate,
// and export the project / finding / semantic graph that lives in the historical database.
pub mod export_dot;
pub mod export_html;
pub mod finding_link_args;
pub mod init_db;
pub mod learn;
pub mod link;
pub mod list_projects;
pub mod list_semantics;
pub mod merge_args;
pub mod reclassify_others;
pub mod retro_link;
pub mod search_semantics;
pub mod set_platform_id;
pub mod validate_db;
