//! Project-shaped types shared across the knowdit pipeline.
//!
//! Data flow:
//!
//! ```text
//!     PathBuf + globs ──build──> ProjectScope ──read──> ProjectScopeContent
//!                                                            │
//!                              ┌─────────────────────────────┼─────────────────────────┐
//!                              ▼                             ▼                         ▼
//!                       TreesitterProject              ProjectData            ProjectScopeContent
//!                       (Vec<ExtractedContract>)       (name + lang +         (consumed by foundry,
//!                                                       platform_id +          downstream callers)
//!                                                       content)
//!                              ▲                             ▲
//!                              │                             │
//!     repo_root ──build─> FoundryProject              C4PairedProjectData
//!                         (CallGraph + StorageGraph)  (ProjectData + audit)
//! ```
//!
//! Each top-level struct owns its inputs (no lifetime params) and exposes
//! its analysis output through plain accessors — the values are derived
//! once in the constructor and cached. The crate intentionally does not
//! re-export the heavy underlying types (`ExtractedContract`, `CallGraph`,
//! `StorageGraph`) so callers go through `knowdit-sol` / `knowdit-repo-model`
//! for those.

pub mod c4;
pub mod data;
pub mod foundry;
pub mod hardhat;
pub mod moves;
pub mod scope;
pub mod treesitter;

pub use c4::{AuditMeta, AuditReportMaterial, C4PairedProjectData};
pub use data::{ProjectData, ProjectSpec, SourceLanguage};
pub use foundry::{FoundryOptions, FoundryProject};
pub use hardhat::{HardhatOptions, HardhatProject};
pub use knowdit_cg_static::{StaticCallGraphResult, StorageAnalysisResult};
pub use moves::{
    MovePlatform, MoveProjectDescriptor, MoveVulnerabilityFinding, MoveVulnerabilitySnippet,
    MoveVulnerabilitySnippetFile, list_contest_ids, list_move_projects, load_move_audit_reports,
};
pub use scope::{ProjectScope, ProjectScopeContent, ScopedSourceFile, read_scope_txt};
pub use treesitter::SolidityTreesitterProject;
