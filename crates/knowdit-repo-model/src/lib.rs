pub mod cg;
pub mod db;
pub mod inheritance;

/// Default cap on merged-variant notes rendered under each mirrored canonical
/// (semantic description / finding fields) in `load_semantic_match_results`.
pub const DEFAULT_VARIANT_RENDER_CAP: usize = 50;

pub mod lang;
pub mod link;
pub mod move_lang;
pub mod repo;
pub mod storage;

#[cfg(test)]
mod tests;

pub use inheritance::{ContractInherit, InheritanceGraph};
pub use lang::SourceLanguage;
pub use link::{LinkInput, LinkKey};
pub use move_lang::{
    MoveAbility, MoveField, MoveFunctionMetadata, MoveGenericParam, MovePackageStructure,
    MoveStruct, MoveVisibility,
};

pub use repo::{
    CodeGenCore, CodeGenRecord, CodeGenStatus, CoverageEntry, FindingMergeDecision,
    FindingProvenance, FindingReviewRecord, FullSpecRegenIds, HarnessRunRecord,
    HistoricalFindingChild, HistoricalLinkedFinding, HistoricalSemanticChild,
    HistoricalSemanticRecord, LinkResumeState, LoadedCodeGen, LoadedHarnessRun,
    LoadedReportFinding, LoadedSpecification, LoadedValidFinding, METADATA_KEY_PROFILE,
    MatchStrength, PendingReflection, PendingRuledOut, ProjectComponent, ProjectProfile,
    ProjectSubsystem, RawFindingMember, ReflectionRecord, ReflectionResult, ReflectionWipeStats,
    RegenEventRecord, RepoDatabase, ReportFindingSeed, ReviewSeverity, ReviewedFinding,
    RuledOutConclusion, RuledOutMergeDecision, RunKind, SemanticMatch, SemanticMatchSet,
    ValidFindingRecord,
};
