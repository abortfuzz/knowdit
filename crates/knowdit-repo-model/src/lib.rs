pub mod cg;
pub mod db;
pub mod inheritance;
pub mod repo;
pub mod storage;

#[cfg(test)]
mod tests;

pub use inheritance::{ContractInherit, InheritanceGraph};

pub use repo::{
    CodeGenCore, CodeGenRecord, CodeGenStatus, CoverageEntry, FullSpecRegenIds, HarnessRunRecord,
    HistoricalLinkedFinding, HistoricalSemanticRecord, LinkResumeState, LoadedCodeGen,
    LoadedHarnessRun, LoadedSpecification, LoadedValidFinding, METADATA_KEY_PROFILE, MatchStrength,
    PendingReflection, ProjectComponent, ProjectProfile, ProjectSubsystem, ReflectionRecord,
    ReflectionResult, ReflectionWipeStats, RegenEventRecord, RepoDatabase, RunKind, SemanticMatch,
    SemanticMatchSet, ValidFindingRecord,
};
