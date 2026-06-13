use std::collections::BTreeMap;

use knowdit_kg_model::{ExtractedFinding, ExtractedSemantic};
use knowdit_repo_model::{cg::CallGraph, storage::StorageGraph};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone)]
pub enum StateGraph {
    Solidity(StorageGraph),
}

/// Fetch from repo database
#[derive(Debug, Clone)]
pub struct RepoContext {
    pub cg: CallGraph,
    pub state_graph: StorageGraph,
    pub semantics: Vec<ExtractedSemantic>,
}

#[derive(Debug, Clone)]
pub struct VulnLinkCandidate {
    pub semantic: ExtractedSemantic,
    pub findings: ExtractedFinding,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AuditStateSpecification {
    /// General description of the state, this might contain multiple rules!
    pub description: String,
    /// The specification requirements for state variables, i.e., the reseves should be drained after being attacked
    pub states_variables: BTreeMap<String, String>,
    /// The specification requirements for contracts, i.e., contract Manager must be present and an admin should be added
    pub contracts: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuqenceCallStep {
    /// The contract of the call
    pub contract: String,
    /// The function name of the call
    pub function: String,
    /// The intention of the call
    pub intention: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AuditSpecification {
    /// The state that needs to be setup, for example, deploying contracts, setup admin
    pub setup: AuditStateSpecification,
    /// The state before the given attack
    pub pre_attack: AuditStateSpecification,
    /// The state after the given attack
    pub post_attack: AuditStateSpecification,
    /// The intended sequence
    pub sequence: Vec<SuqenceCallStep>,
}
