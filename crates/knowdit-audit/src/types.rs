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

/// One state variable declared on an [`AuxiliaryContract`]. Auxiliary
/// contracts are synthesized by the PoC harness, so unlike project state
/// variables these are defined by the agent rather than grounded against
/// the project source.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuxStateVariable {
    /// Solidity type of the variable, e.g. `uint256`, `address`.
    pub solidity_type: String,
    /// What this variable is for in the attack scenario.
    pub purpose: String,
}

/// A helper contract the PoC must deploy itself — an attacker contract,
/// malicious callback, mock token, etc. — that does not exist in the
/// project source. Declared explicitly by the agent so spec references to
/// it (and to its state variables / functions) are grounded against this
/// registry instead of the project, and so the harness knows to
/// synthesize it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuxiliaryContract {
    /// Why this auxiliary contract exists in the PoC, e.g. "reentrancy attacker".
    pub purpose: String,
    /// State variables the auxiliary contract declares: name -> metadata.
    pub state_variables: BTreeMap<String, AuxStateVariable>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AuditSpecification {
    /// One- or two-sentence summary of the overall vulnerable behavior
    /// this spec captures. Required at commit time.
    #[serde(default)]
    pub summary: String,
    /// The state that needs to be setup, for example, deploying contracts, setup admin
    pub setup: AuditStateSpecification,
    /// The state before the given attack
    pub pre_attack: AuditStateSpecification,
    /// The state after the given attack
    pub post_attack: AuditStateSpecification,
    /// The intended sequence
    pub sequence: Vec<SuqenceCallStep>,
    /// Auxiliary contracts the PoC must deploy itself (attacker contracts,
    /// malicious callbacks, mocks). Keyed by the name the agent chose.
    #[serde(default)]
    pub auxiliary_contracts: BTreeMap<String, AuxiliaryContract>,
}
