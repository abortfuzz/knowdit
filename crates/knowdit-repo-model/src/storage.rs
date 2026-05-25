use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::cg::{FileChunk, FileLocation};

/// One state variable as captured by the static analyzer. `id` is project-local and stable across
/// rerouting; AST node ids from solc are not surfaced.
#[derive(Deserialize, Serialize, Clone, Debug)]
pub struct StateVariable {
    pub id: i32,
    pub name: String,
    /// Stringified Solidity type, taken from `typeDescriptions.typeString`. Complex / generic
    /// types (`mapping(address => uint256)`, `MyStruct`) are stored verbatim.
    pub type_name: String,
    pub relative_file_path: std::path::PathBuf,
    pub loc: FileLocation,
    /// Source text of the declaration.
    pub content: String,
}

/// One row of `contract_variable`: `contract_id` declared `state_variable_id`. Inherited variables
/// are NOT recorded here — only the contract that physically declares the variable.
#[derive(Deserialize, Serialize, Clone, Debug)]
pub struct ContractVariable {
    pub contract_id: i32,
    pub state_variable_id: i32,
    pub description: Option<String>,
}

/// `function_id` reads or writes `state_variable_id`.
#[derive(Deserialize, Serialize, Clone, Debug)]
pub struct FunctionStateVariable {
    pub function_id: i32,
    pub state_variable_id: i32,
    pub is_write: bool,
    pub description: Option<String>,
}

#[derive(Deserialize, Serialize, Clone, Debug, Default)]
pub struct StorageGraph {
    pub state_variables: BTreeMap<i32, StateVariable>,
    pub contract_variables: Vec<ContractVariable>,
    pub function_state_variables: Vec<FunctionStateVariable>,
}

/// Options controlling the storage DOT export.
#[derive(Debug, Clone, Default)]
pub struct StorageDotOptions {
    /// If `true`, include state variables that no function reads or writes.
    pub include_isolated_state_variables: bool,
}

pub(crate) fn dot_escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

/// Helper for the analyzer when assembling a `StateVariable` from its declaration text.
pub fn make_state_variable(
    id: i32,
    name: String,
    type_name: String,
    relative_file_path: std::path::PathBuf,
    chunk: FileChunk,
) -> StateVariable {
    StateVariable {
        id,
        name,
        type_name,
        relative_file_path,
        loc: chunk.loc,
        content: chunk.content,
    }
}
