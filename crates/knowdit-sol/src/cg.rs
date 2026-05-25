use std::{fmt, path::PathBuf};

use color_eyre::eyre::{ContextCompat, WrapErr, ensure};
use knowdit_repo_model::cg::FileChunk;
use serde::Serialize;
use tree_sitter::Parser;

pub use crate::filter::{
    SolidityExtractionConfig, filter_analysis_source_files, normalize_relative_source_files,
};
use crate::node::{
    callable_args, callable_kind_from_node, callable_name, collect_contract_nodes, node_chunk,
    node_field_text,
};

/// One Solidity source file plus its already-loaded content. The
/// tree-sitter pass needs the source bytes; this struct lets callers
/// that have already read the file (e.g. a [`crate::filter::SolidityExtractionConfig`]-
/// driven CLI flow or a `knowdit_project::ProjectScopeContent` snapshot)
/// pass the content straight through instead of forcing a second
/// `tokio::fs::read_to_string` per file.
#[derive(Debug, Clone)]
pub struct SoliditySourceInput {
    /// Path of the source file relative to the project root. Stored
    /// verbatim on each extracted contract / callable so downstream
    /// consumers can hash-locate them.
    pub relative_path: PathBuf,
    /// Full source text of the file. tree-sitter parses this directly.
    pub content: String,
}

/// Contracts/functions extracted from a Solidity repository before any LLM callgraph analysis.
#[derive(Debug, Clone, Serialize)]
pub struct SolidityExtractionResult {
    pub repo_root: PathBuf,
    pub source_files: Vec<PathBuf>,
    pub analysis_source_files: Vec<PathBuf>,
    pub contracts: Vec<ExtractedContract>,
}

/// Solidity declaration kind for a contract-like source item.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub enum SolidityContractKind {
    Contract,
    Interface,
    Library,
}

impl SolidityContractKind {
    pub(crate) fn from_node_kind(kind: &str) -> Option<Self> {
        match kind {
            "contract_declaration" => Some(Self::Contract),
            "interface_declaration" => Some(Self::Interface),
            "library_declaration" => Some(Self::Library),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Contract => "contract",
            Self::Interface => "interface",
            Self::Library => "library",
        }
    }
}

/// Solidity callable kind represented as a callgraph function node.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub enum SolidityCallableKind {
    Function,
    Constructor,
    Receive,
    Fallback,
    Modifier,
}

impl SolidityCallableKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Function => "function",
            Self::Constructor => "constructor",
            Self::Receive => "receive",
            Self::Fallback => "fallback",
            Self::Modifier => "modifier",
        }
    }
}

/// Repository callgraph function node kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub enum SolidityFunctionNodeKind {
    ContractFunctionDefinition,
    InterfaceFunctionDeclaration,
}

impl SolidityFunctionNodeKind {
    fn from_container_kind(kind: SolidityContractKind) -> Self {
        match kind {
            SolidityContractKind::Interface => Self::InterfaceFunctionDeclaration,
            SolidityContractKind::Contract | SolidityContractKind::Library => {
                Self::ContractFunctionDefinition
            }
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::ContractFunctionDefinition => "contract_function_definition",
            Self::InterfaceFunctionDeclaration => "interface_function_declaration",
        }
    }

    pub fn is_definition(self) -> bool {
        matches!(self, Self::ContractFunctionDefinition)
    }
}

/// A contract/interface/library extracted from Solidity source.
#[derive(Debug, Clone, Serialize)]
pub struct ExtractedContract {
    pub id: i32,
    pub name: String,
    pub kind: SolidityContractKind,
    pub relative_file_path: PathBuf,
    pub chunk: FileChunk,
    pub functions: Vec<ExtractedCallable>,
}

impl fmt::Display for ExtractedContract {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Contract({} {} @ {} (id={}, functions={}))",
            self.kind.as_str(),
            self.name,
            self.relative_file_path.display(),
            self.id,
            self.functions.len()
        )
    }
}

/// A function-like Solidity item extracted by tree-sitter.
#[derive(Debug, Clone, Serialize)]
pub struct ExtractedCallable {
    pub id: i32,
    pub contract_id: i32,
    pub contract_name: String,
    pub kind: SolidityCallableKind,
    pub node_kind: SolidityFunctionNodeKind,
    pub name: String,
    pub args: String,
    pub relative_file_path: PathBuf,
    pub chunk: FileChunk,
}

/// Extract Solidity contracts/functions without invoking the LLM.
pub async fn extract_repo_contracts_functions(
    config: &SolidityExtractionConfig,
) -> Result<SolidityExtractionResult, color_eyre::Report> {
    let repo_root = config.repo_root.canonicalize().wrap_err_with(|| {
        format!(
            "failed to canonicalize repo root {}",
            config.repo_root.display()
        )
    })?;
    ensure!(
        repo_root.is_dir(),
        "repo root {} is not a directory",
        repo_root.display()
    );

    let source_files = normalize_relative_source_files(&repo_root, config.source_files.clone())?;
    ensure!(
        !source_files.is_empty(),
        "no Solidity source files provided under {}",
        repo_root.display()
    );
    let analysis_source_files = filter_analysis_source_files(
        source_files.clone(),
        normalize_relative_source_files(&repo_root, config.analysis_source_files.clone())?,
    )?;

    let mut inputs: Vec<SoliditySourceInput> = Vec::with_capacity(source_files.len());
    for relative in &source_files {
        let absolute = repo_root.join(relative);
        let content = tokio::fs::read_to_string(&absolute)
            .await
            .wrap_err_with(|| format!("failed to read Solidity file {}", absolute.display()))?;
        inputs.push(SoliditySourceInput {
            relative_path: relative.clone(),
            content,
        });
    }
    let contracts = extract_contracts_functions(&inputs)?;
    ensure!(
        !contracts.is_empty(),
        "no Solidity contracts/interfaces/libraries were extracted under {}",
        repo_root.display()
    );

    Ok(SolidityExtractionResult {
        repo_root,
        source_files,
        analysis_source_files,
        contracts,
    })
}

/// Extract Solidity contracts and callables with tree-sitter from
/// pre-loaded source content. Sync: tree-sitter parsing is CPU-bound
/// and the caller has already taken care of disk I/O. The previous
/// `(repo_root, &[PathBuf])` signature is preserved at the outer
/// [`extract_repo_contracts_functions`] entry point, which handles
/// reading + then defers here.
pub fn extract_contracts_functions(
    inputs: &[SoliditySourceInput],
) -> Result<Vec<ExtractedContract>, color_eyre::Report> {
    let mut parser = Parser::new();
    let language = tree_sitter_solidity::LANGUAGE.into();
    parser
        .set_language(&language)
        .wrap_err("failed to load tree-sitter Solidity grammar")?;

    let mut contracts = Vec::new();
    let mut next_contract_id = 1;
    let mut next_function_id = 1;

    for input in inputs {
        let relative_file_path = &input.relative_path;
        let source = &input.content;
        let tree = parser.parse(source.as_bytes(), None).wrap_err_with(|| {
            format!(
                "failed to parse Solidity file {}",
                relative_file_path.display()
            )
        })?;
        let root = tree.root_node();
        if root.has_error() {
            tracing::warn!(
                path = %relative_file_path.display(),
                "tree-sitter reported syntax errors; attempting best-effort extraction"
            );
        }

        let mut contract_nodes = Vec::new();
        collect_contract_nodes(root, &mut contract_nodes);

        for contract_node in contract_nodes {
            let Some(contract_kind) = SolidityContractKind::from_node_kind(contract_node.kind())
            else {
                continue;
            };
            let name = node_field_text(contract_node, "name", source).wrap_err_with(|| {
                format!(
                    "failed to read contract name in {} at byte {}",
                    relative_file_path.display(),
                    contract_node.start_byte()
                )
            })?;
            let contract_id = next_contract_id;
            next_contract_id += 1;

            let mut functions = Vec::new();
            if let Some(body) = contract_node.child_by_field_name("body") {
                let mut cursor = body.walk();
                let body_children = body.named_children(&mut cursor).collect::<Vec<_>>();
                for child in body_children {
                    let Some(callable_kind) = callable_kind_from_node(child, &source) else {
                        continue;
                    };
                    let callable_name = callable_name(child, callable_kind, &source)?;
                    let args = callable_args(child, &source)?;
                    let chunk = node_chunk(child, &source)?;
                    functions.push(ExtractedCallable {
                        id: next_function_id,
                        contract_id,
                        contract_name: name.clone(),
                        kind: callable_kind,
                        node_kind: SolidityFunctionNodeKind::from_container_kind(contract_kind),
                        name: callable_name,
                        args,
                        relative_file_path: relative_file_path.clone(),
                        chunk,
                    });
                    next_function_id += 1;
                }
            }

            contracts.push(ExtractedContract {
                id: contract_id,
                name,
                kind: contract_kind,
                relative_file_path: relative_file_path.clone(),
                chunk: node_chunk(contract_node, &source)?,
                functions,
            });
        }
    }

    Ok(contracts)
}
