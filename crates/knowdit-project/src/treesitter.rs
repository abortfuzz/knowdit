//! `SolidityTreesitterProject` — tree-sitter view of a Solidity project.
//!
//! Wraps the output of `knowdit_sol::cg::extract_contracts_functions`,
//! driven directly from a [`ProjectScopeContent`] snapshot so the file
//! bodies the scope walker already read from disk are reused verbatim
//! — no second `tokio::fs::read_to_string` per file.

use std::path::{Path, PathBuf};

use color_eyre::eyre::Result;
use knowdit_sol::cg::{ExtractedContract, SoliditySourceInput, extract_contracts_functions};

use crate::scope::ProjectScopeContent;

/// Tree-sitter analysis output for one Solidity project.
///
/// Owns the contracts vec and the repo root the extraction was rooted
/// at — that pair is everything downstream callers (callgraph
/// synthesis, prompt building, etc.) need to address a function back
/// to its file.
#[derive(Debug, Clone)]
pub struct SolidityTreesitterProject {
    repo_root: PathBuf,
    contracts: Vec<ExtractedContract>,
}

impl SolidityTreesitterProject {
    /// Run tree-sitter over every file in `content`. The input bodies
    /// are forwarded directly into `knowdit_sol::cg::extract_contracts_functions`,
    /// which is sync (CPU-bound parsing only).
    pub fn build(content: &ProjectScopeContent) -> Result<Self> {
        let inputs: Vec<SoliditySourceInput> = content
            .files()
            .iter()
            .map(|file| SoliditySourceInput {
                relative_path: file.relative_path.clone(),
                content: file.content.clone(),
            })
            .collect();
        let contracts = extract_contracts_functions(&inputs)?;
        Ok(Self {
            repo_root: content.repo_root().to_path_buf(),
            contracts,
        })
    }

    pub fn repo_root(&self) -> &Path {
        &self.repo_root
    }

    pub fn contracts(&self) -> &[ExtractedContract] {
        &self.contracts
    }

    pub fn into_contracts(self) -> Vec<ExtractedContract> {
        self.contracts
    }
}
