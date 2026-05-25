use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
};

use color_eyre::eyre::{WrapErr, ensure};

/// Configuration for Solidity extraction after CLI/source discovery has expanded globs.
#[derive(Debug, Clone)]
pub struct SolidityExtractionConfig {
    /// Repository root.
    pub repo_root: PathBuf,
    /// Solidity source files, relative to `repo_root`, extracted by tree-sitter.
    pub source_files: Vec<PathBuf>,
    /// Subset of `source_files` whose functions should be analyzed by the callgraph agent.
    pub analysis_source_files: Vec<PathBuf>,
}

impl SolidityExtractionConfig {
    pub fn new(
        repo_root: impl Into<PathBuf>,
        source_files: Vec<PathBuf>,
        analysis_source_files: Vec<PathBuf>,
    ) -> Self {
        Self {
            repo_root: repo_root.into(),
            source_files,
            analysis_source_files,
        }
    }
}

pub fn normalize_relative_source_files(
    repo_root: &Path,
    source_files: Vec<PathBuf>,
) -> Result<Vec<PathBuf>, color_eyre::Report> {
    let mut seen = BTreeSet::new();
    let mut normalized = Vec::new();
    for path in source_files {
        let path = normalize_relative_path(repo_root, path)?;
        if seen.insert(path_key(&path)) {
            normalized.push(path);
        }
    }
    normalized.sort();
    Ok(normalized)
}

pub fn filter_analysis_source_files(
    mut source_files: Vec<PathBuf>,
    analysis_source_files: Vec<PathBuf>,
) -> Result<Vec<PathBuf>, color_eyre::Report> {
    if analysis_source_files.is_empty() {
        source_files.sort();
        return Ok(source_files);
    }

    let sources_by_key = source_files
        .into_iter()
        .map(|path| (path_key(&path), path))
        .collect::<BTreeMap<_, _>>();
    let mut missing = Vec::new();
    let mut seen = BTreeSet::new();
    let mut filtered = Vec::new();

    for path in analysis_source_files {
        let key = path_key(&path);
        let Some(source_path) = sources_by_key.get(&key) else {
            missing.push(path);
            continue;
        };
        if seen.insert(key) {
            filtered.push(source_path.clone());
        }
    }

    ensure!(
        missing.is_empty(),
        "analysis source files are not present in the tree-sitter source set: {}",
        missing
            .iter()
            .map(|path| path.display().to_string())
            .collect::<Vec<_>>()
            .join(", ")
    );
    ensure!(
        !filtered.is_empty(),
        "callgraph analysis source set is empty"
    );

    filtered.sort();
    Ok(filtered)
}

fn normalize_relative_path(repo_root: &Path, path: PathBuf) -> Result<PathBuf, color_eyre::Report> {
    let path = if path.is_absolute() {
        path.strip_prefix(repo_root)
            .wrap_err_with(|| {
                format!(
                    "source file {} is not under repo root {}",
                    path.display(),
                    repo_root.display()
                )
            })?
            .to_path_buf()
    } else {
        path
    };
    let normalized = path_key(&path);
    ensure!(!normalized.is_empty(), "source file path is empty");
    Ok(PathBuf::from(normalized))
}

fn path_key(path: &Path) -> String {
    path.to_string_lossy()
        .trim()
        .trim_start_matches("./")
        .to_string()
}
