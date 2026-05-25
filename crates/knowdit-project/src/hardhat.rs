//! `HardhatProject` — read-only view of a Solidity project that has
//! already been compiled by Hardhat. Mirrors [`crate::FoundryProject`]'s
//! external shape but does *not* drive solc itself: it consumes the
//! Hardhat `artifacts/build-info/*.json` files (schema
//! `hh-sol-build-info-1`), pulls out the per-source AST + content, and
//! feeds the same `knowdit-cg-static` pipeline that Foundry uses.
//!
//! Auto-compiling missing artifacts (npm install, `npx hardhat compile`)
//! is intentionally *not* in this module — that belongs to a future
//! auto-build step that runs before this view is constructed.

use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    time::SystemTime,
};

use color_eyre::eyre::{Result, WrapErr, ensure};
use foundry_compilers_artifacts::ast::SourceUnit as AstSourceUnit;
use knowdit_cg_static::{
    SourceUnitInput, StaticCallGraphResult, StorageAnalysisResult, analyze_storage,
    build_call_graph_with_maps,
};
use knowdit_repo_model::{cg::CallGraph, inheritance::InheritanceGraph, storage::StorageGraph};
use serde::Deserialize;

const DEFAULT_ARTIFACTS_DIR: &str = "artifacts";
const BUILD_INFO_SUBDIR: &str = "build-info";

/// Tunables for [`HardhatProject::build`]. Mirrors the shape of
/// [`crate::FoundryOptions`] in that all fields are runtime-configurable
/// via the CLI layer; defaults reflect the Hardhat layout you get from
/// `npx hardhat init`.
#[derive(Debug, Clone, Default)]
pub struct HardhatOptions {
    /// Override the artifacts root. When `Some`, joined against the
    /// project root; when `None`, defaults to `artifacts/`. The actual
    /// build-info JSONs are read from `<artifacts>/build-info/`.
    pub artifacts_dir: Option<PathBuf>,
}

impl HardhatOptions {
    /// Resolve the directory that contains `<id>.json` build-info files.
    fn build_info_dir(&self, repo_root: &Path) -> PathBuf {
        let artifacts = self
            .artifacts_dir
            .clone()
            .map(|p| {
                if p.is_absolute() {
                    p
                } else {
                    repo_root.join(p)
                }
            })
            .unwrap_or_else(|| repo_root.join(DEFAULT_ARTIFACTS_DIR));
        artifacts.join(BUILD_INFO_SUBDIR)
    }
}

/// Read-only static-analysis view of a Hardhat project. Constructed
/// from already-emitted build-info JSONs; never invokes solc directly.
#[derive(Debug, Clone)]
pub struct HardhatProject {
    repo_root: PathBuf,
    inputs: Vec<SourceUnitInput>,
    call_graph: StaticCallGraphResult,
    storage: StorageAnalysisResult,
}

impl HardhatProject {
    /// Locate and parse `artifacts/build-info/*.json`, then run the
    /// static call-graph + storage analyses over the resulting ASTs.
    /// Async because JSON parsing happens on a blocking task to avoid
    /// stalling the runtime on multi-megabyte build-info payloads.
    pub async fn build(repo_root: PathBuf, options: HardhatOptions) -> Result<Self> {
        let repo_root = repo_root.canonicalize().wrap_err_with(|| {
            format!("failed to canonicalize repo root {}", repo_root.display())
        })?;
        ensure!(
            repo_root.is_dir(),
            "repo root {} is not a directory",
            repo_root.display(),
        );

        let inputs = Self::load_source_units(&repo_root, &options).await?;
        let (call_graph, id_maps) = build_call_graph_with_maps(&repo_root, &inputs)
            .wrap_err("failed to build static Solidity call graph")?;
        let storage = analyze_storage(&repo_root, &inputs, &id_maps)
            .wrap_err("failed to run storage analysis")?;

        Ok(Self {
            repo_root,
            inputs,
            call_graph,
            storage,
        })
    }

    pub fn repo_root(&self) -> &Path {
        &self.repo_root
    }

    pub fn inputs(&self) -> &[SourceUnitInput] {
        &self.inputs
    }

    pub fn into_inputs(self) -> Vec<SourceUnitInput> {
        self.inputs
    }

    pub fn call_graph(&self) -> &CallGraph {
        &self.call_graph.call_graph
    }

    pub fn storage_graph(&self) -> &StorageGraph {
        &self.storage.storage
    }

    pub fn inheritance_graph(&self) -> &InheritanceGraph {
        &self.storage.inheritance
    }

    pub fn call_graph_result(&self) -> &StaticCallGraphResult {
        &self.call_graph
    }

    pub fn storage_result(&self) -> &StorageAnalysisResult {
        &self.storage
    }

    /// Discover + parse every `<artifacts>/build-info/*.json`, merge
    /// by source path (newer mtime wins), and materialize the
    /// `SourceUnitInput`s the cg-static pipeline expects.
    async fn load_source_units(
        repo_root: &Path,
        options: &HardhatOptions,
    ) -> Result<Vec<SourceUnitInput>> {
        let repo_root = repo_root.to_path_buf();
        let options = options.clone();

        tokio::task::spawn_blocking(move || -> Result<Vec<SourceUnitInput>> {
            let dir = options.build_info_dir(&repo_root);
            let collection = BuildInfoCollection::from_dir(&dir)?;
            collection.into_source_units(&repo_root)
        })
        .await
        .wrap_err("Hardhat build-info parse task panicked")?
    }
}

// ---------------------------------------------------------------------------
// Build-info schema — serde-derived, `hh-sol-build-info-1`.
// Only the fields we consume are modelled; unknown keys are ignored
// (defaults / `#[serde(default)]` on collections so partial files still
// parse). The schema is published by Hardhat and stable; mismatches are
// surfaced via the `_format` check rather than serde errors.
// ---------------------------------------------------------------------------

/// Versions of Hardhat's build-info schema we know how to parse.
/// Serde rejects any `_format` not listed here at deserialization
/// time, so unknown future versions fail loudly with the offending
/// string in the error message rather than mid-parse on a renamed
/// field. Add a new variant the day Hardhat ships a v2.
#[derive(Debug, Deserialize)]
enum BuildInfoFormat {
    #[serde(rename = "hh-sol-build-info-1")]
    HhSolBuildInfo1,
}

#[derive(Debug, Deserialize)]
struct BuildInfo {
    #[serde(rename = "_format")]
    #[allow(dead_code)]
    format: BuildInfoFormat,
    #[serde(default)]
    #[allow(dead_code)]
    id: String,
    #[serde(rename = "solcVersion", default)]
    #[allow(dead_code)]
    solc_version: String,
    #[serde(default)]
    input: BuildInfoInput,
    #[serde(default)]
    output: BuildInfoOutput,
}

#[derive(Debug, Default, Deserialize)]
struct BuildInfoInput {
    #[serde(default)]
    sources: BTreeMap<String, BuildInfoInputSource>,
}

#[derive(Debug, Default, Deserialize)]
struct BuildInfoInputSource {
    #[serde(default)]
    content: String,
}

#[derive(Debug, Default, Deserialize)]
struct BuildInfoOutput {
    #[serde(default)]
    sources: BTreeMap<String, BuildInfoOutputSource>,
}

#[derive(Debug, Deserialize)]
struct BuildInfoOutputSource {
    ast: AstSourceUnit,
}

/// One loaded build-info JSON plus the on-disk mtime used to break
/// ties when multiple files describe the same source.
struct BuildInfoFile {
    path: PathBuf,
    mtime: SystemTime,
    info: BuildInfo,
}

impl BuildInfoFile {
    fn load(path: PathBuf) -> Result<Self> {
        let metadata = fs::metadata(&path)
            .wrap_err_with(|| format!("failed to stat build-info {}", path.display()))?;
        let mtime = metadata.modified().unwrap_or(SystemTime::UNIX_EPOCH);
        let text = fs::read_to_string(&path)
            .wrap_err_with(|| format!("failed to read build-info {}", path.display()))?;
        let info: BuildInfo = serde_json::from_str(&text).wrap_err_with(|| {
            format!(
                "failed to deserialize hh-sol-build-info JSON at {}",
                path.display()
            )
        })?;
        Ok(Self { path, mtime, info })
    }
}

/// Accumulator that merges every parsed build-info into a per-source
/// view keyed by the source path as it appears in `output.sources`
/// (project-relative, e.g. `contracts/Foo.sol`). When the same source
/// appears in multiple build-info files (Hardhat's incremental compile
/// leaves older snapshots on disk), the file with the newer mtime wins.
struct BuildInfoCollection {
    files: Vec<BuildInfoFile>,
}

impl BuildInfoCollection {
    fn from_dir(dir: &Path) -> Result<Self> {
        ensure!(
            dir.is_dir(),
            "Hardhat build-info directory not found: {} (run `npx hardhat compile` first, or pass --artifacts-dir)",
            dir.display(),
        );

        let mut files = Vec::new();
        let read_dir = fs::read_dir(dir)
            .wrap_err_with(|| format!("failed to read build-info dir {}", dir.display()))?;
        for entry in read_dir {
            let entry = entry.wrap_err_with(|| {
                format!("failed to enumerate build-info dir {}", dir.display())
            })?;
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) != Some("json") {
                continue;
            }
            files.push(BuildInfoFile::load(path)?);
        }
        ensure!(
            !files.is_empty(),
            "no build-info JSON files in {}",
            dir.display()
        );
        Ok(Self { files })
    }

    /// Fold every build-info file into `(rel_path -> winning ast + content)`,
    /// then materialize `SourceUnitInput`s in stable path order.
    fn into_source_units(self, repo_root: &Path) -> Result<Vec<SourceUnitInput>> {
        struct Winner {
            mtime: SystemTime,
            ast: AstSourceUnit,
            content: String,
            origin: PathBuf,
        }

        let mut winners: BTreeMap<String, Winner> = BTreeMap::new();
        for file in self.files {
            let BuildInfoFile {
                path: origin,
                mtime,
                info,
            } = file;
            // Pre-extract input contents into a path-keyed lookup so we
            // can pair each output AST with its source. Hardhat always
            // emits `input.sources[k].content` next to `output.sources[k].ast`
            // for the same key, but we tolerate missing content (fall
            // back to reading from disk later).
            let BuildInfo { input, output, .. } = info;
            let mut contents: BTreeMap<String, String> = input
                .sources
                .into_iter()
                .map(|(k, v)| (k, v.content))
                .collect();

            for (rel_path, out_src) in output.sources {
                let content = contents.remove(&rel_path).unwrap_or_default();
                match winners.get(&rel_path) {
                    Some(existing) if existing.mtime >= mtime => continue,
                    _ => {}
                }
                winners.insert(
                    rel_path,
                    Winner {
                        mtime,
                        ast: out_src.ast,
                        content,
                        origin: origin.clone(),
                    },
                );
            }
        }

        let mut inputs = Vec::with_capacity(winners.len());
        for (rel_path, w) in winners {
            let content = if w.content.is_empty() {
                Self::fallback_read_source(repo_root, &rel_path, &w.origin)?
            } else {
                w.content
            };
            let absolute_path = if w.ast.absolute_path.is_empty() {
                rel_path.clone()
            } else {
                w.ast.absolute_path.clone()
            };
            inputs.push(SourceUnitInput {
                absolute_path,
                source: content,
                source_unit: w.ast,
            });
        }

        ensure!(
            !inputs.is_empty(),
            "Hardhat build-info contained no source ASTs (outputSelection may have stripped them)"
        );
        Ok(inputs)
    }

    /// Some build-info producers omit `input.sources[*].content`. In
    /// that case fall back to reading the project file from disk via
    /// the project-relative path key. The `origin` argument is only
    /// used to produce a useful error message.
    fn fallback_read_source(repo_root: &Path, rel_path: &str, origin: &Path) -> Result<String> {
        let candidate = repo_root.join(rel_path);
        fs::read_to_string(&candidate).wrap_err_with(|| {
            format!(
                "build-info {} omitted input.sources content for {}; failed to read from disk at {}",
                origin.display(),
                rel_path,
                candidate.display(),
            )
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn options_default_resolves_to_artifacts_build_info() {
        let root = PathBuf::from("/tmp/example");
        let dir = HardhatOptions::default().build_info_dir(&root);
        assert_eq!(dir, root.join("artifacts").join("build-info"));
    }

    #[test]
    fn options_override_relative() {
        let root = PathBuf::from("/tmp/example");
        let opts = HardhatOptions {
            artifacts_dir: Some(PathBuf::from("custom/out")),
        };
        assert_eq!(
            opts.build_info_dir(&root),
            root.join("custom/out").join("build-info")
        );
    }

    #[test]
    fn options_override_absolute() {
        let opts = HardhatOptions {
            artifacts_dir: Some(PathBuf::from("/abs/artifacts")),
        };
        assert_eq!(
            opts.build_info_dir(Path::new("/anywhere")),
            PathBuf::from("/abs/artifacts/build-info")
        );
    }
}
