//! Project file scope — the set of repo-relative paths the rest of the
//! pipeline cares about, plus the in-memory snapshot of their contents.
//!
//! Conceptually [`ProjectScope`] is the "what files" view (cheap) and
//! [`ProjectScopeContent`] is the "what's in them" view (one read from
//! disk per file). Splitting the two lets callers narrow the scope
//! (`filter` / `filter_by_patterns`) without re-reading anything.

use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
};

use color_eyre::eyre::{Result, WrapErr, eyre};
use std::sync::OnceLock;

use globset::{Glob, GlobSet, GlobSetBuilder};

/// A repo-relative file set. The `repo_root` is canonicalized at
/// construction time; every `PathBuf` in `paths` is relative to it and
/// already stripped of leading `./` segments.
///
/// The struct intentionally stores *paths only*, not content — see
/// [`Self::read`] for the disk-reading step. Construction never touches
/// file contents, so a `ProjectScope` is cheap to build, clone, and
/// further narrow via [`Self::filter`].
#[derive(Debug, Clone)]
pub struct ProjectScope {
    repo_root: PathBuf,
    paths: BTreeSet<PathBuf>,
}

impl ProjectScope {
    /// Whether `relative_path` lives in a tree the project loader treats as
    /// vendored or non-production — `lib/`, `node_modules/`, `test/`, `mock/`,
    /// `script/`, `deploy/`, `src/vendor/`, build output.
    ///
    /// The call-graph and storage phases deliberately ingest those trees, because
    /// resolving an inherited or imported symbol needs the dependency's source. So
    /// anything that reads the call graph back as *the project's own* surface has to
    /// filter them out again, and does it here rather than by restating the list —
    /// [`crate::data::DEFAULT_VENDORED_EXCLUDES`] stays the single definition.
    pub fn is_vendored_path(relative_path: &Path) -> bool {
        static EXCLUDES: OnceLock<GlobSet> = OnceLock::new();
        // The patterns are a compile-time constant that the loader itself already
        // compiles on every project load, so a failure here is impossible in
        // practice; an empty set (matching nothing) is the safe reading either way.
        EXCLUDES
            .get_or_init(|| {
                let mut builder = GlobSetBuilder::new();
                for pattern in crate::data::DEFAULT_VENDORED_EXCLUDES {
                    if let Ok(glob) = Glob::new(pattern) {
                        builder.add(glob);
                    }
                }
                builder.build().unwrap_or_else(|_| GlobSet::empty())
            })
            .is_match(relative_path)
    }

    /// Walk `repo_root` and capture every regular file whose
    /// repo-relative path matches `include` and does not match
    /// `exclude`. Both globsets are pre-compiled; use
    /// [`Self::build_from_patterns`] if you only have raw pattern
    /// strings.
    ///
    /// Semantics of an *empty* globset:
    ///
    /// * empty `include` → nothing is captured (a strict "include set"
    ///   with no rules matches nothing). Pass a globset containing
    ///   `**/*` (or use [`Self::build_from_patterns`] with `["**/*"]`)
    ///   to mean "include everything".
    /// * empty `exclude` → nothing is excluded.
    ///
    /// The walker descends into all subdirectories unconditionally;
    /// path-level exclusion is the *only* mechanism for skipping
    /// vendored directories like `node_modules`. Callers wanting the
    /// classic blocklist should pass it explicitly via the `exclude`
    /// set.
    pub fn build(repo_root: PathBuf, include: &GlobSet, exclude: &GlobSet) -> Result<Self> {
        let repo_root = repo_root.canonicalize().wrap_err_with(|| {
            format!("failed to canonicalize repo root {}", repo_root.display())
        })?;
        if !repo_root.is_dir() {
            return Err(eyre!(
                "repo root {} is not a directory",
                repo_root.display()
            ));
        }
        // Dir-level exclude prunes whole subtrees (cheap); file-level
        // checks both include + exclude on the repo-relative path.
        // Paths that can't be stripped back to repo_root (shouldn't
        // happen under a canonical root) are rejected on both filters.
        let accept_dir = |dir: &Path| -> bool {
            match dir.strip_prefix(&repo_root) {
                Ok(rel) if !rel.as_os_str().is_empty() => !exclude.is_match(rel),
                Ok(_) => true, // the root itself
                Err(_) => false,
            }
        };
        let accept_file = |file: &Path| -> bool {
            let Ok(rel) = file.strip_prefix(&repo_root) else {
                return false;
            };
            !exclude.is_match(rel) && include.is_match(rel)
        };
        let abs_paths = walk_files(&repo_root, &accept_dir, &accept_file, None)?;
        let paths: BTreeSet<PathBuf> = abs_paths
            .into_iter()
            .filter_map(|p| p.strip_prefix(&repo_root).ok().map(Path::to_path_buf))
            .collect();
        Ok(Self { repo_root, paths })
    }

    /// Convenience wrapper around [`Self::build`] for callers that
    /// have glob *strings* rather than compiled [`GlobSet`]s. The
    /// `include` and `exclude` slices are compiled into globsets here;
    /// an empty `include` list is rewritten to `["**/*"]` so callers
    /// don't have to remember the "include everything" idiom.
    pub fn build_from_patterns(
        repo_root: PathBuf,
        include: &[&str],
        exclude: &[&str],
    ) -> Result<Self> {
        let include_patterns: Vec<&str> = if include.is_empty() {
            vec!["**/*"]
        } else {
            include.to_vec()
        };
        let include_set = compile_globs(&include_patterns)?;
        let exclude_set = compile_globs(exclude)?;
        Self::build(repo_root, &include_set, &exclude_set)
    }

    /// Derive a stricter scope by AND-ing additional include/exclude
    /// rules onto the existing path set. The returned scope shares the
    /// same `repo_root`; its `paths` are a (possibly equal) subset of
    /// `self.paths`. No I/O happens — purely set arithmetic over the
    /// already-walked paths.
    pub fn filter(&self, include: &GlobSet, exclude: &GlobSet) -> Self {
        let paths = self
            .paths
            .iter()
            .filter(|path| include.is_match(path) && !exclude.is_match(path))
            .cloned()
            .collect();
        Self {
            repo_root: self.repo_root.clone(),
            paths,
        }
    }

    /// Glob-string variant of [`Self::filter`]. Same empty-include
    /// convention as [`Self::build_from_patterns`].
    pub fn filter_by_patterns(&self, include: &[&str], exclude: &[&str]) -> Result<Self> {
        let include_patterns: Vec<&str> = if include.is_empty() {
            vec!["**/*"]
        } else {
            include.to_vec()
        };
        let include_set = compile_globs(&include_patterns)?;
        let exclude_set = compile_globs(exclude)?;
        Ok(self.filter(&include_set, &exclude_set))
    }

    /// Read every in-scope file from disk into memory, producing a
    /// [`ProjectScopeContent`]. Reads run sequentially via `tokio::fs`;
    /// for very large projects we can swap in a `JoinSet` later, but
    /// sequential reads keep the failure ordering deterministic which
    /// matters for the resume-after-error story.
    pub async fn read(&self) -> Result<ProjectScopeContent> {
        let mut files = Vec::with_capacity(self.paths.len());
        for relative in &self.paths {
            let absolute = self.repo_root.join(relative);
            let content = tokio::fs::read_to_string(&absolute)
                .await
                .wrap_err_with(|| format!("failed to read {}", absolute.display()))?;
            files.push(ScopedSourceFile {
                absolute_path: absolute,
                relative_path: relative.clone(),
                content,
            });
        }
        Ok(ProjectScopeContent {
            repo_root: self.repo_root.clone(),
            files,
        })
    }

    pub fn repo_root(&self) -> &Path {
        &self.repo_root
    }

    pub fn paths(&self) -> &BTreeSet<PathBuf> {
        &self.paths
    }

    pub fn is_empty(&self) -> bool {
        self.paths.is_empty()
    }

    pub fn len(&self) -> usize {
        self.paths.len()
    }
}

/// One file under a [`ProjectScope`], paired with its on-disk content.
/// Stores both the absolute and the repo-relative form so that downstream
/// callers (tree-sitter, foundry-compilers, AST consumers) never need to
/// re-derive one from the other and can match against whichever form the
/// underlying tool expects.
#[derive(Debug, Clone)]
pub struct ScopedSourceFile {
    pub absolute_path: PathBuf,
    pub relative_path: PathBuf,
    pub content: String,
}

/// In-memory snapshot of a [`ProjectScope`] after one pass of disk reads.
/// Owns its `files` so callers (e.g. [`crate::TreesitterProject`]) can
/// consume the bytes without re-touching the filesystem.
#[derive(Debug, Clone)]
pub struct ProjectScopeContent {
    repo_root: PathBuf,
    files: Vec<ScopedSourceFile>,
}

impl ProjectScopeContent {
    /// Direct constructor for callers that already have the file
    /// content in memory (e.g. they got the path list from a
    /// pre-existing source-discovery pipeline) and don't want to go
    /// through a [`ProjectScope`] walk. The slice order is
    /// preserved as-is — callers wanting `BTreeSet` ordering should
    /// sort beforehand.
    pub fn new(repo_root: PathBuf, files: Vec<ScopedSourceFile>) -> Self {
        Self { repo_root, files }
    }

    pub fn repo_root(&self) -> &Path {
        &self.repo_root
    }

    pub fn files(&self) -> &[ScopedSourceFile] {
        &self.files
    }

    pub fn into_files(self) -> Vec<ScopedSourceFile> {
        self.files
    }

    pub fn is_empty(&self) -> bool {
        self.files.is_empty()
    }

    pub fn len(&self) -> usize {
        self.files.len()
    }
}

// ---------------------------------------------------------------------------
// Internals
// ---------------------------------------------------------------------------

/// Parse a `scope.txt` file at the repo root and turn each non-comment
/// line into a glob pattern. Returns:
///
/// * `Ok(None)` — no `scope.txt` at the root; caller decides the
///   fallback (typically `"**/*.sol"` for Solidity flows).
/// * `Ok(Some(vec))` — one entry per non-blank, non-comment line.
///
/// The conversion rules mirror the C4-style scope.txt convention:
///
/// * Lines starting with `#` and blank lines are skipped.
/// * Absolute paths under the repo root are made relative.
/// * Trailing `/` becomes `<value>**` (whole directory).
/// * Paths that already contain glob meta-characters (`* ? [ ] { } !`)
///   are passed through unchanged.
/// * Bare directory names (no trailing slash, no meta) are rewritten
///   to `<value>/**`.
/// * Everything else is treated as a literal file path.
pub fn read_scope_txt(repo_root: &Path) -> Result<Option<Vec<String>>> {
    let path = repo_root.join("scope.txt");
    if !path.is_file() {
        return Ok(None);
    }
    let content = std::fs::read_to_string(&path)
        .wrap_err_with(|| format!("failed to read scope file {}", path.display()))?;
    let globs = content
        .lines()
        .filter_map(|line| scope_line_to_glob(repo_root, line))
        .collect::<Vec<_>>();
    Ok(Some(globs))
}

fn scope_line_to_glob(repo_root: &Path, line: &str) -> Option<String> {
    let trimmed = line.trim();
    if trimmed.is_empty() || trimmed.starts_with('#') {
        return None;
    }
    let path = Path::new(trimmed);
    let mut value = if path.is_absolute() {
        path.strip_prefix(repo_root)
            .unwrap_or(path)
            .to_string_lossy()
            .to_string()
    } else {
        trimmed.to_string()
    };
    value = value.trim_start_matches("./").to_string();
    if value.is_empty() {
        return None;
    }
    if value
        .chars()
        .any(|c| matches!(c, '*' | '?' | '[' | ']' | '{' | '}' | '!'))
    {
        return Some(value);
    }
    if value.ends_with('/') {
        return Some(format!("{value}**"));
    }
    if repo_root.join(&value).is_dir() {
        return Some(format!("{value}/**"));
    }
    Some(value)
}

fn compile_globs(patterns: &[&str]) -> Result<GlobSet> {
    let mut builder = GlobSetBuilder::new();
    for pattern in patterns {
        let glob =
            Glob::new(pattern).wrap_err_with(|| format!("invalid glob pattern `{pattern}`"))?;
        builder.add(glob);
    }
    builder.build().wrap_err("failed to build globset")
}

/// Generic recursive directory walker. Returns every regular file path
/// (absolute) under `root` for which `accept_file(path)` is true, never
/// descending into a directory `dir` where `accept_dir(dir)` is false.
/// Symlinks are skipped unconditionally to avoid loops. `max_depth` is
/// a countdown: `None` is unbounded, `Some(0)` returns immediately.
///
/// Wrapping crates layer their own semantics on top:
/// * `RepoSourceScope::build` adapts globset include/exclude — both
///   filters compare the repo-relative path; the absolute paths
///   returned here are stripped back down at the caller.
/// * The audit harness's `list_test_files` tool uses an extension
///   allowlist on files + a hardcoded vendored-dir blocklist on dirs
///   + a depth budget.
pub fn walk_files<F, G>(
    root: &Path,
    accept_dir: &F,
    accept_file: &G,
    max_depth: Option<usize>,
) -> Result<BTreeSet<PathBuf>>
where
    F: Fn(&Path) -> bool,
    G: Fn(&Path) -> bool,
{
    let mut out = BTreeSet::new();
    if !root.is_dir() {
        return Ok(out);
    }
    walk_files_inner(root, accept_dir, accept_file, max_depth, &mut out)?;
    Ok(out)
}

fn walk_files_inner<F, G>(
    dir: &Path,
    accept_dir: &F,
    accept_file: &G,
    depth_remaining: Option<usize>,
    out: &mut BTreeSet<PathBuf>,
) -> Result<()>
where
    F: Fn(&Path) -> bool,
    G: Fn(&Path) -> bool,
{
    if matches!(depth_remaining, Some(0)) {
        return Ok(());
    }
    let read = std::fs::read_dir(dir)
        .wrap_err_with(|| format!("failed to read directory {}", dir.display()))?;
    for entry in read {
        let entry = entry.wrap_err_with(|| format!("failed to read entry in {}", dir.display()))?;
        let file_type = entry
            .file_type()
            .wrap_err_with(|| format!("failed to read file type for {}", entry.path().display()))?;
        if file_type.is_symlink() {
            continue;
        }
        let path = entry.path();
        if file_type.is_dir() {
            if !accept_dir(&path) {
                continue;
            }
            walk_files_inner(
                &path,
                accept_dir,
                accept_file,
                depth_remaining.map(|d| d - 1),
                out,
            )?;
            continue;
        }
        if !file_type.is_file() {
            continue;
        }
        if accept_file(&path) {
            out.insert(path);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_file(root: &Path, relative: &str, content: &str) {
        let path = root.join(relative);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(path, content).unwrap();
    }

    fn tempdir() -> tempfile::TempDir {
        tempfile::tempdir().unwrap()
    }

    #[test]
    fn build_from_patterns_default_include_matches_everything() {
        let dir = tempdir();
        write_file(dir.path(), "src/A.sol", "contract A {}");
        write_file(dir.path(), "lib/B.sol", "contract B {}");
        write_file(dir.path(), "README.md", "x");

        let scope = ProjectScope::build_from_patterns(dir.path().to_path_buf(), &[], &[]).unwrap();
        assert_eq!(scope.len(), 3);
        assert!(scope.paths().contains(&PathBuf::from("src/A.sol")));
        assert!(scope.paths().contains(&PathBuf::from("README.md")));
    }

    #[test]
    fn build_honours_exclude() {
        let dir = tempdir();
        write_file(dir.path(), "src/A.sol", "");
        write_file(dir.path(), "lib/B.sol", "");

        let scope =
            ProjectScope::build_from_patterns(dir.path().to_path_buf(), &["**/*.sol"], &["lib/**"])
                .unwrap();
        assert_eq!(scope.len(), 1);
        assert!(scope.paths().contains(&PathBuf::from("src/A.sol")));
        assert!(!scope.paths().contains(&PathBuf::from("lib/B.sol")));
    }

    #[test]
    fn filter_narrows_existing_scope() {
        let dir = tempdir();
        write_file(dir.path(), "src/A.sol", "");
        write_file(dir.path(), "test/T.sol", "");
        let scope = ProjectScope::build_from_patterns(dir.path().to_path_buf(), &["**/*.sol"], &[])
            .unwrap();
        let narrowed = scope.filter_by_patterns(&["src/**"], &[]).unwrap();
        assert_eq!(narrowed.len(), 1);
        assert!(narrowed.paths().contains(&PathBuf::from("src/A.sol")));
    }

    #[tokio::test]
    async fn read_returns_content() {
        let dir = tempdir();
        write_file(dir.path(), "a.sol", "contract A {}");
        let scope = ProjectScope::build_from_patterns(dir.path().to_path_buf(), &["**/*.sol"], &[])
            .unwrap();
        let content = scope.read().await.unwrap();
        assert_eq!(content.len(), 1);
        let file = &content.files()[0];
        assert_eq!(file.relative_path, PathBuf::from("a.sol"));
        assert_eq!(file.content, "contract A {}");
    }
}
