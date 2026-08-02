//! `ProjectData` — the language + identity + content bundle that the rest
//! of the pipeline (extraction, mapping, spec-gen) consumes.
//!
//! Deliberately *not* a place for analysis output: `ProjectData` does not
//! own the call graph, treesitter contracts, audit report, or
//! foundry-compiled artifacts. Those live on their own types
//! ([`crate::SolidityTreesitterProject`], [`crate::FoundryProject`],
//! [`crate::C4PairedProjectData`]) so callers that only need one of them
//! don't drag the others into scope.

use std::path::{Path, PathBuf};

use color_eyre::eyre::{Result, WrapErr, eyre};

use crate::scope::{ProjectScope, ProjectScopeContent, ScopedSourceFile};

/// Source language for a project. Re-exported from
/// `knowdit-repo-model` so the type lives in one place — the
/// `ProjectProfile` row in the repo DB carries it, and the
/// project-load auto-detector here writes it into
/// [`ProjectData`]. Keeping the canonical definition in
/// `knowdit-repo-model` (the storage-layer crate) means the
/// DB-side serde derives are the only ones in the workspace.
pub use knowdit_repo_model::SourceLanguage;

/// A project, as the higher-level pipeline sees it.
///
/// `name` is the canonical identifier the database uses, `platform_id`
/// is the optional outside-world handle (e.g. `c4-455`), `language`
/// tells downstream agents which extractor to dispatch to, and
/// `content` is the already-read source corpus the scope walker
/// produced.
#[derive(Debug, Clone)]
pub struct ProjectData {
    pub name: String,
    pub platform_id: Option<String>,
    pub language: SourceLanguage,
    pub content: ProjectScopeContent,
}

impl ProjectData {
    pub fn new(
        name: String,
        platform_id: Option<String>,
        language: SourceLanguage,
        content: ProjectScopeContent,
    ) -> Self {
        Self {
            name,
            platform_id,
            language,
            content,
        }
    }

    /// Display-friendly identifier: `platform_id` if set, otherwise
    /// `name`. Used for log lines and progress reporting.
    pub fn display_id(&self) -> &str {
        self.platform_id.as_deref().unwrap_or(&self.name)
    }

    /// Repo root resolved by the scope walker. Always absolute and
    /// canonicalised because the underlying [`ProjectScope::build`]
    /// canonicalises before walking.
    pub fn repo_root(&self) -> &Path {
        self.content.repo_root()
    }

    /// In-scope source files with content. The slice order matches the
    /// `BTreeSet<PathBuf>` order of the [`ProjectScope`] this project
    /// was built from.
    pub fn source_files(&self) -> &[ScopedSourceFile] {
        self.content.files()
    }

    // ----------------------------------------------------------------
    // Constructors. All are async because they read source bodies from
    // disk via [`ProjectScope::read`]; even the language-fixed
    // constructors go through that path so all loaders share one walker.
    // ----------------------------------------------------------------

    /// Parse a `name:path` / `name:path:platform_id` spec and load
    /// the project, auto-detecting Solidity vs Move based on which
    /// extension is present under `path`. Errors when both are
    /// present (we don't support mixed-language projects) or when
    /// neither is.
    pub async fn from_source_dir_spec(spec: &str) -> Result<Self> {
        let parsed = ProjectSpec::parse(spec)?;
        Self::from_source_dir(&parsed.name, &parsed.root, parsed.platform_id.as_deref()).await
    }

    /// Parse a `name:path` / `name:path:platform_id` spec and load
    /// the project, forcing Solidity (no auto-detect). Faster than
    /// [`Self::from_source_dir_spec`] when you already know the
    /// project is Solidity because it only walks for `.sol` files.
    pub async fn from_path_spec(spec: &str) -> Result<Self> {
        let parsed = ProjectSpec::parse(spec)?;
        Self::from_dir(&parsed.name, &parsed.root, parsed.platform_id.as_deref()).await
    }

    /// Load a Solidity project from `root_dir`. Walks the tree with
    /// the default vendored-dir blocklist (`node_modules`, `lib`,
    /// `build`, `artifacts`, `cache`, `coverage`, `.git`, `target`,
    /// `typechain*`).
    pub async fn from_dir(name: &str, root_dir: &Path, platform_id: Option<&str>) -> Result<Self> {
        let scope = ProjectScope::build_from_patterns(
            root_dir.to_path_buf(),
            &["**/*.sol"],
            &DEFAULT_VENDORED_EXCLUDES,
        )
        .wrap_err_with(|| {
            format!(
                "failed to build Solidity scope under {}",
                root_dir.display()
            )
        })?;
        if scope.is_empty() {
            return Err(eyre!(
                "no Solidity source files found under {}",
                root_dir.display()
            ));
        }
        let content = scope.read().await?;
        Ok(Self {
            name: name.to_string(),
            platform_id: platform_id.map(str::to_string),
            language: SourceLanguage::Solidity,
            content,
        })
    }

    /// Load a project from `root_dir`, auto-detecting language by
    /// walking once per supported language and choosing the one
    /// that produced any files.
    pub async fn from_source_dir(
        name: &str,
        root_dir: &Path,
        platform_id: Option<&str>,
    ) -> Result<Self> {
        let solidity_scope = ProjectScope::build_from_patterns(
            root_dir.to_path_buf(),
            &["**/*.sol"],
            &DEFAULT_VENDORED_EXCLUDES,
        )
        .ok();
        let move_scope = ProjectScope::build_from_patterns(
            root_dir.to_path_buf(),
            &["**/*.move"],
            &DEFAULT_VENDORED_EXCLUDES,
        )
        .ok();

        let (language, scope) = match (
            solidity_scope
                .as_ref()
                .map(|s| !s.is_empty())
                .unwrap_or(false),
            move_scope.as_ref().map(|s| !s.is_empty()).unwrap_or(false),
        ) {
            (true, false) => (SourceLanguage::Solidity, solidity_scope.unwrap()),
            (false, true) => (SourceLanguage::Move, move_scope.unwrap()),
            (true, true) => {
                return Err(eyre!(
                    "project directory contains both Solidity and Move sources: {}",
                    root_dir.display()
                ));
            }
            (false, false) => {
                return Err(eyre!(
                    "no Solidity or Move source files found under {}",
                    root_dir.display()
                ));
            }
        };
        let content = scope.read().await?;
        Ok(Self {
            name: name.to_string(),
            platform_id: platform_id.map(str::to_string),
            language,
            content,
        })
    }

    /// Load a Move project snapshot. Walks for `**/*.move`, applies
    /// the standard vendored-dir blocklist, and tags `platform_id`
    /// as `b-<commit_hash>` to match the existing C4-style scheme.
    pub async fn from_move_snapshot(
        name: &str,
        root_dir: &Path,
        commit_hash: &str,
    ) -> Result<Self> {
        let scope = ProjectScope::build_from_patterns(
            root_dir.to_path_buf(),
            &["**/*.move"],
            &DEFAULT_VENDORED_EXCLUDES,
        )
        .wrap_err_with(|| format!("failed to build Move scope under {}", root_dir.display()))?;
        if scope.is_empty() {
            return Err(eyre!(
                "no Move source files found under {}",
                root_dir.display()
            ));
        }
        let content = scope.read().await?;
        Ok(Self {
            name: name.to_string(),
            platform_id: Some(format!("b-{commit_hash}")),
            language: SourceLanguage::Move,
            content,
        })
    }

    /// Build a project from an explicit list of repo-relative paths,
    /// skipping the [`ProjectScope::build_from_patterns`] walk.
    /// Useful when the source set has already been filtered upstream
    /// — e.g. by `scope.txt` + glob filters in the static Solidity
    /// pipeline — so we just want to read those exact files and
    /// wrap them in a `ProjectData`. The paths are joined onto a
    /// canonicalised `root_dir`; each file is loaded sequentially
    /// via `tokio::fs::read_to_string`.
    pub async fn from_relative_paths(
        name: &str,
        root_dir: &Path,
        language: SourceLanguage,
        platform_id: Option<&str>,
        relative_paths: &[PathBuf],
    ) -> Result<Self> {
        let root_dir = root_dir
            .canonicalize()
            .wrap_err_with(|| format!("failed to canonicalize repo root {}", root_dir.display()))?;
        let mut files = Vec::with_capacity(relative_paths.len());
        for relative_path in relative_paths {
            let absolute_path = root_dir.join(relative_path);
            let content = tokio::fs::read_to_string(&absolute_path)
                .await
                .wrap_err_with(|| {
                    format!(
                        "failed to read {} source file {}",
                        language.display_name(),
                        absolute_path.display()
                    )
                })?;
            files.push(ScopedSourceFile {
                absolute_path,
                relative_path: relative_path.clone(),
                content,
            });
        }
        let content = ProjectScopeContent::new(root_dir, files);
        Ok(Self {
            name: name.to_string(),
            platform_id: platform_id.map(str::to_string),
            language,
            content,
        })
    }
}

/// Default vendored-dir excludes shared by every project loader.
/// Matched against repo-relative paths via globset; covers both
/// `node_modules/` at root and any nested `**/node_modules/` etc.
///
/// In addition to third-party / build output directories, we exclude
/// common non-production Solidity trees (`test`, `deploy`, `script`,
/// and `src/vendor`) so the LLM-facing audit pipeline focuses on the
/// primary contract surface instead of ballooning prompts with harness
/// code or vendored implementations.
pub(crate) const DEFAULT_VENDORED_EXCLUDES: [&str; 42] = [
    "node_modules",
    "node_modules/**",
    "**/node_modules",
    "**/node_modules/**",
    "lib",
    "lib/**",
    "**/lib",
    "**/lib/**",
    "build",
    "build/**",
    "**/build",
    "**/build/**",
    "artifacts",
    "artifacts/**",
    "**/artifacts",
    "**/artifacts/**",
    "cache",
    "cache/**",
    "**/cache",
    "**/cache/**",
    // `test/` and `mock/` were filtered by the pre-350cd38
    // `should_skip_source_file` helper that lived in the old
    // knowdit-kg::project_loader (deleted by the May 2026
    // "workflow setup" refactor). The doc comment above always
    // claimed test/ was excluded — the array just didn't match.
    // Restoring both globs so post-refactor extracts match the
    // original behaviour. Without these, projects with large test/
    // fixtures (Kleidi has 1106 .sol files in test/) overflow the
    // categorize prompt budget.
    "test",
    "test/**",
    "**/test",
    "**/test/**",
    "mock",
    "mock/**",
    "**/mock",
    "**/mock/**",
    "deploy",
    "deploy/**",
    "**/deploy",
    "**/deploy/**",
    "script",
    "script/**",
    "**/script",
    "**/script/**",
    "src/vendor",
    "src/vendor/**",
    "**/src/vendor",
    "**/src/vendor/**",
    ".git/**",
    "target/**",
];


// ---------------------------------------------------------------------------
// Spec parsing (shared by from_source_dir_spec / from_path_spec).
// ---------------------------------------------------------------------------

/// Parsed `name:path[:platform_id]` triple. Lightweight (no source
/// load); construct via [`ProjectSpec::parse`] when you only need
/// the spec parts without walking the source tree.
#[derive(Debug, Clone)]
pub struct ProjectSpec {
    pub name: String,
    pub root: PathBuf,
    pub platform_id: Option<String>,
}

impl ProjectSpec {
    pub fn parse(spec: &str) -> Result<Self> {
        let parts: Vec<&str> = spec.splitn(3, ':').collect();
        let (name, root, platform_id) = match parts.as_slice() {
            [name, path] => (*name, *path, None),
            [name, path, pid] => (*name, *path, Some(*pid)),
            _ => {
                return Err(eyre!(
                    "expected `name:path` or `name:path:platform_id`, got `{}`",
                    spec
                ));
            }
        };
        if name.trim().is_empty() || root.trim().is_empty() {
            return Err(eyre!("project name and path must be non-empty: `{}`", spec));
        }
        // Shells only tilde-expand at the start of a word, so
        // `--project name:~/path` leaves the literal `~` in the spec
        // string (the shell sees one word starting with `n`).
        // `shellexpand::tilde` does the expansion: `~` / `~/...` →
        // `$HOME` / `$HOME/...`. `~user/...` is also handled when the
        // platform supports it. If `$HOME` is unset, the path comes
        // back unchanged — at which point the eventual filesystem
        // open will fail with the literal path in the error, which is
        // the right signal.
        Ok(ProjectSpec {
            name: name.trim().to_string(),
            root: PathBuf::from(shellexpand::tilde(root.trim()).as_ref()),
            platform_id: platform_id
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_string),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(root: &Path, rel: &str, body: &str) {
        let path = root.join(rel);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(path, body).unwrap();
    }

    #[tokio::test]
    async fn from_dir_loads_solidity_only() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "src/A.sol", "contract A {}");
        write(dir.path(), "lib/B.sol", "contract B {}"); // excluded by default
        let pd = ProjectData::from_dir("p", dir.path(), Some("plat-1"))
            .await
            .unwrap();
        assert_eq!(pd.language, SourceLanguage::Solidity);
        assert_eq!(pd.platform_id.as_deref(), Some("plat-1"));
        assert_eq!(pd.source_files().len(), 1);
        assert_eq!(pd.display_id(), "plat-1");
    }

    #[tokio::test]
    async fn from_source_dir_picks_solidity() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "src/A.sol", "");
        let pd = ProjectData::from_source_dir("p", dir.path(), None)
            .await
            .unwrap();
        assert_eq!(pd.language, SourceLanguage::Solidity);
        assert_eq!(pd.display_id(), "p");
    }

    #[tokio::test]
    async fn from_source_dir_picks_move() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "sources/A.move", "module M {}");
        let pd = ProjectData::from_source_dir("p", dir.path(), None)
            .await
            .unwrap();
        assert_eq!(pd.language, SourceLanguage::Move);
    }

    #[tokio::test]
    async fn from_source_dir_rejects_mixed_language() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "src/A.sol", "");
        write(dir.path(), "sources/A.move", "");
        let err = ProjectData::from_source_dir("p", dir.path(), None)
            .await
            .err()
            .unwrap();
        assert!(err.to_string().contains("both Solidity and Move"));
    }

    #[test]
    fn project_spec_parse_three_parts() {
        let p = ProjectSpec::parse("foo:/tmp/bar:c4-1").unwrap();
        assert_eq!(p.name, "foo");
        assert_eq!(p.root, PathBuf::from("/tmp/bar"));
        assert_eq!(p.platform_id.as_deref(), Some("c4-1"));
    }

    #[test]
    fn project_spec_parse_two_parts() {
        let p = ProjectSpec::parse("foo:bar").unwrap();
        assert!(p.platform_id.is_none());
    }

    #[test]
    fn project_spec_parse_rejects_garbage() {
        assert!(ProjectSpec::parse("foo").is_err());
        assert!(ProjectSpec::parse(":/x").is_err());
    }

    #[test]
    fn project_spec_parse_expands_leading_tilde() {
        // Shells don't tilde-expand inside `name:~/path` (the `~` is
        // not at the start of a word), so the parser delegates to
        // `shellexpand::tilde`. Read the test environment's current
        // `$HOME` rather than mutating it — `set_var` races between
        // concurrent tests.
        let home = std::env::var("HOME").expect("HOME should be set in the test environment");
        let p = ProjectSpec::parse("foo:~/megaeth/normal-account").unwrap();
        assert_eq!(p.root, PathBuf::from(home).join("megaeth/normal-account"));
    }

    #[test]
    fn project_spec_parse_leaves_non_tilde_paths_alone() {
        assert_eq!(
            ProjectSpec::parse("foo:/abs/path").unwrap().root,
            PathBuf::from("/abs/path")
        );
        assert_eq!(
            ProjectSpec::parse("foo:rel/path").unwrap().root,
            PathBuf::from("rel/path")
        );
        // `bar/~/baz` is not a leading `~/` — leave untouched. This
        // is `shellexpand::tilde`'s contract, not our own logic, but
        // worth pinning to catch the day someone swaps in a different
        // expander.
        assert_eq!(
            ProjectSpec::parse("foo:bar/~/baz").unwrap().root,
            PathBuf::from("bar/~/baz")
        );
    }
}
