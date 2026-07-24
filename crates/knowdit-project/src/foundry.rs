//! `FoundryProject` — solc + static-analysis view of a Solidity project.
//!
//! Drives `foundry-compilers` over a repo root and caches the
//! per-source-unit ASTs plus the derived [`CallGraph`] / [`StorageGraph`].
//! Construction is heavy (svm download + full solc compile) so all
//! analysis output is computed once in [`FoundryProject::build`] and
//! exposed via accessors.
//!
//! `foundry.toml` parsing is done with our own serde-derived
//! [`FoundryToml`] struct rather than pulling the upstream `foundry-config`
//! crate — we only care about the `remappings` (and `src`) keys and don't
//! want to compile all of figment / alloy-runtime / dotenv for that.

use std::{
    collections::{BTreeMap, BTreeSet, btree_map},
    fs,
    path::{Path, PathBuf},
};

use color_eyre::eyre::{Result, WrapErr, ensure, eyre};
use foundry_compilers::{
    Project, ProjectBuilder, ProjectPathsConfig,
    compilers::solc::{SolcCompiler, SolcLanguage, SolcSettings},
};
use foundry_compilers_artifacts::EvmVersion;
use foundry_compilers_artifacts::Settings as SolcCompilerSettings;
use foundry_compilers_artifacts::ast::SourceUnit as AstSourceUnit;
use foundry_compilers_artifacts::remappings::Remapping;
use knowdit_cg_static::{
    SourceUnitInput, StaticCallGraphResult, StorageAnalysisResult, analyze_storage,
    build_call_graph_with_maps,
};
use knowdit_repo_model::{cg::CallGraph, inheritance::InheritanceGraph, storage::StorageGraph};
use serde::Deserialize;

/// Heavyweight, owned analysis result for a Solidity repo: solc
/// compile + static call-graph synthesis + storage read/write analysis.
///
/// The `inputs` field is the canonical post-compile artifact —
/// `(absolute_path, source, source_unit_ast)` triples — and is kept
/// alongside the derived graphs so downstream passes can re-use the
/// already-parsed AST without re-driving solc.
#[derive(Debug, Clone)]
pub struct FoundryProject {
    repo_root: PathBuf,
    inputs: Vec<SourceUnitInput>,
    /// Full call-graph analysis output (graph + counts). Owned;
    /// accessors borrow the fields downstream callers need.
    call_graph: StaticCallGraphResult,
    /// Full storage analysis output (graph + counts).
    storage: StorageAnalysisResult,
}

/// Tunables for [`FoundryProject::build`]. Mirrors the subset of
/// `foundry-config`'s settings that affect static call-graph
/// extraction — everything else (test/script dirs, fuzz runs, etc.)
/// is irrelevant to us.
///
/// All fields are runtime-configurable via the CLI through
/// `knowdit::cli::FoundryCliOptions` and its `to_foundry_options`.
#[derive(Debug, Clone)]
pub struct FoundryOptions {
    /// Override the contracts source dir. When `Some`, joined against
    /// the project root; when `None`, taken from
    /// `[profile.<profile>].src` (or `[default].src`), falling back
    /// to first existing of `src/` and `contracts/`. Absolute paths
    /// are kept verbatim.
    pub src: Option<PathBuf>,
    /// Name of the `[profile.<name>]` block in `foundry.toml` to read
    /// for `src` / `remappings`. Defaults to `"default"`. Projects
    /// like silo-finance keep their src configuration in a non-default
    /// profile (e.g. `"core"`) — pass that name here to reach it.
    pub profile: String,
    /// Enable solc's IR-based codegen (the `viaIR = true` setting).
    /// Some projects (notably anything that hits "Stack too deep"
    /// from the legacy codegen) need this to compile at all. Off by
    /// default to match foundry's own default.
    pub via_ir: bool,
}

impl Default for FoundryOptions {
    fn default() -> Self {
        Self {
            src: None,
            profile: "default".to_string(),
            via_ir: false,
        }
    }
}

impl FoundryProject {
    /// Compile the project at `repo_root` via solc (using foundry's
    /// auto-managed solc-version-manager and remapping discovery), then
    /// run the static call-graph + storage analyses over the resulting
    /// ASTs. Async because the compile itself happens on a blocking
    /// task and we wait for it via tokio.
    ///
    /// `options` controls profile selection, source-dir override, and
    /// the `viaIR` solc flag — see [`FoundryOptions`].
    pub async fn build(repo_root: PathBuf, options: FoundryOptions) -> Result<Self> {
        let repo_root = Self::canonical_repo_root(repo_root)?;
        let inputs = Self::compile_source_units(&repo_root, &options).await?;
        Self::finish_build(repo_root, inputs)
    }

    /// Compile via the caller-supplied `forge` binary (`forge build --force
    /// --ast --build-info`, all outputs redirected to a temp dir) and parse
    /// the emitted build-info JSON for per-source ASTs. This inherits forge's
    /// EXACT config resolution — remappings (incl. context-scoped nested
    /// ones), profile selection, solc version management, `ignored_error_codes`
    /// — so any project `forge build` accepts compiles here identically.
    /// Prefer this whenever a forge binary is available; the in-process
    /// foundry-compilers pipeline ([`Self::build`]) remains the fallback and
    /// hand-mirrors that resolution. Requires a forge new enough to know
    /// `--ast` (validated on 1.7.x).
    pub async fn build_with_forge_bin(
        forge_bin: PathBuf,
        repo_root: PathBuf,
        options: FoundryOptions,
    ) -> Result<Self> {
        let repo_root = Self::canonical_repo_root(repo_root)?;
        let inputs =
            Self::compile_source_units_with_forge(&forge_bin, &repo_root, &options).await?;
        Self::finish_build(repo_root, inputs)
    }

    /// Pick the compile backend from `forge_bin`: `Some` → the forge-binary
    /// build-info pipeline ([`Self::build_with_forge_bin`]), `None` → the
    /// in-process foundry-compilers fallback ([`Self::build`]).
    pub async fn may_build_forge(
        forge_bin: Option<PathBuf>,
        repo_root: PathBuf,
        options: FoundryOptions,
    ) -> Result<Self> {
        match forge_bin {
            Some(bin) => {
                tracing::info!(
                    "FoundryProject: compiling via forge binary {}",
                    bin.display()
                );
                Self::build_with_forge_bin(bin, repo_root, options).await
            }
            None => {
                tracing::info!(
                    "FoundryProject: no forge binary supplied; compiling via in-process foundry-compilers"
                );
                Self::build(repo_root, options).await
            }
        }
    }

    fn canonical_repo_root(repo_root: PathBuf) -> Result<PathBuf> {
        let repo_root = repo_root.canonicalize().wrap_err_with(|| {
            format!("failed to canonicalize repo root {}", repo_root.display())
        })?;
        ensure!(
            repo_root.is_dir(),
            "repo root {} is not a directory",
            repo_root.display(),
        );
        Ok(repo_root)
    }

    /// Shared tail of every compile backend: static call-graph + storage
    /// analyses over the source-unit ASTs.
    fn finish_build(repo_root: PathBuf, inputs: Vec<SourceUnitInput>) -> Result<Self> {
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

    /// Full call-graph analysis output (graph + counts).
    pub fn call_graph_result(&self) -> &StaticCallGraphResult {
        &self.call_graph
    }

    /// Full storage analysis output (graph + counts).
    pub fn storage_result(&self) -> &StorageAnalysisResult {
        &self.storage
    }

    // ----------------------------------------------------------------
    // Internals — solc compile pipeline. Ported from the previous
    // `cmd::solidity::compile_source_units` + helpers. Lives on
    // `FoundryProject` so the build pipeline is one cohesive type
    // surface rather than a free-floating helper module.
    // ----------------------------------------------------------------

    /// Drive `solc` over `repo_root` and convert every compiled unit
    /// into the high-fidelity AST shape that `knowdit-cg-static`
    /// consumes. Filters by `include_path_fragments` /
    /// `exclude_path_fragments` after compile (we still ask solc to
    /// compile everything it can resolve — partial sets miss imports).
    async fn compile_source_units(
        repo_root: &Path,
        options: &FoundryOptions,
    ) -> Result<Vec<SourceUnitInput>> {
        let repo_root = repo_root.to_path_buf();
        let options = options.clone();

        tokio::task::spawn_blocking(move || -> Result<Vec<SourceUnitInput>> {
            // Parse `foundry.toml` once — it drives both path/remapping
            // resolution and the solc settings assembled below.
            let foundry = FoundryToml::load(&repo_root)?;
            let paths = Self::build_project_paths(&repo_root, &options, &foundry)?;

            // Assemble solc settings from the selected profile so we
            // compile the same way `forge build` would — honouring
            // `evm_version` (e.g. a project that needs the `osaka`-only
            // `clz` opcode), `via_ir`, and the optimizer config.
            // Starting from `Settings::default()` preserves the default
            // output_selection + `with_ast()` that the call-graph
            // extractor depends on; we only overlay the profile's keys.
            // The `--via-ir` CLI flag force-enables IR codegen on top of
            // whatever the toml declares.
            let mut solc_settings = SolcSettings::default();
            solc_settings.settings = foundry
                .select(&options.profile)
                .solc_compiler_settings(options.via_ir)?;

            // `ephemeral()` disables the on-disk cache
            // (`cache/solidity-files-cache.json`) because (a) cached
            // entries from a prior `forge build` don't carry AST output
            // so reusing them yields zero ASTs; (b) we don't want to
            // litter the project's `out/` with our own artifacts.
            let project: Project<SolcCompiler> = ProjectBuilder::<SolcCompiler>::default()
                .paths(paths)
                .settings(solc_settings)
                .ephemeral()
                .no_artifacts()
                .build(SolcCompiler::AutoDetect)
                .map_err(|err| eyre!("failed to build foundry-compilers project: {err}"))?;

            let output = project
                .compile()
                .map_err(|err| eyre!("foundry-compilers compilation failed: {err}"))?;
            for compile_error in &output.output().errors {
                if compile_error.severity.is_error() {
                    return Err(eyre!("solc reported error: {compile_error}"));
                }
            }

            let aggregated = output.into_output();
            let mut inputs: Vec<SourceUnitInput> = Vec::new();
            for (path, source_file) in aggregated.sources.into_sources() {
                let Some(ast) = source_file.ast else {
                    tracing::warn!("solc emitted no AST for {} (skipping)", path.display());
                    continue;
                };

                // foundry-compilers exposes a low-fidelity AST type but
                // knowdit-cg-static expects the high-fidelity
                // `foundry_compilers_artifacts::ast::SourceUnit`. The
                // documented conversion path is round-tripping through
                // `serde_json::Value`; one allocation per file,
                // negligible compared to compile time.
                let ast_value = serde_json::to_value(&ast).wrap_err_with(|| {
                    format!(
                        "failed to re-serialize lowfidelity AST for {}",
                        path.display()
                    )
                })?;
                let source_unit: AstSourceUnit =
                    serde_json::from_value(ast_value).wrap_err_with(|| {
                        format!("failed to deserialize solc AST for {}", path.display())
                    })?;

                let abs_path = if path.is_absolute() {
                    path.clone()
                } else {
                    repo_root.join(&path)
                };
                let source = fs::read_to_string(&abs_path).wrap_err_with(|| {
                    format!("failed to read source content from {}", abs_path.display())
                })?;

                inputs.push(SourceUnitInput {
                    absolute_path: source_unit.absolute_path.clone(),
                    source,
                    source_unit,
                });
            }

            ensure!(
                !inputs.is_empty(),
                "solc produced no source unit ASTs for the project"
            );
            Ok(inputs)
        })
        .await
        .wrap_err("solc compile task panicked")?
    }

    /// `forge build` the project and harvest per-source ASTs from its
    /// build-info JSON. Outputs (`out`, `build-info`, compile cache) all live
    /// in a temp dir so the project checkout stays pristine; `--force`
    /// guarantees a fresh compile (cached artifacts carry no AST). Test and
    /// script sources are skipped to match the in-process backend's
    /// `.knowdit-no-walk` behaviour.
    async fn compile_source_units_with_forge(
        forge_bin: &Path,
        repo_root: &Path,
        options: &FoundryOptions,
    ) -> Result<Vec<SourceUnitInput>> {
        let tmp = tempfile::tempdir().wrap_err("failed to create temp dir for forge outputs")?;
        let out_dir = tmp.path().join("out");
        let bi_dir = tmp.path().join("build-info");
        let cache_dir = tmp.path().join("cache");

        let mut cmd = tokio::process::Command::new(forge_bin);
        cmd.current_dir(repo_root)
            .arg("build")
            .arg("--force")
            .arg("--ast")
            .arg("--build-info")
            // `test` / `script` are forge aliases for the `.t.sol` / `.s.sol`
            // suffixes only; the dir globs also exclude un-suffixed helpers
            // (mocks under test/, config helpers under script/) to match the
            // in-process backend's whole-dir `.knowdit-no-walk` exclusion.
            .args(["--skip", "test"])
            .args(["--skip", "script"])
            .args(["--skip", "**/test/**"])
            .args(["--skip", "**/script/**"])
            .arg("-o")
            .arg(&out_dir)
            .arg("--build-info-path")
            .arg(&bi_dir)
            .arg("--cache-path")
            .arg(&cache_dir)
            .env("FOUNDRY_PROFILE", &options.profile);
        if options.via_ir {
            cmd.arg("--via-ir");
        }
        if let Some(src) = &options.src {
            cmd.env("FOUNDRY_SRC", src);
        }

        let output = cmd
            .output()
            .await
            .wrap_err_with(|| format!("failed to spawn forge binary {}", forge_bin.display()))?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let stdout = String::from_utf8_lossy(&output.stdout);
            let tail = |s: &str| {
                s.char_indices()
                    .rev()
                    .nth(3999)
                    .map(|(i, _)| s[i..].to_string())
                    .unwrap_or_else(|| s.to_string())
            };
            return Err(eyre!(
                "forge build failed ({}) in {}:\nstdout tail: {}\nstderr tail: {}",
                output.status,
                repo_root.display(),
                tail(&stdout),
                tail(&stderr),
            ));
        }

        // One build-info file per compiler job — read them all and merge
        // sources (first occurrence of a path wins).
        let mut inputs: Vec<SourceUnitInput> = Vec::new();
        let mut seen_paths: BTreeSet<String> = BTreeSet::new();
        for entry in fs::read_dir(&bi_dir)
            .wrap_err_with(|| format!("failed to read build-info dir {}", bi_dir.display()))?
        {
            let path = entry?.path();
            if path.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }
            let file = fs::File::open(&path)
                .wrap_err_with(|| format!("failed to open build-info {}", path.display()))?;
            let value: serde_json::Value =
                serde_json::from_reader(std::io::BufReader::new(file))
                    .wrap_err_with(|| format!("failed to parse build-info {}", path.display()))?;

            let input_sources = value
                .get("input")
                .and_then(|i| i.get("sources"))
                .and_then(|s| s.as_object());
            let Some(sources) = value
                .get("output")
                .and_then(|o| o.get("sources"))
                .and_then(|s| s.as_object())
            else {
                continue;
            };

            for (source_path, source_entry) in sources {
                if seen_paths.contains(source_path) {
                    continue;
                }
                let Some(ast) = source_entry.get("ast") else {
                    tracing::warn!("forge emitted no AST for {source_path} (skipping)");
                    continue;
                };
                let source_unit: AstSourceUnit = serde_json::from_value(ast.clone())
                    .wrap_err_with(|| {
                        format!("failed to deserialize solc AST for {source_path}")
                    })?;

                // Prefer the exact bytes solc compiled (standard-json input
                // section); fall back to reading the file from disk.
                let source = match input_sources
                    .and_then(|s| s.get(source_path))
                    .and_then(|s| s.get("content"))
                    .and_then(|c| c.as_str())
                {
                    Some(content) => content.to_string(),
                    None => {
                        let abs = repo_root.join(source_path);
                        fs::read_to_string(&abs).wrap_err_with(|| {
                            format!("failed to read source content from {}", abs.display())
                        })?
                    }
                };

                seen_paths.insert(source_path.clone());
                inputs.push(SourceUnitInput {
                    absolute_path: source_unit.absolute_path.clone(),
                    source,
                    source_unit,
                });
            }
        }

        ensure!(
            !inputs.is_empty(),
            "forge build produced no source unit ASTs for the project (build-info dir {})",
            bi_dir.display(),
        );
        Ok(inputs)
    }

    /// Construct a `ProjectPathsConfig` that mirrors what `forge`
    /// resolves at startup: sources dir + libs (`lib`, `node_modules`)
    /// + remappings (foundry.toml → remappings.txt → nested
    /// `lib/<sub>/foundry.toml` + `lib/<sub>/remappings.txt` →
    /// `Remapping::find_many` auto-detect).
    ///
    /// The remapping pipeline mirrors `foundry-config`
    /// (`providers/remappings.rs`) closely enough that any project
    /// that compiles with `forge build` should compile here too:
    ///
    /// 1. User-supplied remappings (foundry.toml + remappings.txt)
    ///    are added first, in that order.
    /// 2. For each `lib/<sub>` containing a `foundry.toml`, that
    ///    sub-project's remappings (foundry.toml + remappings.txt)
    ///    are collected with paths absolutized against the sub root,
    ///    plus a synthetic `<sub_name>/=<sub>/<custom_src>/` when the
    ///    sub-project's `src` is non-default. `Remapping::find_many`
    ///    is run on every lib dir for directory-structure-based
    ///    auto-detect.
    /// 3. Auto-detected remappings are deduped by `(context, name)`,
    ///    keeping the shortest path (closest to root). Generic names
    ///    `lib/`, `src/`, `contracts/` are dropped.
    /// 4. Auto-detected remappings are merged into the user set via
    ///    `Remappings::push`, which performs prefix-conflict dedup
    ///    (`@foo/` blocks `@foo/bar/` in the same context), filters
    ///    `.sol`-file remappings whose target isn't `.sol`, and
    ///    drops anything matching the project's own `src`/`test`/
    ///    `script` directory names (foundry/foundry#3440).
    ///
    /// `tests` and `scripts` are pointed at a sentinel path so
    /// foundry-compilers skips them: audit checkouts often have test
    /// files whose imports don't resolve in the audit environment,
    /// and we only care about `src/`.
    fn build_project_paths(
        repo_root: &Path,
        options: &FoundryOptions,
        foundry: &FoundryToml,
    ) -> Result<ProjectPathsConfig<SolcLanguage>> {
        let mut builder = ProjectPathsConfig::builder().root(repo_root);

        // Source-dir precedence: explicit `options.src` →
        // `[profile.<options.profile>].src` → `[default].src` →
        // `[profile.default].src` → fallback to first existing
        // `src/` / `contracts/`.
        let profile = foundry.select(&options.profile);
        let configured_src = profile.src.clone();
        let sources_dir = if let Some(p) = options.src.as_ref() {
            Some(if p.is_absolute() {
                p.clone()
            } else {
                repo_root.join(p)
            })
        } else if let Some(s) = configured_src.as_deref() {
            Some(repo_root.join(s))
        } else {
            ["src", "contracts"]
                .into_iter()
                .map(|d| repo_root.join(d))
                .find(|p| p.is_dir())
        };
        if let Some(dir) = &sources_dir {
            builder = builder.sources(dir);
        }

        let no_walk = repo_root.join(".knowdit-no-walk");
        builder = builder.tests(&no_walk).scripts(&no_walk);

        let lib_dirs: Vec<PathBuf> = ["lib", "node_modules"]
            .into_iter()
            .map(|d| repo_root.join(d))
            .filter(|p| p.is_dir())
            .collect();
        if !lib_dirs.is_empty() {
            builder = builder.libs(lib_dirs.iter().cloned());
        }

        // Project-path names that lib remappings are not allowed to
        // override (foundry/foundry#3440). Mirrors foundry-config's
        // `Remappings::with_figment` for src/test/script.
        let project_src_name = configured_src
            .clone()
            .or_else(|| {
                sources_dir.as_ref().and_then(|p| {
                    p.file_name()
                        .and_then(|s| s.to_str())
                        .map(|s| s.to_string())
                })
            })
            .unwrap_or_else(|| "src".to_string());
        let mut project_path_names: BTreeSet<String> = BTreeSet::new();
        project_path_names.insert(format!("{project_src_name}/"));
        project_path_names.insert("test/".to_string());
        project_path_names.insert("script/".to_string());

        // ----- user remappings: remappings.txt FIRST, then foundry.toml
        // (selected profile + legacy `[default]`) — matches forge's
        // precedence (`remappings.txt` wins on an exact-name duplicate) -----
        let mut user_remappings: Vec<Remapping> = Vec::new();
        let remappings_txt = repo_root.join("remappings.txt");
        if remappings_txt.is_file() {
            let text = fs::read_to_string(&remappings_txt).wrap_err_with(|| {
                format!(
                    "failed to read remappings file {}",
                    remappings_txt.display()
                )
            })?;
            for (idx, raw) in text.lines().enumerate() {
                if let Some(r) =
                    parse_remapping_line(raw, &remappings_txt.display().to_string(), Some(idx + 1))
                {
                    user_remappings.push(r);
                }
            }
        }
        for raw in foundry.remappings_for_profile(&options.profile) {
            if let Some(r) = parse_remapping_line(&raw, "foundry.toml", None) {
                user_remappings.push(r);
            }
        }

        let mut all = Remappings::with_project_paths(project_path_names);
        all.extend_user(user_remappings);

        // ----- auto-detect: nested foundry + Remapping::find_many -----
        // Mirrors foundry-config's `get_remappings` loop. All paths in
        // `lib_dedup` are absolute so `insert_closest`'s components-count
        // comparison is fair across nested + find_many.
        let mut lib_dedup: BTreeMap<Option<String>, BTreeMap<String, PathBuf>> = BTreeMap::new();
        for lib in &lib_dirs {
            let entries = match fs::read_dir(lib) {
                Ok(it) => it,
                Err(err) => {
                    tracing::warn!("failed to read lib dir {}: {err}", lib.display());
                    continue;
                }
            };
            for entry in entries.flatten() {
                let sub = entry.path();
                if !sub.is_dir() {
                    continue;
                }
                for r in collect_nested_remappings(&sub)? {
                    if matches!(r.name.as_str(), "lib/" | "src/" | "contracts/") {
                        continue;
                    }
                    insert_closest(&mut lib_dedup, r.context, r.name, PathBuf::from(r.path));
                }
            }
            for r in Remapping::find_many(lib) {
                if matches!(r.name.as_str(), "lib/" | "src/" | "contracts/") {
                    continue;
                }
                insert_closest(&mut lib_dedup, r.context, r.name, PathBuf::from(r.path));
            }
        }

        let flat: Vec<Remapping> = lib_dedup
            .into_iter()
            .flat_map(|(context, m)| {
                m.into_iter().map(move |(name, path)| Remapping {
                    context: context.clone(),
                    name,
                    path: path.to_string_lossy().into_owned(),
                })
            })
            .collect();
        all.extend(flat);

        let remappings = all.into_inner();
        if !remappings.is_empty() {
            builder = builder.remappings(remappings);
        }

        builder
            .build()
            .map_err(|err| eyre!("failed to build foundry-compilers project paths: {err}"))
    }
}

// ---------------------------------------------------------------------------
// Remapping resolution helpers — straight ports of `foundry-config`'s
// `providers/remappings.rs` types/functions, restricted to what we need.
// ---------------------------------------------------------------------------

/// Mirror of `foundry_config::Remappings`: append-only set with
/// prefix-conflict dedup and project-path filtering.
struct Remappings {
    remappings: Vec<Remapping>,
    /// Names (with trailing `/`) of the project's `src` / `test` /
    /// `script` dirs. Lib remappings matching any of these names are
    /// dropped — see foundry/foundry#3440.
    project_paths: BTreeSet<String>,
}

impl Remappings {
    fn with_project_paths(project_paths: BTreeSet<String>) -> Self {
        Self {
            remappings: Vec::new(),
            project_paths,
        }
    }

    /// Direct port of `foundry_config::Remappings::push`.
    fn push(&mut self, remapping: Remapping) {
        // `.sol`-file remapping: target must also be a `.sol` file.
        if remapping.name.ends_with(".sol") && !remapping.path.ends_with(".sol") {
            return;
        }

        let conflict = self.remappings.iter().any(|existing| {
            if remapping.name.ends_with(".sol") {
                return existing.name == remapping.name
                    && existing.context == remapping.context
                    && existing.path == remapping.path;
            }
            let mut existing_name_path = existing.name.clone();
            if !existing_name_path.ends_with('/') {
                existing_name_path.push('/');
            }
            let is_conflicting = remapping.name.starts_with(&existing_name_path)
                || existing.name.starts_with(&remapping.name);
            is_conflicting && existing.context == remapping.context
        });
        if conflict {
            return;
        }

        if self
            .project_paths
            .iter()
            .any(|p| remapping.name.eq_ignore_ascii_case(p))
        {
            return;
        }

        self.remappings.push(remapping);
    }

    fn extend(&mut self, remappings: Vec<Remapping>) {
        for r in remappings {
            self.push(r);
        }
    }

    /// Insert a USER remapping (`remappings.txt` / `foundry.toml`). Unlike
    /// [`Self::push`], user remappings are deduped EXACTLY (same context +
    /// name; first one wins, so pass `remappings.txt` before `foundry.toml`)
    /// — nested prefixes like `@openzeppelin/` alongside
    /// `@openzeppelin/contracts-upgradeable/` are all kept, and solc's
    /// longest-prefix match picks the right one per import. Routing user
    /// remappings through `push`'s prefix-conflict filter (meant for
    /// AUTO-DETECTED remappings, foundry/foundry#3440) silently dropped the
    /// longer user rules and mis-resolved imports `forge build` accepts.
    fn push_user(&mut self, remapping: Remapping) {
        if remapping.name.ends_with(".sol") && !remapping.path.ends_with(".sol") {
            return;
        }
        let duplicate = self.remappings.iter().any(|existing| {
            existing.context == remapping.context && existing.name == remapping.name
        });
        if duplicate {
            return;
        }
        if self
            .project_paths
            .iter()
            .any(|p| remapping.name.eq_ignore_ascii_case(p))
        {
            return;
        }
        self.remappings.push(remapping);
    }

    fn extend_user(&mut self, remappings: Vec<Remapping>) {
        for r in remappings {
            self.push_user(r);
        }
    }

    /// Final `(context, name)` dedup — mirrors `foundry_config::Remappings::into_inner`.
    fn into_inner(self) -> Vec<Remapping> {
        let mut seen: BTreeSet<String> = BTreeSet::new();
        self.remappings
            .into_iter()
            .filter(|r| {
                let key = match &r.context {
                    Some(ctx) => format!("{ctx}{}", r.name),
                    None => r.name.clone(),
                };
                seen.insert(key)
            })
            .collect()
    }
}

/// Direct port of `foundry_config::providers::remappings::insert_closest`.
fn insert_closest(
    mappings: &mut BTreeMap<Option<String>, BTreeMap<String, PathBuf>>,
    context: Option<String>,
    key: String,
    path: PathBuf,
) {
    let m = mappings.entry(context).or_default();
    match m.entry(key) {
        btree_map::Entry::Occupied(mut e)
            if e.get().components().count() > path.components().count() =>
        {
            e.insert(path);
        }
        btree_map::Entry::Vacant(e) => {
            e.insert(path);
        }
        _ => {}
    }
}

/// Parse one remappings line, stripping a trailing `# comment`
/// (foundry-config doesn't do this, but `remappings.txt` files in the
/// wild often have inline comments — keeping it is harmless).
fn parse_remapping_line(raw: &str, source: &str, lineno: Option<usize>) -> Option<Remapping> {
    let trimmed = raw.split('#').next().unwrap_or("").trim();
    if trimmed.is_empty() {
        return None;
    }
    match trimmed.parse::<Remapping>() {
        Ok(r) => Some(r),
        Err(err) => {
            let where_ = match lineno {
                Some(n) => format!("{source}:{n}"),
                None => source.to_string(),
            };
            tracing::warn!("ignoring invalid remapping at {where_}: {trimmed:?} ({err})");
            None
        }
    }
}

/// Equivalent of `foundry_config::providers::remappings::nested_foundry_remappings`,
/// but without depending on the figment-driven `Config::load_with_root_and_fallback`.
/// Reads `<sub>/foundry.toml`'s `remappings = [...]` plus
/// `<sub>/remappings.txt`, absolutizes each remapping's path against
/// `<sub>`, and (when `<sub>`'s `src` field is non-standard) synthesizes
/// the `<sub_name>/=<sub>/<src>/` shortcut.
///
/// Returns an empty Vec when `<sub>/foundry.toml` is absent — we use
/// that as the gate-keeper, mirroring `foundry_toml_dirs` (depth=1).
fn collect_nested_remappings(sub_abs: &Path) -> Result<Vec<Remapping>> {
    if !sub_abs.join("foundry.toml").is_file() {
        return Ok(Vec::new());
    }

    let toml = FoundryToml::load(sub_abs)?;
    let mut out: Vec<Remapping> = Vec::new();

    // Nested sub-projects always read their own `[profile.default]`
    // (mirroring foundry-config's `Config::load_with_root_and_fallback`,
    // which selects the default profile when consuming a lib).
    for raw in toml.remappings_for_profile("default") {
        if let Some(mut r) = parse_remapping_line(&raw, "foundry.toml", None) {
            r.path = absolutize_remapping_path(sub_abs, &r.path);
            out.push(r);
        }
    }

    let rtxt = sub_abs.join("remappings.txt");
    if rtxt.is_file() {
        let text = fs::read_to_string(&rtxt)
            .wrap_err_with(|| format!("failed to read {}", rtxt.display()))?;
        for (idx, raw) in text.lines().enumerate() {
            if let Some(mut r) =
                parse_remapping_line(raw, &rtxt.display().to_string(), Some(idx + 1))
            {
                r.path = absolutize_remapping_path(sub_abs, &r.path);
                out.push(r);
            }
        }
    }

    // Mirror foundry-config's `src_remapping` synthesis: if the
    // sub-project's `src` is not one of the standard names that
    // `Remapping::find_many` already recognizes, add an explicit
    // `<sub_name>/=<sub>/<src>/` so imports of the form
    // `<sub_name>/Foo.sol` resolve.
    let sub_src = toml.select("default").src.clone();
    if let Some(src) = sub_src
        && !matches!(src.as_str(), "src" | "contracts" | "lib")
        && let Some(name) = sub_abs.file_name().and_then(|s| s.to_str())
    {
        let mut path = sub_abs.join(&src).to_string_lossy().into_owned();
        if !path.ends_with('/') {
            path.push('/');
        }
        out.push(Remapping {
            context: None,
            name: format!("{name}/"),
            path,
        });
    }

    Ok(out)
}

/// Resolve a remapping `path` (as written in a sub-project's config) to
/// an absolute path. Relative paths are joined against the sub-project
/// root; absolute paths are kept verbatim. The result always ends with
/// a trailing `/` so foundry-compilers treats it as a directory prefix.
fn absolutize_remapping_path(base: &Path, raw: &str) -> String {
    let pb = if Path::new(raw).is_absolute() {
        PathBuf::from(raw)
    } else {
        base.join(raw)
    };
    let mut s = pb.to_string_lossy().into_owned();
    if !s.ends_with('/') {
        s.push('/');
    }
    s
}

// ---------------------------------------------------------------------------
// foundry.toml parsing — minimal serde mirror.
// ---------------------------------------------------------------------------

/// Minimal serde-derived mirror of `foundry-config`'s `Config`,
/// restricted to the keys this crate consumes (`src`, `libs`,
/// `remappings`). Foundry supports two layouts for the same payload:
///
/// * `[default]` — legacy flat block.
/// * `[profile.<name>]` — current. The name is arbitrary; `default`
///   is just one of them. Real projects (silo-finance, optimism,
///   etc.) define multiple and pick at the CLI via `--profile`.
///
/// [`Self::select`] resolves a profile name to a single profile by
/// looking in `[profile.<name>]` first, then falling back to the
/// legacy `[default]` block, and finally an empty profile.
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct FoundryToml {
    /// Legacy `[default]` block.
    pub default: FoundryProfile,
    /// All `[profile.<name>]` blocks. Unknown names are not an error
    /// — `select` decides what to do.
    pub profile: BTreeMap<String, FoundryProfile>,
}

#[derive(Debug, Default, Deserialize, Clone)]
#[serde(default)]
pub struct FoundryProfile {
    /// `src = "src"` — the contracts root.
    pub src: Option<String>,
    /// `libs = ["lib"]` — vendored dep dirs.
    #[allow(dead_code)]
    pub libs: Vec<String>,
    /// `remappings = ["@oz/=lib/openzeppelin-contracts/contracts/", ...]`.
    pub remappings: Vec<String>,
    /// `test = "test"` — Foundry test root. Consumers pick which
    /// profile to read from (audit currently uses the conventional
    /// default).
    pub test: Option<String>,
    /// `evm_version = "osaka"` — target EVM version. Must be honoured
    /// or projects using version-gated opcodes (e.g. the `osaka`-only
    /// `clz`) fail to compile with solc error 4948.
    pub evm_version: Option<String>,
    /// `via_ir = true` — IR-based codegen. Some projects only compile
    /// (no "stack too deep") through the IR pipeline.
    pub via_ir: Option<bool>,
    /// `optimizer = true` — enable the solc optimizer.
    pub optimizer: Option<bool>,
    /// `optimizer_runs = 800` — optimizer run count.
    pub optimizer_runs: Option<usize>,
}

impl FoundryProfile {
    /// Assemble the `solc` settings this profile implies, mirroring the
    /// `[profile.<name>]` keys `forge` itself honours: `evm_version`,
    /// `via_ir`, `optimizer`, `optimizer_runs`. Starting from
    /// `Settings::default()` keeps solc's default output_selection
    /// (plus AST) that the call-graph extractor relies on; we only
    /// overlay the keys the profile actually sets, leaving the rest at
    /// their defaults.
    ///
    /// `cli_via_ir` force-enables IR codegen (the `--via-ir` escape
    /// hatch) regardless of the toml; the toml can also enable it on
    /// its own. Errors only on an `evm_version` string solc doesn't
    /// recognise.
    fn solc_compiler_settings(&self, cli_via_ir: bool) -> Result<SolcCompilerSettings> {
        let mut settings = SolcCompilerSettings::default();
        if cli_via_ir || self.via_ir.unwrap_or(false) {
            settings = settings.with_via_ir();
        }
        if let Some(raw) = self.evm_version.as_deref() {
            let evm: EvmVersion = raw
                .parse()
                .map_err(|_| eyre!("unsupported evm_version `{raw}` in foundry.toml"))?;
            settings.evm_version = Some(evm);
        }
        if let Some(enabled) = self.optimizer {
            settings.optimizer.enabled = Some(enabled);
        }
        if let Some(runs) = self.optimizer_runs {
            settings.optimizer.runs = Some(runs);
        }
        Ok(settings)
    }
}

impl FoundryToml {
    /// Load and parse `<repo_root>/foundry.toml`. Returns
    /// `FoundryToml::default()` (empty) when the file is missing or
    /// not valid TOML — callers fall back to `remappings.txt` /
    /// auto-discovery in those cases.
    fn load(repo_root: &Path) -> Result<Self> {
        let path = repo_root.join("foundry.toml");
        if !path.is_file() {
            return Ok(Self::default());
        }
        let text = fs::read_to_string(&path)
            .wrap_err_with(|| format!("failed to read {}", path.display()))?;
        match toml::from_str::<Self>(&text) {
            Ok(parsed) => Ok(parsed),
            Err(err) => {
                tracing::warn!(
                    "foundry.toml at {} is not valid TOML: {err}",
                    path.display()
                );
                Ok(Self::default())
            }
        }
    }

    /// Resolve a profile name to a single [`FoundryProfile`]. Lookup
    /// order:
    /// 1. `[profile.<name>]` if present.
    /// 2. The legacy `[default]` block (regardless of name).
    /// 3. An empty profile.
    ///
    /// Returns an owned `Cow`-like clone so callers can read fields
    /// without borrowing constraints. Profile contents are tiny so
    /// the clone is cheap.
    fn select(&self, name: &str) -> FoundryProfile {
        if let Some(p) = self.profile.get(name) {
            return p.clone();
        }
        self.default.clone()
    }

    /// Remappings for `select(name)`, concatenated with the legacy
    /// `[default]` block's remappings when the two profiles are
    /// distinct (so users mixing both layouts don't lose either set).
    /// Order matches the previous loader: `[default]` first, then
    /// `[profile.<name>]`.
    fn remappings_for_profile(&self, name: &str) -> Vec<String> {
        let profile = self.profile.get(name);
        let mut out = Vec::new();
        out.extend(self.default.remappings.iter().cloned());
        if let Some(p) = profile {
            out.extend(p.remappings.iter().cloned());
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn foundry_toml_default_layout_remappings() {
        let text = r#"
[default]
remappings = ["@oz/=lib/oz/contracts/"]
src = "contracts"
"#;
        let parsed: FoundryToml = toml::from_str(text).unwrap();
        assert_eq!(parsed.default.remappings, vec!["@oz/=lib/oz/contracts/"]);
        assert_eq!(parsed.default.src.as_deref(), Some("contracts"));
        assert!(parsed.profile.is_empty());
        // `[default]` fallback applies whatever profile is requested.
        let selected = parsed.select("default");
        assert_eq!(selected.src.as_deref(), Some("contracts"));
        assert_eq!(
            parsed.remappings_for_profile("default"),
            vec!["@oz/=lib/oz/contracts/"]
        );
    }

    #[test]
    fn foundry_toml_profile_default_layout_remappings() {
        let text = r#"
[profile.default]
remappings = ["@oz/=lib/oz/contracts/", "ds-test/=lib/ds-test/src/"]
"#;
        let parsed: FoundryToml = toml::from_str(text).unwrap();
        assert_eq!(parsed.profile.get("default").unwrap().remappings.len(), 2);
        assert_eq!(parsed.remappings_for_profile("default").len(), 2);
        assert!(parsed.default.remappings.is_empty());
    }

    #[test]
    fn foundry_toml_unknown_keys_ignored() {
        let text = r#"
[profile.default]
remappings = ["@oz/=lib/oz/contracts/"]
src = "src"
out = "out"
optimizer = true
optimizer_runs = 200
fuzz_runs = 1024
"#;
        let parsed: FoundryToml = toml::from_str(text).unwrap();
        let p = parsed.profile.get("default").unwrap();
        assert_eq!(p.remappings.len(), 1);
        assert_eq!(p.src.as_deref(), Some("src"));
    }

    #[test]
    fn foundry_toml_missing_file_returns_default() {
        let dir = tempfile::tempdir().unwrap();
        let parsed = FoundryToml::load(dir.path()).unwrap();
        assert!(parsed.remappings_for_profile("default").is_empty());
    }

    #[test]
    fn foundry_toml_malformed_returns_default() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("foundry.toml"), "this is not toml [[[").unwrap();
        let parsed = FoundryToml::load(dir.path()).unwrap();
        assert!(parsed.remappings_for_profile("default").is_empty());
    }

    #[test]
    fn foundry_toml_named_profile() {
        // silo-finance-style: `[profile.default]` has no src; the real
        // src lives under named profiles like `core`.
        let text = r#"
[profile.default]
libs = ["lib"]
[profile.core]
src = "silo-core/contracts"
remappings = ["@silo-core/=silo-core/contracts/"]
"#;
        let parsed: FoundryToml = toml::from_str(text).unwrap();
        assert!(parsed.select("default").src.is_none());
        assert_eq!(
            parsed.select("core").src.as_deref(),
            Some("silo-core/contracts")
        );
        assert_eq!(
            parsed.remappings_for_profile("core"),
            vec!["@silo-core/=silo-core/contracts/"],
        );
        // Unknown profile name falls back to `[default]` (empty here).
        assert!(parsed.select("does-not-exist").src.is_none());
    }
}
