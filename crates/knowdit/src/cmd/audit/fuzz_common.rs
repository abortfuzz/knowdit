//! Foundry / fuzz-agent runtime knobs shared by `agentic fuzz`,
//! `agentic regen`, and `workflow autoloop` (which drives both).
//! The same `SolidityFuzzGenerator` underpins all three, so the
//! forge-backend config (binary / docker image / memory cap), the
//! per-spec LLM-agent budget, and the Gate 2 inline-fidelity
//! threshold are a single struct flattened wherever needed.
//!
//! Long-flag names carry a phase-disambiguating prefix
//! (`--harness-*` / `--forge-*` / `--gate2-*`) so flattening
//! [`HarnessSharedArgs`] into the autoloop alongside other phase
//! `SharedArgs` doesn't trip clap's duplicate-arg check. The CLI
//! standalone commands inherit the same names — there is no
//! pre-rename compatibility layer.

use std::path::{Path, PathBuf};
use std::time::Duration;

use clap::Args;
use color_eyre::eyre::Result;
use knowdit_audit::harness::forge::{ForgeBackend, ForgeRunner};
use knowdit_audit::harness::solidity::FuzzOptions;

/// Forge backend + harness-codegen-agent knobs. Flattened by
/// `agentic fuzz`, `agentic regen`, and `workflow autoloop`. All
/// fields use phase-disambiguated long names so multiple consumers
/// can co-exist in one `clap::Args` parse tree.
#[derive(Args, Clone, Debug)]
pub struct HarnessSharedArgs {
    /// `llmy` cache key prefix. When unset, each subcommand falls
    /// back to a per-subcommand default
    /// (`{project}-knowdit-fuzz` / `{project}-knowdit-regen`).
    #[arg(long = "harness-cache-key")]
    pub harness_cache_key: Option<String>,

    /// Debug-prefix forwarded to llmy for LLM-call dumps.
    #[arg(long = "harness-debug-prefix")]
    pub harness_debug_prefix: Option<String>,

    /// Path to a local `forge` binary. When set, knowdit runs forge
    /// directly on the host (optionally wrapped in a cgroup v2 memory
    /// cap — see `--forge-mem-cap-gb`). When unset (default), knowdit
    /// uses `docker run --rm <docker-image> forge ...` so a
    /// memory-runaway forge can't OOM the host.
    #[arg(long = "forge-bin")]
    pub forge_bin: Option<PathBuf>,

    /// Docker image used when `--forge-bin` is not provided. The image
    /// must have `forge` installed at `/usr/local/bin/forge` and must
    /// run as a uid that matches the host (the default
    /// `lazymio/knowdit:foundry` runs uid 1000).
    #[arg(long = "forge-docker-image", default_value = "lazymio/knowdit:foundry")]
    pub docker_image: String,

    /// Per-invocation memory ceiling, in GiB. In docker mode this is
    /// plumbed through `--memory` / `--memory-swap`. In local mode
    /// this is enforced via cgroup v2 (when a writable delegated
    /// parent is available); if no usable cgroup is found we log a
    /// warning and fall back to direct exec. Set to 0 to disable the
    /// cap entirely.
    #[arg(long = "forge-mem-cap-gb", default_value_t = 12)]
    pub forge_mem_cap_gb: u64,

    /// Where to write `.sol` harness files. If omitted: auto-detect —
    /// if the repo has `foundry.toml` + `test/`, write to
    /// `<repo>/test/knowdit_harness/`, otherwise `<repo>/knowdit_harness/`.
    #[arg(long = "harness-dir")]
    pub harness_dir: Option<PathBuf>,

    /// Hard timeout per forge subprocess (seconds).
    #[arg(long = "forge-timeout-secs", default_value_t = 600)]
    pub forge_timeout_secs: u64,

    /// `--fuzz-runs` for the `forge test` invocation.
    #[arg(long = "forge-test-runs", default_value_t = 100_000)]
    pub forge_test_runs: u64,

    /// `--fuzz-runs` for the `forge coverage` invocation. Coverage is
    /// much slower per sample, so this is usually a smaller value.
    #[arg(long = "forge-coverage-runs", default_value_t = 5_000)]
    pub forge_coverage_runs: u64,

    /// Maximum agent steps per spec across all restarts. Cumulative
    /// budget — restarts reuse the same step counter so a model that
    /// thrashes can't reset its budget by re-opening.
    #[arg(long = "harness-max-agent-steps", default_value_t = 120)]
    pub harness_max_agent_steps: usize,

    /// Approximate token count at which the orchestrator restarts the
    /// agent. Defaults to None (no restart; rely on step budget). Set
    /// this to ~80% of the model's input window to avoid hitting
    /// hard context limits during long iterations.
    #[arg(long = "harness-window-restart-threshold-tokens")]
    pub harness_window_restart_threshold_tokens: Option<usize>,

    /// Maximum number of agent restarts per spec before the spec is
    /// abandoned. Each restart drops conversation history but keeps
    /// the harness file on disk plus a short "previous attempt" note
    /// in the new system prompt so the new agent doesn't restart from
    /// scratch.
    #[arg(long = "harness-max-restarts", default_value_t = 3)]
    pub harness_max_restarts: usize,

    /// Gate 2 fidelity threshold for the inline coverage gate. The
    /// agent gets `[GATE 2 FAILED — coverage]` in its `run_forge`
    /// tool result when `hit_fns / expected_fns < this`. Same default
    /// as `agentic reflect`.
    #[arg(long = "gate2-fidelity-threshold", default_value_t = 0.5)]
    pub gate2_fidelity_threshold: f64,

    /// Tell the harness pipeline that the project's solc build uses
    /// viaIR. Plumbed into the per-spec prompt (so the agent knows
    /// coverage might fail) and into `forge coverage --force-via-ir`
    /// when the resolved forge backend supports the flag. The
    /// autoloop orchestrator overrides this from its top-level
    /// `--via-ir` so the user doesn't have to pass it twice.
    #[arg(long = "harness-via-ir", default_value_t = false)]
    pub harness_via_ir: bool,
}

/// Per-subcommand fields [`HarnessSharedArgs`] doesn't know about
/// (project root, fuzz-only caps, default cache key, project viaIR
/// state). The caller fills this in;
/// [`HarnessSharedArgs::to_fuzz_options`] consumes it.
#[derive(Debug, Clone)]
pub struct FuzzOptionsBuild {
    pub repo_root: PathBuf,
    /// Used when `HarnessSharedArgs::cache_key` is `None`. Subcommands
    /// pass `{project}-knowdit-fuzz` or `{project}-knowdit-regen`.
    pub default_cache_key: String,
    pub max_specs: usize,
    pub concurrency: usize,
    pub regenerate: bool,
    /// Whether the project's solc settings use viaIR. Plumbs into
    /// `forge coverage --force-via-ir` when the backend supports it
    /// and into the per-spec prompt note when it doesn't. Standalone
    /// `agentic fuzz` / `agentic regen` get this from the project
    /// foundry profile via `--harness-via-ir`; the autoloop
    /// orchestrator overrides it from `--via-ir` on the foundry
    /// flatten group.
    pub via_ir: bool,
}

impl HarnessSharedArgs {
    /// Resolve a [`ForgeBackend`] (preflight + feature probe) from
    /// these args. Callers do this exactly once per pipeline
    /// invocation and thread the result through every phase that
    /// needs a forge runtime — the per-spec [`ForgeRunner`]
    /// constructor takes `ForgeBackend` by value, so the
    /// `forge coverage --help` probe runs only once even when fuzz
    /// + regen both run inside the same autoloop cycle.
    pub fn to_forge_backend(&self) -> Result<ForgeBackend> {
        let mem_cap_bytes =
            (self.forge_mem_cap_gb > 0).then(|| self.forge_mem_cap_gb * 1024 * 1024 * 1024);
        ForgeBackend::new(
            self.forge_bin.clone(),
            self.docker_image.clone(),
            mem_cap_bytes,
        )
    }

    /// Smoke-test the forge environment before any LLM-driven phase
    /// touches the project. Build a one-off [`ForgeRunner`] off
    /// `backend` (so the `forge coverage --help` probe doesn't
    /// re-fire) with a short 60s timeout, point it at the same
    /// harness dir the fuzz phase would use, and run
    /// [`ForgeRunner::preflight`] — a trivial compile + execute of
    /// `import "forge-std/Test.sol"`. Returns `Err` with forge's
    /// verbatim stdout/stderr on failure so the user sees the actual
    /// compile error rather than burning extract/map/spec-gen tokens
    /// on a project that was always going to fail.
    ///
    /// Cheap: one short forge subprocess. Designed to be called once
    /// per pipeline invocation at the top of streamloop / autoloop /
    /// standalone fuzz / standalone regen, before any DB-heavy or
    /// LLM-heavy stage runs.
    pub async fn preflight(&self, backend: &ForgeBackend, repo_root: &Path) -> Result<()> {
        // Reuse `to_fuzz_options` purely for its harness_dir resolution
        // logic (foundry.toml → test/knowdit_harness; else
        // knowdit_harness). Other field values are placeholders since
        // `resolve_harness_dir` only reads `harness_dir` + `repo_root`.
        let opts = self.to_fuzz_options(FuzzOptionsBuild {
            repo_root: repo_root.to_path_buf(),
            default_cache_key: String::new(),
            max_specs: 0,
            concurrency: 1,
            regenerate: false,
            via_ir: false,
        });
        let harness_dir = opts.resolve_harness_dir();
        tokio::fs::create_dir_all(&harness_dir)
            .await
            .map_err(|e| color_eyre::eyre::eyre!(
                "preflight: failed to create harness_dir {}: {e}",
                harness_dir.display()
            ))?;
        let harness_dir = std::fs::canonicalize(&harness_dir).unwrap_or(harness_dir);
        let forge_work_dir = if repo_root.join("foundry.toml").exists() {
            repo_root.to_path_buf()
        } else {
            harness_dir.clone()
        };
        // Preflight harness is one trivial test; 60s is generous even
        // for slow docker pulls. Independent of `forge_timeout_secs`
        // (which the agent uses for real fuzz runs).
        let runner = ForgeRunner::new(
            backend.clone(),
            forge_work_dir,
            Duration::from_secs(60),
        );
        runner.preflight(&harness_dir).await
    }

    /// Compose [`FuzzOptions`] from `self` plus the per-subcommand
    /// pieces in `build`. Single source of truth for forge-runtime
    /// config — no caller spells `FuzzOptions { ... }` directly.
    pub fn to_fuzz_options(&self, build: FuzzOptionsBuild) -> FuzzOptions {
        let cache_key = self
            .harness_cache_key
            .clone()
            .unwrap_or(build.default_cache_key);
        let forge_mem_cap_bytes =
            (self.forge_mem_cap_gb > 0).then(|| self.forge_mem_cap_gb * 1024 * 1024 * 1024);
        FuzzOptions {
            repo_root: build.repo_root,
            harness_dir: self.harness_dir.clone(),
            forge_bin: self.forge_bin.clone(),
            docker_image: self.docker_image.clone(),
            forge_mem_cap_bytes,
            forge_timeout_secs: self.forge_timeout_secs,
            forge_test_runs: self.forge_test_runs,
            forge_coverage_runs: self.forge_coverage_runs,
            max_agent_steps: self.harness_max_agent_steps,
            max_specs: build.max_specs,
            concurrency: build.concurrency.max(1),
            regenerate: build.regenerate,
            cache_key,
            debug_prefix: self.harness_debug_prefix.clone(),
            llm_settings: None,
            window_restart_threshold_tokens: self.harness_window_restart_threshold_tokens,
            max_restarts: self.harness_max_restarts,
            gate2_fidelity_threshold: self.gate2_fidelity_threshold,
            via_ir: build.via_ir,
        }
    }
}
