//! [`SolidityHarness`] — Foundry impl of
//! [`crate::harness::backend::HarnessBackend`]. Owns the configuration
//! a Solidity codegen pass needs ([`HarnessKind`], [`FuzzOptions`],
//! [`ForgeBackend`]); per-call resources (DB, LLM, spec id, etc.) flow
//! through trait method args so the same `SolidityHarness` instance
//! services every stage of an autoloop cycle without re-resolving the
//! forge runtime each call.
//!
//! Why a thin wrapper around [`SolidityHarnessGenerator`]:
//! the underlying generator already exposes the right four entry
//! methods (`run` / `fuzz_one_existing_spec` / `regen_one_spec` /
//! `regen_codegen_with_explicit_spec`); we just need a stable
//! settings-holder shape that orchestrators can carry around as a
//! `<B: HarnessBackend>` without paying construction cost per call.
//! Each trait method builds a fresh [`SolidityHarnessGenerator`] from
//! the held settings + the call's `repo` / `llm` — the generator
//! itself is cheap to construct (clones four fields).

use std::future::Future;
use std::path::{Path, PathBuf};
use std::time::Duration;

use color_eyre::eyre::{Result, eyre};
use knowdit_repo_model::RepoDatabase;
use llmy::client::client::LLM;

use crate::harness::backend::HarnessBackend;
use crate::harness::forge::{ForgeBackend, ForgeRunner};
use crate::harness::solidity::{
    CodegenRegenInMemory, FuzzOneOutcome, FuzzOptions, FuzzOutcome, HarnessKind, RegenOutcome,
    SolidityHarnessGenerator,
};
use crate::types::AuditSpecification;

/// Solidity / Foundry harness backend. Holds the once-resolved
/// [`ForgeBackend`] (so `forge coverage --help` only probes once per
/// pipeline invocation), the [`FuzzOptions`] that drive the per-spec
/// agent loop, and the [`HarnessKind`] mode selector. Cheap to clone
/// when an orchestrator needs to fan it out to workers — internal
/// fields are all `Clone`.
#[derive(Clone)]
pub struct SolidityHarness {
    kind: HarnessKind,
    options: FuzzOptions,
    forge_backend: ForgeBackend,
}

impl SolidityHarness {
    /// Bundle CLI-resolved settings into a single backend handle. No
    /// disk / network IO — the heavy `ForgeBackend::new` probe (which
    /// also resolves the host's forge binary or docker runtime) has
    /// already happened in `HarnessSharedArgs::to_forge_backend`.
    pub fn new(kind: HarnessKind, options: FuzzOptions, forge_backend: ForgeBackend) -> Self {
        Self {
            kind,
            options,
            forge_backend,
        }
    }

    /// Access the underlying forge runtime — orchestrators that
    /// preflight via a side path (or need to thread the backend
    /// elsewhere) read it through here. Cloning the
    /// [`ForgeBackend`] is cheap; it's a struct of probe results
    /// + an enum.
    pub fn forge_backend(&self) -> &ForgeBackend {
        &self.forge_backend
    }

    /// Per-call factory. The held settings get stamped onto a fresh
    /// [`SolidityHarnessGenerator`] bound to this call's `repo` /
    /// `llm` — the generator clones both inside, so the trait method
    /// can return without borrow concerns.
    fn make_generator(&self, repo: &RepoDatabase, llm: &LLM) -> SolidityHarnessGenerator {
        SolidityHarnessGenerator::new(
            self.kind,
            repo,
            llm,
            &self.options,
            self.forge_backend.clone(),
        )
    }

    /// Resolve where preflight should drop its smoke-test harness.
    /// Mirrors the dir-selection logic baked into
    /// [`FuzzOptions::resolve_harness_dir`] but operates against a
    /// caller-supplied `repo_root` rather than the one currently in
    /// `self.options` — autoloop's preflight runs before any per-project
    /// state has been threaded into FuzzOptions.
    fn preflight_harness_dir(&self, repo_root: &Path) -> PathBuf {
        let mut opts = self.options.clone();
        opts.repo_root = repo_root.to_path_buf();
        opts.resolve_harness_dir()
    }
}

impl SolidityHarness {
    /// Markdown language-context block prepended to every
    /// audit-phase agent system prompt when this is the
    /// runtime backend. Exposed as a `pub const` so callers
    /// that don't have a `SolidityHarness` instance (e.g.
    /// standalone audit-phase CLIs that don't fuzz) can still
    /// reach the wording.
    pub const PROMPT_PREFIX: &'static str = r#"## Project source language

- language: **Solidity**
- source file extension: `.sol`
- top-level container: `contract`
- documentation convention: NatSpec (`/// @notice ...`) and inline `//` comments
- assertion idiom: `require(cond, "REASON")` for input validation, `revert CustomError(args)` (or `revert("REASON")`) for explicit failure; foundry tests also use `vm.expectRevert(...)` to bracket expected reverts
- type system: static types include `uint256`, `address`, `mapping(K=>V)`, `bytes`, `struct`. State lives in per-contract storage slots. Reverts propagate via `require` / `revert` and bubble up the call stack.

Use vocabulary consistent with Solidity throughout — `contract` / `function` / `modifier` / `storage` / `revert` — never Move terms.
"#;
}

impl HarnessBackend for SolidityHarness {
    fn prompt_prefix(&self) -> &'static str {
        Self::PROMPT_PREFIX
    }

    async fn preflight(&self, repo_root: &Path) -> Result<()> {
        let harness_dir = self.preflight_harness_dir(repo_root);
        tokio::fs::create_dir_all(&harness_dir).await.map_err(|e| {
            eyre!(
                "preflight: failed to create harness_dir {}: {e}",
                harness_dir.display()
            )
        })?;
        let harness_dir = std::fs::canonicalize(&harness_dir).unwrap_or(harness_dir);
        let forge_work_dir = if repo_root.join("foundry.toml").exists() {
            repo_root.to_path_buf()
        } else {
            harness_dir.clone()
        };
        // Preflight is one trivial test; 60s is generous even on slow
        // docker pulls. Independent of the user's `forge_timeout_secs`,
        // which the per-spec agent uses for real fuzz runs.
        let runner = ForgeRunner::new(
            self.forge_backend.clone(),
            forge_work_dir,
            Duration::from_secs(60),
        );
        runner.preflight(&harness_dir).await
    }

    async fn fuzz_sweep(&self, repo: &RepoDatabase, llm: &LLM) -> Result<FuzzOutcome> {
        self.make_generator(repo, llm).run().await
    }

    async fn fuzz_one_existing_spec(
        &self,
        repo: &RepoDatabase,
        llm: &LLM,
        spec_id: i32,
    ) -> Result<Option<FuzzOneOutcome>> {
        self.make_generator(repo, llm)
            .fuzz_one_existing_spec(spec_id)
            .await
    }

    async fn regen_codegen_for_spec(
        &self,
        repo: &RepoDatabase,
        llm: &LLM,
        spec_id: i32,
        prior_feedback: String,
    ) -> Result<RegenOutcome> {
        self.make_generator(repo, llm)
            .regen_one_spec(spec_id, prior_feedback)
            .await
    }

    async fn codegen_for_in_memory_spec(
        &self,
        repo: &RepoDatabase,
        llm: &LLM,
        extract_id: i32,
        finding_id: i32,
        spec: AuditSpecification,
        synthetic_spec_id: i32,
        prior_feedback: String,
    ) -> Result<CodegenRegenInMemory> {
        self.make_generator(repo, llm)
            .regen_codegen_with_explicit_spec(
                extract_id,
                finding_id,
                spec,
                synthetic_spec_id,
                prior_feedback,
            )
            .await
    }
}

// `impl Future + Send` on the trait methods is satisfied by the inner
// `SolidityHarnessGenerator` futures which are all Send (everything
// they hold — RepoDatabase, LLM, ForgeBackend, FuzzOptions, etc. — is
// Send). No PhantomData / explicit assertion needed; if a future field
// regresses to !Send, the trait impl will fail to compile here.
#[doc(hidden)]
#[allow(dead_code)]
fn _assert_solidity_harness_is_send_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<SolidityHarness>();
}

// Silence unused-import warnings if the future-bound check below ever
// gets simplified away — the trait import has to stay because the
// `impl HarnessBackend for SolidityHarness` block uses it.
const _: fn() = || {
    fn _check<F: Future<Output = Result<()>> + Send>(_: F) {}
};
