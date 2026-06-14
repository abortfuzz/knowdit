//! `SpecBackend` — the per-language seam for specification generation.
//!
//! Mirrors [`crate::harness::HarnessBackend`] (which owns harness synthesis /
//! execution) on the spec-generation side: each source language provides its
//! own project index, spec model, and agent, but the streamloop dispatches
//! through this one trait so the link-planning / resume / scheduling layer
//! stays language-agnostic.
//!
//! The Solidity pipeline keeps its existing
//! [`crate::spec::SpecificationGenerator`] entry points (`run` /
//! `prepare_stream`); the Move pipeline implements this trait in
//! `knowdit-move`. The shared per-link work unit is
//! [`knowdit_repo_model::LinkInput`]; both languages persist their specs as
//! JSON into the same `specification` table via
//! [`knowdit_repo_model::RepoDatabase::append_specifications`], so the returned
//! [`LinkSpecOutcome`] only needs `status` + `specification_ids` to drive the
//! downstream fuzz / reflect cycle.

use std::future::Future;

use color_eyre::eyre::Result;
use knowdit_repo_model::{LinkInput, RepoDatabase};
use llmy::client::client::LLM;

use super::{LinkSpecOutcome, SpecGenOptions};

pub trait SpecBackend: Send + Sync {
    /// Build and cache this backend's per-project static index (once, before
    /// the per-link loop). For Solidity this is the call/storage/inheritance
    /// `ProjectIndex`; for Move it is the module / struct-field / function
    /// index. Idempotent — calling twice reuses the cached index.
    fn prepare_spec_index(&self, repo: &RepoDatabase) -> impl Future<Output = Result<()>> + Send;

    /// Run the spec-generation agent for one link and persist any committed
    /// specifications to the `specification` table, returning the outcome with
    /// `specification_ids` populated. Implementations must short-circuit when
    /// `link.pre_committed_spec_ids` is non-empty (DB resume): skip the agent
    /// and synthesize a `Built` outcome from those ids so the caller's
    /// fuzz / reflect cycle resumes where the prior run stopped.
    fn generate_specs_for_link(
        &self,
        repo: &RepoDatabase,
        llm: &LLM,
        link: &LinkInput,
        options: &SpecGenOptions,
    ) -> impl Future<Output = Result<LinkSpecOutcome>> + Send;
}
