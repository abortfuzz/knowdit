//! Specification Generator agent.
//!
//! Step 2 of the agentic auditing workflow described in
//! `paper/samples/sections/3-methodology.tex`. Given the Knowledge Mapper
//! output (extract semantic ↔ historical semantic ↔ historical finding
//! "links") stored in a project's [`RepoDatabase`], this agent decides for
//! each link whether the historical vulnerability pattern can be reproduced
//! on the current project, and if so emits one or more
//! [`AuditSpecification`]s describing the setup / pre-attack / post-attack
//! state invariants and the core call sequence to exercise.
//!
//! The agent is memory-equipped (long-term: the link details, persisted in
//! the system prompt; short-term: one entry per project contract preloaded
//! from the static-analysis tables). It builds each spec incrementally
//! through tool calls so failures are easier to attribute.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::Arc;

use color_eyre::eyre::{Result, WrapErr};
use itertools::Itertools;
use knowdit_kg_model::ExtractedSemantic;
use knowdit_repo_model::cg::{CallGraph, Contract, Function, FunctionCall, Interface};
use knowdit_repo_model::inheritance::{ContractInherit, InheritanceGraph};
use knowdit_repo_model::storage::{ContractVariable, StateVariable, StorageGraph};
use knowdit_repo_model::{
    HistoricalSemanticRecord, RepoDatabase, SemanticMatchSet, repo::SpecificationRecord,
};
use llmy::agent::StepResult;
use llmy::agent::tools::memory::{AgentMemory, AgentMemoryContent, AgentMemoryContext};
use llmy::client::client::LLM;
use llmy::client::settings::LLMSettings;
use llmy::harness::memory::AgentMemorySystemPromptCriteria;
use llmy::harness::{Agent, AgentConfig};
use serde::Serialize;
use tokio::sync::Mutex;

use crate::types::AuditSpecification;

mod backend;
mod prompt;
mod tools;
pub use backend::SpecBackend;
use prompt::{build_regen_prompt_extension, build_system_prompt, build_user_prompt};
pub(crate) use tools::{
    LookupCallGraphTool, LookupStateVariableXrefsTool, ReadContractSourceTool,
    ReadFunctionSourceTool,
};

// `LinkInput` / `LinkKey` are the language-agnostic per-link work units; they
// live in `knowdit-repo-model` so both the Solidity (here) and Move
// (`knowdit-move`) spec pipelines share them. Re-exported so existing
// `crate::spec::LinkInput` paths keep resolving.
pub use knowdit_repo_model::{LinkInput, LinkKey};

// ---------------------------------------------------------------------------
// Public configuration / output types
// ---------------------------------------------------------------------------

/// Tunables for one Specification Generator pass.
#[derive(Debug, Clone)]
pub struct SpecGenOptions {
    /// Maximum number of agent steps allowed for a single link before the
    /// link is force-abandoned.
    pub max_agent_steps: usize,
    /// Soft cap on how many `AuditSpecification`s the agent may commit for
    /// one link. The agent is free to commit fewer.
    pub max_specs_per_link: usize,
    /// Compact the conversation when the rendered context exceeds this many
    /// approximate tokens. `None` defaults to 80% of the model's max input.
    pub compact_context_threshold_tokens: Option<usize>,
    /// `llmy` cache key prefix (per-project, set by the CLI).
    pub cache_key: String,
    /// Optional debug prefix passed to llmy.
    pub debug_prefix: Option<String>,
    /// Optional per-call llmy settings.
    pub llm_settings: Option<LLMSettings>,
    /// Optional cap on the total number of links processed (after de-dup).
    /// `None` means process every link.
    pub max_links: Option<usize>,
    /// At most this many findings per *(extract, historical)* pair. When
    /// multiple extracts match the same historical, each (extract, historical)
    /// pair gets its own quota — so a finding still useful for one extract
    /// is not crowded out by an unrelated extract that happens to also match
    /// the same historical. `None` means no cap.
    pub max_findings_per_historical: Option<usize>,
    /// Cap on the total number of links processed *per extract*. Combined
    /// with [`Self::max_findings_per_historical`] this lets a project's
    /// budget be spread fairly across all matched extracts rather than the
    /// first one monopolising the cost. `None` means no per-extract cap.
    pub max_links_per_extract: Option<usize>,
    /// Number of `run_link` agent runs allowed in flight at once. `1` runs
    /// strictly serially (default); higher values dispatch links to a worker
    /// pool. The shared billing cap, prompt cache, and DB write are all
    /// already concurrency-safe.
    pub concurrency: usize,
    /// When `true`, clear the `specification` table at the start of the run
    /// and process every link from scratch. When `false` (default), skip any
    /// link whose `(semantic_id, finding_id)` already has rows in the spec
    /// table — so a re-run picks up exactly where the previous one stopped.
    pub regenerate: bool,
    /// Minimum mapper-emitted match strength to consider for spec
    /// generation. Links with `strength < min_strength` are dropped
    /// up-front (before any cap). Default `Medium` skips `Low` matches
    /// (treated as noise).
    pub min_strength: knowdit_repo_model::MatchStrength,
    /// Minimum semantic↔finding link strength (from the global linker)
    /// to consider. A LinkInput fans out per `(extract, historical,
    /// finding)`; this drops any finding whose `(historical, finding)`
    /// link is weaker than `min_link_strength`. Default `Medium`
    /// matches the noise floor used for `min_strength`.
    pub min_link_strength: knowdit_kg_model::link_strength::LinkStrength,
    /// Pre-rendered Markdown block describing the project's
    /// source language; verbatim-prepended to each per-link
    /// system prompt. See [`crate::profile::ProfileOptions::language_prompt_prefix`]
    /// for the same dispatch convention.
    pub language_prompt_prefix: String,
}

impl Default for SpecGenOptions {
    fn default() -> Self {
        Self {
            max_agent_steps: 60,
            max_specs_per_link: 4,
            compact_context_threshold_tokens: None,
            cache_key: "knowdit-spec".to_string(),
            debug_prefix: None,
            llm_settings: None,
            max_links: None,
            max_findings_per_historical: None,
            max_links_per_extract: None,
            concurrency: 1,
            regenerate: false,
            min_strength: knowdit_repo_model::MatchStrength::Medium,
            min_link_strength: knowdit_kg_model::link_strength::LinkStrength::Medium,
            language_prompt_prefix: String::new(),
        }
    }
}

/// Outcome of one link's spec-generation run.
#[derive(Debug, Clone)]
pub struct LinkSpecOutcome {
    /// 1-based ordinal in the planned link stream — useful for progress
    /// reporting and for schedulers that need a stable cross-batch label.
    pub ordinal: usize,
    /// `project_semantic.id` from the project DB.
    pub extract_id: i32,
    /// Historical semantic id, mirrored into the project DB.
    pub historical_id: i32,
    /// Historical finding id, mirrored into the project DB.
    pub finding_id: i32,
    /// Whether the agent committed at least one spec.
    pub status: LinkSpecStatus,
    /// Specs the agent committed before finalizing.
    pub specifications: Vec<AuditSpecification>,
    /// DB ids of `specifications` after the commit transaction succeeds.
    /// Populated by `commit_link_outcome`; empty on commit failure or when
    /// `specifications` was empty.
    pub specification_ids: Vec<i32>,
    /// Reason the agent reported for abandoning, when `status == Abandoned`.
    pub abort_reason: Option<String>,
    /// Free-form summary from the agent's final tool call.
    pub final_summary: Option<String>,
    /// Number of agent steps consumed (counts initial step too).
    pub steps: usize,
    /// Number of context-compaction passes triggered.
    pub compact_count: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LinkSpecStatus {
    /// The agent committed at least one specification and signaled success.
    Built,
    /// The agent decided the historical pattern doesn't apply to this
    /// project, or hit step/runtime limits before finalizing.
    Abandoned,
}

/// Aggregate run outcome.
#[derive(Debug, Clone, Default)]
pub struct SpecGenOutcome {
    pub link_count: usize,
    pub built_link_count: usize,
    pub abandoned_link_count: usize,
    pub total_specs: usize,
    pub by_link: Vec<LinkSpecOutcome>,
}

/// A serial, resume-safe spec-generation queue prepared from the project's
/// current mapper output. Callers can pull one link at a time and interleave
/// downstream phases (codegen / reflect / regen) between links.
pub struct SpecGenStream {
    project_index: Arc<ProjectIndex>,
    queue: VecDeque<LinkInput>,
    total_links: usize,
    processed_links: usize,
    options: SpecGenOptions,
    matched_extract_count: usize,
    historical_finding_total: usize,
}

impl SpecGenStream {
    pub fn total_links(&self) -> usize {
        self.total_links
    }

    pub fn processed_links(&self) -> usize {
        self.processed_links
    }

    pub fn remaining_links(&self) -> usize {
        self.queue.len()
    }

    pub fn matched_extract_count(&self) -> usize {
        self.matched_extract_count
    }

    pub fn historical_finding_total(&self) -> usize {
        self.historical_finding_total
    }

    pub fn next_link_key(&self) -> Option<LinkKey> {
        self.queue.front().map(LinkInput::key)
    }

    pub fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }

    /// Claim one link from the stream **without** running it. Lets an
    /// external scheduler keep a bounded number of full link pipelines
    /// active at once: claim → gen-spec → fuzz → reflect → regen →
    /// snapshot. The returned [`PlannedLinkWork`] carries everything
    /// `process_link` needs, so the scheduler can run it on its own
    /// task. Note: `processed_links` is bumped on claim, so the
    /// scheduler must guarantee the claimed work is either run or
    /// dropped — there is no `unpop`.
    pub fn pop_next_work(&mut self) -> Option<PlannedLinkWork> {
        let link = self.queue.pop_front()?;
        let ordinal = self.processed_links + 1;
        self.processed_links += 1;
        Some(PlannedLinkWork {
            ordinal,
            total_links: self.total_links,
            link,
            project_index: self.project_index.clone(),
            options: self.options.clone(),
        })
    }

    /// Process exactly one pending link, appending any committed specs to the
    /// project DB before returning. Returns `Ok(None)` when the queue is empty.
    pub async fn run_next(
        &mut self,
        repo: &RepoDatabase,
        llm: &LLM,
    ) -> Result<Option<LinkSpecOutcome>> {
        let Some(link) = self.queue.pop_front() else {
            return Ok(None);
        };
        let ordinal = self.processed_links + 1;
        let mut outcome = process_link(
            &link,
            &self.project_index,
            llm,
            &self.options,
            ordinal,
            self.total_links,
        )
        .await;
        outcome.specification_ids = commit_link_outcome(repo, &outcome).await;
        self.processed_links += 1;
        Ok(Some(outcome))
    }

    /// Process up to `batch_size` pending links concurrently and return each
    /// outcome in completion order. DB commits happen on the calling task as
    /// each worker finishes, so writes stay serialized just like the
    /// monolithic `SpecificationGenerator::run` path. Returns an empty Vec
    /// when the queue is exhausted. `batch_size` is clamped to at least 1.
    pub async fn run_next_batch(
        &mut self,
        repo: &RepoDatabase,
        llm: &LLM,
        batch_size: usize,
    ) -> Result<Vec<LinkSpecOutcome>> {
        self.run_next_batch_with_hook(repo, llm, batch_size, |_| Ok(()))
            .await
    }

    /// Like [`Self::run_next_batch`], but invokes `on_committed` immediately
    /// after each worker outcome has been serialized into the DB. The
    /// callback runs on the calling task, so it can write local progress
    /// snapshots in actual completion order without waiting for slower
    /// links in the same batch. If the hook returns `Err`, the remaining
    /// in-flight tasks still finish but the error is propagated up.
    pub async fn run_next_batch_with_hook<F>(
        &mut self,
        repo: &RepoDatabase,
        llm: &LLM,
        batch_size: usize,
        mut on_committed: F,
    ) -> Result<Vec<LinkSpecOutcome>>
    where
        F: FnMut(&LinkSpecOutcome) -> Result<()>,
    {
        if self.queue.is_empty() {
            return Ok(Vec::new());
        }
        let batch_size = batch_size.max(1).min(self.queue.len());

        let mut batch: Vec<(usize, LinkInput)> = Vec::with_capacity(batch_size);
        let base_ordinal = self.processed_links + 1;
        for i in 0..batch_size {
            let Some(link) = self.queue.pop_front() else {
                break;
            };
            batch.push((base_ordinal + i, link));
        }

        if batch.len() == 1 {
            let (ordinal, link) = batch.into_iter().next().unwrap();
            let mut outcome = process_link(
                &link,
                &self.project_index,
                llm,
                &self.options,
                ordinal,
                self.total_links,
            )
            .await;
            outcome.specification_ids = commit_link_outcome(repo, &outcome).await;
            self.processed_links += 1;
            on_committed(&outcome)?;
            return Ok(vec![outcome]);
        }

        let (tx, mut rx) = tokio::sync::mpsc::channel::<LinkSpecOutcome>(batch.len());
        let mut handles = Vec::with_capacity(batch.len());
        for (ordinal, link) in batch {
            let project_index = self.project_index.clone();
            let llm = llm.clone();
            let options = self.options.clone();
            let total = self.total_links;
            let tx = tx.clone();
            handles.push(tokio::spawn(async move {
                let outcome =
                    process_link(&link, &project_index, &llm, &options, ordinal, total).await;
                let _ = tx.send(outcome).await;
            }));
        }
        drop(tx);

        let mut results = Vec::with_capacity(handles.len());
        while let Some(mut outcome) = rx.recv().await {
            outcome.specification_ids = commit_link_outcome(repo, &outcome).await;
            self.processed_links += 1;
            on_committed(&outcome)?;
            results.push(outcome);
        }
        for h in handles {
            let _ = h.await;
        }
        Ok(results)
    }
}

/// One claimed link ready to be run by an external scheduler. Carries
/// everything `process_link` needs (the link itself plus a cheap
/// `Arc<ProjectIndex>` clone), so the scheduler can spawn `.run(repo, llm)`
/// on its own task and interleave the link's fuzz/reflect/regen lifecycle
/// without holding the [`SpecGenStream`] borrow.
#[derive(Clone)]
pub struct PlannedLinkWork {
    ordinal: usize,
    total_links: usize,
    link: LinkInput,
    project_index: Arc<ProjectIndex>,
    options: SpecGenOptions,
}

impl PlannedLinkWork {
    pub fn ordinal(&self) -> usize {
        self.ordinal
    }

    pub fn total_links(&self) -> usize {
        self.total_links
    }

    pub fn link_key(&self) -> LinkKey {
        self.link.key()
    }

    /// Run the claimed link end-to-end and commit any built specs to the
    /// project DB. Returns the populated `LinkSpecOutcome` with
    /// `specification_ids` filled in on success.
    ///
    /// When the link arrives with `pre_committed_spec_ids` populated
    /// (DB resume: this `(extract, finding)` already has spec rows but
    /// no code_gen yet), the gen-spec agent is skipped entirely and
    /// the outcome is synthesized as `Built` with those ids — the
    /// caller's inner fuzz / reflect / regen cycle then picks up where
    /// the prior run left off.
    pub async fn run(self, repo: &RepoDatabase, llm: &LLM) -> LinkSpecOutcome {
        if !self.link.pre_committed_spec_ids.is_empty() {
            tracing::info!(
                "Spec generator skipping gen-spec for resumed link={} (total = {}) {} — {} pre-committed spec(s)",
                self.ordinal,
                self.total_links,
                self.link,
                self.link.pre_committed_spec_ids.len(),
            );
            return LinkSpecOutcome {
                ordinal: self.ordinal,
                extract_id: self.link.extract_id,
                historical_id: self.link.historical_id,
                finding_id: self.link.finding_id,
                status: LinkSpecStatus::Built,
                specifications: Vec::new(),
                specification_ids: self.link.pre_committed_spec_ids.clone(),
                abort_reason: None,
                final_summary: Some(
                    "resumed from existing spec rows; gen-spec agent skipped".to_string(),
                ),
                steps: 0,
                compact_count: 0,
            };
        }
        let mut outcome = process_link(
            &self.link,
            &self.project_index,
            llm,
            &self.options,
            self.ordinal,
            self.total_links,
        )
        .await;
        outcome.specification_ids = commit_link_outcome(repo, &outcome).await;
        outcome
    }
}

// ---------------------------------------------------------------------------
// Top-level driver
// ---------------------------------------------------------------------------

/// Specification Generator agent.
#[derive(Debug, Clone, Default)]
pub struct SpecificationGenerator;

impl SpecificationGenerator {
    pub fn new() -> Self {
        Self
    }

    /// Run one spec-generation pass over every (extract, historical,
    /// finding) link present in `repo`. Specs are persisted to the
    /// `specification` table via [`RepoDatabase::write_specifications`].
    pub async fn run(
        &self,
        repo: &RepoDatabase,
        llm: &LLM,
        options: &SpecGenOptions,
    ) -> Result<SpecGenOutcome> {
        let PlannedLinks {
            project_index,
            links,
            matched_extract_count,
            historical_finding_total,
        } = match Self::plan_links(repo, options).await? {
            Some(plan) => plan,
            None => return Ok(SpecGenOutcome::default()),
        };
        let total_links = links.len();
        tracing::info!(
            "Specification Generator: {} link(s) to process across {} matched extract(s) and {} historical finding(s)",
            total_links,
            matched_extract_count,
            historical_finding_total,
        );

        let concurrency = options.concurrency.max(1);
        let outcomes: Vec<LinkSpecOutcome> = if concurrency == 1 {
            let mut outcomes: Vec<LinkSpecOutcome> = Vec::with_capacity(total_links);
            for (idx, link) in links.iter().enumerate() {
                let mut outcome =
                    process_link(link, &project_index, llm, options, idx + 1, total_links).await;
                outcome.specification_ids = commit_link_outcome(repo, &outcome).await;
                outcomes.push(outcome);
            }
            outcomes
        } else {
            tracing::info!("Specification Generator running with concurrency={concurrency}",);
            // Owned indexed inputs so workers can move them.
            let indexed: Vec<(usize, LinkInput)> = links.into_iter().enumerate().collect();
            let queue = Arc::new(Mutex::new(indexed.into_iter().rev().collect::<Vec<_>>()));
            let (tx, mut rx) =
                tokio::sync::mpsc::channel::<(usize, LinkSpecOutcome)>(concurrency * 2);

            let mut handles = Vec::with_capacity(concurrency);
            for _ in 0..concurrency {
                let queue = queue.clone();
                let project_index = project_index.clone();
                let llm = llm.clone();
                let options = options.clone();
                let tx = tx.clone();
                handles.push(tokio::spawn(async move {
                    loop {
                        let next = {
                            let mut q = queue.lock().await;
                            q.pop()
                        };
                        let Some((idx, link)) = next else {
                            break;
                        };
                        let outcome = process_link(
                            &link,
                            &project_index,
                            &llm,
                            &options,
                            idx + 1,
                            total_links,
                        )
                        .await;
                        if tx.send((idx, outcome)).await.is_err() {
                            break;
                        }
                    }
                }));
            }
            drop(tx);

            let mut collected: Vec<Option<LinkSpecOutcome>> =
                (0..total_links).map(|_| None).collect();
            while let Some((idx, mut outcome)) = rx.recv().await {
                // Commit on the main task so all writes go through one DB
                // handle in serialized order; SQLite handles small txns well.
                outcome.specification_ids = commit_link_outcome(repo, &outcome).await;
                if idx < collected.len() {
                    collected[idx] = Some(outcome);
                }
            }
            for h in handles {
                let _ = h.await;
            }
            collected
                .into_iter()
                .map(|o| o.expect("every link should produce an outcome"))
                .collect()
        };

        let outcome = aggregate(outcomes);
        // Persistence already happened incrementally in `commit_link_outcome`.
        // The legacy end-of-run `write_specifications` is intentionally
        // skipped — it would `delete_many()` the rows we just wrote.
        tracing::info!(
            "Specification Generator wrote {} spec(s) covering {} link(s); {} link(s) abandoned",
            outcome.total_specs,
            outcome.built_link_count,
            outcome.abandoned_link_count,
        );
        Ok(outcome)
    }

    /// Prepare a serial, round-robin link stream. Each `run_next()` call
    /// consumes one `(extract, historical, finding)` link and appends any
    /// committed specs to the DB immediately, which lets higher-level
    /// orchestrators interleave codegen / reflect / regen between links.
    pub async fn prepare_stream(
        &self,
        repo: &RepoDatabase,
        options: &SpecGenOptions,
    ) -> Result<Option<SpecGenStream>> {
        let PlannedLinks {
            project_index,
            links,
            matched_extract_count,
            historical_finding_total,
        } = match Self::plan_links(repo, options).await? {
            Some(plan) => plan,
            None => return Ok(None),
        };
        Ok(Some(SpecGenStream {
            project_index,
            total_links: links.len(),
            queue: VecDeque::from(links),
            processed_links: 0,
            options: options.clone(),
            matched_extract_count,
            historical_finding_total,
        }))
    }

    /// Plan the resume-filtered, capped, interleaved link queue **without**
    /// building a Solidity [`ProjectIndex`] — for non-Solidity spec backends
    /// that ground against their own project index (e.g. the Move backend in
    /// `knowdit-move`). Reuses the exact resume / cap / interleave logic of
    /// [`Self::prepare_stream`]; only the (unused-for-Move) Solidity index is
    /// dropped.
    pub async fn plan_link_inputs(
        &self,
        repo: &RepoDatabase,
        options: &SpecGenOptions,
    ) -> Result<Option<PlannedLinkInputs>> {
        Ok(Self::plan_links(repo, options).await?.map(|p| PlannedLinkInputs {
            links: p.links,
            matched_extract_count: p.matched_extract_count,
            historical_finding_total: p.historical_finding_total,
        }))
    }

    /// Build the read-only state shared by [`Self::run`] (full sweep) and
    /// [`Self::regen_one_link`] (single-link regen via `agentic regen`).
    /// Returns `None` only when the project DB is empty enough that no
    /// spec generation is possible — caller should treat as a no-op.
    async fn prepare_runtime(repo: &RepoDatabase) -> Result<Option<SpecRuntime>> {
        let extracted = repo
            .load_project_semantics()
            .await
            .wrap_err("failed to load extracted project semantics")?;
        if extracted.is_empty() {
            tracing::warn!("Specification Generator invoked with no extracted semantics");
            return Ok(None);
        }
        let match_set: SemanticMatchSet = repo
            .load_semantic_match_results()
            .await
            .wrap_err("failed to load Knowledge Mapper output")?;
        if match_set.matches.is_empty() {
            tracing::warn!(
                "Specification Generator invoked but the project has no semantic_matched rows; run map-semantics first"
            );
            return Ok(None);
        }
        let call_graph = repo
            .load_call_graph()
            .await
            .wrap_err("failed to load project call graph")?;
        let storage_graph = repo
            .load_storage_graph()
            .await
            .wrap_err("failed to load project storage graph")?;
        let inheritance_graph = repo
            .load_inheritance_graph()
            .await
            .wrap_err("failed to load project inheritance graph")?;
        let project_index = Arc::new(ProjectIndex::build(
            call_graph,
            storage_graph,
            inheritance_graph,
        ));

        let extracted_by_id: BTreeMap<i32, ExtractedSemantic> = extracted
            .into_iter()
            .enumerate()
            .map(|(i, sem)| ((i as i32) + 1, sem))
            .collect();
        let historical_by_id: BTreeMap<i32, HistoricalSemanticRecord> = match_set
            .historicals
            .iter()
            .map(|record| (record.semantic.id, record.clone()))
            .collect();
        let links = LinkInput::build_all(&match_set.matches, &extracted_by_id, &historical_by_id);

        Ok(Some(SpecRuntime {
            project_index,
            extracted_by_id,
            historical_by_id,
            match_set,
            links,
        }))
    }

    async fn plan_links(
        repo: &RepoDatabase,
        options: &SpecGenOptions,
    ) -> Result<Option<PlannedLinks>> {
        let SpecRuntime {
            project_index,
            mut links,
            historical_by_id,
            match_set,
            ..
        } = match Self::prepare_runtime(repo).await? {
            Some(rt) => rt,
            None => return Ok(None),
        };
        let raw_link_count = links.len();

        // Strength filter (plan §7.1). Applied BEFORE the existing
        // caps so links removed at the rubric layer don't burn through
        // per-extract / per-pair quotas.
        let min_rank = options.min_strength.rank();
        let pre_strength = links.len();
        links.retain(|link| link.strength.rank() >= min_rank);
        if links.len() != pre_strength {
            tracing::info!(
                "Specification Generator strength filter (min={}): {} → {} link(s)",
                options.min_strength,
                pre_strength,
                links.len(),
            );
        }
        // Independent link-strength filter on the `(historical, finding)`
        // edge.
        let min_link_rank = options.min_link_strength.rank();
        let pre_link_strength = links.len();
        links.retain(|link| link.link_strength.rank() >= min_link_rank);
        if links.len() != pre_link_strength {
            tracing::info!(
                "Specification Generator link-strength filter (min={}): {} → {} link(s)",
                options.min_link_strength.as_str(),
                pre_link_strength,
                links.len(),
            );
        }
        // Stable sort by (match strength desc, link strength desc) so any
        // later truncation hits the strongest evidence first across both
        // axes.
        links.sort_by(|a, b| {
            b.strength
                .rank()
                .cmp(&a.strength.rank())
                .then_with(|| b.link_strength.rank().cmp(&a.link_strength.rank()))
        });

        if let Some(per_eh_cap) = options.max_findings_per_historical.filter(|n| *n > 0) {
            let mut counts: BTreeMap<(i32, i32), usize> = BTreeMap::new();
            links.retain(|link| {
                let count = counts
                    .entry((link.extract_id, link.historical_id))
                    .or_insert(0);
                if *count >= per_eh_cap {
                    false
                } else {
                    *count += 1;
                    true
                }
            });
            tracing::info!(
                "Specification Generator capping at {} finding(s) per (extract, historical) pair: {} → {} link(s)",
                per_eh_cap,
                raw_link_count,
                links.len()
            );
        }

        if let Some(per_e_cap) = options.max_links_per_extract.filter(|n| *n > 0) {
            let before = links.len();
            let mut counts: BTreeMap<i32, usize> = BTreeMap::new();
            links.retain(|link| {
                let count = counts.entry(link.extract_id).or_insert(0);
                if *count >= per_e_cap {
                    false
                } else {
                    *count += 1;
                    true
                }
            });
            tracing::info!(
                "Specification Generator capping at {} link(s) per extract: {} → {} link(s)",
                per_e_cap,
                before,
                links.len()
            );
        }

        if let Some(cap) = options.max_links.filter(|n| *n > 0)
            && links.len() > cap
        {
            tracing::info!(
                "Specification Generator truncating from {} to {} link(s) for this run",
                links.len(),
                cap
            );
            links.truncate(cap);
        }

        links = interleave_by_extract(links);

        if options.regenerate {
            repo.clear_specifications()
                .await
                .wrap_err("failed to clear existing specifications before regenerate")?;
            tracing::info!("Specification Generator: --regenerate set, cleared existing specs");
        } else {
            // DB-driven resume. Per candidate link, look up
            // [`LinkResumeState`]:
            //   * NotStarted → keep, run gen-spec from scratch.
            //   * Partial    → keep, tag with the existing spec ids so
            //                  [`PlannedLinkWork::run`] skips gen-spec
            //                  and feeds them into the cycle.
            //   * Built      → drop (link has already been fuzzed at
            //                  least once; standalone reflect / regen
            //                  can still drive any pending state).
            let before = links.len();
            let mut kept: Vec<LinkInput> = Vec::with_capacity(before);
            let mut dropped_built = 0usize;
            let mut resumed_partial = 0usize;
            for mut link in links.drain(..) {
                let state = repo
                    .link_resume_state(link.extract_id, link.historical_id, link.finding_id)
                    .await
                    .wrap_err_with(|| {
                        format!(
                            "failed to resolve link resume state for (extract={}, historical={}, finding={})",
                            link.extract_id, link.historical_id, link.finding_id
                        )
                    })?;
                match state {
                    knowdit_repo_model::LinkResumeState::Built => {
                        dropped_built += 1;
                    }
                    knowdit_repo_model::LinkResumeState::Partial { spec_ids } => {
                        resumed_partial += 1;
                        link.pre_committed_spec_ids = spec_ids;
                        kept.push(link);
                    }
                    knowdit_repo_model::LinkResumeState::NotStarted => {
                        kept.push(link);
                    }
                }
            }
            links = kept;
            if dropped_built > 0 || resumed_partial > 0 {
                tracing::info!(
                    "Specification Generator resume: {} link(s) dropped (Built), {} link(s) resuming at inner cycle (Partial), {} link(s) remaining; {} → {} link(s) total",
                    dropped_built,
                    resumed_partial,
                    links.len(),
                    before,
                    links.len(),
                );
            }
        }

        if links.is_empty() {
            tracing::warn!("Specification Generator: no links to process after expansion");
            return Ok(None);
        }

        Ok(Some(PlannedLinks {
            project_index,
            links,
            matched_extract_count: match_set
                .matches
                .iter()
                .map(|m| m.extract_id)
                .unique()
                .count(),
            historical_finding_total: historical_by_id
                .values()
                .map(|r| r.findings.len())
                .sum::<usize>(),
        }))
    }

    /// Regenerate the spec for one `(extract_id, finding_id)` pair with a
    /// prior reflection's reason fed back into the agent's system prompt.
    /// Returns the new spec **in memory** (not persisted) so the caller
    /// can flow it into `repo.write_full_spec_regen` together with the
    /// freshly-regenerated codegen — one atomic transaction, no orphan rows
    /// on partial failure.
    pub async fn regen_one_link(
        repo: &RepoDatabase,
        llm: &LLM,
        options: &SpecGenOptions,
        request: SpecRegenRequest,
    ) -> Result<SpecRegenInMemory> {
        let runtime = Self::prepare_runtime(repo)
            .await?
            .ok_or_else(|| color_eyre::eyre::eyre!("project DB has no extracts/matches"))?;
        let link = runtime
            .links
            .iter()
            .find(|l| {
                l.extract_id == request.extract_id
                    && l.historical_id == request.historical_id
                    && l.finding_id == request.finding_id
            })
            .cloned()
            .ok_or_else(|| {
                color_eyre::eyre::eyre!(
                    "no LinkInput for (extract={}, historical={}, finding={}) — did the KG change since the spec was first synthesized?",
                    request.extract_id,
                    request.historical_id,
                    request.finding_id
                )
            })?;
        let prompt_extension = build_regen_prompt_extension(&request.mode, &request.prior_feedback);
        let outcome = run_link(
            &link,
            &runtime.project_index,
            llm,
            options,
            request.serial_for_cache_key,
            Some(&prompt_extension),
        )
        .await?;
        Ok(SpecRegenInMemory {
            extract_id: request.extract_id,
            finding_id: request.finding_id,
            specifications: outcome.specifications,
            status: outcome.status,
            abort_reason: outcome.abort_reason,
            steps: outcome.steps,
        })
    }
}

/// Cross-link state shared between `run` and `regen_one_link`. Built once
/// per CLI invocation; fields are owned (no lifetime params) so the
/// runtime can be passed across async boundaries by clone.
pub(crate) struct SpecRuntime {
    pub(crate) project_index: Arc<ProjectIndex>,
    pub(crate) extracted_by_id: BTreeMap<i32, ExtractedSemantic>,
    pub(crate) historical_by_id: BTreeMap<i32, HistoricalSemanticRecord>,
    pub(crate) match_set: SemanticMatchSet,
    pub(crate) links: Vec<LinkInput>,
}

struct PlannedLinks {
    project_index: Arc<ProjectIndex>,
    links: Vec<LinkInput>,
    matched_extract_count: usize,
    historical_finding_total: usize,
}

/// The language-agnostic subset of [`PlannedLinks`]: the resume-filtered,
/// capped, interleaved per-link work units plus the counts orchestrators log,
/// *without* the Solidity [`ProjectIndex`]. Produced by
/// [`SpecificationGenerator::plan_link_inputs`] for non-Solidity spec backends
/// (e.g. Move) that build and ground against their own project index.
pub struct PlannedLinkInputs {
    pub links: Vec<LinkInput>,
    pub matched_extract_count: usize,
    pub historical_finding_total: usize,
}

/// One spec-regen request from `agentic regen`. Keeps the four
/// regen inputs in one struct so the per-call signature stays terse
/// even as the spec-regen knobs grow.
#[derive(Debug, Clone)]
pub struct SpecRegenRequest {
    pub extract_id: i32,
    /// `historical_semantic.id` of the prior spec — pinned so
    /// `regen_one_link` matches the **same** LinkInput the original
    /// spec was authored from. Without this, sibling LinkInputs
    /// sharing `(E, F)` but with different H could silently swap in
    /// during regen.
    pub historical_id: i32,
    pub finding_id: i32,
    pub mode: SpecRegenMode,
    pub prior_feedback: String,
    /// Used by the cache key to namespace LLM calls per regen
    /// attempt. Pass the triggering `reflection.id` so a re-run hits
    /// cache.
    pub serial_for_cache_key: usize,
}

/// Patch vs from-scratch (per `plan_reflection.md` §3.2). Patch mode
/// shows the agent the prior spec; from-scratch tells it to discard
/// history.
#[derive(Debug, Clone)]
pub enum SpecRegenMode {
    Patch(AuditSpecification),
    FromScratch,
}

/// Output of [`SpecificationGenerator::regen_one_link`] — the new specs
/// the agent committed, not yet persisted. The caller composes this with
/// a codegen regen + lineage rows in one atomic txn.
#[derive(Debug, Clone)]
pub struct SpecRegenInMemory {
    pub extract_id: i32,
    pub finding_id: i32,
    pub specifications: Vec<AuditSpecification>,
    pub status: LinkSpecStatus,
    pub abort_reason: Option<String>,
    pub steps: usize,
}

/// Commit the link's specs to the project DB and return the new
/// `specification.id`s in `outcome.specifications` order. An empty Vec
/// means either the link committed nothing, or the commit failed (which
/// is logged) — callers should treat it the same way.
async fn commit_link_outcome(repo: &RepoDatabase, outcome: &LinkSpecOutcome) -> Vec<i32> {
    if outcome.specifications.is_empty() {
        return Vec::new();
    }
    let mut payload = Vec::with_capacity(outcome.specifications.len());
    for spec in &outcome.specifications {
        match serde_json::to_string(spec) {
            Ok(json) => payload.push(SpecificationRecord {
                semantic_id: outcome.extract_id,
                historical_id: outcome.historical_id,
                finding_id: outcome.finding_id,
                specification_json: json,
            }),
            Err(err) => {
                tracing::error!(
                    "failed to JSON-serialize spec for extract={} finding={}: {err:#}",
                    outcome.extract_id,
                    outcome.finding_id
                );
                return Vec::new();
            }
        }
    }
    match repo.append_specifications(&payload).await {
        Ok(ids) => ids,
        Err(err) => {
            tracing::error!(
                "failed to append {} spec(s) for extract={} finding={}: {err:#}",
                payload.len(),
                outcome.extract_id,
                outcome.finding_id,
            );
            Vec::new()
        }
    }
}

async fn process_link(
    link: &LinkInput,
    project_index: &Arc<ProjectIndex>,
    llm: &LLM,
    options: &SpecGenOptions,
    link_idx_1based: usize,
    total_links: usize,
) -> LinkSpecOutcome {
    let label = format!(
        "link={} (total = {}) {}",
        link_idx_1based, total_links, link
    );
    tracing::info!("Spec generator starting {label}");
    match run_link(link, project_index, llm, options, link_idx_1based, None).await {
        Ok(outcome) => {
            let kind = match outcome.status {
                LinkSpecStatus::Built => "built",
                LinkSpecStatus::Abandoned => "abandoned",
            };
            tracing::info!(
                "{label}: {kind} ({} spec(s), {} step(s), {} compaction(s)){}",
                outcome.specifications.len(),
                outcome.steps,
                outcome.compact_count,
                outcome
                    .abort_reason
                    .as_ref()
                    .map(|r| format!(" — {r}"))
                    .unwrap_or_default(),
            );
            outcome
        }
        Err(err) => {
            tracing::error!(
                "{label}: agent run failed, abandoning link without committing — {err:#}"
            );
            LinkSpecOutcome {
                ordinal: link_idx_1based,
                extract_id: link.extract_id,
                historical_id: link.historical_id,
                finding_id: link.finding_id,
                status: LinkSpecStatus::Abandoned,
                specifications: Vec::new(),
                specification_ids: Vec::new(),
                abort_reason: Some(format!("agent error: {err:#}")),
                final_summary: None,
                steps: 0,
                compact_count: 0,
            }
        }
    }
}

fn aggregate(by_link: Vec<LinkSpecOutcome>) -> SpecGenOutcome {
    let mut out = SpecGenOutcome::default();
    out.link_count = by_link.len();
    for record in &by_link {
        match record.status {
            LinkSpecStatus::Built => out.built_link_count += 1,
            LinkSpecStatus::Abandoned => out.abandoned_link_count += 1,
        }
        out.total_specs += record.specifications.len();
    }
    out.by_link = by_link;
    out
}

// ---------------------------------------------------------------------------
// Link expansion
// ---------------------------------------------------------------------------

/// Round-robin interleave links by `extract_id` so a billing cap that cuts the
/// run short still hits every extract's top-priority links rather than burning
/// the whole budget on the lowest-id extract.
pub(crate) fn interleave_by_extract(links: Vec<LinkInput>) -> Vec<LinkInput> {
    use std::collections::VecDeque;
    let mut by_extract: BTreeMap<i32, VecDeque<LinkInput>> = BTreeMap::new();
    for link in links {
        by_extract
            .entry(link.extract_id)
            .or_default()
            .push_back(link);
    }
    let total: usize = by_extract.values().map(|q| q.len()).sum();
    let mut out: Vec<LinkInput> = Vec::with_capacity(total);
    while !by_extract.is_empty() {
        let keys: Vec<i32> = by_extract.keys().copied().collect();
        for k in keys {
            if let Some(queue) = by_extract.get_mut(&k) {
                if let Some(link) = queue.pop_front() {
                    out.push(link);
                }
                if queue.is_empty() {
                    by_extract.remove(&k);
                }
            }
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Project index (precomputed lookups for the agent's tools)
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub struct ProjectIndex {
    /// Held by `Arc` so downstream consumers (e.g. the harness
    /// `RunForgeTool` that needs a `&CallGraph` for the coverage gate)
    /// can keep a cheap reference instead of triggering a full
    /// `CallGraph::clone()` per spec — which over thousands of specs
    /// fragmented glibc malloc badly enough to OOM the orchestrator.
    pub call_graph: Arc<CallGraph>,
    pub storage_graph: StorageGraph,
    pub inheritance_graph: InheritanceGraph,
    /// `function.id -> (relative_file_path, contract_or_interface_name, kind)`
    pub function_owner: BTreeMap<i32, FunctionOwner>,
    /// Lower-cased contract name -> contract ids (multiple files may reuse).
    pub contract_ids_by_name: BTreeMap<String, Vec<i32>>,
    /// Lower-cased interface name -> interface ids.
    pub interface_ids_by_name: BTreeMap<String, Vec<i32>>,
    /// state_variable_id -> declaring contract id (from contract_variable).
    pub declaring_contract_for_var: BTreeMap<i32, i32>,
    /// contract_id -> all state-variable ids (own + inherited via the
    /// transitive closure of contract_inherits).
    pub visible_state_vars: BTreeMap<i32, BTreeSet<i32>>,
    /// Lower-cased state-variable name -> state_variable ids.
    pub state_var_ids_by_name: BTreeMap<String, Vec<i32>>,
}

#[derive(Debug, Clone)]
pub(crate) struct FunctionOwner {
    pub(crate) relative_file_path: String,
    pub(crate) container_kind: ContainerKind,
    pub(crate) container_name: String,
    pub(crate) container_id: i32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ContainerKind {
    Contract,
    Interface,
}

impl ContainerKind {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Contract => "contract",
            Self::Interface => "interface",
        }
    }
}

impl ProjectIndex {
    pub(crate) fn build(
        call_graph: CallGraph,
        storage_graph: StorageGraph,
        inheritance_graph: InheritanceGraph,
    ) -> Self {
        // Wrap the call graph in an `Arc` up front so every downstream
        // hand-off (including the per-spec `RunForgeTool::callgraph`)
        // is a refcount bump rather than a deep clone of every contract
        // / function / source body.
        let call_graph = Arc::new(call_graph);
        let mut function_owner: BTreeMap<i32, FunctionOwner> = BTreeMap::new();
        let mut contract_ids_by_name: BTreeMap<String, Vec<i32>> = BTreeMap::new();
        let mut interface_ids_by_name: BTreeMap<String, Vec<i32>> = BTreeMap::new();
        for contract in call_graph.contracts.values() {
            contract_ids_by_name
                .entry(contract.name.to_lowercase())
                .or_default()
                .push(contract.id);
            for function in &contract.functions {
                function_owner.insert(
                    function.id,
                    FunctionOwner {
                        relative_file_path: contract.relative_file_path.display().to_string(),
                        container_kind: ContainerKind::Contract,
                        container_name: contract.name.clone(),
                        container_id: contract.id,
                    },
                );
            }
        }
        for interface in call_graph.interfaces.values() {
            interface_ids_by_name
                .entry(interface.name.to_lowercase())
                .or_default()
                .push(interface.id);
            for function in &interface.functions {
                function_owner.insert(
                    function.id,
                    FunctionOwner {
                        relative_file_path: interface.relative_file_path.display().to_string(),
                        container_kind: ContainerKind::Interface,
                        container_name: interface.name.clone(),
                        container_id: interface.id,
                    },
                );
            }
        }

        let mut declaring_contract_for_var: BTreeMap<i32, i32> = BTreeMap::new();
        for ContractVariable {
            contract_id,
            state_variable_id,
            ..
        } in &storage_graph.contract_variables
        {
            declaring_contract_for_var
                .entry(*state_variable_id)
                .or_insert(*contract_id);
        }

        let inherits = inheritance_closure(&inheritance_graph.inherits);
        let mut visible_state_vars: BTreeMap<i32, BTreeSet<i32>> = BTreeMap::new();
        for ContractVariable {
            contract_id,
            state_variable_id,
            ..
        } in &storage_graph.contract_variables
        {
            visible_state_vars
                .entry(*contract_id)
                .or_default()
                .insert(*state_variable_id);
        }
        // Add inherited variables to descendants.
        let snapshot = visible_state_vars.clone();
        for (contract_id, ancestors) in &inherits {
            let entry = visible_state_vars.entry(*contract_id).or_default();
            for ancestor in ancestors {
                if let Some(vars) = snapshot.get(ancestor) {
                    for var in vars {
                        entry.insert(*var);
                    }
                }
            }
        }

        let mut state_var_ids_by_name: BTreeMap<String, Vec<i32>> = BTreeMap::new();
        for var in storage_graph.state_variables.values() {
            state_var_ids_by_name
                .entry(var.name.to_lowercase())
                .or_default()
                .push(var.id);
        }

        Self {
            call_graph,
            storage_graph,
            inheritance_graph,
            function_owner,
            contract_ids_by_name,
            interface_ids_by_name,
            declaring_contract_for_var,
            visible_state_vars,
            state_var_ids_by_name,
        }
    }

    pub(crate) fn contract(&self, id: i32) -> Option<&Contract> {
        self.call_graph.contracts.get(&id)
    }

    pub(crate) fn interface(&self, id: i32) -> Option<&Interface> {
        self.call_graph.interfaces.get(&id)
    }

    pub(crate) fn state_variable(&self, id: i32) -> Option<&StateVariable> {
        self.storage_graph.state_variables.get(&id)
    }

    pub(crate) fn lookup_contract(&self, name: &str) -> Vec<i32> {
        self.contract_ids_by_name
            .get(&name.to_lowercase())
            .cloned()
            .unwrap_or_default()
    }

    pub(crate) fn lookup_interface(&self, name: &str) -> Vec<i32> {
        self.interface_ids_by_name
            .get(&name.to_lowercase())
            .cloned()
            .unwrap_or_default()
    }

    pub(crate) fn lookup_state_var(&self, name: &str) -> Vec<i32> {
        self.state_var_ids_by_name
            .get(&name.to_lowercase())
            .cloned()
            .unwrap_or_default()
    }


    /// True when `name` resolves to a project contract or interface.
    /// Used by the spec-builder tools to reject hallucinated contract
    /// references before they enter the draft.
    pub(crate) fn has_contract(&self, name: &str) -> bool {
        !self.lookup_contract(name).is_empty() || !self.lookup_interface(name).is_empty()
    }

    /// True when `key` resolves to a project state variable. Accepts a
    /// bare `fieldName` (matched anywhere in the project) or a qualified
    /// `Contract.field` (the field must be visible to that contract,
    /// inherited members included).
    pub(crate) fn has_state_variable(&self, key: &str) -> bool {
        let key = key.trim();
        match key.split_once('.') {
            Some((contract, field)) => {
                let var_ids = self.lookup_state_var(field.trim());
                if var_ids.is_empty() {
                    return false;
                }
                self.lookup_contract(contract.trim()).iter().any(|cid| {
                    self.visible_state_vars
                        .get(cid)
                        .map(|visible| var_ids.iter().any(|vid| visible.contains(vid)))
                        .unwrap_or(false)
                })
            }
            None => !self.lookup_state_var(key).is_empty(),
        }
    }

    /// True when project contract/interface `contract` declares — or
    /// inherits — a function named `function` (case-insensitive).
    pub(crate) fn contract_has_function(&self, contract: &str, function: &str) -> bool {
        let target = function.trim().to_lowercase();
        let declares = |cid: i32| {
            self.contract(cid)
                .map(|c| c.functions.iter().any(|f| f.name.to_lowercase() == target))
                .unwrap_or(false)
        };
        for cid in self.lookup_contract(contract) {
            if declares(cid) {
                return true;
            }
            if self
                .inheritance_graph
                .ancestors_of(cid)
                .into_iter()
                .any(declares)
            {
                return true;
            }
        }
        self.lookup_interface(contract).into_iter().any(|iid| {
            self.interface(iid)
                .map(|i| i.functions.iter().any(|f| f.name.to_lowercase() == target))
                .unwrap_or(false)
        })
    }

    fn render_interface_lookup(
        &self,
        interface: &Interface,
        focus_function: Option<&str>,
    ) -> String {
        let mut out = String::new();
        out.push_str(&format!(
            "## interface `{}` @ `{}` (id={})\n",
            interface.name,
            interface.relative_file_path.display(),
            interface.id
        ));
        let focus = focus_function.map(str::to_lowercase);
        for f in &interface.functions {
            if focus
                .as_deref()
                .map(|n| f.name.to_lowercase() == n)
                .unwrap_or(true)
            {
                out.push_str(&format!(
                    "- {}({}) @ {}:{} (id={})\n",
                    f.name,
                    f.args,
                    f.relative_file_path.display(),
                    f.loc.start_line,
                    f.id
                ));
            }
        }
        out
    }

    fn render_contract_lookup(&self, contract: &Contract, focus_function: Option<&str>) -> String {
        let mut out = String::new();
        out.push_str(&format!(
            "## contract `{}` @ `{}` (id={})\n",
            contract.name,
            contract.relative_file_path.display(),
            contract.id
        ));
        let focus = focus_function.map(str::to_lowercase);
        let matched: Vec<&Function> = contract
            .functions
            .iter()
            .filter(|f| {
                focus
                    .as_deref()
                    .map(|name| f.name.to_lowercase() == name)
                    .unwrap_or(true)
            })
            .collect();

        if focus.is_some() && matched.is_empty() {
            out.push_str(&format!(
                "no function matching `{}` in this contract; available functions:\n",
                focus_function.unwrap_or("")
            ));
            for f in &contract.functions {
                out.push_str(&format!(
                    "- {}({}) @ {}:{} (id={})\n",
                    f.name,
                    f.args,
                    f.relative_file_path.display(),
                    f.loc.start_line,
                    f.id
                ));
            }
            return out;
        }

        if focus.is_none() {
            out.push_str("Functions:\n");
            for f in &contract.functions {
                out.push_str(&format!(
                    "- {}({}) @ {}:{} (id={})\n",
                    f.name,
                    f.args,
                    f.relative_file_path.display(),
                    f.loc.start_line,
                    f.id
                ));
            }
            return out;
        }

        for function in matched {
            out.push_str(&format!(
                "\n### function `{}({})` @ {}:{} (id={})\n",
                function.name,
                function.args,
                function.relative_file_path.display(),
                function.loc.start_line,
                function.id
            ));
            if let Some(content) = &function.content {
                out.push_str("source:\n```solidity\n");
                out.push_str(content.trim_end());
                out.push_str("\n```\n");
            }
            out.push_str("\noutgoing calls:\n");
            if function.calls.is_empty() {
                out.push_str("- (none)\n");
            } else {
                for call in &function.calls {
                    out.push_str(&format!(
                        "- -> {}\n",
                        self.describe_endpoint(call.to_id, call)
                    ));
                }
            }
            out.push_str("\nincoming calls:\n");
            let mut incoming: Vec<&FunctionCall> = Vec::new();
            for c in self.call_graph.contracts.values() {
                for f in &c.functions {
                    for call in &f.calls {
                        if call.to_id == function.id {
                            incoming.push(call);
                        }
                    }
                }
            }
            for i in self.call_graph.interfaces.values() {
                for f in &i.functions {
                    for call in &f.calls {
                        if call.to_id == function.id {
                            incoming.push(call);
                        }
                    }
                }
            }
            if incoming.is_empty() {
                out.push_str("- (none in static analysis)\n");
            } else {
                for call in incoming {
                    out.push_str(&format!(
                        "- <- {}\n",
                        self.describe_endpoint(call.from_id, call)
                    ));
                }
            }
        }

        out
    }

    fn describe_function_xref(&self, function_id: i32, description: Option<&str>) -> String {
        let endpoint = match self.function_owner.get(&function_id) {
            Some(owner) => {
                let function_label = match owner.container_kind {
                    ContainerKind::Contract => self
                        .contract(owner.container_id)
                        .and_then(|c| c.functions.iter().find(|f| f.id == function_id))
                        .map(|f| format!("{}({})", f.name, f.args)),
                    ContainerKind::Interface => self
                        .interface(owner.container_id)
                        .and_then(|i| i.functions.iter().find(|f| f.id == function_id))
                        .map(|f| format!("{}({})", f.name, f.args)),
                }
                .unwrap_or_else(|| format!("function#{function_id}"));
                format!(
                    "{} {}::{} @ {}",
                    owner.container_kind.as_str(),
                    owner.container_name,
                    function_label,
                    owner.relative_file_path
                )
            }
            None => format!("(unknown owner) function#{function_id}"),
        };
        match description.map(str::trim).filter(|s| !s.is_empty()) {
            Some(desc) => format!("{endpoint} :: {desc}"),
            None => endpoint,
        }
    }

    fn describe_endpoint(&self, function_id: i32, call: &FunctionCall) -> String {
        let owner = self.function_owner.get(&function_id);
        let function_name = owner
            .and_then(|owner| match owner.container_kind {
                ContainerKind::Contract => self
                    .contract(owner.container_id)
                    .and_then(|c| c.functions.iter().find(|f| f.id == function_id))
                    .map(|f| format!("{}({})", f.name, f.args)),
                ContainerKind::Interface => self
                    .interface(owner.container_id)
                    .and_then(|i| i.functions.iter().find(|f| f.id == function_id))
                    .map(|f| format!("{}({})", f.name, f.args)),
            })
            .unwrap_or_else(|| format!("function#{function_id}"));
        let suffix = call
            .description
            .as_ref()
            .filter(|d| !d.trim().is_empty())
            .map(|d| format!(" :: {}", d.trim()))
            .unwrap_or_default();
        match owner {
            Some(owner) => format!(
                "{} {}::{} @ {}{suffix}",
                owner.container_kind.as_str(),
                owner.container_name,
                function_name,
                owner.relative_file_path,
            ),
            None => format!("(unknown owner) {}{}", function_name, suffix),
        }
    }
}

pub(crate) fn inheritance_closure(rows: &[ContractInherit]) -> BTreeMap<i32, BTreeSet<i32>> {
    let mut direct: BTreeMap<i32, BTreeSet<i32>> = BTreeMap::new();
    for row in rows {
        direct
            .entry(row.contract_id)
            .or_default()
            .insert(row.inherited_id);
    }
    let mut closure: BTreeMap<i32, BTreeSet<i32>> = BTreeMap::new();
    for &start in direct.keys() {
        let mut acc: BTreeSet<i32> = BTreeSet::new();
        let mut frontier: Vec<i32> = direct
            .get(&start)
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .collect();
        while let Some(node) = frontier.pop() {
            if !acc.insert(node) {
                continue;
            }
            if let Some(parents) = direct.get(&node) {
                for parent in parents {
                    if !acc.contains(parent) {
                        frontier.push(*parent);
                    }
                }
            }
        }
        closure.insert(start, acc);
    }
    closure
}

// ---------------------------------------------------------------------------
// Per-link agent runner
// ---------------------------------------------------------------------------

const DEFAULT_COMPACT_RATIO: f64 = 0.8;

async fn run_link(
    link: &LinkInput,
    project_index: &Arc<ProjectIndex>,
    llm: &LLM,
    options: &SpecGenOptions,
    link_serial: usize,
    // When `Some`, this run is a spec regen — the agent's system prompt
    // gets the supplied feedback section appended verbatim (`run_link`
    // doesn't format it; that's the regen caller's job).
    prompt_extension: Option<&str>,
) -> Result<LinkSpecOutcome> {
    let memory = build_link_memory(project_index)?;
    let draft = tools::DraftHandle::new();
    let tool_box = draft.build_tool_box(project_index, options.max_specs_per_link);

    let cache_key = format!(
        "{}-link{:04}-e{}-h{}-f{}",
        options.cache_key, link_serial, link.extract_id, link.historical_id, link.finding_id
    );
    let debug_prefix = options.debug_prefix.as_ref().map(|prefix| {
        format!(
            "{}-link{:04}-e{}-h{}-f{}",
            prefix, link_serial, link.extract_id, link.historical_id, link.finding_id
        )
    });

    let mut system_prompt = build_system_prompt(link);
    if let Some(ext) = prompt_extension {
        system_prompt.push_str("\n\n");
        system_prompt.push_str(ext);
    }
    // Sequential tool calls: the spec builder exposes `update_* / add_* /
    // set_* … commit / finalize` tools. A same-turn parallel `commit`
    // racing a builder mutation can serialize a stale spec (the mutation
    // lands after commit already snapshotted). Force ordered execution.
    let mut agent = Agent::with_memory_config(
        system_prompt,
        tool_box,
        cache_key,
        &memory,
        &spec_memory_criteria(),
        AgentConfig::default().sequential_toolcall(),
    )
    .await;

    let compact_threshold = options
        .compact_context_threshold_tokens
        .unwrap_or_else(|| (llm.model.config.max_input() as f64 * DEFAULT_COMPACT_RATIO) as usize);

    let user_prompt = build_user_prompt(link, project_index);
    let mut step_result = agent
        .step_with_user(
            user_prompt,
            llm,
            debug_prefix.as_deref(),
            options.llm_settings.clone(),
        )
        .await
        .wrap_err("spec generator agent failed on initial step")?;

    let mut steps = 1usize;
    let mut compact_count = 0usize;

    while {
        let snapshot = draft.snapshot().await;
        snapshot.final_status.is_none()
    } {
        if matches!(step_result, StepResult::Stop(_)) {
            // Agent stopped without finalizing; treat as silent abandon.
            let mut guard = draft.0.lock().await;
            guard.final_status.get_or_insert(LinkSpecStatus::Abandoned);
            guard
                .abort_reason
                .get_or_insert_with(|| "agent stopped without calling finalize".to_string());
            break;
        }

        if steps >= options.max_agent_steps {
            let mut guard = draft.0.lock().await;
            guard.final_status.get_or_insert(LinkSpecStatus::Abandoned);
            guard.abort_reason.get_or_insert_with(|| {
                format!(
                    "agent exceeded max_agent_steps={} before finalizing",
                    options.max_agent_steps
                )
            });
            break;
        }

        if let Some(tokens) = agent.approx_context_tokens(&llm.model.config)
            && tokens >= compact_threshold
        {
            tracing::info!(
                "Spec generator compacting agent context (tokens={tokens}, threshold={compact_threshold})"
            );
            agent = agent
                .compact(
                    llm,
                    debug_prefix
                        .as_ref()
                        .map(|prefix| format!("{prefix}-compact"))
                        .as_deref(),
                    options.llm_settings.clone(),
                )
                .await
                .wrap_err("spec generator agent failed to compact context")?;
            compact_count += 1;
        }

        steps += 1;
        step_result = agent
            .step(llm, debug_prefix.as_deref(), options.llm_settings.clone())
            .await
            .wrap_err_with(|| format!("spec generator agent failed at step {steps}"))?;
    }

    let snapshot = draft.snapshot().await;
    let status = snapshot.final_status.unwrap_or(LinkSpecStatus::Abandoned);
    Ok(LinkSpecOutcome {
        ordinal: link_serial,
        extract_id: link.extract_id,
        historical_id: link.historical_id,
        finding_id: link.finding_id,
        status,
        specifications: snapshot.completed.clone(),
        specification_ids: Vec::new(),
        abort_reason: snapshot.abort_reason.clone(),
        final_summary: snapshot.final_summary.clone(),
        steps,
        compact_count,
    })
}

// ---------------------------------------------------------------------------
// Memory construction
// ---------------------------------------------------------------------------

pub(crate) fn build_link_memory(project_index: &ProjectIndex) -> Result<AgentMemoryContext> {
    let mut short_term: BTreeMap<String, AgentMemoryContent> = BTreeMap::new();
    for contract in project_index.call_graph.contracts.values() {
        let title = format!(
            "{}:{}:{}:{}",
            contract.relative_file_path.display(),
            contract.name,
            contract.chunk.loc.start_line,
            contract.chunk.loc.start_column,
        );
        let content = render_contract_memory(contract, project_index);
        short_term.insert(
            title.clone(),
            AgentMemoryContent {
                title,
                related_context: format!(
                    "Index for contract {}: state variables (own + inherited) and function signatures with their outgoing calls. Bodies are NOT inlined — use `read_function_source` or `read_contract_source` to fetch source on demand.",
                    contract.name
                ),
                trigger_scenario:
                    "Read this index when you need to find the right function/state variable to inspect. Then call `read_function_source(contract, function)` for that one body — read by function, not whole-file, unless you really need the full file."
                        .to_string(),
                content,
                raw_content: None,
            },
        );
    }
    for interface in project_index.call_graph.interfaces.values() {
        let title = format!(
            "{}:{}:{}:{}",
            interface.relative_file_path.display(),
            interface.name,
            interface.chunk.loc.start_line,
            interface.chunk.loc.start_column,
        );
        let content = render_interface_memory(interface);
        short_term.insert(
            title.clone(),
            AgentMemoryContent {
                title,
                related_context: format!(
                    "Function declarations of interface {} (signatures only; use `read_contract_source` if you need the raw interface text)",
                    interface.name
                ),
                trigger_scenario:
                    "Read this entry when a contract calls an interface and you need its declared signatures"
                        .to_string(),
                content,
                raw_content: None,
            },
        );
    }

    Ok(AgentMemoryContext::new_without_search(AgentMemory {
        long_term: BTreeMap::new(),
        short_term,
    }))
}

pub(crate) fn render_contract_memory(contract: &Contract, project_index: &ProjectIndex) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "# Contract `{}` @ `{}`\n\n",
        contract.name,
        contract.relative_file_path.display()
    ));
    if let Some(desc) = &contract.description
        && !desc.trim().is_empty()
    {
        out.push_str(&format!("Description: {}\n\n", desc.trim()));
    }
    out.push_str("## State variables (own + inherited)\n");
    let visible_ids = project_index
        .visible_state_vars
        .get(&contract.id)
        .cloned()
        .unwrap_or_default();
    if visible_ids.is_empty() {
        out.push_str("- (none)\n");
    } else {
        for var_id in &visible_ids {
            if let Some(var) = project_index.state_variable(*var_id) {
                let owner_id = project_index
                    .declaring_contract_for_var
                    .get(var_id)
                    .copied();
                let owner = owner_id
                    .and_then(|id| project_index.contract(id))
                    .map(|c| c.name.as_str())
                    .unwrap_or("?");
                let inherited = owner_id != Some(contract.id);
                out.push_str(&format!(
                    "- {} {} ({}{})\n  declaration: `{}` @ {}:{}\n",
                    var.type_name.trim(),
                    var.name,
                    owner,
                    if inherited { ", inherited" } else { "" },
                    var.content.trim().lines().next().unwrap_or("").trim(),
                    var.relative_file_path.display(),
                    var.loc.start_line,
                ));
            }
        }
    }

    out.push_str(
        "\n## Functions (full signatures + outgoing calls; use `read_function_source` for a single function body or `read_contract_source` for the whole file)\n",
    );
    if contract.functions.is_empty() {
        out.push_str("- (none)\n");
    } else {
        for function in &contract.functions {
            let sig = render_function_signature(function);
            out.push_str(&format!(
                "- {} @ {}:{} (id={})\n",
                sig,
                function.relative_file_path.display(),
                function.loc.start_line,
                function.id,
            ));
            for call in &function.calls {
                out.push_str(&format!(
                    "  -> {}\n",
                    project_index.describe_endpoint(call.to_id, call)
                ));
            }
        }
    }

    out
}

pub(crate) fn render_interface_memory(interface: &Interface) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "# Interface `{}` @ `{}`\n\n",
        interface.name,
        interface.relative_file_path.display()
    ));
    out.push_str(
        "## Function declarations (full signatures; use `read_contract_source` for the full interface text)\n",
    );
    for function in &interface.functions {
        let sig = render_function_signature(function);
        out.push_str(&format!(
            "- {} @ {}:{} (id={})\n",
            sig,
            function.relative_file_path.display(),
            function.loc.start_line,
            function.id,
        ));
    }
    out
}

/// Render a function's full Solidity signature line (including visibility,
/// mutability, and return types) by extracting it from the recorded source
/// content. Falls back to the bare `name(args)` form when no body content
/// was captured (rare, but possible for some interface declarations).
fn render_function_signature(function: &Function) -> String {
    if let Some(source) = function.content.as_deref()
        && let Some(sig) = extract_signature_head(source)
    {
        return format!("`{sig}`");
    }
    format!("`{}({})`", function.name, function.args)
}

/// Read the function's first `{...}`/`;` terminator-delimited prefix from
/// `source` and squash whitespace — that yields the canonical signature
/// even when the declaration spans multiple lines.
fn extract_signature_head(source: &str) -> Option<String> {
    let mut buf = String::new();
    for ch in source.chars() {
        if ch == '{' || ch == ';' {
            break;
        }
        if ch == '\n' || ch == '\r' || ch == '\t' {
            buf.push(' ');
        } else {
            buf.push(ch);
        }
    }
    let collapsed = buf.split_whitespace().collect::<Vec<_>>().join(" ");
    let trimmed = collapsed.trim().to_string();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed)
    }
}

pub(crate) fn spec_memory_criteria() -> AgentMemorySystemPromptCriteria {
    AgentMemorySystemPromptCriteria::builder()
        .append_short_term_memory_criteria(
            "Per-contract source bundles. Each entry contains the contract source plus its own and inherited state variables. Titles are formatted as `relative_file_path:Contract:line:col` and are stable across the agent's lifetime."
                .to_string(),
        )
        .append_short_term_memory_trigger(
            "Before reasoning about how a state variable, modifier, or function body behaves on the current project."
                .to_string(),
        )
        .append_short_term_memory_trigger(
            "When mapping the historical vulnerability pattern onto concrete project contracts."
                .to_string(),
        )
        .append_short_term_memory_operator(
            "These contract entries were preloaded by the runtime. Read them; do not delete or rewrite them."
                .to_string(),
        )
        .build()
}

// ---------------------------------------------------------------------------
// Serializable wire forms (used by the CLI)
// ---------------------------------------------------------------------------

/// Serializable summary the CLI dumps to JSON / md.
#[derive(Debug, Clone, Serialize)]
pub struct LinkSpecSummary {
    pub extract_id: i32,
    pub historical_id: i32,
    pub finding_id: i32,
    pub status: LinkSpecStatus,
    pub specifications: Vec<AuditSpecification>,
    pub abort_reason: Option<String>,
    pub final_summary: Option<String>,
    pub steps: usize,
    pub compact_count: usize,
}

impl From<&LinkSpecOutcome> for LinkSpecSummary {
    fn from(outcome: &LinkSpecOutcome) -> Self {
        Self {
            extract_id: outcome.extract_id,
            historical_id: outcome.historical_id,
            finding_id: outcome.finding_id,
            status: outcome.status,
            specifications: outcome.specifications.clone(),
            abort_reason: outcome.abort_reason.clone(),
            final_summary: outcome.final_summary.clone(),
            steps: outcome.steps,
            compact_count: outcome.compact_count,
        }
    }
}
