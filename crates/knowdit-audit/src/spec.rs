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
use std::fmt;
use std::sync::Arc;

use color_eyre::eyre::{Result, WrapErr};
use itertools::Itertools;
use knowdit_kg_model::audit_finding::FindingSeverity;
use knowdit_kg_model::db::audit_finding;
use knowdit_kg_model::db::semantic_node;
use knowdit_kg_model::{ExtractedFunction, ExtractedSemantic};
use knowdit_repo_model::cg::{CallGraph, Contract, Function, FunctionCall, Interface};
use knowdit_repo_model::inheritance::{ContractInherit, InheritanceGraph};
use knowdit_repo_model::storage::{
    ContractVariable, FunctionStateVariable, StateVariable, StorageGraph,
};
use knowdit_repo_model::{
    HistoricalSemanticRecord, RepoDatabase, SemanticMatchSet, repo::SpecificationRecord,
};
use llmy::agent::StepResult;
use llmy::agent::tool::ToolBox;
use llmy::agent::tools::memory::{AgentMemory, AgentMemoryContent, AgentMemoryContext};
use llmy::client::client::LLM;
use llmy::client::settings::LLMSettings;
use llmy::harness::Agent;
use llmy::harness::memory::AgentMemorySystemPromptCriteria;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

use crate::types::{AuditSpecification, AuditStateSpecification, SuqenceCallStep};

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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

/// Stable identifier for one expanded `(extract, historical, finding)` link.
/// Public so orchestrators can log / snapshot progress without reaching into
/// the generator's private runtime state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct LinkKey {
    pub extract_id: i32,
    pub historical_id: i32,
    pub finding_id: i32,
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
        let links = build_link_inputs(&match_set.matches, &extracted_by_id, &historical_by_id);

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

fn build_regen_prompt_extension(mode: &SpecRegenMode, feedback: &str) -> String {
    match mode {
        SpecRegenMode::Patch(prior_spec) => {
            let prior_json = serde_json::to_string_pretty(prior_spec)
                .unwrap_or_else(|_| "<unserializable>".into());
            format!(
                "## Prior attempt feedback (this is a spec regen — patch mode)\n\
                 \n\
                 The previously-committed spec for this (extract, finding) pair was \
                 classified `IncompleteSpecification` by the validator.\n\
                 \n\
                 Reason:\n{feedback}\n\
                 \n\
                 Previous spec (JSON):\n```json\n{prior_json}\n```\n\
                 \n\
                 Patch the spec by issuing the appropriate tool calls to address the \
                 issue above. Don't commit the same spec — it's already known to be \
                 unrealizable. If the previous spec is fundamentally wrong (wrong \
                 contracts, unreachable state), produce a structurally different spec \
                 rather than tweaking what's there."
            )
        }
        SpecRegenMode::FromScratch => format!(
            "## Prior attempt feedback (this is a spec regen — from-scratch mode)\n\
             \n\
             The previously-committed specs for this (extract, finding) pair were \
             repeatedly classified `IncompleteSpecification` after multiple patch \
             attempts. The history is being discarded; resynthesize from the \
             knowledge graph.\n\
             \n\
             Why we're restarting:\n{feedback}\n\
             \n\
             Approach this as a fresh spec-generation task. Use the lookup tools to \
             read the relevant project contracts, and produce a spec that's grounded \
             in actual project shape rather than continuing to refine a structurally-\
             wrong starting point."
        ),
    }
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

#[derive(Debug, Clone)]
pub(crate) struct LinkInput {
    pub(crate) extract_id: i32,
    pub(crate) historical_id: i32,
    pub(crate) finding_id: i32,
    /// Mapper-emitted strength on the underlying
    /// `(extract, historical)` pair, copied onto every LinkInput
    /// fanned out from that pair. Used by gen-specs to filter / order
    /// candidates by strength (plan §7.1).
    pub(crate) strength: knowdit_repo_model::MatchStrength,
    /// Global linker-emitted strength on the `(historical, finding)`
    /// edge — how directly this historical finding instantiates the
    /// historical semantic. Independent axis from `strength`.
    pub(crate) link_strength: knowdit_kg_model::link_strength::LinkStrength,
    pub(crate) extract: ExtractedSemantic,
    pub(crate) historical: semantic_node::Model,
    pub(crate) finding: audit_finding::Model,
    /// Spec ids already committed for this link in a prior run.
    /// Empty for fresh links. When non-empty, [`PlannedLinkWork::run`]
    /// short-circuits the gen-spec agent and emits a [`LinkSpecOutcome`]
    /// synthesized from these ids — the inner cycle in the caller
    /// then drives fuzz / reflect / regen against them. Populated by
    /// [`SpecificationGenerator::plan_links`] via
    /// [`RepoDatabase::link_resume_state`].
    pub(crate) pre_committed_spec_ids: Vec<i32>,
}

impl LinkInput {
    fn key(&self) -> LinkKey {
        LinkKey {
            extract_id: self.extract_id,
            historical_id: self.historical_id,
            finding_id: self.finding_id,
        }
    }
}

impl fmt::Display for LinkInput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Link(id={}, extract={}, historical={}, finding={}, strength={})",
            self.extract_id, self.extract_id, self.historical_id, self.finding_id, self.strength,
        )
    }
}

pub(crate) fn build_link_inputs(
    matches: &[knowdit_repo_model::SemanticMatch],
    extracted_by_id: &BTreeMap<i32, ExtractedSemantic>,
    historical_by_id: &BTreeMap<i32, HistoricalSemanticRecord>,
) -> Vec<LinkInput> {
    let mut out = Vec::new();
    let mut seen: BTreeSet<(i32, i32, i32)> = BTreeSet::new();
    for m in matches {
        let extract_id = m.extract_id;
        let historical_id = m.historical_id;
        let Some(extract) = extracted_by_id.get(&extract_id) else {
            tracing::warn!(
                "Skipping match (extract={}, historical={}): no project_semantic row",
                extract_id,
                historical_id
            );
            continue;
        };
        let Some(record) = historical_by_id.get(&historical_id) else {
            tracing::warn!(
                "Skipping match (extract={}, historical={}): no historical_semantic row",
                extract_id,
                historical_id
            );
            continue;
        };
        if record.findings.is_empty() {
            tracing::debug!(
                "Skipping match (extract={}, historical={}): historical has no findings linked",
                extract_id,
                historical_id
            );
            continue;
        }
        for linked in &record.findings {
            let finding = &linked.finding;
            if !seen.insert((extract_id, historical_id, finding.id)) {
                continue;
            }
            out.push(LinkInput {
                extract_id,
                historical_id,
                finding_id: finding.id,
                strength: m.strength,
                link_strength: linked.strength,
                extract: extract.clone(),
                historical: record.semantic.clone(),
                finding: finding.clone(),
                pre_committed_spec_ids: Vec::new(),
            });
        }
    }
    out
}

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
    let draft = DraftHandle(Arc::new(Mutex::new(SpecDraft::default())));

    let mut tools = ToolBox::new();
    tools.add_tool(UpdateStateDescriptionTool {
        draft: draft.clone(),
    });
    tools.add_tool(AddStateVariableConstraintTool {
        draft: draft.clone(),
    });
    tools.add_tool(AddContractConstraintTool {
        draft: draft.clone(),
    });
    tools.add_tool(SetCallSequenceTool {
        draft: draft.clone(),
    });
    tools.add_tool(CommitSpecificationTool {
        draft: draft.clone(),
        max_specs: options.max_specs_per_link,
    });
    tools.add_tool(FinalizeTool {
        draft: draft.clone(),
    });
    tools.add_tool(LookupCallGraphTool {
        project: project_index.clone(),
    });
    tools.add_tool(LookupStateVariableXrefsTool {
        project: project_index.clone(),
    });
    tools.add_tool(ReadContractSourceTool {
        project: project_index.clone(),
    });
    tools.add_tool(ReadFunctionSourceTool {
        project: project_index.clone(),
    });

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
    let mut agent = Agent::with_memory(
        system_prompt,
        tools,
        cache_key,
        &memory,
        &spec_memory_criteria(),
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
                    describe_endpoint(call.to_id, project_index, call)
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
// Prompts
// ---------------------------------------------------------------------------

fn build_system_prompt(link: &LinkInput) -> String {
    let extract = &link.extract;
    let historical = &link.historical;
    let finding = &link.finding;
    let extract_functions = render_extracted_functions(&extract.functions);
    format!(
        r#"You are the Specification Generator agent for a knowledge-driven smart-contract auditing pipeline.

## Your task

You are given a `(project_semantic, historical_semantic, historical_finding)` link from the Knowledge Mapper. The historical finding is a *topic hint* drawn from another project — it likely will not fit the current project verbatim. **Your task is to use the historical finding as a starting point to look for any plausibly related issue inside the matched project semantic, and emit `AuditSpecification`(s) describing those issues.** A committed spec only needs to be *related* to the historical finding (same root-cause family, same kind of state corruption, same exploit shape, or any concrete generalization/specialization of its mechanism). It does NOT have to be a verbatim reproduction.

You operate per-link. The link below stays in your system prompt for the entire run.

## Project DeFi semantic (extracted from the current project)
- id: {extract_id}
- category: {extract_category}
- name: {extract_name}
- definition: {extract_definition}
- description: {extract_description}

### Project semantic function anchors (real names from this project)
Use these as the primary source of truth for `setup.contracts` keys and `sequence` contract/function names. They are real extracted project functions, not conceptual labels:
{extract_functions}

## Historical DeFi semantic (from the knowledge graph; matched as encompassing the project's semantic)
- id: {historical_id}
- category: {historical_category}
- name: {historical_name}
- definition: {historical_definition}
- description: {historical_description}

## Historical finding (use as topic hint, not strict template)
- id: {finding_id}
- title: {finding_title}
- severity: {finding_severity}
- root cause: {finding_root_cause}
- description: {finding_description}
- vulnerability patterns: {finding_patterns}
- known exploits: {finding_exploits}

# Audit-specification model

An `AuditSpecification` defines:

1. **Setup state** — outcome of contract deployment + initial state. State-variable invariants describe what must hold before any real transaction. Contract invariants describe what contracts must exist / be configured.
2. **Pre-vuln state** — state immediately before the issue is triggered. The setup may already satisfy this; if so, leave constraints empty.
3. **Post-vuln state** — state after the issue manifests. Invariants here are what the harness should check (a violated property, an unexpected balance/share/state delta, a stuck/locked condition, etc).
4. **Call sequence** — the core sequence of contract calls that, applied to a system in pre-vuln state, drives the post-vuln state.

A spec does not have to be an *exploit*. It may be:
- A reproduction of the historical exploit, adapted to this project's contracts.
- A *related* issue you found while exploring around the historical finding's topic (e.g. the same kind of accounting drift in a different function, an analogous reentrancy window, a similar invariant break under different inputs).
- A *latent* property whose violation would have the same impact family as the historical finding, even if the exact root cause differs.

If you find more than one plausible scenario for one link, commit each as a separate spec.

# `post_attack.description` contract — read carefully

This field is the most carefully constrained one. The verdict-grader downstream uses it to decide whether the harness reproduces a *real bug* or merely walks a *documented intended path*; a sloppy `post_attack` description is the #1 cause of false-positive `ValidFinding` verdicts. Get this wrong and your whole spec turns into noise.

## Required structure (three parts, all mandatory)

1. **Project's promised state.** Cite a specific `<file:contract.function>` whose NatSpec / inline comments / explicit `require` / clearly documented invariant says state `aaaa` should hold after the sequence. Example: *"Timelock.executeWhitelisted at src/Timelock.sol:496 promises that any executed payload's `[startIndex, endIndex]` slice matches one of the recorded check hashes."*
2. **Attacked state — what actually reaches.** State the concrete value `bbbb` that the attack produces. Example: *"After the sequence, _calldataList for (target, selector) contains two overlapping ranges, and the slice for one of them is silently dropped, so checkCalldata returns true on a payload that no whitelisted hash actually matches."*
3. **Concrete bad consequence.** A specific protocol-impact statement: funds drained, fees stolen, hot signer privilege escalated, reentrancy window opened, accounting drift compounding, indefinite DoS, key invariant broken in a way an attacker monetises, etc. Without naming a concrete loss/exposure, post_attack is rejected. Example: *"A hot signer can route arbitrary value-bearing calldata through executeWhitelisted past the whitelist, draining safe-managed funds; severity Medium because requires a hot-signer role but no further preconditions."*

## Hard exclusions

- ✘ **Documented intended behaviour is NOT a `post_attack` target.** Before writing `post_attack`, read the relevant function's source comments / NatSpec / `require` reasons. If the source explicitly documents the post-state you're describing, the spec is invalid — that's the project's design, not a bug.
  - Concrete example: *"After updatePauseDuration, pauseStartTime is reset to 0"* is **REJECTED** because `ConfigurablePause._updatePauseDuration` carries the comment `/// if the contract was already paused, reset the pauseStartTime to 0 so that this function cannot pause the contract again` — the reset is the project's deliberate mitigation, not an attack outcome.
  - Concrete example: *"RecoverySpellFactory accepts `recoveryThreshold < threshold`"* is **REJECTED** because `_paramChecks` only requires `recoveryThreshold <= owners.length` and the project nowhere promises `recoveryThreshold >= threshold` — the spec invented a constraint the project never made.
- ✘ **No vague divergence.** *"may be inconsistent"*, *"could diverge"*, *"may misreport"*, *"semantically unsafe"* with no concrete value attached are all rejected.
- ✘ **No reverse-engineered specs from the post-state up.** Don't pick a state, then write `setup`/`pre_attack`/`sequence` that reach it. Work top-down: read the project source, find an explicit promise, find a path that breaks the promise, then `post_attack` writes itself.

## Self-check before `commit_specification`

Re-read your `post_attack.description` and answer YES to every question:
1. Did I cite a specific project `<file:contract.function>` whose code or comments establish the expected state?
2. Did I name the concrete attacked state (a specific value, mapping entry, balance change, role table, etc.) — not a vague *"becomes inconsistent"*?
3. Did I name a concrete bad consequence (drain / loss / DoS / bypass / accounting drift) the attacker monetises?
4. Did I verify the project source does NOT explicitly document the post-state as intended (no NatSpec / inline comment that says *"this clears X"*)?

If any answer is NO, rewrite the description and re-check before committing. The runtime rejects `post_attack` descriptions that visibly lack a consequence clause.

# Methodology

**Start from the project semantic — not the historical finding.**

1. **Enumerate the matched semantic's surface area.** Use `list_memories` to find the entries for the project semantic's contracts (the `functions` field of the project semantic and the `category` are your starting hints). For each relevant contract, use `read_memory` to load its *signature index* — it lists state variables (own + inherited) and every function's signature plus outgoing calls. Bodies are NOT inlined. Build a mental map of: which functions belong to this semantic, what state they read/write, what other contracts they call into.

2. **Use `lookup_call_graph` and `lookup_state_variable_xrefs`** to learn which functions are upstream/downstream of the ones in your semantic, and which functions read or write a given state variable. Follow these edges outward — anything the historical finding could plausibly relate to is fair game.

3. **Read function bodies on demand.** Prefer `read_function_source(contract, function)` for a single function — much cheaper than a whole file. Use `read_contract_source(contract)` only when you really need surrounding file context (modifiers, imports, struct layouts). Avoid re-reading the same big file.

4. **Treat the historical finding as a hypothesis seed.** Read its root_cause, patterns, exploits as topic hints. Then ask:
   - Does the project's matched semantic have analogous functions / state variables / external boundaries?
   - Could a similar mechanism (same shape of accounting error, same reentrancy window class, same invariant violation, same access-control gap, same arithmetic edge case) exist *anywhere related* in this semantic — even if the surface details differ?
   - Are there nearby functions that share state with the matched semantic and exhibit a related class of issue?
   You are encouraged to broaden the search to any function whose behavior is *topically related* to the historical finding's root cause, not just functions that exactly mirror the historical exploit.

5. **Build the spec field by field via tool calls.** Stage = `setup` / `pre_attack` / `post_attack`. The same draft is mutated in place; nothing is committed until `commit_specification`. After committing, the draft resets so you can build another spec for the same link.

6. **Finalize.** Call `finalize` exactly once — `status="completed"` if you committed ≥1 spec, `status="abandoned"` only under the strict criteria below.

# Abandon criteria (strict)

You may only `finalize(status="abandoned")` after you have **read at least the relevant function bodies** in the matched semantic and *one* of these is concretely demonstrable:

- The functionality the finding requires (e.g. a specific contract role, an external call shape, a particular state variable, a particular flow) does **not exist anywhere reachable from the project semantic**, and you have shown which lookups you tried.
- The finding's exact issue is *clearly already fixed* in the project (e.g. the unsafe call has a `nonReentrant` modifier verified by reading the body, the missing check is present, the unbounded loop has an explicit cap, etc.) and there is no analogous issue in nearby functions you read.

The `abort_reason` must cite the specific contracts/functions you inspected and what you found there. **Do NOT abandon on a hunch or because the historical surface details don't line up — when in doubt, look for a related issue and commit it.** Mapper has already determined the project semantic is in scope; your job is to harvest *any* related issue, not to gate on exact reproduction.

# Tool rules

- All spec-building tools (`update_state_description`, `add_state_variable_constraint`, `add_contract_constraint`, `set_call_sequence`) edit the current draft. Later calls overwrite earlier values for the same field.
- `set_call_sequence` replaces the whole sequence each call; build it up in one call.
- `commit_specification` is idempotent per draft — don't call it twice for the same draft. After commit, the draft is cleared.
- Memory write/update/delete tools are available, but the preloaded per-contract signature indexes are read-only context; do not modify them. You may write your own short-term notes.

# Hard rules

- You MUST end with `finalize`. Without it the runtime records the link as abandoned.
- Be specific about state variables: prefer `Contract.fieldName` keys when the same field name exists on multiple contracts.
- Specs must reference *real* contracts, functions, and state variables you actually read in this project — never invent fictional names to make a spec stick.
- In `setup.contracts`, use real contract or interface names from the project source. Do not use role/instance labels such as `EntryPoint`, `WalletProxy`, `SmartAccount`, `Stage2Module wallet`, `AttackerContract`, or `HookExtension` unless that exact contract/interface exists in the project. Put role descriptions inside the value text instead.
- In `sequence`, use exact project contract/function names from the function anchors or `lookup_call_graph` results. If the runtime object is a proxy or module-composed wallet, name the concrete module function that actually appears in source, such as `ERC4337v07.executeUserOp`, `Calls.selfExecute`, `Hooks.fallback`, or `Implementation.updateImplementation`.
- A committed spec must be *defensible*: you can name the project functions in its sequence and the state variables in its invariants. But it does NOT need to be a verbatim reproduction of the historical finding — `related to` is enough.
"#,
        extract_id = link.extract_id,
        extract_category = extract.category.as_str(),
        extract_name = extract.name,
        extract_definition = extract.definition.trim(),
        extract_description = extract.description.trim(),
        extract_functions = extract_functions,
        historical_id = link.historical_id,
        historical_category = historical.category.as_str(),
        historical_name = historical.name,
        historical_definition = historical.definition.trim(),
        historical_description = historical.description.trim(),
        finding_id = link.finding_id,
        finding_title = finding.title,
        finding_severity = format_severity(finding.severity),
        finding_root_cause = finding.root_cause.trim(),
        finding_description = finding.description.trim(),
        finding_patterns = finding.patterns.trim(),
        finding_exploits = finding.exploits.trim(),
    )
}

fn format_severity(s: FindingSeverity) -> &'static str {
    match s {
        FindingSeverity::High => "High",
        FindingSeverity::Medium => "Medium",
        FindingSeverity::Low => "Low",
    }
}

/// Heuristic post_attack quality gate, run at commit time. Reads the
/// description and verifies it has the three parts from the system
/// prompt's `post_attack.description contract` section: a project
/// expectation anchor, an attacked-state contrast, and a concrete
/// consequence keyword. Returns `Err(reason)` when one is missing —
/// the caller surfaces the reason to the agent so it can rewrite.
///
/// Heuristic, not bulletproof: a determined agent can satisfy the
/// keyword checks with weasel phrasing. The system prompt carries the
/// real semantic spec; this gate just filters the most blatant
/// "vague divergence" / "documented intended behavior" descriptions
/// the model produced under earlier prompts.
fn check_post_attack_shape(desc: &str) -> std::result::Result<(), &'static str> {
    let trimmed = desc.trim();
    if trimmed.len() < 80 {
        return Err(
            "description is too short (< 80 chars) to carry the required three-part structure (project expectation + attacked state + consequence).",
        );
    }
    let lc = trimmed.to_lowercase();
    let has_anchor = [
        "expects",
        "expect",
        "should",
        "promises",
        "documents",
        "invariant",
        "natspec",
        "comment says",
    ]
    .iter()
    .any(|kw| lc.contains(kw));
    let has_contrast = [
        "but",
        "however",
        "instead",
        "yet",
        "whereas",
        "despite",
        "actually",
        "rather than",
    ]
    .iter()
    .any(|kw| lc.contains(kw));
    let consequence_kws = [
        "drain",
        "loss",
        "lose",
        "stolen",
        "steal",
        "theft",
        "funds",
        "fees",
        "reentr",
        "bypass",
        "brick",
        "locked",
        "stuck",
        "grief",
        "denial",
        "dos",
        "inflate",
        "deflate",
        "exploit",
        "drift",
        "extract",
        "monet",
        "compromis",
        "drained",
        "withdraw without",
        "siphon",
    ];
    let has_consequence = consequence_kws.iter().any(|kw| lc.contains(kw));
    if !has_anchor {
        return Err(
            "missing the project-expectation anchor: the text should cite where the project promises the state (e.g. \"Timelock.execute expects ...\", \"NatSpec says ...\", \"the require message ...\"). Use words like `expects`, `should`, `promises`, or quote the relevant comment.",
        );
    }
    if !has_contrast {
        return Err(
            "missing the contrast between expected and attacked state: use `but`, `however`, `instead`, `whereas`, etc. to make the violation explicit.",
        );
    }
    if !has_consequence {
        return Err(
            "missing the concrete bad consequence: name what the attacker monetises or what the protocol loses (drain/loss/funds/fees/reentrancy/bypass/DoS/grief/inflate/exploit/...). Without a stated consequence, the verdict-grader cannot tell this state apart from documented intended behavior.",
        );
    }
    Ok(())
}

#[cfg(test)]
mod post_attack_shape_tests {
    use super::check_post_attack_shape;

    #[test]
    fn good_post_attack_passes() {
        let s = "Timelock.executeWhitelisted at src/Timelock.sol:496 expects each executed payload's [startIndex,endIndex] slice to match a recorded check hash; but after the sequence, _calldataList holds two overlapping ranges and the second silently shadows the first, so a hot signer can drain safe-managed funds via crafted calldata.";
        assert!(
            check_post_attack_shape(s).is_ok(),
            "{:?}",
            check_post_attack_shape(s)
        );
    }

    #[test]
    fn vague_inconsistency_rejected() {
        let s = "After the maintenance call, the pause state becomes inconsistent with the prior active pause window: pauseStartTime is reset to 0 or otherwise no longer reflects the outstanding pause.";
        // "but" not present, no consequence keyword, no clear anchor — should fail.
        assert!(check_post_attack_shape(s).is_err());
    }

    #[test]
    fn intended_documented_behavior_with_consequence_passes_keywords_but_anchor_should_force_human_re_review()
     {
        // We only catch the obvious omissions; this one slips through
        // the keyword check. The system prompt + agent self-check is
        // what catches semantic-level "this is intended" cases.
        let s = "After updatePauseDuration, the project expects pauseStartTime to remain unchanged but the function resets it to 0, which would let attackers exploit a fund-loss path.";
        assert!(check_post_attack_shape(s).is_ok());
    }

    #[test]
    fn too_short_rejected() {
        let s = "ok";
        assert!(check_post_attack_shape(s).is_err());
    }

    #[test]
    fn missing_consequence_rejected() {
        let s = "The contract expects pauseStartTime to remain unchanged but the function resets it to 0, leaving the system in a different state than the one originally configured by the guardian.";
        assert!(check_post_attack_shape(s).is_err()); // no consequence keyword
    }
}

fn build_user_prompt(link: &LinkInput, project_index: &ProjectIndex) -> String {
    let contract_count = project_index.call_graph.contracts.len();
    let interface_count = project_index.call_graph.interfaces.len();
    let extract_functions = render_extracted_functions(&link.extract.functions);
    format!(
        r#"Explore the matched project semantic for any issue *related to* the historical finding in your system prompt, then commit AuditSpecification(s) for what you find.

Project static-analysis short-term memory: {contract_count} contract entr(ies), {interface_count} interface entr(ies). Titles follow `relative_file_path:Contract:line:col`.

Matched semantic function anchors:
{extract_functions}

Suggested first moves:
1. `list_memories` to see what's available.
2. `read_memory` on the contracts listed in "Matched semantic function anchors" — that is your anchor.
3. From there, follow `lookup_call_graph` edges and `lookup_state_variable_xrefs` to surface every function in or near the semantic that could share the historical finding's failure mode (same root-cause family, same kind of state corruption, same exploit class).
4. `read_function_source(contract, function)` for the bodies you actually need to reason about. Avoid loading the same big file twice — the signature index already tells you what each function calls.
5. Commit one spec per plausibly-related issue you find. The spec only needs to be *related to* the historical finding, not a verbatim reproduction.

Reason briefly out loud, then start issuing tool calls. Keep `finalize` for the very end. Per the system prompt, abandoning requires showing which functions you read and why the finding has no related issue here.

Link summary: extract_id={extract}, historical_id={historical}, finding_id={finding}.
"#,
        contract_count = contract_count,
        interface_count = interface_count,
        extract_functions = extract_functions,
        extract = link.extract_id,
        historical = link.historical_id,
        finding = link.finding_id,
    )
}

/// Render `link.extract.functions` as the anchor list embedded in the
/// gen-specs prompts. Each line is `- \`{contract}\`.\`{name}\` —
/// \`{signature or "(no recorded signature)"}\``. Empty input emits a
/// single fallback bullet so the prompt slot is never blank.
fn render_extracted_functions(functions: &[ExtractedFunction]) -> String {
    if functions.is_empty() {
        return "- (none recorded; use lookup_call_graph before naming contracts/functions)\n"
            .to_string();
    }
    let mut out = String::new();
    for f in functions {
        let signature = f
            .signature
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .unwrap_or("(no recorded signature)");
        out.push_str(&format!(
            "- `{}`.`{}` — `{}`\n",
            f.contract, f.name, signature
        ));
    }
    out
}

// ---------------------------------------------------------------------------
// Spec draft + tools
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default)]
struct SpecDraft {
    setup: AuditStateSpecification,
    pre_attack: AuditStateSpecification,
    post_attack: AuditStateSpecification,
    sequence: Vec<SuqenceCallStep>,
    /// Specs that have been committed already.
    completed: Vec<AuditSpecification>,
    /// Set on `finalize`. Until then the agent loop keeps spinning.
    final_status: Option<LinkSpecStatus>,
    abort_reason: Option<String>,
    final_summary: Option<String>,
}

impl SpecDraft {
    fn reset_draft(&mut self) {
        self.setup = AuditStateSpecification::default();
        self.pre_attack = AuditStateSpecification::default();
        self.post_attack = AuditStateSpecification::default();
        self.sequence.clear();
    }

    fn build_spec(&self) -> AuditSpecification {
        AuditSpecification {
            setup: self.setup.clone(),
            pre_attack: self.pre_attack.clone(),
            post_attack: self.post_attack.clone(),
            sequence: self.sequence.clone(),
        }
    }

    fn draft_summary(&self) -> String {
        format!(
            "setup{{desc={} sv={} contracts={}}} pre{{desc={} sv={} contracts={}}} post{{desc={} sv={} contracts={}}} sequence={}",
            !self.setup.description.is_empty() as u8,
            self.setup.states_variables.len(),
            self.setup.contracts.len(),
            !self.pre_attack.description.is_empty() as u8,
            self.pre_attack.states_variables.len(),
            self.pre_attack.contracts.len(),
            !self.post_attack.description.is_empty() as u8,
            self.post_attack.states_variables.len(),
            self.post_attack.contracts.len(),
            self.sequence.len(),
        )
    }
}

#[derive(Clone)]
struct DraftHandle(Arc<Mutex<SpecDraft>>);

impl std::fmt::Debug for DraftHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DraftHandle").finish_non_exhaustive()
    }
}

impl DraftHandle {
    async fn snapshot(&self) -> SpecDraft {
        self.0.lock().await.clone()
    }
}

#[derive(Debug, Clone, Copy, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
enum SpecStage {
    Setup,
    PreAttack,
    PostAttack,
}

impl SpecStage {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Setup => "setup",
            Self::PreAttack => "pre_attack",
            Self::PostAttack => "post_attack",
        }
    }
}

fn stage_field_mut(draft: &mut SpecDraft, stage: SpecStage) -> &mut AuditStateSpecification {
    match stage {
        SpecStage::Setup => &mut draft.setup,
        SpecStage::PreAttack => &mut draft.pre_attack,
        SpecStage::PostAttack => &mut draft.post_attack,
    }
}

// ---- update_state_description ----

#[derive(Debug, Clone, Deserialize, JsonSchema)]
struct UpdateStateDescriptionArgs {
    /// One of `setup`, `pre_attack`, `post_attack`.
    stage: SpecStage,
    /// Free-form description of the general business logic governing this stage.
    description: String,
}

#[derive(Debug, Clone)]
#[llmy::agent::tool(
    arguments = UpdateStateDescriptionArgs,
    invoke = invoke,
    name = "update_state_description",
    description = "Set or replace the general-business-logic description of one stage of the current spec draft (setup / pre_attack / post_attack). Each stage holds exactly one description string. When stage=post_attack the description MUST follow the three-part contract from the system prompt: (1) cite a project file:contract.function whose comments or invariants establish the promised state, (2) name the concrete attacked state, (3) state the concrete bad consequence (drain / loss / DoS / bypass). post_attack descriptions that look like documented intended behavior, that are vague (\"may be inconsistent\"), or that omit the consequence clause are rejected by commit_specification.",
)]
struct UpdateStateDescriptionTool {
    draft: DraftHandle,
}

impl UpdateStateDescriptionTool {
    async fn invoke(
        &self,
        args: UpdateStateDescriptionArgs,
    ) -> std::result::Result<String, llmy::agent::LLMYError> {
        let mut guard = self.draft.0.lock().await;
        let stage_label = args.stage.as_str();
        let field = stage_field_mut(&mut guard, args.stage);
        field.description = args.description.trim().to_string();
        Ok(format!(
            "ok: updated {stage_label} description ({} chars). Draft: {}",
            field.description.len(),
            guard.draft_summary()
        ))
    }
}

// ---- add_state_variable_constraint ----

#[derive(Debug, Clone, Deserialize, JsonSchema)]
struct AddStateVariableConstraintArgs {
    stage: SpecStage,
    /// Identifier for the state variable. Prefer `Contract.fieldName` form
    /// when the same name lives on multiple contracts.
    key: String,
    /// Constraint text: either a value, an invariant, or "must be initialized".
    constraint: String,
}

#[derive(Debug, Clone)]
#[llmy::agent::tool(
    arguments = AddStateVariableConstraintArgs,
    invoke = invoke,
    name = "add_state_variable_constraint",
    description = "Insert or overwrite one state-variable constraint on the current draft's stage. Use `Contract.fieldName` keys when names collide across contracts.",
)]
struct AddStateVariableConstraintTool {
    draft: DraftHandle,
}

impl AddStateVariableConstraintTool {
    async fn invoke(
        &self,
        args: AddStateVariableConstraintArgs,
    ) -> std::result::Result<String, llmy::agent::LLMYError> {
        let mut guard = self.draft.0.lock().await;
        let stage_label = args.stage.as_str();
        let field = stage_field_mut(&mut guard, args.stage);
        field.states_variables.insert(
            args.key.trim().to_string(),
            args.constraint.trim().to_string(),
        );
        Ok(format!(
            "ok: {stage_label} state-variable constraints now {}. Draft: {}",
            field.states_variables.len(),
            guard.draft_summary()
        ))
    }
}

// ---- add_contract_constraint ----

#[derive(Debug, Clone, Deserialize, JsonSchema)]
struct AddContractConstraintArgs {
    stage: SpecStage,
    /// Contract name (or logical role, e.g. "AdminTimelock").
    contract: String,
    /// Constraint text: e.g. "must be deployed and own >0 of TokenA", "admin
    /// is the test EOA".
    constraint: String,
}

#[derive(Debug, Clone)]
#[llmy::agent::tool(
    arguments = AddContractConstraintArgs,
    invoke = invoke,
    name = "add_contract_constraint",
    description = "Insert or overwrite one contract-level constraint on the current draft's stage (e.g. deployment, role assignment).",
)]
struct AddContractConstraintTool {
    draft: DraftHandle,
}

impl AddContractConstraintTool {
    async fn invoke(
        &self,
        args: AddContractConstraintArgs,
    ) -> std::result::Result<String, llmy::agent::LLMYError> {
        let mut guard = self.draft.0.lock().await;
        let stage_label = args.stage.as_str();
        let field = stage_field_mut(&mut guard, args.stage);
        field.contracts.insert(
            args.contract.trim().to_string(),
            args.constraint.trim().to_string(),
        );
        Ok(format!(
            "ok: {stage_label} contract constraints now {}. Draft: {}",
            field.contracts.len(),
            guard.draft_summary()
        ))
    }
}

// ---- set_call_sequence ----

#[derive(Debug, Clone, Deserialize, JsonSchema)]
struct CallStepArg {
    /// Contract whose function is being called.
    contract: String,
    /// Function name (no parameter list).
    function: String,
    /// One-sentence intention of the call in this scenario.
    intention: String,
}

#[derive(Debug, Clone, Deserialize, JsonSchema)]
struct SetCallSequenceArgs {
    /// Replaces the entire call sequence on the current draft.
    steps: Vec<CallStepArg>,
}

#[derive(Debug, Clone)]
#[llmy::agent::tool(
    arguments = SetCallSequenceArgs,
    invoke = invoke,
    name = "set_call_sequence",
    description = "Replace the current draft's core call sequence with the provided ordered list of (contract, function, intention) steps.",
)]
struct SetCallSequenceTool {
    draft: DraftHandle,
}

impl SetCallSequenceTool {
    async fn invoke(
        &self,
        args: SetCallSequenceArgs,
    ) -> std::result::Result<String, llmy::agent::LLMYError> {
        if args.steps.is_empty() {
            return Ok("error: refusing to set an empty call sequence; commit_specification needs at least one core call".to_string());
        }
        let mut guard = self.draft.0.lock().await;
        guard.sequence = args
            .steps
            .into_iter()
            .map(|step| SuqenceCallStep {
                contract: step.contract.trim().to_string(),
                function: step.function.trim().to_string(),
                intention: step.intention.trim().to_string(),
            })
            .collect();
        Ok(format!(
            "ok: call sequence now {} step(s). Draft: {}",
            guard.sequence.len(),
            guard.draft_summary()
        ))
    }
}

// ---- commit_specification ----

#[derive(Debug, Clone, Deserialize, JsonSchema)]
struct CommitSpecificationArgs {
    /// Optional one-sentence note about what this spec covers, for the run log.
    #[serde(default)]
    note: Option<String>,
}

#[derive(Debug, Clone)]
#[llmy::agent::tool(
    arguments = CommitSpecificationArgs,
    invoke = invoke,
    name = "commit_specification",
    description = "Snapshot the current draft as one finalized AuditSpecification and reset the draft for the next one. Requires non-empty post_attack description and at least one call-sequence step.",
)]
struct CommitSpecificationTool {
    draft: DraftHandle,
    max_specs: usize,
}

impl CommitSpecificationTool {
    async fn invoke(
        &self,
        args: CommitSpecificationArgs,
    ) -> std::result::Result<String, llmy::agent::LLMYError> {
        let mut guard = self.draft.0.lock().await;
        if guard.completed.len() >= self.max_specs {
            return Ok(format!(
                "error: max_specs_per_link={} reached; call finalize next",
                self.max_specs
            ));
        }
        if guard.post_attack.description.is_empty() {
            return Ok(
                "error: post_attack.description is empty; specify what state proves the vulnerability before committing"
                    .to_string(),
            );
        }
        if let Err(reason) = check_post_attack_shape(&guard.post_attack.description) {
            return Ok(format!(
                "error: post_attack.description rejected: {reason} \
                 Re-read the system prompt's `post_attack.description contract` section: \
                 (1) cite project file:contract.function whose comments/invariants set the expected state, \
                 (2) name the concrete attacked state, \
                 (3) state the concrete bad consequence (drain/loss/DoS/bypass). \
                 Then call update_state_description(stage=\"post_attack\", ...) again with the revised text."
            ));
        }
        if guard.sequence.is_empty() {
            return Ok(
                "error: call sequence is empty; describe at least one core call before committing"
                    .to_string(),
            );
        }
        let spec = guard.build_spec();
        guard.completed.push(spec);
        guard.reset_draft();
        let note = args
            .note
            .as_deref()
            .map(|v| v.trim())
            .filter(|v| !v.is_empty())
            .map(|v| format!(" ({v})"))
            .unwrap_or_default();
        Ok(format!(
            "ok: committed spec #{} for this link{note}. Draft has been reset.",
            guard.completed.len()
        ))
    }
}

// ---- finalize ----

#[derive(Debug, Clone, Copy, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
enum FinalizeStatus {
    Completed,
    Abandoned,
}

#[derive(Debug, Clone, Deserialize, JsonSchema)]
struct FinalizeArgs {
    /// `completed` if at least one spec was committed; `abandoned` otherwise.
    status: FinalizeStatus,
    /// Free-form summary of what you produced or why you abandoned. Required.
    summary: String,
    /// When abandoned, a one-sentence reason (e.g. "project has no AMM
    /// pool — historical pattern doesn't apply").
    #[serde(default)]
    abort_reason: Option<String>,
}

#[derive(Debug, Clone)]
#[llmy::agent::tool(
    arguments = FinalizeArgs,
    invoke = invoke,
    name = "finalize",
    description = "End the spec-generation run for this link. Use `completed` when at least one spec has been committed; otherwise `abandoned`. Once called, no further tool calls are honoured.",
)]
struct FinalizeTool {
    draft: DraftHandle,
}

impl FinalizeTool {
    async fn invoke(
        &self,
        args: FinalizeArgs,
    ) -> std::result::Result<String, llmy::agent::LLMYError> {
        let mut guard = self.draft.0.lock().await;
        let status = match args.status {
            FinalizeStatus::Completed => {
                if guard.completed.is_empty() {
                    return Ok(
                        "error: cannot finalize as completed without at least one committed spec; use status=abandoned"
                            .to_string(),
                    );
                }
                LinkSpecStatus::Built
            }
            FinalizeStatus::Abandoned => LinkSpecStatus::Abandoned,
        };
        guard.final_status = Some(status);
        guard.final_summary = Some(args.summary);
        guard.abort_reason = args.abort_reason.or_else(|| {
            if status == LinkSpecStatus::Abandoned {
                Some("agent abandoned without explicit reason".to_string())
            } else {
                None
            }
        });
        Ok(format!(
            "ok: finalized as {} with {} committed spec(s). Stop now.",
            match status {
                LinkSpecStatus::Built => "completed",
                LinkSpecStatus::Abandoned => "abandoned",
            },
            guard.completed.len()
        ))
    }
}

// ---- lookup_call_graph ----

#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub(crate) struct LookupCallGraphArgs {
    /// Contract or interface name (case-insensitive). Required.
    contract: String,
    /// Optional function name to focus on. When omitted, all functions of
    /// the contract are listed (no edges).
    #[serde(default)]
    function: Option<String>,
}

#[derive(Debug, Clone)]
#[llmy::agent::tool(
    arguments = LookupCallGraphArgs,
    invoke = invoke,
    name = "lookup_call_graph",
    description = "Return the call-graph context for a contract or function: outgoing edges, incoming edges, and source content. Pass just the contract to enumerate its functions; pass contract+function for full edge listing.",
)]
pub(crate) struct LookupCallGraphTool {
    pub(crate) project: Arc<ProjectIndex>,
}

impl LookupCallGraphTool {
    async fn invoke(
        &self,
        args: LookupCallGraphArgs,
    ) -> std::result::Result<String, llmy::agent::LLMYError> {
        let contract_ids = self.project.lookup_contract(&args.contract);
        let interface_ids = self.project.lookup_interface(&args.contract);
        if contract_ids.is_empty() && interface_ids.is_empty() {
            return Ok(format!(
                "no contract or interface named `{}` found in this project",
                args.contract
            ));
        }
        let mut out = String::new();
        for id in contract_ids {
            if let Some(contract) = self.project.contract(id) {
                out.push_str(&render_contract_lookup(
                    contract,
                    args.function.as_deref(),
                    &self.project,
                ));
                out.push_str("\n---\n");
            }
        }
        for id in interface_ids {
            if let Some(interface) = self.project.interface(id) {
                out.push_str(&render_interface_lookup(
                    interface,
                    args.function.as_deref(),
                ));
                out.push_str("\n---\n");
            }
        }
        Ok(out)
    }
}

pub(crate) fn render_contract_lookup(
    contract: &Contract,
    focus_function: Option<&str>,
    project: &ProjectIndex,
) -> String {
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
                    describe_endpoint(call.to_id, project, call)
                ));
            }
        }
        out.push_str("\nincoming calls:\n");
        let mut incoming: Vec<&FunctionCall> = Vec::new();
        for c in project.call_graph.contracts.values() {
            for f in &c.functions {
                for call in &f.calls {
                    if call.to_id == function.id {
                        incoming.push(call);
                    }
                }
            }
        }
        for i in project.call_graph.interfaces.values() {
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
                    describe_endpoint(call.from_id, project, call)
                ));
            }
        }
    }

    out
}

pub(crate) fn render_interface_lookup(
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

pub(crate) fn describe_endpoint(
    function_id: i32,
    project: &ProjectIndex,
    call: &FunctionCall,
) -> String {
    let owner = project.function_owner.get(&function_id);
    let function_name = owner
        .and_then(|owner| match owner.container_kind {
            ContainerKind::Contract => project
                .contract(owner.container_id)
                .and_then(|c| c.functions.iter().find(|f| f.id == function_id))
                .map(|f| format!("{}({})", f.name, f.args)),
            ContainerKind::Interface => project
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

// ---- read_contract_source ----

#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub(crate) struct ReadContractSourceArgs {
    /// Contract or interface name (case-insensitive).
    contract: String,
}

#[derive(Debug, Clone)]
#[llmy::agent::tool(
    arguments = ReadContractSourceArgs,
    invoke = invoke,
    name = "read_contract_source",
    description = "Return the full source text of a contract or interface. Expensive — prefer `read_function_source` for a single function body when you only need to inspect one function. Use this when you need surrounding file context (modifiers, imports, struct layouts).",
)]
pub(crate) struct ReadContractSourceTool {
    pub(crate) project: Arc<ProjectIndex>,
}

impl ReadContractSourceTool {
    async fn invoke(
        &self,
        args: ReadContractSourceArgs,
    ) -> std::result::Result<String, llmy::agent::LLMYError> {
        let contract_ids = self.project.lookup_contract(&args.contract);
        let interface_ids = self.project.lookup_interface(&args.contract);
        if contract_ids.is_empty() && interface_ids.is_empty() {
            return Ok(format!(
                "no contract or interface named `{}` found in this project",
                args.contract
            ));
        }
        let mut out = String::new();
        for id in contract_ids {
            if let Some(contract) = self.project.contract(id) {
                out.push_str(&format!(
                    "## contract `{}` @ `{}` (id={})\n```solidity\n{}\n```\n---\n",
                    contract.name,
                    contract.relative_file_path.display(),
                    contract.id,
                    contract.chunk.content.trim_end(),
                ));
            }
        }
        for id in interface_ids {
            if let Some(interface) = self.project.interface(id) {
                out.push_str(&format!(
                    "## interface `{}` @ `{}` (id={})\n```solidity\n{}\n```\n---\n",
                    interface.name,
                    interface.relative_file_path.display(),
                    interface.id,
                    interface.chunk.content.trim_end(),
                ));
            }
        }
        Ok(out)
    }
}

// ---- read_function_source ----

#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub(crate) struct ReadFunctionSourceArgs {
    /// Contract or interface name (case-insensitive).
    contract: String,
    /// Function name (case-insensitive). For overloads, all matching bodies are returned.
    function: String,
}

#[derive(Debug, Clone)]
#[llmy::agent::tool(
    arguments = ReadFunctionSourceArgs,
    invoke = invoke,
    name = "read_function_source",
    description = "Return the source text of a single function (preferred over `read_contract_source` for body inspection). Returns all overloads matching the name within the contract. For interfaces this returns the declaration line.",
)]
pub(crate) struct ReadFunctionSourceTool {
    pub(crate) project: Arc<ProjectIndex>,
}

impl ReadFunctionSourceTool {
    async fn invoke(
        &self,
        args: ReadFunctionSourceArgs,
    ) -> std::result::Result<String, llmy::agent::LLMYError> {
        let target = args.function.to_lowercase();
        let mut out = String::new();
        let mut found = false;

        for cid in self.project.lookup_contract(&args.contract) {
            if let Some(contract) = self.project.contract(cid) {
                for f in contract
                    .functions
                    .iter()
                    .filter(|f| f.name.to_lowercase() == target)
                {
                    found = true;
                    out.push_str(&format!(
                        "## `{}::{}({})` @ {}:{} (id={})\n",
                        contract.name,
                        f.name,
                        f.args,
                        f.relative_file_path.display(),
                        f.loc.start_line,
                        f.id,
                    ));
                    if let Some(body) = &f.content {
                        out.push_str("```solidity\n");
                        out.push_str(body.trim_end());
                        out.push_str("\n```\n");
                    } else {
                        out.push_str("(no body — this function has no recorded source)\n");
                    }
                    if !f.calls.is_empty() {
                        out.push_str("outgoing calls:\n");
                        for call in &f.calls {
                            out.push_str(&format!(
                                "- -> {}\n",
                                describe_endpoint(call.to_id, &self.project, call)
                            ));
                        }
                    }
                    out.push_str("---\n");
                }
            }
        }
        for iid in self.project.lookup_interface(&args.contract) {
            if let Some(interface) = self.project.interface(iid) {
                for f in interface
                    .functions
                    .iter()
                    .filter(|f| f.name.to_lowercase() == target)
                {
                    found = true;
                    out.push_str(&format!(
                        "## (interface) `{}::{}({})` @ {}:{} (id={})\n(declaration only)\n---\n",
                        interface.name,
                        f.name,
                        f.args,
                        f.relative_file_path.display(),
                        f.loc.start_line,
                        f.id,
                    ));
                }
            }
        }

        if !found {
            return Ok(format!(
                "no function named `{}` in contract or interface `{}`. Use `read_memory` to see available signatures.",
                args.function, args.contract
            ));
        }
        Ok(out)
    }
}

// ---- lookup_state_variable_xrefs ----

#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub(crate) struct LookupStateVariableXrefsArgs {
    /// State-variable name (case-insensitive).
    state_variable: String,
    /// Optional contract scope (case-insensitive). When provided, only
    /// matches declared in or visible to this contract are returned.
    #[serde(default)]
    contract: Option<String>,
}

#[derive(Debug, Clone)]
#[llmy::agent::tool(
    arguments = LookupStateVariableXrefsArgs,
    invoke = invoke,
    name = "lookup_state_variable_xrefs",
    description = "Return cross-references for a state variable: declaring contract, all functions reading it, all functions writing it. Optionally constrain the search to a single contract scope.",
)]
pub(crate) struct LookupStateVariableXrefsTool {
    pub(crate) project: Arc<ProjectIndex>,
}

impl LookupStateVariableXrefsTool {
    async fn invoke(
        &self,
        args: LookupStateVariableXrefsArgs,
    ) -> std::result::Result<String, llmy::agent::LLMYError> {
        let candidate_ids = self.project.lookup_state_var(&args.state_variable);
        if candidate_ids.is_empty() {
            return Ok(format!(
                "no state variable named `{}` found in this project",
                args.state_variable
            ));
        }
        let scope_contract_ids: Option<Vec<i32>> = args
            .contract
            .as_deref()
            .map(|name| self.project.lookup_contract(name));

        let mut out = String::new();
        for var_id in &candidate_ids {
            let Some(var) = self.project.state_variable(*var_id) else {
                continue;
            };
            let declaring_contract_id =
                self.project.declaring_contract_for_var.get(var_id).copied();
            // Apply scope filter: keep only when scope contract sees this var.
            if let Some(scope_ids) = &scope_contract_ids {
                let visible = scope_ids.iter().any(|cid| {
                    self.project
                        .visible_state_vars
                        .get(cid)
                        .map(|s| s.contains(var_id))
                        .unwrap_or(false)
                });
                if !visible {
                    continue;
                }
            }
            let declaring_contract_name = declaring_contract_id
                .and_then(|id| self.project.contract(id))
                .map(|c| c.name.as_str())
                .unwrap_or("?");
            out.push_str(&format!(
                "## {} {} (id={}) declared in `{}` @ {}:{}\n",
                var.type_name.trim(),
                var.name,
                var.id,
                declaring_contract_name,
                var.relative_file_path.display(),
                var.loc.start_line
            ));

            let xrefs: Vec<&FunctionStateVariable> = self
                .project
                .storage_graph
                .function_state_variables
                .iter()
                .filter(|fsv| fsv.state_variable_id == var.id)
                .collect();

            let (writes, reads): (Vec<&&FunctionStateVariable>, Vec<&&FunctionStateVariable>) =
                xrefs.iter().partition(|fsv| fsv.is_write);
            out.push_str(&format!(
                "writers ({}) and readers ({})\n",
                writes.len(),
                reads.len()
            ));
            if !writes.is_empty() {
                out.push_str("\nwriters:\n");
                for fsv in writes {
                    out.push_str(&format!(
                        "- {}\n",
                        describe_function_xref(
                            fsv.function_id,
                            &self.project,
                            fsv.description.as_deref()
                        )
                    ));
                }
            }
            if !reads.is_empty() {
                out.push_str("\nreaders:\n");
                for fsv in reads {
                    out.push_str(&format!(
                        "- {}\n",
                        describe_function_xref(
                            fsv.function_id,
                            &self.project,
                            fsv.description.as_deref()
                        )
                    ));
                }
            }
            out.push_str("\n---\n");
        }
        if out.is_empty() {
            return Ok(format!(
                "no state variable named `{}` matches the given contract scope",
                args.state_variable
            ));
        }
        Ok(out)
    }
}

pub(crate) fn describe_function_xref(
    function_id: i32,
    project: &ProjectIndex,
    description: Option<&str>,
) -> String {
    let endpoint = match project.function_owner.get(&function_id) {
        Some(owner) => {
            let function_label = match owner.container_kind {
                ContainerKind::Contract => project
                    .contract(owner.container_id)
                    .and_then(|c| c.functions.iter().find(|f| f.id == function_id))
                    .map(|f| format!("{}({})", f.name, f.args)),
                ContainerKind::Interface => project
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

// ---------------------------------------------------------------------------
// Serializable wire forms (used by the CLI)
// ---------------------------------------------------------------------------

/// Serializable summary the CLI dumps to JSON / md.
#[derive(Debug, Clone, Serialize)]
pub struct LinkSpecSummary {
    pub extract_id: i32,
    pub historical_id: i32,
    pub finding_id: i32,
    pub status: &'static str,
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
            status: match outcome.status {
                LinkSpecStatus::Built => "built",
                LinkSpecStatus::Abandoned => "abandoned",
            },
            specifications: outcome.specifications.clone(),
            abort_reason: outcome.abort_reason.clone(),
            final_summary: outcome.final_summary.clone(),
            steps: outcome.steps,
            compact_count: outcome.compact_count,
        }
    }
}
