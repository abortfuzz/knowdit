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

use std::collections::{BTreeMap, VecDeque};
use std::sync::Arc;

use color_eyre::eyre::{Result, WrapErr};
use itertools::Itertools;
use knowdit_kg_model::ExtractedSemantic;
use knowdit_repo_model::{
    HistoricalSemanticRecord, RepoDatabase, SemanticMatchSet, repo::SpecificationRecord,
};
use llmy::agent::{LLMYError, StepResult};
use llmy::client::client::LLM;
use llmy::client::rust_decimal::Decimal;
use llmy::client::settings::LLMSettings;
use llmy::harness::memory::AgentMemorySystemPromptCriteria;
use llmy::harness::{Agent, AgentConfig};
use serde::Serialize;
use tokio::sync::Mutex;

use crate::types::AuditSpecification;

mod backend;
mod index;
mod prompt;
mod tools;
pub use backend::SpecBackend;
pub use index::ProjectIndex;
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
// Billing-cap exhaustion
// ---------------------------------------------------------------------------

/// Details of a billing-cap exhaustion ([`LLMYError::Billing`]) lifted out of
/// an eyre error chain. A billing exhaustion is **run-fatal**, not a per-link
/// failure: `llmy` fails fast on the pre-flight `check_cap` before every
/// request, so once the cap is hit *every* later LLM call fails the same way.
/// Orchestrators surface this (which cap, how much spent) and abort the whole
/// run instead of silently abandoning the rest of the queue one wasted link at
/// a time.
#[derive(Debug, Clone, Serialize)]
pub struct BillingExhausted {
    pub cap: Decimal,
    pub current: Decimal,
    /// Name of the scope whose cap was exceeded, if it had one.
    pub scope: Option<String>,
    /// Billing-tree node id whose cap was exceeded (0 = root).
    pub node: u64,
}

/// If `err`'s cause chain contains an [`LLMYError::Billing`], return its
/// details. Walks the full chain because [`PlannedLinkWork::run_agent`] / the graders
/// `wrap_err` the raw `LLMYError` into an eyre report before it reaches a caller.
pub fn billing_exhaustion(err: &color_eyre::eyre::Report) -> Option<BillingExhausted> {
    err.chain()
        .find_map(|cause| match cause.downcast_ref::<LLMYError>() {
            Some(LLMYError::Billing {
                cap,
                current,
                node,
                scope,
            }) => Some(BillingExhausted {
                cap: *cap,
                current: *current,
                scope: scope.clone(),
                node: *node,
            }),
            _ => None,
        })
}

/// Convenience predicate over [`billing_exhaustion`].
pub fn is_billing_exhausted(err: &color_eyre::eyre::Report) -> bool {
    billing_exhaustion(err).is_some()
}

// ---------------------------------------------------------------------------
// Public configuration / output types
// ---------------------------------------------------------------------------

/// Where a link's finding originated — controls how the gen-spec agent frames
/// it. A run is uniformly one source (set on [`SpecGenOptions`]), so this is
/// run-level config, not per-link.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LinkSource {
    /// Discovered by the Knowledge Mapper from the historical KG: the finding is
    /// a *topic hint* to explore for related issues.
    #[default]
    Mapper,
    /// Supplied externally (e.g. `workflow external-validate`): the finding is a
    /// concrete reported issue to reproduce / validate, not a hint.
    External,
}

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
    /// Number of [`PlannedLinkWork::run_agent`] agent runs allowed in flight at once. `1` runs
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
    /// Whether the links come from the Knowledge Mapper (topic hints) or are
    /// externally-supplied reported findings to validate. Frames the gen-spec
    /// agent's system prompt; see [`LinkSource`].
    pub link_source: LinkSource,
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
            link_source: LinkSource::Mapper,
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
    /// Populated by [`LinkSpecOutcome::commit`]; empty on commit failure or when
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

impl LinkSpecOutcome {
    /// Persist `self.specifications` to the project DB's `specification` table
    /// and record the assigned row ids in `self.specification_ids`. A no-op
    /// (leaving `specification_ids` empty) when there are no specs, or on a
    /// serialize / append failure (logged, not fatal — a commit failure for one
    /// link shouldn't abort the run).
    pub async fn commit(&mut self, repo: &RepoDatabase) {
        if self.specifications.is_empty() {
            return;
        }
        let mut payload = Vec::with_capacity(self.specifications.len());
        for spec in &self.specifications {
            match serde_json::to_string(spec) {
                Ok(json) => payload.push(SpecificationRecord {
                    semantic_id: self.extract_id,
                    historical_id: self.historical_id,
                    finding_id: self.finding_id,
                    specification_json: json,
                }),
                Err(err) => {
                    tracing::error!(
                        "failed to JSON-serialize spec for extract={} finding={}: {err:#}",
                        self.extract_id,
                        self.finding_id
                    );
                    return;
                }
            }
        }
        match repo.append_specifications(&payload).await {
            Ok(ids) => self.specification_ids = ids,
            Err(err) => {
                tracing::error!(
                    "failed to append {} spec(s) for extract={} finding={}: {err:#}",
                    payload.len(),
                    self.extract_id,
                    self.finding_id,
                );
            }
        }
    }
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
    /// [`PlannedLinkWork::process`] needs, so the scheduler can run it on its own
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
}

/// One claimed link ready to be run by an external scheduler. Carries
/// everything [`PlannedLinkWork::process`] needs (the link itself plus a cheap
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
    ///
    /// Returns `Err` only on a billing-cap exhaustion (run-fatal — see
    /// [`PlannedLinkWork::process`]); a per-link agent failure is folded into an
    /// `Abandoned` outcome so the scheduler keeps going.
    pub async fn run(self, repo: &RepoDatabase, llm: &LLM) -> Result<LinkSpecOutcome> {
        if !self.link.pre_committed_spec_ids.is_empty() {
            tracing::info!(
                "Spec generator skipping gen-spec for resumed link={} (total = {}) {} — {} pre-committed spec(s)",
                self.ordinal,
                self.total_links,
                self.link,
                self.link.pre_committed_spec_ids.len(),
            );
            return Ok(LinkSpecOutcome {
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
            });
        }
        let mut outcome = self.process(llm).await?;
        outcome.commit(repo).await;
        Ok(outcome)
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
            for (idx, link) in links.into_iter().enumerate() {
                let work = PlannedLinkWork {
                    ordinal: idx + 1,
                    total_links,
                    link,
                    project_index: project_index.clone(),
                    options: options.clone(),
                };
                let mut outcome = work.process(llm).await?;
                outcome.commit(repo).await;
                outcomes.push(outcome);
            }
            outcomes
        } else {
            tracing::info!("Specification Generator running with concurrency={concurrency}",);
            // Owned indexed inputs so workers can move them.
            let indexed: Vec<(usize, LinkInput)> = links.into_iter().enumerate().collect();
            let queue = Arc::new(Mutex::new(indexed.into_iter().rev().collect::<Vec<_>>()));
            let (tx, mut rx) =
                tokio::sync::mpsc::channel::<(usize, Result<LinkSpecOutcome>)>(concurrency * 2);

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
                        let work = PlannedLinkWork {
                            ordinal: idx + 1,
                            total_links,
                            link,
                            project_index: project_index.clone(),
                            options: options.clone(),
                        };
                        let outcome = work.process(&llm).await;
                        if tx.send((idx, outcome)).await.is_err() {
                            break;
                        }
                    }
                }));
            }
            drop(tx);

            let mut collected: Vec<Option<LinkSpecOutcome>> =
                (0..total_links).map(|_| None).collect();
            let mut billing_err: Option<color_eyre::eyre::Report> = None;
            while let Some((idx, outcome)) = rx.recv().await {
                // The only `Err` `process` yields is a billing-cap exhaustion,
                // which is run-fatal: stop collecting and propagate so the run
                // aborts instead of churning the rest of the queue against a
                // dead cap.
                let mut outcome = match outcome {
                    Ok(outcome) => outcome,
                    Err(err) => {
                        billing_err = Some(err);
                        break;
                    }
                };
                // Commit on the main task so all writes go through one DB
                // handle in serialized order; SQLite handles small txns well.
                outcome.commit(repo).await;
                if idx < collected.len() {
                    collected[idx] = Some(outcome);
                }
            }
            if let Some(err) = billing_err {
                return Err(err);
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
        // Persistence already happened incrementally via `LinkSpecOutcome::commit`.
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
        Ok(Self::plan_links(repo, options)
            .await?
            .map(|p| PlannedLinkInputs {
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
        // Wrap the single regen link in a `PlannedLinkWork` so it goes through
        // the same agent loop as the streaming path. `total_links = 1` and the
        // ordinal is the cache-key serial (a regen, not a stream position).
        let work = PlannedLinkWork {
            ordinal: request.serial_for_cache_key,
            total_links: 1,
            link,
            project_index: runtime.project_index.clone(),
            options: options.clone(),
        };
        let outcome = work.run_agent(llm, Some(&prompt_extension)).await?;
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

// ---------------------------------------------------------------------------
// Per-link agent runner
// ---------------------------------------------------------------------------

const DEFAULT_COMPACT_RATIO: f64 = 0.8;

/// The per-link gen-spec agent loop, owned by [`PlannedLinkWork`] — the struct
/// that already carries the link plus everything needed to run it (its grounding
/// [`ProjectIndex`] and [`SpecGenOptions`]). The `llm` and the optional regen
/// `prompt_extension` are the only per-call inputs.
impl PlannedLinkWork {
    /// Drive the gen-spec agent for this link to completion. Propagates step
    /// errors (including [`LLMYError::Billing`]) via `?`. When `prompt_extension`
    /// is `Some`, this run is a spec regen and the supplied feedback section is
    /// appended to the agent's system prompt verbatim (this method doesn't
    /// format it — that's the regen caller's job).
    pub(crate) async fn run_agent(
        &self,
        llm: &LLM,
        prompt_extension: Option<&str>,
    ) -> Result<LinkSpecOutcome> {
        let link = &self.link;
        let project_index = &self.project_index;
        let options = &self.options;
        let link_serial = self.ordinal;
        let memory = project_index.build_link_memory()?;
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

        let mut system_prompt = build_system_prompt(link, options.link_source);
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

        let compact_threshold = options.compact_context_threshold_tokens.unwrap_or_else(|| {
            (llm.model.config.max_input() as f64 * DEFAULT_COMPACT_RATIO) as usize
        });

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

    /// [`Self::run_agent`] + logging + error classification. A per-link agent
    /// failure becomes an `Abandoned` outcome (`Ok`) so the scheduler keeps
    /// going; only a **billing-cap exhaustion** returns `Err`, signalling the
    /// caller to abort the whole run rather than burn the rest of the queue
    /// against an already-dead cap (see [`is_billing_exhausted`]).
    pub(crate) async fn process(&self, llm: &LLM) -> Result<LinkSpecOutcome> {
        let link = &self.link;
        let link_idx_1based = self.ordinal;
        let total_links = self.total_links;
        let label = format!(
            "link={} (total = {}) {}",
            link_idx_1based, total_links, link
        );
        tracing::info!("Spec generator starting {label}");
        match self.run_agent(llm, None).await {
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
                Ok(outcome)
            }
            // Billing-cap exhaustion is run-fatal, not a per-link failure: every
            // later LLM call hits the same dead cap. Propagate so the
            // orchestrator aborts instead of abandoning the rest of the queue.
            Err(err) if is_billing_exhausted(&err) => Err(err),
            Err(err) => {
                tracing::error!(
                    "{label}: agent run failed, abandoning link without committing — {err:#}"
                );
                Ok(LinkSpecOutcome {
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
                })
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Memory construction
// ---------------------------------------------------------------------------

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
