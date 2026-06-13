use crate::agent_runner::{AgentChunkBuffer, AgentChunkRunner, AgentRunOptions};
use crate::agents::FinalizeArgs;
use crate::category::DeFiCategory;
use crate::db::HistoricalDatabase;
use crate::error::{KgError, Result};
use crate::learn::{ExtractedFinding, count_tokens, get_context_budget, sanitize_prompt_prefix};
use crate::prompts;
use itertools::Itertools;
use llmy::agent::tool::ToolBox;
use llmy::agent::{LLMYError, tool};
use llmy::client::client::LLM;
use llmy::client::model::OpenAIModel;
use schemars::JsonSchema;
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::sync::Arc;

/// One per-finding decision emitted by the link agent. Doubles as the
/// `emit_finding_link_decision` tool's `ARGUMENTS` shape — no duplicate
/// "Args" mirror. Field order keeps `reasoning` first to nudge the agent
/// into chain-of-thought before the evidence list.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct FindingLinkDecision {
    /// Brief explanation of why these semantics are related (or why none
    /// were chosen).
    pub reasoning: String,
    /// `finding-N` id taken from the prompt's "Findings To Link" section.
    /// Must be one of the IDs the prompt listed; otherwise the tool
    /// rejects the call so the agent can retry.
    pub finding_id: String,
    /// Per-link evidence. Empty list = "no link" — that's a valid decision;
    /// the tool still records it so the orchestrator counts the finding as
    /// covered. Each entry must reference a `Candidate ID` from the
    /// prompt's candidate list AND articulate concretely why this finding's
    /// bug pattern can fire on that semantic.
    pub semantic_evidence: Vec<LinkEvidence>,
}

/// Concrete evidence justifying one finding↔semantic link.
///
/// Under the v2 "forced per-candidate emit" contract (plan_link.md §6.1),
/// the agent must emit one LinkEvidence per candidate semantic shown,
/// each tagged with a `strength` label from `{High, Medium, Low}`.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct LinkEvidence {
    /// `Candidate ID` (e.g. `sem-12`) from the prompt's "Candidate
    /// Semantics" section.
    pub semantic_id: String,
    /// Strength tier for this link, drawn from {`High`, `Medium`, `Low`}.
    /// Parsed via `LinkStrength::parse`; unknown values are rejected by
    /// the tool handler so the agent can retry. Per-tier evidence length
    /// floors: High/Medium >= 40 chars, Low >= 15 chars.
    pub strength: String,
    /// One- or two-sentence concrete justification: cite a specific
    /// behaviour from the semantic's description (state mutation, call
    /// ordering, external boundary, invariant) that matches the finding's
    /// pattern/exploit prerequisites. Generic theme overlap ("both involve
    /// deposit") is not sufficient — name the specific shared behaviour.
    pub why_finding_can_fire: String,
}

#[derive(Debug, Clone)]
pub struct PendingFindingForLinking {
    pub finding_id: i32,
    pub link_target_finding_id: i32,
    pub categories: Vec<DeFiCategory>,
    pub finding: ExtractedFinding,
}

/// One link decision the link agent produced for one (finding, semantic)
/// edge. Carries strength + evidence so it can be persisted into
/// `semantic_finding_link.{strength,evidence}` directly.
#[derive(Debug, Clone)]
pub struct PersistedSemanticLink {
    pub semantic_id: i32,
    pub strength: knowdit_kg_model::link_strength::LinkStrength,
    pub evidence: String,
}

#[derive(Debug, Clone)]
pub struct PersistedFindingLinkResult {
    pub finding_id: i32,
    pub link_target_finding_id: i32,
    pub semantic_links: Vec<PersistedSemanticLink>,
}

#[derive(Debug, Clone, Copy)]
pub struct FindingLinkOptions {
    pub concurrency: usize,
    pub input_token_budget: Option<usize>,
    pub finding_token_budget: Option<usize>,
    /// Hard ceiling on findings per batch — independent of token
    /// budget. The token-based partitioner would happily pack 400+
    /// findings into a single batch on small-finding KGs (e.g. the
    /// Move KG: ~150 tok/finding × 459 findings ≈ 70K tok, fits
    /// in one 72K budget), but agents in practice can only stably
    /// emit decisions for a few dozen findings per attempt before
    /// finalizing prematurely. Cap both ways: token budget AND
    /// finding count. `None` ⇒ uses [`DEFAULT_MAX_FINDINGS_PER_BATCH`].
    pub max_findings_per_batch: Option<usize>,
    /// Max attempts per (finding-batch × semantic-chunk) — if the agent
    /// finalizes without covering every finding in the batch, the runner
    /// re-runs a fresh agent restricted to the still-missing findings.
    /// After this many attempts the missing findings are treated as
    /// `no-link` and a warning is logged.
    pub max_response_attempts: usize,
    /// Per-attempt cap on agent steps (inner step loop, not the
    /// missing-coverage retry counter).
    pub max_agent_steps: usize,
    pub include_unlinked: bool,
}

#[derive(Debug, Clone)]
struct SemanticLinkCandidate {
    candidate_id: String,
    canonical_semantic_id: i32,
    is_canonical: bool,
    category: DeFiCategory,
    name: String,
    definition: String,
    description: String,
}

#[derive(Debug, Clone)]
struct FindingLinkContext {
    prompt_prefix: String,
    prompt_prefix_tokens: usize,
    candidate_token_count: usize,
    candidate_map: HashMap<String, i32>,
    cache_key: String,
}

#[derive(Debug, Clone)]
struct FindingLinkCandidateEntry {
    candidate_id: String,
    canonical_semantic_id: i32,
    is_canonical: bool,
    category: DeFiCategory,
    name: String,
    prompt_body: String,
    token_count: usize,
}

/// A semantic chunking unit built around one canonical semantic and every
/// merged alias that resolves to it.
///
/// `FindingLinkCandidateEntry` is the prompt-level unit that gets rendered into
/// the candidate list. `FindingLinkCandidateGroup` is one level above that: it
/// keeps the canonical entry and all of its aliases together so chunking never
/// splits an alias away from the canonical target the model must return.
#[derive(Debug, Clone)]
struct FindingLinkCandidateGroup {
    canonical_semantic_id: i32,
    category: DeFiCategory,
    name: String,
    entries: Vec<FindingLinkCandidateEntry>,
    token_count: usize,
}

#[derive(Debug, Clone)]
struct FindingLinkBatchEntry {
    pending: PendingFindingForLinking,
    prompt_finding_id: String,
    prompt_body: String,
    token_count: usize,
}

#[derive(Debug, Clone)]
struct FindingLinkBatch {
    context_key: FindingLinkContextKey,
    entries: Vec<FindingLinkBatchEntry>,
    finding_token_count: usize,
    finding_token_budget: usize,
    input_token_budget: usize,
}

impl std::fmt::Display for FindingLinkBatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}:{}",
            self.context_key.label(),
            finding_link_batch_entry_span(&self.entries)
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct FindingLinkContextKey {
    categories: BTreeSet<DeFiCategory>,
    semantic_chunk_index: usize,
}

impl FindingLinkContextKey {
    fn empty() -> Self {
        Self {
            categories: BTreeSet::new(),
            semantic_chunk_index: 0,
        }
    }

    #[cfg(test)]
    fn for_category(category: DeFiCategory) -> Self {
        let mut categories = BTreeSet::new();
        categories.insert(category);
        Self {
            categories,
            semantic_chunk_index: 0,
        }
    }

    /// Linking is one-time. Cost is not the concern; we want the LLM to see
    /// every canonical semantic for every pending finding in one consistent
    /// pass, irrespective of the originating project's categories. The empty
    /// `categories` set is the marker that downstream code uses to switch
    /// into "all-canonical-semantics" candidate loading.
    fn from_project_categories(_categories: &[DeFiCategory]) -> Vec<Self> {
        vec![Self::empty()]
    }

    fn prompt_category(&self) -> Option<DeFiCategory> {
        self.categories.iter().next().copied()
    }

    fn with_semantic_chunk(&self, semantic_chunk_index: usize) -> Self {
        Self {
            categories: self.categories.clone(),
            semantic_chunk_index,
        }
    }

    fn cache_key(&self) -> String {
        format!("finding-link-{}", self.slug())
    }

    fn label(&self) -> String {
        self.slug()
    }

    fn slug(&self) -> String {
        // Always include `chunk-<n>` — even for the empty-categories
        // "all-canonical" pass, the semantic library is split into N
        // chunks and each becomes its own batch. Without the chunk
        // suffix all N parallel batches log identically and the user
        // can't tell which one is still running.
        let base = if self.categories.is_empty() {
            "none".to_string()
        } else {
            sanitize_prompt_prefix(
                &self
                    .categories
                    .iter()
                    .map(DeFiCategory::as_str)
                    .collect::<Vec<_>>()
                    .join("-"),
            )
        };

        format!("{}-chunk-{}", base, self.semantic_chunk_index)
    }
}

impl FindingLinkContext {
    fn build(
        model: &OpenAIModel,
        context_key: &FindingLinkContextKey,
        candidate_entries: Vec<FindingLinkCandidateEntry>,
    ) -> Self {
        let candidate_token_count = candidate_entries
            .iter()
            .map(|entry| entry.token_count)
            .sum();
        let candidate_text = candidate_entries
            .iter()
            .map(|entry| entry.prompt_body.as_str())
            .collect::<String>();
        let candidate_map = candidate_entries
            .into_iter()
            .map(|entry| (entry.candidate_id, entry.canonical_semantic_id))
            .collect();
        let prompt_prefix =
            prompts::finding_link_user_prefix(context_key.prompt_category(), &candidate_text);

        Self {
            prompt_prefix_tokens: count_tokens(model, &prompt_prefix),
            prompt_prefix,
            candidate_token_count,
            candidate_map,
            cache_key: context_key.cache_key(),
        }
    }
}

#[derive(Debug, Default)]
struct FindingLinkContextPlan {
    pending_by_context: BTreeMap<FindingLinkContextKey, Vec<PendingFindingForLinking>>,
}

impl FindingLinkContextPlan {
    fn from_pending_findings(pending_findings: Vec<PendingFindingForLinking>) -> Self {
        let mut plan = Self::default();

        for pending in pending_findings {
            for context_key in FindingLinkContextKey::from_project_categories(&pending.categories) {
                plan.pending_by_context
                    .entry(context_key)
                    .or_default()
                    .push(pending.clone());
            }
        }

        plan
    }

    async fn materialize(
        self,
        db: &HistoricalDatabase,
        model: &OpenAIModel,
        budgets: &FindingLinkBudgets,
    ) -> Result<FindingLinkExecutionPlan> {
        use std::sync::Arc;

        let mut contexts = BTreeMap::new();
        let mut expanded_pending = BTreeMap::new();
        let mut expected_context_counts = HashMap::new();

        for (base_context_key, pending_findings) in self.pending_by_context {
            let chunked_contexts =
                build_finding_link_contexts(db, model, &base_context_key, budgets).await?;
            let chunk_count = chunked_contexts.len();

            for pending in &pending_findings {
                expected_context_counts
                    .entry(pending.finding_id)
                    .and_modify(|count| *count += chunk_count)
                    .or_insert(chunk_count);
            }

            for (context_key, context) in chunked_contexts {
                contexts.insert(context_key.clone(), Arc::new(context));
                expanded_pending.insert(context_key, pending_findings.clone());
            }
        }

        let batches = build_finding_link_batches(model, expanded_pending, &contexts, budgets)?;

        Ok(FindingLinkExecutionPlan {
            contexts,
            batches,
            expected_context_counts,
        })
    }
}

#[derive(Debug)]
struct FindingLinkExecutionPlan {
    contexts: BTreeMap<FindingLinkContextKey, std::sync::Arc<FindingLinkContext>>,
    batches: Vec<FindingLinkBatch>,
    expected_context_counts: HashMap<i32, usize>,
}

impl FindingLinkExecutionPlan {
    fn expected_context_count(&self, finding_id: i32) -> usize {
        self.expected_context_counts
            .get(&finding_id)
            .copied()
            .unwrap_or(0)
    }

    fn task_count(&self) -> usize {
        self.batches.iter().map(|batch| batch.entries.len()).sum()
    }
}

/// Hard cap on findings per batch when [`FindingLinkOptions::max_findings_per_batch`]
/// isn't set. Empirically ~50 is what the post-step-cap-200 agent
/// handles reliably across both Move and Solidity KGs without
/// finalizing prematurely. Override with `--max-findings-per-batch`.
const DEFAULT_MAX_FINDINGS_PER_BATCH: usize = 50;

#[derive(Debug, Clone, Copy)]
struct FindingLinkBudgets {
    input_token_budget: usize,
    semantic_token_target: usize,
    finding_token_target: usize,
    /// Independent of token budget: hard cap on findings per batch.
    /// `partition_finding_link_entries` honours `min(token, count)`.
    max_findings_per_batch: usize,
}

impl FindingLinkBudgets {
    fn from_options(model: &OpenAIModel, options: FindingLinkOptions) -> Self {
        let max_input_budget = get_context_budget(model).max(1);
        let input_token_budget = options
            .input_token_budget
            .unwrap_or(max_input_budget)
            .min(max_input_budget)
            .max(1);
        let shared_target = (input_token_budget / 3).max(1);
        let finding_token_target = options
            .finding_token_budget
            .unwrap_or(shared_target)
            .min(shared_target)
            .max(1);
        let max_findings_per_batch = options
            .max_findings_per_batch
            .unwrap_or(DEFAULT_MAX_FINDINGS_PER_BATCH)
            .max(1);

        Self {
            input_token_budget,
            semantic_token_target: shared_target,
            finding_token_target,
            max_findings_per_batch,
        }
    }

    fn semantic_token_budget(
        &self,
        model: &OpenAIModel,
        prompt_category: Option<DeFiCategory>,
    ) -> Result<usize> {
        let system_tokens = count_tokens(model, prompts::GENERAL_ROLE_SYSTEM);
        let stable_prefix_tokens = count_tokens(
            model,
            &prompts::finding_link_user_prefix(prompt_category, ""),
        );
        let available_for_candidates = self
            .input_token_budget
            .saturating_sub(system_tokens + stable_prefix_tokens + self.finding_token_target);
        let effective = self.semantic_token_target.min(available_for_candidates);

        if effective == 0 {
            return Err(KgError::other(format!(
                "Finding link prompt for category '{}' leaves no room for semantic candidates under input budget {}",
                prompt_category
                    .map(|category| category.as_str())
                    .unwrap_or("None"),
                self.input_token_budget
            )));
        }

        Ok(effective)
    }

    fn finding_token_budget(
        &self,
        model: &OpenAIModel,
        context: &FindingLinkContext,
    ) -> Result<usize> {
        let system_tokens = count_tokens(model, prompts::GENERAL_ROLE_SYSTEM);
        let available = self
            .input_token_budget
            .saturating_sub(system_tokens + context.prompt_prefix_tokens);
        let effective = self.finding_token_target.min(available);

        if effective == 0 {
            return Err(KgError::other(format!(
                "Finding link context '{}' leaves no room for batched findings under input budget {}",
                context.cache_key, self.input_token_budget
            )));
        }

        Ok(effective)
    }
}

#[derive(Debug)]
struct AggregatedFindingLinkResult {
    finding_id: i32,
    link_target_finding_id: i32,
    expected_contexts: usize,
    completed_contexts: usize,
    /// Keyed by semantic_id (post-canonical-resolution). When multiple
    /// contexts emit the same (finding, semantic) pair (e.g. raw vs
    /// canonical both linked), we keep the strongest strength; the
    /// evidence text is taken from the same row.
    semantic_links: BTreeMap<i32, PersistedSemanticLink>,
}

pub async fn link_pending_findings(
    db: &HistoricalDatabase,
    llm: &LLM,
    options: FindingLinkOptions,
) -> Result<()> {
    use std::sync::Arc;
    use tokio::sync::mpsc;
    use tokio::task::JoinSet;

    let pending_findings = db
        .list_findings_for_linking(options.include_unlinked)
        .await?;
    if pending_findings.is_empty() {
        tracing::info!("No findings pending linking.");
        return Ok(());
    }

    let total_pending_findings = pending_findings.len();
    let concurrency = options.concurrency.max(1);
    let max_response_attempts = options.max_response_attempts.max(1);
    let agent_options = AgentRunOptions::new(options.max_agent_steps);
    let budgets = FindingLinkBudgets::from_options(&llm.model, options);
    tracing::info!(
        "Will link {} pending findings (concurrency={}, input token budget={}, target semantic tokens={}, target finding tokens={}, max response attempts={}, max agent steps={})",
        total_pending_findings,
        concurrency,
        budgets.input_token_budget,
        budgets.semantic_token_target,
        budgets.finding_token_target,
        max_response_attempts,
        options.max_agent_steps,
    );

    let plan = FindingLinkContextPlan::from_pending_findings(pending_findings.clone());
    let execution_plan = plan.materialize(db, &llm.model, &budgets).await?;
    let mut aggregated_results: HashMap<i32, AggregatedFindingLinkResult> = pending_findings
        .iter()
        .map(|pending| {
            (
                pending.finding_id,
                AggregatedFindingLinkResult {
                    finding_id: pending.finding_id,
                    link_target_finding_id: pending.link_target_finding_id,
                    expected_contexts: execution_plan.expected_context_count(pending.finding_id),
                    completed_contexts: 0,
                    semantic_links: BTreeMap::new(),
                },
            )
        })
        .collect();
    let task_count = execution_plan.task_count();
    let FindingLinkExecutionPlan {
        contexts, batches, ..
    } = execution_plan;

    tracing::info!(
        "Prepared {} finding-link batch(es) covering {} finding-context task(s) for {} pending findings",
        batches.len(),
        task_count,
        total_pending_findings
    );

    let mut failed_findings = HashSet::new();
    let mut committed_findings: HashSet<i32> = HashSet::new();
    if concurrency <= 1 {
        for batch in batches {
            let key = batch.context_key.clone();
            let context = contexts.get(&key).ok_or_else(|| {
                KgError::other(format!("Missing link context for key '{}'", key.label()))
            })?;

            let runner = FindingLinkBatchAgentRunner {
                llm: llm.clone(),
                batch: &batch,
                context: context.as_ref(),
                agent_options: agent_options.clone(),
                max_response_attempts,
            };
            match runner.run().await {
                Ok(results) => {
                    // Mirror the concurrent branch: persist this batch's
                    // per-finding sfl rows BEFORE the in-memory merge.
                    // `commit_completed_findings` only writes the
                    // `finding_link_status` row — it relies on this
                    // call to have already landed the link edges, so
                    // the sfl payload must hit DB here or it's lost.
                    persist_batch_partials(db, &failed_findings, &committed_findings, &results)
                        .await;
                    if let Err(e) =
                        merge_finding_link_batch_results(&mut aggregated_results, results)
                    {
                        mark_batch_findings_failed(&mut failed_findings, &batch);
                        tracing::error!(
                            "Failed to aggregate finding-link batch {} ({} finding-category task(s)): {}",
                            &batch,
                            batch.entries.len(),
                            e
                        );
                    } else {
                        commit_completed_findings(
                            db,
                            &mut aggregated_results,
                            &mut failed_findings,
                            &mut committed_findings,
                            batch.entries.iter().map(|e| e.pending.finding_id),
                        )
                        .await;
                    }
                }
                Err(e) => {
                    mark_batch_findings_failed(&mut failed_findings, &batch);
                    tracing::error!(
                        "Failed to link finding batch {} ({} finding-category task(s)): {}",
                        &batch,
                        batch.entries.len(),
                        e
                    );
                }
            }
        }
    } else {
        let contexts = Arc::new(contexts);
        let (tx, rx) = async_channel::bounded::<FindingLinkBatch>(batches.len() + 1);
        let (out_tx, mut out_rx) = mpsc::channel::<(
            FindingLinkBatch,
            Result<Vec<PersistedFindingLinkResult>>,
        )>(concurrency + 1);
        let mut handles = JoinSet::new();

        for _ in 0..concurrency {
            let rx = rx.clone();
            let out = out_tx.clone();
            let llm_clone = llm.clone();
            let contexts = contexts.clone();
            let worker_agent_options = agent_options.clone();

            handles.spawn(async move {
                while let Ok(batch) = rx.recv().await {
                    let result = match contexts.get(&batch.context_key) {
                        Some(context) => {
                            let runner = FindingLinkBatchAgentRunner {
                                llm: llm_clone.clone(),
                                batch: &batch,
                                context: context.as_ref(),
                                agent_options: worker_agent_options.clone(),
                                max_response_attempts,
                            };
                            runner.run().await
                        }
                        None => Err(KgError::other(format!(
                            "Missing link context for key '{}'",
                            batch.context_key.label()
                        ))),
                    };

                    out.send((batch, result))
                        .await
                        .expect("can not send finding link batch result");
                }

                Ok::<_, KgError>(())
            });
        }
        drop(out_tx);
        drop(rx);

        for batch in batches {
            tx.send(batch)
                .await
                .expect("fail to send out finding link batch");
        }
        drop(tx);

        while let Some(handle) = out_rx.recv().await {
            let (batch, results) = handle;
            match results {
                Ok(results) => {
                    // Durably persist this batch's per-finding decisions
                    // before merging into the in-memory aggregate. A
                    // kill / billing-cap abort here leaves the sfl rows
                    // in place; the finding stays out of
                    // `finding_link_status` until the last batch
                    // completes, so downstream consumers don't see the
                    // partial state. Without this step the entire run's
                    // work would live in `aggregated_results` only and
                    // evaporate on exit.
                    persist_batch_partials(db, &failed_findings, &committed_findings, &results)
                        .await;
                    if let Err(e) =
                        merge_finding_link_batch_results(&mut aggregated_results, results)
                    {
                        mark_batch_findings_failed(&mut failed_findings, &batch);
                        tracing::error!(
                            "Failed to aggregate finding-link batch {} ({} finding-category task(s)): {}",
                            &batch,
                            batch.entries.len(),
                            e
                        );
                    } else {
                        commit_completed_findings(
                            db,
                            &mut aggregated_results,
                            &mut failed_findings,
                            &mut committed_findings,
                            batch.entries.iter().map(|e| e.pending.finding_id),
                        )
                        .await;
                    }
                }
                Err(e) => {
                    mark_batch_findings_failed(&mut failed_findings, &batch);
                    tracing::error!(
                        "Finding-link batch {} ({} finding-category task(s)) failed: {}",
                        &batch,
                        batch.entries.len(),
                        e
                    );
                }
            }
        }

        while let Some(handle) = handles.join_next().await {
            match handle {
                Ok(Ok(())) => {}
                Ok(Err(e)) => {
                    tracing::error!("Finding-link worker task failed: {}", e);
                }
                Err(e) => {
                    tracing::error!("Finding-link worker task panicked: {}", e);
                }
            }
        }
    }

    let final_results = finalize_finding_link_results(aggregated_results, &mut failed_findings);
    for result in final_results {
        if let Err(e) = db.write_finding_link_result(&result).await {
            failed_findings.insert(result.finding_id);
            tracing::error!(
                "Failed to save finding links for #{}: {}",
                result.finding_id,
                e
            );
        }
    }

    if !failed_findings.is_empty() {
        tracing::warn!(
            "Finding linking failed for {} finding(s)",
            failed_findings.len()
        );
    }

    let findings_without_links = db.list_processed_findings_without_semantic_links().await?;
    if !findings_without_links.is_empty() {
        let preview = findings_without_links
            .iter()
            .take(20)
            .map(|finding_id| format!("finding-{finding_id}"))
            .collect::<Vec<_>>()
            .join(", ");
        let remainder = findings_without_links.len().saturating_sub(20);
        let more = if remainder > 0 {
            format!(" and {remainder} more")
        } else {
            String::new()
        };
        let retry_hint = if options.include_unlinked {
            "These findings were included in this run because `--include-unlinked` was enabled, but they still ended up without semantic links."
        } else {
            "To retry just these findings, run `knowdit link --include-unlinked`."
        };
        tracing::warn!(
            "{} processed finding(s) still have no semantic links after this run: {}{}. {}",
            findings_without_links.len(),
            preview,
            more,
            retry_hint,
        );
    }

    tracing::info!("Finding linking complete.");
    Ok(())
}

fn partition_finding_link_entries(
    entries: Vec<FindingLinkBatchEntry>,
    token_budget: usize,
    max_count: usize,
) -> Vec<Vec<FindingLinkBatchEntry>> {
    let mut batches = Vec::new();
    let mut current = Vec::new();
    let mut current_tokens = 0usize;

    for entry in entries {
        let count_exceeded = current.len() >= max_count;
        let tokens_exceeded = current_tokens + entry.token_count > token_budget;
        if !current.is_empty() && (count_exceeded || tokens_exceeded) {
            batches.push(current);
            current = Vec::new();
            current_tokens = 0;
        }

        current_tokens += entry.token_count;
        current.push(entry);
    }

    if !current.is_empty() {
        batches.push(current);
    }

    batches
}

fn partition_finding_link_candidate_groups(
    groups: Vec<FindingLinkCandidateGroup>,
    token_budget: usize,
) -> Vec<Vec<FindingLinkCandidateEntry>> {
    let mut batches = Vec::new();
    let mut current = Vec::new();
    let mut current_tokens = 0usize;

    for group in groups {
        if !current.is_empty() && current_tokens + group.token_count > token_budget {
            batches.push(current);
            current = Vec::new();
            current_tokens = 0;
        }

        current_tokens += group.token_count;
        current.extend(group.entries);
    }

    if !current.is_empty() {
        batches.push(current);
    }

    batches
}

fn group_finding_link_candidate_entries(
    entries: Vec<FindingLinkCandidateEntry>,
) -> Result<Vec<FindingLinkCandidateGroup>> {
    let mut grouped_entries = BTreeMap::<i32, Vec<FindingLinkCandidateEntry>>::new();
    for entry in entries {
        grouped_entries
            .entry(entry.canonical_semantic_id)
            .or_default()
            .push(entry);
    }

    let mut groups = Vec::new();
    for (canonical_semantic_id, mut group_entries) in grouped_entries {
        group_entries.sort_by(|lhs, rhs| {
            rhs.is_canonical
                .cmp(&lhs.is_canonical)
                .then_with(|| lhs.name.cmp(&rhs.name))
                .then_with(|| lhs.candidate_id.cmp(&rhs.candidate_id))
        });

        let canonical_entry = group_entries
            .first()
            .filter(|entry| entry.is_canonical)
            .ok_or_else(|| {
                KgError::other(format!(
                    "Missing canonical semantic sem-{} while building finding-link candidate group",
                    canonical_semantic_id
                ))
            })?;

        let token_count = group_entries.iter().map(|entry| entry.token_count).sum();
        groups.push(FindingLinkCandidateGroup {
            canonical_semantic_id,
            category: canonical_entry.category,
            name: canonical_entry.name.clone(),
            entries: group_entries,
            token_count,
        });
    }

    groups.sort_by(|lhs, rhs| {
        lhs.category
            .as_str()
            .cmp(rhs.category.as_str())
            .then_with(|| lhs.name.cmp(&rhs.name))
            .then_with(|| lhs.canonical_semantic_id.cmp(&rhs.canonical_semantic_id))
    });

    Ok(groups)
}

fn build_finding_link_batches(
    model: &OpenAIModel,
    pending_by_context: BTreeMap<FindingLinkContextKey, Vec<PendingFindingForLinking>>,
    contexts: &BTreeMap<FindingLinkContextKey, std::sync::Arc<FindingLinkContext>>,
    budgets: &FindingLinkBudgets,
) -> Result<Vec<FindingLinkBatch>> {
    let mut batches = Vec::new();

    for (context_key, pending_findings) in pending_by_context {
        let context = contexts.get(&context_key).ok_or_else(|| {
            KgError::other(format!(
                "Missing link context for key '{}'",
                context_key.label()
            ))
        })?;
        let finding_token_budget = budgets.finding_token_budget(model, context.as_ref())?;

        let entries = pending_findings
            .into_iter()
            .map(|pending| {
                let prompt_finding_id = prompt_finding_id(pending.finding_id);
                let prompt_body = prompts::finding_link_finding_entry(
                    &prompt_finding_id,
                    &pending.categories,
                    &pending.finding.title,
                    pending.finding.severity,
                    pending.finding.category,
                    &pending.finding.subcategory,
                    &pending.finding.root_cause,
                    &pending.finding.description,
                    &pending.finding.patterns,
                    &pending.finding.exploits,
                );
                let token_count = count_tokens(model, &prompt_body);
                FindingLinkBatchEntry {
                    pending,
                    prompt_finding_id,
                    prompt_body,
                    token_count,
                }
            })
            .collect();

        for batch_entries in partition_finding_link_entries(
            entries,
            finding_token_budget,
            budgets.max_findings_per_batch,
        ) {
            let finding_token_count = batch_entries.iter().map(|entry| entry.token_count).sum();
            if finding_token_count > finding_token_budget {
                tracing::warn!(
                    "Finding-link batch {} exceeds finding token budget {} with {} finding tokens; sending as singleton batch",
                    finding_link_batch_entry_span(&batch_entries),
                    finding_token_budget,
                    finding_token_count
                );
            }

            batches.push(FindingLinkBatch {
                context_key: context_key.clone(),
                entries: batch_entries,
                finding_token_count,
                finding_token_budget,
                input_token_budget: budgets.input_token_budget,
            });
        }
    }

    Ok(batches)
}

async fn build_finding_link_contexts(
    db: &HistoricalDatabase,
    model: &OpenAIModel,
    base_context_key: &FindingLinkContextKey,
    budgets: &FindingLinkBudgets,
) -> Result<Vec<(FindingLinkContextKey, FindingLinkContext)>> {
    // The current linking strategy is "one-time, exhaustive": for every
    // pending finding we present every canonical semantic across all
    // categories. The empty key marks this all-canonical pass — there are no
    // merged aliases in the candidate set, so the canonical-target indirection
    // collapses to identity.
    let candidates: Vec<SemanticLinkCandidate> = db
        .all_canonical_semantic_link_candidates()
        .await?
        .into_iter()
        .map(|node| SemanticLinkCandidate {
            candidate_id: format!("sem-{}", node.id),
            canonical_semantic_id: node.id,
            is_canonical: true,
            category: node.category,
            name: node.name,
            definition: node.definition,
            description: node.description,
        })
        .collect();

    let candidate_entries: Vec<FindingLinkCandidateEntry> = candidates
        .into_iter()
        .map(|candidate| {
            let prompt_body = render_finding_link_candidate(&candidate);
            FindingLinkCandidateEntry {
                candidate_id: candidate.candidate_id,
                canonical_semantic_id: candidate.canonical_semantic_id,
                is_canonical: candidate.is_canonical,
                category: candidate.category,
                name: candidate.name,
                token_count: count_tokens(model, &prompt_body),
                prompt_body,
            }
        })
        .collect();

    if candidate_entries.is_empty() {
        return Ok(vec![(
            base_context_key.clone(),
            FindingLinkContext::build(model, base_context_key, Vec::new()),
        )]);
    }

    let semantic_token_budget =
        budgets.semantic_token_budget(model, base_context_key.prompt_category())?;
    let candidate_groups = group_finding_link_candidate_entries(candidate_entries)?;
    let candidate_chunks =
        partition_finding_link_candidate_groups(candidate_groups, semantic_token_budget);

    Ok(candidate_chunks
        .into_iter()
        .enumerate()
        .map(|(chunk_index, candidate_entries)| {
            let context_key = base_context_key.with_semantic_chunk(chunk_index);
            let context = FindingLinkContext::build(model, &context_key, candidate_entries);
            (context_key, context)
        })
        .collect())
}

fn render_finding_link_candidate(candidate: &SemanticLinkCandidate) -> String {
    // After the all-canonical pass refactor, every candidate is canonical and
    // `is_canonical` is always true. Kept as one render path for simplicity.
    format!(
        "Candidate ID: {}\nCategory: {}\nName: {}\nDefinition: {}\nDescription: {}\n\n",
        candidate.candidate_id,
        candidate.category,
        candidate.name,
        candidate.definition,
        candidate.description
    )
}

fn merge_finding_link_batch_results(
    aggregated_results: &mut HashMap<i32, AggregatedFindingLinkResult>,
    results: Vec<PersistedFindingLinkResult>,
) -> Result<()> {
    for result in results {
        let aggregate = aggregated_results
            .get_mut(&result.finding_id)
            .ok_or_else(|| {
                KgError::other(format!(
                    "Finding link aggregation is missing finding {}",
                    result.finding_id
                ))
            })?;

        if aggregate.link_target_finding_id != result.link_target_finding_id {
            return Err(KgError::other(format!(
                "Finding {} resolved inconsistent link targets: {} vs {}",
                result.finding_id, aggregate.link_target_finding_id, result.link_target_finding_id
            )));
        }

        aggregate.completed_contexts += 1;
        for link in result.semantic_links {
            // On collision keep the strongest strength; evidence sticks
            // with the strength that wins.
            aggregate
                .semantic_links
                .entry(link.semantic_id)
                .and_modify(|existing| {
                    if link.strength.rank() > existing.strength.rank() {
                        *existing = link.clone();
                    }
                })
                .or_insert(link);
        }
    }

    Ok(())
}

fn finalize_finding_link_results(
    aggregated_results: HashMap<i32, AggregatedFindingLinkResult>,
    failed_findings: &mut HashSet<i32>,
) -> Vec<PersistedFindingLinkResult> {
    let mut final_results = Vec::new();

    for aggregate in aggregated_results
        .into_values()
        .sorted_by_key(|aggregate| aggregate.finding_id)
    {
        if failed_findings.contains(&aggregate.finding_id) {
            continue;
        }

        if aggregate.completed_contexts != aggregate.expected_contexts {
            failed_findings.insert(aggregate.finding_id);
            tracing::error!(
                "Finding #{} only completed {}/{} category-specific link tasks",
                aggregate.finding_id,
                aggregate.completed_contexts,
                aggregate.expected_contexts
            );
            continue;
        }

        final_results.push(PersistedFindingLinkResult {
            finding_id: aggregate.finding_id,
            link_target_finding_id: aggregate.link_target_finding_id,
            semantic_links: aggregate.semantic_links.into_values().collect(),
        });
    }

    final_results
}

fn mark_batch_findings_failed(failed_findings: &mut HashSet<i32>, batch: &FindingLinkBatch) {
    failed_findings.extend(batch.entries.iter().map(|entry| entry.pending.finding_id));
}

/// Per-batch durable write: every finding's batch-level decision lands
/// in `semantic_finding_link` immediately. The finding stays out of
/// `finding_link_status` until the last batch completes, so downstream
/// consumers (mapper, spec-gen) don't see the partial state via
/// `load_knowledge_graph`. The upsert is strongest-strength-wins so
/// repeated batches over the same (semantic, finding) edge keep the
/// strongest tier seen — making resume idempotent: a re-run merges on
/// top of any rows the prior abort left behind.
async fn persist_batch_partials(
    db: &HistoricalDatabase,
    failed_findings: &HashSet<i32>,
    committed_findings: &HashSet<i32>,
    results: &[PersistedFindingLinkResult],
) {
    for result in results {
        if failed_findings.contains(&result.finding_id)
            || committed_findings.contains(&result.finding_id)
        {
            continue;
        }
        if let Err(e) = db.upsert_finding_link_partial(result).await {
            tracing::error!(
                "Failed to persist partial batch links for finding #{}: {}",
                result.finding_id,
                e
            );
            // Don't add to failed_findings here — the in-memory
            // aggregate still wants the merge so the finding can
            // either succeed via a later batch's write or fall
            // through to the final-flush diagnostic. The retry
            // dance lives at the batch-runner layer.
        }
    }
}

/// Drains any aggregated findings whose every expected context has now been
/// merged and inserts their `finding_link_status` row. The actual link
/// rows were already durably written by `persist_batch_partials` after each
/// batch; this is the one transactional step that promotes them from
/// "partial" (sfl-only) to "queryable by downstream consumers" (sfl + fls).
async fn commit_completed_findings<I: IntoIterator<Item = i32>>(
    db: &HistoricalDatabase,
    aggregated_results: &mut HashMap<i32, AggregatedFindingLinkResult>,
    failed_findings: &mut HashSet<i32>,
    committed_findings: &mut HashSet<i32>,
    finding_ids: I,
) {
    let mut seen: HashSet<i32> = HashSet::new();
    for fid in finding_ids {
        if !seen.insert(fid) {
            continue;
        }
        if failed_findings.contains(&fid) || committed_findings.contains(&fid) {
            continue;
        }
        let ready = aggregated_results
            .get(&fid)
            .map(|agg| agg.expected_contexts > 0 && agg.completed_contexts >= agg.expected_contexts)
            .unwrap_or(false);
        if !ready {
            continue;
        }
        let agg = aggregated_results
            .remove(&fid)
            .expect("readiness check just confirmed presence");
        let link_count = agg.semantic_links.len();
        let finding_id = agg.finding_id;
        match db.mark_finding_link_complete(finding_id).await {
            Ok(()) => {
                committed_findings.insert(finding_id);
                tracing::debug!(
                    "Committed finding #{} ({} semantic link(s))",
                    finding_id,
                    link_count,
                );
            }
            Err(e) => {
                failed_findings.insert(finding_id);
                tracing::error!("Failed to mark finding #{} complete: {}", finding_id, e);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Per-batch agent runner — replaces the old JSON+parse `link_pending_findings_batch`
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
#[tool(
    arguments = FindingLinkDecision,
    invoke = invoke,
    description = "Emit one link decision for a single finding in this prompt. Call once per `finding_id` shown under \"Findings To Link\". `semantic_evidence` is a list of {semantic_id, strength, why_finding_can_fire} entries — include candidates the finding is at least tangentially related to (Low or higher). Candidates with NO meaningful relation can be omitted entirely; silent omission is treated as 'no link'. Each entry's `semantic_id` MUST be a Candidate ID from the prompt; `strength` is one of `High` / `Medium` / `Low`; `why_finding_can_fire` cites the specific behaviour from the semantic's description that ties to this finding. High/Medium evidence must be at least 40 characters; Low can be as short as 15. The tool validates ids, strength parsing, and evidence length; rejected decisions can be re-emitted.",
    name = "emit_finding_link_decision",
)]
struct EmitFindingLinkDecisionTool {
    buffer: Arc<AgentChunkBuffer<FindingLinkDecision>>,
    /// Set of `finding-N` ids the prompt actually listed. Rejecting any
    /// other id at the tool boundary lets the agent see the error message
    /// and retry within its step loop instead of having the orchestrator
    /// silently fold the decision into "no-link" later.
    valid_finding_ids: Arc<HashSet<String>>,
    /// Set of `Candidate ID` values the prompt actually listed.
    valid_semantic_ids: Arc<HashSet<String>>,
    /// Per-attempt heartbeat label so progress logs can identify which
    /// batch+attempt is making forward progress. Set by the batch
    /// runner before installing the tool.
    label: String,
    /// Total findings this attempt was asked to emit decisions for.
    /// Used as the denominator in the progress heartbeat.
    target_finding_count: usize,
    /// Running count of accepted emit calls during this attempt.
    /// Atomic so the tool's `&self` invoke can mutate without locks.
    emit_count: Arc<std::sync::atomic::AtomicUsize>,
}

/// Minimum byte length of `why_finding_can_fire` per strength tier. Low
/// rationales are short by design (they exist for audit, not downstream
/// consumption); High and Medium must be substantive enough to justify
/// the claim. See plan_link.md §6.1.
const LINK_EVIDENCE_MIN_HIGH_MEDIUM: usize = 40;
const LINK_EVIDENCE_MIN_LOW: usize = 15;

impl EmitFindingLinkDecisionTool {
    async fn invoke(&self, args: FindingLinkDecision) -> std::result::Result<String, LLMYError> {
        if args.finding_id.trim().is_empty() {
            return Ok("error: `finding_id` must not be empty".to_string());
        }
        if !self.valid_finding_ids.contains(&args.finding_id) {
            return Ok(format!(
                "error: `finding_id` '{}' is not in this prompt's \"Findings To Link\" section. Re-emit using one of the IDs shown there exactly.",
                args.finding_id,
            ));
        }

        // Only validate that referenced ids exist. Silent omission is
        // allowed and means "no link" for unreferenced candidates —
        // the full per-candidate coverage contract was unworkable at
        // the link agent's scale (1493 canonical sems per context vs
        // mapper's ~16); see plan_link.md §4 撤回 entry for the post-
        // mortem.
        let invalid_ids: Vec<&String> = args
            .semantic_evidence
            .iter()
            .map(|e| &e.semantic_id)
            .filter(|id| !self.valid_semantic_ids.contains(*id))
            .collect();
        if !invalid_ids.is_empty() {
            return Ok(format!(
                "error: `semantic_evidence` contains semantic_id values not in this prompt's \"Candidate Semantics\" list: {invalid_ids:?}. Re-emit this decision using only `Candidate ID` values shown above.",
            ));
        }

        // Per-entry: strength parses + evidence length floor depending on tier.
        for evidence in &args.semantic_evidence {
            let Some(strength) =
                knowdit_kg_model::link_strength::LinkStrength::parse(&evidence.strength)
            else {
                return Ok(format!(
                    "error: evidence for semantic_id '{}' under finding '{}' has unrecognised `strength` value {:?}. Use one of `High`, `Medium`, or `Low` (case-insensitive).",
                    evidence.semantic_id, args.finding_id, evidence.strength,
                ));
            };
            let trimmed = evidence.why_finding_can_fire.trim();
            if trimmed.is_empty() {
                return Ok(format!(
                    "error: evidence for semantic_id '{}' under finding '{}' has empty `why_finding_can_fire`. Even Low strength needs a brief reason (>= {} chars) explaining why the link is tangential.",
                    evidence.semantic_id, args.finding_id, LINK_EVIDENCE_MIN_LOW,
                ));
            }
            let floor = match strength {
                knowdit_kg_model::link_strength::LinkStrength::High
                | knowdit_kg_model::link_strength::LinkStrength::Medium => {
                    LINK_EVIDENCE_MIN_HIGH_MEDIUM
                }
                knowdit_kg_model::link_strength::LinkStrength::Low => LINK_EVIDENCE_MIN_LOW,
            };
            if trimmed.len() < floor {
                return Ok(format!(
                    "error: evidence for semantic_id '{}' (strength={}) under finding '{}' is only {} chars; the {} tier requires at least {} chars. Cite a specific behaviour from the semantic's description that matches the finding's bug prerequisites.",
                    evidence.semantic_id,
                    strength,
                    args.finding_id,
                    trimmed.len(),
                    strength,
                    floor,
                ));
            }
        }
        let response = self
            .buffer
            .push_with_message(args, "finding link decision")
            .await;
        // Heartbeat: print one line per `LINK_PROGRESS_HEARTBEAT_EVERY`
        // accepted emits so a stuck attempt is visible as a flatline,
        // not as ambiguous silence between attempts.
        let n = self
            .emit_count
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            + 1;
        if n.is_multiple_of(LINK_PROGRESS_HEARTBEAT_EVERY) || n == self.target_finding_count {
            tracing::info!(
                "{}: progress {}/{} decisions emitted",
                self.label,
                n,
                self.target_finding_count,
            );
        }
        Ok(response)
    }
}

/// Emit one heartbeat log line for every N accepted emits. Tuned so a
/// 100-finding batch logs ~4 times per attempt; large batches still
/// stay readable without flooding.
const LINK_PROGRESS_HEARTBEAT_EVERY: usize = 25;

#[derive(Debug, Clone)]
#[tool(
    arguments = FinalizeArgs,
    invoke = invoke,
    description = "Signal that every finding in this prompt has been processed via emit_finding_link_decision (with possibly empty semantic_ids when no candidate is related). Call exactly once, then stop.",
    name = "finalize_finding_link",
)]
struct FinalizeFindingLinkTool {
    buffer: Arc<AgentChunkBuffer<FindingLinkDecision>>,
}

impl FinalizeFindingLinkTool {
    async fn invoke(&self, args: FinalizeArgs) -> std::result::Result<String, LLMYError> {
        Ok(self
            .buffer
            .finalize_with_message(args.summary, "finding linking")
            .await)
    }
}

/// Single-batch link runner. Drives one Agent per attempt (re-running with
/// the prompt restricted to still-missing findings between attempts), up to
/// `max_response_attempts` times. The final pass folds any remaining
/// uncovered findings into empty `PersistedFindingLinkResult`s and logs a
/// warning, matching the prior best-effort behaviour.
struct FindingLinkBatchAgentRunner<'a> {
    llm: LLM,
    batch: &'a FindingLinkBatch,
    context: &'a FindingLinkContext,
    agent_options: AgentRunOptions,
    max_response_attempts: usize,
}

impl<'a> FindingLinkBatchAgentRunner<'a> {
    async fn run(self) -> Result<Vec<PersistedFindingLinkResult>> {
        if self.batch.entries.is_empty() {
            return Ok(Vec::new());
        }
        if self.context.candidate_map.is_empty() {
            tracing::info!(
                "No semantic candidates for finding batch {}, marking {} finding(s) as processed without links",
                self.batch,
                self.batch.entries.len(),
            );
            return Ok(self
                .batch
                .entries
                .iter()
                .map(|entry| PersistedFindingLinkResult {
                    finding_id: entry.pending.finding_id,
                    link_target_finding_id: entry.pending.link_target_finding_id,
                    semantic_links: Vec::new(),
                })
                .collect());
        }

        tracing::info!(
            "Linking finding batch {} ({} finding(s), ~{} semantic tokens, ~{} finding tokens, finding_budget={}, input_budget={}, max_response_attempts={})",
            self.batch,
            self.batch.entries.len(),
            self.context.candidate_token_count,
            self.batch.finding_token_count,
            self.batch.finding_token_budget,
            self.batch.input_token_budget,
            self.max_response_attempts,
        );

        // Step budget sanity: agent needs ~1 step per emit + 1 finalize
        // + reasoning headroom. If the step cap looks tight, warn so
        // the operator can raise --link-max-agent-steps before the run
        // burns through 3 attempts hitting the step ceiling.
        let max_agent_steps = self.agent_options.max_agent_steps;
        let step_headroom = max_agent_steps.saturating_sub(self.batch.entries.len() + 1);
        if step_headroom < 4 {
            tracing::warn!(
                "Finding batch {} may not fit the step budget: {} finding(s) need ≥{} steps (emit+finalize), but --link-max-agent-steps is {}. Expect premature finalize / no-link defaults. Lower --max-findings-per-batch or raise --link-max-agent-steps.",
                self.batch,
                self.batch.entries.len(),
                self.batch.entries.len() + 1,
                max_agent_steps,
            );
        }

        let valid_semantic_ids: Arc<HashSet<String>> =
            Arc::new(self.context.candidate_map.keys().cloned().collect());
        // `collected[finding_id]` holds the most recent decision the agent
        // emitted for that finding across all attempts. Re-attempts only
        // ask the agent about findings still missing from this map.
        let mut collected: HashMap<i32, FindingLinkDecision> = HashMap::new();

        for attempt in 1..=self.max_response_attempts {
            let still_missing: Vec<&FindingLinkBatchEntry> = self
                .batch
                .entries
                .iter()
                .filter(|entry| !collected.contains_key(&entry.pending.finding_id))
                .collect();
            if still_missing.is_empty() {
                break;
            }

            let valid_finding_ids: Arc<HashSet<String>> = Arc::new(
                still_missing
                    .iter()
                    .map(|entry| entry.prompt_finding_id.clone())
                    .collect(),
            );
            let mut user_prompt = self.context.prompt_prefix.clone();
            for entry in &still_missing {
                user_prompt.push_str(&entry.prompt_body);
            }
            let cache_key = format!("{}-attempt{:02}", self.context.cache_key, attempt);
            let label = format!("finding-link-{}-attempt{:02}", self.batch, attempt);
            let target_finding_count = still_missing.len();
            let agent_decisions = self
                .run_one_attempt(
                    user_prompt,
                    cache_key,
                    label.clone(),
                    valid_finding_ids,
                    valid_semantic_ids.clone(),
                    attempt,
                    target_finding_count,
                )
                .await?;
            tracing::info!(
                "{}: agent emitted {} decision(s) for {} pending finding(s)",
                label,
                agent_decisions.len(),
                still_missing.len(),
            );

            // Map prompt_finding_id ("finding-N") back to the numeric
            // finding_id and store the latest decision per finding.
            let entries_by_prompt_id: HashMap<&str, &FindingLinkBatchEntry> = self
                .batch
                .entries
                .iter()
                .map(|entry| (entry.prompt_finding_id.as_str(), entry))
                .collect();
            for decision in agent_decisions {
                if let Some(entry) = entries_by_prompt_id.get(decision.finding_id.as_str()) {
                    collected.insert(entry.pending.finding_id, decision);
                }
            }

            // Coverage check after this attempt — log + retry if anything
            // is still missing and we haven't blown the cap yet.
            let leftover: Vec<&FindingLinkBatchEntry> = self
                .batch
                .entries
                .iter()
                .filter(|entry| !collected.contains_key(&entry.pending.finding_id))
                .collect();
            if leftover.is_empty() {
                break;
            }
            if attempt < self.max_response_attempts {
                tracing::warn!(
                    "Finding-link batch {} attempt {}/{}: {} finding(s) still missing decisions ({}); retrying with restricted prompt",
                    self.batch,
                    attempt,
                    self.max_response_attempts,
                    leftover.len(),
                    leftover
                        .iter()
                        .map(|entry| entry.prompt_finding_id.as_str())
                        .collect::<Vec<_>>()
                        .join(", "),
                );
            } else {
                tracing::warn!(
                    "Finding-link batch {} exhausted {} attempt(s) with {} finding(s) still missing ({}); treating them as no-link results",
                    self.batch,
                    self.max_response_attempts,
                    leftover.len(),
                    leftover
                        .iter()
                        .map(|entry| entry.prompt_finding_id.as_str())
                        .collect::<Vec<_>>()
                        .join(", "),
                );
            }
        }

        // Materialize one PersistedFindingLinkResult per batch entry, in
        // input order. Findings without a recorded decision get an empty
        // semantic_ids list (already warned about above).
        Ok(self
            .batch
            .entries
            .iter()
            .map(|entry| {
                let semantic_links = collected
                    .remove(&entry.pending.finding_id)
                    .map(|d| {
                        Self::resolve_semantic_links(
                            d.semantic_evidence,
                            &self.context.candidate_map,
                        )
                    })
                    .unwrap_or_default();
                PersistedFindingLinkResult {
                    finding_id: entry.pending.finding_id,
                    link_target_finding_id: entry.pending.link_target_finding_id,
                    semantic_links,
                }
            })
            .collect())
    }

    async fn run_one_attempt(
        &self,
        user_prompt: String,
        cache_key: String,
        label: String,
        valid_finding_ids: Arc<HashSet<String>>,
        valid_semantic_ids: Arc<HashSet<String>>,
        attempt: usize,
        target_finding_count: usize,
    ) -> Result<Vec<FindingLinkDecision>> {
        let buffer = AgentChunkBuffer::<FindingLinkDecision>::new();
        let mut tools = ToolBox::new();
        tools.add_tool(EmitFindingLinkDecisionTool {
            buffer: buffer.clone(),
            valid_finding_ids,
            valid_semantic_ids,
            label: label.clone(),
            target_finding_count,
            emit_count: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        });
        tools.add_tool(FinalizeFindingLinkTool {
            buffer: buffer.clone(),
        });
        let runner = AgentChunkRunner {
            llm: self.llm.clone(),
            options: self
                .agent_options
                .scoped(&format!("link-{}-attempt{:02}", self.batch, attempt)),
            buffer: buffer.clone(),
            tools,
            system_prompt: prompts::GENERAL_ROLE_SYSTEM.to_string(),
            user_prompt,
            cache_key,
            label,
        };
        let _outcome = runner.run().await?;
        Ok(buffer.drain().await)
    }

    /// Resolve the agent-emitted evidence list into
    /// [`PersistedSemanticLink`] entries carrying canonical semantic ids
    /// (via the context's candidate map) plus the per-link strength +
    /// evidence text. Unknown or unparseable strengths are silently
    /// dropped here (the tool handler already rejected them before this
    /// point; this is the defensive last line). On duplicate semantic
    /// ids the strongest emit wins.
    fn resolve_semantic_links(
        evidence: Vec<LinkEvidence>,
        candidate_map: &HashMap<String, i32>,
    ) -> Vec<PersistedSemanticLink> {
        let mut by_id: BTreeMap<i32, PersistedSemanticLink> = BTreeMap::new();
        for ev in evidence {
            let Some(target) = candidate_map.get(&ev.semantic_id).copied() else {
                continue;
            };
            let Some(strength) = knowdit_kg_model::link_strength::LinkStrength::parse(&ev.strength)
            else {
                continue;
            };
            let new_link = PersistedSemanticLink {
                semantic_id: target,
                strength,
                evidence: ev.why_finding_can_fire,
            };
            by_id
                .entry(target)
                .and_modify(|existing| {
                    if new_link.strength.rank() > existing.strength.rank() {
                        *existing = new_link.clone();
                    }
                })
                .or_insert(new_link);
        }
        by_id.into_values().collect()
    }
}

fn prompt_finding_id(finding_id: i32) -> String {
    format!("finding-{}", finding_id)
}

/// Retro-link pass for the incremental learn-new-project flow.
///
/// Inputs:
///   - `pending_semantic` queue (canonical semantics newly introduced by
///     the most recent project admission(s));
///   - `finding_link_status` set (findings that have already been globally
///     linked in a previous pass and won't go through `link_pending_findings`
///     again).
///
/// For each pre-linked finding the LLM is asked which of the pending
/// canonical semantics it should additionally link to. New rows are appended
/// to `semantic_finding_link`. After every finding has been processed the
/// `pending_semantic` queue is cleared. `finding_link_status` is NOT
/// touched (those findings were already there).
///
/// Bootstrap callers (no prior `finding_link_status` rows) can still call
/// this — the function will just clear the pending queue and return.
pub async fn retro_link_pending_semantics(
    db: &HistoricalDatabase,
    llm: &LLM,
    options: FindingLinkOptions,
) -> Result<()> {
    let pending_semantics = db.list_pending_canonical_semantics().await?;
    if pending_semantics.is_empty() {
        tracing::info!("Retro-link: pending_semantic queue is empty, nothing to do");
        return Ok(());
    }
    let already_linked_findings = db.list_findings_with_link_status().await?;
    if already_linked_findings.is_empty() {
        tracing::info!(
            "Retro-link: no findings in finding_link_status; clearing the {} queued pending semantic(s) without LLM work (bootstrap path)",
            pending_semantics.len()
        );
        db.clear_pending_semantic_queue().await?;
        return Ok(());
    }

    let model = &llm.model;
    let max_response_attempts = options.max_response_attempts.max(1);
    let agent_options = AgentRunOptions::new(options.max_agent_steps);
    let budgets = FindingLinkBudgets::from_options(model, options);

    // Render the (small, bounded) pending semantics as a single candidate
    // block — they all fit in one prompt.
    let candidate_entries: Vec<FindingLinkCandidateEntry> = pending_semantics
        .iter()
        .map(|node| {
            let candidate = SemanticLinkCandidate {
                candidate_id: format!("sem-{}", node.id),
                canonical_semantic_id: node.id,
                is_canonical: true,
                category: node.category,
                name: node.name.clone(),
                definition: node.definition.clone(),
                description: node.description.clone(),
            };
            let prompt_body = render_finding_link_candidate(&candidate);
            FindingLinkCandidateEntry {
                candidate_id: candidate.candidate_id,
                canonical_semantic_id: candidate.canonical_semantic_id,
                is_canonical: candidate.is_canonical,
                category: candidate.category,
                name: candidate.name,
                token_count: count_tokens(model, &prompt_body),
                prompt_body,
            }
        })
        .collect();

    let context_key = FindingLinkContextKey::empty();
    let context = std::sync::Arc::new(FindingLinkContext::build(
        model,
        &context_key,
        candidate_entries,
    ));
    let finding_token_budget = budgets.finding_token_budget(model, context.as_ref())?;

    // Build per-finding entries.
    let entries: Vec<FindingLinkBatchEntry> = already_linked_findings
        .into_iter()
        .map(|pending| {
            let prompt_finding_id = prompt_finding_id(pending.finding_id);
            let prompt_body = prompts::finding_link_finding_entry(
                &prompt_finding_id,
                &pending.categories,
                &pending.finding.title,
                pending.finding.severity,
                pending.finding.category,
                &pending.finding.subcategory,
                &pending.finding.root_cause,
                &pending.finding.description,
                &pending.finding.patterns,
                &pending.finding.exploits,
            );
            let token_count = count_tokens(model, &prompt_body);
            FindingLinkBatchEntry {
                pending,
                prompt_finding_id,
                prompt_body,
                token_count,
            }
        })
        .collect();

    let total = entries.len();
    let batches = partition_finding_link_entries(
        entries,
        finding_token_budget,
        budgets.max_findings_per_batch,
    );
    tracing::info!(
        "Retro-link: {} pending canonical semantic(s) × {} pre-linked finding(s) → {} batch(es)",
        context.candidate_map.len(),
        total,
        batches.len()
    );

    let mut total_inserted = 0usize;
    for (idx, batch_entries) in batches.into_iter().enumerate() {
        let finding_token_count = batch_entries.iter().map(|e| e.token_count).sum();
        let batch = FindingLinkBatch {
            context_key: context_key.clone(),
            entries: batch_entries,
            finding_token_count,
            finding_token_budget,
            input_token_budget: budgets.input_token_budget,
        };
        tracing::info!(
            "Retro-link batch {}: {} finding(s)",
            idx + 1,
            batch.entries.len()
        );
        let runner = FindingLinkBatchAgentRunner {
            llm: llm.clone(),
            batch: &batch,
            context: context.as_ref(),
            agent_options: agent_options.clone(),
            max_response_attempts,
        };
        let results = runner.run().await?;

        // Translate to LinkEdge rows (carrying strength + evidence) and
        // write directly. Skip writing finding_link_status — these
        // findings are already there.
        let mut edges = Vec::new();
        for result in results {
            for link in result.semantic_links {
                edges.push(crate::db::LinkEdge {
                    semantic_node_id: link.semantic_id,
                    audit_finding_id: result.link_target_finding_id,
                    strength: link.strength,
                    evidence: link.evidence,
                });
            }
        }
        let inserted = db.append_semantic_finding_links(&edges).await?;
        total_inserted += inserted;
        tracing::info!(
            "Retro-link batch {} inserted {} new semantic_finding_link row(s)",
            idx + 1,
            inserted
        );
    }

    let cleared = db.clear_pending_semantic_queue().await?;
    tracing::info!(
        "Retro-link complete: {} new link(s) total, cleared {} row(s) from pending_semantic queue",
        total_inserted,
        cleared
    );
    Ok(())
}

fn finding_link_batch_entry_span(entries: &[FindingLinkBatchEntry]) -> String {
    let first = entries.first().map(|entry| entry.pending.finding_id);
    let last = entries.last().map(|entry| entry.pending.finding_id);
    match (first, last) {
        (Some(first), Some(last)) if first == last => format!("{}", first),
        (Some(first), Some(last)) => format!("{}-{}", first, last),
        _ => "empty".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vulnerability::{FindingSeverity, VulnerabilityCategory};

    fn sample_finding(id: i32) -> PendingFindingForLinking {
        PendingFindingForLinking {
            finding_id: id,
            link_target_finding_id: id,
            categories: vec![DeFiCategory::Dexes],
            finding: ExtractedFinding {
                title: format!("Finding {}", id),
                severity: FindingSeverity::Medium,
                category: VulnerabilityCategory::AccessControl,
                subcategory: "Missing Input Validation".to_string(),
                root_cause: "Unchecked parameters".to_string(),
                description: "A critical flow trusts malformed input.".to_string(),
                patterns: "Input not validated".to_string(),
                exploits: "Attacker passes malformed values".to_string(),
            },
        }
    }

    fn sample_finding_with_categories(
        id: i32,
        categories: Vec<DeFiCategory>,
    ) -> PendingFindingForLinking {
        let mut finding = sample_finding(id);
        finding.categories = categories;
        finding
    }

    fn sample_batch_entry(id: i32, token_count: usize) -> FindingLinkBatchEntry {
        FindingLinkBatchEntry {
            pending: sample_finding(id),
            prompt_finding_id: prompt_finding_id(id),
            prompt_body: format!("### finding-{}\n", id),
            token_count,
        }
    }

    fn sample_context_key(category: DeFiCategory) -> FindingLinkContextKey {
        FindingLinkContextKey::for_category(category)
    }

    #[test]
    fn partition_finding_link_entries_respects_budget_and_order() {
        let batches = partition_finding_link_entries(
            vec![
                sample_batch_entry(101, 40),
                sample_batch_entry(102, 20),
                sample_batch_entry(103, 50),
            ],
            60,
            usize::MAX,
        );

        assert_eq!(batches.len(), 2);
        assert_eq!(
            batches[0]
                .iter()
                .map(|entry| entry.pending.finding_id)
                .collect::<Vec<_>>(),
            vec![101, 102]
        );
        assert_eq!(
            batches[1]
                .iter()
                .map(|entry| entry.pending.finding_id)
                .collect::<Vec<_>>(),
            vec![103]
        );
    }

    #[test]
    fn partition_finding_link_entries_keeps_oversized_singleton_batch() {
        let batches = partition_finding_link_entries(
            vec![sample_batch_entry(201, 120), sample_batch_entry(202, 30)],
            100,
            usize::MAX,
        );

        assert_eq!(batches.len(), 2);
        assert_eq!(batches[0].len(), 1);
        assert_eq!(batches[0][0].pending.finding_id, 201);
        assert_eq!(batches[1].len(), 1);
        assert_eq!(batches[1][0].pending.finding_id, 202);
    }

    #[test]
    fn partition_finding_link_entries_honours_count_cap_under_token_budget() {
        // Tokens-wise everything fits; count cap should still split.
        let batches = partition_finding_link_entries(
            vec![
                sample_batch_entry(301, 10),
                sample_batch_entry(302, 10),
                sample_batch_entry(303, 10),
                sample_batch_entry(304, 10),
                sample_batch_entry(305, 10),
            ],
            10_000,
            2,
        );

        assert_eq!(batches.len(), 3);
        assert_eq!(batches[0].len(), 2);
        assert_eq!(batches[1].len(), 2);
        assert_eq!(batches[2].len(), 1);
    }

    #[test]
    fn resolve_semantic_links_dedupes_and_maps_through_candidate_map() {
        // The agent-side tool already validates ids; this helper maps the
        // surviving `Candidate ID` strings back to canonical i32 ids and
        // parses the per-link strength tier. On dedupe the strongest
        // strength wins (here all three are High).
        let candidate_map: HashMap<String, i32> = HashMap::from([
            ("sem-1".to_string(), 1),
            ("sem-merged".to_string(), 1),
            ("sem-2".to_string(), 2),
        ]);
        let resolved = FindingLinkBatchAgentRunner::resolve_semantic_links(
            vec![
                LinkEvidence {
                    semantic_id: "sem-1".to_string(),
                    strength: "High".to_string(),
                    why_finding_can_fire: "shared behaviour 1".to_string(),
                },
                LinkEvidence {
                    semantic_id: "sem-merged".to_string(),
                    strength: "High".to_string(),
                    why_finding_can_fire: "shared behaviour merged".to_string(),
                },
                LinkEvidence {
                    semantic_id: "sem-2".to_string(),
                    strength: "High".to_string(),
                    why_finding_can_fire: "shared behaviour 2".to_string(),
                },
            ],
            &candidate_map,
        );
        let resolved_ids: Vec<i32> = resolved.iter().map(|link| link.semantic_id).collect();
        assert_eq!(resolved_ids, vec![1, 2]);
    }

    #[test]
    fn merge_finding_link_batch_results_aggregates_multiple_categories() {
        use knowdit_kg_model::link_strength::LinkStrength;

        fn link(sid: i32, strength: LinkStrength) -> PersistedSemanticLink {
            PersistedSemanticLink {
                semantic_id: sid,
                strength,
                evidence: format!("evidence for sem-{sid}"),
            }
        }

        let mut aggregated_results = HashMap::from([(
            501,
            AggregatedFindingLinkResult {
                finding_id: 501,
                link_target_finding_id: 777,
                expected_contexts: 2,
                completed_contexts: 0,
                semantic_links: BTreeMap::new(),
            },
        )]);

        merge_finding_link_batch_results(
            &mut aggregated_results,
            vec![PersistedFindingLinkResult {
                finding_id: 501,
                link_target_finding_id: 777,
                semantic_links: vec![link(3, LinkStrength::Medium), link(1, LinkStrength::Medium)],
            }],
        )
        .expect("first category result should merge");

        merge_finding_link_batch_results(
            &mut aggregated_results,
            vec![PersistedFindingLinkResult {
                finding_id: 501,
                link_target_finding_id: 777,
                semantic_links: vec![link(2, LinkStrength::Medium), link(3, LinkStrength::Medium)],
            }],
        )
        .expect("second category result should merge");

        let mut failed_findings = HashSet::new();
        let results = finalize_finding_link_results(aggregated_results, &mut failed_findings);

        assert!(failed_findings.is_empty());
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].finding_id, 501);
        assert_eq!(results[0].link_target_finding_id, 777);
        let resolved_ids: Vec<i32> = results[0]
            .semantic_links
            .iter()
            .map(|l| l.semantic_id)
            .collect();
        assert_eq!(resolved_ids, vec![1, 2, 3]);
    }

    #[test]
    fn finalize_finding_link_results_rejects_missing_category_runs() {
        let aggregated_results = HashMap::from([(
            601,
            AggregatedFindingLinkResult {
                finding_id: 601,
                link_target_finding_id: 601,
                expected_contexts: 3,
                completed_contexts: 2,
                semantic_links: BTreeMap::new(),
            },
        )]);

        let mut failed_findings = HashSet::new();
        let results = finalize_finding_link_results(aggregated_results, &mut failed_findings);

        assert!(results.is_empty());
        assert!(failed_findings.contains(&601));
    }

    #[test]
    fn finding_link_context_plan_collapses_to_single_all_canonical_key() {
        // After the all-canonical refactor every pending finding routes through
        // the same single empty-categories context key, regardless of the
        // originating project's categories.
        let finding = sample_finding_with_categories(
            701,
            vec![
                DeFiCategory::Yield,
                DeFiCategory::Dexes,
                DeFiCategory::Yield,
            ],
        );

        let context_keys = FindingLinkContextKey::from_project_categories(&finding.categories);
        assert_eq!(context_keys.len(), 1);
        assert!(context_keys[0].categories.is_empty());
    }

    #[test]
    fn partition_finding_link_candidate_groups_keeps_aliases_with_canonical() {
        let batches = partition_finding_link_candidate_groups(
            vec![
                FindingLinkCandidateGroup {
                    canonical_semantic_id: 1,
                    category: DeFiCategory::Dexes,
                    name: "Canonical 1".to_string(),
                    token_count: 70,
                    entries: vec![
                        FindingLinkCandidateEntry {
                            candidate_id: "sem-1".to_string(),
                            canonical_semantic_id: 1,
                            is_canonical: true,
                            category: DeFiCategory::Dexes,
                            name: "Canonical 1".to_string(),
                            prompt_body: "candidate-1".to_string(),
                            token_count: 40,
                        },
                        FindingLinkCandidateEntry {
                            candidate_id: "sem-101".to_string(),
                            canonical_semantic_id: 1,
                            is_canonical: false,
                            category: DeFiCategory::Dexes,
                            name: "Alias 101".to_string(),
                            prompt_body: "candidate-101".to_string(),
                            token_count: 30,
                        },
                    ],
                },
                FindingLinkCandidateGroup {
                    canonical_semantic_id: 2,
                    category: DeFiCategory::Dexes,
                    name: "Canonical 2".to_string(),
                    token_count: 20,
                    entries: vec![FindingLinkCandidateEntry {
                        candidate_id: "sem-2".to_string(),
                        canonical_semantic_id: 2,
                        is_canonical: true,
                        category: DeFiCategory::Dexes,
                        name: "Canonical 2".to_string(),
                        prompt_body: "candidate-2".to_string(),
                        token_count: 20,
                    }],
                },
            ],
            60,
        );

        assert_eq!(batches.len(), 2);
        assert_eq!(
            batches[0]
                .iter()
                .map(|entry| entry.candidate_id.as_str())
                .collect::<Vec<_>>(),
            vec!["sem-1", "sem-101"]
        );
        assert_eq!(
            batches[1]
                .iter()
                .map(|entry| entry.candidate_id.as_str())
                .collect::<Vec<_>>(),
            vec!["sem-2"]
        );
    }

    #[test]
    fn group_finding_link_candidate_entries_requires_canonical_entry() {
        let error = group_finding_link_candidate_entries(vec![FindingLinkCandidateEntry {
            candidate_id: "sem-101".to_string(),
            canonical_semantic_id: 1,
            is_canonical: false,
            category: DeFiCategory::Dexes,
            name: "Alias 101".to_string(),
            prompt_body: "candidate-101".to_string(),
            token_count: 30,
        }])
        .expect_err("candidate groups should require the canonical semantic entry");

        assert!(
            error.to_string().contains(
                "Missing canonical semantic sem-1 while building finding-link candidate group"
            ),
            "unexpected error: {error}"
        );
    }
}
