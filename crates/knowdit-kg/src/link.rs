use crate::category::DeFiCategory;
use crate::db::DatabaseGraph;
use crate::error::{KgError, Result};
use crate::learn::{
    ExtractedFinding, count_tokens, get_context_budget, prompt_json_with_retry,
    sanitize_prompt_prefix,
};
use crate::prompts;
use color_eyre::eyre::eyre;
use itertools::Itertools;
use llmy::client::client::LLM;
use llmy::client::model::OpenAIModel;
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

#[derive(Debug, Deserialize)]
struct FindingLinkDecision {
    finding_id: String,
    semantic_ids: Vec<String>,
    #[allow(dead_code)]
    reasoning: String,
}

#[derive(Debug, Deserialize)]
struct FindingLinkBatchResponse {
    results: Vec<FindingLinkDecision>,
}

#[derive(Debug, thiserror::Error)]
enum FindingLinkBatchResponseError {
    #[error("Unknown semantic candidate id '{semantic_id}' in finding link response")]
    UnknownSemanticCandidateId { semantic_id: String },

    #[error(transparent)]
    Fatal(#[from] KgError),
}

impl FindingLinkBatchResponseError {
    fn fatal(message: impl Into<String>) -> Self {
        Self::Fatal(KgError::other(message))
    }

    fn into_kg_error(self) -> KgError {
        match self {
            Self::UnknownSemanticCandidateId { semantic_id } => KgError::other(format!(
                "Unknown semantic candidate id '{}' in finding link response",
                semantic_id
            )),
            Self::Fatal(err) => err,
        }
    }
}

#[derive(Debug, Clone)]
pub struct PendingFindingForLinking {
    pub finding_id: i32,
    pub link_target_finding_id: i32,
    pub categories: Vec<DeFiCategory>,
    pub finding: ExtractedFinding,
}

#[derive(Debug, Clone)]
pub struct PersistedFindingLinkResult {
    pub finding_id: i32,
    pub link_target_finding_id: i32,
    pub semantic_ids: Vec<i32>,
}

#[derive(Debug, Clone, Copy)]
pub struct FindingLinkOptions {
    pub concurrency: usize,
    pub input_token_budget: Option<usize>,
    pub finding_token_budget: Option<usize>,
    pub max_response_attempts: usize,
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
    status: String,
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

    fn for_category(category: DeFiCategory) -> Self {
        let mut categories = BTreeSet::new();
        categories.insert(category);
        Self {
            categories,
            semantic_chunk_index: 0,
        }
    }

    fn from_project_categories(categories: &[DeFiCategory]) -> Vec<Self> {
        let categories: BTreeSet<DeFiCategory> = categories.iter().copied().collect();
        if categories.is_empty() {
            return vec![Self::empty()];
        }

        categories.into_iter().map(Self::for_category).collect()
    }

    fn is_empty(&self) -> bool {
        self.categories.is_empty()
    }

    fn prompt_category(&self) -> Option<DeFiCategory> {
        self.categories.iter().next().copied()
    }

    fn semantic_categories(&self) -> Vec<DeFiCategory> {
        self.categories.iter().copied().collect()
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
        if self.categories.is_empty() {
            return "none".to_string();
        }

        let base = sanitize_prompt_prefix(
            &self
                .categories
                .iter()
                .map(DeFiCategory::as_str)
                .collect::<Vec<_>>()
                .join("-"),
        );

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
        db: &DatabaseGraph,
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

#[derive(Debug, Clone, Copy)]
struct FindingLinkBudgets {
    input_token_budget: usize,
    semantic_token_target: usize,
    finding_token_target: usize,
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

        Self {
            input_token_budget,
            semantic_token_target: shared_target,
            finding_token_target,
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
    semantic_ids: BTreeSet<i32>,
}

pub async fn link_pending_findings(
    db: &DatabaseGraph,
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
    let budgets = FindingLinkBudgets::from_options(&llm.model, options);
    tracing::info!(
        "Will link {} pending findings (concurrency={}, input token budget={}, target semantic tokens={}, target finding tokens={}, max response attempts={})",
        total_pending_findings,
        concurrency,
        budgets.input_token_budget,
        budgets.semantic_token_target,
        budgets.finding_token_target,
        max_response_attempts,
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
                    semantic_ids: BTreeSet::new(),
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
    if concurrency <= 1 {
        for batch in batches {
            let key = batch.context_key.clone();
            let context = contexts.get(&key).ok_or_else(|| {
                KgError::other(format!("Missing link context for key '{}'", key.label()))
            })?;

            match link_pending_findings_batch(llm, &batch, context.as_ref(), max_response_attempts)
                .await
            {
                Ok(results) => {
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

            handles.spawn(async move {
                while let Ok(batch) = rx.recv().await {
                    let result = match contexts.get(&batch.context_key) {
                        Some(context) => {
                            link_pending_findings_batch(
                                &llm_clone,
                                &batch,
                                context.as_ref(),
                                max_response_attempts,
                            )
                            .await
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
) -> Vec<Vec<FindingLinkBatchEntry>> {
    let mut batches = Vec::new();
    let mut current = Vec::new();
    let mut current_tokens = 0usize;

    for entry in entries {
        if !current.is_empty() && current_tokens + entry.token_count > token_budget {
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

        for batch_entries in partition_finding_link_entries(entries, finding_token_budget) {
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
    db: &DatabaseGraph,
    model: &OpenAIModel,
    base_context_key: &FindingLinkContextKey,
    budgets: &FindingLinkBudgets,
) -> Result<Vec<(FindingLinkContextKey, FindingLinkContext)>> {
    if base_context_key.is_empty() {
        return Ok(vec![(
            base_context_key.clone(),
            FindingLinkContext::build(model, base_context_key, Vec::new()),
        )]);
    }

    let semantic_categories = base_context_key.semantic_categories();
    let candidates: Vec<SemanticLinkCandidate> = db
        .semantic_link_candidates_for_categories(&semantic_categories)
        .await?
        .into_iter()
        .map(|(node, canonical_id)| {
            let is_canonical = node.id == canonical_id;
            SemanticLinkCandidate {
                candidate_id: format!("sem-{}", node.id),
                canonical_semantic_id: canonical_id,
                is_canonical,
                category: node.category,
                name: node.name,
                definition: node.definition,
                description: node.description,
                status: if is_canonical {
                    "active".to_string()
                } else {
                    format!("merged -> sem-{}", canonical_id)
                },
            }
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
    if candidate.is_canonical {
        return format!(
            "Candidate ID: {}\nStatus: {}\nCategory: {}\nName: {}\nDefinition: {}\nDescription: {}\n\n",
            candidate.candidate_id,
            candidate.status,
            candidate.category,
            candidate.name,
            candidate.definition,
            candidate.description
        );
    }

    format!(
        "Historical Alias ID: {}\nCanonical Link Target: sem-{}\nSelection Rule: If this alias is relevant, return sem-{} instead of the alias ID.\nStatus: {}\nCategory: {}\nName: {}\nDefinition: {}\nDescription: {}\n\n",
        candidate.candidate_id,
        candidate.canonical_semantic_id,
        candidate.canonical_semantic_id,
        candidate.status,
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
        aggregate.semantic_ids.extend(result.semantic_ids);
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
            semantic_ids: aggregate.semantic_ids.into_iter().collect(),
        });
    }

    final_results
}

fn mark_batch_findings_failed(failed_findings: &mut HashSet<i32>, batch: &FindingLinkBatch) {
    failed_findings.extend(batch.entries.iter().map(|entry| entry.pending.finding_id));
}

async fn link_pending_findings_batch(
    llm: &LLM,
    batch: &FindingLinkBatch,
    context: &FindingLinkContext,
    max_response_attempts: usize,
) -> Result<Vec<PersistedFindingLinkResult>> {
    if batch.entries.is_empty() {
        return Ok(Vec::new());
    }

    if context.candidate_map.is_empty() {
        tracing::info!(
            "No semantic candidates for finding batch {}, marking {} finding(s) as processed without links",
            batch,
            batch.entries.len()
        );
        return Ok(batch
            .entries
            .iter()
            .map(|entry| PersistedFindingLinkResult {
                finding_id: entry.pending.finding_id,
                link_target_finding_id: entry.pending.link_target_finding_id,
                semantic_ids: Vec::new(),
            })
            .collect());
    }

    let mut user_msg = context.prompt_prefix.clone();
    for entry in &batch.entries {
        user_msg.push_str(&entry.prompt_body);
    }

    tracing::info!(
        "Linking finding batch {} ({} finding(s), ~{} semantic tokens, ~{} finding tokens, ~{} prompt tokens, finding_budget={}, input_budget={})",
        batch,
        batch.entries.len(),
        context.candidate_token_count,
        batch.finding_token_count,
        count_tokens(&llm.model, &user_msg),
        batch.finding_token_budget,
        batch.input_token_budget
    );

    let prompt_label = format!("finding linking for batch {}", batch);
    for attempt in 1..=max_response_attempts {
        let debug_key = format!("finding-link-{}-attempt-{}", batch, attempt);
        let parsed: FindingLinkBatchResponse = prompt_json_with_retry(
            llm,
            prompts::GENERAL_ROLE_SYSTEM,
            &user_msg,
            Some(&debug_key),
            Some(&context.cache_key),
            &prompt_label,
        )
        .await?;

        match resolve_finding_link_batch_response(parsed, batch, context) {
            Ok(results) => return Ok(results),
            Err(FindingLinkBatchResponseError::UnknownSemanticCandidateId { semantic_id })
                if attempt < max_response_attempts =>
            {
                tracing::warn!(
                    "Finding-link batch {} returned unknown semantic candidate id '{}' on attempt {}/{}; retrying batch",
                    batch,
                    semantic_id,
                    attempt,
                    max_response_attempts,
                );
            }
            Err(FindingLinkBatchResponseError::UnknownSemanticCandidateId { semantic_id }) => {
                return Err(KgError::other(format!(
                    "Finding-link batch {} kept returning unknown semantic candidate id '{}' after {} attempt(s)",
                    batch, semantic_id, max_response_attempts,
                )));
            }
            Err(err) => return Err(err.into_kg_error()),
        }
    }

    Err(eyre!("fail to get result in {} retries", max_response_attempts).into())
}

fn resolve_finding_link_batch_response(
    parsed: FindingLinkBatchResponse,
    batch: &FindingLinkBatch,
    context: &FindingLinkContext,
) -> std::result::Result<Vec<PersistedFindingLinkResult>, FindingLinkBatchResponseError> {
    let expected_by_prompt_id: HashMap<&str, &FindingLinkBatchEntry> = batch
        .entries
        .iter()
        .map(|entry| (entry.prompt_finding_id.as_str(), entry))
        .collect();
    let mut seen_prompt_ids = HashSet::new();
    let mut results_by_finding_id = HashMap::new();

    for decision in parsed.results {
        let entry = expected_by_prompt_id
            .get(decision.finding_id.as_str())
            .ok_or_else(|| {
                FindingLinkBatchResponseError::fatal(format!(
                    "Finding link batch {} returned unknown finding id '{}'",
                    batch, decision.finding_id
                ))
            })?;
        if !seen_prompt_ids.insert(entry.prompt_finding_id.clone()) {
            return Err(FindingLinkBatchResponseError::fatal(format!(
                "Finding link batch {} returned duplicate finding id '{}'",
                batch, entry.prompt_finding_id
            )));
        }

        let semantic_ids = resolve_finding_link_semantic_ids(decision.semantic_ids, context)?;
        results_by_finding_id.insert(
            entry.pending.finding_id,
            PersistedFindingLinkResult {
                finding_id: entry.pending.finding_id,
                link_target_finding_id: entry.pending.link_target_finding_id,
                semantic_ids,
            },
        );
    }

    let missing_entries: Vec<&FindingLinkBatchEntry> = batch
        .entries
        .iter()
        .filter(|entry| !seen_prompt_ids.contains(&entry.prompt_finding_id))
        .collect();
    if !missing_entries.is_empty() {
        let missing_prompt_ids = missing_entries
            .iter()
            .map(|entry| entry.prompt_finding_id.clone())
            .collect::<Vec<_>>();
        tracing::warn!(
            "Finding link batch {} omitted finding ids: {}; treating them as no-link results",
            batch,
            missing_prompt_ids.join(", ")
        );
        for entry in missing_entries {
            results_by_finding_id.insert(
                entry.pending.finding_id,
                PersistedFindingLinkResult {
                    finding_id: entry.pending.finding_id,
                    link_target_finding_id: entry.pending.link_target_finding_id,
                    semantic_ids: Vec::new(),
                },
            );
        }
    }

    batch
        .entries
        .iter()
        .map(|entry| {
            results_by_finding_id
                .remove(&entry.pending.finding_id)
                .ok_or_else(|| {
                    FindingLinkBatchResponseError::fatal(format!(
                        "Finding link batch {} produced no persisted result for finding #{}",
                        batch, entry.pending.finding_id
                    ))
                })
        })
        .collect()
}

fn resolve_finding_link_semantic_ids(
    semantic_candidate_ids: Vec<String>,
    context: &FindingLinkContext,
) -> std::result::Result<Vec<i32>, FindingLinkBatchResponseError> {
    let mut semantic_ids = Vec::new();
    let mut seen = HashSet::new();

    for semantic_id in semantic_candidate_ids {
        let target_id = *context.candidate_map.get(&semantic_id).ok_or_else(|| {
            FindingLinkBatchResponseError::UnknownSemanticCandidateId { semantic_id }
        })?;
        if seen.insert(target_id) {
            semantic_ids.push(target_id);
        }
    }

    Ok(semantic_ids)
}

fn prompt_finding_id(finding_id: i32) -> String {
    format!("finding-{}", finding_id)
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
        );

        assert_eq!(batches.len(), 2);
        assert_eq!(batches[0].len(), 1);
        assert_eq!(batches[0][0].pending.finding_id, 201);
        assert_eq!(batches[1].len(), 1);
        assert_eq!(batches[1][0].pending.finding_id, 202);
    }

    #[test]
    fn resolve_finding_link_batch_response_maps_and_deduplicates_semantics() {
        let batch = FindingLinkBatch {
            context_key: sample_context_key(DeFiCategory::Dexes),
            entries: vec![sample_batch_entry(301, 20), sample_batch_entry(302, 20)],
            finding_token_count: 40,
            finding_token_budget: 100,
            input_token_budget: 300,
        };
        let context = FindingLinkContext {
            prompt_prefix: String::new(),
            prompt_prefix_tokens: 0,
            candidate_token_count: 20,
            candidate_map: HashMap::from([
                ("sem-1".to_string(), 1),
                ("sem-merged".to_string(), 1),
                ("sem-2".to_string(), 2),
            ]),
            cache_key: "finding-link-dexes".to_string(),
        };
        let parsed = FindingLinkBatchResponse {
            results: vec![
                FindingLinkDecision {
                    finding_id: "finding-301".to_string(),
                    semantic_ids: vec![
                        "sem-1".to_string(),
                        "sem-merged".to_string(),
                        "sem-2".to_string(),
                    ],
                    reasoning: "related".to_string(),
                },
                FindingLinkDecision {
                    finding_id: "finding-302".to_string(),
                    semantic_ids: vec![],
                    reasoning: "none".to_string(),
                },
            ],
        };

        let resolved = resolve_finding_link_batch_response(parsed, &batch, &context)
            .expect("batch response should resolve");

        assert_eq!(resolved.len(), 2);
        assert_eq!(resolved[0].finding_id, 301);
        assert_eq!(resolved[0].semantic_ids, vec![1, 2]);
        assert_eq!(resolved[1].finding_id, 302);
        assert!(resolved[1].semantic_ids.is_empty());
    }

    #[test]
    fn resolve_finding_link_batch_response_defaults_missing_findings_to_no_links() {
        let batch = FindingLinkBatch {
            context_key: sample_context_key(DeFiCategory::Dexes),
            entries: vec![sample_batch_entry(401, 20), sample_batch_entry(402, 20)],
            finding_token_count: 40,
            finding_token_budget: 100,
            input_token_budget: 300,
        };
        let context = FindingLinkContext {
            prompt_prefix: String::new(),
            prompt_prefix_tokens: 0,
            candidate_token_count: 10,
            candidate_map: HashMap::from([("sem-1".to_string(), 1)]),
            cache_key: "finding-link-dexes".to_string(),
        };
        let parsed = FindingLinkBatchResponse {
            results: vec![FindingLinkDecision {
                finding_id: "finding-401".to_string(),
                semantic_ids: vec!["sem-1".to_string()],
                reasoning: "related".to_string(),
            }],
        };

        let resolved = resolve_finding_link_batch_response(parsed, &batch, &context)
            .expect("missing batch entries should default to empty semantic links");
        assert_eq!(resolved.len(), 2);
        assert_eq!(resolved[0].finding_id, 401);
        assert_eq!(resolved[0].semantic_ids, vec![1]);
        assert_eq!(resolved[1].finding_id, 402);
        assert!(resolved[1].semantic_ids.is_empty());
    }

    #[test]
    fn resolve_finding_link_semantic_ids_marks_unknown_ids_retryable() {
        let context = FindingLinkContext {
            prompt_prefix: String::new(),
            prompt_prefix_tokens: 0,
            candidate_token_count: 10,
            candidate_map: HashMap::from([("sem-1".to_string(), 1)]),
            cache_key: "finding-link-dexes".to_string(),
        };

        let error = resolve_finding_link_semantic_ids(vec!["sem-404".to_string()], &context)
            .expect_err("unknown semantic ids should request a retry");

        assert!(matches!(
            error,
            FindingLinkBatchResponseError::UnknownSemanticCandidateId { semantic_id }
                if semantic_id == "sem-404"
        ));
    }

    #[test]
    fn merge_finding_link_batch_results_aggregates_multiple_categories() {
        let mut aggregated_results = HashMap::from([(
            501,
            AggregatedFindingLinkResult {
                finding_id: 501,
                link_target_finding_id: 777,
                expected_contexts: 2,
                completed_contexts: 0,
                semantic_ids: BTreeSet::new(),
            },
        )]);

        merge_finding_link_batch_results(
            &mut aggregated_results,
            vec![PersistedFindingLinkResult {
                finding_id: 501,
                link_target_finding_id: 777,
                semantic_ids: vec![3, 1],
            }],
        )
        .expect("first category result should merge");

        merge_finding_link_batch_results(
            &mut aggregated_results,
            vec![PersistedFindingLinkResult {
                finding_id: 501,
                link_target_finding_id: 777,
                semantic_ids: vec![2, 3],
            }],
        )
        .expect("second category result should merge");

        let mut failed_findings = HashSet::new();
        let results = finalize_finding_link_results(aggregated_results, &mut failed_findings);

        assert!(failed_findings.is_empty());
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].finding_id, 501);
        assert_eq!(results[0].link_target_finding_id, 777);
        assert_eq!(results[0].semantic_ids, vec![1, 2, 3]);
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
                semantic_ids: BTreeSet::from([1, 2]),
            },
        )]);

        let mut failed_findings = HashSet::new();
        let results = finalize_finding_link_results(aggregated_results, &mut failed_findings);

        assert!(results.is_empty());
        assert!(failed_findings.contains(&601));
    }

    #[test]
    fn finding_link_context_plan_splits_distinct_categories() {
        let finding = sample_finding_with_categories(
            701,
            vec![
                DeFiCategory::Yield,
                DeFiCategory::Dexes,
                DeFiCategory::Yield,
            ],
        );

        let context_keys = FindingLinkContextKey::from_project_categories(&finding.categories);
        assert_eq!(context_keys.len(), 2);
        assert!(context_keys.contains(&sample_context_key(DeFiCategory::Dexes)));
        assert!(context_keys.contains(&sample_context_key(DeFiCategory::Yield)));
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
