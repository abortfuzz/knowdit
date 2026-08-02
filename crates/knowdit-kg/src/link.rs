use crate::agent_runner::{AgentChunkBuffer, AgentChunkRunner, AgentRunOptions};
use crate::agents::FinalizeArgs;
use crate::category::DeFiCategory;
use crate::db::HistoricalDatabase;
use crate::error::{KgError, Result};
use crate::learn::{ExtractedFinding, get_context_budget, sanitize_prompt_prefix};
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
/// Under the "forced per-candidate emit" contract,
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
    /// Absolute ceiling on total input tokens per prompt. `None` ⇒ derived from
    /// the model window × `context_window_utilization`; can only lower it.
    pub input_token_budget: Option<usize>,
    /// Share of the input budget reserved for the findings block. The
    /// semantic-candidate block is NOT separately configured — it takes ALL
    /// remaining input after findings + system + prefix, so it fills the window
    /// automatically (lower this ⇒ more room for semantics ⇒ fewer / zero
    /// candidate chunks). Must be in (0, 1); the CLI defaults it to 0.35.
    pub finding_token_ratio: f64,
    /// Hard ceiling on canonical semantics (candidates) per chunk — the count
    /// analogue of the token budget. Raw-children candidates vary wildly in size,
    /// so the token budget alone can't pin the candidate *count*; this does.
    /// `usize::MAX` ⇒ token-only chunking (the CLI default).
    pub max_semantics_per_batch: usize,
    /// Hard ceiling on findings per batch — independent of token
    /// budget. The token-based partitioner would happily pack 400+
    /// findings into a single batch on small-finding KGs (e.g. the
    /// Move KG: ~150 tok/finding × 459 findings ≈ 70K tok, fits
    /// in one 72K budget), but agents in practice can only stably
    /// emit decisions for a few dozen findings per attempt before
    /// finalizing prematurely. Cap both ways: token budget AND
    /// finding count. The CLI defaults this to 135, which also bounds
    /// the agent conversation's terminal size (each finding adds
    /// ~230-310 tokens of emit output) so runs stay inside 256K-window
    /// models; 0 is clamped to 1.
    pub max_findings_per_batch: usize,
    /// Max attempts per (finding-batch × semantic-chunk) — if the agent
    /// finalizes without covering every finding in the batch, the runner
    /// re-runs a fresh agent restricted to the still-missing findings.
    /// After this many attempts the missing findings are treated as
    /// `no-link` and a warning is logged.
    pub max_response_attempts: usize,
    /// Per-attempt cap on agent steps (inner step loop, not the
    /// missing-coverage retry counter).
    pub max_agent_steps: usize,
    /// Minimum byte length of `why_finding_can_fire` for High/Medium entries.
    /// Low rationales are short by design (audit trail, not downstream
    /// consumption); High and Medium must be substantive enough to justify
    /// the claim.
    pub evidence_min_high_medium: usize,
    /// Minimum byte length of `why_finding_can_fire` for Low entries.
    pub evidence_min_low: usize,
    /// Minimum normalized length of a quoted span for the High verbatim-quote
    /// check (~6 words at the CLI default). Blind evals caught agents attaching
    /// well-written evidence to the WRONG finding_id in large batches (the
    /// quoted "finding text" existed verbatim in a DIFFERENT finding);
    /// requiring a quote that mechanically appears in the referenced finding's
    /// own body turns that silent mis-attribution into a correctable tool
    /// error.
    pub high_quote_min_chars: usize,
    pub include_unlinked: bool,
    /// Cross-seam scope for the merge-kg ③b pass: when `Some(max)`, only
    /// canonical semantics with `id <= max` are offered as link candidates.
    /// `None` (the default) presents every canonical, matching the standard
    /// exhaustive `link` behaviour used by `workflow learn`.
    pub candidate_max_semantic_id: Option<i32>,
    /// Fraction of the model's context window a single link prompt may fill.
    /// Defaults to [`crate::learn::DEFAULT_CONTEXT_WINDOW_UTILIZATION`];
    /// overridable per-command (e.g. `merge-kg`).
    pub context_window_utilization: f64,
    /// Max merged variants (count) rendered under each canonical candidate AND
    /// under each finding, so a heavily-merged node does not blow up the prompt.
    /// The CLI defaults this to 8.
    pub variant_render_cap: usize,
    /// When true, render merged variants as each folded child's **full raw text**
    /// ([`VariantMode::RawChildren`]) instead of the compact
    /// `appended_*` deltas — richer link context (approaching the pre-Option-A
    /// inline density exp linked on) at the cost of larger prompts. Applies to
    /// both the semantic candidate and the finding entry.
    pub render_raw_children: bool,
    /// Per-variant char cap applied only in raw-children mode (`0` = unbounded),
    /// so one bloated child cannot dominate the prompt. The CLI defaults this
    /// to 400.
    pub raw_child_char_cap: usize,
}

#[derive(Debug, Clone)]
pub(crate) struct SemanticLinkCandidate {
    pub(crate) candidate_id: String,
    pub(crate) canonical_semantic_id: i32,
    pub(crate) is_canonical: bool,
    pub(crate) category: DeFiCategory,
    pub(crate) name: String,
    pub(crate) definition: String,
    pub(crate) description: String,
    /// `appended_description` notes of the raws folded into this canonical —
    /// each variant's concrete delta beyond `description`.
    pub(crate) variant_notes: Vec<String>,
}

#[derive(Debug, Clone)]
struct FindingLinkContext {
    prompt_prefix: String,
    prompt_prefix_tokens: usize,
    candidate_token_count: usize,
    candidate_map: HashMap<String, i32>,
    slug: String,
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

    fn context_slug(&self) -> String {
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
            prompt_prefix_tokens: model.config.count_tokens_lossy(&prompt_prefix),
            prompt_prefix,
            candidate_token_count,
            candidate_map,
            slug: context_key.context_slug(),
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

        // In raw-children mode, fetch each finding's folded raw children so the
        // finding entry can render its full merged variants (parity with the
        // semantic candidate side). Compact mode renders the canonical only.
        let finding_children: HashMap<i32, FindingRawChildren> = if budgets.render_raw_children {
            let mut ids: Vec<i32> = expanded_pending
                .values()
                .flat_map(|pendings| pendings.iter().map(|p| p.finding_id))
                .collect();
            ids.sort_unstable();
            ids.dedup();
            db.finding_children_with_notes(&ids)
                .await?
                .into_iter()
                .map(|(finding_id, children)| {
                    let mut raw = FindingRawChildren::default();
                    for (child, _, _, _) in children {
                        raw.root_causes
                            .push(label_variant(&child.title, child.root_cause));
                        raw.descriptions
                            .push(label_variant(&child.title, child.description));
                        raw.patterns
                            .push(label_variant(&child.title, child.patterns));
                        raw.exploits
                            .push(label_variant(&child.title, child.exploits));
                    }
                    (finding_id, raw)
                })
                .collect()
        } else {
            HashMap::new()
        };

        let batches = budgets.build_finding_link_batches(
            model,
            expanded_pending,
            &contexts,
            &finding_children,
        )?;

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
    finding_token_target: usize,
    /// Independent of token budget: hard cap on findings per batch.
    /// `partition_finding_link_entries` honours `min(token, count)`.
    max_findings_per_batch: usize,
    /// Count cap on candidate semantics per chunk (the semantic block otherwise
    /// takes all input left after findings). `partition_finding_link_candidate_groups`
    /// honours `min(token, count)`.
    max_semantics_per_batch: usize,
    /// Cross-seam candidate ceiling (merge-kg ③b). `None` ⇒ all canonicals.
    candidate_max_semantic_id: Option<i32>,
    /// Cap on merged-variant notes rendered per candidate.
    variant_render_cap: usize,
    /// Render merged variants as full raw child text vs compact deltas.
    render_raw_children: bool,
    /// Per-variant char cap in raw-children mode (0 = unbounded).
    raw_child_char_cap: usize,
}

impl FindingLinkBudgets {
    /// Per-variant char cap to pass the shared renderer: the configured cap in
    /// raw-children mode, or 0 (no truncation) in compact mode where notes are
    /// already short.
    fn effective_child_char_cap(&self) -> usize {
        if self.render_raw_children {
            self.raw_child_char_cap
        } else {
            0
        }
    }
}

impl FindingLinkBudgets {
    fn from_options(model: &OpenAIModel, options: FindingLinkOptions) -> Self {
        let max_input_budget = get_context_budget(model, options.context_window_utilization).max(1);
        let input_token_budget = options
            .input_token_budget
            .unwrap_or(max_input_budget)
            .min(max_input_budget)
            .max(1);
        let finding_token_target =
            ((input_token_budget as f64 * options.finding_token_ratio) as usize).max(1);
        let max_findings_per_batch = options.max_findings_per_batch.max(1);
        let max_semantics_per_batch = options.max_semantics_per_batch.max(1);

        Self {
            input_token_budget,
            finding_token_target,
            max_findings_per_batch,
            max_semantics_per_batch,
            candidate_max_semantic_id: options.candidate_max_semantic_id,
            variant_render_cap: options.variant_render_cap,
            render_raw_children: options.render_raw_children,
            raw_child_char_cap: options.raw_child_char_cap,
        }
    }

    fn semantic_token_budget(
        &self,
        model: &OpenAIModel,
        prompt_category: Option<DeFiCategory>,
    ) -> Result<usize> {
        let system_tokens = model
            .config
            .count_tokens_lossy(prompts::GENERAL_ROLE_SYSTEM);
        let stable_prefix_tokens = model
            .config
            .count_tokens_lossy(&prompts::finding_link_user_prefix(prompt_category, ""));
        // The semantic block takes ALL input left after findings + system +
        // prefix — no separate semantic ratio. Lowering finding_token_ratio (or
        // raising utilization) directly widens this, fitting more canonicals per
        // prompt and reducing the number of candidate chunks.
        let effective = self
            .input_token_budget
            .saturating_sub(system_tokens + stable_prefix_tokens + self.finding_token_target);

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
        let system_tokens = model
            .config
            .count_tokens_lossy(prompts::GENERAL_ROLE_SYSTEM);
        let available = self
            .input_token_budget
            .saturating_sub(system_tokens + context.prompt_prefix_tokens);
        let effective = self.finding_token_target.min(available);

        if effective == 0 {
            return Err(KgError::other(format!(
                "Finding link context '{}' leaves no room for batched findings under input budget {}",
                context.slug, self.input_token_budget
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

impl FindingLinkOptions {
    /// Startup sanity warnings for the coupled shape knobs — changing one of
    /// (window utilization, max_findings_per_batch, finding_token_ratio)
    /// without re-tuning the others silently drifts the batch shape, so an
    /// out-of-tune combination warns at launch instead of surfacing as a bad
    /// KG hours and dollars later.
    fn warn_param_drift(&self, model: &OpenAIModel) {
        let per_mille_per_finding =
            self.context_window_utilization * 1000.0 / self.max_findings_per_batch.max(1) as f64;
        if !(1.2..=1.5).contains(&per_mille_per_finding) {
            let lo = (self.context_window_utilization * 1000.0 / 1.5).round() as usize;
            let hi = (self.context_window_utilization * 1000.0 / 1.2).round() as usize;
            tracing::warn!(
                "link shape knobs look out of tune: utilization×1000/max_findings_per_batch = {:.2}, expected 1.2–1.5. At utilization {} a matched batch cap is ~{}–{} findings; scaling one knob without the other drifts batch density and the agent's terminal context size.",
                per_mille_per_finding,
                self.context_window_utilization,
                lo,
                hi,
            );
        }
        if !(0.3..=0.5).contains(&self.finding_token_ratio) {
            tracing::warn!(
                "finding_token_ratio {} is outside the tuned 0.3–0.5 band: below it the finding block starves (tiny chatty batches), above it the semantic block starves (dense candidate chunks).",
                self.finding_token_ratio,
            );
        }
        if let Some(explicit) = self.input_token_budget {
            let derived = get_context_budget(model, self.context_window_utilization).max(1);
            if explicit > derived {
                tracing::warn!(
                    "--input-token-budget {} exceeds window×utilization = {} and will be CLAMPED to {}; raise --link-context-window-utilization if the explicit budget is intended.",
                    explicit,
                    derived,
                    derived,
                );
            }
        }
    }

    pub async fn link_pending_findings(self, db: &HistoricalDatabase, llm: &LLM) -> Result<()> {
        self.warn_param_drift(&llm.model);
        use std::sync::Arc;
        use tokio::sync::mpsc;
        use tokio::task::JoinSet;

        let pending_findings = db.list_findings_for_linking(self.include_unlinked).await?;
        if pending_findings.is_empty() {
            tracing::info!("No findings pending linking.");
            return Ok(());
        }

        let total_pending_findings = pending_findings.len();
        let concurrency = self.concurrency.max(1);
        let max_response_attempts = self.max_response_attempts.max(1);
        let evidence_min_high_medium = self.evidence_min_high_medium;
        let evidence_min_low = self.evidence_min_low;
        let high_quote_min_chars = self.high_quote_min_chars;
        let agent_options = AgentRunOptions::new(self.max_agent_steps);
        let budgets = FindingLinkBudgets::from_options(&llm.model, self);
        tracing::info!(
            "Will link {} pending findings (concurrency={}, input token budget={}, finding token budget={}, semantic budget=rest of input after findings, max response attempts={}, max agent steps={})",
            total_pending_findings,
            concurrency,
            budgets.input_token_budget,
            budgets.finding_token_target,
            max_response_attempts,
            self.max_agent_steps,
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
                        expected_contexts: execution_plan
                            .expected_context_count(pending.finding_id),
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
                    evidence_min_high_medium,
                    evidence_min_low,
                    high_quote_min_chars,
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
                                    evidence_min_high_medium,
                                    evidence_min_low,
                                    high_quote_min_chars,
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
            let retry_hint = if self.include_unlinked {
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
}

fn partition_finding_link_entries(
    entries: Vec<FindingLinkBatchEntry>,
    token_budget: usize,
    max_count: usize,
) -> Vec<Vec<FindingLinkBatchEntry>> {
    let mut batches = Vec::new();
    let mut current = Vec::new();
    let mut current_tokens = 0usize;
    // Tokens left on the table each time the COUNT cap closed a batch before the
    // token budget was full (window under-filled because of the cap, not lack of room).
    let mut count_capped_slack: Vec<usize> = Vec::new();

    for entry in entries {
        let count_exceeded = current.len() >= max_count;
        let tokens_exceeded = current_tokens + entry.token_count > token_budget;
        if !current.is_empty() && (count_exceeded || tokens_exceeded) {
            if count_exceeded && !tokens_exceeded {
                count_capped_slack.push(token_budget.saturating_sub(current_tokens));
            }
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

    log_count_cap_slack(
        "finding",
        "--max-findings-per-batch",
        "lower --finding-token-ratio so the slack goes to semantic candidates",
        max_count,
        token_budget,
        &count_capped_slack,
    );

    batches
}

fn partition_finding_link_candidate_groups(
    groups: Vec<FindingLinkCandidateGroup>,
    token_budget: usize,
    max_count: usize,
) -> Vec<Vec<FindingLinkCandidateEntry>> {
    let mut batches = Vec::new();
    let mut current = Vec::new();
    let mut current_tokens = 0usize;
    let mut current_count = 0usize;
    // Tokens left on the table each time the COUNT cap closed a chunk before the
    // token budget was full (window under-filled because of the cap, not lack of room).
    let mut count_capped_slack: Vec<usize> = Vec::new();

    for group in groups {
        // Split on EITHER limit: token budget or candidate count. A group is one
        // canonical (+ its aliases), so `current_count` tracks canonicals/chunk.
        let over_tokens = current_tokens + group.token_count > token_budget;
        let over_count = current_count + 1 > max_count;
        if !current.is_empty() && (over_tokens || over_count) {
            if over_count && !over_tokens {
                count_capped_slack.push(token_budget.saturating_sub(current_tokens));
            }
            batches.push(current);
            current = Vec::new();
            current_tokens = 0;
            current_count = 0;
        }

        current_tokens += group.token_count;
        current_count += 1;
        current.extend(group.entries);
    }

    if !current.is_empty() {
        batches.push(current);
    }

    log_count_cap_slack(
        "semantic",
        "--max-semantics-per-batch",
        "lower --link-context-window-utilization or raise --finding-token-ratio",
        max_count,
        token_budget,
        &count_capped_slack,
    );

    batches
}

/// Info-level fill report for when a COUNT cap closed one or more batches
/// *before* the token budget filled. This is EXPECTED behaviour, not an
/// anomaly: the finding cap default (135) is a deliberate terminal-context
/// bound that binds on small-finding corpora, and an explicit semantic cap is
/// a deliberate sparse-chunk choice — hence info, not warn (mistuned knob
/// COMBINATIONS are what `warn_param_drift` warns about). The idle slack is
/// NOT handed to the semantic block: semantic chunks are partitioned once per
/// context and shared by every finding batch (per-chunk prompt caching), so
/// the semantic budget subtracts the finding token TARGET, not per-batch
/// actual usage; rebalancing is an offline `--finding-token-ratio` decision.
/// Silent when no cap bound (`count_capped_slack` empty).
fn log_count_cap_slack(
    kind: &str,
    cap_flag: &str,
    shrink_budget_hint: &str,
    max_count: usize,
    token_budget: usize,
    count_capped_slack: &[usize],
) {
    if count_capped_slack.is_empty() || token_budget == 0 {
        return;
    }
    let n = count_capped_slack.len();
    let total: usize = count_capped_slack.iter().sum();
    let avg = total / n;
    let pct = avg as f64 / token_budget as f64 * 100.0;
    tracing::info!(
        "{} count cap {}={} closed {} batch(es) before filling the {}-token budget: each capped batch leaves ~{} tokens (~{:.0}%) of that budget idle. To reclaim it, shrink this block's token budget ({}); raising the cap also works but keep it inside the tuned utilization×1000/cap = 1.2–1.5 band (see the shape-drift warning).",
        kind,
        cap_flag,
        max_count,
        n,
        token_budget,
        avg,
        pct,
        shrink_budget_hint
    );
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

/// A canonical finding's folded raw children, split by field, so the finding
/// entry can render its full merged variants in raw-children mode (parity with
/// the semantic candidate side). Empty in compact mode.
#[derive(Default)]
struct FindingRawChildren {
    root_causes: Vec<String>,
    descriptions: Vec<String>,
    patterns: Vec<String>,
    exploits: Vec<String>,
}

/// Prefix a folded raw's field text with its source name — `from raw "<name>":
/// <text>` — so the merged-variant block reads as distinct, named sub-mechanisms
/// (restores the labelling the anonymous `Merged variants` bullets had dropped).
pub(crate) fn label_variant(name: &str, text: String) -> String {
    let name = name.trim();
    if name.is_empty() {
        format!("additional context: {text}")
    } else {
        format!("additional context (from raw \"{name}\"): {text}")
    }
}

impl FindingRawChildren {
    /// Render each finding field as the bounded canonical value followed by up
    /// to `cap` folded raw children (each capped to `per_child_chars`).
    /// Returns `(root_cause, description, patterns, exploits)`.
    fn render(
        &self,
        finding: &ExtractedFinding,
        cap: usize,
        per_child_chars: usize,
    ) -> (String, String, String, String) {
        use knowdit_kg_model::render::render_with_variants_capped as render;
        (
            render(&finding.root_cause, &self.root_causes, cap, per_child_chars),
            render(
                &finding.description,
                &self.descriptions,
                cap,
                per_child_chars,
            ),
            render(&finding.patterns, &self.patterns, cap, per_child_chars),
            render(&finding.exploits, &self.exploits, cap, per_child_chars),
        )
    }
}

impl FindingLinkBudgets {
    fn build_finding_link_batches(
        &self,
        model: &OpenAIModel,
        pending_by_context: BTreeMap<FindingLinkContextKey, Vec<PendingFindingForLinking>>,
        contexts: &BTreeMap<FindingLinkContextKey, std::sync::Arc<FindingLinkContext>>,
        finding_children: &HashMap<i32, FindingRawChildren>,
    ) -> Result<Vec<FindingLinkBatch>> {
        let mut batches = Vec::new();

        for (context_key, pending_findings) in pending_by_context {
            let context = contexts.get(&context_key).ok_or_else(|| {
                KgError::other(format!(
                    "Missing link context for key '{}'",
                    context_key.label()
                ))
            })?;
            let finding_token_budget = self.finding_token_budget(model, context.as_ref())?;

            let entries = pending_findings
                .into_iter()
                .map(|pending| {
                    let prompt_finding_id = prompt_finding_id(pending.finding_id);
                    // Raw-children mode renders the canonical fields + folded raw
                    // children; compact mode (empty map) renders canonical only.
                    let prompt_body = match finding_children.get(&pending.finding_id) {
                        Some(children) => {
                            let (root_cause, description, patterns, exploits) = children.render(
                                &pending.finding,
                                self.variant_render_cap,
                                self.raw_child_char_cap,
                            );
                            prompts::finding_link_finding_entry(
                                &prompt_finding_id,
                                &pending.categories,
                                &pending.finding.title,
                                pending.finding.severity,
                                pending.finding.category,
                                &pending.finding.subcategory,
                                &root_cause,
                                &description,
                                &patterns,
                                &exploits,
                            )
                        }
                        None => prompts::finding_link_finding_entry(
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
                        ),
                    };
                    let token_count = model.config.count_tokens_lossy(&prompt_body);
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
                self.max_findings_per_batch,
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
                    input_token_budget: self.input_token_budget,
                });
            }
        }

        Ok(batches)
    }
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
    // Merged-variant entries per canonical, so each candidate renders its folded
    // raws alongside the (bounded) canonical description. Compact mode uses the
    // short `appended_description` deltas; raw-children mode uses each folded
    // child's full raw description (bounded per-entry by the char cap).
    let candidate_nodes = db.all_canonical_semantic_link_candidates().await?;
    let mut variant_notes: HashMap<i32, Vec<String>> = if budgets.render_raw_children {
        let candidate_ids: Vec<i32> = candidate_nodes.iter().map(|node| node.id).collect();
        db.semantic_children_with_notes(&candidate_ids)
            .await?
            .into_iter()
            .map(|(canonical_id, children)| {
                (
                    canonical_id,
                    children
                        .into_iter()
                        .map(|(child, _note)| label_variant(&child.name, child.description))
                        .collect(),
                )
            })
            .collect()
    } else {
        db.semantic_merge_appended_notes().await?
    };
    let candidates: Vec<SemanticLinkCandidate> = candidate_nodes
        .into_iter()
        // merge-kg ③b: restrict to the destination's pre-import (native)
        // canonicals so a source finding is only cross-linked against the
        // opposite KG's semantics; its own KG's links were carried verbatim.
        .filter(|node| {
            budgets
                .candidate_max_semantic_id
                .is_none_or(|max| node.id <= max)
        })
        .map(|node| SemanticLinkCandidate {
            candidate_id: format!("sem-{}", node.id),
            canonical_semantic_id: node.id,
            is_canonical: true,
            category: node.category,
            variant_notes: variant_notes.remove(&node.id).unwrap_or_default(),
            name: node.name,
            definition: node.definition,
            description: node.description,
        })
        .collect();

    let candidate_entries: Vec<FindingLinkCandidateEntry> = candidates
        .into_iter()
        .map(|candidate| {
            let prompt_body = candidate.render(
                budgets.variant_render_cap,
                budgets.effective_child_char_cap(),
            );
            FindingLinkCandidateEntry {
                candidate_id: candidate.candidate_id,
                canonical_semantic_id: candidate.canonical_semantic_id,
                is_canonical: candidate.is_canonical,
                category: candidate.category,
                name: candidate.name,
                token_count: model.config.count_tokens_lossy(&prompt_body),
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
    let candidate_chunks = partition_finding_link_candidate_groups(
        candidate_groups,
        semantic_token_budget,
        budgets.max_semantics_per_batch,
    );

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

impl SemanticLinkCandidate {
    /// Render this candidate for the link prompt: the bounded canonical
    /// description followed by up to `variant_cap` merged-variant entries
    /// (compact deltas or full raw children, per the caller), each capped to
    /// `per_child_char_cap` chars.
    pub(crate) fn render(&self, variant_cap: usize, per_child_char_cap: usize) -> String {
        let description = knowdit_kg_model::render::render_with_variants_capped(
            &self.description,
            &self.variant_notes,
            variant_cap,
            per_child_char_cap,
        );
        format!(
            "Candidate ID: {}\nCategory: {}\nName: {}\nDefinition: {}\nDescription: {}\n\n",
            self.candidate_id, self.category, self.name, self.definition, description
        )
    }
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
    /// `prompt_finding_id` → normalized rendered finding body, used to verify
    /// that a High entry's quoted fragment really comes from THE finding it is
    /// attached to (catches cross-finding evidence mis-attribution in large
    /// batches — see `FindingLinkOptions::high_quote_min_chars`).
    finding_bodies: Arc<HashMap<String, String>>,
    /// Evidence-length floors and the High quote-span floor, from
    /// [`FindingLinkOptions`].
    evidence_min_high_medium: usize,
    evidence_min_low: usize,
    high_quote_min_chars: usize,
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

/// Every run of non-quote characters that immediately FOLLOWS a `"` in the
/// (normalized) evidence text. Deliberately not a balanced `"..."` pair match:
/// a stray or nested quote inverts open/close parity and a pair-matcher would
/// hide the real quote inside an "even" segment, falsely rejecting a
/// well-grounded High. An off-parity segment is the model's own prose and only
/// passes the guard if it verbatim-overlaps the finding's body at span length
/// — which is grounding either way.
static QUOTED_SPAN_RE: std::sync::LazyLock<regex::Regex> =
    std::sync::LazyLock::new(|| regex::Regex::new(r#""([^"]+)"#).expect("literal regex"));

/// Lowercase, straighten curly quotes, and collapse whitespace so verbatim-
/// quote membership survives line wrapping and case drift between the prompt
/// rendering and the model's copy of it.
fn normalize_for_quote_match(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut last_space = false;
    for c in s.chars() {
        let c = match c {
            '\u{201C}' | '\u{201D}' => '"',
            '\u{2018}' | '\u{2019}' => '\'',
            c => c,
        };
        if c.is_whitespace() {
            if !last_space {
                out.push(' ');
                last_space = true;
            }
        } else {
            for lc in c.to_lowercase() {
                out.push(lc);
            }
            last_space = false;
        }
    }
    out
}

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
        // mapper's ~16): asking for a verdict on every candidate blew the
        // context and degraded the verdicts that were emitted.
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
                    evidence.semantic_id, args.finding_id, self.evidence_min_low,
                ));
            }
            let floor = match strength {
                knowdit_kg_model::link_strength::LinkStrength::High
                | knowdit_kg_model::link_strength::LinkStrength::Medium => {
                    self.evidence_min_high_medium
                }
                knowdit_kg_model::link_strength::LinkStrength::Low => self.evidence_min_low,
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
            if matches!(
                strength,
                knowdit_kg_model::link_strength::LinkStrength::High
            ) && let Some(body) = self.finding_bodies.get(&args.finding_id)
            {
                let norm_ev = normalize_for_quote_match(trimmed);
                let spans: Vec<&str> = QUOTED_SPAN_RE
                    .captures_iter(&norm_ev)
                    .filter_map(|c| c.get(1))
                    .map(|m| m.as_str().trim())
                    .filter(|s| s.len() >= self.high_quote_min_chars)
                    .collect();
                if spans.is_empty() {
                    return Ok(format!(
                        "error: High evidence for semantic_id '{}' under finding '{}' must include a VERBATIM fragment (>= 6 consecutive words, wrapped in double quotes) copied from that finding's own root_cause/description text. Re-emit with a real quote, or demote the entry.",
                        evidence.semantic_id, args.finding_id,
                    ));
                }
                if !spans.iter().any(|s| body.contains(s)) {
                    return Ok(format!(
                        "error: none of the quoted fragments in your High evidence for finding '{}' appear in that finding's own text. You may have MIXED UP finding ids — this evidence may describe a different finding in the prompt. Re-check which finding this evidence is really about and re-emit it under that finding_id (or demote/drop this entry).",
                        args.finding_id,
                    ));
                }
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
    evidence_min_high_medium: usize,
    evidence_min_low: usize,
    high_quote_min_chars: usize,
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
            let finding_bodies: Arc<HashMap<String, String>> = Arc::new(
                still_missing
                    .iter()
                    .map(|entry| {
                        (
                            entry.prompt_finding_id.clone(),
                            normalize_for_quote_match(&entry.prompt_body),
                        )
                    })
                    .collect(),
            );
            let mut user_prompt = self.context.prompt_prefix.clone();
            for entry in &still_missing {
                user_prompt.push_str(&entry.prompt_body);
            }
            let label = format!("finding-link-{}-attempt{:02}", self.batch, attempt);
            let target_finding_count = still_missing.len();
            let agent_decisions = self
                .run_one_attempt(
                    user_prompt,
                    label.clone(),
                    valid_finding_ids,
                    valid_semantic_ids.clone(),
                    finding_bodies,
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

    #[allow(clippy::too_many_arguments)]
    async fn run_one_attempt(
        &self,
        user_prompt: String,
        label: String,
        valid_finding_ids: Arc<HashSet<String>>,
        valid_semantic_ids: Arc<HashSet<String>>,
        finding_bodies: Arc<HashMap<String, String>>,
        attempt: usize,
        target_finding_count: usize,
    ) -> Result<Vec<FindingLinkDecision>> {
        let buffer = AgentChunkBuffer::<FindingLinkDecision>::new();
        let mut tools = ToolBox::new();
        tools.add_tool(EmitFindingLinkDecisionTool {
            buffer: buffer.clone(),
            valid_finding_ids,
            valid_semantic_ids,
            finding_bodies,
            evidence_min_high_medium: self.evidence_min_high_medium,
            evidence_min_low: self.evidence_min_low,
            high_quote_min_chars: self.high_quote_min_chars,
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
    options.warn_param_drift(model);
    let budgets = FindingLinkBudgets::from_options(model, options);

    // Render the pending semantics as link candidates (chunked below — a
    // merge-kg import can queue 1000+ at once).
    let candidate_entries: Vec<FindingLinkCandidateEntry> = pending_semantics
        .iter()
        .map(|node| {
            let candidate = SemanticLinkCandidate {
                candidate_id: format!("sem-{}", node.id),
                canonical_semantic_id: node.id,
                is_canonical: true,
                category: node.category,
                // Retro-linked semantics are freshly-imported canonicals with
                // no folded children yet, so there are no variant notes.
                variant_notes: Vec::new(),
                name: node.name.clone(),
                definition: node.definition.clone(),
                description: node.description.clone(),
            };
            let prompt_body = candidate.render(
                budgets.variant_render_cap,
                budgets.effective_child_char_cap(),
            );
            FindingLinkCandidateEntry {
                candidate_id: candidate.candidate_id,
                canonical_semantic_id: candidate.canonical_semantic_id,
                is_canonical: candidate.is_canonical,
                category: candidate.category,
                name: candidate.name,
                token_count: model.config.count_tokens_lossy(&prompt_body),
                prompt_body,
            }
        })
        .collect();

    // merge-kg can queue a whole source KG's worth of new canonicals (1000+),
    // far beyond one prompt: chunk the candidate block exactly like the main
    // link pass — an unchunked prefix would eat the entire input budget (hard
    // error today) or silently exceed 256K-window deployments.
    let semantic_token_budget = budgets.semantic_token_budget(model, None)?;
    let candidate_groups = group_finding_link_candidate_entries(candidate_entries)?;
    let candidate_chunks = partition_finding_link_candidate_groups(
        candidate_groups,
        semantic_token_budget,
        budgets.max_semantics_per_batch,
    );
    let chunk_count = candidate_chunks.len();

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
            let token_count = model.config.count_tokens_lossy(&prompt_body);
            FindingLinkBatchEntry {
                pending,
                prompt_finding_id,
                prompt_body,
                token_count,
            }
        })
        .collect();

    let total = entries.len();

    // Materialize every chunk's context and its finding batches up front so
    // a worker pool can drain the whole chunk × batch grid concurrently.
    let mut contexts: BTreeMap<FindingLinkContextKey, std::sync::Arc<FindingLinkContext>> =
        BTreeMap::new();
    let mut all_batches: Vec<FindingLinkBatch> = Vec::new();
    for (chunk_index, chunk_entries) in candidate_chunks.into_iter().enumerate() {
        let context_key = FindingLinkContextKey::empty().with_semantic_chunk(chunk_index);
        let context = std::sync::Arc::new(FindingLinkContext::build(
            model,
            &context_key,
            chunk_entries,
        ));
        let finding_token_budget = budgets.finding_token_budget(model, context.as_ref())?;
        // Prefix size differs per chunk, so each chunk re-partitions its own
        // copy of the finding entries under its own finding budget.
        let batches = partition_finding_link_entries(
            entries.clone(),
            finding_token_budget,
            budgets.max_findings_per_batch,
        );
        tracing::info!(
            "Retro-link chunk {}/{}: {} candidate semantic(s) × {} pre-linked finding(s) → {} batch(es)",
            chunk_index + 1,
            chunk_count,
            context.candidate_map.len(),
            total,
            batches.len()
        );
        for batch_entries in batches {
            let finding_token_count = batch_entries.iter().map(|e| e.token_count).sum();
            all_batches.push(FindingLinkBatch {
                context_key: context_key.clone(),
                entries: batch_entries,
                finding_token_count,
                finding_token_budget,
                input_token_budget: budgets.input_token_budget,
            });
        }
        contexts.insert(context_key, context);
    }

    /// Translate one batch's agent results into link edges and append them
    /// (idempotent per (semantic, finding) pair, so interrupted retro-links
    /// can simply be re-run).
    async fn persist_retro_results(
        db: &HistoricalDatabase,
        batch_label: &str,
        results: Vec<PersistedFindingLinkResult>,
    ) -> Result<usize> {
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
        tracing::info!(
            "Retro-link batch {} inserted {} new semantic_finding_link row(s)",
            batch_label,
            inserted
        );
        Ok(inserted)
    }

    let concurrency = options.concurrency.max(1);
    let total_batches = all_batches.len();
    let mut total_inserted = 0usize;

    if concurrency <= 1 {
        for batch in all_batches {
            let context = contexts
                .get(&batch.context_key)
                .ok_or_else(|| {
                    KgError::other(format!(
                        "Missing retro-link context for key '{}'",
                        batch.context_key.label()
                    ))
                })?
                .clone();
            tracing::info!(
                "Retro-link batch {}: {} finding(s)",
                &batch,
                batch.entries.len()
            );
            let runner = FindingLinkBatchAgentRunner {
                llm: llm.clone(),
                batch: &batch,
                context: context.as_ref(),
                agent_options: agent_options.clone(),
                max_response_attempts,
                evidence_min_high_medium: options.evidence_min_high_medium,
                evidence_min_low: options.evidence_min_low,
                high_quote_min_chars: options.high_quote_min_chars,
            };
            let results = runner.run().await?;
            total_inserted += persist_retro_results(db, &format!("{}", &batch), results).await?;
        }
    } else {
        use tokio::sync::mpsc;
        use tokio::task::JoinSet;

        let contexts = std::sync::Arc::new(contexts);
        let (tx, rx) = async_channel::bounded::<FindingLinkBatch>(total_batches + 1);
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
            let options = options;

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
                                evidence_min_high_medium: options.evidence_min_high_medium,
                                evidence_min_low: options.evidence_min_low,
                                high_quote_min_chars: options.high_quote_min_chars,
                            };
                            runner.run().await
                        }
                        None => Err(KgError::other(format!(
                            "Missing retro-link context for key '{}'",
                            batch.context_key.label()
                        ))),
                    };
                    if out.send((batch, result)).await.is_err() {
                        break;
                    }
                }
            });
        }
        drop(out_tx);

        for batch in all_batches {
            tx.send(batch)
                .await
                .map_err(|e| KgError::other(format!("retro-link work queue closed early: {e}")))?;
        }
        tx.close();

        // Single-writer collector: agents run concurrently, edge inserts stay
        // serialized here. A failed batch does NOT clear the pending queue —
        // the error propagates after the pool drains and a re-run resumes
        // idempotently.
        let mut first_error: Option<KgError> = None;
        while let Some((batch, result)) = out_rx.recv().await {
            match result {
                Ok(results) => {
                    match persist_retro_results(db, &format!("{}", &batch), results).await {
                        Ok(inserted) => total_inserted += inserted,
                        Err(e) => {
                            tracing::error!("Retro-link batch {} failed to persist: {}", &batch, e);
                            first_error.get_or_insert(e);
                        }
                    }
                }
                Err(e) => {
                    tracing::error!("Retro-link batch {} failed: {}", &batch, e);
                    first_error.get_or_insert(e);
                }
            }
        }
        while handles.join_next().await.is_some() {}
        if let Some(e) = first_error {
            return Err(e);
        }
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
    fn partition_finding_link_candidate_groups_honours_count_cap() {
        // Token budget is unlimited, but the count cap (2) forces a split.
        let group = |id: i32| FindingLinkCandidateGroup {
            canonical_semantic_id: id,
            category: DeFiCategory::Dexes,
            name: format!("Canonical {id}"),
            token_count: 10,
            entries: vec![FindingLinkCandidateEntry {
                candidate_id: format!("sem-{id}"),
                canonical_semantic_id: id,
                is_canonical: true,
                category: DeFiCategory::Dexes,
                name: format!("Canonical {id}"),
                prompt_body: format!("candidate-{id}"),
                token_count: 10,
            }],
        };
        let batches = partition_finding_link_candidate_groups(
            vec![group(1), group(2), group(3)],
            usize::MAX,
            2,
        );
        assert_eq!(batches.len(), 2);
        assert_eq!(batches[0].len(), 2);
        assert_eq!(batches[1].len(), 1);
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
            usize::MAX,
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
