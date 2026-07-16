//! Workflow-specific agent runners + tools for the KG learn pipeline.
//!
//! ## Tools
//!
//! Every tool uses [`llmy::agent::tool`]-derive (the proc macro re-exported
//! by `llmy::agent`). The macro generates `impl Tool` from the
//! `#[tool(arguments = …, invoke = …)]` attribute, so the only
//! hand-written code is the typed arguments struct (often the workflow's
//! own domain type) and the async invoke method.
//!
//! ## Workflow runners
//!
//! - [`CategorizeRunner`] — single-shot project categorization.
//! - [`SemanticChunkExtractor`] — per-chunk DeFi-semantic extraction.
//! - [`FindingChunkExtractor`] — per-chunk audit-finding extraction.
//! - [`SemanticMergeChunkRunner`] — runs **one** merge agent against a
//!   chunk of existing canonicals (+ their merged-away raw children). The
//!   higher-level [`SemanticMerger`] chunks, parallelises, and aggregates.
//! - [`FindingMergeChunkRunner`] / [`FindingMerger`] — finding analogues.
//!
//! ## Multi-target merge
//!
//! A new raw semantic / finding may merge into multiple existing
//! canonicals. Per-chunk the agent emits the IDs that match in *its*
//! chunk; the orchestrator unions those id lists across chunks. If every
//! chunk says "no merge", the new raw is admitted as a fresh canonical.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use llmy::agent::tool::ToolBox;
use llmy::agent::{LLMYError, tool};
use llmy::client::client::LLM;
use llmy::client::model::OpenAIModel;
use schemars::JsonSchema;
use serde::Deserialize;
use tokio::task::JoinSet;

use knowdit_kg_model::category::DeFiCategory;
use knowdit_kg_model::db::{audit_finding, finding_category, semantic_node};
use knowdit_kg_model::{ExtractedFinding, ExtractedSemantic};

use crate::agent_runner::{AgentChunkBuffer, AgentChunkRunner, AgentRunOptions, AgentRunOutcome};
use crate::error::{KgError, Result};
use crate::vulnerability::validate_taxonomy_pair;

// ---------------------------------------------------------------------------
// Shared finalize-tool argument shape
// ---------------------------------------------------------------------------

/// Argument shape for every "I'm done with this chunk" tool. We keep the
/// payload minimal — just an optional summary the agent may use to explain
/// its decisions.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct FinalizeArgs {
    /// Optional one-line summary of what this chunk produced (or why it
    /// produced nothing). Useful for telemetry; the runner ignores it for
    /// downstream logic.
    #[serde(default)]
    pub summary: Option<String>,
}

// ---------------------------------------------------------------------------
// Categorize
// ---------------------------------------------------------------------------

/// Single record produced by the categorize agent. Doubles as the
/// `set_project_categories` tool's `ARGUMENTS` shape (no duplicate
/// "Args" mirror). Field order keeps `reasoning` first so the agent
/// commits to the rationale before the categories list.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct CategorizationRecord {
    /// Short brief explaining why these categories fit the project.
    pub reasoning: String,
    /// Human-readable name for the project (used for telemetry only).
    pub project_name: String,
    /// One or more DeFi categories that describe the project. Multiple
    /// entries are allowed when the project spans multiple sub-domains.
    pub categories: Vec<DeFiCategory>,
}

#[derive(Debug, Clone)]
#[tool(
    arguments = CategorizationRecord,
    invoke = invoke,
    description = "Record the project's DeFi categories. Call exactly once per project, before invoking finalize_categorization.",
    name = "set_project_categories",
)]
struct SetProjectCategoriesTool {
    buffer: Arc<AgentChunkBuffer<CategorizationRecord>>,
}

impl SetProjectCategoriesTool {
    async fn invoke(&self, args: CategorizationRecord) -> std::result::Result<String, LLMYError> {
        if args.categories.is_empty() {
            return Ok(
                "error: categories must be a non-empty list; pick at least one category"
                    .to_string(),
            );
        }
        Ok(self.buffer.push_with_message(args, "categorization").await)
    }
}

#[derive(Debug, Clone)]
#[tool(
    arguments = FinalizeArgs,
    invoke = invoke,
    description = "Signal that categorization is complete. Call exactly once, after set_project_categories. Stop emitting tool calls afterwards.",
    name = "finalize_categorization",
)]
struct FinalizeCategorizationTool {
    buffer: Arc<AgentChunkBuffer<CategorizationRecord>>,
}

impl FinalizeCategorizationTool {
    async fn invoke(&self, args: FinalizeArgs) -> std::result::Result<String, LLMYError> {
        if self.buffer.len().await == 0 {
            return Ok(
                "error: cannot finalize before calling set_project_categories at least once"
                    .to_string(),
            );
        }
        Ok(self
            .buffer
            .finalize_with_message(args.summary, "categorization")
            .await)
    }
}

/// Drives the categorize phase: builds the system / user prompts from a
/// project's source body, runs the agent loop until the buffer is
/// finalized, and returns the chosen categories.
pub struct CategorizeRunner {
    pub llm: LLM,
    pub options: AgentRunOptions,
    pub system_prompt: String,
    pub user_prompt: String,
    pub cache_key: String,
    pub label: String,
}

impl CategorizeRunner {
    pub async fn run(self) -> Result<CategorizationRecord> {
        let buffer = AgentChunkBuffer::<CategorizationRecord>::new();
        let label = self.label.clone();

        let mut tools = ToolBox::new();
        tools.add_tool(SetProjectCategoriesTool {
            buffer: buffer.clone(),
        });
        tools.add_tool(FinalizeCategorizationTool {
            buffer: buffer.clone(),
        });

        let runner = AgentChunkRunner {
            llm: self.llm,
            options: self.options,
            buffer: buffer.clone(),
            tools,
            system_prompt: self.system_prompt,
            user_prompt: self.user_prompt,
            cache_key: self.cache_key,
            label: self.label,
        };

        let _outcome: AgentRunOutcome = runner.run().await?;

        let mut records = buffer.drain().await;
        if records.is_empty() {
            return Err(KgError::other(format!(
                "{label} agent finished without recording any categorization",
            )));
        }
        Ok(records.remove(records.len() - 1))
    }
}

// ---------------------------------------------------------------------------
// Semantic extraction
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
#[tool(
    arguments = ExtractedSemantic,
    invoke = invoke,
    description = "Emit one DeFi Semantic extracted from the chunk. Call once per distinct semantic; cluster all callable functions that share the same business meaning under one call. `functions` must contain at least one entry.",
    name = "emit_semantic",
)]
struct EmitSemanticTool {
    buffer: Arc<AgentChunkBuffer<ExtractedSemantic>>,
}

impl EmitSemanticTool {
    async fn invoke(&self, args: ExtractedSemantic) -> std::result::Result<String, LLMYError> {
        if args.name.trim().is_empty() {
            return Ok("error: `name` must not be empty".to_string());
        }
        if args.functions.is_empty() {
            return Ok(
                "error: `functions` must contain at least one entry pointing at the source"
                    .to_string(),
            );
        }
        Ok(self.buffer.push_with_message(args, "semantic").await)
    }
}

#[derive(Debug, Clone)]
#[tool(
    arguments = FinalizeArgs,
    invoke = invoke,
    description = "Signal that every DeFi semantic visible in this chunk has been emitted via emit_semantic. Call exactly once, then stop.",
    name = "finalize_semantic_extraction",
)]
struct FinalizeSemanticExtractTool {
    buffer: Arc<AgentChunkBuffer<ExtractedSemantic>>,
}

impl FinalizeSemanticExtractTool {
    async fn invoke(&self, args: FinalizeArgs) -> std::result::Result<String, LLMYError> {
        Ok(self
            .buffer
            .finalize_with_message(args.summary, "semantic extraction")
            .await)
    }
}

pub struct SemanticChunkExtractor {
    pub llm: LLM,
    pub options: AgentRunOptions,
    pub system_prompt: String,
    pub user_prompt: String,
    pub cache_key: String,
    pub label: String,
}

impl SemanticChunkExtractor {
    pub async fn run(self) -> Result<Vec<ExtractedSemantic>> {
        let buffer = AgentChunkBuffer::<ExtractedSemantic>::new();

        let mut tools = ToolBox::new();
        tools.add_tool(EmitSemanticTool {
            buffer: buffer.clone(),
        });
        tools.add_tool(FinalizeSemanticExtractTool {
            buffer: buffer.clone(),
        });

        let runner = AgentChunkRunner {
            llm: self.llm,
            options: self.options,
            buffer: buffer.clone(),
            tools,
            system_prompt: self.system_prompt,
            user_prompt: self.user_prompt,
            cache_key: self.cache_key,
            label: self.label,
        };
        let _outcome = runner.run().await?;
        Ok(buffer.drain().await)
    }
}

// ---------------------------------------------------------------------------
// Finding extraction
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
#[tool(
    arguments = ExtractedFinding,
    invoke = invoke,
    description = "Emit one vulnerability finding extracted from the report chunk. Decompose a multi-mechanism finding into multiple calls (one per independent mechanism); deduplicate repeated mentions of the same finding.",
    name = "emit_finding",
)]
struct EmitFindingTool {
    buffer: Arc<AgentChunkBuffer<ExtractedFinding>>,
}

impl EmitFindingTool {
    async fn invoke(&self, args: ExtractedFinding) -> std::result::Result<String, LLMYError> {
        if args.title.trim().is_empty() {
            return Ok("error: `title` must not be empty".to_string());
        }
        if let Some(hint) = validate_taxonomy_pair(args.category, &args.subcategory) {
            return Ok(format!("error: {hint}"));
        }
        Ok(self.buffer.push_with_message(args, "finding").await)
    }
}

#[derive(Debug, Clone)]
#[tool(
    arguments = FinalizeArgs,
    invoke = invoke,
    description = "Signal that every distinct vulnerability finding visible in this chunk has been emitted. Call exactly once, then stop.",
    name = "finalize_finding_extraction",
)]
struct FinalizeFindingExtractTool {
    buffer: Arc<AgentChunkBuffer<ExtractedFinding>>,
}

impl FinalizeFindingExtractTool {
    async fn invoke(&self, args: FinalizeArgs) -> std::result::Result<String, LLMYError> {
        Ok(self
            .buffer
            .finalize_with_message(args.summary, "finding extraction")
            .await)
    }
}

pub struct FindingChunkExtractor {
    pub llm: LLM,
    pub options: AgentRunOptions,
    pub system_prompt: String,
    pub user_prompt: String,
    pub cache_key: String,
    pub label: String,
}

impl FindingChunkExtractor {
    pub async fn run(self) -> Result<Vec<ExtractedFinding>> {
        let buffer = AgentChunkBuffer::<ExtractedFinding>::new();

        let mut tools = ToolBox::new();
        tools.add_tool(EmitFindingTool {
            buffer: buffer.clone(),
        });
        tools.add_tool(FinalizeFindingExtractTool {
            buffer: buffer.clone(),
        });

        let runner = AgentChunkRunner {
            llm: self.llm,
            options: self.options,
            buffer: buffer.clone(),
            tools,
            system_prompt: self.system_prompt,
            user_prompt: self.user_prompt,
            cache_key: self.cache_key,
            label: self.label,
        };
        let _outcome = runner.run().await?;
        Ok(buffer.drain().await)
    }
}

// ---------------------------------------------------------------------------
// Merge — shared types
// ---------------------------------------------------------------------------

/// Thresholds for the merge-field concreteness guard enforced at the emit-tool
/// boundary (see [`MergeFieldGuard::check_field_update`]). CLI-tunable via `MergeCliArgs`.
#[derive(Debug, Clone, Copy)]
pub struct MergeFieldGuard {
    /// Upper bound (chars) on a proposed `updated_*` replacement — the
    /// canonical field is a concise concrete representative, not a transcript.
    pub max_chars: usize,
    /// Below this current length the field is too thin to protect, so any
    /// replacement is accepted (it can only add concrete signal).
    pub concrete_floor: usize,
    /// Reject a replacement shorter than this fraction of an already-substantial
    /// current value — shrinking a concrete write-up on merge is the signature
    /// of over-generalization (a rich description collapsing into "improper
    /// access control").
    pub min_shrink_ratio: f64,
    /// Upper bound (chars) on a merge edge's required `appended_description`
    /// note — it must stay a one-or-two-sentence concrete delta, not a
    /// transcript.
    pub appended_max_chars: usize,
}

impl Default for MergeFieldGuard {
    fn default() -> Self {
        Self {
            max_chars: 2_000,
            concrete_floor: 160,
            min_shrink_ratio: 0.6,
            appended_max_chars: 600,
        }
    }
}

impl MergeFieldGuard {
    /// Validate a proposed `updated_*` replacement at the tool boundary so the
    /// agent gets actionable feedback and can re-emit — rather than the write
    /// layer silently dropping or truncating it. Returns `Ok(())` to accept, or
    /// `Err(message)` (a tool-result string handed back to the agent) when the
    /// value is over-long or markedly shortens/abstracts a target's CURRENT
    /// value. Thresholds come from `self` (CLI-tunable via `MergeCliArgs`).
    ///
    /// `field`/`label` only phrase the message; `current_of` yields a target
    /// canonical's current text (the value rendered in this chunk's prompt).
    fn check_field_update(
        &self,
        field: &str,
        label: &str,
        candidate: &str,
        target_ids: &[i32],
        current_of: impl Fn(i32) -> Option<String>,
    ) -> std::result::Result<(), String> {
        let candidate_len = candidate.chars().count();
        if candidate_len > self.max_chars {
            return Err(format!(
                "error: `{field}` for '{label}' is {candidate_len} chars — too long. Keep it a concise, self-contained concrete representative (≤ {} chars): the essential state variables, gates, and failure modes only. The full per-raw detail already lives on the raw nodes.",
                self.max_chars,
            ));
        }
        for &id in target_ids {
            let Some(current) = current_of(id) else {
                continue;
            };
            let current_len = current.trim().chars().count();
            if current_len >= self.concrete_floor
                && (candidate_len as f64) < (current_len as f64) * self.min_shrink_ratio
            {
                return Err(format!(
                    "error: the `{field}` you proposed for canonical #{id} ({candidate_len} chars) is far shorter than its current value ({current_len} chars) — that reads as a generalization, and broadening a concrete write-up toward an abstract category label (e.g. \"improper access control\") erases the signal that makes the canonical useful. Either re-emit `{field}` as a replacement at least as concrete and complete as the current value, or omit `{field}` to keep the current one."
                ));
            }
        }
        Ok(())
    }

    /// Validate the required merge-edge `appended_*` note at the tool boundary.
    /// Every fold must carry a one-or-two-sentence summary of how the raw
    /// *extends* the canonical it folds into — that per-edge delta is what keeps
    /// the concrete variance downstream once the canonical field itself is
    /// bounded. Returns `Err(message)` (handed back to the agent) when the note
    /// is missing or over-long.
    fn check_appended_note(
        &self,
        field: &str,
        label: &str,
        note: Option<&str>,
    ) -> std::result::Result<(), String> {
        let note = note.map(str::trim).unwrap_or("");
        if note.is_empty() {
            return Err(format!(
                "error: merging '{label}' requires `{field}` — one or two sentences on how this raw extends the canonical(s) it folds into (its concrete delta for this field). Re-emit with it filled."
            ));
        }
        let len = note.chars().count();
        if len > self.appended_max_chars {
            return Err(format!(
                "error: `{field}` for '{label}' is {len} chars — keep it to one or two sentences (≤ {} chars) naming just the concrete delta this raw adds.",
                self.appended_max_chars,
            ));
        }
        Ok(())
    }
}

/// CLI-tunable knobs for the merge orchestration. Exposed through
/// `MergeCliArgs` and threaded down to both [`SemanticMerger`] and
/// [`FindingMerger`].
#[derive(Debug, Clone, Copy)]
pub struct MergeChunkingOptions {
    /// Share (0, 1) of a merge prompt's usable window (model window ×
    /// utilization, minus the system prompt) reserved for the NEW-items block.
    /// The existing-candidate block takes the remainder and is chunked to fit
    /// it. See [`MergeWindowSplit`] for how the two token budgets are derived.
    pub new_item_token_ratio: f64,
    /// Maximum number of merge agents (one per work unit) running in
    /// parallel. `1` falls back to sequential execution. A work unit is one
    /// (new-item batch × candidate chunk) pair.
    pub concurrency: usize,
    /// Hard **count cap** on how many new items (semantics / findings) any
    /// single merge agent decides on. New items are batched by the model's
    /// context window first (so the rendered block always fits), and this cap
    /// closes a batch early when it's reached — each `emit` is one agent step,
    /// so it also keeps an agent's per-item steps under its step budget.
    /// Batches fan out across `concurrency`; batching never changes the merge
    /// outcome (decisions aggregate by name across all work units).
    pub new_item_batch_size: usize,
    /// Thresholds for the concreteness guard applied to `updated_*` merge
    /// fields at the emit-tool boundary.
    pub field_guard: MergeFieldGuard,
}

impl Default for MergeChunkingOptions {
    fn default() -> Self {
        Self {
            new_item_token_ratio: 0.8,
            concurrency: 1,
            new_item_batch_size: 40,
            field_guard: MergeFieldGuard::default(),
        }
    }
}

impl MergeChunkingOptions {
    pub fn new(
        new_item_token_ratio: f64,
        concurrency: usize,
        new_item_batch_size: usize,
        field_guard: MergeFieldGuard,
    ) -> Self {
        Self {
            new_item_token_ratio: new_item_token_ratio.clamp(0.05, 0.95),
            concurrency: concurrency.max(1),
            new_item_batch_size: new_item_batch_size.max(1),
            field_guard,
        }
    }

    /// Greedy token+count packer for a merge agent's new items, mirroring the
    /// link pipeline's `partition_finding_link_entries`. A batch closes when
    /// adding the next item would exceed EITHER the token budget (so the
    /// rendered block fits the model window) OR the count cap (so the agent's
    /// per-item `emit` steps stay under its step budget). A single oversized
    /// item still gets its own batch rather than being dropped.
    fn pack_new_item_batches<T>(
        items: Vec<T>,
        token_budget: usize,
        count_cap: usize,
        token_cost: impl Fn(&T) -> usize,
    ) -> Vec<Vec<T>> {
        let count_cap = count_cap.max(1);
        let mut batches = Vec::new();
        let mut current: Vec<T> = Vec::new();
        let mut current_tokens = 0usize;
        for item in items {
            let cost = token_cost(&item);
            let count_exceeded = current.len() >= count_cap;
            let tokens_exceeded = current_tokens + cost > token_budget;
            if !current.is_empty() && (count_exceeded || tokens_exceeded) {
                batches.push(std::mem::take(&mut current));
                current_tokens = 0;
            }
            current.push(item);
            current_tokens += cost;
        }
        if !current.is_empty() {
            batches.push(current);
        }
        batches
    }
}

/// One existing canonical (= merge survivor) and the raws that were
/// previously merged into it. The agent sees the full provenance so any
/// `updated_*` generalization it produces can take prior merges into
/// account.
#[derive(Debug, Clone)]
pub struct CanonicalWithChildren<T> {
    pub canonical: T,
    /// Raw rows where `_merge.from = self.canonical.id`. Empty when the
    /// canonical has no merged-away children (still a "solo" canonical).
    pub raw_children: Vec<T>,
}

// ---------------------------------------------------------------------------
// Semantic merge
// ---------------------------------------------------------------------------

/// One agent decision for a single newly-extracted raw semantic.
/// Doubles as the `emit_semantic_merge_decision` tool's `ARGUMENTS`
/// shape. `merge_target_ids` is multi-valued so a single raw can fold
/// into more than one existing canonical (the orchestrator unions the
/// id list across chunks).
#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct SemanticMergeDecision {
    /// Free-form reasoning supporting this decision.
    pub reason: String,
    /// Name of the new raw semantic this decision applies to. Must match
    /// (case-insensitively) one of the names listed in the prompt's
    /// "New Semantics" block.
    pub new_semantic_name: String,
    /// Existing canonical semantic IDs (drawn from this chunk's prompt)
    /// the new raw should fold into. Empty list = "no match in this
    /// chunk; treat as a fresh canonical from this chunk's perspective".
    pub merge_target_ids: Vec<i32>,
    /// Optional (merge-only) full replacement for the canonical's description,
    /// supplied ONLY to make it a more concrete / complete representative —
    /// never to generalize. The emit tool rejects a value that is over-long or
    /// that markedly shortens (i.e. abstracts) the canonical's current
    /// description. `None` keeps it unchanged. `name` and `definition` are
    /// stable identity and are never modified; if the raw cannot be expressed
    /// under them, emit an empty `merge_target_ids` so a fresh canonical is
    /// created instead.
    pub updated_description: Option<String>,
    /// REQUIRED when merging (`merge_target_ids` non-empty): a one-or-two
    /// sentence note on how THIS raw *extends* the canonical(s) it folds into —
    /// its concrete delta beyond the canonical's own description. Stored on the
    /// `semantic_merge` edge and surfaced downstream, so bounding the canonical
    /// description does not lose per-variant detail. Omit only for NEW (empty
    /// `merge_target_ids`).
    pub appended_description: Option<String>,
}

#[derive(Debug, Clone)]
#[tool(
    arguments = SemanticMergeDecision,
    invoke = invoke,
    description = "Emit one merge decision for a new raw semantic. Call once per `new_semantic_name` shown in the prompt. `merge_target_ids` may list multiple canonicals from THIS chunk; an empty list means NEW (no match in this chunk). The canonical's `name` and `definition` are stable identity and are NEVER modified by this decision — only `updated_description` (optional, when merging) replaces the canonical's description, and you supply it ONLY to make that description a more concrete/complete representative, never to generalize; omit it to keep the existing one. When merging you MUST also give `appended_description`: one or two sentences on how THIS raw extends the canonical (its concrete delta) — it is stored on the merge edge, not in the canonical. The tool validates `new_semantic_name` against the prompt's new-semantics list, `merge_target_ids` against this chunk's candidate IDs, rejects an `updated_description` that is over-long or that abstracts (markedly shortens) the target's current description, and rejects a missing/over-long `appended_description` on a merge; rejected decisions come back with an error message so you can re-emit a corrected one.",
    name = "emit_semantic_merge_decision",
)]
struct EmitSemanticMergeDecisionTool {
    buffer: Arc<AgentChunkBuffer<SemanticMergeDecision>>,
    /// Lower-cased names of every newly-extracted semantic in the
    /// project, set once when the chunk runner is built. Used to reject
    /// hallucinated names at the tool boundary so the agent gets feedback
    /// and can retry rather than the orchestrator silently dropping the
    /// decision later.
    valid_names: Arc<HashSet<String>>,
    /// Canonical IDs visible in *this* chunk's prompt. The agent must
    /// only emit IDs from this set; foreign IDs are rejected.
    valid_target_ids: Arc<HashSet<i32>>,
    /// Current description of each candidate canonical in this chunk, keyed by
    /// id — used to reject an over-generalizing `updated_description` at the
    /// tool boundary (see [`MergeFieldGuard::check_field_update`]).
    target_descriptions: Arc<HashMap<i32, String>>,
    /// Concreteness-guard thresholds (CLI-tunable).
    field_guard: MergeFieldGuard,
}

impl EmitSemanticMergeDecisionTool {
    async fn invoke(&self, args: SemanticMergeDecision) -> std::result::Result<String, LLMYError> {
        if args.new_semantic_name.trim().is_empty() {
            return Ok("error: `new_semantic_name` must not be empty".to_string());
        }
        if !self
            .valid_names
            .contains(&args.new_semantic_name.to_lowercase())
        {
            return Ok(format!(
                "error: `new_semantic_name` '{}' does not match any name in this prompt's new-semantics list. Re-emit using one of the names shown there (case-insensitive).",
                args.new_semantic_name,
            ));
        }
        let invalid: Vec<i32> = args
            .merge_target_ids
            .iter()
            .filter(|id| !self.valid_target_ids.contains(id))
            .copied()
            .collect();
        if !invalid.is_empty() {
            return Ok(format!(
                "error: `merge_target_ids` contains IDs not in this chunk's candidate list: {invalid:?}. Re-emit this decision using only canonical IDs that appear in the candidate list above. If '{}' has no match in this chunk, emit `merge_target_ids: []`.",
                args.new_semantic_name,
            ));
        }
        if let Some(updated) = args.updated_description.as_deref() {
            let updated = updated.trim();
            if !updated.is_empty() {
                if args.merge_target_ids.is_empty() {
                    return Ok(format!(
                        "error: `updated_description` only applies when merging, but `merge_target_ids` is empty for '{}'. Omit `updated_description` for a NEW semantic, or set `merge_target_ids` to the canonical(s) to fold into.",
                        args.new_semantic_name,
                    ));
                }
                if let Err(msg) = self.field_guard.check_field_update(
                    "updated_description",
                    &args.new_semantic_name,
                    updated,
                    &args.merge_target_ids,
                    |id| self.target_descriptions.get(&id).cloned(),
                ) {
                    return Ok(msg);
                }
            }
        }
        if !args.merge_target_ids.is_empty()
            && let Err(msg) = self.field_guard.check_appended_note(
                "appended_description",
                &args.new_semantic_name,
                args.appended_description.as_deref(),
            )
        {
            return Ok(msg);
        }
        Ok(self
            .buffer
            .push_with_message(args, "semantic merge decision")
            .await)
    }
}

#[derive(Debug, Clone)]
#[tool(
    arguments = FinalizeArgs,
    invoke = invoke,
    description = "Signal that every newly-extracted semantic listed in the prompt has received a merge decision (with possibly empty target_ids when no match in this chunk). Call exactly once, then stop.",
    name = "finalize_semantic_merge",
)]
struct FinalizeSemanticMergeTool {
    buffer: Arc<AgentChunkBuffer<SemanticMergeDecision>>,
}

impl FinalizeSemanticMergeTool {
    async fn invoke(&self, args: FinalizeArgs) -> std::result::Result<String, LLMYError> {
        Ok(self
            .buffer
            .finalize_with_message(args.summary, "semantic merge")
            .await)
    }
}

/// One merge agent against a single chunk of existing canonical
/// semantics. The orchestrator [`SemanticMerger`] builds the chunks and
/// runs many of these in parallel. `valid_names` / `valid_target_ids`
/// are wired into the emit tool so it can reject hallucinated names or
/// out-of-chunk IDs at the tool boundary (the agent gets the rejection
/// as a tool-result string and can retry).
pub struct SemanticMergeChunkRunner {
    pub llm: LLM,
    pub options: AgentRunOptions,
    pub system_prompt: String,
    pub user_prompt: String,
    pub cache_key: String,
    pub label: String,
    pub valid_names: Arc<HashSet<String>>,
    pub valid_target_ids: Arc<HashSet<i32>>,
    pub target_descriptions: Arc<HashMap<i32, String>>,
    pub field_guard: MergeFieldGuard,
}

impl SemanticMergeChunkRunner {
    pub async fn run(self) -> Result<Vec<SemanticMergeDecision>> {
        let buffer = AgentChunkBuffer::<SemanticMergeDecision>::new();

        let mut tools = ToolBox::new();
        tools.add_tool(EmitSemanticMergeDecisionTool {
            buffer: buffer.clone(),
            valid_names: self.valid_names,
            valid_target_ids: self.valid_target_ids,
            target_descriptions: self.target_descriptions,
            field_guard: self.field_guard,
        });
        tools.add_tool(FinalizeSemanticMergeTool {
            buffer: buffer.clone(),
        });

        let runner = AgentChunkRunner {
            llm: self.llm,
            options: self.options,
            buffer: buffer.clone(),
            tools,
            system_prompt: self.system_prompt,
            user_prompt: self.user_prompt,
            cache_key: self.cache_key,
            label: self.label,
        };
        let _outcome = runner.run().await?;
        Ok(buffer.drain().await)
    }
}

/// Top-level orchestrator for cross-project semantic merge. Chunks the
/// existing canonicals by token budget, runs one [`SemanticMergeChunkRunner`]
/// per chunk in parallel, and aggregates the per-chunk decisions into a
/// final `(new_semantic_name → AggregatedSemanticMergeDecision)` map.
pub struct SemanticMerger {
    /// New raw semantics extracted from the current project, awaiting
    /// merge decisions.
    pub new_semantics: Vec<ExtractedSemantic>,
    /// Existing canonicals (with their merged-away raw children) eligible
    /// to be merge targets.
    pub candidates: Vec<CanonicalWithChildren<semantic_node::Model>>,
    /// LLM client (cloned per chunk).
    pub llm: LLM,
    /// Base agent run options (each chunk gets a `scoped` subprefix).
    pub agent_options: AgentRunOptions,
    pub chunking: MergeChunkingOptions,
    /// Cache key root (each chunk appends its index).
    pub cache_key_root: String,
    /// Debug key root (each chunk appends its index).
    pub debug_key_root: String,
    /// Human label root (used in tracing).
    pub label_root: String,
}

/// Aggregated per-raw decision after combining decisions across all chunks.
#[derive(Debug, Clone)]
pub struct AggregatedSemanticMergeDecision {
    pub new_semantic_name: String,
    /// Union of `merge_target_ids` across every chunk's decision for this
    /// raw. Empty = no chunk matched, so admit the raw as a fresh canonical.
    pub merge_target_ids: Vec<i32>,
    /// Full replacement description for each merged-into canonical (a concise
    /// generalization). Replaces at write time; `None` keeps the existing.
    pub updated_description: Option<String>,
    /// The merge-edge `appended_description` note (how the raw extends the
    /// canonical), first non-empty across chunks. Written to every folded edge.
    pub appended_description: Option<String>,
}

impl SemanticMerger {
    pub async fn run(mut self) -> Result<Vec<AggregatedSemanticMergeDecision>> {
        if self.new_semantics.is_empty() {
            return Ok(Vec::new());
        }
        let mut aggregated: Vec<AggregatedSemanticMergeDecision> = self
            .new_semantics
            .iter()
            .map(|s| AggregatedSemanticMergeDecision {
                new_semantic_name: s.name.clone(),
                merge_target_ids: Vec::new(),
                updated_description: None,
                appended_description: None,
            })
            .collect();
        let candidates = std::mem::take(&mut self.candidates);
        if candidates.is_empty() {
            return Ok(aggregated);
        }
        // Split the usable window between the candidate block and the new-items
        // block by the configured ratio (see `MergeWindowSplit`), then chunk
        // candidates to `candidate_budget` and batch new items to
        // `new_item_budget` — plus a hard count cap so no agent emits more
        // decisions than its step budget allows (same token+count partitioning
        // the link pipeline uses). Work units are (new-item batch × candidate
        // chunk); they fan out under the shared `concurrency` bound.
        let model = self.llm.model.clone();
        let split = MergeWindowSplit::compute(
            &model,
            self.agent_options.context_window_utilization,
            self.chunking.new_item_token_ratio,
        );
        let chunks = self.pack_into_chunks(candidates, split.candidate_budget);
        let by_name = SemanticMergeAggregator::name_index(&self.new_semantics);
        let known_targets = SemanticMergeAggregator::known_canonical_ids(&chunks);
        let batches = MergeChunkingOptions::pack_new_item_batches(
            self.new_semantics.clone(),
            split.new_item_budget,
            self.chunking.new_item_batch_size,
            |sem| {
                model
                    .config
                    .count_tokens_lossy(&Self::render_new_block(std::slice::from_ref(sem)))
            },
        );
        tracing::info!(
            "{}: {} candidate chunk(s) × {} new-item batch(es) = {} work unit(s) (concurrency={}, new_item_ratio={:.2}, candidate_budget={}, new_item_budget={}, count_cap={})",
            self.label_root,
            chunks.len(),
            batches.len(),
            chunks.len() * batches.len(),
            self.chunking.concurrency,
            self.chunking.new_item_token_ratio,
            split.candidate_budget,
            split.new_item_budget,
            self.chunking.new_item_batch_size,
        );
        let chunk_results = self.dispatch_batched(&chunks, &batches).await?;
        SemanticMergeAggregator::merge(&mut aggregated, chunk_results, &by_name, &known_targets);
        Ok(aggregated)
    }

    fn pack_into_chunks(
        &self,
        candidates: Vec<CanonicalWithChildren<semantic_node::Model>>,
        candidate_budget: usize,
    ) -> Vec<Vec<CanonicalWithChildren<semantic_node::Model>>> {
        let model = self.llm.model.clone();
        Self::pack_chunks(&model, candidates, candidate_budget)
    }

    fn build_chunk_runner(
        &self,
        idx: usize,
        total: usize,
        chunk: &[CanonicalWithChildren<semantic_node::Model>],
        new_semantics_block: &str,
        valid_names: Arc<HashSet<String>>,
    ) -> SemanticMergeChunkRunner {
        let user_prompt = crate::prompts::merge_semantics_user_message(
            &Self::render_candidate_chunk(chunk),
            new_semantics_block,
        );
        let cache_key = format!("{}-chunk{idx:04}", self.cache_key_root);
        let debug_scope = format!("{}-chunk{idx:04}", self.debug_key_root);
        let label = format!("{}-chunk{idx:04}of{total:04}", self.label_root);
        let valid_target_ids: Arc<HashSet<i32>> =
            Arc::new(chunk.iter().map(|c| c.canonical.id).collect());
        let target_descriptions: Arc<HashMap<i32, String>> = Arc::new(
            chunk
                .iter()
                .map(|c| (c.canonical.id, c.canonical.description.clone()))
                .collect(),
        );
        SemanticMergeChunkRunner {
            llm: self.llm.clone(),
            options: self.agent_options.scoped(&debug_scope),
            system_prompt: crate::prompts::GENERAL_ROLE_SYSTEM.to_string(),
            user_prompt,
            cache_key,
            label,
            valid_names,
            valid_target_ids,
            target_descriptions,
            field_guard: self.chunking.field_guard,
        }
    }

    /// Dispatch (new-item batch × candidate chunk) work units through a
    /// shared bounded-concurrency pool. Each unit's agent sees one batch of
    /// new semantics plus one candidate chunk. Result order is irrelevant —
    /// the aggregator folds every unit's decisions by name.
    async fn dispatch_batched(
        &self,
        chunks: &[Vec<CanonicalWithChildren<semantic_node::Model>>],
        batches: &[Vec<ExtractedSemantic>],
    ) -> Result<Vec<Vec<SemanticMergeDecision>>> {
        let total_units = batches.len().saturating_mul(chunks.len());
        let mut runners = Vec::with_capacity(total_units);
        let mut unit_idx = 0usize;
        for batch in batches {
            let new_block = Self::render_new_block(batch);
            let valid_names: Arc<HashSet<String>> =
                Arc::new(batch.iter().map(|s| s.name.to_lowercase()).collect());
            for chunk in chunks {
                runners.push(self.build_chunk_runner(
                    unit_idx,
                    total_units,
                    chunk,
                    &new_block,
                    valid_names.clone(),
                ));
                unit_idx += 1;
            }
        }
        Self::run_runners(runners, self.chunking.concurrency.max(1)).await
    }

    /// Run pre-built merge-chunk runners through a bounded-concurrency pool.
    /// Results come back in completion order (the caller aggregates by name, so
    /// order does not matter).
    async fn run_runners(
        runners: Vec<SemanticMergeChunkRunner>,
        concurrency: usize,
    ) -> Result<Vec<Vec<SemanticMergeDecision>>> {
        let mut out = Vec::with_capacity(runners.len());
        if runners.is_empty() {
            return Ok(out);
        }
        if concurrency <= 1 {
            for runner in runners {
                out.push(runner.run().await?);
            }
            return Ok(out);
        }
        let mut it = runners.into_iter();
        let mut joins: JoinSet<Result<Vec<SemanticMergeDecision>>> = JoinSet::new();
        for _ in 0..concurrency {
            if let Some(runner) = it.next() {
                joins.spawn(async move { runner.run().await });
            }
        }
        while let Some(joined) = joins.join_next().await {
            let res = joined.map_err(|e| KgError::other(format!("semantic merge join: {e}")))?;
            out.push(res?);
            if let Some(runner) = it.next() {
                joins.spawn(async move { runner.run().await });
            }
        }
        Ok(out)
    }
}

/// The two token budgets that split one merge agent's usable prompt window.
///
/// `usable = model window × utilization − system prompt`; the NEW-items block
/// gets `usable × new_item_token_ratio` and the existing-candidate block takes
/// the remainder, so `system + candidate_budget + new_item_budget` fits the
/// window by construction — no overflow, no floor hacks (unlike the old
/// absolute candidate budget, which could exceed a small model window). Both
/// budgets carry a small floor so a tiny / misconfigured window still yields a
/// usable block of each kind.
#[derive(Debug, Clone, Copy)]
struct MergeWindowSplit {
    /// Per-chunk cap on the rendered candidate (existing-canonical) block.
    candidate_budget: usize,
    /// Per-batch cap on the rendered new-items block.
    new_item_budget: usize,
}

impl MergeWindowSplit {
    /// Minimum tokens handed to either block regardless of ratio, so a small
    /// window degrades to "a little of each" rather than starving one to zero.
    const MIN_BLOCK_TOKENS: usize = 2048;

    /// Split an already-computed usable budget by `new_item_token_ratio`. Kept
    /// separate from [`Self::compute`] so the arithmetic is unit-testable
    /// without constructing a model. The new-items budget is taken first and
    /// the candidate block gets the remainder, so the two sum to `usable`
    /// whenever neither floor bites.
    fn from_usable(usable: usize, new_item_token_ratio: f64) -> Self {
        let ratio = new_item_token_ratio.clamp(0.05, 0.95);
        let new_item_budget = ((usable as f64 * ratio) as usize).max(Self::MIN_BLOCK_TOKENS);
        let candidate_budget = usable
            .saturating_sub(new_item_budget)
            .max(Self::MIN_BLOCK_TOKENS);
        Self {
            candidate_budget,
            new_item_budget,
        }
    }

    fn compute(model: &OpenAIModel, utilization: f64, new_item_token_ratio: f64) -> Self {
        let system_tokens = model
            .config
            .count_tokens_lossy(crate::prompts::GENERAL_ROLE_SYSTEM);
        let usable =
            crate::learn::get_context_budget(model, utilization).saturating_sub(system_tokens);
        if usable < Self::MIN_BLOCK_TOKENS * 2 {
            tracing::warn!(
                usable,
                "merge window too small to honor the new-item/candidate split; both blocks \
                 fall back to their {}-token floor and the prompt may exceed the model window",
                Self::MIN_BLOCK_TOKENS,
            );
        }
        Self::from_usable(usable, new_item_token_ratio)
    }
}

/// Pure helper: combines per-chunk decisions into the project-level result.
struct SemanticMergeAggregator;

impl SemanticMergeAggregator {
    fn name_index(new_semantics: &[ExtractedSemantic]) -> std::collections::HashMap<String, usize> {
        new_semantics
            .iter()
            .enumerate()
            .map(|(idx, s)| (s.name.to_lowercase(), idx))
            .collect()
    }

    fn known_canonical_ids(
        chunks: &[Vec<CanonicalWithChildren<semantic_node::Model>>],
    ) -> std::collections::HashSet<i32> {
        chunks
            .iter()
            .flat_map(|chunk| chunk.iter().map(|c| c.canonical.id))
            .collect()
    }

    fn merge(
        aggregated: &mut [AggregatedSemanticMergeDecision],
        chunk_results: Vec<Vec<SemanticMergeDecision>>,
        by_name: &std::collections::HashMap<String, usize>,
        known_targets: &std::collections::HashSet<i32>,
    ) {
        for decisions in chunk_results {
            for decision in decisions {
                let Some(&idx) = by_name.get(&decision.new_semantic_name.to_lowercase()) else {
                    tracing::warn!(
                        "Semantic merge decision referenced unknown new_semantic_name '{}'; ignoring",
                        decision.new_semantic_name,
                    );
                    continue;
                };
                let agg = &mut aggregated[idx];
                for target in decision.merge_target_ids {
                    if !known_targets.contains(&target) {
                        tracing::warn!(
                            "Semantic merge decision for '{}' targeted unknown sem-{}; dropping",
                            agg.new_semantic_name,
                            target
                        );
                        continue;
                    }
                    if !agg.merge_target_ids.contains(&target) {
                        agg.merge_target_ids.push(target);
                    }
                }
                Self::adopt_update(&mut agg.updated_description, decision.updated_description);
                Self::adopt_update(&mut agg.appended_description, decision.appended_description);
            }
        }
    }

    /// Keep the first non-empty updated value across chunks. Each chunk that
    /// merged this raw proposes a full generalization; one suffices (they are
    /// full replacements, not accumulating fragments), so the first wins.
    fn adopt_update(slot: &mut Option<String>, candidate: Option<String>) {
        if slot.is_none()
            && let Some(candidate) = candidate
            && !candidate.trim().is_empty()
        {
            *slot = Some(candidate);
        }
    }
}

// `SemanticMerger`'s pure rendering / packing helpers live as associated
// functions so all merge logic is reachable through the type.
impl SemanticMerger {
    fn render_new_block(new_semantics: &[ExtractedSemantic]) -> String {
        let mut buf = String::new();
        for sem in new_semantics {
            buf.push_str(&format!(
                "Category: {}\nName: {}\nDefinition: {}\nDescription: {}\n\n",
                sem.category, sem.name, sem.definition, sem.description,
            ));
        }
        buf
    }

    fn render_candidate_chunk(chunk: &[CanonicalWithChildren<semantic_node::Model>]) -> String {
        let mut buf = String::new();
        for entry in chunk {
            let canonical = &entry.canonical;
            buf.push_str(&format!(
                "ID: {}\nCategory: {}\nName: {}\nDefinition: {}\nDescription: {}\n",
                canonical.id,
                canonical.category,
                canonical.name,
                canonical.definition,
                canonical.description,
            ));
            if !entry.raw_children.is_empty() {
                buf.push_str(
                    "Merged from (historical raws — for context, not selectable as merge_target_ids):\n",
                );
                for raw in &entry.raw_children {
                    buf.push_str(&format!(
                        "  - Name: {}\n    Definition: {}\n    Description: {}\n",
                        raw.name, raw.definition, raw.description,
                    ));
                }
            }
            buf.push('\n');
        }
        buf
    }

    fn pack_chunks(
        model: &OpenAIModel,
        candidates: Vec<CanonicalWithChildren<semantic_node::Model>>,
        chunk_token_budget: usize,
    ) -> Vec<Vec<CanonicalWithChildren<semantic_node::Model>>> {
        let mut chunks: Vec<Vec<CanonicalWithChildren<semantic_node::Model>>> = Vec::new();
        let mut current: Vec<CanonicalWithChildren<semantic_node::Model>> = Vec::new();
        let mut current_tokens: usize = 0;
        for entry in candidates {
            let single = Self::render_candidate_chunk(std::slice::from_ref(&entry));
            let cost = model.config.count_tokens_lossy(&single);
            if !current.is_empty() && current_tokens + cost > chunk_token_budget {
                chunks.push(std::mem::take(&mut current));
                current_tokens = 0;
            }
            current.push(entry);
            current_tokens += cost;
        }
        if !current.is_empty() {
            chunks.push(current);
        }
        chunks
    }
}

// ---------------------------------------------------------------------------
// Finding merge
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct FindingMergeDecision {
    /// Free-form reasoning supporting this decision.
    pub reason: String,
    /// Title of the new raw finding this decision applies to. Must match
    /// (case-insensitively) one of the titles listed in the prompt's
    /// "New Findings" block.
    pub new_finding_title: String,
    /// Existing canonical finding IDs (drawn from this chunk) the new raw
    /// should fold into. Empty list = "no match in this chunk".
    pub merge_target_ids: Vec<i32>,
    /// Optional (merge-only) full replacement for the canonical's description,
    /// supplied ONLY to make it a more concrete / complete representative —
    /// never to generalize. The emit tool rejects a value that is over-long or
    /// that markedly shortens (abstracts) the canonical's current description.
    /// `None` keeps it unchanged. `title`, `severity`, and `root_cause` are
    /// stable identity and are never modified by a merge decision.
    pub updated_description: Option<String>,
    /// Optional (merge-only) full replacement for `patterns`, under the same
    /// concrete-representative rule and tool validation. `None` keeps existing.
    pub updated_patterns: Option<String>,
    /// Optional (merge-only) full replacement for `exploits`, under the same
    /// concrete-representative rule and tool validation. `None` keeps existing.
    pub updated_exploits: Option<String>,
    /// REQUIRED when merging (`merge_target_ids` non-empty): one-or-two
    /// sentence notes on how THIS raw *extends* the canonical(s) it folds into —
    /// its concrete delta beyond the canonical's own fields, one per mutable
    /// field. All three are emitted together in this call and stored on the
    /// `finding_merge` edge, so bounding the canonical fields does not lose
    /// per-variant detail. Omit only for NEW (empty `merge_target_ids`).
    pub appended_description: Option<String>,
    pub appended_patterns: Option<String>,
    pub appended_exploits: Option<String>,
}

#[derive(Debug, Clone)]
#[tool(
    arguments = FindingMergeDecision,
    invoke = invoke,
    description = "Emit one merge decision for a new raw finding. Call once per `new_finding_title` shown in the prompt. `merge_target_ids` may list multiple canonicals from THIS chunk; an empty list means NEW (no match in this chunk). The canonical's `title`, `severity`, and `root_cause` are stable identity and are NEVER modified by this decision — only `updated_description` / `updated_patterns` / `updated_exploits` (optional, when merging) replace the canonical's fields, and you supply each ONLY to make that field a more concrete/complete representative, never to generalize; omit any to keep the existing value. When merging you MUST also give `appended_description` / `appended_patterns` / `appended_exploits` (all in this call): one or two sentences each on how THIS raw extends the canonical's description / patterns / exploits (its concrete delta) — they are stored on the merge edge, not in the canonical. The tool validates `new_finding_title` against the prompt's new-findings list, `merge_target_ids` against this chunk's candidate IDs, rejects any `updated_*` that is over-long or that abstracts (markedly shortens) the target's current value, and rejects a missing/over-long `appended_*` on a merge; rejected decisions come back with an error message so you can re-emit a corrected one.",
    name = "emit_finding_merge_decision",
)]
struct EmitFindingMergeDecisionTool {
    buffer: Arc<AgentChunkBuffer<FindingMergeDecision>>,
    /// Lower-cased titles of every newly-extracted finding in the project.
    valid_titles: Arc<HashSet<String>>,
    /// Canonical IDs visible in *this* chunk's prompt.
    valid_target_ids: Arc<HashSet<i32>>,
    /// Current mutable text of each candidate canonical in this chunk, keyed by
    /// id — used to reject an over-generalizing `updated_*` at the tool
    /// boundary (see [`MergeFieldGuard::check_field_update`]).
    target_texts: Arc<HashMap<i32, FindingTargetText>>,
    /// Concreteness-guard thresholds (CLI-tunable).
    field_guard: MergeFieldGuard,
}

/// Snapshot of a candidate canonical finding's mutable fields, captured when a
/// chunk runner is built so the emit tool can compare a proposed `updated_*`
/// against the current value.
#[derive(Debug, Clone, Default)]
pub struct FindingTargetText {
    description: String,
    patterns: String,
    exploits: String,
}

impl EmitFindingMergeDecisionTool {
    async fn invoke(&self, args: FindingMergeDecision) -> std::result::Result<String, LLMYError> {
        if args.new_finding_title.trim().is_empty() {
            return Ok("error: `new_finding_title` must not be empty".to_string());
        }
        if !self
            .valid_titles
            .contains(&args.new_finding_title.to_lowercase())
        {
            return Ok(format!(
                "error: `new_finding_title` '{}' does not match any title in this prompt's new-findings list. Re-emit using one of the titles shown there (case-insensitive).",
                args.new_finding_title,
            ));
        }
        let invalid: Vec<i32> = args
            .merge_target_ids
            .iter()
            .filter(|id| !self.valid_target_ids.contains(id))
            .copied()
            .collect();
        if !invalid.is_empty() {
            return Ok(format!(
                "error: `merge_target_ids` contains IDs not in this chunk's candidate list: {invalid:?}. Re-emit this decision using only canonical IDs that appear in the candidate list above. If '{}' has no match in this chunk, emit `merge_target_ids: []`.",
                args.new_finding_title,
            ));
        }
        let any_update = [
            &args.updated_description,
            &args.updated_patterns,
            &args.updated_exploits,
        ]
        .into_iter()
        .any(|v| v.as_deref().map(str::trim).is_some_and(|s| !s.is_empty()));
        if any_update && args.merge_target_ids.is_empty() {
            return Ok(format!(
                "error: the `updated_*` fields only apply when merging, but `merge_target_ids` is empty for '{}'. Omit them for a NEW finding, or set `merge_target_ids` to the canonical(s) to fold into.",
                args.new_finding_title,
            ));
        }
        if let Some(v) = args.updated_description.as_deref() {
            let v = v.trim();
            if !v.is_empty()
                && let Err(msg) = self.field_guard.check_field_update(
                    "updated_description",
                    &args.new_finding_title,
                    v,
                    &args.merge_target_ids,
                    |id| self.target_texts.get(&id).map(|t| t.description.clone()),
                )
            {
                return Ok(msg);
            }
        }
        if let Some(v) = args.updated_patterns.as_deref() {
            let v = v.trim();
            if !v.is_empty()
                && let Err(msg) = self.field_guard.check_field_update(
                    "updated_patterns",
                    &args.new_finding_title,
                    v,
                    &args.merge_target_ids,
                    |id| self.target_texts.get(&id).map(|t| t.patterns.clone()),
                )
            {
                return Ok(msg);
            }
        }
        if let Some(v) = args.updated_exploits.as_deref() {
            let v = v.trim();
            if !v.is_empty()
                && let Err(msg) = self.field_guard.check_field_update(
                    "updated_exploits",
                    &args.new_finding_title,
                    v,
                    &args.merge_target_ids,
                    |id| self.target_texts.get(&id).map(|t| t.exploits.clone()),
                )
            {
                return Ok(msg);
            }
        }
        if !args.merge_target_ids.is_empty() {
            for (field, note) in [
                ("appended_description", args.appended_description.as_deref()),
                ("appended_patterns", args.appended_patterns.as_deref()),
                ("appended_exploits", args.appended_exploits.as_deref()),
            ] {
                if let Err(msg) =
                    self.field_guard
                        .check_appended_note(field, &args.new_finding_title, note)
                {
                    return Ok(msg);
                }
            }
        }
        Ok(self
            .buffer
            .push_with_message(args, "finding merge decision")
            .await)
    }
}

#[derive(Debug, Clone)]
#[tool(
    arguments = FinalizeArgs,
    invoke = invoke,
    description = "Signal that every newly-extracted finding listed in the prompt has received a merge decision (with possibly empty target_ids). Call exactly once, then stop.",
    name = "finalize_finding_merge",
)]
struct FinalizeFindingMergeTool {
    buffer: Arc<AgentChunkBuffer<FindingMergeDecision>>,
}

impl FinalizeFindingMergeTool {
    async fn invoke(&self, args: FinalizeArgs) -> std::result::Result<String, LLMYError> {
        Ok(self
            .buffer
            .finalize_with_message(args.summary, "finding merge")
            .await)
    }
}

pub struct FindingMergeChunkRunner {
    pub llm: LLM,
    pub options: AgentRunOptions,
    pub system_prompt: String,
    pub user_prompt: String,
    pub cache_key: String,
    pub label: String,
    pub valid_titles: Arc<HashSet<String>>,
    pub valid_target_ids: Arc<HashSet<i32>>,
    pub target_texts: Arc<HashMap<i32, FindingTargetText>>,
    pub field_guard: MergeFieldGuard,
}

impl FindingMergeChunkRunner {
    pub async fn run(self) -> Result<Vec<FindingMergeDecision>> {
        let buffer = AgentChunkBuffer::<FindingMergeDecision>::new();

        let mut tools = ToolBox::new();
        tools.add_tool(EmitFindingMergeDecisionTool {
            buffer: buffer.clone(),
            valid_titles: self.valid_titles,
            valid_target_ids: self.valid_target_ids,
            target_texts: self.target_texts,
            field_guard: self.field_guard,
        });
        tools.add_tool(FinalizeFindingMergeTool {
            buffer: buffer.clone(),
        });

        let runner = AgentChunkRunner {
            llm: self.llm,
            options: self.options,
            buffer: buffer.clone(),
            tools,
            system_prompt: self.system_prompt,
            user_prompt: self.user_prompt,
            cache_key: self.cache_key,
            label: self.label,
        };
        let _outcome = runner.run().await?;
        Ok(buffer.drain().await)
    }
}

/// Per-canonical finding bundle: the canonical row + its taxonomy entry +
/// the raws that have been merged into it. Findings (unlike semantics)
/// also carry a `finding_category` join for taxonomy display.
#[derive(Debug, Clone)]
pub struct FindingCanonicalWithTaxonomy {
    pub canonical: audit_finding::Model,
    pub category: finding_category::Model,
    pub raw_children: Vec<audit_finding::Model>,
}

pub struct FindingMerger {
    pub new_findings: Vec<ExtractedFinding>,
    pub candidates: Vec<FindingCanonicalWithTaxonomy>,
    pub llm: LLM,
    pub agent_options: AgentRunOptions,
    pub chunking: MergeChunkingOptions,
    pub cache_key_root: String,
    pub debug_key_root: String,
    pub label_root: String,
}

#[derive(Debug, Clone)]
pub struct AggregatedFindingMergeDecision {
    pub new_finding_title: String,
    pub merge_target_ids: Vec<i32>,
    /// Full replacement description for each merged-into canonical (a concise
    /// generalization). Replaces at write time; `None` keeps the existing.
    pub updated_description: Option<String>,
    /// Full replacement patterns; `None` keeps the existing.
    pub updated_patterns: Option<String>,
    /// Full replacement exploit paths; `None` keeps the existing.
    pub updated_exploits: Option<String>,
    /// The merge-edge `appended_*` notes (how the raw extends the canonical),
    /// first non-empty across chunks. Written to every folded edge.
    pub appended_description: Option<String>,
    pub appended_patterns: Option<String>,
    pub appended_exploits: Option<String>,
}

impl FindingMerger {
    pub async fn run(mut self) -> Result<Vec<AggregatedFindingMergeDecision>> {
        if self.new_findings.is_empty() {
            return Ok(Vec::new());
        }
        let mut aggregated: Vec<AggregatedFindingMergeDecision> = self
            .new_findings
            .iter()
            .map(|f| AggregatedFindingMergeDecision {
                new_finding_title: f.title.clone(),
                merge_target_ids: Vec::new(),
                updated_description: None,
                updated_patterns: None,
                updated_exploits: None,
                appended_description: None,
                appended_patterns: None,
                appended_exploits: None,
            })
            .collect();
        let candidates = std::mem::take(&mut self.candidates);
        if candidates.is_empty() {
            return Ok(aggregated);
        }
        // Split the usable window between the candidate block and the new-items
        // block by the configured ratio (see `MergeWindowSplit`), mirroring the
        // semantic path. Work units (batch × candidate chunk) fan out under
        // `concurrency`.
        let model = self.llm.model.clone();
        let split = MergeWindowSplit::compute(
            &model,
            self.agent_options.context_window_utilization,
            self.chunking.new_item_token_ratio,
        );
        let chunks = self.pack_into_chunks(candidates, split.candidate_budget);
        let by_title: std::collections::HashMap<String, usize> = self
            .new_findings
            .iter()
            .enumerate()
            .map(|(idx, f)| (f.title.to_lowercase(), idx))
            .collect();
        let known_targets: std::collections::HashSet<i32> = chunks
            .iter()
            .flat_map(|chunk| chunk.iter().map(|c| c.canonical.id))
            .collect();
        let batches = MergeChunkingOptions::pack_new_item_batches(
            self.new_findings.clone(),
            split.new_item_budget,
            self.chunking.new_item_batch_size,
            |finding| {
                model
                    .config
                    .count_tokens_lossy(&Self::render_new_block(std::slice::from_ref(finding)))
            },
        );
        tracing::info!(
            "{}: {} candidate chunk(s) × {} new-item batch(es) = {} work unit(s) (concurrency={}, new_item_ratio={:.2}, candidate_budget={}, new_item_budget={}, count_cap={})",
            self.label_root,
            chunks.len(),
            batches.len(),
            chunks.len() * batches.len(),
            self.chunking.concurrency,
            self.chunking.new_item_token_ratio,
            split.candidate_budget,
            split.new_item_budget,
            self.chunking.new_item_batch_size,
        );
        let chunk_results = self.dispatch_batched(&chunks, &batches).await?;
        for decisions in chunk_results {
            for decision in decisions {
                let Some(&idx) = by_title.get(&decision.new_finding_title.to_lowercase()) else {
                    tracing::warn!(
                        "Finding merge decision referenced unknown new_finding_title '{}'; ignoring",
                        decision.new_finding_title,
                    );
                    continue;
                };
                let agg = &mut aggregated[idx];
                for target in decision.merge_target_ids {
                    if !known_targets.contains(&target) {
                        tracing::warn!(
                            "Finding merge decision for '{}' targeted unknown finding-{}; dropping",
                            agg.new_finding_title,
                            target
                        );
                        continue;
                    }
                    if !agg.merge_target_ids.contains(&target) {
                        agg.merge_target_ids.push(target);
                    }
                }
                SemanticMergeAggregator::adopt_update(
                    &mut agg.updated_description,
                    decision.updated_description,
                );
                SemanticMergeAggregator::adopt_update(
                    &mut agg.updated_patterns,
                    decision.updated_patterns,
                );
                SemanticMergeAggregator::adopt_update(
                    &mut agg.updated_exploits,
                    decision.updated_exploits,
                );
                SemanticMergeAggregator::adopt_update(
                    &mut agg.appended_description,
                    decision.appended_description,
                );
                SemanticMergeAggregator::adopt_update(
                    &mut agg.appended_patterns,
                    decision.appended_patterns,
                );
                SemanticMergeAggregator::adopt_update(
                    &mut agg.appended_exploits,
                    decision.appended_exploits,
                );
            }
        }
        Ok(aggregated)
    }

    fn pack_into_chunks(
        &self,
        candidates: Vec<FindingCanonicalWithTaxonomy>,
        candidate_budget: usize,
    ) -> Vec<Vec<FindingCanonicalWithTaxonomy>> {
        let model = self.llm.model.clone();
        Self::pack_chunks(&model, candidates, candidate_budget)
    }

    fn build_chunk_runner(
        &self,
        idx: usize,
        total: usize,
        chunk: &[FindingCanonicalWithTaxonomy],
        new_findings_block: &str,
        valid_titles: Arc<HashSet<String>>,
    ) -> FindingMergeChunkRunner {
        let user_prompt = crate::prompts::merge_findings_user_message(
            &Self::render_candidate_chunk(chunk),
            new_findings_block,
        );
        let cache_key = format!("{}-chunk{idx:04}", self.cache_key_root);
        let debug_scope = format!("{}-chunk{idx:04}", self.debug_key_root);
        let label = format!("{}-chunk{idx:04}of{total:04}", self.label_root);
        let valid_target_ids: Arc<HashSet<i32>> =
            Arc::new(chunk.iter().map(|c| c.canonical.id).collect());
        let target_texts: Arc<HashMap<i32, FindingTargetText>> = Arc::new(
            chunk
                .iter()
                .map(|c| {
                    (
                        c.canonical.id,
                        FindingTargetText {
                            description: c.canonical.description.clone(),
                            patterns: c.canonical.patterns.clone(),
                            exploits: c.canonical.exploits.clone(),
                        },
                    )
                })
                .collect(),
        );
        FindingMergeChunkRunner {
            llm: self.llm.clone(),
            options: self.agent_options.scoped(&debug_scope),
            system_prompt: crate::prompts::GENERAL_ROLE_SYSTEM.to_string(),
            user_prompt,
            cache_key,
            label,
            valid_titles,
            valid_target_ids,
            target_texts,
            field_guard: self.chunking.field_guard,
        }
    }

    /// Mirror of [`SemanticMerger::dispatch_batched`] for findings.
    async fn dispatch_batched(
        &self,
        chunks: &[Vec<FindingCanonicalWithTaxonomy>],
        batches: &[Vec<ExtractedFinding>],
    ) -> Result<Vec<Vec<FindingMergeDecision>>> {
        let total_units = batches.len().saturating_mul(chunks.len());
        let mut runners = Vec::with_capacity(total_units);
        let mut unit_idx = 0usize;
        for batch in batches {
            let new_block = Self::render_new_block(batch);
            let valid_titles: Arc<HashSet<String>> =
                Arc::new(batch.iter().map(|f| f.title.to_lowercase()).collect());
            for chunk in chunks {
                runners.push(self.build_chunk_runner(
                    unit_idx,
                    total_units,
                    chunk,
                    &new_block,
                    valid_titles.clone(),
                ));
                unit_idx += 1;
            }
        }
        Self::run_runners(runners, self.chunking.concurrency.max(1)).await
    }

    /// Bounded-concurrency pool for pre-built finding-merge runners. Mirror of
    /// [`SemanticMerger::run_runners`].
    async fn run_runners(
        runners: Vec<FindingMergeChunkRunner>,
        concurrency: usize,
    ) -> Result<Vec<Vec<FindingMergeDecision>>> {
        let mut out = Vec::with_capacity(runners.len());
        if runners.is_empty() {
            return Ok(out);
        }
        if concurrency <= 1 {
            for runner in runners {
                out.push(runner.run().await?);
            }
            return Ok(out);
        }
        let mut it = runners.into_iter();
        let mut joins: JoinSet<Result<Vec<FindingMergeDecision>>> = JoinSet::new();
        for _ in 0..concurrency {
            if let Some(runner) = it.next() {
                joins.spawn(async move { runner.run().await });
            }
        }
        while let Some(joined) = joins.join_next().await {
            let res = joined.map_err(|e| KgError::other(format!("finding merge join: {e}")))?;
            out.push(res?);
            if let Some(runner) = it.next() {
                joins.spawn(async move { runner.run().await });
            }
        }
        Ok(out)
    }
}

// `FindingMerger`'s pure rendering / packing helpers, mirroring
// [`SemanticMerger`]'s associated functions.
impl FindingMerger {
    fn render_new_block(new_findings: &[ExtractedFinding]) -> String {
        let mut buf = String::new();
        for finding in new_findings {
            buf.push_str(&format!(
                "Severity: {}\nCategory: {}\nSubcategory: {}\nTitle: {}\nRoot Cause: {}\nDescription: {}\nPatterns: {}\nExploits: {}\n\n",
                finding.severity,
                finding.category,
                finding.subcategory,
                finding.title,
                finding.root_cause,
                finding.description,
                finding.patterns,
                finding.exploits,
            ));
        }
        buf
    }

    fn render_candidate_chunk(chunk: &[FindingCanonicalWithTaxonomy]) -> String {
        let mut buf = String::new();
        for entry in chunk {
            let f = &entry.canonical;
            buf.push_str(&format!(
                "ID: {}\nSeverity: {}\nCategory: {}\nSubcategory: {}\nTitle: {}\nRoot Cause: {}\nDescription: {}\nPatterns: {}\nExploits: {}\n",
                f.id,
                f.severity,
                entry.category.category,
                entry.category.name,
                f.title,
                f.root_cause,
                f.description,
                f.patterns,
                f.exploits,
            ));
            if !entry.raw_children.is_empty() {
                buf.push_str(
                    "Merged from (historical raws — for context, not selectable as merge_target_ids):\n",
                );
                for raw in &entry.raw_children {
                    buf.push_str(&format!(
                        "  - Title: {}\n    Severity: {}\n    Root Cause: {}\n    Description: {}\n    Patterns: {}\n    Exploits: {}\n",
                        raw.title, raw.severity, raw.root_cause, raw.description, raw.patterns, raw.exploits,
                    ));
                }
            }
            buf.push('\n');
        }
        buf
    }

    fn pack_chunks(
        model: &OpenAIModel,
        candidates: Vec<FindingCanonicalWithTaxonomy>,
        chunk_token_budget: usize,
    ) -> Vec<Vec<FindingCanonicalWithTaxonomy>> {
        let mut chunks: Vec<Vec<FindingCanonicalWithTaxonomy>> = Vec::new();
        let mut current: Vec<FindingCanonicalWithTaxonomy> = Vec::new();
        let mut current_tokens: usize = 0;
        for entry in candidates {
            let single = Self::render_candidate_chunk(std::slice::from_ref(&entry));
            let cost = model.config.count_tokens_lossy(&single);
            if !current.is_empty() && current_tokens + cost > chunk_token_budget {
                chunks.push(std::mem::take(&mut current));
                current_tokens = 0;
            }
            current.push(entry);
            current_tokens += cost;
        }
        if !current.is_empty() {
            chunks.push(current);
        }
        chunks
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn batch_sizes(batches: &[Vec<i32>]) -> Vec<usize> {
        batches.iter().map(Vec::len).collect()
    }

    #[test]
    fn merge_window_split_reserves_new_ratio_and_gives_candidate_remainder() {
        // 1M-window model at util 0.4 ⇒ usable ≈ 400k. Default ratio 0.8 keeps
        // the candidate block at the remaining ~80k; the two sum to `usable`.
        let split = MergeWindowSplit::from_usable(400_000, 0.8);
        assert_eq!(split.new_item_budget, 320_000);
        assert_eq!(split.candidate_budget, 80_000);
        assert_eq!(
            split.new_item_budget + split.candidate_budget,
            400_000,
            "split must not lose or invent window when no floor bites"
        );

        // A 50/50 split is exact.
        let half = MergeWindowSplit::from_usable(100_000, 0.5);
        assert_eq!(half.new_item_budget, 50_000);
        assert_eq!(half.candidate_budget, 50_000);
    }

    #[test]
    fn merge_window_split_floors_both_blocks_on_a_tiny_window() {
        // Below 2× the floor neither block can get its full share; both fall
        // back to the floor rather than starving one to zero.
        let split = MergeWindowSplit::from_usable(3_000, 0.8);
        assert!(split.new_item_budget >= MergeWindowSplit::MIN_BLOCK_TOKENS);
        assert!(split.candidate_budget >= MergeWindowSplit::MIN_BLOCK_TOKENS);
    }

    #[test]
    fn merge_window_split_clamps_out_of_range_ratio() {
        // A ratio outside (0.05, 0.95) is clamped, so the candidate block is
        // never starved entirely even on a misconfigured value.
        let split = MergeWindowSplit::from_usable(100_000, 2.0);
        assert_eq!(split.new_item_budget, 95_000);
        assert_eq!(split.candidate_budget, 5_000);
    }

    // A substantial, concrete current description used to exercise the
    // anti-abstraction guard. Comfortably above MERGE_FIELD_CONCRETE_FLOOR.
    const CURRENT: &str = "Vault.deposit increments s_depositedAssets additively \
        prior to safeTransferFrom, gated by whenNotPaused; minted shares equal \
        previewDeposit(assets); reverts when paused or on zero assets.";

    #[test]
    fn check_merge_field_accepts_comparable_concrete_replacement() {
        // A replacement of similar length/concreteness is accepted.
        let candidate = "Vault.deposit adds assets to s_depositedAssets before \
            safeTransferFrom under whenNotPaused; shares = previewDeposit(assets); \
            reverts on paused or zero-asset deposits and on transfer failure.";
        assert!(
            MergeFieldGuard::default()
                .check_field_update("updated_description", "raw", candidate, &[7], |_| Some(
                    CURRENT.to_string()
                ))
                .is_ok()
        );
    }

    #[test]
    fn check_merge_field_rejects_abstracting_shrink() {
        // Collapsing a rich description into a generic label is rejected with
        // feedback rather than silently written.
        let err = MergeFieldGuard::default()
            .check_field_update(
                "updated_description",
                "raw",
                "improper access control",
                &[7],
                |_| Some(CURRENT.to_string()),
            )
            .unwrap_err();
        assert!(err.contains("shorter"), "unexpected message: {err}");
    }

    #[test]
    fn check_merge_field_accepts_any_replacement_when_current_is_thin() {
        // A thin current value (below the floor) has nothing concrete to
        // protect, so even a short replacement is accepted.
        assert!(
            MergeFieldGuard::default()
                .check_field_update("updated_description", "raw", "swap", &[7], |_| Some(
                    "amm".to_string()
                ))
                .is_ok()
        );
    }

    #[test]
    fn check_merge_field_rejects_overlong_candidate() {
        let guard = MergeFieldGuard::default();
        let candidate = "x".repeat(guard.max_chars + 1);
        let err = guard
            .check_field_update("updated_patterns", "raw", &candidate, &[7], |_| {
                Some(CURRENT.to_string())
            })
            .unwrap_err();
        assert!(err.contains("too long"), "unexpected message: {err}");
    }

    #[test]
    fn pack_new_item_batches_respects_count_cap() {
        // cost 1 each, effectively-infinite token budget → only the count cap
        // closes batches.
        let batches = MergeChunkingOptions::pack_new_item_batches(
            (0..10).collect::<Vec<i32>>(),
            1_000_000,
            4,
            |_| 1,
        );
        assert_eq!(batch_sizes(&batches), vec![4, 4, 2]);
    }

    #[test]
    fn pack_new_item_batches_respects_token_budget() {
        // cost 30 each, budget 100, count cap effectively infinite → 3 per
        // batch (90 <= 100, 120 > 100).
        let batches = MergeChunkingOptions::pack_new_item_batches(
            (0..7).collect::<Vec<i32>>(),
            100,
            1000,
            |_| 30,
        );
        assert_eq!(batch_sizes(&batches), vec![3, 3, 1]);
    }

    #[test]
    fn pack_new_item_batches_isolates_oversized_item() {
        // A single item larger than the whole budget still gets its own batch
        // (never dropped).
        let costs = [10usize, 500, 10];
        let batches =
            MergeChunkingOptions::pack_new_item_batches(vec![0i32, 1, 2], 100, 1000, |&i| {
                costs[i as usize]
            });
        assert_eq!(batch_sizes(&batches), vec![1, 1, 1]);
    }

    #[test]
    fn pack_new_item_batches_count_cap_floored_to_one() {
        // A zero count cap must floor to 1, not wedge on empty batches.
        let batches =
            MergeChunkingOptions::pack_new_item_batches(vec![0i32, 1, 2], 1_000_000, 0, |_| 1);
        assert_eq!(batch_sizes(&batches), vec![1, 1, 1]);
    }
}
