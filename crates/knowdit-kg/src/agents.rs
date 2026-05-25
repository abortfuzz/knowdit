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

use std::collections::HashSet;
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

/// CLI-tunable knobs for the merge orchestration. Exposed through
/// `MergeCliArgs` and threaded down to both [`SemanticMerger`] and
/// [`FindingMerger`].
#[derive(Debug, Clone, Copy)]
pub struct MergeChunkingOptions {
    /// Soft cap on the rendered token cost of the existing-canonical
    /// candidates section in a single merge prompt. The chunker packs
    /// canonicals (with their merged-away children) greedily until adding
    /// the next candidate would exceed this budget.
    pub chunk_candidate_token_budget: usize,
    /// Maximum number of merge agents (one per candidate chunk) running in
    /// parallel. `1` falls back to sequential execution.
    pub concurrency: usize,
}

impl Default for MergeChunkingOptions {
    fn default() -> Self {
        Self {
            chunk_candidate_token_budget: 50_000,
            concurrency: 1,
        }
    }
}

impl MergeChunkingOptions {
    pub fn new(chunk_candidate_token_budget: usize, concurrency: usize) -> Self {
        Self {
            chunk_candidate_token_budget: chunk_candidate_token_budget.max(1024),
            concurrency: concurrency.max(1),
        }
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
    /// Optional behavioural detail this raw contributes that is worth
    /// recording on the canonical's description. Appended to the
    /// canonical's existing description; never replaces. The canonical's
    /// `name` and `definition` are stable identity and are never modified
    /// by a merge decision. If the raw cannot be expressed under the
    /// existing name + definition, emit an empty `merge_target_ids`
    /// instead so a fresh canonical is created.
    pub appended_description: Option<String>,
}

#[derive(Debug, Clone)]
#[tool(
    arguments = SemanticMergeDecision,
    invoke = invoke,
    description = "Emit one merge decision for a new raw semantic. Call once per `new_semantic_name` shown in the prompt. `merge_target_ids` may list multiple canonicals from THIS chunk; an empty list means NEW (no match in this chunk). The canonical's `name` and `definition` are stable identity and are NEVER modified by this decision — only `appended_description` (optional, when merging) is appended to the canonical's existing description. The tool validates `new_semantic_name` against the prompt's new-semantics list and `merge_target_ids` against this chunk's candidate IDs; invalid decisions are rejected with an error message so you can re-emit a corrected one.",
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
}

impl SemanticMergeChunkRunner {
    pub async fn run(self) -> Result<Vec<SemanticMergeDecision>> {
        let buffer = AgentChunkBuffer::<SemanticMergeDecision>::new();

        let mut tools = ToolBox::new();
        tools.add_tool(EmitSemanticMergeDecisionTool {
            buffer: buffer.clone(),
            valid_names: self.valid_names,
            valid_target_ids: self.valid_target_ids,
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
    /// Detail to append to each merged-into canonical's description.
    /// Never replaces — only appended with a separator at write time.
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
                appended_description: None,
            })
            .collect();
        let candidates = std::mem::take(&mut self.candidates);
        if candidates.is_empty() {
            return Ok(aggregated);
        }
        let chunks = self.pack_into_chunks(candidates);
        tracing::info!(
            "{}: {} candidate chunks (concurrency={}, candidate_token_budget={})",
            self.label_root,
            chunks.len(),
            self.chunking.concurrency,
            self.chunking.chunk_candidate_token_budget,
        );
        // Precompute the project-wide valid-names set once and share it
        // by `Arc` across every chunk's emit tool (so the tool can reject
        // hallucinated names at the call site instead of in the post-hoc
        // aggregator).
        let valid_names: Arc<HashSet<String>> = Arc::new(
            self.new_semantics
                .iter()
                .map(|s| s.name.to_lowercase())
                .collect(),
        );
        let by_name = SemanticMergeAggregator::name_index(&self.new_semantics);
        let known_targets = SemanticMergeAggregator::known_canonical_ids(&chunks);
        let new_semantics_block = Self::render_new_block(&self.new_semantics);
        let chunk_results = self
            .dispatch_chunks(chunks, new_semantics_block, valid_names)
            .await?;
        SemanticMergeAggregator::merge(&mut aggregated, chunk_results, &by_name, &known_targets);
        Ok(aggregated)
    }

    fn pack_into_chunks(
        &self,
        candidates: Vec<CanonicalWithChildren<semantic_node::Model>>,
    ) -> Vec<Vec<CanonicalWithChildren<semantic_node::Model>>> {
        let model = self.llm.model.clone();
        Self::pack_chunks(
            &model,
            candidates,
            self.chunking.chunk_candidate_token_budget,
        )
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
        SemanticMergeChunkRunner {
            llm: self.llm.clone(),
            options: self.agent_options.scoped(&debug_scope),
            system_prompt: crate::prompts::GENERAL_ROLE_SYSTEM.to_string(),
            user_prompt,
            cache_key,
            label,
            valid_names,
            valid_target_ids,
        }
    }

    async fn dispatch_chunks(
        &self,
        chunks: Vec<Vec<CanonicalWithChildren<semantic_node::Model>>>,
        new_semantics_block: String,
        valid_names: Arc<HashSet<String>>,
    ) -> Result<Vec<Vec<SemanticMergeDecision>>> {
        let total = chunks.len();
        let concurrency = self.chunking.concurrency.max(1);
        if concurrency <= 1 || total <= 1 {
            self.dispatch_sequential(chunks, new_semantics_block, valid_names)
                .await
        } else {
            self.dispatch_concurrent(chunks, new_semantics_block, valid_names, concurrency)
                .await
        }
    }

    async fn dispatch_sequential(
        &self,
        chunks: Vec<Vec<CanonicalWithChildren<semantic_node::Model>>>,
        new_semantics_block: String,
        valid_names: Arc<HashSet<String>>,
    ) -> Result<Vec<Vec<SemanticMergeDecision>>> {
        let total = chunks.len();
        let mut out = Vec::with_capacity(total);
        for (idx, chunk) in chunks.into_iter().enumerate() {
            let runner = self.build_chunk_runner(
                idx,
                total,
                &chunk,
                &new_semantics_block,
                valid_names.clone(),
            );
            out.push(runner.run().await?);
        }
        Ok(out)
    }

    async fn dispatch_concurrent(
        &self,
        chunks: Vec<Vec<CanonicalWithChildren<semantic_node::Model>>>,
        new_semantics_block: String,
        valid_names: Arc<HashSet<String>>,
        concurrency: usize,
    ) -> Result<Vec<Vec<SemanticMergeDecision>>> {
        let total = chunks.len();
        let mut joins: JoinSet<(usize, Result<Vec<SemanticMergeDecision>>)> = JoinSet::new();
        let mut pending = chunks.into_iter().enumerate().collect::<Vec<_>>();
        let mut alive = 0usize;
        let mut results: Vec<Option<Vec<SemanticMergeDecision>>> =
            (0..total).map(|_| None).collect();
        while !pending.is_empty() || alive > 0 {
            while alive < concurrency && !pending.is_empty() {
                let (idx, chunk) = pending.remove(0);
                let runner = self.build_chunk_runner(
                    idx,
                    total,
                    &chunk,
                    &new_semantics_block,
                    valid_names.clone(),
                );
                joins.spawn(async move { (idx, runner.run().await) });
                alive += 1;
            }
            if let Some(joined) = joins.join_next().await {
                alive -= 1;
                let (idx, res) = joined.map_err(|e| KgError::other(format!("merge join: {e}")))?;
                results[idx] = Some(res?);
            }
        }
        Ok(results.into_iter().map(|o| o.unwrap_or_default()).collect())
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
                Self::adopt_longer(&mut agg.appended_description, decision.appended_description);
            }
        }
    }

    fn adopt_longer(slot: &mut Option<String>, candidate: Option<String>) {
        if let Some(candidate) = candidate {
            if candidate.trim().is_empty() {
                return;
            }
            match slot {
                Some(existing) if existing.len() >= candidate.len() => {}
                _ => *slot = Some(candidate),
            }
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
            let cost = crate::learn::count_tokens(model, &single);
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
    /// Optional behavioural detail this raw contributes — appended to the
    /// canonical's description, never replaces. The canonical's `title`,
    /// `severity`, and `root_cause` are stable identity and are never
    /// modified by a merge decision.
    pub appended_description: Option<String>,
    /// Optional additional pattern detail this raw contributes — appended
    /// to canonical's patterns, never replaces.
    pub appended_patterns: Option<String>,
    /// Optional additional exploit-path detail this raw contributes —
    /// appended to canonical's exploits, never replaces.
    pub appended_exploits: Option<String>,
}

#[derive(Debug, Clone)]
#[tool(
    arguments = FindingMergeDecision,
    invoke = invoke,
    description = "Emit one merge decision for a new raw finding. Call once per `new_finding_title` shown in the prompt. `merge_target_ids` may list multiple canonicals from THIS chunk; an empty list means NEW (no match in this chunk). The canonical's `title`, `severity`, and `root_cause` are stable identity and are NEVER modified by this decision — only `appended_description` / `appended_patterns` / `appended_exploits` (optional, when merging) are appended to the canonical's existing fields. The tool validates `new_finding_title` against the prompt's new-findings list and `merge_target_ids` against this chunk's candidate IDs; invalid decisions are rejected with an error message so you can re-emit a corrected one.",
    name = "emit_finding_merge_decision",
)]
struct EmitFindingMergeDecisionTool {
    buffer: Arc<AgentChunkBuffer<FindingMergeDecision>>,
    /// Lower-cased titles of every newly-extracted finding in the project.
    valid_titles: Arc<HashSet<String>>,
    /// Canonical IDs visible in *this* chunk's prompt.
    valid_target_ids: Arc<HashSet<i32>>,
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
}

impl FindingMergeChunkRunner {
    pub async fn run(self) -> Result<Vec<FindingMergeDecision>> {
        let buffer = AgentChunkBuffer::<FindingMergeDecision>::new();

        let mut tools = ToolBox::new();
        tools.add_tool(EmitFindingMergeDecisionTool {
            buffer: buffer.clone(),
            valid_titles: self.valid_titles,
            valid_target_ids: self.valid_target_ids,
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
    /// Detail to append to each merged-into canonical's description.
    pub appended_description: Option<String>,
    /// Detail to append to each merged-into canonical's patterns.
    pub appended_patterns: Option<String>,
    /// Detail to append to each merged-into canonical's exploits.
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
                appended_description: None,
                appended_patterns: None,
                appended_exploits: None,
            })
            .collect();
        let candidates = std::mem::take(&mut self.candidates);
        if candidates.is_empty() {
            return Ok(aggregated);
        }
        let chunks = self.pack_into_chunks(candidates);
        tracing::info!(
            "{}: {} candidate chunks (concurrency={}, candidate_token_budget={})",
            self.label_root,
            chunks.len(),
            self.chunking.concurrency,
            self.chunking.chunk_candidate_token_budget,
        );
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
        // Same as SemanticMerger: precompute the per-project valid-title
        // set once, share by Arc into every chunk's emit tool so
        // hallucinated titles are rejected at the call site.
        let valid_titles: Arc<HashSet<String>> = Arc::new(by_title.keys().cloned().collect());
        let new_findings_block = Self::render_new_block(&self.new_findings);
        let chunk_results = self
            .dispatch_chunks(chunks, new_findings_block, valid_titles)
            .await?;
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
                SemanticMergeAggregator::adopt_longer(
                    &mut agg.appended_description,
                    decision.appended_description,
                );
                SemanticMergeAggregator::adopt_longer(
                    &mut agg.appended_patterns,
                    decision.appended_patterns,
                );
                SemanticMergeAggregator::adopt_longer(
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
    ) -> Vec<Vec<FindingCanonicalWithTaxonomy>> {
        let model = self.llm.model.clone();
        Self::pack_chunks(
            &model,
            candidates,
            self.chunking.chunk_candidate_token_budget,
        )
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
        FindingMergeChunkRunner {
            llm: self.llm.clone(),
            options: self.agent_options.scoped(&debug_scope),
            system_prompt: crate::prompts::GENERAL_ROLE_SYSTEM.to_string(),
            user_prompt,
            cache_key,
            label,
            valid_titles,
            valid_target_ids,
        }
    }

    async fn dispatch_chunks(
        &self,
        chunks: Vec<Vec<FindingCanonicalWithTaxonomy>>,
        new_findings_block: String,
        valid_titles: Arc<HashSet<String>>,
    ) -> Result<Vec<Vec<FindingMergeDecision>>> {
        let total = chunks.len();
        let concurrency = self.chunking.concurrency.max(1);
        if concurrency <= 1 || total <= 1 {
            self.dispatch_sequential(chunks, new_findings_block, valid_titles)
                .await
        } else {
            self.dispatch_concurrent(chunks, new_findings_block, valid_titles, concurrency)
                .await
        }
    }

    async fn dispatch_sequential(
        &self,
        chunks: Vec<Vec<FindingCanonicalWithTaxonomy>>,
        new_findings_block: String,
        valid_titles: Arc<HashSet<String>>,
    ) -> Result<Vec<Vec<FindingMergeDecision>>> {
        let total = chunks.len();
        let mut out = Vec::with_capacity(total);
        for (idx, chunk) in chunks.into_iter().enumerate() {
            let runner = self.build_chunk_runner(
                idx,
                total,
                &chunk,
                &new_findings_block,
                valid_titles.clone(),
            );
            out.push(runner.run().await?);
        }
        Ok(out)
    }

    async fn dispatch_concurrent(
        &self,
        chunks: Vec<Vec<FindingCanonicalWithTaxonomy>>,
        new_findings_block: String,
        valid_titles: Arc<HashSet<String>>,
        concurrency: usize,
    ) -> Result<Vec<Vec<FindingMergeDecision>>> {
        let total = chunks.len();
        let mut joins: JoinSet<(usize, Result<Vec<FindingMergeDecision>>)> = JoinSet::new();
        let mut pending = chunks.into_iter().enumerate().collect::<Vec<_>>();
        let mut alive = 0usize;
        let mut results: Vec<Option<Vec<FindingMergeDecision>>> =
            (0..total).map(|_| None).collect();
        while !pending.is_empty() || alive > 0 {
            while alive < concurrency && !pending.is_empty() {
                let (idx, chunk) = pending.remove(0);
                let runner = self.build_chunk_runner(
                    idx,
                    total,
                    &chunk,
                    &new_findings_block,
                    valid_titles.clone(),
                );
                joins.spawn(async move { (idx, runner.run().await) });
                alive += 1;
            }
            if let Some(joined) = joins.join_next().await {
                alive -= 1;
                let (idx, res) = joined.map_err(|e| KgError::other(format!("merge join: {e}")))?;
                results[idx] = Some(res?);
            }
        }
        Ok(results.into_iter().map(|o| o.unwrap_or_default()).collect())
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
                        "  - Title: {}\n    Severity: {}\n    Root Cause: {}\n    Description: {}\n",
                        raw.title, raw.severity, raw.root_cause, raw.description,
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
            let cost = crate::learn::count_tokens(model, &single);
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
