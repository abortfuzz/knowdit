use crate::category::DeFiCategory;
use crate::db::DatabaseGraph;
use crate::error::{KgError, Result};
pub use crate::link::{
    FindingLinkOptions, PendingFindingForLinking, PersistedFindingLinkResult, link_pending_findings,
};
use crate::project_loader::ProjectData;
use crate::prompts;
use crate::vulnerability::{FindingSeverity, VulnerabilityCategory, resolve_taxonomy_entry};
use itertools::Itertools;
use llmy::client::client::LLM;
use llmy::client::context::TokenCursor;
use llmy::client::model::OpenAIModel;
use llmy::openai::types::chat::CreateChatCompletionResponse;
use llmy::tokenizer;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

// ── LLM response types ──────────────────────────────────────────────

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct CategorizeResponse {
    project_name: String,
    categories: Vec<DeFiCategory>,
    reasoning: String,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct ExtractedSemantic {
    pub name: String,
    pub category: DeFiCategory,
    pub definition: String,
    pub description: String,
    pub short_description: String,
    pub functions: Vec<ExtractedFunction>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct ExtractedFunction {
    pub name: String,
    pub contract: String,
    pub signature: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ExtractResponse {
    semantics: Vec<ExtractedSemantic>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct ExtractedFinding {
    pub title: String,
    pub severity: FindingSeverity,
    pub category: VulnerabilityCategory,
    pub subcategory: String,
    pub root_cause: String,
    pub description: String,
    pub patterns: String,
    pub exploits: String,
}

#[derive(Debug, Deserialize)]
struct FindingExtractResponse {
    findings: Vec<ExtractedFinding>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct MergeDecision {
    new_semantic_name: String,
    action: String,
    merge_target_id: Option<i32>,
    updated_name: Option<String>,
    updated_definition: Option<String>,
    updated_description: Option<String>,
    reason: String,
}

#[derive(Debug, Deserialize)]
struct MergeResponse {
    decisions: Vec<MergeDecision>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct FindingMergeDecision {
    new_finding_title: String,
    action: String,
    merge_target_id: Option<i32>,
    updated_severity: Option<FindingSeverity>,
    updated_root_cause: Option<String>,
    updated_description: Option<String>,
    updated_patterns: Option<String>,
    updated_exploits: Option<String>,
    reason: String,
}

#[derive(Debug, Deserialize)]
struct FindingMergeResponse {
    decisions: Vec<FindingMergeDecision>,
}

#[derive(Debug, thiserror::Error)]
enum MergeResponseValidationError {
    #[error(
        "Semantic merge response referenced unknown target sem-{target_id} for '{semantic_name}'"
    )]
    UnknownSemanticTarget {
        semantic_name: String,
        target_id: i32,
    },

    #[error(
        "Finding merge response referenced unknown target finding-{target_id} for '{finding_title}'"
    )]
    UnknownFindingTarget {
        finding_title: String,
        target_id: i32,
    },
}

// ── Public merge types (used by DatabaseGraph) ────────────────────────

#[derive(Debug, Clone)]
pub enum MergeAction {
    New,
    Merge {
        target_id: i32,
        updated_name: Option<String>,
        updated_definition: Option<String>,
        updated_description: Option<String>,
    },
}

#[derive(Debug, Clone)]
pub struct MergeResult {
    pub semantic: ExtractedSemantic,
    pub action: MergeAction,
}

#[derive(Debug, Clone)]
pub enum FindingMergeAction {
    New,
    Merge {
        target_id: i32,
        updated_severity: Option<FindingSeverity>,
        updated_root_cause: Option<String>,
        updated_description: Option<String>,
        updated_patterns: Option<String>,
        updated_exploits: Option<String>,
    },
}

#[derive(Debug, Clone)]
pub struct FindingMergeResult {
    pub finding: ExtractedFinding,
    pub action: FindingMergeAction,
}

#[derive(Debug, Clone, Copy)]
pub struct MergeRetryOptions {
    pub max_response_attempts: usize,
}

// ── ProjectData learning pipeline ───────────────────────────────────

/// Intermediate result from the categorize + extract phase.
/// Can be computed concurrently across projects.
pub struct ExtractResult {
    pub categories: Vec<DeFiCategory>,
    pub semantics: Vec<ExtractedSemantic>,
    pub findings: Vec<ExtractedFinding>,
}

impl ProjectData {
    /// Phase 1: Categorize the project and extract semantics.
    /// Safe to run concurrently across multiple projects.
    pub async fn categorize_and_extract(&self, llm: &LLM) -> Result<ExtractResult> {
        let pid = self.display_id();

        tracing::info!(
            "Processing project {}: {} ({} source files)",
            pid,
            self.name,
            self.source_files.len()
        );

        if self.source_files.is_empty() {
            tracing::warn!("No source files found for project {}", pid);
            return Ok(ExtractResult {
                categories: vec![],
                semantics: vec![],
                findings: vec![],
            });
        }

        let categories = self.categorize(llm).await?;
        tracing::info!("Project {} categorized as: {:?}", pid, categories);

        let (all_semantics, all_findings) = tokio::try_join!(
            self.extract_semantics(llm, &categories),
            self.extract_findings(llm, &categories)
        )?;

        tracing::info!(
            "Extracted {} raw semantics from project {}",
            all_semantics.len(),
            pid
        );

        tracing::info!(
            "Extracted {} raw findings from project {}",
            all_findings.len(),
            pid
        );

        let deduped = Self::dedup_semantics(all_semantics);
        let deduped_findings = Self::dedup_findings(all_findings);
        tracing::info!(
            "After intra-project dedup: {} semantics for project {}",
            deduped.len(),
            pid
        );

        tracing::info!(
            "After intra-project dedup: {} findings for project {}",
            deduped_findings.len(),
            pid
        );

        Ok(ExtractResult {
            categories,
            semantics: deduped,
            findings: deduped_findings,
        })
    }

    /// Phase 2: Merge extracted semantics with existing KB and write to DB.
    /// MUST be run serially (one project at a time) to avoid merge conflicts.
    pub async fn merge_and_write(
        &self,
        db: &DatabaseGraph,
        llm: &LLM,
        extract: &ExtractResult,
        merge_options: MergeRetryOptions,
    ) -> Result<()> {
        let pid = self.display_id();

        if extract.semantics.is_empty() && extract.findings.is_empty() {
            db.write_project_completed(
                &self.name,
                self.platform_id.as_deref(),
                &extract.categories,
                &[],
                &[],
            )
            .await?;
            tracing::info!("Project {} written (no semantics or findings)", pid);
            return Ok(());
        }

        let semantic_merge_results = self
            .merge_with_existing(db, llm, extract, merge_options)
            .await?;
        let finding_merge_results = self
            .merge_findings_with_existing(db, llm, extract, merge_options)
            .await?;

        db.write_project_completed(
            &self.name,
            self.platform_id.as_deref(),
            &extract.categories,
            &semantic_merge_results,
            &finding_merge_results,
        )
        .await?;

        tracing::info!("Project {} fully processed and saved", pid);
        Ok(())
    }

    /// Check if this project is already completed in the DB.
    pub async fn is_completed(&self, db: &DatabaseGraph) -> Result<bool> {
        if let Some(pid) = &self.platform_id {
            db.is_project_completed(pid).await
        } else {
            Ok(db
                .get_project_by_name(&self.name)
                .await?
                .map(|p| p.status == "completed")
                .unwrap_or(false))
        }
    }

    fn build_project_prompt_body(&self) -> String {
        let mut content = prompts::project_user_prefix();
        content.push_str("## Source Files\n\n");

        for file in &self.source_files {
            content.push_str(&format!(
                "### {}\n```{}\n{}\n```\n\n",
                file.relative_path,
                self.source_language.code_fence(),
                file.content
            ));
        }

        if let Some(readme) = self.load_readme() {
            content.push_str("## README\n\n");
            content.push_str(&readme);
            content.push_str("\n\n");
        }

        content
    }

    fn build_report_prompt_body(&self) -> Option<String> {
        let report = self.audit_report.as_ref()?.render();
        let mut content = prompts::report_user_prefix();
        content.push_str(&report);
        content.push_str("\n\n");
        Some(content)
    }

    fn load_readme(&self) -> Option<String> {
        for name in &["README.md", "readme.md", "Readme.md"] {
            let readme_path = self.root_dir.join(name);
            if readme_path.exists() {
                if let Ok(readme) = std::fs::read_to_string(&readme_path) {
                    return Some(readme);
                }
            }
        }

        None
    }

    fn prompt_cache_key(&self) -> String {
        sanitize_prompt_prefix(&self.display_id())
    }

    fn debug_key(&self, stage: &str) -> String {
        format!(
            "{}-{}",
            sanitize_prompt_prefix(stage),
            self.prompt_cache_key()
        )
    }

    fn merge_cache_key(&self) -> String {
        format!("{}-merge", self.prompt_cache_key())
    }

    fn finding_cache_key(&self) -> String {
        format!("{}-finding", self.prompt_cache_key())
    }

    fn finding_merge_cache_key(&self) -> String {
        format!("{}-finding-merge", self.prompt_cache_key())
    }

    // ── Private pipeline steps ──────────────────────────────────────

    /// Categorize the project using an LLM. Fills the context window with
    /// the README and as many source files as fit.
    async fn categorize(&self, llm: &LLM) -> Result<Vec<DeFiCategory>> {
        let model = &llm.model;
        let system_prompt = prompts::GENERAL_ROLE_SYSTEM;
        let user_suffix = prompts::CATEGORIZE_USER_SUFFIX;
        let debug_key = self.debug_key("categorize");
        let cache_key = self.prompt_cache_key();
        let sys_tokens = count_tokens(model, system_prompt);
        let suffix_tokens = count_tokens(model, &user_suffix);
        let budget = get_context_budget(model).saturating_sub(sys_tokens + suffix_tokens);
        let content = self.build_project_prompt_body();

        // Take only what fits in the budget
        let Some(mut cursor) = TokenCursor::new(content, model.clone()) else {
            return Err(KgError::other(
                "Failed to initialize TokenCursor for categorization",
            ));
        };
        let user_msg = format!("{}{}", cursor.next_chunk(budget).unwrap_or(""), user_suffix);

        tracing::info!(
            "Categorization prompt: ~{} tokens (budget: {})",
            sys_tokens + count_tokens(model, &user_msg),
            sys_tokens + budget
        );

        let parsed: CategorizeResponse = prompt_json_with_retry(
            llm,
            system_prompt,
            &user_msg,
            Some(&debug_key),
            Some(&cache_key),
            "categorization",
        )
        .await?;
        Ok(parsed.categories)
    }

    /// Extract semantics from the project's source files. Splits the full
    /// source text into chunks that fit the context window, calling the LLM
    /// once per chunk.
    async fn extract_semantics(
        &self,
        llm: &LLM,
        categories: &[DeFiCategory],
    ) -> Result<Vec<ExtractedSemantic>> {
        let system_prompt = prompts::GENERAL_ROLE_SYSTEM;
        let model = &llm.model;
        let debug_key = self.debug_key("extract");
        let cache_key = self.prompt_cache_key();
        let sys_tokens = count_tokens(model, system_prompt);
        let total_budget = get_context_budget(model);
        let user_suffix = prompts::extract_semantics_user_suffix(categories);
        let suffix_tokens = count_tokens(model, &user_suffix);

        // Token budget available for source content per chunk
        let chunk_budget = total_budget.saturating_sub(sys_tokens + suffix_tokens);

        let all_files = self.build_project_prompt_body();

        let Some(mut cursor) = TokenCursor::new(all_files, model.clone()) else {
            return Err(KgError::other(
                "Failed to initialize TokenCursor for extraction",
            ));
        };
        let mut all_semantics = Vec::new();
        let mut chunk_idx = 0;

        while let Some(chunk) = cursor.next_chunk(chunk_budget) {
            let user_msg = format!("{}{}", chunk, user_suffix);

            tracing::info!(
                "Extracting semantics from chunk {} (~{} tokens, done={})",
                chunk_idx,
                sys_tokens + count_tokens(model, &user_msg),
                cursor.is_done()
            );

            let parsed: ExtractResponse = prompt_json_with_retry(
                llm,
                system_prompt,
                &user_msg,
                Some(&debug_key),
                Some(&cache_key),
                "semantic extraction",
            )
            .await?;
            all_semantics.extend(parsed.semantics);
            chunk_idx += 1;
        }

        Ok(all_semantics)
    }

    async fn extract_findings(
        &self,
        llm: &LLM,
        categories: &[DeFiCategory],
    ) -> Result<Vec<ExtractedFinding>> {
        let Some(report_body) = self.build_report_prompt_body() else {
            tracing::warn!("No audit report found for project {}", self.display_id());
            return Ok(Vec::new());
        };

        let system_prompt = prompts::GENERAL_ROLE_SYSTEM;
        let model = &llm.model;
        let debug_key = self.debug_key("finding-extract");
        let cache_key = self.finding_cache_key();
        let sys_tokens = count_tokens(model, system_prompt);
        let total_budget = get_context_budget(model);
        let user_suffix = prompts::extract_findings_user_suffix(categories);
        let suffix_tokens = count_tokens(model, &user_suffix);
        let chunk_budget = total_budget.saturating_sub(sys_tokens + suffix_tokens);

        let Some(mut cursor) = TokenCursor::new(report_body, model.clone()) else {
            return Err(KgError::other(
                "Failed to initialize TokenCursor for finding extraction",
            ));
        };

        let mut all_findings = Vec::new();
        let mut chunk_idx = 0;

        while let Some(chunk) = cursor.next_chunk(chunk_budget) {
            let user_msg = format!("{}{}", chunk, user_suffix);

            tracing::info!(
                "Extracting findings from chunk {} (~{} tokens, done={})",
                chunk_idx,
                sys_tokens + count_tokens(model, &user_msg),
                cursor.is_done()
            );

            let parsed: FindingExtractResponse = prompt_json_with_retry(
                llm,
                system_prompt,
                &user_msg,
                Some(&debug_key),
                Some(&cache_key),
                "finding extraction",
            )
            .await?;

            for finding in parsed.findings {
                all_findings.push(Self::canonicalize_finding(finding)?);
            }

            chunk_idx += 1;
        }

        Ok(all_findings)
    }

    /// Deduplicate semantics by name (case-insensitive). Keeps the longer
    /// description and merges function lists.
    fn dedup_semantics(semantics: Vec<ExtractedSemantic>) -> Vec<ExtractedSemantic> {
        let mut by_name: HashMap<String, ExtractedSemantic> = HashMap::new();

        for sem in semantics {
            let key = sem.name.to_lowercase().trim().to_string();
            if let Some(existing) = by_name.get_mut(&key) {
                for func in sem.functions {
                    let already_has = existing
                        .functions
                        .iter()
                        .any(|f| f.name == func.name && f.contract == func.contract);
                    if !already_has {
                        existing.functions.push(func);
                    }
                }
                if sem.description.len() > existing.description.len() {
                    existing.description = sem.description;
                    existing.definition = sem.definition;
                }
            } else {
                by_name.insert(key, sem);
            }
        }

        by_name.into_values().collect()
    }

    fn dedup_findings(findings: Vec<ExtractedFinding>) -> Vec<ExtractedFinding> {
        let mut by_title: HashMap<String, ExtractedFinding> = HashMap::new();

        for finding in findings {
            let key = finding.title.to_lowercase().trim().to_string();
            if let Some(existing) = by_title.get_mut(&key) {
                existing.severity = existing.severity.max(finding.severity);

                if finding.description.len() > existing.description.len() {
                    existing.category = finding.category;
                    existing.subcategory = finding.subcategory.clone();
                    existing.description = finding.description.clone();
                }

                if finding.root_cause.len() > existing.root_cause.len() {
                    existing.root_cause = finding.root_cause.clone();
                }

                if finding.patterns.len() > existing.patterns.len() {
                    existing.patterns = finding.patterns.clone();
                }

                if finding.exploits.len() > existing.exploits.len() {
                    existing.exploits = finding.exploits.clone();
                }
            } else {
                by_title.insert(key, finding);
            }
        }

        by_title.into_values().collect()
    }

    fn canonicalize_finding(mut finding: ExtractedFinding) -> Result<ExtractedFinding> {
        finding.title = finding.title.trim().to_string();
        finding.root_cause = finding.root_cause.trim().to_string();
        finding.description = finding.description.trim().to_string();
        finding.patterns = finding.patterns.trim().to_string();
        finding.exploits = finding.exploits.trim().to_string();

        let Some(entry) = resolve_taxonomy_entry(finding.category, &finding.subcategory) else {
            return Err(KgError::other(format!(
                "Unknown vulnerability subcategory '{}' for category '{}'",
                finding.subcategory, finding.category
            )));
        };

        finding.subcategory = entry.subcategory.to_string();
        Ok(finding)
    }

    async fn merge_with_existing(
        &self,
        db: &DatabaseGraph,
        llm: &LLM,
        extract: &ExtractResult,
        merge_options: MergeRetryOptions,
    ) -> Result<Vec<MergeResult>> {
        let semantic_categories: Vec<DeFiCategory> = extract
            .semantics
            .iter()
            .map(|sem| sem.category)
            .unique()
            .collect();
        let existing_nodes = db
            .existing_semantics_for_categories(&semantic_categories)
            .await?;
        let existing_node_ids: HashSet<i32> = existing_nodes.iter().map(|node| node.id).collect();

        if existing_nodes.is_empty() {
            return Ok(extract
                .semantics
                .iter()
                .map(|s| MergeResult {
                    semantic: s.clone(),
                    action: MergeAction::New,
                })
                .collect());
        }

        // Build merge prompt
        let mut existing_desc = String::new();
        for node in &existing_nodes {
            existing_desc.push_str(&format!(
                "ID: {}\nCategory: {}\nName: {}\nDefinition: {}\nDescription: {}\n\n",
                node.id, node.category, node.name, node.definition, node.description
            ));
        }

        let mut new_desc = String::new();
        for sem in &extract.semantics {
            new_desc.push_str(&format!(
                "Category: {}\nName: {}\nDefinition: {}\nDescription: {}\n\n",
                sem.category, sem.name, sem.definition, sem.description
            ));
        }

        let user_msg = prompts::merge_semantics_user_message(&existing_desc, &new_desc);

        let model = &llm.model;
        let sys_tokens = count_tokens(model, prompts::GENERAL_ROLE_SYSTEM);
        let user_tokens = count_tokens(model, &user_msg);

        tracing::info!(
            "Merge decision prompt: ~{} tokens (system: {}, user: {})",
            sys_tokens + user_tokens,
            sys_tokens,
            user_tokens
        );

        let max_tokens = get_context_budget(model);
        if sys_tokens + user_tokens > max_tokens {
            tracing::warn!("Merge prompt too large, marking all as new");
            return Ok(extract
                .semantics
                .iter()
                .map(|s| MergeResult {
                    semantic: s.clone(),
                    action: MergeAction::New,
                })
                .collect());
        }

        let max_response_attempts = merge_options.max_response_attempts.max(1);
        let merge_cache_key = self.merge_cache_key();
        let merge_debug_key = self.debug_key("merge");
        let merge_resp = {
            let mut validated = None;

            for attempt in 1..=max_response_attempts {
                let debug_key = format!("{}-attempt-{}", merge_debug_key, attempt);
                let parsed: MergeResponse = prompt_json_with_retry(
                    llm,
                    prompts::GENERAL_ROLE_SYSTEM,
                    &user_msg,
                    Some(&debug_key),
                    Some(&merge_cache_key),
                    "semantic merge",
                )
                .await?;

                match validate_semantic_merge_response(&parsed, &existing_node_ids) {
                    Ok(()) => {
                        validated = Some(parsed);
                        break;
                    }
                    Err(err) if attempt < max_response_attempts => {
                        tracing::warn!(
                            "Semantic merge response failed validation on attempt {}/{}: {}; retrying",
                            attempt,
                            max_response_attempts,
                            err
                        );
                    }
                    Err(err) => {
                        return Err(KgError::other(format!(
                            "Semantic merge response kept failing validation after {} attempt(s): {}",
                            max_response_attempts, err
                        )));
                    }
                }
            }

            validated.expect("semantic merge validation should either succeed or return")
        };

        let mut results = Vec::new();
        for sem in &extract.semantics {
            let decision = merge_resp
                .decisions
                .iter()
                .find(|d| d.new_semantic_name.to_lowercase() == sem.name.to_lowercase());

            let action = match decision {
                Some(d) if d.action == "merge" => {
                    if let Some(target_id) = d.merge_target_id {
                        MergeAction::Merge {
                            target_id,
                            updated_name: d.updated_name.clone(),
                            updated_definition: d.updated_definition.clone(),
                            updated_description: d.updated_description.clone(),
                        }
                    } else {
                        tracing::warn!(
                            "Merge decision for '{}' missing target_id, treating as new",
                            sem.name
                        );
                        MergeAction::New
                    }
                }
                _ => MergeAction::New,
            };

            results.push(MergeResult {
                semantic: sem.clone(),
                action,
            });
        }

        Ok(results)
    }

    async fn merge_findings_with_existing(
        &self,
        db: &DatabaseGraph,
        llm: &LLM,
        extract: &ExtractResult,
        merge_options: MergeRetryOptions,
    ) -> Result<Vec<FindingMergeResult>> {
        if extract.findings.is_empty() {
            return Ok(Vec::new());
        }

        let finding_categories: Vec<VulnerabilityCategory> = extract
            .findings
            .iter()
            .map(|finding| finding.category)
            .unique()
            .collect();
        let existing_findings = db
            .existing_findings_for_categories(&finding_categories)
            .await?;
        let existing_finding_ids: HashSet<i32> = existing_findings
            .iter()
            .map(|(finding, _)| finding.id)
            .collect();

        if existing_findings.is_empty() {
            return Ok(extract
                .findings
                .iter()
                .map(|finding| FindingMergeResult {
                    finding: finding.clone(),
                    action: FindingMergeAction::New,
                })
                .collect());
        }

        let mut existing_desc = String::new();
        for (finding, category) in &existing_findings {
            existing_desc.push_str(&format!(
                "ID: {}\nSeverity: {}\nCategory: {}\nSubcategory: {}\nTitle: {}\nRoot Cause: {}\nDescription: {}\nPatterns: {}\nExploits: {}\n\n",
                finding.id,
                finding.severity,
                category.category,
                category.name,
                finding.title,
                finding.root_cause,
                finding.description,
                finding.patterns,
                finding.exploits
            ));
        }

        let mut new_desc = String::new();
        for finding in &extract.findings {
            new_desc.push_str(&format!(
                "Severity: {}\nCategory: {}\nSubcategory: {}\nTitle: {}\nRoot Cause: {}\nDescription: {}\nPatterns: {}\nExploits: {}\n\n",
                finding.severity,
                finding.category,
                finding.subcategory,
                finding.title,
                finding.root_cause,
                finding.description,
                finding.patterns,
                finding.exploits
            ));
        }

        let user_msg = prompts::merge_findings_user_message(&existing_desc, &new_desc);
        let model = &llm.model;
        let sys_tokens = count_tokens(model, prompts::GENERAL_ROLE_SYSTEM);
        let user_tokens = count_tokens(model, &user_msg);

        tracing::info!(
            "Finding merge prompt: ~{} tokens (system: {}, user: {})",
            sys_tokens + user_tokens,
            sys_tokens,
            user_tokens
        );

        let max_tokens = get_context_budget(model);
        if sys_tokens + user_tokens > max_tokens {
            tracing::warn!("Finding merge prompt too large, marking all findings as new");
            return Ok(extract
                .findings
                .iter()
                .map(|finding| FindingMergeResult {
                    finding: finding.clone(),
                    action: FindingMergeAction::New,
                })
                .collect());
        }

        let max_response_attempts = merge_options.max_response_attempts.max(1);
        let finding_merge_cache_key = self.finding_merge_cache_key();
        let finding_merge_debug_key = self.debug_key("finding-merge");
        let merge_resp = {
            let mut validated = None;

            for attempt in 1..=max_response_attempts {
                let debug_key = format!("{}-attempt-{}", finding_merge_debug_key, attempt);
                let parsed: FindingMergeResponse = prompt_json_with_retry(
                    llm,
                    prompts::GENERAL_ROLE_SYSTEM,
                    &user_msg,
                    Some(&debug_key),
                    Some(&finding_merge_cache_key),
                    "finding merge",
                )
                .await?;

                match validate_finding_merge_response(&parsed, &existing_finding_ids) {
                    Ok(()) => {
                        validated = Some(parsed);
                        break;
                    }
                    Err(err) if attempt < max_response_attempts => {
                        tracing::warn!(
                            "Finding merge response failed validation on attempt {}/{}: {}; retrying",
                            attempt,
                            max_response_attempts,
                            err
                        );
                    }
                    Err(err) => {
                        return Err(KgError::other(format!(
                            "Finding merge response kept failing validation after {} attempt(s): {}",
                            max_response_attempts, err
                        )));
                    }
                }
            }

            validated.expect("finding merge validation should either succeed or return")
        };

        let mut results = Vec::new();
        for finding in &extract.findings {
            let decision = merge_resp
                .decisions
                .iter()
                .find(|d| d.new_finding_title.to_lowercase() == finding.title.to_lowercase());

            let action = match decision {
                Some(d) if d.action == "merge" => {
                    if let Some(target_id) = d.merge_target_id {
                        FindingMergeAction::Merge {
                            target_id,
                            updated_severity: d.updated_severity,
                            updated_root_cause: d.updated_root_cause.clone(),
                            updated_description: d.updated_description.clone(),
                            updated_patterns: d.updated_patterns.clone(),
                            updated_exploits: d.updated_exploits.clone(),
                        }
                    } else {
                        tracing::warn!(
                            "Finding merge decision for '{}' missing target_id, treating as new",
                            finding.title
                        );
                        FindingMergeAction::New
                    }
                }
                _ => FindingMergeAction::New,
            };

            results.push(FindingMergeResult {
                finding: finding.clone(),
                action,
            });
        }

        Ok(results)
    }
}

// ── Token counting utilities ────────────────────────────────────────

pub(crate) fn count_tokens(model: &OpenAIModel, text: &str) -> usize {
    tokenizer::count_tokens_for_model(model.model_id(), text).unwrap_or_else(|| text.len() / 4)
}

pub(crate) fn get_context_budget(model: &OpenAIModel) -> usize {
    (model.config.max_input() as f64 * 0.8) as _
}

pub(crate) fn sanitize_prompt_prefix(value: &str) -> String {
    let mut out = String::new();
    let mut last_was_dash = false;

    for ch in value.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_lowercase());
            last_was_dash = false;
        } else if !last_was_dash {
            out.push('-');
            last_was_dash = true;
        }

        if out.len() >= 48 {
            break;
        }
    }

    let trimmed = out.trim_matches('-');
    if trimmed.is_empty() {
        "project".to_string()
    } else {
        trimmed.to_string()
    }
}

// ── Response parsing utilities ──────────────────────────────────────

fn extract_response_text(resp: &CreateChatCompletionResponse) -> Result<String> {
    resp.choices
        .first()
        .and_then(|c| c.message.content.as_ref())
        .cloned()
        .ok_or_else(|| KgError::other("No response content from LLM"))
}

pub(crate) async fn prompt_json_with_retry<T: serde::de::DeserializeOwned>(
    llm: &LLM,
    system_prompt: &str,
    user_msg: &str,
    debug_key: Option<&str>,
    cache_key: Option<&str>,
    label: &str,
) -> Result<T> {
    const MAX_PARSE_ATTEMPTS: usize = 3;
    let mut last_error = None;

    for attempt in 1..=MAX_PARSE_ATTEMPTS {
        let resp = llm
            .prompt_once_with_retry(system_prompt, user_msg, debug_key, cache_key, None)
            .await?;

        match extract_response_text(&resp).and_then(|text| parse_json_response(&text)) {
            Ok(parsed) => return Ok(parsed),
            Err(err) => {
                tracing::warn!(
                    "{} parse attempt {}/{} failed: {}",
                    label,
                    attempt,
                    MAX_PARSE_ATTEMPTS,
                    err
                );
                last_error = Some(err);
            }
        }
    }

    Err(last_error.unwrap_or_else(|| {
        KgError::other(format!("{} failed without a concrete parse error", label))
    }))
}

fn parse_json_response<T: serde::de::DeserializeOwned>(text: &str) -> Result<T> {
    let cleaned = strip_code_fence(text);

    if let Ok(parsed) = serde_json::from_str(&cleaned) {
        return Ok(parsed);
    }

    if let Some(json_str) = extract_json_payload(&cleaned) {
        if let Ok(parsed) = serde_json::from_str(&json_str) {
            return Ok(parsed);
        }
    }

    Err(KgError::other(format!(
        "Failed to parse JSON from LLM response:\n{}",
        &text[..text.len().min(500)]
    )))
}

fn strip_code_fence(text: &str) -> String {
    let trimmed = text.trim();
    if trimmed.starts_with("```") {
        let after_first = if let Some(pos) = trimmed.find('\n') {
            &trimmed[pos + 1..]
        } else {
            trimmed
        };
        if after_first.ends_with("```") {
            return after_first[..after_first.len() - 3].trim().to_string();
        }
    }
    trimmed.to_string()
}

fn extract_json_payload(text: &str) -> Option<String> {
    let start = text.find('{')?;
    let mut depth = 0;
    let mut end = start;
    for (i, c) in text[start..].char_indices() {
        match c {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    end = start + i + 1;
                    break;
                }
            }
            _ => {}
        }
    }
    if depth == 0 && end > start {
        Some(text[start..end].to_string())
    } else {
        None
    }
}

fn validate_semantic_merge_response(
    response: &MergeResponse,
    existing_node_ids: &HashSet<i32>,
) -> std::result::Result<(), MergeResponseValidationError> {
    for decision in &response.decisions {
        if decision.action == "merge" {
            if let Some(target_id) = decision.merge_target_id {
                if !existing_node_ids.contains(&target_id) {
                    return Err(MergeResponseValidationError::UnknownSemanticTarget {
                        semantic_name: decision.new_semantic_name.clone(),
                        target_id,
                    });
                }
            }
        }
    }

    Ok(())
}

fn validate_finding_merge_response(
    response: &FindingMergeResponse,
    existing_finding_ids: &HashSet<i32>,
) -> std::result::Result<(), MergeResponseValidationError> {
    for decision in &response.decisions {
        if decision.action == "merge" {
            if let Some(target_id) = decision.merge_target_id {
                if !existing_finding_ids.contains(&target_id) {
                    return Err(MergeResponseValidationError::UnknownFindingTarget {
                        finding_title: decision.new_finding_title.clone(),
                        target_id,
                    });
                }
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_semantic_merge_response_rejects_unknown_target_ids() {
        let response = MergeResponse {
            decisions: vec![MergeDecision {
                new_semantic_name: "Semantic A".to_string(),
                action: "merge".to_string(),
                merge_target_id: Some(999999),
                updated_name: None,
                updated_definition: None,
                updated_description: None,
                reason: "test".to_string(),
            }],
        };

        let error = validate_semantic_merge_response(&response, &HashSet::from([1, 2, 3]))
            .expect_err("unknown semantic merge targets should fail validation");

        assert!(matches!(
            error,
            MergeResponseValidationError::UnknownSemanticTarget {
                semantic_name,
                target_id
            } if semantic_name == "Semantic A" && target_id == 999999
        ));
    }

    #[test]
    fn validate_finding_merge_response_rejects_unknown_target_ids() {
        let response = FindingMergeResponse {
            decisions: vec![FindingMergeDecision {
                new_finding_title: "Finding A".to_string(),
                action: "merge".to_string(),
                merge_target_id: Some(999999),
                updated_severity: None,
                updated_root_cause: None,
                updated_description: None,
                updated_patterns: None,
                updated_exploits: None,
                reason: "test".to_string(),
            }],
        };

        let error = validate_finding_merge_response(&response, &HashSet::from([1, 2, 3]))
            .expect_err("unknown finding merge targets should fail validation");

        assert!(matches!(
            error,
            MergeResponseValidationError::UnknownFindingTarget {
                finding_title,
                target_id
            } if finding_title == "Finding A" && target_id == 999999
        ));
    }
}
