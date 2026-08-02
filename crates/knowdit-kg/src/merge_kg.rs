//! `merge_kg` — merge one historical KG (the *source*) into another (the
//! *destination*) with semantic dedup, reusing the `workflow learn` machinery.
//!
//! High-level flow (source `B` → destination `A`):
//!
//! 1. **Global canonical dedup.** Every canonical semantic / finding of `B`
//!    is compared against `A`'s canonicals by the reusable merge agents
//!    ([`SemanticMerger`] / [`FindingMerger`]). Each yields a New / Merge
//!    decision.
//! 2. **Flatten import.** [`HistoricalDatabase::import_merged_canonicals`]
//!    writes each `B` canonical as a *fresh leaf*: New ⇒ becomes an `A`
//!    canonical; Merge ⇒ a single `semantic_merge` / `finding_merge` edge to
//!    the `A` canonical (one level, never a chain). Provenance is carried.
//! 3. **Structural link carry (no LLM).** `B`'s `semantic_finding_link` rows
//!    are remapped through the src→dst id maps and inserted verbatim, so `B`'s
//!    entire internal link knowledge (intra- and cross-project) comes over
//!    without re-running the linker.
//! 4. **Cross-seam ③a — retro-link.** `A`'s pre-existing findings are linked
//!    against `B`'s genuinely-new canonical semantics (the New decisions).
//! 5. **Cross-seam ③b — link.** `B`'s genuinely-new findings are linked
//!    against `A`'s pre-existing canonical semantics (candidate set scoped by
//!    the pre-import id ceiling in `residual` mode).
//!
//! Overlapping concepts (folded in step 2) need no LLM linking: the fold plus
//! the carried links plus the mapper's raw-chase already surface `B`'s
//! findings under the merged `A` canonical. Only the non-overlapping
//! `{new} × {old}` tails cost LLM, and they are symmetric (steps 4 and 5).

use std::collections::HashMap;

use itertools::Itertools;
use llmy::client::client::LLM;

use crate::agent_runner::AgentRunOptions;
use crate::agents::{
    AggregatedFindingMergeDecision, FindingMerger, MergeChunkingOptions, SemanticMerger,
};
use crate::category::DeFiCategory;
use crate::db::{HistoricalDatabase, MergeImportFinding, MergeImportLink, MergeImportSemantic};
use crate::error::Result;
use crate::learn::{ExtractedFinding, ExtractedSemantic};
use crate::link::{FindingLinkOptions, retro_link_pending_semantics};
use crate::vulnerability::VulnerabilityCategory;
use knowdit_kg_model::db::merge_status::MergePhase;

/// Scope of the ③b cross-seam link pass (source findings × destination
/// semantics).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkMode {
    /// Present only the destination's pre-import (native) canonical semantics
    /// as candidates — trusting the dedup fold to have already connected
    /// overlapping concepts. Cheapest correct scope.
    Residual,
    /// Present every canonical (a safety net against imperfect folding).
    Full,
    /// Skip ③b entirely (imported new findings are marked link-complete).
    Off,
}

#[derive(Debug, Clone)]
pub struct MergeKgOptions {
    pub merge_agent: AgentRunOptions,
    pub merge_chunking: MergeChunkingOptions,
    /// Knobs for both cross-seam link passes (concurrency, token budgets, …).
    pub link: FindingLinkOptions,
    /// Run the ③a retro-link pass (`A`'s findings × `B`'s new semantics).
    pub run_retro_link: bool,
    pub link_mode: LinkMode,
    /// Stable label for the source KG, used as the resume key (persisted in
    /// `merge_status.source_key`). NOT the connection string — that can carry
    /// credentials. Re-running with the same key resumes an interrupted merge.
    pub source_key: String,
}

#[derive(Debug, Default)]
pub struct MergeKgReport {
    pub projects_imported: usize,
    pub new_semantics: usize,
    pub folded_semantics: usize,
    pub new_findings: usize,
    pub folded_findings: usize,
    pub carried_links: usize,
    pub retro_linked: bool,
    pub linked: bool,
}

/// Merge `src` into `dst`. `dst` must already be schema-initialised (the CLI
/// wrapper opens it via `connect_init`). `src` is read-only.
pub async fn merge_kg(
    src: &HistoricalDatabase,
    dst: &HistoricalDatabase,
    llm: &LLM,
    opts: MergeKgOptions,
) -> Result<MergeKgReport> {
    let mut report = MergeKgReport::default();
    let source_key = opts.source_key.clone();

    // ── Resume detection ────────────────────────────────────────────────
    // A merge is: global dedup → ONE atomic import → ③a retro-link → ③b
    // link. The import writes a `merge_status` row (phase `'imported'`) inside
    // its own transaction, so "import committed ⟺ a row exists". On re-run we
    // look that row up: if present the import already landed and we skip it
    // (re-importing would duplicate every source canonical) and resume the
    // link passes; if absent this is a fresh merge. The link passes are
    // themselves resumable via their own queues (`pending_semantic` for retro,
    // `finding_link_status` for ③b) — `phase` only gates whether we re-enter
    // each stage, and carries the persisted `native_sem_ceiling` so ③b's
    // `Residual` scope stays correct across a resume.
    let (merge_id, sem_ceiling, mut phase) = match dst.get_active_merge(&source_key).await? {
        Some((id, ceiling, phase)) => {
            tracing::info!(
                merge_id = id,
                phase = %phase,
                source_key = %source_key,
                "merge-kg: resuming interrupted merge — import already committed, skipping it"
            );
            (id, ceiling, phase)
        }
        None => run_merge_import(src, dst, llm, &opts, &source_key, &mut report).await?,
    };

    // `phase` is an ordered cursor (Imported < Retro < Link): each stage runs
    // only if the persisted phase hasn't reached it yet, so a resume re-enters
    // exactly the unfinished stages.

    // ── ③a retro-link — A findings × B new semantics ────────────────────
    if phase < MergePhase::Retro {
        if opts.run_retro_link {
            retro_link_pending_semantics(dst, llm, opts.link).await?;
            report.retro_linked = true;
        } else {
            // Don't leave the enqueued New semantics as dead queue rows.
            dst.clear_pending_semantic_queue().await?;
        }
        dst.set_merge_phase(merge_id, MergePhase::Retro).await?;
        phase = MergePhase::Retro;
    }

    // ── ③b link — B new findings × A old semantics ──────────────────────
    if phase < MergePhase::Link {
        match opts.link_mode {
            LinkMode::Off => {
                // Imported new findings won't be visited by the linker; mark
                // every still-pending finding link-complete so carried
                // `semantic_finding_link` rows don't read as a partial-link
                // state. Driven by the live pending set (not the import
                // outcome) so it's correct on a resume, where no outcome exists.
                for finding in dst.list_pending_findings_for_linking().await? {
                    dst.mark_finding_link_complete(finding.finding_id).await?;
                }
            }
            LinkMode::Residual => {
                let mut link_opts = opts.link;
                link_opts.candidate_max_semantic_id = sem_ceiling;
                link_opts.link_pending_findings(dst, llm).await?;
                report.linked = true;
            }
            LinkMode::Full => {
                opts.link.link_pending_findings(dst, llm).await?;
                report.linked = true;
            }
        }
        dst.set_merge_phase(merge_id, MergePhase::Link).await?;
    }

    Ok(report)
}

/// Fresh-merge path: global semantic + finding dedup against the destination's
/// current canonicals, then ONE atomic import (which also writes the
/// `merge_status` marker). Returns `(merge_status.id, native_sem_ceiling,
/// "imported")`. Split out of [`merge_kg`] so the resume path skips it wholesale.
async fn run_merge_import(
    src: &HistoricalDatabase,
    dst: &HistoricalDatabase,
    llm: &LLM,
    opts: &MergeKgOptions,
    source_key: &str,
    report: &mut MergeKgReport,
) -> Result<(i32, Option<i32>, MergePhase)> {
    // ── Phase 0: source/destination id boundary + project provenance ────
    // Captured BEFORE any import: every row we insert gets a strictly larger
    // auto-increment id, so this ceiling cleanly separates `A`-native
    // canonicals (id <= ceiling) from `B`-imported ones for the ③b scope. It
    // is persisted (in the import txn) so a resumed ③b uses the same boundary.
    let sem_ceiling = dst.max_semantic_node_id().await?;

    let src_projects = src.list_completed_projects().await?;
    let mut proj_map: HashMap<i32, i32> = HashMap::new();
    for (project, platform) in &src_projects {
        // Dedup by the raw platform_id: the same real-world contest (e.g.
        // `c4-420`) already present in the destination is reused, not
        // re-imported as a duplicate project row. Projects without a platform
        // id dedup by name. The source's semantics/findings still import
        // normally — only their provenance attaches to the existing project.
        let dst_pid = dst
            .upsert_import_project(
                &project.name,
                platform.as_ref().map(|pp| pp.platform_id.as_str()),
            )
            .await?;
        proj_map.insert(project.id, dst_pid);
    }
    report.projects_imported = proj_map.len();

    // Read the source's canonical graph + provenance + links.
    let src_sem = src.all_canonical_semantics_with_functions().await?;
    let src_find = src.all_canonical_findings_with_taxonomy().await?;
    let src_links = src.all_semantic_finding_links().await?;
    let sem_prov = src.project_semantic_provenance().await?;
    let find_prov = src.project_finding_provenance().await?;

    let map_provenance = |ids: Option<&Vec<i32>>| -> Vec<i32> {
        ids.into_iter()
            .flatten()
            .filter_map(|pid| proj_map.get(pid).copied())
            .collect()
    };

    // ── Phase 1: semantic dedup (global, once) ──────────────────────────
    let sem_extracts: Vec<ExtractedSemantic> = src_sem
        .iter()
        .map(|(node, funcs)| ExtractedSemantic::from_model(node.clone(), funcs.clone()))
        .collect();

    let sem_import: Vec<MergeImportSemantic> = if sem_extracts.is_empty() {
        Vec::new()
    } else {
        let categories: Vec<DeFiCategory> =
            sem_extracts.iter().map(|s| s.category).unique().collect();
        let candidates = dst
            .canonical_semantics_with_children_for_categories(&categories)
            .await?;
        let decisions = SemanticMerger {
            new_semantics: sem_extracts.clone(),
            candidates,
            llm: llm.clone(),
            agent_options: opts.merge_agent.clone(),
            chunking: opts.merge_chunking,
            debug_key_root: "merge-kg-semantic".to_string(),
            label_root: "merge-kg-semantic".to_string(),
        }
        .run()
        .await?;
        let by_name: HashMap<String, (Vec<i32>, Option<String>, Option<String>)> = decisions
            .into_iter()
            .map(|d| {
                (
                    d.new_semantic_name.to_lowercase(),
                    (
                        d.merge_target_ids,
                        d.updated_description,
                        d.appended_description,
                    ),
                )
            })
            .collect();

        src_sem
            .iter()
            .zip(sem_extracts.iter())
            .map(|((node, _), extract)| {
                let decision = by_name.get(&extract.name.to_lowercase());
                MergeImportSemantic {
                    src_id: node.id,
                    semantic: extract.clone(),
                    target_ids: decision.map(|(t, _, _)| t.clone()).unwrap_or_default(),
                    updated_description: decision.and_then(|(_, u, _)| u.clone()),
                    appended_description: decision.and_then(|(_, _, a)| a.clone()),
                    provenance: map_provenance(sem_prov.get(&node.id)),
                }
            })
            .collect()
    };

    // ── Phase 2: finding dedup (global, once) ───────────────────────────
    let find_extracts: Vec<ExtractedFinding> = src_find
        .iter()
        .map(|(model, category, subcategory)| {
            ExtractedFinding::from_model(model.clone(), *category, subcategory.clone())
        })
        .collect();

    let find_import: Vec<MergeImportFinding> = if find_extracts.is_empty() {
        Vec::new()
    } else {
        let categories: Vec<VulnerabilityCategory> =
            find_extracts.iter().map(|f| f.category).unique().collect();
        let candidates = dst
            .canonical_findings_with_children_for_categories(&categories)
            .await?;
        let decisions = FindingMerger {
            new_findings: find_extracts.clone(),
            candidates,
            llm: llm.clone(),
            agent_options: opts.merge_agent.clone(),
            chunking: opts.merge_chunking,
            debug_key_root: "merge-kg-finding".to_string(),
            label_root: "merge-kg-finding".to_string(),
        }
        .run()
        .await?;
        let by_title: HashMap<String, AggregatedFindingMergeDecision> = decisions
            .into_iter()
            .map(|d| (d.new_finding_title.to_lowercase(), d))
            .collect();

        src_find
            .iter()
            .zip(find_extracts.iter())
            .map(|((model, _, _), extract)| {
                let decision = by_title.get(&extract.title.to_lowercase());
                MergeImportFinding {
                    src_id: model.id,
                    finding: extract.clone(),
                    target_ids: decision
                        .map(|d| d.merge_target_ids.clone())
                        .unwrap_or_default(),
                    updated_description: decision.and_then(|d| d.updated_description.clone()),
                    updated_patterns: decision.and_then(|d| d.updated_patterns.clone()),
                    updated_exploits: decision.and_then(|d| d.updated_exploits.clone()),
                    appended_description: decision.and_then(|d| d.appended_description.clone()),
                    appended_patterns: decision.and_then(|d| d.appended_patterns.clone()),
                    appended_exploits: decision.and_then(|d| d.appended_exploits.clone()),
                    provenance: map_provenance(find_prov.get(&model.id)),
                }
            })
            .collect()
    };

    // ── Phase 3: structural link carry inputs ───────────────────────────
    let link_import: Vec<MergeImportLink> = src_links
        .iter()
        .map(|l| MergeImportLink {
            src_finding_id: l.audit_finding_id,
            src_semantic_id: l.semantic_node_id,
            strength: l.strength,
            evidence: l.evidence.clone(),
        })
        .collect();

    // Persist Phases 1–3 atomically. The SAME transaction writes the
    // `merge_status` marker (phase `'imported'`), keyed by `source_key` and
    // carrying `sem_ceiling`, so an interrupted run resumes from the link
    // passes instead of re-importing.
    let outcome = dst
        .import_merged_canonicals(
            &sem_import,
            &find_import,
            &link_import,
            source_key,
            sem_ceiling,
        )
        .await?;
    report.new_semantics = outcome.new_semantics;
    report.folded_semantics = outcome.folded_semantics;
    report.new_findings = outcome.new_findings;
    report.folded_findings = outcome.folded_findings;
    report.carried_links = outcome.carried_links;

    tracing::info!(
        "merge-kg import done: semantics +{} new / {} folded, findings +{} new / {} folded, {} links carried",
        outcome.new_semantics,
        outcome.folded_semantics,
        outcome.new_findings,
        outcome.folded_findings,
        outcome.carried_links,
    );

    Ok((outcome.merge_status_id, sem_ceiling, MergePhase::Imported))
}
