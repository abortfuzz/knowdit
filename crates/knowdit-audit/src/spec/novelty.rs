//! Link novelty judge — the audit-time deduplicator that runs **before** any
//! expensive agent work.
//!
//! ## Why this exists
//!
//! `LinkInput::build_all` fans every mapper match out into one
//! `(extract, historical semantic, historical finding)` triple, and each triple
//! costs a full gen-spec → fuzz → reflect pipeline. On the three
//! `eval_audits/2026-07-metric-wtdcode` baselines that fan-out was 13–31 link
//! runs per *distinct* project-side bug: the same defect gets rediscovered from
//! dozens of unrelated historical findings because a project usually offers one
//! salient surface per defect family.
//!
//! Two facts shape the design:
//!
//! * The redundancy is **project-side**, so no property of the knowledge graph
//!   predicts it. Offline replay of the baselines showed mechanical reorderings
//!   (rotate by finding, prefer low-degree findings) recover *fewer* distinct
//!   bugs per link than today's ordering — they optimize "distinct historical
//!   findings", which is not the quantity that matters.
//! * Comparing a pending link against the **canonical findings the run has
//!   already reported** does predict it. Replaying the baselines with this
//!   judge in place recovers 68–75% of the canonical findings in 300 link runs
//!   where the current ordering reaches 53–63%, and 83–91% by 500 runs against
//!   70–75%.
//!
//! The comparison set is deliberately the deduplicated report (`report_finding`,
//! the canonical set the report-phase merge agent maintains) rather than the
//! built specifications. Granularity is the whole game here: on the baselines a
//! single hot function carries ~3 distinct canonical findings, so judging "does
//! this link target a function some specification already targets" defers real
//! bugs and measures barely better than no judge at all. Judging against
//! canonical findings asks the question that actually matters — would this link
//! rediscover a bug we have already reported.
//!
//! ## Contract
//!
//! A `DuplicateOf` verdict **defers**, it never drops: the scheduler moves the
//! link to a back lane that drains once the main queue is empty, so a
//! sufficiently funded run still executes every candidate link and a
//! mis-judgement only costs ordering. That is what lets this judge be cheap and
//! imperfect — recall is the lever, false positives are nearly free.
//!
//! The judge is a single JSON call per batch (no agent, no tools), and it may
//! only answer with finding ids drawn from the inventory it was shown — the
//! same "never invent an id" anchoring the report-phase merge agent uses.
//!
//! The pass is a no-op until the run has canonical findings to compare against,
//! which means it only engages when `--review-findings` is on (that is what
//! drains review + merge after each link and fills `report_finding`).

use std::collections::{BTreeMap, BTreeSet};

use color_eyre::eyre::{Result, WrapErr};
use knowdit_kg::text::truncate_text;
use knowdit_repo_model::{LinkInput, LinkKey, LoadedReportFinding, ProjectProfile};

use super::prompt;
use llmy::client::client::LLM;
use serde::{Deserialize, Serialize};

/// Tunables for one novelty pass. Mirrors the CLI knobs so the caller owns the
/// numbers (there are no magic constants in this module).
#[derive(Debug, Clone)]
pub struct NoveltyOptions {
    /// Candidate links offered to the judge per LLM call.
    pub batch_size: usize,
    /// Cap on canonical findings rendered as the comparison inventory. The
    /// most recent ones are kept. In practice the canonical set stays small
    /// (the baselines finished at 83–92 findings), so this rarely binds.
    pub max_inventory: usize,
    /// Characters of each finding field rendered into a candidate block.
    pub finding_field_chars: usize,
    /// Characters of each canonical finding field rendered into the inventory.
    pub spec_summary_chars: usize,
    /// `llmy` cache key prefix.
    pub cache_key: Option<String>,
    /// Verbatim per-language block prepended to the system prompt, same
    /// convention as the mapper and the reflection graders.
    pub language_prompt_prefix: String,
}

/// One canonical finding this run has already reported, as the judge sees it.
/// `root_cause` leads because that is the field the report-phase merge agent
/// treats as the normalized dedup key, and it is what transfers across the
/// historical/project boundary; `primary_contract` / `primary_function` are
/// locating hints only — several distinct canonical findings routinely share a
/// hot function.
#[derive(Debug, Clone, Serialize)]
pub struct ReportedFindingDigest {
    pub finding_id: i32,
    pub title: String,
    pub root_cause: String,
    pub primary_contract: String,
    pub primary_function: String,
}

impl ReportedFindingDigest {
    pub fn from_loaded(finding: &LoadedReportFinding, field_chars: usize) -> Self {
        Self {
            finding_id: finding.id,
            title: truncate_text(finding.title.trim(), field_chars),
            root_cause: truncate_text(finding.root_cause.trim(), field_chars),
            primary_contract: finding.primary_contract.clone(),
            primary_function: finding.primary_function.clone(),
        }
    }
}

/// One candidate defect offered to the judge. `candidate_id` is the anchor the
/// model answers with — a batch-local index, so the model never has to echo a
/// database key and the caller can map answers back without trusting the model
/// to reproduce ids.
///
/// The evidence is a historical finding — a defect observed in *another*
/// project — so deciding whether it lands on something already reported here is
/// a prediction, and the judge is told to answer `new` when unsure.
#[derive(Debug, Clone, Serialize)]
pub struct NoveltyCandidate {
    pub candidate_id: usize,
    /// Project- and historical-side framing, for locating the claim.
    pub context: String,
    pub defect_title: String,
    pub defect_root_cause: String,
    pub defect_detail: String,
}

impl NoveltyCandidate {
    /// Frame a not-yet-run link: the evidence is the historical finding the
    /// link would try to reproduce.
    fn from_link(candidate_id: usize, link: &LinkInput, field_chars: usize) -> Self {
        Self {
            candidate_id,
            context: format!(
                "project semantic \"{}\" ↔ historical semantic \"{}\"",
                link.extract.name, link.historical.name
            ),
            defect_title: truncate_text(link.finding.title.trim(), field_chars),
            defect_root_cause: truncate_text(link.finding.root_cause.trim(), field_chars),
            defect_detail: truncate_text(link.finding_rendered_patterns.trim(), field_chars),
        }
    }
}

/// What the judge decided about one candidate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkNovelty {
    /// Nothing in the inventory covers this link — run it now.
    New,
    /// The named canonical finding already covers this defect — defer the link.
    DuplicateOf(i32),
}

/// One batch, serialized verbatim as the judge's user prompt.
#[derive(Debug, Clone, Serialize)]
struct NoveltyBatch {
    reported_findings: Vec<ReportedFindingDigest>,
    candidates: Vec<NoveltyCandidate>,
}

#[derive(Debug, Deserialize)]
struct NoveltyResponse {
    verdicts: Vec<NoveltyVerdict>,
}

#[derive(Debug, Deserialize)]
struct NoveltyVerdict {
    candidate_id: usize,
    verdict: String,
    #[serde(default)]
    duplicate_of_finding_id: Option<i32>,
    #[serde(default)]
    reason: String,
}

/// Batched novelty judge. Owns the framing (profile + rubric) once and is
/// reused for every batch of a run, so the system prompt stays cache-warm.
#[derive(Debug, Clone)]
pub struct LinkNoveltyJudge {
    system_prompt: String,
    options: NoveltyOptions,
}

impl LinkNoveltyJudge {
    pub fn new(profile: &ProjectProfile, options: NoveltyOptions) -> Self {
        Self {
            system_prompt: prompt::novelty_system(profile, &options.language_prompt_prefix),
            options,
        }
    }

    /// Digest the run's canonical findings into the comparison inventory,
    /// newest first and capped at `max_inventory`.
    pub fn build_inventory(&self, reported: &[LoadedReportFinding]) -> Vec<ReportedFindingDigest> {
        let mut digests: Vec<ReportedFindingDigest> = reported
            .iter()
            .rev()
            .map(|f| ReportedFindingDigest::from_loaded(f, self.options.spec_summary_chars))
            .take(self.options.max_inventory)
            .collect();
        digests.reverse();
        digests
    }

    /// Judge one batch of pending links against `inventory`.
    ///
    /// Returns a verdict for every link that came back cleanly; links the model
    /// omitted or answered unusably are simply absent from the map, and the
    /// caller treats absence as [`LinkNovelty::New`] — an omission must never
    /// silently defer work.
    pub async fn judge(
        &self,
        llm: &LLM,
        inventory: &[ReportedFindingDigest],
        links: &[LinkInput],
    ) -> Result<BTreeMap<LinkKey, LinkNovelty>> {
        let candidates: Vec<NoveltyCandidate> = links
            .iter()
            .enumerate()
            .map(|(i, link)| NoveltyCandidate::from_link(i, link, self.options.finding_field_chars))
            .collect();
        if inventory.is_empty() || candidates.is_empty() {
            return Ok(BTreeMap::new());
        }
        let batch = NoveltyBatch {
            reported_findings: inventory.to_vec(),
            candidates: candidates.to_vec(),
        };
        let user_prompt = serde_json::to_string_pretty(&batch)
            .wrap_err("link novelty judge: failed to serialize batch")?;
        let response: NoveltyResponse = llm
            .prompt_json_with_retry(
                &self.system_prompt,
                &user_prompt,
                None,
                self.options.cache_key.as_deref(),
                None,
            )
            .await
            .wrap_err("link novelty judge: LLM call failed")?;

        let valid_finding_ids: BTreeSet<i32> = inventory.iter().map(|f| f.finding_id).collect();
        let valid_candidate_ids: BTreeSet<usize> =
            candidates.iter().map(|c| c.candidate_id).collect();
        let mut out: BTreeMap<LinkKey, LinkNovelty> = BTreeMap::new();
        for verdict in response.verdicts {
            if !valid_candidate_ids.contains(&verdict.candidate_id) {
                tracing::warn!(
                    "link novelty judge: dropping verdict for unknown candidate_id {}",
                    verdict.candidate_id
                );
                continue;
            }
            let novelty = if verdict.verdict.trim().eq_ignore_ascii_case("duplicate") {
                match verdict.duplicate_of_finding_id {
                    Some(id) if valid_finding_ids.contains(&id) => {
                        tracing::debug!(
                            "link novelty judge: candidate {} duplicates finding {} — {}",
                            verdict.candidate_id,
                            id,
                            verdict.reason.trim()
                        );
                        LinkNovelty::DuplicateOf(id)
                    }
                    Some(id) => {
                        tracing::warn!(
                            "link novelty judge: candidate {} claims duplicate of finding {} \
                             which was not in the shown inventory — treating as new",
                            verdict.candidate_id,
                            id
                        );
                        LinkNovelty::New
                    }
                    None => {
                        tracing::warn!(
                            "link novelty judge: candidate {} answered `duplicate` without a \
                             finding id — treating as new",
                            verdict.candidate_id
                        );
                        LinkNovelty::New
                    }
                }
            } else {
                LinkNovelty::New
            };
            if let Some(link) = links.get(verdict.candidate_id) {
                out.insert(link.key(), novelty);
            }
        }
        Ok(out)
    }
}
