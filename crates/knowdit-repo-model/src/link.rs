//! `LinkInput` — one expanded `(extract, historical, finding)` link, the
//! unit of work consumed by every language's spec-generation backend.
//!
//! Lives here (rather than in a language-specific spec crate) because it
//! bundles the project-side match data ([`SemanticMatch`] /
//! [`HistoricalSemanticRecord`], both defined in this crate) with the
//! knowledge-graph rows, and is shared by the Solidity (`knowdit-audit`)
//! and Move (`knowdit-move`) spec pipelines.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use knowdit_kg_model::ExtractedSemantic;
use knowdit_kg_model::db::{audit_finding, semantic_node};
use knowdit_kg_model::link_strength::LinkStrength;

use crate::{HistoricalSemanticRecord, MatchStrength, SemanticMatch};

/// Stable identifier for one expanded `(extract, historical, finding)` link.
/// Public so orchestrators can log / snapshot progress without reaching into
/// a generator's private runtime state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct LinkKey {
    pub extract_id: i32,
    pub historical_id: i32,
    pub finding_id: i32,
}

/// One expanded `(extract, historical, finding)` link ready to run.
#[derive(Debug, Clone)]
pub struct LinkInput {
    pub extract_id: i32,
    pub historical_id: i32,
    pub finding_id: i32,
    /// Mapper-emitted strength on the underlying `(extract, historical)`
    /// pair, copied onto every LinkInput fanned out from that pair. Used by
    /// gen-specs to filter / order candidates by strength.
    pub strength: MatchStrength,
    /// Global linker-emitted strength on the `(historical, finding)` edge —
    /// how directly this historical finding instantiates the historical
    /// semantic. Independent axis from `strength`.
    pub link_strength: LinkStrength,
    pub extract: ExtractedSemantic,
    pub historical: semantic_node::Model,
    pub finding: audit_finding::Model,
    /// `historical.description` / `finding.{description,patterns,exploits}`
    /// rendered with their merged-variant deltas from the mirror (bounded
    /// canonical representative + each folded raw's concrete delta). Prompt
    /// builders should read these instead of the raw fields; each falls back to
    /// the raw field when the mirror carried no rendered value.
    pub historical_rendered_description: String,
    pub finding_rendered_description: String,
    pub finding_rendered_patterns: String,
    pub finding_rendered_exploits: String,
    /// Spec ids already committed for this link in a prior run. Empty for
    /// fresh links. When non-empty, a backend's per-link runner short-circuits
    /// the gen-spec agent and synthesizes an outcome from these ids so the
    /// caller drives fuzz / reflect / regen against them. Populated from
    /// [`crate::RepoDatabase::link_resume_state`].
    pub pre_committed_spec_ids: Vec<i32>,
}

/// Pick the mirror-rendered value, or fall back to the raw canonical field when
/// the mirror carried nothing rendered (e.g. legacy project DBs written before
/// merged-variant rendering).
fn rendered_or(rendered: &str, raw: &str) -> String {
    if rendered.trim().is_empty() {
        raw.to_string()
    } else {
        rendered.to_string()
    }
}

impl LinkInput {
    pub fn key(&self) -> LinkKey {
        LinkKey {
            extract_id: self.extract_id,
            historical_id: self.historical_id,
            finding_id: self.finding_id,
        }
    }

    /// Fan out mapper matches into one [`LinkInput`] per linked finding,
    /// deduplicated on the `(extract, historical, finding)` triple. Matches
    /// with no project-side extract row, no historical row, or no linked
    /// findings are skipped.
    pub fn build_all(
        matches: &[SemanticMatch],
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
                    historical_rendered_description: rendered_or(
                        &record.rendered_description,
                        &record.semantic.description,
                    ),
                    finding_rendered_description: rendered_or(
                        &linked.rendered_description,
                        &finding.description,
                    ),
                    finding_rendered_patterns: rendered_or(
                        &linked.rendered_patterns,
                        &finding.patterns,
                    ),
                    finding_rendered_exploits: rendered_or(
                        &linked.rendered_exploits,
                        &finding.exploits,
                    ),
                    historical: record.semantic.clone(),
                    finding: finding.clone(),
                    pre_committed_spec_ids: Vec::new(),
                });
            }
        }
        out
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
