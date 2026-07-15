//! KG database statistics — the SHARED MEASUREMENT CALIBER for debugging
//! builds, printed by `learn validate-db` and returnable programmatically via
//! [`HistoricalDatabase::kg_stats`].
//!
//! Calibers (fixed so every debugging session measures the same thing):
//! - Counts/densities use the investigation caliber: **cross-project links
//!   only** (evidence not stamped with the in-project prefix), **canonical**
//!   row denominators (rows not folded away by merge).
//! - "Rendered" lengths go through the linker's own render path
//!   ([`SemanticLinkCandidate::render`] /
//!   [`knowdit_kg_model::render::render_with_variants_capped`]) at the
//!   CALLER-SUPPLIED variant caps — the CLI shares one clap struct between
//!   `link` and `validate-db`, so passing the same caps shows exactly the
//!   per-candidate / per-finding mass a link run puts in its prompts.

use std::collections::{HashMap, HashSet};

use knowdit_kg_model::db::{
    audit_finding, audit_finding_category, finding_category, finding_link_status, finding_merge,
    merge_status, pending_semantic, project, project_category, project_finding, project_platform,
    project_semantic, semantic_finding_link, semantic_function, semantic_merge, semantic_node,
};
use knowdit_kg_model::link_strength::LinkStrength;
use knowdit_kg_model::render::render_with_variants_capped;
use sea_orm::EntityTrait;

use crate::db::{HistoricalDatabase, IN_PROJECT_LINK_EVIDENCE_PREFIX};
use crate::error::Result;
use crate::link::{SemanticLinkCandidate, label_variant};

/// Average char lengths of one text field: the raw column value vs the
/// render at the caps recorded in [`KgStats::variant_render_cap`] /
/// [`KgStats::raw_child_char_cap`].
#[derive(Debug, Clone, Copy, Default)]
pub struct FieldLens {
    pub raw: usize,
    pub rendered: usize,
}

#[derive(Debug, Clone, Default)]
pub struct KgStats {
    /// Variant count cap the rendered lengths were computed at.
    pub variant_render_cap: usize,
    /// Per-variant char cap (0 = unbounded) the rendered lengths used.
    pub raw_child_char_cap: usize,

    // ── row counts ──
    pub projects_total: usize,
    /// Project count per platform (prefix of `platform_id`, e.g. "c4"),
    /// sorted by count descending.
    pub platforms: Vec<(String, usize)>,
    pub semantics_total: usize,
    pub semantics_canonical: usize,
    pub semantics_folded: usize,
    pub findings_total: usize,
    pub findings_canonical: usize,
    pub findings_folded: usize,

    // ── merge-edge shape (merge_target_ids is multi-valued by design:
    //    one raw can fold into several canonicals) ──
    pub semantic_merge_edges: usize,
    pub semantic_max_parents: usize,
    pub finding_merge_edges: usize,
    pub finding_max_parents: usize,

    // ── pipeline state ──
    /// Findings the global cross-project linker has processed
    /// (`finding_link_status` rows) — equals `findings_total` on a
    /// completed build.
    pub link_processed_findings: usize,
    /// Extract-time semantics still awaiting merge — 0 on a completed build.
    pub pending_semantics: usize,
    /// merge-kg workflow bookkeeping rows — 0 unless a cross-KG merge ran.
    pub merge_status_rows: usize,

    // ── extraction richness / provenance reach ──
    pub semantic_functions_total: usize,
    pub functions_per_raw_semantic: f64,
    /// Distinct source projects per canonical semantic (itself + folded
    /// children) — the cross-project reach the KG's reuse value rests on.
    pub projects_per_canonical_semantic: f64,
    pub max_projects_per_canonical_semantic: usize,
    pub projects_per_canonical_finding: f64,
    pub categories_per_project: f64,
    /// Canonical-semantic DeFi-category distribution, top entries by count.
    pub top_semantic_categories: Vec<(String, usize)>,
    /// Finding vulnerability-category distribution, top entries by count.
    pub top_finding_categories: Vec<(String, usize)>,

    // ── links ──
    pub links_total: usize,
    pub links_in_project: usize,
    pub links_cross: usize,
    pub total_high: usize,
    pub total_medium: usize,
    pub total_low: usize,
    pub in_project_high: usize,
    pub in_project_medium: usize,
    pub in_project_low: usize,
    pub cross_high: usize,
    pub cross_medium: usize,
    pub cross_low: usize,

    // ── density (cross-project links over canonical rows) ──
    pub cross_links_per_canonical_finding: f64,
    pub cross_high_per_canonical_finding: f64,
    pub cross_links_per_canonical_semantic: f64,
    /// Distinct canonical findings carrying ≥1 cross-project link.
    pub linked_canonical_findings: usize,
    /// Distinct canonical semantics carrying ≥1 cross-project link.
    pub linked_canonical_semantics: usize,

    // ── per-project averages (raw rows / cross links over ALL projects) ──
    pub semantics_per_project: f64,
    pub findings_per_project: f64,
    pub cross_links_per_project: f64,

    // ── avg field chars over canonical rows: raw column / link-prompt render ──
    pub semantic_name_chars: usize,
    pub semantic_definition_chars: usize,
    pub semantic_description: FieldLens,
    /// Full rendered candidate block ("Candidate ID: … Description: …"), the
    /// per-candidate prompt mass the linker sees.
    pub semantic_candidate_body_chars: usize,
    pub finding_title_chars: usize,
    pub finding_root_cause: FieldLens,
    pub finding_description: FieldLens,
    pub finding_patterns: FieldLens,
    pub finding_exploits: FieldLens,
}

fn avg(total: usize, n: usize) -> usize {
    if n == 0 { 0 } else { total / n }
}

fn pct(part: usize, whole: usize) -> f64 {
    if whole == 0 {
        0.0
    } else {
        part as f64 * 100.0 / whole as f64
    }
}

impl std::fmt::Display for KgStats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "── KG stats ─────────────────────────────────────────")?;
        let platforms = self
            .platforms
            .iter()
            .map(|(name, n)| format!("{name} {n}"))
            .collect::<Vec<_>>()
            .join(" | ");
        writeln!(f, "projects: {} ({})", self.projects_total, platforms)?;
        writeln!(
            f,
            "  per project: raw semantics {:.1} | raw findings {:.1} | cross-links {:.1} | categories {:.1}",
            self.semantics_per_project,
            self.findings_per_project,
            self.cross_links_per_project,
            self.categories_per_project,
        )?;
        writeln!(
            f,
            "semantics: {} raw = {} canonical + {} folded",
            self.semantics_total, self.semantics_canonical, self.semantics_folded
        )?;
        writeln!(
            f,
            "findings:  {} raw = {} canonical + {} folded",
            self.findings_total, self.findings_canonical, self.findings_folded
        )?;
        writeln!(
            f,
            "merge edges (multi-parent by design): semantics {} edges / {} children (max {} parents) | findings {} / {} (max {})",
            self.semantic_merge_edges,
            self.semantics_folded,
            self.semantic_max_parents,
            self.finding_merge_edges,
            self.findings_folded,
            self.finding_max_parents,
        )?;
        writeln!(
            f,
            "pipeline: link-processed findings {}/{} | pending semantics {} | merge-kg status rows {}",
            self.link_processed_findings,
            self.findings_total,
            self.pending_semantics,
            self.merge_status_rows,
        )?;
        writeln!(
            f,
            "links: {} total = {} in-project + {} cross-project",
            self.links_total, self.links_in_project, self.links_cross
        )?;
        writeln!(
            f,
            "  total by strength:         High {} ({:.0}%) | Medium {} ({:.0}%) | Low {} ({:.0}%)",
            self.total_high,
            pct(self.total_high, self.links_total),
            self.total_medium,
            pct(self.total_medium, self.links_total),
            self.total_low,
            pct(self.total_low, self.links_total),
        )?;
        writeln!(
            f,
            "  in-project by strength:    High {} ({:.0}%) | Medium {} ({:.0}%) | Low {} ({:.0}%)",
            self.in_project_high,
            pct(self.in_project_high, self.links_in_project),
            self.in_project_medium,
            pct(self.in_project_medium, self.links_in_project),
            self.in_project_low,
            pct(self.in_project_low, self.links_in_project),
        )?;
        writeln!(
            f,
            "  cross-project by strength: High {} ({:.0}%) | Medium {} ({:.0}%) | Low {} ({:.0}%)",
            self.cross_high,
            pct(self.cross_high, self.links_cross),
            self.cross_medium,
            pct(self.cross_medium, self.links_cross),
            self.cross_low,
            pct(self.cross_low, self.links_cross),
        )?;
        writeln!(f, "density (cross-project / canonical):")?;
        writeln!(
            f,
            "  links/finding {:.2} | High/finding {:.2} | links/semantic {:.2}",
            self.cross_links_per_canonical_finding,
            self.cross_high_per_canonical_finding,
            self.cross_links_per_canonical_semantic,
        )?;
        writeln!(
            f,
            "  canonicals with >=1 cross-link: findings {}/{} ({:.0}%) | semantics {}/{} ({:.0}%)",
            self.linked_canonical_findings,
            self.findings_canonical,
            pct(self.linked_canonical_findings, self.findings_canonical),
            self.linked_canonical_semantics,
            self.semantics_canonical,
            pct(self.linked_canonical_semantics, self.semantics_canonical),
        )?;
        writeln!(
            f,
            "distinct source projects per canonical (its own + folded children's, deduped): semantic {:.2} (max {}) | finding {:.2}",
            self.projects_per_canonical_semantic,
            self.max_projects_per_canonical_semantic,
            self.projects_per_canonical_finding,
        )?;
        writeln!(
            f,
            "functions: {} ({:.1}/raw semantic)",
            self.semantic_functions_total, self.functions_per_raw_semantic,
        )?;
        let sem_cats = self
            .top_semantic_categories
            .iter()
            .map(|(name, n)| format!("{name} {n}"))
            .collect::<Vec<_>>()
            .join(" | ");
        writeln!(f, "top semantic categories (canonical): {sem_cats}")?;
        let cats = self
            .top_finding_categories
            .iter()
            .map(|(name, n)| format!("{name} {n}"))
            .collect::<Vec<_>>()
            .join(" | ");
        writeln!(f, "top finding categories: {cats}")?;
        writeln!(
            f,
            "avg field chars over canonical rows (raw column → rendered @ {} variants x {} chars, 0=unbounded):",
            self.variant_render_cap, self.raw_child_char_cap
        )?;
        writeln!(
            f,
            "  semantic: name {} | definition {} | description {} → {} | candidate body → {}",
            self.semantic_name_chars,
            self.semantic_definition_chars,
            self.semantic_description.raw,
            self.semantic_description.rendered,
            self.semantic_candidate_body_chars,
        )?;
        writeln!(
            f,
            "  finding:  title {} | root_cause {} → {} | description {} → {} | patterns {} → {} | exploits {} → {}",
            self.finding_title_chars,
            self.finding_root_cause.raw,
            self.finding_root_cause.rendered,
            self.finding_description.raw,
            self.finding_description.rendered,
            self.finding_patterns.raw,
            self.finding_patterns.rendered,
            self.finding_exploits.raw,
            self.finding_exploits.rendered,
        )?;
        Ok(())
    }
}

impl HistoricalDatabase {
    /// Compute [`KgStats`] for this KG. Loads the five relevant tables fully
    /// into memory (KGs are small — thousands of rows) and reuses the linker's
    /// render path for the "rendered" lengths.
    pub async fn kg_stats(
        &self,
        variant_render_cap: usize,
        raw_child_char_cap: usize,
    ) -> Result<KgStats> {
        let semantics = semantic_node::Entity::find().all(self.conn()).await?;
        let sem_merges = semantic_merge::Entity::find().all(self.conn()).await?;
        let findings = audit_finding::Entity::find().all(self.conn()).await?;
        let find_merges = finding_merge::Entity::find().all(self.conn()).await?;
        let links = semantic_finding_link::Entity::find()
            .all(self.conn())
            .await?;
        let projects = project::Entity::find().all(self.conn()).await?;
        let platforms = project_platform::Entity::find().all(self.conn()).await?;
        let link_status = finding_link_status::Entity::find().all(self.conn()).await?;
        let pending = pending_semantic::Entity::find().all(self.conn()).await?;
        let merge_statuses = merge_status::Entity::find().all(self.conn()).await?;
        let functions = semantic_function::Entity::find().all(self.conn()).await?;
        let proj_sems = project_semantic::Entity::find().all(self.conn()).await?;
        let proj_finds = project_finding::Entity::find().all(self.conn()).await?;
        let proj_cats = project_category::Entity::find().all(self.conn()).await?;
        let find_cats = audit_finding_category::Entity::find()
            .all(self.conn())
            .await?;
        let cat_names = finding_category::Entity::find().all(self.conn()).await?;

        let mut stats = KgStats {
            variant_render_cap,
            raw_child_char_cap,
            ..KgStats::default()
        };

        // ── projects / platforms ──
        stats.projects_total = projects.len();
        let mut by_platform: HashMap<String, usize> = HashMap::new();
        for p in &platforms {
            let prefix = p
                .platform_id
                .split_once('-')
                .map_or(p.platform_id.as_str(), |(prefix, _)| prefix);
            *by_platform.entry(prefix.to_string()).or_default() += 1;
        }
        stats.platforms = by_platform.into_iter().collect();
        stats
            .platforms
            .sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));

        // ── counts ──
        let folded_semantics: HashSet<i32> =
            sem_merges.iter().map(|m| m.from_semantic_id).collect();
        let folded_findings: HashSet<i32> = find_merges.iter().map(|m| m.from_finding_id).collect();
        stats.semantics_total = semantics.len();
        stats.semantics_folded = folded_semantics.len();
        stats.semantics_canonical = semantics.len() - folded_semantics.len();
        stats.findings_total = findings.len();
        stats.findings_folded = folded_findings.len();
        stats.findings_canonical = findings.len() - folded_findings.len();

        // ── links ──
        let mut linked_findings: HashSet<i32> = HashSet::new();
        let mut linked_semantics: HashSet<i32> = HashSet::new();
        stats.links_total = links.len();
        for link in &links {
            match link.strength {
                LinkStrength::High => stats.total_high += 1,
                LinkStrength::Medium => stats.total_medium += 1,
                LinkStrength::Low => stats.total_low += 1,
            }
            if link.evidence.starts_with(IN_PROJECT_LINK_EVIDENCE_PREFIX) {
                stats.links_in_project += 1;
                match link.strength {
                    LinkStrength::High => stats.in_project_high += 1,
                    LinkStrength::Medium => stats.in_project_medium += 1,
                    LinkStrength::Low => stats.in_project_low += 1,
                }
                continue;
            }
            stats.links_cross += 1;
            match link.strength {
                LinkStrength::High => stats.cross_high += 1,
                LinkStrength::Medium => stats.cross_medium += 1,
                LinkStrength::Low => stats.cross_low += 1,
            }
            linked_findings.insert(link.audit_finding_id);
            linked_semantics.insert(link.semantic_node_id);
        }
        stats.linked_canonical_findings = linked_findings.len();
        stats.linked_canonical_semantics = linked_semantics.len();
        if stats.findings_canonical > 0 {
            stats.cross_links_per_canonical_finding =
                stats.links_cross as f64 / stats.findings_canonical as f64;
            stats.cross_high_per_canonical_finding =
                stats.cross_high as f64 / stats.findings_canonical as f64;
        }
        if stats.semantics_canonical > 0 {
            stats.cross_links_per_canonical_semantic =
                stats.links_cross as f64 / stats.semantics_canonical as f64;
        }
        if stats.projects_total > 0 {
            let n = stats.projects_total as f64;
            stats.semantics_per_project = stats.semantics_total as f64 / n;
            stats.findings_per_project = stats.findings_total as f64 / n;
            stats.cross_links_per_project = stats.links_cross as f64 / n;
            stats.categories_per_project = proj_cats.len() as f64 / n;
        }

        // ── merge-edge shape ──
        stats.semantic_merge_edges = sem_merges.len();
        stats.finding_merge_edges = find_merges.len();
        let mut parents: HashMap<i32, usize> = HashMap::new();
        for m in &sem_merges {
            *parents.entry(m.from_semantic_id).or_default() += 1;
        }
        stats.semantic_max_parents = parents.values().copied().max().unwrap_or(0);
        parents.clear();
        for m in &find_merges {
            *parents.entry(m.from_finding_id).or_default() += 1;
        }
        stats.finding_max_parents = parents.values().copied().max().unwrap_or(0);

        // ── pipeline state ──
        stats.link_processed_findings = link_status.len();
        stats.pending_semantics = pending.len();
        stats.merge_status_rows = merge_statuses.len();

        // ── extraction richness / provenance reach ──
        stats.semantic_functions_total = functions.len();
        if stats.semantics_total > 0 {
            stats.functions_per_raw_semantic =
                functions.len() as f64 / stats.semantics_total as f64;
        }
        // canonical reach = distinct projects of the canonical itself + its children
        let mut sem_projects: HashMap<i32, HashSet<i32>> = HashMap::new();
        for ps in &proj_sems {
            sem_projects
                .entry(ps.semantic_node_id)
                .or_default()
                .insert(ps.project_id);
        }
        let mut canonical_of_sem: HashMap<i32, i32> = HashMap::new();
        for m in &sem_merges {
            canonical_of_sem.insert(m.from_semantic_id, m.to_semantic_id);
        }
        let mut reach: HashMap<i32, HashSet<i32>> = HashMap::new();
        for (sem_id, projs) in &sem_projects {
            // children may have several parents; credit each parent
            let owners: Vec<i32> = if folded_semantics.contains(sem_id) {
                sem_merges
                    .iter()
                    .filter(|m| m.from_semantic_id == *sem_id)
                    .map(|m| m.to_semantic_id)
                    .collect()
            } else {
                vec![*sem_id]
            };
            for owner in owners {
                reach
                    .entry(owner)
                    .or_default()
                    .extend(projs.iter().copied());
            }
        }
        if stats.semantics_canonical > 0 {
            stats.projects_per_canonical_semantic = reach
                .iter()
                .filter(|(id, _)| !folded_semantics.contains(id))
                .map(|(_, p)| p.len())
                .sum::<usize>() as f64
                / stats.semantics_canonical as f64;
            stats.max_projects_per_canonical_semantic = reach
                .iter()
                .filter(|(id, _)| !folded_semantics.contains(id))
                .map(|(_, p)| p.len())
                .max()
                .unwrap_or(0);
        }
        let mut find_projects: HashMap<i32, HashSet<i32>> = HashMap::new();
        for pf in &proj_finds {
            find_projects
                .entry(pf.audit_finding_id)
                .or_default()
                .insert(pf.project_id);
        }
        let mut freach: HashMap<i32, HashSet<i32>> = HashMap::new();
        for (fid, projs) in &find_projects {
            let owners: Vec<i32> = if folded_findings.contains(fid) {
                find_merges
                    .iter()
                    .filter(|m| m.from_finding_id == *fid)
                    .map(|m| m.to_finding_id)
                    .collect()
            } else {
                vec![*fid]
            };
            for owner in owners {
                freach
                    .entry(owner)
                    .or_default()
                    .extend(projs.iter().copied());
            }
        }
        if stats.findings_canonical > 0 {
            stats.projects_per_canonical_finding = freach
                .iter()
                .filter(|(id, _)| !folded_findings.contains(id))
                .map(|(_, p)| p.len())
                .sum::<usize>() as f64
                / stats.findings_canonical as f64;
        }
        // top semantic DeFi categories (over canonical rows)
        let mut sem_cat_counts: HashMap<String, usize> = HashMap::new();
        for sem in semantics
            .iter()
            .filter(|s| !folded_semantics.contains(&s.id))
        {
            *sem_cat_counts.entry(sem.category.to_string()).or_default() += 1;
        }
        let mut top: Vec<(String, usize)> = sem_cat_counts.into_iter().collect();
        top.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
        top.truncate(5);
        stats.top_semantic_categories = top;

        // top finding vulnerability categories
        let name_of: HashMap<i32, &str> =
            cat_names.iter().map(|c| (c.id, c.name.as_str())).collect();
        let mut cat_counts: HashMap<&str, usize> = HashMap::new();
        for fc in &find_cats {
            if let Some(name) = name_of.get(&fc.finding_category_id) {
                *cat_counts.entry(name).or_default() += 1;
            }
        }
        let mut top: Vec<(String, usize)> = cat_counts
            .into_iter()
            .map(|(k, v)| (k.to_string(), v))
            .collect();
        top.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
        top.truncate(5);
        stats.top_finding_categories = top;

        // ── field lengths (canonical rows) ──
        let chars = |s: &str| s.chars().count();

        let sem_children: HashMap<i32, Vec<&semantic_node::Model>> = {
            let by_id: HashMap<i32, &semantic_node::Model> =
                semantics.iter().map(|s| (s.id, s)).collect();
            let mut map: HashMap<i32, Vec<&semantic_node::Model>> = HashMap::new();
            for m in &sem_merges {
                if let Some(child) = by_id.get(&m.from_semantic_id) {
                    map.entry(m.to_semantic_id).or_default().push(child);
                }
            }
            map
        };
        let (mut name_c, mut def_c, mut desc_raw, mut desc_ren, mut body_c) = (0, 0, 0, 0, 0);
        for sem in semantics
            .iter()
            .filter(|s| !folded_semantics.contains(&s.id))
        {
            name_c += chars(&sem.name);
            def_c += chars(&sem.definition);
            desc_raw += chars(&sem.description);
            let variant_notes: Vec<String> = sem_children
                .get(&sem.id)
                .map(|children| {
                    children
                        .iter()
                        .map(|c| label_variant(&c.name, c.description.clone()))
                        .collect()
                })
                .unwrap_or_default();
            desc_ren += chars(&render_with_variants_capped(
                &sem.description,
                &variant_notes,
                variant_render_cap,
                raw_child_char_cap,
            ));
            let candidate = SemanticLinkCandidate {
                candidate_id: format!("sem-{}", sem.id),
                canonical_semantic_id: sem.id,
                is_canonical: true,
                category: sem.category,
                name: sem.name.clone(),
                definition: sem.definition.clone(),
                description: sem.description.clone(),
                variant_notes,
            };
            body_c += chars(&candidate.render(variant_render_cap, raw_child_char_cap));
        }
        let n = stats.semantics_canonical;
        stats.semantic_name_chars = avg(name_c, n);
        stats.semantic_definition_chars = avg(def_c, n);
        stats.semantic_description = FieldLens {
            raw: avg(desc_raw, n),
            rendered: avg(desc_ren, n),
        };
        stats.semantic_candidate_body_chars = avg(body_c, n);

        let find_children: HashMap<i32, Vec<&audit_finding::Model>> = {
            let by_id: HashMap<i32, &audit_finding::Model> =
                findings.iter().map(|f| (f.id, f)).collect();
            let mut map: HashMap<i32, Vec<&audit_finding::Model>> = HashMap::new();
            for m in &find_merges {
                if let Some(child) = by_id.get(&m.from_finding_id) {
                    map.entry(m.to_finding_id).or_default().push(child);
                }
            }
            map
        };
        let mut title_c = 0;
        let mut fields = [FieldLens::default(); 4]; // root_cause, description, patterns, exploits
        for finding in findings.iter().filter(|f| !folded_findings.contains(&f.id)) {
            title_c += chars(&finding.title);
            let children = find_children
                .get(&finding.id)
                .map(Vec::as_slice)
                .unwrap_or_default();
            let per_field: [(&str, Box<dyn Fn(&audit_finding::Model) -> &str>); 4] = [
                (&finding.root_cause, Box::new(|c| &c.root_cause)),
                (&finding.description, Box::new(|c| &c.description)),
                (&finding.patterns, Box::new(|c| &c.patterns)),
                (&finding.exploits, Box::new(|c| &c.exploits)),
            ];
            for (i, (canonical_text, child_field)) in per_field.iter().enumerate() {
                fields[i].raw += chars(canonical_text);
                let notes: Vec<String> = children
                    .iter()
                    .map(|c| label_variant(&c.title, child_field(c).to_string()))
                    .collect();
                fields[i].rendered += chars(&render_with_variants_capped(
                    canonical_text,
                    &notes,
                    variant_render_cap,
                    raw_child_char_cap,
                ));
            }
        }
        let n = stats.findings_canonical;
        stats.finding_title_chars = avg(title_c, n);
        let f = |acc: FieldLens| FieldLens {
            raw: avg(acc.raw, n),
            rendered: avg(acc.rendered, n),
        };
        stats.finding_root_cause = f(fields[0]);
        stats.finding_description = f(fields[1]);
        stats.finding_patterns = f(fields[2]);
        stats.finding_exploits = f(fields[3]);

        Ok(stats)
    }
}
