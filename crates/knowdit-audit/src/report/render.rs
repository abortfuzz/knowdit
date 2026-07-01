//! Non-LLM Markdown renderer for the finished report.
//!
//! Takes one [`RenderFinding`] per canonical cluster — already resolved to its
//! representative member (the cluster's chosen finding) plus the duplicate
//! members — and produces the client `audit_report.md`:
//!
//! * **Executive summary** + **table of contents**.
//! * **Body**: one section per reportable canonical, rendered from the
//!   representative member (title / severity / location / description / impact
//!   / recommendation / proof-of-concept).
//! * **Appendix: Duplicate instances** — the non-representative members of each
//!   canonical, grouped under that canonical's id, as `title` + `description`
//!   only (no PoC).
//! * **Appendix: Out of scope** — the `ReviewedOutOfScope` canonicals, flat,
//!   as `title` + `description` only.
//!
//! All client text comes from the Review agent (no Writer stage); the PoC is
//! the representative member's existing `harness_source`.

use std::fmt::Write as _;

use knowdit_repo_model::ReviewSeverity;

/// One duplicate (non-representative) cluster member, rendered in the appendix.
#[derive(Debug, Clone)]
pub struct DuplicateBrief {
    pub title: String,
    pub description: String,
}

/// One canonical cluster, resolved to its representative member + duplicates,
/// ready to render. The caller picks the representative
/// (`RawFindingMember::representative_key`) and supplies its review fields and
/// `harness_source` PoC.
#[derive(Debug, Clone)]
pub struct RenderFinding {
    pub canonical_id: i32,
    pub severity: ReviewSeverity,
    /// Representative member's client title.
    pub title: String,
    /// Representative member's client description.
    pub description: String,
    /// Representative member's affected location (`file:line`).
    pub location: String,
    /// Representative member's client impact statement.
    pub impact: String,
    /// Representative member's remediation guidance.
    pub recommendation: String,
    /// Representative member's existing proof-of-concept (`harness_source`).
    /// May contain internal naming — accepted as-is.
    pub poc: String,
    /// Non-representative members of the cluster (title + description only).
    pub duplicates: Vec<DuplicateBrief>,
}

/// Severity buckets in report-body order. `ReviewedOutOfScope` is rendered in
/// a separate appendix, so it is not in this order.
const BODY_ORDER: [ReviewSeverity; 4] = [
    ReviewSeverity::High,
    ReviewSeverity::Medium,
    ReviewSeverity::Low,
    ReviewSeverity::Informational,
];

/// Short tag for the `H-01` / `M-02` style ids.
fn severity_tag(s: ReviewSeverity) -> &'static str {
    match s {
        ReviewSeverity::High => "H",
        ReviewSeverity::Medium => "M",
        ReviewSeverity::Low => "L",
        ReviewSeverity::Informational => "I",
        ReviewSeverity::ReviewedOutOfScope => "OOS",
    }
}

/// GitHub-style heading anchor for a finding id + title.
fn anchor(id: &str, title: &str) -> String {
    format!("{id}-{title}")
        .to_lowercase()
        .chars()
        .filter_map(|c| {
            if c.is_ascii_alphanumeric() {
                Some(c)
            } else if c == ' ' || c == '-' {
                Some('-')
            } else {
                None
            }
        })
        .collect()
}

/// One finding with its assigned report id (e.g. `H-01`), in render order.
struct Numbered<'a> {
    id: String,
    finding: &'a RenderFinding,
}

/// Group + number the reportable findings (body, by severity) and the
/// out-of-scope findings (appendix), in report order.
fn number_findings(findings: &[RenderFinding]) -> (Vec<Numbered<'_>>, Vec<Numbered<'_>>) {
    let mut body: Vec<Numbered<'_>> = Vec::new();
    for sev in BODY_ORDER {
        let mut n = 0usize;
        for f in findings.iter().filter(|f| f.severity == sev) {
            n += 1;
            body.push(Numbered {
                id: format!("{}-{:02}", severity_tag(sev), n),
                finding: f,
            });
        }
    }
    let mut oos: Vec<Numbered<'_>> = Vec::new();
    let mut n = 0usize;
    for f in findings
        .iter()
        .filter(|f| f.severity == ReviewSeverity::ReviewedOutOfScope)
    {
        n += 1;
        oos.push(Numbered {
            id: format!("OOS-{n:02}"),
            finding: f,
        });
    }
    (body, oos)
}

/// Render the full client report from the per-canonical [`RenderFinding`]s.
pub fn render_markdown_report(project_name: &str, findings: &[RenderFinding]) -> String {
    let (body, oos) = number_findings(findings);

    let mut out = String::new();
    let _ = writeln!(out, "# {project_name} — Audit Report\n");

    // Executive summary table.
    let _ = writeln!(out, "## Executive Summary\n");
    let _ = writeln!(out, "| Severity | Count |");
    let _ = writeln!(out, "|---|---|");
    for sev in BODY_ORDER {
        let count = findings.iter().filter(|f| f.severity == sev).count();
        let _ = writeln!(out, "| {} | {} |", sev.as_str(), count);
    }
    let _ = writeln!(out, "| Out of scope | {} |", oos.len());
    let _ = writeln!(out, "| **Total** | **{}** |\n", findings.len());

    // Table of contents.
    let _ = writeln!(out, "## Table of Contents\n");
    for sev in BODY_ORDER {
        let in_sev: Vec<&Numbered<'_>> =
            body.iter().filter(|n| n.finding.severity == sev).collect();
        if in_sev.is_empty() {
            continue;
        }
        let _ = writeln!(out, "- **{}**", sev.as_str());
        for n in in_sev {
            let _ = writeln!(
                out,
                "  - [{}: {}](#{})",
                n.id,
                n.finding.title,
                anchor(&n.id, &n.finding.title)
            );
        }
    }
    let _ = writeln!(out);

    // Body sections.
    for sev in BODY_ORDER {
        let in_sev: Vec<&Numbered<'_>> =
            body.iter().filter(|n| n.finding.severity == sev).collect();
        if in_sev.is_empty() {
            continue;
        }
        let _ = writeln!(out, "---\n\n## {} severity findings\n", sev.as_str());
        for n in &in_sev {
            render_body_finding(&mut out, n);
        }
    }

    // Appendix: duplicate instances, grouped by the canonical they were folded
    // into (its body id), title + description only.
    let dup_groups: Vec<&Numbered<'_>> = body
        .iter()
        .filter(|n| !n.finding.duplicates.is_empty())
        .collect();
    if !dup_groups.is_empty() {
        let _ = writeln!(
            out,
            "---\n\n## Appendix: Duplicate instances\n\n\
             Each entry below was found to be the same underlying issue as the referenced \
             finding and folded into it; listed here for completeness.\n"
        );
        for n in dup_groups {
            let _ = writeln!(out, "### Duplicates of {}: {}\n", n.id, n.finding.title);
            for dup in &n.finding.duplicates {
                let _ = writeln!(out, "- **{}**\n\n  {}\n", dup.title, dup.description);
            }
        }
    }

    // Appendix: out of scope, flat, title + description only.
    if !oos.is_empty() {
        let _ = writeln!(
            out,
            "---\n\n## Appendix: Out of scope / acknowledged\n\n\
             The following were investigated and confirmed as real behaviors but fall outside the \
             audit scope or the project's stated trust assumptions.\n"
        );
        for n in &oos {
            let _ = writeln!(out, "### {}: {}\n", n.id, n.finding.title);
            let _ = writeln!(out, "{}\n", n.finding.description);
        }
    }

    out
}

fn render_body_finding(out: &mut String, n: &Numbered<'_>) {
    let f = n.finding;
    let _ = writeln!(out, "### {}: {}\n", n.id, f.title);
    let _ = writeln!(out, "**Severity:** {}\n", f.severity.as_str());
    if !f.location.trim().is_empty() {
        let _ = writeln!(out, "**Location:** {}\n", f.location);
    }
    let _ = writeln!(out, "#### Description\n\n{}\n", f.description);
    if !f.impact.trim().is_empty() {
        let _ = writeln!(out, "#### Impact\n\n{}\n", f.impact);
    }
    if !f.poc.trim().is_empty() {
        let _ = writeln!(
            out,
            "#### Proof of Concept\n\n```solidity\n{}\n```\n",
            f.poc
        );
    }
    if !f.recommendation.trim().is_empty() {
        let _ = writeln!(out, "#### Recommendation\n\n{}\n", f.recommendation);
    }
}
