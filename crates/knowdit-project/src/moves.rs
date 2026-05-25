//! Move-specific project types: platform identifiers, snapshot
//! discovery, and the audit-report shape that comes with Move projects.
//!
//! Lifted from `knowdit_kg::project_loader` so all project-related
//! data lives in one crate. The LLM-driven analysis methods that
//! previously hung off these types stay in `knowdit-kg` — this
//! module is data + filesystem discovery only.

use std::{
    collections::HashMap,
    path::{Path, PathBuf},
};

use color_eyre::eyre::{Result, WrapErr};
use serde::Deserialize;

/// Which Move ecosystem a project belongs to. Drives the directory
/// layout used to enumerate snapshots and pair them with audit
/// findings under `moves/`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MovePlatform {
    Aptos,
    Sui,
}

impl MovePlatform {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Aptos => "aptos",
            Self::Sui => "sui",
        }
    }

    /// Subdirectory of `moves/` that contains source snapshots for
    /// this platform.
    pub fn codebase_dir(self) -> &'static str {
        match self {
            Self::Aptos => "_codebase_apt",
            Self::Sui => "_codebase_sui",
        }
    }

    /// Subdirectory of `moves/` that contains vulnerability JSONs for
    /// this platform.
    pub fn vulnerability_dir(self) -> &'static str {
        match self {
            Self::Aptos => "_vun_apt",
            Self::Sui => "_vun_sui/vulnerability_snippets",
        }
    }
}

/// One discoverable Move project snapshot, before any source loading.
/// `snapshot_sort_key` is used to pick the most recent snapshot when
/// multiple share a commit hash; it's not exposed publicly because
/// callers only ever sort by it indirectly through
/// [`list_move_projects`].
#[derive(Debug, Clone)]
pub struct MoveProjectDescriptor {
    pub platform: MovePlatform,
    pub commit_hash: String,
    pub name: String,
    pub root_dir: PathBuf,
    snapshot_sort_key: String,
}

impl MoveProjectDescriptor {
    pub fn snapshot_sort_key(&self) -> &str {
        &self.snapshot_sort_key
    }
}

/// Parsed contents of a `moves/_vun_*/<id>.json` file: one finding.
/// Aligned with the upstream JSON schema; unknown fields are
/// permitted via serde's default behaviour for missing keys (see
/// each `#[serde(default)]`).
#[derive(Debug, Clone, Deserialize)]
pub struct MoveVulnerabilityFinding {
    pub id: u32,
    pub commit: String,
    #[serde(default)]
    pub project_id: Option<u32>,
    #[serde(default)]
    pub number: Option<String>,
    #[serde(default)]
    pub title: String,
    #[serde(rename = "type", default)]
    pub finding_type: Option<String>,
    #[serde(default)]
    pub severity: Option<String>,
    #[serde(default)]
    pub confidence: Option<String>,
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub suggestion: Option<String>,
    #[serde(default)]
    pub resolution: Option<String>,
    #[serde(default)]
    pub notes: Option<String>,
    #[serde(default)]
    pub files: Vec<MoveVulnerabilitySnippetFile>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct MoveVulnerabilitySnippetFile {
    pub filename: String,
    #[serde(default)]
    pub commit: String,
    #[serde(default)]
    pub snippets: Vec<String>,
}

/// One Move project's worth of vulnerability findings, keyed by
/// commit hash so it can be paired with a snapshot.
#[derive(Debug, Clone)]
pub struct MoveVulnerabilitySnippet {
    pub commit: String,
    pub findings: Vec<MoveVulnerabilityFinding>,
}

impl MoveVulnerabilitySnippet {
    pub fn new(commit: impl Into<String>, mut findings: Vec<MoveVulnerabilityFinding>) -> Self {
        findings.sort_by_key(|finding| finding.id);
        Self {
            commit: commit.into(),
            findings,
        }
    }

    /// Render the snippet as markdown for prompt construction.
    pub fn render(&self) -> String {
        if self.findings.is_empty() {
            return String::new();
        }
        let mut out = String::from("## Move Audit Finding Material\n\n");
        for finding in &self.findings {
            finding.render_into(&mut out);
        }
        out
    }
}

impl MoveVulnerabilityFinding {
    fn render_into(&self, out: &mut String) {
        out.push_str(&format!("### Finding {}: {}\n\n", self.id, self.title));
        out.push_str(&format!("- Commit: {}\n", self.commit));
        if let Some(number) = self
            .number
            .as_deref()
            .filter(|value| !value.trim().is_empty())
        {
            out.push_str(&format!("- Finding Number: {}\n", number));
        }
        if let Some(kind) = self
            .finding_type
            .as_deref()
            .filter(|value| !value.trim().is_empty())
        {
            out.push_str(&format!("- Type: {}\n", kind));
        }
        if let Some(severity) = self
            .severity
            .as_deref()
            .filter(|value| !value.trim().is_empty())
        {
            out.push_str(&format!("- Original Severity: {}\n", severity));
        }
        if let Some(confidence) = self
            .confidence
            .as_deref()
            .filter(|value| !value.trim().is_empty())
        {
            out.push_str(&format!("- Confidence: {}\n", confidence));
        }
        if let Some(status) = self
            .status
            .as_deref()
            .filter(|value| !value.trim().is_empty())
        {
            out.push_str(&format!("- Status: {}\n", status));
        }
        out.push('\n');

        append_section(out, "Description", &self.description);
        append_optional_section(out, "Suggestion", self.suggestion.as_deref());
        append_optional_section(out, "Resolution", self.resolution.as_deref());
        append_optional_section(out, "Notes", self.notes.as_deref());

        if !self.files.is_empty() {
            out.push_str("#### Referenced Files\n\n");
            for file in &self.files {
                out.push_str(&format!("##### {}\n\n", file.filename));
                if !file.commit.trim().is_empty() && file.commit != self.commit {
                    out.push_str(&format!("- File Commit: {}\n\n", file.commit));
                }
                if !file.snippets.is_empty() {
                    out.push_str("```move\n");
                    out.push_str(&file.snippets.join("\n"));
                    out.push_str("\n```\n\n");
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Discovery helpers (filesystem-only — no LLM).
// ---------------------------------------------------------------------------

/// Enumerate Move project snapshots under `moves/`, deduplicating by
/// commit hash so each project is represented by its most recent
/// snapshot.
pub fn list_move_projects(
    moves_dir: &Path,
    platforms: &[MovePlatform],
) -> Result<Vec<MoveProjectDescriptor>> {
    let mut by_commit = HashMap::<String, MoveProjectDescriptor>::new();

    for platform in requested_platforms(platforms) {
        let codebase_root = moves_dir.join(platform.codebase_dir());
        if !codebase_root.exists() {
            tracing::warn!(
                "Move codebase directory not found: {}",
                codebase_root.display()
            );
            continue;
        }

        for entry in std::fs::read_dir(&codebase_root)
            .wrap_err_with(|| format!("failed to read move codebase {}", codebase_root.display()))?
        {
            let entry = entry?;
            if !entry.file_type()?.is_dir() {
                continue;
            }

            let snapshot_path = entry.path();
            let snapshot_name = entry.file_name().to_string_lossy().to_string();
            let Some((commit_hash, root_dir)) = discover_move_snapshot(&snapshot_path)? else {
                tracing::warn!(
                    "Skipping move snapshot without a commit dir: {}",
                    snapshot_path.display()
                );
                continue;
            };

            let name = load_move_package_name(&root_dir).unwrap_or_else(|| commit_hash.clone());
            let descriptor = MoveProjectDescriptor {
                platform,
                commit_hash: commit_hash.clone(),
                name,
                root_dir,
                snapshot_sort_key: snapshot_sort_key(&snapshot_name),
            };

            match by_commit.get_mut(&commit_hash) {
                Some(existing) if descriptor.snapshot_sort_key > existing.snapshot_sort_key => {
                    *existing = descriptor;
                }
                None => {
                    by_commit.insert(commit_hash, descriptor);
                }
                Some(_) => {}
            }
        }
    }

    let mut projects: Vec<_> = by_commit.into_values().collect();
    projects.sort_by(|a, b| {
        b.snapshot_sort_key
            .cmp(&a.snapshot_sort_key)
            .then_with(|| a.commit_hash.cmp(&b.commit_hash))
    });
    Ok(projects)
}

/// Load every Move vulnerability JSON found under `moves/_vun_*/` and
/// group them by commit hash. Returns a `commit -> snippet` map ready
/// to be paired with snapshots from [`list_move_projects`].
pub fn load_move_audit_reports(
    moves_dir: &Path,
    platforms: &[MovePlatform],
) -> Result<HashMap<String, MoveVulnerabilitySnippet>> {
    let mut vulnerabilities_by_commit: HashMap<String, Vec<MoveVulnerabilityFinding>> =
        HashMap::new();

    for platform in requested_platforms(platforms) {
        let vuln_root = moves_dir.join(platform.vulnerability_dir());
        if !vuln_root.exists() {
            tracing::warn!(
                "Move vulnerability directory not found: {}",
                vuln_root.display()
            );
            continue;
        }

        for entry in std::fs::read_dir(&vuln_root)
            .wrap_err_with(|| format!("failed to read {}", vuln_root.display()))?
        {
            let entry = entry?;
            let path = entry.path();
            if !entry.file_type()?.is_file()
                || path.extension().and_then(|ext| ext.to_str()) != Some("json")
            {
                continue;
            }

            let text = std::fs::read_to_string(&path)
                .wrap_err_with(|| format!("failed to read {}", path.display()))?;
            let snippet: MoveVulnerabilityFinding =
                serde_json::from_str(&text).wrap_err_with(|| {
                    format!("failed to parse move vulnerability JSON {}", path.display())
                })?;
            vulnerabilities_by_commit
                .entry(snippet.commit.clone())
                .or_default()
                .push(snippet);
        }
    }

    let mut reports = HashMap::new();
    for (commit_hash, snippets) in vulnerabilities_by_commit {
        if !snippets.is_empty() {
            reports.insert(
                commit_hash.clone(),
                MoveVulnerabilitySnippet::new(commit_hash, snippets),
            );
        }
    }
    Ok(reports)
}

/// Enumerate Code4rena contest IDs under `<dataset>/contracts/`.
/// Useful for batch-processing — the audit and report files for each
/// contest are loaded via [`crate::C4PairedProjectData::from_dataset_dir`].
pub fn list_contest_ids(dataset_dir: &Path) -> Result<Vec<u32>> {
    let contracts_dir = dataset_dir.join("contracts");
    let mut ids = Vec::new();
    for entry in std::fs::read_dir(&contracts_dir)
        .wrap_err_with(|| format!("failed to read {}", contracts_dir.display()))?
    {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            if let Some(name) = entry.file_name().to_str() {
                if let Ok(id) = name.parse::<u32>() {
                    ids.push(id);
                }
            }
        }
    }
    ids.sort();
    Ok(ids)
}

// ---------------------------------------------------------------------------
// Internals
// ---------------------------------------------------------------------------

fn requested_platforms(platforms: &[MovePlatform]) -> Vec<MovePlatform> {
    if platforms.is_empty() {
        vec![MovePlatform::Aptos, MovePlatform::Sui]
    } else {
        let mut out = Vec::new();
        for platform in platforms {
            if !out.contains(platform) {
                out.push(*platform);
            }
        }
        out
    }
}

fn discover_move_snapshot(snapshot_dir: &Path) -> Result<Option<(String, PathBuf)>> {
    let mut commit_dirs = Vec::new();
    for entry in std::fs::read_dir(snapshot_dir)? {
        let entry = entry?;
        if !entry.file_type()?.is_dir() {
            continue;
        }
        let name = entry.file_name().to_string_lossy().to_string();
        if is_hex_commit_hash(&name) {
            commit_dirs.push((name, entry.path()));
        }
    }
    commit_dirs.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(commit_dirs.into_iter().next())
}

fn is_hex_commit_hash(text: &str) -> bool {
    text.len() == 40 && text.chars().all(|ch| ch.is_ascii_hexdigit())
}

fn snapshot_sort_key(snapshot_name: &str) -> String {
    let mut parts = snapshot_name.rsplitn(3, '_');
    let time = parts.next().unwrap_or_default();
    let date = parts.next().unwrap_or_default();
    if date.len() == 8
        && time.len() == 6
        && date.chars().all(|ch| ch.is_ascii_digit())
        && time.chars().all(|ch| ch.is_ascii_digit())
    {
        format!("{date}_{time}")
    } else {
        snapshot_name.to_string()
    }
}

fn load_move_package_name(root_dir: &Path) -> Option<String> {
    let contents = std::fs::read_to_string(root_dir.join("Move.toml")).ok()?;
    parse_move_package_name(&contents)
}

fn parse_move_package_name(contents: &str) -> Option<String> {
    let mut in_package_section = false;
    for raw_line in contents.lines() {
        let line = raw_line.split('#').next().unwrap_or_default().trim();
        if line.is_empty() {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            in_package_section = line == "[package]";
            continue;
        }
        if in_package_section {
            let Some(rest) = line.strip_prefix("name") else {
                continue;
            };
            let Some(value) = rest.trim_start().strip_prefix('=') else {
                continue;
            };
            let value = value.trim().trim_matches('"');
            if !value.is_empty() {
                return Some(value.to_string());
            }
        }
    }
    None
}

fn append_section(out: &mut String, heading: &str, value: &str) {
    let value = value.trim();
    if value.is_empty() {
        return;
    }
    out.push_str(&format!("#### {heading}\n\n{value}\n\n"));
}

fn append_optional_section(out: &mut String, heading: &str, value: Option<&str>) {
    if let Some(value) = value {
        append_section(out, heading, value);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_move_package_name_finds_name() {
        let toml = r#"
[package]
name = "foo_bar"
version = "0.1"
"#;
        assert_eq!(parse_move_package_name(toml).as_deref(), Some("foo_bar"));
    }

    #[test]
    fn parse_move_package_name_other_section_ignored() {
        let toml = r#"
[addresses]
name = "ignored"
"#;
        assert_eq!(parse_move_package_name(toml), None);
    }

    #[test]
    fn is_hex_commit_recognises_40_hex_chars() {
        assert!(is_hex_commit_hash(
            "0123456789abcdef0123456789abcdef01234567"
        ));
        assert!(!is_hex_commit_hash("short"));
        assert!(!is_hex_commit_hash(
            "g123456789abcdef0123456789abcdef01234567"
        ));
    }
}
