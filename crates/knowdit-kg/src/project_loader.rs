use crate::error::{KgError, Result};
use serde::Deserialize;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// Metadata from the audit JSON files in out_train/audits/
#[derive(Debug, Clone, Deserialize)]
pub struct AuditMeta {
    #[serde(rename = "contestId")]
    pub contest_id: u32,
    pub title: String,
    pub slug: Option<String>,
    #[serde(rename = "startTime")]
    pub start_time: Option<String>,
    #[serde(rename = "endTime")]
    pub end_time: Option<String>,
    pub details: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceLanguage {
    Solidity,
    Move,
}

impl SourceLanguage {
    pub fn display_name(self) -> &'static str {
        match self {
            Self::Solidity => "Solidity",
            Self::Move => "Move",
        }
    }

    pub fn code_fence(self) -> &'static str {
        match self {
            Self::Solidity => "solidity",
            Self::Move => "move",
        }
    }

    fn extension(self) -> &'static str {
        match self {
            Self::Solidity => "sol",
            Self::Move => "move",
        }
    }
}

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

    fn codebase_dir(self) -> &'static str {
        match self {
            Self::Aptos => "_codebase_apt",
            Self::Sui => "_codebase_sui",
        }
    }

    fn vulnerability_dir(self) -> &'static str {
        match self {
            Self::Aptos => "_vun_apt",
            Self::Sui => "_vun_sui/vulnerability_snippets",
        }
    }
}

#[derive(Debug, Clone)]
pub struct MoveProjectDescriptor {
    pub platform: MovePlatform,
    pub commit_hash: String,
    pub name: String,
    pub root_dir: PathBuf,
    snapshot_sort_key: String,
}

impl MoveProjectDescriptor {
    pub fn into_project_data(
        self,
        audit_report: Option<MoveVulnerabilitySnippet>,
    ) -> Result<ProjectData> {
        ProjectData::from_move_snapshot(&self.name, &self.root_dir, &self.commit_hash, audit_report)
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct MoveVulnerabilitySnippetFile {
    pub filename: String,
    #[serde(default)]
    pub commit: String,
    #[serde(default)]
    pub snippets: Vec<String>,
}

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

        append_move_section(out, "Description", &self.description);
        append_optional_move_section(out, "Suggestion", self.suggestion.as_deref());
        append_optional_move_section(out, "Resolution", self.resolution.as_deref());
        append_optional_move_section(out, "Notes", self.notes.as_deref());

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

#[derive(Debug, Clone)]
pub enum AuditReportMaterial {
    Text(String),
    MoveVulnerabilitySnippet(MoveVulnerabilitySnippet),
}

impl AuditReportMaterial {
    pub fn render(&self) -> String {
        match self {
            Self::Text(text) => text.clone(),
            Self::MoveVulnerabilitySnippet(snippet) => snippet.render(),
        }
    }
}

/// A project to be learned. Can be created from any directory containing source files.
#[derive(Debug, Clone)]
pub struct ProjectData {
    pub name: String,
    /// Platform-specific ID, e.g. "c4-420". None for generic projects.
    pub platform_id: Option<String>,
    pub root_dir: PathBuf,
    pub audit_report: Option<AuditReportMaterial>,
    pub source_language: SourceLanguage,
    pub source_files: Vec<SourceFile>,
}

#[derive(Debug, Clone)]
pub struct SourceFile {
    pub path: PathBuf,
    pub relative_path: String,
    pub content: String,
}

impl ProjectData {
    /// Load a project from an arbitrary directory containing Solidity files.
    pub fn from_dir(name: &str, root_dir: &Path, platform_id: Option<&str>) -> Result<Self> {
        if !root_dir.exists() || !root_dir.is_dir() {
            return Err(KgError::other(format!(
                "Project directory not found: {}",
                root_dir.display()
            )));
        }

        let source_files = collect_source_files(root_dir, SourceLanguage::Solidity)?;

        Ok(Self {
            name: name.to_string(),
            platform_id: platform_id.map(|s| s.to_string()),
            root_dir: root_dir.to_path_buf(),
            audit_report: None,
            source_language: SourceLanguage::Solidity,
            source_files,
        })
    }

    /// Load a Code4rena project from the out_train directory structure.
    pub fn from_c4(out_train: &Path, contest_id: u32) -> Result<Self> {
        let audit_path = out_train
            .join("audits")
            .join(format!("{}.json", contest_id));
        if !audit_path.exists() {
            return Err(KgError::other(format!(
                "Audit metadata not found: {}",
                audit_path.display()
            )));
        }
        let meta: AuditMeta = serde_json::from_str(&std::fs::read_to_string(&audit_path)?)?;

        let contracts_dir = out_train.join("contracts").join(contest_id.to_string());
        if !contracts_dir.exists() {
            return Err(KgError::other(format!(
                "Contracts directory not found: {}",
                contracts_dir.display()
            )));
        }

        let source_files = collect_source_files(&contracts_dir, SourceLanguage::Solidity)?;
        let report_path = out_train.join("reports").join(format!("{}.md", contest_id));
        let audit_report = if report_path.exists() {
            match std::fs::read_to_string(&report_path) {
                Ok(report) if !report.trim().is_empty() => Some(report),
                Ok(_) => None,
                Err(e) => {
                    tracing::warn!("Failed to read {}: {}", report_path.display(), e);
                    None
                }
            }
        } else {
            tracing::warn!("Audit report not found: {}", report_path.display());
            None
        };

        Ok(Self {
            name: meta.title,
            platform_id: Some(format!("c4-{}", contest_id)),
            root_dir: contracts_dir,
            audit_report: audit_report.map(AuditReportMaterial::Text),
            source_language: SourceLanguage::Solidity,
            source_files,
        })
    }

    /// Load a Move project snapshot from the `moves/` dataset.
    pub fn from_move_snapshot(
        name: &str,
        root_dir: &Path,
        commit_hash: &str,
        audit_report: Option<MoveVulnerabilitySnippet>,
    ) -> Result<Self> {
        if !root_dir.exists() || !root_dir.is_dir() {
            return Err(KgError::other(format!(
                "Move project directory not found: {}",
                root_dir.display()
            )));
        }

        let source_files = collect_source_files(root_dir, SourceLanguage::Move)?;

        Ok(Self {
            name: name.to_string(),
            platform_id: Some(format!("b-{}", commit_hash)),
            root_dir: root_dir.to_path_buf(),
            audit_report: audit_report.map(AuditReportMaterial::MoveVulnerabilitySnippet),
            source_language: SourceLanguage::Move,
            source_files,
        })
    }

    /// A display-friendly identifier: platform_id if set, else project name.
    pub fn display_id(&self) -> String {
        self.platform_id
            .clone()
            .unwrap_or_else(|| self.name.clone())
    }
}

/// List all available contest IDs in out_train/
pub fn list_contest_ids(out_train: &Path) -> Result<Vec<u32>> {
    let contracts_dir = out_train.join("contracts");
    let mut ids = Vec::new();
    for entry in std::fs::read_dir(&contracts_dir)? {
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

pub fn list_move_projects(
    moves_dir: &Path,
    platforms: &[MovePlatform],
) -> Result<Vec<MoveProjectDescriptor>> {
    let mut by_commit = HashMap::<String, MoveProjectDescriptor>::new();

    for platform in requested_move_platforms(platforms) {
        let codebase_root = moves_dir.join(platform.codebase_dir());
        if !codebase_root.exists() {
            tracing::warn!(
                "Move codebase directory not found: {}",
                codebase_root.display()
            );
            continue;
        }

        for entry in std::fs::read_dir(&codebase_root)? {
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

pub fn load_move_audit_reports(
    moves_dir: &Path,
    platforms: &[MovePlatform],
) -> Result<HashMap<String, MoveVulnerabilitySnippet>> {
    let mut vulnerabilities_by_commit: HashMap<String, Vec<MoveVulnerabilityFinding>> =
        HashMap::new();

    for platform in requested_move_platforms(platforms) {
        let vuln_root = moves_dir.join(platform.vulnerability_dir());
        if !vuln_root.exists() {
            tracing::warn!(
                "Move vulnerability directory not found: {}",
                vuln_root.display()
            );
            continue;
        }

        for entry in std::fs::read_dir(&vuln_root)? {
            let entry = entry?;
            let path = entry.path();
            if !entry.file_type()?.is_file()
                || path.extension().and_then(|ext| ext.to_str()) != Some("json")
            {
                continue;
            }

            let snippet: MoveVulnerabilityFinding =
                serde_json::from_str(&std::fs::read_to_string(&path)?)?;
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

fn requested_move_platforms(platforms: &[MovePlatform]) -> Vec<MovePlatform> {
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

fn append_move_section(out: &mut String, heading: &str, value: &str) {
    let value = value.trim();
    if value.is_empty() {
        return;
    }
    out.push_str(&format!("#### {}\n\n{}\n\n", heading, value));
}

fn append_optional_move_section(out: &mut String, heading: &str, value: Option<&str>) {
    if let Some(value) = value {
        append_move_section(out, heading, value);
    }
}

fn collect_source_files(dir: &Path, language: SourceLanguage) -> Result<Vec<SourceFile>> {
    let mut files = Vec::new();
    collect_source_recursive(dir, dir, language, &mut files)?;
    files.sort_by(|a, b| a.relative_path.cmp(&b.relative_path));
    Ok(files)
}

fn collect_source_recursive(
    base: &Path,
    dir: &Path,
    language: SourceLanguage,
    files: &mut Vec<SourceFile>,
) -> Result<()> {
    if !dir.is_dir() {
        return Ok(());
    }
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            let dir_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            // Skip common non-source directories
            if matches!(
                dir_name,
                "node_modules"
                    | "build"
                    | "artifacts"
                    | "cache"
                    | "coverage"
                    | ".git"
                    | "target"
                    | "typechain"
                    | "typechain-types"
                    | "deployments"
            ) {
                continue;
            }
            collect_source_recursive(base, &path, language, files)?;
        } else if path.extension().and_then(|e| e.to_str()) == Some(language.extension()) {
            let relative = path
                .strip_prefix(base)
                .unwrap_or(&path)
                .to_string_lossy()
                .to_string();

            if should_skip_source_file(language, &relative) {
                continue;
            }

            match std::fs::read_to_string(&path) {
                Ok(content) => {
                    if !content.trim().is_empty() {
                        files.push(SourceFile {
                            path: path.clone(),
                            relative_path: relative,
                            content,
                        });
                    }
                }
                Err(e) => {
                    tracing::warn!("Failed to read {}: {}", path.display(), e);
                }
            }
        }
    }
    Ok(())
}

fn should_skip_source_file(language: SourceLanguage, relative_path: &str) -> bool {
    let lower = relative_path.to_lowercase();
    if lower.starts_with("tests/")
        || lower.starts_with("test/")
        || lower.contains("/tests/")
        || lower.contains("/test/")
    {
        return true;
    }

    matches!(language, SourceLanguage::Solidity)
        && (lower.starts_with("mock/") || lower.contains("/mock/"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_move_package_name_reads_package_section() {
        let contents = r#"
[package]
name = "haedal_pmm"
edition = "2024.beta"

[addresses]
haedal_pmm = "0x0"
"#;

        assert_eq!(
            parse_move_package_name(contents),
            Some("haedal_pmm".to_string())
        );
    }

    #[test]
    fn move_vulnerability_snippet_render_includes_core_fields() {
        let report = MoveVulnerabilitySnippet::new(
            "48eac9a37c8d7157570cbb798b9df7a9cf53676e",
            vec![MoveVulnerabilityFinding {
                id: 100,
                commit: "48eac9a37c8d7157570cbb798b9df7a9cf53676e".to_string(),
                project_id: Some(190),
                number: Some("STA".to_string()),
                title: "The Error Codes Are Not Used Anywhere".to_string(),
                finding_type: Some("Findings".to_string()),
                severity: Some("Minor".to_string()),
                confidence: Some("High".to_string()),
                status: Some("Fixed".to_string()),
                description: "The Error codes are not used anywhere.".to_string(),
                suggestion: Some("Remove the unused error codes.".to_string()),
                resolution: Some("This issue has been fixed.".to_string()),
                notes: None,
                files: vec![MoveVulnerabilitySnippetFile {
                    filename: "sources/staking.move".to_string(),
                    commit: "48eac9a37c8d7157570cbb798b9df7a9cf53676e".to_string(),
                    snippets: vec!["const EClaimEpochNotFound: u64 = 2;".to_string()],
                }],
            }],
        )
        .render();

        assert!(report.contains("### Finding 100: The Error Codes Are Not Used Anywhere"));
        assert!(report.contains("- Original Severity: Minor"));
        assert!(report.contains("#### Description"));
        assert!(report.contains("sources/staking.move"));
        assert!(report.contains("```move"));
    }
}
