//! The **Review agent** — third grader in the reflection family, run by the
//! `review-findings` workflow (NOT inline in `agentic reflect`).
//!
//! The verdict + severity graders only decide *is this a real bug* and a
//! fuzz-time tier; a `valid_finding` row has no title and no normalized
//! shape. This agent turns one confirmed [`LoadedValidFinding`] into the
//! structured, client-facing finding the downstream Merge agent clusters on
//! and the Writer agent renders: a `title`, a re-graded
//! [`ReviewSeverity`] (the fuzz-time severity is not trusted), a normalized
//! `root_cause` / `description`, and the affected `location`.
//!
//! It also owns the **scope decision**. When the workflow resolves an
//! authoritative scope override (a `--scope-file` or `knowdit-scope.md`),
//! that text is injected verbatim into the system prompt and the agent is
//! told to judge scope ONLY against it; otherwise the agent surveys the
//! project's own `AUDIT_SCOPE.md` / `ASSUMPTIONS.md` plus built-in
//! not-accepted heuristics. A finding ruled out of scope is emitted as
//! [`ReviewSeverity::ReviewedOutOfScope`] — there is no separate
//! disposition field.
//!
//! Mirrors [`super::severity_grader::SeverityGrader`] in shape: same
//! `ProjectIndex`-backed toolbox + repo file tools, same
//! [`drive_agent_loop`] driver, one `emit_finding_review` tool writing into
//! an [`AttemptHandle`].

use std::path::{Path, PathBuf};
use std::sync::Arc;

use color_eyre::eyre::{Result, WrapErr};
use knowdit_repo_model::{FindingReviewRecord, LoadedValidFinding, RepoDatabase, ReviewSeverity};
use llmy::agent::tool::ToolBox;
use llmy::agent::tools::files::{FindFileTool, GrepDirectoryTool, ListDirectoryTool, ReadFileTool};
use llmy::client::client::LLM;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::spec::{
    LookupCallGraphTool, LookupStateVariableXrefsTool, ProjectIndex, ReadContractSourceTool,
    ReadFunctionSourceTool,
};

use super::agent_loop::{AttemptHandle, GraderOptions, RunSummary, drive_agent_loop};
use super::prompt::review_system;

/// Number of trailing bytes of forge stdout the agent sees. The tail
/// carries the invariant verdict + counter-example dump.
const STDOUT_TAIL_BYTES: usize = 4_000;

/// One review task — the per-raw-finding context the Review agent grades.
/// Serialized verbatim as the agent's user prompt. Built from a
/// [`LoadedValidFinding`] via [`ReviewInput::from_valid_finding`].
#[derive(Debug, Clone, Serialize)]
pub struct ReviewInput {
    pub reflection_id: i32,
    pub run_id: i32,
    pub spec_id: i32,
    /// The AuditSpecification (parsed) this finding proved.
    pub spec: serde_json::Value,
    /// The committed PoC harness source.
    pub harness_source: String,
    /// The violating harness_run digest.
    pub run: RunSummary,
    /// The verdict grader's argument for why this is a real bug — anchor
    /// the review on it instead of re-deciding existence.
    pub verdict_reason: String,
    /// The fuzz-time severity tier + reason. A weak prior only: this agent
    /// re-grades from scratch (the fuzz grader over-produces `Medium`).
    pub fuzz_severity: String,
    pub fuzz_severity_reason: String,
}

impl ReviewInput {
    /// Assemble the agent input from a loaded raw finding: parse the spec
    /// JSON, digest the forge run, and carry the verdict / fuzz-severity
    /// reasoning as anchors.
    pub fn from_valid_finding(vf: &LoadedValidFinding) -> Result<Self> {
        let spec: serde_json::Value =
            serde_json::from_str(&vf.specification_json).wrap_err_with(|| {
                format!(
                    "review: failed to parse specification.json for spec_id={}",
                    vf.spec_id
                )
            })?;
        let stdout = &vf.run_stdout;
        let stdout_tail = if stdout.len() <= STDOUT_TAIL_BYTES {
            stdout.clone()
        } else {
            let mut start = stdout.len() - STDOUT_TAIL_BYTES;
            while start < stdout.len() && !stdout.is_char_boundary(start) {
                start += 1;
            }
            stdout[start..].to_string()
        };
        let run = RunSummary {
            kind: vf.run_kind.clone(),
            exit_code: vf.run_exit_code.unwrap_or(-1),
            violated: vf.run_violated,
            stdout_tail,
            counterexample_json: vf
                .run_sequence_json
                .as_deref()
                .and_then(|s| serde_json::from_str(s).ok()),
        };
        Ok(Self {
            reflection_id: vf.reflection_id,
            run_id: vf.run_id,
            spec_id: vf.spec_id,
            spec,
            harness_source: vf.harness_source.clone(),
            run,
            verdict_reason: vf.verdict_reason.clone(),
            fuzz_severity: vf.severity.clone(),
            fuzz_severity_reason: vf.severity_reason.clone(),
        })
    }
}

/// The structured review captured from the agent.
#[derive(Debug, Clone)]
pub struct ReviewOutput {
    pub title: String,
    pub severity: ReviewSeverity,
    pub review_reason: String,
    pub root_cause: String,
    pub description: String,
    pub location: String,
    pub impact: String,
    pub recommendation: String,
    pub primary_contract: String,
    pub primary_function: String,
    pub severity_reason: String,
    pub steps: usize,
}

impl ReviewOutput {
    /// Pair the graded review with its raw finding into the DB write
    /// record the workflow persists via
    /// [`RepoDatabase::insert_finding_review`].
    pub fn into_record(self, reflection_id: i32) -> FindingReviewRecord {
        FindingReviewRecord {
            reflection_id,
            title: self.title,
            severity: self.severity,
            review_reason: self.review_reason,
            root_cause: self.root_cause,
            description: self.description,
            location: self.location,
            impact: self.impact,
            recommendation: self.recommendation,
            primary_contract: self.primary_contract,
            primary_function: self.primary_function,
            severity_reason: self.severity_reason,
        }
    }
}

/// The Review agent. Holds the shared `ProjectIndex`, the repo root (for
/// file tools), the language prompt prefix, and the resolved authoritative
/// scope override (if any).
pub struct ReviewGrader {
    llm: LLM,
    project_index: Arc<ProjectIndex>,
    repo_root: PathBuf,
    language_prompt_prefix: String,
    /// Authoritative audit-scope text resolved by the workflow
    /// (`--scope-file` or `knowdit-scope.md/.txt`). When `Some`, it is
    /// injected into the system prompt and overrides the project's own
    /// scope docs.
    scope_override: Option<String>,
    options: GraderOptions,
}

impl ReviewGrader {
    /// Build a Review agent, loading the project graphs once.
    pub async fn new(
        repo: &RepoDatabase,
        repo_root: &Path,
        language_prompt_prefix: String,
        scope_override: Option<String>,
        llm: &LLM,
        options: GraderOptions,
    ) -> Result<Self> {
        let call_graph = repo
            .load_call_graph()
            .await
            .wrap_err("review agent: failed to load project call graph")?;
        let storage_graph = repo
            .load_storage_graph()
            .await
            .wrap_err("review agent: failed to load project storage graph")?;
        let inheritance_graph = repo
            .load_inheritance_graph()
            .await
            .wrap_err("review agent: failed to load project inheritance graph")?;
        let project_index = Arc::new(ProjectIndex::build(
            call_graph,
            storage_graph,
            inheritance_graph,
        ));
        Ok(Self {
            llm: llm.clone(),
            project_index,
            repo_root: repo_root.to_path_buf(),
            language_prompt_prefix,
            scope_override,
            options,
        })
    }

    /// Review one confirmed raw finding into a structured, client-facing
    /// finding. Returns `Err` only on agent / tool wiring failures or
    /// step-budget exhaustion — the caller MUST NOT persist on `Err`.
    pub async fn grade(&self, input: &ReviewInput) -> Result<ReviewOutput> {
        let attempt: AttemptHandle<RawReview> = AttemptHandle::new();
        let tools = build_review_toolbox(&self.project_index, &self.repo_root, &attempt);
        let user_prompt = serde_json::to_string_pretty(input)
            .wrap_err("review agent: failed to serialize ReviewInput")?;
        let cache_suffix = format!("review-r{:06}-s{:06}", input.run_id, input.spec_id);
        let steps = drive_agent_loop(
            &self.project_index,
            &self.llm,
            &self.options,
            review_system(&self.language_prompt_prefix, self.scope_override.as_deref()),
            user_prompt,
            &cache_suffix,
            tools,
            &attempt,
        )
        .await?;
        let raw = attempt
            .take()
            .await
            .expect("drive_agent_loop returns only when attempt is set");
        Ok(ReviewOutput {
            title: raw.title,
            severity: raw.severity.into(),
            review_reason: raw.review_reason,
            root_cause: raw.root_cause,
            description: raw.description,
            location: raw.location,
            impact: raw.impact,
            recommendation: raw.recommendation,
            primary_contract: raw.primary_contract,
            primary_function: raw.primary_function,
            severity_reason: raw.severity_reason,
            steps,
        })
    }
}

fn build_review_toolbox(
    project_index: &Arc<ProjectIndex>,
    repo_root: &Path,
    attempt: &AttemptHandle<RawReview>,
) -> ToolBox {
    let mut tools = ToolBox::new();
    tools.add_tool(LookupCallGraphTool {
        project: project_index.clone(),
    });
    tools.add_tool(LookupStateVariableXrefsTool {
        project: project_index.clone(),
    });
    tools.add_tool(ReadContractSourceTool {
        project: project_index.clone(),
    });
    tools.add_tool(ReadFunctionSourceTool {
        project: project_index.clone(),
    });
    // Repo-level IO: the agent reads project scope docs / NatSpec / source
    // comments when judging scope + impact and grounding the location.
    tools.add_tool(ReadFileTool::new(repo_root.to_path_buf()));
    tools.add_tool(ListDirectoryTool::new_root(repo_root.to_path_buf()));
    tools.add_tool(FindFileTool::new(repo_root.to_path_buf()));
    tools.add_tool(GrepDirectoryTool::new(repo_root.to_path_buf()));
    tools.add_tool(EmitFindingReviewTool {
        attempt: attempt.clone(),
    });
    tools
}

// ---------------------------------------------------------------------------
// emit_finding_review tool
// ---------------------------------------------------------------------------

/// 5-class tier the Review agent may emit. Mirrors
/// [`knowdit_repo_model::ReviewSeverity`]; a local enum so this module
/// derives `JsonSchema` without touching the repo-model crate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
pub enum ReviewSeverityArg {
    High,
    Medium,
    Low,
    Informational,
    ReviewedOutOfScope,
}

impl From<ReviewSeverityArg> for ReviewSeverity {
    fn from(t: ReviewSeverityArg) -> Self {
        match t {
            ReviewSeverityArg::High => Self::High,
            ReviewSeverityArg::Medium => Self::Medium,
            ReviewSeverityArg::Low => Self::Low,
            ReviewSeverityArg::Informational => Self::Informational,
            ReviewSeverityArg::ReviewedOutOfScope => Self::ReviewedOutOfScope,
        }
    }
}

#[derive(Debug, Clone)]
struct RawReview {
    title: String,
    severity: ReviewSeverityArg,
    review_reason: String,
    root_cause: String,
    description: String,
    location: String,
    impact: String,
    recommendation: String,
    primary_contract: String,
    primary_function: String,
    severity_reason: String,
}

#[derive(Debug, Clone, Deserialize, JsonSchema)]
struct EmitFindingReviewArgs {
    /// Concise, client-facing, project-specific title. No workflow jargon
    /// (no spec/extract/historical ids, no "harness"/"fuzz").
    title: String,
    /// `High` | `Medium` | `Low` | `Informational` | `ReviewedOutOfScope`.
    severity: ReviewSeverityArg,
    /// Scope / severity rationale. For `ReviewedOutOfScope` cite the
    /// excluding scope rule or assumption; for the tiers, justify the
    /// chosen severity.
    review_reason: String,
    /// One-line normalized root cause — the cluster key.
    root_cause: String,
    /// Normalized, project-terms description of the vulnerable mechanism
    /// (no workflow jargon). This is what the client report shows.
    description: String,
    /// Primary affected location: `Contract.function` and `file:line`.
    location: String,
    /// Client-facing impact: what is lost / broken, who can trigger it, under
    /// what preconditions. Project terms only.
    impact: String,
    /// Client-facing remediation: the concrete fix (missing check, corrected
    /// ordering, invariant to enforce). Project terms only.
    recommendation: String,
    /// Primary affected contract name (e.g. `ClimatePool`), verified to
    /// exist via lookup_call_graph.
    primary_contract: String,
    /// Primary affected function name (e.g. `sweepUnclaimable`), verified to
    /// exist on `primary_contract`.
    primary_function: String,
    /// Concrete impact argument (the violating function + state effect).
    severity_reason: String,
}

#[derive(Debug, Clone)]
#[llmy::agent::tool(
    arguments = EmitFindingReviewArgs,
    invoke = invoke,
    description = "Commit the structured, client-facing review of this finding and end the agent run. Call EXACTLY once, after grounding title/location/severity/scope in the actual project source and scope docs. Use ReviewedOutOfScope when the bug is real but excluded by the audit scope or the project's stated assumptions. All text must be in project terms — never mention specs/harnesses/fuzzing or any internal ids.",
    name = "emit_finding_review",
)]
struct EmitFindingReviewTool {
    attempt: AttemptHandle<RawReview>,
}

impl EmitFindingReviewTool {
    async fn invoke(
        &self,
        args: EmitFindingReviewArgs,
    ) -> std::result::Result<String, llmy::agent::LLMYError> {
        if args.title.trim().is_empty() {
            return Ok("error: title must be non-empty".to_string());
        }
        if args.review_reason.trim().is_empty() {
            return Ok("error: review_reason must be non-empty".to_string());
        }
        if args.root_cause.trim().is_empty() {
            return Ok("error: root_cause must be non-empty".to_string());
        }
        if args.impact.trim().is_empty() {
            return Ok("error: impact must be non-empty".to_string());
        }
        if args.recommendation.trim().is_empty() {
            return Ok("error: recommendation must be non-empty".to_string());
        }
        match self
            .attempt
            .try_set(RawReview {
                title: args.title,
                severity: args.severity,
                review_reason: args.review_reason,
                root_cause: args.root_cause,
                description: args.description,
                location: args.location,
                impact: args.impact,
                recommendation: args.recommendation,
                primary_contract: args.primary_contract,
                primary_function: args.primary_function,
                severity_reason: args.severity_reason,
            })
            .await
        {
            Ok(()) => {
                Ok("ok: finding review committed; the runtime will end the agent now".to_string())
            }
            Err(_) => Ok("error: emit_finding_review already called for this run".to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn emit_review_args_typed_enum() {
        let s = r#"{"title":"t","severity":"ReviewedOutOfScope","review_reason":"r","root_cause":"rc","description":"d","location":"l","impact":"i","recommendation":"rec","primary_contract":"C","primary_function":"f","severity_reason":"sr"}"#;
        let args: EmitFindingReviewArgs = serde_json::from_str(s).unwrap();
        assert_eq!(args.severity, ReviewSeverityArg::ReviewedOutOfScope);
    }

    #[test]
    fn emit_review_args_unknown_severity_rejected() {
        let s = r#"{"title":"t","severity":"Critical","review_reason":"r","root_cause":"rc","description":"d","location":"l","impact":"i","recommendation":"rec","primary_contract":"C","primary_function":"f","severity_reason":"sr"}"#;
        assert!(serde_json::from_str::<EmitFindingReviewArgs>(s).is_err());
    }
}
