//! Phase 2 of reflection: the **severity grader** agent.
//!
//! Runs only when [`super::grader::VerdictGrader`] returned
//! `ValidFinding`. Decides which of the three severity tiers the bug
//! falls into:
//!
//! - **High** — full liquidity drain. The agent must first identify
//!   the project's "liquidity" state variables (pool balances, total
//!   supplies, collateral pots, share pools, etc.) using
//!   `lookup_state_variable_xrefs`, then argue from
//!   `read_function_source` of the violating function how the
//!   counter-example trace empties them entirely.
//! - **Medium** — partial loss / griefing / DOS / privileged-actor
//!   exploitation. The agent must name the specific affected
//!   function or state variable.
//! - **Low** — non-exploitable, informational, edge-case-only.
//!
//! The agent is fed the verdict grader's `rationale` (Phase 1's
//! output) so it has the "why ValidFinding" context to anchor its
//! severity argument.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use color_eyre::eyre::{Result, WrapErr};
use knowdit_kg_model::audit_finding::FindingSeverity;
use knowdit_repo_model::RepoDatabase;
use llmy::agent::tool::ToolBox;
use llmy::agent::tools::files::{FindFileTool, GrepDirectoryTool, ListDirectoryTool, ReadFileTool};
use llmy::client::client::LLM;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::spec::{
    LookupCallGraphTool, LookupStateVariableXrefsTool, ProjectIndex, ReadContractSourceTool,
    ReadFunctionSourceTool,
};
use crate::types::AuditSpecification;

use super::agent_loop::{
    AttemptHandle, CoverageSummary, GraderOptions, RunSummary, drive_agent_loop,
};
use super::prompt::SEVERITY_SYSTEM;

/// Single per-`harness_run` severity-grading task. Same per-run /
/// per-spec context the verdict grader saw, plus the verdict
/// grader's `rationale` (so the severity agent can build on the
/// same evidence rather than rediscover it).
#[derive(Debug, Clone, Serialize)]
pub struct SeverityInput {
    pub run_id: i32,
    pub spec_id: i32,
    pub spec: AuditSpecification,
    pub harness_source: String,
    pub finding_title: Option<String>,
    pub run: RunSummary,
    pub coverage_summary: Option<CoverageSummary>,
    /// `VerdictGrader::grade(...).reason` — what the verdict agent
    /// concluded about why this is a real bug.
    pub verdict_reason: String,
}

/// Severity captured by [`EmitSeverityTool`].
#[derive(Debug, Clone)]
pub struct SeverityOutput {
    pub severity: FindingSeverity,
    pub severity_reason: String,
    pub steps: usize,
}

/// The severity grader agent. Same shape as [`super::grader::VerdictGrader`]
/// but with the severity-specific prompt + emit tool.
pub struct SeverityGrader {
    llm: LLM,
    project_index: Arc<ProjectIndex>,
    /// Repository root on disk. Threaded into [`build_severity_toolbox`]
    /// so the agent's `read_file` / `list_dir` / `find_file` / `grep`
    /// tools sandbox to this directory.
    repo_root: PathBuf,
    options: GraderOptions,
}

impl SeverityGrader {
    /// Build a severity grader. Loads the project graphs once.
    pub async fn new(
        repo: &RepoDatabase,
        repo_root: &Path,
        llm: &LLM,
        options: GraderOptions,
    ) -> Result<Self> {
        let call_graph = repo
            .load_call_graph()
            .await
            .wrap_err("severity grader: failed to load project call graph")?;
        let storage_graph = repo
            .load_storage_graph()
            .await
            .wrap_err("severity grader: failed to load project storage graph")?;
        let inheritance_graph = repo
            .load_inheritance_graph()
            .await
            .wrap_err("severity grader: failed to load project inheritance graph")?;
        let project_index = Arc::new(ProjectIndex::build(
            call_graph,
            storage_graph,
            inheritance_graph,
        ));
        Ok(Self {
            llm: llm.clone(),
            project_index,
            repo_root: repo_root.to_path_buf(),
            options,
        })
    }

    /// Build a severity grader sharing the verdict grader's already-
    /// loaded `ProjectIndex`. Saves a redundant call_graph +
    /// storage_graph load when both graders run in the same CLI
    /// invocation (the typical case).
    pub fn new_with_index(
        llm: &LLM,
        repo_root: &Path,
        project_index: Arc<ProjectIndex>,
        options: GraderOptions,
    ) -> Self {
        Self {
            llm: llm.clone(),
            project_index,
            repo_root: repo_root.to_path_buf(),
            options,
        }
    }

    /// Grade severity for one ValidFinding. Returns `Err` only on
    /// agent / tool wiring failures or step-budget exhaustion — the
    /// caller MUST NOT persist a row in those cases. Resume safety:
    /// re-running picks the run back up; llmy cache reuses prior
    /// agent steps.
    pub async fn grade(&self, input: &SeverityInput) -> Result<SeverityOutput> {
        let attempt: AttemptHandle<RawSeverity> = AttemptHandle::new();
        let tools = build_severity_toolbox(&self.project_index, &self.repo_root, &attempt);
        let user_prompt = serde_json::to_string_pretty(input)
            .wrap_err("severity grader: failed to serialize SeverityInput")?;
        let cache_suffix = format!("severity-r{:06}-s{:06}", input.run_id, input.spec_id);
        let steps = drive_agent_loop(
            &self.project_index,
            &self.llm,
            &self.options,
            SEVERITY_SYSTEM.to_string(),
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
        Ok(SeverityOutput {
            severity: raw.severity.into(),
            severity_reason: raw.severity_reason,
            steps,
        })
    }
}

fn build_severity_toolbox(
    project_index: &Arc<ProjectIndex>,
    repo_root: &Path,
    attempt: &AttemptHandle<RawSeverity>,
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
    // Same repo-level IO as the verdict grader — severity benefits from
    // reading README / docs / NatSpec when assessing liquidity impact.
    tools.add_tool(ReadFileTool::new(repo_root.to_path_buf()));
    tools.add_tool(ListDirectoryTool::new_root(repo_root.to_path_buf()));
    tools.add_tool(FindFileTool::new(repo_root.to_path_buf()));
    tools.add_tool(GrepDirectoryTool::new(repo_root.to_path_buf()));
    tools.add_tool(EmitSeverityTool {
        attempt: attempt.clone(),
    });
    tools
}

// ---------------------------------------------------------------------------
// emit_severity tool
// ---------------------------------------------------------------------------

/// 3-class severity tier the agent may emit. Mirrors
/// [`FindingSeverity`] (defined in `knowdit-kg-model`); we keep a
/// local enum so this module can derive `JsonSchema` without
/// touching the kg-model crate's derives.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
pub enum SeverityTier {
    High,
    Medium,
    Low,
}

impl From<SeverityTier> for FindingSeverity {
    fn from(t: SeverityTier) -> Self {
        match t {
            SeverityTier::High => Self::High,
            SeverityTier::Medium => Self::Medium,
            SeverityTier::Low => Self::Low,
        }
    }
}

#[derive(Debug, Clone)]
struct RawSeverity {
    severity: SeverityTier,
    severity_reason: String,
}

#[derive(Debug, Clone, Deserialize, JsonSchema)]
struct EmitSeverityArgs {
    /// `High` | `Medium` | `Low`. Pick exactly one.
    severity: SeverityTier,
    /// Concrete one-paragraph rationale that MUST cite specific
    /// state variables (for High) or specific affected function +
    /// state variable (for Medium). Generic phrasing is rejected.
    severity_reason: String,
}

#[derive(Debug, Clone)]
#[llmy::agent::tool(
    arguments = EmitSeverityArgs,
    invoke = invoke,
    description = "Commit the final severity tier for this ValidFinding and end the agent run. Call EXACTLY once. AFTER gathering enough evidence via lookup_state_variable_xrefs (to identify liquidity state vars) and read_function_source (to argue the trace's effect on them). High requires demonstrated FULL liquidity drain on identified state variables. Medium requires the affected function + state variable to be named explicitly. Low is the fallback for anything not exploitable.",
    name = "emit_severity",
)]
struct EmitSeverityTool {
    attempt: AttemptHandle<RawSeverity>,
}

impl EmitSeverityTool {
    async fn invoke(
        &self,
        args: EmitSeverityArgs,
    ) -> std::result::Result<String, llmy::agent::LLMYError> {
        if args.severity_reason.trim().is_empty() {
            return Ok("error: severity_reason must be non-empty".to_string());
        }
        match self
            .attempt
            .try_set(RawSeverity {
                severity: args.severity,
                severity_reason: args.severity_reason,
            })
            .await
        {
            Ok(()) => Ok("ok: severity committed; the runtime will end the agent now".to_string()),
            Err(_) => Ok("error: emit_severity already called for this run".to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn emit_severity_args_typed_enum() {
        let s = r#"{"severity":"High","severity_reason":"x"}"#;
        let args: EmitSeverityArgs = serde_json::from_str(s).unwrap();
        assert_eq!(args.severity, SeverityTier::High);
    }

    #[test]
    fn emit_severity_args_unknown_rejected() {
        let s = r#"{"severity":"Critical","severity_reason":"x"}"#;
        assert!(serde_json::from_str::<EmitSeverityArgs>(s).is_err());
    }

    #[test]
    fn severity_tier_to_finding_severity() {
        for (st, want) in [
            (SeverityTier::High, FindingSeverity::High),
            (SeverityTier::Medium, FindingSeverity::Medium),
            (SeverityTier::Low, FindingSeverity::Low),
        ] {
            let s: FindingSeverity = st.into();
            assert_eq!(s, want);
        }
    }
}
