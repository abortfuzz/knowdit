//! Phase 1 of reflection: the **verdict grader** agent.
//!
//! Classifies one violated `harness_run` into one of five
//! [`ReflectionResult`] verdicts. Severity (when verdict is
//! `ValidFinding`) is decided by a separate
//! [`super::severity_grader::SeverityGrader`] in Phase 2 — this
//! agent's `EmitVerdictTool` deliberately does NOT carry a severity
//! field.
//!
//! Verdict order in the system prompt is set by check cost: cheap
//! lookups first (`IncompleteSpecification` from a missing contract),
//! deeper reads last (`ValidFinding` requires reading the violating
//! function source).
//!
//! Both `VerdictGrader` and `SeverityGrader` share the project
//! lookup tools (`lookup_call_graph` / `lookup_state_variable_xrefs` /
//! `read_contract_source` / `read_function_source`) loaded out of
//! `crate::spec`; the shared agent-loop driver lives in
//! [`super::agent_loop`].

use std::sync::Arc;

use color_eyre::eyre::{Result, WrapErr};
use knowdit_repo_model::{ReflectionResult, RepoDatabase};
use llmy::agent::tool::ToolBox;
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

/// Single per-`harness_run` grading task. All fields owned so the
/// input crosses async boundaries by clone — no lifetime params on
/// this struct or on [`VerdictGrader::grade`].
#[derive(Debug, Clone, Serialize)]
pub struct VerdictInput {
    pub run_id: i32,
    pub spec_id: i32,
    pub spec: AuditSpecification,
    pub harness_source: String,
    pub finding_title: Option<String>,
    pub run: RunSummary,
    pub coverage_summary: Option<CoverageSummary>,
    /// Number of ancestor reflections in this code_gen's regen
    /// lineage already classified `IncompleteStep`. Drives the
    /// "two strikes → escalate to IncompleteSpecification" rule.
    pub prior_incomplete_step_count: u32,
}

/// Verdict captured by [`EmitVerdictTool`]. The 5-class
/// [`GraderVerdict`] excludes `Suspect` at the type level (`Suspect`
/// is reserved for inline gates).
#[derive(Debug, Clone)]
pub struct VerdictOutput {
    pub result: ReflectionResult,
    pub reason: String,
    pub steps: usize,
}

/// The verdict grader agent. Owns its `LLM` clone (cheap), the
/// `ProjectIndex` (Arc-shared with the agent's tools), and the
/// per-CLI-invocation [`GraderOptions`]. Built once via [`Self::new`]
/// and reused across every harness_run graded — the project index is
/// loaded once, not per call.
pub struct VerdictGrader {
    llm: LLM,
    project_index: Arc<ProjectIndex>,
    options: GraderOptions,
}

impl VerdictGrader {
    /// Build a grader. Loads the project call graph + storage graph
    /// once; subsequent [`Self::grade`] calls are pure compute over
    /// already-resident state.
    pub async fn new(repo: &RepoDatabase, llm: &LLM, options: GraderOptions) -> Result<Self> {
        let call_graph = repo
            .load_call_graph()
            .await
            .wrap_err("verdict grader: failed to load project call graph")?;
        let storage_graph = repo
            .load_storage_graph()
            .await
            .wrap_err("verdict grader: failed to load project storage graph")?;
        let inheritance_graph = repo
            .load_inheritance_graph()
            .await
            .wrap_err("verdict grader: failed to load project inheritance graph")?;
        let project_index = Arc::new(ProjectIndex::build(
            call_graph,
            storage_graph,
            inheritance_graph,
        ));
        Ok(Self {
            llm: llm.clone(),
            project_index,
            options,
        })
    }

    /// Skip the project-index reload when the caller already has one
    /// (e.g. the severity grader loads its own index from the same
    /// repo). Used by [`super::severity_grader::SeverityGrader::new_with_index`].
    pub fn project_index(&self) -> &Arc<ProjectIndex> {
        &self.project_index
    }

    /// Grade one violated `harness_run`. Returns `Err` only on
    /// agent / tool wiring failures or when the agent exhausts its
    /// step budget without emitting a verdict — the caller MUST NOT
    /// persist a row in those cases (resume safety: re-running picks
    /// the run back up and llmy cache reuses prior agent steps).
    pub async fn grade(&self, input: &VerdictInput) -> Result<VerdictOutput> {
        let attempt: AttemptHandle<RawVerdict> = AttemptHandle::new();
        let tools = build_verdict_toolbox(&self.project_index, &attempt);
        let user_prompt = serde_json::to_string_pretty(input)
            .wrap_err("verdict grader: failed to serialize VerdictInput")?;
        let cache_suffix = format!("verdict-r{:06}-s{:06}", input.run_id, input.spec_id);
        let steps = drive_agent_loop(
            &self.project_index,
            &self.llm,
            &self.options,
            VERDICT_SYSTEM.to_string(),
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
        Ok(VerdictOutput {
            result: raw.classification.into(),
            reason: raw.rationale,
            steps,
        })
    }
}

fn build_verdict_toolbox(
    project_index: &Arc<ProjectIndex>,
    attempt: &AttemptHandle<RawVerdict>,
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
    tools.add_tool(EmitVerdictTool {
        attempt: attempt.clone(),
    });
    tools
}

// ---------------------------------------------------------------------------
// emit_verdict tool
// ---------------------------------------------------------------------------

/// 5-class verdict the agent is allowed to emit. Defined locally
/// (instead of reusing the 6-variant [`ReflectionResult`]) so the
/// agent can't emit `Suspect` — that's reserved for inline gates.
/// serde + JsonSchema do all the parsing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
pub enum GraderVerdict {
    ValidFinding,
    ExpectedViolation,
    OutOfScope,
    IncompleteStep,
    IncompleteSpecification,
}

impl From<GraderVerdict> for ReflectionResult {
    fn from(v: GraderVerdict) -> Self {
        match v {
            GraderVerdict::ValidFinding => Self::ValidFinding,
            GraderVerdict::ExpectedViolation => Self::ExpectedViolation,
            GraderVerdict::OutOfScope => Self::OutOfScope,
            GraderVerdict::IncompleteStep => Self::IncompleteStep,
            GraderVerdict::IncompleteSpecification => Self::IncompleteSpecification,
        }
    }
}

#[derive(Debug, Clone)]
struct RawVerdict {
    classification: GraderVerdict,
    rationale: String,
}

#[derive(Debug, Clone, Deserialize, JsonSchema)]
struct EmitVerdictArgs {
    /// The 5-class verdict. The agent must pick exactly one.
    classification: GraderVerdict,
    /// Concrete one-paragraph reason. Must cite specific function /
    /// contract names from the counter-example or `spec.sequence`
    /// (the system prompt rejects vague rationales).
    rationale: String,
}

#[derive(Debug, Clone)]
#[llmy::agent::tool(
    arguments = EmitVerdictArgs,
    invoke = invoke,
    description = "Commit the final 5-class classification for this harness_run and end the agent run. Call EXACTLY once, AFTER gathering enough evidence via the lookup_call_graph / lookup_state_variable_xrefs / read_contract_source / read_function_source tools. Severity (for ValidFinding) is decided by a separate downstream agent — do NOT include it here.",
    name = "emit_verdict",
)]
struct EmitVerdictTool {
    attempt: AttemptHandle<RawVerdict>,
}

impl EmitVerdictTool {
    async fn invoke(
        &self,
        args: EmitVerdictArgs,
    ) -> std::result::Result<String, llmy::agent::LLMYError> {
        if args.rationale.trim().is_empty() {
            return Ok("error: rationale must be non-empty".to_string());
        }
        match self
            .attempt
            .try_set(RawVerdict {
                classification: args.classification,
                rationale: args.rationale,
            })
            .await
        {
            Ok(()) => Ok("ok: verdict committed; the runtime will end the agent now".to_string()),
            Err(_) => Ok("error: emit_verdict already called for this run".to_string()),
        }
    }
}

// ---------------------------------------------------------------------------
// System prompt
// ---------------------------------------------------------------------------

/// Methodology-rich system prompt. Ordered so the cheapest-to-confirm
/// verdict (`IncompleteSpecification`) is checked first, saving agent
/// steps on the common "spec references nonexistent contract" case.
const VERDICT_SYSTEM: &str = r#"You are the Reflector verdict agent — a multi-turn code auditor that classifies one violated harness_run against the project under audit.

You will be given a JSON document with:
- `run_id`, `spec_id`: row identifiers for tracing
- `spec`: the AuditSpecification this harness was supposed to validate (setup contracts/state, pre_attack/post_attack states, ordered call sequence)
- `harness_source`: the .sol file the fuzz agent committed
- `finding_title`: optional historical-finding label that motivated the spec
- `run`: this single harness_run's digest (kind, exit_code, violated, stdout_tail, decoded counter-example)
- `coverage_summary`: hit/expected count of spec.sequence functions and missed-step labels (when a coverage run was issued for this code_gen)
- `prior_incomplete_step_count`: how many ancestor reflections in this code_gen's regen lineage are already `IncompleteStep`

You have inspection tools to verify against the actual project source — USE them; do NOT classify from harness_source / spec text alone:

- `lookup_call_graph(contract, function?)` — confirm a contract/function exists; see incoming/outgoing edges
- `lookup_state_variable_xrefs(state_variable)` — find readers/writers of a state var
- `read_contract_source(contract)` — full source of one contract
- `read_function_source(contract, function)` — focused source for one function
- `emit_verdict(classification, rationale)` — finalize the agent run

# Verdicts (evaluate in this order; first match wins)

## 1. IncompleteSpecification — verify FIRST, cheap to confirm

Methodology:
- For each name in `spec.setup.contracts`: call `lookup_call_graph(name)`. If ANY response is "no contract or interface named `X` found", classify `IncompleteSpecification`.
- For each entry in `spec.sequence`: call `lookup_call_graph(contract, function)`. If the function isn't on the named contract OR isn't on any contract in the project, classify `IncompleteSpecification`.
- If `prior_incomplete_step_count >= 2`: the codegen has tried at least twice to reach this spec and failed. Spec is at fault — escalate to `IncompleteSpecification` regardless of other signals.

## 2. IncompleteStep

Methodology:
- The counter-example's `(contract_name, func_name)` set has NO overlap with `spec.sequence` — the harness fired a violation in some other path → `IncompleteStep`.
- `coverage_summary.missed_step_labels` lists spec.sequence functions: `read_function_source` on those — if their bodies show the path was avoidable from the harness's setUp, classify `IncompleteStep`.
- `run.stdout_tail` mentions reverts on access-control / preconditions / paused state that the spec did NOT instruct the harness to satisfy → `IncompleteStep`.

## 3. OutOfScope

Methodology:
- For each `contract_name` in counter-example: call `lookup_call_graph`. If a name fails to resolve, that contract is locally defined inside `harness_source` — scaffolding (Mock*, Stub*, Fake*, Handler*, custom test contract).
- If the violation chain is dominated by such scaffolding (no project contracts in counter-example or coverage hit functions), classify `OutOfScope`.
- `read_contract_source` on a counter-example contract: a "no contract found" response confirms scaffolding.
- The violation's failing assertion is on harness-authored test-only state, not on project state → `OutOfScope`.

## 4. ExpectedViolation

Methodology:
- The spec's `post_attack` state matches what the violation actually demonstrates — the spec was a "validate this attack reaches state X" demonstration and the violation IS state X.
- `read_function_source` on the spec.sequence functions; verify the executed path produces `spec.post_attack` exactly.
- The harness's invariant body asserts the negation of `spec.post_attack` and that's what failed — this is the spec being satisfied, not a bug.

## 5. ValidFinding

Methodology:
- Counter-example's `(contract_name, func_name)` set CONTAINS at least one project contract (verify with `lookup_call_graph`).
- `read_function_source` on the violating function — the path produces a state change that exceeds `spec.post_attack` (overflow, access-control bypass, accounting mismatch, reentrancy, mass slashing, etc.) and is attributable to a real bug, not a misuse the harness fabricated.
- The bug would still trigger if invoked from a normal external caller with the same calldata (i.e. it's not gated by the harness's scaffolding).

(Severity tier — High / Medium / Low — is decided by a SEPARATE downstream agent. Do not include it here.)

# Hard rules

- Call `emit_verdict` EXACTLY once. It ends your run.
- `classification` must be one of the five `GraderVerdict` variants. Serde rejects unknown strings.
- `rationale` must cite specific function or contract names from the counter-example or spec.sequence (e.g. `"PanopticPool.dispatch reverts on s_paused; spec.setup did not unpause"`). Vague phrasing is rejected by reviewers.
- Treat any contract authored INSIDE `harness_source` (Mock*, Stub*, Fake*, Vulnerable*, Handler*, Test*) as untrusted scaffolding. `ValidFinding` requires the violation chain to traverse contracts found in the project's call graph.
- If your other evidence still points to `IncompleteStep` BUT `prior_incomplete_step_count >= 2`, escalate to `IncompleteSpecification`.
- Translate older 4-class verdicts: `valid_vuln` → `ValidFinding`; `expected_revert` → `ExpectedViolation`; `incomplete_attacking_scenario` → `IncompleteStep` (or `IncompleteSpecification` if spec is at fault); `invalid_vuln` → `OutOfScope`.

# Workflow tips

- Burn cheap calls first: `lookup_call_graph` on every name in `spec.setup.contracts` and `spec.sequence`. This usually settles `IncompleteSpecification` immediately.
- Then `lookup_call_graph` on every `contract_name` in the counter-example. Names that fail to resolve = scaffolding = `OutOfScope` evidence.
- Only fall into `read_function_source` when choosing between `IncompleteStep` / `ExpectedViolation` / `ValidFinding`.
- Don't dump every contract you can think of; the agent step budget is finite.
"#;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn emit_verdict_args_typed_enum() {
        let s = r#"{"classification":"ValidFinding","rationale":"x"}"#;
        let args: EmitVerdictArgs = serde_json::from_str(s).unwrap();
        assert_eq!(args.classification, GraderVerdict::ValidFinding);
    }

    #[test]
    fn emit_verdict_args_unknown_classification_rejected() {
        let s = r#"{"classification":"valid_vuln","rationale":"x"}"#;
        assert!(serde_json::from_str::<EmitVerdictArgs>(s).is_err());
    }

    #[test]
    fn grader_verdict_to_reflection_result() {
        for (gv, want) in [
            (GraderVerdict::ValidFinding, ReflectionResult::ValidFinding),
            (
                GraderVerdict::ExpectedViolation,
                ReflectionResult::ExpectedViolation,
            ),
            (GraderVerdict::OutOfScope, ReflectionResult::OutOfScope),
            (
                GraderVerdict::IncompleteStep,
                ReflectionResult::IncompleteStep,
            ),
            (
                GraderVerdict::IncompleteSpecification,
                ReflectionResult::IncompleteSpecification,
            ),
        ] {
            let r: ReflectionResult = gv.into();
            assert_eq!(r, want);
        }
    }
}
