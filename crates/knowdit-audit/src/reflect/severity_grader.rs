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

use std::sync::Arc;

use color_eyre::eyre::{Result, WrapErr};
use knowdit_kg_model::audit_finding::FindingSeverity;
use knowdit_repo_model::RepoDatabase;
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
    options: GraderOptions,
}

impl SeverityGrader {
    /// Build a severity grader. Loads the project graphs once.
    pub async fn new(repo: &RepoDatabase, llm: &LLM, options: GraderOptions) -> Result<Self> {
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
            options,
        })
    }

    /// Build a severity grader sharing the verdict grader's already-
    /// loaded `ProjectIndex`. Saves a redundant call_graph +
    /// storage_graph load when both graders run in the same CLI
    /// invocation (the typical case).
    pub fn new_with_index(
        llm: &LLM,
        project_index: Arc<ProjectIndex>,
        options: GraderOptions,
    ) -> Self {
        Self {
            llm: llm.clone(),
            project_index,
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
        let tools = build_severity_toolbox(&self.project_index, &attempt);
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

// ---------------------------------------------------------------------------
// System prompt
// ---------------------------------------------------------------------------

const SEVERITY_SYSTEM: &str = r#"You are the Severity Grader — a multi-turn auditor that decides the severity tier (High / Medium / Low) of one ValidFinding.

A separate verdict-grader agent has already classified this harness_run as a real bug and produced a `verdict_reason`. Your job is the dedicated severity argument, not to re-litigate whether the bug exists.

You will be given a JSON document with the same per-run context the verdict grader saw, plus:
- `verdict_reason`: Phase 1's argument for why this is a ValidFinding (use this as anchor; build on it)

You have project-source inspection tools — USE them; severity claims must be grounded in actual contract state, not in handwaving:

- `lookup_call_graph(contract, function?)` — verify a contract/function exists and look at its edges
- `lookup_state_variable_xrefs(state_variable)` — find the contracts and functions that read or write a given state variable; this is THE primary tool for identifying "what is liquidity in this project"
- `read_contract_source(contract)` — full source of one contract
- `read_function_source(contract, function)` — focused source for one function
- `emit_severity(severity, severity_reason)` — finalize the agent run

# Severity tiers

## High — full liquidity drain (strict)

Methodology (REQUIRED for High):
1. **Identify liquidity state variables.** From the harness's affected contracts (the ones in the counter-example) and from the spec, list which state variables represent the project's *moveable economic value*. Typical candidates by name pattern (but VERIFY each via `lookup_state_variable_xrefs` to confirm it's actually money-bearing):
    - pool/vault balances: `s_balance`, `totalAssets`, `s_assets`, `s_collateral`, `s_lockedAssets`
    - share/supply totals: `totalSupply`, `s_shares`, `s_creditedShares`
    - reserve / floor: `reserves`, `s_reserve0`, `s_reserve1`
    - per-user accounting that the protocol is solvent against: `s_balanceOf[]`, `s_userAssets`, etc.
2. **Argue full drain.** Read the violating function source via `read_function_source`. From the counter-example trace + the function body, argue that ALL of the identified liquidity state variables for the affected contract end up at 0 (or attacker-owned) at the end of the trace, with no recovery path / no access control gate the spec did not already account for.
3. **No partial drain or "would-drain-given-more-iterations" qualifies as High.** If the trace only shows a leak proportional to inputs, or requires a privileged actor, OR only impacts a subset of liquidity, downgrade to Medium.

If you cannot list at least one concrete liquidity state variable AND argue its full drain from the trace, do NOT emit High. Downgrade.

## Medium — partial loss / DOS / griefing / privileged-actor exploitation

Methodology:
- Same lookup discipline as High: identify the AFFECTED function and the AFFECTED state variable explicitly. Generic "the protocol can be griefed" without naming a function and a state variable is rejected.
- Examples that fit Medium:
    - small recoverable accounting drift (e.g. rounding leaks $X per call)
    - DOS that requires a specific privileged role (admin, owner, guardian)
    - griefing: attacker burns gas / blocks operations without taking value
    - exploitable only in a narrow window (e.g. specific oracle state)
- If the trace does demonstrate partial value loss but no specific function / state variable can be cited, that's a sign the verdict itself is shaky — but you still pick the best fitting tier here. (You can't downgrade the verdict; only severity is yours to decide.)

## Low — informational / non-exploitable in practice / minor edge cases

Methodology:
- Use this tier for everything that isn't a concrete loss event: protocol-economics edge cases, theoretically exploitable but blocked by external invariants, informational findings (events emitted incorrectly, off-by-one in non-monetary state, etc.).
- Cite the function + state involved, but the rationale should also explain WHY it's not exploitable in practice (gas economics make it unprofitable, oracle staleness blocks it, etc.).

# Hard rules

- Call `emit_severity` EXACTLY once.
- `severity` must be `High` | `Medium` | `Low`. Serde rejects unknowns.
- `severity_reason` must:
    - For High: name at least one concrete liquidity state variable AND argue the trace fully drains it via the violating function.
    - For Medium: name the affected function AND the affected state variable.
    - For Low: name the involved function/state AND the reason it isn't exploitable in practice.
- DO NOT re-argue whether this is a ValidFinding. The verdict grader already did. If you genuinely think it isn't a bug at all → still pick Low and explain in the rationale (the verdict grader gets the final say on classification).
- Use the lookup tools. A severity reason that doesn't reflect the actual project state variables (i.e. that any LLM could have written without ever reading source) is unacceptable.

# Workflow tips

- Start by scanning `verdict_reason` for the function name(s) it cites. `read_function_source` on those.
- Inside the function source, look for any `state_var = 0`, `state_var -= …`, transfer-out calls, or write paths that would drain a balance. Note the state vars they touch.
- For each candidate state var, `lookup_state_variable_xrefs` to see which functions write it. Are the ones the harness called the only write path? Are there mitigating writes elsewhere that would refill it?
- Only after you have at least one liquidity state variable concretely identified do you commit to High. Otherwise Medium.
- For Medium / Low you can be lighter on tool usage, but still need to name a specific function + state variable.
"#;

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
