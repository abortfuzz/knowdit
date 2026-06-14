//! Spec-builder agent tools + the draft state they mutate.
//!
//!
//! Split out of `spec/mod.rs`: the `#[llmy::agent::tool]` structs, the
//! shared `SpecDraft` they build up, and the commit-time `post_attack`
//! shape gate. `build_tool_box` assembles the full set so each tool's
//! fields stay private to this module — only `LinkInput::run` (in
//! `agent.rs`) needs the resulting `ToolBox` plus the `DraftHandle` to
//! read the committed result back out.

use std::collections::BTreeMap;
use std::sync::Arc;

use schemars::JsonSchema;
use serde::Deserialize;
use tokio::sync::Mutex;

use llmy::agent::tool::ToolBox;

use knowdit_repo_model::storage::FunctionStateVariable;

use crate::types::{
    AuditSpecification, AuditStateSpecification, AuxStateVariable, AuxiliaryContract,
    SuqenceCallStep,
};

use super::{LinkSpecStatus, ProjectIndex};

// ---------------------------------------------------------------------------
// Spec draft + tools
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default)]
pub struct SpecDraft {
    pub setup: AuditStateSpecification,
    pub pre_attack: AuditStateSpecification,
    pub post_attack: AuditStateSpecification,
    pub sequence: Vec<SuqenceCallStep>,
    /// Auxiliary contracts the PoC must deploy itself, declared via
    /// `add_aux_contract` / `add_aux_contract_state`. Carried into the
    /// committed spec; cleared on `reset_draft`.
    pub auxiliary_contracts: BTreeMap<String, AuxiliaryContract>,
    /// Specs that have been committed already.
    pub completed: Vec<AuditSpecification>,
    /// Set on `finalize`. Until then the agent loop keeps spinning.
    pub final_status: Option<LinkSpecStatus>,
    pub abort_reason: Option<String>,
    pub final_summary: Option<String>,
}

impl SpecDraft {
    fn reset_draft(&mut self) {
        self.setup = AuditStateSpecification::default();
        self.pre_attack = AuditStateSpecification::default();
        self.post_attack = AuditStateSpecification::default();
        self.sequence.clear();
        self.auxiliary_contracts.clear();
    }

    fn build_spec(&self, summary: String) -> AuditSpecification {
        AuditSpecification {
            summary,
            setup: self.setup.clone(),
            pre_attack: self.pre_attack.clone(),
            post_attack: self.post_attack.clone(),
            sequence: self.sequence.clone(),
            auxiliary_contracts: self.auxiliary_contracts.clone(),
        }
    }

    /// Case-insensitive lookup of a declared auxiliary contract.
    fn find_aux_contract(&self, name: &str) -> Option<&AuxiliaryContract> {
        let needle = name.trim().to_lowercase();
        self.auxiliary_contracts
            .iter()
            .find(|(k, _)| k.to_lowercase() == needle)
            .map(|(_, v)| v)
    }

    /// The stored (original-case) key of a declared auxiliary contract,
    /// matched case-insensitively.
    fn aux_contract_key(&self, name: &str) -> Option<String> {
        let needle = name.trim().to_lowercase();
        self.auxiliary_contracts
            .keys()
            .find(|k| k.to_lowercase() == needle)
            .cloned()
    }

    /// True when `key` is a `Contract.field` reference to a state
    /// variable declared on an already-registered auxiliary contract.
    fn aux_has_state_variable(&self, key: &str) -> bool {
        match key.trim().split_once('.') {
            Some((contract, field)) => self
                .find_aux_contract(contract)
                .map(|aux| aux.state_variables.contains_key(field.trim()))
                .unwrap_or(false),
            None => false,
        }
    }

    fn draft_summary(&self) -> String {
        format!(
            "setup{{desc={} sv={} contracts={}}} pre{{desc={} sv={} contracts={}}} post{{desc={} sv={} contracts={}}} sequence={}",
            !self.setup.description.is_empty() as u8,
            self.setup.states_variables.len(),
            self.setup.contracts.len(),
            !self.pre_attack.description.is_empty() as u8,
            self.pre_attack.states_variables.len(),
            self.pre_attack.contracts.len(),
            !self.post_attack.description.is_empty() as u8,
            self.post_attack.states_variables.len(),
            self.post_attack.contracts.len(),
            self.sequence.len(),
        )
    }
}

#[derive(Clone)]
pub struct DraftHandle(pub Arc<Mutex<SpecDraft>>);

impl std::fmt::Debug for DraftHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DraftHandle").finish_non_exhaustive()
    }
}

impl DraftHandle {
    pub fn new() -> Self {
        Self(Arc::new(Mutex::new(SpecDraft::default())))
    }

    pub async fn snapshot(&self) -> SpecDraft {
        self.0.lock().await.clone()
    }

    /// Assemble the spec-builder agent's full tool box over this draft.
    /// Keeps each tool's fields private to this module; the caller only
    /// gets the `ToolBox` and keeps this `DraftHandle` to read the
    /// committed specs back.
    pub fn build_tool_box(
        &self,
        project_index: &Arc<ProjectIndex>,
        max_specs_per_link: usize,
    ) -> ToolBox {
        let mut tools = ToolBox::new();
        tools.add_tool(UpdateStateDescriptionTool {
            draft: self.clone(),
        });
        tools.add_tool(AddStateVariableConstraintTool {
            draft: self.clone(),
            project: project_index.clone(),
        });
        tools.add_tool(AddContractConstraintTool {
            draft: self.clone(),
            project: project_index.clone(),
        });
        tools.add_tool(SetCallSequenceTool {
            draft: self.clone(),
            project: project_index.clone(),
        });
        tools.add_tool(AddAuxContractTool {
            draft: self.clone(),
            project: project_index.clone(),
        });
        tools.add_tool(AddAuxContractStateTool {
            draft: self.clone(),
        });
        tools.add_tool(CommitSpecificationTool {
            draft: self.clone(),
            max_specs: max_specs_per_link,
        });
        tools.add_tool(FinalizeTool {
            draft: self.clone(),
        });
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
        tools
    }
}

#[derive(Debug, Clone, Copy, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
enum SpecStage {
    Setup,
    PreAttack,
    PostAttack,
}

impl SpecStage {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Setup => "setup",
            Self::PreAttack => "pre_attack",
            Self::PostAttack => "post_attack",
        }
    }
}

fn stage_field_mut(draft: &mut SpecDraft, stage: SpecStage) -> &mut AuditStateSpecification {
    match stage {
        SpecStage::Setup => &mut draft.setup,
        SpecStage::PreAttack => &mut draft.pre_attack,
        SpecStage::PostAttack => &mut draft.post_attack,
    }
}

// ---- update_state_description ----

#[derive(Debug, Clone, Deserialize, JsonSchema)]
struct UpdateStateDescriptionArgs {
    /// One of `setup`, `pre_attack`, `post_attack`.
    stage: SpecStage,
    /// Free-form description of the general business logic governing this stage.
    description: String,
}

#[derive(Debug, Clone)]
#[llmy::agent::tool(
    arguments = UpdateStateDescriptionArgs,
    invoke = invoke,
    name = "update_state_description",
    description = "Set or replace the general-business-logic description of one stage of the current spec draft (setup / pre_attack / post_attack). Each stage holds exactly one description string. For stage=post_attack, describe how the attacked state violates a project expectation and the concrete bad consequence (drain / loss / DoS / bypass); the actual proof of the vulnerability goes into post_attack's state-variable / contract invariants, which commit_specification requires.",
)]
struct UpdateStateDescriptionTool {
    draft: DraftHandle,
}

impl UpdateStateDescriptionTool {
    async fn invoke(
        &self,
        args: UpdateStateDescriptionArgs,
    ) -> std::result::Result<String, llmy::agent::LLMYError> {
        let mut guard = self.draft.0.lock().await;
        let stage_label = args.stage.as_str();
        let field = stage_field_mut(&mut guard, args.stage);
        field.description = args.description.trim().to_string();
        Ok(format!(
            "ok: updated {stage_label} description ({} chars). Draft: {}",
            field.description.len(),
            guard.draft_summary()
        ))
    }
}

// ---- add_state_variable_constraint ----

#[derive(Debug, Clone, Deserialize, JsonSchema)]
struct AddStateVariableConstraintArgs {
    stage: SpecStage,
    /// Identifier for the state variable. Prefer `Contract.fieldName` form
    /// when the same name lives on multiple contracts. For a variable on
    /// an auxiliary contract you must use the `AuxContract.fieldName` form,
    /// and that contract + field must already be declared with
    /// `add_aux_contract` / `add_aux_contract_state`.
    key: String,
    /// Constraint text: either a value, an invariant, or "must be initialized".
    constraint: String,
}

#[derive(Debug, Clone)]
#[llmy::agent::tool(
    arguments = AddStateVariableConstraintArgs,
    invoke = invoke,
    name = "add_state_variable_constraint",
    description = "Insert or overwrite one state-variable constraint on the current draft's stage. The key must be a real project state variable (bare name, or `Contract.fieldName` to disambiguate) OR a `AuxContract.fieldName` declared via add_aux_contract_state. Unknown identifiers are rejected and nothing is added.",
)]
struct AddStateVariableConstraintTool {
    draft: DraftHandle,
    project: Arc<ProjectIndex>,
}

impl AddStateVariableConstraintTool {
    async fn invoke(
        &self,
        args: AddStateVariableConstraintArgs,
    ) -> std::result::Result<String, llmy::agent::LLMYError> {
        let key = args.key.trim().to_string();
        let mut guard = self.draft.0.lock().await;
        if !guard.aux_has_state_variable(&key) && !self.project.has_state_variable(&key) {
            return Ok(format!(
                "error: `{key}` is not a project state variable and not a declared auxiliary-contract field. \
                 Look it up with lookup_state_variable_xrefs (use `Contract.fieldName` to disambiguate), \
                 or, if it belongs to a helper contract the PoC deploys, declare it first with \
                 add_aux_contract + add_aux_contract_state and reference it as `AuxContract.fieldName`. \
                 Draft unchanged — fix the name and retry."
            ));
        }
        let stage_label = args.stage.as_str();
        let field = stage_field_mut(&mut guard, args.stage);
        field
            .states_variables
            .insert(key, args.constraint.trim().to_string());
        Ok(format!(
            "ok: {stage_label} state-variable constraints now {}. Draft: {}",
            field.states_variables.len(),
            guard.draft_summary()
        ))
    }
}

// ---- add_contract_constraint ----

#[derive(Debug, Clone, Deserialize, JsonSchema)]
struct AddContractConstraintArgs {
    stage: SpecStage,
    /// Contract name. Must be a real project contract/interface, or an
    /// auxiliary contract already declared with `add_aux_contract`.
    contract: String,
    /// Constraint text: e.g. "must be deployed and own >0 of TokenA", "admin
    /// is the test EOA".
    constraint: String,
}

#[derive(Debug, Clone)]
#[llmy::agent::tool(
    arguments = AddContractConstraintArgs,
    invoke = invoke,
    name = "add_contract_constraint",
    description = "Insert or overwrite one contract-level constraint on the current draft's stage (e.g. deployment, role assignment). The contract must be a real project contract/interface OR an auxiliary contract declared via add_aux_contract. Unknown names are rejected and nothing is added.",
)]
struct AddContractConstraintTool {
    draft: DraftHandle,
    project: Arc<ProjectIndex>,
}

impl AddContractConstraintTool {
    async fn invoke(
        &self,
        args: AddContractConstraintArgs,
    ) -> std::result::Result<String, llmy::agent::LLMYError> {
        let contract = args.contract.trim().to_string();
        let mut guard = self.draft.0.lock().await;
        if !self.project.has_contract(&contract) && guard.find_aux_contract(&contract).is_none() {
            return Ok(format!(
                "error: `{contract}` is not a project contract/interface and not a declared auxiliary contract. \
                 Use a real project name (check with lookup_call_graph), or, if the PoC deploys it, \
                 declare it first with add_aux_contract. Draft unchanged — fix the name and retry."
            ));
        }
        let stage_label = args.stage.as_str();
        let field = stage_field_mut(&mut guard, args.stage);
        field
            .contracts
            .insert(contract, args.constraint.trim().to_string());
        Ok(format!(
            "ok: {stage_label} contract constraints now {}. Draft: {}",
            field.contracts.len(),
            guard.draft_summary()
        ))
    }
}

// ---- set_call_sequence ----

#[derive(Debug, Clone, Deserialize, JsonSchema)]
struct CallStepArg {
    /// Contract whose function is being called.
    contract: String,
    /// Function name (no parameter list).
    function: String,
    /// One-sentence intention of the call in this scenario.
    intention: String,
}

#[derive(Debug, Clone, Deserialize, JsonSchema)]
struct SetCallSequenceArgs {
    /// Replaces the entire call sequence on the current draft.
    steps: Vec<CallStepArg>,
}

#[derive(Debug, Clone)]
#[llmy::agent::tool(
    arguments = SetCallSequenceArgs,
    invoke = invoke,
    name = "set_call_sequence",
    description = "Replace the current draft's core call sequence with the provided ordered list of (contract, function, intention) steps. Every step's contract must be a real project contract/interface (its function is grounded) OR an auxiliary contract declared via add_aux_contract. If any step references an unknown contract or function the whole call is rejected and the existing sequence is left unchanged.",
)]
struct SetCallSequenceTool {
    draft: DraftHandle,
    project: Arc<ProjectIndex>,
}

impl SetCallSequenceTool {
    async fn invoke(
        &self,
        args: SetCallSequenceArgs,
    ) -> std::result::Result<String, llmy::agent::LLMYError> {
        if args.steps.is_empty() {
            return Ok("error: refusing to set an empty call sequence; commit_specification needs at least one core call".to_string());
        }
        let mut guard = self.draft.0.lock().await;
        // Validate every step before mutating anything.
        let mut problems: Vec<String> = Vec::new();
        for (i, step) in args.steps.iter().enumerate() {
            let contract = step.contract.trim();
            let function = step.function.trim();
            if guard.find_aux_contract(contract).is_some() {
                // Auxiliary contract: its functions are synthesized by the
                // harness, so accept any function name.
                continue;
            }
            if !self.project.has_contract(contract) {
                problems.push(format!(
                    "step {}: contract `{contract}` is not a project contract/interface and not a declared auxiliary contract",
                    i + 1
                ));
            } else if !self.project.contract_has_function(contract, function) {
                problems.push(format!(
                    "step {}: `{contract}` has no function `{function}` (own or inherited)",
                    i + 1
                ));
            }
        }
        if !problems.is_empty() {
            return Ok(format!(
                "error: call sequence rejected, existing sequence unchanged. \
                 Fix these and resend the full sequence:\n- {}\n\
                 Verify names with lookup_call_graph, or declare helper contracts with add_aux_contract first.",
                problems.join("\n- ")
            ));
        }
        guard.sequence = args
            .steps
            .into_iter()
            .map(|step| SuqenceCallStep {
                contract: step.contract.trim().to_string(),
                function: step.function.trim().to_string(),
                intention: step.intention.trim().to_string(),
            })
            .collect();
        Ok(format!(
            "ok: call sequence now {} step(s). Draft: {}",
            guard.sequence.len(),
            guard.draft_summary()
        ))
    }
}

// ---- add_aux_contract ----

#[derive(Debug, Clone, Deserialize, JsonSchema)]
struct AddAuxContractArgs {
    /// Name for the auxiliary contract the PoC will deploy (you choose it).
    /// Must NOT collide with a real project contract/interface.
    name: String,
    /// Why this contract exists in the attack, e.g. "reentrancy attacker that
    /// re-enters withdraw on receive()".
    purpose: String,
}

#[derive(Debug, Clone)]
#[llmy::agent::tool(
    arguments = AddAuxContractArgs,
    invoke = invoke,
    name = "add_aux_contract",
    description = "Declare a helper contract the PoC must deploy itself (attacker contract, malicious callback, mock token) that does NOT exist in the project source. Required before you can reference it (or its state) in constraints or the call sequence. The name must not collide with a real project contract/interface.",
)]
struct AddAuxContractTool {
    draft: DraftHandle,
    project: Arc<ProjectIndex>,
}

impl AddAuxContractTool {
    async fn invoke(
        &self,
        args: AddAuxContractArgs,
    ) -> std::result::Result<String, llmy::agent::LLMYError> {
        let name = args.name.trim().to_string();
        if name.is_empty() {
            return Ok("error: auxiliary contract name is empty. Draft unchanged.".to_string());
        }
        if self.project.has_contract(&name) {
            return Ok(format!(
                "error: `{name}` is a real project contract/interface — don't redeclare it as auxiliary. \
                 Reference it directly, or pick a different name for your helper contract. Draft unchanged."
            ));
        }
        let mut guard = self.draft.0.lock().await;
        let entry = guard.auxiliary_contracts.entry(name.clone()).or_default();
        entry.purpose = args.purpose.trim().to_string();
        Ok(format!(
            "ok: auxiliary contract `{name}` declared ({} total). Add its state with add_aux_contract_state.",
            guard.auxiliary_contracts.len()
        ))
    }
}

// ---- add_aux_contract_state ----

#[derive(Debug, Clone, Deserialize, JsonSchema)]
struct AddAuxContractStateArgs {
    /// Name of an auxiliary contract already declared with add_aux_contract.
    contract: String,
    /// State variable name on that auxiliary contract.
    name: String,
    /// Solidity type, e.g. `uint256`, `address`, `mapping(address => uint256)`.
    solidity_type: String,
    /// What this variable is for in the attack scenario.
    purpose: String,
}

#[derive(Debug, Clone)]
#[llmy::agent::tool(
    arguments = AddAuxContractStateArgs,
    invoke = invoke,
    name = "add_aux_contract_state",
    description = "Declare one state variable (name + Solidity type + purpose) on an auxiliary contract previously declared with add_aux_contract. Reference it later as `AuxContract.fieldName`. Fails if the auxiliary contract was not declared first.",
)]
struct AddAuxContractStateTool {
    draft: DraftHandle,
}

impl AddAuxContractStateTool {
    async fn invoke(
        &self,
        args: AddAuxContractStateArgs,
    ) -> std::result::Result<String, llmy::agent::LLMYError> {
        let var_name = args.name.trim().to_string();
        let solidity_type = args.solidity_type.trim().to_string();
        if var_name.is_empty() || solidity_type.is_empty() {
            return Ok(
                "error: state variable name and solidity_type are both required. Draft unchanged."
                    .to_string(),
            );
        }
        let mut guard = self.draft.0.lock().await;
        let Some(key) = guard.aux_contract_key(&args.contract) else {
            return Ok(format!(
                "error: auxiliary contract `{}` is not declared yet; call add_aux_contract first. Draft unchanged.",
                args.contract.trim()
            ));
        };
        let aux = guard.auxiliary_contracts.get_mut(&key).expect("key exists");
        aux.state_variables.insert(
            var_name.clone(),
            AuxStateVariable {
                solidity_type,
                purpose: args.purpose.trim().to_string(),
            },
        );
        Ok(format!(
            "ok: auxiliary contract `{key}` now has {} state variable(s). Reference as `{key}.{var_name}`.",
            aux.state_variables.len()
        ))
    }
}

// ---- commit_specification ----

#[derive(Debug, Clone, Deserialize, JsonSchema)]
struct CommitSpecificationArgs {
    /// One- or two-sentence summary of the overall vulnerable behavior this
    /// spec captures (what the attacker does and what breaks). Required.
    summary: String,
}

#[derive(Debug, Clone)]
#[llmy::agent::tool(
    arguments = CommitSpecificationArgs,
    invoke = invoke,
    name = "commit_specification",
    description = "Snapshot the current draft as one finalized AuditSpecification and reset the draft for the next one. Requires a non-empty summary, at least one post_attack invariant (state-variable or contract constraint), and at least one call-sequence step.",
)]
struct CommitSpecificationTool {
    draft: DraftHandle,
    max_specs: usize,
}

impl CommitSpecificationTool {
    async fn invoke(
        &self,
        args: CommitSpecificationArgs,
    ) -> std::result::Result<String, llmy::agent::LLMYError> {
        let summary = args.summary.trim().to_string();
        let mut guard = self.draft.0.lock().await;
        if guard.completed.len() >= self.max_specs {
            return Ok(format!(
                "error: max_specs_per_link={} reached; call finalize next",
                self.max_specs
            ));
        }
        if summary.is_empty() {
            return Ok(
                "error: summary is required — give a one- or two-sentence description of the overall vulnerable behavior this spec captures. Draft unchanged."
                    .to_string(),
            );
        }
        if guard.post_attack.states_variables.is_empty() && guard.post_attack.contracts.is_empty() {
            return Ok(
                "error: post_attack has no invariant; add at least one state-variable or contract constraint that proves the vulnerability (add_state_variable_constraint / add_contract_constraint, stage=post_attack) before committing. Draft unchanged."
                    .to_string(),
            );
        }
        if guard.sequence.is_empty() {
            return Ok(
                "error: call sequence is empty; describe at least one core call before committing. Draft unchanged."
                    .to_string(),
            );
        }
        let spec = guard.build_spec(summary);
        guard.completed.push(spec);
        guard.reset_draft();
        Ok(format!(
            "ok: committed spec #{} for this link. Draft has been reset.",
            guard.completed.len()
        ))
    }
}

// ---- finalize ----

#[derive(Debug, Clone, Copy, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
enum FinalizeStatus {
    Completed,
    Abandoned,
}

#[derive(Debug, Clone, Deserialize, JsonSchema)]
struct FinalizeArgs {
    /// `completed` if at least one spec was committed; `abandoned` otherwise.
    status: FinalizeStatus,
    /// Free-form summary of what you produced or why you abandoned. Required.
    summary: String,
    /// When abandoned, a one-sentence reason (e.g. "project has no AMM
    /// pool — historical pattern doesn't apply").
    #[serde(default)]
    abort_reason: Option<String>,
}

#[derive(Debug, Clone)]
#[llmy::agent::tool(
    arguments = FinalizeArgs,
    invoke = invoke,
    name = "finalize",
    description = "End the spec-generation run for this link. Use `completed` when at least one spec has been committed; otherwise `abandoned`. Once called, no further tool calls are honoured.",
)]
struct FinalizeTool {
    draft: DraftHandle,
}

impl FinalizeTool {
    async fn invoke(
        &self,
        args: FinalizeArgs,
    ) -> std::result::Result<String, llmy::agent::LLMYError> {
        let mut guard = self.draft.0.lock().await;
        let status = match args.status {
            FinalizeStatus::Completed => {
                if guard.completed.is_empty() {
                    return Ok(
                        "error: cannot finalize as completed without at least one committed spec; use status=abandoned"
                            .to_string(),
                    );
                }
                LinkSpecStatus::Built
            }
            FinalizeStatus::Abandoned => LinkSpecStatus::Abandoned,
        };
        guard.final_status = Some(status);
        guard.final_summary = Some(args.summary);
        guard.abort_reason = args.abort_reason.or_else(|| {
            if status == LinkSpecStatus::Abandoned {
                Some("agent abandoned without explicit reason".to_string())
            } else {
                None
            }
        });
        Ok(format!(
            "ok: finalized as {} with {} committed spec(s). Stop now.",
            match status {
                LinkSpecStatus::Built => "completed",
                LinkSpecStatus::Abandoned => "abandoned",
            },
            guard.completed.len()
        ))
    }
}

// ---- lookup_call_graph ----

#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub(crate) struct LookupCallGraphArgs {
    /// Contract or interface name (case-insensitive). Required.
    contract: String,
    /// Optional function name to focus on. When omitted, all functions of
    /// the contract are listed (no edges).
    #[serde(default)]
    function: Option<String>,
}

#[derive(Debug, Clone)]
#[llmy::agent::tool(
    arguments = LookupCallGraphArgs,
    invoke = invoke,
    name = "lookup_call_graph",
    description = "Return the call-graph context for a contract or function: outgoing edges, incoming edges, and source content. Pass just the contract to enumerate its functions; pass contract+function for full edge listing.",
)]
pub(crate) struct LookupCallGraphTool {
    pub(crate) project: Arc<ProjectIndex>,
}

impl LookupCallGraphTool {
    async fn invoke(
        &self,
        args: LookupCallGraphArgs,
    ) -> std::result::Result<String, llmy::agent::LLMYError> {
        let contract_ids = self.project.lookup_contract(&args.contract);
        let interface_ids = self.project.lookup_interface(&args.contract);
        if contract_ids.is_empty() && interface_ids.is_empty() {
            return Ok(format!(
                "no contract or interface named `{}` found in this project",
                args.contract
            ));
        }
        let mut out = String::new();
        for id in contract_ids {
            if let Some(contract) = self.project.contract(id) {
                out.push_str(
                    &self
                        .project
                        .render_contract_lookup(contract, args.function.as_deref()),
                );
                out.push_str("\n---\n");
            }
        }
        for id in interface_ids {
            if let Some(interface) = self.project.interface(id) {
                out.push_str(
                    &self
                        .project
                        .render_interface_lookup(interface, args.function.as_deref()),
                );
                out.push_str("\n---\n");
            }
        }
        Ok(out)
    }
}

// ---- read_contract_source ----

#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub(crate) struct ReadContractSourceArgs {
    /// Contract or interface name (case-insensitive).
    contract: String,
}

#[derive(Debug, Clone)]
#[llmy::agent::tool(
    arguments = ReadContractSourceArgs,
    invoke = invoke,
    name = "read_contract_source",
    description = "Return the full source text of a contract or interface. Expensive — prefer `read_function_source` for a single function body when you only need to inspect one function. Use this when you need surrounding file context (modifiers, imports, struct layouts).",
)]
pub(crate) struct ReadContractSourceTool {
    pub(crate) project: Arc<ProjectIndex>,
}

impl ReadContractSourceTool {
    async fn invoke(
        &self,
        args: ReadContractSourceArgs,
    ) -> std::result::Result<String, llmy::agent::LLMYError> {
        let contract_ids = self.project.lookup_contract(&args.contract);
        let interface_ids = self.project.lookup_interface(&args.contract);
        if contract_ids.is_empty() && interface_ids.is_empty() {
            return Ok(format!(
                "no contract or interface named `{}` found in this project",
                args.contract
            ));
        }
        let mut out = String::new();
        for id in contract_ids {
            if let Some(contract) = self.project.contract(id) {
                out.push_str(&format!(
                    "## contract `{}` @ `{}` (id={})\n```solidity\n{}\n```\n---\n",
                    contract.name,
                    contract.relative_file_path.display(),
                    contract.id,
                    contract.chunk.content.trim_end(),
                ));
            }
        }
        for id in interface_ids {
            if let Some(interface) = self.project.interface(id) {
                out.push_str(&format!(
                    "## interface `{}` @ `{}` (id={})\n```solidity\n{}\n```\n---\n",
                    interface.name,
                    interface.relative_file_path.display(),
                    interface.id,
                    interface.chunk.content.trim_end(),
                ));
            }
        }
        Ok(out)
    }
}

// ---- read_function_source ----

#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub(crate) struct ReadFunctionSourceArgs {
    /// Contract or interface name (case-insensitive).
    contract: String,
    /// Function name (case-insensitive). For overloads, all matching bodies are returned.
    function: String,
}

#[derive(Debug, Clone)]
#[llmy::agent::tool(
    arguments = ReadFunctionSourceArgs,
    invoke = invoke,
    name = "read_function_source",
    description = "Return the source text of a single function (preferred over `read_contract_source` for body inspection). Returns all overloads matching the name within the contract. For interfaces this returns the declaration line.",
)]
pub(crate) struct ReadFunctionSourceTool {
    pub(crate) project: Arc<ProjectIndex>,
}

impl ReadFunctionSourceTool {
    async fn invoke(
        &self,
        args: ReadFunctionSourceArgs,
    ) -> std::result::Result<String, llmy::agent::LLMYError> {
        let target = args.function.to_lowercase();
        let mut out = String::new();
        let mut found = false;

        for cid in self.project.lookup_contract(&args.contract) {
            if let Some(contract) = self.project.contract(cid) {
                for f in contract
                    .functions
                    .iter()
                    .filter(|f| f.name.to_lowercase() == target)
                {
                    found = true;
                    out.push_str(&format!(
                        "## `{}::{}({})` @ {}:{} (id={})\n",
                        contract.name,
                        f.name,
                        f.args,
                        f.relative_file_path.display(),
                        f.loc.start_line,
                        f.id,
                    ));
                    if let Some(body) = &f.content {
                        out.push_str("```solidity\n");
                        out.push_str(body.trim_end());
                        out.push_str("\n```\n");
                    } else {
                        out.push_str("(no body — this function has no recorded source)\n");
                    }
                    if !f.calls.is_empty() {
                        out.push_str("outgoing calls:\n");
                        for call in &f.calls {
                            out.push_str(&format!(
                                "- -> {}\n",
                                self.project.describe_endpoint(call.to_id, call)
                            ));
                        }
                    }
                    out.push_str("---\n");
                }
            }
        }
        for iid in self.project.lookup_interface(&args.contract) {
            if let Some(interface) = self.project.interface(iid) {
                for f in interface
                    .functions
                    .iter()
                    .filter(|f| f.name.to_lowercase() == target)
                {
                    found = true;
                    out.push_str(&format!(
                        "## (interface) `{}::{}({})` @ {}:{} (id={})\n(declaration only)\n---\n",
                        interface.name,
                        f.name,
                        f.args,
                        f.relative_file_path.display(),
                        f.loc.start_line,
                        f.id,
                    ));
                }
            }
        }

        if !found {
            return Ok(format!(
                "no function named `{}` in contract or interface `{}`. Use `read_memory` to see available signatures.",
                args.function, args.contract
            ));
        }
        Ok(out)
    }
}

// ---- lookup_state_variable_xrefs ----

#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub(crate) struct LookupStateVariableXrefsArgs {
    /// State-variable name (case-insensitive).
    state_variable: String,
    /// Optional contract scope (case-insensitive). When provided, only
    /// matches declared in or visible to this contract are returned.
    #[serde(default)]
    contract: Option<String>,
}

#[derive(Debug, Clone)]
#[llmy::agent::tool(
    arguments = LookupStateVariableXrefsArgs,
    invoke = invoke,
    name = "lookup_state_variable_xrefs",
    description = "Return cross-references for a state variable: declaring contract, all functions reading it, all functions writing it. Optionally constrain the search to a single contract scope.",
)]
pub(crate) struct LookupStateVariableXrefsTool {
    pub(crate) project: Arc<ProjectIndex>,
}

impl LookupStateVariableXrefsTool {
    async fn invoke(
        &self,
        args: LookupStateVariableXrefsArgs,
    ) -> std::result::Result<String, llmy::agent::LLMYError> {
        let candidate_ids = self.project.lookup_state_var(&args.state_variable);
        if candidate_ids.is_empty() {
            return Ok(format!(
                "no state variable named `{}` found in this project",
                args.state_variable
            ));
        }
        let scope_contract_ids: Option<Vec<i32>> = args
            .contract
            .as_deref()
            .map(|name| self.project.lookup_contract(name));

        let mut out = String::new();
        for var_id in &candidate_ids {
            let Some(var) = self.project.state_variable(*var_id) else {
                continue;
            };
            let declaring_contract_id =
                self.project.declaring_contract_for_var.get(var_id).copied();
            // Apply scope filter: keep only when scope contract sees this var.
            if let Some(scope_ids) = &scope_contract_ids {
                let visible = scope_ids.iter().any(|cid| {
                    self.project
                        .visible_state_vars
                        .get(cid)
                        .map(|s| s.contains(var_id))
                        .unwrap_or(false)
                });
                if !visible {
                    continue;
                }
            }
            let declaring_contract_name = declaring_contract_id
                .and_then(|id| self.project.contract(id))
                .map(|c| c.name.as_str())
                .unwrap_or("?");
            out.push_str(&format!(
                "## {} {} (id={}) declared in `{}` @ {}:{}\n",
                var.type_name.trim(),
                var.name,
                var.id,
                declaring_contract_name,
                var.relative_file_path.display(),
                var.loc.start_line
            ));

            let xrefs: Vec<&FunctionStateVariable> = self
                .project
                .storage_graph
                .function_state_variables
                .iter()
                .filter(|fsv| fsv.state_variable_id == var.id)
                .collect();

            let (writes, reads): (Vec<&&FunctionStateVariable>, Vec<&&FunctionStateVariable>) =
                xrefs.iter().partition(|fsv| fsv.is_write);
            out.push_str(&format!(
                "writers ({}) and readers ({})\n",
                writes.len(),
                reads.len()
            ));
            if !writes.is_empty() {
                out.push_str("\nwriters:\n");
                for fsv in writes {
                    out.push_str(&format!(
                        "- {}\n",
                        self.project
                            .describe_function_xref(fsv.function_id, fsv.description.as_deref())
                    ));
                }
            }
            if !reads.is_empty() {
                out.push_str("\nreaders:\n");
                for fsv in reads {
                    out.push_str(&format!(
                        "- {}\n",
                        self.project
                            .describe_function_xref(fsv.function_id, fsv.description.as_deref())
                    ));
                }
            }
            out.push_str("\n---\n");
        }
        if out.is_empty() {
            return Ok(format!(
                "no state variable named `{}` matches the given contract scope",
                args.state_variable
            ));
        }
        Ok(out)
    }
}

#[cfg(test)]
mod grounding_tests {
    use super::*;
    use knowdit_repo_model::cg::{
        CallGraph, Contract, FileChunk, FileLocation, Function, Interface,
    };
    use knowdit_repo_model::inheritance::{ContractInherit, InheritanceGraph};
    use knowdit_repo_model::storage::{ContractVariable, StateVariable, StorageGraph};
    use std::path::PathBuf;

    fn loc() -> FileLocation {
        FileLocation {
            start_line: 1,
            start_column: 0,
            end_line: 2,
            end_column: 0,
        }
    }

    fn chunk() -> FileChunk {
        FileChunk {
            loc: loc(),
            content: String::new(),
        }
    }

    fn func(id: i32, name: &str) -> Function {
        Function {
            id,
            name: name.to_string(),
            args: String::new(),
            relative_file_path: PathBuf::from("src/X.sol"),
            loc: loc(),
            content: None,
            calls: vec![],
            description: None,
        }
    }

    fn contract(id: i32, name: &str, functions: Vec<Function>) -> Contract {
        Contract {
            id,
            name: name.to_string(),
            relative_file_path: PathBuf::from("src/X.sol"),
            chunk: chunk(),
            functions,
            description: None,
        }
    }

    fn state_var(id: i32, name: &str, ty: &str) -> StateVariable {
        StateVariable {
            id,
            name: name.to_string(),
            type_name: ty.to_string(),
            relative_file_path: PathBuf::from("src/X.sol"),
            loc: loc(),
            content: String::new(),
        }
    }

    /// Vault (own var `balances`, own fn `withdraw`) inherits Base (var
    /// `paused`, fn `pause`); plus interface IERC20 with `transfer`.
    fn project_index() -> Arc<ProjectIndex> {
        let mut contracts = BTreeMap::new();
        contracts.insert(1, contract(1, "Vault", vec![func(100, "withdraw")]));
        contracts.insert(2, contract(2, "Base", vec![func(200, "pause")]));
        let mut interfaces = BTreeMap::new();
        interfaces.insert(
            3,
            Interface {
                id: 3,
                name: "IERC20".to_string(),
                relative_file_path: PathBuf::from("src/I.sol"),
                chunk: chunk(),
                functions: vec![func(300, "transfer")],
                description: None,
            },
        );
        let call_graph = CallGraph {
            contracts,
            interfaces,
        };

        let mut state_variables = BTreeMap::new();
        state_variables.insert(10, state_var(10, "balances", "mapping(address => uint256)"));
        state_variables.insert(11, state_var(11, "paused", "bool"));
        let storage_graph = StorageGraph {
            state_variables,
            contract_variables: vec![
                ContractVariable {
                    contract_id: 1,
                    state_variable_id: 10,
                    description: None,
                },
                ContractVariable {
                    contract_id: 2,
                    state_variable_id: 11,
                    description: None,
                },
            ],
            function_state_variables: vec![],
        };
        let inheritance_graph = InheritanceGraph::new(vec![ContractInherit {
            contract_id: 1,
            inherited_id: 2,
        }]);
        Arc::new(ProjectIndex::build(
            call_graph,
            storage_graph,
            inheritance_graph,
        ))
    }

    #[test]
    fn project_index_grounds_contracts_vars_and_functions() {
        let idx = project_index();
        assert!(idx.has_contract("Vault"));
        assert!(idx.has_contract("vault")); // index is lower-cased
        assert!(idx.has_contract("IERC20"));
        assert!(!idx.has_contract("Ghost"));

        assert!(idx.has_state_variable("balances")); // bare
        assert!(idx.has_state_variable("Vault.balances")); // qualified, own
        assert!(idx.has_state_variable("Vault.paused")); // qualified, inherited
        assert!(!idx.has_state_variable("Base.balances")); // not visible to Base
        assert!(!idx.has_state_variable("Vault.ghost"));
        assert!(!idx.has_state_variable("ghost"));

        assert!(idx.contract_has_function("Vault", "withdraw")); // own
        assert!(idx.contract_has_function("Vault", "pause")); // inherited
        assert!(idx.contract_has_function("IERC20", "transfer")); // interface
        assert!(!idx.contract_has_function("Vault", "ghost"));
        assert!(!idx.contract_has_function("Ghost", "x"));
    }

    #[tokio::test]
    async fn state_var_constraint_rejects_unknown_without_mutating() {
        let idx = project_index();
        let draft = DraftHandle::new();
        let tool = AddStateVariableConstraintTool {
            draft: draft.clone(),
            project: idx.clone(),
        };
        let res = tool
            .invoke(AddStateVariableConstraintArgs {
                stage: SpecStage::PostAttack,
                key: "ghost".to_string(),
                constraint: "== 0".to_string(),
            })
            .await
            .unwrap();
        assert!(res.starts_with("error:"), "{res}");
        assert!(res.contains("Draft unchanged"), "{res}");
        assert!(
            draft
                .snapshot()
                .await
                .post_attack
                .states_variables
                .is_empty()
        );

        // a real project var is accepted
        let res = tool
            .invoke(AddStateVariableConstraintArgs {
                stage: SpecStage::PostAttack,
                key: "Vault.balances".to_string(),
                constraint: "drained".to_string(),
            })
            .await
            .unwrap();
        assert!(res.starts_with("ok:"), "{res}");
        assert_eq!(draft.snapshot().await.post_attack.states_variables.len(), 1);
    }

    #[tokio::test]
    async fn aux_contract_workflow_grounds_against_registry() {
        let idx = project_index();
        let draft = DraftHandle::new();

        // cannot declare aux state before the aux contract exists
        let r = AddAuxContractStateTool {
            draft: draft.clone(),
        }
        .invoke(AddAuxContractStateArgs {
            contract: "Attacker".to_string(),
            name: "callCount".to_string(),
            solidity_type: "uint256".to_string(),
            purpose: "reentry counter".to_string(),
        })
        .await
        .unwrap();
        assert!(r.starts_with("error:"), "{r}");

        // cannot shadow a real project contract
        let r = AddAuxContractTool {
            draft: draft.clone(),
            project: idx.clone(),
        }
        .invoke(AddAuxContractArgs {
            name: "Vault".to_string(),
            purpose: "x".to_string(),
        })
        .await
        .unwrap();
        assert!(r.starts_with("error:"), "{r}");

        // declare aux contract + state
        AddAuxContractTool {
            draft: draft.clone(),
            project: idx.clone(),
        }
        .invoke(AddAuxContractArgs {
            name: "Attacker".to_string(),
            purpose: "reentrancy".to_string(),
        })
        .await
        .unwrap();
        AddAuxContractStateTool {
            draft: draft.clone(),
        }
        .invoke(AddAuxContractStateArgs {
            contract: "Attacker".to_string(),
            name: "callCount".to_string(),
            solidity_type: "uint256".to_string(),
            purpose: "reentry counter".to_string(),
        })
        .await
        .unwrap();

        // aux state var grounds via the registry (case-insensitive contract)
        let r = AddStateVariableConstraintTool {
            draft: draft.clone(),
            project: idx.clone(),
        }
        .invoke(AddStateVariableConstraintArgs {
            stage: SpecStage::PostAttack,
            key: "attacker.callCount".to_string(),
            constraint: "== 2".to_string(),
        })
        .await
        .unwrap();
        assert!(r.starts_with("ok:"), "{r}");

        // contract constraint accepts the aux contract
        let r = AddContractConstraintTool {
            draft: draft.clone(),
            project: idx.clone(),
        }
        .invoke(AddContractConstraintArgs {
            stage: SpecStage::Setup,
            contract: "Attacker".to_string(),
            constraint: "deployed".to_string(),
        })
        .await
        .unwrap();
        assert!(r.starts_with("ok:"), "{r}");
    }

    #[tokio::test]
    async fn set_call_sequence_is_atomic_and_allows_aux_functions() {
        let idx = project_index();
        let draft = DraftHandle::new();
        AddAuxContractTool {
            draft: draft.clone(),
            project: idx.clone(),
        }
        .invoke(AddAuxContractArgs {
            name: "Attacker".to_string(),
            purpose: "reentrancy".to_string(),
        })
        .await
        .unwrap();

        let seq = SetCallSequenceTool {
            draft: draft.clone(),
            project: idx.clone(),
        };

        // one phantom function => whole call rejected, sequence untouched
        let r = seq
            .invoke(SetCallSequenceArgs {
                steps: vec![
                    CallStepArg {
                        contract: "Vault".to_string(),
                        function: "withdraw".to_string(),
                        intention: "a".to_string(),
                    },
                    CallStepArg {
                        contract: "Vault".to_string(),
                        function: "ghost".to_string(),
                        intention: "b".to_string(),
                    },
                ],
            })
            .await
            .unwrap();
        assert!(r.starts_with("error:"), "{r}");
        assert!(draft.snapshot().await.sequence.is_empty());

        // project fn grounded + aux fn accepted (synthesized by harness)
        let r = seq
            .invoke(SetCallSequenceArgs {
                steps: vec![
                    CallStepArg {
                        contract: "Attacker".to_string(),
                        function: "attack".to_string(),
                        intention: "kick".to_string(),
                    },
                    CallStepArg {
                        contract: "Vault".to_string(),
                        function: "withdraw".to_string(),
                        intention: "reenter".to_string(),
                    },
                ],
            })
            .await
            .unwrap();
        assert!(r.starts_with("ok:"), "{r}");
        assert_eq!(draft.snapshot().await.sequence.len(), 2);
    }

    #[tokio::test]
    async fn commit_requires_summary_invariant_and_sequence() {
        let idx = project_index();
        let draft = DraftHandle::new();
        let commit = CommitSpecificationTool {
            draft: draft.clone(),
            max_specs: 4,
        };

        let r = commit
            .invoke(CommitSpecificationArgs {
                summary: "   ".to_string(),
            })
            .await
            .unwrap();
        assert!(r.contains("summary is required"), "{r}");

        let r = commit
            .invoke(CommitSpecificationArgs {
                summary: "drain".to_string(),
            })
            .await
            .unwrap();
        assert!(r.contains("post_attack has no invariant"), "{r}");

        AddStateVariableConstraintTool {
            draft: draft.clone(),
            project: idx.clone(),
        }
        .invoke(AddStateVariableConstraintArgs {
            stage: SpecStage::PostAttack,
            key: "balances".to_string(),
            constraint: "drained".to_string(),
        })
        .await
        .unwrap();

        let r = commit
            .invoke(CommitSpecificationArgs {
                summary: "drain".to_string(),
            })
            .await
            .unwrap();
        assert!(r.contains("call sequence is empty"), "{r}");

        SetCallSequenceTool {
            draft: draft.clone(),
            project: idx.clone(),
        }
        .invoke(SetCallSequenceArgs {
            steps: vec![CallStepArg {
                contract: "Vault".to_string(),
                function: "withdraw".to_string(),
                intention: "x".to_string(),
            }],
        })
        .await
        .unwrap();

        let r = commit
            .invoke(CommitSpecificationArgs {
                summary: "attacker drains vault".to_string(),
            })
            .await
            .unwrap();
        assert!(r.starts_with("ok:"), "{r}");
        let snap = draft.snapshot().await;
        assert_eq!(snap.completed.len(), 1);
        assert_eq!(snap.completed[0].summary, "attacker drains vault");
        // draft reset after commit
        assert!(snap.post_attack.states_variables.is_empty());
        assert!(snap.sequence.is_empty());
    }
}
