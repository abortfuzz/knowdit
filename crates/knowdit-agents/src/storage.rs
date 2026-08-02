use std::{
    collections::{BTreeMap, HashMap, HashSet, VecDeque},
    fmt::Write as _,
    sync::Arc,
};

use color_eyre::eyre::{ContextCompat, WrapErr, ensure};
use knowdit_repo_model::{
    inheritance::{ContractInherit, InheritanceGraph},
    storage::{ContractVariable, FunctionStateVariable, StateVariable, StorageGraph},
};
use knowdit_sol::{
    cg::{
        ExtractedContract, SolidityCallableKind, SolidityExtractionConfig,
        extract_repo_contracts_functions,
    },
    storage::{
        ExtractedInheritance, ExtractedStateVariable, extract_state_variables_and_inheritance,
    },
};
use llmy::{
    agent::{LLMYError, StepResult, tool::ToolBox},
    client::{client::LLM, settings::LLMSettings},
    harness::Agent,
};
use schemars::JsonSchema;
use serde::Deserialize;
use tokio::sync::Mutex;

use crate::storage_prompt::{
    StorageAgentPromptInput, storage_agent_system_prompt, storage_agent_user_prompt,
};

#[derive(Debug, Clone)]
pub struct StorageAgentConfig {
    pub extraction: SolidityExtractionConfig,
    pub max_agent_steps: usize,
    pub debug_prefix: Option<String>,
    pub llm_settings: Option<LLMSettings>,
}

impl StorageAgentConfig {
    pub fn new(
        extraction: SolidityExtractionConfig,
        max_agent_steps: usize,
        debug_prefix: Option<String>,
        llm_settings: Option<LLMSettings>,
    ) -> Self {
        Self {
            extraction,
            max_agent_steps,
            debug_prefix,
            llm_settings,
        }
    }
}

#[derive(Debug, Clone)]
pub struct StorageAgentResult {
    pub storage_graph: StorageGraph,
    pub inheritance_graph: InheritanceGraph,
    /// Tree-sitter extracted contracts + functions, exposed so the CLI can persist a callgraph
    /// skeleton (contracts/functions/links, no call edges) using the same project-local ids
    /// as the storage analysis.
    pub extracted_contracts: Vec<ExtractedContract>,
    pub steps: usize,
    pub final_response: String,
}

pub async fn analyze_repo_storage(
    llm: &LLM,
    config: StorageAgentConfig,
) -> Result<StorageAgentResult, color_eyre::Report> {
    let extraction = extract_repo_contracts_functions(&config.extraction).await?;
    let storage_extraction =
        extract_state_variables_and_inheritance(&extraction.repo_root, &extraction.contracts)
            .await?;

    let extracted_contracts = extraction.contracts.clone();
    let runner = StorageRunner::new(extraction.contracts, storage_extraction);
    let mut result = runner.run(llm, &config).await?;
    result.extracted_contracts = extracted_contracts;
    Ok(result)
}

struct StorageRunner {
    contract_by_id: BTreeMap<i32, ExtractedContract>,
    state_variables: Vec<ExtractedStateVariable>,
    state_variable_by_id: BTreeMap<i32, ExtractedStateVariable>,
    /// Project-local inheritance edges (parent_contract_id known).
    contract_inherits: Vec<ContractInherit>,
    /// All `is X` rows including unresolved external parents (for prompt context).
    raw_inherits: Vec<ExtractedInheritance>,
    /// State vars visible to each contract = own + transitive parents.
    visible_state_var_ids: BTreeMap<i32, Vec<i32>>,
}

impl StorageRunner {
    fn new(
        contracts: Vec<ExtractedContract>,
        storage_extraction: knowdit_sol::storage::StorageExtractionResult,
    ) -> Self {
        let contract_by_id = contracts
            .iter()
            .cloned()
            .map(|c| (c.id, c))
            .collect::<BTreeMap<_, _>>();
        let state_variable_by_id = storage_extraction
            .state_variables
            .iter()
            .cloned()
            .map(|v| (v.id, v))
            .collect::<BTreeMap<_, _>>();

        let mut contract_inherits: Vec<ContractInherit> = Vec::new();
        for inh in &storage_extraction.inherits {
            if let Some(parent_id) = inh.parent_contract_id {
                contract_inherits.push(ContractInherit {
                    contract_id: inh.contract_id,
                    inherited_id: parent_id,
                });
            }
        }
        contract_inherits.sort_by_key(|i| (i.contract_id, i.inherited_id));
        contract_inherits.dedup_by_key(|i| (i.contract_id, i.inherited_id));

        // Build adjacency: child -> parents
        let mut parents: BTreeMap<i32, Vec<i32>> = BTreeMap::new();
        for ci in &contract_inherits {
            parents
                .entry(ci.contract_id)
                .or_default()
                .push(ci.inherited_id);
        }

        // own_state_var_ids
        let mut own_state_var_ids: BTreeMap<i32, Vec<i32>> = BTreeMap::new();
        for sv in &storage_extraction.state_variables {
            own_state_var_ids
                .entry(sv.contract_id)
                .or_default()
                .push(sv.id);
        }

        // visible_state_var_ids: BFS over inheritance closure
        let mut visible_state_var_ids: BTreeMap<i32, Vec<i32>> = BTreeMap::new();
        for c in &contracts {
            let mut visited: HashSet<i32> = HashSet::new();
            let mut queue: VecDeque<i32> = VecDeque::new();
            queue.push_back(c.id);
            let mut visible: Vec<i32> = Vec::new();
            while let Some(cid) = queue.pop_front() {
                if !visited.insert(cid) {
                    continue;
                }
                if let Some(svs) = own_state_var_ids.get(&cid) {
                    visible.extend(svs.iter().copied());
                }
                if let Some(ps) = parents.get(&cid) {
                    for &p in ps {
                        if !visited.contains(&p) {
                            queue.push_back(p);
                        }
                    }
                }
            }
            visible.sort();
            visible.dedup();
            visible_state_var_ids.insert(c.id, visible);
        }

        Self {
            contract_by_id,
            state_variables: storage_extraction.state_variables.clone(),
            state_variable_by_id,
            contract_inherits,
            raw_inherits: storage_extraction.inherits,
            visible_state_var_ids,
        }
    }

    async fn run(
        self,
        llm: &LLM,
        config: &StorageAgentConfig,
    ) -> Result<StorageAgentResult, color_eyre::Report> {
        let store = SharedStorageEdges::default();
        let mut summaries: Vec<String> = Vec::new();
        let mut total_steps = 0usize;

        // Iterate contracts in deterministic order. Skip Interface kind (no bodies, no R/W).
        let mut contract_ids: Vec<i32> = self.contract_by_id.keys().copied().collect();
        contract_ids.sort();

        for cid in contract_ids {
            let contract = self
                .contract_by_id
                .get(&cid)
                .cloned()
                .wrap_err("missing contract")?;
            // Skip interfaces and library/contract entries that have no functions and no state vars.
            let has_functions = contract.functions.iter().any(|f| {
                matches!(
                    f.kind,
                    SolidityCallableKind::Function
                        | SolidityCallableKind::Constructor
                        | SolidityCallableKind::Receive
                        | SolidityCallableKind::Fallback
                        | SolidityCallableKind::Modifier
                )
            });
            let visible_svs = self
                .visible_state_var_ids
                .get(&cid)
                .cloned()
                .unwrap_or_default();
            // Drop constants — agent doesn't need to see them.
            let visible_svs: Vec<i32> = visible_svs
                .into_iter()
                .filter(|sv_id| {
                    self.state_variable_by_id
                        .get(sv_id)
                        .map(|sv| !sv.is_constant)
                        .unwrap_or(false)
                })
                .collect();
            if !has_functions || visible_svs.is_empty() {
                continue;
            }

            let function_index_table = self.render_function_index(&contract);
            let state_variable_index_table = self.render_state_var_index(&visible_svs);
            let inheritance_chain = self.render_inheritance_chain(cid);
            let contract_source =
                render_with_line_numbers(&contract.chunk.content, contract.chunk.loc.start_line);

            let prompt_input = StorageAgentPromptInput {
                contract_label: format!(
                    "{} {} ({})",
                    contract.kind.as_str(),
                    contract.name,
                    contract.relative_file_path.display()
                ),
                contract_source,
                function_index_table,
                state_variable_index_table,
                inheritance_chain,
            };

            let mut tools = ToolBox::new();
            tools.add_tool(RecordStateVarAccessTool::new(
                contract
                    .functions
                    .iter()
                    .map(|f| f.id)
                    .collect::<HashSet<_>>(),
                visible_svs.iter().copied().collect::<HashSet<_>>(),
                store.clone(),
            ));

            let mut agent = Agent::new(storage_agent_system_prompt(), tools, None);
            let user = storage_agent_user_prompt(prompt_input);
            let mut steps = 1;
            let mut step_result = agent
                .step_with_user(
                    user,
                    llm,
                    config.debug_prefix.as_deref(),
                    config.llm_settings.clone(),
                )
                .await
                .wrap_err_with(|| {
                    format!(
                        "storage agent initial step failed for contract {}",
                        contract.name
                    )
                })?;

            loop {
                if let StepResult::Stop(summary) = &step_result {
                    summaries.push(format!(
                        "{}::{}",
                        contract.relative_file_path.display(),
                        contract.name
                    ));
                    summaries.push(summary.trim().to_string());
                    break;
                }
                ensure!(
                    steps < config.max_agent_steps,
                    "storage agent exceeded max_agent_steps={} on contract {}",
                    config.max_agent_steps,
                    contract.name
                );
                steps += 1;
                step_result = agent
                    .step(
                        llm,
                        config.debug_prefix.as_deref(),
                        config.llm_settings.clone(),
                    )
                    .await
                    .wrap_err_with(|| {
                        format!(
                            "storage agent step {} failed for contract {}",
                            steps, contract.name
                        )
                    })?;
            }
            total_steps += steps;
        }

        // Build StorageGraph
        let mut state_variables_map: BTreeMap<i32, StateVariable> = BTreeMap::new();
        for sv in &self.state_variables {
            state_variables_map.insert(
                sv.id,
                StateVariable {
                    id: sv.id,
                    name: sv.name.clone(),
                    type_name: sv.type_text.clone(),
                    relative_file_path: sv.relative_file_path.clone(),
                    loc: sv.chunk.loc,
                    content: sv.chunk.content.clone(),
                },
            );
        }
        let mut contract_variables: Vec<ContractVariable> = self
            .state_variables
            .iter()
            .map(|sv| ContractVariable {
                contract_id: sv.contract_id,
                state_variable_id: sv.id,
                description: None,
            })
            .collect();
        contract_variables.sort_by_key(|cv| (cv.contract_id, cv.state_variable_id));
        let recorded = store.snapshot().await;
        let storage_graph = StorageGraph {
            state_variables: state_variables_map,
            contract_variables,
            function_state_variables: recorded,
        };
        let inheritance_graph = InheritanceGraph::new(self.contract_inherits.clone());

        Ok(StorageAgentResult {
            storage_graph,
            inheritance_graph,
            extracted_contracts: Vec::new(),
            steps: total_steps,
            final_response: summaries.join("\n"),
        })
    }

    fn render_function_index(&self, contract: &ExtractedContract) -> String {
        let mut s = String::new();
        for f in &contract.functions {
            let _ = writeln!(
                s,
                "- function_id={} kind={} name={} args=({}) line={}",
                f.id,
                f.kind.as_str(),
                f.name,
                f.args,
                f.chunk.loc.start_line
            );
        }
        if s.is_empty() {
            "(no functions)".to_string()
        } else {
            s
        }
    }

    fn render_state_var_index(&self, ids: &[i32]) -> String {
        let mut s = String::new();
        for sv_id in ids {
            let Some(sv) = self.state_variable_by_id.get(sv_id) else {
                continue;
            };
            let imm = if sv.is_immutable { " [immutable]" } else { "" };
            let _ = writeln!(
                s,
                "- state_variable_id={} contract={} name={} type={}{}",
                sv.id, sv.contract_name, sv.name, sv.type_text, imm
            );
        }
        if s.is_empty() {
            "(none — contract has no visible state variables)".to_string()
        } else {
            s
        }
    }

    fn render_inheritance_chain(&self, contract_id: i32) -> String {
        let mut chain: Vec<String> = Vec::new();
        for inh in &self.raw_inherits {
            if inh.contract_id != contract_id {
                continue;
            }
            if let Some(pid) = inh.parent_contract_id {
                let parent = self.contract_by_id.get(&pid);
                let label = parent
                    .map(|p| format!("{} ({})", p.name, p.relative_file_path.display()))
                    .unwrap_or_else(|| inh.parent_name.clone());
                chain.push(format!("- {}", label));
            } else {
                chain.push(format!(
                    "- {} (external / not in tree-sitter index)",
                    inh.parent_name
                ));
            }
        }
        if chain.is_empty() {
            "(none)".to_string()
        } else {
            chain.join("\n")
        }
    }
}

#[derive(Debug, Clone, Default)]
struct SharedStorageEdges {
    inner: Arc<Mutex<HashMap<(i32, i32, bool), Option<String>>>>,
}

impl SharedStorageEdges {
    async fn record(&self, fid: i32, sv: i32, is_write: bool, description: Option<String>) -> bool {
        let mut g = self.inner.lock().await;
        let key = (fid, sv, is_write);
        if let std::collections::hash_map::Entry::Vacant(e) = g.entry(key) {
            e.insert(description);
            true
        } else {
            // Keep first description if present; ignore further.
            false
        }
    }

    async fn snapshot(&self) -> Vec<FunctionStateVariable> {
        let g = self.inner.lock().await;
        let mut out: Vec<FunctionStateVariable> = g
            .iter()
            .map(|((fid, sv, w), desc)| FunctionStateVariable {
                function_id: *fid,
                state_variable_id: *sv,
                is_write: *w,
                description: desc.clone(),
            })
            .collect();
        out.sort_by_key(|r| (r.function_id, r.state_variable_id, r.is_write));
        out
    }
}

#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct RecordStateVarAccessArgs {
    /// Project-local id of the function/modifier (must be one listed in the function index).
    pub function_id: i32,
    /// Project-local id of the state variable (must be one listed in the visible state var index).
    pub state_variable_id: i32,
    /// `true` for stores/deletes/array.push/array.pop/compound assigns/++/--; `false` for reads.
    pub is_write: bool,
    /// Optional 1-line description of the access (e.g. "post-increment", "delete on map slot").
    #[serde(default)]
    pub description: Option<String>,
}

#[derive(Debug, Clone)]
#[llmy::agent::tool(
    arguments = RecordStateVarAccessArgs,
    invoke = record_state_variable_access,
    name = "record_state_variable_access",
    description = "Record one (function -> state-variable) read or write edge for the contract under analysis. Pass the project-local function_id from the function index and the project-local state_variable_id from the visible state-var index. Use is_write=true for any write (assignment / delete / push / pop / compound op / ++ / --). Repeated calls with the same (function_id, state_variable_id, is_write) triple are idempotent. If the function_id or state_variable_id is not in the indexes for this contract, the tool refuses and returns the candidate ids; fix the selector and retry.",
)]
struct RecordStateVarAccessTool {
    valid_function_ids: HashSet<i32>,
    valid_state_var_ids: HashSet<i32>,
    store: SharedStorageEdges,
}

impl RecordStateVarAccessTool {
    fn new(
        valid_function_ids: HashSet<i32>,
        valid_state_var_ids: HashSet<i32>,
        store: SharedStorageEdges,
    ) -> Self {
        Self {
            valid_function_ids,
            valid_state_var_ids,
            store,
        }
    }

    async fn record_state_variable_access(
        &self,
        args: RecordStateVarAccessArgs,
    ) -> Result<String, LLMYError> {
        if !self.valid_function_ids.contains(&args.function_id) {
            let mut ids: Vec<i32> = self.valid_function_ids.iter().copied().collect();
            ids.sort();
            return Ok(format!(
                "rejected: function_id={} is not in this contract's function index. Valid function_ids: {:?}",
                args.function_id, ids
            ));
        }
        if !self.valid_state_var_ids.contains(&args.state_variable_id) {
            let mut ids: Vec<i32> = self.valid_state_var_ids.iter().copied().collect();
            ids.sort();
            return Ok(format!(
                "rejected: state_variable_id={} is not visible to this contract. Visible state_variable_ids: {:?}",
                args.state_variable_id, ids
            ));
        }
        let inserted = self
            .store
            .record(
                args.function_id,
                args.state_variable_id,
                args.is_write,
                args.description.clone(),
            )
            .await;
        Ok(format!(
            "{} ({} -> sv{} {})",
            if inserted {
                "recorded"
            } else {
                "already recorded"
            },
            args.function_id,
            args.state_variable_id,
            if args.is_write { "WRITE" } else { "READ" }
        ))
    }
}

fn render_with_line_numbers(content: &str, start_line: usize) -> String {
    let mut out = String::new();
    for (i, line) in content.lines().enumerate() {
        let _ = writeln!(out, "{:5} {}", start_line + i, line);
    }
    out
}
