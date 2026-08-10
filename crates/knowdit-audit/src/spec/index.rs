//! The Solidity project index: precomputed call-graph / storage / inheritance
//! lookups the spec-gen agent's tools resolve against, plus the agent-memory
//! renderings derived from it. Split out of `spec::mod` so the index and its
//! derived views live together.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use color_eyre::eyre::Result;
use knowdit_repo_model::cg::{CallGraph, Contract, Function, FunctionCall, Interface};
use knowdit_repo_model::inheritance::{ContractInherit, InheritanceGraph};
use knowdit_repo_model::storage::{ContractVariable, StateVariable, StorageGraph};
use llmy::agent::tools::memory::{AgentMemory, AgentMemoryContent, AgentMemoryContext};

#[derive(Debug)]
pub struct ProjectIndex {
    /// Held by `Arc` so downstream consumers (e.g. the harness
    /// `RunForgeTool` that needs a `&CallGraph` for the coverage gate)
    /// can keep a cheap reference instead of triggering a full
    /// `CallGraph::clone()` per spec — which over thousands of specs
    /// fragmented glibc malloc badly enough to OOM the orchestrator.
    pub call_graph: Arc<CallGraph>,
    pub storage_graph: StorageGraph,
    pub inheritance_graph: InheritanceGraph,
    /// `function.id -> (relative_file_path, contract_or_interface_name, kind)`
    pub function_owner: BTreeMap<i32, FunctionOwner>,
    /// Lower-cased contract name -> contract ids (multiple files may reuse).
    pub contract_ids_by_name: BTreeMap<String, Vec<i32>>,
    /// Lower-cased interface name -> interface ids.
    pub interface_ids_by_name: BTreeMap<String, Vec<i32>>,
    /// state_variable_id -> declaring contract id (from contract_variable).
    pub declaring_contract_for_var: BTreeMap<i32, i32>,
    /// contract_id -> all state-variable ids (own + inherited via the
    /// transitive closure of contract_inherits).
    pub visible_state_vars: BTreeMap<i32, BTreeSet<i32>>,
    /// Lower-cased state-variable name -> state_variable ids.
    pub state_var_ids_by_name: BTreeMap<String, Vec<i32>>,
}

/// Which part of the project a link agent's signature index should cover.
///
/// Named rather than passed as a pair of `Option`s because the two cases are
/// decisions, not absent arguments: an agent reading everything on demand needs
/// the whole map, and one holding part of the source in its prompt needs only
/// the part it does not already have.
#[derive(Debug, Clone, Copy)]
pub(crate) enum MemoryScope<'a> {
    WholeProject,
    Only {
        contracts: &'a BTreeSet<i32>,
        interfaces: &'a BTreeSet<i32>,
    },
}

/// One contract or interface, rendered on its own, as a unit the resident-block
/// packer can take or leave.
#[derive(Debug, Clone)]
pub(crate) struct ResidentCandidate {
    pub(crate) id: i32,
    pub(crate) is_interface: bool,
    pub(crate) name: String,
    /// Repo-relative path of the defining file. Matched against the profile's
    /// core components in preference to the name, which can repeat across
    /// files.
    pub(crate) relative_file_path: String,
    /// Calls made plus calls received; the packing priority. Interfaces score 0
    /// — they declare rather than call, and are small enough to ride along.
    pub(crate) degree: usize,
    pub(crate) source: String,
}

#[derive(Debug, Clone)]
pub(crate) struct FunctionOwner {
    pub(crate) relative_file_path: String,
    pub(crate) container_kind: ContainerKind,
    pub(crate) container_name: String,
    pub(crate) container_id: i32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ContainerKind {
    Contract,
    Interface,
}

impl ContainerKind {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Contract => "contract",
            Self::Interface => "interface",
        }
    }
}

impl ProjectIndex {
    pub(crate) fn build(
        call_graph: CallGraph,
        storage_graph: StorageGraph,
        inheritance_graph: InheritanceGraph,
    ) -> Self {
        // Wrap the call graph in an `Arc` up front so every downstream
        // hand-off (including the per-spec `RunForgeTool::callgraph`)
        // is a refcount bump rather than a deep clone of every contract
        // / function / source body.
        let call_graph = Arc::new(call_graph);
        let mut function_owner: BTreeMap<i32, FunctionOwner> = BTreeMap::new();
        let mut contract_ids_by_name: BTreeMap<String, Vec<i32>> = BTreeMap::new();
        let mut interface_ids_by_name: BTreeMap<String, Vec<i32>> = BTreeMap::new();
        for contract in call_graph.contracts.values() {
            contract_ids_by_name
                .entry(contract.name.to_lowercase())
                .or_default()
                .push(contract.id);
            for function in &contract.functions {
                function_owner.insert(
                    function.id,
                    FunctionOwner {
                        relative_file_path: contract.relative_file_path.display().to_string(),
                        container_kind: ContainerKind::Contract,
                        container_name: contract.name.clone(),
                        container_id: contract.id,
                    },
                );
            }
        }
        for interface in call_graph.interfaces.values() {
            interface_ids_by_name
                .entry(interface.name.to_lowercase())
                .or_default()
                .push(interface.id);
            for function in &interface.functions {
                function_owner.insert(
                    function.id,
                    FunctionOwner {
                        relative_file_path: interface.relative_file_path.display().to_string(),
                        container_kind: ContainerKind::Interface,
                        container_name: interface.name.clone(),
                        container_id: interface.id,
                    },
                );
            }
        }

        let mut declaring_contract_for_var: BTreeMap<i32, i32> = BTreeMap::new();
        for ContractVariable {
            contract_id,
            state_variable_id,
            ..
        } in &storage_graph.contract_variables
        {
            declaring_contract_for_var
                .entry(*state_variable_id)
                .or_insert(*contract_id);
        }

        let inherits = inheritance_closure(&inheritance_graph.inherits);
        let mut visible_state_vars: BTreeMap<i32, BTreeSet<i32>> = BTreeMap::new();
        for ContractVariable {
            contract_id,
            state_variable_id,
            ..
        } in &storage_graph.contract_variables
        {
            visible_state_vars
                .entry(*contract_id)
                .or_default()
                .insert(*state_variable_id);
        }
        // Add inherited variables to descendants.
        let snapshot = visible_state_vars.clone();
        for (contract_id, ancestors) in &inherits {
            let entry = visible_state_vars.entry(*contract_id).or_default();
            for ancestor in ancestors {
                if let Some(vars) = snapshot.get(ancestor) {
                    for var in vars {
                        entry.insert(*var);
                    }
                }
            }
        }

        let mut state_var_ids_by_name: BTreeMap<String, Vec<i32>> = BTreeMap::new();
        for var in storage_graph.state_variables.values() {
            state_var_ids_by_name
                .entry(var.name.to_lowercase())
                .or_default()
                .push(var.id);
        }

        Self {
            call_graph,
            storage_graph,
            inheritance_graph,
            function_owner,
            contract_ids_by_name,
            interface_ids_by_name,
            declaring_contract_for_var,
            visible_state_vars,
            state_var_ids_by_name,
        }
    }

    pub(crate) fn contract(&self, id: i32) -> Option<&Contract> {
        self.call_graph.contracts.get(&id)
    }

    pub(crate) fn interface(&self, id: i32) -> Option<&Interface> {
        self.call_graph.interfaces.get(&id)
    }

    pub(crate) fn state_variable(&self, id: i32) -> Option<&StateVariable> {
        self.storage_graph.state_variables.get(&id)
    }

    pub(crate) fn lookup_contract(&self, name: &str) -> Vec<i32> {
        self.contract_ids_by_name
            .get(&name.to_lowercase())
            .cloned()
            .unwrap_or_default()
    }

    pub(crate) fn lookup_interface(&self, name: &str) -> Vec<i32> {
        self.interface_ids_by_name
            .get(&name.to_lowercase())
            .cloned()
            .unwrap_or_default()
    }

    pub(crate) fn lookup_state_var(&self, name: &str) -> Vec<i32> {
        self.state_var_ids_by_name
            .get(&name.to_lowercase())
            .cloned()
            .unwrap_or_default()
    }

    /// True when `name` resolves to a project contract or interface.
    /// Used by the spec-builder tools to reject hallucinated contract
    /// references before they enter the draft.
    pub(crate) fn has_contract(&self, name: &str) -> bool {
        !self.lookup_contract(name).is_empty() || !self.lookup_interface(name).is_empty()
    }

    /// True when `key` resolves to a project state variable. Accepts a
    /// bare `fieldName` (matched anywhere in the project) or a qualified
    /// `Contract.field` (the field must be visible to that contract,
    /// inherited members included).
    pub(crate) fn has_state_variable(&self, key: &str) -> bool {
        let key = key.trim();
        match key.split_once('.') {
            Some((contract, field)) => {
                let var_ids = self.lookup_state_var(field.trim());
                if var_ids.is_empty() {
                    return false;
                }
                self.lookup_contract(contract.trim()).iter().any(|cid| {
                    self.visible_state_vars
                        .get(cid)
                        .map(|visible| var_ids.iter().any(|vid| visible.contains(vid)))
                        .unwrap_or(false)
                })
            }
            None => !self.lookup_state_var(key).is_empty(),
        }
    }

    /// True when project contract/interface `contract` declares — or
    /// inherits — a function named `function` (case-insensitive).
    pub(crate) fn contract_has_function(&self, contract: &str, function: &str) -> bool {
        let target = function.trim().to_lowercase();
        let declares = |cid: i32| {
            self.contract(cid)
                .map(|c| c.functions.iter().any(|f| f.name.to_lowercase() == target))
                .unwrap_or(false)
        };
        for cid in self.lookup_contract(contract) {
            if declares(cid) {
                return true;
            }
            if self
                .inheritance_graph
                .ancestors_of(cid)
                .into_iter()
                .any(declares)
            {
                return true;
            }
        }
        self.lookup_interface(contract).into_iter().any(|iid| {
            self.interface(iid)
                .map(|i| i.functions.iter().any(|f| f.name.to_lowercase() == target))
                .unwrap_or(false)
        })
    }

    pub(crate) fn render_interface_lookup(
        &self,
        interface: &Interface,
        focus_function: Option<&str>,
    ) -> String {
        let mut out = String::new();
        out.push_str(&format!(
            "## interface `{}` @ `{}` (id={})\n",
            interface.name,
            interface.relative_file_path.display(),
            interface.id
        ));
        let focus = focus_function.map(str::to_lowercase);
        for f in &interface.functions {
            if focus
                .as_deref()
                .map(|n| f.name.to_lowercase() == n)
                .unwrap_or(true)
            {
                out.push_str(&format!(
                    "- {}({}) @ {}:{} (id={})\n",
                    f.name,
                    f.args,
                    f.relative_file_path.display(),
                    f.loc.start_line,
                    f.id
                ));
            }
        }
        out
    }

    pub(crate) fn render_contract_lookup(
        &self,
        contract: &Contract,
        focus_function: Option<&str>,
    ) -> String {
        let mut out = String::new();
        out.push_str(&format!(
            "## contract `{}` @ `{}` (id={})\n",
            contract.name,
            contract.relative_file_path.display(),
            contract.id
        ));
        let focus = focus_function.map(str::to_lowercase);
        let matched: Vec<&Function> = contract
            .functions
            .iter()
            .filter(|f| {
                focus
                    .as_deref()
                    .map(|name| f.name.to_lowercase() == name)
                    .unwrap_or(true)
            })
            .collect();

        if focus.is_some() && matched.is_empty() {
            out.push_str(&format!(
                "no function matching `{}` in this contract; available functions:\n",
                focus_function.unwrap_or("")
            ));
            for f in &contract.functions {
                out.push_str(&format!(
                    "- {}({}) @ {}:{} (id={})\n",
                    f.name,
                    f.args,
                    f.relative_file_path.display(),
                    f.loc.start_line,
                    f.id
                ));
            }
            return out;
        }

        if focus.is_none() {
            out.push_str("Functions:\n");
            for f in &contract.functions {
                out.push_str(&format!(
                    "- {}({}) @ {}:{} (id={})\n",
                    f.name,
                    f.args,
                    f.relative_file_path.display(),
                    f.loc.start_line,
                    f.id
                ));
            }
            return out;
        }

        for function in matched {
            out.push_str(&format!(
                "\n### function `{}({})` @ {}:{} (id={})\n",
                function.name,
                function.args,
                function.relative_file_path.display(),
                function.loc.start_line,
                function.id
            ));
            if let Some(content) = &function.content {
                out.push_str("source:\n```solidity\n");
                out.push_str(content.trim_end());
                out.push_str("\n```\n");
            }
            out.push_str("\noutgoing calls:\n");
            if function.calls.is_empty() {
                out.push_str("- (none)\n");
            } else {
                for call in &function.calls {
                    out.push_str(&format!(
                        "- -> {}\n",
                        self.describe_endpoint(call.to_id, call)
                    ));
                }
            }
            out.push_str("\nincoming calls:\n");
            let mut incoming: Vec<&FunctionCall> = Vec::new();
            for c in self.call_graph.contracts.values() {
                for f in &c.functions {
                    for call in &f.calls {
                        if call.to_id == function.id {
                            incoming.push(call);
                        }
                    }
                }
            }
            for i in self.call_graph.interfaces.values() {
                for f in &i.functions {
                    for call in &f.calls {
                        if call.to_id == function.id {
                            incoming.push(call);
                        }
                    }
                }
            }
            if incoming.is_empty() {
                out.push_str("- (none in static analysis)\n");
            } else {
                for call in incoming {
                    out.push_str(&format!(
                        "- <- {}\n",
                        self.describe_endpoint(call.from_id, call)
                    ));
                }
            }
        }

        out
    }

    pub(crate) fn describe_function_xref(
        &self,
        function_id: i32,
        description: Option<&str>,
    ) -> String {
        let endpoint = match self.function_owner.get(&function_id) {
            Some(owner) => {
                let function_label = match owner.container_kind {
                    ContainerKind::Contract => self
                        .contract(owner.container_id)
                        .and_then(|c| c.functions.iter().find(|f| f.id == function_id))
                        .map(|f| format!("{}({})", f.name, f.args)),
                    ContainerKind::Interface => self
                        .interface(owner.container_id)
                        .and_then(|i| i.functions.iter().find(|f| f.id == function_id))
                        .map(|f| format!("{}({})", f.name, f.args)),
                }
                .unwrap_or_else(|| format!("function#{function_id}"));
                format!(
                    "{} {}::{} @ {}",
                    owner.container_kind.as_str(),
                    owner.container_name,
                    function_label,
                    owner.relative_file_path
                )
            }
            None => format!("(unknown owner) function#{function_id}"),
        };
        match description.map(str::trim).filter(|s| !s.is_empty()) {
            Some(desc) => format!("{endpoint} :: {desc}"),
            None => endpoint,
        }
    }

    pub(crate) fn describe_endpoint(&self, function_id: i32, call: &FunctionCall) -> String {
        let owner = self.function_owner.get(&function_id);
        let function_name = owner
            .and_then(|owner| match owner.container_kind {
                ContainerKind::Contract => self
                    .contract(owner.container_id)
                    .and_then(|c| c.functions.iter().find(|f| f.id == function_id))
                    .map(|f| format!("{}({})", f.name, f.args)),
                ContainerKind::Interface => self
                    .interface(owner.container_id)
                    .and_then(|i| i.functions.iter().find(|f| f.id == function_id))
                    .map(|f| format!("{}({})", f.name, f.args)),
            })
            .unwrap_or_else(|| format!("function#{function_id}"));
        let suffix = call
            .description
            .as_ref()
            .filter(|d| !d.trim().is_empty())
            .map(|d| format!(" :: {}", d.trim()))
            .unwrap_or_default();
        match owner {
            Some(owner) => format!(
                "{} {}::{} @ {}{suffix}",
                owner.container_kind.as_str(),
                owner.container_name,
                function_name,
                owner.relative_file_path,
            ),
            None => format!("(unknown owner) {}{}", function_name, suffix),
        }
    }
}

pub(crate) fn inheritance_closure(rows: &[ContractInherit]) -> BTreeMap<i32, BTreeSet<i32>> {
    let mut direct: BTreeMap<i32, BTreeSet<i32>> = BTreeMap::new();
    for row in rows {
        direct
            .entry(row.contract_id)
            .or_default()
            .insert(row.inherited_id);
    }
    let mut closure: BTreeMap<i32, BTreeSet<i32>> = BTreeMap::new();
    for &start in direct.keys() {
        let mut acc: BTreeSet<i32> = BTreeSet::new();
        let mut frontier: Vec<i32> = direct
            .get(&start)
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .collect();
        while let Some(node) = frontier.pop() {
            if !acc.insert(node) {
                continue;
            }
            if let Some(parents) = direct.get(&node) {
                for parent in parents {
                    if !acc.contains(parent) {
                        frontier.push(*parent);
                    }
                }
            }
        }
        closure.insert(start, acc);
    }
    closure
}

impl ProjectIndex {
    /// Render the agent's short-term memory: one entry per contract / interface
    /// in this index, holding state-var + function-signature indexes (bodies are
    /// fetched on demand via tools). Long-term memory is empty here — the link
    /// details live in the system prompt.
    /// The per-contract signature index an agent navigates by.
    ///
    /// The index is a map for finding bodies worth fetching, so under residency
    /// it should cover exactly the gaps in the resident block — an entry for a
    /// body already printed in the prompt is dead weight in every call of the
    /// conversation. [`MemoryScope`] says which gaps.
    pub(crate) fn build_link_memory(&self, scope: MemoryScope<'_>) -> Result<AgentMemoryContext> {
        let (only_contracts, only_interfaces) = match scope {
            MemoryScope::WholeProject => (None, None),
            MemoryScope::Only {
                contracts,
                interfaces,
            } => (Some(contracts), Some(interfaces)),
        };
        let mut short_term: BTreeMap<String, AgentMemoryContent> = BTreeMap::new();
        for contract in self.call_graph.contracts.values() {
            if only_contracts.is_some_and(|ids| !ids.contains(&contract.id)) {
                continue;
            }
            let title = format!(
                "{}:{}:{}:{}",
                contract.relative_file_path.display(),
                contract.name,
                contract.chunk.loc.start_line,
                contract.chunk.loc.start_column,
            );
            let content = self.render_contract_memory(contract);
            short_term.insert(
                title.clone(),
                AgentMemoryContent {
                    title,
                    related_context: format!(
                        "Index for contract {}: state variables (own + inherited) and function signatures with their outgoing calls. Bodies are NOT inlined — use `read_function_source` or `read_contract_source` to fetch source on demand.",
                        contract.name
                    ),
                    trigger_scenario:
                        "Read this index when you need to find the right function/state variable to inspect. Then call `read_function_source(contract, function)` for that one body — read by function, not whole-file, unless you really need the full file."
                            .to_string(),
                    content,
                    raw_content: None,
                },
            );
        }
        for interface in self.call_graph.interfaces.values() {
            if only_interfaces.is_some_and(|ids| !ids.contains(&interface.id)) {
                continue;
            }
            let title = format!(
                "{}:{}:{}:{}",
                interface.relative_file_path.display(),
                interface.name,
                interface.chunk.loc.start_line,
                interface.chunk.loc.start_column,
            );
            let content = self.render_interface_memory(interface);
            short_term.insert(
                title.clone(),
                AgentMemoryContent {
                    title,
                    related_context: format!(
                        "Function declarations of interface {} (signatures only; use `read_contract_source` if you need the raw interface text)",
                        interface.name
                    ),
                    trigger_scenario:
                        "Read this entry when a contract calls an interface and you need its declared signatures"
                            .to_string(),
                    content,
                    raw_content: None,
                },
            );
        }

        Ok(AgentMemoryContext::new_without_search(AgentMemory {
            long_term: BTreeMap::new(),
            short_term,
        }))
    }

    /// Append one contract's source in the form every consumer expects: a
    /// `## contract` header naming the KG identity, then the raw body in a
    /// fenced block. Shared by the `read_contract_source` tool and by
    /// [`Self::resident_candidates`], so an agent that reads source on demand
    /// and an agent that gets it resident in its prompt see byte-identical
    /// text.
    pub(crate) fn push_contract_source(&self, out: &mut String, contract: &Contract) {
        out.push_str(&format!(
            "## contract `{}` @ `{}` (id={})\n```solidity\n{}\n```\n---\n",
            contract.name,
            contract.relative_file_path.display(),
            contract.id,
            contract.chunk.content.trim_end(),
        ));
    }

    /// Interface counterpart of [`Self::push_contract_source`].
    pub(crate) fn push_interface_source(&self, out: &mut String, interface: &Interface) {
        out.push_str(&format!(
            "## interface `{}` @ `{}` (id={})\n```solidity\n{}\n```\n---\n",
            interface.name,
            interface.relative_file_path.display(),
            interface.id,
            interface.chunk.content.trim_end(),
        ));
    }

    /// The project's own contracts and interfaces, each rendered on its own, in
    /// the order a resident block should try to fit them.
    ///
    /// Vendored and non-production trees are dropped. The call graph carries
    /// them — it has to, since resolving an inherited or imported symbol needs
    /// the dependency's source — but they can outweigh the project's own code:
    /// on a mid-sized Foundry project the vendored trees were 45% of the text,
    /// and dropping them halved the resident block. Since that block is re-read
    /// on every call of every link, carrying a dependency tree in it is the most
    /// expensive thing an agent never reads. The source tools reach those trees
    /// instead.
    ///
    /// `include_lib` carries the project's `--include-lib-sources` setting: with
    /// it set, `lib/` holds the project's own implementation rather than its
    /// dependencies, and dropping it here would leave the audited code out of
    /// both the resident block and the signature index that covers what the
    /// block omits.
    ///
    /// Each candidate carries its call-graph degree and its path; the packing
    /// order is
    /// [`crate::source_access::ProjectSourceAccess::resolve`]'s decision, since
    /// that is where the budget lives.
    pub(crate) fn resident_candidates(&self, include_lib: bool) -> Vec<ResidentCandidate> {
        // Degree per owning contract: every call is counted once for the caller
        // and once for the callee, so a hub scores on both sides.
        let mut degree: BTreeMap<i32, usize> = BTreeMap::new();
        for contract in self.call_graph.contracts.values() {
            for function in &contract.functions {
                *degree.entry(contract.id).or_default() += function.calls.len();
                for call in &function.calls {
                    if let Some(owner) = self.function_owner.get(&call.to_id) {
                        *degree.entry(owner.container_id).or_default() += 1;
                    }
                }
            }
        }

        let mut out: Vec<ResidentCandidate> = Vec::new();
        for contract in self.call_graph.contracts.values() {
            if knowdit_project::ProjectScope::is_vendored_path(
                &contract.relative_file_path,
                include_lib,
            ) {
                continue;
            }
            let mut source = String::new();
            self.push_contract_source(&mut source, contract);
            out.push(ResidentCandidate {
                id: contract.id,
                is_interface: false,
                name: contract.name.clone(),
                relative_file_path: contract.relative_file_path.display().to_string(),
                degree: degree.get(&contract.id).copied().unwrap_or_default(),
                source,
            });
        }
        for interface in self.call_graph.interfaces.values() {
            if knowdit_project::ProjectScope::is_vendored_path(
                &interface.relative_file_path,
                include_lib,
            ) {
                continue;
            }
            let mut source = String::new();
            self.push_interface_source(&mut source, interface);
            out.push(ResidentCandidate {
                id: interface.id,
                is_interface: true,
                name: interface.name.clone(),
                relative_file_path: interface.relative_file_path.display().to_string(),
                degree: 0,
                source,
            });
        }
        out
    }

    fn render_contract_memory(&self, contract: &Contract) -> String {
        let mut out = String::new();
        out.push_str(&format!(
            "# Contract `{}` @ `{}`\n\n",
            contract.name,
            contract.relative_file_path.display()
        ));
        if let Some(desc) = &contract.description
            && !desc.trim().is_empty()
        {
            out.push_str(&format!("Description: {}\n\n", desc.trim()));
        }
        out.push_str("## State variables (own + inherited)\n");
        let visible_ids = self
            .visible_state_vars
            .get(&contract.id)
            .cloned()
            .unwrap_or_default();
        if visible_ids.is_empty() {
            out.push_str("- (none)\n");
        } else {
            for var_id in &visible_ids {
                if let Some(var) = self.state_variable(*var_id) {
                    let owner_id = self.declaring_contract_for_var.get(var_id).copied();
                    let owner = owner_id
                        .and_then(|id| self.contract(id))
                        .map(|c| c.name.as_str())
                        .unwrap_or("?");
                    let inherited = owner_id != Some(contract.id);
                    out.push_str(&format!(
                        "- {} {} ({}{})\n  declaration: `{}` @ {}:{}\n",
                        var.type_name.trim(),
                        var.name,
                        owner,
                        if inherited { ", inherited" } else { "" },
                        var.content.trim().lines().next().unwrap_or("").trim(),
                        var.relative_file_path.display(),
                        var.loc.start_line,
                    ));
                }
            }
        }

        out.push_str(
            "\n## Functions (full signatures + outgoing calls; use `read_function_source` for a single function body or `read_contract_source` for the whole file)\n",
        );
        if contract.functions.is_empty() {
            out.push_str("- (none)\n");
        } else {
            for function in &contract.functions {
                let sig = self.render_function_signature(function);
                out.push_str(&format!(
                    "- {} @ {}:{} (id={})\n",
                    sig,
                    function.relative_file_path.display(),
                    function.loc.start_line,
                    function.id,
                ));
                for call in &function.calls {
                    out.push_str(&format!(
                        "  -> {}\n",
                        self.describe_endpoint(call.to_id, call)
                    ));
                }
            }
        }

        out
    }

    /// Lives on `ProjectIndex` for symmetry with [`Self::render_contract_memory`]
    /// even though an interface index needs no project-wide lookups.
    fn render_interface_memory(&self, interface: &Interface) -> String {
        let mut out = String::new();
        out.push_str(&format!(
            "# Interface `{}` @ `{}`\n\n",
            interface.name,
            interface.relative_file_path.display()
        ));
        out.push_str(
            "## Function declarations (full signatures; use `read_contract_source` for the full interface text)\n",
        );
        for function in &interface.functions {
            let sig = self.render_function_signature(function);
            out.push_str(&format!(
                "- {} @ {}:{} (id={})\n",
                sig,
                function.relative_file_path.display(),
                function.loc.start_line,
                function.id,
            ));
        }
        out
    }

    /// Render a function's full Solidity signature line (including visibility,
    /// mutability, and return types) via the tree-sitter extractor in
    /// `knowdit-sol`. Falls back to the bare `name(args)` form when there is no
    /// body content (interface declarations) or the source can't be parsed.
    fn render_function_signature(&self, function: &Function) -> String {
        if let Some(source) = function.content.as_deref()
            && let Ok(Some(sig)) = knowdit_sol::signature::extract_function_signature(source)
        {
            return format!("`{sig}`");
        }
        format!("`{}({})`", function.name, function.args)
    }
}
