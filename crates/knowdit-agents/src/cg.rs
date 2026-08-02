use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    fmt,
    path::{Path, PathBuf},
    sync::Arc,
};

use color_eyre::eyre::{ContextCompat, WrapErr, ensure};
use knowdit_kg::learn::ExtractedSemantic;
use knowdit_repo_model::cg::{
    CallGraph, Contract, FileChunk, FileLocation, Function, FunctionCall, Interface,
};
use knowdit_sol::cg::{
    ExtractedCallable, ExtractedContract, SolidityCallableKind, SolidityContractKind,
    SolidityExtractionConfig, SolidityFunctionNodeKind, extract_repo_contracts_functions,
};
use llmy::{
    agent::{
        LLMYError, StepResult,
        tool::ToolBox,
        tools::{
            files::ReadFileTool,
            memory::{AgentMemory, AgentMemoryContent, AgentMemoryContext},
        },
    },
    client::{client::LLM, settings::LLMSettings},
    harness::{Agent, memory::AgentMemorySystemPromptCriteria},
};
use schemars::JsonSchema;
use serde::Deserialize;
use tokio::sync::Mutex;

use crate::prompt::{self, FunctionAgentPromptInput};

/// Configuration for the llmy-powered Solidity repository callgraph agent.
#[derive(Debug, Clone)]
pub struct CallGraphAgentConfig {
    /// Source collection and tree-sitter extraction settings.
    pub extraction: SolidityExtractionConfig,
    /// Maximum llmy steps for each per-callable agent.
    pub max_agent_steps: usize,
    /// Maximum times a known non-terminal leaf may be re-analyzed before failing completion.
    pub max_leaf_completion_attempts: usize,
    /// Optional debug prefix passed to llmy.
    pub debug_prefix: Option<String>,
    /// Optional per-call llmy settings.
    pub llm_settings: Option<LLMSettings>,
    /// Memory prompt criteria for deciding long-term and short-term memory behavior.
    pub memory_prompt_criteria: AgentMemorySystemPromptCriteria,
}

impl CallGraphAgentConfig {
    pub fn new(
        extraction: SolidityExtractionConfig,
        max_agent_steps: usize,
        max_leaf_completion_attempts: usize,
        debug_prefix: Option<String>,
        llm_settings: Option<LLMSettings>,
    ) -> Self {
        Self {
            extraction,
            max_agent_steps,
            max_leaf_completion_attempts,
            debug_prefix,
            llm_settings,
            memory_prompt_criteria: prompt::default_memory_prompt_criteria(),
        }
    }
}

/// Result of a callgraph agent run, including the memory context for inspection or reuse.
#[derive(Debug, Clone)]
pub struct CallGraphAgentResult {
    pub call_graph: CallGraph,
    pub terminal_nodes: Vec<CallGraphTerminalNode>,
    /// Plain-text summaries returned by per-callable agents.
    pub final_response: String,
    pub steps: usize,
    pub memory: AgentMemoryContext,
}

#[derive(Debug, Clone)]
pub struct CallGraphTerminalNode {
    pub label: String,
    pub reason: String,
    pub description: Option<String>,
}

/// Analyze a Solidity repository with llmy agents and return a repository call graph.
pub async fn analyze_repo_call_graph(
    llm: &LLM,
    config: CallGraphAgentConfig,
    semantics: &[ExtractedSemantic],
) -> Result<CallGraphAgentResult, color_eyre::Report> {
    ensure!(
        config.max_leaf_completion_attempts > 0,
        "max_leaf_completion_attempts must be greater than zero"
    );
    let extraction = extract_repo_contracts_functions(&config.extraction).await?;

    let memory = build_agent_memory(semantics, &extraction.contracts).await?;
    let mut runner = FunctionAgentRunner::new(
        config,
        extraction.repo_root,
        extraction.source_files,
        extraction.analysis_source_files,
        extraction.contracts,
        semantics.len(),
    );
    let run = runner.run(llm, &memory).await?;

    Ok(CallGraphAgentResult {
        call_graph: run.call_graph,
        terminal_nodes: run.terminal_nodes,
        final_response: run.final_response,
        steps: run.steps,
        memory,
    })
}

async fn build_agent_memory(
    semantics: &[ExtractedSemantic],
    contracts: &[ExtractedContract],
) -> Result<AgentMemoryContext, color_eyre::Report> {
    let mut long_term = BTreeMap::new();

    let overview = render_semantic_overview(semantics);
    long_term.insert(
        "project-semantics-overview".to_string(),
        AgentMemoryContent {
            title: "project-semantics-overview".to_string(),
            related_context: "Known project categories and semantic domains".to_string(),
            trigger_scenario:
                "Before deciding which Solidity contracts and functions are semantically important"
                    .to_string(),
            content: overview,
            raw_content: Some(
                serde_json::to_string_pretty(semantics)
                    .wrap_err("failed to serialize extracted semantics for memory")?,
            ),
        },
    );

    for (index, semantic) in semantics.iter().enumerate() {
        let title = format!(
            "semantic:{}:{}",
            index + 1,
            sanitize_memory_title(&semantic.name)
        );
        long_term.insert(
            title.clone(),
            AgentMemoryContent {
                title,
                related_context: format!("Project semantic category {:?}", semantic.category),
                trigger_scenario:
                    "When mapping contracts, functions, and calls to protocol-level behavior"
                        .to_string(),
                content: render_semantic_memory_entry(semantic),
                raw_content: Some(
                    serde_json::to_string_pretty(semantic).wrap_err_with(|| {
                        format!("failed to serialize semantic {}", semantic.name)
                    })?,
                ),
            },
        );
    }

    let short_term = contracts
        .iter()
        .map(|contract| {
            let title = contract_memory_title(contract);
            (
                title.clone(),
                AgentMemoryContent {
                    title,
                    related_context: format!(
                        "Tree-sitter Solidity callable index for {}::{}",
                        contract.relative_file_path.display(),
                        contract.name
                    ),
                    trigger_scenario:
                        "When resolving callees, inherited/imported targets, overload line numbers/columns, or exact record_call_relation selectors"
                            .to_string(),
                    content: render_contract_callable_memory_entry(contract),
                    raw_content: None,
                },
            )
        })
        .collect::<BTreeMap<_, _>>();

    Ok(AgentMemoryContext::new_without_search(AgentMemory {
        long_term,
        short_term,
    }))
}

struct FunctionAgentRunResult {
    summary: String,
    steps: usize,
}

struct FunctionAgentRunnerResult {
    call_graph: CallGraph,
    terminal_nodes: Vec<CallGraphTerminalNode>,
    final_response: String,
    steps: usize,
}

#[derive(Debug, Clone)]
struct FunctionAgentRunner {
    config: CallGraphAgentConfig,
    repo_root: PathBuf,
    extracted_contracts: Vec<ExtractedContract>,
    contracts_by_id: BTreeMap<i32, ExtractedContract>,
    index: Arc<CallGraphIndex>,
    relation_store: SharedCallRelations,
    terminal_store: SharedTerminalNodes,
    source_manifest: String,
    semantics_count: usize,
    root_function_ids: BTreeSet<i32>,
    analyzed_function_ids: BTreeSet<i32>,
    queued_function_ids: BTreeSet<i32>,
    analysis_attempts: BTreeMap<i32, usize>,
    queue: VecDeque<i32>,
    summaries: Vec<String>,
    total_steps: usize,
}

impl FunctionAgentRunner {
    fn new(
        config: CallGraphAgentConfig,
        repo_root: PathBuf,
        source_files: Vec<PathBuf>,
        analysis_source_files: Vec<PathBuf>,
        extracted_contracts: Vec<ExtractedContract>,
        semantics_count: usize,
    ) -> Self {
        let index = Arc::new(CallGraphIndex::new(
            &extracted_contracts,
            &analysis_source_files,
        ));
        let root_function_ids = index.function_ids().into_iter().collect::<BTreeSet<_>>();
        let queue = VecDeque::from(root_function_ids.iter().copied().collect::<Vec<_>>());
        let queued_function_ids = queue.iter().copied().collect::<BTreeSet<_>>();
        let contracts_by_id = extracted_contracts
            .iter()
            .cloned()
            .map(|contract| (contract.id, contract))
            .collect::<BTreeMap<_, _>>();
        let source_manifest = render_source_manifest(&source_files, &analysis_source_files);
        let terminal_store = SharedTerminalNodes::with_initial(index.automatic_terminal_nodes());

        Self {
            config,
            repo_root,
            extracted_contracts,
            contracts_by_id,
            index,
            relation_store: SharedCallRelations::default(),
            terminal_store,
            source_manifest,
            semantics_count,
            root_function_ids,
            analyzed_function_ids: BTreeSet::new(),
            queued_function_ids,
            analysis_attempts: BTreeMap::new(),
            queue,
            summaries: Vec::new(),
            total_steps: 0,
        }
    }

    async fn run(
        &mut self,
        llm: &LLM,
        memory: &AgentMemoryContext,
    ) -> Result<FunctionAgentRunnerResult, color_eyre::Report> {
        loop {
            while let Some(function_id) = self.queue.pop_front() {
                self.queued_function_ids.remove(&function_id);
                if self.terminal_store.contains_known(function_id).await {
                    continue;
                }

                let attempts = self.analysis_attempts.entry(function_id).or_default();
                *attempts += 1;
                ensure!(
                    *attempts <= self.config.max_leaf_completion_attempts,
                    "callgraph leaf {} remained non-terminal after {} analysis attempts; recorded outgoing call edges or call record_terminal_node with an appropriate reason",
                    self.index
                        .function(function_id)
                        .map(FunctionIndexEntry::label)
                        .unwrap_or_else(|| format!("known function id {function_id}")),
                    self.config.max_leaf_completion_attempts
                );

                let function = self
                    .index
                    .function(function_id)
                    .cloned()
                    .wrap_err_with(|| format!("missing function index entry {function_id}"))?;
                let contract = self
                    .contracts_by_id
                    .get(&function.contract_id)
                    .cloned()
                    .wrap_err_with(|| {
                        format!(
                            "missing contract {} for function {}",
                            function.contract_id, function_id
                        )
                    })?;

                let run = self
                    .run_function_agent(llm, memory, contract, function)
                    .await?;

                self.total_steps += run.steps;
                self.summaries.push(run.summary);
                self.analyzed_function_ids.insert(function_id);
                self.queue_non_terminal_leaves().await?;
            }

            self.queue_non_terminal_leaves().await?;
            if self.queue.is_empty() {
                break;
            }
        }

        ensure!(
            self.non_terminal_leaf_nodes().await?.is_empty(),
            "callgraph completion failed with non-terminal leaves still present but no runnable target was queued"
        );

        let call_graph = self.export_call_graph().await?;
        let terminal_nodes = self.render_terminal_nodes().await;
        Ok(FunctionAgentRunnerResult {
            call_graph,
            terminal_nodes,
            final_response: self.summaries.join("\n\n"),
            steps: self.total_steps,
        })
    }

    async fn queue_non_terminal_leaves(&mut self) -> Result<(), color_eyre::Report> {
        for node in self.non_terminal_leaf_nodes().await? {
            match node {
                CallGraphNode::Known(function_id) => {
                    let function = self
                        .index
                        .function(function_id)
                        .wrap_err_with(|| format!("missing function index entry {function_id}"))?;
                    if function.node_kind == SolidityFunctionNodeKind::InterfaceFunctionDeclaration
                    {
                        self.terminal_store
                            .record(RecordedTerminalNode {
                                target: CallGraphNode::Known(function_id),
                                reason: TerminalNodeReason::InterfaceFunction,
                                description: Some("interface function declaration".to_string()),
                            })
                            .await;
                    } else if function.node_kind.is_definition()
                        && self.queued_function_ids.insert(function_id)
                    {
                        self.queue.push_back(function_id);
                    }
                }
                CallGraphNode::External(endpoint) => {
                    self.terminal_store
                        .record(RecordedTerminalNode {
                            target: CallGraphNode::External(endpoint),
                            reason: TerminalNodeReason::MissingTreeSitterNode,
                            description: Some(
                                "callee selector was not found by tree-sitter extraction"
                                    .to_string(),
                            ),
                        })
                        .await;
                }
            }
        }
        Ok(())
    }

    async fn non_terminal_leaf_nodes(&self) -> Result<Vec<CallGraphNode>, color_eyre::Report> {
        let calls = self.relation_store.list().await;
        let terminals = self.terminal_store.list().await;
        Ok(non_terminal_leaf_nodes(
            &self.root_function_ids,
            &calls,
            &terminals,
        ))
    }

    async fn render_terminal_nodes(&self) -> Vec<CallGraphTerminalNode> {
        self.terminal_store
            .list()
            .await
            .into_iter()
            .map(|terminal| CallGraphTerminalNode {
                label: terminal.target.label(&self.index),
                reason: terminal.reason.as_str().to_string(),
                description: terminal.description,
            })
            .collect()
    }

    async fn export_call_graph(&self) -> Result<CallGraph, color_eyre::Report> {
        let recorded_calls = self.relation_store.list().await;
        let terminal_nodes = self.terminal_store.list().await;
        ensure!(
            non_terminal_leaf_nodes(&self.root_function_ids, &recorded_calls, &terminal_nodes)
                .is_empty(),
            "cannot export incomplete callgraph with non-terminal leaf nodes"
        );
        let call_graph = build_call_graph(&self.extracted_contracts, &recorded_calls);
        validate_call_graph(&call_graph)?;
        Ok(call_graph)
    }

    async fn run_function_agent(
        &self,
        llm: &LLM,
        memory: &AgentMemoryContext,
        contract: ExtractedContract,
        function: FunctionIndexEntry,
    ) -> Result<FunctionAgentRunResult, color_eyre::Report> {
        let mut tools = ToolBox::new();
        tools.add_tool(ReadFileTool::new(self.repo_root.clone()));
        let mut analyzed_snapshot = self.analyzed_function_ids.clone();
        analyzed_snapshot.remove(&function.id);
        tools.add_tool(RecordCallRelationTool::new(
            self.index.clone(),
            self.relation_store.clone(),
            self.terminal_store.clone(),
            Arc::new(analyzed_snapshot.clone()),
        ));
        tools.add_tool(RecordTerminalNodeTool::new(
            self.index.clone(),
            self.relation_store.clone(),
            self.terminal_store.clone(),
        ));

        let debug_prefix = self.config.debug_prefix.clone();
        tracing::info!(
            contract = %contract,
            function = %function,
            attempt = self.analysis_attempts.get(&function.id).copied().unwrap_or_default(),
            analyzed_functions = self.analyzed_function_ids.len(),
            queued_functions = self.queue.len(),
            recorded_calls = self.relation_store.list().await.len(),
            terminal_nodes = self.terminal_store.list().await.len(),
            "starting Solidity callgraph function agent"
        );
        let mut agent = Agent::with_memory(
            prompt::function_agent_system_prompt(),
            tools,
            None,
            memory,
            &self.config.memory_prompt_criteria,
        )
        .await;

        let user_prompt = prompt::function_agent_user_prompt(FunctionAgentPromptInput {
            source_manifest: self.source_manifest.clone(),
            analyzed_functions_manifest: self.index.render_analyzed_manifest(&analyzed_snapshot),
            start_contract_label: format!(
                "{} {} ({})",
                contract.kind.as_str(),
                contract.name,
                contract.relative_file_path.display()
            ),
            start_contract_source: contract.chunk.content,
            start_function_label: function.to_string(),
            start_function_selector: function.selector_manifest(),
            start_function_source: function.chunk.content.clone(),
            semantic_count: self.semantics_count,
        });

        let mut steps = 1;
        let function_str = function.to_string();
        let mut step_result = agent
            .step_with_user(
                user_prompt,
                llm,
                debug_prefix.as_deref(),
                self.config.llm_settings.clone(),
            )
            .await
            .wrap_err_with(|| {
                format!(
                    "callgraph agent failed on initial step for {}",
                    function_str
                )
            })?;

        loop {
            if let StepResult::Stop(summary) = step_result {
                return Ok(FunctionAgentRunResult {
                    summary: format!("{}\n{}", function_str, summary.trim()),
                    steps,
                });
            }

            ensure!(
                steps < self.config.max_agent_steps,
                "callgraph agent exceeded max_agent_steps={} while analyzing {}",
                self.config.max_agent_steps,
                function_str
            );

            steps += 1;
            step_result = agent
                .step(
                    llm,
                    debug_prefix.as_deref(),
                    self.config.llm_settings.clone(),
                )
                .await
                .wrap_err_with(|| {
                    format!(
                        "callgraph agent failed at step {steps} for {}",
                        function_str
                    )
                })?;
        }
    }
}

#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct CallEndpointSelector {
    /// Source file path relative to the repository root.
    #[serde(default)]
    pub relative_file_path: Option<PathBuf>,
    /// 1-based callable start line from the tree-sitter callable index `loc` range.
    #[serde(default)]
    pub line_number: Option<usize>,
    /// 0-based callable start column from the tree-sitter callable index `loc` range.
    #[serde(default)]
    pub line_column: Option<usize>,
    /// Contract/interface/library name from the tree-sitter callable index.
    pub contract: String,
    /// Callable name from the tree-sitter callable index.
    pub name: String,
    /// Optional callable kind for readability. It is ignored for endpoint matching.
    #[serde(default)]
    pub kind: Option<String>,
    /// Optional Solidity parameter-list text for readability. It is ignored for endpoint matching.
    /// For example: "uint256 amount, address recipient". Empty string means no args.
    #[serde(default)]
    pub args: Option<String>,
}

impl CallEndpointSelector {
    fn label(&self) -> String {
        format!(
            "relative_file_path={:?}; line_number={:?}; line_column={:?}; contract={}; name={}; kind={:?}; args={:?}",
            self.relative_file_path,
            self.line_number,
            self.line_column,
            self.contract,
            self.name,
            self.kind,
            self.args
        )
    }
}

#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct RecordCallRelationArgs {
    pub caller: CallEndpointSelector,
    pub callee: CallEndpointSelector,
    /// Context for this call edge, such as forwarding, validation, accounting, liquidity updates,
    /// oracle reads, or access-control checks. Include Project Semantic context when relevant.
    #[serde(default)]
    pub description: Option<String>,
}

#[derive(Debug, Clone, Copy, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum TerminalNodeReasonArg {
    NoExternalCall,
    MissingTreeSitterNode,
    InterfaceFunction,
}

#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct RecordTerminalNodeArgs {
    pub node: CallEndpointSelector,
    /// Why this callgraph node is terminal: no_external_call, missing_tree_sitter_node, or interface_function.
    pub reason: TerminalNodeReasonArg,
    /// Evidence or source context for the terminal decision.
    #[serde(default)]
    pub description: Option<String>,
}

#[derive(Debug, Clone)]
#[llmy::agent::tool(
    arguments = RecordTerminalNodeArgs,
    invoke = record_terminal_node,
    name = "record_terminal_node",
    description = "Record that one Solidity callgraph node is terminal. Use reason=no_external_call after inspecting a concrete implementation and confirming it has no outgoing repository-local or external dependency calls. Use reason=missing_tree_sitter_node only after confirming the selector is not present in the tree-sitter callable index memory; call this before record_call_relation for a confirmed external or missing-tree-sitter callee. Use reason=interface_function for interface declarations. Repeated calls are accepted and idempotent. Prefer relative_file_path, contract, and name first; add line_number/line_column only when the tool reports ambiguity.",
)]
struct RecordTerminalNodeTool {
    index: Arc<CallGraphIndex>,
    calls: SharedCallRelations,
    terminals: SharedTerminalNodes,
}

impl RecordTerminalNodeTool {
    fn new(
        index: Arc<CallGraphIndex>,
        calls: SharedCallRelations,
        terminals: SharedTerminalNodes,
    ) -> Self {
        Self {
            index,
            calls,
            terminals,
        }
    }

    async fn record_terminal_node(
        &self,
        args: RecordTerminalNodeArgs,
    ) -> Result<String, LLMYError> {
        let reason = TerminalNodeReason::from_arg(args.reason);
        let matches = self.index.select_endpoint(&args.node);
        let matches_without_location = self.index.select_endpoint_without_location(&args.node);
        if let Some(message) = missing_required_endpoint_fields_message(
            "terminal node",
            &args.node,
            &matches_without_location,
        ) {
            return Ok(message);
        }
        if matches.is_empty()
            && let Some(message) = location_filtered_endpoint_message(
                "terminal node",
                &args.node,
                &matches_without_location,
            )
        {
            return Ok(message);
        }
        let target = match matches.as_slice() {
            [node] => match reason {
                TerminalNodeReason::NoExternalCall => {
                    if node.node_kind == SolidityFunctionNodeKind::InterfaceFunctionDeclaration {
                        CallGraphNode::Known(node.id)
                    } else if node.node_kind.is_definition() {
                        CallGraphNode::Known(node.id)
                    } else {
                        let message = format!(
                            "terminal node not recorded: reason=no_external_call requires a concrete callable implementation, but the selector matched a non-definition callable. Re-check the short-term callable index memory and retry with reason=interface_function for an interface declaration, or use a concrete implementation selector if one exists: {}",
                            node.label()
                        );
                        tracing::warn!(
                            selector = %args.node.label(),
                            matched = %node.label(),
                            reason = reason.as_str(),
                            instruction = %message,
                            "record_terminal_node returned repair instruction"
                        );
                        return Ok(message);
                    }
                }
                TerminalNodeReason::InterfaceFunction => {
                    if node.node_kind != SolidityFunctionNodeKind::InterfaceFunctionDeclaration {
                        let message = format!(
                            "terminal node not recorded: reason=interface_function requires an interface function declaration, but the selector matched a concrete callable. Inspect the callable body; if it has no outgoing calls, retry record_terminal_node with reason=no_external_call, otherwise record its outgoing edges with record_call_relation: {}",
                            node.label()
                        );
                        tracing::warn!(
                            selector = %args.node.label(),
                            matched = %node.label(),
                            reason = reason.as_str(),
                            instruction = %message,
                            "record_terminal_node returned repair instruction"
                        );
                        return Ok(message);
                    }
                    CallGraphNode::Known(node.id)
                }
                TerminalNodeReason::MissingTreeSitterNode => {
                    return Ok(format!(
                        "selector is present in the tree-sitter callable index, so missing_tree_sitter_node is not applicable: {}",
                        node.label()
                    ));
                }
            },
            [] => match reason {
                TerminalNodeReason::MissingTreeSitterNode => {
                    CallGraphNode::External(ExternalEndpoint::from_selector(&args.node))
                }
                TerminalNodeReason::NoExternalCall | TerminalNodeReason::InterfaceFunction => {
                    return Ok(format!(
                        "selector did not match a known callable. Use reason=missing_tree_sitter_node if this is intentionally an external/missing tree-sitter node: {}",
                        args.node.label()
                    ));
                }
            },
            many => {
                return Ok(ambiguous_endpoint_message(
                    "terminal node",
                    &args.node,
                    many,
                ));
            }
        };

        let inserted = self
            .terminals
            .record(RecordedTerminalNode {
                target: target.clone(),
                reason,
                description: args.description,
            })
            .await;
        if reason == TerminalNodeReason::NoExternalCall
            && let CallGraphNode::Known(function_id) = &target
            && self.calls.has_outgoing(*function_id).await
        {
            self.terminals
                .remove(&CallGraphNode::Known(*function_id))
                .await;
            let target = self
                .index
                .function(*function_id)
                .map(FunctionIndexEntry::label)
                .unwrap_or_else(|| format!("known function id {function_id}"));
            let message = format!(
                "terminal node not recorded: {} already has outgoing call edges",
                target
            );
            tracing::warn!(
                target = %target,
                reason = reason.as_str(),
                instruction = %message,
                "record_terminal_node returned repair instruction"
            );
            return Ok(message);
        }
        Ok(format!(
            "terminal node {}: {} ({})",
            if inserted {
                "recorded"
            } else {
                "already recorded"
            },
            target.label(&self.index),
            reason.as_str()
        ))
    }
}

#[derive(Debug, Clone)]
#[llmy::agent::tool(
    arguments = RecordCallRelationArgs,
    invoke = record_call_relation,
    name = "record_call_relation",
    description = "Record one Solidity call edge by endpoint selectors after both endpoints are known or explicitly confirmed. For the first attempt, pass relative_file_path, contract, and name, and omit line_number/line_column; if the tool reports ambiguity, retry with the exact line_number/line_column from one returned candidate. This tool does not create missing callees. If the callee selector is absent from the tree-sitter callable index, no edge is recorded; confirm it with record_terminal_node reason=missing_tree_sitter_node, then call record_call_relation again. Do not pass ids; ids are resolved and assigned by the Rust caller. The optional description explains the call context, such as forwarding, validation, liquidity updates, accounting, oracle reads, or access-control checks; include Project Semantic context when relevant. The result tells whether the caller or callee is already fully analyzed and whether the agent should stop that recursive branch.",
)]
struct RecordCallRelationTool {
    index: Arc<CallGraphIndex>,
    calls: SharedCallRelations,
    terminals: SharedTerminalNodes,
    analyzed_function_ids: Arc<BTreeSet<i32>>,
}

impl RecordCallRelationTool {
    fn new(
        index: Arc<CallGraphIndex>,
        calls: SharedCallRelations,
        terminals: SharedTerminalNodes,
        analyzed_function_ids: Arc<BTreeSet<i32>>,
    ) -> Self {
        Self {
            index,
            calls,
            terminals,
            analyzed_function_ids,
        }
    }

    async fn record_call_relation(
        &self,
        args: RecordCallRelationArgs,
    ) -> Result<String, LLMYError> {
        let caller_matches = self.index.select_endpoint(&args.caller);
        let caller_matches_without_location =
            self.index.select_endpoint_without_location(&args.caller);
        if let Some(message) = missing_required_endpoint_fields_message(
            "caller",
            &args.caller,
            &caller_matches_without_location,
        ) {
            tracing::warn!(
                reason = "caller_missing_required_fields",
                caller = %args.caller.label(),
                callee = %args.callee.label(),
                instruction = %message,
                "record_call_relation returned repair instruction"
            );
            return Ok(message);
        }
        if caller_matches.is_empty()
            && let Some(message) = location_filtered_endpoint_message(
                "caller",
                &args.caller,
                &caller_matches_without_location,
            )
        {
            tracing::warn!(
                reason = "caller_location_mismatch",
                caller = %args.caller.label(),
                callee = %args.callee.label(),
                instruction = %message,
                "record_call_relation returned repair instruction"
            );
            return Ok(message);
        }
        let caller = match caller_matches.as_slice() {
            [caller] => caller.clone(),
            [] => {
                let message = format!(
                    "caller selector did not match any known callable, so no call edge was recorded. Use the exact caller selector from the starting callable prompt or short-term callable index memory and call record_call_relation again: {}",
                    args.caller.label()
                );
                tracing::warn!(
                    reason = "caller_unknown_selector",
                    caller = %args.caller.label(),
                    callee = %args.callee.label(),
                    instruction = %message,
                    "record_call_relation returned repair instruction"
                );
                return Ok(message);
            }
            many => {
                let message = ambiguous_endpoint_message("caller", &args.caller, many);
                tracing::warn!(
                    reason = "caller_ambiguous_selector",
                    caller = %args.caller.label(),
                    callee = %args.callee.label(),
                    instruction = %message,
                    "record_call_relation returned repair instruction"
                );
                return Ok(message);
            }
        };

        let callee_matches = self.index.select_endpoint(&args.callee);
        let callee_matches_without_location =
            self.index.select_endpoint_without_location(&args.callee);
        if let Some(message) = missing_required_endpoint_fields_message(
            "callee",
            &args.callee,
            &callee_matches_without_location,
        ) {
            tracing::warn!(
                reason = "callee_missing_required_fields",
                caller = %args.caller.label(),
                callee = %args.callee.label(),
                instruction = %message,
                "record_call_relation returned repair instruction"
            );
            return Ok(message);
        }
        if callee_matches.is_empty()
            && let Some(message) = location_filtered_endpoint_message(
                "callee",
                &args.callee,
                &callee_matches_without_location,
            )
        {
            tracing::warn!(
                reason = "callee_location_mismatch",
                caller = %args.caller.label(),
                callee = %args.callee.label(),
                instruction = %message,
                "record_call_relation returned repair instruction"
            );
            return Ok(message);
        }
        let (target, callee_label, callee_found_in_callable_index, callee_is_analyzed) =
            match callee_matches.as_slice() {
                [callee] => {
                    let callee_is_analyzed = self.analyzed_function_ids.contains(&callee.id)
                        || self.terminals.contains_known(callee.id).await;
                    (
                        RecordedCallTarget::Known(callee.id),
                        callee.label(),
                        true,
                        callee_is_analyzed,
                    )
                }
                [] => {
                    let endpoint = ExternalEndpoint::from_selector(&args.callee);
                    let external_node = CallGraphNode::External(endpoint.clone());
                    if !self.terminals.contains(&external_node).await {
                        let message = format!(
                            "callee selector did not match any known callable, so no call edge was recorded. Confirm by reading source and short-term callable index memory. If this callee is truly external or missing from tree-sitter extraction, first call record_terminal_node with reason=missing_tree_sitter_node for this selector, then call record_call_relation again: {}",
                            args.callee.label()
                        );
                        tracing::warn!(
                            reason = "callee_unconfirmed_missing_tree_sitter",
                            caller = %args.caller.label(),
                            callee = %args.callee.label(),
                            instruction = %message,
                            "record_call_relation returned repair instruction"
                        );
                        return Ok(message);
                    }
                    let target = RecordedCallTarget::External(endpoint);
                    (target.clone(), target.label(), false, true)
                }
                many => {
                    let message = ambiguous_endpoint_message("callee", &args.callee, many);
                    tracing::warn!(
                        reason = "callee_ambiguous_selector",
                        caller = %args.caller.label(),
                        callee = %args.callee.label(),
                        instruction = %message,
                        "record_call_relation returned repair instruction"
                    );
                    return Ok(message);
                }
            };
        let caller_is_analyzed = self.analyzed_function_ids.contains(&caller.id);

        self.calls
            .record(RecordedCall {
                from_id: caller.id,
                target: target.clone(),
                description: args.description,
            })
            .await;
        if caller.node_kind.is_definition() {
            self.terminals
                .remove(&CallGraphNode::Known(caller.id))
                .await;
        }

        let next_action = if caller_is_analyzed {
            "caller is already fully analyzed; do not expand from this caller"
        } else if !callee_found_in_callable_index {
            "callee is a confirmed missing tree-sitter terminal node; stop this recursive branch"
        } else if callee_is_analyzed {
            "callee is already fully analyzed or is a terminal node; stop this recursive branch at the callee"
        } else {
            "callee is not marked fully analyzed; inspect its implementation if this branch has not already been exhausted"
        };

        Ok(format!(
            "recorded call: {} -> {}\ncallee_found_in_callable_index: {}\ncaller_fully_analyzed: {}\ncallee_fully_analyzed: {}\nnext_action: {}",
            caller.label(),
            callee_label,
            callee_found_in_callable_index,
            caller_is_analyzed,
            callee_is_analyzed,
            next_action,
        ))
    }
}

#[derive(Debug, Clone, Default)]
struct SharedCallRelations {
    inner: Arc<Mutex<Vec<RecordedCall>>>,
}

impl SharedCallRelations {
    async fn record(&self, call: RecordedCall) {
        let mut calls = self.inner.lock().await;
        if calls
            .iter()
            .any(|existing| existing.from_id == call.from_id && existing.target == call.target)
        {
            return;
        }
        calls.push(call);
    }

    async fn list(&self) -> Vec<RecordedCall> {
        self.inner.lock().await.clone()
    }

    async fn has_outgoing(&self, function_id: i32) -> bool {
        self.inner
            .lock()
            .await
            .iter()
            .any(|call| call.from_id == function_id)
    }
}

#[derive(Debug, Clone, Default)]
struct SharedTerminalNodes {
    inner: Arc<Mutex<BTreeMap<CallGraphNode, RecordedTerminalNode>>>,
}

impl SharedTerminalNodes {
    fn with_initial(nodes: impl IntoIterator<Item = RecordedTerminalNode>) -> Self {
        Self {
            inner: Arc::new(Mutex::new(
                nodes
                    .into_iter()
                    .map(|node| (node.target.clone(), node))
                    .collect(),
            )),
        }
    }

    async fn record(&self, node: RecordedTerminalNode) -> bool {
        let mut nodes = self.inner.lock().await;
        if nodes.contains_key(&node.target) {
            return false;
        }
        nodes.insert(node.target.clone(), node);
        true
    }

    async fn contains_known(&self, function_id: i32) -> bool {
        self.contains(&CallGraphNode::Known(function_id)).await
    }

    async fn contains(&self, target: &CallGraphNode) -> bool {
        self.inner.lock().await.contains_key(target)
    }

    async fn list(&self) -> Vec<RecordedTerminalNode> {
        self.inner.lock().await.values().cloned().collect()
    }

    async fn remove(&self, target: &CallGraphNode) -> Option<RecordedTerminalNode> {
        self.inner.lock().await.remove(target)
    }
}

#[derive(Debug, Clone)]
struct RecordedCall {
    from_id: i32,
    target: RecordedCallTarget,
    description: Option<String>,
}

#[derive(Debug, Clone)]
struct RecordedTerminalNode {
    target: CallGraphNode,
    reason: TerminalNodeReason,
    description: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum CallGraphNode {
    Known(i32),
    External(ExternalEndpoint),
}

impl CallGraphNode {
    fn label(&self, index: &CallGraphIndex) -> String {
        match self {
            Self::Known(id) => index
                .function(*id)
                .map(FunctionIndexEntry::label)
                .unwrap_or_else(|| format!("known function id {id}")),
            Self::External(endpoint) => endpoint.label(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TerminalNodeReason {
    NoExternalCall,
    MissingTreeSitterNode,
    InterfaceFunction,
}

impl TerminalNodeReason {
    fn from_arg(value: TerminalNodeReasonArg) -> Self {
        match value {
            TerminalNodeReasonArg::NoExternalCall => Self::NoExternalCall,
            TerminalNodeReasonArg::MissingTreeSitterNode => Self::MissingTreeSitterNode,
            TerminalNodeReasonArg::InterfaceFunction => Self::InterfaceFunction,
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::NoExternalCall => "no_external_call",
            Self::MissingTreeSitterNode => "missing_tree_sitter_node",
            Self::InterfaceFunction => "interface_function",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum RecordedCallTarget {
    Known(i32),
    External(ExternalEndpoint),
}

impl RecordedCallTarget {
    fn label(&self) -> String {
        match self {
            Self::Known(id) => format!("known function id {id}"),
            Self::External(endpoint) => endpoint.label(),
        }
    }
}

fn non_terminal_leaf_nodes(
    root_function_ids: &BTreeSet<i32>,
    recorded_calls: &[RecordedCall],
    terminal_nodes: &[RecordedTerminalNode],
) -> Vec<CallGraphNode> {
    let mut nodes = root_function_ids
        .iter()
        .copied()
        .map(CallGraphNode::Known)
        .collect::<BTreeSet<_>>();
    let mut outgoing = BTreeSet::new();
    for call in recorded_calls {
        let from = CallGraphNode::Known(call.from_id);
        nodes.insert(from.clone());
        outgoing.insert(from);
        nodes.insert(match &call.target {
            RecordedCallTarget::Known(to_id) => CallGraphNode::Known(*to_id),
            RecordedCallTarget::External(endpoint) => CallGraphNode::External(endpoint.clone()),
        });
    }

    let terminal_nodes = terminal_nodes
        .iter()
        .map(|node| node.target.clone())
        .collect::<BTreeSet<_>>();
    nodes
        .into_iter()
        .filter(|node| !outgoing.contains(node) && !terminal_nodes.contains(node))
        .collect()
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct ExternalEndpoint {
    relative_file_path: Option<PathBuf>,
    contract: String,
    name: String,
    kind: Option<String>,
    args: String,
}

impl ExternalEndpoint {
    fn from_selector(selector: &CallEndpointSelector) -> Self {
        Self {
            relative_file_path: selector.relative_file_path.clone(),
            contract: selector.contract.trim().to_string(),
            name: selector.name.trim().to_string(),
            kind: selector.kind.as_deref().map(str::trim).map(str::to_string),
            args: selector
                .args
                .as_deref()
                .map(normalize_args_selector)
                .unwrap_or_default(),
        }
    }

    fn contract_key(&self) -> ExternalContractKey {
        ExternalContractKey {
            relative_file_path: self.relative_file_path.clone(),
            contract: self.contract.clone(),
        }
    }

    fn label(&self) -> String {
        format!(
            "external {}::{}({}) [{}]{}",
            self.contract,
            self.name,
            self.args,
            self.kind.as_deref().unwrap_or("unknown"),
            self.relative_file_path
                .as_deref()
                .map(|path| format!(" @ {}", path.display()))
                .unwrap_or_default()
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct ExternalContractKey {
    relative_file_path: Option<PathBuf>,
    contract: String,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct FunctionKey {
    contract: String,
    name: String,
    kind: SolidityCallableKind,
    args: String,
}

impl fmt::Display for FunctionKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Key({}::{}({:?}),kind=[{}])",
            self.contract,
            self.name,
            self.args,
            self.kind.as_str()
        )
    }
}

#[derive(Debug, Clone)]
struct FunctionIndexEntry {
    id: i32,
    contract_id: i32,
    key: FunctionKey,
    contract_kind: SolidityContractKind,
    node_kind: SolidityFunctionNodeKind,
    in_analysis_scope: bool,
    relative_file_path: PathBuf,
    chunk: FileChunk,
}

impl FunctionIndexEntry {
    fn should_analyze(&self) -> bool {
        self.node_kind.is_definition() && self.in_analysis_scope
    }

    fn label(&self) -> String {
        self.to_string()
    }

    fn selector_manifest(&self) -> String {
        format!(
            "caller.relative_file_path={}\ncaller.contract={}\ncaller.name={}",
            self.relative_file_path.display(),
            self.key.contract,
            self.key.name
        )
    }

    fn matches_line_location(&self, line_number: usize, line_column: Option<usize>) -> bool {
        self.chunk.loc.start_line == line_number
            && line_column.is_none_or(|line_column| self.chunk.loc.start_column == line_column)
    }

    fn selector_candidate_label(&self) -> String {
        format!(
            "relative_file_path={}; line_number={}; line_column={}; contract={}; name={} ({})",
            self.relative_file_path.display(),
            self.chunk.loc.start_line,
            self.chunk.loc.start_column,
            self.key.contract,
            self.key.name,
            self.label()
        )
    }
}

fn selector_candidate_labels(matches: &[FunctionIndexEntry]) -> String {
    matches
        .iter()
        .map(FunctionIndexEntry::selector_candidate_label)
        .collect::<Vec<_>>()
        .join("; ")
}

fn ambiguous_endpoint_message(
    role: &str,
    selector: &CallEndpointSelector,
    matches: &[FunctionIndexEntry],
) -> String {
    format!(
        "{} selector matched multiple known callables, so no call edge or terminal node was recorded. Choose the intended candidate from the list below, then call the tool again with relative_file_path, contract, name, and that candidate's line_number and line_column. Selector: {}. Candidates: {}",
        role,
        selector.label(),
        selector_candidate_labels(matches)
    )
}

fn location_filtered_endpoint_message(
    role: &str,
    selector: &CallEndpointSelector,
    matches_without_location: &[FunctionIndexEntry],
) -> Option<String> {
    if selector.line_number.is_none() || matches_without_location.is_empty() {
        return None;
    }

    Some(format!(
        "{} selector did not match any callable at the supplied line_number/line_column, but relative_file_path, contract, and name matched known callables. The supplied line_number or line_column may be inaccurate, so no graph mutation was recorded. Retry with line_number/line_column omitted if the base selector is unique, or choose the intended candidate below and retry with its exact line_number and line_column. Selector: {}. Candidates: {}",
        role,
        selector.label(),
        selector_candidate_labels(matches_without_location)
    ))
}

fn missing_required_endpoint_fields_message(
    role: &str,
    selector: &CallEndpointSelector,
    matches: &[FunctionIndexEntry],
) -> Option<String> {
    if matches.is_empty() {
        return None;
    }

    let mut missing = Vec::new();
    if selector.relative_file_path.is_none() {
        missing.push("relative_file_path");
    }

    if missing.is_empty() {
        None
    } else {
        Some(format!(
            "{} selector matched known callable candidates but is missing required selector fields: {}. First use relative_file_path, contract, and name from short-term callable index memory; add line_number and line_column only if the tool reports ambiguity. Selector: {}. Candidates: {}",
            role,
            missing.join(", "),
            selector.label(),
            selector_candidate_labels(matches)
        ))
    }
}

fn format_prompt_callable_manifest_line(function: &FunctionIndexEntry) -> String {
    format!(
        "    - {} {}({}) loc={}:{}-{}:{}",
        function.key.kind.as_str(),
        function.key.name,
        function.key.args,
        function.chunk.loc.start_line,
        function.chunk.loc.start_column,
        function.chunk.loc.end_line,
        function.chunk.loc.end_column,
    )
}

fn contract_memory_title(contract: &ExtractedContract) -> String {
    format!(
        "{}::{}",
        contract.relative_file_path.display(),
        contract.name
    )
}

fn format_contract_memory_callable_line(function: &ExtractedCallable) -> String {
    format!(
        "    - {} {}({}) loc={}:{}-{}:{}",
        function.kind.as_str(),
        function.name,
        function.args,
        function.chunk.loc.start_line,
        function.chunk.loc.start_column,
        function.chunk.loc.end_line,
        function.chunk.loc.end_column,
    )
}

fn render_contract_callable_memory_entry(contract: &ExtractedContract) -> String {
    let mut lines = vec![
        format!("- file: {}", contract.relative_file_path.display()),
        format!(
            "  - {}: {} loc={}:{}-{}:{}",
            contract.kind.as_str(),
            contract.name,
            contract.chunk.loc.start_line,
            contract.chunk.loc.start_column,
            contract.chunk.loc.end_line,
            contract.chunk.loc.end_column,
        ),
    ];

    let mut functions = contract.functions.iter().collect::<Vec<_>>();
    functions.sort_by_key(|function| {
        (
            function.chunk.loc.start_line,
            function.chunk.loc.start_column,
            function.kind,
            function.name.clone(),
            function.args.clone(),
        )
    });

    if functions.is_empty() {
        lines.push("    - <no callables>".to_string());
    } else {
        lines.extend(
            functions
                .into_iter()
                .map(format_contract_memory_callable_line),
        );
    }

    lines.join("\n")
}

fn render_grouped_function_manifest<'a>(
    entries: impl IntoIterator<Item = &'a FunctionIndexEntry>,
) -> String {
    let mut by_file = BTreeMap::<
        PathBuf,
        BTreeMap<(SolidityContractKind, String), Vec<&FunctionIndexEntry>>,
    >::new();
    let mut count = 0usize;

    for entry in entries {
        count += 1;
        by_file
            .entry(entry.relative_file_path.clone())
            .or_default()
            .entry((entry.contract_kind, entry.key.contract.clone()))
            .or_default()
            .push(entry);
    }

    if count == 0 {
        return "<none>".to_string();
    }

    let mut lines = Vec::new();
    for (relative_file_path, contracts) in by_file {
        lines.push(format!("- file: {}", relative_file_path.display()));
        for ((contract_kind, contract_name), mut functions) in contracts {
            functions.sort_by_key(|function| {
                (
                    function.chunk.loc.start_line,
                    function.chunk.loc.start_column,
                    function.key.kind,
                    function.key.name.clone(),
                    function.key.args.clone(),
                )
            });
            lines.push(format!("  - {}: {}", contract_kind.as_str(), contract_name));
            lines.extend(
                functions
                    .into_iter()
                    .map(format_prompt_callable_manifest_line),
            );
        }
    }

    lines.join("\n")
}

impl fmt::Display for FunctionIndexEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Function({}, kind={}, analysis_scope={}, path={}, id={})",
            self.key,
            self.node_kind.as_str(),
            self.in_analysis_scope,
            self.relative_file_path.display(),
            self.id
        )
    }
}

#[derive(Debug, Clone)]
struct CallGraphIndex {
    functions: BTreeMap<i32, FunctionIndexEntry>,
    candidates: BTreeMap<(String, String), Vec<i32>>,
}

impl CallGraphIndex {
    fn new(contracts: &[ExtractedContract], analysis_source_files: &[PathBuf]) -> Self {
        let mut functions = BTreeMap::new();
        let mut candidates: BTreeMap<(String, String), Vec<i32>> = BTreeMap::new();
        let analysis_source_files = analysis_source_files
            .iter()
            .map(|path| normalize_relative_path_selector(path))
            .collect::<BTreeSet<_>>();

        for contract in contracts {
            for callable in &contract.functions {
                let in_analysis_scope = analysis_source_files.contains(
                    &normalize_relative_path_selector(&callable.relative_file_path),
                );
                let entry = FunctionIndexEntry {
                    id: callable.id,
                    contract_id: contract.id,
                    key: FunctionKey {
                        contract: contract.name.clone(),
                        name: callable.name.clone(),
                        kind: callable.kind,
                        args: callable.args.clone(),
                    },
                    contract_kind: contract.kind,
                    node_kind: callable.node_kind,
                    in_analysis_scope,
                    relative_file_path: callable.relative_file_path.clone(),
                    chunk: callable.chunk.clone(),
                };
                candidates
                    .entry((entry.key.contract.clone(), entry.key.name.clone()))
                    .or_default()
                    .push(entry.id);
                functions.insert(entry.id, entry);
            }
        }

        Self {
            functions,
            candidates,
        }
    }

    fn function_ids(&self) -> Vec<i32> {
        self.functions
            .iter()
            .filter(|(_, function)| function.should_analyze())
            .map(|(id, _)| *id)
            .collect()
    }

    fn automatic_terminal_nodes(&self) -> Vec<RecordedTerminalNode> {
        self.functions
            .iter()
            .filter(|(_, function)| {
                function.node_kind == SolidityFunctionNodeKind::InterfaceFunctionDeclaration
            })
            .map(|(id, function)| RecordedTerminalNode {
                target: CallGraphNode::Known(*id),
                reason: TerminalNodeReason::InterfaceFunction,
                description: Some(format!(
                    "{} is an interface function declaration",
                    function.label()
                )),
            })
            .collect()
    }

    fn function(&self, id: i32) -> Option<&FunctionIndexEntry> {
        self.functions.get(&id)
    }

    fn select_endpoint(&self, selector: &CallEndpointSelector) -> Vec<FunctionIndexEntry> {
        self.select_endpoint_candidates(selector, true)
    }

    fn select_endpoint_without_location(
        &self,
        selector: &CallEndpointSelector,
    ) -> Vec<FunctionIndexEntry> {
        self.select_endpoint_candidates(selector, false)
    }

    fn select_endpoint_candidates(
        &self,
        selector: &CallEndpointSelector,
        use_location: bool,
    ) -> Vec<FunctionIndexEntry> {
        let contract = selector.contract.trim().to_string();
        let name = selector.name.trim().to_string();
        let relative_file_path = selector
            .relative_file_path
            .as_deref()
            .map(normalize_relative_path_selector);
        let line_number = selector.line_number;
        let line_column = selector.line_column;
        let Some(candidate_ids) = self.candidates.get(&(contract, name)) else {
            return Vec::new();
        };

        candidate_ids
            .iter()
            .filter_map(|id| self.functions.get(id))
            .filter(|entry| {
                relative_file_path
                    .as_ref()
                    .is_none_or(|relative_file_path| {
                        normalize_relative_path_selector(&entry.relative_file_path)
                            == *relative_file_path
                    })
            })
            .filter(|entry| {
                !use_location
                    || line_number.is_none_or(|line_number| {
                        entry.matches_line_location(line_number, line_column)
                    })
            })
            .cloned()
            .collect::<Vec<_>>()
    }

    #[cfg(test)]
    fn render_manifest(&self) -> String {
        render_grouped_function_manifest(self.functions.values())
    }

    fn render_analyzed_manifest(&self, analyzed: &BTreeSet<i32>) -> String {
        render_grouped_function_manifest(analyzed.iter().filter_map(|id| self.functions.get(id)))
    }
}

fn build_call_graph(contracts: &[ExtractedContract], recorded_calls: &[RecordedCall]) -> CallGraph {
    let mut next_interface_id = contracts
        .iter()
        .map(|contract| contract.id)
        .max()
        .unwrap_or(0)
        + 1;
    let mut next_function_id = contracts
        .iter()
        .flat_map(|contract| contract.functions.iter().map(|function| function.id))
        .max()
        .unwrap_or(0)
        + 1;
    let mut external_interface_ids = BTreeMap::new();
    let mut external_function_ids = BTreeMap::new();

    for call in recorded_calls {
        let RecordedCallTarget::External(endpoint) = &call.target else {
            continue;
        };
        external_interface_ids
            .entry(endpoint.contract_key())
            .or_insert_with(|| {
                let id = next_interface_id;
                next_interface_id += 1;
                id
            });
        external_function_ids
            .entry(endpoint.clone())
            .or_insert_with(|| {
                let id = next_function_id;
                next_function_id += 1;
                id
            });
    }

    let mut unique_calls = BTreeMap::new();
    for call in recorded_calls {
        let to_id = match &call.target {
            RecordedCallTarget::Known(to_id) => *to_id,
            RecordedCallTarget::External(endpoint) => external_function_ids[endpoint],
        };
        unique_calls
            .entry((call.from_id, to_id))
            .or_insert_with(|| call.description.clone());
    }
    let mut calls_by_from: BTreeMap<i32, Vec<FunctionCall>> = BTreeMap::new();
    for (index, ((from_id, to_id), description)) in unique_calls.into_iter().enumerate() {
        calls_by_from
            .entry(from_id)
            .or_default()
            .push(FunctionCall {
                id: index as i32 + 1,
                from_id,
                to_id,
                description,
            });
    }

    let contracts_by_id = contracts
        .iter()
        .filter(|contract| contract.kind != SolidityContractKind::Interface)
        .map(|contract| {
            let functions = contract
                .functions
                .iter()
                .map(|callable| Function {
                    id: callable.id,
                    name: callable.name.clone(),
                    args: callable.args.clone(),
                    relative_file_path: callable.relative_file_path.clone(),
                    loc: callable.chunk.loc,
                    content: Some(callable.chunk.content.clone()),
                    calls: calls_by_from.remove(&callable.id).unwrap_or_default(),
                    description: Some(format!(
                        "Solidity {} {}::{} ({})",
                        callable.kind.as_str(),
                        callable.contract_name,
                        callable.name,
                        callable.node_kind.as_str()
                    )),
                })
                .collect::<Vec<_>>();

            (
                contract.id,
                Contract {
                    id: contract.id,
                    name: contract.name.clone(),
                    relative_file_path: contract.relative_file_path.clone(),
                    chunk: contract.chunk.clone(),
                    functions,
                    description: Some(format!(
                        "Solidity {} {}",
                        contract.kind.as_str(),
                        contract.name
                    )),
                },
            )
        })
        .collect::<BTreeMap<_, _>>();

    let mut interfaces = contracts
        .iter()
        .filter(|contract| contract.kind == SolidityContractKind::Interface)
        .map(|interface| {
            let functions = interface
                .functions
                .iter()
                .map(|callable| Function {
                    id: callable.id,
                    name: callable.name.clone(),
                    args: callable.args.clone(),
                    relative_file_path: callable.relative_file_path.clone(),
                    loc: callable.chunk.loc,
                    content: None,
                    calls: calls_by_from.remove(&callable.id).unwrap_or_default(),
                    description: Some(format!(
                        "Solidity {} {}::{} ({})",
                        callable.kind.as_str(),
                        callable.contract_name,
                        callable.name,
                        callable.node_kind.as_str()
                    )),
                })
                .collect::<Vec<_>>();

            (
                interface.id,
                Interface {
                    id: interface.id,
                    name: interface.name.clone(),
                    relative_file_path: interface.relative_file_path.clone(),
                    chunk: interface.chunk.clone(),
                    functions,
                    description: Some(format!("Solidity interface {}", interface.name)),
                },
            )
        })
        .collect::<BTreeMap<_, _>>();

    for (contract_key, interface_id) in external_interface_ids {
        let functions = external_function_ids
            .iter()
            .filter(|(endpoint, _)| endpoint.contract_key() == contract_key)
            .map(|(endpoint, function_id)| Function {
                id: *function_id,
                name: endpoint.name.clone(),
                args: endpoint.args.clone(),
                relative_file_path: endpoint
                    .relative_file_path
                    .clone()
                    .unwrap_or_else(|| PathBuf::from("<external>")),
                loc: synthetic_external_chunk(endpoint.label()).loc,
                content: None,
                calls: Vec::new(),
                description: Some(format!(
                    "External dependency interface declaration: {}",
                    endpoint.label()
                )),
            })
            .collect::<Vec<_>>();
        let label = contract_key
            .relative_file_path
            .as_deref()
            .map(|path| {
                format!(
                    "external dependency {} at {}",
                    contract_key.contract,
                    path.display()
                )
            })
            .unwrap_or_else(|| format!("external dependency {}", contract_key.contract));
        interfaces.insert(
            interface_id,
            Interface {
                id: interface_id,
                name: contract_key.contract,
                relative_file_path: contract_key
                    .relative_file_path
                    .unwrap_or_else(|| PathBuf::from("<external>")),
                chunk: synthetic_external_chunk(label),
                functions,
                description: Some(
                    "External dependency with no repository-local source chunk".to_string(),
                ),
            },
        );
    }

    CallGraph {
        contracts: contracts_by_id,
        interfaces,
    }
}

fn synthetic_external_chunk(content: String) -> FileChunk {
    FileChunk {
        loc: FileLocation {
            start_line: 1,
            start_column: 0,
            end_line: 1,
            end_column: content.chars().count(),
        },
        content,
    }
}

fn normalize_args_selector(value: &str) -> String {
    let trimmed = value.trim();
    let trimmed = trimmed
        .strip_prefix('(')
        .and_then(|value| value.strip_suffix(')'))
        .unwrap_or(trimmed);
    normalize_parameter_list_text(trimmed)
}

fn normalize_relative_path_selector(path: &Path) -> String {
    path.to_string_lossy()
        .trim()
        .trim_start_matches("./")
        .to_string()
}

fn normalize_parameter_list_text(value: &str) -> String {
    let collapsed = value.split_whitespace().collect::<Vec<_>>().join(" ");
    let mut normalized = String::with_capacity(collapsed.len());
    let mut skip_spaces_after_comma = false;

    for character in collapsed.chars() {
        if character == ',' {
            while normalized.ends_with(' ') {
                normalized.pop();
            }
            normalized.push(',');
            skip_spaces_after_comma = true;
        } else if skip_spaces_after_comma && character == ' ' {
            continue;
        } else {
            normalized.push(character);
            skip_spaces_after_comma = false;
        }
    }

    normalized
}

fn render_source_manifest(source_files: &[PathBuf], _analysis_source_files: &[PathBuf]) -> String {
    source_files
        .iter()
        .map(|path| format!("- {}", path.display()))
        .collect::<Vec<_>>()
        .join("\n")
}

fn render_semantic_overview(semantics: &[ExtractedSemantic]) -> String {
    if semantics.is_empty() {
        return "No extracted project semantics were provided.".to_string();
    }

    semantics
        .iter()
        .map(|semantic| format!("- {} ({:?})", semantic.name, semantic.category))
        .collect::<Vec<_>>()
        .join("\n")
}

fn render_semantic_memory_entry(semantic: &ExtractedSemantic) -> String {
    let functions = semantic
        .functions
        .iter()
        .map(|function| {
            let signature = function
                .signature
                .as_deref()
                .unwrap_or("<unknown signature>");
            format!("{}::{} {}", function.contract, function.name, signature)
        })
        .collect::<Vec<_>>()
        .join("; ");

    format!(
        "name: {}\ncategory: {:?}\ndefinition: {}\nfunctions: {}",
        semantic.name,
        semantic.category,
        semantic.definition,
        if functions.is_empty() {
            "<none>"
        } else {
            &functions
        },
    )
}

fn sanitize_memory_title(value: &str) -> String {
    let mut title = String::new();
    let mut last_was_dash = false;

    for character in value.chars() {
        if character.is_ascii_alphanumeric() {
            title.push(character.to_ascii_lowercase());
            last_was_dash = false;
        } else if !last_was_dash {
            title.push('-');
            last_was_dash = true;
        }

        if title.len() >= 96 {
            break;
        }
    }

    title.trim_matches('-').to_string()
}
fn validate_call_graph(call_graph: &CallGraph) -> Result<(), color_eyre::Report> {
    let mut function_ids = BTreeSet::new();
    let mut call_ids = BTreeSet::new();

    for (contract_id, contract) in &call_graph.contracts {
        ensure!(
            *contract_id == contract.id,
            "contract map key {} does not match contract.id {}",
            contract_id,
            contract.id
        );

        for function in &contract.functions {
            ensure!(
                function_ids.insert(function.id),
                "duplicate function id {} in final callgraph",
                function.id
            );
        }
    }
    for (interface_id, interface) in &call_graph.interfaces {
        ensure!(
            *interface_id == interface.id,
            "interface map key {} does not match interface.id {}",
            interface_id,
            interface.id
        );

        for function in &interface.functions {
            ensure!(
                function_ids.insert(function.id),
                "duplicate function id {} in final callgraph",
                function.id
            );
        }
    }

    for contract in call_graph.contracts.values() {
        for function in &contract.functions {
            validate_location(
                "function",
                function.id,
                function.loc.start_line,
                function.loc.start_column,
                function.loc.end_line,
                function.loc.end_column,
            )?;

            for call in &function.calls {
                ensure!(
                    call.from_id == function.id,
                    "call {} is stored under function {} but has from_id {}",
                    call.id,
                    function.id,
                    call.from_id
                );
                ensure!(
                    function_ids.contains(&call.to_id),
                    "call {} points to missing to_id {}",
                    call.id,
                    call.to_id
                );
                ensure!(
                    call_ids.insert(call.id),
                    "duplicate call id {} in final callgraph",
                    call.id
                );
            }
        }

        validate_location(
            "contract",
            contract.id,
            contract.chunk.loc.start_line,
            contract.chunk.loc.start_column,
            contract.chunk.loc.end_line,
            contract.chunk.loc.end_column,
        )?;
    }
    for interface in call_graph.interfaces.values() {
        for function in &interface.functions {
            validate_location(
                "interface function",
                function.id,
                function.loc.start_line,
                function.loc.start_column,
                function.loc.end_line,
                function.loc.end_column,
            )?;

            for call in &function.calls {
                ensure!(
                    call.from_id == function.id,
                    "call {} is stored under function {} but has from_id {}",
                    call.id,
                    function.id,
                    call.from_id
                );
                ensure!(
                    function_ids.contains(&call.to_id),
                    "call {} points to missing to_id {}",
                    call.id,
                    call.to_id
                );
                ensure!(
                    call_ids.insert(call.id),
                    "duplicate call id {} in final callgraph",
                    call.id
                );
            }
        }

        validate_location(
            "interface",
            interface.id,
            interface.chunk.loc.start_line,
            interface.chunk.loc.start_column,
            interface.chunk.loc.end_line,
            interface.chunk.loc.end_column,
        )?;
    }

    Ok(())
}

fn validate_location(
    kind: &str,
    id: i32,
    start_line: usize,
    start_column: usize,
    end_line: usize,
    end_column: usize,
) -> Result<(), color_eyre::Report> {
    ensure!(start_line > 0, "{kind} {id} has line 0 in source location");
    ensure!(
        (start_line, start_column) <= (end_line, end_column),
        "{kind} {id} has an inverted source location {}:{}..{}:{}",
        start_line,
        start_column,
        end_line,
        end_column
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn leaf_completion_requires_terminal_or_outgoing_edge_and_handles_cycles() {
        let roots = BTreeSet::from([1]);
        let calls = vec![RecordedCall {
            from_id: 1,
            target: RecordedCallTarget::Known(2),
            description: None,
        }];

        assert_eq!(
            non_terminal_leaf_nodes(&roots, &calls, &[]),
            vec![CallGraphNode::Known(2)]
        );

        let terminals = vec![RecordedTerminalNode {
            target: CallGraphNode::Known(2),
            reason: TerminalNodeReason::NoExternalCall,
            description: None,
        }];
        assert!(non_terminal_leaf_nodes(&roots, &calls, &terminals).is_empty());

        let cycle = vec![
            RecordedCall {
                from_id: 1,
                target: RecordedCallTarget::Known(2),
                description: None,
            },
            RecordedCall {
                from_id: 2,
                target: RecordedCallTarget::Known(1),
                description: None,
            },
        ];
        assert!(non_terminal_leaf_nodes(&roots, &cycle, &[]).is_empty());

        let external = external_endpoint("IERC20", "transfer");
        let external_calls = vec![RecordedCall {
            from_id: 1,
            target: RecordedCallTarget::External(external.clone()),
            description: None,
        }];
        assert_eq!(
            non_terminal_leaf_nodes(&roots, &external_calls, &[]),
            vec![CallGraphNode::External(external.clone())]
        );
        let external_terminals = vec![RecordedTerminalNode {
            target: CallGraphNode::External(external),
            reason: TerminalNodeReason::MissingTreeSitterNode,
            description: None,
        }];
        assert!(non_terminal_leaf_nodes(&roots, &external_calls, &external_terminals).is_empty());
    }

    #[test]
    fn automatic_terminal_nodes_marks_interface_functions() {
        let contracts = vec![test_contract(
            1,
            "IRouter",
            SolidityContractKind::Interface,
            vec![test_callable(
                1,
                1,
                "IRouter",
                "route",
                SolidityFunctionNodeKind::InterfaceFunctionDeclaration,
            )],
        )];
        let index = CallGraphIndex::new(&contracts, &[PathBuf::from("src/Test.sol")]);
        let terminals = index.automatic_terminal_nodes();

        assert_eq!(terminals.len(), 1);
        assert_eq!(terminals[0].target, CallGraphNode::Known(1));
        assert_eq!(terminals[0].reason, TerminalNodeReason::InterfaceFunction);
    }

    #[test]
    fn render_manifest_groups_callables_without_internal_scope_fields() {
        let contracts = vec![
            test_contract(
                1,
                "App",
                SolidityContractKind::Contract,
                vec![test_callable(
                    1,
                    1,
                    "App",
                    "run",
                    SolidityFunctionNodeKind::ContractFunctionDefinition,
                )],
            ),
            test_contract(
                2,
                "IRouter",
                SolidityContractKind::Interface,
                vec![test_callable(
                    2,
                    2,
                    "IRouter",
                    "route",
                    SolidityFunctionNodeKind::InterfaceFunctionDeclaration,
                )],
            ),
        ];
        let index = CallGraphIndex::new(&contracts, &[PathBuf::from("src/Test.sol")]);
        let manifest = index.render_manifest();

        assert!(manifest.contains("- file: src/Test.sol"));
        assert!(manifest.contains("  - contract: App"));
        assert!(manifest.contains("    - function run()"));
        assert!(manifest.contains("  - interface: IRouter"));
        assert!(manifest.contains("    - function route()"));
        assert!(!manifest.contains("node_type"));
        assert!(!manifest.contains("analysis_scope"));

        let source_manifest = render_source_manifest(
            &[PathBuf::from("src/Test.sol")],
            &[PathBuf::from("src/Test.sol")],
        );
        assert_eq!(source_manifest, "- src/Test.sol");
    }

    #[test]
    fn contract_memory_entry_uses_path_contract_title_and_lists_locations() {
        let contract = test_contract(
            1,
            "App",
            SolidityContractKind::Contract,
            vec![test_callable(
                1,
                1,
                "App",
                "run",
                SolidityFunctionNodeKind::ContractFunctionDefinition,
            )],
        );

        assert_eq!(contract_memory_title(&contract), "src/Test.sol::App");

        let rendered = render_contract_callable_memory_entry(&contract);
        assert!(rendered.contains("- file: src/Test.sol"));
        assert!(rendered.contains("  - contract: App loc=1:0-1:15"));
        assert!(rendered.contains("    - function run() loc=1:0-1:26"));
    }

    #[test]
    fn endpoint_selection_uses_location_only_as_optional_disambiguator() {
        let contracts = vec![test_contract(
            1,
            "App",
            SolidityContractKind::Contract,
            vec![
                test_callable(
                    1,
                    1,
                    "App",
                    "run",
                    SolidityFunctionNodeKind::ContractFunctionDefinition,
                ),
                test_callable_at_line(
                    2,
                    1,
                    "App",
                    "run",
                    SolidityFunctionNodeKind::ContractFunctionDefinition,
                    2,
                ),
                test_callable_at_location(
                    3,
                    1,
                    "App",
                    "run",
                    SolidityFunctionNodeKind::ContractFunctionDefinition,
                    2,
                    8,
                ),
            ],
        )];
        let index = CallGraphIndex::new(&contracts, &[PathBuf::from("src/Test.sol")]);

        let coarse_matches = index.select_endpoint(&CallEndpointSelector {
            relative_file_path: Some(PathBuf::from("src/Test.sol")),
            line_number: None,
            line_column: None,
            contract: "App".to_string(),
            name: "run".to_string(),
            kind: Some("modifier".to_string()),
            args: Some("uint256 ignored".to_string()),
        });
        assert_eq!(coarse_matches.len(), 3);

        let matches = index.select_endpoint(&CallEndpointSelector {
            relative_file_path: Some(PathBuf::from("src/Test.sol")),
            line_number: Some(2),
            line_column: Some(8),
            contract: "App".to_string(),
            name: "run".to_string(),
            kind: Some("modifier".to_string()),
            args: Some("uint256 ignored".to_string()),
        });

        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].id, 3);
    }

    #[tokio::test]
    async fn record_call_relation_requires_confirmed_missing_tree_sitter_target() {
        let contracts = vec![test_contract(
            1,
            "App",
            SolidityContractKind::Contract,
            vec![test_callable(
                1,
                1,
                "App",
                "run",
                SolidityFunctionNodeKind::ContractFunctionDefinition,
            )],
        )];
        let index = Arc::new(CallGraphIndex::new(
            &contracts,
            &[PathBuf::from("src/Test.sol")],
        ));
        let calls = SharedCallRelations::default();
        let terminals = SharedTerminalNodes::default();
        let tool = RecordCallRelationTool::new(
            index,
            calls.clone(),
            terminals.clone(),
            Arc::new(BTreeSet::new()),
        );

        let missing_message = tool
            .record_call_relation(RecordCallRelationArgs {
                caller: selector("App", "run"),
                callee: selector("IERC20", "transfer"),
                description: Some("token transfer".to_string()),
            })
            .await
            .expect("missing callee should be reported to the model");

        assert!(missing_message.contains("callee selector did not match any known callable"));
        assert!(missing_message.contains("record_terminal_node"));
        assert!(calls.list().await.is_empty());
        assert!(terminals.list().await.is_empty());

        let terminal_tool =
            RecordTerminalNodeTool::new(tool.index.clone(), calls.clone(), terminals.clone());
        terminal_tool
            .record_terminal_node(RecordTerminalNodeArgs {
                node: selector("IERC20", "transfer"),
                reason: TerminalNodeReasonArg::MissingTreeSitterNode,
                description: Some("confirmed external token call".to_string()),
            })
            .await
            .expect("missing callee terminal node should record");

        tool.record_call_relation(RecordCallRelationArgs {
            caller: selector("App", "run"),
            callee: selector("IERC20", "transfer"),
            description: Some("token transfer".to_string()),
        })
        .await
        .expect("call relation should record after missing callee is confirmed");

        let terminal_nodes = terminals.list().await;
        assert_eq!(terminal_nodes.len(), 1);
        assert_eq!(
            terminal_nodes[0].reason,
            TerminalNodeReason::MissingTreeSitterNode
        );
        assert!(matches!(
            terminal_nodes[0].target,
            CallGraphNode::External(_)
        ));
        assert_eq!(calls.list().await.len(), 1);
    }

    #[tokio::test]
    async fn record_terminal_node_returns_instruction_for_wrong_reason_without_mutating() {
        let contracts = vec![test_contract(
            1,
            "App",
            SolidityContractKind::Contract,
            vec![test_callable(
                1,
                1,
                "App",
                "run",
                SolidityFunctionNodeKind::ContractFunctionDefinition,
            )],
        )];
        let index = Arc::new(CallGraphIndex::new(
            &contracts,
            &[PathBuf::from("src/Test.sol")],
        ));
        let calls = SharedCallRelations::default();
        let terminals = SharedTerminalNodes::default();
        let tool = RecordTerminalNodeTool::new(index, calls.clone(), terminals.clone());

        let message = tool
            .record_terminal_node(RecordTerminalNodeArgs {
                node: selector("App", "run"),
                reason: TerminalNodeReasonArg::InterfaceFunction,
                description: None,
            })
            .await
            .expect("wrong terminal reason should be reported to the model");

        assert!(message.contains("terminal node not recorded"));
        assert!(message.contains("reason=interface_function"));
        assert!(message.contains("reason=no_external_call"));
        assert!(calls.list().await.is_empty());
        assert!(terminals.list().await.is_empty());
    }

    #[tokio::test]
    async fn record_call_relation_returns_message_when_caller_selector_is_unknown() {
        let contracts = vec![test_contract(
            1,
            "App",
            SolidityContractKind::Contract,
            vec![test_callable(
                1,
                1,
                "App",
                "run",
                SolidityFunctionNodeKind::ContractFunctionDefinition,
            )],
        )];
        let index = Arc::new(CallGraphIndex::new(
            &contracts,
            &[PathBuf::from("src/Test.sol")],
        ));
        let calls = SharedCallRelations::default();
        let terminals = SharedTerminalNodes::default();
        let tool = RecordCallRelationTool::new(
            index,
            calls.clone(),
            terminals.clone(),
            Arc::new(BTreeSet::new()),
        );

        let message = tool
            .record_call_relation(RecordCallRelationArgs {
                caller: selector("Missing", "run"),
                callee: selector("App", "run"),
                description: None,
            })
            .await
            .expect("unknown caller selector should be reported to the model");

        assert!(message.contains("caller selector did not match any known callable"));
        assert!(calls.list().await.is_empty());
        assert!(terminals.list().await.is_empty());
    }

    #[tokio::test]
    async fn record_call_relation_returns_message_when_callee_selector_is_ambiguous() {
        let contracts = vec![test_contract(
            1,
            "App",
            SolidityContractKind::Contract,
            vec![
                test_callable(
                    1,
                    1,
                    "App",
                    "run",
                    SolidityFunctionNodeKind::ContractFunctionDefinition,
                ),
                test_callable_at_line(
                    2,
                    1,
                    "App",
                    "target",
                    SolidityFunctionNodeKind::ContractFunctionDefinition,
                    2,
                ),
                test_callable_at_location(
                    3,
                    1,
                    "App",
                    "target",
                    SolidityFunctionNodeKind::ContractFunctionDefinition,
                    2,
                    8,
                ),
            ],
        )];
        let index = Arc::new(CallGraphIndex::new(
            &contracts,
            &[PathBuf::from("src/Test.sol")],
        ));
        let calls = SharedCallRelations::default();
        let terminals = SharedTerminalNodes::default();
        let tool = RecordCallRelationTool::new(
            index,
            calls.clone(),
            terminals.clone(),
            Arc::new(BTreeSet::new()),
        );

        let ambiguous_callee = selector("App", "target");
        let message = tool
            .record_call_relation(RecordCallRelationArgs {
                caller: selector("App", "run"),
                callee: ambiguous_callee,
                description: None,
            })
            .await
            .expect("ambiguous callee selector should be reported to the model");

        assert!(message.contains("callee selector matched multiple known callables"));
        assert!(message.contains("line_number=2"));
        assert!(message.contains("line_column=0"));
        assert!(message.contains("line_column=8"));
        assert!(calls.list().await.is_empty());
        assert!(terminals.list().await.is_empty());
    }

    #[tokio::test]
    async fn record_call_relation_reports_inaccurate_line_location_without_mutating() {
        let contracts = vec![test_contract(
            1,
            "App",
            SolidityContractKind::Contract,
            vec![
                test_callable(
                    1,
                    1,
                    "App",
                    "run",
                    SolidityFunctionNodeKind::ContractFunctionDefinition,
                ),
                test_callable_at_location(
                    2,
                    1,
                    "App",
                    "target",
                    SolidityFunctionNodeKind::ContractFunctionDefinition,
                    2,
                    8,
                ),
            ],
        )];
        let index = Arc::new(CallGraphIndex::new(
            &contracts,
            &[PathBuf::from("src/Test.sol")],
        ));
        let calls = SharedCallRelations::default();
        let terminals = SharedTerminalNodes::default();
        let tool = RecordCallRelationTool::new(
            index,
            calls.clone(),
            terminals.clone(),
            Arc::new(BTreeSet::new()),
        );

        let mut callee = selector("App", "target");
        callee.line_number = Some(99);
        callee.line_column = Some(99);
        let message = tool
            .record_call_relation(RecordCallRelationArgs {
                caller: selector("App", "run"),
                callee,
                description: None,
            })
            .await
            .expect("inaccurate line selector should be reported to the model");

        assert!(message.contains("supplied line_number/line_column"));
        assert!(message.contains("line_number=2"));
        assert!(message.contains("line_column=8"));
        assert!(calls.list().await.is_empty());
        assert!(terminals.list().await.is_empty());
    }

    fn test_contract(
        id: i32,
        name: &str,
        kind: SolidityContractKind,
        functions: Vec<ExtractedCallable>,
    ) -> ExtractedContract {
        ExtractedContract {
            id,
            name: name.to_string(),
            kind,
            relative_file_path: PathBuf::from("src/Test.sol"),
            chunk: chunk(&format!("contract {name} {{}}")),
            functions,
        }
    }

    fn test_callable(
        id: i32,
        contract_id: i32,
        contract_name: &str,
        name: &str,
        node_kind: SolidityFunctionNodeKind,
    ) -> ExtractedCallable {
        test_callable_at_line(id, contract_id, contract_name, name, node_kind, 1)
    }

    fn test_callable_at_line(
        id: i32,
        contract_id: i32,
        contract_name: &str,
        name: &str,
        node_kind: SolidityFunctionNodeKind,
        start_line: usize,
    ) -> ExtractedCallable {
        test_callable_at_location(
            id,
            contract_id,
            contract_name,
            name,
            node_kind,
            start_line,
            0,
        )
    }

    fn test_callable_at_location(
        id: i32,
        contract_id: i32,
        contract_name: &str,
        name: &str,
        node_kind: SolidityFunctionNodeKind,
        start_line: usize,
        start_column: usize,
    ) -> ExtractedCallable {
        let mut chunk = chunk(&format!("function {name}() external {{}}"));
        chunk.loc.start_line = start_line;
        chunk.loc.start_column = start_column;
        chunk.loc.end_line = start_line;

        ExtractedCallable {
            id,
            contract_id,
            contract_name: contract_name.to_string(),
            kind: SolidityCallableKind::Function,
            node_kind,
            name: name.to_string(),
            args: String::new(),
            relative_file_path: PathBuf::from("src/Test.sol"),
            chunk,
        }
    }

    fn selector(contract: &str, name: &str) -> CallEndpointSelector {
        CallEndpointSelector {
            relative_file_path: Some(PathBuf::from("src/Test.sol")),
            line_number: None,
            line_column: None,
            contract: contract.to_string(),
            name: name.to_string(),
            kind: Some("function".to_string()),
            args: Some(String::new()),
        }
    }

    fn external_endpoint(contract: &str, name: &str) -> ExternalEndpoint {
        ExternalEndpoint::from_selector(&selector(contract, name))
    }

    fn chunk(content: &str) -> FileChunk {
        FileChunk {
            loc: FileLocation {
                start_line: 1,
                start_column: 0,
                end_line: 1,
                end_column: content.len(),
            },
            content: content.to_string(),
        }
    }
}
