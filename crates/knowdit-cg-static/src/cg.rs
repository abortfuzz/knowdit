use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    path::{Path, PathBuf},
};

use color_eyre::eyre::{ContextCompat, WrapErr, ensure};
use foundry_compilers_artifacts::ast::{
    ContractDefinition, ContractDefinitionPart, ContractKind, Expression, FunctionCall,
    FunctionDefinition, FunctionKind, IdentifierOrIdentifierPath, ModifierDefinition,
    ModifierInvocation, ParameterList, SourceLocation, SourceUnit, SourceUnitPart,
    visitor::{Visitor, Walk},
};
use knowdit_repo_model::cg::{
    CallGraph, Contract, FileChunk, FileLocation, Function, FunctionCall as RepoCall, Interface,
};

/// One compiled source unit and the raw source text for it. The caller is responsible for
/// pairing the AST with its source content (read from disk or pulled out of the compiler input).
#[derive(Debug, Clone)]
pub struct SourceUnitInput {
    /// Absolute path to the source file (matches `SourceUnit.absolute_path`).
    pub absolute_path: String,
    /// Raw source text. Required to extract function bodies and parameter strings.
    pub source: String,
    /// Parsed solc AST for this file.
    pub source_unit: SourceUnit,
}

/// Result of a static call graph extraction driven by `foundry-compilers-artifacts` AST.
#[derive(Debug, Clone)]
pub struct StaticCallGraphResult {
    pub call_graph: CallGraph,
    pub contract_count: usize,
    pub interface_count: usize,
    pub function_count: usize,
    pub call_count: usize,
}

/// Build a static call graph over a set of compiled source units. Edges are derived from
/// `referenced_declaration` resolution on `FunctionCall` and `ModifierInvocation` AST nodes.
pub fn build_call_graph(
    repo_root: &Path,
    inputs: &[SourceUnitInput],
) -> Result<StaticCallGraphResult, color_eyre::Report> {
    Ok(build_call_graph_with_maps(repo_root, inputs)?.0)
}

/// Same as [`build_call_graph`] but also returns the solc `NodeID -> assigned id` maps the
/// builder produced. The storage analyzer reuses the same project-local ids so that all rows
/// in the project database refer to the same `function`/`contract` records.
pub fn build_call_graph_with_maps(
    repo_root: &Path,
    inputs: &[SourceUnitInput],
) -> Result<(StaticCallGraphResult, IdMaps), color_eyre::Report> {
    ensure!(
        !inputs.is_empty(),
        "no source units provided to build_call_graph"
    );

    let mut builder = CallGraphBuilder::new(repo_root);
    for input in inputs {
        builder.ingest_input(input)?;
    }
    builder.build_edges();
    Ok(builder.finish_with_maps())
}

/// Stable solc-NodeID → project-local-id mappings produced by the call graph builder.
#[derive(Debug, Clone, Default)]
pub struct IdMaps {
    pub function_id_by_node: HashMap<NodeID, i32>,
    pub contract_id_by_node: HashMap<NodeID, i32>,
}

pub type NodeID = isize;

#[derive(Debug, Clone)]
struct CallableEntry {
    container_id: i32,
    container_is_interface: bool,
    function: Function,
}

enum CallableAst {
    Function(Box<FunctionDefinition>),
    Modifier(Box<ModifierDefinition>),
}

struct CallGraphBuilder<'a> {
    repo_root: &'a Path,
    contracts: BTreeMap<i32, Contract>,
    interfaces: BTreeMap<i32, Interface>,
    callables: BTreeMap<i32, CallableEntry>,
    function_id_by_node: HashMap<NodeID, i32>,
    contract_id_by_node: HashMap<NodeID, i32>,
    /// `ContractDefinition NodeID -> constructor FunctionDefinition NodeID`. Lets us redirect a
    /// `BaseConstructorSpecifier` modifier invocation (whose `referenced_declaration` points at
    /// the contract) to the contract's constructor, so we emit an edge to the right callable.
    constructor_node_by_contract: HashMap<NodeID, NodeID>,
    /// `Callable NodeID -> owned AST` for the callable. Stored so edge resolution can re-walk
    /// the body without holding a borrow into the input slice.
    callable_ast_by_node: HashMap<NodeID, CallableAst>,
    /// Synthetic file-level container ids, keyed by absolute path, for free functions
    /// (top-level `function` not inside any contract). One synthetic Contract row is created
    /// lazily per file that contains at least one free function.
    free_container_by_path: HashMap<String, i32>,
    next_contract_id: i32,
    next_function_id: i32,
    next_call_id: i32,
}

impl<'a> CallGraphBuilder<'a> {
    fn new(repo_root: &'a Path) -> Self {
        Self {
            repo_root,
            contracts: BTreeMap::new(),
            interfaces: BTreeMap::new(),
            callables: BTreeMap::new(),
            function_id_by_node: HashMap::new(),
            contract_id_by_node: HashMap::new(),
            constructor_node_by_contract: HashMap::new(),
            callable_ast_by_node: HashMap::new(),
            free_container_by_path: HashMap::new(),
            next_contract_id: 1,
            next_function_id: 1,
            next_call_id: 1,
        }
    }

    fn ingest_input(&mut self, input: &SourceUnitInput) -> Result<(), color_eyre::Report> {
        let absolute_path = &input.absolute_path;
        let source = input.source.as_str();
        let relative_file_path = self.relative_path(absolute_path);

        let mut contract_nodes: Vec<&ContractDefinition> = input
            .source_unit
            .nodes
            .iter()
            .filter_map(|node| match node {
                SourceUnitPart::ContractDefinition(contract) => Some(contract.as_ref()),
                _ => None,
            })
            .collect();
        contract_nodes.sort_by_key(|contract| contract.id);

        for contract in contract_nodes {
            self.ingest_contract(absolute_path, &relative_file_path, source, contract)?;
        }

        let mut free_functions: Vec<&FunctionDefinition> = input
            .source_unit
            .nodes
            .iter()
            .filter_map(|node| match node {
                SourceUnitPart::FunctionDefinition(function) => Some(function.as_ref()),
                _ => None,
            })
            .collect();
        free_functions.sort_by_key(|function| function.id);

        for function in free_functions {
            let container_id = self.free_function_container(absolute_path, &relative_file_path);
            self.ingest_function(&relative_file_path, source, container_id, false, function)?;
        }

        Ok(())
    }

    fn free_function_container(&mut self, absolute_path: &str, relative_file_path: &Path) -> i32 {
        if let Some(&id) = self.free_container_by_path.get(absolute_path) {
            return id;
        }
        let contract_id = self.next_contract_id;
        self.next_contract_id += 1;
        let name = relative_file_path
            .file_stem()
            .and_then(|stem| stem.to_str())
            .map(|stem| format!("__free__{stem}"))
            .unwrap_or_else(|| "__free__".to_string());
        self.contracts.insert(
            contract_id,
            Contract {
                id: contract_id,
                name,
                relative_file_path: relative_file_path.to_path_buf(),
                chunk: FileChunk {
                    loc: FileLocation {
                        start_line: 1,
                        start_column: 0,
                        end_line: 1,
                        end_column: 0,
                    },
                    content: String::new(),
                },
                functions: Vec::new(),
                description: Some(
                    "Synthetic container for top-level free functions in this file.".to_string(),
                ),
            },
        );
        self.free_container_by_path
            .insert(absolute_path.to_string(), contract_id);
        contract_id
    }

    fn ingest_contract(
        &mut self,
        absolute_path: &str,
        relative_file_path: &Path,
        source: &str,
        contract: &ContractDefinition,
    ) -> Result<(), color_eyre::Report> {
        let node_id = contract.id as NodeID;
        if self.contract_id_by_node.contains_key(&node_id) {
            return Ok(());
        }

        let chunk = chunk_from_src(&contract.src, source).wrap_err_with(|| {
            format!(
                "failed to compute source range for contract {} in {absolute_path}",
                contract.name
            )
        })?;
        let contract_id = self.next_contract_id;
        self.next_contract_id += 1;
        self.contract_id_by_node.insert(node_id, contract_id);

        let is_interface = matches!(contract.kind, ContractKind::Interface);
        if is_interface {
            self.interfaces.insert(
                contract_id,
                Interface {
                    id: contract_id,
                    name: contract.name.clone(),
                    relative_file_path: relative_file_path.to_path_buf(),
                    chunk,
                    functions: Vec::new(),
                    description: None,
                },
            );
        } else {
            self.contracts.insert(
                contract_id,
                Contract {
                    id: contract_id,
                    name: contract.name.clone(),
                    relative_file_path: relative_file_path.to_path_buf(),
                    chunk,
                    functions: Vec::new(),
                    description: None,
                },
            );
        }

        for member in &contract.nodes {
            match member {
                ContractDefinitionPart::FunctionDefinition(function) => {
                    self.ingest_function(
                        relative_file_path,
                        source,
                        contract_id,
                        is_interface,
                        function.as_ref(),
                    )?;
                }
                ContractDefinitionPart::ModifierDefinition(modifier) => {
                    self.ingest_modifier(
                        relative_file_path,
                        source,
                        contract_id,
                        is_interface,
                        modifier.as_ref(),
                    )?;
                }
                _ => {}
            }
        }

        Ok(())
    }

    fn ingest_function(
        &mut self,
        relative_file_path: &Path,
        source: &str,
        contract_id: i32,
        contract_is_interface: bool,
        function: &FunctionDefinition,
    ) -> Result<(), color_eyre::Report> {
        let node_id = function.id as NodeID;
        if self.function_id_by_node.contains_key(&node_id) {
            return Ok(());
        }

        let function_id = self.next_function_id;
        self.next_function_id += 1;

        let name = display_function_name(function);
        let args = parameter_list_text(&function.parameters, source)?;
        let chunk = chunk_from_src(&function.src, source)
            .wrap_err_with(|| format!("failed to compute source range for function {name}"))?;
        let content = if function.implemented && function.body.is_some() {
            Some(chunk.content.clone())
        } else {
            None
        };

        self.callables.insert(
            function_id,
            CallableEntry {
                container_id: contract_id,
                container_is_interface: contract_is_interface,
                function: Function {
                    id: function_id,
                    name,
                    args,
                    relative_file_path: relative_file_path.to_path_buf(),
                    loc: chunk.loc,
                    content,
                    calls: Vec::new(),
                    description: None,
                },
            },
        );
        self.function_id_by_node.insert(node_id, function_id);
        if matches!(function.kind(), FunctionKind::Constructor) {
            if let Some(scope) = function.scope {
                self.constructor_node_by_contract
                    .entry(scope as NodeID)
                    .or_insert(node_id);
            }
        }
        self.callable_ast_by_node
            .insert(node_id, CallableAst::Function(Box::new(function.clone())));
        Ok(())
    }

    fn ingest_modifier(
        &mut self,
        relative_file_path: &Path,
        source: &str,
        contract_id: i32,
        contract_is_interface: bool,
        modifier: &ModifierDefinition,
    ) -> Result<(), color_eyre::Report> {
        let node_id = modifier.id as NodeID;
        if self.function_id_by_node.contains_key(&node_id) {
            return Ok(());
        }

        let function_id = self.next_function_id;
        self.next_function_id += 1;

        let args = parameter_list_text(&modifier.parameters, source)?;
        let chunk = chunk_from_src(&modifier.src, source).wrap_err_with(|| {
            format!(
                "failed to compute source range for modifier {}",
                modifier.name
            )
        })?;
        let content = if modifier.body.is_some() {
            Some(chunk.content.clone())
        } else {
            None
        };

        self.callables.insert(
            function_id,
            CallableEntry {
                container_id: contract_id,
                container_is_interface: contract_is_interface,
                function: Function {
                    id: function_id,
                    name: modifier.name.clone(),
                    args,
                    relative_file_path: relative_file_path.to_path_buf(),
                    loc: chunk.loc,
                    content,
                    calls: Vec::new(),
                    description: None,
                },
            },
        );
        self.function_id_by_node.insert(node_id, function_id);
        self.callable_ast_by_node
            .insert(node_id, CallableAst::Modifier(Box::new(modifier.clone())));
        Ok(())
    }

    fn build_edges(&mut self) {
        let mut edge_lists: BTreeMap<i32, Vec<RepoCall>> = BTreeMap::new();

        let mut node_ids: Vec<NodeID> = self.callable_ast_by_node.keys().copied().collect();
        node_ids.sort();

        for node_id in node_ids {
            let function_id = match self.function_id_by_node.get(&node_id) {
                Some(id) => *id,
                None => continue,
            };

            let mut collector = CallSiteCollector::default();
            match self.callable_ast_by_node.get(&node_id) {
                Some(CallableAst::Function(function)) => function.walk(&mut collector),
                Some(CallableAst::Modifier(modifier)) => modifier.walk(&mut collector),
                None => continue,
            }

            let mut emitted: BTreeSet<i32> = BTreeSet::new();
            let mut edges: Vec<RepoCall> = Vec::new();

            for raw_target in collector.function_call_targets {
                let Some(&target_function_id) = self.function_id_by_node.get(&raw_target) else {
                    continue;
                };
                if target_function_id == function_id || !emitted.insert(target_function_id) {
                    continue;
                }
                let id = self.next_call_id;
                self.next_call_id += 1;
                edges.push(RepoCall {
                    id,
                    from_id: function_id,
                    to_id: target_function_id,
                    description: None,
                });
            }

            for raw_target in collector.modifier_invocation_targets {
                // `BaseConstructorSpecifier` references the contract; redirect to its
                // constructor so we emit an edge to a real callable.
                let target_node_id = if self.contract_id_by_node.contains_key(&raw_target) {
                    match self.constructor_node_by_contract.get(&raw_target) {
                        Some(&ctor) => ctor,
                        None => continue,
                    }
                } else {
                    raw_target
                };
                let Some(&target_function_id) = self.function_id_by_node.get(&target_node_id)
                else {
                    continue;
                };
                if target_function_id == function_id || !emitted.insert(target_function_id) {
                    continue;
                }
                let id = self.next_call_id;
                self.next_call_id += 1;
                edges.push(RepoCall {
                    id,
                    from_id: function_id,
                    to_id: target_function_id,
                    description: None,
                });
            }

            edge_lists.insert(function_id, edges);
        }

        for (function_id, edges) in edge_lists {
            if let Some(callable) = self.callables.get_mut(&function_id) {
                callable.function.calls = edges;
            }
        }
    }

    fn finish_with_maps(self) -> (StaticCallGraphResult, IdMaps) {
        let function_id_by_node = self.function_id_by_node.clone();
        let contract_id_by_node = self.contract_id_by_node.clone();
        let result = self.finish();
        (
            result,
            IdMaps {
                function_id_by_node,
                contract_id_by_node,
            },
        )
    }

    fn finish(mut self) -> StaticCallGraphResult {
        let mut function_count = 0;
        let mut call_count = 0;
        for entry in self.callables.into_values() {
            function_count += 1;
            call_count += entry.function.calls.len();
            if entry.container_is_interface {
                if let Some(interface) = self.interfaces.get_mut(&entry.container_id) {
                    interface.functions.push(entry.function);
                }
            } else if let Some(contract) = self.contracts.get_mut(&entry.container_id) {
                contract.functions.push(entry.function);
            }
        }

        for contract in self.contracts.values_mut() {
            contract.functions.sort_by(sort_functions);
        }
        for interface in self.interfaces.values_mut() {
            interface.functions.sort_by(sort_functions);
        }

        StaticCallGraphResult {
            contract_count: self.contracts.len(),
            interface_count: self.interfaces.len(),
            function_count,
            call_count,
            call_graph: CallGraph {
                contracts: self.contracts,
                interfaces: self.interfaces,
            },
        }
    }

    fn relative_path(&self, absolute_path: &str) -> PathBuf {
        let candidate = Path::new(absolute_path);
        if let Ok(stripped) = candidate.strip_prefix(self.repo_root) {
            return stripped.to_path_buf();
        }
        if let Ok(canonical_root) = self.repo_root.canonicalize()
            && let Ok(stripped) = candidate.strip_prefix(&canonical_root)
        {
            return stripped.to_path_buf();
        }
        candidate.to_path_buf()
    }
}

#[derive(Default)]
struct CallSiteCollector {
    function_call_targets: Vec<NodeID>,
    modifier_invocation_targets: Vec<NodeID>,
}

impl Visitor for CallSiteCollector {
    fn visit_function_call(&mut self, function_call: &FunctionCall) {
        if let Some(target) = function_call_target(function_call) {
            self.function_call_targets.push(target);
        }
    }

    fn visit_modifier_invocation(&mut self, invocation: &ModifierInvocation) {
        let target = match &invocation.modifier_name {
            IdentifierOrIdentifierPath::Identifier(identifier) => identifier.referenced_declaration,
            IdentifierOrIdentifierPath::IdentifierPath(path) => Some(path.referenced_declaration),
        };
        if let Some(target) = target {
            self.modifier_invocation_targets.push(target);
        }
    }
}

fn function_call_target(function_call: &FunctionCall) -> Option<NodeID> {
    match &function_call.expression {
        Expression::Identifier(identifier) => identifier.referenced_declaration,
        Expression::MemberAccess(member) => member.referenced_declaration,
        _ => None,
    }
}

fn sort_functions(left: &Function, right: &Function) -> std::cmp::Ordering {
    left.relative_file_path
        .cmp(&right.relative_file_path)
        .then_with(|| left.loc.start_line.cmp(&right.loc.start_line))
        .then_with(|| left.loc.start_column.cmp(&right.loc.start_column))
        .then_with(|| left.id.cmp(&right.id))
}

fn display_function_name(function: &FunctionDefinition) -> String {
    if !function.name.is_empty() {
        return function.name.clone();
    }
    match function.kind() {
        FunctionKind::Constructor => "constructor".to_string(),
        FunctionKind::Receive => "receive".to_string(),
        FunctionKind::Fallback => "fallback".to_string(),
        FunctionKind::Function | FunctionKind::FreeFunction => function.name.clone(),
    }
}

fn parameter_list_text(
    parameters: &ParameterList,
    source: &str,
) -> Result<String, color_eyre::Report> {
    if parameters.parameters.is_empty() {
        return Ok(String::new());
    }

    let first = parameters
        .parameters
        .first()
        .expect("parameter list checked non-empty");
    let last = parameters
        .parameters
        .last()
        .expect("parameter list checked non-empty");

    let (first_offset, _, _) = source_location_components(&first.src)?;
    let (last_offset, last_length, _) = source_location_components(&last.src)?;
    let end = last_offset + last_length;
    ensure!(
        end >= first_offset,
        "parameter list end offset {end} precedes first offset {first_offset}"
    );
    ensure!(
        end <= source.len(),
        "parameter range end {end} exceeds source length {}",
        source.len()
    );
    ensure!(
        source.is_char_boundary(first_offset) && source.is_char_boundary(end),
        "parameter range {first_offset}..{end} crosses a UTF-8 boundary"
    );

    Ok(source[first_offset..end].trim().to_string())
}

fn chunk_from_src(src: &SourceLocation, source: &str) -> Result<FileChunk, color_eyre::Report> {
    let (offset, length, _) = source_location_components(src)?;
    let end = offset + length;
    ensure!(
        end <= source.len(),
        "src range {offset}..{end} exceeds source length {}",
        source.len()
    );
    ensure!(
        source.is_char_boundary(offset) && source.is_char_boundary(end),
        "src range {offset}..{end} crosses a UTF-8 boundary"
    );

    let (start_line, start_column) = byte_to_line_column(source, offset)?;
    let (end_line, end_column) = byte_to_line_column(source, end)?;
    Ok(FileChunk {
        loc: FileLocation {
            start_line,
            start_column,
            end_line,
            end_column,
        },
        content: source[offset..end].to_string(),
    })
}

fn source_location_components(
    src: &SourceLocation,
) -> Result<(usize, usize, Option<usize>), color_eyre::Report> {
    let offset = src
        .start
        .wrap_err("source location is missing start offset")?;
    let length = src.length.wrap_err("source location is missing length")?;
    Ok((offset, length, src.index))
}

fn byte_to_line_column(source: &str, byte: usize) -> Result<(usize, usize), color_eyre::Report> {
    ensure!(
        byte <= source.len(),
        "byte offset {byte} exceeds source length"
    );
    ensure!(
        source.is_char_boundary(byte),
        "byte offset {byte} is not a UTF-8 character boundary"
    );

    let mut line = 1;
    let mut column = 0usize;
    for character in source[..byte].chars() {
        if character == '\n' {
            line += 1;
            column = 0;
        } else {
            column += 1;
        }
    }
    Ok((line, column))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn byte_to_line_column_counts_lines() {
        let source = "abc\ndef\nghi";
        let (line, column) = byte_to_line_column(source, 4).expect("valid byte");
        assert_eq!(line, 2);
        assert_eq!(column, 0);

        let (line, column) = byte_to_line_column(source, 8).expect("valid byte");
        assert_eq!(line, 3);
        assert_eq!(column, 0);

        let (line, column) = byte_to_line_column(source, 6).expect("valid byte");
        assert_eq!(line, 2);
        assert_eq!(column, 2);
    }
}
