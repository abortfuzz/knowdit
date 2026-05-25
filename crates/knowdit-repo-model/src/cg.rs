use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
};

use color_eyre::eyre::{WrapErr, ensure};
use ropey::Rope;
use serde::{Deserialize, Serialize};

/// A source range inside a file.
///
/// Lines are 1-based and columns are 0-based character offsets. The end
/// position is exclusive, so the range can be passed directly to text slicing
/// after conversion to character offsets.
#[derive(Deserialize, Serialize, Clone, Copy, Debug)]
pub struct FileLocation {
    /// First line included in the range.
    pub start_line: usize,
    /// First column included on `start_line`.
    pub start_column: usize,
    /// Line containing the exclusive end position.
    pub end_line: usize,
    /// Exclusive end column on `end_line`.
    pub end_column: usize,
}

impl FileLocation {
    pub async fn to_chunk(&self, fpath: &Path) -> Result<FileChunk, color_eyre::Report> {
        let content = tokio::fs::read_to_string(fpath)
            .await
            .wrap_err_with(|| format!("failed to read source file {}", fpath.display()))?;
        let content = Rope::from_str(&content);

        let start_char = position_to_char(&content, self.start_line, self.start_column, fpath)?;
        let end_char = position_to_char(&content, self.end_line, self.end_column, fpath)?;

        ensure!(
            start_char <= end_char,
            "invalid file location for {}: start position {}:{} is after end position {}:{}",
            fpath.display(),
            self.start_line,
            self.start_column,
            self.end_line,
            self.end_column
        );

        Ok(FileChunk {
            loc: *self,
            content: content.slice(start_char..end_char).to_string(),
        })
    }
}

fn position_to_char(
    content: &Rope,
    line: usize,
    column: usize,
    fpath: &Path,
) -> Result<usize, color_eyre::Report> {
    ensure!(
        line > 0,
        "invalid file location for {}: line numbers are 1-based, got line 0",
        fpath.display()
    );

    let line_idx = line - 1;
    ensure!(
        line_idx < content.len_lines(),
        "invalid file location for {}: line {} is past end of file with {} lines",
        fpath.display(),
        line,
        content.len_lines()
    );

    let line_start = content.line_to_char(line_idx);
    let line_end = if line_idx + 1 < content.len_lines() {
        content.line_to_char(line_idx + 1)
    } else {
        content.len_chars()
    };
    let line_len = line_end - line_start;

    ensure!(
        column <= line_len,
        "invalid file location for {}: column {} is past end of line {} with {} columns",
        fpath.display(),
        column,
        line,
        line_len
    );

    Ok(line_start + column)
}

/// A source fragment paired with its original file location.
#[derive(Deserialize, Serialize, Clone, Debug)]
pub struct FileChunk {
    /// Source coordinates for this chunk.
    pub loc: FileLocation,
    /// Source text covered by `loc`.
    pub content: String,
}

/// A directed function-call edge in the repository call graph.
#[derive(Deserialize, Serialize, Clone, Debug)]
pub struct FunctionCall {
    /// Stable database identifier for the call edge.
    pub id: i32,
    /// Caller function id.
    pub from_id: i32,
    /// Callee function id.
    pub to_id: i32,
    /// Optional human-readable explanation of the call relationship.
    pub description: Option<String>,
}

/// A function node with its source chunk and outgoing call edges.
#[derive(Deserialize, Serialize, Clone, Debug)]
pub struct Function {
    /// Stable database identifier for the function.
    pub id: i32,
    /// Function name recorded during extraction.
    pub name: String,
    /// Solidity parameter-list text used to distinguish overloaded functions.
    pub args: String,
    /// Source file path relative to the repository root.
    pub relative_file_path: PathBuf,
    /// Source coordinates for the function body or declaration.
    pub loc: FileLocation,
    /// Source content for a concrete function definition. Interface declarations have no body.
    pub content: Option<String>,
    /// Outgoing calls from this function to other functions.
    pub calls: Vec<FunctionCall>,
    /// Optional semantic summary or notes for the function.
    pub description: Option<String>,
}

/// A contract/module containing the functions extracted from one source range.
#[derive(Deserialize, Serialize, Clone, Debug)]
pub struct Contract {
    /// Stable database identifier for the contract.
    pub id: i32,
    /// Contract name recorded during extraction.
    pub name: String,
    /// Source file path relative to the repository root.
    pub relative_file_path: PathBuf,
    /// Source chunk for the contract body or declaration.
    pub chunk: FileChunk,
    /// Functions belonging to this contract, sorted by source location.
    pub functions: Vec<Function>,
    /// Optional semantic summary or notes for the contract.
    pub description: Option<String>,
}

/// An interface containing function declarations extracted from one source range.
#[derive(Deserialize, Serialize, Clone, Debug)]
pub struct Interface {
    /// Stable database identifier for the interface.
    pub id: i32,
    /// Interface name recorded during extraction.
    pub name: String,
    /// Source file path relative to the repository root.
    pub relative_file_path: PathBuf,
    /// Source chunk for the interface declaration.
    pub chunk: FileChunk,
    /// Functions declared by this interface, sorted by source location.
    pub functions: Vec<Function>,
    /// Optional semantic summary or notes for the interface.
    pub description: Option<String>,
}

/// In-memory representation of the repository-level function call graph.
#[derive(Deserialize, Serialize, Clone, Debug)]
pub struct CallGraph {
    /// Contracts keyed by their database id for deterministic traversal.
    pub contracts: BTreeMap<i32, Contract>,
    /// Interfaces keyed by their database id for deterministic traversal.
    pub interfaces: BTreeMap<i32, Interface>,
}

/// One resolved callee returned by [`CallGraph::resolve_interface_function`].
/// `function_id` and `container_id` jointly identify the function within
/// its owning contract / interface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResolvedCallee {
    pub function_id: i32,
    pub container_id: i32,
    pub container_kind: ResolvedContainerKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResolvedContainerKind {
    Contract,
    Interface,
}

impl CallGraph {
    /// Look up a function by its database id, returning the owning
    /// container and the function itself. Returns `None` when the id
    /// doesn't appear in this graph.
    pub fn find_function(&self, function_id: i32) -> Option<(ResolvedCallee, &Function)> {
        for contract in self.contracts.values() {
            for function in &contract.functions {
                if function.id == function_id {
                    return Some((
                        ResolvedCallee {
                            function_id: function.id,
                            container_id: contract.id,
                            container_kind: ResolvedContainerKind::Contract,
                        },
                        function,
                    ));
                }
            }
        }
        for interface in self.interfaces.values() {
            for function in &interface.functions {
                if function.id == function_id {
                    return Some((
                        ResolvedCallee {
                            function_id: function.id,
                            container_id: interface.id,
                            container_kind: ResolvedContainerKind::Interface,
                        },
                        function,
                    ));
                }
            }
        }
        None
    }

    /// Resolve a (possibly interface) function id to every in-project
    /// concrete implementation. Strategy:
    ///
    /// 1. Look up the owning container of `function_id`. If the lookup
    ///    fails (id unknown to this graph) return an empty Vec.
    /// 2. Walk the descendants of that container in `inheritance` —
    ///    every contract that directly or transitively inherits the
    ///    owner. For each descendant, return the function with a
    ///    matching `(name, args)` signature, if one exists.
    /// 3. If the owning container is itself a concrete contract,
    ///    include the original function in the result (the original
    ///    site is a real callable — overrides in descendants extend
    ///    the polymorphic set but don't replace it).
    ///
    /// Empty Vec means "no in-project implementations found"; that
    /// happens for interface methods of external types or for stale
    /// graphs.
    pub fn resolve_interface_function(
        &self,
        inheritance: &crate::inheritance::InheritanceGraph,
        function_id: i32,
    ) -> Vec<ResolvedCallee> {
        let Some((origin, origin_fn)) = self.find_function(function_id) else {
            return Vec::new();
        };
        let signature = (origin_fn.name.as_str(), origin_fn.args.as_str());

        let mut out: Vec<ResolvedCallee> = Vec::new();
        // Concrete owner: the function itself is a valid callee.
        if matches!(origin.container_kind, ResolvedContainerKind::Contract) {
            out.push(origin);
        }
        for descendant_id in inheritance.descendants_of(origin.container_id) {
            let Some(contract) = self.contracts.get(&descendant_id) else {
                continue;
            };
            for function in &contract.functions {
                if function.name == signature.0 && function.args == signature.1 {
                    out.push(ResolvedCallee {
                        function_id: function.id,
                        container_id: contract.id,
                        container_kind: ResolvedContainerKind::Contract,
                    });
                }
            }
        }
        out
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct CallGraphDotOptions {
    pub include_isolated_nodes: bool,
}

/// Aggregate counts for one call graph. Cheap to compute (`O(n)` over
/// every container's function list) and intended for log lines /
/// progress reporting — not as a substitute for iterating the graph
/// itself.
#[derive(Clone, Copy, Debug, Default)]
pub struct CallGraphCounts {
    /// Number of contract-like containers — sum of `contracts` and
    /// `interfaces`. We bundle them because every container has a
    /// `functions` vec, and downstream log lines only care about the
    /// total.
    pub container_count: usize,
    pub function_count: usize,
    pub call_count: usize,
}

impl CallGraph {
    /// Aggregate node and edge counts across both contracts and
    /// interfaces. Used by every "wrote callgraph to..." log line —
    /// kept on the type so callers don't reach for an out-of-tree
    /// helper for what is structurally an accessor.
    pub fn counts(&self) -> CallGraphCounts {
        let containers = self
            .contracts
            .values()
            .map(|c| &c.functions)
            .chain(self.interfaces.values().map(|i| &i.functions));
        let mut function_count = 0usize;
        let mut call_count = 0usize;
        for functions in containers {
            function_count += functions.len();
            for function in functions {
                call_count += function.calls.len();
            }
        }
        CallGraphCounts {
            container_count: self.contracts.len() + self.interfaces.len(),
            function_count,
            call_count,
        }
    }

    pub fn export_dot(&self) -> String {
        self.export_dot_with_options(CallGraphDotOptions::default())
    }

    pub fn export_dot_with_options(&self, options: CallGraphDotOptions) -> String {
        let connected_function_ids = self.connected_function_ids();
        let mut dot = String::new();
        dot.push_str("digraph ProjectCallGraph {\n");
        dot.push_str("  rankdir=LR;\n");
        dot.push_str("  graph [compound=true];\n");
        dot.push_str("  node [shape=box, style=\"rounded,filled\", fontname=\"Helvetica\"];\n");
        dot.push_str("  edge [fontname=\"Helvetica\"];\n\n");

        for contract in self.contracts.values() {
            let functions = contract
                .functions
                .iter()
                .filter(|function| {
                    options.include_isolated_nodes || connected_function_ids.contains(&function.id)
                })
                .collect::<Vec<_>>();
            if functions.is_empty() {
                continue;
            }

            dot.push_str(&format!("  subgraph cluster_contract_{} {{\n", contract.id));
            dot.push_str(&format!(
                "    label=\"{}\";\n",
                escape_dot(&format!(
                    "contract {}\n{}",
                    contract.name,
                    contract.relative_file_path.display()
                ))
            ));
            dot.push_str("    color=\"#93c5fd\";\n");
            dot.push_str("    style=\"rounded\";\n");
            for function in functions {
                dot.push_str(&format!(
                    "    function_{} [label=\"{}\", fillcolor=\"#dbeafe\"];\n",
                    function.id,
                    escape_dot(&function_dot_label(function))
                ));
            }
            dot.push_str("  }\n\n");
        }

        for interface in self.interfaces.values() {
            let functions = interface
                .functions
                .iter()
                .filter(|function| {
                    options.include_isolated_nodes || connected_function_ids.contains(&function.id)
                })
                .collect::<Vec<_>>();
            if functions.is_empty() {
                continue;
            }

            dot.push_str(&format!(
                "  subgraph cluster_interface_{} {{\n",
                interface.id
            ));
            dot.push_str(&format!(
                "    label=\"{}\";\n",
                escape_dot(&format!(
                    "interface {}\n{}",
                    interface.name,
                    interface.relative_file_path.display()
                ))
            ));
            dot.push_str("    color=\"#c4b5fd\";\n");
            dot.push_str("    style=\"rounded,dashed\";\n");
            for function in functions {
                dot.push_str(&format!(
                    "    function_{} [label=\"{}\", fillcolor=\"#ede9fe\"];\n",
                    function.id,
                    escape_dot(&function_dot_label(function))
                ));
            }
            dot.push_str("  }\n\n");
        }

        for function in self
            .contracts
            .values()
            .flat_map(|contract| contract.functions.iter())
            .chain(
                self.interfaces
                    .values()
                    .flat_map(|interface| interface.functions.iter()),
            )
        {
            for call in &function.calls {
                if let Some(description) = &call.description {
                    dot.push_str(&format!(
                        "  function_{} -> function_{} [label=\"{}\"];\n",
                        call.from_id,
                        call.to_id,
                        escape_dot(&short_dot_label(description))
                    ));
                } else {
                    dot.push_str(&format!(
                        "  function_{} -> function_{};\n",
                        call.from_id, call.to_id
                    ));
                }
            }
        }

        dot.push_str("}\n");
        dot
    }

    fn connected_function_ids(&self) -> BTreeSet<i32> {
        let mut connected_function_ids = BTreeSet::new();
        for function in self
            .contracts
            .values()
            .flat_map(|contract| contract.functions.iter())
            .chain(
                self.interfaces
                    .values()
                    .flat_map(|interface| interface.functions.iter()),
            )
        {
            for call in &function.calls {
                connected_function_ids.insert(call.from_id);
                connected_function_ids.insert(call.to_id);
            }
        }
        connected_function_ids
    }
}

pub(crate) fn location_to_db(
    table: &'static str,
    id: i32,
    loc: &FileLocation,
) -> Result<(i32, i32, i32, i32), color_eyre::Report> {
    Ok((
        position_value_to_db(table, id, "start_line", loc.start_line)?,
        position_value_to_db(table, id, "start_column", loc.start_column)?,
        position_value_to_db(table, id, "end_line", loc.end_line)?,
        position_value_to_db(table, id, "end_column", loc.end_column)?,
    ))
}

fn position_value_to_db(
    table: &'static str,
    id: i32,
    field: &'static str,
    value: usize,
) -> Result<i32, color_eyre::Report> {
    ensure!(
        value <= i32::MAX as usize,
        "{} row {} has {} value too large for database: {}",
        table,
        id,
        field,
        value
    );
    Ok(value as i32)
}

pub(crate) fn location_from_db(
    table: &'static str,
    id: i32,
    start_line: i32,
    start_column: i32,
    end_line: i32,
    end_column: i32,
) -> Result<FileLocation, color_eyre::Report> {
    let loc = FileLocation {
        start_line: start_line as _,
        start_column: start_column as _,
        end_line: end_line as _,
        end_column: end_column as _,
    };

    ensure!(
        loc.start_line > 0 && loc.end_line > 0,
        "{} row {} has invalid 0-based line value: start_line={}, end_line={}",
        table,
        id,
        loc.start_line,
        loc.end_line
    );

    Ok(loc)
}

fn function_dot_label(function: &Function) -> String {
    format!(
        "{}({})\n{}:{}\nid={}",
        function.name,
        function.args,
        function.relative_file_path.display(),
        function.loc.start_line,
        function.id
    )
}

fn short_dot_label(value: &str) -> String {
    const MAX_CHARS: usize = 120;
    let mut label = value.lines().collect::<Vec<_>>().join(" ");
    if label.chars().count() <= MAX_CHARS {
        return label;
    }

    label = label.chars().take(MAX_CHARS - 3).collect::<String>();
    label.push_str("...");
    label
}

fn escape_dot(value: &str) -> String {
    value
        .chars()
        .flat_map(|character| match character {
            '\\' => "\\\\".chars().collect::<Vec<_>>(),
            '"' => "\\\"".chars().collect::<Vec<_>>(),
            '\n' => "\\n".chars().collect::<Vec<_>>(),
            '\r' => Vec::new(),
            character => vec![character],
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn exports_call_graph_as_dot() {
        let call_graph = CallGraph {
            contracts: BTreeMap::from([(
                1,
                Contract {
                    id: 1,
                    name: "Vault".to_string(),
                    relative_file_path: PathBuf::from("src/Vault.sol"),
                    chunk: chunk("contract Vault {}", 1, 0, 17),
                    functions: vec![
                        Function {
                            id: 1,
                            name: "deposit".to_string(),
                            args: "uint256 amount".to_string(),
                            relative_file_path: PathBuf::from("src/Vault.sol"),
                            loc: loc(2, 4, 40),
                            content: Some("function deposit(uint256 amount) {}".to_string()),
                            calls: vec![FunctionCall {
                                id: 1,
                                from_id: 1,
                                to_id: 2,
                                description: Some("updates accounting".to_string()),
                            }],
                            description: None,
                        },
                        Function {
                            id: 2,
                            name: "account".to_string(),
                            args: String::new(),
                            relative_file_path: PathBuf::from("src/Vault.sol"),
                            loc: loc(3, 4, 30),
                            content: Some("function account() {}".to_string()),
                            calls: Vec::new(),
                            description: None,
                        },
                    ],
                    description: None,
                },
            )]),
            interfaces: BTreeMap::from([(
                10,
                Interface {
                    id: 10,
                    name: "IERC20".to_string(),
                    relative_file_path: PathBuf::from("src/IERC20.sol"),
                    chunk: chunk("interface IERC20 {}", 1, 0, 19),
                    functions: vec![Function {
                        id: 10,
                        name: "transfer".to_string(),
                        args: "address to, uint256 amount".to_string(),
                        relative_file_path: PathBuf::from("src/IERC20.sol"),
                        loc: loc(2, 4, 70),
                        content: None,
                        calls: Vec::new(),
                        description: None,
                    }],
                    description: None,
                },
            )]),
        };

        let dot = call_graph.export_dot();

        assert!(dot.contains("digraph ProjectCallGraph"));
        assert!(dot.contains("subgraph cluster_contract_1"));
        assert!(!dot.contains("subgraph cluster_interface_10"));
        assert!(
            dot.contains("function_1 [label=\"deposit(uint256 amount)\\nsrc/Vault.sol:2\\nid=1\"")
        );
        assert!(dot.contains("function_2 [label=\"account()\\nsrc/Vault.sol:3\\nid=2\""));
        assert!(!dot.contains("function_10 [label="));
        assert!(dot.contains("function_1 -> function_2 [label=\"updates accounting\"]"));

        let dot_with_isolated = call_graph.export_dot_with_options(CallGraphDotOptions {
            include_isolated_nodes: true,
        });
        assert!(dot_with_isolated.contains("subgraph cluster_interface_10"));
        assert!(dot_with_isolated.contains("function_10 [label="));
    }

    fn chunk(content: &str, line: usize, start_column: usize, end_column: usize) -> FileChunk {
        FileChunk {
            loc: loc(line, start_column, end_column),
            content: content.to_string(),
        }
    }

    fn loc(line: usize, start_column: usize, end_column: usize) -> FileLocation {
        FileLocation {
            start_line: line,
            start_column,
            end_line: line,
            end_column,
        }
    }
}
