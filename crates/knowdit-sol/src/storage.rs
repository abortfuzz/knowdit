//! Tree-sitter extraction of state variables and inheritance specifiers, mirroring
//! `cg::extract_repo_contracts_functions` but yielding storage-shaped records rather than
//! callgraph-shaped ones. The output is project-local: contract ids match
//! [`crate::cg::ExtractedContract::id`] and inheritance is resolved by *name within the same
//! project*. Names that don't resolve (3rd-party imports, etc.) are dropped silently.

use std::{
    collections::{BTreeMap, HashMap},
    path::PathBuf,
};

use color_eyre::eyre::{ContextCompat, WrapErr, ensure};
use knowdit_repo_model::cg::FileChunk;
use serde::Serialize;
use tree_sitter::{Node, Parser};

use crate::cg::{ExtractedContract, SolidityContractKind};

/// One state variable declared inside a tree-sitter-extracted contract.
#[derive(Debug, Clone, Serialize)]
pub struct ExtractedStateVariable {
    pub id: i32,
    /// Project-local id of the declaring contract (matches `ExtractedContract.id`).
    pub contract_id: i32,
    /// Declaring contract name (denormalized for readability).
    pub contract_name: String,
    pub name: String,
    /// Stringified Solidity type as it appears in source (mappings/structs included verbatim).
    pub type_text: String,
    /// True for `constant` declarations; we still record them but the agent should skip them as
    /// "no storage" rows.
    pub is_constant: bool,
    /// True for `immutable` declarations; immutables are stored in code, not storage, but the
    /// agent typically treats them as state variables for read/write purposes.
    pub is_immutable: bool,
    pub relative_file_path: PathBuf,
    pub chunk: FileChunk,
}

/// One direct `is`-spec edge captured per contract. `parent_name` is the textual reference;
/// `parent_contract_id` is `None` if it doesn't resolve to any project-local contract.
#[derive(Debug, Clone, Serialize)]
pub struct ExtractedInheritance {
    pub contract_id: i32,
    pub contract_name: String,
    pub parent_name: String,
    pub parent_contract_id: Option<i32>,
}

/// Bundled output of the tree-sitter storage extractor.
#[derive(Debug, Clone, Serialize, Default)]
pub struct StorageExtractionResult {
    pub state_variables: Vec<ExtractedStateVariable>,
    pub inherits: Vec<ExtractedInheritance>,
}

/// Walk the same .sol files used by the call-graph extractor and pull out state variables and
/// inheritance specifiers. The caller is expected to have already parsed/extracted contracts
/// via [`crate::cg::extract_repo_contracts_functions`]; we reuse the (id, name) mapping so the
/// project-local ids stay consistent across the two passes.
pub async fn extract_state_variables_and_inheritance(
    repo_root: &std::path::Path,
    contracts: &[ExtractedContract],
) -> Result<StorageExtractionResult, color_eyre::Report> {
    let mut parser = Parser::new();
    let language = tree_sitter_solidity::LANGUAGE.into();
    parser
        .set_language(&language)
        .wrap_err("failed to load tree-sitter Solidity grammar")?;

    // Group contract ids by their (relative_file_path, name) so we can re-attach state vars
    // from a fresh tree-sitter pass. Names should be unique within a single .sol file in
    // well-formed projects; if there's a clash we take the first-seen contract id.
    let mut id_by_file_and_name: HashMap<(PathBuf, String), i32> = HashMap::new();
    let mut name_to_ids: BTreeMap<String, Vec<i32>> = BTreeMap::new();
    for c in contracts {
        id_by_file_and_name
            .entry((c.relative_file_path.clone(), c.name.clone()))
            .or_insert(c.id);
        name_to_ids.entry(c.name.clone()).or_default().push(c.id);
    }
    // De-dup file lists so we parse each file once.
    let mut files_to_parse: Vec<PathBuf> = contracts
        .iter()
        .map(|c| c.relative_file_path.clone())
        .collect();
    files_to_parse.sort();
    files_to_parse.dedup();

    let mut state_variables = Vec::new();
    let mut inherits = Vec::new();
    let mut next_state_var_id = 1i32;

    for relative in &files_to_parse {
        let absolute = repo_root.join(relative);
        let source = tokio::fs::read_to_string(&absolute)
            .await
            .wrap_err_with(|| format!("failed to read Solidity file {}", absolute.display()))?;
        let tree = parser
            .parse(source.as_bytes(), None)
            .wrap_err_with(|| format!("failed to parse Solidity file {}", absolute.display()))?;
        let root = tree.root_node();

        let mut contract_nodes = Vec::new();
        crate::node::collect_contract_nodes_pub(root, &mut contract_nodes);

        for cn in contract_nodes {
            if SolidityContractKind::from_node_kind(cn.kind()).is_none() {
                continue;
            }
            let Some(name_node) = cn.child_by_field_name("name") else {
                continue;
            };
            let contract_name = name_node
                .utf8_text(source.as_bytes())
                .ok()
                .map(|s| s.to_string())
                .unwrap_or_default();
            let Some(&contract_id) =
                id_by_file_and_name.get(&(relative.clone(), contract_name.clone()))
            else {
                continue;
            };

            // Inheritance specifiers
            let mut cursor = cn.walk();
            for child in cn.named_children(&mut cursor) {
                if child.kind() == "inheritance_specifier" {
                    let parent_name = parent_name_of_inheritance_specifier(child, &source);
                    let Some(parent_name) = parent_name else {
                        continue;
                    };
                    // Resolve by name. If multiple contracts share the name, keep them all (one
                    // row per resolution); typically there's one.
                    let parent_ids = name_to_ids.get(&parent_name).cloned().unwrap_or_default();
                    if parent_ids.is_empty() {
                        inherits.push(ExtractedInheritance {
                            contract_id,
                            contract_name: contract_name.clone(),
                            parent_name,
                            parent_contract_id: None,
                        });
                    } else {
                        for pid in parent_ids {
                            if pid == contract_id {
                                continue;
                            }
                            inherits.push(ExtractedInheritance {
                                contract_id,
                                contract_name: contract_name.clone(),
                                parent_name: parent_name.clone(),
                                parent_contract_id: Some(pid),
                            });
                        }
                    }
                }
            }

            // State variables
            if let Some(body) = cn.child_by_field_name("body") {
                let mut cursor = body.walk();
                for child in body.named_children(&mut cursor) {
                    if child.kind() != "state_variable_declaration" {
                        continue;
                    }
                    let Some(state_var) = parse_state_variable(
                        child,
                        &source,
                        next_state_var_id,
                        contract_id,
                        contract_name.clone(),
                        relative.clone(),
                    )?
                    else {
                        continue;
                    };
                    next_state_var_id += 1;
                    state_variables.push(state_var);
                }
            }
        }
    }

    Ok(StorageExtractionResult {
        state_variables,
        inherits,
    })
}

fn parent_name_of_inheritance_specifier(node: Node<'_>, source: &str) -> Option<String> {
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if child.kind() == "user_defined_type" {
            let mut cur2 = child.walk();
            // Take the last identifier — for `Foo.Bar` it's the inner name; if a single
            // identifier, that's the parent name.
            let mut last_id: Option<Node<'_>> = None;
            for c in child.named_children(&mut cur2) {
                if c.kind() == "identifier" {
                    last_id = Some(c);
                }
            }
            if let Some(id_node) = last_id
                && let Ok(text) = id_node.utf8_text(source.as_bytes())
            {
                return Some(text.to_string());
            }
        } else if child.kind() == "identifier"
            && let Ok(text) = child.utf8_text(source.as_bytes())
        {
            return Some(text.to_string());
        }
    }
    None
}

fn parse_state_variable(
    node: Node<'_>,
    source: &str,
    id: i32,
    contract_id: i32,
    contract_name: String,
    relative_file_path: PathBuf,
) -> Result<Option<ExtractedStateVariable>, color_eyre::Report> {
    let raw = node
        .utf8_text(source.as_bytes())
        .wrap_err("state_variable_declaration is not utf-8")?;

    // Name: last named identifier child (after type_name). Skip identifiers nested inside
    // type_name (e.g. user-defined struct name).
    let mut name: Option<String> = None;
    let mut type_text: Option<String> = None;
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        match child.kind() {
            "type_name" => {
                let text = child
                    .utf8_text(source.as_bytes())
                    .wrap_err("type_name not utf-8")?;
                type_text = Some(text.trim().to_string());
            }
            "identifier" => {
                let text = child
                    .utf8_text(source.as_bytes())
                    .wrap_err("identifier not utf-8")?;
                name = Some(text.to_string());
            }
            _ => {}
        }
    }
    let Some(name) = name else {
        return Ok(None);
    };
    let type_text = type_text.unwrap_or_default();

    let is_constant = contains_keyword(raw, "constant");
    let is_immutable = contains_keyword(raw, "immutable");

    ensure!(
        source.is_char_boundary(node.start_byte()) && source.is_char_boundary(node.end_byte()),
        "tree-sitter produced non-UTF-8-boundary state variable range {}..{}",
        node.start_byte(),
        node.end_byte()
    );
    let chunk = crate::node::node_chunk_pub(node, source)?;

    Ok(Some(ExtractedStateVariable {
        id,
        contract_id,
        contract_name,
        name,
        type_text,
        is_constant,
        is_immutable,
        relative_file_path,
        chunk,
    }))
}

fn contains_keyword(haystack: &str, kw: &str) -> bool {
    let mut idx = 0usize;
    while let Some(found) = haystack[idx..].find(kw) {
        let pos = idx + found;
        let before = pos
            .checked_sub(1)
            .and_then(|p| haystack.as_bytes().get(p))
            .copied();
        let after = haystack.as_bytes().get(pos + kw.len()).copied();
        let lhs_ok = before.is_none_or(|b| !is_id_byte(b));
        let rhs_ok = after.is_none_or(|b| !is_id_byte(b));
        if lhs_ok && rhs_ok {
            return true;
        }
        idx = pos + kw.len();
    }
    false
}

fn is_id_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}
