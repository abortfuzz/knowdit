use color_eyre::eyre::{ContextCompat, WrapErr, ensure};
use knowdit_repo_model::cg::{FileChunk, FileLocation};
use tree_sitter::Node;

use crate::cg::{SolidityCallableKind, SolidityContractKind};

pub fn collect_contract_nodes_pub<'tree>(node: Node<'tree>, out: &mut Vec<Node<'tree>>) {
    collect_contract_nodes(node, out);
}

pub fn node_chunk_pub(node: Node<'_>, source: &str) -> Result<FileChunk, color_eyre::Report> {
    node_chunk(node, source)
}

pub(crate) fn collect_contract_nodes<'tree>(node: Node<'tree>, out: &mut Vec<Node<'tree>>) {
    if SolidityContractKind::from_node_kind(node.kind()).is_some() {
        out.push(node);
        return;
    }

    let mut cursor = node.walk();
    let children = node.named_children(&mut cursor).collect::<Vec<_>>();
    for child in children {
        collect_contract_nodes(child, out);
    }
}

pub(crate) fn callable_kind_from_node(
    node: Node<'_>,
    source: &str,
) -> Option<SolidityCallableKind> {
    match node.kind() {
        "function_definition" => Some(SolidityCallableKind::Function),
        "constructor_definition" => Some(SolidityCallableKind::Constructor),
        "modifier_definition" => Some(SolidityCallableKind::Modifier),
        "fallback_receive_definition" => {
            if node_text_lossy(node, source)
                .trim_start()
                .starts_with("receive")
            {
                Some(SolidityCallableKind::Receive)
            } else {
                Some(SolidityCallableKind::Fallback)
            }
        }
        _ => None,
    }
}

pub(crate) fn callable_name(
    node: Node<'_>,
    kind: SolidityCallableKind,
    source: &str,
) -> Result<String, color_eyre::Report> {
    match kind {
        SolidityCallableKind::Function | SolidityCallableKind::Modifier => {
            node_field_text(node, "name", source)
        }
        SolidityCallableKind::Constructor => Ok("constructor".to_string()),
        SolidityCallableKind::Receive => Ok("receive".to_string()),
        SolidityCallableKind::Fallback => Ok("fallback".to_string()),
    }
}

pub(crate) fn callable_args(node: Node<'_>, source: &str) -> Result<String, color_eyre::Report> {
    let mut cursor = node.walk();
    let cutoff = callable_parameter_cutoff(node, source)?;
    let parameters = node
        .named_children(&mut cursor)
        .filter(|child| child.kind() == "parameter" && child.start_byte() < cutoff)
        .collect::<Vec<_>>();

    let Some(first_parameter) = parameters.first() else {
        return Ok(String::new());
    };
    let last_parameter = parameters
        .last()
        .expect("non-empty parameters should have a last element");

    ensure!(
        source.is_char_boundary(first_parameter.start_byte())
            && source.is_char_boundary(last_parameter.end_byte()),
        "tree-sitter produced non-UTF-8-boundary parameter-list range {}..{}",
        first_parameter.start_byte(),
        last_parameter.end_byte()
    );

    Ok(
        source[first_parameter.start_byte()..last_parameter.end_byte()]
            .trim()
            .to_string(),
    )
}

pub(crate) fn node_field_text(
    node: Node<'_>,
    field: &str,
    source: &str,
) -> Result<String, color_eyre::Report> {
    let field_node = node
        .child_by_field_name(field)
        .wrap_err_with(|| format!("node {} is missing field {field}", node.kind()))?;
    node_text(field_node, source)
}

pub(crate) fn node_text(node: Node<'_>, source: &str) -> Result<String, color_eyre::Report> {
    Ok(node
        .utf8_text(source.as_bytes())
        .wrap_err_with(|| format!("failed to read text for node {}", node.kind()))?
        .to_string())
}

pub(crate) fn node_text_lossy(node: Node<'_>, source: &str) -> String {
    node.utf8_text(source.as_bytes())
        .unwrap_or_default()
        .to_string()
}

pub(crate) fn node_chunk(node: Node<'_>, source: &str) -> Result<FileChunk, color_eyre::Report> {
    ensure!(
        source.is_char_boundary(node.start_byte()) && source.is_char_boundary(node.end_byte()),
        "tree-sitter produced non-UTF-8-boundary byte range {}..{}",
        node.start_byte(),
        node.end_byte()
    );
    Ok(FileChunk {
        loc: file_location_from_node(node, source)?,
        content: source[node.start_byte()..node.end_byte()].to_string(),
    })
}

fn file_location_from_node(
    node: Node<'_>,
    source: &str,
) -> Result<FileLocation, color_eyre::Report> {
    let (start_line, start_column) = byte_to_line_column(source, node.start_byte())?;
    let (end_line, end_column) = byte_to_line_column(source, node.end_byte())?;
    Ok(FileLocation {
        start_line,
        start_column,
        end_line,
        end_column,
    })
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
    let mut column = 0;
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

fn callable_parameter_cutoff(node: Node<'_>, source: &str) -> Result<usize, color_eyre::Report> {
    let body_start = node
        .child_by_field_name("body")
        .map(|body| body.start_byte())
        .unwrap_or_else(|| node.end_byte());
    ensure!(
        source.is_char_boundary(node.start_byte()) && source.is_char_boundary(body_start),
        "tree-sitter produced non-UTF-8-boundary callable header range {}..{}",
        node.start_byte(),
        body_start
    );

    let header = &source[node.start_byte()..body_start];
    Ok(find_ascii_keyword(header, "returns")
        .map(|offset| node.start_byte() + offset)
        .unwrap_or(body_start))
}

fn find_ascii_keyword(haystack: &str, keyword: &str) -> Option<usize> {
    haystack.match_indices(keyword).find_map(|(index, _)| {
        let before = index
            .checked_sub(1)
            .and_then(|previous| haystack.as_bytes().get(previous))
            .copied();
        let after = haystack.as_bytes().get(index + keyword.len()).copied();
        if before.is_none_or(|byte| !is_identifier_byte(byte))
            && after.is_none_or(|byte| !is_identifier_byte(byte))
        {
            Some(index)
        } else {
            None
        }
    })
}

fn is_identifier_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}
