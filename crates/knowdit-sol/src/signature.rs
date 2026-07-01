//! Signature-head extraction for a single Solidity callable.
//!
//! Given the source text of one function / constructor / modifier / fallback /
//! receive, return its signature line — everything from the callable keyword up
//! to (but not including) the body block — with interior whitespace squashed
//! and inline comments removed.
//!
//! Done via tree-sitter (not string scanning): the body block's start byte is
//! determined by the grammar, so `{`, `}`, `;` and comment/string text inside
//! the signature region (block comments between params, a string in a modifier
//! argument, multi-line declarations) never trip an early cutoff — the failure
//! mode of the old hand-rolled character scanner.

use color_eyre::eyre::{Result, WrapErr, eyre};
use tree_sitter::{Node, Parser};

use crate::node::callable_kind_from_node;

/// Extract the signature head of the first callable found in `source`.
///
/// Returns `None` when `source` contains no callable (e.g. only a comment, or
/// unparseable text). Body-less declarations (interface functions) yield the
/// declaration with its trailing `;` stripped.
pub fn extract_function_signature(source: &str) -> Result<Option<String>> {
    // Constructors / modifiers / fallback / receive are only grammatical inside
    // a contract body, so wrap before parsing. Free functions would parse bare,
    // but wrapping handles every callable kind uniformly. Every byte offset
    // below indexes into `wrapped` (the extracted text is identical to the
    // input, just shifted).
    let wrapped = format!("contract __KnowditSigProbe {{\n{source}\n}}");

    let mut parser = Parser::new();
    let language = tree_sitter_solidity::LANGUAGE.into();
    parser
        .set_language(&language)
        .wrap_err("failed to load tree-sitter Solidity grammar")?;
    let tree = parser
        .parse(&wrapped, None)
        .ok_or_else(|| eyre!("tree-sitter returned no parse tree for the input source"))?;

    let Some(callable) = first_callable(tree.root_node(), &wrapped) else {
        return Ok(None);
    };

    // The header runs from the callable keyword up to its body block. A
    // body-less declaration has no `body` field, so fall back to the node end
    // (its trailing `;` is stripped below).
    let head_start = callable.start_byte();
    let head_end = callable
        .child_by_field_name("body")
        .map(|body| body.start_byte())
        .unwrap_or_else(|| callable.end_byte());
    if !wrapped.is_char_boundary(head_start) || !wrapped.is_char_boundary(head_end) {
        return Err(eyre!(
            "tree-sitter produced a non-UTF-8-boundary signature range {head_start}..{head_end}"
        ));
    }

    // Excise comment nodes so inline `//` / `/* */` NatSpec inside the signature
    // region doesn't leak into the rendered text.
    let mut comments = Vec::new();
    collect_comment_spans(callable, head_start, head_end, &mut comments);
    comments.sort_unstable();

    let mut head = String::new();
    let mut cursor = head_start;
    for (start, end) in comments {
        if start >= cursor {
            head.push_str(&wrapped[cursor..start]);
            head.push(' ');
            cursor = end;
        }
    }
    head.push_str(&wrapped[cursor..head_end]);

    let collapsed = head
        .trim_end_matches(';')
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    Ok((!collapsed.is_empty()).then_some(collapsed))
}

/// Depth-first search for the first callable-definition node.
fn first_callable<'tree>(node: Node<'tree>, source: &str) -> Option<Node<'tree>> {
    if callable_kind_from_node(node, source).is_some() {
        return Some(node);
    }
    let mut cursor = node.walk();
    let children = node.named_children(&mut cursor).collect::<Vec<_>>();
    children
        .into_iter()
        .find_map(|child| first_callable(child, source))
}

/// Collect the byte spans of `comment` nodes lying within `[lo, hi)`.
fn collect_comment_spans(node: Node<'_>, lo: usize, hi: usize, out: &mut Vec<(usize, usize)>) {
    if node.kind() == "comment" {
        let (start, end) = (node.start_byte(), node.end_byte());
        if start >= lo && end <= hi {
            out.push((start, end));
            return;
        }
    }
    let mut cursor = node.walk();
    let children = node.children(&mut cursor).collect::<Vec<_>>();
    for child in children {
        // Only descend into nodes overlapping the header region.
        if child.start_byte() < hi && child.end_byte() > lo {
            collect_comment_spans(child, lo, hi, out);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::extract_function_signature;

    fn sig(source: &str) -> Option<String> {
        extract_function_signature(source).expect("parse should not fail")
    }

    #[test]
    fn plain_function_body_is_dropped() {
        assert_eq!(
            sig("function foo() public {\n    x = 1;\n}").as_deref(),
            Some("function foo() public"),
        );
    }

    #[test]
    fn visibility_mutability_and_returns_are_kept() {
        assert_eq!(
            sig("function foo() public view returns (uint256) { return 1; }").as_deref(),
            Some("function foo() public view returns (uint256)"),
        );
    }

    #[test]
    fn multiline_signature_is_collapsed() {
        assert_eq!(
            sig("function foo(\n    uint a,\n    uint b\n) external returns (bool) {\n}")
                .as_deref(),
            Some("function foo( uint a, uint b ) external returns (bool)"),
        );
    }

    #[test]
    fn block_comment_braces_and_semicolons_do_not_terminate() {
        // The `;` and `{` inside the block comment must not cut the head short,
        // and the comment text itself must not leak into the result.
        assert_eq!(
            sig("function foo(/* a; b { c */ uint x) public {}").as_deref(),
            Some("function foo( uint x) public"),
        );
    }

    #[test]
    fn line_comment_semicolon_does_not_terminate() {
        assert_eq!(
            sig("function foo() public // ends; here\n{}").as_deref(),
            Some("function foo() public"),
        );
    }

    #[test]
    fn string_literal_delimiters_are_ignored_and_kept() {
        assert_eq!(
            sig("function foo() public onlyRole(\"admin{;}\") {}").as_deref(),
            Some("function foo() public onlyRole(\"admin{;}\")"),
        );
    }

    #[test]
    fn constructor_and_modifier_are_recognized() {
        assert_eq!(
            sig("constructor(uint256 x) Ownable() { y = x; }").as_deref(),
            Some("constructor(uint256 x) Ownable()"),
        );
        assert_eq!(
            sig("modifier onlyOwner() { require(msg.sender == owner); _; }").as_deref(),
            Some("modifier onlyOwner()"),
        );
    }

    #[test]
    fn bodyless_declaration_strips_trailing_semicolon() {
        assert_eq!(
            sig("function foo() external view returns (uint256);").as_deref(),
            Some("function foo() external view returns (uint256)"),
        );
    }

    #[test]
    fn no_callable_or_empty_is_none() {
        assert_eq!(sig("// just a comment"), None);
        assert_eq!(sig(""), None);
        assert_eq!(sig("   \n\t "), None);
    }
}
