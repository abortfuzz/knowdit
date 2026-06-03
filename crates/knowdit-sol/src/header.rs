//! "Header" extraction for a Solidity source file: every byte before
//! the first contract / interface / library / abstract-contract
//! declaration. By construction this captures the leading SPDX
//! comment, `pragma` line(s), every `import` statement, and any blank
//! lines or comments interleaved with them — exactly the slice the
//! harness agent needs to imitate when authoring a new test file.
//!
//! Implemented via tree-sitter (not string scanning) so quirks like
//! block comments, multi-line `import { ... }`, or pragma versions
//! split across lines don't trip the cutoff.

use color_eyre::eyre::{Result, WrapErr, eyre};
use tree_sitter::Parser;

/// Return every byte in `source` up to (but not including) the first
/// contract-shaped top-level declaration. Returns the whole source
/// when none is found (e.g. an interface-only file).
pub fn extract_header(source: &str) -> Result<String> {
    let mut parser = Parser::new();
    let language = tree_sitter_solidity::LANGUAGE.into();
    parser
        .set_language(&language)
        .wrap_err("failed to load tree-sitter Solidity grammar")?;
    let tree = parser
        .parse(source, None)
        .ok_or_else(|| eyre!("tree-sitter returned no parse tree for the input source"))?;
    let root = tree.root_node();
    let mut cutoff = source.len();
    for i in 0..root.named_child_count() {
        // `named_child` only returns Some for indices < named_child_count
        // by construction, so the unwrap below cannot trip.
        let child = root.named_child(i).expect("i < named_child_count");
        if matches!(
            child.kind(),
            "contract_declaration"
                | "interface_declaration"
                | "library_declaration"
                | "abstract_contract_declaration"
        ) {
            cutoff = child.start_byte();
            break;
        }
    }
    // Clamp to a UTF-8 boundary in case tree-sitter handed back a byte
    // offset mid-codepoint (it shouldn't, but `to_string()` panics if
    // we slice mid-char).
    while cutoff > 0 && !source.is_char_boundary(cutoff) {
        cutoff -= 1;
    }
    Ok(source[..cutoff].to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn picks_up_spdx_pragma_and_imports() {
        let src = "// SPDX-License-Identifier: UNLICENSED\n\
                   pragma solidity ^0.8.24;\n\
                   import {Foo} from \"foo/Foo.sol\";\n\
                   import \"forge-std/Test.sol\";\n\
                   \n\
                   contract Test_42 is Test {\n\
                       function setUp() public {}\n\
                   }\n";
        let header = extract_header(src).unwrap();
        assert!(header.contains("// SPDX-License-Identifier"));
        assert!(header.contains("pragma solidity"));
        assert!(header.contains("import {Foo}"));
        assert!(header.contains("forge-std/Test.sol"));
        assert!(!header.contains("contract Test_42"));
    }

    #[test]
    fn keeps_full_source_when_no_contract_declaration() {
        let src = "pragma solidity ^0.8.0;\nimport \"a.sol\";\n";
        let header = extract_header(src).unwrap();
        assert_eq!(header, src);
    }

    #[test]
    fn cuts_at_abstract_contract() {
        let src = "pragma solidity ^0.8.0;\nimport \"a.sol\";\nabstract contract Foo {}\ncontract Bar {}\n";
        let header = extract_header(src).unwrap();
        assert!(header.contains("import \"a.sol\""));
        assert!(!header.contains("abstract contract"));
        assert!(!header.contains("contract Bar"));
    }
}
