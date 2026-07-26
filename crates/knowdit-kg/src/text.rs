//! Shared text helpers for rendering values into prompts, labels, and logs.
//!
//! These exist here rather than next to each caller because the same
//! "shorten this for display" need showed up independently in the graph
//! renderer, the audit prompts, and the CLI's progress lines, and three
//! near-identical copies is how they drift apart.

/// Collapse whitespace and cut to `max_chars` characters, appending `…` when
/// anything was dropped.
///
/// Character-based rather than byte-based because callers are budgeting a
/// prompt or a label, not a buffer, and because slicing bytes through a
/// multi-byte character panics. Whitespace is collapsed first so a multi-line
/// database field renders as one line and spends its budget on content rather
/// than on indentation.
///
/// For capturing subprocess output use
/// `harness::solidity::utils::truncate_str` instead — that one is byte-bounded
/// and states how much it dropped, which is what a log reader needs.
pub fn truncate_text(value: &str, max_chars: usize) -> String {
    let compact = value.split_whitespace().collect::<Vec<_>>().join(" ");
    let mut chars = compact.chars();
    let truncated: String = chars.by_ref().take(max_chars).collect();
    if chars.next().is_some() {
        format!("{}…", truncated.trim_end())
    } else {
        compact
    }
}
