//! Shared rendering for a canonical text field plus its merged-variant notes.
//!
//! A canonical semantic/finding keeps a concise, concrete representative in its
//! own field; each raw child folded into it contributes a short
//! `appended_description` on the merge edge describing how that variant extends
//! the canonical. This helper composes the two into one block, capping the
//! number of variant notes so a canonical merged hundreds of times cannot blow
//! up a prompt. Shared by the KG-side link candidate rendering and the
//! per-project mirror's `render_*` accessors.

/// Which representation of a canonical field's merged variants to render.
///
/// The two modes produce the same visual block (via
/// [`render_with_variants_capped`]); they differ only in what the caller passes
/// as the entry list, so every consumer (link candidates, the per-project
/// mirror, spec/harness prompts) stays on one shared render path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VariantMode {
    /// Each entry is a short `appended_*` delta note (how the child extends the
    /// canonical). Compact — safe for large fan-out.
    Compact,
    /// Each entry is a merged child's full raw field text. Richest context,
    /// approaching the pre-Option-A inline density; bound with the caps.
    RawChildren,
}

/// Render `canonical` followed by up to `cap` variant `notes`. Blank notes are
/// skipped; when more than `cap` non-blank notes remain, the dropped count is
/// disclosed rather than silently truncated.
///
/// Thin wrapper over [`render_with_variants_capped`] with no per-entry cap.
pub fn render_with_variants(canonical: &str, notes: &[String], cap: usize) -> String {
    render_with_variants_capped(canonical, notes, cap, 0)
}

/// Render `canonical` followed by up to `cap` variant `entries`, each truncated
/// to `per_entry_chars` characters (`0` = no per-entry truncation). Blank
/// entries are skipped; entries beyond `cap` are disclosed as a count.
///
/// The single shared render path for both [`VariantMode`]s: the caller chooses
/// whether `entries` are compact delta notes or full raw-child texts, and the
/// count cap plus per-entry char cap keep even a heavily-merged canonical from
/// blowing up the prompt.
pub fn render_with_variants_capped(
    canonical: &str,
    entries: &[String],
    cap: usize,
    per_entry_chars: usize,
) -> String {
    let mut out = canonical.trim().to_string();
    let variants: Vec<&str> = entries
        .iter()
        .map(|n| n.trim())
        .filter(|n| !n.is_empty())
        .collect();
    if variants.is_empty() {
        return out;
    }
    // Render each folded raw as a SUBORDINATE context line (exp-era framing),
    // NOT a "Merged variants … extends the above" block — the latter invited the
    // linker to treat every folded variant as another matchable mechanism and
    // over-assign High. `label_variant` already prefixes each note with
    // `additional context (from raw "<name>"): …`.
    for note in variants.iter().take(cap) {
        out.push_str("\n— ");
        if per_entry_chars > 0 && note.chars().count() > per_entry_chars {
            let kept: String = note.chars().take(per_entry_chars).collect();
            out.push_str(&kept);
            out.push_str(" …[truncated]");
        } else {
            out.push_str(note);
        }
    }
    let shown = variants.len().min(cap);
    if variants.len() > shown {
        out.push_str(&format!(
            "\n— (+{} more folded raws not shown)",
            variants.len() - shown
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_notes_returns_canonical_only() {
        assert_eq!(
            render_with_variants("canonical text", &[], 50),
            "canonical text"
        );
    }

    #[test]
    fn blank_notes_are_skipped() {
        let notes = vec!["  ".to_string(), "".to_string()];
        assert_eq!(render_with_variants("c", &notes, 50), "c");
    }

    #[test]
    fn renders_notes_and_discloses_overflow() {
        let notes = vec![
            "adds A".to_string(),
            "adds B".to_string(),
            "adds C".to_string(),
        ];
        let out = render_with_variants("canonical", &notes, 2);
        assert!(out.contains("— adds A"));
        assert!(out.contains("— adds B"));
        assert!(!out.contains("adds C"));
        assert!(out.contains("+1 more folded raws not shown"));
    }

    #[test]
    fn per_entry_char_cap_truncates_shown_entries() {
        let notes = vec!["abcdefghij".to_string()];
        let out = render_with_variants_capped("c", &notes, 50, 4);
        assert!(out.contains("— abcd …[truncated]"));
        assert!(!out.contains("abcde"));
    }

    #[test]
    fn zero_char_cap_means_no_truncation() {
        let notes = vec!["abcdefghij".to_string()];
        let out = render_with_variants_capped("c", &notes, 50, 0);
        assert!(out.contains("— abcdefghij"));
        assert!(!out.contains("truncated"));
    }
}
