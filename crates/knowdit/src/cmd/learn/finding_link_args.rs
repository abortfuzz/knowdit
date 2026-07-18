use clap::Args;
use color_eyre::eyre::{Result, ensure};
use knowdit_kg::learn::FindingLinkOptions;

#[derive(Args, Debug, Clone, Copy, serde::Serialize, serde::Deserialize)]
pub struct FindingLinkCliArgs {
    /// Absolute ceiling on total input tokens per linking prompt. Unset ⇒
    /// derived from the model window × `--link-context-window-utilization`; can
    /// only lower it, never exceed it.
    #[arg(long)]
    pub input_token_budget: Option<usize>,

    /// Share of the input budget reserved for the findings block. The
    /// semantic-candidate block is NOT separately configured — it takes ALL
    /// input left after findings + system + prefix, so it fills the window
    /// automatically. LOWER this (e.g. 0.25) to leave more room for semantics →
    /// all canonicals fit ONE prompt → no candidate chunking → global
    /// competition (fewer, more selective links). Must be in (0, 1).
    #[arg(long, default_value_t = 0.35)]
    pub finding_token_ratio: f64,

    /// Hard ceiling on canonical semantics per chunk — the count analogue of the
    /// semantic token budget (which is just "all input left after findings").
    /// Because raw-children semantics vary wildly in size, the token budget alone
    /// can't pin the count; this does. Default is unbounded (token-only chunking);
    /// set a number to cap how many semantics the model must weigh per prompt.
    #[arg(long, default_value_t = usize::MAX)]
    pub max_semantics_per_batch: usize,

    /// Hard ceiling on findings per batch — independent of token budget.
    /// The default (135) does two jobs at once: it bounds the agent
    /// conversation's terminal size (each finding adds ~230-310 tokens of
    /// emit output on top of the first-step prompt — at a ~200K prompt,
    /// 135 findings keeps the terminal comfortably inside a 256K window),
    /// and it stops the small-finding tail from ballooning (short findings
    /// pack absurdly dense — ~150 tok/finding fits ~480 in a 72K budget).
    ///
    /// Batch size is ALSO a strong knob for link density: with few
    /// findings per request the agent elaborates on each and links
    /// liberally (<60 findings averaged ~0.85 links/finding); with many it
    /// stays terse (>=150 averaged ~0.05) — a ~15x swing. The Link-budget
    /// prompt block now carries most of the density control, but don't
    /// drop this far below ~100 without re-checking link counts, and don't
    /// push past ~600 — huge batches (700-finding agents, ~900 steps)
    /// finalize prematurely, retry heavily, hit per-request timeouts, and
    /// blind-eval WORSE on High calibration. `--link-max-agent-steps`
    /// auto-scales with this (1.2×) unless set explicitly.
    #[arg(long, default_value_t = 135)]
    pub max_findings_per_batch: usize,

    /// Maximum attempts per (finding-batch × semantic-chunk): if the agent
    /// finalizes without covering every finding in the batch, the runner
    /// re-runs a fresh agent restricted to the still-missing findings,
    /// up to this many times. Findings still missing after the cap are
    /// logged as a warning and treated as no-link.
    #[arg(long, default_value_t = 3)]
    pub max_response_attempts: usize,

    /// Per-attempt cap on agent steps (one tool call = one step): one
    /// emit per finding, one finalize, plus a few reasoning steps.
    /// Unset ⇒ auto-sized to `ceil(1.2 × --max-findings-per-batch)`
    /// (20% headroom over one emit per finding), so it tracks the batch
    /// size automatically instead of needing a manual bump. Set an
    /// explicit value to override. The runner logs a warning at batch
    /// start when this looks too tight.
    #[arg(long)]
    pub link_max_agent_steps: Option<usize>,

    /// Fraction (0,1] of the model's context window a single
    /// finding-linking prompt may fill — governs how many findings +
    /// semantic candidates are packed per prompt. Lower = more, smaller
    /// prompts with sharper attention: blind evals consistently scored
    /// ~200K-token prompts ABOVE 375K+ fills of the same corpus, so the
    /// default stays low (0.2 ≈ 200K on a ~1M-window model) and also
    /// leaves multi-step growth headroom for 256K-window models. Set
    /// `--input-token-budget` instead when you need an exact prompt size.
    /// Carries the `--link-` prefix so it can be flattened next to the
    /// merge / extract `--context-window-utilization` without colliding.
    #[arg(long, default_value_t = 0.2)]
    pub link_context_window_utilization: f64,

    /// Turn OFF full raw-children rendering and fall back to the compact
    /// `appended_*` delta notes under each candidate/finding. Raw-children
    /// rendering — each folded child's FULL raw text, the richer link context
    /// approaching the pre-Option-A inline density — is **on by default**
    /// (applies to both the semantic candidate and the finding); this flag
    /// disables it for smaller prompts with less context.
    #[arg(long)]
    pub link_no_render_raw_children: bool,

    /// Minimum byte length of a High/Medium entry's `why_finding_can_fire` —
    /// enforced at the emit tool boundary so thin justifications bounce back
    /// to the agent instead of landing in the KG.
    #[arg(long, default_value_t = 40)]
    pub link_evidence_min_high_medium: usize,

    /// Minimum byte length of a Low entry's `why_finding_can_fire`. Low
    /// rationales are short by design (audit trail, not downstream
    /// consumption).
    #[arg(long, default_value_t = 15)]
    pub link_evidence_min_low: usize,

    /// Minimum normalized length (chars, ~6 words at the default) of the
    /// verbatim quote a High entry must copy from ITS OWN finding's text.
    /// The emit tool verifies the quote is a substring of the attached
    /// finding's rendered body and rejects mismatches — this catches
    /// cross-finding evidence mis-attribution in large batches (evidence
    /// written for finding A emitted under finding B's id).
    #[arg(long, default_value_t = 25)]
    pub link_high_quote_min_chars: usize,

    #[command(flatten)]
    pub render: VariantRenderArgs,
}

/// The merged-variant render caps, shared by `link` (bounds the link prompt)
/// and `validate-db` (measures the DB's rendered field lengths) so both speak
/// the same caliber: pass the same values to see exactly the per-candidate /
/// per-finding mass a link run would put in its prompts.
#[derive(Args, Debug, Clone, Copy, serde::Serialize, serde::Deserialize)]
pub struct VariantRenderArgs {
    /// Max merged variants (count) rendered under each candidate AND each
    /// finding. Kept SMALL for linking: many rendered variants bloat each
    /// candidate (more match surface → more spurious High) and grow the
    /// candidate block into extra chunks.
    #[arg(long, default_value_t = 8)]
    pub link_variant_render_cap: usize,

    /// Per-variant char cap for raw-children rendering (0 = unbounded), so one
    /// bloated raw child cannot dominate the prompt. Kept SHORT — exp-era
    /// rendered folded raws as brief subordinate context; long variant dumps
    /// broaden each candidate and drive spurious High. Ignored under
    /// `--link-no-render-raw-children`.
    #[arg(long, default_value_t = 400)]
    pub link_raw_child_char_cap: usize,
}

impl FindingLinkCliArgs {
    pub fn validate(&self) -> Result<()> {
        if let Some(budget) = self.input_token_budget {
            ensure!(budget > 0, "Input token budget must be greater than zero");
        }

        ensure!(
            self.finding_token_ratio > 0.0 && self.finding_token_ratio < 1.0,
            "finding_token_ratio must be in (0, 1) — the semantic block takes the remainder"
        );

        ensure!(
            self.max_findings_per_batch > 0,
            "Max findings per batch must be greater than zero"
        );
        ensure!(
            self.max_semantics_per_batch > 0,
            "Max semantics per batch must be greater than zero"
        );

        ensure!(
            self.max_response_attempts > 0,
            "Max response attempts must be greater than zero"
        );
        if let Some(steps) = self.link_max_agent_steps {
            ensure!(steps > 0, "link_max_agent_steps must be greater than zero");
        }
        ensure!(
            self.link_context_window_utilization > 0.0
                && self.link_context_window_utilization <= 1.0,
            "link_context_window_utilization must be in (0, 1]",
        );
        ensure!(
            self.link_evidence_min_low > 0 && self.link_evidence_min_high_medium > 0,
            "link evidence length floors must be greater than zero"
        );
        ensure!(
            self.link_high_quote_min_chars > 0,
            "link_high_quote_min_chars must be greater than zero"
        );

        Ok(())
    }

    pub fn to_options(&self, concurrency: usize) -> FindingLinkOptions {
        FindingLinkOptions {
            concurrency,
            input_token_budget: self.input_token_budget,
            finding_token_ratio: self.finding_token_ratio,
            max_semantics_per_batch: self.max_semantics_per_batch,
            max_findings_per_batch: self.max_findings_per_batch,
            max_response_attempts: self.max_response_attempts,
            max_agent_steps: self
                .link_max_agent_steps
                .unwrap_or_else(|| (self.max_findings_per_batch as f64 * 1.2).ceil() as usize),
            include_unlinked: false,
            candidate_max_semantic_id: None,
            context_window_utilization: self.link_context_window_utilization,
            variant_render_cap: self.render.link_variant_render_cap,
            render_raw_children: !self.link_no_render_raw_children,
            raw_child_char_cap: self.render.link_raw_child_char_cap,
            evidence_min_high_medium: self.link_evidence_min_high_medium,
            evidence_min_low: self.link_evidence_min_low,
            high_quote_min_chars: self.link_high_quote_min_chars,
        }
    }
}
