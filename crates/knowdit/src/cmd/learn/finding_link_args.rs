use clap::Args;
use color_eyre::eyre::{Result, ensure};
use knowdit_kg::learn::FindingLinkOptions;

#[derive(Args, Debug, Clone, Copy)]
pub struct FindingLinkCliArgs {
    /// Expected maximum total input tokens per linking prompt.
    #[arg(long)]
    pub input_token_budget: Option<usize>,

    /// Maximum tokens that finding payloads may occupy in each linking prompt.
    #[arg(long)]
    pub finding_token_budget: Option<usize>,

    /// Hard ceiling on findings per batch — independent of token
    /// budget. Token-based partitioning alone packs too many findings
    /// when each finding's text is short (e.g. ~150 tok/finding on
    /// the Move KG fits ~480 findings in a 72K budget); agents in
    /// practice can only stably emit decisions for a few dozen
    /// findings per attempt before finalizing prematurely. Leave
    /// unset to use the built-in default.
    #[arg(long)]
    pub max_findings_per_batch: Option<usize>,

    /// Maximum attempts per (finding-batch × semantic-chunk): if the agent
    /// finalizes without covering every finding in the batch, the runner
    /// re-runs a fresh agent restricted to the still-missing findings,
    /// up to this many times. Findings still missing after the cap are
    /// logged as a warning and treated as no-link.
    #[arg(long, default_value_t = 3)]
    pub max_response_attempts: usize,

    /// Per-attempt cap on agent steps (one tool call = one step).
    /// Rule of thumb: needs to be at least `max_findings_per_batch +
    /// 4` (one emit per finding, one finalize, plus a few reasoning
    /// steps). The runner logs a warning at batch start when this
    /// looks too tight. Default 200 sized for the new ~50-finding
    /// batches; raise alongside `--max-findings-per-batch` if you
    /// crank it up.
    #[arg(long, default_value_t = 200)]
    pub link_max_agent_steps: usize,
}

impl FindingLinkCliArgs {
    pub fn validate(&self) -> Result<()> {
        if let Some(budget) = self.input_token_budget {
            ensure!(budget > 0, "Input token budget must be greater than zero");
        }

        if let Some(budget) = self.finding_token_budget {
            ensure!(budget > 0, "Finding token budget must be greater than zero");
        }

        ensure!(
            self.max_response_attempts > 0,
            "Max response attempts must be greater than zero"
        );
        ensure!(
            self.link_max_agent_steps > 0,
            "link_max_agent_steps must be greater than zero",
        );

        Ok(())
    }

    pub fn to_options(&self, concurrency: usize) -> FindingLinkOptions {
        FindingLinkOptions {
            concurrency,
            input_token_budget: self.input_token_budget,
            finding_token_budget: self.finding_token_budget,
            max_findings_per_batch: self.max_findings_per_batch,
            max_response_attempts: self.max_response_attempts,
            max_agent_steps: self.link_max_agent_steps,
            include_unlinked: false,
        }
    }
}
