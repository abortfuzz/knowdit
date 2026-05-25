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

    /// Maximum attempts per (finding-batch × semantic-chunk): if the agent
    /// finalizes without covering every finding in the batch, the runner
    /// re-runs a fresh agent restricted to the still-missing findings,
    /// up to this many times. Findings still missing after the cap are
    /// logged as a warning and treated as no-link.
    #[arg(long, default_value_t = 3)]
    pub max_response_attempts: usize,

    /// Per-attempt cap on agent steps (one tool call = one step). Bigger
    /// batches need more steps so the agent can emit one decision per
    /// finding plus a finalize call. Default 320 sized for the post-
    /// refactor "emit 1 finding per step" agent on the biggest batches
    /// we currently materialise (~250 findings) with headroom for a
    /// few extra reasoning steps.
    #[arg(long, default_value_t = 320)]
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
            max_response_attempts: self.max_response_attempts,
            max_agent_steps: self.link_max_agent_steps,
            include_unlinked: false,
        }
    }
}
