use clap::Args;
use color_eyre::eyre::{Result, ensure};
use knowdit_kg::learn::FindingLinkOptions;

#[derive(Args, Debug, Clone, Copy)]
pub struct FindingLinkCliArgs {
    /// Expected maximum total input tokens per linking prompt
    #[arg(long)]
    input_token_budget: Option<usize>,

    /// Maximum tokens that finding payloads may occupy in each linking prompt
    #[arg(long)]
    finding_token_budget: Option<usize>,

    /// Maximum number of retries when a linking response contains unknown semantic candidate ids
    #[arg(long, default_value_t = 3)]
    max_response_attempts: usize,
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

        Ok(())
    }

    pub fn to_options(&self, concurrency: usize) -> FindingLinkOptions {
        FindingLinkOptions {
            concurrency,
            input_token_budget: self.input_token_budget,
            finding_token_budget: self.finding_token_budget,
            max_response_attempts: self.max_response_attempts,
            include_unlinked: false,
        }
    }
}
