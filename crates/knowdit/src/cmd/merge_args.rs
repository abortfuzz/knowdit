use clap::Args;
use color_eyre::eyre::{Result, ensure};
use knowdit_kg::learn::MergeRetryOptions;

#[derive(Args, Debug, Clone, Copy)]
pub struct MergeCliArgs {
    /// Maximum retries when a semantic/finding merge response references a target ID not present in the merge prompt
    #[arg(long, default_value_t = 3)]
    max_merge_response_attempts: usize,
}

impl MergeCliArgs {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.max_merge_response_attempts > 0,
            "Max merge response attempts must be greater than zero"
        );

        Ok(())
    }

    pub fn to_options(&self) -> MergeRetryOptions {
        MergeRetryOptions {
            max_response_attempts: self.max_merge_response_attempts,
        }
    }
}
