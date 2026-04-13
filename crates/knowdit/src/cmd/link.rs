use crate::cmd::finding_link_args::FindingLinkCliArgs;
use clap::Args;
use color_eyre::eyre::Result;
use knowdit_kg::db::DatabaseGraph;
use llmy::clap::OpenAISetup;

#[derive(Args)]
pub struct LinkArgs {
    /// Number of findings to link concurrently
    #[arg(long, default_value_t = 1)]
    concurrency: usize,

    /// Also include already-processed findings whose canonical target still has no semantic links
    #[arg(long)]
    include_unlinked: bool,

    #[command(flatten)]
    finding_link: FindingLinkCliArgs,
}

pub async fn run(db: &DatabaseGraph, llm_setup: &OpenAISetup, args: LinkArgs) -> Result<()> {
    args.finding_link.validate()?;

    let llm = llm_setup.clone().to_llm();
    let mut options = args.finding_link.to_options(args.concurrency);
    options.include_unlinked = args.include_unlinked;
    knowdit_kg::learn::link_pending_findings(db, &llm, options).await?;
    Ok(())
}
