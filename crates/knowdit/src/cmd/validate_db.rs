use clap::Args;
use color_eyre::eyre::{Result, eyre};
use knowdit_kg::db::DatabaseGraph;

#[derive(Args, Debug, Default)]
pub struct ValidateDbArgs {
    /// Delete dangling relation rows that reference missing parent rows
    #[arg(long)]
    repair: bool,
}

pub async fn run(db: &DatabaseGraph, args: ValidateDbArgs) -> Result<()> {
    let report = db.validate_db(args.repair).await?;

    if args.repair {
        if report.detected_issues.is_empty() {
            tracing::info!("Database validation passed. No issues found.");
            return Ok(());
        }

        tracing::info!(
            "Database validation detected {} issue(s) and repaired {} row(s)",
            report.detected_issue_count(),
            report.repaired_rows
        );

        if report.is_clean() {
            tracing::info!("Database validation passed after repair.");
            return Ok(());
        }

        eprintln!(
            "Database validation still has {} issue(s) after repair:",
            report.remaining_issue_count()
        );
        for issue in &report.remaining_issues {
            eprintln!("- {}", issue);
        }

        return Err(eyre!(
            "Database validation repaired {} row(s) but {} issue(s) remain",
            report.repaired_rows,
            report.remaining_issue_count()
        ));
    }

    if report.is_clean() {
        tracing::info!("Database validation passed.");
        return Ok(());
    }

    eprintln!(
        "Database validation found {} issue(s):",
        report.remaining_issue_count()
    );
    for issue in &report.remaining_issues {
        eprintln!("- {}", issue);
    }

    Err(eyre!(
        "Database validation found {} issue(s)",
        report.remaining_issue_count()
    ))
}
