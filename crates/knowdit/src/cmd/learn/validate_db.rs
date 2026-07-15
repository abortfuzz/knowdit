use clap::Args;
use color_eyre::eyre::{Result, eyre};
use knowdit_kg::db::HistoricalDatabase;

use super::finding_link_args::VariantRenderArgs;

#[derive(Args, Debug)]
pub struct ValidateDbArgs {
    /// Delete dangling relation rows that reference missing parent rows
    #[arg(long)]
    pub repair: bool,

    #[command(flatten)]
    pub render: VariantRenderArgs,
}

impl ValidateDbArgs {
    pub async fn run(self, db: &HistoricalDatabase) -> Result<()> {
        let report = db.validate_db(self.repair).await?;

        // DB stats first — the shared measurement caliber for debugging
        // (counts, link density, field/render lengths); printed regardless of
        // whether validation passes so a broken DB can still be sized up.
        print!(
            "{}",
            db.kg_stats(
                self.render.link_variant_render_cap,
                self.render.link_raw_child_char_cap,
            )
            .await?
        );

        if self.repair {
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
}
