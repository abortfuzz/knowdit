//! `agentic gen-specs` subcommand: run the Specification Generator agent.
//!
//! Reads the Knowledge Mapper output (extract↔historical↔finding links) from
//! the project's per-project SQLite database, runs a memory-equipped agent
//! per link to derive zero or more `AuditSpecification`s, and persists the
//! results back to the `specification` table. Optionally dumps a JSON
//! summary for offline review against the project's ground-truth report.
use std::path::PathBuf;

use clap::{Args, ValueEnum};
use color_eyre::eyre::Result;
use knowdit_audit::harness::solidity::SolidityHarness;
use knowdit_audit::spec::{
    LinkSpecSummary, SpecGenOptions, SpecGenOutcome, SpecificationGenerator,
};
use knowdit_kg_model::link_strength::LinkStrength;
use knowdit_repo_model::{MatchStrength, RepoDatabase};
use llmy::client::client::LLM;
use serde::Serialize;

use crate::cli::{DatabaseArgs, LoadedRepoDatabase, ProjectArgs};

/// CLI-layer mirror of the 3-tier strength tiers used by both
/// [`MatchStrength`] (mapper) and [`LinkStrength`] (global linker).
/// Those enums live in DB-facing crates that don't (and shouldn't)
/// depend on clap, so this thin wrapper carries the `ValueEnum`
/// derive while converting cleanly to either real enum at the
/// boundary.
#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum MinStrengthArg {
    High,
    Medium,
    Low,
}

impl From<MinStrengthArg> for MatchStrength {
    fn from(v: MinStrengthArg) -> Self {
        match v {
            MinStrengthArg::High => MatchStrength::High,
            MinStrengthArg::Medium => MatchStrength::Medium,
            MinStrengthArg::Low => MatchStrength::Low,
        }
    }
}

impl From<MinStrengthArg> for LinkStrength {
    fn from(v: MinStrengthArg) -> Self {
        match v {
            MinStrengthArg::High => LinkStrength::High,
            MinStrengthArg::Medium => LinkStrength::Medium,
            MinStrengthArg::Low => LinkStrength::Low,
        }
    }
}

/// Knobs for the gen-specs phase. Long-flag names carry a
/// `--gen-specs-*` prefix to disambiguate from other phases'
/// equivalents (`cache_key`, `concurrency`, `regenerate`,
/// `max_agent_steps`, `compact_context_threshold_tokens`,
/// `debug_prefix`).
#[derive(Args, Clone, Debug)]
pub struct GenSpecsSharedArgs {
    /// `llmy` cache key prefix. Defaults to
    /// `{project_name}-knowdit-spec` so different projects don't
    /// share a cache namespace.
    #[arg(long = "gen-specs-cache-key")]
    pub gen_specs_cache_key: Option<String>,

    /// Maximum agent steps per link before forced abandonment.
    #[arg(long = "gen-specs-max-agent-steps", default_value_t = 60)]
    pub gen_specs_max_agent_steps: usize,

    /// Maximum specifications a single link may commit before finalize.
    #[arg(long = "gen-specs-max-specs-per-link", default_value_t = 4)]
    pub gen_specs_max_specs_per_link: usize,

    /// Cap on number of links processed in this run. `0` means no cap.
    #[arg(long = "gen-specs-max-links", default_value_t = 0)]
    pub gen_specs_max_links: usize,

    /// Cap on findings per *(extract, historical)* pair. `0` means
    /// no cap. When multiple extracts match the same historical,
    /// each pair gets its own quota.
    #[arg(long = "gen-specs-max-findings-per-historical", default_value_t = 0)]
    pub gen_specs_max_findings_per_historical: usize,

    /// Cap on the total number of links processed *per extract*.
    /// `0` means no cap.
    #[arg(long = "gen-specs-max-links-per-extract", default_value_t = 0)]
    pub gen_specs_max_links_per_extract: usize,

    /// Compaction threshold in approximate tokens. Default ~80% of
    /// model max.
    #[arg(long = "gen-specs-compact-context-threshold-tokens")]
    pub gen_specs_compact_context_threshold_tokens: Option<usize>,

    /// Number of links processed in parallel. Defaults to `1`
    /// (strict serial) when omitted. Typed `Option` so streamloop's
    /// `--default-concurrency` can tell "user passed it" from
    /// "default kicked in" — an explicit value wins over `-d`.
    #[arg(long = "gen-specs-concurrency")]
    pub gen_specs_concurrency: Option<usize>,

    /// Regenerate every spec from scratch. Default is to skip any
    /// `(semantic_id, finding_id)` pair that already has rows.
    #[arg(long = "gen-specs-regenerate", default_value_t = false)]
    pub gen_specs_regenerate: bool,

    /// Minimum mapper-emitted match strength to consider. Links with
    /// strength below this tier are dropped before any other capping
    /// is applied. Default `medium` skips `Low` matches (noise) but
    /// keeps `High` + `Medium`. Set to `low` to consider every link;
    /// `high` to be strict.
    #[arg(long = "gen-specs-min-strength", value_enum, default_value_t = MinStrengthArg::Medium)]
    pub gen_specs_min_strength: MinStrengthArg,

    /// Minimum global-linker-emitted link strength on the
    /// `(historical, finding)` edge. Independent axis from
    /// `--gen-specs-min-strength`: this rejects findings the linker
    /// considered only weakly tied to the historical semantic, even
    /// when the mapper found a strong extract↔historical match.
    /// Default `medium` skips `Low` link edges.
    #[arg(long = "gen-specs-min-link-strength", value_enum, default_value_t = MinStrengthArg::Medium)]
    pub gen_specs_min_link_strength: MinStrengthArg,

    /// Debug prefix passed to llmy.
    #[arg(long = "gen-specs-debug-prefix")]
    pub gen_specs_debug_prefix: Option<String>,
}

#[derive(Args)]
pub struct GenSpecsArgs {
    #[command(flatten)]
    pub project: ProjectArgs,

    #[command(flatten)]
    pub db: DatabaseArgs,

    #[command(flatten)]
    pub shared: GenSpecsSharedArgs,

    /// Optional JSON output path summarizing all link outcomes.
    /// CLI-only; the autoloop manages its own dumps.
    #[arg(long)]
    pub out: Option<PathBuf>,
}

#[derive(Debug, Serialize)]
struct RunSummary {
    project: String,
    link_count: usize,
    built_link_count: usize,
    abandoned_link_count: usize,
    total_specs: usize,
    by_link: Vec<LinkSpecSummary>,
}

impl GenSpecsArgs {
    /// CLI entry: open the project DB, delegate to
    /// [`Self::gen_specs`], pretty-print + optionally dump `--out`.
    ///
    /// Standalone CLI is Solidity-only — same rationale as
    /// `map-semantics`. Move projects go through `workflow
    /// streamloop`, which passes its harness backend's prefix.
    pub async fn run(self, llm: &LLM) -> Result<()> {
        let LoadedRepoDatabase { spec, repo, .. } = self
            .project
            .to_repo_database(self.db.database_path.clone())
            .await?;
        let outcome = Self::gen_specs(
            &repo,
            llm,
            &spec.name,
            SolidityHarness::PROMPT_PREFIX.to_string(),
            &self.shared,
        )
        .await?;
        println!(
            "Specification Generator finished: {} link(s), {} built, {} abandoned, {} spec(s) committed",
            outcome.link_count,
            outcome.built_link_count,
            outcome.abandoned_link_count,
            outcome.total_specs,
        );
        if let Some(out_path) = self.out.as_ref() {
            if let Some(parent) = out_path.parent().filter(|p| !p.as_os_str().is_empty()) {
                std::fs::create_dir_all(parent)?;
            }
            let summary = RunSummary {
                project: spec.name.clone(),
                link_count: outcome.link_count,
                built_link_count: outcome.built_link_count,
                abandoned_link_count: outcome.abandoned_link_count,
                total_specs: outcome.total_specs,
                by_link: outcome.by_link.iter().map(LinkSpecSummary::from).collect(),
            };
            std::fs::write(out_path, serde_json::to_string_pretty(&summary)?)?;
            tracing::info!("Specification summary written to {}", out_path.display());
        }
        Ok(())
    }

    /// In-process entry: run the Specification Generator against an
    /// already-opened repo DB + LLM. No `&self` — every knob comes
    /// from `shared`.
    ///
    /// `language_prompt_prefix` is the language-context block to
    /// prepend to the spec-gen agent's system prompt. Sourced from
    /// `harness_backend.prompt_prefix()` by streamloop, or
    /// hardcoded to `SolidityHarness::PROMPT_PREFIX` by the
    /// standalone Solidity-only CLI.
    pub async fn gen_specs(
        repo: &RepoDatabase,
        llm: &LLM,
        project_name: &str,
        language_prompt_prefix: String,
        shared: &GenSpecsSharedArgs,
    ) -> Result<SpecGenOutcome> {
        // Profile fetch verifies the upstream pipeline produced one.
        repo.get_project_profile().await?.ok_or_else(|| {
            color_eyre::eyre::eyre!(
                "Specification Generator requires a ProjectProfile; run `knowdit agentic \
                 profile` for project '{project_name}' first (or let `workflow streamloop` \
                 run the profile phase)."
            )
        })?;
        let cache_key = shared
            .gen_specs_cache_key
            .clone()
            .unwrap_or_else(|| format!("{}-knowdit-spec", project_name));
        let options = SpecGenOptions {
            max_agent_steps: shared.gen_specs_max_agent_steps,
            max_specs_per_link: shared.gen_specs_max_specs_per_link,
            compact_context_threshold_tokens: shared.gen_specs_compact_context_threshold_tokens,
            cache_key,
            debug_prefix: shared.gen_specs_debug_prefix.clone(),
            llm_settings: None,
            max_links: (shared.gen_specs_max_links > 0).then_some(shared.gen_specs_max_links),
            max_findings_per_historical: (shared.gen_specs_max_findings_per_historical > 0)
                .then_some(shared.gen_specs_max_findings_per_historical),
            max_links_per_extract: (shared.gen_specs_max_links_per_extract > 0)
                .then_some(shared.gen_specs_max_links_per_extract),
            concurrency: shared.gen_specs_concurrency.unwrap_or(1).max(1),
            regenerate: shared.gen_specs_regenerate,
            min_strength: shared.gen_specs_min_strength.into(),
            min_link_strength: shared.gen_specs_min_link_strength.into(),
            language_prompt_prefix,
        };
        SpecificationGenerator::new().run(repo, llm, &options).await
    }
}
