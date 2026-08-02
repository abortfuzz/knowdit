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
    LinkSource, LinkSpecSummary, SpecGenOptions, SpecGenOutcome, SpecificationGenerator,
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
/// equivalents (`concurrency`, `regenerate`, `max_agent_steps`,
/// `debug_prefix`).
#[derive(Args, Clone, Debug)]
pub struct GenSpecsSharedArgs {
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
    /// is applied. Set to `medium` to also take `Medium` matches, or
    /// `low` to consider every link.
    ///
    /// Defaults to `high` because it is the one knowledge-graph property
    /// measured to predict whether a link yields anything. Over 5,838 links
    /// with ground truth, `High` matches produced a canonical finding 17.2% of
    /// the time against 10.9% for `Medium`. The advantage survives controlling
    /// for queue position (High links are scheduled earlier, so the raw gap is
    /// partly ordering): within the same quartile of a run it is 1.20x / 1.67x
    /// / 1.99x over the first three quarters, reversing only in the last
    /// quarter once the `High` pool is exhausted.
    ///
    /// Supply is not the binding constraint: on tare the `High` tier held 3,617
    /// candidate links while a $400 run gets through ~550, so a budgeted run
    /// stays in the most productive part of the tier and never reaches the
    /// reversal. Raise the budget far enough to drain it and `medium` becomes
    /// the better setting again.
    ///
    /// The other graph-side properties were measured and do NOT predict yield —
    /// link strength above the `Medium` cutoff (0.99x / 1.15x), finding
    /// out-degree (0.90–1.10x), and historical severity, which is mildly
    /// inverted (`Low` 17.9% vs `High` 11.6%: the severest historical bugs are
    /// the most project-specific, hence the least reproducible elsewhere).
    #[arg(long = "gen-specs-min-strength", value_enum, default_value_t = MinStrengthArg::High)]
    pub gen_specs_min_strength: MinStrengthArg,

    /// Fraction of the model's input window that the whole in-scope project
    /// source may occupy when kept resident in the gen-spec system prompt.
    ///
    /// When the rendered source fits the budget, every contract and interface
    /// body is placed at the top of the system prompt and the
    /// `read_contract_source` / `read_function_source` tools and the
    /// signature-index memory are withheld — they could only return text the
    /// agent already holds. When it does not fit, the agent reads on demand
    /// exactly as before. The call-graph and cross-reference tools stay in both
    /// modes (they return derived relations, not source), as do the repository
    /// file tools (tests, docs and vendored trees are outside the block).
    ///
    /// This is an economic budget, not a fit check: the block is re-billed at
    /// the cached input rate on every call the stage makes, so a source tree
    /// big enough to outweigh the reads it replaces costs more than it saves
    /// even when it fits the window comfortably. `0` disables residency.
    #[arg(long = "gen-specs-resident-source-window-ratio", default_value_t = 0.0)]
    pub gen_specs_resident_source_window_ratio: f64,

    /// Minimum global-linker-emitted link strength on the
    /// `(historical, finding)` edge. Independent axis from
    /// `--gen-specs-min-strength`: this rejects findings the linker
    /// considered only weakly tied to the historical semantic, even
    /// when the mapper found a strong extract↔historical match.
    /// Default `medium` skips `Low` link edges.
    #[arg(long = "gen-specs-min-link-strength", value_enum, default_value_t = MinStrengthArg::Medium)]
    pub gen_specs_min_link_strength: MinStrengthArg,

    /// Debug prefix passed to llmy.
    #[arg(long = "gen-specs-debug-prefix", default_value = "spec")]
    pub gen_specs_debug_prefix: Option<String>,
}

impl GenSpecsSharedArgs {
    /// Build the [`SpecGenOptions`] for one Specification Generator pass from
    /// these CLI knobs. `link_source` frames the gen-spec agent (mapper
    /// topic-hint vs external reported finding).
    pub(crate) fn build_spec_options(
        &self,
        language_prompt_prefix: String,
        link_source: LinkSource,
        project_profile: Option<knowdit_repo_model::ProjectProfile>,
    ) -> SpecGenOptions {
        SpecGenOptions {
            max_agent_steps: self.gen_specs_max_agent_steps,
            max_specs_per_link: self.gen_specs_max_specs_per_link,
            debug_prefix: self.gen_specs_debug_prefix.clone(),
            llm_settings: None,
            max_links: (self.gen_specs_max_links > 0).then_some(self.gen_specs_max_links),
            max_findings_per_historical: (self.gen_specs_max_findings_per_historical > 0)
                .then_some(self.gen_specs_max_findings_per_historical),
            max_links_per_extract: (self.gen_specs_max_links_per_extract > 0)
                .then_some(self.gen_specs_max_links_per_extract),
            concurrency: 1,
            regenerate: self.gen_specs_regenerate,
            min_strength: self.gen_specs_min_strength.into(),
            min_link_strength: self.gen_specs_min_link_strength.into(),
            language_prompt_prefix,
            link_source,
            project_profile,
            resident_source_window_ratio: self.gen_specs_resident_source_window_ratio,
            source_access: std::sync::Arc::new(std::sync::OnceLock::new()),
        }
    }
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
            .to_repo_database(self.db.database_path.clone(), self.db.variant_render_cap)
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
        // The profile is both a precondition (the upstream pipeline must have
        // produced one) and an input: it goes into every link's system prompt.
        let profile = repo.get_project_profile().await?.ok_or_else(|| {
            color_eyre::eyre::eyre!(
                "Specification Generator requires a ProjectProfile; run `knowdit agentic \
                 profile` for project '{project_name}' first (or let `workflow streamloop` \
                 run the profile phase)."
            )
        })?;
        let mut options =
            shared.build_spec_options(language_prompt_prefix, LinkSource::Mapper, Some(profile));
        // The only knob this standalone path reads that the shared builder
        // does not: streamloop drives concurrency from its own scheduler.
        options.concurrency = shared.gen_specs_concurrency.unwrap_or(1).max(1);
        SpecificationGenerator::new().run(repo, llm, &options).await
    }
}
