//! `agentic map-semantics` subcommand: run the Knowledge Mapper agent.
//!
//! Loads the project's extracted semantics + cached [`ProjectProfile`]
//! from the repo database, fuzzy-matches the extracts against the
//! historical knowledge graph with per-pair strength labels, and
//! persists the matched historical semantics + findings + match edges
//! back into the project database for downstream consumers.
//!
//! Profile is REQUIRED — if the project DB has no `project_metadata`
//! `profile` row, this entry returns an error directing the caller to
//! run `agentic profile` first. The autoloop orchestrator inserts a
//! profile phase before map-semantics so the requirement is satisfied
//! automatically there.
use clap::Args;
use color_eyre::eyre::{Result, eyre};
use itertools::Itertools;
use knowdit_audit::harness::solidity::SolidityHarness;
use knowdit_audit::mapper::{KnowledgeMapper, MapperOptions, MapperOutcome};
use knowdit_kg::db::HistoricalDatabase;
use knowdit_kg_model::category::DeFiCategory;
use knowdit_repo_model::RepoDatabase;
use llmy::client::client::LLM;

use crate::cli::{DatabaseArgs, HistoricalDatabaseArgs, LoadedRepoDatabase, ProjectArgs};

/// Knobs for the map-semantics phase. Long-flag names carry a
/// `--map-*` prefix so flattening this alongside other phase
/// `SharedArgs` (gen-specs, reflect — all of which also have a
/// `--cache-key`) in the autoloop doesn't trip clap's duplicate-arg
/// check.
#[derive(Args, Clone, Debug)]
pub struct MapSemanticsSharedArgs {
    /// Number of historical semantics presented to the LLM in a
    /// single matching prompt.
    #[arg(long = "map-batch-size", default_value_t = 16)]
    pub map_batch_size: usize,

    /// `llmy` cache key prefix. Defaults to
    /// `{project_name}-knowdit-mapper` when omitted so different
    /// projects don't share a cache namespace.
    #[arg(long = "map-cache-key")]
    pub map_cache_key: Option<String>,

    /// Max historical batches the mapper matches concurrently (each
    /// batch is one LLM call). Defaults to 8 when unset. `workflow
    /// streamloop` fills this from `--default-concurrency` when you
    /// don't pass it explicitly. Typed `Option` so that fill-in can
    /// tell "unset" from an explicit value.
    #[arg(long = "map-concurrency")]
    pub map_concurrency: Option<usize>,

    /// Comma-separated extra historical categories to widen the mapper's
    /// candidate pool beyond the project's own auto-classified categories
    /// (which always include `Others`). Use this when a project
    /// auto-classifies too narrowly — e.g. a P2P-escrow project tagged only
    /// `Others` can pass `--mapper-extra-categories Services` to surface
    /// signature/authorization historical knowledge. Names are case- and
    /// separator-insensitive (`Services`, `real world assets`, …); unknown
    /// names abort with the list of valid categories.
    #[arg(long = "mapper-extra-categories")]
    pub mapper_extra_categories: Option<String>,
}

impl MapSemanticsSharedArgs {
    /// Resolve `--mapper-extra-categories` (a comma-separated string) into
    /// typed categories, erroring on any unknown name (with the valid list) so
    /// a typo fails fast rather than silently widening nothing. Empty / unset
    /// yields no extra categories.
    pub fn extra_categories(&self) -> Result<Vec<DeFiCategory>> {
        self.mapper_extra_categories
            .as_deref()
            .unwrap_or_default()
            .split(',')
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .map(|s| {
                DeFiCategory::parse(s).ok_or_else(|| {
                    eyre!(
                        "unknown --mapper-extra-categories value '{s}'; valid categories: {}",
                        DeFiCategory::ALL.iter().map(|c| c.as_str()).join(", "),
                    )
                })
            })
            .collect()
    }
}

#[derive(Args)]
pub struct MapSemanticsArgs {
    #[command(flatten)]
    pub project: ProjectArgs,

    #[command(flatten)]
    pub db: DatabaseArgs,

    /// Historical knowledge-graph database to match the project's
    /// extracted semantics against. The mapper is the only agentic
    /// subcommand that needs the KG, so this flag is local to it.
    #[command(flatten)]
    pub kg: HistoricalDatabaseArgs,

    #[command(flatten)]
    pub shared: MapSemanticsSharedArgs,
}

impl MapSemanticsArgs {
    /// CLI entry: open the historical KG + project DB, delegate to
    /// [`Self::map_semantics`], print a one-line summary.
    ///
    /// Standalone CLI is Solidity-only: it doesn't construct a
    /// harness backend, so the language prefix is hardcoded to
    /// [`SolidityHarness::PROMPT_PREFIX`]. Move projects must go
    /// through `workflow streamloop`, which has a backend in hand
    /// and passes its `prompt_prefix()`.
    pub async fn run(self, llm: &LLM) -> Result<()> {
        let kg = self.kg.connect_init_for_consumer().await?;
        let LoadedRepoDatabase { spec, repo, .. } = self
            .project
            .to_repo_database(self.db.database_path.clone())
            .await?;
        let outcome = Self::map_semantics(
            &repo,
            &kg,
            llm,
            &spec.name,
            SolidityHarness::PROMPT_PREFIX.to_string(),
            &self.shared,
        )
        .await?;
        println!(
            "Knowledge Mapper finished: {} extract semantic(s), {} historical considered, {} matched pair(s), {} unmatched extract(s), {} historical finding(s) ingested",
            outcome.extracted_count,
            outcome.historical_considered,
            outcome.matched_pair_count,
            outcome.unmatched_extract_count,
            outcome.historical_finding_count,
        );
        Ok(())
    }

    /// In-process entry: run the Knowledge Mapper against
    /// already-opened repo + KG connections. No `&self`.
    ///
    /// Requires `project_metadata.profile` to be populated already —
    /// returns an error otherwise. The autoloop runs the profile
    /// phase ahead of map-semantics to satisfy this; standalone CLI
    /// users must run `agentic profile` first.
    ///
    /// `language_prompt_prefix` is the language-context block to
    /// prepend to the mapper agent's system prompt. Callers source
    /// it from `harness_backend.prompt_prefix()` when they have one
    /// (streamloop) or hardcode `SolidityHarness::PROMPT_PREFIX` for
    /// the standalone Solidity-only CLI path.
    pub async fn map_semantics(
        repo: &RepoDatabase,
        kg: &HistoricalDatabase,
        llm: &LLM,
        project_name: &str,
        language_prompt_prefix: String,
        shared: &MapSemanticsSharedArgs,
    ) -> Result<MapperOutcome> {
        let profile = repo.get_project_profile().await?.ok_or_else(|| {
            eyre!(
                "Knowledge Mapper requires a ProjectProfile; run `knowdit agentic profile` for \
                 project '{project_name}' first (or let `workflow autoloop` run the profile phase)"
            )
        })?;
        let cache_key = shared
            .map_cache_key
            .clone()
            .unwrap_or_else(|| format!("{}-knowdit-mapper", project_name));
        let options = MapperOptions {
            batch_size: shared.map_batch_size.max(1),
            concurrency: shared.map_concurrency.unwrap_or(8).max(1),
            cache_key: Some(cache_key),
            language_prompt_prefix: language_prompt_prefix.clone(),
            extra_categories: shared.extra_categories()?,
        };
        KnowledgeMapper::new(profile, language_prompt_prefix)
            .run(repo, kg, llm, &options)
            .await
    }
}
