//! `knowdit workflow streamloop` — link-by-link orchestrator that runs
//! `gen-specs` in round-robin order across extracts and immediately drains
//! downstream phases (`fuzz` → `reflect` → `regen`) after each link.
//!
//! Compared to `workflow autoloop`, this keeps the pipeline moving for every
//! semantic instead of first expanding a giant global spec backlog. The
//! specification generator already interleaves links by `extract_id`; this
//! orchestrator preserves that order and, after each committed spec link,
//! runs the downstream phases until they reach a local fixed point before
//! advancing to the next link.

use std::path::{Path, PathBuf};

use clap::Args;
use color_eyre::eyre::{Result, WrapErr, eyre};
use knowdit_audit::harness::solidity::FuzzOutcome;
use knowdit_audit::mapper::MapperOutcome;
use knowdit_audit::spec::{LinkKey, LinkSpecStatus, SpecGenOptions, SpecificationGenerator};
use knowdit_repo_model::LoadedValidFinding;
use llmy::clap::OptOpenAISetup;
use llmy::client::client::LLM;
use serde::Serialize;

use crate::cmd::audit::extract_semantics::{ExtractSemanticsArgs, ExtractSemanticsSharedArgs};
use crate::cmd::audit::fuzz::{FuzzArgs, FuzzSharedArgs};
use crate::cmd::audit::fuzz_common::HarnessSharedArgs;
use crate::cmd::audit::gen_specs::GenSpecsSharedArgs;
use crate::cmd::audit::map_semantics::{MapSemanticsArgs, MapSemanticsSharedArgs};
use crate::cmd::audit::profile::{ProfileArgs, ProfileSharedArgs};
use crate::cmd::audit::reflect::{ReflectArgs, ReflectSharedArgs, ReflectStats};
use crate::cmd::audit::regen::{RegenArgs, RegenSharedArgs, RegenStats};
use crate::cmd::solidity::SolidityCallGraphStaticArgs;

#[derive(Args, Debug, Clone)]
pub struct StreamloopArgs {
    #[command(flatten)]
    pub project: crate::cli::ProjectArgs,

    #[command(flatten)]
    pub db: crate::cli::DatabaseArgs,

    #[command(flatten)]
    pub kg: crate::cli::HistoricalDatabaseArgs,

    #[command(flatten)]
    pub backend: crate::cli::ProjectBackendCliOptions,

    #[command(flatten)]
    pub reflect_llm: OptOpenAISetup,

    #[command(flatten)]
    pub extract: ExtractSemanticsSharedArgs,

    #[command(flatten)]
    pub profile: ProfileSharedArgs,

    #[command(flatten)]
    pub map: MapSemanticsSharedArgs,

    #[command(flatten)]
    pub gen_specs: GenSpecsSharedArgs,

    #[command(flatten)]
    pub harness: HarnessSharedArgs,

    #[command(flatten)]
    pub fuzz: FuzzSharedArgs,

    #[command(flatten)]
    pub reflect: ReflectSharedArgs,

    #[command(flatten)]
    pub regen: RegenSharedArgs,

    /// Safety cap on how many fuzz→reflect→regen drain passes may happen
    /// after one batch of committed links before we advance to the next
    /// gen-specs batch. Prevents a single noisy batch from monopolizing
    /// the run forever.
    #[arg(long, default_value_t = 8)]
    pub max_inner_cycles_per_batch: usize,

    /// Number of links processed in parallel during the `gen-specs` phase
    /// of the stream. `1` keeps strict round-robin order; higher values
    /// dispatch a batch of links to a worker pool, commit each outcome as
    /// it finishes, then drain the downstream phases per link in
    /// completion order. The shared billing cap, prompt cache, and DB
    /// writes are already concurrency-safe.
    #[arg(long, default_value_t = 1)]
    pub stream_link_concurrency: usize,

    #[arg(short, long)]
    pub output_folder: PathBuf,

    #[arg(short, long)]
    pub force_clean_output: bool,
}

impl StreamloopArgs {
    pub async fn run(mut self, primary_llm: &LLM) -> Result<()> {
        tracing::info!("[streamloop stage 1/10] preparing output folder");
        self.prepare_output_folder()?;
        self.harness.harness_via_ir = self.backend.foundry.via_ir;
        let forge_backend = self.harness.to_forge_backend()?;

        tracing::info!("[streamloop stage 2/10] loading project DB and connecting to KG");
        let loaded = self
            .project
            .to_repo_database(self.db.database_path.clone())
            .await?;
        let kg = self.kg.connect().await?;
        let spec_name = loaded.spec.name.clone();
        let repo_root = loaded.spec.root.clone();
        let repo = loaded.repo;
        tracing::info!(
            "[streamloop stage 2/10] DB ready (project={}, repo_root={})",
            spec_name,
            repo_root.display(),
        );

        // Preflight the forge environment NOW, before any LLM stage
        // touches the project. A misconfigured Hardhat-only project
        // (no foundry.toml, no forge-std, etc.) fails in seconds
        // here instead of after 4 hours of extract/map/spec-gen.
        tracing::info!("[streamloop preflight] verifying forge environment");
        self.harness
            .preflight(&forge_backend, &repo_root)
            .await
            .wrap_err("forge environment preflight failed — fix the project's foundry config / forge-std install and re-run")?;
        tracing::info!("[streamloop preflight] forge environment OK");

        tracing::info!("[streamloop stage 3/10] loading call graph");
        let cg = repo.load_call_graph().await?;
        if cg.contracts.is_empty() {
            tracing::info!(
                "[streamloop stage 3/10] no contracts in call graph — running static call-graph phase"
            );
            SolidityCallGraphStaticArgs::update_call_graph(&repo, &repo_root, &self.backend)
                .await?;
        }
        let cg = repo.load_call_graph().await?;
        if cg.contracts.is_empty() {
            return Err(eyre!(
                "no available contracts found after call-graph rebuild"
            ));
        }
        tracing::info!(
            "[streamloop stage 3/10] call graph ready: {} contract(s)",
            cg.contracts.len()
        );

        let reflect_llm = self
            .reflect_llm
            .clone()
            .may_llm()
            .await
            .map_err(|err| eyre!("failed to build reflect LLM: {err}"))?
            .unwrap_or_else(|| primary_llm.clone());

        tracing::info!("[streamloop stage 4/10] extracting project semantics");
        let project_data = self.project.to_project_data().await?;
        let semantics = ExtractSemanticsArgs::extract_semantics(
            &repo,
            primary_llm,
            &project_data,
            &self.extract,
        )
        .await?;
        tracing::info!(
            "[streamloop stage 4/10] extracted {} project semantic(s)",
            semantics.len()
        );

        // Profile phase: runs once between extract and map-semantics.
        // Resume-safe via `get_project_profile()` inside the generator
        // — if a profile is already cached this is a cheap DB read.
        tracing::info!("[streamloop stage 5/10] building project profile");
        let profile =
            ProfileArgs::profile(&repo, primary_llm, &spec_name, &repo_root, &self.profile).await?;
        tracing::info!(
            "[streamloop stage 5/10] profile ready: {} subsystem(s), {} core component(s)",
            profile.subsystems.len(),
            profile.core_components.len(),
        );

        tracing::info!("[streamloop stage 6/10] mapping extract↔historical semantics");
        let match_set = repo.load_semantic_match_results().await?;
        if match_set.matches.is_empty() {
            tracing::info!(
                "[streamloop stage 6/10] no mapped semantics yet — running map-semantics phase"
            );
            let outcome: MapperOutcome =
                MapSemanticsArgs::map_semantics(&repo, &kg, primary_llm, &spec_name, &self.map)
                    .await?;
            tracing::info!(
                "[streamloop stage 6/10] mapper finished: {} matched pair(s) (High={}/Medium={}/Low={}), {} unmatched extract(s)",
                outcome.matched_pair_count,
                outcome.strength_counts.high,
                outcome.strength_counts.medium,
                outcome.strength_counts.low,
                outcome.unmatched_extract_count,
            );
        } else {
            tracing::info!(
                "[streamloop stage 6/10] mapper output already present: {} matched pair(s) — skipping",
                match_set.matches.len(),
            );
        }

        tracing::info!("[streamloop stage 7/10] preparing spec-gen stream");
        let gen_options = build_spec_options(&spec_name, &self.gen_specs);
        let mut stream = match SpecificationGenerator::new()
            .prepare_stream(&repo, &gen_options)
            .await?
        {
            Some(stream) => stream,
            None => {
                tracing::warn!(
                    "[streamloop stage 7/10] no pending links after planner/resume filters — nothing to do"
                );
                return Ok(());
            }
        };
        let link_concurrency = self.stream_link_concurrency.max(1);
        tracing::info!(
            "[streamloop stage 7/10] starting main loop: {} link(s) across {} extract(s) and {} historical finding(s), gen-specs concurrency={}",
            stream.total_links(),
            stream.matched_extract_count(),
            stream.historical_finding_total(),
            link_concurrency,
        );

        let mut completed_specs = 0usize;
        let mut abandoned_links = 0usize;
        let mut snapshots_written = 0usize;
        let mut batch_idx = 0usize;

        while !stream.is_empty() {
            batch_idx += 1;
            let total_links = stream.total_links();
            let processed_before = stream.processed_links();
            let queued = stream.remaining_links().min(link_concurrency);
            tracing::info!(
                "[streamloop stage 8/10 batch #{}] gen-specs: dispatching {} link(s) in parallel ({}/{} processed so far)",
                batch_idx,
                queued,
                processed_before,
                total_links,
            );
            let batch = stream
                .run_next_batch(&repo, primary_llm, link_concurrency)
                .await?;
            if batch.is_empty() {
                break;
            }
            tracing::info!(
                "[streamloop stage 8/10 batch #{}] gen-specs: batch complete: {} outcome(s) returned ({}/{} processed)",
                batch_idx,
                batch.len(),
                stream.processed_links(),
                total_links,
            );

            let mut any_committed = false;
            for outcome in &batch {
                match outcome.status {
                    LinkSpecStatus::Built => completed_specs += outcome.specifications.len(),
                    LinkSpecStatus::Abandoned => abandoned_links += 1,
                }
                if !outcome.specifications.is_empty() {
                    any_committed = true;
                }
            }

            // Drain fuzz → reflect → regen for the whole batch in one go.
            // Each of these phases is already incremental over pending DB
            // rows, so calling the unfiltered entry points picks up exactly
            // the specs this batch just committed (plus any stragglers from
            // earlier batches) — no per-link pair filter needed.
            let mut drained = LinkDrainCounts::default();
            if any_committed {
                for inner_cycle in 1..=self.max_inner_cycles_per_batch {
                    tracing::info!(
                        "[streamloop stage 9/10 batch #{}] drain cycle {}/{}: fuzz",
                        batch_idx,
                        inner_cycle,
                        self.max_inner_cycles_per_batch,
                    );
                    let fuzz_outcome: FuzzOutcome = FuzzArgs::fuzz(
                        &repo,
                        primary_llm,
                        &spec_name,
                        &repo_root,
                        &self.harness,
                        &self.fuzz,
                        &forge_backend,
                    )
                    .await?;
                    tracing::info!(
                        "[streamloop stage 9/10 batch #{}] drain cycle {}/{}: reflect (fuzz: {} completed / {} violated)",
                        batch_idx,
                        inner_cycle,
                        self.max_inner_cycles_per_batch,
                        fuzz_outcome.completed_count,
                        fuzz_outcome.violated_count,
                    );
                    let reflect_stats: ReflectStats =
                        ReflectArgs::reflect(&repo, &reflect_llm, &spec_name, &self.reflect)
                            .await?;
                    tracing::info!(
                        "[streamloop stage 9/10 batch #{}] drain cycle {}/{}: regen (reflect: {} graded)",
                        batch_idx,
                        inner_cycle,
                        self.max_inner_cycles_per_batch,
                        reflect_stats.graded,
                    );
                    let regen_stats: RegenStats = RegenArgs::regen(
                        &repo,
                        primary_llm,
                        &spec_name,
                        &repo_root,
                        &self.harness,
                        &self.regen,
                        &forge_backend,
                    )
                    .await?;

                    drained.fuzz_completed += fuzz_outcome.completed_count;
                    drained.fuzz_violated += fuzz_outcome.violated_count;
                    drained.reflect_graded += reflect_stats.graded;
                    drained.regen_codegen += regen_stats.codegen_regen;
                    drained.regen_spec += regen_stats.spec_regen;

                    let progressed = fuzz_outcome.completed_count > 0
                        || reflect_stats.graded > 0
                        || regen_stats.codegen_regen + regen_stats.spec_regen > 0;
                    if !progressed {
                        tracing::info!(
                            "[streamloop stage 9/10 batch #{}] drain: fixed point reached after {} cycle(s)",
                            batch_idx,
                            inner_cycle,
                        );
                        break;
                    }
                    if inner_cycle == self.max_inner_cycles_per_batch {
                        tracing::info!(
                            "[streamloop stage 9/10 batch #{}] drain: hit max_inner_cycles_per_batch={} — moving on",
                            batch_idx,
                            self.max_inner_cycles_per_batch,
                        );
                    }
                }
            } else {
                tracing::info!(
                    "[streamloop stage 9/10 batch #{}] drain: batch produced no new specs — skipping",
                    batch_idx,
                );
            }

            let valid_findings = repo.load_valid_findings().await?;
            for outcome in batch {
                let link_key = LinkKey {
                    extract_id: outcome.extract_id,
                    historical_id: outcome.historical_id,
                    finding_id: outcome.finding_id,
                };
                let link_label = format!(
                    "extract={} historical={} finding={}",
                    link_key.extract_id, link_key.historical_id, link_key.finding_id,
                );
                if outcome.specifications.is_empty() {
                    tracing::info!(
                        "[streamloop stage 10/10 batch #{}] snapshot: skipping {} — no committed specs (status={:?}{})",
                        batch_idx,
                        link_label,
                        outcome.status,
                        outcome
                            .abort_reason
                            .as_deref()
                            .map(|r| format!(", reason={r}"))
                            .unwrap_or_default(),
                    );
                    continue;
                }
                snapshots_written += 1;
                tracing::info!(
                    "[streamloop stage 10/10 batch #{}] snapshot: writing link_{:04} for {} ({}/{} links done overall)",
                    batch_idx,
                    snapshots_written,
                    link_label,
                    stream.processed_links(),
                    total_links,
                );
                write_link_snapshot(
                    &self.output_folder,
                    snapshots_written,
                    &link_key,
                    stream.processed_links(),
                    total_links,
                    &outcome,
                    &drained,
                    &valid_findings,
                )?;
            }
        }

        tracing::info!(
            "Streamloop finished: processed_links={} built_specs={} abandoned_links={} remaining_links={}",
            stream.processed_links(),
            completed_specs,
            abandoned_links,
            stream.remaining_links(),
        );
        Ok(())
    }

    fn prepare_output_folder(&self) -> Result<()> {
        let out = &self.output_folder;
        if out.exists() {
            if self.force_clean_output {
                std::fs::remove_dir_all(out)
                    .wrap_err_with(|| format!("failed to clean output folder {}", out.display()))?;
            } else {
                tracing::info!(
                    "Reusing existing output folder {} (pass --force-clean-output to wipe)",
                    out.display()
                );
            }
        }
        std::fs::create_dir_all(out)
            .wrap_err_with(|| format!("failed to create output folder {}", out.display()))?;
        Ok(())
    }
}

fn build_spec_options(project_name: &str, shared: &GenSpecsSharedArgs) -> SpecGenOptions {
    SpecGenOptions {
        max_agent_steps: shared.gen_specs_max_agent_steps,
        max_specs_per_link: shared.gen_specs_max_specs_per_link,
        compact_context_threshold_tokens: shared.gen_specs_compact_context_threshold_tokens,
        cache_key: shared
            .gen_specs_cache_key
            .clone()
            .unwrap_or_else(|| format!("{}-knowdit-spec", project_name)),
        debug_prefix: shared.gen_specs_debug_prefix.clone(),
        llm_settings: None,
        max_links: (shared.gen_specs_max_links > 0).then_some(shared.gen_specs_max_links),
        max_findings_per_historical: (shared.gen_specs_max_findings_per_historical > 0)
            .then_some(shared.gen_specs_max_findings_per_historical),
        max_links_per_extract: (shared.gen_specs_max_links_per_extract > 0)
            .then_some(shared.gen_specs_max_links_per_extract),
        concurrency: 1,
        regenerate: shared.gen_specs_regenerate,
        min_strength: shared.gen_specs_min_strength.into(),
        min_link_strength: shared.gen_specs_min_link_strength.into(),
    }
}

#[derive(Debug, Default, Serialize)]
struct LinkDrainCounts {
    fuzz_completed: usize,
    fuzz_violated: usize,
    reflect_graded: usize,
    regen_codegen: usize,
    regen_spec: usize,
}

#[derive(Debug, Serialize)]
struct LinkSnapshot {
    ordinal: usize,
    total_links: usize,
    link: LinkSnapshotKey,
    status: String,
    committed_spec_count: usize,
    abort_reason: Option<String>,
    steps: usize,
    compact_count: usize,
    drain: LinkDrainCounts,
    valid_finding_total: usize,
}

#[derive(Debug, Serialize)]
struct LinkSnapshotKey {
    extract_id: i32,
    historical_id: i32,
    finding_id: i32,
}

fn write_link_snapshot(
    output_folder: &Path,
    sequence: usize,
    link_key: &LinkKey,
    ordinal: usize,
    total_links: usize,
    outcome: &knowdit_audit::spec::LinkSpecOutcome,
    drain: &LinkDrainCounts,
    valid_findings: &[LoadedValidFinding],
) -> Result<()> {
    let dir = output_folder.join(format!("link_{sequence:04}"));
    std::fs::create_dir_all(&dir)
        .wrap_err_with(|| format!("failed to create {}", dir.display()))?;
    let snapshot = LinkSnapshot {
        ordinal,
        total_links,
        link: LinkSnapshotKey {
            extract_id: link_key.extract_id,
            historical_id: link_key.historical_id,
            finding_id: link_key.finding_id,
        },
        status: match outcome.status {
            LinkSpecStatus::Built => "built".to_string(),
            LinkSpecStatus::Abandoned => "abandoned".to_string(),
        },
        committed_spec_count: outcome.specifications.len(),
        abort_reason: outcome.abort_reason.clone(),
        steps: outcome.steps,
        compact_count: outcome.compact_count,
        drain: LinkDrainCounts {
            fuzz_completed: drain.fuzz_completed,
            fuzz_violated: drain.fuzz_violated,
            reflect_graded: drain.reflect_graded,
            regen_codegen: drain.regen_codegen,
            regen_spec: drain.regen_spec,
        },
        valid_finding_total: valid_findings.len(),
    };
    std::fs::write(
        dir.join("summary.json"),
        serde_json::to_string_pretty(&snapshot)?,
    )?;
    if !valid_findings.is_empty() {
        let findings_dir = dir.join("valid_findings");
        std::fs::create_dir_all(&findings_dir)?;
        for vf in valid_findings {
            std::fs::write(
                findings_dir.join(format!("finding_{}.json", vf.reflection_id)),
                serde_json::to_string_pretty(vf)?,
            )?;
        }
    }
    Ok(())
}
