//! `agentic regen` subcommand: consume the pending-reflection queue,
//! regenerate code_gens (and, for `IncompleteSpecification`, specs too)
//! with the prior reflection feedback fed back into the agent.
//!
//! Per `plan_reflection.md` §3 / §5:
//!
//! * Pending = reflection rows whose `result ∈ {Suspect, IncompleteStep,
//!   IncompleteSpecification}` and which no `*_regen` row has consumed
//!   yet (NOT EXISTS check happens in
//!   [`RepoDatabase::pending_reflections`]).
//! * For each pending row:
//!   1. If `code_gen_chain_depth >= --max-chain-depth` → write a new
//!      reflection (`IncompleteSpecification`, "chain depth exceeded")
//!      and stop. The escalation enters next run's pending queue and
//!      will trigger a spec regen instead of yet another codegen retry.
//!   2. `Suspect` / `IncompleteStep` → re-run [`SolidityFuzzGenerator::regen_one_spec`]
//!      with the prior reason as system-prompt feedback. Write a
//!      `code_gen_regen` lineage row pointing to the parent.
//!   3. `IncompleteSpecification` → spec regen. Patch mode (default)
//!      shows the agent the prior spec + reflection reason; from-scratch
//!      mode kicks in once `spec_chain_depth > --spec-regen-patch-threshold`
//!      and tells the agent to discard history. Either path produces a
//!      new spec in memory; we then run codegen on it (also in memory)
//!      and persist the new spec, new code_gen, and both lineage rows
//!      in one [`RepoDatabase::write_full_spec_regen`] transaction —
//!      crash anywhere mid-pipeline leaves zero dirty rows.

use clap::Args;
use color_eyre::eyre::{Result, WrapErr};
use knowdit_audit::harness::forge::ForgeBackend;
use knowdit_audit::harness::solidity::{CodegenRegenInMemory, RegenOutcome, SolidityFuzzGenerator};
use knowdit_audit::spec::{
    LinkSpecStatus, SpecGenOptions, SpecRegenInMemory, SpecRegenMode, SpecRegenRequest,
    SpecificationGenerator,
};
use knowdit_audit::types::AuditSpecification;
use knowdit_repo_model::{
    LoadedSpecification, PendingReflection, ReflectionResult, RegenEventRecord, RepoDatabase,
    repo::SpecificationRecord,
};
use llmy::client::client::LLM;
use std::path::Path;

use super::fuzz_common::{FuzzOptionsBuild, HarnessSharedArgs};
use crate::cli::{DatabaseArgs, LoadedRepoDatabase, ProjectArgs};

/// Regen-only knobs (the harness backend itself lives in
/// [`HarnessSharedArgs`], shared with `agentic fuzz`).
#[derive(Args, Clone, Debug)]
pub struct RegenSharedArgs {
    /// Cap on number of pending reflections consumed in this run.
    /// `0` = consume all.
    #[arg(long = "regen-max-pending", default_value_t = 0)]
    pub regen_max_pending: usize,

    /// Hard ceiling on `code_gen_regen` chain depth. When the chain
    /// hits this depth, the pending reflection is rerouted to spec
    /// regen rather than yet another codegen retry. Default 5
    /// mirrors the plan.
    #[arg(long = "regen-max-chain-depth", default_value_t = 5)]
    pub regen_max_chain_depth: u32,

    /// `specification_regen` chain depth threshold below which the
    /// spec regen runs in **patch mode** (prior spec + reflection
    /// feedback as agent input) and above which it runs **from
    /// scratch** (drop history, resynthesize from KG).
    #[arg(long = "spec-regen-patch-threshold", default_value_t = 5)]
    pub spec_regen_patch_threshold: u32,

    /// Maximum agent steps per spec-regen attempt before forced
    /// finalize. Distinct from the codegen agent's
    /// `--harness-max-agent-steps` (in [`HarnessSharedArgs`]).
    #[arg(long = "spec-regen-max-agent-steps", default_value_t = 60)]
    pub spec_regen_max_agent_steps: usize,

    /// Soft cap on how many `AuditSpecification`s the spec-regen
    /// agent may commit per regen call. Should usually be `1` for
    /// regen since we want a single replacement spec, not a
    /// portfolio.
    #[arg(long = "spec-regen-max-specs-per-link", default_value_t = 1)]
    pub spec_regen_max_specs_per_link: usize,
}

#[derive(Args)]
pub struct RegenArgs {
    #[command(flatten)]
    pub project: ProjectArgs,

    #[command(flatten)]
    pub db: DatabaseArgs,

    /// Forge backend + per-spec agent budget + Gate 2 threshold.
    /// Shared with `agentic fuzz` and `workflow autoloop`.
    #[command(flatten)]
    pub harness: HarnessSharedArgs,

    #[command(flatten)]
    pub shared: RegenSharedArgs,
}

impl RegenArgs {
    /// CLI entry: open the project DB, build the forge backend,
    /// delegate to [`Self::regen`], print summary.
    pub async fn run(self, llm: &LLM) -> Result<()> {
        let LoadedRepoDatabase { spec, repo, .. } = self
            .project
            .to_repo_database(self.db.database_path.clone())
            .await?;
        let backend = self.harness.to_forge_backend()?;
        // Preflight before the regen agent loop touches forge — same
        // rationale as standalone fuzz.
        self.harness
            .preflight(&backend, &spec.root)
            .await
            .wrap_err("forge environment preflight failed")?;
        let stats = Self::regen(
            &repo,
            llm,
            &spec.name,
            &spec.root,
            &self.harness,
            &self.shared,
            &backend,
        )
        .await?;
        println!(
            "Regen finished: examined={} codegen_regen={} spec_regen={} escalated_chain_depth={} skipped_no_pair={} skipped_abandoned_spec={} errors={}",
            stats.examined,
            stats.codegen_regen,
            stats.spec_regen,
            stats.escalated_chain_depth,
            stats.skipped_no_pair,
            stats.skipped_abandoned_spec,
            stats.errors,
        );
        Ok(())
    }

    /// In-process entry: consume the pending-reflection queue against
    /// pre-built repo + LLM handles + forge backend. The autoloop
    /// reuses the same `backend` it passed to fuzz so the
    /// `forge coverage --help` probe runs once per cycle, not twice.
    pub async fn regen(
        repo: &RepoDatabase,
        llm: &LLM,
        project_name: &str,
        repo_root: &Path,
        harness: &HarnessSharedArgs,
        shared: &RegenSharedArgs,
        backend: &ForgeBackend,
    ) -> Result<RegenStats> {
        let fuzz_options = harness.to_fuzz_options(FuzzOptionsBuild {
            repo_root: repo_root.to_path_buf(),
            default_cache_key: format!("{}-knowdit-regen", project_name),
            max_specs: 0,
            concurrency: 1,
            regenerate: false,
            via_ir: harness.harness_via_ir,
        });
        let fuzz_generator = SolidityFuzzGenerator::new(repo, llm, &fuzz_options, backend.clone());
        let spec_options = SpecGenOptions {
            max_agent_steps: shared.spec_regen_max_agent_steps,
            max_specs_per_link: shared.spec_regen_max_specs_per_link,
            cache_key: format!("{}-knowdit-spec-regen", project_name),
            debug_prefix: harness.harness_debug_prefix.clone(),
            ..SpecGenOptions::default()
        };
        let runner = RegenRunner::new(
            repo.clone(),
            fuzz_generator,
            llm.clone(),
            spec_options,
            shared.regen_max_chain_depth,
            shared.spec_regen_patch_threshold,
        );
        runner.run(shared.regen_max_pending).await
    }
}

/// Aggregate counters for one `agentic regen` invocation.
#[derive(Default, Debug)]
pub struct RegenStats {
    pub examined: usize,
    pub codegen_regen: usize,
    pub spec_regen: usize,
    pub escalated_chain_depth: usize,
    pub skipped_no_pair: usize,
    pub skipped_abandoned_spec: usize,
    pub errors: usize,
}

struct RegenRunner {
    repo: RepoDatabase,
    fuzz: SolidityFuzzGenerator,
    llm: LLM,
    spec_options: SpecGenOptions,
    max_chain_depth: u32,
    spec_regen_patch_threshold: u32,
}

impl RegenRunner {
    fn new(
        repo: RepoDatabase,
        fuzz: SolidityFuzzGenerator,
        llm: LLM,
        spec_options: SpecGenOptions,
        max_chain_depth: u32,
        spec_regen_patch_threshold: u32,
    ) -> Self {
        Self {
            repo,
            fuzz,
            llm,
            spec_options,
            max_chain_depth,
            spec_regen_patch_threshold,
        }
    }

    async fn run(&self, max_pending: usize) -> Result<RegenStats> {
        let mut stats = RegenStats::default();
        let pending = self.repo.pending_reflections().await?;
        for r in pending {
            if max_pending > 0 && stats.examined >= max_pending {
                break;
            }
            stats.examined += 1;
            if let Err(err) = self.handle(&r, &mut stats).await {
                tracing::error!(reflection_id = r.reflection_id, "regen failed: {err:#}");
                stats.errors += 1;
            }
        }
        Ok(stats)
    }

    async fn handle(&self, r: &PendingReflection, stats: &mut RegenStats) -> Result<()> {
        // Chain-depth escalation. If the codegen chain is already deep,
        // any further codegen retry is unlikely to converge — route the
        // SAME reflection through the spec-regen path instead. We don't
        // synthesize a new reflection row (reflection.run_id is UNIQUE,
        // and the existing pending row already says "needs regen");
        // we just override the dispatch verdict for this attempt.
        let depth = self.repo.code_gen_chain_depth(r.code_id).await?;
        let effective_result = if depth >= self.max_chain_depth
            && !matches!(r.result, ReflectionResult::IncompleteSpecification)
        {
            stats.escalated_chain_depth += 1;
            tracing::warn!(
                reflection_id = r.reflection_id,
                run_id = r.run_id,
                code_id = r.code_id,
                spec_id = r.spec_id,
                "chain depth {depth} hit ceiling {}; rerouting from {:?} to spec regen",
                self.max_chain_depth,
                r.result
            );
            ReflectionResult::IncompleteSpecification
        } else {
            r.result
        };

        match effective_result {
            ReflectionResult::Suspect | ReflectionResult::IncompleteStep => {
                self.codegen_regen(r, stats).await
            }
            ReflectionResult::IncompleteSpecification => self.spec_regen(r, stats).await,
            // The pending query already filters out terminal verdicts;
            // hitting them here would mean the SQL changed under us.
            ReflectionResult::ValidFinding
            | ReflectionResult::ExpectedViolation
            | ReflectionResult::OutOfScope => Err(color_eyre::eyre::eyre!(
                "pending query yielded terminal verdict {:?}; \
                     check pending_reflections SQL",
                r.result
            )),
        }
    }

    async fn codegen_regen(&self, r: &PendingReflection, stats: &mut RegenStats) -> Result<()> {
        let feedback = format_prior_feedback(r);
        let outcome: RegenOutcome = self
            .fuzz
            .regen_one_spec(r.spec_id, feedback)
            .await
            .wrap_err_with(|| format!("regen_one_spec failed for spec_id={}", r.spec_id))?;
        // Lineage row is written after the new code_gen lands. Resume
        // safety: a crash here leaves the new code_gen but no lineage,
        // and the original reflection is still pending — next pass
        // picks it up and we burn an extra regen attempt. Acceptable.
        let event = RegenEventRecord {
            child_id: outcome.new_code_gen_id,
            parent_id: r.code_id,
            reason: r.reason.clone(),
            triggered_by_reflection_id: r.reflection_id,
        };
        self.repo.insert_code_gen_regen(&event).await?;
        stats.codegen_regen += 1;
        tracing::info!(
            reflection_id = r.reflection_id,
            parent_code_id = r.code_id,
            child_code_id = outcome.new_code_gen_id,
            status = ?outcome.status,
            any_violation = outcome.any_violation,
            "codegen regen complete"
        );
        Ok(())
    }

    /// Spec regen pathway: produces a new spec + new code_gen for the
    /// (extract, finding) pair, persisted atomically alongside both
    /// lineage rows. Crash anywhere in the agent loops below leaves
    /// zero dirty rows because nothing is persisted until the final
    /// `write_full_spec_regen` transaction commits.
    async fn spec_regen(&self, r: &PendingReflection, stats: &mut RegenStats) -> Result<()> {
        let SpecRegenContext {
            extract_id,
            finding_id,
            prior_spec,
            prior_spec_id,
        } = match self.load_spec_regen_context(r).await? {
            Some(ctx) => ctx,
            None => {
                stats.skipped_no_pair += 1;
                return Ok(());
            }
        };
        let mode = self
            .choose_spec_regen_mode(prior_spec_id, prior_spec)
            .await?;
        let feedback = format_prior_feedback(r);

        // Phase 1: agent → new spec (in memory).
        let spec_request = SpecRegenRequest {
            extract_id,
            finding_id,
            mode,
            prior_feedback: feedback.clone(),
            serial_for_cache_key: r.reflection_id as usize,
        };
        let spec_outcome: SpecRegenInMemory = SpecificationGenerator::regen_one_link(
            &self.repo,
            &self.llm,
            &self.spec_options,
            spec_request,
        )
        .await
        .wrap_err_with(|| {
            format!("spec regen agent failed for (extract={extract_id}, finding={finding_id})")
        })?;
        let new_spec = match pick_first_spec(&spec_outcome) {
            Some(s) => s,
            None => {
                tracing::warn!(
                    reflection_id = r.reflection_id,
                    extract_id,
                    finding_id,
                    abort_reason = ?spec_outcome.abort_reason,
                    "spec regen agent finished without committing a spec; leaving pending row alone"
                );
                stats.skipped_abandoned_spec += 1;
                return Ok(());
            }
        };

        // Phase 2: agent → new code_gen for the in-memory spec.
        let synthetic_spec_id = -(r.reflection_id);
        let codegen: CodegenRegenInMemory = self
            .fuzz
            .regen_codegen_with_explicit_spec(
                extract_id,
                finding_id,
                new_spec.clone(),
                synthetic_spec_id,
                feedback,
            )
            .await
            .wrap_err_with(|| {
                format!(
                    "codegen regen failed for newly-regenerated spec (extract={extract_id}, finding={finding_id})"
                )
            })?;

        // Phase 3: atomic persist — spec + code_gen + harness_runs +
        // line_coverage + both lineage rows in one transaction. Either
        // every row lands or none.
        let new_spec_record = SpecificationRecord {
            semantic_id: extract_id,
            finding_id,
            specification_json: serde_json::to_string(&new_spec)
                .wrap_err("failed to serialize regenerated spec to JSON")?,
        };
        let ids = self
            .repo
            .write_full_spec_regen(
                &new_spec_record,
                &codegen.code_gen,
                &codegen.coverage_per_run,
                prior_spec_id,
                r.code_id,
                r.reflection_id,
                &r.reason,
                &r.reason,
            )
            .await?;
        stats.spec_regen += 1;
        tracing::info!(
            reflection_id = r.reflection_id,
            parent_spec_id = prior_spec_id,
            child_spec_id = ids.child_spec_id,
            parent_code_id = r.code_id,
            child_code_id = ids.child_code_gen_id,
            status = ?codegen.status,
            "spec regen complete"
        );
        Ok(())
    }

    /// Look up the prior spec for a pending reflection. `None` means
    /// the spec row no longer exists (operator deleted it / DB drift);
    /// caller skips the row.
    async fn load_spec_regen_context(
        &self,
        r: &PendingReflection,
    ) -> Result<Option<SpecRegenContext>> {
        let specs = self.repo.load_specifications().await?;
        let Some(prior_row): Option<LoadedSpecification> =
            specs.into_iter().find(|s| s.id == r.spec_id)
        else {
            tracing::warn!(
                reflection_id = r.reflection_id,
                spec_id = r.spec_id,
                "spec regen: prior spec id not found in specification table; skipping"
            );
            return Ok(None);
        };
        let prior_spec: AuditSpecification = serde_json::from_str(&prior_row.specification_json)
            .wrap_err_with(|| {
                format!("failed to parse prior spec JSON for spec_id={}", r.spec_id)
            })?;
        Ok(Some(SpecRegenContext {
            extract_id: prior_row.semantic_id,
            finding_id: prior_row.finding_id,
            prior_spec,
            prior_spec_id: r.spec_id,
        }))
    }

    /// Patch when the spec_regen chain depth is shallow enough that
    /// "tweak the existing spec" is still a productive ask;
    /// from-scratch once we're past `--spec-regen-patch-threshold`.
    async fn choose_spec_regen_mode(
        &self,
        prior_spec_id: i32,
        prior_spec: AuditSpecification,
    ) -> Result<SpecRegenMode> {
        let depth = self.repo.spec_chain_depth(prior_spec_id).await?;
        if depth <= self.spec_regen_patch_threshold {
            Ok(SpecRegenMode::Patch(prior_spec))
        } else {
            tracing::info!(
                spec_id = prior_spec_id,
                spec_chain_depth = depth,
                threshold = self.spec_regen_patch_threshold,
                "spec_regen depth past patch threshold; switching to from-scratch mode"
            );
            Ok(SpecRegenMode::FromScratch)
        }
    }
}

/// Bundle of state the spec_regen path looks up once at the top of
/// each pending row, so the body of `spec_regen` reads as a linear
/// data flow rather than a string of dependent .await chains.
struct SpecRegenContext {
    extract_id: i32,
    finding_id: i32,
    prior_spec: AuditSpecification,
    prior_spec_id: i32,
}

fn pick_first_spec(out: &SpecRegenInMemory) -> Option<AuditSpecification> {
    if !matches!(out.status, LinkSpecStatus::Built) {
        return None;
    }
    out.specifications.first().cloned()
}

/// Render the prior reflection into a feedback string for the agent's
/// system prompt. Keeps it terse — verdict + reason — so the agent
/// reads it without burning context, but specific enough that it knows
/// what to fix.
fn format_prior_feedback(r: &PendingReflection) -> String {
    format!(
        "Previous attempt: spec {} → code_gen {} → harness_run {} was classified `{:?}`.\n\
         Reason: {}",
        r.spec_id, r.code_id, r.run_id, r.result, r.reason
    )
}
