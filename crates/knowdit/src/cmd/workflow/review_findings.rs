//! `knowdit workflow review-findings` — turn raw `valid_finding` rows into a
//! client-facing audit report.
//!
//! Three phases over the project DB, each resume-safe and idempotent:
//!
//! 1. **Review** (concurrent): every `ValidFinding` lacking a `finding_review`
//!    is graded by [`ReviewGrader`] into a structured, client-facing shape
//!    (title / re-graded severity / root cause / description / location), with
//!    out-of-scope findings flagged. Persisted per finding.
//! 2. **Merge** (serial, incremental): each reviewed finding without a
//!    `finding_merge` edge is folded by [`MergeAgent`] into a canonical
//!    `report_finding` (or starts a new one). The canonical set accumulates
//!    in memory and on disk as it goes — every new raw finding stacks onto it.
//! 3. **Write** (concurrent): each `Merged` reportable canonical is rendered
//!    by [`WriterAgent`] into the client writeup (description / impact /
//!    location / PoC / recommendation), applied atomically.
//!
//! Finally the finished canonicals are rendered to `<output>/audit_report.md`
//! and dumped one-JSON-per-finding under `<output>/report_findings/`.
//!
//! The whole pipeline ([`ReviewFindingsRun::run`]) is shared with streamloop's
//! `--review-findings` flag, which constructs the run from its already-resolved
//! repo / LLM / language prefix instead of the standalone CLI args.

use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use clap::Args;
use color_eyre::eyre::{Result, WrapErr};
use knowdit_audit::harness::solidity::SolidityHarness;
use knowdit_audit::reflect::agent_loop::GraderOptions;
use knowdit_audit::reflect::review_grader::{ReviewGrader, ReviewInput};
use knowdit_audit::report::merge::{MergeAgent, MergeInput};
use knowdit_audit::report::render::{DuplicateBrief, RenderFinding, render_markdown_report};
use knowdit_audit::report::ruled_out::{ConclusionMergeInput, RuledOutMerger};
use knowdit_audit::spec::is_billing_exhausted;
use knowdit_repo_model::{
    FindingMergeDecision, LoadedReportFinding, RawFindingMember, RepoDatabase, ReportFindingSeed,
    ReviewSeverity, ReviewedFinding, RuledOutConclusion, RuledOutMergeDecision, SourceLanguage,
};
use llmy::client::client::LLM;
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;
use tokio::task::JoinSet;

use crate::cli::{DatabaseArgs, LoadedRepoDatabase, ProjectArgs};
use crate::cmd::workflow::utils::write_json_atomic;

/// Tunables shared by the standalone command and streamloop's flag.
#[derive(Args, Clone, Debug)]
pub struct ReviewFindingsSharedArgs {
    /// Explicit out-of-repo authoritative audit standard/scope file. When set,
    /// it is injected at the top of the Review agent's prompt and overrides the
    /// default scope + severity rubric wherever it speaks to them. When unset,
    /// the Review agent looks for an in-repo `knowdit-*.md` at runtime; absent
    /// that, the project docs + default heuristics apply.
    #[arg(long = "scope-file")]
    pub scope_file: Option<PathBuf>,

    /// Max agent steps per Review / Merge / Writer agent call.
    #[arg(long = "review-max-agent-steps", default_value_t = 40)]
    pub review_max_agent_steps: usize,

    /// Worker count for the Review phase (per-finding) and the Writer phase
    /// (per-canonical). The Merge phase is always serial (it mutates the
    /// shared canonical set). Defaults to `1`.
    #[arg(long = "review-concurrency")]
    pub review_concurrency: Option<usize>,

    /// Fraction of the model's max input the Merge agent uses as its
    /// candidate-chunk budget. Canonicals beyond what fits are split into
    /// further chunks; most projects fit in one (a single call). Range (0,1].
    #[arg(long = "review-context-window-ratio", default_value_t = 0.5)]
    pub review_context_window_ratio: f64,
}

impl ReviewFindingsSharedArgs {
    pub(crate) fn grader_options(&self) -> GraderOptions {
        GraderOptions {
            max_agent_steps: self.review_max_agent_steps,
            debug_prefix: Some("review".to_string()),
            llm_settings: None,
        }
    }
}

#[derive(Args)]
pub struct ReviewFindingsArgs {
    #[command(flatten)]
    pub project: ProjectArgs,

    #[command(flatten)]
    pub db: DatabaseArgs,

    #[command(flatten)]
    pub shared: ReviewFindingsSharedArgs,

    /// Output folder for `audit_report.md` and `report_findings/*.json`.
    #[arg(short, long)]
    pub output_folder: PathBuf,
}

impl ReviewFindingsArgs {
    pub async fn run(self, llm: &LLM) -> Result<()> {
        let LoadedRepoDatabase { spec, repo, .. } = self
            .project
            .to_repo_database(self.db.database_path.clone(), self.db.variant_render_cap)
            .await?;

        // Standalone CLI is Solidity-only (mirrors `agentic reflect`); other
        // languages must come through `workflow streamloop --review-findings`,
        // which threads its own backend prompt prefix in.
        let profile = repo.get_project_profile().await?.ok_or_else(|| {
            color_eyre::eyre::eyre!(
                "review-findings requires a ProjectProfile; run `knowdit agentic profile` for \
                 project '{}' first (or run it via `workflow streamloop`).",
                spec.name
            )
        })?;
        if profile.language != SourceLanguage::Solidity {
            return Err(color_eyre::eyre::eyre!(
                "standalone `workflow review-findings` only supports Solidity; use \
                 `workflow streamloop --review-findings` for other languages"
            ));
        }

        let scope_override = resolve_scope_override(self.shared.scope_file.as_deref())?;
        let options = self.shared.grader_options();
        let run = ReviewFindingsRun {
            repo,
            llm: llm.clone(),
            project_name: spec.name,
            repo_root: spec.root,
            language_prompt_prefix: SolidityHarness::PROMPT_PREFIX.to_string(),
            scope_override,
            options,
            output_folder: self.output_folder,
            concurrency: self.shared.review_concurrency.unwrap_or(1).max(1),
            window_ratio: self.shared.review_context_window_ratio,
        };
        let stats = run.run().await?;
        println!(
            "review-findings finished: reviewed={} (out_of_scope={}, review_errors={}); \
             canonicals={} (new={}, merged_in={}, merge_errors={})",
            stats.reviewed,
            stats.out_of_scope,
            stats.review_errors,
            stats.canonicals,
            stats.merged_new,
            stats.merged_into,
            stats.merge_errors,
        );
        Ok(())
    }
}

/// Read the explicitly-supplied authoritative standard file (`--scope-file`),
/// if any. There is deliberately NO hardcoded in-repo filename: a standard
/// dropped into the repo as `knowdit-*.md` is discovered and read by the
/// Review agent itself at runtime (the prompt instructs it to), so the host
/// only injects a standard when the user points at an out-of-repo file.
pub fn resolve_scope_override(scope_file: Option<&Path>) -> Result<Option<String>> {
    let Some(path) = scope_file else {
        return Ok(None);
    };
    let text = std::fs::read_to_string(path)
        .wrap_err_with(|| format!("failed to read --scope-file {}", path.display()))?;
    tracing::info!(
        "[review-findings] injecting authoritative standard from {}",
        path.display()
    );
    Ok(Some(text))
}

/// On-disk shape of one unique (deduplicated) finding, dumped to
/// `<output>/unique_findings/finding_{id}.json` incrementally as the cluster
/// grows. Self-contained: the canonical identity, the chosen representative
/// member (the report renders from it) + its `harness_source` PoC, and every
/// cluster member's structured review. Pure serde, no ad-hoc JSON.
///
/// Also embedded whole into each raw finding's on-disk `merged_to` field
/// (see [`crate::cmd::workflow::streamloop::OnDiskFinding`]), so a raw dump
/// carries its complete unique finding inline.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct OnDiskUniqueFinding {
    #[serde(flatten)]
    finding: LoadedReportFinding,
    /// `reflection_id` of the representative member (highest
    /// `(severity, link_strength, mapper_strength)`, then shortest harness).
    representative_reflection_id: i32,
    /// The representative member's existing proof-of-concept (`harness_source`).
    poc: String,
    /// Every cluster member's review (the representative is one of these).
    members: Vec<ReviewedFinding>,
}

impl OnDiskUniqueFinding {
    /// Embed this complete unique finding into the raw finding's on-disk dump
    /// at `path` (a streamloop [`OnDiskFinding`]'s `merged_to`), atomically.
    /// Round-trips through the serde shape — no ad-hoc JSON surgery.
    fn stamp_merged_to(&self, path: &Path) -> Result<()> {
        let text = std::fs::read_to_string(path)
            .wrap_err_with(|| format!("failed to read {}", path.display()))?;
        let mut on_disk: crate::cmd::workflow::streamloop::OnDiskFinding =
            serde_json::from_str(&text)
                .wrap_err_with(|| format!("failed to parse {}", path.display()))?;
        on_disk.merged_to = Some(self.clone());
        write_json_atomic(path, &on_disk)
    }
}

/// Roll-up counters for the run.
#[derive(Debug, Default, Clone, Copy)]
pub struct ReviewFindingsStats {
    pub reviewed: usize,
    pub out_of_scope: usize,
    pub review_errors: usize,
    pub canonicals: usize,
    pub merged_new: usize,
    pub merged_into: usize,
    pub merge_errors: usize,
    /// Rejections placed into the ruled-out conclusion set.
    pub ruled_out_placed: usize,
    /// Distinct conclusions that set currently holds. The ratio between the
    /// two is the redundancy this injection removes.
    pub ruled_out_conclusions: usize,
    pub ruled_out_errors: usize,
}

/// The shared Review → Merge → Write → export pipeline. Owns cheap-to-clone
/// handles (`RepoDatabase` / `LLM` are `Arc` inside) so phase tasks can be
/// spawned `'static`.
pub struct ReviewFindingsRun {
    pub repo: RepoDatabase,
    pub llm: LLM,
    pub project_name: String,
    pub repo_root: PathBuf,
    pub language_prompt_prefix: String,
    pub scope_override: Option<String>,
    pub options: GraderOptions,
    pub output_folder: PathBuf,
    /// Worker count for the Review + Write phases (Merge is serial).
    pub concurrency: usize,
    /// Merge candidate-chunk budget as a fraction of the model's max input.
    pub window_ratio: f64,
}

/// The report knobs streamloop carries into the shared link pipeline so it
/// can drain review + merge after each completed link. Paired with the
/// pipeline's already-resolved repo / LLM / prefix to build a
/// [`ReportContext`].
#[derive(Clone)]
pub struct ReportInlineCfg {
    pub scope_override: Option<String>,
    pub options: GraderOptions,
    pub window_ratio: f64,
    pub concurrency: usize,
}

impl ReportInlineCfg {
    /// Combine with the pipeline's resolved context into a runnable config.
    pub fn into_run(
        self,
        repo: RepoDatabase,
        llm: LLM,
        project_name: String,
        repo_root: PathBuf,
        language_prompt_prefix: String,
        output_folder: PathBuf,
    ) -> ReviewFindingsRun {
        ReviewFindingsRun {
            repo,
            llm,
            project_name,
            repo_root,
            language_prompt_prefix,
            scope_override: self.scope_override,
            options: self.options,
            output_folder,
            concurrency: self.concurrency,
            window_ratio: self.window_ratio,
        }
    }
}

impl ReviewFindingsRun {
    /// Standalone batch run: build the context, then review → merge →
    /// finalize (export), all once.
    pub async fn run(self) -> Result<ReviewFindingsStats> {
        let mut ctx = ReportContext::build(self).await?;
        ctx.review_pending().await?;
        ctx.merge_pending().await?;
        ctx.finalize().await?;
        Ok(ctx.stats)
    }
}

/// Persistent report pipeline: the built agents + the in-memory canonical set
/// + counters. Built once; [`Self::review_pending`] / [`Self::merge_pending`]
/// are idempotent DB-driven drains that can be called repeatedly (streamloop
/// calls them after each completed link), and [`Self::write_and_export`]
/// finalizes. The standalone command calls all three once.
pub struct ReportContext {
    repo: RepoDatabase,
    llm: LLM,
    repo_root: PathBuf,
    project_name: String,
    language_prompt_prefix: String,
    options: GraderOptions,
    output_folder: PathBuf,
    concurrency: usize,
    review: Arc<ReviewGrader>,
    merge: MergeAgent,
    ruled_out: RuledOutMerger,
    /// The merge agent's accumulating canonical set, kept in sync with the DB
    /// across drains so each new finding compares against all prior canonicals.
    canonicals: Vec<LoadedReportFinding>,
    /// Same accumulator for the ruled-out side.
    conclusions: Vec<RuledOutConclusion>,
    pub stats: ReviewFindingsStats,
}

impl ReportContext {
    pub async fn build(run: ReviewFindingsRun) -> Result<Self> {
        std::fs::create_dir_all(run.output_folder.join("unique_findings")).wrap_err_with(|| {
            format!(
                "failed to create output folder {}",
                run.output_folder.display()
            )
        })?;
        let review = Arc::new(
            ReviewGrader::new(
                &run.repo,
                &run.repo_root,
                run.language_prompt_prefix.clone(),
                run.scope_override.clone(),
                &run.llm,
                run.options.clone(),
            )
            .await?,
        );
        let merge = MergeAgent::new(
            &run.repo,
            &run.repo_root,
            run.language_prompt_prefix.clone(),
            &run.llm,
            run.options.clone(),
            run.window_ratio,
        )
        .await?;
        // Shares the merge agent's already-loaded project graphs.
        let ruled_out = RuledOutMerger::new(
            merge.project_index().clone(),
            run.language_prompt_prefix.clone(),
            &run.llm,
            run.options.clone(),
            run.window_ratio,
        );
        let canonicals = run.repo.load_report_findings().await?;
        let conclusions = run.repo.load_ruled_out_conclusions().await?;
        Ok(Self {
            repo: run.repo,
            llm: run.llm,
            repo_root: run.repo_root,
            project_name: run.project_name,
            language_prompt_prefix: run.language_prompt_prefix,
            options: run.options,
            output_folder: run.output_folder,
            concurrency: run.concurrency.max(1),
            review,
            merge,
            ruled_out,
            canonicals,
            conclusions,
            stats: ReviewFindingsStats::default(),
        })
    }

    /// Review every raw finding that lacks a `finding_review`, bounded-
    /// concurrently. Idempotent: re-running only grades what's new.
    pub async fn review_pending(&mut self) -> Result<()> {
        let pending = self.repo.load_unreviewed_valid_findings().await?;
        if pending.is_empty() {
            return Ok(());
        }
        tracing::info!(
            "[review-findings] review: {} unreviewed finding(s)",
            pending.len()
        );
        let queue = Arc::new(Mutex::new(VecDeque::from(pending)));
        let mut tasks: JoinSet<Result<ReviewSeverity>> = JoinSet::new();
        loop {
            while tasks.len() < self.concurrency {
                let Some(vf) = queue.lock().await.pop_front() else {
                    break;
                };
                let grader = self.review.clone();
                let repo = self.repo.clone();
                tasks.spawn(async move {
                    let input = ReviewInput::from_valid_finding(&vf)?;
                    let out = grader.grade(&input).await?;
                    let severity = out.severity;
                    repo.insert_finding_review(&out.into_record(vf.reflection_id))
                        .await?;
                    Ok(severity)
                });
            }
            let Some(joined) = tasks.join_next().await else {
                break;
            };
            match joined {
                Ok(Ok(severity)) => {
                    self.stats.reviewed += 1;
                    if severity == ReviewSeverity::ReviewedOutOfScope {
                        self.stats.out_of_scope += 1;
                    }
                }
                Ok(Err(err)) => {
                    if is_billing_exhausted(&err) {
                        tasks.abort_all();
                        return Err(err).wrap_err(
                            "review-findings stopped because the LLM billing cap was exhausted",
                        );
                    }
                    self.stats.review_errors += 1;
                    tracing::error!("[review-findings] review failed for a finding: {err:#}");
                }
                Err(join_err) => {
                    self.stats.review_errors += 1;
                    tracing::error!("[review-findings] review task panicked: {join_err:#}");
                }
            }
        }
        Ok(())
    }

    /// Fold every reviewed-but-unmerged finding into the canonical set,
    /// serially against the accumulating in-memory canonicals. A per-finding
    /// failure leaves it unmerged for the next drain.
    pub async fn merge_pending(&mut self) -> Result<()> {
        let pending = self.repo.load_unmerged_finding_reviews().await?;
        if pending.is_empty() {
            self.stats.canonicals = self.canonicals.len();
            return Ok(());
        }
        tracing::info!(
            "[review-findings] merge: {} unmerged reviewed finding(s)",
            pending.len()
        );
        for finding in pending {
            let input = MergeInput::new(&finding, &self.canonicals);
            let choice = match self.merge.decide(&input).await {
                Ok(c) => c,
                Err(err) => {
                    self.stats.merge_errors += 1;
                    tracing::error!(
                        "[review-findings] merge failed for reflection {}: {err:#}",
                        finding.reflection_id
                    );
                    continue;
                }
            };
            let decision = match choice.merge_into {
                Some(id) => FindingMergeDecision::MergeInto {
                    report_finding_id: id,
                    raise_to: Some(finding.severity),
                },
                None => FindingMergeDecision::NewCanonical(ReportFindingSeed {
                    title: finding.title.clone(),
                    severity: finding.severity,
                    root_cause: finding.root_cause.clone(),
                    description: finding.description.clone(),
                    primary_contract: finding.primary_contract.clone(),
                    primary_function: finding.primary_function.clone(),
                }),
            };
            let rid = finding.reflection_id;
            let canonical_id = self.repo.commit_finding_merge(rid, decision).await?;
            match choice.merge_into {
                None => {
                    self.stats.merged_new += 1;
                    self.canonicals.push(LoadedReportFinding {
                        id: canonical_id,
                        title: finding.title,
                        severity: finding.severity,
                        root_cause: finding.root_cause,
                        description: finding.description,
                        primary_contract: finding.primary_contract,
                        primary_function: finding.primary_function,
                    });
                }
                Some(id) => {
                    self.stats.merged_into += 1;
                    if let Some(c) = self.canonicals.iter_mut().find(|c| c.id == id)
                        && finding.severity.rank() > c.severity.rank()
                    {
                        c.severity = finding.severity;
                    }
                }
            }
            self.stats.canonicals = self.canonicals.len();
            // Incremental write: only the affected canonical's JSON + the raw
            // finding's `merged_to` (the complete unique finding embedded). The
            // `audit_report.md` render needs per-canonical representative
            // resolution, so it runs once at finalize, not per merge.
            if let Some(unique) = self.build_unique_finding(canonical_id).await? {
                self.write_unique_finding(canonical_id, &unique)?;
                self.stamp_raw_merged_to(rid, &unique);
            }
        }
        Ok(())
    }

    /// Fold every unplaced rejection into the ruled-out conclusion set,
    /// serially against the accumulating in-memory conclusions. Mirrors
    /// [`Self::merge_pending`]: a per-rejection failure leaves it unplaced for
    /// the next drain, so nothing is lost and nothing is double-counted.
    ///
    /// Unlike the finding side this produces no report output — the set exists
    /// solely to be injected into later gen-spec prompts, so that agents stop
    /// re-establishing conclusions their peers already reached.
    pub async fn ruled_out_pending(&mut self) -> Result<()> {
        let pending = self.repo.load_unmerged_ruled_out().await?;
        if pending.is_empty() {
            self.stats.ruled_out_conclusions = self.conclusions.len();
            return Ok(());
        }
        tracing::info!(
            "[review-findings] ruled-out: {} unplaced rejection(s) against {} conclusion(s)",
            pending.len(),
            self.conclusions.len(),
        );
        for rejection in pending {
            let input = ConclusionMergeInput::new(&rejection, &self.conclusions);
            let choice = match self.ruled_out.decide(&input).await {
                Ok(c) => c,
                Err(err) => {
                    self.stats.ruled_out_errors += 1;
                    tracing::error!(
                        "[review-findings] ruled-out placement failed for reflection {}: {err:#}",
                        rejection.reflection_id
                    );
                    continue;
                }
            };
            let decision = match choice.merge_into {
                Some(to_reflection_id) => RuledOutMergeDecision::MergeInto { to_reflection_id },
                None => RuledOutMergeDecision::NewConclusion,
            };
            let representative = self
                .repo
                .commit_ruled_out_merge(rejection.reflection_id, decision)
                .await?;
            self.stats.ruled_out_placed += 1;
            match self.conclusions.iter_mut().find(|c| c.id == representative) {
                Some(existing) => existing.occurrences += 1,
                None => self.conclusions.push(RuledOutConclusion {
                    id: representative,
                    claim: rejection.claim,
                    evidence: rejection.evidence,
                    occurrences: 1,
                }),
            }
            // Keep the accumulator in the order the renderer expects
            // (most-repeated first) so a capped block keeps the conclusions
            // that cost the most to rediscover.
            self.conclusions
                .sort_by(|a, b| b.occurrences.cmp(&a.occurrences).then(a.id.cmp(&b.id)));
            self.stats.ruled_out_conclusions = self.conclusions.len();
        }
        tracing::info!(
            "[review-findings] ruled-out: {} rejection(s) placed into {} distinct conclusion(s)",
            self.stats.ruled_out_placed,
            self.conclusions.len(),
        );
        Ok(())
    }

    /// Assemble one canonical's unique finding: identity + the representative
    /// member (chosen by `representative_key`) + its PoC + all member reviews.
    /// `None` if the canonical or its members vanished.
    async fn build_unique_finding(&self, canonical_id: i32) -> Result<Option<OnDiskUniqueFinding>> {
        let Some(finding) = self.repo.load_report_finding(canonical_id).await? else {
            return Ok(None);
        };
        let members = self.repo.load_report_finding_members(canonical_id).await?;
        let Some(rep) = members.iter().max_by_key(|m| m.representative_key()) else {
            return Ok(None);
        };
        Ok(Some(OnDiskUniqueFinding {
            finding,
            representative_reflection_id: rep.review.reflection_id,
            poc: rep.source.harness_source.clone(),
            members: members.iter().map(|m| m.review.clone()).collect(),
        }))
    }

    /// Resolve a canonical to its [`RenderFinding`] (representative member's
    /// client fields + PoC + the duplicate members). `None` if no members.
    fn render_finding_of(
        canonical: &LoadedReportFinding,
        members: &[RawFindingMember],
    ) -> Option<RenderFinding> {
        let rep = members.iter().max_by_key(|m| m.representative_key())?;
        let duplicates = members
            .iter()
            .filter(|m| m.review.reflection_id != rep.review.reflection_id)
            .map(|m| DuplicateBrief {
                title: m.review.title.clone(),
                description: m.review.description.clone(),
            })
            .collect();
        Some(RenderFinding {
            canonical_id: canonical.id,
            severity: canonical.severity,
            title: rep.review.title.clone(),
            description: rep.review.description.clone(),
            location: rep.review.location.clone(),
            impact: rep.review.impact.clone(),
            recommendation: rep.review.recommendation.clone(),
            poc: rep.source.harness_source.clone(),
            duplicates,
        })
    }

    /// Atomic dump of one `unique_findings/finding_{id}.json`.
    fn write_unique_finding(&self, canonical_id: i32, unique: &OnDiskUniqueFinding) -> Result<()> {
        write_json_atomic(
            &self
                .output_folder
                .join("unique_findings")
                .join(format!("finding_{canonical_id:04}.json")),
            unique,
        )
    }

    /// Best-effort: embed the complete unique finding into the raw finding's
    /// on-disk dump (`<output>/valid_findings/finding_{reflection_id}.json`,
    /// written by streamloop). Silently skips when the file is absent (e.g. the
    /// standalone command, whose output folder has no raw dump).
    fn stamp_raw_merged_to(&self, reflection_id: i32, unique: &OnDiskUniqueFinding) {
        let path = self
            .output_folder
            .join("valid_findings")
            .join(format!("finding_{reflection_id}.json"));
        if !path.exists() {
            return;
        }
        if let Err(err) = unique.stamp_merged_to(&path) {
            tracing::warn!(
                "[review-findings] could not stamp merged_to on {}: {err:#}",
                path.display()
            );
        }
    }

    /// Re-stamp every merged raw finding with its FINAL complete unique finding
    /// (writeups included). During the run each raw dump only carries a
    /// point-in-time snapshot from when it merged; this finalize pass brings
    /// them all up to the end state. Best-effort per file.
    async fn restamp_all_merged(&self) -> Result<()> {
        for canonical in &self.canonicals {
            let Some(unique) = self.build_unique_finding(canonical.id).await? else {
                continue;
            };
            for member in &unique.members {
                self.stamp_raw_merged_to(member.reflection_id, &unique);
            }
        }
        Ok(())
    }

    /// Finalize: re-stamp every merged raw dump with its final complete unique
    /// finding, then render `<output>/audit_report.md` from each canonical's
    /// representative member (+ duplicates). No Writer agent — the client text
    /// is the representative's review and the PoC is its `harness_source`.
    pub async fn finalize(&mut self) -> Result<()> {
        self.canonicals = self.repo.load_report_findings().await?;
        self.stats.canonicals = self.canonicals.len();
        self.restamp_all_merged().await?;

        let mut render_findings: Vec<RenderFinding> = Vec::with_capacity(self.canonicals.len());
        for canonical in &self.canonicals {
            let members = self.repo.load_report_finding_members(canonical.id).await?;
            if let Some(rf) = Self::render_finding_of(canonical, &members) {
                render_findings.push(rf);
            }
        }
        let markdown = render_markdown_report(&self.project_name, &render_findings);
        let report_path = self.output_folder.join("audit_report.md");
        let tmp = report_path.with_extension("md.tmp");
        std::fs::write(&tmp, markdown)
            .wrap_err_with(|| format!("failed to write {}", tmp.display()))?;
        std::fs::rename(&tmp, &report_path)
            .wrap_err_with(|| format!("failed to rename into {}", report_path.display()))?;
        tracing::info!(
            "[review-findings] report: {} unique finding(s) → {}",
            render_findings.len(),
            report_path.display()
        );
        Ok(())
    }
}
