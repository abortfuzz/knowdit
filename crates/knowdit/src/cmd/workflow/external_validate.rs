//! `workflow external-validate` — validate externally-supplied findings.
//!
//! Where `streamloop` *discovers* candidate issues (extract-semantics →
//! map-semantics against the historical KG), this workflow takes a JSON file of
//! already-known findings (e.g. converted from an external audit backend's
//! Phase-3 output) and runs only the *validation* half of the pipeline against
//! them: gen-specs → fuzz (PoC) → reflect (→ regen).
//!
//! The JSON is ingested into exactly the tables `map-semantics` would have
//! written (`project_semantic` + a synthesized historical shell carrying the
//! finding + `semantic_matched`), so the downstream DB-driven pipeline
//! (`SpecGenStream` / `LinkScheduler`) is reused verbatim — see
//! [`crate::cmd::workflow::streamloop`].
//!
//! Solidity-only: external findings originate from a Solidity audit backend.

use std::collections::BTreeMap;
use std::path::PathBuf;

use clap::Args;
use color_eyre::eyre::{Result, WrapErr, eyre};
use knowdit_audit::harness::HarnessBackend;
use knowdit_audit::spec::{LinkSource, StatusRenderCaps};
use knowdit_kg_model::audit_finding::FindingSeverity;
use knowdit_kg_model::category::DeFiCategory;
use knowdit_kg_model::db::{audit_finding, semantic_node};
use knowdit_kg_model::link_strength::LinkStrength;
use knowdit_kg_model::{ExtractedFunction, ExtractedSemantic};
use knowdit_project::SourceLanguage;
use knowdit_repo_model::cg::CallGraph;
use knowdit_repo_model::{
    HistoricalLinkedFinding, HistoricalSemanticRecord, MatchStrength, RepoDatabase,
    ReviewedFinding, SemanticMatch, SemanticMatchSet,
};
use llmy::clap::OptOpenAISetup;
use llmy::client::client::LLM;
use serde::{Deserialize, Serialize};

use crate::cmd::audit::fuzz::FuzzSharedArgs;
use crate::cmd::audit::fuzz_common::{FuzzOptionsBuild, HarnessSharedArgs};
use crate::cmd::audit::gen_specs::GenSpecsSharedArgs;
use crate::cmd::audit::profile::{ProfileArgs, ProfileSharedArgs};
use crate::cmd::audit::reflect::ReflectSharedArgs;
use crate::cmd::audit::regen::RegenSharedArgs;
use crate::cmd::solidity::SolidityCallGraphStaticArgs;
use crate::cmd::workflow::review_findings::{self, ReviewFindingsRun, ReviewFindingsSharedArgs};
use crate::cmd::workflow::streamloop::{LinkPipelineInputs, PhaseUsage};
use crate::cmd::workflow::utils::write_json_atomic;

#[derive(Args, Debug, Clone)]
pub struct ExternalValidateArgs {
    #[command(flatten)]
    pub project: crate::cli::ProjectArgs,

    #[command(flatten)]
    pub db: crate::cli::DatabaseArgs,

    #[command(flatten)]
    pub backend: crate::cli::ProjectBackendCliOptions,

    // No `--kg` / extract / map shared args: this workflow replaces the
    // discovery stages with the `--findings` JSON ingest.
    #[command(flatten)]
    pub reflect_llm: OptOpenAISetup,

    #[command(flatten)]
    pub profile: ProfileSharedArgs,

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

    /// Review/report criteria applied after a finding is reproduced.
    #[command(flatten)]
    pub review: ReviewFindingsSharedArgs,

    /// Path to the external findings JSON (knowdit `ExternalFindingsFile`
    /// shape). Each finding names a target contract (+ optional function) plus
    /// the reported vulnerability details to reproduce.
    #[arg(long)]
    pub findings: PathBuf,

    /// Safety cap on fuzz → reflect → regen lineage passes per link before the
    /// worker slot is released. Same role as in `streamloop`.
    #[arg(long, default_value_t = 8)]
    pub max_inner_cycles_per_batch: usize,

    /// Number of link pipelines kept active at once (default 1).
    #[arg(long)]
    pub stream_link_concurrency: Option<usize>,

    /// Fallback concurrency for every sub-phase when its per-phase flag is
    /// unset. Per-phase flags always win.
    #[arg(short = 'd', long)]
    pub default_concurrency: Option<usize>,

    /// Output folder for per-link summaries, the usage report, and the
    /// validation report. Deterministic layout → re-running resumes.
    #[arg(short, long)]
    pub output_folder: PathBuf,

    /// `rm -rf` the output folder before the run (off by default so resume
    /// works).
    #[arg(short, long)]
    pub force_clean_output: bool,
}

impl ExternalValidateArgs {
    pub async fn run(mut self, primary_llm: &LLM) -> Result<()> {
        self.apply_default_concurrency();
        self.prepare_output_folder()?;
        self.harness.harness_via_ir = self.backend.foundry.via_ir;

        let loaded = self
            .project
            .to_repo_database(self.db.database_path.clone(), self.db.variant_render_cap)
            .await?;
        let spec_name = loaded.spec.name.clone();
        let repo_root = loaded.spec.root.clone();
        let repo = loaded.repo;

        let reflect_llm = self
            .reflect_llm
            .clone()
            .may_llm()
            .await
            .map_err(|err| eyre!("failed to build reflect LLM: {err}"))?
            .unwrap_or_else(|| primary_llm.clone());

        // Profile is still run: reflect (Gate-2 coverage) needs a cached
        // `ProjectProfile`, and it's the language gate — this workflow is
        // Solidity-only.
        let profile_llm = primary_llm.scope(Some("profile".to_string()), None);
        let profile = ProfileArgs::profile(&repo, &profile_llm, &repo_root, &self.profile).await?;
        if profile.language != SourceLanguage::Solidity {
            return Err(eyre!(
                "workflow external-validate is Solidity-only; profile declared language={:?}",
                profile.language
            ));
        }

        let harness_backend = self.harness.to_solidity_harness(FuzzOptionsBuild {
            repo_root: repo_root.clone(),
            max_specs: 0,
            concurrency: self.fuzz.fuzz_concurrency.unwrap_or(1).max(1),
            regenerate: self.fuzz.fuzz_regenerate,
            via_ir: self.harness.harness_via_ir,
        })?;
        tracing::info!("[external-validate] verifying forge environment");
        harness_backend.preflight(&repo_root).await.wrap_err(
            "forge environment preflight failed — fix the project's foundry config / forge-std \
             install and re-run",
        )?;

        // Call graph is needed both to ground the findings' targets and for the
        // gen-spec agent's ProjectIndex.
        let cg = repo.load_call_graph().await?;
        if cg.contracts.is_empty() {
            tracing::info!(
                "[external-validate] no contracts in call graph — running static call-graph phase"
            );
            SolidityCallGraphStaticArgs::update_call_graph(
                &repo,
                &repo_root,
                &self.backend,
                self.harness.forge_bin.clone(),
            )
            .await?;
        }
        let cg = repo.load_call_graph().await?;
        if cg.contracts.is_empty() {
            return Err(eyre!(
                "no available contracts found after Solidity call-graph rebuild"
            ));
        }

        // Ingest the external findings in place of extract-semantics +
        // map-semantics: they land in the same mapper-output tables.
        let mut outcomes = self.ingest_external_findings(&repo).await?;
        let grounded = outcomes.iter().filter(|o| o.grounded).count();
        if grounded == 0 {
            tracing::warn!(
                "[external-validate] no findings could be grounded against the project — nothing to validate"
            );
        }

        // Shared post-mapper pipeline. `LinkSource::External` flips the gen-spec
        // agent from "explore for related issues" to "reproduce this reported
        // finding".
        let language_prompt_prefix = harness_backend.prompt_prefix().to_string();
        let gen_options = self.gen_specs.build_spec_options(
            language_prompt_prefix.clone(),
            LinkSource::External,
            Some(profile.clone()),
            self.project.include_lib_sources,
        );
        // Resolve review inputs before starting costly validation work so a
        // missing/invalid criteria file fails fast.
        let review_scope_override =
            review_findings::resolve_scope_override(self.review.scope_file.as_deref())?;
        let review_options = self.review.grader_options();
        // Keep a DB handle for the post-run verdict correlation (the pipeline
        // moves `repo` into its LinkContext).
        let report_repo = repo.clone();
        let mut usage = LinkPipelineInputs {
            backend: harness_backend,
            primary_llm: primary_llm.clone(),
            reflect_llm,
            repo,
            repo_root: repo_root.clone(),
            spec_name: spec_name.clone(),
            language_prompt_prefix: language_prompt_prefix.clone(),
            gen_options,
            harness: self.harness.clone(),
            reflect: self.reflect.clone(),
            regen: self.regen.clone(),
            output_folder: self.output_folder.clone(),
            max_inner_cycles: self.max_inner_cycles_per_batch.max(1),
            concurrency: self.stream_link_concurrency.unwrap_or(1).max(1),
            only_spec: false,
            report_cfg: None,
            // The novelty judge defers a link whose specifications duplicate
            // ones the run already built. That is the right question when
            // links come from the mapper, where the same defect is reachable
            // from many historical findings; here every link *is* a distinct
            // reported finding the caller asked to be validated, so deferring
            // one as a duplicate would silently drop it from the report.
            novelty: None,
            novelty_batch: 0,
            // Both injections read sets that the *inline* review + merge drain
            // produces, and this workflow deliberately runs review after the
            // pipeline instead (`report_cfg: None`), so both would always be
            // empty here. Caps are zero for the same reason: nothing renders.
            inject_reviewed_findings: false,
            inject_ruled_out: false,
            status_caps: StatusRenderCaps {
                max_reported: 0,
                max_ruled_out: 0,
                field_chars: 0,
            },
        }
        .run()
        .await?;

        // Review is intentionally owned by external-validate rather than the
        // shared streamloop scheduler. Validation first produces raw valid
        // findings; only then do we review, merge, and export them using the
        // caller-supplied criteria (`--scope-file`).
        let review_llm = primary_llm.scope(Some("external-validate-review".to_string()), None);
        let review_result = ReviewFindingsRun {
            repo: report_repo.clone(),
            llm: review_llm,
            project_name: spec_name.clone(),
            repo_root,
            language_prompt_prefix,
            scope_override: review_scope_override,
            options: review_options,
            output_folder: self.output_folder.clone(),
            concurrency: self.review.review_concurrency.unwrap_or(1).max(1),
            window_ratio: self.review.review_context_window_ratio,
        }
        .run()
        .await;

        // This workflow has no extract / mapper phase; only profile + per-link.
        usage.profile = PhaseUsage::snapshot(&profile_llm);
        usage.finalize_total();
        usage
            .write(&self.output_folder)
            .wrap_err("failed to write run usage report")?;

        self.mark_reproduced_findings(&report_repo, &mut outcomes)
            .await?;
        let report = ValidationReport::from_outcomes(outcomes);
        let report_path = self.output_folder.join("validation_report.json");
        write_json_atomic(&report_path, &report)?;
        tracing::info!(
            "[external-validate] validation report: {} grounded, {} skipped, {} reproduced → {}",
            report.grounded,
            report.skipped,
            report.reproduced,
            report_path.display(),
        );

        if let Some(abort) = &usage.billing_abort {
            return Err(eyre!(
                "billing cap exhausted: scope `{}` hit cap ${} (spent ${}); run aborted. \
                 Partial usage + validation report written to {}.",
                abort.scope.as_deref().unwrap_or("root"),
                abort.cap,
                abort.current,
                self.output_folder.display(),
            ));
        }
        if let Err(err) = review_result {
            return Err(err).wrap_err_with(|| {
                format!(
                    "external-validate review failed; partial usage + validation report written to {}",
                    self.output_folder.display()
                )
            });
        }
        Ok(())
    }

    fn apply_default_concurrency(&mut self) {
        let Some(d) = self.default_concurrency else {
            return;
        };
        let d = d.max(1);
        self.gen_specs.gen_specs_concurrency.get_or_insert(d);
        self.fuzz.fuzz_concurrency.get_or_insert(d);
        self.reflect.reflect_concurrency.get_or_insert(d);
        self.regen.regen_concurrency.get_or_insert(d);
        self.stream_link_concurrency.get_or_insert(d);
        self.review.review_concurrency.get_or_insert(d);
    }

    fn prepare_output_folder(&self) -> Result<()> {
        let out = &self.output_folder;
        if out.exists() && self.force_clean_output {
            std::fs::remove_dir_all(out)
                .wrap_err_with(|| format!("failed to clean output folder {}", out.display()))?;
        }
        std::fs::create_dir_all(out)
            .wrap_err_with(|| format!("failed to create output folder {}", out.display()))?;
        Ok(())
    }

    /// Read + parse the findings JSON, ground every target against the project
    /// call graph, and write the grounded ones into the mapper-output tables
    /// (transactional replace → idempotent on re-run). Returns every finding's
    /// outcome (grounded and skipped) for the report.
    async fn ingest_external_findings(&self, repo: &RepoDatabase) -> Result<Vec<FindingOutcome>> {
        let text = std::fs::read_to_string(&self.findings).wrap_err_with(|| {
            format!(
                "failed to read findings JSON at {}",
                self.findings.display()
            )
        })?;
        let file: ExternalFindingsFile = serde_json::from_str(&text).wrap_err_with(|| {
            format!(
                "failed to parse findings JSON at {}",
                self.findings.display()
            )
        })?;

        let call_graph = repo.load_call_graph().await?;
        let index = GroundingIndex::from_call_graph(&call_graph);
        let ingested = build_ingest(&file.findings, &index);

        let grounded = ingested.extracts.len();
        let skipped = ingested.outcomes.len() - grounded;
        repo.replace_project_semantics(&ingested.extracts).await?;
        repo.write_semantic_match_results(&ingested.match_set)
            .await?;
        tracing::info!(
            "[external-validate] ingested {} finding(s): {} grounded → links, {} skipped (target not in call graph)",
            ingested.outcomes.len(),
            grounded,
            skipped,
        );
        Ok(ingested.outcomes)
    }

    /// After the pipeline, flip `reproduced = true` on every grounded finding
    /// reflect confirmed as a `ValidFinding`.
    ///
    /// Tying a verdict back to an input finding is a two-hop join, because
    /// `LoadedValidFinding` only carries `spec_id`:
    /// `ValidFinding.spec_id` → `specification.finding_id` → the finding's
    /// `link_id` (each grounded finding got a 1:1:1 triple in [`build_ingest`],
    /// so `link_id == finding_id`). One finding may own several specs, and one
    /// spec several confirming reflections, hence the per-finding id list.
    async fn mark_reproduced_findings(
        &self,
        repo: &RepoDatabase,
        outcomes: &mut [FindingOutcome],
    ) -> Result<()> {
        // spec_id → finding_id, over the spec rows produced this run.
        let finding_of_spec: BTreeMap<i32, i32> = repo
            .load_specifications()
            .await?
            .into_iter()
            .map(|s| (s.id, s.finding_id))
            .collect();

        // finding_id → confirming reflection ids.
        let mut reflections_of_finding: BTreeMap<i32, Vec<i32>> = BTreeMap::new();
        for valid in repo.load_valid_findings().await? {
            if let Some(&finding_id) = finding_of_spec.get(&valid.spec_id) {
                reflections_of_finding
                    .entry(finding_id)
                    .or_default()
                    .push(valid.reflection_id);
            }
        }

        for outcome in outcomes.iter_mut() {
            if let Some(reflection_ids) = outcome
                .link_id
                .and_then(|id| reflections_of_finding.get(&id))
            {
                outcome.reproduced = true;
                outcome.valid_reflection_ids = reflection_ids.clone();
                outcome.reviews = repo
                    .load_finding_reviews_by_reflection_ids(reflection_ids)
                    .await?;
            }
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Input schema (knowdit's own — external Phase-3 JSON is converted to this by
// the caller). Kept minimal: a target location to ground against + the reported
// vulnerability details to reproduce.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ExternalFindingsFile {
    pub findings: Vec<ExternalFinding>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ExternalFinding {
    /// Optional target contract name. When omitted, the whole project's call
    /// graph is used as the validation anchor.
    #[serde(default)]
    pub contract: Option<String>,
    /// Optional target function within the contract. When present it's grounded
    /// too (and becomes the sole anchor); when absent, all of the contract's
    /// functions are offered as anchors.
    #[serde(default)]
    pub function: Option<String>,
    pub title: String,
    #[serde(default)]
    pub root_cause: String,
    pub description: String,
    #[serde(default = "default_severity")]
    pub severity: FindingSeverity,
    #[serde(default)]
    pub patterns: String,
    #[serde(default)]
    pub exploits: String,
    /// DeFi category for the synthesized semantic (default `Services`).
    #[serde(default)]
    pub category: Option<DeFiCategory>,
    /// Opaque external identifier, surfaced verbatim in the validation report.
    #[serde(default)]
    pub id: Option<String>,
}

fn default_severity() -> FindingSeverity {
    FindingSeverity::Medium
}

// ---------------------------------------------------------------------------
// Grounding + ingest: JSON → the exact tables `map-semantics` writes.
// ---------------------------------------------------------------------------

/// Anchorable view of one contract, derived from the call graph. Kept as a
/// plain map (not the full `CallGraph`) so [`build_ingest`] is unit-testable
/// without constructing a call graph.
struct ContractAnchor {
    functions: Vec<ExtractedFunction>,
}

struct GroundingIndex {
    /// Lower-cased contract name → its anchorable functions.
    contracts: BTreeMap<String, ContractAnchor>,
}

impl GroundingIndex {
    fn from_call_graph(call_graph: &CallGraph) -> Self {
        let mut contracts = BTreeMap::new();
        for contract in call_graph.contracts.values() {
            let file_path = contract.relative_file_path.display().to_string();
            let functions = contract
                .functions
                .iter()
                .map(|f| ExtractedFunction {
                    name: f.name.clone(),
                    contract: file_path.clone(),
                    signature: None,
                })
                .collect();
            contracts.insert(contract.name.to_lowercase(), ContractAnchor { functions });
        }
        Self { contracts }
    }

    /// Resolve a finding's `(contract, function?)` target to its anchors, or a
    /// human-readable reason it can't be grounded (→ the finding is skipped).
    fn ground(
        &self,
        contract: Option<&str>,
        function: Option<&str>,
    ) -> Result<Vec<ExtractedFunction>, String> {
        match contract {
            Some(contract) => {
                let anchor = self
                    .contracts
                    .get(&contract.to_lowercase())
                    .ok_or_else(|| {
                        format!("contract `{contract}` not found in project call graph")
                    })?;
                match function {
                    Some(func) => anchor
                        .functions
                        .iter()
                        .find(|f| f.name.eq_ignore_ascii_case(func))
                        .cloned()
                        .map(|f| vec![f])
                        .ok_or_else(|| {
                            format!("function `{func}` not found in contract `{contract}`")
                        }),
                    None if anchor.functions.is_empty() => Err(format!(
                        "contract `{contract}` has no functions to anchor on"
                    )),
                    None => Ok(anchor.functions.clone()),
                }
            }
            None => {
                let anchors: Vec<_> = self
                    .contracts
                    .values()
                    .flat_map(|anchor| anchor.functions.iter())
                    .filter(|anchor| {
                        function
                            .map(|func| anchor.name.eq_ignore_ascii_case(func))
                            .unwrap_or(true)
                    })
                    .cloned()
                    .collect();
                if anchors.is_empty() {
                    match function {
                        Some(func) => {
                            Err(format!("function `{func}` not found in project call graph"))
                        }
                        None => Err("project call graph has no functions to anchor on".to_string()),
                    }
                } else {
                    Ok(anchors)
                }
            }
        }
    }
}

/// Per-finding ingest outcome, surfaced in the validation report so skipped
/// findings aren't silent.
#[derive(Debug, Clone, Serialize)]
pub struct FindingOutcome {
    /// 0-based position in the input file.
    pub index: usize,
    pub external_id: Option<String>,
    pub contract: Option<String>,
    pub function: Option<String>,
    pub title: String,
    pub grounded: bool,
    pub skip_reason: Option<String>,
    /// `(extract_id, historical_id, finding_id)` once grounded (all equal — one
    /// 1:1:1 triple per finding). `None` for skipped findings.
    pub link_id: Option<i32>,
    /// Whether reflect confirmed a `ValidFinding` for this finding — i.e. the
    /// reported issue reproduced. Filled after the pipeline runs; always `false`
    /// for skipped findings.
    pub reproduced: bool,
    /// `reflection.id`s of the confirming `ValidFinding` reflections, if any.
    pub valid_reflection_ids: Vec<i32>,
    /// Structured post-validation reviews for the confirming reflections.
    /// Empty when the finding was not reproduced or review did not complete.
    pub reviews: Vec<ReviewedFinding>,
}

/// Result of mapping the input file to mapper-output rows.
struct Ingested {
    extracts: Vec<ExtractedSemantic>,
    match_set: SemanticMatchSet,
    outcomes: Vec<FindingOutcome>,
}

/// Map external findings → `(ExtractedSemantic, historical shell, finding,
/// match)` rows. Each grounded finding becomes one independent 1:1:1 triple
/// whose ids are positional among grounded findings (matching
/// `replace_project_semantics`' `index + 1` id assignment). Pure over
/// [`GroundingIndex`] so it's unit-testable.
fn build_ingest(findings: &[ExternalFinding], index: &GroundingIndex) -> Ingested {
    let mut extracts = Vec::new();
    let mut historicals = Vec::new();
    let mut matches = Vec::new();
    let mut outcomes = Vec::new();

    for (i, f) in findings.iter().enumerate() {
        let anchors = match index.ground(f.contract.as_deref(), f.function.as_deref()) {
            Ok(anchors) => anchors,
            Err(reason) => {
                outcomes.push(FindingOutcome {
                    index: i,
                    external_id: f.id.clone(),
                    contract: f.contract.clone(),
                    function: f.function.clone(),
                    title: f.title.clone(),
                    grounded: false,
                    skip_reason: Some(reason),
                    link_id: None,
                    reproduced: false,
                    valid_reflection_ids: Vec::new(),
                    reviews: Vec::new(),
                });
                continue;
            }
        };

        // Positional id among grounded findings == `replace_project_semantics`
        // assigns `index + 1`; reuse it for the (separate-table) historical +
        // finding rows so the whole triple shares one id.
        let id = (extracts.len() + 1) as i32;
        let category = f.category.unwrap_or(DeFiCategory::Services);
        let contract_name = f.contract.as_deref().unwrap_or("<project>");
        let function_clause = f
            .function
            .as_deref()
            .map(|fun| format!(", function `{fun}`"))
            .unwrap_or_default();

        extracts.push(ExtractedSemantic {
            name: contract_name.to_string(),
            category,
            definition: format!(
                "External validation target: reported finding `{}` in contract `{}`{}.",
                f.title, contract_name, function_clause
            ),
            description: f.description.clone(),
            functions: anchors,
        });

        historicals.push(HistoricalSemanticRecord {
            semantic: semantic_node::Model {
                id,
                name: f.title.clone(),
                definition: if f.root_cause.trim().is_empty() {
                    f.title.clone()
                } else {
                    f.root_cause.clone()
                },
                description: f.description.clone(),
                category,
            },
            findings: vec![HistoricalLinkedFinding {
                finding: audit_finding::Model {
                    id,
                    title: f.title.clone(),
                    severity: f.severity,
                    root_cause: f.root_cause.clone(),
                    description: f.description.clone(),
                    patterns: f.patterns.clone(),
                    exploits: f.exploits.clone(),
                },
                strength: LinkStrength::High,
                evidence: "external validation target".to_string(),
                raw_children: Vec::new(),
                rendered_description: String::new(),
                rendered_patterns: String::new(),
                rendered_exploits: String::new(),
            }],
            raw_children: Vec::new(),
            rendered_description: String::new(),
        });

        matches.push(SemanticMatch {
            extract_id: id,
            historical_id: id,
            strength: MatchStrength::High,
            evidence: "external validation target".to_string(),
        });

        outcomes.push(FindingOutcome {
            index: i,
            external_id: f.id.clone(),
            contract: f.contract.clone(),
            function: f.function.clone(),
            title: f.title.clone(),
            grounded: true,
            skip_reason: None,
            link_id: Some(id),
            reproduced: false,
            valid_reflection_ids: Vec::new(),
            reviews: Vec::new(),
        });
    }

    Ingested {
        extracts,
        match_set: SemanticMatchSet {
            historicals,
            matches,
        },
        outcomes,
    }
}

/// On-disk `<output_folder>/validation_report.json`: every input finding with
/// its grounding outcome + reproduction verdict (so neither skipped targets nor
/// non-reproducing findings are silent).
#[derive(Debug, Serialize)]
struct ValidationReport {
    total_findings: usize,
    grounded: usize,
    skipped: usize,
    /// Grounded findings reflect confirmed as `ValidFinding`.
    reproduced: usize,
    findings: Vec<FindingOutcome>,
}

impl ValidationReport {
    fn from_outcomes(outcomes: Vec<FindingOutcome>) -> Self {
        let grounded = outcomes.iter().filter(|o| o.grounded).count();
        let reproduced = outcomes.iter().filter(|o| o.reproduced).count();
        Self {
            total_findings: outcomes.len(),
            grounded,
            skipped: outcomes.len() - grounded,
            reproduced,
            findings: outcomes,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn index_with(contracts: &[(&str, &[&str])]) -> GroundingIndex {
        let mut map = BTreeMap::new();
        for (name, funcs) in contracts {
            let functions = funcs
                .iter()
                .map(|f| ExtractedFunction {
                    name: f.to_string(),
                    contract: format!("src/{name}.sol"),
                    signature: None,
                })
                .collect();
            map.insert(name.to_lowercase(), ContractAnchor { functions });
        }
        GroundingIndex { contracts: map }
    }

    fn finding(contract: &str, function: Option<&str>, title: &str) -> ExternalFinding {
        ExternalFinding {
            contract: Some(contract.to_string()),
            function: function.map(str::to_string),
            title: title.to_string(),
            root_cause: String::new(),
            description: "desc".to_string(),
            severity: FindingSeverity::Medium,
            patterns: String::new(),
            exploits: String::new(),
            category: None,
            id: None,
        }
    }

    #[test]
    fn grounded_findings_become_positional_triples_and_misses_are_skipped() {
        let index = index_with(&[("Vault", &["deposit", "withdraw"])]);
        let findings = vec![
            finding("Vault", Some("deposit"), "reentrancy"),
            finding("Ghost", None, "missing contract"),
            finding("Vault", None, "whole-contract"),
        ];
        let out = build_ingest(&findings, &index);

        // Two grounded → ids 1 and 2; one skipped.
        assert_eq!(out.extracts.len(), 2);
        assert_eq!(out.match_set.matches.len(), 2);
        assert_eq!(out.match_set.historicals.len(), 2);
        assert_eq!(
            out.match_set
                .matches
                .iter()
                .map(|m| m.extract_id)
                .collect::<Vec<_>>(),
            vec![1, 2],
        );
        assert_eq!(out.match_set.matches[0].historical_id, 1);

        // Targeted function → single anchor; no function → all contract funcs.
        assert_eq!(out.extracts[0].functions.len(), 1);
        assert_eq!(out.extracts[0].functions[0].name, "deposit");
        assert_eq!(out.extracts[1].functions.len(), 2);

        // Outcomes cover all three in input order; the miss is recorded.
        assert_eq!(out.outcomes.len(), 3);
        assert!(out.outcomes[0].grounded && out.outcomes[0].link_id == Some(1));
        assert!(!out.outcomes[1].grounded);
        assert!(
            out.outcomes[1]
                .skip_reason
                .as_deref()
                .unwrap()
                .contains("Ghost")
        );
        assert!(out.outcomes[2].grounded && out.outcomes[2].link_id == Some(2));
    }

    #[test]
    fn unknown_function_on_known_contract_is_skipped() {
        let index = index_with(&[("Vault", &["deposit"])]);
        let out = build_ingest(&[finding("Vault", Some("nope"), "t")], &index);
        assert_eq!(out.extracts.len(), 0);
        assert!(!out.outcomes[0].grounded);
        assert!(
            out.outcomes[0]
                .skip_reason
                .as_deref()
                .unwrap()
                .contains("nope")
        );
    }

    #[test]
    fn missing_contract_anchors_against_the_whole_project() {
        let index = index_with(&[("Vault", &["deposit", "withdraw"]), ("Router", &["swap"])]);
        let mut target = finding("unused", None, "project-wide");
        target.contract = None;
        let out = build_ingest(&[target], &index);
        assert_eq!(out.extracts.len(), 1);
        assert_eq!(out.extracts[0].name, "<project>");
        assert_eq!(out.extracts[0].functions.len(), 3);
        assert!(out.outcomes[0].grounded);
        assert_eq!(out.outcomes[0].contract, None);
    }
}
