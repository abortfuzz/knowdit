//! Project profile generation agent (Phase A of the v2 mapper plan).
//!
//! Produces a [`ProjectProfile`] from the project's source / docs and
//! persists it into the per-project DB under `project_metadata` row
//! `key = "profile"`. Downstream the Knowledge Mapper reads this back
//! and injects it into its system prompt to ground per-pair strength
//! judgements in actual project context.
//!
//! Data flow (single struct + member fns per §1.1):
//!
//! 1. Caller constructs [`ProjectProfileGenerator::new`] with
//!    [`ProfileOptions`] (cache key / budget knobs / regenerate flag).
//! 2. [`ProjectProfileGenerator::run`] takes `repo`, `llm`,
//!    `repo_root` as method arguments (no `&self` reference fields →
//!    no `<'a>` per §1.6).
//! 3. Resume: if `repo.get_project_profile()` is already `Some` and
//!    `regenerate == false`, short-circuit and return the cached
//!    profile (plan §1.5 "断点续跑").
//! 4. Otherwise build a `ToolBox` with three llmy-agent-tools file
//!    tools (`read_file`, `list_dir`, `find_file`) rooted at
//!    `repo_root` plus one local `finalize_profile` sink, drive a
//!    plain `Agent` step loop up to `max_agent_steps`, persist the
//!    captured profile via `repo.set_project_profile()` in a single
//!    atomic write.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use color_eyre::eyre::{Result, WrapErr, eyre};
use knowdit_repo_model::{ProjectComponent, ProjectProfile, ProjectSubsystem, RepoDatabase};
use llmy::agent::StepResult;
use llmy::agent::tool::ToolBox;
use llmy::agent::tools::files::{FindFileTool, ListDirectoryTool, ReadFileTool};
use llmy::client::client::LLM;
use llmy::client::settings::LLMSettings;
use llmy::harness::Agent;
use schemars::JsonSchema;
use serde::Deserialize;
use tokio::sync::Mutex;

/// Tunables for one profile-gen pass. Owned, no lifetime params; all
/// knobs come from clap-derive in the CLI layer per §1.2.
#[derive(Debug, Clone)]
pub struct ProfileOptions {
    /// `llmy` cache key prefix for this run.
    pub cache_key: String,
    /// Optional debug-prefix passed to llmy for request dumps.
    pub debug_prefix: Option<String>,
    /// Optional per-call llmy settings.
    pub llm_settings: Option<LLMSettings>,
    /// Maximum agent steps before forced finalize.
    pub max_agent_steps: usize,
    /// Soft cap surfaced in the prompt to tell the agent how many
    /// `read_file` invocations it should budget. Not enforced by the
    /// tool layer (we let llmy file tools count themselves) — this
    /// is just calibration text.
    pub max_files_read: usize,
    /// When `true`, ignore an existing `project_metadata` profile row
    /// and regenerate from scratch. When `false` (default), the
    /// generator short-circuits if a profile is already in the DB.
    pub regenerate: bool,
}

/// Project profile generator agent.
///
/// `repo` / `llm` are passed as method arguments to [`Self::run`], not
/// held as struct fields, so this type has **no** lifetime parameter
/// (plan §1.6).
#[derive(Debug, Clone)]
pub struct ProjectProfileGenerator {
    options: ProfileOptions,
}

impl ProjectProfileGenerator {
    pub fn new(options: ProfileOptions) -> Self {
        Self { options }
    }

    pub fn options(&self) -> &ProfileOptions {
        &self.options
    }

    /// Drive one profile-gen pass against `repo` + `llm`, with the
    /// project tree rooted at `repo_root`. Returns the final
    /// `ProjectProfile` (also persisted to the DB on success).
    pub async fn run(
        &self,
        repo: &RepoDatabase,
        llm: &LLM,
        repo_root: &Path,
    ) -> Result<ProjectProfile> {
        if !self.options.regenerate
            && let Some(existing) = repo
                .get_project_profile()
                .await
                .wrap_err("profile-gen: failed to query existing project_profile row")?
        {
            tracing::info!(
                "ProjectProfileGenerator: reusing existing profile ({} subsystems, {} components)",
                existing.subsystems.len(),
                existing.core_components.len()
            );
            return Ok(existing);
        }

        let attempt = ProfileAttemptHandle::new();
        let tools = build_profile_toolbox(repo_root.to_path_buf(), attempt.clone());

        let max_files_read = self.options.max_files_read.max(1);
        let system_prompt = build_system_prompt(max_files_read);
        let user_prompt = format!(
            "Profile the project rooted at this repository. The list_dir / find_file / read_file tools \
             are constrained to the project tree; relative paths are resolved against the project \
             root. Call finalize_profile exactly once when you have enough context. Aim for at most \
             {max_files_read} read_file invocations."
        );

        let cache_key = self.options.cache_key.clone();
        let debug_prefix = self.options.debug_prefix.clone();
        let mut agent = Agent::new(system_prompt, tools, cache_key);

        let mut step = agent
            .step_with_user(
                user_prompt,
                llm,
                debug_prefix.as_deref(),
                self.options.llm_settings.clone(),
            )
            .await
            .wrap_err("profile-gen: failed on initial agent step")?;
        let mut steps = 1usize;

        while !attempt.is_set().await {
            if matches!(step, StepResult::Stop(_)) {
                return Err(eyre!(
                    "profile-gen: agent stopped at step {steps} without calling finalize_profile"
                ));
            }
            if steps >= self.options.max_agent_steps {
                return Err(eyre!(
                    "profile-gen: agent exhausted max_agent_steps={} without calling finalize_profile; \
                     raise --profile-max-agent-steps and retry",
                    self.options.max_agent_steps,
                ));
            }
            steps += 1;
            step = agent
                .step(
                    llm,
                    debug_prefix.as_deref(),
                    self.options.llm_settings.clone(),
                )
                .await
                .wrap_err_with(|| format!("profile-gen: agent failed at step {steps}"))?;
        }

        let profile = attempt
            .take()
            .await
            .expect("profile attempt set but inner None");

        repo.set_project_profile(&profile)
            .await
            .wrap_err("profile-gen: failed to persist ProjectProfile via set_project_profile")?;

        tracing::info!(
            "ProjectProfileGenerator finished: {} subsystem(s), {} core component(s), {} step(s)",
            profile.subsystems.len(),
            profile.core_components.len(),
            steps,
        );
        Ok(profile)
    }
}

fn build_profile_toolbox(repo_root: PathBuf, attempt: ProfileAttemptHandle) -> ToolBox {
    let mut tools = ToolBox::new();
    tools.add_tool(ReadFileTool::new(repo_root.clone()));
    tools.add_tool(ListDirectoryTool::new_root(repo_root.clone()));
    tools.add_tool(FindFileTool::new(repo_root));
    tools.add_tool(FinalizeProfileTool { attempt });
    tools
}

// ---------------------------------------------------------------------------
// finalize_profile tool + attempt handle
// ---------------------------------------------------------------------------

/// Typed shared slot for the agent's final profile. Same pattern as
/// `crate::reflect::agent_loop::AttemptHandle` but local to profile-gen
/// so we don't pull the reflect agent's other infrastructure.
#[derive(Debug, Default)]
pub struct ProfileAttemptHandle {
    inner: Arc<Mutex<Option<ProjectProfile>>>,
}

impl Clone for ProfileAttemptHandle {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

impl ProfileAttemptHandle {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(None)),
        }
    }

    pub async fn is_set(&self) -> bool {
        self.inner.lock().await.is_some()
    }

    pub async fn try_set(&self, value: ProjectProfile) -> std::result::Result<(), &'static str> {
        let mut g = self.inner.lock().await;
        if g.is_some() {
            return Err("already set");
        }
        *g = Some(value);
        Ok(())
    }

    pub async fn take(&self) -> Option<ProjectProfile> {
        self.inner.lock().await.take()
    }
}

#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct FinalizeProfileArgs {
    /// 100-300 word prose describing what the project IS — the
    /// mechanism it uses, what role it plays. No marketing language.
    pub domain_summary: String,
    /// 3-8 free-form short tags with mechanism summaries. There is no
    /// canonical vocabulary; downstream mapper matches on `summary`
    /// text, not on `name`.
    pub subsystems: Vec<FinalizeSubsystem>,
    /// 3-12 main in-scope contracts: name + path + one-sentence role.
    pub core_components: Vec<FinalizeComponent>,
    /// Free prose listing subdomains the project explicitly does NOT
    /// have. Used by mapper to confidently emit Low when a historical
    /// targets an absent subsystem.
    pub out_of_scope_notes: String,
    /// Files actually opened via `read_file` in this run.
    pub source_files_read: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct FinalizeSubsystem {
    pub name: String,
    pub summary: String,
}

#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct FinalizeComponent {
    pub name: String,
    pub path: String,
    pub role: String,
}

impl From<FinalizeProfileArgs> for ProjectProfile {
    fn from(value: FinalizeProfileArgs) -> Self {
        Self {
            domain_summary: value.domain_summary,
            subsystems: value
                .subsystems
                .into_iter()
                .map(|s| ProjectSubsystem {
                    name: s.name,
                    summary: s.summary,
                })
                .collect(),
            core_components: value
                .core_components
                .into_iter()
                .map(|c| ProjectComponent {
                    name: c.name,
                    path: c.path,
                    role: c.role,
                })
                .collect(),
            out_of_scope_notes: value.out_of_scope_notes,
            source_files_read: value.source_files_read,
        }
    }
}

#[derive(Debug, Clone)]
#[llmy::agent::tool(
    arguments = FinalizeProfileArgs,
    invoke = invoke,
    description = "Commit the final ProjectProfile and end the agent run. Call EXACTLY once after \
                   you have read enough docs/source to fill every field. The mapper downstream \
                   reads `summary` text and `out_of_scope_notes` to judge each historical \
                   semantic's relevance to this project — populate them with concrete mechanism \
                   descriptions, not marketing language.",
    name = "finalize_profile",
)]
struct FinalizeProfileTool {
    attempt: ProfileAttemptHandle,
}

impl FinalizeProfileTool {
    async fn invoke(
        &self,
        args: FinalizeProfileArgs,
    ) -> std::result::Result<String, llmy::agent::LLMYError> {
        if args.domain_summary.trim().is_empty() {
            return Ok("error: domain_summary must be non-empty".to_string());
        }
        if args.subsystems.is_empty() {
            return Ok("error: subsystems must contain at least one entry".to_string());
        }
        if args.core_components.is_empty() {
            return Ok("error: core_components must contain at least one entry".to_string());
        }
        match self.attempt.try_set(args.into()).await {
            Ok(()) => Ok("ok: profile committed; finish the run".to_string()),
            Err(_) => Ok(
                "error: finalize_profile was already called this run; do not call it twice"
                    .to_string(),
            ),
        }
    }
}

// ---------------------------------------------------------------------------
// System prompt
// ---------------------------------------------------------------------------

fn build_system_prompt(max_files_read: usize) -> String {
    format!(
        r#"You are profiling a smart-contract project to give downstream auditing agents enough
context to know what this project IS and ISN'T.

Workflow:
  1. Use list_dir at the project root to see top-level layout. Common doc locations to probe
     with list_dir / find_file:
       README*, scope.txt, scope.md, docs/, audit/
     Common contract locations:
       src/, contracts/
  2. Use read_file to read the most informative docs (README first, then scope, then audit
     notes if present). Cap your reads at {max_files_read}.
  3. If docs are absent or unhelpful, fall back to list_dir on src/ (or contracts/) +
     read_file on 2-3 of the main contract files for shape inference.
  4. Call finalize_profile exactly once with a complete profile.

Tool reference (all relative paths are resolved against the project root):
  - list_dir(relative_path)         — list direct child entries
  - find_file(directory, file_name_pattern) — recursive find under directory
  - read_file(file_path, offset?, limit?)   — read file contents
  - finalize_profile({{...fields}})  — sink; call exactly once

Rules for each field:

  - domain_summary (~200 words): what this project IS, what role it plays in DeFi/wallet/infra
    space, who the user is. Be concrete. Avoid marketing language ("the leading X protocol") —
    say what mechanism it uses.

  - subsystems (3-8 entries): the main mechanisms / subsystems this project implements.
    Each entry is {{name, summary}}:
      name:    short free-form label you choose (no canonical vocabulary required), e.g.
               "timelock execution", "calldata whitelist", "pause guardian role"
      summary: one-sentence description of what the subsystem does, written so a reader who
               hasn't seen this project can match it against arbitrary other descriptions.
    Downstream mapper compares your `summary` text against historical semantic descriptions; it
    does NOT do string matching on `name`. So make summaries explicit about MECHANISM, not just
    label.
      Good summary: "schedule/execute pattern where any address with PROPOSER_ROLE queues an
                     operation, anyone with EXECUTOR_ROLE can run it after the delay"
      Bad summary:  "handles timelock stuff"

  - core_components (3-12 entries): main contracts in scope. Each entry:
      {{name: ContractName, path: src/..., role: "1-sentence purpose"}}
    Used by mapper to point at "where in the project this mechanism lives" when justifying a
    High match.

  - out_of_scope_notes: subdomains the project explicitly does NOT touch, written as free prose
    (NOT a list). This is often more useful than the scope itself for downstream matching.
    Examples:
      "no lending market, no borrow/supply accounting; no AMM or LP positions; no reward
       distribution or yield emissions"
    If you cannot identify any out-of-scope notes, write
      "out-of-scope notes not derivable from project docs"
    — do not invent.

  - source_files_read: list every file path you actually opened via read_file in this run.

Defaults / anti-patterns:
  - If a doc is autogenerated boilerplate (e.g. default Foundry README), note that and rely on
    contract reading.
  - Don't pad fields. Minimum entries are acceptable if truly nothing more applies.
  - Don't speculate on bugs / vulnerabilities. This is project FRAMING, not audit content.
  - Do not invent canonical jargon for subsystem names. Use whatever label fits the project's
    own code/docs. The mechanism in `summary` is what carries the signal."#,
        max_files_read = max_files_read,
    )
}
