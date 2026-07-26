//! `agentic profile` subcommand: generate / refresh a per-project
//! [`ProjectProfile`] used by the Knowledge Mapper to ground per-pair
//! strength judgments.
//!
//! Resume-safe: the in-process entry [`ProfileArgs::profile`] checks
//! `repo.get_project_profile()` first and returns the existing profile
//! unless `--profile-regenerate` is set. The autoloop wraps the same
//! entry so it short-circuits when a profile is already cached.
use clap::Args;
use color_eyre::eyre::Result;
use knowdit_audit::profile::{ProfileOptions, ProjectProfileGenerator};
use knowdit_kg::text::truncate_text;
use knowdit_repo_model::{ProjectProfile, RepoDatabase};
use llmy::client::client::LLM;
use std::path::Path;

use crate::cli::{DatabaseArgs, LoadedRepoDatabase, ProjectArgs};

/// Tunables for the profile-gen phase. Same `<Phase>SharedArgs`
/// flatten pattern as `HarnessSharedArgs` / `MapSemanticsSharedArgs`,
/// so this struct is shared by both `agentic profile` (standalone)
/// and `workflow autoloop` (in-process).
#[derive(Args, Clone, Debug)]
pub struct ProfileSharedArgs {
    /// `llmy` cache key prefix. Defaults to
    /// `{project_name}-knowdit-profile` when omitted so different
    /// projects don't share a server-side prompt-cache namespace.
    #[arg(long = "profile-cache-key")]
    pub profile_cache_key: Option<String>,

    /// Debug-prefix forwarded to llmy for LLM-call dumps.
    #[arg(long = "profile-debug-prefix")]
    pub profile_debug_prefix: Option<String>,

    /// Maximum agent steps per profile-gen pass before forced finalize.
    /// Bumped from 12 to 20 to give the agent breathing room when
    /// `--profile-max-files-read=24` (default) prompts it to read
    /// more docs/source files.
    #[arg(long = "profile-max-agent-steps", default_value_t = 20)]
    pub profile_max_agent_steps: usize,

    /// Soft cap (surfaced in the system prompt) on how many
    /// `read_file` invocations the profile agent should make. Not a
    /// hard limit — the agent decides.
    #[arg(long = "profile-max-files-read", default_value_t = 24)]
    pub profile_max_files_read: usize,

    /// Regenerate from scratch even when a profile is already cached
    /// in the project DB.
    #[arg(long = "profile-regenerate", default_value_t = false)]
    pub profile_regenerate: bool,
}

#[derive(Args)]
pub struct ProfileArgs {
    #[command(flatten)]
    pub project: ProjectArgs,

    #[command(flatten)]
    pub db: DatabaseArgs,

    #[command(flatten)]
    pub shared: ProfileSharedArgs,
}

impl ProfileArgs {
    /// CLI entry. Opens the repo DB, runs the profile-gen agent,
    /// prints a one-line summary.
    pub async fn run(self, llm: &LLM) -> Result<()> {
        // Profile is the discoverer of project language — no
        // pre-load detection or prefix dispatch needed here.
        // The agent reads the source itself and commits a
        // `language` value via `finalize_profile`.
        let LoadedRepoDatabase { spec, repo, .. } = self
            .project
            .to_repo_database(self.db.database_path.clone(), self.db.variant_render_cap)
            .await?;
        let profile = Self::profile(&repo, llm, &spec.name, &spec.root, &self.shared).await?;
        println!(
            "Profile ready: {} subsystem(s), {} core component(s), {} source file(s) read; out_of_scope: {}",
            profile.subsystems.len(),
            profile.core_components.len(),
            profile.source_files_read.len(),
            truncate_text(&profile.out_of_scope_notes, 80)
        );
        Ok(())
    }

    /// In-process entry: returns the `ProjectProfile` for this repo
    /// DB, generating + persisting it on first call. Used both by the
    /// standalone CLI and by `workflow autoloop`'s profile phase.
    pub async fn profile(
        repo: &RepoDatabase,
        llm: &LLM,
        project_name: &str,
        repo_root: &Path,
        shared: &ProfileSharedArgs,
    ) -> Result<ProjectProfile> {
        let cache_key = shared
            .profile_cache_key
            .clone()
            .unwrap_or_else(|| format!("{}-knowdit-profile", project_name));
        let options = ProfileOptions {
            cache_key,
            debug_prefix: shared.profile_debug_prefix.clone(),
            llm_settings: None,
            max_agent_steps: shared.profile_max_agent_steps,
            max_files_read: shared.profile_max_files_read,
            regenerate: shared.profile_regenerate,
        };
        ProjectProfileGenerator::new(options)
            .run(repo, llm, repo_root)
            .await
    }
}
