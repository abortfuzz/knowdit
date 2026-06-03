//! `forge` invocation backends.
//!
//! Three flavors, picked once at startup and held by every per-spec
//! `RunForgeTool`:
//!
//!   1. [`ForgeBackend::LocalDirect`] — spawn the host's `forge` binary,
//!      no memory cap.
//!   2. [`ForgeBackend::LocalCgroup`] — spawn the host's `forge` inside
//!      a fresh cgroup v2 child of our delegated user.slice ancestor,
//!      with `memory.max` enforcing a per-invocation ceiling. Linux only.
//!   3. [`ForgeBackend::Docker`] — spawn `docker run --rm
//!      --memory=<N> --memory-swap=<N> -v <repo>:<repo> -w <repo>
//!      --entrypoint forge <image> <args...>`. Linux only.
//!
//! Per-invocation cleanup goes through [`ForgeHandle`] whose `Drop` does
//! the right thing for the variant — most importantly an explicit
//! `docker kill --signal=KILL <name>` for the Docker case, since
//! SIGKILL'ing the docker CLI client doesn't reliably propagate to the
//! daemon-managed container.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

/// Monotonically increasing process-local counter, used to uniquify
/// concurrent preflight directories (`_knowdit_preflight_{pid}_{nanos}_{ctr}`)
/// so two preflights in the same nanosecond bucket still get distinct
/// dirs. `Ordering::Relaxed` is fine — we only need uniqueness, not
/// ordering between writes.
static PREFLIGHT_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Last `max_bytes` of `s`, snapped to a UTF-8 boundary. Used for
/// embedding forge output tails in error messages without risking
/// a `str` slice panic on multi-byte boundaries.
fn tail_utf8(s: &str, max_bytes: usize) -> &str {
    if s.len() <= max_bytes {
        return s;
    }
    let mut start = s.len() - max_bytes;
    while start < s.len() && !s.is_char_boundary(start) {
        start += 1;
    }
    &s[start..]
}

use color_eyre::eyre::{Result, WrapErr, eyre};
use tokio::process::Command;

#[cfg(target_os = "linux")]
use super::cgroup::ScopedCgroup;

/// One forge invocation backend = how to spawn `forge <args>`. The
/// outer [`ForgeBackend`] owns this plus a probed [`ForgeFeatures`]
/// table so callers can branch on optional flags (currently:
/// `forge coverage --force-via-ir`) without re-running probes.
#[derive(Debug, Clone)]
pub enum ForgeBackendKind {
    LocalDirect {
        binary: PathBuf,
    },
    #[cfg(target_os = "linux")]
    LocalCgroup {
        binary: PathBuf,
        /// Path relative to `/sys/fs/cgroup` (the value returned by
        /// [`ScopedCgroup::probe_parent`]).
        cgroup_parent: String,
        mem_max_bytes: u64,
    },
    #[cfg(target_os = "linux")]
    Docker {
        image: String,
        mem_max_bytes: u64,
    },
}

/// Capability set probed at backend construction. Lets callers
/// (e.g. the per-spec `RunForgeTool`) opt into newer forge flags
/// without re-asking each invocation.
#[derive(Debug, Clone, Default)]
pub struct ForgeFeatures {
    /// Whether the probed `forge coverage` accepts the
    /// `--force-via-ir` flag. Required to compile via-IR-only
    /// projects under coverage (forge coverage historically refused
    /// viaIR for source-map fidelity reasons; the flag opts back in
    /// at the cost of some line-mapping accuracy).
    pub coverage_force_via_ir: bool,
}

/// Forge invocation runtime. Combines the chosen spawn strategy
/// (`kind`) with the capability set we probed at construction time
/// (`features`). Constructed once per fuzz pass; cloned into each
/// per-spec [`ForgeRunner`].
#[derive(Debug, Clone)]
pub struct ForgeBackend {
    pub kind: ForgeBackendKind,
    pub features: ForgeFeatures,
}

impl ForgeBackend {
    /// Resolve a usable `forge` runtime and probe its feature flags.
    /// Used as the single source of truth for both preflight checks
    /// (callers discard the result) and for the fuzz pass itself
    /// (callers pass the value into [`ForgeRunner::new`]).
    ///
    /// Resolution order for the runtime:
    ///
    /// 1. **`forge_bin = Some(path)`** → local mode against that
    ///    explicit binary. Cgroup wrapping kicks in when
    ///    `mem_cap_bytes` is set AND a writable cgroup v2 ancestor
    ///    with `memory` delegation exists; otherwise direct exec
    ///    with a `tracing::warn!`.
    /// 2. **`forge_bin = None`, Linux, docker runtime present**
    ///    → docker mode against `docker_image`. If the image is not
    ///    pulled yet, `docker run` will pull it on first invocation;
    ///    no preflight pull happens here.
    /// 3. **Fallback** → look up `forge` on `$PATH`. Picks the first
    ///    executable named `forge` in `$PATH` and treats it as a
    ///    user-supplied `--forge-bin`. Used on Linux when docker is
    ///    not installed, and on non-Linux OSes (which never had
    ///    docker support to begin with).
    /// 4. **None of the above** → hard error.
    pub fn new(
        forge_bin: Option<PathBuf>,
        docker_image: String,
        mem_cap_bytes: Option<u64>,
    ) -> Result<Self> {
        let kind = resolve_kind(forge_bin, docker_image, mem_cap_bytes)?;
        let features = probe_features(&kind);
        Ok(Self { kind, features })
    }
}

fn resolve_kind(
    forge_bin: Option<PathBuf>,
    docker_image: String,
    mem_cap_bytes: Option<u64>,
) -> Result<ForgeBackendKind> {
    if let Some(binary) = forge_bin {
        return local_kind(binary, mem_cap_bytes);
    }
    #[cfg(target_os = "linux")]
    {
        if docker_runtime_present() {
            let cap = mem_cap_bytes.unwrap_or(0);
            tracing::info!(
                "ForgeBackend: Docker image={docker_image} mem_max={} MB",
                cap / (1024 * 1024),
            );
            return Ok(ForgeBackendKind::Docker {
                image: docker_image,
                mem_max_bytes: cap,
            });
        }
        tracing::warn!("ForgeBackend: docker not available; falling back to `forge` in $PATH");
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = docker_image;
    }
    match find_forge_on_path() {
        Some(binary) => {
            tracing::info!(
                "ForgeBackend: resolved `forge` from $PATH at {}",
                binary.display()
            );
            local_kind(binary, mem_cap_bytes)
        }
        None => Err(eyre!(
            "no usable forge: --forge-bin unset, docker runtime not available, \
             and no `forge` executable in $PATH. Install foundryup, run `docker pull \
             lazymio/knowdit:foundry`, or pass `--forge-bin <path>`."
        )),
    }
}

fn local_kind(binary: PathBuf, mem_cap_bytes: Option<u64>) -> Result<ForgeBackendKind> {
    // `Command::new(relative).current_dir(work_dir)` resolves the
    // binary relative to `work_dir`, NOT the caller's cwd — so a
    // user-supplied `--forge-bin ../foundry/target/release/forge`
    // ends up looked up under the project root (e.g.
    // `out_git/foo/../foundry/...`) and silently fails to spawn.
    // Canonicalize up front so the spawn path is unambiguous, mirroring
    // the same trick `ForgeRunner::new` already does for `work_dir`.
    let binary = match std::fs::canonicalize(&binary) {
        Ok(p) => p,
        Err(err) => {
            return Err(eyre!(
                "--forge-bin {} cannot be canonicalized ({err:#}). \
                 Pass an existing path; relative paths are interpreted \
                 against your shell's cwd at the moment knowdit was launched.",
                binary.display()
            ));
        }
    };
    #[cfg(target_os = "linux")]
    {
        if let Some(cap) = mem_cap_bytes {
            if let Some(parent) = ScopedCgroup::probe_parent() {
                tracing::info!(
                    "ForgeBackend: LocalCgroup binary={} parent={parent} mem_max={} MB",
                    binary.display(),
                    cap / (1024 * 1024)
                );
                return Ok(ForgeBackendKind::LocalCgroup {
                    binary,
                    cgroup_parent: parent,
                    mem_max_bytes: cap,
                });
            }
            tracing::warn!(
                "ForgeBackend: --forge-mem-cap-gb requested but no usable cgroup v2 \
                 parent found; falling back to direct exec without a memory ceiling"
            );
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        if mem_cap_bytes.is_some() {
            tracing::warn!("ForgeBackend: --forge-mem-cap-gb is Linux-only; ignoring on this OS");
        }
    }
    tracing::info!("ForgeBackend: LocalDirect binary={}", binary.display());
    Ok(ForgeBackendKind::LocalDirect { binary })
}

/// Probe the resolved backend for optional `forge coverage` flags.
/// Currently we only care about `--force-via-ir`; if missing, callers
/// that want via-IR coverage must either upgrade their forge or
/// accept that coverage will not compile their project.
///
/// Probing runs `forge coverage --help` through the same backend the
/// fuzz pass would use (host binary direct, or
/// `docker run <image> forge coverage --help`), so a docker image
/// that lacks the flag is detected the same way as a stale host
/// binary.
fn probe_features(kind: &ForgeBackendKind) -> ForgeFeatures {
    let help = coverage_help_output(kind).unwrap_or_default();
    let coverage_force_via_ir = help.contains("--force-via-ir");
    if !coverage_force_via_ir {
        tracing::warn!(
            "ForgeBackend: `forge coverage` does not support `--force-via-ir` on this binary. \
             Coverage runs cannot use viaIR; via-IR-only projects may fail to compile under \
             `forge coverage`. Upgrade foundry or pull a newer `--forge-docker-image`."
        );
    } else {
        tracing::info!("ForgeBackend: `forge coverage --force-via-ir` supported");
    }
    ForgeFeatures {
        coverage_force_via_ir,
    }
}

/// Best-effort capture of `forge coverage --help`. Returns `None`
/// on any failure (probe is non-fatal — features default to off).
fn coverage_help_output(kind: &ForgeBackendKind) -> Option<String> {
    use std::process::{Command, Stdio};
    let mut cmd = match kind {
        ForgeBackendKind::LocalDirect { binary } => {
            let mut c = Command::new(binary);
            c.args(["coverage", "--help"]);
            c
        }
        #[cfg(target_os = "linux")]
        ForgeBackendKind::LocalCgroup { binary, .. } => {
            let mut c = Command::new(binary);
            c.args(["coverage", "--help"]);
            c
        }
        #[cfg(target_os = "linux")]
        ForgeBackendKind::Docker { image, .. } => {
            let mut c = Command::new("docker");
            c.args([
                "run",
                "--rm",
                "--network",
                "none",
                "--entrypoint",
                "/usr/local/bin/forge",
                image,
                "coverage",
                "--help",
            ]);
            c
        }
    };
    let out = cmd.stdin(Stdio::null()).output().ok()?;
    let mut combined = String::from_utf8_lossy(&out.stdout).into_owned();
    combined.push_str(&String::from_utf8_lossy(&out.stderr));
    Some(combined)
}

/// True iff `docker --version` exits successfully. Cheap; used by
/// [`ForgeBackend::resolve`] to decide between docker mode and the
/// `$PATH` forge fallback.
#[cfg(target_os = "linux")]
fn docker_runtime_present() -> bool {
    std::process::Command::new("docker")
        .arg("--version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// First executable named `forge` found by walking `$PATH`. Mirrors
/// what `Command::new("forge")` would resolve at exec time but
/// returns the concrete path so we can log it + (on Linux) take the
/// cgroup-wrapping branch.
fn find_forge_on_path() -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path) {
        let candidate = dir.join("forge");
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

/// Owns the chosen backend + per-invocation defaults. Splits forge
/// invocations into `Test` (yields counter-example + trace) and `Coverage`
/// (yields lcov rows).
#[derive(Debug, Clone)]
pub struct ForgeRunner {
    backend: ForgeBackend,
    /// Working directory — the directory that contains `foundry.toml`.
    /// Forge resolves remappings + sources from here. In docker mode it's
    /// also the bind-mount source AND target (we mount the same path on
    /// both sides so foundry.toml + remappings + error-message paths all
    /// match the host).
    work_dir: PathBuf,
    timeout: Duration,
    /// Optional override for the project's `test = '...'` foundry directive,
    /// passed through `FOUNDRY_TEST=<path>` so forge only walks one
    /// subdirectory and its dependency closure. Lets us isolate concurrent
    /// per-spec harnesses from each other's compile errors.
    test_dir_override: Option<PathBuf>,
}

impl ForgeRunner {
    pub fn new(backend: ForgeBackend, work_dir: PathBuf, timeout: Duration) -> Self {
        // Docker rejects relative `-v`/`-w` paths ("the working directory
        // '...' is invalid, it needs to be an absolute path"), and a
        // relative `work_dir` is brittle for the local backends too once
        // anything in the runtime changes its CWD. Resolve to an absolute
        // path up front: prefer canonicalize (drops `..`, resolves
        // symlinks) and fall back to `std::path::absolute` if the path
        // doesn't exist yet.
        let work_dir = match std::fs::canonicalize(&work_dir) {
            Ok(p) => p,
            Err(_) => match std::path::absolute(&work_dir) {
                Ok(p) => p,
                Err(err) => {
                    tracing::warn!(
                        "ForgeRunner: failed to make work_dir {} absolute ({err:#}); \
                         the docker backend will likely reject this",
                        work_dir.display(),
                    );
                    work_dir
                }
            },
        };
        Self {
            backend,
            work_dir,
            timeout,
            test_dir_override: None,
        }
    }

    /// Return a copy of `self` with `FOUNDRY_TEST` set to the given path
    /// for every forge invocation. Path may be absolute or relative to
    /// `work_dir`.
    pub fn with_test_dir(mut self, test_dir: PathBuf) -> Self {
        self.test_dir_override = Some(test_dir);
        self
    }

    /// The working directory forge runs in. Callers (notably the
    /// coverage-result reader) need this to find lcov.info on disk.
    pub fn work_dir(&self) -> &std::path::Path {
        &self.work_dir
    }

    /// Expose the probed feature set so per-spec tools can decide
    /// whether to pass optional flags like `--force-via-ir`.
    pub fn features(&self) -> &ForgeFeatures {
        &self.backend.features
    }

    /// Monotonic-ish nanosecond stamp for unique cgroup / container
    /// names. Wallclock-based; collisions only happen if two invocations
    /// land in the same nanosecond on the same `pid`, which is fine
    /// because the names also include `std::process::id()`.
    fn nanos_now() -> u128 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    }

    /// Read effective uid/gid by parsing `/proc/self/status`. Only
    /// called from the docker spawn path so this is Linux-only. Falls
    /// back to `(1000, 1000)` if the file can't be read or parsed —
    /// matches the default uid baked into `lazymio/knowdit:foundry`.
    #[cfg(target_os = "linux")]
    fn read_proc_uid_gid() -> (u32, u32) {
        let s = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
        let mut uid: u32 = 1000;
        let mut gid: u32 = 1000;
        for line in s.lines() {
            // Format: `Uid:\t<real>\t<effective>\t<saved>\t<filesystem>`
            if let Some(rest) = line.strip_prefix("Uid:") {
                if let Some(real) = rest.split_whitespace().next()
                    && let Ok(v) = real.parse()
                {
                    uid = v;
                }
            } else if let Some(rest) = line.strip_prefix("Gid:")
                && let Some(real) = rest.split_whitespace().next()
                && let Ok(v) = real.parse()
            {
                gid = v;
            }
        }
        (uid, gid)
    }

    /// Spawn `forge args...` and return [`ForgeOutput`]. Hard-bounded by
    /// `self.timeout` — if exceeded the handle is dropped and the
    /// per-backend cleanup fires (kill child / docker kill / cgroup.kill).
    pub async fn run(&self, args: &[String]) -> Result<ForgeOutput> {
        let start = Instant::now();
        let handle = self.spawn(args)?;
        let timeout = self.timeout;
        let outcome = tokio::time::timeout(timeout, handle.wait_with_output()).await;
        let duration_ms = start.elapsed().as_millis() as i64;
        match outcome {
            Ok(Ok(out)) => Ok(ForgeOutput {
                exit_code: out.status.code().unwrap_or(-2),
                stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
                stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
                duration_ms,
                timed_out: false,
            }),
            Ok(Err(io_err)) => Err(io_err).wrap_err("forge wait_with_output failed"),
            Err(_elapsed) => Ok(ForgeOutput {
                exit_code: -1,
                stdout: String::new(),
                stderr: format!(
                    "knowdit: forge timed out after {} seconds",
                    timeout.as_secs()
                ),
                duration_ms,
                timed_out: true,
            }),
        }
    }

    /// Smoke-test the forge environment with a trivial harness that
    /// just `emit log_string("ok")` after `import "forge-std/Test.sol"`.
    /// On success, the project's Foundry environment (foundry.toml,
    /// remappings, forge-std availability, solc version, docker
    /// bind-mounts) is wired up well enough for the LLM-driven fuzz
    /// agent to make progress.
    ///
    /// On failure, returns `Err` with forge's own stdout + stderr
    /// embedded so the user can read the actual compile error rather
    /// than burn LLM tokens chasing a phantom "No tests found".
    /// Cleans up the temp file regardless of outcome.
    ///
    /// `harness_dir` is where the smoke test lives; it must be inside
    /// (or equal to) [`Self::work_dir`] so docker bind-mounts and
    /// `--match-path` agree. Same `forge_test_runs=1` flag — this
    /// isn't a fuzz, just a discoverability + compile check.
    pub async fn preflight(&self, harness_dir: &Path) -> Result<()> {
        const PREFLIGHT_DIR_PREFIX: &str = "_knowdit_preflight";
        const PREFLIGHT_HARNESS: &str = r#"// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import "forge-std/Test.sol";

contract KnowditPreflight is Test {
    function test_knowdit_preflight() public {
        emit log_string("knowdit preflight: ok");
    }
}
"#;

        let preflight_id = PREFLIGHT_COUNTER.fetch_add(1, Ordering::Relaxed);
        let preflight_dir = harness_dir.join(format!(
            "{PREFLIGHT_DIR_PREFIX}_{}_{}_{}",
            std::process::id(),
            Self::nanos_now(),
            preflight_id
        ));
        tokio::fs::create_dir_all(&preflight_dir)
            .await
            .wrap_err_with(|| {
                format!(
                    "preflight: failed to create {}; harness_dir may not be writable",
                    preflight_dir.display()
                )
            })?;
        let test_path = preflight_dir.join("KnowditPreflight.t.sol");
        tokio::fs::write(&test_path, PREFLIGHT_HARNESS)
            .await
            .wrap_err_with(|| format!("preflight: failed to write {}", test_path.display()))?;

        // Reuse the same FOUNDRY_TEST + --match-path scoping the per-spec
        // runner uses, so this smoke test doesn't drag any existing
        // harness file into its compile graph.
        let canonical_pre =
            std::fs::canonicalize(&preflight_dir).unwrap_or_else(|_| preflight_dir.clone());
        let pre_rel = canonical_pre
            .strip_prefix(self.work_dir())
            .map(|p| p.to_path_buf())
            .unwrap_or_else(|_| canonical_pre.clone());
        let scoped = self.clone().with_test_dir(preflight_dir.clone());
        let argv: Vec<String> = vec![
            "test".to_string(),
            "--match-contract".to_string(),
            "KnowditPreflight".to_string(),
            "--match-path".to_string(),
            format!("{}/*", pre_rel.to_string_lossy().trim_end_matches('/')),
            "--fuzz-runs".to_string(),
            "1".to_string(),
        ];

        let out_result = scoped.run(&argv).await;

        // Clean up regardless — leaving the file around lets stale
        // state poison the next preflight (different solc / shim).
        if let Err(e) = tokio::fs::remove_dir_all(&preflight_dir).await {
            tracing::warn!(
                preflight_dir = %preflight_dir.display(),
                "preflight cleanup failed (non-fatal): {e}"
            );
        }

        let out = out_result
            .wrap_err("preflight: forge spawn failed (binary path / docker / cgroup issue?)")?;
        let combined_tail = format!(
            "{}{}",
            tail_utf8(&out.stdout, 4_000),
            tail_utf8(&out.stderr, 4_000),
        );
        let looks_passed = combined_tail.contains("[PASS] test_knowdit_preflight")
            || combined_tail.contains("1 passed; 0 failed")
            || combined_tail.contains("1 tests passed");
        if out.exit_code == 0 && looks_passed {
            tracing::info!(
                duration_ms = out.duration_ms,
                "preflight: forge environment OK"
            );
            return Ok(());
        }

        Err(eyre!(
            "preflight: forge environment is broken — the trivial smoke test \
             `import \"forge-std/Test.sol\"; emit log_string(\"ok\")` did NOT pass. \
             Common causes: forge-std missing under lib/, foundry.toml absent or \
             pinning a solc version no installed solc satisfies, --match-path \
             resolving outside the project, or docker bind-mount misconfigured. \
             Fix the environment (autobuild.py handles most Hardhat→Foundry shim \
             setup) and re-run.\n\
             forge exit_code={} timed_out={} duration_ms={}\n\
             --- forge output (last ~4K of stdout + stderr) ---\n{}",
            out.exit_code,
            out.timed_out,
            out.duration_ms,
            combined_tail,
        ))
    }

    /// Spawn the forge invocation and return a [`ForgeHandle`] whose
    /// `Drop` performs backend-specific cleanup.
    fn spawn(&self, args: &[String]) -> Result<ForgeHandle> {
        let test_env = self
            .test_dir_override
            .as_ref()
            .map(|p| ("FOUNDRY_TEST", p.clone()));

        match &self.backend.kind {
            ForgeBackendKind::LocalDirect { binary } => {
                let mut cmd = Command::new(binary);
                cmd.args(args)
                    .current_dir(&self.work_dir)
                    .kill_on_drop(true);
                if let Some((k, v)) = &test_env {
                    cmd.env(k, v);
                }
                let child = cmd
                    .stdin(std::process::Stdio::null())
                    .stdout(std::process::Stdio::piped())
                    .stderr(std::process::Stdio::piped())
                    .spawn()
                    .wrap_err_with(|| {
                        format!("failed to spawn `{} {:?}`", binary.display(), args)
                    })?;
                Ok(ForgeHandle::LocalDirect { child: Some(child) })
            }

            #[cfg(target_os = "linux")]
            ForgeBackendKind::LocalCgroup {
                binary,
                cgroup_parent,
                mem_max_bytes,
            } => {
                let cg_name = format!("knowdit-forge-{}-{}", std::process::id(), Self::nanos_now());
                let scoped = ScopedCgroup::create(cgroup_parent, &cg_name, *mem_max_bytes)
                    .map_err(|e| eyre!("failed to create cgroup {cgroup_parent}/{cg_name}: {e}"))?;

                let mut cmd = Command::new(binary);
                cmd.args(args)
                    .current_dir(&self.work_dir)
                    .kill_on_drop(true);
                if let Some((k, v)) = &test_env {
                    cmd.env(k, v);
                }
                let child = cmd
                    .stdin(std::process::Stdio::null())
                    .stdout(std::process::Stdio::piped())
                    .stderr(std::process::Stdio::piped())
                    .spawn()
                    .wrap_err_with(|| {
                        format!("failed to spawn `{} {:?}`", binary.display(), args)
                    })?;
                if let Some(pid) = child.id()
                    && let Err(e) = scoped.add_pid(pid)
                {
                    tracing::warn!(
                        "ForgeRunner: failed to attach pid {pid} to cgroup; \
                             memory cap won't apply: {e}"
                    );
                }
                Ok(ForgeHandle::LocalCgroup {
                    child: Some(child),
                    _cgroup: scoped,
                })
            }

            #[cfg(target_os = "linux")]
            ForgeBackendKind::Docker {
                image,
                mem_max_bytes,
            } => {
                let container_name =
                    format!("knowdit-forge-{}-{}", std::process::id(), Self::nanos_now());
                let (uid, gid) = Self::read_proc_uid_gid();
                let work_str = self.work_dir.display().to_string();
                let mut cmd = Command::new("docker");
                cmd.arg("run")
                    .arg("--rm")
                    .arg("--name")
                    .arg(&container_name)
                    .arg("--user")
                    .arg(format!("{uid}:{gid}"))
                    .arg("--network")
                    .arg("none")
                    .arg("-v")
                    .arg(format!("{work_str}:{work_str}"))
                    .arg("-w")
                    .arg(&work_str);
                if *mem_max_bytes > 0 {
                    cmd.arg(format!("--memory={mem_max_bytes}b"))
                        .arg(format!("--memory-swap={mem_max_bytes}b"));
                }
                if let Some((k, v)) = &test_env {
                    cmd.arg("-e").arg(format!("{k}={}", v.display()));
                }
                cmd.arg("--entrypoint")
                    .arg("/usr/local/bin/forge")
                    .arg(image)
                    .args(args)
                    .kill_on_drop(true);
                let child = cmd
                    .stdin(std::process::Stdio::null())
                    .stdout(std::process::Stdio::piped())
                    .stderr(std::process::Stdio::piped())
                    .spawn()
                    .wrap_err_with(|| format!("failed to spawn `docker run ... {image}`"))?;
                Ok(ForgeHandle::Docker {
                    child: Some(child),
                    container_name,
                })
            }
        }
    }
}

/// Per-invocation handle. Holds the child + any backend-specific cleanup
/// state. `Drop` kills the right things in the right order.
///
/// `child` is wrapped in `Option` so [`Self::wait_with_output`] can
/// `take()` it without moving out of `self` (which `Drop`-implementing
/// types forbid). After a successful wait the child slot is `None`, so
/// the per-variant Drop logic still runs but has nothing left to kill —
/// `docker kill` against an already-exited container is a harmless no-op,
/// and the cgroup is already empty so `cgroup.kill` + rmdir succeed
/// immediately.
#[derive(Debug)]
enum ForgeHandle {
    LocalDirect {
        child: Option<tokio::process::Child>,
    },
    #[cfg(target_os = "linux")]
    LocalCgroup {
        child: Option<tokio::process::Child>,
        _cgroup: ScopedCgroup,
    },
    #[cfg(target_os = "linux")]
    Docker {
        child: Option<tokio::process::Child>,
        container_name: String,
    },
}

impl ForgeHandle {
    fn take_child(&mut self) -> Option<tokio::process::Child> {
        match self {
            ForgeHandle::LocalDirect { child } => child.take(),
            #[cfg(target_os = "linux")]
            ForgeHandle::LocalCgroup { child, .. } => child.take(),
            #[cfg(target_os = "linux")]
            ForgeHandle::Docker { child, .. } => child.take(),
        }
    }

    /// Block until the child exits and collect stdout/stderr. `Drop` runs
    /// when this future resolves (or is cancelled), so backend cleanup
    /// fires on every path.
    async fn wait_with_output(mut self) -> std::io::Result<std::process::Output> {
        let child = self
            .take_child()
            .expect("ForgeHandle::wait_with_output: child already consumed");
        child.wait_with_output().await
    }
}

impl Drop for ForgeHandle {
    fn drop(&mut self) {
        match self {
            ForgeHandle::LocalDirect { .. } => {
                // Child (if still here) gets SIGKILL'd via tokio
                // `kill_on_drop`. Nothing else to do.
            }
            #[cfg(target_os = "linux")]
            ForgeHandle::LocalCgroup { .. } => {
                // Field-order drop: `child` (kill_on_drop SIGKILL), then
                // `_cgroup` (cgroup.kill + retry rmdir). Already in
                // declaration order; no manual sequencing needed.
            }
            #[cfg(target_os = "linux")]
            ForgeHandle::Docker { container_name, .. } => {
                // Killing the docker CLI client (tokio kill_on_drop) does
                // NOT reliably propagate to the daemon-managed container,
                // so explicitly tell dockerd to kill it. SIGKILL is
                // `docker kill`'s default. Best-effort, fire-and-forget.
                let _ = std::process::Command::new("docker")
                    .args(["kill", container_name.as_str()])
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null())
                    .spawn();
            }
        }
    }
}

/// Raw subprocess outcome before parsing.
#[derive(Debug, Clone)]
pub struct ForgeOutput {
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
    pub duration_ms: i64,
    pub timed_out: bool,
}
