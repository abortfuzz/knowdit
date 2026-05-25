//! cgroup v2 helpers — raw `/sys/fs/cgroup` I/O.
//!
//! Linux-only. The whole module is gated on `target_os = "linux"`, so
//! non-Linux callers can't reach here.
//!
//! We avoid pulling in a full cgroup crate (e.g. `cgroups-rs`) for what
//! amounts to a handful of file writes per invocation:
//!   `mkdir <parent>/<name>`
//!   `echo <N>     > memory.max`
//!   `echo 0       > memory.swap.max`
//!   `echo <pid>   > cgroup.procs`
//!   `echo 1       > cgroup.kill`     (in `Drop`)
//!   `rmdir <parent>/<name>`           (in `Drop`)
//!
//! Such a crate adds non-trivial transitive deps and a v1/v2 abstraction
//! we don't need, and doesn't natively wrap `cgroup.kill` (which we want
//! for clean teardown), so we'd be writing this raw layer either way.

#![cfg(target_os = "linux")]

use std::path::{Path, PathBuf};

/// A freshly-created cgroup v2 child. Drops by killing every process
/// inside via `cgroup.kill` then `rmdir`-ing.
#[derive(Debug)]
pub(super) struct ScopedCgroup {
    abs_path: PathBuf,
}

impl ScopedCgroup {
    /// Walk our cgroup ancestors looking for the deepest one we can mkdir
    /// under AND that delegates `memory` to its children. Returns the
    /// path relative to `/sys/fs/cgroup` (e.g.
    /// `user.slice/user-1000.slice/user@1000.service/app.slice`) on
    /// success, or `None` if no usable parent was found.
    pub(super) fn probe_parent() -> Option<String> {
        let raw = std::fs::read_to_string("/proc/self/cgroup").ok()?;
        // cgroup v2 lines look like `0::/user.slice/.../my.scope`.
        let line = raw.lines().find(|l| l.starts_with("0::"))?;
        let our_rel = line.strip_prefix("0::")?.trim_start_matches('/');
        let our_path = PathBuf::from(our_rel);
        let mut cur: Option<&Path> = our_path.parent();
        while let Some(p) = cur {
            if p.as_os_str().is_empty() {
                break;
            }
            let abs = Path::new("/sys/fs/cgroup").join(p);
            let has_mem = std::fs::read_to_string(abs.join("cgroup.subtree_control"))
                .map(|s| s.split_whitespace().any(|w| w == "memory"))
                .unwrap_or(false);
            if has_mem {
                let probe = abs.join(format!(
                    "knowdit-probe-{}-{}",
                    std::process::id(),
                    Self::nanos_now(),
                ));
                if std::fs::create_dir(&probe).is_ok() {
                    let _ = std::fs::remove_dir(&probe);
                    return Some(p.to_string_lossy().into_owned());
                }
            }
            cur = p.parent();
        }
        None
    }

    /// `parent_rel` is what [`Self::probe_parent`] returned. `name`
    /// should be unique per concurrent invocation.
    pub(super) fn create(
        parent_rel: &str,
        name: &str,
        mem_max_bytes: u64,
    ) -> std::io::Result<Self> {
        let abs = Path::new("/sys/fs/cgroup")
            .join(parent_rel.trim_start_matches('/'))
            .join(name);
        std::fs::create_dir(&abs)?;
        std::fs::write(abs.join("memory.max"), mem_max_bytes.to_string().as_bytes())?;
        // Best-effort: make swap unavailable so OOM fires at memory.max
        // instead of silently paging out.
        let _ = std::fs::write(abs.join("memory.swap.max"), b"0");
        Ok(Self { abs_path: abs })
    }

    /// Move `pid` (and its tgid group) into this cgroup.
    pub(super) fn add_pid(&self, pid: u32) -> std::io::Result<()> {
        std::fs::write(
            self.abs_path.join("cgroup.procs"),
            pid.to_string().as_bytes(),
        )
    }

    fn nanos_now() -> u128 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    }
}

impl Drop for ScopedCgroup {
    fn drop(&mut self) {
        // `echo 1 > cgroup.kill` SIGKILLs every process in the cgroup
        // atomically (v2 kernel feature). Then we can rmdir.
        let _ = std::fs::write(self.abs_path.join("cgroup.kill"), b"1");
        // Kernel reaping is fast but not instantaneous; retry briefly.
        for _ in 0..50 {
            if std::fs::remove_dir(&self.abs_path).is_ok() {
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        if let Err(e) = std::fs::remove_dir(&self.abs_path) {
            tracing::debug!(
                "ScopedCgroup: failed to rmdir {}: {e}",
                self.abs_path.display()
            );
        }
    }
}
