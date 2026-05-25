//! Synthesize fuzzing harnesses from generated `AuditSpecification`s and
//! drive `forge` against them.
//!
//! Currently only Solidity / Foundry is supported. Layout:
//!
//!   * [`solidity`] — agent loop, tools, persistence; the public surface
//!     of this module.
//!   * [`solidity_prompt`] — prompt construction, split out to keep the
//!     agent loop focused on data flow.
//!   * [`forge`] — `forge`-invocation backends (local direct, local
//!     cgroup-capped, docker) plus the per-invocation handle whose
//!     `Drop` performs backend-specific cleanup.
//!   * [`cgroup`] — cgroup v2 raw `/sys/fs/cgroup` helpers used by the
//!     `LocalCgroup` backend (Linux only).
#[cfg(target_os = "linux")]
mod cgroup;
pub mod forge;
pub mod forge_json;
pub mod solidity;
mod solidity_prompt;
