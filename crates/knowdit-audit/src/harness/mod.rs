//! Synthesize fuzzing harnesses from generated `AuditSpecification`s and
//! drive `forge` against them.
//!
//! Currently only Solidity / Foundry is supported. Layout:
//!
//!   * [`solidity`] — public surface; sub-module split into
//!     `harness` (handler+invariant mode), `poc` (deterministic PoC
//!     mode), `runtime` (solidity-layer forge driver shared by both
//!     modes), `utils` (data types + parsers), `prompt`
//!     (handler+invariant prompt builders).
//!   * [`forge`] — generic `forge`-invocation backends (local direct,
//!     local cgroup-capped, docker) plus the per-invocation handle
//!     whose `Drop` performs backend-specific cleanup.
//!   * [`forge_json`] — typed mirror of `forge test --json` output.
//!   * [`cgroup`] — cgroup v2 raw `/sys/fs/cgroup` helpers used by the
//!     `LocalCgroup` backend (Linux only).
pub mod backend;
#[cfg(target_os = "linux")]
mod cgroup;
pub mod forge;
pub mod forge_json;
pub mod solidity;

pub use backend::HarnessBackend;
