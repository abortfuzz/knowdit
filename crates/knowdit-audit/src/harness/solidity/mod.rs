//! Foundry fuzzing harness generator.
//!
//! One concrete [`SolidityFuzzGenerator`] type with a [`HarnessKind`]
//! field that selects between two test-authoring modes:
//!
//! * [`HarnessKind::Handler`] — agent writes a Foundry handler contract
//!   + an invariant test contract; forge fuzzes input sequences;
//!   violation = invariant counter-example.
//! * [`HarnessKind::Poc`] — agent writes one `test_…()` function that
//!   drives the attack deterministically; violation = test reverts
//!   with reason containing `KNOWDIT_POST_ATTACK_REACHED:`.
//!
//! Both modes share the same downstream surface ([`LinkFuzzOutcome`] →
//! `repo.write_code_gen_with_runs`), so callers never branch on mode.
//!
//! Internal layout:
//!
//! * [`utils`] — shared data types ([`FuzzOptions`], [`FuzzOutcome`],
//!   [`LinkFuzzOutcome`], [`ForgeTestSummary`], [`CounterCall`]), forge
//!   JSON / lcov parsers, agent-state plumbing, project conventions
//!   loader, the `KNOWDIT_POST_ATTACK_REACHED:` detector.
//! * [`runtime`] — solidity-layer forge driver: per-spec scratch dir
//!   isolation, the `run_forge` / `list_test_files` agent tools, the
//!   shared agent loop, [`SolidityFuzzGenerator`] and its dispatch
//!   helpers.
//! * [`harness`] — handler+invariant mode: `write_harness_file` tool +
//!   prompt builders.
//! * [`poc`] — deterministic PoC mode: `write_poc_file` tool + prompt
//!   builders.
//!
//! The generic forge backend (`ForgeBackend`, `ForgeRunner`,
//! docker/cgroup variants) lives one level up at
//! [`crate::harness::forge`].

mod backend;
mod harness;
mod poc;
mod runtime;
mod tools;
mod utils;

pub use backend::SolidityHarness;
pub use runtime::{CodegenRegenInMemory, FuzzOneOutcome, RegenOutcome, SolidityHarnessGenerator};
pub use utils::{CounterCall, ForgeTestSummary, FuzzOptions, FuzzOutcome, LinkFuzzOutcome};

/// Harness-authoring mode passed to [`SolidityFuzzGenerator::new`].
/// `Handler` (the default) is the long-standing Foundry handler +
/// invariant pipeline; `Poc` is the deterministic-PoC mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HarnessKind {
    /// Foundry handler contract + `invariant_…` test. Fuzzer drives
    /// input sequences; violation = invariant counter-example.
    Handler,
    /// Single `test_…()` function whose body deterministically
    /// reproduces the attack; violation = test reverts with reason
    /// starting `KNOWDIT_POST_ATTACK_REACHED:`.
    Poc,
}
