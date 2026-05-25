//! Mirror of the subset of `forge test --json` schema we consume.
//!
//! We deliberately do *not* depend on the `forge` / `foundry-evm` crates:
//! foundry isn't published to crates.io, and a git dep would pull
//! foundry-evm + alloy + revm + ... (thousands of transitive crates). The
//! JSON shape is small enough that a hand-mirror is cheaper, and this
//! file is the only place forge's wire format leaks into our code.
//!
//! Each user-facing struct is wrapped via [`WithOtherFields`] so any
//! forge-side schema change shows up as captured-but-unread keys in
//! `.other` rather than silently dropped data. Cheaply re-serializable
//! → the original forge bytes can be reconstructed when we persist
//! `counterexample` to the DB.
//!
//! Field set on the modeled side is intentionally trimmed: we keep
//! `status`, `reason`, `counterexample`, and `kind`. Heavier fields
//! (traces, logs, breakpoints, gas snapshots) flow through `.other`
//! without us reading them; downstream gates only need the verdict
//! fields.

use std::collections::BTreeMap;

use alloy_serde::WithOtherFields;
use serde::{Deserialize, Serialize};

/// Top-level shape of `forge test --json`: one entry per test contract,
/// keyed by `"path/to/file.sol:ContractName"`. Each entry is a
/// `WithOtherFields<SuiteResult>` so unknown top-level keys (e.g. the
/// `duration` / `warnings` fields we don't read) round-trip cleanly.
pub type SuiteMap = BTreeMap<String, WithOtherFields<SuiteResult>>;

/// Mirror of `forge::result::SuiteResult`.
#[derive(Debug, Default, Deserialize, Serialize)]
pub struct SuiteResult {
    #[serde(default)]
    pub test_results: BTreeMap<String, WithOtherFields<TestResult>>,
}

/// Mirror of `forge::result::TestResult`. `kind` stays as raw
/// `serde_json::Value` because it's an externally-tagged enum that
/// gains variants over time; drill in via [`TestResult::invariant_stats`].
#[derive(Debug, Default, Deserialize, Serialize)]
pub struct TestResult {
    #[serde(default)]
    pub status: TestStatus,
    #[serde(default)]
    pub reason: Option<String>,
    #[serde(default)]
    pub counterexample: Option<CounterExample>,
    #[serde(default)]
    pub invariant_failures: Vec<WithOtherFields<InvariantFailure>>,
    #[serde(default)]
    pub kind: serde_json::Value,
}

/// Mirror of `forge::result::TestStatus`.
#[derive(Debug, Default, Deserialize, Serialize, PartialEq, Eq, Clone, Copy)]
pub enum TestStatus {
    Success,
    #[default]
    Failure,
    Skipped,
}

/// Mirror of `evm::fuzz::CounterExample`. Externally tagged. `Sequence`
/// is what an invariant breach produces; `Single` is for plain fuzz.
/// Inner `BaseCounterExample` is wrapped so per-call extra fields
/// (forge's fuzz_seed/run/worker etc.) round-trip into the DB.
#[derive(Debug, Deserialize, Serialize)]
pub enum CounterExample {
    Single(WithOtherFields<BaseCounterExample>),
    Sequence(usize, Vec<WithOtherFields<BaseCounterExample>>),
}

/// Mirror of one entry in Forge's newer `invariant_failures` array.
/// We only need the nested `counterexample` plus the human-readable
/// `reason`; any additional fields still round-trip through `other`.
#[derive(Debug, Default, Deserialize, Serialize)]
pub struct InvariantFailure {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub reason: Option<String>,
    #[serde(default)]
    pub counterexample: Option<CounterExample>,
}

/// Mirror of `evm::fuzz::BaseCounterExample`. Models only the fields
/// our gates read; anything else forge emits (warp, roll, calldata,
/// raw_args, fuzz metadata, future additions) is captured by the
/// `WithOtherFields` wrapper at the use site.
#[derive(Debug, Default, Deserialize, Serialize)]
pub struct BaseCounterExample {
    #[serde(default)]
    pub sender: Option<String>,
    #[serde(default)]
    pub addr: Option<String>,
    #[serde(default)]
    pub contract_name: Option<String>,
    #[serde(default)]
    pub func_name: Option<String>,
    #[serde(default)]
    pub signature: Option<String>,
    #[serde(default)]
    pub args: Option<String>,
}

/// Subset of `forge::result::TestKind::Invariant` we read.
#[derive(Debug, Default, Deserialize, Serialize)]
pub struct InvariantStats {
    #[serde(default)]
    pub runs: i64,
    #[serde(default)]
    pub calls: i64,
    #[serde(default)]
    pub reverts: i64,
}

impl TestResult {
    /// Try to read the `Invariant` arm of `kind`. `None` for
    /// Unit/Fuzz/Table tests, or when the shape changed.
    pub fn invariant_stats(&self) -> Option<InvariantStats> {
        let inv = self.kind.get("Invariant")?;
        serde_json::from_value(inv.clone()).ok()
    }

    /// True iff this entry represents a setUp() revert. Forge surfaces
    /// these in two shapes depending on version: a synthesized
    /// `test_name == "setUp()"` Failure entry (newer), or a regular
    /// test failure whose `reason` starts with `"failed to set up"`
    /// (older). We accept both.
    pub fn is_setup_failure(&self, test_name: &str) -> bool {
        if self.status != TestStatus::Failure {
            return false;
        }
        if test_name == "setUp()" {
            return true;
        }
        match &self.reason {
            Some(r) => r.to_ascii_lowercase().contains("failed to set up"),
            None => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(stdout: &str) -> SuiteMap {
        serde_json::from_str(stdout.trim()).unwrap_or_default()
    }

    #[test]
    fn parses_v9_setup_failure_sample() {
        let sample = r#"{
            "test/foo.sol:Test_123": {
                "test_results": {
                    "setUp()": {
                        "status": "Failure",
                        "reason": "call to non-contract address 0x7d356b6aFBF4b3e9a5d9AA02275F0e00558627e8",
                        "counterexample": null,
                        "kind": {"Unit": {"gas": 0}},
                        "logs": [],
                        "decoded_logs": [],
                        "traces": [],
                        "labeled_addresses": {},
                        "duration": "0s",
                        "breakpoints": {},
                        "gas_snapshots": {}
                    }
                }
            }
        }"#;
        let suites = parse(sample);
        let suite = suites.values().next().unwrap();
        let (name, tr) = suite.test_results.iter().next().unwrap();
        assert_eq!(name, "setUp()");
        assert_eq!(tr.status, TestStatus::Failure);
        assert!(tr.is_setup_failure(name));
        assert!(tr.invariant_stats().is_none());
        // Heavy fields are captured in `other` rather than dropped.
        assert!(tr.other.contains_key("traces"));
        assert!(tr.other.contains_key("breakpoints"));
    }

    #[test]
    fn parses_invariant_kind() {
        let sample = r#"{
            "x:Y": {
                "test_results": {
                    "invariant_x": {
                        "status": "Success",
                        "reason": null,
                        "counterexample": null,
                        "kind": {"Invariant": {"runs": 256, "calls": 12800, "reverts": 12780}}
                    }
                }
            }
        }"#;
        let suites = parse(sample);
        let tr = suites
            .values()
            .next()
            .unwrap()
            .test_results
            .values()
            .next()
            .unwrap();
        let stats = tr.invariant_stats().unwrap();
        assert_eq!(stats.calls, 12800);
        assert_eq!(stats.reverts, 12780);
    }

    #[test]
    fn parses_counterexample_sequence_with_extra_fields() {
        // Forge actually emits fuzz_seed / fuzz_run / fuzz_worker on each
        // BaseCounterExample. Verify those fields make it into `other`
        // so re-serializing into sequence_json keeps them.
        let sample = r#"{
            "x:Y": {
                "test_results": {
                    "invariant_x": {
                        "status": "Failure",
                        "reason": "post-attack invariant violated",
                        "counterexample": {
                            "Sequence": [2, [
                                {"sender": "0xaaa", "addr": "0xbbb",
                                 "contract_name": "Pool", "func_name": "dispatch",
                                 "args": "[1,2]",
                                 "fuzz_seed": "0xdeadbeef", "fuzz_run": 7},
                                {"sender": "0xaaa", "addr": "0xccc",
                                 "contract_name": "CollateralTracker", "func_name": "withdraw",
                                 "args": "[100]",
                                 "fuzz_seed": "0xdeadbeef", "fuzz_run": 7}
                            ]]
                        },
                        "kind": {"Invariant": {"runs": 256, "calls": 1000, "reverts": 50}}
                    }
                }
            }
        }"#;
        let suites = parse(sample);
        let tr = suites
            .values()
            .next()
            .unwrap()
            .test_results
            .values()
            .next()
            .unwrap();
        let ce = tr.counterexample.as_ref().unwrap();
        match ce {
            CounterExample::Sequence(_orig, calls) => {
                assert_eq!(calls.len(), 2);
                assert_eq!(calls[0].contract_name.as_deref(), Some("Pool"));
                assert_eq!(calls[0].func_name.as_deref(), Some("dispatch"));
                // Extra forge fields preserved in `other`.
                assert!(calls[0].other.contains_key("fuzz_seed"));
                assert!(calls[0].other.contains_key("fuzz_run"));
            }
            _ => panic!("expected Sequence variant"),
        }

        // Round-trip: re-serializing should preserve the extra fields.
        let json = serde_json::to_string(ce).unwrap();
        assert!(json.contains("fuzz_seed"));
        assert!(json.contains("fuzz_run"));
    }

    #[test]
    fn returns_empty_on_compile_error_stdout() {
        let stdout = "Compiler run failed:\nWarning (8429): ...";
        assert!(parse(stdout).is_empty());
    }

    #[test]
    fn parses_counterexample_from_invariant_failures_array() {
        let sample = r#"{
            "x:Y": {
                "test_results": {
                    "invariant_x": {
                        "status": "Failure",
                        "reason": null,
                        "counterexample": null,
                        "invariant_failures": [{
                            "name": "invariant_x",
                            "reason": "assertion failed",
                            "counterexample": {
                                "Sequence": [1, [
                                    {"sender": "0xaaa", "addr": "0xbbb",
                                     "contract_name": "Pool", "func_name": "dispatch",
                                     "args": "[1,2]"}
                                ]]
                            }
                        }],
                        "kind": {"Invariant": {"runs": 1, "calls": 1, "reverts": 0}}
                    }
                }
            }
        }"#;
        let suites = parse(sample);
        let tr = suites
            .values()
            .next()
            .unwrap()
            .test_results
            .values()
            .next()
            .unwrap();
        assert!(tr.counterexample.is_none());
        assert_eq!(tr.invariant_failures.len(), 1);
        let ce = tr.invariant_failures[0].counterexample.as_ref().unwrap();
        match ce {
            CounterExample::Sequence(_orig, calls) => {
                assert_eq!(calls.len(), 1);
                assert_eq!(calls[0].contract_name.as_deref(), Some("Pool"));
                assert_eq!(calls[0].func_name.as_deref(), Some("dispatch"));
            }
            _ => panic!("expected Sequence variant"),
        }
    }

    #[test]
    fn unknown_kind_variant_doesnt_break() {
        let sample = r#"{
            "x:Y": {
                "test_results": {
                    "t": {
                        "status": "Success",
                        "kind": {"NewVariant": {"foo": 42}}
                    }
                }
            }
        }"#;
        let suites = parse(sample);
        let tr = suites
            .values()
            .next()
            .unwrap()
            .test_results
            .values()
            .next()
            .unwrap();
        assert!(tr.invariant_stats().is_none());
        assert_eq!(tr.status, TestStatus::Success);
    }
}
