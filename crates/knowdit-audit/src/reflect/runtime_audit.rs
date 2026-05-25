//! Gate 1 (runtime variant): score one `forge test --json` invocation
//! against the spec without re-reading the harness source.
//!
//! Inputs are everything forge already gives us in JSON
//! (`ForgeTestSummary`) plus the spec's `sequence`. Pure function: same
//! shape as `coverage_audit::run`, so the fuzz inner loop and `agentic
//! reflect` outer loop can call it with the same signature.
//!
//! The signals here are blunt but high-precision: each one means the
//! harness compiled but didn't actually exercise project code.

use std::collections::BTreeSet;

use crate::harness::solidity::ForgeTestSummary;
use crate::types::AuditSpecification;

use super::{AuditOutcome, GateKind};

/// Threshold over which "fuzzer reverted on every call" stops being noise
/// and starts being a strong signal of mocked-environment scaffolding.
/// 0.95 = 19/20 calls reverting.
pub const HIGH_REVERT_RATE: f64 = 0.95;

/// Run Gate 1 against one forge-test JSON summary. Order of checks matters:
/// `setup_failed` precedes `revert_rate` precedes `counterexample_disjoint`,
/// because a setUp failure invalidates the rest of the signals.
pub fn run(summary: &ForgeTestSummary, spec: &AuditSpecification) -> AuditOutcome {
    if summary.setup_failed {
        let why = summary
            .failure_reason
            .as_deref()
            .unwrap_or("(no reason reported)");
        return AuditOutcome::Fail {
            gate: GateKind::Static,
            reason: format!("setUp() failed: {why}"),
        };
    }
    let rate = summary.revert_rate();
    if summary.total_calls > 0 && rate >= HIGH_REVERT_RATE {
        return AuditOutcome::Fail {
            gate: GateKind::Static,
            reason: format!(
                "{}/{} fuzz calls reverted ({:.1}%); fuzzer never reached real code paths",
                summary.total_reverts,
                summary.total_calls,
                rate * 100.0
            ),
        };
    }
    if summary.violated {
        let spec_pairs: BTreeSet<(String, String)> = spec
            .sequence
            .iter()
            .map(|s| (s.contract.clone(), s.function.clone()))
            .collect();
        if !spec_pairs.is_empty() {
            let any_overlap =
                summary
                    .counterexample_calls
                    .iter()
                    .any(|c| match (&c.contract, &c.function) {
                        (Some(con), Some(func)) => {
                            spec_pairs.contains(&(con.clone(), func.clone()))
                        }
                        _ => false,
                    });
            // Also accept a function-only match (contract names sometimes
            // differ between spec and decoded trace — interface vs impl).
            let any_function_overlap = !any_overlap
                && summary
                    .counterexample_calls
                    .iter()
                    .any(|c| match &c.function {
                        Some(func) => spec_pairs.iter().any(|(_, f)| f == func),
                        None => false,
                    });
            if !any_overlap && !any_function_overlap {
                let touched: Vec<String> = summary
                    .counterexample_calls
                    .iter()
                    .map(|c| {
                        format!(
                            "{}::{}",
                            c.contract.as_deref().unwrap_or("?"),
                            c.function.as_deref().unwrap_or("?")
                        )
                    })
                    .collect();
                return AuditOutcome::Fail {
                    gate: GateKind::Static,
                    reason: format!(
                        "counter-example touches none of spec.sequence ({} expected). Touched: [{}]",
                        spec_pairs.len(),
                        touched.join(", ")
                    ),
                };
            }
        }
    }
    AuditOutcome::Pass
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::harness::solidity::CounterCall;
    use crate::types::{AuditStateSpecification, SuqenceCallStep};
    use std::collections::BTreeMap;

    fn fake_spec() -> AuditSpecification {
        AuditSpecification {
            setup: AuditStateSpecification::default(),
            pre_attack: AuditStateSpecification::default(),
            post_attack: AuditStateSpecification::default(),
            sequence: vec![SuqenceCallStep {
                contract: "Pool".into(),
                function: "dispatch".into(),
                intention: String::new(),
            }],
        }
    }

    #[test]
    fn flags_setup_failure() {
        let summary = ForgeTestSummary {
            setup_failed: true,
            failure_reason: Some("call to non-contract address 0x0".into()),
            ..Default::default()
        };
        let outcome = run(&summary, &fake_spec());
        assert!(matches!(outcome, AuditOutcome::Fail { .. }));
    }

    #[test]
    fn flags_high_revert_rate() {
        let summary = ForgeTestSummary {
            total_calls: 1000,
            total_reverts: 990,
            ..Default::default()
        };
        match run(&summary, &fake_spec()) {
            AuditOutcome::Fail { reason, .. } => assert!(reason.contains("99")),
            _ => panic!("expected fail"),
        }
    }

    #[test]
    fn passes_when_revert_rate_low_and_no_violation() {
        let summary = ForgeTestSummary {
            total_calls: 1000,
            total_reverts: 50,
            ..Default::default()
        };
        assert!(matches!(run(&summary, &fake_spec()), AuditOutcome::Pass));
    }

    #[test]
    fn flags_counterexample_disjoint_from_spec() {
        let summary = ForgeTestSummary {
            total_calls: 100,
            total_reverts: 5,
            violated: true,
            counterexample_calls: vec![CounterCall {
                contract: Some("OracleStub".into()),
                function: Some("setPrice".into()),
                args: None,
            }],
            ..Default::default()
        };
        match run(&summary, &fake_spec()) {
            AuditOutcome::Fail { reason, .. } => assert!(reason.contains("touches none")),
            _ => panic!("expected fail"),
        }
    }

    #[test]
    fn passes_counterexample_overlapping_spec() {
        let summary = ForgeTestSummary {
            total_calls: 100,
            total_reverts: 5,
            violated: true,
            counterexample_calls: vec![CounterCall {
                contract: Some("Pool".into()),
                function: Some("dispatch".into()),
                args: None,
            }],
            ..Default::default()
        };
        assert!(matches!(run(&summary, &fake_spec()), AuditOutcome::Pass));
    }
}
