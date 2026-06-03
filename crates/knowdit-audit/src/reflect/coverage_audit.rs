//! Gate 2: coverage audit.
//!
//! Each `spec.sequence` step names a `(contract, function)` pair. We
//! resolve that pair to a concrete `Function` in the project call
//! graph (which carries `relative_file_path` + line range), then
//! intersect the line range with the `line_coverage` rows produced by
//! the harness's coverage forge run.
//!
//! The fidelity score is `hit_fns / expected_fns`. Below
//! `gate2_fidelity_threshold` the harness is flagged: forge ran but
//! the spec-prescribed code path was never actually exercised — the
//! classic "fake scaffolding" failure mode.

use std::collections::BTreeMap;

use knowdit_repo_model::{
    CoverageEntry,
    cg::{CallGraph, Function},
};

use crate::types::{AuditSpecification, SuqenceCallStep};

use super::{AuditOutcome, AuditThresholds, GateKind};

/// Resolution + hit status for one `spec.sequence` step.
#[derive(Debug, Clone)]
pub enum StepStatus {
    /// `(contract, function)` did not match anything in the call graph.
    /// We treat these as "expected = 0" for fidelity (excluded from
    /// both numerator and denominator) since the spec is referencing
    /// something that doesn't exist in the project; not the harness's
    /// fault. Logged for the human to inspect.
    Unresolved,
    /// Step was resolved and at least one of the function's lines had
    /// `hit_count > 0`.
    Hit { contract: String, function: String },
    /// Step resolved but no covered lines fell within its range.
    Missed { contract: String, function: String },
}

/// Aggregated Gate 2 verdict.
#[derive(Debug, Clone)]
pub struct CoverageReport {
    pub steps: Vec<StepStatus>,
    /// Number of steps in `Hit` state.
    pub hit_fns: usize,
    /// Number of steps in `Hit` or `Missed` (denominator for fidelity).
    pub expected_fns: usize,
    /// `hit_fns / expected_fns`, or 1.0 when `expected_fns == 0`.
    pub fidelity: f64,
}

impl CoverageReport {
    pub fn missed_step_labels(&self) -> Vec<String> {
        self.steps
            .iter()
            .filter_map(|s| match s {
                StepStatus::Missed { contract, function } => {
                    Some(format!("{contract}::{function}"))
                }
                _ => None,
            })
            .collect()
    }

    pub fn unresolved_step_labels(&self) -> Vec<String> {
        self.steps
            .iter()
            .filter_map(|s| match s {
                StepStatus::Unresolved => Some("(unresolved)".to_string()),
                _ => None,
            })
            .collect()
    }

    pub fn failure_reason(&self, thresholds: &AuditThresholds) -> Option<String> {
        if self.expected_fns == 0 {
            // Spec sequence references nothing the call graph knows;
            // can't form a coverage opinion. Pass.
            return None;
        }
        if self.fidelity < thresholds.gate2_fidelity_threshold {
            let missed = self.missed_step_labels();
            return Some(format!(
                "fidelity={:.2} < {:.2}; {}/{} spec.sequence functions hit; missing: [{}]",
                self.fidelity,
                thresholds.gate2_fidelity_threshold,
                self.hit_fns,
                self.expected_fns,
                missed.join(", "),
            ));
        }
        None
    }
}

/// Top-level Gate 2 entry point.
pub fn run(
    spec: &AuditSpecification,
    coverage: &[CoverageEntry],
    callgraph: &CallGraph,
    thresholds: &AuditThresholds,
) -> AuditOutcome {
    let report = collect_report(spec, coverage, callgraph);
    match report.failure_reason(thresholds) {
        Some(reason) => AuditOutcome::Fail {
            gate: GateKind::Coverage,
            reason,
        },
        None => AuditOutcome::Pass,
    }
}

/// Same as [`run`] but returns the structured report.
pub fn collect_report(
    spec: &AuditSpecification,
    coverage: &[CoverageEntry],
    callgraph: &CallGraph,
) -> CoverageReport {
    let by_path = group_coverage_by_path(coverage);
    let mut steps: Vec<StepStatus> = Vec::with_capacity(spec.sequence.len());
    let mut hit = 0usize;
    let mut expected = 0usize;
    for step in &spec.sequence {
        let Some(function) = resolve_function(callgraph, step) else {
            steps.push(StepStatus::Unresolved);
            continue;
        };
        expected += 1;
        let path_key = function.relative_file_path.to_string_lossy().into_owned();
        let was_hit = by_path
            .get(&path_key)
            .map(|covered| covered_intersects(covered, &function))
            .unwrap_or(false);
        if was_hit {
            hit += 1;
            steps.push(StepStatus::Hit {
                contract: step.contract.clone(),
                function: step.function.clone(),
            });
        } else {
            steps.push(StepStatus::Missed {
                contract: step.contract.clone(),
                function: step.function.clone(),
            });
        }
    }
    let fidelity = if expected == 0 {
        1.0
    } else {
        hit as f64 / expected as f64
    };
    CoverageReport {
        steps,
        hit_fns: hit,
        expected_fns: expected,
        fidelity,
    }
}

/// Bucket `CoverageEntry`s by `relative_contract_path` so each
/// function lookup is O(1) over its file's hits instead of O(N) over
/// the whole project.
fn group_coverage_by_path(coverage: &[CoverageEntry]) -> BTreeMap<String, Vec<&CoverageEntry>> {
    let mut by_path: BTreeMap<String, Vec<&CoverageEntry>> = BTreeMap::new();
    for entry in coverage.iter().filter(|e| e.hit_count > 0) {
        by_path
            .entry(entry.relative_contract_path.clone())
            .or_default()
            .push(entry);
    }
    by_path
}

fn resolve_function(callgraph: &CallGraph, step: &SuqenceCallStep) -> Option<Function> {
    if let Some(c) = callgraph
        .contracts
        .values()
        .find(|c| c.name == step.contract)
        && let Some(f) = c.functions.iter().find(|f| f.name == step.function)
    {
        return Some(f.clone());
    }
    if let Some(i) = callgraph
        .interfaces
        .values()
        .find(|i| i.name == step.contract)
        && let Some(f) = i.functions.iter().find(|f| f.name == step.function)
    {
        return Some(f.clone());
    }
    // Loose fallback: any function with this name in any contract /
    // interface, regardless of contract.name. Spec.sequence sometimes
    // names a contract that's the *interface* (e.g. `IPanopticPool`)
    // while the actual implementation lives on `PanopticPool`.
    callgraph
        .contracts
        .values()
        .flat_map(|c| &c.functions)
        .chain(callgraph.interfaces.values().flat_map(|i| &i.functions))
        .find(|f| f.name == step.function)
        .cloned()
}

fn covered_intersects(covered_lines: &[&CoverageEntry], function: &Function) -> bool {
    let lo = function.loc.start_line;
    let hi = function.loc.end_line;
    covered_lines
        .iter()
        .any(|entry| (entry.line_number as usize) >= lo && (entry.line_number as usize) <= hi)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{AuditStateSpecification, SuqenceCallStep};
    use knowdit_repo_model::cg::{Contract, FileChunk, FileLocation};
    use std::collections::BTreeMap;
    use std::path::PathBuf;

    fn make_function(name: &str, path: &str, start: usize, end: usize) -> Function {
        Function {
            id: 1,
            name: name.to_string(),
            args: String::new(),
            relative_file_path: PathBuf::from(path),
            loc: FileLocation {
                start_line: start,
                start_column: 0,
                end_line: end,
                end_column: 0,
            },
            content: None,
            calls: vec![],
            description: None,
        }
    }

    fn make_callgraph_with_one_function() -> CallGraph {
        let mut contracts = BTreeMap::new();
        contracts.insert(
            1,
            Contract {
                id: 1,
                name: "Pool".to_string(),
                relative_file_path: PathBuf::from("contracts/Pool.sol"),
                chunk: FileChunk {
                    loc: FileLocation {
                        start_line: 1,
                        start_column: 0,
                        end_line: 100,
                        end_column: 0,
                    },
                    content: String::new(),
                },
                functions: vec![make_function("dispatch", "contracts/Pool.sol", 30, 50)],
                description: None,
            },
        );
        CallGraph {
            contracts,
            interfaces: BTreeMap::new(),
        }
    }

    fn fake_spec() -> AuditSpecification {
        AuditSpecification {
            setup: AuditStateSpecification::default(),
            pre_attack: AuditStateSpecification::default(),
            post_attack: AuditStateSpecification::default(),
            sequence: vec![SuqenceCallStep {
                contract: "Pool".to_string(),
                function: "dispatch".to_string(),
                intention: String::new(),
            }],
        }
    }

    #[test]
    fn hit_when_covered_line_in_function_range() {
        let cg = make_callgraph_with_one_function();
        let coverage = vec![CoverageEntry {
            relative_contract_path: "contracts/Pool.sol".into(),
            line_number: 35,
            hit_count: 7,
        }];
        let report = collect_report(&fake_spec(), &coverage, &cg);
        assert_eq!(report.expected_fns, 1);
        assert_eq!(report.hit_fns, 1);
        assert!((report.fidelity - 1.0).abs() < 1e-9);
        assert!(report.failure_reason(&AuditThresholds::default()).is_none());
    }

    #[test]
    fn miss_when_no_lines_covered() {
        let cg = make_callgraph_with_one_function();
        let coverage = vec![];
        let report = collect_report(&fake_spec(), &coverage, &cg);
        assert_eq!(report.expected_fns, 1);
        assert_eq!(report.hit_fns, 0);
        assert_eq!(report.fidelity, 0.0);
        let reason = report.failure_reason(&AuditThresholds::default()).unwrap();
        assert!(reason.contains("Pool::dispatch"));
    }

    #[test]
    fn unresolved_steps_dont_count_against_fidelity() {
        let cg = make_callgraph_with_one_function();
        let mut spec = fake_spec();
        spec.sequence.push(SuqenceCallStep {
            contract: "DoesNotExist".to_string(),
            function: "no_such_fn".to_string(),
            intention: String::new(),
        });
        let coverage = vec![CoverageEntry {
            relative_contract_path: "contracts/Pool.sol".into(),
            line_number: 35,
            hit_count: 7,
        }];
        let report = collect_report(&spec, &coverage, &cg);
        assert_eq!(report.expected_fns, 1, "unresolved step excluded");
        assert_eq!(report.hit_fns, 1);
        assert!((report.fidelity - 1.0).abs() < 1e-9);
    }
}
