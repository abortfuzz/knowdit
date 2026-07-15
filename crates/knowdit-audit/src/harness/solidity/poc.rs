//! Deterministic-PoC mode: prompts that tell the agent to author a
//! single `Test_<id>` contract whose `test_…()` function body
//! reproduces the attack deterministically. The post-attack assertion
//! uses the magic prefix `KNOWDIT_POST_ATTACK_REACHED:` so the
//! orchestrator can distinguish "intended exploit reproduction" from
//! "random revert".
//!
//! The actual `write_harness_file` tool is mode-agnostic and lives in
//! [`super::runtime`]; this module only contributes prompt content
//! that `HarnessKind::Poc` dispatches to.

use std::path::Path;

use itertools::Itertools;

use super::utils::{POC_VIOLATION_MARKER, ProjectConventions};
use crate::spec::LinkInput;
use crate::types::AuditSpecification;

pub(super) fn build_system_prompt(
    link: &LinkInput,
    spec: &AuditSpecification,
    spec_id: i32,
    harness_dir: &Path,
    conv: &ProjectConventions,
    coverage_via_ir_unsupported: bool,
) -> String {
    let coverage_via_ir_note = if coverage_via_ir_unsupported {
        "\n\n## Heads-up: viaIR + forge coverage\n\
        This project's solc settings require viaIR, but the available `forge` \
        binary's `coverage` subcommand does NOT support `--force-via-ir`. \
        Coverage compile failures on viaIR projects are **expected** — \
        coverage is informational evidence here, not a gate, so a coverage \
        failure does NOT invalidate a deterministic violation.\n"
    } else {
        ""
    };
    let spec_json =
        serde_json::to_string_pretty(spec).unwrap_or_else(|_| "<unserializable>".into());
    format!(
        r#"You are the Deterministic-PoC Harness agent for a knowledge-driven
smart-contract auditing pipeline.

## Your task

You are given:
- A project semantic (extracted from the current project)
- The historical semantic + finding it was matched to
- An `AuditSpecification` (setup / pre_attack / post_attack / sequence)

Synthesize ONE Solidity test file containing a single
`contract Test_{spec_id} is Test` whose `test_…()` function body
**deterministically reproduces the attack** described by
`spec.sequence`. There is NO Foundry handler, NO `invariant_…`
function, NO fuzzer. You drive every step yourself, then assert
post_attack reachability with the magic-prefix `require`:

```solidity
require(<post_attack_condition>, "{marker} <one-line why this means the bug>");
```

The orchestrator recognises this exact prefix as a real PoC
violation (distinct from a random revert). Without the prefix
your test failing means "broken harness", not "bug found".

The orchestrator drives termination — there is no `finalize` tool.
Each `run_forge` call always runs `forge test --json -vvvvvv`, and
(when the test exits 0 OR reverts with the magic prefix) auto-runs
`forge coverage --report lcov` for evidence. Keep iterating
`write_harness_file` + `run_forge` until the test reverts with the magic
prefix (`violated=true`, `deterministic_violation=true`).{coverage_via_ir_note}

## Project DeFi semantic
- id: {extract_id}
- name: {extract_name}
- definition: {extract_definition}
- description: {extract_description}

## Historical DeFi semantic
- id: {historical_id}
- name: {historical_name}
- definition: {historical_definition}

## Historical finding (the attack you are reproducing)
- id: {finding_id}
- title: {finding_title}
- root_cause: {finding_root_cause}
- description: {finding_description}

## AuditSpecification (spec_id={spec_id})

```json
{spec_json}
```

## Project Foundry conventions (USE THESE — copy/adapt the import paths)

The harness file lives at `{harness_dir}/Test_{spec_id}.t.sol`. The
forge subprocess runs from the project repository root. **Use the
project's own remappings — do NOT write `../contracts/...` style
imports**, they will not resolve.

**Pragma**: copy the EXACT pragma from the sample test below.
Mismatched pragmas trigger `Found incompatible versions` errors.

**Vendored libs**: only import INTERFACES — never concrete
implementations pinned to older pragmas.

`foundry.toml` (excerpt):
```toml
{foundry_toml_excerpt}
```

`remappings.txt`:
```
{remappings_txt}
```

Existing test files in this project (imitate their imports):
{sample_test_filenames}

Excerpt of one existing test's imports:
```solidity
{sample_test_imports}
```

# Output shape

Write ONE `.sol` file with this skeleton:

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.x;
import "forge-std/Test.sol";
import {{<your project's source contracts via remappings>}};

contract Test_{spec_id} is Test {{
    function setUp() public {{
        // Realize spec.setup.contracts (deploy + initialize)
        // Realize spec.setup.states_variables (init paths or stdstore)
        // Stage spec.pre_attack invariants — these MUST hold before the
        // attack begins. If you can't satisfy them, the PoC is invalid.
    }}

    function test_post_attack_state_must_not_be_reachable() public {{
        // Drive spec.sequence STEP BY STEP, in order, using exactly the
        // calls and pranks the spec lists (vm.startPrank / vm.warp /
        // vm.deal as needed). Do NOT introduce random inputs.
        //
        // After the last sequence call, evaluate post_attack:
        bool post_attack_reached = /* compute from spec.post_attack */;
        require(
            post_attack_reached,
            "{marker} <one-line: what was supposed to hold and what is broken>"
        );
    }}
}}
```

# Methodology

1. **Read function signatures carefully** before any call. Wrong arity
   or accessor on a private state var → compile fails.

2. **Find existing setUp() patterns to imitate.** Before writing
   setUp() yourself, call `list_test_files()` and `read_file(...)` on
   the most relevant existing tests. If a project test deploys the
   same contracts the spec.setup mentions, borrow its setUp() shape.

3. **No on-chain assumptions.** Treat the EVM as completely empty at
   the start of setUp(). YOU construct every fact the spec.pre_attack
   requires.

4. **spec.sequence is your recipe, not a hint.** Each entry is a call
   you must issue, in order, with the contract/function/caller as
   named. Don't drop steps — fix the harness instead.

5. **The post_attack assertion is your gate.** Pick a condition
   derived directly from `spec.post_attack`:
   - "balance drained": `require(victim.balance() < expected_min, "{marker} drained ...");`
   - "invariant broken": `require(invariant_holds(), "{marker} invariant ... broke");`
   - "unauthorized access": `require(!auth_check(), "{marker} unauthorized ... succeeded");`
   The free-form reason after the prefix is the one-liner the reflect
   grader sees downstream.

6. Iterate:
   - `list_test_files()` / `read_file(...)` — survey patterns
   - `lookup_call_graph` / `read_function_source` — confirm signatures
   - `write_harness_file(filename, content)` — emit/overwrite the .sol
   - `run_forge(match_contract="Test_{spec_id}", match_test="test_…")` —
     orchestrator runs forge and auto-coverage. Tool result tells you
     compile-or-not, calls, test status, deterministic-violation marker.
   - Parse: compile error → fix; setUp revert → fix; deterministic
     violation observed → orchestrator stops; test passed → either
     bug not reachable from your setUp or your assertion is wrong
     direction — re-check and iterate.

# Hard rules

- Harness filename MUST be a basename like `Test_{spec_id}.t.sol`.
- The test contract name MUST be `Test_{spec_id}` so you can pass it
  to `--match-contract`.
- The PoC entry point MUST start with `test_` and MUST NOT start
  with `invariant_` (that would route through the fuzzer).
- The post-attack assertion MUST use exactly
  `require(<cond>, "{marker} <reason>")`. Use this prefix ONLY for
  the post-attack assertion — other reverts in your test should use
  distinct messages.
- All imports MUST use the project's remappings — never `../contracts/...`.
- Don't declare "done" in chat. The orchestrator decides when to stop.
- Harness is written to: `{harness_dir}` (absolute path on disk).
"#,
        marker = POC_VIOLATION_MARKER,
        extract_id = link.extract_id,
        extract_name = link.extract.name,
        extract_definition = link.extract.definition.trim(),
        extract_description = link.extract.description.trim(),
        historical_id = link.historical_id,
        historical_name = link.historical.name,
        historical_definition = link.historical.definition.trim(),
        finding_id = link.finding_id,
        finding_title = link.finding.title,
        finding_root_cause = link.finding.root_cause.trim(),
        finding_description = link.finding_rendered_description.trim(),
        spec_id = spec_id,
        spec_json = spec_json,
        harness_dir = harness_dir.display(),
        foundry_toml_excerpt = if conv.foundry_toml_excerpt().is_empty() {
            "(no foundry.toml found at repo root)".to_string()
        } else {
            conv.foundry_toml_excerpt().to_string()
        },
        remappings_txt = if conv.remappings_txt().is_empty() {
            "(no remappings.txt — rely on foundry.toml `remappings`)".to_string()
        } else {
            conv.remappings_txt().to_string()
        },
        sample_test_filenames = if conv.sample_test_filenames().is_empty() {
            "(no existing tests found under the configured test dir)".to_string()
        } else {
            conv.sample_test_filenames()
                .iter()
                .map(|s| format!("- {s}"))
                .join("\n")
        },
        sample_test_imports = if conv.sample_test_imports().is_empty() {
            "(no existing test file's imports could be mined)".to_string()
        } else {
            conv.sample_test_imports().to_string()
        },
    )
}

pub(super) fn build_user_prompt(spec_id: i32) -> String {
    format!(
        "Synthesize the deterministic PoC for spec_id={spec_id} per the system prompt.\n\
         Plan briefly out loud, then begin issuing tool calls. The orchestrator \
         decides when to stop — keep iterating `write_harness_file` + `run_forge` \
         until the `test_…` function reverts with the `{marker}` prefix.\n",
        marker = POC_VIOLATION_MARKER,
    )
}

pub(super) fn build_restart_bootstrap(
    harness_filename: Option<&str>,
    last_test_calls: u64,
    last_gate_passed: bool,
    prior_restarts: usize,
) -> String {
    let mut out = String::from("\n\n## Restart context\n\n");
    out.push_str(&format!(
        "This is restart #{}: the previous agent ran out of conversation budget. ",
        prior_restarts + 1
    ));
    match harness_filename {
        Some(name) => out.push_str(&format!(
            "It left a PoC file on disk at `{name}` under the per-spec directory. \
             Read it with `read_file` BEFORE rewriting. "
        )),
        None => out.push_str(
            "It did NOT write any PoC file. Start from scratch using the \
             methodology in the system prompt. ",
        ),
    }
    out.push_str(&format!(
        "Last `run_forge` summary: calls={last_test_calls}, coverage_gate_passed={last_gate_passed}. "
    ));
    if last_test_calls == 0 {
        out.push_str(
            "Zero calls means forge either didn't discover the test_… function \
             or `setUp()` reverted before the test body ran — diagnose that first. ",
        );
    }
    out.push_str(
        "Remember: the post-attack assertion MUST use \
         `require(<cond>, \"KNOWDIT_POST_ATTACK_REACHED: …\")`. ",
    );
    out
}
