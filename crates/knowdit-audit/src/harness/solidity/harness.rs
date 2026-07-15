//! Handler-invariant mode: prompts that tell the agent to author a
//! Foundry handler contract + an invariant test contract. Forge fuzzes
//! the handler entry points; violation = invariant counter-example.
//!
//! The actual `write_harness_file` tool is mode-agnostic and lives in
//! [`super::runtime`]; this module only contributes prompt content
//! that `HarnessKind::Handler` dispatches to.

use std::path::Path;

use itertools::Itertools;

use super::utils::ProjectConventions;
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
        binary's `coverage` subcommand does NOT support `--force-via-ir`. The \
        orchestrator runs `forge coverage` for you automatically after each \
        clean `forge test`; coverage compile failures on viaIR projects are \
        **expected** and the orchestrator records a Gate 2 miss without you \
        needing to do anything. Focus on making the test compile and run.\n"
    } else {
        ""
    };
    let spec_json =
        serde_json::to_string_pretty(spec).unwrap_or_else(|_| "<unserializable>".into());
    format!(
        r#"You are the Foundry Fuzzing Harness Generator agent for a knowledge-driven
smart-contract auditing pipeline.

## Your task

You are given:
- A project semantic (extracted from the current project)
- The historical semantic + finding it was matched to
- An `AuditSpecification` (setup / pre_attack / post_attack / sequence)

Synthesize a single Solidity test file that contains BOTH a Foundry handler
(per the handler-pattern in https://www.getfoundry.sh/guides/invariant-testing#handler-pattern)
AND an invariant test contract. Then call `run_forge` to compile + execute it.

The orchestrator drives termination — there is no `finalize` tool. Each
`run_forge` call always runs `forge test`, and (when the test exits 0 with
calls > 0) automatically runs `forge coverage --report lcov` right after.
You receive both results back in the same tool response. Keep iterating
`write_harness_file` + `run_forge` until **the test reproduces the spec's
post_attack violation** (`violated=true`). The orchestrator stops the loop
on violation, on step-budget exhaustion, or on conversation-window
exhaustion (a fresh agent is then restarted with a short summary of your
last run).{coverage_via_ir_note}

## Project DeFi semantic
- id: {extract_id}
- name: {extract_name}
- definition: {extract_definition}
- description: {extract_description}

## Historical DeFi semantic
- id: {historical_id}
- name: {historical_name}
- definition: {historical_definition}

## Historical finding (use as topic context for the invariant)
- id: {finding_id}
- title: {finding_title}
- root_cause: {finding_root_cause}
- description: {finding_description}

## AuditSpecification (spec_id={spec_id})

```json
{spec_json}
```

## Project Foundry conventions (USE THESE — copy/adapt the import paths)

The harness file lives at `{harness_dir}/Test_{spec_id}.t.sol` (a per-spec
subdirectory; concurrent specs each get their own dir so they don't share
a compile graph). The forge subprocess runs from the project repository
root. **Use the project's own remappings — do NOT write `../contracts/...`
style imports**, they will not resolve.

**Pragma**: copy the EXACT pragma from the sample test below (e.g.
`pragma solidity ^0.8.24;`). Mismatched pragmas trigger
`Found incompatible versions` errors against the project's vendored libs.

**Vendored libs**: only import INTERFACES (e.g.
`import {{IUniswapV3Pool}} from "v3-core/interfaces/IUniswapV3Pool.sol";`),
NEVER concrete implementations like `UniswapV3Pool.sol` /
`UniswapV3Factory.sol` — those are pinned to older pragmas (e.g. `=0.8.12`)
that will conflict with your harness pragma.

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

contract HandlerFor_<SemanticName> is Test {{
    // bounded wrappers around project semantic functions, using uint256
    // ghost variables / clamping as the Foundry handler pattern demands
}}

contract Test_{spec_id} is Test {{
    HandlerFor_<...> internal handler;

    function setUp() public {{
        // realize spec.setup.contracts (deploy + initialize)
        // realize spec.setup.states_variables (init paths or stdstore)
        // optionally enforce spec.pre_attack invariants here at the end
        handler = new HandlerFor_<...>(...);
        targetContract(address(handler));
    }}

    function invariant_no_post_attack_state() public view {{
        // ENCODE ¬post_attack: assert FALSE the broken state described
        // by spec.post_attack. Fuzzer hitting `false` == bug reproduced.
    }}
}}
```

# Methodology

1. **Read function signatures carefully**. The signature index in your
   memory shows the FULL Solidity signature (visibility, mutability,
   return types, full argument types) for every function. Read those
   exactly — do NOT invent constructor arities, do NOT assume `public`
   visibility on members marked `internal`/`private`. If you call
   something with the wrong arity or accessor on a private state var,
   the harness will not compile.

2. **Find existing setUp() patterns to imitate.** Before writing setUp()
   yourself, call `list_test_files()` to enumerate the project's existing
   foundry/hardhat tests + deploy scripts, then `read_file(file_path=...)`
   on the most relevant one(s). If an existing test's deployment shape
   matches the spec's `initial state` requirements, borrow it.

3. **No on-chain assumptions.** Treat the EVM as completely empty at the
   start of setUp(). Anything you `vm.assume(...)` will cause the
   invariant fuzz to abort. The fuzzer only sees the EVM you build.

4. For every state variable in spec.setup.states_variables you must
   confirm — by reading its declaring contract — a feasible path to the
   target state in setUp().

5. spec.sequence is a HINT. You may add adjacent handler entry points
   if they share state with sequence functions and could plausibly drive
   the post_attack condition.

6. Iterate:
   - `list_test_files()` / `read_file(file_path=...)` — survey patterns
   - `lookup_call_graph` / `read_function_source` — confirm signatures
   - `write_harness_file(filename, content)` — emit/overwrite the .sol
   - `run_forge(match_contract="Test_{spec_id}")` — the orchestrator
     runs `forge test` and (when the test exited 0 with calls > 0) auto-
     runs `forge coverage`.
   - Parse the result; compile error → fix; setUp revert → fix; calls=0
     → fix discovery; invariant violated → orchestrator stops you.

# Hard rules

- Harness filename MUST be a basename like `Test_{spec_id}.t.sol`.
- The test contract name MUST be `Test_{spec_id}` so you can pass it to
  `--match-contract`.
- All imports MUST use the project's remappings — never `../contracts/...`.
- Don't declare "done" in chat. The orchestrator decides when to stop.
- Harness is written to: `{harness_dir}` (absolute path on disk).
"#,
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
        "Synthesize the Foundry harness for spec_id={spec_id} per the system prompt.\n\
         Plan briefly out loud, then begin issuing tool calls. The orchestrator \
         decides when to stop — just keep iterating `write_harness_file` + \
         `run_forge` until the invariant is violated or it pulls the plug.\n"
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
            "It left a harness on disk at `{name}` under the per-spec directory. \
             Read it with `read_file` BEFORE rewriting — the previous agent's \
             output may be salvageable. "
        )),
        None => out.push_str(
            "It did NOT write any harness file. Start from scratch using the \
             methodology in the system prompt. ",
        ),
    }
    out.push_str(&format!(
        "Last `run_forge` summary: calls={last_test_calls}, coverage_gate_passed={last_gate_passed}. "
    ));
    if last_test_calls == 0 {
        out.push_str(
            "Zero calls means forge either didn't discover the test or `setUp()` \
             reverted before any sequence call — diagnose that first. ",
        );
    } else if !last_gate_passed {
        out.push_str(
            "Calls > 0 but coverage gate didn't pass — the handler is touching \
             too few of the spec's functions. Add more handler entry points or \
             unblock the ones that revert. ",
        );
    }
    out
}
