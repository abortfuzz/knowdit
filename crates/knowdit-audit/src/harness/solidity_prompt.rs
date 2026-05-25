//! Foundry harness agent prompt construction.
//!
//! Split out from [`super::solidity`] to keep the runner focused on data flow
//! and lifecycle. Everything in this module is private to the `harness`
//! parent module.

use std::path::{Path, PathBuf};

use itertools::Itertools;

use super::solidity::{parse_foundry_test_dir, truncate_str};
use crate::spec::LinkInput;
use crate::types::AuditSpecification;

/// Excerpt of the project's foundry config + remapping conventions, surfaced
/// to the agent so it picks the right import paths and test contract layout.
#[derive(Debug, Clone, Default)]
pub(super) struct ProjectConventions {
    foundry_toml_excerpt: String,
    remappings_txt: String,
    /// Existing test files (basenames only) the agent can imitate.
    sample_test_filenames: Vec<String>,
    /// Excerpt from one existing test file's import section, if any.
    sample_test_imports: String,
}

impl ProjectConventions {
    pub(super) async fn load(repo_root: &Path) -> Self {
        let mut me = Self::default();
        if let Ok(text) = tokio::fs::read_to_string(repo_root.join("foundry.toml")).await {
            me.foundry_toml_excerpt = truncate_str(&text, 4_096);
        }
        if let Ok(text) = tokio::fs::read_to_string(repo_root.join("remappings.txt")).await {
            me.remappings_txt = truncate_str(&text, 4_096);
        }
        let test_dir = if let Some(td) = parse_foundry_test_dir(&me.foundry_toml_excerpt) {
            repo_root.join(td)
        } else {
            repo_root.join("test")
        };
        let mut tests: Vec<PathBuf> = Vec::new();
        if let Ok(mut entries) = tokio::fs::read_dir(&test_dir).await {
            while let Ok(Some(e)) = entries.next_entry().await {
                let p = e.path();
                if p.extension().and_then(|s| s.to_str()) == Some("sol") {
                    tests.push(p);
                }
            }
            // Recurse one level deeper too — Panoptic puts tests under
            // test/foundry/core/, etc.
            if let Ok(mut top) = tokio::fs::read_dir(&test_dir).await {
                while let Ok(Some(e)) = top.next_entry().await {
                    let p = e.path();
                    if p.is_dir() {
                        if let Ok(mut sub) = tokio::fs::read_dir(&p).await {
                            while let Ok(Some(e2)) = sub.next_entry().await {
                                let p2 = e2.path();
                                if p2.extension().and_then(|s| s.to_str()) == Some("sol") {
                                    tests.push(p2);
                                }
                            }
                        }
                    }
                }
            }
        }
        tests.sort();
        tests.dedup();
        me.sample_test_filenames = tests
            .iter()
            .take(8)
            .filter_map(|p| p.file_name().and_then(|s| s.to_str()).map(String::from))
            .collect();
        if let Some(first) = tests.first() {
            if let Ok(text) = tokio::fs::read_to_string(first).await {
                let mut imports = String::new();
                for line in text.lines().take(80) {
                    let trimmed = line.trim();
                    if trimmed.starts_with("import ")
                        || trimmed.starts_with("// SPDX")
                        || trimmed.starts_with("pragma ")
                    {
                        imports.push_str(line);
                        imports.push('\n');
                    } else if trimmed.starts_with("contract ") || trimmed.starts_with("abstract ") {
                        break;
                    }
                }
                me.sample_test_imports = truncate_str(&imports, 2_048);
            }
        }
        me
    }
}

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
that will conflict with your harness pragma. Existing project tests use
mainnet pool addresses (forked) for concrete pool instances; for a fuzz
harness you typically only need the interface to type your handler args.

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
   on the most relevant one(s) — usually you want a file that constructs the
   same contracts the spec.setup.contracts mentions. **If an existing
   test's deployment shape matches the spec's `initial state` requirements,
   borrow it.** Adapt parameter values to your spec's invariants, but keep
   the deployment topology that the project's own tests have already
   proven to work.

3. **No on-chain assumptions.** Treat the EVM as completely empty at the
   start of setUp(). If the spec's pre_attack state requires a fact about
   the world (a deployed token at a specific address, a Uniswap pool with
   liquidity, an oracle feed populated), you MUST construct that fact in
   setUp(). Anything you `vm.assume(...)` or implicitly require from
   "production" state will cause the invariant fuzz to abort. The fuzzer
   only sees the EVM you build.

4. For every state variable in spec.setup.states_variables you must
   confirm — by reading its declaring contract — a feasible path to the
   target state in setUp(): either an init/constructor call, an admin
   function, or `stdstore` with explicit justification (and NEVER access
   a private/internal field directly from your harness).

5. spec.sequence is a HINT. You may add adjacent handler entry points
   if they share state with sequence functions and could plausibly drive
   the post_attack condition.

6. Iterate:
   - `list_test_files()` / `read_file(file_path=...)` — survey existing patterns
   - `lookup_call_graph` / `read_function_source` — confirm the exact
     signature of every function you'll call
   - `write_harness_file(filename, content)` — emit/overwrite the .sol
   - `run_forge(match_contract="Test_{spec_id}")` — orchestrator runs
     `forge test` (and auto-runs `forge coverage` when the test exited 0
     with calls > 0). Tool result tells you: compile-or-not, calls,
     reverts, whether the invariant was violated, plus Gate 1 (runtime)
     and Gate 2 (coverage) verdicts.
   - Parse the result: compile error → fix the harness and re-run;
     `setUp()` revert → fix setUp and re-run; `calls=0` ("No tests found"
     or filtered out) → fix discovery/`match-test` and re-run; invariant
     violated → orchestrator will stop you, you're done; no violation
     but Gate 1/2 still complaining → keep iterating.
   - You don't call finalize. The orchestrator decides when to stop
     (violation observed / step budget hit / window full → restart with
     a fresh agent or hard abandon).

# Hard rules

- Harness filename MUST be a basename like `Test_{spec_id}.t.sol`.
- The test contract name MUST be `Test_{spec_id}` so you can pass it to
  `--match-contract`.
- All imports MUST use the project's remappings (see `remappings.txt`
  above). Examples for THIS project:
    `import "forge-std/Test.sol";`
    `import {{X}} from "@contracts/X.sol";`
    `import {{Y}} from "@types/Y.sol";`
  NEVER use `../contracts/...` — the harness file is nested several
  directories deep under the test root and relative paths break.
- Don't declare "done" in chat. The orchestrator stops the loop; you
  just keep iterating until it does. If you genuinely cannot make
  progress (e.g. the spec references contracts that don't exist in
  this project at all), write a short note via the chat — but keep
  trying `write_harness_file` + `run_forge`. Mapper has already
  determined this semantic is in scope; abandon-by-inaction is not a
  valid outcome.
- Specs may reference contracts/state that are RELATED to the project's
  semantic but not literally present. In that case adapt the harness to
  the project's actual contracts.
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
        finding_description = link.finding.description.trim(),
        spec_id = spec_id,
        spec_json = spec_json,
        harness_dir = harness_dir.display(),
        foundry_toml_excerpt = if conv.foundry_toml_excerpt.is_empty() {
            "(no foundry.toml found at repo root)".to_string()
        } else {
            conv.foundry_toml_excerpt.clone()
        },
        remappings_txt = if conv.remappings_txt.is_empty() {
            "(no remappings.txt — rely on foundry.toml `remappings`)".to_string()
        } else {
            conv.remappings_txt.clone()
        },
        sample_test_filenames = if conv.sample_test_filenames.is_empty() {
            "(no existing tests found under the configured test dir)".to_string()
        } else {
            conv.sample_test_filenames
                .iter()
                .map(|s| format!("- {s}"))
                .join("\n")
        },
        sample_test_imports = if conv.sample_test_imports.is_empty() {
            "(no existing test file's imports could be mined)".to_string()
        } else {
            conv.sample_test_imports.clone()
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

/// One-paragraph bootstrap appended to the system prompt when the
/// orchestrator restarts the agent after a window blow-up. Carries
/// the bare-minimum context the new agent needs so it doesn't start
/// from scratch: which file is on disk, and how the last run went.
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
