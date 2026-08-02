//! Prompt construction for the Specification Generator agent.
//!
//!
//! Split out of `spec.rs` (which owns the agent loop, tools, draft state,
//! and DB plumbing) so the large prompt strings live in one focused place
//! — the same convention as `reflect/prompt.rs`. Only the system / user /
//! regen-feedback builders are exposed (`pub(super)`); their callers stay
//! in `super`.

use knowdit_kg::text::truncate_text;
use knowdit_kg_model::ExtractedFunction;
use knowdit_kg_model::audit_finding::FindingSeverity;
use knowdit_repo_model::ProjectProfile;

use super::{
    AuditStatusSummary, LinkInput, LinkSource, ProjectIndex, SpecRegenMode, StatusRenderCaps,
};

/// Frame the resident project source as the opening section of the gen-spec
/// system prompt.
///
/// Placed ahead of every other section because it is identical for every link
/// in the run, and because the sections below it keep their existing order —
/// the source is added, nothing is rearranged.
///
/// `omitted` names the project contracts that did not fit the budget. Naming
/// them is load-bearing: an agent that reads this section as the complete
/// project will conclude a missing contract does not exist rather than fetching
/// it, and abandon the link on that basis.
pub(super) fn build_resident_source_block(source: &str, omitted: &[String]) -> String {
    let scope = match omitted.is_empty() {
        true => "Every contract and interface the project defines is here, whole bodies, nothing \
                 elided."
            .to_string(),
        false => format!(
            "Most of the project is here, whole bodies, nothing elided — but {} of its contracts \
             did not fit and are NOT below: {}. Those still exist; fetch them with \
             `read_contract_source` / `read_function_source`, and your signature-index memory \
             covers them.",
            omitted.len(),
            omitted.join(", "),
        ),
    };
    format!(
        "# Project source\n\n\
         {scope}\n\n\
         Also NOT below: vendored dependencies (OpenZeppelin and friends), tests, scripts and \
         deploy code. `read_contract_source` / `read_function_source` reach those too — use them \
         for a dependency whose exact behaviour your reasoning turns on, not for anything already \
         printed below. Use `lookup_call_graph` / `lookup_state_variable_xrefs` as before for \
         relations the source does not spell out.\n\n\
         {source}\n\
         # End of project source\n\n"
    )
}

pub(super) fn build_regen_prompt_extension(mode: &SpecRegenMode, feedback: &str) -> String {
    match mode {
        SpecRegenMode::Patch(prior_spec) => {
            let prior_json = serde_json::to_string_pretty(prior_spec)
                .unwrap_or_else(|_| "<unserializable>".into());
            format!(
                "## Prior attempt feedback (this is a spec regen — patch mode)\n\
                 \n\
                 The previously-committed spec for this (extract, finding) pair was \
                 classified `IncompleteSpecification` by the validator.\n\
                 \n\
                 Reason:\n{feedback}\n\
                 \n\
                 Previous spec (JSON):\n```json\n{prior_json}\n```\n\
                 \n\
                 Patch the spec by issuing the appropriate tool calls to address the \
                 issue above. Don't commit the same spec — it's already known to be \
                 unrealizable. If the previous spec is fundamentally wrong (wrong \
                 contracts, unreachable state), produce a structurally different spec \
                 rather than tweaking what's there."
            )
        }
        SpecRegenMode::FromScratch => format!(
            "## Prior attempt feedback (this is a spec regen — from-scratch mode)\n\
             \n\
             The previously-committed specs for this (extract, finding) pair were \
             repeatedly classified `IncompleteSpecification` after multiple patch \
             attempts. The history is being discarded; resynthesize from the \
             knowledge graph.\n\
             \n\
             Why we're restarting:\n{feedback}\n\
             \n\
             Approach this as a fresh spec-generation task. Use the lookup tools to \
             read the relevant project contracts, and produce a spec that's grounded \
             in actual project shape rather than continuing to refine a structurally-\
             wrong starting point."
        ),
    }
}

/// Task framing and finding-section header for one link source: a Knowledge
/// Mapper topic hint (explore for related issues) vs an externally-reported
/// finding (validate this specific issue). The two halves land in different
/// messages — the framing in the system prompt, the header on the link block —
/// so they are produced together to stay in step.
fn link_framing(source: LinkSource) -> (&'static str, &'static str) {
    match source {
        LinkSource::Mapper => (
            "You are given a `(project_semantic, historical_semantic, historical_finding)` link from the Knowledge Mapper. The historical finding is a *topic hint* drawn from another project — it likely will not fit the current project verbatim. **Your task is to use the historical finding as a starting point to look for any plausibly related issue inside the matched project semantic, and emit `AuditSpecification`(s) describing those issues.** A committed spec only needs to be *related* to the historical finding (same root-cause family, same kind of state corruption, same exploit shape, or any concrete generalization/specialization of its mechanism). It does NOT have to be a verbatim reproduction.",
            "## Historical finding (use as topic hint, not strict template)",
        ),
        LinkSource::External => (
            "The finding below was **reported against this exact project** (e.g. by an external audit) and localized to the project semantic below. **Your task is to emit `AuditSpecification`(s) that reproduce this specific reported issue on the current code**, encoding its reported impact as the post_attack invariant. This is a concrete claim to validate — NOT a topic hint to generalize from: stay faithful to the reported root cause and the named target functions. If, after reading the code, the issue genuinely cannot occur, `abandoned` with the reason is the correct outcome (it documents that the report does not reproduce).",
            "## Reported finding (validate this specific issue)",
        ),
    }
}

/// The run-invariant half of the gen-spec prompt: role, task framing, project
/// profile, and the whole methodology.
///
/// Deliberately carries nothing that varies per link — that lives in
/// [`build_link_prompt`], which arrives as a conversation message instead. The
/// split is what makes the tool definitions plus this entire prompt one stable
/// prefix that every link in the run shares, so it is written to the model's
/// prompt cache once rather than re-sent at full price for each of them.
pub(super) fn build_system_prompt(source: LinkSource, profile: Option<&ProjectProfile>) -> String {
    let (task_paragraph, _) = link_framing(source);
    // The profile is what the project says it is, written before any link ran.
    // It is the only place the agent learns the project's declared boundaries —
    // "no interest calculation, not an AMM" — which the code cannot state and
    // which otherwise costs a whole pipeline to discover per link.
    //
    // The caveat is load-bearing: without it the "does NOT implement" list reads
    // as permission to abandon, and gen-spec's abandon rate rises sharply from
    // the very first link (measured on tare: 51% over the first 50 links against
    // 36% for the same links without the profile).
    let profile_block = match profile {
        Some(p) => format!(
            "\n{}\nThis describes what the project IS, to save you rediscovering it. It is a \
             framing aid, NOT a scope filter: the \"does NOT implement\" list rules out whole \
             product areas (an AMM curve in a project that has no AMM), never a defect class. \
             Access control, accounting, rounding, reentrancy, and upgrade/migration bugs live \
             in every project regardless of what it declines to be, and the historical finding \
             you were given is a topic hint to explore — not a feature that must exist here \
             verbatim. Never `finalize(status=\"abandoned\")` on the strength of this section.\n",
            p.render_for_prompt()
        ),
        None => String::new(),
    };
    format!(
        r#"You are the Specification Generator agent for a knowledge-driven Solidity smart-contract auditing pipeline.

## Your task

{task_paragraph}

You operate per-link. Everything in this system prompt is identical for every link in the run; the link you are actually working — the project semantic, the historical semantic it matched, and the historical finding — arrives in the messages below, together with what this audit has already settled.
{profile_block}

# Audit-specification model

An `AuditSpecification` defines:

1. **Setup state** — outcome of contract deployment + initial state. State-variable invariants describe what must hold before any real transaction. Contract invariants describe what contracts must exist / be configured.
2. **Pre-vuln state** — state immediately before the issue is triggered. The setup may already satisfy this; if so, leave constraints empty.
3. **Post-vuln state** — state after the issue manifests. Invariants here are what the harness should check (a violated property, an unexpected balance/share/state delta, a stuck/locked condition, etc).
4. **Call sequence** — the core sequence of contract calls that, applied to a system in pre-vuln state, drives the post-vuln state.

A spec does not have to be an *exploit*. It may be:
- A reproduction of the historical exploit, adapted to this project's contracts.
- A *related* issue you found while exploring around the historical finding's topic (e.g. the same kind of accounting drift in a different function, an analogous reentrancy window, a similar invariant break under different inputs).
- A *latent* property whose violation would have the same impact family as the historical finding, even if the exact root cause differs.

If you find more than one plausible scenario for one link, commit each as a separate spec.

# `post_attack.description` contract — read carefully

This field is the most carefully constrained one. The verdict-grader downstream uses it to decide whether the harness reproduces a *real bug* or merely walks a *documented intended path*; a sloppy `post_attack` description is the #1 cause of false-positive `ValidFinding` verdicts. Get this wrong and your whole spec turns into noise.

## Required structure (three parts, all mandatory)

1. **Project's promised state.** Cite a specific `<file:contract.function>` whose NatSpec / inline comments / explicit `require` / clearly documented invariant says state `aaaa` should hold after the sequence. Example: *"Timelock.executeWhitelisted at src/Timelock.sol:496 promises that any executed payload's `[startIndex, endIndex]` slice matches one of the recorded check hashes."*
2. **Attacked state — what actually reaches.** State the concrete value `bbbb` that the attack produces. Example: *"After the sequence, _calldataList for (target, selector) contains two overlapping ranges, and the slice for one of them is silently dropped, so checkCalldata returns true on a payload that no whitelisted hash actually matches."*
3. **Concrete bad consequence.** A specific protocol-impact statement: funds drained, fees stolen, hot signer privilege escalated, reentrancy window opened, accounting drift compounding, indefinite DoS, key invariant broken in a way an attacker monetises, etc. Without a concrete loss/exposure the spec is noise even if it commits. Example: *"A hot signer can route arbitrary value-bearing calldata through executeWhitelisted past the whitelist, draining safe-managed funds; severity Medium because requires a hot-signer role but no further preconditions."*

The description is your reasoning. The **machine-checked proof** is the `post_attack` state-variable / contract invariants: `commit_specification` requires at least one of them, and every name you reference there (and in `setup` / `pre_attack` / `sequence`) is grounded against the project — unknown identifiers are rejected at the tool call, not at commit. Encode the violated property as a concrete `post_attack` invariant, don't leave it only in prose.

## Hard exclusions

- ✘ **Documented intended behaviour is NOT a `post_attack` target.** Before writing `post_attack`, read the relevant function's source comments / NatSpec / `require` reasons. If the source explicitly documents the post-state you're describing, the spec is invalid — that's the project's design, not a bug.
  - Concrete example: *"After updatePauseDuration, pauseStartTime is reset to 0"* is **REJECTED** because `ConfigurablePause._updatePauseDuration` carries the comment `/// if the contract was already paused, reset the pauseStartTime to 0 so that this function cannot pause the contract again` — the reset is the project's deliberate mitigation, not an attack outcome.
  - Concrete example: *"RecoverySpellFactory accepts `recoveryThreshold < threshold`"* is **REJECTED** because `_paramChecks` only requires `recoveryThreshold <= owners.length` and the project nowhere promises `recoveryThreshold >= threshold` — the spec invented a constraint the project never made.
- ✘ **No vague divergence.** *"may be inconsistent"*, *"could diverge"*, *"may misreport"*, *"semantically unsafe"* with no concrete value attached are all rejected.
- ✘ **No reverse-engineered specs from the post-state up.** Don't pick a state, then write `setup`/`pre_attack`/`sequence` that reach it. Work top-down: read the project source, find an explicit promise, find a path that breaks the promise, then `post_attack` writes itself.

## Self-check before `commit_specification`

Re-read your `post_attack.description` and answer YES to every question:
1. Did I cite a specific project `<file:contract.function>` whose code or comments establish the expected state?
2. Did I name the concrete attacked state (a specific value, mapping entry, balance change, role table, etc.) — not a vague *"becomes inconsistent"*?
3. Did I name a concrete bad consequence (drain / loss / DoS / bypass / accounting drift) the attacker monetises?
4. Did I verify the project source does NOT explicitly document the post-state as intended (no NatSpec / inline comment that says *"this clears X"*)?

5. Did I encode the violated property as at least one concrete `post_attack` state-variable or contract invariant (not just prose)?

If any answer is NO, rewrite before committing. `commit_specification` requires a non-empty `summary`, at least one `post_attack` invariant, and a non-empty call sequence.

# Methodology

**Start from the project semantic — not the historical finding.**

1. **Enumerate the matched semantic's surface area.** Use `list_memories` to find the entries for the project semantic's contracts (the `functions` field of the project semantic and the `category` are your starting hints). For each relevant contract, use `read_memory` to load its *signature index* — it lists state variables (own + inherited) and every function's signature plus outgoing calls. Bodies are NOT inlined. Build a mental map of: which functions belong to this semantic, what state they read/write, what other contracts they call into.

2. **Use `lookup_call_graph` and `lookup_state_variable_xrefs`** to learn which functions are upstream/downstream of the ones in your semantic, and which functions read or write a given state variable. Follow these edges outward — anything the historical finding could plausibly relate to is fair game.

3. **Read function bodies on demand.** Prefer `read_function_source(contract, function)` for a single function — much cheaper than a whole file. Use `read_contract_source(contract)` only when you really need surrounding file context (modifiers, imports, struct layouts). Avoid re-reading the same big file.

4. **Treat the historical finding as a hypothesis seed.** Read its root_cause, patterns, exploits as topic hints. Then ask:
   - Does the project's matched semantic have analogous functions / state variables / external boundaries?
   - Could a similar mechanism (same shape of accounting error, same reentrancy window class, same invariant violation, same access-control gap, same arithmetic edge case) exist *anywhere related* in this semantic — even if the surface details differ?
   - Are there nearby functions that share state with the matched semantic and exhibit a related class of issue?
   You are encouraged to broaden the search to any function whose behavior is *topically related* to the historical finding's root cause, not just functions that exactly mirror the historical exploit.

5. **Build the spec field by field via tool calls.** Stage = `setup` / `pre_attack` / `post_attack`. The same draft is mutated in place; nothing is committed until `commit_specification`. After committing, the draft resets so you can build another spec for the same link.

6. **Finalize.** Call `finalize` exactly once — `status="completed"` if you committed ≥1 spec, `status="abandoned"` only under the strict criteria below.

# Abandon criteria (strict)

You may only `finalize(status="abandoned")` after you have **read at least the relevant function bodies** in the matched semantic and *one* of these is concretely demonstrable:

- The functionality the finding requires (e.g. a specific contract role, an external call shape, a particular state variable, a particular flow) does **not exist anywhere reachable from the project semantic**, and you have shown which lookups you tried.
- The finding's exact issue is *clearly already fixed* in the project (e.g. the unsafe call has a `nonReentrant` modifier verified by reading the body, the missing check is present, the unbounded loop has an explicit cap, etc.) and there is no analogous issue in nearby functions you read.

The `abort_reason` must cite the specific contracts/functions you inspected and what you found there. **Do NOT abandon on a hunch or because the historical surface details don't line up — when in doubt, look for a related issue and commit it.** Mapper has already determined the project semantic is in scope; your job is to harvest *any* related issue, not to gate on exact reproduction.

# Tool rules

- All spec-building tools (`update_state_description`, `add_state_variable_constraint`, `add_contract_constraint`, `set_call_sequence`) edit the current draft. Later calls overwrite earlier values for the same field.
- **Grounding is enforced at the tool call.** `add_contract_constraint`, `add_state_variable_constraint`, and `set_call_sequence` reject any name that is neither a real project artifact nor a declared auxiliary one — and on rejection the draft is left unchanged. Use `lookup_call_graph` / `lookup_state_variable_xrefs` to find the real name, fix it, and retry.
- **Auxiliary (helper) contracts.** The PoC often needs a contract that does NOT exist in the project — an attacker contract, a malicious callback, a mock token. Declare it with `add_aux_contract(name, purpose)`, declare each of its state variables with `add_aux_contract_state(contract, name, solidity_type, purpose)`, then reference it like any project contract: as a `sequence` step's contract, an `add_contract_constraint` target, or an `AuxContract.fieldName` state-variable key. You must declare an auxiliary contract before referencing it. Its name must not collide with a real project contract.
- `set_call_sequence` replaces the whole sequence each call; build it up in one call. If any step is rejected, the whole call is rejected and the previous sequence stays.
- `commit_specification` takes a required `summary` (one or two sentences on the overall vulnerable behavior). It is idempotent per draft — don't call it twice for the same draft. After commit, the draft is cleared.
- Memory write/update/delete tools are available, but the preloaded per-contract signature indexes are read-only context; do not modify them. You may write your own short-term notes.

# Hard rules

- You MUST end with `finalize`. Without it the runtime records the link as abandoned.
- Be specific about state variables: prefer `Contract.fieldName` keys when the same field name exists on multiple contracts. A state variable on an auxiliary contract MUST use the `AuxContract.fieldName` form.
- Project contracts, functions, and state variables must be *real* names from this project — they are grounded against the project and a fictional name is rejected at the tool call. Don't try to make a spec stick by inventing a project name.
- A contract the PoC has to deploy itself (attacker / callback / mock) is legitimate — but declare it as an auxiliary contract (`add_aux_contract` + `add_aux_contract_state`) instead of pretending it's a project contract. Once declared it can appear in `setup.contracts`, in invariants, and in the `sequence` just like a project contract.
- In `sequence`, use exact project contract/function names from the function anchors or `lookup_call_graph` results. If the runtime object is a proxy or module-composed wallet, name the concrete module function that actually appears in source, such as `ERC4337v07.executeUserOp`, `Calls.selfExecute`, `Hooks.fallback`, or `Implementation.updateImplementation`.
- A committed spec must be *defensible*: you can name the project functions in its sequence and the state variables in its invariants. But it does NOT need to be a verbatim reproduction of the historical finding — `related to` is enough.
"#,
        profile_block = profile_block,
    )
}

fn format_severity(s: FindingSeverity) -> &'static str {
    match s {
        FindingSeverity::High => "High",
        FindingSeverity::Medium => "Medium",
        FindingSeverity::Low => "Low",
    }
}

/// Render the audit-status block the gen-spec prompt embeds — both what has
/// been reported and what has been ruled out, under one shared budget.
///
/// Lives here rather than next to the struct so the wording, the per-field
/// truncation, and the prompt that consumes them all stay in one file.
impl AuditStatusSummary {
    pub fn render(&self, caps: &StatusRenderCaps) -> String {
        if self.is_empty() {
            return String::new();
        }
        let mut out = String::new();
        out.push_str(
            "# What this audit has already settled\n\n\
             Other agents are working this project in parallel and have covered the ground below. \
             This is here to point your search somewhere new — it is NOT a filter, and NOT an \
             abandon criterion. Committing a spec never requires clearing anything with this \
             list, and no entry below is grounds for `finalize(status=\"abandoned\")`; the strict \
             criteria in your system prompt still govern that, unchanged. If everything you \
             happened to look at first is covered here, that means you have not looked far \
             enough yet — widen the search, do not give up on the link.\n",
        );
        self.render_reported(caps, &mut out);
        self.render_ruled_out(caps, &mut out);
        out
    }

    /// Bugs the report already contains. Under a cap the NEWEST are kept: a run
    /// reports its coarsest findings early and its subtler ones late, and the
    /// subtle ones are what an agent is most likely to re-derive.
    fn render_reported(&self, caps: &StatusRenderCaps, out: &mut String) {
        if self.reported.is_empty() {
            return;
        }
        let skipped = self.reported.len().saturating_sub(caps.max_reported);
        out.push_str("\n## Already reported — do NOT re-report these\n\n");
        for f in &self.reported[skipped..] {
            out.push_str(&format!(
                "- [#{}] {}\n    where: {}.{}\n    root cause: {}\n",
                f.id,
                f.title.trim(),
                f.primary_contract,
                f.primary_function,
                truncate_text(f.root_cause.trim(), caps.field_chars),
            ));
        }
        if skipped > 0 {
            out.push_str(&format!(
                "- (+{skipped} older reported finding(s) not listed; the report already covers \
                 more than what you see here)\n"
            ));
        }
        out.push_str(
            "\nA spec that restates one of these adds nothing to this audit, however real it is. \
             Treat them as covered ground and prefer a DIFFERENT defect, even in the same contract \
             or the same function — a function that already has one reported bug very often has \
             others (a missing zero check and a missing equality check in one setter are two \
             findings, not one). Only if you find nothing else at all should you fall back to \
             `finalize(status=\"abandoned\")`, and then say which of these already covered what \
             you saw.\n",
        );
    }

    /// Directions a reviewer already investigated and closed. Under a cap the
    /// most-repeated are kept, since those are the walls agents keep hitting.
    fn render_ruled_out(&self, caps: &StatusRenderCaps, out: &mut String) {
        if self.ruled_out.is_empty() {
            return;
        }
        let shown = self.ruled_out.len().min(caps.max_ruled_out);
        out.push_str("\n## Already ruled out — established facts about THIS project\n\n");
        for c in &self.ruled_out[..shown] {
            out.push_str(&format!(
                "- {}\n",
                truncate_text(c.claim.trim(), caps.field_chars)
            ));
            let evidence = c.evidence.trim();
            if !evidence.is_empty() {
                out.push_str(&format!(
                    "    basis: {}\n",
                    truncate_text(evidence, caps.field_chars)
                ));
            }
        }
        let skipped = self.ruled_out.len().saturating_sub(shown);
        if skipped > 0 {
            out.push_str(&format!(
                "- (+{skipped} further conclusion(s) not listed, each covering fewer cases than \
                 those above)\n"
            ));
        }
        out.push_str(
            "\nEach line is a fact about this project that a reviewer established with the full \
             code in hand, after an agent spent a whole pipeline arguing the opposite. One spec — \
             the spec whose ONLY claim to being a bug is the thing a line here contradicts — is \
             not worth writing. Everything else still is.\n\
             \n\
             Read each line as narrowly as it is written, and only against the exact claim it \
             makes. A trusted role being allowed to do X does not make the contract it operates \
             on safe. An accepted token assumption does not close the accounting built on top of \
             it. A documented migration procedure does not mean every function it touches is \
             correct. The overwhelmingly common case is that a defect near one of these facts is \
             NOT covered by it — a different missing check, a different caller reaching the same \
             state, an ordering the fact never speaks to. Treat these as narrow carve-outs in a \
             search space you should still be exploring, not as a map of where the bugs aren't.\n\
             \n\
             A line ending in `…` was shortened for space; its qualifying clause is missing, so \
             read it as narrower than it appears, never broader.\n\
             \n\
             If you believe one of these facts is simply wrong, you need evidence from the code \
             that the reviewer did not have — say so in the spec rather than restating the claim \
             it already rejected.\n",
        );
    }
}

/// What the run has already settled, as its own conversation message.
///
/// Peers working the same contract have no other way to know what has already
/// been covered, and left blind they all converge on that contract's most
/// salient defect (~8.5 links per distinct bug on the metric-* baselines) and
/// re-argue the same rejections (73% of all verdicts on a full tare run).
/// Guidance, not a filter: it never forbids committing a spec, it only says
/// which ground is already covered.
///
/// Separate from [`build_link_prompt`] because it changes on a different clock:
/// the same summary is shared by every link scheduled against one snapshot,
/// while the link block differs for all of them.
pub(super) fn build_status_prompt(status_summary: &str) -> String {
    match status_summary.trim().is_empty() {
        true => "# What this audit has already settled\n\nNothing yet — you are early in the run, so no ground has been covered by a peer.\n".to_string(),
        false => format!("{}\n", status_summary.trim_end()),
    }
}

/// The per-link half of the gen-spec prompt: which link to work, and where to
/// start. Sent as a conversation message rather than as part of the system
/// prompt so that everything ahead of it — the tool definitions and the whole
/// of [`build_system_prompt`] — stays byte-identical across the run.
///
/// `resident_source` selects the opening moves: with the project source in the
/// system prompt there is no signature-index memory and no source-reading tools
/// to suggest, so pointing at them would send the agent after tools it does not
/// have.
pub(super) fn build_link_prompt(
    link: &LinkInput,
    source: LinkSource,
    project_index: &ProjectIndex,
    resident_source: bool,
    extension: Option<&str>,
) -> String {
    let extract = &link.extract;
    let historical = &link.historical;
    let finding = &link.finding;
    let (_, finding_header) = link_framing(source);
    let extract_functions = render_extracted_functions(&extract.functions);
    let first_moves = match resident_source {
        true => {
            "1. Find the contracts named in \"Project semantic function anchors\" in the project source at the top of your system prompt, and read the bodies that belong to this semantic. If one of them is listed there as not fitting, fetch it with `read_contract_source`.\n\
                 2. Follow `lookup_call_graph` edges and `lookup_state_variable_xrefs` to surface every function in or near the semantic that could share the historical finding's failure mode (same root-cause family, same kind of state corruption, same exploit class) — those relations are not spelled out by the source itself.\n\
                 3. Commit one spec per plausibly-related issue you find. The spec only needs to be *related to* the historical finding, not a verbatim reproduction."
        }
        false => {
            "1. `list_memories` to see what's available.\n\
                  2. `read_memory` on the contracts listed in \"Project semantic function anchors\" — that is your anchor.\n\
                  3. From there, follow `lookup_call_graph` edges and `lookup_state_variable_xrefs` to surface every function in or near the semantic that could share the historical finding's failure mode (same root-cause family, same kind of state corruption, same exploit class).\n\
                  4. `read_function_source(contract, function)` for the bodies you actually need to reason about. Avoid loading the same big file twice — the signature index already tells you what each function calls.\n\
                  5. Commit one spec per plausibly-related issue you find. The spec only needs to be *related to* the historical finding, not a verbatim reproduction."
        }
    };
    let index_block = match resident_source {
        true => String::new(),
        false => format!(
            "\nProject static-analysis short-term memory: {} contract entr(ies), {} interface entr(ies). Titles follow `relative_file_path:Contract:line:col`.\n",
            project_index.call_graph.contracts.len(),
            project_index.call_graph.interfaces.len(),
        ),
    };
    let extension_block = match extension {
        Some(text) => format!("\n{text}\n"),
        None => String::new(),
    };
    format!(
        r#"# Your link

Explore the matched project semantic for any issue *related to* the historical finding below, then commit AuditSpecification(s) for what you find.

## Project DeFi semantic (extracted from the current project)
- id: {extract_id}
- category: {extract_category}
- name: {extract_name}
- definition: {extract_definition}
- description: {extract_description}

### Project semantic function anchors (real names from this project)
Use these as the primary source of truth for `setup.contracts` keys and `sequence` contract/function names. They are real extracted project functions, not conceptual labels:
{extract_functions}

## Historical DeFi semantic (from the knowledge graph; matched as encompassing the project's semantic)
- id: {historical_id}
- category: {historical_category}
- name: {historical_name}
- definition: {historical_definition}
- description: {historical_description}

{finding_header}
- id: {finding_id}
- title: {finding_title}
- severity: {finding_severity}
- root cause: {finding_root_cause}
- description: {finding_description}
- vulnerability patterns: {finding_patterns}
- known exploits: {finding_exploits}
{index_block}{extension_block}
Suggested first moves:
{first_moves}

Reason briefly out loud, then start issuing tool calls. Keep `finalize` for the very end. Per the system prompt, abandoning requires showing which functions you read and why the finding has no related issue here.

Link summary: extract_id={extract_id}, historical_id={historical_id}, finding_id={finding_id}.
"#,
        extract_id = link.extract_id,
        extract_category = extract.category.as_str(),
        extract_name = extract.name,
        extract_definition = extract.definition.trim(),
        extract_description = extract.description.trim(),
        extract_functions = extract_functions,
        historical_id = link.historical_id,
        historical_category = historical.category.as_str(),
        historical_name = historical.name,
        historical_definition = historical.definition.trim(),
        historical_description = link.historical_rendered_description.trim(),
        finding_header = finding_header,
        finding_id = link.finding_id,
        finding_title = finding.title,
        finding_severity = format_severity(finding.severity),
        finding_root_cause = finding.root_cause.trim(),
        finding_description = link.finding_rendered_description.trim(),
        finding_patterns = link.finding_rendered_patterns.trim(),
        finding_exploits = link.finding_rendered_exploits.trim(),
        index_block = index_block,
        extension_block = extension_block,
        first_moves = first_moves,
    )
}

/// Render `link.extract.functions` as the anchor list embedded in the
/// gen-specs prompts. Each line is `- \`{contract}\`.\`{name}\` —
/// \`{signature or "(no recorded signature)"}\``. Empty input emits a
/// single fallback bullet so the prompt slot is never blank.
fn render_extracted_functions(functions: &[ExtractedFunction]) -> String {
    if functions.is_empty() {
        return "- (none recorded; use lookup_call_graph before naming contracts/functions)\n"
            .to_string();
    }
    let mut out = String::new();
    for f in functions {
        let signature = f
            .signature
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .unwrap_or("(no recorded signature)");
        out.push_str(&format!(
            "- `{}`.`{}` — `{}`\n",
            f.contract, f.name, signature
        ));
    }
    out
}

// ---------------------------------------------------------------------------
// Link novelty judge
// ---------------------------------------------------------------------------

/// Assemble the novelty judge's system prompt: the rubric wrapped around a
/// rendered snapshot of the project profile, so the judge weighs candidates
/// against what this project actually is. Lives here with the rest of the
/// spec-phase prompt text so the wording is editable without touching the
/// judge's wiring — same convention as [`build_system_prompt`].
pub(super) fn novelty_system(profile: &ProjectProfile, language_prompt_prefix: &str) -> String {
    let mut block = String::new();
    let prefix = language_prompt_prefix.trim();
    if !prefix.is_empty() {
        block.push_str(prefix);
        block.push_str("\n\n");
    }
    block.push_str(&profile.render_for_prompt());
    format!("{NOVELTY_PREAMBLE}\n\n{block}{NOVELTY_RUBRIC}")
}

pub(super) const NOVELTY_PREAMBLE: &str = "You are the Link Novelty Judge for an agentic smart-contract auditing pipeline. The pipeline expands historical vulnerability knowledge into candidate links and runs an expensive agent on each one, which tries to reproduce that historical defect against THIS project. Many unrelated historical findings converge on the same project bug, so most of a run's budget is spent rediscovering findings the report already contains.\n\nYou are shown the canonical findings this run has ALREADY reported and a batch of candidate links that have NOT run yet. For each candidate, decide whether running it would rediscover one of those reported findings.\n\nA `duplicate` verdict does not discard the link — it moves to the back of the queue and a well-funded run still executes it. A wrong `duplicate` costs only ordering; a missed duplicate costs a whole agent pipeline. Reply with strict JSON only, no commentary.";

pub(super) const NOVELTY_RUBRIC: &str = r#"## What makes a candidate a duplicate

Judge on the DEFECT, not on wording and not on location. A candidate is `duplicate` only when its defect is the SAME BUG as one already reported — same broken property, same missing check, one fix kills both.

  duplicate  The candidate's root cause maps onto a reported finding's root cause. Different historical projects, different phrasing, different severity, and different naming do NOT make it new.

  new        Anything else, including — and this is the common case —
             - SAME contract and SAME function as a reported finding, but a DIFFERENT defect. A hot function typically carries several distinct bugs: a missing zero-address check, a value-equality check that is also missing, an unbounded numeric parameter, and a stale-config path can all live in one setter and are FOUR findings, not one.
             - a defect whose surface is not represented in the reported set at all.

`primary_contract` / `primary_function` in the reported set are locating hints, not the dedup key. Matching them is NOT sufficient evidence of duplication — compare root causes, and only call `duplicate` when the underlying defect is the same.

## Method

- Read `defect_root_cause` and `defect_detail` first: they describe the code shape of the defect.
- Look for a reported finding whose `root_cause` describes that same defect.
- Ask yourself: would one patch fix both? If no, it is `new`.
- When genuinely torn, answer `new`. Missing a real bug is the expensive error; re-checking a duplicate merely costs one pipeline.

## Output

Emit one entry per candidate shown — no silent omission:

{"verdicts":[{"candidate_id":0,"verdict":"duplicate","duplicate_of_finding_id":41,"reason":"..."},{"candidate_id":1,"verdict":"new","reason":"..."}]}

Hard rules:
- `candidate_id` must be one of the ids shown in this batch.
- `duplicate_of_finding_id` is REQUIRED when `verdict` is `duplicate`, and must be a `finding_id` from `reported_findings`. Never invent one.
- `reason` is one short sentence naming the shared defect (for `duplicate`) or what makes it distinct (for `new`)."#;
