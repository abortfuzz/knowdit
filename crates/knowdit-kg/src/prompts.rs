use crate::category::DeFiCategory;
use crate::vulnerability::{FindingSeverity, VulnerabilityCategory, taxonomy_prompt};

/// Prompt templates for the DeFi semantic extraction pipeline.
/// The layout is intentionally cache-friendly:
/// - The system prompt stays short and stable.
/// - The user prompt begins with a stable shared prefix.
/// - Project material appears after that shared prefix.
/// - Task-specific instructions are appended after the project material.

pub const GENERAL_ROLE_SYSTEM: &str = r#"You are an expert DeFi knowledge engineer and senior smart contract analyst.
Follow the user's instructions exactly.
Use canonical, project-agnostic DeFi terminology.
When the user requests JSON, return strict JSON only."#;

pub const PROJECT_USER_PREFIX_HEAD: &str = r#"You are given a DeFi project.
Read the project materials carefully.
Use only the material provided.
Apply the category definitions below consistently whenever you classify either the project or any extracted semantic.

## Category Definitions

"#;

pub const PROJECT_MATERIALS_HEADER: &str = r#"## Project Materials

"#;

pub const REPORT_USER_PREFIX_HEAD: &str = r#"You are given DeFi audit finding material.
This material may be a full audit report or a collection of vulnerability notes/snippets for one project.
Read the material carefully.
Use only the material provided.
Classify each extracted vulnerability with exactly one category and one subcategory from the taxonomy below.

## Severity Definitions

- High: Exploitation directly causes meaningful fund loss.
- Medium: Exploitation does not directly cause fund loss, or only causes very small loss comparable to operational or gas impact, such as denial of service.
- Low: Gas optimizations, hardening suggestions, or minor correctness issues.

## Vulnerability Taxonomy

"#;

pub const REPORT_MATERIALS_HEADER: &str = r#"## Audit Finding Material

"#;

/// NOTE: Always put reasoning ahead to make a CoT style output

pub const CATEGORY_DEFINITIONS: &str = r#"Categories:

* **Lending:** Protocols that allow users to supply assets to earn interest or borrow assets by providing collateral (e.g., Aave, Compound).
* **Dexes:** Decentralized exchanges facilitating asset swaps via AMMs or order books (e.g., Uniswap, Curve).
* **Yield:** Protocols focused on staking, locking, or rewards distribution mechanisms to incentivize liquidity or holding.
* **Services:** Utility protocols providing infrastructure, privacy, automation, or oracle services.
* **Derivatives:** Financial instruments derived from underlying assets, including perpetual futures, options, and synthetics.
* **Yield Aggregator:** Vaults or strategies that automate yield farming by moving assets across protocols to maximize returns.
* **Real World Assets:** Protocols tokenizing off-chain physical assets like real estate, treasury bills, or commodities.
* **Stablecoins:** Protocols issuing tokens pegged to a fiat currency or stable value.
* **Indexes:** Protocols creating baskets of tokens to represent a market sector or weighted strategy.
* **Insurance:** Protocols providing coverage against smart contract failure, hacks, or de-pegging events.
* **NFT Marketplace:** Platforms facilitating the buying, selling, or auctioning of NFTs.
* **NFT Lending:** Protocols using NFTs as collateral for loans or rental markets.
* **Cross Chain:** Bridges, messaging protocols, or interoperability layers between blockchains.
* **Others:** Unique or experimental projects that do not fit the above categories.
"#;

pub fn project_user_prefix() -> String {
    format!(
        "{}{}{}",
        PROJECT_USER_PREFIX_HEAD, CATEGORY_DEFINITIONS, PROJECT_MATERIALS_HEADER
    )
}

pub fn report_user_prefix() -> String {
    format!(
        "{}{}\n{}",
        REPORT_USER_PREFIX_HEAD,
        taxonomy_prompt(),
        REPORT_MATERIALS_HEADER
    )
}

pub const CATEGORIZE_USER_SUFFIX: &str = r#"
## Instructions

Analyze the project materials above and determine which DeFi categories the project belongs to. A project may belong to multiple categories. Use the category definitions above.

## Tool Usage

Use these tools to record your decision (do NOT output JSON in plain text):
- `set_project_categories({reasoning, project_name, categories})` — call exactly once, with `categories` populated by the chosen DeFi category enum values (e.g. `Lending`, `Yield`). Multiple entries are allowed.
- `finalize_categorization({summary?})` — call exactly once after `set_project_categories`. After this, stop emitting tool calls.
"#;

pub fn extract_semantics_user_suffix(categories: &[DeFiCategory]) -> String {
    let known_categories = if categories.is_empty() {
        "None".to_string()
    } else {
        categories
            .iter()
            .map(DeFiCategory::as_str)
            .collect::<Vec<_>>()
            .join(", ")
    };

    format!(
        r#"
## Instructions

The project materials above have already been categorized as: {known_categories}

Extract DeFi Semantics from the provided project material chunk.

### Definition of DeFi Semantic

A DeFi Semantic is defined by:
1. **Name:** A short, abstract, canonical name (e.g., "Constant Product AMM Swap", "Collateralized Debt Position Opening").
2. **Definition:** A one-sentence formal definition of this semantic.
3. **Description:** Concrete behavioural prose carrying the implementation details a future reader needs to recognise the same semantic in another project. **NOT** abstract metaphor like "manages user deposits". Whenever applicable from the actual source, include:
   - Critical state variables read or written, with the operation (e.g. "increments `s_depositedAssets` additively by the *requested* `assets` value, before calling `transferFrom`").
   - Access control: which role / modifier / `msg.sender` check gates each entry point.
   - External calls and their failure modes (revert / swallowed in try/catch / silently ignored).
   - Critical invariants the path enforces or violates (e.g. "reverts on `reserveX < amount`", "preserves `k = reserveX * reserveY` modulo fee").
   - Pre-condition state and post-condition state in concrete terms.

   Always say WHICH state variable, WITH WHAT semantics, WHO is allowed, WHEN the side effect happens, WHAT external boundaries are crossed. Aim for 4–8 sentences. Detail beats brevity.
4. **Functions:** The specific functions or entry points in the source code that implement this semantic. Use the containing file or module path in the `contract` field. At least one entry is required per semantic.
5. **Category:** Exactly one DeFi category, picked from the project's known categories above. Use `Others` only when none fit.

### Critical Rules

1. **Hard rule on abstraction.** In the `name`, `definition`, and `description` fields you MUST NOT include any of:
   - Specific protocol or project names (Uniswap, Aave, Compound, BentoBox, Tempus, Pendle, …).
   - Specific contract names (UniswapV2Pair, BentoBoxV1, …).
   - Specific function signatures or library APIs (`swap(...)`, `depositAndFix(...)`).
   - Specific branded asset names (USDC, DAI, stETH, …) — say "stablecoin", "wrapped staking receipt", etc.
   Use only abstract DeFi roles like "AMM swap helper", "external principal-token integration", "shared collateral vault", "yield strategy adapter", "liquidity-mining staker", "signature forwarder".
   - Bad: "Deposit into BentoBox to mint BentoShares"
   - Good: "Deposit into shared vault to mint unified liquidity shares"
   The `functions` field IS the place for project-specific implementation pointers and SHOULD keep the real contract path and function name.

2. **Use canonical DeFi vocabulary:** "liquidity provision", "collateralized debt position", "yield-bearing vault share", "constant-product swap", "concentrated liquidity range order", etc.

3. **Cluster every callable function or public entry point visible in this chunk** into a semantic — but cluster aggressively. Many functions in the same file usually map to the same DeFi semantic (e.g. `mint`, `burn`, `_mint`, `_burn` together = "Fungible Token Supply Adjustment"). The `functions` array is where you enumerate every member of a cluster; the *number of distinct semantics* should stay small. If a function does not correspond to any DeFi semantic (pure admin/governance, view-only getters, standard token boilerplate), put it under a single "Utility/Admin" semantic for this chunk — do not create one Utility/Admin semantic per file.

4. **Be thorough within this chunk** but stay project-agnostic. Subsequent chunks of the same project receive different code; cross-chunk merging will deduplicate later, so do not skip a real semantic just because it might appear elsewhere.

## Tool Usage

Use these tools to stream out the extraction (do NOT emit free-form JSON):
- `emit_semantic({{name, definition, description, category, functions: [{{name, contract, signature?}}, …]}})` — call once for each distinct DeFi Semantic you identify in this chunk. Cluster aggressively; emit one call per *distinct* semantic, with every same-meaning function listed inside `functions`.
- `finalize_semantic_extraction({{summary?}})` — call exactly once when this chunk has been fully covered (or when it contains no meaningful DeFi semantics — call finalize directly without any `emit_semantic`). After this, stop emitting tool calls.
"#
    )
}

pub fn merge_semantics_user_message(existing_semantics: &str, new_semantics: &str) -> String {
    format!(
        r#"You are given DeFi semantic data to reconcile against the historical knowledge base.

## Semantic Data

### Existing Semantics in Knowledge Base

{existing_semantics}

### Newly Extracted Semantics (from the current project)

{new_semantics}

## Instructions

For every newly extracted semantic listed above, decide whether it should:
- **MERGE** into one or more existing canonical semantics in the knowledge base, OR
- be admitted as a **NEW** canonical semantic (emit `merge_target_ids: []`).

### Decision Criteria

The judgement must be grounded in the *concrete behavioural details* in
each side's `Description` field — which state variables are mutated, which
access controls gate them, what external boundaries are crossed, what
invariants are enforced. Surface-level theme overlap ("both involve admin",
"both manage parameters", "both touch deposits") is NOT a sufficient reason
to merge.

**MERGE only when:**
- The same concrete state variable(s) are mutated under the same accounting
  semantics (additive / multiplicative / replace-on-checkpoint, etc).
- The same external-call failure modes apply (revert vs swallowed vs caught).
- The same access-control shape gates the entry (single owner, role with
  specific permission, signature gate, …) AND it gates the same kind of
  state mutation.
- The pre-condition state and post-condition state are equivalent in
  concrete terms, not just in narrative.
- The semantic category is the same.

**Otherwise emit NEW** (empty `merge_target_ids`):
- A different concrete state-mutation accounting, even if the broad theme
  overlaps.
- A different external-boundary failure mode.
- A different access-control surface.
- A new financial primitive not covered by any existing semantic.

When in doubt: **prefer NEW**. A precise canonical capturing one specific
behaviour is more useful than a vague canonical loosely covering many.

### Canonical Identity is Locked

When you choose to MERGE, the target canonical's `name` and `definition`
are NEVER modified by your decision — they are the canonical's stable
identity. If the new raw's behaviour cannot be naturally described under
the existing canonical's name + definition, emit `merge_target_ids: []`
(NEW) instead of trying to fit the raw under it.

You MAY supply `appended_description` to record a specific implementation
detail this raw contributes that is worth preserving on the canonical. It
will be APPENDED to the canonical's description (not replacing it). Use it
when the raw's behaviour fits cleanly under the existing identity but adds
a non-trivial concrete variant worth noting.

### Examples

✓ Good merge:
  raw description: "increments `s_depositedAssets` additively by `assets`
    before `transferFrom`; reverts on `paused`; minted shares =
    `previewDeposit(assets)`"
  canonical description: "Vault.deposit increments `s_depositedAssets`
    additively prior to `safeTransferFrom`; gated by `whenNotPaused`;
    shares = `previewDeposit`"
  → MERGE: same state variable (`s_depositedAssets`), same accounting
    (additive before transfer), same gate (`whenNotPaused`).

✗ Bad merge (must be NEW):
  raw description: "Owner-gated `setOracleFeed(address)` updates
    `s_priceFeed` mapping for one collateral; emits `OracleFeedUpdated`."
  canonical description: "Owner-gated `setRouter(address)` updates the
    swap-router reference; reverts on zero-address."
  Theme overlap: "owner-gated setter, single state variable update".
  But: different state variable (`s_priceFeed` vs `s_router`), different
  invariants, different downstream consumers.
  → NEW: theme overlap is not a behavioural anchor.

## Tool Usage

Use these tools (do NOT emit free-form JSON):
- `emit_semantic_merge_decision({{reason, new_semantic_name, merge_target_ids, appended_description?}})` — call exactly once for each `new_semantic_name` listed in the prompt above. Set `merge_target_ids: []` for NEW; set it to one or more existing canonical IDs (from this chunk's prompt) for MERGE. `appended_description` is optional and only applies on merge.
- `finalize_semantic_merge({{summary?}})` — call exactly once after every newly-extracted semantic has been decided. Stop afterwards.
"#
    )
}

pub fn extract_findings_user_suffix(categories: &[DeFiCategory]) -> String {
    let known_categories = if categories.is_empty() {
        "None".to_string()
    } else {
        categories
            .iter()
            .map(DeFiCategory::as_str)
            .collect::<Vec<_>>()
            .join(", ")
    };

    format!(
        r#"
## Instructions

The underlying project for this report has already been categorized as: {known_categories}

Extract the unique vulnerability findings described in the audit material above.

### Definition of Vulnerability Pattern

For each finding, capture:
1. **title**: Keep the original report title when one is available.
2. **root_cause**: The technical and economic root cause. Cite the specific accounting step / state mutation / call ordering / failure-mode that constitutes the bug, not abstract metaphor. E.g. "`swap()` reads `s_reserves` to compute `minimumOut` but allows `setFeeInfo` to mutate the live fee schedule between blocks, so a victim swap is priced under the new fee schedule" — not just "missing slippage check".
3. **description**: Concrete description of the vulnerable behavioural shape and its impact, in terms of state pre- and post-condition. Include WHICH state variables drift, WHO can drive them off-invariant, and WHAT downstream paths consume the corrupted state.
4. **severity**: One of `High`, `Medium`, or `Low` using the severity definitions above.
5. **patterns**: The specific state variables / call orderings / external failure modes / control-flow shapes that constitute the bug. Cite Solidity-level details (e.g. "`transferFrom` is called BEFORE the reserve update; reentrancy guard is per-pool not per-router") rather than English summaries ("missing reentrancy guard").
6. **exploits**: Concrete attack sequence in terms of `(msg.sender, function, observed state, ordering vs other tx)`. Make it reproducible: a future reader should be able to translate the prose into an explicit transaction sequence.
7. **category**: Exactly one top-level vulnerability category from the taxonomy.
8. **subcategory**: Exactly one subcategory from the chosen top-level category.

### Critical Rules

0. **Hard rule on abstraction.** Outside the `title` field, the `root_cause`, `description`, `patterns`, and `exploits` fields MUST NOT include any of:
   - Specific protocol or project names (Uniswap, Aave, Compound, Tempus, Pendle, BentoBox, …).
   - Specific contract names (UniswapV2Pair, BentoBoxV1, …).
   - Specific function signatures or library APIs (`depositAndFix(...)`, `swapExactTokensForTokens(...)`).
   - Specific branded asset names (USDC, DAI, stETH, …) — say "stablecoin", "wrapped staking receipt", etc. instead.
   Use only abstract roles like "AMM swap helper", "external principal-token integration", "liquidation keeper", "signature forwarder", "shared collateral vault", "yield strategy adapter". The `title` field is the only place where the original report wording is preserved verbatim.
1. Deduplicate repeated mentions of the same finding inside this material chunk.
2. **Atomic decomposition.** If a single original finding describes ≥2 independently triggerable vulnerability mechanisms (e.g., "uses the wrong return value AND skips slippage validation"; "missing access control AND missing zero-address check on the same setter"), emit one record per mechanism. The records share the same `title` (original report title) but each record's `root_cause`, `patterns`, and `exploits` MUST describe one mechanism only. The decision criterion is functional independence: if fixing one mechanism would still leave the other independently exploitable on a different project, the mechanisms are independent and must be split.
3. Include economically meaningful root causes when the bug depends on incentives, liquidity flow, or bridge accounting.
4. Do not invent findings that are not supported by the material above.
5. Always use a subcategory name exactly as written in the taxonomy.

## Tool Usage

Use these tools to stream out the extraction (do NOT emit free-form JSON):
- `emit_finding({{title, severity, category, subcategory, root_cause, description, patterns, exploits}})` — call once per *atomic* vulnerability mechanism. If one original report finding decomposes into multiple independent mechanisms, share the same `title` across the calls but populate `root_cause` / `patterns` / `exploits` independently for each.
- `finalize_finding_extraction({{summary?}})` — call exactly once when every distinct finding in this chunk has been emitted (or when the chunk contains no findings — call finalize directly without `emit_finding`). Stop afterwards.
"#
    )
}

/// Prompt body for in-project linking. Run AFTER per-project extract and
/// BEFORE any cross-project merge: every finding from this project must
/// claim ≥1 same-project semantic. The returned indices are positional in
/// the lists rendered into the prompt.
pub fn in_project_link_user_message(
    project_categories: &[DeFiCategory],
    semantics_block: &str,
    findings_block: &str,
) -> String {
    let known_categories = if project_categories.is_empty() {
        "None".to_string()
    } else {
        project_categories
            .iter()
            .map(DeFiCategory::as_str)
            .collect::<Vec<_>>()
            .join(", ")
    };
    format!(
        r#"You are linking each audit finding from a single DeFi project to the project's own DeFi semantics.

The project has been categorized as: {known_categories}

## Project Semantics (candidates)

Each candidate is identified by its zero-based index `S`. The list below contains every DeFi semantic this project implements; pick from these only.

{semantics_block}

## Project Findings

Each finding is identified by its zero-based index `F`. These findings come from the project's own audit report.

{findings_block}

## Instructions

For every finding F, return the list of semantic indices S whose business logic is needed to reproduce or trigger that finding. Be expansive when the relationship is plausible.

### Hard rules

- Every finding must appear in the output exactly once.
- Every finding's `semantic_indices` array must contain at least ONE index. Findings cannot be left unlinked at this stage; if no semantic looks right, pick the closest "Utility/Admin" or whichever semantic supplies the contract surface where the bug lives.
- Use only `S` indices that appear in the candidate list above.
- A finding may link to multiple semantics — list them all.

## Output Format

Output strict JSON:
```json
{{
  "links": [
    {{
      "finding_index": 0,
      "reasoning": "Brief explanation of why these semantics are required for this finding",
      "semantic_indices": [3, 7]
    }},
    {{
      "finding_index": 1,
      "reasoning": "...",
      "semantic_indices": [0]
    }}
  ]
}}
```
"#
    )
}

pub fn merge_findings_user_message(existing_findings: &str, new_findings: &str) -> String {
    format!(
        r#"You are given vulnerability-pattern data to reconcile.

## Existing Findings in Knowledge Base

{existing_findings}

## Newly Extracted Findings

{new_findings}

## Instructions

For each newly extracted finding, decide whether it should be merged with one or more existing findings in the knowledge base or added as a new finding (emit `merge_target_ids: []`).

### Merge Criteria

The judgement must be grounded in the *concrete details* in each side's
`Root Cause`, `Patterns`, and `Exploits` fields — the specific accounting
step / state variable drift / call ordering / external-boundary failure
mode that constitutes the bug. Surface theme overlap ("both involve fee
calculation", "both touch admin authority") is NOT a sufficient reason to
merge.

**MERGE only when:**
- Same concrete state-variable drift (e.g. both bugs cause
  `s_depositedAssets` to track > actual token balance).
- Same exploit-shape: ordering of calls / conditions / oracle assumptions
  reproducible to the same attacker setup.
- Same vulnerability taxonomy category AND closely matching subcategory.

**Otherwise emit NEW** (empty `merge_target_ids`):
- Different state variable affected.
- Different attacker entry point (different `msg.sender` setup, different
  ordering, different external boundary).
- Different taxonomy category or substantially different subcategory.

When in doubt: **prefer NEW**. A precise canonical finding capturing one
specific bug pattern is more useful than a vague canonical that loosely
covers many.

### Canonical Identity is Locked

When you MERGE, the target canonical's `title`, `severity`, and
`root_cause` are NEVER modified — they are the canonical's stable
identity. You MAY supply `appended_description` / `appended_patterns` /
`appended_exploits` to record specific extra detail the new raw
contributes; these are APPENDED (not replaced) and should be incremental,
not a rewrite.

If the new raw's bug shape cannot be expressed under the existing target's
title/severity/root_cause, emit `merge_target_ids: []` (NEW) instead.

## Tool Usage

Use these tools (do NOT emit free-form JSON):
- `emit_finding_merge_decision({{reason, new_finding_title, merge_target_ids, appended_description?, appended_patterns?, appended_exploits?}})` — call exactly once for each `new_finding_title` listed in the prompt above. Empty `merge_target_ids` = NEW; one or more IDs = MERGE.
- `finalize_finding_merge({{summary?}})` — call exactly once after every newly-extracted finding has been decided. Stop afterwards.
"#
    )
}

pub const FINDING_LINK_USER_PREFIX_HEAD: &str = r#"You are linking DeFi vulnerability findings to DeFi semantics.

The candidate set below contains every active canonical semantic across all DeFi categories — pick from it without category prefiltering. The originating project's category for each finding is just additional context, not a filter."#;

pub const FINDING_LINK_USER_PREFIX_CONTEXT_NOTE: &str = r#""#;

pub const FINDING_LINK_CANDIDATE_HEADER: &str = r#"

## Candidate Semantics

"#;

pub const FINDING_LINK_INSTRUCTIONS_AND_OUTPUT: &str = r#"
## Instructions

For each finding below, decide which candidate semantics from the list
above the finding has at least a tangential relation to, and emit a
strength-tagged entry per such candidate. Candidates with NO meaningful
relation can be omitted entirely — silent omission is treated as "no
link" for that pair. The candidate set per prompt is large, so be
selective; you do NOT need to enumerate Low entries for clearly unrelated
candidates. When in doubt about whether a candidate qualifies for at
least Low, emit it with `Low` rather than guessing it away.

### Strength rubric — single axis: DIRECTNESS OF INSTANTIATION

Strength is determined by ONE check: how directly does this finding
instantiate the semantic's described failure mode?

  High    The finding is a textbook example of the semantic's failure
          mode. The finding's `root_cause` directly describes the
          invariant the semantic encodes being violated, AND the
          `exploits` / `patterns` cite the semantic's central behaviour
          as the attack surface. A reader of the semantic alone would
          predict this finding could exist.

  Medium  The finding touches this semantic but the bug lies on a
          DIFFERENT sub-mechanism the semantic happens to involve.
          To label Medium you must point to the specific sub-mechanism
          of the semantic the finding hits. Same category alone is NOT
          Medium — point to a concrete sub-step shared by both sides.

  Low     The finding only TANGENTIALLY touches this semantic. Common
          cases:
            - the semantic appears in setUp / preconditions but the
              actual bug is on a different code path
            - the finding's root_cause mentions the semantic only
              because it's nominally in scope
            - topic / category overlap with no concrete instantiation
              of the semantic's specific failure mode
          Most "broad topic match" links land here.

### Calibrate deliberately

Unwarranted `High` poisons downstream budgets — every future consumer of
this KG that filters by strength spends tokens on edges that don't actually
instantiate the semantic. Unwarranted `Low` silently hides real bugs.

  - DEFAULT TO LOW when uncertain. No penalty for emitting Low. Real
    penalty for emitting High-or-above without concrete invariant +
    finding-text pairing.
  - CATEGORY MATCH IS NOT MEDIUM. Two records sharing DeFiCategory or
    same project domain is not, by itself, a Medium link. If your
    evidence reduces to "same area", that's Low.
  - DO NOT promote to High solely because surface keywords match. High
    requires the same FAILURE MODE, not the same vocabulary.
  - DO NOT downgrade to Low just because the finding is from a different
    project than the semantic's originating project — semantics are
    universal. Downgrade only when the finding's actual bug is not what
    the semantic encodes.

### Evidence rules

The `why_finding_can_fire` field is required per entry:

  - For **High** (>= 40 chars): state the invariant the semantic encodes
    (cite the semantic's definition/description verbatim or paraphrase)
    AND name the finding's root_cause text describing that invariant
    being violated. The pairing should be tight enough that a reader
    could verify it from just the two text blocks.
  - For **Medium** (>= 40 chars): name the specific sub-mechanism of
    the semantic the finding hits, and explain what differs from the
    semantic's central failure mode. If you can only say "both involve
    X" without naming a sub-mechanism, demote to Low.
  - For **Low** (>= 15 chars): state where in the semantic the finding
    nominally appears (precondition / setUp / shared category) and why
    it's not a direct instantiation. Short reasons are fine.

## Tool Usage

Use these tools (do NOT emit free-form JSON):
- `emit_finding_link_decision({reasoning, finding_id, semantic_evidence: [{semantic_id, strength, why_finding_can_fire}, ...]})` — call exactly once per `finding_id` listed below. `semantic_evidence` is a list of decisions for candidates the finding is at least tangentially related to (Low or higher); omit candidates with no meaningful relation. An empty list means "no link" for this finding. `strength` is one of `High`, `Medium`, `Low`; `why_finding_can_fire` cites the specific behaviour from the semantic's description (or — for Low — names where the semantic only tangentially appears).
- `finalize_finding_link({summary?})` — call exactly once after every finding has been emitted.

## Findings To Link

"#;

pub fn finding_link_user_prefix(
    _category: Option<DeFiCategory>,
    candidate_semantics: &str,
) -> String {
    format!(
        "{}{}{}{}{}",
        FINDING_LINK_USER_PREFIX_HEAD,
        FINDING_LINK_USER_PREFIX_CONTEXT_NOTE,
        FINDING_LINK_CANDIDATE_HEADER,
        candidate_semantics,
        FINDING_LINK_INSTRUCTIONS_AND_OUTPUT
    )
}

pub fn finding_link_finding_entry(
    finding_id: &str,
    project_categories: &[DeFiCategory],
    title: &str,
    severity: FindingSeverity,
    category: VulnerabilityCategory,
    subcategory: &str,
    root_cause: &str,
    description: &str,
    patterns: &str,
    exploits: &str,
) -> String {
    let known_project_categories = if project_categories.is_empty() {
        "None".to_string()
    } else {
        project_categories
            .iter()
            .map(DeFiCategory::as_str)
            .collect::<Vec<_>>()
            .join(", ")
    };

    format!(
        r#"### {finding_id}

- Project DeFi Categories: {known_project_categories}
- Title: {title}
- Severity: {severity}
- Category: {category}
- Subcategory: {subcategory}
- Root Cause: {root_cause}
- Description: {description}
- Patterns: {patterns}
- Exploits: {exploits}

"#
    )
}
