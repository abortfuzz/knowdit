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

## Output Format

Output strict JSON:
```json
{
  "reasoning": "Brief explanation of why these categories were chosen.",
  "project_name": "Name of the project",
  "categories": ["Lending", "Yield"]
}
```
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

Extract DeFi Semantics from the provided project material.

### Definition of DeFi Semantic

A DeFi Semantic is defined by:
1. **Name:** A short, abstract, canonical name (e.g., "Constant Product AMM Swap", "Collateralized Debt Position Opening")
2. **Definition:** A one-sentence formal definition of this semantic.
3. **Description:** An abstract description of the user interaction, value flow, and financial outcome using generic DeFi terminology.
4. **Functions:** The specific functions or entry points in the source code that implement this semantic. Use the containing file or module path in the `contract` field.

### Critical Rules

1. **Abstract away all project branding.** Replace project-specific names with generic DeFi roles.
   - Bad: "Deposit into BentoBox to mint BentoShares"
   - Good: "Deposit into shared vault to mint unified liquidity shares"

2. **Use canonical DeFi vocabulary:** "liquidity provision", "collateralized debt position", "yield-bearing vault share", "constant-product swap", "concentrated liquidity range order", etc.

3. **Map every callable function or public entry point visible in the provided project material** to a semantic. If a function does not correspond to any DeFi semantic (e.g., pure admin/governance, view-only getters, or standard token boilerplate), mark it under a special "Utility/Admin" semantic.

4. **Be thorough within the provided project material.** Do not skip callable functions that are visible in the material above.

5. **Assign exactly one DeFi category** to each semantic. Use the best-fitting category from the known project categories above and apply the category definitions above consistently. Only use "Others" when none of the known project categories fit.

6. **Short Description Format:** Construct using "Action -> Object -> Outcome" (e.g., "Supply collateral to mint synthetic stablecoins"). Around 100 characters, strictly generic.

## Output Format

Output strict JSON:
```json
{{
  "semantics": [
    {{
      "name": "Constant Product AMM Swap",
      "category": "Dexes",
      "definition": "Exchange one token for another through an automated market maker using the constant product formula.",
      "description": "User swaps token A for token B through a liquidity pool that maintains x*y=k invariant. The exchange rate is determined by the pool's reserve ratio, and a fee is deducted from the input amount.",
      "short_description": "Swap tokens via constant-product AMM pool",
      "functions": [
        {{
          "name": "swap",
          "contract": "sources/pool.move",
          "signature": "swap(address,bool,int256,uint160,bytes)"
        }}
      ]
    }}
  ]
}}
```

If the provided project material contains no meaningful DeFi semantics (e.g., it is a standard library, interface-only file, or utility-only chunk), output:
```json
{{
  "semantics": []
}}
```
"#
    )
}

pub fn merge_semantics_user_message(existing_semantics: &str, new_semantics: &str) -> String {
    format!(
        r#"You are given semantic data to reconcile.

## Semantic Data

### Existing Semantics in Knowledge Base

{existing_semantics}

### Newly Extracted Semantics

{new_semantics}

## Instructions

Decide whether each newly extracted semantic should be merged with an existing semantic in the knowledge base or added as a new entry.

### Decision Criteria

**MERGE if:**
- The core financial mechanism is the same (e.g., both describe "constant product AMM swap" even if implementation details differ).
- The user's financial outcome is equivalent.
- Differences are only in implementation, code patterns, or minor parameter variations.
- The semantic category is the same.

**NEW if:**
- The mechanism introduces a genuinely different risk or reward profile.
- The value flow or state changes are fundamentally different.
- It represents a new financial primitive not covered by the existing semantics.
- The semantic category is different.

## Output Format

For each new semantic, output a decision as strict JSON:
```json
{{
  "decisions": [
    {{
      "reason": "Why these semantics are the same mechanism",
      "new_semantic_name": "Name of the newly extracted semantic",
      "action": "merge",
      "merge_target_id": 42,
      "updated_name": "Updated abstract name if the merge warrants a broader name",
      "updated_definition": "Updated, more abstract definition covering both old and new",
      "updated_description": "Updated description that generalizes across both projects"
    }},
    {{
      "reason": "Why this is genuinely novel",
      "new_semantic_name": "Some Novel Mechanism",
      "action": "new"
    }}
  ]
}}
```
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
2. **root_cause**: The technical and economic root cause behind the vulnerability.
3. **description**: An abstract but precise description of the vulnerable pattern and its impact.
4. **severity**: One of `High`, `Medium`, or `Low` using the severity definitions above.
5. **patterns**: What code patterns, state assumptions, or protocol conditions usually trigger the bug.
6. **exploits**: How the bug is typically exploited in practice.
7. **category**: Exactly one top-level vulnerability category from the taxonomy.
8. **subcategory**: Exactly one subcategory from the chosen top-level category.

### Critical Rules

1. Deduplicate repeated mentions of the same finding inside this material chunk.
2. Keep titles faithful to the report, but make root cause, description, patterns, and exploits project-agnostic when possible.
3. Include economically meaningful root causes when the bug depends on incentives, liquidity flow, or bridge accounting.
4. Do not invent findings that are not supported by the material above.
5. Always use a subcategory name exactly as written in the taxonomy.

## Output Format

Output strict JSON:
```json
{{
  "findings": [
    {{
      "title": "Original report title",
      "severity": "High",
      "category": "Access Control",
      "subcategory": "Missing Input Validation",
      "root_cause": "Critical settlement parameters are trusted without validating that they match the asset and destination context.",
      "description": "A cross-chain settlement flow accepts inconsistent destination or asset parameters, allowing state to advance under incorrect assumptions and causing incorrect minting, release, or accounting outcomes.",
      "patterns": "User-controlled or relayed settlement parameters are consumed without checking whitelist membership, chain identity, asset identity, or prior message state.",
      "exploits": "An attacker submits or replays a settlement message with malformed parameters so downstream handlers process an unintended asset, chain, or status transition."
    }}
  ]
}}
```

If the provided material contains no actual findings, output:
```json
{{
  "findings": []
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

For each newly extracted finding, decide whether it should be merged with an existing finding in the knowledge base or added as a new finding.

### Merge Criteria

Merge when the finding represents the same underlying vulnerability pattern:
- the same root cause or invariant break,
- the same exploit mechanism or failure mode,
- the same vulnerability taxonomy category and closely matching subcategory,
- differences are mostly project-specific names, code locations, or incident framing.

Keep as new when the finding introduces a genuinely distinct pattern:
- a different root cause,
- a different exploit path,
- a different user or protocol outcome,
- a materially different taxonomy category or subcategory.

If you merge, you may generalize the target finding by updating severity, root cause, description, patterns, and exploits.
Do not rename the target title.

## Output Format

Output strict JSON:
```json
{{
  "decisions": [
    {{
      "reason": "Why these findings represent the same vulnerability pattern",
      "new_finding_title": "Original report title",
      "action": "merge",
      "merge_target_id": 42,
      "updated_severity": "High",
      "updated_root_cause": "Generalized root cause",
      "updated_description": "Generalized description",
      "updated_patterns": "Generalized triggering patterns",
      "updated_exploits": "Generalized exploit path"
    }},
    {{
      "reason": "Why this is a novel pattern",
      "new_finding_title": "Another report title",
      "action": "new"
    }}
  ]
}}
```
"#
    )
}

pub const FINDING_LINK_USER_PREFIX_HEAD: &str = r#"You are linking DeFi vulnerability findings to DeFi semantics.

This prompt is anchored to this DeFi category: "#;

pub const FINDING_LINK_USER_PREFIX_CONTEXT_NOTE: &str = r#"

Most candidate semantics were surfaced from this category. Some active canonical targets may list a different primary category because merged historical aliases must still resolve to the canonical semantic shown in this prompt.

Each finding may come from a project with broader DeFi coverage. When provided, use the per-finding project categories as extra context, but only choose among the candidate semantics shown in this prompt."#;

pub const FINDING_LINK_CANDIDATE_HEADER: &str = r#"

## Candidate Semantics

"#;

pub const FINDING_LINK_INSTRUCTIONS_AND_OUTPUT: &str = r#"
## Instructions

For each finding below, select every semantic that is materially related.

- Be expansive rather than conservative when the relationship is plausible and meaningful.
- A semantic is related when the finding depends on that user interaction, value flow, settlement path, accounting step, or callable mechanism.
- Return finding IDs exactly as shown.
- Return semantic IDs using active `Candidate ID` values.
- `Historical Alias ID` entries are reference-only merged semantics. If one is relevant, return its `Canonical Link Target` instead of the alias ID.
- If a semantic has no merge history, return its `Candidate ID` directly.
- Do not omit any finding. If a finding has no direct semantic relationship, still return it with `"semantic_ids": []`.
- Every finding listed below must appear exactly once in the output.
- The `results` array must contain one entry for every finding below, even when the correct answer is an empty list.

## Output Format

Output strict JSON:
```json
{
  "results": [
    {
    "reasoning": "Brief explanation of why these semantics are related.",
      "finding_id": "finding-123",
      "semantic_ids": ["sem-12", "sem-19"],
      
    },
    {
      "reasoning": "Explain why no direct semantic relationship was found.",
      "finding_id": "finding-124",
      "semantic_ids": [],
    }
  ]
}
```

## Findings To Link

"#;

pub fn finding_link_user_prefix(
    category: Option<DeFiCategory>,
    candidate_semantics: &str,
) -> String {
    let category_name = category.map(|category| category.as_str()).unwrap_or("None");

    format!(
        "{}{}{}{}{}{}",
        FINDING_LINK_USER_PREFIX_HEAD,
        category_name,
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
