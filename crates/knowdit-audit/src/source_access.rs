//! How an audit agent reaches the project's Solidity source.
//!
//! Two ways to hand over a contract body, and one run uses both:
//!
//! * **resident** — the body sits in the system prompt from the first call, in
//!   a block identical for every link in the run, so it is written to the
//!   model's prompt cache once and read back at the cached rate thereafter.
//! * **on demand** — the agent fetches it with `read_contract_source` /
//!   `read_function_source`, navigating by the per-contract signature index in
//!   short-term memory. Every fetched body then rides along in the context of
//!   every later call in that conversation.
//!
//! The split between them is a budget, not a switch. [`Self::resolve`] fills the
//! resident block up to the stage's allowance and leaves the rest on demand, so
//! a project larger than the budget still gets whatever fits instead of falling
//! back to reading everything. Both ends of the range degrade into the simple
//! cases: nothing fits and this is exactly the pre-residency pipeline; the whole
//! project fits and nothing is left for the tools but vendored trees.
//!
//! Whatever the split, one value drives all three consumers — the prompt text,
//! the signature index, and the omitted-contract manifest — so they cannot drift
//! apart. An agent told a contract is resident when it is not goes looking in
//! the wrong place; one handed an index entry for a body already printed above
//! pays for it on every call.
//!
//! Residency is an economic choice, not a fit check. The block is carried at the
//! cached input rate on *every* call the stage makes, and a link takes roughly
//! ten of them, so one resident token ends up costing about what one uncached
//! token costs — residency only pays for source the agent would otherwise have
//! read anyway. That is what the ratio bounds, and why its default is a small
//! slice of the window rather than "as much as fits".

use std::collections::BTreeSet;

use color_eyre::eyre::Result;
use llmy::agent::tools::memory::{AgentMemory, AgentMemoryContext};
use llmy::client::client::LLM;

use knowdit_repo_model::ProjectProfile;

use crate::spec::{MemoryScope, ProjectIndex};

/// Hand-written so a stray `{:?}` on the options struct that carries this prints
/// the decision and its size rather than a quarter-megabyte of Solidity.
impl std::fmt::Debug for ProjectSourceAccess {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "ProjectSourceAccess({} resident, {} tokens, {} on demand)",
            self.resident_count,
            self.tokens,
            self.omitted.len()
        )
    }
}

pub struct ProjectSourceAccess {
    /// The contracts and interfaces that fit, rendered once so each link borrows
    /// the text rather than rebuilding it. Empty when the budget admits none.
    /// The framing around it is prompt copy and lives with the stage's other
    /// prompt text, not here.
    source: String,
    /// Cost of `source` under the deciding stage's tokenizer.
    tokens: usize,
    /// The project contracts and interfaces that did *not* fit. The signature
    /// index is built from exactly these under residency, so it covers the gaps
    /// in the block and nothing else.
    omitted_contracts: BTreeSet<i32>,
    omitted_interfaces: BTreeSet<i32>,
    /// Their names, for the prompt's manifest. Sorted, because it is rendered
    /// into a cached prefix.
    omitted: Vec<String>,
    /// How many entities the block does carry, for logging.
    resident_count: usize,
}

impl ProjectSourceAccess {
    /// Decide the resident/on-demand split for one stage.
    ///
    /// `window_ratio` is the fraction of this stage's model input window the
    /// resident block may occupy, matching the `--*-context-window-ratio`
    /// convention the other stages use. Candidates are priced with the model's
    /// own tokenizer — Solidity tokenizes densely enough (~2.9 chars/token) that
    /// a character estimate lands on the wrong side of a tight budget.
    ///
    /// Packing is first-fit and keeps going after the first miss, so one
    /// oversized contract does not shut out everything behind it.
    ///
    /// Order is: contracts the project profile calls core, in the profile's own
    /// order; then everything else by descending call-graph degree; size and
    /// name break the remaining ties.
    ///
    /// The profile leads because it is the only signal produced by asking the
    /// question directly — its agent was told to name the contracts carrying the
    /// project's own business logic, and those are where defects concentrate. On
    /// a mid-sized lending project whose earlier full-budget audit had been
    /// scored against, the profile named ten contracts and those ten accounted
    /// for 63 of the 65 in-scope findings that audit had produced.
    ///
    /// Call-graph degree is the fallback for whatever the profile does not name,
    /// and a poor lead on its own: it ranks utility contracts highly for being
    /// called from everywhere, which is not the same as being worth reading. On
    /// that same project, ordering purely by degree left a budget covering half
    /// the source reaching 53 of those 65, against 61 when the profile led.
    ///
    /// Ordering by ascending size — packing the most contracts a budget allows —
    /// is worse than either, and worth recording because it sounds reasonable:
    /// contracts are large *because* they are central, so smallest-first packs
    /// the periphery and defers the core. It reached 26 of 65 at the same
    /// budget.
    ///
    /// `include_lib` carries the project's `--include-lib-sources` setting
    /// through to the candidate filter; see
    /// [`ProjectIndex::resident_candidates`].
    ///
    /// Every term is run-invariant, so each link packs the same prefix — without
    /// that the block cannot sit inside a cached prompt prefix.
    pub fn resolve(
        index: &ProjectIndex,
        llm: &LLM,
        window_ratio: f64,
        profile: Option<&ProjectProfile>,
        include_lib: bool,
    ) -> Self {
        let mut access = Self {
            source: String::new(),
            tokens: 0,
            omitted_contracts: BTreeSet::new(),
            omitted_interfaces: BTreeSet::new(),
            omitted: Vec::new(),
            resident_count: 0,
        };
        if window_ratio <= 0.0 {
            return access;
        }
        let budget = (llm.model.config.max_input() as f64 * window_ratio.clamp(0.01, 1.0)) as usize;

        // Path first: a contract name can repeat across files, and the profile
        // records the defining file precisely so the two can be tied together.
        let core: &[knowdit_repo_model::ProjectComponent] = profile
            .map(|p| p.core_components.as_slice())
            .unwrap_or_default();
        let core_rank = |candidate: &crate::spec::ResidentCandidate| {
            core.iter()
                .position(|c| {
                    c.path.trim_start_matches("./") == candidate.relative_file_path
                        || (c.path.is_empty() && c.name == candidate.name)
                })
                .or_else(|| core.iter().position(|c| c.name == candidate.name))
                .unwrap_or(usize::MAX)
        };

        let mut candidates = index.resident_candidates(include_lib);
        candidates.sort_by(|a, b| {
            core_rank(a)
                .cmp(&core_rank(b))
                .then(b.degree.cmp(&a.degree))
                .then(b.source.len().cmp(&a.source.len()))
                .then(a.name.cmp(&b.name))
        });

        for candidate in candidates {
            let cost = llm.model.config.count_tokens_lossy(&candidate.source);
            if access.tokens + cost > budget {
                match candidate.is_interface {
                    true => access.omitted_interfaces.insert(candidate.id),
                    false => access.omitted_contracts.insert(candidate.id),
                };
                access.omitted.push(candidate.name);
                continue;
            }
            access.tokens += cost;
            access.resident_count += 1;
            access.source.push_str(&candidate.source);
        }
        access.omitted.sort();

        tracing::info!(
            tokens = access.tokens,
            budget,
            resident = access.resident_count,
            on_demand = access.omitted.len(),
            "resident source block packed"
        );
        access
    }

    /// The rendered source for the top of the stage's system prompt, ahead of
    /// every section that does not vary between runs, or `None` when nothing
    /// fit — in which case the prompt renders byte-identically to how it did
    /// before this type existed. The caller wraps this in its own framing copy.
    pub fn resident_source(&self) -> Option<&str> {
        match self.source.is_empty() {
            true => None,
            false => Some(&self.source),
        }
    }

    /// Names of the project's contracts and interfaces that did **not** fit, so
    /// the prompt can say which ones still have to be fetched. Empty when the
    /// whole project is resident.
    ///
    /// Worth naming rather than leaving implicit: an agent that assumes the
    /// block is complete will conclude a contract does not exist instead of
    /// reaching for the tool.
    pub fn omitted(&self) -> &[String] {
        &self.omitted
    }

    /// Short-term memory for a link agent.
    ///
    /// Without a resident block this is the full signature index, unchanged from
    /// before residency existed. With one it covers exactly the project
    /// contracts the block left out — and so is empty when the whole project
    /// fits. Vendored trees are deliberately absent either way once residency is
    /// on: an index of them would be paid for on every call, while agents reach
    /// them by name through the source tools without one — over a full-budget
    /// audit run carrying no such index, agents still issued 378 successful
    /// reads against vendored contracts.
    pub fn link_memory(&self, index: &ProjectIndex) -> Result<AgentMemoryContext> {
        if self.source.is_empty() {
            return index.build_link_memory(MemoryScope::WholeProject);
        }
        if self.omitted.is_empty() {
            return Ok(AgentMemoryContext::new_without_search(AgentMemory {
                long_term: Default::default(),
                short_term: Default::default(),
            }));
        }
        index.build_link_memory(MemoryScope::Only {
            contracts: &self.omitted_contracts,
            interfaces: &self.omitted_interfaces,
        })
    }
}
