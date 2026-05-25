//! Contract inheritance — extracted from the Solidity `is`-clauses on
//! every `contract`/`abstract contract` and stored as direct
//! parent→child edges. Used by:
//!
//! * Storage analysis (state variables flow through `linearizedBaseContracts`)
//! * Call dispatch resolution (find every concrete implementation of an
//!   interface function by reverse-closing the inheritance relation)
//!
//! Lives separately from [`crate::cg::CallGraph`] and [`crate::storage::StorageGraph`]
//! because both of those consume it but neither owns it semantically — it's
//! a fact about the type lattice, not about calls or storage.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use serde::{Deserialize, Serialize};

/// `contract_id` directly inherits from `inherited_id` (one row per
/// `is`-spec). Either endpoint may refer to a contract or an interface
/// (Solidity contracts inherit from both); the persistence layer keeps
/// no FK to disambiguate — consumers join through [`crate::cg::CallGraph`]
/// when they need the distinction.
#[derive(Deserialize, Serialize, Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ContractInherit {
    pub contract_id: i32,
    pub inherited_id: i32,
}

/// All `is`-clause edges across the project. Direct only — transitive
/// closure is computed on demand via [`InheritanceGraph::descendants_of`]
/// / [`InheritanceGraph::ancestors_of`].
#[derive(Deserialize, Serialize, Clone, Debug, Default)]
pub struct InheritanceGraph {
    pub inherits: Vec<ContractInherit>,
}

impl InheritanceGraph {
    pub fn new(inherits: Vec<ContractInherit>) -> Self {
        Self { inherits }
    }

    pub fn is_empty(&self) -> bool {
        self.inherits.is_empty()
    }

    pub fn len(&self) -> usize {
        self.inherits.len()
    }

    /// `descendants[i]` = set of contracts that (transitively) inherit `i`.
    /// `i` itself is not included.
    fn build_descendant_index(&self) -> BTreeMap<i32, Vec<i32>> {
        // Edge `(child, parent)` → `parent → [child, ...]`.
        let mut children: BTreeMap<i32, Vec<i32>> = BTreeMap::new();
        for edge in &self.inherits {
            children
                .entry(edge.inherited_id)
                .or_default()
                .push(edge.contract_id);
        }
        children
    }

    fn build_ancestor_index(&self) -> BTreeMap<i32, Vec<i32>> {
        let mut parents: BTreeMap<i32, Vec<i32>> = BTreeMap::new();
        for edge in &self.inherits {
            parents
                .entry(edge.contract_id)
                .or_default()
                .push(edge.inherited_id);
        }
        parents
    }

    /// Reverse closure: every contract that inherits `ancestor_id`
    /// directly or transitively. Excludes `ancestor_id` itself.
    pub fn descendants_of(&self, ancestor_id: i32) -> BTreeSet<i32> {
        let children = self.build_descendant_index();
        Self::bfs_closure(&children, ancestor_id)
    }

    /// Forward closure: every contract that `child_id` inherits
    /// directly or transitively. Excludes `child_id` itself.
    pub fn ancestors_of(&self, child_id: i32) -> BTreeSet<i32> {
        let parents = self.build_ancestor_index();
        Self::bfs_closure(&parents, child_id)
    }

    fn bfs_closure(index: &BTreeMap<i32, Vec<i32>>, start: i32) -> BTreeSet<i32> {
        let mut out: BTreeSet<i32> = BTreeSet::new();
        let mut queue: VecDeque<i32> = VecDeque::new();
        queue.push_back(start);
        while let Some(node) = queue.pop_front() {
            if let Some(neighbours) = index.get(&node) {
                for &next in neighbours {
                    if out.insert(next) {
                        queue.push_back(next);
                    }
                }
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn edge(c: i32, i: i32) -> ContractInherit {
        ContractInherit {
            contract_id: c,
            inherited_id: i,
        }
    }

    #[test]
    fn descendants_transitive() {
        // 3 → 2 → 1 (3 inherits 2 which inherits 1)
        let g = InheritanceGraph::new(vec![edge(2, 1), edge(3, 2)]);
        assert_eq!(g.descendants_of(1), BTreeSet::from([2, 3]));
        assert_eq!(g.descendants_of(2), BTreeSet::from([3]));
        assert_eq!(g.descendants_of(3), BTreeSet::new());
    }

    #[test]
    fn ancestors_transitive() {
        let g = InheritanceGraph::new(vec![edge(2, 1), edge(3, 2)]);
        assert_eq!(g.ancestors_of(3), BTreeSet::from([1, 2]));
        assert_eq!(g.ancestors_of(2), BTreeSet::from([1]));
        assert_eq!(g.ancestors_of(1), BTreeSet::new());
    }

    #[test]
    fn cycle_safe() {
        // Solidity rejects this but the algorithm shouldn't loop if a
        // malformed DB ever sneaks one through.
        let g = InheritanceGraph::new(vec![edge(1, 2), edge(2, 1)]);
        let d = g.descendants_of(1);
        assert!(d.contains(&2) && d.contains(&1));
    }
}
