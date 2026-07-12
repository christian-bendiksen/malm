//! A value-keyed DAG over petgraph with cycle checks, parallel batches, and
//! transitive dependency ordering.
//! Adapted from AerynOS moss-rs.

// SPDX-FileCopyrightText: 2023 AerynOS Developers
// SPDX-License-Identifier: MPL-2.0

use petgraph::{
    Direction,
    algo::has_path_connecting,
    stable_graph::StableDiGraph,
    visit::{Dfs, Reversed, Topo, Walker},
};
use std::collections::{HashMap, HashSet};
use std::hash::Hash;

/// Node index type used by the original moss-rs implementation.
pub type NodeIndex = petgraph::stable_graph::NodeIndex<u32>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddEdgeError {
    MissingNode,
    Duplicate,
    Cycle,
}

impl std::fmt::Display for AddEdgeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AddEdgeError::Cycle => write!(f, "Cannot add edge: would create a cycle"),
            AddEdgeError::Duplicate => write!(f, "Cannot add edge: edge already exists"),
            AddEdgeError::MissingNode => {
                write!(f, "Cannot add edge: one or both nodes are missing")
            }
        }
    }
}

impl std::error::Error for AddEdgeError {}

/// A value-keyed directed acyclic graph built on petgraph.
#[derive(Debug, Clone)]
pub struct Dag<N> {
    graph: StableDiGraph<N, (), u32>,
    node_map: HashMap<N, NodeIndex>,
}

impl<N> Default for Dag<N> {
    fn default() -> Self {
        Self {
            graph: StableDiGraph::default(),
            node_map: HashMap::new(),
        }
    }
}

impl<N> AsRef<StableDiGraph<N, (), u32>> for Dag<N> {
    fn as_ref(&self) -> &StableDiGraph<N, (), u32> {
        &self.graph
    }
}

/// Methods that do not require node values to implement `Eq` or `Hash`.
impl<N> Dag<N> {
    /// Creates an empty DAG.
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns node indices in topological order.
    fn topo_indices(&self) -> impl Iterator<Item = NodeIndex> + '_ {
        Topo::new(&self.graph).iter(&self.graph)
    }

    /// Adds an edge from `a` to `b`.
    pub fn add_edge(&mut self, a: NodeIndex, b: NodeIndex) -> Result<(), AddEdgeError> {
        if !self.graph.contains_node(a) || !self.graph.contains_node(b) {
            return Err(AddEdgeError::MissingNode);
        }
        if self.graph.contains_edge(a, b) {
            return Err(AddEdgeError::Duplicate);
        }
        // The edge would form a cycle if b already reaches a.
        if has_path_connecting(&self.graph, b, a, None) {
            return Err(AddEdgeError::Cycle);
        }
        self.graph.add_edge(a, b, ());
        Ok(())
    }

    /// Groups nodes into batches that can run in parallel.
    ///
    /// Node order within each batch is unspecified. Use
    /// [`Self::batched_topo_sorted`] when it must be deterministic.
    pub fn batched_topo(&self) -> Vec<Vec<N>>
    where
        N: Clone,
    {
        let mut in_degrees = HashMap::new();
        let mut zero_in_degree = Vec::new();

        let total_nodes = self.graph.node_count();

        for node_idx in self.graph.node_indices() {
            let degree = self
                .graph
                .edges_directed(node_idx, Direction::Incoming)
                .count();
            if degree == 0 {
                zero_in_degree.push(node_idx);
            } else {
                in_degrees.insert(node_idx, degree);
            }
        }

        let mut batches = Vec::new();

        while !zero_in_degree.is_empty() {
            let mut next_zero_in_degree = Vec::new();
            let mut current_batch = Vec::with_capacity(zero_in_degree.len());

            for current_node in zero_in_degree {
                current_batch.push(self.graph[current_node].clone());

                for neighbor in self
                    .graph
                    .neighbors_directed(current_node, Direction::Outgoing)
                {
                    if let Some(degree) = in_degrees.get_mut(&neighbor) {
                        *degree -= 1;
                        if *degree == 0 {
                            next_zero_in_degree.push(neighbor);
                            in_degrees.remove(&neighbor);
                        }
                    }
                }
            }

            batches.push(current_batch);
            zero_in_degree = next_zero_in_degree;
        }

        debug_assert_eq!(
            batches.iter().map(Vec::len).sum::<usize>(),
            total_nodes,
            "batched_topo dropped nodes — possible cycle in DAG"
        );

        batches
    }

    /// Groups nodes into parallel batches with deterministic node ordering
    /// within each batch.
    pub fn batched_topo_sorted(&self) -> Vec<Vec<N>>
    where
        N: Clone + Ord,
    {
        let mut batches = self.batched_topo();
        for batch in &mut batches {
            batch.sort();
        }
        batches
    }
}

/// Value-based methods for node types that implement `Eq` and `Hash`.
impl<N> Dag<N>
where
    N: Clone + Eq + Hash,
{
    pub fn add_node_or_get_index(&mut self, node: &N) -> NodeIndex {
        if let Some(&index) = self.node_map.get(node) {
            index
        } else {
            let index = self.graph.add_node(node.clone());
            self.node_map.insert(node.clone(), index);
            index
        }
    }

    pub fn get_index(&self, node: &N) -> Option<NodeIndex> {
        self.node_map.get(node).copied()
    }

    /// Adds an edge from a dependency to the node that depends on it.
    pub fn add_dependency(&mut self, dependency: &N, dependent: &N) -> Result<(), AddEdgeError> {
        let dependency = self
            .get_index(dependency)
            .ok_or(AddEdgeError::MissingNode)?;
        let dependent = self.get_index(dependent).ok_or(AddEdgeError::MissingNode)?;
        self.add_edge(dependency, dependent)
    }

    /// Returns `node` and its transitive dependencies in topological order.
    ///
    /// Each dependency appears before its dependents. Returns `None` if `node`
    /// is not in the graph.
    // Reverse DFS collects the dependencies; the forward topological order
    // then places each dependency before its dependents.
    pub fn dependency_order(&self, node: &N) -> Option<Vec<&N>> {
        let start = self.get_index(node)?;
        let reversed = Reversed(&self.graph);
        let dependencies: HashSet<NodeIndex> = Dfs::new(reversed, start).iter(reversed).collect();

        Some(
            self.topo_indices()
                .filter(|idx| dependencies.contains(idx))
                .map(|idx| &self.graph[idx])
                .collect(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_batched_linear_dag() {
        let mut graph: Dag<i32> = Dag::new();

        // A -> B -> C -> D
        let a = graph.add_node_or_get_index(&1);
        let b = graph.add_node_or_get_index(&2);
        let c = graph.add_node_or_get_index(&3);
        let d = graph.add_node_or_get_index(&4);

        graph.add_edge(a, b).unwrap();
        graph.add_edge(b, c).unwrap();
        graph.add_edge(c, d).unwrap();

        let batches = graph.batched_topo();

        // A chain puts each node in its own batch.
        assert_eq!(batches.len(), 4);
        for batch in &batches {
            assert_eq!(batch.len(), 1);
        }
    }

    #[test]
    fn test_topo_batched_simple_dag() {
        let mut graph: Dag<usize> = Dag::new();

        // Two branches converge at E:
        //   A -> C -> E
        //   B -> D -> E
        let a = graph.add_node_or_get_index(&1);
        let b = graph.add_node_or_get_index(&2);
        let c = graph.add_node_or_get_index(&3);
        let d = graph.add_node_or_get_index(&4);
        let e = graph.add_node_or_get_index(&5);

        graph.add_edge(a, c).unwrap();
        graph.add_edge(b, d).unwrap();
        graph.add_edge(c, e).unwrap();
        graph.add_edge(d, e).unwrap();

        let batches = graph.batched_topo();

        assert_eq!(batches.len(), 3);

        let val_a = &graph.as_ref()[a];
        let val_b = &graph.as_ref()[b];
        let val_c = &graph.as_ref()[c];
        let val_d = &graph.as_ref()[d];
        let val_e = &graph.as_ref()[e];

        // Roots: A and B.
        assert_eq!(batches[0].len(), 2);
        assert!(batches[0].contains(val_a));
        assert!(batches[0].contains(val_b));

        // Middle layer: C and D.
        assert_eq!(batches[1].len(), 2);
        assert!(batches[1].contains(val_c));
        assert!(batches[1].contains(val_d));

        // Sink: E.
        assert_eq!(batches[2].len(), 1);
        assert!(batches[2].contains(val_e));
    }

    #[test]
    fn test_topo_batched_fully_parallel() {
        let mut graph: Dag<char> = Dag::new();

        // Four independent nodes.
        let _a = graph.add_node_or_get_index(&'A');
        let _b = graph.add_node_or_get_index(&'B');
        let _c = graph.add_node_or_get_index(&'C');
        let _d = graph.add_node_or_get_index(&'D');

        let batches = graph.batched_topo();

        // All four share one batch.
        assert_eq!(batches.len(), 1);
        assert_eq!(batches[0].len(), 4);
    }

    #[test]
    fn test_topo_batched_empty_graph() {
        let graph: Dag<i32> = Dag::new();
        let batches = graph.batched_topo();
        assert_eq!(batches.len(), 0);
    }

    #[test]
    fn dependency_order_includes_transitive_diamond_dependencies() {
        let mut graph = Dag::new();
        for node in ["base", "left", "right", "leaf"] {
            graph.add_node_or_get_index(&node);
        }
        graph.add_dependency(&"base", &"left").unwrap();
        graph.add_dependency(&"base", &"right").unwrap();
        graph.add_dependency(&"left", &"leaf").unwrap();
        graph.add_dependency(&"right", &"leaf").unwrap();

        let order = graph.dependency_order(&"leaf").unwrap();
        let position = |node| {
            order
                .iter()
                .position(|&&candidate| candidate == node)
                .unwrap()
        };

        assert_eq!(order.len(), 4);
        assert!(position("base") < position("left"));
        assert!(position("base") < position("right"));
        assert!(position("left") < position("leaf"));
        assert!(position("right") < position("leaf"));
    }

    #[test]
    fn value_edges_report_missing_duplicate_and_cycle_errors() {
        let mut graph = Dag::new();
        graph.add_node_or_get_index(&"a");
        graph.add_node_or_get_index(&"b");

        assert_eq!(
            graph.add_dependency(&"missing", &"b"),
            Err(AddEdgeError::MissingNode)
        );
        graph.add_dependency(&"a", &"b").unwrap();
        assert_eq!(
            graph.add_dependency(&"a", &"b"),
            Err(AddEdgeError::Duplicate)
        );
        assert_eq!(graph.add_dependency(&"b", &"a"), Err(AddEdgeError::Cycle));
        assert_eq!(graph.dependency_order(&"missing"), None);
    }

    #[test]
    fn sorted_batches_are_deterministic() {
        let mut graph = Dag::new();
        for node in [3, 1, 2, 4] {
            graph.add_node_or_get_index(&node);
        }
        graph.add_dependency(&1, &4).unwrap();
        graph.add_dependency(&2, &4).unwrap();
        graph.add_dependency(&3, &4).unwrap();

        assert_eq!(graph.batched_topo_sorted(), vec![vec![1, 2, 3], vec![4]]);
    }

    #[test]
    fn self_loop_is_rejected_as_cycle() {
        let mut graph: Dag<i32> = Dag::new();
        let a = graph.add_node_or_get_index(&1);
        assert_eq!(graph.add_edge(a, a), Err(AddEdgeError::Cycle));
    }
}
