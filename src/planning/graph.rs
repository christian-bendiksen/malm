//! Builds operation dependencies, rejects overlapping destinations, and orders
//! removals before materialization.

use crate::planning::plan::Operation;
use crate::state::target_lock::physical_key;
use anyhow::Result;
use dag::{AddEdgeError, Dag};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

pub fn build_operation_graph(operations: &[Operation]) -> Result<Dag<usize>> {
    let (graph, errors) = analyze_operation_graph(operations)?;
    if errors.is_empty() {
        Ok(graph)
    } else {
        anyhow::bail!("{}", errors.join("\n"))
    }
}

pub(crate) fn analyze_operation_graph(
    operations: &[Operation],
) -> Result<(Dag<usize>, Vec<String>)> {
    let mut graph = Dag::new();
    for index in 0..operations.len() {
        graph.add_node_or_get_index(&index);
    }

    let physical_keys: Vec<Option<PathBuf>> = operations
        .iter()
        .map(|operation| operation.affected_target().map(physical_key))
        .collect();

    let lexical: Vec<(&Path, usize)> = operations
        .iter()
        .enumerate()
        .filter_map(|(index, operation)| operation.affected_target().map(|path| (path, index)))
        .collect();
    let physical: Vec<(&Path, usize)> = physical_keys
        .iter()
        .enumerate()
        .filter_map(|(index, key)| key.as_deref().map(|path| (path, index)))
        .collect();

    let mut candidates = overlapping_pairs(lexical);
    candidates.extend(overlapping_pairs(physical));

    let errors = {
        let mut analysis = GraphAnalysis {
            operations,
            graph: &mut graph,
            errors: Vec::new(),
            compared: BTreeSet::new(),
        };

        for (a, b) in candidates {
            let (left, right) = if a < b { (a, b) } else { (b, a) };
            let left_path = operations[left]
                .affected_target()
                .expect("candidate implies target");
            let right_path = operations[right]
                .affected_target()
                .expect("candidate implies target");
            // Two lexically different paths that resolve to the same physical
            // location are duplicates.
            let same_path = left_path == right_path || physical_keys[left] == physical_keys[right];
            analysis.order_pair(left, left_path, right, right_path, same_path)?;
        }

        analysis.errors
    };

    Ok((graph, errors))
}

// Sorted paths + a stack of active ancestors enumerates every
// ancestor/descendant pair in one pass.
fn overlapping_pairs(mut keys: Vec<(&Path, usize)>) -> Vec<(usize, usize)> {
    keys.sort();
    let mut stack: Vec<usize> = Vec::new();
    let mut pairs = Vec::new();
    for index in 0..keys.len() {
        while let Some(&top) = stack.last() {
            if keys[index].0.starts_with(keys[top].0) {
                break;
            }
            stack.pop();
        }
        for &ancestor in &stack {
            pairs.push((keys[ancestor].1, keys[index].1));
        }
        stack.push(index);
    }
    pairs
}

struct GraphAnalysis<'a> {
    operations: &'a [Operation],
    graph: &'a mut Dag<usize>,
    errors: Vec<String>,
    compared: BTreeSet<(usize, usize)>,
}

impl GraphAnalysis<'_> {
    // Ordering rules: deeper paths are removed before their parents, and a
    // path is removed before anything is materialized beneath it.
    fn order_pair(
        &mut self,
        left: usize,
        left_path: &Path,
        right: usize,
        right_path: &Path,
        same_path: bool,
    ) -> Result<()> {
        let pair = if left < right {
            (left, right)
        } else {
            (right, left)
        };
        if !self.compared.insert(pair) {
            return Ok(());
        }

        let left_materializes = self.operations[left].managed_target_after_apply().is_some();
        let right_materializes = self.operations[right]
            .managed_target_after_apply()
            .is_some();

        match (left_materializes, right_materializes) {
            // Assets merge into shared parents: each install manages only its
            // payload's top-level entries under the destination, so two assets
            // may share or nest destinations. Order them deterministically
            // (declaration order / parent first); the executor re-checks the
            // concrete entry paths once payloads are in the CAS.
            (true, true)
                if self.operations[left].is_asset() && self.operations[right].is_asset() =>
            {
                if same_path {
                    add_ordering(self.graph, pair.0, pair.1)?;
                } else {
                    let (shallower, deeper) = if left_path.starts_with(right_path) {
                        (right, left)
                    } else {
                        (left, right)
                    };
                    add_ordering(self.graph, shallower, deeper)?;
                }
            }
            (true, true) => {
                let relationship = if same_path {
                    "duplicate destination"
                } else {
                    "overlapping managed destinations"
                };
                self.errors.push(format!(
                    "{relationship}: {} [{}] and {} [{}]",
                    left_path.display(),
                    self.operations[left].declaration_label(),
                    right_path.display(),
                    self.operations[right].declaration_label()
                ));
            }
            (false, false) if same_path => self.errors.push(format!(
                "duplicate removal destination: {} [{}] and [{}]",
                left_path.display(),
                self.operations[left].declaration_label(),
                self.operations[right].declaration_label()
            )),
            (false, false) => {
                let (deeper, shallower) = if left_path.starts_with(right_path) {
                    (left, right)
                } else {
                    (right, left)
                };
                add_ordering(self.graph, deeper, shallower)?;
            }
            (false, true) => add_ordering(self.graph, left, right)?,
            (true, false) => add_ordering(self.graph, right, left)?,
        }

        Ok(())
    }
}

fn add_ordering(graph: &mut Dag<usize>, dependency: usize, dependent: usize) -> Result<()> {
    match graph.add_dependency(&dependency, &dependent) {
        Ok(()) | Err(AddEdgeError::Duplicate) => Ok(()),
        Err(error) => {
            anyhow::bail!("cannot order operations {dependency} and {dependent}: {error}")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pairs(paths: &[&str]) -> Vec<(usize, usize)> {
        let keys: Vec<(&Path, usize)> = paths
            .iter()
            .enumerate()
            .map(|(index, p)| (Path::new(*p), index))
            .collect();
        let mut found = overlapping_pairs(keys);
        for pair in &mut found {
            if pair.0 > pair.1 {
                *pair = (pair.1, pair.0);
            }
        }
        found.sort();
        found.dedup();
        found
    }

    #[test]
    fn overlapping_pairs_finds_ancestors_and_duplicates() {
        assert_eq!(pairs(&["/a/b", "/a", "/c"]), vec![(0, 1)]);
        assert_eq!(pairs(&["/a", "/a"]), vec![(0, 1)]);
        assert_eq!(
            pairs(&["/a/b/c", "/a", "/a/b"]),
            vec![(0, 1), (0, 2), (1, 2)]
        );
        assert_eq!(pairs(&["/x/1", "/x/2", "/x/3"]), vec![]);
    }

    #[test]
    fn overlapping_pairs_component_order_beats_byte_order() {
        assert_eq!(pairs(&["/a", "/a.b", "/a/c"]), vec![(0, 2)]);
    }

    fn asset(name: &str, dst: &str) -> Operation {
        Operation::InstallAsset {
            name: name.to_owned(),
            url: "https://example.invalid/a.tar.xz".to_owned(),
            target: PathBuf::from(dst),
            sha256: None,
            format: crate::assets::ArchiveFormat::TarXz,
            refresh_font_cache: false,
            declaration: None,
            previous: Vec::new(),
        }
    }

    fn symlink(target: &str) -> Operation {
        Operation::CreateSymlink {
            owner: crate::planning::plan::DeclarationOwner::Symlink,
            source: PathBuf::from("/repo/src"),
            target: PathBuf::from(target),
            policy: crate::config::MissingSourcePolicy::RequireSource,
            conflict: crate::config::ConflictPolicy::Backup,
        }
    }

    fn errors(ops: &[Operation]) -> Vec<String> {
        analyze_operation_graph(ops).unwrap().1
    }

    #[test]
    fn assets_may_share_and_nest_destinations() {
        assert!(errors(&[asset("a", "/themes"), asset("b", "/themes")]).is_empty());
        assert!(errors(&[asset("a", "/themes"), asset("b", "/themes/sub")]).is_empty());
    }

    #[test]
    fn non_asset_destination_conflicts_still_error() {
        let duplicate = errors(&[symlink("/t/x"), symlink("/t/x")]);
        assert_eq!(duplicate.len(), 1);
        assert!(
            duplicate[0].contains("duplicate destination"),
            "{duplicate:?}"
        );

        let overlap = errors(&[asset("a", "/themes"), symlink("/themes/style.css")]);
        assert_eq!(overlap.len(), 1);
        assert!(
            overlap[0].contains("overlapping managed destinations"),
            "{overlap:?}"
        );
    }
}
