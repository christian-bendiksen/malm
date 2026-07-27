use std::collections::{BTreeMap, BTreeSet, VecDeque};

use malm_types::Digest;

use crate::{
    MAX_TREE_AGGREGATE_FILE_BYTES, MAX_TREE_DEPTH, MAX_TREE_ENTRIES, MAX_TREE_PATH_BYTES,
    SymlinkObjectV1, TreeEntryKindV1, TreeObjectV1, TreePathSegmentV1, symlink_object_digest_v1,
    tree_object_digest_v1,
};

/// Resource totals for one completely validated logical tree graph.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TreeSummaryV1 {
    entries: usize,
    file_bytes: u64,
    depth: usize,
}

impl TreeSummaryV1 {
    #[must_use]
    pub const fn entries(self) -> usize {
        self.entries
    }

    /// Returns logical file bytes, including repeated objects.
    #[must_use]
    pub const fn file_bytes(self) -> u64 {
        self.file_bytes
    }

    /// Returns the deepest entry path in segments.
    #[must_use]
    pub const fn depth(self) -> usize {
        self.depth
    }
}

/// A closed, validated set of tree and symlink objects rooted at one tree digest.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TreeGraphV1 {
    root: Digest,
    trees: BTreeMap<Digest, TreeObjectV1>,
    symlinks: BTreeMap<Digest, SymlinkObjectV1>,
    summary: TreeSummaryV1,
}

impl TreeGraphV1 {
    /// Indexes canonical objects by their computed identities and validates the
    /// complete graph reachable from `root`.
    pub fn new<T, S>(root: Digest, trees: T, symlinks: S) -> Result<Self, TreeGraphError>
    where
        T: IntoIterator<Item = TreeObjectV1>,
        S: IntoIterator<Item = SymlinkObjectV1>,
    {
        let mut tree_index = BTreeMap::new();
        for tree in trees {
            let digest = tree_object_digest_v1(&tree);
            if tree_index
                .insert(digest.clone(), tree.clone())
                .is_some_and(|previous| previous != tree)
            {
                return Err(TreeGraphError::ObjectDigestCollision { digest });
            }
        }
        let mut symlink_index = BTreeMap::new();
        for symlink in symlinks {
            let digest = symlink_object_digest_v1(&symlink);
            if symlink_index
                .insert(digest.clone(), symlink.clone())
                .is_some_and(|previous| previous != symlink)
            {
                return Err(TreeGraphError::ObjectDigestCollision { digest });
            }
        }

        let summary = validate_graph(&root, &tree_index, &symlink_index)?;
        Ok(Self {
            root,
            trees: tree_index,
            symlinks: symlink_index,
            summary,
        })
    }

    #[must_use]
    pub const fn root_digest(&self) -> &Digest {
        &self.root
    }

    #[must_use]
    pub fn root(&self) -> &TreeObjectV1 {
        self.trees
            .get(&self.root)
            .expect("validated graph retains its root object")
    }

    #[must_use]
    pub fn tree_object(&self, digest: &Digest) -> Option<&TreeObjectV1> {
        self.trees.get(digest)
    }

    #[must_use]
    pub fn symlink_object(&self, digest: &Digest) -> Option<&SymlinkObjectV1> {
        self.symlinks.get(digest)
    }

    #[must_use]
    pub const fn summary(&self) -> TreeSummaryV1 {
        self.summary
    }
}

/// An invalid object graph or tree resource total.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
#[non_exhaustive]
pub enum TreeGraphError {
    #[error("tree path {path:?} references missing tree {digest}")]
    MissingTreeObject { digest: Digest, path: String },
    #[error("tree path {path:?} references missing symlink {digest}")]
    MissingSymlinkObject { digest: Digest, path: String },
    #[error("distinct objects have the same digest {digest}")]
    ObjectDigestCollision { digest: Digest },
    #[error("directory cycle at {path:?} through {digest}")]
    DirectoryCycle { digest: Digest, path: String },
    #[error("symlink cycle at {path:?}")]
    SymlinkCycle { path: String },
    #[error("directory {path:?} has entry mode {entry_mode:#o} but child root mode {root_mode:#o}")]
    DirectoryModeMismatch {
        path: String,
        entry_mode: u32,
        root_mode: u32,
    },
    #[error("unsafe relative symlink {path:?}: {reason}")]
    UnsafeSymlink { path: String, reason: &'static str },
    #[error("tree path {path:?} has depth {actual}; limit is {limit}")]
    DepthExceeded {
        path: String,
        limit: usize,
        actual: usize,
    },
    #[error("tree path has {path_bytes} UTF-8 bytes; limit is {limit}")]
    PathTooLong { path_bytes: usize, limit: usize },
    #[error("logical tree has {actual} entries; limit is {limit}")]
    TooManyEntries { limit: usize, actual: usize },
    #[error("logical tree has {actual} file bytes; limit is {limit}")]
    AggregateFileBytesExceeded { limit: u64, actual: u64 },
    #[error("file object {digest} has conflicting lengths {first} and {second}")]
    ConflictingFileLength {
        digest: Digest,
        first: u64,
        second: u64,
    },
}

#[derive(Default)]
struct WalkState {
    entries: usize,
    file_bytes: u64,
    depth: usize,
    file_lengths: BTreeMap<Digest, u64>,
    links: BTreeMap<String, Digest>,
}

struct Walk<'a> {
    trees: &'a BTreeMap<Digest, TreeObjectV1>,
    symlinks: &'a BTreeMap<Digest, SymlinkObjectV1>,
    ancestors: BTreeSet<Digest>,
    state: WalkState,
}

fn validate_graph(
    root: &Digest,
    trees: &BTreeMap<Digest, TreeObjectV1>,
    symlinks: &BTreeMap<Digest, SymlinkObjectV1>,
) -> Result<TreeSummaryV1, TreeGraphError> {
    if !trees.contains_key(root) {
        return Err(TreeGraphError::MissingTreeObject {
            digest: root.clone(),
            path: String::new(),
        });
    }
    let mut walk = Walk {
        trees,
        symlinks,
        ancestors: BTreeSet::new(),
        state: WalkState::default(),
    };
    walk.walk_tree(root, "", 0)?;
    validate_symlinks(&walk.state.links, symlinks)?;
    Ok(TreeSummaryV1 {
        entries: walk.state.entries,
        file_bytes: walk.state.file_bytes,
        depth: walk.state.depth,
    })
}

impl Walk<'_> {
    fn walk_tree(
        &mut self,
        digest: &Digest,
        prefix: &str,
        depth: usize,
    ) -> Result<(), TreeGraphError> {
        if !self.ancestors.insert(digest.clone()) {
            return Err(TreeGraphError::DirectoryCycle {
                digest: digest.clone(),
                path: prefix.to_owned(),
            });
        }
        let tree = self
            .trees
            .get(digest)
            .ok_or_else(|| TreeGraphError::MissingTreeObject {
                digest: digest.clone(),
                path: prefix.to_owned(),
            })?;

        for entry in tree.entries() {
            let path = join_path(prefix, entry.name().as_str());
            let entry_depth = depth + 1;
            if entry_depth > MAX_TREE_DEPTH {
                return Err(TreeGraphError::DepthExceeded {
                    path,
                    limit: MAX_TREE_DEPTH,
                    actual: entry_depth,
                });
            }
            if path.len() > MAX_TREE_PATH_BYTES {
                return Err(TreeGraphError::PathTooLong {
                    path_bytes: path.len(),
                    limit: MAX_TREE_PATH_BYTES,
                });
            }
            self.state.entries = self.state.entries.saturating_add(1);
            if self.state.entries > MAX_TREE_ENTRIES {
                return Err(TreeGraphError::TooManyEntries {
                    limit: MAX_TREE_ENTRIES,
                    actual: self.state.entries,
                });
            }
            self.state.depth = self.state.depth.max(entry_depth);

            match entry.kind() {
                TreeEntryKindV1::File { digest, byte_len } => {
                    self.state.file_bytes = self.state.file_bytes.saturating_add(*byte_len);
                    if self.state.file_bytes > MAX_TREE_AGGREGATE_FILE_BYTES {
                        return Err(TreeGraphError::AggregateFileBytesExceeded {
                            limit: MAX_TREE_AGGREGATE_FILE_BYTES,
                            actual: self.state.file_bytes,
                        });
                    }
                    if let Some(first) = self.state.file_lengths.insert(digest.clone(), *byte_len)
                        && first != *byte_len
                    {
                        return Err(TreeGraphError::ConflictingFileLength {
                            digest: digest.clone(),
                            first,
                            second: *byte_len,
                        });
                    }
                }
                TreeEntryKindV1::Directory {
                    digest: child_digest,
                } => {
                    let child = self.trees.get(child_digest).ok_or_else(|| {
                        TreeGraphError::MissingTreeObject {
                            digest: child_digest.clone(),
                            path: path.clone(),
                        }
                    })?;
                    if entry.mode() != child.root_mode() {
                        return Err(TreeGraphError::DirectoryModeMismatch {
                            path,
                            entry_mode: entry.mode(),
                            root_mode: child.root_mode(),
                        });
                    }
                    self.walk_tree(child_digest, &path, entry_depth)?;
                }
                TreeEntryKindV1::SafeRelativeSymlink { digest } => {
                    if !self.symlinks.contains_key(digest) {
                        return Err(TreeGraphError::MissingSymlinkObject {
                            digest: digest.clone(),
                            path,
                        });
                    }
                    self.state.links.insert(path, digest.clone());
                }
            }
        }
        self.ancestors.remove(digest);
        Ok(())
    }
}

fn validate_symlinks(
    links: &BTreeMap<String, Digest>,
    objects: &BTreeMap<Digest, SymlinkObjectV1>,
) -> Result<(), TreeGraphError> {
    let mut targets = BTreeMap::new();
    for (path, digest) in links {
        let object = objects
            .get(digest)
            .expect("tree walk checked every symlink reference");
        targets.insert(path.clone(), safe_target_path(path, object.target())?);
    }

    let mut edges = BTreeMap::<String, Vec<String>>::new();
    let mut incoming = links
        .keys()
        .map(|path| (path.clone(), 0_usize))
        .collect::<BTreeMap<_, _>>();
    for (path, target) in &targets {
        let mut prefix = String::new();
        for segment in target.split('/') {
            if segment.is_empty() {
                continue;
            }
            prefix = join_path(&prefix, segment);
            if links.contains_key(&prefix) {
                edges.entry(path.clone()).or_default().push(prefix.clone());
                *incoming
                    .get_mut(&prefix)
                    .expect("symlink dependency has an incoming counter") += 1;
            }
        }
    }

    let mut ready = incoming
        .iter()
        .filter_map(|(path, count)| (*count == 0).then_some(path.clone()))
        .collect::<VecDeque<_>>();
    let mut visited = 0_usize;
    while let Some(path) = ready.pop_front() {
        visited += 1;
        for dependency in edges.get(&path).into_iter().flatten() {
            let count = incoming
                .get_mut(dependency)
                .expect("symlink dependency has an incoming counter");
            *count -= 1;
            if *count == 0 {
                ready.push_back(dependency.clone());
            }
        }
    }
    if visited != incoming.len() {
        let path = incoming
            .into_iter()
            .find_map(|(path, count)| (count != 0).then_some(path))
            .expect("an incomplete topological walk leaves a cycle");
        return Err(TreeGraphError::SymlinkCycle { path });
    }
    Ok(())
}

fn safe_target_path(path: &str, target: &str) -> Result<String, TreeGraphError> {
    let unsafe_target = |reason| TreeGraphError::UnsafeSymlink {
        path: path.to_owned(),
        reason,
    };
    if target.starts_with('/') {
        return Err(unsafe_target("target must be relative"));
    }
    if target.contains('\\') {
        return Err(unsafe_target("target must not contain backslash"));
    }
    for segment in target.split('/') {
        TreePathSegmentV1::new(segment)
            .map_err(|_| unsafe_target("target must contain only canonical path segments"))?;
    }
    let parent = path.rsplit_once('/').map_or("", |(parent, _)| parent);
    let resolved = if parent.is_empty() {
        target.to_owned()
    } else {
        join_path(parent, target)
    };
    let depth = resolved.split('/').count();
    if depth > MAX_TREE_DEPTH {
        return Err(unsafe_target(
            "resolved target exceeds the tree depth limit",
        ));
    }
    if resolved.len() > MAX_TREE_PATH_BYTES {
        return Err(unsafe_target(
            "resolved target exceeds the tree path byte limit",
        ));
    }
    Ok(resolved)
}

fn join_path(parent: &str, child: &str) -> String {
    if parent.is_empty() {
        child.to_owned()
    } else {
        let mut path = String::with_capacity(parent.len() + 1 + child.len());
        path.push_str(parent);
        path.push('/');
        path.push_str(child);
        path
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        MAX_TREE_FILE_BYTES, TreeEntryV1, TreeGraphError, TreeObjectV1, TreePathSegmentV1,
    };

    fn segment(value: &str) -> TreePathSegmentV1 {
        TreePathSegmentV1::new(value).unwrap()
    }

    fn directory(name: &str, child: &TreeObjectV1) -> TreeEntryV1 {
        TreeEntryV1::directory(
            segment(name),
            child.root_mode(),
            tree_object_digest_v1(child),
        )
        .unwrap()
    }

    #[test]
    fn complete_graph_validates_references_modes_and_safe_links() {
        let target = SymlinkObjectV1::new("tool").unwrap();
        let child = TreeObjectV1::new(
            0o700,
            vec![
                TreeEntryV1::file(segment("tool"), 0o700, Digest::sha256(b"tool bytes"), 10)
                    .unwrap(),
            ],
        )
        .unwrap();
        let root = TreeObjectV1::new(
            0o755,
            vec![
                directory("bin", &child),
                TreeEntryV1::safe_relative_symlink(
                    segment("current"),
                    symlink_object_digest_v1(&target),
                ),
            ],
        )
        .unwrap();
        let graph =
            TreeGraphV1::new(tree_object_digest_v1(&root), [root, child], [target]).unwrap();
        assert_eq!(graph.summary().entries(), 3);
        assert_eq!(graph.summary().file_bytes(), 10);
        assert_eq!(graph.summary().depth(), 2);
    }

    #[test]
    fn graph_rejects_unsafe_and_cyclic_symlink_targets() {
        for target in ["/absolute", "../escape", "a/./b", "a//b", "a\\b"] {
            let symlink = SymlinkObjectV1::new(target).unwrap();
            let root = TreeObjectV1::new(
                0o755,
                vec![TreeEntryV1::safe_relative_symlink(
                    segment("link"),
                    symlink_object_digest_v1(&symlink),
                )],
            )
            .unwrap();
            assert!(matches!(
                TreeGraphV1::new(tree_object_digest_v1(&root), [root], [symlink]),
                Err(TreeGraphError::UnsafeSymlink { .. })
            ));
        }

        let a = SymlinkObjectV1::new("b").unwrap();
        let b = SymlinkObjectV1::new("a").unwrap();
        let root = TreeObjectV1::new(
            0o755,
            vec![
                TreeEntryV1::safe_relative_symlink(segment("a"), symlink_object_digest_v1(&a)),
                TreeEntryV1::safe_relative_symlink(segment("b"), symlink_object_digest_v1(&b)),
            ],
        )
        .unwrap();
        assert!(matches!(
            TreeGraphV1::new(tree_object_digest_v1(&root), [root], [a, b]),
            Err(TreeGraphError::SymlinkCycle { .. })
        ));
    }

    #[test]
    fn graph_enforces_depth_path_entry_and_aggregate_budgets_across_shared_objects() {
        let mut depth_objects = vec![TreeObjectV1::new(0o755, vec![]).unwrap()];
        for index in 0..MAX_TREE_DEPTH {
            let child = depth_objects.last().unwrap();
            depth_objects.push(
                TreeObjectV1::new(0o755, vec![directory(&format!("d{index}"), child)]).unwrap(),
            );
        }
        let depth_root = depth_objects.last().unwrap();
        let boundary =
            TreeGraphV1::new(tree_object_digest_v1(depth_root), depth_objects.clone(), []).unwrap();
        assert_eq!(boundary.summary().depth(), MAX_TREE_DEPTH);

        let child = depth_objects.last().unwrap();
        depth_objects.push(TreeObjectV1::new(0o755, vec![directory("too-deep", child)]).unwrap());
        let depth_root = depth_objects.last().unwrap();
        assert!(matches!(
            TreeGraphV1::new(tree_object_digest_v1(depth_root), depth_objects.clone(), []),
            Err(TreeGraphError::DepthExceeded { .. })
        ));

        let mut exact_path_segments = vec!["x".repeat(crate::MAX_TREE_SEGMENT_BYTES); 15];
        exact_path_segments.push("y".repeat(127));
        exact_path_segments.push("z".repeat(128));
        let mut exact_path_objects = vec![TreeObjectV1::new(0o755, vec![]).unwrap()];
        for name in exact_path_segments.iter().rev() {
            let child = exact_path_objects.last().unwrap();
            exact_path_objects
                .push(TreeObjectV1::new(0o755, vec![directory(name, child)]).unwrap());
        }
        let exact_path_root = exact_path_objects.last().unwrap();
        TreeGraphV1::new(
            tree_object_digest_v1(exact_path_root),
            exact_path_objects,
            [],
        )
        .unwrap();

        let long = "x".repeat(crate::MAX_TREE_SEGMENT_BYTES);
        let mut path_objects = vec![TreeObjectV1::new(0o755, vec![]).unwrap()];
        for _ in 0..17 {
            let child = path_objects.last().unwrap();
            path_objects.push(TreeObjectV1::new(0o755, vec![directory(&long, child)]).unwrap());
        }
        let path_root = path_objects.last().unwrap();
        assert!(matches!(
            TreeGraphV1::new(tree_object_digest_v1(path_root), path_objects, []),
            Err(TreeGraphError::PathTooLong { .. })
        ));

        let mut fanout_objects = vec![TreeObjectV1::new(0o755, vec![]).unwrap()];
        for _ in 0..16 {
            let child = fanout_objects.last().unwrap();
            fanout_objects.push(
                TreeObjectV1::new(0o755, vec![directory("a", child), directory("b", child)])
                    .unwrap(),
            );
        }
        let fanout_root = fanout_objects.last().unwrap();
        assert!(matches!(
            TreeGraphV1::new(tree_object_digest_v1(fanout_root), fanout_objects, []),
            Err(TreeGraphError::TooManyEntries { .. })
        ));

        let leaf = TreeObjectV1::new(
            0o755,
            vec![
                TreeEntryV1::file(
                    segment("large"),
                    0o644,
                    Digest::sha256(b"large"),
                    MAX_TREE_FILE_BYTES / 2 + 1,
                )
                .unwrap(),
            ],
        )
        .unwrap();
        let root =
            TreeObjectV1::new(0o755, vec![directory("a", &leaf), directory("b", &leaf)]).unwrap();
        assert!(matches!(
            TreeGraphV1::new(tree_object_digest_v1(&root), [root, leaf], []),
            Err(TreeGraphError::AggregateFileBytesExceeded { .. })
        ));
    }

    #[test]
    fn graph_rejects_missing_objects_and_directory_mode_disagreement() {
        let missing = Digest::sha256(b"missing tree");
        let root = TreeObjectV1::new(
            0o755,
            vec![TreeEntryV1::directory(segment("missing"), 0o755, missing).unwrap()],
        )
        .unwrap();
        assert!(matches!(
            TreeGraphV1::new(tree_object_digest_v1(&root), [root], []),
            Err(TreeGraphError::MissingTreeObject { .. })
        ));

        let child = TreeObjectV1::new(0o700, vec![]).unwrap();
        let root = TreeObjectV1::new(
            0o755,
            vec![
                TreeEntryV1::directory(segment("child"), 0o755, tree_object_digest_v1(&child))
                    .unwrap(),
            ],
        )
        .unwrap();
        assert!(matches!(
            TreeGraphV1::new(tree_object_digest_v1(&root), [root, child], []),
            Err(TreeGraphError::DirectoryModeMismatch { .. })
        ));
    }
}
