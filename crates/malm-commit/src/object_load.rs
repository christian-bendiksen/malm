//! Loads immutable prepared records, artifact blobs, and canonical objects
//! under explicit decode limits.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs::File,
    sync::Arc,
};

use malm_store::{
    PreparedOperationV1, PreparedRecordV1, StateGenerationV1, StateTargetStateV1,
    decode_prepared_record_v1,
};
use malm_types::{ArtifactId, Digest, PreparedId};
use rustix::fs::{AtFlags, FileType, statat};

use crate::{
    CommitError, LoadedArtifacts, MAX_RETENTION_DECODED_BYTES, MAX_RETENTION_ENTRIES, StoreHandles,
    canonical, read_immutable,
};

pub(crate) fn load_prepared(
    store: &StoreHandles,
    plan_id: &PreparedId,
) -> Result<PreparedRecordV1, CommitError> {
    load_prepared_with_encoded_len(store, plan_id).map(|(prepared, _)| prepared)
}

pub(crate) fn load_prepared_with_encoded_len(
    store: &StoreHandles,
    plan_id: &PreparedId,
) -> Result<(PreparedRecordV1, usize), CommitError> {
    let path = store.root_path.join("prepared").join(plan_id.as_str());
    let prepared = store
        .prepared
        .as_ref()
        .ok_or_else(|| CommitError::MissingPlan(plan_id.clone()))?;
    let bytes = read_immutable(
        prepared,
        plan_id.as_str(),
        &path,
        store.uid,
        malm_store::MAX_PREPARED_RECORD_BYTES as u64,
    )?
    .ok_or_else(|| CommitError::MissingPlan(plan_id.clone()))?;
    let encoded_len = bytes.len();
    let prepared = decode_prepared_record_v1(plan_id, &bytes).map_err(CommitError::invalid_plan)?;
    Ok((prepared, encoded_len))
}

pub(crate) fn load_all_artifacts(
    store: &StoreHandles,
    prepared: &PreparedRecordV1,
) -> Result<LoadedArtifacts, CommitError> {
    let blobs = if prepared.artifacts().is_empty() {
        return Ok(BTreeMap::new());
    } else {
        store
            .blobs
            .as_ref()
            .ok_or_else(|| CommitError::MissingArtifact(prepared.artifacts()[0].digest().clone()))?
    };
    // Load bytes only for artifacts this plan will place. For every other
    // artifact, its content-addressed name and exact length prove its stored
    // shape; the next consumer verifies the digest when it reads the bytes.
    let referenced: BTreeSet<&ArtifactId> = prepared
        .operations()
        .iter()
        .filter_map(|operation| match operation {
            PreparedOperationV1::PlaceFile { artifact_id, .. } => Some(artifact_id),
            _ => None,
        })
        .collect();
    let mut by_digest = BTreeMap::<Digest, Arc<[u8]>>::new();
    let mut by_id = BTreeMap::new();
    for artifact in prepared.artifacts() {
        if !referenced.contains(artifact.id()) {
            let path = store
                .root_path
                .join("objects/blobs")
                .join(artifact.digest().as_str());
            let stat = statat(blobs, artifact.digest().as_str(), AtFlags::SYMLINK_NOFOLLOW)
                .map_err(|_| CommitError::MissingArtifact(artifact.digest().clone()))?;
            if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
                || u64::try_from(stat.st_size).unwrap_or(u64::MAX) != artifact.byte_len()
            {
                return Err(CommitError::InvalidStore(format!(
                    "artifact blob {} differs from its prepared metadata",
                    path.display()
                )));
            }
            continue;
        }
        let bytes = if let Some(bytes) = by_digest.get(artifact.digest()) {
            Arc::clone(bytes)
        } else {
            let path = store
                .root_path
                .join("objects/blobs")
                .join(artifact.digest().as_str());
            let bytes = read_immutable(
                blobs,
                artifact.digest().as_str(),
                &path,
                store.uid,
                malm_store::MAX_ARTIFACT_BLOB_BYTES,
            )?
            .ok_or_else(|| CommitError::MissingArtifact(artifact.digest().clone()))?;
            let actual = Digest::sha256(&bytes);
            if &actual != artifact.digest() {
                return Err(CommitError::CorruptArtifact {
                    expected: artifact.digest().clone(),
                    actual,
                });
            }
            if malm_types::usize_to_u64(bytes.len()) != artifact.byte_len() {
                return Err(CommitError::InvalidPlan(
                    "artifact length differs from prepared metadata".to_owned(),
                ));
            }
            let bytes = Arc::<[u8]>::from(bytes);
            by_digest.insert(artifact.digest().clone(), Arc::clone(&bytes));
            bytes
        };
        if malm_types::usize_to_u64(bytes.len()) != artifact.byte_len() {
            return Err(CommitError::InvalidPlan(
                "artifact length differs from prepared metadata".to_owned(),
            ));
        }
        by_id.insert(artifact.id().clone(), bytes);
    }
    Ok(by_id)
}

pub(crate) fn load_canonical_objects(
    store: &StoreHandles,
    prepared: &PreparedRecordV1,
    previous: Option<&StateGenerationV1>,
) -> Result<canonical::CanonicalObjects, CommitError> {
    let mut tree_roots = BTreeSet::new();
    let mut direct_symlinks = BTreeSet::new();
    collect_canonical_state_roots(
        prepared
            .desired_snapshot()
            .targets()
            .iter()
            .map(malm_store::StateTargetV1::state)
            .chain(
                previous
                    .into_iter()
                    .flat_map(StateGenerationV1::targets)
                    .map(malm_store::StateTargetV1::state),
            ),
        &mut tree_roots,
        &mut direct_symlinks,
    );
    tree_roots.extend(
        prepared
            .tracked_root()
            .map(|tracked| tracked.root_tree_digest().clone())
            .into_iter()
            .chain(
                previous
                    .and_then(StateGenerationV1::tracked_root)
                    .map(|tracked| tracked.root_tree_digest().clone()),
            ),
    );
    load_canonical_roots(store, tree_roots, direct_symlinks)
}

pub(crate) fn load_canonical_state_objects<'a>(
    store: &StoreHandles,
    states: impl IntoIterator<Item = &'a StateTargetStateV1>,
) -> Result<canonical::CanonicalObjects, CommitError> {
    let mut budget = CanonicalLoadBudget::default();
    load_canonical_state_objects_with_budget(store, states, &mut budget)
}

pub(crate) fn load_canonical_state_objects_with_budget<'a>(
    store: &StoreHandles,
    states: impl IntoIterator<Item = &'a StateTargetStateV1>,
    budget: &mut CanonicalLoadBudget,
) -> Result<canonical::CanonicalObjects, CommitError> {
    let mut tree_roots = BTreeSet::new();
    let mut direct_symlinks = BTreeSet::new();
    collect_canonical_state_roots(states, &mut tree_roots, &mut direct_symlinks);

    load_canonical_roots_with_budget(store, tree_roots, direct_symlinks, budget)
}

pub(crate) fn collect_canonical_state_roots<'a>(
    states: impl IntoIterator<Item = &'a StateTargetStateV1>,
    tree_roots: &mut BTreeSet<Digest>,
    direct_symlinks: &mut BTreeSet<Digest>,
) {
    for state in states {
        match state {
            StateTargetStateV1::Symlink {
                symlink: Some(symlink),
            } => {
                direct_symlinks.insert(symlink.object().clone());
            }
            StateTargetStateV1::Tree { tree: Some(tree) } => {
                tree_roots.insert(tree.tree().clone());
            }
            StateTargetStateV1::File { .. }
            | StateTargetStateV1::Directory { .. }
            | StateTargetStateV1::Symlink { symlink: None }
            | StateTargetStateV1::Tree { tree: None } => {}
        }
    }
}

pub(crate) fn load_canonical_roots(
    store: &StoreHandles,
    tree_roots: BTreeSet<Digest>,
    direct_symlinks: BTreeSet<Digest>,
) -> Result<canonical::CanonicalObjects, CommitError> {
    let mut budget = CanonicalLoadBudget::default();
    load_canonical_roots_with_budget(store, tree_roots, direct_symlinks, &mut budget)
}

#[derive(Default)]
pub(crate) struct CanonicalLoadBudget {
    pub(crate) traversed_items: usize,
    pub(crate) decoded_bytes: u64,
}

pub(crate) fn load_canonical_roots_with_budget(
    store: &StoreHandles,
    tree_roots: BTreeSet<Digest>,
    mut direct_symlinks: BTreeSet<Digest>,
    budget: &mut CanonicalLoadBudget,
) -> Result<canonical::CanonicalObjects, CommitError> {
    let mut objects = canonical::CanonicalObjects::empty();
    for root in &tree_roots {
        let mut pending_trees = vec![(root.clone(), 0_usize, 0_usize)];
        let mut logical_entries = 0_usize;
        let mut logical_file_bytes = 0_u64;
        while let Some((digest, depth, prefix_bytes)) = pending_trees.pop() {
            charge_canonical_load_item(budget)?;
            if !objects.trees.contains_key(&digest) {
                let bytes = read_canonical_object(
                    store,
                    store.trees.as_ref(),
                    "trees",
                    &digest,
                    canonical::MAX_TREE_OBJECT_BYTES,
                )?;
                charge_canonical_load_bytes(budget, bytes.len())?;
                let tree = canonical::decode_tree(&digest, &bytes)
                    .map_err(|error| invalid_canonical_object("tree", &digest, error))?;
                objects.trees.insert(digest.clone(), tree);
            }
            let tree = objects
                .trees
                .get(&digest)
                .expect("the canonical tree was loaded above");
            for entry in &tree.entries {
                charge_canonical_load_item(budget)?;
                let entry_depth = depth.saturating_add(1);
                if entry_depth > canonical::MAX_DEPTH {
                    return Err(invalid_canonical_graph(
                        root,
                        "the depth limit was exceeded while loading its closure",
                    ));
                }
                let path_bytes = prefix_bytes
                    .checked_add(usize::from(prefix_bytes != 0))
                    .and_then(|bytes| bytes.checked_add(entry.name.len()))
                    .unwrap_or(usize::MAX);
                if path_bytes > canonical::MAX_PATH_BYTES {
                    return Err(invalid_canonical_graph(
                        root,
                        "the path-byte limit was exceeded while loading its closure",
                    ));
                }
                if logical_entries == canonical::MAX_ENTRIES {
                    return Err(invalid_canonical_graph(
                        root,
                        "the logical-entry limit was exceeded while loading its closure",
                    ));
                }
                logical_entries += 1;
                match &entry.kind {
                    canonical::TreeEntryKind::File { digest, byte_len } => {
                        logical_file_bytes =
                            logical_file_bytes.checked_add(*byte_len).ok_or_else(|| {
                                invalid_canonical_graph(
                                    root,
                                    "the file-byte total overflowed while loading its closure",
                                )
                            })?;
                        if logical_file_bytes > canonical::MAX_FILE_BYTES {
                            return Err(invalid_canonical_graph(
                                root,
                                "the aggregate file-byte limit was exceeded while loading its closure",
                            ));
                        }
                        if !objects.files.contains_key(digest) {
                            let bytes = read_canonical_object(
                                store,
                                store.files.as_ref(),
                                "files",
                                digest,
                                canonical::MAX_FILE_OBJECT_BYTES,
                            )?;
                            charge_canonical_load_bytes(budget, bytes.len())?;
                            let contents = canonical::decode_file(digest, &bytes)
                                .map_err(|error| invalid_canonical_object("file", digest, error))?;
                            if u64::try_from(contents.len()).unwrap_or(u64::MAX) != *byte_len {
                                return Err(invalid_canonical_graph(
                                    root,
                                    "a file length differed while loading its closure",
                                ));
                            }
                            objects.files.insert(digest.clone(), contents);
                        }
                    }
                    canonical::TreeEntryKind::Directory { digest } => {
                        pending_trees.push((digest.clone(), entry_depth, path_bytes));
                    }
                    canonical::TreeEntryKind::Symlink { digest } => {
                        direct_symlinks.insert(digest.clone());
                    }
                }
            }
        }
    }
    for digest in direct_symlinks {
        if objects.symlinks.contains_key(&digest) {
            continue;
        }
        charge_canonical_load_item(budget)?;
        let bytes = read_canonical_object(
            store,
            store.symlinks.as_ref(),
            "symlinks",
            &digest,
            canonical::MAX_SYMLINK_OBJECT_BYTES,
        )?;
        charge_canonical_load_bytes(budget, bytes.len())?;
        let target = canonical::decode_symlink(&digest, &bytes)
            .map_err(|error| invalid_canonical_object("symlink", &digest, error))?;
        objects.symlinks.insert(digest, target);
    }
    for root in tree_roots {
        objects
            .validate_tree(&root)
            .map_err(|error| invalid_canonical_object("tree graph", &root, error))?;
    }
    store.revalidate()?;
    Ok(objects)
}

pub(crate) fn charge_canonical_load_item(
    budget: &mut CanonicalLoadBudget,
) -> Result<(), CommitError> {
    if budget.traversed_items == MAX_RETENTION_ENTRIES {
        return Err(CommitError::InvalidStore(format!(
            "canonical root traversal exceeds {MAX_RETENTION_ENTRIES} logical work items"
        )));
    }
    budget.traversed_items += 1;
    Ok(())
}

pub(crate) fn charge_canonical_load_bytes(
    budget: &mut CanonicalLoadBudget,
    bytes: usize,
) -> Result<(), CommitError> {
    budget.decoded_bytes = budget
        .decoded_bytes
        .saturating_add(u64::try_from(bytes).unwrap_or(u64::MAX));
    if budget.decoded_bytes > MAX_RETENTION_DECODED_BYTES {
        return Err(CommitError::InvalidStore(format!(
            "canonical root loading exceeds {MAX_RETENTION_DECODED_BYTES} decoded bytes"
        )));
    }
    Ok(())
}

pub(crate) fn invalid_canonical_graph(root: &Digest, detail: &str) -> CommitError {
    invalid_canonical_object(
        "tree graph",
        root,
        canonical::CanonicalObjectIssue::InvalidEncoding {
            detail: detail.to_owned(),
        },
    )
}

pub(crate) fn read_canonical_object(
    store: &StoreHandles,
    directory: Option<&File>,
    kind: &str,
    digest: &Digest,
    maximum: u64,
) -> Result<Vec<u8>, CommitError> {
    let directory = directory.ok_or_else(|| {
        CommitError::InvalidStore(format!("canonical {kind} object {digest} is missing"))
    })?;
    let path = store
        .root_path
        .join("objects")
        .join(kind)
        .join(digest.as_str());
    read_immutable(directory, digest.as_str(), &path, store.uid, maximum)?.ok_or_else(|| {
        CommitError::InvalidStore(format!("canonical {kind} object {digest} is missing"))
    })
}

pub(crate) fn invalid_canonical_object(
    kind: &str,
    digest: &Digest,
    issue: canonical::CanonicalObjectIssue,
) -> CommitError {
    CommitError::InvalidStore(format!(
        "canonical {kind} object {digest} is invalid: {issue}"
    ))
}
