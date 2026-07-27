//! Computes the objects retained by current authorities and removes objects
//! outside that closure.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs::File,
    path::{Path, PathBuf},
};

use malm_store::{
    OwnershipProjectionV1, PreparedInputKindV1, PreparedRecordV1, RestorePointV1,
    RetentionAuthorityV1, StateGenerationV1, StateTargetStateV1, TransformImplementationV1,
    decode_prepared_record_v1,
};
use malm_types::{Digest, PreparedId, PruneOutcomeV1, PruneRequestV1, RetentionObjectV1};
use rustix::fs::{AtFlags, Dir, FileType, fsync, statat, unlinkat};

use crate::object_load::{
    CanonicalLoadBudget, collect_canonical_state_roots, load_canonical_roots_with_budget,
};
use crate::{
    CommitConfig, CommitError, MAX_RETENTION_DECODED_BYTES, MAX_RETENTION_ENTRIES, StoreHandles,
    canonical, ensure_bound, invalid_canonical_object, io_error, pack_object, read_catalog,
    read_immutable, reject_projection_authority_aliases, validate_restore_point_reference,
};

pub(crate) fn prune_store(
    config: &CommitConfig,
    store: &StoreHandles,
    request: &PruneRequestV1,
    dry_run: bool,
) -> Result<PruneOutcomeV1, CommitError> {
    let mut decoded_bytes = 0_u64;
    let prepared = load_prepared_records(store, &mut decoded_bytes)?;
    for plan_id in request.plan_ids() {
        if !prepared.contains_key(plan_id) {
            return Err(CommitError::MissingPlan(plan_id.clone()));
        }
    }
    let mut verified_blobs = BTreeMap::new();
    for record in prepared.values() {
        for artifact in record.artifacts() {
            // This checks only existence and shape, so it does not consume the
            // decode budget.
            let length = if let Some(length) = verified_blobs.get(artifact.digest()) {
                *length
            } else {
                let length = verify_blob(store, artifact.digest())?;
                verified_blobs.insert(artifact.digest().clone(), length);
                length
            };
            if length != artifact.byte_len() {
                return Err(CommitError::InvalidPlan(
                    "artifact length differs from prepared metadata".to_owned(),
                ));
            }
        }
    }

    let generation_directory = GenerationDirectory::open(store)?;
    let generations = generation_directory.as_ref().map_or_else(
        || Ok(BTreeMap::new()),
        |directory| directory.load_all(store, &mut decoded_bytes),
    )?;
    for generation in generations.values() {
        let prepared_record = prepared.get(generation.plan_id()).ok_or_else(|| {
            CommitError::InvalidStore(format!(
                "state generation references missing plan {}",
                generation.plan_id()
            ))
        })?;
        let previous = generation
            .previous_generation()
            .and_then(|digest| generations.get(digest));
        let rebuilt = if generation.previous_generation().is_some() && previous.is_none() {
            StateGenerationV1::from_retained_prepared(
                generation.plan_id().clone(),
                generation.previous_generation().cloned(),
                prepared_record,
            )
        } else {
            StateGenerationV1::from_prepared(
                generation.plan_id().clone(),
                generation.previous_generation().cloned(),
                previous,
                prepared_record,
            )
        }
        .map_err(CommitError::invalid_store)?;
        if &rebuilt != generation {
            return Err(CommitError::InvalidStore(
                "state generation does not match its prepared transition".to_owned(),
            ));
        }
    }
    let mut all_tree_roots = BTreeSet::new();
    let mut all_direct_symlinks = BTreeSet::new();
    collect_canonical_state_roots(
        prepared
            .values()
            .flat_map(|record| record.desired_snapshot().targets())
            .chain(generations.values().flat_map(StateGenerationV1::targets))
            .map(malm_store::StateTargetV1::state),
        &mut all_tree_roots,
        &mut all_direct_symlinks,
    );
    all_tree_roots.extend(
        prepared
            .values()
            .filter_map(PreparedRecordV1::tracked_root)
            .chain(
                generations
                    .values()
                    .filter_map(StateGenerationV1::tracked_root),
            )
            .map(|tracked| tracked.root_tree_digest().clone()),
    );
    let mut canonical_budget = CanonicalLoadBudget {
        decoded_bytes,
        ..CanonicalLoadBudget::default()
    };
    load_canonical_roots_with_budget(
        store,
        all_tree_roots,
        all_direct_symlinks,
        &mut canonical_budget,
    )?;
    decoded_bytes = canonical_budget.decoded_bytes;
    let catalog = read_catalog(store)?;
    let selected = catalog
        .heads()
        .iter()
        .map(|head| {
            let generation = generations.get(head.generation()).ok_or_else(|| {
                CommitError::InvalidStore(format!(
                    "retained state generation {} is missing",
                    head.generation()
                ))
            })?;
            Ok((head.namespace(), generation))
        })
        .collect::<Result<Vec<_>, CommitError>>()?;
    let projection = OwnershipProjectionV1::from_selected_generations(selected)
        .map_err(CommitError::invalid_store)?;
    reject_projection_authority_aliases(config, store, &projection, None, true)?;
    let mut retained = RetainedClosure::default();
    for head in catalog.heads() {
        let generation = generations.get(head.generation()).ok_or_else(|| {
            CommitError::InvalidStore(format!(
                "retained state generation {} is missing",
                head.generation()
            ))
        })?;
        retained.generation_roots.push((
            head.generation().clone(),
            generation.retention_authority().history().generations(),
        ));
        if let Some(point) = generation.restore_point() {
            collect_restore_point_root(point, &generations, &mut retained.generation_roots)?;
        }
        collect_retention_authority_roots(
            generation.retention_authority(),
            &generations,
            &mut retained,
        )?;
    }
    for (plan_id, record) in &prepared {
        if request.plan_ids().binary_search(plan_id).is_ok() {
            continue;
        }
        if let Some(point) = record.restore_point() {
            collect_restore_point_root(point, &generations, &mut retained.generation_roots)?;
        }
        collect_retention_authority_roots(
            record.retention_authority(),
            &generations,
            &mut retained,
        )?;
    }

    let mut reachable_generations = BTreeSet::new();
    for (root, limit) in retained.generation_roots {
        let mut current = Some(root);
        let mut lineage = BTreeSet::new();
        for _ in 0..limit {
            let Some(digest) = current else {
                break;
            };
            if !lineage.insert(digest.clone()) {
                return Err(CommitError::InvalidStore(
                    "retained generation root contains a cycle".to_owned(),
                ));
            }
            let generation = generations.get(&digest).ok_or_else(|| {
                CommitError::InvalidStore(format!("retained state generation {digest} is missing"))
            })?;
            reachable_generations.insert(digest);
            current = generation.previous_generation().cloned();
        }
    }
    for digest in &reachable_generations {
        let generation = &generations[digest];
        retained.plan_ids.insert(generation.plan_id().clone());
        retained.blobs.extend(
            generation
                .artifacts()
                .iter()
                .map(|artifact| artifact.digest().clone()),
        );
        for target in generation.targets() {
            let StateTargetStateV1::File { file: Some(file) } = target.state() else {
                continue;
            };
            let length = if let Some(length) = verified_blobs.get(file.digest()) {
                *length
            } else {
                let length = verify_blob(store, file.digest())?;
                verified_blobs.insert(file.digest().clone(), length);
                length
            };
            if length != file.byte_len() {
                return Err(CommitError::InvalidStore(
                    "retained target length differs from its state metadata".to_owned(),
                ));
            }
            retained.blobs.insert(file.digest().clone());
        }
    }
    for plan_id in &retained.plan_ids {
        if !prepared.contains_key(plan_id) {
            return Err(CommitError::InvalidStore(format!(
                "explicitly retained prepared plan {plan_id} is missing"
            )));
        }
    }
    for plan_id in request.plan_ids() {
        if retained.plan_ids.contains(plan_id) {
            return Err(CommitError::PlanInUse(plan_id.clone()));
        }
    }
    // In sweep mode, remove every plan left unretained after the full
    // reachability pass, in addition to the explicit selections. All sweep
    // candidates contributed their retention roots before this decision, so a
    // sweep cannot collect an object that one of those plans retains. Repeated
    // sweeps therefore converge on the same retained closure.
    let pruned_plan_ids: Vec<PreparedId> = {
        let mut pruned: BTreeSet<PreparedId> = request.plan_ids().iter().cloned().collect();
        if request.sweeps_unreferenced() {
            pruned.extend(
                prepared
                    .keys()
                    .filter(|plan_id| !retained.plan_ids.contains(*plan_id))
                    .cloned(),
            );
        }
        pruned.into_iter().collect()
    };
    for (plan_id, record) in &prepared {
        if pruned_plan_ids.binary_search(plan_id).is_err() {
            retained.blobs.extend(
                record
                    .artifacts()
                    .iter()
                    .map(|artifact| artifact.digest().clone()),
            );
            retained.packs.extend(record_pack_roots(record));
        }
    }
    let mut retained_tree_roots = BTreeSet::new();
    let mut retained_direct_symlinks = BTreeSet::new();
    collect_canonical_state_roots(
        prepared
            .iter()
            .filter(|(plan_id, _)| pruned_plan_ids.binary_search(plan_id).is_err())
            .flat_map(|(_, record)| record.desired_snapshot().targets())
            .chain(
                generations
                    .iter()
                    .filter(|(digest, _)| reachable_generations.contains(digest))
                    .flat_map(|(_, generation)| generation.targets()),
            )
            .map(malm_store::StateTargetV1::state),
        &mut retained_tree_roots,
        &mut retained_direct_symlinks,
    );
    retained_tree_roots.extend(
        prepared
            .iter()
            .filter(|(plan_id, _)| pruned_plan_ids.binary_search(plan_id).is_err())
            .filter_map(|(_, record)| record.tracked_root())
            .chain(
                generations
                    .iter()
                    .filter(|(digest, _)| reachable_generations.contains(digest))
                    .filter_map(|(_, generation)| generation.tracked_root()),
            )
            .map(|tracked| tracked.root_tree_digest().clone()),
    );
    canonical_budget.decoded_bytes = decoded_bytes;
    let retained_canonical = load_canonical_roots_with_budget(
        store,
        retained_tree_roots,
        retained_direct_symlinks,
        &mut canonical_budget,
    )?;
    let pinned_canonical = load_canonical_roots_with_budget(
        store,
        retained.pinned_trees.clone(),
        retained.pinned_symlinks.clone(),
        &mut canonical_budget,
    )?;
    decoded_bytes = canonical_budget.decoded_bytes;
    retained
        .pinned_files
        .extend(pinned_canonical.files.keys().cloned());
    retained
        .pinned_symlinks
        .extend(pinned_canonical.symlinks.keys().cloned());
    retained
        .pinned_trees
        .extend(pinned_canonical.trees.keys().cloned());
    let mut retained_files = retained_canonical
        .files
        .keys()
        .cloned()
        .collect::<BTreeSet<_>>();
    let mut retained_symlinks = retained_canonical
        .symlinks
        .keys()
        .cloned()
        .collect::<BTreeSet<_>>();
    let mut retained_trees = retained_canonical
        .trees
        .keys()
        .cloned()
        .collect::<BTreeSet<_>>();
    retained_files.extend(retained.pinned_files);
    retained_symlinks.extend(retained.pinned_symlinks);
    retained_trees.extend(retained.pinned_trees);

    let all_blobs = load_blob_names(store)?;
    for digest in &retained.blobs {
        if !all_blobs.contains(digest) {
            return Err(CommitError::MissingArtifact(digest.clone()));
        }
    }
    // A retained deduplicated pack also retains its member blobs. Check each
    // member's stored length against the manifest before blob collection.
    for digest in &retained.packs {
        for (member, byte_len) in retained_pack_member_blobs(store, digest, &mut decoded_bytes)? {
            if let Some(length) = verified_blobs.get(&member) {
                if *length != byte_len {
                    return Err(CommitError::InvalidStore(format!(
                        "pack member blob {member} length differs from its manifest entry"
                    )));
                }
            } else {
                let length = verify_blob(store, &member)?;
                if length != byte_len {
                    return Err(CommitError::InvalidStore(format!(
                        "pack member blob {member} length differs from its manifest entry"
                    )));
                }
                verified_blobs.insert(member.clone(), length);
            }
            retained.blobs.insert(member);
        }
    }
    let removed_blobs = all_blobs
        .difference(&retained.blobs)
        .cloned()
        .collect::<Vec<_>>();
    let all_packs = load_pack_names(store)?;
    for digest in &retained.packs {
        if !all_packs.contains(digest) {
            return Err(CommitError::InvalidStore(format!(
                "retained pack object {digest} is missing"
            )));
        }
    }
    let removed_packs = all_packs
        .difference(&retained.packs)
        .cloned()
        .collect::<Vec<_>>();
    let all_files = load_canonical_names(
        store,
        store.files.as_ref(),
        "files",
        CanonicalRetentionKind::File,
        &mut decoded_bytes,
    )?;
    let all_symlinks = load_canonical_names(
        store,
        store.symlinks.as_ref(),
        "symlinks",
        CanonicalRetentionKind::Symlink,
        &mut decoded_bytes,
    )?;
    let all_trees = load_canonical_names(
        store,
        store.trees.as_ref(),
        "trees",
        CanonicalRetentionKind::Tree,
        &mut decoded_bytes,
    )?;
    for digest in &retained_files {
        if !all_files.contains(digest) {
            return Err(CommitError::InvalidStore(format!(
                "retained canonical file object {digest} is missing"
            )));
        }
    }
    for digest in &retained_symlinks {
        if !all_symlinks.contains(digest) {
            return Err(CommitError::InvalidStore(format!(
                "retained canonical symlink object {digest} is missing"
            )));
        }
    }
    for digest in &retained_trees {
        if !all_trees.contains(digest) {
            return Err(CommitError::InvalidStore(format!(
                "retained canonical tree object {digest} is missing"
            )));
        }
    }
    let removed_files = all_files
        .difference(&retained_files)
        .cloned()
        .collect::<Vec<_>>();
    let removed_symlinks = all_symlinks
        .difference(&retained_symlinks)
        .cloned()
        .collect::<Vec<_>>();
    let removed_trees = all_trees
        .difference(&retained_trees)
        .cloned()
        .collect::<Vec<_>>();
    for digest in &removed_blobs {
        if !verified_blobs.contains_key(digest) {
            let length = verify_blob(store, digest)?;
            verified_blobs.insert(digest.clone(), length);
        }
    }
    let removed_generations = order_generation_removals(&generations, &reachable_generations)?;

    let count = |entries: usize| malm_types::usize_to_u64(entries);
    let outcome = PruneOutcomeV1 {
        prepared_records: count(pruned_plan_ids.len()),
        artifact_blobs: count(removed_blobs.len()),
        state_generations: count(removed_generations.len()),
        pack_objects: count(removed_packs.len()),
        canonical_files: count(removed_files.len()),
        canonical_symlinks: count(removed_symlinks.len()),
        canonical_trees: count(removed_trees.len()),
    };
    if dry_run {
        store.revalidate()?;
        return Ok(outcome);
    }

    store.revalidate()?;
    if let Some(directory) = &generation_directory {
        directory.revalidate(store)?;
        remove_names(
            directory.generations,
            removed_generations.iter().map(Digest::as_str),
            &directory.path,
            "remove unreachable state generation",
            store.uid,
            malm_store::MAX_STATE_RECORD_BYTES as u64,
            RemovalSync::Each {
                after_remove_failpoint: Some("v1.prune.after_generation_remove"),
            },
        )?;
    }
    if let Some(directory) = &store.prepared {
        store.revalidate()?;
        remove_names(
            directory,
            pruned_plan_ids.iter().map(PreparedId::as_str),
            &store.root_path.join("prepared"),
            "remove prepared record",
            store.uid,
            malm_store::MAX_PREPARED_RECORD_BYTES as u64,
            RemovalSync::Batch,
        )?;
    }
    if let Some(directory) = &store.blobs {
        store.revalidate()?;
        remove_names(
            directory,
            removed_blobs.iter().map(Digest::as_str),
            &store.root_path.join("objects/blobs"),
            "remove unreachable artifact blob",
            store.uid,
            malm_store::MAX_ARTIFACT_BLOB_BYTES,
            RemovalSync::Batch,
        )?;
    }
    for (directory, area) in [
        (store.packs.as_ref(), "objects/packs"),
        (store.pack_manifests.as_ref(), "objects/pack-manifests"),
    ] {
        let Some(directory) = directory else {
            continue;
        };
        store.revalidate()?;
        // A pack has either a monolithic object or a manifest representation.
        // Remove an unreachable digest only from the representation that holds
        // it.
        let path = store.root_path.join(area);
        let present = directory_names(directory, &path)?
            .into_iter()
            .collect::<BTreeSet<_>>();
        remove_names(
            directory,
            removed_packs
                .iter()
                .map(Digest::as_str)
                .filter(|name| present.contains(*name)),
            &path,
            "remove unreachable pack object",
            store.uid,
            pack_object::MAX_PACK_OBJECT_BYTES,
            RemovalSync::Batch,
        )?;
    }
    for (directory, name, removed, role, maximum) in [
        (
            store.trees.as_ref(),
            "trees",
            &removed_trees,
            "remove unreachable canonical tree object",
            canonical::MAX_TREE_OBJECT_BYTES,
        ),
        (
            store.symlinks.as_ref(),
            "symlinks",
            &removed_symlinks,
            "remove unreachable canonical symlink object",
            canonical::MAX_SYMLINK_OBJECT_BYTES,
        ),
        (
            store.files.as_ref(),
            "files",
            &removed_files,
            "remove unreachable canonical file object",
            canonical::MAX_FILE_OBJECT_BYTES,
        ),
    ] {
        if let Some(directory) = directory {
            store.revalidate()?;
            remove_names(
                directory,
                removed.iter().map(Digest::as_str),
                &store.root_path.join("objects").join(name),
                role,
                store.uid,
                maximum,
                RemovalSync::Batch,
            )?;
        }
    }
    store.revalidate()?;
    Ok(outcome)
}

#[derive(Default)]
pub(crate) struct RetainedClosure {
    generation_roots: Vec<(Digest, u32)>,
    plan_ids: BTreeSet<PreparedId>,
    blobs: BTreeSet<Digest>,
    packs: BTreeSet<Digest>,
    pinned_files: BTreeSet<Digest>,
    pinned_symlinks: BTreeSet<Digest>,
    pinned_trees: BTreeSet<Digest>,
}

pub(crate) fn collect_retention_authority_roots(
    authority: &RetentionAuthorityV1,
    generations: &BTreeMap<Digest, StateGenerationV1>,
    retained: &mut RetainedClosure,
) -> Result<(), CommitError> {
    for point in authority.restore_points() {
        collect_restore_point_root(point, generations, &mut retained.generation_roots)?;
    }
    for pin in authority.explicit_pins() {
        match pin {
            RetentionObjectV1::PreparedPlan { plan_id } => {
                retained.plan_ids.insert(plan_id.clone());
            }
            RetentionObjectV1::StateGeneration { digest } => {
                retained.generation_roots.push((digest.clone(), 1));
            }
            RetentionObjectV1::ArtifactBlob { digest } => {
                retained.blobs.insert(digest.clone());
            }
            RetentionObjectV1::PackObject { digest } => {
                retained.packs.insert(digest.clone());
            }
            RetentionObjectV1::CanonicalFile { digest } => {
                retained.pinned_files.insert(digest.clone());
            }
            RetentionObjectV1::CanonicalSymlink { digest } => {
                retained.pinned_symlinks.insert(digest.clone());
            }
            RetentionObjectV1::CanonicalTree { digest } => {
                retained.pinned_trees.insert(digest.clone());
            }
        }
    }
    Ok(())
}

pub(crate) fn collect_restore_point_root(
    point: &RestorePointV1,
    generations: &BTreeMap<Digest, StateGenerationV1>,
    generation_roots: &mut Vec<(Digest, u32)>,
) -> Result<(), CommitError> {
    let generation = generations.get(point.generation()).ok_or_else(|| {
        CommitError::InvalidStore(format!(
            "restore point generation {} is missing",
            point.generation()
        ))
    })?;
    validate_restore_point_reference(point, point.generation(), generation)
        .map_err(CommitError::invalid_store)?;
    generation_roots.push((point.generation().clone(), 1));
    Ok(())
}

pub(crate) fn record_pack_roots(record: &PreparedRecordV1) -> BTreeSet<Digest> {
    let mut roots = record
        .inputs()
        .iter()
        .filter(|input| {
            input.kind() == PreparedInputKindV1::Source && input.name().starts_with("pack:")
        })
        .map(|input| input.digest().clone())
        .collect::<BTreeSet<_>>();
    roots.extend(record.transforms().iter().filter_map(
        |transform| match transform.implementation() {
            TransformImplementationV1::Component {
                pack_content_digest,
                ..
            } => Some(pack_content_digest.clone()),
            TransformImplementationV1::BuiltIn { .. } => None,
        },
    ));
    roots
}

/// Checks that a digest-named retained pack object is a bounded, owned regular
/// file. Content is verified by every pack load and by `fsck`; retention needs
/// only the published shape to decide whether the named object exists.
pub(crate) fn verify_pack_object(
    store: &StoreHandles,
    digest: &Digest,
) -> Result<usize, CommitError> {
    let mut found = None;
    for (directory, area) in [
        (store.pack_manifests.as_ref(), "objects/pack-manifests"),
        (store.packs.as_ref(), "objects/packs"),
    ] {
        let Some(directory) = directory else {
            continue;
        };
        match statat(directory, digest.as_str(), AtFlags::SYMLINK_NOFOLLOW) {
            Ok(stat) => {
                found = Some((stat, store.root_path.join(area).join(digest.as_str())));
                break;
            }
            Err(rustix::io::Errno::NOENT) => continue,
            Err(source) => {
                return Err(io_error(
                    "inspect retained pack object",
                    &store.root_path.join(area).join(digest.as_str()),
                    source,
                ));
            }
        }
    }
    let Some((stat, _path)) = found else {
        return Err(CommitError::InvalidStore(format!(
            "pack object {digest} is missing"
        )));
    };
    let size = u64::try_from(stat.st_size).unwrap_or(u64::MAX);
    if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
        || stat.st_uid != store.uid
        || size > pack_object::MAX_PACK_OBJECT_BYTES
    {
        return Err(CommitError::InvalidStore(format!(
            "pack object {digest} is invalid"
        )));
    }
    Ok(usize::try_from(size).unwrap_or(usize::MAX))
}

pub(crate) fn load_pack_names(store: &StoreHandles) -> Result<BTreeSet<Digest>, CommitError> {
    let mut result = BTreeSet::new();
    for (directory, area) in [
        (store.packs.as_ref(), "objects/packs"),
        (store.pack_manifests.as_ref(), "objects/pack-manifests"),
    ] {
        let Some(directory) = directory else {
            continue;
        };
        let path = store.root_path.join(area);
        for name in directory_names(directory, &path)? {
            let digest = Digest::new(name.clone()).map_err(|error| {
                CommitError::InvalidStore(format!("invalid pack object name {name:?}: {error}"))
            })?;
            verify_pack_object(store, &digest)?;
            result.insert(digest);
        }
    }
    Ok(result)
}

/// Returns the member blob digests and lengths from a retained deduplicated
/// pack. A legacy monolithic pack has no member blobs and returns an empty
/// list.
pub(crate) fn retained_pack_member_blobs(
    store: &StoreHandles,
    digest: &Digest,
    decoded_bytes: &mut u64,
) -> Result<Vec<(Digest, u64)>, CommitError> {
    let Some(directory) = &store.pack_manifests else {
        return Ok(Vec::new());
    };
    let path = store
        .root_path
        .join("objects/pack-manifests")
        .join(digest.as_str());
    let Some(bytes) = read_immutable(
        directory,
        digest.as_str(),
        &path,
        store.uid,
        128 * 1024 * 1024,
    )?
    else {
        return Ok(Vec::new());
    };
    charge_retention_bytes(decoded_bytes, bytes.len())?;
    let members = decode_pack_manifest_members(&bytes).map_err(|detail| {
        CommitError::InvalidStore(format!("pack manifest {digest} is invalid: {detail}"))
    })?;
    Ok(members)
}

/// Decodes only the blob digest and byte length from each pack member. It
/// follows the same frozen pack-manifest envelope as the producer and rejects
/// any structural error.
pub(crate) fn decode_pack_manifest_members(bytes: &[u8]) -> Result<Vec<(Digest, u64)>, String> {
    const MANIFEST_DOMAIN: &[u8] = b"malm-pack-manifest-object-v1\0";
    let rest = bytes
        .strip_prefix(MANIFEST_DOMAIN)
        .ok_or("wrong pack manifest domain")?;
    let (version, mut rest) = rest.split_at_checked(2).ok_or("truncated version")?;
    if u16::from_be_bytes(version.try_into().expect("split length")) != 1 {
        return Err("unsupported pack manifest version".to_owned());
    }
    let (count, tail) = rest.split_at_checked(8).ok_or("truncated count")?;
    rest = tail;
    let count = usize::try_from(u64::from_be_bytes(count.try_into().expect("split length")))
        .map_err(|_| "member count overflows")?;
    if count > 100_000 {
        return Err("member count exceeds the pack entry limit".to_owned());
    }
    let mut take = |length: usize| -> Result<&[u8], String> {
        let (value, tail) = rest.split_at_checked(length).ok_or("truncated member")?;
        rest = tail;
        Ok(value)
    };
    let mut members = Vec::with_capacity(count);
    for _ in 0..count {
        let path_len = usize::try_from(u64::from_be_bytes(
            take(8)?.try_into().expect("split length"),
        ))
        .map_err(|_| "path length overflows")?;
        if path_len > 1024 {
            return Err("member path exceeds the pack path limit".to_owned());
        }
        take(path_len)?;
        let digest_len = usize::try_from(u64::from_be_bytes(
            take(8)?.try_into().expect("split length"),
        ))
        .map_err(|_| "digest length overflows")?;
        if digest_len > 128 {
            return Err("member digest exceeds the identifier limit".to_owned());
        }
        let blob = std::str::from_utf8(take(digest_len)?)
            .map_err(|_| "member digest is not UTF-8")?
            .to_owned();
        let byte_len = u64::from_be_bytes(take(8)?.try_into().expect("split length"));
        members.push((
            Digest::new(blob).map_err(|error| format!("invalid member digest: {error}"))?,
            byte_len,
        ));
    }
    if !rest.is_empty() {
        return Err("trailing bytes after the final member".to_owned());
    }
    Ok(members)
}

pub(crate) fn order_generation_removals(
    generations: &BTreeMap<Digest, StateGenerationV1>,
    reachable: &BTreeSet<Digest>,
) -> Result<Vec<Digest>, CommitError> {
    let removed = generations
        .keys()
        .filter(|digest| !reachable.contains(*digest))
        .cloned()
        .collect::<BTreeSet<_>>();
    let mut remaining_children = removed
        .iter()
        .cloned()
        .map(|digest| (digest, 0_usize))
        .collect::<BTreeMap<_, _>>();
    for digest in &removed {
        if let Some(previous) = generations[digest].previous_generation()
            && let Some(children) = remaining_children.get_mut(previous)
        {
            *children = children.saturating_add(1);
        }
    }
    let mut leaves = remaining_children
        .iter()
        .filter_map(|(digest, children)| (*children == 0).then_some(digest.clone()))
        .collect::<BTreeSet<_>>();
    let mut ordered = Vec::with_capacity(removed.len());
    while let Some(digest) = leaves.pop_first() {
        ordered.push(digest.clone());
        if let Some(previous) = generations[&digest].previous_generation()
            && let Some(children) = remaining_children.get_mut(previous)
        {
            *children = children.checked_sub(1).ok_or_else(|| {
                CommitError::InvalidStore(
                    "unreachable generation dependency accounting underflowed".to_owned(),
                )
            })?;
            if *children == 0 {
                leaves.insert(previous.clone());
            }
        }
    }
    if ordered.len() != removed.len() {
        return Err(CommitError::InvalidStore(
            "unreachable state generations contain a dependency cycle".to_owned(),
        ));
    }
    Ok(ordered)
}

pub(crate) fn load_prepared_records(
    store: &StoreHandles,
    decoded_bytes: &mut u64,
) -> Result<BTreeMap<PreparedId, PreparedRecordV1>, CommitError> {
    let Some(directory) = &store.prepared else {
        return Ok(BTreeMap::new());
    };
    directory_names(directory, &store.root_path.join("prepared"))?
        .into_iter()
        .map(|name| {
            let plan_id = PreparedId::new(name.clone()).map_err(|error| {
                CommitError::InvalidStore(format!("invalid prepared record name {name:?}: {error}"))
            })?;
            let path = store.root_path.join("prepared").join(plan_id.as_str());
            let bytes = read_immutable(
                directory,
                plan_id.as_str(),
                &path,
                store.uid,
                malm_store::MAX_PREPARED_RECORD_BYTES as u64,
            )?
            .ok_or_else(|| CommitError::MissingPlan(plan_id.clone()))?;
            charge_retention_bytes(decoded_bytes, bytes.len())?;
            let record =
                decode_prepared_record_v1(&plan_id, &bytes).map_err(CommitError::invalid_plan)?;
            Ok((plan_id, record))
        })
        .collect()
}

pub(crate) fn load_blob_names(store: &StoreHandles) -> Result<BTreeSet<Digest>, CommitError> {
    let Some(directory) = &store.blobs else {
        return Ok(BTreeSet::new());
    };
    directory_names(directory, &store.root_path.join("objects/blobs"))?
        .into_iter()
        .map(|name| {
            Digest::new(name.clone()).map_err(|error| {
                CommitError::InvalidStore(format!("invalid artifact blob name {name:?}: {error}"))
            })
        })
        .collect()
}

#[derive(Clone, Copy)]
pub(crate) enum CanonicalRetentionKind {
    File,
    Symlink,
    Tree,
}

pub(crate) fn load_canonical_names(
    store: &StoreHandles,
    directory: Option<&File>,
    name: &str,
    kind: CanonicalRetentionKind,
    decoded_bytes: &mut u64,
) -> Result<BTreeSet<Digest>, CommitError> {
    let Some(directory) = directory else {
        return Ok(BTreeSet::new());
    };
    let path = store.root_path.join("objects").join(name);
    directory_names(directory, &path)?
        .into_iter()
        .map(|entry| {
            let digest = Digest::new(entry.clone()).map_err(|error| {
                CommitError::InvalidStore(format!(
                    "invalid canonical {name} object name {entry:?}: {error}"
                ))
            })?;
            let maximum = match kind {
                CanonicalRetentionKind::File => canonical::MAX_FILE_OBJECT_BYTES,
                CanonicalRetentionKind::Symlink => canonical::MAX_SYMLINK_OBJECT_BYTES,
                CanonicalRetentionKind::Tree => canonical::MAX_TREE_OBJECT_BYTES,
            };
            match kind {
                // Decode trees because their entries define reachability.
                // File and symlink leaves need only have a valid stored shape;
                // consumers verify their digests on read, and `fsck` audits
                // all stored content.
                CanonicalRetentionKind::Tree => {
                    let bytes = read_immutable(
                        directory,
                        digest.as_str(),
                        &path.join(digest.as_str()),
                        store.uid,
                        maximum,
                    )?
                    .ok_or_else(|| {
                        CommitError::InvalidStore(format!(
                            "canonical {name} object {digest} vanished during retention"
                        ))
                    })?;
                    charge_retention_bytes(decoded_bytes, bytes.len())?;
                    canonical::decode_tree(&digest, &bytes)
                        .map(drop)
                        .map_err(|error| invalid_canonical_object(name, &digest, error))?;
                }
                CanonicalRetentionKind::File | CanonicalRetentionKind::Symlink => {
                    let entry_path = path.join(digest.as_str());
                    let stat = statat(directory, digest.as_str(), AtFlags::SYMLINK_NOFOLLOW)
                        .map_err(|_| {
                            CommitError::InvalidStore(format!(
                                "canonical {name} object {digest} vanished during retention"
                            ))
                        })?;
                    let size = u64::try_from(stat.st_size).unwrap_or(u64::MAX);
                    if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
                        || stat.st_uid != store.uid
                        || size > maximum
                    {
                        return Err(CommitError::InvalidStore(format!(
                            "canonical {name} object {} differs from its published shape",
                            entry_path.display()
                        )));
                    }
                }
            }
            Ok(digest)
        })
        .collect()
}

/// Checks that a digest-named retained artifact blob is a bounded, owned regular
/// file and returns its length.
///
/// Retention depends on membership in digest sets, not on payload contents. A
/// corrupt retained blob cannot make an unreferenced blob reachable, so hashing
/// here would not change the collection decision. Consumers verify digests on
/// read, and `fsck` performs the full content audit.
pub(crate) fn verify_blob(store: &StoreHandles, digest: &Digest) -> Result<u64, CommitError> {
    let directory = store
        .blobs
        .as_ref()
        .ok_or_else(|| CommitError::MissingArtifact(digest.clone()))?;
    let stat = match statat(directory, digest.as_str(), AtFlags::SYMLINK_NOFOLLOW) {
        Ok(stat) => stat,
        Err(rustix::io::Errno::NOENT) => {
            return Err(CommitError::MissingArtifact(digest.clone()));
        }
        Err(source) => {
            return Err(io_error(
                "inspect retained artifact blob",
                &store.root_path.join("objects/blobs").join(digest.as_str()),
                source,
            ));
        }
    };
    let size = u64::try_from(stat.st_size).unwrap_or(u64::MAX);
    if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
        || stat.st_uid != store.uid
        || size > malm_store::MAX_ARTIFACT_BLOB_BYTES
    {
        return Err(CommitError::InvalidStore(format!(
            "retained artifact blob {digest} differs from its published shape"
        )));
    }
    Ok(size)
}

pub(crate) struct GenerationDirectory<'a> {
    state: &'a File,
    generations: &'a File,
    state_path: PathBuf,
    path: PathBuf,
}

impl<'a> GenerationDirectory<'a> {
    pub(crate) fn open(store: &'a StoreHandles) -> Result<Option<Self>, CommitError> {
        let state_path = store.root_path.join("state");
        let Some(state) = &store.state else {
            return Ok(None);
        };
        let path = state_path.join("generations");
        let Some(generations) = &store.generations else {
            return Ok(None);
        };
        Ok(Some(Self {
            state,
            generations,
            state_path,
            path,
        }))
    }

    pub(crate) fn load_all(
        &self,
        store: &StoreHandles,
        decoded_bytes: &mut u64,
    ) -> Result<BTreeMap<Digest, StateGenerationV1>, CommitError> {
        directory_names(self.generations, &self.path)?
            .into_iter()
            .map(|name| {
                let digest = Digest::new(name.clone()).map_err(|error| {
                    CommitError::InvalidStore(format!(
                        "invalid state generation name {name:?}: {error}"
                    ))
                })?;
                let bytes = read_immutable(
                    self.generations,
                    digest.as_str(),
                    &self.path.join(digest.as_str()),
                    store.uid,
                    malm_store::MAX_STATE_RECORD_BYTES as u64,
                )?
                .ok_or_else(|| CommitError::InvalidStore("state generation vanished".to_owned()))?;
                charge_retention_bytes(decoded_bytes, bytes.len())?;
                let generation = malm_store::decode_state_generation_v1(&digest, &bytes)
                    .map_err(CommitError::invalid_store)?;
                Ok((digest, generation))
            })
            .collect()
    }

    pub(crate) fn revalidate(&self, store: &StoreHandles) -> Result<(), CommitError> {
        ensure_bound(
            &store.root,
            "state",
            self.state,
            &self.state_path,
            store.uid,
        )?;
        ensure_bound(
            self.state,
            "generations",
            self.generations,
            &self.path,
            store.uid,
        )
    }
}

pub(crate) fn charge_retention_bytes(total: &mut u64, bytes: usize) -> Result<(), CommitError> {
    *total = total
        .checked_add(u64::try_from(bytes).unwrap_or(u64::MAX))
        .ok_or_else(|| CommitError::InvalidStore("retention byte budget overflows".to_owned()))?;
    if *total > MAX_RETENTION_DECODED_BYTES {
        return Err(CommitError::InvalidStore(format!(
            "retention decoded records exceed {MAX_RETENTION_DECODED_BYTES} bytes"
        )));
    }
    Ok(())
}

pub(crate) fn directory_names(directory: &File, path: &Path) -> Result<Vec<String>, CommitError> {
    let mut entries = Dir::read_from(directory)
        .map_err(|source| io_error("enumerate store directory", path, source))?;
    let mut names = Vec::new();
    while let Some(entry) = entries.read() {
        let entry = entry.map_err(|source| io_error("enumerate store directory", path, source))?;
        let bytes = entry.file_name().to_bytes();
        if matches!(bytes, b"." | b"..") {
            continue;
        }
        if names.len() == MAX_RETENTION_ENTRIES {
            return Err(CommitError::InvalidStore(format!(
                "{} contains more than {MAX_RETENTION_ENTRIES} entries",
                path.display()
            )));
        }
        let name = std::str::from_utf8(bytes).map_err(|_| {
            CommitError::InvalidStore(format!("{} contains a non-UTF-8 entry", path.display()))
        })?;
        names.push(name.to_owned());
    }
    names.sort();
    Ok(names)
}

#[derive(Clone, Copy)]
pub(crate) enum RemovalSync {
    Batch,
    Each {
        after_remove_failpoint: Option<&'static str>,
    },
}

pub(crate) fn remove_names<'a>(
    directory: &File,
    names: impl IntoIterator<Item = &'a str>,
    path: &Path,
    operation: &'static str,
    uid: u32,
    maximum: u64,
    sync: RemovalSync,
) -> Result<(), CommitError> {
    let mut removed = false;
    for name in names {
        let entry_path = path.join(name);
        let bytes = read_immutable(directory, name, &entry_path, uid, maximum)?
            .ok_or_else(|| CommitError::InvalidStore("retention entry vanished".to_owned()))?;
        // Hash content-addressed entries before unlinking them. A pack manifest
        // is named by the logical pack digest, which is proved only after pack
        // reassembly, so require a valid manifest structure here. This keeps an
        // aliased foreign file from being deleted through a store path.
        let identity_holds = if operation == "remove unreachable pack object"
            && bytes.starts_with(b"malm-pack-manifest-object-v1\0")
        {
            decode_pack_manifest_members(&bytes).is_ok()
        } else {
            let expected = if let Some(digest) = name.strip_prefix("pp-") {
                format!("sha256-{digest}")
            } else {
                name.to_owned()
            };
            Digest::sha256(&bytes).as_str() == expected
        };
        if !identity_holds {
            return Err(CommitError::InvalidStore(format!(
                "retention entry identity changed at {}",
                entry_path.display()
            )));
        }
        unlinkat(directory, name, AtFlags::empty())
            .map_err(|source| io_error(operation, &entry_path, source))?;
        removed = true;
        if matches!(sync, RemovalSync::Each { .. }) {
            fsync(directory)
                .map_err(|source| io_error("sync pruned store directory", path, source))?;
        }
        if let RemovalSync::Each {
            after_remove_failpoint: Some(failpoint),
        } = sync
        {
            commit_failpoint!(failpoint);
        }
    }
    if removed && matches!(sync, RemovalSync::Batch) {
        fsync(directory).map_err(|source| io_error("sync pruned store directory", path, source))?;
    }
    Ok(())
}
