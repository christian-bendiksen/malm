use super::{
    AtFlags, BTreeMap, BTreeSet, CommitConfig, CommitError, Committer, DIRECTORY_FLAGS, Digest,
    Dir, File, FileType, LineageDepth, Mode, NamespaceName, OFlags, OsString, PinnedChain,
    PreparedId, ROOT_RESOLVE_FLAGS, StateCatalogV1, StateGenerationV1, StateTargetStateV1,
    StoreHandles, decode_state_catalog_v1, fstat, io_error, load_canonical_state_objects,
    load_catalog_ownership, load_generation, load_generation_with_encoded_len, load_journal,
    load_prepared_with_encoded_len, openat2, prove_safe_existing_directory_leaf, read_catalog,
    read_immutable, read_mutable, record_pack_roots, reject_projection_authority_aliases,
    reject_protected_traversal_directory, require_pinned_entry, require_target_state,
    same_snapshot, source_digest_matches, stable_file_digest, statat, state_catalog_digest_v1,
    state_generation_validation_error, validate_catalog_lineages,
    validate_directly_retained_generation, validate_generation_transition, validate_journal,
    validate_journal_catalog_transition, validate_restore_point_reference,
    validate_target_directory,
};
use malm_store::{
    LifecycleStateV1, OwnershipProjectionV1, PreparedTransitionV1, RestorePointV1, StateTargetV1,
    TrackedRootV1,
};
use malm_types::{
    ArchiveProvenanceV1, CanonicalTreeEntryInspectionV1, CanonicalTreeEntryKindInspectionV1,
    CanonicalTreeInspectionRequestV1, CanonicalTreeInspectionV1, CatalogInspectionRequestV1,
    CatalogInspectionV1, CatalogNamespaceInspectionV1, DesiredSnapshotInspectionRequestV1,
    DesiredSnapshotInspectionV1, DesiredTargetInspectionV1, DesiredTargetStateInspectionV1,
    FsckFindingCodeV1, FsckFindingV1, FsckReportPartsV1, FsckReportV1, FsckRequestV1,
    FsckSeverityV1, FsckStoreAreaV1, FsckSubjectV1, GenerationInspectionPartsV1,
    GenerationInspectionRequestV1, GenerationInspectionV1, GenerationInventoryRequestV1,
    GenerationInventoryV1, LifecycleStateViewV1, LifecycleTransitionViewV1,
    NamespaceHistoryRequestV1, NamespaceHistoryV1, NamespaceInspectionRequestV1,
    NamespaceInspectionV1, NamespaceStatusKindV1, NamespaceStatusPartsV1, NamespaceStatusRequestV1,
    NamespaceStatusV1, ObjectInventoryKindV1, ObjectInventoryRequestV1, ObjectInventoryV1,
    RestorePointInspectionV1, RetentionAuthorityInspectionV1, RetentionInspectionV1,
    RetentionObjectV1, TargetStatusKindV1, TargetStatusV1, TrackedRootInspectionV1,
    TrackingInspectionV1,
};

use std::os::unix::ffi::{OsStrExt, OsStringExt};

impl Committer {
    /// Returns the complete canonical catalog after enforcing the request's
    /// namespace and decoded-byte limits.
    pub fn inspect_catalog_v1(
        &self,
        request: &CatalogInspectionRequestV1,
    ) -> Result<CatalogInspectionV1, CommitError> {
        let store = StoreHandles::open(&self.config)?;
        let (catalog, bytes) = load_catalog_record_with_bytes(&store)?;
        if catalog.heads().len() > request.max_namespaces()
            || u64::try_from(bytes.len()).unwrap_or(u64::MAX) > request.max_decoded_bytes()
        {
            return Err(CommitError::InvalidStore(
                "catalog inspection exceeds its requested limits".to_owned(),
            ));
        }
        let result = CatalogInspectionV1::new(
            state_catalog_digest_v1(&catalog),
            catalog
                .heads()
                .iter()
                .map(|head| {
                    CatalogNamespaceInspectionV1::new(
                        head.namespace().clone(),
                        head.generation().clone(),
                    )
                })
                .collect(),
            malm_types::usize_to_u64(bytes.len()),
        );
        require_catalog_bytes(&store, &bytes)?;
        store.revalidate()?;
        Ok(result)
    }

    /// Returns a namespace and its verified selected generation, if it exists.
    pub fn inspect_namespace_v1(
        &self,
        request: &NamespaceInspectionRequestV1,
    ) -> Result<NamespaceInspectionV1, CommitError> {
        let store = StoreHandles::open(&self.config)?;
        let (catalog, catalog_bytes) = load_catalog_record_with_bytes(&store)?;
        let head = catalog.generation(request.namespace()).cloned();
        let (generation, generation_bytes) = match &head {
            Some(head) => {
                let selected = load_generation(&store, head)?;
                if selected.namespace() != request.namespace() {
                    return Err(CommitError::InvalidStore(
                        "catalog head belongs to another namespace".to_owned(),
                    ));
                }
                let retained =
                    usize::try_from(selected.retention_authority().history().generations())
                        .expect("u32 fits in usize");
                let (lineage, bytes) = inspect_lineage(
                    &store,
                    request.namespace(),
                    head,
                    retained,
                    request.max_decoded_bytes(),
                )?;
                (lineage.into_iter().next(), bytes)
            }
            None => (None, 0),
        };
        require_catalog_bytes(&store, &catalog_bytes)?;
        store.revalidate()?;
        Ok(NamespaceInspectionV1::new(
            request.namespace().clone(),
            head,
            generation,
            generation_bytes,
        ))
    }

    /// Returns the exact cumulative desired snapshot recorded by a verified
    /// generation.
    pub fn inspect_desired_snapshot_v1(
        &self,
        request: &DesiredSnapshotInspectionRequestV1,
    ) -> Result<DesiredSnapshotInspectionV1, CommitError> {
        let store = StoreHandles::open(&self.config)?;
        let before = directory_snapshot(&store)?;
        let (generation, encoded_bytes) =
            load_generation_with_encoded_len(&store, request.generation())?;
        if generation.namespace() != request.namespace() {
            return Err(CommitError::InvalidStore(
                "desired snapshot generation belongs to another namespace".to_owned(),
            ));
        }
        if generation.targets().len() > request.max_targets()
            || u64::try_from(encoded_bytes).unwrap_or(u64::MAX) > request.max_decoded_bytes()
        {
            return Err(CommitError::InvalidStore(
                "desired snapshot inspection exceeds its requested limits".to_owned(),
            ));
        }
        validate_generation_transition(&store, &generation)?;
        let targets = generation
            .targets()
            .iter()
            .map(desired_target_view)
            .collect::<Result<Vec<_>, _>>()?;
        let result = DesiredSnapshotInspectionV1::new(
            request.namespace().clone(),
            request.generation().clone(),
            generation.desired_snapshot_digest().clone(),
            targets,
            malm_types::usize_to_u64(encoded_bytes),
        );
        require_directory_snapshot(&store, &before)?;
        store.revalidate()?;
        Ok(result)
    }

    /// Returns a complete canonical tree after recursively verifying every
    /// referenced object within the requested limits.
    pub fn inspect_canonical_tree_v1(
        &self,
        request: &CanonicalTreeInspectionRequestV1,
    ) -> Result<CanonicalTreeInspectionV1, CommitError> {
        let store = StoreHandles::open(&self.config)?;
        let before = directory_snapshot(&store)?;
        let mut budget = DecodeBudget {
            decoded_bytes: 0,
            requested_maximum: request.max_decoded_bytes(),
        };
        let mut entries = Vec::new();
        let mut objects = super::canonical::CanonicalObjects::empty();
        let mut stack = vec![(request.tree().clone(), String::new(), 0_usize)];
        let mut root_mode = None;
        let mut logical_file_bytes = 0_u64;
        while let Some((digest, prefix, depth)) = stack.pop() {
            if !objects.trees.contains_key(&digest) {
                let bytes = read_bounded_canonical(
                    &store,
                    store.trees.as_ref(),
                    "trees",
                    &digest,
                    super::canonical::MAX_TREE_OBJECT_BYTES,
                    &mut budget,
                )?;
                let tree = super::canonical::decode_tree(&digest, &bytes)
                    .map_err(|error| super::invalid_canonical_object("tree", &digest, error))?;
                objects.trees.insert(digest.clone(), tree);
            }
            let tree = objects
                .trees
                .get(&digest)
                .expect("the canonical tree was loaded above");
            if prefix.is_empty() {
                root_mode = Some(tree.root_mode);
            }
            for entry in tree.entries.iter().rev() {
                let entry_depth = depth.saturating_add(1);
                if entry_depth > super::canonical::MAX_DEPTH {
                    return Err(CommitError::InvalidStore(
                        "canonical tree inspection exceeds the graph depth limit".to_owned(),
                    ));
                }
                let path_bytes = prefix
                    .len()
                    .checked_add(usize::from(!prefix.is_empty()))
                    .and_then(|bytes| bytes.checked_add(entry.name.len()))
                    .unwrap_or(usize::MAX);
                if path_bytes > super::canonical::MAX_PATH_BYTES {
                    return Err(CommitError::InvalidStore(
                        "canonical tree inspection exceeds the graph path-byte limit".to_owned(),
                    ));
                }
                if entries.len() == request.max_entries() {
                    return Err(CommitError::InvalidStore(
                        "canonical tree inspection exceeds its requested item limit".to_owned(),
                    ));
                }
                if entries.len() == super::canonical::MAX_ENTRIES {
                    return Err(CommitError::InvalidStore(
                        "canonical tree inspection exceeds the graph entry limit".to_owned(),
                    ));
                }
                let path = if prefix.is_empty() {
                    entry.name.clone()
                } else {
                    format!("{prefix}/{}", entry.name)
                };
                let kind = match &entry.kind {
                    super::canonical::TreeEntryKind::File { digest, byte_len } => {
                        logical_file_bytes =
                            logical_file_bytes.checked_add(*byte_len).ok_or_else(|| {
                                CommitError::InvalidStore(
                                    "canonical tree inspection file-byte total overflowed"
                                        .to_owned(),
                                )
                            })?;
                        if logical_file_bytes > super::canonical::MAX_FILE_BYTES {
                            return Err(CommitError::InvalidStore(
                                "canonical tree inspection exceeds the graph file-byte limit"
                                    .to_owned(),
                            ));
                        }
                        if !objects.files.contains_key(digest) {
                            let bytes = read_bounded_canonical(
                                &store,
                                store.files.as_ref(),
                                "files",
                                digest,
                                super::canonical::MAX_FILE_OBJECT_BYTES,
                                &mut budget,
                            )?;
                            let contents =
                                super::canonical::decode_file(digest, &bytes).map_err(|error| {
                                    super::invalid_canonical_object("file", digest, error)
                                })?;
                            if u64::try_from(contents.len()).unwrap_or(u64::MAX) != *byte_len {
                                return Err(CommitError::InvalidStore(
                                    "canonical tree file length is inconsistent".to_owned(),
                                ));
                            }
                            objects.files.insert(digest.clone(), contents);
                        }
                        CanonicalTreeEntryKindInspectionV1::File {
                            digest: digest.clone(),
                            byte_len: *byte_len,
                        }
                    }
                    super::canonical::TreeEntryKind::Directory { digest } => {
                        stack.push((digest.clone(), path.clone(), entry_depth));
                        CanonicalTreeEntryKindInspectionV1::Directory {
                            digest: digest.clone(),
                        }
                    }
                    super::canonical::TreeEntryKind::Symlink { digest } => {
                        if !objects.symlinks.contains_key(digest) {
                            let bytes = read_bounded_canonical(
                                &store,
                                store.symlinks.as_ref(),
                                "symlinks",
                                digest,
                                super::canonical::MAX_SYMLINK_OBJECT_BYTES,
                                &mut budget,
                            )?;
                            let target = super::canonical::decode_symlink(digest, &bytes).map_err(
                                |error| super::invalid_canonical_object("symlink", digest, error),
                            )?;
                            objects.symlinks.insert(digest.clone(), target);
                        }
                        CanonicalTreeEntryKindInspectionV1::Symlink {
                            digest: digest.clone(),
                        }
                    }
                };
                entries.push(CanonicalTreeEntryInspectionV1::new(path, entry.mode, kind));
            }
        }
        objects.validate_tree(request.tree()).map_err(|error| {
            super::invalid_canonical_object("tree graph", request.tree(), error)
        })?;
        entries.sort_by(|left, right| left.relative_path().cmp(right.relative_path()));
        require_directory_snapshot(&store, &before)?;
        store.revalidate()?;
        Ok(CanonicalTreeInspectionV1::new(
            request.tree().clone(),
            root_mode.ok_or_else(|| {
                CommitError::InvalidStore("canonical tree root is missing".to_owned())
            })?,
            entries,
            budget.decoded_bytes,
        ))
    }

    /// Returns the exact retention authority recorded by a verified generation.
    pub fn inspect_retention_authority_v1(
        &self,
        request: &GenerationInspectionRequestV1,
    ) -> Result<RetentionInspectionV1, CommitError> {
        let generation = self.inspect_generation_details_v1(request)?;
        Ok(RetentionInspectionV1::new(
            generation.namespace().clone(),
            generation.generation().clone(),
            generation.retention_authority().clone(),
        ))
    }

    /// Returns the redacted tracked-root authority from a verified generation.
    pub fn inspect_tracking_v1(
        &self,
        request: &GenerationInspectionRequestV1,
    ) -> Result<TrackingInspectionV1, CommitError> {
        let generation = self.inspect_generation_details_v1(request)?;
        Ok(TrackingInspectionV1::new(
            generation.namespace().clone(),
            generation.generation().clone(),
            generation.tracked_root().cloned(),
        ))
    }

    /// Loads the selected head and a checkout source while proving that the
    /// current retention authority still authorizes both generations.
    pub fn inspect_checkout_generations_v1(
        &self,
        namespace: &NamespaceName,
        target: &Digest,
    ) -> Result<(Digest, StateGenerationV1, StateGenerationV1), CommitError> {
        let store = StoreHandles::open(&self.config)?;
        let before = directory_snapshot(&store)?;
        let (catalog, catalog_bytes) = load_catalog_record_with_bytes(&store)?;
        validate_catalog_lineages(&store, &catalog, None, LineageDepth::Routine)?;
        let current_digest = catalog.generation(namespace).cloned().ok_or_else(|| {
            CommitError::InvalidStore(format!(
                "checkout requires a head for namespace {namespace}"
            ))
        })?;
        let current = load_generation(&store, &current_digest)?;
        if current.namespace() != namespace {
            return Err(CommitError::InvalidStore(
                "checkout head belongs to another namespace".to_owned(),
            ));
        }
        let authorized = load_effectively_retained_generation(
            &store,
            namespace,
            &current_digest,
            &current,
            target,
        )?;
        inspect_lineage(
            &store,
            namespace,
            target,
            authorized.validation_depth,
            malm_types::usize_to_u64(super::MAX_LINEAGE_VALIDATION_BYTES),
        )?;
        require_catalog_bytes(&store, &catalog_bytes)?;
        require_directory_snapshot(&store, &before)?;
        store.revalidate()?;
        Ok((current_digest, current, authorized.generation))
    }

    /// Returns the complete selected predecessor chain in newest-first order
    /// after verifying each returned generation.
    pub fn inspect_namespace_history_v1(
        &self,
        request: &NamespaceHistoryRequestV1,
    ) -> Result<NamespaceHistoryV1, CommitError> {
        let store = StoreHandles::open(&self.config)?;
        let catalog = load_catalog_record(&store)?;
        let head = catalog.generation(request.namespace()).cloned();
        let (generations, decoded_bytes) = match &head {
            Some(head) => {
                let selected = load_generation(&store, head)?;
                let retained =
                    usize::try_from(selected.retention_authority().history().generations())
                        .expect("u32 fits in usize");
                inspect_lineage(
                    &store,
                    request.namespace(),
                    head,
                    request.max_generations().min(retained),
                    request.max_decoded_bytes(),
                )?
            }
            None => (Vec::new(), 0),
        };
        store.revalidate()?;
        Ok(NamespaceHistoryV1::new(
            request.namespace().clone(),
            head,
            generations,
            decoded_bytes,
        ))
    }

    /// Returns only generations authorized by the selected namespace's current
    /// history, restore points, or explicit generation pins.
    pub fn inspect_generation_inventory_v1(
        &self,
        request: &GenerationInventoryRequestV1,
    ) -> Result<GenerationInventoryV1, CommitError> {
        let store = StoreHandles::open(&self.config)?;
        let before = directory_snapshot(&store)?;
        let (catalog, catalog_bytes) = load_catalog_record_with_bytes(&store)?;
        let head = catalog
            .generation(request.namespace())
            .cloned()
            .ok_or_else(|| {
                CommitError::InvalidStore(format!(
                    "generation inventory requires a head for namespace {}",
                    request.namespace()
                ))
            })?;
        let current = load_generation(&store, &head)?;
        if current.namespace() != request.namespace() {
            return Err(CommitError::InvalidStore(
                "selected generation belongs to another namespace".to_owned(),
            ));
        }

        let history_depth = usize::try_from(current.retention_authority().history().generations())
            .expect("u32 fits in usize");
        let (history, history_bytes) = inspect_lineage(
            &store,
            request.namespace(),
            &head,
            history_depth,
            request.max_decoded_bytes(),
        )?;
        let mut generations = history
            .into_iter()
            .map(|generation| generation.generation().clone())
            .collect::<BTreeSet<_>>();
        let mut direct = current
            .retention_authority()
            .restore_points()
            .iter()
            .map(|point| point.generation().clone())
            .collect::<BTreeSet<_>>();
        direct.extend(
            current
                .retention_authority()
                .explicit_pins()
                .iter()
                .filter_map(|pin| match pin {
                    RetentionObjectV1::StateGeneration { digest } => Some(digest.clone()),
                    _ => None,
                }),
        );
        direct.retain(|digest| !generations.contains(digest));
        if generations.len().saturating_add(direct.len()) > request.max_generations() {
            return Err(CommitError::InvalidStore(
                "generation inventory exceeds its requested item limit".to_owned(),
            ));
        }

        let mut direct_bytes = 0_usize;
        for digest in direct {
            let generation =
                validate_directly_retained_generation(&store, &digest, &mut direct_bytes)?;
            if generation.namespace() != request.namespace() {
                return Err(CommitError::InvalidStore(
                    "retained generation belongs to another namespace".to_owned(),
                ));
            }
            if let Some(point) = current
                .retention_authority()
                .restore_points()
                .iter()
                .find(|point| point.generation() == &digest)
            {
                validate_restore_point_reference(point, &digest, &generation)
                    .map_err(CommitError::invalid_store)?;
            }
            generations.insert(digest);
        }
        let decoded_bytes = history_bytes
            .checked_add(u64::try_from(direct_bytes).unwrap_or(u64::MAX))
            .ok_or_else(|| {
                CommitError::InvalidStore(
                    "generation inventory byte accounting overflowed".to_owned(),
                )
            })?;
        if decoded_bytes > request.max_decoded_bytes() {
            return Err(CommitError::InvalidStore(
                "generation inventory exceeds its requested decoded-byte limit".to_owned(),
            ));
        }
        require_catalog_bytes(&store, &catalog_bytes)?;
        require_directory_snapshot(&store, &before)?;
        store.revalidate()?;
        Ok(GenerationInventoryV1::new(
            request.namespace().clone(),
            generations.into_iter().collect(),
            decoded_bytes,
        ))
    }

    /// Returns canonical digest names from the requested immutable-object
    /// domain, up to the request's object limit, without exposing store paths.
    pub fn inspect_object_inventory_v1(
        &self,
        request: &ObjectInventoryRequestV1,
    ) -> Result<ObjectInventoryV1, CommitError> {
        let store = StoreHandles::open(&self.config)?;
        let before = directory_snapshot(&store)?;
        let mut objects = BTreeSet::new();
        let mut enumerated = 0_usize;
        match request.kind() {
            ObjectInventoryKindV1::ArtifactBlob => inventory_object_directory(
                store.blobs.as_ref(),
                &store.root_path.join("objects/blobs"),
                request.max_objects(),
                &mut enumerated,
                &mut objects,
            )?,
            ObjectInventoryKindV1::PackObject => {
                inventory_object_directory(
                    store.packs.as_ref(),
                    &store.root_path.join("objects/packs"),
                    request.max_objects(),
                    &mut enumerated,
                    &mut objects,
                )?;
                inventory_object_directory(
                    store.pack_manifests.as_ref(),
                    &store.root_path.join("objects/pack-manifests"),
                    request.max_objects(),
                    &mut enumerated,
                    &mut objects,
                )?;
            }
            ObjectInventoryKindV1::CanonicalFile => inventory_object_directory(
                store.files.as_ref(),
                &store.root_path.join("objects/files"),
                request.max_objects(),
                &mut enumerated,
                &mut objects,
            )?,
            ObjectInventoryKindV1::CanonicalSymlink => inventory_object_directory(
                store.symlinks.as_ref(),
                &store.root_path.join("objects/symlinks"),
                request.max_objects(),
                &mut enumerated,
                &mut objects,
            )?,
            ObjectInventoryKindV1::CanonicalTree => inventory_object_directory(
                store.trees.as_ref(),
                &store.root_path.join("objects/trees"),
                request.max_objects(),
                &mut enumerated,
                &mut objects,
            )?,
        }
        require_directory_snapshot(&store, &before)?;
        store.revalidate()?;
        Ok(ObjectInventoryV1::new(
            request.kind(),
            objects.into_iter().collect(),
        ))
    }

    /// Returns one generation after proving that the current namespace head
    /// retains it and that its requested lineage is valid.
    pub fn inspect_generation_details_v1(
        &self,
        request: &GenerationInspectionRequestV1,
    ) -> Result<GenerationInspectionV1, CommitError> {
        let store = StoreHandles::open(&self.config)?;
        let before = directory_snapshot(&store)?;
        let (catalog, catalog_bytes) = load_catalog_record_with_bytes(&store)?;
        validate_catalog_lineages(&store, &catalog, None, LineageDepth::Routine)?;
        let current_digest = catalog
            .generation(request.namespace())
            .cloned()
            .ok_or_else(|| {
                CommitError::InvalidStore(format!(
                    "generation inspection requires a head for namespace {}",
                    request.namespace()
                ))
            })?;
        let current = load_generation(&store, &current_digest)?;
        let authorized = load_effectively_retained_generation(
            &store,
            request.namespace(),
            &current_digest,
            &current,
            request.generation(),
        )?;
        let (lineage, _) = inspect_lineage(
            &store,
            request.namespace(),
            request.generation(),
            request.max_generations().min(authorized.validation_depth),
            request.max_decoded_bytes(),
        )?;
        require_catalog_bytes(&store, &catalog_bytes)?;
        require_directory_snapshot(&store, &before)?;
        store.revalidate()?;
        lineage.into_iter().next().ok_or_else(|| {
            CommitError::InvalidStore("authorized generation inspection is empty".to_owned())
        })
    }

    /// Checks selected and reachable store authority without repairing data or
    /// creating lock files.
    pub fn fsck_v1(&self, request: &FsckRequestV1) -> Result<FsckReportV1, CommitError> {
        let mut scan = FsckScan::new(*request);
        let store = match StoreHandles::open(&self.config) {
            Ok(store) => store,
            Err(CommitError::Io {
                operation,
                path,
                source,
            }) if source.kind() != std::io::ErrorKind::NotFound => {
                return Err(CommitError::Io {
                    operation,
                    path,
                    source,
                });
            }
            Err(_) => {
                scan.error(
                    FsckFindingCodeV1::InvalidDescriptor,
                    FsckSubjectV1::StoreDescriptor,
                    "the final root descriptor or trusted root metadata is invalid",
                );
                scan.coverage_gap();
                return Ok(scan.finish());
            }
        };
        let before = directory_snapshot(&store)?;
        scan.inspect_store_shape(&store)?;
        scan.inspect_lock(&store, "transaction.lock", FsckSubjectV1::TransactionLock)?;
        scan.inspect_lock(&store, "maintenance.lock", FsckSubjectV1::MaintenanceLock)?;

        let loaded_journal = scan.load_journal(&store)?;
        let journal_before = journal_fingerprint(loaded_journal.as_ref());
        let (catalog, catalog_bytes) = scan.load_catalog(&store)?;
        let prepared = scan.load_prepared_records(&store)?;
        let generations = scan.load_generations(&store)?;
        let blobs = scan.load_blobs(&store)?;
        let packs = scan.load_packs(&store)?;
        let canonical = scan.load_canonical_objects(&store)?;

        if scan.authority_inventory_complete() {
            scan.validate_authority(
                &self.config,
                &store,
                FsckWorld {
                    catalog: catalog.as_ref(),
                    journal: loaded_journal.as_ref(),
                    prepared: &prepared,
                    generations: &generations,
                    blobs: &blobs,
                    packs: &packs,
                    canonical: &canonical,
                },
            )?;
        }

        commit_failpoint!("v1.fsck.before_authority_revalidation");
        if require_directory_snapshot(&store, &before).is_err()
            || catalog_bytes.as_ref().is_some_and(|bytes| {
                load_catalog_record_with_bytes(&store)
                    .map(|(_, current)| current != *bytes)
                    .unwrap_or(true)
            })
            || (scan.journal_inventory_complete
                && match load_journal(&store) {
                    Ok(current) => journal_fingerprint(current.as_ref()) != journal_before,
                    Err(_) => true,
                })
        {
            scan.error(
                FsckFindingCodeV1::AuthorityChanged,
                FsckSubjectV1::Coverage,
                "store authority changed during the read-only fsck snapshot",
            );
            scan.coverage_gap();
        }
        store.revalidate()?;
        Ok(scan.finish())
    }

    /// Compares selected desired state with bounded target observations without
    /// following symlinks.
    pub fn inspect_namespace_status_v1(
        &self,
        request: &NamespaceStatusRequestV1,
    ) -> Result<NamespaceStatusV1, CommitError> {
        let store = match StoreHandles::open(&self.config) {
            Ok(store) => store,
            Err(error @ CommitError::Io { .. }) => return Err(error),
            Err(_) => return Ok(incompatible_status(request, None, None, None)),
        };
        let before = directory_snapshot(&store)?;
        let loaded_journal = match load_journal(&store) {
            Ok(journal) => journal,
            Err(error @ CommitError::Io { .. }) => return Err(error),
            Err(_) => return Ok(incompatible_status(request, None, None, None)),
        };
        let journal_before = journal_fingerprint(loaded_journal.as_ref());
        if loaded_journal.is_some() {
            return finish_status_snapshot(
                &store,
                &before,
                None,
                journal_before,
                NamespaceStatusV1::from(NamespaceStatusPartsV1 {
                    namespace: request.namespace().clone(),
                    head: None,
                    lifecycle: None,
                    desired_snapshot_digest: None,
                    status: NamespaceStatusKindV1::RecoveryRequired,
                    targets: Vec::new(),
                    observed_bytes: 0,
                    detail: Some("an incomplete global transaction requires recovery".to_owned()),
                }),
            );
        }
        let catalog = match read_catalog(&store) {
            Ok(catalog) => catalog,
            Err(error @ CommitError::Io { .. }) => return Err(error),
            Err(_) => return Ok(incompatible_status(request, None, None, None)),
        };
        let catalog_bytes = malm_store::encode_state_catalog_v1(&catalog);
        let Some(head) = catalog.generation(request.namespace()).cloned() else {
            return finish_status_snapshot(
                &store,
                &before,
                Some(&catalog_bytes),
                journal_before,
                NamespaceStatusV1::from(NamespaceStatusPartsV1 {
                    namespace: request.namespace().clone(),
                    head: None,
                    lifecycle: None,
                    desired_snapshot_digest: None,
                    status: NamespaceStatusKindV1::NotFound,
                    targets: Vec::new(),
                    observed_bytes: 0,
                    detail: None,
                }),
            );
        };
        let generation = match load_generation(&store, &head) {
            Ok(generation) => generation,
            Err(error @ CommitError::Io { .. }) => return Err(error),
            Err(_) => return Ok(incompatible_status(request, Some(head), None, None)),
        };
        if generation.namespace() != request.namespace() {
            return Ok(incompatible_status(request, Some(head), None, None));
        }
        if let Err(error) = load_catalog_ownership(&self.config, &store, &catalog) {
            if matches!(error, CommitError::Io { .. }) {
                return Err(error);
            }
            return Ok(incompatible_status(
                request,
                Some(head),
                Some(lifecycle_view(generation.lifecycle_state())),
                Some(generation.desired_snapshot_digest().clone()),
            ));
        }
        let lifecycle = lifecycle_view(generation.lifecycle_state());
        if generation.lifecycle_state() == LifecycleStateV1::Disabled {
            return finish_status_snapshot(
                &store,
                &before,
                Some(&catalog_bytes),
                journal_before,
                NamespaceStatusV1::from(NamespaceStatusPartsV1 {
                    namespace: request.namespace().clone(),
                    head: Some(head),
                    lifecycle: Some(lifecycle),
                    desired_snapshot_digest: Some(generation.desired_snapshot_digest().clone()),
                    status: NamespaceStatusKindV1::Disabled,
                    targets: Vec::new(),
                    observed_bytes: 0,
                    detail: None,
                }),
            );
        }
        if generation.targets().len() > request.max_targets() {
            return Ok(incompatible_status(
                request,
                Some(head),
                Some(lifecycle),
                Some(generation.desired_snapshot_digest().clone()),
            ));
        }
        let canonical = match load_canonical_state_objects(
            &store,
            generation.targets().iter().map(StateTargetV1::state),
        ) {
            Ok(canonical) => canonical,
            Err(error @ CommitError::Io { .. }) => return Err(error),
            Err(_) => {
                return Ok(incompatible_status(
                    request,
                    Some(head),
                    Some(lifecycle),
                    Some(generation.desired_snapshot_digest().clone()),
                ));
            }
        };

        let mut observed_bytes = 0_u64;
        let mut targets = Vec::with_capacity(generation.targets().len());
        for target in generation.targets() {
            let status = match observe_status_target(
                &self.config,
                &store,
                target,
                &canonical,
                &mut observed_bytes,
                request.max_observed_bytes(),
            ) {
                Ok(status) => status,
                Err(CommitError::StaleTarget(_) | CommitError::StaleInspection) => {
                    TargetStatusKindV1::Stale
                }
                Err(_) => TargetStatusKindV1::Incompatible,
            };
            targets.push(TargetStatusV1::new(
                target.authority().clone(),
                target.relative_path().to_owned(),
                status,
            ));
        }
        let status = aggregate_target_status(&targets);
        finish_status_snapshot(
            &store,
            &before,
            Some(&catalog_bytes),
            journal_before,
            NamespaceStatusV1::from(NamespaceStatusPartsV1 {
                namespace: request.namespace().clone(),
                head: Some(head),
                lifecycle: Some(lifecycle),
                desired_snapshot_digest: Some(generation.desired_snapshot_digest().clone()),
                status,
                targets,
                observed_bytes,
                detail: None,
            }),
        )
    }
}

fn load_catalog_record(store: &StoreHandles) -> Result<StateCatalogV1, CommitError> {
    load_catalog_record_with_bytes(store).map(|(catalog, _)| catalog)
}

fn load_catalog_record_with_bytes(
    store: &StoreHandles,
) -> Result<(StateCatalogV1, Vec<u8>), CommitError> {
    let state = store
        .state
        .as_ref()
        .ok_or_else(|| CommitError::InvalidStore("state/catalog.json is missing".to_owned()))?;
    let path = store.root_path.join("state/catalog.json");
    let bytes = read_mutable(
        state,
        "catalog.json",
        &path,
        store.uid,
        malm_store::MAX_STATE_CATALOG_BYTES as u64,
    )?
    .ok_or_else(|| CommitError::InvalidStore("state/catalog.json is missing".to_owned()))?;
    let catalog = decode_state_catalog_v1(&bytes).map_err(CommitError::invalid_store)?;
    Ok((catalog, bytes))
}

fn require_catalog_bytes(store: &StoreHandles, expected: &[u8]) -> Result<(), CommitError> {
    let (_, current) = load_catalog_record_with_bytes(store)?;
    if current == expected {
        Ok(())
    } else {
        Err(CommitError::StaleInspection)
    }
}

#[derive(Clone)]
struct StoreDirectorySnapshot {
    root: rustix::fs::Stat,
    prepared: Option<rustix::fs::Stat>,
    objects: Option<rustix::fs::Stat>,
    blobs: Option<rustix::fs::Stat>,
    packs: Option<rustix::fs::Stat>,
    pack_manifests: Option<rustix::fs::Stat>,
    files: Option<rustix::fs::Stat>,
    symlinks: Option<rustix::fs::Stat>,
    trees: Option<rustix::fs::Stat>,
    transactions: Option<rustix::fs::Stat>,
    state: Option<rustix::fs::Stat>,
    generations: Option<rustix::fs::Stat>,
}

fn directory_snapshot(store: &StoreHandles) -> Result<StoreDirectorySnapshot, CommitError> {
    fn optional(
        file: Option<&File>,
        path: &std::path::Path,
    ) -> Result<Option<rustix::fs::Stat>, CommitError> {
        file.map(|file| {
            fstat(file).map_err(|source| io_error("inspect store directory snapshot", path, source))
        })
        .transpose()
    }

    Ok(StoreDirectorySnapshot {
        root: fstat(&store.root)
            .map_err(|source| io_error("inspect store root snapshot", &store.root_path, source))?,
        prepared: optional(store.prepared.as_ref(), &store.root_path.join("prepared"))?,
        objects: optional(store.objects.as_ref(), &store.root_path.join("objects"))?,
        blobs: optional(store.blobs.as_ref(), &store.root_path.join("objects/blobs"))?,
        packs: optional(store.packs.as_ref(), &store.root_path.join("objects/packs"))?,
        pack_manifests: optional(
            store.pack_manifests.as_ref(),
            &store.root_path.join("objects/pack-manifests"),
        )?,
        files: optional(store.files.as_ref(), &store.root_path.join("objects/files"))?,
        symlinks: optional(
            store.symlinks.as_ref(),
            &store.root_path.join("objects/symlinks"),
        )?,
        trees: optional(store.trees.as_ref(), &store.root_path.join("objects/trees"))?,
        transactions: optional(
            store.transactions.as_ref(),
            &store.root_path.join("transactions"),
        )?,
        state: optional(store.state.as_ref(), &store.root_path.join("state"))?,
        generations: optional(
            store.generations.as_ref(),
            &store.root_path.join("state/generations"),
        )?,
    })
}

fn require_directory_snapshot(
    store: &StoreHandles,
    expected: &StoreDirectorySnapshot,
) -> Result<(), CommitError> {
    let current = directory_snapshot(store)?;
    let unchanged = same_snapshot(&expected.root, &current.root)
        && optional_snapshot_matches(expected.prepared.as_ref(), current.prepared.as_ref())
        && optional_snapshot_matches(expected.objects.as_ref(), current.objects.as_ref())
        && optional_snapshot_matches(expected.blobs.as_ref(), current.blobs.as_ref())
        && optional_snapshot_matches(expected.packs.as_ref(), current.packs.as_ref())
        && optional_snapshot_matches(
            expected.pack_manifests.as_ref(),
            current.pack_manifests.as_ref(),
        )
        && optional_snapshot_matches(expected.files.as_ref(), current.files.as_ref())
        && optional_snapshot_matches(expected.symlinks.as_ref(), current.symlinks.as_ref())
        && optional_snapshot_matches(expected.trees.as_ref(), current.trees.as_ref())
        && optional_snapshot_matches(
            expected.transactions.as_ref(),
            current.transactions.as_ref(),
        )
        && optional_snapshot_matches(expected.state.as_ref(), current.state.as_ref())
        && optional_snapshot_matches(expected.generations.as_ref(), current.generations.as_ref());
    if unchanged {
        Ok(())
    } else {
        Err(CommitError::StaleInspection)
    }
}

fn inventory_object_directory(
    directory: Option<&File>,
    path: &std::path::Path,
    maximum: usize,
    enumerated: &mut usize,
    objects: &mut BTreeSet<Digest>,
) -> Result<(), CommitError> {
    let Some(directory) = directory else {
        return Ok(());
    };
    let mut entries = Dir::read_from(directory)
        .map_err(|source| io_error("enumerate object inventory", path, source))?;
    while let Some(entry) = entries.read() {
        let entry = entry.map_err(|source| io_error("enumerate object inventory", path, source))?;
        let bytes = entry.file_name().to_bytes();
        if matches!(bytes, b"." | b"..") {
            continue;
        }
        if *enumerated == maximum {
            return Err(CommitError::InvalidStore(
                "object inventory exceeds its requested item limit".to_owned(),
            ));
        }
        *enumerated += 1;
        let name = std::str::from_utf8(bytes).map_err(|_| {
            CommitError::InvalidStore("object inventory contains a non-UTF-8 name".to_owned())
        })?;
        let digest = Digest::new(name.to_owned()).map_err(|_| {
            CommitError::InvalidStore(
                "object inventory contains a malformed digest name".to_owned(),
            )
        })?;
        objects.insert(digest);
    }
    Ok(())
}

fn optional_snapshot_matches(
    expected: Option<&rustix::fs::Stat>,
    current: Option<&rustix::fs::Stat>,
) -> bool {
    match (expected, current) {
        (Some(expected), Some(current)) => same_snapshot(expected, current),
        (None, None) => true,
        (Some(_), None) | (None, Some(_)) => false,
    }
}

fn desired_target_view(target: &StateTargetV1) -> Result<DesiredTargetInspectionV1, CommitError> {
    let state = match target.state() {
        StateTargetStateV1::File { file } => DesiredTargetStateInspectionV1::File {
            digest: file.as_ref().map(|file| file.digest().clone()),
            byte_len: file.as_ref().map(malm_store::StateFileV1::byte_len),
            mode: file.as_ref().map(malm_store::StateFileV1::mode),
        },
        StateTargetStateV1::Directory { directory } => DesiredTargetStateInspectionV1::Directory {
            mode: directory.map(malm_store::StateDirectoryV1::mode),
        },
        StateTargetStateV1::Symlink { symlink } => DesiredTargetStateInspectionV1::Symlink {
            object: symlink.as_ref().map(|symlink| symlink.object().clone()),
        },
        StateTargetStateV1::Tree { tree } => DesiredTargetStateInspectionV1::Tree {
            tree: tree.as_ref().map(|tree| tree.tree().clone()),
            archive_provenance: tree
                .as_ref()
                .and_then(malm_store::StateTreeV1::archive_provenance)
                .map(|provenance| {
                    ArchiveProvenanceV1::new(
                        provenance.payload().clone(),
                        provenance.decoder().to_owned(),
                    )
                    .map_err(CommitError::invalid_store)
                })
                .transpose()?,
        },
    };
    Ok(DesiredTargetInspectionV1::new(
        target.authority().clone(),
        target.relative_path().to_owned(),
        state,
    ))
}

struct DecodeBudget {
    decoded_bytes: u64,
    requested_maximum: u64,
}

fn read_bounded_canonical(
    store: &StoreHandles,
    directory: Option<&File>,
    kind: &str,
    digest: &Digest,
    family_maximum: u64,
    budget: &mut DecodeBudget,
) -> Result<Vec<u8>, CommitError> {
    let DecodeBudget {
        decoded_bytes,
        requested_maximum,
    } = budget;
    let requested_maximum = *requested_maximum;
    let directory = directory.ok_or_else(|| {
        CommitError::InvalidStore(format!("canonical {kind} object {digest} is missing"))
    })?;
    let path = store
        .root_path
        .join("objects")
        .join(kind)
        .join(digest.as_str());
    let stat = statat(directory, digest.as_str(), AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|source| io_error("inspect canonical object", &path, source))?;
    let size = u64::try_from(stat.st_size).unwrap_or(u64::MAX);
    if size > family_maximum {
        return Err(CommitError::InvalidStore(format!(
            "canonical {kind} object exceeds its family limit"
        )));
    }
    let next = decoded_bytes.checked_add(size).ok_or_else(|| {
        CommitError::InvalidStore("inspection decoded-byte accounting overflowed".to_owned())
    })?;
    if next > requested_maximum {
        return Err(CommitError::InvalidStore(
            "canonical tree inspection exceeds its decoded-byte limit".to_owned(),
        ));
    }
    *decoded_bytes = next;
    read_immutable(directory, digest.as_str(), &path, store.uid, family_maximum)?
        .ok_or_else(|| CommitError::InvalidStore(format!("canonical {kind} object is missing")))
}

struct AuthorizedGeneration {
    generation: StateGenerationV1,
    validation_depth: usize,
}

fn load_effectively_retained_generation(
    store: &StoreHandles,
    namespace: &NamespaceName,
    current_digest: &Digest,
    current: &StateGenerationV1,
    target: &Digest,
) -> Result<AuthorizedGeneration, CommitError> {
    if current.namespace() != namespace {
        return Err(CommitError::InvalidStore(
            "selected generation belongs to another namespace".to_owned(),
        ));
    }
    let history_depth = usize::try_from(current.retention_authority().history().generations())
        .expect("u32 fits in usize");
    let mut digest = current_digest.clone();
    let mut generation = current.clone();
    for offset in 0..history_depth {
        if &digest == target {
            return Ok(AuthorizedGeneration {
                generation,
                validation_depth: history_depth - offset,
            });
        }
        if offset + 1 == history_depth {
            break;
        }
        let Some(previous) = generation.previous_generation().cloned() else {
            break;
        };
        digest = previous;
        generation = load_generation(store, &digest)?;
        if generation.namespace() != namespace {
            return Err(CommitError::InvalidStore(
                "selected generation history changes namespace".to_owned(),
            ));
        }
    }

    let restore_point = current
        .retention_authority()
        .restore_points()
        .iter()
        .find(|point| point.generation() == target);
    let state_generation_pin = current
        .retention_authority()
        .explicit_pins()
        .iter()
        .any(|pin| {
            matches!(
                pin,
                RetentionObjectV1::StateGeneration { digest } if digest == target
            )
        });
    if restore_point.is_none() && !state_generation_pin {
        return Err(CommitError::InvalidStore(format!(
            "generation {target} is not retained by the current namespace authority"
        )));
    }
    let generation = load_generation(store, target)?;
    if generation.namespace() != namespace {
        return Err(CommitError::InvalidStore(
            "retained generation belongs to another namespace".to_owned(),
        ));
    }
    if let Some(point) = restore_point {
        validate_restore_point_reference(point, target, &generation)
            .map_err(CommitError::invalid_store)?;
    }
    Ok(AuthorizedGeneration {
        generation,
        validation_depth: 1,
    })
}

fn inspect_lineage(
    store: &StoreHandles,
    namespace: &NamespaceName,
    start: &Digest,
    max_generations: usize,
    max_decoded_bytes: u64,
) -> Result<(Vec<GenerationInspectionV1>, u64), CommitError> {
    let mut views = Vec::new();
    let mut seen = BTreeSet::new();
    let mut decoded_bytes = 0_u64;
    let mut current_digest = start.clone();
    loop {
        if views.len() == max_generations {
            break;
        }
        if !seen.insert(current_digest.clone()) {
            return Err(CommitError::InvalidStore(format!(
                "namespace {namespace} generation history contains a cycle"
            )));
        }
        let (generation, generation_bytes) =
            load_generation_with_encoded_len(store, &current_digest)?;
        charge_inspection_bytes(&mut decoded_bytes, generation_bytes, max_decoded_bytes)?;
        if generation.namespace() != namespace {
            return Err(CommitError::InvalidStore(format!(
                "namespace {namespace} history enters a generation for another namespace"
            )));
        }
        let (prepared, prepared_bytes) =
            load_prepared_with_encoded_len(store, generation.plan_id())
                .map_err(state_generation_validation_error)?;
        charge_inspection_bytes(&mut decoded_bytes, prepared_bytes, max_decoded_bytes)?;
        let at_retained_floor = views.len() + 1 == max_generations;
        let previous = if at_retained_floor {
            None
        } else {
            generation
                .previous_generation()
                .map(|digest| {
                    let (previous, bytes) = load_generation_with_encoded_len(store, digest)?;
                    charge_inspection_bytes(&mut decoded_bytes, bytes, max_decoded_bytes)?;
                    Ok::<_, CommitError>((digest.clone(), previous, bytes))
                })
                .transpose()?
        };
        let rebuilt = if at_retained_floor && generation.previous_generation().is_some() {
            StateGenerationV1::from_retained_prepared(
                generation.plan_id().clone(),
                generation.previous_generation().cloned(),
                &prepared,
            )
        } else {
            StateGenerationV1::from_prepared(
                generation.plan_id().clone(),
                generation.previous_generation().cloned(),
                previous.as_ref().map(|(_, generation, _)| generation),
                &prepared,
            )
        }
        .map_err(CommitError::invalid_store)?;
        if rebuilt != generation {
            return Err(CommitError::InvalidStore(
                "state generation does not match its prepared transition".to_owned(),
            ));
        }
        views.push(generation_view(current_digest.clone(), &generation));
        let Some((digest, _, _)) = previous else {
            break;
        };
        current_digest = digest;
    }
    Ok((views, decoded_bytes))
}

fn charge_inspection_bytes(total: &mut u64, bytes: usize, maximum: u64) -> Result<(), CommitError> {
    *total = total
        .checked_add(u64::try_from(bytes).unwrap_or(u64::MAX))
        .ok_or_else(|| CommitError::InvalidStore("inspection byte budget overflowed".to_owned()))?;
    if *total > maximum {
        return Err(CommitError::InvalidStore(format!(
            "inspection decoded bytes exceed the requested {maximum} byte limit"
        )));
    }
    Ok(())
}

fn generation_view(digest: Digest, generation: &StateGenerationV1) -> GenerationInspectionV1 {
    let present = generation
        .targets()
        .iter()
        .filter(|target| target.is_present())
        .count();
    let total = generation.targets().len();
    GenerationInspectionV1::from(GenerationInspectionPartsV1 {
        namespace: generation.namespace().clone(),
        generation: digest,
        lifecycle: lifecycle_view(generation.lifecycle_state()),
        desired_snapshot_digest: generation.desired_snapshot_digest().clone(),
        target_count: malm_types::usize_to_u64(total),
        present_target_count: malm_types::usize_to_u64(present),
        absent_target_count: malm_types::usize_to_u64(total - present),
        plan_id: generation.plan_id().clone(),
        predecessor: generation.previous_generation().cloned(),
        tracked_root: generation.tracked_root().map(tracked_root_view),
    })
    .with_authority(
        transition_view(generation.transition()),
        generation.restore_point().map(restore_point_view),
        RetentionAuthorityInspectionV1::new(
            generation.retention_authority().history().generations(),
            generation
                .retention_authority()
                .restore_points()
                .iter()
                .map(restore_point_view)
                .collect(),
            generation.retention_authority().explicit_pins().to_vec(),
        ),
    )
}

fn transition_view(transition: &PreparedTransitionV1) -> LifecycleTransitionViewV1 {
    match transition {
        PreparedTransitionV1::Reconcile => LifecycleTransitionViewV1::Reconcile,
        PreparedTransitionV1::Disable => LifecycleTransitionViewV1::Disable,
        PreparedTransitionV1::Enable { restore_point } => LifecycleTransitionViewV1::Enable {
            restore_generation: restore_point.generation().clone(),
        },
        PreparedTransitionV1::Checkout { source_generation } => {
            LifecycleTransitionViewV1::Checkout {
                source_generation: source_generation.clone(),
            }
        }
        PreparedTransitionV1::RetentionAuthority => LifecycleTransitionViewV1::RetentionAuthority,
        PreparedTransitionV1::NamespaceRemoval { .. } => {
            LifecycleTransitionViewV1::NamespaceRemoval {
                drops_history: true,
            }
        }
    }
}

fn restore_point_view(point: &RestorePointV1) -> RestorePointInspectionV1 {
    RestorePointInspectionV1::new(
        point.generation().clone(),
        lifecycle_view(point.lifecycle()),
        point.desired_snapshot_digest().clone(),
        point.tracked_root().map(tracked_root_view),
    )
}

fn tracked_root_view(tracked: &TrackedRootV1) -> TrackedRootInspectionV1 {
    TrackedRootInspectionV1::new(
        tracked.moving_selector().as_str().to_owned(),
        tracked.applied_revision().as_str().to_owned(),
        tracked.root_tree_digest().clone(),
    )
}

const fn lifecycle_view(lifecycle: LifecycleStateV1) -> LifecycleStateViewV1 {
    match lifecycle {
        LifecycleStateV1::Enabled => LifecycleStateViewV1::Enabled,
        LifecycleStateV1::Disabled => LifecycleStateViewV1::Disabled,
    }
}

struct FsckScan {
    request: FsckRequestV1,
    findings: Vec<FsckFindingV1>,
    findings_truncated: bool,
    complete: bool,
    enumerated_entries: usize,
    traversed_objects: usize,
    traversal_limit_reported: bool,
    decoded_byte_limit_reported: bool,
    journal_inventory_complete: bool,
    decoded_bytes: u64,
    observed_bytes: u64,
    checked_targets: u64,
    checked_generations: BTreeSet<Digest>,
    checked_prepared: BTreeSet<PreparedId>,
    checked_blobs: BTreeSet<Digest>,
    checked_packs: BTreeSet<Digest>,
    checked_files: BTreeSet<Digest>,
    checked_symlinks: BTreeSet<Digest>,
    checked_trees: BTreeSet<Digest>,
}

struct FsckEntryRead<'a> {
    family: &'a str,
    leaf: &'a str,
    maximum: u64,
    code: FsckFindingCodeV1,
    subject: FsckSubjectV1,
}

#[derive(Clone, Copy)]
struct FsckWorld<'a> {
    catalog: Option<&'a StateCatalogV1>,
    journal: Option<&'a super::LoadedJournalV1>,
    prepared: &'a BTreeMap<PreparedId, malm_store::PreparedRecordV1>,
    generations: &'a BTreeMap<Digest, StateGenerationV1>,
    blobs: &'a BTreeMap<Digest, u64>,
    packs: &'a BTreeSet<Digest>,
    canonical: &'a super::canonical::CanonicalObjects,
}

#[derive(Default)]
struct FsckAuthorityRoots {
    generations: Vec<FsckGenerationRoot>,
    plans: BTreeSet<PreparedId>,
    blobs: BTreeSet<Digest>,
    packs: BTreeSet<Digest>,
    files: BTreeSet<Digest>,
    symlinks: BTreeSet<Digest>,
    trees: BTreeSet<Digest>,
}

struct FsckGenerationRoot {
    digest: Digest,
    limit: u32,
    namespace: Option<NamespaceName>,
}

impl FsckScan {
    fn new(request: FsckRequestV1) -> Self {
        Self {
            request,
            findings: Vec::new(),
            findings_truncated: false,
            complete: true,
            enumerated_entries: 0,
            traversed_objects: 0,
            traversal_limit_reported: false,
            decoded_byte_limit_reported: false,
            journal_inventory_complete: true,
            decoded_bytes: 0,
            observed_bytes: 0,
            checked_targets: 0,
            checked_generations: BTreeSet::new(),
            checked_prepared: BTreeSet::new(),
            checked_blobs: BTreeSet::new(),
            checked_packs: BTreeSet::new(),
            checked_files: BTreeSet::new(),
            checked_symlinks: BTreeSet::new(),
            checked_trees: BTreeSet::new(),
        }
    }

    fn error(&mut self, code: FsckFindingCodeV1, subject: FsckSubjectV1, detail: &'static str) {
        self.complete = false;
        self.finding(code, FsckSeverityV1::Error, subject, detail);
    }

    fn warning(&mut self, code: FsckFindingCodeV1, subject: FsckSubjectV1, detail: &'static str) {
        self.finding(code, FsckSeverityV1::Warning, subject, detail);
    }

    fn finding(
        &mut self,
        code: FsckFindingCodeV1,
        severity: FsckSeverityV1,
        subject: FsckSubjectV1,
        detail: &'static str,
    ) {
        if self.findings.len() < self.request.max_findings() {
            self.findings
                .push(FsckFindingV1::new(code, severity, subject, detail));
            return;
        }
        if self.findings_truncated {
            return;
        }
        self.findings_truncated = true;
        self.complete = false;
        let last = self
            .findings
            .last_mut()
            .expect("validated fsck finding limit is nonzero");
        *last = FsckFindingV1::new(
            FsckFindingCodeV1::FindingLimitExceeded,
            FsckSeverityV1::Error,
            FsckSubjectV1::Coverage,
            "additional fsck findings were omitted at the requested finding limit",
        );
    }

    fn coverage_gap(&mut self) {
        self.complete = false;
    }

    fn authority_inventory_complete(&self) -> bool {
        !self.traversal_limit_reported && !self.decoded_byte_limit_reported
    }

    fn charge_object(&mut self, subject: FsckSubjectV1) -> bool {
        if self.traversed_objects == self.request.max_objects() {
            if !self.traversal_limit_reported {
                self.traversal_limit_reported = true;
                self.error(
                    FsckFindingCodeV1::TraversalLimitExceeded,
                    subject,
                    "physical object traversal exceeded the requested object limit",
                );
            }
            return false;
        }
        self.traversed_objects += 1;
        true
    }

    fn charge_bytes(&mut self, bytes: u64, subject: FsckSubjectV1) -> bool {
        let Some(next) = self.decoded_bytes.checked_add(bytes) else {
            if !self.decoded_byte_limit_reported {
                self.decoded_byte_limit_reported = true;
                self.error(
                    FsckFindingCodeV1::DecodedByteLimitExceeded,
                    subject,
                    "fsck decoded-byte accounting overflowed",
                );
            }
            return false;
        };
        if next > self.request.max_decoded_bytes() {
            if !self.decoded_byte_limit_reported {
                self.decoded_byte_limit_reported = true;
                self.error(
                    FsckFindingCodeV1::DecodedByteLimitExceeded,
                    subject,
                    "physical object bytes exceed the requested decoded-byte limit",
                );
            }
            return false;
        }
        self.decoded_bytes = next;
        true
    }

    fn directory_entries(
        &mut self,
        directory: &File,
        path: &std::path::Path,
        area: FsckStoreAreaV1,
    ) -> Result<Vec<OsString>, CommitError> {
        let mut entries = Dir::read_from(directory)
            .map_err(|source| io_error("enumerate fsck store directory", path, source))?;
        let mut names = Vec::new();
        while let Some(entry) = entries.read() {
            let entry =
                entry.map_err(|source| io_error("enumerate fsck store directory", path, source))?;
            let bytes = entry.file_name().to_bytes();
            if matches!(bytes, b"." | b"..") {
                continue;
            }
            if self.enumerated_entries == self.request.max_objects() {
                if !self.traversal_limit_reported {
                    self.traversal_limit_reported = true;
                    self.error(
                        FsckFindingCodeV1::TraversalLimitExceeded,
                        FsckSubjectV1::StoreArea(area),
                        "store directory enumeration exceeded the requested object limit",
                    );
                }
                break;
            }
            self.enumerated_entries += 1;
            names.push(OsString::from_vec(bytes.to_vec()));
        }
        names.sort_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
        Ok(names)
    }

    fn inspect_store_shape(&mut self, store: &StoreHandles) -> Result<(), CommitError> {
        self.inspect_directory_shape(
            &store.root,
            &store.root_path,
            FsckStoreAreaV1::Root,
            &[
                malm_root::DESCRIPTOR_FILENAME,
                "transaction.lock",
                "maintenance.lock",
                "prepared",
                "objects",
                "transactions",
                "state",
            ],
        )?;
        if let Some(objects) = &store.objects {
            self.inspect_directory_shape(
                objects,
                &store.root_path.join("objects"),
                FsckStoreAreaV1::Objects,
                &[
                    "blobs",
                    "packs",
                    "pack-manifests",
                    "files",
                    "symlinks",
                    "trees",
                ],
            )?;
        }
        if let Some(state) = &store.state {
            self.inspect_directory_shape(
                state,
                &store.root_path.join("state"),
                FsckStoreAreaV1::State,
                &[
                    "catalog.json",
                    ".catalog.json.new",
                    "generations",
                    "observed.json",
                    ".observed.json.new",
                ],
            )?;
        }
        if let Some(transactions) = &store.transactions {
            self.inspect_directory_shape(
                transactions,
                &store.root_path.join("transactions"),
                FsckStoreAreaV1::Transactions,
                &["current.json", ".current.json.update", ".current.json.new"],
            )?;
        }
        Ok(())
    }

    fn inspect_directory_shape(
        &mut self,
        directory: &File,
        path: &std::path::Path,
        area: FsckStoreAreaV1,
        allowed: &[&str],
    ) -> Result<(), CommitError> {
        for name in self.directory_entries(directory, path, area)? {
            let bytes = name.as_bytes();
            if allowed.iter().any(|allowed| allowed.as_bytes() == bytes) {
                continue;
            }
            let code = if bytes.starts_with(b".") {
                FsckFindingCodeV1::InvalidStaging
            } else {
                FsckFindingCodeV1::MalformedStoreEntry
            };
            self.error(
                code,
                FsckSubjectV1::StoreArea(area),
                "the store area contains an unrecognized entry",
            );
        }
        Ok(())
    }

    fn inspect_lock(
        &mut self,
        store: &StoreHandles,
        leaf: &str,
        subject: FsckSubjectV1,
    ) -> Result<(), CommitError> {
        let path = store.root_path.join(leaf);
        match read_mutable(&store.root, leaf, &path, store.uid, 0) {
            Ok(_) => Ok(()),
            Err(error @ CommitError::Io { .. }) => Err(error),
            Err(_) => {
                self.error(
                    FsckFindingCodeV1::InvalidLockMetadata,
                    subject,
                    "an existing store lock has unsafe metadata or changed while inspected",
                );
                Ok(())
            }
        }
    }

    fn prepare_entry_read(
        &mut self,
        directory: &File,
        leaf: &str,
        maximum: u64,
        code: FsckFindingCodeV1,
        subject: FsckSubjectV1,
    ) -> Result<Option<()>, CommitError> {
        let stat = match statat(directory, leaf, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(stat) => stat,
            Err(rustix::io::Errno::NOENT) => return Ok(None),
            Err(source) => {
                return Err(io_error(
                    "inspect fsck store entry",
                    std::path::Path::new(leaf),
                    source,
                ));
            }
        };
        let size = u64::try_from(stat.st_size).unwrap_or(u64::MAX);
        if size > maximum {
            self.error(
                code,
                subject,
                "the store entry exceeds its format-specific encoded-size limit",
            );
            return Ok(None);
        }
        if !self.charge_bytes(size, subject) {
            return Ok(None);
        }
        Ok(Some(()))
    }

    fn read_immutable_entry(
        &mut self,
        store: &StoreHandles,
        directory: &File,
        entry: FsckEntryRead<'_>,
    ) -> Result<Option<Vec<u8>>, CommitError> {
        let FsckEntryRead {
            family,
            leaf,
            maximum,
            code,
            subject,
        } = entry;
        if self
            .prepare_entry_read(directory, leaf, maximum, code, subject.clone())?
            .is_none()
        {
            return Ok(None);
        }
        let path = store.root_path.join(family).join(leaf);
        match read_immutable(directory, leaf, &path, store.uid, maximum) {
            Ok(Some(bytes)) => Ok(Some(bytes)),
            Ok(None) => {
                self.error(
                    FsckFindingCodeV1::AuthorityChanged,
                    subject,
                    "a physically enumerated immutable entry vanished during fsck",
                );
                Ok(None)
            }
            Err(error @ CommitError::Io { .. }) => Err(error),
            Err(_) => {
                self.error(
                    code,
                    subject,
                    "the immutable entry is unsafe, corrupt, or changed while inspected",
                );
                Ok(None)
            }
        }
    }

    fn load_journal(
        &mut self,
        store: &StoreHandles,
    ) -> Result<Option<super::LoadedJournalV1>, CommitError> {
        let Some(directory) = &store.transactions else {
            return Ok(None);
        };
        for (leaf, subject) in [
            ("current.json", FsckSubjectV1::Journal),
            (".current.json.update", FsckSubjectV1::JournalStaging),
        ] {
            if statat(directory, leaf, AtFlags::SYMLINK_NOFOLLOW).is_ok() {
                if !self.charge_object(subject.clone()) {
                    self.journal_inventory_complete = false;
                    return Ok(None);
                }
                if self
                    .prepare_entry_read(
                        directory,
                        leaf,
                        super::MAX_TRANSACTION_JOURNAL_BYTES as u64,
                        FsckFindingCodeV1::InvalidJournal,
                        subject,
                    )?
                    .is_none()
                {
                    self.journal_inventory_complete = false;
                    return Ok(None);
                }
            }
        }
        match load_journal(store) {
            Ok(journal) => {
                if journal.is_some() {
                    self.error(
                        FsckFindingCodeV1::RecoveryRequired,
                        FsckSubjectV1::Journal,
                        "an incomplete successor transaction requires explicit recovery",
                    );
                }
                Ok(journal)
            }
            Err(error @ CommitError::Io { .. }) => Err(error),
            Err(_) => {
                self.journal_inventory_complete = false;
                self.error(
                    FsckFindingCodeV1::InvalidJournal,
                    FsckSubjectV1::Journal,
                    "transaction journal state is unsafe, corrupt, noncanonical, or inconsistent",
                );
                Ok(None)
            }
        }
    }

    fn load_catalog(
        &mut self,
        store: &StoreHandles,
    ) -> Result<(Option<StateCatalogV1>, Option<Vec<u8>>), CommitError> {
        let Some(state) = &store.state else {
            self.error(
                FsckFindingCodeV1::MissingCatalog,
                FsckSubjectV1::Catalog,
                "the state directory and global catalog are missing",
            );
            return Ok((None, None));
        };
        if !self.charge_object(FsckSubjectV1::Catalog) {
            return Ok((None, None));
        }
        if self
            .prepare_entry_read(
                state,
                "catalog.json",
                malm_store::MAX_STATE_CATALOG_BYTES as u64,
                FsckFindingCodeV1::InvalidCatalog,
                FsckSubjectV1::Catalog,
            )?
            .is_none()
        {
            if statat(state, "catalog.json", AtFlags::SYMLINK_NOFOLLOW).is_err() {
                self.error(
                    FsckFindingCodeV1::MissingCatalog,
                    FsckSubjectV1::Catalog,
                    "the authoritative global catalog is missing",
                );
            }
            return Ok((None, None));
        }
        match load_catalog_record_with_bytes(store) {
            Ok((catalog, bytes)) => {
                // Unlike routine operations, fsck checks every retained
                // generation. This includes cycles and the transition at the
                // retention boundary.
                if validate_catalog_lineages(store, &catalog, None, LineageDepth::Full).is_err() {
                    self.error(
                        FsckFindingCodeV1::InvalidCatalog,
                        FsckSubjectV1::Catalog,
                        "a namespace's retained generation lineage is invalid",
                    );
                }
                Ok((Some(catalog), Some(bytes)))
            }
            Err(error @ CommitError::Io { .. }) => Err(error),
            Err(_) => {
                self.error(
                    FsckFindingCodeV1::InvalidCatalog,
                    FsckSubjectV1::Catalog,
                    "the authoritative global catalog is unsafe, corrupt, or noncanonical",
                );
                Ok((None, None))
            }
        }
    }

    fn load_prepared_records(
        &mut self,
        store: &StoreHandles,
    ) -> Result<BTreeMap<PreparedId, malm_store::PreparedRecordV1>, CommitError> {
        let Some(directory) = &store.prepared else {
            return Ok(BTreeMap::new());
        };
        let path = store.root_path.join("prepared");
        let mut records = BTreeMap::new();
        for name in self.directory_entries(directory, &path, FsckStoreAreaV1::Prepared)? {
            let Ok(name) = name.into_string() else {
                self.error(
                    FsckFindingCodeV1::MalformedStoreEntry,
                    FsckSubjectV1::StoreArea(FsckStoreAreaV1::Prepared),
                    "the prepared-record directory contains a non-UTF-8 name",
                );
                continue;
            };
            let plan_id = match PreparedId::new(name) {
                Ok(plan_id) => plan_id,
                Err(_) => {
                    self.error(
                        FsckFindingCodeV1::MalformedStoreEntry,
                        FsckSubjectV1::StoreArea(FsckStoreAreaV1::Prepared),
                        "the prepared-record directory contains a malformed plan identity",
                    );
                    continue;
                }
            };
            let subject = FsckSubjectV1::PreparedPlan(plan_id.clone());
            if !self.charge_object(subject.clone()) {
                continue;
            }
            self.checked_prepared.insert(plan_id.clone());
            let Some(bytes) = self.read_immutable_entry(
                store,
                directory,
                FsckEntryRead {
                    family: "prepared",
                    leaf: plan_id.as_str(),
                    maximum: malm_store::MAX_PREPARED_RECORD_BYTES as u64,
                    code: FsckFindingCodeV1::InvalidPreparedPlan,
                    subject: subject.clone(),
                },
            )?
            else {
                continue;
            };
            match malm_store::decode_prepared_record_v1(&plan_id, &bytes) {
                Ok(record) => {
                    records.insert(plan_id, record);
                }
                Err(_) => self.error(
                    FsckFindingCodeV1::InvalidPreparedPlan,
                    subject,
                    "the prepared record is corrupt, noncanonical, unsupported, or misnamed",
                ),
            }
        }
        Ok(records)
    }

    fn load_generations(
        &mut self,
        store: &StoreHandles,
    ) -> Result<BTreeMap<Digest, StateGenerationV1>, CommitError> {
        let Some(directory) = &store.generations else {
            return Ok(BTreeMap::new());
        };
        let path = store.root_path.join("state/generations");
        let mut records = BTreeMap::new();
        for name in self.directory_entries(directory, &path, FsckStoreAreaV1::Generations)? {
            let Some(digest) = self.parse_digest_name(name, FsckStoreAreaV1::Generations) else {
                continue;
            };
            let subject = FsckSubjectV1::Generation(digest.clone());
            if !self.charge_object(subject.clone()) {
                continue;
            }
            self.checked_generations.insert(digest.clone());
            let Some(bytes) = self.read_immutable_entry(
                store,
                directory,
                FsckEntryRead {
                    family: "state/generations",
                    leaf: digest.as_str(),
                    maximum: malm_store::MAX_STATE_RECORD_BYTES as u64,
                    code: FsckFindingCodeV1::InvalidGeneration,
                    subject: subject.clone(),
                },
            )?
            else {
                continue;
            };
            match malm_store::decode_state_generation_v1(&digest, &bytes) {
                Ok(record) => {
                    records.insert(digest, record);
                }
                Err(_) => self.error(
                    FsckFindingCodeV1::InvalidGeneration,
                    subject,
                    "the state generation is corrupt, noncanonical, unsupported, or misnamed",
                ),
            }
        }
        Ok(records)
    }

    fn load_blobs(&mut self, store: &StoreHandles) -> Result<BTreeMap<Digest, u64>, CommitError> {
        let Some(directory) = &store.blobs else {
            return Ok(BTreeMap::new());
        };
        let path = store.root_path.join("objects/blobs");
        let mut blobs = BTreeMap::new();
        for name in self.directory_entries(directory, &path, FsckStoreAreaV1::ArtifactBlobs)? {
            let Some(digest) = self.parse_digest_name(name, FsckStoreAreaV1::ArtifactBlobs) else {
                continue;
            };
            let subject = FsckSubjectV1::ArtifactBlob(digest.clone());
            if !self.charge_object(subject.clone()) {
                continue;
            }
            self.checked_blobs.insert(digest.clone());
            let Some(bytes) = self.read_immutable_entry(
                store,
                directory,
                FsckEntryRead {
                    family: "objects/blobs",
                    leaf: digest.as_str(),
                    maximum: malm_store::MAX_ARTIFACT_BLOB_BYTES,
                    code: FsckFindingCodeV1::CorruptArtifactBlob,
                    subject: subject.clone(),
                },
            )?
            else {
                continue;
            };
            if Digest::sha256(&bytes) != digest {
                self.error(
                    FsckFindingCodeV1::CorruptArtifactBlob,
                    subject,
                    "the artifact blob bytes do not match their content address",
                );
                continue;
            }
            blobs.insert(digest, malm_types::usize_to_u64(bytes.len()));
        }
        Ok(blobs)
    }

    fn load_packs(&mut self, store: &StoreHandles) -> Result<BTreeSet<Digest>, CommitError> {
        let Some(directory) = &store.packs else {
            return Ok(BTreeSet::new());
        };
        let path = store.root_path.join("objects/packs");
        let mut packs = BTreeSet::new();
        for name in self.directory_entries(directory, &path, FsckStoreAreaV1::PackObjects)? {
            let Some(digest) = self.parse_digest_name(name, FsckStoreAreaV1::PackObjects) else {
                continue;
            };
            let subject = FsckSubjectV1::PackObject(digest.clone());
            if !self.charge_object(subject.clone()) {
                continue;
            }
            self.checked_packs.insert(digest.clone());
            let Some(bytes) = self.read_immutable_entry(
                store,
                directory,
                FsckEntryRead {
                    family: "objects/packs",
                    leaf: digest.as_str(),
                    maximum: super::pack_object::MAX_PACK_OBJECT_BYTES,
                    code: FsckFindingCodeV1::CorruptPackObject,
                    subject: subject.clone(),
                },
            )?
            else {
                continue;
            };
            if !super::pack_object::validate(&bytes, &digest) {
                self.error(
                    FsckFindingCodeV1::CorruptPackObject,
                    subject,
                    "the pack object is corrupt, noncanonical, unsupported, or misnamed",
                );
                continue;
            }
            packs.insert(digest);
        }
        if let Some(directory) = &store.pack_manifests {
            let path = store.root_path.join("objects/pack-manifests");
            for name in self.directory_entries(directory, &path, FsckStoreAreaV1::PackObjects)? {
                let Some(digest) = self.parse_digest_name(name, FsckStoreAreaV1::PackObjects)
                else {
                    continue;
                };
                let subject = FsckSubjectV1::PackObject(digest.clone());
                if !self.charge_object(subject.clone()) {
                    continue;
                }
                self.checked_packs.insert(digest.clone());
                let Some(bytes) = self.read_immutable_entry(
                    store,
                    directory,
                    FsckEntryRead {
                        family: "objects/pack-manifests",
                        leaf: digest.as_str(),
                        maximum: 128 * 1024 * 1024,
                        code: FsckFindingCodeV1::CorruptPackObject,
                        subject: subject.clone(),
                    },
                )?
                else {
                    continue;
                };
                let members = match super::decode_pack_manifest_members(&bytes) {
                    Ok(members) => members,
                    Err(_) => {
                        self.error(
                            FsckFindingCodeV1::CorruptPackObject,
                            subject,
                            "the pack manifest is corrupt, noncanonical, or unsupported",
                        );
                        continue;
                    }
                };
                let mut complete = true;
                for (member, byte_len) in members {
                    let missing = store
                        .blobs
                        .as_ref()
                        .and_then(|blobs| {
                            statat(blobs, member.as_str(), AtFlags::SYMLINK_NOFOLLOW).ok()
                        })
                        .is_none_or(|stat| u64::try_from(stat.st_size).ok() != Some(byte_len));
                    if missing {
                        complete = false;
                    }
                }
                if !complete {
                    self.error(
                        FsckFindingCodeV1::CorruptPackObject,
                        subject,
                        "a pack manifest member blob is missing or has the wrong length",
                    );
                    continue;
                }
                packs.insert(digest);
            }
        }
        Ok(packs)
    }

    fn load_canonical_objects(
        &mut self,
        store: &StoreHandles,
    ) -> Result<super::canonical::CanonicalObjects, CommitError> {
        let mut objects = super::canonical::CanonicalObjects::empty();
        if let Some(directory) = &store.files {
            let path = store.root_path.join("objects/files");
            for name in self.directory_entries(directory, &path, FsckStoreAreaV1::CanonicalFiles)? {
                let Some(digest) = self.parse_digest_name(name, FsckStoreAreaV1::CanonicalFiles)
                else {
                    continue;
                };
                let subject = FsckSubjectV1::CanonicalFile(digest.clone());
                if !self.charge_object(subject.clone()) {
                    continue;
                }
                self.checked_files.insert(digest.clone());
                let Some(bytes) = self.read_immutable_entry(
                    store,
                    directory,
                    FsckEntryRead {
                        family: "objects/files",
                        leaf: digest.as_str(),
                        maximum: super::canonical::MAX_FILE_OBJECT_BYTES,
                        code: FsckFindingCodeV1::CorruptCanonicalObject,
                        subject: subject.clone(),
                    },
                )?
                else {
                    continue;
                };
                match super::canonical::decode_file(&digest, &bytes) {
                    Ok(contents) => {
                        objects.files.insert(digest, contents);
                    }
                    Err(_) => self.error(
                        FsckFindingCodeV1::CorruptCanonicalObject,
                        subject,
                        "the canonical file object is corrupt, noncanonical, or misnamed",
                    ),
                }
            }
        }
        if let Some(directory) = &store.symlinks {
            let path = store.root_path.join("objects/symlinks");
            for name in
                self.directory_entries(directory, &path, FsckStoreAreaV1::CanonicalSymlinks)?
            {
                let Some(digest) = self.parse_digest_name(name, FsckStoreAreaV1::CanonicalSymlinks)
                else {
                    continue;
                };
                let subject = FsckSubjectV1::CanonicalSymlink(digest.clone());
                if !self.charge_object(subject.clone()) {
                    continue;
                }
                self.checked_symlinks.insert(digest.clone());
                let Some(bytes) = self.read_immutable_entry(
                    store,
                    directory,
                    FsckEntryRead {
                        family: "objects/symlinks",
                        leaf: digest.as_str(),
                        maximum: super::canonical::MAX_SYMLINK_OBJECT_BYTES,
                        code: FsckFindingCodeV1::CorruptCanonicalObject,
                        subject: subject.clone(),
                    },
                )?
                else {
                    continue;
                };
                match super::canonical::decode_symlink(&digest, &bytes) {
                    Ok(target) => {
                        objects.symlinks.insert(digest, target);
                    }
                    Err(_) => self.error(
                        FsckFindingCodeV1::CorruptCanonicalObject,
                        subject,
                        "the canonical symlink object is corrupt, noncanonical, or misnamed",
                    ),
                }
            }
        }
        if let Some(directory) = &store.trees {
            let path = store.root_path.join("objects/trees");
            for name in self.directory_entries(directory, &path, FsckStoreAreaV1::CanonicalTrees)? {
                let Some(digest) = self.parse_digest_name(name, FsckStoreAreaV1::CanonicalTrees)
                else {
                    continue;
                };
                let subject = FsckSubjectV1::CanonicalTree(digest.clone());
                if !self.charge_object(subject.clone()) {
                    continue;
                }
                self.checked_trees.insert(digest.clone());
                let Some(bytes) = self.read_immutable_entry(
                    store,
                    directory,
                    FsckEntryRead {
                        family: "objects/trees",
                        leaf: digest.as_str(),
                        maximum: super::canonical::MAX_TREE_OBJECT_BYTES,
                        code: FsckFindingCodeV1::CorruptCanonicalObject,
                        subject: subject.clone(),
                    },
                )?
                else {
                    continue;
                };
                match super::canonical::decode_tree(&digest, &bytes) {
                    Ok(tree) => {
                        objects.trees.insert(digest, tree);
                    }
                    Err(_) => self.error(
                        FsckFindingCodeV1::CorruptCanonicalObject,
                        subject,
                        "the canonical tree object is corrupt, noncanonical, or misnamed",
                    ),
                }
            }
        }
        Ok(objects)
    }

    fn parse_digest_name(&mut self, name: OsString, area: FsckStoreAreaV1) -> Option<Digest> {
        let Ok(name) = name.into_string() else {
            self.error(
                FsckFindingCodeV1::MalformedStoreEntry,
                FsckSubjectV1::StoreArea(area),
                "an immutable-object directory contains a non-UTF-8 name",
            );
            return None;
        };
        match Digest::new(name) {
            Ok(digest) => Some(digest),
            Err(_) => {
                self.error(
                    FsckFindingCodeV1::MalformedStoreEntry,
                    FsckSubjectV1::StoreArea(area),
                    "an immutable-object directory contains a malformed content address",
                );
                None
            }
        }
    }

    fn validate_authority(
        &mut self,
        config: &CommitConfig,
        store: &StoreHandles,
        world: FsckWorld<'_>,
    ) -> Result<(), CommitError> {
        let FsckWorld {
            catalog,
            prepared,
            generations,
            blobs,
            packs,
            canonical,
            ..
        } = world;
        let mut roots = FsckAuthorityRoots::default();
        roots.plans.extend(prepared.keys().cloned());
        let mut selected = Vec::<(NamespaceName, StateGenerationV1)>::new();

        if let Some(catalog) = catalog {
            for head in catalog.heads() {
                let Some(generation) = generations.get(head.generation()) else {
                    self.error(
                        FsckFindingCodeV1::MissingGeneration,
                        FsckSubjectV1::Generation(head.generation().clone()),
                        "a catalog-selected namespace head is missing or invalid",
                    );
                    continue;
                };
                if generation.namespace() != head.namespace() {
                    self.error(
                        FsckFindingCodeV1::CrossNamespaceHistory,
                        FsckSubjectV1::Generation(head.generation().clone()),
                        "a catalog head selects a generation for another namespace",
                    );
                }
                selected.push((head.namespace().clone(), generation.clone()));
                roots.generations.push(FsckGenerationRoot {
                    digest: head.generation().clone(),
                    limit: generation.retention_authority().history().generations(),
                    namespace: Some(head.namespace().clone()),
                });
                if let Some(point) = generation.restore_point() {
                    self.collect_restore_point_root(point, generations, &mut roots);
                }
                self.collect_retention_roots(
                    generation.retention_authority(),
                    generations,
                    &mut roots,
                );
            }
        }

        for record in prepared.values() {
            if let Some(point) = record.restore_point() {
                self.collect_restore_point_root(point, generations, &mut roots);
            }
            self.collect_retention_roots(record.retention_authority(), generations, &mut roots);
        }
        self.validate_journal_authority(store, world, &mut roots)?;

        let mut generation_namespaces = BTreeMap::new();
        let mut reachable_generations = BTreeSet::new();
        for root in &roots.generations {
            self.walk_generation_root(
                root,
                prepared,
                generations,
                &mut generation_namespaces,
                &mut reachable_generations,
            );
        }
        for (digest, generation) in generations {
            if reachable_generations.contains(digest) {
                continue;
            }
            self.validate_unreachable_generation(digest, generation, prepared, generations);
            self.warning(
                FsckFindingCodeV1::UnreachableImmutableObject,
                FsckSubjectV1::Generation(digest.clone()),
                "the verified state generation is not retained by current authority",
            );
        }

        let mut artifact_lengths = BTreeMap::<Digest, BTreeSet<u64>>::new();
        for plan_id in roots.plans.clone() {
            let Some(record) = prepared.get(&plan_id) else {
                self.error(
                    FsckFindingCodeV1::MissingPreparedPlan,
                    FsckSubjectV1::PreparedPlan(plan_id),
                    "retention or journal authority references a missing prepared plan",
                );
                continue;
            };
            record_prepared_dependencies(record, &mut roots, &mut artifact_lengths);
        }
        for digest in &reachable_generations {
            if let Some(generation) = generations.get(digest) {
                record_generation_dependencies(generation, &mut roots, &mut artifact_lengths);
            }
        }
        self.validate_blob_roots(&roots.blobs, &artifact_lengths, blobs);
        self.validate_pack_roots(&roots.packs, packs);
        let (reachable_files, reachable_symlinks, reachable_trees) =
            self.validate_canonical_roots(&roots, canonical);

        for digest in blobs.keys().filter(|digest| !roots.blobs.contains(*digest)) {
            self.warning(
                FsckFindingCodeV1::UnreachableImmutableObject,
                FsckSubjectV1::ArtifactBlob(digest.clone()),
                "the verified artifact blob is not retained by current authority",
            );
        }
        for digest in packs.iter().filter(|digest| !roots.packs.contains(*digest)) {
            self.warning(
                FsckFindingCodeV1::UnreachableImmutableObject,
                FsckSubjectV1::PackObject(digest.clone()),
                "the verified pack object is not retained by current authority",
            );
        }
        for digest in canonical
            .files
            .keys()
            .filter(|digest| !reachable_files.contains(*digest))
        {
            self.warning(
                FsckFindingCodeV1::UnreachableImmutableObject,
                FsckSubjectV1::CanonicalFile(digest.clone()),
                "the verified canonical file is not retained by current authority",
            );
        }
        for digest in canonical
            .symlinks
            .keys()
            .filter(|digest| !reachable_symlinks.contains(*digest))
        {
            self.warning(
                FsckFindingCodeV1::UnreachableImmutableObject,
                FsckSubjectV1::CanonicalSymlink(digest.clone()),
                "the verified canonical symlink is not retained by current authority",
            );
        }
        for digest in canonical
            .trees
            .keys()
            .filter(|digest| !reachable_trees.contains(*digest))
        {
            self.warning(
                FsckFindingCodeV1::UnreachableImmutableObject,
                FsckSubjectV1::CanonicalTree(digest.clone()),
                "the verified canonical tree is not retained by current authority",
            );
        }

        self.validate_ownership(config, store, &selected);
        if self.request.observes_targets() {
            self.observe_selected_targets(config, store, &selected, canonical);
        }
        Ok(())
    }

    fn collect_retention_roots(
        &mut self,
        authority: &malm_store::RetentionAuthorityV1,
        generations: &BTreeMap<Digest, StateGenerationV1>,
        roots: &mut FsckAuthorityRoots,
    ) {
        for point in authority.restore_points() {
            self.collect_restore_point_root(point, generations, roots);
        }
        for pin in authority.explicit_pins() {
            match pin {
                RetentionObjectV1::PreparedPlan { plan_id } => {
                    roots.plans.insert(plan_id.clone());
                }
                RetentionObjectV1::StateGeneration { digest } => {
                    roots.generations.push(FsckGenerationRoot {
                        digest: digest.clone(),
                        limit: 1,
                        namespace: None,
                    });
                }
                RetentionObjectV1::ArtifactBlob { digest } => {
                    roots.blobs.insert(digest.clone());
                }
                RetentionObjectV1::PackObject { digest } => {
                    roots.packs.insert(digest.clone());
                }
                RetentionObjectV1::CanonicalFile { digest } => {
                    roots.files.insert(digest.clone());
                }
                RetentionObjectV1::CanonicalSymlink { digest } => {
                    roots.symlinks.insert(digest.clone());
                }
                RetentionObjectV1::CanonicalTree { digest } => {
                    roots.trees.insert(digest.clone());
                }
            }
        }
    }

    fn collect_restore_point_root(
        &mut self,
        point: &RestorePointV1,
        generations: &BTreeMap<Digest, StateGenerationV1>,
        roots: &mut FsckAuthorityRoots,
    ) {
        match generations.get(point.generation()) {
            Some(generation)
                if validate_restore_point_reference(point, point.generation(), generation)
                    .is_ok() =>
            {
                roots.generations.push(FsckGenerationRoot {
                    digest: point.generation().clone(),
                    limit: 1,
                    namespace: Some(point.namespace().clone()),
                });
            }
            Some(_) => self.error(
                FsckFindingCodeV1::InvalidGeneration,
                FsckSubjectV1::Retention,
                "a restore point differs from its retained generation",
            ),
            None => self.error(
                FsckFindingCodeV1::MissingGeneration,
                FsckSubjectV1::Generation(point.generation().clone()),
                "a restore point references a missing or invalid generation",
            ),
        }
    }

    fn validate_journal_authority(
        &mut self,
        store: &StoreHandles,
        world: FsckWorld<'_>,
        roots: &mut FsckAuthorityRoots,
    ) -> Result<(), CommitError> {
        let FsckWorld {
            catalog,
            journal: loaded,
            prepared,
            generations,
            ..
        } = world;
        let Some(loaded) = loaded else {
            if let Some(state) = &store.state
                && statat(state, ".catalog.json.new", AtFlags::SYMLINK_NOFOLLOW).is_ok()
            {
                self.error(
                    FsckFindingCodeV1::InvalidStaging,
                    FsckSubjectV1::CatalogStaging,
                    "catalog staging exists without a valid transaction journal",
                );
            }
            return Ok(());
        };
        let journal = &loaded.journal;
        roots.plans.insert(journal.plan_id.clone());
        if let Some(previous) = &journal.previous_generation {
            roots.generations.push(FsckGenerationRoot {
                digest: previous.clone(),
                limit: 1,
                namespace: Some(journal.namespace.clone()),
            });
        }
        if let Some(next) = &journal.next_generation
            && generations.contains_key(next)
        {
            roots.generations.push(FsckGenerationRoot {
                digest: next.clone(),
                limit: 1,
                namespace: Some(journal.namespace.clone()),
            });
        }
        let Some(record) = prepared.get(&journal.plan_id) else {
            self.error(
                FsckFindingCodeV1::MissingPreparedPlan,
                FsckSubjectV1::PreparedPlan(journal.plan_id.clone()),
                "the current journal references a missing or invalid prepared plan",
            );
            return Ok(());
        };
        for result in [
            validate_journal(store, record, journal).map(drop),
            catalog
                .map(|catalog| validate_journal_catalog_transition(catalog, journal).map(drop))
                .unwrap_or_else(|| {
                    Err(CommitError::InvalidJournal(
                        "the journal cannot be related to a missing catalog".to_owned(),
                    ))
                }),
            super::validate_catalog_staging(store, journal),
        ] {
            match result {
                Ok(()) => {}
                Err(error @ CommitError::Io { .. }) => return Err(error),
                Err(_) => self.error(
                    FsckFindingCodeV1::InvalidJournal,
                    FsckSubjectV1::Journal,
                    "the journal, catalog, plan, generation, or staging identities disagree",
                ),
            }
        }
        Ok(())
    }

    fn walk_generation_root(
        &mut self,
        root: &FsckGenerationRoot,
        prepared: &BTreeMap<PreparedId, malm_store::PreparedRecordV1>,
        generations: &BTreeMap<Digest, StateGenerationV1>,
        generation_namespaces: &mut BTreeMap<Digest, NamespaceName>,
        reachable: &mut BTreeSet<Digest>,
    ) {
        let mut current = Some(root.digest.clone());
        let mut namespace = root.namespace.clone();
        let mut lineage = BTreeSet::new();
        for index in 0..root.limit {
            let Some(digest) = current else {
                break;
            };
            if !lineage.insert(digest.clone()) {
                self.error(
                    FsckFindingCodeV1::CyclicHistory,
                    namespace
                        .clone()
                        .map_or(FsckSubjectV1::Generation(digest), FsckSubjectV1::Namespace),
                    "a retained generation predecessor chain contains a cycle",
                );
                break;
            }
            let Some(generation) = generations.get(&digest) else {
                self.error(
                    FsckFindingCodeV1::MissingGeneration,
                    FsckSubjectV1::Generation(digest),
                    "retention authority references a missing or invalid generation",
                );
                break;
            };
            let expected_namespace =
                namespace.get_or_insert_with(|| generation.namespace().clone());
            if generation.namespace() != expected_namespace {
                self.error(
                    FsckFindingCodeV1::CrossNamespaceHistory,
                    FsckSubjectV1::Generation(digest.clone()),
                    "a retained history enters a generation for another namespace",
                );
                break;
            }
            if let Some(first) =
                generation_namespaces.insert(digest.clone(), expected_namespace.clone())
                && first != *expected_namespace
            {
                self.error(
                    FsckFindingCodeV1::SharedGeneration,
                    FsckSubjectV1::Generation(digest.clone()),
                    "one generation is retained by different namespace histories",
                );
            }
            reachable.insert(digest.clone());
            let at_floor = index + 1 == root.limit;
            self.validate_generation_transition_record(
                &digest,
                generation,
                at_floor,
                prepared,
                generations,
            );
            if at_floor {
                break;
            }
            current = generation.previous_generation().cloned();
        }
    }

    fn validate_generation_transition_record(
        &mut self,
        digest: &Digest,
        generation: &StateGenerationV1,
        at_retained_floor: bool,
        prepared: &BTreeMap<PreparedId, malm_store::PreparedRecordV1>,
        generations: &BTreeMap<Digest, StateGenerationV1>,
    ) {
        let Some(record) = prepared.get(generation.plan_id()) else {
            self.error(
                FsckFindingCodeV1::MissingPreparedPlan,
                FsckSubjectV1::PreparedPlan(generation.plan_id().clone()),
                "a retained generation references a missing or invalid prepared plan",
            );
            return;
        };
        let rebuilt = if at_retained_floor {
            StateGenerationV1::from_retained_prepared(
                generation.plan_id().clone(),
                generation.previous_generation().cloned(),
                record,
            )
        } else {
            let previous = generation
                .previous_generation()
                .and_then(|previous| generations.get(previous));
            if generation.previous_generation().is_some() && previous.is_none() {
                self.error(
                    FsckFindingCodeV1::MissingGeneration,
                    FsckSubjectV1::Generation(
                        generation
                            .previous_generation()
                            .expect("missing predecessor has an identity")
                            .clone(),
                    ),
                    "a retained history edge points to a missing or invalid predecessor",
                );
                return;
            }
            StateGenerationV1::from_prepared(
                generation.plan_id().clone(),
                generation.previous_generation().cloned(),
                previous,
                record,
            )
        };
        if rebuilt.as_ref() != Ok(generation) {
            self.error(
                FsckFindingCodeV1::InvalidPreparedTransition,
                FsckSubjectV1::Generation(digest.clone()),
                "the generation is not the exact transition derived from its prepared plan",
            );
        }
    }

    fn validate_unreachable_generation(
        &mut self,
        digest: &Digest,
        generation: &StateGenerationV1,
        prepared: &BTreeMap<PreparedId, malm_store::PreparedRecordV1>,
        generations: &BTreeMap<Digest, StateGenerationV1>,
    ) {
        let Some(record) = prepared.get(generation.plan_id()) else {
            self.error(
                FsckFindingCodeV1::MissingPreparedPlan,
                FsckSubjectV1::PreparedPlan(generation.plan_id().clone()),
                "an unretained generation references a missing or invalid prepared plan",
            );
            return;
        };
        let previous = generation
            .previous_generation()
            .and_then(|previous| generations.get(previous));
        let rebuilt = if generation.previous_generation().is_some() && previous.is_none() {
            StateGenerationV1::from_retained_prepared(
                generation.plan_id().clone(),
                generation.previous_generation().cloned(),
                record,
            )
        } else {
            StateGenerationV1::from_prepared(
                generation.plan_id().clone(),
                generation.previous_generation().cloned(),
                previous,
                record,
            )
        };
        if rebuilt.as_ref() != Ok(generation) {
            self.error(
                FsckFindingCodeV1::InvalidPreparedTransition,
                FsckSubjectV1::Generation(digest.clone()),
                "the unretained generation differs from its immutable prepared authority",
            );
        }
    }

    fn validate_blob_roots(
        &mut self,
        retained: &BTreeSet<Digest>,
        lengths: &BTreeMap<Digest, BTreeSet<u64>>,
        blobs: &BTreeMap<Digest, u64>,
    ) {
        for digest in retained {
            let Some(actual) = blobs.get(digest) else {
                self.error(
                    FsckFindingCodeV1::MissingArtifactBlob,
                    FsckSubjectV1::ArtifactBlob(digest.clone()),
                    "retained authority references a missing or invalid artifact blob",
                );
                continue;
            };
            if let Some(expected) = lengths.get(digest)
                && (expected.len() != 1 || expected.first() != Some(actual))
            {
                self.error(
                    FsckFindingCodeV1::ArtifactLengthMismatch,
                    FsckSubjectV1::ArtifactBlob(digest.clone()),
                    "retained records assign conflicting or incorrect artifact lengths",
                );
            }
        }
    }

    fn validate_pack_roots(&mut self, retained: &BTreeSet<Digest>, packs: &BTreeSet<Digest>) {
        for digest in retained {
            if !packs.contains(digest) {
                self.error(
                    FsckFindingCodeV1::MissingPackObject,
                    FsckSubjectV1::PackObject(digest.clone()),
                    "retained authority references a missing or invalid pack object",
                );
            }
        }
    }

    fn validate_canonical_roots(
        &mut self,
        roots: &FsckAuthorityRoots,
        objects: &super::canonical::CanonicalObjects,
    ) -> (BTreeSet<Digest>, BTreeSet<Digest>, BTreeSet<Digest>) {
        let mut files = roots.files.clone();
        let mut symlinks = roots.symlinks.clone();
        let mut trees = BTreeSet::new();
        for digest in &roots.files {
            if !objects.files.contains_key(digest) {
                self.error(
                    FsckFindingCodeV1::MissingCanonicalObject,
                    FsckSubjectV1::CanonicalFile(digest.clone()),
                    "retention authority references a missing or invalid canonical file",
                );
            }
        }
        for digest in &roots.symlinks {
            match objects.safe_symlink_target(digest) {
                Ok(_) => {}
                Err(_) if !objects.symlinks.contains_key(digest) => self.error(
                    FsckFindingCodeV1::MissingCanonicalObject,
                    FsckSubjectV1::CanonicalSymlink(digest.clone()),
                    "retention authority references a missing or invalid canonical symlink",
                ),
                Err(_) => self.error(
                    FsckFindingCodeV1::CorruptCanonicalObject,
                    FsckSubjectV1::CanonicalSymlink(digest.clone()),
                    "a retained canonical symlink has an unsafe target",
                ),
            }
        }
        for root in &roots.trees {
            let complete =
                self.mark_canonical_tree(root, objects, &mut files, &mut symlinks, &mut trees);
            if complete && objects.validate_tree(root).is_err() {
                self.error(
                    FsckFindingCodeV1::CorruptCanonicalObject,
                    FsckSubjectV1::CanonicalTree(root.clone()),
                    "a retained canonical tree graph is cyclic, unsafe, or inconsistent",
                );
            }
        }
        (files, symlinks, trees)
    }

    fn mark_canonical_tree(
        &mut self,
        digest: &Digest,
        objects: &super::canonical::CanonicalObjects,
        files: &mut BTreeSet<Digest>,
        symlinks: &mut BTreeSet<Digest>,
        trees: &mut BTreeSet<Digest>,
    ) -> bool {
        let mut pending = vec![digest.clone()];
        let mut complete = true;
        while let Some(digest) = pending.pop() {
            if !trees.insert(digest.clone()) {
                continue;
            }
            let Some(tree) = objects.trees.get(&digest) else {
                complete = false;
                self.error(
                    FsckFindingCodeV1::MissingCanonicalObject,
                    FsckSubjectV1::CanonicalTree(digest),
                    "retained authority references a missing or invalid canonical tree",
                );
                continue;
            };
            for entry in &tree.entries {
                match &entry.kind {
                    super::canonical::TreeEntryKind::File { digest, byte_len } => {
                        files.insert(digest.clone());
                        match objects.files.get(digest) {
                            Some(bytes) if u64::try_from(bytes.len()).ok() == Some(*byte_len) => {}
                            Some(_) => {
                                complete = false;
                                self.error(
                                    FsckFindingCodeV1::CorruptCanonicalObject,
                                    FsckSubjectV1::CanonicalFile(digest.clone()),
                                    "a canonical tree assigns an incorrect file length",
                                );
                            }
                            None => {
                                complete = false;
                                self.error(
                                    FsckFindingCodeV1::MissingCanonicalObject,
                                    FsckSubjectV1::CanonicalFile(digest.clone()),
                                    "a retained canonical tree references a missing or invalid file",
                                );
                            }
                        }
                    }
                    super::canonical::TreeEntryKind::Directory { digest } => {
                        pending.push(digest.clone());
                    }
                    super::canonical::TreeEntryKind::Symlink { digest } => {
                        symlinks.insert(digest.clone());
                        if !objects.symlinks.contains_key(digest) {
                            complete = false;
                            self.error(
                                FsckFindingCodeV1::MissingCanonicalObject,
                                FsckSubjectV1::CanonicalSymlink(digest.clone()),
                                "a retained canonical tree references a missing or invalid symlink",
                            );
                        }
                    }
                }
            }
        }
        complete
    }

    fn validate_ownership(
        &mut self,
        config: &CommitConfig,
        store: &StoreHandles,
        selected: &[(NamespaceName, StateGenerationV1)],
    ) {
        let projection = OwnershipProjectionV1::from_selected_generations(
            selected
                .iter()
                .map(|(namespace, generation)| (namespace, generation)),
        );
        let valid = projection.is_ok_and(|projection| {
            reject_projection_authority_aliases(config, store, &projection, None, true).is_ok()
        });
        if !valid {
            self.error(
                FsckFindingCodeV1::InvalidOwnership,
                FsckSubjectV1::Ownership,
                "catalog-selected snapshots cannot form one safe ownership projection",
            );
        }
    }

    fn observe_selected_targets(
        &mut self,
        config: &CommitConfig,
        store: &StoreHandles,
        selected: &[(NamespaceName, StateGenerationV1)],
        canonical: &super::canonical::CanonicalObjects,
    ) {
        for (_, generation) in selected {
            for target in generation.targets() {
                if usize::try_from(self.checked_targets).unwrap_or(usize::MAX)
                    == self.request.max_target_observations()
                {
                    self.error(
                        FsckFindingCodeV1::TraversalLimitExceeded,
                        FsckSubjectV1::Coverage,
                        "managed-target observations exceed the requested target limit",
                    );
                    return;
                }
                self.checked_targets += 1;
                let subject = FsckSubjectV1::Target {
                    authority: target.authority().clone(),
                    relative_path: target.relative_path().to_owned(),
                };
                match observe_status_target(
                    config,
                    store,
                    target,
                    canonical,
                    &mut self.observed_bytes,
                    self.request.max_observed_bytes(),
                ) {
                    Ok(TargetStatusKindV1::Exact) => {}
                    Ok(_) => self.warning(
                        FsckFindingCodeV1::TargetDrift,
                        subject,
                        "the managed target differs from the catalog-selected desired snapshot",
                    ),
                    Err(_) => {
                        self.coverage_gap();
                        self.warning(
                            FsckFindingCodeV1::TargetObservationFailed,
                            subject,
                            "the managed target could not be safely and completely observed",
                        );
                    }
                }
            }
        }
    }

    fn finish(self) -> FsckReportV1 {
        let count = |entries: usize| malm_types::usize_to_u64(entries);
        FsckReportV1::from(FsckReportPartsV1 {
            findings: self.findings,
            checked_generations: count(self.checked_generations.len()),
            checked_prepared_plans: count(self.checked_prepared.len()),
            checked_artifact_blobs: count(self.checked_blobs.len()),
            checked_pack_objects: count(self.checked_packs.len()),
            checked_canonical_files: count(self.checked_files.len()),
            checked_canonical_symlinks: count(self.checked_symlinks.len()),
            checked_canonical_trees: count(self.checked_trees.len()),
            checked_targets: self.checked_targets,
            decoded_bytes: self.decoded_bytes,
            observed_bytes: self.observed_bytes,
            findings_truncated: self.findings_truncated,
            complete: self.complete,
        })
    }
}

fn journal_fingerprint(
    loaded: Option<&super::LoadedJournalV1>,
) -> Option<(Digest, super::StagedJournalUpdate)> {
    loaded.map(|loaded| {
        (
            Digest::sha256(super::canonical_journal(&loaded.journal)),
            loaded.staged_update,
        )
    })
}

fn record_prepared_dependencies(
    record: &malm_store::PreparedRecordV1,
    roots: &mut FsckAuthorityRoots,
    lengths: &mut BTreeMap<Digest, BTreeSet<u64>>,
) {
    for artifact in record.artifacts() {
        roots.blobs.insert(artifact.digest().clone());
        lengths
            .entry(artifact.digest().clone())
            .or_default()
            .insert(artifact.byte_len());
    }
    roots.packs.extend(record_pack_roots(record));
    for target in record.desired_snapshot().targets() {
        record_state_dependencies(target.state(), roots, lengths);
    }
    if let Some(tracked) = record.tracked_root() {
        roots.trees.insert(tracked.root_tree_digest().clone());
    }
}

fn record_generation_dependencies(
    generation: &StateGenerationV1,
    roots: &mut FsckAuthorityRoots,
    lengths: &mut BTreeMap<Digest, BTreeSet<u64>>,
) {
    roots.blobs.extend(
        generation
            .artifacts()
            .iter()
            .map(|artifact| artifact.digest().clone()),
    );
    for target in generation.targets() {
        record_state_dependencies(target.state(), roots, lengths);
    }
    if let Some(tracked) = generation.tracked_root() {
        roots.trees.insert(tracked.root_tree_digest().clone());
    }
}

fn record_state_dependencies(
    state: &StateTargetStateV1,
    roots: &mut FsckAuthorityRoots,
    lengths: &mut BTreeMap<Digest, BTreeSet<u64>>,
) {
    match state {
        StateTargetStateV1::File { file: Some(file) } => {
            roots.blobs.insert(file.digest().clone());
            lengths
                .entry(file.digest().clone())
                .or_default()
                .insert(file.byte_len());
        }
        StateTargetStateV1::Symlink {
            symlink: Some(symlink),
        } => {
            roots.symlinks.insert(symlink.object().clone());
        }
        StateTargetStateV1::Tree { tree: Some(tree) } => {
            roots.trees.insert(tree.tree().clone());
        }
        StateTargetStateV1::File { file: None }
        | StateTargetStateV1::Directory { .. }
        | StateTargetStateV1::Symlink { symlink: None }
        | StateTargetStateV1::Tree { tree: None } => {}
    }
}

fn incompatible_status(
    request: &NamespaceStatusRequestV1,
    head: Option<Digest>,
    lifecycle: Option<LifecycleStateViewV1>,
    desired_snapshot_digest: Option<Digest>,
) -> NamespaceStatusV1 {
    NamespaceStatusV1::from(NamespaceStatusPartsV1 {
        namespace: request.namespace().clone(),
        head,
        lifecycle,
        desired_snapshot_digest,
        status: NamespaceStatusKindV1::IncompatibleOrCorrupt,
        targets: Vec::new(),
        observed_bytes: 0,
        detail: Some("selected state cannot be safely and completely inspected".to_owned()),
    })
}

fn finish_status_snapshot(
    store: &StoreHandles,
    before: &StoreDirectorySnapshot,
    catalog_bytes: Option<&[u8]>,
    journal_before: Option<(Digest, super::StagedJournalUpdate)>,
    result: NamespaceStatusV1,
) -> Result<NamespaceStatusV1, CommitError> {
    commit_failpoint!("v1.status.before_authority_revalidation");
    let changed = require_directory_snapshot(store, before).is_err()
        || catalog_bytes.is_some_and(|expected| {
            load_catalog_record_with_bytes(store)
                .map(|(_, current)| current != expected)
                .unwrap_or(true)
        })
        || load_journal(store)
            .map(|current| journal_fingerprint(current.as_ref()) != journal_before)
            .unwrap_or(true)
        || store.revalidate().is_err();
    if !changed {
        return Ok(result);
    }
    let targets = result
        .targets()
        .iter()
        .map(|target| {
            TargetStatusV1::new(
                target.authority().clone(),
                target.relative_path().to_owned(),
                TargetStatusKindV1::Stale,
            )
        })
        .collect();
    Ok(NamespaceStatusV1::from(NamespaceStatusPartsV1 {
        namespace: result.namespace().clone(),
        head: result.head().cloned(),
        lifecycle: result.lifecycle(),
        desired_snapshot_digest: result.desired_snapshot_digest().cloned(),
        status: NamespaceStatusKindV1::Stale,
        targets,
        observed_bytes: result.observed_bytes(),
        detail: Some("store authority changed during the status observation".to_owned()),
    }))
}

fn aggregate_target_status(targets: &[TargetStatusV1]) -> NamespaceStatusKindV1 {
    if targets
        .iter()
        .any(|target| target.status() == TargetStatusKindV1::Stale)
    {
        NamespaceStatusKindV1::Stale
    } else if targets
        .iter()
        .any(|target| target.status() == TargetStatusKindV1::Incompatible)
    {
        NamespaceStatusKindV1::IncompatibleOrCorrupt
    } else if targets
        .iter()
        .any(|target| target.status() == TargetStatusKindV1::Unexpected)
    {
        NamespaceStatusKindV1::EnabledUnexpected
    } else if targets
        .iter()
        .any(|target| target.status() == TargetStatusKindV1::Modified)
    {
        NamespaceStatusKindV1::EnabledModified
    } else if targets
        .iter()
        .any(|target| target.status() == TargetStatusKindV1::Missing)
    {
        NamespaceStatusKindV1::EnabledMissing
    } else {
        NamespaceStatusKindV1::EnabledExact
    }
}

fn observe_status_target(
    config: &CommitConfig,
    store: &StoreHandles,
    target: &StateTargetV1,
    canonical: &super::canonical::CanonicalObjects,
    observed_bytes: &mut u64,
    max_observed_bytes: u64,
) -> Result<TargetStatusKindV1, CommitError> {
    let authority_path = config
        .target_authorities
        .get(target.authority())
        .ok_or_else(|| CommitError::UnknownTargetAuthority(target.authority().clone()))?;
    let absolute = authority_path.join(target.relative_path());
    if super::overlaps(&absolute, &config.state_root) {
        return Err(CommitError::UnsafeTarget(
            "status target enters protected state".to_owned(),
        ));
    }
    let chain = PinnedChain::open(authority_path)?;
    validate_target_directory(chain.directory(), authority_path, config.effective_user_id)?;
    reject_protected_traversal_directory(store, chain.directory(), authority_path)?;
    let segments = target.relative_path().split('/').collect::<Vec<_>>();
    let mut parent = chain
        .directory()
        .try_clone()
        .map_err(|source| CommitError::Io {
            operation: "clone status target anchor",
            path: authority_path.clone(),
            source,
        })?;
    for (position, segment) in segments[..segments.len() - 1].iter().enumerate() {
        let path = authority_path.join(segments[..=position].join("/"));
        parent = match openat2(
            &parent,
            *segment,
            DIRECTORY_FLAGS | OFlags::NOFOLLOW | OFlags::NOATIME,
            Mode::empty(),
            ROOT_RESOLVE_FLAGS,
        ) {
            Ok(next) => File::from(next),
            Err(rustix::io::Errno::NOENT) => {
                chain.ensure_bound(authority_path)?;
                store.revalidate()?;
                return Ok(if target.is_present() {
                    TargetStatusKindV1::Missing
                } else {
                    TargetStatusKindV1::Exact
                });
            }
            Err(source) => return Err(io_error("open status target ancestor", &path, source)),
        };
        validate_target_directory(&parent, &path, config.effective_user_id)?;
        reject_protected_traversal_directory(store, &parent, &path)?;
    }
    let leaf = segments.last().expect("validated target path has a leaf");
    let stat = match statat(&parent, *leaf, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(stat) => Some(stat),
        Err(rustix::io::Errno::NOENT) => None,
        Err(source) => return Err(io_error("inspect status target leaf", &absolute, source)),
    };
    if let Some(actual) = stat.as_ref() {
        prove_safe_existing_directory_leaf(
            store,
            &parent,
            std::ffi::OsStr::new(*leaf),
            &absolute,
            actual,
        )?;
    }
    let status = match (target.state(), stat.as_ref()) {
        (StateTargetStateV1::File { file: None }, None)
        | (StateTargetStateV1::Directory { directory: None }, None)
        | (StateTargetStateV1::Symlink { symlink: None }, None)
        | (StateTargetStateV1::Tree { tree: None }, None) => TargetStatusKindV1::Exact,
        (StateTargetStateV1::File { file: None }, Some(_))
        | (StateTargetStateV1::Directory { directory: None }, Some(_))
        | (StateTargetStateV1::Symlink { symlink: None }, Some(_))
        | (StateTargetStateV1::Tree { tree: None }, Some(_)) => TargetStatusKindV1::Unexpected,
        (StateTargetStateV1::File { file: Some(_) }, None)
        | (StateTargetStateV1::Directory { directory: Some(_) }, None)
        | (StateTargetStateV1::Symlink { symlink: Some(_) }, None)
        | (StateTargetStateV1::Tree { tree: Some(_) }, None) => TargetStatusKindV1::Missing,
        (
            StateTargetStateV1::Directory {
                directory: Some(expected),
            },
            Some(actual),
        ) => {
            if FileType::from_raw_mode(actual.st_mode) != FileType::Directory
                || actual.st_uid != config.effective_user_id
                || actual.st_mode & 0o7777 != expected.mode()
            {
                TargetStatusKindV1::Modified
            } else {
                let directory = openat2(
                    &parent,
                    *leaf,
                    DIRECTORY_FLAGS | OFlags::NOFOLLOW | OFlags::NOATIME,
                    Mode::empty(),
                    ROOT_RESOLVE_FLAGS,
                )
                .map(File::from)
                .map_err(|source| io_error("open status target directory", &absolute, source))?;
                let opened = fstat(&directory).map_err(|source| {
                    io_error("inspect status target directory", &absolute, source)
                })?;
                if !same_snapshot(actual, &opened) {
                    return Err(CommitError::StaleTarget(
                        "status target changed while opening".to_owned(),
                    ));
                }
                let final_stat = require_pinned_entry(
                    &parent,
                    std::ffi::OsStr::new(*leaf),
                    &directory,
                    &absolute,
                    "status target directory",
                )?;
                if !same_snapshot(&opened, &final_stat) {
                    return Err(CommitError::StaleTarget(
                        "status target directory changed during verification".to_owned(),
                    ));
                }
                TargetStatusKindV1::Exact
            }
        }
        (
            StateTargetStateV1::File {
                file: Some(expected),
            },
            Some(actual),
        ) => {
            if FileType::from_raw_mode(actual.st_mode) != FileType::RegularFile
                || actual.st_uid != config.effective_user_id
                || actual.st_nlink != 1
                || actual.st_mode & 0o7777 != expected.mode()
                || u64::try_from(actual.st_size).unwrap_or(u64::MAX) != expected.byte_len()
            {
                TargetStatusKindV1::Modified
            } else {
                let next_bytes =
                    observed_bytes
                        .checked_add(expected.byte_len())
                        .ok_or_else(|| {
                            CommitError::InvalidStore(
                                "status byte accounting overflowed".to_owned(),
                            )
                        })?;
                if next_bytes > max_observed_bytes {
                    return Err(CommitError::InvalidStore(
                        "status target hashing exceeds its byte limit".to_owned(),
                    ));
                }
                let file = openat2(
                    &parent,
                    *leaf,
                    OFlags::RDONLY
                        | OFlags::NONBLOCK
                        | OFlags::NOFOLLOW
                        | OFlags::NOATIME
                        | OFlags::CLOEXEC,
                    Mode::empty(),
                    ROOT_RESOLVE_FLAGS,
                )
                .map(File::from)
                .map_err(|source| io_error("open status target file", &absolute, source))?;
                let opened = fstat(&file)
                    .map_err(|source| io_error("inspect status target file", &absolute, source))?;
                if !same_snapshot(actual, &opened) {
                    return Err(CommitError::StaleTarget(
                        "status target changed while opening".to_owned(),
                    ));
                }
                let (digest, hashed) = stable_file_digest(&file, &absolute, "status target")?;
                let rebound =
                    statat(&parent, *leaf, AtFlags::SYMLINK_NOFOLLOW).map_err(|source| {
                        io_error("revalidate status target file", &absolute, source)
                    })?;
                if !same_snapshot(&opened, &hashed) || !same_snapshot(&rebound, &hashed) {
                    return Err(CommitError::StaleTarget(
                        "status target changed while hashing".to_owned(),
                    ));
                }
                *observed_bytes = next_bytes;
                if source_digest_matches(digest, expected.digest()) {
                    TargetStatusKindV1::Exact
                } else {
                    TargetStatusKindV1::Modified
                }
            }
        }
        (StateTargetStateV1::Symlink { symlink: Some(_) }, Some(_)) => {
            match require_target_state(
                &parent,
                std::ffi::OsStr::new(*leaf),
                target.state(),
                canonical,
                config.effective_user_id,
                &absolute,
            ) {
                Ok(()) => TargetStatusKindV1::Exact,
                Err(CommitError::StaleTarget(_) | CommitError::InvalidJournal(_)) => {
                    TargetStatusKindV1::Modified
                }
                Err(error) => return Err(error),
            }
        }
        (StateTargetStateV1::Tree { tree: Some(tree) }, Some(_)) => {
            let tree_bytes = canonical
                .tree_file_bytes(tree.tree())
                .map_err(CommitError::invalid_store)?;
            let next_bytes = observed_bytes.checked_add(tree_bytes).ok_or_else(|| {
                CommitError::InvalidStore("status byte accounting overflowed".to_owned())
            })?;
            if next_bytes > max_observed_bytes {
                return Err(CommitError::InvalidStore(
                    "status target hashing exceeds its byte limit".to_owned(),
                ));
            }
            match require_target_state(
                &parent,
                std::ffi::OsStr::new(*leaf),
                target.state(),
                canonical,
                config.effective_user_id,
                &absolute,
            ) {
                Ok(()) => {
                    *observed_bytes = next_bytes;
                    TargetStatusKindV1::Exact
                }
                Err(CommitError::StaleTarget(_) | CommitError::InvalidJournal(_)) => {
                    TargetStatusKindV1::Modified
                }
                Err(error) => return Err(error),
            }
        }
    };
    chain.ensure_bound(authority_path)?;
    store.revalidate()?;
    Ok(status)
}
