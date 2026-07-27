//! Pins, updates, verifies, and recovers individual commit targets.

use std::{
    collections::BTreeMap,
    ffi::{OsStr, OsString},
    fs::File,
    io::Write,
    path::{Path, PathBuf},
    sync::Arc,
};

use malm_store::{
    FileIdentityV1, LeafObservationV1, PreparedOperationV1, StateTargetStateV1, TargetObservationV1,
};
use malm_types::{DeploymentName, PreparedId};
use rustix::fs::{
    AtFlags, FileType, Mode, OFlags, RenameFlags, fchmod, fstat, fsync, linkat, mkdirat, openat,
    openat2, renameat_with, statat, symlinkat,
};

use crate::canonical;
use crate::object_load::invalid_canonical_object;
use crate::path_safety::{
    PinnedChain, io_error, overlaps, prove_safe_existing_directory_leaf,
    reject_protected_traversal_directory, same_object,
};
use crate::{
    BackupExpectation, CommitConfig, CommitError, DIRECTORY_FLAGS, JournalBackupV1,
    JournalOperationV1, LoadedArtifacts, ObservedFileV1, ObservedScope, OperationSlot,
    PinnedPreparedSource, PublishContext, QuarantineEntry, ROOT_RESOLVE_FLAGS, SourceDigestV1,
    StoreHandles, TransactionJournalV1, backup_source_digest, compare_created_identity,
    compare_identity, compare_identity_for_mode, compare_journaled_backup, compare_leaf,
    compare_object_identity, compare_relocated_identity, conflicting_target_observation,
    entry_stat, file_identity, is_directory_identity, journaled_backup_identity,
    journaled_backup_source_digest, materialize_tree_directory, observed_proves_state,
    pin_prepared_source, quarantine_and_remove_prior_entry, quarantine_and_remove_tree_entry,
    quarantine_and_unlink_created_entry, quarantine_and_unlink_entry, removal_flags,
    remove_partial_tree_directory, replace_journal, require_empty_directory_entry,
    require_entry_absent, require_entry_identity, require_leaf_bytes, require_managed_directory,
    require_pinned_entry, require_prior_removal_state, require_relocated_pinned_entry,
    require_symlink_target, require_target_state, require_tree_directory, require_tree_entry,
    require_tree_entry_observed, restore_pinned_backup, restore_raced_staging,
    same_created_identity, same_relocated_identity, unlink_pinned_entry, validate_target_directory,
    verify_adopted_backup, verify_entry_source_digest, verify_relocated_source,
};

#[derive(Default)]
pub(crate) struct CommitPinCache {
    authorities: BTreeMap<DeploymentName, CachedTargetAuthority>,
}

pub(crate) struct CachedTargetAuthority {
    path: PathBuf,
    traversal_anchor: FileIdentityV1,
    chain: Arc<PinnedChain>,
    prefixes: BTreeMap<String, CachedTargetDirectory>,
}

pub(crate) struct CachedTargetDirectory {
    observation: FileIdentityV1,
    handle: Arc<File>,
}

pub(crate) struct TargetPins {
    chain: Arc<PinnedChain>,
    root: Arc<File>,
    ancestors: Vec<(OsString, Arc<File>)>,
    parent: Arc<File>,
    /// Parent segments that the plan must create before this target can be
    /// reached. Until then, `parent` pins the deepest existing directory.
    pending: Vec<OsString>,
    /// Authority-relative paths corresponding to `pending`.
    pending_prefixes: Vec<String>,
    /// Object identity of the directory pinned by `parent`.
    parent_object: FileIdentityV1,
}

/// Created directory identities taken from the journal. During recovery, a
/// pending ancestor is accepted only when its authority, path, and identity
/// match an entry in this map.
pub(crate) type CreatedDirectories = BTreeMap<(DeploymentName, String), FileIdentityV1>;

impl CommitPinCache {
    pub(crate) fn pin_target(
        &mut self,
        config: &CommitConfig,
        store: &StoreHandles,
        authority_path: &Path,
        observation: &TargetObservationV1,
        recovery: bool,
        created_directories: Option<&CreatedDirectories>,
    ) -> Result<TargetPins, CommitError> {
        let segments = observation.relative_path().split('/').collect::<Vec<_>>();
        let parent_segments = &segments[..segments.len() - 1];
        let missing = usize::try_from(observation.missing_ancestors())
            .map_err(|_| CommitError::InvalidPlan("missing ancestor count overflows".to_owned()))?;
        if missing > parent_segments.len()
            || (missing > 0 && !matches!(observation.leaf(), LeafObservationV1::Absent))
        {
            return Err(CommitError::InvalidPlan(
                "target missing-ancestor observation is inconsistent".to_owned(),
            ));
        }
        let existing_segments = &parent_segments[..parent_segments.len() - missing];
        if observation.ancestors().len() != existing_segments.len().saturating_sub(1) {
            return Err(CommitError::InvalidPlan(
                "target ancestor count is inconsistent".to_owned(),
            ));
        }

        if !self.authorities.contains_key(observation.authority()) {
            let chain = Arc::new(PinnedChain::open(authority_path)?);
            validate_target_directory(chain.directory(), authority_path, config.effective_user_id)?;
            compare_identity_for_mode(
                &fstat(chain.directory())
                    .map_err(|source| io_error("inspect target anchor", authority_path, source))?,
                observation.traversal_anchor(),
                "target traversal anchor",
                recovery,
            )?;
            reject_protected_traversal_directory(store, chain.directory(), authority_path)?;
            let root = openat2(
                chain.directory(),
                ".",
                DIRECTORY_FLAGS | OFlags::NOFOLLOW | OFlags::NOATIME,
                Mode::empty(),
                ROOT_RESOLVE_FLAGS,
            )
            .map(File::from)
            .map(Arc::new)
            .map_err(|source| {
                io_error("open target anchor for mutation", authority_path, source)
            })?;
            let mut prefixes = BTreeMap::new();
            prefixes.insert(
                String::new(),
                CachedTargetDirectory {
                    observation: observation.traversal_anchor(),
                    handle: root,
                },
            );
            self.authorities.insert(
                observation.authority().clone(),
                CachedTargetAuthority {
                    path: authority_path.to_path_buf(),
                    traversal_anchor: observation.traversal_anchor(),
                    chain,
                    prefixes,
                },
            );
        }

        let authority = self
            .authorities
            .get_mut(observation.authority())
            .expect("target authority was cached");
        if authority.path != authority_path
            || authority.traversal_anchor != observation.traversal_anchor()
        {
            return Err(conflicting_target_observation("authority"));
        }
        let root = authority
            .prefixes
            .get("")
            .expect("target authority root was cached");
        validate_target_directory(&root.handle, authority_path, config.effective_user_id)?;
        reject_protected_traversal_directory(store, &root.handle, authority_path)?;
        compare_identity_for_mode(
            &fstat(&root.handle)
                .map_err(|source| io_error("inspect target anchor", authority_path, source))?,
            observation.traversal_anchor(),
            "target traversal anchor",
            recovery,
        )?;

        let mut prefix = String::new();
        let mut ancestors = Vec::with_capacity(existing_segments.len());
        if existing_segments.is_empty() && root.observation != observation.parent() {
            return Err(conflicting_target_observation("ancestor"));
        }
        if existing_segments.is_empty() {
            compare_identity_for_mode(
                &fstat(&root.handle)
                    .map_err(|source| io_error("inspect target parent", authority_path, source))?,
                observation.parent(),
                "target parent",
                recovery,
            )?;
        }
        for (position, segment) in existing_segments.iter().enumerate() {
            let previous_prefix = prefix.clone();
            if !prefix.is_empty() {
                prefix.push('/');
            }
            prefix.push_str(segment);
            let expected = if position + 1 == existing_segments.len() {
                observation.parent()
            } else {
                observation.ancestors()[position]
            };
            let path = authority_path.join(&prefix);
            if !authority.prefixes.contains_key(&prefix) {
                let previous = authority
                    .prefixes
                    .get(&previous_prefix)
                    .expect("parent target prefix was cached");
                let handle = openat2(
                    &previous.handle,
                    *segment,
                    DIRECTORY_FLAGS | OFlags::NOFOLLOW | OFlags::NOATIME,
                    Mode::empty(),
                    ROOT_RESOLVE_FLAGS,
                )
                .map(File::from)
                .map(Arc::new)
                .map_err(|source| io_error("open target ancestor", &path, source))?;
                authority.prefixes.insert(
                    prefix.clone(),
                    CachedTargetDirectory {
                        observation: expected,
                        handle,
                    },
                );
            }
            let directory = authority
                .prefixes
                .get(&prefix)
                .expect("target prefix was cached");
            if directory.observation != expected {
                return Err(conflicting_target_observation("ancestor"));
            }
            validate_target_directory(&directory.handle, &path, config.effective_user_id)?;
            reject_protected_traversal_directory(store, &directory.handle, &path)?;
            compare_identity_for_mode(
                &fstat(&directory.handle)
                    .map_err(|source| io_error("inspect target ancestor", &path, source))?,
                expected,
                if position + 1 == existing_segments.len() {
                    "target parent"
                } else {
                    "target ancestor"
                },
                recovery,
            )?;
            ancestors.push((OsString::from(segment), Arc::clone(&directory.handle)));
        }
        let mut parent = if prefix.is_empty() {
            Arc::clone(
                &authority
                    .prefixes
                    .get("")
                    .expect("target authority root was cached")
                    .handle,
            )
        } else {
            Arc::clone(
                &authority
                    .prefixes
                    .get(&prefix)
                    .expect("target parent was cached")
                    .handle,
            )
        };
        let mut parent_object = observation.parent();
        let mut pending = Vec::with_capacity(missing);
        let mut pending_prefixes = Vec::with_capacity(missing);
        for segment in &parent_segments[existing_segments.len()..] {
            if !prefix.is_empty() {
                prefix.push('/');
            }
            prefix.push_str(segment);
            pending.push(OsString::from(segment));
            pending_prefixes.push(prefix.clone());
        }
        // A crashed commit may already have created some pending ancestors.
        // Recovery accepts one only if it matches the identity journaled by
        // this transaction; any other existing directory may be an external
        // replacement and is rejected. A missing directory remains pending.
        // Its dependent operation has not run and has an empty journal record,
        // so rollback has nothing to undo there.
        if recovery && !pending.is_empty() {
            let created_directories = created_directories.ok_or_else(|| {
                CommitError::InvalidPlan(
                    "recovery pinning requires the journaled directory identities".to_owned(),
                )
            })?;
            while !pending.is_empty() {
                let segment = &pending[0];
                let pending_prefix = &pending_prefixes[0];
                let path = authority_path.join(pending_prefix);
                let handle = match openat2(
                    &parent,
                    segment.as_os_str(),
                    DIRECTORY_FLAGS | OFlags::NOFOLLOW | OFlags::NOATIME,
                    Mode::empty(),
                    ROOT_RESOLVE_FLAGS,
                ) {
                    Ok(handle) => Arc::new(File::from(handle)),
                    Err(rustix::io::Errno::NOENT) => break,
                    Err(source) => {
                        return Err(io_error("open pending target ancestor", &path, source));
                    }
                };
                let stat = fstat(&handle)
                    .map_err(|source| io_error("inspect pending target ancestor", &path, source))?;
                let journaled = created_directories
                    .get(&(observation.authority().clone(), pending_prefix.clone()))
                    .ok_or_else(|| {
                        CommitError::StaleTarget(
                            "pending target ancestor was created externally".to_owned(),
                        )
                    })?;
                compare_created_identity(&stat, *journaled, "pending target ancestor")?;
                validate_target_directory(&handle, &path, config.effective_user_id)?;
                reject_protected_traversal_directory(store, &handle, &path)?;
                ancestors.push((segment.clone(), Arc::clone(&handle)));
                parent = handle;
                parent_object = file_identity(&stat);
                pending.remove(0);
                pending_prefixes.remove(0);
            }
        }
        Ok(TargetPins {
            chain: Arc::clone(&authority.chain),
            root: Arc::clone(
                &authority
                    .prefixes
                    .get("")
                    .expect("target authority root was cached")
                    .handle,
            ),
            ancestors,
            parent,
            pending,
            pending_prefixes,
            parent_object,
        })
    }
}

pub(crate) struct PinnedTarget {
    pub(crate) operation: PreparedOperationV1,
    prior_state: Option<StateTargetStateV1>,
    pub(crate) authority_path: PathBuf,
    parent_path: PathBuf,
    pub(crate) chain: Arc<PinnedChain>,
    root: Arc<File>,
    pub(crate) ancestors: Vec<(OsString, Arc<File>)>,
    pub(crate) parent: Arc<File>,
    pub(crate) leaf: OsString,
    plan_id: PreparedId,
    index: usize,
    pub(crate) uid: u32,
    pub(crate) expected_parent: FileIdentityV1,
    /// Object identity of `parent`, updated as pending ancestors are pinned.
    pub(crate) parent_object: FileIdentityV1,
    /// Parent segments that must be created and pinned before this target can
    /// be reached.
    pub(crate) pending: Vec<OsString>,
    /// Authority-relative paths corresponding to `pending`.
    pub(crate) pending_prefixes: Vec<String>,
    restored_race: Option<FileIdentityV1>,
    /// File prepared by phase A but not yet renamed into place.
    pub(crate) staged: Option<StagedFileV1>,
    /// Prior leaf pinned in phase B; its optional source digest becomes the
    /// journaled backup intent.
    pub(crate) pinned_source: Option<PinnedPreparedSource>,
}

pub(crate) struct StagedFileV1 {
    file: File,
    name: OsString,
    pub(crate) identity: FileIdentityV1,
}

impl PinnedTarget {
    pub(crate) fn open(
        cache: &mut CommitPinCache,
        config: &CommitConfig,
        store: &StoreHandles,
        plan_id: &PreparedId,
        index: usize,
        operation: PreparedOperationV1,
        prior_state: Option<StateTargetStateV1>,
    ) -> Result<Self, CommitError> {
        Self::open_inner(
            cache,
            config,
            store,
            OperationSlot {
                plan_id,
                index,
                operation,
                prior_state,
            },
            false,
            None,
        )
    }

    pub(crate) fn open_for_recovery(
        config: &CommitConfig,
        store: &StoreHandles,
        plan_id: &PreparedId,
        index: usize,
        operation: PreparedOperationV1,
        prior_state: Option<StateTargetStateV1>,
        created_directories: &CreatedDirectories,
    ) -> Result<Self, CommitError> {
        let mut cache = CommitPinCache::default();
        Self::open_inner(
            &mut cache,
            config,
            store,
            OperationSlot {
                plan_id,
                index,
                operation,
                prior_state,
            },
            true,
            Some(created_directories),
        )
    }

    pub(crate) fn open_inner(
        cache: &mut CommitPinCache,
        config: &CommitConfig,
        store: &StoreHandles,
        slot: OperationSlot<'_>,
        recovery: bool,
        created_directories: Option<&CreatedDirectories>,
    ) -> Result<Self, CommitError> {
        let OperationSlot {
            plan_id,
            index,
            operation,
            prior_state,
        } = slot;
        let observation = operation.observation().clone();
        if let LeafObservationV1::Present(identity) = observation.leaf()
            && identity.user_id != config.effective_user_id
        {
            return Err(CommitError::UnsafeTarget(
                "target leaf is owned by another user".to_owned(),
            ));
        }
        let authority_path = config
            .target_authorities
            .get(observation.authority())
            .cloned()
            .ok_or_else(|| CommitError::UnknownTargetAuthority(observation.authority().clone()))?;
        let absolute = authority_path.join(observation.relative_path());
        if overlaps(&absolute, &config.state_root) {
            return Err(CommitError::UnsafeTarget(
                "destination enters protected state".to_owned(),
            ));
        }
        let segments = observation.relative_path().split('/').collect::<Vec<_>>();
        let TargetPins {
            chain,
            root,
            ancestors,
            parent,
            pending,
            pending_prefixes,
            parent_object,
        } = cache.pin_target(
            config,
            store,
            &authority_path,
            &observation,
            recovery,
            created_directories,
        )?;
        let leaf = OsString::from(*segments.last().expect("validated path has a leaf"));
        let parent_path = absolute
            .parent()
            .expect("validated destination has a parent")
            .to_path_buf();
        let target = Self {
            operation,
            prior_state,
            authority_path,
            parent_path,
            chain,
            root,
            ancestors,
            parent,
            leaf,
            plan_id: plan_id.clone(),
            index,
            uid: config.effective_user_id,
            expected_parent: parent_object,
            parent_object,
            pending,
            pending_prefixes,
            restored_race: None,
            staged: None,
            pinned_source: None,
        };
        if recovery {
            target.revalidate_bindings(store)?;
        } else {
            target.revalidate(store)?;
        }
        Ok(target)
    }

    pub(crate) fn revalidate_bindings(&self, store: &StoreHandles) -> Result<(), CommitError> {
        self.chain.ensure_bound(&self.authority_path)?;
        let mut current = self.root.as_ref();
        for (leaf, pinned) in &self.ancestors {
            let bound = statat(current, leaf, AtFlags::SYMLINK_NOFOLLOW).map_err(|source| {
                io_error("revalidate target ancestor", &self.authority_path, source)
            })?;
            let pinned_stat = fstat(pinned).map_err(|source| {
                io_error(
                    "inspect pinned target ancestor",
                    &self.authority_path,
                    source,
                )
            })?;
            if !same_object(&bound, &pinned_stat) {
                return Err(CommitError::StaleTarget(
                    "target ancestor binding changed".to_owned(),
                ));
            }
            current = pinned;
        }
        let parent_stat = fstat(&self.parent).map_err(|source| {
            io_error("inspect pinned target parent", &self.authority_path, source)
        })?;
        compare_object_identity(&parent_stat, self.parent_object, "target parent")?;
        reject_protected_traversal_directory(store, &self.parent, &self.parent_path)?;
        if self.pending.is_empty() {
            self.revalidate_directory_leaf(store)
        } else {
            // The leaf cannot be reached while an ancestor is missing. Prove
            // the first missing ancestor is still absent instead; if it now
            // exists, an external actor may have created it after prepare and
            // the plan must be prepared again.
            self.require_pending_head_absent()
        }
    }

    /// Proves that the first missing ancestor is still absent. Only this plan's
    /// directory operation may make the pending chain reachable.
    pub(crate) fn require_pending_head_absent(&self) -> Result<(), CommitError> {
        let head = self
            .pending
            .first()
            .expect("pending head requires pending segments");
        let prefix = self
            .pending_prefixes
            .first()
            .expect("pending head requires pending prefixes");
        match statat(&self.parent, head, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(_) => Err(CommitError::StaleTarget(format!(
                "target ancestor {} was created externally",
                self.authority_path.join(prefix).display()
            ))),
            Err(rustix::io::Errno::NOENT) => Ok(()),
            Err(source) => Err(io_error(
                "inspect pending target ancestor",
                &self.authority_path.join(prefix),
                source,
            )),
        }
    }

    pub(crate) fn revalidate(&self, store: &StoreHandles) -> Result<(), CommitError> {
        self.revalidate_bindings(store)?;
        let parent_stat = fstat(&self.parent).map_err(|source| {
            io_error("inspect pinned target parent", &self.authority_path, source)
        })?;
        compare_identity(&parent_stat, self.expected_parent, "target parent")?;
        if !self.pending.is_empty() {
            // The absent pending head makes the leaf and all staging names
            // below it unreachable.
            return Ok(());
        }
        compare_leaf(
            &self.parent,
            &self.leaf,
            self.operation.observation().leaf(),
            &self
                .authority_path
                .join(self.operation.observation().relative_path()),
        )?;
        self.require_staging_absent()
    }

    pub(crate) fn revalidate_directory_leaf(
        &self,
        store: &StoreHandles,
    ) -> Result<(), CommitError> {
        let path = self
            .authority_path
            .join(self.operation.observation().relative_path());
        if let Some(observed) = entry_stat(&self.parent, &self.leaf, &path)? {
            prove_safe_existing_directory_leaf(store, &self.parent, &self.leaf, &path, &observed)?;
        }
        Ok(())
    }

    pub(crate) fn verify_prior_state(
        &self,
        canonical: &canonical::CanonicalObjects,
        observed: Option<&BTreeMap<String, ObservedFileV1>>,
    ) -> Result<(), CommitError> {
        // AssertExact promises an exact match with the ledger and therefore
        // verifies all content. A mutating operation may replace locally
        // modified content only after prepare records an approval-required
        // finding. Its journal then records the digest of the bytes actually
        // moved aside, so rollback and cleanup do not depend on the old ledger
        // content still being present in the store.
        let expected = match &self.operation {
            PreparedOperationV1::AssertExact { state, .. } => Some(state),
            _ => None,
        };
        if let Some(expected) = expected {
            let path = self
                .authority_path
                .join(self.operation.observation().relative_path());
            if self.observed_proves(expected, observed, &path)? {
                return Ok(());
            }
            if let StateTargetStateV1::Tree { tree: Some(tree) } = expected {
                let observation = self.operation.observation();
                let key = format!(
                    "{}:{}",
                    observation.authority(),
                    observation.relative_path()
                );
                return require_tree_entry_observed(
                    &self.parent,
                    &self.leaf,
                    tree.tree(),
                    canonical,
                    self.uid,
                    &path,
                    self.observed_scope(observed, &key),
                );
            }
            require_target_state(
                &self.parent,
                &self.leaf,
                expected,
                canonical,
                self.uid,
                &path,
            )?;
        }
        Ok(())
    }

    /// Returns true only when the cache records the asserted digest and the
    /// live file has exactly the recorded filesystem identity.
    pub(crate) fn observed_proves(
        &self,
        expected: &StateTargetStateV1,
        observed: Option<&BTreeMap<String, ObservedFileV1>>,
        path: &Path,
    ) -> Result<bool, CommitError> {
        let StateTargetStateV1::File { file: Some(file) } = expected else {
            return Ok(false);
        };
        if observed.is_none() {
            return Ok(false);
        }
        let observation = self.operation.observation();
        let key = format!(
            "{}:{}",
            observation.authority(),
            observation.relative_path()
        );
        let current = statat(&self.parent, &self.leaf, AtFlags::SYMLINK_NOFOLLOW)
            .map_err(|source| io_error("inspect asserted target", path, source))?;
        Ok(observed_proves_state(observed, &key, file, &current))
    }

    pub(crate) fn observed_scope<'a>(
        &self,
        observed: Option<&'a BTreeMap<String, ObservedFileV1>>,
        key: &'a str,
    ) -> Option<ObservedScope<'a>> {
        observed.map(|files| ObservedScope { files, key })
    }

    pub(crate) fn require_prior_backup_state(
        &self,
        leaf: &OsStr,
        canonical: &canonical::CanonicalObjects,
        path: &Path,
    ) -> Result<(), CommitError> {
        // File and symlink backups are proved by their pinned identity and the
        // content digest in the journal. They need not match old ledger bytes
        // because replacing local changes required explicit approval. A
        // directory or tree still needs the exact ledger state: its cleanup
        // walks and removes the entries described by that state.
        if let Some(state) = self.prior_state.as_ref().filter(|state| {
            matches!(
                state,
                StateTargetStateV1::Directory { .. } | StateTargetStateV1::Tree { .. }
            )
        }) {
            require_prior_removal_state(&self.parent, leaf, state, canonical, self.uid, path)?;
        }
        Ok(())
    }

    pub(crate) fn publish_staged_entry(
        &mut self,
        staging_name: &OsStr,
        staging: &File,
        identity: FileIdentityV1,
        before_final_rename: Option<&'static str>,
        context: PublishContext<'_, '_>,
    ) -> Result<(), CommitError> {
        let PublishContext {
            canonical,
            store,
            journal,
            path,
        } = context;
        let backup_name = self.temporary_name("backup");
        self.revalidate_bindings(store)?;
        compare_leaf(
            &self.parent,
            &self.leaf,
            self.operation.observation().leaf(),
            path,
        )?;
        if let LeafObservationV1::Present(expected) = self.operation.observation().leaf() {
            let pinned_source = pin_prepared_source(
                &self.parent,
                &self.leaf,
                expected,
                path,
                "prepared replacement source",
            )?;
            self.record_backup_intent(store, journal, pinned_source.content_digest)?;
            self.revalidate_bindings(store)?;
            compare_leaf(
                &self.parent,
                &self.leaf,
                LeafObservationV1::Present(expected),
                path,
            )?;
            require_pinned_entry(
                &self.parent,
                &self.leaf,
                &pinned_source.file,
                path,
                "prepared replacement source",
            )?;
            renameat_with(
                &self.parent,
                &self.leaf,
                &self.parent,
                &backup_name,
                RenameFlags::NOREPLACE,
            )
            .map_err(|source| io_error("backup prepared target", path, source))?;
            fsync(&self.parent)
                .map_err(|source| io_error("sync prepared target backup", path, source))?;
            let backup = match verify_relocated_source(
                &self.parent,
                &backup_name,
                &pinned_source,
                expected,
                path,
                "quarantined target",
            )
            .and_then(|backup| {
                self.require_prior_backup_state(&backup_name, canonical, path)?;
                Ok(backup)
            }) {
                Ok(backup) => backup,
                Err(error) => {
                    let backup =
                        entry_stat(&self.parent, &backup_name, path)?.ok_or_else(|| {
                            CommitError::RollbackFailed(
                                "quarantined replacement target vanished".to_owned(),
                            )
                        })?;
                    let raced_identity = file_identity(&backup);
                    restore_pinned_backup(
                        &self.parent,
                        &backup_name,
                        &self.leaf,
                        path,
                        BackupExpectation::exact(raced_identity, "raced replacement target"),
                    )?;
                    self.restored_race = Some(raced_identity);
                    return Err(error);
                }
            };
            self.record_backup_identity(store, journal, file_identity(&backup))?;
        }
        self.revalidate_bindings(store)?;
        require_pinned_entry(
            &self.parent,
            staging_name,
            staging,
            path,
            "prepared staging entry",
        )?;
        if let Some(failpoint) = before_final_rename {
            commit_failpoint!(failpoint);
        }
        if let Err(source) = renameat_with(
            &self.parent,
            staging_name,
            &self.parent,
            &self.leaf,
            RenameFlags::NOREPLACE,
        ) {
            return Err(io_error("place prepared target", path, source));
        }
        if let Err(error) = require_relocated_pinned_entry(
            &self.parent,
            &self.leaf,
            staging,
            identity,
            path,
            "placed prepared entry",
        ) {
            restore_raced_staging(
                &self.parent,
                &self.leaf,
                staging_name,
                path,
                "raced staging entry",
            )?;
            if let LeafObservationV1::Present(expected) = self.operation.observation().leaf() {
                restore_pinned_backup(
                    &self.parent,
                    &backup_name,
                    &self.leaf,
                    path,
                    BackupExpectation::journaled(&journal.operations[self.index])?,
                )?;
                compare_leaf(
                    &self.parent,
                    &self.leaf,
                    LeafObservationV1::Present(expected),
                    path,
                )?;
            }
            return Err(error);
        }
        fsync(&self.parent).map_err(|source| io_error("sync prepared target parent", path, source))
    }

    /// Phase A1 creates, writes, and syncs an anonymous inode for a `PlaceFile`
    /// operation. No target-directory entry is visible or durable yet.
    pub(crate) fn stage_file_creation(
        &mut self,
        blobs: &LoadedArtifacts,
    ) -> Result<(), CommitError> {
        let PreparedOperationV1::PlaceFile {
            artifact_id, mode, ..
        } = &self.operation
        else {
            return Ok(());
        };
        let path = self
            .authority_path
            .join(self.operation.observation().relative_path());
        let bytes = &blobs[artifact_id];
        let mut temporary = openat(
            &self.parent,
            ".",
            OFlags::TMPFILE | OFlags::RDWR | OFlags::CLOEXEC,
            Mode::from_raw_mode(*mode),
        )
        .map(File::from)
        .map_err(|source| io_error("create prepared target inode", &path, source))?;
        temporary
            .write_all(bytes)
            .map_err(|source| CommitError::Io {
                operation: "write prepared target inode",
                path: path.clone(),
                source,
            })?;
        fchmod(&temporary, Mode::from_raw_mode(*mode))
            .map_err(|source| io_error("set prepared target mode", &path, source))?;
        temporary.flush().map_err(|source| CommitError::Io {
            operation: "flush prepared target inode",
            path: path.clone(),
            source,
        })?;
        fsync(&temporary)
            .map_err(|source| io_error("sync prepared target inode", &path, source))?;
        let mut identity = file_identity(
            &fstat(&temporary)
                .map_err(|source| io_error("inspect prepared target inode", &path, source))?,
        );
        identity.links = 1;
        self.staged = Some(StagedFileV1 {
            file: temporary,
            name: self.temporary_name("new"),
            identity,
        });
        Ok(())
    }

    /// Phase A4 links the staged inode under its temporary name. The caller
    /// must later sync each affected parent directory to make these links
    /// durable.
    pub(crate) fn link_staged_file(&mut self, store: &StoreHandles) -> Result<(), CommitError> {
        let Some(staged) = self.staged.as_ref() else {
            return Ok(());
        };
        let path = self
            .authority_path
            .join(self.operation.observation().relative_path());
        self.revalidate_bindings(store)?;
        require_entry_absent(&self.parent, &staged.name, &path)?;
        linkat(
            &staged.file,
            "",
            &self.parent,
            &staged.name,
            AtFlags::EMPTY_PATH,
        )
        .map_err(|source| io_error("stage prepared target inode", &path, source))?;
        Ok(())
    }

    /// Phase B1 validates and pins a present leaf, returning its content digest
    /// for the backup intent. Returns `None` for an absent leaf or an operation
    /// that does not need a backup.
    pub(crate) fn pin_replacement_source(
        &mut self,
        canonical: &canonical::CanonicalObjects,
        store: &StoreHandles,
    ) -> Result<Option<Option<SourceDigestV1>>, CommitError> {
        let path = self
            .authority_path
            .join(self.operation.observation().relative_path());
        let role = match &self.operation {
            PreparedOperationV1::PlaceFile { .. } => "prepared replacement source",
            PreparedOperationV1::RemoveLeaf { .. } => "prepared removal source",
            _ => return Ok(None),
        };
        if !self.pending.is_empty() {
            // A removal below a missing ancestor has no source to pin. The
            // parent binding still proves that the pending head is absent.
            self.revalidate_bindings(store)?;
            return Ok(None);
        }
        self.revalidate_bindings(store)?;
        compare_leaf(
            &self.parent,
            &self.leaf,
            self.operation.observation().leaf(),
            &path,
        )?;
        let LeafObservationV1::Present(expected) = self.operation.observation().leaf() else {
            return Ok(None);
        };
        if matches!(&self.operation, PreparedOperationV1::RemoveLeaf { .. })
            && is_directory_identity(expected)
        {
            match self.prior_state.as_ref() {
                Some(StateTargetStateV1::Tree { tree: Some(_) }) => {
                    self.require_prior_backup_state(&self.leaf, canonical, &path)?;
                }
                _ => require_empty_directory_entry(&self.parent, &self.leaf, &path)?,
            }
        }
        self.revalidate_bindings(store)?;
        compare_leaf(
            &self.parent,
            &self.leaf,
            LeafObservationV1::Present(expected),
            &path,
        )?;
        let pinned = pin_prepared_source(&self.parent, &self.leaf, expected, &path, role)?;
        let digest = pinned.content_digest;
        self.pinned_source = Some(pinned);
        Ok(Some(digest))
    }

    /// Phase C1 renames the present leaf to its backup name. A later parent
    /// sync makes the rename durable before the backup identity is journaled.
    pub(crate) fn rename_to_backup(&mut self, store: &StoreHandles) -> Result<(), CommitError> {
        let Some(pinned) = self.pinned_source.as_ref() else {
            return Ok(());
        };
        let path = self
            .authority_path
            .join(self.operation.observation().relative_path());
        let LeafObservationV1::Present(expected) = self.operation.observation().leaf() else {
            return Err(CommitError::InvalidJournal(
                "pinned source without a present observation".to_owned(),
            ));
        };
        let backup_name = self.temporary_name("backup");
        let role = match &self.operation {
            PreparedOperationV1::RemoveLeaf { .. } => "prepared removal source",
            _ => "prepared replacement source",
        };
        self.revalidate_bindings(store)?;
        compare_leaf(
            &self.parent,
            &self.leaf,
            LeafObservationV1::Present(expected),
            &path,
        )?;
        require_pinned_entry(&self.parent, &self.leaf, &pinned.file, &path, role)?;
        match &self.operation {
            PreparedOperationV1::RemoveLeaf { .. } => {
                commit_failpoint!("v1.commit.remove.before_backup_rename");
            }
            _ => {
                commit_failpoint!("v1.commit.place.before_backup_rename");
            }
        }
        renameat_with(
            &self.parent,
            &self.leaf,
            &self.parent,
            &backup_name,
            RenameFlags::NOREPLACE,
        )
        .map_err(|source| io_error("backup prepared target", &path, source))?;
        match &self.operation {
            PreparedOperationV1::RemoveLeaf { .. } => {
                commit_failpoint!("v1.commit.remove.after_backup_rename");
            }
            _ => {
                commit_failpoint!("v1.commit.place.after_backup_rename");
            }
        }
        Ok(())
    }

    /// Phase C3 verifies that the backup is the pinned prior object and still
    /// has the journaled content digest, then returns its identity for the
    /// batched journal update.
    pub(crate) fn identify_backup(
        &mut self,
        canonical: &canonical::CanonicalObjects,
    ) -> Result<Option<FileIdentityV1>, CommitError> {
        let Some(pinned) = self.pinned_source.as_ref() else {
            return Ok(None);
        };
        let path = self
            .authority_path
            .join(self.operation.observation().relative_path());
        let LeafObservationV1::Present(expected) = self.operation.observation().leaf() else {
            return Err(CommitError::InvalidJournal(
                "pinned source without a present observation".to_owned(),
            ));
        };
        let backup_name = self.temporary_name("backup");
        let backup = match verify_relocated_source(
            &self.parent,
            &backup_name,
            pinned,
            expected,
            &path,
            "quarantined target",
        ) {
            Ok(backup) => backup,
            Err(error) => {
                let backup = entry_stat(&self.parent, &backup_name, &path)?.ok_or_else(|| {
                    CommitError::RollbackFailed("quarantined target vanished".to_owned())
                })?;
                let raced_identity = file_identity(&backup);
                restore_pinned_backup(
                    &self.parent,
                    &backup_name,
                    &self.leaf,
                    &path,
                    BackupExpectation::exact(raced_identity, "raced replacement target"),
                )?;
                self.restored_race = Some(raced_identity);
                match &self.operation {
                    PreparedOperationV1::RemoveLeaf { .. } => {
                        commit_failpoint!("v1.commit.remove.after_raced_restore");
                    }
                    _ => {
                        commit_failpoint!("v1.commit.place.after_raced_restore");
                    }
                }
                return Err(error);
            }
        };
        match &self.operation {
            PreparedOperationV1::RemoveLeaf { .. } => {
                if is_directory_identity(expected) {
                    match self.prior_state.as_ref() {
                        Some(StateTargetStateV1::Tree { tree: Some(_) }) => {
                            self.require_prior_backup_state(&backup_name, canonical, &path)?;
                        }
                        _ => require_empty_directory_entry(&self.parent, &backup_name, &path)?,
                    }
                }
            }
            _ => {
                self.require_prior_backup_state(&backup_name, canonical, &path)?;
            }
        }
        Ok(Some(file_identity(&backup)))
    }

    /// Phase C5 renames the staged file into place. The caller must finish the
    /// phase by syncing each affected parent directory.
    pub(crate) fn rename_into_place(
        &mut self,
        store: &StoreHandles,
        journal: &TransactionJournalV1,
    ) -> Result<(), CommitError> {
        let Some(staged) = self.staged.as_ref() else {
            return Ok(());
        };
        let path = self
            .authority_path
            .join(self.operation.observation().relative_path());
        let backup_name = self.temporary_name("backup");
        self.revalidate_bindings(store)?;
        require_pinned_entry(
            &self.parent,
            &staged.name,
            &staged.file,
            &path,
            "prepared file staging",
        )?;
        commit_failpoint!("v1.commit.place.before_final_rename");
        if let Err(source) = renameat_with(
            &self.parent,
            &staged.name,
            &self.parent,
            &self.leaf,
            RenameFlags::NOREPLACE,
        ) {
            return Err(io_error("place prepared target", &path, source));
        }
        if let Err(error) = require_relocated_pinned_entry(
            &self.parent,
            &self.leaf,
            &staged.file,
            staged.identity,
            &path,
            "placed prepared file",
        ) {
            restore_raced_staging(
                &self.parent,
                &self.leaf,
                &staged.name,
                &path,
                "raced file staging",
            )?;
            if let LeafObservationV1::Present(expected) = self.operation.observation().leaf() {
                restore_pinned_backup(
                    &self.parent,
                    &backup_name,
                    &self.leaf,
                    &path,
                    BackupExpectation::journaled(&journal.operations[self.index])?,
                )?;
                compare_leaf(
                    &self.parent,
                    &self.leaf,
                    LeafObservationV1::Present(expected),
                    &path,
                )?;
            }
            return Err(error);
        }
        Ok(())
    }

    pub(crate) fn apply(
        &mut self,
        _blobs: &LoadedArtifacts,
        canonical: &canonical::CanonicalObjects,
        store: &StoreHandles,
        journal: &mut TransactionJournalV1,
    ) -> Result<(), CommitError> {
        let path = self
            .authority_path
            .join(self.operation.observation().relative_path());
        match &self.operation {
            PreparedOperationV1::EnsureDirectory { mode, .. } => {
                let staging_name = self.temporary_name("new-dir");
                mkdirat(&self.parent, &staging_name, Mode::from_raw_mode(*mode)).map_err(
                    |source| io_error("create prepared directory staging", &path, source),
                )?;
                let created = openat2(
                    &self.parent,
                    &staging_name,
                    DIRECTORY_FLAGS | OFlags::NOFOLLOW,
                    Mode::empty(),
                    ROOT_RESOLVE_FLAGS,
                )
                .map(File::from)
                .map_err(|source| io_error("open prepared directory", &path, source))?;
                fchmod(&created, Mode::from_raw_mode(*mode))
                    .map_err(|source| io_error("set prepared directory mode", &path, source))?;
                fsync(&created)
                    .map_err(|source| io_error("sync prepared directory", &path, source))?;
                let identity = file_identity(
                    &fstat(&created)
                        .map_err(|source| io_error("inspect prepared directory", &path, source))?,
                );
                commit_failpoint!("v1.commit.ensure.before_identity");
                fsync(&self.parent)
                    .map_err(|source| io_error("sync prepared directory parent", &path, source))?;
                self.record_created_identity(store, journal, identity)?;
                commit_failpoint!("v1.commit.ensure.after_create");
                self.publish_staged_entry(
                    &staging_name,
                    &created,
                    identity,
                    Some("v1.commit.ensure.before_final_rename"),
                    PublishContext {
                        canonical,
                        store,
                        journal,
                        path: &path,
                    },
                )
            }
            PreparedOperationV1::PlaceFile { .. } => Err(CommitError::InvalidPlan(
                "place-file dispatched through phased schedule, not apply".to_owned(),
            )),
            PreparedOperationV1::PlaceSymlink { object, .. } => {
                let target = canonical
                    .safe_symlink_target(object)
                    .map_err(|error| invalid_canonical_object("symlink", object, error))?;
                let staging_name = self.temporary_name("new-link");
                symlinkat(target, &self.parent, &staging_name)
                    .map_err(|source| io_error("create prepared symlink staging", &path, source))?;
                let staging = openat2(
                    &self.parent,
                    &staging_name,
                    OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                    Mode::empty(),
                    ROOT_RESOLVE_FLAGS,
                )
                .map(File::from)
                .map_err(|source| io_error("pin prepared symlink staging", &path, source))?;
                require_symlink_target(&self.parent, &staging_name, target, self.uid, &path)?;
                let identity = file_identity(
                    &fstat(&staging)
                        .map_err(|source| io_error("inspect prepared symlink", &path, source))?,
                );
                fsync(&self.parent)
                    .map_err(|source| io_error("sync prepared symlink staging", &path, source))?;
                self.record_created_identity(store, journal, identity)?;
                self.publish_staged_entry(
                    &staging_name,
                    &staging,
                    identity,
                    None,
                    PublishContext {
                        canonical,
                        store,
                        journal,
                        path: &path,
                    },
                )
            }
            PreparedOperationV1::PlaceTree { tree, .. } => {
                let root = canonical.trees.get(tree).ok_or_else(|| {
                    CommitError::InvalidStore(format!("canonical tree object {tree} is missing"))
                })?;
                let staging_name = self.temporary_name("new-tree");
                mkdirat(&self.parent, &staging_name, Mode::from_raw_mode(0o700))
                    .map_err(|source| io_error("create prepared tree staging", &path, source))?;
                let staging = match openat2(
                    &self.parent,
                    &staging_name,
                    DIRECTORY_FLAGS | OFlags::NOFOLLOW,
                    Mode::empty(),
                    ROOT_RESOLVE_FLAGS,
                ) {
                    Ok(staging) => File::from(staging),
                    Err(source) => {
                        return Err(io_error("open prepared tree staging", &path, source));
                    }
                };
                if let Err(error) =
                    materialize_tree_directory(&staging, tree, canonical, self.uid, &path)
                {
                    let cleanup =
                        remove_partial_tree_directory(&staging, tree, canonical, self.uid, &path)
                            .and_then(|()| {
                                unlink_pinned_entry(
                                    &self.parent,
                                    &staging_name,
                                    &staging,
                                    AtFlags::REMOVEDIR,
                                    &path,
                                    "failed canonical tree staging",
                                )
                            });
                    return match cleanup {
                        Ok(()) => Err(error),
                        Err(cleanup) => Err(CommitError::RollbackFailed(format!(
                            "{error}; failed to remove tree staging: {cleanup}"
                        ))),
                    };
                }
                fchmod(&staging, Mode::from_raw_mode(root.root_mode))
                    .map_err(|source| io_error("set prepared tree root mode", &path, source))?;
                fsync(&staging)
                    .map_err(|source| io_error("sync prepared tree root", &path, source))?;
                require_tree_directory(&staging, tree, canonical, self.uid, &path)?;
                let identity = file_identity(
                    &fstat(&staging)
                        .map_err(|source| io_error("inspect prepared tree root", &path, source))?,
                );
                fsync(&self.parent)
                    .map_err(|source| io_error("sync prepared tree staging", &path, source))?;
                self.record_created_identity(store, journal, identity)?;
                self.publish_staged_entry(
                    &staging_name,
                    &staging,
                    identity,
                    None,
                    PublishContext {
                        canonical,
                        store,
                        journal,
                        path: &path,
                    },
                )
            }
            PreparedOperationV1::RemoveLeaf { .. } => Err(CommitError::InvalidPlan(
                "remove-leaf dispatched through phased schedule, not apply".to_owned(),
            )),
            PreparedOperationV1::AssertAbsent { .. } => {
                self.revalidate_bindings(store)?;
                compare_leaf(&self.parent, &self.leaf, LeafObservationV1::Absent, &path)?;
                self.revalidate_bindings(store)
            }
            // Preflight proves the prior state, and verify_applied repeats the
            // exact proof before publication. AssertExact does not mutate.
            PreparedOperationV1::AssertExact { .. } => Ok(()),
        }
    }

    /// Adds the created identity to the in-memory journal. The phase driver
    /// publishes all staged identities in one durable rewrite.
    pub(crate) fn stage_created_identity(
        &self,
        journal: &mut TransactionJournalV1,
        identity: FileIdentityV1,
    ) {
        journal.operations[self.index].created_identity = Some(identity);
    }

    pub(crate) fn record_created_identity(
        &self,
        store: &StoreHandles,
        journal: &mut TransactionJournalV1,
        identity: FileIdentityV1,
    ) -> Result<(), CommitError> {
        self.stage_created_identity(journal, identity);
        replace_journal(store, journal)
    }

    /// Adds a backup intent to the in-memory journal without publishing it.
    pub(crate) fn stage_backup_intent(
        &self,
        journal: &mut TransactionJournalV1,
        source_digest: Option<SourceDigestV1>,
    ) -> Result<(), CommitError> {
        if journal.operations[self.index].backup.is_some() {
            return Err(CommitError::InvalidJournal(
                "transaction backup intent is already established".to_owned(),
            ));
        }
        journal.operations[self.index].backup = Some(JournalBackupV1::Intent { source_digest });
        Ok(())
    }

    pub(crate) fn record_backup_intent(
        &self,
        store: &StoreHandles,
        journal: &mut TransactionJournalV1,
        source_digest: Option<SourceDigestV1>,
    ) -> Result<(), CommitError> {
        self.stage_backup_intent(journal, source_digest)?;
        replace_journal(store, journal)
    }

    /// Upgrades the in-memory backup intent with the verified backup identity.
    /// The phase driver publishes the update later.
    pub(crate) fn stage_backup_identity(
        &self,
        journal: &mut TransactionJournalV1,
        identity: FileIdentityV1,
    ) -> Result<(), CommitError> {
        let Some(JournalBackupV1::Intent { source_digest }) = journal.operations[self.index].backup
        else {
            return Err(CommitError::InvalidJournal(
                "transaction backup identity has no durable intent".to_owned(),
            ));
        };
        journal.operations[self.index].backup = Some(JournalBackupV1::Identified {
            identity,
            source_digest,
        });
        Ok(())
    }

    pub(crate) fn record_backup_identity(
        &self,
        store: &StoreHandles,
        journal: &mut TransactionJournalV1,
        identity: FileIdentityV1,
    ) -> Result<(), CommitError> {
        self.stage_backup_identity(journal, identity)?;
        replace_journal(store, journal)
    }

    pub(crate) fn require_created_canonical_entry(
        &self,
        leaf: &OsStr,
        canonical: &canonical::CanonicalObjects,
        path: &Path,
    ) -> Result<(), CommitError> {
        match &self.operation {
            PreparedOperationV1::EnsureDirectory { mode, .. } => {
                require_managed_directory(&self.parent, leaf, Some(*mode), self.uid, path)
            }
            PreparedOperationV1::PlaceSymlink { object, .. } => require_symlink_target(
                &self.parent,
                leaf,
                canonical
                    .safe_symlink_target(object)
                    .map_err(|error| invalid_canonical_object("symlink", object, error))?,
                self.uid,
                path,
            ),
            PreparedOperationV1::PlaceTree { tree, .. } => {
                require_tree_entry(&self.parent, leaf, tree, canonical, self.uid, path)
            }
            _ => Err(CommitError::InvalidPlan(
                "canonical entry validation was requested for another operation".to_owned(),
            )),
        }
    }

    pub(crate) fn remove_created_canonical_entry(
        &self,
        source: Option<&OsStr>,
        quarantine: &OsStr,
        identity: FileIdentityV1,
        canonical: &canonical::CanonicalObjects,
        path: &Path,
    ) -> Result<(), CommitError> {
        let created = QuarantineEntry {
            parent: &self.parent,
            source,
            quarantine,
            path,
            identity,
            created: true,
        };
        match &self.operation {
            PreparedOperationV1::EnsureDirectory { .. } => {
                quarantine_and_unlink_entry(created, AtFlags::REMOVEDIR, |leaf| {
                    self.require_created_canonical_entry(leaf, canonical, path)
                })
            }
            PreparedOperationV1::PlaceSymlink { .. } => {
                quarantine_and_unlink_entry(created, AtFlags::empty(), |leaf| {
                    self.require_created_canonical_entry(leaf, canonical, path)
                })
            }
            PreparedOperationV1::PlaceTree { tree, .. } => {
                quarantine_and_remove_tree_entry(created, tree, canonical, self.uid)
            }
            _ => Err(CommitError::InvalidPlan(
                "canonical entry removal was requested for another operation".to_owned(),
            )),
        }
    }

    pub(crate) fn rollback_canonical_placement(
        &mut self,
        canonical: &canonical::CanonicalObjects,
        journal: &JournalOperationV1,
        path: &Path,
    ) -> Result<(), CommitError> {
        let staging_name = match self.operation {
            PreparedOperationV1::EnsureDirectory { .. } => self.temporary_name("new-dir"),
            PreparedOperationV1::PlaceSymlink { .. } => self.temporary_name("new-link"),
            PreparedOperationV1::PlaceTree { .. } => self.temporary_name("new-tree"),
            _ => {
                return Err(CommitError::InvalidPlan(
                    "canonical rollback was requested for another operation".to_owned(),
                ));
            }
        };
        let backup_name = self.temporary_name("backup");
        let quarantine = self.temporary_name("delete-created");
        if entry_stat(&self.parent, &quarantine, path)?.is_some() {
            let identity = journal.created_identity.ok_or_else(|| {
                CommitError::InvalidJournal(
                    "unidentified canonical-entry quarantine remains".to_owned(),
                )
            })?;
            self.remove_created_canonical_entry(None, &quarantine, identity, canonical, path)?;
        }
        if let Some(staging) = entry_stat(&self.parent, &staging_name, path)? {
            let identity = journal.created_identity.ok_or_else(|| {
                CommitError::InvalidJournal(
                    "unidentified canonical staging entry remains".to_owned(),
                )
            })?;
            compare_created_identity(&staging, identity, "canonical staging entry")?;
            self.require_created_canonical_entry(&staging_name, canonical, path)?;
            self.remove_created_canonical_entry(
                Some(&staging_name),
                &quarantine,
                identity,
                canonical,
                path,
            )?;
        }
        match self.operation.observation().leaf() {
            LeafObservationV1::Absent => {
                require_entry_absent(&self.parent, &backup_name, path)?;
                if let (Some(identity), Some(actual)) = (
                    journal.created_identity,
                    entry_stat(&self.parent, &self.leaf, path)?,
                ) {
                    if !same_created_identity(&actual, identity) {
                        return Err(CommitError::InvalidJournal(
                            "created canonical target was externally replaced".to_owned(),
                        ));
                    }
                    self.require_created_canonical_entry(&self.leaf, canonical, path)?;
                    self.remove_created_canonical_entry(
                        Some(&self.leaf),
                        &quarantine,
                        identity,
                        canonical,
                        path,
                    )?;
                }
            }
            LeafObservationV1::Present(expected) => {
                let backup = entry_stat(&self.parent, &backup_name, path)?;
                let leaf = entry_stat(&self.parent, &self.leaf, path)?;
                if let Some(identity) = self.restored_race {
                    if backup.is_some() {
                        return Err(CommitError::RollbackFailed(
                            "restored raced replacement still has a backup name".to_owned(),
                        ));
                    }
                    let leaf = leaf.ok_or_else(|| {
                        CommitError::RollbackFailed(
                            "restored raced replacement vanished".to_owned(),
                        )
                    })?;
                    compare_relocated_identity(&leaf, identity, "restored raced replacement")?;
                    return Ok(());
                }
                if let Some(backup) = backup {
                    let expectation = BackupExpectation::rollback(
                        journal,
                        expected,
                        "transaction replacement backup",
                    )?;
                    expectation.compare(&backup, "transaction replacement backup intent")?;
                    self.require_prior_backup_state(&backup_name, canonical, path)?;
                    if let Some(actual) = leaf {
                        let identity = journal.created_identity.ok_or_else(|| {
                            CommitError::InvalidJournal(
                                "canonical replacement has no journaled identity".to_owned(),
                            )
                        })?;
                        compare_created_identity(
                            &actual,
                            identity,
                            "created canonical replacement",
                        )?;
                        self.require_created_canonical_entry(&self.leaf, canonical, path)?;
                        self.remove_created_canonical_entry(
                            Some(&self.leaf),
                            &quarantine,
                            identity,
                            canonical,
                            path,
                        )?;
                    }
                    restore_pinned_backup(
                        &self.parent,
                        &backup_name,
                        &self.leaf,
                        path,
                        expectation,
                    )?;
                } else {
                    let leaf = leaf.ok_or_else(|| {
                        CommitError::InvalidJournal(
                            "replacement backup and original leaf are both missing".to_owned(),
                        )
                    })?;
                    if !same_relocated_identity(&leaf, expected) {
                        return Err(CommitError::InvalidJournal(
                            "replacement backup is missing while a changed leaf remains".to_owned(),
                        ));
                    }
                }
                self.require_prior_backup_state(&self.leaf, canonical, path)?;
            }
        }
        Ok(())
    }

    pub(crate) fn finish_canonical_placement(
        &self,
        canonical: &canonical::CanonicalObjects,
        journal: &JournalOperationV1,
        path: &Path,
    ) -> Result<(), CommitError> {
        let identity = journal.created_identity.ok_or_else(|| {
            CommitError::InvalidJournal(
                "placed canonical entry has no journaled identity".to_owned(),
            )
        })?;
        require_entry_identity(
            &self.parent,
            &self.leaf,
            identity,
            path,
            "placed canonical entry",
        )?;
        self.require_created_canonical_entry(&self.leaf, canonical, path)?;
        let staging_name = match self.operation {
            PreparedOperationV1::EnsureDirectory { .. } => self.temporary_name("new-dir"),
            PreparedOperationV1::PlaceSymlink { .. } => self.temporary_name("new-link"),
            PreparedOperationV1::PlaceTree { .. } => self.temporary_name("new-tree"),
            _ => unreachable!("only canonical placements use this helper"),
        };
        require_entry_absent(&self.parent, &staging_name, path)?;
        self.finish_prior_backup(canonical, journal, path)
    }

    pub(crate) fn finish_prior_backup(
        &self,
        canonical: &canonical::CanonicalObjects,
        journal: &JournalOperationV1,
        path: &Path,
    ) -> Result<(), CommitError> {
        let backup_name = self.temporary_name("backup");
        let quarantine = self.temporary_name("delete-backup");
        let LeafObservationV1::Present(_) = self.operation.observation().leaf() else {
            require_entry_absent(&self.parent, &backup_name, path)?;
            return require_entry_absent(&self.parent, &quarantine, path);
        };
        let identity = journaled_backup_identity(journal)?;
        let Some(state) = self.prior_state.as_ref().filter(|state| {
            matches!(
                state,
                StateTargetStateV1::Directory { .. } | StateTargetStateV1::Tree { .. }
            )
        }) else {
            // For an adopted leaf or a prior file or symlink, the journaled
            // backup identity and source digest prove what may be removed. The
            // backup need not match old ledger content because replacing local
            // changes required explicit approval; the journal describes the
            // bytes that this transaction actually moved aside.
            let source_digest = journaled_backup_source_digest(journal)?;
            let validate =
                |leaf: &OsStr| verify_adopted_backup(&self.parent, leaf, source_digest, path);
            if entry_stat(&self.parent, &quarantine, path)?.is_some() {
                return quarantine_and_unlink_entry(
                    QuarantineEntry {
                        parent: &self.parent,
                        source: None,
                        quarantine: &quarantine,
                        path,
                        identity,
                        created: false,
                    },
                    removal_flags(identity),
                    validate,
                );
            }
            if let Some(backup) = entry_stat(&self.parent, &backup_name, path)? {
                compare_journaled_backup(&backup, journal)?;
                quarantine_and_unlink_entry(
                    QuarantineEntry {
                        parent: &self.parent,
                        source: Some(&backup_name),
                        quarantine: &quarantine,
                        path,
                        identity,
                        created: false,
                    },
                    removal_flags(identity),
                    validate,
                )?;
            }
            return Ok(());
        };
        if entry_stat(&self.parent, &quarantine, path)?.is_some() {
            return quarantine_and_remove_prior_entry(
                QuarantineEntry {
                    parent: &self.parent,
                    source: None,
                    quarantine: &quarantine,
                    path,
                    identity,
                    created: false,
                },
                state,
                canonical,
                self.uid,
            );
        }
        if let Some(backup) = entry_stat(&self.parent, &backup_name, path)? {
            compare_journaled_backup(&backup, journal)?;
            require_target_state(&self.parent, &backup_name, state, canonical, self.uid, path)?;
            quarantine_and_remove_prior_entry(
                QuarantineEntry {
                    parent: &self.parent,
                    source: Some(&backup_name),
                    quarantine: &quarantine,
                    path,
                    identity,
                    created: false,
                },
                state,
                canonical,
                self.uid,
            )?;
        }
        Ok(())
    }

    pub(crate) fn rollback_incomplete(
        &mut self,
        store: &StoreHandles,
        blobs: &LoadedArtifacts,
        canonical: &canonical::CanonicalObjects,
        journal: &JournalOperationV1,
    ) -> Result<(), CommitError> {
        self.rollback_incomplete_inner(blobs, canonical, journal, Some(store))
    }

    pub(crate) fn rollback_pinned(
        &mut self,
        blobs: &LoadedArtifacts,
        canonical: &canonical::CanonicalObjects,
        journal: &JournalOperationV1,
    ) -> Result<(), CommitError> {
        self.rollback_incomplete_inner(blobs, canonical, journal, None)
    }

    pub(crate) fn rollback_incomplete_inner(
        &mut self,
        blobs: &LoadedArtifacts,
        canonical: &canonical::CanonicalObjects,
        journal: &JournalOperationV1,
        recovery_store: Option<&StoreHandles>,
    ) -> Result<(), CommitError> {
        if let Some(store) = recovery_store {
            self.revalidate_bindings_for_recovery(store)?;
        } else {
            let parent = fstat(&self.parent).map_err(|source| {
                io_error(
                    "inspect pinned rollback parent",
                    &self.authority_path,
                    source,
                )
            })?;
            compare_object_identity(&parent, self.parent_object, "pinned rollback parent")?;
        }
        let path = self
            .authority_path
            .join(self.operation.observation().relative_path());
        match &self.operation {
            PreparedOperationV1::EnsureDirectory { .. } => {
                self.rollback_canonical_placement(canonical, journal, &path)?;
            }
            PreparedOperationV1::PlaceFile {
                artifact_id, mode, ..
            } => {
                let new_name = self.temporary_name("new");
                let backup_name = self.temporary_name("backup");
                let quarantine = self.temporary_name("delete-created");
                let verify = |leaf: &OsStr| {
                    require_leaf_bytes(
                        &self.parent,
                        leaf,
                        &blobs[artifact_id],
                        *mode,
                        self.uid,
                        &path,
                    )
                };
                if entry_stat(&self.parent, &quarantine, &path)?.is_some() {
                    let identity = journal.created_identity.ok_or_else(|| {
                        CommitError::InvalidJournal(
                            "unidentified created-file quarantine remains".to_owned(),
                        )
                    })?;
                    quarantine_and_unlink_entry(
                        QuarantineEntry {
                            parent: &self.parent,
                            source: None,
                            quarantine: &quarantine,
                            path: &path,
                            identity,
                            created: true,
                        },
                        AtFlags::empty(),
                        verify,
                    )?;
                }
                if let Some(staging) = entry_stat(&self.parent, &new_name, &path)? {
                    let identity = journal.created_identity.ok_or_else(|| {
                        CommitError::InvalidJournal(
                            "unidentified file staging entry remains".to_owned(),
                        )
                    })?;
                    compare_created_identity(&staging, identity, "created file staging")?;
                    verify(&new_name)?;
                    quarantine_and_unlink_created_entry(
                        &self.parent,
                        &new_name,
                        &quarantine,
                        &path,
                        identity,
                        AtFlags::empty(),
                        verify,
                    )?;
                }
                match self.operation.observation().leaf() {
                    LeafObservationV1::Absent => {
                        if entry_stat(&self.parent, &backup_name, &path)?.is_some() {
                            return Err(CommitError::InvalidJournal(
                                "unexpected backup for an originally absent leaf".to_owned(),
                            ));
                        }
                        if let (Some(identity), Some(actual)) = (
                            journal.created_identity,
                            entry_stat(&self.parent, &self.leaf, &path)?,
                        ) && same_created_identity(&actual, identity)
                        {
                            verify(&self.leaf)?;
                            quarantine_and_unlink_created_entry(
                                &self.parent,
                                &self.leaf,
                                &quarantine,
                                &path,
                                identity,
                                AtFlags::empty(),
                                verify,
                            )?;
                        }
                    }
                    LeafObservationV1::Present(expected) => {
                        let backup = entry_stat(&self.parent, &backup_name, &path)?;
                        let leaf = entry_stat(&self.parent, &self.leaf, &path)?;
                        if let Some(identity) = self.restored_race {
                            if backup.is_some() {
                                return Err(CommitError::RollbackFailed(
                                    "restored raced replacement still has a backup name".to_owned(),
                                ));
                            }
                            let leaf = leaf.ok_or_else(|| {
                                CommitError::RollbackFailed(
                                    "restored raced replacement vanished".to_owned(),
                                )
                            })?;
                            compare_relocated_identity(
                                &leaf,
                                identity,
                                "restored raced replacement",
                            )?;
                        } else if let Some(backup) = backup {
                            let expectation = BackupExpectation::rollback(
                                journal,
                                expected,
                                "transaction replacement backup",
                            )?;
                            expectation
                                .compare(&backup, "transaction replacement backup intent")?;
                            self.require_prior_backup_state(&backup_name, canonical, &path)?;
                            if let Some(actual) = leaf {
                                let identity = journal.created_identity.ok_or_else(|| {
                                    CommitError::InvalidJournal(
                                        "replacement target has no journaled identity".to_owned(),
                                    )
                                })?;
                                compare_created_identity(
                                    &actual,
                                    identity,
                                    "created replacement target",
                                )?;
                                verify(&self.leaf)?;
                                quarantine_and_unlink_created_entry(
                                    &self.parent,
                                    &self.leaf,
                                    &quarantine,
                                    &path,
                                    identity,
                                    AtFlags::empty(),
                                    verify,
                                )?;
                            }
                            restore_pinned_backup(
                                &self.parent,
                                &backup_name,
                                &self.leaf,
                                &path,
                                expectation,
                            )?;
                        } else {
                            match leaf {
                                Some(actual) if same_relocated_identity(&actual, expected) => {
                                    if let Some(source_digest) = backup_source_digest(journal) {
                                        verify_entry_source_digest(
                                            &self.parent,
                                            &self.leaf,
                                            source_digest,
                                            &path,
                                            "transaction replacement source",
                                        )?;
                                    }
                                }
                                Some(_) => {
                                    return Err(CommitError::InvalidJournal(
                                    "replacement backup is missing while a changed leaf remains"
                                        .to_owned(),
                                    ));
                                }
                                None => {
                                    return Err(CommitError::InvalidJournal(
                                        "replacement backup and original leaf are both missing"
                                            .to_owned(),
                                    ));
                                }
                            }
                        }
                    }
                }
            }
            PreparedOperationV1::PlaceSymlink { .. } | PreparedOperationV1::PlaceTree { .. } => {
                self.rollback_canonical_placement(canonical, journal, &path)?;
            }
            PreparedOperationV1::RemoveLeaf { .. } => {
                let backup_name = self.temporary_name("backup");
                let LeafObservationV1::Present(expected) = self.operation.observation().leaf()
                else {
                    require_entry_absent(&self.parent, &self.leaf, &path)?;
                    return require_entry_absent(&self.parent, &backup_name, &path);
                };
                let backup = entry_stat(&self.parent, &backup_name, &path)?;
                let leaf = entry_stat(&self.parent, &self.leaf, &path)?;
                if let Some(identity) = self.restored_race {
                    if backup.is_some() {
                        return Err(CommitError::RollbackFailed(
                            "restored raced removal still has a backup name".to_owned(),
                        ));
                    }
                    let leaf = leaf.ok_or_else(|| {
                        CommitError::RollbackFailed("restored raced removal vanished".to_owned())
                    })?;
                    compare_relocated_identity(&leaf, identity, "restored raced removal")?;
                    fsync(&self.parent).map_err(|source| {
                        io_error("sync recovered target parent", &path, source)
                    })?;
                    return Ok(());
                }
                let Some(backup) = backup else {
                    return match leaf {
                        Some(actual) if same_relocated_identity(&actual, expected) => {
                            if let Some(source_digest) = backup_source_digest(journal) {
                                verify_entry_source_digest(
                                    &self.parent,
                                    &self.leaf,
                                    source_digest,
                                    &path,
                                    "transaction removal source",
                                )?;
                            }
                            Ok(())
                        }
                        Some(_) => Err(CommitError::InvalidJournal(
                            "removal backup is missing while a changed leaf remains".to_owned(),
                        )),
                        None => Err(CommitError::InvalidJournal(
                            "removal backup and original leaf are both missing".to_owned(),
                        )),
                    };
                };
                let expectation =
                    BackupExpectation::rollback(journal, expected, "transaction removal backup")?;
                expectation.compare(&backup, "transaction removal backup intent")?;
                if is_directory_identity(expected) {
                    match self.prior_state.as_ref() {
                        Some(StateTargetStateV1::Tree { tree: Some(_) }) => {
                            self.require_prior_backup_state(&backup_name, canonical, &path)?;
                        }
                        _ => require_empty_directory_entry(&self.parent, &backup_name, &path)?,
                    }
                }
                if leaf.is_some() {
                    return Err(CommitError::InvalidJournal(
                        "removed leaf was externally recreated".to_owned(),
                    ));
                }
                restore_pinned_backup(&self.parent, &backup_name, &self.leaf, &path, expectation)?;
            }
            PreparedOperationV1::AssertAbsent { .. } => {
                require_entry_absent(&self.parent, &self.leaf, &path)?;
            }
            PreparedOperationV1::AssertExact { state, .. } => {
                require_target_state(&self.parent, &self.leaf, state, canonical, self.uid, &path)?;
            }
        }
        fsync(&self.parent)
            .map_err(|source| io_error("sync recovered target parent", &path, source))
    }

    pub(crate) fn finish_incomplete(
        &mut self,
        store: &StoreHandles,
        blobs: &LoadedArtifacts,
        canonical: &canonical::CanonicalObjects,
        journal: &JournalOperationV1,
    ) -> Result<(), CommitError> {
        self.revalidate_bindings_for_recovery(store)?;
        let path = self
            .authority_path
            .join(self.operation.observation().relative_path());
        match &self.operation {
            PreparedOperationV1::EnsureDirectory { .. } => {
                self.finish_canonical_placement(canonical, journal, &path)?;
            }
            PreparedOperationV1::PlaceFile {
                artifact_id, mode, ..
            } => {
                let identity = journal.created_identity.ok_or_else(|| {
                    CommitError::InvalidJournal("placed file has no journaled identity".to_owned())
                })?;
                require_entry_identity(&self.parent, &self.leaf, identity, &path, "placed file")?;
                require_leaf_bytes(
                    &self.parent,
                    &self.leaf,
                    &blobs[artifact_id],
                    *mode,
                    self.uid,
                    &path,
                )?;
                require_entry_absent(&self.parent, &self.temporary_name("new"), &path)?;
                self.finish_prior_backup(canonical, journal, &path)?;
            }
            PreparedOperationV1::PlaceSymlink { .. } | PreparedOperationV1::PlaceTree { .. } => {
                self.finish_canonical_placement(canonical, journal, &path)?;
            }
            PreparedOperationV1::RemoveLeaf { .. } => {
                if entry_stat(&self.parent, &self.leaf, &path)?.is_some() {
                    return Err(CommitError::InvalidJournal(
                        "prepared removal is not reflected in the target".to_owned(),
                    ));
                }
                self.finish_prior_backup(canonical, journal, &path)?;
            }
            PreparedOperationV1::AssertAbsent { .. } => {
                require_entry_absent(&self.parent, &self.leaf, &path)?;
            }
            PreparedOperationV1::AssertExact { state, .. } => {
                require_target_state(&self.parent, &self.leaf, state, canonical, self.uid, &path)?;
            }
        }
        fsync(&self.parent)
            .map_err(|source| io_error("sync recovered target parent", &path, source))
    }

    pub(crate) fn verify_applied(
        &mut self,
        store: &StoreHandles,
        blobs: &LoadedArtifacts,
        canonical: &canonical::CanonicalObjects,
        journal: &JournalOperationV1,
        observed: Option<&BTreeMap<String, ObservedFileV1>>,
    ) -> Result<(), CommitError> {
        self.revalidate_bindings_for_recovery(store)?;
        let path = self
            .authority_path
            .join(self.operation.observation().relative_path());
        let verified = match &self.operation {
            PreparedOperationV1::PlaceFile {
                artifact_id, mode, ..
            } => {
                let identity = journal.created_identity.ok_or_else(|| {
                    CommitError::InvalidJournal("placed file has no journaled identity".to_owned())
                })?;
                require_entry_identity(&self.parent, &self.leaf, identity, &path, "placed file")?;
                require_leaf_bytes(
                    &self.parent,
                    &self.leaf,
                    &blobs[artifact_id],
                    *mode,
                    self.uid,
                    &path,
                )?;
                require_entry_absent(&self.parent, &self.temporary_name("new"), &path)?;
                let backup_name = self.temporary_name("backup");
                match self.operation.observation().leaf() {
                    LeafObservationV1::Present(_) => {
                        let backup =
                            entry_stat(&self.parent, &backup_name, &path)?.ok_or_else(|| {
                                CommitError::InvalidJournal(
                                    "replacement backup is missing before publication".to_owned(),
                                )
                            })?;
                        compare_journaled_backup(&backup, journal)?;
                        self.require_prior_backup_state(&backup_name, canonical, &path)
                    }
                    LeafObservationV1::Absent => {
                        require_entry_absent(&self.parent, &backup_name, &path)
                    }
                }
            }
            PreparedOperationV1::EnsureDirectory { .. }
            | PreparedOperationV1::PlaceSymlink { .. }
            | PreparedOperationV1::PlaceTree { .. } => {
                let identity = journal.created_identity.ok_or_else(|| {
                    CommitError::InvalidJournal(
                        "placed canonical entry has no journaled identity".to_owned(),
                    )
                })?;
                require_entry_identity(
                    &self.parent,
                    &self.leaf,
                    identity,
                    &path,
                    "placed canonical entry",
                )?;
                self.require_created_canonical_entry(&self.leaf, canonical, &path)?;
                let staging = match self.operation {
                    PreparedOperationV1::EnsureDirectory { .. } => self.temporary_name("new-dir"),
                    PreparedOperationV1::PlaceSymlink { .. } => self.temporary_name("new-link"),
                    PreparedOperationV1::PlaceTree { .. } => self.temporary_name("new-tree"),
                    _ => unreachable!(),
                };
                require_entry_absent(&self.parent, &staging, &path)?;
                let backup_name = self.temporary_name("backup");
                match self.operation.observation().leaf() {
                    LeafObservationV1::Present(_) => {
                        let backup =
                            entry_stat(&self.parent, &backup_name, &path)?.ok_or_else(|| {
                                CommitError::InvalidJournal(
                                    "replacement backup is missing before publication".to_owned(),
                                )
                            })?;
                        compare_journaled_backup(&backup, journal)?;
                        self.require_prior_backup_state(&backup_name, canonical, &path)
                    }
                    LeafObservationV1::Absent => {
                        require_entry_absent(&self.parent, &backup_name, &path)
                    }
                }
            }
            PreparedOperationV1::RemoveLeaf { .. } => {
                require_entry_absent(&self.parent, &self.leaf, &path)?;
                let backup_name = self.temporary_name("backup");
                match self.operation.observation().leaf() {
                    LeafObservationV1::Present(expected) => {
                        let backup =
                            entry_stat(&self.parent, &backup_name, &path)?.ok_or_else(|| {
                                CommitError::InvalidJournal(
                                    "removal backup is missing before publication".to_owned(),
                                )
                            })?;
                        compare_journaled_backup(&backup, journal)?;
                        if is_directory_identity(expected) {
                            match self.prior_state.as_ref() {
                                Some(StateTargetStateV1::Tree { tree: Some(_) }) => {
                                    self.require_prior_backup_state(
                                        &backup_name,
                                        canonical,
                                        &path,
                                    )?;
                                }
                                _ => require_empty_directory_entry(
                                    &self.parent,
                                    &backup_name,
                                    &path,
                                )?,
                            }
                        }
                        Ok(())
                    }
                    LeafObservationV1::Absent => {
                        require_entry_absent(&self.parent, &backup_name, &path)
                    }
                }
            }
            PreparedOperationV1::AssertAbsent { .. } => {
                require_entry_absent(&self.parent, &self.leaf, &path)
            }
            PreparedOperationV1::AssertExact { state, .. } => {
                // AssertExact does not mutate its target, so its preflight
                // content proof remains valid. A final stat below proves that
                // the path still names the same object after other mutations.
                if self.observed_proves(state, observed, &path)? {
                    Ok(())
                } else if let StateTargetStateV1::Tree { tree: Some(tree) } = state {
                    let observation = self.operation.observation();
                    let key = format!(
                        "{}:{}",
                        observation.authority(),
                        observation.relative_path()
                    );
                    require_tree_entry_observed(
                        &self.parent,
                        &self.leaf,
                        tree.tree(),
                        canonical,
                        self.uid,
                        &path,
                        self.observed_scope(observed, &key),
                    )
                } else {
                    require_target_state(
                        &self.parent,
                        &self.leaf,
                        state,
                        canonical,
                        self.uid,
                        &path,
                    )
                }
            }
        };
        verified?;
        commit_failpoint!("v1.commit.verify.before_final_rebound");
        self.require_applied_binding(store, journal, &path)
    }

    pub(crate) fn require_applied_binding(
        &self,
        store: &StoreHandles,
        journal: &JournalOperationV1,
        path: &Path,
    ) -> Result<(), CommitError> {
        self.revalidate_bindings_for_recovery(store)?;
        let expected = match &self.operation {
            PreparedOperationV1::EnsureDirectory { .. }
            | PreparedOperationV1::PlaceFile { .. }
            | PreparedOperationV1::PlaceSymlink { .. }
            | PreparedOperationV1::PlaceTree { .. } => {
                Some(journal.created_identity.ok_or_else(|| {
                    CommitError::InvalidJournal(
                        "placed target has no journaled identity before publication".to_owned(),
                    )
                })?)
            }
            PreparedOperationV1::AssertExact { .. } => {
                let LeafObservationV1::Present(expected) = self.operation.observation().leaf()
                else {
                    return Err(CommitError::InvalidJournal(
                        "exact target assertion has no observed leaf identity".to_owned(),
                    ));
                };
                Some(expected)
            }
            PreparedOperationV1::RemoveLeaf { .. } | PreparedOperationV1::AssertAbsent { .. } => {
                None
            }
        };
        let Some(expected) = expected else {
            if !self.pending.is_empty() {
                // The absent pending head proves that the leaf below it is
                // still absent.
                return self.require_pending_head_absent();
            }
            return require_entry_absent(&self.parent, &self.leaf, path);
        };
        let pinned = openat2(
            &self.parent,
            &self.leaf,
            OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
            ROOT_RESOLVE_FLAGS,
        )
        .map(File::from)
        .map_err(|source| io_error("pin applied transaction target", path, source))?;
        let stat = require_pinned_entry(
            &self.parent,
            &self.leaf,
            &pinned,
            path,
            "applied transaction target",
        )?;
        match self.operation {
            // Child operations may legitimately change a directory's times,
            // size, and link count. For an asserted directory, bind the same
            // object with the expected owner and mode; each child operation
            // verifies its own state. Non-directories must keep their complete
            // identity.
            PreparedOperationV1::AssertExact { .. }
                if FileType::from_raw_mode(expected.mode) == FileType::Directory =>
            {
                compare_created_identity(&stat, expected, "applied exact target")
            }
            PreparedOperationV1::AssertExact { .. } => {
                compare_identity(&stat, expected, "applied exact target")
            }
            _ => compare_created_identity(&stat, expected, "applied transaction target"),
        }
    }

    pub(crate) fn revalidate_bindings_for_recovery(
        &self,
        store: &StoreHandles,
    ) -> Result<(), CommitError> {
        self.chain.ensure_bound(&self.authority_path)?;
        let mut current = self.root.as_ref();
        for (leaf, pinned) in &self.ancestors {
            let bound = statat(current, leaf, AtFlags::SYMLINK_NOFOLLOW).map_err(|source| {
                io_error("revalidate recovery ancestor", &self.authority_path, source)
            })?;
            let pinned_stat = fstat(pinned).map_err(|source| {
                io_error("inspect recovery ancestor", &self.authority_path, source)
            })?;
            if !same_object(&bound, &pinned_stat) {
                return Err(CommitError::StaleTarget(
                    "target ancestor binding changed during recovery".to_owned(),
                ));
            }
            current = pinned;
        }
        let parent = fstat(&self.parent)
            .map_err(|source| io_error("inspect recovery parent", &self.authority_path, source))?;
        compare_object_identity(&parent, self.parent_object, "recovery parent")?;
        reject_protected_traversal_directory(store, &self.parent, &self.parent_path)?;
        if self.pending.is_empty() {
            self.revalidate_directory_leaf(store)
        } else {
            Ok(())
        }
    }

    pub(crate) fn temporary_name(&self, suffix: &str) -> OsString {
        let digest = &self.plan_id.as_str()[3..];
        OsString::from(format!(".malm-{digest}-{}-{suffix}", self.index))
    }

    pub(crate) fn require_staging_absent(&self) -> Result<(), CommitError> {
        let path = self
            .authority_path
            .join(self.operation.observation().relative_path());
        match self.operation {
            PreparedOperationV1::EnsureDirectory { .. } => {
                require_entry_absent(&self.parent, &self.temporary_name("new-dir"), &path)?;
                require_entry_absent(&self.parent, &self.temporary_name("backup"), &path)?;
                require_entry_absent(&self.parent, &self.temporary_name("delete-created"), &path)?;
                require_entry_absent(&self.parent, &self.temporary_name("delete-backup"), &path)
            }
            PreparedOperationV1::PlaceFile { .. } => {
                require_entry_absent(&self.parent, &self.temporary_name("new"), &path)?;
                require_entry_absent(&self.parent, &self.temporary_name("backup"), &path)?;
                require_entry_absent(&self.parent, &self.temporary_name("delete-created"), &path)?;
                require_entry_absent(&self.parent, &self.temporary_name("delete-backup"), &path)
            }
            PreparedOperationV1::PlaceSymlink { .. } => {
                require_entry_absent(&self.parent, &self.temporary_name("new-link"), &path)?;
                require_entry_absent(&self.parent, &self.temporary_name("backup"), &path)?;
                require_entry_absent(&self.parent, &self.temporary_name("delete-created"), &path)?;
                require_entry_absent(&self.parent, &self.temporary_name("delete-backup"), &path)
            }
            PreparedOperationV1::PlaceTree { .. } => {
                require_entry_absent(&self.parent, &self.temporary_name("new-tree"), &path)?;
                require_entry_absent(&self.parent, &self.temporary_name("backup"), &path)?;
                require_entry_absent(&self.parent, &self.temporary_name("delete-created"), &path)?;
                require_entry_absent(&self.parent, &self.temporary_name("delete-backup"), &path)
            }
            PreparedOperationV1::RemoveLeaf { .. } => {
                require_entry_absent(&self.parent, &self.temporary_name("backup"), &path)?;
                require_entry_absent(&self.parent, &self.temporary_name("delete-backup"), &path)
            }
            PreparedOperationV1::AssertAbsent { .. } | PreparedOperationV1::AssertExact { .. } => {
                Ok(())
            }
        }
    }
}
