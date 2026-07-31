//! Applies immutable `store/v1` records without using the online engine.

#![forbid(unsafe_code)]

#[cfg(all(feature = "failpoints", not(debug_assertions)))]
compile_error!("the `failpoints` feature must not be enabled in release builds");

mod canonical;
#[cfg(feature = "failpoints")]
mod failpoint;
macro_rules! commit_failpoint {
    ($name:expr) => {
        #[cfg(feature = "failpoints")]
        crate::failpoint::hit($name);
        #[cfg(not(feature = "failpoints"))]
        let _ = $name;
    };
}

mod inspection;
mod object_load;
mod pack_object;
mod path_safety;
mod retention;
mod target;

use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    ffi::{OsStr, OsString},
    fmt,
    fs::File,
    io::{self, Read, Seek, SeekFrom, Write},
    os::unix::ffi::OsStrExt,
    path::{Component, Path, PathBuf},
    sync::Arc,
};

use malm_store::{
    FileIdentityV1, LeafObservationV1, OwnershipClaimV1, OwnershipOverlapKindV1,
    OwnershipProjectionError, OwnershipProjectionV1, PreparedOperationV1, PreparedRecordV1,
    PreparedTransitionV1, RestorePointV1, RetentionAuthorityV1, StateCatalogV1, StateGenerationV1,
    StateTargetStateV1, decode_state_catalog_v1, encode_prepared_record_v1,
    encode_state_catalog_v1, encode_state_generation_v1, prepared_id_v1,
    reconcile_desired_snapshot_v1, state_catalog_digest_v1, state_generation_digest_v1,
};
use malm_types::{
    ApplyOutcomeV1, ArtifactId, CommitRequestV1, DeploymentName, Digest, NamespaceName, PreparedId,
    PruneOutcomeV1, PruneRequestV1, RecoveryOutcomeV1, RetentionObjectV1, StateViewV1,
};
use rustix::fs::{
    AtFlags, Dir, FileType, FlockOperation, Mode, OFlags, RenameFlags, ResolveFlags, Stat, fchmod,
    flock, fstat, fsync, linkat, mkdirat, openat, openat2, readlinkat, renameat_with, statat,
    symlinkat, unlinkat,
};
use serde::de::{SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use sha2::{Digest as ShaDigest, Sha256};

pub(crate) use crate::object_load::load_canonical_state_objects;
use crate::object_load::{
    CanonicalLoadBudget, charge_canonical_load_bytes, charge_canonical_load_item,
    invalid_canonical_object, load_all_artifacts, load_canonical_objects,
    load_canonical_roots_with_budget, load_canonical_state_objects_with_budget, load_prepared,
    load_prepared_with_encoded_len, read_canonical_object,
};
use crate::path_safety::{
    PinnedChain, directory_contains, directory_is_mount_alias_of, io_error, normalize_absolute,
    overlaps, prove_safe_existing_directory_leaf, reject_protected_traversal_directory,
    same_object, same_snapshot,
};
use crate::retention::{
    decode_pack_manifest_members, directory_names, prune_store, record_pack_roots, verify_blob,
    verify_pack_object,
};
use crate::target::{CommitPinCache, CreatedDirectories, PinnedTarget};

const DIRECTORY_FLAGS: OFlags = OFlags::RDONLY
    .union(OFlags::DIRECTORY)
    .union(OFlags::CLOEXEC);
const ROOT_DIRECTORY_FLAGS: OFlags = OFlags::PATH
    .union(OFlags::DIRECTORY)
    .union(OFlags::CLOEXEC)
    .union(OFlags::NOFOLLOW);
const RESOLVE_FLAGS: ResolveFlags = ResolveFlags::BENEATH
    .union(ResolveFlags::NO_SYMLINKS)
    .union(ResolveFlags::NO_MAGICLINKS);
const ROOT_RESOLVE_FLAGS: ResolveFlags = RESOLVE_FLAGS.union(ResolveFlags::NO_XDEV);
const CONTAINER_MODE: u32 = 0o700;
const IMMUTABLE_MODE: u32 = 0o400;
const MUTABLE_MODE: u32 = 0o600;
const MAX_RETENTION_ENTRIES: usize = 1_000_000;
const MAX_RETENTION_DECODED_BYTES: u64 = 512 * 1024 * 1024;
const MAX_TRANSACTION_JOURNAL_BYTES: usize = 56 * 1024 * 1024;
const MAX_SELECTED_GENERATION_LINEAGE: usize = 65_536;
const MAX_SELECTED_GENERATION_BYTES: usize = 64 * 1024 * 1024;
const MAX_LINEAGE_VALIDATION_BYTES: usize = 512 * 1024 * 1024;
const MAX_OWNERSHIP_PINNED_DESCRIPTORS: u64 = 4_096;
const MAX_TARGET_PINNED_DESCRIPTORS: u64 = 4_096;
const TARGET_DESCRIPTOR_RESERVE: u64 = 64;

type LoadedArtifacts = BTreeMap<ArtifactId, Arc<[u8]>>;

/// Filesystem authorities and resource limits used by offline commits.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommitConfig {
    state_root: PathBuf,
    effective_user_id: u32,
    open_file_soft_limit: Option<u64>,
    target_authorities: BTreeMap<DeploymentName, PathBuf>,
}

impl CommitConfig {
    pub fn new(
        state_root: impl Into<PathBuf>,
        effective_user_id: u32,
        open_file_soft_limit: Option<u64>,
    ) -> Result<Self, CommitConfigError> {
        let state_root = state_root.into();
        malm_root::validate_injected_root(&state_root)
            .map_err(CommitConfigError::InvalidStateRoot)?;
        Ok(Self {
            state_root,
            effective_user_id,
            open_file_soft_limit,
            target_authorities: BTreeMap::new(),
        })
    }

    pub fn with_target_authority(
        mut self,
        authority: DeploymentName,
        path: impl Into<PathBuf>,
    ) -> Result<Self, CommitConfigError> {
        let path = normalize_absolute(path.into())?;
        if path.starts_with(&self.state_root) {
            return Err(CommitConfigError::TargetInsideState(authority));
        }
        if self
            .target_authorities
            .insert(authority.clone(), path)
            .is_some()
        {
            return Err(CommitConfigError::DuplicateTargetAuthority(authority));
        }
        Ok(self)
    }

    #[must_use]
    pub fn state_root(&self) -> &Path {
        &self.state_root
    }
}

/// Error returned when commit authorities cannot be configured safely.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CommitConfigError {
    InvalidStateRoot(malm_root::RootPathError),
    PathMustBeAbsolute(PathBuf),
    FilesystemRootNotAllowed,
    PathEscapesRoot(PathBuf),
    TargetInsideState(DeploymentName),
    DuplicateTargetAuthority(DeploymentName),
}

impl fmt::Display for CommitConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidStateRoot(source) => write!(formatter, "invalid state root: {source}"),
            Self::PathMustBeAbsolute(path) => {
                write!(
                    formatter,
                    "commit authority must be absolute: {}",
                    path.display()
                )
            }
            Self::FilesystemRootNotAllowed => {
                formatter.write_str("filesystem root cannot be a commit authority")
            }
            Self::PathEscapesRoot(path) => {
                write!(
                    formatter,
                    "commit authority escapes above filesystem root: {}",
                    path.display()
                )
            }
            Self::TargetInsideState(authority) => {
                write!(
                    formatter,
                    "target authority {authority} is inside protected state"
                )
            }
            Self::DuplicateTargetAuthority(authority) => {
                write!(
                    formatter,
                    "target authority {authority} is configured twice"
                )
            }
        }
    }
}

impl Error for CommitConfigError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::InvalidStateRoot(source) => Some(source),
            _ => None,
        }
    }
}

/// Fail-closed error from an offline commit, recovery, prune, or inspection.
#[derive(Debug)]
#[non_exhaustive]
pub enum CommitError {
    ReadOnlyStore,
    Busy,
    InvalidStore(String),
    MissingPlan(PreparedId),
    PlanInUse(PreparedId),
    InvalidPlan(String),
    ApprovalPlanMismatch,
    ApprovalFindingsMismatch,
    StaleNamespaceHead {
        namespace: NamespaceName,
        expected: Option<Digest>,
        actual: Option<Digest>,
    },
    TargetOwnershipConflict {
        requesting_namespace: NamespaceName,
        owning_namespace: NamespaceName,
        requesting_authority: Box<DeploymentName>,
        owning_authority: Box<DeploymentName>,
        requested_path: String,
        owned_path: String,
        overlap: OwnershipOverlapKindV1,
    },
    UnownedTargetMutation {
        namespace: NamespaceName,
        authority: DeploymentName,
        relative_path: String,
    },
    MissingArtifact(Digest),
    CorruptArtifact {
        expected: Digest,
        actual: Digest,
    },
    UnknownTargetAuthority(DeploymentName),
    UnsafeTarget(String),
    StaleTarget(String),
    StaleInspection,
    RollbackFailed(String),
    RecoveryRequired,
    InvalidJournal(String),
    Io {
        operation: &'static str,
        path: PathBuf,
        source: io::Error,
    },
}

impl CommitError {
    /// Converts a displayable error into an invalid-store error.
    pub fn invalid_store(error: impl fmt::Display) -> Self {
        Self::InvalidStore(error.to_string())
    }

    /// Converts a displayable error into an invalid-plan error.
    pub fn invalid_plan(error: impl fmt::Display) -> Self {
        Self::InvalidPlan(error.to_string())
    }
}

impl fmt::Display for CommitError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ReadOnlyStore => formatter.write_str("store is configured read-only"),
            Self::Busy => formatter.write_str("another v1 commit owns the transaction lock"),
            Self::InvalidStore(reason) => write!(formatter, "invalid store: {reason}"),
            Self::MissingPlan(plan) => write!(formatter, "prepared plan {plan} is missing"),
            Self::PlanInUse(plan) => {
                write!(
                    formatter,
                    "prepared plan {plan} is retained by catalog-selected state"
                )
            }
            Self::InvalidPlan(reason) => write!(formatter, "invalid prepared plan: {reason}"),
            Self::ApprovalPlanMismatch => formatter.write_str("approval names another plan"),
            Self::ApprovalFindingsMismatch => {
                formatter.write_str("approval does not match the plan's required findings")
            }
            Self::StaleNamespaceHead {
                namespace,
                expected,
                actual,
            } => write!(
                formatter,
                "namespace {namespace} head is stale: expected {expected:?}, found {actual:?}"
            ),
            Self::TargetOwnershipConflict {
                requesting_namespace,
                owning_namespace,
                requesting_authority,
                owning_authority,
                requested_path,
                owned_path,
                overlap,
            } => write!(
                formatter,
                "namespace {requesting_namespace} target {requesting_authority}:{requested_path} has an {overlap} ownership conflict with namespace {owning_namespace} target {owning_authority}:{owned_path}"
            ),
            Self::UnownedTargetMutation {
                namespace,
                authority,
                relative_path,
            } => write!(
                formatter,
                "namespace {namespace} cannot mutate unowned target {authority}:{relative_path}"
            ),
            Self::MissingArtifact(digest) => write!(formatter, "artifact {digest} is missing"),
            Self::CorruptArtifact { expected, actual } => write!(
                formatter,
                "artifact digest mismatch: expected {expected}, computed {actual}"
            ),
            Self::UnknownTargetAuthority(authority) => {
                write!(formatter, "target authority {authority} is not configured")
            }
            Self::UnsafeTarget(reason) => write!(formatter, "unsafe target: {reason}"),
            Self::StaleTarget(reason) => write!(formatter, "stale target: {reason}"),
            Self::StaleInspection => {
                formatter.write_str("store authority changed during read-only inspection")
            }
            Self::RollbackFailed(reason) => write!(formatter, "commit rollback failed: {reason}"),
            Self::RecoveryRequired => {
                formatter.write_str("an incomplete v1 transaction requires recovery")
            }
            Self::InvalidJournal(reason) => {
                write!(formatter, "invalid transaction journal: {reason}")
            }
            Self::Io {
                operation,
                path,
                source,
            } => {
                write!(formatter, "{operation} {}: {source}", path.display())
            }
        }
    }
}

impl Error for CommitError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}

/// Applies immutable prepared records using only verified data from the local
/// store.
pub struct Committer {
    config: CommitConfig,
}

impl fmt::Debug for Committer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Committer")
            .field("config", &self.config)
            .finish()
    }
}

impl Committer {
    #[must_use]
    pub const fn new(config: CommitConfig) -> Self {
        Self { config }
    }

    /// Publishes the canonical empty catalog for a new store.
    pub fn initialize_catalog_v1(&self) -> Result<(), CommitError> {
        let mut store = StoreHandles::open(&self.config)?;
        let transaction_lock = match preflight_catalog_initialization(&store)? {
            CatalogInitialization::MissingFromNonempty => {
                // A nonempty state directory without a catalog is valid only
                // while an existing initializer holds the published lock. Do
                // not create a new lock that would legitimize a malformed
                // store.
                TransactionLock::acquire_existing_blocking(&store)?
                    .ok_or_else(missing_state_catalog_error)?
            }
            CatalogInitialization::Empty | CatalogInitialization::Ready(_) => {
                commit_failpoint!("v1.initialize.before_lock");
                TransactionLock::acquire_blocking(&store)?
            }
        };
        store.refresh_optional_children()?;
        store.revalidate()?;
        transaction_lock.revalidate(&store)?;
        if load_journal(&store)?.is_some() {
            return Err(CommitError::RecoveryRequired);
        }
        match preflight_catalog_initialization(&store)? {
            CatalogInitialization::Ready(catalog) => {
                publish_initial_catalog(&store, &catalog)?;
                transaction_lock.revalidate(&store)?;
                return Ok(());
            }
            CatalogInitialization::MissingFromNonempty => {
                return Err(missing_state_catalog_error());
            }
            CatalogInitialization::Empty => {}
        }
        store.ensure_state_container()?;
        let catalog = StateCatalogV1::new(Vec::new()).map_err(CommitError::invalid_store)?;
        publish_initial_catalog(&store, &catalog)?;
        transaction_lock.revalidate(&store)?;
        Ok(())
    }

    /// Returns a namespace head without intentionally updating access times.
    pub fn inspect_state_v1(&self, namespace: &NamespaceName) -> Result<StateViewV1, CommitError> {
        let store = StoreHandles::open(&self.config)?;
        let catalog = read_catalog(&store)?;
        let head = catalog.generation(namespace).cloned();
        store.revalidate()?;
        Ok(StateViewV1::new(namespace.clone(), head))
    }

    /// Loads a retained immutable generation and verifies its prepared
    /// transition.
    pub fn inspect_generation_v1(
        &self,
        generation: &Digest,
    ) -> Result<StateGenerationV1, CommitError> {
        let store = StoreHandles::open(&self.config)?;
        let record = load_generation(&store, generation)?;
        validate_generation_transition(&store, &record)?;
        store.revalidate()?;
        Ok(record)
    }

    /// Loads the namespace head and up to `limit` retained predecessors in one
    /// store session.
    ///
    /// Each returned generation receives the same transition validation as
    /// [`Self::inspect_generation_v1`].
    pub fn inspect_lineage_v1(
        &self,
        namespace: &NamespaceName,
        limit: usize,
    ) -> Result<Vec<(Digest, StateGenerationV1)>, CommitError> {
        let store = StoreHandles::open(&self.config)?;
        let catalog = read_catalog(&store)?;
        let mut current = catalog.generation(namespace).cloned();
        let mut lineage = Vec::new();
        while let Some(digest) = current {
            if lineage.len() == limit {
                break;
            }
            let record = load_generation(&store, &digest)?;
            validate_generation_transition(&store, &record)?;
            current = record.previous_generation().cloned();
            lineage.push((digest, record));
        }
        store.revalidate()?;
        Ok(lineage)
    }

    /// Verifies a candidate plan against the ownership derived from the current
    /// catalog.
    pub fn validate_prepared_ownership_v1(
        &self,
        plan_id: &PreparedId,
        prepared: &PreparedRecordV1,
    ) -> Result<(), CommitError> {
        if prepared_id_v1(prepared) != *plan_id {
            return Err(CommitError::InvalidPlan(
                "prepared plan identity differs from its canonical record".to_owned(),
            ));
        }
        validate_descriptor_budget(&self.config, prepared)?;
        let store = StoreHandles::open(&self.config)?;
        let catalog = read_catalog(&store)?;
        derive_owned_transition(&self.config, &store, &catalog, plan_id, prepared)?;
        store.revalidate()
    }

    /// Returns cached file identities for one exact namespace generation,
    /// keyed by `authority:relative_path`.
    ///
    /// A live [`FileIdentityV1`] equal to the cached identity proves that the
    /// file still has the paired digest: every userspace modification changes
    /// `ctime`, and userspace cannot choose a `ctime` value. The cache is only
    /// an optimization. This returns `None` if the cache is absent, invalid,
    /// stale, or belongs to another generation.
    #[must_use]
    pub fn observed_identities_v1(
        &self,
        namespace: &NamespaceName,
        generation: &Digest,
    ) -> Option<BTreeMap<String, (FileIdentityV1, Digest)>> {
        let store = StoreHandles::open(&self.config).ok()?;
        let observed = read_observed_identities(&store)?;
        let files = observed_files_for(Some(&observed), namespace, generation)?;
        Some(
            files
                .into_iter()
                .map(|(key, entry)| (key, (entry.identity, entry.digest)))
                .collect(),
        )
    }

    /// Recovers an incomplete transaction to either its prior state or the
    /// exact prepared state selected by the published catalog.
    pub fn recover_v1(&self) -> Result<RecoveryOutcomeV1, CommitError> {
        let mut store = StoreHandles::open(&self.config)?;
        let transaction_lock = TransactionLock::acquire(&store)?;
        store.refresh_optional_children()?;
        store.revalidate()?;
        transaction_lock.revalidate(&store)?;
        let catalog = read_catalog(&store)?;
        load_catalog_ownership(&self.config, &store, &catalog)?;
        let Some(loaded) = load_journal(&store)? else {
            require_catalog_staging_absent(&store)?;
            return Ok(RecoveryOutcomeV1::NoTransaction);
        };
        let journal = &loaded.journal;
        let prepared = load_prepared(&store, &journal.plan_id)?;
        validate_journal(&store, &prepared, journal)?;
        let position = validate_journal_catalog_transition(&catalog, journal)?;
        validate_catalog_staging(&store, journal)?;
        match position {
            CatalogPosition::Next => {
                validate_roll_forward_journal(&prepared, journal)?;
                finish_recovery(&self.config, &store, &prepared, journal)?;
            }
            CatalogPosition::Previous => {
                rollback_recovery(&self.config, &store, &prepared, journal)?;
            }
        }
        store.revalidate()?;
        transaction_lock.revalidate(&store)?;
        remove_journal(&store)?;
        let catalog = read_catalog(&store)?;
        let expected_catalog = match position {
            CatalogPosition::Previous => &journal.previous_catalog,
            CatalogPosition::Next => &journal.next_catalog,
        };
        if state_catalog_digest_v1(&catalog) != *expected_catalog {
            return Err(CommitError::InvalidJournal(
                "catalog changed while recovery finalized".to_owned(),
            ));
        }
        Ok(RecoveryOutcomeV1::recovered(
            journal.namespace.clone(),
            catalog.generation(&journal.namespace).cloned(),
        ))
    }

    /// Removes only selected plans that are not in use, plus stored objects
    /// unreachable from retained state.
    pub fn prune_v1(&self, request: &PruneRequestV1) -> Result<PruneOutcomeV1, CommitError> {
        self.prune_with_mode_v1(request, false)
    }

    /// Computes the same reference-aware result as [`Self::prune_v1`] without
    /// removing anything.
    pub fn preview_prune_v1(
        &self,
        request: &PruneRequestV1,
    ) -> Result<PruneOutcomeV1, CommitError> {
        self.prune_with_mode_v1(request, true)
    }

    fn prune_with_mode_v1(
        &self,
        request: &PruneRequestV1,
        dry_run: bool,
    ) -> Result<PruneOutcomeV1, CommitError> {
        let mut store = StoreHandles::open(&self.config)?;
        let transaction_lock = if dry_run {
            TransactionLock::acquire_existing(&store)?
        } else {
            TransactionLock::acquire(&store)?
        };
        let maintenance_lock = if dry_run {
            MaintenanceLock::acquire_existing(&store)?
        } else {
            Some(MaintenanceLock::acquire(&store)?)
        };
        store.refresh_optional_children()?;
        store.revalidate()?;
        transaction_lock.revalidate(&store)?;
        if let Some(maintenance_lock) = &maintenance_lock {
            maintenance_lock.revalidate(&store)?;
        }
        if load_journal(&store)?.is_some() {
            return Err(CommitError::RecoveryRequired);
        }
        require_catalog_staging_absent(&store)?;
        let outcome = prune_store(&self.config, &store, request, dry_run)?;
        transaction_lock.revalidate(&store)?;
        if let Some(maintenance_lock) = &maintenance_lock {
            maintenance_lock.revalidate(&store)?;
        } else if MaintenanceLock::acquire_existing(&store)?.is_some() {
            return Err(CommitError::StaleInspection);
        }
        Ok(outcome)
    }

    /// Applies one exact approved plan while holding the global transaction
    /// lock.
    pub fn commit_v1(&self, request: &CommitRequestV1) -> Result<ApplyOutcomeV1, CommitError> {
        if request.approval().plan_id() != request.plan_id() {
            return Err(CommitError::ApprovalPlanMismatch);
        }
        let mut store = StoreHandles::open(&self.config)?;
        let transaction_lock = TransactionLock::acquire(&store)?;
        store.refresh_optional_children()?;
        if load_journal(&store)?.is_some() {
            return Err(CommitError::RecoveryRequired);
        }
        require_catalog_staging_absent(&store)?;
        store.revalidate()?;
        transaction_lock.revalidate(&store)?;
        let prepared = load_prepared(&store, request.plan_id())?;
        if request.approval().findings_digest() != prepared.approval_digest() {
            return Err(CommitError::ApprovalFindingsMismatch);
        }
        validate_descriptor_budget(&self.config, &prepared)?;
        let previous_catalog = read_catalog(&store)?;
        let OwnedTransition {
            namespace,
            previous,
            generation,
            generation_digest,
            next_catalog,
        } = derive_owned_transition(
            &self.config,
            &store,
            &previous_catalog,
            request.plan_id(),
            &prepared,
        )?;
        let previous_record = previous
            .as_ref()
            .map(|digest| load_generation(&store, digest))
            .transpose()?;
        let blobs = load_all_artifacts(&store, &prepared)?;
        let canonical = load_canonical_objects(&store, &prepared, previous_record.as_ref())?;
        let mut pin_cache = CommitPinCache::default();
        let mut targets = prepared
            .operations()
            .iter()
            .enumerate()
            .map(|(index, operation)| {
                PinnedTarget::open(
                    &mut pin_cache,
                    &self.config,
                    &store,
                    request.plan_id(),
                    index,
                    operation.clone(),
                    prior_target_state(previous_record.as_ref(), operation),
                )
            })
            .collect::<Result<Vec<_>, _>>()?;
        reject_overlapping_target_authorities(&targets)?;
        // A cached identity can prove that an asserted file is unchanged since
        // the previous commit. Any missing or mismatched cache entry falls back
        // to reading and verifying the content.
        let observed = previous.as_ref().and_then(|head| {
            observed_files_for(read_observed_identities(&store).as_ref(), &namespace, head)
        });
        store.revalidate()?;
        parallel_targets(&targets, |target| {
            target.revalidate(&store)?;
            target.verify_prior_state(&canonical, observed.as_ref())
        })?;
        commit_failpoint!("v1.commit.after_preflight");

        let mut journal = TransactionJournalV1 {
            schema_version: 1,
            namespace: namespace.clone(),
            plan_id: request.plan_id().clone(),
            previous_catalog: state_catalog_digest_v1(&previous_catalog),
            next_catalog: state_catalog_digest_v1(&next_catalog),
            previous_generation: previous.clone(),
            next_generation: generation_digest.clone(),
            operations: vec![JournalOperationV1::default(); targets.len()],
        };
        store.ensure_commit_containers()?;
        for target in &targets {
            target.revalidate(&store)?;
        }
        transaction_lock.revalidate(&store)?;
        publish_journal(&store, &journal)?;
        commit_failpoint!("v1.commit.after_journal");

        // Run directory, symlink, tree, and absence operations first. File
        // placements and removals use the phased schedule below so their
        // watcher-visible renames happen in one short burst.
        let mutation_result = (|targets: &mut Vec<PinnedTarget>,
                                journal: &mut TransactionJournalV1|
         -> Result<(), CommitError> {
            for index in 0..targets.len() {
                if !matches!(
                    targets[index].operation,
                    PreparedOperationV1::EnsureDirectory { .. }
                        | PreparedOperationV1::PlaceSymlink { .. }
                        | PreparedOperationV1::PlaceTree { .. }
                        | PreparedOperationV1::AssertAbsent { .. }
                ) {
                    continue;
                }
                store.revalidate()?;
                commit_failpoint!("v1.commit.before_operation");
                targets[index].revalidate(&store)?;
                targets[index].apply(&blobs, &canonical, &store, journal)?;
                store.revalidate()?;
                complete_pending_pins(targets, index, &store)?;
                refresh_expected_parents(targets, index)?;
                commit_failpoint!("v1.commit.after_operation");
            }

            // Phase A creates and syncs anonymous replacement files, records
            // all created identities in one durable journal update, links the
            // temporary names, and then syncs every affected parent.
            store.revalidate()?;
            // Check for external races before recording any phased-operation
            // identity. An operation with an empty journal record is known not
            // to have touched its target and needs no rollback. The canonical
            // operations above are excluded because they already changed their
            // leaves legitimately.
            for target in targets.iter() {
                if matches!(
                    target.operation,
                    PreparedOperationV1::EnsureDirectory { .. }
                        | PreparedOperationV1::PlaceSymlink { .. }
                        | PreparedOperationV1::PlaceTree { .. }
                ) {
                    continue;
                }
                // Every phased mutation must now have a pinned parent because
                // earlier directory operations created all planned ancestors.
                // A removal or absence assertion may remain below an ancestor
                // the plan never creates; that missing ancestor proves the
                // leaf is absent.
                if !target.pending.is_empty()
                    && !matches!(
                        target.operation,
                        PreparedOperationV1::RemoveLeaf { .. }
                            | PreparedOperationV1::AssertAbsent { .. }
                    )
                {
                    return Err(CommitError::InvalidPlan(
                        "target ancestors were never created by the plan".to_owned(),
                    ));
                }
                target.revalidate(&store)?;
            }
            parallel_targets_mut(targets, |target| target.stage_file_creation(&blobs))?;
            let mut staged_any = false;
            for target in targets.iter() {
                if let Some(staged) = target.staged.as_ref() {
                    target.stage_created_identity(journal, staged.identity);
                    staged_any = true;
                }
            }
            if staged_any {
                replace_journal(&store, journal)?;
            }
            commit_failpoint!("v1.commit.place.after_identity");
            for target in targets.iter_mut() {
                target.link_staged_file(&store)?;
            }
            sync_unique_parents(targets, |target| target.staged.is_some())?;
            commit_failpoint!("v1.commit.place.after_staging");
            refresh_all_expected_parents(targets)?;

            // Phase B pins each prior leaf and publishes all backup intents in
            // one durable journal update before any backup rename.
            store.revalidate()?;
            let mut intents = false;
            for target in targets.iter_mut() {
                if let Some(digest) = target.pin_replacement_source(&canonical, &store)? {
                    target.stage_backup_intent(journal, digest)?;
                    intents = true;
                }
            }
            if intents {
                replace_journal(&store, journal)?;
            }
            commit_failpoint!("v1.commit.place.after_backup_intent");
            commit_failpoint!("v1.commit.remove.after_backup_intent");

            // Phase C performs the visible burst in durability order: rename
            // old leaves to backup names, sync all parents, identify and
            // journal every backup, rename staged files into place, then sync
            // all parents again. No unrelated work runs between these renames.
            for target in targets.iter_mut() {
                target.rename_to_backup(&store)?;
            }
            sync_unique_parents(targets, |target| target.pinned_source.is_some())?;
            commit_failpoint!("v1.commit.place.after_backup_sync");
            commit_failpoint!("v1.commit.remove.after_backup_sync");
            let mut identified = false;
            for target in targets.iter_mut() {
                if let Some(identity) = target.identify_backup(&canonical)? {
                    target.stage_backup_identity(journal, identity)?;
                    identified = true;
                }
            }
            if identified {
                replace_journal(&store, journal)?;
            }
            commit_failpoint!("v1.commit.place.after_backup");
            commit_failpoint!("v1.commit.remove.after_backup");
            for target in targets.iter_mut() {
                target.rename_into_place(&store, journal)?;
            }
            sync_unique_parents(targets, |target| target.staged.is_some())?;
            refresh_all_expected_parents(targets)?;
            commit_failpoint!("v1.commit.burst.after_final_sync");
            Ok(())
        })(&mut targets, &mut journal);
        if let Err(error) = mutation_result {
            return Err(phase_failure(
                error,
                &mut targets,
                &blobs,
                &canonical,
                &journal,
                &store,
            ));
        }

        // Target verification is independent. Parallel execution still reports
        // the first error in target order, matching sequential behavior.
        let verified: Result<(), CommitError> = {
            const MIN_PARALLEL_ITEMS: usize = 16;
            if targets.len() < MIN_PARALLEL_ITEMS {
                targets
                    .iter_mut()
                    .zip(&journal.operations)
                    .try_for_each(|(target, operation)| {
                        target.verify_applied(
                            &store,
                            &blobs,
                            &canonical,
                            operation,
                            observed.as_ref(),
                        )
                    })
            } else {
                let workers = std::thread::available_parallelism()
                    .map(std::num::NonZeroUsize::get)
                    .unwrap_or(1)
                    .clamp(1, targets.len());
                let chunk_len = targets.len().div_ceil(workers).max(1);
                let store = &store;
                let blobs = &blobs;
                let canonical = &canonical;
                let observed = observed.as_ref();
                let mut results: Vec<Result<(), CommitError>> = std::thread::scope(|scope| {
                    let handles = targets
                        .chunks_mut(chunk_len)
                        .zip(journal.operations.chunks(chunk_len))
                        .map(|(target_chunk, operation_chunk)| {
                            scope.spawn(move || {
                                target_chunk
                                    .iter_mut()
                                    .zip(operation_chunk)
                                    .map(|(target, operation)| {
                                        target.verify_applied(
                                            store, blobs, canonical, operation, observed,
                                        )
                                    })
                                    .collect::<Vec<_>>()
                            })
                        })
                        .collect::<Vec<_>>();
                    handles
                        .into_iter()
                        .flat_map(|handle| handle.join().expect("verify worker never panics"))
                        .collect()
                });
                results.drain(..).collect()
            }
        };
        if let Err(error) = verified {
            if let Err(reason) =
                rollback_targets(&mut targets, &blobs, &canonical, &journal.operations)
            {
                return Err(CommitError::RollbackFailed(reason));
            }
            remove_journal(&store)?;
            return Err(error);
        }

        // After state publication starts, ordinary rollback is no longer safe.
        // An I/O error may be reported after the catalog rename reached the
        // filesystem, so only recovery may choose the prior or next state.
        transaction_lock.revalidate(&store)?;
        publish_generation_and_catalog(
            &store,
            generation_digest.as_ref(),
            generation.as_ref(),
            &previous_catalog,
            &next_catalog,
        )?;
        for (target, operation) in targets.iter_mut().zip(&journal.operations) {
            if !matches!(&target.operation, PreparedOperationV1::AssertExact { .. }) {
                target.finish_incomplete(&store, &blobs, &canonical, operation)?;
            }
            commit_failpoint!("v1.commit.after_finalize");
        }
        transaction_lock.revalidate(&store)?;
        remove_journal(&store)?;
        commit_failpoint!("v1.commit.after_journal_removed");
        // The observed-identity cache is optional; failure only causes later
        // commits to hash content again.
        let _ = record_observed_identities(
            &store,
            &targets,
            &namespace,
            generation_digest.as_ref().zip(generation.as_ref()),
            &canonical,
        );
        match generation_digest {
            Some(generation_digest) => Ok(ApplyOutcomeV1::new(
                request.plan_id().clone(),
                namespace,
                previous,
                generation_digest,
            )),
            None => Ok(ApplyOutcomeV1::removed(
                request.plan_id().clone(),
                namespace,
                previous.expect("namespace removal requires a predecessor"),
            )),
        }
    }
}

struct OwnedTransition {
    namespace: NamespaceName,
    previous: Option<Digest>,
    generation: Option<StateGenerationV1>,
    generation_digest: Option<Digest>,
    next_catalog: StateCatalogV1,
}

struct CatalogOwnership {
    selected: Vec<(NamespaceName, StateGenerationV1)>,
    projection: OwnershipProjectionV1,
}

fn derive_owned_transition(
    config: &CommitConfig,
    store: &StoreHandles,
    previous_catalog: &StateCatalogV1,
    plan_id: &PreparedId,
    prepared: &PreparedRecordV1,
) -> Result<OwnedTransition, CommitError> {
    let namespace = prepared.namespace().clone();
    let previous = previous_catalog.generation(&namespace).cloned();
    if previous.as_ref() != prepared.expected_head() {
        return Err(CommitError::StaleNamespaceHead {
            namespace,
            expected: prepared.expected_head().cloned(),
            actual: previous,
        });
    }
    let CatalogOwnership {
        mut selected,
        projection: current_projection,
    } = load_catalog_ownership(config, store, previous_catalog)?;
    for operation in prepared.operations() {
        if matches!(operation, PreparedOperationV1::AssertAbsent { .. }) {
            continue;
        }
        let observation = operation.observation();
        if let Some(claim) = current_projection.conflicting_claim(
            observation.authority(),
            observation.relative_path(),
            &namespace,
        ) {
            let overlap = if claim.relative_path() == observation.relative_path() {
                OwnershipOverlapKindV1::Exact
            } else {
                OwnershipOverlapKindV1::AncestorDescendant
            };
            return Err(CommitError::TargetOwnershipConflict {
                requesting_namespace: namespace,
                owning_namespace: claim.namespace().clone(),
                requesting_authority: Box::new(observation.authority().clone()),
                owning_authority: Box::new(claim.authority().clone()),
                requested_path: observation.relative_path().to_owned(),
                owned_path: claim.relative_path().to_owned(),
                overlap,
            });
        }
        let requires_exact_owner = match operation {
            PreparedOperationV1::RemoveLeaf { .. } => true,
            PreparedOperationV1::EnsureDirectory { .. } => {
                matches!(observation.leaf(), LeafObservationV1::Present(_))
            }
            // A replacing placement may adopt a present leaf with no namespace
            // owner because prepare requires approval for replacing it. The
            // conflict check above still rejects another namespace's claim,
            // and a non-replacing placement still requires exact ownership.
            // A directory cannot be adopted because its contents have no
            // managed manifest to prove what would be destroyed; it must be
            // moved aside explicitly.
            PreparedOperationV1::PlaceFile { .. }
            | PreparedOperationV1::PlaceSymlink { .. }
            | PreparedOperationV1::PlaceTree { .. } => match observation.leaf() {
                LeafObservationV1::Absent => false,
                LeafObservationV1::Present(identity) => {
                    !operation.replaces_existing()
                        || FileType::from_raw_mode(identity.mode) == FileType::Directory
                }
            },
            PreparedOperationV1::AssertExact {
                state: StateTargetStateV1::Directory { directory: Some(_) },
                ..
            } => !prepared.operations().iter().any(|candidate| {
                candidate.observation().authority() == observation.authority()
                    && candidate
                        .observation()
                        .relative_path()
                        .strip_prefix(observation.relative_path())
                        .is_some_and(|suffix| suffix.starts_with('/'))
            }),
            PreparedOperationV1::AssertExact { .. } => true,
            PreparedOperationV1::AssertAbsent { .. } => false,
        };
        if requires_exact_owner
            && current_projection.exact_owner(observation.authority(), observation.relative_path())
                != Some(&namespace)
        {
            return Err(CommitError::UnownedTargetMutation {
                namespace,
                authority: observation.authority().clone(),
                relative_path: observation.relative_path().to_owned(),
            });
        }
    }

    let previous_record = selected
        .iter()
        .find(|(selected_namespace, _)| selected_namespace == &namespace)
        .map(|(_, generation)| generation);
    malm_store::validate_prepared_transition_v1(previous_record, prepared)
        .map_err(CommitError::invalid_plan)?;
    let mut canonical_budget = CanonicalLoadBudget::default();
    validate_transition_references(store, previous_record, prepared, &mut canonical_budget)?;
    if matches!(
        prepared.transition(),
        PreparedTransitionV1::NamespaceRemoval { .. }
    ) {
        selected.retain(|(selected_namespace, _)| selected_namespace != &namespace);
        let next_projection = OwnershipProjectionV1::from_selected_generations(
            selected
                .iter()
                .map(|(selected_namespace, generation)| (selected_namespace, generation)),
        )
        .map_err(|error| candidate_ownership_error(&namespace, error))?;
        reject_projection_authority_aliases(
            config,
            store,
            &next_projection,
            Some(&namespace),
            false,
        )?;
        let mut next_catalog = previous_catalog.clone();
        if next_catalog.remove_head(&namespace) != previous {
            return Err(CommitError::InvalidPlan(
                "namespace-removal catalog predecessor changed".to_owned(),
            ));
        }
        validate_catalog_lineages(store, &next_catalog, None, LineageDepth::Routine)
            .map_err(candidate_catalog_validation_error)?;
        validate_catalog_retention_authorities(store, &next_catalog, None, &mut canonical_budget)
            .map_err(candidate_catalog_validation_error)?;
        return Ok(OwnedTransition {
            namespace,
            previous,
            generation: None,
            generation_digest: None,
            next_catalog,
        });
    }

    let generation = StateGenerationV1::from_prepared(
        plan_id.clone(),
        previous.clone(),
        previous_record,
        prepared,
    )
    .map_err(CommitError::invalid_plan)?;
    let candidate_generation_bytes = encode_state_generation_v1(&generation).len();
    let generation_digest = state_generation_digest_v1(&generation);
    if let Some((_, selected_generation)) = selected
        .iter_mut()
        .find(|(selected_namespace, _)| selected_namespace == &namespace)
    {
        *selected_generation = generation.clone();
    } else {
        selected.push((namespace.clone(), generation.clone()));
    }
    let next_projection = OwnershipProjectionV1::from_selected_generations(
        selected
            .iter()
            .map(|(selected_namespace, generation)| (selected_namespace, generation)),
    )
    .map_err(|error| candidate_ownership_error(&namespace, error))?;
    reject_projection_authority_aliases(config, store, &next_projection, Some(&namespace), false)?;

    let mut next_catalog = previous_catalog.clone();
    next_catalog
        .update_head(namespace.clone(), generation_digest.clone())
        .map_err(CommitError::invalid_plan)?;
    let candidate = CandidateGeneration {
        digest: &generation_digest,
        generation: &generation,
        prepared,
        encoded_bytes: candidate_generation_bytes,
    };
    validate_catalog_lineages(store, &next_catalog, Some(candidate), LineageDepth::Routine)
        .map_err(candidate_catalog_validation_error)?;
    validate_catalog_retention_authorities(
        store,
        &next_catalog,
        Some(candidate),
        &mut canonical_budget,
    )
    .map_err(candidate_catalog_validation_error)?;
    Ok(OwnedTransition {
        namespace,
        previous,
        generation: Some(generation),
        generation_digest: Some(generation_digest),
        next_catalog,
    })
}

fn validate_transition_references(
    store: &StoreHandles,
    previous: Option<&StateGenerationV1>,
    prepared: &PreparedRecordV1,
    canonical_budget: &mut CanonicalLoadBudget,
) -> Result<(), CommitError> {
    validate_added_retention_references(
        store,
        previous.map(StateGenerationV1::retention_authority),
        prepared.retention_authority(),
        canonical_budget,
    )?;
    let source = match prepared.transition() {
        PreparedTransitionV1::Enable { restore_point } => {
            Some((restore_point.generation(), Some(restore_point)))
        }
        PreparedTransitionV1::Checkout { source_generation } => Some((source_generation, None)),
        PreparedTransitionV1::Reconcile
        | PreparedTransitionV1::Disable
        | PreparedTransitionV1::RetentionAuthority
        | PreparedTransitionV1::NamespaceRemoval { .. } => None,
    };
    if let Some((digest, restore_point)) = source {
        let generation = load_generation(store, digest)?;
        validate_generation_transition(store, &generation)?;
        if generation.namespace() != prepared.namespace() {
            return Err(CommitError::InvalidPlan(
                "transition source generation belongs to another namespace".to_owned(),
            ));
        }
        if let Some(point) = restore_point {
            validate_restore_point_reference(point, digest, &generation)?;
            if generation.lifecycle_state() != malm_store::LifecycleStateV1::Enabled
                || generation.desired_snapshot() != prepared.desired_snapshot()
                || generation.tracked_root() != prepared.tracked_root()
            {
                return Err(CommitError::InvalidPlan(
                    "enable does not exactly reproduce its retained restore generation".to_owned(),
                ));
            }
        } else {
            let expected_snapshot =
                if generation.lifecycle_state() == malm_store::LifecycleStateV1::Disabled {
                    malm_store::DesiredSnapshotV1::empty()
                } else {
                    let current = prepared
                        .expected_head()
                        .ok_or_else(|| {
                            CommitError::InvalidPlan(
                                "checkout requires a selected current generation".to_owned(),
                            )
                        })
                        .and_then(|digest| load_generation(store, digest))?;
                    reconcile_desired_snapshot_v1(
                        Some(current.desired_snapshot()),
                        generation.desired_snapshot().targets().to_vec(),
                    )
                    .map_err(CommitError::invalid_plan)?
                };
            if generation.lifecycle_state() != prepared.lifecycle_state()
                || &expected_snapshot != prepared.desired_snapshot()
                || generation.restore_point() != prepared.restore_point()
                || generation.tracked_root() != prepared.tracked_root()
            {
                return Err(CommitError::InvalidPlan(
                    "checkout does not reproduce its retained source generation with cumulative tombstones"
                        .to_owned(),
                ));
            }
        }
    }
    Ok(())
}

fn candidate_catalog_validation_error(error: CommitError) -> CommitError {
    match error {
        CommitError::InvalidStore(reason) => {
            CommitError::InvalidPlan(format!("candidate catalog retention is invalid: {reason}"))
        }
        error => error,
    }
}

fn validate_catalog_retention_authorities(
    store: &StoreHandles,
    catalog: &StateCatalogV1,
    candidate: Option<CandidateGeneration<'_>>,
    canonical_budget: &mut CanonicalLoadBudget,
) -> Result<(), CommitError> {
    let mut decoded_bytes = 0;
    for head in catalog.heads() {
        let selected_candidate =
            candidate.filter(|candidate| candidate.digest == head.generation());
        let generation = match selected_candidate {
            Some(candidate) => candidate.generation.clone(),
            _ => load_generation(store, head.generation())?,
        };
        if generation.namespace() != head.namespace() {
            return Err(CommitError::InvalidStore(
                "catalog retention authority belongs to another namespace".to_owned(),
            ));
        }
        for point in generation.retention_authority().restore_points() {
            let retained = validate_directly_retained_generation(
                store,
                point.generation(),
                &mut decoded_bytes,
            )?;
            validate_restore_point_reference(point, point.generation(), &retained)?;
            validate_retained_generation_dependencies(store, &retained, canonical_budget)?;
        }
        for pin in generation.retention_authority().explicit_pins() {
            match pin {
                RetentionObjectV1::StateGeneration { digest } => {
                    let retained =
                        validate_directly_retained_generation(store, digest, &mut decoded_bytes)?;
                    if retained.namespace() != generation.namespace() {
                        return Err(CommitError::InvalidPlan(
                            "retention pin selects another namespace generation".to_owned(),
                        ));
                    }
                    validate_retained_generation_dependencies(store, &retained, canonical_budget)?;
                }
                pin => validate_retention_pin(store, pin, canonical_budget)?,
            }
        }
    }
    Ok(())
}

fn validate_directly_retained_generation(
    store: &StoreHandles,
    digest: &Digest,
    decoded_bytes: &mut usize,
) -> Result<StateGenerationV1, CommitError> {
    let (generation, encoded_bytes) = load_generation_with_encoded_len(store, digest)?;
    charge_lineage_validation_bytes(decoded_bytes, encoded_bytes)?;
    validate_retained_generation_transition_with_budget(store, &generation, decoded_bytes)
        .map_err(state_generation_validation_error)?;
    Ok(generation)
}

fn validate_added_retention_references(
    store: &StoreHandles,
    previous: Option<&RetentionAuthorityV1>,
    next: &RetentionAuthorityV1,
    canonical_budget: &mut CanonicalLoadBudget,
) -> Result<(), CommitError> {
    for point in next.restore_points() {
        let unchanged = previous.is_some_and(|authority| {
            authority
                .restore_points()
                .binary_search_by(|candidate| candidate.generation().cmp(point.generation()))
                .is_ok_and(|index| &authority.restore_points()[index] == point)
        });
        if unchanged {
            continue;
        }
        let mut decoded_bytes = 0;
        let generation =
            validate_directly_retained_generation(store, point.generation(), &mut decoded_bytes)?;
        validate_restore_point_reference(point, point.generation(), &generation)?;
        validate_retained_generation_dependencies(store, &generation, canonical_budget)?;
    }
    for pin in next.explicit_pins() {
        if previous.is_some_and(|authority| authority.explicit_pins().binary_search(pin).is_ok()) {
            continue;
        }
        validate_retention_pin(store, pin, canonical_budget)?;
    }
    Ok(())
}

fn validate_retention_pin(
    store: &StoreHandles,
    pin: &RetentionObjectV1,
    canonical_budget: &mut CanonicalLoadBudget,
) -> Result<(), CommitError> {
    match pin {
        RetentionObjectV1::PreparedPlan { plan_id } => {
            validate_retained_prepared_dependencies(store, plan_id, canonical_budget)?;
        }
        RetentionObjectV1::StateGeneration { digest } => {
            let mut decoded_bytes = 0;
            let generation =
                validate_directly_retained_generation(store, digest, &mut decoded_bytes)?;
            validate_retained_generation_dependencies(store, &generation, canonical_budget)?;
        }
        RetentionObjectV1::ArtifactBlob { digest } => {
            verify_blob(store, digest)?;
        }
        RetentionObjectV1::PackObject { digest } => {
            verify_pack_object(store, digest)?;
        }
        RetentionObjectV1::CanonicalFile { digest } => {
            charge_canonical_load_item(canonical_budget)?;
            let bytes = read_canonical_object(
                store,
                store.files.as_ref(),
                "files",
                digest,
                canonical::MAX_FILE_OBJECT_BYTES,
            )?;
            charge_canonical_load_bytes(canonical_budget, bytes.len())?;
            canonical::decode_file(digest, &bytes)
                .map_err(|error| invalid_canonical_object("file", digest, error))?;
        }
        RetentionObjectV1::CanonicalSymlink { digest } => {
            load_canonical_roots_with_budget(
                store,
                BTreeSet::new(),
                BTreeSet::from([digest.clone()]),
                canonical_budget,
            )?;
        }
        RetentionObjectV1::CanonicalTree { digest } => {
            load_canonical_roots_with_budget(
                store,
                BTreeSet::from([digest.clone()]),
                BTreeSet::new(),
                canonical_budget,
            )?;
        }
    }
    Ok(())
}

fn validate_retained_generation_dependencies(
    store: &StoreHandles,
    generation: &StateGenerationV1,
    canonical_budget: &mut CanonicalLoadBudget,
) -> Result<(), CommitError> {
    validate_retained_prepared_dependencies(store, generation.plan_id(), canonical_budget)?;
    validate_retained_snapshot_dependencies(
        store,
        generation.desired_snapshot(),
        canonical_budget,
    )?;
    if let Some(tracked) = generation.tracked_root() {
        load_canonical_roots_with_budget(
            store,
            BTreeSet::from([tracked.root_tree_digest().clone()]),
            BTreeSet::new(),
            canonical_budget,
        )?;
    }
    Ok(())
}

fn validate_retained_prepared_dependencies(
    store: &StoreHandles,
    plan_id: &PreparedId,
    canonical_budget: &mut CanonicalLoadBudget,
) -> Result<(), CommitError> {
    let prepared = load_prepared(store, plan_id)?;
    validate_prepared_dependencies(store, &prepared, canonical_budget)
}

fn validate_prepared_dependencies(
    store: &StoreHandles,
    prepared: &PreparedRecordV1,
    canonical_budget: &mut CanonicalLoadBudget,
) -> Result<(), CommitError> {
    load_all_artifacts(store, prepared)?;
    validate_retained_snapshot_dependencies(store, prepared.desired_snapshot(), canonical_budget)?;
    for digest in record_pack_roots(prepared) {
        verify_pack_object(store, &digest)?;
    }
    if let Some(tracked) = prepared.tracked_root() {
        load_canonical_roots_with_budget(
            store,
            BTreeSet::from([tracked.root_tree_digest().clone()]),
            BTreeSet::new(),
            canonical_budget,
        )?;
    }
    Ok(())
}

fn validate_retained_snapshot_dependencies(
    store: &StoreHandles,
    snapshot: &malm_store::DesiredSnapshotV1,
    canonical_budget: &mut CanonicalLoadBudget,
) -> Result<(), CommitError> {
    let mut verified_blobs = BTreeSet::new();
    for target in snapshot.targets() {
        let StateTargetStateV1::File { file: Some(file) } = target.state() else {
            continue;
        };
        if !verified_blobs.insert(file.digest()) {
            continue;
        }
        let length = verify_blob(store, file.digest())?;
        if length != file.byte_len() {
            return Err(CommitError::InvalidStore(
                "retained target length differs from its state metadata".to_owned(),
            ));
        }
    }
    load_canonical_state_objects_with_budget(
        store,
        snapshot.targets().iter().map(|target| target.state()),
        canonical_budget,
    )?;
    Ok(())
}

fn validate_restore_point_reference(
    point: &RestorePointV1,
    digest: &Digest,
    generation: &StateGenerationV1,
) -> Result<(), CommitError> {
    if point.generation() != digest
        || point.namespace() != generation.namespace()
        || point.lifecycle() != generation.lifecycle_state()
        || point.desired_snapshot_digest() != generation.desired_snapshot_digest()
        || point.tracked_root() != generation.tracked_root()
    {
        return Err(CommitError::InvalidPlan(
            "restore point differs from its retained generation".to_owned(),
        ));
    }
    Ok(())
}

fn load_selected_generations(
    store: &StoreHandles,
    catalog: &StateCatalogV1,
) -> Result<(Vec<(NamespaceName, StateGenerationV1)>, usize), CommitError> {
    let mut selected = Vec::with_capacity(catalog.heads().len());
    let mut decoded_bytes = 0_usize;
    let mut target_slots = 0_usize;
    for head in catalog.heads() {
        let (generation, encoded_bytes) =
            load_generation_with_encoded_len(store, head.generation())?;
        charge_selected_generation_bytes(&mut decoded_bytes, encoded_bytes)?;
        target_slots = target_slots.saturating_add(generation.targets().len());
        if target_slots > malm_store::MAX_OWNERSHIP_TARGET_SLOTS {
            return Err(CommitError::InvalidStore(format!(
                "selected ownership target slots exceed {} entries",
                malm_store::MAX_OWNERSHIP_TARGET_SLOTS
            )));
        }
        if generation.namespace() != head.namespace() {
            return Err(CommitError::InvalidStore(format!(
                "catalog namespace {} selects a generation for namespace {}",
                head.namespace(),
                generation.namespace()
            )));
        }
        selected.push((head.namespace().clone(), generation));
    }
    Ok((selected, decoded_bytes))
}

fn charge_selected_generation_bytes(total: &mut usize, bytes: usize) -> Result<(), CommitError> {
    *total = total.saturating_add(bytes);
    if *total > MAX_SELECTED_GENERATION_BYTES {
        return Err(CommitError::InvalidStore(format!(
            "selected generation records exceed {MAX_SELECTED_GENERATION_BYTES} bytes"
        )));
    }
    Ok(())
}

#[derive(Clone, Copy)]
struct CandidateGeneration<'a> {
    digest: &'a Digest,
    generation: &'a StateGenerationV1,
    prepared: &'a PreparedRecordV1,
    encoded_bytes: usize,
}

fn validate_candidate_generation_transition_with_budget(
    store: &StoreHandles,
    candidate: CandidateGeneration<'_>,
    retained_floor: bool,
    decoded_bytes: &mut usize,
) -> Result<(), CommitError> {
    charge_lineage_validation_bytes(
        decoded_bytes,
        encode_prepared_record_v1(candidate.prepared).len(),
    )?;
    let rebuilt = if retained_floor {
        StateGenerationV1::from_retained_prepared(
            candidate.generation.plan_id().clone(),
            candidate.generation.previous_generation().cloned(),
            candidate.prepared,
        )
    } else {
        let previous = candidate
            .generation
            .previous_generation()
            .map(|digest| {
                let (generation, encoded_bytes) = load_generation_with_encoded_len(store, digest)?;
                charge_lineage_validation_bytes(decoded_bytes, encoded_bytes)?;
                Ok::<_, CommitError>(generation)
            })
            .transpose()?;
        StateGenerationV1::from_prepared(
            candidate.generation.plan_id().clone(),
            candidate.generation.previous_generation().cloned(),
            previous.as_ref(),
            candidate.prepared,
        )
    }
    .map_err(CommitError::invalid_store)?;
    if &rebuilt != candidate.generation {
        return Err(CommitError::InvalidStore(
            "candidate state generation does not match its prepared transition".to_owned(),
        ));
    }
    Ok(())
}

/// Selects the amount of retained history checked during lineage validation.
#[derive(Clone, Copy, Eq, PartialEq)]
enum LineageDepth {
    /// Checks each head and its immediate predecessor, which are the links a
    /// routine prepare or commit can extend. Older records are immutable and
    /// content-addressed, so `fsck` is responsible for rechecking the complete
    /// retained history.
    Routine,
    /// Checks the complete retained chain, including cycles and the transition
    /// at the retention boundary.
    Full,
}

fn validate_catalog_lineages(
    store: &StoreHandles,
    catalog: &StateCatalogV1,
    candidate: Option<CandidateGeneration<'_>>,
    depth: LineageDepth,
) -> Result<(), CommitError> {
    let mut validated = BTreeMap::<Digest, NamespaceName>::new();
    let mut traversed = 0_usize;
    let mut decoded_bytes = 0_usize;
    let mut selected_bytes = 0_usize;
    for head in catalog.heads() {
        let mut current = Some(head.generation().clone());
        let mut lineage = BTreeSet::new();
        let mut selected_head = true;
        let mut retained_limit = None;
        let mut retained_count = 0_u32;
        while let Some(digest) = current {
            if !lineage.insert(digest.clone()) {
                return Err(CommitError::InvalidStore(format!(
                    "namespace {} generation history contains a cycle",
                    head.namespace()
                )));
            }
            if let Some(namespace) = validated.get(&digest) {
                if namespace != head.namespace() {
                    return Err(CommitError::InvalidStore(format!(
                        "generation {digest} is shared by namespace {namespace} and namespace {}",
                        head.namespace()
                    )));
                }
                break;
            }
            if traversed == MAX_SELECTED_GENERATION_LINEAGE {
                return Err(CommitError::InvalidStore(format!(
                    "selected generation history exceeds {MAX_SELECTED_GENERATION_LINEAGE} entries"
                )));
            }
            let selected_candidate = candidate.filter(|candidate| candidate.digest == &digest);
            let (generation, encoded_bytes) = match selected_candidate {
                Some(candidate) => (candidate.generation.clone(), candidate.encoded_bytes),
                _ => load_generation_with_encoded_len(store, &digest)?,
            };
            charge_lineage_validation_bytes(&mut decoded_bytes, encoded_bytes)?;
            if selected_head {
                charge_selected_generation_bytes(&mut selected_bytes, encoded_bytes)?;
                selected_head = false;
            }
            if generation.namespace() != head.namespace() {
                return Err(CommitError::InvalidStore(format!(
                    "namespace {} history enters generation {digest} for namespace {}",
                    head.namespace(),
                    generation.namespace()
                )));
            }
            let limit = *retained_limit
                .get_or_insert_with(|| generation.retention_authority().history().generations());
            retained_count = retained_count.saturating_add(1);
            if depth == LineageDepth::Routine
                && retained_count == 2
                && generation.retention_authority().history().generations() == limit
            {
                // Once the head and predecessor are valid and agree on the
                // retention limit, routine validation can stop because older
                // records are immutable and content-addressed. If the limit
                // changed, continue the walk: an expanded limit promises that
                // deeper records are actually retained and valid.
                if let Some(candidate) = selected_candidate {
                    validate_candidate_generation_transition_with_budget(
                        store,
                        candidate,
                        false,
                        &mut decoded_bytes,
                    )
                    .map_err(state_generation_validation_error)?;
                }
                current = None;
                continue;
            }
            if retained_count == limit {
                if let Some(candidate) = selected_candidate {
                    validate_candidate_generation_transition_with_budget(
                        store,
                        candidate,
                        true,
                        &mut decoded_bytes,
                    )
                    .map_err(state_generation_validation_error)?;
                } else {
                    validate_retained_generation_transition_with_budget(
                        store,
                        &generation,
                        &mut decoded_bytes,
                    )
                    .map_err(state_generation_validation_error)?;
                }
                current = None;
            } else {
                if let Some(candidate) = selected_candidate {
                    validate_candidate_generation_transition_with_budget(
                        store,
                        candidate,
                        false,
                        &mut decoded_bytes,
                    )
                    .map_err(state_generation_validation_error)?;
                } else {
                    validate_generation_transition_with_budget(
                        store,
                        &generation,
                        &mut decoded_bytes,
                    )
                    .map_err(state_generation_validation_error)?;
                }
                current = generation.previous_generation().cloned();
            }
            validated.insert(digest, head.namespace().clone());
            traversed += 1;
        }
    }
    Ok(())
}

fn charge_lineage_validation_bytes(total: &mut usize, bytes: usize) -> Result<(), CommitError> {
    *total = total.saturating_add(bytes);
    if *total > MAX_LINEAGE_VALIDATION_BYTES {
        return Err(CommitError::InvalidStore(format!(
            "selected lineage validation exceeds {MAX_LINEAGE_VALIDATION_BYTES} decoded bytes"
        )));
    }
    Ok(())
}

fn load_catalog_ownership(
    config: &CommitConfig,
    store: &StoreHandles,
    catalog: &StateCatalogV1,
) -> Result<CatalogOwnership, CommitError> {
    let (selected, _) = load_selected_generations(store, catalog)?;
    let projection = OwnershipProjectionV1::from_selected_generations(
        selected
            .iter()
            .map(|(selected_namespace, generation)| (selected_namespace, generation)),
    )
    .map_err(CommitError::invalid_store)?;
    if let Err(error) = reject_projection_authority_aliases(config, store, &projection, None, false)
    {
        return Err(match error {
            CommitError::TargetOwnershipConflict { .. } => {
                CommitError::InvalidStore(error.to_string())
            }
            error => error,
        });
    }
    Ok(CatalogOwnership {
        selected,
        projection,
    })
}

fn candidate_ownership_error(
    namespace: &NamespaceName,
    error: OwnershipProjectionError,
) -> CommitError {
    match error {
        OwnershipProjectionError::Conflict {
            overlap,
            authority,
            first_namespace,
            first_path,
            second_namespace,
            second_path,
        } if &first_namespace == namespace => CommitError::TargetOwnershipConflict {
            requesting_namespace: first_namespace,
            owning_namespace: second_namespace,
            requesting_authority: Box::new(authority.clone()),
            owning_authority: Box::new(authority),
            requested_path: first_path,
            owned_path: second_path,
            overlap,
        },
        OwnershipProjectionError::Conflict {
            overlap,
            authority,
            first_namespace,
            first_path,
            second_namespace,
            second_path,
        } if &second_namespace == namespace => CommitError::TargetOwnershipConflict {
            requesting_namespace: second_namespace,
            owning_namespace: first_namespace,
            requesting_authority: Box::new(authority.clone()),
            owning_authority: Box::new(authority),
            requested_path: second_path,
            owned_path: first_path,
            overlap,
        },
        OwnershipProjectionError::Conflict { .. } => CommitError::InvalidStore(error.to_string()),
        OwnershipProjectionError::NamespaceMismatch { .. } => {
            CommitError::InvalidStore(error.to_string())
        }
        OwnershipProjectionError::TooManyClaims { .. } => {
            CommitError::InvalidPlan(error.to_string())
        }
        _ => CommitError::InvalidPlan(error.to_string()),
    }
}

struct ProjectedAuthority<'a> {
    authority: &'a DeploymentName,
    path: PathBuf,
    chain: PinnedChain,
    claims: Vec<&'a OwnershipClaimV1>,
}

fn reject_projection_authority_aliases(
    config: &CommitConfig,
    store: &StoreHandles,
    projection: &OwnershipProjectionV1,
    requesting_namespace: Option<&NamespaceName>,
    allow_unconfigured: bool,
) -> Result<(), CommitError> {
    validate_projection_descriptor_budget(
        config,
        projection,
        requesting_namespace,
        allow_unconfigured,
    )?;
    let mut authorities = Vec::<ProjectedAuthority<'_>>::new();
    for claim in projection.claims() {
        if let Some(current) = authorities.last_mut()
            && current.authority == claim.authority()
        {
            current.claims.push(claim);
            continue;
        }
        let Some(path) = config.target_authorities.get(claim.authority()).cloned() else {
            if allow_unconfigured {
                continue;
            }
            return Err(CommitError::UnknownTargetAuthority(
                claim.authority().clone(),
            ));
        };
        let chain = PinnedChain::open(&path)?;
        validate_target_directory(chain.directory(), &path, config.effective_user_id)?;
        reject_protected_traversal_directory(store, chain.directory(), &path)?;
        authorities.push(ProjectedAuthority {
            authority: claim.authority(),
            path,
            chain,
            claims: vec![claim],
        });
    }

    for left_index in 0..authorities.len() {
        for right_index in left_index + 1..authorities.len() {
            let left = &authorities[left_index];
            let right = &authorities[right_index];
            if !authority_roots_overlap(&left.chain, &left.path, &right.chain, &right.path)? {
                continue;
            }
            let left_requested = requesting_namespace.and_then(|namespace| {
                left.claims
                    .iter()
                    .copied()
                    .find(|claim| claim.namespace() == namespace)
            });
            let right_requested = requesting_namespace.and_then(|namespace| {
                right
                    .claims
                    .iter()
                    .copied()
                    .find(|claim| claim.namespace() == namespace)
            });
            let (requesting, owning) = if let Some(requesting) = left_requested {
                (requesting, right.claims[0])
            } else if let Some(requesting) = right_requested {
                (requesting, left.claims[0])
            } else {
                (right.claims[0], left.claims[0])
            };
            return Err(CommitError::TargetOwnershipConflict {
                requesting_namespace: requesting.namespace().clone(),
                owning_namespace: owning.namespace().clone(),
                requesting_authority: Box::new(requesting.authority().clone()),
                owning_authority: Box::new(owning.authority().clone()),
                requested_path: requesting.relative_path().to_owned(),
                owned_path: owning.relative_path().to_owned(),
                overlap: OwnershipOverlapKindV1::PhysicalAuthorityAlias,
            });
        }
    }
    Ok(())
}

fn validate_projection_descriptor_budget(
    config: &CommitConfig,
    projection: &OwnershipProjectionV1,
    requesting_namespace: Option<&NamespaceName>,
    allow_unconfigured: bool,
) -> Result<(), CommitError> {
    let mut required = 64_u64;
    let mut previous = None;
    for claim in projection.claims() {
        if previous == Some(claim.authority()) {
            continue;
        }
        previous = Some(claim.authority());
        let Some(path) = config.target_authorities.get(claim.authority()) else {
            if allow_unconfigured {
                continue;
            }
            return Err(CommitError::UnknownTargetAuthority(
                claim.authority().clone(),
            ));
        };
        let depth = path
            .components()
            .filter(|component| matches!(component, Component::Normal(_)))
            .count();
        required = required
            .checked_add(u64::try_from(depth + 1).unwrap_or(u64::MAX))
            .ok_or_else(|| projection_resource_error(requesting_namespace, u64::MAX, None))?;
    }

    if required > MAX_OWNERSHIP_PINNED_DESCRIPTORS {
        return Err(projection_resource_error(
            requesting_namespace,
            required,
            Some(MAX_OWNERSHIP_PINNED_DESCRIPTORS),
        ));
    }
    let soft_limit = config.open_file_soft_limit.unwrap_or(u64::MAX);
    let available = soft_limit.saturating_sub((soft_limit / 4).max(64));
    if required > available {
        return Err(projection_resource_error(
            requesting_namespace,
            required,
            Some(available),
        ));
    }
    Ok(())
}

fn projection_resource_error(
    requesting_namespace: Option<&NamespaceName>,
    required: u64,
    available: Option<u64>,
) -> CommitError {
    let detail = match available {
        Some(available) => format!(
            "ownership projection requires {required} pinned filesystem descriptors but only {available} are allowed"
        ),
        None => "ownership projection descriptor budget overflows".to_owned(),
    };
    if requesting_namespace.is_some() {
        CommitError::InvalidPlan(detail)
    } else {
        CommitError::InvalidStore(detail)
    }
}

fn authority_roots_overlap(
    left_chain: &PinnedChain,
    left_path: &Path,
    right_chain: &PinnedChain,
    right_path: &Path,
) -> Result<bool, CommitError> {
    Ok(
        directory_contains(left_chain.directory(), right_chain.directory(), right_path)?
            || directory_contains(right_chain.directory(), left_chain.directory(), left_path)?
            || directory_is_mount_alias_of(
                left_chain.directory(),
                left_path,
                right_chain.directory(),
                right_path,
            )?
            || directory_is_mount_alias_of(
                right_chain.directory(),
                right_path,
                left_chain.directory(),
                left_path,
            )?,
    )
}

fn reject_overlapping_target_authorities(targets: &[PinnedTarget]) -> Result<(), CommitError> {
    let mut authorities = Vec::<(&DeploymentName, &PinnedChain, &Path)>::new();
    for target in targets {
        let authority = target.operation.observation().authority();
        if authorities
            .iter()
            .all(|(existing, _, _)| *existing != authority)
        {
            authorities.push((authority, target.chain.as_ref(), &target.authority_path));
        }
    }
    for left in 0..authorities.len() {
        for right in left + 1..authorities.len() {
            let (_, left_chain, left_path) = authorities[left];
            let (_, right_chain, right_path) = authorities[right];
            if authority_roots_overlap(left_chain, left_path, right_chain, right_path)? {
                return Err(CommitError::InvalidPlan(
                    "distinct target authorities overlap physically".to_owned(),
                ));
            }
        }
    }
    Ok(())
}

fn validate_descriptor_budget(
    config: &CommitConfig,
    prepared: &PreparedRecordV1,
) -> Result<(), CommitError> {
    let DescriptorRequirement { directories, leaves } =
        target_descriptor_requirement(config, prepared)?;
    if directories > MAX_TARGET_PINNED_DESCRIPTORS {
        return Err(CommitError::InvalidPlan(format!(
            "plan requires {directories} pinned filesystem descriptors, exceeding the safety limit of {MAX_TARGET_PINNED_DESCRIPTORS}"
        )));
    }
    // The phased schedule holds every staged inode and every pinned prior leaf
    // open at the same time as the directory pins, so the process limit has to
    // cover the sum rather than the directory pins alone.
    let required = directories
        .checked_add(leaves)
        .ok_or_else(descriptor_budget_overflow)?;
    let soft_limit = config.open_file_soft_limit.unwrap_or(u64::MAX);
    let reserve = (soft_limit / 4).max(TARGET_DESCRIPTOR_RESERVE);
    if required > soft_limit.saturating_sub(reserve) {
        return Err(CommitError::InvalidPlan(format!(
            "plan requires {required} pinned filesystem descriptors but the process limit is {soft_limit}"
        )));
    }
    Ok(())
}

#[derive(Default)]
struct DescriptorAuthority {
    traversal_anchor: Option<FileIdentityV1>,
    prefixes: BTreeMap<String, FileIdentityV1>,
}

/// Descriptors a commit holds open at its peak. `directories` counts the
/// traversal and ancestor pins shared across targets; `leaves` counts the
/// per-operation descriptors the phased schedule holds alongside them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DescriptorRequirement {
    directories: u64,
    leaves: u64,
}

fn target_descriptor_requirement(
    config: &CommitConfig,
    prepared: &PreparedRecordV1,
) -> Result<DescriptorRequirement, CommitError> {
    let mut pinned = 0_u64;
    let mut leaves = 0_u64;
    let mut destinations = BTreeSet::new();
    let mut pending_prefixes = BTreeSet::new();
    let mut authorities = BTreeMap::<DeploymentName, DescriptorAuthority>::new();
    for operation in prepared.operations() {
        let observation = operation.observation();
        let authority_path = config
            .target_authorities
            .get(observation.authority())
            .ok_or_else(|| CommitError::UnknownTargetAuthority(observation.authority().clone()))?;
        if !destinations.insert((
            observation.authority().clone(),
            observation.relative_path().to_owned(),
        )) {
            return Err(CommitError::InvalidPlan(
                "target operation destinations are duplicated".to_owned(),
            ));
        }

        // Phase A stages one anonymous inode per file placement and holds it
        // until the burst renames it into place. Phase B pins the prior leaf
        // of every replacement and removal for the same span.
        let staged = u64::from(matches!(operation, PreparedOperationV1::PlaceFile { .. }));
        let prior = u64::from(
            matches!(
                operation,
                PreparedOperationV1::PlaceFile { .. } | PreparedOperationV1::RemoveLeaf { .. }
            ) && matches!(observation.leaf(), LeafObservationV1::Present(_)),
        );
        leaves = leaves
            .checked_add(staged)
            .and_then(|count| count.checked_add(prior))
            .ok_or_else(descriptor_budget_overflow)?;

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

        let authority = match authorities.entry(observation.authority().clone()) {
            std::collections::btree_map::Entry::Vacant(entry) => {
                let authority_depth = authority_path
                    .components()
                    .filter(|component| matches!(component, Component::Normal(_)))
                    .count();
                pinned = pinned
                    .checked_add(u64::try_from(authority_depth + 1).unwrap_or(u64::MAX))
                    .and_then(|count| count.checked_add(1))
                    .ok_or_else(descriptor_budget_overflow)?;
                let mut authority = DescriptorAuthority {
                    traversal_anchor: Some(observation.traversal_anchor()),
                    prefixes: BTreeMap::new(),
                };
                authority
                    .prefixes
                    .insert(String::new(), observation.traversal_anchor());
                entry.insert(authority)
            }
            std::collections::btree_map::Entry::Occupied(entry) => entry.into_mut(),
        };
        if authority.traversal_anchor != Some(observation.traversal_anchor()) {
            return Err(conflicting_target_observation("authority"));
        }

        if existing_segments.is_empty() {
            observe_descriptor_prefix(authority, "", observation.parent(), &mut pinned)?;
        }
        let mut prefix = String::new();
        for (position, segment) in existing_segments.iter().enumerate() {
            if !prefix.is_empty() {
                prefix.push('/');
            }
            prefix.push_str(segment);
            let expected = if position + 1 == existing_segments.len() {
                observation.parent()
            } else {
                observation.ancestors()[position]
            };
            observe_descriptor_prefix(authority, &prefix, expected, &mut pinned)?;
        }
        // Each unique pending prefix will require a descriptor after the plan
        // creates it. It has no identity to compare yet, but it must still be
        // reserved in the descriptor budget.
        for segment in &parent_segments[existing_segments.len()..] {
            if !prefix.is_empty() {
                prefix.push('/');
            }
            prefix.push_str(segment);
            let key = (observation.authority().clone(), prefix.clone());
            if pending_prefixes.insert(key) {
                pinned = pinned
                    .checked_add(1)
                    .ok_or_else(descriptor_budget_overflow)?;
            }
        }
    }
    Ok(DescriptorRequirement {
        directories: pinned,
        leaves,
    })
}

fn observe_descriptor_prefix(
    authority: &mut DescriptorAuthority,
    prefix: &str,
    expected: FileIdentityV1,
    pinned: &mut u64,
) -> Result<(), CommitError> {
    if let Some(previous) = authority.prefixes.get(prefix) {
        if *previous != expected {
            return Err(conflicting_target_observation("ancestor"));
        }
    } else {
        authority.prefixes.insert(prefix.to_owned(), expected);
        *pinned = pinned
            .checked_add(1)
            .ok_or_else(descriptor_budget_overflow)?;
    }
    Ok(())
}

fn conflicting_target_observation(role: &str) -> CommitError {
    CommitError::InvalidPlan(format!("target observations conflict for a shared {role}"))
}

fn descriptor_budget_overflow() -> CommitError {
    CommitError::InvalidPlan("target descriptor budget overflows".to_owned())
}

struct StoreHandles {
    root_chain: PinnedChain,
    root: File,
    prepared: Option<File>,
    objects: Option<File>,
    blobs: Option<File>,
    packs: Option<File>,
    pack_manifests: Option<File>,
    files: Option<File>,
    symlinks: Option<File>,
    trees: Option<File>,
    transactions: Option<File>,
    state: Option<File>,
    generations: Option<File>,
    root_path: PathBuf,
    uid: u32,
}

impl StoreHandles {
    fn open(config: &CommitConfig) -> Result<Self, CommitError> {
        let root_chain = PinnedChain::open(&config.state_root)?;
        root_chain.require_no_bind_mount_aliases(&config.state_root)?;
        let root = openat2(
            root_chain.directory(),
            ".",
            DIRECTORY_FLAGS | OFlags::NOFOLLOW | OFlags::NOATIME,
            Mode::empty(),
            RESOLVE_FLAGS,
        )
        .map(File::from)
        .map_err(|source| io_error("open store I/O handle", &config.state_root, source))?;
        validate_directory(
            &root,
            &config.state_root,
            config.effective_user_id,
            CONTAINER_MODE,
        )?;
        validate_store_descriptor(&root, &config.state_root, config.effective_user_id)?;
        validate_store_layout(&root, &config.state_root, config.effective_user_id)?;
        let prepared_path = config.state_root.join("prepared");
        let prepared =
            open_optional_container(&root, "prepared", &prepared_path, config.effective_user_id)?;
        let objects_path = config.state_root.join("objects");
        let objects =
            open_optional_container(&root, "objects", &objects_path, config.effective_user_id)?;
        let blobs = objects
            .as_ref()
            .map(|objects| {
                open_optional_container(
                    objects,
                    "blobs",
                    &objects_path.join("blobs"),
                    config.effective_user_id,
                )
            })
            .transpose()?
            .flatten();
        let packs = open_object_kind(
            objects.as_ref(),
            "packs",
            &objects_path.join("packs"),
            config.effective_user_id,
        )?;
        let pack_manifests = open_object_kind(
            objects.as_ref(),
            "pack-manifests",
            &objects_path.join("pack-manifests"),
            config.effective_user_id,
        )?;
        let files = open_object_kind(
            objects.as_ref(),
            "files",
            &objects_path.join("files"),
            config.effective_user_id,
        )?;
        let symlinks = open_object_kind(
            objects.as_ref(),
            "symlinks",
            &objects_path.join("symlinks"),
            config.effective_user_id,
        )?;
        let trees = open_object_kind(
            objects.as_ref(),
            "trees",
            &objects_path.join("trees"),
            config.effective_user_id,
        )?;
        let transactions = open_optional_container(
            &root,
            "transactions",
            &config.state_root.join("transactions"),
            config.effective_user_id,
        )?;
        let state_path = config.state_root.join("state");
        let state = open_optional_container(&root, "state", &state_path, config.effective_user_id)?;
        let generations = state
            .as_ref()
            .map(|state| {
                open_optional_container(
                    state,
                    "generations",
                    &state_path.join("generations"),
                    config.effective_user_id,
                )
            })
            .transpose()?
            .flatten();
        let result = Self {
            root_chain,
            root,
            prepared,
            objects,
            blobs,
            packs,
            pack_manifests,
            files,
            symlinks,
            trees,
            transactions,
            state,
            generations,
            root_path: config.state_root.clone(),
            uid: config.effective_user_id,
        };
        result.revalidate()?;
        Ok(result)
    }

    fn refresh_optional_children(&mut self) -> Result<(), CommitError> {
        self.prepared = open_optional_container(
            &self.root,
            "prepared",
            &self.root_path.join("prepared"),
            self.uid,
        )?;
        let objects = open_optional_container(
            &self.root,
            "objects",
            &self.root_path.join("objects"),
            self.uid,
        )?;
        self.blobs = objects
            .as_ref()
            .map(|objects| {
                open_optional_container(
                    objects,
                    "blobs",
                    &self.root_path.join("objects/blobs"),
                    self.uid,
                )
            })
            .transpose()?
            .flatten();
        self.packs = open_object_kind(
            objects.as_ref(),
            "packs",
            &self.root_path.join("objects/packs"),
            self.uid,
        )?;
        self.pack_manifests = open_object_kind(
            objects.as_ref(),
            "pack-manifests",
            &self.root_path.join("objects/pack-manifests"),
            self.uid,
        )?;
        self.files = open_object_kind(
            objects.as_ref(),
            "files",
            &self.root_path.join("objects/files"),
            self.uid,
        )?;
        self.symlinks = open_object_kind(
            objects.as_ref(),
            "symlinks",
            &self.root_path.join("objects/symlinks"),
            self.uid,
        )?;
        self.trees = open_object_kind(
            objects.as_ref(),
            "trees",
            &self.root_path.join("objects/trees"),
            self.uid,
        )?;
        self.objects = objects;
        self.transactions = open_optional_container(
            &self.root,
            "transactions",
            &self.root_path.join("transactions"),
            self.uid,
        )?;
        let state_path = self.root_path.join("state");
        self.state = open_optional_container(&self.root, "state", &state_path, self.uid)?;
        self.generations = self
            .state
            .as_ref()
            .map(|state| {
                open_optional_container(
                    state,
                    "generations",
                    &state_path.join("generations"),
                    self.uid,
                )
            })
            .transpose()?
            .flatten();
        Ok(())
    }

    fn ensure_commit_containers(&mut self) -> Result<(), CommitError> {
        let transactions_path = self.root_path.join("transactions");
        self.transactions = Some(open_or_create_container(
            &self.root,
            "transactions",
            &transactions_path,
            self.uid,
        )?);
        let state_path = self.root_path.join("state");
        let state = self
            .state
            .as_ref()
            .ok_or_else(|| CommitError::InvalidStore("state directory is not pinned".to_owned()))?;
        let generations_path = state_path.join("generations");
        self.generations = Some(open_or_create_container(
            state,
            "generations",
            &generations_path,
            self.uid,
        )?);
        self.revalidate()
    }

    fn ensure_state_container(&mut self) -> Result<(), CommitError> {
        let state_path = self.root_path.join("state");
        self.state = Some(open_or_create_container(
            &self.root,
            "state",
            &state_path,
            self.uid,
        )?);
        self.revalidate()
    }

    fn revalidate(&self) -> Result<(), CommitError> {
        self.root_chain.ensure_bound(&self.root_path)?;
        validate_state_parent_directory(
            self.root_chain.parent_directory(),
            self.root_path
                .parent()
                .expect("normalized root has a parent"),
            self.uid,
        )?;
        validate_directory(&self.root, &self.root_path, self.uid, CONTAINER_MODE)?;
        validate_store_descriptor(&self.root, &self.root_path, self.uid)?;
        validate_store_layout(&self.root, &self.root_path, self.uid)?;
        if let Some(prepared) = &self.prepared {
            ensure_bound(
                &self.root,
                "prepared",
                prepared,
                &self.root_path.join("prepared"),
                self.uid,
            )?;
        }
        if let Some(objects) = &self.objects {
            ensure_bound(
                &self.root,
                "objects",
                objects,
                &self.root_path.join("objects"),
                self.uid,
            )?;
        }
        if let Some(blobs) = &self.blobs {
            let objects = self.objects.as_ref().ok_or_else(|| {
                CommitError::InvalidStore("object family has no pinned objects parent".to_owned())
            })?;
            ensure_bound(
                objects,
                "blobs",
                blobs,
                &self.root_path.join("objects/blobs"),
                self.uid,
            )?;
        }
        for (name, directory) in [
            ("packs", self.packs.as_ref()),
            ("pack-manifests", self.pack_manifests.as_ref()),
            ("files", self.files.as_ref()),
            ("symlinks", self.symlinks.as_ref()),
            ("trees", self.trees.as_ref()),
        ] {
            if let Some(directory) = directory {
                let objects = self.objects.as_ref().ok_or_else(|| {
                    CommitError::InvalidStore(
                        "object family has no pinned objects parent".to_owned(),
                    )
                })?;
                ensure_bound(
                    objects,
                    name,
                    directory,
                    &self.root_path.join("objects").join(name),
                    self.uid,
                )?;
            }
        }
        if let Some(transactions) = &self.transactions {
            ensure_bound(
                &self.root,
                "transactions",
                transactions,
                &self.root_path.join("transactions"),
                self.uid,
            )?;
        }
        if let Some(state) = &self.state {
            let state_path = self.root_path.join("state");
            ensure_bound(&self.root, "state", state, &state_path, self.uid)?;
            if let Some(generations) = &self.generations {
                ensure_bound(
                    state,
                    "generations",
                    generations,
                    &state_path.join("generations"),
                    self.uid,
                )?;
            }
        } else if self.generations.is_some() {
            return Err(CommitError::InvalidStore(
                "generation directory has no pinned state parent".to_owned(),
            ));
        }
        Ok(())
    }
}

struct TransactionLock {
    file: File,
}

struct MaintenanceLock {
    file: File,
}

impl MaintenanceLock {
    fn acquire(store: &StoreHandles) -> Result<Self, CommitError> {
        acquire_lock(
            store,
            "maintenance.lock",
            "maintenance",
            FlockOperation::NonBlockingLockExclusive,
        )
        .map(|file| Self { file })
    }

    fn acquire_existing(store: &StoreHandles) -> Result<Option<Self>, CommitError> {
        acquire_existing_lock(
            store,
            "maintenance.lock",
            "maintenance",
            FlockOperation::NonBlockingLockExclusive,
        )
        .map(|file| file.map(|file| Self { file }))
    }

    fn revalidate(&self, store: &StoreHandles) -> Result<(), CommitError> {
        revalidate_lock(store, "maintenance.lock", &self.file)
    }
}

impl TransactionLock {
    fn acquire(store: &StoreHandles) -> Result<Self, CommitError> {
        acquire_lock(
            store,
            "transaction.lock",
            "transaction",
            FlockOperation::NonBlockingLockExclusive,
        )
        .map(|file| Self { file })
    }

    fn acquire_blocking(store: &StoreHandles) -> Result<Self, CommitError> {
        acquire_lock(
            store,
            "transaction.lock",
            "transaction",
            FlockOperation::LockExclusive,
        )
        .map(|file| Self { file })
    }

    fn acquire_existing_blocking(store: &StoreHandles) -> Result<Option<Self>, CommitError> {
        acquire_existing_lock(
            store,
            "transaction.lock",
            "transaction",
            FlockOperation::LockExclusive,
        )
        .map(|file| file.map(|file| Self { file }))
    }

    fn acquire_existing(store: &StoreHandles) -> Result<Self, CommitError> {
        acquire_existing_lock(
            store,
            "transaction.lock",
            "transaction",
            FlockOperation::NonBlockingLockExclusive,
        )?
        .map(|file| Self { file })
        .ok_or_else(|| CommitError::InvalidStore("transaction lock is missing".to_owned()))
    }

    fn revalidate(&self, store: &StoreHandles) -> Result<(), CommitError> {
        revalidate_lock(store, "transaction.lock", &self.file)
    }
}

fn acquire_lock(
    store: &StoreHandles,
    leaf: &str,
    role: &'static str,
    operation: FlockOperation,
) -> Result<File, CommitError> {
    let path = store.root_path.join(leaf);
    let created = match openat2(
        &store.root,
        leaf,
        OFlags::RDWR
            | OFlags::CREATE
            | OFlags::EXCL
            | OFlags::NONBLOCK
            | OFlags::CLOEXEC
            | OFlags::NOFOLLOW,
        Mode::from_raw_mode(MUTABLE_MODE),
        ROOT_RESOLVE_FLAGS,
    ) {
        Ok(file) => Some(File::from(file)),
        Err(rustix::io::Errno::EXIST) => None,
        Err(source) => return Err(io_error("create store lock", &path, source)),
    };
    let file = if let Some(file) = created {
        fchmod(&file, Mode::from_raw_mode(MUTABLE_MODE))
            .map_err(|source| io_error("set store lock mode", &path, source))?;
        fsync(&file).map_err(|source| io_error("sync store lock", &path, source))?;
        fsync(&store.root).map_err(|source| io_error("sync store root", &path, source))?;
        file
    } else {
        let file = openat2(
            &store.root,
            leaf,
            OFlags::RDWR | OFlags::NONBLOCK | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
            ROOT_RESOLVE_FLAGS,
        )
        .map(File::from)
        .map_err(|source| io_error("open store lock", &path, source))?;
        fsync(&store.root).map_err(|source| io_error("sync store root", &path, source))?;
        file
    };
    validate_file_stat(
        &fstat(&file).map_err(|source| io_error("inspect store lock", &path, source))?,
        &path,
        store.uid,
        MUTABLE_MODE,
        0,
    )?;
    match flock(&file, operation) {
        Ok(()) => {}
        Err(rustix::io::Errno::WOULDBLOCK) => return Err(CommitError::Busy),
        Err(source) => return Err(io_error("acquire store lock", &path, source)),
    }
    revalidate_lock(store, leaf, &file).map_err(|error| match error {
        CommitError::InvalidStore(reason) => {
            CommitError::InvalidStore(format!("{role} lock is unsafe: {reason}"))
        }
        other => other,
    })?;
    Ok(file)
}

fn acquire_existing_lock(
    store: &StoreHandles,
    leaf: &str,
    role: &'static str,
    operation: FlockOperation,
) -> Result<Option<File>, CommitError> {
    let path = store.root_path.join(leaf);
    let file = match openat2(
        &store.root,
        leaf,
        OFlags::RDWR | OFlags::NONBLOCK | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
        ROOT_RESOLVE_FLAGS,
    ) {
        Ok(file) => File::from(file),
        Err(rustix::io::Errno::NOENT) => return Ok(None),
        Err(source) => return Err(io_error("open store lock", &path, source)),
    };
    validate_file_stat(
        &fstat(&file).map_err(|source| io_error("inspect store lock", &path, source))?,
        &path,
        store.uid,
        MUTABLE_MODE,
        0,
    )?;
    match flock(&file, operation) {
        Ok(()) => {}
        Err(rustix::io::Errno::WOULDBLOCK) => return Err(CommitError::Busy),
        Err(source) => return Err(io_error("acquire store lock", &path, source)),
    }
    revalidate_lock(store, leaf, &file).map_err(|error| match error {
        CommitError::InvalidStore(reason) => {
            CommitError::InvalidStore(format!("{role} lock is unsafe: {reason}"))
        }
        other => other,
    })?;
    Ok(Some(file))
}

fn revalidate_lock(store: &StoreHandles, leaf: &str, file: &File) -> Result<(), CommitError> {
    let path = store.root_path.join(leaf);
    let bound = statat(&store.root, leaf, AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|source| io_error("revalidate store lock", &path, source))?;
    let opened =
        fstat(file).map_err(|source| io_error("inspect pinned store lock", &path, source))?;
    validate_file_stat(&opened, &path, store.uid, MUTABLE_MODE, 0)?;
    if !same_object(&bound, &opened) {
        return Err(CommitError::InvalidStore(
            "store lock binding changed".to_owned(),
        ));
    }
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TransactionJournalV1 {
    schema_version: u32,
    namespace: NamespaceName,
    plan_id: PreparedId,
    previous_catalog: Digest,
    next_catalog: Digest,
    previous_generation: Option<Digest>,
    next_generation: Option<Digest>,
    #[serde(deserialize_with = "deserialize_journal_operations")]
    operations: Vec<JournalOperationV1>,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct JournalOperationV1 {
    created_identity: Option<FileIdentityV1>,
    backup: Option<JournalBackupV1>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "kebab-case", deny_unknown_fields)]
enum JournalBackupV1 {
    Intent {
        source_digest: Option<SourceDigestV1>,
    },
    Identified {
        identity: FileIdentityV1,
        source_digest: Option<SourceDigestV1>,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SourceDigestV1([u8; 32]);

impl Serialize for SourceDigestV1 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut value = String::with_capacity(71);
        value.push_str("sha256-");
        for byte in self.0 {
            value.push(char::from(HEX[usize::from(byte >> 4)]));
            value.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
        serializer.serialize_str(&value)
    }
}

impl<'de> Deserialize<'de> for SourceDigestV1 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        let encoded = value
            .strip_prefix("sha256-")
            .ok_or_else(|| serde::de::Error::custom("source digest must use the sha256- prefix"))?;
        if encoded.len() != 64 {
            return Err(serde::de::Error::custom(
                "source digest must contain 64 lowercase hexadecimal digits",
            ));
        }
        let mut digest = [0_u8; 32];
        for (index, pair) in encoded.as_bytes().chunks_exact(2).enumerate() {
            let high = decode_lower_hex(pair[0]).ok_or_else(|| {
                serde::de::Error::custom(
                    "source digest must contain only lowercase hexadecimal digits",
                )
            })?;
            let low = decode_lower_hex(pair[1]).ok_or_else(|| {
                serde::de::Error::custom(
                    "source digest must contain only lowercase hexadecimal digits",
                )
            })?;
            digest[index] = (high << 4) | low;
        }
        Ok(Self(digest))
    }
}

const fn decode_lower_hex(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

fn deserialize_journal_operations<'de, D>(
    deserializer: D,
) -> Result<Vec<JournalOperationV1>, D::Error>
where
    D: Deserializer<'de>,
{
    struct OperationsVisitor;

    impl<'de> Visitor<'de> for OperationsVisitor {
        type Value = Vec<JournalOperationV1>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(
                formatter,
                "at most {} transaction journal operations",
                malm_store::MAX_PREPARED_OPERATIONS
            )
        }

        fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
        where
            A: SeqAccess<'de>,
        {
            let mut operations = Vec::with_capacity(
                sequence
                    .size_hint()
                    .unwrap_or_default()
                    .min(malm_store::MAX_PREPARED_OPERATIONS),
            );
            while let Some(operation) = sequence.next_element()? {
                if operations.len() == malm_store::MAX_PREPARED_OPERATIONS {
                    return Err(serde::de::Error::custom(format_args!(
                        "transaction journal exceeds {} operations",
                        malm_store::MAX_PREPARED_OPERATIONS
                    )));
                }
                operations.push(operation);
            }
            Ok(operations)
        }
    }

    deserializer.deserialize_seq(OperationsVisitor)
}

struct LoadedJournalV1 {
    journal: TransactionJournalV1,
    staged_update: StagedJournalUpdate,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum StagedJournalUpdate {
    None,
    Candidate,
    Previous,
}

fn load_journal(store: &StoreHandles) -> Result<Option<LoadedJournalV1>, CommitError> {
    let Some(directory) = &store.transactions else {
        return Ok(None);
    };
    let path = store.root_path.join("transactions/current.json");
    if statat(directory, ".current.json.new", AtFlags::SYMLINK_NOFOLLOW).is_ok() {
        return Err(CommitError::InvalidJournal(
            "unpublished transaction journal staging remains".to_owned(),
        ));
    }
    let current = read_mutable(
        directory,
        "current.json",
        &path,
        store.uid,
        MAX_TRANSACTION_JOURNAL_BYTES as u64,
    )?;
    let update_path = store.root_path.join("transactions/.current.json.update");
    let update = read_mutable(
        directory,
        ".current.json.update",
        &update_path,
        store.uid,
        MAX_TRANSACTION_JOURNAL_BYTES as u64,
    )?;
    let Some(bytes) = current else {
        if let Some(update) = update {
            return Ok(Some(LoadedJournalV1 {
                journal: decode_journal_bytes(&update)?,
                staged_update: StagedJournalUpdate::Candidate,
            }));
        }
        return Ok(None);
    };
    let current = decode_journal_bytes(&bytes)?;
    if let Some(update) = update {
        let updated = decode_journal_bytes(&update)?;
        if validate_journal_progression(&current, &updated).is_ok() {
            return Ok(Some(LoadedJournalV1 {
                journal: updated,
                staged_update: StagedJournalUpdate::Candidate,
            }));
        }
        validate_journal_progression(&updated, &current)?;
        return Ok(Some(LoadedJournalV1 {
            journal: current,
            staged_update: StagedJournalUpdate::Previous,
        }));
    }
    Ok(Some(LoadedJournalV1 {
        journal: current,
        staged_update: StagedJournalUpdate::None,
    }))
}

fn decode_journal_bytes(bytes: &[u8]) -> Result<TransactionJournalV1, CommitError> {
    let journal: TransactionJournalV1 = serde_json::from_slice(bytes)
        .map_err(|error| CommitError::InvalidJournal(error.to_string()))?;
    let canonical = canonical_journal(&journal);
    if canonical.as_slice() != bytes || journal.schema_version != 1 {
        return Err(CommitError::InvalidJournal(
            "journal is noncanonical or unsupported".to_owned(),
        ));
    }
    Ok(journal)
}

fn validate_journal_progression(
    current: &TransactionJournalV1,
    updated: &TransactionJournalV1,
) -> Result<(), CommitError> {
    if current.schema_version != updated.schema_version
        || current.namespace != updated.namespace
        || current.plan_id != updated.plan_id
        || current.previous_catalog != updated.previous_catalog
        || current.next_catalog != updated.next_catalog
        || current.previous_generation != updated.previous_generation
        || current.next_generation != updated.next_generation
        || current.operations.len() != updated.operations.len()
    {
        return Err(CommitError::InvalidJournal(
            "journal update changes immutable transaction fields".to_owned(),
        ));
    }
    // A batched journal rewrite may advance several operations at once. Check
    // each operation independently so batching cannot hide an illegal phase
    // transition.
    for (before, after) in current.operations.iter().zip(&updated.operations) {
        if before.created_identity.is_some() && before.created_identity != after.created_identity {
            return Err(CommitError::InvalidJournal(
                "journal update changes an established operation identity".to_owned(),
            ));
        }
        if before.created_identity.is_none()
            && after.created_identity.is_some()
            && (before.backup.is_some() || after.backup.is_some())
        {
            return Err(CommitError::InvalidJournal(
                "journal update establishes creation and backup phases together".to_owned(),
            ));
        }
        let backup_progresses = match (before.backup, after.backup) {
            (None, None) => true,
            (None, Some(JournalBackupV1::Intent { .. })) => true,
            (None, Some(JournalBackupV1::Identified { .. })) => false,
            (Some(JournalBackupV1::Intent { .. }), None) => false,
            (Some(JournalBackupV1::Identified { .. }), None) => false,
            (
                Some(JournalBackupV1::Intent {
                    source_digest: before,
                }),
                Some(JournalBackupV1::Intent {
                    source_digest: after,
                }),
            ) => before == after,
            (
                Some(JournalBackupV1::Intent {
                    source_digest: before,
                }),
                Some(JournalBackupV1::Identified {
                    source_digest: after,
                    ..
                }),
            ) => before == after,
            (Some(JournalBackupV1::Identified { .. }), Some(JournalBackupV1::Intent { .. })) => {
                false
            }
            (
                Some(JournalBackupV1::Identified {
                    identity: before_identity,
                    source_digest: before_digest,
                }),
                Some(JournalBackupV1::Identified {
                    identity: after_identity,
                    source_digest: after_digest,
                }),
            ) => before_identity == after_identity && before_digest == after_digest,
        };
        if !backup_progresses {
            return Err(CommitError::InvalidJournal(
                "journal update has an invalid backup phase progression".to_owned(),
            ));
        }
    }
    Ok(())
}

fn publish_journal(
    store: &StoreHandles,
    journal: &TransactionJournalV1,
) -> Result<(), CommitError> {
    store.revalidate()?;
    let directory = store.transactions.as_ref().ok_or_else(|| {
        CommitError::InvalidStore("transaction directory is not pinned".to_owned())
    })?;
    let path = store.root_path.join("transactions/current.json");
    if statat(directory, "current.json", AtFlags::SYMLINK_NOFOLLOW).is_ok() {
        return Err(CommitError::RecoveryRequired);
    }
    let bytes = canonical_journal(journal);
    if bytes.len() > MAX_TRANSACTION_JOURNAL_BYTES {
        return Err(CommitError::InvalidPlan(
            "transaction journal exceeds its encoded size limit".to_owned(),
        ));
    }
    let file = write_unnamed_mutable(directory, &path, &bytes, "transaction journal")?;
    linkat(&file, "", directory, "current.json", AtFlags::EMPTY_PATH).map_err(|source| {
        if source == rustix::io::Errno::EXIST {
            CommitError::RecoveryRequired
        } else {
            io_error("publish transaction journal", &path, source)
        }
    })?;
    fsync(directory).map_err(|source| io_error("sync transaction directory", &path, source))?;
    store.revalidate()
}

fn replace_journal(
    store: &StoreHandles,
    journal: &TransactionJournalV1,
) -> Result<(), CommitError> {
    store.revalidate()?;
    let directory = store.transactions.as_ref().ok_or_else(|| {
        CommitError::InvalidJournal("transaction directory is missing".to_owned())
    })?;
    let path = store.root_path.join("transactions/current.json");
    let bytes = canonical_journal(journal);
    if bytes.len() > MAX_TRANSACTION_JOURNAL_BYTES {
        return Err(CommitError::InvalidJournal(
            "transaction journal exceeds its encoded size limit".to_owned(),
        ));
    }
    let staging = ".current.json.update";
    require_store_entry_absent(directory, staging, &path)?;
    let (current, current_bytes, _) = read_mutable_pinned(
        directory,
        "current.json",
        &path,
        store.uid,
        MAX_TRANSACTION_JOURNAL_BYTES as u64,
    )?
    .ok_or_else(|| CommitError::InvalidJournal("current journal vanished".to_owned()))?;
    let current_journal = decode_journal_bytes(&current_bytes)?;
    validate_journal_progression(&current_journal, journal)?;
    let file = write_unnamed_mutable(directory, &path, &bytes, "transaction journal update")?;
    linkat(&file, "", directory, staging, AtFlags::EMPTY_PATH)
        .map_err(|source| io_error("stage transaction journal update", &path, source))?;
    fsync(directory)
        .map_err(|source| io_error("sync staged transaction journal update", &path, source))?;
    commit_failpoint!("v1.commit.journal_update.after_link");
    let exchange = PinnedExchange {
        directory,
        path: &path,
        role: "transaction journal update",
        uid: store.uid,
        max: MAX_TRANSACTION_JOURNAL_BYTES as u64,
    };
    exchange_pinned_store_entries(
        exchange,
        ExchangeSide {
            leaf: staging,
            pinned: &file,
            bytes: &bytes,
        },
        ExchangeSide {
            leaf: "current.json",
            pinned: &current,
            bytes: &current_bytes,
        },
    )?;
    commit_failpoint!("v1.commit.journal_update.after_exchange");
    remove_pinned_mutable_entry(
        PinnedEntry {
            directory,
            leaf: staging,
            path: &store.root_path.join("transactions/.current.json.update"),
            uid: store.uid,
            max: MAX_TRANSACTION_JOURNAL_BYTES as u64,
        },
        &current_bytes,
        "remove prior transaction journal",
    )?;
    fsync(directory).map_err(|source| io_error("sync transaction directory", &path, source))?;
    let published = read_mutable(
        directory,
        "current.json",
        &path,
        store.uid,
        MAX_TRANSACTION_JOURNAL_BYTES as u64,
    )?
    .ok_or_else(|| CommitError::InvalidJournal("published journal vanished".to_owned()))?;
    if published != bytes {
        return Err(CommitError::InvalidJournal(
            "published transaction journal differs from its staged bytes".to_owned(),
        ));
    }
    store.revalidate()
}

#[derive(Clone, Copy)]
struct PinnedEntry<'a> {
    directory: &'a File,
    leaf: &'a str,
    path: &'a Path,
    uid: u32,
    max: u64,
}

#[derive(Clone, Copy)]
struct PinnedExchange<'a> {
    directory: &'a File,
    path: &'a Path,
    role: &'a str,
    uid: u32,
    max: u64,
}

#[derive(Clone, Copy)]
struct ExchangeSide<'a> {
    leaf: &'a str,
    pinned: &'a File,
    bytes: &'a [u8],
}

impl<'a> PinnedExchange<'a> {
    const fn entry(self, leaf: &'a str) -> PinnedEntry<'a> {
        PinnedEntry {
            directory: self.directory,
            leaf,
            path: self.path,
            uid: self.uid,
            max: self.max,
        }
    }
}

fn exchange_pinned_store_entries(
    store: PinnedExchange<'_>,
    staged: ExchangeSide<'_>,
    current: ExchangeSide<'_>,
) -> Result<(), CommitError> {
    let PinnedExchange {
        directory,
        path,
        role,
        ..
    } = store;
    require_pinned_mutable_bytes(store.entry(staged.leaf), staged.pinned, role, staged.bytes)?;
    require_pinned_mutable_bytes(
        store.entry(current.leaf),
        current.pinned,
        role,
        current.bytes,
    )?;
    renameat_with(
        directory,
        staged.leaf,
        directory,
        current.leaf,
        RenameFlags::EXCHANGE,
    )
    .map_err(|source| io_error("exchange staged store entry", path, source))?;
    let staged_bound = statat(directory, staged.leaf, AtFlags::SYMLINK_NOFOLLOW);
    let current_bound = statat(directory, current.leaf, AtFlags::SYMLINK_NOFOLLOW);
    let staged_expected = fstat(current.pinned);
    let current_expected = fstat(staged.pinned);
    let identities_published = matches!(
        (staged_bound, current_bound, staged_expected, current_expected),
        (Ok(staged_bound), Ok(current_bound), Ok(staged_expected), Ok(current_expected))
            if same_object(&staged_bound, &staged_expected)
                && same_object(&current_bound, &current_expected)
    );
    let bytes_published = identities_published
        && require_pinned_mutable_bytes(
            store.entry(staged.leaf),
            current.pinned,
            role,
            current.bytes,
        )
        .is_ok()
        && require_pinned_mutable_bytes(
            store.entry(current.leaf),
            staged.pinned,
            role,
            staged.bytes,
        )
        .is_ok();
    if !bytes_published {
        let restored = renameat_with(
            directory,
            staged.leaf,
            directory,
            current.leaf,
            RenameFlags::EXCHANGE,
        );
        let _ = fsync(directory);
        if let Err(source) = restored {
            return Err(io_error("restore exchanged store entries", path, source));
        }
        return Err(CommitError::InvalidStore(format!(
            "{role} binding changed during publication"
        )));
    }
    fsync(directory).map_err(|source| io_error("sync exchanged store entries", path, source))
}

fn require_pinned_mutable_bytes(
    entry: PinnedEntry<'_>,
    pinned: &File,
    role: &str,
    expected: &[u8],
) -> Result<(), CommitError> {
    let path = entry.path;
    let (opened, bytes, _) =
        read_mutable_pinned(entry.directory, entry.leaf, path, entry.uid, entry.max)?
            .ok_or_else(|| CommitError::InvalidStore(format!("{role} vanished")))?;
    let observed =
        fstat(&opened).map_err(|source| io_error("inspect staged store entry", path, source))?;
    let intended =
        fstat(pinned).map_err(|source| io_error("inspect pinned store entry", path, source))?;
    if !same_object(&observed, &intended) || bytes != expected {
        return Err(CommitError::InvalidStore(format!(
            "{role} changed before publication"
        )));
    }
    require_pinned_store_entry(entry.directory, entry.leaf, pinned, path, role)
}

fn require_pinned_store_entry(
    directory: &File,
    leaf: &str,
    pinned: &File,
    path: &Path,
    role: &str,
) -> Result<(), CommitError> {
    let bound = statat(directory, leaf, AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|source| io_error("revalidate staged store entry", path, source))?;
    let opened =
        fstat(pinned).map_err(|source| io_error("inspect pinned store entry", path, source))?;
    if !same_snapshot(&bound, &opened) {
        return Err(CommitError::InvalidStore(format!("{role} binding changed")));
    }
    Ok(())
}

fn remove_pinned_mutable_entry(
    entry: PinnedEntry<'_>,
    expected: &[u8],
    operation: &'static str,
) -> Result<(), CommitError> {
    let PinnedEntry {
        directory,
        leaf,
        path,
        uid,
        max,
    } = entry;
    let (pinned, bytes, _) = read_mutable_pinned(directory, leaf, path, uid, max)?
        .ok_or_else(|| CommitError::InvalidStore(format!("{} vanished", path.display())))?;
    if bytes != expected {
        return Err(CommitError::InvalidStore(format!(
            "{} changed before removal",
            path.display()
        )));
    }
    require_pinned_store_entry(directory, leaf, &pinned, path, operation)?;
    unlinkat(directory, leaf, AtFlags::empty()).map_err(|source| io_error(operation, path, source))
}

fn remove_optional_pinned_mutable_entry(
    entry: PinnedEntry<'_>,
    expected: &[u8],
    operation: &'static str,
) -> Result<bool, CommitError> {
    match statat(entry.directory, entry.leaf, AtFlags::SYMLINK_NOFOLLOW) {
        Err(rustix::io::Errno::NOENT) => return Ok(false),
        Ok(_) => {}
        Err(source) => {
            return Err(io_error("inspect mutable store entry", entry.path, source));
        }
    }
    remove_pinned_mutable_entry(entry, expected, operation)?;
    Ok(true)
}

fn journal_at(
    directory: &File,
    leaf: &str,
    path: &Path,
    uid: u32,
) -> Result<Option<(Vec<u8>, TransactionJournalV1)>, CommitError> {
    let Some(bytes) = read_mutable(
        directory,
        leaf,
        path,
        uid,
        MAX_TRANSACTION_JOURNAL_BYTES as u64,
    )?
    else {
        return Ok(None);
    };
    let journal = decode_journal_bytes(&bytes)?;
    Ok(Some((bytes, journal)))
}

fn write_unnamed_mutable(
    directory: &File,
    path: &Path,
    bytes: &[u8],
    role: &'static str,
) -> Result<File, CommitError> {
    let mut file = openat(
        directory,
        ".",
        OFlags::TMPFILE | OFlags::RDWR | OFlags::CLOEXEC,
        Mode::from_raw_mode(MUTABLE_MODE),
    )
    .map(File::from)
    .map_err(|source| io_error(role, path, source))?;
    fchmod(&file, Mode::from_raw_mode(MUTABLE_MODE))
        .map_err(|source| io_error("set mutable store entry mode", path, source))?;
    file.write_all(bytes).map_err(|source| CommitError::Io {
        operation: role,
        path: path.to_path_buf(),
        source,
    })?;
    file.flush().map_err(|source| CommitError::Io {
        operation: role,
        path: path.to_path_buf(),
        source,
    })?;
    fsync(&file).map_err(|source| io_error("sync mutable store entry", path, source))?;
    Ok(file)
}

fn remove_journal(store: &StoreHandles) -> Result<(), CommitError> {
    store.revalidate()?;
    let Some(directory) = &store.transactions else {
        return Ok(());
    };
    let Some(loaded) = load_journal(store)? else {
        return Ok(());
    };
    let path = store.root_path.join("transactions/current.json");
    let update_path = store.root_path.join("transactions/.current.json.update");
    let authoritative = canonical_journal(&loaded.journal);
    match loaded.staged_update {
        StagedJournalUpdate::Candidate => {
            if let Some((current_bytes, current)) =
                journal_at(directory, "current.json", &path, store.uid)?
            {
                validate_journal_progression(&current, &loaded.journal)?;
                remove_pinned_mutable_entry(
                    PinnedEntry {
                        directory,
                        leaf: "current.json",
                        path: &path,
                        uid: store.uid,
                        max: MAX_TRANSACTION_JOURNAL_BYTES as u64,
                    },
                    &current_bytes,
                    "remove prior transaction journal",
                )?;
                fsync(directory)
                    .map_err(|source| io_error("sync transaction directory", &path, source))?;
                commit_failpoint!("v1.commit.journal_remove.after_current");
            }
            remove_pinned_mutable_entry(
                PinnedEntry {
                    directory,
                    leaf: ".current.json.update",
                    path: &update_path,
                    uid: store.uid,
                    max: MAX_TRANSACTION_JOURNAL_BYTES as u64,
                },
                &authoritative,
                "remove staged transaction journal update",
            )?;
        }
        StagedJournalUpdate::Previous => {
            let (previous_bytes, previous) =
                journal_at(directory, ".current.json.update", &update_path, store.uid)?
                    .ok_or_else(|| {
                        CommitError::InvalidJournal("previous journal update vanished".to_owned())
                    })?;
            validate_journal_progression(&previous, &loaded.journal)?;
            remove_pinned_mutable_entry(
                PinnedEntry {
                    directory,
                    leaf: ".current.json.update",
                    path: &update_path,
                    uid: store.uid,
                    max: MAX_TRANSACTION_JOURNAL_BYTES as u64,
                },
                &previous_bytes,
                "remove prior transaction journal update",
            )?;
            fsync(directory)
                .map_err(|source| io_error("sync transaction directory", &path, source))?;
            commit_failpoint!("v1.commit.journal_remove.after_update");
            remove_pinned_mutable_entry(
                PinnedEntry {
                    directory,
                    leaf: "current.json",
                    path: &path,
                    uid: store.uid,
                    max: MAX_TRANSACTION_JOURNAL_BYTES as u64,
                },
                &authoritative,
                "remove transaction journal",
            )?;
        }
        StagedJournalUpdate::None => {
            remove_optional_pinned_mutable_entry(
                PinnedEntry {
                    directory,
                    leaf: "current.json",
                    path: &path,
                    uid: store.uid,
                    max: MAX_TRANSACTION_JOURNAL_BYTES as u64,
                },
                &authoritative,
                "remove transaction journal",
            )?;
        }
    }
    fsync(directory).map_err(|source| io_error("sync transaction directory", &path, source))?;
    store.revalidate()
}

fn canonical_journal(journal: &TransactionJournalV1) -> Vec<u8> {
    let mut bytes = serde_json::to_vec(journal).expect("journal fields always serialize");
    bytes.push(b'\n');
    bytes
}

fn validate_journal(
    store: &StoreHandles,
    prepared: &PreparedRecordV1,
    journal: &TransactionJournalV1,
) -> Result<(), CommitError> {
    if prepared.namespace() != &journal.namespace {
        return Err(CommitError::InvalidJournal(
            "journal namespace differs from its prepared plan".to_owned(),
        ));
    }
    if prepared.expected_head() != journal.previous_generation.as_ref() {
        return Err(CommitError::InvalidJournal(
            "journal prior generation differs from the prepared namespace-head precondition"
                .to_owned(),
        ));
    }
    if journal.previous_catalog == journal.next_catalog {
        return Err(CommitError::InvalidJournal(
            "journal catalog transition does not change the catalog".to_owned(),
        ));
    }
    if journal.operations.len() != prepared.operations().len() {
        return Err(CommitError::InvalidJournal(
            "journal operation count differs from its prepared plan".to_owned(),
        ));
    }
    for (operation, journal_operation) in prepared.operations().iter().zip(&journal.operations) {
        let invalid = match operation {
            PreparedOperationV1::EnsureDirectory { observation, .. }
            | PreparedOperationV1::PlaceFile { observation, .. }
            | PreparedOperationV1::PlaceSymlink { observation, .. }
            | PreparedOperationV1::PlaceTree { observation, .. } => {
                (matches!(observation.leaf(), LeafObservationV1::Absent)
                    && journal_operation.backup.is_some())
                    || (journal_operation.backup.is_some()
                        && journal_operation.created_identity.is_none())
            }
            PreparedOperationV1::RemoveLeaf { observation } => {
                journal_operation.created_identity.is_some()
                    || (matches!(observation.leaf(), LeafObservationV1::Absent)
                        && journal_operation.backup.is_some())
            }
            PreparedOperationV1::AssertAbsent { .. } | PreparedOperationV1::AssertExact { .. } => {
                journal_operation.created_identity.is_some() || journal_operation.backup.is_some()
            }
        };
        if invalid {
            return Err(CommitError::InvalidJournal(
                "journal operation identities are inconsistent with the prepared operation"
                    .to_owned(),
            ));
        }
        let source_digest = match journal_operation.backup {
            Some(
                JournalBackupV1::Intent { source_digest }
                | JournalBackupV1::Identified { source_digest, .. },
            ) => Some(source_digest),
            None => None,
        };
        if let Some(source_digest) = source_digest {
            let LeafObservationV1::Present(expected) = operation.observation().leaf() else {
                return Err(CommitError::InvalidJournal(
                    "backup intent has no prepared source identity".to_owned(),
                ));
            };
            let regular = FileType::from_raw_mode(expected.mode) == FileType::RegularFile;
            if regular != source_digest.is_some() {
                return Err(CommitError::InvalidJournal(
                    "backup intent source digest does not match the prepared source type"
                        .to_owned(),
                ));
            }
        }
        if let Some(JournalBackupV1::Identified { identity, .. }) = journal_operation.backup {
            let LeafObservationV1::Present(expected) = operation.observation().leaf() else {
                return Err(CommitError::InvalidJournal(
                    "identified backup has no prepared source identity".to_owned(),
                ));
            };
            if !same_relocated_file_identity(identity, expected) {
                return Err(CommitError::InvalidJournal(
                    "identified backup does not match its prepared source".to_owned(),
                ));
            }
        }
    }
    let removal = matches!(
        prepared.transition(),
        PreparedTransitionV1::NamespaceRemoval { .. }
    );
    if removal != journal.next_generation.is_none() {
        return Err(CommitError::InvalidJournal(
            "only namespace removal may omit the next generation".to_owned(),
        ));
    }
    let previous = journal
        .previous_generation
        .as_ref()
        .map(|digest| load_generation(store, digest))
        .transpose()?;
    malm_store::validate_prepared_transition_v1(previous.as_ref(), prepared)
        .map_err(|error| CommitError::InvalidJournal(error.to_string()))?;
    let mut canonical_budget = CanonicalLoadBudget::default();
    validate_transition_references(store, previous.as_ref(), prepared, &mut canonical_budget)
        .map_err(|error| CommitError::InvalidJournal(error.to_string()))?;
    if let Some(next_generation) = &journal.next_generation {
        let generation = StateGenerationV1::from_prepared(
            journal.plan_id.clone(),
            journal.previous_generation.clone(),
            previous.as_ref(),
            prepared,
        )
        .map_err(|error| CommitError::InvalidJournal(error.to_string()))?;
        if state_generation_digest_v1(&generation) != *next_generation {
            return Err(CommitError::InvalidJournal(
                "journal next generation is not derived from its prepared plan".to_owned(),
            ));
        }
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CatalogPosition {
    Previous,
    Next,
}

fn validate_journal_catalog_transition(
    catalog: &StateCatalogV1,
    journal: &TransactionJournalV1,
) -> Result<CatalogPosition, CommitError> {
    let digest = state_catalog_digest_v1(catalog);
    if digest == journal.previous_catalog {
        if catalog.generation(&journal.namespace) != journal.previous_generation.as_ref() {
            return Err(CommitError::InvalidJournal(
                "prior catalog does not select the journaled namespace predecessor".to_owned(),
            ));
        }
        let mut next = catalog.clone();
        match &journal.next_generation {
            Some(generation) => {
                next.update_head(journal.namespace.clone(), generation.clone())
                    .map_err(|error| CommitError::InvalidJournal(error.to_string()))?;
            }
            None => {
                if next.remove_head(&journal.namespace) != journal.previous_generation {
                    return Err(CommitError::InvalidJournal(
                        "namespace-removal catalog predecessor changed".to_owned(),
                    ));
                }
            }
        }
        if state_catalog_digest_v1(&next) != journal.next_catalog {
            return Err(CommitError::InvalidJournal(
                "next catalog changes more than the journaled namespace".to_owned(),
            ));
        }
        return Ok(CatalogPosition::Previous);
    }
    if digest == journal.next_catalog {
        if catalog.generation(&journal.namespace) != journal.next_generation.as_ref() {
            return Err(CommitError::InvalidJournal(
                "next catalog does not select the journaled namespace successor".to_owned(),
            ));
        }
        let mut previous = catalog.clone();
        match &journal.previous_generation {
            Some(generation) => {
                previous
                    .update_head(journal.namespace.clone(), generation.clone())
                    .map_err(|error| CommitError::InvalidJournal(error.to_string()))?;
            }
            None => {
                previous.remove_head(&journal.namespace);
            }
        }
        if state_catalog_digest_v1(&previous) != journal.previous_catalog {
            return Err(CommitError::InvalidJournal(
                "prior catalog changes more than the journaled namespace".to_owned(),
            ));
        }
        return Ok(CatalogPosition::Next);
    }
    Err(CommitError::InvalidJournal(
        "catalog is neither the exact prior nor next transaction catalog".to_owned(),
    ))
}

fn validate_roll_forward_journal(
    prepared: &PreparedRecordV1,
    journal: &TransactionJournalV1,
) -> Result<(), CommitError> {
    for (operation, state) in prepared.operations().iter().zip(&journal.operations) {
        let complete = match operation {
            PreparedOperationV1::EnsureDirectory { observation, .. }
            | PreparedOperationV1::PlaceFile { observation, .. }
            | PreparedOperationV1::PlaceSymlink { observation, .. }
            | PreparedOperationV1::PlaceTree { observation, .. } => match observation.leaf() {
                LeafObservationV1::Absent => {
                    state.created_identity.is_some() && state.backup.is_none()
                }
                LeafObservationV1::Present(_) => {
                    state.created_identity.is_some()
                        && matches!(state.backup, Some(JournalBackupV1::Identified { .. }))
                }
            },
            PreparedOperationV1::RemoveLeaf { observation } => match observation.leaf() {
                LeafObservationV1::Absent => {
                    state.created_identity.is_none() && state.backup.is_none()
                }
                LeafObservationV1::Present(_) => {
                    state.created_identity.is_none()
                        && matches!(state.backup, Some(JournalBackupV1::Identified { .. }))
                }
            },
            PreparedOperationV1::AssertAbsent { .. } | PreparedOperationV1::AssertExact { .. } => {
                state.created_identity.is_none() && state.backup.is_none()
            }
        };
        if !complete {
            return Err(CommitError::InvalidJournal(
                "activated transaction journal contains an incomplete operation phase".to_owned(),
            ));
        }
    }
    Ok(())
}

fn rollback_recovery(
    config: &CommitConfig,
    store: &StoreHandles,
    prepared: &PreparedRecordV1,
    journal: &TransactionJournalV1,
) -> Result<(), CommitError> {
    let blobs = load_all_artifacts(store, prepared)?;
    let previous = journal
        .previous_generation
        .as_ref()
        .map(|digest| load_generation(store, digest))
        .transpose()?;
    let canonical = load_canonical_objects(store, prepared, previous.as_ref())?;
    let created_directories = journaled_created_directories(prepared, journal);
    for (index, operation) in prepared.operations().iter().enumerate().rev() {
        let mut target = PinnedTarget::open_for_recovery(
            config,
            store,
            &journal.plan_id,
            index,
            operation.clone(),
            prior_target_state(previous.as_ref(), operation),
            &created_directories,
        )?;
        target.rollback_incomplete(store, &blobs, &canonical, &journal.operations[index])?;
    }
    remove_catalog_staging(store, journal)
}

fn finish_recovery(
    config: &CommitConfig,
    store: &StoreHandles,
    prepared: &PreparedRecordV1,
    journal: &TransactionJournalV1,
) -> Result<(), CommitError> {
    let blobs = load_all_artifacts(store, prepared)?;
    let previous = journal
        .previous_generation
        .as_ref()
        .map(|digest| load_generation(store, digest))
        .transpose()?;
    let canonical = load_canonical_objects(store, prepared, previous.as_ref())?;
    let created_directories = journaled_created_directories(prepared, journal);
    for (index, operation) in prepared.operations().iter().enumerate() {
        let mut target = PinnedTarget::open_for_recovery(
            config,
            store,
            &journal.plan_id,
            index,
            operation.clone(),
            prior_target_state(previous.as_ref(), operation),
            &created_directories,
        )?;
        target.finish_incomplete(store, &blobs, &canonical, &journal.operations[index])?;
    }
    remove_catalog_staging(store, journal)
}

/// Returns the directory identities recorded before the crash. Recovery accepts
/// a pending ancestor as transaction-created only when it matches this map.
fn journaled_created_directories(
    prepared: &PreparedRecordV1,
    journal: &TransactionJournalV1,
) -> CreatedDirectories {
    prepared
        .operations()
        .iter()
        .enumerate()
        .filter(|(_, operation)| matches!(operation, PreparedOperationV1::EnsureDirectory { .. }))
        .filter_map(|(index, operation)| {
            let identity = journal.operations.get(index)?.created_identity?;
            let observation = operation.observation();
            Some((
                (
                    observation.authority().clone(),
                    observation.relative_path().to_owned(),
                ),
                identity,
            ))
        })
        .collect()
}

struct OperationSlot<'a> {
    plan_id: &'a PreparedId,
    index: usize,
    operation: PreparedOperationV1,
    prior_state: Option<StateTargetStateV1>,
}

struct PublishContext<'a, 'j> {
    canonical: &'a canonical::CanonicalObjects,
    store: &'a StoreHandles,
    journal: &'j mut TransactionJournalV1,
    path: &'a Path,
}

fn prior_target_state(
    previous: Option<&StateGenerationV1>,
    operation: &PreparedOperationV1,
) -> Option<StateTargetStateV1> {
    let observation = operation.observation();
    previous?
        .targets()
        .iter()
        .find(|target| {
            target.authority() == observation.authority()
                && target.relative_path() == observation.relative_path()
        })
        .map(|target| target.state().clone())
}

/// Advances targets that were waiting for the directory just created.
///
/// Each target opens the directory through its own pinned parent and compares
/// it with the object opened through the creating operation. An external swap
/// therefore fails the identity check. Parent-first directory operations let
/// nested pending chains advance one level at a time.
fn complete_pending_pins(
    targets: &mut [PinnedTarget],
    changed_index: usize,
    store: &StoreHandles,
) -> Result<(), CommitError> {
    if !matches!(
        targets[changed_index].operation,
        PreparedOperationV1::EnsureDirectory { .. }
    ) {
        return Ok(());
    }
    let observation = targets[changed_index].operation.observation();
    let created_authority = observation.authority().clone();
    let created_path = observation.relative_path().to_owned();
    let created_uid = targets[changed_index].uid;
    let absolute = targets[changed_index].authority_path.join(&created_path);
    let created = openat2(
        &targets[changed_index].parent,
        &targets[changed_index].leaf,
        DIRECTORY_FLAGS | OFlags::NOFOLLOW | OFlags::NOATIME,
        Mode::empty(),
        ROOT_RESOLVE_FLAGS,
    )
    .map(File::from)
    .map(Arc::new)
    .map_err(|source| io_error("open created target directory", &absolute, source))?;
    let created_stat = fstat(&created)
        .map_err(|source| io_error("inspect created target directory", &absolute, source))?;
    validate_target_directory(&created, &absolute, created_uid)?;
    reject_protected_traversal_directory(store, &created, &absolute)?;
    for target in targets.iter_mut() {
        if target.pending.is_empty()
            || target.operation.observation().authority() != &created_authority
            || target.pending_prefixes[0] != created_path
        {
            continue;
        }
        let segment = target.pending[0].clone();
        let handle = openat2(
            &target.parent,
            segment.as_os_str(),
            DIRECTORY_FLAGS | OFlags::NOFOLLOW | OFlags::NOATIME,
            Mode::empty(),
            ROOT_RESOLVE_FLAGS,
        )
        .map(File::from)
        .map_err(|source| io_error("open completed target ancestor", &absolute, source))?;
        let stat = fstat(&handle)
            .map_err(|source| io_error("inspect completed target ancestor", &absolute, source))?;
        if !same_object(&created_stat, &stat) {
            return Err(CommitError::StaleTarget(
                "created target ancestor changed before its dependents pinned it".to_owned(),
            ));
        }
        // The per-target open proved that this target's own pinned parent
        // still binds the segment to the directory this operation created.
        // That proof is what the open was for; the descriptor itself is
        // redundant because it names the same inode as `created`. Dropping it
        // and sharing `created` keeps one descriptor per created directory
        // instead of one per dependent target, which is what the plan's
        // descriptor budget reserves.
        drop(handle);
        let identity = file_identity(&stat);
        target.ancestors.push((segment, Arc::clone(&created)));
        target.parent = Arc::clone(&created);
        target.parent_object = identity;
        target.expected_parent = identity;
        target.pending.remove(0);
        target.pending_prefixes.remove(0);
    }
    Ok(())
}

fn refresh_expected_parents(
    targets: &mut [PinnedTarget],
    changed_index: usize,
) -> Result<(), CommitError> {
    let changed = fstat(&targets[changed_index].parent).map_err(|source| {
        io_error(
            "inspect changed target parent",
            &targets[changed_index].authority_path,
            source,
        )
    })?;
    let identity = file_identity(&changed);
    // Refresh every target that shares this parent. In the phased schedule, a
    // target with an earlier plan index may still be waiting to run.
    for target in targets.iter_mut() {
        let candidate = fstat(&target.parent).map_err(|source| {
            io_error(
                "inspect subsequent target parent",
                &target.authority_path,
                source,
            )
        })?;
        if same_object(&changed, &candidate) {
            target.expected_parent = identity;
        }
    }
    Ok(())
}

/// Syncs each selected parent directory once. This is the phase durability
/// barrier for batched mutations and replaces a parent sync after every file.
fn sync_unique_parents(
    targets: &[PinnedTarget],
    select: impl Fn(&PinnedTarget) -> bool,
) -> Result<(), CommitError> {
    let mut synced: BTreeSet<(u64, u64)> = BTreeSet::new();
    for target in targets.iter().filter(|target| select(target)) {
        let stat = fstat(&target.parent)
            .map_err(|source| io_error("inspect target parent", &target.authority_path, source))?;
        if synced.insert((stat.st_dev, stat.st_ino)) {
            fsync(&target.parent)
                .map_err(|source| io_error("sync target parent", &target.authority_path, source))?;
        }
    }
    Ok(())
}

fn refresh_all_expected_parents(targets: &mut [PinnedTarget]) -> Result<(), CommitError> {
    let mut identities: BTreeMap<(u64, u64), FileIdentityV1> = BTreeMap::new();
    for target in targets.iter_mut() {
        let stat = fstat(&target.parent)
            .map_err(|source| io_error("inspect target parent", &target.authority_path, source))?;
        let identity = identities
            .entry((stat.st_dev, stat.st_ino))
            .or_insert_with(|| file_identity(&stat));
        target.expected_parent = *identity;
    }
    Ok(())
}

/// Runs independent checks in parallel while returning the first error in item
/// order, as a sequential check would.
fn parallel_targets<T: Sync, E: Send>(
    items: &[T],
    run: impl Fn(&T) -> Result<(), E> + Sync,
) -> Result<(), E> {
    const MIN_PARALLEL_ITEMS: usize = 16;
    if items.len() < MIN_PARALLEL_ITEMS {
        return items.iter().try_for_each(run);
    }
    let workers = std::thread::available_parallelism()
        .map(std::num::NonZeroUsize::get)
        .unwrap_or(1)
        .clamp(1, items.len());
    let chunk_len = items.len().div_ceil(workers).max(1);
    let mut results: Vec<Result<(), E>> = std::thread::scope(|scope| {
        let handles = items
            .chunks(chunk_len)
            .map(|chunk| scope.spawn(|| chunk.iter().map(&run).collect::<Vec<_>>()))
            .collect::<Vec<_>>();
        handles
            .into_iter()
            .flat_map(|handle| handle.join().expect("target worker never panics"))
            .collect()
    });
    for result in results.drain(..) {
        result?;
    }
    Ok(())
}

fn parallel_targets_mut<T: Send, E: Send>(
    items: &mut [T],
    run: impl Fn(&mut T) -> Result<(), E> + Sync,
) -> Result<(), E> {
    const MIN_PARALLEL_ITEMS: usize = 16;
    if items.len() < MIN_PARALLEL_ITEMS {
        return items.iter_mut().try_for_each(run);
    }
    let workers = std::thread::available_parallelism()
        .map(std::num::NonZeroUsize::get)
        .unwrap_or(1)
        .clamp(1, items.len());
    let chunk_len = items.len().div_ceil(workers).max(1);
    let mut results: Vec<Result<(), E>> = std::thread::scope(|scope| {
        let handles = items
            .chunks_mut(chunk_len)
            .map(|chunk| scope.spawn(|| chunk.iter_mut().map(&run).collect::<Vec<_>>()))
            .collect::<Vec<_>>();
        handles
            .into_iter()
            .flat_map(|handle| handle.join().expect("target worker never panics"))
            .collect()
    });
    for result in results.drain(..) {
        result?;
    }
    Ok(())
}

/// Rolls back every target after a phase error. Invalid store or journal data
/// leaves the journal in place for recovery; other errors remove it only after
/// rollback succeeds.
fn phase_failure(
    error: CommitError,
    targets: &mut [PinnedTarget],
    blobs: &LoadedArtifacts,
    canonical: &canonical::CanonicalObjects,
    journal: &TransactionJournalV1,
    store: &StoreHandles,
) -> CommitError {
    if let Err(reason) = rollback_targets(targets, blobs, canonical, &journal.operations) {
        return CommitError::RollbackFailed(format!("{error}; rollback failed: {reason}"));
    }
    if matches!(
        error,
        CommitError::InvalidStore(_) | CommitError::InvalidJournal(_)
    ) {
        return error;
    }
    match remove_journal(store) {
        Ok(()) => error,
        Err(removal) => CommitError::RollbackFailed(format!("{error}; {removal}")),
    }
}

fn rollback_targets(
    targets: &mut [PinnedTarget],
    blobs: &LoadedArtifacts,
    canonical: &canonical::CanonicalObjects,
    operations: &[JournalOperationV1],
) -> Result<(), String> {
    let mut failures = Vec::with_capacity(targets.len());
    for (target, operation) in targets.iter_mut().zip(operations).rev() {
        // An empty mutation record proves the target was untouched because a
        // staged inode stays anonymous until its identity is durable. Skip it
        // so an external change to an untouched leaf cannot break rollback.
        // Assertions still run because their rollback step is the final drift
        // check.
        if operation.created_identity.is_none()
            && operation.backup.is_none()
            && !matches!(
                target.operation,
                PreparedOperationV1::AssertExact { .. } | PreparedOperationV1::AssertAbsent { .. }
            )
        {
            continue;
        }
        if let Err(error) = target.rollback_pinned(blobs, canonical, operation) {
            failures.push(error.to_string());
        }
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(failures.join("; "))
    }
}

fn publish_generation_and_catalog(
    store: &StoreHandles,
    digest: Option<&Digest>,
    generation: Option<&StateGenerationV1>,
    previous_catalog: &StateCatalogV1,
    next_catalog: &StateCatalogV1,
) -> Result<(), CommitError> {
    store.revalidate()?;
    let state_path = store.root_path.join("state");
    let state = store
        .state
        .as_ref()
        .ok_or_else(|| CommitError::InvalidStore("state directory is not pinned".to_owned()))?;
    match (digest, generation) {
        (Some(digest), Some(generation)) => {
            let generations_path = state_path.join("generations");
            let generations = store.generations.as_ref().ok_or_else(|| {
                CommitError::InvalidStore("generation directory is not pinned".to_owned())
            })?;
            let bytes = encode_state_generation_v1(generation);
            if bytes.len() > malm_store::MAX_STATE_RECORD_BYTES {
                return Err(CommitError::InvalidPlan(
                    "derived state generation exceeds its encoded size limit".to_owned(),
                ));
            }
            publish_immutable(
                generations,
                digest.as_str(),
                &generations_path.join(digest.as_str()),
                &bytes,
                store.uid,
            )?;
            commit_failpoint!("v1.commit.after_generation");
        }
        (None, None) => {}
        _ => {
            return Err(CommitError::InvalidPlan(
                "generation identity and record presence differ".to_owned(),
            ));
        }
    }
    store.revalidate()?;
    let catalog = encode_state_catalog_v1(next_catalog);
    let previous = encode_state_catalog_v1(previous_catalog);
    replace_catalog(
        state,
        &state_path.join("catalog.json"),
        &catalog,
        &previous,
        store.uid,
    )?;
    // `replace_catalog` syncs `state` after publishing the new catalog. A
    // second sync here would not add another durability transition.
    commit_failpoint!("v1.commit.after_catalog");
    store.revalidate()
}

fn publish_initial_catalog(
    store: &StoreHandles,
    catalog: &StateCatalogV1,
) -> Result<(), CommitError> {
    let state_path = store.root_path.join("state");
    let state = store
        .state
        .as_ref()
        .ok_or_else(|| CommitError::InvalidStore("state directory is not pinned".to_owned()))?;
    let bytes = encode_state_catalog_v1(catalog);
    publish_initial_catalog_file(state, &state_path.join("catalog.json"), &bytes, store.uid)?;
    fsync(state).map_err(|source| io_error("sync state directory", &state_path, source))?;
    store.revalidate()
}

fn read_catalog(store: &StoreHandles) -> Result<StateCatalogV1, CommitError> {
    read_catalog_optional(store)?
        .ok_or_else(|| CommitError::InvalidStore("state/catalog.json is missing".to_owned()))
}

fn read_catalog_optional(store: &StoreHandles) -> Result<Option<StateCatalogV1>, CommitError> {
    let state_path = store.root_path.join("state");
    let Some(state) = &store.state else {
        return Ok(None);
    };
    let path = state_path.join("catalog.json");
    let Some(bytes) = read_mutable(
        state,
        "catalog.json",
        &path,
        store.uid,
        malm_store::MAX_STATE_CATALOG_BYTES as u64,
    )?
    else {
        return Ok(None);
    };
    let catalog = decode_state_catalog_v1(&bytes).map_err(CommitError::invalid_store)?;
    // A routine catalog read checks each head and immediate predecessor, the
    // links that normal operations can extend. Older retained generations are
    // immutable and content-addressed; `fsck` performs their full audit.
    validate_catalog_lineages(store, &catalog, None, LineageDepth::Routine)?;
    Ok(Some(catalog))
}

enum CatalogInitialization {
    Empty,
    Ready(StateCatalogV1),
    MissingFromNonempty,
}

fn preflight_catalog_initialization(
    store: &StoreHandles,
) -> Result<CatalogInitialization, CommitError> {
    let catalog = read_catalog_optional(store)?;
    if catalog.is_none()
        && let Some(state) = &store.state
        && !directory_names(state, &store.root_path.join("state"))?.is_empty()
    {
        return Ok(CatalogInitialization::MissingFromNonempty);
    }
    Ok(match catalog {
        Some(catalog) => CatalogInitialization::Ready(catalog),
        None => CatalogInitialization::Empty,
    })
}

fn missing_state_catalog_error() -> CommitError {
    CommitError::InvalidStore("state catalog is missing from a nonempty state directory".to_owned())
}

fn load_generation(
    store: &StoreHandles,
    digest: &Digest,
) -> Result<StateGenerationV1, CommitError> {
    load_generation_with_encoded_len(store, digest).map(|(generation, _)| generation)
}

fn load_generation_with_encoded_len(
    store: &StoreHandles,
    digest: &Digest,
) -> Result<(StateGenerationV1, usize), CommitError> {
    let generations = store.generations.as_ref().ok_or_else(|| {
        CommitError::InvalidStore("state generations directory is missing".to_owned())
    })?;
    let generation_path = store
        .root_path
        .join("state/generations")
        .join(digest.as_str());
    let bytes = read_immutable(
        generations,
        digest.as_str(),
        &generation_path,
        store.uid,
        malm_store::MAX_STATE_RECORD_BYTES as u64,
    )?
    .ok_or_else(|| CommitError::InvalidStore("state generation object is missing".to_owned()))?;
    let encoded_len = bytes.len();
    let generation = malm_store::decode_state_generation_v1(digest, &bytes)
        .map_err(CommitError::invalid_store)?;
    Ok((generation, encoded_len))
}

fn validate_generation_transition(
    store: &StoreHandles,
    generation: &StateGenerationV1,
) -> Result<(), CommitError> {
    let mut decoded_bytes = 0;
    match validate_generation_transition_with_budget(store, generation, &mut decoded_bytes) {
        Err(CommitError::InvalidStore(reason))
            if generation.previous_generation().is_some()
                && reason == "state generation object is missing" =>
        {
            validate_retained_generation_transition_with_budget(
                store,
                generation,
                &mut decoded_bytes,
            )
            .map_err(state_generation_validation_error)
        }
        result => result.map_err(state_generation_validation_error),
    }
}

fn state_generation_validation_error(error: CommitError) -> CommitError {
    match error {
        CommitError::MissingPlan(plan_id) => CommitError::InvalidStore(format!(
            "state generation references missing prepared plan {plan_id}"
        )),
        CommitError::InvalidPlan(reason) => CommitError::InvalidStore(format!(
            "state generation references an invalid prepared plan: {reason}"
        )),
        error => error,
    }
}

fn validate_generation_transition_with_budget(
    store: &StoreHandles,
    generation: &StateGenerationV1,
    decoded_bytes: &mut usize,
) -> Result<(), CommitError> {
    let (prepared, prepared_bytes) = load_prepared_with_encoded_len(store, generation.plan_id())?;
    charge_lineage_validation_bytes(decoded_bytes, prepared_bytes)?;
    let previous = if let Some(digest) = generation.previous_generation() {
        let (previous, previous_bytes) = load_generation_with_encoded_len(store, digest)?;
        charge_lineage_validation_bytes(decoded_bytes, previous_bytes)?;
        Some(previous)
    } else {
        None
    };
    let rebuilt = StateGenerationV1::from_prepared(
        generation.plan_id().clone(),
        generation.previous_generation().cloned(),
        previous.as_ref(),
        &prepared,
    )
    .map_err(CommitError::invalid_store)?;
    if &rebuilt != generation {
        return Err(CommitError::InvalidStore(
            "state generation does not match its prepared transition".to_owned(),
        ));
    }
    Ok(())
}

fn validate_retained_generation_transition_with_budget(
    store: &StoreHandles,
    generation: &StateGenerationV1,
    decoded_bytes: &mut usize,
) -> Result<(), CommitError> {
    let (prepared, prepared_bytes) = load_prepared_with_encoded_len(store, generation.plan_id())?;
    charge_lineage_validation_bytes(decoded_bytes, prepared_bytes)?;
    let rebuilt = StateGenerationV1::from_retained_prepared(
        generation.plan_id().clone(),
        generation.previous_generation().cloned(),
        &prepared,
    )
    .map_err(CommitError::invalid_store)?;
    if &rebuilt != generation {
        return Err(CommitError::InvalidStore(
            "retained state generation does not match its prepared authority".to_owned(),
        ));
    }
    Ok(())
}

fn validate_store_descriptor(root: &File, root_path: &Path, uid: u32) -> Result<(), CommitError> {
    let path = root_path.join(malm_root::DESCRIPTOR_FILENAME);
    let bytes = read_mutable(
        root,
        malm_root::DESCRIPTOR_FILENAME,
        &path,
        uid,
        malm_root::MAX_DESCRIPTOR_BYTES as u64,
    )?
    .ok_or_else(|| CommitError::InvalidStore("descriptor.json is missing".to_owned()))?;
    malm_root::decode_descriptor_v1(&bytes).map_err(|error| {
        CommitError::InvalidStore(format!("invalid final-root descriptor: {error}"))
    })?;
    Ok(())
}

fn validate_store_layout(root: &File, root_path: &Path, uid: u32) -> Result<(), CommitError> {
    for _ in 0..32 {
        match validate_store_layout_once(root, root_path, uid) {
            Err(CommitError::InvalidStore(reason))
                if reason == "final-root layout changed during admission" =>
            {
                continue;
            }
            result => return result,
        }
    }
    Err(CommitError::InvalidStore(
        "final-root layout changed during admission".to_owned(),
    ))
}

fn validate_store_layout_once(root: &File, root_path: &Path, uid: u32) -> Result<(), CommitError> {
    let before =
        fstat(root).map_err(|source| io_error("inspect final-root layout", root_path, source))?;
    let names = final_root_names(root, root_path)?;
    for name in &names {
        let contract = malm_root::final_root_entry(name.as_bytes()).ok_or_else(|| {
            CommitError::InvalidStore(format!(
                "final root contains unrecognized top-level entry {name:?}"
            ))
        })?;
        let path = root_path.join(name);
        match contract.kind() {
            malm_root::FinalRootEntryKind::Descriptor => {}
            malm_root::FinalRootEntryKind::Directory => {
                open_container(root, name, &path, uid)?;
            }
            malm_root::FinalRootEntryKind::Lock => {
                read_mutable(root, name, &path, uid, 0)?.ok_or_else(|| {
                    CommitError::InvalidStore(
                        "final-root lock vanished during admission".to_owned(),
                    )
                })?;
            }
        }
    }
    let after =
        fstat(root).map_err(|source| io_error("reinspect final-root layout", root_path, source))?;
    if !same_snapshot(&before, &after) || names != final_root_names(root, root_path)? {
        return Err(CommitError::InvalidStore(
            "final-root layout changed during admission".to_owned(),
        ));
    }
    Ok(())
}

fn final_root_names(root: &File, root_path: &Path) -> Result<Vec<String>, CommitError> {
    let mut entries = Dir::read_from(root)
        .map_err(|source| io_error("enumerate final-root layout", root_path, source))?;
    let mut names = Vec::new();
    while let Some(entry) = entries.read() {
        let entry =
            entry.map_err(|source| io_error("enumerate final-root layout", root_path, source))?;
        let bytes = entry.file_name().to_bytes();
        if matches!(bytes, b"." | b"..") {
            continue;
        }
        let Some(contract) = malm_root::final_root_entry(bytes) else {
            return Err(CommitError::InvalidStore(
                "final root contains an unrecognized top-level entry".to_owned(),
            ));
        };
        names.push(contract.name().to_owned());
    }
    names.sort();
    Ok(names)
}

fn open_container(parent: &File, leaf: &str, path: &Path, uid: u32) -> Result<File, CommitError> {
    open_optional_container(parent, leaf, path, uid)?
        .ok_or_else(|| CommitError::InvalidStore(format!("{} is missing", path.display())))
}

fn open_object_kind(
    objects: Option<&File>,
    leaf: &str,
    path: &Path,
    uid: u32,
) -> Result<Option<File>, CommitError> {
    objects
        .map(|objects| open_optional_container(objects, leaf, path, uid))
        .transpose()
        .map(Option::flatten)
}

fn open_optional_container(
    parent: &File,
    leaf: &str,
    path: &Path,
    uid: u32,
) -> Result<Option<File>, CommitError> {
    let result = openat2(
        parent,
        leaf,
        DIRECTORY_FLAGS | OFlags::NOFOLLOW | OFlags::NOATIME,
        Mode::empty(),
        ROOT_RESOLVE_FLAGS,
    );
    let directory = match result {
        Ok(directory) => File::from(directory),
        Err(rustix::io::Errno::NOENT) => return Ok(None),
        Err(source) => return Err(io_error("open store container", path, source)),
    };
    validate_directory(&directory, path, uid, CONTAINER_MODE)?;
    Ok(Some(directory))
}

fn open_or_create_container(
    parent: &File,
    leaf: &str,
    path: &Path,
    uid: u32,
) -> Result<File, CommitError> {
    if let Some(directory) = open_optional_container(parent, leaf, path, uid)? {
        fsync(&directory).map_err(|source| io_error("sync store container", path, source))?;
        fsync(parent).map_err(|source| io_error("sync store container parent", path, source))?;
        return Ok(directory);
    }
    match mkdirat(parent, leaf, Mode::from_raw_mode(CONTAINER_MODE)) {
        Ok(()) | Err(rustix::io::Errno::EXIST) => {}
        Err(source) => return Err(io_error("create store container", path, source)),
    }
    let directory = open_container(parent, leaf, path, uid)?;
    fsync(&directory).map_err(|source| io_error("sync store container", path, source))?;
    fsync(parent).map_err(|source| io_error("sync store container parent", path, source))?;
    Ok(directory)
}

fn ensure_bound(
    parent: &File,
    leaf: &str,
    pinned: &File,
    path: &Path,
    uid: u32,
) -> Result<(), CommitError> {
    let bound = statat(parent, leaf, AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|source| io_error("revalidate store container", path, source))?;
    let pinned_stat =
        fstat(pinned).map_err(|source| io_error("inspect pinned store container", path, source))?;
    validate_directory(pinned, path, uid, CONTAINER_MODE)?;
    if !same_object(&bound, &pinned_stat) {
        return Err(CommitError::InvalidStore(
            "store container binding changed".to_owned(),
        ));
    }
    Ok(())
}

fn validate_directory(file: &File, path: &Path, uid: u32, mode: u32) -> Result<(), CommitError> {
    let stat = fstat(file).map_err(|source| io_error("inspect directory", path, source))?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::Directory
        || stat.st_uid != uid
        || stat.st_mode & 0o7777 != mode
    {
        return Err(CommitError::InvalidStore(format!(
            "unsafe directory metadata at {}",
            path.display()
        )));
    }
    Ok(())
}

fn validate_state_parent_directory(file: &File, path: &Path, uid: u32) -> Result<(), CommitError> {
    let stat = fstat(file).map_err(|source| io_error("inspect state parent", path, source))?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::Directory
        || stat.st_uid != uid
        || stat.st_mode & 0o7022 != 0
    {
        return Err(CommitError::InvalidStore(format!(
            "unsafe state parent metadata at {}",
            path.display()
        )));
    }
    Ok(())
}

fn validate_target_directory(file: &File, path: &Path, uid: u32) -> Result<(), CommitError> {
    let stat = fstat(file).map_err(|source| io_error("inspect target directory", path, source))?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::Directory
        || stat.st_uid != uid
        || stat.st_mode & 0o7022 != 0
    {
        return Err(CommitError::UnsafeTarget(format!(
            "unsafe directory metadata at {}",
            path.display()
        )));
    }
    Ok(())
}

fn read_immutable(
    parent: &File,
    leaf: &str,
    path: &Path,
    uid: u32,
    max: u64,
) -> Result<Option<Vec<u8>>, CommitError> {
    read_entry(parent, leaf, path, uid, IMMUTABLE_MODE, max)
}

fn read_mutable(
    parent: &File,
    leaf: &str,
    path: &Path,
    uid: u32,
    max: u64,
) -> Result<Option<Vec<u8>>, CommitError> {
    read_entry(parent, leaf, path, uid, MUTABLE_MODE, max)
}

fn read_entry(
    parent: &File,
    leaf: &str,
    path: &Path,
    uid: u32,
    mode: u32,
    max: u64,
) -> Result<Option<Vec<u8>>, CommitError> {
    Ok(read_entry_pinned(parent, leaf, path, uid, mode, max)?.map(|(_file, bytes, _stat)| bytes))
}

fn read_mutable_pinned(
    parent: &File,
    leaf: &str,
    path: &Path,
    uid: u32,
    max: u64,
) -> Result<Option<(File, Vec<u8>, Stat)>, CommitError> {
    read_entry_pinned(parent, leaf, path, uid, MUTABLE_MODE, max)
}

fn read_entry_pinned(
    parent: &File,
    leaf: &str,
    path: &Path,
    uid: u32,
    mode: u32,
    max: u64,
) -> Result<Option<(File, Vec<u8>, Stat)>, CommitError> {
    let observed = match statat(parent, leaf, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(stat) => stat,
        Err(rustix::io::Errno::NOENT) => return Ok(None),
        Err(source) => return Err(io_error("inspect store entry", path, source)),
    };
    validate_file_stat(&observed, path, uid, mode, max)?;
    let mut file = openat2(
        parent,
        leaf,
        OFlags::RDONLY | OFlags::NONBLOCK | OFlags::NOFOLLOW | OFlags::NOATIME | OFlags::CLOEXEC,
        Mode::empty(),
        ROOT_RESOLVE_FLAGS,
    )
    .map(File::from)
    .map_err(|source| io_error("open store entry", path, source))?;
    let opened =
        fstat(&file).map_err(|source| io_error("inspect opened store entry", path, source))?;
    validate_file_stat(&opened, path, uid, mode, max)?;
    if !same_snapshot(&observed, &opened) {
        return Err(CommitError::InvalidStore(
            "store entry changed while opening".to_owned(),
        ));
    }
    let initial_capacity = u64::try_from(opened.st_size).unwrap_or(0).min(max);
    let mut bytes = Vec::with_capacity(usize::try_from(initial_capacity).unwrap_or(0));
    (&mut file)
        .take(max.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|source| CommitError::Io {
            operation: "read store entry",
            path: path.to_path_buf(),
            source,
        })?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > max {
        return Err(CommitError::InvalidStore(format!(
            "store entry exceeds its size limit at {}",
            path.display()
        )));
    }
    let after = fstat(&file).map_err(|source| io_error("reinspect store entry", path, source))?;
    if !same_snapshot(&opened, &after) {
        return Err(CommitError::InvalidStore(
            "store entry changed while reading".to_owned(),
        ));
    }
    Ok(Some((file, bytes, after)))
}

fn validate_file_stat(
    stat: &Stat,
    path: &Path,
    uid: u32,
    mode: u32,
    max: u64,
) -> Result<(), CommitError> {
    if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
        || stat.st_uid != uid
        || stat.st_mode & 0o7777 != mode
        || stat.st_nlink != 1
        || u64::try_from(stat.st_size).unwrap_or(u64::MAX) > max
    {
        return Err(CommitError::InvalidStore(format!(
            "unsafe file metadata at {}",
            path.display()
        )));
    }
    Ok(())
}

fn publish_immutable(
    parent: &File,
    leaf: &str,
    path: &Path,
    bytes: &[u8],
    uid: u32,
) -> Result<(), CommitError> {
    if let Some(existing) = read_immutable(
        parent,
        leaf,
        path,
        uid,
        malm_store::MAX_STATE_RECORD_BYTES as u64,
    )? {
        if existing == bytes {
            sync_existing_immutable(parent, leaf, path)?;
            return Ok(());
        }
        return Err(CommitError::InvalidStore(
            "immutable state generation name collision".to_owned(),
        ));
    }
    let mut temporary = openat(
        parent,
        ".",
        OFlags::TMPFILE | OFlags::RDWR | OFlags::CLOEXEC,
        Mode::from_raw_mode(IMMUTABLE_MODE),
    )
    .map(File::from)
    .map_err(|source| io_error("create immutable state object", path, source))?;
    fchmod(&temporary, Mode::from_raw_mode(IMMUTABLE_MODE))
        .map_err(|source| io_error("set immutable state mode", path, source))?;
    temporary
        .write_all(bytes)
        .map_err(|source| CommitError::Io {
            operation: "write immutable state object",
            path: path.to_path_buf(),
            source,
        })?;
    temporary.flush().map_err(|source| CommitError::Io {
        operation: "flush immutable state object",
        path: path.to_path_buf(),
        source,
    })?;
    fsync(&temporary).map_err(|source| io_error("sync immutable state object", path, source))?;
    match linkat(&temporary, "", parent, leaf, AtFlags::EMPTY_PATH) {
        Ok(()) => {}
        Err(rustix::io::Errno::EXIST) => {
            let existing = read_immutable(
                parent,
                leaf,
                path,
                uid,
                malm_store::MAX_STATE_RECORD_BYTES as u64,
            )?
            .ok_or_else(|| {
                CommitError::InvalidStore("concurrent state object vanished".to_owned())
            })?;
            if existing != bytes {
                return Err(CommitError::InvalidStore(
                    "concurrent state object differs".to_owned(),
                ));
            }
            sync_existing_immutable(parent, leaf, path)?;
        }
        Err(source) => return Err(io_error("publish immutable state object", path, source)),
    }
    fsync(parent).map_err(|source| io_error("sync state generation directory", path, source))
}

fn sync_existing_immutable(parent: &File, leaf: &str, path: &Path) -> Result<(), CommitError> {
    let file = openat2(
        parent,
        leaf,
        OFlags::RDONLY | OFlags::NONBLOCK | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
        ROOT_RESOLVE_FLAGS,
    )
    .map(File::from)
    .map_err(|source| io_error("open existing immutable state object", path, source))?;
    fsync(&file)
        .map_err(|source| io_error("sync existing immutable state object", path, source))?;
    fsync(parent).map_err(|source| io_error("sync state generation directory", path, source))
}

fn publish_initial_catalog_file(
    parent: &File,
    path: &Path,
    bytes: &[u8],
    uid: u32,
) -> Result<(), CommitError> {
    let leaf = "catalog.json";
    let temporary_name = ".catalog.json.new";
    let max = malm_store::MAX_STATE_CATALOG_BYTES as u64;
    require_store_entry_absent(parent, temporary_name, path)?;
    if let Some((existing, existing_bytes, _)) = read_mutable_pinned(parent, leaf, path, uid, max)?
    {
        if existing_bytes != bytes {
            return Err(CommitError::InvalidStore(
                "existing initial state catalog differs".to_owned(),
            ));
        }
        fsync(&existing).map_err(|source| io_error("sync existing state catalog", path, source))?;
        require_pinned_mutable_bytes(
            PinnedEntry {
                directory: parent,
                leaf,
                path,
                uid,
                max,
            },
            &existing,
            "existing state catalog",
            bytes,
        )?;
        fsync(parent).map_err(|source| io_error("sync initial state catalog", path, source))?;
        return require_pinned_store_entry(parent, leaf, &existing, path, "existing state catalog");
    }
    let temporary = write_unnamed_mutable(parent, path, bytes, "initial state catalog")?;
    match linkat(&temporary, "", parent, leaf, AtFlags::EMPTY_PATH) {
        Ok(()) => {}
        Err(rustix::io::Errno::EXIST) => {
            return Err(CommitError::InvalidStore(
                "concurrent state catalog appeared before publication".to_owned(),
            ));
        }
        Err(source) => return Err(io_error("publish initial state catalog", path, source)),
    }
    commit_failpoint!("v1.initialize.catalog.after_link");
    require_pinned_mutable_bytes(
        PinnedEntry {
            directory: parent,
            leaf,
            path,
            uid,
            max,
        },
        &temporary,
        "initial state catalog",
        bytes,
    )?;
    fsync(parent).map_err(|source| io_error("sync initial state catalog", path, source))?;
    let published = read_mutable(parent, leaf, path, uid, max)?
        .ok_or_else(|| CommitError::InvalidStore("initial state catalog vanished".to_owned()))?;
    if published != bytes {
        return Err(CommitError::InvalidStore(
            "initial state catalog differs from its published bytes".to_owned(),
        ));
    }
    Ok(())
}

/// A file identity recorded immediately after commit, paired with the content
/// digest proved by the committed state.
///
/// Any userspace write, metadata change, or rename changes `ctime`, and
/// userspace cannot set `ctime`. An exact [`FileIdentityV1`] match therefore
/// proves that the file still has `digest` without rereading it. Forging this
/// cache requires write access to the 0700 store, which already controls the
/// catalog and blobs, so the cache adds no authority. It is advisory: missing,
/// stale, or corrupt data only causes full content hashing.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ObservedFileV1 {
    identity: FileIdentityV1,
    digest: Digest,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ObservedNamespaceV1 {
    generation: Digest,
    files: BTreeMap<String, ObservedFileV1>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ObservedIdentitiesV1 {
    schema_version: u32,
    namespaces: BTreeMap<NamespaceName, ObservedNamespaceV1>,
}

const OBSERVED_IDENTITIES_FILE: &str = "observed.json";
const OBSERVED_IDENTITIES_STAGING: &str = ".observed.json.new";
/// Tree members can make this cache much larger than the catalog. If it exceeds
/// this limit, the cache is not written and later verification hashes content.
const OBSERVED_IDENTITIES_MAX_BYTES: usize = 16 * 1024 * 1024;

#[derive(Clone, Copy)]
struct ObservedScope<'a> {
    files: &'a BTreeMap<String, ObservedFileV1>,
    key: &'a str,
}

/// Reads the advisory identity cache. Missing, stale, malformed, or unsafe data
/// returns `None` instead of failing the operation.
fn read_observed_identities(store: &StoreHandles) -> Option<ObservedIdentitiesV1> {
    let state = store.state.as_ref()?;
    let path = store.root_path.join("state").join(OBSERVED_IDENTITIES_FILE);
    let bytes = read_mutable(
        state,
        OBSERVED_IDENTITIES_FILE,
        &path,
        store.uid,
        OBSERVED_IDENTITIES_MAX_BYTES as u64,
    )
    .ok()
    .flatten()?;
    let observed: ObservedIdentitiesV1 = serde_json::from_slice(&bytes).ok()?;
    (observed.schema_version == 1).then_some(observed)
}

/// Returns cached files only when the namespace entry belongs to `generation`.
fn observed_files_for(
    observed: Option<&ObservedIdentitiesV1>,
    namespace: &NamespaceName,
    generation: &Digest,
) -> Option<BTreeMap<String, ObservedFileV1>> {
    let entry = observed?.namespaces.get(namespace)?;
    (&entry.generation == generation).then(|| entry.files.clone())
}

/// Returns true when both the asserted digest and the complete live identity
/// match the cached observation.
fn observed_proves_state(
    observed: Option<&BTreeMap<String, ObservedFileV1>>,
    key: &str,
    file: &malm_store::StateFileV1,
    current: &Stat,
) -> bool {
    let Some(entry) = observed.and_then(|files| files.get(key)) else {
        return false;
    };
    entry.digest == *file.digest()
        && entry.identity.size == file.byte_len()
        && file_identity(current) == entry.identity
}

/// Buffers writes up to a fixed limit so cache serialization cannot allocate
/// beyond the advisory cache bound.
struct BoundedWriter {
    buffer: Vec<u8>,
    limit: usize,
}

impl BoundedWriter {
    fn new(limit: usize) -> Self {
        Self {
            buffer: Vec::new(),
            limit,
        }
    }

    fn into_vec(self) -> Vec<u8> {
        self.buffer
    }
}

impl Write for BoundedWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.buffer.len() + buf.len() > self.limit {
            return Err(io::Error::other(
                "observed-identity cache exceeds its byte limit",
            ));
        }
        self.buffer.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Best-effort update of the committed namespace's identity cache.
///
/// This runs after catalog publication. Failure may discard the cache but must
/// not fail or roll back the commit, so all errors are ignored.
///
/// A crash can leave `.observed.json.new`, causing the next staging `linkat` to
/// return `EEXIST`. Ignoring that error deliberately drops the new cache and
/// makes later commits hash content again. The catalog and journal, not this
/// cache, remain the durable authority.
fn record_observed_identities(
    store: &StoreHandles,
    targets: &[PinnedTarget],
    namespace: &NamespaceName,
    generation: Option<(&Digest, &StateGenerationV1)>,
    canonical: &canonical::CanonicalObjects,
) -> Option<()> {
    let state = store.state.as_ref()?;
    let path = store.root_path.join("state").join(OBSERVED_IDENTITIES_FILE);
    let mut observed = read_observed_identities(store).unwrap_or_default();
    observed.schema_version = 1;
    match generation {
        None => {
            observed.namespaces.remove(namespace);
        }
        Some((digest, generation)) => {
            let mut file_states: BTreeMap<&str, &malm_store::StateFileV1> = BTreeMap::new();
            let mut tree_states: BTreeMap<&str, &Digest> = BTreeMap::new();
            for target in generation.desired_snapshot().targets() {
                match target.state() {
                    StateTargetStateV1::File { file: Some(file) } => {
                        file_states.insert(target.relative_path(), file);
                    }
                    StateTargetStateV1::Tree { tree: Some(tree) } => {
                        tree_states.insert(target.relative_path(), tree.tree());
                    }
                    _ => {}
                }
            }
            let mut files = BTreeMap::new();
            for target in targets {
                let observation = target.operation.observation();
                let key = format!(
                    "{}:{}",
                    observation.authority(),
                    observation.relative_path()
                );
                if let Some(file) = file_states.get(observation.relative_path()) {
                    let Ok(stat) = statat(&target.parent, &target.leaf, AtFlags::SYMLINK_NOFOLLOW)
                    else {
                        continue;
                    };
                    if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
                        || u64::try_from(stat.st_size).ok() != Some(file.byte_len())
                    {
                        continue;
                    }
                    files.insert(
                        key,
                        ObservedFileV1 {
                            identity: file_identity(&stat),
                            digest: file.digest().clone(),
                        },
                    );
                } else if let Some(tree) = tree_states.get(observation.relative_path()) {
                    // Record tree members in one stat walk so the next commit
                    // can prove unchanged members by identity instead of
                    // reading their content.
                    let Ok(root) = openat2(
                        &target.parent,
                        &target.leaf,
                        DIRECTORY_FLAGS | OFlags::NOFOLLOW,
                        Mode::empty(),
                        ROOT_RESOLVE_FLAGS,
                    ) else {
                        continue;
                    };
                    record_tree_member_identities(
                        &File::from(root),
                        tree,
                        canonical,
                        &key,
                        &mut files,
                    );
                }
            }
            observed.namespaces.insert(
                namespace.clone(),
                ObservedNamespaceV1 {
                    generation: digest.clone(),
                    files,
                },
            );
        }
    }
    // Serialize through the bounded writer so the temporary allocation cannot
    // grow beyond the cache limit.
    let mut writer = BoundedWriter::new(OBSERVED_IDENTITIES_MAX_BYTES);
    serde_json::to_writer(&mut writer, &observed).ok()?;
    let bytes = writer.into_vec();
    let temporary =
        write_unnamed_mutable(state, &path, &bytes, "observed-identity staging").ok()?;
    let _ = unlinkat(state, OBSERVED_IDENTITIES_STAGING, AtFlags::empty());
    linkat(
        &temporary,
        "",
        state,
        OBSERVED_IDENTITIES_STAGING,
        AtFlags::EMPTY_PATH,
    )
    .ok()?;
    renameat_with(
        state,
        OBSERVED_IDENTITIES_STAGING,
        state,
        OBSERVED_IDENTITIES_FILE,
        RenameFlags::empty(),
    )
    .ok()?;
    fsync(state).ok()?;
    Some(())
}

fn replace_catalog(
    parent: &File,
    path: &Path,
    bytes: &[u8],
    expected: &[u8],
    uid: u32,
) -> Result<(), CommitError> {
    let leaf = "catalog.json";
    let temporary_name = ".catalog.json.new";
    let max = malm_store::MAX_STATE_CATALOG_BYTES as u64;
    require_store_entry_absent(parent, temporary_name, path)?;
    let current = read_mutable_pinned(parent, leaf, path, uid, max)?.ok_or_else(|| {
        CommitError::InvalidStore("state catalog vanished before publication".to_owned())
    })?;
    if current.1 != expected {
        return Err(CommitError::InvalidStore(
            "state catalog changed before publication".to_owned(),
        ));
    }
    let temporary = write_unnamed_mutable(parent, path, bytes, "state-catalog staging file")?;
    linkat(&temporary, "", parent, temporary_name, AtFlags::EMPTY_PATH)
        .map_err(|source| io_error("stage state catalog", path, source))?;
    fsync(parent).map_err(|source| io_error("sync staged state catalog", path, source))?;
    commit_failpoint!("v1.commit.catalog.after_staging");
    let (current, current_bytes, _) = current;
    exchange_pinned_store_entries(
        PinnedExchange {
            directory: parent,
            path,
            role: "state catalog",
            uid,
            max,
        },
        ExchangeSide {
            leaf: temporary_name,
            pinned: &temporary,
            bytes,
        },
        ExchangeSide {
            leaf,
            pinned: &current,
            bytes: &current_bytes,
        },
    )?;
    commit_failpoint!("v1.commit.catalog.after_exchange");
    remove_pinned_mutable_entry(
        PinnedEntry {
            directory: parent,
            leaf: temporary_name,
            path: &path.with_file_name(temporary_name),
            uid,
            max,
        },
        &current_bytes,
        "remove prior state catalog",
    )?;
    fsync(parent).map_err(|source| io_error("sync published state catalog", path, source))?;
    let published = read_mutable(parent, leaf, path, uid, max)?
        .ok_or_else(|| CommitError::InvalidStore("published state catalog vanished".to_owned()))?;
    if published != bytes {
        return Err(CommitError::InvalidStore(
            "published state catalog differs from its staged bytes".to_owned(),
        ));
    }
    Ok(())
}

fn remove_catalog_staging(
    store: &StoreHandles,
    journal: &TransactionJournalV1,
) -> Result<(), CommitError> {
    let Some(pinned) = load_catalog_staging(store, journal)? else {
        return Ok(());
    };
    let Some(state) = &store.state else {
        return Ok(());
    };
    let path = store.root_path.join("state/.catalog.json.new");
    require_pinned_store_entry(
        state,
        ".catalog.json.new",
        &pinned,
        &path,
        "state-catalog staging",
    )?;
    unlinkat(state, ".catalog.json.new", AtFlags::empty())
        .map_err(|source| io_error("remove state-catalog staging", &path, source))?;
    fsync(state).map_err(|source| io_error("sync state directory", &path, source))?;
    store.revalidate()
}

fn validate_catalog_staging(
    store: &StoreHandles,
    journal: &TransactionJournalV1,
) -> Result<(), CommitError> {
    load_catalog_staging(store, journal).map(|_| ())
}

fn load_catalog_staging(
    store: &StoreHandles,
    journal: &TransactionJournalV1,
) -> Result<Option<File>, CommitError> {
    let Some(state) = &store.state else {
        return Ok(None);
    };
    let path = store.root_path.join("state/.catalog.json.new");
    let Some((pinned, bytes, _)) = read_mutable_pinned(
        state,
        ".catalog.json.new",
        &path,
        store.uid,
        malm_store::MAX_STATE_CATALOG_BYTES as u64,
    )?
    else {
        return Ok(None);
    };
    let catalog = decode_state_catalog_v1(&bytes)
        .map_err(|error| CommitError::InvalidJournal(error.to_string()))?;
    let digest = state_catalog_digest_v1(&catalog);
    if digest != journal.next_catalog && digest != journal.previous_catalog {
        return Err(CommitError::InvalidJournal(
            "state-catalog staging is neither transaction catalog".to_owned(),
        ));
    }
    require_pinned_store_entry(
        state,
        ".catalog.json.new",
        &pinned,
        &path,
        "state-catalog staging",
    )?;
    Ok(Some(pinned))
}

fn require_catalog_staging_absent(store: &StoreHandles) -> Result<(), CommitError> {
    let Some(state) = &store.state else {
        return Ok(());
    };
    require_store_entry_absent(
        state,
        ".catalog.json.new",
        &store.root_path.join("state/catalog.json"),
    )
}

fn require_store_entry_absent(parent: &File, leaf: &str, path: &Path) -> Result<(), CommitError> {
    match statat(parent, leaf, AtFlags::SYMLINK_NOFOLLOW) {
        Err(rustix::io::Errno::NOENT) => Ok(()),
        Ok(_) => Err(CommitError::InvalidStore(format!(
            "unidentified staging entry exists at {}",
            path.with_file_name(leaf).display()
        ))),
        Err(source) => Err(io_error("inspect store staging entry", path, source)),
    }
}

fn compare_leaf(
    parent: &File,
    leaf: &OsStr,
    expected: LeafObservationV1,
    path: &Path,
) -> Result<(), CommitError> {
    let actual = match statat(parent, leaf, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(stat) => Some(stat),
        Err(rustix::io::Errno::NOENT) => None,
        Err(source) => return Err(io_error("revalidate target leaf", path, source)),
    };
    match (expected, actual) {
        (LeafObservationV1::Absent, None) => Ok(()),
        (LeafObservationV1::Present(expected), Some(actual)) => {
            // Directory children may change during this plan or through
            // allowed unmanaged content, which changes the directory's times,
            // size, and link count. Bind a directory by object, owner, and
            // mode. Non-directories must match the complete identity and have
            // only one hard link.
            if FileType::from_raw_mode(expected.mode) == FileType::Directory {
                compare_created_identity(&actual, expected, "target leaf")?;
                return Ok(());
            }
            compare_identity(&actual, expected, "target leaf")?;
            if actual.st_nlink != 1 {
                return Err(CommitError::UnsafeTarget(
                    "target leaf has multiple hard links".to_owned(),
                ));
            }
            Ok(())
        }
        _ => Err(CommitError::StaleTarget(
            "target leaf presence changed".to_owned(),
        )),
    }
}

fn compare_identity(stat: &Stat, expected: FileIdentityV1, role: &str) -> Result<(), CommitError> {
    let actual = file_identity(stat);
    if actual != expected {
        return Err(CommitError::StaleTarget(format!("{role} identity changed")));
    }
    Ok(())
}

fn compare_object_identity(
    stat: &Stat,
    expected: FileIdentityV1,
    role: &str,
) -> Result<(), CommitError> {
    if stat.st_dev != expected.device || stat.st_ino != expected.inode {
        return Err(CommitError::StaleTarget(format!(
            "{role} object identity changed"
        )));
    }
    Ok(())
}

fn compare_created_identity(
    stat: &Stat,
    expected: FileIdentityV1,
    role: &str,
) -> Result<(), CommitError> {
    if !same_created_identity(stat, expected) {
        return Err(CommitError::StaleTarget(format!("{role} identity changed")));
    }
    Ok(())
}

fn same_created_identity(stat: &Stat, expected: FileIdentityV1) -> bool {
    // Child operations legitimately change a created directory's link count,
    // size, and times. Prove the same device and inode, owner, and exact mode;
    // directories cannot be hard-linked into place, and child operations
    // verify their own entries. Non-directories retain the full relocated
    // identity check.
    if FileType::from_raw_mode(expected.mode) == FileType::Directory {
        let actual = file_identity(stat);
        return actual.device == expected.device
            && actual.inode == expected.inode
            && actual.user_id == expected.user_id
            && actual.group_id == expected.group_id
            && actual.mode == expected.mode;
    }
    same_relocated_identity(stat, expected)
}

fn compare_relocated_identity(
    stat: &Stat,
    expected: FileIdentityV1,
    role: &str,
) -> Result<(), CommitError> {
    if !same_relocated_identity(stat, expected) {
        return Err(CommitError::StaleTarget(format!("{role} identity changed")));
    }
    Ok(())
}

fn journaled_backup_identity(journal: &JournalOperationV1) -> Result<FileIdentityV1, CommitError> {
    match journal.backup {
        Some(JournalBackupV1::Identified { identity, .. }) => Ok(identity),
        Some(JournalBackupV1::Intent { .. }) => Err(CommitError::InvalidJournal(
            "transaction backup intent has no identified backup".to_owned(),
        )),
        None => Err(CommitError::InvalidJournal(
            "transaction backup has no journaled identity".to_owned(),
        )),
    }
}

fn journaled_backup_source_digest(
    journal: &JournalOperationV1,
) -> Result<Option<SourceDigestV1>, CommitError> {
    match journal.backup {
        Some(JournalBackupV1::Identified { source_digest, .. }) => Ok(source_digest),
        Some(JournalBackupV1::Intent { .. }) => Err(CommitError::InvalidJournal(
            "transaction backup intent has no identified backup".to_owned(),
        )),
        None => Err(CommitError::InvalidJournal(
            "transaction backup has no journaled identity".to_owned(),
        )),
    }
}

const fn backup_source_digest(journal: &JournalOperationV1) -> Option<SourceDigestV1> {
    match journal.backup {
        Some(
            JournalBackupV1::Intent { source_digest }
            | JournalBackupV1::Identified { source_digest, .. },
        ) => source_digest,
        None => None,
    }
}

fn compare_journaled_backup(stat: &Stat, journal: &JournalOperationV1) -> Result<(), CommitError> {
    compare_identity(
        stat,
        journaled_backup_identity(journal)?,
        "transaction backup",
    )
}

struct PinnedPreparedSource {
    file: File,
    content_digest: Option<SourceDigestV1>,
}

fn pin_prepared_source(
    parent: &File,
    leaf: &OsStr,
    expected: FileIdentityV1,
    path: &Path,
    role: &str,
) -> Result<PinnedPreparedSource, CommitError> {
    let regular = FileType::from_raw_mode(expected.mode) == FileType::RegularFile;
    let flags = if regular {
        OFlags::RDONLY | OFlags::NONBLOCK | OFlags::NOFOLLOW | OFlags::CLOEXEC
    } else {
        OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC
    };
    let file = openat2(parent, leaf, flags, Mode::empty(), ROOT_RESOLVE_FLAGS)
        .map(File::from)
        .map_err(|source| io_error("pin prepared target source", path, source))?;
    let pinned =
        fstat(&file).map_err(|source| io_error("inspect prepared target source", path, source))?;
    compare_identity(&pinned, expected, role)?;
    let bound = statat(parent, leaf, AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|source| io_error("revalidate prepared target source", path, source))?;
    if !same_snapshot(&bound, &pinned) {
        return Err(CommitError::StaleTarget(format!(
            "{role} binding changed while pinning"
        )));
    }
    commit_failpoint!("v1.commit.source.before_initial_hash");
    let (content_digest, content_snapshot) = if regular {
        let (digest, hashed) = stable_file_digest(&file, path, role)?;
        if !same_snapshot(&pinned, &hashed) {
            return Err(CommitError::StaleTarget(format!(
                "{role} changed before hashing"
            )));
        }
        (Some(digest), Some(hashed))
    } else {
        (None, None)
    };
    let final_stat = require_pinned_entry(parent, leaf, &file, path, role)?;
    if content_snapshot.is_some_and(|hashed| !same_snapshot(&hashed, &final_stat)) {
        return Err(CommitError::StaleTarget(format!(
            "{role} changed after hashing"
        )));
    }
    Ok(PinnedPreparedSource {
        file,
        content_digest,
    })
}

fn verify_relocated_source(
    parent: &File,
    leaf: &OsStr,
    pinned: &PinnedPreparedSource,
    expected: FileIdentityV1,
    path: &Path,
    role: &str,
) -> Result<Stat, CommitError> {
    let bound = statat(parent, leaf, AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|source| io_error("inspect relocated target source", path, source))?;
    let opened = fstat(&pinned.file)
        .map_err(|source| io_error("reinspect relocated target source", path, source))?;
    if !same_object(&bound, &opened) {
        return Err(CommitError::StaleTarget(format!(
            "{role} object changed during relocation"
        )));
    }
    compare_relocated_identity(&opened, expected, role)?;
    let relocation_snapshot = if let Some(expected_digest) = pinned.content_digest {
        let (actual_digest, hashed) = stable_file_digest(&pinned.file, path, role)?;
        if !same_snapshot(&opened, &hashed) {
            return Err(CommitError::StaleTarget(format!(
                "{role} changed before relocated hashing"
            )));
        }
        if actual_digest != expected_digest {
            return Err(CommitError::StaleTarget(format!(
                "{role} content changed during relocation"
            )));
        }
        commit_failpoint!("v1.commit.source.after_relocated_hash");
        hashed
    } else {
        opened
    };
    let after = fstat(&pinned.file)
        .map_err(|source| io_error("reinspect relocated target source", path, source))?;
    let rebound = statat(parent, leaf, AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|source| io_error("revalidate relocated target source", path, source))?;
    if !same_snapshot(&relocation_snapshot, &after) || !same_snapshot(&rebound, &after) {
        return Err(CommitError::StaleTarget(format!(
            "{role} binding changed after relocation"
        )));
    }
    Ok(after)
}

fn stable_file_digest(
    file: &File,
    path: &Path,
    role: &str,
) -> Result<(SourceDigestV1, Stat), CommitError> {
    let before = fstat(file).map_err(|source| io_error("inspect target content", path, source))?;
    let mut reader = file.try_clone().map_err(|source| CommitError::Io {
        operation: "clone target content descriptor",
        path: path.to_path_buf(),
        source,
    })?;
    reader
        .seek(SeekFrom::Start(0))
        .map_err(|source| CommitError::Io {
            operation: "rewind target content descriptor",
            path: path.to_path_buf(),
            source,
        })?;
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = reader.read(&mut buffer).map_err(|source| CommitError::Io {
            operation: "read target content for relocation",
            path: path.to_path_buf(),
            source,
        })?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    let after = fstat(file).map_err(|source| io_error("reinspect target content", path, source))?;
    if !same_snapshot(&before, &after) {
        return Err(CommitError::StaleTarget(format!(
            "{role} changed while hashing"
        )));
    }
    Ok((SourceDigestV1(digest.finalize().into()), after))
}

fn require_pinned_entry(
    parent: &File,
    leaf: &OsStr,
    pinned: &File,
    path: &Path,
    role: &str,
) -> Result<Stat, CommitError> {
    let bound = statat(parent, leaf, AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|source| io_error("revalidate pinned transaction entry", path, source))?;
    let opened = fstat(pinned)
        .map_err(|source| io_error("inspect pinned transaction entry", path, source))?;
    if !same_snapshot(&bound, &opened) {
        return Err(CommitError::StaleTarget(format!("{role} binding changed")));
    }
    Ok(opened)
}

fn unlink_pinned_entry(
    parent: &File,
    leaf: &OsStr,
    pinned: &File,
    flags: AtFlags,
    path: &Path,
    role: &str,
) -> Result<(), CommitError> {
    let validated = fstat(pinned)
        .map_err(|source| io_error("inspect entry before pinned removal", path, source))?;
    let final_stat = require_pinned_entry(parent, leaf, pinned, path, role)?;
    if !same_snapshot(&validated, &final_stat) {
        return Err(CommitError::InvalidJournal(format!(
            "{role} changed before removal"
        )));
    }
    unlinkat(parent, leaf, flags).map_err(|source| io_error("remove pinned entry", path, source))
}

fn require_relocated_pinned_entry(
    parent: &File,
    leaf: &OsStr,
    pinned: &File,
    expected: FileIdentityV1,
    path: &Path,
    role: &str,
) -> Result<(), CommitError> {
    let bound = statat(parent, leaf, AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|source| io_error("inspect relocated transaction entry", path, source))?;
    let opened = fstat(pinned)
        .map_err(|source| io_error("reinspect relocated transaction entry", path, source))?;
    if !same_object(&bound, &opened) || !same_relocated_identity(&opened, expected) {
        return Err(CommitError::StaleTarget(format!(
            "{role} changed during relocation"
        )));
    }
    Ok(())
}

fn restore_raced_staging(
    parent: &File,
    leaf: &OsStr,
    staging: &OsStr,
    path: &Path,
    role: &str,
) -> Result<(), CommitError> {
    let raced = statat(parent, leaf, AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|source| io_error("inspect raced transaction staging", path, source))?;
    restore_pinned_backup(
        parent,
        leaf,
        staging,
        path,
        BackupExpectation::exact(file_identity(&raced), role),
    )
}

fn verify_entry_source_digest(
    parent: &File,
    leaf: &OsStr,
    expected_digest: SourceDigestV1,
    path: &Path,
    role: &str,
) -> Result<(), CommitError> {
    let file = openat2(
        parent,
        leaf,
        OFlags::RDONLY | OFlags::NONBLOCK | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
        ROOT_RESOLVE_FLAGS,
    )
    .map(File::from)
    .map_err(|source| io_error("pin transaction source content", path, source))?;
    let initial = fstat(&file)
        .map_err(|source| io_error("inspect transaction source content", path, source))?;
    let bound = statat(parent, leaf, AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|source| io_error("revalidate transaction source content", path, source))?;
    if !same_snapshot(&bound, &initial) {
        return Err(CommitError::StaleTarget(format!(
            "{role} binding changed while hashing"
        )));
    }
    let (actual_digest, hashed) = stable_file_digest(&file, path, role)?;
    if !same_snapshot(&initial, &hashed) || actual_digest != expected_digest {
        return Err(CommitError::StaleTarget(format!(
            "{role} content differs from durable backup intent"
        )));
    }
    let final_stat = fstat(&file)
        .map_err(|source| io_error("reinspect transaction source content", path, source))?;
    let final_bound = statat(parent, leaf, AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|source| io_error("revalidate transaction source content", path, source))?;
    if !same_snapshot(&hashed, &final_stat) || !same_snapshot(&final_bound, &final_stat) {
        return Err(CommitError::StaleTarget(format!(
            "{role} changed after hashing"
        )));
    }
    Ok(())
}

/// Verifies an adopted backup against the source recorded in the journal.
/// Regular files must have and match a content digest. Only an entry that could
/// not be hashed, such as a symlink, may omit one.
fn verify_adopted_backup(
    parent: &File,
    leaf: &OsStr,
    source_digest: Option<SourceDigestV1>,
    path: &Path,
) -> Result<(), CommitError> {
    let Some(expected) = source_digest else {
        let stat = entry_stat(parent, leaf, path)?.ok_or_else(|| {
            CommitError::InvalidJournal("adopted replacement backup is missing".to_owned())
        })?;
        if FileType::from_raw_mode(stat.st_mode) == FileType::RegularFile {
            return Err(CommitError::InvalidJournal(
                "adopted replacement backup has no journaled content digest".to_owned(),
            ));
        }
        return Ok(());
    };
    verify_entry_source_digest(parent, leaf, expected, path, "adopted replacement backup")
}

/// The identity and optional content digest that a backup must retain before it
/// can be restored. `exact_before` distinguishes an identified backup from a
/// backup known only by its pre-rename identity.
#[derive(Clone, Copy)]
struct BackupExpectation<'a> {
    identity: FileIdentityV1,
    exact_before: bool,
    source_digest: Option<SourceDigestV1>,
    role: &'a str,
}

impl<'a> BackupExpectation<'a> {
    /// Requires an exact identity match without a content-digest check.
    const fn exact(identity: FileIdentityV1, role: &'a str) -> Self {
        Self {
            identity,
            exact_before: true,
            source_digest: None,
            role,
        }
    }

    /// Builds the rollback proof from the journal. An identified backup must
    /// match its journaled identity exactly. A bare intent can only prove the
    /// prepared object after relocation.
    fn rollback(
        journal: &JournalOperationV1,
        prepared: FileIdentityV1,
        role: &'a str,
    ) -> Result<Self, CommitError> {
        let (identity, exact_before, source_digest) = match journal.backup {
            Some(JournalBackupV1::Intent { source_digest }) => (prepared, false, source_digest),
            Some(JournalBackupV1::Identified {
                identity,
                source_digest,
            }) => (identity, true, source_digest),
            None => {
                return Err(CommitError::InvalidJournal(
                    "transaction backup has no durable intent".to_owned(),
                ));
            }
        };
        Ok(Self {
            identity,
            exact_before,
            source_digest,
            role,
        })
    }

    /// Checks the backup with the exact or relocated comparison selected by the
    /// journal phase.
    fn compare(self, stat: &Stat, intent_role: &str) -> Result<(), CommitError> {
        if self.exact_before {
            compare_identity(stat, self.identity, self.role)
        } else {
            compare_relocated_identity(stat, self.identity, intent_role)
        }
    }

    /// Builds an exact expectation from an identified journal backup.
    fn journaled(operation: &JournalOperationV1) -> Result<Self, CommitError> {
        Ok(Self {
            identity: journaled_backup_identity(operation)?,
            exact_before: true,
            source_digest: journaled_backup_source_digest(operation)?,
            role: "transaction replacement backup",
        })
    }
}

fn restore_pinned_backup(
    parent: &File,
    backup_name: &OsStr,
    leaf: &OsStr,
    path: &Path,
    expected: BackupExpectation<'_>,
) -> Result<(), CommitError> {
    let BackupExpectation {
        identity,
        exact_before,
        source_digest,
        role,
    } = expected;
    require_entry_absent(parent, leaf, path)?;
    let flags = if source_digest.is_some() {
        OFlags::RDONLY | OFlags::NONBLOCK | OFlags::CLOEXEC | OFlags::NOFOLLOW
    } else {
        OFlags::PATH | OFlags::CLOEXEC | OFlags::NOFOLLOW
    };
    let pinned = openat2(
        parent,
        backup_name,
        flags,
        Mode::empty(),
        ROOT_RESOLVE_FLAGS,
    )
    .map(File::from)
    .map_err(|source| io_error("pin transaction backup for restoration", path, source))?;
    let pinned_before = fstat(&pinned)
        .map_err(|source| io_error("inspect pinned transaction backup", path, source))?;
    if exact_before {
        compare_identity(&pinned_before, identity, role)?;
    } else {
        compare_relocated_identity(&pinned_before, identity, role)?;
    }
    let content_snapshot = if let Some(expected_digest) = source_digest {
        let (actual_digest, hashed) = stable_file_digest(&pinned, path, role)?;
        if !same_snapshot(&pinned_before, &hashed) || actual_digest != expected_digest {
            return Err(CommitError::StaleTarget(format!(
                "{role} content changed before restoration"
            )));
        }
        Some(hashed)
    } else {
        None
    };
    let bound_before = statat(parent, backup_name, AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|source| io_error("revalidate transaction backup", path, source))?;
    if !same_snapshot(&bound_before, &pinned_before) {
        return Err(CommitError::RollbackFailed(format!(
            "{role} binding changed before restoration"
        )));
    }
    let immediately_before =
        fstat(&pinned).map_err(|source| io_error("reinspect transaction backup", path, source))?;
    if content_snapshot.is_some_and(|hashed| !same_snapshot(&hashed, &immediately_before)) {
        return Err(CommitError::StaleTarget(format!(
            "{role} changed after restoration hashing"
        )));
    }

    renameat_with(parent, backup_name, parent, leaf, RenameFlags::NOREPLACE)
        .map_err(|source| io_error("restore pinned transaction backup", path, source))?;
    let bound_after = statat(parent, leaf, AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|source| io_error("inspect restored transaction backup", path, source))?;
    let pinned_after = fstat(&pinned)
        .map_err(|source| io_error("revalidate restored transaction backup", path, source))?;
    if !same_snapshot(&bound_after, &pinned_after)
        || !same_relocated_identity(&bound_after, identity)
    {
        // Do not move the foreign leaf into the durable backup name. The
        // original backup inode is now reachable only through `pinned` because
        // Linux has no unprivileged linkat-from-fd operation. Reusing the backup
        // name for foreign content would give recovery and operators false
        // evidence, so leave that content at `leaf` and fail.
        let _ = fsync(parent);
        return Err(CommitError::RollbackFailed(format!(
            "{role} identity changed during restoration"
        )));
    }
    let restored_snapshot = if let Some(expected_digest) = source_digest {
        let (actual_digest, hashed) = stable_file_digest(&pinned, path, role)?;
        if !same_snapshot(&pinned_after, &hashed) || actual_digest != expected_digest {
            return Err(CommitError::StaleTarget(format!(
                "{role} content changed during restoration"
            )));
        }
        hashed
    } else {
        pinned_after
    };
    let final_stat = fstat(&pinned)
        .map_err(|source| io_error("reinspect restored transaction backup", path, source))?;
    let final_bound = statat(parent, leaf, AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|source| io_error("revalidate restored transaction backup", path, source))?;
    if !same_snapshot(&restored_snapshot, &final_stat) || !same_snapshot(&final_bound, &final_stat)
    {
        return Err(CommitError::RollbackFailed(format!(
            "{role} changed after restoration"
        )));
    }
    require_entry_absent(parent, backup_name, path)?;
    fsync(parent).map_err(|source| io_error("sync restored transaction backup", path, source))?;
    commit_failpoint!("v1.commit.rollback.after_restore");
    Ok(())
}

fn same_relocated_identity(stat: &Stat, expected: FileIdentityV1) -> bool {
    same_relocated_file_identity(file_identity(stat), expected)
}

fn same_relocated_file_identity(actual: FileIdentityV1, expected: FileIdentityV1) -> bool {
    actual.device == expected.device
        && actual.inode == expected.inode
        && actual.user_id == expected.user_id
        && actual.group_id == expected.group_id
        && actual.mode == expected.mode
        && actual.links == expected.links
        && actual.size == expected.size
        && actual.modified_seconds == expected.modified_seconds
        && actual.modified_nanoseconds == expected.modified_nanoseconds
}

fn compare_identity_for_mode(
    stat: &Stat,
    expected: FileIdentityV1,
    role: &str,
    recovery: bool,
) -> Result<(), CommitError> {
    if recovery {
        compare_object_identity(stat, expected, role)
    } else {
        compare_identity(stat, expected, role)
    }
}

fn entry_stat(parent: &File, leaf: &OsStr, path: &Path) -> Result<Option<Stat>, CommitError> {
    match statat(parent, leaf, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(stat) => Ok(Some(stat)),
        Err(rustix::io::Errno::NOENT) => Ok(None),
        Err(source) => Err(io_error("inspect transaction entry", path, source)),
    }
}

fn quarantine_and_unlink_created_entry<F>(
    parent: &File,
    leaf: &OsStr,
    quarantine: &OsStr,
    path: &Path,
    expected: FileIdentityV1,
    flags: AtFlags,
    validate: F,
) -> Result<(), CommitError>
where
    F: Fn(&OsStr) -> Result<(), CommitError>,
{
    quarantine_and_unlink_entry(
        QuarantineEntry {
            parent,
            source: Some(leaf),
            quarantine,
            path,
            identity: expected,
            created: true,
        },
        flags,
        validate,
    )
}

/// Describes an entry being quarantined before removal. `source` is absent when
/// the entry is already quarantined. `created` selects the identity rule for a
/// transaction-created entry rather than a relocated backup.
#[derive(Clone, Copy)]
struct QuarantineEntry<'a> {
    parent: &'a File,
    source: Option<&'a OsStr>,
    quarantine: &'a OsStr,
    path: &'a Path,
    identity: FileIdentityV1,
    created: bool,
}

fn quarantine_and_unlink_entry<F>(
    entry: QuarantineEntry<'_>,
    flags: AtFlags,
    validate: F,
) -> Result<(), CommitError>
where
    F: Fn(&OsStr) -> Result<(), CommitError>,
{
    let QuarantineEntry {
        parent,
        source,
        quarantine,
        path,
        identity: expected,
        created,
    } = entry;
    if let Some(source) = source {
        require_entry_absent(parent, quarantine, path)?;
        renameat_with(parent, source, parent, quarantine, RenameFlags::NOREPLACE)
            .map_err(|error| io_error("quarantine transaction entry", path, error))?;
        fsync(parent).map_err(|source| io_error("sync transaction quarantine", path, source))?;
        commit_failpoint!("v1.commit.cleanup.after_quarantine");
    }
    let before = entry_stat(parent, quarantine, path)?.ok_or_else(|| {
        CommitError::InvalidJournal("quarantined transaction entry is missing".to_owned())
    })?;
    let checked = if created {
        compare_created_identity(&before, expected, "quarantined transaction-created entry")
    } else {
        compare_relocated_identity(&before, expected, "quarantined transaction backup")
    }
    .and_then(|()| validate(quarantine))
    .and_then(|()| {
        let after = entry_stat(parent, quarantine, path)?.ok_or_else(|| {
            CommitError::InvalidJournal("quarantined transaction entry vanished".to_owned())
        })?;
        if same_snapshot(&before, &after) {
            Ok(())
        } else {
            Err(CommitError::InvalidJournal(
                "quarantined transaction entry changed during validation".to_owned(),
            ))
        }
    });
    if let Err(error) = checked {
        if let Some(source) = source
            && entry_stat(parent, source, path)?.is_none()
        {
            renameat_with(parent, quarantine, parent, source, RenameFlags::NOREPLACE).map_err(
                |restore| {
                    CommitError::RollbackFailed(format!(
                        "restore mismatched quarantined entry: {restore}"
                    ))
                },
            )?;
            fsync(parent)
                .map_err(|source| io_error("sync restored quarantined entry", path, source))?;
        }
        return Err(error);
    }
    let pinned = openat2(
        parent,
        quarantine,
        OFlags::PATH | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
        ROOT_RESOLVE_FLAGS,
    )
    .map(File::from)
    .map_err(|source| io_error("pin quarantined transaction entry", path, source))?;
    let pinned_before = fstat(&pinned)
        .map_err(|source| io_error("inspect pinned transaction entry", path, source))?;
    if !same_snapshot(&before, &pinned_before) {
        return Err(CommitError::InvalidJournal(
            "quarantined transaction entry changed while pinning".to_owned(),
        ));
    }
    // Before the final parent fsync, crash-visible quarantine state depends on
    // the filesystem. Failpoint tests must allow the different outcomes of ext4
    // data=ordered, ext4 data=journal, and XFS.
    commit_failpoint!("v1.commit.cleanup.before_unlink");
    let bound = statat(parent, quarantine, AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|source| io_error("revalidate quarantined transaction entry", path, source))?;
    let pinned_after = fstat(&pinned)
        .map_err(|source| io_error("reinspect pinned transaction entry", path, source))?;
    if !same_snapshot(&before, &pinned_after) || !same_snapshot(&bound, &pinned_after) {
        return Err(CommitError::InvalidJournal(
            "quarantined transaction entry binding changed before removal".to_owned(),
        ));
    }
    validate(quarantine)?;
    let final_bound = statat(parent, quarantine, AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|source| io_error("revalidate quarantined transaction entry", path, source))?;
    let final_pinned = fstat(&pinned)
        .map_err(|source| io_error("reinspect pinned transaction entry", path, source))?;
    if !same_snapshot(&before, &final_pinned) || !same_snapshot(&final_bound, &final_pinned) {
        return Err(CommitError::InvalidJournal(
            "quarantined transaction entry changed during final validation".to_owned(),
        ));
    }
    unlinkat(parent, quarantine, flags)
        .map_err(|source| io_error("remove quarantined transaction entry", path, source))?;
    fsync(parent).map_err(|source| io_error("sync removed transaction entry", path, source))
}

fn require_entry_absent(parent: &File, leaf: &OsStr, path: &Path) -> Result<(), CommitError> {
    if entry_stat(parent, leaf, path)?.is_some() {
        return Err(CommitError::InvalidJournal(
            "unexpected transaction staging entry remains".to_owned(),
        ));
    }
    Ok(())
}

fn require_entry_identity(
    parent: &File,
    leaf: &OsStr,
    expected: FileIdentityV1,
    path: &Path,
    role: &str,
) -> Result<(), CommitError> {
    let pinned = openat2(
        parent,
        leaf,
        OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
        ROOT_RESOLVE_FLAGS,
    )
    .map(File::from)
    .map_err(|source| io_error("pin identified transaction entry", path, source))?;
    let actual = require_pinned_entry(parent, leaf, &pinned, path, role)?;
    compare_created_identity(&actual, expected, role)
}

fn require_target_state(
    parent: &File,
    leaf: &OsStr,
    state: &StateTargetStateV1,
    canonical: &canonical::CanonicalObjects,
    uid: u32,
    path: &Path,
) -> Result<(), CommitError> {
    match state {
        StateTargetStateV1::File { file: None }
        | StateTargetStateV1::Directory { directory: None }
        | StateTargetStateV1::Symlink { symlink: None }
        | StateTargetStateV1::Tree { tree: None } => require_entry_absent(parent, leaf, path),
        StateTargetStateV1::File { file: Some(file) } => {
            require_state_file(parent, leaf, file, uid, path)
        }
        StateTargetStateV1::Directory {
            directory: Some(directory),
        } => require_directory_state(parent, leaf, directory.mode(), uid, path),
        StateTargetStateV1::Symlink {
            symlink: Some(symlink),
        } => require_symlink_target(
            parent,
            leaf,
            canonical
                .safe_symlink_target(symlink.object())
                .map_err(|error| invalid_canonical_object("symlink", symlink.object(), error))?,
            uid,
            path,
        ),
        StateTargetStateV1::Tree { tree: Some(tree) } => {
            require_tree_entry(parent, leaf, tree.tree(), canonical, uid, path)
        }
    }
}

fn require_state_file(
    parent: &File,
    leaf: &OsStr,
    expected: &malm_store::StateFileV1,
    uid: u32,
    path: &Path,
) -> Result<(), CommitError> {
    let file = openat2(
        parent,
        leaf,
        OFlags::RDONLY | OFlags::NONBLOCK | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
        ROOT_RESOLVE_FLAGS,
    )
    .map(File::from)
    .map_err(|source| io_error("open exact target file", path, source))?;
    let initial =
        fstat(&file).map_err(|source| io_error("inspect exact target file", path, source))?;
    let bound = statat(parent, leaf, AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|source| io_error("revalidate exact target file", path, source))?;
    if !same_snapshot(&initial, &bound)
        || FileType::from_raw_mode(initial.st_mode) != FileType::RegularFile
        || initial.st_uid != uid
        || initial.st_nlink != 1
        || initial.st_mode & 0o7777 != expected.mode()
        || u64::try_from(initial.st_size).unwrap_or(u64::MAX) != expected.byte_len()
    {
        return Err(CommitError::StaleTarget(format!(
            "target file {} differs from its managed state",
            path.display()
        )));
    }
    let (digest, hashed) = stable_file_digest(&file, path, "exact target file")?;
    let final_stat = require_pinned_entry(parent, leaf, &file, path, "exact target file")?;
    if !same_snapshot(&initial, &hashed)
        || !same_snapshot(&final_stat, &hashed)
        || !source_digest_matches(digest, expected.digest())
    {
        return Err(CommitError::StaleTarget(format!(
            "target file {} content differs from its managed state",
            path.display()
        )));
    }
    Ok(())
}

fn source_digest_matches(actual: SourceDigestV1, expected: &Digest) -> bool {
    let encoded = &expected.as_str().as_bytes()[7..];
    encoded.chunks_exact(2).enumerate().all(|(index, pair)| {
        let high = decode_lower_hex(pair[0]).expect("validated digest contains lowercase hex");
        let low = decode_lower_hex(pair[1]).expect("validated digest contains lowercase hex");
        actual.0[index] == (high << 4) | low
    })
}

fn require_directory_state(
    parent: &File,
    leaf: &OsStr,
    mode: u32,
    uid: u32,
    path: &Path,
) -> Result<(), CommitError> {
    let initial = statat(parent, leaf, AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|source| io_error("inspect exact target directory", path, source))?;
    if FileType::from_raw_mode(initial.st_mode) != FileType::Directory
        || initial.st_uid != uid
        || initial.st_mode & 0o7777 != mode
    {
        return Err(CommitError::StaleTarget(format!(
            "target directory {} differs from its managed state",
            path.display()
        )));
    }
    let directory = openat2(
        parent,
        leaf,
        DIRECTORY_FLAGS | OFlags::NOFOLLOW,
        Mode::empty(),
        ROOT_RESOLVE_FLAGS,
    )
    .map(File::from)
    .map_err(|source| io_error("open exact target directory", path, source))?;
    let opened = fstat(&directory)
        .map_err(|source| io_error("inspect opened exact target directory", path, source))?;
    let final_stat =
        require_pinned_entry(parent, leaf, &directory, path, "exact target directory")?;
    if !same_snapshot(&initial, &opened) || !same_snapshot(&opened, &final_stat) {
        return Err(CommitError::StaleTarget(
            "target directory changed while opening".to_owned(),
        ));
    }
    Ok(())
}

fn require_symlink_target(
    parent: &File,
    leaf: &OsStr,
    expected: &str,
    uid: u32,
    path: &Path,
) -> Result<(), CommitError> {
    pin_symlink_target(parent, leaf, expected, uid, path).map(drop)
}

fn pin_symlink_target(
    parent: &File,
    leaf: &OsStr,
    expected: &str,
    uid: u32,
    path: &Path,
) -> Result<PinnedVerifiedEntry, CommitError> {
    let symlink = openat2(
        parent,
        leaf,
        OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
        ROOT_RESOLVE_FLAGS,
    )
    .map(File::from)
    .map_err(|source| io_error("pin exact target symlink", path, source))?;
    let initial =
        fstat(&symlink).map_err(|source| io_error("inspect exact target symlink", path, source))?;
    if FileType::from_raw_mode(initial.st_mode) != FileType::Symlink
        || initial.st_uid != uid
        || initial.st_nlink != 1
    {
        return Err(CommitError::StaleTarget(format!(
            "target symlink {} differs from its managed state",
            path.display()
        )));
    }
    let target = readlinkat(&symlink, "", Vec::new())
        .map_err(|source| io_error("read exact target symlink", path, source))?;
    let final_stat = require_pinned_entry(parent, leaf, &symlink, path, "exact target symlink")?;
    if !same_snapshot(&initial, &final_stat) || target.to_bytes() != expected.as_bytes() {
        return Err(CommitError::StaleTarget(format!(
            "target symlink {} content differs from its managed state",
            path.display()
        )));
    }
    Ok(PinnedVerifiedEntry {
        file: symlink,
        snapshot: final_stat,
    })
}

/// Records each reachable tree member's identity and canonical digest. This is
/// best-effort; a member that cannot be inspected is omitted and will be fully
/// verified later.
fn record_tree_member_identities(
    directory: &File,
    digest: &Digest,
    canonical: &canonical::CanonicalObjects,
    key_prefix: &str,
    files: &mut BTreeMap<String, ObservedFileV1>,
) {
    let Some(tree) = canonical.trees.get(digest) else {
        return;
    };
    for entry in &tree.entries {
        let leaf = OsStr::from_bytes(entry.name.as_bytes());
        let key = format!("{key_prefix}/{}", entry.name);
        match &entry.kind {
            canonical::TreeEntryKind::File { digest, .. }
            | canonical::TreeEntryKind::Symlink { digest } => {
                let Ok(stat) = statat(directory, leaf, AtFlags::SYMLINK_NOFOLLOW) else {
                    continue;
                };
                files.insert(
                    key,
                    ObservedFileV1 {
                        identity: file_identity(&stat),
                        digest: (*digest).clone(),
                    },
                );
            }
            canonical::TreeEntryKind::Directory { digest } => {
                let Ok(child) = openat2(
                    directory,
                    leaf,
                    DIRECTORY_FLAGS | OFlags::NOFOLLOW,
                    Mode::empty(),
                    ROOT_RESOLVE_FLAGS,
                ) else {
                    continue;
                };
                record_tree_member_identities(&File::from(child), digest, canonical, &key, files);
            }
        }
    }
}

fn require_tree_entry(
    parent: &File,
    leaf: &OsStr,
    digest: &Digest,
    canonical: &canonical::CanonicalObjects,
    uid: u32,
    path: &Path,
) -> Result<(), CommitError> {
    require_tree_entry_observed(parent, leaf, digest, canonical, uid, path, None)
}

fn require_tree_entry_observed(
    parent: &File,
    leaf: &OsStr,
    digest: &Digest,
    canonical: &canonical::CanonicalObjects,
    uid: u32,
    path: &Path,
    observed: Option<ObservedScope<'_>>,
) -> Result<(), CommitError> {
    let initial = statat(parent, leaf, AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|source| io_error("inspect canonical tree root", path, source))?;
    let directory = openat2(
        parent,
        leaf,
        DIRECTORY_FLAGS | OFlags::NOFOLLOW,
        Mode::empty(),
        ROOT_RESOLVE_FLAGS,
    )
    .map(File::from)
    .map_err(|source| io_error("open canonical tree root", path, source))?;
    let opened = fstat(&directory)
        .map_err(|source| io_error("inspect opened canonical tree root", path, source))?;
    if !same_snapshot(&initial, &opened) {
        return Err(CommitError::StaleTarget(
            "canonical tree root changed while opening".to_owned(),
        ));
    }
    require_tree_directory_observed(&directory, digest, canonical, uid, path, observed)?;
    let final_opened = require_pinned_entry(parent, leaf, &directory, path, "canonical tree root")?;
    if !same_snapshot(&opened, &final_opened) {
        return Err(CommitError::StaleTarget(
            "canonical tree root changed during verification".to_owned(),
        ));
    }
    Ok(())
}

fn require_tree_directory(
    directory: &File,
    digest: &Digest,
    canonical: &canonical::CanonicalObjects,
    uid: u32,
    path: &Path,
) -> Result<(), CommitError> {
    require_tree_directory_observed(directory, digest, canonical, uid, path, None)
}

/// Verifies a canonical tree, optionally using identities recorded for this
/// exact tree entry. An exact live identity match proves unchanged content
/// because every userspace mutation changes `ctime`, which userspace cannot
/// set. Missing or mismatched observations fall back to full content checks.
fn require_tree_directory_observed(
    directory: &File,
    digest: &Digest,
    canonical: &canonical::CanonicalObjects,
    uid: u32,
    path: &Path,
    observed: Option<ObservedScope<'_>>,
) -> Result<(), CommitError> {
    let tree = canonical.trees.get(digest).ok_or_else(|| {
        CommitError::InvalidStore(format!("canonical tree object {digest} is missing"))
    })?;
    let initial = fstat(directory)
        .map_err(|source| io_error("inspect canonical tree directory", path, source))?;
    if FileType::from_raw_mode(initial.st_mode) != FileType::Directory
        || initial.st_uid != uid
        || initial.st_mode & 0o7777 != tree.root_mode
    {
        return Err(CommitError::StaleTarget(
            "canonical tree directory has unexpected metadata".to_owned(),
        ));
    }
    let actual = directory_entry_names(directory, path)?;
    let expected = tree
        .entries
        .iter()
        .map(|entry| entry.name.as_bytes().to_vec())
        .collect::<BTreeSet<_>>();
    if actual != expected {
        return Err(CommitError::StaleTarget(
            "canonical tree directory entries differ from managed state".to_owned(),
        ));
    }
    for entry in &tree.entries {
        let leaf = OsStr::from_bytes(entry.name.as_bytes());
        let child_path = path.join(&entry.name);
        match &entry.kind {
            canonical::TreeEntryKind::File { digest, .. } => {
                if let Some(scope) = observed
                    && let Ok(current) = statat(directory, leaf, AtFlags::SYMLINK_NOFOLLOW)
                    && FileType::from_raw_mode(current.st_mode) == FileType::RegularFile
                    && current.st_uid == uid
                    && scope
                        .files
                        .get(&format!("{}/{}", scope.key, entry.name))
                        .is_some_and(|cached| {
                            &cached.digest == digest && file_identity(&current) == cached.identity
                        })
                {
                    continue;
                }
                let bytes = canonical.files.get(digest).ok_or_else(|| {
                    CommitError::InvalidStore(format!("canonical file object {digest} is missing"))
                })?;
                require_leaf_bytes(directory, leaf, bytes, entry.mode, uid, &child_path)?;
            }
            canonical::TreeEntryKind::Symlink { digest } => {
                if let Some(scope) = observed
                    && let Ok(current) = statat(directory, leaf, AtFlags::SYMLINK_NOFOLLOW)
                    && FileType::from_raw_mode(current.st_mode) == FileType::Symlink
                    && scope
                        .files
                        .get(&format!("{}/{}", scope.key, entry.name))
                        .is_some_and(|cached| {
                            &cached.digest == digest && file_identity(&current) == cached.identity
                        })
                {
                    continue;
                }
                require_symlink_target(
                    directory,
                    leaf,
                    canonical
                        .safe_symlink_target(digest)
                        .map_err(|error| invalid_canonical_object("symlink", digest, error))?,
                    uid,
                    &child_path,
                )?;
            }
            canonical::TreeEntryKind::Directory { digest } => {
                let initial =
                    statat(directory, leaf, AtFlags::SYMLINK_NOFOLLOW).map_err(|source| {
                        io_error("inspect canonical child tree", &child_path, source)
                    })?;
                let child = openat2(
                    directory,
                    leaf,
                    DIRECTORY_FLAGS | OFlags::NOFOLLOW,
                    Mode::empty(),
                    ROOT_RESOLVE_FLAGS,
                )
                .map(File::from)
                .map_err(|source| io_error("open canonical child tree", &child_path, source))?;
                let opened = fstat(&child).map_err(|source| {
                    io_error("inspect opened canonical child tree", &child_path, source)
                })?;
                if !same_snapshot(&initial, &opened) {
                    return Err(CommitError::StaleTarget(
                        "canonical child tree changed while opening".to_owned(),
                    ));
                }
                let child_key = observed.map(|scope| format!("{}/{}", scope.key, entry.name));
                require_tree_directory_observed(
                    &child,
                    digest,
                    canonical,
                    uid,
                    &child_path,
                    observed
                        .zip(child_key.as_deref())
                        .map(|(scope, key)| ObservedScope {
                            files: scope.files,
                            key,
                        }),
                )?;
                let final_stat = require_pinned_entry(
                    directory,
                    leaf,
                    &child,
                    &child_path,
                    "canonical child tree",
                )?;
                if !same_snapshot(&opened, &final_stat) {
                    return Err(CommitError::StaleTarget(
                        "canonical child tree changed during verification".to_owned(),
                    ));
                }
            }
        }
    }
    let final_stat = fstat(directory)
        .map_err(|source| io_error("reinspect canonical tree directory", path, source))?;
    if !same_snapshot(&initial, &final_stat) {
        return Err(CommitError::StaleTarget(
            "canonical tree directory changed during verification".to_owned(),
        ));
    }
    Ok(())
}

fn directory_entry_names(directory: &File, path: &Path) -> Result<BTreeSet<Vec<u8>>, CommitError> {
    let mut names = BTreeSet::new();
    let mut entries = Dir::read_from(directory)
        .map_err(|source| io_error("enumerate canonical tree directory", path, source))?;
    while let Some(entry) = entries.read() {
        let entry =
            entry.map_err(|source| io_error("enumerate canonical tree directory", path, source))?;
        if !matches!(entry.file_name().to_bytes(), b"." | b"..") {
            names.insert(entry.file_name().to_bytes().to_vec());
        }
    }
    Ok(names)
}

fn materialize_tree_directory(
    directory: &File,
    digest: &Digest,
    canonical: &canonical::CanonicalObjects,
    uid: u32,
    path: &Path,
) -> Result<(), CommitError> {
    let tree = canonical.trees.get(digest).ok_or_else(|| {
        CommitError::InvalidStore(format!("canonical tree object {digest} is missing"))
    })?;
    for entry in &tree.entries {
        let leaf = OsStr::from_bytes(entry.name.as_bytes());
        let child_path = path.join(&entry.name);
        match &entry.kind {
            canonical::TreeEntryKind::File { digest, .. } => {
                let bytes = canonical.files.get(digest).ok_or_else(|| {
                    CommitError::InvalidStore(format!("canonical file object {digest} is missing"))
                })?;
                let mut file = openat2(
                    directory,
                    leaf,
                    OFlags::CREATE
                        | OFlags::EXCL
                        | OFlags::WRONLY
                        | OFlags::NOFOLLOW
                        | OFlags::CLOEXEC,
                    Mode::from_raw_mode(entry.mode),
                    ROOT_RESOLVE_FLAGS,
                )
                .map(File::from)
                .map_err(|source| io_error("create canonical tree file", &child_path, source))?;
                let result = (|| {
                    file.write_all(bytes).map_err(|source| CommitError::Io {
                        operation: "write canonical tree file",
                        path: child_path.clone(),
                        source,
                    })?;
                    fchmod(&file, Mode::from_raw_mode(entry.mode)).map_err(|source| {
                        io_error("set canonical tree file mode", &child_path, source)
                    })?;
                    file.flush().map_err(|source| CommitError::Io {
                        operation: "flush canonical tree file",
                        path: child_path.clone(),
                        source,
                    })?;
                    fsync(&file)
                        .map_err(|source| io_error("sync canonical tree file", &child_path, source))
                })();
                if let Err(error) = result {
                    return match unlink_pinned_entry(
                        directory,
                        leaf,
                        &file,
                        AtFlags::empty(),
                        &child_path,
                        "failed canonical tree file",
                    ) {
                        Ok(()) => Err(error),
                        Err(cleanup) => Err(CommitError::RollbackFailed(format!(
                            "{error}; failed to remove canonical tree file: {cleanup}"
                        ))),
                    };
                }
            }
            canonical::TreeEntryKind::Symlink { digest } => {
                let target = canonical
                    .safe_symlink_target(digest)
                    .map_err(|error| invalid_canonical_object("symlink", digest, error))?;
                symlinkat(target, directory, leaf).map_err(|source| {
                    io_error("create canonical tree symlink", &child_path, source)
                })?;
                let created = openat2(
                    directory,
                    leaf,
                    OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                    Mode::empty(),
                    ROOT_RESOLVE_FLAGS,
                )
                .map(File::from)
                .map_err(|source| io_error("pin canonical tree symlink", &child_path, source))?;
                if let Err(error) =
                    require_symlink_target(directory, leaf, target, uid, &child_path)
                {
                    return match unlink_pinned_entry(
                        directory,
                        leaf,
                        &created,
                        AtFlags::empty(),
                        &child_path,
                        "failed canonical tree symlink",
                    ) {
                        Ok(()) => Err(error),
                        Err(cleanup) => Err(CommitError::RollbackFailed(format!(
                            "{error}; failed to remove canonical tree symlink: {cleanup}"
                        ))),
                    };
                }
            }
            canonical::TreeEntryKind::Directory { digest } => {
                mkdirat(directory, leaf, Mode::from_raw_mode(0o700)).map_err(|source| {
                    io_error("create canonical child tree", &child_path, source)
                })?;
                let child = openat2(
                    directory,
                    leaf,
                    DIRECTORY_FLAGS | OFlags::NOFOLLOW,
                    Mode::empty(),
                    ROOT_RESOLVE_FLAGS,
                )
                .map(File::from)
                .map_err(|source| io_error("open canonical child tree", &child_path, source))?;
                if let Err(error) =
                    materialize_tree_directory(&child, digest, canonical, uid, &child_path)
                {
                    let cleanup =
                        remove_partial_tree_directory(&child, digest, canonical, uid, &child_path)
                            .and_then(|()| {
                                unlink_pinned_entry(
                                    directory,
                                    leaf,
                                    &child,
                                    AtFlags::REMOVEDIR,
                                    &child_path,
                                    "failed canonical child tree",
                                )
                            });
                    return match cleanup {
                        Ok(()) => Err(error),
                        Err(cleanup) => Err(CommitError::RollbackFailed(format!(
                            "{error}; failed to remove canonical child tree: {cleanup}"
                        ))),
                    };
                }
            }
        }
    }
    fchmod(directory, Mode::from_raw_mode(tree.root_mode))
        .map_err(|source| io_error("set canonical tree directory mode", path, source))?;
    fsync(directory).map_err(|source| io_error("sync canonical tree directory", path, source))
}

fn remove_partial_tree_directory(
    directory: &File,
    digest: &Digest,
    canonical: &canonical::CanonicalObjects,
    uid: u32,
    path: &Path,
) -> Result<(), CommitError> {
    let tree = canonical.trees.get(digest).ok_or_else(|| {
        CommitError::InvalidStore(format!("canonical tree object {digest} is missing"))
    })?;
    let root = fstat(directory)
        .map_err(|source| io_error("inspect tree cleanup directory", path, source))?;
    let root_mode = root.st_mode & 0o7777;
    if FileType::from_raw_mode(root.st_mode) != FileType::Directory
        || root.st_uid != uid
        || (root_mode != 0o700 && root_mode != tree.root_mode)
    {
        return Err(CommitError::InvalidJournal(
            "tree cleanup root has unexpected metadata".to_owned(),
        ));
    }
    let actual = directory_entry_names(directory, path)?;
    let by_name = tree
        .entries
        .iter()
        .map(|entry| (entry.name.as_bytes().to_vec(), entry))
        .collect::<BTreeMap<_, _>>();
    if actual.iter().any(|name| !by_name.contains_key(name)) {
        return Err(CommitError::InvalidJournal(
            "tree cleanup found an unexpected entry".to_owned(),
        ));
    }
    for name in actual {
        let entry = by_name[&name];
        let leaf = OsStr::from_bytes(&name);
        let child_path = path.join(&entry.name);
        match &entry.kind {
            canonical::TreeEntryKind::File { digest, .. } => {
                let bytes = canonical.files.get(digest).ok_or_else(|| {
                    CommitError::InvalidStore(format!("canonical file object {digest} is missing"))
                })?;
                let pinned = pin_leaf_bytes(directory, leaf, bytes, entry.mode, uid, &child_path)?;
                commit_failpoint!("v1.commit.tree_cleanup.before_child_unlink");
                require_verified_entry_rebound(
                    directory,
                    leaf,
                    &pinned,
                    &child_path,
                    "canonical tree cleanup file",
                )?;
                unlinkat(directory, leaf, AtFlags::empty()).map_err(|source| {
                    io_error("remove canonical tree file", &child_path, source)
                })?;
            }
            canonical::TreeEntryKind::Symlink { digest } => {
                let pinned = pin_symlink_target(
                    directory,
                    leaf,
                    canonical
                        .safe_symlink_target(digest)
                        .map_err(|error| invalid_canonical_object("symlink", digest, error))?,
                    uid,
                    &child_path,
                )?;
                commit_failpoint!("v1.commit.tree_cleanup.before_child_unlink");
                require_verified_entry_rebound(
                    directory,
                    leaf,
                    &pinned,
                    &child_path,
                    "canonical tree cleanup symlink",
                )?;
                unlinkat(directory, leaf, AtFlags::empty()).map_err(|source| {
                    io_error("remove canonical tree symlink", &child_path, source)
                })?;
            }
            canonical::TreeEntryKind::Directory { digest } => {
                let initial =
                    statat(directory, leaf, AtFlags::SYMLINK_NOFOLLOW).map_err(|source| {
                        io_error("inspect canonical tree cleanup child", &child_path, source)
                    })?;
                let child = openat2(
                    directory,
                    leaf,
                    DIRECTORY_FLAGS | OFlags::NOFOLLOW,
                    Mode::empty(),
                    ROOT_RESOLVE_FLAGS,
                )
                .map(File::from)
                .map_err(|source| {
                    io_error("open canonical tree cleanup child", &child_path, source)
                })?;
                let opened = fstat(&child).map_err(|source| {
                    io_error(
                        "inspect opened canonical tree cleanup child",
                        &child_path,
                        source,
                    )
                })?;
                if !same_snapshot(&initial, &opened) {
                    return Err(CommitError::InvalidJournal(
                        "canonical tree cleanup child changed while opening".to_owned(),
                    ));
                }
                remove_partial_tree_directory(&child, digest, canonical, uid, &child_path)?;
                let cleaned = fstat(&child).map_err(|source| {
                    io_error(
                        "reinspect canonical tree cleanup child",
                        &child_path,
                        source,
                    )
                })?;
                commit_failpoint!("v1.commit.tree_cleanup.before_child_unlink");
                let final_stat = require_pinned_entry(
                    directory,
                    leaf,
                    &child,
                    &child_path,
                    "canonical tree cleanup child",
                )?;
                if !same_snapshot(&cleaned, &final_stat) {
                    return Err(CommitError::InvalidJournal(
                        "canonical tree cleanup child changed before removal".to_owned(),
                    ));
                }
                unlinkat(directory, leaf, AtFlags::REMOVEDIR).map_err(|source| {
                    io_error("remove canonical child tree", &child_path, source)
                })?;
            }
        }
    }
    fsync(directory).map_err(|source| io_error("sync cleaned canonical tree", path, source))
}

fn quarantine_and_remove_tree_entry(
    entry: QuarantineEntry<'_>,
    digest: &Digest,
    canonical: &canonical::CanonicalObjects,
    uid: u32,
) -> Result<(), CommitError> {
    let QuarantineEntry {
        parent,
        source,
        quarantine,
        path,
        identity,
        created,
    } = entry;
    if let Some(source) = source {
        require_entry_absent(parent, quarantine, path)?;
        renameat_with(parent, source, parent, quarantine, RenameFlags::NOREPLACE)
            .map_err(|error| io_error("quarantine canonical tree", path, error))?;
        fsync(parent).map_err(|source| io_error("sync tree quarantine", path, source))?;
    }
    let stat = entry_stat(parent, quarantine, path)?.ok_or_else(|| {
        CommitError::InvalidJournal("quarantined canonical tree is missing".to_owned())
    })?;
    if source.is_some() {
        if created {
            compare_created_identity(&stat, identity, "quarantined created tree")?;
        } else {
            compare_relocated_identity(&stat, identity, "quarantined tree backup")?;
        }
        require_tree_entry(parent, quarantine, digest, canonical, uid, path)?;
    } else {
        compare_object_identity(&stat, identity, "partially removed canonical tree")?;
    }
    let directory = openat2(
        parent,
        quarantine,
        DIRECTORY_FLAGS | OFlags::NOFOLLOW,
        Mode::empty(),
        ROOT_RESOLVE_FLAGS,
    )
    .map(File::from)
    .map_err(|source| io_error("open quarantined canonical tree", path, source))?;
    let opened = fstat(&directory)
        .map_err(|source| io_error("inspect quarantined canonical tree", path, source))?;
    if !same_object(&stat, &opened) {
        return Err(CommitError::InvalidJournal(
            "canonical tree quarantine binding changed".to_owned(),
        ));
    }
    remove_partial_tree_directory(&directory, digest, canonical, uid, path)?;
    commit_failpoint!("v1.commit.tree_cleanup.before_root_unlink");
    let rebound = statat(parent, quarantine, AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|source| io_error("revalidate cleaned canonical tree", path, source))?;
    let final_opened = fstat(&directory)
        .map_err(|source| io_error("reinspect cleaned canonical tree", path, source))?;
    if !same_object(&rebound, &final_opened) || !same_object(&stat, &final_opened) {
        return Err(CommitError::InvalidJournal(
            "canonical tree quarantine changed during cleanup".to_owned(),
        ));
    }
    unlinkat(parent, quarantine, AtFlags::REMOVEDIR)
        .map_err(|source| io_error("remove canonical tree root", path, source))?;
    fsync(parent).map_err(|source| io_error("sync removed canonical tree", path, source))
}

fn quarantine_and_remove_prior_entry(
    entry: QuarantineEntry<'_>,
    state: &StateTargetStateV1,
    canonical: &canonical::CanonicalObjects,
    uid: u32,
) -> Result<(), CommitError> {
    if let StateTargetStateV1::Tree { tree: Some(tree) } = state {
        return quarantine_and_remove_tree_entry(entry, tree.tree(), canonical, uid);
    }
    let QuarantineEntry { parent, path, .. } = entry;
    quarantine_and_unlink_entry(entry, removal_flags(entry.identity), |leaf| {
        require_prior_removal_state(parent, leaf, state, canonical, uid, path)
    })
}

fn require_prior_removal_state(
    parent: &File,
    leaf: &OsStr,
    state: &StateTargetStateV1,
    canonical: &canonical::CanonicalObjects,
    uid: u32,
    path: &Path,
) -> Result<(), CommitError> {
    require_target_state(parent, leaf, state, canonical, uid, path)?;
    if matches!(state, StateTargetStateV1::Directory { directory: Some(_) }) {
        require_empty_directory_entry(parent, leaf, path)?;
    }
    Ok(())
}

struct PinnedVerifiedEntry {
    file: File,
    snapshot: Stat,
}

fn require_verified_entry_rebound(
    parent: &File,
    leaf: &OsStr,
    pinned: &PinnedVerifiedEntry,
    path: &Path,
    role: &str,
) -> Result<(), CommitError> {
    let final_stat = require_pinned_entry(parent, leaf, &pinned.file, path, role)?;
    if !same_snapshot(&pinned.snapshot, &final_stat) {
        return Err(CommitError::InvalidJournal(format!(
            "{role} changed after validation"
        )));
    }
    Ok(())
}

fn require_leaf_bytes(
    parent: &File,
    leaf: &OsStr,
    expected: &[u8],
    expected_mode: u32,
    expected_uid: u32,
    path: &Path,
) -> Result<(), CommitError> {
    pin_leaf_bytes(parent, leaf, expected, expected_mode, expected_uid, path).map(drop)
}

fn pin_leaf_bytes(
    parent: &File,
    leaf: &OsStr,
    expected: &[u8],
    expected_mode: u32,
    expected_uid: u32,
    path: &Path,
) -> Result<PinnedVerifiedEntry, CommitError> {
    let mut file = openat2(
        parent,
        leaf,
        OFlags::RDONLY | OFlags::NONBLOCK | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
        ROOT_RESOLVE_FLAGS,
    )
    .map(File::from)
    .map_err(|source| io_error("open transaction target", path, source))?;
    let stat =
        fstat(&file).map_err(|source| io_error("inspect transaction target", path, source))?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
        || stat.st_uid != expected_uid
        || stat.st_mode & 0o7777 != expected_mode
        || stat.st_nlink != 1
        || u64::try_from(stat.st_size).unwrap_or(u64::MAX)
            != malm_types::usize_to_u64(expected.len())
    {
        return Err(CommitError::InvalidJournal(
            "transaction target is not the prepared regular file".to_owned(),
        ));
    }
    let mut actual = Vec::with_capacity(expected.len().saturating_add(1));
    (&mut file)
        .take(
            u64::try_from(expected.len())
                .unwrap_or(u64::MAX)
                .saturating_add(1),
        )
        .read_to_end(&mut actual)
        .map_err(|source| CommitError::Io {
            operation: "read transaction target",
            path: path.to_path_buf(),
            source,
        })?;
    let after =
        fstat(&file).map_err(|source| io_error("reinspect transaction target", path, source))?;
    if !same_snapshot(&stat, &after) {
        return Err(CommitError::InvalidJournal(
            "transaction target changed while reading".to_owned(),
        ));
    }
    if actual != expected {
        return Err(CommitError::InvalidJournal(
            "transaction target bytes differ from the prepared artifact".to_owned(),
        ));
    }
    let final_stat = require_pinned_entry(parent, leaf, &file, path, "transaction target")?;
    if !same_snapshot(&after, &final_stat) {
        return Err(CommitError::InvalidJournal(
            "transaction target binding changed after verification".to_owned(),
        ));
    }
    Ok(PinnedVerifiedEntry {
        file,
        snapshot: final_stat,
    })
}

fn require_managed_directory(
    parent: &File,
    leaf: &OsStr,
    expected_mode: Option<u32>,
    expected_uid: u32,
    path: &Path,
) -> Result<(), CommitError> {
    let directory = openat2(
        parent,
        leaf,
        DIRECTORY_FLAGS | OFlags::NOFOLLOW,
        Mode::empty(),
        ROOT_RESOLVE_FLAGS,
    )
    .map(File::from)
    .map_err(|source| io_error("open transaction directory", path, source))?;
    let stat = fstat(&directory)
        .map_err(|source| io_error("inspect transaction directory", path, source))?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::Directory
        || stat.st_uid != expected_uid
        || expected_mode.is_some_and(|mode| stat.st_mode & 0o7777 != mode)
    {
        return Err(CommitError::InvalidJournal(
            "transaction directory has unexpected metadata".to_owned(),
        ));
    }
    // Do not require this directory to be empty. A created ancestor may now
    // hold children placed by this plan, and each child has its own verification
    // step. During rollback, REMOVEDIR still refuses to delete a nonempty
    // directory.
    let final_stat = require_pinned_entry(
        parent,
        leaf,
        &directory,
        path,
        "managed transaction directory",
    )?;
    if !same_snapshot(&stat, &final_stat) {
        return Err(CommitError::InvalidJournal(
            "transaction directory binding changed during verification".to_owned(),
        ));
    }
    Ok(())
}

fn require_empty_directory_entry(
    parent: &File,
    leaf: &OsStr,
    path: &Path,
) -> Result<(), CommitError> {
    let directory = openat2(
        parent,
        leaf,
        DIRECTORY_FLAGS | OFlags::NOFOLLOW,
        Mode::empty(),
        ROOT_RESOLVE_FLAGS,
    )
    .map(File::from)
    .map_err(|source| io_error("open removed transaction directory", path, source))?;
    let initial = fstat(&directory)
        .map_err(|source| io_error("inspect removed transaction directory", path, source))?;
    let mut entries = Dir::read_from(&directory)
        .map_err(|source| io_error("enumerate removed transaction directory", path, source))?;
    while let Some(entry) = entries.read() {
        let entry = entry
            .map_err(|source| io_error("enumerate removed transaction directory", path, source))?;
        if !matches!(entry.file_name().to_bytes(), b"." | b"..") {
            return Err(CommitError::InvalidJournal(
                "removed transaction directory is not empty".to_owned(),
            ));
        }
    }
    let final_stat = require_pinned_entry(
        parent,
        leaf,
        &directory,
        path,
        "removed transaction directory",
    )?;
    if !same_snapshot(&initial, &final_stat) {
        return Err(CommitError::InvalidJournal(
            "removed transaction directory binding changed during verification".to_owned(),
        ));
    }
    Ok(())
}

const fn is_directory_identity(identity: FileIdentityV1) -> bool {
    identity.mode & 0o170_000 == 0o040_000
}

const fn removal_flags(identity: FileIdentityV1) -> AtFlags {
    if is_directory_identity(identity) {
        AtFlags::REMOVEDIR
    } else {
        AtFlags::empty()
    }
}

fn file_identity(stat: &Stat) -> FileIdentityV1 {
    FileIdentityV1 {
        device: stat.st_dev,
        inode: stat.st_ino,
        user_id: stat.st_uid,
        group_id: stat.st_gid,
        mode: stat.st_mode,
        links: stat.st_nlink,
        size: u64::try_from(stat.st_size).unwrap_or(u64::MAX),
        modified_seconds: stat.st_mtime,
        modified_nanoseconds: u32::try_from(stat.st_mtime_nsec).unwrap_or(u32::MAX),
        changed_seconds: stat.st_ctime,
        changed_nanoseconds: u32::try_from(stat.st_ctime_nsec).unwrap_or(u32::MAX),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use malm_store::{PreparedRecordPartsV1, TargetObservationV1};

    fn identity(inode: u64) -> FileIdentityV1 {
        FileIdentityV1 {
            device: 1,
            inode,
            user_id: 1_000,
            group_id: 1_000,
            mode: 0o100_600,
            links: 1,
            size: 7,
            modified_seconds: 10,
            modified_nanoseconds: 20,
            changed_seconds: 30,
            changed_nanoseconds: 40,
        }
    }

    fn journal(operation: JournalOperationV1) -> TransactionJournalV1 {
        TransactionJournalV1 {
            schema_version: 1,
            namespace: NamespaceName::new("test").unwrap(),
            plan_id: PreparedId::from_digest(&Digest::sha256(b"plan")),
            previous_catalog: Digest::sha256(b"previous catalog"),
            next_catalog: Digest::sha256(b"next catalog"),
            previous_generation: None,
            next_generation: Some(Digest::sha256(b"generation")),
            operations: vec![operation],
        }
    }

    #[test]
    fn backup_journal_progression_is_monotonic() {
        let pending = journal(JournalOperationV1::default());
        let mut intent = pending.clone();
        intent.operations[0].backup = Some(JournalBackupV1::Intent {
            source_digest: None,
        });
        assert!(validate_journal_progression(&pending, &intent).is_ok());

        let mut identified = intent.clone();
        identified.operations[0].backup = Some(JournalBackupV1::Identified {
            identity: identity(1),
            source_digest: None,
        });
        assert!(validate_journal_progression(&intent, &identified).is_ok());
        assert!(validate_journal_progression(&identified, &identified).is_ok());

        assert!(validate_journal_progression(&pending, &identified).is_err());
        assert!(validate_journal_progression(&intent, &pending).is_err());
        assert!(validate_journal_progression(&identified, &intent).is_err());

        let mut changed = identified.clone();
        changed.operations[0].backup = Some(JournalBackupV1::Identified {
            identity: identity(2),
            source_digest: None,
        });
        assert!(validate_journal_progression(&identified, &changed).is_err());

        let mut late_creation = identified.clone();
        late_creation.operations[0].created_identity = Some(identity(3));
        assert!(validate_journal_progression(&identified, &late_creation).is_err());

        let mut combined = pending.clone();
        combined.operations[0].created_identity = Some(identity(4));
        combined.operations[0].backup = Some(JournalBackupV1::Intent {
            source_digest: None,
        });
        assert!(validate_journal_progression(&pending, &combined).is_err());

        let mut two_pending = pending.clone();
        two_pending.operations.push(JournalOperationV1::default());
        let mut two_changes = two_pending.clone();
        two_changes.operations[0].backup = Some(JournalBackupV1::Intent {
            source_digest: None,
        });
        two_changes.operations[1].backup = Some(JournalBackupV1::Intent {
            source_digest: None,
        });
        assert!(validate_journal_progression(&two_pending, &two_changes).is_ok());

        let mut two_mixed = two_changes.clone();
        two_mixed.operations[0].backup = None;
        assert!(validate_journal_progression(&two_changes, &two_mixed).is_err());
    }

    #[test]
    fn journal_wire_rejects_old_and_incomplete_backup_shapes() {
        let fixture = include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../schemas/store/v1/fixtures/valid/transaction-journal.json"
        ));
        assert!(decode_journal_bytes(fixture).is_ok());
        assert!(
            decode_journal_bytes(include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../schemas/store/v1/fixtures/golden/transaction-journal.json"
            )))
            .is_ok()
        );
        for rejected in [
            include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../schemas/store/v1/fixtures/malformed/transaction-journal-missing-field.json"
            )) as &[u8],
            include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../schemas/store/v1/fixtures/malformed/transaction-journal-unknown-field.json"
            )),
            include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../schemas/store/v1/fixtures/malformed/transaction-journal-noncanonical.json"
            )),
            include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../schemas/store/v1/fixtures/malformed/transaction-journal-legacy-backup.json"
            )),
            include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../schemas/store/v1/fixtures/unsupported/transaction-journal-version-2.json"
            )),
        ] {
            assert!(matches!(
                decode_journal_bytes(rejected),
                Err(CommitError::InvalidJournal(_))
            ));
        }

        let pending = journal(JournalOperationV1::default());
        assert_eq!(
            decode_journal_bytes(&canonical_journal(&pending)).unwrap(),
            pending
        );

        let mut old: serde_json::Value =
            serde_json::from_slice(&canonical_journal(&pending)).unwrap();
        let operation = old["operations"][0].as_object_mut().unwrap();
        operation.remove("backup");
        operation.insert("backup_identity".to_owned(), serde_json::Value::Null);
        let mut bytes = serde_json::to_vec(&old).unwrap();
        bytes.push(b'\n');
        assert!(matches!(
            decode_journal_bytes(&bytes),
            Err(CommitError::InvalidJournal(_))
        ));

        let mut missing: serde_json::Value =
            serde_json::from_slice(&canonical_journal(&pending)).unwrap();
        missing["operations"][0]
            .as_object_mut()
            .unwrap()
            .remove("backup");
        let mut bytes = serde_json::to_vec(&missing).unwrap();
        bytes.push(b'\n');
        assert!(matches!(
            decode_journal_bytes(&bytes),
            Err(CommitError::InvalidJournal(_))
        ));
    }

    #[test]
    fn maximum_identified_journal_fits_the_encoded_resource_bound() {
        let maximum = FileIdentityV1 {
            device: u64::MAX,
            inode: u64::MAX,
            user_id: u32::MAX,
            group_id: u32::MAX,
            mode: u32::MAX,
            links: u64::MAX,
            size: u64::MAX,
            modified_seconds: i64::MIN,
            modified_nanoseconds: u32::MAX,
            changed_seconds: i64::MIN,
            changed_nanoseconds: u32::MAX,
        };
        let operation = JournalOperationV1 {
            created_identity: Some(maximum),
            backup: Some(JournalBackupV1::Identified {
                identity: maximum,
                source_digest: Some(SourceDigestV1([u8::MAX; 32])),
            }),
        };
        let mut maximum_journal = journal(operation);
        maximum_journal.operations = vec![operation; malm_store::MAX_PREPARED_OPERATIONS];
        let actual = canonical_journal(&maximum_journal).len();
        assert!(
            actual <= MAX_TRANSACTION_JOURNAL_BYTES,
            "maximum journal uses {actual} bytes; limit is {MAX_TRANSACTION_JOURNAL_BYTES}"
        );
    }

    #[test]
    fn journal_operation_count_is_bounded_during_deserialization() {
        let mut bounded = journal(JournalOperationV1::default());
        bounded.operations =
            vec![JournalOperationV1::default(); malm_store::MAX_PREPARED_OPERATIONS];
        assert!(decode_journal_bytes(&canonical_journal(&bounded)).is_ok());

        bounded.operations.push(JournalOperationV1::default());
        assert!(matches!(
            decode_journal_bytes(&canonical_journal(&bounded)),
            Err(CommitError::InvalidJournal(reason))
                if reason.contains("transaction journal exceeds")
        ));
    }

    #[test]
    fn selected_generation_bytes_have_an_aggregate_bound() {
        let mut total = MAX_SELECTED_GENERATION_BYTES - 1;
        assert!(charge_selected_generation_bytes(&mut total, 1).is_ok());
        assert!(matches!(
            charge_selected_generation_bytes(&mut total, 1),
            Err(CommitError::InvalidStore(reason))
                if reason.contains("selected generation records exceed")
        ));
    }

    #[test]
    fn lineage_validation_has_an_aggregate_decoded_byte_bound() {
        let mut total = MAX_LINEAGE_VALIDATION_BYTES - 1;
        assert!(charge_lineage_validation_bytes(&mut total, 1).is_ok());
        assert!(matches!(
            charge_lineage_validation_bytes(&mut total, 1),
            Err(CommitError::InvalidStore(reason))
                if reason.contains("selected lineage validation exceeds")
        ));
    }

    #[test]
    fn target_authority_admission_is_directional() {
        let home = Path::new("/tmp/malm-home-authority");
        let state = home.join(".local/state/malm");
        let authority = DeploymentName::new("home").unwrap();

        assert!(overlaps(home, &state));
        for target in [&state, &state.join("nested")] {
            assert!(matches!(
                CommitConfig::new(&state, 1_000, None)
                    .unwrap()
                    .with_target_authority(authority.clone(), target),
                Err(CommitConfigError::TargetInsideState(rejected)) if rejected == authority
            ));
        }

        let config = CommitConfig::new(&state, 1_000, None)
            .unwrap()
            .with_target_authority(authority.clone(), home)
            .unwrap();
        assert_eq!(
            config
                .target_authorities
                .get(&authority)
                .map(PathBuf::as_path),
            Some(home)
        );
    }

    fn descriptor_operation(
        relative_path: impl Into<String>,
        anchor: FileIdentityV1,
        ancestors: Vec<FileIdentityV1>,
        parent: FileIdentityV1,
    ) -> PreparedOperationV1 {
        PreparedOperationV1::AssertAbsent {
            observation: TargetObservationV1::new(
                DeploymentName::new("home").unwrap(),
                relative_path,
                anchor,
                ancestors,
                parent,
                LeafObservationV1::Absent,
            )
            .unwrap(),
        }
    }

    fn descriptor_plan(operations: Vec<PreparedOperationV1>) -> PreparedRecordV1 {
        PreparedRecordV1::try_from(PreparedRecordPartsV1 {
            namespace: NamespaceName::new("descriptor-test").unwrap(),
            expected_head: None,
            graph_digest: Digest::sha256(b"descriptor graph"),
            inputs: Vec::new(),
            artifacts: Vec::new(),
            transforms: Vec::new(),
            findings: Vec::new(),
            operations,
            desired_snapshot: malm_store::DesiredSnapshotV1::empty(),
        })
        .unwrap()
    }

    fn descriptor_config() -> CommitConfig {
        CommitConfig::new("/var/lib/malm-descriptor-test", 1_000, Some(1_024))
            .unwrap()
            .with_target_authority(
                DeploymentName::new("home").unwrap(),
                "/home/christian/target",
            )
            .unwrap()
    }

    #[test]
    fn target_descriptor_count_deduplicates_shared_prefixes() {
        let anchor = identity(1);
        let outputs = identity(2);
        let shared = identity(3);
        let single = descriptor_plan(vec![descriptor_operation(
            "outputs/shared/a",
            anchor,
            vec![outputs],
            shared,
        )]);
        let shared_parent = descriptor_plan(vec![
            descriptor_operation("outputs/shared/a", anchor, vec![outputs], shared),
            descriptor_operation("outputs/shared/b", anchor, vec![outputs], shared),
        ]);
        let distinct_parent = descriptor_plan(vec![
            descriptor_operation("outputs/shared/a", anchor, vec![outputs], shared),
            descriptor_operation("outputs/other/b", anchor, vec![outputs], identity(4)),
        ]);
        let config = descriptor_config();

        let single = target_descriptor_requirement(&config, &single)
            .unwrap()
            .directories;
        assert_eq!(
            target_descriptor_requirement(&config, &shared_parent)
                .unwrap()
                .directories,
            single
        );
        assert_eq!(
            target_descriptor_requirement(&config, &distinct_parent)
                .unwrap()
                .directories,
            single + 1
        );
    }

    #[test]
    fn smia_shaped_descriptor_count_is_114_before_reserve() {
        let anchor = identity(1);
        let outputs = identity(2);
        let operations = (0..135)
            .map(|index| {
                let group = index % 108;
                descriptor_operation(
                    format!("outputs/group-{group}/file-{index}"),
                    anchor,
                    vec![outputs],
                    identity(100 + group),
                )
            })
            .collect();
        let prepared = descriptor_plan(operations);

        // The plan pins four authority-chain descriptors and 110 relative
        // prefixes. Admission adds the transient descriptor reserve elsewhere.
        // Absence assertions stage nothing, so they need no leaf descriptors.
        assert_eq!(
            target_descriptor_requirement(&descriptor_config(), &prepared).unwrap(),
            DescriptorRequirement {
                directories: 114,
                leaves: 0,
            }
        );
    }

    #[test]
    fn target_descriptor_count_rejects_conflicting_shared_observations() {
        let anchor = identity(1);
        let outputs = identity(2);
        let prepared = descriptor_plan(vec![
            descriptor_operation("outputs/shared/a", anchor, vec![outputs], identity(3)),
            descriptor_operation("outputs/shared/b", anchor, vec![outputs], identity(4)),
        ]);

        assert!(matches!(
            target_descriptor_requirement(&descriptor_config(), &prepared),
            Err(CommitError::InvalidPlan(reason)) if reason.contains("observations conflict")
        ));
    }

    #[test]
    fn target_descriptor_count_rejects_malformed_ancestor_counts() {
        let prepared = descriptor_plan(vec![descriptor_operation(
            "outputs/shared/file",
            identity(1),
            Vec::new(),
            identity(2),
        )]);

        assert!(matches!(
            target_descriptor_requirement(&descriptor_config(), &prepared),
            Err(CommitError::InvalidPlan(reason)) if reason.contains("ancestor count")
        ));
    }

    #[test]
    fn prepare_validation_rejects_the_commit_descriptor_budget_before_store_access() {
        let prepared = descriptor_plan(vec![descriptor_operation(
            "output/file",
            identity(1),
            Vec::new(),
            identity(2),
        )]);
        let plan_id = prepared_id_v1(&prepared);
        let config = CommitConfig::new("/tmp/malm-descriptor-test-state", 1_000, Some(64))
            .unwrap()
            .with_target_authority(
                DeploymentName::new("home").unwrap(),
                "/tmp/malm-descriptor-test-target",
            )
            .unwrap();

        assert!(matches!(
            Committer::new(config).validate_prepared_ownership_v1(&plan_id, &prepared),
            Err(CommitError::InvalidPlan(reason))
                if reason.contains("pinned filesystem descriptors")
        ));
    }
}
