//! Reusable v1 engine boundary.

// Diagnostics carry structured nested errors; boxing these cold-path values
// would make the public API less direct.
#![allow(clippy::result_large_err)]

#[cfg(all(feature = "failpoints", not(debug_assertions)))]
compile_error!("the `failpoints` feature must not be enabled in release builds");

#[cfg(feature = "failpoints")]
mod failpoint;

macro_rules! engine_failpoint {
    ($name:expr) => {
        #[cfg(feature = "failpoints")]
        crate::failpoint::hit($name);
    };
}

mod authoring_prepare;
mod canonical_store;
mod checkout_prepare;
mod config_prepare;
mod durability;
mod deployment_prepare;
mod events;
mod git_acquisition;
mod graph_acquisition;
mod lifecycle_prepare;
mod lock_operation;
mod mount_identity;
mod pack_capture;
mod pack_store;
mod ports;
mod prepare_reuse;
mod prepared_store;
mod profile_switch;
mod tracked_update;

pub use canonical_store::{
    ArchivePublicationError, CanonicalObjectIssue, CanonicalObjectKind, CanonicalObjectPublication,
};
pub use config_prepare::StaticPrepareError;
pub use deployment_prepare::{
    StaticDeploymentPrepareError, StaticDeploymentPrepareRequestV1, StaticGraphAcquisitionV1,
    StaticProfile,
};
pub use events::{
    DiagnosticEvent, DiagnosticSink, EngineFailureKind, EngineFailureRef, EngineOperation,
    OperationId, OperationOutcome, ProgressEvent, ProgressSink,
};
pub use git_acquisition::{
    GitAcquisitionConfig, GitAcquisitionConfigError, GitAcquisitionIssue, GitCommandStage,
    GitObjectFormat, GitObjectKind, GitOutputStream, MAX_GIT_ACQUISITION_TIMEOUT,
    MAX_GIT_TRANSFER_BYTES,
};
pub use malm_archive::{
    ArchiveDeclarationV1, ArchiveDecodeError, ArchiveLimitsV1, DecodedArchiveV1,
};
pub use malm_commit::{CommitConfigError, CommitError};
pub use malm_config::{DesiredOutputKindV1, DesiredOutputSetV1, EvaluatedRichConfigV1};
pub use malm_format_component_api::FormatComponentAuthorizationV1;
pub use malm_store::{ConfigEntryPointV1, MovingSelectorV1, OwnershipOverlapKindV1};
pub use malm_tree::{SymlinkObjectV1, TreeObjectV1, tree_object_digest_v1};
pub use malm_types::{
    ApplyOutcomeV1, ApprovalV1, ArtifactBytesInspectionRequestV1, ArtifactDescriptorV1, ArtifactId,
    ArtifactMetadataInspectionRequestV1, ArtifactMetadataInspectionV1, ArtifactV1,
    CanonicalTreeEntryInspectionV1, CanonicalTreeEntryKindInspectionV1,
    CanonicalTreeInspectionRequestV1, CanonicalTreeInspectionV1, CapturedInputsInspectionV1,
    CatalogInspectionRequestV1, CatalogInspectionV1, CatalogNamespaceInspectionV1,
    CheckoutRequestV1, CommitRequestV1, DeploymentDtoError, DesiredSnapshotInspectionRequestV1,
    DesiredSnapshotInspectionV1, DesiredTargetInspectionV1, DesiredTargetStateInspectionV1,
    DirectorySafetyReasonV1, DisableRequestV1, EnableRequestV1, FsckFindingCodeV1, FsckFindingV1,
    FsckReportPartsV1, FsckReportV1, FsckRequestV1, FsckSeverityV1, FsckStoreAreaV1, FsckSubjectV1,
    GenerationInspectionPartsV1, GenerationInspectionRequestV1, GenerationInspectionV1,
    GenerationInventoryRequestV1, GenerationInventoryV1, HistoryRetentionRequestV1,
    InspectionDtoError, InspectionLimitsV1, LifecycleRequestV1, LifecycleStateViewV1,
    LifecycleTransitionViewV1, NamespaceHistoryRequestV1, NamespaceHistoryV1,
    NamespaceInspectionRequestV1, NamespaceInspectionV1, NamespaceRemovalHistoryV1,
    NamespaceRemovalRequestV1, NamespaceStatusKindV1, NamespaceStatusPartsV1,
    NamespaceStatusRequestV1, NamespaceStatusV1, ObjectInventoryKindV1, ObjectInventoryRequestV1,
    ObjectInventoryV1, PolicyFindingV1, PrepareArtifactV1, PrepareInputKindV1, PrepareInputV1,
    PrepareOperationV1, PreparePolicyFindingV1, PrepareRequestPartsV1, PrepareRequestV1,
    PrepareTransformDiagnosticLocationV1, PrepareTransformDiagnosticSeverityV1,
    PrepareTransformDiagnosticV1, PrepareTransformImplementationV1,
    PrepareTransformOutputLocationV1, PrepareTransformProvenanceV1, PrepareTransformResourceV1,
    PrepareTransformSourceLocationV1, PreparedDeploymentPartsV1, PreparedDeploymentV1, PreparedId,
    PreparedPlanInspectionRequestV1, PreparedTrackingAcquisitionGrantV1,
    PreparedTrackingAcquisitionKindV1, PreparedTrackingReviewPartsV1, PreparedTrackingReviewV1,
    PruneOutcomeV1, PruneRequestV1, RecoveryOutcomeV1, RestorePointInspectionV1,
    RestorePointRequestV1, RetentionAuthorityInspectionV1, RetentionInspectionV1,
    RetentionObjectV1, RetentionPinRequestV1, StateViewV1, StoreDirectoryV1, StoreErrorCodeV1,
    StoreErrorDetailsV1, StoreErrorV1, StoreErrorValidationError, StoreMetadataReasonV1,
    StoreOperationV1, StoreRequestV1, StoreResultV1, StoreRootV1, StoreStatusV1,
    TargetStatusKindV1, TargetStatusV1, TrackedRootInspectionV1, TrackedRootNoChangeV1,
    TrackedRootUpdateOutcomeV1, TrackingInspectionV1, TransformProvenanceInspectionV1,
};
pub use ports::{
    EnginePorts, FormatComponentExecutionIssue, FormatComponentExecutionPort, GitPackFile,
    GitPackFileModeError, GitProcessPort, ProcessFacts, SecureRandomPort,
};
pub use profile_switch::{ProfileSwitchError, ProfileSwitchRequestV1};
pub use tracked_update::{
    TrackedDeploymentPrepareRequestV1, TrackedRootAcquisitionGrantsV1, TrackedRootError,
    TrackedRootInfrastructureV1, TrackedRootPrepareRequestPartsV1, TrackedRootPrepareRequestV1,
    TrackedRootRequestError, TrackedRootUpdateRequestV1, UpdateOutcomeV1, UpdateRequestV1,
};

use std::error::Error;
use std::ffi::{OsStr, OsString};
use std::fmt;
use std::fs::File;
use std::io;
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use rustix::fs::{
    AtFlags, Mode, OFlags, RenameFlags, ResolveFlags, Stat, fchmod, fstat, fsync, mkdirat, open,
    openat, openat2, renameat_with, statat, unlinkat,
};

#[derive(Debug)]
struct DiscoveredPackV1 {
    digest: malm_types::Digest,
    total_bytes: u64,
    pack: std::sync::Arc<malm_module_graph::VerifiedPackV1>,
    publication: PackObjectPublication,
}

impl DiscoveredPackV1 {
    /// Derives the byte total and shared pack from one verified value.
    fn new(
        digest: malm_types::Digest,
        pack: malm_module_graph::VerifiedPackV1,
        publication: PackObjectPublication,
    ) -> Self {
        Self {
            digest,
            total_bytes: pack.total_bytes(),
            pack: std::sync::Arc::new(pack),
            publication,
        }
    }

    fn manifest(&self) -> &malm_pack::PackManifestV1 {
        self.pack.manifest()
    }
}

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

/// Access granted to an Engine's final store.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StoreAccess {
    /// Store inspection is allowed, but initialization and later mutations are not.
    ReadOnly,
    /// Store inspection and mutation are allowed.
    ReadWrite,
}

/// A directory involved in state-root validation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StateDirectory {
    /// The trusted parent containing the final root.
    StateParent,
    /// The final successor root.
    V1Root,
}

impl fmt::Display for StateDirectory {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::StateParent => formatter.write_str("state parent"),
            Self::V1Root => formatter.write_str("state root"),
        }
    }
}

/// Invalid explicit Engine root configuration.
// The cause already appears in Display, and source() would duplicate it.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
#[non_exhaustive]
pub enum EngineConfigError {
    /// The explicit final-root path violates the injected-root contract.
    #[error("invalid state root: {0}")]
    InvalidStateRoot(malm_root::RootPathError),
    /// A managed target authority was relative or the filesystem root.
    #[error("target authority {authority} must name an absolute non-root path, got {}", path.display())]
    InvalidTargetRoot {
        /// Stable authority selected by deployment requests.
        authority: malm_types::DeploymentName,
        /// Rejected path.
        path: PathBuf,
    },
    /// A managed target root is equal to or lexically inside protected state.
    #[error("target authority {authority} at {} is inside protected state", path.display())]
    TargetOverlapsState {
        /// Stable authority selected by deployment requests.
        authority: malm_types::DeploymentName,
        /// Rejected normalized target root.
        path: PathBuf,
    },
    /// One target authority was configured more than once.
    #[error("target authority {0} is configured twice")]
    DuplicateTargetAuthority(malm_types::DeploymentName),
}

/// Explicit roots and capabilities for one Engine instance.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EngineConfig {
    state_root: PathBuf,
    store_access: StoreAccess,
    target_authorities: std::collections::BTreeMap<malm_types::DeploymentName, PathBuf>,
}

impl EngineConfig {
    /// Creates a configuration from one exact injected final-root path.
    pub fn new(
        state_root: impl Into<PathBuf>,
        store_access: StoreAccess,
    ) -> Result<Self, EngineConfigError> {
        let state_root = state_root.into();
        malm_root::validate_injected_root(&state_root)
            .map_err(EngineConfigError::InvalidStateRoot)?;

        Ok(Self {
            state_root,
            store_access,
            target_authorities: std::collections::BTreeMap::new(),
        })
    }

    /// Creates the final `malm` root beneath an explicit state home.
    pub fn from_state_home(
        state_home: impl AsRef<Path>,
        store_access: StoreAccess,
    ) -> Result<Self, EngineConfigError> {
        let state_home = state_home.as_ref();
        Self::new(
            state_home.join(malm_root::PRODUCTION_ROOT_LEAF),
            store_access,
        )
    }

    /// Returns the exact final state root.
    #[must_use]
    pub fn state_root(&self) -> &Path {
        &self.state_root
    }

    /// Returns the trusted parent of the final state root.
    #[must_use]
    pub fn state_parent(&self) -> &Path {
        self.state_root
            .parent()
            .expect("validated final root has a parent")
    }

    /// Returns the configured store capability.
    #[must_use]
    pub const fn store_access(&self) -> StoreAccess {
        self.store_access
    }

    /// Adds one explicit managed-target authority without granting arbitrary paths to requests.
    pub fn with_target_authority(
        mut self,
        authority: malm_types::DeploymentName,
        path: impl Into<PathBuf>,
    ) -> Result<Self, EngineConfigError> {
        let path = normalize_target_absolute(&authority, path.into())?;
        if path.starts_with(&self.state_root) {
            return Err(EngineConfigError::TargetOverlapsState {
                authority: authority.clone(),
                path,
            });
        }
        if self
            .target_authorities
            .insert(authority.clone(), path)
            .is_some()
        {
            return Err(EngineConfigError::DuplicateTargetAuthority(authority));
        }
        Ok(self)
    }

    /// Returns the explicit root for a stable target authority.
    #[must_use]
    pub fn target_root(&self, authority: &malm_types::DeploymentName) -> Option<&Path> {
        self.target_authorities.get(authority).map(PathBuf::as_path)
    }

    fn state_leaf(&self) -> &OsStr {
        self.state_root
            .file_name()
            .expect("validated final root has a leaf")
    }
}

/// Current lifecycle state of the final state root.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StoreStatus {
    /// No final state root exists beneath the configured state parent.
    Absent,
    /// A safe final state root exists but has no store descriptor or other content.
    Uninitialized,
    /// A safe final state root contains the exact supported store descriptor.
    Ready,
}

/// Result of explicitly initializing the final state root.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InitializeStoreOutcome {
    status: StoreStatus,
}

/// One durable prepared plan in the human review index.
///
/// The modification time is a host filesystem observation used only to
/// order review listings; it never participates in digests, canonical
/// encodings, or machine-facing contracts.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlanIndexEntryV1 {
    plan_id: PreparedId,
    modified_seconds: i64,
    modified_nanoseconds: i64,
}

impl PlanIndexEntryV1 {
    pub(crate) const fn new(
        plan_id: PreparedId,
        modified_seconds: i64,
        modified_nanoseconds: i64,
    ) -> Self {
        Self {
            plan_id,
            modified_seconds,
            modified_nanoseconds,
        }
    }

    /// Returns the durable plan identifier.
    #[must_use]
    pub const fn plan_id(&self) -> &PreparedId {
        &self.plan_id
    }

    /// Returns the record's modification time in whole seconds since the
    /// Unix epoch.
    #[must_use]
    pub const fn modified_seconds(&self) -> i64 {
        self.modified_seconds
    }

    /// Returns the sub-second part of the modification time.
    #[must_use]
    pub const fn modified_nanoseconds(&self) -> i64 {
        self.modified_nanoseconds
    }
}

/// Result of publishing an immutable v1 pack object.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PackObjectPublication {
    /// This operation published the canonical object name.
    Published,
    /// An existing object was fully verified and reused.
    Reused,
}

/// Typed reason a v1 pack object or its private containers were rejected.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
#[non_exhaustive]
pub enum PackObjectIssue {
    /// The requested object is not present in the store.
    #[error("object is not cached")]
    Missing,
    /// An `objects` or `packs` entry is not a safe directory.
    #[error("object-store container is not a directory")]
    ContainerNotDirectory,
    /// A stored object is not a regular file.
    #[error("object is not a regular file")]
    ObjectNotRegular,
    /// A store entry has an unexpected owner.
    #[error("owner uid must be {expected_uid}, found {actual_uid}")]
    WrongOwner {
        /// Required owner.
        expected_uid: u32,
        /// Observed owner.
        actual_uid: u32,
    },
    /// A store entry has unexpected permission or special bits.
    #[error("mode must be {expected:04o}, found {actual:04o}")]
    UnexpectedMode {
        /// Required exact mode.
        expected: u32,
        /// Observed mode.
        actual: u32,
    },
    /// A stored object has an unexpected link count.
    #[error("link count must be {expected}, found {actual}")]
    UnexpectedLinks {
        /// Required link count.
        expected: u64,
        /// Observed link count.
        actual: u64,
    },
    /// A stored object exceeds the canonical encoded-object limit.
    #[error("object is {actual} bytes; limit is {limit}")]
    ObjectTooLarge {
        /// Maximum bytes.
        limit: u64,
        /// Observed bytes.
        actual: u64,
    },
    /// Supplied or stored bytes do not match the requested digest.
    #[error("object bytes compute digest {actual}")]
    DigestMismatch {
        /// Digest computed from the supplied or stored bytes.
        actual: malm_types::Digest,
    },
    /// Logical pack files or canonical object bytes are malformed.
    #[error("{detail}")]
    InvalidEncoding {
        /// Deterministic validation detail.
        detail: String,
    },
    /// A pinned object or container changed during the operation.
    #[error("object-store observation changed during the operation")]
    ObservationChanged,
}

/// Typed reason a local pack source could not be captured safely.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
#[non_exhaustive]
pub enum PackCaptureIssue {
    /// The explicit source root was not absolute.
    #[error("source root must be absolute")]
    SourceRootMustBeAbsolute,
    /// The explicit source root does not exist.
    #[error("source root does not exist")]
    SourceRootMissing,
    /// The source root or one of its path components is not a directory.
    #[error("source root path contains a non-directory")]
    SourceRootNotDirectory,
    /// The source overlaps an Engine state authority.
    #[error("source overlaps the protected state root")]
    ProtectedStateOverlap,
    /// A non-reserved source entry name is not UTF-8.
    #[error("source entry name is not UTF-8")]
    NonUtf8Name,
    /// A source-relative path is invalid under `pack/v1`.
    #[error("{detail}")]
    InvalidPath {
        /// Deterministic path-validation detail.
        detail: String,
    },
    /// A non-reserved source entry is a symbolic link.
    #[error("symbolic links are not valid pack entries")]
    SymbolicLink,
    /// A non-reserved source entry is neither a directory nor a regular file.
    #[error("special files are not valid pack entries")]
    UnsupportedFileType,
    /// Traversal attempted to cross a mount below the selected source root.
    #[error("source traversal cannot cross a nested mount")]
    MountBoundary,
    /// A source regular file has another hard-link alias.
    #[error("link count must be {expected}, found {actual}")]
    UnexpectedLinks {
        /// Required link count.
        expected: u64,
        /// Observed link count.
        actual: u64,
    },
    /// One source file exceeds the pack limit.
    #[error("source file is {actual} bytes; limit is {limit}")]
    FileTooLarge {
        /// Maximum bytes.
        limit: u64,
        /// Observed bytes.
        actual: u64,
    },
    /// The source contains too many included regular files.
    #[error("source contains {actual} files; limit is {limit}")]
    TooManyFiles {
        /// Maximum included files.
        limit: usize,
        /// Observed files, capped at the first over-limit value.
        actual: usize,
    },
    /// Included source bytes exceed the pack-tree limit.
    #[error("source contains {actual} file bytes; limit is {limit}")]
    TreeTooLarge {
        /// Maximum bytes.
        limit: u64,
        /// Observed bytes.
        actual: u64,
    },
    /// Filesystem traversal exceeded its bounded entry budget.
    #[error("source traversal exceeds {limit} entries")]
    TraversalLimitExceeded {
        /// Maximum visited non-dot entries outside excluded subtrees.
        limit: usize,
    },
    /// The source does not contain the required root manifest.
    #[error("source is missing malm-pack.kdl")]
    MissingManifest,
    /// Captured bytes do not match the digest required by the lock.
    #[error("local source drift: lock requires {expected}, captured {actual}")]
    DigestMismatch {
        /// Locked digest.
        expected: malm_types::Digest,
        /// Digest computed from the stable capture.
        actual: malm_types::Digest,
    },
    /// The captured pack manifest or one of its declared files is invalid.
    #[error("invalid captured pack: {detail}")]
    InvalidPack {
        /// Deterministic pack-verification detail.
        detail: String,
    },
    /// A source entry, binding, or directory changed during capture.
    #[error("source changed while it was being captured")]
    ObservationChanged,
}

/// Explicit filesystem and network grants for complete lock acquisition.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct GraphAcquisitionInputs {
    local_locators: std::collections::BTreeSet<malm_pack::LocalLocator>,
    git_urls: std::collections::BTreeSet<malm_pack::GitUrl>,
    git_scratch_roots: std::collections::BTreeMap<malm_types::Digest, PathBuf>,
}

impl GraphAcquisitionInputs {
    /// Creates a complete explicit authority set for one acquisition request.
    #[must_use]
    pub const fn new(
        local_locators: std::collections::BTreeSet<malm_pack::LocalLocator>,
        git_urls: std::collections::BTreeSet<malm_pack::GitUrl>,
        git_scratch_roots: std::collections::BTreeMap<malm_types::Digest, PathBuf>,
    ) -> Self {
        Self {
            local_locators,
            git_urls,
            git_scratch_roots,
        }
    }

    /// Returns the exact root-relative local authorities.
    #[must_use]
    pub const fn local_locators(&self) -> &std::collections::BTreeSet<malm_pack::LocalLocator> {
        &self.local_locators
    }

    /// Returns normalized HTTPS authorities approved for Git access.
    #[must_use]
    pub const fn git_urls(&self) -> &std::collections::BTreeSet<malm_pack::GitUrl> {
        &self.git_urls
    }

    /// Returns caller-owned scratch roots keyed by missing pack digest.
    #[must_use]
    pub const fn git_scratch_roots(
        &self,
    ) -> &std::collections::BTreeMap<malm_types::Digest, PathBuf> {
        &self.git_scratch_roots
    }
}

/// Failure while acquiring and assembling a complete locked pack graph.
#[derive(Debug)]
#[non_exhaustive]
pub enum GraphAcquisitionError {
    /// A local lock node was not present in the caller's explicit grant set.
    LocalSourceNotGranted {
        /// Locked node requiring local filesystem authority.
        node_id: malm_types::PackNodeId,
        /// Root-pack-relative locator requiring authorization.
        locator: malm_pack::LocalLocator,
    },
    /// A Git URL in the lock was not present in the explicit grant set.
    GitSourceNotGranted {
        /// Locked node requiring network or cached remote authority.
        node_id: malm_types::PackNodeId,
        /// Exact normalized URL requiring authorization.
        url: malm_pack::GitUrl,
    },
    /// A unique missing remote pack has no caller-owned scratch directory.
    MissingGitScratch {
        /// Locked pack content requiring acquisition.
        digest: malm_types::Digest,
    },
    /// This local-only operation encountered a Git lock node.
    UnsupportedGitSource {
        /// Locked node requiring Git acquisition.
        node_id: malm_types::PackNodeId,
        /// Exact Git source retained for diagnostics.
        git_source: malm_pack::GitSourceV1,
    },
    /// Stable capture or CAS publication failed for one lock node.
    Source {
        /// Locked node being acquired.
        node_id: malm_types::PackNodeId,
        /// Underlying Engine source or store failure.
        source: EngineError,
    },
    /// All source objects were published, but final graph verification failed.
    Assembly {
        /// Offline graph verification failure.
        source: malm_module_graph::GraphAssemblyError<EngineError>,
    },
}

impl fmt::Display for GraphAcquisitionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LocalSourceNotGranted { node_id, locator } => write!(
                formatter,
                "local source {locator} for locked node {node_id} was not explicitly granted"
            ),
            Self::GitSourceNotGranted { node_id, url } => write!(
                formatter,
                "Git source {url} for locked node {node_id} was not explicitly granted"
            ),
            Self::MissingGitScratch { digest } => write!(
                formatter,
                "missing caller-owned Git scratch directory for uncached pack {digest}"
            ),
            Self::UnsupportedGitSource {
                node_id,
                git_source,
            } => write!(
                formatter,
                "locked node {node_id} requires unsupported Git acquisition from {}",
                git_source.url()
            ),
            Self::Source { node_id, source } => {
                write!(formatter, "acquire locked node {node_id}: {source}")
            }
            Self::Assembly { source } => write!(formatter, "assemble acquired graph: {source}"),
        }
    }
}

impl Error for GraphAcquisitionError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        // The cause already appears in Display, and source() would duplicate it.
        None
    }
}

/// Explicit authorities used while discovering a new complete lock graph.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct LockResolutionInputs {
    local_locators: std::collections::BTreeSet<malm_pack::LocalLocator>,
    git_urls: std::collections::BTreeSet<malm_pack::GitUrl>,
    git_scratch_roots: std::collections::BTreeMap<malm_pack::GitSourceV1, PathBuf>,
    format_component_execution_profile: Option<malm_types::Digest>,
}

impl LockResolutionInputs {
    /// Creates a complete explicit authority set for one lock operation.
    #[must_use]
    pub const fn new(
        local_locators: std::collections::BTreeSet<malm_pack::LocalLocator>,
        git_urls: std::collections::BTreeSet<malm_pack::GitUrl>,
        git_scratch_roots: std::collections::BTreeMap<malm_pack::GitSourceV1, PathBuf>,
    ) -> Self {
        Self {
            local_locators,
            git_urls,
            git_scratch_roots,
            format_component_execution_profile: None,
        }
    }

    /// Supplies the exact profile stamped on every `format-component/v1` lock record.
    #[must_use]
    pub fn with_format_component_execution_profile(
        mut self,
        execution_profile: malm_types::Digest,
    ) -> Self {
        self.format_component_execution_profile = Some(execution_profile);
        self
    }

    /// Returns exact root-relative local authorities.
    #[must_use]
    pub const fn local_locators(&self) -> &std::collections::BTreeSet<malm_pack::LocalLocator> {
        &self.local_locators
    }

    /// Returns normalized HTTPS authorities approved for Git access.
    #[must_use]
    pub const fn git_urls(&self) -> &std::collections::BTreeSet<malm_pack::GitUrl> {
        &self.git_urls
    }

    /// Returns caller-owned scratch roots keyed by exact Git source identity.
    #[must_use]
    pub const fn git_scratch_roots(
        &self,
    ) -> &std::collections::BTreeMap<malm_pack::GitSourceV1, PathBuf> {
        &self.git_scratch_roots
    }

    /// Returns the caller-supplied `format-component/v1` execution profile, if any.
    #[must_use]
    pub const fn format_component_execution_profile(&self) -> Option<&malm_types::Digest> {
        self.format_component_execution_profile.as_ref()
    }
}

/// Durable filesystem result of an explicit lock operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LockFilePublication {
    /// A previously absent lock was created without replacement.
    Created,
    /// A valid existing lock was atomically replaced.
    Updated,
    /// The existing lock already contained the canonical candidate bytes.
    Unchanged,
}

/// Complete candidate graph and durable lock-file outcome.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LockOperationOutcome {
    lock: malm_pack::LockV1,
    publication: LockFilePublication,
}

impl LockOperationOutcome {
    const fn new(lock: malm_pack::LockV1, publication: LockFilePublication) -> Self {
        Self { lock, publication }
    }

    /// Returns the complete validated lock written by the operation.
    #[must_use]
    pub const fn lock(&self) -> &malm_pack::LockV1 {
        &self.lock
    }

    /// Returns whether the root lock was created, updated, or unchanged.
    #[must_use]
    pub const fn publication(&self) -> LockFilePublication {
        self.publication
    }

    /// Consumes the result and returns the complete lock.
    #[must_use]
    pub fn into_lock(self) -> malm_pack::LockV1 {
        self.lock
    }
}

/// Typed root `malm.lock` inspection or publication failure.
#[derive(Debug)]
#[non_exhaustive]
pub enum LockFileIssue {
    /// Another cooperative lock operation currently owns the root directory.
    Busy,
    /// Creation requires the destination name to be absent.
    AlreadyExists,
    /// Update requires an existing lock.
    Missing,
    /// The existing lock is not a regular file.
    NotRegular,
    /// The existing lock is not owned by the effective user.
    WrongOwner {
        /// Required owner.
        expected_uid: u32,
        /// Observed owner.
        actual_uid: u32,
    },
    /// The lock does not have exact generated-file permissions.
    UnexpectedMode {
        /// Required mode.
        expected: u32,
        /// Observed mode.
        actual: u32,
    },
    /// The existing lock has another hard link.
    UnexpectedLinks {
        /// Required link count.
        expected: u64,
        /// Observed link count.
        actual: u64,
    },
    /// The existing or generated bytes exceed the lock/v1 limit.
    TooLarge {
        /// Maximum bytes.
        limit: usize,
        /// Observed bytes.
        actual: usize,
    },
    /// Existing bytes are not a valid lock/v1 document.
    Invalid {
        /// Strict lock reader failure.
        source: malm_pack::LockReadError,
    },
    /// The lock binding or metadata changed during the operation.
    ObservationChanged,
    /// A reserved staging entry is not a complete canonical generated lock.
    UnsafeStaging,
    /// Descriptor-relative lock I/O failed.
    Io {
        /// Static operation description.
        operation: &'static str,
        /// Underlying host failure.
        source: io::Error,
    },
}

impl fmt::Display for LockFileIssue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Busy => formatter.write_str("another lock operation is in progress"),
            Self::AlreadyExists => formatter.write_str("lock already exists"),
            Self::Missing => formatter.write_str("lock does not exist"),
            Self::NotRegular => formatter.write_str("lock is not a regular file"),
            Self::WrongOwner {
                expected_uid,
                actual_uid,
            } => write!(
                formatter,
                "lock owner uid must be {expected_uid}, found {actual_uid}"
            ),
            Self::UnexpectedMode { expected, actual } => {
                write!(
                    formatter,
                    "lock mode must be {expected:04o}, found {actual:04o}"
                )
            }
            Self::UnexpectedLinks { expected, actual } => {
                write!(
                    formatter,
                    "lock link count must be {expected}, found {actual}"
                )
            }
            Self::TooLarge { limit, actual } => {
                write!(formatter, "lock is {actual} bytes; limit is {limit}")
            }
            Self::Invalid { source } => source.fmt(formatter),
            Self::ObservationChanged => formatter.write_str("lock changed during the operation"),
            Self::UnsafeStaging => {
                formatter.write_str("lock staging entry is not a canonical generated lock")
            }
            Self::Io { operation, source } => write!(formatter, "{operation}: {source}"),
        }
    }
}

impl Error for LockFileIssue {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        // The cause already appears in Display, and source() would duplicate it.
        None
    }
}

/// Failure while explicitly creating or updating a complete lock/v1 graph.
#[derive(Debug)]
#[non_exhaustive]
pub enum LockOperationError {
    /// Components were discovered without an explicit profile resolution input.
    MissingFormatComponentExecutionProfile,
    /// A discovered local selector was not explicitly granted.
    LocalSourceNotGranted {
        /// Root-relative locator requiring authorization.
        locator: malm_pack::LocalLocator,
    },
    /// A discovered Git URL was not explicitly granted.
    GitSourceNotGranted {
        /// Normalized URL requiring authorization.
        url: malm_pack::GitUrl,
    },
    /// A Git source requiring acquisition has no caller-owned scratch root.
    MissingGitScratch {
        /// Exact source requiring scratch.
        git_source: malm_pack::GitSourceV1,
    },
    /// A dependency declaration names another package than its source contains.
    PackageMismatch {
        /// Exact discovered source.
        source_identity: malm_pack::LockedSourceV1,
        /// Package required by the declaration.
        expected: malm_types::PackageId,
        /// Package declared by the discovered manifest.
        actual: malm_types::PackageId,
    },
    /// A local source changed while the complete graph was being resolved.
    SourceChanged {
        /// Root or local source that changed.
        source_identity: malm_pack::LockedSourceV1,
        /// Digest used to build the candidate graph.
        expected: malm_types::Digest,
        /// Digest observed during final validation.
        actual: malm_types::Digest,
    },
    /// Source capture, Git acquisition, or CAS access failed.
    Source {
        /// Source being discovered.
        source_identity: malm_pack::LockedSourceV1,
        /// Underlying Engine failure.
        source: EngineError,
    },
    /// A prior exact Git source points at semantically invalid cached bytes.
    CachedPackInvalid {
        /// Exact Git source whose old digest was reused.
        source_identity: malm_pack::LockedSourceV1,
        /// Cached content digest.
        digest: malm_types::Digest,
        /// Deterministic verification detail.
        detail: String,
    },
    /// Candidate graph construction failed semantic lock validation.
    Validation {
        /// Structural or graph validation failure.
        source: malm_pack::LockValidationError,
    },
    /// Generated canonical JSON exceeds the lock/v1 byte limit.
    EncodedLockTooLarge {
        /// Maximum bytes.
        limit: usize,
        /// Generated bytes.
        actual: usize,
    },
    /// Complete discovery exceeded a fixed aggregate resource ceiling.
    ResourceLimitExceeded {
        /// Bounded operation resource.
        resource: &'static str,
        /// Maximum accepted amount.
        limit: u64,
        /// Observed amount.
        actual: u64,
    },
    /// Final offline assembly disagreed with discovered graph data.
    Assembly {
        /// Offline graph verification failure.
        source: malm_module_graph::GraphAssemblyError<EngineError>,
    },
    /// Root lock-file inspection or publication failed.
    LockFile {
        /// Fixed root lock path.
        path: PathBuf,
        /// Typed file failure.
        reason: LockFileIssue,
    },
}

impl fmt::Display for LockOperationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingFormatComponentExecutionProfile => formatter.write_str(
                "lock resolution found format-component/v1 declarations but no execution profile was supplied",
            ),
            Self::LocalSourceNotGranted { locator } => {
                write!(
                    formatter,
                    "local source {locator} was not explicitly granted"
                )
            }
            Self::GitSourceNotGranted { url } => {
                write!(formatter, "Git source {url} was not explicitly granted")
            }
            Self::MissingGitScratch { git_source } => write!(
                formatter,
                "missing caller-owned scratch for Git source {} at {}",
                git_source.url(),
                git_source.commit()
            ),
            Self::PackageMismatch {
                source_identity,
                expected,
                actual,
            } => write!(
                formatter,
                "source {source_identity:?} declares package {actual}, dependency requires {expected}"
            ),
            Self::SourceChanged {
                source_identity,
                expected,
                actual,
            } => write!(
                formatter,
                "source {source_identity:?} changed during lock resolution: expected {expected}, found {actual}"
            ),
            Self::Source {
                source_identity,
                source,
            } => write!(formatter, "resolve source {source_identity:?}: {source}"),
            Self::CachedPackInvalid {
                source_identity,
                digest,
                detail,
            } => write!(
                formatter,
                "cached pack {digest} for source {source_identity:?} is invalid: {detail}"
            ),
            Self::Validation { source } => write!(formatter, "build lock graph: {source}"),
            Self::EncodedLockTooLarge { limit, actual } => {
                write!(
                    formatter,
                    "generated lock is {actual} bytes; limit is {limit}"
                )
            }
            Self::ResourceLimitExceeded {
                resource,
                limit,
                actual,
            } => write!(
                formatter,
                "lock resolution {resource} is {actual}; limit is {limit}"
            ),
            Self::Assembly { source } => write!(formatter, "verify generated lock: {source}"),
            Self::LockFile { path, reason } => {
                write!(formatter, "lock file {}: {reason}", path.display())
            }
        }
    }
}

impl Error for LockOperationError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        // The cause already appears in Display, and source() would duplicate it.
        None
    }
}

impl InitializeStoreOutcome {
    /// Returns the validated post-operation store status.
    #[must_use]
    pub const fn status(self) -> StoreStatus {
        self.status
    }

    const fn ready() -> Self {
        Self {
            status: StoreStatus::Ready,
        }
    }
}

/// Typed reason that final store metadata is malformed.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
#[non_exhaustive]
pub enum StoreMetadataIssue {
    /// A markerless root contains data and cannot be initialized implicitly.
    #[error("descriptor.json is missing but the state root is not empty")]
    MarkerMissingWithOtherEntries,
    /// `descriptor.json` is not a regular file.
    #[error("descriptor.json is not a regular file")]
    MarkerNotRegular,
    /// `descriptor.json` exceeds the bounded reader limit.
    #[error("descriptor.json is {actual} bytes; limit is {limit}")]
    MarkerTooLarge {
        /// Maximum accepted byte count.
        limit: usize,
        /// Observed byte count.
        actual: u64,
    },
    /// A descriptor-bearing root contains a name outside the final allowlist.
    #[error("state root contains an unrecognized top-level entry")]
    UnexpectedRootEntry,
    /// An allowed top-level leaf has incompatible type or metadata.
    #[error("invalid top-level final-root entry: {detail}")]
    InvalidRootEntry {
        /// Deterministic metadata detail.
        detail: String,
    },
    /// `descriptor.json` is not owned by the current effective user.
    #[error(
        "descriptor.json is owned by uid {actual_uid}, not current effective uid {expected_uid}"
    )]
    WrongOwner {
        /// Required owner.
        expected_uid: u32,
        /// Observed owner.
        actual_uid: u32,
    },
    /// `descriptor.json` does not have mode `0600`.
    #[error("descriptor.json mode must be 0600, found {actual:04o}")]
    UnexpectedMode {
        /// Observed permission and special mode bits.
        actual: u32,
    },
    /// `descriptor.json` has another hard-link alias.
    #[error("descriptor.json must have one link, found {links}")]
    MultipleLinks {
        /// Observed link count.
        links: u64,
    },
    /// The descriptor changed while it was being inspected or published.
    #[error("descriptor.json changed while it was being inspected")]
    ObservationChanged,
    /// The JSON descriptor is not the exact supported shape.
    #[error("invalid final-root descriptor: {detail}")]
    InvalidDescriptor {
        /// Parser detail suitable for diagnostics, not compatibility logic.
        detail: String,
    },
}

/// Typed reason that a directory is unsafe for v1 state.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[non_exhaustive]
pub enum DirectorySafetyIssue {
    /// The directory is not owned by the current effective user.
    #[error("owned by uid {actual_uid}, not current effective uid {expected_uid}")]
    WrongOwner {
        /// Required owner.
        expected_uid: u32,
        /// Observed owner.
        actual_uid: u32,
    },
    /// The state parent permits namespace mutation by group or other.
    #[error("mode {mode:04o} permits writes by group or other")]
    GroupOrOtherWritable {
        /// Observed permission bits.
        mode: u32,
    },
    /// Set-user-ID, set-group-ID, or sticky semantics are not allowed.
    #[error("mode {mode:04o} contains special mode bits")]
    SpecialModeBitsSet {
        /// Complete observed permission and special mode bits.
        mode: u32,
    },
    /// The final state root does not have the required exact permission bits.
    #[error("mode must be {expected:04o}, found {actual:04o}")]
    UnexpectedMode {
        /// Required permission bits.
        expected: u32,
        /// Observed permission bits.
        actual: u32,
    },
    /// Physical ancestry could not be bounded safely.
    #[error("physical ancestry exceeds {limit} directories")]
    AncestryLimitExceeded {
        /// Maximum number of ancestors inspected.
        limit: usize,
    },
}

/// Maximum number of directory occupancy conflict paths retained for diagnostics.
pub const MAX_DIRECTORY_CONFLICT_PATHS: usize = 256;

/// Typed reason prepared-plan storage or target observation failed.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
#[non_exhaustive]
pub enum PreparedStoreIssue {
    #[error("another prepared-store publication or retention operation is in progress")]
    PublicationBusy,
    #[error("prepared plan is missing")]
    MissingPlan,
    #[error("prepared artifact blob is missing")]
    MissingBlob,
    #[error("store container is not a directory")]
    ContainerNotDirectory,
    #[error("store entry is not a regular file")]
    EntryNotRegular,
    #[error("store entry is owned by uid {actual_uid}, expected {expected_uid}")]
    WrongOwner { expected_uid: u32, actual_uid: u32 },
    #[error("store entry mode is {actual:04o}, expected {expected:04o}")]
    UnexpectedMode { expected: u32, actual: u32 },
    #[error("store entry has {actual} links, expected {expected}")]
    UnexpectedLinks { expected: u64, actual: u64 },
    #[error("store entry has {actual} bytes; limit is {limit}")]
    EntryTooLarge { limit: u64, actual: u64 },
    #[error("store entry digest mismatch: expected {expected}, computed {actual}")]
    DigestMismatch {
        expected: malm_types::Digest,
        actual: malm_types::Digest,
    },
    #[error("invalid prepared record: {detail}")]
    InvalidRecord { detail: String },
    #[error("store or target observation changed")]
    ObservationChanged,
    #[error("namespace {namespace} head is stale: expected {expected:?}, found {actual:?}")]
    StaleNamespaceHead {
        namespace: malm_types::NamespaceName,
        expected: Option<malm_types::Digest>,
        actual: Option<malm_types::Digest>,
    },
    #[error(
        "namespace {requesting_namespace} target {requesting_authority}:{requested_path} has an {overlap} ownership conflict with namespace {owning_namespace} target {owning_authority}:{owned_path}"
    )]
    TargetOwnershipConflict {
        requesting_namespace: Box<malm_types::NamespaceName>,
        owning_namespace: Box<malm_types::NamespaceName>,
        requesting_authority: Box<malm_types::DeploymentName>,
        owning_authority: Box<malm_types::DeploymentName>,
        requested_path: String,
        owned_path: String,
        overlap: OwnershipOverlapKindV1,
    },
    #[error("namespace {namespace} cannot mutate unowned target {authority}:{relative_path}")]
    UnownedTargetMutation {
        namespace: malm_types::NamespaceName,
        authority: malm_types::DeploymentName,
        relative_path: String,
    },
    #[error("target authority {0} is not configured")]
    UnknownTargetAuthority(malm_types::DeploymentName),
    /// Exact directory leaves that must be moved or removed before preparation
    /// can continue. `paths` is non-empty, sorted, and bounded by
    /// [`MAX_DIRECTORY_CONFLICT_PATHS`].
    #[error(
        "directory occupancy conflicts block target preparation ({} paths retained, {omitted_count} omitted)",
        .paths.len()
    )]
    DirectoryOccupancyConflicts {
        /// Lexicographically first absolute blocker paths.
        paths: Vec<PathBuf>,
        /// Additional unique blocker paths omitted from `paths`.
        omitted_count: usize,
    },
    /// A managed target's on-disk content drifted and the plan carries no
    /// artifact that could restore it.
    #[error(
        "target {authority}:{relative_path} was modified outside malm and this plan cannot restore it; run `malm apply` to restore the managed content, or update the source to adopt the local changes"
    )]
    UnrestorableLocalModification {
        authority: malm_types::DeploymentName,
        relative_path: String,
    },
    /// A managed target was deleted outside malm and the plan carries
    /// nothing that could recreate it.
    #[error(
        "target {authority}:{relative_path} was deleted outside malm and this plan cannot recreate it; run `malm apply` to restore the managed content, or update the source to drop the target"
    )]
    UnrestorableMissingTarget {
        authority: malm_types::DeploymentName,
        relative_path: String,
    },
    /// An operation's ancestor directory is missing and no operation
    /// earlier in the plan creates it.
    #[error(
        "target {authority}:{relative_path} lies under missing directory {authority}:{missing_prefix} and this plan does not create it; run `malm apply` to restore the managed directory"
    )]
    MissingManagedAncestor {
        authority: malm_types::DeploymentName,
        relative_path: String,
        missing_prefix: String,
    },
    #[error("unsafe managed target: {detail}")]
    UnsafeTarget { detail: String },
    #[error("operation references artifact {0}")]
    UnknownArtifact(ArtifactId),
}

/// Failure from an Engine root operation.
#[derive(Debug)]
#[non_exhaustive]
pub enum EngineError {
    /// The operation requires write access that was not granted at construction.
    ReadOnlyStore,
    /// An operation requires an explicitly initialized supported store.
    StoreNotReady {
        /// Current safe store state.
        status: StoreStatus,
    },
    /// Initialization cannot proceed until the explicit state parent exists.
    StateParentMissing {
        /// The missing parent.
        path: PathBuf,
    },
    /// A directory failed ownership or mode validation.
    UnsafeDirectory {
        /// Which directory was rejected.
        directory: StateDirectory,
        /// The rejected path.
        path: PathBuf,
        /// Structured safety failure.
        reason: DirectorySafetyIssue,
    },
    /// The final root's namespace binding changed while an operation was in progress.
    RootObservationChanged {
        /// The configured path.
        path: PathBuf,
    },
    /// The configured state parent's namespace binding changed during an operation.
    StateParentObservationChanged {
        /// The configured state parent.
        path: PathBuf,
    },
    /// The store descriptor is malformed and is never repaired implicitly.
    MalformedStoreMetadata {
        /// Descriptor path used only for diagnostics.
        path: PathBuf,
        /// Structured validation failure.
        reason: StoreMetadataIssue,
    },
    /// The descriptor names a store schema this Engine does not implement.
    UnsupportedStoreVersion {
        /// Descriptor path used only for diagnostics.
        path: PathBuf,
        /// Required schema version.
        expected: u32,
        /// Observed schema version.
        found: u32,
    },
    /// A v1 pack object or one of its containers is unsafe or malformed.
    PackObject {
        /// Requested object identity.
        digest: malm_types::Digest,
        /// Store path used only for diagnostics.
        path: PathBuf,
        /// Structured rejection reason.
        reason: PackObjectIssue,
    },
    /// A canonical file, symlink, or tree object is unsafe or malformed.
    CanonicalObject {
        /// Expected canonical object category.
        kind: CanonicalObjectKind,
        /// Requested canonical object identity.
        digest: malm_types::Digest,
        /// Store path used only for diagnostics.
        path: PathBuf,
        /// Structured rejection reason.
        reason: CanonicalObjectIssue,
    },
    /// A local source tree is unsafe, invalid, unstable, or differs from its lock.
    PackCapture {
        /// Explicit normalized source root.
        root: PathBuf,
        /// Source entry associated with the failure.
        path: PathBuf,
        /// Structured rejection reason.
        reason: PackCaptureIssue,
    },
    /// Exact Git acquisition, object parsing, or source verification failed.
    GitAcquisition {
        /// Exact normalized Git source requested by the lock.
        git_source: Box<malm_pack::GitSourceV1>,
        /// Caller-owned scratch directory used only on a cache miss.
        scratch_root: PathBuf,
        /// Structured acquisition failure.
        reason: GitAcquisitionIssue,
    },
    /// A prepared record, artifact blob, or target precondition is unsafe or invalid.
    PreparedStore {
        /// Store or managed-target path used only for diagnostics.
        path: PathBuf,
        /// Structured rejection reason.
        reason: PreparedStoreIssue,
    },
    /// Commit-only state validation failed while preparing a deployment.
    Commit {
        /// Structured commit subsystem failure.
        source: CommitError,
    },
    /// A filesystem operation failed.
    Io {
        /// Static operation description.
        operation: &'static str,
        /// Path associated with the operation.
        path: PathBuf,
        /// Underlying operating-system error.
        source: io::Error,
    },
    /// A background worker thread panicked while an operation was in progress.
    ///
    /// Surfaced as a typed failure rather than propagating the panic so the
    /// Engine can report it through the standard `EngineError` channel
    /// instead of crashing the caller's thread.
    WorkerPanic {
        /// Static description of what the worker was doing.
        operation: &'static str,
    },
}

impl fmt::Display for EngineError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ReadOnlyStore => formatter.write_str("store is configured read-only"),
            Self::StoreNotReady { status } => {
                write!(formatter, "store is not ready: {status:?}")
            }
            Self::StateParentMissing { path } => write!(
                formatter,
                "state parent {} does not exist and cannot be created safely; create it (mode 700) before initializing Malm",
                path.display()
            ),
            Self::UnsafeDirectory {
                directory,
                path,
                reason,
            } => write!(
                formatter,
                "refusing unsafe {directory} {}: {reason}",
                path.display()
            ),
            Self::RootObservationChanged { path } => write!(
                formatter,
                "state root binding changed while inspecting {}",
                path.display()
            ),
            Self::StateParentObservationChanged { path } => write!(
                formatter,
                "state parent binding changed while inspecting {}",
                path.display()
            ),
            Self::MalformedStoreMetadata { path, reason } => write!(
                formatter,
                "malformed store metadata {}: {reason}; the incompatible root was left unchanged; move or remove the entire root for a clean reset (no state, history, or cache import is available)",
                path.display()
            ),
            Self::UnsupportedStoreVersion {
                path,
                expected,
                found,
            } => write!(
                formatter,
                "unsupported store schema in {}: expected exactly {expected}, found {found}; the incompatible root was left unchanged; move or remove the entire root for a clean reset (no state, history, or cache import is available)",
                path.display()
            ),
            Self::PackObject {
                digest,
                path,
                reason,
            } => write!(
                formatter,
                "invalid v1 pack object {digest} at {}: {reason}",
                path.display()
            ),
            Self::CanonicalObject {
                kind,
                digest,
                path,
                reason,
            } => write!(
                formatter,
                "invalid v1 canonical {kind} object {digest} at {}: {reason}",
                path.display()
            ),
            Self::PackCapture { root, path, reason } => {
                write!(
                    formatter,
                    "cannot capture local pack {} at {}: {reason}",
                    root.display(),
                    path.display()
                )?;
                if matches!(reason, PackCaptureIssue::DigestMismatch { .. }) {
                    write!(
                        formatter,
                        "; the source changed since it was locked — review the \
                         change and run `malm source lock update --source {}`",
                        root.display()
                    )?;
                }
                Ok(())
            }
            Self::GitAcquisition {
                git_source,
                scratch_root,
                reason,
            } => write!(
                formatter,
                "cannot acquire exact Git pack {} at {} subdir {} using scratch {}: {reason}",
                git_source.url(),
                git_source.commit(),
                git_source.subdir(),
                scratch_root.display()
            ),
            Self::PreparedStore { path, reason } => {
                write!(
                    formatter,
                    "prepared deployment error at {}: {reason}",
                    path.display()
                )
            }
            Self::Commit { source } => {
                write!(formatter, "commit state validation failed: {source}")
            }
            Self::Io {
                operation,
                path,
                source,
            } => write!(formatter, "{operation} {}: {source}", path.display()),
            Self::WorkerPanic { operation } => {
                write!(formatter, "{operation} worker panicked")
            }
        }
    }
}

impl Error for EngineError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        // The cause already appears in Display, and source() would duplicate it.
        None
    }
}

/// Reusable Malm Engine facade.
pub struct Engine {
    config: EngineConfig,
    ports: EnginePorts,
    next_operation_id: AtomicU64,
}

impl fmt::Debug for Engine {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Engine")
            .field("config", &self.config)
            .field("ports", &self.ports)
            .finish_non_exhaustive()
    }
}

trait ObservableError {
    fn failure(&self) -> EngineFailureRef<'_>;
}

impl ObservableError for EngineError {
    fn failure(&self) -> EngineFailureRef<'_> {
        match self {
            Self::Commit { source } => EngineFailureRef::Commit(source),
            _ => EngineFailureRef::Engine(self),
        }
    }
}

impl ObservableError for GraphAcquisitionError {
    fn failure(&self) -> EngineFailureRef<'_> {
        EngineFailureRef::GraphAcquisition(self)
    }
}

impl ObservableError for ArchivePublicationError {
    fn failure(&self) -> EngineFailureRef<'_> {
        EngineFailureRef::ArchivePublication(self)
    }
}

impl ObservableError for malm_module_graph::GraphAssemblyError<EngineError> {
    fn failure(&self) -> EngineFailureRef<'_> {
        EngineFailureRef::GraphAssembly(self)
    }
}

impl ObservableError for LockOperationError {
    fn failure(&self) -> EngineFailureRef<'_> {
        EngineFailureRef::LockOperation(self)
    }
}

impl ObservableError for StaticPrepareError {
    fn failure(&self) -> EngineFailureRef<'_> {
        EngineFailureRef::StaticPrepare(self)
    }
}

impl ObservableError for StaticDeploymentPrepareError {
    fn failure(&self) -> EngineFailureRef<'_> {
        EngineFailureRef::StaticDeploymentPrepare(self)
    }
}

impl ObservableError for TrackedRootError {
    fn failure(&self) -> EngineFailureRef<'_> {
        EngineFailureRef::TrackedRoot(self)
    }
}

impl ObservableError for ProfileSwitchError {
    fn failure(&self) -> EngineFailureRef<'_> {
        EngineFailureRef::ProfileSwitch(self)
    }
}

impl ObservableError for CommitError {
    fn failure(&self) -> EngineFailureRef<'_> {
        EngineFailureRef::Commit(self)
    }
}

#[derive(Debug)]
struct ReadyStoreRoot<'a> {
    config: &'a EngineConfig,
    expected_user_id: u32,
    parent_chain: PinnedDirectoryChain,
    state: File,
    state_io: File,
    descriptor: store::PinnedDescriptor,
}

impl ReadyStoreRoot<'_> {
    fn revalidate(&self) -> Result<(), EngineError> {
        let parent = self.parent_chain.directory();
        self.descriptor
            .revalidate(&self.state_io, self.config.state_root())?;
        store::validate_layout(
            &self.state_io,
            self.config.state_root(),
            self.expected_user_id,
        )?;
        validate_store_root(&self.state, self.config.state_root(), self.expected_user_id)?;
        ensure_bound(
            parent,
            self.config.state_leaf(),
            &self.state,
            self.config.state_root(),
        )?;
        let state_stat = directory_stat(
            &self.state,
            self.config.state_root(),
            "inspect pinned state root",
        )?;
        let io_stat = directory_stat(
            &self.state_io,
            self.config.state_root(),
            "inspect state root I/O handle",
        )?;
        if !same_object(&state_stat, &io_stat) {
            return Err(EngineError::RootObservationChanged {
                path: self.config.state_root().to_path_buf(),
            });
        }
        validate_state_parent(parent, self.config.state_parent(), self.expected_user_id)?;
        self.parent_chain.ensure_bound(self.config.state_parent())?;
        Ok(())
    }
}

impl Engine {
    /// Constructs an Engine from explicit configuration and host ports.
    #[must_use]
    pub const fn new(config: EngineConfig, ports: EnginePorts) -> Self {
        Self {
            config,
            ports,
            next_operation_id: AtomicU64::new(1),
        }
    }

    /// Returns this Engine's explicit configuration.
    #[must_use]
    pub const fn config(&self) -> &EngineConfig {
        &self.config
    }

    /// Returns the process facts frozen into this Engine's host contract.
    #[must_use]
    pub const fn process_facts(&self) -> ProcessFacts {
        self.ports.process_facts()
    }

    /// Executes an implemented store operation through stable semantic DTOs.
    ///
    /// Roots and host capabilities remain construction-time authority and are
    /// never serialized into the request. The returned error omits paths,
    /// operating-system errors, and private implementation models.
    pub fn execute_store_v1(&self, request: StoreRequestV1) -> Result<StoreResultV1, StoreErrorV1> {
        match request.operation() {
            StoreOperationV1::Status => self
                .store_status()
                .map(store_status_v1)
                .map(StoreResultV1::status)
                .map_err(store_error_v1),
            StoreOperationV1::Initialize => self
                .initialize_store()
                .map(|_| StoreResultV1::initialized())
                .map_err(store_error_v1),
        }
    }

    /// Persists an immutable deployment after capturing exact target observations.
    ///
    /// Artifact blobs are published first and the prepared record is published
    /// last without replacement. This operation never mutates managed targets or
    /// active deployment state.
    pub fn prepare_v1(
        &self,
        request: &PrepareRequestV1,
    ) -> Result<PreparedDeploymentV1, EngineError> {
        self.observe(EngineOperation::PrepareV1, || {
            prepared_store::prepare(self, request)
        })
    }

    /// Reloads and verifies one durable prepared plan for review.
    pub fn plan_v1(&self, plan_id: &PreparedId) -> Result<PreparedDeploymentV1, EngineError> {
        self.observe(EngineOperation::InspectPlanV1, || {
            prepared_store::plan(self, plan_id)
        })
    }

    /// Enumerates every durable prepared plan, newest record first.
    ///
    /// Ordering derives from record file modification times, a host
    /// filesystem observation for human review only. It never enters any
    /// digest or canonical encoding and is deliberately absent from
    /// `machine/v1`, whose consumers must reference exact plan identifiers.
    pub fn list_plans_v1(&self) -> Result<Vec<PlanIndexEntryV1>, EngineError> {
        self.observe(EngineOperation::InspectPlanIndexV1, || {
            prepared_store::list_plans(self)
        })
    }

    /// Reloads one durable plan through explicit item and decoded-byte limits.
    pub fn inspect_prepared_plan_v1(
        &self,
        request: &PreparedPlanInspectionRequestV1,
    ) -> Result<PreparedDeploymentV1, EngineError> {
        self.observe(EngineOperation::InspectPlanV1, || {
            prepared_store::inspect_plan(self, request)
        })
    }

    /// Returns verified metadata for one artifact without loading its bytes.
    pub fn inspect_artifact_metadata_v1(
        &self,
        request: &ArtifactMetadataInspectionRequestV1,
    ) -> Result<ArtifactMetadataInspectionV1, EngineError> {
        self.observe(EngineOperation::InspectArtifactMetadataV1, || {
            prepared_store::inspect_artifact_metadata(self, request)
        })
    }

    /// Returns only the exact captured input identities bound into one durable plan.
    pub fn inspect_captured_inputs_v1(
        &self,
        request: &PreparedPlanInspectionRequestV1,
    ) -> Result<CapturedInputsInspectionV1, EngineError> {
        self.observe(EngineOperation::InspectCapturedInputsV1, || {
            prepared_store::inspect_captured_inputs(self, request)
        })
    }

    /// Returns complete deterministic transform provenance for one durable plan.
    pub fn inspect_transform_provenance_v1(
        &self,
        request: &PreparedPlanInspectionRequestV1,
    ) -> Result<TransformProvenanceInspectionV1, EngineError> {
        self.observe(EngineOperation::InspectTransformProvenanceV1, || {
            prepared_store::inspect_transform_provenance(self, request)
        })
    }

    /// Loads one artifact only through a verified prepared-plan reference.
    pub fn artifact_v1(
        &self,
        plan_id: &PreparedId,
        artifact_id: &ArtifactId,
    ) -> Result<ArtifactV1, EngineError> {
        self.observe(EngineOperation::LoadArtifactV1, || {
            prepared_store::artifact(self, plan_id, artifact_id)
        })
    }

    /// Loads one verified artifact through an explicit byte bound.
    pub fn inspect_artifact_bytes_v1(
        &self,
        request: &ArtifactBytesInspectionRequestV1,
    ) -> Result<ArtifactV1, EngineError> {
        self.observe(EngineOperation::LoadArtifactV1, || {
            prepared_store::inspect_artifact_bytes(self, request)
        })
    }

    /// Evaluates one profile from verified pack bytes and persists its static file outputs.
    pub fn prepare_static_profile_v1(
        &self,
        profile: StaticProfile<'_>,
        profile_name: Option<&malm_types::ContributionName>,
    ) -> Result<PreparedDeploymentV1, StaticPrepareError> {
        self.observe(EngineOperation::PrepareStaticProfileV1, || {
            config_prepare::prepare(
                config_prepare::StaticPrepareContext {
                    engine: self,
                    graph: profile.graph,
                    component_authorization: profile.component_authorization,
                    namespace: profile.namespace,
                    target_authority: profile.target_authority,
                    expected_head: profile.expected_head,
                    tracked_root: None,
                },
                profile_name,
                None,
            )
        })
    }

    /// Acquires one exact locked graph, evaluates a static profile, observes current
    /// state and targets, and atomically persists the resulting immutable plan.
    pub fn prepare_static_deployment_v1(
        &self,
        request: &StaticDeploymentPrepareRequestV1,
    ) -> Result<PreparedDeploymentV1, StaticDeploymentPrepareError> {
        self.observe(EngineOperation::PrepareStaticDeploymentV1, || {
            deployment_prepare::prepare(self, request)
        })
    }

    /// Resolves one moving root exactly once and persists a reviewable tracked deployment plan.
    pub fn prepare_tracked_root_v1(
        &self,
        request: &TrackedRootPrepareRequestV1,
    ) -> Result<PreparedDeploymentV1, TrackedRootError> {
        self.observe(EngineOperation::PrepareTrackedRootV1, || {
            tracked_update::prepare(self, request)
        })
    }

    /// Resolves one moving root and prepares a complete tracked deployment.
    pub fn prepare_tracked_deployment_v1(
        &self,
        request: &TrackedRootPrepareRequestV1,
    ) -> Result<PreparedDeploymentV1, TrackedRootError> {
        self.prepare_tracked_root_v1(request)
    }

    /// Uses only selected-generation tracking authority to prepare a no-change or advancing update.
    pub fn update_v1(
        &self,
        request: &TrackedRootUpdateRequestV1,
    ) -> Result<TrackedRootUpdateOutcomeV1, TrackedRootError> {
        self.observe(EngineOperation::UpdateTrackedRootV1, || {
            tracked_update::update(self, request)
        })
    }

    /// Updates from the selected generation's persisted tracking authority.
    pub fn update_tracked_root_v1(
        &self,
        request: &TrackedRootUpdateRequestV1,
    ) -> Result<TrackedRootUpdateOutcomeV1, TrackedRootError> {
        self.update_v1(request)
    }

    /// Evaluates another profile using only the active generation's retained exact pack graph.
    pub fn prepare_profile_switch_v1(
        &self,
        request: &ProfileSwitchRequestV1,
    ) -> Result<PreparedDeploymentV1, ProfileSwitchError> {
        self.observe(EngineOperation::PrepareProfileSwitchV1, || {
            profile_switch::prepare(self, request)
        })
    }

    /// Prepares an offline restore plan for one generation retained by current authority.
    pub fn prepare_checkout_v1(
        &self,
        request: &CheckoutRequestV1,
    ) -> Result<PreparedDeploymentV1, EngineError> {
        self.observe(EngineOperation::PrepareCheckoutV1, || {
            checkout_prepare::prepare(self, request)
        })
    }

    /// Prepares a reviewable removal transition while retaining desired and tracking state.
    pub fn prepare_disable_v1<R>(&self, request: &R) -> Result<PreparedDeploymentV1, EngineError>
    where
        R: std::borrow::Borrow<malm_types::NamespaceName> + ?Sized,
    {
        self.observe(EngineOperation::PrepareDisableV1, || {
            lifecycle_prepare::disable(self, request.borrow())
        })
    }

    /// Prepares an offline recreation transition from retained durable blobs.
    pub fn prepare_enable_v1<R>(&self, request: &R) -> Result<PreparedDeploymentV1, EngineError>
    where
        R: std::borrow::Borrow<malm_types::NamespaceName> + ?Sized,
    {
        self.observe(EngineOperation::PrepareEnableV1, || {
            lifecycle_prepare::enable(self, request.borrow())
        })
    }

    /// Prepares complete target reconciliation followed by atomic namespace-head removal.
    pub fn prepare_namespace_removal_v1(
        &self,
        request: &NamespaceRemovalRequestV1,
    ) -> Result<PreparedDeploymentV1, EngineError> {
        self.observe(EngineOperation::PrepareNamespaceRemovalV1, || {
            lifecycle_prepare::remove_namespace(self, request)
        })
    }

    /// Prepares a new generation carrying a replacement bounded-history policy.
    pub fn prepare_history_retention_v1(
        &self,
        request: &HistoryRetentionRequestV1,
    ) -> Result<PreparedDeploymentV1, EngineError> {
        self.observe(EngineOperation::PrepareRetentionAuthorityV1, || {
            lifecycle_prepare::set_history_policy(self, request)
        })
    }

    /// Prepares a new generation adding one verified immutable-object pin.
    pub fn prepare_pin_v1(
        &self,
        request: &RetentionPinRequestV1,
    ) -> Result<PreparedDeploymentV1, EngineError> {
        self.observe(EngineOperation::PrepareRetentionAuthorityV1, || {
            lifecycle_prepare::pin(self, request)
        })
    }

    /// Prepares a new generation removing one exact immutable-object pin.
    pub fn prepare_unpin_v1(
        &self,
        request: &RetentionPinRequestV1,
    ) -> Result<PreparedDeploymentV1, EngineError> {
        self.observe(EngineOperation::PrepareRetentionAuthorityV1, || {
            lifecycle_prepare::unpin(self, request)
        })
    }

    /// Prepares a new generation adding one fully verified generation restore point.
    pub fn prepare_restore_point_v1(
        &self,
        request: &RestorePointRequestV1,
    ) -> Result<PreparedDeploymentV1, EngineError> {
        self.observe(EngineOperation::PrepareRetentionAuthorityV1, || {
            lifecycle_prepare::add_restore_point(self, request)
        })
    }

    /// Prepares a new generation dropping one unselected restore point.
    pub fn prepare_drop_restore_point_v1(
        &self,
        request: &RestorePointRequestV1,
    ) -> Result<PreparedDeploymentV1, EngineError> {
        self.observe(EngineOperation::PrepareRetentionAuthorityV1, || {
            lifecycle_prepare::drop_restore_point(self, request)
        })
    }

    /// Applies only a durable prepared record and local CAS objects.
    pub fn commit_v1(&self, request: &CommitRequestV1) -> Result<ApplyOutcomeV1, CommitError> {
        self.observe(EngineOperation::CommitV1, || {
            self.require_commit_write_access()?;
            self.committer_v1()?.commit_v1(request)
        })
    }

    /// Reconciles an incomplete commit to its prior or exact prepared state.
    pub fn recover_v1(&self) -> Result<RecoveryOutcomeV1, CommitError> {
        self.observe(EngineOperation::RecoverV1, || {
            self.require_commit_write_access()?;
            self.committer_v1()?.recover_v1()
        })
    }

    /// Inspects one namespace head through the commit-only package.
    pub fn inspect_state_v1(
        &self,
        namespace: &malm_types::NamespaceName,
    ) -> Result<StateViewV1, CommitError> {
        self.observe(EngineOperation::InspectStateV1, || {
            self.committer_v1()?.inspect_state_v1(namespace)
        })
    }

    /// Returns the complete canonical global catalog through a bounded semantic DTO.
    pub fn inspect_catalog_v1(
        &self,
        request: &CatalogInspectionRequestV1,
    ) -> Result<CatalogInspectionV1, CommitError> {
        self.observe(EngineOperation::InspectCatalogV1, || {
            self.committer_v1()?.inspect_catalog_v1(request)
        })
    }

    /// Returns one catalog-selected namespace and its verified generation.
    pub fn inspect_namespace_v1(
        &self,
        request: &NamespaceInspectionRequestV1,
    ) -> Result<NamespaceInspectionV1, CommitError> {
        self.observe(EngineOperation::InspectNamespaceV1, || {
            self.committer_v1()?.inspect_namespace_v1(request)
        })
    }

    /// Returns one fully verified selected namespace history without creating a lock.
    pub fn inspect_namespace_history_v1(
        &self,
        request: &NamespaceHistoryRequestV1,
    ) -> Result<NamespaceHistoryV1, CommitError> {
        self.observe(EngineOperation::InspectNamespaceHistoryV1, || {
            self.committer_v1()?.inspect_namespace_history_v1(request)
        })
    }

    /// Returns a bounded inventory of generations authorized by one selected
    /// namespace's effective retention authority.
    pub fn inspect_generation_inventory_v1(
        &self,
        request: &GenerationInventoryRequestV1,
    ) -> Result<GenerationInventoryV1, CommitError> {
        self.observe(EngineOperation::InspectGenerationInventoryV1, || {
            self.committer_v1()?
                .inspect_generation_inventory_v1(request)
        })
    }

    /// Returns one projection authorized by the current namespace retention roots.
    pub fn inspect_generation_details_v1(
        &self,
        request: &GenerationInspectionRequestV1,
    ) -> Result<GenerationInspectionV1, CommitError> {
        self.observe(EngineOperation::InspectGenerationV1, || {
            self.committer_v1()?.inspect_generation_details_v1(request)
        })
    }

    /// Returns one generation's exact cumulative desired snapshot.
    pub fn inspect_desired_snapshot_v1(
        &self,
        request: &DesiredSnapshotInspectionRequestV1,
    ) -> Result<DesiredSnapshotInspectionV1, CommitError> {
        self.observe(EngineOperation::InspectDesiredSnapshotV1, || {
            self.committer_v1()?.inspect_desired_snapshot_v1(request)
        })
    }

    /// Recursively verifies and expands one bounded canonical tree graph.
    pub fn inspect_canonical_tree_v1(
        &self,
        request: &CanonicalTreeInspectionRequestV1,
    ) -> Result<CanonicalTreeInspectionV1, CommitError> {
        self.observe(EngineOperation::InspectCanonicalTreeV1, || {
            self.committer_v1()?.inspect_canonical_tree_v1(request)
        })
    }

    /// Returns a bounded inventory for one exact immutable-object store kind.
    pub fn inspect_object_inventory_v1(
        &self,
        request: &ObjectInventoryRequestV1,
    ) -> Result<ObjectInventoryV1, CommitError> {
        self.observe(EngineOperation::InspectObjectInventoryV1, || {
            self.committer_v1()?.inspect_object_inventory_v1(request)
        })
    }

    /// Returns exact retention authority selected by one verified generation.
    pub fn inspect_retention_authority_v1(
        &self,
        request: &GenerationInspectionRequestV1,
    ) -> Result<RetentionInspectionV1, CommitError> {
        self.observe(EngineOperation::InspectRetentionV1, || {
            self.committer_v1()?.inspect_retention_authority_v1(request)
        })
    }

    /// Returns path- and capability-redacted tracked-root authority.
    pub fn inspect_tracking_v1(
        &self,
        request: &GenerationInspectionRequestV1,
    ) -> Result<TrackingInspectionV1, CommitError> {
        self.observe(EngineOperation::InspectTrackingV1, || {
            self.committer_v1()?.inspect_tracking_v1(request)
        })
    }

    /// Performs bounded selected/reachable fsck without repair or lock creation.
    pub fn fsck_v1(&self, request: &FsckRequestV1) -> Result<FsckReportV1, CommitError> {
        self.observe(EngineOperation::FsckV1, || {
            self.committer_v1()?.fsck_v1(request)
        })
    }

    /// Observes selected desired targets through bounded no-follow traversal.
    pub fn inspect_namespace_status_v1(
        &self,
        request: &NamespaceStatusRequestV1,
    ) -> Result<NamespaceStatusV1, CommitError> {
        self.observe(EngineOperation::InspectNamespaceStatusV1, || {
            self.committer_v1()?.inspect_namespace_status_v1(request)
        })
    }

    /// Applies an explicit reference-aware retention request under store locks.
    pub fn prune_v1(&self, request: &PruneRequestV1) -> Result<PruneOutcomeV1, CommitError> {
        self.observe(EngineOperation::PruneV1, || {
            self.require_commit_write_access()?;
            self.committer_v1()?.prune_v1(request)
        })
    }

    /// Computes the exact prune result under store locks without removing anything.
    pub fn preview_prune_v1(
        &self,
        request: &PruneRequestV1,
    ) -> Result<PruneOutcomeV1, CommitError> {
        self.observe(EngineOperation::PruneV1, || {
            self.require_commit_write_access()?;
            self.committer_v1()?.preview_prune_v1(request)
        })
    }

    fn require_commit_write_access(&self) -> Result<(), CommitError> {
        if self.config.store_access() == StoreAccess::ReadWrite {
            Ok(())
        } else {
            Err(CommitError::ReadOnlyStore)
        }
    }

    fn committer_v1(&self) -> Result<malm_commit::Committer, CommitError> {
        let mut config = malm_commit::CommitConfig::new(
            self.config.state_root(),
            self.effective_user_id(),
            self.process_facts().open_file_soft_limit(),
        )
        .map_err(CommitError::invalid_store)?;
        for (authority, path) in &self.config.target_authorities {
            config = config
                .with_target_authority(authority.clone(), path)
                .map_err(CommitError::invalid_store)?;
        }
        Ok(malm_commit::Committer::new(config))
    }

    /// Inspects the final state root without creating or replacing store entries.
    pub fn store_status(&self) -> Result<StoreStatus, EngineError> {
        self.observe(EngineOperation::StoreStatus, || self.store_status_raw())
    }

    fn store_status_raw(&self) -> Result<StoreStatus, EngineError> {
        let Some(parent_chain) = self.open_state_parent()? else {
            return Ok(StoreStatus::Absent);
        };
        let parent = parent_chain.directory();
        validate_state_parent(parent, self.config.state_parent(), self.effective_user_id())?;
        parent_chain.ensure_bound(self.config.state_parent())?;

        let state = open_child_directory(
            parent,
            self.config.state_leaf(),
            self.config.state_root(),
            "open state root without following symlinks",
        )?;

        let Some(state) = state else {
            parent_chain.ensure_bound(self.config.state_parent())?;
            return Ok(StoreStatus::Absent);
        };
        validate_store_root(&state, self.config.state_root(), self.effective_user_id())?;
        ensure_bound(
            parent,
            self.config.state_leaf(),
            &state,
            self.config.state_root(),
        )?;
        let state_io = open_io_directory(&state, self.config.state_root())?;
        let status = match store::inspect(
            &state_io,
            self.config.state_root(),
            self.effective_user_id(),
        )? {
            store::MetadataState::Missing => StoreStatus::Uninitialized,
            store::MetadataState::Ready => StoreStatus::Ready,
        };
        validate_store_root(&state, self.config.state_root(), self.effective_user_id())?;
        ensure_bound(
            parent,
            self.config.state_leaf(),
            &state,
            self.config.state_root(),
        )?;
        validate_state_parent(parent, self.config.state_parent(), self.effective_user_id())?;
        parent_chain.ensure_bound(self.config.state_parent())?;
        Ok(status)
    }

    /// Ensures a supported descriptor exists beneath a safe `0700` root.
    ///
    /// If absent, the root is created relative to the pinned state parent and
    /// `descriptor.json` is published atomically without replacing an existing
    /// descriptor. The result reports only the validated postcondition because
    /// another process may initialize concurrently.
    pub fn initialize_store(&self) -> Result<InitializeStoreOutcome, EngineError> {
        self.observe(EngineOperation::InitializeStore, || {
            self.initialize_store_with(|| {})
        })
    }

    /// Publishes or verifies one domain-separated canonical regular-file object.
    ///
    /// `expected_digest` identifies the canonical encoding, not the raw file
    /// contents. The stored object is immutable and private to the final CAS.
    pub fn publish_file_object_v1(
        &self,
        expected_digest: &malm_types::Digest,
        contents: &[u8],
    ) -> Result<CanonicalObjectPublication, EngineError> {
        self.observe(EngineOperation::PublishFileObjectV1, || {
            canonical_store::publish_file(self, expected_digest, contents)
        })
    }

    /// Publishes or verifies one canonical symbolic-link object.
    pub fn publish_symlink_object_v1(
        &self,
        expected_digest: &malm_types::Digest,
        object: &SymlinkObjectV1,
    ) -> Result<CanonicalObjectPublication, EngineError> {
        self.observe(EngineOperation::PublishSymlinkObjectV1, || {
            canonical_store::publish_symlink(self, expected_digest, object)
        })
    }

    /// Publishes or verifies one canonical tree object.
    pub fn publish_tree_object_v1(
        &self,
        expected_digest: &malm_types::Digest,
        object: &TreeObjectV1,
    ) -> Result<CanonicalObjectPublication, EngineError> {
        self.observe(EngineOperation::PublishTreeObjectV1, || {
            canonical_store::publish_tree(self, expected_digest, object)
        })
    }

    /// Loads and fully verifies one canonical regular-file object.
    pub fn load_file_object_v1(&self, digest: &malm_types::Digest) -> Result<Vec<u8>, EngineError> {
        self.observe(EngineOperation::LoadFileObjectV1, || {
            canonical_store::load_file(self, digest)
        })
    }

    /// Loads and fully verifies one canonical symbolic-link object.
    pub fn load_symlink_object_v1(
        &self,
        digest: &malm_types::Digest,
    ) -> Result<SymlinkObjectV1, EngineError> {
        self.observe(EngineOperation::LoadSymlinkObjectV1, || {
            canonical_store::load_symlink(self, digest)
        })
    }

    /// Loads and fully verifies one canonical tree object.
    pub fn load_tree_object_v1(
        &self,
        digest: &malm_types::Digest,
    ) -> Result<TreeObjectV1, EngineError> {
        self.observe(EngineOperation::LoadTreeObjectV1, || {
            canonical_store::load_tree(self, digest)
        })
    }

    /// Decodes an exact archive/v1 payload and durably publishes its canonical objects.
    ///
    /// The complete payload and resulting graph are verified before the store is
    /// opened for mutation. File, symlink, and non-root tree objects become
    /// durable before the root tree is linked last. This operation never mutates
    /// a managed target or publishes a prepared deployment record.
    pub fn decode_and_publish_archive_v1<R: io::Read>(
        &self,
        reader: R,
        declaration: ArchiveDeclarationV1,
        limits: ArchiveLimitsV1,
    ) -> Result<DecodedArchiveV1, ArchivePublicationError> {
        self.observe(EngineOperation::DecodeAndPublishArchiveV1, || {
            canonical_store::decode_and_publish(self, reader, declaration, limits)
        })
    }

    /// Publishes or verifies one immutable pack object in the final CAS.
    pub fn publish_pack_object_v1(
        &self,
        expected_digest: &malm_types::Digest,
        files: &[malm_pack::PackFileV1],
    ) -> Result<PackObjectPublication, EngineError> {
        self.observe(EngineOperation::PublishPackObjectV1, || {
            self.publish_pack_object_raw(expected_digest, files)
        })
    }

    fn publish_pack_object_raw(
        &self,
        expected_digest: &malm_types::Digest,
        files: &[malm_pack::PackFileV1],
    ) -> Result<PackObjectPublication, EngineError> {
        pack_store::publish(self, expected_digest, files)
    }

    /// Captures and publishes a policy-approved local pack at its locked digest.
    ///
    /// `source_root` must be an explicit absolute directory with no symbolic
    /// link in its path. Capture never follows links or nested mounts, omits
    /// `.git`, `malm.lock`, and lock-staging components, rejects unstable or special entries,
    /// and always re-hashes the current source even when the object is cached.
    /// The caller remains responsible for authorizing the local path before
    /// granting it to this filesystem adapter.
    pub fn capture_and_publish_local_pack_v1(
        &self,
        source_root: &Path,
        expected_digest: &malm_types::Digest,
    ) -> Result<PackObjectPublication, EngineError> {
        self.observe(EngineOperation::CaptureLocalPackV1, || {
            self.capture_local_pack_raw(source_root, expected_digest)
        })
    }

    fn capture_local_pack_raw(
        &self,
        source_root: &Path,
        expected_digest: &malm_types::Digest,
    ) -> Result<PackObjectPublication, EngineError> {
        pack_capture::capture_and_publish(self, source_root, expected_digest)
    }

    /// Acquires one exact Git commit/subdirectory and publishes its pack object.
    ///
    /// A verified CAS hit returns without inspecting `git` or `scratch_root`.
    /// On a miss, Git fetches only the full locked object ID into the explicit
    /// empty scratch directory. The selected commit must itself be a commit;
    /// tags are never peeled. Pack bytes come directly from committed trees and
    /// blobs, not checkout or archive transformations.
    pub fn acquire_and_publish_git_pack_v1(
        &self,
        git_source: &malm_pack::GitSourceV1,
        expected_digest: &malm_types::Digest,
        git: &GitAcquisitionConfig,
        scratch_root: &Path,
    ) -> Result<PackObjectPublication, EngineError> {
        self.observe(EngineOperation::AcquireGitPackV1, || {
            self.acquire_git_pack_raw(git_source, expected_digest, git, scratch_root)
        })
    }

    fn acquire_git_pack_raw(
        &self,
        git_source: &malm_pack::GitSourceV1,
        expected_digest: &malm_types::Digest,
        git: &GitAcquisitionConfig,
        scratch_root: &Path,
    ) -> Result<PackObjectPublication, EngineError> {
        git_acquisition::acquire_and_publish(self, git_source, expected_digest, git, scratch_root)
    }

    /// Acquires and assembles a complete lock containing only root/local nodes.
    ///
    /// Every `Local` node must have its exact locator in `granted_locators`.
    /// Locators are resolved relative to `root_source`, never relative to the
    /// importing pack. All local origins are recaptured even when their locked
    /// objects already exist, so a cache hit cannot conceal drift. Any Git node
    /// is rejected before source capture or CAS mutation.
    pub fn acquire_locked_local_graph_v1(
        &self,
        root_source: &Path,
        lock: &malm_pack::LockV1,
        granted_locators: &std::collections::BTreeSet<malm_pack::LocalLocator>,
    ) -> Result<malm_module_graph::AssembledLockedGraphV1, GraphAcquisitionError> {
        self.observe(EngineOperation::AcquireLocalGraphV1, || {
            graph_acquisition::acquire_local(self, root_source, lock, granted_locators)
        })
    }

    /// Acquires and assembles a complete mixed root/local/exact-Git lock graph.
    ///
    /// Every local locator and Git URL requires an explicit grant. Scratch is
    /// keyed by unique missing content digest, so fully cached Git objects need
    /// no scratch and never inspect or execute `git`. Local origins are always
    /// recaptured before final offline graph verification.
    pub fn acquire_locked_graph_v1(
        &self,
        root_source: &Path,
        lock: &malm_pack::LockV1,
        inputs: &GraphAcquisitionInputs,
        git: &GitAcquisitionConfig,
    ) -> Result<malm_module_graph::AssembledLockedGraphV1, GraphAcquisitionError> {
        self.observe(EngineOperation::AcquireGraphV1, || {
            graph_acquisition::acquire(self, root_source, lock, inputs, git)
        })
    }

    /// Discovers a complete graph and creates an absent root `malm.lock`.
    ///
    /// Root and local sources are captured from current bytes. Exact Git
    /// sources are fetched into caller-owned scratch because their independent
    /// content digests are not known before discovery. The lock is published
    /// only after complete graph validation and offline CAS assembly succeed.
    pub fn create_lock_v1(
        &self,
        root_source: &Path,
        inputs: &LockResolutionInputs,
        git: &GitAcquisitionConfig,
    ) -> Result<LockOperationOutcome, LockOperationError> {
        self.observe(EngineOperation::CreateLockV1, || {
            lock_operation::create(self, root_source, inputs, git)
        })
    }

    /// Re-resolves a complete graph and updates an existing root `malm.lock`.
    ///
    /// The old lock must be a safe valid lock/v1 file. Root and local sources
    /// are always recaptured; unchanged exact Git sources may reuse verified
    /// CAS objects without Git or scratch. Canonically unchanged output keeps
    /// the existing lock inode.
    pub fn update_lock_v1(
        &self,
        root_source: &Path,
        inputs: &LockResolutionInputs,
        git: &GitAcquisitionConfig,
    ) -> Result<LockOperationOutcome, LockOperationError> {
        self.observe(EngineOperation::UpdateLockV1, || {
            lock_operation::update(self, root_source, inputs, git)
        })
    }

    /// Loads and fully verifies one immutable pack object from the v1 CAS.
    pub fn load_pack_object_v1(
        &self,
        digest: &malm_types::Digest,
    ) -> Result<Vec<malm_pack::PackFileV1>, EngineError> {
        self.observe(EngineOperation::LoadPackObjectV1, || {
            self.load_pack_object_raw(digest)
        })
    }

    fn load_pack_object_raw(
        &self,
        digest: &malm_types::Digest,
    ) -> Result<Vec<malm_pack::PackFileV1>, EngineError> {
        pack_store::load(self, digest)
    }

    /// Assembles a complete lock graph using only verified cached v1 objects.
    pub fn assemble_cached_pack_graph_v1(
        &self,
        lock: &malm_pack::LockV1,
    ) -> Result<
        malm_module_graph::AssembledLockedGraphV1,
        malm_module_graph::GraphAssemblyError<EngineError>,
    > {
        self.observe(EngineOperation::AssembleCachedGraphV1, || {
            self.assemble_cached_pack_graph_raw(lock)
        })
    }

    fn assemble_cached_pack_graph_raw(
        &self,
        lock: &malm_pack::LockV1,
    ) -> Result<
        malm_module_graph::AssembledLockedGraphV1,
        malm_module_graph::GraphAssemblyError<EngineError>,
    > {
        malm_module_graph::assemble_locked_graph_v1(lock, self)
    }

    fn assemble_pack_graph_with_verified_raw(
        &self,
        lock: &malm_pack::LockV1,
        verified: &std::collections::BTreeMap<
            malm_types::Digest,
            std::sync::Arc<malm_module_graph::VerifiedPackV1>,
        >,
    ) -> Result<
        malm_module_graph::AssembledLockedGraphV1,
        malm_module_graph::GraphAssemblyError<EngineError>,
    > {
        malm_module_graph::assemble_locked_graph_with_verified_v1(lock, self, verified)
    }

    fn observe<T, E, F>(&self, operation: EngineOperation, run: F) -> Result<T, E>
    where
        F: FnOnce() -> Result<T, E>,
        E: ObservableError,
    {
        let operation_id = OperationId::new(self.next_operation_id.fetch_add(1, Ordering::Relaxed));
        events::emit_progress(
            self.ports.progress(),
            ProgressEvent::OperationStarted {
                operation_id,
                operation,
            },
        );
        let result = run();
        let outcome = match &result {
            Ok(_) => OperationOutcome::Succeeded,
            Err(error) => {
                events::emit_diagnostic(
                    self.ports.diagnostics(),
                    DiagnosticEvent::new(operation_id, operation, error.failure()),
                );
                OperationOutcome::Failed
            }
        };
        events::emit_progress(
            self.ports.progress(),
            ProgressEvent::OperationFinished {
                operation_id,
                operation,
                outcome,
            },
        );
        result
    }

    pub(crate) const fn effective_user_id(&self) -> u32 {
        self.ports.process_facts().effective_user_id()
    }

    pub(crate) const fn open_file_soft_limit(&self) -> Option<u64> {
        self.ports.process_facts().open_file_soft_limit()
    }

    pub(crate) fn secure_random(&self) -> &dyn SecureRandomPort {
        self.ports.secure_random()
    }

    pub(crate) fn git_process(&self) -> &dyn GitProcessPort {
        self.ports.git_process()
    }

    fn initialize_store_with(
        &self,
        after_create: impl FnOnce(),
    ) -> Result<InitializeStoreOutcome, EngineError> {
        if self.config.store_access() != StoreAccess::ReadWrite {
            return Err(EngineError::ReadOnlyStore);
        }

        let parent_chain = match self.open_state_parent()? {
            Some(chain) => chain,
            None => {
                self.create_state_parent_directories()?;
                self.open_state_parent()?
                    .ok_or_else(|| EngineError::StateParentObservationChanged {
                        path: self.config.state_parent().to_path_buf(),
                    })?
            }
        };
        let parent = parent_chain.directory();
        validate_state_parent(parent, self.config.state_parent(), self.effective_user_id())?;
        parent_chain.ensure_bound(self.config.state_parent())?;

        let existing_state = open_child_directory(
            parent,
            self.config.state_leaf(),
            self.config.state_root(),
            "open state root without following symlinks",
        )?;

        let state = if let Some(state) = existing_state {
            state
        } else {
            // Build and pin a private empty root before publishing its stable name.
            validate_state_parent(parent, self.config.state_parent(), self.effective_user_id())?;
            parent_chain.ensure_bound(self.config.state_parent())?;
            let (staging_leaf, staging) = create_staged_state_root(parent, self)?;
            ensure_bound(parent, &staging_leaf, &staging, self.config.state_root())?;
            parent_chain.ensure_bound(self.config.state_parent())?;
            match renameat_with(
                parent,
                &staging_leaf,
                parent,
                self.config.state_leaf(),
                RenameFlags::NOREPLACE,
            ) {
                Ok(()) => {
                    ensure_bound(
                        parent,
                        self.config.state_leaf(),
                        &staging,
                        self.config.state_root(),
                    )?;
                    after_create();
                    ensure_bound(
                        parent,
                        self.config.state_leaf(),
                        &staging,
                        self.config.state_root(),
                    )?;
                    staging
                }
                Err(rustix::io::Errno::EXIST) => {
                    discard_staged_state_root(
                        parent,
                        &staging_leaf,
                        &staging,
                        self.config.state_root(),
                    )?;
                    open_child_directory(
                        parent,
                        self.config.state_leaf(),
                        self.config.state_root(),
                        "pin concurrently initialized state root",
                    )?
                    .ok_or_else(|| EngineError::RootObservationChanged {
                        path: self.config.state_root().to_path_buf(),
                    })?
                }
                Err(source) => {
                    discard_staged_state_root(
                        parent,
                        &staging_leaf,
                        &staging,
                        self.config.state_root(),
                    )?;
                    return Err(errno_error(
                        "publish state root without replacement",
                        self.config.state_root(),
                        source,
                    ));
                }
            }
        };

        validate_store_root(&state, self.config.state_root(), self.effective_user_id())?;
        ensure_bound(
            parent,
            self.config.state_leaf(),
            &state,
            self.config.state_root(),
        )?;
        let state_io = open_io_directory(&state, self.config.state_root())?;

        if store::inspect(
            &state_io,
            self.config.state_root(),
            self.effective_user_id(),
        )? == store::MetadataState::Missing
        {
            parent_chain.ensure_bound(self.config.state_parent())?;
            ensure_bound(
                parent,
                self.config.state_leaf(),
                &state,
                self.config.state_root(),
            )?;
            store::publish(
                &state_io,
                self.config.state_root(),
                self.effective_user_id(),
            )?;
        }

        self.committer_v1()
            .and_then(|committer| committer.initialize_catalog_v1())
            .map_err(|error| EngineError::Io {
                operation: "initialize v1 state catalog",
                path: self.config.state_root().join("state/catalog.json"),
                source: io::Error::other(error),
            })?;

        fsync(&state_io).map_err(|source| {
            errno_error(
                "sync initialized state root",
                self.config.state_root(),
                source,
            )
        })?;
        fsync(parent).map_err(|source| {
            errno_error("sync state parent", self.config.state_parent(), source)
        })?;

        if store::inspect(
            &state_io,
            self.config.state_root(),
            self.effective_user_id(),
        )? != store::MetadataState::Ready
        {
            return Err(EngineError::MalformedStoreMetadata {
                path: self.config.state_root().join(store::MARKER_NAME),
                reason: StoreMetadataIssue::ObservationChanged,
            });
        }
        validate_store_root(&state, self.config.state_root(), self.effective_user_id())?;
        ensure_bound(
            parent,
            self.config.state_leaf(),
            &state,
            self.config.state_root(),
        )?;
        validate_state_parent(parent, self.config.state_parent(), self.effective_user_id())?;
        parent_chain.ensure_bound(self.config.state_parent())?;
        Ok(InitializeStoreOutcome::ready())
    }

    fn open_state_parent(&self) -> Result<Option<PinnedDirectoryChain>, EngineError> {
        match PinnedDirectoryChain::open(self.config.state_parent()) {
            Ok(parent) => Ok(Some(parent)),
            Err(rustix::io::Errno::NOENT) => Ok(None),
            Err(source) => Err(errno_error(
                "open state parent without following symlinks",
                self.config.state_parent(),
                source,
            )),
        }
    }

    /// Creates the missing components of the configured state parent.
    ///
    /// Missing components are created mode 0700 only beneath a deepest
    /// existing ancestor that itself satisfies the state-parent safety
    /// checks (user-owned, no special mode bits, not group/other-writable);
    /// an unsafe ancestor keeps initialization refused as
    /// [`EngineError::StateParentMissing`]. Symlinked ancestors are still
    /// rejected by `RESOLVE_NO_SYMLINKS` resolution.
    fn create_state_parent_directories(&self) -> Result<(), EngineError> {
        let path = self.config.state_parent();
        let uid = self.effective_user_id();
        let mut current = File::from(
            open("/", ROOT_DIRECTORY_FLAGS, Mode::empty())
                .map_err(|source| errno_error("open filesystem root", path, source))?,
        );
        let mut creating = false;
        for component in path.components() {
            let Component::Normal(leaf) = component else {
                continue;
            };
            if !creating {
                match openat2(&current, leaf, ROOT_DIRECTORY_FLAGS, Mode::empty(), RESOLVE_FLAGS) {
                    Ok(handle) => {
                        current = File::from(handle);
                        continue;
                    }
                    Err(rustix::io::Errno::NOENT) => {
                        match validate_state_parent(&current, path, uid) {
                            Ok(()) => creating = true,
                            Err(EngineError::UnsafeDirectory { .. }) => {
                                return Err(EngineError::StateParentMissing {
                                    path: path.to_path_buf(),
                                });
                            }
                            Err(other) => return Err(other),
                        }
                    }
                    Err(source) => {
                        return Err(errno_error(
                            "open state parent without following symlinks",
                            path,
                            source,
                        ));
                    }
                }
            }
            let created_here = match mkdirat(&current, leaf, Mode::from_raw_mode(0o700)) {
                Ok(()) => true,
                Err(rustix::io::Errno::EXIST) => false,
                Err(source) => {
                    return Err(errno_error(
                        "create missing state parent directory",
                        path,
                        source,
                    ));
                }
            };
            let child = File::from(
                openat2(
                    &current,
                    leaf,
                    DIRECTORY_FLAGS.union(OFlags::NOFOLLOW),
                    Mode::empty(),
                    RESOLVE_FLAGS,
                )
                .map_err(|source| {
                    errno_error("pin created state parent directory", path, source)
                })?,
            );
            let stat = directory_stat(&child, path, "inspect created state parent directory")?;
            validate_owner(&stat, StateDirectory::StateParent, path, uid)?;
            if created_here {
                if stat.st_mode & 0o7777 != 0o700 {
                    fchmod(&child, Mode::from_raw_mode(0o700)).map_err(|source| {
                        errno_error("restrict created state parent directory", path, source)
                    })?;
                }
            } else {
                // Lost a creation race: accept the concurrently created
                // directory only if it already satisfies the safety checks.
                validate_state_parent(&child, path, uid)?;
            }
            ensure_bound(&current, leaf, &child, path)?;
            current = child;
        }
        Ok(())
    }

    fn open_ready_store(&self) -> Result<ReadyStoreRoot<'_>, EngineError> {
        let Some(parent_chain) = self.open_state_parent()? else {
            return Err(EngineError::StoreNotReady {
                status: StoreStatus::Absent,
            });
        };
        let parent = parent_chain.directory();
        validate_state_parent(parent, self.config.state_parent(), self.effective_user_id())?;
        parent_chain.ensure_bound(self.config.state_parent())?;

        let Some(state) = open_child_directory(
            parent,
            self.config.state_leaf(),
            self.config.state_root(),
            "open state root without following symlinks",
        )?
        else {
            return Err(EngineError::StoreNotReady {
                status: StoreStatus::Absent,
            });
        };
        validate_store_root(&state, self.config.state_root(), self.effective_user_id())?;
        ensure_bound(
            parent,
            self.config.state_leaf(),
            &state,
            self.config.state_root(),
        )?;
        let state_io = open_io_directory(&state, self.config.state_root())?;
        let Some(descriptor) = store::pin(
            &state_io,
            self.config.state_root(),
            self.effective_user_id(),
        )?
        else {
            return Err(EngineError::StoreNotReady {
                status: StoreStatus::Uninitialized,
            });
        };
        let ready = ReadyStoreRoot {
            config: &self.config,
            expected_user_id: self.effective_user_id(),
            parent_chain,
            state,
            state_io,
            descriptor,
        };
        ready.revalidate()?;
        Ok(ready)
    }
}

const fn store_status_v1(status: StoreStatus) -> StoreStatusV1 {
    match status {
        StoreStatus::Absent => StoreStatusV1::Absent,
        StoreStatus::Uninitialized => StoreStatusV1::Uninitialized,
        StoreStatus::Ready => StoreStatusV1::Ready,
    }
}

const fn store_directory_v1(directory: StateDirectory) -> StoreDirectoryV1 {
    match directory {
        StateDirectory::StateParent => StoreDirectoryV1::StateParent,
        StateDirectory::V1Root => StoreDirectoryV1::V1Root,
    }
}

const fn directory_safety_reason_v1(reason: DirectorySafetyIssue) -> DirectorySafetyReasonV1 {
    match reason {
        DirectorySafetyIssue::WrongOwner { .. } => DirectorySafetyReasonV1::WrongOwner,
        DirectorySafetyIssue::GroupOrOtherWritable { .. } => {
            DirectorySafetyReasonV1::GroupOrOtherWritable
        }
        DirectorySafetyIssue::SpecialModeBitsSet { .. } => {
            DirectorySafetyReasonV1::SpecialModeBitsSet
        }
        DirectorySafetyIssue::UnexpectedMode { .. } => DirectorySafetyReasonV1::UnexpectedMode,
        DirectorySafetyIssue::AncestryLimitExceeded { .. } => {
            DirectorySafetyReasonV1::AncestryLimitExceeded
        }
    }
}

const fn store_metadata_reason_v1(reason: &StoreMetadataIssue) -> StoreMetadataReasonV1 {
    match reason {
        StoreMetadataIssue::MarkerMissingWithOtherEntries => {
            StoreMetadataReasonV1::MarkerMissingWithOtherEntries
        }
        StoreMetadataIssue::MarkerNotRegular => StoreMetadataReasonV1::MarkerNotRegular,
        StoreMetadataIssue::MarkerTooLarge { .. } => StoreMetadataReasonV1::MarkerTooLarge,
        StoreMetadataIssue::UnexpectedRootEntry => StoreMetadataReasonV1::UnexpectedRootEntry,
        StoreMetadataIssue::InvalidRootEntry { .. } => StoreMetadataReasonV1::InvalidRootEntry,
        StoreMetadataIssue::WrongOwner { .. } => StoreMetadataReasonV1::WrongOwner,
        StoreMetadataIssue::UnexpectedMode { .. } => StoreMetadataReasonV1::UnexpectedMode,
        StoreMetadataIssue::MultipleLinks { .. } => StoreMetadataReasonV1::MultipleLinks,
        StoreMetadataIssue::ObservationChanged => StoreMetadataReasonV1::ObservationChanged,
        StoreMetadataIssue::InvalidDescriptor { .. } => StoreMetadataReasonV1::InvalidDescriptor,
    }
}

fn store_error_v1(error: EngineError) -> StoreErrorV1 {
    match error {
        EngineError::ReadOnlyStore => StoreErrorV1::read_only_store(),
        EngineError::StoreNotReady { status } => {
            StoreErrorV1::store_not_ready(store_status_v1(status))
                .unwrap_or_else(|_| StoreErrorV1::internal())
        }
        EngineError::StateParentMissing { .. } => StoreErrorV1::state_parent_missing(),
        EngineError::UnsafeDirectory {
            directory, reason, ..
        } => StoreErrorV1::unsafe_directory(
            store_directory_v1(directory),
            directory_safety_reason_v1(reason),
        ),
        EngineError::RootObservationChanged { .. } => {
            StoreErrorV1::root_observation_changed(StoreRootV1::V1)
        }
        EngineError::StateParentObservationChanged { .. } => {
            StoreErrorV1::state_parent_observation_changed()
        }
        EngineError::MalformedStoreMetadata { reason, .. } => {
            StoreErrorV1::malformed_store_metadata(store_metadata_reason_v1(&reason))
        }
        EngineError::UnsupportedStoreVersion {
            expected, found, ..
        } => StoreErrorV1::unsupported_store_version(expected, found)
            .unwrap_or_else(|_| StoreErrorV1::internal()),
        EngineError::Io { .. } => StoreErrorV1::io(),
        EngineError::PackObject { .. }
        | EngineError::CanonicalObject { .. }
        | EngineError::PackCapture { .. }
        | EngineError::GitAcquisition { .. }
        | EngineError::PreparedStore { .. }
        | EngineError::Commit { .. }
        | EngineError::WorkerPanic { .. } => StoreErrorV1::internal(),
    }
}

impl malm_module_graph::PackObjectSourceV1 for Engine {
    type Error = EngineError;

    fn load_pack(
        &self,
        content_digest: &malm_types::Digest,
    ) -> Result<Vec<malm_pack::PackFileV1>, Self::Error> {
        self.load_pack_object_raw(content_digest)
    }
}

fn normalize_target_absolute(
    authority: &malm_types::DeploymentName,
    path: PathBuf,
) -> Result<PathBuf, EngineConfigError> {
    if !path.is_absolute() {
        return Err(EngineConfigError::InvalidTargetRoot {
            authority: authority.clone(),
            path,
        });
    }
    let original = path.clone();
    let mut parts = Vec::<OsString>::new();
    for component in path.components() {
        match component {
            Component::RootDir | Component::CurDir => {}
            Component::ParentDir => {
                parts.pop();
            }
            Component::Normal(part) => parts.push(part.to_os_string()),
            Component::Prefix(_) => {
                return Err(EngineConfigError::InvalidTargetRoot {
                    authority: authority.clone(),
                    path: original,
                });
            }
        }
    }
    if parts.is_empty() {
        return Err(EngineConfigError::InvalidTargetRoot {
            authority: authority.clone(),
            path: original,
        });
    }
    let mut normalized = PathBuf::from("/");
    normalized.extend(parts);
    Ok(normalized)
}

fn paths_overlap(left: &Path, right: &Path) -> bool {
    left == right || left.starts_with(right) || right.starts_with(left)
}

#[derive(Debug)]
struct PinnedDirectory {
    handle: File,
    leaf: Option<OsString>,
}

#[derive(Debug)]
struct PinnedDirectoryChain {
    directories: Vec<PinnedDirectory>,
}

impl PinnedDirectoryChain {
    fn open(path: &Path) -> rustix::io::Result<Self> {
        let filesystem_root = File::from(open("/", ROOT_DIRECTORY_FLAGS, Mode::empty())?);
        let mut directories = vec![PinnedDirectory {
            handle: filesystem_root,
            leaf: None,
        }];

        for component in path.components() {
            let Component::Normal(leaf) = component else {
                continue;
            };
            let handle = File::from(openat2(
                &directories
                    .last()
                    .expect("filesystem root starts the directory chain")
                    .handle,
                leaf,
                ROOT_DIRECTORY_FLAGS,
                Mode::empty(),
                RESOLVE_FLAGS,
            )?);
            directories.push(PinnedDirectory {
                handle,
                leaf: Some(leaf.to_os_string()),
            });
        }

        let state_parent = File::from(openat2(
            &directories
                .last()
                .expect("filesystem root starts the directory chain")
                .handle,
            ".",
            DIRECTORY_FLAGS.union(OFlags::NOFOLLOW),
            Mode::empty(),
            RESOLVE_FLAGS,
        )?);
        directories
            .last_mut()
            .expect("filesystem root starts the directory chain")
            .handle = state_parent;

        Ok(Self { directories })
    }

    fn directory(&self) -> &File {
        &self
            .directories
            .last()
            .expect("filesystem root starts the directory chain")
            .handle
    }

    fn ensure_bound(&self, path: &Path) -> Result<(), EngineError> {
        for pair in self.directories.windows(2) {
            let [parent, child] = pair else {
                unreachable!("directory-chain windows have two entries");
            };
            let leaf = child
                .leaf
                .as_deref()
                .expect("non-root directory-chain entries have a leaf");
            let bound = match statat(&parent.handle, leaf, AtFlags::SYMLINK_NOFOLLOW) {
                Ok(stat) => stat,
                Err(rustix::io::Errno::NOENT | rustix::io::Errno::NOTDIR) => {
                    return Err(EngineError::StateParentObservationChanged {
                        path: path.to_path_buf(),
                    });
                }
                Err(source) => {
                    return Err(errno_error("revalidate state parent binding", path, source));
                }
            };
            let pinned = directory_stat(&child.handle, path, "inspect pinned state parent")?;
            if !same_object(&bound, &pinned) {
                return Err(EngineError::StateParentObservationChanged {
                    path: path.to_path_buf(),
                });
            }
        }
        Ok(())
    }
}

fn open_child_directory(
    parent: &File,
    leaf: &OsStr,
    path: &Path,
    operation: &'static str,
) -> Result<Option<File>, EngineError> {
    match openat2(
        parent,
        leaf,
        ROOT_DIRECTORY_FLAGS,
        Mode::empty(),
        ROOT_RESOLVE_FLAGS,
    ) {
        Ok(directory) => Ok(Some(File::from(directory))),
        Err(rustix::io::Errno::NOENT) => Ok(None),
        Err(source) => Err(errno_error(operation, path, source)),
    }
}

fn open_io_directory(pinned: &File, path: &Path) -> Result<File, EngineError> {
    let directory = openat2(
        pinned,
        ".",
        DIRECTORY_FLAGS
            .union(OFlags::NOFOLLOW)
            .union(OFlags::NOATIME),
        Mode::empty(),
        RESOLVE_FLAGS,
    )
    .map(File::from)
    .map_err(|source| errno_error("open pinned state root for I/O", path, source))?;
    let pinned_stat = directory_stat(pinned, path, "inspect pinned state root")?;
    let io_stat = directory_stat(&directory, path, "inspect state root I/O handle")?;
    if !same_object(&pinned_stat, &io_stat) {
        return Err(EngineError::RootObservationChanged {
            path: path.to_path_buf(),
        });
    }
    Ok(directory)
}

fn create_staged_state_root(
    parent: &File,
    engine: &Engine,
) -> Result<(OsString, File), EngineError> {
    let config = &engine.config;
    for _ in 0..32 {
        let mut random = [0_u8; 16];
        engine
            .secure_random()
            .fill(&mut random)
            .map_err(|source| EngineError::Io {
                operation: "generate private state-root staging name",
                path: config.state_root().to_path_buf(),
                source,
            })?;
        let staging_leaf = OsString::from(format!(
            ".{}.init-{}",
            config.state_leaf().to_string_lossy(),
            hex::encode(random)
        ));
        match mkdirat(parent, &staging_leaf, Mode::from_raw_mode(0o700)) {
            Ok(()) => {}
            Err(rustix::io::Errno::EXIST) => continue,
            Err(source) => {
                return Err(errno_error(
                    "create private state-root staging directory",
                    config.state_root(),
                    source,
                ));
            }
        }
        let staged = open_child_directory(
            parent,
            &staging_leaf,
            config.state_root(),
            "pin private state-root staging directory",
        )?
        .ok_or_else(|| EngineError::RootObservationChanged {
            path: config.state_root().to_path_buf(),
        })?;
        ensure_bound(parent, &staging_leaf, &staged, config.state_root())?;
        if let Err(error) =
            validate_store_root(&staged, config.state_root(), engine.effective_user_id())
        {
            discard_staged_state_root(parent, &staging_leaf, &staged, config.state_root())?;
            return Err(error);
        }
        return Ok((staging_leaf, staged));
    }

    Err(EngineError::Io {
        operation: "allocate private state-root staging name",
        path: config.state_root().to_path_buf(),
        source: io::Error::new(
            io::ErrorKind::AlreadyExists,
            "exhausted random staging-name attempts",
        ),
    })
}

fn discard_staged_state_root(
    parent: &File,
    staging_leaf: &OsStr,
    staged: &File,
    state_root: &Path,
) -> Result<(), EngineError> {
    ensure_bound(parent, staging_leaf, staged, state_root)?;
    unlinkat(parent, staging_leaf, AtFlags::REMOVEDIR).map_err(|source| {
        errno_error(
            "remove private state-root staging directory",
            state_root,
            source,
        )
    })
}

fn validate_state_parent(
    parent: &File,
    path: &Path,
    expected_user_id: u32,
) -> Result<(), EngineError> {
    let stat = directory_stat(parent, path, "inspect state parent")?;
    validate_owner(&stat, StateDirectory::StateParent, path, expected_user_id)?;
    let mode = stat.st_mode & 0o7777;
    if mode & 0o7000 != 0 {
        return Err(EngineError::UnsafeDirectory {
            directory: StateDirectory::StateParent,
            path: path.to_path_buf(),
            reason: DirectorySafetyIssue::SpecialModeBitsSet { mode },
        });
    }
    if mode & 0o022 != 0 {
        return Err(EngineError::UnsafeDirectory {
            directory: StateDirectory::StateParent,
            path: path.to_path_buf(),
            reason: DirectorySafetyIssue::GroupOrOtherWritable { mode },
        });
    }
    Ok(())
}

fn validate_store_root(
    state: &File,
    path: &Path,
    expected_user_id: u32,
) -> Result<(), EngineError> {
    let stat = directory_stat(state, path, "inspect state root")?;
    validate_owner(&stat, StateDirectory::V1Root, path, expected_user_id)?;
    let mode = stat.st_mode & 0o7777;
    if mode != 0o700 {
        return Err(EngineError::UnsafeDirectory {
            directory: StateDirectory::V1Root,
            path: path.to_path_buf(),
            reason: DirectorySafetyIssue::UnexpectedMode {
                expected: 0o700,
                actual: mode,
            },
        });
    }
    Ok(())
}

fn validate_owner(
    stat: &Stat,
    directory: StateDirectory,
    path: &Path,
    expected_uid: u32,
) -> Result<(), EngineError> {
    if stat.st_uid != expected_uid {
        return Err(EngineError::UnsafeDirectory {
            directory,
            path: path.to_path_buf(),
            reason: DirectorySafetyIssue::WrongOwner {
                expected_uid,
                actual_uid: stat.st_uid,
            },
        });
    }
    Ok(())
}

fn directory_contains(
    ancestor: &File,
    descendant: &File,
    state_parent: &Path,
) -> Result<bool, EngineError> {
    let ancestor_stat = directory_stat(ancestor, state_parent, "inspect root identity")?;
    let mut current = descendant.try_clone().map_err(|source| EngineError::Io {
        operation: "clone root handle for ancestry check",
        path: state_parent.to_path_buf(),
        source,
    })?;

    for _ in 0..4_096 {
        let current_stat = directory_stat(&current, state_parent, "inspect root ancestry")?;
        if same_object(&ancestor_stat, &current_stat) {
            return Ok(true);
        }
        let parent = openat(&current, "..", ROOT_DIRECTORY_FLAGS, Mode::empty())
            .map(File::from)
            .map_err(|source| errno_error("open physical root ancestor", state_parent, source))?;
        let parent_stat = directory_stat(&parent, state_parent, "inspect root ancestor")?;
        if same_object(&current_stat, &parent_stat) {
            return Ok(false);
        }
        current = parent;
    }

    Err(EngineError::UnsafeDirectory {
        directory: StateDirectory::StateParent,
        path: state_parent.to_path_buf(),
        reason: DirectorySafetyIssue::AncestryLimitExceeded { limit: 4_096 },
    })
}

fn ensure_bound(
    parent: &File,
    leaf: &OsStr,
    directory: &File,
    path: &Path,
) -> Result<(), EngineError> {
    let pinned = directory_stat(directory, path, "inspect pinned root identity")?;
    let bound = match statat(parent, leaf, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(stat) => stat,
        Err(rustix::io::Errno::NOENT) => {
            return Err(EngineError::RootObservationChanged {
                path: path.to_path_buf(),
            });
        }
        Err(source) => return Err(errno_error("revalidate state root binding", path, source)),
    };
    if !same_object(&pinned, &bound) {
        return Err(EngineError::RootObservationChanged {
            path: path.to_path_buf(),
        });
    }
    Ok(())
}

fn directory_stat(
    directory: &File,
    path: &Path,
    operation: &'static str,
) -> Result<Stat, EngineError> {
    fstat(directory).map_err(|source| errno_error(operation, path, source))
}

fn same_object(left: &Stat, right: &Stat) -> bool {
    left.st_dev == right.st_dev && left.st_ino == right.st_ino
}

fn same_file_snapshot(left: &Stat, right: &Stat) -> bool {
    same_object(left, right)
        && left.st_mode == right.st_mode
        && left.st_uid == right.st_uid
        && left.st_gid == right.st_gid
        && left.st_nlink == right.st_nlink
        && left.st_size == right.st_size
        && left.st_mtime == right.st_mtime
        && left.st_mtime_nsec == right.st_mtime_nsec
        && left.st_ctime == right.st_ctime
        && left.st_ctime_nsec == right.st_ctime_nsec
}

pub(crate) fn io_error(operation: &'static str, path: &Path, source: io::Error) -> EngineError {
    EngineError::Io {
        operation,
        path: path.to_path_buf(),
        source,
    }
}

pub(crate) fn errno_error(
    operation: &'static str,
    path: &Path,
    source: rustix::io::Errno,
) -> EngineError {
    io_error(operation, path, io::Error::from(source))
}

/// Returns raw file-name bytes for every entry except `.` and `..`.
pub(crate) fn dir_entry_names(directory: &File) -> io::Result<Vec<Vec<u8>>> {
    use rustix::fs::Dir;
    let mut stream = Dir::read_from(directory)?;
    let mut names = Vec::new();
    while let Some(entry) = stream.read() {
        let entry = entry?;
        let name = entry.file_name().to_bytes();
        if matches!(name, b"." | b"..") {
            continue;
        }
        names.push(name.to_vec());
    }
    Ok(names)
}

mod store {
    use std::ffi::OsStr;
    use std::fs::File;
    use std::io::{Read, Write};
    use std::os::unix::ffi::OsStrExt;
    use std::path::{Path, PathBuf};

    use super::{
        DIRECTORY_FLAGS, EngineError, ROOT_RESOLVE_FLAGS, StoreMetadataIssue, errno_error,
        io_error, same_file_snapshot, same_object,
    };
    use rustix::fs::{
        AtFlags, FileType, Mode, OFlags, Stat, fchmod, fstat, fsync, linkat, openat, openat2,
        statat,
    };

    pub(super) const MARKER_NAME: &str = malm_root::DESCRIPTOR_FILENAME;
    const STORE_SCHEMA_VERSION: u32 = malm_root::DESCRIPTOR_VERSION;
    const MAX_MARKER_BYTES: usize = malm_root::MAX_DESCRIPTOR_BYTES;
    const CANONICAL_DESCRIPTOR: &[u8] = malm_root::DESCRIPTOR_CANONICAL_BYTES;

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub(super) enum MetadataState {
        Missing,
        Ready,
    }

    #[derive(Debug)]
    pub(super) struct PinnedDescriptor {
        marker: File,
        snapshot: Stat,
        expected_user_id: u32,
    }

    impl PinnedDescriptor {
        pub(super) fn revalidate(&self, root: &File, root_path: &Path) -> Result<(), EngineError> {
            let marker_path = marker_path(root_path);
            let current =
                ensure_marker_bound(root, &self.marker, &marker_path, self.expected_user_id)?;
            if !same_file_snapshot(&self.snapshot, &current) {
                return Err(metadata_error(
                    &marker_path,
                    StoreMetadataIssue::ObservationChanged,
                ));
            }
            Ok(())
        }
    }

    pub(super) fn inspect(
        root: &File,
        root_path: &Path,
        expected_user_id: u32,
    ) -> Result<MetadataState, EngineError> {
        pin(root, root_path, expected_user_id).map(|descriptor| {
            if descriptor.is_some() {
                MetadataState::Ready
            } else {
                MetadataState::Missing
            }
        })
    }

    #[cfg(test)]
    fn inspect_with(
        root: &File,
        root_path: &Path,
        expected_user_id: u32,
        after_read: impl FnOnce(),
    ) -> Result<MetadataState, EngineError> {
        pin_with(root, root_path, expected_user_id, after_read).map(|descriptor| {
            if descriptor.is_some() {
                MetadataState::Ready
            } else {
                MetadataState::Missing
            }
        })
    }

    pub(super) fn pin(
        root: &File,
        root_path: &Path,
        expected_user_id: u32,
    ) -> Result<Option<PinnedDescriptor>, EngineError> {
        pin_with(root, root_path, expected_user_id, || {})
    }

    fn pin_with(
        root: &File,
        root_path: &Path,
        expected_user_id: u32,
        after_read: impl FnOnce(),
    ) -> Result<Option<PinnedDescriptor>, EngineError> {
        let marker_path = marker_path(root_path);
        let mut after_read = Some(after_read);
        for _ in 0..3 {
            let observed = match statat(root, MARKER_NAME, AtFlags::SYMLINK_NOFOLLOW) {
                Ok(stat) => stat,
                Err(rustix::io::Errno::NOENT) => {
                    if root_is_empty(root, root_path)? {
                        return Ok(None);
                    }
                    if statat(root, MARKER_NAME, AtFlags::SYMLINK_NOFOLLOW).is_ok() {
                        continue;
                    }
                    return Err(metadata_error(
                        &marker_path,
                        StoreMetadataIssue::MarkerMissingWithOtherEntries,
                    ));
                }
                Err(source) => {
                    return Err(errno_error(
                        "inspect store descriptor",
                        &marker_path,
                        source,
                    ));
                }
            };
            validate_marker_stat(&observed, &marker_path, expected_user_id)?;
            let mut marker = match openat2(
                root,
                MARKER_NAME,
                OFlags::RDONLY
                    | OFlags::NONBLOCK
                    | OFlags::NOFOLLOW
                    | OFlags::NOATIME
                    | OFlags::CLOEXEC,
                Mode::empty(),
                ROOT_RESOLVE_FLAGS,
            ) {
                Ok(marker) => File::from(marker),
                Err(rustix::io::Errno::NOENT | rustix::io::Errno::LOOP) => continue,
                Err(source) => {
                    return Err(errno_error(
                        "open store descriptor without following symlinks",
                        &marker_path,
                        source,
                    ));
                }
            };
            let opened = fstat(&marker).map_err(|source| {
                errno_error("inspect opened store descriptor", &marker_path, source)
            })?;
            if !same_object(&observed, &opened) {
                continue;
            }
            validate_marker_stat(&opened, &marker_path, expected_user_id)?;

            let mut bytes = Vec::with_capacity(opened.st_size as usize);
            Read::by_ref(&mut marker)
                .take((MAX_MARKER_BYTES + 1) as u64)
                .read_to_end(&mut bytes)
                .map_err(|source| io_error("read store descriptor", &marker_path, source))?;
            if bytes.len() > MAX_MARKER_BYTES {
                return Err(metadata_error(
                    &marker_path,
                    StoreMetadataIssue::MarkerTooLarge {
                        limit: MAX_MARKER_BYTES,
                        actual: bytes.len() as u64,
                    },
                ));
            }
            if let Some(after_read) = after_read.take() {
                after_read();
            }
            let final_stat = ensure_marker_bound(root, &marker, &marker_path, expected_user_id)?;
            if !same_file_snapshot(&opened, &final_stat) {
                continue;
            }
            parse_descriptor(&bytes, &marker_path)?;
            let confirmed = ensure_marker_bound(root, &marker, &marker_path, expected_user_id)?;
            if !same_file_snapshot(&opened, &confirmed) {
                continue;
            }
            validate_layout(root, root_path, expected_user_id)?;
            let confirmed = ensure_marker_bound(root, &marker, &marker_path, expected_user_id)?;
            if !same_file_snapshot(&opened, &confirmed) {
                continue;
            }
            return Ok(Some(PinnedDescriptor {
                marker,
                snapshot: confirmed,
                expected_user_id,
            }));
        }

        Err(metadata_error(
            &marker_path,
            StoreMetadataIssue::ObservationChanged,
        ))
    }

    pub(super) fn validate_layout(
        root: &File,
        root_path: &Path,
        expected_user_id: u32,
    ) -> Result<(), EngineError> {
        for _ in 0..32 {
            match validate_layout_once(root, root_path, expected_user_id) {
                Err(EngineError::MalformedStoreMetadata {
                    reason: StoreMetadataIssue::ObservationChanged,
                    ..
                }) => continue,
                result => return result,
            }
        }
        Err(metadata_error(
            root_path,
            StoreMetadataIssue::ObservationChanged,
        ))
    }

    fn validate_layout_once(
        root: &File,
        root_path: &Path,
        expected_user_id: u32,
    ) -> Result<(), EngineError> {
        let before = fstat(root)
            .map_err(|source| errno_error("inspect final-root layout", root_path, source))?;
        let names = root_entry_names(root, root_path)?;
        for name in &names {
            let Some(contract) = malm_root::final_root_entry(name) else {
                return Err(metadata_error(
                    &root_path.join(OsStr::from_bytes(name)),
                    StoreMetadataIssue::UnexpectedRootEntry,
                ));
            };
            let path = root_path.join(OsStr::from_bytes(name));
            match contract.kind() {
                malm_root::FinalRootEntryKind::Descriptor => {}
                malm_root::FinalRootEntryKind::Directory => {
                    validate_layout_directory(root, contract.name(), &path, expected_user_id)?;
                }
                malm_root::FinalRootEntryKind::Lock => {
                    validate_layout_lock(root, contract.name(), &path, expected_user_id)?;
                }
            }
        }
        let after = fstat(root)
            .map_err(|source| errno_error("reinspect final-root layout", root_path, source))?;
        if !same_file_snapshot(&before, &after) || names != root_entry_names(root, root_path)? {
            return Err(metadata_error(
                root_path,
                StoreMetadataIssue::ObservationChanged,
            ));
        }
        Ok(())
    }

    fn root_entry_names(root: &File, root_path: &Path) -> Result<Vec<Vec<u8>>, EngineError> {
        let enumeration = openat2(
            root,
            ".",
            DIRECTORY_FLAGS | OFlags::NOFOLLOW | OFlags::NOATIME,
            Mode::empty(),
            ROOT_RESOLVE_FLAGS,
        )
        .map(File::from)
        .map_err(|source| {
            errno_error("open final root for layout enumeration", root_path, source)
        })?;
        let mut names = super::dir_entry_names(&enumeration)
            .map_err(|source| io_error("enumerate final-root layout", root_path, source))?;
        names.sort();
        Ok(names)
    }

    fn validate_layout_directory(
        root: &File,
        leaf: &str,
        path: &Path,
        expected_user_id: u32,
    ) -> Result<(), EngineError> {
        let observed = statat(root, leaf, AtFlags::SYMLINK_NOFOLLOW)
            .map_err(|source| errno_error("inspect final-root container", path, source))?;
        validate_layout_entry_stat(
            &observed,
            path,
            FileType::Directory,
            expected_user_id,
            malm_root::CONTAINER_MODE,
            false,
        )?;
        let directory = openat2(
            root,
            leaf,
            DIRECTORY_FLAGS | OFlags::NOFOLLOW | OFlags::NOATIME,
            Mode::empty(),
            ROOT_RESOLVE_FLAGS,
        )
        .map(File::from)
        .map_err(|source| errno_error("pin final-root container", path, source))?;
        let opened = fstat(&directory)
            .map_err(|source| errno_error("inspect pinned final-root container", path, source))?;
        validate_layout_entry_stat(
            &opened,
            path,
            FileType::Directory,
            expected_user_id,
            malm_root::CONTAINER_MODE,
            false,
        )?;
        if !same_object(&observed, &opened) {
            return Err(metadata_error(path, StoreMetadataIssue::ObservationChanged));
        }
        Ok(())
    }

    fn validate_layout_lock(
        root: &File,
        leaf: &str,
        path: &Path,
        expected_user_id: u32,
    ) -> Result<(), EngineError> {
        let observed = statat(root, leaf, AtFlags::SYMLINK_NOFOLLOW)
            .map_err(|source| errno_error("inspect final-root lock", path, source))?;
        validate_layout_entry_stat(
            &observed,
            path,
            FileType::RegularFile,
            expected_user_id,
            malm_root::MUTABLE_FILE_MODE,
            true,
        )?;
        let file = openat2(
            root,
            leaf,
            OFlags::RDONLY
                | OFlags::NONBLOCK
                | OFlags::NOFOLLOW
                | OFlags::NOATIME
                | OFlags::CLOEXEC,
            Mode::empty(),
            ROOT_RESOLVE_FLAGS,
        )
        .map(File::from)
        .map_err(|source| errno_error("pin final-root lock", path, source))?;
        let opened = fstat(&file)
            .map_err(|source| errno_error("inspect pinned final-root lock", path, source))?;
        validate_layout_entry_stat(
            &opened,
            path,
            FileType::RegularFile,
            expected_user_id,
            malm_root::MUTABLE_FILE_MODE,
            true,
        )?;
        if !same_object(&observed, &opened) {
            return Err(metadata_error(path, StoreMetadataIssue::ObservationChanged));
        }
        Ok(())
    }

    fn validate_layout_entry_stat(
        stat: &Stat,
        path: &Path,
        expected_kind: FileType,
        expected_user_id: u32,
        expected_mode: u32,
        lock: bool,
    ) -> Result<(), EngineError> {
        let detail = if FileType::from_raw_mode(stat.st_mode) != expected_kind {
            Some("filesystem kind is not allowed")
        } else if stat.st_uid != expected_user_id {
            Some("owner differs from the effective user")
        } else if stat.st_mode & 0o7777 != expected_mode {
            Some("permission or special-mode bits are not canonical")
        } else if lock && stat.st_nlink != 1 {
            Some("lock must have exactly one link")
        } else if lock && stat.st_size != 0 {
            Some("lock must be empty")
        } else {
            None
        };
        if let Some(detail) = detail {
            return Err(metadata_error(
                path,
                StoreMetadataIssue::InvalidRootEntry {
                    detail: detail.to_owned(),
                },
            ));
        }
        Ok(())
    }

    pub(super) fn publish(
        root: &File,
        root_path: &Path,
        expected_user_id: u32,
    ) -> Result<(), EngineError> {
        publish_with(root, root_path, expected_user_id, || {})
    }

    fn publish_with(
        root: &File,
        root_path: &Path,
        expected_user_id: u32,
        before_link: impl FnOnce(),
    ) -> Result<(), EngineError> {
        let marker_path = marker_path(root_path);
        let temporary = openat(
            root,
            ".",
            OFlags::TMPFILE | OFlags::RDWR | OFlags::CLOEXEC,
            Mode::from_raw_mode(0o600),
        )
        .map(File::from)
        .map_err(|source| errno_error("create unnamed store descriptor", &marker_path, source))?;
        let mut temporary = temporary;
        fchmod(&temporary, Mode::from_raw_mode(0o600)).map_err(|source| {
            errno_error(
                "set unnamed store descriptor permissions",
                &marker_path,
                source,
            )
        })?;
        temporary
            .write_all(CANONICAL_DESCRIPTOR)
            .map_err(|source| io_error("write store descriptor", &marker_path, source))?;
        fsync(&temporary)
            .map_err(|source| errno_error("sync unnamed store descriptor", &marker_path, source))?;

        before_link();
        match inspect(root, root_path, expected_user_id)? {
            MetadataState::Missing => {}
            MetadataState::Ready => {
                fsync(root).map_err(|source| {
                    errno_error(
                        "sync concurrently initialized store root",
                        root_path,
                        source,
                    )
                })?;
                return Ok(());
            }
        }
        match linkat(&temporary, "", root, MARKER_NAME, AtFlags::EMPTY_PATH) {
            Ok(()) => {
                ensure_marker_bound(root, &temporary, &marker_path, expected_user_id)?;
                fsync(root).map_err(|source| errno_error("sync store root", root_path, source))?;
                ensure_marker_bound(root, &temporary, &marker_path, expected_user_id)?;
                if inspect(root, root_path, expected_user_id)? != MetadataState::Ready {
                    return Err(metadata_error(
                        &marker_path,
                        StoreMetadataIssue::ObservationChanged,
                    ));
                }
            }
            Err(rustix::io::Errno::EXIST) => {
                if inspect(root, root_path, expected_user_id)? != MetadataState::Ready {
                    return Err(metadata_error(
                        &marker_path,
                        StoreMetadataIssue::ObservationChanged,
                    ));
                }
                fsync(root).map_err(|source| {
                    errno_error(
                        "sync concurrently initialized store root",
                        root_path,
                        source,
                    )
                })?;
            }
            Err(source) => {
                return Err(errno_error(
                    "publish store descriptor without replacement",
                    &marker_path,
                    source,
                ));
            }
        }
        Ok(())
    }

    fn parse_descriptor(bytes: &[u8], path: &Path) -> Result<(), EngineError> {
        match malm_root::decode_descriptor_v1(bytes) {
            Ok(_) => Ok(()),
            Err(malm_root::DescriptorDecodeError::UnsupportedVersion { found, .. }) => {
                let found = u32::try_from(found).map_err(|_| {
                    metadata_error(
                        path,
                        StoreMetadataIssue::InvalidDescriptor {
                            detail: "descriptor version does not fit the supported version domain"
                                .to_owned(),
                        },
                    )
                })?;
                Err(EngineError::UnsupportedStoreVersion {
                    path: path.to_path_buf(),
                    expected: STORE_SCHEMA_VERSION,
                    found,
                })
            }
            Err(malm_root::DescriptorDecodeError::TooLarge { limit, actual }) => {
                Err(metadata_error(
                    path,
                    StoreMetadataIssue::MarkerTooLarge {
                        limit,
                        actual: actual as u64,
                    },
                ))
            }
            Err(error) => Err(metadata_error(
                path,
                StoreMetadataIssue::InvalidDescriptor {
                    detail: error.to_string(),
                },
            )),
        }
    }

    fn validate_marker_stat(
        stat: &Stat,
        path: &Path,
        expected_user_id: u32,
    ) -> Result<(), EngineError> {
        if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile {
            return Err(metadata_error(path, StoreMetadataIssue::MarkerNotRegular));
        }
        if stat.st_size < 0 {
            return Err(metadata_error(
                path,
                StoreMetadataIssue::InvalidDescriptor {
                    detail: "descriptor.json reports a negative size".to_owned(),
                },
            ));
        }
        let size = stat.st_size as u64;
        if size > MAX_MARKER_BYTES as u64 {
            return Err(metadata_error(
                path,
                StoreMetadataIssue::MarkerTooLarge {
                    limit: MAX_MARKER_BYTES,
                    actual: size,
                },
            ));
        }
        if stat.st_uid != expected_user_id {
            return Err(metadata_error(
                path,
                StoreMetadataIssue::WrongOwner {
                    expected_uid: expected_user_id,
                    actual_uid: stat.st_uid,
                },
            ));
        }
        let mode = stat.st_mode & 0o7777;
        if mode != 0o600 {
            return Err(metadata_error(
                path,
                StoreMetadataIssue::UnexpectedMode { actual: mode },
            ));
        }
        if stat.st_nlink != 1 {
            return Err(metadata_error(
                path,
                StoreMetadataIssue::MultipleLinks {
                    links: stat.st_nlink,
                },
            ));
        }
        Ok(())
    }

    fn ensure_marker_bound(
        root: &File,
        marker: &File,
        path: &Path,
        expected_user_id: u32,
    ) -> Result<Stat, EngineError> {
        let pinned = fstat(marker)
            .map_err(|source| errno_error("inspect pinned store descriptor", path, source))?;
        validate_marker_stat(&pinned, path, expected_user_id)?;
        let bound = match statat(root, MARKER_NAME, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(stat) => stat,
            Err(rustix::io::Errno::NOENT) => {
                return Err(metadata_error(path, StoreMetadataIssue::ObservationChanged));
            }
            Err(source) => {
                return Err(errno_error(
                    "revalidate store descriptor binding",
                    path,
                    source,
                ));
            }
        };
        if !same_object(&pinned, &bound) {
            return Err(metadata_error(path, StoreMetadataIssue::ObservationChanged));
        }
        validate_marker_stat(&bound, path, expected_user_id)?;
        Ok(pinned)
    }

    fn root_is_empty(root: &File, root_path: &Path) -> Result<bool, EngineError> {
        root_entry_names(root, root_path).map(|names| names.is_empty())
    }

    fn marker_path(root_path: &Path) -> PathBuf {
        root_path.join(MARKER_NAME)
    }

    fn metadata_error(path: &Path, reason: StoreMetadataIssue) -> EngineError {
        EngineError::MalformedStoreMetadata {
            path: path.to_path_buf(),
            reason,
        }
    }

    #[cfg(test)]
    mod tests {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        use super::*;

        const VALID: &[u8] = include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../schemas/root/v1/fixtures/valid/descriptor.json"
        ));

        #[test]
        fn canonical_bytes_match_the_golden_fixture_and_schema() {
            assert_eq!(CANONICAL_DESCRIPTOR, VALID);
            parse_descriptor(VALID, Path::new("descriptor.json")).unwrap();

            let schema: serde_json::Value = serde_json::from_str(include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../schemas/root/v1/schema.json"
            )))
            .unwrap();
            assert_eq!(schema["additionalProperties"], false);
            assert_eq!(schema["properties"]["format"]["const"], "malm-state");
            assert_eq!(schema["properties"]["version"]["const"], 1);
            assert_eq!(schema["required"], serde_json::json!(["format", "version"]));
        }

        #[test]
        fn malformed_and_unsupported_fixtures_are_rejected() {
            for malformed in [
                include_bytes!(concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/../../schemas/root/v1/fixtures/malformed/missing-version.json"
                ))
                .as_slice(),
                include_bytes!(concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/../../schemas/root/v1/fixtures/malformed/unknown-field.json"
                ))
                .as_slice(),
                include_bytes!(concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/../../schemas/root/v1/fixtures/malformed/duplicate-version.json"
                ))
                .as_slice(),
                include_bytes!(concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/../../schemas/root/v1/fixtures/malformed/wrong-version-type.json"
                ))
                .as_slice(),
                include_bytes!(concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/../../schemas/root/v1/fixtures/malformed/noncanonical-whitespace.json"
                ))
                .as_slice(),
            ] {
                assert!(matches!(
                    parse_descriptor(malformed, Path::new("descriptor.json")),
                    Err(EngineError::MalformedStoreMetadata { .. })
                ));
            }

            let unsupported = include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../schemas/root/v1/fixtures/unsupported/version.json"
            ));
            assert!(matches!(
                parse_descriptor(unsupported, Path::new("descriptor.json")),
                Err(EngineError::UnsupportedStoreVersion {
                    expected: 1,
                    found: 2,
                    ..
                })
            ));
        }

        #[test]
        fn publication_is_canonical_durable_and_no_replace() {
            let root = tempfile::tempdir().unwrap();
            let root_file = File::open(root.path()).unwrap();
            let expected_user_id = fstat(&root_file).unwrap().st_uid;
            let marker_path = root.path().join(MARKER_NAME);
            publish_with(&root_file, root.path(), expected_user_id, || {
                assert!(!marker_path.exists());
            })
            .unwrap();
            let first_metadata = std::fs::metadata(&marker_path).unwrap();

            assert_eq!(std::fs::read(&marker_path).unwrap(), CANONICAL_DESCRIPTOR);
            assert_eq!(first_metadata.mode() & 0o7777, 0o600);
            assert_eq!(first_metadata.nlink(), 1);
            assert_eq!(
                inspect(&root_file, root.path(), expected_user_id).unwrap(),
                MetadataState::Ready
            );

            publish(&root_file, root.path(), expected_user_id).unwrap();
            let second_metadata = std::fs::metadata(&marker_path).unwrap();
            assert_eq!(first_metadata.dev(), second_metadata.dev());
            assert_eq!(first_metadata.ino(), second_metadata.ino());
        }

        #[test]
        fn concurrent_winner_is_validated_and_never_replaced() {
            let root = tempfile::tempdir().unwrap();
            let root_file = File::open(root.path()).unwrap();
            let expected_user_id = fstat(&root_file).unwrap().st_uid;
            let marker_path = root.path().join(MARKER_NAME);
            let replacement = b"{\"schema_version\":1,\"unknown\":true}\n";

            let error = publish_with(&root_file, root.path(), expected_user_id, || {
                std::fs::write(&marker_path, replacement).unwrap();
                std::fs::set_permissions(&marker_path, std::fs::Permissions::from_mode(0o600))
                    .unwrap();
            })
            .unwrap_err();

            assert!(matches!(error, EngineError::MalformedStoreMetadata { .. }));
            assert_eq!(std::fs::read(&marker_path).unwrap(), replacement);
        }

        #[test]
        fn metadata_change_after_read_is_rejected() {
            let parent = tempfile::tempdir().unwrap();
            let root_path = parent.path().join("root");
            std::fs::create_dir(&root_path).unwrap();
            let marker_path = root_path.join(MARKER_NAME);
            let alias = parent.path().join("marker-alias");
            std::fs::write(&marker_path, CANONICAL_DESCRIPTOR).unwrap();
            std::fs::set_permissions(&marker_path, std::fs::Permissions::from_mode(0o600)).unwrap();
            let root = File::open(&root_path).unwrap();
            let expected_user_id = fstat(&root).unwrap().st_uid;

            let error = inspect_with(&root, &root_path, expected_user_id, || {
                std::fs::hard_link(&marker_path, &alias).unwrap();
            })
            .unwrap_err();

            assert!(matches!(
                error,
                EngineError::MalformedStoreMetadata {
                    reason: StoreMetadataIssue::MultipleLinks { links: 2 },
                    ..
                }
            ));
        }

        #[test]
        fn content_appearing_before_publication_is_not_blessed() {
            let root = tempfile::tempdir().unwrap();
            let root_file = File::open(root.path()).unwrap();
            let expected_user_id = fstat(&root_file).unwrap().st_uid;
            let unrelated = root.path().join("unrelated");

            let error = publish_with(&root_file, root.path(), expected_user_id, || {
                std::fs::write(&unrelated, b"do not bless").unwrap();
            })
            .unwrap_err();

            assert!(matches!(
                error,
                EngineError::MalformedStoreMetadata {
                    reason: StoreMetadataIssue::MarkerMissingWithOtherEntries,
                    ..
                }
            ));
            assert!(!root.path().join(MARKER_NAME).exists());
            assert_eq!(std::fs::read(unrelated).unwrap(), b"do not bless");
        }
    }
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    use super::*;

    #[test]
    fn injected_root_parent_aliases_are_rejected() {
        let error =
            EngineConfig::new("/tmp/state/other/../malm", StoreAccess::ReadOnly).unwrap_err();
        assert!(matches!(
            error,
            EngineConfigError::InvalidStateRoot(
                malm_root::RootPathError::InjectedRootParentComponent { .. }
            )
        ));
    }

    #[test]
    fn engine_uses_the_injected_root_contract_without_a_leaf_alias() {
        assert!(EngineConfig::new("/tmp/state/final-root", StoreAccess::ReadOnly).is_ok());
        for root in ["relative", "/", "/tmp/state/./root", "/tmp/state/root/"] {
            assert!(matches!(
                EngineConfig::new(root, StoreAccess::ReadOnly),
                Err(EngineConfigError::InvalidStateRoot(_))
            ));
        }
    }

    #[test]
    fn changed_root_binding_is_detected_from_pinned_identity() {
        let temp = tempfile::tempdir().unwrap();
        let state_parent = temp.path().join("state");
        std::fs::create_dir(&state_parent).unwrap();
        std::fs::set_permissions(&state_parent, std::fs::Permissions::from_mode(0o700)).unwrap();
        let state_root = state_parent.join("malm");
        let moved_root = state_parent.join("moved");
        let attacker = temp.path().join("attacker");
        std::fs::create_dir(&state_root).unwrap();
        std::fs::create_dir(&attacker).unwrap();

        let config = EngineConfig::from_state_home(&state_parent, StoreAccess::ReadWrite).unwrap();
        let parent_chain = PinnedDirectoryChain::open(config.state_parent()).unwrap();
        let parent = parent_chain.directory();
        let pinned = open_child_directory(
            parent,
            config.state_leaf(),
            config.state_root(),
            "test open",
        )
        .unwrap()
        .unwrap();
        std::fs::rename(&state_root, &moved_root).unwrap();
        std::os::unix::fs::symlink(&attacker, &state_root).unwrap();

        let error =
            ensure_bound(parent, config.state_leaf(), &pinned, config.state_root()).unwrap_err();
        assert!(matches!(error, EngineError::RootObservationChanged { .. }));
    }

    #[test]
    fn replacement_between_create_and_open_is_not_modified() {
        let temp = tempfile::tempdir().unwrap();
        let state_parent = temp.path().join("state");
        let attacker = temp.path().join("attacker");
        let sentinel = attacker.join("sentinel");
        std::fs::create_dir(&state_parent).unwrap();
        std::fs::set_permissions(&state_parent, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::create_dir(&attacker).unwrap();
        std::fs::set_permissions(&attacker, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::write(&sentinel, b"unrelated").unwrap();
        let engine = Engine::new(
            EngineConfig::from_state_home(&state_parent, StoreAccess::ReadWrite).unwrap(),
            EnginePorts::system(),
        );
        let state_root = state_parent.join("malm");
        let displaced = state_parent.join("displaced");
        let replacement_metadata = RefCell::new(None);

        let error = engine
            .initialize_store_with(|| {
                std::fs::rename(&state_root, &displaced).unwrap();
                std::fs::rename(&attacker, &state_root).unwrap();
                replacement_metadata.replace(Some(std::fs::metadata(&state_root).unwrap()));
            })
            .unwrap_err();

        assert!(matches!(error, EngineError::RootObservationChanged { .. }));
        assert_eq!(
            std::fs::read(state_root.join("sentinel")).unwrap(),
            b"unrelated"
        );
        assert!(!state_root.join(store::MARKER_NAME).exists());
        let before = replacement_metadata.into_inner().unwrap();
        let after = std::fs::metadata(&state_root).unwrap();
        assert_eq!(before.mode(), after.mode());
        assert_eq!(before.mtime(), after.mtime());
        assert_eq!(before.mtime_nsec(), after.mtime_nsec());
        assert_eq!(before.ctime(), after.ctime());
        assert_eq!(before.ctime_nsec(), after.ctime_nsec());
    }

    #[test]
    fn renamed_state_parent_invalidates_initialization_postcondition() {
        let temp = tempfile::tempdir().unwrap();
        let state_parent = temp.path().join("state");
        let moved_parent = temp.path().join("moved-state");
        std::fs::create_dir(&state_parent).unwrap();
        std::fs::set_permissions(&state_parent, std::fs::Permissions::from_mode(0o700)).unwrap();
        let engine = Engine::new(
            EngineConfig::from_state_home(&state_parent, StoreAccess::ReadWrite).unwrap(),
            EnginePorts::system(),
        );

        let error = engine
            .initialize_store_with(|| {
                std::fs::rename(&state_parent, &moved_parent).unwrap();
                std::fs::create_dir(&state_parent).unwrap();
                std::fs::set_permissions(&state_parent, std::fs::Permissions::from_mode(0o700))
                    .unwrap();
            })
            .unwrap_err();

        assert!(matches!(
            error,
            EngineError::StateParentObservationChanged { .. }
        ));
        assert!(!state_parent.join("malm").exists());
        assert!(moved_parent.join("malm").is_dir());
    }

    #[test]
    fn application_roots_cannot_cross_mount_points() {
        let filesystem_root = File::from(open("/", DIRECTORY_FLAGS, Mode::empty()).unwrap());
        let error = open_child_directory(
            &filesystem_root,
            OsStr::new("proc"),
            Path::new("/proc"),
            "test mount crossing",
        )
        .unwrap_err();
        let EngineError::Io { source, .. } = error else {
            panic!("expected mount crossing to fail with an I/O error");
        };
        assert_eq!(source.raw_os_error(), Some(libc::EXDEV));
    }

    #[test]
    fn private_store_failures_map_exhaustively_to_stable_dtos() {
        for (status, expected) in [
            (StoreStatus::Absent, StoreStatusV1::Absent),
            (StoreStatus::Uninitialized, StoreStatusV1::Uninitialized),
            (StoreStatus::Ready, StoreStatusV1::Ready),
        ] {
            assert_eq!(store_status_v1(status), expected);
        }
        for (directory, expected) in [
            (StateDirectory::StateParent, StoreDirectoryV1::StateParent),
            (StateDirectory::V1Root, StoreDirectoryV1::V1Root),
        ] {
            assert_eq!(store_directory_v1(directory), expected);
        }
        for (reason, expected) in [
            (
                DirectorySafetyIssue::WrongOwner {
                    expected_uid: 1,
                    actual_uid: 2,
                },
                DirectorySafetyReasonV1::WrongOwner,
            ),
            (
                DirectorySafetyIssue::GroupOrOtherWritable { mode: 0o777 },
                DirectorySafetyReasonV1::GroupOrOtherWritable,
            ),
            (
                DirectorySafetyIssue::SpecialModeBitsSet { mode: 0o1700 },
                DirectorySafetyReasonV1::SpecialModeBitsSet,
            ),
            (
                DirectorySafetyIssue::UnexpectedMode {
                    expected: 0o700,
                    actual: 0o755,
                },
                DirectorySafetyReasonV1::UnexpectedMode,
            ),
            (
                DirectorySafetyIssue::AncestryLimitExceeded { limit: 64 },
                DirectorySafetyReasonV1::AncestryLimitExceeded,
            ),
        ] {
            assert_eq!(directory_safety_reason_v1(reason), expected);
        }
        for (reason, expected) in [
            (
                StoreMetadataIssue::MarkerMissingWithOtherEntries,
                StoreMetadataReasonV1::MarkerMissingWithOtherEntries,
            ),
            (
                StoreMetadataIssue::MarkerNotRegular,
                StoreMetadataReasonV1::MarkerNotRegular,
            ),
            (
                StoreMetadataIssue::MarkerTooLarge {
                    limit: 4_096,
                    actual: 4_097,
                },
                StoreMetadataReasonV1::MarkerTooLarge,
            ),
            (
                StoreMetadataIssue::UnexpectedRootEntry,
                StoreMetadataReasonV1::UnexpectedRootEntry,
            ),
            (
                StoreMetadataIssue::InvalidRootEntry {
                    detail: "private metadata detail".to_owned(),
                },
                StoreMetadataReasonV1::InvalidRootEntry,
            ),
            (
                StoreMetadataIssue::WrongOwner {
                    expected_uid: 1,
                    actual_uid: 2,
                },
                StoreMetadataReasonV1::WrongOwner,
            ),
            (
                StoreMetadataIssue::UnexpectedMode { actual: 0o644 },
                StoreMetadataReasonV1::UnexpectedMode,
            ),
            (
                StoreMetadataIssue::MultipleLinks { links: 2 },
                StoreMetadataReasonV1::MultipleLinks,
            ),
            (
                StoreMetadataIssue::ObservationChanged,
                StoreMetadataReasonV1::ObservationChanged,
            ),
            (
                StoreMetadataIssue::InvalidDescriptor {
                    detail: "private parser detail".to_owned(),
                },
                StoreMetadataReasonV1::InvalidDescriptor,
            ),
        ] {
            assert_eq!(store_metadata_reason_v1(&reason), expected);
        }

        let path = PathBuf::from("/private/not-serialized");
        let mappings = [
            (EngineError::ReadOnlyStore, StoreErrorV1::read_only_store()),
            (
                EngineError::StoreNotReady {
                    status: StoreStatus::Absent,
                },
                StoreErrorV1::store_not_ready(StoreStatusV1::Absent).unwrap(),
            ),
            (
                EngineError::StateParentMissing { path: path.clone() },
                StoreErrorV1::state_parent_missing(),
            ),
            (
                EngineError::UnsafeDirectory {
                    directory: StateDirectory::V1Root,
                    path: path.clone(),
                    reason: DirectorySafetyIssue::UnexpectedMode {
                        expected: 0o700,
                        actual: 0o755,
                    },
                },
                StoreErrorV1::unsafe_directory(
                    StoreDirectoryV1::V1Root,
                    DirectorySafetyReasonV1::UnexpectedMode,
                ),
            ),
            (
                EngineError::RootObservationChanged { path: path.clone() },
                StoreErrorV1::root_observation_changed(StoreRootV1::V1),
            ),
            (
                EngineError::StateParentObservationChanged { path: path.clone() },
                StoreErrorV1::state_parent_observation_changed(),
            ),
            (
                EngineError::MalformedStoreMetadata {
                    path: path.clone(),
                    reason: StoreMetadataIssue::InvalidDescriptor {
                        detail: "private parser detail".to_owned(),
                    },
                },
                StoreErrorV1::malformed_store_metadata(StoreMetadataReasonV1::InvalidDescriptor),
            ),
            (
                EngineError::UnsupportedStoreVersion {
                    path: path.clone(),
                    expected: 1,
                    found: 2,
                },
                StoreErrorV1::unsupported_store_version(1, 2).unwrap(),
            ),
            (
                EngineError::Io {
                    operation: "private operation",
                    path: path.clone(),
                    source: io::Error::new(io::ErrorKind::PermissionDenied, "private OS detail"),
                },
                StoreErrorV1::io(),
            ),
        ];
        for (private, stable) in mappings {
            assert_eq!(store_error_v1(private), stable);
        }

        assert_eq!(
            store_error_v1(EngineError::StoreNotReady {
                status: StoreStatus::Ready,
            }),
            StoreErrorV1::internal()
        );
        assert_eq!(
            store_error_v1(EngineError::UnsupportedStoreVersion {
                path: path.clone(),
                expected: 1,
                found: 1,
            }),
            StoreErrorV1::internal()
        );

        let digest = malm_types::Digest::sha256(b"private pack");
        assert_eq!(
            store_error_v1(EngineError::PackObject {
                digest,
                path: path.clone(),
                reason: PackObjectIssue::Missing,
            }),
            StoreErrorV1::internal()
        );
        assert_eq!(
            store_error_v1(EngineError::PackCapture {
                root: path.clone(),
                path: path.clone(),
                reason: PackCaptureIssue::SourceRootMissing,
            }),
            StoreErrorV1::internal()
        );

        let git_source = malm_pack::GitSourceV1::new(
            malm_pack::GitUrl::new("https://example.com/repository").unwrap(),
            malm_pack::GitObjectId::new(format!("sha1-{}", "0".repeat(40))).unwrap(),
            malm_pack::PackSubdir::new(".").unwrap(),
        );
        assert_eq!(
            store_error_v1(EngineError::GitAcquisition {
                git_source: Box::new(git_source),
                scratch_root: path,
                reason: GitAcquisitionIssue::ScratchRootMissing,
            }),
            StoreErrorV1::internal()
        );
    }
}
