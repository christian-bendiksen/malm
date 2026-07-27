//! Stable lifecycle, inspection, fsck, and status DTOs.

use crate::{
    ArchiveProvenanceV1, ArtifactDescriptorV1, ArtifactId, DeploymentName, Digest, NamespaceName,
    PrepareInputV1, PrepareTransformProvenanceV1, PreparedId, RetentionObjectV1,
};

/// Maximum predecessor records in one inspection request.
pub const MAX_HISTORY_GENERATIONS_V1: usize = 65_536;
/// Maximum decoded record bytes in one inspection request.
pub const MAX_INSPECTION_DECODED_BYTES_V1: u64 = 512 * 1024 * 1024;
/// Maximum logical values returned by one inspection request.
pub const MAX_INSPECTION_ITEMS_V1: usize = 65_536;
/// Maximum artifact bytes returned by one inspection request.
pub const MAX_INSPECTION_ARTIFACT_BYTES_V1: u64 = 256 * 1024 * 1024;
/// Maximum findings in one fsck report.
pub const MAX_FSCK_FINDINGS_V1: usize = 16_384;
/// Maximum reachable records and blobs traversed by fsck.
pub const MAX_FSCK_OBJECTS_V1: usize = 262_144;
/// Maximum decoded record and artifact bytes processed by fsck.
pub const MAX_FSCK_DECODED_BYTES_V1: u64 = 512 * 1024 * 1024;
/// Maximum managed targets observed by fsck.
pub const MAX_FSCK_TARGETS_V1: usize = 65_536;
/// Maximum managed-target bytes hashed by fsck.
pub const MAX_FSCK_OBSERVED_BYTES_V1: u64 = 512 * 1024 * 1024;
/// Maximum desired targets observed by one status request.
pub const MAX_STATUS_TARGETS_V1: usize = 65_536;
/// Maximum regular-file bytes hashed by one status request.
pub const MAX_STATUS_OBSERVED_BYTES_V1: u64 = 512 * 1024 * 1024;

/// Lifecycle state without store-record details.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LifecycleStateViewV1 {
    Enabled,
    Disabled,
}

/// Selects a namespace for a lifecycle transition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LifecycleRequestV1 {
    namespace: NamespaceName,
}

impl LifecycleRequestV1 {
    #[must_use]
    pub const fn new(namespace: NamespaceName) -> Self {
        Self { namespace }
    }

    #[must_use]
    pub const fn namespace(&self) -> &NamespaceName {
        &self.namespace
    }
}

impl std::borrow::Borrow<NamespaceName> for LifecycleRequestV1 {
    fn borrow(&self) -> &NamespaceName {
        self.namespace()
    }
}

/// Request used to prepare a disable transition.
pub type DisableRequestV1 = LifecycleRequestV1;
/// Request used to prepare an enable transition.
pub type EnableRequestV1 = LifecycleRequestV1;

/// Reviewed handling of namespace history during removal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NamespaceRemovalHistoryV1 {
    Drop,
}

/// Selects a namespace and history policy for removal.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NamespaceRemovalRequestV1 {
    namespace: NamespaceName,
    history: NamespaceRemovalHistoryV1,
}

impl NamespaceRemovalRequestV1 {
    #[must_use]
    pub const fn new(namespace: NamespaceName, history: NamespaceRemovalHistoryV1) -> Self {
        Self { namespace, history }
    }

    #[must_use]
    pub const fn namespace(&self) -> &NamespaceName {
        &self.namespace
    }
    #[must_use]
    pub const fn history(&self) -> NamespaceRemovalHistoryV1 {
        self.history
    }
}

/// Sets the predecessor history retained for a namespace.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HistoryRetentionRequestV1 {
    namespace: NamespaceName,
    generations: u32,
}

impl HistoryRetentionRequestV1 {
    pub fn new(namespace: NamespaceName, generations: u32) -> Result<Self, InspectionDtoError> {
        validate_byte_limit(
            "retained history generations",
            u64::from(generations),
            MAX_HISTORY_GENERATIONS_V1 as u64,
        )?;
        Ok(Self {
            namespace,
            generations,
        })
    }

    #[must_use]
    pub const fn namespace(&self) -> &NamespaceName {
        &self.namespace
    }
    #[must_use]
    pub const fn generations(&self) -> u32 {
        self.generations
    }
}

/// Adds or removes an explicit retention pin.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RetentionPinRequestV1 {
    namespace: NamespaceName,
    object: RetentionObjectV1,
}

impl RetentionPinRequestV1 {
    #[must_use]
    pub const fn new(namespace: NamespaceName, object: RetentionObjectV1) -> Self {
        Self { namespace, object }
    }

    #[must_use]
    pub const fn namespace(&self) -> &NamespaceName {
        &self.namespace
    }
    #[must_use]
    pub const fn object(&self) -> &RetentionObjectV1 {
        &self.object
    }
}

/// Adds or removes a generation-backed restore point.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RestorePointRequestV1 {
    namespace: NamespaceName,
    generation: Digest,
}

impl RestorePointRequestV1 {
    #[must_use]
    pub const fn new(namespace: NamespaceName, generation: Digest) -> Self {
        Self {
            namespace,
            generation,
        }
    }

    #[must_use]
    pub const fn namespace(&self) -> &NamespaceName {
        &self.namespace
    }
    #[must_use]
    pub const fn generation(&self) -> &Digest {
        &self.generation
    }
}

/// A bounded namespace-history request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NamespaceHistoryRequestV1 {
    namespace: NamespaceName,
    max_generations: usize,
    max_decoded_bytes: u64,
}

impl NamespaceHistoryRequestV1 {
    #[must_use]
    pub const fn new(namespace: NamespaceName) -> Self {
        Self {
            namespace,
            max_generations: MAX_HISTORY_GENERATIONS_V1,
            max_decoded_bytes: MAX_INSPECTION_DECODED_BYTES_V1,
        }
    }

    pub fn with_limits(
        namespace: NamespaceName,
        max_generations: usize,
        max_decoded_bytes: u64,
    ) -> Result<Self, InspectionDtoError> {
        validate_limit(
            "history generations",
            max_generations,
            MAX_HISTORY_GENERATIONS_V1,
        )?;
        validate_byte_limit(
            "history decoded bytes",
            max_decoded_bytes,
            MAX_INSPECTION_DECODED_BYTES_V1,
        )?;
        Ok(Self {
            namespace,
            max_generations,
            max_decoded_bytes,
        })
    }

    #[must_use]
    pub const fn namespace(&self) -> &NamespaceName {
        &self.namespace
    }
    #[must_use]
    pub const fn max_generations(&self) -> usize {
        self.max_generations
    }
    #[must_use]
    pub const fn max_decoded_bytes(&self) -> u64 {
        self.max_decoded_bytes
    }
}

/// Requests bounded generation IDs authorized by the selected retention authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GenerationInventoryRequestV1 {
    namespace: NamespaceName,
    limits: InspectionLimitsV1,
}

impl GenerationInventoryRequestV1 {
    #[must_use]
    pub const fn new(namespace: NamespaceName) -> Self {
        Self {
            namespace,
            limits: InspectionLimitsV1::new(),
        }
    }

    pub fn with_limits(
        namespace: NamespaceName,
        max_generations: usize,
        max_decoded_bytes: u64,
    ) -> Result<Self, InspectionDtoError> {
        Ok(Self {
            namespace,
            limits: InspectionLimitsV1::with_limits(max_generations, max_decoded_bytes)?,
        })
    }

    #[must_use]
    pub const fn namespace(&self) -> &NamespaceName {
        &self.namespace
    }
    #[must_use]
    pub const fn max_generations(&self) -> usize {
        self.limits.max_items
    }
    #[must_use]
    pub const fn max_decoded_bytes(&self) -> u64 {
        self.limits.max_decoded_bytes
    }
}

/// Requests bounded inspection of a generation and its complete predecessor chain.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GenerationInspectionRequestV1 {
    namespace: NamespaceName,
    generation: Digest,
    max_generations: usize,
    max_decoded_bytes: u64,
}

impl GenerationInspectionRequestV1 {
    #[must_use]
    pub const fn new(namespace: NamespaceName, generation: Digest) -> Self {
        Self {
            namespace,
            generation,
            max_generations: MAX_HISTORY_GENERATIONS_V1,
            max_decoded_bytes: MAX_INSPECTION_DECODED_BYTES_V1,
        }
    }

    pub fn with_limits(
        namespace: NamespaceName,
        generation: Digest,
        max_generations: usize,
        max_decoded_bytes: u64,
    ) -> Result<Self, InspectionDtoError> {
        let history =
            NamespaceHistoryRequestV1::with_limits(namespace, max_generations, max_decoded_bytes)?;
        Ok(Self {
            namespace: history.namespace,
            generation,
            max_generations,
            max_decoded_bytes,
        })
    }

    #[must_use]
    pub const fn namespace(&self) -> &NamespaceName {
        &self.namespace
    }
    #[must_use]
    pub const fn generation(&self) -> &Digest {
        &self.generation
    }
    #[must_use]
    pub const fn max_generations(&self) -> usize {
        self.max_generations
    }
    #[must_use]
    pub const fn max_decoded_bytes(&self) -> u64 {
        self.max_decoded_bytes
    }
}

/// Shared item and byte limits for inspection requests.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InspectionLimitsV1 {
    max_items: usize,
    max_decoded_bytes: u64,
}

impl InspectionLimitsV1 {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            max_items: MAX_INSPECTION_ITEMS_V1,
            max_decoded_bytes: MAX_INSPECTION_DECODED_BYTES_V1,
        }
    }

    pub fn with_limits(
        max_items: usize,
        max_decoded_bytes: u64,
    ) -> Result<Self, InspectionDtoError> {
        validate_limit("inspection items", max_items, MAX_INSPECTION_ITEMS_V1)?;
        validate_byte_limit(
            "inspection decoded bytes",
            max_decoded_bytes,
            MAX_INSPECTION_DECODED_BYTES_V1,
        )?;
        Ok(Self {
            max_items,
            max_decoded_bytes,
        })
    }

    #[must_use]
    pub const fn max_items(self) -> usize {
        self.max_items
    }
    #[must_use]
    pub const fn max_decoded_bytes(self) -> u64 {
        self.max_decoded_bytes
    }
}

impl Default for InspectionLimitsV1 {
    fn default() -> Self {
        Self::new()
    }
}

/// A specific immutable-object store domain available for inventory.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ObjectInventoryKindV1 {
    ArtifactBlob,
    PackObject,
    CanonicalFile,
    CanonicalSymlink,
    CanonicalTree,
}

/// Requests bounded IDs from one immutable-object domain.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ObjectInventoryRequestV1 {
    kind: ObjectInventoryKindV1,
    max_objects: usize,
}

impl ObjectInventoryRequestV1 {
    #[must_use]
    pub const fn new(kind: ObjectInventoryKindV1) -> Self {
        Self {
            kind,
            max_objects: MAX_INSPECTION_ITEMS_V1,
        }
    }

    pub fn with_limit(
        kind: ObjectInventoryKindV1,
        max_objects: usize,
    ) -> Result<Self, InspectionDtoError> {
        validate_limit(
            "object inventory entries",
            max_objects,
            MAX_INSPECTION_ITEMS_V1,
        )?;
        Ok(Self { kind, max_objects })
    }

    #[must_use]
    pub const fn kind(self) -> ObjectInventoryKindV1 {
        self.kind
    }
    #[must_use]
    pub const fn max_objects(self) -> usize {
        self.max_objects
    }
}

/// Generation IDs authorized by a namespace's selected authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GenerationInventoryV1 {
    namespace: NamespaceName,
    generations: Vec<Digest>,
    decoded_bytes: u64,
}

impl GenerationInventoryV1 {
    #[must_use]
    pub const fn new(
        namespace: NamespaceName,
        generations: Vec<Digest>,
        decoded_bytes: u64,
    ) -> Self {
        Self {
            namespace,
            generations,
            decoded_bytes,
        }
    }

    #[must_use]
    pub const fn namespace(&self) -> &NamespaceName {
        &self.namespace
    }
    #[must_use]
    pub fn generations(&self) -> &[Digest] {
        &self.generations
    }
    #[must_use]
    pub const fn decoded_bytes(&self) -> u64 {
        self.decoded_bytes
    }
}

/// Digest IDs in one immutable-object store domain.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObjectInventoryV1 {
    kind: ObjectInventoryKindV1,
    objects: Vec<Digest>,
}

impl ObjectInventoryV1 {
    #[must_use]
    pub const fn new(kind: ObjectInventoryKindV1, objects: Vec<Digest>) -> Self {
        Self { kind, objects }
    }

    #[must_use]
    pub const fn kind(&self) -> ObjectInventoryKindV1 {
        self.kind
    }
    #[must_use]
    pub fn objects(&self) -> &[Digest] {
        &self.objects
    }
}

/// Requests the complete selected namespace catalog within fixed limits.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CatalogInspectionRequestV1 {
    limits: InspectionLimitsV1,
}

impl CatalogInspectionRequestV1 {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            limits: InspectionLimitsV1::new(),
        }
    }

    pub fn with_limits(
        max_namespaces: usize,
        max_decoded_bytes: u64,
    ) -> Result<Self, InspectionDtoError> {
        Ok(Self {
            limits: InspectionLimitsV1::with_limits(max_namespaces, max_decoded_bytes)?,
        })
    }

    #[must_use]
    pub const fn max_namespaces(self) -> usize {
        self.limits.max_items
    }
    #[must_use]
    pub const fn max_decoded_bytes(self) -> u64 {
        self.limits.max_decoded_bytes
    }
}

impl Default for CatalogInspectionRequestV1 {
    fn default() -> Self {
        Self::new()
    }
}

/// A namespace head selected by the global catalog.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CatalogNamespaceInspectionV1 {
    namespace: NamespaceName,
    generation: Digest,
}

impl CatalogNamespaceInspectionV1 {
    #[must_use]
    pub const fn new(namespace: NamespaceName, generation: Digest) -> Self {
        Self {
            namespace,
            generation,
        }
    }

    #[must_use]
    pub const fn namespace(&self) -> &NamespaceName {
        &self.namespace
    }
    #[must_use]
    pub const fn generation(&self) -> &Digest {
        &self.generation
    }
}

/// A complete verified view of the global catalog.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CatalogInspectionV1 {
    digest: Digest,
    namespaces: Vec<CatalogNamespaceInspectionV1>,
    decoded_bytes: u64,
}

impl CatalogInspectionV1 {
    #[must_use]
    pub const fn new(
        digest: Digest,
        namespaces: Vec<CatalogNamespaceInspectionV1>,
        decoded_bytes: u64,
    ) -> Self {
        Self {
            digest,
            namespaces,
            decoded_bytes,
        }
    }

    #[must_use]
    pub const fn digest(&self) -> &Digest {
        &self.digest
    }
    #[must_use]
    pub fn namespaces(&self) -> &[CatalogNamespaceInspectionV1] {
        &self.namespaces
    }
    #[must_use]
    pub const fn decoded_bytes(&self) -> u64 {
        self.decoded_bytes
    }
}

/// Requests a catalog-selected namespace generation within a byte limit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NamespaceInspectionRequestV1 {
    namespace: NamespaceName,
    max_decoded_bytes: u64,
}

impl NamespaceInspectionRequestV1 {
    #[must_use]
    pub const fn new(namespace: NamespaceName) -> Self {
        Self {
            namespace,
            max_decoded_bytes: MAX_INSPECTION_DECODED_BYTES_V1,
        }
    }

    pub fn with_limit(
        namespace: NamespaceName,
        max_decoded_bytes: u64,
    ) -> Result<Self, InspectionDtoError> {
        validate_byte_limit(
            "namespace decoded bytes",
            max_decoded_bytes,
            MAX_INSPECTION_DECODED_BYTES_V1,
        )?;
        Ok(Self {
            namespace,
            max_decoded_bytes,
        })
    }

    #[must_use]
    pub const fn namespace(&self) -> &NamespaceName {
        &self.namespace
    }
    #[must_use]
    pub const fn max_decoded_bytes(&self) -> u64 {
        self.max_decoded_bytes
    }
}

/// Verified selected state for a namespace.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NamespaceInspectionV1 {
    namespace: NamespaceName,
    head: Option<Digest>,
    generation: Option<GenerationInspectionV1>,
    decoded_bytes: u64,
}

impl NamespaceInspectionV1 {
    #[must_use]
    pub const fn new(
        namespace: NamespaceName,
        head: Option<Digest>,
        generation: Option<GenerationInspectionV1>,
        decoded_bytes: u64,
    ) -> Self {
        Self {
            namespace,
            head,
            generation,
            decoded_bytes,
        }
    }

    #[must_use]
    pub const fn namespace(&self) -> &NamespaceName {
        &self.namespace
    }
    #[must_use]
    pub const fn head(&self) -> Option<&Digest> {
        self.head.as_ref()
    }
    #[must_use]
    pub const fn generation(&self) -> Option<&GenerationInspectionV1> {
        self.generation.as_ref()
    }
    #[must_use]
    pub const fn decoded_bytes(&self) -> u64 {
        self.decoded_bytes
    }
}

/// Requests a generation's complete cumulative snapshot within fixed limits.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DesiredSnapshotInspectionRequestV1 {
    namespace: NamespaceName,
    generation: Digest,
    limits: InspectionLimitsV1,
}

impl DesiredSnapshotInspectionRequestV1 {
    #[must_use]
    pub const fn new(namespace: NamespaceName, generation: Digest) -> Self {
        Self {
            namespace,
            generation,
            limits: InspectionLimitsV1::new(),
        }
    }

    pub fn with_limits(
        namespace: NamespaceName,
        generation: Digest,
        max_targets: usize,
        max_decoded_bytes: u64,
    ) -> Result<Self, InspectionDtoError> {
        Ok(Self {
            namespace,
            generation,
            limits: InspectionLimitsV1::with_limits(max_targets, max_decoded_bytes)?,
        })
    }

    #[must_use]
    pub const fn namespace(&self) -> &NamespaceName {
        &self.namespace
    }
    #[must_use]
    pub const fn generation(&self) -> &Digest {
        &self.generation
    }
    #[must_use]
    pub const fn max_targets(&self) -> usize {
        self.limits.max_items
    }
    #[must_use]
    pub const fn max_decoded_bytes(&self) -> u64 {
        self.limits.max_decoded_bytes
    }
}

/// A desired state from the closed set for a namespace target slot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DesiredTargetStateInspectionV1 {
    File {
        digest: Option<Digest>,
        byte_len: Option<u64>,
        mode: Option<u32>,
    },
    Directory {
        mode: Option<u32>,
    },
    Symlink {
        object: Option<Digest>,
    },
    Tree {
        tree: Option<Digest>,
        archive_provenance: Option<ArchiveProvenanceV1>,
    },
}

/// A path-redacted target in a cumulative desired snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DesiredTargetInspectionV1 {
    authority: DeploymentName,
    relative_path: String,
    state: DesiredTargetStateInspectionV1,
}

impl DesiredTargetInspectionV1 {
    #[must_use]
    pub fn new(
        authority: DeploymentName,
        relative_path: String,
        state: DesiredTargetStateInspectionV1,
    ) -> Self {
        Self {
            authority,
            relative_path,
            state,
        }
    }

    #[must_use]
    pub const fn authority(&self) -> &DeploymentName {
        &self.authority
    }
    #[must_use]
    pub fn relative_path(&self) -> &str {
        &self.relative_path
    }
    #[must_use]
    pub const fn state(&self) -> &DesiredTargetStateInspectionV1 {
        &self.state
    }
}

/// A complete verified cumulative desired snapshot for one generation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DesiredSnapshotInspectionV1 {
    namespace: NamespaceName,
    generation: Digest,
    digest: Digest,
    targets: Vec<DesiredTargetInspectionV1>,
    decoded_bytes: u64,
}

impl DesiredSnapshotInspectionV1 {
    #[must_use]
    pub const fn new(
        namespace: NamespaceName,
        generation: Digest,
        digest: Digest,
        targets: Vec<DesiredTargetInspectionV1>,
        decoded_bytes: u64,
    ) -> Self {
        Self {
            namespace,
            generation,
            digest,
            targets,
            decoded_bytes,
        }
    }

    #[must_use]
    pub const fn namespace(&self) -> &NamespaceName {
        &self.namespace
    }
    #[must_use]
    pub const fn generation(&self) -> &Digest {
        &self.generation
    }
    #[must_use]
    pub const fn digest(&self) -> &Digest {
        &self.digest
    }
    #[must_use]
    pub fn targets(&self) -> &[DesiredTargetInspectionV1] {
        &self.targets
    }
    #[must_use]
    pub const fn decoded_bytes(&self) -> u64 {
        self.decoded_bytes
    }
}

/// Requests bounded recursive inspection of a canonical tree graph.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CanonicalTreeInspectionRequestV1 {
    tree: Digest,
    limits: InspectionLimitsV1,
}

impl CanonicalTreeInspectionRequestV1 {
    #[must_use]
    pub const fn new(tree: Digest) -> Self {
        Self {
            tree,
            limits: InspectionLimitsV1::new(),
        }
    }

    pub fn with_limits(
        tree: Digest,
        max_entries: usize,
        max_decoded_bytes: u64,
    ) -> Result<Self, InspectionDtoError> {
        Ok(Self {
            tree,
            limits: InspectionLimitsV1::with_limits(max_entries, max_decoded_bytes)?,
        })
    }

    #[must_use]
    pub const fn tree(&self) -> &Digest {
        &self.tree
    }
    #[must_use]
    pub const fn max_entries(&self) -> usize {
        self.limits.max_items
    }
    #[must_use]
    pub const fn max_decoded_bytes(&self) -> u64 {
        self.limits.max_decoded_bytes
    }
}

/// An object kind from the closed set for a canonical tree entry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CanonicalTreeEntryKindInspectionV1 {
    File { digest: Digest, byte_len: u64 },
    Directory { digest: Digest },
    Symlink { digest: Digest },
}

/// A fully qualified entry in an expanded canonical tree.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CanonicalTreeEntryInspectionV1 {
    relative_path: String,
    mode: u32,
    kind: CanonicalTreeEntryKindInspectionV1,
}

impl CanonicalTreeEntryInspectionV1 {
    #[must_use]
    pub fn new(relative_path: String, mode: u32, kind: CanonicalTreeEntryKindInspectionV1) -> Self {
        Self {
            relative_path,
            mode,
            kind,
        }
    }

    #[must_use]
    pub fn relative_path(&self) -> &str {
        &self.relative_path
    }
    #[must_use]
    pub const fn mode(&self) -> u32 {
        self.mode
    }
    #[must_use]
    pub const fn kind(&self) -> &CanonicalTreeEntryKindInspectionV1 {
        &self.kind
    }
}

/// A complete recursively verified canonical tree view.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CanonicalTreeInspectionV1 {
    tree: Digest,
    root_mode: u32,
    entries: Vec<CanonicalTreeEntryInspectionV1>,
    decoded_bytes: u64,
}

impl CanonicalTreeInspectionV1 {
    #[must_use]
    pub const fn new(
        tree: Digest,
        root_mode: u32,
        entries: Vec<CanonicalTreeEntryInspectionV1>,
        decoded_bytes: u64,
    ) -> Self {
        Self {
            tree,
            root_mode,
            entries,
            decoded_bytes,
        }
    }

    #[must_use]
    pub const fn tree(&self) -> &Digest {
        &self.tree
    }
    #[must_use]
    pub const fn root_mode(&self) -> u32 {
        self.root_mode
    }
    #[must_use]
    pub fn entries(&self) -> &[CanonicalTreeEntryInspectionV1] {
        &self.entries
    }
    #[must_use]
    pub const fn decoded_bytes(&self) -> u64 {
        self.decoded_bytes
    }
}

/// Requests a durable prepared plan within item and byte limits.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreparedPlanInspectionRequestV1 {
    plan_id: PreparedId,
    limits: InspectionLimitsV1,
}

impl PreparedPlanInspectionRequestV1 {
    #[must_use]
    pub const fn new(plan_id: PreparedId) -> Self {
        Self {
            plan_id,
            limits: InspectionLimitsV1::new(),
        }
    }

    pub fn with_limits(
        plan_id: PreparedId,
        max_items: usize,
        max_decoded_bytes: u64,
    ) -> Result<Self, InspectionDtoError> {
        Ok(Self {
            plan_id,
            limits: InspectionLimitsV1::with_limits(max_items, max_decoded_bytes)?,
        })
    }

    #[must_use]
    pub const fn plan_id(&self) -> &PreparedId {
        &self.plan_id
    }
    #[must_use]
    pub const fn max_items(&self) -> usize {
        self.limits.max_items
    }
    #[must_use]
    pub const fn max_decoded_bytes(&self) -> u64 {
        self.limits.max_decoded_bytes
    }
}

/// Selects verified artifact metadata from a durable plan within a byte limit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArtifactMetadataInspectionRequestV1 {
    plan_id: PreparedId,
    artifact_id: ArtifactId,
    max_decoded_bytes: u64,
}

impl ArtifactMetadataInspectionRequestV1 {
    #[must_use]
    pub const fn new(plan_id: PreparedId, artifact_id: ArtifactId) -> Self {
        Self {
            plan_id,
            artifact_id,
            max_decoded_bytes: MAX_INSPECTION_DECODED_BYTES_V1,
        }
    }

    pub fn with_limit(
        plan_id: PreparedId,
        artifact_id: ArtifactId,
        max_decoded_bytes: u64,
    ) -> Result<Self, InspectionDtoError> {
        validate_byte_limit(
            "artifact metadata decoded bytes",
            max_decoded_bytes,
            MAX_INSPECTION_DECODED_BYTES_V1,
        )?;
        Ok(Self {
            plan_id,
            artifact_id,
            max_decoded_bytes,
        })
    }

    #[must_use]
    pub const fn plan_id(&self) -> &PreparedId {
        &self.plan_id
    }
    #[must_use]
    pub const fn artifact_id(&self) -> &ArtifactId {
        &self.artifact_id
    }
    #[must_use]
    pub const fn max_decoded_bytes(&self) -> u64 {
        self.max_decoded_bytes
    }
}

/// Selects bounded artifact bytes from a durable plan.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArtifactBytesInspectionRequestV1 {
    plan_id: PreparedId,
    artifact_id: ArtifactId,
    max_artifact_bytes: u64,
}

impl ArtifactBytesInspectionRequestV1 {
    #[must_use]
    pub const fn new(plan_id: PreparedId, artifact_id: ArtifactId) -> Self {
        Self {
            plan_id,
            artifact_id,
            max_artifact_bytes: MAX_INSPECTION_ARTIFACT_BYTES_V1,
        }
    }

    pub fn with_limit(
        plan_id: PreparedId,
        artifact_id: ArtifactId,
        max_artifact_bytes: u64,
    ) -> Result<Self, InspectionDtoError> {
        validate_byte_limit(
            "artifact bytes",
            max_artifact_bytes,
            MAX_INSPECTION_ARTIFACT_BYTES_V1,
        )?;
        Ok(Self {
            plan_id,
            artifact_id,
            max_artifact_bytes,
        })
    }

    #[must_use]
    pub const fn plan_id(&self) -> &PreparedId {
        &self.plan_id
    }
    #[must_use]
    pub const fn artifact_id(&self) -> &ArtifactId {
        &self.artifact_id
    }
    #[must_use]
    pub const fn max_artifact_bytes(&self) -> u64 {
        self.max_artifact_bytes
    }
}

/// Verified artifact metadata without the artifact bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArtifactMetadataInspectionV1 {
    plan_id: PreparedId,
    descriptor: ArtifactDescriptorV1,
    decoded_bytes: u64,
}

impl ArtifactMetadataInspectionV1 {
    #[must_use]
    pub const fn new(
        plan_id: PreparedId,
        descriptor: ArtifactDescriptorV1,
        decoded_bytes: u64,
    ) -> Self {
        Self {
            plan_id,
            descriptor,
            decoded_bytes,
        }
    }

    #[must_use]
    pub const fn plan_id(&self) -> &PreparedId {
        &self.plan_id
    }
    #[must_use]
    pub const fn descriptor(&self) -> &ArtifactDescriptorV1 {
        &self.descriptor
    }
    #[must_use]
    pub const fn decoded_bytes(&self) -> u64 {
        self.decoded_bytes
    }
}

/// Exact captured source, config, component, and asset inputs for a durable plan.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CapturedInputsInspectionV1 {
    plan_id: PreparedId,
    graph_digest: Digest,
    inputs: Vec<PrepareInputV1>,
    decoded_bytes: u64,
}

impl CapturedInputsInspectionV1 {
    #[must_use]
    pub const fn new(
        plan_id: PreparedId,
        graph_digest: Digest,
        inputs: Vec<PrepareInputV1>,
        decoded_bytes: u64,
    ) -> Self {
        Self {
            plan_id,
            graph_digest,
            inputs,
            decoded_bytes,
        }
    }

    #[must_use]
    pub const fn plan_id(&self) -> &PreparedId {
        &self.plan_id
    }
    #[must_use]
    pub const fn graph_digest(&self) -> &Digest {
        &self.graph_digest
    }
    #[must_use]
    pub fn inputs(&self) -> &[PrepareInputV1] {
        &self.inputs
    }
    #[must_use]
    pub const fn decoded_bytes(&self) -> u64 {
        self.decoded_bytes
    }
}

/// Complete deterministic transform provenance for a durable plan.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransformProvenanceInspectionV1 {
    plan_id: PreparedId,
    transforms: Vec<PrepareTransformProvenanceV1>,
    decoded_bytes: u64,
}

impl TransformProvenanceInspectionV1 {
    #[must_use]
    pub const fn new(
        plan_id: PreparedId,
        transforms: Vec<PrepareTransformProvenanceV1>,
        decoded_bytes: u64,
    ) -> Self {
        Self {
            plan_id,
            transforms,
            decoded_bytes,
        }
    }

    #[must_use]
    pub const fn plan_id(&self) -> &PreparedId {
        &self.plan_id
    }
    #[must_use]
    pub fn transforms(&self) -> &[PrepareTransformProvenanceV1] {
        &self.transforms
    }
    #[must_use]
    pub const fn decoded_bytes(&self) -> u64 {
        self.decoded_bytes
    }
}

/// Tracked-root state without source locators, config paths, or grants.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrackedRootInspectionV1 {
    moving_selector: String,
    applied_revision: String,
    root_tree_digest: Digest,
}

/// An exact immutable restore point without paths or grants.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RestorePointInspectionV1 {
    generation: Digest,
    lifecycle: LifecycleStateViewV1,
    desired_snapshot_digest: Digest,
    tracked_root: Option<TrackedRootInspectionV1>,
}

impl RestorePointInspectionV1 {
    #[must_use]
    pub const fn new(
        generation: Digest,
        lifecycle: LifecycleStateViewV1,
        desired_snapshot_digest: Digest,
        tracked_root: Option<TrackedRootInspectionV1>,
    ) -> Self {
        Self {
            generation,
            lifecycle,
            desired_snapshot_digest,
            tracked_root,
        }
    }

    #[must_use]
    pub const fn generation(&self) -> &Digest {
        &self.generation
    }
    #[must_use]
    pub const fn lifecycle(&self) -> LifecycleStateViewV1 {
        self.lifecycle
    }
    #[must_use]
    pub const fn desired_snapshot_digest(&self) -> &Digest {
        &self.desired_snapshot_digest
    }
    #[must_use]
    pub const fn tracked_root(&self) -> Option<&TrackedRootInspectionV1> {
        self.tracked_root.as_ref()
    }
}

/// A semantic transition from the closed set shown during review and inspection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LifecycleTransitionViewV1 {
    Reconcile,
    Disable,
    Enable { restore_generation: Digest },
    Checkout { source_generation: Digest },
    RetentionAuthority,
    NamespaceRemoval { drops_history: bool },
}

/// A complete semantic view of namespace retention authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RetentionAuthorityInspectionV1 {
    history_generations: u32,
    restore_points: Vec<RestorePointInspectionV1>,
    explicit_pins: Vec<RetentionObjectV1>,
}

impl RetentionAuthorityInspectionV1 {
    #[must_use]
    pub const fn new(
        history_generations: u32,
        restore_points: Vec<RestorePointInspectionV1>,
        explicit_pins: Vec<RetentionObjectV1>,
    ) -> Self {
        Self {
            history_generations,
            restore_points,
            explicit_pins,
        }
    }

    #[must_use]
    pub const fn history_generations(&self) -> u32 {
        self.history_generations
    }
    #[must_use]
    pub fn restore_points(&self) -> &[RestorePointInspectionV1] {
        &self.restore_points
    }
    #[must_use]
    pub fn explicit_pins(&self) -> &[RetentionObjectV1] {
        &self.explicit_pins
    }
}

impl TrackedRootInspectionV1 {
    #[must_use]
    pub fn new(
        moving_selector: String,
        applied_revision: String,
        root_tree_digest: Digest,
    ) -> Self {
        Self {
            moving_selector,
            applied_revision,
            root_tree_digest,
        }
    }

    #[must_use]
    pub fn moving_selector(&self) -> &str {
        &self.moving_selector
    }
    #[must_use]
    pub fn applied_revision(&self) -> &str {
        &self.applied_revision
    }
    #[must_use]
    pub const fn root_tree_digest(&self) -> &Digest {
        &self.root_tree_digest
    }
}

/// A verified semantic view of one immutable namespace generation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GenerationInspectionV1 {
    namespace: NamespaceName,
    generation: Digest,
    lifecycle: LifecycleStateViewV1,
    desired_snapshot_digest: Digest,
    target_count: u64,
    present_target_count: u64,
    absent_target_count: u64,
    plan_id: PreparedId,
    predecessor: Option<Digest>,
    tracked_root: Option<TrackedRootInspectionV1>,
    transition: LifecycleTransitionViewV1,
    restore_point: Option<RestorePointInspectionV1>,
    retention: RetentionAuthorityInspectionV1,
}

/// Named fields used to construct a [`GenerationInspectionV1`].
///
/// The three target counters are named here so values with the same type cannot
/// be transposed silently. Conversion initializes transition, restore point,
/// and retention to the defaults replaced by
/// [`GenerationInspectionV1::with_authority`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GenerationInspectionPartsV1 {
    pub namespace: NamespaceName,
    pub generation: Digest,
    pub lifecycle: LifecycleStateViewV1,
    pub desired_snapshot_digest: Digest,
    pub target_count: u64,
    pub present_target_count: u64,
    pub absent_target_count: u64,
    pub plan_id: PreparedId,
    pub predecessor: Option<Digest>,
    pub tracked_root: Option<TrackedRootInspectionV1>,
}

impl From<GenerationInspectionPartsV1> for GenerationInspectionV1 {
    fn from(parts: GenerationInspectionPartsV1) -> Self {
        Self {
            namespace: parts.namespace,
            generation: parts.generation,
            lifecycle: parts.lifecycle,
            desired_snapshot_digest: parts.desired_snapshot_digest,
            target_count: parts.target_count,
            present_target_count: parts.present_target_count,
            absent_target_count: parts.absent_target_count,
            plan_id: parts.plan_id,
            predecessor: parts.predecessor,
            tracked_root: parts.tracked_root,
            transition: LifecycleTransitionViewV1::Reconcile,
            restore_point: None,
            retention: RetentionAuthorityInspectionV1::new(256, vec![], vec![]),
        }
    }
}

impl GenerationInspectionV1 {
    #[must_use]
    pub fn with_authority(
        mut self,
        transition: LifecycleTransitionViewV1,
        restore_point: Option<RestorePointInspectionV1>,
        retention: RetentionAuthorityInspectionV1,
    ) -> Self {
        self.transition = transition;
        self.restore_point = restore_point;
        self.retention = retention;
        self
    }

    #[must_use]
    pub const fn namespace(&self) -> &NamespaceName {
        &self.namespace
    }
    #[must_use]
    pub const fn generation(&self) -> &Digest {
        &self.generation
    }
    #[must_use]
    pub const fn lifecycle(&self) -> LifecycleStateViewV1 {
        self.lifecycle
    }
    #[must_use]
    pub const fn desired_snapshot_digest(&self) -> &Digest {
        &self.desired_snapshot_digest
    }
    #[must_use]
    pub const fn target_count(&self) -> u64 {
        self.target_count
    }
    #[must_use]
    pub const fn present_target_count(&self) -> u64 {
        self.present_target_count
    }
    #[must_use]
    pub const fn absent_target_count(&self) -> u64 {
        self.absent_target_count
    }
    #[must_use]
    pub const fn plan_id(&self) -> &PreparedId {
        &self.plan_id
    }
    #[must_use]
    pub const fn predecessor(&self) -> Option<&Digest> {
        self.predecessor.as_ref()
    }
    #[must_use]
    pub const fn tracked_root(&self) -> Option<&TrackedRootInspectionV1> {
        self.tracked_root.as_ref()
    }
    #[must_use]
    pub const fn transition(&self) -> &LifecycleTransitionViewV1 {
        &self.transition
    }
    #[must_use]
    pub const fn restore_point(&self) -> Option<&RestorePointInspectionV1> {
        self.restore_point.as_ref()
    }
    #[must_use]
    pub const fn retention_authority(&self) -> &RetentionAuthorityInspectionV1 {
        &self.retention
    }
}

/// Exact retention authority selected by a verified namespace generation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RetentionInspectionV1 {
    namespace: NamespaceName,
    generation: Digest,
    authority: RetentionAuthorityInspectionV1,
}

impl RetentionInspectionV1 {
    #[must_use]
    pub const fn new(
        namespace: NamespaceName,
        generation: Digest,
        authority: RetentionAuthorityInspectionV1,
    ) -> Self {
        Self {
            namespace,
            generation,
            authority,
        }
    }

    #[must_use]
    pub const fn namespace(&self) -> &NamespaceName {
        &self.namespace
    }
    #[must_use]
    pub const fn generation(&self) -> &Digest {
        &self.generation
    }
    #[must_use]
    pub const fn authority(&self) -> &RetentionAuthorityInspectionV1 {
        &self.authority
    }
}

/// Redacted tracking authority selected by a verified namespace generation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrackingInspectionV1 {
    namespace: NamespaceName,
    generation: Digest,
    tracked_root: Option<TrackedRootInspectionV1>,
}

impl TrackingInspectionV1 {
    #[must_use]
    pub const fn new(
        namespace: NamespaceName,
        generation: Digest,
        tracked_root: Option<TrackedRootInspectionV1>,
    ) -> Self {
        Self {
            namespace,
            generation,
            tracked_root,
        }
    }

    #[must_use]
    pub const fn namespace(&self) -> &NamespaceName {
        &self.namespace
    }
    #[must_use]
    pub const fn generation(&self) -> &Digest {
        &self.generation
    }
    #[must_use]
    pub const fn tracked_root(&self) -> Option<&TrackedRootInspectionV1> {
        self.tracked_root.as_ref()
    }
}

/// A complete verified predecessor chain ordered newest first.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NamespaceHistoryV1 {
    namespace: NamespaceName,
    head: Option<Digest>,
    generations: Vec<GenerationInspectionV1>,
    decoded_bytes: u64,
}

impl NamespaceHistoryV1 {
    #[must_use]
    pub fn new(
        namespace: NamespaceName,
        head: Option<Digest>,
        generations: Vec<GenerationInspectionV1>,
        decoded_bytes: u64,
    ) -> Self {
        Self {
            namespace,
            head,
            generations,
            decoded_bytes,
        }
    }

    #[must_use]
    pub const fn namespace(&self) -> &NamespaceName {
        &self.namespace
    }
    #[must_use]
    pub const fn head(&self) -> Option<&Digest> {
        self.head.as_ref()
    }
    #[must_use]
    pub fn generations(&self) -> &[GenerationInspectionV1] {
        &self.generations
    }
    #[must_use]
    pub const fn decoded_bytes(&self) -> u64 {
        self.decoded_bytes
    }
}

/// The path-free subject of an fsck finding.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FsckSubjectV1 {
    StoreDescriptor,
    TransactionLock,
    MaintenanceLock,
    Journal,
    JournalStaging,
    Catalog,
    CatalogStaging,
    Namespace(NamespaceName),
    Generation(Digest),
    PreparedPlan(PreparedId),
    ArtifactBlob(Digest),
    PackObject(Digest),
    CanonicalFile(Digest),
    CanonicalSymlink(Digest),
    CanonicalTree(Digest),
    Target {
        authority: DeploymentName,
        relative_path: String,
    },
    StoreArea(FsckStoreAreaV1),
    Retention,
    Ownership,
    Coverage,
}

/// Store area used when a malformed name has no valid object ID.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FsckStoreAreaV1 {
    Root,
    State,
    Generations,
    Prepared,
    Transactions,
    Objects,
    ArtifactBlobs,
    PackObjects,
    CanonicalFiles,
    CanonicalSymlinks,
    CanonicalTrees,
}

/// The stable logical class of an fsck finding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FsckFindingCodeV1 {
    InvalidDescriptor,
    RecoveryRequired,
    InvalidJournal,
    MissingCatalog,
    InvalidCatalog,
    MissingGeneration,
    InvalidGeneration,
    CyclicHistory,
    CrossNamespaceHistory,
    SharedGeneration,
    MissingPreparedPlan,
    InvalidPreparedPlan,
    InvalidPreparedTransition,
    MissingArtifactBlob,
    CorruptArtifactBlob,
    ArtifactLengthMismatch,
    MissingPackObject,
    CorruptPackObject,
    MissingCanonicalObject,
    CorruptCanonicalObject,
    InvalidLockMetadata,
    InvalidStaging,
    MalformedStoreEntry,
    UnreachableImmutableObject,
    TargetDrift,
    TargetObservationFailed,
    AuthorityChanged,
    InvalidOwnership,
    TraversalLimitExceeded,
    DecodedByteLimitExceeded,
    FindingLimitExceeded,
}

/// The severity of an fsck finding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FsckSeverityV1 {
    Error,
    Warning,
}

/// A structured fsck finding without host paths.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FsckFindingV1 {
    code: FsckFindingCodeV1,
    severity: FsckSeverityV1,
    subject: FsckSubjectV1,
    detail: String,
}

impl FsckFindingV1 {
    #[must_use]
    pub fn new(
        code: FsckFindingCodeV1,
        severity: FsckSeverityV1,
        subject: FsckSubjectV1,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            code,
            severity,
            subject,
            detail: detail.into(),
        }
    }

    #[must_use]
    pub const fn code(&self) -> FsckFindingCodeV1 {
        self.code
    }
    #[must_use]
    pub const fn severity(&self) -> FsckSeverityV1 {
        self.severity
    }
    #[must_use]
    pub const fn subject(&self) -> &FsckSubjectV1 {
        &self.subject
    }
    #[must_use]
    pub fn detail(&self) -> &str {
        &self.detail
    }
}

/// Resource limits for read-only fsck.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FsckRequestV1 {
    max_findings: usize,
    max_objects: usize,
    max_decoded_bytes: u64,
    observe_targets: bool,
    max_target_observations: usize,
    max_observed_bytes: u64,
}

impl FsckRequestV1 {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            max_findings: MAX_FSCK_FINDINGS_V1,
            max_objects: MAX_FSCK_OBJECTS_V1,
            max_decoded_bytes: MAX_FSCK_DECODED_BYTES_V1,
            observe_targets: false,
            max_target_observations: MAX_FSCK_TARGETS_V1,
            max_observed_bytes: MAX_FSCK_OBSERVED_BYTES_V1,
        }
    }

    pub fn with_limits(
        max_findings: usize,
        max_objects: usize,
        max_decoded_bytes: u64,
    ) -> Result<Self, InspectionDtoError> {
        validate_limit("fsck findings", max_findings, MAX_FSCK_FINDINGS_V1)?;
        validate_limit("fsck objects", max_objects, MAX_FSCK_OBJECTS_V1)?;
        validate_byte_limit(
            "fsck decoded bytes",
            max_decoded_bytes,
            MAX_FSCK_DECODED_BYTES_V1,
        )?;
        Ok(Self {
            max_findings,
            max_objects,
            max_decoded_bytes,
            observe_targets: false,
            max_target_observations: MAX_FSCK_TARGETS_V1,
            max_observed_bytes: MAX_FSCK_OBSERVED_BYTES_V1,
        })
    }

    pub fn with_target_observations(
        mut self,
        max_targets: usize,
        max_observed_bytes: u64,
    ) -> Result<Self, InspectionDtoError> {
        validate_limit("fsck target observations", max_targets, MAX_FSCK_TARGETS_V1)?;
        validate_byte_limit(
            "fsck observed bytes",
            max_observed_bytes,
            MAX_FSCK_OBSERVED_BYTES_V1,
        )?;
        self.observe_targets = true;
        self.max_target_observations = max_targets;
        self.max_observed_bytes = max_observed_bytes;
        Ok(self)
    }

    #[must_use]
    pub const fn max_findings(self) -> usize {
        self.max_findings
    }
    #[must_use]
    pub const fn max_objects(self) -> usize {
        self.max_objects
    }
    #[must_use]
    pub const fn max_decoded_bytes(self) -> u64 {
        self.max_decoded_bytes
    }
    #[must_use]
    pub const fn observes_targets(self) -> bool {
        self.observe_targets
    }
    #[must_use]
    pub const fn max_target_observations(self) -> usize {
        self.max_target_observations
    }
    #[must_use]
    pub const fn max_observed_bytes(self) -> u64 {
        self.max_observed_bytes
    }
}

impl Default for FsckRequestV1 {
    fn default() -> Self {
        Self::new()
    }
}

/// Read-only fsck results for selected and reachable authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FsckReportV1 {
    findings: Vec<FsckFindingV1>,
    checked_generations: u64,
    checked_prepared_plans: u64,
    checked_artifact_blobs: u64,
    checked_pack_objects: u64,
    checked_canonical_files: u64,
    checked_canonical_symlinks: u64,
    checked_canonical_trees: u64,
    checked_targets: u64,
    decoded_bytes: u64,
    observed_bytes: u64,
    findings_truncated: bool,
    complete: bool,
}

/// Named fields used to construct an [`FsckReportV1`].
///
/// Naming each counter at construction prevents the ten interchangeable `u64`
/// totals from being transposed silently.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FsckReportPartsV1 {
    pub findings: Vec<FsckFindingV1>,
    pub checked_generations: u64,
    pub checked_prepared_plans: u64,
    pub checked_artifact_blobs: u64,
    pub checked_pack_objects: u64,
    pub checked_canonical_files: u64,
    pub checked_canonical_symlinks: u64,
    pub checked_canonical_trees: u64,
    pub checked_targets: u64,
    pub decoded_bytes: u64,
    pub observed_bytes: u64,
    pub findings_truncated: bool,
    pub complete: bool,
}

impl From<FsckReportPartsV1> for FsckReportV1 {
    fn from(parts: FsckReportPartsV1) -> Self {
        Self {
            findings: parts.findings,
            checked_generations: parts.checked_generations,
            checked_prepared_plans: parts.checked_prepared_plans,
            checked_artifact_blobs: parts.checked_artifact_blobs,
            checked_pack_objects: parts.checked_pack_objects,
            checked_canonical_files: parts.checked_canonical_files,
            checked_canonical_symlinks: parts.checked_canonical_symlinks,
            checked_canonical_trees: parts.checked_canonical_trees,
            checked_targets: parts.checked_targets,
            decoded_bytes: parts.decoded_bytes,
            observed_bytes: parts.observed_bytes,
            findings_truncated: parts.findings_truncated,
            complete: parts.complete,
        }
    }
}

impl FsckReportV1 {
    #[must_use]
    pub fn findings(&self) -> &[FsckFindingV1] {
        &self.findings
    }

    #[must_use]
    pub fn is_clean(&self) -> bool {
        self.findings
            .iter()
            .all(|finding| finding.severity != FsckSeverityV1::Error)
    }

    #[must_use]
    pub const fn checked_generations(&self) -> u64 {
        self.checked_generations
    }
    #[must_use]
    pub const fn checked_prepared_plans(&self) -> u64 {
        self.checked_prepared_plans
    }
    #[must_use]
    pub const fn checked_artifact_blobs(&self) -> u64 {
        self.checked_artifact_blobs
    }
    #[must_use]
    pub const fn checked_pack_objects(&self) -> u64 {
        self.checked_pack_objects
    }
    #[must_use]
    pub const fn checked_canonical_files(&self) -> u64 {
        self.checked_canonical_files
    }
    #[must_use]
    pub const fn checked_canonical_symlinks(&self) -> u64 {
        self.checked_canonical_symlinks
    }
    #[must_use]
    pub const fn checked_canonical_trees(&self) -> u64 {
        self.checked_canonical_trees
    }
    #[must_use]
    pub const fn checked_targets(&self) -> u64 {
        self.checked_targets
    }
    #[must_use]
    pub const fn decoded_bytes(&self) -> u64 {
        self.decoded_bytes
    }
    #[must_use]
    pub const fn observed_bytes(&self) -> u64 {
        self.observed_bytes
    }
    #[must_use]
    pub const fn findings_truncated(&self) -> bool {
        self.findings_truncated
    }
    #[must_use]
    pub const fn complete(&self) -> bool {
        self.complete
    }
}

/// Namespace status derived from selected durable state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NamespaceStatusKindV1 {
    NotFound,
    EnabledExact,
    EnabledModified,
    EnabledMissing,
    EnabledUnexpected,
    Disabled,
    Stale,
    IncompatibleOrCorrupt,
    RecoveryRequired,
}

/// Status of a target in the selected desired snapshot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TargetStatusKindV1 {
    Exact,
    Modified,
    Missing,
    Unexpected,
    Stale,
    Incompatible,
}

/// Target status containing only stable authority and a relative path.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TargetStatusV1 {
    authority: DeploymentName,
    relative_path: String,
    status: TargetStatusKindV1,
}

impl TargetStatusV1 {
    #[must_use]
    pub fn new(
        authority: DeploymentName,
        relative_path: String,
        status: TargetStatusKindV1,
    ) -> Self {
        Self {
            authority,
            relative_path,
            status,
        }
    }

    #[must_use]
    pub const fn authority(&self) -> &DeploymentName {
        &self.authority
    }
    #[must_use]
    pub fn relative_path(&self) -> &str {
        &self.relative_path
    }
    #[must_use]
    pub const fn status(&self) -> TargetStatusKindV1 {
        self.status
    }
}

/// Resource limits for a read-only namespace status request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NamespaceStatusRequestV1 {
    namespace: NamespaceName,
    max_targets: usize,
    max_observed_bytes: u64,
}

impl NamespaceStatusRequestV1 {
    #[must_use]
    pub const fn new(namespace: NamespaceName) -> Self {
        Self {
            namespace,
            max_targets: MAX_STATUS_TARGETS_V1,
            max_observed_bytes: MAX_STATUS_OBSERVED_BYTES_V1,
        }
    }

    pub fn with_limits(
        namespace: NamespaceName,
        max_targets: usize,
        max_observed_bytes: u64,
    ) -> Result<Self, InspectionDtoError> {
        validate_limit("status targets", max_targets, MAX_STATUS_TARGETS_V1)?;
        validate_byte_limit(
            "status observed bytes",
            max_observed_bytes,
            MAX_STATUS_OBSERVED_BYTES_V1,
        )?;
        Ok(Self {
            namespace,
            max_targets,
            max_observed_bytes,
        })
    }

    #[must_use]
    pub const fn namespace(&self) -> &NamespaceName {
        &self.namespace
    }
    #[must_use]
    pub const fn max_targets(&self) -> usize {
        self.max_targets
    }
    #[must_use]
    pub const fn max_observed_bytes(&self) -> u64 {
        self.max_observed_bytes
    }
}

/// Complete status results for a namespace.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NamespaceStatusV1 {
    namespace: NamespaceName,
    head: Option<Digest>,
    lifecycle: Option<LifecycleStateViewV1>,
    desired_snapshot_digest: Option<Digest>,
    status: NamespaceStatusKindV1,
    targets: Vec<TargetStatusV1>,
    observed_bytes: u64,
    detail: Option<String>,
}

/// Named fields used to construct a [`NamespaceStatusV1`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NamespaceStatusPartsV1 {
    pub namespace: NamespaceName,
    pub head: Option<Digest>,
    pub lifecycle: Option<LifecycleStateViewV1>,
    pub desired_snapshot_digest: Option<Digest>,
    pub status: NamespaceStatusKindV1,
    pub targets: Vec<TargetStatusV1>,
    pub observed_bytes: u64,
    pub detail: Option<String>,
}

impl From<NamespaceStatusPartsV1> for NamespaceStatusV1 {
    fn from(parts: NamespaceStatusPartsV1) -> Self {
        Self {
            namespace: parts.namespace,
            head: parts.head,
            lifecycle: parts.lifecycle,
            desired_snapshot_digest: parts.desired_snapshot_digest,
            status: parts.status,
            targets: parts.targets,
            observed_bytes: parts.observed_bytes,
            detail: parts.detail,
        }
    }
}

impl NamespaceStatusV1 {
    #[must_use]
    pub const fn namespace(&self) -> &NamespaceName {
        &self.namespace
    }
    #[must_use]
    pub const fn head(&self) -> Option<&Digest> {
        self.head.as_ref()
    }
    #[must_use]
    pub const fn lifecycle(&self) -> Option<LifecycleStateViewV1> {
        self.lifecycle
    }
    #[must_use]
    pub const fn desired_snapshot_digest(&self) -> Option<&Digest> {
        self.desired_snapshot_digest.as_ref()
    }
    #[must_use]
    pub const fn status(&self) -> NamespaceStatusKindV1 {
        self.status
    }
    #[must_use]
    pub fn targets(&self) -> &[TargetStatusV1] {
        &self.targets
    }
    #[must_use]
    pub const fn observed_bytes(&self) -> u64 {
        self.observed_bytes
    }
    #[must_use]
    pub fn detail(&self) -> Option<&str> {
        self.detail.as_deref()
    }
}

/// Invalid resource limits for a read-only request.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
#[error("{field} limit must be in 1..={maximum}, got {actual}")]
pub struct InspectionDtoError {
    field: &'static str,
    maximum: u64,
    actual: u64,
}

fn validate_limit(
    field: &'static str,
    actual: usize,
    maximum: usize,
) -> Result<(), InspectionDtoError> {
    if actual == 0 || actual > maximum {
        return Err(InspectionDtoError {
            field,
            maximum: maximum as u64,
            actual: actual as u64,
        });
    }
    Ok(())
}

fn validate_byte_limit(
    field: &'static str,
    actual: u64,
    maximum: u64,
) -> Result<(), InspectionDtoError> {
    if actual == 0 || actual > maximum {
        return Err(InspectionDtoError {
            field,
            maximum,
            actual,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounded_requests_reject_zero_and_excessive_limits() {
        let namespace = NamespaceName::new("workstation").unwrap();
        assert!(NamespaceHistoryRequestV1::with_limits(namespace.clone(), 0, 1).is_err());
        assert!(
            NamespaceStatusRequestV1::with_limits(namespace, MAX_STATUS_TARGETS_V1 + 1, 1,)
                .is_err()
        );
        assert!(FsckRequestV1::with_limits(1, 1, 1).is_ok());
        assert!(FsckRequestV1::with_limits(1, 1, 0).is_err());
    }

    #[test]
    fn tracking_inspection_contains_no_source_or_grant_fields() {
        let view = TrackedRootInspectionV1::new(
            "refs/heads/main".to_owned(),
            "sha1-1111111111111111111111111111111111111111".to_owned(),
            Digest::sha256(b"tree"),
        );
        assert_eq!(view.moving_selector(), "refs/heads/main");
        assert!(view.applied_revision().starts_with("sha1-"));
    }
}
