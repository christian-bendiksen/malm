use crate::MAX_ARTIFACT_BLOB_BYTES;
use crate::MAX_DESIRED_TARGETS;
use crate::MAX_PREPARED_ARTIFACTS;
use crate::MAX_STATE_CATALOG_BYTES;
use crate::MAX_STATE_CATALOG_HEADS;
use crate::MAX_STATE_RECORD_BYTES;
use crate::MAX_TRANSFORM_PROVENANCE;
use crate::PREPARED_RECORD_SCHEMA_VERSION;
use crate::STATE_CATALOG_SCHEMA_VERSION;
use crate::bounded_seq_eager;
use crate::ownership::desired_snapshot_digest_v1;
use crate::ownership::validate_prepared_transition_v1;
use crate::prepared::ArchiveProvenanceV1;
use crate::prepared::PreparedRecordError;
use crate::prepared::PreparedRecordV1;
use crate::prepared::TransformProvenanceV1;
use crate::prepared::prepared_id_v1;
use crate::tracked_root::LifecycleStateV1;
use crate::tracked_root::PreparedTransitionV1;
use crate::tracked_root::RestorePointV1;
use crate::tracked_root::RetentionAuthorityV1;
use crate::tracked_root::TrackedRootV1;
use crate::tracked_root::validate_restore_point;
use crate::tracked_root::validate_retention_authority;
use crate::tracked_root::validate_selected_restore_authority;
use crate::tracked_root::validate_tracked_root;
use crate::validate::validate_label;
use crate::validate::validate_relative_path;
use malm_types::ArtifactId;
use malm_types::DeploymentName;
use malm_types::Digest;
use malm_types::NamespaceName;
use malm_types::PreparedId;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeMap;
use std::collections::BTreeSet;

/// Artifact ownership projected into an immutable state generation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StateArtifactV1 {
    id: ArtifactId,
    digest: Digest,
}

impl StateArtifactV1 {
    #[must_use]
    pub const fn new(id: ArtifactId, digest: Digest) -> Self {
        Self { id, digest }
    }

    #[must_use]
    pub const fn id(&self) -> &ArtifactId {
        &self.id
    }
    #[must_use]
    pub const fn digest(&self) -> &Digest {
        &self.digest
    }
}

/// Restorable regular-file state for a cumulative managed target slot.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StateFileV1 {
    pub(crate) digest: Digest,
    pub(crate) byte_len: u64,
    pub(crate) mode: u32,
}

impl StateFileV1 {
    /// Creates validated desired regular-file state.
    pub fn new(digest: Digest, byte_len: u64, mode: u32) -> Result<Self, StateRecordError> {
        let file = Self {
            digest,
            byte_len,
            mode,
        };
        validate_state_file(&file)?;
        Ok(file)
    }

    #[must_use]
    pub const fn digest(&self) -> &Digest {
        &self.digest
    }
    #[must_use]
    pub const fn byte_len(&self) -> u64 {
        self.byte_len
    }
    #[must_use]
    pub const fn mode(&self) -> u32 {
        self.mode
    }
}

/// Restorable directory state for a cumulative managed target slot.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StateDirectoryV1 {
    pub(crate) mode: u32,
}

/// Restorable safe-relative symbolic-link state.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StateSymlinkV1 {
    pub(crate) object: Digest,
}

impl StateSymlinkV1 {
    #[must_use]
    pub const fn new(object: Digest) -> Self {
        Self { object }
    }

    #[must_use]
    pub const fn object(&self) -> &Digest {
        &self.object
    }
}

/// Restorable canonical tree-root state and optional archive provenance.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StateTreeV1 {
    pub(crate) tree: Digest,
    pub(crate) archive_provenance: Option<ArchiveProvenanceV1>,
}

impl StateTreeV1 {
    #[must_use]
    pub const fn new(tree: Digest) -> Self {
        Self {
            tree,
            archive_provenance: None,
        }
    }

    #[must_use]
    pub const fn from_archive(tree: Digest, archive_provenance: ArchiveProvenanceV1) -> Self {
        Self {
            tree,
            archive_provenance: Some(archive_provenance),
        }
    }

    #[must_use]
    pub const fn tree(&self) -> &Digest {
        &self.tree
    }
    #[must_use]
    pub const fn archive_provenance(&self) -> Option<&ArchiveProvenanceV1> {
        self.archive_provenance.as_ref()
    }
}

impl StateDirectoryV1 {
    /// Creates validated desired directory state.
    pub fn new(mode: u32) -> Result<Self, StateRecordError> {
        let directory = Self { mode };
        validate_state_directory(directory)?;
        Ok(directory)
    }

    #[must_use]
    pub const fn mode(self) -> u32 {
        self.mode
    }
}

/// The kind and present or absent value of a cumulative target slot.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum StateTargetStateV1 {
    File { file: Option<StateFileV1> },
    Directory { directory: Option<StateDirectoryV1> },
    Symlink { symlink: Option<StateSymlinkV1> },
    Tree { tree: Option<StateTreeV1> },
}

/// A path-keyed target slot retained across the full generation lineage.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StateTargetV1 {
    pub(crate) authority: DeploymentName,
    pub(crate) relative_path: String,
    pub(crate) state: StateTargetStateV1,
}

impl StateTargetV1 {
    /// Creates one validated desired target slot.
    pub fn new(
        authority: DeploymentName,
        relative_path: impl Into<String>,
        state: StateTargetStateV1,
    ) -> Result<Self, StateRecordError> {
        let target = Self {
            authority,
            relative_path: relative_path.into(),
            state,
        };
        validate_state_targets(std::slice::from_ref(&target))?;
        Ok(target)
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
    pub const fn state(&self) -> &StateTargetStateV1 {
        &self.state
    }

    #[must_use]
    pub const fn is_present(&self) -> bool {
        match &self.state {
            StateTargetStateV1::File { file } => file.is_some(),
            StateTargetStateV1::Directory { directory } => directory.is_some(),
            StateTargetStateV1::Symlink { symlink } => symlink.is_some(),
            StateTargetStateV1::Tree { tree } => tree.is_some(),
        }
    }
}

/// Complete canonical cumulative desired target snapshot for one namespace.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct DesiredSnapshotV1(
    #[serde(deserialize_with = "deserialize_state_targets")] pub(crate) Vec<StateTargetV1>,
);

impl DesiredSnapshotV1 {
    /// Canonicalizes a complete snapshot by target authority and path.
    pub fn new(mut targets: Vec<StateTargetV1>) -> Result<Self, StateRecordError> {
        targets.sort_by(|left, right| {
            (left.authority(), left.relative_path())
                .cmp(&(right.authority(), right.relative_path()))
        });
        validate_state_targets(&targets)?;
        Ok(Self(targets))
    }

    #[must_use]
    pub const fn empty() -> Self {
        Self(Vec::new())
    }

    /// Returns canonical target slots, including cumulative tombstones.
    #[must_use]
    pub fn targets(&self) -> &[StateTargetV1] {
        &self.0
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// An immutable namespace generation produced from exactly one prepared plan.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StateGenerationV1 {
    pub(crate) schema_version: u32,
    pub(crate) namespace: NamespaceName,
    pub(crate) plan_id: PreparedId,
    pub(crate) previous_generation: Option<Digest>,
    pub(crate) transition: PreparedTransitionV1,
    pub(crate) lifecycle: LifecycleStateV1,
    pub(crate) restore_point: Option<RestorePointV1>,
    pub(crate) retention: RetentionAuthorityV1,
    pub(crate) tracked_root: Option<TrackedRootV1>,
    pub(crate) desired_snapshot: DesiredSnapshotV1,
    pub(crate) desired_snapshot_digest: Digest,
    pub(crate) artifacts: Vec<StateArtifactV1>,
    pub(crate) transforms: Vec<TransformProvenanceV1>,
}

impl StateGenerationV1 {
    pub fn from_prepared(
        plan_id: PreparedId,
        previous_generation: Option<Digest>,
        previous: Option<&Self>,
        prepared: &PreparedRecordV1,
    ) -> Result<Self, StateRecordError> {
        if plan_id != prepared_id_v1(prepared) {
            return Err(StateRecordError::InvalidState(
                "generation plan identity differs from its prepared record".to_owned(),
            ));
        }
        if prepared.expected_head() != previous_generation.as_ref() {
            return Err(StateRecordError::InvalidState(
                "prepared namespace-head precondition differs from the predecessor".to_owned(),
            ));
        }
        if previous_generation.is_some() != previous.is_some() {
            return Err(StateRecordError::InvalidState(
                "previous generation identity and record presence differ".to_owned(),
            ));
        }
        if let (Some(expected), Some(previous)) = (previous_generation.as_ref(), previous)
            && state_generation_digest_v1(previous) != *expected
        {
            return Err(StateRecordError::InvalidState(
                "predecessor bytes differ from the previous generation identity".to_owned(),
            ));
        }
        if previous.is_some_and(|previous| previous.namespace != prepared.namespace) {
            return Err(StateRecordError::InvalidState(
                "generation namespace differs from its predecessor".to_owned(),
            ));
        }
        validate_prepared_transition_v1(previous, prepared)?;
        if matches!(
            prepared.transition(),
            PreparedTransitionV1::NamespaceRemoval { .. }
        ) {
            return Err(StateRecordError::InvalidState(
                "namespace removal cannot produce a state generation".to_owned(),
            ));
        }
        let generation = Self {
            schema_version: PREPARED_RECORD_SCHEMA_VERSION,
            namespace: prepared.namespace.clone(),
            plan_id,
            previous_generation,
            transition: prepared.transition.clone(),
            lifecycle: prepared.lifecycle,
            restore_point: prepared.restore_point.clone(),
            retention: prepared.retention.clone(),
            tracked_root: prepared.tracked_root.clone(),
            desired_snapshot: prepared.desired_snapshot.clone(),
            desired_snapshot_digest: prepared.desired_snapshot_digest.clone(),
            artifacts: prepared
                .artifacts
                .iter()
                .map(|artifact| StateArtifactV1 {
                    id: artifact.id.clone(),
                    digest: artifact.digest.clone(),
                })
                .collect(),
            transforms: prepared.transforms.clone(),
        };
        let actual = encode_state_generation_v1(&generation).len();
        if actual > MAX_STATE_RECORD_BYTES {
            return Err(StateRecordError::TooLarge {
                limit: MAX_STATE_RECORD_BYTES,
                actual,
            });
        }
        Ok(generation)
    }

    /// Rebuilds a retained history-floor generation after pruning its weak predecessor edge.
    ///
    /// The prepared record remains the content-addressed authority for every
    /// copied field. Live admission always uses [`Self::from_prepared`] with the
    /// exact predecessor present.
    pub fn from_retained_prepared(
        plan_id: PreparedId,
        previous_generation: Option<Digest>,
        prepared: &PreparedRecordV1,
    ) -> Result<Self, StateRecordError> {
        if plan_id != prepared_id_v1(prepared) {
            return Err(StateRecordError::InvalidState(
                "generation plan identity differs from its prepared record".to_owned(),
            ));
        }
        if prepared.expected_head() != previous_generation.as_ref() {
            return Err(StateRecordError::InvalidState(
                "prepared namespace-head precondition differs from the retained predecessor edge"
                    .to_owned(),
            ));
        }
        if matches!(
            prepared.transition(),
            PreparedTransitionV1::NamespaceRemoval { .. }
        ) {
            return Err(StateRecordError::InvalidState(
                "namespace removal cannot produce a state generation".to_owned(),
            ));
        }
        validate_state_targets(prepared.desired_snapshot().targets())?;
        if desired_snapshot_digest_v1(prepared.namespace(), prepared.desired_snapshot())
            != *prepared.desired_snapshot_digest()
        {
            return Err(StateRecordError::InvalidState(
                "prepared desired-snapshot digest differs from its complete snapshot".to_owned(),
            ));
        }
        let generation = Self {
            schema_version: PREPARED_RECORD_SCHEMA_VERSION,
            namespace: prepared.namespace.clone(),
            plan_id,
            previous_generation,
            transition: prepared.transition.clone(),
            lifecycle: prepared.lifecycle,
            restore_point: prepared.restore_point.clone(),
            retention: prepared.retention.clone(),
            tracked_root: prepared.tracked_root.clone(),
            desired_snapshot: prepared.desired_snapshot.clone(),
            desired_snapshot_digest: prepared.desired_snapshot_digest.clone(),
            artifacts: prepared
                .artifacts
                .iter()
                .map(|artifact| StateArtifactV1 {
                    id: artifact.id.clone(),
                    digest: artifact.digest.clone(),
                })
                .collect(),
            transforms: prepared.transforms.clone(),
        };
        validate_state_generation(&generation)?;
        Ok(generation)
    }

    #[must_use]
    pub const fn namespace(&self) -> &NamespaceName {
        &self.namespace
    }
    #[must_use]
    pub const fn plan_id(&self) -> &PreparedId {
        &self.plan_id
    }
    #[must_use]
    pub const fn previous_generation(&self) -> Option<&Digest> {
        self.previous_generation.as_ref()
    }
    #[must_use]
    pub const fn transition(&self) -> &PreparedTransitionV1 {
        &self.transition
    }

    /// Returns the lifecycle state that controls ownership of this snapshot.
    #[must_use]
    pub const fn lifecycle_state(&self) -> LifecycleStateV1 {
        self.lifecycle
    }

    #[must_use]
    pub const fn lifecycle(&self) -> LifecycleStateV1 {
        self.lifecycle_state()
    }
    #[must_use]
    pub const fn restore_point(&self) -> Option<&RestorePointV1> {
        self.restore_point.as_ref()
    }
    #[must_use]
    pub const fn retention_authority(&self) -> &RetentionAuthorityV1 {
        &self.retention
    }

    /// Returns immutable tracking state copied from the committed prepared plan.
    #[must_use]
    pub const fn tracked_root(&self) -> Option<&TrackedRootV1> {
        self.tracked_root.as_ref()
    }

    /// Returns the exact desired snapshot copied from the committed plan.
    #[must_use]
    pub const fn desired_snapshot(&self) -> &DesiredSnapshotV1 {
        &self.desired_snapshot
    }

    /// Returns the digest of the exact desired snapshot copied from the plan.
    #[must_use]
    pub const fn desired_snapshot_digest(&self) -> &Digest {
        &self.desired_snapshot_digest
    }
    #[must_use]
    pub fn artifacts(&self) -> &[StateArtifactV1] {
        &self.artifacts
    }

    /// Returns transform provenance copied verbatim from the committed prepared plan.
    #[must_use]
    pub fn transforms(&self) -> &[TransformProvenanceV1] {
        &self.transforms
    }
    #[must_use]
    pub fn targets(&self) -> &[StateTargetV1] {
        self.desired_snapshot.targets()
    }
}

pub(crate) fn prepared_error_as_state(error: PreparedRecordError) -> StateRecordError {
    StateRecordError::InvalidState(error.to_string())
}

/// A namespace-to-generation binding in the mutable state catalog.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NamespaceHeadV1 {
    namespace: NamespaceName,
    generation: Digest,
}

impl NamespaceHeadV1 {
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

/// Canonical mutable index of every namespace's immutable generation head.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StateCatalogV1 {
    schema_version: u32,
    #[serde(deserialize_with = "deserialize_catalog_heads")]
    heads: Vec<NamespaceHeadV1>,
}

impl StateCatalogV1 {
    /// Builds a canonical catalog, sorting heads and rejecting duplicate namespaces.
    pub fn new(mut heads: Vec<NamespaceHeadV1>) -> Result<Self, StateCatalogError> {
        if heads.len() > MAX_STATE_CATALOG_HEADS {
            return Err(StateCatalogError::TooManyHeads {
                limit: MAX_STATE_CATALOG_HEADS,
                actual: heads.len(),
            });
        }
        heads.sort_by(|left, right| left.namespace.cmp(&right.namespace));
        validate_catalog_heads(&heads)?;

        let catalog = Self {
            schema_version: STATE_CATALOG_SCHEMA_VERSION,
            heads,
        };
        let actual = encode_state_catalog_v1(&catalog).len();
        if actual > MAX_STATE_CATALOG_BYTES {
            return Err(StateCatalogError::TooLarge {
                limit: MAX_STATE_CATALOG_BYTES,
                actual,
            });
        }
        Ok(catalog)
    }

    #[must_use]
    pub const fn schema_version(&self) -> u32 {
        self.schema_version
    }
    #[must_use]
    pub fn heads(&self) -> &[NamespaceHeadV1] {
        &self.heads
    }

    #[must_use]
    pub fn head(&self, namespace: &NamespaceName) -> Option<&NamespaceHeadV1> {
        self.heads
            .binary_search_by(|head| head.namespace.cmp(namespace))
            .ok()
            .map(|index| &self.heads[index])
    }

    #[must_use]
    pub fn generation(&self, namespace: &NamespaceName) -> Option<&Digest> {
        self.head(namespace).map(NamespaceHeadV1::generation)
    }

    /// Inserts or replaces one namespace head while preserving canonical ordering.
    pub fn update_head(
        &mut self,
        namespace: NamespaceName,
        generation: Digest,
    ) -> Result<Option<Digest>, StateCatalogError> {
        let mut heads = self.heads.clone();
        let previous = match heads.binary_search_by(|head| head.namespace.cmp(&namespace)) {
            Ok(index) => Some(std::mem::replace(&mut heads[index].generation, generation)),
            Err(index) => {
                heads.insert(index, NamespaceHeadV1::new(namespace, generation));
                None
            }
        };
        *self = Self::new(heads)?;
        Ok(previous)
    }

    pub fn remove_head(&mut self, namespace: &NamespaceName) -> Option<Digest> {
        let index = self
            .heads
            .binary_search_by(|head| head.namespace.cmp(namespace))
            .ok()?;
        Some(self.heads.remove(index).generation)
    }
}

/// Encodes a validated state catalog as compact canonical JSON with one final LF.
#[must_use]
pub fn encode_state_catalog_v1(catalog: &StateCatalogV1) -> Vec<u8> {
    canonical_json(catalog)
}

/// Computes the SHA-256 identity of a catalog's exact canonical bytes.
#[must_use]
pub fn state_catalog_digest_v1(catalog: &StateCatalogV1) -> Digest {
    Digest::sha256(encode_state_catalog_v1(catalog))
}

/// Strictly decodes and validates one canonical state catalog.
pub fn decode_state_catalog_v1(bytes: &[u8]) -> Result<StateCatalogV1, StateCatalogError> {
    if bytes.len() > MAX_STATE_CATALOG_BYTES {
        return Err(StateCatalogError::TooLarge {
            limit: MAX_STATE_CATALOG_BYTES,
            actual: bytes.len(),
        });
    }
    let catalog: StateCatalogV1 = serde_json::from_slice(bytes)
        .map_err(|error| StateCatalogError::InvalidJson(error.to_string()))?;
    if catalog.schema_version != STATE_CATALOG_SCHEMA_VERSION {
        return Err(StateCatalogError::UnsupportedVersion {
            expected: STATE_CATALOG_SCHEMA_VERSION,
            found: catalog.schema_version,
        });
    }
    if encode_state_catalog_v1(&catalog) != bytes {
        return Err(StateCatalogError::NonCanonical);
    }
    validate_catalog_heads(&catalog.heads)?;
    Ok(catalog)
}

/// Strict state-catalog decoding or semantic failure.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
#[non_exhaustive]
pub enum StateCatalogError {
    #[error("state catalog has {actual} bytes; limit is {limit}")]
    TooLarge { limit: usize, actual: usize },
    #[error("invalid state catalog: {0}")]
    InvalidJson(String),
    #[error("unsupported state catalog version {found}; expected {expected}")]
    UnsupportedVersion { expected: u32, found: u32 },
    #[error("state catalog is not canonical")]
    NonCanonical,
    #[error("state catalog head count {actual} exceeds limit {limit}")]
    TooManyHeads { limit: usize, actual: usize },
    #[error("duplicate state catalog namespace {0}")]
    DuplicateNamespace(NamespaceName),
    #[error("state catalog heads are not strictly sorted by namespace")]
    HeadsNotSorted,
}

fn validate_catalog_heads(heads: &[NamespaceHeadV1]) -> Result<(), StateCatalogError> {
    if heads.len() > MAX_STATE_CATALOG_HEADS {
        return Err(StateCatalogError::TooManyHeads {
            limit: MAX_STATE_CATALOG_HEADS,
            actual: heads.len(),
        });
    }
    for pair in heads.windows(2) {
        match pair[0].namespace.cmp(&pair[1].namespace) {
            std::cmp::Ordering::Less => {}
            std::cmp::Ordering::Equal => {
                return Err(StateCatalogError::DuplicateNamespace(
                    pair[0].namespace.clone(),
                ));
            }
            std::cmp::Ordering::Greater => return Err(StateCatalogError::HeadsNotSorted),
        }
    }
    Ok(())
}

fn deserialize_catalog_heads<'de, D>(deserializer: D) -> Result<Vec<NamespaceHeadV1>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    bounded_seq_eager(
        deserializer,
        MAX_STATE_CATALOG_HEADS,
        "state catalog heads",
        "state catalog",
        "heads",
    )
}

/// Encodes one immutable state generation as canonical JSON.
#[must_use]
pub fn encode_state_generation_v1(generation: &StateGenerationV1) -> Vec<u8> {
    canonical_json(generation)
}

/// Computes the immutable generation object's SHA-256 identity.
#[must_use]
pub fn state_generation_digest_v1(generation: &StateGenerationV1) -> Digest {
    Digest::sha256(encode_state_generation_v1(generation))
}

/// Strictly decodes and verifies one immutable state generation.
pub fn decode_state_generation_v1(
    expected: &Digest,
    bytes: &[u8],
) -> Result<StateGenerationV1, StateRecordError> {
    let generation: StateGenerationV1 = decode_canonical_state(bytes)?;
    let actual = state_generation_digest_v1(&generation);
    if &actual != expected {
        return Err(StateRecordError::DigestMismatch {
            expected: expected.clone(),
            actual,
        });
    }
    validate_state_generation(&generation)?;
    Ok(generation)
}

/// Strict state-record decoding failure.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum StateRecordError {
    #[error("state record has {actual} bytes; limit is {limit}")]
    TooLarge { limit: usize, actual: usize },
    #[error("invalid state record: {0}")]
    InvalidJson(String),
    #[error("unsupported state version {found}; expected {expected}")]
    UnsupportedVersion { expected: u32, found: u32 },
    #[error("state record is not canonical")]
    NonCanonical,
    #[error("state generation mismatch: expected {expected}, computed {actual}")]
    DigestMismatch { expected: Digest, actual: Digest },
    #[error("invalid state generation: {0}")]
    InvalidState(String),
}

pub(crate) fn validate_state_generation(
    generation: &StateGenerationV1,
) -> Result<(), StateRecordError> {
    if let Some(tracked_root) = &generation.tracked_root {
        validate_tracked_root(tracked_root).map_err(|error| match error {
            PreparedRecordError::UnsupportedVersion { expected, found } => {
                StateRecordError::UnsupportedVersion { expected, found }
            }
            error => StateRecordError::InvalidState(error.to_string()),
        })?;
    }
    if let Some(restore_point) = &generation.restore_point {
        validate_restore_point(restore_point, Some(&generation.namespace))
            .map_err(prepared_error_as_state)?;
    }
    validate_retention_authority(&generation.retention, Some(&generation.namespace))
        .map_err(prepared_error_as_state)?;
    validate_selected_restore_authority(
        generation.lifecycle,
        generation.restore_point.as_ref(),
        &generation.retention,
    )
    .map_err(prepared_error_as_state)?;
    if matches!(
        generation.transition,
        PreparedTransitionV1::NamespaceRemoval { .. }
    ) {
        return Err(StateRecordError::InvalidState(
            "namespace-removal transition cannot be stored as a generation".to_owned(),
        ));
    }
    if generation.artifacts.len() > MAX_PREPARED_ARTIFACTS {
        return Err(StateRecordError::InvalidState(
            "artifact ownership exceeds its count limit".to_owned(),
        ));
    }
    for pair in generation.artifacts.windows(2) {
        if pair[0].id >= pair[1].id {
            return Err(StateRecordError::InvalidState(
                "artifact ownership must be strictly ordered by identifier".to_owned(),
            ));
        }
    }
    if generation.transforms.len() > MAX_TRANSFORM_PROVENANCE {
        return Err(StateRecordError::InvalidState(
            "transform provenance exceeds its count limit".to_owned(),
        ));
    }
    for transform in &generation.transforms {
        transform.validate().map_err(prepared_error_as_state)?;
    }
    for pair in generation.transforms.windows(2) {
        if pair[0].request_digest >= pair[1].request_digest {
            return Err(StateRecordError::InvalidState(
                "transform provenance must be strictly ordered by request digest".to_owned(),
            ));
        }
    }
    validate_state_targets(generation.desired_snapshot.targets())?;
    let desired = desired_snapshot_digest_v1(&generation.namespace, &generation.desired_snapshot);
    if desired != generation.desired_snapshot_digest {
        return Err(StateRecordError::InvalidState(
            "desired-snapshot digest differs from the complete desired snapshot".to_owned(),
        ));
    }
    Ok(())
}

pub(crate) fn validate_state_targets(targets: &[StateTargetV1]) -> Result<(), StateRecordError> {
    if targets.len() > MAX_DESIRED_TARGETS {
        return Err(StateRecordError::InvalidState(
            "complete desired snapshot exceeds its target count limit".to_owned(),
        ));
    }
    let mut digest_lengths = BTreeMap::new();
    // A present managed directory may contain other managed targets. Restored
    // ancestor directories require this shape. Every other present state is a
    // leaf and cannot appear on another target's ancestor path.
    let present_leaves = targets
        .iter()
        .filter(|target| {
            target.is_present()
                && !matches!(
                    target.state,
                    StateTargetStateV1::Directory { directory: Some(_) }
                )
        })
        .map(|target| {
            (
                target.authority().clone(),
                target.relative_path().to_owned(),
            )
        })
        .collect::<BTreeSet<_>>();
    for (index, target) in targets.iter().enumerate() {
        validate_relative_path(&target.relative_path).map_err(prepared_error_as_state)?;
        if index > 0 {
            let previous = &targets[index - 1];
            let ordering = (previous.authority(), previous.relative_path())
                .cmp(&(target.authority(), target.relative_path()));
            if !ordering.is_lt() {
                return Err(StateRecordError::InvalidState(
                    "target slots must be strictly ordered by authority and path".to_owned(),
                ));
            }
        }
        match &target.state {
            StateTargetStateV1::File { file: Some(file) } => {
                validate_state_file(file)?;
                if let Some(previous) = digest_lengths.insert(&file.digest, file.byte_len)
                    && previous != file.byte_len
                {
                    return Err(StateRecordError::InvalidState(
                        "one target digest cannot have conflicting lengths".to_owned(),
                    ));
                }
            }
            StateTargetStateV1::Directory {
                directory: Some(directory),
            } => {
                validate_state_directory(*directory)?;
            }
            StateTargetStateV1::Symlink { symlink: Some(_) } => {}
            StateTargetStateV1::Tree { tree: Some(tree) } => {
                if let Some(provenance) = tree.archive_provenance() {
                    validate_label("archive decoder", provenance.decoder())
                        .map_err(prepared_error_as_state)?;
                }
            }
            StateTargetStateV1::File { file: None }
            | StateTargetStateV1::Directory { directory: None }
            | StateTargetStateV1::Symlink { symlink: None }
            | StateTargetStateV1::Tree { tree: None } => {}
        }
        if target.is_present() {
            for (separator, _) in target.relative_path.match_indices('/') {
                let ancestor = &target.relative_path[..separator];
                if present_leaves.contains(&(target.authority.clone(), ancestor.to_owned())) {
                    return Err(StateRecordError::InvalidState(format!(
                        "present desired targets overlap at {}:{ancestor} and {}:{}",
                        target.authority, target.authority, target.relative_path
                    )));
                }
            }
        }
    }
    Ok(())
}

pub(crate) fn validate_target_state(state: &StateTargetStateV1) -> Result<(), StateRecordError> {
    match state {
        StateTargetStateV1::File { file: Some(file) } => validate_state_file(file),
        StateTargetStateV1::Directory {
            directory: Some(directory),
        } => validate_state_directory(*directory),
        StateTargetStateV1::Symlink { symlink: Some(_) } => Ok(()),
        StateTargetStateV1::Tree { tree: Some(tree) } => {
            if let Some(provenance) = tree.archive_provenance() {
                validate_label("archive decoder", provenance.decoder())
                    .map_err(prepared_error_as_state)?;
            }
            Ok(())
        }
        StateTargetStateV1::File { file: None }
        | StateTargetStateV1::Directory { directory: None }
        | StateTargetStateV1::Symlink { symlink: None }
        | StateTargetStateV1::Tree { tree: None } => Ok(()),
    }
}

fn validate_state_file(file: &StateFileV1) -> Result<(), StateRecordError> {
    if file.mode & !0o777 != 0 || file.mode & 0o400 == 0 {
        return Err(StateRecordError::InvalidState(
            "target file mode must contain only permission bits and remain owner-readable"
                .to_owned(),
        ));
    }
    if file.byte_len > MAX_ARTIFACT_BLOB_BYTES {
        return Err(StateRecordError::InvalidState(
            "target file exceeds the per-blob size limit".to_owned(),
        ));
    }
    if file.byte_len == 0 && file.digest != Digest::sha256([]) {
        return Err(StateRecordError::InvalidState(
            "zero-byte target files must have the empty SHA-256 digest".to_owned(),
        ));
    }
    Ok(())
}

fn validate_state_directory(directory: StateDirectoryV1) -> Result<(), StateRecordError> {
    if directory.mode & !0o777 != 0 || directory.mode & 0o500 != 0o500 {
        return Err(StateRecordError::InvalidState(
            "target directory mode must contain only permission bits and remain owner-readable and owner-searchable"
                .to_owned(),
        ));
    }
    Ok(())
}

fn deserialize_state_targets<'de, D>(deserializer: D) -> Result<Vec<StateTargetV1>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    bounded_seq_eager(
        deserializer,
        MAX_DESIRED_TARGETS,
        "desired targets",
        "desired snapshot",
        "targets",
    )
}

fn canonical_json(value: &impl Serialize) -> Vec<u8> {
    let mut bytes = serde_json::to_vec(value).expect("validated state records always serialize");
    bytes.push(b'\n');
    bytes
}

fn decode_canonical_state<T>(bytes: &[u8]) -> Result<T, StateRecordError>
where
    T: for<'de> Deserialize<'de> + Serialize,
{
    if bytes.len() > MAX_STATE_RECORD_BYTES {
        return Err(StateRecordError::TooLarge {
            limit: MAX_STATE_RECORD_BYTES,
            actual: bytes.len(),
        });
    }
    let value: T = serde_json::from_slice(bytes)
        .map_err(|error| StateRecordError::InvalidJson(error.to_string()))?;
    let encoded = canonical_json(&value);
    if encoded != bytes {
        return Err(StateRecordError::NonCanonical);
    }
    let json: serde_json::Value = serde_json::from_slice(bytes)
        .map_err(|error| StateRecordError::InvalidJson(error.to_string()))?;
    let found = json
        .get("schema_version")
        .and_then(serde_json::Value::as_u64)
        .and_then(|version| u32::try_from(version).ok())
        .unwrap_or(u32::MAX);
    if found != PREPARED_RECORD_SCHEMA_VERSION {
        return Err(StateRecordError::UnsupportedVersion {
            expected: PREPARED_RECORD_SCHEMA_VERSION,
            found,
        });
    }
    Ok(value)
}

#[cfg(test)]
mod tests;
