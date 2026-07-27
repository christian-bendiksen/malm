use crate::MAX_ARTIFACT_BLOB_BYTES;
use crate::MAX_POLICY_FINDINGS;
use crate::MAX_PREPARED_ARTIFACTS;
use crate::MAX_PREPARED_INPUTS;
use crate::MAX_PREPARED_OPERATIONS;
use crate::MAX_PREPARED_RECORD_BYTES;
use crate::MAX_PREPARED_UNIQUE_ARTIFACT_BYTES;
use crate::MAX_TRANSFORM_DIAGNOSTIC_NOTES;
use crate::MAX_TRANSFORM_DIAGNOSTIC_TOTAL_TEXT_BYTES;
use crate::MAX_TRANSFORM_DIAGNOSTICS;
use crate::MAX_TRANSFORM_PROVENANCE;
use crate::MAX_TRANSFORM_RESOURCES;
use crate::PREPARED_RECORD_SCHEMA_VERSION;
use crate::TRACKED_ROOT_SCHEMA_VERSION;
use crate::ownership::desired_snapshot_digest_v1;
use crate::ownership::state_is_present;
use crate::state::DesiredSnapshotV1;
use crate::state::StateTargetStateV1;
use crate::state::validate_state_targets;
use crate::state::validate_target_state;
use crate::tracked_root::LifecycleStateV1;
use crate::tracked_root::PreparedTransitionV1;
use crate::tracked_root::RestorePointV1;
use crate::tracked_root::RetentionAuthorityV1;
use crate::tracked_root::SchemaVersionsV1;
use crate::tracked_root::TrackedRootV1;
use crate::tracked_root::validate_restore_point;
use crate::tracked_root::validate_retention_authority;
use crate::tracked_root::validate_selected_restore_authority;
use crate::tracked_root::validate_tracked_root;
use crate::validate::check_limit;
use crate::validate::deserialize_transform_diagnostic_notes;
use crate::validate::deserialize_transform_diagnostics;
use crate::validate::deserialize_transform_resources;
use crate::validate::reject_destination_prefixes;
use crate::validate::reject_duplicates;
use crate::validate::validate_diagnostic_code;
use crate::validate::validate_diagnostic_text;
use crate::validate::validate_label;
use crate::validate::validate_relative_path;
use crate::validate::validate_text;
use malm_types::ArtifactId;
use malm_types::ContributionName;
use malm_types::DeploymentName;
use malm_types::Digest;
use malm_types::NamespaceName;
use malm_types::PackNodeId;
use malm_types::PreparedId;
use malm_types::policy_approval_digest_v1;
use malm_types::policy_finding_id_v1;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeMap;

/// Kinds of immutable input captured during preparation.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PreparedInputKindV1 {
    Source,
    Config,
    Lock,
    Component,
    Asset,
    Other,
}

impl From<PreparedInputKindV1> for malm_types::PrepareInputKindV1 {
    fn from(kind: PreparedInputKindV1) -> Self {
        match kind {
            PreparedInputKindV1::Source => Self::Source,
            PreparedInputKindV1::Config => Self::Config,
            PreparedInputKindV1::Lock => Self::Lock,
            PreparedInputKindV1::Component => Self::Component,
            PreparedInputKindV1::Asset => Self::Asset,
            PreparedInputKindV1::Other => Self::Other,
        }
    }
}

impl From<malm_types::PrepareInputKindV1> for PreparedInputKindV1 {
    fn from(kind: malm_types::PrepareInputKindV1) -> Self {
        match kind {
            malm_types::PrepareInputKindV1::Source => Self::Source,
            malm_types::PrepareInputKindV1::Config => Self::Config,
            malm_types::PrepareInputKindV1::Lock => Self::Lock,
            malm_types::PrepareInputKindV1::Component => Self::Component,
            malm_types::PrepareInputKindV1::Asset => Self::Asset,
            malm_types::PrepareInputKindV1::Other => Self::Other,
        }
    }
}

/// An immutable input identified by name and digest.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreparedInputV1 {
    kind: PreparedInputKindV1,
    name: String,
    digest: Digest,
}

impl PreparedInputV1 {
    pub fn new(
        kind: PreparedInputKindV1,
        name: impl Into<String>,
        digest: Digest,
    ) -> Result<Self, PreparedRecordError> {
        let name = name.into();
        validate_label("prepared input name", &name)?;
        Ok(Self { kind, name, digest })
    }

    #[must_use]
    pub const fn kind(&self) -> PreparedInputKindV1 {
        self.kind
    }
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }
    #[must_use]
    pub const fn digest(&self) -> &Digest {
        &self.digest
    }
}

/// An immutable artifact stored separately in the blob CAS.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreparedArtifactV1 {
    pub(crate) id: ArtifactId,
    pub(crate) digest: Digest,
    byte_len: u64,
    media_type: String,
}

impl PreparedArtifactV1 {
    pub fn new(
        id: ArtifactId,
        digest: Digest,
        byte_len: u64,
        media_type: impl Into<String>,
    ) -> Result<Self, PreparedRecordError> {
        let media_type = media_type.into();
        validate_label("artifact media type", &media_type)?;
        Ok(Self {
            id,
            digest,
            byte_len,
            media_type,
        })
    }

    #[must_use]
    pub const fn id(&self) -> &ArtifactId {
        &self.id
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
    pub fn media_type(&self) -> &str {
        &self.media_type
    }
}

/// The exact identity of a declared resource used by a persisted transform.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransformResourceV1 {
    name: String,
    digest: Digest,
}

/// The closed severity levels for successful persisted transform diagnostics.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TransformDiagnosticSeverityV1 {
    Error,
    Warning,
    Info,
}

/// The closed primary source or output locations for persisted transform diagnostics.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum TransformDiagnosticLocationV1 {
    Source {
        authority_label: ContributionName,
        authority_identity: Digest,
        document_path: String,
        source_byte_len: u64,
        start: u32,
        end: u32,
    },
    Output {
        start: u64,
        end: u64,
    },
}

impl TransformDiagnosticLocationV1 {
    fn validate(&self) -> Result<(), PreparedRecordError> {
        match self {
            Self::Source {
                document_path,
                source_byte_len,
                start,
                end,
                ..
            } => {
                validate_relative_path(document_path)?;
                if *source_byte_len > malm_types::MAX_TRANSFORM_SOURCE_DOCUMENT_BYTES_V1 {
                    return Err(PreparedRecordError::InvalidField {
                        field: "transform diagnostic source byte length",
                        reason: "exceeds its byte limit",
                    });
                }
                if start > end {
                    return Err(PreparedRecordError::InvalidField {
                        field: "transform diagnostic source range",
                        reason: "start must not exceed end",
                    });
                }
                if u64::from(*end) > *source_byte_len {
                    return Err(PreparedRecordError::InvalidField {
                        field: "transform diagnostic source range",
                        reason: "end exceeds the exact captured source byte length",
                    });
                }
            }
            Self::Output { start, end } if start > end => {
                return Err(PreparedRecordError::InvalidField {
                    field: "transform diagnostic output range",
                    reason: "start must not exceed end",
                });
            }
            Self::Output { .. } => {}
        }
        Ok(())
    }
}

/// A complete bounded diagnostic returned by a successful persisted transform.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransformDiagnosticV1 {
    severity: TransformDiagnosticSeverityV1,
    code: String,
    message: String,
    primary: Option<TransformDiagnosticLocationV1>,
    #[serde(deserialize_with = "deserialize_transform_diagnostic_notes")]
    notes: Vec<String>,
}

impl TransformDiagnosticV1 {
    pub fn new(
        severity: TransformDiagnosticSeverityV1,
        code: impl Into<String>,
        message: impl Into<String>,
        primary: Option<TransformDiagnosticLocationV1>,
        notes: Vec<String>,
    ) -> Result<Self, PreparedRecordError> {
        let diagnostic = Self {
            severity,
            code: code.into(),
            message: message.into(),
            primary,
            notes,
        };
        diagnostic.validate()?;
        Ok(diagnostic)
    }

    fn validate(&self) -> Result<(), PreparedRecordError> {
        if self.severity == TransformDiagnosticSeverityV1::Error {
            return Err(PreparedRecordError::InvalidField {
                field: "transform diagnostic severity",
                reason: "successful transforms cannot contain error diagnostics",
            });
        }
        validate_diagnostic_code(&self.code)?;
        validate_diagnostic_text("transform diagnostic message", &self.message)?;
        check_limit(
            "transform diagnostic notes",
            self.notes.len(),
            MAX_TRANSFORM_DIAGNOSTIC_NOTES,
        )?;
        let mut total = self.message.len();
        for note in &self.notes {
            validate_diagnostic_text("transform diagnostic note", note)?;
            total = total.saturating_add(note.len());
        }
        check_limit(
            "transform diagnostic text bytes",
            total,
            MAX_TRANSFORM_DIAGNOSTIC_TOTAL_TEXT_BYTES,
        )?;
        if let Some(primary) = &self.primary {
            primary.validate()?;
        }
        Ok(())
    }

    #[must_use]
    pub const fn severity(&self) -> TransformDiagnosticSeverityV1 {
        self.severity
    }
    #[must_use]
    pub fn code(&self) -> &str {
        &self.code
    }
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }
    #[must_use]
    pub const fn primary(&self) -> Option<&TransformDiagnosticLocationV1> {
        self.primary.as_ref()
    }
    #[must_use]
    pub fn notes(&self) -> &[String] {
        &self.notes
    }
}

impl TransformResourceV1 {
    pub fn new(name: impl Into<String>, digest: Digest) -> Result<Self, PreparedRecordError> {
        let name = name.into();
        validate_label("transform resource name", &name)?;
        Ok(Self { name, digest })
    }

    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }
    #[must_use]
    pub const fn digest(&self) -> &Digest {
        &self.digest
    }
}

/// The closed built-in or component identity of a persisted transform.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum TransformImplementationV1 {
    BuiltIn {
        implementation: String,
    },
    Component {
        pack_node_id: PackNodeId,
        pack_content_digest: Digest,
        component_path: String,
        component_digest: Digest,
        interface_version: String,
        execution_profile_digest: Digest,
    },
}

impl TransformImplementationV1 {
    pub fn built_in(implementation: impl Into<String>) -> Result<Self, PreparedRecordError> {
        let implementation = implementation.into();
        validate_label("built-in transform implementation", &implementation)?;
        Ok(Self::BuiltIn { implementation })
    }

    pub fn component(
        pack_node_id: PackNodeId,
        pack_content_digest: Digest,
        component_path: impl Into<String>,
        component_digest: Digest,
        interface_version: impl Into<String>,
        execution_profile_digest: Digest,
    ) -> Result<Self, PreparedRecordError> {
        let component_path = component_path.into();
        validate_relative_path(&component_path)?;
        let interface_version = interface_version.into();
        if interface_version != "format-component/v1" {
            return Err(PreparedRecordError::InvalidField {
                field: "format component interface version",
                reason: "must be exactly format-component/v1",
            });
        }
        Ok(Self::Component {
            pack_node_id,
            pack_content_digest,
            component_path,
            component_digest,
            interface_version,
            execution_profile_digest,
        })
    }

    fn validate(&self) -> Result<(), PreparedRecordError> {
        match self {
            Self::BuiltIn { implementation } => {
                validate_label("built-in transform implementation", implementation)
            }
            Self::Component {
                component_path,
                interface_version,
                ..
            } => {
                validate_relative_path(component_path)?;
                if interface_version != "format-component/v1" {
                    return Err(PreparedRecordError::InvalidField {
                        field: "format component interface version",
                        reason: "must be exactly format-component/v1",
                    });
                }
                Ok(())
            }
        }
    }
}

/// Exact provenance for a persisted deterministic format-transform result.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransformProvenanceV1 {
    name: String,
    implementation: TransformImplementationV1,
    pub(crate) request_digest: Digest,
    document_digest: Digest,
    #[serde(deserialize_with = "deserialize_transform_resources")]
    resources: Vec<TransformResourceV1>,
    response_digest: Digest,
    #[serde(deserialize_with = "deserialize_transform_diagnostics")]
    diagnostics: Vec<TransformDiagnosticV1>,
}

impl TransformProvenanceV1 {
    pub fn new(
        name: impl Into<String>,
        implementation: TransformImplementationV1,
        request_digest: Digest,
        document_digest: Digest,
        mut resources: Vec<TransformResourceV1>,
        response_digest: Digest,
        mut diagnostics: Vec<TransformDiagnosticV1>,
    ) -> Result<Self, PreparedRecordError> {
        let name = name.into();
        validate_label("transform name", &name)?;
        check_limit(
            "transform resources",
            resources.len(),
            MAX_TRANSFORM_RESOURCES,
        )?;
        resources.sort();
        reject_duplicates(
            "transform resource",
            resources.iter().map(|resource| resource.name.as_str()),
        )?;
        diagnostics.sort();
        let provenance = Self {
            name,
            implementation,
            request_digest,
            document_digest,
            resources,
            response_digest,
            diagnostics,
        };
        provenance.validate()?;
        Ok(provenance)
    }

    pub(crate) fn validate(&self) -> Result<(), PreparedRecordError> {
        validate_label("transform name", &self.name)?;
        self.implementation.validate()?;
        check_limit(
            "transform resources",
            self.resources.len(),
            MAX_TRANSFORM_RESOURCES,
        )?;
        for resource in &self.resources {
            validate_label("transform resource name", &resource.name)?;
        }
        reject_duplicates(
            "transform resource",
            self.resources.iter().map(|resource| resource.name.as_str()),
        )?;
        check_limit(
            "transform diagnostics",
            self.diagnostics.len(),
            MAX_TRANSFORM_DIAGNOSTICS,
        )?;
        let mut total = 0_usize;
        for diagnostic in &self.diagnostics {
            diagnostic.validate()?;
            total = total
                .saturating_add(diagnostic.message.len())
                .saturating_add(diagnostic.notes.iter().map(String::len).sum::<usize>());
        }
        if self.diagnostics.windows(2).any(|pair| pair[0] >= pair[1]) {
            return Err(PreparedRecordError::InvalidField {
                field: "transform diagnostics",
                reason: "must be unique and in canonical order",
            });
        }
        check_limit(
            "transform diagnostic text bytes",
            total,
            MAX_TRANSFORM_DIAGNOSTIC_TOTAL_TEXT_BYTES,
        )?;
        Ok(())
    }

    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }
    #[must_use]
    pub const fn implementation(&self) -> &TransformImplementationV1 {
        &self.implementation
    }
    #[must_use]
    pub const fn request_digest(&self) -> &Digest {
        &self.request_digest
    }
    #[must_use]
    pub const fn document_digest(&self) -> &Digest {
        &self.document_digest
    }
    #[must_use]
    pub fn resources(&self) -> &[TransformResourceV1] {
        &self.resources
    }
    #[must_use]
    pub const fn response_digest(&self) -> &Digest {
        &self.response_digest
    }
    #[must_use]
    pub fn diagnostics(&self) -> &[TransformDiagnosticV1] {
        &self.diagnostics
    }
}

/// Stable filesystem identity captured without following a leaf symlink.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileIdentityV1 {
    pub device: u64,
    pub inode: u64,
    pub user_id: u32,
    pub group_id: u32,
    pub mode: u32,
    pub links: u64,
    pub size: u64,
    pub modified_seconds: i64,
    pub modified_nanoseconds: u32,
    pub changed_seconds: i64,
    pub changed_nanoseconds: u32,
}

/// Expected state of the observed destination leaf.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "state", content = "identity", rename_all = "kebab-case")]
pub enum LeafObservationV1 {
    Absent,
    Present(FileIdentityV1),
}

/// Descriptor-relative traversal observations for one managed destination.
///
/// `missing_ancestors` counts trailing parent segments that did not exist when
/// the destination was observed. Directory operations earlier in the same plan
/// must create them. `parent` identifies the deepest existing directory, and
/// `ancestors` contains only existing intermediate identities. A zero count is
/// omitted from the canonical encoding, preserving the bytes and identities of
/// plans that do not encounter missing ancestors.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TargetObservationV1 {
    authority: DeploymentName,
    relative_path: String,
    traversal_anchor: FileIdentityV1,
    ancestors: Vec<FileIdentityV1>,
    parent: FileIdentityV1,
    leaf: LeafObservationV1,
    #[serde(default, skip_serializing_if = "missing_ancestors_is_zero")]
    missing_ancestors: u32,
}

fn missing_ancestors_is_zero(missing_ancestors: &u32) -> bool {
    *missing_ancestors == 0
}

impl TargetObservationV1 {
    pub fn new(
        authority: DeploymentName,
        relative_path: impl Into<String>,
        traversal_anchor: FileIdentityV1,
        ancestors: Vec<FileIdentityV1>,
        parent: FileIdentityV1,
        leaf: LeafObservationV1,
    ) -> Result<Self, PreparedRecordError> {
        Self::with_missing_ancestors(
            authority,
            relative_path,
            traversal_anchor,
            ancestors,
            parent,
            leaf,
            0,
        )
    }

    pub fn with_missing_ancestors(
        authority: DeploymentName,
        relative_path: impl Into<String>,
        traversal_anchor: FileIdentityV1,
        ancestors: Vec<FileIdentityV1>,
        parent: FileIdentityV1,
        leaf: LeafObservationV1,
        missing_ancestors: u32,
    ) -> Result<Self, PreparedRecordError> {
        let relative_path = relative_path.into();
        validate_relative_path(&relative_path)?;
        check_limit("target ancestors", ancestors.len(), 64)?;
        if missing_ancestors > 0 {
            if !matches!(leaf, LeafObservationV1::Absent) {
                return Err(PreparedRecordError::InvalidField {
                    field: "target observation",
                    reason: "missing ancestors require an absent leaf",
                });
            }
            let parent_segments = relative_path.matches('/').count();
            let missing = usize::try_from(missing_ancestors).unwrap_or(usize::MAX);
            if missing > parent_segments
                || ancestors.len() != (parent_segments - missing).saturating_sub(1)
            {
                return Err(PreparedRecordError::InvalidField {
                    field: "target observation",
                    reason: "missing ancestor count does not match the traversal shape",
                });
            }
        }
        Ok(Self {
            authority,
            relative_path,
            traversal_anchor,
            ancestors,
            parent,
            leaf,
            missing_ancestors,
        })
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
    pub const fn traversal_anchor(&self) -> FileIdentityV1 {
        self.traversal_anchor
    }
    #[must_use]
    pub fn ancestors(&self) -> &[FileIdentityV1] {
        &self.ancestors
    }
    #[must_use]
    pub const fn parent(&self) -> FileIdentityV1 {
        self.parent
    }
    #[must_use]
    pub const fn leaf(&self) -> LeafObservationV1 {
        self.leaf
    }

    /// The number of trailing parent segments that earlier directory operations must create.
    #[must_use]
    pub const fn missing_ancestors(&self) -> u32 {
        self.missing_ancestors
    }
}

/// Archive payload and decoder provenance retained for a tree operation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArchiveProvenanceV1 {
    payload: Digest,
    decoder: String,
}

impl ArchiveProvenanceV1 {
    pub fn new(payload: Digest, decoder: impl Into<String>) -> Result<Self, PreparedRecordError> {
        let decoder = decoder.into();
        validate_label("archive decoder", &decoder)?;
        Ok(Self { payload, decoder })
    }

    #[must_use]
    pub const fn payload(&self) -> &Digest {
        &self.payload
    }
    #[must_use]
    pub fn decoder(&self) -> &str {
        &self.decoder
    }
}

/// The closed set of filesystem operations accepted by commit/v1.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "kebab-case")]
pub enum PreparedOperationV1 {
    EnsureDirectory {
        observation: TargetObservationV1,
        mode: u32,
    },
    PlaceFile {
        observation: TargetObservationV1,
        artifact_id: ArtifactId,
        mode: u32,
        replace_existing: bool,
    },
    PlaceSymlink {
        observation: TargetObservationV1,
        object: Digest,
        replace_existing: bool,
    },
    PlaceTree {
        observation: TargetObservationV1,
        tree: Digest,
        archive_provenance: Option<ArchiveProvenanceV1>,
        replace_existing: bool,
    },
    RemoveLeaf {
        observation: TargetObservationV1,
    },
    AssertAbsent {
        observation: TargetObservationV1,
    },
    AssertExact {
        observation: TargetObservationV1,
        state: StateTargetStateV1,
    },
}

impl PreparedOperationV1 {
    #[must_use]
    pub const fn observation(&self) -> &TargetObservationV1 {
        match self {
            Self::EnsureDirectory { observation, .. }
            | Self::PlaceFile { observation, .. }
            | Self::PlaceSymlink { observation, .. }
            | Self::PlaceTree { observation, .. }
            | Self::RemoveLeaf { observation }
            | Self::AssertAbsent { observation }
            | Self::AssertExact { observation, .. } => observation,
        }
    }

    #[must_use]
    pub const fn artifact_id(&self) -> Option<&ArtifactId> {
        match self {
            Self::PlaceFile { artifact_id, .. } => Some(artifact_id),
            Self::EnsureDirectory { .. }
            | Self::PlaceSymlink { .. }
            | Self::PlaceTree { .. }
            | Self::RemoveLeaf { .. }
            | Self::AssertAbsent { .. }
            | Self::AssertExact { .. } => None,
        }
    }

    #[must_use]
    pub const fn replaces_existing(&self) -> bool {
        matches!(
            self,
            Self::EnsureDirectory {
                observation: TargetObservationV1 {
                    leaf: LeafObservationV1::Present(_),
                    ..
                },
                ..
            } | Self::PlaceFile {
                replace_existing: true,
                ..
            } | Self::PlaceSymlink {
                replace_existing: true,
                ..
            } | Self::PlaceTree {
                replace_existing: true,
                ..
            }
        )
    }

    #[must_use]
    pub const fn object_digest(&self) -> Option<&Digest> {
        match self {
            Self::PlaceSymlink { object, .. } => Some(object),
            _ => None,
        }
    }

    #[must_use]
    pub const fn tree_digest(&self) -> Option<&Digest> {
        match self {
            Self::PlaceTree { tree, .. } => Some(tree),
            _ => None,
        }
    }

    #[must_use]
    pub const fn archive_provenance(&self) -> Option<&ArchiveProvenanceV1> {
        match self {
            Self::PlaceTree {
                archive_provenance, ..
            } => archive_provenance.as_ref(),
            _ => None,
        }
    }

    #[must_use]
    pub const fn asserted_state(&self) -> Option<&StateTargetStateV1> {
        match self {
            Self::AssertExact { state, .. } => Some(state),
            _ => None,
        }
    }
}

/// An immutable policy finding shown before approval.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyFindingV1 {
    id: Digest,
    code: String,
    message: String,
    approval_required: bool,
}

impl PolicyFindingV1 {
    pub fn new(
        code: impl Into<String>,
        message: impl Into<String>,
        approval_required: bool,
    ) -> Result<Self, PreparedRecordError> {
        let code = code.into();
        let message = message.into();
        validate_label("policy finding code", &code)?;
        validate_text("policy finding message", &message, 64 * 1024)?;
        let id = policy_finding_id_v1(&code, &message, approval_required);
        Ok(Self {
            id,
            code,
            message,
            approval_required,
        })
    }

    #[must_use]
    pub const fn id(&self) -> &Digest {
        &self.id
    }
    #[must_use]
    pub fn code(&self) -> &str {
        &self.code
    }
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }
    #[must_use]
    pub const fn approval_required(&self) -> bool {
        self.approval_required
    }
}

/// The complete immutable input accepted by commit/v1.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreparedRecordV1 {
    schema_version: u32,
    schema_versions: SchemaVersionsV1,
    pub(crate) namespace: NamespaceName,
    expected_head: Option<Digest>,
    pub(crate) transition: PreparedTransitionV1,
    pub(crate) lifecycle: LifecycleStateV1,
    pub(crate) restore_point: Option<RestorePointV1>,
    pub(crate) retention: RetentionAuthorityV1,
    pub(crate) tracked_root: Option<TrackedRootV1>,
    graph_digest: Digest,
    inputs: Vec<PreparedInputV1>,
    pub(crate) artifacts: Vec<PreparedArtifactV1>,
    pub(crate) transforms: Vec<TransformProvenanceV1>,
    findings: Vec<PolicyFindingV1>,
    approval_digest: Digest,
    operations: Vec<PreparedOperationV1>,
    pub(crate) desired_snapshot: DesiredSnapshotV1,
    pub(crate) desired_snapshot_digest: Digest,
}

/// Fields used to build a canonical [`PreparedRecordV1`].
///
/// Conversion into [`PreparedRecordV1`] enforces every section limit, sorts and
/// deduplicates each section, validates transform provenance, desired-snapshot
/// targets, artifact byte budgets, and operation semantics, and derives the
/// approval and desired-snapshot digests.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreparedRecordPartsV1 {
    pub namespace: NamespaceName,
    pub expected_head: Option<Digest>,
    pub graph_digest: Digest,
    pub inputs: Vec<PreparedInputV1>,
    pub artifacts: Vec<PreparedArtifactV1>,
    pub transforms: Vec<TransformProvenanceV1>,
    pub findings: Vec<PolicyFindingV1>,
    pub operations: Vec<PreparedOperationV1>,
    pub desired_snapshot: DesiredSnapshotV1,
}

impl TryFrom<PreparedRecordPartsV1> for PreparedRecordV1 {
    type Error = PreparedRecordError;

    fn try_from(parts: PreparedRecordPartsV1) -> Result<Self, Self::Error> {
        let PreparedRecordPartsV1 {
            namespace,
            expected_head,
            graph_digest,
            mut inputs,
            mut artifacts,
            mut transforms,
            mut findings,
            operations,
            desired_snapshot,
        } = parts;
        check_limit("inputs", inputs.len(), MAX_PREPARED_INPUTS)?;
        check_limit("artifacts", artifacts.len(), MAX_PREPARED_ARTIFACTS)?;
        check_limit(
            "transform provenance",
            transforms.len(),
            MAX_TRANSFORM_PROVENANCE,
        )?;
        check_limit("policy findings", findings.len(), MAX_POLICY_FINDINGS)?;
        check_limit("operations", operations.len(), MAX_PREPARED_OPERATIONS)?;
        validate_state_targets(desired_snapshot.targets())
            .map_err(|error| PreparedRecordError::InvalidDesiredSnapshot(error.to_string()))?;
        for transform in &transforms {
            transform.validate()?;
        }

        inputs.sort_by(|left, right| {
            (left.kind, left.name.as_str()).cmp(&(right.kind, right.name.as_str()))
        });
        reject_duplicates(
            "prepared input",
            inputs.iter().map(|input| (input.kind, input.name.as_str())),
        )?;
        artifacts.sort_by(|left, right| left.id.cmp(&right.id));
        reject_duplicates(
            "artifact",
            artifacts.iter().map(|artifact| artifact.id.as_str()),
        )?;
        transforms.sort_by(|left, right| left.request_digest.cmp(&right.request_digest));
        reject_duplicates(
            "transform request",
            transforms
                .iter()
                .map(|provenance| provenance.request_digest.as_str()),
        )?;
        findings.sort_by(|left, right| left.id.cmp(&right.id));
        reject_duplicates(
            "policy finding",
            findings.iter().map(|finding| finding.id.as_str()),
        )?;
        reject_duplicates(
            "operation destination",
            operations.iter().map(|operation| {
                (
                    operation.observation().authority().as_str(),
                    operation.observation().relative_path(),
                )
            }),
        )?;
        reject_destination_prefixes(&operations)?;

        let mut artifact_lengths = BTreeMap::new();
        let mut unique_artifact_bytes = 0_u64;
        for artifact in &artifacts {
            if artifact.byte_len > MAX_ARTIFACT_BLOB_BYTES {
                return Err(PreparedRecordError::InvalidField {
                    field: "artifact byte length",
                    reason: "exceeds the per-blob size limit",
                });
            }
            if artifact.byte_len == 0 && artifact.digest != Digest::sha256([]) {
                return Err(PreparedRecordError::InvalidField {
                    field: "artifact byte length",
                    reason: "zero-byte artifacts must have the empty SHA-256 digest",
                });
            }
            if let Some(previous) = artifact_lengths.insert(&artifact.digest, artifact.byte_len) {
                if previous != artifact.byte_len {
                    return Err(PreparedRecordError::InvalidField {
                        field: "artifact byte length",
                        reason: "one digest cannot have conflicting lengths",
                    });
                }
            } else {
                unique_artifact_bytes = unique_artifact_bytes
                    .checked_add(artifact.byte_len)
                    .ok_or(PreparedRecordError::InvalidField {
                        field: "artifact bytes",
                        reason: "aggregate byte length overflows",
                    })?;
            }
        }
        if unique_artifact_bytes > MAX_PREPARED_UNIQUE_ARTIFACT_BYTES {
            return Err(PreparedRecordError::InvalidField {
                field: "artifact bytes",
                reason: "aggregate unique blob bytes exceed the plan limit",
            });
        }
        for operation in &operations {
            if let Some(artifact_id) = operation.artifact_id()
                && artifacts
                    .binary_search_by(|artifact| artifact.id.cmp(artifact_id))
                    .is_err()
            {
                return Err(PreparedRecordError::UnknownArtifact(artifact_id.clone()));
            }
            let mode = match operation {
                PreparedOperationV1::EnsureDirectory { mode, .. }
                | PreparedOperationV1::PlaceFile { mode, .. } => Some(*mode),
                PreparedOperationV1::PlaceSymlink { .. }
                | PreparedOperationV1::PlaceTree { .. }
                | PreparedOperationV1::RemoveLeaf { .. }
                | PreparedOperationV1::AssertAbsent { .. }
                | PreparedOperationV1::AssertExact { .. } => None,
            };
            if mode.is_some_and(|mode| mode & !0o777 != 0) {
                return Err(PreparedRecordError::InvalidField {
                    field: "operation mode",
                    reason: "must contain only permission bits",
                });
            }
            match operation {
                PreparedOperationV1::EnsureDirectory { mode, .. } if mode & 0o500 != 0o500 => {
                    return Err(PreparedRecordError::InvalidField {
                        field: "directory operation mode",
                        reason: "must remain owner-readable and owner-searchable for recovery",
                    });
                }
                PreparedOperationV1::PlaceFile { mode, .. } if mode & 0o400 == 0 => {
                    return Err(PreparedRecordError::InvalidField {
                        field: "file operation mode",
                        reason: "must remain owner-readable for verification and recovery",
                    });
                }
                _ => {}
            }
            validate_operation_semantics(operation)?;
        }

        let approval_digest = policy_approval_digest_v1(
            findings
                .iter()
                .map(|finding| (finding.id.clone(), finding.approval_required)),
        );
        let desired_snapshot_digest = desired_snapshot_digest_v1(&namespace, &desired_snapshot);
        let record = Self {
            schema_version: PREPARED_RECORD_SCHEMA_VERSION,
            schema_versions: SchemaVersionsV1::default(),
            namespace,
            expected_head,
            transition: PreparedTransitionV1::Reconcile,
            lifecycle: LifecycleStateV1::Enabled,
            restore_point: None,
            retention: RetentionAuthorityV1::default(),
            tracked_root: None,
            graph_digest,
            inputs,
            artifacts,
            transforms,
            findings,
            approval_digest,
            operations,
            desired_snapshot,
            desired_snapshot_digest,
        };
        record.validate_encoded_size()?;
        Ok(record)
    }
}

impl PreparedRecordV1 {
    pub fn with_lifecycle_state(
        mut self,
        lifecycle: LifecycleStateV1,
    ) -> Result<Self, PreparedRecordError> {
        self.lifecycle = lifecycle;
        self.validate_encoded_size()?;
        Ok(self)
    }

    pub fn with_lifecycle(self, lifecycle: LifecycleStateV1) -> Result<Self, PreparedRecordError> {
        self.with_lifecycle_state(lifecycle)
    }

    pub fn with_transition(
        mut self,
        transition: PreparedTransitionV1,
    ) -> Result<Self, PreparedRecordError> {
        self.transition = transition;
        self.validate_encoded_size()?;
        Ok(self)
    }

    pub fn with_restore_point(
        mut self,
        restore_point: Option<RestorePointV1>,
    ) -> Result<Self, PreparedRecordError> {
        if let Some(point) = &restore_point {
            validate_restore_point(point, Some(&self.namespace))?;
        }
        self.restore_point = restore_point;
        self.validate_encoded_size()?;
        Ok(self)
    }

    pub fn with_retention_authority(
        mut self,
        retention: RetentionAuthorityV1,
    ) -> Result<Self, PreparedRecordError> {
        validate_retention_authority(&retention, Some(&self.namespace))?;
        self.retention = retention;
        self.validate_encoded_size()?;
        Ok(self)
    }

    pub fn with_tracked_root(
        mut self,
        tracked_root: Option<TrackedRootV1>,
    ) -> Result<Self, PreparedRecordError> {
        if let Some(tracked_root) = &tracked_root {
            validate_tracked_root(tracked_root)?;
        }
        self.tracked_root = tracked_root;
        self.validate_encoded_size()?;
        Ok(self)
    }

    fn validate_encoded_size(&self) -> Result<(), PreparedRecordError> {
        let actual = encode_prepared_record_v1(self).len();
        if actual > MAX_PREPARED_RECORD_BYTES {
            return Err(PreparedRecordError::TooLarge {
                limit: MAX_PREPARED_RECORD_BYTES,
                actual,
            });
        }
        Ok(())
    }

    #[must_use]
    pub const fn namespace(&self) -> &NamespaceName {
        &self.namespace
    }
    #[must_use]
    pub const fn expected_head(&self) -> Option<&Digest> {
        self.expected_head.as_ref()
    }
    #[must_use]
    pub const fn transition(&self) -> &PreparedTransitionV1 {
        &self.transition
    }

    /// Returns the lifecycle state intended by this transition.
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

    /// Returns the next tracked-root state. `None` clears tracking.
    #[must_use]
    pub const fn tracked_root(&self) -> Option<&TrackedRootV1> {
        self.tracked_root.as_ref()
    }
    #[must_use]
    pub const fn graph_digest(&self) -> &Digest {
        &self.graph_digest
    }
    #[must_use]
    pub fn inputs(&self) -> &[PreparedInputV1] {
        &self.inputs
    }
    #[must_use]
    pub fn artifacts(&self) -> &[PreparedArtifactV1] {
        &self.artifacts
    }
    #[must_use]
    pub fn transforms(&self) -> &[TransformProvenanceV1] {
        &self.transforms
    }
    #[must_use]
    pub fn findings(&self) -> &[PolicyFindingV1] {
        &self.findings
    }
    #[must_use]
    pub const fn approval_digest(&self) -> &Digest {
        &self.approval_digest
    }
    #[must_use]
    pub fn operations(&self) -> &[PreparedOperationV1] {
        &self.operations
    }

    /// Returns the complete canonical desired snapshot bound by this plan.
    #[must_use]
    pub const fn desired_snapshot(&self) -> &DesiredSnapshotV1 {
        &self.desired_snapshot
    }

    /// Returns the domain-separated digest of the complete desired snapshot.
    #[must_use]
    pub const fn desired_snapshot_digest(&self) -> &Digest {
        &self.desired_snapshot_digest
    }
}

pub(crate) fn validate_operation_semantics(
    operation: &PreparedOperationV1,
) -> Result<(), PreparedRecordError> {
    match operation {
        PreparedOperationV1::EnsureDirectory { .. } => {}
        PreparedOperationV1::PlaceFile {
            observation,
            replace_existing,
            ..
        } => {
            if let LeafObservationV1::Present(_) = observation.leaf()
                && !replace_existing
            {
                return Err(PreparedRecordError::InvalidField {
                    field: "place-file conflict policy",
                    reason: "an existing leaf requires replacement permission",
                });
            }
        }
        PreparedOperationV1::PlaceSymlink {
            observation,
            replace_existing,
            ..
        } => {
            if let LeafObservationV1::Present(_) = observation.leaf()
                && !replace_existing
            {
                return Err(PreparedRecordError::InvalidField {
                    field: "place-symlink conflict policy",
                    reason: "an existing leaf requires replacement permission",
                });
            }
        }
        PreparedOperationV1::PlaceTree {
            observation,
            replace_existing,
            ..
        } => {
            if let LeafObservationV1::Present(_) = observation.leaf()
                && !replace_existing
            {
                return Err(PreparedRecordError::InvalidField {
                    field: "place-tree conflict policy",
                    reason: "an existing leaf requires replacement permission",
                });
            }
        }
        PreparedOperationV1::RemoveLeaf { .. } => {}
        PreparedOperationV1::AssertAbsent { observation } => {
            if !matches!(observation.leaf(), LeafObservationV1::Absent) {
                return Err(PreparedRecordError::InvalidField {
                    field: "assert-absent leaf",
                    reason: "an absence assertion requires an absent leaf",
                });
            }
        }
        PreparedOperationV1::AssertExact { observation, state } => {
            if !matches!(observation.leaf(), LeafObservationV1::Present(_)) {
                return Err(PreparedRecordError::InvalidField {
                    field: "assert-exact leaf",
                    reason: "an exact assertion requires a present leaf",
                });
            }
            if !state_is_present(state) {
                return Err(PreparedRecordError::InvalidField {
                    field: "assert-exact state",
                    reason: "an exact assertion requires present desired state",
                });
            }
            validate_target_state(state)
                .map_err(|error| PreparedRecordError::InvalidDesiredSnapshot(error.to_string()))?;
        }
    }
    Ok(())
}

/// Strict prepared-record decoding or semantic failure.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
#[non_exhaustive]
pub enum PreparedRecordError {
    #[error("prepared record has {actual} bytes; limit is {limit}")]
    TooLarge { limit: usize, actual: usize },
    #[error("invalid prepared record: {0}")]
    InvalidJson(String),
    #[error("unsupported prepared record version {found}; expected {expected}")]
    UnsupportedVersion { expected: u32, found: u32 },
    #[error("prepared record is not canonical")]
    NonCanonical,
    #[error("prepared record identity mismatch: expected {expected}, computed {actual}")]
    DigestMismatch {
        expected: PreparedId,
        actual: PreparedId,
    },
    #[error("{field} count {actual} exceeds limit {limit}")]
    LimitExceeded {
        field: &'static str,
        limit: usize,
        actual: usize,
    },
    #[error("duplicate {field}")]
    Duplicate { field: &'static str },
    #[error("invalid {field}: {reason}")]
    InvalidField {
        field: &'static str,
        reason: &'static str,
    },
    #[error("invalid desired snapshot: {0}")]
    InvalidDesiredSnapshot(String),
    #[error("operation references artifact {0}")]
    UnknownArtifact(ArtifactId),
}

impl From<malm_types::ValidationError> for PreparedRecordError {
    fn from(error: malm_types::ValidationError) -> Self {
        Self::InvalidField {
            field: error.field,
            reason: error.reason,
        }
    }
}

/// Encodes one validated record as canonical JSON ending in one newline.
#[must_use]
pub fn encode_prepared_record_v1(record: &PreparedRecordV1) -> Vec<u8> {
    let mut bytes = serde_json::to_vec(record).expect("validated store records always serialize");
    bytes.push(b'\n');
    bytes
}

/// Computes the full SHA-256 plan identity of canonical record bytes.
#[must_use]
pub fn prepared_id_v1(record: &PreparedRecordV1) -> PreparedId {
    PreparedId::from_digest(&Digest::sha256(encode_prepared_record_v1(record)))
}

/// Strictly decodes canonical bytes and verifies their filename identity.
pub fn decode_prepared_record_v1(
    expected: &PreparedId,
    bytes: &[u8],
) -> Result<PreparedRecordV1, PreparedRecordError> {
    if bytes.len() > MAX_PREPARED_RECORD_BYTES {
        return Err(PreparedRecordError::TooLarge {
            limit: MAX_PREPARED_RECORD_BYTES,
            actual: bytes.len(),
        });
    }
    let record: PreparedRecordV1 = serde_json::from_slice(bytes)
        .map_err(|error| PreparedRecordError::InvalidJson(error.to_string()))?;
    if record.schema_version != PREPARED_RECORD_SCHEMA_VERSION {
        return Err(PreparedRecordError::UnsupportedVersion {
            expected: PREPARED_RECORD_SCHEMA_VERSION,
            found: record.schema_version,
        });
    }
    let canonical = encode_prepared_record_v1(&record);
    if canonical != bytes {
        return Err(PreparedRecordError::NonCanonical);
    }
    let actual = PreparedId::from_digest(&Digest::sha256(bytes));
    if &actual != expected {
        return Err(PreparedRecordError::DigestMismatch {
            expected: expected.clone(),
            actual,
        });
    }
    validate_decoded(&record)?;
    Ok(record)
}

fn validate_decoded(record: &PreparedRecordV1) -> Result<(), PreparedRecordError> {
    let tracked_root = record
        .tracked_root
        .as_ref()
        .map(rebuild_tracked_root)
        .transpose()?;
    if desired_snapshot_digest_v1(&record.namespace, &record.desired_snapshot)
        != record.desired_snapshot_digest
    {
        return Err(PreparedRecordError::InvalidDesiredSnapshot(
            "digest differs from the complete persisted snapshot".to_owned(),
        ));
    }
    let desired_snapshot = DesiredSnapshotV1::new(record.desired_snapshot.0.clone())
        .map_err(|error| PreparedRecordError::InvalidDesiredSnapshot(error.to_string()))?;
    let rebuilt = PreparedRecordV1::try_from(PreparedRecordPartsV1 {
        namespace: record.namespace.clone(),
        expected_head: record.expected_head.clone(),
        graph_digest: record.graph_digest.clone(),
        inputs: record.inputs.clone(),
        artifacts: record.artifacts.clone(),
        transforms: record.transforms.clone(),
        findings: record.findings.clone(),
        operations: record.operations.clone(),
        desired_snapshot,
    })?
    .with_transition(record.transition.clone())?
    .with_lifecycle_state(record.lifecycle)?
    .with_restore_point(record.restore_point.clone())?
    .with_retention_authority(record.retention.clone())?
    .with_tracked_root(tracked_root)?;
    if !matches!(
        record.transition,
        PreparedTransitionV1::NamespaceRemoval { .. }
    ) {
        validate_selected_restore_authority(
            record.lifecycle,
            record.restore_point.as_ref(),
            &record.retention,
        )?;
    }
    if &rebuilt != record {
        return Err(PreparedRecordError::NonCanonical);
    }
    Ok(())
}

fn rebuild_tracked_root(
    tracked_root: &TrackedRootV1,
) -> Result<TrackedRootV1, PreparedRecordError> {
    if tracked_root.schema_version != TRACKED_ROOT_SCHEMA_VERSION {
        return Err(PreparedRecordError::UnsupportedVersion {
            expected: TRACKED_ROOT_SCHEMA_VERSION,
            found: tracked_root.schema_version,
        });
    }
    TrackedRootV1::new(
        tracked_root.source_locator.clone(),
        tracked_root.moving_selector.clone(),
        tracked_root.applied_revision.clone(),
        tracked_root.root_tree_digest.clone(),
        tracked_root.config_entry_point.clone(),
        tracked_root.selected_profile.clone(),
        tracked_root.acquisition_grants.clone(),
    )?
    .with_source_subdir(tracked_root.source_subdir.clone())
}

#[cfg(test)]
mod tests;
