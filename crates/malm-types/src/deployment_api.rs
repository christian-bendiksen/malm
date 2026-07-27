//! Stable deployment DTOs shared by Engine and its adapters.

use serde::{Deserialize, Serialize};

use crate::{
    ArtifactId, ContributionName, DeploymentName, Digest, LifecycleStateViewV1,
    LifecycleTransitionViewV1, NamespaceName, PackNodeId, PreparedId, RestorePointInspectionV1,
    RetentionAuthorityInspectionV1,
};

/// Maximum diagnostics retained for a successful transform.
pub const MAX_TRANSFORM_DIAGNOSTICS_V1: usize = 256;
/// Maximum resource identities retained for one transform.
pub const MAX_TRANSFORM_RESOURCES_V1: usize = 1024;
/// Maximum bytes in one diagnostic message or note.
pub const MAX_TRANSFORM_DIAGNOSTIC_TEXT_BYTES_V1: usize = 16 * 1024;
/// Maximum notes retained by one diagnostic.
pub const MAX_TRANSFORM_DIAGNOSTIC_NOTES_V1: usize = 64;
/// Maximum total message and note bytes retained for one transform.
pub const MAX_TRANSFORM_DIAGNOSTIC_TOTAL_TEXT_BYTES_V1: usize = 1024 * 1024;
/// Maximum source-document length referenced by transform diagnostics.
pub const MAX_TRANSFORM_SOURCE_DOCUMENT_BYTES_V1: u64 = 1024 * 1024;
/// Interface ID for a `format-component/v1` declaration.
pub const FORMAT_COMPONENT_INTERFACE_V1: &str = "format-component/v1";

/// An immutable successor-store object selected by explicit retention authority.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum RetentionObjectV1 {
    PreparedPlan { plan_id: PreparedId },
    StateGeneration { digest: Digest },
    ArtifactBlob { digest: Digest },
    PackObject { digest: Digest },
    CanonicalFile { digest: Digest },
    CanonicalSymlink { digest: Digest },
    CanonicalTree { digest: Digest },
}

impl RetentionObjectV1 {
    #[must_use]
    pub const fn digest(&self) -> Option<&Digest> {
        match self {
            Self::PreparedPlan { .. } => None,
            Self::StateGeneration { digest }
            | Self::ArtifactBlob { digest }
            | Self::PackObject { digest }
            | Self::CanonicalFile { digest }
            | Self::CanonicalSymlink { digest }
            | Self::CanonicalTree { digest } => Some(digest),
        }
    }

    #[must_use]
    pub const fn plan_id(&self) -> Option<&PreparedId> {
        match self {
            Self::PreparedPlan { plan_id } => Some(plan_id),
            _ => None,
        }
    }
}

/// The kind of immutable provenance input supplied to prepare.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum PrepareInputKindV1 {
    Source,
    Config,
    Lock,
    Component,
    Asset,
    Other,
}

/// A named immutable input captured by prepare orchestration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrepareInputV1 {
    kind: PrepareInputKindV1,
    name: String,
    digest: Digest,
}

impl PrepareInputV1 {
    pub fn new(
        kind: PrepareInputKindV1,
        name: impl Into<String>,
        digest: Digest,
    ) -> Result<Self, DeploymentDtoError> {
        let name = name.into();
        validate_label("prepare input name", &name)?;
        Ok(Self { kind, name, digest })
    }

    #[must_use]
    pub const fn kind(&self) -> PrepareInputKindV1 {
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

/// Prepared artifact bytes and presentation metadata.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrepareArtifactV1 {
    id: ArtifactId,
    bytes: Vec<u8>,
    media_type: String,
}

impl PrepareArtifactV1 {
    pub fn new(
        id: ArtifactId,
        bytes: Vec<u8>,
        media_type: impl Into<String>,
    ) -> Result<Self, DeploymentDtoError> {
        let media_type = media_type.into();
        validate_label("artifact media type", &media_type)?;
        Ok(Self {
            id,
            bytes,
            media_type,
        })
    }

    #[must_use]
    pub const fn id(&self) -> &ArtifactId {
        &self.id
    }
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    #[must_use]
    pub fn media_type(&self) -> &str {
        &self.media_type
    }
}

/// A resource identity consumed by a transform.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct PrepareTransformResourceV1 {
    name: String,
    digest: Digest,
}

/// Diagnostic severity allowed for a successful transform.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum PrepareTransformDiagnosticSeverityV1 {
    Error,
    Warning,
    Info,
}

/// A byte range in a locked config document.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct PrepareTransformSourceLocationV1 {
    authority_label: ContributionName,
    authority_identity: Digest,
    document_path: String,
    source_byte_len: u64,
    start: u32,
    end: u32,
}

impl PrepareTransformSourceLocationV1 {
    pub fn new(
        authority_label: ContributionName,
        authority_identity: Digest,
        document_path: impl Into<String>,
        source_byte_len: u64,
        start: u32,
        end: u32,
    ) -> Result<Self, DeploymentDtoError> {
        let document_path = document_path.into();
        validate_relative_path(&document_path)?;
        if source_byte_len > MAX_TRANSFORM_SOURCE_DOCUMENT_BYTES_V1 {
            return Err(DeploymentDtoError {
                field: "transform diagnostic source byte length",
                reason: "exceeds its byte limit",
            });
        }
        if start > end {
            return Err(DeploymentDtoError {
                field: "transform diagnostic source range",
                reason: "start must not exceed end",
            });
        }
        if u64::from(end) > source_byte_len {
            return Err(DeploymentDtoError {
                field: "transform diagnostic source range",
                reason: "end exceeds the exact captured source byte length",
            });
        }
        Ok(Self {
            authority_label,
            authority_identity,
            document_path,
            source_byte_len,
            start,
            end,
        })
    }

    #[must_use]
    pub const fn authority_label(&self) -> &ContributionName {
        &self.authority_label
    }
    #[must_use]
    pub const fn authority_identity(&self) -> &Digest {
        &self.authority_identity
    }
    #[must_use]
    pub fn document_path(&self) -> &str {
        &self.document_path
    }
    #[must_use]
    pub const fn source_byte_len(&self) -> u64 {
        self.source_byte_len
    }
    #[must_use]
    pub const fn start(&self) -> u32 {
        self.start
    }
    #[must_use]
    pub const fn end(&self) -> u32 {
        self.end
    }
}

/// A half-open byte range in generated transform output.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct PrepareTransformOutputLocationV1 {
    start: u64,
    end: u64,
}

impl PrepareTransformOutputLocationV1 {
    pub const fn new(start: u64, end: u64) -> Result<Self, DeploymentDtoError> {
        if start > end {
            return Err(DeploymentDtoError {
                field: "transform diagnostic output range",
                reason: "start must not exceed end",
            });
        }
        Ok(Self { start, end })
    }

    #[must_use]
    pub const fn start(self) -> u64 {
        self.start
    }
    #[must_use]
    pub const fn end(self) -> u64 {
        self.end
    }
}

/// The source or output location of a transform diagnostic.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum PrepareTransformDiagnosticLocationV1 {
    Source(PrepareTransformSourceLocationV1),
    Output(PrepareTransformOutputLocationV1),
}

/// A bounded diagnostic from a successful transform.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct PrepareTransformDiagnosticV1 {
    severity: PrepareTransformDiagnosticSeverityV1,
    code: String,
    message: String,
    primary: Option<PrepareTransformDiagnosticLocationV1>,
    notes: Vec<String>,
}

impl PrepareTransformDiagnosticV1 {
    pub fn new(
        severity: PrepareTransformDiagnosticSeverityV1,
        code: impl Into<String>,
        message: impl Into<String>,
        primary: Option<PrepareTransformDiagnosticLocationV1>,
        notes: Vec<String>,
    ) -> Result<Self, DeploymentDtoError> {
        if severity == PrepareTransformDiagnosticSeverityV1::Error {
            return Err(DeploymentDtoError {
                field: "transform diagnostic severity",
                reason: "successful transforms cannot contain error diagnostics",
            });
        }
        let code = code.into();
        validate_diagnostic_code(&code)?;
        let message = message.into();
        validate_diagnostic_text("transform diagnostic message", &message)?;
        if notes.len() > MAX_TRANSFORM_DIAGNOSTIC_NOTES_V1 {
            return Err(DeploymentDtoError {
                field: "transform diagnostic notes",
                reason: "exceeds its count limit",
            });
        }
        let mut total = message.len();
        for note in &notes {
            validate_diagnostic_text("transform diagnostic note", note)?;
            total = total.saturating_add(note.len());
        }
        if total > MAX_TRANSFORM_DIAGNOSTIC_TOTAL_TEXT_BYTES_V1 {
            return Err(DeploymentDtoError {
                field: "transform diagnostic text",
                reason: "exceeds its aggregate byte limit",
            });
        }
        Ok(Self {
            severity,
            code,
            message,
            primary,
            notes,
        })
    }

    #[must_use]
    pub const fn severity(&self) -> PrepareTransformDiagnosticSeverityV1 {
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
    pub const fn primary(&self) -> Option<&PrepareTransformDiagnosticLocationV1> {
        self.primary.as_ref()
    }
    #[must_use]
    pub fn notes(&self) -> &[String] {
        &self.notes
    }
}

impl PrepareTransformResourceV1 {
    pub fn new(name: impl Into<String>, digest: Digest) -> Result<Self, DeploymentDtoError> {
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

/// The implementation identity stored with a transform result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PrepareTransformImplementationV1 {
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

impl PrepareTransformImplementationV1 {
    pub fn built_in(implementation: impl Into<String>) -> Result<Self, DeploymentDtoError> {
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
    ) -> Result<Self, DeploymentDtoError> {
        let component_path = component_path.into();
        validate_relative_path(&component_path)?;
        let interface_version = interface_version.into();
        if interface_version != FORMAT_COMPONENT_INTERFACE_V1 {
            return Err(DeploymentDtoError {
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
}

/// Deterministic provenance for a transform result included in a plan.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrepareTransformProvenanceV1 {
    name: String,
    implementation: PrepareTransformImplementationV1,
    request_digest: Digest,
    document_digest: Digest,
    resources: Vec<PrepareTransformResourceV1>,
    response_digest: Digest,
    diagnostics: Vec<PrepareTransformDiagnosticV1>,
}

impl PrepareTransformProvenanceV1 {
    pub fn new(
        name: impl Into<String>,
        implementation: PrepareTransformImplementationV1,
        request_digest: Digest,
        document_digest: Digest,
        mut resources: Vec<PrepareTransformResourceV1>,
        response_digest: Digest,
        mut diagnostics: Vec<PrepareTransformDiagnosticV1>,
    ) -> Result<Self, DeploymentDtoError> {
        let name = name.into();
        validate_label("transform name", &name)?;
        if resources.len() > MAX_TRANSFORM_RESOURCES_V1 {
            return Err(DeploymentDtoError {
                field: "transform resources",
                reason: "exceeds its count limit",
            });
        }
        resources.sort();
        if resources
            .windows(2)
            .any(|pair| pair[0].name == pair[1].name)
        {
            return Err(DeploymentDtoError {
                field: "transform resources",
                reason: "resource names must be unique",
            });
        }
        diagnostics.sort();
        validate_transform_diagnostics(&diagnostics)?;
        Ok(Self {
            name,
            implementation,
            request_digest,
            document_digest,
            resources,
            response_digest,
            diagnostics,
        })
    }

    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }
    #[must_use]
    pub const fn implementation(&self) -> &PrepareTransformImplementationV1 {
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
    pub fn resources(&self) -> &[PrepareTransformResourceV1] {
        &self.resources
    }
    #[must_use]
    pub const fn response_digest(&self) -> &Digest {
        &self.response_digest
    }
    #[must_use]
    pub fn diagnostics(&self) -> &[PrepareTransformDiagnosticV1] {
        &self.diagnostics
    }
}

/// A policy finding stored for immutable review.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreparePolicyFindingV1 {
    code: String,
    message: String,
    approval_required: bool,
}

impl PreparePolicyFindingV1 {
    pub fn new(
        code: impl Into<String>,
        message: impl Into<String>,
        approval_required: bool,
    ) -> Result<Self, DeploymentDtoError> {
        let code = code.into();
        let message = message.into();
        validate_label("policy finding code", &code)?;
        validate_text("policy finding message", &message, 64 * 1024)?;
        Ok(Self {
            code,
            message,
            approval_required,
        })
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

/// Computes the canonical ID of a v1 policy finding.
#[must_use]
pub fn policy_finding_id_v1(code: &str, message: &str, approval_required: bool) -> Digest {
    let mut bytes = b"malm-policy-finding-v1\0".to_vec();
    append_policy_text(&mut bytes, code);
    append_policy_text(&mut bytes, message);
    bytes.push(u8::from(approval_required));
    Digest::sha256(bytes)
}

/// Computes the approval binding for all findings that require approval.
#[must_use]
pub fn policy_approval_digest_v1(findings: impl IntoIterator<Item = (Digest, bool)>) -> Digest {
    let mut ids = findings
        .into_iter()
        .filter_map(|(id, required)| required.then_some(id))
        .collect::<Vec<_>>();
    ids.sort();
    let mut bytes = b"malm-plan-approval-v1\0".to_vec();
    for id in ids {
        append_policy_text(&mut bytes, id.as_str());
    }
    Digest::sha256(bytes)
}

fn append_policy_text(bytes: &mut Vec<u8>, value: &str) {
    bytes.extend_from_slice(&crate::usize_to_u64(value.len()).to_be_bytes());
    bytes.extend_from_slice(value.as_bytes());
}

/// Archive payload and decoder provenance.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArchiveProvenanceV1 {
    payload: Digest,
    decoder: String,
}

impl ArchiveProvenanceV1 {
    pub fn new(payload: Digest, decoder: impl Into<String>) -> Result<Self, DeploymentDtoError> {
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

/// Exact logical state required by a no-mutation target assertion.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PrepareTargetStateV1 {
    File {
        digest: Digest,
        byte_len: u64,
        mode: u32,
    },
    Directory {
        mode: u32,
    },
    Symlink {
        object: Digest,
    },
    Tree {
        tree: Digest,
        archive_provenance: Option<ArchiveProvenanceV1>,
    },
}

impl PrepareTargetStateV1 {
    pub fn file(digest: Digest, byte_len: u64, mode: u32) -> Result<Self, DeploymentDtoError> {
        validate_file_mode(mode)?;
        Ok(Self::File {
            digest,
            byte_len,
            mode,
        })
    }

    pub fn directory(mode: u32) -> Result<Self, DeploymentDtoError> {
        validate_directory_mode(mode)?;
        Ok(Self::Directory { mode })
    }

    #[must_use]
    pub const fn symlink(object: Digest) -> Self {
        Self::Symlink { object }
    }

    #[must_use]
    pub const fn tree(tree: Digest) -> Self {
        Self::Tree {
            tree,
            archive_provenance: None,
        }
    }

    #[must_use]
    pub const fn archive_tree(tree: Digest, archive_provenance: ArchiveProvenanceV1) -> Self {
        Self::Tree {
            tree,
            archive_provenance: Some(archive_provenance),
        }
    }
}

/// An operation from the closed set requested before target observation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PrepareOperationV1 {
    EnsureDirectory {
        authority: DeploymentName,
        relative_path: String,
        mode: u32,
        replace_existing: bool,
    },
    PlaceFile {
        authority: DeploymentName,
        relative_path: String,
        artifact_id: ArtifactId,
        mode: u32,
        replace_existing: bool,
    },
    PlaceSymlink {
        authority: DeploymentName,
        relative_path: String,
        object: Digest,
        replace_existing: bool,
    },
    PlaceTree {
        authority: DeploymentName,
        relative_path: String,
        tree: Digest,
        archive_provenance: Option<ArchiveProvenanceV1>,
        replace_existing: bool,
    },
    RemoveLeaf {
        authority: DeploymentName,
        relative_path: String,
    },
    AssertAbsent {
        authority: DeploymentName,
        relative_path: String,
    },
    AssertExact {
        authority: DeploymentName,
        relative_path: String,
        state: PrepareTargetStateV1,
    },
}

impl PrepareOperationV1 {
    pub fn ensure_directory(
        authority: DeploymentName,
        relative_path: impl Into<String>,
        mode: u32,
    ) -> Result<Self, DeploymentDtoError> {
        validate_directory_mode(mode)?;
        let relative_path = relative_path.into();
        validate_relative_path(&relative_path)?;
        Ok(Self::EnsureDirectory {
            authority,
            relative_path,
            mode,
            replace_existing: false,
        })
    }

    pub fn replace_directory(
        authority: DeploymentName,
        relative_path: impl Into<String>,
        mode: u32,
    ) -> Result<Self, DeploymentDtoError> {
        let mut operation = Self::ensure_directory(authority, relative_path, mode)?;
        let Self::EnsureDirectory {
            replace_existing, ..
        } = &mut operation
        else {
            unreachable!("ensure_directory constructs EnsureDirectory")
        };
        *replace_existing = true;
        Ok(operation)
    }

    pub fn place_file(
        authority: DeploymentName,
        relative_path: impl Into<String>,
        artifact_id: ArtifactId,
        mode: u32,
    ) -> Result<Self, DeploymentDtoError> {
        validate_file_mode(mode)?;
        let relative_path = relative_path.into();
        validate_relative_path(&relative_path)?;
        Ok(Self::PlaceFile {
            authority,
            relative_path,
            artifact_id,
            mode,
            replace_existing: false,
        })
    }

    pub fn replace_file(
        authority: DeploymentName,
        relative_path: impl Into<String>,
        artifact_id: ArtifactId,
        mode: u32,
    ) -> Result<Self, DeploymentDtoError> {
        let mut operation = Self::place_file(authority, relative_path, artifact_id, mode)?;
        let Self::PlaceFile {
            replace_existing, ..
        } = &mut operation
        else {
            unreachable!("place_file constructs PlaceFile")
        };
        *replace_existing = true;
        Ok(operation)
    }

    pub fn place_symlink(
        authority: DeploymentName,
        relative_path: impl Into<String>,
        object: Digest,
    ) -> Result<Self, DeploymentDtoError> {
        let relative_path = relative_path.into();
        validate_relative_path(&relative_path)?;
        Ok(Self::PlaceSymlink {
            authority,
            relative_path,
            object,
            replace_existing: false,
        })
    }

    pub fn replace_symlink(
        authority: DeploymentName,
        relative_path: impl Into<String>,
        object: Digest,
    ) -> Result<Self, DeploymentDtoError> {
        let mut operation = Self::place_symlink(authority, relative_path, object)?;
        let Self::PlaceSymlink {
            replace_existing, ..
        } = &mut operation
        else {
            unreachable!("place_symlink constructs PlaceSymlink")
        };
        *replace_existing = true;
        Ok(operation)
    }

    pub fn place_tree(
        authority: DeploymentName,
        relative_path: impl Into<String>,
        tree: Digest,
    ) -> Result<Self, DeploymentDtoError> {
        Self::place_tree_with_provenance(authority, relative_path, tree, None)
    }

    pub fn place_archive_tree(
        authority: DeploymentName,
        relative_path: impl Into<String>,
        tree: Digest,
        archive_provenance: ArchiveProvenanceV1,
    ) -> Result<Self, DeploymentDtoError> {
        Self::place_tree_with_provenance(authority, relative_path, tree, Some(archive_provenance))
    }

    fn place_tree_with_provenance(
        authority: DeploymentName,
        relative_path: impl Into<String>,
        tree: Digest,
        archive_provenance: Option<ArchiveProvenanceV1>,
    ) -> Result<Self, DeploymentDtoError> {
        let relative_path = relative_path.into();
        validate_relative_path(&relative_path)?;
        Ok(Self::PlaceTree {
            authority,
            relative_path,
            tree,
            archive_provenance,
            replace_existing: false,
        })
    }

    pub fn replace_tree(
        authority: DeploymentName,
        relative_path: impl Into<String>,
        tree: Digest,
    ) -> Result<Self, DeploymentDtoError> {
        Self::replace_tree_with_provenance(authority, relative_path, tree, None)
    }

    pub fn replace_archive_tree(
        authority: DeploymentName,
        relative_path: impl Into<String>,
        tree: Digest,
        archive_provenance: ArchiveProvenanceV1,
    ) -> Result<Self, DeploymentDtoError> {
        Self::replace_tree_with_provenance(authority, relative_path, tree, Some(archive_provenance))
    }

    fn replace_tree_with_provenance(
        authority: DeploymentName,
        relative_path: impl Into<String>,
        tree: Digest,
        archive_provenance: Option<ArchiveProvenanceV1>,
    ) -> Result<Self, DeploymentDtoError> {
        let mut operation =
            Self::place_tree_with_provenance(authority, relative_path, tree, archive_provenance)?;
        let Self::PlaceTree {
            replace_existing, ..
        } = &mut operation
        else {
            unreachable!("place_tree_with_provenance constructs PlaceTree")
        };
        *replace_existing = true;
        Ok(operation)
    }

    pub fn remove_leaf(
        authority: DeploymentName,
        relative_path: impl Into<String>,
    ) -> Result<Self, DeploymentDtoError> {
        let relative_path = relative_path.into();
        validate_relative_path(&relative_path)?;
        Ok(Self::RemoveLeaf {
            authority,
            relative_path,
        })
    }

    pub fn assert_absent(
        authority: DeploymentName,
        relative_path: impl Into<String>,
    ) -> Result<Self, DeploymentDtoError> {
        let relative_path = relative_path.into();
        validate_relative_path(&relative_path)?;
        Ok(Self::AssertAbsent {
            authority,
            relative_path,
        })
    }

    pub fn assert_exact(
        authority: DeploymentName,
        relative_path: impl Into<String>,
        state: PrepareTargetStateV1,
    ) -> Result<Self, DeploymentDtoError> {
        let relative_path = relative_path.into();
        validate_relative_path(&relative_path)?;
        Ok(Self::AssertExact {
            authority,
            relative_path,
            state,
        })
    }

    #[must_use]
    pub const fn authority(&self) -> &DeploymentName {
        match self {
            Self::EnsureDirectory { authority, .. }
            | Self::PlaceFile { authority, .. }
            | Self::PlaceSymlink { authority, .. }
            | Self::PlaceTree { authority, .. }
            | Self::RemoveLeaf { authority, .. }
            | Self::AssertAbsent { authority, .. }
            | Self::AssertExact { authority, .. } => authority,
        }
    }

    #[must_use]
    pub fn relative_path(&self) -> &str {
        match self {
            Self::EnsureDirectory { relative_path, .. }
            | Self::PlaceFile { relative_path, .. }
            | Self::PlaceSymlink { relative_path, .. }
            | Self::PlaceTree { relative_path, .. }
            | Self::RemoveLeaf { relative_path, .. }
            | Self::AssertAbsent { relative_path, .. }
            | Self::AssertExact { relative_path, .. } => relative_path,
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
    pub const fn mode(&self) -> Option<u32> {
        match self {
            Self::EnsureDirectory { mode, .. } | Self::PlaceFile { mode, .. } => Some(*mode),
            Self::PlaceSymlink { .. }
            | Self::PlaceTree { .. }
            | Self::RemoveLeaf { .. }
            | Self::AssertAbsent { .. }
            | Self::AssertExact { .. } => None,
        }
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
    pub const fn asserted_state(&self) -> Option<&PrepareTargetStateV1> {
        match self {
            Self::AssertExact { state, .. } => Some(state),
            _ => None,
        }
    }

    #[must_use]
    pub const fn replaces_existing(&self) -> bool {
        matches!(
            self,
            Self::EnsureDirectory {
                replace_existing: true,
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
}

/// Complete prepare input without ambient path or process authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrepareRequestV1 {
    namespace: NamespaceName,
    expected_head: Option<Digest>,
    graph_digest: Digest,
    inputs: Vec<PrepareInputV1>,
    artifacts: Vec<PrepareArtifactV1>,
    transforms: Vec<PrepareTransformProvenanceV1>,
    findings: Vec<PreparePolicyFindingV1>,
    operations: Vec<PrepareOperationV1>,
}

/// Named fields used to construct a [`PrepareRequestV1`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrepareRequestPartsV1 {
    pub namespace: NamespaceName,
    pub expected_head: Option<Digest>,
    pub graph_digest: Digest,
    pub inputs: Vec<PrepareInputV1>,
    pub artifacts: Vec<PrepareArtifactV1>,
    pub transforms: Vec<PrepareTransformProvenanceV1>,
    pub findings: Vec<PreparePolicyFindingV1>,
    pub operations: Vec<PrepareOperationV1>,
}

impl From<PrepareRequestPartsV1> for PrepareRequestV1 {
    fn from(parts: PrepareRequestPartsV1) -> Self {
        Self {
            namespace: parts.namespace,
            expected_head: parts.expected_head,
            graph_digest: parts.graph_digest,
            inputs: parts.inputs,
            artifacts: parts.artifacts,
            transforms: parts.transforms,
            findings: parts.findings,
            operations: parts.operations,
        }
    }
}

impl PrepareRequestV1 {
    #[must_use]
    pub const fn namespace(&self) -> &NamespaceName {
        &self.namespace
    }
    #[must_use]
    pub const fn expected_head(&self) -> Option<&Digest> {
        self.expected_head.as_ref()
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
    pub fn artifacts(&self) -> &[PrepareArtifactV1] {
        &self.artifacts
    }
    #[must_use]
    pub fn transforms(&self) -> &[PrepareTransformProvenanceV1] {
        &self.transforms
    }
    #[must_use]
    pub fn findings(&self) -> &[PreparePolicyFindingV1] {
        &self.findings
    }
    #[must_use]
    pub fn operations(&self) -> &[PrepareOperationV1] {
        &self.operations
    }
}

/// Artifact metadata stored for review.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArtifactDescriptorV1 {
    id: ArtifactId,
    digest: Digest,
    byte_len: u64,
    media_type: String,
}

impl ArtifactDescriptorV1 {
    #[must_use]
    pub fn new(id: ArtifactId, digest: Digest, byte_len: u64, media_type: String) -> Self {
        Self {
            id,
            digest,
            byte_len,
            media_type,
        }
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

/// A policy finding stored for review.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicyFindingV1 {
    id: Digest,
    code: String,
    message: String,
    approval_required: bool,
}

impl PolicyFindingV1 {
    #[must_use]
    pub fn new(id: Digest, code: String, message: String, approval_required: bool) -> Self {
        Self {
            id,
            code,
            message,
            approval_required,
        }
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

/// Acquisition authority retained for a tracked update.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum PreparedTrackingAcquisitionKindV1 {
    LocalSource,
    GitSource,
}

/// A credential-free acquisition grant shown during prepare review.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct PreparedTrackingAcquisitionGrantV1 {
    kind: PreparedTrackingAcquisitionKindV1,
    locator: String,
}

impl PreparedTrackingAcquisitionGrantV1 {
    pub fn new(
        kind: PreparedTrackingAcquisitionKindV1,
        locator: impl Into<String>,
    ) -> Result<Self, DeploymentDtoError> {
        let locator = locator.into();
        match kind {
            PreparedTrackingAcquisitionKindV1::LocalSource => {
                validate_prepared_tracking_local_locator(&locator)?;
            }
            PreparedTrackingAcquisitionKindV1::GitSource => {
                validate_prepared_tracking_https_locator(
                    "prepared tracking Git acquisition locator",
                    &locator,
                    4096,
                )?;
            }
        }
        Ok(Self { kind, locator })
    }

    #[must_use]
    pub const fn kind(&self) -> PreparedTrackingAcquisitionKindV1 {
        self.kind
    }
    #[must_use]
    pub fn locator(&self) -> &str {
        &self.locator
    }
}

/// Complete tracked-update authority committed by a prepared plan.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreparedTrackingReviewV1 {
    source_locator: String,
    moving_selector: String,
    applied_revision: String,
    root_tree_digest: Digest,
    source_subdir: String,
    config_entry_point: String,
    selected_profile: ContributionName,
    target_authority: DeploymentName,
    acquisition_grants: Vec<PreparedTrackingAcquisitionGrantV1>,
    component_grants: Vec<Digest>,
}

/// Fields used to construct a [`PreparedTrackingReviewV1`].
///
/// Conversion validates all locators, selectors, revisions, paths, and grant
/// sets. It is the only constructor for the review value.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreparedTrackingReviewPartsV1 {
    pub source_locator: String,
    pub moving_selector: String,
    pub applied_revision: String,
    pub root_tree_digest: Digest,
    pub source_subdir: String,
    pub config_entry_point: String,
    pub selected_profile: ContributionName,
    pub target_authority: DeploymentName,
    pub acquisition_grants: Vec<PreparedTrackingAcquisitionGrantV1>,
    pub component_grants: Vec<Digest>,
}

impl TryFrom<PreparedTrackingReviewPartsV1> for PreparedTrackingReviewV1 {
    type Error = DeploymentDtoError;

    fn try_from(parts: PreparedTrackingReviewPartsV1) -> Result<Self, Self::Error> {
        let PreparedTrackingReviewPartsV1 {
            source_locator,
            moving_selector,
            applied_revision,
            root_tree_digest,
            source_subdir,
            config_entry_point,
            selected_profile,
            target_authority,
            mut acquisition_grants,
            mut component_grants,
        } = parts;
        validate_prepared_tracking_https_locator(
            "prepared tracking source locator",
            &source_locator,
            2048,
        )?;
        validate_prepared_tracking_selector(&moving_selector)?;
        validate_prepared_tracking_revision(&applied_revision)?;
        validate_prepared_tracking_subdir(&source_subdir)?;
        validate_relative_path(&config_entry_point)?;
        if acquisition_grants.len() > 8192 || component_grants.len() > 8192 {
            return Err(DeploymentDtoError {
                field: "prepared tracking grants",
                reason: "exceeds its count limit",
            });
        }
        acquisition_grants.sort();
        component_grants.sort();
        if acquisition_grants.windows(2).any(|pair| pair[0] >= pair[1])
            || component_grants.windows(2).any(|pair| pair[0] >= pair[1])
        {
            return Err(DeploymentDtoError {
                field: "prepared tracking grants",
                reason: "must be unique",
            });
        }
        Ok(Self {
            source_locator,
            moving_selector,
            applied_revision,
            root_tree_digest,
            source_subdir,
            config_entry_point,
            selected_profile,
            target_authority,
            acquisition_grants,
            component_grants,
        })
    }
}

impl PreparedTrackingReviewV1 {
    #[must_use]
    pub fn source_locator(&self) -> &str {
        &self.source_locator
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
    #[must_use]
    pub fn source_subdir(&self) -> &str {
        &self.source_subdir
    }
    #[must_use]
    pub fn config_entry_point(&self) -> &str {
        &self.config_entry_point
    }
    #[must_use]
    pub const fn selected_profile(&self) -> &ContributionName {
        &self.selected_profile
    }
    #[must_use]
    pub const fn target_authority(&self) -> &DeploymentName {
        &self.target_authority
    }
    #[must_use]
    pub fn acquisition_grants(&self) -> &[PreparedTrackingAcquisitionGrantV1] {
        &self.acquisition_grants
    }
    #[must_use]
    pub fn component_grants(&self) -> &[Digest] {
        &self.component_grants
    }
}

/// Durable review result returned only after the prepared record is reloaded.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreparedDeploymentV1 {
    plan_id: PreparedId,
    namespace: NamespaceName,
    expected_head: Option<Digest>,
    graph_digest: Digest,
    inputs: Vec<PrepareInputV1>,
    transforms: Vec<PrepareTransformProvenanceV1>,
    artifacts: Vec<ArtifactDescriptorV1>,
    findings: Vec<PolicyFindingV1>,
    approval_digest: Digest,
    operations: Vec<PrepareOperationV1>,
    transition: LifecycleTransitionViewV1,
    lifecycle: LifecycleStateViewV1,
    restore_point: Option<RestorePointInspectionV1>,
    retention: RetentionAuthorityInspectionV1,
    tracked_root: Option<PreparedTrackingReviewV1>,
}

/// Verified result when a tracked selector still points to the selected generation's revision.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrackedRootNoChangeV1 {
    namespace: NamespaceName,
    generation: Digest,
    applied_revision: String,
    root_tree_digest: Digest,
}

impl TrackedRootNoChangeV1 {
    #[must_use]
    pub fn new(
        namespace: NamespaceName,
        generation: Digest,
        applied_revision: String,
        root_tree_digest: Digest,
    ) -> Self {
        Self {
            namespace,
            generation,
            applied_revision,
            root_tree_digest,
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
    pub fn applied_revision(&self) -> &str {
        &self.applied_revision
    }
    #[must_use]
    pub const fn root_tree_digest(&self) -> &Digest {
        &self.root_tree_digest
    }
}

/// Result of checking a tracked namespace during prepare.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TrackedRootUpdateOutcomeV1 {
    NoChange(TrackedRootNoChangeV1),
    Prepared(Box<PreparedDeploymentV1>),
}

impl TrackedRootUpdateOutcomeV1 {
    #[must_use]
    pub const fn no_change(&self) -> Option<&TrackedRootNoChangeV1> {
        match self {
            Self::NoChange(result) => Some(result),
            Self::Prepared(_) => None,
        }
    }

    #[must_use]
    pub fn prepared(&self) -> Option<&PreparedDeploymentV1> {
        match self {
            Self::NoChange(_) => None,
            Self::Prepared(prepared) => Some(prepared.as_ref()),
        }
    }

    #[must_use]
    pub fn into_prepared(self) -> Option<PreparedDeploymentV1> {
        match self {
            Self::NoChange(_) => None,
            Self::Prepared(prepared) => Some(*prepared),
        }
    }
}

/// Persisted fields used to construct a [`PreparedDeploymentV1`].
///
/// Conversion initializes transition, lifecycle state, restore point,
/// retention, and tracked root to the defaults replaced by the builder methods.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreparedDeploymentPartsV1 {
    pub plan_id: PreparedId,
    pub namespace: NamespaceName,
    pub expected_head: Option<Digest>,
    pub graph_digest: Digest,
    pub inputs: Vec<PrepareInputV1>,
    pub transforms: Vec<PrepareTransformProvenanceV1>,
    pub artifacts: Vec<ArtifactDescriptorV1>,
    pub findings: Vec<PolicyFindingV1>,
    pub approval_digest: Digest,
    pub operations: Vec<PrepareOperationV1>,
}

impl From<PreparedDeploymentPartsV1> for PreparedDeploymentV1 {
    fn from(parts: PreparedDeploymentPartsV1) -> Self {
        Self {
            plan_id: parts.plan_id,
            namespace: parts.namespace,
            expected_head: parts.expected_head,
            graph_digest: parts.graph_digest,
            inputs: parts.inputs,
            transforms: parts.transforms,
            artifacts: parts.artifacts,
            findings: parts.findings,
            approval_digest: parts.approval_digest,
            operations: parts.operations,
            transition: LifecycleTransitionViewV1::Reconcile,
            lifecycle: LifecycleStateViewV1::Enabled,
            restore_point: None,
            retention: RetentionAuthorityInspectionV1::new(256, vec![], vec![]),
            tracked_root: None,
        }
    }
}

impl PreparedDeploymentV1 {
    /// Sets the lifecycle state shown during review.
    #[must_use]
    pub fn with_lifecycle_state(mut self, lifecycle: LifecycleStateViewV1) -> Self {
        self.lifecycle = lifecycle;
        self
    }

    /// Sets the semantic transition bound to the stored plan.
    #[must_use]
    pub fn with_transition(mut self, transition: LifecycleTransitionViewV1) -> Self {
        self.transition = transition;
        self
    }

    /// Sets the restore point for a disabled next generation.
    #[must_use]
    pub fn with_restore_point(mut self, restore_point: Option<RestorePointInspectionV1>) -> Self {
        self.restore_point = restore_point;
        self
    }

    /// Sets the next namespace retention authority.
    #[must_use]
    pub fn with_retention_authority(mut self, retention: RetentionAuthorityInspectionV1) -> Self {
        self.retention = retention;
        self
    }

    /// Sets the tracked-root transition stored in the plan.
    #[must_use]
    pub fn with_tracking_review(mut self, tracked_root: Option<PreparedTrackingReviewV1>) -> Self {
        self.tracked_root = tracked_root;
        self
    }

    #[must_use]
    pub const fn plan_id(&self) -> &PreparedId {
        &self.plan_id
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
    pub const fn graph_digest(&self) -> &Digest {
        &self.graph_digest
    }
    /// Returns all source, config, component, and asset inputs bound to the plan.
    #[must_use]
    pub fn inputs(&self) -> &[PrepareInputV1] {
        &self.inputs
    }
    /// Returns deterministic provenance for every format transform in the plan.
    #[must_use]
    pub fn transforms(&self) -> &[PrepareTransformProvenanceV1] {
        &self.transforms
    }
    #[must_use]
    pub fn artifacts(&self) -> &[ArtifactDescriptorV1] {
        &self.artifacts
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
    pub const fn operation_count(&self) -> u64 {
        self.operations.len() as u64
    }

    /// Returns the exact operation sequence bound to the plan.
    #[must_use]
    pub fn operations(&self) -> &[PrepareOperationV1] {
        &self.operations
    }
    #[must_use]
    pub const fn lifecycle_state(&self) -> LifecycleStateViewV1 {
        self.lifecycle
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
    /// Returns complete tracking data, or `None` if the plan clears tracking.
    #[must_use]
    pub const fn tracking_review(&self) -> Option<&PreparedTrackingReviewV1> {
        self.tracked_root.as_ref()
    }

    /// Returns tracking data using the tracked-root name.
    #[must_use]
    pub const fn tracked_root(&self) -> Option<&PreparedTrackingReviewV1> {
        self.tracking_review()
    }
}

/// A retrieved immutable artifact.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArtifactV1 {
    descriptor: ArtifactDescriptorV1,
    bytes: Vec<u8>,
}

impl ArtifactV1 {
    #[must_use]
    pub fn new(descriptor: ArtifactDescriptorV1, bytes: Vec<u8>) -> Self {
        Self { descriptor, bytes }
    }

    #[must_use]
    pub const fn descriptor(&self) -> &ArtifactDescriptorV1 {
        &self.descriptor
    }
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}

/// Approval cryptographically bound to one plan and finding set.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApprovalV1 {
    plan_id: PreparedId,
    findings_digest: Digest,
}

impl ApprovalV1 {
    #[must_use]
    pub const fn new(plan_id: PreparedId, findings_digest: Digest) -> Self {
        Self {
            plan_id,
            findings_digest,
        }
    }

    #[must_use]
    pub const fn plan_id(&self) -> &PreparedId {
        &self.plan_id
    }
    #[must_use]
    pub const fn findings_digest(&self) -> &Digest {
        &self.findings_digest
    }
}

/// The only semantic input accepted by commit/v1.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommitRequestV1 {
    plan_id: PreparedId,
    approval: ApprovalV1,
}

impl CommitRequestV1 {
    #[must_use]
    pub const fn new(plan_id: PreparedId, approval: ApprovalV1) -> Self {
        Self { plan_id, approval }
    }

    #[must_use]
    pub const fn plan_id(&self) -> &PreparedId {
        &self.plan_id
    }
    #[must_use]
    pub const fn approval(&self) -> &ApprovalV1 {
        &self.approval
    }
}

/// A successful atomic namespace-head transition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApplyOutcomeV1 {
    plan_id: PreparedId,
    namespace: NamespaceName,
    previous_head: Option<Digest>,
    head: Option<Digest>,
}

impl ApplyOutcomeV1 {
    #[must_use]
    pub const fn new(
        plan_id: PreparedId,
        namespace: NamespaceName,
        previous_head: Option<Digest>,
        head: Digest,
    ) -> Self {
        Self {
            plan_id,
            namespace,
            previous_head,
            head: Some(head),
        }
    }

    /// Creates the outcome for a removed namespace head.
    #[must_use]
    pub const fn removed(
        plan_id: PreparedId,
        namespace: NamespaceName,
        previous_head: Digest,
    ) -> Self {
        Self {
            plan_id,
            namespace,
            previous_head: Some(previous_head),
            head: None,
        }
    }

    #[must_use]
    pub const fn plan_id(&self) -> &PreparedId {
        &self.plan_id
    }
    #[must_use]
    pub const fn namespace(&self) -> &NamespaceName {
        &self.namespace
    }
    #[must_use]
    pub const fn previous_head(&self) -> Option<&Digest> {
        self.previous_head.as_ref()
    }

    #[must_use]
    pub fn head(&self) -> &Digest {
        self.head
            .as_ref()
            .expect("namespace-removal outcomes have no head; use next_head")
    }

    /// Returns the exact next head, or `None` for namespace removal.
    #[must_use]
    pub const fn next_head(&self) -> Option<&Digest> {
        self.head.as_ref()
    }
}

/// A read-only namespace-head view.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StateViewV1 {
    namespace: NamespaceName,
    head: Option<Digest>,
}

impl StateViewV1 {
    #[must_use]
    pub const fn new(namespace: NamespaceName, head: Option<Digest>) -> Self {
        Self { namespace, head }
    }

    #[must_use]
    pub const fn namespace(&self) -> &NamespaceName {
        &self.namespace
    }
    #[must_use]
    pub const fn head(&self) -> Option<&Digest> {
        self.head.as_ref()
    }
}

/// Selects a retained generation for deterministic restore-plan preparation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CheckoutRequestV1 {
    namespace: NamespaceName,
    target_generation: Digest,
}

impl CheckoutRequestV1 {
    #[must_use]
    pub const fn new(namespace: NamespaceName, target_generation: Digest) -> Self {
        Self {
            namespace,
            target_generation,
        }
    }

    #[must_use]
    pub const fn namespace(&self) -> &NamespaceName {
        &self.namespace
    }
    #[must_use]
    pub const fn target_generation(&self) -> &Digest {
        &self.target_generation
    }
}

/// Result of reconciling the global transaction journal.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RecoveryOutcomeV1 {
    /// No journal existed and no namespace changed.
    NoTransaction,
    /// A journaled namespace was recovered to the selected head.
    Recovered {
        namespace: NamespaceName,
        head: Option<Digest>,
    },
}

impl RecoveryOutcomeV1 {
    #[must_use]
    pub const fn recovered(namespace: NamespaceName, head: Option<Digest>) -> Self {
        Self::Recovered { namespace, head }
    }

    #[must_use]
    pub const fn namespace(&self) -> Option<&NamespaceName> {
        match self {
            Self::NoTransaction => None,
            Self::Recovered { namespace, .. } => Some(namespace),
        }
    }

    #[must_use]
    pub const fn head(&self) -> Option<&Digest> {
        match self {
            Self::NoTransaction | Self::Recovered { head: None, .. } => None,
            Self::Recovered {
                head: Some(head), ..
            } => Some(head),
        }
    }
}

/// Prepared plans selected for reference-aware removal.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PruneRequestV1 {
    plan_ids: Vec<PreparedId>,
    sweep_unreferenced: bool,
}

impl PruneRequestV1 {
    #[must_use]
    pub fn new(mut plan_ids: Vec<PreparedId>) -> Self {
        plan_ids.sort();
        plan_ids.dedup();
        Self {
            plan_ids,
            sweep_unreferenced: false,
        }
    }

    /// Also selects plans not referenced by a retained generation, restore
    /// point, or pin. Store reachability prevents selection of plans in use.
    /// `machine/v1` cannot request a sweep; automation must name plans.
    #[must_use]
    pub fn sweep_unreferenced(mut self) -> Self {
        self.sweep_unreferenced = true;
        self
    }

    #[must_use]
    pub fn plan_ids(&self) -> &[PreparedId] {
        &self.plan_ids
    }
    #[must_use]
    pub const fn sweeps_unreferenced(&self) -> bool {
        self.sweep_unreferenced
    }
}

/// Removal counts from one locked, reference-aware maintenance pass.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PruneOutcomeV1 {
    pub prepared_records: u64,
    pub artifact_blobs: u64,
    pub state_generations: u64,
    pub pack_objects: u64,
    pub canonical_files: u64,
    pub canonical_symlinks: u64,
    pub canonical_trees: u64,
}

impl PruneOutcomeV1 {
    /// Creates an outcome with object counts set to zero.
    #[must_use]
    pub const fn new(prepared_records: u64, artifact_blobs: u64, state_generations: u64) -> Self {
        Self {
            prepared_records,
            artifact_blobs,
            state_generations,
            pack_objects: 0,
            canonical_files: 0,
            canonical_symlinks: 0,
            canonical_trees: 0,
        }
    }
}

/// Stable DTO construction failure.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
#[error("invalid {field}: {reason}")]
pub struct DeploymentDtoError {
    field: &'static str,
    reason: &'static str,
}

impl From<crate::ValidationError> for DeploymentDtoError {
    fn from(error: crate::ValidationError) -> Self {
        Self {
            field: error.field,
            reason: error.reason,
        }
    }
}

impl DeploymentDtoError {
    #[must_use]
    pub const fn reason(&self) -> &'static str {
        self.reason
    }
}

fn validate_mode(mode: u32) -> Result<(), DeploymentDtoError> {
    if mode & !0o777 != 0 {
        return Err(DeploymentDtoError {
            field: "operation mode",
            reason: "must contain only permission bits",
        });
    }
    Ok(())
}

fn validate_file_mode(mode: u32) -> Result<(), DeploymentDtoError> {
    validate_mode(mode)?;
    if mode & 0o400 == 0 {
        return Err(DeploymentDtoError {
            field: "file operation mode",
            reason: "must remain owner-readable for verification and recovery",
        });
    }
    Ok(())
}

fn validate_directory_mode(mode: u32) -> Result<(), DeploymentDtoError> {
    validate_mode(mode)?;
    if mode & 0o500 != 0o500 {
        return Err(DeploymentDtoError {
            field: "directory operation mode",
            reason: "must remain owner-readable and owner-searchable for recovery",
        });
    }
    Ok(())
}

fn validate_label(field: &'static str, value: &str) -> Result<(), DeploymentDtoError> {
    crate::validate::validate_label(field, value).map_err(Into::into)
}

fn validate_diagnostic_code(value: &str) -> Result<(), DeploymentDtoError> {
    crate::validate::validate_diagnostic_code(value).map_err(Into::into)
}

fn validate_diagnostic_text(field: &'static str, value: &str) -> Result<(), DeploymentDtoError> {
    if value.len() > MAX_TRANSFORM_DIAGNOSTIC_TEXT_BYTES_V1 {
        return Err(DeploymentDtoError {
            field,
            reason: "exceeds its byte limit",
        });
    }
    Ok(())
}

fn validate_transform_diagnostics(
    diagnostics: &[PrepareTransformDiagnosticV1],
) -> Result<(), DeploymentDtoError> {
    if diagnostics.len() > MAX_TRANSFORM_DIAGNOSTICS_V1 {
        return Err(DeploymentDtoError {
            field: "transform diagnostics",
            reason: "exceeds its count limit",
        });
    }
    if diagnostics
        .iter()
        .any(|diagnostic| diagnostic.severity == PrepareTransformDiagnosticSeverityV1::Error)
    {
        return Err(DeploymentDtoError {
            field: "transform diagnostic severity",
            reason: "successful transforms cannot contain error diagnostics",
        });
    }
    if diagnostics.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(DeploymentDtoError {
            field: "transform diagnostics",
            reason: "must be unique and in canonical order",
        });
    }
    let total = diagnostics.iter().fold(0_usize, |total, diagnostic| {
        total
            .saturating_add(diagnostic.message.len())
            .saturating_add(diagnostic.notes.iter().map(String::len).sum::<usize>())
    });
    if total > MAX_TRANSFORM_DIAGNOSTIC_TOTAL_TEXT_BYTES_V1 {
        return Err(DeploymentDtoError {
            field: "transform diagnostic text",
            reason: "exceeds its aggregate byte limit",
        });
    }
    Ok(())
}

fn validate_prepared_tracking_https_locator(
    field: &'static str,
    value: &str,
    limit: usize,
) -> Result<(), DeploymentDtoError> {
    validate_text(field, value, limit)?;
    let Some(remainder) = value.strip_prefix("https://") else {
        return Err(DeploymentDtoError {
            field,
            reason: "must be a canonical credential-free HTTPS locator",
        });
    };
    let Some((authority, path)) = remainder.split_once('/') else {
        return Err(DeploymentDtoError {
            field,
            reason: "must be a canonical credential-free HTTPS locator",
        });
    };
    if !value.is_ascii()
        || value.trim() != value
        || value.contains(['\\', '?', '#'])
        || value.bytes().any(|byte| byte.is_ascii_whitespace())
        || authority.is_empty()
        || authority.contains('@')
        || authority.bytes().any(|byte| byte.is_ascii_uppercase())
        || path.is_empty()
        || path
            .split('/')
            .any(|segment| segment.is_empty() || matches!(segment, "." | ".."))
    {
        return Err(DeploymentDtoError {
            field,
            reason: "must be a canonical credential-free HTTPS locator",
        });
    }
    Ok(())
}

fn validate_prepared_tracking_selector(value: &str) -> Result<(), DeploymentDtoError> {
    validate_text("prepared tracking moving selector", value, 1024)?;
    if value.trim() != value
        || value == "@"
        || value.starts_with('/')
        || value.ends_with('/')
        || value.ends_with('.')
        || value.contains("//")
        || value.contains("..")
        || value.contains("@{")
        || value.contains('\\')
        || value
            .chars()
            .any(|character| character.is_control() || character.is_whitespace())
        || value
            .bytes()
            .any(|byte| matches!(byte, b'~' | b'^' | b':' | b'?' | b'*' | b'['))
    {
        return Err(DeploymentDtoError {
            field: "prepared tracking moving selector",
            reason: "must be a bounded canonical symbolic Git selector",
        });
    }
    Ok(())
}

fn validate_prepared_tracking_revision(value: &str) -> Result<(), DeploymentDtoError> {
    let hexadecimal = value
        .strip_prefix("sha1-")
        .filter(|value| value.len() == 40)
        .or_else(|| {
            value
                .strip_prefix("sha256-")
                .filter(|value| value.len() == 64)
        });
    if hexadecimal.is_none_or(|value| {
        !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    }) {
        return Err(DeploymentDtoError {
            field: "prepared tracking applied revision",
            reason: "must be a canonical algorithm-tagged exact revision",
        });
    }
    Ok(())
}

fn validate_prepared_tracking_subdir(value: &str) -> Result<(), DeploymentDtoError> {
    if value == "." {
        return Ok(());
    }
    validate_relative_path(value)
}

fn validate_prepared_tracking_local_locator(value: &str) -> Result<(), DeploymentDtoError> {
    if value == "." {
        return Ok(());
    }
    validate_text("prepared tracking local acquisition locator", value, 4096)?;
    let mut saw_normal = false;
    if value.starts_with('/')
        || value.contains('\\')
        || value.chars().any(char::is_control)
        || value.split('/').count() > 64
    {
        return Err(DeploymentDtoError {
            field: "prepared tracking local acquisition locator",
            reason: "must be a canonical logical local locator",
        });
    }
    for segment in value.split('/') {
        if segment.is_empty()
            || segment == "."
            || segment.len() > 255
            || matches!(segment, ".git" | "malm.lock" | ".malm-lock.tmp")
            || (segment == ".." && saw_normal)
        {
            return Err(DeploymentDtoError {
                field: "prepared tracking local acquisition locator",
                reason: "must be a canonical logical local locator",
            });
        }
        if segment != ".." {
            saw_normal = true;
        }
    }
    Ok(())
}

fn validate_text(field: &'static str, value: &str, limit: usize) -> Result<(), DeploymentDtoError> {
    crate::validate::validate_text(field, value, limit).map_err(Into::into)
}

fn validate_relative_path(value: &str) -> Result<(), DeploymentDtoError> {
    crate::validate::validate_relative_path(value).map_err(Into::into)
}

#[cfg(test)]
mod tests {
    use super::{
        PrepareTransformDiagnosticSeverityV1, PrepareTransformDiagnosticV1,
        PrepareTransformImplementationV1, PrepareTransformProvenanceV1,
        PrepareTransformSourceLocationV1, PreparedTrackingReviewPartsV1, PreparedTrackingReviewV1,
    };
    use crate::{ContributionName, DeploymentName, Digest};

    #[test]
    fn successful_transform_dtos_reject_errors_duplicates_and_oob_sources() {
        assert!(
            PrepareTransformDiagnosticV1::new(
                PrepareTransformDiagnosticSeverityV1::Error,
                "invalid.success",
                "error",
                None,
                vec![],
            )
            .is_err()
        );
        assert!(
            PrepareTransformSourceLocationV1::new(
                ContributionName::new("root").unwrap(),
                Digest::sha256(b"root"),
                "malm.kdl",
                1,
                0,
                2,
            )
            .is_err()
        );
        let diagnostic = PrepareTransformDiagnosticV1::new(
            PrepareTransformDiagnosticSeverityV1::Info,
            "duplicate.info",
            "same",
            None,
            vec![],
        )
        .unwrap();
        assert!(
            PrepareTransformProvenanceV1::new(
                "transform",
                PrepareTransformImplementationV1::built_in("test/1").unwrap(),
                Digest::sha256(b"request"),
                Digest::sha256(b"document"),
                vec![],
                Digest::sha256(b"response"),
                vec![diagnostic.clone(), diagnostic],
            )
            .is_err()
        );
    }

    #[test]
    fn prepared_tracking_review_rejects_credentials_and_host_paths() {
        let review = |source: &str| {
            PreparedTrackingReviewV1::try_from(PreparedTrackingReviewPartsV1 {
                source_locator: source.to_owned(),
                moving_selector: "refs/heads/main".to_owned(),
                applied_revision: format!("sha1-{}", "1".repeat(40)),
                root_tree_digest: Digest::sha256(b"tree"),
                source_subdir: ".".to_owned(),
                config_entry_point: "malm.kdl".to_owned(),
                selected_profile: ContributionName::new("default").unwrap(),
                target_authority: DeploymentName::new("home").unwrap(),
                acquisition_grants: vec![],
                component_grants: vec![],
            })
        };
        assert!(review("https://user@example.invalid/root.git").is_err());
        assert!(review("/tmp/root").is_err());
        assert!(review("https://example.invalid/root.git").is_ok());
    }
}
