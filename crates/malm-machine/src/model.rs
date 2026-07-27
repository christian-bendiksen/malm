use malm_types::{
    ApplyOutcomeV1, ArtifactId, ArtifactMetadataInspectionRequestV1, ArtifactMetadataInspectionV1,
    ArtifactV1, CanonicalTreeInspectionRequestV1, CanonicalTreeInspectionV1,
    CapturedInputsInspectionV1, CatalogInspectionRequestV1, CatalogInspectionV1, CheckoutRequestV1,
    CommitRequestV1, DesiredSnapshotInspectionRequestV1, DesiredSnapshotInspectionV1,
    DirectorySafetyReasonV1, DisableRequestV1, EnableRequestV1, FsckReportV1, FsckRequestV1,
    GenerationInspectionRequestV1, GenerationInspectionV1, HistoryRetentionRequestV1,
    NamespaceHistoryRequestV1, NamespaceHistoryV1, NamespaceInspectionRequestV1,
    NamespaceInspectionV1, NamespaceName, NamespaceRemovalRequestV1, NamespaceStatusRequestV1,
    NamespaceStatusV1, PrepareRequestV1, PreparedDeploymentV1, PreparedId,
    PreparedPlanInspectionRequestV1, PruneOutcomeV1, PruneRequestV1, RecoveryOutcomeV1,
    RestorePointRequestV1, RetentionInspectionV1, RetentionPinRequestV1, StateViewV1,
    StoreDirectoryV1, StoreErrorCodeV1, StoreErrorDetailsV1, StoreErrorV1, StoreMetadataReasonV1,
    StoreRootV1, StoreStatusV1, TrackingInspectionV1, TransformProvenanceInspectionV1,
};

use crate::{
    MAX_MACHINE_CODE_BYTES, MAX_MACHINE_DIAGNOSTICS, MAX_MACHINE_SEQUENCE, MAX_MACHINE_TEXT_BYTES,
    MAX_REQUEST_ID_BYTES,
};

/// Invalid machine-owned scalar or envelope model.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
#[non_exhaustive]
pub enum MachineValidationError {
    #[error("invalid machine request ID ({value_len} bytes): {reason}")]
    InvalidRequestId {
        value_len: usize,
        reason: &'static str,
    },
    #[error("invalid machine diagnostic code ({value_len} bytes): {reason}")]
    InvalidCode {
        value_len: usize,
        reason: &'static str,
    },
    #[error("invalid machine text ({value_len} bytes): {reason}")]
    InvalidText {
        value_len: usize,
        reason: &'static str,
    },
    #[error("machine error has {actual} diagnostics; limit is {limit}")]
    TooManyDiagnostics { limit: usize, actual: usize },
    #[error("{frame} frame cannot use sequence {sequence}; maximum is {MAX_MACHINE_SEQUENCE}")]
    InvalidSequence { frame: &'static str, sequence: u64 },
    #[error("invalid prepared deployment: {0}")]
    InvalidPreparedDeployment(&'static str),
    #[error("machine error code, category, and details disagree")]
    InvalidErrorShape,
    #[error("unsupported request: {0}")]
    UnsupportedRequest(&'static str),
}

malm_types::validated_string! {
    /// Caller-selected opaque request correlation identifier.
    pub struct RequestIdV1;
    error: MachineValidationError;
    validate: |value: &str| {
        if value.is_empty() {
            return Err("must not be empty");
        }
        if value.len() > MAX_REQUEST_ID_BYTES {
            return Err("must be at most 128 bytes");
        }
        if !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'))
        {
            return Err(
                "may contain only ASCII letters, digits, dot, underscore, colon, and hyphen",
            );
        }
        Ok(())
    };
    make_error: |value, reason| MachineValidationError::InvalidRequestId {
        value_len: value.len(),
        reason,
    };
    impl: serde;
}

malm_types::validated_string! {
    /// Bounded stable machine or diagnostic code.
    pub struct MachineCodeV1;
    error: MachineValidationError;
    validate: |value: &str| {
        if value.is_empty() {
            return Err("must not be empty");
        }
        if value.len() > MAX_MACHINE_CODE_BYTES {
            return Err("must be at most 64 bytes");
        }
        let bytes = value.as_bytes();
        if !bytes[0].is_ascii_lowercase()
            || !bytes
                .iter()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-')
        {
            return Err(
                "must start with a lowercase letter and contain lowercase letters, digits, or hyphens",
            );
        }
        Ok(())
    };
    make_error: |value, reason| MachineValidationError::InvalidCode {
        value_len: value.len(),
        reason,
    };
    impl: serde;
}

malm_types::validated_string! {
    /// Bounded informational text that is never compatibility logic.
    pub struct MachineTextV1;
    error: MachineValidationError;
    validate: |value: &str| {
        if value.len() > MAX_MACHINE_TEXT_BYTES {
            return Err("must be at most 65536 bytes");
        }
        if value
            .chars()
            .any(|character| character.is_control() && !matches!(character, '\n' | '\t'))
        {
            return Err("must not contain control characters other than newline and tab");
        }
        Ok(())
    };
    make_error: |value, reason| MachineValidationError::InvalidText {
        value_len: value.len(),
        reason,
    };
    impl: serde;
}

/// The closed set of operations accepted by the machine/v1 adapter.
///
/// Keep this enum literal. Workspace source-contract tests parse it so every
/// protocol operation remains visible and auditable in source. Keep the
/// variants in stable wire inventory order.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum MachineOperationV1 {
    StoreStatus,
    InitializeStore,
    Prepare,
    Plan,
    Artifact,
    Commit,
    State,
    Recover,
    Prune,
    Checkout,
    Disable,
    Enable,
    RemoveNamespace,
    SetHistoryRetention,
    Pin,
    Unpin,
    AddRestorePoint,
    DropRestorePoint,
    Catalog,
    Namespace,
    History,
    Generation,
    DesiredSnapshot,
    CanonicalTree,
    ArtifactMetadata,
    CapturedInputs,
    TransformProvenance,
    Retention,
    Tracking,
    Status,
    Fsck,
}

impl MachineOperationV1 {
    /// Every machine/v1 operation in stable wire inventory order.
    pub const ALL: &'static [Self] = &[
        Self::StoreStatus,
        Self::InitializeStore,
        Self::Prepare,
        Self::Plan,
        Self::Artifact,
        Self::Commit,
        Self::State,
        Self::Recover,
        Self::Prune,
        Self::Checkout,
        Self::Disable,
        Self::Enable,
        Self::RemoveNamespace,
        Self::SetHistoryRetention,
        Self::Pin,
        Self::Unpin,
        Self::AddRestorePoint,
        Self::DropRestorePoint,
        Self::Catalog,
        Self::Namespace,
        Self::History,
        Self::Generation,
        Self::DesiredSnapshot,
        Self::CanonicalTree,
        Self::ArtifactMetadata,
        Self::CapturedInputs,
        Self::TransformProvenance,
        Self::Retention,
        Self::Tracking,
        Self::Status,
        Self::Fsck,
    ];

    /// Returns the stable snake-case machine/v1 operation value.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::StoreStatus => "store_status",
            Self::InitializeStore => "initialize_store",
            Self::Prepare => "prepare",
            Self::Plan => "plan",
            Self::Artifact => "artifact",
            Self::Commit => "commit",
            Self::State => "state",
            Self::Recover => "recover",
            Self::Prune => "prune",
            Self::Checkout => "checkout",
            Self::Disable => "disable",
            Self::Enable => "enable",
            Self::RemoveNamespace => "remove_namespace",
            Self::SetHistoryRetention => "set_history_retention",
            Self::Pin => "pin",
            Self::Unpin => "unpin",
            Self::AddRestorePoint => "add_restore_point",
            Self::DropRestorePoint => "drop_restore_point",
            Self::Catalog => "catalog",
            Self::Namespace => "namespace",
            Self::History => "history",
            Self::Generation => "generation",
            Self::DesiredSnapshot => "desired_snapshot",
            Self::CanonicalTree => "canonical_tree",
            Self::ArtifactMetadata => "artifact_metadata",
            Self::CapturedInputs => "captured_inputs",
            Self::TransformProvenance => "transform_provenance",
            Self::Retention => "retention",
            Self::Tracking => "tracking",
            Self::Status => "status",
            Self::Fsck => "fsck",
        }
    }
}

impl MachineRequestV1 {
    #[must_use]
    pub const fn operation(&self) -> MachineOperationV1 {
        match self {
            Self::StoreStatus => MachineOperationV1::StoreStatus,
            Self::InitializeStore => MachineOperationV1::InitializeStore,
            Self::Prepare(_) => MachineOperationV1::Prepare,
            Self::Plan(_) => MachineOperationV1::Plan,
            Self::Artifact { .. } => MachineOperationV1::Artifact,
            Self::Commit(_) => MachineOperationV1::Commit,
            Self::State(_) => MachineOperationV1::State,
            Self::Recover => MachineOperationV1::Recover,
            Self::Prune(_) => MachineOperationV1::Prune,
            Self::Checkout(_) => MachineOperationV1::Checkout,
            Self::Disable(_) => MachineOperationV1::Disable,
            Self::Enable(_) => MachineOperationV1::Enable,
            Self::RemoveNamespace(_) => MachineOperationV1::RemoveNamespace,
            Self::SetHistoryRetention(_) => MachineOperationV1::SetHistoryRetention,
            Self::Pin(_) => MachineOperationV1::Pin,
            Self::Unpin(_) => MachineOperationV1::Unpin,
            Self::AddRestorePoint(_) => MachineOperationV1::AddRestorePoint,
            Self::DropRestorePoint(_) => MachineOperationV1::DropRestorePoint,
            Self::Catalog(_) => MachineOperationV1::Catalog,
            Self::Namespace(_) => MachineOperationV1::Namespace,
            Self::History(_) => MachineOperationV1::History,
            Self::Generation(_) => MachineOperationV1::Generation,
            Self::DesiredSnapshot(_) => MachineOperationV1::DesiredSnapshot,
            Self::CanonicalTree(_) => MachineOperationV1::CanonicalTree,
            Self::ArtifactMetadata(_) => MachineOperationV1::ArtifactMetadata,
            Self::CapturedInputs(_) => MachineOperationV1::CapturedInputs,
            Self::TransformProvenance(_) => MachineOperationV1::TransformProvenance,
            Self::Retention(_) => MachineOperationV1::Retention,
            Self::Tracking(_) => MachineOperationV1::Tracking,
            Self::Status(_) => MachineOperationV1::Status,
            Self::Fsck(_) => MachineOperationV1::Fsck,
        }
    }
}

impl MachineResultV1 {
    #[must_use]
    pub const fn operation(&self) -> MachineOperationV1 {
        match self {
            Self::StoreStatus(_) => MachineOperationV1::StoreStatus,
            Self::InitializeStore => MachineOperationV1::InitializeStore,
            Self::Prepare(_) => MachineOperationV1::Prepare,
            Self::Plan(_) => MachineOperationV1::Plan,
            Self::Artifact(_) => MachineOperationV1::Artifact,
            Self::Commit(_) => MachineOperationV1::Commit,
            Self::State(_) => MachineOperationV1::State,
            Self::Recover(_) => MachineOperationV1::Recover,
            Self::Prune(_) => MachineOperationV1::Prune,
            Self::Checkout(_) => MachineOperationV1::Checkout,
            Self::Disable(_) => MachineOperationV1::Disable,
            Self::Enable(_) => MachineOperationV1::Enable,
            Self::RemoveNamespace(_) => MachineOperationV1::RemoveNamespace,
            Self::SetHistoryRetention(_) => MachineOperationV1::SetHistoryRetention,
            Self::Pin(_) => MachineOperationV1::Pin,
            Self::Unpin(_) => MachineOperationV1::Unpin,
            Self::AddRestorePoint(_) => MachineOperationV1::AddRestorePoint,
            Self::DropRestorePoint(_) => MachineOperationV1::DropRestorePoint,
            Self::Catalog(_) => MachineOperationV1::Catalog,
            Self::Namespace(_) => MachineOperationV1::Namespace,
            Self::History(_) => MachineOperationV1::History,
            Self::Generation(_) => MachineOperationV1::Generation,
            Self::DesiredSnapshot(_) => MachineOperationV1::DesiredSnapshot,
            Self::CanonicalTree(_) => MachineOperationV1::CanonicalTree,
            Self::ArtifactMetadata(_) => MachineOperationV1::ArtifactMetadata,
            Self::CapturedInputs(_) => MachineOperationV1::CapturedInputs,
            Self::TransformProvenance(_) => MachineOperationV1::TransformProvenance,
            Self::Retention(_) => MachineOperationV1::Retention,
            Self::Tracking(_) => MachineOperationV1::Tracking,
            Self::Status(_) => MachineOperationV1::Status,
            Self::Fsck(_) => MachineOperationV1::Fsck,
        }
    }
}

/// A complete semantic request with no host construction authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MachineRequestV1 {
    StoreStatus,
    InitializeStore,
    Prepare(PrepareRequestV1),
    Plan(PreparedId),
    Artifact {
        plan_id: PreparedId,
        artifact_id: ArtifactId,
    },
    Commit(CommitRequestV1),
    State(NamespaceName),
    Recover,
    Prune(PruneRequestV1),
    Checkout(CheckoutRequestV1),
    Disable(DisableRequestV1),
    Enable(EnableRequestV1),
    RemoveNamespace(NamespaceRemovalRequestV1),
    SetHistoryRetention(HistoryRetentionRequestV1),
    Pin(RetentionPinRequestV1),
    Unpin(RetentionPinRequestV1),
    AddRestorePoint(RestorePointRequestV1),
    DropRestorePoint(RestorePointRequestV1),
    Catalog(CatalogInspectionRequestV1),
    Namespace(NamespaceInspectionRequestV1),
    History(NamespaceHistoryRequestV1),
    Generation(GenerationInspectionRequestV1),
    DesiredSnapshot(DesiredSnapshotInspectionRequestV1),
    CanonicalTree(CanonicalTreeInspectionRequestV1),
    ArtifactMetadata(ArtifactMetadataInspectionRequestV1),
    CapturedInputs(PreparedPlanInspectionRequestV1),
    TransformProvenance(PreparedPlanInspectionRequestV1),
    Retention(GenerationInspectionRequestV1),
    Tracking(GenerationInspectionRequestV1),
    Status(NamespaceStatusRequestV1),
    Fsck(FsckRequestV1),
}

/// A complete successful semantic result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MachineResultV1 {
    StoreStatus(StoreStatusV1),
    InitializeStore,
    Prepare(PreparedDeploymentV1),
    Plan(PreparedDeploymentV1),
    Artifact(ArtifactV1),
    Commit(ApplyOutcomeV1),
    State(StateViewV1),
    Recover(RecoveryOutcomeV1),
    Prune(PruneOutcomeV1),
    Checkout(PreparedDeploymentV1),
    Disable(PreparedDeploymentV1),
    Enable(PreparedDeploymentV1),
    RemoveNamespace(PreparedDeploymentV1),
    SetHistoryRetention(PreparedDeploymentV1),
    Pin(PreparedDeploymentV1),
    Unpin(PreparedDeploymentV1),
    AddRestorePoint(PreparedDeploymentV1),
    DropRestorePoint(PreparedDeploymentV1),
    Catalog(CatalogInspectionV1),
    Namespace(NamespaceInspectionV1),
    History(NamespaceHistoryV1),
    Generation(GenerationInspectionV1),
    DesiredSnapshot(DesiredSnapshotInspectionV1),
    CanonicalTree(CanonicalTreeInspectionV1),
    ArtifactMetadata(ArtifactMetadataInspectionV1),
    CapturedInputs(CapturedInputsInspectionV1),
    TransformProvenance(TransformProvenanceInspectionV1),
    Retention(RetentionInspectionV1),
    Tracking(TrackingInspectionV1),
    Status(NamespaceStatusV1),
    Fsck(FsckReportV1),
}

/// A complete client request with no host construction authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RequestEnvelopeV1 {
    request_id: RequestIdV1,
    request: MachineRequestV1,
}

impl RequestEnvelopeV1 {
    #[must_use]
    pub const fn new(request_id: RequestIdV1, request: MachineRequestV1) -> Self {
        Self {
            request_id,
            request,
        }
    }

    #[must_use]
    pub const fn request_id(&self) -> &RequestIdV1 {
        &self.request_id
    }

    #[must_use]
    pub const fn request(&self) -> &MachineRequestV1 {
        &self.request
    }
}

/// The severity of an owned machine diagnostic.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DiagnosticSeverityV1 {
    Error,
    Warning,
    Notice,
}

/// A bounded owned diagnostic that can outlive an Engine callback.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MachineDiagnosticV1 {
    severity: DiagnosticSeverityV1,
    code: MachineCodeV1,
    message: MachineTextV1,
}

impl MachineDiagnosticV1 {
    #[must_use]
    pub const fn new(
        severity: DiagnosticSeverityV1,
        code: MachineCodeV1,
        message: MachineTextV1,
    ) -> Self {
        Self {
            severity,
            code,
            message,
        }
    }

    #[must_use]
    pub const fn severity(&self) -> DiagnosticSeverityV1 {
        self.severity
    }

    #[must_use]
    pub const fn code(&self) -> &MachineCodeV1 {
        &self.code
    }

    #[must_use]
    pub const fn message(&self) -> &MachineTextV1 {
        &self.message
    }
}

/// A broad stable category for terminal machine failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MachineErrorCategoryV1 {
    InvalidRequest,
    Unsupported,
    NotFound,
    PermissionDenied,
    Conflict,
    ResourceLimit,
    Unavailable,
    Internal,
}

/// The closed error code set implemented by the initial machine contract.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MachineErrorCodeV1 {
    MalformedJson,
    InvalidRequest,
    UnsupportedMachineVersion,
    FrameResourceLimit,
    ReadOnlyStore,
    StoreNotReady,
    StateParentMissing,
    UnsafeDirectory,
    RootObservationChanged,
    StateParentObservationChanged,
    MalformedStoreMetadata,
    UnsupportedStoreVersion,
    StoreIo,
    PlanNotFound,
    ArtifactNotFound,
    ApprovalMismatch,
    StalePlan,
    RecoveryRequired,
    OperationBusy,
    InvalidDeployment,
    UnsafeTarget,
    CorruptStore,
    CorruptArtifact,
    DeploymentIo,
    InternalEngineError,
}

impl MachineErrorCodeV1 {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::MalformedJson => "malformed-json",
            Self::InvalidRequest => "invalid-request",
            Self::UnsupportedMachineVersion => "unsupported-machine-version",
            Self::FrameResourceLimit => "frame-resource-limit",
            Self::ReadOnlyStore => "read-only-store",
            Self::StoreNotReady => "store-not-ready",
            Self::StateParentMissing => "state-parent-missing",
            Self::UnsafeDirectory => "unsafe-directory",
            Self::RootObservationChanged => "root-observation-changed",
            Self::StateParentObservationChanged => "state-parent-observation-changed",
            Self::MalformedStoreMetadata => "malformed-store-metadata",
            Self::UnsupportedStoreVersion => "unsupported-store-version",
            Self::StoreIo => "store-io",
            Self::PlanNotFound => "plan-not-found",
            Self::ArtifactNotFound => "artifact-not-found",
            Self::ApprovalMismatch => "approval-mismatch",
            Self::StalePlan => "stale-plan",
            Self::RecoveryRequired => "recovery-required",
            Self::OperationBusy => "operation-busy",
            Self::InvalidDeployment => "invalid-deployment",
            Self::UnsafeTarget => "unsafe-target",
            Self::CorruptStore => "corrupt-store",
            Self::CorruptArtifact => "corrupt-artifact",
            Self::DeploymentIo => "deployment-io",
            Self::InternalEngineError => "internal-engine-error",
        }
    }
}

/// The schema family named by unsupported-version details.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SchemaFamilyV1 {
    Machine,
    Store,
}

/// Closed primitive-only details for a machine error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MachineErrorDetailsV1 {
    None,
    CurrentStatus(StoreStatusV1),
    UnsafeDirectory {
        directory: StoreDirectoryV1,
        reason: DirectorySafetyReasonV1,
    },
    RootObservation(StoreRootV1),
    StoreMetadata(StoreMetadataReasonV1),
    UnsupportedSchema {
        schema: SchemaFamilyV1,
        expected: u32,
        found: u32,
    },
}

/// A complete bounded terminal machine error.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MachineErrorV1 {
    category: MachineErrorCategoryV1,
    code: MachineErrorCodeV1,
    message: MachineTextV1,
    details: MachineErrorDetailsV1,
    diagnostics: Vec<MachineDiagnosticV1>,
}

impl MachineErrorV1 {
    pub fn new(
        category: MachineErrorCategoryV1,
        code: MachineErrorCodeV1,
        message: MachineTextV1,
        details: MachineErrorDetailsV1,
        diagnostics: Vec<MachineDiagnosticV1>,
    ) -> Result<Self, MachineValidationError> {
        if diagnostics.len() > MAX_MACHINE_DIAGNOSTICS {
            return Err(MachineValidationError::TooManyDiagnostics {
                limit: MAX_MACHINE_DIAGNOSTICS,
                actual: diagnostics.len(),
            });
        }
        if expected_error_shape(code) != (category, details_kind(details)) {
            return Err(MachineValidationError::InvalidErrorShape);
        }
        if matches!(
            details,
            MachineErrorDetailsV1::CurrentStatus(StoreStatusV1::Ready)
        ) {
            return Err(MachineValidationError::InvalidErrorShape);
        }
        if let MachineErrorDetailsV1::UnsupportedSchema {
            expected, found, ..
        } = details
            && expected == found
        {
            return Err(MachineValidationError::InvalidErrorShape);
        }
        Ok(Self {
            category,
            code,
            message,
            details,
            diagnostics,
        })
    }

    pub fn from_store(error: StoreErrorV1) -> Self {
        let code = machine_store_code(error.code());
        let details = machine_store_details(error.details());
        let (category, _) = expected_error_shape(code);
        Self {
            category,
            code,
            message: MachineTextV1::new(store_error_message(error.code()))
                .expect("static store error message is valid"),
            details,
            diagnostics: Vec::new(),
        }
    }

    pub(crate) fn malformed_json() -> Self {
        Self::protocol_error(
            MachineErrorCategoryV1::InvalidRequest,
            MachineErrorCodeV1::MalformedJson,
            "The request is not a valid LF-terminated machine JSON record.",
            MachineErrorDetailsV1::None,
        )
    }

    pub(crate) fn invalid_request() -> Self {
        Self::protocol_error(
            MachineErrorCategoryV1::InvalidRequest,
            MachineErrorCodeV1::InvalidRequest,
            "The request does not match the machine/v1 contract.",
            MachineErrorDetailsV1::None,
        )
    }

    pub(crate) fn unsupported_machine_version(found: u32) -> Self {
        Self::protocol_error(
            MachineErrorCategoryV1::Unsupported,
            MachineErrorCodeV1::UnsupportedMachineVersion,
            "The requested machine schema version is unsupported.",
            MachineErrorDetailsV1::UnsupportedSchema {
                schema: SchemaFamilyV1::Machine,
                expected: crate::MACHINE_SCHEMA_VERSION,
                found,
            },
        )
    }

    pub(crate) fn frame_resource_limit() -> Self {
        Self::protocol_error(
            MachineErrorCategoryV1::ResourceLimit,
            MachineErrorCodeV1::FrameResourceLimit,
            "The request exceeds a machine/v1 record resource limit.",
            MachineErrorDetailsV1::None,
        )
    }

    fn protocol_error(
        category: MachineErrorCategoryV1,
        code: MachineErrorCodeV1,
        message: &'static str,
        details: MachineErrorDetailsV1,
    ) -> Self {
        Self::new(
            category,
            code,
            MachineTextV1::new(message).expect("static machine error message is valid"),
            details,
            Vec::new(),
        )
        .expect("static machine error shape is valid")
    }

    #[must_use]
    pub const fn category(&self) -> MachineErrorCategoryV1 {
        self.category
    }

    #[must_use]
    pub const fn code(&self) -> MachineErrorCodeV1 {
        self.code
    }

    #[must_use]
    pub const fn message(&self) -> &MachineTextV1 {
        &self.message
    }

    #[must_use]
    pub const fn details(&self) -> MachineErrorDetailsV1 {
        self.details
    }

    #[must_use]
    pub fn diagnostics(&self) -> &[MachineDiagnosticV1] {
        &self.diagnostics
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ErrorDetailsKind {
    None,
    CurrentStatus,
    UnsafeDirectory,
    RootObservation,
    StoreMetadata,
    UnsupportedMachine,
    UnsupportedStore,
}

const fn details_kind(details: MachineErrorDetailsV1) -> ErrorDetailsKind {
    match details {
        MachineErrorDetailsV1::None => ErrorDetailsKind::None,
        MachineErrorDetailsV1::CurrentStatus(_) => ErrorDetailsKind::CurrentStatus,
        MachineErrorDetailsV1::UnsafeDirectory { .. } => ErrorDetailsKind::UnsafeDirectory,
        MachineErrorDetailsV1::RootObservation(_) => ErrorDetailsKind::RootObservation,
        MachineErrorDetailsV1::StoreMetadata(_) => ErrorDetailsKind::StoreMetadata,
        MachineErrorDetailsV1::UnsupportedSchema {
            schema: SchemaFamilyV1::Machine,
            ..
        } => ErrorDetailsKind::UnsupportedMachine,
        MachineErrorDetailsV1::UnsupportedSchema {
            schema: SchemaFamilyV1::Store,
            ..
        } => ErrorDetailsKind::UnsupportedStore,
    }
}

const fn expected_error_shape(
    code: MachineErrorCodeV1,
) -> (MachineErrorCategoryV1, ErrorDetailsKind) {
    use ErrorDetailsKind as Detail;
    use MachineErrorCategoryV1 as Category;
    use MachineErrorCodeV1 as Code;

    match code {
        Code::MalformedJson | Code::InvalidRequest => (Category::InvalidRequest, Detail::None),
        Code::UnsupportedMachineVersion => (Category::Unsupported, Detail::UnsupportedMachine),
        Code::FrameResourceLimit => (Category::ResourceLimit, Detail::None),
        Code::ReadOnlyStore => (Category::PermissionDenied, Detail::None),
        Code::StoreNotReady => (Category::Conflict, Detail::CurrentStatus),
        Code::StateParentMissing => (Category::NotFound, Detail::None),
        Code::UnsafeDirectory => (Category::Conflict, Detail::UnsafeDirectory),
        Code::RootObservationChanged => (Category::Conflict, Detail::RootObservation),
        Code::StateParentObservationChanged => (Category::Conflict, Detail::None),
        Code::MalformedStoreMetadata => (Category::Conflict, Detail::StoreMetadata),
        Code::UnsupportedStoreVersion => (Category::Unsupported, Detail::UnsupportedStore),
        Code::StoreIo => (Category::Unavailable, Detail::None),
        Code::PlanNotFound | Code::ArtifactNotFound => (Category::NotFound, Detail::None),
        Code::ApprovalMismatch
        | Code::StalePlan
        | Code::RecoveryRequired
        | Code::OperationBusy
        | Code::InvalidDeployment
        | Code::UnsafeTarget
        | Code::CorruptStore
        | Code::CorruptArtifact => (Category::Conflict, Detail::None),
        Code::DeploymentIo => (Category::Unavailable, Detail::None),
        Code::InternalEngineError => (Category::Internal, Detail::None),
    }
}

const fn machine_store_code(code: StoreErrorCodeV1) -> MachineErrorCodeV1 {
    match code {
        StoreErrorCodeV1::ReadOnlyStore => MachineErrorCodeV1::ReadOnlyStore,
        StoreErrorCodeV1::StoreNotReady => MachineErrorCodeV1::StoreNotReady,
        StoreErrorCodeV1::StateParentMissing => MachineErrorCodeV1::StateParentMissing,
        StoreErrorCodeV1::UnsafeDirectory => MachineErrorCodeV1::UnsafeDirectory,
        StoreErrorCodeV1::RootObservationChanged => MachineErrorCodeV1::RootObservationChanged,
        StoreErrorCodeV1::StateParentObservationChanged => {
            MachineErrorCodeV1::StateParentObservationChanged
        }
        StoreErrorCodeV1::MalformedStoreMetadata => MachineErrorCodeV1::MalformedStoreMetadata,
        StoreErrorCodeV1::UnsupportedStoreVersion => MachineErrorCodeV1::UnsupportedStoreVersion,
        StoreErrorCodeV1::Io => MachineErrorCodeV1::StoreIo,
        StoreErrorCodeV1::Internal => MachineErrorCodeV1::InternalEngineError,
    }
}

const fn machine_store_details(details: StoreErrorDetailsV1) -> MachineErrorDetailsV1 {
    match details {
        StoreErrorDetailsV1::None => MachineErrorDetailsV1::None,
        StoreErrorDetailsV1::CurrentStatus(status) => MachineErrorDetailsV1::CurrentStatus(status),
        StoreErrorDetailsV1::UnsafeDirectory { directory, reason } => {
            MachineErrorDetailsV1::UnsafeDirectory { directory, reason }
        }
        StoreErrorDetailsV1::RootObservation(root) => MachineErrorDetailsV1::RootObservation(root),
        StoreErrorDetailsV1::StoreMetadata(reason) => MachineErrorDetailsV1::StoreMetadata(reason),
        StoreErrorDetailsV1::UnsupportedVersion { expected, found } => {
            MachineErrorDetailsV1::UnsupportedSchema {
                schema: SchemaFamilyV1::Store,
                expected,
                found,
            }
        }
    }
}

const fn store_error_message(code: StoreErrorCodeV1) -> &'static str {
    match code {
        StoreErrorCodeV1::ReadOnlyStore => "The Engine was not granted write access to the store.",
        StoreErrorCodeV1::StoreNotReady => "The store is not ready for this operation.",
        StoreErrorCodeV1::StateParentMissing => "The configured state parent does not exist.",
        StoreErrorCodeV1::UnsafeDirectory => "A state directory failed safety validation.",
        StoreErrorCodeV1::RootObservationChanged => {
            "A state root changed while it was being inspected."
        }
        StoreErrorCodeV1::StateParentObservationChanged => {
            "The state parent changed while it was being inspected."
        }
        StoreErrorCodeV1::MalformedStoreMetadata => "The store metadata is malformed.",
        StoreErrorCodeV1::UnsupportedStoreVersion => "The store schema is unsupported.",
        StoreErrorCodeV1::Io => "A store I/O operation failed.",
        StoreErrorCodeV1::Internal => "An internal Engine error occurred.",
    }
}

/// The frame-sequence rule shared by constructors and `validate`.
///
/// A frame with a request ID uses sequence numbers from 1 through the
/// interoperable JSON integer limit. A frame without a request ID uses 0.
const fn sequence_ok(has_request_id: bool, sequence: u64) -> bool {
    if has_request_id {
        sequence > 0 && sequence <= MAX_MACHINE_SEQUENCE
    } else {
        sequence == 0
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(clippy::large_enum_variant)]
pub enum ServerFrameV1 {
    Started {
        request_id: RequestIdV1,
        operation: MachineOperationV1,
    },
    Result {
        request_id: RequestIdV1,
        sequence: u64,
        result: MachineResultV1,
    },
    Error {
        request_id: Option<RequestIdV1>,
        sequence: u64,
        error: MachineErrorV1,
    },
}

impl ServerFrameV1 {
    #[must_use]
    pub const fn started(request_id: RequestIdV1, operation: MachineOperationV1) -> Self {
        Self::Started {
            request_id,
            operation,
        }
    }

    pub fn result(
        request_id: RequestIdV1,
        sequence: u64,
        result: MachineResultV1,
    ) -> Result<Self, MachineValidationError> {
        if !sequence_ok(true, sequence) {
            return Err(MachineValidationError::InvalidSequence {
                frame: "result",
                sequence,
            });
        }
        Ok(Self::Result {
            request_id,
            sequence,
            result,
        })
    }

    pub fn error(
        request_id: Option<RequestIdV1>,
        sequence: u64,
        error: MachineErrorV1,
    ) -> Result<Self, MachineValidationError> {
        if !sequence_ok(request_id.is_some(), sequence) {
            return Err(MachineValidationError::InvalidSequence {
                frame: "error",
                sequence,
            });
        }
        Ok(Self::Error {
            request_id,
            sequence,
            error,
        })
    }

    #[must_use]
    pub const fn uncorrelated_error(error: MachineErrorV1) -> Self {
        Self::Error {
            request_id: None,
            sequence: 0,
            error,
        }
    }

    pub(crate) fn validate(&self) -> Result<(), MachineValidationError> {
        let (frame, has_request_id, sequence) = match self {
            Self::Started { .. } => return Ok(()),
            Self::Result { sequence, .. } => ("result", true, *sequence),
            Self::Error {
                request_id,
                sequence,
                ..
            } => ("error", request_id.is_some(), *sequence),
        };
        if sequence_ok(has_request_id, sequence) {
            Ok(())
        } else {
            Err(MachineValidationError::InvalidSequence { frame, sequence })
        }
    }

    #[must_use]
    pub const fn request_id(&self) -> Option<&RequestIdV1> {
        match self {
            Self::Started { request_id, .. } | Self::Result { request_id, .. } => Some(request_id),
            Self::Error { request_id, .. } => request_id.as_ref(),
        }
    }

    #[must_use]
    pub const fn sequence(&self) -> u64 {
        match self {
            Self::Started { .. } => 0,
            Self::Result { sequence, .. } | Self::Error { sequence, .. } => *sequence,
        }
    }
}

/// Invalid ordering or correlation in an accepted request's response stream.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
#[non_exhaustive]
pub enum MachineStreamError {
    #[error("response frame request ID does not match its request")]
    RequestIdMismatch,
    #[error("response frame operation does not match its request")]
    OperationMismatch,
    #[error("unexpected response frame; expected {expected}")]
    UnexpectedFrame { expected: &'static str },
    #[error("response frame sequence must be {expected}, found {actual}")]
    InvalidSequence { expected: u64, actual: u64 },
    #[error("response stream contains a frame after its terminal frame")]
    FrameAfterTerminal,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ResponseStreamStateV1 {
    AwaitingStarted,
    AwaitingTerminal,
    Terminal,
}

/// Validates records emitted for one fully accepted request without performing I/O.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResponseStreamValidatorV1 {
    request_id: RequestIdV1,
    operation: MachineOperationV1,
    state: ResponseStreamStateV1,
}

impl ResponseStreamValidatorV1 {
    #[must_use]
    pub fn new(request: &RequestEnvelopeV1) -> Self {
        Self {
            request_id: request.request_id().clone(),
            operation: request.request().operation(),
            state: ResponseStreamStateV1::AwaitingStarted,
        }
    }

    /// Validates one response record and advances the stream state.
    pub fn observe(&mut self, frame: &ServerFrameV1) -> Result<(), MachineStreamError> {
        match self.state {
            ResponseStreamStateV1::AwaitingStarted => {
                let ServerFrameV1::Started {
                    request_id,
                    operation,
                } = frame
                else {
                    return Err(MachineStreamError::UnexpectedFrame {
                        expected: "a started event",
                    });
                };
                self.validate_request_id(request_id)?;
                if *operation != self.operation {
                    return Err(MachineStreamError::OperationMismatch);
                }
                self.state = ResponseStreamStateV1::AwaitingTerminal;
                Ok(())
            }
            ResponseStreamStateV1::AwaitingTerminal => {
                let (request_id, sequence, operation) = match frame {
                    ServerFrameV1::Result {
                        request_id,
                        sequence,
                        result,
                    } => (request_id, *sequence, Some(result.operation())),
                    ServerFrameV1::Error {
                        request_id: Some(request_id),
                        sequence,
                        ..
                    } => (request_id, *sequence, None),
                    ServerFrameV1::Started { .. } => {
                        return Err(MachineStreamError::UnexpectedFrame {
                            expected: "a terminal result or error",
                        });
                    }
                    ServerFrameV1::Error {
                        request_id: None, ..
                    } => return Err(MachineStreamError::RequestIdMismatch),
                };
                self.validate_request_id(request_id)?;
                if sequence != 1 {
                    return Err(MachineStreamError::InvalidSequence {
                        expected: 1,
                        actual: sequence,
                    });
                }
                if operation.is_some_and(|operation| operation != self.operation) {
                    return Err(MachineStreamError::OperationMismatch);
                }
                self.state = ResponseStreamStateV1::Terminal;
                Ok(())
            }
            ResponseStreamStateV1::Terminal => Err(MachineStreamError::FrameAfterTerminal),
        }
    }

    #[must_use]
    pub const fn is_terminal(&self) -> bool {
        matches!(self.state, ResponseStreamStateV1::Terminal)
    }

    fn validate_request_id(&self, actual: &RequestIdV1) -> Result<(), MachineStreamError> {
        if actual == &self.request_id {
            Ok(())
        } else {
            Err(MachineStreamError::RequestIdMismatch)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        MachineErrorV1, MachineResultV1, MachineValidationError, RequestIdV1, ServerFrameV1,
    };
    use crate::MAX_MACHINE_SEQUENCE;

    const SEQUENCE_CASES: [u64; 4] = [0, 1, MAX_MACHINE_SEQUENCE, MAX_MACHINE_SEQUENCE + 1];

    fn request_id() -> RequestIdV1 {
        RequestIdV1::new("req-1").expect("static request ID is valid")
    }

    #[test]
    fn constructor_and_validate_agree_on_sequence_boundaries() {
        for sequence in SEQUENCE_CASES {
            let constructed =
                ServerFrameV1::result(request_id(), sequence, MachineResultV1::InitializeStore);
            let unchecked = ServerFrameV1::Result {
                request_id: request_id(),
                sequence,
                result: MachineResultV1::InitializeStore,
            };
            assert_eq!(
                constructed.is_ok(),
                unchecked.validate().is_ok(),
                "result frame disagreement at sequence {sequence}"
            );
            assert_eq!(
                constructed.err(),
                unchecked.validate().err(),
                "result frame error disagreement at sequence {sequence}"
            );

            for correlated in [false, true] {
                let id = correlated.then(request_id);
                let constructed =
                    ServerFrameV1::error(id.clone(), sequence, MachineErrorV1::malformed_json());
                let unchecked = ServerFrameV1::Error {
                    request_id: id,
                    sequence,
                    error: MachineErrorV1::malformed_json(),
                };
                assert_eq!(
                    constructed.is_ok(),
                    unchecked.validate().is_ok(),
                    "error frame disagreement at sequence {sequence}, correlated {correlated}"
                );
                assert_eq!(
                    constructed.err(),
                    unchecked.validate().err(),
                    "error frame error disagreement at sequence {sequence}, correlated {correlated}"
                );
            }
        }
    }

    #[test]
    fn sequence_rule_accepts_only_the_specified_cases() {
        let accepted: Vec<(bool, u64)> = [false, true]
            .into_iter()
            .flat_map(|correlated| SEQUENCE_CASES.map(|sequence| (correlated, sequence)))
            .filter(|&(correlated, sequence)| super::sequence_ok(correlated, sequence))
            .collect();
        assert_eq!(
            accepted,
            vec![(false, 0), (true, 1), (true, MAX_MACHINE_SEQUENCE)]
        );
    }

    #[test]
    fn sequence_error_message_is_stable() {
        let error = ServerFrameV1::result(request_id(), 0, MachineResultV1::InitializeStore)
            .expect_err("sequence 0 is rejected for result frames");
        assert_eq!(
            error,
            MachineValidationError::InvalidSequence {
                frame: "result",
                sequence: 0,
            }
        );
        assert_eq!(
            error.to_string(),
            "result frame cannot use sequence 0; maximum is 9007199254740991"
        );
    }
}
