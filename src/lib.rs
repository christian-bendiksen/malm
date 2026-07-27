#![forbid(unsafe_code)]
//! Exports the Engine API and the Malm CLI entry point.

#[cfg(all(feature = "failpoints", not(debug_assertions)))]
compile_error!("the `failpoints` feature must not be enabled in release builds");

pub mod api;
pub(crate) mod cli;

pub use malm_engine::{
    ApplyOutcomeV1, ApprovalV1, ArtifactBytesInspectionRequestV1, ArtifactDescriptorV1, ArtifactId,
    ArtifactMetadataInspectionRequestV1, ArtifactMetadataInspectionV1, ArtifactV1,
    CanonicalTreeEntryInspectionV1, CanonicalTreeEntryKindInspectionV1,
    CanonicalTreeInspectionRequestV1, CanonicalTreeInspectionV1, CapturedInputsInspectionV1,
    CatalogInspectionRequestV1, CatalogInspectionV1, CatalogNamespaceInspectionV1,
    CheckoutRequestV1, CommitConfigError, CommitError, CommitRequestV1, ConfigEntryPointV1,
    DeploymentDtoError, DesiredSnapshotInspectionRequestV1, DesiredSnapshotInspectionV1,
    DesiredTargetInspectionV1, DesiredTargetStateInspectionV1, DiagnosticEvent, DiagnosticSink,
    DirectorySafetyIssue, DirectorySafetyReasonV1, DisableRequestV1, EnableRequestV1, Engine,
    EngineConfig, EngineConfigError, EngineError, EngineFailureKind, EngineFailureRef,
    EngineOperation, EnginePorts, FormatComponentAuthorizationV1, FormatComponentExecutionIssue,
    FormatComponentExecutionPort, FsckFindingCodeV1, FsckFindingV1, FsckReportPartsV1,
    FsckReportV1, FsckRequestV1, FsckSeverityV1, FsckStoreAreaV1, FsckSubjectV1,
    GenerationInspectionPartsV1, GenerationInspectionRequestV1, GenerationInspectionV1,
    GenerationInventoryRequestV1, GenerationInventoryV1, GitAcquisitionConfig,
    GitAcquisitionConfigError, GitAcquisitionIssue, GitCommandStage, GitObjectFormat,
    GitObjectKind, GitOutputStream, GitPackFile, GitProcessPort, GraphAcquisitionError,
    GraphAcquisitionInputs, HistoryRetentionRequestV1, InitializeStoreOutcome, InspectionDtoError,
    InspectionLimitsV1, LifecycleRequestV1, LifecycleStateViewV1, LifecycleTransitionViewV1,
    LockFileIssue, LockFilePublication, LockOperationError, LockOperationOutcome,
    LockResolutionInputs, MAX_GIT_ACQUISITION_TIMEOUT, MAX_GIT_TRANSFER_BYTES, MovingSelectorV1,
    NamespaceHistoryRequestV1, NamespaceHistoryV1, NamespaceInspectionRequestV1,
    NamespaceInspectionV1, NamespaceRemovalHistoryV1, NamespaceRemovalRequestV1,
    NamespaceStatusKindV1, NamespaceStatusPartsV1, NamespaceStatusRequestV1, NamespaceStatusV1,
    ObjectInventoryKindV1, ObjectInventoryRequestV1, ObjectInventoryV1, OperationId,
    OperationOutcome, OwnershipOverlapKindV1, PackCaptureIssue, PackObjectIssue,
    PackObjectPublication, PlanIndexEntryV1, PolicyFindingV1, PrepareArtifactV1,
    PrepareInputKindV1, PrepareInputV1, PrepareOperationV1, PreparePolicyFindingV1,
    PrepareRequestPartsV1, PrepareRequestV1, PrepareTransformDiagnosticLocationV1,
    PrepareTransformDiagnosticSeverityV1, PrepareTransformDiagnosticV1,
    PrepareTransformImplementationV1, PrepareTransformOutputLocationV1,
    PrepareTransformProvenanceV1, PrepareTransformResourceV1, PrepareTransformSourceLocationV1,
    PreparedDeploymentPartsV1, PreparedDeploymentV1, PreparedId, PreparedPlanInspectionRequestV1,
    PreparedStoreIssue, ProcessFacts, ProfileSwitchError, ProfileSwitchRequestV1, ProgressEvent,
    ProgressSink, PruneOutcomeV1, PruneRequestV1, RecoveryOutcomeV1, RestorePointInspectionV1,
    RestorePointRequestV1, RetentionAuthorityInspectionV1, RetentionInspectionV1,
    RetentionObjectV1, RetentionPinRequestV1, SecureRandomPort, StateDirectory, StateViewV1,
    StaticDeploymentPrepareError, StaticDeploymentPrepareRequestV1, StaticGraphAcquisitionV1,
    StaticPrepareError, StoreAccess, StoreDirectoryV1, StoreErrorCodeV1, StoreErrorDetailsV1,
    StoreErrorV1, StoreErrorValidationError, StoreMetadataIssue, StoreMetadataReasonV1,
    StoreOperationV1, StoreRequestV1, StoreResultV1, StoreRootV1, StoreStatus, StoreStatusV1,
    TargetStatusKindV1, TargetStatusV1, TrackedRootAcquisitionGrantsV1, TrackedRootError,
    TrackedRootInfrastructureV1, TrackedRootInspectionV1, TrackedRootNoChangeV1,
    TrackedRootPrepareRequestPartsV1, TrackedRootPrepareRequestV1, TrackedRootRequestError,
    TrackedRootUpdateOutcomeV1, TrackedRootUpdateRequestV1, TrackingInspectionV1,
    TransformProvenanceInspectionV1, TreeObjectV1, tree_object_digest_v1,
};
