use std::panic::{AssertUnwindSafe, catch_unwind};

use crate::{
    ArchivePublicationError, CommitError, EngineError, GraphAcquisitionError, LockOperationError,
    ProfileSwitchError, StaticDeploymentPrepareError, StaticPrepareError, TrackedRootError,
};

/// Correlates progress and diagnostics from one Engine operation.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct OperationId(u64);

impl OperationId {
    pub(crate) const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Returns the Engine-local numeric identifier.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// A public Engine operation that can emit progress or diagnostics.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum EngineOperation {
    StoreStatus,
    InitializeStore,
    PublishFileObjectV1,
    PublishSymlinkObjectV1,
    PublishTreeObjectV1,
    LoadFileObjectV1,
    LoadSymlinkObjectV1,
    LoadTreeObjectV1,
    DecodeAndPublishArchiveV1,
    PublishPackObjectV1,
    CaptureLocalPackV1,
    AcquireGitPackV1,
    AcquireLocalGraphV1,
    AcquireGraphV1,
    CreateLockV1,
    UpdateLockV1,
    LoadPackObjectV1,
    AssembleCachedGraphV1,
    PrepareV1,
    InspectPlanV1,
    InspectPlanIndexV1,
    InspectArtifactMetadataV1,
    InspectCapturedInputsV1,
    InspectTransformProvenanceV1,
    LoadArtifactV1,
    PrepareStaticProfileV1,
    PrepareStaticDeploymentV1,
    PrepareTrackedRootV1,
    UpdateTrackedRootV1,
    PrepareProfileSwitchV1,
    PrepareCheckoutV1,
    PrepareDisableV1,
    PrepareEnableV1,
    PrepareNamespaceRemovalV1,
    PrepareRetentionAuthorityV1,
    CommitV1,
    RecoverV1,
    InspectStateV1,
    InspectCatalogV1,
    InspectNamespaceV1,
    InspectNamespaceHistoryV1,
    InspectGenerationInventoryV1,
    InspectGenerationV1,
    InspectDesiredSnapshotV1,
    InspectCanonicalTreeV1,
    InspectObjectInventoryV1,
    InspectRetentionV1,
    InspectTrackingV1,
    FsckV1,
    InspectNamespaceStatusV1,
    PruneV1,
}

impl EngineOperation {
    /// Every public Engine operation in stable inventory order.
    pub const ALL: &'static [Self] = &[
        Self::StoreStatus,
        Self::InitializeStore,
        Self::PublishFileObjectV1,
        Self::PublishSymlinkObjectV1,
        Self::PublishTreeObjectV1,
        Self::LoadFileObjectV1,
        Self::LoadSymlinkObjectV1,
        Self::LoadTreeObjectV1,
        Self::DecodeAndPublishArchiveV1,
        Self::PublishPackObjectV1,
        Self::CaptureLocalPackV1,
        Self::AcquireGitPackV1,
        Self::AcquireLocalGraphV1,
        Self::AcquireGraphV1,
        Self::CreateLockV1,
        Self::UpdateLockV1,
        Self::LoadPackObjectV1,
        Self::AssembleCachedGraphV1,
        Self::PrepareV1,
        Self::InspectPlanV1,
        Self::InspectPlanIndexV1,
        Self::InspectArtifactMetadataV1,
        Self::InspectCapturedInputsV1,
        Self::InspectTransformProvenanceV1,
        Self::LoadArtifactV1,
        Self::PrepareStaticProfileV1,
        Self::PrepareStaticDeploymentV1,
        Self::PrepareTrackedRootV1,
        Self::UpdateTrackedRootV1,
        Self::PrepareProfileSwitchV1,
        Self::PrepareCheckoutV1,
        Self::PrepareDisableV1,
        Self::PrepareEnableV1,
        Self::PrepareNamespaceRemovalV1,
        Self::PrepareRetentionAuthorityV1,
        Self::CommitV1,
        Self::RecoverV1,
        Self::InspectStateV1,
        Self::InspectCatalogV1,
        Self::InspectNamespaceV1,
        Self::InspectNamespaceHistoryV1,
        Self::InspectGenerationInventoryV1,
        Self::InspectGenerationV1,
        Self::InspectDesiredSnapshotV1,
        Self::InspectCanonicalTreeV1,
        Self::InspectObjectInventoryV1,
        Self::InspectRetentionV1,
        Self::InspectTrackingV1,
        Self::FsckV1,
        Self::InspectNamespaceStatusV1,
        Self::PruneV1,
    ];

    /// Returns the stable identifier used by operation inventories and adapters.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::StoreStatus => "store_status",
            Self::InitializeStore => "initialize_store",
            Self::PublishFileObjectV1 => "publish_file_object_v1",
            Self::PublishSymlinkObjectV1 => "publish_symlink_object_v1",
            Self::PublishTreeObjectV1 => "publish_tree_object_v1",
            Self::LoadFileObjectV1 => "load_file_object_v1",
            Self::LoadSymlinkObjectV1 => "load_symlink_object_v1",
            Self::LoadTreeObjectV1 => "load_tree_object_v1",
            Self::DecodeAndPublishArchiveV1 => "decode_and_publish_archive_v1",
            Self::PublishPackObjectV1 => "publish_pack_object_v1",
            Self::CaptureLocalPackV1 => "capture_local_pack_v1",
            Self::AcquireGitPackV1 => "acquire_git_pack_v1",
            Self::AcquireLocalGraphV1 => "acquire_local_graph_v1",
            Self::AcquireGraphV1 => "acquire_graph_v1",
            Self::CreateLockV1 => "create_lock_v1",
            Self::UpdateLockV1 => "update_lock_v1",
            Self::LoadPackObjectV1 => "load_pack_object_v1",
            Self::AssembleCachedGraphV1 => "assemble_cached_graph_v1",
            Self::PrepareV1 => "prepare_v1",
            Self::InspectPlanV1 => "inspect_plan_v1",
            Self::InspectPlanIndexV1 => "inspect_plan_index_v1",
            Self::InspectArtifactMetadataV1 => "inspect_artifact_metadata_v1",
            Self::InspectCapturedInputsV1 => "inspect_captured_inputs_v1",
            Self::InspectTransformProvenanceV1 => "inspect_transform_provenance_v1",
            Self::LoadArtifactV1 => "load_artifact_v1",
            Self::PrepareStaticProfileV1 => "prepare_static_profile_v1",
            Self::PrepareStaticDeploymentV1 => "prepare_static_deployment_v1",
            Self::PrepareTrackedRootV1 => "prepare_tracked_root_v1",
            Self::UpdateTrackedRootV1 => "update_tracked_root_v1",
            Self::PrepareProfileSwitchV1 => "prepare_profile_switch_v1",
            Self::PrepareCheckoutV1 => "prepare_checkout_v1",
            Self::PrepareDisableV1 => "prepare_disable_v1",
            Self::PrepareEnableV1 => "prepare_enable_v1",
            Self::PrepareNamespaceRemovalV1 => "prepare_namespace_removal_v1",
            Self::PrepareRetentionAuthorityV1 => "prepare_retention_authority_v1",
            Self::CommitV1 => "commit_v1",
            Self::RecoverV1 => "recover_v1",
            Self::InspectStateV1 => "inspect_state_v1",
            Self::InspectCatalogV1 => "inspect_catalog_v1",
            Self::InspectNamespaceV1 => "inspect_namespace_v1",
            Self::InspectNamespaceHistoryV1 => "inspect_namespace_history_v1",
            Self::InspectGenerationInventoryV1 => "inspect_generation_inventory_v1",
            Self::InspectGenerationV1 => "inspect_generation_v1",
            Self::InspectDesiredSnapshotV1 => "inspect_desired_snapshot_v1",
            Self::InspectCanonicalTreeV1 => "inspect_canonical_tree_v1",
            Self::InspectObjectInventoryV1 => "inspect_object_inventory_v1",
            Self::InspectRetentionV1 => "inspect_retention_v1",
            Self::InspectTrackingV1 => "inspect_tracking_v1",
            Self::FsckV1 => "fsck_v1",
            Self::InspectNamespaceStatusV1 => "inspect_namespace_status_v1",
            Self::PruneV1 => "prune_v1",
        }
    }
}

/// Final status of an observed Engine operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum OperationOutcome {
    Succeeded,
    Failed,
}

/// Structured progress emitted synchronously by the Engine facade.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ProgressEvent {
    OperationStarted {
        operation_id: OperationId,
        operation: EngineOperation,
    },
    OperationFinished {
        operation_id: OperationId,
        operation: EngineOperation,
        outcome: OperationOutcome,
    },
}

/// Receives typed progress without controlling Engine outcomes.
pub trait ProgressSink: Send + Sync + 'static {
    /// Called synchronously on the thread executing the operation.
    ///
    /// Implementations should be fast and non-reentrant. Panics are isolated
    /// and do not alter the Engine result.
    fn emit(&self, event: ProgressEvent);
}

/// Identifies the structured error family referenced by a diagnostic.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum EngineFailureKind {
    Engine,
    ArchivePublication,
    GraphAcquisition,
    GraphAssembly,
    LockOperation,
    StaticPrepare,
    StaticDeploymentPrepare,
    TrackedRoot,
    ProfileSwitch,
    Commit,
}

/// Borrowed structured failure from an Engine operation.
#[derive(Clone, Copy, Debug)]
#[non_exhaustive]
pub enum EngineFailureRef<'a> {
    Engine(&'a EngineError),
    ArchivePublication(&'a ArchivePublicationError),
    GraphAcquisition(&'a GraphAcquisitionError),
    GraphAssembly(&'a malm_module_graph::GraphAssemblyError<EngineError>),
    LockOperation(&'a LockOperationError),
    StaticPrepare(&'a StaticPrepareError),
    StaticDeploymentPrepare(&'a StaticDeploymentPrepareError),
    TrackedRoot(&'a TrackedRootError),
    ProfileSwitch(&'a ProfileSwitchError),
    Commit(&'a CommitError),
}

impl EngineFailureRef<'_> {
    /// Returns the stable Rust error family for this diagnostic.
    #[must_use]
    pub const fn kind(self) -> EngineFailureKind {
        match self {
            Self::Engine(_) => EngineFailureKind::Engine,
            Self::ArchivePublication(_) => EngineFailureKind::ArchivePublication,
            Self::GraphAcquisition(_) => EngineFailureKind::GraphAcquisition,
            Self::GraphAssembly(_) => EngineFailureKind::GraphAssembly,
            Self::LockOperation(_) => EngineFailureKind::LockOperation,
            Self::StaticPrepare(_) => EngineFailureKind::StaticPrepare,
            Self::StaticDeploymentPrepare(_) => EngineFailureKind::StaticDeploymentPrepare,
            Self::TrackedRoot(_) => EngineFailureKind::TrackedRoot,
            Self::ProfileSwitch(_) => EngineFailureKind::ProfileSwitch,
            Self::Commit(_) => EngineFailureKind::Commit,
        }
    }
}

/// One typed operation failure emitted before the operation finishes.
#[derive(Clone, Copy, Debug)]
pub struct DiagnosticEvent<'a> {
    operation_id: OperationId,
    operation: EngineOperation,
    failure: EngineFailureRef<'a>,
}

impl<'a> DiagnosticEvent<'a> {
    pub(crate) const fn new(
        operation_id: OperationId,
        operation: EngineOperation,
        failure: EngineFailureRef<'a>,
    ) -> Self {
        Self {
            operation_id,
            operation,
            failure,
        }
    }

    #[must_use]
    pub const fn operation_id(&self) -> OperationId {
        self.operation_id
    }

    #[must_use]
    pub const fn operation(&self) -> EngineOperation {
        self.operation
    }

    #[must_use]
    pub const fn failure(&self) -> EngineFailureRef<'a> {
        self.failure
    }
}

/// Receives typed diagnostics without replacing the returned structured error.
pub trait DiagnosticSink: Send + Sync + 'static {
    /// Called synchronously after an operation fails.
    ///
    /// Implementations should be fast and non-reentrant. Panics are isolated
    /// and do not alter the Engine result.
    fn emit(&self, event: DiagnosticEvent<'_>);
}

pub(crate) fn emit_progress(sink: &dyn ProgressSink, event: ProgressEvent) {
    discard_panic(catch_unwind(AssertUnwindSafe(|| sink.emit(event))));
}

pub(crate) fn emit_diagnostic(sink: &dyn DiagnosticSink, event: DiagnosticEvent<'_>) {
    discard_panic(catch_unwind(AssertUnwindSafe(|| sink.emit(event))));
}

fn discard_panic(result: std::thread::Result<()>) {
    if let Err(payload) = result
        && let Err(drop_panic) = catch_unwind(AssertUnwindSafe(|| drop(payload)))
    {
        // A hostile panic payload may itself panic while being destroyed.
        // Leaking that second payload preserves the observer-isolation contract.
        std::mem::forget(drop_panic);
    }
}

#[derive(Debug)]
pub(crate) struct NoopProgressSink;

impl ProgressSink for NoopProgressSink {
    fn emit(&self, _event: ProgressEvent) {}
}

#[derive(Debug)]
pub(crate) struct NoopDiagnosticSink;

impl DiagnosticSink for NoopDiagnosticSink {
    fn emit(&self, _event: DiagnosticEvent<'_>) {}
}
