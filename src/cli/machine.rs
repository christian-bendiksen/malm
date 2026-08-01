//! Adapts one strict machine/v1 request stream over standard input and output.

use std::io::{BufRead, Read, Write};

use anyhow::Result;
use malm_machine::{
    MAX_MACHINE_FRAME_BYTES, MachineErrorCategoryV1, MachineErrorCodeV1, MachineErrorDetailsV1,
    MachineErrorV1, MachineRequestV1, MachineResultV1, MachineTextV1, MachineWriteError,
    ServerFrameV1, decode_request_v1, encode_server_frame_v1, request_error_frame_v1,
};

use crate::cli::output::{
    CommitErrorClass, EngineErrorClass, classify_commit_error, classify_engine_error,
};
use crate::{
    CommitError, Engine, EngineConfig, EngineError, EngineOperation, EnginePorts, StoreAccess,
    StoreRequestV1,
};
use malm_types::DeploymentName;

pub fn run() -> Result<i32> {
    let mut bytes = Vec::new();
    std::io::stdin()
        .lock()
        .take(malm_types::usize_to_u64(MAX_MACHINE_FRAME_BYTES + 1))
        .read_until(b'\n', &mut bytes)?;
    let request = match decode_request_v1(&bytes) {
        Ok(request) => request,
        Err(error) => {
            write_frame(&request_error_frame_v1(&error))?;
            return Ok(2);
        }
    };
    let operation = request.request().operation();
    write_frame(&ServerFrameV1::started(
        request.request_id().clone(),
        operation,
    ))?;

    let contract = crate::cli::contracts::machine_contract(operation);
    let access = contract
        .effect()
        .store_access()
        .expect("machine operations have a fixed store-access effect");
    let config = match engine_config(access, requires_target(request.request())) {
        Ok(config) => config,
        Err(_) => {
            write_frame(&ServerFrameV1::error(
                Some(request.request_id().clone()),
                1,
                adapter_error(),
            )?)?;
            return Ok(2);
        }
    };
    let engine = Engine::new(config, EnginePorts::system());
    match execute(&engine, request.request(), contract) {
        Ok(result) => {
            let frame = ServerFrameV1::result(request.request_id().clone(), 1, result)?;
            match encode_server_frame_v1(&frame) {
                Ok(bytes) => {
                    write_bytes(&bytes)?;
                    Ok(0)
                }
                Err(MachineWriteError::TooLarge { .. }) => {
                    write_frame(&ServerFrameV1::error(
                        Some(request.request_id().clone()),
                        1,
                        simple_error(
                            MachineErrorCategoryV1::ResourceLimit,
                            MachineErrorCodeV1::FrameResourceLimit,
                            "The result exceeds a machine record resource limit.",
                        ),
                    )?)?;
                    Ok(2)
                }
                Err(error) => Err(error.into()),
            }
        }
        Err(error) => {
            write_frame(&ServerFrameV1::error(
                Some(request.request_id().clone()),
                1,
                error,
            )?)?;
            Ok(2)
        }
    }
}

fn engine_config(access: StoreAccess, target: bool) -> Result<EngineConfig> {
    let environment = crate::cli::SuccessorEnvironment::ambient()?;
    let mut config = environment.engine_config(access)?;
    if target {
        config = config.with_target_authority(DeploymentName::new("home")?, environment.home()?)?;
    }
    Ok(config)
}

fn requires_target(request: &MachineRequestV1) -> bool {
    match request {
        MachineRequestV1::Prepare(_)
        | MachineRequestV1::Commit(_)
        | MachineRequestV1::Recover
        | MachineRequestV1::Checkout(_)
        | MachineRequestV1::Disable(_)
        | MachineRequestV1::Enable(_)
        | MachineRequestV1::RemoveNamespace(_)
        | MachineRequestV1::SetHistoryRetention(_)
        | MachineRequestV1::Pin(_)
        | MachineRequestV1::Unpin(_)
        | MachineRequestV1::AddRestorePoint(_)
        | MachineRequestV1::DropRestorePoint(_)
        | MachineRequestV1::Status(_) => true,
        MachineRequestV1::Fsck(request) => request.observes_targets(),
        MachineRequestV1::StoreStatus
        | MachineRequestV1::InitializeStore
        | MachineRequestV1::Plan(_)
        | MachineRequestV1::Artifact { .. }
        | MachineRequestV1::State(_)
        | MachineRequestV1::Prune(_)
        | MachineRequestV1::Catalog(_)
        | MachineRequestV1::Namespace(_)
        | MachineRequestV1::History(_)
        | MachineRequestV1::Generation(_)
        | MachineRequestV1::DesiredSnapshot(_)
        | MachineRequestV1::CanonicalTree(_)
        | MachineRequestV1::ArtifactMetadata(_)
        | MachineRequestV1::CapturedInputs(_)
        | MachineRequestV1::TransformProvenance(_)
        | MachineRequestV1::Retention(_)
        | MachineRequestV1::Tracking(_) => false,
    }
}

fn execute(
    engine: &Engine,
    request: &MachineRequestV1,
    contract: crate::cli::contracts::OperationContract,
) -> Result<MachineResultV1, MachineErrorV1> {
    contract.assert_engine_operation(executed_engine_operation(request));
    match request {
        MachineRequestV1::StoreStatus => engine
            .execute_store_v1(StoreRequestV1::status())
            .map(|result| MachineResultV1::StoreStatus(result.store_status()))
            .map_err(MachineErrorV1::from_store),
        MachineRequestV1::InitializeStore => engine
            .execute_store_v1(StoreRequestV1::initialize())
            .map(|_| MachineResultV1::InitializeStore)
            .map_err(MachineErrorV1::from_store),
        MachineRequestV1::Prepare(request) => engine
            .prepare_v1(request)
            .map(MachineResultV1::Prepare)
            .map_err(machine_engine_error),
        MachineRequestV1::Plan(plan_id) => engine
            .plan_v1(plan_id)
            .map(MachineResultV1::Plan)
            .map_err(machine_engine_error),
        MachineRequestV1::Artifact {
            plan_id,
            artifact_id,
        } => engine
            .artifact_v1(plan_id, artifact_id)
            .map(MachineResultV1::Artifact)
            .map_err(machine_engine_error),
        MachineRequestV1::Commit(request) => engine
            .commit_v1(request)
            .map(MachineResultV1::Commit)
            .map_err(machine_commit_error),
        MachineRequestV1::State(namespace) => engine
            .inspect_state_v1(namespace)
            .map(MachineResultV1::State)
            .map_err(machine_commit_error),
        MachineRequestV1::Recover => engine
            .recover_v1()
            .map(MachineResultV1::Recover)
            .map_err(machine_commit_error),
        MachineRequestV1::Prune(request) => engine
            .prune_v1(request)
            .map(MachineResultV1::Prune)
            .map_err(machine_commit_error),
        MachineRequestV1::Checkout(request) => engine
            .prepare_checkout_v1(request)
            .map(MachineResultV1::Checkout)
            .map_err(machine_engine_error),
        MachineRequestV1::Disable(request) => engine
            .prepare_disable_v1(request)
            .map(MachineResultV1::Disable)
            .map_err(machine_engine_error),
        MachineRequestV1::Enable(request) => engine
            .prepare_enable_v1(request)
            .map(MachineResultV1::Enable)
            .map_err(machine_engine_error),
        MachineRequestV1::RemoveNamespace(request) => engine
            .prepare_namespace_removal_v1(request)
            .map(MachineResultV1::RemoveNamespace)
            .map_err(machine_engine_error),
        MachineRequestV1::SetHistoryRetention(request) => engine
            .prepare_history_retention_v1(request)
            .map(MachineResultV1::SetHistoryRetention)
            .map_err(machine_engine_error),
        MachineRequestV1::Pin(request) => engine
            .prepare_pin_v1(request)
            .map(MachineResultV1::Pin)
            .map_err(machine_engine_error),
        MachineRequestV1::Unpin(request) => engine
            .prepare_unpin_v1(request)
            .map(MachineResultV1::Unpin)
            .map_err(machine_engine_error),
        MachineRequestV1::AddRestorePoint(request) => engine
            .prepare_restore_point_v1(request)
            .map(MachineResultV1::AddRestorePoint)
            .map_err(machine_engine_error),
        MachineRequestV1::DropRestorePoint(request) => engine
            .prepare_drop_restore_point_v1(request)
            .map(MachineResultV1::DropRestorePoint)
            .map_err(machine_engine_error),
        MachineRequestV1::Catalog(request) => engine
            .inspect_catalog_v1(request)
            .map(MachineResultV1::Catalog)
            .map_err(machine_commit_error),
        MachineRequestV1::Namespace(request) => engine
            .inspect_namespace_v1(request)
            .map(MachineResultV1::Namespace)
            .map_err(machine_commit_error),
        MachineRequestV1::History(request) => engine
            .inspect_namespace_history_v1(request)
            .map(MachineResultV1::History)
            .map_err(machine_commit_error),
        MachineRequestV1::Generation(request) => engine
            .inspect_generation_details_v1(request)
            .map(MachineResultV1::Generation)
            .map_err(machine_commit_error),
        MachineRequestV1::DesiredSnapshot(request) => engine
            .inspect_desired_snapshot_v1(request)
            .map(MachineResultV1::DesiredSnapshot)
            .map_err(machine_commit_error),
        MachineRequestV1::CanonicalTree(request) => engine
            .inspect_canonical_tree_v1(request)
            .map(MachineResultV1::CanonicalTree)
            .map_err(machine_commit_error),
        MachineRequestV1::ArtifactMetadata(request) => engine
            .inspect_artifact_metadata_v1(request)
            .map(MachineResultV1::ArtifactMetadata)
            .map_err(machine_engine_error),
        MachineRequestV1::CapturedInputs(request) => engine
            .inspect_captured_inputs_v1(request)
            .map(MachineResultV1::CapturedInputs)
            .map_err(machine_engine_error),
        MachineRequestV1::TransformProvenance(request) => engine
            .inspect_transform_provenance_v1(request)
            .map(MachineResultV1::TransformProvenance)
            .map_err(machine_engine_error),
        MachineRequestV1::Retention(request) => engine
            .inspect_retention_authority_v1(request)
            .map(MachineResultV1::Retention)
            .map_err(machine_commit_error),
        MachineRequestV1::Tracking(request) => engine
            .inspect_tracking_v1(request)
            .map(MachineResultV1::Tracking)
            .map_err(machine_commit_error),
        MachineRequestV1::Status(request) => engine
            .inspect_namespace_status_v1(request)
            .map(MachineResultV1::Status)
            .map_err(machine_commit_error),
        MachineRequestV1::Fsck(request) => engine
            .fsck_v1(request)
            .map(MachineResultV1::Fsck)
            .map_err(machine_commit_error),
    }
}

const fn executed_engine_operation(request: &MachineRequestV1) -> EngineOperation {
    match request {
        MachineRequestV1::StoreStatus => EngineOperation::StoreStatus,
        MachineRequestV1::InitializeStore => EngineOperation::InitializeStore,
        MachineRequestV1::Prepare(_) => EngineOperation::PrepareV1,
        MachineRequestV1::Plan(_) => EngineOperation::InspectPlanV1,
        MachineRequestV1::Artifact { .. } => EngineOperation::LoadArtifactV1,
        MachineRequestV1::Commit(_) => EngineOperation::CommitV1,
        MachineRequestV1::State(_) => EngineOperation::InspectStateV1,
        MachineRequestV1::Recover => EngineOperation::RecoverV1,
        MachineRequestV1::Prune(_) => EngineOperation::PruneV1,
        MachineRequestV1::Checkout(_) => EngineOperation::PrepareCheckoutV1,
        MachineRequestV1::Disable(_) => EngineOperation::PrepareDisableV1,
        MachineRequestV1::Enable(_) => EngineOperation::PrepareEnableV1,
        MachineRequestV1::RemoveNamespace(_) => EngineOperation::PrepareNamespaceRemovalV1,
        MachineRequestV1::SetHistoryRetention(_)
        | MachineRequestV1::Pin(_)
        | MachineRequestV1::Unpin(_)
        | MachineRequestV1::AddRestorePoint(_)
        | MachineRequestV1::DropRestorePoint(_) => EngineOperation::PrepareRetentionAuthorityV1,
        MachineRequestV1::Catalog(_) => EngineOperation::InspectCatalogV1,
        MachineRequestV1::Namespace(_) => EngineOperation::InspectNamespaceV1,
        MachineRequestV1::History(_) => EngineOperation::InspectNamespaceHistoryV1,
        MachineRequestV1::Generation(_) => EngineOperation::InspectGenerationV1,
        MachineRequestV1::DesiredSnapshot(_) => EngineOperation::InspectDesiredSnapshotV1,
        MachineRequestV1::CanonicalTree(_) => EngineOperation::InspectCanonicalTreeV1,
        MachineRequestV1::ArtifactMetadata(_) => EngineOperation::InspectArtifactMetadataV1,
        MachineRequestV1::CapturedInputs(_) => EngineOperation::InspectCapturedInputsV1,
        MachineRequestV1::TransformProvenance(_) => EngineOperation::InspectTransformProvenanceV1,
        MachineRequestV1::Retention(_) => EngineOperation::InspectRetentionV1,
        MachineRequestV1::Tracking(_) => EngineOperation::InspectTrackingV1,
        MachineRequestV1::Status(_) => EngineOperation::InspectNamespaceStatusV1,
        MachineRequestV1::Fsck(_) => EngineOperation::FsckV1,
    }
}

fn write_frame(frame: &ServerFrameV1) -> Result<()> {
    let bytes = encode_server_frame_v1(frame)?;
    write_bytes(&bytes)
}

fn write_bytes(bytes: &[u8]) -> Result<()> {
    let mut stdout = std::io::stdout().lock();
    stdout.write_all(bytes)?;
    stdout.flush()?;
    Ok(())
}

fn machine_engine_error(error: EngineError) -> MachineErrorV1 {
    match classify_engine_error(&error) {
        EngineErrorClass::ReadOnlyStore => simple_error(
            MachineErrorCategoryV1::PermissionDenied,
            MachineErrorCodeV1::ReadOnlyStore,
            "The Engine was not granted write access to the store.",
        ),
        EngineErrorClass::PreparedMissingPlan => simple_error(
            MachineErrorCategoryV1::NotFound,
            MachineErrorCodeV1::PlanNotFound,
            "The requested prepared plan does not exist.",
        ),
        EngineErrorClass::PreparedMissingArtifact => simple_error(
            MachineErrorCategoryV1::NotFound,
            MachineErrorCodeV1::ArtifactNotFound,
            "The requested prepared artifact does not exist.",
        ),
        EngineErrorClass::PreparedBusy => simple_error(
            MachineErrorCategoryV1::Conflict,
            MachineErrorCodeV1::OperationBusy,
            "Another store maintenance operation is in progress.",
        ),
        EngineErrorClass::PreparedStaleHead => simple_error(
            MachineErrorCategoryV1::Conflict,
            MachineErrorCodeV1::StalePlan,
            "The prepared plan no longer matches its namespace head.",
        ),
        EngineErrorClass::PreparedUnsafeTarget => simple_error(
            MachineErrorCategoryV1::Conflict,
            MachineErrorCodeV1::UnsafeTarget,
            "A managed target failed safety validation.",
        ),
        EngineErrorClass::PreparedInvalid => simple_error(
            MachineErrorCategoryV1::Conflict,
            MachineErrorCodeV1::InvalidDeployment,
            "The deployment request or its stored data is invalid.",
        ),
        EngineErrorClass::Io => simple_error(
            MachineErrorCategoryV1::Unavailable,
            MachineErrorCodeV1::DeploymentIo,
            "A deployment I/O operation failed.",
        ),
        EngineErrorClass::Commit(class) => machine_commit_class_error(class),
        EngineErrorClass::Other => simple_error(
            MachineErrorCategoryV1::Conflict,
            MachineErrorCodeV1::InvalidDeployment,
            "The deployment request cannot be executed in the current Engine state.",
        ),
    }
}

fn machine_commit_error(error: CommitError) -> MachineErrorV1 {
    machine_commit_class_error(classify_commit_error(&error))
}

fn machine_commit_class_error(class: CommitErrorClass) -> MachineErrorV1 {
    match class {
        CommitErrorClass::ReadOnlyStore => simple_error(
            MachineErrorCategoryV1::PermissionDenied,
            MachineErrorCodeV1::ReadOnlyStore,
            "The Engine was not granted write access to the store.",
        ),
        CommitErrorClass::Busy => simple_error(
            MachineErrorCategoryV1::Conflict,
            MachineErrorCodeV1::OperationBusy,
            "Another commit or recovery operation is in progress.",
        ),
        CommitErrorClass::MissingPlan => simple_error(
            MachineErrorCategoryV1::NotFound,
            MachineErrorCodeV1::PlanNotFound,
            "The requested prepared plan does not exist.",
        ),
        CommitErrorClass::MissingArtifact => simple_error(
            MachineErrorCategoryV1::NotFound,
            MachineErrorCodeV1::ArtifactNotFound,
            "A required prepared artifact does not exist.",
        ),
        CommitErrorClass::ApprovalMismatch => simple_error(
            MachineErrorCategoryV1::Conflict,
            MachineErrorCodeV1::ApprovalMismatch,
            "The approval does not match the prepared plan.",
        ),
        CommitErrorClass::StaleNamespaceHead => simple_error(
            MachineErrorCategoryV1::Conflict,
            MachineErrorCodeV1::StalePlan,
            "The prepared plan no longer matches its namespace head.",
        ),
        CommitErrorClass::RecoveryRequired => simple_error(
            MachineErrorCategoryV1::Conflict,
            MachineErrorCodeV1::RecoveryRequired,
            "An incomplete transaction must be recovered first.",
        ),
        CommitErrorClass::UnsafeTarget => simple_error(
            MachineErrorCategoryV1::Conflict,
            MachineErrorCodeV1::UnsafeTarget,
            "A managed target failed safety or freshness validation.",
        ),
        CommitErrorClass::CorruptStore => simple_error(
            MachineErrorCategoryV1::Conflict,
            MachineErrorCodeV1::CorruptStore,
            "The store or transaction journal is invalid.",
        ),
        CommitErrorClass::CorruptArtifact => simple_error(
            MachineErrorCategoryV1::Conflict,
            MachineErrorCodeV1::CorruptArtifact,
            "A prepared artifact failed digest verification.",
        ),
        CommitErrorClass::PlanInUse | CommitErrorClass::InvalidPlanState => simple_error(
            MachineErrorCategoryV1::Conflict,
            MachineErrorCodeV1::InvalidDeployment,
            "The deployment operation conflicts with retained or prepared state.",
        ),
        CommitErrorClass::Io => simple_error(
            MachineErrorCategoryV1::Unavailable,
            MachineErrorCodeV1::DeploymentIo,
            "A deployment I/O operation failed.",
        ),
        CommitErrorClass::Other => simple_error(
            MachineErrorCategoryV1::Internal,
            MachineErrorCodeV1::InternalEngineError,
            "An internal Engine error occurred.",
        ),
    }
}

fn simple_error(
    category: MachineErrorCategoryV1,
    code: MachineErrorCodeV1,
    message: &'static str,
) -> MachineErrorV1 {
    MachineErrorV1::new(
        category,
        code,
        MachineTextV1::new(message).expect("static machine error text is valid"),
        MachineErrorDetailsV1::None,
        Vec::new(),
    )
    .expect("static machine error shape is valid")
}
fn adapter_error() -> MachineErrorV1 {
    MachineErrorV1::new(
        MachineErrorCategoryV1::Internal,
        MachineErrorCodeV1::InternalEngineError,
        MachineTextV1::new("The machine adapter could not construct its Engine authority.")
            .expect("static machine error text is valid"),
        MachineErrorDetailsV1::None,
        Vec::new(),
    )
    .expect("static machine error shape is valid")
}

#[cfg(test)]
mod classifier_tests {
    use std::path::PathBuf;

    use super::{machine_commit_class_error, machine_commit_error, machine_engine_error};
    use crate::{CommitError, EngineError, OwnershipOverlapKindV1, PreparedStoreIssue};

    use super::CommitErrorClass;
    use malm_machine::{MachineErrorCategoryV1 as Category, MachineErrorCodeV1 as Code};
    use malm_types::{ArtifactId, DeploymentName, Digest, NamespaceName, PreparedId};

    fn digest() -> Digest {
        Digest::new(format!("sha256-{}", "1".repeat(64))).unwrap()
    }

    fn plan_id() -> PreparedId {
        PreparedId::new(format!("pp-{}", "2".repeat(64))).unwrap()
    }

    fn namespace() -> NamespaceName {
        NamespaceName::new("default".to_owned()).unwrap()
    }

    fn authority() -> DeploymentName {
        DeploymentName::new("home".to_owned()).unwrap()
    }

    fn io_error() -> std::io::Error {
        std::io::Error::other("io")
    }

    /// Pairs one representative of each [`CommitError`] variant with its
    /// pre-classifier machine category and code.
    fn commit_error_cases() -> Vec<(CommitError, Category, Code)> {
        vec![
            (
                CommitError::ReadOnlyStore,
                Category::PermissionDenied,
                Code::ReadOnlyStore,
            ),
            (CommitError::Busy, Category::Conflict, Code::OperationBusy),
            (
                CommitError::InvalidStore("reason".to_owned()),
                Category::Conflict,
                Code::CorruptStore,
            ),
            (
                CommitError::MissingPlan(plan_id()),
                Category::NotFound,
                Code::PlanNotFound,
            ),
            (
                CommitError::PlanInUse(plan_id()),
                Category::Conflict,
                Code::InvalidDeployment,
            ),
            (
                CommitError::InvalidPlan("reason".to_owned()),
                Category::Conflict,
                Code::InvalidDeployment,
            ),
            (
                CommitError::ApprovalPlanMismatch,
                Category::Conflict,
                Code::ApprovalMismatch,
            ),
            (
                CommitError::ApprovalFindingsMismatch,
                Category::Conflict,
                Code::ApprovalMismatch,
            ),
            (
                CommitError::StaleNamespaceHead {
                    namespace: namespace(),
                    expected: None,
                    actual: Some(digest()),
                },
                Category::Conflict,
                Code::StalePlan,
            ),
            (
                CommitError::TargetOwnershipConflict {
                    requesting_namespace: namespace(),
                    owning_namespace: namespace(),
                    requesting_authority: Box::new(authority()),
                    owning_authority: Box::new(authority()),
                    requested_path: ".config/a".to_owned(),
                    owned_path: ".config/a".to_owned(),
                    overlap: OwnershipOverlapKindV1::Exact,
                },
                Category::Conflict,
                Code::UnsafeTarget,
            ),
            (
                CommitError::UnownedTargetMutation {
                    namespace: namespace(),
                    authority: authority(),
                    relative_path: ".config/a".to_owned(),
                },
                Category::Conflict,
                Code::UnsafeTarget,
            ),
            (
                CommitError::MissingArtifact(digest()),
                Category::NotFound,
                Code::ArtifactNotFound,
            ),
            (
                CommitError::CorruptArtifact {
                    expected: digest(),
                    actual: digest(),
                },
                Category::Conflict,
                Code::CorruptArtifact,
            ),
            (
                CommitError::UnknownTargetAuthority(authority()),
                Category::Conflict,
                Code::UnsafeTarget,
            ),
            (
                CommitError::UnsafeTarget("reason".to_owned()),
                Category::Conflict,
                Code::UnsafeTarget,
            ),
            (
                CommitError::StaleTarget("reason".to_owned()),
                Category::Conflict,
                Code::UnsafeTarget,
            ),
            (
                CommitError::StaleInspection,
                Category::Conflict,
                Code::UnsafeTarget,
            ),
            (
                CommitError::RollbackFailed("reason".to_owned()),
                Category::Conflict,
                Code::InvalidDeployment,
            ),
            (
                CommitError::RecoveryRequired,
                Category::Conflict,
                Code::RecoveryRequired,
            ),
            (
                CommitError::InvalidJournal("reason".to_owned()),
                Category::Conflict,
                Code::CorruptStore,
            ),
            (
                CommitError::Io {
                    operation: "open",
                    path: PathBuf::from("/store"),
                    source: io_error(),
                },
                Category::Unavailable,
                Code::DeploymentIo,
            ),
        ]
    }

    /// Covers each classified [`PreparedStoreIssue`] group and the remaining
    /// top-level [`EngineError`] groups.
    fn engine_error_cases() -> Vec<(EngineError, Category, Code)> {
        let prepared = |reason| EngineError::PreparedStore {
            path: PathBuf::from("/store"),
            reason,
        };
        vec![
            (
                EngineError::ReadOnlyStore,
                Category::PermissionDenied,
                Code::ReadOnlyStore,
            ),
            (
                prepared(PreparedStoreIssue::MissingPlan),
                Category::NotFound,
                Code::PlanNotFound,
            ),
            (
                prepared(PreparedStoreIssue::MissingBlob),
                Category::NotFound,
                Code::ArtifactNotFound,
            ),
            (
                prepared(PreparedStoreIssue::UnknownArtifact(
                    ArtifactId::new("artifact".to_owned()).unwrap(),
                )),
                Category::NotFound,
                Code::ArtifactNotFound,
            ),
            (
                prepared(PreparedStoreIssue::PublicationBusy),
                Category::Conflict,
                Code::OperationBusy,
            ),
            (
                prepared(PreparedStoreIssue::StaleNamespaceHead {
                    namespace: namespace(),
                    expected: None,
                    actual: Some(digest()),
                }),
                Category::Conflict,
                Code::StalePlan,
            ),
            (
                prepared(PreparedStoreIssue::UnsafeTarget {
                    detail: "reason".to_owned(),
                }),
                Category::Conflict,
                Code::UnsafeTarget,
            ),
            (
                prepared(PreparedStoreIssue::DirectoryOccupancyConflicts {
                    paths: vec![PathBuf::from("/private/target")],
                    omitted_count: 0,
                }),
                Category::Conflict,
                Code::UnsafeTarget,
            ),
            (
                prepared(PreparedStoreIssue::UnknownTargetAuthority(authority())),
                Category::Conflict,
                Code::UnsafeTarget,
            ),
            (
                prepared(PreparedStoreIssue::UnownedTargetMutation {
                    namespace: namespace(),
                    authority: authority(),
                    relative_path: ".config/a".to_owned(),
                }),
                Category::Conflict,
                Code::UnsafeTarget,
            ),
            (
                prepared(PreparedStoreIssue::ObservationChanged),
                Category::Conflict,
                Code::InvalidDeployment,
            ),
            (
                EngineError::Commit {
                    source: CommitError::PlanInUse(plan_id()),
                },
                Category::Conflict,
                Code::InvalidDeployment,
            ),
            (
                EngineError::Commit {
                    source: CommitError::RecoveryRequired,
                },
                Category::Conflict,
                Code::RecoveryRequired,
            ),
            (
                EngineError::Io {
                    operation: "open",
                    path: PathBuf::from("/store"),
                    source: io_error(),
                },
                Category::Unavailable,
                Code::DeploymentIo,
            ),
        ]
    }

    #[test]
    fn every_commit_error_variant_keeps_its_pre_classifier_machine_error() {
        for (error, category, code) in commit_error_cases() {
            let detail = format!("{error:?}");
            let machine = machine_commit_error(error);
            assert_eq!(machine.category(), category, "{detail}");
            assert_eq!(machine.code(), code, "{detail}");
        }
    }

    #[test]
    fn every_engine_error_group_keeps_its_pre_classifier_machine_error() {
        for (error, category, code) in engine_error_cases() {
            let detail = format!("{error:?}");
            let machine = machine_engine_error(error);
            assert_eq!(machine.category(), category, "{detail}");
            assert_eq!(machine.code(), code, "{detail}");
        }
    }

    #[test]
    fn other_commit_error_class_keeps_machine_internal_engine_error() {
        // Machine/v1 treats catch-all commit errors as internal failures, unlike
        // the CLI compatibility mapping to invalid-deployment and Conflict.
        let machine = machine_commit_class_error(CommitErrorClass::Other);
        assert_eq!(machine.category(), Category::Internal);
        assert_eq!(machine.code(), Code::InternalEngineError);
    }
}
