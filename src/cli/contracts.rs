//! Defines the closed effect and Engine-operation contracts for production adapters.

use malm_machine::MachineOperationV1;

use crate::{EngineOperation, StoreAccess};

use super::{Cmd, LockCmd, StoreCmd};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum CommandEffect {
    ReadOnlyInspection,
    HostWriteExport,
    PrepareOnly,
    PrepareWithAcquisition,
    LockWithAcquisition,
    MutationWrite,
}

impl CommandEffect {
    pub(super) const fn as_str(self) -> &'static str {
        match self {
            Self::ReadOnlyInspection => "read-only-inspection",
            Self::HostWriteExport => "host-write-export",
            Self::PrepareOnly => "prepare-only",
            Self::PrepareWithAcquisition => "prepare-with-acquisition",
            Self::LockWithAcquisition => "lock-with-acquisition",
            Self::MutationWrite => "mutation-write",
        }
    }

    pub(super) const fn store_access(self) -> Option<StoreAccess> {
        match self {
            Self::ReadOnlyInspection | Self::HostWriteExport => Some(StoreAccess::ReadOnly),
            Self::PrepareOnly
            | Self::PrepareWithAcquisition
            | Self::LockWithAcquisition
            | Self::MutationWrite => Some(StoreAccess::ReadWrite),
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub(super) struct OperationContract {
    engine_operations: &'static [EngineOperation],
    effect: CommandEffect,
}

impl OperationContract {
    const fn new(engine_operations: &'static [EngineOperation], effect: CommandEffect) -> Self {
        Self {
            engine_operations,
            effect,
        }
    }

    pub(super) const fn effect(self) -> CommandEffect {
        self.effect
    }

    pub(super) fn assert_engine_operation(self, operation: EngineOperation) {
        assert!(
            self.engine_operations.contains(&operation),
            "dispatch arm disagrees with its closed Engine-operation contract"
        );
    }
}

pub(super) const fn cli_contract(command: &Cmd) -> OperationContract {
    use CommandEffect::{
        HostWriteExport, MutationWrite, PrepareOnly, PrepareWithAcquisition, ReadOnlyInspection,
    };
    use EngineOperation as Engine;

    match command {
        Cmd::ComponentHostProfile => OperationContract::new(&[], ReadOnlyInspection),
        Cmd::Store { cmd } => store_contract(cmd),
        Cmd::Lock { cmd } => lock_contract(cmd),
        Cmd::Prepare { .. } => {
            OperationContract::new(&[Engine::PrepareStaticDeploymentV1], PrepareWithAcquisition)
        }
        Cmd::Apply { .. } => OperationContract::new(
            &[Engine::PrepareStaticDeploymentV1, Engine::CommitV1],
            MutationWrite,
        ),
        Cmd::Check { .. } | Cmd::Vars { .. } => OperationContract::new(&[], ReadOnlyInspection),
        Cmd::Render { .. } => OperationContract::new(&[], HostWriteExport),
        Cmd::Track { .. } => {
            OperationContract::new(&[Engine::PrepareTrackedRootV1], PrepareWithAcquisition)
        }
        Cmd::Update { .. } => {
            OperationContract::new(&[Engine::UpdateTrackedRootV1], PrepareWithAcquisition)
        }
        Cmd::Switch { .. } => {
            OperationContract::new(&[Engine::PrepareProfileSwitchV1], PrepareOnly)
        }
        Cmd::Plan { .. } => OperationContract::new(
            &[Engine::InspectPlanV1, Engine::InspectPlanIndexV1],
            ReadOnlyInspection,
        ),
        Cmd::PlanList => OperationContract::new(
            &[Engine::InspectPlanIndexV1, Engine::InspectPlanV1],
            ReadOnlyInspection,
        ),
        Cmd::ArtifactList { .. } => OperationContract::new(
            &[Engine::InspectPlanV1, Engine::InspectPlanIndexV1],
            ReadOnlyInspection,
        ),
        Cmd::Artifact { .. } => OperationContract::new(
            &[Engine::LoadArtifactV1, Engine::InspectPlanIndexV1],
            HostWriteExport,
        ),
        Cmd::Commit { .. } => OperationContract::new(
            &[
                Engine::CommitV1,
                Engine::InspectPlanV1,
                Engine::InspectPlanIndexV1,
            ],
            MutationWrite,
        ),
        Cmd::Checkout { .. } => OperationContract::new(
            &[
                Engine::PrepareCheckoutV1,
                Engine::InspectGenerationInventoryV1,
            ],
            PrepareOnly,
        ),
        Cmd::Recover { .. } => OperationContract::new(&[Engine::RecoverV1], MutationWrite),
        Cmd::Prune { .. } => OperationContract::new(
            &[Engine::PruneV1, Engine::InspectPlanIndexV1],
            MutationWrite,
        ),
        Cmd::Disable { .. } => OperationContract::new(&[Engine::PrepareDisableV1], PrepareOnly),
        Cmd::Enable { .. } => OperationContract::new(&[Engine::PrepareEnableV1], PrepareOnly),
        Cmd::RemoveNamespace { .. } => {
            OperationContract::new(&[Engine::PrepareNamespaceRemovalV1], PrepareOnly)
        }
        Cmd::SetHistoryRetention { .. } => {
            OperationContract::new(&[Engine::PrepareRetentionAuthorityV1], PrepareOnly)
        }
        Cmd::Pin { .. } | Cmd::Unpin { .. } => OperationContract::new(
            &[
                Engine::PrepareRetentionAuthorityV1,
                Engine::InspectPlanIndexV1,
                Engine::InspectGenerationInventoryV1,
                Engine::InspectObjectInventoryV1,
            ],
            PrepareOnly,
        ),
        Cmd::AddRestorePoint { .. } | Cmd::DropRestorePoint { .. } => OperationContract::new(
            &[
                Engine::PrepareRetentionAuthorityV1,
                Engine::InspectGenerationInventoryV1,
            ],
            PrepareOnly,
        ),
        Cmd::Catalog => OperationContract::new(&[Engine::InspectCatalogV1], ReadOnlyInspection),
        Cmd::Namespace { .. } => {
            OperationContract::new(&[Engine::InspectNamespaceV1], ReadOnlyInspection)
        }
        Cmd::History { .. } => {
            OperationContract::new(&[Engine::InspectNamespaceHistoryV1], ReadOnlyInspection)
        }
        Cmd::Generation { .. } => OperationContract::new(
            &[
                Engine::InspectGenerationV1,
                Engine::InspectGenerationInventoryV1,
            ],
            ReadOnlyInspection,
        ),
        Cmd::DesiredSnapshot { .. } => OperationContract::new(
            &[
                Engine::InspectDesiredSnapshotV1,
                Engine::InspectGenerationInventoryV1,
            ],
            ReadOnlyInspection,
        ),
        Cmd::CanonicalTree { .. } => OperationContract::new(
            &[
                Engine::InspectCanonicalTreeV1,
                Engine::InspectObjectInventoryV1,
            ],
            ReadOnlyInspection,
        ),
        Cmd::ArtifactMetadata { .. } => OperationContract::new(
            &[
                Engine::InspectArtifactMetadataV1,
                Engine::InspectPlanIndexV1,
            ],
            ReadOnlyInspection,
        ),
        Cmd::CapturedInputs { .. } => OperationContract::new(
            &[Engine::InspectCapturedInputsV1, Engine::InspectPlanIndexV1],
            ReadOnlyInspection,
        ),
        Cmd::TransformProvenance { .. } => OperationContract::new(
            &[
                Engine::InspectTransformProvenanceV1,
                Engine::InspectPlanIndexV1,
            ],
            ReadOnlyInspection,
        ),
        Cmd::Retention { .. } => OperationContract::new(
            &[
                Engine::InspectRetentionV1,
                Engine::InspectGenerationInventoryV1,
            ],
            ReadOnlyInspection,
        ),
        Cmd::Tracking { .. } => OperationContract::new(
            &[
                Engine::InspectTrackingV1,
                Engine::InspectGenerationInventoryV1,
            ],
            ReadOnlyInspection,
        ),
        Cmd::Status { .. } => {
            OperationContract::new(&[Engine::InspectNamespaceStatusV1], ReadOnlyInspection)
        }
        Cmd::Fsck { .. } => OperationContract::new(&[Engine::FsckV1], ReadOnlyInspection),
    }
}

pub(super) const fn lock_contract(command: &LockCmd) -> OperationContract {
    use CommandEffect::LockWithAcquisition;
    use EngineOperation as Engine;

    match command {
        LockCmd::Create(_) => OperationContract::new(&[Engine::CreateLockV1], LockWithAcquisition),
        LockCmd::Update(_) => OperationContract::new(&[Engine::UpdateLockV1], LockWithAcquisition),
    }
}

pub(super) const fn store_contract(command: &StoreCmd) -> OperationContract {
    match command {
        StoreCmd::Status => OperationContract::new(
            &[EngineOperation::StoreStatus],
            CommandEffect::ReadOnlyInspection,
        ),
        StoreCmd::Initialize => OperationContract::new(
            &[EngineOperation::InitializeStore],
            CommandEffect::MutationWrite,
        ),
    }
}

pub(super) const fn machine_contract(operation: MachineOperationV1) -> OperationContract {
    use CommandEffect::{MutationWrite, PrepareOnly, ReadOnlyInspection};
    use EngineOperation as Engine;
    use MachineOperationV1 as Machine;

    match operation {
        Machine::StoreStatus => OperationContract::new(&[Engine::StoreStatus], ReadOnlyInspection),
        Machine::InitializeStore => {
            OperationContract::new(&[Engine::InitializeStore], MutationWrite)
        }
        Machine::Prepare => OperationContract::new(&[Engine::PrepareV1], PrepareOnly),
        Machine::Plan => OperationContract::new(&[Engine::InspectPlanV1], ReadOnlyInspection),
        Machine::Artifact => OperationContract::new(&[Engine::LoadArtifactV1], ReadOnlyInspection),
        Machine::Commit => OperationContract::new(&[Engine::CommitV1], MutationWrite),
        Machine::State => OperationContract::new(&[Engine::InspectStateV1], ReadOnlyInspection),
        Machine::Recover => OperationContract::new(&[Engine::RecoverV1], MutationWrite),
        Machine::Prune => OperationContract::new(&[Engine::PruneV1], MutationWrite),
        Machine::Checkout => OperationContract::new(&[Engine::PrepareCheckoutV1], PrepareOnly),
        Machine::Disable => OperationContract::new(&[Engine::PrepareDisableV1], PrepareOnly),
        Machine::Enable => OperationContract::new(&[Engine::PrepareEnableV1], PrepareOnly),
        Machine::RemoveNamespace => {
            OperationContract::new(&[Engine::PrepareNamespaceRemovalV1], PrepareOnly)
        }
        Machine::SetHistoryRetention
        | Machine::Pin
        | Machine::Unpin
        | Machine::AddRestorePoint
        | Machine::DropRestorePoint => {
            OperationContract::new(&[Engine::PrepareRetentionAuthorityV1], PrepareOnly)
        }
        Machine::Catalog => OperationContract::new(&[Engine::InspectCatalogV1], ReadOnlyInspection),
        Machine::Namespace => {
            OperationContract::new(&[Engine::InspectNamespaceV1], ReadOnlyInspection)
        }
        Machine::History => {
            OperationContract::new(&[Engine::InspectNamespaceHistoryV1], ReadOnlyInspection)
        }
        Machine::Generation => {
            OperationContract::new(&[Engine::InspectGenerationV1], ReadOnlyInspection)
        }
        Machine::DesiredSnapshot => {
            OperationContract::new(&[Engine::InspectDesiredSnapshotV1], ReadOnlyInspection)
        }
        Machine::CanonicalTree => {
            OperationContract::new(&[Engine::InspectCanonicalTreeV1], ReadOnlyInspection)
        }
        Machine::ArtifactMetadata => {
            OperationContract::new(&[Engine::InspectArtifactMetadataV1], ReadOnlyInspection)
        }
        Machine::CapturedInputs => {
            OperationContract::new(&[Engine::InspectCapturedInputsV1], ReadOnlyInspection)
        }
        Machine::TransformProvenance => {
            OperationContract::new(&[Engine::InspectTransformProvenanceV1], ReadOnlyInspection)
        }
        Machine::Retention => {
            OperationContract::new(&[Engine::InspectRetentionV1], ReadOnlyInspection)
        }
        Machine::Tracking => {
            OperationContract::new(&[Engine::InspectTrackingV1], ReadOnlyInspection)
        }
        Machine::Status => {
            OperationContract::new(&[Engine::InspectNamespaceStatusV1], ReadOnlyInspection)
        }
        Machine::Fsck => OperationContract::new(&[Engine::FsckV1], ReadOnlyInspection),
    }
}
