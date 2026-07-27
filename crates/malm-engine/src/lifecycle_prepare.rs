use std::collections::{BTreeMap, BTreeSet};

use malm_store::{
    DesiredSnapshotV1, HistoryRetentionPolicyV1, LifecycleStateV1, NamespaceRemovalHistoryV1,
    PreparedInputKindV1, PreparedTransitionV1, RequiredTargetMutationV1, RestorePointV1,
    RetentionAuthorityV1, StateGenerationV1, StateTargetStateV1, TrackedRootV1,
    reconcile_desired_snapshot_v1, required_target_mutations_v1,
};
use malm_types::{
    ArtifactId, Digest, HistoryRetentionRequestV1, NamespaceName, NamespaceRemovalRequestV1,
    PrepareArtifactV1, PrepareInputKindV1, PrepareInputV1, PrepareOperationV1,
    PreparePolicyFindingV1, PrepareRequestPartsV1, PrepareRequestV1, PreparedDeploymentV1,
    RestorePointRequestV1, RetentionObjectV1, RetentionPinRequestV1,
};

use crate::{Engine, EngineError, prepared_store};

pub(super) fn disable(
    engine: &Engine,
    namespace: &NamespaceName,
) -> Result<PreparedDeploymentV1, EngineError> {
    let (head, current) = selected_generation(engine, namespace, "disable")?;
    if current.lifecycle_state() != LifecycleStateV1::Enabled {
        return Err(prepared_store::invalid_record(
            engine,
            format!("namespace {namespace} is already disabled"),
        ));
    }
    verify_retained_blobs(engine, current.desired_snapshot())?;
    let restore_point = RestorePointV1::new(
        current.namespace().clone(),
        head.clone(),
        current.lifecycle_state(),
        current.desired_snapshot_digest().clone(),
        current.tracked_root().cloned(),
    );
    let retention = current
        .retention_authority()
        .clone()
        .with_restore_point(restore_point.clone())
        .map_err(|error| prepared_store::invalid_record(engine, error))?;
    prepare_selected_state(
        engine,
        &head,
        &current,
        SelectedState {
            transition: PreparedTransitionV1::Disable,
            next_lifecycle: LifecycleStateV1::Disabled,
            desired: &DesiredSnapshotV1::empty(),
            restore_point: Some(&restore_point),
            retention: &retention,
            tracked_root: None,
        },
        Some(&current),
        TransitionDescription::Disable,
        false,
    )
}

pub(super) fn enable(
    engine: &Engine,
    namespace: &NamespaceName,
) -> Result<PreparedDeploymentV1, EngineError> {
    let (head, current) = selected_generation(engine, namespace, "enable")?;
    if current.lifecycle_state() != LifecycleStateV1::Disabled {
        return Err(prepared_store::invalid_record(
            engine,
            format!("namespace {namespace} is already enabled"),
        ));
    }
    let restore_point = current.restore_point().cloned().ok_or_else(|| {
        prepared_store::invalid_record(
            engine,
            format!("disabled namespace {namespace} has no explicit restore point"),
        )
    })?;
    let restored = load_restore_generation(engine, &restore_point)?;
    verify_retained_blobs(engine, restored.desired_snapshot())?;
    prepare_selected_state(
        engine,
        &head,
        &current,
        SelectedState {
            transition: PreparedTransitionV1::Enable {
                restore_point: Box::new(restore_point.clone()),
            },
            next_lifecycle: LifecycleStateV1::Enabled,
            desired: restored.desired_snapshot(),
            restore_point: None,
            retention: current.retention_authority(),
            tracked_root: restored.tracked_root(),
        },
        Some(&restored),
        TransitionDescription::Enable,
        false,
    )
}

pub(super) fn checkout(
    engine: &Engine,
    current_head: &Digest,
    current: &StateGenerationV1,
    desired_head: &Digest,
    desired: &StateGenerationV1,
) -> Result<PreparedDeploymentV1, EngineError> {
    let desired_snapshot = if desired.lifecycle_state() == LifecycleStateV1::Disabled {
        DesiredSnapshotV1::empty()
    } else {
        reconcile_desired_snapshot_v1(
            Some(current.desired_snapshot()),
            desired.desired_snapshot().targets().to_vec(),
        )
        .map_err(|error| prepared_store::invalid_record(engine, error))?
    };
    verify_retained_blobs(engine, &desired_snapshot)?;
    let retention = match desired.restore_point() {
        Some(point) => current
            .retention_authority()
            .clone()
            .with_restore_point(point.clone())
            .map_err(|error| prepared_store::invalid_record(engine, error))?,
        None => current.retention_authority().clone(),
    };
    prepare_selected_state(
        engine,
        current_head,
        current,
        SelectedState {
            transition: PreparedTransitionV1::Checkout {
                source_generation: desired_head.clone(),
            },
            next_lifecycle: desired.lifecycle_state(),
            desired: &desired_snapshot,
            restore_point: desired.restore_point(),
            retention: &retention,
            tracked_root: desired.tracked_root(),
        },
        Some(desired),
        TransitionDescription::Checkout(desired_head),
        true,
    )
}

pub(super) fn remove_namespace(
    engine: &Engine,
    request: &NamespaceRemovalRequestV1,
) -> Result<PreparedDeploymentV1, EngineError> {
    let (head, current) = selected_generation(engine, request.namespace(), "namespace removal")?;
    let history = match request.history() {
        malm_types::NamespaceRemovalHistoryV1::Drop => NamespaceRemovalHistoryV1::Drop,
    };
    prepare_selected_state(
        engine,
        &head,
        &current,
        SelectedState {
            transition: PreparedTransitionV1::NamespaceRemoval { history },
            next_lifecycle: LifecycleStateV1::Disabled,
            desired: &DesiredSnapshotV1::empty(),
            restore_point: None,
            retention: current.retention_authority(),
            tracked_root: None,
        },
        None,
        TransitionDescription::NamespaceRemoval,
        false,
    )
}

pub(super) fn set_history_policy(
    engine: &Engine,
    request: &HistoryRetentionRequestV1,
) -> Result<PreparedDeploymentV1, EngineError> {
    let (head, current) = selected_generation(engine, request.namespace(), "history policy")?;
    let history = HistoryRetentionPolicyV1::new(request.generations())
        .map_err(|error| prepared_store::invalid_record(engine, error))?;
    let retention = current
        .retention_authority()
        .clone()
        .with_history(history)
        .map_err(|error| prepared_store::invalid_record(engine, error))?;
    prepare_authority_update(engine, &head, &current, &retention, "history-policy")
}

pub(super) fn pin(
    engine: &Engine,
    request: &RetentionPinRequestV1,
) -> Result<PreparedDeploymentV1, EngineError> {
    let (head, current) = selected_generation(engine, request.namespace(), "pin")?;
    verify_pin(engine, request.object())?;
    let retention = current
        .retention_authority()
        .clone()
        .with_pin(request.object().clone())
        .map_err(|error| prepared_store::invalid_record(engine, error))?;
    prepare_authority_update(engine, &head, &current, &retention, "pin")
}

pub(super) fn unpin(
    engine: &Engine,
    request: &RetentionPinRequestV1,
) -> Result<PreparedDeploymentV1, EngineError> {
    let (head, current) = selected_generation(engine, request.namespace(), "unpin")?;
    let retention = current
        .retention_authority()
        .clone()
        .without_pin(request.object())
        .map_err(|error| prepared_store::invalid_record(engine, error))?;
    prepare_authority_update(engine, &head, &current, &retention, "unpin")
}

pub(super) fn add_restore_point(
    engine: &Engine,
    request: &RestorePointRequestV1,
) -> Result<PreparedDeploymentV1, EngineError> {
    let (head, current) = selected_generation(engine, request.namespace(), "restore point")?;
    let committer = engine
        .committer_v1()
        .map_err(|error| prepared_store::commit_error(engine, error))?;
    let source = committer
        .inspect_generation_v1(request.generation())
        .map_err(|error| prepared_store::commit_error(engine, error))?;
    if source.namespace() != request.namespace() {
        return Err(prepared_store::invalid_record(
            engine,
            "restore point generation belongs to another namespace".to_owned(),
        ));
    }
    verify_retained_blobs(engine, source.desired_snapshot())?;
    let point = RestorePointV1::new(
        source.namespace().clone(),
        request.generation().clone(),
        source.lifecycle_state(),
        source.desired_snapshot_digest().clone(),
        source.tracked_root().cloned(),
    );
    let retention = current
        .retention_authority()
        .clone()
        .with_restore_point(point)
        .map_err(|error| prepared_store::invalid_record(engine, error))?;
    prepare_authority_update(engine, &head, &current, &retention, "restore-point-add")
}

pub(super) fn drop_restore_point(
    engine: &Engine,
    request: &RestorePointRequestV1,
) -> Result<PreparedDeploymentV1, EngineError> {
    let (head, current) = selected_generation(engine, request.namespace(), "restore point")?;
    if current
        .restore_point()
        .is_some_and(|point| point.generation() == request.generation())
    {
        return Err(prepared_store::invalid_record(
            engine,
            "cannot drop the restore point selected by a disabled generation".to_owned(),
        ));
    }
    let retention = current
        .retention_authority()
        .clone()
        .without_restore_point(request.generation())
        .map_err(|error| prepared_store::invalid_record(engine, error))?;
    prepare_authority_update(engine, &head, &current, &retention, "restore-point-drop")
}

fn selected_generation(
    engine: &Engine,
    namespace: &NamespaceName,
    operation: &str,
) -> Result<(Digest, StateGenerationV1), EngineError> {
    let committer = engine
        .committer_v1()
        .map_err(|error| prepared_store::commit_error(engine, error))?;
    let head = committer
        .inspect_state_v1(namespace)
        .map_err(|error| prepared_store::commit_error(engine, error))?
        .head()
        .cloned()
        .ok_or_else(|| {
            prepared_store::invalid_record(
                engine,
                format!("{operation} requires a head for namespace {namespace}"),
            )
        })?;
    let generation = committer
        .inspect_generation_v1(&head)
        .map_err(|error| prepared_store::commit_error(engine, error))?;
    if generation.namespace() != namespace {
        return Err(prepared_store::invalid_record(
            engine,
            format!("{operation} selected a generation for another namespace"),
        ));
    }
    Ok((head, generation))
}

enum TransitionDescription<'a> {
    Disable,
    Enable,
    Checkout(&'a Digest),
    NamespaceRemoval,
    RetentionAuthority(&'a str),
}

impl TransitionDescription<'_> {
    const fn input_name(&self) -> &'static str {
        match self {
            Self::Disable => "lifecycle-disable-head",
            Self::Enable => "lifecycle-enable-head",
            Self::Checkout(_) => "checkout-generation",
            Self::NamespaceRemoval => "namespace-removal-head",
            Self::RetentionAuthority(_) => "retention-authority-head",
        }
    }

    const fn finding_code(&self) -> &str {
        match self {
            Self::Disable => "disable",
            Self::Enable => "enable",
            Self::Checkout(_) => "checkout",
            Self::NamespaceRemoval => "namespace-removal",
            Self::RetentionAuthority(operation) => operation,
        }
    }

    fn input_digest(&self, current_head: &Digest) -> Digest {
        match self {
            Self::Disable | Self::Enable | Self::NamespaceRemoval | Self::RetentionAuthority(_) => {
                current_head.clone()
            }
            Self::Checkout(target) => (*target).clone(),
        }
    }

    fn finding_message(&self, namespace: &NamespaceName) -> String {
        match self {
            Self::Disable => format!(
                "disable namespace {namespace} with an empty desired snapshot and exact restore point"
            ),
            Self::Enable => format!("enable namespace {namespace} from its exact restore point"),
            Self::Checkout(target) => format!("restore retained generation {target}"),
            Self::NamespaceRemoval => format!(
                "remove namespace {namespace}, release every live target, and drop its unpinned history authority"
            ),
            Self::RetentionAuthority(operation) => {
                format!("update namespace {namespace} retention authority ({operation})")
            }
        }
    }
}

/// Complete persisted state selected by one lifecycle transition.
struct SelectedState<'a> {
    transition: PreparedTransitionV1,
    next_lifecycle: LifecycleStateV1,
    desired: &'a DesiredSnapshotV1,
    restore_point: Option<&'a RestorePointV1>,
    retention: &'a RetentionAuthorityV1,
    tracked_root: Option<&'a TrackedRootV1>,
}

fn prepare_selected_state(
    engine: &Engine,
    current_head: &Digest,
    current: &StateGenerationV1,
    selected: SelectedState<'_>,
    graph_authority: Option<&StateGenerationV1>,
    description: TransitionDescription<'_>,
    assert_absent_targets: bool,
) -> Result<PreparedDeploymentV1, EngineError> {
    let SelectedState {
        transition,
        next_lifecycle,
        desired,
        restore_point,
        retention,
        tracked_root,
    } = selected;
    let required = required_target_mutations_v1(
        Some((current.lifecycle_state(), current.desired_snapshot())),
        next_lifecycle,
        desired,
    )
    .map_err(|error| prepared_store::invalid_record(engine, error))?;
    let mut artifact_specs = BTreeMap::<Digest, (u64, ArtifactId)>::new();
    let mut operations = Vec::with_capacity(required.len());
    for mutation in required {
        let operation = match mutation {
            RequiredTargetMutationV1::EnsureDirectory {
                authority,
                relative_path,
                mode,
            } => {
                if effective_present(current, &authority, &relative_path) {
                    PrepareOperationV1::replace_directory(authority, relative_path, mode)
                } else {
                    PrepareOperationV1::ensure_directory(authority, relative_path, mode)
                }
            }
            RequiredTargetMutationV1::PlaceFile {
                authority,
                relative_path,
                digest,
                byte_len,
                mode,
            } => {
                let artifact_id = retained_artifact_id(engine, &digest)?;
                if let Some((previous_len, _)) = artifact_specs.get(&digest) {
                    if *previous_len != byte_len {
                        return Err(prepared_store::invalid_record(
                            engine,
                            "retained digest has conflicting byte lengths".to_owned(),
                        ));
                    }
                } else {
                    artifact_specs.insert(digest, (byte_len, artifact_id.clone()));
                }
                if effective_present(current, &authority, &relative_path) {
                    PrepareOperationV1::replace_file(authority, relative_path, artifact_id, mode)
                } else {
                    PrepareOperationV1::place_file(authority, relative_path, artifact_id, mode)
                }
            }
            RequiredTargetMutationV1::PlaceSymlink {
                authority,
                relative_path,
                object,
            } => {
                if effective_present(current, &authority, &relative_path) {
                    PrepareOperationV1::replace_symlink(authority, relative_path, object)
                } else {
                    PrepareOperationV1::place_symlink(authority, relative_path, object)
                }
            }
            RequiredTargetMutationV1::PlaceTree {
                authority,
                relative_path,
                tree,
                archive_provenance,
            } => {
                let provenance = archive_provenance.map(|provenance| {
                    malm_types::ArchiveProvenanceV1::new(
                        provenance.payload().clone(),
                        provenance.decoder(),
                    )
                    .expect("validated archive provenance projects into the semantic DTO")
                });
                match (
                    effective_present(current, &authority, &relative_path),
                    provenance,
                ) {
                    (true, Some(provenance)) => PrepareOperationV1::replace_archive_tree(
                        authority,
                        relative_path,
                        tree,
                        provenance,
                    ),
                    (true, None) => {
                        PrepareOperationV1::replace_tree(authority, relative_path, tree)
                    }
                    (false, Some(provenance)) => PrepareOperationV1::place_archive_tree(
                        authority,
                        relative_path,
                        tree,
                        provenance,
                    ),
                    (false, None) => PrepareOperationV1::place_tree(authority, relative_path, tree),
                }
            }
            RequiredTargetMutationV1::RemoveLeaf {
                authority,
                relative_path,
            } => PrepareOperationV1::remove_leaf(authority, relative_path),
            RequiredTargetMutationV1::AssertExact {
                authority,
                relative_path,
                state,
            } => PrepareOperationV1::assert_exact(
                authority,
                relative_path,
                prepared_store::target_state_view(engine, &state)?,
            ),
        }
        .map_err(|error| prepared_store::invalid_record(engine, error))?;
        operations.push(operation);
    }

    if assert_absent_targets {
        let destinations = operations
            .iter()
            .map(|operation| {
                (
                    operation.authority().clone(),
                    operation.relative_path().to_owned(),
                )
            })
            .collect::<BTreeSet<_>>();
        for target in desired
            .targets()
            .iter()
            .filter(|target| !target.is_present())
        {
            let key = (
                target.authority().clone(),
                target.relative_path().to_owned(),
            );
            if destinations.contains(&key)
                || effective_present(current, target.authority(), target.relative_path())
            {
                continue;
            }
            operations.push(
                PrepareOperationV1::assert_absent(key.0, key.1)
                    .map_err(|error| prepared_store::invalid_record(engine, error))?,
            );
        }
    }

    let unique_bytes = artifact_specs
        .values()
        .try_fold(0_u64, |total, (length, _)| {
            total.checked_add(*length).ok_or_else(|| {
                prepared_store::invalid_record(
                    engine,
                    "retained artifact bytes overflow".to_owned(),
                )
            })
        })?;
    if unique_bytes > malm_store::MAX_PREPARED_UNIQUE_ARTIFACT_BYTES {
        return Err(prepared_store::invalid_record(
            engine,
            "retained artifacts exceed the prepared-plan byte limit".to_owned(),
        ));
    }
    let mut artifacts = Vec::with_capacity(artifact_specs.len());
    for (digest, (expected_len, artifact_id)) in artifact_specs {
        let bytes = prepared_store::load_blob_by_digest(engine, &digest)?;
        if u64::try_from(bytes.len()).unwrap_or(u64::MAX) != expected_len {
            return Err(prepared_store::invalid_record(
                engine,
                format!("retained blob {digest} differs from desired target metadata"),
            ));
        }
        artifacts.push(
            PrepareArtifactV1::new(artifact_id, bytes, "application/octet-stream")
                .map_err(|error| prepared_store::invalid_record(engine, error))?,
        );
    }

    let input = PrepareInputV1::new(
        PrepareInputKindV1::Other,
        description.input_name(),
        description.input_digest(current_head),
    )
    .map_err(|error| prepared_store::invalid_record(engine, error))?;
    let mut inputs = vec![input];
    let finding = PreparePolicyFindingV1::new(
        description.finding_code(),
        description.finding_message(current.namespace()),
        true,
    )
    .map_err(|error| prepared_store::invalid_record(engine, error))?;
    let retained = graph_authority
        .map(|generation| prepared_store::load_retained_graph_record(engine, generation))
        .transpose()?
        .flatten();
    let graph_digest = if let Some(retained) = retained {
        for input in retained.inputs().iter().filter(|input| {
            matches!(
                input.kind(),
                PreparedInputKindV1::Source
                    | PreparedInputKindV1::Lock
                    | PreparedInputKindV1::Component
            ) || (input.kind() == PreparedInputKindV1::Other
                && (input
                    .name()
                    .starts_with(crate::config_prepare::STATIC_CONFIG_ENTRY_INPUT_PREFIX)
                    || input
                        .name()
                        .starts_with(crate::config_prepare::STATIC_TARGET_AUTHORITY_INPUT_PREFIX)
                    || input.name() == crate::config_prepare::LOCKED_COMPONENT_PROFILES_INPUT
                    || input
                        .name()
                        .starts_with(crate::config_prepare::LOCKED_COMPONENT_PROFILE_INPUT_PREFIX)))
        }) {
            let kind = match input.kind() {
                PreparedInputKindV1::Source => PrepareInputKindV1::Source,
                PreparedInputKindV1::Lock => PrepareInputKindV1::Lock,
                PreparedInputKindV1::Component => PrepareInputKindV1::Component,
                PreparedInputKindV1::Other => PrepareInputKindV1::Other,
                PreparedInputKindV1::Config | PreparedInputKindV1::Asset => {
                    unreachable!("filtered retained graph input kind")
                }
            };
            inputs.push(
                PrepareInputV1::new(kind, input.name(), input.digest().clone())
                    .map_err(|error| prepared_store::invalid_record(engine, error))?,
            );
        }
        retained.graph_digest().clone()
    } else {
        transition_graph_digest(
            description.finding_code(),
            current_head,
            current.namespace(),
            desired,
            next_lifecycle,
        )
    };
    let request = PrepareRequestV1::from(PrepareRequestPartsV1 {
        namespace: current.namespace().clone(),
        expected_head: Some(current_head.clone()),
        graph_digest,
        inputs,
        artifacts,
        transforms: vec![],
        findings: vec![finding],
        operations,
    });
    prepared_store::prepare_with_state(
        engine,
        &request,
        prepared_store::ExplicitPreparedState::new(
            transition,
            next_lifecycle,
            desired,
            restore_point,
            retention,
            tracked_root,
        ),
    )
}

fn prepare_authority_update(
    engine: &Engine,
    current_head: &Digest,
    current: &StateGenerationV1,
    retention: &RetentionAuthorityV1,
    operation: &str,
) -> Result<PreparedDeploymentV1, EngineError> {
    prepare_selected_state(
        engine,
        current_head,
        current,
        SelectedState {
            transition: PreparedTransitionV1::RetentionAuthority,
            next_lifecycle: current.lifecycle_state(),
            desired: current.desired_snapshot(),
            restore_point: current.restore_point(),
            retention,
            tracked_root: current.tracked_root(),
        },
        Some(current),
        TransitionDescription::RetentionAuthority(operation),
        false,
    )
}

fn load_restore_generation(
    engine: &Engine,
    point: &RestorePointV1,
) -> Result<StateGenerationV1, EngineError> {
    let committer = engine
        .committer_v1()
        .map_err(|error| prepared_store::commit_error(engine, error))?;
    let generation = committer
        .inspect_generation_v1(point.generation())
        .map_err(|error| prepared_store::commit_error(engine, error))?;
    if generation.namespace() != point.namespace()
        || generation.lifecycle_state() != point.lifecycle()
        || generation.desired_snapshot_digest() != point.desired_snapshot_digest()
        || generation.tracked_root() != point.tracked_root()
    {
        return Err(prepared_store::invalid_record(
            engine,
            "restore point does not match its retained generation".to_owned(),
        ));
    }
    Ok(generation)
}

fn verify_pin(engine: &Engine, pin: &RetentionObjectV1) -> Result<(), EngineError> {
    match pin {
        RetentionObjectV1::PreparedPlan { plan_id } => {
            engine.plan_v1(plan_id)?;
        }
        RetentionObjectV1::StateGeneration { digest } => {
            engine
                .committer_v1()
                .and_then(|committer| committer.inspect_generation_v1(digest))
                .map_err(|error| prepared_store::commit_error(engine, error))?;
        }
        RetentionObjectV1::ArtifactBlob { digest } => {
            prepared_store::load_blob_by_digest(engine, digest)?;
        }
        RetentionObjectV1::PackObject { digest } => {
            engine.load_pack_object_v1(digest)?;
        }
        RetentionObjectV1::CanonicalFile { digest } => {
            engine.load_file_object_v1(digest)?;
        }
        RetentionObjectV1::CanonicalSymlink { digest } => {
            engine.load_symlink_object_v1(digest)?;
        }
        RetentionObjectV1::CanonicalTree { digest } => {
            crate::canonical_store::load_tree_graph(engine, digest)?;
        }
    }
    Ok(())
}

fn effective_present(
    generation: &StateGenerationV1,
    authority: &malm_types::DeploymentName,
    relative_path: &str,
) -> bool {
    generation.lifecycle_state().is_enabled()
        && generation
            .desired_snapshot()
            .targets()
            .binary_search_by(|target| {
                (target.authority(), target.relative_path()).cmp(&(authority, relative_path))
            })
            .is_ok_and(|index| generation.desired_snapshot().targets()[index].is_present())
}

fn verify_retained_blobs(engine: &Engine, desired: &DesiredSnapshotV1) -> Result<(), EngineError> {
    let mut verified = BTreeSet::new();
    for target in desired.targets() {
        match target.state() {
            StateTargetStateV1::File { file: Some(file) } => {
                if !verified.insert(file.digest().clone()) {
                    continue;
                }
                let bytes = prepared_store::load_blob_by_digest(engine, file.digest())?;
                if u64::try_from(bytes.len()).unwrap_or(u64::MAX) != file.byte_len() {
                    return Err(prepared_store::invalid_record(
                        engine,
                        format!(
                            "retained blob {} differs from desired target metadata",
                            file.digest()
                        ),
                    ));
                }
            }
            StateTargetStateV1::Symlink {
                symlink: Some(symlink),
            } => {
                engine.load_symlink_object_v1(symlink.object())?;
            }
            StateTargetStateV1::Tree { tree: Some(tree) } => {
                crate::canonical_store::load_tree_graph(engine, tree.tree())?;
            }
            StateTargetStateV1::Directory { .. }
            | StateTargetStateV1::File { file: None }
            | StateTargetStateV1::Symlink { symlink: None }
            | StateTargetStateV1::Tree { tree: None } => {}
        }
    }
    Ok(())
}

fn retained_artifact_id(engine: &Engine, digest: &Digest) -> Result<ArtifactId, EngineError> {
    ArtifactId::new(format!("retained/{}", &digest.as_str()[7..]))
        .map_err(|error| prepared_store::invalid_record(engine, error))
}

fn transition_graph_digest(
    operation: &str,
    current_head: &Digest,
    namespace: &NamespaceName,
    desired: &DesiredSnapshotV1,
    lifecycle: LifecycleStateV1,
) -> Digest {
    let mut bytes = b"malm-lifecycle-transition-v1\0".to_vec();
    bytes.extend_from_slice(operation.as_bytes());
    bytes.push(0);
    bytes.extend_from_slice(current_head.as_str().as_bytes());
    bytes.push(0);
    bytes.extend_from_slice(match lifecycle {
        LifecycleStateV1::Enabled => b"enabled",
        LifecycleStateV1::Disabled => b"disabled",
    });
    bytes.push(0);
    bytes.extend_from_slice(
        malm_store::desired_snapshot_digest_v1(namespace, desired)
            .as_str()
            .as_bytes(),
    );
    Digest::sha256(bytes)
}
