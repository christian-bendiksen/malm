use super::*;
use crate::LeafObservationV1;
use crate::OwnershipOverlapKindV1;
use crate::OwnershipProjectionError;
use crate::OwnershipProjectionV1;
use crate::PreparedArtifactV1;
use crate::PreparedOperationV1;
use crate::PreparedRecordPartsV1;
use crate::RequiredTargetMutationV1;
use crate::TargetObservationV1;
use crate::decode_prepared_record_v1;
use crate::encode_prepared_record_v1;
use crate::required_target_mutations_v1;
use crate::test_fixtures::identity;
use crate::test_fixtures::state_target;
use crate::test_fixtures::test_generation;

#[test]
fn desired_snapshots_sort_strictly_and_enforce_their_target_limit() {
    let snapshot = DesiredSnapshotV1::new(vec![
        state_target("home", "z", false),
        state_target("home", "a", false),
    ])
    .unwrap();
    assert_eq!(snapshot.targets()[0].relative_path(), "a");
    assert_eq!(snapshot.targets()[1].relative_path(), "z");

    let repeated = state_target("home", "target", false);
    assert!(matches!(
        DesiredSnapshotV1::new(vec![repeated; MAX_DESIRED_TARGETS + 1]),
        Err(StateRecordError::InvalidState(reason))
            if reason.contains("target count limit")
    ));

    let namespace = NamespaceName::new("workstation").unwrap();
    let mut noncanonical = PreparedRecordV1::try_from(PreparedRecordPartsV1 {
        namespace: namespace.clone(),
        expected_head: None,
        graph_digest: Digest::sha256(b"graph"),
        inputs: vec![],
        artifacts: vec![],
        transforms: vec![],
        findings: vec![],
        operations: vec![],
        desired_snapshot: snapshot,
    })
    .unwrap();
    noncanonical.desired_snapshot.0.reverse();
    noncanonical.desired_snapshot_digest =
        desired_snapshot_digest_v1(&namespace, noncanonical.desired_snapshot());
    let bytes = encode_prepared_record_v1(&noncanonical);
    let id = prepared_id_v1(&noncanonical);
    assert_eq!(
        decode_prepared_record_v1(&id, &bytes),
        Err(PreparedRecordError::NonCanonical)
    );
}

#[test]
fn state_catalogs_sort_lookup_and_update_namespace_heads() {
    let alpha = NamespaceName::new("alpha").unwrap();
    let beta = NamespaceName::new("Beta_2").unwrap();
    let alpha_generation = Digest::sha256(b"alpha generation");
    let beta_generation = Digest::sha256(b"beta generation");
    let mut catalog = StateCatalogV1::new(vec![
        NamespaceHeadV1::new(beta.clone(), beta_generation.clone()),
        NamespaceHeadV1::new(alpha.clone(), alpha_generation.clone()),
    ])
    .unwrap();

    assert_eq!(catalog.schema_version(), STATE_CATALOG_SCHEMA_VERSION);
    assert_eq!(catalog.heads()[0].namespace(), &beta);
    assert_eq!(catalog.heads()[1].namespace(), &alpha);
    assert_eq!(catalog.generation(&alpha), Some(&alpha_generation));
    assert_eq!(
        catalog.head(&beta).map(NamespaceHeadV1::generation),
        Some(&beta_generation)
    );

    let replacement = Digest::sha256(b"replacement generation");
    assert_eq!(
        catalog
            .update_head(alpha.clone(), replacement.clone())
            .unwrap(),
        Some(alpha_generation)
    );
    assert_eq!(catalog.generation(&alpha), Some(&replacement));

    let gamma = NamespaceName::new("gamma").unwrap();
    let gamma_generation = Digest::sha256(b"gamma generation");
    assert_eq!(
        catalog
            .update_head(gamma.clone(), gamma_generation.clone())
            .unwrap(),
        None
    );
    assert_eq!(catalog.generation(&gamma), Some(&gamma_generation));
    assert_eq!(catalog.remove_head(&beta), Some(beta_generation));
    assert!(catalog.head(&beta).is_none());

    let bytes = encode_state_catalog_v1(&catalog);
    assert_eq!(decode_state_catalog_v1(&bytes).unwrap(), catalog);
    assert_eq!(state_catalog_digest_v1(&catalog), Digest::sha256(bytes));
}

#[test]
fn state_catalogs_reject_duplicates_and_enforce_resource_limits() {
    let namespace = NamespaceName::new("duplicate").unwrap();
    assert!(matches!(
        StateCatalogV1::new(vec![
            NamespaceHeadV1::new(namespace.clone(), Digest::sha256(b"one")),
            NamespaceHeadV1::new(namespace.clone(), Digest::sha256(b"two")),
        ]),
        Err(StateCatalogError::DuplicateNamespace(found)) if found == namespace
    ));

    let generation = Digest::sha256(b"generation");
    let heads = (0..=MAX_STATE_CATALOG_HEADS)
        .map(|index| {
            NamespaceHeadV1::new(
                NamespaceName::new(format!("namespace-{index:04}")).unwrap(),
                generation.clone(),
            )
        })
        .collect();
    assert!(matches!(
        StateCatalogV1::new(heads),
        Err(StateCatalogError::TooManyHeads {
            limit: MAX_STATE_CATALOG_HEADS,
            actual,
        }) if actual == MAX_STATE_CATALOG_HEADS + 1
    ));

    let encoded_head = serde_json::to_string(&NamespaceHeadV1::new(
        NamespaceName::new("repeated").unwrap(),
        generation,
    ))
    .unwrap();
    let mut overfull = String::from("{\"schema_version\":1,\"heads\":[");
    for index in 0..=MAX_STATE_CATALOG_HEADS {
        if index != 0 {
            overfull.push(',');
        }
        overfull.push_str(&encoded_head);
    }
    overfull.push_str("]}\n");
    assert!(matches!(
        decode_state_catalog_v1(overfull.as_bytes()),
        Err(StateCatalogError::InvalidJson(_))
    ));

    let oversized = vec![b' '; MAX_STATE_CATALOG_BYTES + 1];
    assert_eq!(
        decode_state_catalog_v1(&oversized),
        Err(StateCatalogError::TooLarge {
            limit: MAX_STATE_CATALOG_BYTES,
            actual: MAX_STATE_CATALOG_BYTES + 1,
        })
    );
}

#[test]
fn disable_uses_empty_state_and_enable_recreates_the_exact_restore_point() {
    let namespace = NamespaceName::new("alpha").unwrap();
    let desired = DesiredSnapshotV1::new(vec![state_target("home", "shared", true)]).unwrap();
    let place = PreparedOperationV1::EnsureDirectory {
        observation: TargetObservationV1::new(
            DeploymentName::new("home").unwrap(),
            "shared",
            identity(1),
            vec![],
            identity(2),
            LeafObservationV1::Absent,
        )
        .unwrap(),
        mode: 0o700,
    };
    let enabled_plan = PreparedRecordV1::try_from(PreparedRecordPartsV1 {
        namespace: namespace.clone(),
        expected_head: None,
        graph_digest: Digest::sha256(b"enabled graph"),
        inputs: vec![],
        artifacts: vec![],
        transforms: vec![],
        findings: vec![],
        operations: vec![place],
        desired_snapshot: desired.clone(),
    })
    .unwrap();
    let enabled =
        StateGenerationV1::from_prepared(prepared_id_v1(&enabled_plan), None, None, &enabled_plan)
            .unwrap();
    let enabled_digest = state_generation_digest_v1(&enabled);
    assert!(matches!(
        required_target_mutations_v1(
            Some((LifecycleStateV1::Enabled, enabled.desired_snapshot())),
            LifecycleStateV1::Disabled,
            &DesiredSnapshotV1::empty(),
        )
        .unwrap()
        .as_slice(),
        [RequiredTargetMutationV1::RemoveLeaf { .. }]
    ));
    let remove = PreparedOperationV1::RemoveLeaf {
        observation: TargetObservationV1::new(
            DeploymentName::new("home").unwrap(),
            "shared",
            identity(1),
            vec![],
            identity(2),
            LeafObservationV1::Present(identity(3)),
        )
        .unwrap(),
    };
    let restore_point = RestorePointV1::new(
        namespace.clone(),
        enabled_digest.clone(),
        enabled.lifecycle_state(),
        enabled.desired_snapshot_digest().clone(),
        enabled.tracked_root().cloned(),
    );
    let retention = enabled
        .retention_authority()
        .clone()
        .with_restore_point(restore_point.clone())
        .unwrap();
    let disabled_plan = PreparedRecordV1::try_from(PreparedRecordPartsV1 {
        namespace: namespace.clone(),
        expected_head: Some(enabled_digest.clone()),
        graph_digest: Digest::sha256(b"disabled graph"),
        inputs: vec![],
        artifacts: vec![],
        transforms: vec![],
        findings: vec![],
        operations: vec![remove],
        desired_snapshot: DesiredSnapshotV1::empty(),
    })
    .unwrap()
    .with_transition(PreparedTransitionV1::Disable)
    .unwrap()
    .with_lifecycle_state(LifecycleStateV1::Disabled)
    .unwrap()
    .with_restore_point(Some(restore_point.clone()))
    .unwrap()
    .with_retention_authority(retention.clone())
    .unwrap();
    let disabled = StateGenerationV1::from_prepared(
        prepared_id_v1(&disabled_plan),
        Some(enabled_digest),
        Some(&enabled),
        &disabled_plan,
    )
    .unwrap();
    let beta = test_generation("beta", vec![state_target("home", "shared", true)]);

    let projection = OwnershipProjectionV1::from_selected_generations([
        (disabled.namespace(), &disabled),
        (beta.namespace(), &beta),
    ])
    .unwrap();
    assert!(disabled.targets().is_empty());
    assert_eq!(disabled.restore_point(), Some(&restore_point));
    assert_eq!(projection.claims().len(), 1);
    assert_eq!(projection.claims()[0].namespace(), beta.namespace());

    let disabled_digest = state_generation_digest_v1(&disabled);
    assert!(matches!(
        required_target_mutations_v1(
            Some((LifecycleStateV1::Disabled, disabled.desired_snapshot())),
            LifecycleStateV1::Enabled,
            &desired,
        )
        .unwrap()
        .as_slice(),
        [RequiredTargetMutationV1::EnsureDirectory { mode: 0o700, .. }]
    ));
    let recreate = PreparedOperationV1::EnsureDirectory {
        observation: TargetObservationV1::new(
            DeploymentName::new("home").unwrap(),
            "shared",
            identity(1),
            vec![],
            identity(2),
            LeafObservationV1::Absent,
        )
        .unwrap(),
        mode: 0o700,
    };
    let reenabled_plan = PreparedRecordV1::try_from(PreparedRecordPartsV1 {
        namespace,
        expected_head: Some(disabled_digest.clone()),
        graph_digest: Digest::sha256(b"re-enabled graph"),
        inputs: vec![],
        artifacts: vec![],
        transforms: vec![],
        findings: vec![],
        operations: vec![recreate],
        desired_snapshot: desired,
    })
    .unwrap()
    .with_transition(PreparedTransitionV1::Enable {
        restore_point: Box::new(restore_point.clone()),
    })
    .unwrap()
    .with_retention_authority(retention)
    .unwrap();
    let reenabled = StateGenerationV1::from_prepared(
        prepared_id_v1(&reenabled_plan),
        Some(disabled_digest),
        Some(&disabled),
        &reenabled_plan,
    )
    .unwrap();
    assert_eq!(reenabled.targets(), enabled.targets());
    assert_eq!(reenabled.lifecycle_state(), LifecycleStateV1::Enabled);
    assert!(matches!(
        OwnershipProjectionV1::from_selected_generations([
            (reenabled.namespace(), &reenabled),
            (beta.namespace(), &beta),
        ]),
        Err(OwnershipProjectionError::Conflict {
            overlap: OwnershipOverlapKindV1::Exact,
            ..
        })
    ));
}

#[test]
fn disabled_state_requires_an_explicit_lifecycle_transition_and_restore_point() {
    let plan = PreparedRecordV1::try_from(PreparedRecordPartsV1 {
        namespace: NamespaceName::new("alpha").unwrap(),
        expected_head: None,
        graph_digest: Digest::sha256(b"invalid direct disabled graph"),
        inputs: vec![],
        artifacts: vec![],
        transforms: vec![],
        findings: vec![],
        operations: vec![],
        desired_snapshot: DesiredSnapshotV1::empty(),
    })
    .unwrap()
    .with_lifecycle_state(LifecycleStateV1::Disabled)
    .unwrap();
    assert!(StateGenerationV1::from_prepared(prepared_id_v1(&plan), None, None, &plan).is_err());
}

#[test]
fn generation_derivation_rejects_forged_desired_and_lifecycle_manifests() {
    let namespace = NamespaceName::new("alpha").unwrap();
    let desired = DesiredSnapshotV1::new(vec![state_target("home", "managed", true)]).unwrap();
    let operation = PreparedOperationV1::EnsureDirectory {
        observation: TargetObservationV1::new(
            DeploymentName::new("home").unwrap(),
            "managed",
            identity(1),
            vec![],
            identity(2),
            LeafObservationV1::Absent,
        )
        .unwrap(),
        mode: 0o700,
    };
    let valid = PreparedRecordV1::try_from(PreparedRecordPartsV1 {
        namespace: namespace.clone(),
        expected_head: None,
        graph_digest: Digest::sha256(b"graph"),
        inputs: vec![],
        artifacts: vec![],
        transforms: vec![],
        findings: vec![],
        operations: vec![operation],
        desired_snapshot: desired,
    })
    .unwrap();
    let generation =
        StateGenerationV1::from_prepared(prepared_id_v1(&valid), None, None, &valid).unwrap();

    let mut wrong_digest = valid.clone();
    wrong_digest.desired_snapshot_digest = Digest::sha256(b"forged digest");
    assert!(
        StateGenerationV1::from_prepared(prepared_id_v1(&wrong_digest), None, None, &wrong_digest,)
            .is_err()
    );

    let mut wrong_snapshot = valid.clone();
    wrong_snapshot.desired_snapshot = DesiredSnapshotV1::empty();
    wrong_snapshot.desired_snapshot_digest =
        desired_snapshot_digest_v1(&namespace, wrong_snapshot.desired_snapshot());
    assert!(
        StateGenerationV1::from_prepared(
            prepared_id_v1(&wrong_snapshot),
            None,
            None,
            &wrong_snapshot,
        )
        .is_err()
    );

    let mut wrong_lifecycle = valid.clone();
    wrong_lifecycle.lifecycle = LifecycleStateV1::Disabled;
    assert!(
        StateGenerationV1::from_prepared(
            prepared_id_v1(&wrong_lifecycle),
            None,
            None,
            &wrong_lifecycle,
        )
        .is_err()
    );

    let mut forged_generation = generation.clone();
    forged_generation.desired_snapshot = DesiredSnapshotV1::empty();
    forged_generation.desired_snapshot_digest = desired_snapshot_digest_v1(
        forged_generation.namespace(),
        forged_generation.desired_snapshot(),
    );
    assert_ne!(
        StateGenerationV1::from_prepared(prepared_id_v1(&valid), None, None, &valid,).unwrap(),
        forged_generation
    );
}

#[test]
fn desired_snapshots_reject_same_namespace_nesting() {
    // Present managed directories may enclose targets so ancestors can be restored.
    assert!(
        DesiredSnapshotV1::new(vec![
            state_target("home", "a", true),
            state_target("home", "a/b", true),
        ])
        .is_ok()
    );
    // Other present states are leaves and cannot enclose targets.
    let file_target = |relative_path: &str| StateTargetV1 {
        authority: DeploymentName::new("home").unwrap(),
        relative_path: relative_path.to_owned(),
        state: StateTargetStateV1::File {
            file: Some(StateFileV1::new(Digest::sha256(b"leaf"), 4, 0o600).unwrap()),
        },
    };
    assert!(matches!(
        DesiredSnapshotV1::new(vec![file_target("a"), file_target("a/b")]),
        Err(StateRecordError::InvalidState(reason)) if reason.contains("overlap")
    ));
    assert!(matches!(
        DesiredSnapshotV1::new(vec![file_target("a"), state_target("home", "a/b", true)]),
        Err(StateRecordError::InvalidState(reason)) if reason.contains("overlap")
    ));
}

#[test]
fn state_generation_construction_enforces_its_encoded_size_limit() {
    let artifacts = (0..15_000)
        .map(|index| {
            PreparedArtifactV1::new(
                ArtifactId::new(format!("a/{index:05}-{}", "x".repeat(240))).unwrap(),
                Digest::sha256([]),
                0,
                "application/octet-stream",
            )
            .unwrap()
        })
        .collect();

    let namespace = NamespaceName::new("workstation").unwrap();
    let record = PreparedRecordV1::try_from(PreparedRecordPartsV1 {
        namespace: namespace.clone(),
        expected_head: None,
        graph_digest: Digest::sha256(b"graph"),
        inputs: vec![],
        artifacts,
        transforms: vec![],
        findings: vec![],
        operations: vec![],
        desired_snapshot: DesiredSnapshotV1::empty(),
    })
    .unwrap();
    assert!(matches!(
        StateGenerationV1::from_prepared(prepared_id_v1(&record), None, None, &record,),
        Err(StateRecordError::TooLarge { .. })
    ));
}
