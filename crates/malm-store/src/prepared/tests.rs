use super::*;
use crate::StateGenerationV1;
use crate::StateRecordError;
use crate::test_fixtures::identity;
use crate::test_fixtures::record;

#[test]
fn prepared_records_are_canonical_and_content_addressed() {
    let record = record();
    let bytes = encode_prepared_record_v1(&record);
    let id = prepared_id_v1(&record);

    assert_eq!(decode_prepared_record_v1(&id, &bytes).unwrap(), record);
    assert_eq!(id.digest(), Digest::sha256(&bytes));
    assert!(bytes.ends_with(b"\n"));
    assert_eq!(record.lifecycle_state(), LifecycleStateV1::Enabled);
    assert_eq!(record.tracked_root(), None);
}

#[test]
fn decoding_rejects_noncanonical_unknown_and_wrong_identity() {
    let record = record();
    let bytes = encode_prepared_record_v1(&record);
    let id = prepared_id_v1(&record);
    let pretty = serde_json::to_string_pretty(&record).unwrap();
    assert_eq!(
        decode_prepared_record_v1(&id, pretty.as_bytes()).unwrap_err(),
        PreparedRecordError::NonCanonical
    );

    let mut value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    value["unknown"] = true.into();
    assert!(matches!(
        decode_prepared_record_v1(&id, serde_json::to_string(&value).unwrap().as_bytes()),
        Err(PreparedRecordError::InvalidJson(_))
    ));
    assert!(matches!(
        decode_prepared_record_v1(&PreparedId::from_digest(&Digest::sha256(b"wrong")), &bytes),
        Err(PreparedRecordError::DigestMismatch { .. })
    ));
}

#[test]
fn operation_destinations_cannot_overlap_by_prefix() {
    let artifact = PreparedArtifactV1::new(
        ArtifactId::new("config/file").unwrap(),
        Digest::sha256(b"content"),
        7,
        "text/plain",
    )
    .unwrap();
    let authority = DeploymentName::new("home").unwrap();
    let directory = TargetObservationV1::new(
        authority.clone(),
        "config",
        identity(1),
        vec![],
        identity(1),
        LeafObservationV1::Present(identity(2)),
    )
    .unwrap();
    let file = TargetObservationV1::new(
        authority,
        "config/file",
        identity(1),
        vec![],
        identity(2),
        LeafObservationV1::Absent,
    )
    .unwrap();

    // Directory-shaped ancestors may enclose destinations during restoration.
    assert!(
        PreparedRecordV1::try_from(PreparedRecordPartsV1 {
            namespace: NamespaceName::new("workstation").unwrap(),
            expected_head: None,
            graph_digest: Digest::sha256(b"graph"),
            inputs: vec![],
            artifacts: vec![artifact.clone()],
            transforms: vec![],
            findings: vec![],
            operations: vec![
                PreparedOperationV1::EnsureDirectory {
                    observation: directory.clone(),
                    mode: 0o700,
                },
                PreparedOperationV1::PlaceFile {
                    observation: file.clone(),
                    artifact_id: ArtifactId::new("config/file").unwrap(),
                    mode: 0o600,
                    replace_existing: false,
                },
            ],
            desired_snapshot: DesiredSnapshotV1::empty()
        })
        .is_ok()
    );
    // Leaf-shaped ancestors cannot enclose destinations.
    assert!(matches!(
        PreparedRecordV1::try_from(PreparedRecordPartsV1 {
            namespace: NamespaceName::new("workstation").unwrap(),
            expected_head: None,
            graph_digest: Digest::sha256(b"graph"),
            inputs: vec![],
            artifacts: vec![artifact],
            transforms: vec![],
            findings: vec![],
            operations: vec![
                PreparedOperationV1::AssertAbsent {
                    observation: directory,
                },
                PreparedOperationV1::PlaceFile {
                    observation: file,
                    artifact_id: ArtifactId::new("config/file").unwrap(),
                    mode: 0o600,
                    replace_existing: false,
                },
            ],
            desired_snapshot: DesiredSnapshotV1::empty()
        }),
        Err(PreparedRecordError::InvalidField {
            field: "operation destination",
            ..
        })
    ));
}

#[test]
fn operation_destination_prefix_check_uses_path_components() {
    let operation = |relative_path| PreparedOperationV1::AssertAbsent {
        observation: TargetObservationV1::new(
            DeploymentName::new("home").unwrap(),
            relative_path,
            identity(1),
            vec![],
            identity(2),
            LeafObservationV1::Absent,
        )
        .unwrap(),
    };
    let a = operation("a");
    let a_dash = operation("a-b");
    let a_child = operation("a/b");

    assert!(reject_destination_prefixes(&[a.clone(), a_dash.clone()]).is_ok());
    assert!(matches!(
        reject_destination_prefixes(&[a, a_dash, a_child]),
        Err(PreparedRecordError::InvalidField {
            field: "operation destination",
            ..
        })
    ));
}

#[test]
fn operation_leaf_semantics_are_validated_during_construction() {
    let artifact = PreparedArtifactV1::new(
        ArtifactId::new("config/file").unwrap(),
        Digest::sha256(b"content"),
        7,
        "text/plain",
    )
    .unwrap();
    let authority = DeploymentName::new("home").unwrap();
    let existing_file = TargetObservationV1::new(
        authority.clone(),
        "config/file",
        identity(1),
        vec![],
        identity(2),
        LeafObservationV1::Present(identity(3)),
    )
    .unwrap();
    let absent = TargetObservationV1::new(
        authority,
        "config/absent",
        identity(1),
        vec![],
        identity(2),
        LeafObservationV1::Absent,
    )
    .unwrap();
    let build = |operation| {
        PreparedRecordV1::try_from(PreparedRecordPartsV1 {
            namespace: NamespaceName::new("workstation").unwrap(),
            expected_head: None,
            graph_digest: Digest::sha256(b"graph"),
            inputs: vec![],
            artifacts: vec![artifact.clone()],
            transforms: vec![],
            findings: vec![],
            operations: vec![operation],
            desired_snapshot: DesiredSnapshotV1::empty(),
        })
    };

    assert!(matches!(
        build(PreparedOperationV1::PlaceFile {
            observation: existing_file.clone(),
            artifact_id: ArtifactId::new("config/file").unwrap(),
            mode: 0o600,
            replace_existing: false,
        }),
        Err(PreparedRecordError::InvalidField {
            field: "place-file conflict policy",
            ..
        })
    ));
    assert!(
        build(PreparedOperationV1::EnsureDirectory {
            observation: existing_file,
            mode: 0o700,
        })
        .is_ok()
    );
    let unowned_absent_removal = build(PreparedOperationV1::RemoveLeaf {
        observation: absent,
    })
    .unwrap();
    assert!(matches!(
        StateGenerationV1::from_prepared(
            prepared_id_v1(&unowned_absent_removal),
            None,
            None,
            &unowned_absent_removal,
        ),
        Err(StateRecordError::InvalidState(reason))
            if reason.contains("not required by the lifecycle transition")
    ));
}

#[test]
fn aggregate_artifact_bytes_are_bounded_by_unique_digest() {
    let artifact = |id: &str, digest: Digest| {
        PreparedArtifactV1::new(
            ArtifactId::new(id).unwrap(),
            digest,
            192 * 1024 * 1024,
            "application/octet-stream",
        )
        .unwrap()
    };
    let first_digest = Digest::sha256(b"first");
    let build = |artifacts| {
        PreparedRecordV1::try_from(PreparedRecordPartsV1 {
            namespace: NamespaceName::new("workstation").unwrap(),
            expected_head: None,
            graph_digest: Digest::sha256(b"graph"),
            inputs: vec![],
            artifacts,
            transforms: vec![],
            findings: vec![],
            operations: vec![],
            desired_snapshot: DesiredSnapshotV1::empty(),
        })
    };

    assert!(
        build(vec![
            artifact("a/one", first_digest.clone()),
            artifact("a/two", first_digest),
        ])
        .is_ok()
    );
    assert!(matches!(
        build(vec![
            artifact("a/one", Digest::sha256(b"one")),
            artifact("a/two", Digest::sha256(b"two")),
        ]),
        Err(PreparedRecordError::InvalidField {
            field: "artifact bytes",
            ..
        })
    ));
}

#[test]
fn prepared_record_construction_enforces_its_encoded_size_limit() {
    let findings = (0..300)
        .map(|index| {
            PolicyFindingV1::new(
                format!("finding-{index}"),
                format!("{index:03}-{}", "x".repeat(64 * 1024 - 4)),
                false,
            )
            .unwrap()
        })
        .collect();

    assert!(matches!(
        PreparedRecordV1::try_from(PreparedRecordPartsV1 {
            namespace: NamespaceName::new("workstation").unwrap(),
            expected_head: None,
            graph_digest: Digest::sha256(b"graph"),
            inputs: vec![],
            artifacts: vec![],
            transforms: vec![],
            findings,
            operations: vec![],
            desired_snapshot: DesiredSnapshotV1::empty()
        }),
        Err(PreparedRecordError::TooLarge {
            limit: MAX_PREPARED_RECORD_BYTES,
            ..
        })
    ));
}
