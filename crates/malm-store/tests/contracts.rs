use malm_store::{
    AcquisitionGrantKindV1, AcquisitionGrantV1, ConfigEntryPointV1, DesiredSnapshotV1,
    ExactRevisionV1, FileIdentityV1, LeafObservationV1, LifecycleStateV1,
    MAX_TRANSFORM_DIAGNOSTIC_NOTES, MAX_TRANSFORM_DIAGNOSTIC_TEXT_BYTES, MAX_TRANSFORM_DIAGNOSTICS,
    MAX_TRANSFORM_RESOURCES, MovingSelectorV1, NamespaceHeadV1, PolicyFindingV1,
    PreparedArtifactV1, PreparedInputKindV1, PreparedInputV1, PreparedOperationV1,
    PreparedRecordError, PreparedRecordPartsV1, PreparedRecordV1, StateCatalogError,
    StateCatalogV1, StateFileV1, StateGenerationV1, StateRecordError, StateTargetStateV1,
    StateTargetV1, TargetObservationV1, TrackedRootSourceLocatorV1, TrackedRootSubdirV1,
    TrackedRootV1, TransformDiagnosticLocationV1, TransformDiagnosticSeverityV1,
    TransformDiagnosticV1, TransformImplementationV1, TransformProvenanceV1, TransformResourceV1,
    decode_prepared_record_v1, decode_state_catalog_v1, decode_state_generation_v1,
    encode_prepared_record_v1, encode_state_catalog_v1, encode_state_generation_v1, prepared_id_v1,
    state_catalog_digest_v1, state_generation_digest_v1,
};
use malm_types::{
    ArtifactId, ContributionName, DeploymentName, Digest, NamespaceName, PackNodeId, PreparedId,
};
use serde::Deserialize;

const VALID_PREPARED: &[u8] =
    include_bytes!("../../../schemas/store/v1/fixtures/valid/prepared-record.json");
const VALID_GENERATION: &[u8] =
    include_bytes!("../../../schemas/store/v1/fixtures/valid/state-generation.json");
const VALID_CATALOG: &[u8] =
    include_bytes!("../../../schemas/store/v1/fixtures/valid/state-catalog.json");
const GOLDEN_PREPARED: &[u8] =
    include_bytes!("../../../schemas/store/v1/fixtures/golden/prepared-record.json");
const GOLDEN_GENERATION: &[u8] =
    include_bytes!("../../../schemas/store/v1/fixtures/golden/state-generation.json");
const GOLDEN_CATALOG: &[u8] =
    include_bytes!("../../../schemas/store/v1/fixtures/golden/state-catalog.json");

#[derive(Deserialize)]
struct FixtureIdentities {
    valid: RecordIdentities,
    golden: RecordIdentities,
}

#[derive(Deserialize)]
struct RecordIdentities {
    prepared_record: PreparedId,
    state_generation: Digest,
    state_catalog: Digest,
}

fn fixture_identities() -> FixtureIdentities {
    serde_json::from_slice(include_bytes!(
        "../../../schemas/store/v1/fixtures/golden/digests.json"
    ))
    .unwrap()
}

fn directory_identity(inode: u64) -> FileIdentityV1 {
    FileIdentityV1 {
        device: 7,
        inode,
        user_id: 1_000,
        group_id: 1_000,
        mode: 0o040_700,
        links: 1,
        size: 4_096,
        modified_seconds: 1_700_000_000,
        modified_nanoseconds: 123_456_789,
        changed_seconds: 1_700_000_001,
        changed_nanoseconds: 987_654_321,
    }
}

fn golden_prepared_record() -> PreparedRecordV1 {
    let namespace = NamespaceName::new("workstation").unwrap();
    let artifact = PreparedArtifactV1::new(
        ArtifactId::new("config/app.toml").unwrap(),
        Digest::sha256(b"theme = \"dark\"\n"),
        15,
        "text/plain",
    )
    .unwrap();
    let operation = PreparedOperationV1::PlaceFile {
        observation: TargetObservationV1::new(
            DeploymentName::new("home").unwrap(),
            ".config/malm/app.toml",
            directory_identity(10),
            vec![directory_identity(11)],
            directory_identity(12),
            LeafObservationV1::Absent,
        )
        .unwrap(),
        artifact_id: artifact.id().clone(),
        mode: 0o600,
        replace_existing: false,
    };
    let desired_snapshot = DesiredSnapshotV1::new(vec![
        StateTargetV1::new(
            DeploymentName::new("home").unwrap(),
            ".config/malm/app.toml",
            StateTargetStateV1::File {
                file: Some(
                    StateFileV1::new(artifact.digest().clone(), artifact.byte_len(), 0o600)
                        .unwrap(),
                ),
            },
        )
        .unwrap(),
    ])
    .unwrap();

    PreparedRecordV1::try_from(PreparedRecordPartsV1 {
        namespace: namespace.clone(),
        expected_head: None,
        graph_digest: Digest::sha256(b"fixture graph"),
        inputs: vec![
            PreparedInputV1::new(
                PreparedInputKindV1::Config,
                "root-config",
                Digest::sha256(b"fixture config"),
            )
            .unwrap(),
        ],
        artifacts: vec![artifact],
        transforms: vec![],
        findings: vec![
            PolicyFindingV1::new("create-file", "Create the fixture file", true).unwrap(),
        ],
        operations: vec![operation],
        desired_snapshot,
    })
    .unwrap()
    .with_tracked_root(Some(
        TrackedRootV1::new(
            TrackedRootSourceLocatorV1::new("https://example.com/dotfiles.git").unwrap(),
            MovingSelectorV1::new("refs/heads/main").unwrap(),
            ExactRevisionV1::new(format!("sha1-{}", "1".repeat(40))).unwrap(),
            Digest::new(format!("sha256-{}", "2".repeat(64))).unwrap(),
            ConfigEntryPointV1::new("malm.kdl").unwrap(),
            ContributionName::new("desktop").unwrap(),
            vec![
                AcquisitionGrantV1::new(
                    AcquisitionGrantKindV1::GitSource,
                    "https://example.com/dependency.git",
                )
                .unwrap(),
                AcquisitionGrantV1::new(AcquisitionGrantKindV1::LocalSource, "../shared-pack")
                    .unwrap(),
                AcquisitionGrantV1::new(
                    AcquisitionGrantKindV1::FormatComponent,
                    format!("sha256-{}", "3".repeat(64)),
                )
                .unwrap(),
                AcquisitionGrantV1::new(AcquisitionGrantKindV1::TargetAuthority, "home").unwrap(),
            ],
        )
        .unwrap()
        .with_source_subdir(TrackedRootSubdirV1::new("packs/root").unwrap())
        .unwrap(),
    ))
    .unwrap()
}

fn diagnostic_transform() -> TransformProvenanceV1 {
    let digest =
        |digit: char| Digest::new(format!("sha256-{}", digit.to_string().repeat(64))).unwrap();
    TransformProvenanceV1::new(
        "settings",
        TransformImplementationV1::component(
            PackNodeId::new(digest('1')),
            digest('2'),
            "components/formatter.wasm",
            digest('3'),
            "format-component/v1",
            digest('4'),
        )
        .unwrap(),
        digest('5'),
        digest('6'),
        vec![TransformResourceV1::new("theme", digest('7')).unwrap()],
        digest('8'),
        vec![
            TransformDiagnosticV1::new(
                TransformDiagnosticSeverityV1::Warning,
                "component.warning",
                "review output",
                Some(TransformDiagnosticLocationV1::Source {
                    authority_label: ContributionName::new("root").unwrap(),
                    authority_identity: digest('9'),
                    document_path: "malm.kdl".to_owned(),
                    source_byte_len: 64,
                    start: 12,
                    end: 24,
                }),
                vec!["first note".to_owned(), "second note".to_owned()],
            )
            .unwrap(),
            TransformDiagnosticV1::new(
                TransformDiagnosticSeverityV1::Info,
                "component.info",
                "output detail",
                Some(TransformDiagnosticLocationV1::Output { start: 2, end: 8 }),
                vec![],
            )
            .unwrap(),
        ],
    )
    .unwrap()
}

fn golden_state_catalog(identities: &FixtureIdentities) -> StateCatalogV1 {
    StateCatalogV1::new(vec![
        NamespaceHeadV1::new(
            NamespaceName::new("workstation").unwrap(),
            identities.golden.state_generation.clone(),
        ),
        NamespaceHeadV1::new(
            NamespaceName::new("minimal").unwrap(),
            identities.valid.state_generation.clone(),
        ),
    ])
    .unwrap()
}

#[test]
fn valid_fixtures_decode_and_form_one_verified_transition() {
    let identities = fixture_identities();
    let prepared =
        decode_prepared_record_v1(&identities.valid.prepared_record, VALID_PREPARED).unwrap();
    assert_eq!(prepared.namespace().as_str(), "minimal");
    assert_eq!(prepared.lifecycle_state(), LifecycleStateV1::Enabled);
    assert_eq!(prepared.tracked_root(), None);
    assert!(!String::from_utf8_lossy(VALID_PREPARED).contains("source_subdir"));
    assert!(prepared.desired_snapshot().is_empty());
    assert_eq!(encode_prepared_record_v1(&prepared), VALID_PREPARED);

    let generation =
        decode_state_generation_v1(&identities.valid.state_generation, VALID_GENERATION).unwrap();
    assert_eq!(generation.plan_id(), &identities.valid.prepared_record);
    assert_eq!(generation.lifecycle_state(), LifecycleStateV1::Enabled);
    assert_eq!(generation.tracked_root(), None);
    assert_eq!(generation.desired_snapshot(), prepared.desired_snapshot());
    assert_eq!(encode_state_generation_v1(&generation), VALID_GENERATION);
    assert_eq!(
        StateGenerationV1::from_prepared(identities.valid.prepared_record, None, None, &prepared,)
            .unwrap(),
        generation
    );

    let catalog = decode_state_catalog_v1(VALID_CATALOG).unwrap();
    let namespace = NamespaceName::new("minimal").unwrap();
    assert_eq!(catalog.schema_version(), 1);
    assert_eq!(catalog.heads().len(), 1);
    assert_eq!(
        catalog.generation(&namespace),
        Some(&identities.valid.state_generation)
    );
    assert_eq!(encode_state_catalog_v1(&catalog), VALID_CATALOG);
    assert_eq!(
        state_catalog_digest_v1(&catalog),
        identities.valid.state_catalog
    );
}

#[test]
fn canonical_writers_match_exact_golden_bytes_and_identities() {
    let identities = fixture_identities();
    let catalog = golden_state_catalog(&identities);
    let prepared = golden_prepared_record();
    assert_eq!(encode_prepared_record_v1(&prepared), GOLDEN_PREPARED);
    assert_eq!(prepared_id_v1(&prepared), identities.golden.prepared_record);
    assert_eq!(prepared.lifecycle_state(), LifecycleStateV1::Enabled);
    assert_eq!(
        prepared.tracked_root().unwrap().moving_selector().as_str(),
        "refs/heads/main"
    );
    assert_eq!(
        prepared.tracked_root().unwrap().source_subdir().as_str(),
        "packs/root"
    );
    assert!(String::from_utf8_lossy(GOLDEN_PREPARED).contains("\"source_subdir\":\"packs/root\""));
    assert_eq!(
        decode_prepared_record_v1(&identities.golden.prepared_record, GOLDEN_PREPARED).unwrap(),
        prepared
    );

    let generation =
        StateGenerationV1::from_prepared(identities.golden.prepared_record, None, None, &prepared)
            .unwrap();
    assert_eq!(generation.tracked_root(), prepared.tracked_root());
    assert_eq!(encode_state_generation_v1(&generation), GOLDEN_GENERATION);
    assert_eq!(
        state_generation_digest_v1(&generation),
        identities.golden.state_generation
    );
    assert_eq!(
        decode_state_generation_v1(&identities.golden.state_generation, GOLDEN_GENERATION).unwrap(),
        generation
    );

    assert_eq!(encode_state_catalog_v1(&catalog), GOLDEN_CATALOG);
    assert_eq!(
        state_catalog_digest_v1(&catalog),
        identities.golden.state_catalog
    );
    assert_eq!(decode_state_catalog_v1(GOLDEN_CATALOG).unwrap(), catalog);
}

#[test]
fn transform_diagnostics_have_exact_golden_bytes_and_bind_record_and_generation_identity() {
    let transform = diagnostic_transform();
    let mut encoded = serde_json::to_vec(&transform).unwrap();
    encoded.push(b'\n');
    assert_eq!(
        encoded,
        include_bytes!("../../../schemas/store/v1/fixtures/golden/transform-provenance.json")
    );

    let record = PreparedRecordV1::try_from(PreparedRecordPartsV1 {
        namespace: NamespaceName::new("diagnostics").unwrap(),
        expected_head: None,
        graph_digest: Digest::sha256(b"diagnostic graph"),
        inputs: vec![],
        artifacts: vec![],
        transforms: vec![transform.clone()],
        findings: vec![],
        operations: vec![],
        desired_snapshot: DesiredSnapshotV1::empty(),
    })
    .unwrap();
    let without_diagnostics = TransformProvenanceV1::new(
        transform.name(),
        transform.implementation().clone(),
        transform.request_digest().clone(),
        transform.document_digest().clone(),
        transform.resources().to_vec(),
        transform.response_digest().clone(),
        vec![],
    )
    .unwrap();
    let alternate = PreparedRecordV1::try_from(PreparedRecordPartsV1 {
        namespace: record.namespace().clone(),
        expected_head: None,
        graph_digest: record.graph_digest().clone(),
        inputs: vec![],
        artifacts: vec![],
        transforms: vec![without_diagnostics],
        findings: vec![],
        operations: vec![],
        desired_snapshot: DesiredSnapshotV1::empty(),
    })
    .unwrap();
    assert_ne!(prepared_id_v1(&record), prepared_id_v1(&alternate));

    let plan_id = prepared_id_v1(&record);
    let generation = StateGenerationV1::from_prepared(plan_id, None, None, &record).unwrap();
    assert_eq!(generation.transforms(), [transform]);
}

#[test]
fn transform_diagnostic_limits_and_malformed_locations_fail_closed() {
    let diagnostic = TransformDiagnosticV1::new(
        TransformDiagnosticSeverityV1::Info,
        "limit.info",
        "message",
        None,
        vec![],
    )
    .unwrap();
    assert!(matches!(
        TransformDiagnosticV1::new(
            TransformDiagnosticSeverityV1::Error,
            "invalid.success",
            "successful provenance cannot contain errors",
            None,
            vec![],
        ),
        Err(PreparedRecordError::InvalidField {
            field: "transform diagnostic severity",
            ..
        })
    ));
    assert!(matches!(
        TransformDiagnosticV1::new(
            TransformDiagnosticSeverityV1::Warning,
            "invalid.range",
            "range exceeds source",
            Some(TransformDiagnosticLocationV1::Source {
                authority_label: ContributionName::new("root").unwrap(),
                authority_identity: Digest::sha256(b"root"),
                document_path: "malm.kdl".to_owned(),
                source_byte_len: 1,
                start: 0,
                end: 2,
            }),
            vec![],
        ),
        Err(PreparedRecordError::InvalidField {
            field: "transform diagnostic source range",
            ..
        })
    ));
    assert!(matches!(
        TransformDiagnosticV1::new(
            TransformDiagnosticSeverityV1::Info,
            "limit.info",
            "message",
            None,
            vec![String::new(); MAX_TRANSFORM_DIAGNOSTIC_NOTES + 1],
        ),
        Err(PreparedRecordError::LimitExceeded {
            field: "transform diagnostic notes",
            ..
        })
    ));
    assert!(matches!(
        TransformDiagnosticV1::new(
            TransformDiagnosticSeverityV1::Info,
            "limit.info",
            "x".repeat(MAX_TRANSFORM_DIAGNOSTIC_TEXT_BYTES + 1),
            None,
            vec![],
        ),
        Err(PreparedRecordError::LimitExceeded {
            field: "transform diagnostic message",
            ..
        })
    ));

    let base = diagnostic_transform();
    assert!(matches!(
        TransformProvenanceV1::new(
            base.name(),
            base.implementation().clone(),
            base.request_digest().clone(),
            base.document_digest().clone(),
            base.resources().to_vec(),
            base.response_digest().clone(),
            vec![diagnostic.clone(), diagnostic.clone()],
        ),
        Err(PreparedRecordError::InvalidField {
            field: "transform diagnostics",
            ..
        })
    ));
    assert!(matches!(
        TransformProvenanceV1::new(
            base.name(),
            base.implementation().clone(),
            base.request_digest().clone(),
            base.document_digest().clone(),
            base.resources().to_vec(),
            base.response_digest().clone(),
            vec![diagnostic.clone(); MAX_TRANSFORM_DIAGNOSTICS + 1],
        ),
        Err(PreparedRecordError::LimitExceeded {
            field: "transform diagnostics",
            ..
        })
    ));
    assert!(matches!(
        TransformProvenanceV1::new(
            base.name(),
            base.implementation().clone(),
            base.request_digest().clone(),
            base.document_digest().clone(),
            vec![base.resources()[0].clone(); MAX_TRANSFORM_RESOURCES + 1],
            base.response_digest().clone(),
            vec![],
        ),
        Err(PreparedRecordError::LimitExceeded {
            field: "transform resources",
            ..
        })
    ));
    let large = (0..65)
        .map(|index| {
            TransformDiagnosticV1::new(
                TransformDiagnosticSeverityV1::Info,
                format!("limit.large-{index}"),
                "x".repeat(MAX_TRANSFORM_DIAGNOSTIC_TEXT_BYTES),
                None,
                vec![],
            )
            .unwrap()
        })
        .collect();
    assert!(matches!(
        TransformProvenanceV1::new(
            base.name(),
            base.implementation().clone(),
            base.request_digest().clone(),
            base.document_digest().clone(),
            base.resources().to_vec(),
            base.response_digest().clone(),
            large,
        ),
        Err(PreparedRecordError::LimitExceeded {
            field: "transform diagnostic text bytes",
            ..
        })
    ));
    assert!(matches!(
        TransformDiagnosticV1::new(
            TransformDiagnosticSeverityV1::Warning,
            "host.path",
            "must reject host path",
            Some(TransformDiagnosticLocationV1::Source {
                authority_label: ContributionName::new("root").unwrap(),
                authority_identity: Digest::sha256(b"root"),
                document_path: "/tmp/host/malm.kdl".to_owned(),
                source_byte_len: 1,
                start: 0,
                end: 1,
            }),
            vec![],
        ),
        Err(PreparedRecordError::InvalidField {
            field: "relative path",
            ..
        })
    ));

    let record = PreparedRecordV1::try_from(PreparedRecordPartsV1 {
        namespace: NamespaceName::new("malformed-diagnostic").unwrap(),
        expected_head: None,
        graph_digest: Digest::sha256(b"malformed graph"),
        inputs: vec![],
        artifacts: vec![],
        transforms: vec![base],
        findings: vec![],
        operations: vec![],
        desired_snapshot: DesiredSnapshotV1::empty(),
    })
    .unwrap();
    let malformed = String::from_utf8(encode_prepared_record_v1(&record))
        .unwrap()
        .replace("\"start\":12,\"end\":24", "\"start\":25,\"end\":24")
        .into_bytes();
    let malformed_id = PreparedId::from_digest(&Digest::sha256(&malformed));
    assert!(matches!(
        decode_prepared_record_v1(&malformed_id, &malformed),
        Err(PreparedRecordError::InvalidField {
            field: "transform diagnostic source range",
            ..
        })
    ));

    let encoded = encode_prepared_record_v1(&record);
    let error_severity = String::from_utf8(encoded.clone())
        .unwrap()
        .replace("\"severity\":\"warning\"", "\"severity\":\"error\"")
        .into_bytes();
    let error_id = PreparedId::from_digest(&Digest::sha256(&error_severity));
    assert!(matches!(
        decode_prepared_record_v1(&error_id, &error_severity),
        Err(PreparedRecordError::InvalidField {
            field: "transform diagnostic severity",
            ..
        })
    ));

    let original_diagnostics = serde_json::to_string(record.transforms()[0].diagnostics()).unwrap();
    let mut duplicate_diagnostics = record.transforms()[0].diagnostics().to_vec();
    duplicate_diagnostics.push(duplicate_diagnostics[0].clone());
    let duplicate_diagnostics = serde_json::to_string(&duplicate_diagnostics).unwrap();
    let duplicate_bytes = String::from_utf8(encoded)
        .unwrap()
        .replace(
            &format!("\"diagnostics\":{original_diagnostics}"),
            &format!("\"diagnostics\":{duplicate_diagnostics}"),
        )
        .into_bytes();
    let duplicate_id = PreparedId::from_digest(&Digest::sha256(&duplicate_bytes));
    assert!(matches!(
        decode_prepared_record_v1(&duplicate_id, &duplicate_bytes),
        Err(PreparedRecordError::InvalidField {
            field: "transform diagnostics",
            ..
        })
    ));
}

#[test]
fn prepared_fixtures_reject_malformed_unknown_and_noncanonical_records() {
    let expected = PreparedId::from_digest(&Digest::sha256(b"fixture expectation"));
    for bytes in [
        include_bytes!(
            "../../../schemas/store/v1/fixtures/malformed/prepared-record-missing-field.json"
        ) as &[u8],
        include_bytes!(
            "../../../schemas/store/v1/fixtures/malformed/prepared-record-unknown-field.json"
        ),
        include_bytes!(
            "../../../schemas/store/v1/fixtures/malformed/prepared-record-invalid-lifecycle.json"
        ),
        include_bytes!(
            "../../../schemas/store/v1/fixtures/malformed/prepared-record-invalid-transition.json"
        ),
        include_bytes!(
            "../../../schemas/store/v1/fixtures/malformed/prepared-record-invalid-tracked-root.json"
        ),
        include_bytes!(
            "../../../schemas/store/v1/fixtures/malformed/prepared-record-legacy-intended-digest.json"
        ),
    ] {
        assert!(matches!(
            decode_prepared_record_v1(&expected, bytes),
            Err(PreparedRecordError::InvalidJson(_))
        ));
    }
    assert_eq!(
        decode_prepared_record_v1(
            &expected,
            include_bytes!(
                "../../../schemas/store/v1/fixtures/malformed/prepared-record-noncanonical.json"
            )
        ),
        Err(PreparedRecordError::NonCanonical)
    );

    let unsorted = include_bytes!(
        "../../../schemas/store/v1/fixtures/malformed/prepared-record-unsorted-grants.json"
    );
    let unsorted_id = PreparedId::from_digest(&Digest::sha256(unsorted));
    assert_eq!(
        decode_prepared_record_v1(&unsorted_id, unsorted),
        Err(PreparedRecordError::NonCanonical)
    );

    let corrupt = include_bytes!(
        "../../../schemas/store/v1/fixtures/malformed/prepared-record-desired-digest-mismatch.json"
    );
    let corrupt_id = PreparedId::from_digest(&Digest::sha256(corrupt));
    assert!(matches!(
        decode_prepared_record_v1(&corrupt_id, corrupt),
        Err(PreparedRecordError::InvalidDesiredSnapshot(_))
    ));

    let invalid_retention = include_bytes!(
        "../../../schemas/store/v1/fixtures/malformed/prepared-record-invalid-retention.json"
    );
    let invalid_retention_id = PreparedId::from_digest(&Digest::sha256(invalid_retention));
    assert!(matches!(
        decode_prepared_record_v1(&invalid_retention_id, invalid_retention),
        Err(PreparedRecordError::InvalidField {
            field: "history retention generations",
            ..
        })
    ));
}

#[test]
fn state_generation_fixtures_reject_malformed_unknown_and_noncanonical_records() {
    let expected = Digest::sha256(b"fixture expectation");
    for bytes in [
        include_bytes!(
            "../../../schemas/store/v1/fixtures/malformed/state-generation-missing-field.json"
        ) as &[u8],
        include_bytes!(
            "../../../schemas/store/v1/fixtures/malformed/state-generation-unknown-field.json"
        ),
        include_bytes!(
            "../../../schemas/store/v1/fixtures/malformed/state-generation-invalid-lifecycle.json"
        ),
        include_bytes!(
            "../../../schemas/store/v1/fixtures/malformed/state-generation-invalid-transition.json"
        ),
        include_bytes!(
            "../../../schemas/store/v1/fixtures/malformed/state-generation-invalid-tracked-root.json"
        ),
        include_bytes!(
            "../../../schemas/store/v1/fixtures/malformed/state-generation-legacy-derived-targets.json"
        ),
    ] {
        assert!(matches!(
            decode_state_generation_v1(&expected, bytes),
            Err(StateRecordError::InvalidJson(_))
        ));
    }
    assert_eq!(
        decode_state_generation_v1(
            &expected,
            include_bytes!(
                "../../../schemas/store/v1/fixtures/malformed/state-generation-noncanonical.json"
            )
        ),
        Err(StateRecordError::NonCanonical)
    );

    let corrupt = include_bytes!(
        "../../../schemas/store/v1/fixtures/malformed/state-generation-desired-digest-mismatch.json"
    );
    let corrupt_id = Digest::sha256(corrupt);
    assert!(matches!(
        decode_state_generation_v1(&corrupt_id, corrupt),
        Err(StateRecordError::InvalidState(_))
    ));

    let invalid_retention = include_bytes!(
        "../../../schemas/store/v1/fixtures/malformed/state-generation-invalid-retention.json"
    );
    let invalid_retention_id = Digest::sha256(invalid_retention);
    assert!(matches!(
        decode_state_generation_v1(&invalid_retention_id, invalid_retention),
        Err(StateRecordError::InvalidState(_))
    ));
}

#[test]
fn state_catalog_fixtures_reject_malformed_and_noncanonical_records() {
    for bytes in [
        include_bytes!(
            "../../../schemas/store/v1/fixtures/malformed/state-catalog-missing-field.json"
        ) as &[u8],
        include_bytes!(
            "../../../schemas/store/v1/fixtures/malformed/state-catalog-unknown-field.json"
        ),
        include_bytes!(
            "../../../schemas/store/v1/fixtures/malformed/state-catalog-invalid-namespace.json"
        ),
        include_bytes!(
            "../../../schemas/store/v1/fixtures/malformed/state-catalog-invalid-generation.json"
        ),
    ] {
        assert!(matches!(
            decode_state_catalog_v1(bytes),
            Err(StateCatalogError::InvalidJson(_))
        ));
    }
    assert_eq!(
        decode_state_catalog_v1(include_bytes!(
            "../../../schemas/store/v1/fixtures/malformed/state-catalog-noncanonical.json"
        )),
        Err(StateCatalogError::NonCanonical)
    );
    assert_eq!(
        decode_state_catalog_v1(include_bytes!(
            "../../../schemas/store/v1/fixtures/malformed/state-catalog-unsorted.json"
        )),
        Err(StateCatalogError::HeadsNotSorted)
    );
    assert_eq!(
        decode_state_catalog_v1(include_bytes!(
            "../../../schemas/store/v1/fixtures/malformed/state-catalog-duplicate-namespace.json"
        )),
        Err(StateCatalogError::DuplicateNamespace(
            NamespaceName::new("minimal").unwrap()
        ))
    );
}

#[test]
fn every_public_record_codec_rejects_version_2() {
    let expected_prepared = PreparedId::from_digest(&Digest::sha256(b"fixture expectation"));
    assert_eq!(
        decode_prepared_record_v1(
            &expected_prepared,
            include_bytes!(
                "../../../schemas/store/v1/fixtures/unsupported/prepared-record-version-2.json"
            )
        ),
        Err(PreparedRecordError::UnsupportedVersion {
            expected: 1,
            found: 2,
        })
    );

    let expected_generation = Digest::sha256(b"fixture expectation");
    assert_eq!(
        decode_state_generation_v1(
            &expected_generation,
            include_bytes!(
                "../../../schemas/store/v1/fixtures/unsupported/state-generation-version-2.json"
            )
        ),
        Err(StateRecordError::UnsupportedVersion {
            expected: 1,
            found: 2,
        })
    );
    assert_eq!(
        decode_state_catalog_v1(include_bytes!(
            "../../../schemas/store/v1/fixtures/unsupported/state-catalog-version-2.json"
        )),
        Err(StateCatalogError::UnsupportedVersion {
            expected: 1,
            found: 2,
        })
    );

    let tracked_prepared = include_bytes!(
        "../../../schemas/store/v1/fixtures/unsupported/prepared-record-tracked-root-version-2.json"
    );
    let tracked_prepared_id = PreparedId::from_digest(&Digest::sha256(tracked_prepared));
    assert_eq!(
        decode_prepared_record_v1(&tracked_prepared_id, tracked_prepared),
        Err(PreparedRecordError::UnsupportedVersion {
            expected: 1,
            found: 2,
        })
    );

    let tracked_generation = include_bytes!(
        "../../../schemas/store/v1/fixtures/unsupported/state-generation-tracked-root-version-2.json"
    );
    let tracked_generation_id = Digest::sha256(tracked_generation);
    assert_eq!(
        decode_state_generation_v1(&tracked_generation_id, tracked_generation),
        Err(StateRecordError::UnsupportedVersion {
            expected: 1,
            found: 2,
        })
    );
}

#[test]
fn golden_identity_mismatches_fail_closed() {
    let wrong_prepared = PreparedId::from_digest(&Digest::sha256(b"wrong prepared identity"));
    assert!(matches!(
        decode_prepared_record_v1(&wrong_prepared, GOLDEN_PREPARED),
        Err(PreparedRecordError::DigestMismatch { .. })
    ));

    let wrong_generation = Digest::sha256(b"wrong generation identity");
    assert!(matches!(
        decode_state_generation_v1(&wrong_generation, GOLDEN_GENERATION),
        Err(StateRecordError::DigestMismatch { .. })
    ));
}

#[test]
fn missing_ancestor_observations_round_trip_and_default_to_zero() {
    // A record without the field decodes to zero. An observation with no
    // missing ancestors omits it, preserving pre-feature wire bytes and plan
    // identities; the golden fixture pins that compatibility contract.
    let plain = TargetObservationV1::new(
        DeploymentName::new("home").unwrap(),
        ".config/malm/app.toml",
        directory_identity(10),
        vec![directory_identity(11)],
        directory_identity(12),
        LeafObservationV1::Absent,
    )
    .unwrap();
    assert_eq!(plain.missing_ancestors(), 0);
    let encoded = serde_json::to_vec(&plain).unwrap();
    assert!(
        !String::from_utf8(encoded.clone())
            .unwrap()
            .contains("missing_ancestors"),
        "feature-free observations omit the field entirely"
    );
    let decoded: TargetObservationV1 = serde_json::from_slice(&encoded).unwrap();
    assert_eq!(decoded, plain);

    // Two trailing parents are missing. Only `.config` exists, so it is the
    // observation parent and no intermediate ancestor identities are valid.
    let pending = TargetObservationV1::with_missing_ancestors(
        DeploymentName::new("home").unwrap(),
        ".config/ghostty/themes/dark.conf",
        directory_identity(10),
        vec![],
        directory_identity(12),
        LeafObservationV1::Absent,
        2,
    )
    .unwrap();
    assert_eq!(pending.missing_ancestors(), 2);
    let decoded: TargetObservationV1 =
        serde_json::from_slice(&serde_json::to_vec(&pending).unwrap()).unwrap();
    assert_eq!(decoded, pending);

    // A present leaf cannot exist below a missing ancestor.
    assert!(
        TargetObservationV1::with_missing_ancestors(
            DeploymentName::new("home").unwrap(),
            ".config/ghostty/config",
            directory_identity(10),
            vec![],
            directory_identity(11),
            LeafObservationV1::Present(directory_identity(12)),
            1,
        )
        .is_err()
    );
    // The missing count cannot exceed the target's parent depth.
    assert!(
        TargetObservationV1::with_missing_ancestors(
            DeploymentName::new("home").unwrap(),
            ".config/ghostty/config",
            directory_identity(10),
            vec![],
            directory_identity(11),
            LeafObservationV1::Absent,
            3,
        )
        .is_err()
    );
    // Existing ancestor identities must shrink as the missing suffix grows.
    assert!(
        TargetObservationV1::with_missing_ancestors(
            DeploymentName::new("home").unwrap(),
            ".config/ghostty/themes/dark.conf",
            directory_identity(10),
            vec![directory_identity(11), directory_identity(12)],
            directory_identity(13),
            LeafObservationV1::Absent,
            2,
        )
        .is_err()
    );
}
