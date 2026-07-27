use std::fmt::Write;

use malm_machine::{
    DiagnosticSeverityV1, MAX_MACHINE_ARRAY_ITEMS, MAX_MACHINE_DIAGNOSTICS,
    MAX_MACHINE_FRAME_BYTES, MAX_MACHINE_JSON_DEPTH, MAX_MACHINE_OBJECT_MEMBERS,
    MAX_MACHINE_SEQUENCE, MAX_MACHINE_TEXT_BYTES, MAX_REQUEST_ID_BYTES, MachineCodeV1,
    MachineDiagnosticV1, MachineErrorCategoryV1, MachineErrorCodeV1, MachineErrorDetailsV1,
    MachineErrorV1, MachineOperationV1, MachineReadError, MachineRequestV1, MachineResultV1,
    MachineStreamError, MachineTextV1, MachineValidationError, MachineWriteError,
    RequestEnvelopeV1, RequestIdV1, ResponseStreamValidatorV1, SchemaFamilyV1, ServerFrameV1,
    decode_request_v1, decode_server_frame_v1, encode_request_v1, encode_server_frame_v1,
    request_error_frame_v1,
};
use malm_types::{
    ApplyOutcomeV1, ApprovalV1, ArchiveProvenanceV1, ArtifactDescriptorV1, ArtifactId,
    ArtifactMetadataInspectionRequestV1, ArtifactMetadataInspectionV1, ArtifactV1,
    CanonicalTreeInspectionRequestV1, CanonicalTreeInspectionV1, CapturedInputsInspectionV1,
    CatalogInspectionRequestV1, CatalogInspectionV1, CatalogNamespaceInspectionV1,
    CheckoutRequestV1, CommitRequestV1, ContributionName, DeploymentName,
    DesiredSnapshotInspectionRequestV1, DesiredSnapshotInspectionV1, Digest,
    DirectorySafetyReasonV1, FsckFindingCodeV1, FsckFindingV1, FsckReportPartsV1, FsckReportV1,
    FsckRequestV1, FsckSeverityV1, FsckSubjectV1, GenerationInspectionPartsV1,
    GenerationInspectionRequestV1, GenerationInspectionV1, HistoryRetentionRequestV1,
    LifecycleRequestV1, LifecycleStateViewV1, LifecycleTransitionViewV1, NamespaceHistoryRequestV1,
    NamespaceHistoryV1, NamespaceInspectionRequestV1, NamespaceInspectionV1, NamespaceName,
    NamespaceRemovalHistoryV1, NamespaceRemovalRequestV1, NamespaceStatusKindV1,
    NamespaceStatusPartsV1, NamespaceStatusRequestV1, NamespaceStatusV1, PackNodeId,
    PolicyFindingV1, PrepareArtifactV1, PrepareInputKindV1, PrepareInputV1, PrepareOperationV1,
    PreparePolicyFindingV1, PrepareRequestPartsV1, PrepareRequestV1, PrepareTargetStateV1,
    PrepareTransformDiagnosticLocationV1, PrepareTransformDiagnosticSeverityV1,
    PrepareTransformDiagnosticV1, PrepareTransformImplementationV1,
    PrepareTransformOutputLocationV1, PrepareTransformProvenanceV1, PrepareTransformResourceV1,
    PrepareTransformSourceLocationV1, PreparedDeploymentPartsV1, PreparedDeploymentV1, PreparedId,
    PreparedPlanInspectionRequestV1, PreparedTrackingAcquisitionGrantV1,
    PreparedTrackingAcquisitionKindV1, PreparedTrackingReviewPartsV1, PreparedTrackingReviewV1,
    PruneOutcomeV1, PruneRequestV1, RecoveryOutcomeV1, RestorePointRequestV1,
    RetentionAuthorityInspectionV1, RetentionInspectionV1, RetentionObjectV1,
    RetentionPinRequestV1, StateViewV1, StoreDirectoryV1, StoreErrorV1, StoreMetadataReasonV1,
    StoreRootV1, StoreStatusV1, TrackingInspectionV1, TransformProvenanceInspectionV1,
    policy_approval_digest_v1, policy_finding_id_v1,
};

const VALID_REQUEST_STATUS: &[u8] =
    include_bytes!("../../../schemas/machine/v1/fixtures/valid/request-status.jsonl");
const VALID_REQUEST_INITIALIZE: &[u8] =
    include_bytes!("../../../schemas/machine/v1/fixtures/valid/request-initialize.jsonl");
const VALID_SERVER_STARTED: &[u8] =
    include_bytes!("../../../schemas/machine/v1/fixtures/valid/server-started.jsonl");
const VALID_SERVER_RESULT: &[u8] =
    include_bytes!("../../../schemas/machine/v1/fixtures/valid/server-result.jsonl");
const VALID_SERVER_ERROR: &[u8] =
    include_bytes!("../../../schemas/machine/v1/fixtures/valid/server-error.jsonl");
const GOLDEN_REQUEST_PLAN: &[u8] =
    include_bytes!("../../../schemas/machine/v1/fixtures/golden/request-plan.jsonl");
const GOLDEN_SERVER_STATE: &[u8] =
    include_bytes!("../../../schemas/machine/v1/fixtures/golden/server-state-result.jsonl");
const GOLDEN_CANONICAL_REQUEST: &[u8] = include_bytes!(
    "../../../schemas/machine/v1/fixtures/golden/request-canonical-operations.jsonl"
);
const GOLDEN_CANONICAL_RESULT: &[u8] =
    include_bytes!("../../../schemas/machine/v1/fixtures/golden/server-prepared-canonical.jsonl");

fn request_id(value: &str) -> RequestIdV1 {
    RequestIdV1::new(value).unwrap()
}

fn text(value: &str) -> MachineTextV1 {
    MachineTextV1::new(value).unwrap()
}

fn read_only_error() -> MachineErrorV1 {
    MachineErrorV1::from_store(StoreErrorV1::read_only_store())
}

#[test]
fn valid_fixtures_decode_to_stable_semantic_dtos() {
    let status = decode_request_v1(VALID_REQUEST_STATUS).unwrap();
    assert_eq!(status.request_id().as_str(), "req-1");
    assert_eq!(
        status.request().operation(),
        MachineOperationV1::StoreStatus
    );

    let initialize = decode_request_v1(VALID_REQUEST_INITIALIZE).unwrap();
    assert_eq!(initialize.request_id().as_str(), "req-2");
    assert_eq!(
        initialize.request().operation(),
        MachineOperationV1::InitializeStore
    );

    assert!(matches!(
        decode_server_frame_v1(VALID_SERVER_STARTED).unwrap(),
        ServerFrameV1::Started {
            operation: MachineOperationV1::StoreStatus,
            ..
        }
    ));
    assert!(matches!(
        decode_server_frame_v1(VALID_SERVER_RESULT).unwrap(),
        ServerFrameV1::Result {
            sequence: 1,
            result,
            ..
        } if result == MachineResultV1::StoreStatus(StoreStatusV1::Absent)
    ));
    assert!(matches!(
        decode_server_frame_v1(VALID_SERVER_ERROR).unwrap(),
        ServerFrameV1::Error {
            sequence: 1,
            error,
            ..
        } if error.code() == MachineErrorCodeV1::ReadOnlyStore
    ));
}

#[test]
fn canonical_writers_match_exact_golden_records() {
    let request = RequestEnvelopeV1::new(request_id("req-1"), MachineRequestV1::StoreStatus);
    assert_eq!(
        encode_request_v1(&request).unwrap(),
        include_bytes!("../../../schemas/machine/v1/fixtures/golden/request-status.jsonl")
    );

    let started = ServerFrameV1::started(request_id("req-1"), MachineOperationV1::StoreStatus);
    assert_eq!(
        encode_server_frame_v1(&started).unwrap(),
        include_bytes!("../../../schemas/machine/v1/fixtures/golden/server-started.jsonl")
    );

    let result = ServerFrameV1::result(
        request_id("req-1"),
        1,
        MachineResultV1::StoreStatus(StoreStatusV1::Absent),
    )
    .unwrap();
    assert_eq!(
        encode_server_frame_v1(&result).unwrap(),
        include_bytes!("../../../schemas/machine/v1/fixtures/golden/server-result.jsonl")
    );

    let error = ServerFrameV1::error(Some(request_id("req-2")), 1, read_only_error()).unwrap();
    assert_eq!(
        encode_server_frame_v1(&error).unwrap(),
        include_bytes!("../../../schemas/machine/v1/fixtures/golden/server-error.jsonl")
    );

    let plan = RequestEnvelopeV1::new(
        request_id("plan-1"),
        MachineRequestV1::Plan(PreparedId::new(format!("pp-{}", "0".repeat(64))).unwrap()),
    );
    assert_eq!(encode_request_v1(&plan).unwrap(), GOLDEN_REQUEST_PLAN);
    let state = ServerFrameV1::result(
        request_id("state-1"),
        1,
        MachineResultV1::State(StateViewV1::new(
            NamespaceName::new("default").unwrap(),
            None,
        )),
    )
    .unwrap();
    assert_eq!(encode_server_frame_v1(&state).unwrap(), GOLDEN_SERVER_STATE);

    let canonical_request = decode_request_v1(GOLDEN_CANONICAL_REQUEST).unwrap();
    assert_eq!(
        encode_request_v1(&canonical_request).unwrap(),
        GOLDEN_CANONICAL_REQUEST
    );
    let MachineRequestV1::Prepare(canonical_prepare) = canonical_request.request() else {
        panic!("canonical request fixture must contain prepare");
    };
    assert!(matches!(
        canonical_prepare.operations(),
        [
            PrepareOperationV1::PlaceSymlink { .. },
            PrepareOperationV1::PlaceTree { .. },
            PrepareOperationV1::AssertExact { .. }
        ]
    ));

    let canonical_result = decode_server_frame_v1(GOLDEN_CANONICAL_RESULT).unwrap();
    assert_eq!(
        encode_server_frame_v1(&canonical_result).unwrap(),
        GOLDEN_CANONICAL_RESULT
    );
    let ServerFrameV1::Result {
        result: MachineResultV1::Prepare(canonical_deployment),
        ..
    } = canonical_result
    else {
        panic!("canonical result fixture must contain a prepared deployment");
    };
    assert_eq!(
        canonical_deployment.lifecycle_state(),
        LifecycleStateViewV1::Disabled
    );
    assert_eq!(
        canonical_deployment
            .tracked_root()
            .expect("fixture carries tracking")
            .moving_selector(),
        "refs/heads/main"
    );
    assert_eq!(canonical_deployment.transforms().len(), 1);
    assert_eq!(canonical_deployment.transforms()[0].diagnostics().len(), 2);
    assert_eq!(
        canonical_deployment.transforms()[0].diagnostics()[0].code(),
        "component.warning"
    );
}

#[test]
fn every_deployment_request_and_result_round_trips_through_strict_records() {
    let artifact_id = ArtifactId::new("config/machine").unwrap();
    let artifact_bytes = b"machine bytes\n".to_vec();
    let artifact_digest = Digest::sha256(&artifact_bytes);
    let plan_id = PreparedId::from_digest(&Digest::sha256(b"machine plan"));
    let generation = Digest::sha256(b"machine generation");
    let namespace = NamespaceName::new("workstation").unwrap();
    let operation = PrepareOperationV1::place_file(
        DeploymentName::new("home").unwrap(),
        "config/machine.conf",
        artifact_id.clone(),
        0o600,
    )
    .unwrap();
    let archive_provenance =
        ArchiveProvenanceV1::new(Digest::sha256(b"machine archive"), "tar-v1").unwrap();
    let operations = vec![
        PrepareOperationV1::ensure_directory(
            DeploymentName::new("home").unwrap(),
            "config/directory",
            0o700,
        )
        .unwrap(),
        PrepareOperationV1::replace_directory(
            DeploymentName::new("home").unwrap(),
            "config/replaced-directory",
            0o750,
        )
        .unwrap(),
        operation.clone(),
        PrepareOperationV1::replace_symlink(
            DeploymentName::new("home").unwrap(),
            "config/link",
            Digest::sha256(b"machine symlink"),
        )
        .unwrap(),
        PrepareOperationV1::place_archive_tree(
            DeploymentName::new("home").unwrap(),
            "config/tree",
            Digest::sha256(b"machine tree"),
            archive_provenance.clone(),
        )
        .unwrap(),
        PrepareOperationV1::assert_exact(
            DeploymentName::new("home").unwrap(),
            "config/exact-file",
            PrepareTargetStateV1::file(Digest::sha256(b"exact file"), 10, 0o600).unwrap(),
        )
        .unwrap(),
        PrepareOperationV1::assert_exact(
            DeploymentName::new("home").unwrap(),
            "config/exact-directory",
            PrepareTargetStateV1::directory(0o700).unwrap(),
        )
        .unwrap(),
        PrepareOperationV1::assert_exact(
            DeploymentName::new("home").unwrap(),
            "config/exact-link",
            PrepareTargetStateV1::symlink(Digest::sha256(b"exact symlink")),
        )
        .unwrap(),
        PrepareOperationV1::assert_exact(
            DeploymentName::new("home").unwrap(),
            "config/exact-tree",
            PrepareTargetStateV1::archive_tree(Digest::sha256(b"exact tree"), archive_provenance),
        )
        .unwrap(),
    ];
    let prepare = PrepareRequestV1::from(PrepareRequestPartsV1 {
        namespace: namespace.clone(),
        expected_head: None,
        graph_digest: Digest::sha256(b"machine graph"),
        inputs: vec![
            PrepareInputV1::new(
                PrepareInputKindV1::Config,
                "machine-input",
                Digest::sha256(b"input"),
            )
            .unwrap(),
        ],
        artifacts: vec![
            PrepareArtifactV1::new(artifact_id.clone(), artifact_bytes.clone(), "text/plain")
                .unwrap(),
        ],
        transforms: vec![],
        findings: vec![PreparePolicyFindingV1::new("review", "review machine plan", true).unwrap()],
        operations: operations.clone(),
    });
    let requests = vec![
        MachineRequestV1::StoreStatus,
        MachineRequestV1::InitializeStore,
        MachineRequestV1::Prepare(prepare),
        MachineRequestV1::Plan(plan_id.clone()),
        MachineRequestV1::Artifact {
            plan_id: plan_id.clone(),
            artifact_id: artifact_id.clone(),
        },
        MachineRequestV1::Commit(CommitRequestV1::new(
            plan_id.clone(),
            ApprovalV1::new(plan_id.clone(), Digest::sha256(b"approval")),
        )),
        MachineRequestV1::State(namespace.clone()),
        MachineRequestV1::Recover,
        MachineRequestV1::Prune(PruneRequestV1::new(vec![plan_id.clone()])),
        MachineRequestV1::Checkout(CheckoutRequestV1::new(
            namespace.clone(),
            generation.clone(),
        )),
    ];
    let request_schema: serde_json::Value = serde_json::from_str(include_str!(
        "../../../schemas/machine/v1/request.schema.json"
    ))
    .unwrap();
    let request_validator = jsonschema::validator_for(&request_schema).unwrap();
    for (index, request) in requests.into_iter().enumerate() {
        let envelope = RequestEnvelopeV1::new(request_id(&format!("request-{index}")), request);
        let encoded = encode_request_v1(&envelope).unwrap();
        assert_eq!(decode_request_v1(&encoded).unwrap(), envelope);
        let value: serde_json::Value =
            serde_json::from_slice(encoded.strip_suffix(b"\n").unwrap()).unwrap();
        assert!(request_validator.is_valid(&value));
    }

    let descriptor = ArtifactDescriptorV1::new(
        artifact_id,
        artifact_digest,
        u64::try_from(artifact_bytes.len()).unwrap(),
        "text/plain".to_owned(),
    );
    let finding_id = policy_finding_id_v1("review", "review machine plan", true);
    let approval_digest = policy_approval_digest_v1([(finding_id.clone(), true)]);
    let deployment = PreparedDeploymentV1::from(PreparedDeploymentPartsV1 {
        plan_id: plan_id.clone(),
        namespace: namespace.clone(),
        expected_head: None,
        graph_digest: Digest::sha256(b"machine graph"),
        inputs: vec![
            PrepareInputV1::new(
                PrepareInputKindV1::Source,
                "reviewed-source",
                Digest::sha256(b"source"),
            )
            .unwrap(),
        ],
        transforms: vec![
            PrepareTransformProvenanceV1::new(
                "settings",
                PrepareTransformImplementationV1::component(
                    PackNodeId::new(Digest::sha256(b"node")),
                    Digest::sha256(b"pack"),
                    "components/formatter.wasm",
                    Digest::sha256(b"component"),
                    "format-component/v1",
                    Digest::sha256(b"profile"),
                )
                .unwrap(),
                Digest::sha256(b"request"),
                Digest::sha256(b"document"),
                vec![
                    PrepareTransformResourceV1::new("theme", Digest::sha256(b"resource")).unwrap(),
                ],
                Digest::sha256(b"response"),
                vec![
                    PrepareTransformDiagnosticV1::new(
                        PrepareTransformDiagnosticSeverityV1::Warning,
                        "component.warning",
                        "review the component output",
                        Some(PrepareTransformDiagnosticLocationV1::Source(
                            PrepareTransformSourceLocationV1::new(
                                ContributionName::new("root").unwrap(),
                                Digest::sha256(b"root pack"),
                                "malm.kdl",
                                64,
                                12,
                                24,
                            )
                            .unwrap(),
                        )),
                        vec!["first note".to_owned(), "second note".to_owned()],
                    )
                    .unwrap(),
                    PrepareTransformDiagnosticV1::new(
                        PrepareTransformDiagnosticSeverityV1::Info,
                        "component.info",
                        "generated output detail",
                        Some(PrepareTransformDiagnosticLocationV1::Output(
                            PrepareTransformOutputLocationV1::new(2, 8).unwrap(),
                        )),
                        vec![],
                    )
                    .unwrap(),
                ],
            )
            .unwrap(),
        ],
        artifacts: vec![descriptor.clone()],
        findings: vec![PolicyFindingV1::new(
            finding_id.clone(),
            "review".to_owned(),
            "review machine plan".to_owned(),
            true,
        )],
        approval_digest: approval_digest.clone(),
        operations,
    })
    .with_lifecycle_state(LifecycleStateViewV1::Disabled)
    .with_tracking_review(Some(
        PreparedTrackingReviewV1::try_from(PreparedTrackingReviewPartsV1 {
            source_locator: "https://example.invalid/root.git".to_owned(),
            moving_selector: "refs/heads/main".to_owned(),
            applied_revision: format!("sha1-{}", "1".repeat(40)),
            root_tree_digest: Digest::sha256(b"tracked root tree"),
            source_subdir: "packs/root".to_owned(),
            config_entry_point: "malm.kdl".to_owned(),
            selected_profile: ContributionName::new("desktop").unwrap(),
            target_authority: DeploymentName::new("home").unwrap(),
            acquisition_grants: vec![
                PreparedTrackingAcquisitionGrantV1::new(
                    PreparedTrackingAcquisitionKindV1::GitSource,
                    "https://example.invalid/dependency.git",
                )
                .unwrap(),
                PreparedTrackingAcquisitionGrantV1::new(
                    PreparedTrackingAcquisitionKindV1::LocalSource,
                    "../shared-pack",
                )
                .unwrap(),
            ],
            component_grants: vec![Digest::sha256(b"granted component")],
        })
        .unwrap(),
    ));
    let integrity_frame = ServerFrameV1::result(
        request_id("result-integrity"),
        1,
        MachineResultV1::Prepare(deployment.clone()),
    )
    .unwrap();
    let integrity_json =
        String::from_utf8(encode_server_frame_v1(&integrity_frame).unwrap()).unwrap();
    let forged_finding = integrity_json.replace(
        finding_id.as_str(),
        Digest::sha256(b"forged finding").as_str(),
    );
    assert!(matches!(
        decode_server_frame_v1(forged_finding.as_bytes()),
        Err(MachineReadError::InvalidEnvelope(_))
    ));
    let forged_approval = integrity_json.replace(
        approval_digest.as_str(),
        Digest::sha256(b"forged approval").as_str(),
    );
    assert!(matches!(
        decode_server_frame_v1(forged_approval.as_bytes()),
        Err(MachineReadError::InvalidEnvelope(_))
    ));
    let invalid_range =
        integrity_json.replace("\"start\":12,\"end\":24", "\"start\":25,\"end\":24");
    assert!(decode_server_frame_v1(invalid_range.as_bytes()).is_err());
    let out_of_bounds_source =
        integrity_json.replace("\"source_byte_len\":64", "\"source_byte_len\":23");
    assert!(decode_server_frame_v1(out_of_bounds_source.as_bytes()).is_err());
    let error_on_success =
        integrity_json.replacen("\"severity\":\"warning\"", "\"severity\":\"error\"", 1);
    assert!(decode_server_frame_v1(error_on_success.as_bytes()).is_err());
    let unknown_diagnostic = integrity_json.replacen(
        "\"notes\":[\"first note\",\"second note\"]",
        "\"unknown\":true,\"notes\":[\"first note\",\"second note\"]",
        1,
    );
    assert!(decode_server_frame_v1(unknown_diagnostic.as_bytes()).is_err());
    let mut over_limit: serde_json::Value = serde_json::from_str(&integrity_json).unwrap();
    let diagnostic = over_limit["result"]["deployment"]["transforms"][0]["diagnostics"][0].clone();
    over_limit["result"]["deployment"]["transforms"][0]["diagnostics"] =
        serde_json::Value::Array(vec![
            diagnostic;
            malm_types::MAX_TRANSFORM_DIAGNOSTICS_V1 + 1
        ]);
    let mut over_limit = serde_json::to_vec(&over_limit).unwrap();
    over_limit.push(b'\n');
    assert!(decode_server_frame_v1(&over_limit).is_err());
    let results = vec![
        MachineResultV1::StoreStatus(StoreStatusV1::Ready),
        MachineResultV1::InitializeStore,
        MachineResultV1::Prepare(deployment.clone()),
        MachineResultV1::Plan(deployment.clone()),
        MachineResultV1::Artifact(ArtifactV1::new(descriptor, artifact_bytes)),
        MachineResultV1::Commit(ApplyOutcomeV1::new(
            plan_id.clone(),
            namespace.clone(),
            None,
            generation.clone(),
        )),
        MachineResultV1::Commit(ApplyOutcomeV1::removed(
            plan_id,
            namespace.clone(),
            generation.clone(),
        )),
        MachineResultV1::State(StateViewV1::new(
            namespace.clone(),
            Some(generation.clone()),
        )),
        MachineResultV1::Recover(RecoveryOutcomeV1::recovered(namespace, Some(generation))),
        MachineResultV1::Prune(PruneOutcomeV1 {
            prepared_records: 1,
            artifact_blobs: 2,
            state_generations: 3,
            pack_objects: 4,
            canonical_files: 5,
            canonical_symlinks: 6,
            canonical_trees: 7,
        }),
        MachineResultV1::Checkout(deployment),
    ];
    let server_schema: serde_json::Value = serde_json::from_str(include_str!(
        "../../../schemas/machine/v1/server.schema.json"
    ))
    .unwrap();
    let server_validator = jsonschema::validator_for(&server_schema).unwrap();
    for (index, result) in results.into_iter().enumerate() {
        let frame =
            ServerFrameV1::result(request_id(&format!("result-{index}")), 1, result).unwrap();
        let encoded = encode_server_frame_v1(&frame).unwrap();
        assert_eq!(decode_server_frame_v1(&encoded).unwrap(), frame);
        let value: serde_json::Value =
            serde_json::from_slice(encoded.strip_suffix(b"\n").unwrap()).unwrap();
        assert!(server_validator.is_valid(&value));
    }
}

#[test]
fn nullable_commit_head_decodes_only_as_a_well_formed_namespace_removal() {
    let outcome = ApplyOutcomeV1::removed(
        PreparedId::from_digest(&Digest::sha256(b"removed plan")),
        NamespaceName::new("removed").unwrap(),
        Digest::sha256(b"previous generation"),
    );
    let frame = ServerFrameV1::result(
        request_id("removed-commit"),
        1,
        MachineResultV1::Commit(outcome.clone()),
    )
    .unwrap();
    let encoded = encode_server_frame_v1(&frame).unwrap();
    assert_eq!(decode_server_frame_v1(&encoded).unwrap(), frame);
    let ServerFrameV1::Result {
        result: MachineResultV1::Commit(decoded),
        ..
    } = decode_server_frame_v1(&encoded).unwrap()
    else {
        panic!("removed commit decoded as another result")
    };
    assert_eq!(decoded, outcome);
    assert!(decoded.next_head().is_none());

    let mut invalid: serde_json::Value =
        serde_json::from_slice(encoded.strip_suffix(b"\n").unwrap()).unwrap();
    invalid["result"]["outcome"]["previous_head"] = serde_json::Value::Null;
    let mut invalid = serde_json::to_vec(&invalid).unwrap();
    invalid.push(b'\n');
    assert!(matches!(
        decode_server_frame_v1(&invalid),
        Err(MachineReadError::InvalidEnvelope(reason))
            if reason.contains("requires a previous head")
    ));
}

#[test]
fn lifecycle_and_inspection_families_round_trip_through_strict_schemas() {
    let namespace = NamespaceName::new("inspection").unwrap();
    let generation_digest = Digest::sha256(b"inspection generation");
    let plan_id = PreparedId::from_digest(&Digest::sha256(b"inspection plan"));
    let artifact_id = ArtifactId::new("inspection/artifact").unwrap();
    let object = RetentionObjectV1::ArtifactBlob {
        digest: Digest::sha256(b"retained blob"),
    };
    let generation_request = GenerationInspectionRequestV1::with_limits(
        namespace.clone(),
        generation_digest.clone(),
        4,
        1024 * 1024,
    )
    .unwrap();
    let plan_request =
        PreparedPlanInspectionRequestV1::with_limits(plan_id.clone(), 4, 1024 * 1024).unwrap();
    let requests = vec![
        MachineRequestV1::Disable(LifecycleRequestV1::new(namespace.clone())),
        MachineRequestV1::Enable(LifecycleRequestV1::new(namespace.clone())),
        MachineRequestV1::RemoveNamespace(NamespaceRemovalRequestV1::new(
            namespace.clone(),
            NamespaceRemovalHistoryV1::Drop,
        )),
        MachineRequestV1::SetHistoryRetention(
            HistoryRetentionRequestV1::new(namespace.clone(), 4).unwrap(),
        ),
        MachineRequestV1::Pin(RetentionPinRequestV1::new(
            namespace.clone(),
            object.clone(),
        )),
        MachineRequestV1::Unpin(RetentionPinRequestV1::new(namespace.clone(), object)),
        MachineRequestV1::AddRestorePoint(RestorePointRequestV1::new(
            namespace.clone(),
            generation_digest.clone(),
        )),
        MachineRequestV1::DropRestorePoint(RestorePointRequestV1::new(
            namespace.clone(),
            generation_digest.clone(),
        )),
        MachineRequestV1::Catalog(CatalogInspectionRequestV1::with_limits(4, 1024 * 1024).unwrap()),
        MachineRequestV1::Namespace(
            NamespaceInspectionRequestV1::with_limit(namespace.clone(), 1024 * 1024).unwrap(),
        ),
        MachineRequestV1::History(
            NamespaceHistoryRequestV1::with_limits(namespace.clone(), 4, 1024 * 1024).unwrap(),
        ),
        MachineRequestV1::Generation(generation_request.clone()),
        MachineRequestV1::DesiredSnapshot(
            DesiredSnapshotInspectionRequestV1::with_limits(
                namespace.clone(),
                generation_digest.clone(),
                4,
                1024 * 1024,
            )
            .unwrap(),
        ),
        MachineRequestV1::CanonicalTree(
            CanonicalTreeInspectionRequestV1::with_limits(Digest::sha256(b"tree"), 4, 1024 * 1024)
                .unwrap(),
        ),
        MachineRequestV1::ArtifactMetadata(
            ArtifactMetadataInspectionRequestV1::with_limit(
                plan_id.clone(),
                artifact_id.clone(),
                1024 * 1024,
            )
            .unwrap(),
        ),
        MachineRequestV1::CapturedInputs(plan_request.clone()),
        MachineRequestV1::TransformProvenance(plan_request.clone()),
        MachineRequestV1::Retention(generation_request.clone()),
        MachineRequestV1::Tracking(generation_request),
        MachineRequestV1::Status(
            NamespaceStatusRequestV1::with_limits(namespace.clone(), 4, 1024 * 1024).unwrap(),
        ),
        MachineRequestV1::Fsck(FsckRequestV1::with_limits(4, 64, 1024 * 1024).unwrap()),
        MachineRequestV1::Fsck(
            FsckRequestV1::with_limits(4, 64, 1024 * 1024)
                .unwrap()
                .with_target_observations(4, 1024 * 1024)
                .unwrap(),
        ),
    ];
    let request_schema: serde_json::Value = serde_json::from_str(include_str!(
        "../../../schemas/machine/v1/request.schema.json"
    ))
    .unwrap();
    let request_validator = jsonschema::validator_for(&request_schema).unwrap();
    for (index, request) in requests.into_iter().enumerate() {
        let envelope = RequestEnvelopeV1::new(request_id(&format!("inspection-{index}")), request);
        let encoded = encode_request_v1(&envelope).unwrap();
        assert_eq!(decode_request_v1(&encoded).unwrap(), envelope);
        let value: serde_json::Value =
            serde_json::from_slice(encoded.strip_suffix(b"\n").unwrap()).unwrap();
        assert!(request_validator.is_valid(&value), "{value}");
    }

    let retention = RetentionAuthorityInspectionV1::new(4, vec![], vec![]);
    let generation = GenerationInspectionV1::from(GenerationInspectionPartsV1 {
        namespace: namespace.clone(),
        generation: generation_digest.clone(),
        lifecycle: LifecycleStateViewV1::Enabled,
        desired_snapshot_digest: Digest::sha256(b"snapshot"),
        target_count: 0,
        present_target_count: 0,
        absent_target_count: 0,
        plan_id: plan_id.clone(),
        predecessor: None,
        tracked_root: None,
    })
    .with_authority(
        LifecycleTransitionViewV1::Reconcile,
        None,
        retention.clone(),
    );
    let deployment = PreparedDeploymentV1::from(PreparedDeploymentPartsV1 {
        plan_id: plan_id.clone(),
        namespace: namespace.clone(),
        expected_head: None,
        graph_digest: Digest::sha256(b"graph"),
        inputs: vec![],
        transforms: vec![],
        artifacts: vec![],
        findings: vec![],
        approval_digest: policy_approval_digest_v1([]),
        operations: vec![],
    })
    .with_retention_authority(retention.clone());
    let descriptor = ArtifactDescriptorV1::new(
        artifact_id,
        Digest::sha256([]),
        0,
        "application/octet-stream".to_owned(),
    );
    let catalog = CatalogInspectionV1::new(
        Digest::sha256(b"catalog"),
        vec![CatalogNamespaceInspectionV1::new(
            namespace.clone(),
            generation_digest.clone(),
        )],
        10,
    );
    let results = vec![
        MachineResultV1::Disable(deployment.clone()),
        MachineResultV1::Enable(deployment.clone()),
        MachineResultV1::RemoveNamespace(deployment.clone()),
        MachineResultV1::SetHistoryRetention(deployment.clone()),
        MachineResultV1::Pin(deployment.clone()),
        MachineResultV1::Unpin(deployment.clone()),
        MachineResultV1::AddRestorePoint(deployment.clone()),
        MachineResultV1::DropRestorePoint(deployment),
        MachineResultV1::Catalog(catalog),
        MachineResultV1::Namespace(NamespaceInspectionV1::new(
            namespace.clone(),
            Some(generation_digest.clone()),
            Some(generation.clone()),
            20,
        )),
        MachineResultV1::History(NamespaceHistoryV1::new(
            namespace.clone(),
            Some(generation_digest.clone()),
            vec![generation.clone()],
            20,
        )),
        MachineResultV1::Generation(generation.clone()),
        MachineResultV1::DesiredSnapshot(DesiredSnapshotInspectionV1::new(
            namespace.clone(),
            generation_digest.clone(),
            Digest::sha256(b"snapshot"),
            vec![],
            10,
        )),
        MachineResultV1::CanonicalTree(CanonicalTreeInspectionV1::new(
            Digest::sha256(b"tree"),
            0o700,
            vec![],
            10,
        )),
        MachineResultV1::ArtifactMetadata(ArtifactMetadataInspectionV1::new(
            plan_id.clone(),
            descriptor,
            10,
        )),
        MachineResultV1::CapturedInputs(CapturedInputsInspectionV1::new(
            plan_id.clone(),
            Digest::sha256(b"graph"),
            vec![],
            10,
        )),
        MachineResultV1::TransformProvenance(TransformProvenanceInspectionV1::new(
            plan_id,
            vec![],
            10,
        )),
        MachineResultV1::Retention(RetentionInspectionV1::new(
            namespace.clone(),
            generation_digest.clone(),
            retention,
        )),
        MachineResultV1::Tracking(TrackingInspectionV1::new(
            namespace.clone(),
            generation_digest,
            None,
        )),
        MachineResultV1::Status(NamespaceStatusV1::from(NamespaceStatusPartsV1 {
            namespace,
            head: None,
            lifecycle: None,
            desired_snapshot_digest: None,
            status: NamespaceStatusKindV1::NotFound,
            targets: vec![],
            observed_bytes: 0,
            detail: None,
        })),
        MachineResultV1::Fsck(FsckReportV1::from(FsckReportPartsV1 {
            findings: vec![FsckFindingV1::new(
                FsckFindingCodeV1::UnreachableImmutableObject,
                FsckSeverityV1::Warning,
                FsckSubjectV1::Coverage,
                "verified leak",
            )],
            checked_generations: 1,
            checked_prepared_plans: 2,
            checked_artifact_blobs: 3,
            checked_pack_objects: 4,
            checked_canonical_files: 5,
            checked_canonical_symlinks: 6,
            checked_canonical_trees: 7,
            checked_targets: 0,
            decoded_bytes: 100,
            observed_bytes: 0,
            findings_truncated: false,
            complete: true,
        })),
    ];
    let server_schema: serde_json::Value = serde_json::from_str(include_str!(
        "../../../schemas/machine/v1/server.schema.json"
    ))
    .unwrap();
    let server_validator = jsonschema::validator_for(&server_schema).unwrap();
    for (index, result) in results.into_iter().enumerate() {
        let frame =
            ServerFrameV1::result(request_id(&format!("inspection-result-{index}")), 1, result)
                .unwrap();
        let encoded = encode_server_frame_v1(&frame).unwrap();
        assert_eq!(decode_server_frame_v1(&encoded).unwrap(), frame);
        let value: serde_json::Value =
            serde_json::from_slice(encoded.strip_suffix(b"\n").unwrap()).unwrap();
        assert!(server_validator.is_valid(&value), "{value}");
    }
}

#[test]
fn every_store_error_shape_and_diagnostic_severity_round_trips() {
    let mut errors = vec![
        StoreErrorV1::read_only_store(),
        StoreErrorV1::store_not_ready(StoreStatusV1::Absent).unwrap(),
        StoreErrorV1::state_parent_missing(),
        StoreErrorV1::state_parent_observation_changed(),
        StoreErrorV1::io(),
        StoreErrorV1::internal(),
        StoreErrorV1::unsupported_store_version(1, 2).unwrap(),
    ];
    for directory in [StoreDirectoryV1::StateParent, StoreDirectoryV1::V1Root] {
        for reason in [
            DirectorySafetyReasonV1::WrongOwner,
            DirectorySafetyReasonV1::GroupOrOtherWritable,
            DirectorySafetyReasonV1::SpecialModeBitsSet,
            DirectorySafetyReasonV1::UnexpectedMode,
            DirectorySafetyReasonV1::AncestryLimitExceeded,
        ] {
            errors.push(StoreErrorV1::unsafe_directory(directory, reason));
        }
    }
    errors.push(StoreErrorV1::root_observation_changed(StoreRootV1::V1));
    for reason in [
        StoreMetadataReasonV1::MarkerMissingWithOtherEntries,
        StoreMetadataReasonV1::MarkerNotRegular,
        StoreMetadataReasonV1::MarkerTooLarge,
        StoreMetadataReasonV1::UnexpectedRootEntry,
        StoreMetadataReasonV1::InvalidRootEntry,
        StoreMetadataReasonV1::WrongOwner,
        StoreMetadataReasonV1::UnexpectedMode,
        StoreMetadataReasonV1::MultipleLinks,
        StoreMetadataReasonV1::ObservationChanged,
        StoreMetadataReasonV1::InvalidDescriptor,
    ] {
        errors.push(StoreErrorV1::malformed_store_metadata(reason));
    }

    for (index, error) in errors.into_iter().enumerate() {
        let frame = ServerFrameV1::error(
            Some(request_id(&format!("error-{index}"))),
            1,
            MachineErrorV1::from_store(error),
        )
        .unwrap();
        let encoded = encode_server_frame_v1(&frame).unwrap();
        assert_eq!(decode_server_frame_v1(&encoded).unwrap(), frame);
    }

    let diagnostics = [
        DiagnosticSeverityV1::Error,
        DiagnosticSeverityV1::Warning,
        DiagnosticSeverityV1::Notice,
    ]
    .into_iter()
    .map(|severity| {
        MachineDiagnosticV1::new(
            severity,
            MachineCodeV1::new("test-diagnostic").unwrap(),
            text("diagnostic text"),
        )
    })
    .collect();
    let error = MachineErrorV1::new(
        MachineErrorCategoryV1::Internal,
        MachineErrorCodeV1::InternalEngineError,
        text("bounded message"),
        MachineErrorDetailsV1::None,
        diagnostics,
    )
    .unwrap();
    let frame = ServerFrameV1::error(Some(request_id("diagnostics")), 1, error).unwrap();
    let encoded = encode_server_frame_v1(&frame).unwrap();
    assert_eq!(decode_server_frame_v1(&encoded).unwrap(), frame);

    for (category, code) in [
        (
            MachineErrorCategoryV1::NotFound,
            MachineErrorCodeV1::PlanNotFound,
        ),
        (
            MachineErrorCategoryV1::NotFound,
            MachineErrorCodeV1::ArtifactNotFound,
        ),
        (
            MachineErrorCategoryV1::Conflict,
            MachineErrorCodeV1::ApprovalMismatch,
        ),
        (
            MachineErrorCategoryV1::Conflict,
            MachineErrorCodeV1::StalePlan,
        ),
        (
            MachineErrorCategoryV1::Conflict,
            MachineErrorCodeV1::RecoveryRequired,
        ),
        (
            MachineErrorCategoryV1::Conflict,
            MachineErrorCodeV1::OperationBusy,
        ),
        (
            MachineErrorCategoryV1::Conflict,
            MachineErrorCodeV1::InvalidDeployment,
        ),
        (
            MachineErrorCategoryV1::Conflict,
            MachineErrorCodeV1::UnsafeTarget,
        ),
        (
            MachineErrorCategoryV1::Conflict,
            MachineErrorCodeV1::CorruptStore,
        ),
        (
            MachineErrorCategoryV1::Conflict,
            MachineErrorCodeV1::CorruptArtifact,
        ),
        (
            MachineErrorCategoryV1::Unavailable,
            MachineErrorCodeV1::DeploymentIo,
        ),
    ] {
        let error = MachineErrorV1::new(
            category,
            code,
            text("deployment error"),
            MachineErrorDetailsV1::None,
            vec![],
        )
        .unwrap();
        let frame = ServerFrameV1::error(Some(request_id(code.as_str())), 1, error).unwrap();
        let encoded = encode_server_frame_v1(&frame).unwrap();
        assert_eq!(decode_server_frame_v1(&encoded).unwrap(), frame);
    }
}

#[test]
fn malformed_and_unsupported_fixtures_fail_closed() {
    assert!(
        decode_request_v1(include_bytes!(
            "../../../schemas/machine/v1/fixtures/malformed/request-unknown-field.jsonl"
        ))
        .is_err()
    );
    assert!(
        decode_request_v1(include_bytes!(
            "../../../schemas/machine/v1/fixtures/malformed/request-nested-unknown-field.jsonl"
        ))
        .is_err()
    );
    assert!(matches!(
        decode_request_v1(include_bytes!(
            "../../../schemas/machine/v1/fixtures/malformed/request-duplicate-key.jsonl"
        )),
        Err(MachineReadError::DuplicateKey)
    ));
    assert!(
        decode_request_v1(include_bytes!(
            "../../../schemas/machine/v1/fixtures/malformed/request-exact-state-unknown-field.jsonl"
        ))
        .is_err()
    );
    assert!(matches!(
        decode_request_v1(include_bytes!(
            "../../../schemas/machine/v1/fixtures/malformed/request-tree-provenance-duplicate-key.jsonl"
        )),
        Err(MachineReadError::DuplicateKey)
    ));
    for (name, fixture) in [
        (
            "missing request ID",
            include_bytes!(
                "../../../schemas/machine/v1/fixtures/malformed/error-missing-request-id.jsonl"
            ) as &[u8],
        ),
        (
            "zero result sequence",
            include_bytes!(
                "../../../schemas/machine/v1/fixtures/malformed/result-zero-sequence.jsonl"
            ),
        ),
        (
            "non-ready initialize result",
            include_bytes!(
                "../../../schemas/machine/v1/fixtures/malformed/initialize-not-ready.jsonl"
            ),
        ),
        (
            "mismatched error shape",
            include_bytes!(
                "../../../schemas/machine/v1/fixtures/malformed/error-shape-mismatch.jsonl"
            ),
        ),
        (
            "unknown none-details field",
            include_bytes!(
                "../../../schemas/machine/v1/fixtures/malformed/details-none-unknown-field.jsonl"
            ),
        ),
        (
            "uncorrelated positive sequence",
            include_bytes!(
                "../../../schemas/machine/v1/fixtures/malformed/error-null-positive-sequence.jsonl"
            ),
        ),
        (
            "correlated zero sequence",
            include_bytes!(
                "../../../schemas/machine/v1/fixtures/malformed/error-correlated-zero-sequence.jsonl"
            ),
        ),
        (
            "equal unsupported versions",
            include_bytes!(
                "../../../schemas/machine/v1/fixtures/malformed/unsupported-equal-versions.jsonl"
            ),
        ),
    ] {
        assert!(
            decode_server_frame_v1(fixture).is_err(),
            "accepted malformed fixture: {name}"
        );
    }

    assert!(matches!(
        decode_request_v1(include_bytes!(
            "../../../schemas/machine/v1/fixtures/unsupported/version-2.jsonl"
        )),
        Err(MachineReadError::UnsupportedVersion {
            expected: 1,
            found: 2
        })
    ));
}

#[test]
fn framing_version_and_numeric_domains_are_strict() {
    for bytes in [b"{}".as_slice(), b"{}\n\n", b"{}\r\n", b"\n"] {
        assert!(matches!(
            decode_request_v1(bytes),
            Err(MachineReadError::InvalidFraming(_))
        ));
    }
    assert!(matches!(
        decode_request_v1(&[0xff, b'\n']),
        Err(MachineReadError::InvalidUtf8)
    ));
    assert!(matches!(
        decode_request_v1(b"{} trailing\n"),
        Err(MachineReadError::MalformedJson(_))
    ));

    for version in ["-1", "1.0", "4294967296", "\"1\""] {
        let record = format!(
            "{{\"schema_version\":{version},\"request_id\":\"r\",\"type\":\"request\",\"request\":{{\"type\":\"store_status\"}}}}\n"
        );
        assert!(matches!(
            decode_request_v1(record.as_bytes()),
            Err(MachineReadError::InvalidEnvelope(_))
        ));
    }
    let maximum_version = b"{\"schema_version\":4294967295,\"request_id\":\"r\",\"type\":\"request\",\"request\":{\"type\":\"store_status\"}}\n";
    assert!(matches!(
        decode_request_v1(maximum_version),
        Err(MachineReadError::UnsupportedVersion {
            found: u32::MAX,
            ..
        })
    ));

    for sequence in ["-1", "1.0", "9007199254740992"] {
        let record = format!(
            "{{\"schema_version\":1,\"request_id\":\"r\",\"sequence\":{sequence},\"type\":\"result\",\"result\":{{\"type\":\"store_status\",\"status\":\"ready\"}}}}\n"
        );
        assert!(decode_server_frame_v1(record.as_bytes()).is_err());
    }
}

#[test]
fn preflight_enforces_every_json_resource_budget() {
    assert!(matches!(
        decode_request_v1(&vec![b' '; MAX_MACHINE_FRAME_BYTES + 1]),
        Err(MachineReadError::TooLarge { .. })
    ));

    let nested = format!(
        "{}0{}\n",
        "[".repeat(MAX_MACHINE_JSON_DEPTH + 1),
        "]".repeat(MAX_MACHINE_JSON_DEPTH + 1)
    );
    assert!(matches!(
        decode_request_v1(nested.as_bytes()),
        Err(MachineReadError::TooDeep { .. })
    ));

    let mut object = String::from("{");
    for index in 0..=MAX_MACHINE_OBJECT_MEMBERS {
        if index != 0 {
            object.push(',');
        }
        write!(object, "\"k{index}\":null").unwrap();
    }
    object.push_str("}\n");
    assert!(matches!(
        decode_request_v1(object.as_bytes()),
        Err(MachineReadError::TooManyObjectMembers { .. })
    ));

    let array = format!(
        "[{}]\n",
        vec!["null"; MAX_MACHINE_ARRAY_ITEMS + 1].join(",")
    );
    assert!(matches!(
        decode_request_v1(array.as_bytes()),
        Err(MachineReadError::TooManyArrayItems { .. })
    ));

    let inner = format!("[{}]", vec!["null"; MAX_MACHINE_ARRAY_ITEMS].join(","));
    let aggregate = format!("[{}]\n", vec![inner; 16].join(","));
    assert!(aggregate.len() < MAX_MACHINE_FRAME_BYTES);
    assert!(matches!(
        decode_request_v1(aggregate.as_bytes()),
        Err(MachineReadError::TooManyValues { .. })
    ));
}

#[test]
fn scalar_and_model_boundaries_are_enforced() {
    assert!(RequestIdV1::new("a".repeat(MAX_REQUEST_ID_BYTES)).is_ok());
    assert!(RequestIdV1::new("a".repeat(MAX_REQUEST_ID_BYTES + 1)).is_err());
    for invalid in ["", "has space", "non-ascii-å"] {
        assert!(RequestIdV1::new(invalid).is_err());
    }

    assert!(MachineCodeV1::new("a".repeat(64)).is_ok());
    assert!(MachineCodeV1::new("a".repeat(65)).is_err());
    assert!(MachineCodeV1::new("Uppercase").is_err());
    assert!(MachineTextV1::new("x".repeat(MAX_MACHINE_TEXT_BYTES)).is_ok());
    assert!(MachineTextV1::new("x".repeat(MAX_MACHINE_TEXT_BYTES + 1)).is_err());
    assert!(MachineTextV1::new("é".repeat(MAX_MACHINE_TEXT_BYTES / 2)).is_ok());
    assert!(MachineTextV1::new("é".repeat(MAX_MACHINE_TEXT_BYTES / 2 + 1)).is_err());
    assert!(MachineTextV1::new("bad\u{1}").is_err());
    assert!(MachineTextV1::new("bad\u{85}").is_err());
    assert!(MachineTextV1::new("line\nbreak\tallowed").is_ok());

    let diagnostic = MachineDiagnosticV1::new(
        DiagnosticSeverityV1::Error,
        MachineCodeV1::new("many").unwrap(),
        text("message"),
    );
    assert!(
        MachineErrorV1::new(
            MachineErrorCategoryV1::Internal,
            MachineErrorCodeV1::InternalEngineError,
            text("error"),
            MachineErrorDetailsV1::None,
            vec![diagnostic; MAX_MACHINE_DIAGNOSTICS + 1],
        )
        .is_err()
    );

    assert!(
        MachineErrorV1::new(
            MachineErrorCategoryV1::Conflict,
            MachineErrorCodeV1::StoreNotReady,
            text("error"),
            MachineErrorDetailsV1::CurrentStatus(StoreStatusV1::Ready),
            vec![],
        )
        .is_err()
    );
    assert!(
        MachineErrorV1::new(
            MachineErrorCategoryV1::Unsupported,
            MachineErrorCodeV1::UnsupportedMachineVersion,
            text("error"),
            MachineErrorDetailsV1::UnsupportedSchema {
                schema: SchemaFamilyV1::Machine,
                expected: 1,
                found: 1,
            },
            vec![],
        )
        .is_err()
    );
}

#[test]
fn writers_reject_publicly_constructed_invalid_frames() {
    let invalid_result = ServerFrameV1::Result {
        request_id: request_id("req"),
        sequence: 0,
        result: MachineResultV1::StoreStatus(StoreStatusV1::Ready),
    };
    assert!(matches!(
        encode_server_frame_v1(&invalid_result),
        Err(MachineWriteError::InvalidSemantics(_))
    ));

    let invalid_review = ServerFrameV1::result(
        request_id("invalid-review"),
        1,
        MachineResultV1::Prepare(PreparedDeploymentV1::from(PreparedDeploymentPartsV1 {
            plan_id: PreparedId::from_digest(&Digest::sha256(b"invalid review plan")),
            namespace: NamespaceName::new("invalid-review").unwrap(),
            expected_head: None,
            graph_digest: Digest::sha256(b"invalid review graph"),
            inputs: vec![],
            transforms: vec![],
            artifacts: vec![],
            findings: vec![PolicyFindingV1::new(
                Digest::sha256(b"forged finding ID"),
                "review".to_owned(),
                "review invalid plan".to_owned(),
                true,
            )],
            approval_digest: Digest::sha256(b"forged approval"),
            operations: vec![],
        })),
    )
    .unwrap();
    assert!(matches!(
        encode_server_frame_v1(&invalid_review),
        Err(MachineWriteError::InvalidSemantics(
            MachineValidationError::InvalidPreparedDeployment(_)
        ))
    ));

    for invalid_error in [
        ServerFrameV1::Error {
            request_id: None,
            sequence: 1,
            error: read_only_error(),
        },
        ServerFrameV1::Error {
            request_id: Some(request_id("req")),
            sequence: 0,
            error: read_only_error(),
        },
        ServerFrameV1::Error {
            request_id: Some(request_id("req")),
            sequence: MAX_MACHINE_SEQUENCE + 1,
            error: read_only_error(),
        },
    ] {
        assert!(matches!(
            encode_server_frame_v1(&invalid_error),
            Err(MachineWriteError::InvalidSemantics(_))
        ));
    }

    let maximum = ServerFrameV1::result(
        request_id("req"),
        MAX_MACHINE_SEQUENCE,
        MachineResultV1::StoreStatus(StoreStatusV1::Ready),
    )
    .unwrap();
    let encoded = encode_server_frame_v1(&maximum).unwrap();
    assert_eq!(decode_server_frame_v1(&encoded).unwrap(), maximum);
    assert!(
        ServerFrameV1::result(
            request_id("req"),
            MAX_MACHINE_SEQUENCE + 1,
            MachineResultV1::StoreStatus(StoreStatusV1::Ready),
        )
        .is_err()
    );

    let oversized_bytes = vec![0_u8; MAX_MACHINE_FRAME_BYTES / 2];
    let oversized = ServerFrameV1::result(
        request_id("oversized"),
        1,
        MachineResultV1::Artifact(ArtifactV1::new(
            ArtifactDescriptorV1::new(
                ArtifactId::new("large/artifact").unwrap(),
                Digest::sha256(&oversized_bytes),
                u64::try_from(oversized_bytes.len()).unwrap(),
                "application/octet-stream".to_owned(),
            ),
            oversized_bytes,
        )),
    )
    .unwrap();
    assert!(matches!(
        encode_server_frame_v1(&oversized),
        Err(MachineWriteError::TooLarge { .. })
    ));
}

#[test]
fn writers_enforce_exact_machine_array_and_inspection_boundaries() {
    let namespace = NamespaceName::new("n").unwrap();
    let maximum_request = RequestEnvelopeV1::new(
        request_id("history-maximum"),
        MachineRequestV1::History(
            NamespaceHistoryRequestV1::with_limits(
                namespace.clone(),
                MAX_MACHINE_ARRAY_ITEMS,
                1024,
            )
            .unwrap(),
        ),
    );
    let encoded = encode_request_v1(&maximum_request).unwrap();
    assert_eq!(decode_request_v1(&encoded).unwrap(), maximum_request);
    let request_schema: serde_json::Value = serde_json::from_slice(include_bytes!(
        "../../../schemas/machine/v1/request.schema.json"
    ))
    .unwrap();
    let request_validator = jsonschema::validator_for(&request_schema).unwrap();
    assert!(request_validator.is_valid(&serde_json::from_slice(&encoded).unwrap()));

    let over_limit_request = RequestEnvelopeV1::new(
        request_id("history-over-limit"),
        MachineRequestV1::History(
            NamespaceHistoryRequestV1::with_limits(
                namespace.clone(),
                MAX_MACHINE_ARRAY_ITEMS + 1,
                1024,
            )
            .unwrap(),
        ),
    );
    assert!(matches!(
        encode_request_v1(&over_limit_request),
        Err(MachineWriteError::InvalidSemantics(
            MachineValidationError::UnsupportedRequest(_)
        ))
    ));
    assert!(NamespaceHistoryRequestV1::with_limits(namespace.clone(), 0, 1024).is_err());

    let item = CatalogNamespaceInspectionV1::new(namespace, Digest::sha256(b"generation"));
    let maximum_frame = ServerFrameV1::result(
        request_id("catalog-maximum"),
        1,
        MachineResultV1::Catalog(CatalogInspectionV1::new(
            Digest::sha256(b"catalog"),
            vec![item.clone(); MAX_MACHINE_ARRAY_ITEMS],
            1,
        )),
    )
    .unwrap();
    let encoded = encode_server_frame_v1(&maximum_frame).unwrap();
    assert_eq!(decode_server_frame_v1(&encoded).unwrap(), maximum_frame);
    let server_schema: serde_json::Value = serde_json::from_slice(include_bytes!(
        "../../../schemas/machine/v1/server.schema.json"
    ))
    .unwrap();
    let server_validator = jsonschema::validator_for(&server_schema).unwrap();
    assert!(server_validator.is_valid(&serde_json::from_slice(&encoded).unwrap()));

    let over_limit_frame = ServerFrameV1::result(
        request_id("catalog-over-limit"),
        1,
        MachineResultV1::Catalog(CatalogInspectionV1::new(
            Digest::sha256(b"catalog"),
            vec![item; MAX_MACHINE_ARRAY_ITEMS + 1],
            1,
        )),
    )
    .unwrap();
    assert!(matches!(
        encode_server_frame_v1(&over_limit_frame),
        Err(MachineWriteError::RejectedByDecoder(error))
            if matches!(*error, MachineReadError::TooManyArrayItems { .. })
    ));
}

#[test]
fn decode_failures_map_to_bounded_uncorrelated_errors() {
    let cases = [
        (
            decode_request_v1(b"not-json\n").unwrap_err(),
            MachineErrorCodeV1::MalformedJson,
        ),
        (
            decode_request_v1(include_bytes!(
                "../../../schemas/machine/v1/fixtures/malformed/request-unknown-field.jsonl"
            ))
            .unwrap_err(),
            MachineErrorCodeV1::InvalidRequest,
        ),
        (
            decode_request_v1(include_bytes!(
                "../../../schemas/machine/v1/fixtures/unsupported/version-2.jsonl"
            ))
            .unwrap_err(),
            MachineErrorCodeV1::UnsupportedMachineVersion,
        ),
        (
            decode_request_v1(&vec![b' '; MAX_MACHINE_FRAME_BYTES + 1]).unwrap_err(),
            MachineErrorCodeV1::FrameResourceLimit,
        ),
    ];

    for (read_error, expected_code) in cases {
        let frame = request_error_frame_v1(&read_error);
        let ServerFrameV1::Error {
            request_id,
            sequence,
            error,
        } = &frame
        else {
            panic!("decode error did not map to an error frame");
        };
        assert!(request_id.is_none());
        assert_eq!(*sequence, 0);
        assert_eq!(error.code(), expected_code);
        let encoded = encode_server_frame_v1(&frame).unwrap();
        assert!(
            String::from_utf8(encoded)
                .unwrap()
                .contains("\"request_id\":null")
        );
    }

    for inconsistent in [
        MachineReadError::UnsupportedVersion {
            expected: 2,
            found: 1,
        },
        MachineReadError::UnsupportedVersion {
            expected: 1,
            found: 1,
        },
    ] {
        let ServerFrameV1::Error { error, .. } = request_error_frame_v1(&inconsistent) else {
            panic!("decode error did not map to an error frame");
        };
        assert_eq!(error.code(), MachineErrorCodeV1::InvalidRequest);
    }
}

#[test]
fn accepted_request_streams_are_correlated_ordered_and_terminal() {
    let request = RequestEnvelopeV1::new(request_id("stream"), MachineRequestV1::StoreStatus);
    let mut stream = ResponseStreamValidatorV1::new(&request);
    let started = ServerFrameV1::started(request_id("stream"), MachineOperationV1::StoreStatus);
    let result = ServerFrameV1::result(
        request_id("stream"),
        1,
        MachineResultV1::StoreStatus(StoreStatusV1::Ready),
    )
    .unwrap();
    stream.observe(&started).unwrap();
    stream.observe(&result).unwrap();
    assert!(stream.is_terminal());
    assert_eq!(
        stream.observe(&result),
        Err(MachineStreamError::FrameAfterTerminal)
    );

    let mut stream = ResponseStreamValidatorV1::new(&request);
    assert!(matches!(
        stream.observe(&result),
        Err(MachineStreamError::UnexpectedFrame { .. })
    ));
    assert_eq!(
        stream.observe(&ServerFrameV1::started(
            request_id("other"),
            MachineOperationV1::StoreStatus
        )),
        Err(MachineStreamError::RequestIdMismatch)
    );
    assert_eq!(
        stream.observe(&ServerFrameV1::started(
            request_id("stream"),
            MachineOperationV1::InitializeStore
        )),
        Err(MachineStreamError::OperationMismatch)
    );

    stream.observe(&started).unwrap();
    let skipped = ServerFrameV1::result(
        request_id("stream"),
        2,
        MachineResultV1::StoreStatus(StoreStatusV1::Ready),
    )
    .unwrap();
    assert_eq!(
        stream.observe(&skipped),
        Err(MachineStreamError::InvalidSequence {
            expected: 1,
            actual: 2,
        })
    );
    let wrong_operation =
        ServerFrameV1::result(request_id("stream"), 1, MachineResultV1::InitializeStore).unwrap();
    assert_eq!(
        stream.observe(&wrong_operation),
        Err(MachineStreamError::OperationMismatch)
    );
}

#[test]
fn schemas_validate_writer_records_and_reject_structurally_malformed_fixtures() {
    fn assert_closed_objects(value: &serde_json::Value, path: &str) {
        if value.get("type").and_then(serde_json::Value::as_str) == Some("object") {
            assert_eq!(
                value.get("additionalProperties"),
                Some(&serde_json::Value::Bool(false)),
                "object schema is open at {path}"
            );
        }
        match value {
            serde_json::Value::Array(values) => {
                for (index, child) in values.iter().enumerate() {
                    assert_closed_objects(child, &format!("{path}/{index}"));
                }
            }
            serde_json::Value::Object(values) => {
                for (name, child) in values {
                    assert_closed_objects(child, &format!("{path}/{name}"));
                }
            }
            _ => {}
        }
    }

    let request_schema: serde_json::Value = serde_json::from_str(include_str!(
        "../../../schemas/machine/v1/request.schema.json"
    ))
    .unwrap();
    let server_schema: serde_json::Value = serde_json::from_str(include_str!(
        "../../../schemas/machine/v1/server.schema.json"
    ))
    .unwrap();
    for schema in [&request_schema, &server_schema] {
        assert_eq!(
            schema["$schema"],
            "https://json-schema.org/draft/2020-12/schema"
        );
        jsonschema::meta::validate(schema).unwrap();
        assert_closed_objects(schema, "#");
    }

    fn record_value(bytes: &[u8]) -> serde_json::Value {
        serde_json::from_slice(bytes.strip_suffix(b"\n").unwrap()).unwrap()
    }

    let request_validator = jsonschema::validator_for(&request_schema).unwrap();
    for fixture in [
        VALID_REQUEST_STATUS,
        VALID_REQUEST_INITIALIZE,
        GOLDEN_REQUEST_PLAN,
    ] {
        let value = record_value(fixture);
        assert!(request_validator.is_valid(&value));
    }
    for fixture in [
        include_bytes!("../../../schemas/machine/v1/fixtures/malformed/request-unknown-field.jsonl")
            as &[u8],
        include_bytes!(
            "../../../schemas/machine/v1/fixtures/malformed/request-nested-unknown-field.jsonl"
        ),
        include_bytes!("../../../schemas/machine/v1/fixtures/unsupported/version-2.jsonl"),
    ] {
        let value = record_value(fixture);
        assert!(!request_validator.is_valid(&value));
    }

    let server_validator = jsonschema::validator_for(&server_schema).unwrap();
    for fixture in [
        VALID_SERVER_STARTED,
        VALID_SERVER_RESULT,
        VALID_SERVER_ERROR,
        include_bytes!("../../../schemas/machine/v1/fixtures/golden/server-started.jsonl"),
        include_bytes!("../../../schemas/machine/v1/fixtures/golden/server-result.jsonl"),
        include_bytes!("../../../schemas/machine/v1/fixtures/golden/server-error.jsonl"),
        GOLDEN_SERVER_STATE,
    ] {
        let value = record_value(fixture);
        assert!(server_validator.is_valid(&value));
    }
    for fixture in [
        include_bytes!(
            "../../../schemas/machine/v1/fixtures/malformed/error-missing-request-id.jsonl"
        ) as &[u8],
        include_bytes!("../../../schemas/machine/v1/fixtures/malformed/result-zero-sequence.jsonl"),
        include_bytes!("../../../schemas/machine/v1/fixtures/malformed/initialize-not-ready.jsonl"),
        include_bytes!("../../../schemas/machine/v1/fixtures/malformed/error-shape-mismatch.jsonl"),
        include_bytes!(
            "../../../schemas/machine/v1/fixtures/malformed/details-none-unknown-field.jsonl"
        ),
        include_bytes!(
            "../../../schemas/machine/v1/fixtures/malformed/error-null-positive-sequence.jsonl"
        ),
        include_bytes!(
            "../../../schemas/machine/v1/fixtures/malformed/error-correlated-zero-sequence.jsonl"
        ),
    ] {
        let value = record_value(fixture);
        assert!(!server_validator.is_valid(&value));
    }

    let c1_control = serde_json::json!({
        "schema_version": 1,
        "request_id": "r",
        "sequence": 1,
        "type": "error",
        "error": {
            "category": "internal",
            "code": "internal-engine-error",
            "message": "bad\u{85}",
            "details": {"type": "none"},
            "diagnostics": []
        }
    });
    assert!(!server_validator.is_valid(&c1_control));
}
