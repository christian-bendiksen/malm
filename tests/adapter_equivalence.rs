mod common;

use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::process::{Command, Stdio};

use common::TestEnv;
use malm::{
    ApprovalV1, CommitRequestV1, Engine, GitAcquisitionConfig, LockFilePublication,
    LockResolutionInputs, PrepareArtifactV1, PrepareInputKindV1, PrepareInputV1,
    PrepareOperationV1, PreparePolicyFindingV1, PrepareRequestPartsV1, PrepareRequestV1,
    PrepareTransformDiagnosticLocationV1, PrepareTransformDiagnosticSeverityV1,
    PrepareTransformDiagnosticV1, PrepareTransformImplementationV1, PreparedDeploymentV1,
    PruneRequestV1, StoreStatus, TreeObjectV1, tree_object_digest_v1,
};
use malm_machine::{
    MachineRequestV1, MachineResultV1, RequestEnvelopeV1, RequestIdV1, ServerFrameV1,
    decode_server_frame_v1, encode_request_v1,
};
use malm_pack::{
    LOCK_FILE, PackFileV1, PackPath, decode_lock_v1, lock_graph_digest, pack_content_digest,
};
use malm_tree::{
    SymlinkObjectV1, TreeEntryV1, TreePathSegmentV1, file_object_digest_v1,
    symlink_object_digest_v1,
};
use malm_types::{
    ArchiveProvenanceV1, ArtifactMetadataInspectionRequestV1, CanonicalTreeInspectionRequestV1,
    CatalogInspectionRequestV1, CheckoutRequestV1, DesiredSnapshotInspectionRequestV1,
    FsckRequestV1, GenerationInspectionRequestV1, HistoryRetentionRequestV1, LifecycleRequestV1,
    LifecycleStateViewV1, LifecycleTransitionViewV1, NamespaceHistoryRequestV1,
    NamespaceInspectionRequestV1, NamespaceRemovalHistoryV1, NamespaceRemovalRequestV1,
    NamespaceStatusRequestV1, PreparedPlanInspectionRequestV1, RestorePointInspectionV1,
    RestorePointRequestV1, RetentionAuthorityInspectionV1, RetentionObjectV1,
    RetentionPinRequestV1, StoreStatusV1, TrackedRootInspectionV1,
};
use malm_types::{
    ArtifactId, DeploymentName, Digest, NamespaceName, PrepareTargetStateV1, PreparedId,
    PreparedTrackingAcquisitionKindV1, PreparedTrackingReviewV1,
};

const TREE_FILE_BYTES: &[u8] = b"canonical tree entry\n";
fn request() -> PrepareRequestV1 {
    PrepareRequestV1::from(PrepareRequestPartsV1 {
        namespace: NamespaceName::new("workstation").unwrap(),
        expected_head: None,
        graph_digest: Digest::sha256(b"adapter-equivalence-graph"),
        inputs: vec![
            PrepareInputV1::new(
                PrepareInputKindV1::Config,
                "root-config",
                Digest::sha256(b"adapter-equivalence-config"),
            )
            .unwrap(),
        ],
        artifacts: vec![
            PrepareArtifactV1::new(
                ArtifactId::new("parity/result").unwrap(),
                b"\0adapter parity\xff\n".to_vec(),
                "application/octet-stream",
            )
            .unwrap(),
        ],
        transforms: vec![],
        findings: vec![
            PreparePolicyFindingV1::new(
                "adapter-advisory",
                "advisory finding shared by every adapter",
                false,
            )
            .unwrap(),
            PreparePolicyFindingV1::new(
                "adapter-approval",
                "approval finding shared by every adapter",
                true,
            )
            .unwrap(),
        ],
        operations: vec![],
    })
}

fn review_request() -> PrepareRequestV1 {
    let (_, tree_digest) = request_tree();
    let artifact_id = ArtifactId::new("review/result").unwrap();
    PrepareRequestV1::from(PrepareRequestPartsV1 {
        namespace: NamespaceName::new("review").unwrap(),
        expected_head: None,
        graph_digest: Digest::sha256(b"human review graph"),
        inputs: vec![
            PrepareInputV1::new(
                PrepareInputKindV1::Config,
                "review-config",
                Digest::sha256(b"human review config"),
            )
            .unwrap(),
        ],
        artifacts: vec![
            PrepareArtifactV1::new(
                artifact_id.clone(),
                b"human review file\n".to_vec(),
                "text/plain",
            )
            .unwrap(),
        ],
        transforms: vec![],
        findings: vec![
            PreparePolicyFindingV1::new("human-review", "review every stable field", true).unwrap(),
        ],
        operations: vec![
            PrepareOperationV1::place_file(
                DeploymentName::new("home").unwrap(),
                "review-result",
                artifact_id,
                0o600,
            )
            .unwrap(),
            PrepareOperationV1::place_archive_tree(
                DeploymentName::new("home").unwrap(),
                "review-tree",
                tree_digest,
                ArchiveProvenanceV1::new(
                    Digest::sha256(b"adapter archive payload"),
                    "malm.posix-ustar.none/v1",
                )
                .unwrap(),
            )
            .unwrap(),
        ],
    })
}

fn request_tree() -> (TreeObjectV1, Digest) {
    let file_digest = file_object_digest_v1(TREE_FILE_BYTES).unwrap();
    let tree = TreeObjectV1::new(
        0o750,
        vec![
            TreeEntryV1::file(
                TreePathSegmentV1::new("entry.txt").unwrap(),
                0o640,
                file_digest,
                u64::try_from(TREE_FILE_BYTES.len()).unwrap(),
            )
            .unwrap(),
        ],
    )
    .unwrap();
    let digest = tree_object_digest_v1(&tree);
    (tree, digest)
}

fn publish_request_tree(engine: &Engine) {
    let file_digest = file_object_digest_v1(TREE_FILE_BYTES).unwrap();
    engine
        .publish_file_object_v1(&file_digest, TREE_FILE_BYTES)
        .unwrap();
    let (tree, tree_digest) = request_tree();
    engine.publish_tree_object_v1(&tree_digest, &tree).unwrap();
}

fn prepare_prune_parity_fixture(engine: &Engine) -> PreparedDeploymentV1 {
    let policy = engine
        .prepare_history_retention_v1(
            &HistoryRetentionRequestV1::new(NamespaceName::new("workstation").unwrap(), 1).unwrap(),
        )
        .unwrap();
    engine.commit_v1(&commit_request(&policy)).unwrap();

    publish_request_tree(engine);
    let symlink = SymlinkObjectV1::new("orphan-target").unwrap();
    let symlink_digest = symlink_object_digest_v1(&symlink);
    engine
        .publish_symlink_object_v1(&symlink_digest, &symlink)
        .unwrap();
    let pack_files = vec![PackFileV1::new(
        PackPath::new("malm-pack.kdl").unwrap(),
        b"schema 1\npack \"prune-parity-orphan\"\n",
    )];
    let pack_digest =
        pack_content_digest(pack_files.iter().map(|file| (file.path(), file.bytes()))).unwrap();
    engine
        .publish_pack_object_v1(&pack_digest, &pack_files)
        .unwrap();

    engine
        .prepare_v1(&PrepareRequestV1::from(PrepareRequestPartsV1 {
            namespace: NamespaceName::new("disposable").unwrap(),
            expected_head: None,
            graph_digest: Digest::sha256(b"adapter-equivalence-disposable"),
            inputs: vec![],
            artifacts: vec![
                PrepareArtifactV1::new(
                    ArtifactId::new("disposable/artifact").unwrap(),
                    b"disposable prune bytes".to_vec(),
                    "application/octet-stream",
                )
                .unwrap(),
            ],
            transforms: vec![],
            findings: vec![],
            operations: vec![],
        }))
        .unwrap()
}

fn seed_diagnostic_plan(env: &TestEnv) -> PreparedId {
    let engine = env.engine();
    engine.initialize_store().unwrap();
    let base = include_str!("../schemas/store/v1/fixtures/valid/prepared-record.json");
    let transform =
        include_str!("../schemas/store/v1/fixtures/golden/transform-provenance.json").trim_end();
    let record = base.trim_end().replace(
        "\"transforms\":[]",
        &format!("\"transforms\":[{transform}]"),
    ) + "\n";
    let plan_id = PreparedId::from_digest(&Digest::sha256(record.as_bytes()));
    let state_root = engine.config().state_root();
    for directory in [
        state_root.join("objects"),
        state_root.join("objects/blobs"),
        state_root.join("prepared"),
    ] {
        std::fs::create_dir_all(&directory).unwrap();
        std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let prepared = state_root.join("prepared");
    let path = prepared.join(plan_id.as_str());
    std::fs::write(&path, record).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o400)).unwrap();
    plan_id
}

fn run_machine(env: &TestEnv, id: &str, request: MachineRequestV1) -> MachineResultV1 {
    let request_id = RequestIdV1::new(id).unwrap();
    let operation = request.operation();
    let envelope = RequestEnvelopeV1::new(request_id.clone(), request);
    let mut child = Command::new(env!("CARGO_BIN_EXE_malm"))
        .arg("machine")
        .env("HOME", env.home())
        .env("XDG_STATE_HOME", env.state_home())
        .env_remove("MALM_FAILPOINT")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(&encode_request_v1(&envelope).unwrap())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty());
    let frames = output
        .stdout
        .split_inclusive(|byte| *byte == b'\n')
        .map(|record| decode_server_frame_v1(record).unwrap())
        .collect::<Vec<_>>();
    assert_eq!(frames.len(), 2);
    assert!(matches!(
        &frames[0],
        ServerFrameV1::Started {
            request_id: actual,
            operation: actual_operation,
        } if actual == &request_id && *actual_operation == operation
    ));
    let ServerFrameV1::Result {
        request_id: actual,
        sequence: 1,
        result,
    } = &frames[1]
    else {
        panic!("machine adapter did not return one correlated result: {frames:?}")
    };
    assert_eq!(actual, &request_id);
    result.clone()
}

fn run_cli_json(env: &TestEnv, arguments: &[&str]) -> serde_json::Value {
    let output = env.malm_without_repo(arguments);
    assert!(
        output.status.success(),
        "malm {arguments:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty());
    let envelope: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(envelope.as_object().unwrap().len(), 5);
    assert_eq!(envelope["schema_version"], 1);
    assert!(envelope["command"].is_string());
    assert!(envelope["outcome"].is_string());
    assert_eq!(envelope["diagnostics"], serde_json::json!([]));
    assert!(envelope.get("data").is_some());
    envelope["data"].clone()
}

fn run_cli_text(env: &TestEnv, arguments: &[&str]) -> String {
    let output = env.malm_without_repo(arguments);
    assert!(
        output.status.success(),
        "malm {arguments:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty());
    String::from_utf8(output.stdout).unwrap()
}

fn plan_json(plan: &PreparedDeploymentV1) -> serde_json::Value {
    let inputs = plan
        .inputs()
        .iter()
        .map(|input| {
            serde_json::json!({
                "kind": input_kind_name(input.kind()),
                "name": input.name(),
                "digest": input.digest().as_str(),
            })
        })
        .collect::<Vec<_>>();
    let transforms = plan
        .transforms()
        .iter()
        .map(|transform| {
            let implementation = match transform.implementation() {
                PrepareTransformImplementationV1::BuiltIn { implementation } => {
                    serde_json::json!({
                        "kind": "built-in",
                        "implementation": implementation,
                    })
                }
                PrepareTransformImplementationV1::Component {
                    pack_node_id,
                    pack_content_digest,
                    component_path,
                    component_digest,
                    interface_version,
                    execution_profile_digest,
                } => serde_json::json!({
                    "kind": "component",
                    "pack_node_id": pack_node_id.to_string(),
                    "pack_content_digest": pack_content_digest.as_str(),
                    "component_path": component_path,
                    "component_digest": component_digest.as_str(),
                    "interface_version": interface_version,
                    "execution_profile_digest": execution_profile_digest.as_str(),
                }),
            };
            serde_json::json!({
                "name": transform.name(),
                "implementation": implementation,
                "request_digest": transform.request_digest().as_str(),
                "document_digest": transform.document_digest().as_str(),
                "resources": transform.resources().iter().map(|resource| serde_json::json!({
                    "name": resource.name(),
                    "digest": resource.digest().as_str(),
                })).collect::<Vec<_>>(),
                "response_digest": transform.response_digest().as_str(),
                "diagnostics": transform.diagnostics().iter().map(transform_diagnostic_json).collect::<Vec<_>>(),
            })
        })
        .collect::<Vec<_>>();
    let artifacts = plan
        .artifacts()
        .iter()
        .map(|artifact| {
            serde_json::json!({
                "id": artifact.id().as_str(),
                "digest": artifact.digest().as_str(),
                "byte_len": artifact.byte_len(),
                "media_type": artifact.media_type(),
            })
        })
        .collect::<Vec<_>>();
    let findings = plan
        .findings()
        .iter()
        .map(|finding| {
            serde_json::json!({
                "id": finding.id().as_str(),
                "code": finding.code(),
                "message": finding.message(),
                "approval_required": finding.approval_required(),
            })
        })
        .collect::<Vec<_>>();
    let operations = plan
        .operations()
        .iter()
        .map(operation_json)
        .collect::<Vec<_>>();
    serde_json::json!({
        "plan_id": plan.plan_id().as_str(),
        "namespace": plan.namespace().as_str(),
        "expected_head": plan.expected_head().map(Digest::as_str),
        "transition": lifecycle_transition_json(plan.transition()),
        "lifecycle": lifecycle_state_name(plan.lifecycle_state()),
        "restore_point": plan.restore_point().map(restore_point_json),
        "retention": retention_authority_json(plan.retention_authority()),
        "tracked_root": plan.tracking_review().map(prepared_tracking_json),
        "graph_digest": plan.graph_digest().as_str(),
        "inputs": inputs,
        "transforms": transforms,
        "approval_digest": plan.approval_digest().as_str(),
        "operation_count": plan.operation_count(),
        "operations": operations,
        "artifacts": artifacts,
        "findings": findings,
    })
}

fn assert_contains(text: &str, value: impl std::fmt::Display) {
    let value = value.to_string();
    assert!(
        text.contains(&value),
        "human output omitted {value:?}:\n{text}"
    );
}

fn human_digest(tag: &str, digest: &Digest) -> String {
    format!("{tag}:{}", &digest.as_str()[7..19])
}

fn human_plan(plan: &PreparedId) -> String {
    format!("plan:{}", &plan.as_str()[3..15])
}

fn assert_contains_wrapped(text: &str, value: &str) {
    let text = text.split_whitespace().collect::<Vec<_>>().join(" ");
    let value = value.split_whitespace().collect::<Vec<_>>().join(" ");
    assert!(
        text.contains(&value),
        "human output omitted wrapped {value:?}:\n{text}"
    );
}

fn assert_target_state_text(text: &str, state: &PrepareTargetStateV1) {
    match state {
        PrepareTargetStateV1::File {
            digest,
            byte_len,
            mode,
        } => {
            assert_contains(text, digest);
            assert_contains(text, byte_len);
            assert_contains(text, format!("{mode:04o}"));
        }
        PrepareTargetStateV1::Directory { mode } => {
            assert_contains(text, format!("{mode:04o}"));
        }
        PrepareTargetStateV1::Symlink { object } => assert_contains(text, object),
        PrepareTargetStateV1::Tree {
            tree,
            archive_provenance,
        } => {
            assert_contains(text, tree);
            if let Some(provenance) = archive_provenance {
                assert_contains(text, provenance.payload());
                assert_contains(text, provenance.decoder());
            }
        }
    }
}

fn assert_transform_text(text: &str, transform: &malm::PrepareTransformProvenanceV1) {
    assert_contains(text, transform.name());
    assert_contains(text, transform.request_digest());
    assert_contains(text, transform.document_digest());
    assert_contains(text, transform.response_digest());
    match transform.implementation() {
        PrepareTransformImplementationV1::BuiltIn { implementation } => {
            assert_contains(text, implementation);
        }
        PrepareTransformImplementationV1::Component {
            pack_node_id,
            pack_content_digest,
            component_path,
            component_digest,
            interface_version,
            execution_profile_digest,
        } => {
            assert_contains(text, pack_node_id);
            assert_contains(text, pack_content_digest);
            assert_contains(text, component_path);
            assert_contains(text, component_digest);
            assert_contains(text, interface_version);
            assert_contains(text, execution_profile_digest);
        }
    }
    for resource in transform.resources() {
        assert_contains(text, resource.name());
        assert_contains(text, resource.digest());
    }
    for diagnostic in transform.diagnostics() {
        assert_contains(text, diagnostic.code());
        assert_contains(text, diagnostic.message());
        match diagnostic.primary() {
            Some(PrepareTransformDiagnosticLocationV1::Source(source)) => {
                assert_contains(text, source.authority_label());
                assert_contains(text, source.authority_identity());
                assert_contains(text, source.document_path());
                assert_contains(text, source.start());
                assert_contains(text, source.end());
            }
            Some(PrepareTransformDiagnosticLocationV1::Output(output)) => {
                assert_contains(text, output.start());
                assert_contains(text, output.end());
            }
            None => assert_contains(text, "primary=none"),
        }
        for note in diagnostic.notes() {
            assert_contains(text, note);
        }
    }
}

fn assert_plan_text(text: &str, plan: &PreparedDeploymentV1) {
    let approval_count = plan
        .findings()
        .iter()
        .filter(|finding| finding.approval_required())
        .count();
    assert_contains(
        text,
        if approval_count == 0 {
            "Plan ready"
        } else {
            "Plan requires approval"
        },
    );
    assert_contains(text, plan.plan_id());
    assert_contains(text, plan.namespace());
    if let Some(head) = plan.expected_head() {
        assert_contains(text, head);
    }
    assert_contains(
        text,
        match plan.transition() {
            LifecycleTransitionViewV1::Reconcile => "reconcile desired state",
            LifecycleTransitionViewV1::Disable => "disable namespace",
            LifecycleTransitionViewV1::Enable { .. } => "enable namespace",
            LifecycleTransitionViewV1::Checkout { .. } => "restore generation",
            LifecycleTransitionViewV1::RetentionAuthority => "update retention",
            LifecycleTransitionViewV1::NamespaceRemoval { .. } => "remove namespace",
        },
    );
    if let Some(tracking) = plan.tracking_review() {
        assert_contains(text, tracking.source_locator());
        assert_contains(text, tracking.moving_selector());
        assert_contains(text, tracking.applied_revision());
        assert_contains(text, tracking.selected_profile());
    }
    for finding in plan.findings() {
        assert_contains(text, finding.code());
        assert_contains_wrapped(text, finding.message());
    }
    for operation in plan.operations() {
        match operation {
            PrepareOperationV1::EnsureDirectory {
                authority,
                relative_path,
                mode,
                replace_existing,
            } => {
                assert_contains(text, authority);
                assert_contains(text, relative_path);
                assert_contains(text, format!("{mode:04o}"));
                assert_contains(text, if *replace_existing { "~" } else { "+" });
            }
            PrepareOperationV1::PlaceFile {
                authority,
                relative_path,
                artifact_id: _,
                mode,
                replace_existing,
            } => {
                assert_contains(text, authority);
                assert_contains(text, relative_path);
                assert_contains(text, format!("{mode:04o}"));
                assert_contains(text, if *replace_existing { "~" } else { "+" });
            }
            PrepareOperationV1::PlaceSymlink {
                authority,
                relative_path,
                object: _,
                replace_existing,
            } => {
                assert_contains(text, authority);
                assert_contains(text, relative_path);
                assert_contains(text, if *replace_existing { "~" } else { "+" });
            }
            PrepareOperationV1::PlaceTree {
                authority,
                relative_path,
                tree: _,
                archive_provenance: _,
                replace_existing,
            } => {
                assert_contains(text, authority);
                assert_contains(text, relative_path);
                assert_contains(text, if *replace_existing { "~" } else { "+" });
            }
            PrepareOperationV1::RemoveLeaf {
                authority,
                relative_path,
            } => {
                assert_contains(text, authority);
                assert_contains(text, relative_path);
            }
            PrepareOperationV1::AssertAbsent { .. } | PrepareOperationV1::AssertExact { .. } => {}
        }
    }
    assert_contains(text, format!("{} inputs", plan.inputs().len()));
    assert_contains(text, format!("{} transforms", plan.transforms().len()));
    assert_contains(text, format!("{} artifacts", plan.artifacts().len()));
}

fn transform_diagnostic_json(diagnostic: &PrepareTransformDiagnosticV1) -> serde_json::Value {
    let severity = match diagnostic.severity() {
        PrepareTransformDiagnosticSeverityV1::Error => "error",
        PrepareTransformDiagnosticSeverityV1::Warning => "warning",
        PrepareTransformDiagnosticSeverityV1::Info => "info",
    };
    let primary = diagnostic.primary().map(|location| match location {
        PrepareTransformDiagnosticLocationV1::Source(source) => serde_json::json!({
            "kind": "source",
            "authority_label": source.authority_label().as_str(),
            "authority_identity": source.authority_identity().as_str(),
            "document_path": source.document_path(),
            "start": source.start(),
            "end": source.end(),
        }),
        PrepareTransformDiagnosticLocationV1::Output(output) => serde_json::json!({
            "kind": "output",
            "start": output.start(),
            "end": output.end(),
        }),
    });
    serde_json::json!({
        "severity": severity,
        "code": diagnostic.code(),
        "message": diagnostic.message(),
        "primary": primary,
        "notes": diagnostic.notes(),
    })
}

const fn lifecycle_state_name(state: LifecycleStateViewV1) -> &'static str {
    match state {
        LifecycleStateViewV1::Enabled => "enabled",
        LifecycleStateViewV1::Disabled => "disabled",
    }
}

fn lifecycle_transition_json(transition: &LifecycleTransitionViewV1) -> serde_json::Value {
    match transition {
        LifecycleTransitionViewV1::Reconcile => serde_json::json!({ "kind": "reconcile" }),
        LifecycleTransitionViewV1::Disable => serde_json::json!({ "kind": "disable" }),
        LifecycleTransitionViewV1::Enable { restore_generation } => serde_json::json!({
            "kind": "enable",
            "restore_generation": restore_generation.as_str(),
        }),
        LifecycleTransitionViewV1::Checkout { source_generation } => serde_json::json!({
            "kind": "checkout",
            "source_generation": source_generation.as_str(),
        }),
        LifecycleTransitionViewV1::RetentionAuthority => {
            serde_json::json!({ "kind": "retention_authority" })
        }
        LifecycleTransitionViewV1::NamespaceRemoval { drops_history } => serde_json::json!({
            "kind": "namespace_removal",
            "drops_history": drops_history,
        }),
    }
}

fn tracked_root_json(tracked: &TrackedRootInspectionV1) -> serde_json::Value {
    serde_json::json!({
        "moving_selector": tracked.moving_selector(),
        "applied_revision": tracked.applied_revision(),
        "root_tree_digest": tracked.root_tree_digest().as_str(),
    })
}

fn prepared_tracking_json(tracked: &PreparedTrackingReviewV1) -> serde_json::Value {
    serde_json::json!({
        "source_locator": tracked.source_locator(),
        "moving_selector": tracked.moving_selector(),
        "applied_revision": tracked.applied_revision(),
        "root_tree_digest": tracked.root_tree_digest().as_str(),
        "source_subdir": tracked.source_subdir(),
        "config_entry_point": tracked.config_entry_point(),
        "selected_profile": tracked.selected_profile().as_str(),
        "target_authority": tracked.target_authority().as_str(),
        "acquisition_grants": tracked.acquisition_grants().iter().map(|grant| serde_json::json!({
            "kind": match grant.kind() {
                PreparedTrackingAcquisitionKindV1::LocalSource => "local_source",
                PreparedTrackingAcquisitionKindV1::GitSource => "git_source",
            },
            "locator": grant.locator(),
        })).collect::<Vec<_>>(),
        "component_grants": tracked.component_grants().iter().map(Digest::as_str).collect::<Vec<_>>(),
    })
}

fn restore_point_json(restore: &RestorePointInspectionV1) -> serde_json::Value {
    serde_json::json!({
        "generation": restore.generation().as_str(),
        "lifecycle": lifecycle_state_name(restore.lifecycle()),
        "desired_snapshot_digest": restore.desired_snapshot_digest().as_str(),
        "tracked_root": restore.tracked_root().map(tracked_root_json),
    })
}

fn retention_object_json(object: &RetentionObjectV1) -> serde_json::Value {
    match object {
        RetentionObjectV1::PreparedPlan { plan_id } => {
            serde_json::json!({ "kind": "prepared_plan", "plan_id": plan_id.as_str() })
        }
        RetentionObjectV1::StateGeneration { digest } => {
            serde_json::json!({ "kind": "state_generation", "digest": digest.as_str() })
        }
        RetentionObjectV1::ArtifactBlob { digest } => {
            serde_json::json!({ "kind": "artifact_blob", "digest": digest.as_str() })
        }
        RetentionObjectV1::PackObject { digest } => {
            serde_json::json!({ "kind": "pack_object", "digest": digest.as_str() })
        }
        RetentionObjectV1::CanonicalFile { digest } => {
            serde_json::json!({ "kind": "canonical_file", "digest": digest.as_str() })
        }
        RetentionObjectV1::CanonicalSymlink { digest } => {
            serde_json::json!({ "kind": "canonical_symlink", "digest": digest.as_str() })
        }
        RetentionObjectV1::CanonicalTree { digest } => {
            serde_json::json!({ "kind": "canonical_tree", "digest": digest.as_str() })
        }
    }
}

fn retention_authority_json(authority: &RetentionAuthorityInspectionV1) -> serde_json::Value {
    serde_json::json!({
        "history_generations": authority.history_generations(),
        "restore_points": authority.restore_points().iter().map(restore_point_json).collect::<Vec<_>>(),
        "explicit_pins": authority.explicit_pins().iter().map(retention_object_json).collect::<Vec<_>>(),
    })
}

const fn input_kind_name(kind: PrepareInputKindV1) -> &'static str {
    match kind {
        PrepareInputKindV1::Source => "source",
        PrepareInputKindV1::Config => "config",
        PrepareInputKindV1::Lock => "lock",
        PrepareInputKindV1::Component => "component",
        PrepareInputKindV1::Asset => "asset",
        PrepareInputKindV1::Other => "other",
    }
}

fn operation_json(operation: &PrepareOperationV1) -> serde_json::Value {
    match operation {
        PrepareOperationV1::EnsureDirectory {
            authority,
            relative_path,
            mode,
            replace_existing,
        } => serde_json::json!({
            "operation": "ensure_directory",
            "authority": authority.as_str(),
            "relative_path": relative_path,
            "mode": mode,
            "replace_existing": replace_existing,
        }),
        PrepareOperationV1::PlaceFile {
            authority,
            relative_path,
            artifact_id,
            mode,
            replace_existing,
        } => serde_json::json!({
            "operation": "place_file",
            "authority": authority.as_str(),
            "relative_path": relative_path,
            "artifact_id": artifact_id.as_str(),
            "mode": mode,
            "replace_existing": replace_existing,
        }),
        PrepareOperationV1::PlaceSymlink {
            authority,
            relative_path,
            object,
            replace_existing,
        } => serde_json::json!({
            "operation": "place_symlink",
            "authority": authority.as_str(),
            "relative_path": relative_path,
            "object": object.as_str(),
            "replace_existing": replace_existing,
        }),
        PrepareOperationV1::PlaceTree {
            authority,
            relative_path,
            tree,
            archive_provenance,
            replace_existing,
        } => serde_json::json!({
            "operation": "place_tree",
            "authority": authority.as_str(),
            "relative_path": relative_path,
            "tree": tree.as_str(),
            "archive_provenance": archive_provenance.as_ref().map(|provenance| serde_json::json!({
                "payload": provenance.payload().as_str(),
                "decoder": provenance.decoder(),
            })),
            "replace_existing": replace_existing,
        }),
        PrepareOperationV1::RemoveLeaf {
            authority,
            relative_path,
        } => serde_json::json!({
            "operation": "remove_leaf",
            "authority": authority.as_str(),
            "relative_path": relative_path,
        }),
        PrepareOperationV1::AssertAbsent {
            authority,
            relative_path,
        } => serde_json::json!({
            "operation": "assert_absent",
            "authority": authority.as_str(),
            "relative_path": relative_path,
        }),
        PrepareOperationV1::AssertExact {
            authority,
            relative_path,
            state,
        } => serde_json::json!({
            "operation": "assert_exact",
            "authority": authority.as_str(),
            "relative_path": relative_path,
            "state": target_state_json(state),
        }),
    }
}

fn target_state_json(state: &PrepareTargetStateV1) -> serde_json::Value {
    match state {
        PrepareTargetStateV1::File {
            digest,
            byte_len,
            mode,
        } => serde_json::json!({
            "kind": "file",
            "digest": digest.as_str(),
            "byte_len": byte_len,
            "mode": mode,
        }),
        PrepareTargetStateV1::Directory { mode } => serde_json::json!({
            "kind": "directory",
            "mode": mode,
        }),
        PrepareTargetStateV1::Symlink { object } => serde_json::json!({
            "kind": "symlink",
            "object": object.as_str(),
        }),
        PrepareTargetStateV1::Tree {
            tree,
            archive_provenance,
        } => serde_json::json!({
            "kind": "tree",
            "tree": tree.as_str(),
            "archive_provenance": archive_provenance.as_ref().map(|provenance| serde_json::json!({
                "payload": provenance.payload().as_str(),
                "decoder": provenance.decoder(),
            })),
        }),
    }
}

fn commit_request(plan: &PreparedDeploymentV1) -> CommitRequestV1 {
    CommitRequestV1::new(
        plan.plan_id().clone(),
        ApprovalV1::new(plan.plan_id().clone(), plan.approval_digest().clone()),
    )
}

fn seed_committed(env: &TestEnv) -> (Engine, PreparedDeploymentV1, Digest) {
    let engine = env.engine();
    engine.initialize_store().unwrap();
    let plan = engine.prepare_v1(&request()).unwrap();
    let head = engine
        .commit_v1(&commit_request(&plan))
        .unwrap()
        .head()
        .clone();
    (engine, plan, head)
}

fn machine_lifecycle_plan(result: MachineResultV1) -> PreparedDeploymentV1 {
    match result {
        MachineResultV1::Disable(plan)
        | MachineResultV1::Enable(plan)
        | MachineResultV1::RemoveNamespace(plan)
        | MachineResultV1::SetHistoryRetention(plan)
        | MachineResultV1::Pin(plan)
        | MachineResultV1::Unpin(plan)
        | MachineResultV1::AddRestorePoint(plan)
        | MachineResultV1::DropRestorePoint(plan) => plan,
        result => panic!("machine returned a non-lifecycle result: {result:?}"),
    }
}

fn cli_lifecycle_plan(
    env: &TestEnv,
    arguments: &[&str],
    expected: &PreparedDeploymentV1,
) -> PreparedDeploymentV1 {
    let json = run_cli_json(env, arguments);
    assert_eq!(json, plan_json(expected));
    let mut text_arguments = Vec::new();
    let mut arguments = arguments.iter().copied();
    while let Some(argument) = arguments.next() {
        if argument == "--format" {
            assert_eq!(arguments.next(), Some("json"));
            text_arguments.push("--verbose");
        } else {
            text_arguments.push(argument);
        }
    }
    assert_plan_text(&run_cli_text(env, &text_arguments), expected);
    env.engine().plan_v1(expected.plan_id()).unwrap()
}

fn commit_lifecycle_three_ways(
    embedded: &Engine,
    embedded_plan: &PreparedDeploymentV1,
    machine_env: &TestEnv,
    machine_plan: &PreparedDeploymentV1,
    cli_env: &TestEnv,
    cli_plan: &PreparedDeploymentV1,
) {
    let embedded_outcome = embedded.commit_v1(&commit_request(embedded_plan)).unwrap();
    let MachineResultV1::Commit(machine_outcome) = run_machine(
        machine_env,
        &format!("commit-{}", machine_plan.plan_id()),
        MachineRequestV1::Commit(commit_request(machine_plan)),
    ) else {
        panic!("machine lifecycle commit returned another result")
    };
    assert_eq!(machine_outcome, embedded_outcome);
    let cli_outcome = run_cli_json(
        cli_env,
        &[
            "plan",
            "--format",
            "json",
            "apply",
            cli_plan.plan_id().as_str(),
            "--approval",
            cli_plan.approval_digest().as_str(),
        ],
    );
    assert_eq!(
        cli_outcome,
        serde_json::json!({
            "plan_id": embedded_outcome.plan_id().as_str(),
            "namespace": embedded_outcome.namespace().as_str(),
            "previous_generation": embedded_outcome.previous_head().map(Digest::as_str),
            "generation": embedded_outcome.next_head().map(Digest::as_str),
            "removed": embedded_outcome.next_head().is_none(),
        })
    );
}

#[test]
fn embedded_and_human_lock_adapters_publish_the_same_lock_and_result() {
    let embedded_env = TestEnv::new();
    std::fs::write(
        embedded_env.repo().join("malm-pack.kdl"),
        include_bytes!("../schemas/pack/v1/fixtures/valid/minimal.kdl"),
    )
    .unwrap();
    let embedded = embedded_env.engine();
    embedded.initialize_store().unwrap();
    let outcome = embedded
        .create_lock_v1(
            &embedded_env.repo(),
            &LockResolutionInputs::default(),
            &GitAcquisitionConfig::new("/definitely/missing/git").unwrap(),
        )
        .unwrap();
    assert_eq!(outcome.publication(), LockFilePublication::Created);

    let cli_env = TestEnv::new();
    std::fs::write(
        cli_env.repo().join("malm-pack.kdl"),
        include_bytes!("../schemas/pack/v1/fixtures/valid/minimal.kdl"),
    )
    .unwrap();
    assert!(
        cli_env
            .malm_without_repo(&["store", "init"])
            .status
            .success()
    );
    let cli = run_cli_json(
        &cli_env,
        &[
            "source",
            "--format",
            "json",
            "lock",
            "create",
            "--source",
            cli_env.repo().to_str().unwrap(),
            "--git-executable",
            "/definitely/missing/git",
        ],
    );
    let embedded_bytes = std::fs::read(embedded_env.repo().join(LOCK_FILE)).unwrap();
    let cli_bytes = std::fs::read(cli_env.repo().join(LOCK_FILE)).unwrap();
    assert_eq!(cli_bytes, embedded_bytes);
    assert_eq!(decode_lock_v1(&cli_bytes).unwrap(), *outcome.lock());
    assert_eq!(
        cli,
        serde_json::json!({
            "publication": "created",
            "source": cli_env.repo(),
            "git_executable": "/definitely/missing/git",
            "graph_digest": lock_graph_digest(outcome.lock()).as_str(),
            "pack_count": outcome.lock().nodes().len(),
        })
    );
}

#[test]
fn engine_and_machine_prepare_the_same_resolved_request_while_cli_consumes_the_same_durable_review_projection()
 {
    let embedded_env = TestEnv::new();
    let embedded = embedded_env.engine();
    embedded.initialize_store().unwrap();
    let embedded_plan = embedded.prepare_v1(&request()).unwrap();
    let artifact_id = ArtifactId::new("parity/result").unwrap();
    let embedded_artifact = embedded
        .artifact_v1(embedded_plan.plan_id(), &artifact_id)
        .unwrap();

    let machine_env = TestEnv::new();
    assert_eq!(
        run_machine(
            &machine_env,
            "initialize",
            MachineRequestV1::InitializeStore
        ),
        MachineResultV1::InitializeStore
    );
    let MachineResultV1::Prepare(machine_plan) = run_machine(
        &machine_env,
        "prepare",
        MachineRequestV1::Prepare(request()),
    ) else {
        panic!("machine prepare returned another result")
    };
    assert_eq!(machine_plan, embedded_plan);
    let MachineResultV1::Plan(machine_reloaded) = run_machine(
        &machine_env,
        "plan",
        MachineRequestV1::Plan(machine_plan.plan_id().clone()),
    ) else {
        panic!("machine plan returned another result")
    };
    assert_eq!(machine_reloaded, embedded_plan);
    let MachineResultV1::Artifact(machine_artifact) = run_machine(
        &machine_env,
        "artifact",
        MachineRequestV1::Artifact {
            plan_id: machine_plan.plan_id().clone(),
            artifact_id: artifact_id.clone(),
        },
    ) else {
        panic!("machine artifact returned another result")
    };
    assert_eq!(machine_artifact, embedded_artifact);

    let cli_env = TestEnv::new();
    let initialized = cli_env.malm_without_repo(&["store", "init"]);
    assert!(
        initialized.status.success(),
        "{}",
        String::from_utf8_lossy(&initialized.stderr)
    );
    let cli_seed = cli_env.engine();
    let cli_plan = cli_seed.prepare_v1(&request()).unwrap();
    assert_eq!(cli_plan, embedded_plan);
    drop(cli_seed);
    assert_eq!(
        run_cli_json(
            &cli_env,
            &[
                "plan",
                "--format",
                "json",
                "show",
                cli_plan.plan_id().as_str()
            ],
        ),
        plan_json(&embedded_plan)
    );
    let concise = run_cli_text(&cli_env, &["plan", "show", cli_plan.plan_id().as_str()]);
    assert_contains(&concise, "Approval required  1");
    assert_contains(&concise, "approval finding shared by every adapter");
    assert_contains(&concise, "Advisories  1");
    assert_contains(&concise, "Advisory finding shared by every adapter");
    assert!(!concise.contains("adapter-advisory"), "{concise}");
    assert!(!concise.contains("Technical"), "{concise}");
    assert_plan_text(
        &run_cli_text(
            &cli_env,
            &["plan", "--verbose", "show", cli_plan.plan_id().as_str()],
        ),
        &embedded_plan,
    );
    let exported = cli_env.repo().join("parity-result");
    assert_eq!(
        run_cli_json(
            &cli_env,
            &[
                "plan",
                "--format",
                "json",
                "artifact",
                "export",
                cli_plan.plan_id().as_str(),
                artifact_id.as_str(),
                "--output",
                exported.to_str().unwrap(),
            ]
        ),
        serde_json::json!({
            "artifact_id": embedded_artifact.descriptor().id().as_str(),
            "digest": embedded_artifact.descriptor().digest().as_str(),
            "byte_len": embedded_artifact.descriptor().byte_len(),
            "media_type": embedded_artifact.descriptor().media_type(),
            "output": exported,
        })
    );
    assert_eq!(std::fs::read(&exported).unwrap(), embedded_artifact.bytes());

    let embedded_outcome = embedded.commit_v1(&commit_request(&embedded_plan)).unwrap();
    let MachineResultV1::Commit(machine_outcome) = run_machine(
        &machine_env,
        "commit",
        MachineRequestV1::Commit(commit_request(&machine_plan)),
    ) else {
        panic!("machine commit returned another result")
    };
    assert_eq!(machine_outcome, embedded_outcome);
    assert_eq!(
        run_cli_json(
            &cli_env,
            &[
                "plan",
                "--format",
                "json",
                "apply",
                cli_plan.plan_id().as_str(),
                "--approval",
                cli_plan.approval_digest().as_str(),
            ]
        ),
        serde_json::json!({
            "plan_id": embedded_outcome.plan_id().as_str(),
            "namespace": embedded_outcome.namespace().as_str(),
            "previous_generation": embedded_outcome.previous_head().map(Digest::as_str),
            "generation": embedded_outcome.next_head().map(Digest::as_str),
            "removed": false,
        })
    );

    let embedded_state = embedded
        .inspect_state_v1(embedded_outcome.namespace())
        .unwrap();
    let MachineResultV1::State(machine_state) = run_machine(
        &machine_env,
        "state",
        MachineRequestV1::State(embedded_outcome.namespace().clone()),
    ) else {
        panic!("machine state returned another result")
    };
    assert_eq!(machine_state, embedded_state);
    let cli_state = run_cli_json(
        &cli_env,
        &[
            "namespace",
            "--format",
            "json",
            "show",
            "--namespace",
            "workstation",
        ],
    );
    assert_eq!(cli_state["namespace"], embedded_state.namespace().as_str());
    assert_eq!(
        cli_state["head"],
        serde_json::to_value(embedded_state.head().map(Digest::as_str)).unwrap()
    );
    assert!(embedded_env.state_root().join("descriptor.json").is_file());
    assert!(machine_env.state_root().join("descriptor.json").is_file());
    assert!(cli_env.state_root().join("descriptor.json").is_file());
}

#[test]
fn persisted_transform_diagnostics_are_equivalent_in_machine_json_and_actual_human_text() {
    let env = TestEnv::new();
    let plan_id = seed_diagnostic_plan(&env);
    let embedded = env.engine().plan_v1(&plan_id).unwrap();
    assert_eq!(embedded.transforms().len(), 1);
    assert_eq!(embedded.transforms()[0].diagnostics().len(), 2);

    let MachineResultV1::Plan(machine) = run_machine(
        &env,
        "diagnostic-plan",
        MachineRequestV1::Plan(plan_id.clone()),
    ) else {
        panic!("machine diagnostic plan returned another result")
    };
    assert_eq!(machine, embedded);
    assert_eq!(
        run_cli_json(
            &env,
            &["plan", "--format", "json", "show", plan_id.as_str()],
        ),
        plan_json(&embedded)
    );
    let plan_text = run_cli_text(&env, &["plan", "--verbose", "show", plan_id.as_str()]);
    assert_plan_text(&plan_text, &embedded);

    let request =
        PreparedPlanInspectionRequestV1::with_limits(plan_id.clone(), 4096, 512 * 1024 * 1024)
            .unwrap();
    let embedded_provenance = env
        .engine()
        .inspect_transform_provenance_v1(&request)
        .unwrap();
    let MachineResultV1::TransformProvenance(machine_provenance) = run_machine(
        &env,
        "diagnostic-provenance",
        MachineRequestV1::TransformProvenance(request),
    ) else {
        panic!("machine diagnostic provenance returned another result")
    };
    assert_eq!(machine_provenance, embedded_provenance);
    let json = run_cli_json(
        &env,
        &["plan", "--format", "json", "transforms", plan_id.as_str()],
    );
    assert_eq!(json["plan_id"], plan_id.as_str());
    assert_eq!(json["transforms"], plan_json(&embedded)["transforms"]);
    let text = run_cli_text(&env, &["plan", "transforms", plan_id.as_str()]);
    assert_contains(&text, human_plan(&plan_id));
    assert_transform_text(&text, &embedded.transforms()[0]);
}

#[test]
fn human_review_text_exposes_archive_exact_snapshot_and_tree_identities() {
    let env = TestEnv::new();
    let engine = env.engine();
    engine.initialize_store().unwrap();
    publish_request_tree(&engine);
    let plan = engine.prepare_v1(&review_request()).unwrap();

    let MachineResultV1::Plan(machine_plan) = run_machine(
        &env,
        "human-review-plan",
        MachineRequestV1::Plan(plan.plan_id().clone()),
    ) else {
        panic!("machine human-review plan returned another result")
    };
    assert_eq!(machine_plan, plan);
    assert_eq!(
        run_cli_json(
            &env,
            &["plan", "--format", "json", "show", plan.plan_id().as_str()],
        ),
        plan_json(&plan)
    );
    assert_plan_text(
        &run_cli_text(
            &env,
            &["plan", "--verbose", "show", plan.plan_id().as_str()],
        ),
        &plan,
    );

    let outcome = engine.commit_v1(&commit_request(&plan)).unwrap();
    let desired_request = DesiredSnapshotInspectionRequestV1::with_limits(
        NamespaceName::new("review").unwrap(),
        outcome.head().clone(),
        4096,
        512 * 1024 * 1024,
    )
    .unwrap();
    let desired = engine
        .inspect_desired_snapshot_v1(&desired_request)
        .unwrap();
    let MachineResultV1::DesiredSnapshot(machine_desired) = run_machine(
        &env,
        "human-review-snapshot",
        MachineRequestV1::DesiredSnapshot(desired_request),
    ) else {
        panic!("machine human-review snapshot returned another result")
    };
    assert_eq!(machine_desired, desired);
    let desired_text = run_cli_text(
        &env,
        &[
            "namespace",
            "generation",
            "desired",
            outcome.head().as_str(),
            "--namespace",
            "review",
        ],
    );
    assert_contains(&desired_text, desired.namespace());
    assert_contains(&desired_text, human_digest("gen", desired.generation()));
    assert_eq!(desired.targets().len(), 2);
    for target in desired.targets() {
        assert_contains(&desired_text, target.authority());
        assert_contains(&desired_text, target.relative_path());
        match target.state() {
            malm_types::DesiredTargetStateInspectionV1::File {
                digest,
                byte_len,
                mode,
            } => {
                assert_contains(
                    &desired_text,
                    human_digest("file", digest.as_ref().unwrap()),
                );
                assert_contains(&desired_text, byte_len.unwrap());
                assert_contains(&desired_text, format!("{:04o}", mode.unwrap()));
            }
            malm_types::DesiredTargetStateInspectionV1::Tree {
                tree,
                archive_provenance,
            } => {
                assert_contains(&desired_text, human_digest("tree", tree.as_ref().unwrap()));
                let provenance = archive_provenance.as_ref().unwrap();
                assert_contains(&desired_text, provenance.payload());
                assert_contains(&desired_text, provenance.decoder());
            }
            state => panic!("unexpected review desired state: {state:?}"),
        }
    }

    let (_, tree_digest) = request_tree();
    let tree_request =
        CanonicalTreeInspectionRequestV1::with_limits(tree_digest.clone(), 4096, 512 * 1024 * 1024)
            .unwrap();
    let tree = engine.inspect_canonical_tree_v1(&tree_request).unwrap();
    let MachineResultV1::CanonicalTree(machine_tree) = run_machine(
        &env,
        "human-review-tree",
        MachineRequestV1::CanonicalTree(tree_request),
    ) else {
        panic!("machine human-review tree returned another result")
    };
    assert_eq!(machine_tree, tree);
    let tree_text = run_cli_text(&env, &["object", "tree", "show", tree_digest.as_str()]);
    assert_contains(&tree_text, human_digest("tree", &tree_digest));
    assert_contains(&tree_text, format!("{:04o}", tree.root_mode()));
    for entry in tree.entries() {
        assert_contains(&tree_text, entry.relative_path());
        assert_contains(&tree_text, format!("{:04o}", entry.mode()));
        if let malm_types::CanonicalTreeEntryKindInspectionV1::File { digest, byte_len } =
            entry.kind()
        {
            assert_contains(&tree_text, human_digest("file", digest));
            assert_contains(&tree_text, byte_len);
        }
    }

    let retention = engine
        .prepare_history_retention_v1(
            &HistoryRetentionRequestV1::new(NamespaceName::new("review").unwrap(), 8).unwrap(),
        )
        .unwrap();
    assert!(retention.operations().iter().any(|operation| matches!(
        operation,
        PrepareOperationV1::AssertExact {
            state: PrepareTargetStateV1::Tree {
                archive_provenance: Some(_),
                ..
            },
            ..
        }
    )));
    let text = run_cli_text(
        &env,
        &["plan", "--verbose", "show", retention.plan_id().as_str()],
    );
    assert_plan_text(&text, &retention);
    assert_contains(&text, retention.plan_id());
    assert_contains(&text, retention.graph_digest());
    assert_contains(&text, retention.approval_digest());
    for operation in retention.operations() {
        if let PrepareOperationV1::AssertExact {
            authority,
            relative_path,
            state,
        } = operation
        {
            assert_contains(&text, authority);
            assert_contains(&text, relative_path);
            assert_target_state_text(&text, state);
        }
    }
}

#[test]
fn lifecycle_retention_and_inspection_have_equivalent_embedded_machine_and_human_views() {
    let embedded_env = TestEnv::new();
    let machine_env = TestEnv::new();
    let cli_env = TestEnv::new();
    let (embedded, embedded_seed, initial_head) = seed_committed(&embedded_env);
    let (machine_engine, machine_seed, machine_head) = seed_committed(&machine_env);
    let (cli_engine, cli_seed, cli_head) = seed_committed(&cli_env);
    assert_eq!(machine_seed, embedded_seed);
    assert_eq!(cli_seed, embedded_seed);
    assert_eq!(machine_head, initial_head);
    assert_eq!(cli_head, initial_head);
    let (_, tree_digest) = request_tree();
    publish_request_tree(&embedded);
    publish_request_tree(&machine_engine);
    publish_request_tree(&cli_engine);

    let namespace = NamespaceName::new("workstation").unwrap();
    let decoded_limit = 1024 * 1024;
    let catalog_request = CatalogInspectionRequestV1::with_limits(4096, decoded_limit).unwrap();
    let embedded_catalog = embedded.inspect_catalog_v1(&catalog_request).unwrap();
    let MachineResultV1::Catalog(machine_catalog) = run_machine(
        &machine_env,
        "inspect-catalog",
        MachineRequestV1::Catalog(catalog_request),
    ) else {
        panic!("machine catalog returned another result")
    };
    assert_eq!(machine_catalog, embedded_catalog);
    let cli_catalog = run_cli_json(&cli_env, &["namespace", "--format", "json", "list"]);
    assert_eq!(cli_catalog["digest"], embedded_catalog.digest().as_str());
    assert_eq!(cli_catalog["namespaces"][0]["namespace"], "workstation");
    assert_eq!(
        cli_catalog["namespaces"][0]["generation"],
        initial_head.as_str()
    );

    let namespace_request =
        NamespaceInspectionRequestV1::with_limit(namespace.clone(), decoded_limit).unwrap();
    let embedded_namespace = embedded.inspect_namespace_v1(&namespace_request).unwrap();
    let MachineResultV1::Namespace(machine_namespace) = run_machine(
        &machine_env,
        "inspect-namespace",
        MachineRequestV1::Namespace(namespace_request),
    ) else {
        panic!("machine namespace returned another result")
    };
    assert_eq!(machine_namespace, embedded_namespace);
    let cli_namespace = run_cli_json(
        &cli_env,
        &[
            "namespace",
            "--format",
            "json",
            "show",
            "--namespace",
            "workstation",
        ],
    );
    assert_eq!(cli_namespace["head"], initial_head.as_str());
    assert_eq!(
        cli_namespace["generation"]["generation"],
        initial_head.as_str()
    );

    let history_request =
        NamespaceHistoryRequestV1::with_limits(namespace.clone(), 4096, decoded_limit).unwrap();
    let embedded_history = embedded
        .inspect_namespace_history_v1(&history_request)
        .unwrap();
    let MachineResultV1::History(machine_history) = run_machine(
        &machine_env,
        "inspect-history",
        MachineRequestV1::History(history_request),
    ) else {
        panic!("machine history returned another result")
    };
    assert_eq!(machine_history, embedded_history);
    let cli_history = run_cli_json(
        &cli_env,
        &[
            "namespace",
            "--format",
            "json",
            "history",
            "--namespace",
            "workstation",
        ],
    );
    assert_eq!(cli_history["head"], initial_head.as_str());
    assert_eq!(cli_history["generations"].as_array().unwrap().len(), 1);

    let generation_request = GenerationInspectionRequestV1::with_limits(
        namespace.clone(),
        initial_head.clone(),
        4096,
        decoded_limit,
    )
    .unwrap();
    let embedded_generation = embedded
        .inspect_generation_details_v1(&generation_request)
        .unwrap();
    let MachineResultV1::Generation(machine_generation) = run_machine(
        &machine_env,
        "inspect-generation",
        MachineRequestV1::Generation(generation_request.clone()),
    ) else {
        panic!("machine generation returned another result")
    };
    assert_eq!(machine_generation, embedded_generation);
    let cli_generation = run_cli_json(
        &cli_env,
        &[
            "namespace",
            "--format",
            "json",
            "generation",
            "show",
            initial_head.as_str(),
            "--namespace",
            "workstation",
        ],
    );
    assert_eq!(cli_generation["generation"], initial_head.as_str());
    assert_eq!(cli_generation["retention"]["history_generations"], 256);

    let desired_request = DesiredSnapshotInspectionRequestV1::with_limits(
        namespace.clone(),
        initial_head.clone(),
        4096,
        decoded_limit,
    )
    .unwrap();
    let embedded_desired = embedded
        .inspect_desired_snapshot_v1(&desired_request)
        .unwrap();
    let MachineResultV1::DesiredSnapshot(machine_desired) = run_machine(
        &machine_env,
        "inspect-desired-snapshot",
        MachineRequestV1::DesiredSnapshot(desired_request),
    ) else {
        panic!("machine desired snapshot returned another result")
    };
    assert_eq!(machine_desired, embedded_desired);
    let cli_desired = run_cli_json(
        &cli_env,
        &[
            "namespace",
            "--format",
            "json",
            "generation",
            "desired",
            initial_head.as_str(),
            "--namespace",
            "workstation",
        ],
    );
    assert_eq!(cli_desired["digest"], embedded_desired.digest().as_str());
    assert_eq!(
        cli_desired["targets"].as_array().unwrap().len(),
        embedded_desired.targets().len()
    );
    let desired_text = run_cli_text(
        &cli_env,
        &[
            "namespace",
            "generation",
            "desired",
            initial_head.as_str(),
            "--namespace",
            "workstation",
        ],
    );
    assert_contains(&desired_text, embedded_desired.namespace());
    assert_contains(
        &desired_text,
        human_digest("gen", embedded_desired.generation()),
    );
    for target in embedded_desired.targets() {
        assert_contains(&desired_text, target.authority());
        assert_contains(&desired_text, target.relative_path());
        match target.state() {
            malm_types::DesiredTargetStateInspectionV1::File {
                digest,
                byte_len,
                mode,
            } => {
                assert_contains(
                    &desired_text,
                    human_digest("file", digest.as_ref().unwrap()),
                );
                assert_contains(&desired_text, byte_len.unwrap());
                assert_contains(&desired_text, format!("{:04o}", mode.unwrap()));
            }
            malm_types::DesiredTargetStateInspectionV1::Tree {
                tree,
                archive_provenance,
            } => {
                assert_contains(&desired_text, human_digest("tree", tree.as_ref().unwrap()));
                let provenance = archive_provenance.as_ref().unwrap();
                assert_contains(&desired_text, provenance.payload());
                assert_contains(&desired_text, provenance.decoder());
            }
            state => panic!("unexpected desired-state fixture: {state:?}"),
        }
    }

    let tree_request =
        CanonicalTreeInspectionRequestV1::with_limits(tree_digest.clone(), 4096, decoded_limit)
            .unwrap();
    let embedded_tree = embedded.inspect_canonical_tree_v1(&tree_request).unwrap();
    let MachineResultV1::CanonicalTree(machine_tree) = run_machine(
        &machine_env,
        "inspect-canonical-tree",
        MachineRequestV1::CanonicalTree(tree_request),
    ) else {
        panic!("machine canonical tree returned another result")
    };
    assert_eq!(machine_tree, embedded_tree);
    let cli_tree = run_cli_json(
        &cli_env,
        &[
            "object",
            "--format",
            "json",
            "tree",
            "show",
            tree_digest.as_str(),
        ],
    );
    assert_eq!(cli_tree["tree"], tree_digest.as_str());
    assert_eq!(cli_tree["root_mode"], 0o750);
    assert_eq!(cli_tree["entries"].as_array().unwrap().len(), 1);
    let tree_text = run_cli_text(&cli_env, &["object", "tree", "show", tree_digest.as_str()]);
    assert_contains(&tree_text, human_digest("tree", &tree_digest));
    assert_contains(&tree_text, "0750");
    for entry in embedded_tree.entries() {
        assert_contains(&tree_text, entry.relative_path());
        assert_contains(&tree_text, format!("{:04o}", entry.mode()));
        match entry.kind() {
            malm_types::CanonicalTreeEntryKindInspectionV1::File { digest, byte_len } => {
                assert_contains(&tree_text, human_digest("file", digest));
                assert_contains(&tree_text, byte_len);
            }
            malm_types::CanonicalTreeEntryKindInspectionV1::Directory { digest } => {
                assert_contains(&tree_text, human_digest("tree", digest));
            }
            malm_types::CanonicalTreeEntryKindInspectionV1::Symlink { digest } => {
                assert_contains(&tree_text, human_digest("symlink", digest));
            }
        }
    }

    let artifact_id = ArtifactId::new("parity/result").unwrap();
    let metadata_request = ArtifactMetadataInspectionRequestV1::with_limit(
        embedded_seed.plan_id().clone(),
        artifact_id,
        decoded_limit,
    )
    .unwrap();
    let embedded_metadata = embedded
        .inspect_artifact_metadata_v1(&metadata_request)
        .unwrap();
    let MachineResultV1::ArtifactMetadata(machine_metadata) = run_machine(
        &machine_env,
        "inspect-artifact-metadata",
        MachineRequestV1::ArtifactMetadata(metadata_request),
    ) else {
        panic!("machine artifact metadata returned another result")
    };
    assert_eq!(machine_metadata, embedded_metadata);
    let cli_metadata = run_cli_json(
        &cli_env,
        &[
            "plan",
            "--format",
            "json",
            "artifact",
            "show",
            embedded_seed.plan_id().as_str(),
            "parity/result",
        ],
    );
    assert_eq!(
        cli_metadata["descriptor"]["digest"],
        embedded_metadata.descriptor().digest().as_str()
    );

    let plan_request = PreparedPlanInspectionRequestV1::with_limits(
        embedded_seed.plan_id().clone(),
        4096,
        decoded_limit,
    )
    .unwrap();
    let embedded_inputs = embedded.inspect_captured_inputs_v1(&plan_request).unwrap();
    let MachineResultV1::CapturedInputs(machine_inputs) = run_machine(
        &machine_env,
        "inspect-captured-inputs",
        MachineRequestV1::CapturedInputs(plan_request.clone()),
    ) else {
        panic!("machine captured inputs returned another result")
    };
    assert_eq!(machine_inputs, embedded_inputs);
    let cli_inputs = run_cli_json(
        &cli_env,
        &[
            "plan",
            "--format",
            "json",
            "inputs",
            embedded_seed.plan_id().as_str(),
        ],
    );
    assert_eq!(cli_inputs["inputs"].as_array().unwrap().len(), 1);
    assert_eq!(
        cli_inputs["graph_digest"],
        embedded_seed.graph_digest().as_str()
    );

    let embedded_provenance = embedded
        .inspect_transform_provenance_v1(&plan_request)
        .unwrap();
    let MachineResultV1::TransformProvenance(machine_provenance) = run_machine(
        &machine_env,
        "inspect-transform-provenance",
        MachineRequestV1::TransformProvenance(plan_request),
    ) else {
        panic!("machine transform provenance returned another result")
    };
    assert_eq!(machine_provenance, embedded_provenance);
    let cli_provenance = run_cli_json(
        &cli_env,
        &[
            "plan",
            "--format",
            "json",
            "transforms",
            embedded_seed.plan_id().as_str(),
        ],
    );
    assert_eq!(cli_provenance["transforms"], serde_json::json!([]));
    let provenance_text = run_cli_text(
        &cli_env,
        &["plan", "transforms", embedded_seed.plan_id().as_str()],
    );
    assert_contains(&provenance_text, human_plan(embedded_seed.plan_id()));

    let embedded_retention = embedded
        .inspect_retention_authority_v1(&generation_request)
        .unwrap();
    let MachineResultV1::Retention(machine_retention) = run_machine(
        &machine_env,
        "inspect-retention",
        MachineRequestV1::Retention(generation_request.clone()),
    ) else {
        panic!("machine retention returned another result")
    };
    assert_eq!(machine_retention, embedded_retention);
    let cli_retention = run_cli_json(
        &cli_env,
        &[
            "namespace",
            "--format",
            "json",
            "generation",
            "retention",
            initial_head.as_str(),
            "--namespace",
            "workstation",
        ],
    );
    assert_eq!(cli_retention["authority"]["history_generations"], 256);

    let embedded_tracking = embedded.inspect_tracking_v1(&generation_request).unwrap();
    let MachineResultV1::Tracking(machine_tracking) = run_machine(
        &machine_env,
        "inspect-tracking",
        MachineRequestV1::Tracking(generation_request),
    ) else {
        panic!("machine tracking returned another result")
    };
    assert_eq!(machine_tracking, embedded_tracking);
    let cli_tracking = run_cli_json(
        &cli_env,
        &[
            "namespace",
            "--format",
            "json",
            "generation",
            "tracking",
            initial_head.as_str(),
            "--namespace",
            "workstation",
        ],
    );
    assert_eq!(cli_tracking["tracked_root"], serde_json::Value::Null);

    let status_request =
        NamespaceStatusRequestV1::with_limits(namespace.clone(), 4096, decoded_limit).unwrap();
    let embedded_status = embedded
        .inspect_namespace_status_v1(&status_request)
        .unwrap();
    let MachineResultV1::Status(machine_status) = run_machine(
        &machine_env,
        "inspect-status",
        MachineRequestV1::Status(status_request),
    ) else {
        panic!("machine status returned another result")
    };
    assert_eq!(machine_status, embedded_status);
    let cli_status = run_cli_json(
        &cli_env,
        &[
            "namespace",
            "--format",
            "json",
            "status",
            "--namespace",
            "workstation",
        ],
    );
    assert_eq!(cli_status["status"], "enabled_exact");
    assert_eq!(cli_status["targets"], serde_json::json!([]));

    let fsck_request = FsckRequestV1::with_limits(4096, 4096, decoded_limit).unwrap();
    let embedded_fsck = embedded.fsck_v1(&fsck_request).unwrap();
    let MachineResultV1::Fsck(machine_fsck) = run_machine(
        &machine_env,
        "inspect-fsck",
        MachineRequestV1::Fsck(fsck_request),
    ) else {
        panic!("machine fsck returned another result")
    };
    assert_eq!(machine_fsck, embedded_fsck);
    let cli_fsck = run_cli_json(&cli_env, &["store", "--format", "json", "verify"]);
    assert_eq!(cli_fsck["clean"], embedded_fsck.is_clean());
    assert_eq!(
        cli_fsck["checked_generations"],
        embedded_fsck.checked_generations()
    );

    let retention_request = HistoryRetentionRequestV1::new(namespace.clone(), 8).unwrap();
    let embedded_plan = embedded
        .prepare_history_retention_v1(&retention_request)
        .unwrap();
    let machine_plan = machine_lifecycle_plan(run_machine(
        &machine_env,
        "set-history-retention",
        MachineRequestV1::SetHistoryRetention(retention_request),
    ));
    assert_eq!(machine_plan, embedded_plan);
    let cli_plan = cli_lifecycle_plan(
        &cli_env,
        &[
            "plan",
            "--format",
            "json",
            "retention",
            "set-history",
            "8",
            "--namespace",
            "workstation",
        ],
        &embedded_plan,
    );
    assert_eq!(cli_plan, embedded_plan);
    commit_lifecycle_three_ways(
        &embedded,
        &embedded_plan,
        &machine_env,
        &machine_plan,
        &cli_env,
        &cli_plan,
    );

    let pinned = RetentionObjectV1::StateGeneration {
        digest: initial_head.clone(),
    };
    let pin_request = RetentionPinRequestV1::new(namespace.clone(), pinned.clone());
    let embedded_plan = embedded.prepare_pin_v1(&pin_request).unwrap();
    let machine_plan = machine_lifecycle_plan(run_machine(
        &machine_env,
        "pin-generation",
        MachineRequestV1::Pin(pin_request),
    ));
    assert_eq!(machine_plan, embedded_plan);
    let cli_plan = cli_lifecycle_plan(
        &cli_env,
        &[
            "plan",
            "--format",
            "json",
            "retention",
            "pin",
            "state-generation",
            initial_head.as_str(),
            "--namespace",
            "workstation",
        ],
        &embedded_plan,
    );
    assert_eq!(cli_plan, embedded_plan);
    commit_lifecycle_three_ways(
        &embedded,
        &embedded_plan,
        &machine_env,
        &machine_plan,
        &cli_env,
        &cli_plan,
    );

    let unpin_request = RetentionPinRequestV1::new(namespace.clone(), pinned);
    let embedded_plan = embedded.prepare_unpin_v1(&unpin_request).unwrap();
    let machine_plan = machine_lifecycle_plan(run_machine(
        &machine_env,
        "unpin-generation",
        MachineRequestV1::Unpin(unpin_request),
    ));
    assert_eq!(machine_plan, embedded_plan);
    let cli_plan = cli_lifecycle_plan(
        &cli_env,
        &[
            "plan",
            "--format",
            "json",
            "retention",
            "unpin",
            "state-generation",
            initial_head.as_str(),
            "--namespace",
            "workstation",
        ],
        &embedded_plan,
    );
    assert_eq!(cli_plan, embedded_plan);
    commit_lifecycle_three_ways(
        &embedded,
        &embedded_plan,
        &machine_env,
        &machine_plan,
        &cli_env,
        &cli_plan,
    );

    let restore_request = RestorePointRequestV1::new(namespace.clone(), initial_head.clone());
    let embedded_plan = embedded.prepare_restore_point_v1(&restore_request).unwrap();
    let machine_plan = machine_lifecycle_plan(run_machine(
        &machine_env,
        "add-restore-point",
        MachineRequestV1::AddRestorePoint(restore_request),
    ));
    assert_eq!(machine_plan, embedded_plan);
    let cli_plan = cli_lifecycle_plan(
        &cli_env,
        &[
            "plan",
            "--format",
            "json",
            "retention",
            "restore-point",
            "add",
            initial_head.as_str(),
            "--namespace",
            "workstation",
        ],
        &embedded_plan,
    );
    assert_eq!(cli_plan, embedded_plan);
    commit_lifecycle_three_ways(
        &embedded,
        &embedded_plan,
        &machine_env,
        &machine_plan,
        &cli_env,
        &cli_plan,
    );

    let drop_request = RestorePointRequestV1::new(namespace.clone(), initial_head.clone());
    let embedded_plan = embedded
        .prepare_drop_restore_point_v1(&drop_request)
        .unwrap();
    let machine_plan = machine_lifecycle_plan(run_machine(
        &machine_env,
        "drop-restore-point",
        MachineRequestV1::DropRestorePoint(drop_request),
    ));
    assert_eq!(machine_plan, embedded_plan);
    let cli_plan = cli_lifecycle_plan(
        &cli_env,
        &[
            "plan",
            "--format",
            "json",
            "retention",
            "restore-point",
            "drop",
            initial_head.as_str(),
            "--namespace",
            "workstation",
        ],
        &embedded_plan,
    );
    assert_eq!(cli_plan, embedded_plan);
    commit_lifecycle_three_ways(
        &embedded,
        &embedded_plan,
        &machine_env,
        &machine_plan,
        &cli_env,
        &cli_plan,
    );

    let disable_request = LifecycleRequestV1::new(namespace.clone());
    let embedded_plan = embedded.prepare_disable_v1(&disable_request).unwrap();
    let machine_plan = machine_lifecycle_plan(run_machine(
        &machine_env,
        "disable-namespace",
        MachineRequestV1::Disable(disable_request),
    ));
    assert_eq!(machine_plan, embedded_plan);
    let cli_plan = cli_lifecycle_plan(
        &cli_env,
        &[
            "plan",
            "--format",
            "json",
            "disable",
            "--namespace",
            "workstation",
        ],
        &embedded_plan,
    );
    assert_eq!(cli_plan, embedded_plan);
    commit_lifecycle_three_ways(
        &embedded,
        &embedded_plan,
        &machine_env,
        &machine_plan,
        &cli_env,
        &cli_plan,
    );

    let enable_request = LifecycleRequestV1::new(namespace.clone());
    let embedded_plan = embedded.prepare_enable_v1(&enable_request).unwrap();
    let machine_plan = machine_lifecycle_plan(run_machine(
        &machine_env,
        "enable-namespace",
        MachineRequestV1::Enable(enable_request),
    ));
    assert_eq!(machine_plan, embedded_plan);
    let cli_plan = cli_lifecycle_plan(
        &cli_env,
        &[
            "plan",
            "--format",
            "json",
            "enable",
            "--namespace",
            "workstation",
        ],
        &embedded_plan,
    );
    assert_eq!(cli_plan, embedded_plan);
    commit_lifecycle_three_ways(
        &embedded,
        &embedded_plan,
        &machine_env,
        &machine_plan,
        &cli_env,
        &cli_plan,
    );

    let removal_request =
        NamespaceRemovalRequestV1::new(namespace, NamespaceRemovalHistoryV1::Drop);
    let embedded_plan = embedded
        .prepare_namespace_removal_v1(&removal_request)
        .unwrap();
    let machine_plan = machine_lifecycle_plan(run_machine(
        &machine_env,
        "remove-namespace",
        MachineRequestV1::RemoveNamespace(removal_request),
    ));
    assert_eq!(machine_plan, embedded_plan);
    let cli_plan = cli_lifecycle_plan(
        &cli_env,
        &[
            "plan",
            "--format",
            "json",
            "remove",
            "--namespace",
            "workstation",
        ],
        &embedded_plan,
    );
    assert_eq!(cli_plan, embedded_plan);
    commit_lifecycle_three_ways(
        &embedded,
        &embedded_plan,
        &machine_env,
        &machine_plan,
        &cli_env,
        &cli_plan,
    );
    assert!(
        embedded
            .inspect_state_v1(&NamespaceName::new("workstation").unwrap())
            .unwrap()
            .head()
            .is_none()
    );
}

#[test]
fn store_status_checkout_recover_and_prune_are_equivalent_across_all_adapters() {
    let embedded_status_env = TestEnv::new();
    let embedded_status = embedded_status_env.engine();
    assert_eq!(embedded_status.store_status().unwrap(), StoreStatus::Absent);

    let machine_status_env = TestEnv::new();
    assert_eq!(
        run_machine(
            &machine_status_env,
            "store-status-absent",
            MachineRequestV1::StoreStatus,
        ),
        MachineResultV1::StoreStatus(StoreStatusV1::Absent)
    );
    let cli_status_env = TestEnv::new();
    let cli_status = run_cli_text(&cli_status_env, &["store", "status"]);
    assert_contains(&cli_status, "Store is not initialized");
    assert_contains(&cli_status, "absent");

    embedded_status.initialize_store().unwrap();
    assert_eq!(embedded_status.store_status().unwrap(), StoreStatus::Ready);
    assert_eq!(
        run_machine(
            &machine_status_env,
            "store-initialize",
            MachineRequestV1::InitializeStore,
        ),
        MachineResultV1::InitializeStore
    );
    assert_eq!(
        run_machine(
            &machine_status_env,
            "store-status-ready",
            MachineRequestV1::StoreStatus,
        ),
        MachineResultV1::StoreStatus(StoreStatusV1::Ready)
    );
    let initialized = run_cli_text(&cli_status_env, &["store", "init"]);
    assert_contains(&initialized, "Store is ready");
    assert_contains(&initialized, "ready");
    let cli_status = run_cli_text(&cli_status_env, &["store", "status"]);
    assert_contains(&cli_status, "Store is ready");
    assert_contains(&cli_status, "ready");

    let embedded_env = TestEnv::new();
    let machine_env = TestEnv::new();
    let cli_env = TestEnv::new();
    let (embedded, _, head) = seed_committed(&embedded_env);
    let (machine_engine, _, machine_head) = seed_committed(&machine_env);
    let (cli_engine, _, cli_head) = seed_committed(&cli_env);
    assert_eq!(machine_head, head);
    assert_eq!(cli_head, head);

    let checkout_request =
        CheckoutRequestV1::new(NamespaceName::new("workstation").unwrap(), head.clone());
    let embedded_checkout = embedded.prepare_checkout_v1(&checkout_request).unwrap();
    let MachineResultV1::Checkout(machine_checkout) = run_machine(
        &machine_env,
        "checkout",
        MachineRequestV1::Checkout(checkout_request),
    ) else {
        panic!("machine checkout returned another result")
    };
    assert_eq!(machine_checkout, embedded_checkout);
    assert_eq!(
        run_cli_json(
            &cli_env,
            &[
                "plan",
                "--format",
                "json",
                "restore",
                head.as_str(),
                "--namespace",
                "workstation",
            ],
        ),
        plan_json(&embedded_checkout)
    );
    assert_eq!(
        cli_engine.plan_v1(embedded_checkout.plan_id()).unwrap(),
        embedded_checkout
    );

    assert_eq!(
        embedded.recover_v1().unwrap(),
        malm::RecoveryOutcomeV1::NoTransaction
    );
    assert_eq!(
        run_machine(&machine_env, "recover", MachineRequestV1::Recover),
        MachineResultV1::Recover(malm::RecoveryOutcomeV1::NoTransaction)
    );
    assert_eq!(
        run_cli_json(&cli_env, &["store", "--format", "json", "recover"]),
        serde_json::json!({
            "status": "no_transaction",
        })
    );

    let embedded_plan = prepare_prune_parity_fixture(&embedded);
    let machine_plan = prepare_prune_parity_fixture(&machine_engine);
    let cli_plan = prepare_prune_parity_fixture(&cli_engine);
    assert_eq!(machine_plan.plan_id(), embedded_plan.plan_id());
    assert_eq!(cli_plan.plan_id(), embedded_plan.plan_id());

    let embedded_prune = embedded
        .prune_v1(&PruneRequestV1::new(vec![embedded_plan.plan_id().clone()]))
        .unwrap();
    let MachineResultV1::Prune(machine_prune) = run_machine(
        &machine_env,
        "prune",
        MachineRequestV1::Prune(PruneRequestV1::new(vec![machine_plan.plan_id().clone()])),
    ) else {
        panic!("machine prune returned another result")
    };
    assert_eq!(machine_prune, embedded_prune);
    // The two blobs are the plan artifact and the pruned pack's member blob.
    // Deduplicated storage releases member blobs with their pack.
    assert_eq!(
        embedded_prune,
        malm::PruneOutcomeV1 {
            prepared_records: 1,
            artifact_blobs: 2,
            state_generations: 1,
            pack_objects: 1,
            canonical_files: 1,
            canonical_symlinks: 1,
            canonical_trees: 1
        }
    );
    assert_eq!(
        run_cli_json(
            &cli_env,
            &[
                "plan",
                "--format",
                "json",
                "delete",
                cli_plan.plan_id().as_str(),
            ],
        ),
        serde_json::json!({
            "dry_run": false,
            "removed": {
                "prepared_records": embedded_prune.prepared_records,
                "artifact_blobs": embedded_prune.artifact_blobs,
                "state_generations": embedded_prune.state_generations,
                "pack_objects": embedded_prune.pack_objects,
                "canonical_files": embedded_prune.canonical_files,
                "canonical_symlinks": embedded_prune.canonical_symlinks,
                "canonical_trees": embedded_prune.canonical_trees,
            }
        })
    );

    let text_env = TestEnv::new();
    let (text_engine, _, _) = seed_committed(&text_env);
    let text_plan = prepare_prune_parity_fixture(&text_engine);
    let deleted = run_cli_text(&text_env, &["plan", "delete", text_plan.plan_id().as_str()]);
    assert_contains(&deleted, "Plans deleted");
    assert_contains(&deleted, "Plans       1");
    assert_contains(&deleted, "Artifacts   2");
    assert_contains(&deleted, "Generations 1");
    assert_contains(&deleted, "Objects     4");
}
