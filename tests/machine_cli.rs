mod common;

use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

use common::TestEnv;
use malm_machine::{
    MAX_MACHINE_FRAME_BYTES, MachineErrorCodeV1, MachineOperationV1, MachineRequestV1,
    MachineResultV1, RequestEnvelopeV1, RequestIdV1, ServerFrameV1, decode_server_frame_v1,
    encode_request_v1,
};
use malm_types::{
    ApprovalV1, ArtifactId, CheckoutRequestV1, CommitRequestV1, DeploymentName, Digest,
    NamespaceName, NamespaceRemovalHistoryV1, NamespaceRemovalRequestV1, PrepareArtifactV1,
    PrepareOperationV1, PrepareRequestPartsV1, PrepareRequestV1, PruneRequestV1, StoreStatusV1,
};

fn run_machine(env: &TestEnv, input: &[u8]) -> Output {
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
    child.stdin.take().unwrap().write_all(input).unwrap();
    child.wait_with_output().unwrap()
}

fn frames(output: &Output) -> Vec<ServerFrameV1> {
    output
        .stdout
        .split_inclusive(|byte| *byte == b'\n')
        .map(|record| decode_server_frame_v1(record).unwrap())
        .collect()
}

fn run_request(env: &TestEnv, id: &str, request: MachineRequestV1) -> Output {
    let request = RequestEnvelopeV1::new(RequestIdV1::new(id).unwrap(), request);
    run_machine(env, &encode_request_v1(&request).unwrap())
}

fn terminal_result(output: &Output) -> MachineResultV1 {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let frames = frames(output);
    let ServerFrameV1::Result { result, .. } = &frames[1] else {
        panic!("machine request did not return a result: {frames:?}")
    };
    result.clone()
}

#[test]
fn status_and_initialize_execute_through_the_engine_adapter() {
    let env = TestEnv::new();
    let status = run_machine(
        &env,
        include_bytes!("../schemas/machine/v1/fixtures/golden/request-status.jsonl"),
    );
    assert!(status.status.success());
    assert!(status.stderr.is_empty());
    assert_eq!(
        status.stdout,
        [
            include_bytes!("../schemas/machine/v1/fixtures/golden/server-started.jsonl").as_slice(),
            include_bytes!("../schemas/machine/v1/fixtures/golden/server-result.jsonl").as_slice(),
        ]
        .concat()
    );
    assert!(!env.state_root().exists());

    let initialize = run_machine(
        &env,
        b"{\"schema_version\":1,\"request_id\":\"init\",\"type\":\"request\",\"request\":{\"type\":\"initialize_store\"}}\n",
    );
    assert!(initialize.status.success());
    assert!(initialize.stderr.is_empty());
    assert!(matches!(
        frames(&initialize).as_slice(),
        [
            ServerFrameV1::Started {
                operation: MachineOperationV1::InitializeStore,
                ..
            },
            ServerFrameV1::Result { result, .. }
        ] if *result == MachineResultV1::InitializeStore
    ));
    assert_eq!(
        std::fs::read(env.state_root().join("descriptor.json")).unwrap(),
        b"{\"format\":\"malm-state\",\"version\":1}\n"
    );

    let ready = run_machine(
        &env,
        b"{\"schema_version\":1,\"request_id\":\"ready\",\"type\":\"request\",\"request\":{\"type\":\"store_status\"}}\n",
    );
    assert!(matches!(
        frames(&ready).as_slice(),
        [ServerFrameV1::Started { .. }, ServerFrameV1::Result { result, .. }]
            if *result == MachineResultV1::StoreStatus(StoreStatusV1::Ready)
    ));
}

#[test]
fn rejected_records_emit_one_bounded_uncorrelated_error() {
    let env = TestEnv::new();
    for input in [
        b"not-json\n".to_vec(),
        vec![b' '; MAX_MACHINE_FRAME_BYTES + 1],
        b"{\"schema_version\":1,\"request_id\":\"host-track\",\"type\":\"request\",\"request\":{\"type\":\"track\",\"git_executable\":\"/usr/bin/git\",\"root_scratch\":\"/tmp/root\"}}\n".to_vec(),
        b"{\"schema_version\":1,\"request_id\":\"host-update\",\"type\":\"request\",\"request\":{\"type\":\"update\",\"git_executable\":\"/usr/bin/git\",\"root_scratch\":\"/tmp/root\"}}\n".to_vec(),
        b"{\"schema_version\":1,\"request_id\":\"host-lock\",\"type\":\"request\",\"request\":{\"type\":\"lock_create\",\"source\":\"/tmp/pack\",\"git_executable\":\"/usr/bin/git\"}}\n".to_vec(),
    ] {
        let output = run_machine(&env, &input);
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stderr.is_empty());
        let records = frames(&output);
        assert_eq!(records.len(), 1);
        assert!(matches!(
            &records[0],
            ServerFrameV1::Error {
                request_id: None,
                sequence: 0,
                ..
            }
        ));
    }
    assert!(!env.state_root().exists());
}

#[test]
fn engine_failures_are_correlated_without_leaking_host_paths() {
    let env = TestEnv::new();
    std::fs::create_dir(env.state_root()).unwrap();
    std::fs::set_permissions(env.state_root(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let descriptor = env.state_root().join("descriptor.json");
    std::fs::write(&descriptor, b"{\"format\":\"malm-state\",\"version\":2}\n").unwrap();
    std::fs::set_permissions(&descriptor, std::fs::Permissions::from_mode(0o600)).unwrap();

    let output = run_machine(
        &env,
        b"{\"schema_version\":1,\"request_id\":\"bad-store\",\"type\":\"request\",\"request\":{\"type\":\"store_status\"}}\n",
    );

    assert_eq!(output.status.code(), Some(2));
    assert!(output.stderr.is_empty());
    assert!(matches!(
        frames(&output).as_slice(),
        [
            ServerFrameV1::Started {
                operation: MachineOperationV1::StoreStatus,
                ..
            },
            ServerFrameV1::Error {
                request_id: Some(_),
                sequence: 1,
                error,
            }
        ] if error.code() == MachineErrorCodeV1::UnsupportedStoreVersion
    ));
    let encoded = String::from_utf8(output.stdout).unwrap();
    assert!(!encoded.contains(env.home().to_str().unwrap()));
    assert!(!encoded.contains("malm-v1"));
    assert!(!encoded.contains("os error"));
}

#[test]
fn machine_distinguishes_stale_expected_heads_from_corrupt_selected_state() {
    let env = TestEnv::new();
    assert!(
        run_request(&env, "init", MachineRequestV1::InitializeStore)
            .status
            .success()
    );
    let namespace = NamespaceName::new("workstation").unwrap();
    let stale = run_request(
        &env,
        "stale",
        MachineRequestV1::Prepare(PrepareRequestV1::from(PrepareRequestPartsV1 {
            namespace: namespace.clone(),
            expected_head: Some(Digest::sha256(b"nonexistent expected head")),
            graph_digest: Digest::sha256(b"stale graph"),
            inputs: vec![],
            artifacts: vec![],
            transforms: vec![],
            findings: vec![],
            operations: vec![],
        })),
    );
    assert_eq!(stale.status.code(), Some(2));
    assert!(matches!(
        frames(&stale).as_slice(),
        [ServerFrameV1::Started { .. }, ServerFrameV1::Error { error, .. }]
            if error.code() == MachineErrorCodeV1::StalePlan
    ));

    let MachineResultV1::Prepare(prepared) = terminal_result(&run_request(
        &env,
        "prepare",
        MachineRequestV1::Prepare(PrepareRequestV1::from(PrepareRequestPartsV1 {
            namespace: namespace.clone(),
            expected_head: None,
            graph_digest: Digest::sha256(b"baseline graph"),
            inputs: vec![],
            artifacts: vec![],
            transforms: vec![],
            findings: vec![],
            operations: vec![],
        })),
    )) else {
        panic!("prepare returned another result")
    };
    terminal_result(&run_request(
        &env,
        "commit",
        MachineRequestV1::Commit(CommitRequestV1::new(
            prepared.plan_id().clone(),
            ApprovalV1::new(
                prepared.plan_id().clone(),
                prepared.approval_digest().clone(),
            ),
        )),
    ));
    std::fs::remove_file(
        env.state_root()
            .join("prepared")
            .join(prepared.plan_id().as_str()),
    )
    .unwrap();

    let corrupt = run_request(&env, "state", MachineRequestV1::State(namespace));
    assert_eq!(corrupt.status.code(), Some(2));
    assert!(matches!(
        frames(&corrupt).as_slice(),
        [ServerFrameV1::Started { .. }, ServerFrameV1::Error { error, .. }]
            if error.code() == MachineErrorCodeV1::CorruptStore
    ));
}

#[test]
fn adapter_authority_failures_still_terminate_the_accepted_stream() {
    let mut child = Command::new(env!("CARGO_BIN_EXE_malm"))
        .arg("machine")
        .env("HOME", "relative-home-is-invalid")
        .env("XDG_STATE_HOME", "relative-is-invalid")
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
        .write_all(b"{\"schema_version\":1,\"request_id\":\"no-authority\",\"type\":\"request\",\"request\":{\"type\":\"store_status\"}}\n")
        .unwrap();
    let output = child.wait_with_output().unwrap();

    assert_eq!(output.status.code(), Some(2));
    assert!(output.stderr.is_empty());
    assert!(matches!(
        frames(&output).as_slice(),
        [
            ServerFrameV1::Started {
                operation: MachineOperationV1::StoreStatus,
                ..
            },
            ServerFrameV1::Error {
                request_id: Some(_),
                sequence: 1,
                error,
            }
        ] if error.code() == MachineErrorCodeV1::InternalEngineError
    ));
}

#[test]
fn non_target_machine_operation_uses_absolute_xdg_without_home() {
    let env = TestEnv::new();
    let mut child = Command::new(env!("CARGO_BIN_EXE_malm"))
        .arg("machine")
        .env_remove("HOME")
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
        .write_all(
            b"{\"schema_version\":1,\"request_id\":\"xdg-only\",\"type\":\"request\",\"request\":{\"type\":\"store_status\"}}\n",
        )
        .unwrap();
    let output = child.wait_with_output().unwrap();

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty());
    assert!(matches!(
        frames(&output).as_slice(),
        [
            ServerFrameV1::Started {
                operation: MachineOperationV1::StoreStatus,
                ..
            },
            ServerFrameV1::Result {
                result: MachineResultV1::StoreStatus(_),
                ..
            }
        ]
    ));
}

#[test]
fn one_lf_terminated_request_does_not_wait_for_stdin_eof() {
    let env = TestEnv::new();
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
    let mut stdin = child.stdin.take().unwrap();
    stdin
        .write_all(b"{\"schema_version\":1,\"request_id\":\"line\",\"type\":\"request\",\"request\":{\"type\":\"store_status\"}}\n")
        .unwrap();
    stdin.flush().unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    while child.try_wait().unwrap().is_none() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(
        child.try_wait().unwrap().is_some(),
        "machine adapter waited for EOF"
    );
    drop(stdin);
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success());
    assert_eq!(frames(&output).len(), 2);
}

#[test]
fn deployment_operations_round_trip_through_the_machine_adapter() {
    let env = TestEnv::new();
    std::fs::create_dir(env.home().join("config")).unwrap();
    assert!(
        run_request(&env, "init-deploy", MachineRequestV1::InitializeStore)
            .status
            .success()
    );
    let artifact_id = ArtifactId::new("config/machine").unwrap();
    let baseline_request = PrepareRequestV1::from(PrepareRequestPartsV1 {
        namespace: NamespaceName::new("workstation").unwrap(),
        expected_head: None,
        graph_digest: Digest::sha256(b"machine baseline graph"),
        inputs: vec![],
        artifacts: vec![
            PrepareArtifactV1::new(artifact_id.clone(), b"existing\n".to_vec(), "text/plain")
                .unwrap(),
        ],
        transforms: vec![],
        findings: vec![],
        operations: vec![
            PrepareOperationV1::place_file(
                DeploymentName::new("home").unwrap(),
                "config/machine.conf",
                artifact_id.clone(),
                0o600,
            )
            .unwrap(),
        ],
    });
    let MachineResultV1::Prepare(baseline) = terminal_result(&run_request(
        &env,
        "prepare-baseline",
        MachineRequestV1::Prepare(baseline_request),
    )) else {
        panic!("baseline prepare returned another result")
    };
    let MachineResultV1::Commit(baseline) = terminal_result(&run_request(
        &env,
        "commit-baseline",
        MachineRequestV1::Commit(CommitRequestV1::new(
            baseline.plan_id().clone(),
            ApprovalV1::new(
                baseline.plan_id().clone(),
                baseline.approval_digest().clone(),
            ),
        )),
    )) else {
        panic!("baseline commit returned another result")
    };
    let prepare = PrepareRequestV1::from(PrepareRequestPartsV1 {
        namespace: NamespaceName::new("workstation").unwrap(),
        expected_head: Some(baseline.head().clone()),
        graph_digest: Digest::sha256(b"machine graph"),
        inputs: vec![],
        artifacts: vec![
            PrepareArtifactV1::new(
                artifact_id.clone(),
                b"machine deployment\n".to_vec(),
                "text/plain",
            )
            .unwrap(),
        ],
        transforms: vec![],
        findings: vec![],
        operations: vec![
            PrepareOperationV1::replace_file(
                DeploymentName::new("home").unwrap(),
                "config/machine.conf",
                artifact_id.clone(),
                0o600,
            )
            .unwrap(),
        ],
    });
    let MachineResultV1::Prepare(prepared) = terminal_result(&run_request(
        &env,
        "prepare",
        MachineRequestV1::Prepare(prepare),
    )) else {
        panic!("prepare returned another result")
    };
    assert_eq!(
        std::fs::read(env.home().join("config/machine.conf")).unwrap(),
        b"existing\n"
    );
    // The namespace already manages this target. Replacement is therefore a
    // routine update: visible during review but not gated on approval.
    assert!(
        prepared.findings().iter().any(|finding| {
            finding.code() == "replace-existing" && !finding.approval_required()
        })
    );

    let MachineResultV1::Plan(reloaded) = terminal_result(&run_request(
        &env,
        "plan",
        MachineRequestV1::Plan(prepared.plan_id().clone()),
    )) else {
        panic!("plan returned another result")
    };
    assert_eq!(reloaded, prepared);
    let MachineResultV1::Artifact(artifact) = terminal_result(&run_request(
        &env,
        "artifact",
        MachineRequestV1::Artifact {
            plan_id: prepared.plan_id().clone(),
            artifact_id,
        },
    )) else {
        panic!("artifact returned another result")
    };
    assert_eq!(artifact.bytes(), b"machine deployment\n");

    let commit = CommitRequestV1::new(
        prepared.plan_id().clone(),
        ApprovalV1::new(
            prepared.plan_id().clone(),
            prepared.approval_digest().clone(),
        ),
    );
    let MachineResultV1::Commit(outcome) = terminal_result(&run_request(
        &env,
        "commit",
        MachineRequestV1::Commit(commit),
    )) else {
        panic!("commit returned another result")
    };
    assert_eq!(
        std::fs::read(env.home().join("config/machine.conf")).unwrap(),
        b"machine deployment\n"
    );
    let MachineResultV1::State(state) = terminal_result(&run_request(
        &env,
        "state",
        MachineRequestV1::State(outcome.namespace().clone()),
    )) else {
        panic!("state returned another result")
    };
    assert_eq!(state.head(), Some(outcome.head()));
    assert!(matches!(
        terminal_result(&run_request(&env, "recover", MachineRequestV1::Recover)),
        MachineResultV1::Recover(_)
    ));
    assert!(matches!(
        terminal_result(&run_request(
            &env,
            "checkout",
            MachineRequestV1::Checkout(CheckoutRequestV1::new(
                outcome.namespace().clone(),
                outcome.head().clone(),
            ))
        )),
        MachineResultV1::Checkout(_)
    ));

    let disposable = PrepareRequestV1::from(PrepareRequestPartsV1 {
        namespace: NamespaceName::new("workstation").unwrap(),
        expected_head: Some(outcome.head().clone()),
        graph_digest: Digest::sha256(b"disposable machine plan"),
        inputs: vec![],
        artifacts: vec![],
        transforms: vec![],
        findings: vec![],
        operations: vec![],
    });
    let MachineResultV1::Prepare(disposable) = terminal_result(&run_request(
        &env,
        "disposable",
        MachineRequestV1::Prepare(disposable),
    )) else {
        panic!("disposable prepare returned another result")
    };
    let MachineResultV1::Prune(pruned) = terminal_result(&run_request(
        &env,
        "prune",
        MachineRequestV1::Prune(PruneRequestV1::new(vec![disposable.plan_id().clone()])),
    )) else {
        panic!("prune returned another result")
    };
    assert_eq!(pruned.prepared_records, 1);
    assert!(env.state_root().join("descriptor.json").is_file());
}

#[test]
fn namespace_removal_commit_returns_a_correlated_nullable_head_after_durable_success() {
    let env = TestEnv::new();
    assert!(
        run_request(&env, "remove-init", MachineRequestV1::InitializeStore)
            .status
            .success()
    );
    let namespace = NamespaceName::new("removed-machine").unwrap();
    let MachineResultV1::Prepare(seed) = terminal_result(&run_request(
        &env,
        "remove-seed",
        MachineRequestV1::Prepare(PrepareRequestV1::from(PrepareRequestPartsV1 {
            namespace: namespace.clone(),
            expected_head: None,
            graph_digest: Digest::sha256(b"machine namespace removal seed"),
            inputs: vec![],
            artifacts: vec![],
            transforms: vec![],
            findings: vec![],
            operations: vec![],
        })),
    )) else {
        panic!("namespace-removal seed returned another result")
    };
    let MachineResultV1::Commit(seed) = terminal_result(&run_request(
        &env,
        "remove-seed-commit",
        MachineRequestV1::Commit(CommitRequestV1::new(
            seed.plan_id().clone(),
            ApprovalV1::new(seed.plan_id().clone(), seed.approval_digest().clone()),
        )),
    )) else {
        panic!("namespace-removal seed commit returned another result")
    };
    let MachineResultV1::RemoveNamespace(removal) = terminal_result(&run_request(
        &env,
        "remove-prepare",
        MachineRequestV1::RemoveNamespace(NamespaceRemovalRequestV1::new(
            namespace.clone(),
            NamespaceRemovalHistoryV1::Drop,
        )),
    )) else {
        panic!("namespace-removal prepare returned another result")
    };

    let output = run_request(
        &env,
        "remove-commit",
        MachineRequestV1::Commit(CommitRequestV1::new(
            removal.plan_id().clone(),
            ApprovalV1::new(removal.plan_id().clone(), removal.approval_digest().clone()),
        )),
    );
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let records = frames(&output);
    let [
        ServerFrameV1::Started {
            request_id: started,
            operation: MachineOperationV1::Commit,
        },
        ServerFrameV1::Result {
            request_id: completed,
            sequence: 1,
            result: MachineResultV1::Commit(outcome),
        },
    ] = records.as_slice()
    else {
        panic!("namespace-removal commit did not return one correlated result: {records:?}")
    };
    assert_eq!(started.as_str(), "remove-commit");
    assert_eq!(completed, started);
    assert_eq!(outcome.previous_head(), Some(seed.head()));
    assert!(outcome.next_head().is_none());
    assert!(matches!(
        terminal_result(&run_request(
            &env,
            "remove-state",
            MachineRequestV1::State(namespace),
        )),
        MachineResultV1::State(state) if state.head().is_none()
    ));
}
