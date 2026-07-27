#![cfg(feature = "failpoints")]

mod common;

use std::io::{Read, Write};
use std::process::{Command, Output, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use common::TestEnv;
use malm::{
    ApprovalV1, CommitRequestV1, PrepareArtifactV1, PrepareInputKindV1, PrepareInputV1,
    PrepareOperationV1, PrepareRequestPartsV1, PrepareRequestV1, PreparedDeploymentV1,
    RecoveryOutcomeV1,
};
use malm_machine::{
    MachineOperationV1, MachineRequestV1, MachineResultV1, RequestEnvelopeV1, RequestIdV1,
    ServerFrameV1, decode_server_frame_v1, encode_request_v1,
};
use malm_types::{ArtifactId, DeploymentName, Digest, NamespaceName};

const PROCESS_TIMEOUT: Duration = Duration::from_secs(30);
const PRIOR_REPLACEMENT: &[u8] = b"prior replacement\0\xff\n";
const PRIOR_REMOVAL: &[u8] = b"prior removal\0\xfe\n";
const PREPARED_REPLACEMENT: &[u8] = b"prepared replacement\0\x80\n";
const FAILPOINT_ENVIRONMENT: [&str; 5] = [
    "MALM_FAILPOINT",
    "MALM_FAILPOINT_MODE",
    "MALM_FAILPOINT_MARKER",
    "MALM_FAILPOINT_CONTINUE",
    "MALM_FAILPOINT_TIMEOUT_MS",
];

#[derive(Clone, Copy)]
enum RecoveryAdapter {
    HumanCli,
    Machine,
}

#[derive(Clone, Copy)]
enum CrashSide {
    Rollback,
    RollForward,
}

impl CrashSide {
    const fn failpoint(self) -> &'static str {
        match self {
            Self::Rollback => "v1.commit.burst.after_final_sync",
            Self::RollForward => "v1.commit.after_catalog",
        }
    }

    const fn hit(self) -> u64 {
        match self {
            Self::Rollback | Self::RollForward => 1,
        }
    }

    const fn name(self) -> &'static str {
        match self {
            Self::Rollback => "rollback",
            Self::RollForward => "roll-forward",
        }
    }
}

struct Fixture {
    env: TestEnv,
    prepared: PreparedDeploymentV1,
    previous_generation: Digest,
}
fn baseline_request() -> PrepareRequestV1 {
    let replacement = ArtifactId::new("config/replacement").unwrap();
    let removal = ArtifactId::new("config/removal").unwrap();
    let authority = DeploymentName::new("home").unwrap();
    PrepareRequestV1::from(PrepareRequestPartsV1 {
        namespace: NamespaceName::new("workstation").unwrap(),
        expected_head: None,
        graph_digest: Digest::sha256(b"CLI crash recovery baseline graph"),
        inputs: vec![
            PrepareInputV1::new(
                PrepareInputKindV1::Config,
                "crash-recovery-baseline",
                Digest::sha256(b"CLI crash recovery baseline input"),
            )
            .unwrap(),
        ],
        artifacts: vec![
            PrepareArtifactV1::new(
                replacement.clone(),
                PRIOR_REPLACEMENT.to_vec(),
                "application/octet-stream",
            )
            .unwrap(),
            PrepareArtifactV1::new(
                removal.clone(),
                PRIOR_REMOVAL.to_vec(),
                "application/octet-stream",
            )
            .unwrap(),
        ],
        transforms: vec![],
        findings: vec![],
        operations: vec![
            PrepareOperationV1::place_file(
                authority.clone(),
                "config/replacement.bin",
                replacement,
                0o600,
            )
            .unwrap(),
            PrepareOperationV1::place_file(authority, "config/removal.bin", removal, 0o600)
                .unwrap(),
        ],
    })
}

fn transition_request(previous_generation: Digest) -> PrepareRequestV1 {
    let replacement = ArtifactId::new("config/replacement").unwrap();
    let authority = DeploymentName::new("home").unwrap();
    PrepareRequestV1::from(PrepareRequestPartsV1 {
        namespace: NamespaceName::new("workstation").unwrap(),
        expected_head: Some(previous_generation),
        graph_digest: Digest::sha256(b"CLI crash recovery transition graph"),
        inputs: vec![
            PrepareInputV1::new(
                PrepareInputKindV1::Config,
                "crash-recovery-transition",
                Digest::sha256(b"CLI crash recovery transition input"),
            )
            .unwrap(),
        ],
        artifacts: vec![
            PrepareArtifactV1::new(
                replacement.clone(),
                PREPARED_REPLACEMENT.to_vec(),
                "application/octet-stream",
            )
            .unwrap(),
        ],
        transforms: vec![],
        findings: vec![],
        operations: vec![
            PrepareOperationV1::replace_file(
                authority.clone(),
                "config/replacement.bin",
                replacement,
                0o600,
            )
            .unwrap(),
            PrepareOperationV1::remove_leaf(authority, "config/removal.bin").unwrap(),
        ],
    })
}

fn commit_request(prepared: &PreparedDeploymentV1) -> CommitRequestV1 {
    CommitRequestV1::new(
        prepared.plan_id().clone(),
        ApprovalV1::new(
            prepared.plan_id().clone(),
            prepared.approval_digest().clone(),
        ),
    )
}

fn fixture() -> Fixture {
    let env = TestEnv::new();
    std::fs::create_dir(env.home().join("config")).unwrap();
    let engine = env.engine();
    engine.initialize_store().unwrap();

    let baseline = engine.prepare_v1(&baseline_request()).unwrap();
    let baseline = engine.commit_v1(&commit_request(&baseline)).unwrap();
    assert!(baseline.previous_head().is_none());
    let previous_generation = baseline.head().clone();
    assert_eq!(
        std::fs::read(env.home().join("config/replacement.bin")).unwrap(),
        PRIOR_REPLACEMENT
    );
    assert_eq!(
        std::fs::read(env.home().join("config/removal.bin")).unwrap(),
        PRIOR_REMOVAL
    );

    let prepared = engine
        .prepare_v1(&transition_request(previous_generation.clone()))
        .unwrap();
    assert_eq!(prepared.operation_count(), 2);
    assert!(
        env.state_root()
            .join("prepared")
            .join(prepared.plan_id().as_str())
            .is_file()
    );
    for artifact in prepared.artifacts() {
        assert!(
            env.state_root()
                .join("objects/blobs")
                .join(artifact.digest().as_str())
                .is_file()
        );
    }
    drop(engine);

    Fixture {
        env,
        prepared,
        previous_generation,
    }
}

fn run_case(adapter: RecoveryAdapter, side: CrashSide) {
    let fixture = fixture();
    let plan_id = fixture.prepared.plan_id().as_str();
    let approval = fixture.prepared.approval_digest().as_str();
    let crashed = run_malm(
        &fixture.env,
        &["plan", "apply", plan_id, "--approval", approval],
        None,
        Some(side.failpoint()),
    );
    assert!(
        !crashed.status.success(),
        "commit survived {}\nstdout:\n{}\nstderr:\n{}",
        side.failpoint(),
        String::from_utf8_lossy(&crashed.stdout),
        String::from_utf8_lossy(&crashed.stderr),
    );
    assert!(crashed.stdout.is_empty());
    assert_eq!(
        crashed.stderr,
        format!(
            "failpoint {}: aborting (hit {})\n",
            side.failpoint()
                .split_once('=')
                .map_or(side.failpoint(), |pair| pair.0),
            side.hit(),
        )
        .as_bytes()
    );

    let journal_path = fixture.env.state_root().join("transactions/current.json");
    let journal: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&journal_path).unwrap()).unwrap();
    assert_eq!(journal["schema_version"], 1);
    assert_eq!(journal["plan_id"], plan_id);
    assert_eq!(
        journal["previous_generation"],
        fixture.previous_generation.as_str()
    );
    let next_generation = Digest::new(
        journal["next_generation"]
            .as_str()
            .expect("journal next generation")
            .to_owned(),
    )
    .unwrap();
    let expected_generation = match side {
        CrashSide::Rollback => fixture.previous_generation.clone(),
        CrashSide::RollForward => next_generation,
    };

    assert_eq!(
        std::fs::read(fixture.env.home().join("config/replacement.bin")).unwrap(),
        PREPARED_REPLACEMENT
    );
    assert!(!fixture.env.home().join("config/removal.bin").exists());
    assert_eq!(
        fixture
            .env
            .engine()
            .inspect_state_v1(&NamespaceName::new("workstation").unwrap())
            .unwrap()
            .head(),
        Some(&expected_generation)
    );

    match adapter {
        RecoveryAdapter::HumanCli => recover_with_human_cli(&fixture.env, &expected_generation),
        RecoveryAdapter::Machine => {
            recover_with_machine(&fixture.env, side, &expected_generation);
        }
    }

    match side {
        CrashSide::Rollback => {
            assert_eq!(
                std::fs::read(fixture.env.home().join("config/replacement.bin")).unwrap(),
                PRIOR_REPLACEMENT
            );
            assert_eq!(
                std::fs::read(fixture.env.home().join("config/removal.bin")).unwrap(),
                PRIOR_REMOVAL
            );
        }
        CrashSide::RollForward => {
            assert_eq!(
                std::fs::read(fixture.env.home().join("config/replacement.bin")).unwrap(),
                PREPARED_REPLACEMENT
            );
            assert!(!fixture.env.home().join("config/removal.bin").exists());
        }
    }
    assert_eq!(
        fixture
            .env
            .engine()
            .inspect_state_v1(&NamespaceName::new("workstation").unwrap())
            .unwrap()
            .head(),
        Some(&expected_generation)
    );
    assert!(!journal_path.exists());
}

fn recover_with_human_cli(env: &TestEnv, expected_generation: &Digest) {
    let recovered = run_malm(env, &["store", "recover"], None, None);
    assert!(
        recovered.status.success(),
        "human recovery failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&recovered.stdout),
        String::from_utf8_lossy(&recovered.stderr),
    );
    assert!(recovered.stderr.is_empty());
    let rendered = String::from_utf8(recovered.stdout).unwrap();
    assert!(rendered.contains("Recovery completed"), "{rendered}");
    assert!(rendered.contains("workstation"), "{rendered}");
    assert!(
        rendered.contains(&format!("gen:{}", &expected_generation.as_str()[7..19])),
        "{rendered}"
    );
}

fn recover_with_machine(env: &TestEnv, side: CrashSide, expected_generation: &Digest) {
    let request_id = RequestIdV1::new(format!("recover-{}", side.name())).unwrap();
    let request = RequestEnvelopeV1::new(request_id.clone(), MachineRequestV1::Recover);
    let request = encode_request_v1(&request).unwrap();
    let recovered = run_malm(env, &["machine"], Some(&request), None);
    assert!(
        recovered.status.success(),
        "machine recovery failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&recovered.stdout),
        String::from_utf8_lossy(&recovered.stderr),
    );
    assert!(recovered.stderr.is_empty());
    let frames = recovered
        .stdout
        .split_inclusive(|byte| *byte == b'\n')
        .map(|record| decode_server_frame_v1(record).unwrap())
        .collect::<Vec<_>>();
    assert_eq!(
        frames,
        vec![
            ServerFrameV1::started(request_id.clone(), MachineOperationV1::Recover),
            ServerFrameV1::result(
                request_id,
                1,
                MachineResultV1::Recover(RecoveryOutcomeV1::recovered(
                    NamespaceName::new("workstation").unwrap(),
                    Some(expected_generation.clone()),
                )),
            )
            .unwrap(),
        ]
    );
}

fn run_malm(
    env: &TestEnv,
    arguments: &[&str],
    input: Option<&[u8]>,
    failpoint: Option<&str>,
) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_malm"));
    command
        .args(arguments)
        .env("HOME", env.home())
        .env("XDG_STATE_HOME", env.state_home());
    for variable in FAILPOINT_ENVIRONMENT {
        command.env_remove(variable);
    }
    if let Some(failpoint) = failpoint {
        command.env("MALM_FAILPOINT", failpoint);
    }
    run_with_timeout(command, input)
}

fn run_with_timeout(mut command: Command, input: Option<&[u8]>) -> Output {
    command
        .stdin(if input.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn().unwrap();
    let stdout = child.stdout.take().unwrap();
    let stderr = child.stderr.take().unwrap();
    let stdout_thread = thread::spawn(move || drain(stdout));
    let stderr_thread = thread::spawn(move || drain(stderr));
    if let Some(input) = input {
        let mut stdin = child.stdin.take().unwrap();
        stdin.write_all(input).unwrap();
        stdin.flush().unwrap();
    }

    let deadline = Instant::now() + PROCESS_TIMEOUT;
    let mut timed_out = false;
    let status = loop {
        match child.try_wait().unwrap() {
            Some(status) => break status,
            None if Instant::now() >= deadline => {
                timed_out = true;
                child.kill().unwrap();
                break child.wait().unwrap();
            }
            None => thread::sleep(Duration::from_millis(10)),
        }
    };
    let stdout = stdout_thread.join().unwrap();
    let stderr = stderr_thread.join().unwrap();
    assert!(
        !timed_out,
        "malm subprocess exceeded {}s\nstdout:\n{}\nstderr:\n{}",
        PROCESS_TIMEOUT.as_secs(),
        String::from_utf8_lossy(&stdout),
        String::from_utf8_lossy(&stderr),
    );
    Output {
        status,
        stdout,
        stderr,
    }
}

fn drain(mut reader: impl Read) -> Vec<u8> {
    let mut bytes = Vec::new();
    reader.read_to_end(&mut bytes).unwrap();
    bytes
}

#[test]
fn human_cli_rolls_back_an_interrupted_commit() {
    run_case(RecoveryAdapter::HumanCli, CrashSide::Rollback);
}

#[test]
fn human_cli_rolls_forward_an_activated_commit() {
    run_case(RecoveryAdapter::HumanCli, CrashSide::RollForward);
}

#[test]
fn machine_rolls_back_an_interrupted_commit() {
    run_case(RecoveryAdapter::Machine, CrashSide::Rollback);
}

#[test]
fn machine_rolls_forward_an_activated_commit() {
    run_case(RecoveryAdapter::Machine, CrashSide::RollForward);
}
