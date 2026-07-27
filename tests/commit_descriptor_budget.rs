#![cfg(unix)]

use std::fs::{self, File};
use std::io;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;
use std::process::Command;
use std::sync::Arc;

use malm::{
    ApprovalV1, CommitError, CommitRequestV1, DiagnosticEvent, DiagnosticSink, Engine,
    EngineConfig, EnginePorts, GitAcquisitionConfig, GitAcquisitionIssue, GitObjectFormat,
    GitPackFile, GitProcessPort, PrepareArtifactV1, PrepareOperationV1, PrepareRequestPartsV1,
    PrepareRequestV1, ProcessFacts, ProgressEvent, ProgressSink, SecureRandomPort, StoreAccess,
};
use malm_types::{ArtifactId, DeploymentName, Digest, NamespaceName};
use rustix::process::{Resource, Rlimit, getrlimit, setrlimit};

const RLIMIT_CHILD: &str = "MALM_DESCRIPTOR_BUDGET_RLIMIT_CHILD";

struct FixedRandom;

impl SecureRandomPort for FixedRandom {
    fn fill(&self, output: &mut [u8]) -> io::Result<()> {
        output.fill(0x5a);
        Ok(())
    }
}

struct UnusedGit;

impl GitProcessPort for UnusedGit {
    fn initialize(
        &self,
        _config: &GitAcquisitionConfig,
        _scratch: &File,
        _object_format: GitObjectFormat,
        _output_limit: u64,
    ) -> Result<(), GitAcquisitionIssue> {
        panic!("descriptor-budget test does not use Git")
    }

    fn fetch(
        &self,
        _config: &GitAcquisitionConfig,
        _scratch: &File,
        _url: &str,
        _object_id: &str,
        _output_limit: u64,
    ) -> Result<(), GitAcquisitionIssue> {
        panic!("descriptor-budget test does not use Git")
    }

    fn read_pack(
        &self,
        _config: &GitAcquisitionConfig,
        _scratch: &File,
        _object_format: GitObjectFormat,
        _object_id: &str,
        _subdir: &str,
    ) -> Result<Vec<GitPackFile>, GitAcquisitionIssue> {
        panic!("descriptor-budget test does not use Git")
    }
}

struct NoopSink;

impl ProgressSink for NoopSink {
    fn emit(&self, _event: ProgressEvent) {}
}

impl DiagnosticSink for NoopSink {
    fn emit(&self, _event: DiagnosticEvent<'_>) {}
}

fn ports(uid: u32, soft_limit: u64) -> EnginePorts {
    let sink = Arc::new(NoopSink);
    EnginePorts::new(
        ProcessFacts::new(uid, Some(soft_limit)),
        Arc::new(FixedRandom),
        Arc::new(UnusedGit),
        sink.clone(),
        sink,
    )
}

fn engine(state_home: &Path, target: &Path, soft_limit: u64) -> Engine {
    Engine::new(
        EngineConfig::from_state_home(state_home, StoreAccess::ReadWrite)
            .unwrap()
            .with_target_authority(DeploymentName::new("home").unwrap(), target)
            .unwrap(),
        ports(fs::metadata(state_home).unwrap().uid(), soft_limit),
    )
}

fn smia_shaped_request() -> PrepareRequestV1 {
    let mut artifacts = Vec::with_capacity(135);
    let mut operations = Vec::with_capacity(135);
    for index in 0..135 {
        let artifact = ArtifactId::new(format!("outputs/{index}")).unwrap();
        artifacts.push(
            PrepareArtifactV1::new(
                artifact.clone(),
                format!("generated output {index}\n").into_bytes(),
                "text/plain",
            )
            .unwrap(),
        );
        operations.push(
            PrepareOperationV1::place_file(
                DeploymentName::new("home").unwrap(),
                format!("outputs/group-{}/file-{index}", index % 108),
                artifact,
                0o600,
            )
            .unwrap(),
        );
    }
    PrepareRequestV1::from(PrepareRequestPartsV1 {
        namespace: NamespaceName::new("smia-shaped").unwrap(),
        expected_head: None,
        graph_digest: Digest::sha256(b"smia-shaped descriptor budget"),
        inputs: Vec::new(),
        artifacts,
        transforms: Vec::new(),
        findings: Vec::new(),
        operations,
    })
}

#[test]
fn smia_shaped_plan_succeeds_at_1024_and_fails_at_a_genuinely_low_limit() {
    if std::env::var_os(RLIMIT_CHILD).is_none() {
        let output = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "smia_shaped_plan_succeeds_at_1024_and_fails_at_a_genuinely_low_limit",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(RLIMIT_CHILD, "1")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "descriptor-budget child failed\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
        return;
    }

    let inherited = getrlimit(Resource::Nofile);
    assert!(
        inherited.maximum.is_none_or(|maximum| maximum >= 1_024),
        "test requires a hard NOFILE limit of at least 1024"
    );
    setrlimit(
        Resource::Nofile,
        Rlimit {
            current: Some(1_024),
            maximum: inherited.maximum,
        },
    )
    .unwrap();
    assert_eq!(getrlimit(Resource::Nofile).current, Some(1_024));

    let temp = tempfile::tempdir().unwrap();
    let state_home = temp.path().join("state");
    fs::create_dir(&state_home).unwrap();
    fs::set_permissions(&state_home, fs::Permissions::from_mode(0o700)).unwrap();
    let target = temp.path().join("target");
    fs::create_dir(&target).unwrap();
    fs::create_dir(target.join("outputs")).unwrap();
    for group in 0..108 {
        fs::create_dir(target.join(format!("outputs/group-{group}"))).unwrap();
    }

    let normal = engine(&state_home, &target, 1_024);
    normal.initialize_store().unwrap();
    let prepared = normal.prepare_v1(&smia_shaped_request()).unwrap();
    let request = CommitRequestV1::new(
        prepared.plan_id().clone(),
        ApprovalV1::new(
            prepared.plan_id().clone(),
            prepared.approval_digest().clone(),
        ),
    );

    let constrained = engine(&state_home, &target, 128);
    assert!(matches!(
        constrained.commit_v1(&request),
        Err(CommitError::InvalidPlan(reason))
            if reason.contains("pinned filesystem descriptors")
                && reason.contains("process limit is 128")
    ));
    assert!(!target.join("outputs/group-0/file-0").exists());

    normal.commit_v1(&request).unwrap();
    for index in 0..135 {
        assert_eq!(
            fs::read(target.join(format!("outputs/group-{}/file-{index}", index % 108))).unwrap(),
            format!("generated output {index}\n").as_bytes()
        );
    }
}
