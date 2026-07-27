#![cfg(feature = "failpoints")]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use malm_engine::{
    Engine, EngineConfig, EnginePorts, PrepareArtifactV1, PrepareOperationV1,
    PrepareRequestPartsV1, PrepareRequestV1, StoreAccess,
};
use malm_types::{ArtifactId, DeploymentName, Digest, NamespaceName, PreparedId};

const CRASH_ROOT_ENV: &str = "MALM_PREPARE_CRASH_ROOT";
const CHILD_TEST: &str = "crash_prepare_child";
const ARTIFACT_BYTES: &[u8] = b"prepared crash evidence\n";

fn make_engine(root: &Path) -> Engine {
    let state_home = root.join("state");
    if !state_home.exists() {
        fs::create_dir(&state_home).unwrap();
        fs::set_permissions(&state_home, fs::Permissions::from_mode(0o700)).unwrap();
    }
    Engine::new(
        EngineConfig::from_state_home(&state_home, StoreAccess::ReadWrite)
            .unwrap()
            .with_target_authority(DeploymentName::new("home").unwrap(), root.join("target"))
            .unwrap(),
        EnginePorts::system(),
    )
}

fn request() -> PrepareRequestV1 {
    let artifact_id = ArtifactId::new("crash/result").unwrap();
    PrepareRequestV1::from(PrepareRequestPartsV1 {
        namespace: NamespaceName::new("workstation").unwrap(),
        expected_head: None,
        graph_digest: Digest::sha256(b"prepare publication crash graph"),
        inputs: vec![],
        artifacts: vec![
            PrepareArtifactV1::new(artifact_id.clone(), ARTIFACT_BYTES.to_vec(), "text/plain")
                .unwrap(),
        ],
        transforms: vec![],
        findings: vec![],
        operations: vec![
            PrepareOperationV1::place_file(
                DeploymentName::new("home").unwrap(),
                "config/result.conf",
                artifact_id,
                0o600,
            )
            .unwrap(),
        ],
    })
}

#[test]
fn crash_prepare_child() {
    let Some(root) = std::env::var_os(CRASH_ROOT_ENV) else {
        return;
    };
    make_engine(&PathBuf::from(root))
        .prepare_v1(&request())
        .unwrap();
    panic!("configured prepare failpoint did not fire");
}

fn crash_at(root: &Path, failpoint: &str) {
    let output = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", CHILD_TEST, "--nocapture"])
        .env(CRASH_ROOT_ENV, root)
        .env("MALM_FAILPOINT", failpoint)
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !output.status.success() && stderr.contains(&format!("failpoint {failpoint}: aborting")),
        "child did not abort at {failpoint}\nstatus: {:?}\nstdout:\n{}\nstderr:\n{stderr}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
    );
}

fn setup() -> tempfile::TempDir {
    let temp = tempfile::tempdir().unwrap();
    let target = temp.path().join("target");
    fs::create_dir(&target).unwrap();
    fs::create_dir(target.join("config")).unwrap();
    fs::write(target.join("config/sentinel.conf"), b"unchanged\n").unwrap();
    let engine = make_engine(temp.path());
    engine.initialize_store().unwrap();
    assert!(
        engine
            .inspect_state_v1(&NamespaceName::new("workstation").unwrap())
            .unwrap()
            .head()
            .is_none()
    );
    temp
}

fn assert_prepare_did_not_apply(root: &Path, engine: &Engine) {
    let target = root.join("target/config");
    assert_eq!(
        fs::read(target.join("sentinel.conf")).unwrap(),
        b"unchanged\n"
    );
    assert!(!target.join("result.conf").exists());
    assert!(
        engine
            .inspect_state_v1(&NamespaceName::new("workstation").unwrap())
            .unwrap()
            .head()
            .is_none()
    );
}

fn prepared_ids(root: &Path) -> Vec<PreparedId> {
    let mut ids = fs::read_dir(root.join("state/malm/prepared"))
        .unwrap()
        .map(|entry| PreparedId::new(entry.unwrap().file_name().into_string().unwrap()).unwrap())
        .collect::<Vec<_>>();
    ids.sort();
    ids
}

#[test]
fn crash_after_blob_publication_exposes_no_plan_or_state_change() {
    let temp = setup();

    crash_at(temp.path(), "v1.prepare.blob.after_publish");

    let restarted = make_engine(temp.path());
    assert!(prepared_ids(temp.path()).is_empty());
    let blobs = fs::read_dir(temp.path().join("state/malm/objects/blobs"))
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert_eq!(blobs.len(), 1, "a durable orphan blob is permitted");
    assert_prepare_did_not_apply(temp.path(), &restarted);
}

#[test]
fn crash_after_record_link_exposes_only_a_verifiable_plan() {
    let temp = setup();

    crash_at(temp.path(), "v1.prepare.record.after_link");

    let restarted = make_engine(temp.path());
    let ids = prepared_ids(temp.path());
    assert_eq!(ids.len(), 1);
    let plan = restarted.plan_v1(&ids[0]).unwrap();
    assert_eq!(plan.plan_id(), &ids[0]);
    assert_eq!(plan.artifacts().len(), 1);
    let artifact = restarted
        .artifact_v1(&ids[0], &ArtifactId::new("crash/result").unwrap())
        .unwrap();
    assert_eq!(artifact.bytes(), ARTIFACT_BYTES);
    assert_eq!(artifact.descriptor(), &plan.artifacts()[0]);
    assert_prepare_did_not_apply(temp.path(), &restarted);
}
