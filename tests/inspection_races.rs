#![cfg(feature = "failpoints")]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use malm::{
    ApprovalV1, CommitRequestV1, Engine, EngineConfig, EnginePorts, FsckFindingCodeV1,
    FsckRequestV1, NamespaceStatusKindV1, NamespaceStatusRequestV1, PrepareRequestPartsV1,
    PrepareRequestV1, StoreAccess,
};
use malm_types::{DeploymentName, Digest, NamespaceName};

const CHILD_ROOT: &str = "MALM_V1_INSPECTION_RACE_ROOT";
const CHILD_SCENARIO: &str = "MALM_V1_INSPECTION_RACE_SCENARIO";
const TEST_TIMEOUT: Duration = Duration::from_secs(20);

fn engine(root: &Path, access: StoreAccess) -> Engine {
    Engine::new(
        EngineConfig::from_state_home(root.join("state"), access)
            .unwrap()
            .with_target_authority(DeploymentName::new("home").unwrap(), root.join("target"))
            .unwrap(),
        EnginePorts::system(),
    )
}

fn initialize(root: &Path) {
    fs::create_dir(root.join("state")).unwrap();
    fs::set_permissions(root.join("state"), fs::Permissions::from_mode(0o700)).unwrap();
    fs::create_dir(root.join("target")).unwrap();
    let engine = engine(root, StoreAccess::ReadWrite);
    engine.initialize_store().unwrap();
    let namespace = NamespaceName::new("workstation").unwrap();
    let prepared = engine
        .prepare_v1(&PrepareRequestV1::from(PrepareRequestPartsV1 {
            namespace,
            expected_head: None,
            graph_digest: Digest::sha256(b"inspection race"),
            inputs: vec![],
            artifacts: vec![],
            transforms: vec![],
            findings: vec![],
            operations: vec![],
        }))
        .unwrap();
    engine
        .commit_v1(&CommitRequestV1::new(
            prepared.plan_id().clone(),
            ApprovalV1::new(
                prepared.plan_id().clone(),
                prepared.approval_digest().clone(),
            ),
        ))
        .unwrap();
}

#[test]
fn inspection_race_child() {
    let Some(root) = std::env::var_os(CHILD_ROOT) else {
        return;
    };
    let root = PathBuf::from(root);
    let engine = engine(&root, StoreAccess::ReadOnly);
    match std::env::var(CHILD_SCENARIO).as_deref() {
        Ok("status") => {
            let status = engine
                .inspect_namespace_status_v1(&NamespaceStatusRequestV1::new(
                    NamespaceName::new("workstation").unwrap(),
                ))
                .unwrap();
            assert_eq!(status.status(), NamespaceStatusKindV1::Stale);
            assert!(
                status
                    .targets()
                    .iter()
                    .all(|target| { target.status() == malm::TargetStatusKindV1::Stale })
            );
        }
        Ok("fsck") => {
            let report = engine.fsck_v1(&FsckRequestV1::new()).unwrap();
            assert!(!report.complete());
            assert!(
                report
                    .findings()
                    .iter()
                    .any(|finding| { finding.code() == FsckFindingCodeV1::AuthorityChanged })
            );
        }
        scenario => panic!("unknown child scenario: {scenario:?}"),
    }
}

#[test]
fn status_maps_store_authority_races_to_stale() {
    run_race("status", "v1.status.before_authority_revalidation");
}

#[test]
fn fsck_reports_store_authority_races_as_incomplete_coverage() {
    run_race("fsck", "v1.fsck.before_authority_revalidation");
}

fn run_race(scenario: &str, failpoint: &str) {
    let temp = tempfile::tempdir().unwrap();
    initialize(temp.path());
    let marker = temp.path().join("inspection.marker");
    let continue_path = temp.path().join("inspection.continue");
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "inspection_race_child", "--nocapture"])
        .env(CHILD_ROOT, temp.path())
        .env(CHILD_SCENARIO, scenario)
        .env("MALM_FAILPOINT", failpoint)
        .env("MALM_FAILPOINT_MODE", "pause")
        .env("MALM_FAILPOINT_MARKER", &marker)
        .env("MALM_FAILPOINT_CONTINUE", &continue_path)
        .env("MALM_FAILPOINT_TIMEOUT_MS", "15000")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    wait_for_marker(&mut child, &marker, &format!("{failpoint}=1\n"));

    replace_catalog_with_same_bytes(temp.path());
    fs::write(&continue_path, b"continue\n").unwrap();

    let started = Instant::now();
    loop {
        if child.try_wait().unwrap().is_some() {
            break;
        }
        if started.elapsed() >= TEST_TIMEOUT {
            fail_child(child, "timed out waiting for inspection race child");
        }
        thread::sleep(Duration::from_millis(5));
    }
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "inspection race child failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn replace_catalog_with_same_bytes(root: &Path) {
    let state = root.join("state/malm/state");
    let catalog = state.join("catalog.json");
    let replacement = state.join("catalog.race");
    fs::write(&replacement, fs::read(&catalog).unwrap()).unwrap();
    fs::set_permissions(&replacement, fs::Permissions::from_mode(0o400)).unwrap();
    fs::rename(replacement, catalog).unwrap();
}

fn wait_for_marker(child: &mut Child, marker: &Path, expected: &str) {
    let started = Instant::now();
    loop {
        if fs::read_to_string(marker).is_ok_and(|contents| contents == expected) {
            return;
        }
        if let Some(status) = child.try_wait().unwrap() {
            panic!("inspection child exited before reaching the pause barrier: {status}");
        }
        if started.elapsed() >= TEST_TIMEOUT {
            let _ = child.kill();
            panic!("timed out waiting for inspection pause marker");
        }
        thread::sleep(Duration::from_millis(5));
    }
}

fn fail_child(mut child: Child, reason: &str) -> ! {
    let _ = child.kill();
    let output = child.wait_with_output().unwrap();
    panic!(
        "{reason}\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
