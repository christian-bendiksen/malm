#![cfg(feature = "failpoints")]

use std::fs;
use std::fs::OpenOptions;
use std::io::{Seek, SeekFrom, Write};
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::{Mutex, MutexGuard};
use std::thread;
use std::time::{Duration, Instant};

use malm::{
    ApprovalV1, CommitError, CommitRequestV1, Engine, EngineConfig, EnginePorts, PrepareArtifactV1,
    PrepareOperationV1, PrepareRequestPartsV1, PrepareRequestV1, StoreAccess,
};
use malm_tree::{
    TreeEntryV1, TreeObjectV1, TreePathSegmentV1, file_object_digest_v1, tree_object_digest_v1,
};
use malm_types::{ArtifactId, DeploymentName, Digest, NamespaceName, PrepareTargetStateV1};

const CHILD_ROOT: &str = "MALM_V1_RACE_ROOT";
const CHILD_SCENARIO: &str = "MALM_V1_RACE_SCENARIO";
const CHILD_PREVIOUS: &str = "MALM_V1_RACE_PREVIOUS";
const INITIALIZE_RACE_ROOT: &str = "MALM_V1_INITIALIZE_RACE_ROOT";
const TEST_TIMEOUT: Duration = Duration::from_secs(20);

fn test_guard() -> MutexGuard<'static, ()> {
    static TEST_LOCK: Mutex<()> = Mutex::new(());
    TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner())
}

fn make_engine_at(root: &Path, target: &Path) -> Engine {
    let state_home = root.join("state");
    if !state_home.exists() {
        fs::create_dir(&state_home).unwrap();
        fs::set_permissions(&state_home, fs::Permissions::from_mode(0o700)).unwrap();
    }
    Engine::new(
        EngineConfig::from_state_home(&state_home, StoreAccess::ReadWrite)
            .unwrap()
            .with_target_authority(DeploymentName::new("home").unwrap(), target)
            .unwrap(),
        EnginePorts::system(),
    )
}

fn request_for(scenario: &str) -> PrepareRequestV1 {
    request_for_expected(scenario, None)
}

fn request_for_expected(scenario: &str, expected_generation: Option<Digest>) -> PrepareRequestV1 {
    let authority = DeploymentName::new("home").unwrap();
    let (artifacts, operations) = match scenario {
        "ensure" => (
            vec![],
            vec![
                PrepareOperationV1::ensure_directory(authority, "config/nested/generated", 0o700)
                    .unwrap(),
            ],
        ),
        "replace" => {
            let artifact = ArtifactId::new("config/replacement").unwrap();
            (
                vec![
                    PrepareArtifactV1::new(
                        artifact.clone(),
                        b"prepared replacement\n".to_vec(),
                        "text/plain",
                    )
                    .unwrap(),
                ],
                vec![
                    PrepareOperationV1::replace_file(
                        authority,
                        "config/file.conf",
                        artifact,
                        0o600,
                    )
                    .unwrap(),
                ],
            )
        }
        "place" => {
            let artifact = ArtifactId::new("config/placed").unwrap();
            (
                vec![
                    PrepareArtifactV1::new(
                        artifact.clone(),
                        b"prepared placement\n".to_vec(),
                        "text/plain",
                    )
                    .unwrap(),
                ],
                vec![
                    PrepareOperationV1::place_file(authority, "config/raced.conf", artifact, 0o600)
                        .unwrap(),
                ],
            )
        }
        "remove" => (
            vec![],
            vec![PrepareOperationV1::remove_leaf(authority, "config/file.conf").unwrap()],
        ),
        "assert-exact" => {
            let bytes = b"observed original\n";
            (
                vec![],
                vec![
                    PrepareOperationV1::assert_exact(
                        authority,
                        "config/file.conf",
                        PrepareTargetStateV1::file(
                            Digest::sha256(bytes),
                            bytes.len() as u64,
                            0o600,
                        )
                        .unwrap(),
                    )
                    .unwrap(),
                ],
            )
        }
        "remove-second" => {
            let artifact = ArtifactId::new("config/first").unwrap();
            (
                vec![
                    PrepareArtifactV1::new(
                        artifact.clone(),
                        b"first operation\n".to_vec(),
                        "text/plain",
                    )
                    .unwrap(),
                ],
                vec![
                    PrepareOperationV1::place_file(
                        authority.clone(),
                        "config/first.conf",
                        artifact,
                        0o600,
                    )
                    .unwrap(),
                    PrepareOperationV1::remove_leaf(authority, "config/obsolete.conf").unwrap(),
                ],
            )
        }
        "tree-to-file" => {
            let artifact = ArtifactId::new("config/tree-replacement").unwrap();
            (
                vec![
                    PrepareArtifactV1::new(
                        artifact.clone(),
                        b"replacement for tree\n".to_vec(),
                        "text/plain",
                    )
                    .unwrap(),
                ],
                vec![
                    PrepareOperationV1::replace_file(authority, "config/tree", artifact, 0o600)
                        .unwrap(),
                ],
            )
        }
        other => panic!("unknown race scenario {other}"),
    };
    PrepareRequestV1::from(PrepareRequestPartsV1 {
        namespace: NamespaceName::new("workstation").unwrap(),
        expected_head: expected_generation,
        graph_digest: Digest::sha256(scenario.as_bytes()),
        inputs: vec![],
        artifacts,
        transforms: vec![],
        findings: vec![],
        operations,
    })
}

fn current_head(engine: &Engine) -> Option<Digest> {
    engine
        .inspect_state_v1(&NamespaceName::new("workstation").unwrap())
        .unwrap()
        .head()
        .cloned()
}

fn seed_owned_files(engine: &Engine, files: &[(&str, &[u8])]) -> Digest {
    let mut artifacts = Vec::new();
    let mut operations = Vec::new();
    for (index, (relative_path, bytes)) in files.iter().enumerate() {
        let artifact = ArtifactId::new(format!("seed/{index}")).unwrap();
        artifacts
            .push(PrepareArtifactV1::new(artifact.clone(), bytes.to_vec(), "text/plain").unwrap());
        operations.push(
            PrepareOperationV1::place_file(
                DeploymentName::new("home").unwrap(),
                *relative_path,
                artifact,
                0o600,
            )
            .unwrap(),
        );
    }
    let prepared = engine
        .prepare_v1(&PrepareRequestV1::from(PrepareRequestPartsV1 {
            namespace: NamespaceName::new("workstation").unwrap(),
            expected_head: current_head(engine),
            graph_digest: Digest::sha256(b"race fixture ownership"),
            inputs: vec![],
            artifacts,
            transforms: vec![],
            findings: vec![],
            operations,
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
        .unwrap()
        .head()
        .clone()
}

fn seed_owned_tree(engine: &Engine) -> Digest {
    let contents = b"owned tree child\n";
    let file = file_object_digest_v1(contents).unwrap();
    engine.publish_file_object_v1(&file, contents).unwrap();
    let object = TreeObjectV1::new(
        0o700,
        vec![
            TreeEntryV1::file(
                TreePathSegmentV1::new("child.txt").unwrap(),
                0o600,
                file,
                contents.len() as u64,
            )
            .unwrap(),
        ],
    )
    .unwrap();
    let tree = tree_object_digest_v1(&object);
    engine.publish_tree_object_v1(&tree, &object).unwrap();
    let prepared = engine
        .prepare_v1(&PrepareRequestV1::from(PrepareRequestPartsV1 {
            namespace: NamespaceName::new("workstation").unwrap(),
            expected_head: current_head(engine),
            graph_digest: Digest::sha256(b"race fixture tree ownership"),
            inputs: vec![],
            artifacts: vec![],
            transforms: vec![],
            findings: vec![],
            operations: vec![
                PrepareOperationV1::place_tree(
                    DeploymentName::new("home").unwrap(),
                    "config/tree",
                    tree,
                )
                .unwrap(),
            ],
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
        .unwrap()
        .head()
        .clone()
}

#[test]
fn commit_race_child() {
    let Some(root) = std::env::var_os(CHILD_ROOT) else {
        return;
    };
    let _test_guard = test_guard();
    let root = std::path::PathBuf::from(root);
    let scenario = std::env::var(CHILD_SCENARIO).expect("race scenario");
    let engine = make_engine_at(&root, &root.join("target"));
    let expected_generation = std::env::var(CHILD_PREVIOUS)
        .ok()
        .map(|value| Digest::new(value).expect("valid previous generation"))
        .or_else(|| current_head(&engine));
    let prepared = engine
        .prepare_v1(&request_for_expected(
            &scenario,
            expected_generation.clone(),
        ))
        .unwrap();
    let request = CommitRequestV1::new(
        prepared.plan_id().clone(),
        ApprovalV1::new(
            prepared.plan_id().clone(),
            prepared.approval_digest().clone(),
        ),
    );

    let result = engine.commit_v1(&request);

    assert!(
        matches!(
            result,
            Err(CommitError::StaleTarget(_)
                | CommitError::RollbackFailed(_)
                | CommitError::InvalidStore(_)
                | CommitError::InvalidJournal(_))
        ),
        "race was not rejected safely: {result:?}"
    );
    let active = engine
        .inspect_state_v1(&NamespaceName::new("workstation").unwrap())
        .unwrap();
    if std::env::var("MALM_FAILPOINT").is_ok_and(|value| value.contains("cleanup.")) {
        assert!(active.head().is_some());
    } else {
        assert_eq!(active.head(), expected_generation.as_ref());
    }
}

/// Runs commit scenarios that must abort at a failpoint instead of returning an error.
#[test]
fn commit_abort_child() {
    let Some(root) = std::env::var_os(CHILD_ROOT) else {
        return;
    };
    let _test_guard = test_guard();
    let root = std::path::PathBuf::from(root);
    let scenario = std::env::var(CHILD_SCENARIO).expect("crash scenario");
    let engine = make_engine_at(&root, &root.join("target"));
    let expected_generation = std::env::var(CHILD_PREVIOUS)
        .ok()
        .map(|value| Digest::new(value).expect("valid previous generation"))
        .or_else(|| current_head(&engine));
    let prepared = engine
        .prepare_v1(&request_for_expected(
            &scenario,
            expected_generation.clone(),
        ))
        .unwrap();
    let request = CommitRequestV1::new(
        prepared.plan_id().clone(),
        ApprovalV1::new(
            prepared.plan_id().clone(),
            prepared.approval_digest().clone(),
        ),
    );

    // The failpoint must abort before this call returns. A normal return makes
    // the child exit successfully, which the parent treats as a failure.
    let _ = engine.commit_v1(&request);
}

#[test]
fn initialize_race_child() {
    let Some(root) = std::env::var_os(INITIALIZE_RACE_ROOT) else {
        return;
    };
    let _test_guard = test_guard();
    let root = std::path::PathBuf::from(root);
    let engine = make_engine_at(&root, &root.join("target"));
    assert!(engine.initialize_store().is_err());
}

fn run_paused(root: &Path, scenario: &str, failpoint: &str, mutate: impl FnOnce()) {
    run_paused_with_previous(root, scenario, failpoint, None, mutate);
}

fn run_paused_with_previous(
    root: &Path,
    scenario: &str,
    failpoint: &str,
    previous: Option<&Digest>,
    mutate: impl FnOnce(),
) {
    let marker = root.join("race.marker");
    let continue_path = root.join("race.continue");
    let expected_marker = match failpoint.split_once('=') {
        Some((name, nth)) => format!("{name}={nth}\n"),
        None => format!("{failpoint}=1\n"),
    };
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args(["--exact", "commit_race_child", "--nocapture"])
        .env(CHILD_ROOT, root)
        .env(CHILD_SCENARIO, scenario)
        .env("MALM_FAILPOINT", failpoint)
        .env("MALM_FAILPOINT_MODE", "pause")
        .env("MALM_FAILPOINT_MARKER", &marker)
        .env("MALM_FAILPOINT_CONTINUE", &continue_path)
        .env("MALM_FAILPOINT_TIMEOUT_MS", "15000")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(previous) = previous {
        command.env(CHILD_PREVIOUS, previous.as_str());
    } else {
        command.env_remove(CHILD_PREVIOUS);
    }
    let mut child = command.spawn().unwrap();

    let started = Instant::now();
    loop {
        if fs::read_to_string(&marker).is_ok_and(|contents| contents == expected_marker) {
            break;
        }
        if child.try_wait().unwrap().is_some() {
            fail_child(child, "child exited before reaching the pause barrier");
        }
        if started.elapsed() >= TEST_TIMEOUT {
            fail_child(child, "timed out waiting for the pause marker");
        }
        thread::sleep(Duration::from_millis(5));
    }

    mutate();
    fs::write(&continue_path, b"continue\n").unwrap();

    let resumed = Instant::now();
    loop {
        if child.try_wait().unwrap().is_some() {
            break;
        }
        if resumed.elapsed() >= TEST_TIMEOUT {
            fail_child(child, "timed out waiting for the resumed child");
        }
        thread::sleep(Duration::from_millis(5));
    }
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "race child failed\nstatus: {:?}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}

fn run_raced_crash(
    root: &Path,
    scenario: &str,
    before_rename: &str,
    crash_after: &str,
    mutate: impl FnOnce(),
) {
    run_raced_crash_with_previous(root, scenario, before_rename, crash_after, None, mutate);
}

fn run_raced_crash_with_previous(
    root: &Path,
    scenario: &str,
    before_rename: &str,
    crash_after: &str,
    previous: Option<&Digest>,
    mutate: impl FnOnce(),
) {
    let marker = root.join("race.marker");
    let continue_path = root.join("race.continue");
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args(["--exact", "commit_race_child", "--nocapture"])
        .env(CHILD_ROOT, root)
        .env(CHILD_SCENARIO, scenario)
        .env("MALM_FAILPOINT", format!("{before_rename},{crash_after}"))
        .env("MALM_FAILPOINT_MODE", "pause")
        .env("MALM_FAILPOINT_MARKER", &marker)
        .env("MALM_FAILPOINT_CONTINUE", &continue_path)
        .env("MALM_FAILPOINT_TIMEOUT_MS", "15000")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(previous) = previous {
        command.env(CHILD_PREVIOUS, previous.as_str());
    } else {
        command.env_remove(CHILD_PREVIOUS);
    }
    let mut child = command.spawn().unwrap();

    wait_for_marker(&mut child, &marker, &format!("{before_rename}=1\n"));
    mutate();
    fs::remove_file(&marker).unwrap();
    fs::write(&continue_path, b"continue\n").unwrap();
    wait_for_marker(&mut child, &marker, &format!("{crash_after}=1\n"));

    child.kill().unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(
        !output.status.success(),
        "race child survived injected crash\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}

fn wait_for_marker(child: &mut Child, marker: &Path, expected: &str) {
    let started = Instant::now();
    loop {
        if fs::read_to_string(marker).is_ok_and(|contents| contents == expected) {
            return;
        }
        if let Some(status) = child.try_wait().unwrap() {
            panic!("child exited before pause marker {expected:?}: {status}");
        }
        if started.elapsed() >= TEST_TIMEOUT {
            let _ = child.kill();
            panic!("timed out waiting for pause marker {expected:?}");
        }
        thread::sleep(Duration::from_millis(5));
    }
}

fn fail_child(mut child: Child, reason: &str) -> ! {
    let _ = child.kill();
    let output = child.wait_with_output().unwrap();
    panic!(
        "{reason}\nstatus: {:?}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}

fn assert_rejected_cleanly(engine: &Engine, expected: Option<&Digest>) {
    assert_eq!(
        engine
            .inspect_state_v1(&NamespaceName::new("workstation").unwrap())
            .unwrap()
            .head(),
        expected
    );
    assert!(
        !engine
            .config()
            .state_root()
            .join("transactions/current.json")
            .exists()
    );
}

fn assert_no_staging_entries(directory: &Path) {
    assert!(fs::read_dir(directory).unwrap().all(|entry| {
        !entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with(".malm-")
    }));
}

#[test]
fn initialization_revalidates_missing_catalog_state_after_locking() {
    let _test_guard = test_guard();
    let temp = tempfile::tempdir().unwrap();
    let target = temp.path().join("target");
    fs::create_dir(&target).unwrap();
    let engine = make_engine_at(temp.path(), &target);
    engine.initialize_store().unwrap();
    let state_root = engine.config().state_root();
    fs::remove_file(state_root.join("state/catalog.json")).unwrap();
    fs::remove_file(state_root.join("transaction.lock")).unwrap();
    let marker = temp.path().join("initialize-race.marker");
    let continue_path = temp.path().join("initialize-race.continue");
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "initialize_race_child", "--nocapture"])
        .env(INITIALIZE_RACE_ROOT, temp.path())
        .env("MALM_FAILPOINT", "v1.initialize.before_lock")
        .env("MALM_FAILPOINT_MODE", "pause")
        .env("MALM_FAILPOINT_MARKER", &marker)
        .env("MALM_FAILPOINT_CONTINUE", &continue_path)
        .env("MALM_FAILPOINT_TIMEOUT_MS", "15000")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    wait_for_marker(&mut child, &marker, "v1.initialize.before_lock=1\n");

    let sentinel = state_root.join("state/concurrent-sentinel");
    fs::write(&sentinel, b"concurrent authority\n").unwrap();
    fs::write(&continue_path, b"continue\n").unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "initialize race child failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(fs::read(sentinel).unwrap(), b"concurrent authority\n");
    assert!(!state_root.join("state/catalog.json").exists());
}

#[test]
fn ensure_revalidates_an_ancestor_replaced_after_batch_preflight() {
    let _test_guard = test_guard();
    let temp = tempfile::tempdir().unwrap();
    let target = temp.path().join("target");
    fs::create_dir(&target).unwrap();
    fs::create_dir(target.join("config")).unwrap();
    fs::create_dir(target.join("config/nested")).unwrap();
    fs::write(target.join("config/nested/original-marker"), b"original\n").unwrap();
    let engine = make_engine_at(temp.path(), &target);
    engine.initialize_store().unwrap();

    run_paused(temp.path(), "ensure", "v1.commit.after_preflight", || {
        fs::rename(target.join("config"), target.join("excluded-config")).unwrap();
        fs::create_dir(target.join("config")).unwrap();
        fs::create_dir(target.join("config/nested")).unwrap();
        fs::write(
            target.join("config/nested/replacement-marker"),
            b"replacement\n",
        )
        .unwrap();
    });

    assert_eq!(
        fs::read(target.join("excluded-config/nested/original-marker")).unwrap(),
        b"original\n"
    );
    assert_eq!(
        fs::read(target.join("config/nested/replacement-marker")).unwrap(),
        b"replacement\n"
    );
    assert!(!target.join("excluded-config/nested/generated").exists());
    assert!(!target.join("config/nested/generated").exists());
    assert_no_staging_entries(&target.join("excluded-config/nested"));
    assert_no_staging_entries(&target.join("config/nested"));
    assert_rejected_cleanly(&engine, None);
}

#[test]
fn replacement_revalidates_a_leaf_immediately_before_the_operation() {
    let _test_guard = test_guard();
    let temp = tempfile::tempdir().unwrap();
    let target = temp.path().join("target");
    fs::create_dir(&target).unwrap();
    fs::create_dir(target.join("config")).unwrap();
    let leaf = target.join("config/file.conf");
    let engine = make_engine_at(temp.path(), &target);
    engine.initialize_store().unwrap();
    let baseline = seed_owned_files(&engine, &[("config/file.conf", b"observed original\n")]);

    run_paused(temp.path(), "replace", "v1.commit.after_journal", || {
        fs::rename(&leaf, target.join("config/excluded-original.conf")).unwrap();
        fs::write(&leaf, b"concurrent replacement\n").unwrap();
    });

    assert_eq!(fs::read(&leaf).unwrap(), b"concurrent replacement\n");
    assert_eq!(
        fs::read(target.join("config/excluded-original.conf")).unwrap(),
        b"observed original\n"
    );
    assert_no_staging_entries(&target.join("config"));
    assert_rejected_cleanly(&engine, Some(&baseline));
}

#[test]
fn replacement_rejects_and_restores_a_leaf_swapped_after_the_final_check() {
    let _test_guard = test_guard();
    let temp = tempfile::tempdir().unwrap();
    let target = temp.path().join("target");
    fs::create_dir(&target).unwrap();
    fs::create_dir(target.join("config")).unwrap();
    let leaf = target.join("config/file.conf");
    let engine = make_engine_at(temp.path(), &target);
    engine.initialize_store().unwrap();
    let baseline = seed_owned_files(&engine, &[("config/file.conf", b"observed original\n")]);

    run_paused(
        temp.path(),
        "replace",
        "v1.commit.place.before_backup_rename",
        || {
            fs::rename(&leaf, target.join("config/excluded-original.conf")).unwrap();
            fs::write(&leaf, b"concurrent replacement\n").unwrap();
        },
    );

    assert_eq!(fs::read(&leaf).unwrap(), b"concurrent replacement\n");
    assert_eq!(
        fs::read(target.join("config/excluded-original.conf")).unwrap(),
        b"observed original\n"
    );
    assert_no_staging_entries(&target.join("config"));
    assert_rejected_cleanly(&engine, Some(&baseline));
}

#[test]
fn removal_rejects_and_restores_a_leaf_swapped_after_the_final_check() {
    let _test_guard = test_guard();
    let temp = tempfile::tempdir().unwrap();
    let target = temp.path().join("target");
    fs::create_dir(&target).unwrap();
    fs::create_dir(target.join("config")).unwrap();
    let leaf = target.join("config/file.conf");
    let engine = make_engine_at(temp.path(), &target);
    engine.initialize_store().unwrap();
    let baseline = seed_owned_files(&engine, &[("config/file.conf", b"observed original\n")]);

    run_paused(
        temp.path(),
        "remove",
        "v1.commit.remove.before_backup_rename",
        || {
            fs::rename(&leaf, target.join("config/excluded-original.conf")).unwrap();
            fs::write(&leaf, b"concurrent replacement\n").unwrap();
        },
    );

    assert_eq!(fs::read(&leaf).unwrap(), b"concurrent replacement\n");
    assert_eq!(
        fs::read(target.join("config/excluded-original.conf")).unwrap(),
        b"observed original\n"
    );
    assert_no_staging_entries(&target.join("config"));
    assert_rejected_cleanly(&engine, Some(&baseline));
}

#[test]
fn backup_rename_rejects_a_same_inode_rewrite_with_restored_mtime() {
    let _test_guard = test_guard();
    for scenario in ["replace", "remove"] {
        let before_backup = if scenario == "replace" {
            "v1.commit.place.before_backup_rename"
        } else {
            "v1.commit.remove.before_backup_rename"
        };
        for failpoint in [
            "v1.commit.source.before_initial_hash",
            before_backup,
            "v1.commit.source.after_relocated_hash",
        ] {
            let temp = tempfile::tempdir().unwrap();
            let target = temp.path().join("target");
            fs::create_dir(&target).unwrap();
            fs::create_dir(target.join("config")).unwrap();
            let leaf = target.join("config/file.conf");
            let original = b"observed original\n";
            let replacement = vec![b'X'; original.len()];
            let engine = make_engine_at(temp.path(), &target);
            engine.initialize_store().unwrap();
            let baseline = seed_owned_files(&engine, &[("config/file.conf", original)]);
            let metadata = fs::metadata(&leaf).unwrap();
            let accessed = filetime::FileTime::from_last_access_time(&metadata);
            let modified = filetime::FileTime::from_last_modification_time(&metadata);
            let mut open_leaf = OpenOptions::new()
                .read(true)
                .write(true)
                .open(&leaf)
                .unwrap();

            run_paused(temp.path(), scenario, failpoint, || {
                open_leaf.seek(SeekFrom::Start(0)).unwrap();
                open_leaf.write_all(&replacement).unwrap();
                open_leaf.flush().unwrap();
                filetime::set_file_handle_times(&open_leaf, Some(accessed), Some(modified))
                    .unwrap();
            });

            assert_eq!(fs::read(&leaf).unwrap(), replacement, "{failpoint}");
            assert_no_staging_entries(&target.join("config"));
            assert_rejected_cleanly(&engine, Some(&baseline));
        }
    }
}

#[test]
fn backup_intent_digest_rejects_a_rewrite_after_rename_crash() {
    let _test_guard = test_guard();
    for scenario in ["replace", "remove"] {
        let temp = tempfile::tempdir().unwrap();
        let target = temp.path().join("target");
        fs::create_dir(&target).unwrap();
        fs::create_dir(target.join("config")).unwrap();
        let leaf = target.join("config/file.conf");
        let original = b"observed original\n";
        let replacement = vec![b'Y'; original.len()];
        let engine = make_engine_at(temp.path(), &target);
        engine.initialize_store().unwrap();
        seed_owned_files(&engine, &[("config/file.conf", original)]);
        let metadata = fs::metadata(&leaf).unwrap();
        let accessed = filetime::FileTime::from_last_access_time(&metadata);
        let modified = filetime::FileTime::from_last_modification_time(&metadata);
        let mut open_leaf = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&leaf)
            .unwrap();
        let prepared = engine
            .prepare_v1(&request_for_expected(scenario, current_head(&engine)))
            .unwrap();
        let before_rename = if scenario == "replace" {
            "v1.commit.place.before_backup_rename"
        } else {
            "v1.commit.remove.before_backup_rename"
        };
        let after_rename = if scenario == "replace" {
            "v1.commit.place.after_backup_rename"
        } else {
            "v1.commit.remove.after_backup_rename"
        };

        run_raced_crash(temp.path(), scenario, before_rename, after_rename, || {
            open_leaf.seek(SeekFrom::Start(0)).unwrap();
            open_leaf.write_all(&replacement).unwrap();
            open_leaf.flush().unwrap();
            filetime::set_file_handle_times(&open_leaf, Some(accessed), Some(modified)).unwrap();
        });

        assert!(engine.recover_v1().is_err(), "{scenario}");
        assert!(!leaf.exists(), "{scenario}");
        let backup = target.join("config").join(format!(
            ".malm-{}-0-backup",
            &prepared.plan_id().as_str()[3..]
        ));
        assert_eq!(fs::read(backup).unwrap(), replacement, "{scenario}");
        assert!(
            engine
                .config()
                .state_root()
                .join("transactions/current.json")
                .is_file(),
            "{scenario}"
        );
    }
}

#[test]
fn final_placement_restores_a_substituted_staging_inode_without_consuming_it() {
    let _test_guard = test_guard();
    let temp = tempfile::tempdir().unwrap();
    let target = temp.path().join("target");
    fs::create_dir(&target).unwrap();
    fs::create_dir(target.join("config")).unwrap();
    let engine = make_engine_at(temp.path(), &target);
    engine.initialize_store().unwrap();
    let prepared = engine.prepare_v1(&request_for("place")).unwrap();
    let staging = target
        .join("config")
        .join(format!(".malm-{}-0-new", &prepared.plan_id().as_str()[3..]));
    let displaced = target.join("config/displaced-malm-staging");

    run_paused(
        temp.path(),
        "place",
        "v1.commit.place.before_final_rename",
        || {
            fs::rename(&staging, &displaced).unwrap();
            fs::write(&staging, b"unrelated staging bytes\n").unwrap();
        },
    );

    assert!(!target.join("config/raced.conf").exists());
    assert_eq!(fs::read(&staging).unwrap(), b"unrelated staging bytes\n");
    assert_eq!(fs::read(&displaced).unwrap(), b"prepared placement\n");
    assert!(
        engine
            .config()
            .state_root()
            .join("transactions/current.json")
            .is_file()
    );
    assert!(
        engine
            .inspect_state_v1(&NamespaceName::new("workstation").unwrap())
            .unwrap()
            .head()
            .is_none()
    );
}

#[test]
fn final_applied_rebound_rejects_substitution_before_catalog_publication() {
    let _test_guard = test_guard();
    let temp = tempfile::tempdir().unwrap();
    let target = temp.path().join("target");
    fs::create_dir(&target).unwrap();
    fs::create_dir(target.join("config")).unwrap();
    let engine = make_engine_at(temp.path(), &target);
    engine.initialize_store().unwrap();
    let leaf = target.join("config/raced.conf");
    let displaced = target.join("config/displaced-prepared.conf");

    run_paused(
        temp.path(),
        "place",
        "v1.commit.verify.before_final_rebound",
        || {
            fs::rename(&leaf, &displaced).unwrap();
            fs::write(&leaf, b"unrelated concurrent content\n").unwrap();
        },
    );

    assert_eq!(fs::read(&leaf).unwrap(), b"unrelated concurrent content\n");
    assert_eq!(fs::read(&displaced).unwrap(), b"prepared placement\n");
    assert_rejected_cleanly(&engine, None);
}

#[test]
fn final_exact_proof_rejects_drift_after_the_noop_application_phase() {
    let _test_guard = test_guard();
    let temp = tempfile::tempdir().unwrap();
    let target = temp.path().join("target");
    fs::create_dir(&target).unwrap();
    fs::create_dir(target.join("config")).unwrap();
    let engine = make_engine_at(temp.path(), &target);
    engine.initialize_store().unwrap();
    let previous = seed_owned_files(&engine, &[("config/file.conf", b"observed original\n")]);
    let leaf = target.join("config/file.conf");

    run_paused_with_previous(
        temp.path(),
        "assert-exact",
        "v1.commit.burst.after_final_sync",
        Some(&previous),
        || fs::write(&leaf, b"concurrent drift\n").unwrap(),
    );

    assert_eq!(fs::read(&leaf).unwrap(), b"concurrent drift\n");
    assert_eq!(current_head(&engine).as_ref(), Some(&previous));
    assert!(
        engine
            .config()
            .state_root()
            .join("transactions/current.json")
            .is_file()
    );
}

#[test]
fn recursive_tree_cleanup_does_not_unlink_a_substituted_child() {
    let _test_guard = test_guard();
    let temp = tempfile::tempdir().unwrap();
    let target = temp.path().join("target");
    fs::create_dir(&target).unwrap();
    fs::create_dir(target.join("config")).unwrap();
    let engine = make_engine_at(temp.path(), &target);
    engine.initialize_store().unwrap();
    let previous = seed_owned_tree(&engine);
    let displaced = target.join("config/displaced-tree-child.txt");
    let mut raced_child = None;

    run_paused_with_previous(
        temp.path(),
        "tree-to-file",
        "v1.commit.tree_cleanup.before_child_unlink",
        Some(&previous),
        || {
            let quarantine = fs::read_dir(target.join("config"))
                .unwrap()
                .map(Result::unwrap)
                .find(|entry| {
                    entry
                        .file_name()
                        .to_string_lossy()
                        .ends_with("-delete-backup")
                })
                .expect("tree backup quarantine")
                .path();
            let child = quarantine.join("child.txt");
            fs::rename(&child, &displaced).unwrap();
            fs::write(&child, b"unrelated quarantined child\n").unwrap();
            raced_child = Some(child);
        },
    );

    let raced_child = raced_child.unwrap();
    assert_eq!(
        fs::read(&raced_child).unwrap(),
        b"unrelated quarantined child\n"
    );
    assert_eq!(fs::read(&displaced).unwrap(), b"owned tree child\n");
    assert_eq!(
        fs::read(target.join("config/tree")).unwrap(),
        b"replacement for tree\n"
    );
    assert!(
        engine
            .config()
            .state_root()
            .join("transactions/current.json")
            .is_file()
    );
    assert!(engine.recover_v1().is_err());
    assert_eq!(
        fs::read(raced_child).unwrap(),
        b"unrelated quarantined child\n"
    );
}

#[test]
fn journal_publication_does_not_exchange_a_substituted_staging_inode() {
    let _test_guard = test_guard();
    let temp = tempfile::tempdir().unwrap();
    let target = temp.path().join("target");
    fs::create_dir(&target).unwrap();
    fs::create_dir(target.join("config")).unwrap();
    let engine = make_engine_at(temp.path(), &target);
    engine.initialize_store().unwrap();
    let transactions = engine.config().state_root().join("transactions");
    let current = transactions.join("current.json");
    let update = transactions.join(".current.json.update");
    let displaced = transactions.join("displaced-journal-update");

    run_paused(
        temp.path(),
        "place",
        "v1.commit.journal_update.after_link",
        || {
            fs::rename(&update, &displaced).unwrap();
            fs::copy(&current, &update).unwrap();
        },
    );

    assert!(!target.join("config/raced.conf").exists());
    assert!(current.is_file());
    assert!(update.is_file());
    assert!(displaced.is_file());
    assert_eq!(fs::read(&current).unwrap(), fs::read(&update).unwrap());
    assert!(
        engine
            .inspect_state_v1(&NamespaceName::new("workstation").unwrap())
            .unwrap()
            .head()
            .is_none()
    );
}

#[test]
fn journal_publication_does_not_discard_a_substituted_current_inode() {
    let _test_guard = test_guard();
    let temp = tempfile::tempdir().unwrap();
    let target = temp.path().join("target");
    fs::create_dir(&target).unwrap();
    fs::create_dir(target.join("config")).unwrap();
    let engine = make_engine_at(temp.path(), &target);
    engine.initialize_store().unwrap();
    let transactions = engine.config().state_root().join("transactions");
    let current = transactions.join("current.json");
    let update = transactions.join(".current.json.update");
    let displaced = transactions.join("displaced-current-journal");

    run_paused(
        temp.path(),
        "place",
        "v1.commit.journal_update.after_link",
        || {
            fs::rename(&current, &displaced).unwrap();
            fs::copy(&displaced, &current).unwrap();
        },
    );

    assert!(!target.join("config/raced.conf").exists());
    assert!(current.is_file());
    assert!(update.is_file());
    assert!(displaced.is_file());
    assert_eq!(fs::read(&current).unwrap(), fs::read(&displaced).unwrap());
    assert_ne!(fs::read(&current).unwrap(), fs::read(&update).unwrap());
    assert!(
        engine
            .inspect_state_v1(&NamespaceName::new("workstation").unwrap())
            .unwrap()
            .head()
            .is_none()
    );
}

#[test]
fn catalog_publication_does_not_install_rewritten_staged_bytes() {
    let _test_guard = test_guard();
    let temp = tempfile::tempdir().unwrap();
    let target = temp.path().join("target");
    fs::create_dir(&target).unwrap();
    fs::create_dir(target.join("config")).unwrap();
    fs::create_dir(target.join("config/nested")).unwrap();
    let engine = make_engine_at(temp.path(), &target);
    engine.initialize_store().unwrap();
    let unrelated = engine
        .prepare_v1(&PrepareRequestV1::from(PrepareRequestPartsV1 {
            namespace: NamespaceName::new("server").unwrap(),
            expected_head: None,
            graph_digest: Digest::sha256(b"unrelated namespace"),
            inputs: vec![],
            artifacts: vec![],
            transforms: vec![],
            findings: vec![],
            operations: vec![],
        }))
        .unwrap();
    let unrelated = engine
        .commit_v1(&CommitRequestV1::new(
            unrelated.plan_id().clone(),
            ApprovalV1::new(
                unrelated.plan_id().clone(),
                unrelated.approval_digest().clone(),
            ),
        ))
        .unwrap();
    let unrelated_head = unrelated.head().clone();
    let baseline = engine.prepare_v1(&request_for("place")).unwrap();
    let baseline = engine
        .commit_v1(&CommitRequestV1::new(
            baseline.plan_id().clone(),
            ApprovalV1::new(
                baseline.plan_id().clone(),
                baseline.approval_digest().clone(),
            ),
        ))
        .unwrap();
    let previous = baseline.head().clone();
    let catalog_path = engine.config().state_root().join("state/catalog.json");
    let previous_catalog = fs::read(&catalog_path).unwrap();
    let state = engine.config().state_root().join("state");
    let active = state.join("catalog.json");
    let staging = state.join(".catalog.json.new");

    run_paused_with_previous(
        temp.path(),
        "ensure",
        "v1.commit.catalog.after_staging",
        Some(&previous),
        || {
            fs::write(&staging, fs::read(&active).unwrap()).unwrap();
        },
    );

    assert_eq!(
        engine
            .inspect_state_v1(&NamespaceName::new("workstation").unwrap())
            .unwrap()
            .head(),
        Some(&previous)
    );
    assert_eq!(fs::read(&catalog_path).unwrap(), previous_catalog);
    assert_eq!(
        engine
            .inspect_state_v1(&NamespaceName::new("server").unwrap())
            .unwrap()
            .head(),
        Some(&unrelated_head)
    );
    assert!(target.join("config/nested/generated").is_dir());
    assert!(
        engine
            .config()
            .state_root()
            .join("transactions/current.json")
            .is_file()
    );
    let recovered = engine.recover_v1().unwrap();
    assert_eq!(recovered.head(), Some(&previous));
    assert_eq!(fs::read(&catalog_path).unwrap(), previous_catalog);
    assert_eq!(
        engine
            .inspect_state_v1(&NamespaceName::new("server").unwrap())
            .unwrap()
            .head(),
        Some(&unrelated_head)
    );
    assert!(!target.join("config/nested/generated").exists());
    assert!(!staging.exists());
}

#[test]
fn catalog_exchange_crash_recovers_with_the_previous_catalog_staged() {
    let _test_guard = test_guard();
    let temp = tempfile::tempdir().unwrap();
    let target = temp.path().join("target");
    fs::create_dir(&target).unwrap();
    fs::create_dir(target.join("config")).unwrap();
    fs::create_dir(target.join("config/nested")).unwrap();
    let engine = make_engine_at(temp.path(), &target);
    engine.initialize_store().unwrap();
    let unrelated = engine
        .prepare_v1(&PrepareRequestV1::from(PrepareRequestPartsV1 {
            namespace: NamespaceName::new("server").unwrap(),
            expected_head: None,
            graph_digest: Digest::sha256(b"unrelated namespace"),
            inputs: vec![],
            artifacts: vec![],
            transforms: vec![],
            findings: vec![],
            operations: vec![],
        }))
        .unwrap();
    let unrelated = engine
        .commit_v1(&CommitRequestV1::new(
            unrelated.plan_id().clone(),
            ApprovalV1::new(
                unrelated.plan_id().clone(),
                unrelated.approval_digest().clone(),
            ),
        ))
        .unwrap();
    let unrelated_head = unrelated.head().clone();
    let baseline = engine.prepare_v1(&request_for("place")).unwrap();
    let baseline = engine
        .commit_v1(&CommitRequestV1::new(
            baseline.plan_id().clone(),
            ApprovalV1::new(
                baseline.plan_id().clone(),
                baseline.approval_digest().clone(),
            ),
        ))
        .unwrap();
    let previous = baseline.head().clone();
    let catalog_path = engine.config().state_root().join("state/catalog.json");
    let previous_catalog = fs::read(&catalog_path).unwrap();

    run_raced_crash_with_previous(
        temp.path(),
        "ensure",
        "v1.commit.catalog.after_staging",
        "v1.commit.catalog.after_exchange",
        Some(&previous),
        || {},
    );

    let state = engine
        .inspect_state_v1(&NamespaceName::new("workstation").unwrap())
        .unwrap();
    let next = state.head().expect("exchanged next generation").clone();
    assert_ne!(next, previous);
    let next_catalog = fs::read(&catalog_path).unwrap();
    assert_ne!(next_catalog, previous_catalog);
    assert!(
        engine
            .config()
            .state_root()
            .join("state/.catalog.json.new")
            .is_file()
    );
    assert_eq!(
        fs::read(engine.config().state_root().join("state/.catalog.json.new")).unwrap(),
        previous_catalog
    );
    assert_eq!(
        engine
            .inspect_state_v1(&NamespaceName::new("server").unwrap())
            .unwrap()
            .head(),
        Some(&unrelated_head)
    );
    assert!(target.join("config/nested/generated").is_dir());
    let recovered = engine.recover_v1().unwrap();
    assert_eq!(recovered.head(), Some(&next));
    assert_eq!(fs::read(&catalog_path).unwrap(), next_catalog);
    assert_eq!(
        engine
            .inspect_state_v1(&NamespaceName::new("server").unwrap())
            .unwrap()
            .head(),
        Some(&unrelated_head)
    );
    assert!(target.join("config/nested/generated").is_dir());
    assert!(
        !engine
            .config()
            .state_root()
            .join("state/.catalog.json.new")
            .exists()
    );
}

#[test]
fn recovery_validates_catalog_staging_before_replaying_targets() {
    let _test_guard = test_guard();
    let temp = tempfile::tempdir().unwrap();
    let target = temp.path().join("target");
    fs::create_dir(&target).unwrap();
    fs::create_dir(target.join("config")).unwrap();
    fs::create_dir(target.join("config/nested")).unwrap();
    let engine = make_engine_at(temp.path(), &target);
    engine.initialize_store().unwrap();

    run_raced_crash(
        temp.path(),
        "ensure",
        "v1.commit.after_journal",
        "v1.commit.catalog.after_staging",
        || {},
    );

    let generated = target.join("config/nested/generated");
    let staging = engine.config().state_root().join("state/.catalog.json.new");
    let valid_staging = fs::read(&staging).unwrap();
    assert!(generated.is_dir());
    fs::write(&staging, b"{}\n").unwrap();

    assert!(matches!(
        engine.recover_v1(),
        Err(CommitError::InvalidJournal(_))
    ));
    assert!(generated.is_dir());
    assert!(
        engine
            .config()
            .state_root()
            .join("transactions/current.json")
            .is_file()
    );

    fs::write(&staging, valid_staging).unwrap();
    engine.recover_v1().unwrap();
    assert!(!generated.exists());
}

#[test]
fn raced_leaf_crashes_fail_closed_without_authorizing_the_concurrent_inode() {
    let _test_guard = test_guard();
    for (scenario, before_rename, crash_after, restored) in [
        (
            "replace",
            "v1.commit.place.before_backup_rename",
            "v1.commit.place.after_backup_rename",
            false,
        ),
        (
            "replace",
            "v1.commit.place.before_backup_rename",
            "v1.commit.place.after_raced_restore",
            true,
        ),
        (
            "remove",
            "v1.commit.remove.before_backup_rename",
            "v1.commit.remove.after_backup_rename",
            false,
        ),
        (
            "remove",
            "v1.commit.remove.before_backup_rename",
            "v1.commit.remove.after_raced_restore",
            true,
        ),
    ] {
        let temp = tempfile::tempdir().unwrap();
        let target = temp.path().join("target");
        fs::create_dir(&target).unwrap();
        fs::create_dir(target.join("config")).unwrap();
        let leaf = target.join("config/file.conf");
        let engine = make_engine_at(temp.path(), &target);
        engine.initialize_store().unwrap();
        let baseline = seed_owned_files(&engine, &[("config/file.conf", b"observed original\n")]);

        run_raced_crash(temp.path(), scenario, before_rename, crash_after, || {
            fs::rename(&leaf, target.join("config/excluded-original.conf")).unwrap();
            fs::write(&leaf, b"concurrent replacement\n").unwrap();
        });

        assert!(engine.recover_v1().is_err(), "{crash_after}");
        assert!(
            engine
                .config()
                .state_root()
                .join("transactions/current.json")
                .is_file(),
            "{crash_after}"
        );
        if restored {
            assert_eq!(
                fs::read(&leaf).unwrap(),
                b"concurrent replacement\n",
                "{crash_after}"
            );
        } else {
            assert!(!leaf.exists(), "{crash_after}");
            let backups = fs::read_dir(target.join("config"))
                .unwrap()
                .filter_map(Result::ok)
                .filter(|entry| entry.file_name().to_string_lossy().ends_with("-backup"))
                .collect::<Vec<_>>();
            assert_eq!(backups.len(), 1, "{crash_after}");
            assert_eq!(
                fs::read(backups[0].path()).unwrap(),
                b"concurrent replacement\n",
                "{crash_after}"
            );
        }
        assert_eq!(
            fs::read(target.join("config/excluded-original.conf")).unwrap(),
            b"observed original\n",
            "{crash_after}"
        );
        assert!(
            engine
                .inspect_state_v1(&NamespaceName::new("workstation").unwrap())
                .unwrap()
                .head()
                == Some(&baseline),
            "{crash_after}"
        );
    }
}

#[test]
fn absent_place_revalidates_symlink_swaps_toward_the_state_root() {
    let _test_guard = test_guard();
    let temp = tempfile::tempdir().unwrap();
    let target = temp.path().join("target");
    fs::create_dir(&target).unwrap();
    fs::create_dir(target.join("config")).unwrap();
    let engine = make_engine_at(temp.path(), &target);
    engine.initialize_store().unwrap();
    let protected = engine.config().state_root().join("state");
    let protected_marker = protected.join("protected-marker");
    fs::write(&protected_marker, b"protected\n").unwrap();

    run_paused(
        temp.path(),
        "place",
        "v1.commit.place.after_staging",
        || {
            fs::rename(target.join("config"), target.join("excluded-config")).unwrap();
            symlink(&protected, target.join("config")).unwrap();
        },
    );

    assert!(
        fs::symlink_metadata(target.join("config"))
            .unwrap()
            .file_type()
            .is_symlink()
    );
    assert_eq!(fs::read(&protected_marker).unwrap(), b"protected\n");
    assert!(!protected.join("raced.conf").exists());
    assert!(!target.join("excluded-config/raced.conf").exists());
    assert_no_staging_entries(&target.join("excluded-config"));
    assert_rejected_cleanly(&engine, None);
}

#[test]
fn second_remove_is_revalidated_after_the_first_operation_and_rolls_it_back() {
    let _test_guard = test_guard();
    let temp = tempfile::tempdir().unwrap();
    let target = temp.path().join("target");
    fs::create_dir(&target).unwrap();
    fs::create_dir(target.join("config")).unwrap();
    let obsolete = target.join("config/obsolete.conf");
    let engine = make_engine_at(temp.path(), &target);
    engine.initialize_store().unwrap();
    let baseline = seed_owned_files(&engine, &[("config/obsolete.conf", b"observed obsolete\n")]);

    // The phased schedule groups the placement with the removal's backup
    // rename. The raced leaf is detected before placement becomes visible, so
    // the entire group, including the staged placement, rolls back together.
    run_paused(
        temp.path(),
        "remove-second",
        "v1.commit.remove.before_backup_rename",
        || {
            assert!(!target.join("config/first.conf").exists());
            fs::rename(&obsolete, target.join("config/excluded-obsolete.conf")).unwrap();
            fs::write(&obsolete, b"concurrent obsolete\n").unwrap();
        },
    );

    assert!(!target.join("config/first.conf").exists());
    assert_eq!(fs::read(&obsolete).unwrap(), b"concurrent obsolete\n");
    assert_eq!(
        fs::read(target.join("config/excluded-obsolete.conf")).unwrap(),
        b"observed obsolete\n"
    );
    assert_no_staging_entries(&target.join("config"));
    assert_rejected_cleanly(&engine, Some(&baseline));
}

#[test]
fn cleanup_does_not_unlink_a_substituted_quarantine_inode() {
    let _test_guard = test_guard();
    let temp = tempfile::tempdir().unwrap();
    let target = temp.path().join("target");
    fs::create_dir(&target).unwrap();
    fs::create_dir(target.join("config")).unwrap();
    let engine = make_engine_at(temp.path(), &target);
    engine.initialize_store().unwrap();
    seed_owned_files(&engine, &[("config/file.conf", b"observed original\n")]);
    let prepared = engine
        .prepare_v1(&request_for_expected("replace", current_head(&engine)))
        .unwrap();
    let quarantine = target.join("config").join(format!(
        ".malm-{}-0-delete-backup",
        &prepared.plan_id().as_str()[3..]
    ));
    let displaced = target.join("config/displaced-original-backup");

    run_paused(
        temp.path(),
        "replace",
        "v1.commit.cleanup.before_unlink",
        || {
            fs::rename(&quarantine, &displaced).unwrap();
            fs::write(&quarantine, b"unrelated quarantine bytes\n").unwrap();
        },
    );

    assert_eq!(
        fs::read(target.join("config/file.conf")).unwrap(),
        b"prepared replacement\n"
    );
    assert_eq!(
        fs::read(&quarantine).unwrap(),
        b"unrelated quarantine bytes\n"
    );
    assert_eq!(fs::read(&displaced).unwrap(), b"observed original\n");
    assert!(
        engine
            .config()
            .state_root()
            .join("transactions/current.json")
            .is_file()
    );
    assert!(
        engine
            .inspect_state_v1(&NamespaceName::new("workstation").unwrap())
            .unwrap()
            .head()
            .is_some()
    );
    assert!(engine.recover_v1().is_err());
    assert_eq!(
        fs::read(&quarantine).unwrap(),
        b"unrelated quarantine bytes\n"
    );
}

#[test]
fn cleanup_does_not_unlink_a_rewritten_quarantine_inode() {
    let _test_guard = test_guard();
    let temp = tempfile::tempdir().unwrap();
    let target = temp.path().join("target");
    fs::create_dir(&target).unwrap();
    fs::create_dir(target.join("config")).unwrap();
    let leaf = target.join("config/file.conf");
    let original = b"observed original\n";
    let replacement = vec![b'Z'; original.len()];
    let engine = make_engine_at(temp.path(), &target);
    engine.initialize_store().unwrap();
    seed_owned_files(&engine, &[("config/file.conf", original)]);
    let metadata = fs::metadata(&leaf).unwrap();
    let accessed = filetime::FileTime::from_last_access_time(&metadata);
    let modified = filetime::FileTime::from_last_modification_time(&metadata);
    let mut open_leaf = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&leaf)
        .unwrap();
    let prepared = engine
        .prepare_v1(&request_for_expected("replace", current_head(&engine)))
        .unwrap();
    let quarantine = target.join("config").join(format!(
        ".malm-{}-0-delete-backup",
        &prepared.plan_id().as_str()[3..]
    ));

    run_paused(
        temp.path(),
        "replace",
        "v1.commit.cleanup.before_unlink",
        || {
            open_leaf.seek(SeekFrom::Start(0)).unwrap();
            open_leaf.write_all(&replacement).unwrap();
            open_leaf.flush().unwrap();
            filetime::set_file_handle_times(&open_leaf, Some(accessed), Some(modified)).unwrap();
        },
    );

    assert_eq!(fs::read(&quarantine).unwrap(), replacement);
    assert_eq!(
        fs::read(target.join("config/file.conf")).unwrap(),
        b"prepared replacement\n"
    );
    assert!(
        engine
            .config()
            .state_root()
            .join("transactions/current.json")
            .is_file()
    );
    assert!(engine.recover_v1().is_err());
    assert_eq!(fs::read(&quarantine).unwrap(), replacement);
}

#[test]
fn tree_cleanup_before_root_unlink_recovers_forward() {
    let _test_guard = test_guard();
    let temp = tempfile::tempdir().unwrap();
    let target = temp.path().join("target");
    fs::create_dir(&target).unwrap();
    fs::create_dir(target.join("config")).unwrap();
    let engine = make_engine_at(temp.path(), &target);
    engine.initialize_store().unwrap();
    let previous = seed_owned_tree(&engine);

    let output = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "commit_abort_child", "--nocapture"])
        .env(CHILD_ROOT, temp.path())
        .env(CHILD_SCENARIO, "tree-to-file")
        .env(CHILD_PREVIOUS, previous.as_str())
        .env(
            "MALM_FAILPOINT",
            "v1.commit.tree_cleanup.before_root_unlink=1",
        )
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .unwrap();
    assert!(
        !output.status.success(),
        "child unexpectedly survived the failpoint\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    drop(engine);
    let restarted = make_engine_at(temp.path(), &target);
    restarted.recover_v1().unwrap();

    let config = target.join("config");
    assert_eq!(
        fs::read(config.join("tree")).unwrap(),
        b"replacement for tree\n",
        "target should reflect the prepared replacement after recovery"
    );
    assert!(
        !fs::read_dir(&config).unwrap().any(|entry| entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .ends_with("-delete-backup")),
        "tree backup quarantine should be removed"
    );
    assert!(
        !restarted
            .config()
            .state_root()
            .join("transactions/current.json")
            .exists(),
        "journal should be removed after recovery"
    );
    let state = restarted
        .inspect_state_v1(&NamespaceName::new("workstation").unwrap())
        .unwrap();
    assert!(
        state.head().is_some(),
        "catalog should advance to the prepared generation"
    );
    assert_ne!(
        state.head(),
        Some(&previous),
        "generation should change after rolling forward"
    );
}
