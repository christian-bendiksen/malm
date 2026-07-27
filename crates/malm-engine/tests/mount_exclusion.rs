use std::env;
use std::ffi::CString;
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;

use malm_engine::{
    ApprovalV1, CommitError, CommitRequestV1, Engine, EngineConfig, EngineError, EnginePorts,
    FsckFindingCodeV1, FsckRequestV1, GitAcquisitionConfig, GitAcquisitionIssue,
    NamespaceStatusKindV1, NamespaceStatusRequestV1, PackCaptureIssue, PrepareArtifactV1,
    PrepareOperationV1, PrepareRequestPartsV1, PrepareRequestV1, PreparedStoreIssue, StoreAccess,
    TargetStatusKindV1,
};
use malm_pack::{GitObjectId, GitSourceV1, GitUrl, PackSubdir};
use malm_types::{ArtifactId, DeploymentName, Digest, NamespaceName};

const HELPER_ENV: &str = "MALM_ENGINE_BIND_MOUNT_HELPER";
const HELPER_MARKER: &str = "malm-engine bind-mount helper completed";
const TEST_NAME: &str =
    "bind_mount_aliases_are_rejected_for_final_root_prepare_sources_and_scratch";

#[test]
fn bind_mount_aliases_are_rejected_for_final_root_prepare_sources_and_scratch() {
    if env::var_os(HELPER_ENV).is_some() {
        run_bind_mount_checks();
        eprintln!("{HELPER_MARKER}");
        return;
    }

    let probe = Command::new("unshare")
        .args([
            "--user",
            "--map-root-user",
            "--mount",
            "--propagation",
            "private",
            "/bin/true",
        ])
        .output();
    let Ok(probe) = probe else {
        assert!(
            env::var("MALM_REQUIRE_MOUNT_NAMESPACE").as_deref() != Ok("1"),
            "MALM_REQUIRE_MOUNT_NAMESPACE=1 requires the unshare command"
        );
        eprintln!("skipping bind-mount integration test: unshare is unavailable");
        return;
    };
    if !probe.status.success() {
        assert!(
            env::var("MALM_REQUIRE_MOUNT_NAMESPACE").as_deref() != Ok("1"),
            "MALM_REQUIRE_MOUNT_NAMESPACE=1 requires unprivileged user and mount namespaces: {}",
            String::from_utf8_lossy(&probe.stderr)
        );
        eprintln!(
            "skipping bind-mount integration test: unprivileged mount namespaces are unavailable: {}",
            String::from_utf8_lossy(&probe.stderr)
        );
        return;
    }

    let output = Command::new("unshare")
        .args([
            "--user",
            "--map-root-user",
            "--mount",
            "--propagation",
            "private",
        ])
        .arg(env::current_exe().unwrap())
        .args([TEST_NAME, "--exact", "--nocapture"])
        .env(HELPER_ENV, "1")
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success() && stderr.contains(HELPER_MARKER),
        "mount-namespace helper failed\nstdout:\n{stdout}\nstderr:\n{stderr}",
    );
}

fn run_bind_mount_checks() {
    let temp = tempfile::tempdir().unwrap();
    assert_root_aliases_are_rejected(temp.path());

    let state_home = temp.path().join("state");
    fs::create_dir(&state_home).unwrap();
    set_private(&state_home);

    let aliases = temp.path().join("aliases");
    fs::create_dir(&aliases).unwrap();
    let source = aliases.join("source");
    let scratch = aliases.join("scratch");
    let target = aliases.join("target");
    let final_target = aliases.join("final-target");
    let commit_target = aliases.join("commit-target");
    let status_target = aliases.join("status-target");
    for path in [
        &source,
        &scratch,
        &target,
        &final_target,
        &commit_target,
        &status_target,
    ] {
        fs::create_dir(path).unwrap();
    }
    fs::create_dir(final_target.join("managed")).unwrap();
    fs::create_dir(final_target.join("managed/final")).unwrap();
    fs::create_dir(commit_target.join("managed")).unwrap();
    fs::create_dir(status_target.join("managed")).unwrap();

    let authority = DeploymentName::new("target").unwrap();
    let final_authority = DeploymentName::new("final").unwrap();
    let commit_authority = DeploymentName::new("commit").unwrap();
    let status_authority = DeploymentName::new("status").unwrap();
    let config = EngineConfig::from_state_home(&state_home, StoreAccess::ReadWrite)
        .unwrap()
        .with_target_authority(authority.clone(), &target)
        .unwrap()
        .with_target_authority(final_authority.clone(), &final_target)
        .unwrap()
        .with_target_authority(commit_authority.clone(), &commit_target)
        .unwrap()
        .with_target_authority(status_authority.clone(), &status_target)
        .unwrap();
    let engine = Engine::new(config, EnginePorts::system());
    engine.initialize_store().unwrap();

    let protected = engine.config().state_root().join("state");

    let commit_namespace = NamespaceName::new("commit-alias").unwrap();
    let baseline = engine
        .prepare_v1(&PrepareRequestV1::from(PrepareRequestPartsV1 {
            namespace: commit_namespace.clone(),
            expected_head: None,
            graph_digest: Digest::sha256(b"commit directory baseline"),
            inputs: vec![],
            artifacts: vec![],
            transforms: vec![],
            findings: vec![],
            operations: vec![
                PrepareOperationV1::ensure_directory(
                    commit_authority.clone(),
                    "managed/file",
                    0o700,
                )
                .unwrap(),
            ],
        }))
        .unwrap();
    let baseline = engine
        .commit_v1(&CommitRequestV1::new(
            baseline.plan_id().clone(),
            ApprovalV1::new(
                baseline.plan_id().clone(),
                baseline.approval_digest().clone(),
            ),
        ))
        .unwrap();

    let commit_artifact = ArtifactId::new("commit/file").unwrap();
    let commit_alias = engine
        .prepare_v1(&PrepareRequestV1::from(PrepareRequestPartsV1 {
            namespace: commit_namespace,
            expected_head: Some(baseline.head().clone()),
            graph_digest: Digest::sha256(b"commit directory alias"),
            inputs: vec![],
            artifacts: vec![
                PrepareArtifactV1::new(
                    commit_artifact.clone(),
                    b"must not be written\n".to_vec(),
                    "text/plain",
                )
                .unwrap(),
            ],
            transforms: vec![],
            findings: vec![],
            operations: vec![
                PrepareOperationV1::replace_file(
                    commit_authority,
                    "managed/file",
                    commit_artifact,
                    0o600,
                )
                .unwrap(),
            ],
        }))
        .unwrap();
    let commit_leaf = commit_target.join("managed/file");
    bind_mount(&protected, &commit_leaf);
    let commit_result = engine.commit_v1(&CommitRequestV1::new(
        commit_alias.plan_id().clone(),
        ApprovalV1::new(
            commit_alias.plan_id().clone(),
            commit_alias.approval_digest().clone(),
        ),
    ));
    assert!(
        matches!(commit_result, Err(CommitError::UnsafeTarget(_))),
        "unexpected directory-alias commit result: {commit_result:?}"
    );
    assert!(
        !engine
            .config()
            .state_root()
            .join("transactions/current.json")
            .exists()
    );

    let artifact_id = ArtifactId::new("status/file").unwrap();
    let status_namespace = NamespaceName::new("status").unwrap();
    let prepared = engine
        .prepare_v1(&PrepareRequestV1::from(PrepareRequestPartsV1 {
            namespace: status_namespace.clone(),
            expected_head: None,
            graph_digest: Digest::sha256(b"status directory alias"),
            inputs: vec![],
            artifacts: vec![
                PrepareArtifactV1::new(artifact_id.clone(), b"managed\n".to_vec(), "text/plain")
                    .unwrap(),
            ],
            transforms: vec![],
            findings: vec![],
            operations: vec![
                PrepareOperationV1::place_file(
                    status_authority,
                    "managed/file",
                    artifact_id,
                    0o600,
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
        .unwrap();
    let status_leaf = status_target.join("managed/file");
    fs::remove_file(&status_leaf).unwrap();
    fs::create_dir(&status_leaf).unwrap();
    bind_mount(&protected, &status_leaf);

    let status = engine
        .inspect_namespace_status_v1(&NamespaceStatusRequestV1::new(status_namespace))
        .unwrap();
    assert_eq!(
        status.status(),
        NamespaceStatusKindV1::IncompatibleOrCorrupt
    );
    assert!(
        status
            .targets()
            .iter()
            .all(|target| target.status() == TargetStatusKindV1::Incompatible)
    );
    let report = engine
        .fsck_v1(
            &FsckRequestV1::new()
                .with_target_observations(16, 1_024)
                .unwrap(),
        )
        .unwrap();
    assert!(!report.complete());
    assert!(
        report
            .findings()
            .iter()
            .any(|finding| { finding.code() == FsckFindingCodeV1::TargetObservationFailed })
    );

    let final_leaf = final_target.join("managed/final");
    bind_mount(&protected, &final_leaf);
    let final_request = PrepareRequestV1::from(PrepareRequestPartsV1 {
        namespace: NamespaceName::new("final-alias").unwrap(),
        expected_head: None,
        graph_digest: Digest::sha256(b"final directory alias"),
        inputs: vec![],
        artifacts: vec![],
        transforms: vec![],
        findings: vec![],
        operations: vec![
            PrepareOperationV1::ensure_directory(final_authority, "managed/final", 0o700).unwrap(),
        ],
    });
    assert!(matches!(
        engine.prepare_v1(&final_request),
        Err(EngineError::PreparedStore {
            reason: PreparedStoreIssue::UnsafeTarget { detail },
            ..
        }) if detail == "destination is physically inside protected state"
    ));

    for alias in [&source, &scratch, &target] {
        bind_mount(&protected, alias);
    }

    let expected = Digest::sha256(b"mount exclusion is checked before capture");
    assert!(matches!(
        engine.capture_and_publish_local_pack_v1(&source, &expected),
        Err(EngineError::PackCapture {
            reason: PackCaptureIssue::ProtectedStateOverlap,
            ..
        })
    ));

    let git_source = GitSourceV1::new(
        GitUrl::new("https://example.invalid/repository.git").unwrap(),
        GitObjectId::new(format!("sha1-{}", "1".repeat(40))).unwrap(),
        PackSubdir::new(".").unwrap(),
    );
    let git = GitAcquisitionConfig::new("/definitely/not/git").unwrap();
    assert!(matches!(
        engine.acquire_and_publish_git_pack_v1(&git_source, &expected, &git, &scratch),
        Err(EngineError::GitAcquisition {
            reason: GitAcquisitionIssue::ProtectedStateOverlap,
            ..
        })
    ));

    let request = PrepareRequestV1::from(PrepareRequestPartsV1 {
        namespace: NamespaceName::new("test").unwrap(),
        expected_head: None,
        graph_digest: Digest::sha256(b"graph"),
        inputs: vec![],
        artifacts: vec![],
        transforms: vec![],
        findings: vec![],
        operations: vec![PrepareOperationV1::assert_absent(authority, "output").unwrap()],
    });
    assert!(matches!(
        engine.prepare_v1(&request),
        Err(EngineError::PreparedStore {
            reason: PreparedStoreIssue::UnsafeTarget { detail },
            ..
        }) if detail == "destination is physically inside protected state"
    ));
}

fn assert_root_aliases_are_rejected(temp: &Path) {
    let backing = temp.join("root-alias-backing");
    fs::create_dir(&backing).unwrap();
    set_private(&backing);

    let exact = backing.join("exact");
    let bootstrap = Engine::new(
        EngineConfig::new(&exact, StoreAccess::ReadWrite).unwrap(),
        EnginePorts::system(),
    );
    bootstrap.initialize_store().unwrap();

    let state_home = temp.join("mounted-root");
    let state = state_home.join("malm");
    fs::create_dir(&state_home).unwrap();
    set_private(&state_home);
    fs::create_dir(&state).unwrap();
    bind_mount(&exact, &state);

    let engine = Engine::new(
        EngineConfig::from_state_home(&state_home, StoreAccess::ReadWrite).unwrap(),
        EnginePorts::system(),
    );
    assert!(matches!(
        engine.store_status(),
        Err(EngineError::Io { source, .. })
            if source.kind() == std::io::ErrorKind::CrossesDevices
    ));
}

fn set_private(path: &Path) {
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
}

fn bind_mount(source: &Path, target: &Path) {
    let source = CString::new(source.as_os_str().as_bytes()).unwrap();
    let target = CString::new(target.as_os_str().as_bytes()).unwrap();
    // SAFETY: both C strings remain live for the call; null type/data are valid for MS_BIND.
    let result = unsafe {
        libc::mount(
            source.as_ptr(),
            target.as_ptr(),
            std::ptr::null(),
            libc::MS_BIND,
            std::ptr::null(),
        )
    };
    assert_eq!(
        result,
        0,
        "bind mount failed: {}",
        std::io::Error::last_os_error()
    );
}
