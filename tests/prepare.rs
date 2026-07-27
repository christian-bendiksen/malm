use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;

use malm::{
    ApprovalV1, CommitRequestV1, Engine, EngineConfig, EnginePorts, PrepareArtifactV1,
    PrepareInputKindV1, PrepareInputV1, PrepareOperationV1, PreparePolicyFindingV1,
    PrepareRequestPartsV1, PrepareRequestV1, StoreAccess,
};
use malm_types::{ArtifactId, DeploymentName, Digest, NamespaceName};

fn make_engine(temp: &tempfile::TempDir, target: &Path) -> Engine {
    make_engine_at(temp.path().join("state"), target)
}

fn make_engine_at(state_home: std::path::PathBuf, target: &Path) -> Engine {
    if !state_home.exists() {
        fs::create_dir(&state_home).unwrap();
        fs::set_permissions(&state_home, fs::Permissions::from_mode(0o700)).unwrap();
    }
    let config = EngineConfig::from_state_home(&state_home, StoreAccess::ReadWrite)
        .unwrap()
        .with_target_authority(DeploymentName::new("home").unwrap(), target)
        .unwrap();
    Engine::new(config, EnginePorts::system())
}

fn request(bytes: &[u8]) -> PrepareRequestV1 {
    let artifact_id = ArtifactId::new("example/config").unwrap();
    PrepareRequestV1::from(PrepareRequestPartsV1 {
        namespace: NamespaceName::new("workstation").unwrap(),
        expected_head: None,
        graph_digest: Digest::sha256(b"locked graph"),
        inputs: vec![
            PrepareInputV1::new(
                PrepareInputKindV1::Config,
                "root-config",
                Digest::sha256(b"config bytes"),
            )
            .unwrap(),
        ],
        artifacts: vec![
            PrepareArtifactV1::new(artifact_id.clone(), bytes.to_vec(), "text/plain").unwrap(),
        ],
        transforms: vec![],
        findings: vec![],
        operations: vec![
            PrepareOperationV1::place_file(
                DeploymentName::new("home").unwrap(),
                ".config/example.conf",
                artifact_id,
                0o600,
            )
            .unwrap(),
        ],
    })
}

fn operation_request(
    operation: PrepareOperationV1,
    with_artifact: bool,
    findings: Vec<PreparePolicyFindingV1>,
    expected_head: Option<Digest>,
) -> PrepareRequestV1 {
    let artifacts = with_artifact
        .then(|| {
            PrepareArtifactV1::new(
                ArtifactId::new("example/config").unwrap(),
                b"replacement\n".to_vec(),
                "text/plain",
            )
            .unwrap()
        })
        .into_iter()
        .collect();
    PrepareRequestV1::from(PrepareRequestPartsV1 {
        namespace: NamespaceName::new("workstation").unwrap(),
        expected_head,
        graph_digest: Digest::sha256(b"policy graph"),
        inputs: vec![],
        artifacts,
        transforms: vec![],
        findings,
        operations: vec![operation],
    })
}

#[test]
fn prepared_plan_survives_restart_and_does_not_mutate_targets() {
    let temp = tempfile::tempdir().unwrap();
    let target = temp.path().join("target");
    fs::create_dir(&target).unwrap();
    fs::create_dir(target.join(".config")).unwrap();

    let engine = make_engine(&temp, &target);
    engine.initialize_store().unwrap();
    let prepared = engine.prepare_v1(&request(b"prepared bytes\n")).unwrap();
    assert!(!target.join(".config/example.conf").exists());
    let plan_id = prepared.plan_id().clone();
    let artifact_digest = prepared.artifacts()[0].digest().clone();
    drop(engine);

    let restarted = make_engine(&temp, &target);
    let loaded = restarted.plan_v1(&plan_id).unwrap();
    assert_eq!(loaded, prepared);
    let artifact = restarted
        .artifact_v1(&plan_id, &ArtifactId::new("example/config").unwrap())
        .unwrap();
    assert_eq!(artifact.bytes(), b"prepared bytes\n");
    assert_eq!(artifact.descriptor().digest(), &artifact_digest);
    assert!(!target.join(".config/example.conf").exists());
}

#[test]
fn identical_inputs_and_observations_produce_identical_plan_ids() {
    let temp = tempfile::tempdir().unwrap();
    let target = temp.path().join("target");
    fs::create_dir(&target).unwrap();
    fs::create_dir(target.join(".config")).unwrap();
    let engine = make_engine(&temp, &target);
    engine.initialize_store().unwrap();

    let first = engine.prepare_v1(&request(b"one")).unwrap();
    let second = engine.prepare_v1(&request(b"one")).unwrap();
    let changed = engine.prepare_v1(&request(b"two")).unwrap();

    assert_eq!(first.plan_id(), second.plan_id());
    assert_ne!(first.plan_id(), changed.plan_id());
    assert!(!target.join(".config/example.conf").exists());
}

#[test]
fn prepare_never_touches_the_predecessor_sibling() {
    let temp = tempfile::tempdir().unwrap();
    let target = temp.path().join("target");
    fs::create_dir(&target).unwrap();
    fs::create_dir(target.join(".config")).unwrap();
    let engine = make_engine(&temp, &target);
    let sibling = engine
        .config()
        .state_root()
        .parent()
        .unwrap()
        .join("malm-v1");
    fs::create_dir(&sibling).unwrap();
    fs::write(sibling.join("sentinel"), b"predecessor").unwrap();
    engine.initialize_store().unwrap();

    engine.prepare_v1(&request(b"content")).unwrap();

    assert_eq!(fs::read(sibling.join("sentinel")).unwrap(), b"predecessor");
    assert_eq!(fs::read_dir(&sibling).unwrap().count(), 1);
}

#[test]
fn prepare_rejects_a_hard_linked_maintenance_lock_without_chmoding_it() {
    let temp = tempfile::tempdir().unwrap();
    let target = temp.path().join("target");
    fs::create_dir(&target).unwrap();
    fs::create_dir(target.join(".config")).unwrap();
    let engine = make_engine(&temp, &target);
    engine.initialize_store().unwrap();
    let external = temp.path().join("external-lock");
    fs::write(&external, []).unwrap();
    let mode = fs::metadata(&external).unwrap().permissions().mode() & 0o777;
    fs::hard_link(
        &external,
        engine.config().state_root().join("maintenance.lock"),
    )
    .unwrap();

    assert!(engine.prepare_v1(&request(b"content")).is_err());
    assert_eq!(
        fs::metadata(external).unwrap().permissions().mode() & 0o777,
        mode
    );
    assert!(!target.join(".config/example.conf").exists());
}

#[test]
fn destructive_findings_follow_observed_effects_and_cannot_be_omitted() {
    let temp = tempfile::tempdir().unwrap();
    let target = temp.path().join("target");
    fs::create_dir(&target).unwrap();
    fs::create_dir(target.join(".config")).unwrap();
    let engine = make_engine(&temp, &target);
    engine.initialize_store().unwrap();
    let authority = DeploymentName::new("home").unwrap();
    let artifact = ArtifactId::new("example/config").unwrap();

    let absent_replacement = engine
        .prepare_v1(&operation_request(
            PrepareOperationV1::replace_file(
                authority.clone(),
                ".config/replaced.conf",
                artifact.clone(),
                0o600,
            )
            .unwrap(),
            true,
            vec![],
            None,
        ))
        .unwrap();
    assert!(
        absent_replacement
            .findings()
            .iter()
            .all(|finding| finding.code() != "replace-existing")
    );

    let replaced_seed = ArtifactId::new("seed/replaced").unwrap();
    let removed_seed = ArtifactId::new("seed/removed").unwrap();
    let baseline = engine
        .prepare_v1(&PrepareRequestV1::from(PrepareRequestPartsV1 {
            namespace: NamespaceName::new("workstation").unwrap(),
            expected_head: None,
            graph_digest: Digest::sha256(b"owned destructive targets"),
            inputs: vec![],
            artifacts: vec![
                PrepareArtifactV1::new(replaced_seed.clone(), b"existing\n".to_vec(), "text/plain")
                    .unwrap(),
                PrepareArtifactV1::new(removed_seed.clone(), b"remove\n".to_vec(), "text/plain")
                    .unwrap(),
            ],
            transforms: vec![],
            findings: vec![],
            operations: vec![
                PrepareOperationV1::place_file(
                    authority.clone(),
                    ".config/replaced.conf",
                    replaced_seed,
                    0o600,
                )
                .unwrap(),
                PrepareOperationV1::place_file(
                    authority.clone(),
                    ".config/remove.conf",
                    removed_seed,
                    0o600,
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
    let present_replacement = engine
        .prepare_v1(&operation_request(
            PrepareOperationV1::replace_file(
                authority.clone(),
                ".config/replaced.conf",
                artifact,
                0o600,
            )
            .unwrap(),
            true,
            vec![
                PreparePolicyFindingV1::new(
                    "replace-existing",
                    "caller advisory cannot replace mandatory policy",
                    false,
                )
                .unwrap(),
            ],
            Some(baseline.head().clone()),
        ))
        .unwrap();
    // The namespace already manages this leaf, making the mandatory finding
    // advisory for a routine update. The finding must still be present, and a
    // caller-supplied finding cannot replace it.
    assert!(present_replacement.findings().iter().any(|finding| {
        finding.code() == "replace-existing"
            && finding.message() == "replace existing target home:.config/replaced.conf"
            && !finding.approval_required()
    }));
    assert!(present_replacement.findings().iter().any(|finding| {
        finding.message() == "caller advisory cannot replace mandatory policy"
            && !finding.approval_required()
    }));

    let present_removal = engine
        .prepare_v1(&operation_request(
            PrepareOperationV1::remove_leaf(authority.clone(), ".config/remove.conf").unwrap(),
            false,
            vec![],
            Some(baseline.head().clone()),
        ))
        .unwrap();
    assert!(present_removal.findings().iter().any(|finding| {
        finding.code() == "remove-existing"
            && finding.message() == "remove existing target home:.config/remove.conf"
            && !finding.approval_required()
    }));

    let initial = engine
        .prepare_v1(&operation_request(
            PrepareOperationV1::place_file(
                authority.clone(),
                ".config/absent.conf",
                ArtifactId::new("example/config").unwrap(),
                0o600,
            )
            .unwrap(),
            true,
            vec![],
            Some(baseline.head().clone()),
        ))
        .unwrap();
    let outcome = engine
        .commit_v1(&CommitRequestV1::new(
            initial.plan_id().clone(),
            ApprovalV1::new(initial.plan_id().clone(), initial.approval_digest().clone()),
        ))
        .unwrap();
    fs::remove_file(target.join(".config/absent.conf")).unwrap();
    let absent_removal = engine
        .prepare_v1(&operation_request(
            PrepareOperationV1::remove_leaf(authority, ".config/absent.conf").unwrap(),
            false,
            vec![],
            Some(outcome.head().clone()),
        ))
        .unwrap();
    assert!(
        absent_removal
            .findings()
            .iter()
            .all(|finding| finding.code() != "remove-existing")
    );
    assert!(!target.join(".config/replaced.conf").exists());
    assert!(!target.join(".config/remove.conf").exists());
}

#[cfg(feature = "failpoints")]
#[test]
fn prepare_crash_child() {
    let Some(root) = std::env::var_os("MALM_V1_PREPARE_CRASH_ROOT") else {
        return;
    };
    let root = std::path::PathBuf::from(root);
    let target = root.join("target");
    let engine = make_engine_at(root.join("state"), &target);
    engine.initialize_store().unwrap();
    // The failpoint must abort before this call returns. A normal return makes
    // the child exit successfully, which the parent treats as a failure.
    let _ = engine.prepare_v1(&request(b"prepared bytes\n"));
}

#[cfg(feature = "failpoints")]
fn run_prepare_crash(root: &Path, point: &str) {
    let status = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "prepare_crash_child", "--nocapture"])
        .env("MALM_V1_PREPARE_CRASH_ROOT", root)
        .env("MALM_FAILPOINT", point)
        .status()
        .unwrap();
    assert!(
        !status.success(),
        "prepare child unexpectedly survived {point}"
    );
}

#[cfg(feature = "failpoints")]
fn assert_recoverable_prepare(root: &Path, target: &Path) {
    let engine = make_engine_at(root.join("state"), target);
    let prepared = engine.prepare_v1(&request(b"prepared bytes\n")).unwrap();
    let loaded = engine.plan_v1(prepared.plan_id()).unwrap();
    assert_eq!(loaded, prepared);
    let artifact = engine
        .artifact_v1(
            prepared.plan_id(),
            &ArtifactId::new("example/config").unwrap(),
        )
        .unwrap();
    assert_eq!(artifact.bytes(), b"prepared bytes\n");
}

#[cfg(feature = "failpoints")]
fn run_prepared_store_crash_case(point: &str, seed_blob: bool) {
    let temp = tempfile::tempdir().unwrap();
    let target = temp.path().join("target");
    fs::create_dir(&target).unwrap();
    fs::create_dir(target.join(".config")).unwrap();
    let engine = make_engine(&temp, &target);
    engine.initialize_store().unwrap();
    if seed_blob {
        engine.prepare_v1(&request(b"prepared bytes\n")).unwrap();
    }
    drop(engine);

    run_prepare_crash(temp.path(), point);
    assert_recoverable_prepare(temp.path(), &target);
}

#[cfg(feature = "failpoints")]
#[test]
fn crashes_during_prepared_store_publication_leave_a_recoverable_plan() {
    // First publication, after linking the blob bytes.
    run_prepared_store_crash_case("v1.prepare.blob.after_publish=1", false);

    // Cached blob publication through the stat-hit path.
    run_prepared_store_crash_case("v1.prepare.blob.after_publish=1", true);

    // Prepared record linked before its parent directory is synced.
    run_prepared_store_crash_case("v1.prepare.record.after_link=1", false);
}
