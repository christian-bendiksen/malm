use std::fs::{self, File};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
#[cfg(feature = "failpoints")]
use std::process::Command;
use std::sync::{Mutex, MutexGuard};

use malm::{
    ApprovalV1, CheckoutRequestV1, CommitError, CommitRequestV1, Engine, EngineConfig, EngineError,
    EnginePorts, FsckFindingCodeV1, FsckRequestV1, HistoryRetentionRequestV1,
    OwnershipOverlapKindV1, PrepareArtifactV1, PrepareInputKindV1, PrepareInputV1,
    PrepareOperationV1, PrepareRequestPartsV1, PrepareRequestV1, PreparedStoreIssue,
    PruneRequestV1, RestorePointRequestV1, RetentionObjectV1, RetentionPinRequestV1, StoreAccess,
};
use malm_types::{
    ArtifactId, DeploymentName, Digest, GenerationInspectionRequestV1, NamespaceHistoryRequestV1,
    NamespaceName, PreparedId,
};
use rustix::fs::{FlockOperation, flock};

fn test_guard() -> MutexGuard<'static, ()> {
    static TEST_LOCK: Mutex<()> = Mutex::new(());
    TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner())
}

fn make_engine(temp: &tempfile::TempDir, target: &Path) -> Engine {
    let state_home = temp.path().join("state");
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

fn artifact_request(graph: &[u8], bytes: &[u8]) -> PrepareRequestV1 {
    PrepareRequestV1::from(PrepareRequestPartsV1 {
        namespace: NamespaceName::new("workstation").unwrap(),
        expected_head: None,
        graph_digest: Digest::sha256(graph),
        inputs: vec![],
        artifacts: vec![
            PrepareArtifactV1::new(
                ArtifactId::new("artifact/shared").unwrap(),
                bytes.to_vec(),
                "application/octet-stream",
            )
            .unwrap(),
        ],
        transforms: vec![],
        findings: vec![],
        operations: vec![],
    })
}

fn file_request(expected: Option<Digest>, bytes: &[u8], replace: bool) -> PrepareRequestV1 {
    let artifact = ArtifactId::new("config/file").unwrap();
    let operation = if replace {
        PrepareOperationV1::replace_file(
            DeploymentName::new("home").unwrap(),
            "config/file.conf",
            artifact.clone(),
            0o600,
        )
        .unwrap()
    } else {
        PrepareOperationV1::place_file(
            DeploymentName::new("home").unwrap(),
            "config/file.conf",
            artifact.clone(),
            0o600,
        )
        .unwrap()
    };
    PrepareRequestV1::from(PrepareRequestPartsV1 {
        namespace: NamespaceName::new("workstation").unwrap(),
        expected_head: expected,
        graph_digest: Digest::sha256(bytes),
        inputs: vec![],
        artifacts: vec![PrepareArtifactV1::new(artifact, bytes.to_vec(), "text/plain").unwrap()],
        transforms: vec![],
        findings: vec![],
        operations: vec![operation],
    })
}

#[test]
fn bare_sweep_removes_exactly_the_unreferenced_plans() {
    let _test_guard = test_guard();
    let temp = tempfile::tempdir().unwrap();
    let target = temp.path().join("target");
    fs::create_dir(&target).unwrap();
    fs::create_dir(target.join("config")).unwrap();
    let engine = make_engine(&temp, &target);
    engine.initialize_store().unwrap();

    // The head generation retains one committed plan. The other two plans were
    // prepared but never committed, so nothing references them.
    let committed = engine
        .prepare_v1(&file_request(None, b"committed\n", false))
        .unwrap();
    let head = commit(&engine, &committed);
    let stale_one = engine
        .prepare_v1(&file_request(
            Some(head.head().clone()),
            b"stale one\n",
            true,
        ))
        .unwrap();
    let stale_two = engine
        .prepare_v1(&file_request(
            Some(head.head().clone()),
            b"stale two\n",
            true,
        ))
        .unwrap();

    let preview = engine
        .preview_prune_v1(&PruneRequestV1::new(vec![]).sweep_unreferenced())
        .unwrap();
    assert_eq!(preview.prepared_records, 2);
    assert!(engine.plan_v1(stale_one.plan_id()).is_ok());
    assert!(engine.plan_v1(stale_two.plan_id()).is_ok());

    let outcome = engine
        .prune_v1(&PruneRequestV1::new(vec![]).sweep_unreferenced())
        .unwrap();
    assert_eq!(outcome.prepared_records, 2, "both stale plans swept");
    assert!(
        engine.plan_v1(committed.plan_id()).is_ok(),
        "the generation-referenced plan survives the sweep"
    );
    assert!(engine.plan_v1(stale_one.plan_id()).is_err());
    assert!(engine.plan_v1(stale_two.plan_id()).is_err());

    // A second sweep verifies idempotence by finding nothing.
    let outcome = engine
        .prune_v1(&PruneRequestV1::new(vec![]).sweep_unreferenced())
        .unwrap();
    assert_eq!(outcome.prepared_records, 0);

    // A plain empty request still removes no plans.
    let stale_three = engine
        .prepare_v1(&file_request(
            Some(head.head().clone()),
            b"stale three\n",
            true,
        ))
        .unwrap();
    let outcome = engine.prune_v1(&PruneRequestV1::new(vec![])).unwrap();
    assert_eq!(outcome.prepared_records, 0);
    assert!(engine.plan_v1(stale_three.plan_id()).is_ok());
}

#[test]
fn prune_preview_does_not_create_the_maintenance_lock() {
    let _test_guard = test_guard();
    let temp = tempfile::tempdir().unwrap();
    let target = temp.path().join("target");
    fs::create_dir(&target).unwrap();
    let engine = make_engine(&temp, &target);
    engine.initialize_store().unwrap();
    let maintenance_lock = temp.path().join("state/malm/maintenance.lock");
    assert!(!maintenance_lock.exists());

    let outcome = engine
        .preview_prune_v1(&PruneRequestV1::new(vec![]).sweep_unreferenced())
        .unwrap();

    assert_eq!(outcome.prepared_records, 0);
    assert!(!maintenance_lock.exists());
}

fn namespace_file_request(
    namespace: &str,
    relative_path: &str,
    expected: Option<Digest>,
    bytes: &[u8],
    replace: bool,
) -> PrepareRequestV1 {
    let artifact = ArtifactId::new(format!("config/{namespace}")).unwrap();
    let operation = if replace {
        PrepareOperationV1::replace_file(
            DeploymentName::new("home").unwrap(),
            relative_path,
            artifact.clone(),
            0o600,
        )
        .unwrap()
    } else {
        PrepareOperationV1::place_file(
            DeploymentName::new("home").unwrap(),
            relative_path,
            artifact.clone(),
            0o600,
        )
        .unwrap()
    };
    PrepareRequestV1::from(PrepareRequestPartsV1 {
        namespace: NamespaceName::new(namespace).unwrap(),
        expected_head: expected,
        graph_digest: Digest::sha256([namespace.as_bytes(), bytes].concat()),
        inputs: vec![],
        artifacts: vec![PrepareArtifactV1::new(artifact, bytes.to_vec(), "text/plain").unwrap()],
        transforms: vec![],
        findings: vec![],
        operations: vec![operation],
    })
}

fn namespace_authority_file_request(
    namespace: &str,
    authority: &str,
    relative_path: &str,
    bytes: &[u8],
) -> PrepareRequestV1 {
    let artifact = ArtifactId::new(format!("config/{namespace}")).unwrap();
    PrepareRequestV1::from(PrepareRequestPartsV1 {
        namespace: NamespaceName::new(namespace).unwrap(),
        expected_head: None,
        graph_digest: Digest::sha256([namespace.as_bytes(), bytes].concat()),
        inputs: vec![],
        artifacts: vec![
            PrepareArtifactV1::new(artifact.clone(), bytes.to_vec(), "text/plain").unwrap(),
        ],
        transforms: vec![],
        findings: vec![],
        operations: vec![
            PrepareOperationV1::place_file(
                DeploymentName::new(authority).unwrap(),
                relative_path,
                artifact,
                0o600,
            )
            .unwrap(),
        ],
    })
}

fn commit(engine: &Engine, prepared: &malm::PreparedDeploymentV1) -> malm::ApplyOutcomeV1 {
    engine
        .commit_v1(&CommitRequestV1::new(
            prepared.plan_id().clone(),
            ApprovalV1::new(
                prepared.plan_id().clone(),
                prepared.approval_digest().clone(),
            ),
        ))
        .unwrap()
}

#[cfg(feature = "failpoints")]
#[test]
fn prune_crash_child() {
    let Some(root) = std::env::var_os("MALM_V1_PRUNE_CRASH_ROOT") else {
        return;
    };
    let _test_guard = test_guard();
    let root = std::path::PathBuf::from(root);
    let engine = Engine::new(
        EngineConfig::from_state_home(root.join("state"), StoreAccess::ReadWrite)
            .unwrap()
            .with_target_authority(DeploymentName::new("home").unwrap(), root.join("target"))
            .unwrap(),
        EnginePorts::system(),
    );
    engine.prune_v1(&PruneRequestV1::new(vec![])).unwrap();
    panic!("configured prune failpoint did not fire");
}

#[cfg(feature = "failpoints")]
#[test]
fn history_expansion_preflight_child() {
    let Some(root) = std::env::var_os("MALM_HISTORY_EXPANSION_ROOT") else {
        return;
    };
    let _test_guard = test_guard();
    let root = std::path::PathBuf::from(root);
    let engine = Engine::new(
        EngineConfig::from_state_home(root.join("state"), StoreAccess::ReadWrite)
            .unwrap()
            .with_target_authority(DeploymentName::new("home").unwrap(), root.join("target"))
            .unwrap(),
        EnginePorts::system(),
    );
    let plan_id = PreparedId::new(std::env::var("MALM_HISTORY_EXPANSION_PLAN").unwrap()).unwrap();
    let approval = Digest::new(std::env::var("MALM_HISTORY_EXPANSION_APPROVAL").unwrap()).unwrap();
    assert!(matches!(
        engine.commit_v1(&CommitRequestV1::new(
            plan_id.clone(),
            ApprovalV1::new(plan_id, approval),
        )),
        Err(CommitError::InvalidPlan(reason))
            if reason.contains("candidate catalog retention is invalid")
    ));
}

#[test]
fn explicit_plan_removal_preserves_shared_blobs_until_the_last_reference() {
    let _test_guard = test_guard();
    let temp = tempfile::tempdir().unwrap();
    let target = temp.path().join("target");
    fs::create_dir(&target).unwrap();
    let engine = make_engine(&temp, &target);
    engine.initialize_store().unwrap();
    let first = engine
        .prepare_v1(&artifact_request(b"first graph", b"shared bytes"))
        .unwrap();
    let second = engine
        .prepare_v1(&artifact_request(b"second graph", b"shared bytes"))
        .unwrap();
    assert_ne!(first.plan_id(), second.plan_id());
    let blob = engine
        .config()
        .state_root()
        .join("objects/blobs")
        .join(first.artifacts()[0].digest().as_str());

    let outcome = engine
        .prune_v1(&PruneRequestV1::new(vec![first.plan_id().clone()]))
        .unwrap();
    assert_eq!(outcome.prepared_records, 1);
    assert_eq!(outcome.artifact_blobs, 0);
    assert!(blob.exists());
    assert!(engine.plan_v1(first.plan_id()).is_err());
    assert_eq!(
        engine
            .artifact_v1(
                second.plan_id(),
                &ArtifactId::new("artifact/shared").unwrap()
            )
            .unwrap()
            .bytes(),
        b"shared bytes"
    );

    let outcome = engine
        .prune_v1(&PruneRequestV1::new(vec![second.plan_id().clone()]))
        .unwrap();
    assert_eq!(outcome.prepared_records, 1);
    assert_eq!(outcome.artifact_blobs, 1);
    assert!(!blob.exists());
}

#[test]
fn complete_active_generation_chain_retains_its_plans_and_blobs() {
    let _test_guard = test_guard();
    let temp = tempfile::tempdir().unwrap();
    let target = temp.path().join("target");
    fs::create_dir(&target).unwrap();
    fs::create_dir(target.join("config")).unwrap();
    let engine = make_engine(&temp, &target);
    engine.initialize_store().unwrap();
    let first = engine
        .prepare_v1(&file_request(None, b"first generation\n", false))
        .unwrap();
    let first_outcome = commit(&engine, &first);
    let second = engine
        .prepare_v1(&file_request(
            Some(first_outcome.head().clone()),
            b"second generation\n",
            true,
        ))
        .unwrap();
    commit(&engine, &second);

    for plan_id in [first.plan_id(), second.plan_id()] {
        let result = engine.prune_v1(&PruneRequestV1::new(vec![plan_id.clone()]));
        assert!(
            matches!(
                &result,
                Err(CommitError::PlanInUse(actual)) if actual == plan_id
            ),
            "unexpected active-plan prune result: {result:?}"
        );
        assert!(engine.plan_v1(plan_id).is_ok());
    }
    let outcome = engine.prune_v1(&PruneRequestV1::new(vec![])).unwrap();
    assert_eq!(outcome.prepared_records, 0);
    assert_eq!(outcome.artifact_blobs, 0);
    assert_eq!(outcome.state_generations, 0);
    assert_eq!(
        fs::read(target.join("config/file.conf")).unwrap(),
        b"second generation\n"
    );
}

#[test]
fn retention_traverses_every_catalog_namespace_history() {
    let _test_guard = test_guard();
    let temp = tempfile::tempdir().unwrap();
    let target = temp.path().join("target");
    fs::create_dir(&target).unwrap();
    fs::create_dir(target.join("config")).unwrap();
    let engine = make_engine(&temp, &target);
    engine.initialize_store().unwrap();

    let alpha_first = engine
        .prepare_v1(&namespace_file_request(
            "alpha",
            "config/alpha.conf",
            None,
            b"alpha first\n",
            false,
        ))
        .unwrap();
    let alpha_first_outcome = commit(&engine, &alpha_first);
    let beta = engine
        .prepare_v1(&namespace_file_request(
            "beta",
            "config/beta.conf",
            None,
            b"beta\n",
            false,
        ))
        .unwrap();
    let beta_outcome = commit(&engine, &beta);
    let alpha_second = engine
        .prepare_v1(&namespace_file_request(
            "alpha",
            "config/alpha.conf",
            Some(alpha_first_outcome.head().clone()),
            b"alpha second\n",
            true,
        ))
        .unwrap();
    let alpha_second_outcome = commit(&engine, &alpha_second);

    for plan_id in [
        alpha_first.plan_id(),
        alpha_second.plan_id(),
        beta.plan_id(),
    ] {
        assert!(matches!(
            engine.prune_v1(&PruneRequestV1::new(vec![plan_id.clone()])),
            Err(CommitError::PlanInUse(actual)) if &actual == plan_id
        ));
        assert!(engine.plan_v1(plan_id).is_ok());
    }
    let outcome = engine.prune_v1(&PruneRequestV1::new(vec![])).unwrap();
    assert_eq!(outcome.prepared_records, 0);
    assert_eq!(outcome.artifact_blobs, 0);
    assert_eq!(outcome.state_generations, 0);
    assert_eq!(
        engine
            .inspect_state_v1(&NamespaceName::new("alpha").unwrap())
            .unwrap()
            .head(),
        Some(alpha_second_outcome.head())
    );
    assert_eq!(
        engine
            .inspect_state_v1(&NamespaceName::new("beta").unwrap())
            .unwrap()
            .head(),
        Some(beta_outcome.head())
    );
}

#[cfg(feature = "failpoints")]
#[test]
fn interrupted_generation_pruning_leaves_a_valid_predecessor_chain() {
    let _test_guard = test_guard();
    let temp = tempfile::tempdir().unwrap();
    let target = temp.path().join("target");
    fs::create_dir(&target).unwrap();
    fs::create_dir(target.join("config")).unwrap();
    let engine = make_engine(&temp, &target);
    engine.initialize_store().unwrap();
    let first = engine
        .prepare_v1(&file_request(None, b"first generation\n", false))
        .unwrap();
    let first = commit(&engine, &first);
    let second = engine
        .prepare_v1(&file_request(
            Some(first.head().clone()),
            b"second generation\n",
            true,
        ))
        .unwrap();
    let second = commit(&engine, &second);
    let generations = engine.config().state_root().join("state/generations");
    let first_path = generations.join(first.head().as_str());
    let second_path = generations.join(second.head().as_str());
    fs::write(
        engine.config().state_root().join("state/catalog.json"),
        b"{\"schema_version\":1,\"heads\":[]}\n",
    )
    .unwrap();
    drop(engine);

    let status = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "prune_crash_child", "--nocapture"])
        .env("MALM_V1_PRUNE_CRASH_ROOT", temp.path())
        .env("MALM_FAILPOINT", "v1.prune.after_generation_remove=1")
        .status()
        .unwrap();
    assert!(!status.success());
    assert!(first_path.is_file());
    assert!(!second_path.exists());

    let restarted = make_engine(&temp, &target);
    let outcome = restarted.prune_v1(&PruneRequestV1::new(vec![])).unwrap();
    assert_eq!(outcome.state_generations, 1);
    assert!(!first_path.exists());
}

#[test]
fn maintenance_removes_verified_orphan_blobs_but_not_retained_objects() {
    let _test_guard = test_guard();
    let temp = tempfile::tempdir().unwrap();
    let target = temp.path().join("target");
    fs::create_dir(&target).unwrap();
    let engine = make_engine(&temp, &target);
    engine.initialize_store().unwrap();
    let retained = engine
        .prepare_v1(&artifact_request(b"retained", b"retained bytes"))
        .unwrap();
    let orphan_bytes = b"orphan bytes";
    let orphan_digest = Digest::sha256(orphan_bytes);
    let orphan = engine
        .config()
        .state_root()
        .join("objects/blobs")
        .join(orphan_digest.as_str());
    fs::write(&orphan, orphan_bytes).unwrap();
    fs::set_permissions(&orphan, fs::Permissions::from_mode(0o400)).unwrap();

    let outcome = engine.prune_v1(&PruneRequestV1::new(vec![])).unwrap();

    assert_eq!(outcome.artifact_blobs, 1);
    assert!(!orphan.exists());
    assert!(engine.plan_v1(retained.plan_id()).is_ok());
    assert!(
        engine
            .config()
            .state_root()
            .join("objects/blobs")
            .join(retained.artifacts()[0].digest().as_str())
            .exists()
    );
}

#[test]
fn retention_rejects_physical_aliases_in_selected_ownership() {
    let _test_guard = test_guard();
    let temp = tempfile::tempdir().unwrap();
    let alpha_target = temp.path().join("alpha-target");
    let beta_target = temp.path().join("beta-target");
    let gamma_target = temp.path().join("gamma-target");
    for target in [&alpha_target, &beta_target, &gamma_target] {
        fs::create_dir(target).unwrap();
        fs::create_dir(target.join("config")).unwrap();
    }
    let state_home = temp.path().join("state");
    fs::create_dir(&state_home).unwrap();
    fs::set_permissions(&state_home, fs::Permissions::from_mode(0o700)).unwrap();
    let engine = Engine::new(
        EngineConfig::from_state_home(&state_home, StoreAccess::ReadWrite)
            .unwrap()
            .with_target_authority(DeploymentName::new("alpha-root").unwrap(), &alpha_target)
            .unwrap()
            .with_target_authority(DeploymentName::new("beta-root").unwrap(), &beta_target)
            .unwrap()
            .with_target_authority(DeploymentName::new("gamma-root").unwrap(), &gamma_target)
            .unwrap(),
        EnginePorts::system(),
    );
    engine.initialize_store().unwrap();
    let alpha = engine
        .prepare_v1(&namespace_authority_file_request(
            "alpha",
            "alpha-root",
            "config/alpha.conf",
            b"alpha\n",
        ))
        .unwrap();
    commit(&engine, &alpha);
    let beta = engine
        .prepare_v1(&namespace_authority_file_request(
            "beta",
            "beta-root",
            "config/beta.conf",
            b"beta\n",
        ))
        .unwrap();
    commit(&engine, &beta);
    let gamma = engine
        .prepare_v1(&namespace_authority_file_request(
            "gamma",
            "gamma-root",
            "config/gamma.conf",
            b"gamma\n",
        ))
        .unwrap();
    commit(&engine, &gamma);
    let orphan = engine
        .prepare_v1(&artifact_request(b"orphan", b"orphan bytes"))
        .unwrap();
    drop(engine);

    let aliased = Engine::new(
        EngineConfig::from_state_home(&state_home, StoreAccess::ReadWrite)
            .unwrap()
            .with_target_authority(DeploymentName::new("alpha-root").unwrap(), &alpha_target)
            .unwrap()
            .with_target_authority(DeploymentName::new("beta-root").unwrap(), &alpha_target)
            .unwrap(),
        EnginePorts::system(),
    );

    assert!(matches!(
        aliased.prune_v1(&PruneRequestV1::new(vec![orphan.plan_id().clone()])),
        Err(CommitError::TargetOwnershipConflict {
            overlap: OwnershipOverlapKindV1::PhysicalAuthorityAlias,
            ..
        })
    ));
    assert!(aliased.plan_v1(orphan.plan_id()).is_ok());
}

#[test]
fn publication_and_retention_share_a_nonblocking_maintenance_lock() {
    let _test_guard = test_guard();
    let temp = tempfile::tempdir().unwrap();
    let target = temp.path().join("target");
    fs::create_dir(&target).unwrap();
    let engine = make_engine(&temp, &target);
    engine.initialize_store().unwrap();
    let retained = engine
        .prepare_v1(&artifact_request(b"retained", b"retained bytes"))
        .unwrap();
    let lock = File::options()
        .read(true)
        .write(true)
        .open(engine.config().state_root().join("maintenance.lock"))
        .unwrap();
    flock(&lock, FlockOperation::NonBlockingLockExclusive).unwrap();

    assert!(matches!(
        engine.prepare_v1(&artifact_request(b"blocked", b"blocked bytes")),
        Err(EngineError::PreparedStore {
            reason: PreparedStoreIssue::PublicationBusy,
            ..
        })
    ));
    let pack_files = vec![malm_pack::PackFileV1::new(
        malm_pack::PackPath::new("malm-pack.kdl").unwrap(),
        b"schema 1\npack \"blocked\"\n",
    )];
    let pack_digest =
        malm_pack::pack_content_digest(pack_files.iter().map(|file| (file.path(), file.bytes())))
            .unwrap();
    assert!(matches!(
        engine.publish_pack_object_v1(&pack_digest, &pack_files),
        Err(EngineError::PreparedStore {
            reason: PreparedStoreIssue::PublicationBusy,
            ..
        })
    ));
    assert!(matches!(
        engine.prune_v1(&PruneRequestV1::new(vec![retained.plan_id().clone()])),
        Err(CommitError::Busy)
    ));
    assert!(engine.plan_v1(retained.plan_id()).is_ok());
}

#[test]
fn bounded_history_restore_points_and_pins_are_independent_roots() {
    let _test_guard = test_guard();
    let temp = tempfile::tempdir().unwrap();
    let target = temp.path().join("target");
    fs::create_dir(&target).unwrap();
    fs::create_dir(target.join("config")).unwrap();
    let engine = make_engine(&temp, &target);
    engine.initialize_store().unwrap();
    let first = engine
        .prepare_v1(&file_request(None, b"first generation\n", false))
        .unwrap();
    let first_outcome = commit(&engine, &first);
    let second = engine
        .prepare_v1(&file_request(
            Some(first_outcome.head().clone()),
            b"second generation\n",
            true,
        ))
        .unwrap();
    let second_outcome = commit(&engine, &second);

    let restore = engine
        .prepare_restore_point_v1(&RestorePointRequestV1::new(
            NamespaceName::new("workstation").unwrap(),
            first_outcome.head().clone(),
        ))
        .unwrap();
    commit(&engine, &restore);
    let policy = engine
        .prepare_history_retention_v1(
            &HistoryRetentionRequestV1::new(NamespaceName::new("workstation").unwrap(), 1).unwrap(),
        )
        .unwrap();
    let policy_outcome = commit(&engine, &policy);

    let first_generation = engine
        .config()
        .state_root()
        .join("state/generations")
        .join(first_outcome.head().as_str());
    let second_generation = engine
        .config()
        .state_root()
        .join("state/generations")
        .join(second_outcome.head().as_str());
    let outcome = engine.prune_v1(&PruneRequestV1::new(vec![])).unwrap();
    assert!(outcome.state_generations >= 1);
    assert!(
        first_generation.exists(),
        "restore point must retain its generation"
    );
    assert!(
        !second_generation.exists(),
        "history beyond the policy is unreachable"
    );
    let history = engine
        .inspect_namespace_history_v1(&NamespaceHistoryRequestV1::new(
            NamespaceName::new("workstation").unwrap(),
        ))
        .unwrap();
    assert_eq!(history.head(), Some(policy_outcome.head()));
    assert_eq!(history.generations().len(), 1);
    let inspection = GenerationInspectionRequestV1::new(
        NamespaceName::new("workstation").unwrap(),
        policy_outcome.head().clone(),
    );
    assert_eq!(
        engine
            .inspect_generation_details_v1(&inspection)
            .unwrap()
            .generation(),
        policy_outcome.head()
    );
    assert_eq!(
        engine
            .inspect_retention_authority_v1(&inspection)
            .unwrap()
            .generation(),
        policy_outcome.head()
    );
    assert_eq!(
        engine
            .inspect_tracking_v1(&inspection)
            .unwrap()
            .generation(),
        policy_outcome.head()
    );

    assert!(matches!(
        engine.prune_v1(&PruneRequestV1::new(vec![first.plan_id().clone()])),
        Err(CommitError::PlanInUse(plan)) if plan == *first.plan_id()
    ));
}

#[test]
fn pruned_history_cannot_be_reexpanded_into_a_dangling_selected_head() {
    let _test_guard = test_guard();
    let temp = tempfile::tempdir().unwrap();
    let target = temp.path().join("target");
    fs::create_dir(&target).unwrap();
    fs::create_dir(target.join("config")).unwrap();
    let engine = make_engine(&temp, &target);
    engine.initialize_store().unwrap();
    let namespace = NamespaceName::new("workstation").unwrap();

    let first = engine
        .prepare_v1(&file_request(None, b"first\n", false))
        .unwrap();
    let first = commit(&engine, &first);
    let second = engine
        .prepare_v1(&file_request(Some(first.head().clone()), b"second\n", true))
        .unwrap();
    let second = commit(&engine, &second);
    let shrink = engine
        .prepare_history_retention_v1(
            &HistoryRetentionRequestV1::new(namespace.clone(), 1).unwrap(),
        )
        .unwrap();
    let shrink = commit(&engine, &shrink);
    let expansion = engine
        .prepare_history_retention_v1(
            &HistoryRetentionRequestV1::new(namespace.clone(), 3).unwrap(),
        )
        .unwrap();

    engine.prune_v1(&PruneRequestV1::new(vec![])).unwrap();
    assert!(
        !engine
            .config()
            .state_root()
            .join("state/generations")
            .join(second.head().as_str())
            .exists()
    );
    #[cfg(feature = "failpoints")]
    {
        let status = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "history_expansion_preflight_child",
                "--nocapture",
            ])
            .env("MALM_HISTORY_EXPANSION_ROOT", temp.path())
            .env("MALM_HISTORY_EXPANSION_PLAN", expansion.plan_id().as_str())
            .env(
                "MALM_HISTORY_EXPANSION_APPROVAL",
                expansion.approval_digest().as_str(),
            )
            .env("MALM_FAILPOINT", "v1.commit.after_journal")
            .status()
            .unwrap();
        assert!(
            status.success(),
            "invalid expansion reached the post-journal failpoint"
        );
    }
    let result = engine.commit_v1(&CommitRequestV1::new(
        expansion.plan_id().clone(),
        ApprovalV1::new(
            expansion.plan_id().clone(),
            expansion.approval_digest().clone(),
        ),
    ));
    assert!(matches!(
        result,
        Err(CommitError::InvalidPlan(reason))
            if reason.contains("candidate catalog retention is invalid")
    ));
    assert_eq!(
        engine.inspect_state_v1(&namespace).unwrap().head(),
        Some(shrink.head())
    );
    assert_eq!(
        fs::read(target.join("config/file.conf")).unwrap(),
        b"second\n"
    );
    assert!(
        !engine
            .config()
            .state_root()
            .join("transactions/current.json")
            .exists()
    );
    assert_eq!(
        engine.recover_v1().unwrap(),
        malm::RecoveryOutcomeV1::NoTransaction
    );
    assert!(
        engine
            .prepare_history_retention_v1(&HistoryRetentionRequestV1::new(namespace, 3).unwrap())
            .is_err()
    );
}

#[test]
fn checkout_and_direct_inspection_use_only_current_effective_retention_roots() {
    let _test_guard = test_guard();
    let temp = tempfile::tempdir().unwrap();
    let target = temp.path().join("target");
    fs::create_dir(&target).unwrap();
    fs::create_dir(target.join("config")).unwrap();
    let engine = make_engine(&temp, &target);
    engine.initialize_store().unwrap();
    let namespace = NamespaceName::new("workstation").unwrap();

    let first = engine
        .prepare_v1(&file_request(None, b"first\n", false))
        .unwrap();
    let first = commit(&engine, &first);
    let second = engine
        .prepare_v1(&file_request(Some(first.head().clone()), b"second\n", true))
        .unwrap();
    let second = commit(&engine, &second);
    let third = engine
        .prepare_v1(&file_request(Some(second.head().clone()), b"third\n", true))
        .unwrap();
    let third = commit(&engine, &third);
    let restore = engine
        .prepare_restore_point_v1(&RestorePointRequestV1::new(
            namespace.clone(),
            first.head().clone(),
        ))
        .unwrap();
    let restore_update = commit(&engine, &restore);
    let pin = engine
        .prepare_pin_v1(&RetentionPinRequestV1::new(
            namespace.clone(),
            RetentionObjectV1::StateGeneration {
                digest: third.head().clone(),
            },
        ))
        .unwrap();
    let pinned = commit(&engine, &pin);
    let policy = engine
        .prepare_history_retention_v1(
            &HistoryRetentionRequestV1::new(namespace.clone(), 2).unwrap(),
        )
        .unwrap();
    let policy = commit(&engine, &policy);

    assert!(
        engine
            .prepare_checkout_v1(&CheckoutRequestV1::new(
                namespace.clone(),
                pinned.head().clone(),
            ))
            .is_ok()
    );
    assert!(
        engine
            .prepare_checkout_v1(&CheckoutRequestV1::new(
                namespace.clone(),
                restore_update.head().clone(),
            ))
            .is_err()
    );

    let generations = engine.config().state_root().join("state/generations");
    let leaked = fs::read(generations.join(second.head().as_str())).unwrap();
    engine.prune_v1(&PruneRequestV1::new(vec![])).unwrap();
    assert!(!generations.join(second.head().as_str()).exists());

    for retained in [pinned.head(), first.head(), third.head()] {
        assert!(
            engine
                .prepare_checkout_v1(&CheckoutRequestV1::new(namespace.clone(), retained.clone(),))
                .is_ok()
        );
        let inspection = GenerationInspectionRequestV1::new(namespace.clone(), retained.clone());
        assert!(engine.inspect_generation_details_v1(&inspection).is_ok());
        assert!(engine.inspect_retention_authority_v1(&inspection).is_ok());
        assert!(engine.inspect_tracking_v1(&inspection).is_ok());
    }
    assert_eq!(
        engine.inspect_state_v1(&namespace).unwrap().head(),
        Some(policy.head())
    );

    let leaked_path = generations.join(second.head().as_str());
    fs::write(&leaked_path, leaked).unwrap();
    fs::set_permissions(&leaked_path, fs::Permissions::from_mode(0o400)).unwrap();
    assert!(
        engine
            .prepare_checkout_v1(&CheckoutRequestV1::new(
                namespace.clone(),
                second.head().clone(),
            ))
            .is_err()
    );
    let unauthorized = GenerationInspectionRequestV1::new(namespace, second.head().clone());
    assert!(engine.inspect_generation_details_v1(&unauthorized).is_err());
    assert!(
        engine
            .inspect_retention_authority_v1(&unauthorized)
            .is_err()
    );
    assert!(engine.inspect_tracking_v1(&unauthorized).is_err());
}

#[test]
fn disabled_historical_checkout_reinstates_its_selected_restore_root() {
    let _test_guard = test_guard();
    let temp = tempfile::tempdir().unwrap();
    let target = temp.path().join("target");
    fs::create_dir(&target).unwrap();
    fs::create_dir(target.join("config")).unwrap();
    let engine = make_engine(&temp, &target);
    engine.initialize_store().unwrap();
    let namespace = NamespaceName::new("workstation").unwrap();

    let initial = engine
        .prepare_v1(&file_request(None, b"restore me\n", false))
        .unwrap();
    let initial = commit(&engine, &initial);
    let disabled = engine.prepare_disable_v1(&namespace).unwrap();
    let disabled = commit(&engine, &disabled);
    let enabled = engine.prepare_enable_v1(&namespace).unwrap();
    commit(&engine, &enabled);
    let drop_point = engine
        .prepare_drop_restore_point_v1(&RestorePointRequestV1::new(
            namespace.clone(),
            initial.head().clone(),
        ))
        .unwrap();
    commit(&engine, &drop_point);

    let checkout = engine
        .prepare_checkout_v1(&CheckoutRequestV1::new(
            namespace.clone(),
            disabled.head().clone(),
        ))
        .unwrap();
    assert_eq!(
        checkout.restore_point().unwrap().generation(),
        initial.head()
    );
    assert!(
        checkout
            .retention_authority()
            .restore_points()
            .iter()
            .any(|point| point.generation() == initial.head())
    );
    commit(&engine, &checkout);
    engine.prune_v1(&PruneRequestV1::new(vec![])).unwrap();

    let enable = engine.prepare_enable_v1(&namespace).unwrap();
    commit(&engine, &enable);
    assert_eq!(
        fs::read(target.join("config/file.conf")).unwrap(),
        b"restore me\n"
    );
}

#[test]
fn fsck_reports_a_disabled_generation_whose_selected_restore_root_is_omitted() {
    let _test_guard = test_guard();
    let temp = tempfile::tempdir().unwrap();
    let target = temp.path().join("target");
    fs::create_dir(&target).unwrap();
    fs::create_dir(target.join("config")).unwrap();
    let engine = make_engine(&temp, &target);
    engine.initialize_store().unwrap();
    let namespace = NamespaceName::new("workstation").unwrap();
    let initial = engine
        .prepare_v1(&file_request(None, b"corruption fixture\n", false))
        .unwrap();
    commit(&engine, &initial);
    let disabled = engine.prepare_disable_v1(&namespace).unwrap();
    let disabled = commit(&engine, &disabled);

    let generations = engine.config().state_root().join("state/generations");
    let mut generation: serde_json::Value =
        serde_json::from_slice(&fs::read(generations.join(disabled.head().as_str())).unwrap())
            .unwrap();
    generation["retention"]["restore_points"] = serde_json::json!([]);
    let mut bytes = serde_json::to_vec(&generation).unwrap();
    bytes.push(b'\n');
    let forged = Digest::sha256(&bytes);
    let forged_path = generations.join(forged.as_str());
    fs::write(&forged_path, bytes).unwrap();
    fs::set_permissions(&forged_path, fs::Permissions::from_mode(0o400)).unwrap();

    let catalog_path = engine.config().state_root().join("state/catalog.json");
    let mut catalog: serde_json::Value =
        serde_json::from_slice(&fs::read(&catalog_path).unwrap()).unwrap();
    catalog["heads"][0]["generation"] = serde_json::json!(forged.as_str());
    let mut bytes = serde_json::to_vec(&catalog).unwrap();
    bytes.push(b'\n');
    fs::write(&catalog_path, bytes).unwrap();

    let report = engine.fsck_v1(&FsckRequestV1::new()).unwrap();
    assert!(!report.complete());
    assert!(report.findings().iter().any(|finding| {
        matches!(
            finding.code(),
            FsckFindingCodeV1::InvalidGeneration | FsckFindingCodeV1::MissingGeneration
        )
    }));
}

#[test]
fn generation_inspection_still_rejects_a_missing_edge_inside_its_retained_bound() {
    let _test_guard = test_guard();
    let temp = tempfile::tempdir().unwrap();
    let target = temp.path().join("target");
    fs::create_dir(&target).unwrap();
    fs::create_dir(target.join("config")).unwrap();
    let engine = make_engine(&temp, &target);
    engine.initialize_store().unwrap();
    let first = engine
        .prepare_v1(&file_request(None, b"first\n", false))
        .unwrap();
    let first = commit(&engine, &first);
    let second = engine
        .prepare_v1(&file_request(Some(first.head().clone()), b"second\n", true))
        .unwrap();
    let second = commit(&engine, &second);
    fs::remove_file(
        engine
            .config()
            .state_root()
            .join("state/generations")
            .join(first.head().as_str()),
    )
    .unwrap();

    assert!(
        engine
            .inspect_generation_details_v1(&GenerationInspectionRequestV1::new(
                NamespaceName::new("workstation").unwrap(),
                second.head().clone(),
            ))
            .is_err()
    );
}

#[test]
fn explicit_blob_pin_survives_plan_removal_until_the_pin_authority_is_pruned() {
    let _test_guard = test_guard();
    let temp = tempfile::tempdir().unwrap();
    let target = temp.path().join("target");
    fs::create_dir(&target).unwrap();
    fs::create_dir(target.join("config")).unwrap();
    let engine = make_engine(&temp, &target);
    engine.initialize_store().unwrap();
    let active = engine
        .prepare_v1(&file_request(None, b"active\n", false))
        .unwrap();
    commit(&engine, &active);
    let orphan = engine
        .prepare_v1(&PrepareRequestV1::from(PrepareRequestPartsV1 {
            namespace: NamespaceName::new("orphan-plan").unwrap(),
            expected_head: None,
            graph_digest: Digest::sha256(b"orphan"),
            inputs: vec![],
            artifacts: vec![
                PrepareArtifactV1::new(
                    ArtifactId::new("artifact/pinned").unwrap(),
                    b"pinned orphan bytes".to_vec(),
                    "application/octet-stream",
                )
                .unwrap(),
            ],
            transforms: vec![],
            findings: vec![],
            operations: vec![],
        }))
        .unwrap();
    let digest = orphan.artifacts()[0].digest().clone();
    let blob = engine
        .config()
        .state_root()
        .join("objects/blobs")
        .join(digest.as_str());
    let pin_request = RetentionPinRequestV1::new(
        NamespaceName::new("workstation").unwrap(),
        RetentionObjectV1::ArtifactBlob {
            digest: digest.clone(),
        },
    );
    let pin = engine.prepare_pin_v1(&pin_request).unwrap();
    commit(&engine, &pin);

    let outcome = engine
        .prune_v1(&PruneRequestV1::new(vec![orphan.plan_id().clone()]))
        .unwrap();
    assert_eq!(outcome.prepared_records, 1);
    assert_eq!(outcome.artifact_blobs, 0);
    assert!(blob.exists());
}

#[test]
fn pin_commit_revalidates_the_new_root_after_prepare() {
    let _test_guard = test_guard();
    let temp = tempfile::tempdir().unwrap();
    let target = temp.path().join("target");
    fs::create_dir(&target).unwrap();
    fs::create_dir(target.join("config")).unwrap();
    let engine = make_engine(&temp, &target);
    engine.initialize_store().unwrap();
    let active = engine
        .prepare_v1(&file_request(None, b"active\n", false))
        .unwrap();
    let active_head = commit(&engine, &active).head().clone();
    let orphan = engine
        .prepare_v1(&PrepareRequestV1::from(PrepareRequestPartsV1 {
            namespace: NamespaceName::new("pin-source").unwrap(),
            expected_head: None,
            graph_digest: Digest::sha256(b"pin source"),
            inputs: vec![],
            artifacts: vec![
                PrepareArtifactV1::new(
                    ArtifactId::new("artifact/pin-source").unwrap(),
                    b"pin source bytes".to_vec(),
                    "application/octet-stream",
                )
                .unwrap(),
            ],
            transforms: vec![],
            findings: vec![],
            operations: vec![],
        }))
        .unwrap();
    let digest = orphan.artifacts()[0].digest().clone();
    let pin = engine
        .prepare_pin_v1(&RetentionPinRequestV1::new(
            NamespaceName::new("workstation").unwrap(),
            RetentionObjectV1::ArtifactBlob {
                digest: digest.clone(),
            },
        ))
        .unwrap();
    fs::remove_file(
        engine
            .config()
            .state_root()
            .join("objects/blobs")
            .join(digest.as_str()),
    )
    .unwrap();

    let result = engine.commit_v1(&CommitRequestV1::new(
        pin.plan_id().clone(),
        ApprovalV1::new(pin.plan_id().clone(), pin.approval_digest().clone()),
    ));
    assert!(matches!(result, Err(CommitError::MissingArtifact(actual)) if actual == digest));
    assert_eq!(
        engine
            .inspect_state_v1(&NamespaceName::new("workstation").unwrap())
            .unwrap()
            .head(),
        Some(&active_head)
    );
    assert!(
        !engine
            .config()
            .state_root()
            .join("transactions/current.json")
            .exists()
    );
}

#[test]
fn pack_objects_are_verified_and_collected_with_prepared_plan_roots() {
    let _test_guard = test_guard();
    let temp = tempfile::tempdir().unwrap();
    let target = temp.path().join("target");
    fs::create_dir(&target).unwrap();
    let engine = make_engine(&temp, &target);
    engine.initialize_store().unwrap();
    let retained_files = vec![malm_pack::PackFileV1::new(
        malm_pack::PackPath::new("malm-pack.kdl").unwrap(),
        b"schema 1\npack \"retained\"\n",
    )];
    let orphan_files = vec![malm_pack::PackFileV1::new(
        malm_pack::PackPath::new("malm-pack.kdl").unwrap(),
        b"schema 1\npack \"orphan\"\n",
    )];
    let retained_digest = malm_pack::pack_content_digest(
        retained_files
            .iter()
            .map(|file| (file.path(), file.bytes())),
    )
    .unwrap();
    let orphan_digest =
        malm_pack::pack_content_digest(orphan_files.iter().map(|file| (file.path(), file.bytes())))
            .unwrap();
    engine
        .publish_pack_object_v1(&retained_digest, &retained_files)
        .unwrap();
    engine
        .publish_pack_object_v1(&orphan_digest, &orphan_files)
        .unwrap();
    let retained_plan = engine
        .prepare_v1(&PrepareRequestV1::from(PrepareRequestPartsV1 {
            namespace: NamespaceName::new("pack-root").unwrap(),
            expected_head: None,
            graph_digest: Digest::sha256(b"pack graph"),
            inputs: vec![
                PrepareInputV1::new(
                    PrepareInputKindV1::Source,
                    "pack:root",
                    retained_digest.clone(),
                )
                .unwrap(),
            ],
            artifacts: vec![],
            transforms: vec![],
            findings: vec![],
            operations: vec![],
        }))
        .unwrap();

    let outcome = engine.prune_v1(&PruneRequestV1::new(vec![])).unwrap();
    assert_eq!(outcome.pack_objects, 1);
    assert!(engine.load_pack_object_v1(&retained_digest).is_ok());
    assert!(engine.load_pack_object_v1(&orphan_digest).is_err());
    assert!(engine.plan_v1(retained_plan.plan_id()).is_ok());
}

#[test]
fn a_missing_selected_plan_fails_before_collecting_orphans() {
    let _test_guard = test_guard();
    let temp = tempfile::tempdir().unwrap();
    let target = temp.path().join("target");
    fs::create_dir(&target).unwrap();
    let engine = make_engine(&temp, &target);
    engine.initialize_store().unwrap();
    let retained = engine
        .prepare_v1(&artifact_request(b"retained", b"retained bytes"))
        .unwrap();
    let missing = PreparedId::from_digest(&Digest::sha256(b"missing"));

    assert!(matches!(
        engine.prune_v1(&PruneRequestV1::new(vec![missing.clone()])),
        Err(CommitError::MissingPlan(actual)) if actual == missing
    ));
    assert!(engine.plan_v1(retained.plan_id()).is_ok());
}

#[test]
fn read_only_engine_cannot_commit_recover_or_prune() {
    let _test_guard = test_guard();
    let temp = tempfile::tempdir().unwrap();
    let target = temp.path().join("target");
    fs::create_dir(&target).unwrap();
    fs::create_dir(target.join("config")).unwrap();
    let writable = make_engine(&temp, &target);
    writable.initialize_store().unwrap();
    let prepared = writable
        .prepare_v1(&file_request(None, b"read-only guard\n", false))
        .unwrap();
    let read_only = Engine::new(
        EngineConfig::from_state_home(temp.path().join("state"), StoreAccess::ReadOnly)
            .unwrap()
            .with_target_authority(DeploymentName::new("home").unwrap(), &target)
            .unwrap(),
        EnginePorts::system(),
    );
    let commit = CommitRequestV1::new(
        prepared.plan_id().clone(),
        ApprovalV1::new(
            prepared.plan_id().clone(),
            prepared.approval_digest().clone(),
        ),
    );

    assert!(matches!(
        read_only.commit_v1(&commit),
        Err(CommitError::ReadOnlyStore)
    ));
    assert!(matches!(
        read_only.recover_v1(),
        Err(CommitError::ReadOnlyStore)
    ));
    assert!(matches!(
        read_only.prune_v1(&PruneRequestV1::new(vec![prepared.plan_id().clone()])),
        Err(CommitError::ReadOnlyStore)
    ));
    assert!(!target.join("config/file.conf").exists());
    assert!(read_only.plan_v1(prepared.plan_id()).is_ok());
}
