use std::fs;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::Path;

use malm_engine::{
    ApprovalV1, ArtifactBytesInspectionRequestV1, ArtifactMetadataInspectionRequestV1,
    CatalogInspectionRequestV1, CommitError, CommitRequestV1, DesiredSnapshotInspectionRequestV1,
    Engine, EngineConfig, EnginePorts, FsckFindingCodeV1, FsckRequestV1,
    GenerationInspectionRequestV1, GenerationInventoryRequestV1, LifecycleRequestV1,
    LifecycleStateViewV1, LifecycleTransitionViewV1, NamespaceHistoryRequestV1,
    NamespaceInspectionRequestV1, NamespaceRemovalHistoryV1, NamespaceRemovalRequestV1,
    NamespaceStatusKindV1, NamespaceStatusRequestV1, ObjectInventoryKindV1,
    ObjectInventoryRequestV1, PrepareArtifactV1, PrepareOperationV1, PrepareRequestPartsV1,
    PrepareRequestV1, PreparedPlanInspectionRequestV1, PruneRequestV1, RetentionObjectV1,
    StoreAccess, TargetStatusKindV1, TreeObjectV1,
};
use malm_store::{
    AcquisitionGrantKindV1, AcquisitionGrantV1, ConfigEntryPointV1, ExactRevisionV1,
    MovingSelectorV1, NamespaceHeadV1, RetentionAuthorityV1, StateCatalogV1,
    TrackedRootSourceLocatorV1, TrackedRootV1, decode_prepared_record_v1,
    encode_prepared_record_v1, encode_state_catalog_v1, prepared_id_v1,
};
use malm_tree::{MAX_TREE_DEPTH, TreeEntryV1, TreePathSegmentV1, tree_object_digest_v1};
use malm_types::{ArtifactId, ContributionName, DeploymentName, Digest, NamespaceName, PreparedId};

fn make_engine(temp: &tempfile::TempDir, target: &Path, access: StoreAccess) -> Engine {
    let state_home = temp.path().join("state");
    if !state_home.exists() {
        fs::create_dir(&state_home).unwrap();
        fs::set_permissions(&state_home, fs::Permissions::from_mode(0o700)).unwrap();
    }
    let config = EngineConfig::from_state_home(&state_home, access)
        .unwrap()
        .with_target_authority(DeploymentName::new("home").unwrap(), target)
        .unwrap();
    Engine::new(config, EnginePorts::system())
}

fn file_request(
    namespace: &str,
    expected_head: Option<Digest>,
    relative_path: &str,
    bytes: &[u8],
) -> PrepareRequestV1 {
    let artifact_id = ArtifactId::new(format!("files/{namespace}")).unwrap();
    PrepareRequestV1::from(PrepareRequestPartsV1 {
        namespace: NamespaceName::new(namespace).unwrap(),
        expected_head,
        graph_digest: Digest::sha256(
            [namespace.as_bytes(), relative_path.as_bytes(), bytes].concat(),
        ),
        inputs: vec![],
        artifacts: vec![
            PrepareArtifactV1::new(artifact_id.clone(), bytes.to_vec(), "text/plain").unwrap(),
        ],
        transforms: vec![],
        findings: vec![],
        operations: vec![
            PrepareOperationV1::place_file(
                DeploymentName::new("home").unwrap(),
                relative_path,
                artifact_id,
                0o600,
            )
            .unwrap(),
        ],
    })
}

fn commit(engine: &Engine, prepared: &malm_engine::PreparedDeploymentV1) -> Digest {
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

fn tracked_root(root_tree_digest: Digest) -> TrackedRootV1 {
    TrackedRootV1::new(
        TrackedRootSourceLocatorV1::new("https://example.com/root.git").unwrap(),
        MovingSelectorV1::new("refs/heads/main").unwrap(),
        ExactRevisionV1::new(format!("sha1-{}", "1".repeat(40))).unwrap(),
        root_tree_digest,
        ConfigEntryPointV1::new("malm.kdl").unwrap(),
        ContributionName::new("desktop").unwrap(),
        vec![
            AcquisitionGrantV1::new(
                AcquisitionGrantKindV1::GitSource,
                "https://example.com/dependency.git",
            )
            .unwrap(),
            AcquisitionGrantV1::new(AcquisitionGrantKindV1::TargetAuthority, "home").unwrap(),
        ],
    )
    .unwrap()
}

#[test]
fn disable_publishes_empty_snapshot_and_enable_uses_exact_restore_point() {
    let temp = tempfile::tempdir().unwrap();
    let target = temp.path().join("target");
    fs::create_dir(&target).unwrap();
    fs::create_dir(target.join("config")).unwrap();
    let engine = make_engine(&temp, &target, StoreAccess::ReadWrite);
    engine.initialize_store().unwrap();
    let initial = engine
        .prepare_v1(&file_request(
            "alpha",
            None,
            "config/managed.conf",
            b"tracked bytes\n",
        ))
        .unwrap();
    let retained_blob_digest = initial.artifacts()[0].digest().clone();

    let record_path = engine
        .config()
        .state_root()
        .join("prepared")
        .join(initial.plan_id().as_str());
    let tracked_tree = TreeObjectV1::new(0o755, vec![]).unwrap();
    let tracked_tree_digest = tree_object_digest_v1(&tracked_tree);
    engine
        .publish_tree_object_v1(&tracked_tree_digest, &tracked_tree)
        .unwrap();
    let record = decode_prepared_record_v1(initial.plan_id(), &fs::read(record_path).unwrap())
        .unwrap()
        .with_tracked_root(Some(tracked_root(tracked_tree_digest)))
        .unwrap();
    let tracked_plan_id = prepared_id_v1(&record);
    publish_test_record(engine.config().state_root(), &tracked_plan_id, &record);
    let tracked = engine.plan_v1(&tracked_plan_id).unwrap();
    let enabled_head = commit(&engine, &tracked);

    let disable = engine
        .prepare_disable_v1(&LifecycleRequestV1::new(
            NamespaceName::new("alpha").unwrap(),
        ))
        .unwrap();
    assert_eq!(disable.lifecycle_state(), LifecycleStateViewV1::Disabled);
    assert_eq!(disable.operation_count(), 1);
    let disabled_head = commit(&engine, &disable);
    assert_ne!(disabled_head, enabled_head);
    assert!(!target.join("config/managed.conf").exists());
    drop(engine);

    let restarted = make_engine(&temp, &target, StoreAccess::ReadWrite);
    let history = restarted
        .inspect_namespace_history_v1(&NamespaceHistoryRequestV1::new(
            NamespaceName::new("alpha").unwrap(),
        ))
        .unwrap();
    assert_eq!(history.head(), Some(&disabled_head));
    assert_eq!(
        history.generations()[0].lifecycle(),
        LifecycleStateViewV1::Disabled
    );
    assert_eq!(history.generations()[0].target_count(), 0);
    assert!(history.generations()[0].tracked_root().is_none());
    let restore_point = history.generations()[0].restore_point().unwrap();
    assert_eq!(restore_point.generation(), &enabled_head);
    let tracking = restore_point.tracked_root().unwrap();
    assert_eq!(tracking.moving_selector(), "refs/heads/main");
    assert!(tracking.applied_revision().starts_with("sha1-"));
    let inspected = restarted
        .inspect_generation_details_v1(&GenerationInspectionRequestV1::new(
            NamespaceName::new("alpha").unwrap(),
            disabled_head.clone(),
        ))
        .unwrap();
    assert_eq!(inspected.generation(), &disabled_head);
    assert_eq!(inspected.predecessor(), Some(&enabled_head));

    let retained_blob = restarted
        .config()
        .state_root()
        .join("objects/blobs")
        .join(retained_blob_digest.as_str());
    fs::remove_file(&retained_blob).unwrap();
    assert!(
        restarted
            .prepare_enable_v1(&NamespaceName::new("alpha").unwrap())
            .is_err(),
        "enable must reject a missing retained blob before publication"
    );
    fs::write(&retained_blob, b"tracked bytes\n").unwrap();
    fs::set_permissions(&retained_blob, fs::Permissions::from_mode(0o400)).unwrap();

    let enable = restarted
        .prepare_enable_v1(&LifecycleRequestV1::new(
            NamespaceName::new("alpha").unwrap(),
        ))
        .unwrap();
    assert_eq!(enable.lifecycle_state(), LifecycleStateViewV1::Enabled);
    assert_eq!(enable.artifacts()[0].byte_len(), 14);
    let reenabled_head = commit(&restarted, &enable);
    assert_ne!(reenabled_head, disabled_head);
    assert_eq!(
        fs::read(target.join("config/managed.conf")).unwrap(),
        b"tracked bytes\n"
    );
    let history = restarted
        .inspect_namespace_history_v1(&NamespaceHistoryRequestV1::new(
            NamespaceName::new("alpha").unwrap(),
        ))
        .unwrap();
    assert_eq!(history.generations().len(), 3);
    assert!(history.generations()[0].tracked_root().is_some());
    assert!(history.generations()[1].tracked_root().is_none());
    assert!(history.generations()[1].restore_point().is_some());
    assert!(
        restarted
            .prepare_enable_v1(&NamespaceName::new("alpha").unwrap())
            .is_err()
    );
}

#[test]
fn disable_releases_a_managed_directory_after_removing_its_children() {
    let temp = tempfile::tempdir().unwrap();
    let target = temp.path().join("target");
    fs::create_dir(&target).unwrap();
    let engine = make_engine(&temp, &target, StoreAccess::ReadWrite);
    engine.initialize_store().unwrap();

    let initial = engine
        .prepare_v1(&file_request(
            "alpha",
            None,
            "config/managed.conf",
            b"tracked bytes\n",
        ))
        .unwrap();
    commit(&engine, &initial);
    assert!(target.join("config").is_dir());
    fs::write(target.join("config/user.conf"), b"user bytes\n").unwrap();

    let disable = engine
        .prepare_disable_v1(&LifecycleRequestV1::new(
            NamespaceName::new("alpha").unwrap(),
        ))
        .unwrap();
    assert_eq!(disable.operation_count(), 1);
    commit(&engine, &disable);
    assert!(!target.join("config/managed.conf").exists());
    assert!(target.join("config").is_dir());
    assert_eq!(
        fs::read(target.join("config/user.conf")).unwrap(),
        b"user bytes\n"
    );

    let enable = engine
        .prepare_enable_v1(&LifecycleRequestV1::new(
            NamespaceName::new("alpha").unwrap(),
        ))
        .unwrap();
    commit(&engine, &enable);
    assert_eq!(
        fs::read(target.join("config/managed.conf")).unwrap(),
        b"tracked bytes\n"
    );
}

#[test]
fn lifecycle_retains_omitted_slots_and_releases_cross_namespace_ownership() {
    let temp = tempfile::tempdir().unwrap();
    let target = temp.path().join("target");
    fs::create_dir(&target).unwrap();
    fs::create_dir(target.join("config")).unwrap();
    let engine = make_engine(&temp, &target, StoreAccess::ReadWrite);
    engine.initialize_store().unwrap();
    let first = engine
        .prepare_v1(&file_request("alpha", None, "config/old.conf", b"old\n"))
        .unwrap();
    let first_head = commit(&engine, &first);
    let second = engine
        .prepare_v1(&file_request(
            "alpha",
            Some(first_head),
            "config/shared.conf",
            b"alpha\n",
        ))
        .unwrap();
    commit(&engine, &second);
    assert!(!target.join("config/old.conf").exists());
    fs::write(target.join("config/old.conf"), b"unexpected\n").unwrap();
    let status = engine
        .inspect_namespace_status_v1(&NamespaceStatusRequestV1::new(
            NamespaceName::new("alpha").unwrap(),
        ))
        .unwrap();
    assert_eq!(status.status(), NamespaceStatusKindV1::EnabledUnexpected);
    assert!(status.targets().iter().any(|target| {
        target.relative_path() == "config/old.conf"
            && target.status() == TargetStatusKindV1::Unexpected
    }));
    fs::remove_file(target.join("config/old.conf")).unwrap();

    let disable_alpha = engine
        .prepare_disable_v1(&NamespaceName::new("alpha").unwrap())
        .unwrap();
    commit(&engine, &disable_alpha);
    assert_eq!(
        engine
            .inspect_namespace_status_v1(&NamespaceStatusRequestV1::new(
                NamespaceName::new("alpha").unwrap(),
            ))
            .unwrap()
            .status(),
        NamespaceStatusKindV1::Disabled
    );
    let history = engine
        .inspect_namespace_history_v1(&NamespaceHistoryRequestV1::new(
            NamespaceName::new("alpha").unwrap(),
        ))
        .unwrap();
    assert_eq!(history.generations()[0].target_count(), 0);
    assert_eq!(history.generations()[0].present_target_count(), 0);

    let beta = engine
        .prepare_v1(&file_request("beta", None, "config/shared.conf", b"beta\n"))
        .unwrap();
    commit(&engine, &beta);
    assert!(
        engine
            .prepare_enable_v1(&NamespaceName::new("alpha").unwrap())
            .is_err()
    );
    let disable_beta = engine
        .prepare_disable_v1(&NamespaceName::new("beta").unwrap())
        .unwrap();
    commit(&engine, &disable_beta);
    let enable_alpha = engine
        .prepare_enable_v1(&NamespaceName::new("alpha").unwrap())
        .unwrap();
    assert_eq!(enable_alpha.operation_count(), 1);
    commit(&engine, &enable_alpha);
    assert_eq!(
        fs::read(target.join("config/shared.conf")).unwrap(),
        b"alpha\n"
    );
    assert!(!target.join("config/old.conf").exists());
}

#[test]
fn namespace_removal_reconciles_targets_and_catalog_as_one_transition() {
    let temp = tempfile::tempdir().unwrap();
    let target = temp.path().join("target");
    fs::create_dir(&target).unwrap();
    fs::create_dir(target.join("config")).unwrap();
    let engine = make_engine(&temp, &target, StoreAccess::ReadWrite);
    engine.initialize_store().unwrap();
    let alpha = engine
        .prepare_v1(&file_request(
            "alpha",
            None,
            "config/shared.conf",
            b"alpha\n",
        ))
        .unwrap();
    let alpha_head = commit(&engine, &alpha);

    let removal = engine
        .prepare_namespace_removal_v1(&NamespaceRemovalRequestV1::new(
            NamespaceName::new("alpha").unwrap(),
            NamespaceRemovalHistoryV1::Drop,
        ))
        .unwrap();
    assert_eq!(removal.operation_count(), 1);
    assert!(matches!(
        removal.transition(),
        LifecycleTransitionViewV1::NamespaceRemoval {
            drops_history: true
        }
    ));
    let outcome = engine
        .commit_v1(&CommitRequestV1::new(
            removal.plan_id().clone(),
            ApprovalV1::new(removal.plan_id().clone(), removal.approval_digest().clone()),
        ))
        .unwrap();
    assert_eq!(outcome.previous_head(), Some(&alpha_head));
    assert_eq!(outcome.next_head(), None);
    assert!(!target.join("config/shared.conf").exists());
    assert_eq!(
        engine
            .inspect_state_v1(&NamespaceName::new("alpha").unwrap())
            .unwrap()
            .head(),
        None
    );

    let beta = engine
        .prepare_v1(&file_request("beta", None, "config/shared.conf", b"beta\n"))
        .unwrap();
    commit(&engine, &beta);
    assert_eq!(
        fs::read(target.join("config/shared.conf")).unwrap(),
        b"beta\n"
    );
}

#[test]
fn status_history_and_fsck_are_read_only_and_report_drift_without_repair() {
    let temp = tempfile::tempdir().unwrap();
    let target = temp.path().join("target");
    fs::create_dir(&target).unwrap();
    fs::create_dir(target.join("config")).unwrap();
    let engine = make_engine(&temp, &target, StoreAccess::ReadWrite);
    engine.initialize_store().unwrap();
    let prepared = engine
        .prepare_v1(&file_request(
            "alpha",
            None,
            "config/managed.conf",
            b"expected\n",
        ))
        .unwrap();
    let blob = engine
        .config()
        .state_root()
        .join("objects/blobs")
        .join(prepared.artifacts()[0].digest().as_str());
    let head = commit(&engine, &prepared);
    let beta = engine
        .prepare_v1(&file_request(
            "beta",
            None,
            "config/beta.conf",
            b"separate namespace\n",
        ))
        .unwrap();
    let beta_head = commit(&engine, &beta);

    let generations = engine
        .inspect_generation_inventory_v1(&GenerationInventoryRequestV1::new(
            NamespaceName::new("alpha").unwrap(),
        ))
        .unwrap();
    assert_eq!(generations.generations(), std::slice::from_ref(&head));
    assert!(!generations.generations().contains(&beta_head));
    let blobs = engine
        .inspect_object_inventory_v1(&ObjectInventoryRequestV1::new(
            ObjectInventoryKindV1::ArtifactBlob,
        ))
        .unwrap();
    assert!(blobs.objects().contains(prepared.artifacts()[0].digest()));
    let trees = engine
        .inspect_object_inventory_v1(&ObjectInventoryRequestV1::new(
            ObjectInventoryKindV1::CanonicalTree,
        ))
        .unwrap();
    assert!(trees.objects().is_empty());
    let status_request = NamespaceStatusRequestV1::new(NamespaceName::new("alpha").unwrap());
    assert_eq!(
        engine
            .inspect_namespace_status_v1(&status_request)
            .unwrap()
            .status(),
        NamespaceStatusKindV1::EnabledExact
    );
    let journal_path = engine
        .config()
        .state_root()
        .join("transactions/current.json");
    let journal_bytes =
        include_bytes!("../../../schemas/store/v1/fixtures/valid/transaction-journal.json");
    fs::write(&journal_path, journal_bytes).unwrap();
    fs::set_permissions(&journal_path, fs::Permissions::from_mode(0o600)).unwrap();
    assert_eq!(
        engine
            .inspect_namespace_status_v1(&status_request)
            .unwrap()
            .status(),
        NamespaceStatusKindV1::RecoveryRequired
    );
    let recovery_report = engine.fsck_v1(&FsckRequestV1::new()).unwrap();
    assert!(
        recovery_report
            .findings()
            .iter()
            .any(|finding| finding.code() == FsckFindingCodeV1::RecoveryRequired)
    );
    assert_eq!(fs::read(&journal_path).unwrap(), journal_bytes);
    fs::remove_file(journal_path).unwrap();
    fs::write(target.join("config/managed.conf"), b"modified\n").unwrap();
    let status = engine.inspect_namespace_status_v1(&status_request).unwrap();
    assert_eq!(status.status(), NamespaceStatusKindV1::EnabledModified);
    assert_eq!(status.targets()[0].status(), TargetStatusKindV1::Modified);
    fs::remove_file(target.join("config/managed.conf")).unwrap();
    assert_eq!(
        engine
            .inspect_namespace_status_v1(&status_request)
            .unwrap()
            .status(),
        NamespaceStatusKindV1::EnabledMissing
    );
    let outside = temp.path().join("outside");
    fs::write(&outside, b"outside sentinel\n").unwrap();
    symlink(&outside, target.join("config/managed.conf")).unwrap();
    let status = engine.inspect_namespace_status_v1(&status_request).unwrap();
    assert_eq!(status.status(), NamespaceStatusKindV1::EnabledModified);
    assert_eq!(fs::read(&outside).unwrap(), b"outside sentinel\n");
    fs::remove_file(target.join("config/managed.conf")).unwrap();

    fs::set_permissions(&blob, fs::Permissions::from_mode(0o600)).unwrap();
    fs::write(&blob, b"tampered\n").unwrap();
    fs::set_permissions(&blob, fs::Permissions::from_mode(0o400)).unwrap();
    let tampered = fs::read(&blob).unwrap();
    let prepared_count = fs::read_dir(engine.config().state_root().join("prepared"))
        .unwrap()
        .count();
    assert!(
        engine
            .prepare_disable_v1(&NamespaceName::new("alpha").unwrap())
            .is_err()
    );
    assert_eq!(
        fs::read_dir(engine.config().state_root().join("prepared"))
            .unwrap()
            .count(),
        prepared_count,
        "a corrupt retained blob must fail before plan publication"
    );
    for lock in ["transaction.lock", "maintenance.lock"] {
        let path = engine.config().state_root().join(lock);
        if path.exists() {
            fs::remove_file(path).unwrap();
        }
    }
    drop(engine);

    let read_only = make_engine(&temp, &target, StoreAccess::ReadOnly);
    let history = read_only
        .inspect_namespace_history_v1(&NamespaceHistoryRequestV1::new(
            NamespaceName::new("alpha").unwrap(),
        ))
        .unwrap();
    assert_eq!(history.head(), Some(&head));
    assert_eq!(
        read_only
            .inspect_namespace_status_v1(&status_request)
            .unwrap()
            .status(),
        NamespaceStatusKindV1::EnabledMissing
    );
    let report = read_only.fsck_v1(&FsckRequestV1::new()).unwrap();
    assert!(report.findings().iter().any(|finding| {
        matches!(
            finding.code(),
            FsckFindingCodeV1::CorruptArtifactBlob | FsckFindingCodeV1::ArtifactLengthMismatch
        )
    }));
    assert!(report.checked_artifact_blobs() >= 1);
    assert!(!report.complete());
    assert_eq!(
        fs::read(&blob).unwrap(),
        tampered,
        "fsck must not repair blobs"
    );
    assert!(
        !read_only
            .config()
            .state_root()
            .join("transaction.lock")
            .exists()
    );
    assert!(
        !read_only
            .config()
            .state_root()
            .join("maintenance.lock")
            .exists()
    );
}

#[test]
fn bounded_fsck_reports_only_incomplete_coverage_for_an_inventory_cutoff() {
    let temp = tempfile::tempdir().unwrap();
    let target = temp.path().join("target");
    fs::create_dir(&target).unwrap();
    fs::create_dir(target.join("config")).unwrap();
    let engine = make_engine(&temp, &target, StoreAccess::ReadWrite);
    engine.initialize_store().unwrap();
    let prepared = engine
        .prepare_v1(&file_request(
            "alpha",
            None,
            "config/bounded.conf",
            b"bounded\n",
        ))
        .unwrap();
    commit(&engine, &prepared);

    let report = engine
        .fsck_v1(&FsckRequestV1::with_limits(64, 1, 1024 * 1024).unwrap())
        .unwrap();

    assert!(!report.complete());
    assert_eq!(report.findings().len(), 1);
    assert_eq!(
        report.findings()[0].code(),
        FsckFindingCodeV1::TraversalLimitExceeded
    );
}

#[test]
fn journal_decoded_byte_cutoff_is_not_reported_as_an_authority_race() {
    let temp = tempfile::tempdir().unwrap();
    let target = temp.path().join("target");
    fs::create_dir(&target).unwrap();
    let engine = make_engine(&temp, &target, StoreAccess::ReadWrite);
    engine.initialize_store().unwrap();
    let transactions = engine.config().state_root().join("transactions");
    fs::create_dir(&transactions).unwrap();
    fs::set_permissions(&transactions, fs::Permissions::from_mode(0o700)).unwrap();
    let journal = transactions.join("current.json");
    fs::write(
        &journal,
        include_bytes!("../../../schemas/store/v1/fixtures/valid/transaction-journal.json"),
    )
    .unwrap();
    fs::set_permissions(&journal, fs::Permissions::from_mode(0o600)).unwrap();

    let report = engine
        .fsck_v1(&FsckRequestV1::with_limits(64, 4096, 1).unwrap())
        .unwrap();

    assert!(
        report
            .findings()
            .iter()
            .any(|finding| { finding.code() == FsckFindingCodeV1::DecodedByteLimitExceeded })
    );
    assert!(
        report
            .findings()
            .iter()
            .all(|finding| finding.code() != FsckFindingCodeV1::AuthorityChanged)
    );
}

#[test]
fn commit_rejects_tree_depth_before_reading_the_out_of_bounds_object() {
    let temp = tempfile::tempdir().unwrap();
    let target = temp.path().join("target");
    fs::create_dir(&target).unwrap();
    fs::create_dir(target.join("config")).unwrap();
    let engine = make_engine(&temp, &target, StoreAccess::ReadWrite);
    engine.initialize_store().unwrap();
    let original = engine
        .prepare_v1(&file_request(
            "alpha",
            None,
            "config/depth.conf",
            b"bounded\n",
        ))
        .unwrap();
    let record_path = engine
        .config()
        .state_root()
        .join("prepared")
        .join(original.plan_id().as_str());
    let record =
        decode_prepared_record_v1(original.plan_id(), &fs::read(record_path).unwrap()).unwrap();

    let leaf = TreeObjectV1::new(0o755, vec![]).unwrap();
    let leaf_digest = tree_object_digest_v1(&leaf);
    engine.publish_tree_object_v1(&leaf_digest, &leaf).unwrap();
    let mut child = leaf_digest.clone();
    for _ in 0..=MAX_TREE_DEPTH {
        let parent = TreeObjectV1::new(
            0o755,
            vec![
                TreeEntryV1::directory(TreePathSegmentV1::new("child").unwrap(), 0o755, child)
                    .unwrap(),
            ],
        )
        .unwrap();
        child = tree_object_digest_v1(&parent);
        engine.publish_tree_object_v1(&child, &parent).unwrap();
    }
    let root = child;
    fs::set_permissions(
        engine
            .config()
            .state_root()
            .join("objects/trees")
            .join(leaf_digest.as_str()),
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    let record = record
        .with_tracked_root(Some(tracked_root(root.clone())))
        .unwrap();
    let plan_id = prepared_id_v1(&record);
    publish_test_record(engine.config().state_root(), &plan_id, &record);

    assert!(matches!(
        engine.commit_v1(&CommitRequestV1::new(
            plan_id.clone(),
            ApprovalV1::new(plan_id, record.approval_digest().clone()),
        )),
        Err(CommitError::InvalidStore(reason)) if reason.contains("depth limit")
    ));
    assert!(
        !engine
            .config()
            .state_root()
            .join("transactions/current.json")
            .exists()
    );
    fs::set_permissions(
        engine
            .config()
            .state_root()
            .join("objects/trees")
            .join(leaf_digest.as_str()),
        fs::Permissions::from_mode(0o400),
    )
    .unwrap();
    let report = engine.fsck_v1(&FsckRequestV1::new()).unwrap();
    assert!(report.findings().iter().any(|finding| {
        finding.code() == FsckFindingCodeV1::CorruptCanonicalObject
            && matches!(finding.subject(), malm_engine::FsckSubjectV1::CanonicalTree(digest) if digest == &root)
    }));
}

#[test]
fn prune_bounds_aggregate_work_across_many_individually_valid_tree_roots() {
    let temp = tempfile::tempdir().unwrap();
    let target = temp.path().join("target");
    fs::create_dir(&target).unwrap();
    fs::create_dir(target.join("config")).unwrap();
    let engine = make_engine(&temp, &target, StoreAccess::ReadWrite);
    engine.initialize_store().unwrap();
    let original = engine
        .prepare_v1(&file_request(
            "alpha",
            None,
            "config/budget.conf",
            b"bounded\n",
        ))
        .unwrap();
    let record_path = engine
        .config()
        .state_root()
        .join("prepared")
        .join(original.plan_id().as_str());
    let record =
        decode_prepared_record_v1(original.plan_id(), &fs::read(record_path).unwrap()).unwrap();
    let empty = TreeObjectV1::new(0o755, vec![]).unwrap();
    let empty_digest = tree_object_digest_v1(&empty);
    engine
        .publish_tree_object_v1(&empty_digest, &empty)
        .unwrap();
    let shared = TreeObjectV1::new(
        0o755,
        (0..1000)
            .map(|index| {
                TreeEntryV1::directory(
                    TreePathSegmentV1::new(format!("d{index:04}")).unwrap(),
                    0o755,
                    empty_digest.clone(),
                )
                .unwrap()
            })
            .collect(),
    )
    .unwrap();
    let shared_digest = tree_object_digest_v1(&shared);
    engine
        .publish_tree_object_v1(&shared_digest, &shared)
        .unwrap();
    let mut pins = Vec::new();
    for index in 0..500 {
        let wrapper = TreeObjectV1::new(
            0o755,
            vec![
                TreeEntryV1::directory(
                    TreePathSegmentV1::new(format!("root{index:04}")).unwrap(),
                    0o755,
                    shared_digest.clone(),
                )
                .unwrap(),
            ],
        )
        .unwrap();
        let digest = tree_object_digest_v1(&wrapper);
        engine.publish_tree_object_v1(&digest, &wrapper).unwrap();
        pins.push(RetentionObjectV1::CanonicalTree { digest });
    }
    let retention = RetentionAuthorityV1::new(
        record.retention_authority().history(),
        record.retention_authority().restore_points().to_vec(),
        pins,
    )
    .unwrap();
    let record = record.with_retention_authority(retention).unwrap();
    let plan_id = prepared_id_v1(&record);
    publish_test_record(engine.config().state_root(), &plan_id, &record);

    assert!(matches!(
        engine.commit_v1(&CommitRequestV1::new(
            plan_id.clone(),
            ApprovalV1::new(plan_id, record.approval_digest().clone()),
        )),
        Err(CommitError::InvalidStore(reason))
            if reason.contains("canonical root traversal exceeds")
    ));
    assert!(matches!(
        engine.prune_v1(&PruneRequestV1::new(vec![])),
        Err(CommitError::InvalidStore(reason))
            if reason.contains("canonical root traversal exceeds")
    ));
}

#[test]
fn history_and_fsck_reject_cross_namespace_and_dangling_selected_heads_without_repair() {
    let temp = tempfile::tempdir().unwrap();
    let target = temp.path().join("target");
    fs::create_dir(&target).unwrap();
    fs::create_dir(target.join("config")).unwrap();
    let engine = make_engine(&temp, &target, StoreAccess::ReadWrite);
    engine.initialize_store().unwrap();
    let alpha = engine
        .prepare_v1(&file_request("alpha", None, "config/alpha", b"alpha\n"))
        .unwrap();
    commit(&engine, &alpha);
    let beta = engine
        .prepare_v1(&file_request("beta", None, "config/beta", b"beta\n"))
        .unwrap();
    let beta_head = commit(&engine, &beta);
    let catalog_path = engine.config().state_root().join("state/catalog.json");
    let cross_namespace = StateCatalogV1::new(vec![NamespaceHeadV1::new(
        NamespaceName::new("alpha").unwrap(),
        beta_head,
    )])
    .unwrap();
    let cross_namespace_bytes = encode_state_catalog_v1(&cross_namespace);
    fs::write(&catalog_path, &cross_namespace_bytes).unwrap();

    assert!(
        engine
            .inspect_namespace_history_v1(&NamespaceHistoryRequestV1::new(
                NamespaceName::new("alpha").unwrap(),
            ))
            .is_err()
    );
    assert_eq!(
        engine
            .inspect_namespace_status_v1(&NamespaceStatusRequestV1::new(
                NamespaceName::new("alpha").unwrap(),
            ))
            .unwrap()
            .status(),
        NamespaceStatusKindV1::IncompatibleOrCorrupt
    );
    let report = engine.fsck_v1(&FsckRequestV1::new()).unwrap();
    assert!(
        report
            .findings()
            .iter()
            .any(|finding| { finding.code() == FsckFindingCodeV1::CrossNamespaceHistory })
    );
    assert_eq!(fs::read(&catalog_path).unwrap(), cross_namespace_bytes);

    let dangling = StateCatalogV1::new(vec![NamespaceHeadV1::new(
        NamespaceName::new("alpha").unwrap(),
        Digest::sha256(b"missing generation"),
    )])
    .unwrap();
    let dangling_bytes = encode_state_catalog_v1(&dangling);
    fs::write(&catalog_path, &dangling_bytes).unwrap();
    assert!(
        engine
            .inspect_namespace_history_v1(&NamespaceHistoryRequestV1::new(
                NamespaceName::new("alpha").unwrap(),
            ))
            .is_err()
    );
    let report = engine.fsck_v1(&FsckRequestV1::new()).unwrap();
    assert!(report.findings().iter().any(|finding| {
        matches!(
            finding.code(),
            FsckFindingCodeV1::MissingGeneration | FsckFindingCodeV1::InvalidGeneration
        )
    }));
    assert_eq!(fs::read(catalog_path).unwrap(), dangling_bytes);
}

#[test]
fn history_and_fsck_reject_cycle_shaped_generation_corruption() {
    let temp = tempfile::tempdir().unwrap();
    let target = temp.path().join("target");
    fs::create_dir(&target).unwrap();
    fs::create_dir(target.join("config")).unwrap();
    let engine = make_engine(&temp, &target, StoreAccess::ReadWrite);
    engine.initialize_store().unwrap();
    let prepared = engine
        .prepare_v1(&file_request("alpha", None, "config/alpha", b"alpha\n"))
        .unwrap();
    let head = commit(&engine, &prepared);
    let generation_path = engine
        .config()
        .state_root()
        .join("state/generations")
        .join(head.as_str());
    let mut generation: serde_json::Value =
        serde_json::from_slice(&fs::read(&generation_path).unwrap()).unwrap();
    generation["previous_generation"] = serde_json::Value::String(head.to_string());
    let mut cycle_bytes = serde_json::to_vec(&generation).unwrap();
    cycle_bytes.push(b'\n');
    fs::set_permissions(&generation_path, fs::Permissions::from_mode(0o600)).unwrap();
    fs::write(&generation_path, &cycle_bytes).unwrap();
    fs::set_permissions(&generation_path, fs::Permissions::from_mode(0o400)).unwrap();

    assert!(
        engine
            .inspect_namespace_history_v1(&NamespaceHistoryRequestV1::new(
                NamespaceName::new("alpha").unwrap(),
            ))
            .is_err()
    );
    let report = engine.fsck_v1(&FsckRequestV1::new()).unwrap();
    assert!(report.findings().iter().any(|finding| {
        matches!(
            finding.code(),
            FsckFindingCodeV1::CyclicHistory | FsckFindingCodeV1::InvalidGeneration
        )
    }));
    assert_eq!(fs::read(generation_path).unwrap(), cycle_bytes);
}

#[test]
fn bounded_semantic_inspection_projects_every_durable_plan_and_state_section() {
    let temp = tempfile::tempdir().unwrap();
    let target = temp.path().join("target");
    fs::create_dir(&target).unwrap();
    fs::create_dir(target.join("config")).unwrap();
    let engine = make_engine(&temp, &target, StoreAccess::ReadWrite);
    engine.initialize_store().unwrap();
    let prepared = engine
        .prepare_v1(&file_request(
            "alpha",
            None,
            "config/managed.conf",
            b"inspected\n",
        ))
        .unwrap();
    let head = commit(&engine, &prepared);

    let catalog = engine
        .inspect_catalog_v1(&CatalogInspectionRequestV1::new())
        .unwrap();
    assert_eq!(catalog.namespaces().len(), 1);
    assert_eq!(catalog.namespaces()[0].generation(), &head);
    let namespace = engine
        .inspect_namespace_v1(&NamespaceInspectionRequestV1::new(
            NamespaceName::new("alpha").unwrap(),
        ))
        .unwrap();
    assert_eq!(namespace.head(), Some(&head));
    assert_eq!(namespace.generation().unwrap().generation(), &head);
    let desired = engine
        .inspect_desired_snapshot_v1(&DesiredSnapshotInspectionRequestV1::new(
            NamespaceName::new("alpha").unwrap(),
            head.clone(),
        ))
        .unwrap();
    assert_eq!(desired.targets().len(), 1);
    assert_eq!(desired.targets()[0].relative_path(), "config/managed.conf");

    let plan_request = PreparedPlanInspectionRequestV1::new(prepared.plan_id().clone());
    assert_eq!(
        engine.inspect_prepared_plan_v1(&plan_request).unwrap(),
        prepared
    );
    let metadata = engine
        .inspect_artifact_metadata_v1(&ArtifactMetadataInspectionRequestV1::new(
            prepared.plan_id().clone(),
            prepared.artifacts()[0].id().clone(),
        ))
        .unwrap();
    assert_eq!(metadata.descriptor(), &prepared.artifacts()[0]);
    let artifact = engine
        .inspect_artifact_bytes_v1(&ArtifactBytesInspectionRequestV1::new(
            prepared.plan_id().clone(),
            prepared.artifacts()[0].id().clone(),
        ))
        .unwrap();
    assert_eq!(artifact.bytes(), b"inspected\n");
    assert!(
        engine
            .inspect_captured_inputs_v1(&plan_request)
            .unwrap()
            .inputs()
            .is_empty()
    );
    assert!(
        engine
            .inspect_transform_provenance_v1(&plan_request)
            .unwrap()
            .transforms()
            .is_empty()
    );
    let generation_request =
        GenerationInspectionRequestV1::new(NamespaceName::new("alpha").unwrap(), head);
    assert_eq!(
        engine
            .inspect_retention_authority_v1(&generation_request)
            .unwrap()
            .authority()
            .history_generations(),
        256
    );
    assert!(
        engine
            .inspect_tracking_v1(&generation_request)
            .unwrap()
            .tracked_root()
            .is_none()
    );

    let leaked_bytes = b"verified but unreachable";
    let leaked = Digest::sha256(leaked_bytes);
    let leaked_path = engine
        .config()
        .state_root()
        .join("objects/blobs")
        .join(leaked.as_str());
    fs::write(&leaked_path, leaked_bytes).unwrap();
    fs::set_permissions(&leaked_path, fs::Permissions::from_mode(0o400)).unwrap();
    let malformed_path = engine
        .config()
        .state_root()
        .join("objects/blobs/not-a-digest");
    fs::write(&malformed_path, b"malformed").unwrap();
    fs::set_permissions(&malformed_path, fs::Permissions::from_mode(0o400)).unwrap();
    assert!(
        engine
            .inspect_object_inventory_v1(&ObjectInventoryRequestV1::new(
                ObjectInventoryKindV1::ArtifactBlob,
            ))
            .is_err()
    );
    let report = engine.fsck_v1(&FsckRequestV1::new()).unwrap();
    assert!(report.findings().iter().any(|finding| {
        finding.code() == FsckFindingCodeV1::UnreachableImmutableObject
            && matches!(finding.subject(), malm_engine::FsckSubjectV1::ArtifactBlob(digest) if digest == &leaked)
    }));
    assert!(
        report
            .findings()
            .iter()
            .any(|finding| finding.code() == FsckFindingCodeV1::MalformedStoreEntry)
    );
}

fn publish_test_record(
    state_root: &Path,
    plan_id: &PreparedId,
    record: &malm_store::PreparedRecordV1,
) {
    let path = state_root.join("prepared").join(plan_id.as_str());
    fs::write(&path, encode_prepared_record_v1(record)).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o400)).unwrap();
}
