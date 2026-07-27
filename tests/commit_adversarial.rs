use std::ffi::OsString;
use std::fs::{self, File};
use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
use std::path::Path;

use malm::{
    ApprovalV1, CommitError, CommitRequestV1, Engine, EngineConfig, EngineError, EnginePorts,
    OwnershipOverlapKindV1, PrepareArtifactV1, PrepareOperationV1, PrepareRequestPartsV1,
    PrepareRequestV1, PreparedStoreIssue, StoreAccess,
};
use malm_types::{ArtifactId, DeploymentName, Digest, NamespaceName};
use rustix::fs::{RenameFlags, renameat_with};

const MANAGED_TARGET_XATTR_NAME: &str = "user.malm-managed-target";
const MANAGED_TARGET_XATTR_VALUE: &[u8] = b"preserve across rejected commit";

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

fn assert_metadata_unchanged(before: &fs::Metadata, after: &fs::Metadata) {
    assert_eq!(before.dev(), after.dev());
    assert_eq!(before.ino(), after.ino());
    assert_eq!(before.mode(), after.mode());
    assert_eq!(before.nlink(), after.nlink());
    assert_eq!(before.uid(), after.uid());
    assert_eq!(before.gid(), after.gid());
    assert_eq!(before.size(), after.size());
    assert_eq!(before.atime(), after.atime());
    assert_eq!(before.atime_nsec(), after.atime_nsec());
    assert_eq!(before.mtime(), after.mtime());
    assert_eq!(before.mtime_nsec(), after.mtime_nsec());
    assert_eq!(before.ctime(), after.ctime());
    assert_eq!(before.ctime_nsec(), after.ctime_nsec());
}

fn assert_exact_managed_target_xattr(path: &Path) {
    let mut names = xattr::list(path).unwrap().collect::<Vec<_>>();
    names.sort();
    assert_eq!(
        names,
        vec![OsString::from(MANAGED_TARGET_XATTR_NAME)],
        "unexpected xattrs on {}",
        path.display()
    );
    assert_eq!(
        xattr::get(path, MANAGED_TARGET_XATTR_NAME).unwrap(),
        Some(MANAGED_TARGET_XATTR_VALUE.to_vec()),
        "unexpected xattr value on {}",
        path.display()
    );
}

fn prepare(
    engine: &Engine,
    relative_path: &str,
    replace: bool,
) -> (malm::PreparedDeploymentV1, CommitRequestV1) {
    let artifact = ArtifactId::new("config/file").unwrap();
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
    let prepared = engine
        .prepare_v1(&PrepareRequestV1::from(PrepareRequestPartsV1 {
            namespace: NamespaceName::new("workstation").unwrap(),
            expected_head: engine
                .inspect_state_v1(&NamespaceName::new("workstation").unwrap())
                .unwrap()
                .head()
                .cloned(),
            graph_digest: Digest::sha256(b"adversarial graph"),
            inputs: vec![],
            artifacts: vec![
                PrepareArtifactV1::new(artifact, b"prepared bytes\n".to_vec(), "text/plain")
                    .unwrap(),
            ],
            transforms: vec![],
            findings: vec![],
            operations: vec![operation],
        }))
        .unwrap();
    let request = CommitRequestV1::new(
        prepared.plan_id().clone(),
        ApprovalV1::new(
            prepared.plan_id().clone(),
            prepared.approval_digest().clone(),
        ),
    );
    (prepared, request)
}

fn claim_files(engine: &Engine, files: &[(&str, &[u8])]) -> malm::ApplyOutcomeV1 {
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
            expected_head: engine
                .inspect_state_v1(&NamespaceName::new("workstation").unwrap())
                .unwrap()
                .head()
                .cloned(),
            graph_digest: Digest::sha256(b"seed managed targets"),
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
}

#[test]
fn replacement_and_removal_share_one_parent_without_losing_atomicity() {
    let temp = tempfile::tempdir().unwrap();
    let target = temp.path().join("target");
    fs::create_dir(&target).unwrap();
    fs::create_dir(target.join("config")).unwrap();
    let engine = make_engine(&temp, &target);
    engine.initialize_store().unwrap();
    let baseline = claim_files(
        &engine,
        &[
            ("config/file.conf", b"old bytes\n"),
            ("config/obsolete.conf", b"obsolete\n"),
        ],
    );
    let artifact = ArtifactId::new("config/file").unwrap();
    let prepared = engine
        .prepare_v1(&PrepareRequestV1::from(PrepareRequestPartsV1 {
            namespace: NamespaceName::new("workstation").unwrap(),
            expected_head: Some(baseline.head().clone()),
            graph_digest: Digest::sha256(b"replace and remove"),
            inputs: vec![],
            artifacts: vec![
                PrepareArtifactV1::new(artifact.clone(), b"replacement\n".to_vec(), "text/plain")
                    .unwrap(),
            ],
            transforms: vec![],
            findings: vec![],
            operations: vec![
                PrepareOperationV1::replace_file(
                    DeploymentName::new("home").unwrap(),
                    "config/file.conf",
                    artifact,
                    0o600,
                )
                .unwrap(),
                PrepareOperationV1::remove_leaf(
                    DeploymentName::new("home").unwrap(),
                    "config/obsolete.conf",
                )
                .unwrap(),
            ],
        }))
        .unwrap();
    let request = CommitRequestV1::new(
        prepared.plan_id().clone(),
        ApprovalV1::new(
            prepared.plan_id().clone(),
            prepared.approval_digest().clone(),
        ),
    );

    engine.commit_v1(&request).unwrap();

    assert_eq!(
        fs::read(target.join("config/file.conf")).unwrap(),
        b"replacement\n"
    );
    assert!(!target.join("config/obsolete.conf").exists());
    assert!(fs::read_dir(target.join("config")).unwrap().all(|entry| {
        !entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with(".malm-")
    }));
}

#[test]
fn stale_leaf_is_rejected_without_overwriting_the_newer_bytes() {
    let temp = tempfile::tempdir().unwrap();
    let target = temp.path().join("target");
    fs::create_dir(&target).unwrap();
    fs::create_dir(target.join("config")).unwrap();
    let leaf = target.join("config/file.conf");
    let engine = make_engine(&temp, &target);
    engine.initialize_store().unwrap();
    let baseline = claim_files(&engine, &[("config/file.conf", b"observed bytes\n")]);
    let (_, request) = prepare(&engine, "config/file.conf", true);
    fs::write(&leaf, b"newer external bytes with a different length\n").unwrap();

    assert!(matches!(
        engine.commit_v1(&request),
        Err(CommitError::StaleTarget(_))
    ));
    assert_eq!(
        fs::read(&leaf).unwrap(),
        b"newer external bytes with a different length\n"
    );
    assert!(
        engine
            .inspect_state_v1(&NamespaceName::new("workstation").unwrap())
            .unwrap()
            .head()
            == Some(baseline.head())
    );
}

#[test]
fn hard_link_alias_added_after_prepare_blocks_replacement_and_removal() {
    for replace in [true, false] {
        let temp = tempfile::tempdir().unwrap();
        let target = temp.path().join("target");
        fs::create_dir(&target).unwrap();
        fs::create_dir(target.join("config")).unwrap();
        let target_file = target.join("config/file.conf");
        let engine = make_engine(&temp, &target);
        engine.initialize_store().unwrap();
        let baseline = claim_files(&engine, &[("config/file.conf", b"managed bytes\n")]);
        xattr::set(
            &target_file,
            MANAGED_TARGET_XATTR_NAME,
            MANAGED_TARGET_XATTR_VALUE,
        )
        .unwrap();
        assert_exact_managed_target_xattr(&target_file);

        let artifact = ArtifactId::new("config/file").unwrap();
        let (artifacts, operation) = if replace {
            (
                vec![
                    PrepareArtifactV1::new(
                        artifact.clone(),
                        b"replacement bytes\n".to_vec(),
                        "text/plain",
                    )
                    .unwrap(),
                ],
                PrepareOperationV1::replace_file(
                    DeploymentName::new("home").unwrap(),
                    "config/file.conf",
                    artifact,
                    0o600,
                )
                .unwrap(),
            )
        } else {
            (
                vec![],
                PrepareOperationV1::remove_leaf(
                    DeploymentName::new("home").unwrap(),
                    "config/file.conf",
                )
                .unwrap(),
            )
        };
        let prepared = engine
            .prepare_v1(&PrepareRequestV1::from(PrepareRequestPartsV1 {
                namespace: NamespaceName::new("workstation").unwrap(),
                expected_head: Some(baseline.head().clone()),
                graph_digest: Digest::sha256(b"hard-linked managed target"),
                inputs: vec![],
                artifacts,
                transforms: vec![],
                findings: vec![],
                operations: vec![operation],
            }))
            .unwrap();
        let request = CommitRequestV1::new(
            prepared.plan_id().clone(),
            ApprovalV1::new(
                prepared.plan_id().clone(),
                prepared.approval_digest().clone(),
            ),
        );

        let protected_root = engine.config().state_root().join("state");
        let alias = protected_root.join("managed-target-alias");
        fs::hard_link(&target_file, &alias).unwrap();
        let target_bytes = fs::read(&target_file).unwrap();
        let alias_bytes = fs::read(&alias).unwrap();
        let target_before = fs::metadata(&target_file).unwrap();
        let alias_before = fs::metadata(&alias).unwrap();
        assert_eq!(target_before.dev(), alias_before.dev());
        assert_eq!(target_before.ino(), alias_before.ino());
        assert_eq!(target_before.nlink(), 2);

        let journal = engine
            .config()
            .state_root()
            .join("transactions/current.json");
        let catalog = engine.config().state_root().join("state/catalog.json");
        let catalog_before = fs::read(&catalog).unwrap();
        assert!(!journal.exists());

        let result = engine.commit_v1(&request);
        assert!(
            matches!(
                &result,
                Err(CommitError::StaleTarget(_)) | Err(CommitError::UnsafeTarget(_))
            ),
            "unexpected hard-link commit result: {result:?}"
        );

        let target_after = fs::metadata(&target_file).unwrap();
        let alias_after = fs::metadata(&alias).unwrap();
        assert_metadata_unchanged(&target_before, &target_after);
        assert_metadata_unchanged(&alias_before, &alias_after);
        assert_eq!(fs::read(&target_file).unwrap(), target_bytes);
        assert_eq!(fs::read(&alias).unwrap(), alias_bytes);
        assert_exact_managed_target_xattr(&target_file);
        assert_exact_managed_target_xattr(&alias);
        assert!(!journal.exists());
        assert_eq!(fs::read(&catalog).unwrap(), catalog_before);
        assert_eq!(
            engine
                .inspect_state_v1(&NamespaceName::new("workstation").unwrap())
                .unwrap()
                .head(),
            Some(baseline.head())
        );
    }
}

#[test]
fn replaced_parent_and_ancestor_are_never_mutated() {
    for relative_path in ["config/file.conf", "config/nested/file.conf"] {
        let temp = tempfile::tempdir().unwrap();
        let target = temp.path().join("target");
        fs::create_dir(&target).unwrap();
        fs::create_dir(target.join("config")).unwrap();
        if relative_path.contains("nested") {
            fs::create_dir(target.join("config/nested")).unwrap();
        }
        let engine = make_engine(&temp, &target);
        engine.initialize_store().unwrap();
        let (_, request) = prepare(&engine, relative_path, false);

        fs::rename(target.join("config"), target.join("observed-config")).unwrap();
        fs::create_dir(target.join("config")).unwrap();
        if relative_path.contains("nested") {
            fs::create_dir(target.join("config/nested")).unwrap();
        }

        assert!(matches!(
            engine.commit_v1(&request),
            Err(CommitError::StaleTarget(_))
        ));
        assert!(!target.join(relative_path).exists());
        assert!(!target.join("observed-config/file.conf").exists());
        assert!(!target.join("observed-config/nested/file.conf").exists());
        assert!(
            engine
                .inspect_state_v1(&NamespaceName::new("workstation").unwrap())
                .unwrap()
                .head()
                .is_none()
        );
    }
}

#[test]
fn replaced_target_authority_is_never_mutated() {
    let temp = tempfile::tempdir().unwrap();
    let target = temp.path().join("target");
    fs::create_dir(&target).unwrap();
    fs::create_dir(target.join("config")).unwrap();
    let engine = make_engine(&temp, &target);
    engine.initialize_store().unwrap();
    let (_, request) = prepare(&engine, "config/file.conf", false);

    fs::rename(&target, temp.path().join("observed-target")).unwrap();
    fs::create_dir(&target).unwrap();
    fs::create_dir(target.join("config")).unwrap();

    assert!(matches!(
        engine.commit_v1(&request),
        Err(CommitError::StaleTarget(_))
    ));
    assert!(!target.join("config/file.conf").exists());
    assert!(
        !temp
            .path()
            .join("observed-target/config/file.conf")
            .exists()
    );
}

#[test]
fn symlink_swaps_into_the_state_root_fail_closed() {
    let temp = tempfile::tempdir().unwrap();
    let target = temp.path().join("target");
    fs::create_dir(&target).unwrap();
    fs::create_dir(target.join("config")).unwrap();
    let engine = make_engine(&temp, &target);
    engine.initialize_store().unwrap();
    let protected = engine.config().state_root().join("state");
    let marker = protected.join("protected-marker");
    fs::write(&marker, b"must remain unchanged\n").unwrap();
    symlink(&protected, target.join("swap")).unwrap();
    let (_, request) = prepare(&engine, "config/file.conf", false);
    let target_metadata = fs::metadata(&target).unwrap();
    let target_accessed = filetime::FileTime::from_last_access_time(&target_metadata);
    let target_modified = filetime::FileTime::from_last_modification_time(&target_metadata);

    let target_handle = File::open(&target).unwrap();
    renameat_with(
        &target_handle,
        "config",
        &target_handle,
        "swap",
        RenameFlags::EXCHANGE,
    )
    .unwrap();
    filetime::set_file_times(&target, target_accessed, target_modified).unwrap();

    let result = engine.commit_v1(&request);
    assert!(
        matches!(
            result,
            Err(CommitError::Io { .. })
                | Err(CommitError::UnsafeTarget(_))
                | Err(CommitError::StaleTarget(_))
        ),
        "unexpected symlink-swap result: {result:?}"
    );
    assert_eq!(fs::read(&marker).unwrap(), b"must remain unchanged\n");
    assert!(!protected.join("file.conf").exists());
    assert!(!target.join("swap/file.conf").exists());
    assert!(
        engine
            .inspect_state_v1(&NamespaceName::new("workstation").unwrap())
            .unwrap()
            .head()
            .is_none()
    );
}

#[test]
fn same_inode_same_size_rewrite_with_restored_mtime_is_stale() {
    let temp = tempfile::tempdir().unwrap();
    let target = temp.path().join("target");
    fs::create_dir(&target).unwrap();
    fs::create_dir(target.join("config")).unwrap();
    let target_file = target.join("config/file.conf");
    let engine = make_engine(&temp, &target);
    engine.initialize_store().unwrap();
    claim_files(&engine, &[("config/file.conf", b"original bytes\n")]);
    let (_, request) = prepare(&engine, "config/file.conf", true);
    let metadata = fs::metadata(&target_file).unwrap();
    let accessed = filetime::FileTime::from_last_access_time(&metadata);
    let modified = filetime::FileTime::from_last_modification_time(&metadata);

    fs::write(&target_file, b"tampered bytes\n").unwrap();
    filetime::set_file_times(&target_file, accessed, modified).unwrap();

    assert!(matches!(
        engine.commit_v1(&request),
        Err(CommitError::StaleTarget(_))
    ));
    assert_eq!(fs::read(target_file).unwrap(), b"tampered bytes\n");
}

#[test]
fn unsafe_state_parent_and_hard_linked_lock_fail_before_target_mutation() {
    let temp = tempfile::tempdir().unwrap();
    let target = temp.path().join("target");
    fs::create_dir(&target).unwrap();
    fs::create_dir(target.join("config")).unwrap();
    let engine = make_engine(&temp, &target);
    engine.initialize_store().unwrap();
    let (_, request) = prepare(&engine, "config/file.conf", false);

    let external_lock = temp.path().join("external-lock");
    fs::write(&external_lock, []).unwrap();
    let original_mode = fs::metadata(&external_lock).unwrap().permissions().mode() & 0o777;
    fs::remove_file(engine.config().state_root().join("transaction.lock")).unwrap();
    fs::hard_link(
        &external_lock,
        engine.config().state_root().join("transaction.lock"),
    )
    .unwrap();
    assert!(matches!(
        engine.commit_v1(&request),
        Err(CommitError::InvalidStore(_))
    ));
    assert_eq!(
        fs::metadata(&external_lock).unwrap().permissions().mode() & 0o777,
        original_mode
    );
    assert!(!target.join("config/file.conf").exists());

    fs::remove_file(engine.config().state_root().join("transaction.lock")).unwrap();
    fs::set_permissions(temp.path().join("state"), fs::Permissions::from_mode(0o777)).unwrap();
    assert!(matches!(
        engine.commit_v1(&request),
        Err(CommitError::InvalidStore(_))
    ));
    assert!(!target.join("config/file.conf").exists());
}

#[test]
fn physically_overlapping_authorities_are_rejected_before_journaling() {
    let temp = tempfile::tempdir().unwrap();
    let state_home = temp.path().join("state");
    fs::create_dir(&state_home).unwrap();
    fs::set_permissions(&state_home, fs::Permissions::from_mode(0o700)).unwrap();
    let target = temp.path().join("target");
    fs::create_dir(&target).unwrap();
    fs::create_dir(target.join("config")).unwrap();
    let home = DeploymentName::new("home").unwrap();
    let alias = DeploymentName::new("alias").unwrap();
    let engine = Engine::new(
        EngineConfig::from_state_home(&state_home, StoreAccess::ReadWrite)
            .unwrap()
            .with_target_authority(home.clone(), &target)
            .unwrap()
            .with_target_authority(alias.clone(), &target)
            .unwrap(),
        EnginePorts::system(),
    );
    engine.initialize_store().unwrap();
    let first = ArtifactId::new("config/first").unwrap();
    let second = ArtifactId::new("config/second").unwrap();
    let result = engine.prepare_v1(&PrepareRequestV1::from(PrepareRequestPartsV1 {
        namespace: NamespaceName::new("workstation").unwrap(),
        expected_head: None,
        graph_digest: Digest::sha256(b"aliased authorities"),
        inputs: vec![],
        artifacts: vec![
            PrepareArtifactV1::new(first.clone(), b"first\n".to_vec(), "text/plain").unwrap(),
            PrepareArtifactV1::new(second.clone(), b"second\n".to_vec(), "text/plain").unwrap(),
        ],
        transforms: vec![],
        findings: vec![],
        operations: vec![
            PrepareOperationV1::place_file(home, "config/first", first, 0o600).unwrap(),
            PrepareOperationV1::place_file(alias, "config/second", second, 0o600).unwrap(),
        ],
    }));

    assert!(matches!(
        result,
        Err(EngineError::PreparedStore {
            reason: PreparedStoreIssue::TargetOwnershipConflict {
                overlap: OwnershipOverlapKindV1::PhysicalAuthorityAlias,
                ..
            },
            ..
        })
    ));
    assert!(!target.join("config/first").exists());
    assert!(!target.join("config/second").exists());
    assert!(
        !engine
            .config()
            .state_root()
            .join("transactions/current.json")
            .exists()
    );
}

#[test]
fn existing_directory_mode_change_is_a_reviewed_replacement() {
    let temp = tempfile::tempdir().unwrap();
    let target = temp.path().join("target");
    fs::create_dir(&target).unwrap();
    fs::create_dir(target.join("config")).unwrap();
    let engine = make_engine(&temp, &target);
    engine.initialize_store().unwrap();
    let baseline = engine
        .prepare_v1(&PrepareRequestV1::from(PrepareRequestPartsV1 {
            namespace: NamespaceName::new("workstation").unwrap(),
            expected_head: None,
            graph_digest: Digest::sha256(b"directory mode baseline"),
            inputs: vec![],
            artifacts: vec![],
            transforms: vec![],
            findings: vec![],
            operations: vec![
                PrepareOperationV1::ensure_directory(
                    DeploymentName::new("home").unwrap(),
                    "config/generated",
                    0o755,
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
    let request = PrepareRequestV1::from(PrepareRequestPartsV1 {
        namespace: NamespaceName::new("workstation").unwrap(),
        expected_head: Some(baseline.head().clone()),
        graph_digest: Digest::sha256(b"directory mode"),
        inputs: vec![],
        artifacts: vec![],
        transforms: vec![],
        findings: vec![],
        operations: vec![
            PrepareOperationV1::ensure_directory(
                DeploymentName::new("home").unwrap(),
                "config/generated",
                0o700,
            )
            .unwrap(),
        ],
    });

    let before = fs::metadata(target.join("config/generated")).unwrap().ino();
    let prepared = engine.prepare_v1(&request).unwrap();
    assert!(matches!(
        prepared.operations(),
        [PrepareOperationV1::EnsureDirectory {
            replace_existing: true,
            mode: 0o700,
            ..
        }]
    ));
    engine
        .commit_v1(&CommitRequestV1::new(
            prepared.plan_id().clone(),
            ApprovalV1::new(
                prepared.plan_id().clone(),
                prepared.approval_digest().clone(),
            ),
        ))
        .unwrap();
    assert_eq!(
        fs::metadata(target.join("config/generated"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
    assert_ne!(
        fs::metadata(target.join("config/generated")).unwrap().ino(),
        before
    );
}
