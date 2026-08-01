use std::fs;
#[cfg(feature = "failpoints")]
use std::fs::OpenOptions;
#[cfg(feature = "failpoints")]
use std::io::{Seek, SeekFrom, Write};
#[cfg(feature = "failpoints")]
use std::os::unix::fs::MetadataExt;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::{Mutex, MutexGuard};

#[cfg(feature = "failpoints")]
use std::process::Command;

#[cfg(feature = "failpoints")]
use malm::PruneRequestV1;
use malm::{
    ApprovalV1, CheckoutRequestV1, CommitError, CommitRequestV1, Engine, EngineConfig, EngineError,
    EnginePorts, OwnershipOverlapKindV1, PrepareArtifactV1, PrepareOperationV1,
    PrepareRequestPartsV1, PrepareRequestV1, PreparedStoreIssue, StoreAccess,
};
use malm_types::{ArtifactId, DeploymentName, Digest, NamespaceName};

fn test_guard() -> MutexGuard<'static, ()> {
    // Crash tests fork this binary. Until exec, the child inherits every
    // sibling thread's flock descriptors even though they are marked CLOEXEC.
    static TEST_LOCK: Mutex<()> = Mutex::new(());
    TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner())
}

fn make_engine(temp: &tempfile::TempDir, target: &Path) -> Engine {
    make_engine_at(&temp.path().join("state"), target)
}

fn make_engine_at(state_home: &Path, target: &Path) -> Engine {
    if !state_home.exists() {
        fs::create_dir(state_home).unwrap();
        fs::set_permissions(state_home, fs::Permissions::from_mode(0o700)).unwrap();
    }
    Engine::new(
        EngineConfig::from_state_home(state_home, StoreAccess::ReadWrite)
            .unwrap()
            .with_target_authority(DeploymentName::new("home").unwrap(), target)
            .unwrap(),
        EnginePorts::system(),
    )
}

#[cfg(feature = "failpoints")]
fn replacement_request_for(expected_head: Option<Digest>) -> PrepareRequestV1 {
    let artifact = ArtifactId::new("config/file").unwrap();
    PrepareRequestV1::from(PrepareRequestPartsV1 {
        namespace: NamespaceName::new("workstation").unwrap(),
        expected_head,
        graph_digest: Digest::sha256(b"replacement graph"),
        inputs: vec![],
        artifacts: vec![
            PrepareArtifactV1::new(
                artifact.clone(),
                b"replacement bytes\n".to_vec(),
                "text/plain",
            )
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
        ],
    })
}

#[cfg(feature = "failpoints")]
fn removal_request_for(expected_head: Option<Digest>) -> PrepareRequestV1 {
    PrepareRequestV1::from(PrepareRequestPartsV1 {
        namespace: NamespaceName::new("workstation").unwrap(),
        expected_head,
        graph_digest: Digest::sha256(b"removal graph"),
        inputs: vec![],
        artifacts: vec![],
        transforms: vec![],
        findings: vec![],
        operations: vec![
            PrepareOperationV1::remove_leaf(
                DeploymentName::new("home").unwrap(),
                "config/file.conf",
            )
            .unwrap(),
        ],
    })
}

#[cfg(feature = "failpoints")]
fn directory_removal_request_for(expected_head: Option<Digest>) -> PrepareRequestV1 {
    PrepareRequestV1::from(PrepareRequestPartsV1 {
        namespace: NamespaceName::new("workstation").unwrap(),
        expected_head,
        graph_digest: Digest::sha256(b"directory removal graph"),
        inputs: vec![],
        artifacts: vec![],
        transforms: vec![],
        findings: vec![],
        operations: vec![
            PrepareOperationV1::remove_leaf(
                DeploymentName::new("home").unwrap(),
                "config/generated",
            )
            .unwrap(),
        ],
    })
}

fn request() -> PrepareRequestV1 {
    let artifact = ArtifactId::new("config/file").unwrap();
    PrepareRequestV1::from(PrepareRequestPartsV1 {
        namespace: NamespaceName::new("workstation").unwrap(),
        expected_head: None,
        graph_digest: Digest::sha256(b"graph"),
        inputs: vec![],
        artifacts: vec![
            PrepareArtifactV1::new(artifact.clone(), b"offline bytes\n".to_vec(), "text/plain")
                .unwrap(),
        ],
        transforms: vec![],
        findings: vec![],
        operations: vec![
            PrepareOperationV1::place_file(
                DeploymentName::new("home").unwrap(),
                "config/file.conf",
                artifact,
                0o600,
            )
            .unwrap(),
        ],
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

fn namespace_file_request(
    namespace: &str,
    expected: Option<Digest>,
    relative_path: &str,
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

fn namespace_file_request_for_authority(
    namespace: &str,
    authority: &str,
    relative_path: &str,
    bytes: &[u8],
) -> PrepareRequestV1 {
    let artifact = ArtifactId::new(format!("config/{namespace}")).unwrap();
    PrepareRequestV1::from(PrepareRequestPartsV1 {
        namespace: NamespaceName::new(namespace).unwrap(),
        expected_head: None,
        graph_digest: Digest::sha256([namespace.as_bytes(), authority.as_bytes(), bytes].concat()),
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

fn namespace_directory_request(namespace: &str, relative_path: &str) -> PrepareRequestV1 {
    PrepareRequestV1::from(PrepareRequestPartsV1 {
        namespace: NamespaceName::new(namespace).unwrap(),
        expected_head: None,
        graph_digest: Digest::sha256([namespace.as_bytes(), relative_path.as_bytes()].concat()),
        inputs: vec![],
        artifacts: vec![],
        transforms: vec![],
        findings: vec![],
        operations: vec![
            PrepareOperationV1::ensure_directory(
                DeploymentName::new("home").unwrap(),
                relative_path,
                0o700,
            )
            .unwrap(),
        ],
    })
}

fn commit_prepared(engine: &Engine, prepared: &malm::PreparedDeploymentV1) -> malm::ApplyOutcomeV1 {
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
fn current_head(engine: &Engine) -> Option<Digest> {
    engine
        .inspect_state_v1(&NamespaceName::new("workstation").unwrap())
        .unwrap()
        .head()
        .cloned()
}

#[cfg(feature = "failpoints")]
fn seed_owned_file(engine: &Engine, relative_path: &str, bytes: &[u8]) -> malm::ApplyOutcomeV1 {
    let artifact = ArtifactId::new("seed/file").unwrap();
    let prepared = engine
        .prepare_v1(&PrepareRequestV1::from(PrepareRequestPartsV1 {
            namespace: NamespaceName::new("workstation").unwrap(),
            expected_head: current_head(engine),
            graph_digest: Digest::sha256([relative_path.as_bytes(), bytes].concat()),
            inputs: vec![],
            artifacts: vec![
                PrepareArtifactV1::new(artifact.clone(), bytes.to_vec(), "text/plain").unwrap(),
            ],
            transforms: vec![],
            findings: vec![],
            operations: vec![
                PrepareOperationV1::place_file(
                    DeploymentName::new("home").unwrap(),
                    relative_path,
                    artifact,
                    0o600,
                )
                .unwrap(),
            ],
        }))
        .unwrap();
    commit_prepared(engine, &prepared)
}

#[cfg(feature = "failpoints")]
fn seed_owned_directory(engine: &Engine, relative_path: &str) -> malm::ApplyOutcomeV1 {
    let prepared = engine
        .prepare_v1(&PrepareRequestV1::from(PrepareRequestPartsV1 {
            namespace: NamespaceName::new("workstation").unwrap(),
            expected_head: current_head(engine),
            graph_digest: Digest::sha256(relative_path.as_bytes()),
            inputs: vec![],
            artifacts: vec![],
            transforms: vec![],
            findings: vec![],
            operations: vec![
                PrepareOperationV1::ensure_directory(
                    DeploymentName::new("home").unwrap(),
                    relative_path,
                    0o700,
                )
                .unwrap(),
            ],
        }))
        .unwrap();
    commit_prepared(engine, &prepared)
}

fn directory_request_for(expected_head: Option<Digest>) -> PrepareRequestV1 {
    PrepareRequestV1::from(PrepareRequestPartsV1 {
        namespace: NamespaceName::new("workstation").unwrap(),
        expected_head,
        graph_digest: Digest::sha256(b"directory graph"),
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
    })
}

fn directory_request() -> PrepareRequestV1 {
    directory_request_for(None)
}

#[cfg(feature = "failpoints")]
fn crash_scenario_request(engine: &Engine, scenario: &str) -> PrepareRequestV1 {
    let expected = current_head(engine);
    match scenario {
        "replace" => replacement_request_for(expected),
        "remove" => removal_request_for(expected),
        "remove-directory" => directory_removal_request_for(expected),
        "ensure" => directory_request_for(expected),
        "place" => request(),
        _ => panic!("unknown crash scenario {scenario:?}"),
    }
}

#[test]
fn commit_applies_only_the_durable_plan_and_publishes_state() {
    let _test_guard = test_guard();
    let temp = tempfile::tempdir().unwrap();
    let target = temp.path().join("target");
    fs::create_dir(&target).unwrap();
    fs::create_dir(target.join("config")).unwrap();
    let engine = make_engine(&temp, &target);
    engine.initialize_store().unwrap();
    let prepared = engine.prepare_v1(&request()).unwrap();
    let approval = ApprovalV1::new(
        prepared.plan_id().clone(),
        prepared.approval_digest().clone(),
    );
    let request = CommitRequestV1::new(prepared.plan_id().clone(), approval);

    let outcome = engine.commit_v1(&request).unwrap();

    assert_eq!(outcome.plan_id(), prepared.plan_id());
    assert!(outcome.previous_head().is_none());
    assert_eq!(
        fs::read(target.join("config/file.conf")).unwrap(),
        b"offline bytes\n"
    );
    assert_eq!(
        fs::metadata(target.join("config/file.conf"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    assert_eq!(
        engine.inspect_state_v1(outcome.namespace()).unwrap().head(),
        Some(outcome.head())
    );

    drop(engine);
    let restarted = make_engine(&temp, &target);
    assert_eq!(
        restarted
            .inspect_state_v1(outcome.namespace())
            .unwrap()
            .head(),
        Some(outcome.head())
    );
    let repeated = restarted.commit_v1(&request);
    assert!(
        matches!(repeated, Err(CommitError::StaleNamespaceHead { .. })),
        "unexpected repeated-commit result: {repeated:?}"
    );
}

#[test]
fn home_authority_can_prepare_and_commit_above_nested_state() {
    let _test_guard = test_guard();
    let temp = tempfile::tempdir().unwrap();
    let home = temp.path().join("home");
    let state_home = home.join(".local/state");
    fs::create_dir_all(&state_home).unwrap();
    fs::set_permissions(&state_home, fs::Permissions::from_mode(0o700)).unwrap();
    fs::create_dir(home.join("config")).unwrap();
    let engine = make_engine_at(&state_home, &home);
    assert_eq!(engine.config().state_root(), home.join(".local/state/malm"));
    engine.initialize_store().unwrap();

    let prepared = engine.prepare_v1(&request()).unwrap();
    commit_prepared(&engine, &prepared);

    assert_eq!(
        fs::read(home.join("config/file.conf")).unwrap(),
        b"offline bytes\n"
    );
}

#[test]
fn commit_rejects_orphan_catalog_staging_before_mutation() {
    let _test_guard = test_guard();
    let temp = tempfile::tempdir().unwrap();
    let target = temp.path().join("target");
    fs::create_dir(&target).unwrap();
    fs::create_dir(target.join("config")).unwrap();
    let engine = make_engine(&temp, &target);
    engine.initialize_store().unwrap();
    let prepared = engine.prepare_v1(&request()).unwrap();
    let state = engine.config().state_root().join("state");
    fs::copy(state.join("catalog.json"), state.join(".catalog.json.new")).unwrap();

    assert!(matches!(
        engine.recover_v1(),
        Err(CommitError::InvalidStore(_))
    ));

    let result = engine.commit_v1(&CommitRequestV1::new(
        prepared.plan_id().clone(),
        ApprovalV1::new(
            prepared.plan_id().clone(),
            prepared.approval_digest().clone(),
        ),
    ));

    assert!(matches!(result, Err(CommitError::InvalidStore(_))));
    assert!(!target.join("config/file.conf").exists());
    assert!(
        !engine
            .config()
            .state_root()
            .join("transactions/current.json")
            .exists()
    );
}

#[test]
fn prepare_preserves_commit_state_validation_errors() {
    let _test_guard = test_guard();
    let temp = tempfile::tempdir().unwrap();
    let target = temp.path().join("target");
    fs::create_dir(&target).unwrap();
    fs::create_dir(target.join("config")).unwrap();
    let engine = make_engine(&temp, &target);
    engine.initialize_store().unwrap();
    fs::write(
        engine.config().state_root().join("state/catalog.json"),
        b"{}\n",
    )
    .unwrap();

    let error = engine.prepare_v1(&request()).unwrap_err();

    assert!(matches!(
        error,
        EngineError::Commit {
            source: CommitError::InvalidStore(_),
        }
    ));
}

#[test]
fn namespace_heads_advance_independently_in_both_orders() {
    let _test_guard = test_guard();
    for alpha_first in [true, false] {
        let temp = tempfile::tempdir().unwrap();
        let target = temp.path().join("target");
        fs::create_dir(&target).unwrap();
        fs::create_dir(target.join("config")).unwrap();
        fs::create_dir(target.join("config/alpha")).unwrap();
        fs::create_dir(target.join("config/beta")).unwrap();
        let engine = make_engine(&temp, &target);
        engine.initialize_store().unwrap();
        let alpha = engine
            .prepare_v1(&namespace_file_request(
                "alpha",
                None,
                "config/alpha/file.conf",
                b"alpha\n",
                false,
            ))
            .unwrap();
        let beta = engine
            .prepare_v1(&namespace_file_request(
                "beta",
                None,
                "config/beta/file.conf",
                b"beta\n",
                false,
            ))
            .unwrap();
        let (alpha, beta) = if alpha_first {
            (
                commit_prepared(&engine, &alpha),
                commit_prepared(&engine, &beta),
            )
        } else {
            let beta = commit_prepared(&engine, &beta);
            let alpha = commit_prepared(&engine, &alpha);
            (alpha, beta)
        };
        assert_eq!(
            engine.inspect_state_v1(alpha.namespace()).unwrap().head(),
            Some(alpha.head())
        );
        assert_eq!(
            engine.inspect_state_v1(beta.namespace()).unwrap().head(),
            Some(beta.head())
        );
        assert!(alpha.previous_head().is_none());
        assert!(beta.previous_head().is_none());
    }
}

#[test]
fn prepare_rejects_exact_and_ancestor_cross_namespace_claims_before_publication() {
    let _test_guard = test_guard();
    let temp = tempfile::tempdir().unwrap();
    let target = temp.path().join("target");
    fs::create_dir(&target).unwrap();
    fs::create_dir(target.join("config")).unwrap();
    let engine = make_engine(&temp, &target);
    engine.initialize_store().unwrap();

    let alpha = engine
        .prepare_v1(&namespace_file_request(
            "alpha",
            None,
            "config/shared.conf",
            b"alpha bytes\n",
            false,
        ))
        .unwrap();
    commit_prepared(&engine, &alpha);
    let beta_bytes = b"beta bytes\n";
    let error = engine
        .prepare_v1(&namespace_file_request(
            "beta",
            None,
            "config/shared.conf",
            beta_bytes,
            true,
        ))
        .unwrap_err();
    assert!(matches!(
        error,
        EngineError::PreparedStore {
            reason: PreparedStoreIssue::TargetOwnershipConflict {
                requesting_namespace,
                owning_namespace,
                requesting_authority,
                owning_authority,
                requested_path,
                owned_path,
                overlap: OwnershipOverlapKindV1::Exact,
            },
            ..
        } if requesting_namespace.as_str() == "beta"
            && owning_namespace.as_str() == "alpha"
            && requesting_authority.as_str() == "home"
            && owning_authority.as_str() == "home"
            && requested_path == "config/shared.conf"
            && owned_path == "config/shared.conf"
    ));
    assert!(
        !engine
            .config()
            .state_root()
            .join("objects/blobs")
            .join(Digest::sha256(beta_bytes).as_str())
            .exists()
    );

    let gamma_directory = engine
        .prepare_v1(&namespace_directory_request("gamma", "config/owned"))
        .unwrap();
    let gamma_head = commit_prepared(&engine, &gamma_directory);
    let child_bytes = b"cross-namespace child\n";
    let error = engine
        .prepare_v1(&namespace_file_request(
            "beta",
            None,
            "config/owned/child.conf",
            child_bytes,
            false,
        ))
        .unwrap_err();
    assert!(matches!(
        error,
        EngineError::PreparedStore {
            reason: PreparedStoreIssue::TargetOwnershipConflict {
                requesting_namespace,
                owning_namespace,
                requested_path,
                owned_path,
                overlap: OwnershipOverlapKindV1::AncestorDescendant,
                ..
            },
            ..
        } if requesting_namespace.as_str() == "beta"
            && owning_namespace.as_str() == "gamma"
            && requested_path == "config/owned/child.conf"
            && owned_path == "config/owned"
    ));
    assert_eq!(
        engine
            .inspect_state_v1(&NamespaceName::new("gamma").unwrap())
            .unwrap()
            .head(),
        Some(gamma_head.head())
    );
    assert!(
        !engine
            .config()
            .state_root()
            .join("objects/blobs")
            .join(Digest::sha256(child_bytes).as_str())
            .exists()
    );
}

#[test]
fn commit_rechecks_cross_namespace_ownership_under_the_global_lock() {
    let _test_guard = test_guard();
    let temp = tempfile::tempdir().unwrap();
    let target = temp.path().join("target");
    fs::create_dir(&target).unwrap();
    fs::create_dir(target.join("config")).unwrap();
    let engine = make_engine(&temp, &target);
    engine.initialize_store().unwrap();

    let alpha = engine
        .prepare_v1(&namespace_file_request(
            "alpha",
            None,
            "config/contended.conf",
            b"alpha wins\n",
            false,
        ))
        .unwrap();
    let beta = engine
        .prepare_v1(&namespace_file_request(
            "beta",
            None,
            "config/contended.conf",
            b"beta loses\n",
            false,
        ))
        .unwrap();
    commit_prepared(&engine, &alpha);

    let result = engine.commit_v1(&CommitRequestV1::new(
        beta.plan_id().clone(),
        ApprovalV1::new(beta.plan_id().clone(), beta.approval_digest().clone()),
    ));
    assert!(matches!(
        result,
        Err(CommitError::TargetOwnershipConflict {
            requesting_namespace,
            owning_namespace,
            overlap: OwnershipOverlapKindV1::Exact,
            ..
        }) if requesting_namespace.as_str() == "beta" && owning_namespace.as_str() == "alpha"
    ));
    assert_eq!(
        fs::read(target.join("config/contended.conf")).unwrap(),
        b"alpha wins\n"
    );
    assert!(
        engine
            .inspect_state_v1(&NamespaceName::new("beta").unwrap())
            .unwrap()
            .head()
            .is_none()
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
fn unowned_present_targets_are_refused_or_adopt_behind_consent() {
    let _test_guard = test_guard();
    let temp = tempfile::tempdir().unwrap();
    let target = temp.path().join("target");
    fs::create_dir(&target).unwrap();
    fs::create_dir(target.join("config")).unwrap();
    fs::write(target.join("config/remove.conf"), b"unmanaged remove\n").unwrap();
    fs::write(target.join("config/replace.conf"), b"unmanaged replace\n").unwrap();
    fs::create_dir(target.join("config/adopt")).unwrap();
    fs::set_permissions(
        target.join("config/adopt"),
        fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    fs::create_dir(target.join("config/unowned-remove")).unwrap();
    fs::write(
        target.join("config/unowned-remove/keep.txt"),
        b"unmanaged directory contents\n",
    )
    .unwrap();
    let engine = make_engine(&temp, &target);
    engine.initialize_store().unwrap();

    let remove = engine
        .prepare_v1(&PrepareRequestV1::from(PrepareRequestPartsV1 {
            namespace: NamespaceName::new("workstation").unwrap(),
            expected_head: None,
            graph_digest: Digest::sha256(b"unowned removal"),
            inputs: vec![],
            artifacts: vec![],
            transforms: vec![],
            findings: vec![],
            operations: vec![
                PrepareOperationV1::remove_leaf(
                    DeploymentName::new("home").unwrap(),
                    "config/remove.conf",
                )
                .unwrap(),
            ],
        }))
        .unwrap_err();
    assert!(matches!(
        remove,
        EngineError::PreparedStore {
            reason: PreparedStoreIssue::UnownedTargetMutation {
                namespace,
                relative_path,
                ..
            },
            ..
        } if namespace.as_str() == "workstation" && relative_path == "config/remove.conf"
    ));

    let remove_directory = engine
        .prepare_v1(&PrepareRequestV1::from(PrepareRequestPartsV1 {
            namespace: NamespaceName::new("workstation").unwrap(),
            expected_head: None,
            graph_digest: Digest::sha256(b"unowned directory removal"),
            inputs: vec![],
            artifacts: vec![],
            transforms: vec![],
            findings: vec![],
            operations: vec![
                PrepareOperationV1::remove_leaf(
                    DeploymentName::new("home").unwrap(),
                    "config/unowned-remove",
                )
                .unwrap(),
            ],
        }))
        .unwrap_err();
    assert!(matches!(
        remove_directory,
        EngineError::PreparedStore {
            reason: PreparedStoreIssue::UnownedTargetMutation { relative_path, .. },
            ..
        } if relative_path == "config/unowned-remove"
    ));

    // A non-replacing placement cannot adopt an existing leaf; conflict policy
    // requires the leaf to be absent.
    let place = engine
        .prepare_v1(&namespace_file_request(
            "workstation",
            None,
            "config/replace.conf",
            b"replacement\n",
            false,
        ))
        .unwrap_err();
    assert!(matches!(
        place,
        EngineError::PreparedStore {
            reason: PreparedStoreIssue::UnsafeTarget { ref detail },
            ..
        } if detail.contains("requires the leaf to be absent")
    ));

    // A replacing placement can adopt the unmanaged file only after a mandatory
    // replace-existing finding is approved. Preparing the plan must not touch
    // the target.
    let replace = engine
        .prepare_v1(&namespace_file_request(
            "workstation",
            None,
            "config/replace.conf",
            b"replacement\n",
            true,
        ))
        .unwrap();
    let adoption: Vec<_> = replace
        .findings()
        .iter()
        .filter(|finding| finding.code() == "replace-existing")
        .collect();
    assert_eq!(adoption.len(), 1);
    assert!(adoption[0].approval_required());
    assert!(adoption[0].message().contains("config/replace.conf"));

    let adopt = engine
        .prepare_v1(&namespace_directory_request("workstation", "config/adopt"))
        .unwrap_err();
    assert!(matches!(
        adopt,
        EngineError::PreparedStore {
            path,
            reason: PreparedStoreIssue::DirectoryOccupancyConflicts {
                paths,
                omitted_count: 0,
            },
            ..
        } if path == target.join("config/adopt") && paths == vec![path.clone()]
    ));
    assert_eq!(
        fs::read(target.join("config/remove.conf")).unwrap(),
        b"unmanaged remove\n"
    );
    assert_eq!(
        fs::read(target.join("config/replace.conf")).unwrap(),
        b"unmanaged replace\n"
    );
    assert!(target.join("config/adopt").is_dir());
    assert_eq!(
        fs::read(target.join("config/unowned-remove/keep.txt")).unwrap(),
        b"unmanaged directory contents\n"
    );
}

#[test]
fn same_mode_unowned_structural_directory_preserves_unmanaged_siblings() {
    let _test_guard = test_guard();
    let temp = tempfile::tempdir().unwrap();
    let target = temp.path().join("target");
    fs::create_dir(&target).unwrap();
    fs::create_dir(target.join("shared")).unwrap();
    fs::set_permissions(
        target.join("shared"),
        fs::Permissions::from_mode(0o755),
    )
    .unwrap();
    fs::write(target.join("shared/unmanaged.txt"), b"keep\n").unwrap();
    let engine = make_engine(&temp, &target);
    engine.initialize_store().unwrap();
    let artifact = ArtifactId::new("shared/managed").unwrap();
    let prepared = engine
        .prepare_v1(&PrepareRequestV1::from(PrepareRequestPartsV1 {
            namespace: NamespaceName::new("workstation").unwrap(),
            expected_head: None,
            graph_digest: Digest::sha256(b"structural directory adoption"),
            inputs: vec![],
            artifacts: vec![
                PrepareArtifactV1::new(artifact.clone(), b"managed\n".to_vec(), "text/plain")
                    .unwrap(),
            ],
            transforms: vec![],
            findings: vec![],
            operations: vec![
                PrepareOperationV1::ensure_directory(
                    DeploymentName::new("home").unwrap(),
                    "shared",
                    0o755,
                )
                .unwrap(),
                PrepareOperationV1::place_file(
                    DeploymentName::new("home").unwrap(),
                    "shared/managed.txt",
                    artifact,
                    0o600,
                )
                .unwrap(),
            ],
        }))
        .unwrap();

    commit_prepared(&engine, &prepared);
    assert_eq!(
        fs::read(target.join("shared/unmanaged.txt")).unwrap(),
        b"keep\n"
    );
    assert_eq!(
        fs::read(target.join("shared/managed.txt")).unwrap(),
        b"managed\n"
    );
}

#[test]
fn occupied_managed_directory_mode_change_succeeds_after_removal() {
    let _test_guard = test_guard();
    let temp = tempfile::tempdir().unwrap();
    let target = temp.path().join("target");
    fs::create_dir(&target).unwrap();
    fs::create_dir(target.join("config")).unwrap();
    let engine = make_engine(&temp, &target);
    engine.initialize_store().unwrap();

    let directory_request = |expected_head, mode| {
        PrepareRequestV1::from(PrepareRequestPartsV1 {
            namespace: NamespaceName::new("workstation").unwrap(),
            expected_head,
            graph_digest: Digest::sha256(format!("directory mode {mode:o}").as_bytes()),
            inputs: vec![],
            artifacts: vec![],
            transforms: vec![],
            findings: vec![],
            operations: vec![
                PrepareOperationV1::ensure_directory(
                    DeploymentName::new("home").unwrap(),
                    "config/generated",
                    mode,
                )
                .unwrap(),
            ],
        })
    };
    let first = engine.prepare_v1(&directory_request(None, 0o750)).unwrap();
    let first = commit_prepared(&engine, &first);
    fs::write(
        target.join("config/generated/unmanaged.txt"),
        b"blocking contents\n",
    )
    .unwrap();

    let blocked = engine
        .prepare_v1(&directory_request(Some(first.head().clone()), 0o700))
        .unwrap_err();
    assert!(matches!(
        blocked,
        EngineError::PreparedStore {
            reason: PreparedStoreIssue::DirectoryOccupancyConflicts {
                paths,
                omitted_count: 0,
            },
            ..
        } if paths == vec![target.join("config/generated")]
    ));
    assert_eq!(
        fs::read(target.join("config/generated/unmanaged.txt")).unwrap(),
        b"blocking contents\n"
    );

    fs::remove_dir_all(target.join("config/generated")).unwrap();
    let retried = engine
        .prepare_v1(&directory_request(Some(first.head().clone()), 0o700))
        .unwrap();
    commit_prepared(&engine, &retried);
    assert_eq!(
        fs::metadata(target.join("config/generated"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
}

#[test]
fn directory_conflicts_are_sorted_bounded_and_publish_no_artifacts() {
    let _test_guard = test_guard();
    let temp = tempfile::tempdir().unwrap();
    let target = temp.path().join("target");
    fs::create_dir(&target).unwrap();
    fs::create_dir(target.join("config")).unwrap();
    let engine = make_engine(&temp, &target);
    engine.initialize_store().unwrap();

    let mut artifacts = Vec::new();
    let mut operations = Vec::new();
    for index in (0..257).rev() {
        let relative_path = format!("config/blocker-{index:03}");
        fs::create_dir(target.join(&relative_path)).unwrap();
        let artifact_id = ArtifactId::new(format!("blocker-{index:03}")).unwrap();
        artifacts.push(
            PrepareArtifactV1::new(
                artifact_id.clone(),
                format!("artifact {index}\n").into_bytes(),
                "text/plain",
            )
            .unwrap(),
        );
        operations.push(
            PrepareOperationV1::place_file(
                DeploymentName::new("home").unwrap(),
                relative_path,
                artifact_id,
                0o600,
            )
            .unwrap(),
        );
    }
    let first_digest = Digest::sha256(b"artifact 0\n");
    let error = engine
        .prepare_v1(&PrepareRequestV1::from(PrepareRequestPartsV1 {
            namespace: NamespaceName::new("workstation").unwrap(),
            expected_head: None,
            graph_digest: Digest::sha256(b"bounded directory conflicts"),
            inputs: vec![],
            artifacts,
            transforms: vec![],
            findings: vec![],
            operations,
        }))
        .unwrap_err();

    let EngineError::PreparedStore {
        path,
        reason:
            PreparedStoreIssue::DirectoryOccupancyConflicts {
                paths,
                omitted_count,
            },
    } = error
    else {
        panic!("unexpected preparation error: {error:?}")
    };
    assert_eq!(path, target.join("config/blocker-000"));
    assert_eq!(paths.len(), malm::MAX_DIRECTORY_CONFLICT_PATHS);
    assert_eq!(paths.first(), Some(&target.join("config/blocker-000")));
    assert_eq!(paths.last(), Some(&target.join("config/blocker-255")));
    assert_eq!(omitted_count, 1);
    assert!(!engine.config().state_root().join("prepared").exists());
    assert!(
        !engine
            .config()
            .state_root()
            .join("objects/blobs")
            .join(first_digest.as_str())
            .exists()
    );
    assert!(target.join("config/blocker-256").is_dir());
}

#[test]
fn later_hard_observation_error_takes_precedence_over_collected_conflicts() {
    let _test_guard = test_guard();
    let temp = tempfile::tempdir().unwrap();
    let target = temp.path().join("target");
    fs::create_dir(&target).unwrap();
    fs::create_dir(target.join("blocked")).unwrap();
    let engine = make_engine(&temp, &target);
    engine.initialize_store().unwrap();
    let first = ArtifactId::new("first").unwrap();
    let second = ArtifactId::new("second").unwrap();

    let error = engine
        .prepare_v1(&PrepareRequestV1::from(PrepareRequestPartsV1 {
            namespace: NamespaceName::new("workstation").unwrap(),
            expected_head: None,
            graph_digest: Digest::sha256(b"hard observation precedence"),
            inputs: vec![],
            artifacts: vec![
                PrepareArtifactV1::new(first.clone(), b"first\n".to_vec(), "text/plain").unwrap(),
                PrepareArtifactV1::new(second.clone(), b"second\n".to_vec(), "text/plain")
                    .unwrap(),
            ],
            transforms: vec![],
            findings: vec![],
            operations: vec![
                PrepareOperationV1::place_file(
                    DeploymentName::new("home").unwrap(),
                    "blocked",
                    first,
                    0o600,
                )
                .unwrap(),
                PrepareOperationV1::place_file(
                    DeploymentName::new("unknown").unwrap(),
                    "later",
                    second,
                    0o600,
                )
                .unwrap(),
            ],
        }))
        .unwrap_err();

    assert!(matches!(
        error,
        EngineError::PreparedStore {
            reason: PreparedStoreIssue::UnknownTargetAuthority(authority),
            ..
        } if authority.as_str() == "unknown"
    ));
}

#[test]
fn occupancy_precedes_cross_namespace_ownership_until_directory_is_removed() {
    let _test_guard = test_guard();
    let temp = tempfile::tempdir().unwrap();
    let target = temp.path().join("target");
    fs::create_dir(&target).unwrap();
    fs::create_dir(target.join("config")).unwrap();
    let engine = make_engine(&temp, &target);
    engine.initialize_store().unwrap();
    let alpha = engine
        .prepare_v1(&namespace_file_request(
            "alpha",
            None,
            "config/shared.conf",
            b"alpha\n",
            false,
        ))
        .unwrap();
    commit_prepared(&engine, &alpha);
    fs::remove_file(target.join("config/shared.conf")).unwrap();
    fs::create_dir(target.join("config/shared.conf")).unwrap();
    fs::write(
        target.join("config/shared.conf/unmanaged.txt"),
        b"blocking\n",
    )
    .unwrap();

    let blocked = engine
        .prepare_v1(&namespace_file_request(
            "beta",
            None,
            "config/shared.conf",
            b"beta\n",
            true,
        ))
        .unwrap_err();
    assert!(matches!(
        blocked,
        EngineError::PreparedStore {
            reason: PreparedStoreIssue::DirectoryOccupancyConflicts { .. },
            ..
        }
    ));

    fs::remove_dir_all(target.join("config/shared.conf")).unwrap();
    let ownership = engine
        .prepare_v1(&namespace_file_request(
            "beta",
            None,
            "config/shared.conf",
            b"beta\n",
            true,
        ))
        .unwrap_err();
    assert!(matches!(
        ownership,
        EngineError::PreparedStore {
            reason: PreparedStoreIssue::TargetOwnershipConflict {
                requesting_namespace,
                owning_namespace,
                ..
            },
            ..
        } if requesting_namespace.as_str() == "beta" && owning_namespace.as_str() == "alpha"
    ));
}

#[test]
fn physical_authority_aliases_are_rejected_during_prepare_and_locked_commit() {
    let _test_guard = test_guard();
    let temp = tempfile::tempdir().unwrap();
    let target = temp.path().join("target");
    fs::create_dir(&target).unwrap();
    fs::create_dir(target.join("config")).unwrap();
    let state_home = temp.path().join("state");
    fs::create_dir(&state_home).unwrap();
    fs::set_permissions(&state_home, fs::Permissions::from_mode(0o700)).unwrap();
    let engine = Engine::new(
        EngineConfig::from_state_home(&state_home, StoreAccess::ReadWrite)
            .unwrap()
            .with_target_authority(DeploymentName::new("home").unwrap(), &target)
            .unwrap()
            .with_target_authority(DeploymentName::new("alias").unwrap(), &target)
            .unwrap(),
        EnginePorts::system(),
    );
    engine.initialize_store().unwrap();

    let alpha = engine
        .prepare_v1(&namespace_file_request_for_authority(
            "alpha",
            "home",
            "config/alpha.conf",
            b"alpha\n",
        ))
        .unwrap();
    let beta = engine
        .prepare_v1(&namespace_file_request_for_authority(
            "beta",
            "alias",
            "config/beta.conf",
            b"beta\n",
        ))
        .unwrap();
    commit_prepared(&engine, &alpha);

    let result = engine.commit_v1(&CommitRequestV1::new(
        beta.plan_id().clone(),
        ApprovalV1::new(beta.plan_id().clone(), beta.approval_digest().clone()),
    ));
    assert!(matches!(
        result,
        Err(CommitError::TargetOwnershipConflict {
            requesting_namespace,
            owning_namespace,
            requesting_authority,
            owning_authority,
            overlap: OwnershipOverlapKindV1::PhysicalAuthorityAlias,
            ..
        }) if requesting_namespace.as_str() == "beta"
            && owning_namespace.as_str() == "alpha"
            && requesting_authority.as_str() == "alias"
            && owning_authority.as_str() == "home"
    ));
    assert!(!target.join("config/beta.conf").exists());

    let error = engine
        .prepare_v1(&namespace_file_request_for_authority(
            "gamma",
            "alias",
            "config/gamma.conf",
            b"gamma\n",
        ))
        .unwrap_err();
    assert!(matches!(
        error,
        EngineError::PreparedStore {
            reason: PreparedStoreIssue::TargetOwnershipConflict {
                requesting_namespace,
                owning_namespace,
                requesting_authority,
                owning_authority,
                overlap: OwnershipOverlapKindV1::PhysicalAuthorityAlias,
                ..
            },
            ..
        } if requesting_namespace.as_str() == "gamma"
            && owning_namespace.as_str() == "alpha"
            && requesting_authority.as_str() == "alias"
            && owning_authority.as_str() == "home"
    ));
    assert!(!target.join("config/gamma.conf").exists());
}

#[test]
fn a_deep_dangling_selected_history_is_tolerated_by_routine_ops_and_reported_by_fsck() {
    let _test_guard = test_guard();
    let temp = tempfile::tempdir().unwrap();
    let target = temp.path().join("target");
    fs::create_dir(&target).unwrap();
    fs::create_dir(target.join("config")).unwrap();
    let engine = make_engine(&temp, &target);
    engine.initialize_store().unwrap();

    let first = engine
        .prepare_v1(&namespace_file_request(
            "alpha",
            None,
            "config/alpha.conf",
            b"alpha one\n",
            false,
        ))
        .unwrap();
    let first_outcome = commit_prepared(&engine, &first);
    let second = engine
        .prepare_v1(&namespace_file_request(
            "alpha",
            Some(first_outcome.head().clone()),
            "config/alpha.conf",
            b"alpha two\n",
            true,
        ))
        .unwrap();
    let second_outcome = commit_prepared(&engine, &second);
    let third = engine
        .prepare_v1(&namespace_file_request(
            "alpha",
            Some(second_outcome.head().clone()),
            "config/alpha.conf",
            b"alpha three\n",
            true,
        ))
        .unwrap();
    commit_prepared(&engine, &third);
    let beta = engine
        .prepare_v1(&namespace_file_request(
            "beta",
            None,
            "config/beta.conf",
            b"beta\n",
            false,
        ))
        .unwrap();

    let catalog_path = engine.config().state_root().join("state/catalog.json");
    let catalog_before = fs::read(&catalog_path).unwrap();
    fs::remove_file(
        engine
            .config()
            .state_root()
            .join("state/generations")
            .join(first_outcome.head().as_str()),
    )
    .unwrap();
    // Routine operations validate only the history links they extend: each head
    // and its immediate predecessor. A deeper dangling record in another
    // namespace must not block an unrelated mutation.
    let result = engine.commit_v1(&CommitRequestV1::new(
        beta.plan_id().clone(),
        ApprovalV1::new(beta.plan_id().clone(), beta.approval_digest().clone()),
    ));
    assert!(result.is_ok(), "unrelated mutation proceeds: {result:?}");
    assert_eq!(
        fs::read(target.join("config/beta.conf")).unwrap(),
        b"beta\n"
    );
    assert_ne!(
        fs::read(catalog_path).unwrap(),
        catalog_before,
        "the beta head was committed"
    );

    // The deep audit must still report the dangling record.
    let report = engine
        .fsck_v1(&malm_types::FsckRequestV1::default())
        .unwrap();
    assert!(
        report
            .findings()
            .iter()
            .any(|finding| finding.detail().contains("lineage is invalid")),
        "fsck reports the dangling retained lineage: {report:?}"
    );
}

#[test]
fn state_inspection_and_recovery_accept_an_initialized_empty_store() {
    let _test_guard = test_guard();
    let temp = tempfile::tempdir().unwrap();
    let target = temp.path().join("target");
    fs::create_dir(&target).unwrap();
    let engine = make_engine(&temp, &target);
    engine.initialize_store().unwrap();

    assert!(
        engine
            .inspect_state_v1(&NamespaceName::new("workstation").unwrap())
            .unwrap()
            .head()
            .is_none()
    );
    assert!(engine.recover_v1().unwrap().head().is_none());
}

#[test]
fn retained_generations_prepare_offline_reverse_and_forward_checkouts() {
    let _test_guard = test_guard();
    let temp = tempfile::tempdir().unwrap();
    let target = temp.path().join("target");
    fs::create_dir(&target).unwrap();
    fs::create_dir(target.join("config")).unwrap();
    let engine = make_engine(&temp, &target);
    engine.initialize_store().unwrap();

    let empty = engine
        .prepare_v1(&PrepareRequestV1::from(PrepareRequestPartsV1 {
            namespace: NamespaceName::new("workstation").unwrap(),
            expected_head: None,
            graph_digest: Digest::sha256(b"empty generation"),
            inputs: vec![],
            artifacts: vec![],
            transforms: vec![],
            findings: vec![],
            operations: vec![],
        }))
        .unwrap();
    let empty = commit_prepared(&engine, &empty);
    let first = engine
        .prepare_v1(&file_request(
            Some(empty.head().clone()),
            b"first generation\n",
            false,
        ))
        .unwrap();
    let first = commit_prepared(&engine, &first);
    let second = engine
        .prepare_v1(&file_request(
            Some(first.head().clone()),
            b"second generation\n",
            true,
        ))
        .unwrap();
    let second = commit_prepared(&engine, &second);
    assert_eq!(
        fs::read(target.join("config/file.conf")).unwrap(),
        b"second generation\n"
    );

    drop(engine);
    let restarted = make_engine(&temp, &target);
    assert!(
        restarted
            .prepare_checkout_v1(&CheckoutRequestV1::new(
                NamespaceName::new("workstation").unwrap(),
                Digest::sha256(b"not retained"),
            ))
            .is_err()
    );
    assert_eq!(
        fs::read(target.join("config/file.conf")).unwrap(),
        b"second generation\n"
    );
    let reverse = restarted
        .prepare_checkout_v1(&CheckoutRequestV1::new(
            first.namespace().clone(),
            first.head().clone(),
        ))
        .unwrap();
    assert_eq!(reverse.operation_count(), 1);
    assert_eq!(reverse.artifacts()[0].byte_len(), 17);
    assert_eq!(
        fs::read(target.join("config/file.conf")).unwrap(),
        b"second generation\n",
        "checkout preparation must not mutate targets"
    );
    commit_prepared(&restarted, &reverse);
    assert_eq!(
        fs::read(target.join("config/file.conf")).unwrap(),
        b"first generation\n"
    );

    let forward = restarted
        .prepare_checkout_v1(&CheckoutRequestV1::new(
            second.namespace().clone(),
            second.head().clone(),
        ))
        .unwrap();
    commit_prepared(&restarted, &forward);
    assert_eq!(
        fs::read(target.join("config/file.conf")).unwrap(),
        b"second generation\n"
    );

    fs::remove_file(target.join("config/file.conf")).unwrap();
    let remove_already_absent = restarted
        .prepare_checkout_v1(&CheckoutRequestV1::new(
            empty.namespace().clone(),
            empty.head().clone(),
        ))
        .unwrap();
    assert_eq!(remove_already_absent.operation_count(), 1);
    commit_prepared(&restarted, &remove_already_absent);
    assert!(!target.join("config/file.conf").exists());
    let assert_absent = restarted
        .prepare_checkout_v1(&CheckoutRequestV1::new(
            empty.namespace().clone(),
            empty.head().clone(),
        ))
        .unwrap();
    assert!(matches!(
        assert_absent.operations(),
        [PrepareOperationV1::AssertAbsent { .. }]
    ));
    commit_prepared(&restarted, &assert_absent);
    fs::write(
        target.join("config/file.conf"),
        b"externally recreated bytes\n",
    )
    .unwrap();
    assert!(
        restarted
            .prepare_checkout_v1(&CheckoutRequestV1::new(
                empty.namespace().clone(),
                empty.head().clone(),
            ))
            .is_err()
    );
    assert_eq!(
        fs::read(target.join("config/file.conf")).unwrap(),
        b"externally recreated bytes\n"
    );
}

#[test]
fn checkout_removes_and_recreates_an_empty_managed_directory() {
    let _test_guard = test_guard();
    let temp = tempfile::tempdir().unwrap();
    let target = temp.path().join("target");
    fs::create_dir(&target).unwrap();
    fs::create_dir(target.join("config")).unwrap();
    let engine = make_engine(&temp, &target);
    engine.initialize_store().unwrap();
    let empty = engine
        .prepare_v1(&PrepareRequestV1::from(PrepareRequestPartsV1 {
            namespace: NamespaceName::new("workstation").unwrap(),
            expected_head: None,
            graph_digest: Digest::sha256(b"empty directory baseline"),
            inputs: vec![],
            artifacts: vec![],
            transforms: vec![],
            findings: vec![],
            operations: vec![],
        }))
        .unwrap();
    let empty = commit_prepared(&engine, &empty);
    let directory = engine
        .prepare_v1(&PrepareRequestV1::from(PrepareRequestPartsV1 {
            namespace: NamespaceName::new("workstation").unwrap(),
            expected_head: Some(empty.head().clone()),
            graph_digest: Digest::sha256(b"directory generation"),
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
        }))
        .unwrap();
    let directory = commit_prepared(&engine, &directory);
    assert!(target.join("config/generated").is_dir());

    let remove = engine
        .prepare_checkout_v1(&CheckoutRequestV1::new(
            empty.namespace().clone(),
            empty.head().clone(),
        ))
        .unwrap();
    commit_prepared(&engine, &remove);
    assert!(!target.join("config/generated").exists());

    let recreate = engine
        .prepare_checkout_v1(&CheckoutRequestV1::new(
            directory.namespace().clone(),
            directory.head().clone(),
        ))
        .unwrap();
    commit_prepared(&engine, &recreate);
    let metadata = fs::metadata(target.join("config/generated")).unwrap();
    assert!(metadata.is_dir());
    assert_eq!(metadata.permissions().mode() & 0o777, 0o700);
}

#[test]
fn wrong_approval_and_corrupt_objects_fail_before_target_mutation() {
    let _test_guard = test_guard();
    let temp = tempfile::tempdir().unwrap();
    let target = temp.path().join("target");
    fs::create_dir(&target).unwrap();
    fs::create_dir(target.join("config")).unwrap();
    let engine = make_engine(&temp, &target);
    engine.initialize_store().unwrap();
    let prepared = engine.prepare_v1(&request()).unwrap();

    let wrong = CommitRequestV1::new(
        prepared.plan_id().clone(),
        ApprovalV1::new(prepared.plan_id().clone(), Digest::sha256(b"wrong")),
    );
    assert!(matches!(
        engine.commit_v1(&wrong),
        Err(CommitError::ApprovalFindingsMismatch)
    ));
    assert!(!target.join("config/file.conf").exists());

    let blob = engine
        .config()
        .state_root()
        .join("objects/blobs")
        .join(prepared.artifacts()[0].digest().as_str());
    fs::set_permissions(&blob, fs::Permissions::from_mode(0o600)).unwrap();
    fs::write(&blob, b"tampered").unwrap();
    fs::set_permissions(&blob, fs::Permissions::from_mode(0o400)).unwrap();
    let approved = CommitRequestV1::new(
        prepared.plan_id().clone(),
        ApprovalV1::new(
            prepared.plan_id().clone(),
            prepared.approval_digest().clone(),
        ),
    );
    assert!(engine.commit_v1(&approved).is_err());
    assert!(!target.join("config/file.conf").exists());
    assert!(
        engine
            .inspect_state_v1(&NamespaceName::new("workstation").unwrap())
            .unwrap()
            .head()
            .is_none()
    );
}

#[test]
fn multiple_operations_with_one_parent_commit_as_one_generation() {
    let _test_guard = test_guard();
    let temp = tempfile::tempdir().unwrap();
    let target = temp.path().join("target");
    fs::create_dir(&target).unwrap();
    fs::create_dir(target.join("config")).unwrap();
    let engine = make_engine(&temp, &target);
    engine.initialize_store().unwrap();
    let first = ArtifactId::new("config/first").unwrap();
    let second = ArtifactId::new("config/second").unwrap();
    let prepared = engine
        .prepare_v1(&PrepareRequestV1::from(PrepareRequestPartsV1 {
            namespace: NamespaceName::new("workstation").unwrap(),
            expected_head: None,
            graph_digest: Digest::sha256(b"two files"),
            inputs: vec![],
            artifacts: vec![
                PrepareArtifactV1::new(first.clone(), b"first\n".to_vec(), "text/plain").unwrap(),
                PrepareArtifactV1::new(second.clone(), b"second\n".to_vec(), "text/plain").unwrap(),
            ],
            transforms: vec![],
            findings: vec![],
            operations: vec![
                PrepareOperationV1::place_file(
                    DeploymentName::new("home").unwrap(),
                    "config/first.conf",
                    first,
                    0o600,
                )
                .unwrap(),
                PrepareOperationV1::place_file(
                    DeploymentName::new("home").unwrap(),
                    "config/second.conf",
                    second,
                    0o600,
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
        fs::read(target.join("config/first.conf")).unwrap(),
        b"first\n"
    );
    assert_eq!(
        fs::read(target.join("config/second.conf")).unwrap(),
        b"second\n"
    );
}

#[test]
fn commit_creates_a_recoverable_directory_with_exact_mode() {
    let _test_guard = test_guard();
    let temp = tempfile::tempdir().unwrap();
    let target = temp.path().join("target");
    fs::create_dir(&target).unwrap();
    fs::create_dir(target.join("config")).unwrap();
    let engine = make_engine(&temp, &target);
    engine.initialize_store().unwrap();
    let prepared = engine.prepare_v1(&directory_request()).unwrap();
    let request = CommitRequestV1::new(
        prepared.plan_id().clone(),
        ApprovalV1::new(
            prepared.plan_id().clone(),
            prepared.approval_digest().clone(),
        ),
    );

    engine.commit_v1(&request).unwrap();

    let metadata = fs::metadata(target.join("config/generated")).unwrap();
    assert!(metadata.is_dir());
    assert_eq!(metadata.permissions().mode() & 0o777, 0o700);
}

#[cfg(feature = "failpoints")]
#[test]
fn crash_commit_child() {
    let _test_guard = test_guard();
    let Some(root) = std::env::var_os("MALM_V1_CRASH_ROOT") else {
        return;
    };
    let root = std::path::PathBuf::from(root);
    let target = root.join("target");
    let engine = make_engine_at(&root.join("state"), &target);
    let scenario = std::env::var("MALM_V1_CRASH_SCENARIO").unwrap();
    let request = crash_scenario_request(&engine, &scenario);
    let prepared = engine.prepare_v1(&request).unwrap();
    let commit = CommitRequestV1::new(
        prepared.plan_id().clone(),
        ApprovalV1::new(
            prepared.plan_id().clone(),
            prepared.approval_digest().clone(),
        ),
    );
    engine.commit_v1(&commit).unwrap();
    panic!("configured commit failpoint did not fire");
}

#[cfg(feature = "failpoints")]
#[test]
fn crash_initialize_child() {
    let _test_guard = test_guard();
    let Some(root) = std::env::var_os("MALM_V1_INITIALIZE_CRASH_ROOT") else {
        return;
    };
    let root = std::path::PathBuf::from(root);
    let engine = make_engine_at(&root.join("state"), &root.join("target"));
    engine.initialize_store().unwrap();
    panic!("configured initialization failpoint did not fire");
}

#[cfg(feature = "failpoints")]
#[test]
fn crash_recovery_child() {
    let _test_guard = test_guard();
    let Some(root) = std::env::var_os("MALM_V1_RECOVERY_CRASH_ROOT") else {
        return;
    };
    let root = std::path::PathBuf::from(root);
    let engine = make_engine_at(&root.join("state"), &root.join("target"));
    engine.recover_v1().unwrap();
    panic!("configured recovery failpoint did not fire");
}

#[cfg(feature = "failpoints")]
fn run_commit_crash(root: &Path, scenario: &str, point: &str) {
    let status = Command::new(std::env::current_exe().unwrap())
        .arg("--exact")
        .arg("crash_commit_child")
        .arg("--nocapture")
        .env("MALM_V1_CRASH_ROOT", root)
        .env("MALM_V1_CRASH_SCENARIO", scenario)
        .env("MALM_FAILPOINT", point)
        .status()
        .unwrap();
    assert!(!status.success(), "child unexpectedly survived {point}");
}

#[cfg(feature = "failpoints")]
#[test]
fn initial_catalog_link_crash_restarts_without_a_staging_record() {
    let _test_guard = test_guard();
    let temp = tempfile::tempdir().unwrap();
    fs::create_dir(temp.path().join("target")).unwrap();
    let status = Command::new(std::env::current_exe().unwrap())
        .arg("--exact")
        .arg("crash_initialize_child")
        .arg("--nocapture")
        .env("MALM_V1_INITIALIZE_CRASH_ROOT", temp.path())
        .env("MALM_FAILPOINT", "v1.initialize.catalog.after_link")
        .status()
        .unwrap();
    assert!(!status.success());

    let engine = make_engine_at(&temp.path().join("state"), &temp.path().join("target"));
    engine.initialize_store().unwrap();
    assert_eq!(
        fs::read(engine.config().state_root().join("state/catalog.json")).unwrap(),
        b"{\"schema_version\":1,\"heads\":[]}\n"
    );
    assert!(
        !engine
            .config()
            .state_root()
            .join("state/.catalog.json.new")
            .exists()
    );
}

#[cfg(feature = "failpoints")]
fn run_crash_case(point: &str, scenario: &str, rolls_forward: bool) {
    let temp = tempfile::tempdir().unwrap();
    let target = temp.path().join("target");
    fs::create_dir(&target).unwrap();
    fs::create_dir(target.join("config")).unwrap();
    let target_file = target.join("config/file.conf");
    let engine = make_engine(&temp, &target);
    engine.initialize_store().unwrap();
    let previous = match scenario {
        "replace" | "remove" => Some(
            seed_owned_file(&engine, "config/file.conf", b"original bytes\n")
                .head()
                .clone(),
        ),
        "remove-directory" => Some(
            seed_owned_directory(&engine, "config/generated")
                .head()
                .clone(),
        ),
        "ensure" => None,
        _ => unreachable!(),
    };
    let prepare = crash_scenario_request(&engine, scenario);
    let prepared = engine.prepare_v1(&prepare).unwrap();

    run_commit_crash(temp.path(), scenario, point);

    drop(engine);
    let restarted = make_engine(&temp, &target);
    restarted.recover_v1().unwrap();
    let recovered = restarted.inspect_state_v1(prepared.namespace()).unwrap();
    if rolls_forward {
        assert!(recovered.head().is_some(), "{point}");
        match scenario {
            "replace" => assert_eq!(fs::read(&target_file).unwrap(), b"replacement bytes\n"),
            "remove" => assert!(!target_file.exists(), "{point}"),
            "remove-directory" => {
                assert!(!target.join("config/generated").exists(), "{point}");
            }
            "ensure" => {
                let metadata = fs::metadata(target.join("config/generated")).unwrap();
                assert!(metadata.is_dir(), "{point}");
                assert_eq!(metadata.permissions().mode() & 0o777, 0o700, "{point}");
            }
            _ => unreachable!(),
        }
    } else {
        assert_eq!(recovered.head(), previous.as_ref(), "{point}");
        if scenario == "ensure" {
            assert!(!target.join("config/generated").exists(), "{point}");
        } else if scenario == "remove-directory" {
            let metadata = fs::metadata(target.join("config/generated")).unwrap();
            assert!(metadata.is_dir(), "{point}");
            assert_eq!(metadata.permissions().mode() & 0o777, 0o700, "{point}");
        } else {
            assert_eq!(fs::read(&target_file).unwrap(), b"original bytes\n");
        }
    }
    assert!(
        !restarted
            .config()
            .state_root()
            .join("transactions/current.json")
            .exists(),
        "{point}"
    );
    let staging_prefix = format!(".malm-{}-0-", &prepared.plan_id().as_str()[3..]);
    assert!(
        fs::read_dir(target.join("config"))
            .unwrap()
            .all(|entry| !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(&staging_prefix)),
        "{point}"
    );
}

#[cfg(feature = "failpoints")]
#[test]
fn crashes_recover_replacements_to_only_prior_or_prepared_state() {
    let _test_guard = test_guard();
    for point in [
        "v1.commit.after_preflight",
        "v1.commit.after_journal",
        "v1.commit.journal_update.after_link",
        "v1.commit.journal_update.after_exchange",
        "v1.commit.place.after_identity",
        "v1.commit.place.after_staging",
        "v1.commit.journal_update.after_link=2",
        "v1.commit.journal_update.after_exchange=2",
        "v1.commit.place.after_backup_intent",
        "v1.commit.place.before_backup_rename",
        "v1.commit.place.after_backup_rename",
        "v1.commit.place.after_backup_sync",
        "v1.commit.journal_update.after_link=3",
        "v1.commit.journal_update.after_exchange=3",
        "v1.commit.place.after_backup",
        "v1.commit.place.before_final_rename",
        "v1.commit.burst.after_final_sync",
        "v1.commit.after_generation",
        "v1.commit.catalog.after_staging",
    ] {
        run_crash_case(point, "replace", false);
    }
    for point in [
        "v1.commit.after_catalog",
        "v1.commit.cleanup.after_quarantine",
        "v1.commit.cleanup.before_unlink",
        "v1.commit.after_finalize",
        "v1.commit.after_journal_removed",
    ] {
        run_crash_case(point, "replace", true);
    }
}

#[cfg(feature = "failpoints")]
#[test]
fn crashes_recover_removals_to_only_prior_or_prepared_state() {
    let _test_guard = test_guard();
    for scenario in ["remove", "remove-directory"] {
        for point in [
            "v1.commit.after_preflight",
            "v1.commit.after_journal",
            "v1.commit.journal_update.after_link",
            "v1.commit.journal_update.after_exchange",
            "v1.commit.remove.after_backup_intent",
            "v1.commit.remove.before_backup_rename",
            "v1.commit.remove.after_backup_rename",
            "v1.commit.remove.after_backup_sync",
            "v1.commit.journal_update.after_link=2",
            "v1.commit.journal_update.after_exchange=2",
            "v1.commit.remove.after_backup",
            "v1.commit.burst.after_final_sync",
            "v1.commit.after_generation",
            "v1.commit.catalog.after_staging",
        ] {
            run_crash_case(point, scenario, false);
        }
        run_crash_case("v1.commit.after_catalog", scenario, true);
        run_crash_case("v1.commit.cleanup.after_quarantine", scenario, true);
        run_crash_case("v1.commit.cleanup.before_unlink", scenario, true);
        run_crash_case("v1.commit.after_finalize", scenario, true);
    }
}

#[cfg(feature = "failpoints")]
#[test]
fn crashes_recover_directories_to_only_prior_or_prepared_state() {
    let _test_guard = test_guard();
    for point in [
        "v1.commit.after_preflight",
        "v1.commit.after_journal",
        "v1.commit.before_operation",
        "v1.commit.journal_update.after_link",
        "v1.commit.journal_update.after_exchange",
        "v1.commit.ensure.after_create",
        "v1.commit.after_operation",
        "v1.commit.after_generation",
        "v1.commit.catalog.after_staging",
    ] {
        run_crash_case(point, "ensure", false);
    }
    for point in ["v1.commit.after_catalog", "v1.commit.after_finalize"] {
        run_crash_case(point, "ensure", true);
    }
}

#[cfg(feature = "failpoints")]
#[test]
fn recovery_rejects_a_journal_not_derived_from_its_prepared_plan() {
    let _test_guard = test_guard();
    let temp = tempfile::tempdir().unwrap();
    let target = temp.path().join("target");
    fs::create_dir(&target).unwrap();
    fs::create_dir(target.join("config")).unwrap();
    let target_file = target.join("config/file.conf");
    let engine = make_engine(&temp, &target);
    engine.initialize_store().unwrap();
    let baseline = seed_owned_file(&engine, "config/file.conf", b"original bytes\n");
    let prepared = engine
        .prepare_v1(&replacement_request_for(current_head(&engine)))
        .unwrap();
    let commit = CommitRequestV1::new(
        prepared.plan_id().clone(),
        ApprovalV1::new(
            prepared.plan_id().clone(),
            prepared.approval_digest().clone(),
        ),
    );

    let status = Command::new(std::env::current_exe().unwrap())
        .arg("--exact")
        .arg("crash_commit_child")
        .arg("--nocapture")
        .env("MALM_V1_CRASH_ROOT", temp.path())
        .env("MALM_V1_CRASH_SCENARIO", "replace")
        .env("MALM_FAILPOINT", "v1.commit.after_journal")
        .status()
        .unwrap();
    assert!(!status.success());
    drop(engine);

    let restarted = make_engine(&temp, &target);
    assert!(matches!(
        restarted.commit_v1(&commit),
        Err(CommitError::RecoveryRequired)
    ));
    let journal_path = restarted
        .config()
        .state_root()
        .join("transactions/current.json");
    let mut journal: serde_json::Value =
        serde_json::from_slice(&fs::read(&journal_path).unwrap()).unwrap();
    journal["next_generation"] = Digest::sha256(b"forged generation").as_str().into();
    let mut bytes = serde_json::to_vec(&journal).unwrap();
    bytes.push(b'\n');
    fs::write(&journal_path, bytes).unwrap();

    assert!(matches!(
        restarted.recover_v1(),
        Err(CommitError::InvalidJournal(_))
    ));
    assert_eq!(fs::read(&target_file).unwrap(), b"original bytes\n");
    assert!(journal_path.exists());
    assert!(
        restarted
            .inspect_state_v1(&NamespaceName::new("workstation").unwrap())
            .unwrap()
            .head()
            == Some(baseline.head())
    );
}

#[cfg(feature = "failpoints")]
#[test]
fn staged_journal_updates_are_never_promoted_before_validation() {
    let _test_guard = test_guard();
    for remove_current in [false, true] {
        let temp = tempfile::tempdir().unwrap();
        let target = temp.path().join("target");
        fs::create_dir(&target).unwrap();
        fs::create_dir(target.join("config")).unwrap();
        let target_file = target.join("config/file.conf");
        let engine = make_engine(&temp, &target);
        engine.initialize_store().unwrap();
        seed_owned_file(&engine, "config/file.conf", b"original bytes\n");

        run_commit_crash(
            temp.path(),
            "replace",
            "v1.commit.journal_update.after_link",
        );
        drop(engine);

        let transactions = temp.path().join("state/malm/transactions");
        let current = transactions.join("current.json");
        let update = transactions.join(".current.json.update");
        let current_bytes = fs::read(&current).unwrap();
        assert!(update.is_file());
        if remove_current {
            fs::remove_file(&current).unwrap();
        } else {
            let mut forged: serde_json::Value =
                serde_json::from_slice(&fs::read(&update).unwrap()).unwrap();
            forged["plan_id"] = serde_json::Value::String(
                malm_types::PreparedId::from_digest(&Digest::sha256(b"forged update"))
                    .as_str()
                    .to_owned(),
            );
            let mut bytes = serde_json::to_vec(&forged).unwrap();
            bytes.push(b'\n');
            fs::write(&update, bytes).unwrap();
        }

        let restarted = make_engine(&temp, &target);
        if remove_current {
            assert!(restarted.recover_v1().is_ok());
        } else {
            assert!(matches!(
                restarted.recover_v1(),
                Err(CommitError::InvalidJournal(_))
            ));
        }
        assert_eq!(fs::read(&target_file).unwrap(), b"original bytes\n");
        if remove_current {
            assert!(!current.exists());
            assert!(!update.exists());
        } else {
            assert!(update.is_file());
            assert_eq!(fs::read(&current).unwrap(), current_bytes);
        }
    }
}

#[cfg(feature = "failpoints")]
#[test]
fn update_only_cleanup_state_resumes_after_a_recovery_crash() {
    let _test_guard = test_guard();
    let temp = tempfile::tempdir().unwrap();
    let target = temp.path().join("target");
    fs::create_dir(&target).unwrap();
    fs::create_dir(target.join("config")).unwrap();
    let target_file = target.join("config/file.conf");
    let engine = make_engine(&temp, &target);
    engine.initialize_store().unwrap();
    let baseline = seed_owned_file(&engine, "config/file.conf", b"original bytes\n");

    run_commit_crash(
        temp.path(),
        "replace",
        "v1.commit.journal_update.after_link",
    );
    drop(engine);

    let status = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "crash_recovery_child", "--nocapture"])
        .env("MALM_V1_RECOVERY_CRASH_ROOT", temp.path())
        .env("MALM_FAILPOINT", "v1.commit.journal_remove.after_current")
        .status()
        .unwrap();
    assert!(!status.success());

    let transactions = temp.path().join("state/malm/transactions");
    assert!(!transactions.join("current.json").exists());
    assert!(transactions.join(".current.json.update").is_file());
    let restarted = make_engine(&temp, &target);
    assert_eq!(
        restarted.recover_v1().unwrap().head(),
        Some(baseline.head())
    );
    assert_eq!(fs::read(target_file).unwrap(), b"original bytes\n");
    assert!(!transactions.join("current.json").exists());
    assert!(!transactions.join(".current.json.update").exists());
}

#[cfg(feature = "failpoints")]
#[test]
fn previous_cleanup_state_resumes_after_a_recovery_crash() {
    let _test_guard = test_guard();
    let temp = tempfile::tempdir().unwrap();
    let target = temp.path().join("target");
    fs::create_dir(&target).unwrap();
    fs::create_dir(target.join("config")).unwrap();
    let target_file = target.join("config/file.conf");
    let engine = make_engine(&temp, &target);
    engine.initialize_store().unwrap();
    let baseline = seed_owned_file(&engine, "config/file.conf", b"original bytes\n");

    // A crash after journal exchange leaves current.json as the newer journal
    // and .current.json.update as the prior version of the same plan. This is
    // the StagedJournalUpdate::Previous case.
    run_commit_crash(
        temp.path(),
        "replace",
        "v1.commit.journal_update.after_exchange",
    );
    drop(engine);

    let transactions = temp.path().join("state/malm/transactions");
    assert!(transactions.join("current.json").is_file());
    assert!(transactions.join(".current.json.update").is_file());

    let status = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "crash_recovery_child", "--nocapture"])
        .env("MALM_V1_RECOVERY_CRASH_ROOT", temp.path())
        .env("MALM_FAILPOINT", "v1.commit.journal_remove.after_update")
        .status()
        .unwrap();
    assert!(!status.success());

    assert!(transactions.join("current.json").is_file());
    assert!(!transactions.join(".current.json.update").exists());
    let restarted = make_engine(&temp, &target);
    assert_eq!(
        restarted.recover_v1().unwrap().head(),
        Some(baseline.head())
    );
    assert_eq!(fs::read(&target_file).unwrap(), b"original bytes\n");
    assert!(!transactions.join("current.json").exists());
    assert!(!transactions.join(".current.json.update").exists());
}

#[cfg(feature = "failpoints")]
#[test]
fn identified_restored_source_digest_survives_a_second_recovery() {
    let _test_guard = test_guard();
    for scenario in ["replace", "remove"] {
        let temp = tempfile::tempdir().unwrap();
        let target = temp.path().join("target");
        fs::create_dir(&target).unwrap();
        fs::create_dir(target.join("config")).unwrap();
        let target_file = target.join("config/file.conf");
        let original = b"original bytes\n";
        let replacement = vec![b'Q'; original.len()];
        let engine = make_engine(&temp, &target);
        engine.initialize_store().unwrap();
        seed_owned_file(&engine, "config/file.conf", original);
        let commit_crash = if scenario == "replace" {
            "v1.commit.place.after_backup"
        } else {
            "v1.commit.remove.after_backup"
        };
        run_commit_crash(temp.path(), scenario, commit_crash);
        drop(engine);

        let status = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "crash_recovery_child", "--nocapture"])
            .env("MALM_V1_RECOVERY_CRASH_ROOT", temp.path())
            .env("MALM_FAILPOINT", "v1.commit.rollback.after_restore")
            .status()
            .unwrap();
        assert!(!status.success(), "{scenario}");
        let metadata = fs::metadata(&target_file).unwrap();
        let accessed = filetime::FileTime::from_last_access_time(&metadata);
        let modified = filetime::FileTime::from_last_modification_time(&metadata);
        let mut restored = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&target_file)
            .unwrap();
        restored.seek(SeekFrom::Start(0)).unwrap();
        restored.write_all(&replacement).unwrap();
        restored.flush().unwrap();
        filetime::set_file_handle_times(&restored, Some(accessed), Some(modified)).unwrap();

        let restarted = make_engine(&temp, &target);
        assert!(restarted.recover_v1().is_err(), "{scenario}");
        assert_eq!(fs::read(&target_file).unwrap(), replacement, "{scenario}");
        assert!(
            restarted
                .config()
                .state_root()
                .join("transactions/current.json")
                .is_file(),
            "{scenario}"
        );
    }
}

#[cfg(feature = "failpoints")]
#[test]
fn retention_cannot_race_recovery_and_collects_only_the_recovered_orphan() {
    let _test_guard = test_guard();
    let temp = tempfile::tempdir().unwrap();
    let target = temp.path().join("target");
    fs::create_dir(&target).unwrap();
    fs::create_dir(target.join("config")).unwrap();
    let target_file = target.join("config/file.conf");
    let engine = make_engine(&temp, &target);
    engine.initialize_store().unwrap();
    let baseline = seed_owned_file(&engine, "config/file.conf", b"original bytes\n");
    let prepared = engine
        .prepare_v1(&replacement_request_for(current_head(&engine)))
        .unwrap();

    let status = Command::new(std::env::current_exe().unwrap())
        .arg("--exact")
        .arg("crash_commit_child")
        .arg("--nocapture")
        .env("MALM_V1_CRASH_ROOT", temp.path())
        .env("MALM_V1_CRASH_SCENARIO", "replace")
        .env("MALM_FAILPOINT", "v1.commit.after_generation")
        .status()
        .unwrap();
    assert!(!status.success());
    drop(engine);

    let restarted = make_engine(&temp, &target);
    assert!(matches!(
        restarted.prune_v1(&PruneRequestV1::new(vec![])),
        Err(CommitError::RecoveryRequired)
    ));
    assert_eq!(
        restarted.recover_v1().unwrap().head(),
        Some(baseline.head())
    );
    let outcome = restarted.prune_v1(&PruneRequestV1::new(vec![])).unwrap();
    assert_eq!(outcome.prepared_records, 0);
    assert_eq!(outcome.artifact_blobs, 0);
    assert_eq!(outcome.state_generations, 1);
    assert!(restarted.plan_v1(prepared.plan_id()).is_ok());
    assert_eq!(fs::read(target_file).unwrap(), b"original bytes\n");
}

#[cfg(feature = "failpoints")]
#[test]
fn rollback_does_not_delete_an_unrelated_leaf_created_after_the_crash() {
    let _test_guard = test_guard();
    let temp = tempfile::tempdir().unwrap();
    let target = temp.path().join("target");
    fs::create_dir(&target).unwrap();
    fs::create_dir(target.join("config")).unwrap();
    let engine = make_engine(&temp, &target);
    engine.initialize_store().unwrap();
    engine.prepare_v1(&request()).unwrap();

    let status = Command::new(std::env::current_exe().unwrap())
        .arg("--exact")
        .arg("crash_commit_child")
        .arg("--nocapture")
        .env("MALM_V1_CRASH_ROOT", temp.path())
        .env("MALM_V1_CRASH_SCENARIO", "place")
        .env("MALM_FAILPOINT", "v1.commit.after_journal")
        .status()
        .unwrap();
    assert!(!status.success());
    drop(engine);

    let target_file = target.join("config/file.conf");
    fs::write(&target_file, b"unrelated concurrent bytes\n").unwrap();
    let restarted = make_engine(&temp, &target);
    assert!(restarted.recover_v1().unwrap().head().is_none());
    assert_eq!(
        fs::read(target_file).unwrap(),
        b"unrelated concurrent bytes\n"
    );
    assert!(
        !restarted
            .config()
            .state_root()
            .join("transactions/current.json")
            .exists()
    );
}

#[cfg(feature = "failpoints")]
#[test]
fn rollback_preserves_an_unidentified_reserved_staging_entry() {
    let _test_guard = test_guard();
    let temp = tempfile::tempdir().unwrap();
    let target = temp.path().join("target");
    fs::create_dir(&target).unwrap();
    fs::create_dir(target.join("config")).unwrap();
    let engine = make_engine(&temp, &target);
    engine.initialize_store().unwrap();
    let prepared = engine.prepare_v1(&request()).unwrap();

    let status = Command::new(std::env::current_exe().unwrap())
        .arg("--exact")
        .arg("crash_commit_child")
        .arg("--nocapture")
        .env("MALM_V1_CRASH_ROOT", temp.path())
        .env("MALM_V1_CRASH_SCENARIO", "place")
        .env("MALM_FAILPOINT", "v1.commit.after_journal")
        .status()
        .unwrap();
    assert!(!status.success());
    drop(engine);

    let staging = target
        .join("config")
        .join(format!(".malm-{}-0-new", &prepared.plan_id().as_str()[3..]));
    fs::write(&staging, b"unrelated reserved-name content\n").unwrap();
    let restarted = make_engine(&temp, &target);
    assert!(matches!(
        restarted.recover_v1(),
        Err(CommitError::InvalidJournal(_))
    ));
    assert_eq!(
        fs::read(&staging).unwrap(),
        b"unrelated reserved-name content\n"
    );
    assert!(
        restarted
            .config()
            .state_root()
            .join("transactions/current.json")
            .exists()
    );
}

#[cfg(feature = "failpoints")]
#[test]
fn backup_intent_does_not_authorize_an_unrelated_reserved_entry() {
    let _test_guard = test_guard();
    for scenario in ["replace", "remove"] {
        let temp = tempfile::tempdir().unwrap();
        let target = temp.path().join("target");
        fs::create_dir(&target).unwrap();
        fs::create_dir(target.join("config")).unwrap();
        let target_file = target.join("config/file.conf");
        let engine = make_engine(&temp, &target);
        engine.initialize_store().unwrap();
        seed_owned_file(&engine, "config/file.conf", b"original bytes\n");
        let prepare = crash_scenario_request(&engine, scenario);
        let prepared = engine.prepare_v1(&prepare).unwrap();
        let point = if scenario == "replace" {
            "v1.commit.place.after_backup_intent"
        } else {
            "v1.commit.remove.after_backup_intent"
        };

        run_commit_crash(temp.path(), scenario, point);
        drop(engine);

        let backup = target.join("config").join(format!(
            ".malm-{}-0-backup",
            &prepared.plan_id().as_str()[3..]
        ));
        fs::write(&backup, b"unrelated reserved-name backup\n").unwrap();
        let restarted = make_engine(&temp, &target);
        assert!(matches!(
            restarted.recover_v1(),
            Err(CommitError::StaleTarget(_))
        ));
        assert_eq!(fs::read(&target_file).unwrap(), b"original bytes\n");
        assert_eq!(
            fs::read(&backup).unwrap(),
            b"unrelated reserved-name backup\n"
        );
        assert!(
            restarted
                .config()
                .state_root()
                .join("transactions/current.json")
                .exists()
        );
    }
}

#[cfg(feature = "failpoints")]
#[test]
fn identified_backup_identity_must_match_the_prepared_source() {
    let _test_guard = test_guard();
    let temp = tempfile::tempdir().unwrap();
    let target = temp.path().join("target");
    fs::create_dir(&target).unwrap();
    fs::create_dir(target.join("config")).unwrap();
    let target_file = target.join("config/file.conf");
    let engine = make_engine(&temp, &target);
    engine.initialize_store().unwrap();
    seed_owned_file(&engine, "config/file.conf", b"original bytes\n");
    let prepared = engine
        .prepare_v1(&replacement_request_for(current_head(&engine)))
        .unwrap();

    run_commit_crash(temp.path(), "replace", "v1.commit.place.after_backup");
    drop(engine);

    let restarted = make_engine(&temp, &target);
    let journal_path = restarted
        .config()
        .state_root()
        .join("transactions/current.json");
    let mut journal = fs::read(&journal_path).unwrap();
    let backup = b"\"backup\":{\"state\":\"identified\",\"identity\":{";
    let backup_start = journal
        .windows(backup.len())
        .position(|window| window == backup)
        .expect("identified backup in canonical journal");
    let inode = b"\"inode\":";
    let inode_start = journal[backup_start..]
        .windows(inode.len())
        .position(|window| window == inode)
        .map(|offset| backup_start + offset + inode.len())
        .expect("backup inode in canonical journal");
    journal[inode_start] = if journal[inode_start] == b'9' {
        b'8'
    } else {
        b'9'
    };
    fs::write(&journal_path, journal).unwrap();

    assert!(matches!(
        restarted.recover_v1(),
        Err(CommitError::InvalidJournal(reason))
            if reason.contains("identified backup does not match its prepared source")
    ));
    let backup = target.join("config").join(format!(
        ".malm-{}-0-backup",
        &prepared.plan_id().as_str()[3..]
    ));
    assert_eq!(fs::read(backup).unwrap(), b"original bytes\n");
    assert!(!target_file.exists());
    assert!(journal_path.exists());
}

#[cfg(feature = "failpoints")]
#[test]
fn recovery_retains_the_journal_when_a_required_backup_vanishes() {
    let _test_guard = test_guard();
    for scenario in ["replace", "remove"] {
        let temp = tempfile::tempdir().unwrap();
        let target = temp.path().join("target");
        fs::create_dir(&target).unwrap();
        fs::create_dir(target.join("config")).unwrap();
        let engine = make_engine(&temp, &target);
        engine.initialize_store().unwrap();
        seed_owned_file(&engine, "config/file.conf", b"original bytes\n");
        let prepare_request = crash_scenario_request(&engine, scenario);
        let prepared = engine.prepare_v1(&prepare_request).unwrap();

        let status = Command::new(std::env::current_exe().unwrap())
            .arg("--exact")
            .arg("crash_commit_child")
            .arg("--nocapture")
            .env("MALM_V1_CRASH_ROOT", temp.path())
            .env("MALM_V1_CRASH_SCENARIO", scenario)
            .env("MALM_FAILPOINT", "v1.commit.burst.after_final_sync")
            .status()
            .unwrap();
        assert!(!status.success());
        drop(engine);

        let backup = target.join("config").join(format!(
            ".malm-{}-0-backup",
            &prepared.plan_id().as_str()[3..]
        ));
        fs::remove_file(backup).unwrap();
        let restarted = make_engine(&temp, &target);
        assert!(matches!(
            restarted.recover_v1(),
            Err(CommitError::InvalidJournal(_))
        ));
        assert!(
            restarted
                .config()
                .state_root()
                .join("transactions/current.json")
                .exists()
        );
    }
}

#[cfg(feature = "failpoints")]
#[test]
fn a_forged_created_identity_cannot_authorize_unrelated_content_deletion() {
    let _test_guard = test_guard();
    let temp = tempfile::tempdir().unwrap();
    let target = temp.path().join("target");
    fs::create_dir(&target).unwrap();
    fs::create_dir(target.join("config")).unwrap();
    let engine = make_engine(&temp, &target);
    engine.initialize_store().unwrap();
    engine.prepare_v1(&request()).unwrap();

    let status = Command::new(std::env::current_exe().unwrap())
        .arg("--exact")
        .arg("crash_commit_child")
        .arg("--nocapture")
        .env("MALM_V1_CRASH_ROOT", temp.path())
        .env("MALM_V1_CRASH_SCENARIO", "place")
        .env("MALM_FAILPOINT", "v1.commit.after_journal")
        .status()
        .unwrap();
    assert!(!status.success());
    drop(engine);

    let target_file = target.join("config/file.conf");
    fs::write(&target_file, b"foreign bytes\n").unwrap();
    fs::set_permissions(&target_file, fs::Permissions::from_mode(0o600)).unwrap();
    let metadata = fs::symlink_metadata(&target_file).unwrap();
    let restarted = make_engine(&temp, &target);
    let journal_path = restarted
        .config()
        .state_root()
        .join("transactions/current.json");
    let mut journal: serde_json::Value =
        serde_json::from_slice(&fs::read(&journal_path).unwrap()).unwrap();
    journal["operations"][0]["created_identity"] = serde_json::json!({
        "device": metadata.dev(),
        "inode": metadata.ino(),
        "user_id": metadata.uid(),
        "group_id": metadata.gid(),
        "mode": metadata.mode(),
        "links": metadata.nlink(),
        "size": metadata.size(),
        "modified_seconds": metadata.mtime(),
        "modified_nanoseconds": metadata.mtime_nsec(),
        "changed_seconds": metadata.ctime(),
        "changed_nanoseconds": metadata.ctime_nsec(),
    });
    let mut bytes = serde_json::to_vec(&journal).unwrap();
    bytes.push(b'\n');
    fs::write(&journal_path, bytes).unwrap();

    assert!(matches!(
        restarted.recover_v1(),
        Err(CommitError::InvalidJournal(_))
    ));
    assert_eq!(fs::read(&target_file).unwrap(), b"foreign bytes\n");
    assert!(journal_path.exists());
}

#[cfg(feature = "failpoints")]
#[test]
fn recovery_rejects_a_backup_changed_through_an_open_descriptor() {
    let _test_guard = test_guard();
    let temp = tempfile::tempdir().unwrap();
    let target = temp.path().join("target");
    fs::create_dir(&target).unwrap();
    fs::create_dir(target.join("config")).unwrap();
    let target_file = target.join("config/file.conf");
    let engine = make_engine(&temp, &target);
    engine.initialize_store().unwrap();
    seed_owned_file(&engine, "config/file.conf", b"original bytes\n");
    let prepared = engine
        .prepare_v1(&replacement_request_for(current_head(&engine)))
        .unwrap();
    let mut original = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&target_file)
        .unwrap();

    let status = Command::new(std::env::current_exe().unwrap())
        .arg("--exact")
        .arg("crash_commit_child")
        .arg("--nocapture")
        .env("MALM_V1_CRASH_ROOT", temp.path())
        .env("MALM_V1_CRASH_SCENARIO", "replace")
        .env("MALM_FAILPOINT", "v1.commit.place.after_backup")
        .status()
        .unwrap();
    assert!(!status.success());
    drop(engine);

    let backup = target.join("config").join(format!(
        ".malm-{}-0-backup",
        &prepared.plan_id().as_str()[3..]
    ));
    let metadata = fs::metadata(&backup).unwrap();
    let accessed = filetime::FileTime::from_last_access_time(&metadata);
    let modified = filetime::FileTime::from_last_modification_time(&metadata);
    original.seek(SeekFrom::Start(0)).unwrap();
    original.write_all(b"tampered bytes\n").unwrap();
    original.flush().unwrap();
    filetime::set_file_times(&backup, accessed, modified).unwrap();

    let restarted = make_engine(&temp, &target);
    assert!(matches!(
        restarted.recover_v1(),
        Err(CommitError::StaleTarget(_))
    ));
    assert_eq!(fs::read(&backup).unwrap(), b"tampered bytes\n");
    assert!(!target_file.exists());
    assert!(
        restarted
            .config()
            .state_root()
            .join("transactions/current.json")
            .exists()
    );
}

#[cfg(feature = "failpoints")]
#[test]
fn directory_creation_before_identity_durability_fails_closed() {
    let _test_guard = test_guard();
    let temp = tempfile::tempdir().unwrap();
    let target = temp.path().join("target");
    fs::create_dir(&target).unwrap();
    fs::create_dir(target.join("config")).unwrap();
    let engine = make_engine(&temp, &target);
    engine.initialize_store().unwrap();
    let prepared = engine.prepare_v1(&directory_request()).unwrap();
    let status = Command::new(std::env::current_exe().unwrap())
        .arg("--exact")
        .arg("crash_commit_child")
        .arg("--nocapture")
        .env("MALM_V1_CRASH_ROOT", temp.path())
        .env("MALM_V1_CRASH_SCENARIO", "ensure")
        .env("MALM_FAILPOINT", "v1.commit.ensure.before_identity")
        .status()
        .unwrap();
    assert!(!status.success());
    drop(engine);

    let staging = target.join("config").join(format!(
        ".malm-{}-0-new-dir",
        &prepared.plan_id().as_str()[3..]
    ));
    let restarted = make_engine(&temp, &target);
    assert!(matches!(
        restarted.recover_v1(),
        Err(CommitError::InvalidJournal(_))
    ));
    assert!(staging.is_dir());
    assert!(!target.join("config/generated").exists());
    assert!(
        restarted
            .config()
            .state_root()
            .join("transactions/current.json")
            .exists()
    );
}

#[cfg(feature = "failpoints")]
#[test]
fn journal_and_catalog_modes_ignore_a_restrictive_umask() {
    let _test_guard = test_guard();
    const CHILD: &str = "MALM_V1_COMMIT_UMASK_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let output = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "journal_and_catalog_modes_ignore_a_restrictive_umask",
                "--nocapture",
            ])
            .env(CHILD, "1")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "child failed\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    }

    let temp = tempfile::tempdir().unwrap();
    let target = temp.path().join("target");
    fs::create_dir(&target).unwrap();
    fs::create_dir(target.join("config")).unwrap();
    let engine = make_engine(&temp, &target);
    engine.initialize_store().unwrap();
    let first = engine.prepare_v1(&request()).unwrap();
    let first_outcome = engine
        .commit_v1(&CommitRequestV1::new(
            first.plan_id().clone(),
            ApprovalV1::new(first.plan_id().clone(), first.approval_digest().clone()),
        ))
        .unwrap();
    let second = engine
        .prepare_v1(&replacement_request_for(Some(first_outcome.head().clone())))
        .unwrap();
    let previous_umask = rustix::process::umask(rustix::fs::Mode::from_raw_mode(0o777));
    let second_outcome = engine
        .commit_v1(&CommitRequestV1::new(
            second.plan_id().clone(),
            ApprovalV1::new(second.plan_id().clone(), second.approval_digest().clone()),
        ))
        .unwrap();
    rustix::process::umask(previous_umask);

    let active = engine.config().state_root().join("state/catalog.json");
    assert_eq!(
        fs::metadata(active).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(
        engine
            .inspect_state_v1(second_outcome.namespace())
            .unwrap()
            .head(),
        Some(second_outcome.head())
    );
}
