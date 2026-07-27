use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Barrier};
use std::thread;

use malm::{
    CommitError, DirectorySafetyIssue, Engine, EngineConfig, EngineConfigError, EngineError,
    StateDirectory, StoreAccess, StoreMetadataIssue, StoreStatus,
};
use malm_root::{RootPathError, resolve_root};
use malm_types::{DeploymentName, NamespaceName};
use rustix::fs::Mode;

fn create_state_home(parent: &Path, name: &str) -> PathBuf {
    let path = parent.join(name);
    fs::create_dir(&path).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
    path
}

fn engine(state_home: &Path, access: StoreAccess) -> Engine {
    Engine::new(
        EngineConfig::from_state_home(state_home, access).unwrap(),
        malm::EnginePorts::system(),
    )
}

fn create_v1_root(state_home: &Path) -> PathBuf {
    let root = state_home.join("malm");
    fs::create_dir(&root).unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    root
}

fn write_marker(root: &Path, bytes: &[u8]) -> PathBuf {
    let marker = root.join("descriptor.json");
    fs::write(&marker, bytes).unwrap();
    fs::set_permissions(&marker, fs::Permissions::from_mode(0o600)).unwrap();
    marker
}

#[test]
fn explicit_xdg_inputs_resolve_the_one_production_root() {
    let temp = tempfile::tempdir().unwrap();
    let home = temp.path().join("home");
    let xdg = temp.path().join("xdg-state");

    let fallback = EngineConfig::new(
        resolve_root(Some(&home), None).unwrap(),
        StoreAccess::ReadOnly,
    )
    .unwrap();
    assert_eq!(fallback.state_root(), home.join(".local/state/malm"));

    let configured = EngineConfig::new(
        resolve_root(Some(&home), Some(&xdg)).unwrap(),
        StoreAccess::ReadOnly,
    )
    .unwrap();
    assert_eq!(configured.state_root(), xdg.join("malm"));

    assert!(matches!(
        resolve_root(Some(&home), Some(Path::new("relative"))),
        Err(RootPathError::XdgStateHomeNotAbsolute { .. })
    ));
}

#[test]
fn two_engines_are_isolated_and_initialization_is_idempotent() {
    let temp = tempfile::tempdir().unwrap();
    let first_home = create_state_home(temp.path(), "first");
    let second_home = create_state_home(temp.path(), "second");
    let first = engine(&first_home, StoreAccess::ReadWrite);
    let second = engine(&second_home, StoreAccess::ReadWrite);

    assert_eq!(first.store_status().unwrap(), StoreStatus::Absent);
    assert_eq!(second.store_status().unwrap(), StoreStatus::Absent);
    assert_eq!(
        first.initialize_store().unwrap().status(),
        StoreStatus::Ready
    );
    assert_eq!(first.store_status().unwrap(), StoreStatus::Ready);
    assert_eq!(second.store_status().unwrap(), StoreStatus::Absent);
    let marker = first_home.join("malm/descriptor.json");
    let marker_before = fs::metadata(&marker).unwrap();
    assert_eq!(
        first.initialize_store().unwrap().status(),
        StoreStatus::Ready
    );
    assert!(!second_home.join("malm").exists());
    let marker_after = fs::metadata(&marker).unwrap();

    let mode = fs::metadata(first_home.join("malm")).unwrap().mode() & 0o7777;
    assert_eq!(mode, 0o700);
    assert_eq!(marker_before.ino(), marker_after.ino());
    assert_eq!(marker_before.dev(), marker_after.dev());
    assert_eq!(marker_after.mode() & 0o7777, 0o600);
    assert_eq!(
        fs::read(marker).unwrap(),
        b"{\"format\":\"malm-state\",\"version\":1}\n"
    );
}

#[test]
fn empty_existing_root_is_uninitialized_then_becomes_ready() {
    let temp = tempfile::tempdir().unwrap();
    let state_home = create_state_home(temp.path(), "state");
    let state_root = create_v1_root(&state_home);
    let engine = engine(&state_home, StoreAccess::ReadWrite);

    assert_eq!(engine.store_status().unwrap(), StoreStatus::Uninitialized);
    assert_eq!(
        engine.initialize_store().unwrap().status(),
        StoreStatus::Ready
    );
    assert_eq!(engine.store_status().unwrap(), StoreStatus::Ready);
    assert_eq!(
        fs::read(state_root.join("descriptor.json")).unwrap(),
        b"{\"format\":\"malm-state\",\"version\":1}\n"
    );
}

#[test]
fn markerless_content_is_never_blessed_as_a_v1_store() {
    let temp = tempfile::tempdir().unwrap();
    let state_home = create_state_home(temp.path(), "state");
    let state_root = create_v1_root(&state_home);
    let legacy_marker = state_root.join("format.json");
    fs::write(&legacy_marker, b"{\"version\":2}\n").unwrap();
    let before = fs::metadata(&legacy_marker).unwrap();
    let engine = engine(&state_home, StoreAccess::ReadWrite);

    for error in [
        engine.store_status().unwrap_err(),
        engine.initialize_store().unwrap_err(),
    ] {
        assert!(matches!(
            error,
            EngineError::MalformedStoreMetadata {
                reason: StoreMetadataIssue::MarkerMissingWithOtherEntries,
                ..
            }
        ));
    }
    let after = fs::metadata(&legacy_marker).unwrap();
    assert_eq!(fs::read(&legacy_marker).unwrap(), b"{\"version\":2}\n");
    assert_unchanged_metadata(&before, &after);
    assert!(!state_root.join("descriptor.json").exists());
}

#[test]
fn descriptor_bearing_roots_reject_every_unknown_top_level_marker_without_writes() {
    let experimental_marker = ["store", ".json"].concat();
    for leaf in ["format.json", experimental_marker.as_str(), "unknown-entry"] {
        let temp = tempfile::tempdir().unwrap();
        let state_home = create_state_home(temp.path(), "state");
        let state_root = create_v1_root(&state_home);
        let descriptor = write_marker(&state_root, b"{\"format\":\"malm-state\",\"version\":1}\n");
        let alien = state_root.join(leaf);
        fs::write(&alien, b"must remain exact\n").unwrap();
        fs::set_permissions(&alien, fs::Permissions::from_mode(0o640)).unwrap();
        let root_before = fs::metadata(&state_root).unwrap();
        let descriptor_before = fs::metadata(&descriptor).unwrap();
        let alien_before = fs::metadata(&alien).unwrap();
        let engine = engine(&state_home, StoreAccess::ReadWrite);

        for error in [
            engine.store_status().unwrap_err(),
            engine.initialize_store().unwrap_err(),
        ] {
            assert!(matches!(
                error,
                EngineError::MalformedStoreMetadata {
                    reason: StoreMetadataIssue::UnexpectedRootEntry,
                    ..
                }
            ));
        }
        assert_unchanged_metadata(&root_before, &fs::metadata(&state_root).unwrap());
        assert_unchanged_metadata(&descriptor_before, &fs::metadata(&descriptor).unwrap());
        assert_unchanged_metadata(&alien_before, &fs::metadata(&alien).unwrap());
        assert_eq!(fs::read(&alien).unwrap(), b"must remain exact\n");
        assert!(!state_root.join("transaction.lock").exists());
        assert!(!state_root.join("maintenance.lock").exists());
        assert!(!state_root.join("state").exists());
    }
}

#[test]
fn descriptor_bearing_root_rejects_unknown_directories_and_allowed_leaf_metadata() {
    for (leaf, directory, mode) in [
        ("unknown-directory", true, 0o700),
        ("objects", false, 0o600),
        ("state", true, 0o755),
        ("transaction.lock", false, 0o600),
    ] {
        let temp = tempfile::tempdir().unwrap();
        let state_home = create_state_home(temp.path(), "state");
        let state_root = create_v1_root(&state_home);
        write_marker(&state_root, b"{\"format\":\"malm-state\",\"version\":1}\n");
        let entry = state_root.join(leaf);
        if directory {
            fs::create_dir(&entry).unwrap();
        } else {
            fs::write(&entry, b"nonempty").unwrap();
        }
        fs::set_permissions(&entry, fs::Permissions::from_mode(mode)).unwrap();
        let root_before = fs::metadata(&state_root).unwrap();
        let entry_before = fs::metadata(&entry).unwrap();
        let engine = engine(&state_home, StoreAccess::ReadWrite);

        let error = engine.initialize_store().unwrap_err();
        assert!(matches!(
            error,
            EngineError::MalformedStoreMetadata {
                reason: StoreMetadataIssue::UnexpectedRootEntry
                    | StoreMetadataIssue::InvalidRootEntry { .. },
                ..
            }
        ));
        assert_unchanged_metadata(&root_before, &fs::metadata(&state_root).unwrap());
        assert_unchanged_metadata(&entry_before, &fs::metadata(&entry).unwrap());
        assert!(!state_root.join("maintenance.lock").exists());
        assert!(!state_root.join("state/catalog.json").exists());
    }
}

#[test]
fn missing_catalog_in_nonempty_state_is_rejected_before_lock_creation_unchanged() {
    let temp = tempfile::tempdir().unwrap();
    let state_home = create_state_home(temp.path(), "state");
    let state_root = create_v1_root(&state_home);
    let descriptor = write_marker(&state_root, b"{\"format\":\"malm-state\",\"version\":1}\n");
    let state = state_root.join("state");
    fs::create_dir(&state).unwrap();
    fs::set_permissions(&state, fs::Permissions::from_mode(0o700)).unwrap();
    let sentinel = state.join("sentinel");
    fs::write(&sentinel, b"preserve exactly\n").unwrap();
    fs::set_permissions(&sentinel, fs::Permissions::from_mode(0o400)).unwrap();
    let sentinel_bytes = fs::read(&sentinel).unwrap();
    let root_before = fs::metadata(&state_root).unwrap();
    let descriptor_before = fs::metadata(&descriptor).unwrap();
    let state_before = fs::metadata(&state).unwrap();
    let sentinel_before = fs::metadata(&sentinel).unwrap();

    assert!(
        engine(&state_home, StoreAccess::ReadWrite)
            .initialize_store()
            .is_err()
    );

    assert_unchanged_metadata(&root_before, &fs::metadata(&state_root).unwrap());
    assert_unchanged_metadata(&descriptor_before, &fs::metadata(&descriptor).unwrap());
    assert_unchanged_metadata(&state_before, &fs::metadata(&state).unwrap());
    assert_unchanged_metadata(&sentinel_before, &fs::metadata(&sentinel).unwrap());
    assert_eq!(fs::read(&sentinel).unwrap(), sentinel_bytes);
    assert!(!state_root.join("transaction.lock").exists());
    assert!(!state.join("catalog.json").exists());
}

#[test]
fn commit_admission_rejects_unknown_root_content_before_locking() {
    let temp = tempfile::tempdir().unwrap();
    let state_home = create_state_home(temp.path(), "state");
    let engine = engine(&state_home, StoreAccess::ReadWrite);
    engine.initialize_store().unwrap();
    let state_root = engine.config().state_root();
    fs::remove_file(state_root.join("transaction.lock")).unwrap();
    let alien = state_root.join("unknown-entry");
    fs::write(&alien, b"preserve\n").unwrap();
    let before = fs::metadata(&alien).unwrap();

    assert!(matches!(
        engine.inspect_state_v1(&NamespaceName::new("test").unwrap()),
        Err(CommitError::InvalidStore(reason))
            if reason.contains("unrecognized top-level entry")
    ));
    assert_unchanged_metadata(&before, &fs::metadata(&alien).unwrap());
    assert_eq!(fs::read(alien).unwrap(), b"preserve\n");
    assert!(!state_root.join("transaction.lock").exists());
}

#[test]
fn malformed_and_unsupported_descriptors_are_not_repaired() {
    for (name, bytes, unsupported) in [
        (
            "malformed",
            b"{\"format\":\"malm-state\",\"version\":1,\"extra\":true}\n".as_slice(),
            false,
        ),
        (
            "unsupported",
            b"{\"format\":\"malm-state\",\"version\":2}\n".as_slice(),
            true,
        ),
    ] {
        let temp = tempfile::tempdir().unwrap();
        let state_home = create_state_home(temp.path(), name);
        let state_root = create_v1_root(&state_home);
        let marker = write_marker(&state_root, bytes);
        let before = fs::metadata(&marker).unwrap();
        let engine = engine(&state_home, StoreAccess::ReadWrite);

        let status_error = engine.store_status().unwrap_err();
        let init_error = engine.initialize_store().unwrap_err();
        if unsupported {
            assert!(matches!(
                status_error,
                EngineError::UnsupportedStoreVersion {
                    expected: 1,
                    found: 2,
                    ..
                }
            ));
            assert!(matches!(
                init_error,
                EngineError::UnsupportedStoreVersion {
                    expected: 1,
                    found: 2,
                    ..
                }
            ));
        } else {
            assert!(matches!(
                status_error,
                EngineError::MalformedStoreMetadata { .. }
            ));
            assert!(matches!(
                init_error,
                EngineError::MalformedStoreMetadata { .. }
            ));
        }
        assert_eq!(fs::read(&marker).unwrap(), bytes);
        assert_unchanged_except_atime(&before, &fs::metadata(&marker).unwrap());
    }
}

#[test]
fn unsafe_descriptor_objects_fail_without_following_or_replacing_them() {
    let temp = tempfile::tempdir().unwrap();
    let state_home = create_state_home(temp.path(), "state");
    let state_root = create_v1_root(&state_home);
    let outside = temp.path().join("outside");
    fs::write(&outside, b"protected").unwrap();
    std::os::unix::fs::symlink(&outside, state_root.join("descriptor.json")).unwrap();
    let engine = engine(&state_home, StoreAccess::ReadWrite);

    assert!(matches!(
        engine.initialize_store(),
        Err(EngineError::MalformedStoreMetadata {
            reason: StoreMetadataIssue::MarkerNotRegular,
            ..
        })
    ));
    assert_eq!(fs::read(&outside).unwrap(), b"protected");

    fs::remove_file(state_root.join("descriptor.json")).unwrap();
    let marker = write_marker(&state_root, &vec![b'x'; 4_097]);
    assert!(matches!(
        engine.store_status(),
        Err(EngineError::MalformedStoreMetadata {
            reason: StoreMetadataIssue::MarkerTooLarge { limit: 4_096, .. },
            ..
        })
    ));
    assert_eq!(fs::metadata(marker).unwrap().len(), 4_097);
}

#[test]
fn populated_read_only_experimental_sibling_is_not_modified() {
    let temp = tempfile::tempdir().unwrap();
    let state_home = create_state_home(temp.path(), "state");
    let sibling = state_home.join("malm-v1");
    let sentinel = sibling.join("sentinel");
    fs::create_dir(&sibling).unwrap();
    fs::write(&sentinel, b"legacy-state").unwrap();
    let xattr_supported = xattr::set(&sentinel, "user.malm-test", b"preserve").is_ok();
    fs::set_permissions(&sentinel, fs::Permissions::from_mode(0o400)).unwrap();
    fs::set_permissions(&sibling, fs::Permissions::from_mode(0o500)).unwrap();

    let before_bytes = fs::read(&sentinel).unwrap();
    let before_root = fs::metadata(&sibling).unwrap();
    let before_sentinel = fs::metadata(&sentinel).unwrap();
    let before_xattr = xattr_supported.then(|| xattr::get(&sentinel, "user.malm-test").unwrap());

    let engine = engine(&state_home, StoreAccess::ReadWrite);
    assert_eq!(
        engine.initialize_store().unwrap().status(),
        StoreStatus::Ready
    );

    let after_root = fs::metadata(&sibling).unwrap();
    let after_sentinel = fs::metadata(&sentinel).unwrap();
    assert_eq!(fs::read(&sentinel).unwrap(), before_bytes);
    assert_unchanged_metadata(&before_root, &after_root);
    assert_unchanged_metadata(&before_sentinel, &after_sentinel);
    if let Some(before_xattr) = before_xattr {
        assert_eq!(
            xattr::get(&sentinel, "user.malm-test").unwrap(),
            before_xattr
        );
    }

    fs::set_permissions(&sibling, fs::Permissions::from_mode(0o700)).unwrap();
    fs::set_permissions(&sentinel, fs::Permissions::from_mode(0o600)).unwrap();
}

#[test]
fn read_only_engine_cannot_initialize() {
    let temp = tempfile::tempdir().unwrap();
    let state_home = create_state_home(temp.path(), "state");
    let reader = engine(&state_home, StoreAccess::ReadOnly);

    assert!(matches!(
        reader.initialize_store(),
        Err(EngineError::ReadOnlyStore)
    ));
    assert!(!state_home.join("malm").exists());

    let writer = engine(&state_home, StoreAccess::ReadWrite);
    writer.initialize_store().unwrap();
    let marker = state_home.join("malm/descriptor.json");
    let before = fs::metadata(&marker).unwrap();
    assert_eq!(reader.store_status().unwrap(), StoreStatus::Ready);
    assert!(matches!(
        reader.initialize_store(),
        Err(EngineError::ReadOnlyStore)
    ));
    assert_unchanged_except_atime(&before, &fs::metadata(marker).unwrap());
}

#[test]
fn target_authority_rejects_state_and_descendants_but_allows_a_strict_ancestor() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("root");
    let nested = root.join("nested");
    let authority = DeploymentName::new("target").unwrap();

    for target in [&root, &nested] {
        let result = EngineConfig::new(&root, StoreAccess::ReadOnly)
            .unwrap()
            .with_target_authority(authority.clone(), target);
        assert!(matches!(
            result,
            Err(EngineConfigError::TargetOverlapsState { .. })
        ));
    }

    let ancestor = temp.path().to_path_buf();
    let config = EngineConfig::new(&root, StoreAccess::ReadOnly)
        .unwrap()
        .with_target_authority(authority.clone(), &ancestor)
        .unwrap();
    assert_eq!(config.target_root(&authority), Some(ancestor.as_path()));
}

#[test]
fn root_and_intermediate_symlinks_are_rejected_without_following_them() {
    let temp = tempfile::tempdir().unwrap();
    let state_home = create_state_home(temp.path(), "state");
    let outside = temp.path().join("outside");
    fs::create_dir(&outside).unwrap();
    fs::write(outside.join("sentinel"), b"protected").unwrap();
    std::os::unix::fs::symlink(&outside, state_home.join("malm")).unwrap();

    let direct = engine(&state_home, StoreAccess::ReadWrite);
    assert!(direct.store_status().is_err());
    assert!(direct.initialize_store().is_err());
    assert_eq!(fs::read(outside.join("sentinel")).unwrap(), b"protected");

    fs::remove_file(state_home.join("malm")).unwrap();
    let state_alias = temp.path().join("state-alias");
    std::os::unix::fs::symlink(&state_home, &state_alias).unwrap();
    let intermediate = engine(&state_alias, StoreAccess::ReadWrite);
    assert!(intermediate.initialize_store().is_err());
    assert!(!state_home.join("malm").exists());
}

#[test]
fn execute_only_ancestor_supports_descriptor_pinning() {
    let temp = tempfile::tempdir().unwrap();
    let search_only = create_state_home(temp.path(), "search-only");
    let state_home = create_state_home(&search_only, "state");
    fs::set_permissions(&search_only, fs::Permissions::from_mode(0o111)).unwrap();
    let engine = engine(&state_home, StoreAccess::ReadWrite);

    assert_eq!(engine.store_status().unwrap(), StoreStatus::Absent);
    assert_eq!(
        engine.initialize_store().unwrap().status(),
        StoreStatus::Ready
    );

    fs::set_permissions(&search_only, fs::Permissions::from_mode(0o700)).unwrap();
}

#[test]
fn unsafe_existing_permissions_are_reported_without_chmod() {
    let temp = tempfile::tempdir().unwrap();
    let state_home = create_state_home(temp.path(), "state");
    let state_root = state_home.join("malm");
    fs::create_dir(&state_root).unwrap();
    fs::set_permissions(&state_root, fs::Permissions::from_mode(0o755)).unwrap();
    let engine = engine(&state_home, StoreAccess::ReadWrite);

    let error = engine.store_status().unwrap_err();
    assert!(matches!(
        error,
        EngineError::UnsafeDirectory {
            directory: StateDirectory::V1Root,
            ..
        }
    ));
    assert!(engine.initialize_store().is_err());
    assert_eq!(fs::metadata(&state_root).unwrap().mode() & 0o7777, 0o755);
}

#[test]
fn special_mode_bits_are_rejected_on_parent_and_root() {
    let temp = tempfile::tempdir().unwrap();
    let state_home = create_state_home(temp.path(), "state");
    fs::set_permissions(&state_home, fs::Permissions::from_mode(0o2700)).unwrap();
    let engine = engine(&state_home, StoreAccess::ReadWrite);

    let error = engine.initialize_store().unwrap_err();
    assert!(matches!(
        error,
        EngineError::UnsafeDirectory {
            directory: StateDirectory::StateParent,
            reason: DirectorySafetyIssue::SpecialModeBitsSet { mode: 0o2700 },
            ..
        }
    ));
    assert!(!state_home.join("malm").exists());

    fs::set_permissions(&state_home, fs::Permissions::from_mode(0o700)).unwrap();
    let state_root = state_home.join("malm");
    fs::create_dir(&state_root).unwrap();
    fs::set_permissions(&state_root, fs::Permissions::from_mode(0o2700)).unwrap();
    let error = engine.store_status().unwrap_err();
    assert!(matches!(
        error,
        EngineError::UnsafeDirectory {
            directory: StateDirectory::V1Root,
            reason: DirectorySafetyIssue::UnexpectedMode {
                expected: 0o700,
                actual: 0o2700,
            },
            ..
        }
    ));
    fs::set_permissions(&state_root, fs::Permissions::from_mode(0o700)).unwrap();
}

#[test]
fn writable_state_parent_is_rejected_before_creation() {
    let temp = tempfile::tempdir().unwrap();
    let state_home = create_state_home(temp.path(), "state");
    fs::set_permissions(&state_home, fs::Permissions::from_mode(0o770)).unwrap();
    let engine = engine(&state_home, StoreAccess::ReadWrite);

    let error = engine.initialize_store().unwrap_err();
    assert!(matches!(
        error,
        EngineError::UnsafeDirectory {
            directory: StateDirectory::StateParent,
            ..
        }
    ));
    assert!(!state_home.join("malm").exists());
    fs::set_permissions(&state_home, fs::Permissions::from_mode(0o700)).unwrap();
}

#[test]
fn concurrent_initialization_creates_one_root() {
    let temp = tempfile::tempdir().unwrap();
    let state_home = create_state_home(temp.path(), "state");
    let engine = Arc::new(engine(&state_home, StoreAccess::ReadWrite));
    let barrier = Arc::new(Barrier::new(16));
    let mut workers = Vec::new();

    for _ in 0..16 {
        let engine = Arc::clone(&engine);
        let barrier = Arc::clone(&barrier);
        workers.push(thread::spawn(move || {
            barrier.wait();
            engine.initialize_store()
        }));
    }

    let outcomes: Vec<_> = workers
        .into_iter()
        .map(|worker| worker.join().unwrap().unwrap())
        .collect();
    assert!(
        outcomes
            .iter()
            .all(|outcome| outcome.status() == StoreStatus::Ready)
    );
    assert_eq!(engine.store_status().unwrap(), StoreStatus::Ready);
    assert_eq!(
        fs::read(state_home.join("malm/descriptor.json")).unwrap(),
        b"{\"format\":\"malm-state\",\"version\":1}\n"
    );
}

#[test]
fn restrictive_umask_fails_closed_and_can_be_recovered() {
    const CHILD_ENV: &str = "MALM_ENGINE_UMASK_TEST_CHILD";
    if std::env::var_os(CHILD_ENV).is_none() {
        let output = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "restrictive_umask_fails_closed_and_can_be_recovered",
                "--nocapture",
            ])
            .env(CHILD_ENV, "1")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "child test failed:\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    }

    let temp = tempfile::tempdir().unwrap();
    let state_home = create_state_home(temp.path(), "state");
    let engine = engine(&state_home, StoreAccess::ReadWrite);
    let state_root = state_home.join("malm");
    let previous_umask = rustix::process::umask(Mode::from_raw_mode(0o777));

    let error = engine.initialize_store().unwrap_err();
    assert!(matches!(
        error,
        EngineError::UnsafeDirectory {
            directory: StateDirectory::V1Root,
            reason: DirectorySafetyIssue::UnexpectedMode {
                expected: 0o700,
                actual: 0,
            },
            ..
        }
    ));
    assert!(!state_root.exists());
    assert!(fs::read_dir(&state_home).unwrap().all(|entry| {
        !entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .contains(".init-")
    }));
    rustix::process::umask(previous_umask);
    assert_eq!(
        engine.initialize_store().unwrap().status(),
        StoreStatus::Ready
    );
}

fn assert_unchanged_metadata(before: &fs::Metadata, after: &fs::Metadata) {
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

fn assert_unchanged_except_atime(before: &fs::Metadata, after: &fs::Metadata) {
    assert_eq!(before.dev(), after.dev());
    assert_eq!(before.ino(), after.ino());
    assert_eq!(before.mode(), after.mode());
    assert_eq!(before.nlink(), after.nlink());
    assert_eq!(before.uid(), after.uid());
    assert_eq!(before.gid(), after.gid());
    assert_eq!(before.size(), after.size());
    assert_eq!(before.mtime(), after.mtime());
    assert_eq!(before.mtime_nsec(), after.mtime_nsec());
    assert_eq!(before.ctime(), after.ctime());
    assert_eq!(before.ctime_nsec(), after.ctime_nsec());
}
