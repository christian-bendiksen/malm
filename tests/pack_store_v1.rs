use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Barrier};
use std::thread;

use malm::{
    Engine, EngineConfig, EngineError, PackObjectIssue, PackObjectPublication, StoreAccess,
    StoreStatus,
};
use malm_pack::{
    LockV1, LockedPackV1, LockedSourceV1, PACK_MANIFEST_FILE, PackFileV1, PackPath, decode_pack_v1,
    lock_graph_digest, pack_content_digest, write_pack_object_v1,
};
use malm_types::Digest;

const MINIMAL_PACK: &[u8] = include_bytes!("../schemas/pack/v1/fixtures/valid/minimal.kdl");

fn create_state_home(parent: &Path) -> PathBuf {
    let state_home = parent.join("state");
    fs::create_dir(&state_home).unwrap();
    fs::set_permissions(&state_home, fs::Permissions::from_mode(0o700)).unwrap();
    state_home
}

fn engine(state_home: &Path, access: StoreAccess) -> Engine {
    Engine::new(
        EngineConfig::from_state_home(state_home, access).unwrap(),
        malm::EnginePorts::system(),
    )
}

fn initialized_engine(state_home: &Path) -> Engine {
    let engine = engine(state_home, StoreAccess::ReadWrite);
    assert_eq!(
        engine.initialize_store().unwrap().status(),
        StoreStatus::Ready
    );
    engine
}

fn pack_fixture() -> (Digest, Vec<PackFileV1>) {
    let files = vec![PackFileV1::new(
        PackPath::new(PACK_MANIFEST_FILE).unwrap(),
        MINIMAL_PACK,
    )];
    let digest = pack_content_digest(files.iter().map(|file| (file.path(), file.bytes()))).unwrap();
    (digest, files)
}

fn object_path(state_home: &Path, digest: &Digest) -> PathBuf {
    state_home
        .join("malm/objects/pack-manifests")
        .join(digest.as_str())
}

fn create_object_containers(state_home: &Path) {
    let objects = state_home.join("malm/objects");
    fs::create_dir(&objects).unwrap();
    fs::set_permissions(&objects, fs::Permissions::from_mode(0o700)).unwrap();
    for area in ["packs", "pack-manifests"] {
        let directory = objects.join(area);
        fs::create_dir(&directory).unwrap();
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
    }
}

#[test]
fn published_objects_are_reused_read_only_and_assembled_offline() {
    let temp = tempfile::tempdir().unwrap();
    let state_home = create_state_home(temp.path());
    let experimental = state_home.join("malm-v1");
    fs::create_dir(&experimental).unwrap();
    fs::set_permissions(&experimental, fs::Permissions::from_mode(0o700)).unwrap();
    let experimental_sentinel = experimental.join("sentinel");
    fs::write(&experimental_sentinel, b"experimental state").unwrap();
    let experimental_before = fs::metadata(&experimental_sentinel).unwrap();

    let writer = initialized_engine(&state_home);
    let (digest, files) = pack_fixture();
    assert_eq!(
        writer.publish_pack_object_v1(&digest, &files).unwrap(),
        PackObjectPublication::Published
    );

    let path = object_path(&state_home, &digest);
    let stored_bytes = fs::read(&path).unwrap();
    let stored = fs::metadata(&path).unwrap();
    // A deduplicated pack is stored as a manifest named by its logical content
    // digest. Loading it below verifies reassembly.
    assert!(stored_bytes.starts_with(b"malm-pack-manifest-object-v1\0"));
    assert_eq!(stored.mode() & 0o7777, 0o400);
    assert_eq!(stored.nlink(), 1);
    assert_eq!(
        fs::metadata(state_home.join("malm/objects"))
            .unwrap()
            .mode()
            & 0o7777,
        0o700
    );
    assert_eq!(
        fs::metadata(state_home.join("malm/objects/pack-manifests"))
            .unwrap()
            .mode()
            & 0o7777,
        0o700
    );
    assert_eq!(writer.load_pack_object_v1(&digest).unwrap(), files);
    assert_eq!(
        writer.publish_pack_object_v1(&digest, &files).unwrap(),
        PackObjectPublication::Reused
    );

    let manifest = decode_pack_v1(MINIMAL_PACK).unwrap();
    let root = LockedPackV1::new(
        manifest.package_id().clone(),
        LockedSourceV1::Root,
        digest.clone(),
        vec![],
        vec![],
    )
    .unwrap();
    let root_id = root.node_id().clone();
    let lock = LockV1::new(root_id.clone(), vec![root]).unwrap();

    let reader = engine(&state_home, StoreAccess::ReadOnly);
    assert_eq!(reader.load_pack_object_v1(&digest).unwrap(), files);
    assert!(matches!(
        reader.publish_pack_object_v1(&digest, &files),
        Err(EngineError::ReadOnlyStore)
    ));
    let graph = reader.assemble_cached_pack_graph_v1(&lock).unwrap();
    assert_eq!(graph.root_node_id(), &root_id);
    assert_eq!(graph.graph_digest(), &lock_graph_digest(&lock));
    assert_eq!(graph.lock(), &lock);
    assert_eq!(graph.dependency_order(), std::slice::from_ref(&root_id));
    let verified = graph.pack(&root_id).unwrap();
    assert_eq!(verified.content_digest(), &digest);
    assert_eq!(verified.manifest(), &manifest);
    assert_eq!(
        verified.file(&PackPath::new(PACK_MANIFEST_FILE).unwrap()),
        Some(MINIMAL_PACK)
    );

    assert_eq!(
        fs::read(&experimental_sentinel).unwrap(),
        b"experimental state"
    );
    let experimental_after = fs::metadata(&experimental_sentinel).unwrap();
    assert_eq!(experimental_before.dev(), experimental_after.dev());
    assert_eq!(experimental_before.ino(), experimental_after.ino());
    assert_eq!(experimental_before.mode(), experimental_after.mode());
    assert_eq!(experimental_before.nlink(), experimental_after.nlink());
    assert_eq!(experimental_before.size(), experimental_after.size());
    assert_eq!(experimental_before.mtime(), experimental_after.mtime());
    assert_eq!(
        experimental_before.mtime_nsec(),
        experimental_after.mtime_nsec()
    );
}

#[test]
fn unsafe_or_corrupt_objects_are_preserved_and_rejected() {
    let temp = tempfile::tempdir().unwrap();
    let state_home = create_state_home(temp.path());
    let engine = initialized_engine(&state_home);
    let (digest, files) = pack_fixture();
    create_object_containers(&state_home);
    let path = object_path(&state_home, &digest);

    let outside = temp.path().join("outside-object");
    fs::write(&outside, b"protected").unwrap();
    std::os::unix::fs::symlink(&outside, &path).unwrap();
    assert!(matches!(
        engine.load_pack_object_v1(&digest),
        Err(EngineError::PackObject {
            reason: PackObjectIssue::ObjectNotRegular,
            ..
        })
    ));
    assert_eq!(fs::read(&outside).unwrap(), b"protected");
    fs::remove_file(&path).unwrap();

    let mut canonical = Vec::new();
    assert_eq!(
        write_pack_object_v1(&files, &mut canonical).unwrap(),
        digest
    );
    fs::write(&outside, &canonical).unwrap();
    fs::set_permissions(&outside, fs::Permissions::from_mode(0o400)).unwrap();
    fs::hard_link(&outside, &path).unwrap();
    assert!(matches!(
        engine.load_pack_object_v1(&digest),
        Err(EngineError::PackObject {
            reason: PackObjectIssue::UnexpectedLinks {
                expected: 1,
                actual: 2
            },
            ..
        })
    ));
    assert_eq!(fs::read(&outside).unwrap(), canonical);
    fs::remove_file(&path).unwrap();

    fs::write(&path, b"corrupt object").unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o400)).unwrap();
    assert!(matches!(
        engine.publish_pack_object_v1(&digest, &files),
        Err(EngineError::PackObject {
            reason: PackObjectIssue::InvalidEncoding { .. },
            ..
        })
    ));
    assert_eq!(fs::read(&path).unwrap(), b"corrupt object");
    fs::remove_file(&path).unwrap();

    fs::remove_dir(state_home.join("malm/objects/pack-manifests")).unwrap();
    let outside_directory = temp.path().join("outside-packs");
    fs::create_dir(&outside_directory).unwrap();
    fs::write(outside_directory.join("sentinel"), b"outside").unwrap();
    std::os::unix::fs::symlink(
        &outside_directory,
        state_home.join("malm/objects/pack-manifests"),
    )
    .unwrap();
    assert!(matches!(
        engine.load_pack_object_v1(&digest),
        Err(EngineError::PackObject {
            reason: PackObjectIssue::ContainerNotDirectory,
            ..
        })
    ));
    assert_eq!(
        fs::read(outside_directory.join("sentinel")).unwrap(),
        b"outside"
    );
}

#[test]
fn concurrent_publication_has_one_winner_and_verified_reusers() {
    let temp = tempfile::tempdir().unwrap();
    let state_home = create_state_home(temp.path());
    let engine = Arc::new(initialized_engine(&state_home));
    let (digest, files) = pack_fixture();
    let barrier = Arc::new(Barrier::new(12));
    let mut workers = Vec::new();

    for _ in 0..12 {
        let engine = Arc::clone(&engine);
        let barrier = Arc::clone(&barrier);
        let digest = digest.clone();
        let files = files.clone();
        workers.push(thread::spawn(move || {
            barrier.wait();
            engine.publish_pack_object_v1(&digest, &files)
        }));
    }

    let outcomes = workers
        .into_iter()
        .map(|worker| worker.join().unwrap().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| **outcome == PackObjectPublication::Published)
            .count(),
        1
    );
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| **outcome == PackObjectPublication::Reused)
            .count(),
        11
    );
    assert_eq!(engine.load_pack_object_v1(&digest).unwrap(), files);
}

#[test]
fn missing_and_uninitialized_objects_fail_without_creating_state() {
    let temp = tempfile::tempdir().unwrap();
    let state_home = create_state_home(temp.path());
    let (digest, _) = pack_fixture();
    let absent = engine(&state_home, StoreAccess::ReadOnly);
    assert!(matches!(
        absent.load_pack_object_v1(&digest),
        Err(EngineError::StoreNotReady {
            status: StoreStatus::Absent
        })
    ));
    assert!(!state_home.join("malm").exists());

    let initialized = initialized_engine(&state_home);
    assert!(matches!(
        initialized.load_pack_object_v1(&digest),
        Err(EngineError::PackObject {
            reason: PackObjectIssue::Missing,
            ..
        })
    ));
    assert!(!state_home.join("malm/objects").exists());
}
