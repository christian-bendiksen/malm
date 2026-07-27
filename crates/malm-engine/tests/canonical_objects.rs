use std::{
    fs,
    io::Cursor,
    os::unix::fs::{MetadataExt, PermissionsExt},
};

use malm_engine::{
    ArchiveDeclarationV1, ArchiveDecodeError, ArchiveLimitsV1, ArchivePublicationError,
    CanonicalObjectIssue, CanonicalObjectKind, CanonicalObjectPublication,
    CanonicalTreeInspectionRequestV1, Engine, EngineConfig, EngineError, EnginePorts, StoreAccess,
    SymlinkObjectV1, TreeObjectV1,
};
use malm_tree::{
    MAX_TREE_DEPTH, TreeEntryV1, TreePathSegmentV1, encode_symlink_object_v1,
    file_object_digest_v1, symlink_object_digest_v1, tree_object_digest_v1,
};
use malm_types::Digest;

fn initialized_engine(temp: &tempfile::TempDir) -> Engine {
    let state_home = temp.path().join("state");
    fs::create_dir(&state_home).unwrap();
    fs::set_permissions(&state_home, fs::Permissions::from_mode(0o700)).unwrap();
    let engine = Engine::new(
        EngineConfig::from_state_home(&state_home, StoreAccess::ReadWrite).unwrap(),
        EnginePorts::system(),
    );
    engine.initialize_store().unwrap();
    engine
}

fn segment(value: &str) -> TreePathSegmentV1 {
    TreePathSegmentV1::new(value).unwrap()
}

fn object_path(engine: &Engine, directory: &str, digest: &Digest) -> std::path::PathBuf {
    engine
        .config()
        .state_root()
        .join("objects")
        .join(directory)
        .join(digest.as_str())
}

#[test]
fn canonical_objects_round_trip_idempotently_with_private_exact_metadata() {
    let temp = tempfile::tempdir().unwrap();
    let engine = initialized_engine(&temp);
    let contents = b"regular file contents";
    let file_digest = file_object_digest_v1(contents).unwrap();
    let symlink = SymlinkObjectV1::new("file.txt").unwrap();
    let symlink_digest = symlink_object_digest_v1(&symlink);
    let tree = TreeObjectV1::new(
        0o755,
        vec![
            TreeEntryV1::file(
                segment("file.txt"),
                0o644,
                file_digest.clone(),
                contents.len() as u64,
            )
            .unwrap(),
            TreeEntryV1::safe_relative_symlink(segment("current"), symlink_digest.clone()),
        ],
    )
    .unwrap();
    let tree_digest = tree_object_digest_v1(&tree);

    assert_eq!(
        engine
            .publish_file_object_v1(&file_digest, contents)
            .unwrap(),
        CanonicalObjectPublication::Published
    );
    assert_eq!(
        engine
            .publish_symlink_object_v1(&symlink_digest, &symlink)
            .unwrap(),
        CanonicalObjectPublication::Published
    );
    assert_eq!(
        engine.publish_tree_object_v1(&tree_digest, &tree).unwrap(),
        CanonicalObjectPublication::Published
    );
    assert_eq!(engine.load_file_object_v1(&file_digest).unwrap(), contents);
    assert_eq!(
        engine.load_symlink_object_v1(&symlink_digest).unwrap(),
        symlink
    );
    assert_eq!(engine.load_tree_object_v1(&tree_digest).unwrap(), tree);

    assert_eq!(
        engine
            .publish_file_object_v1(&file_digest, contents)
            .unwrap(),
        CanonicalObjectPublication::Reused
    );
    assert_eq!(
        engine
            .publish_symlink_object_v1(&symlink_digest, &symlink)
            .unwrap(),
        CanonicalObjectPublication::Reused
    );
    assert_eq!(
        engine.publish_tree_object_v1(&tree_digest, &tree).unwrap(),
        CanonicalObjectPublication::Reused
    );

    let expected_uid = engine.process_facts().effective_user_id();
    for directory in [
        "objects",
        "objects/files",
        "objects/symlinks",
        "objects/trees",
    ] {
        let metadata = fs::metadata(engine.config().state_root().join(directory)).unwrap();
        assert_eq!(metadata.mode() & 0o7777, 0o700);
        assert_eq!(metadata.uid(), expected_uid);
    }
    for path in [
        object_path(&engine, "files", &file_digest),
        object_path(&engine, "symlinks", &symlink_digest),
        object_path(&engine, "trees", &tree_digest),
    ] {
        let metadata = fs::metadata(path).unwrap();
        assert_eq!(metadata.mode() & 0o7777, 0o400);
        assert_eq!(metadata.nlink(), 1);
        assert_eq!(metadata.uid(), expected_uid);
    }
    let stored_file = fs::read(object_path(&engine, "files", &file_digest)).unwrap();
    assert_ne!(stored_file, contents);
    assert!(stored_file.starts_with(b"malm-file-object\0"));
    assert_eq!(Digest::sha256(stored_file), file_digest);
}

#[test]
fn canonical_tree_inspection_expands_shared_subtrees_and_enforces_depth() {
    let temp = tempfile::tempdir().unwrap();
    let engine = initialized_engine(&temp);
    let contents = b"shared\n";
    let file_digest = file_object_digest_v1(contents).unwrap();
    engine
        .publish_file_object_v1(&file_digest, contents)
        .unwrap();
    let child = TreeObjectV1::new(
        0o755,
        vec![
            TreeEntryV1::file(segment("value"), 0o644, file_digest, contents.len() as u64).unwrap(),
        ],
    )
    .unwrap();
    let child_digest = tree_object_digest_v1(&child);
    engine
        .publish_tree_object_v1(&child_digest, &child)
        .unwrap();
    let root = TreeObjectV1::new(
        0o755,
        vec![
            TreeEntryV1::directory(segment("a"), 0o755, child_digest.clone()).unwrap(),
            TreeEntryV1::directory(segment("b"), 0o755, child_digest).unwrap(),
        ],
    )
    .unwrap();
    let root_digest = tree_object_digest_v1(&root);
    engine.publish_tree_object_v1(&root_digest, &root).unwrap();

    let inspection = engine
        .inspect_canonical_tree_v1(&CanonicalTreeInspectionRequestV1::new(root_digest))
        .unwrap();
    assert_eq!(
        inspection
            .entries()
            .iter()
            .map(|entry| entry.relative_path())
            .collect::<Vec<_>>(),
        ["a", "a/value", "b", "b/value"]
    );

    let leaf = TreeObjectV1::new(0o755, vec![]).unwrap();
    let mut deep = tree_object_digest_v1(&leaf);
    engine.publish_tree_object_v1(&deep, &leaf).unwrap();
    for _ in 0..=MAX_TREE_DEPTH {
        let parent = TreeObjectV1::new(
            0o755,
            vec![TreeEntryV1::directory(segment("child"), 0o755, deep).unwrap()],
        )
        .unwrap();
        deep = tree_object_digest_v1(&parent);
        engine.publish_tree_object_v1(&deep, &parent).unwrap();
    }
    let error = engine
        .inspect_canonical_tree_v1(&CanonicalTreeInspectionRequestV1::new(deep))
        .unwrap_err();
    assert!(error.to_string().contains("depth"));
}

#[test]
fn object_and_container_metadata_tampering_is_rejected_without_repair() {
    let temp = tempfile::tempdir().unwrap();
    let engine = initialized_engine(&temp);
    let contents = b"metadata fixture";
    let digest = file_object_digest_v1(contents).unwrap();
    engine.publish_file_object_v1(&digest, contents).unwrap();
    let path = object_path(&engine, "files", &digest);

    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(matches!(
        engine.load_file_object_v1(&digest),
        Err(EngineError::CanonicalObject {
            kind: CanonicalObjectKind::File,
            reason: CanonicalObjectIssue::UnexpectedMode {
                expected: 0o400,
                actual: 0o600,
            },
            ..
        })
    ));
    assert_eq!(fs::metadata(&path).unwrap().mode() & 0o7777, 0o600);

    fs::set_permissions(&path, fs::Permissions::from_mode(0o400)).unwrap();
    let alias = engine.config().state_root().join("state/object-alias");
    fs::hard_link(&path, &alias).unwrap();
    assert!(matches!(
        engine.load_file_object_v1(&digest),
        Err(EngineError::CanonicalObject {
            reason: CanonicalObjectIssue::UnexpectedLinks {
                expected: 1,
                actual: 2,
            },
            ..
        })
    ));
    assert!(alias.exists());

    fs::remove_file(alias).unwrap();
    let files = engine.config().state_root().join("objects/files");
    fs::set_permissions(&files, fs::Permissions::from_mode(0o755)).unwrap();
    assert!(matches!(
        engine.load_file_object_v1(&digest),
        Err(EngineError::CanonicalObject {
            reason: CanonicalObjectIssue::UnexpectedMode {
                expected: 0o700,
                actual: 0o755,
            },
            ..
        })
    ));
    assert_eq!(fs::metadata(files).unwrap().mode() & 0o7777, 0o755);
}

#[test]
fn matching_digest_from_another_object_domain_is_rejected() {
    let temp = tempfile::tempdir().unwrap();
    let engine = initialized_engine(&temp);
    let symlink = SymlinkObjectV1::new("target").unwrap();
    let digest = symlink_object_digest_v1(&symlink);
    let bytes = encode_symlink_object_v1(&symlink);
    let files = engine.config().state_root().join("objects/files");
    fs::create_dir_all(&files).unwrap();
    fs::set_permissions(
        engine.config().state_root().join("objects"),
        fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    fs::set_permissions(&files, fs::Permissions::from_mode(0o700)).unwrap();
    let path = files.join(digest.as_str());
    fs::write(&path, &bytes).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o400)).unwrap();

    assert_eq!(Digest::sha256(&bytes), digest);
    assert!(matches!(
        engine.load_file_object_v1(&digest),
        Err(EngineError::CanonicalObject {
            kind: CanonicalObjectKind::File,
            reason: CanonicalObjectIssue::InvalidEncoding { .. },
            ..
        })
    ));

    let raw_digest = Digest::sha256(b"raw bytes are not an object identity");
    assert!(matches!(
        engine.publish_file_object_v1(&raw_digest, b"raw bytes are not an object identity"),
        Err(EngineError::CanonicalObject {
            reason: CanonicalObjectIssue::DigestMismatch { .. },
            ..
        })
    ));
}

#[test]
fn malformed_digest_mismatch_and_trailing_archive_inputs_publish_nothing() {
    assert_archive_decode_failure(
        vec![0; 512],
        |bytes| ArchiveDeclarationV1::posix_ustar(bytes.len() as u64, Digest::sha256(bytes)),
        |error| matches!(error, ArchiveDecodeError::MalformedTerminator { .. }),
    );

    assert_archive_decode_failure(
        vec![0; 1024],
        |bytes| {
            ArchiveDeclarationV1::posix_ustar(bytes.len() as u64, Digest::sha256(b"wrong payload"))
        },
        |error| matches!(error, ArchiveDecodeError::PayloadDigestMismatch { .. }),
    );

    assert_archive_decode_failure(
        vec![0; 1025],
        |bytes| ArchiveDeclarationV1::posix_ustar(1024, Digest::sha256(&bytes[..1024])),
        |error| matches!(error, ArchiveDecodeError::TrailingBytes),
    );
}

#[test]
fn verified_archive_publishes_a_loadable_root_tree() {
    let temp = tempfile::tempdir().unwrap();
    let engine = initialized_engine(&temp);
    let payload = vec![0; 1024];
    let declaration =
        ArchiveDeclarationV1::posix_ustar(payload.len() as u64, Digest::sha256(&payload));

    let decoded = engine
        .decode_and_publish_archive_v1(
            Cursor::new(payload.clone()),
            declaration.clone(),
            ArchiveLimitsV1::default(),
        )
        .unwrap();
    let loaded = engine.load_tree_object_v1(decoded.root_digest()).unwrap();
    assert_eq!(&loaded, decoded.tree_graph().root());
    assert!(object_path(&engine, "trees", decoded.root_digest()).is_file());

    let repeated = engine
        .decode_and_publish_archive_v1(
            Cursor::new(payload),
            declaration,
            ArchiveLimitsV1::default(),
        )
        .unwrap();
    assert_eq!(repeated.root_digest(), decoded.root_digest());
}

fn assert_archive_decode_failure(
    bytes: Vec<u8>,
    declaration: impl FnOnce(&[u8]) -> ArchiveDeclarationV1,
    expected: impl FnOnce(&ArchiveDecodeError) -> bool,
) {
    let temp = tempfile::tempdir().unwrap();
    let engine = initialized_engine(&temp);
    assert!(!engine.config().state_root().join("objects").exists());
    let declaration = declaration(&bytes);

    let error = engine
        .decode_and_publish_archive_v1(Cursor::new(bytes), declaration, ArchiveLimitsV1::default())
        .unwrap_err();
    let ArchivePublicationError::Decode { source } = &error else {
        panic!("unexpected archive publication error: {error}");
    };
    assert!(
        expected(source),
        "unexpected archive decode error: {source}"
    );
    assert!(!engine.config().state_root().join("objects").exists());
}
