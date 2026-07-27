use std::ffi::OsString;
use std::fs;
use std::os::unix::ffi::OsStringExt;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};

use malm::{
    Engine, EngineConfig, EngineError, PackCaptureIssue, PackObjectPublication, StoreAccess,
};
use malm_pack::{
    LOCK_STAGING_FILE, MAX_PACK_FILE_BYTES, PACK_MANIFEST_FILE, PackFileV1, PackManifestV1,
    PackModuleV1, PackPath, encode_pack_v1, pack_content_digest,
};
use malm_types::{ContributionName, Digest, PackageId};

const MINIMAL_PACK: &[u8] = include_bytes!("../schemas/pack/v1/fixtures/valid/minimal.kdl");

fn create_state_home(parent: &Path) -> PathBuf {
    let state_home = parent.join("state");
    fs::create_dir(&state_home).unwrap();
    fs::set_permissions(&state_home, fs::Permissions::from_mode(0o700)).unwrap();
    state_home
}

fn initialized_engine(state_home: &Path) -> Engine {
    let engine = Engine::new(
        EngineConfig::from_state_home(state_home, StoreAccess::ReadWrite).unwrap(),
        malm::EnginePorts::system(),
    );
    engine.initialize_store().unwrap();
    engine
}

fn write_minimal_source(path: &Path) {
    fs::create_dir(path).unwrap();
    fs::write(path.join(PACK_MANIFEST_FILE), MINIMAL_PACK).unwrap();
}

fn fixture_digest(mut files: Vec<PackFileV1>) -> (Digest, Vec<PackFileV1>) {
    files.sort_by(|left, right| left.path().cmp(right.path()));
    let digest = pack_content_digest(files.iter().map(|file| (file.path(), file.bytes()))).unwrap();
    (digest, files)
}

fn object_path(state_home: &Path, digest: &Digest) -> PathBuf {
    // Deduplicated packs publish their manifest under the content digest.
    state_home
        .join("malm/objects/pack-manifests")
        .join(digest.as_str())
}

#[test]
fn local_capture_prunes_reserved_paths_and_cached_bytes_do_not_hide_drift() {
    let temp = tempfile::tempdir().unwrap();
    let state_home = create_state_home(temp.path());
    let experimental = state_home.join("malm-v1");
    fs::create_dir(&experimental).unwrap();
    fs::set_permissions(&experimental, fs::Permissions::from_mode(0o700)).unwrap();
    let sentinel = experimental.join("sentinel");
    fs::write(&sentinel, b"experimental state").unwrap();
    let sentinel_before = fs::metadata(&sentinel).unwrap();
    let engine = initialized_engine(&state_home);

    let source = temp.path().join("source");
    write_minimal_source(&source);
    fs::write(source.join("readme.txt"), b"root bytes").unwrap();
    fs::create_dir(source.join("nested")).unwrap();
    fs::write(source.join("nested/data.bin"), [0, 1, 2, 255]).unwrap();
    fs::create_dir(source.join("empty")).unwrap();
    fs::write(source.join("malm.lock"), b"excluded lock").unwrap();
    fs::write(source.join(LOCK_STAGING_FILE), b"excluded staging").unwrap();

    let outside_git = temp.path().join("outside-git");
    fs::create_dir(&outside_git).unwrap();
    fs::write(outside_git.join("sentinel"), b"excluded git data").unwrap();
    std::os::unix::fs::symlink(&outside_git, source.join(".git")).unwrap();
    fs::create_dir(source.join("nested/malm.lock")).unwrap();
    fs::write(
        source.join("nested/malm.lock/ignored"),
        b"nested excluded data",
    )
    .unwrap();

    let (digest, files) = fixture_digest(vec![
        PackFileV1::new(PackPath::new(PACK_MANIFEST_FILE).unwrap(), MINIMAL_PACK),
        PackFileV1::new(PackPath::new("readme.txt").unwrap(), b"root bytes"),
        PackFileV1::new(
            PackPath::new("nested/data.bin").unwrap(),
            vec![0, 1, 2, 255],
        ),
    ]);
    assert_eq!(
        engine
            .capture_and_publish_local_pack_v1(&source, &digest)
            .unwrap(),
        PackObjectPublication::Published
    );
    assert_eq!(engine.load_pack_object_v1(&digest).unwrap(), files);

    fs::write(source.join("malm.lock"), b"changed excluded lock").unwrap();
    fs::write(source.join(LOCK_STAGING_FILE), b"changed excluded staging").unwrap();
    fs::write(outside_git.join("sentinel"), b"changed excluded git data").unwrap();
    fs::write(
        source.join("nested/malm.lock/ignored"),
        b"changed nested data",
    )
    .unwrap();
    fs::set_permissions(source.join("readme.txt"), fs::Permissions::from_mode(0o400)).unwrap();
    assert_eq!(
        engine
            .capture_and_publish_local_pack_v1(&source, &digest)
            .unwrap(),
        PackObjectPublication::Reused
    );

    fs::set_permissions(source.join("readme.txt"), fs::Permissions::from_mode(0o600)).unwrap();
    fs::write(source.join("readme.txt"), b"local drift").unwrap();
    let error = engine
        .capture_and_publish_local_pack_v1(&source, &digest)
        .unwrap_err();
    assert!(matches!(
        error,
        EngineError::PackCapture {
            reason: PackCaptureIssue::DigestMismatch { expected, actual },
            ..
        } if expected == digest && actual != digest
    ));
    assert_eq!(engine.load_pack_object_v1(&digest).unwrap(), files);

    fs::remove_dir_all(&source).unwrap();
    assert!(matches!(
        engine.capture_and_publish_local_pack_v1(&source, &digest),
        Err(EngineError::PackCapture {
            reason: PackCaptureIssue::SourceRootMissing,
            ..
        })
    ));
    assert_eq!(fs::read(&sentinel).unwrap(), b"experimental state");
    let sentinel_after = fs::metadata(&sentinel).unwrap();
    assert_eq!(sentinel_before.dev(), sentinel_after.dev());
    assert_eq!(sentinel_before.ino(), sentinel_after.ino());
    assert_eq!(sentinel_before.mode(), sentinel_after.mode());
    assert_eq!(sentinel_before.nlink(), sentinel_after.nlink());
    assert_eq!(sentinel_before.size(), sentinel_after.size());
    assert_eq!(sentinel_before.mtime(), sentinel_after.mtime());
    assert_eq!(sentinel_before.mtime_nsec(), sentinel_after.mtime_nsec());
}

#[test]
fn unsafe_source_entries_are_rejected_without_publication() {
    let temp = tempfile::tempdir().unwrap();
    let state_home = create_state_home(temp.path());
    let engine = initialized_engine(&state_home);
    let arbitrary_digest = Digest::sha256(b"not reached");

    let symlink_source = temp.path().join("symlink-source");
    write_minimal_source(&symlink_source);
    let outside = temp.path().join("outside");
    fs::write(&outside, b"protected").unwrap();
    std::os::unix::fs::symlink(&outside, symlink_source.join("linked")).unwrap();
    assert!(matches!(
        engine.capture_and_publish_local_pack_v1(&symlink_source, &arbitrary_digest),
        Err(EngineError::PackCapture {
            reason: PackCaptureIssue::SymbolicLink,
            ..
        })
    ));
    assert_eq!(fs::read(&outside).unwrap(), b"protected");

    let hardlink_source = temp.path().join("hardlink-source");
    write_minimal_source(&hardlink_source);
    fs::hard_link(&outside, hardlink_source.join("linked")).unwrap();
    assert!(matches!(
        engine.capture_and_publish_local_pack_v1(&hardlink_source, &arbitrary_digest),
        Err(EngineError::PackCapture {
            reason: PackCaptureIssue::UnexpectedLinks {
                expected: 1,
                actual: 2
            },
            ..
        })
    ));

    let socket_source = temp.path().join("socket-source");
    write_minimal_source(&socket_source);
    let _socket = UnixListener::bind(socket_source.join("socket")).unwrap();
    let socket_error = engine
        .capture_and_publish_local_pack_v1(&socket_source, &arbitrary_digest)
        .unwrap_err();
    assert!(
        matches!(
            &socket_error,
            EngineError::PackCapture {
                reason: PackCaptureIssue::UnsupportedFileType,
                ..
            }
        ),
        "unexpected socket error: {socket_error:?}"
    );

    let non_utf8_source = temp.path().join("non-utf8-source");
    write_minimal_source(&non_utf8_source);
    fs::write(
        non_utf8_source.join(OsString::from_vec(vec![b'n', 0xff])),
        b"invalid name",
    )
    .unwrap();
    assert!(matches!(
        engine.capture_and_publish_local_pack_v1(&non_utf8_source, &arbitrary_digest),
        Err(EngineError::PackCapture {
            reason: PackCaptureIssue::NonUtf8Name,
            ..
        })
    ));

    let invalid_path_source = temp.path().join("invalid-path-source");
    write_minimal_source(&invalid_path_source);
    fs::write(invalid_path_source.join("bad\\name"), b"invalid path").unwrap();
    assert!(matches!(
        engine.capture_and_publish_local_pack_v1(&invalid_path_source, &arbitrary_digest),
        Err(EngineError::PackCapture {
            reason: PackCaptureIssue::InvalidPath { .. },
            ..
        })
    ));

    assert!(!state_home.join("malm/objects").exists());
}

#[test]
fn source_limits_and_missing_manifest_fail_before_publication() {
    let temp = tempfile::tempdir().unwrap();
    let state_home = create_state_home(temp.path());
    let engine = initialized_engine(&state_home);
    let arbitrary_digest = Digest::sha256(b"not reached");

    let missing_manifest = temp.path().join("missing-manifest");
    fs::create_dir(&missing_manifest).unwrap();
    fs::write(missing_manifest.join("data"), b"data").unwrap();
    assert!(matches!(
        engine.capture_and_publish_local_pack_v1(&missing_manifest, &arbitrary_digest),
        Err(EngineError::PackCapture {
            reason: PackCaptureIssue::MissingManifest,
            ..
        })
    ));

    let oversized = temp.path().join("oversized");
    write_minimal_source(&oversized);
    let file = fs::File::create(oversized.join("large")).unwrap();
    file.set_len(MAX_PACK_FILE_BYTES + 1).unwrap();
    assert!(matches!(
        engine.capture_and_publish_local_pack_v1(&oversized, &arbitrary_digest),
        Err(EngineError::PackCapture {
            reason: PackCaptureIssue::FileTooLarge {
                limit: MAX_PACK_FILE_BYTES,
                actual
            },
            ..
        }) if actual == MAX_PACK_FILE_BYTES + 1
    ));

    assert!(!state_home.join("malm/objects").exists());
}

#[test]
fn semantically_invalid_pack_is_not_published() {
    let temp = tempfile::tempdir().unwrap();
    let state_home = create_state_home(temp.path());
    let engine = initialized_engine(&state_home);
    let source = temp.path().join("source");
    fs::create_dir(&source).unwrap();

    let manifest = PackManifestV1::new(
        PackageId::new("com.example.invalid").unwrap(),
        vec![PackModuleV1::new(
            ContributionName::new("missing").unwrap(),
            PackPath::new("modules/missing.kdl").unwrap(),
        )],
        vec![],
        vec![],
        vec![],
        vec![],
        vec![],
    )
    .unwrap();
    let manifest_bytes = encode_pack_v1(&manifest);
    fs::write(source.join(PACK_MANIFEST_FILE), &manifest_bytes).unwrap();
    let (digest, _) = fixture_digest(vec![PackFileV1::new(
        PackPath::new(PACK_MANIFEST_FILE).unwrap(),
        manifest_bytes,
    )]);

    assert!(matches!(
        engine.capture_and_publish_local_pack_v1(&source, &digest),
        Err(EngineError::PackCapture {
            reason: PackCaptureIssue::InvalidPack { .. },
            ..
        })
    ));
    assert!(!object_path(&state_home, &digest).exists());
    assert!(!state_home.join("malm/objects").exists());
}

#[test]
fn source_authority_and_read_only_boundaries_fail_closed() {
    let temp = tempfile::tempdir().unwrap();
    let state_home = create_state_home(temp.path());
    let writer = initialized_engine(&state_home);
    let source = temp.path().join("source");
    write_minimal_source(&source);
    let (digest, _) = fixture_digest(vec![PackFileV1::new(
        PackPath::new(PACK_MANIFEST_FILE).unwrap(),
        MINIMAL_PACK,
    )]);

    let reader = Engine::new(
        EngineConfig::from_state_home(&state_home, StoreAccess::ReadOnly).unwrap(),
        malm::EnginePorts::system(),
    );
    assert!(matches!(
        reader.capture_and_publish_local_pack_v1(&source, &digest),
        Err(EngineError::ReadOnlyStore)
    ));
    assert!(!state_home.join("malm/objects").exists());

    assert!(matches!(
        writer.capture_and_publish_local_pack_v1(Path::new("relative"), &digest),
        Err(EngineError::PackCapture {
            reason: PackCaptureIssue::SourceRootMustBeAbsolute,
            ..
        })
    ));

    let source_link = temp.path().join("source-link");
    std::os::unix::fs::symlink(&source, &source_link).unwrap();
    assert!(matches!(
        writer.capture_and_publish_local_pack_v1(&source_link, &digest),
        Err(EngineError::PackCapture {
            reason: PackCaptureIssue::SymbolicLink,
            ..
        })
    ));

    assert!(matches!(
        writer.capture_and_publish_local_pack_v1(writer.config().state_root(), &digest),
        Err(EngineError::PackCapture {
            reason: PackCaptureIssue::ProtectedStateOverlap,
            ..
        })
    ));
    assert!(matches!(
        writer.capture_and_publish_local_pack_v1(temp.path(), &digest),
        Err(EngineError::PackCapture {
            reason: PackCaptureIssue::ProtectedStateOverlap,
            ..
        })
    ));
    assert!(!writer.config().state_root().join("objects").exists());
}

#[test]
fn declared_capture_roots_restrict_the_walk_to_listed_trees() {
    let temp = tempfile::tempdir().unwrap();
    let state_home = create_state_home(temp.path());
    let engine = initialized_engine(&state_home);

    // This manifest admits only `malm.kdl` and the `malm/` tree. The bounded
    // walk ignores all other source entries, including entries that would be
    // rejected if visited.
    let manifest = PackManifestV1::new(
        PackageId::new("com.example.captures").unwrap(),
        vec![],
        vec![],
        vec![],
        vec![],
        vec![],
        vec![],
    )
    .unwrap()
    .with_config_documents(vec![PackPath::new("malm.kdl").unwrap()])
    .unwrap()
    .with_capture_roots(vec![
        PackPath::new("malm.kdl").unwrap(),
        PackPath::new("malm").unwrap(),
    ])
    .unwrap();
    let manifest_bytes = encode_pack_v1(&manifest);
    assert!(
        manifest_bytes.contains("captures"),
        "non-empty capture roots are encoded"
    );
    let round_tripped = malm_pack::decode_pack_v1(manifest_bytes.as_bytes()).unwrap();
    assert_eq!(round_tripped, manifest);

    let source = temp.path().join("scoped-source");
    fs::create_dir(&source).unwrap();
    fs::write(source.join(PACK_MANIFEST_FILE), manifest_bytes.as_bytes()).unwrap();
    fs::write(source.join("malm.kdl"), b"config target=\"~\"\n").unwrap();
    fs::create_dir(source.join("malm")).unwrap();
    fs::write(source.join("malm/modules.kdl"), b"// captured\n").unwrap();
    // These entries are outside the allowlist. Visiting the symlink would make
    // capture fail, while the large tree and stray file must also remain ignored.
    fs::create_dir(source.join("packs")).unwrap();
    fs::write(source.join("packs/huge.bin"), vec![0u8; 4096]).unwrap();
    fs::write(source.join("README.md"), b"ignored").unwrap();
    std::os::unix::fs::symlink("malm.kdl", source.join("stray-link")).unwrap();

    let expected_files = vec![
        PackFileV1::new(
            PackPath::new(PACK_MANIFEST_FILE).unwrap(),
            manifest_bytes.clone().into_bytes(),
        ),
        PackFileV1::new(
            PackPath::new("malm.kdl").unwrap(),
            b"config target=\"~\"\n".to_vec(),
        ),
        PackFileV1::new(
            PackPath::new("malm/modules.kdl").unwrap(),
            b"// captured\n".to_vec(),
        ),
    ];
    let (digest, _) = fixture_digest(expected_files);
    engine
        .capture_and_publish_local_pack_v1(&source, &digest)
        .unwrap();
    assert!(object_path(&state_home, &digest).exists());
}
