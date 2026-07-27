#![cfg(unix)]

use std::ffi::OsString;
use std::fs;
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use malm::{
    ApprovalV1, CommitError, CommitRequestV1, Engine, EngineConfig, EnginePorts, PrepareArtifactV1,
    PrepareOperationV1, PrepareRequestPartsV1, PrepareRequestV1, PreparedDeploymentV1, StoreAccess,
};
use malm_types::{
    ArtifactId, DeploymentName, Digest, NamespaceName, PrepareTargetStateV1, PreparedId,
};

const PREFLIGHT_XATTR_NAME: &str = "user.malm-preflight-sentinel";
const PREFLIGHT_XATTR_VALUE: &[u8] = b"must remain unchanged";

struct Fixture {
    engine: Engine,
    target: PathBuf,
    _temp: tempfile::TempDir,
}

impl Fixture {
    fn new() -> Self {
        let temp = tempfile::tempdir().unwrap();
        let state_home = temp.path().join("state");
        fs::create_dir(&state_home).unwrap();
        fs::set_permissions(&state_home, fs::Permissions::from_mode(0o700)).unwrap();

        let target = temp.path().join("target");
        fs::create_dir(&target).unwrap();
        fs::create_dir(target.join("config")).unwrap();
        let existing = target.join("config/existing.conf");
        fs::write(&existing, b"existing bytes\n").unwrap();
        xattr::set(&existing, PREFLIGHT_XATTR_NAME, PREFLIGHT_XATTR_VALUE).unwrap();

        let engine = Engine::new(
            EngineConfig::from_state_home(&state_home, StoreAccess::ReadWrite)
                .unwrap()
                .with_target_authority(DeploymentName::new("home").unwrap(), &target)
                .unwrap(),
            EnginePorts::system(),
        );
        engine.initialize_store().unwrap();

        Self {
            engine,
            target,
            _temp: temp,
        }
    }

    fn prepared_record_path(&self, prepared: &PreparedDeploymentV1) -> PathBuf {
        self.engine
            .config()
            .state_root()
            .join("prepared")
            .join(prepared.plan_id().as_str())
    }

    fn artifact_blob_path(&self, prepared: &PreparedDeploymentV1) -> PathBuf {
        self.engine
            .config()
            .state_root()
            .join("objects/blobs")
            .join(prepared.artifacts()[0].digest().as_str())
    }
}

#[derive(Debug, Eq, PartialEq)]
struct MutationSurfaces {
    target: TreeSnapshot,
    transactions: TreeSnapshot,
    active_state: TreeSnapshot,
}

impl MutationSurfaces {
    fn capture(fixture: &Fixture) -> Self {
        let state_root = fixture.engine.config().state_root();
        Self {
            target: TreeSnapshot::capture(&fixture.target),
            transactions: TreeSnapshot::capture(&state_root.join("transactions")),
            active_state: TreeSnapshot::capture(&state_root.join("state")),
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
enum TreeSnapshot {
    Missing,
    Present(Vec<EntrySnapshot>),
}

impl TreeSnapshot {
    fn capture(root: &Path) -> Self {
        match fs::symlink_metadata(root) {
            Ok(_) => {
                let mut entries = Vec::new();
                snapshot_entry(root, Path::new(""), &mut entries);
                Self::Present(entries)
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Self::Missing,
            Err(error) => panic!("cannot inspect {}: {error}", root.display()),
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
struct EntrySnapshot {
    relative_path: PathBuf,
    device: u64,
    inode: u64,
    mode: u32,
    uid: u32,
    gid: u32,
    link_count: u64,
    size: u64,
    modified: (i64, i64),
    changed: (i64, i64),
    xattrs: Vec<(OsString, Vec<u8>)>,
    contents: EntryContents,
}

#[derive(Debug, Eq, PartialEq)]
enum EntryContents {
    Directory,
    File(Vec<u8>),
    Symlink(PathBuf),
    Other,
}

fn snapshot_entry(root: &Path, relative_path: &Path, entries: &mut Vec<EntrySnapshot>) {
    let path = root.join(relative_path);
    let metadata = fs::symlink_metadata(&path).unwrap();
    let file_type = metadata.file_type();
    let contents = if file_type.is_dir() {
        EntryContents::Directory
    } else if file_type.is_file() {
        EntryContents::File(read_regular_file(&path))
    } else if file_type.is_symlink() {
        EntryContents::Symlink(fs::read_link(&path).unwrap())
    } else {
        EntryContents::Other
    };
    let metadata = fs::symlink_metadata(&path).unwrap();
    entries.push(EntrySnapshot {
        relative_path: relative_path.to_path_buf(),
        device: metadata.dev(),
        inode: metadata.ino(),
        mode: metadata.mode(),
        uid: metadata.uid(),
        gid: metadata.gid(),
        link_count: metadata.nlink(),
        size: metadata.size(),
        modified: (metadata.mtime(), metadata.mtime_nsec()),
        changed: (metadata.ctime(), metadata.ctime_nsec()),
        xattrs: snapshot_xattrs(&path),
        contents,
    });

    if file_type.is_dir() {
        let mut children = fs::read_dir(&path)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect::<Vec<_>>();
        children.sort();
        for child in children {
            snapshot_entry(root, &relative_path.join(child), entries);
        }
    }
}

fn read_regular_file(path: &Path) -> Vec<u8> {
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(any(target_os = "android", target_os = "linux"))]
    options.custom_flags(libc::O_NOATIME | libc::O_NOFOLLOW);
    #[cfg(not(any(target_os = "android", target_os = "linux")))]
    options.custom_flags(libc::O_NOFOLLOW);

    let mut file = options.open(path).unwrap();
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes).unwrap();
    bytes
}

fn snapshot_xattrs(path: &Path) -> Vec<(OsString, Vec<u8>)> {
    let mut names = xattr::list(path).unwrap().collect::<Vec<_>>();
    names.sort();
    names
        .into_iter()
        .map(|name| {
            let value = xattr::get(path, &name)
                .unwrap()
                .unwrap_or_else(|| panic!("listed xattr {name:?} disappeared"));
            (name, value)
        })
        .collect()
}

fn file_request(expected_head: Option<Digest>) -> PrepareRequestV1 {
    let artifact_id = ArtifactId::new("config/prepared").unwrap();
    PrepareRequestV1::from(PrepareRequestPartsV1 {
        namespace: NamespaceName::new("workstation").unwrap(),
        expected_head,
        graph_digest: Digest::sha256(b"commit preflight graph"),
        inputs: vec![],
        artifacts: vec![
            PrepareArtifactV1::new(
                artifact_id.clone(),
                b"prepared bytes\n".to_vec(),
                "text/plain",
            )
            .unwrap(),
        ],
        transforms: vec![],
        findings: vec![],
        operations: vec![
            PrepareOperationV1::place_file(
                DeploymentName::new("home").unwrap(),
                "config/prepared.conf",
                artifact_id,
                0o600,
            )
            .unwrap(),
        ],
    })
}

fn approved_request(prepared: &PreparedDeploymentV1) -> CommitRequestV1 {
    CommitRequestV1::new(
        prepared.plan_id().clone(),
        ApprovalV1::new(
            prepared.plan_id().clone(),
            prepared.approval_digest().clone(),
        ),
    )
}

fn assert_preflight_rejection(
    fixture: &Fixture,
    request: &CommitRequestV1,
    assert_error: impl FnOnce(&CommitError),
) {
    let before = MutationSurfaces::capture(fixture);
    let error = fixture.engine.commit_v1(request).unwrap_err();
    assert_error(&error);
    let after = MutationSurfaces::capture(fixture);
    assert_eq!(
        after, before,
        "failed commit mutated a target, transaction journal, or active state"
    );
}

fn mutate_immutable(path: &Path, mutate: impl FnOnce(&mut Vec<u8>)) {
    let mut bytes = fs::read(path).unwrap();
    let original = bytes.clone();
    mutate(&mut bytes);
    assert_ne!(
        bytes, original,
        "test tamper must change the immutable bytes"
    );

    let original_mode = fs::metadata(path).unwrap().permissions().mode() & 0o7777;
    assert_eq!(original_mode, 0o400);
    fs::set_permissions(path, fs::Permissions::from_mode(original_mode | 0o200)).unwrap();
    let write_result = fs::write(path, bytes);
    let restore_result = fs::set_permissions(path, fs::Permissions::from_mode(original_mode));
    write_result.unwrap();
    restore_result.unwrap();
    assert_eq!(
        fs::metadata(path).unwrap().permissions().mode() & 0o7777,
        0o400
    );
}

fn unique_offset(bytes: &[u8], needle: &[u8]) -> usize {
    let offsets = bytes
        .windows(needle.len())
        .enumerate()
        .filter_map(|(offset, window)| (window == needle).then_some(offset))
        .collect::<Vec<_>>();
    assert_eq!(offsets.len(), 1, "expected one immutable-field match");
    offsets[0]
}

#[test]
fn missing_plan_is_rejected_before_any_commit_mutation() {
    let fixture = Fixture::new();
    let missing = PreparedId::from_digest(&Digest::sha256(b"missing prepared plan"));
    let request = CommitRequestV1::new(
        missing.clone(),
        ApprovalV1::new(missing.clone(), Digest::sha256(b"missing approval")),
    );

    assert_preflight_rejection(&fixture, &request, |error| {
        assert!(
            matches!(error, CommitError::MissingPlan(actual) if actual == &missing),
            "unexpected missing-plan error: {error:?}"
        );
    });
}

#[test]
fn missing_artifact_blob_is_rejected_before_any_commit_mutation() {
    let fixture = Fixture::new();
    let prepared = fixture.engine.prepare_v1(&file_request(None)).unwrap();
    let digest = prepared.artifacts()[0].digest().clone();
    fs::remove_file(fixture.artifact_blob_path(&prepared)).unwrap();

    assert_preflight_rejection(&fixture, &approved_request(&prepared), |error| {
        assert!(
            matches!(error, CommitError::MissingArtifact(actual) if actual == &digest),
            "unexpected missing-artifact error: {error:?}"
        );
    });
}

#[test]
fn modified_prepared_record_manifest_is_rejected_before_any_commit_mutation() {
    let fixture = Fixture::new();
    let prepared = fixture.engine.prepare_v1(&file_request(None)).unwrap();
    mutate_immutable(&fixture.prepared_record_path(&prepared), |bytes| {
        let digest = prepared.graph_digest().as_str().as_bytes();
        let offset = unique_offset(bytes, digest) + digest.len() - 1;
        bytes[offset] = if bytes[offset] == b'0' { b'1' } else { b'0' };
    });

    assert_preflight_rejection(
        &fixture,
        &approved_request(&prepared),
        |error| match error {
            CommitError::InvalidPlan(reason) => assert!(
                reason.contains("prepared record identity mismatch"),
                "unexpected modified-record reason: {reason}"
            ),
            _ => panic!("unexpected modified-record error: {error:?}"),
        },
    );
}

#[test]
fn unsupported_prepared_schema_version_is_rejected_before_any_commit_mutation() {
    let fixture = Fixture::new();
    let prepared = fixture.engine.prepare_v1(&file_request(None)).unwrap();
    mutate_immutable(&fixture.prepared_record_path(&prepared), |bytes| {
        let field = b"\"schema_version\":1";
        let offset = unique_offset(bytes, field) + field.len() - 1;
        bytes[offset] = b'2';
    });

    assert_preflight_rejection(
        &fixture,
        &approved_request(&prepared),
        |error| match error {
            CommitError::InvalidPlan(reason) => assert!(
                reason.contains("unsupported prepared record version 2")
                    || reason.contains("prepared record is not canonical"),
                "unexpected unsupported-version reason: {reason}"
            ),
            _ => panic!("unexpected unsupported-version error: {error:?}"),
        },
    );
}

#[test]
fn wrong_approval_is_rejected_before_any_commit_mutation() {
    let fixture = Fixture::new();
    let prepared = fixture.engine.prepare_v1(&file_request(None)).unwrap();
    let other_plan = PreparedId::from_digest(&Digest::sha256(b"another plan"));
    let wrong_plan = CommitRequestV1::new(
        prepared.plan_id().clone(),
        ApprovalV1::new(other_plan, prepared.approval_digest().clone()),
    );
    assert_preflight_rejection(&fixture, &wrong_plan, |error| {
        assert!(
            matches!(error, CommitError::ApprovalPlanMismatch),
            "unexpected approval-plan error: {error:?}"
        );
    });

    let wrong_findings = CommitRequestV1::new(
        prepared.plan_id().clone(),
        ApprovalV1::new(
            prepared.plan_id().clone(),
            Digest::sha256(b"wrong findings approval"),
        ),
    );
    assert_preflight_rejection(&fixture, &wrong_findings, |error| {
        assert!(
            matches!(error, CommitError::ApprovalFindingsMismatch),
            "unexpected approval-findings error: {error:?}"
        );
    });
}

#[test]
fn stale_active_generation_is_rejected_before_any_commit_mutation() {
    let fixture = Fixture::new();
    let stale = fixture.engine.prepare_v1(&file_request(None)).unwrap();
    let baseline = fixture
        .engine
        .prepare_v1(&PrepareRequestV1::from(PrepareRequestPartsV1 {
            namespace: NamespaceName::new("workstation").unwrap(),
            expected_head: None,
            graph_digest: Digest::sha256(b"active baseline"),
            inputs: vec![],
            artifacts: vec![],
            transforms: vec![],
            findings: vec![],
            operations: vec![],
        }))
        .unwrap();
    let active = fixture
        .engine
        .commit_v1(&approved_request(&baseline))
        .unwrap()
        .head()
        .clone();

    assert_preflight_rejection(&fixture, &approved_request(&stale), |error| match error {
        CommitError::StaleNamespaceHead {
            expected, actual, ..
        } => {
            assert!(expected.is_none());
            assert_eq!(actual.as_ref(), Some(&active));
        }
        _ => panic!("unexpected stale-active error: {error:?}"),
    });
}

#[test]
fn stale_target_observation_is_rejected_before_any_commit_mutation() {
    let fixture = Fixture::new();
    let prepared = fixture.engine.prepare_v1(&file_request(None)).unwrap();
    fs::write(
        fixture.target.join("config/prepared.conf"),
        b"external bytes after prepare\n",
    )
    .unwrap();

    assert_preflight_rejection(&fixture, &approved_request(&prepared), |error| {
        assert!(
            matches!(error, CommitError::StaleTarget(_)),
            "unexpected stale-target error: {error:?}"
        );
    });
}

#[test]
fn stale_exact_assertion_is_rejected_before_journal_publication() {
    let fixture = Fixture::new();
    let bytes = b"owned exact bytes\n";
    let artifact = ArtifactId::new("exact/seed").unwrap();
    let seed = fixture
        .engine
        .prepare_v1(&PrepareRequestV1::from(PrepareRequestPartsV1 {
            namespace: NamespaceName::new("workstation").unwrap(),
            expected_head: None,
            graph_digest: Digest::sha256(b"exact assertion seed"),
            inputs: vec![],
            artifacts: vec![
                PrepareArtifactV1::new(artifact.clone(), bytes.to_vec(), "text/plain").unwrap(),
            ],
            transforms: vec![],
            findings: vec![],
            operations: vec![
                PrepareOperationV1::place_file(
                    DeploymentName::new("home").unwrap(),
                    "config/exact.conf",
                    artifact,
                    0o600,
                )
                .unwrap(),
            ],
        }))
        .unwrap();
    let head = fixture
        .engine
        .commit_v1(&approved_request(&seed))
        .unwrap()
        .head()
        .clone();
    let exact = fixture
        .engine
        .prepare_v1(&PrepareRequestV1::from(PrepareRequestPartsV1 {
            namespace: NamespaceName::new("workstation").unwrap(),
            expected_head: Some(head),
            graph_digest: Digest::sha256(b"exact assertion"),
            inputs: vec![],
            artifacts: vec![],
            transforms: vec![],
            findings: vec![],
            operations: vec![
                PrepareOperationV1::assert_exact(
                    DeploymentName::new("home").unwrap(),
                    "config/exact.conf",
                    PrepareTargetStateV1::file(Digest::sha256(bytes), bytes.len() as u64, 0o600)
                        .unwrap(),
                )
                .unwrap(),
            ],
        }))
        .unwrap();
    fs::write(fixture.target.join("config/exact.conf"), b"drifted\n").unwrap();

    assert_preflight_rejection(&fixture, &approved_request(&exact), |error| {
        assert!(matches!(error, CommitError::StaleTarget(_)));
    });
}
