#![cfg(target_os = "linux")]

use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::fs;
use std::io::Read;
use std::mem::MaybeUninit;
use std::os::fd::OwnedFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use malm::{
    ApprovalV1, CheckoutRequestV1, CommitRequestV1, Engine, EngineConfig, EnginePorts,
    PrepareArtifactV1, PrepareOperationV1, PrepareRequestPartsV1, PrepareRequestV1, PruneRequestV1,
    StoreAccess, StoreStatus,
};
use malm_types::{ArtifactId, DeploymentName, Digest, NamespaceName};
use rustix::fs::inotify::{self, CreateFlags, ReadFlags, WatchFlags};
use rustix::fs::{Dir, Mode, OFlags, open};
use rustix::io::Errno;

type FileTimes = [(i64, i64); 3];
type RootSnapshot = BTreeMap<
    PathBuf,
    (
        Option<Vec<u8>>,
        u32,
        u32,
        u32,
        u64,
        u64,
        u64,
        u64,
        FileTimes,
    ),
>;

#[derive(Debug)]
struct MutationEvent {
    path: PathBuf,
    flags: ReadFlags,
}

struct RecursiveMutationWatch {
    fd: OwnedFd,
    directories: BTreeMap<i32, PathBuf>,
}

impl RecursiveMutationWatch {
    fn new(root: &Path) -> Self {
        let fd = inotify::init(CreateFlags::CLOEXEC | CreateFlags::NONBLOCK).unwrap();
        let mut watch = Self {
            fd,
            directories: BTreeMap::new(),
        };
        let mut pending = vec![root.to_path_buf()];
        while let Some(directory) = pending.pop() {
            watch.add(&directory);
            let mut children = Vec::new();
            for entry in fs::read_dir(&directory).unwrap() {
                let entry = entry.unwrap();
                if entry.file_type().unwrap().is_dir() {
                    children.push(entry.path());
                }
            }
            children.sort();
            pending.extend(children.into_iter().rev());
        }
        watch
    }

    fn add(&mut self, directory: &Path) {
        let flags = WatchFlags::ATTRIB
            | WatchFlags::CLOSE_WRITE
            | WatchFlags::CREATE
            | WatchFlags::DELETE
            | WatchFlags::DELETE_SELF
            | WatchFlags::MODIFY
            | WatchFlags::MOVE_SELF
            | WatchFlags::MOVED_FROM
            | WatchFlags::MOVED_TO
            | WatchFlags::DONT_FOLLOW
            | WatchFlags::ONLYDIR;
        let descriptor = inotify::add_watch(&self.fd, directory, flags).unwrap();
        assert!(
            self.directories
                .insert(descriptor, directory.to_path_buf())
                .is_none(),
            "duplicate inotify descriptor for {}",
            directory.display()
        );
    }

    fn take_events(&mut self) -> Vec<MutationEvent> {
        let mut events = Vec::new();
        let mut buffer = [MaybeUninit::uninit(); 8192];
        let mut reader = inotify::Reader::new(&self.fd, &mut buffer);
        loop {
            let event = match reader.next() {
                Ok(event) => event,
                Err(Errno::AGAIN) => break,
                Err(Errno::INTR) => continue,
                Err(error) => panic!("read inotify events: {error}"),
            };
            let mut path = self
                .directories
                .get(&event.wd())
                .cloned()
                .unwrap_or_else(|| PathBuf::from(format!("<inotify:{}>", event.wd())));
            if let Some(name) = event.file_name() {
                path.push(OsStr::from_bytes(name.to_bytes()));
            }
            events.push(MutationEvent {
                path,
                flags: event.events(),
            });
        }
        events
    }
}

fn create_predecessor_sibling(state_home: &Path) -> PathBuf {
    let root = state_home.join("malm-v1");
    for relative in [
        "",
        "objects",
        "objects/files",
        "states",
        "states/default",
        "transactions",
        "transactions/legacy-transaction",
    ] {
        let directory = root.join(relative);
        fs::create_dir(&directory).unwrap();
        fs::set_permissions(directory, fs::Permissions::from_mode(0o700)).unwrap();
    }
    for (relative, bytes) in [
        ("format.json", b"{\"version\":2}\n".as_slice()),
        ("targets.json", b"{\"legacy\":true}\n".as_slice()),
        (
            "objects/files/legacy-object",
            b"legacy object bytes\n".as_slice(),
        ),
        (
            "states/default/state.json",
            b"{\"schema_version\":3,\"mode\":\"enabled\"}\n".as_slice(),
        ),
        (
            "transactions/legacy-transaction/manifest.json",
            b"{\"legacy_transaction\":true}\n".as_slice(),
        ),
    ] {
        let path = root.join(relative);
        fs::write(&path, bytes).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }
    root
}

fn tree_paths(root: &Path) -> Vec<PathBuf> {
    let mut paths = Vec::new();
    let mut pending = vec![root.to_path_buf()];
    while let Some(path) = pending.pop() {
        let metadata = fs::symlink_metadata(&path).unwrap();
        assert!(metadata.is_dir() || metadata.is_file());
        if metadata.is_dir() {
            let directory = open(
                &path,
                OFlags::RDONLY
                    | OFlags::DIRECTORY
                    | OFlags::CLOEXEC
                    | OFlags::NOFOLLOW
                    | OFlags::NOATIME,
                Mode::empty(),
            )
            .unwrap();
            let mut directory = Dir::new(directory).unwrap();
            while let Some(entry) = directory.read() {
                let entry = entry.unwrap();
                let name = entry.file_name().to_bytes();
                if !matches!(name, b"." | b"..") {
                    pending.push(path.join(OsStr::from_bytes(name)));
                }
            }
        }
        paths.push(path);
    }
    paths.sort();
    paths
}

fn snapshot(root: &Path, paths: &[PathBuf]) -> RootSnapshot {
    paths
        .iter()
        .map(|path| {
            let metadata = fs::symlink_metadata(path).unwrap();
            let bytes = metadata.is_file().then(|| {
                let mut file = fs::OpenOptions::new()
                    .read(true)
                    .custom_flags(libc::O_NOATIME | libc::O_NOFOLLOW)
                    .open(path)
                    .unwrap();
                let mut bytes = Vec::new();
                file.read_to_end(&mut bytes).unwrap();
                bytes
            });
            let metadata = fs::symlink_metadata(path).unwrap();
            let times = [
                (metadata.atime(), metadata.atime_nsec()),
                (metadata.mtime(), metadata.mtime_nsec()),
                (metadata.ctime(), metadata.ctime_nsec()),
            ];
            (
                path.strip_prefix(root).unwrap().to_path_buf(),
                (
                    bytes,
                    metadata.mode(),
                    metadata.uid(),
                    metadata.gid(),
                    metadata.nlink(),
                    metadata.size(),
                    metadata.dev(),
                    metadata.ino(),
                    times,
                ),
            )
        })
        .collect()
}

fn make_tree_read_only(paths: &[PathBuf]) {
    for path in paths.iter().rev() {
        let metadata = fs::symlink_metadata(path).unwrap();
        let mode = if metadata.is_dir() { 0o500 } else { 0o400 };
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
    }

    for path in paths {
        let metadata = fs::symlink_metadata(path).unwrap();
        let expected = if metadata.is_dir() { 0o500 } else { 0o400 };
        assert_eq!(metadata.mode() & 0o7777, expected, "{}", path.display());
    }
}

fn calibrate_watch(watch: &mut RecursiveMutationWatch, nested: &Path) {
    let probe = nested.join("inotify-probe");
    let moved = nested.join("inotify-probe-moved");
    fs::write(&probe, b"probe").unwrap();
    fs::set_permissions(&probe, fs::Permissions::from_mode(0o400)).unwrap();
    fs::rename(&probe, &moved).unwrap();
    fs::remove_file(&moved).unwrap();

    let events = watch.take_events();
    let observed = events
        .iter()
        .filter(|event| event.path.starts_with(nested))
        .fold(ReadFlags::empty(), |flags, event| flags | event.flags);
    for required in [
        ReadFlags::CREATE,
        ReadFlags::MODIFY,
        ReadFlags::ATTRIB,
        ReadFlags::MOVED_FROM,
        ReadFlags::MOVED_TO,
        ReadFlags::DELETE,
    ] {
        assert!(
            observed.contains(required),
            "inotify calibration missed {required:?}: {events:#?}"
        );
    }
}

#[test]
fn successor_lifecycle_does_not_touch_the_experimental_sibling() {
    let temp = tempfile::tempdir().unwrap();
    let state_home = temp.path().join("state");
    let target = temp.path().join("target");
    fs::create_dir(&state_home).unwrap();
    fs::set_permissions(&state_home, fs::Permissions::from_mode(0o700)).unwrap();
    fs::create_dir(&target).unwrap();
    fs::create_dir(target.join("config")).unwrap();
    let predecessor = create_predecessor_sibling(&state_home);
    assert_eq!(fs::metadata(&predecessor).unwrap().mode() & 0o777, 0o700);

    let mut watch = RecursiveMutationWatch::new(&predecessor);
    calibrate_watch(&mut watch, &predecessor.join("states/default"));
    let paths = tree_paths(&predecessor);
    make_tree_read_only(&paths);
    let setup_events = watch.take_events();
    assert!(
        !setup_events.is_empty()
            && setup_events
                .iter()
                .all(|event| event.path.starts_with(&predecessor)),
        "unexpected read-only setup events: {setup_events:#?}"
    );
    let before = snapshot(&predecessor, &paths);

    let authority = DeploymentName::new("home").unwrap();
    let engine = Engine::new(
        EngineConfig::from_state_home(&state_home, StoreAccess::ReadWrite)
            .unwrap()
            .with_target_authority(authority.clone(), &target)
            .unwrap(),
        EnginePorts::system(),
    );
    assert_eq!(engine.store_status().unwrap(), StoreStatus::Absent);
    assert_eq!(
        engine.initialize_store().unwrap().status(),
        StoreStatus::Ready
    );
    assert_eq!(engine.store_status().unwrap(), StoreStatus::Ready);
    assert!(
        engine
            .inspect_state_v1(&NamespaceName::new("workstation").unwrap())
            .unwrap()
            .head()
            .is_none()
    );

    let artifact_id = ArtifactId::new("config/legacy-isolation").unwrap();
    let prepared = engine
        .prepare_v1(&PrepareRequestV1::from(PrepareRequestPartsV1 {
            namespace: NamespaceName::new("workstation").unwrap(),
            expected_head: None,
            graph_digest: Digest::sha256(b"legacy isolation graph"),
            inputs: vec![],
            artifacts: vec![
                PrepareArtifactV1::new(artifact_id.clone(), b"v1 output\n".to_vec(), "text/plain")
                    .unwrap(),
            ],
            transforms: vec![],
            findings: vec![],
            operations: vec![
                PrepareOperationV1::place_file(
                    authority,
                    "config/v1.conf",
                    artifact_id.clone(),
                    0o600,
                )
                .unwrap(),
            ],
        }))
        .unwrap();
    assert_eq!(engine.plan_v1(prepared.plan_id()).unwrap(), prepared);
    assert_eq!(
        engine
            .artifact_v1(prepared.plan_id(), &artifact_id)
            .unwrap()
            .bytes(),
        b"v1 output\n"
    );

    let committed = engine
        .commit_v1(&CommitRequestV1::new(
            prepared.plan_id().clone(),
            ApprovalV1::new(
                prepared.plan_id().clone(),
                prepared.approval_digest().clone(),
            ),
        ))
        .unwrap();
    assert_eq!(
        fs::read(target.join("config/v1.conf")).unwrap(),
        b"v1 output\n"
    );
    assert_eq!(
        engine
            .inspect_state_v1(committed.namespace())
            .unwrap()
            .head(),
        Some(committed.head())
    );
    assert!(matches!(
        engine.recover_v1().unwrap(),
        malm::RecoveryOutcomeV1::NoTransaction
    ));

    let checkout = engine
        .prepare_checkout_v1(&CheckoutRequestV1::new(
            committed.namespace().clone(),
            committed.head().clone(),
        ))
        .unwrap();
    assert_eq!(checkout.operation_count(), 1);
    assert_eq!(engine.plan_v1(checkout.plan_id()).unwrap(), checkout);
    let checkout_id = checkout.plan_id().clone();

    let disposable = engine
        .prepare_v1(&PrepareRequestV1::from(PrepareRequestPartsV1 {
            namespace: NamespaceName::new("workstation").unwrap(),
            expected_head: Some(committed.head().clone()),
            graph_digest: Digest::sha256(b"disposable graph"),
            inputs: vec![],
            artifacts: vec![],
            transforms: vec![],
            findings: vec![],
            operations: vec![],
        }))
        .unwrap();
    let disposable_id = disposable.plan_id().clone();
    let pruned = engine
        .prune_v1(&PruneRequestV1::new(vec![
            disposable_id.clone(),
            checkout_id.clone(),
        ]))
        .unwrap();
    assert_eq!(pruned.prepared_records, 2);
    assert!(engine.plan_v1(&disposable_id).is_err());
    assert!(engine.plan_v1(&checkout_id).is_err());

    let after = snapshot(&predecessor, &paths);
    let mutations = watch.take_events();
    assert!(
        mutations.is_empty() && after == before,
        "successor touched the read-only predecessor root\nmutations: {mutations:#?}\nbefore: {before:#?}\nafter: {after:#?}"
    );
}

fn run_store(home: Option<&Path>, xdg_state_home: Option<&OsStr>) -> std::process::Output {
    let mut command = std::process::Command::new(env!("CARGO_BIN_EXE_malm"));
    command.args(["store", "init"]);
    match home {
        Some(home) => {
            command.env("HOME", home);
        }
        None => {
            command.env_remove("HOME");
        }
    }
    match xdg_state_home {
        Some(state_home) => {
            command.env("XDG_STATE_HOME", state_home);
        }
        None => {
            command.env_remove("XDG_STATE_HOME");
        }
    }
    command.env_remove("MALM_FAILPOINT").output().unwrap()
}

fn private_directory(path: &Path) {
    fs::create_dir_all(path).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
}

#[test]
fn final_root_environment_matrix_is_fail_closed() {
    let configured = tempfile::tempdir().unwrap();
    let configured_home = configured.path().join("home");
    let configured_state = configured.path().join("state");
    private_directory(&configured_home);
    private_directory(&configured_state);
    let output = run_store(Some(&configured_home), Some(configured_state.as_os_str()));
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(configured_state.join("malm/descriptor.json").is_file());

    for (name, home) in [
        ("unset-home", None),
        ("empty-home", Some(Path::new(""))),
        ("relative-home", Some(Path::new("relative-home"))),
    ] {
        let output = run_store(home, Some(configured_state.as_os_str()));
        assert!(
            output.status.success(),
            "{name} unexpectedly failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    let explicit_target = configured.path().join("target");
    private_directory(&explicit_target);
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_malm"))
        .args([
            "namespace",
            "status",
            "--namespace",
            "missing",
            "--target",
            &format!("home={}", explicit_target.display()),
        ])
        .env_remove("HOME")
        .env("XDG_STATE_HOME", &configured_state)
        .env_remove("MALM_FAILPOINT")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "explicit target unexpectedly required HOME: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_malm"))
        .args(["namespace", "status", "--namespace", "missing"])
        .env_remove("HOME")
        .env("XDG_STATE_HOME", &configured_state)
        .env_remove("MALM_FAILPOINT")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("HOME"));

    let fallback = tempfile::tempdir().unwrap();
    let fallback_home = fallback.path().join("home");
    private_directory(&fallback_home);
    private_directory(&fallback_home.join(".local/state"));
    let output = run_store(Some(&fallback_home), None);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        fallback_home
            .join(".local/state/malm/descriptor.json")
            .is_file()
    );

    for (name, home, xdg) in [
        ("unset-both", None, None),
        ("empty-fallback-home", Some(Path::new("")), None),
        (
            "relative-fallback-home",
            Some(Path::new("relative-home")),
            None,
        ),
        (
            "empty-xdg",
            Some(configured_home.as_path()),
            Some(OsStr::new("")),
        ),
        (
            "relative-xdg",
            Some(configured_home.as_path()),
            Some(OsStr::new("relative-state")),
        ),
    ] {
        let output = run_store(home, xdg);
        assert_eq!(
            output.status.code(),
            Some(2),
            "{name} unexpectedly succeeded: {}",
            String::from_utf8_lossy(&output.stdout)
        );
    }
    for (name, home, xdg) in [
        (
            "dot-xdg",
            Some(configured_home.clone()),
            Some(configured.path().join("state/./nested")),
        ),
        (
            "parent-xdg",
            Some(configured_home.clone()),
            Some(configured.path().join("state/../nested")),
        ),
        (
            "dot-home",
            Some(configured.path().join("home/./nested")),
            None,
        ),
        (
            "parent-home",
            Some(configured.path().join("home/../nested")),
            None,
        ),
    ] {
        let output = run_store(home.as_deref(), xdg.as_deref().map(Path::as_os_str));
        assert_eq!(
            output.status.code(),
            Some(2),
            "{name} unexpectedly succeeded: {}",
            String::from_utf8_lossy(&output.stdout)
        );
    }
    assert!(!configured_home.join(".local/state/malm").exists());
}

#[test]
fn absent_empty_and_final_roots_are_the_only_initializable_states() {
    for initial in ["absent", "empty", "final"] {
        let temp = tempfile::tempdir().unwrap();
        let home = temp.path().join("home");
        let state_home = temp.path().join("state");
        private_directory(&home);
        private_directory(&state_home);
        let root = state_home.join("malm");
        if matches!(initial, "empty" | "final") {
            private_directory(&root);
        }
        if initial == "final" {
            fs::write(
                root.join("descriptor.json"),
                b"{\"format\":\"malm-state\",\"version\":1}\n",
            )
            .unwrap();
            fs::set_permissions(
                root.join("descriptor.json"),
                fs::Permissions::from_mode(0o600),
            )
            .unwrap();
        }

        let output = run_store(Some(&home), Some(state_home.as_os_str()));
        assert!(
            output.status.success(),
            "{initial}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            fs::read(root.join("descriptor.json")).unwrap(),
            b"{\"format\":\"malm-state\",\"version\":1}\n"
        );
    }
}

#[test]
fn incompatible_root_matrix_is_rejected_exactly_unchanged_before_lock_or_staging() {
    for case in [
        "markerless",
        "legacy-descriptor",
        "experimental-descriptor",
        "mixed",
        "malformed",
        "unsupported",
    ] {
        let temp = tempfile::tempdir().unwrap();
        let home = temp.path().join("home");
        let state_home = temp.path().join("state");
        let root = state_home.join("malm");
        private_directory(&home);
        private_directory(&state_home);
        private_directory(&root);

        match case {
            "markerless" => fs::write(root.join("state.json"), b"old state\n").unwrap(),
            "legacy-descriptor" => {
                fs::write(root.join("format.json"), b"{\"version\":2}\n").unwrap();
            }
            "experimental-descriptor" => {
                fs::write(root.join("store.json"), b"{\"version\":1}\n").unwrap();
            }
            "mixed" => {
                fs::write(
                    root.join("descriptor.json"),
                    b"{\"format\":\"malm-state\",\"version\":1}\n",
                )
                .unwrap();
                fs::write(root.join("format.json"), b"{\"version\":2}\n").unwrap();
            }
            "malformed" => fs::write(root.join("descriptor.json"), b"{not-json\n").unwrap(),
            "unsupported" => fs::write(
                root.join("descriptor.json"),
                b"{\"format\":\"malm-state\",\"version\":2}\n",
            )
            .unwrap(),
            _ => unreachable!(),
        }
        for path in tree_paths(&root) {
            if path.is_file() {
                fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
            }
        }
        let paths = tree_paths(&root);
        let before = snapshot(&root, &paths);

        let output = run_store(Some(&home), Some(state_home.as_os_str()));
        assert_eq!(
            output.status.code(),
            Some(2),
            "{case} unexpectedly initialized: {}",
            String::from_utf8_lossy(&output.stdout)
        );
        assert_eq!(tree_paths(&root), paths, "{case} changed root membership");
        assert_eq!(snapshot(&root, &paths), before, "{case} changed root data");
        assert!(!root.join("transaction.lock").exists());
        assert!(!root.join("maintenance.lock").exists());
        assert!(fs::read_dir(&root).unwrap().all(|entry| {
            !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .contains("staging")
        }));
    }
}
