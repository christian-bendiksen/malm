use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use malm::{
    Engine, EngineConfig, EngineError, GitAcquisitionConfig, GitAcquisitionIssue, GitCommandStage,
    GraphAcquisitionError, GraphAcquisitionInputs, PackObjectPublication, StoreAccess,
};
use malm_pack::{
    DependencySourceV1, GitObjectId, GitSourceV1, GitUrl, LockV1, LockedDependencyV1, LockedPackV1,
    LockedSourceV1, PackDependencyV1, PackFileV1, PackManifestV1, PackPath, PackSubdir,
    encode_lock_v1, encode_pack_v1, pack_content_digest,
};
use malm_types::{Alias, Digest, PackageId};

const REAL_GIT: &str = "/usr/bin/git";
const MINIMAL_PACK: &[u8] = include_bytes!("../schemas/pack/v1/fixtures/valid/minimal.kdl");

fn initialized_engine(parent: &Path) -> Engine {
    let state_home = parent.join("state");
    fs::create_dir(&state_home).unwrap();
    fs::set_permissions(&state_home, fs::Permissions::from_mode(0o700)).unwrap();
    let engine = Engine::new(
        EngineConfig::from_state_home(&state_home, StoreAccess::ReadWrite).unwrap(),
        malm::EnginePorts::system(),
    );
    engine.initialize_store().unwrap();
    engine
}

fn run_git(arguments: &[&str]) -> Vec<u8> {
    let output = Command::new(REAL_GIT)
        .args(arguments)
        .env_clear()
        .env("LC_ALL", "C")
        .env("HOME", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "git {arguments:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    output.stdout
}

struct RepositoryFixture {
    root: PathBuf,
    commit: String,
    digest: Digest,
    files: Vec<PackFileV1>,
}

fn repository_fixture(
    parent: &Path,
    format: &str,
    selected_subdir: Option<&str>,
) -> RepositoryFixture {
    let root = parent.join("repository");
    run_git(&[
        "init",
        "--quiet",
        &format!("--object-format={format}"),
        root.to_str().unwrap(),
    ]);
    let pack_root = selected_subdir.map_or_else(|| root.clone(), |subdir| root.join(subdir));
    fs::create_dir_all(&pack_root).unwrap();
    let data = format!("{format} committed bytes\n").into_bytes();
    fs::write(pack_root.join("malm-pack.kdl"), MINIMAL_PACK).unwrap();
    fs::write(pack_root.join("data.bin"), &data).unwrap();
    if selected_subdir.is_some() {
        fs::write(root.join("outside-selected-pack"), b"not selected\n").unwrap();
    }
    run_git(&["-C", root.to_str().unwrap(), "add", "--all"]);
    run_git(&[
        "-C",
        root.to_str().unwrap(),
        "-c",
        "user.name=Malm Test",
        "-c",
        "user.email=malm@example.invalid",
        "commit",
        "--quiet",
        "-m",
        "fixture",
    ]);
    let commit = String::from_utf8(run_git(&[
        "-C",
        root.to_str().unwrap(),
        "rev-parse",
        "HEAD",
    ]))
    .unwrap()
    .trim()
    .to_owned();
    let mut files = vec![
        PackFileV1::new(PackPath::new("malm-pack.kdl").unwrap(), MINIMAL_PACK),
        PackFileV1::new(PackPath::new("data.bin").unwrap(), data),
    ];
    files.sort_by(|left, right| left.path().cmp(right.path()));
    let digest = pack_content_digest(files.iter().map(|file| (file.path(), file.bytes()))).unwrap();
    RepositoryFixture {
        root,
        commit,
        digest,
        files,
    }
}

fn source(format: &str, commit: &str, subdir: &str) -> GitSourceV1 {
    GitSourceV1::new(
        GitUrl::new(format!("https://example.invalid/{format}.git")).unwrap(),
        GitObjectId::new(format!("{format}-{commit}")).unwrap(),
        PackSubdir::new(subdir).unwrap(),
    )
}

fn create_scratch(parent: &Path, name: &str) -> PathBuf {
    let path = parent.join(name);
    fs::create_dir(&path).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
    path
}

fn write_git_wrapper(parent: &Path, remote: &Path, log: &Path) -> PathBuf {
    let wrapper = parent.join("git-wrapper");
    let script = format!(
        "#!/bin/sh\n\
         log={}\n\
         real={}\n\
         remote={}\n\
         printf '%s\\000' BEGIN >> \"$log\"\n\
         fetch=0\n\
         git_dir=.\n\
         last=\n\
         for arg in \"$@\"; do\n\
           printf '%s\\000' \"$arg\" >> \"$log\"\n\
           case \"$arg\" in\n\
             --git-dir=*) git_dir=${{arg#--git-dir=}} ;;\n\
             fetch) fetch=1 ;;\n\
           esac\n\
           last=$arg\n\
         done\n\
         printf '%s\\000' END >> \"$log\"\n\
         if [ \"$fetch\" = 1 ]; then\n\
           GIT_ALLOW_PROTOCOL=file exec \"$real\" -c protocol.file.allow=always --git-dir=\"$git_dir\" fetch --quiet --no-tags --no-write-fetch-head --no-recurse-submodules --no-auto-maintenance --no-write-commit-graph \"$remote\" \"$last\"\n\
         fi\n\
         exec \"$real\" \"$@\"\n",
        shell_literal(log),
        shell_literal(Path::new(REAL_GIT)),
        shell_literal(remote),
    );
    fs::write(&wrapper, script).unwrap();
    fs::set_permissions(&wrapper, fs::Permissions::from_mode(0o700)).unwrap();
    wrapper
}

fn shell_literal(path: &Path) -> String {
    format!("'{}'", path.to_string_lossy().replace('\'', "'\\''"))
}

fn logged_arguments(path: &Path) -> Vec<String> {
    fs::read(path)
        .unwrap()
        .split(|byte| *byte == 0)
        .filter(|part| !part.is_empty())
        .map(|part| String::from_utf8(part.to_vec()).unwrap())
        .collect()
}

fn object_path(engine: &Engine, digest: &Digest) -> PathBuf {
    engine
        .config()
        .state_root()
        .join("objects/pack-manifests")
        .join(digest.as_str())
}

#[test]
fn exact_sha1_and_sha256_commits_publish_and_reuse_offline() {
    for format in ["sha1", "sha256"] {
        let temp = tempfile::tempdir().unwrap();
        let case = temp.path().join(format);
        fs::create_dir(&case).unwrap();
        let engine = initialized_engine(&case);
        let fixture = repository_fixture(&case, format, None);
        let log = case.join("git.log");
        let wrapper = write_git_wrapper(&case, &fixture.root, &log);
        let scratch = create_scratch(&case, "scratch");
        let git = GitAcquisitionConfig::new(&wrapper).unwrap();
        let git_source = source(format, &fixture.commit, ".");

        assert_eq!(
            engine
                .acquire_and_publish_git_pack_v1(&git_source, &fixture.digest, &git, &scratch,)
                .unwrap(),
            PackObjectPublication::Published
        );
        assert_eq!(
            engine.load_pack_object_v1(&fixture.digest).unwrap(),
            fixture.files
        );

        let arguments = logged_arguments(&log);
        assert!(arguments.iter().any(|argument| argument == "fetch"));
        assert!(
            arguments
                .iter()
                .any(|argument| argument == git_source.url().as_str())
        );
        assert!(arguments.iter().any(|argument| argument == &fixture.commit));
        assert!(arguments.windows(2).any(|arguments| {
            arguments[0] == "-c" && arguments[1] == "http.followRedirects=false"
        }));
        for forbidden in ["clone", "archive", "checkout", "ls-remote"] {
            assert!(!arguments.iter().any(|argument| argument == forbidden));
        }

        let unavailable = GitAcquisitionConfig::new("/definitely/missing/git").unwrap();
        assert_eq!(
            engine
                .acquire_and_publish_git_pack_v1(
                    &git_source,
                    &fixture.digest,
                    &unavailable,
                    Path::new("/definitely/missing/scratch"),
                )
                .unwrap(),
            PackObjectPublication::Reused
        );
    }
}

#[test]
fn selected_subdirectory_is_rooted_and_digest_mismatch_is_not_published() {
    let temp = tempfile::tempdir().unwrap();
    let engine = initialized_engine(temp.path());
    let fixture = repository_fixture(temp.path(), "sha1", Some("pack"));
    let log = temp.path().join("git.log");
    let wrapper = write_git_wrapper(temp.path(), &fixture.root, &log);
    let scratch = create_scratch(temp.path(), "scratch");
    let git = GitAcquisitionConfig::new(wrapper).unwrap();
    let git_source = source("sha1", &fixture.commit, "pack");

    assert_eq!(
        engine
            .acquire_and_publish_git_pack_v1(&git_source, &fixture.digest, &git, &scratch,)
            .unwrap(),
        PackObjectPublication::Published
    );
    assert_eq!(
        engine.load_pack_object_v1(&fixture.digest).unwrap(),
        fixture.files
    );

    let wrong = Digest::sha256(b"wrong selected-tree digest");
    let second_scratch = create_scratch(temp.path(), "scratch-mismatch");
    let error = engine
        .acquire_and_publish_git_pack_v1(&git_source, &wrong, &git, &second_scratch)
        .unwrap_err();
    assert!(matches!(
        error,
        EngineError::GitAcquisition {
            reason: GitAcquisitionIssue::DigestMismatch { expected, actual },
            ..
        } if expected == wrong && actual == fixture.digest
    ));
    assert!(!object_path(&engine, &wrong).exists());
}

#[test]
fn committed_symlinks_are_rejected_before_publication() {
    let temp = tempfile::tempdir().unwrap();
    let engine = initialized_engine(temp.path());
    let repository = temp.path().join("repository");
    run_git(&[
        "init",
        "--quiet",
        "--object-format=sha1",
        repository.to_str().unwrap(),
    ]);
    fs::write(repository.join("malm-pack.kdl"), MINIMAL_PACK).unwrap();
    std::os::unix::fs::symlink("malm-pack.kdl", repository.join("linked")).unwrap();
    run_git(&["-C", repository.to_str().unwrap(), "add", "--all"]);
    run_git(&[
        "-C",
        repository.to_str().unwrap(),
        "-c",
        "user.name=Malm Test",
        "-c",
        "user.email=malm@example.invalid",
        "commit",
        "--quiet",
        "-m",
        "symlink",
    ]);
    let commit = String::from_utf8(run_git(&[
        "-C",
        repository.to_str().unwrap(),
        "rev-parse",
        "HEAD",
    ]))
    .unwrap()
    .trim()
    .to_owned();
    let git_source = source("sha1", &commit, ".");
    let log = temp.path().join("git.log");
    let wrapper = write_git_wrapper(temp.path(), &repository, &log);
    let scratch = create_scratch(temp.path(), "scratch");
    let expected = Digest::sha256(b"not published");

    assert!(matches!(
        engine.acquire_and_publish_git_pack_v1(
            &git_source,
            &expected,
            &GitAcquisitionConfig::new(wrapper).unwrap(),
            &scratch,
        ),
        Err(EngineError::GitAcquisition {
            reason: GitAcquisitionIssue::SymbolicLink { path },
            ..
        }) if path.as_str() == "linked"
    ));
    assert!(!object_path(&engine, &expected).exists());
}

/// A manifest that declares capture roots narrows the local walk, and Git
/// acquisition must narrow the same way. Otherwise a lock written from a checkout
/// never matches the digest of the same commit fetched over Git.
#[test]
fn declared_capture_roots_narrow_git_acquisition_exactly_like_local_capture() {
    let temp = tempfile::tempdir().unwrap();
    // Separate stores keep either adapter from reusing the other's published
    // pack object, so both recompute the digest from real bytes.
    let local_home = temp.path().join("local");
    let git_home = temp.path().join("git");
    fs::create_dir(&local_home).unwrap();
    fs::create_dir(&git_home).unwrap();
    let local_engine = initialized_engine(&local_home);
    let git_engine = initialized_engine(&git_home);
    let manifest = encode_pack_v1(
        &malm_pack::decode_pack_v1(MINIMAL_PACK)
            .unwrap()
            .with_capture_roots(vec![PackPath::new("captured").unwrap()])
            .unwrap(),
    )
    .into_bytes();

    let repository = temp.path().join("narrowed");
    run_git(&[
        "init",
        "--quiet",
        "--object-format=sha1",
        repository.to_str().unwrap(),
    ]);
    fs::write(repository.join("malm-pack.kdl"), &manifest).unwrap();
    fs::create_dir(repository.join("captured")).unwrap();
    fs::write(repository.join("captured/inside.conf"), b"inside\n").unwrap();
    // Committed, but outside the declared roots. Neither adapter may digest it.
    fs::write(repository.join("README.md"), b"outside\n").unwrap();
    fs::create_dir(repository.join("elsewhere")).unwrap();
    fs::write(repository.join("elsewhere/skipped.bin"), b"outside\n").unwrap();
    run_git(&["-C", repository.to_str().unwrap(), "add", "--all"]);
    run_git(&[
        "-C",
        repository.to_str().unwrap(),
        "-c",
        "user.name=Malm Test",
        "-c",
        "user.email=malm@example.invalid",
        "commit",
        "--quiet",
        "-m",
        "narrowed",
    ]);
    let commit = String::from_utf8(run_git(&[
        "-C",
        repository.to_str().unwrap(),
        "rev-parse",
        "HEAD",
    ]))
    .unwrap()
    .trim()
    .to_owned();

    let captured = vec![
        PackFileV1::new(PackPath::new("captured/inside.conf").unwrap(), b"inside\n"),
        PackFileV1::new(PackPath::new("malm-pack.kdl").unwrap(), manifest),
    ];
    let digest =
        pack_content_digest(captured.iter().map(|file| (file.path(), file.bytes()))).unwrap();

    // Capture rejects any other digest, so publishing at this one pins the
    // captured set.
    local_engine
        .capture_and_publish_local_pack_v1(&repository, &digest)
        .unwrap();
    assert_eq!(local_engine.load_pack_object_v1(&digest).unwrap(), captured);

    // Nothing is cached in this store, so the commit is fetched and narrowed.
    let log = temp.path().join("git.log");
    let wrapper = write_git_wrapper(temp.path(), &repository, &log);
    let scratch = create_scratch(temp.path(), "narrowed-scratch");
    assert_eq!(
        git_engine
            .acquire_and_publish_git_pack_v1(
                &source("sha1", &commit, "."),
                &digest,
                &GitAcquisitionConfig::new(wrapper).unwrap(),
                &scratch,
            )
            .unwrap(),
        PackObjectPublication::Published
    );
    assert_eq!(git_engine.load_pack_object_v1(&digest).unwrap(), captured);
    assert!(
        logged_arguments(&log)
            .iter()
            .any(|argument| argument == "fetch")
    );
}

#[test]
fn exact_tag_object_is_rejected_without_peeling() {
    let temp = tempfile::tempdir().unwrap();
    let engine = initialized_engine(temp.path());
    let fixture = repository_fixture(temp.path(), "sha1", None);
    run_git(&[
        "-C",
        fixture.root.to_str().unwrap(),
        "-c",
        "user.name=Malm Test",
        "-c",
        "user.email=malm@example.invalid",
        "tag",
        "-a",
        "v1",
        "-m",
        "annotated tag",
    ]);
    let tag_oid = String::from_utf8(run_git(&[
        "-C",
        fixture.root.to_str().unwrap(),
        "rev-parse",
        "refs/tags/v1^{tag}",
    ]))
    .unwrap()
    .trim()
    .to_owned();
    let git_source = source("sha1", &tag_oid, ".");
    let log = temp.path().join("git.log");
    let wrapper = write_git_wrapper(temp.path(), &fixture.root, &log);
    let scratch = create_scratch(temp.path(), "scratch");
    let expected = Digest::sha256(b"tag object must not be peeled");

    assert!(matches!(
        engine.acquire_and_publish_git_pack_v1(
            &git_source,
            &expected,
            &GitAcquisitionConfig::new(wrapper).unwrap(),
            &scratch,
        ),
        Err(EngineError::GitAcquisition {
            reason: GitAcquisitionIssue::UnexpectedObjectType {
                expected: malm::GitObjectKind::Commit,
                actual,
                ..
            },
            ..
        }) if actual == "tag"
    ));
    assert!(!object_path(&engine, &expected).exists());
}

#[test]
fn mixed_locked_graph_acquires_once_then_assembles_without_git_or_scratch() {
    let temp = tempfile::tempdir().unwrap();
    let engine = initialized_engine(temp.path());
    let remote = repository_fixture(temp.path(), "sha1", None);
    let git_source = source("sha1", &remote.commit, ".");
    let root_path = temp.path().join("root-pack");
    fs::create_dir(&root_path).unwrap();
    let dependency_alias = Alias::new("remote").unwrap();
    let root_manifest = PackManifestV1::new(
        PackageId::new("com.example.root").unwrap(),
        vec![],
        vec![PackDependencyV1::new(
            dependency_alias.clone(),
            PackageId::new("com.example.minimal").unwrap(),
            DependencySourceV1::Git(git_source.clone()),
        )],
        vec![],
        vec![],
        vec![],
        vec![],
    )
    .unwrap();
    let root_manifest_bytes = encode_pack_v1(&root_manifest);
    fs::write(root_path.join("malm-pack.kdl"), &root_manifest_bytes).unwrap();
    let root_files = [PackFileV1::new(
        PackPath::new("malm-pack.kdl").unwrap(),
        root_manifest_bytes,
    )];
    let root_digest =
        pack_content_digest(root_files.iter().map(|file| (file.path(), file.bytes()))).unwrap();
    let remote_node = LockedPackV1::new(
        PackageId::new("com.example.minimal").unwrap(),
        LockedSourceV1::Git(git_source.clone()),
        remote.digest.clone(),
        vec![],
        vec![],
    )
    .unwrap();
    let root_node = LockedPackV1::new(
        PackageId::new("com.example.root").unwrap(),
        LockedSourceV1::Root,
        root_digest,
        vec![LockedDependencyV1::new(
            dependency_alias,
            remote_node.node_id().clone(),
        )],
        vec![],
    )
    .unwrap();
    let lock = LockV1::new(
        root_node.node_id().clone(),
        vec![root_node.clone(), remote_node.clone()],
    )
    .unwrap();
    let lock_before = encode_lock_v1(&lock);
    let log = temp.path().join("git.log");
    let wrapper = write_git_wrapper(temp.path(), &remote.root, &log);
    let scratch = create_scratch(temp.path(), "scratch");

    let ungranted = GraphAcquisitionInputs::new(
        BTreeSet::new(),
        BTreeSet::new(),
        BTreeMap::from([(remote.digest.clone(), scratch.clone())]),
    );
    assert!(matches!(
        engine.acquire_locked_graph_v1(
            &root_path,
            &lock,
            &ungranted,
            &GitAcquisitionConfig::new(&wrapper).unwrap(),
        ),
        Err(GraphAcquisitionError::GitSourceNotGranted { node_id, .. })
            if node_id == *remote_node.node_id()
    ));
    assert!(!engine.config().state_root().join("objects").exists());

    let no_scratch = GraphAcquisitionInputs::new(
        BTreeSet::new(),
        BTreeSet::from([git_source.url().clone()]),
        BTreeMap::new(),
    );
    assert!(matches!(
        engine.acquire_locked_graph_v1(
            &root_path,
            &lock,
            &no_scratch,
            &GitAcquisitionConfig::new(&wrapper).unwrap(),
        ),
        Err(GraphAcquisitionError::MissingGitScratch { digest })
            if digest == remote.digest
    ));
    assert!(!engine.config().state_root().join("objects").exists());

    let inputs = GraphAcquisitionInputs::new(
        BTreeSet::new(),
        BTreeSet::from([git_source.url().clone()]),
        BTreeMap::from([(remote.digest.clone(), scratch)]),
    );
    let graph = engine
        .acquire_locked_graph_v1(
            &root_path,
            &lock,
            &inputs,
            &GitAcquisitionConfig::new(&wrapper).unwrap(),
        )
        .unwrap();
    assert_eq!(graph.root_node_id(), root_node.node_id());
    assert_eq!(
        graph.dependency_order(),
        &[remote_node.node_id().clone(), root_node.node_id().clone()]
    );
    assert_eq!(encode_lock_v1(&lock), lock_before);

    fs::remove_file(wrapper).unwrap();
    let offline_inputs = GraphAcquisitionInputs::new(
        BTreeSet::new(),
        BTreeSet::from([git_source.url().clone()]),
        BTreeMap::new(),
    );
    let offline = engine
        .acquire_locked_graph_v1(
            &root_path,
            &lock,
            &offline_inputs,
            &GitAcquisitionConfig::new("/definitely/missing/git").unwrap(),
        )
        .unwrap();
    assert_eq!(offline.graph_digest(), graph.graph_digest());
    assert_eq!(encode_lock_v1(&lock), lock_before);
}

#[test]
fn scratch_validation_precedes_process_execution() {
    let temp = tempfile::tempdir().unwrap();
    let engine = initialized_engine(temp.path());
    let git_source = source("sha1", &"1".repeat(40), ".");
    let expected = Digest::sha256(b"missing");
    let git = GitAcquisitionConfig::new("/definitely/missing/git").unwrap();

    assert!(matches!(
        engine
            .acquire_and_publish_git_pack_v1(&git_source, &expected, &git, Path::new("relative"),),
        Err(EngineError::GitAcquisition {
            reason: GitAcquisitionIssue::ScratchRootMustBeAbsolute,
            ..
        })
    ));

    let wrong_mode = create_scratch(temp.path(), "wrong-mode");
    fs::set_permissions(&wrong_mode, fs::Permissions::from_mode(0o755)).unwrap();
    assert!(matches!(
        engine.acquire_and_publish_git_pack_v1(&git_source, &expected, &git, &wrong_mode),
        Err(EngineError::GitAcquisition {
            reason: GitAcquisitionIssue::ScratchRootUnexpectedMode {
                expected: 0o700,
                actual: 0o755
            },
            ..
        })
    ));

    let nonempty = create_scratch(temp.path(), "nonempty");
    fs::write(nonempty.join("sentinel"), b"preserve").unwrap();
    assert!(matches!(
        engine.acquire_and_publish_git_pack_v1(&git_source, &expected, &git, &nonempty),
        Err(EngineError::GitAcquisition {
            reason: GitAcquisitionIssue::ScratchRootNotEmpty,
            ..
        })
    ));
    assert_eq!(fs::read(nonempty.join("sentinel")).unwrap(), b"preserve");

    assert!(matches!(
        engine.acquire_and_publish_git_pack_v1(
            &git_source,
            &expected,
            &git,
            engine.config().state_root(),
        ),
        Err(EngineError::GitAcquisition {
            reason: GitAcquisitionIssue::ProtectedStateOverlap,
            ..
        })
    ));
}

#[test]
fn timed_out_git_process_group_is_terminated() {
    let temp = tempfile::tempdir().unwrap();
    let engine = initialized_engine(temp.path());
    let wrapper = temp.path().join("slow-git");
    fs::write(&wrapper, "#!/bin/sh\n/bin/sleep 30 &\nwait\n").unwrap();
    fs::set_permissions(&wrapper, fs::Permissions::from_mode(0o700)).unwrap();
    let scratch = create_scratch(temp.path(), "scratch");
    let git = GitAcquisitionConfig::with_timeout(&wrapper, Duration::from_millis(100)).unwrap();
    let git_source = source("sha1", &"1".repeat(40), ".");
    let started = Instant::now();

    assert!(matches!(
        engine.acquire_and_publish_git_pack_v1(
            &git_source,
            &Digest::sha256(b"missing"),
            &git,
            &scratch,
        ),
        Err(EngineError::GitAcquisition {
            reason: GitAcquisitionIssue::Timeout {
                stage: GitCommandStage::Initialize,
                ..
            },
            ..
        })
    ));
    assert!(started.elapsed() < Duration::from_secs(2));
}

#[test]
fn git_descendants_cannot_leave_the_bounded_process_group() {
    let temp = tempfile::tempdir().unwrap();
    let engine = initialized_engine(temp.path());
    let wrapper = temp.path().join("escaping-git");
    let escaped = temp.path().join("escaped");
    let script = format!(
        "#!/bin/sh\n\
         if /usr/bin/setsid /bin/true 2>/dev/null; then\n\
           /usr/bin/touch {}\n\
         fi\n\
         exit 1\n",
        shell_literal(&escaped),
    );
    fs::write(&wrapper, script).unwrap();
    fs::set_permissions(&wrapper, fs::Permissions::from_mode(0o700)).unwrap();
    let scratch = create_scratch(temp.path(), "scratch");
    let git = GitAcquisitionConfig::with_timeout(&wrapper, Duration::from_secs(2)).unwrap();
    let git_source = source("sha1", &"1".repeat(40), ".");

    assert!(matches!(
        engine.acquire_and_publish_git_pack_v1(
            &git_source,
            &Digest::sha256(b"must not publish"),
            &git,
            &scratch,
        ),
        Err(EngineError::GitAcquisition {
            reason: GitAcquisitionIssue::ProcessFailed {
                stage: GitCommandStage::Initialize,
                ..
            },
            ..
        })
    ));
    assert!(!escaped.exists());
}

#[test]
fn oversized_fetch_file_is_stopped_at_the_transfer_limit() {
    let temp = tempfile::tempdir().unwrap();
    let engine = initialized_engine(temp.path());
    let wrapper = temp.path().join("oversized-git");
    fs::write(
        &wrapper,
        "#!/bin/sh\n\
         fetch=0\n\
         for arg in \"$@\"; do\n\
           if [ \"$arg\" = fetch ]; then fetch=1; fi\n\
         done\n\
         if [ \"$fetch\" = 1 ]; then\n\
           exec /bin/dd if=/dev/zero of=oversized.pack bs=4096 count=64 status=none\n\
         fi\n\
         exec /usr/bin/git \"$@\"\n",
    )
    .unwrap();
    fs::set_permissions(&wrapper, fs::Permissions::from_mode(0o700)).unwrap();
    let scratch = create_scratch(temp.path(), "scratch");
    let limit = 32 * 1024;
    let git = GitAcquisitionConfig::with_limits(&wrapper, Duration::from_secs(5), limit).unwrap();
    let git_source = source("sha1", &"1".repeat(40), ".");
    let expected = Digest::sha256(b"must not publish");

    assert!(matches!(
        engine.acquire_and_publish_git_pack_v1(&git_source, &expected, &git, &scratch),
        Err(EngineError::GitAcquisition {
            reason: GitAcquisitionIssue::TransferLimitExceeded {
                stage: GitCommandStage::Fetch,
                limit: actual_limit,
            },
            ..
        }) if actual_limit == limit
    ));
    assert!(fs::metadata(scratch.join("oversized.pack")).unwrap().len() <= limit);
    assert!(!object_path(&engine, &expected).exists());
}

#[test]
fn aggregate_transfer_overflow_terminates_the_process_group() {
    let temp = tempfile::tempdir().unwrap();
    let engine = initialized_engine(temp.path());
    let wrapper = temp.path().join("aggregate-git");
    fs::write(
        &wrapper,
        "#!/bin/sh\n\
         fetch=0\n\
         for arg in \"$@\"; do\n\
           if [ \"$arg\" = fetch ]; then fetch=1; fi\n\
         done\n\
         if [ \"$fetch\" = 1 ]; then\n\
           /bin/dd if=/dev/zero of=first.pack bs=4096 count=6 status=none\n\
           /bin/dd if=/dev/zero of=second.pack bs=4096 count=6 status=none\n\
           /bin/sleep 30 &\n\
           wait\n\
         fi\n\
         exec /usr/bin/git \"$@\"\n",
    )
    .unwrap();
    fs::set_permissions(&wrapper, fs::Permissions::from_mode(0o700)).unwrap();
    let scratch = create_scratch(temp.path(), "scratch");
    let limit = 32 * 1024;
    let git = GitAcquisitionConfig::with_limits(&wrapper, Duration::from_secs(5), limit).unwrap();
    let git_source = source("sha1", &"1".repeat(40), ".");
    let expected = Digest::sha256(b"must not publish");
    let started = Instant::now();

    assert!(matches!(
        engine.acquire_and_publish_git_pack_v1(&git_source, &expected, &git, &scratch),
        Err(EngineError::GitAcquisition {
            reason: GitAcquisitionIssue::TransferLimitExceeded {
                stage: GitCommandStage::Fetch,
                limit: actual_limit,
            },
            ..
        }) if actual_limit == limit
    ));
    assert!(started.elapsed() < Duration::from_secs(2));
    assert!(!object_path(&engine, &expected).exists());
}

#[test]
fn exited_group_leader_cannot_leave_a_pipe_holding_descendant() {
    let temp = tempfile::tempdir().unwrap();
    let engine = initialized_engine(temp.path());
    let wrapper = temp.path().join("forking-git");
    let script = format!(
        "#!/bin/sh\n\
         init=0\n\
         for arg in \"$@\"; do\n\
           if [ \"$arg\" = init ]; then init=1; fi\n\
         done\n\
         if [ \"$init\" = 1 ]; then\n\
           /bin/sleep 30 &\n\
           exec {} \"$@\"\n\
         fi\n\
         exit 1\n",
        shell_literal(Path::new(REAL_GIT)),
    );
    fs::write(&wrapper, script).unwrap();
    fs::set_permissions(&wrapper, fs::Permissions::from_mode(0o700)).unwrap();
    let scratch = create_scratch(temp.path(), "scratch");
    let git = GitAcquisitionConfig::with_timeout(&wrapper, Duration::from_secs(2)).unwrap();
    let git_source = source("sha1", &"1".repeat(40), ".");
    let started = Instant::now();

    assert!(matches!(
        engine.acquire_and_publish_git_pack_v1(
            &git_source,
            &Digest::sha256(b"must not publish"),
            &git,
            &scratch,
        ),
        Err(EngineError::GitAcquisition {
            reason: GitAcquisitionIssue::ProcessFailed {
                stage: GitCommandStage::Fetch,
                ..
            },
            ..
        })
    ));
    assert!(started.elapsed() < Duration::from_secs(1));
}
