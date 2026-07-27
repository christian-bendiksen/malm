use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::os::unix::fs::symlink;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;

use malm::{
    Engine, EngineConfig, GitAcquisitionConfig, LockFileIssue, LockFilePublication,
    LockOperationError, LockResolutionInputs, StoreAccess,
};
use malm_pack::{
    BundledComponentV1, ComponentInterfaceV1, DependencySourceV1, GitObjectId, GitSourceV1, GitUrl,
    LOCK_FILE, LOCK_STAGING_FILE, LocalLocator, LockValidationError, LockedSourceV1,
    PackDependencyV1, PackFileV1, PackManifestV1, PackModuleV1, PackPath, PackSubdir,
    decode_lock_v1, encode_lock_v1, encode_pack_v1, pack_content_digest,
};
use malm_types::{Alias, ContributionName, Digest, PackageId};

const MINIMAL_PACK: &[u8] = include_bytes!("../schemas/pack/v1/fixtures/valid/minimal.kdl");
const REAL_GIT: &str = "/usr/bin/git";

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

fn package(value: &str) -> PackageId {
    PackageId::new(value).unwrap()
}

fn locator(value: &str) -> LocalLocator {
    LocalLocator::new(value).unwrap()
}

fn dependency(alias: &str, package_id: &str, locator: &LocalLocator) -> PackDependencyV1 {
    PackDependencyV1::new(
        Alias::new(alias).unwrap(),
        package(package_id),
        DependencySourceV1::Local(locator.clone()),
    )
}

fn write_pack(
    root: &Path,
    package_id: &str,
    module: &str,
    dependencies: Vec<PackDependencyV1>,
    module_bytes: &[u8],
) -> Digest {
    fs::create_dir_all(root.join("modules")).unwrap();
    let module_path = PackPath::new(format!("modules/{module}.kdl")).unwrap();
    let manifest = PackManifestV1::new(
        package(package_id),
        vec![PackModuleV1::new(
            ContributionName::new(module).unwrap(),
            module_path.clone(),
        )],
        dependencies,
        vec![],
        vec![],
        vec![],
        vec![],
    )
    .unwrap();
    let manifest_bytes = encode_pack_v1(&manifest);
    fs::write(root.join("malm-pack.kdl"), &manifest_bytes).unwrap();
    fs::write(root.join(module_path.as_str()), module_bytes).unwrap();
    let files = [
        PackFileV1::new(PackPath::new("malm-pack.kdl").unwrap(), manifest_bytes),
        PackFileV1::new(module_path, module_bytes),
    ];
    pack_content_digest(files.iter().map(|file| (file.path(), file.bytes()))).unwrap()
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

fn git_repository(parent: &Path) -> (PathBuf, String) {
    let repository = parent.join("repository");
    run_git(&[
        "init",
        "--quiet",
        "--object-format=sha1",
        repository.to_str().unwrap(),
    ]);
    fs::write(repository.join("malm-pack.kdl"), MINIMAL_PACK).unwrap();
    fs::write(repository.join("data.bin"), b"remote bytes\n").unwrap();
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
        "fixture",
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
    (repository, commit)
}

fn shell_literal(path: &Path) -> String {
    format!("'{}'", path.to_string_lossy().replace('\'', "'\\''"))
}

fn write_git_wrapper(parent: &Path, remote: &Path) -> PathBuf {
    let wrapper = parent.join("git-wrapper");
    let script = format!(
        "#!/bin/sh\n\
         real={}\n\
         remote={}\n\
         fetch=0\n\
         git_dir=.\n\
         last=\n\
         for arg in \"$@\"; do\n\
           case \"$arg\" in\n\
             --git-dir=*) git_dir=${{arg#--git-dir=}} ;;\n\
             fetch) fetch=1 ;;\n\
           esac\n\
           last=$arg\n\
         done\n\
         if [ \"$fetch\" = 1 ]; then\n\
           GIT_ALLOW_PROTOCOL=file exec \"$real\" -c protocol.file.allow=always --git-dir=\"$git_dir\" fetch --quiet --no-tags --no-write-fetch-head --no-recurse-submodules --no-auto-maintenance --no-write-commit-graph \"$remote\" \"$last\"\n\
         fi\n\
         exec \"$real\" \"$@\"\n",
        shell_literal(Path::new(REAL_GIT)),
        shell_literal(remote),
    );
    fs::write(&wrapper, script).unwrap();
    fs::set_permissions(&wrapper, fs::Permissions::from_mode(0o700)).unwrap();
    wrapper
}

fn create_scratch(parent: &Path) -> PathBuf {
    let scratch = parent.join("scratch");
    fs::create_dir(&scratch).unwrap();
    fs::set_permissions(&scratch, fs::Permissions::from_mode(0o700)).unwrap();
    scratch
}

fn object_path(engine: &Engine, digest: &Digest) -> PathBuf {
    // Deduplicated packs publish their manifest under the content digest.
    engine
        .config()
        .state_root()
        .join("objects/pack-manifests")
        .join(digest.as_str())
}

#[test]
fn root_only_lock_create_and_unchanged_update_are_durable() {
    let temp = tempfile::tempdir().unwrap();
    let engine = initialized_engine(temp.path());
    let root = temp.path().join("root-pack");
    fs::create_dir(&root).unwrap();
    fs::write(root.join("malm-pack.kdl"), MINIMAL_PACK).unwrap();
    let inputs = LockResolutionInputs::default();
    let git = GitAcquisitionConfig::new("/definitely/missing/git").unwrap();

    let created = engine.create_lock_v1(&root, &inputs, &git).unwrap();
    assert_eq!(created.publication(), LockFilePublication::Created);
    assert_eq!(created.lock().nodes().len(), 1);
    assert!(matches!(
        created.lock().nodes()[0].source(),
        LockedSourceV1::Root
    ));

    let lock_path = root.join(LOCK_FILE);
    let bytes = fs::read(&lock_path).unwrap();
    assert_eq!(decode_lock_v1(&bytes).unwrap(), *created.lock());
    let metadata = fs::metadata(&lock_path).unwrap();
    assert_eq!(metadata.mode() & 0o7777, 0o644);
    assert_eq!(metadata.nlink(), 1);
    let inode = metadata.ino();

    let stale_staging = root.join(LOCK_STAGING_FILE);
    fs::write(&stale_staging, &bytes).unwrap();
    fs::set_permissions(&stale_staging, fs::Permissions::from_mode(0o644)).unwrap();

    let updated = engine.update_lock_v1(&root, &inputs, &git).unwrap();
    assert_eq!(updated.publication(), LockFilePublication::Unchanged);
    assert_eq!(updated.lock(), created.lock());
    assert_eq!(fs::metadata(&lock_path).unwrap().ino(), inode);
    assert_eq!(fs::read(&lock_path).unwrap(), bytes);
    assert!(!stale_staging.exists());

    let duplicate = engine.create_lock_v1(&root, &inputs, &git);
    assert!(
        matches!(
            &duplicate,
            Err(LockOperationError::LockFile {
                reason: LockFileIssue::AlreadyExists,
                ..
            })
        ),
        "unexpected duplicate-create result: {duplicate:?}"
    );
}

#[test]
fn component_lock_resolution_requires_and_stamps_the_explicit_profile() {
    let temp = tempfile::tempdir().unwrap();
    let engine = initialized_engine(temp.path());
    let root = temp.path().join("root-pack");
    fs::create_dir(&root).unwrap();
    fs::create_dir(root.join("components")).unwrap();
    let component_bytes = b"component bytes";
    let declaration = BundledComponentV1::new(
        ContributionName::new("formatter").unwrap(),
        PackPath::new("components/formatter.wasm").unwrap(),
        Digest::sha256(component_bytes),
        ComponentInterfaceV1::FormatComponentV1,
    );
    let manifest = PackManifestV1::new(
        package("com.example.component"),
        vec![],
        vec![],
        vec![],
        vec![],
        vec![],
        vec![declaration],
    )
    .unwrap();
    fs::write(root.join("malm-pack.kdl"), encode_pack_v1(&manifest)).unwrap();
    fs::write(root.join("components/formatter.wasm"), component_bytes).unwrap();
    let git = GitAcquisitionConfig::new("/definitely/missing/git").unwrap();

    assert!(matches!(
        engine.create_lock_v1(&root, &LockResolutionInputs::default(), &git),
        Err(LockOperationError::MissingFormatComponentExecutionProfile)
    ));
    assert!(!root.join(LOCK_FILE).exists());

    let profile = Digest::sha256(b"explicit format component profile");
    let inputs =
        LockResolutionInputs::default().with_format_component_execution_profile(profile.clone());
    let created = engine.create_lock_v1(&root, &inputs, &git).unwrap();
    let components = created.lock().nodes()[0].components();
    assert_eq!(components.len(), 1);
    assert_eq!(components[0].execution_profile(), &profile);
}

#[test]
fn unrelated_reserved_staging_file_is_preserved_and_rejected() {
    let temp = tempfile::tempdir().unwrap();
    let engine = initialized_engine(temp.path());
    let root = temp.path().join("root-pack");
    fs::create_dir(&root).unwrap();
    fs::write(root.join("malm-pack.kdl"), MINIMAL_PACK).unwrap();
    let inputs = LockResolutionInputs::default();
    let git = GitAcquisitionConfig::new("/definitely/missing/git").unwrap();
    engine.create_lock_v1(&root, &inputs, &git).unwrap();
    let lock_before = fs::read(root.join(LOCK_FILE)).unwrap();
    let staging = root.join(LOCK_STAGING_FILE);
    fs::write(&staging, b"caller data\n").unwrap();
    fs::set_permissions(&staging, fs::Permissions::from_mode(0o644)).unwrap();

    assert!(matches!(
        engine.update_lock_v1(&root, &inputs, &git),
        Err(LockOperationError::LockFile {
            reason: LockFileIssue::UnsafeStaging,
            ..
        })
    ));
    assert_eq!(fs::read(staging).unwrap(), b"caller data\n");
    assert_eq!(fs::read(root.join(LOCK_FILE)).unwrap(), lock_before);
}

#[test]
fn cooperative_root_lock_prevents_overlapping_lock_operations() {
    let temp = tempfile::tempdir().unwrap();
    let engine = initialized_engine(temp.path());
    let root = temp.path().join("root-pack");
    fs::create_dir(&root).unwrap();
    fs::write(root.join("malm-pack.kdl"), MINIMAL_PACK).unwrap();
    let inputs = LockResolutionInputs::default();
    let git = GitAcquisitionConfig::new("/definitely/missing/git").unwrap();
    engine.create_lock_v1(&root, &inputs, &git).unwrap();

    let held = fs::File::open(&root).unwrap();
    rustix::fs::flock(&held, rustix::fs::FlockOperation::NonBlockingLockExclusive).unwrap();
    assert!(matches!(
        engine.update_lock_v1(&root, &inputs, &git),
        Err(LockOperationError::LockFile {
            reason: LockFileIssue::Busy,
            ..
        })
    ));
}

#[test]
fn update_rejects_missing_malformed_and_symbolic_locks_without_source_capture() {
    let temp = tempfile::tempdir().unwrap();
    let engine = initialized_engine(temp.path());
    let root = temp.path().join("root-pack");
    fs::create_dir(&root).unwrap();
    fs::write(root.join("malm-pack.kdl"), MINIMAL_PACK).unwrap();
    let inputs = LockResolutionInputs::default();
    let git = GitAcquisitionConfig::new("/definitely/missing/git").unwrap();
    let lock_path = root.join(LOCK_FILE);

    assert!(matches!(
        engine.update_lock_v1(&root, &inputs, &git),
        Err(LockOperationError::LockFile {
            reason: LockFileIssue::Missing,
            ..
        })
    ));
    assert!(!engine.config().state_root().join("objects").exists());

    fs::write(&lock_path, b"not a lock\n").unwrap();
    fs::set_permissions(&lock_path, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(matches!(
        engine.update_lock_v1(&root, &inputs, &git),
        Err(LockOperationError::LockFile {
            reason: LockFileIssue::Invalid { .. },
            ..
        })
    ));
    assert_eq!(fs::read(&lock_path).unwrap(), b"not a lock\n");
    assert!(!engine.config().state_root().join("objects").exists());

    fs::remove_file(&lock_path).unwrap();
    let target = root.join("lock-target");
    fs::write(&target, b"preserve\n").unwrap();
    symlink(&target, &lock_path).unwrap();
    assert!(matches!(
        engine.update_lock_v1(&root, &inputs, &git),
        Err(LockOperationError::LockFile {
            reason: LockFileIssue::NotRegular,
            ..
        })
    ));
    assert_eq!(fs::read(target).unwrap(), b"preserve\n");
    assert!(!engine.config().state_root().join("objects").exists());
}

#[test]
fn update_rewrites_semantic_json_to_canonical_bytes() {
    let temp = tempfile::tempdir().unwrap();
    let engine = initialized_engine(temp.path());
    let root = temp.path().join("root-pack");
    fs::create_dir(&root).unwrap();
    fs::write(root.join("malm-pack.kdl"), MINIMAL_PACK).unwrap();
    let git = GitAcquisitionConfig::new("/definitely/missing/git").unwrap();
    let created = engine
        .create_lock_v1(&root, &LockResolutionInputs::default(), &git)
        .unwrap();
    let canonical = encode_lock_v1(created.lock());
    let lock_path = root.join(LOCK_FILE);
    let value: serde_json::Value = serde_json::from_slice(&canonical).unwrap();
    let mut compact = serde_json::to_vec(&value).unwrap();
    compact.push(b'\n');
    assert_ne!(compact, canonical);
    fs::write(&lock_path, compact).unwrap();
    fs::set_permissions(&lock_path, fs::Permissions::from_mode(0o644)).unwrap();

    let updated = engine
        .update_lock_v1(&root, &LockResolutionInputs::default(), &git)
        .unwrap();
    assert_eq!(updated.publication(), LockFilePublication::Updated);
    assert_eq!(fs::read(lock_path).unwrap(), canonical);
}

#[test]
fn transitive_local_lock_is_root_relative_and_updates_drift_explicitly() {
    let temp = tempfile::tempdir().unwrap();
    let engine = initialized_engine(temp.path());
    let work = temp.path().join("work");
    let root = work.join("root");
    let middle = work.join("deps/middle");
    let leaf = work.join("shared/leaf");
    let middle_locator = locator("../deps/middle");
    let leaf_locator = locator("../shared/leaf");

    let first_leaf_digest = write_pack(&leaf, "com.example.leaf", "leaf", vec![], b"leaf one\n");
    write_pack(
        &middle,
        "com.example.middle",
        "middle",
        vec![dependency("leaf", "com.example.leaf", &leaf_locator)],
        b"middle\n",
    );
    write_pack(
        &root,
        "com.example.root",
        "root",
        vec![dependency("middle", "com.example.middle", &middle_locator)],
        b"root\n",
    );
    let grants = BTreeSet::from([middle_locator.clone(), leaf_locator.clone()]);
    let inputs = LockResolutionInputs::new(grants.clone(), BTreeSet::new(), BTreeMap::new());
    let git = GitAcquisitionConfig::new("/definitely/missing/git").unwrap();

    let created = engine.create_lock_v1(&root, &inputs, &git).unwrap();
    assert_eq!(created.publication(), LockFilePublication::Created);
    assert_eq!(created.lock().nodes().len(), 3);
    let first_leaf = created
        .lock()
        .nodes()
        .iter()
        .find(|node| node.source() == &LockedSourceV1::Local(leaf_locator.clone()))
        .unwrap();
    assert_eq!(first_leaf.content_digest(), &first_leaf_digest);
    let first_leaf_node = first_leaf.node_id().clone();
    let first_bytes = fs::read(root.join(LOCK_FILE)).unwrap();

    let second_leaf_digest = write_pack(&leaf, "com.example.leaf", "leaf", vec![], b"leaf two\n");
    let updated = engine.update_lock_v1(&root, &inputs, &git).unwrap();
    assert_eq!(updated.publication(), LockFilePublication::Updated);
    let second_leaf = updated
        .lock()
        .nodes()
        .iter()
        .find(|node| node.source() == &LockedSourceV1::Local(leaf_locator.clone()))
        .unwrap();
    assert_eq!(second_leaf.content_digest(), &second_leaf_digest);
    assert_ne!(second_leaf.node_id(), &first_leaf_node);
    assert_ne!(fs::read(root.join(LOCK_FILE)).unwrap(), first_bytes);

    let graph = engine
        .acquire_locked_local_graph_v1(&root, updated.lock(), &grants)
        .unwrap();
    assert_eq!(graph.lock(), updated.lock());
}

#[test]
fn missing_transitive_local_grant_leaves_the_lock_absent() {
    let temp = tempfile::tempdir().unwrap();
    let engine = initialized_engine(temp.path());
    let work = temp.path().join("work");
    let root = work.join("root");
    let middle = work.join("middle");
    let leaf = work.join("leaf");
    let middle_locator = locator("../middle");
    let leaf_locator = locator("../leaf");
    write_pack(&leaf, "com.example.leaf", "leaf", vec![], b"leaf\n");
    write_pack(
        &middle,
        "com.example.middle",
        "middle",
        vec![dependency("leaf", "com.example.leaf", &leaf_locator)],
        b"middle\n",
    );
    write_pack(
        &root,
        "com.example.root",
        "root",
        vec![dependency("middle", "com.example.middle", &middle_locator)],
        b"root\n",
    );
    let inputs = LockResolutionInputs::new(
        BTreeSet::from([middle_locator]),
        BTreeSet::new(),
        BTreeMap::new(),
    );

    assert!(matches!(
        engine.create_lock_v1(
            &root,
            &inputs,
            &GitAcquisitionConfig::new("/definitely/missing/git").unwrap(),
        ),
        Err(LockOperationError::LocalSourceNotGranted { locator })
            if locator == leaf_locator
    ));
    assert!(!root.join(LOCK_FILE).exists());
}

#[test]
fn dependency_package_mismatch_is_rejected_without_a_lock() {
    let temp = tempfile::tempdir().unwrap();
    let engine = initialized_engine(temp.path());
    let root = temp.path().join("work/root");
    let dependency_root = temp.path().join("work/dependency");
    let dependency_locator = locator("../dependency");
    write_pack(
        &dependency_root,
        "com.example.actual",
        "dependency",
        vec![],
        b"dependency\n",
    );
    write_pack(
        &root,
        "com.example.root",
        "root",
        vec![dependency(
            "dependency",
            "com.example.expected",
            &dependency_locator,
        )],
        b"root\n",
    );
    let inputs = LockResolutionInputs::new(
        BTreeSet::from([dependency_locator.clone()]),
        BTreeSet::new(),
        BTreeMap::new(),
    );

    assert!(matches!(
        engine.create_lock_v1(
            &root,
            &inputs,
            &GitAcquisitionConfig::new("/definitely/missing/git").unwrap(),
        ),
        Err(LockOperationError::PackageMismatch {
            source_identity: LockedSourceV1::Local(found),
            expected,
            actual,
        }) if found == dependency_locator
            && expected == package("com.example.expected")
            && actual == package("com.example.actual")
    ));
    assert!(!root.join(LOCK_FILE).exists());
}

#[test]
fn repeated_exact_source_is_one_node_with_edge_scoped_aliases() {
    let temp = tempfile::tempdir().unwrap();
    let engine = initialized_engine(temp.path());
    let root = temp.path().join("work/root");
    let dependency_root = temp.path().join("work/dependency");
    let dependency_locator = locator("../dependency");
    write_pack(
        &dependency_root,
        "com.example.dependency",
        "dependency",
        vec![],
        b"dependency\n",
    );
    write_pack(
        &root,
        "com.example.root",
        "root",
        vec![
            dependency("first", "com.example.dependency", &dependency_locator),
            dependency("second", "com.example.dependency", &dependency_locator),
        ],
        b"root\n",
    );
    let inputs = LockResolutionInputs::new(
        BTreeSet::from([dependency_locator]),
        BTreeSet::new(),
        BTreeMap::new(),
    );

    let outcome = engine
        .create_lock_v1(
            &root,
            &inputs,
            &GitAcquisitionConfig::new("/definitely/missing/git").unwrap(),
        )
        .unwrap();
    assert_eq!(outcome.lock().nodes().len(), 2);
    let root_node = outcome.lock().node(outcome.lock().root_node_id()).unwrap();
    assert_eq!(root_node.dependencies().len(), 2);
    assert_eq!(
        root_node.dependencies()[0].target_node_id(),
        root_node.dependencies()[1].target_node_id()
    );
}

#[test]
fn update_rebuilds_the_closure_and_drops_removed_dependencies() {
    let temp = tempfile::tempdir().unwrap();
    let engine = initialized_engine(temp.path());
    let root = temp.path().join("work/root");
    let dependency_root = temp.path().join("work/dependency");
    let dependency_locator = locator("../dependency");
    write_pack(
        &dependency_root,
        "com.example.dependency",
        "dependency",
        vec![],
        b"dependency\n",
    );
    write_pack(
        &root,
        "com.example.root",
        "root",
        vec![dependency(
            "dependency",
            "com.example.dependency",
            &dependency_locator,
        )],
        b"root\n",
    );
    let inputs = LockResolutionInputs::new(
        BTreeSet::from([dependency_locator]),
        BTreeSet::new(),
        BTreeMap::new(),
    );
    let git = GitAcquisitionConfig::new("/definitely/missing/git").unwrap();
    let created = engine.create_lock_v1(&root, &inputs, &git).unwrap();
    assert_eq!(created.lock().nodes().len(), 2);

    write_pack(&root, "com.example.root", "root", vec![], b"root\n");
    let updated = engine.update_lock_v1(&root, &inputs, &git).unwrap();
    assert_eq!(updated.publication(), LockFilePublication::Updated);
    assert_eq!(updated.lock().nodes().len(), 1);
    assert!(matches!(
        updated.lock().nodes()[0].source(),
        LockedSourceV1::Root
    ));
}

#[test]
fn discovered_dependency_cycle_is_rejected_without_a_lock() {
    let temp = tempfile::tempdir().unwrap();
    let engine = initialized_engine(temp.path());
    let root = temp.path().join("work/root");
    let a_root = temp.path().join("work/a");
    let b_root = temp.path().join("work/b");
    let a_locator = locator("../a");
    let b_locator = locator("../b");
    write_pack(
        &a_root,
        "com.example.a",
        "a",
        vec![dependency("b", "com.example.b", &b_locator)],
        b"a\n",
    );
    write_pack(
        &b_root,
        "com.example.b",
        "b",
        vec![dependency("a", "com.example.a", &a_locator)],
        b"b\n",
    );
    write_pack(
        &root,
        "com.example.root",
        "root",
        vec![dependency("a", "com.example.a", &a_locator)],
        b"root\n",
    );
    let inputs = LockResolutionInputs::new(
        BTreeSet::from([a_locator, b_locator]),
        BTreeSet::new(),
        BTreeMap::new(),
    );

    assert!(matches!(
        engine.create_lock_v1(
            &root,
            &inputs,
            &GitAcquisitionConfig::new("/definitely/missing/git").unwrap(),
        ),
        Err(LockOperationError::Validation {
            source: LockValidationError::Cycle { .. }
        })
    ));
    assert!(!root.join(LOCK_FILE).exists());
}

#[test]
fn exact_git_lock_creation_updates_offline_from_the_verified_cas() {
    let temp = tempfile::tempdir().unwrap();
    let engine = initialized_engine(temp.path());
    let (repository, commit) = git_repository(temp.path());
    let git_source = GitSourceV1::new(
        GitUrl::new("https://example.invalid/repository.git").unwrap(),
        GitObjectId::new(format!("sha1-{commit}")).unwrap(),
        PackSubdir::Root,
    );
    let root = temp.path().join("root-pack");
    write_pack(
        &root,
        "com.example.root",
        "root",
        vec![PackDependencyV1::new(
            Alias::new("remote").unwrap(),
            package("com.example.minimal"),
            DependencySourceV1::Git(git_source.clone()),
        )],
        b"root\n",
    );
    let wrapper = write_git_wrapper(temp.path(), &repository);
    let scratch = create_scratch(temp.path());
    let inputs = LockResolutionInputs::new(
        BTreeSet::new(),
        BTreeSet::from([git_source.url().clone()]),
        BTreeMap::from([(git_source.clone(), scratch)]),
    );

    let created = engine
        .create_lock_v1(
            &root,
            &inputs,
            &GitAcquisitionConfig::new(&wrapper).unwrap(),
        )
        .unwrap();
    assert_eq!(created.publication(), LockFilePublication::Created);
    let remote = created
        .lock()
        .nodes()
        .iter()
        .find(|node| node.source() == &LockedSourceV1::Git(git_source.clone()))
        .unwrap();
    assert_eq!(remote.package_id(), &package("com.example.minimal"));
    let remote_digest = remote.content_digest().clone();

    fs::remove_file(wrapper).unwrap();
    let offline_inputs = LockResolutionInputs::new(
        BTreeSet::new(),
        BTreeSet::from([git_source.url().clone()]),
        BTreeMap::new(),
    );
    let updated = engine
        .update_lock_v1(
            &root,
            &offline_inputs,
            &GitAcquisitionConfig::new("/definitely/missing/git").unwrap(),
        )
        .unwrap();
    assert_eq!(updated.publication(), LockFilePublication::Unchanged);
    assert_eq!(updated.lock(), created.lock());

    let lock_bytes = fs::read(root.join(LOCK_FILE)).unwrap();
    fs::remove_file(object_path(&engine, &remote_digest)).unwrap();
    assert!(matches!(
        engine.update_lock_v1(
            &root,
            &offline_inputs,
            &GitAcquisitionConfig::new("/definitely/missing/git").unwrap(),
        ),
        Err(LockOperationError::MissingGitScratch { git_source: missing })
            if missing == git_source
    ));
    assert_eq!(fs::read(root.join(LOCK_FILE)).unwrap(), lock_bytes);
}
