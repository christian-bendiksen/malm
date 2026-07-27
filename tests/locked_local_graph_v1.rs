use std::collections::BTreeSet;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use malm::{
    Engine, EngineConfig, EngineError, GraphAcquisitionError, PackCaptureIssue, StoreAccess,
};
use malm_module_graph::ModuleReferenceV1;
use malm_pack::{
    DependencySourceV1, GitObjectId, GitSourceV1, GitUrl, LocalLocator, LockV1, LockedDependencyV1,
    LockedPackV1, LockedSourceV1, PackDependencyV1, PackFileV1, PackManifestV1, PackModuleV1,
    PackPath, PackSubdir, encode_lock_v1, encode_pack_v1, pack_content_digest,
};
use malm_types::{Alias, ContributionName, Digest, PackageId};

struct PackFixture {
    digest: Digest,
    module_path: PathBuf,
}

fn package(value: &str) -> PackageId {
    PackageId::new(value).unwrap()
}

fn alias(value: &str) -> Alias {
    Alias::new(value).unwrap()
}

fn name(value: &str) -> ContributionName {
    ContributionName::new(value).unwrap()
}

fn locator(value: &str) -> LocalLocator {
    LocalLocator::new(value).unwrap()
}

fn write_pack(
    root: &Path,
    package_id: &str,
    module: &str,
    dependencies: Vec<PackDependencyV1>,
) -> PackFixture {
    fs::create_dir_all(root.join("modules")).unwrap();
    let module_path = PackPath::new(format!("modules/{module}.kdl")).unwrap();
    let manifest = PackManifestV1::new(
        package(package_id),
        vec![PackModuleV1::new(name(module), module_path.clone())],
        dependencies,
        vec![],
        vec![],
        vec![],
        vec![],
    )
    .unwrap();
    let manifest_bytes = encode_pack_v1(&manifest);
    let module_bytes = format!("module {module}\n").into_bytes();
    fs::write(root.join("malm-pack.kdl"), &manifest_bytes).unwrap();
    let absolute_module_path = root.join(module_path.as_str());
    fs::write(&absolute_module_path, &module_bytes).unwrap();
    let files = [
        PackFileV1::new(PackPath::new("malm-pack.kdl").unwrap(), manifest_bytes),
        PackFileV1::new(module_path, module_bytes),
    ];
    let digest = pack_content_digest(files.iter().map(|file| (file.path(), file.bytes()))).unwrap();
    PackFixture {
        digest,
        module_path: absolute_module_path,
    }
}

fn initialized_engine(temp: &tempfile::TempDir) -> Engine {
    let state_home = temp.path().join("state");
    fs::create_dir(&state_home).unwrap();
    fs::set_permissions(&state_home, fs::Permissions::from_mode(0o700)).unwrap();
    let engine = Engine::new(
        EngineConfig::from_state_home(&state_home, StoreAccess::ReadWrite).unwrap(),
        malm::EnginePorts::system(),
    );
    engine.initialize_store().unwrap();
    engine
}

fn object_path(engine: &Engine, digest: &Digest) -> PathBuf {
    engine
        .config()
        .state_root()
        .join("objects/pack-manifests")
        .join(digest.as_str())
}

struct LocalGraphFixture {
    root_path: PathBuf,
    leaf_path: PathBuf,
    leaf_module_path: PathBuf,
    lock: LockV1,
    grants: BTreeSet<LocalLocator>,
    root: LockedPackV1,
    middle: LockedPackV1,
    leaf: LockedPackV1,
}

fn local_graph_fixture(temp: &tempfile::TempDir) -> LocalGraphFixture {
    let workspace = temp.path().join("work");
    let root_path = workspace.join("root");
    let middle_path = workspace.join("deps/middle");
    let leaf_path = workspace.join("shared/leaf");
    let middle_locator = locator("../deps/middle");
    let leaf_locator = locator("../shared/leaf");

    let leaf_pack = write_pack(&leaf_path, "com.example.leaf", "leaf-module", vec![]);
    let leaf = LockedPackV1::new(
        package("com.example.leaf"),
        LockedSourceV1::Local(leaf_locator.clone()),
        leaf_pack.digest,
        vec![],
        vec![],
    )
    .unwrap();

    let middle_pack = write_pack(
        &middle_path,
        "com.example.middle",
        "middle-module",
        vec![PackDependencyV1::new(
            alias("leaf"),
            package("com.example.leaf"),
            DependencySourceV1::Local(leaf_locator.clone()),
        )],
    );
    let middle = LockedPackV1::new(
        package("com.example.middle"),
        LockedSourceV1::Local(middle_locator.clone()),
        middle_pack.digest,
        vec![LockedDependencyV1::new(
            alias("leaf"),
            leaf.node_id().clone(),
        )],
        vec![],
    )
    .unwrap();

    let root_pack = write_pack(
        &root_path,
        "com.example.root",
        "root-module",
        vec![PackDependencyV1::new(
            alias("middle"),
            package("com.example.middle"),
            DependencySourceV1::Local(middle_locator.clone()),
        )],
    );
    let root = LockedPackV1::new(
        package("com.example.root"),
        LockedSourceV1::Root,
        root_pack.digest,
        vec![LockedDependencyV1::new(
            alias("middle"),
            middle.node_id().clone(),
        )],
        vec![],
    )
    .unwrap();
    let lock = LockV1::new(
        root.node_id().clone(),
        vec![middle.clone(), leaf.clone(), root.clone()],
    )
    .unwrap();

    LocalGraphFixture {
        root_path,
        leaf_path,
        leaf_module_path: leaf_pack.module_path,
        lock,
        grants: BTreeSet::from([middle_locator, leaf_locator]),
        root,
        middle,
        leaf,
    }
}

#[test]
fn transitive_local_graph_is_captured_root_relative_and_assembled() {
    let temp = tempfile::tempdir().unwrap();
    let engine = initialized_engine(&temp);
    let fixture = local_graph_fixture(&temp);
    let lock_before = encode_lock_v1(&fixture.lock);

    let graph = engine
        .acquire_locked_local_graph_v1(&fixture.root_path, &fixture.lock, &fixture.grants)
        .unwrap();

    assert_eq!(encode_lock_v1(&fixture.lock), lock_before);
    assert_eq!(graph.lock(), &fixture.lock);
    assert_eq!(graph.root_node_id(), fixture.root.node_id());
    assert_eq!(
        graph.dependency_order(),
        &[
            fixture.leaf.node_id().clone(),
            fixture.middle.node_id().clone(),
            fixture.root.node_id().clone(),
        ]
    );
    let direct_middle = graph
        .resolve_module(
            fixture.root.node_id(),
            &ModuleReferenceV1::Direct {
                dependency: alias("middle"),
                module: name("middle-module"),
            },
        )
        .unwrap();
    assert_eq!(direct_middle.pack_node_id(), fixture.middle.node_id());
    let direct_leaf = graph
        .resolve_module(
            fixture.middle.node_id(),
            &ModuleReferenceV1::Direct {
                dependency: alias("leaf"),
                module: name("leaf-module"),
            },
        )
        .unwrap();
    assert_eq!(direct_leaf.pack_node_id(), fixture.leaf.node_id());
    assert!(
        graph
            .resolve_module(
                fixture.root.node_id(),
                &ModuleReferenceV1::Direct {
                    dependency: alias("leaf"),
                    module: name("leaf-module"),
                },
            )
            .is_err()
    );

    for node in [&fixture.root, &fixture.middle, &fixture.leaf] {
        assert!(object_path(&engine, node.content_digest()).is_file());
    }
}

#[test]
fn cached_local_graph_does_not_conceal_drift_or_missing_sources() {
    let temp = tempfile::tempdir().unwrap();
    let engine = initialized_engine(&temp);
    let fixture = local_graph_fixture(&temp);
    let lock_before = encode_lock_v1(&fixture.lock);
    engine
        .acquire_locked_local_graph_v1(&fixture.root_path, &fixture.lock, &fixture.grants)
        .unwrap();

    fs::write(&fixture.leaf_module_path, b"local drift\n").unwrap();
    let error = engine
        .acquire_locked_local_graph_v1(&fixture.root_path, &fixture.lock, &fixture.grants)
        .unwrap_err();
    assert!(matches!(
        error,
        GraphAcquisitionError::Source {
            node_id,
            source: EngineError::PackCapture {
                reason: PackCaptureIssue::DigestMismatch { .. },
                ..
            }
        } if node_id == *fixture.leaf.node_id()
    ));
    assert_eq!(encode_lock_v1(&fixture.lock), lock_before);
    assert!(engine.assemble_cached_pack_graph_v1(&fixture.lock).is_ok());

    fs::remove_dir_all(&fixture.leaf_path).unwrap();
    let error = engine
        .acquire_locked_local_graph_v1(&fixture.root_path, &fixture.lock, &fixture.grants)
        .unwrap_err();
    assert!(matches!(
        error,
        GraphAcquisitionError::Source {
            node_id,
            source: EngineError::PackCapture {
                reason: PackCaptureIssue::SourceRootMissing,
                ..
            }
        } if node_id == *fixture.leaf.node_id()
    ));
    assert_eq!(encode_lock_v1(&fixture.lock), lock_before);
}

#[test]
fn all_local_authority_is_validated_before_cas_mutation() {
    let temp = tempfile::tempdir().unwrap();
    let engine = initialized_engine(&temp);
    let fixture = local_graph_fixture(&temp);
    let middle_locator = match fixture.middle.source() {
        LockedSourceV1::Local(locator) => locator.clone(),
        _ => unreachable!(),
    };
    let partial_grants = BTreeSet::from([middle_locator]);

    let error = engine
        .acquire_locked_local_graph_v1(&fixture.root_path, &fixture.lock, &partial_grants)
        .unwrap_err();
    assert!(matches!(
        error,
        GraphAcquisitionError::LocalSourceNotGranted { node_id, .. }
            if node_id == *fixture.leaf.node_id()
    ));
    assert!(!engine.config().state_root().join("objects").exists());
}

#[test]
fn git_nodes_are_rejected_before_local_capture() {
    let temp = tempfile::tempdir().unwrap();
    let engine = initialized_engine(&temp);
    let git_source = GitSourceV1::new(
        GitUrl::new("https://example.com/dependency.git").unwrap(),
        GitObjectId::new(format!("sha1-{}", "a".repeat(40))).unwrap(),
        PackSubdir::new(".").unwrap(),
    );
    let dependency = LockedPackV1::new(
        package("com.example.dependency"),
        LockedSourceV1::Git(git_source.clone()),
        Digest::sha256(b"dependency"),
        vec![],
        vec![],
    )
    .unwrap();
    let root = LockedPackV1::new(
        package("com.example.root"),
        LockedSourceV1::Root,
        Digest::sha256(b"root"),
        vec![LockedDependencyV1::new(
            alias("dependency"),
            dependency.node_id().clone(),
        )],
        vec![],
    )
    .unwrap();
    let lock = LockV1::new(root.node_id().clone(), vec![root, dependency.clone()]).unwrap();

    let error = engine
        .acquire_locked_local_graph_v1(&temp.path().join("missing-root"), &lock, &BTreeSet::new())
        .unwrap_err();
    assert!(matches!(
        error,
        GraphAcquisitionError::UnsupportedGitSource {
            node_id,
            git_source: found,
        } if node_id == *dependency.node_id() && found == git_source
    ));
    assert!(!engine.config().state_root().join("objects").exists());
}
