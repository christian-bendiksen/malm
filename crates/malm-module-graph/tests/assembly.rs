use std::{cell::RefCell, collections::BTreeMap, error::Error, fmt};

use malm_module_graph::{
    GraphAssemblyError, ModuleReferenceV1, ModuleResolutionError, PackFileV1, PackObjectSourceV1,
    PackVerificationError, VerifiedPackV1, assemble_locked_graph_v1,
};
use malm_pack::{
    BundledComponentV1, ComponentInterfaceV1, DependencySourceV1, LocalLocator, LockV1,
    LockedDependencyV1, LockedPackV1, LockedSourceV1, PackDependencyV1, PackManifestV1,
    PackModuleV1, PackPath, encode_pack_v1, pack_content_digest,
};
use malm_types::{Alias, ContributionName, Digest, PackageId};

fn package(value: &str) -> PackageId {
    PackageId::new(value).unwrap()
}

fn alias(value: &str) -> Alias {
    Alias::new(value).unwrap()
}

fn name(value: &str) -> ContributionName {
    ContributionName::new(value).unwrap()
}

fn path(value: &str) -> PackPath {
    PackPath::new(value).unwrap()
}

fn local(value: &str) -> LockedSourceV1 {
    LockedSourceV1::Local(LocalLocator::new(value).unwrap())
}

fn local_declaration(value: &str) -> DependencySourceV1 {
    DependencySourceV1::Local(LocalLocator::new(value).unwrap())
}

#[derive(Clone)]
struct PackFixture {
    digest: Digest,
    files: Vec<PackFileV1>,
}

fn pack_fixture(
    package_id: &str,
    modules: &[&str],
    dependencies: Vec<PackDependencyV1>,
) -> PackFixture {
    pack_fixture_with_components(package_id, modules, dependencies, vec![], vec![])
}

fn pack_fixture_with_components(
    package_id: &str,
    modules: &[&str],
    dependencies: Vec<PackDependencyV1>,
    components: Vec<BundledComponentV1>,
    component_files: Vec<PackFileV1>,
) -> PackFixture {
    let module_entries = modules
        .iter()
        .map(|module| PackModuleV1::new(name(module), path(&format!("modules/{module}.kdl"))))
        .collect::<Vec<_>>();
    let manifest = PackManifestV1::new(
        package(package_id),
        module_entries.clone(),
        dependencies,
        vec![],
        vec![],
        vec![],
        components,
    )
    .unwrap();
    let mut files = vec![PackFileV1::new(
        path("malm-pack.kdl"),
        encode_pack_v1(&manifest),
    )];
    files.extend(module_entries.iter().map(|module| {
        PackFileV1::new(
            module.path().clone(),
            format!("module {:?}", module.name().as_str()),
        )
    }));
    files.extend(component_files);
    let digest = pack_content_digest(files.iter().map(|file| (file.path(), file.bytes()))).unwrap();
    PackFixture { digest, files }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ObjectError(Digest);

impl fmt::Display for ObjectError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "object {} is not cached", self.0)
    }
}

impl Error for ObjectError {}

#[derive(Default)]
struct Objects {
    objects: BTreeMap<Digest, Vec<PackFileV1>>,
    loads: RefCell<BTreeMap<Digest, usize>>,
}

impl Objects {
    fn insert(&mut self, fixture: &PackFixture) {
        self.objects
            .insert(fixture.digest.clone(), fixture.files.clone());
    }

    fn load_count(&self, digest: &Digest) -> usize {
        self.loads.borrow().get(digest).copied().unwrap_or(0)
    }
}

impl PackObjectSourceV1 for Objects {
    type Error = ObjectError;

    fn load_pack(&self, content_digest: &Digest) -> Result<Vec<PackFileV1>, Self::Error> {
        *self
            .loads
            .borrow_mut()
            .entry(content_digest.clone())
            .or_default() += 1;
        self.objects
            .get(content_digest)
            .cloned()
            .ok_or_else(|| ObjectError(content_digest.clone()))
    }
}

#[test]
fn offline_assembly_verifies_objects_and_enforces_private_direct_scopes() {
    let leaf_pack = pack_fixture("com.example.leaf", &["leaf-module"], vec![]);
    let leaf = LockedPackV1::new(
        package("com.example.leaf"),
        local("packs/leaf"),
        leaf_pack.digest.clone(),
        vec![],
        vec![],
    )
    .unwrap();

    let middle_pack = pack_fixture(
        "com.example.middle",
        &["middle-module"],
        vec![PackDependencyV1::new(
            alias("leaf"),
            package("com.example.leaf"),
            local_declaration("packs/leaf"),
        )],
    );
    let middle = LockedPackV1::new(
        package("com.example.middle"),
        local("packs/middle"),
        middle_pack.digest.clone(),
        vec![LockedDependencyV1::new(
            alias("leaf"),
            leaf.node_id().clone(),
        )],
        vec![],
    )
    .unwrap();

    let root_pack = pack_fixture(
        "com.example.root",
        &["root-module"],
        vec![PackDependencyV1::new(
            alias("middle"),
            package("com.example.middle"),
            local_declaration("packs/middle"),
        )],
    );
    let root = LockedPackV1::new(
        package("com.example.root"),
        LockedSourceV1::Root,
        root_pack.digest.clone(),
        vec![LockedDependencyV1::new(
            alias("middle"),
            middle.node_id().clone(),
        )],
        vec![],
    )
    .unwrap();
    let lock = LockV1::new(
        root.node_id().clone(),
        vec![middle.clone(), root.clone(), leaf.clone()],
    )
    .unwrap();

    let mut objects = Objects::default();
    for fixture in [&root_pack, &middle_pack, &leaf_pack] {
        objects.insert(fixture);
    }
    let graph = assemble_locked_graph_v1(&lock, &objects).unwrap();

    assert_eq!(
        graph.dependency_order(),
        &[
            leaf.node_id().clone(),
            middle.node_id().clone(),
            root.node_id().clone()
        ]
    );
    assert_eq!(objects.load_count(&leaf_pack.digest), 1);
    assert_eq!(objects.load_count(&middle_pack.digest), 1);
    assert_eq!(objects.load_count(&root_pack.digest), 1);

    let local = graph
        .resolve_module(
            root.node_id(),
            &ModuleReferenceV1::Local(name("root-module")),
        )
        .unwrap();
    assert_eq!(local.pack_node_id(), root.node_id());
    let direct = graph
        .resolve_module(
            root.node_id(),
            &ModuleReferenceV1::Direct {
                dependency: alias("middle"),
                module: name("middle-module"),
            },
        )
        .unwrap();
    assert_eq!(direct.pack_node_id(), middle.node_id());

    assert!(matches!(
        graph.resolve_module(
            root.node_id(),
            &ModuleReferenceV1::Local(name("middle-module"))
        ),
        Err(ModuleResolutionError::UnknownLocalModule { .. })
    ));
    assert!(matches!(
        graph.resolve_module(
            root.node_id(),
            &ModuleReferenceV1::Direct {
                dependency: alias("leaf"),
                module: name("leaf-module"),
            }
        ),
        Err(ModuleResolutionError::UnknownDependencyAlias { .. })
    ));
}

#[test]
fn diamond_reuses_one_object_and_aliases_remain_scope_local() {
    let shared_pack = pack_fixture("com.example.shared", &["shared-module"], vec![]);
    let shared = LockedPackV1::new(
        package("com.example.shared"),
        local("packs/shared"),
        shared_pack.digest.clone(),
        vec![],
        vec![],
    )
    .unwrap();

    let branch = |package_id: &str, locator: &str| {
        let fixture = pack_fixture(
            package_id,
            &["branch-module"],
            vec![PackDependencyV1::new(
                alias("base"),
                package("com.example.shared"),
                local_declaration("packs/shared"),
            )],
        );
        let node = LockedPackV1::new(
            package(package_id),
            local(locator),
            fixture.digest.clone(),
            vec![LockedDependencyV1::new(
                alias("base"),
                shared.node_id().clone(),
            )],
            vec![],
        )
        .unwrap();
        (fixture, node)
    };
    let (left_pack, left) = branch("com.example.left", "packs/left");
    let (right_pack, right) = branch("com.example.right", "packs/right");
    let root_pack = pack_fixture(
        "com.example.root",
        &["root-module"],
        vec![
            PackDependencyV1::new(
                alias("left"),
                package("com.example.left"),
                local_declaration("packs/left"),
            ),
            PackDependencyV1::new(
                alias("right"),
                package("com.example.right"),
                local_declaration("packs/right"),
            ),
        ],
    );
    let root = LockedPackV1::new(
        package("com.example.root"),
        LockedSourceV1::Root,
        root_pack.digest.clone(),
        vec![
            LockedDependencyV1::new(alias("left"), left.node_id().clone()),
            LockedDependencyV1::new(alias("right"), right.node_id().clone()),
        ],
        vec![],
    )
    .unwrap();
    let lock = LockV1::new(
        root.node_id().clone(),
        vec![shared.clone(), left.clone(), right.clone(), root.clone()],
    )
    .unwrap();
    let mut objects = Objects::default();
    for fixture in [&shared_pack, &left_pack, &right_pack, &root_pack] {
        objects.insert(fixture);
    }

    let graph = assemble_locked_graph_v1(&lock, &objects).unwrap();
    assert_eq!(objects.load_count(&shared_pack.digest), 1);
    for branch in [&left, &right] {
        let resolved = graph
            .resolve_module(
                branch.node_id(),
                &ModuleReferenceV1::Direct {
                    dependency: alias("base"),
                    module: name("shared-module"),
                },
            )
            .unwrap();
        assert_eq!(resolved.pack_node_id(), shared.node_id());
    }
    assert!(matches!(
        graph.resolve_module(
            root.node_id(),
            &ModuleReferenceV1::Direct {
                dependency: alias("base"),
                module: name("shared-module"),
            }
        ),
        Err(ModuleResolutionError::UnknownDependencyAlias { .. })
    ));
}

#[test]
fn multiple_aliases_to_one_target_do_not_stall_dependency_order() {
    let leaf_pack = pack_fixture("com.example.leaf", &["leaf-module"], vec![]);
    let leaf = LockedPackV1::new(
        package("com.example.leaf"),
        local("packs/leaf"),
        leaf_pack.digest.clone(),
        vec![],
        vec![],
    )
    .unwrap();
    let root_pack = pack_fixture(
        "com.example.root",
        &["root-module"],
        vec![
            PackDependencyV1::new(
                alias("leaf-a"),
                package("com.example.leaf"),
                local_declaration("packs/leaf"),
            ),
            PackDependencyV1::new(
                alias("leaf-b"),
                package("com.example.leaf"),
                local_declaration("packs/leaf"),
            ),
        ],
    );
    let root = LockedPackV1::new(
        package("com.example.root"),
        LockedSourceV1::Root,
        root_pack.digest.clone(),
        vec![
            LockedDependencyV1::new(alias("leaf-a"), leaf.node_id().clone()),
            LockedDependencyV1::new(alias("leaf-b"), leaf.node_id().clone()),
        ],
        vec![],
    )
    .unwrap();
    let lock = LockV1::new(root.node_id().clone(), vec![root.clone(), leaf.clone()]).unwrap();
    let mut objects = Objects::default();
    objects.insert(&leaf_pack);
    objects.insert(&root_pack);

    let graph = assemble_locked_graph_v1(&lock, &objects).unwrap();
    assert_eq!(
        graph.dependency_order(),
        &[leaf.node_id().clone(), root.node_id().clone()]
    );
    let first = graph
        .resolve_module(
            root.node_id(),
            &ModuleReferenceV1::Direct {
                dependency: alias("leaf-a"),
                module: name("leaf-module"),
            },
        )
        .unwrap();
    let second = graph
        .resolve_module(
            root.node_id(),
            &ModuleReferenceV1::Direct {
                dependency: alias("leaf-b"),
                module: name("leaf-module"),
            },
        )
        .unwrap();
    assert_eq!(first, second);
}

#[test]
fn identical_content_from_distinct_sources_is_loaded_once_and_kept_immutable() {
    let shared_pack = pack_fixture("com.example.shared", &["shared-module"], vec![]);
    let first = LockedPackV1::new(
        package("com.example.shared"),
        local("packs/first"),
        shared_pack.digest.clone(),
        vec![],
        vec![],
    )
    .unwrap();
    let second = LockedPackV1::new(
        package("com.example.shared"),
        local("packs/second"),
        shared_pack.digest.clone(),
        vec![],
        vec![],
    )
    .unwrap();
    assert_ne!(first.node_id(), second.node_id());

    let root_pack = pack_fixture(
        "com.example.root",
        &["root-module"],
        vec![
            PackDependencyV1::new(
                alias("first"),
                package("com.example.shared"),
                local_declaration("packs/first"),
            ),
            PackDependencyV1::new(
                alias("second"),
                package("com.example.shared"),
                local_declaration("packs/second"),
            ),
        ],
    );
    let root = LockedPackV1::new(
        package("com.example.root"),
        LockedSourceV1::Root,
        root_pack.digest.clone(),
        vec![
            LockedDependencyV1::new(alias("first"), first.node_id().clone()),
            LockedDependencyV1::new(alias("second"), second.node_id().clone()),
        ],
        vec![],
    )
    .unwrap();
    let lock = LockV1::new(root.node_id().clone(), vec![root, first.clone(), second]).unwrap();
    let mut objects = Objects::default();
    objects.insert(&shared_pack);
    objects.insert(&root_pack);

    let graph = assemble_locked_graph_v1(&lock, &objects).unwrap();
    assert_eq!(objects.load_count(&shared_pack.digest), 1);
    assert_eq!(graph.lock(), &lock);
    assert_eq!(
        graph
            .pack(first.node_id())
            .unwrap()
            .file(&path("modules/shared-module.kdl")),
        Some(b"module \"shared-module\"".as_slice())
    );
}

#[test]
fn verification_rejects_digest_missing_paths_and_component_mismatch() {
    let fixture = pack_fixture("com.example.pack", &["main"], vec![]);
    assert!(matches!(
        VerifiedPackV1::from_files(&Digest::sha256(b"wrong"), fixture.files.clone()),
        Err(PackVerificationError::DigestMismatch { .. })
    ));

    let manifest = PackManifestV1::new(
        package("com.example.missing"),
        vec![PackModuleV1::new(name("main"), path("modules/main.kdl"))],
        vec![],
        vec![],
        vec![],
        vec![],
        vec![],
    )
    .unwrap();
    let files = vec![PackFileV1::new(
        path("malm-pack.kdl"),
        encode_pack_v1(&manifest),
    )];
    let digest = pack_content_digest(files.iter().map(|file| (file.path(), file.bytes()))).unwrap();
    assert!(matches!(
        VerifiedPackV1::from_files(&digest, files),
        Err(PackVerificationError::MissingDeclaredPath { kind: "module", .. })
    ));

    let component_path = path("components/renderer.wasm");
    let component = BundledComponentV1::new(
        name("renderer"),
        component_path.clone(),
        Digest::sha256(b"expected bytes"),
        ComponentInterfaceV1::FormatComponentV1,
    );
    let component_fixture = pack_fixture_with_components(
        "com.example.component",
        &[],
        vec![],
        vec![component],
        vec![PackFileV1::new(component_path, b"different bytes")],
    );
    assert!(matches!(
        VerifiedPackV1::from_files(&component_fixture.digest, component_fixture.files.clone()),
        Err(PackVerificationError::ComponentDigestMismatch { .. })
    ));
}

#[test]
fn assembly_fails_closed_on_missing_object_or_manifest_disagreement() {
    let root_pack = pack_fixture("com.example.root", &["main"], vec![]);
    let root = LockedPackV1::new(
        package("com.example.root"),
        LockedSourceV1::Root,
        root_pack.digest.clone(),
        vec![],
        vec![],
    )
    .unwrap();
    let root_only = LockV1::new(root.node_id().clone(), vec![root]).unwrap();
    assert!(matches!(
        assemble_locked_graph_v1(&root_only, &Objects::default()),
        Err(GraphAssemblyError::ObjectLoad { .. })
    ));

    let target_pack = pack_fixture("com.example.target", &["target"], vec![]);
    let target = LockedPackV1::new(
        package("com.example.target"),
        local("packs/actual"),
        target_pack.digest.clone(),
        vec![],
        vec![],
    )
    .unwrap();
    let disagreeing_root_pack = pack_fixture(
        "com.example.root",
        &["main"],
        vec![PackDependencyV1::new(
            alias("target"),
            package("com.example.target"),
            local_declaration("packs/declared"),
        )],
    );
    let disagreeing_root = LockedPackV1::new(
        package("com.example.root"),
        LockedSourceV1::Root,
        disagreeing_root_pack.digest.clone(),
        vec![LockedDependencyV1::new(
            alias("target"),
            target.node_id().clone(),
        )],
        vec![],
    )
    .unwrap();
    let lock = LockV1::new(
        disagreeing_root.node_id().clone(),
        vec![disagreeing_root, target],
    )
    .unwrap();
    let mut objects = Objects::default();
    objects.insert(&target_pack);
    objects.insert(&disagreeing_root_pack);
    assert!(matches!(
        assemble_locked_graph_v1(&lock, &objects),
        Err(GraphAssemblyError::ManifestAgreement(
            malm_pack::LockValidationError::ManifestMismatch { .. }
        ))
    ));
}
