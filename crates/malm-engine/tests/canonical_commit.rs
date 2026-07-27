use std::{
    collections::BTreeMap,
    fs,
    io::Cursor,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::Path,
    sync::{Mutex, MutexGuard},
};

#[cfg(feature = "failpoints")]
use std::{path::PathBuf, process::Command};

use malm_engine::{
    ApprovalV1, CheckoutRequestV1, CommitError, CommitRequestV1, Engine, EngineConfig, EnginePorts,
    FormatComponentAuthorizationV1, FsckFindingCodeV1, FsckRequestV1, NamespaceStatusKindV1,
    NamespaceStatusRequestV1, PrepareArtifactV1, PrepareOperationV1, PrepareRequestPartsV1,
    PrepareRequestV1, PruneRequestV1, StaticProfile, StoreAccess,
};
#[cfg(feature = "failpoints")]
use malm_engine::{NamespaceRemovalHistoryV1, NamespaceRemovalRequestV1};
use malm_module_graph::{PackObjectSourceV1, assemble_locked_graph_v1};
use malm_pack::{
    LockV1, LockedPackV1, LockedSourceV1, PackFileV1, PackManifestV1, PackPath, encode_pack_v1,
    pack_content_digest,
};
use malm_tree::{
    SymlinkObjectV1, TreeEntryV1, TreeObjectV1, TreePathSegmentV1, file_object_digest_v1,
    symlink_object_digest_v1, tree_object_digest_v1,
};
use malm_types::{ArtifactId, DeploymentName, Digest, NamespaceName, PackageId};

#[cfg(feature = "failpoints")]
use malm_types::PreparedId;

fn test_guard() -> MutexGuard<'static, ()> {
    static TEST_LOCK: Mutex<()> = Mutex::new(());
    TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner())
}

struct PackObjects(BTreeMap<Digest, Vec<PackFileV1>>);

impl PackObjectSourceV1 for PackObjects {
    type Error = std::convert::Infallible;

    fn load_pack(&self, digest: &Digest) -> Result<Vec<PackFileV1>, Self::Error> {
        Ok(self.0[digest].clone())
    }
}

fn engine(temp: &tempfile::TempDir, target: &Path) -> Engine {
    let state = temp.path().join("state");
    fs::create_dir(&state).unwrap();
    fs::set_permissions(&state, fs::Permissions::from_mode(0o700)).unwrap();
    Engine::new(
        EngineConfig::from_state_home(&state, StoreAccess::ReadWrite)
            .unwrap()
            .with_target_authority(DeploymentName::new("home").unwrap(), target)
            .unwrap(),
        EnginePorts::system(),
    )
}

fn request(expected_head: Option<Digest>, operations: Vec<PrepareOperationV1>) -> PrepareRequestV1 {
    PrepareRequestV1::from(PrepareRequestPartsV1 {
        namespace: NamespaceName::new("canonical").unwrap(),
        expected_head,
        graph_digest: Digest::sha256(b"canonical graph"),
        inputs: vec![],
        artifacts: vec![],
        transforms: vec![],
        findings: vec![],
        operations,
    })
}

fn commit(
    engine: &Engine,
    prepared: &malm_engine::PreparedDeploymentV1,
) -> malm_engine::ApplyOutcomeV1 {
    engine
        .commit_v1(&CommitRequestV1::new(
            prepared.plan_id().clone(),
            ApprovalV1::new(
                prepared.plan_id().clone(),
                prepared.approval_digest().clone(),
            ),
        ))
        .unwrap()
}

#[test]
fn places_and_exactly_verifies_a_canonical_symlink() {
    let _test_guard = test_guard();
    let temp = tempfile::tempdir().unwrap();
    let target = temp.path().join("target");
    fs::create_dir(&target).unwrap();
    fs::create_dir(target.join("config")).unwrap();
    let engine = engine(&temp, &target);
    engine.initialize_store().unwrap();
    let object = SymlinkObjectV1::new("destination").unwrap();
    let digest = symlink_object_digest_v1(&object);
    engine.publish_symlink_object_v1(&digest, &object).unwrap();
    let prepared = engine
        .prepare_v1(&request(
            None,
            vec![
                PrepareOperationV1::place_symlink(
                    DeploymentName::new("home").unwrap(),
                    "config/link",
                    digest.clone(),
                )
                .unwrap(),
            ],
        ))
        .unwrap();
    let applied = commit(&engine, &prepared);
    assert_eq!(
        fs::read_link(target.join("config/link")).unwrap(),
        Path::new("destination")
    );

    let unchanged = engine
        .prepare_v1(&request(
            Some(applied.head().clone()),
            vec![
                PrepareOperationV1::place_symlink(
                    DeploymentName::new("home").unwrap(),
                    "config/link",
                    digest,
                )
                .unwrap(),
            ],
        ))
        .unwrap();
    assert!(matches!(
        unchanged.operations(),
        [PrepareOperationV1::AssertExact { .. }]
    ));
    let status = engine
        .inspect_namespace_status_v1(&NamespaceStatusRequestV1::new(
            NamespaceName::new("canonical").unwrap(),
        ))
        .unwrap();
    assert_eq!(status.status(), NamespaceStatusKindV1::EnabledExact);
}

#[test]
fn places_and_removes_a_nonempty_canonical_tree() {
    let _test_guard = test_guard();
    let temp = tempfile::tempdir().unwrap();
    let target = temp.path().join("target");
    fs::create_dir(&target).unwrap();
    fs::create_dir(target.join("config")).unwrap();
    let engine = engine(&temp, &target);
    engine.initialize_store().unwrap();

    let contents = b"nested canonical bytes\n";
    let file = file_object_digest_v1(contents).unwrap();
    engine.publish_file_object_v1(&file, contents).unwrap();
    let child = TreeObjectV1::new(
        0o750,
        vec![
            TreeEntryV1::file(
                TreePathSegmentV1::new("file.txt").unwrap(),
                0o640,
                file,
                contents.len() as u64,
            )
            .unwrap(),
        ],
    )
    .unwrap();
    let child_digest = tree_object_digest_v1(&child);
    engine
        .publish_tree_object_v1(&child_digest, &child)
        .unwrap();
    let link = SymlinkObjectV1::new("sub/file.txt").unwrap();
    let link_digest = symlink_object_digest_v1(&link);
    engine
        .publish_symlink_object_v1(&link_digest, &link)
        .unwrap();
    let root = TreeObjectV1::new(
        0o700,
        vec![
            TreeEntryV1::safe_relative_symlink(
                TreePathSegmentV1::new("current").unwrap(),
                link_digest,
            ),
            TreeEntryV1::directory(TreePathSegmentV1::new("sub").unwrap(), 0o750, child_digest)
                .unwrap(),
        ],
    )
    .unwrap();
    let root_digest = tree_object_digest_v1(&root);
    engine.publish_tree_object_v1(&root_digest, &root).unwrap();

    let prepared = engine
        .prepare_v1(&request(
            None,
            vec![
                PrepareOperationV1::place_tree(
                    DeploymentName::new("home").unwrap(),
                    "config/tree",
                    root_digest,
                )
                .unwrap(),
            ],
        ))
        .unwrap();
    let applied = commit(&engine, &prepared);
    assert_eq!(
        fs::read(target.join("config/tree/sub/file.txt")).unwrap(),
        contents
    );
    assert_eq!(
        fs::read_link(target.join("config/tree/current")).unwrap(),
        Path::new("sub/file.txt")
    );

    let replacement_contents = b"replacement tree bytes\n";
    let replacement_file = file_object_digest_v1(replacement_contents).unwrap();
    engine
        .publish_file_object_v1(&replacement_file, replacement_contents)
        .unwrap();
    let replacement_tree = TreeObjectV1::new(
        0o700,
        vec![
            TreeEntryV1::file(
                TreePathSegmentV1::new("replacement.txt").unwrap(),
                0o600,
                replacement_file,
                replacement_contents.len() as u64,
            )
            .unwrap(),
        ],
    )
    .unwrap();
    let replacement_digest = tree_object_digest_v1(&replacement_tree);
    engine
        .publish_tree_object_v1(&replacement_digest, &replacement_tree)
        .unwrap();
    let replacement = engine
        .prepare_v1(&request(
            Some(applied.head().clone()),
            vec![
                PrepareOperationV1::place_tree(
                    DeploymentName::new("home").unwrap(),
                    "config/tree",
                    replacement_digest,
                )
                .unwrap(),
            ],
        ))
        .unwrap();
    let replaced = commit(&engine, &replacement);
    assert_eq!(
        fs::read(target.join("config/tree/replacement.txt")).unwrap(),
        replacement_contents
    );
    assert!(!target.join("config/tree/sub").exists());

    let removal = engine
        .prepare_v1(&request(Some(replaced.head().clone()), vec![]))
        .unwrap();
    assert!(matches!(
        removal.operations(),
        [PrepareOperationV1::RemoveLeaf { .. }]
    ));
    commit(&engine, &removal);
    assert!(!target.join("config/tree").exists());

    let checkout = engine
        .prepare_checkout_v1(&CheckoutRequestV1::new(
            NamespaceName::new("canonical").unwrap(),
            applied.head().clone(),
        ))
        .unwrap();
    commit(&engine, &checkout);
    assert_eq!(
        fs::read(target.join("config/tree/sub/file.txt")).unwrap(),
        contents
    );
}

#[test]
fn rich_outputs_prepare_every_canonical_output_kind() {
    let _test_guard = test_guard();
    let temp = tempfile::tempdir().unwrap();
    let target = temp.path().join("target");
    fs::create_dir(&target).unwrap();
    let engine = engine(&temp, &target);
    engine.initialize_store().unwrap();

    let contents = b"rich canonical file\n";
    let file = file_object_digest_v1(contents).unwrap();
    let tree = TreeObjectV1::new(0o750, vec![]).unwrap();
    let tree_digest = tree_object_digest_v1(&tree);
    engine.publish_tree_object_v1(&tree_digest, &tree).unwrap();
    let archive_bytes = vec![0_u8; 1024];
    let archive = Digest::sha256(&archive_bytes);
    let archive_object = file_object_digest_v1(&archive_bytes).unwrap();
    let decoded = malm_archive::decode_archive_v1(
        Cursor::new(archive_bytes.clone()),
        malm_archive::ArchiveDeclarationV1::posix_ustar(
            archive_bytes.len() as u64,
            archive.clone(),
        ),
        malm_archive::ArchiveLimitsV1::default(),
    )
    .unwrap();
    let archive_tree = decoded.root_digest().clone();
    let source = format!(
        r#"rich-config schema-version=1 default-profile="default" {{
    includes {{}}
    modules {{}}
    variables {{}}
    fragments {{}}
    slots {{}}
    statements {{}}
    profiles {{
        profile "default" abstract=#false {{
            extends {{}}
            statements {{}}
            outputs {{
                regular-file "file" destination="file.txt" source="assets/file.txt" source-kind="asset" raw-digest="{}" object-digest="{file}" byte-len={} executable=#false
                symlink "link" destination="link" target="file.txt"
                canonical-tree "tree" destination="tree" digest="{tree_digest}"
                decoded-archive "archive" destination="archive" source="assets/archive.tar" source-kind="asset" raw-digest="{archive}" object-digest="{archive_object}" byte-len={} decoder="malm.posix-ustar.none" decoder-version=1 tree-digest="{archive_tree}"
                format-file "document" destination="document.json" executable=#false {{
                    built-in "canonical-json"
                    options {{}}
                    resources {{}}
                }}
            }}
        }}
    }}
}}"#,
        Digest::sha256(contents),
        contents.len(),
        archive_bytes.len(),
    );
    let config_path = PackPath::new(malm_config::CONFIG_FILE).unwrap();
    let file_path = PackPath::new("assets/file.txt").unwrap();
    let archive_path = PackPath::new("assets/archive.tar").unwrap();
    let manifest = PackManifestV1::new(
        PackageId::new("com.example.canonical-rich").unwrap(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        vec![file_path.clone(), archive_path.clone()],
        Vec::new(),
    )
    .unwrap()
    .with_config_documents(vec![config_path.clone()])
    .unwrap();
    let mut files = vec![
        PackFileV1::new(
            PackPath::new("malm-pack.kdl").unwrap(),
            encode_pack_v1(&manifest),
        ),
        PackFileV1::new(config_path, source.into_bytes()),
        PackFileV1::new(file_path, contents),
        PackFileV1::new(archive_path, archive_bytes),
    ];
    files.sort_by(|left, right| left.path().cmp(right.path()));
    let content_digest =
        pack_content_digest(files.iter().map(|entry| (entry.path(), entry.bytes()))).unwrap();
    let root = LockedPackV1::new(
        PackageId::new("com.example.canonical-rich").unwrap(),
        LockedSourceV1::Root,
        content_digest.clone(),
        Vec::new(),
        Vec::new(),
    )
    .unwrap();
    let lock = LockV1::new(root.node_id().clone(), vec![root]).unwrap();
    let graph = assemble_locked_graph_v1(
        &lock,
        &PackObjects(BTreeMap::from([(content_digest, files)])),
    )
    .unwrap();
    let prepared = engine
        .prepare_static_profile_v1(
            StaticProfile {
                graph: &graph,
                component_authorization: &FormatComponentAuthorizationV1::default(),
                namespace: NamespaceName::new("canonical").unwrap(),
                target_authority: DeploymentName::new("home").unwrap(),
                expected_head: None,
            },
            None,
        )
        .unwrap();
    assert_eq!(prepared.operations().len(), 5);
    assert_eq!(prepared.transforms().len(), 1);
    assert_eq!(prepared.transforms()[0].name(), "canonical-json");
    let applied = commit(&engine, &prepared);

    assert_eq!(fs::read(target.join("file.txt")).unwrap(), contents);
    assert_eq!(
        fs::read_link(target.join("link")).unwrap(),
        Path::new("file.txt")
    );
    assert!(target.join("tree").is_dir());
    assert!(target.join("archive").is_dir());
    assert_eq!(fs::read(target.join("document.json")).unwrap(), b"{}\n");
    let generation_path = engine
        .config()
        .state_root()
        .join("state")
        .join("generations")
        .join(applied.head().as_str());
    let generation =
        malm_store::decode_state_generation_v1(applied.head(), &fs::read(generation_path).unwrap())
            .unwrap();
    assert_eq!(generation.transforms().len(), 1);
    assert_eq!(generation.transforms()[0].name(), "canonical-json");
}

#[test]
fn fsck_reports_a_corrupt_reachable_canonical_object() {
    let _test_guard = test_guard();
    let temp = tempfile::tempdir().unwrap();
    let target = temp.path().join("target");
    fs::create_dir(&target).unwrap();
    let engine = engine(&temp, &target);
    engine.initialize_store().unwrap();

    let object = SymlinkObjectV1::new("destination").unwrap();
    let digest = symlink_object_digest_v1(&object);
    engine.publish_symlink_object_v1(&digest, &object).unwrap();
    let prepared = engine
        .prepare_v1(&request(
            None,
            vec![
                PrepareOperationV1::place_symlink(
                    DeploymentName::new("home").unwrap(),
                    "link",
                    digest.clone(),
                )
                .unwrap(),
            ],
        ))
        .unwrap();
    commit(&engine, &prepared);

    let object_path = engine
        .config()
        .state_root()
        .join("objects/symlinks")
        .join(digest.as_str());
    fs::set_permissions(&object_path, fs::Permissions::from_mode(0o600)).unwrap();
    fs::write(&object_path, b"corrupt").unwrap();
    fs::set_permissions(&object_path, fs::Permissions::from_mode(0o400)).unwrap();
    let report = engine.fsck_v1(&FsckRequestV1::new()).unwrap();
    assert!(
        report
            .findings()
            .iter()
            .any(|finding| { finding.code() == FsckFindingCodeV1::CorruptCanonicalObject })
    );
}

#[test]
fn retention_keeps_referenced_and_removes_orphan_canonical_objects() {
    let _test_guard = test_guard();
    let temp = tempfile::tempdir().unwrap();
    let target = temp.path().join("target");
    fs::create_dir(&target).unwrap();
    let engine = engine(&temp, &target);
    engine.initialize_store().unwrap();

    let retained = SymlinkObjectV1::new("retained").unwrap();
    let retained_digest = symlink_object_digest_v1(&retained);
    engine
        .publish_symlink_object_v1(&retained_digest, &retained)
        .unwrap();
    let orphan = SymlinkObjectV1::new("orphan").unwrap();
    let orphan_digest = symlink_object_digest_v1(&orphan);
    engine
        .publish_symlink_object_v1(&orphan_digest, &orphan)
        .unwrap();
    engine
        .prepare_v1(&request(
            None,
            vec![
                PrepareOperationV1::place_symlink(
                    DeploymentName::new("home").unwrap(),
                    "link",
                    retained_digest.clone(),
                )
                .unwrap(),
            ],
        ))
        .unwrap();

    engine.prune_v1(&PruneRequestV1::new(vec![])).unwrap();
    assert_eq!(
        engine.load_symlink_object_v1(&retained_digest).unwrap(),
        retained
    );
    assert!(engine.load_symlink_object_v1(&orphan_digest).is_err());
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ManagedKind {
    File,
    Directory,
    Symlink,
    Tree,
}

const MANAGED_KINDS: [ManagedKind; 4] = [
    ManagedKind::File,
    ManagedKind::Directory,
    ManagedKind::Symlink,
    ManagedKind::Tree,
];

struct KindObjects {
    symlink: Digest,
    tree: Digest,
}

fn publish_kind_objects(engine: &Engine) -> KindObjects {
    let symlink = SymlinkObjectV1::new("destination").unwrap();
    let symlink_digest = symlink_object_digest_v1(&symlink);
    engine
        .publish_symlink_object_v1(&symlink_digest, &symlink)
        .unwrap();
    let tree = TreeObjectV1::new(0o700, vec![]).unwrap();
    let tree_digest = tree_object_digest_v1(&tree);
    engine.publish_tree_object_v1(&tree_digest, &tree).unwrap();
    KindObjects {
        symlink: symlink_digest,
        tree: tree_digest,
    }
}

fn kind_request(
    expected_head: Option<Digest>,
    kind: ManagedKind,
    replace_existing: bool,
    objects: &KindObjects,
) -> PrepareRequestV1 {
    let authority = DeploymentName::new("home").unwrap();
    let artifact = ArtifactId::new("managed/file").unwrap();
    let (artifacts, operation) = match kind {
        ManagedKind::File => {
            let operation = if replace_existing {
                PrepareOperationV1::replace_file(authority, "managed", artifact.clone(), 0o600)
            } else {
                PrepareOperationV1::place_file(authority, "managed", artifact.clone(), 0o600)
            }
            .unwrap();
            (
                vec![
                    PrepareArtifactV1::new(
                        artifact,
                        b"managed file bytes\n".to_vec(),
                        "text/plain",
                    )
                    .unwrap(),
                ],
                operation,
            )
        }
        ManagedKind::Directory => {
            let operation = if replace_existing {
                PrepareOperationV1::replace_directory(authority, "managed", 0o700)
            } else {
                PrepareOperationV1::ensure_directory(authority, "managed", 0o700)
            }
            .unwrap();
            (vec![], operation)
        }
        ManagedKind::Symlink => {
            let operation = if replace_existing {
                PrepareOperationV1::replace_symlink(authority, "managed", objects.symlink.clone())
            } else {
                PrepareOperationV1::place_symlink(authority, "managed", objects.symlink.clone())
            }
            .unwrap();
            (vec![], operation)
        }
        ManagedKind::Tree => {
            let operation = if replace_existing {
                PrepareOperationV1::replace_tree(authority, "managed", objects.tree.clone())
            } else {
                PrepareOperationV1::place_tree(authority, "managed", objects.tree.clone())
            }
            .unwrap();
            (vec![], operation)
        }
    };
    PrepareRequestV1::from(PrepareRequestPartsV1 {
        namespace: NamespaceName::new("canonical").unwrap(),
        expected_head,
        graph_digest: Digest::sha256(format!("{kind:?}-{replace_existing}").as_bytes()),
        inputs: vec![],
        artifacts,
        transforms: vec![],
        findings: vec![],
        operations: vec![operation],
    })
}

fn assert_managed_kind(target: &Path, kind: ManagedKind) {
    let path = target.join("managed");
    let metadata = fs::symlink_metadata(&path).unwrap();
    match kind {
        ManagedKind::File => {
            assert!(metadata.file_type().is_file());
            assert_eq!(fs::read(path).unwrap(), b"managed file bytes\n");
        }
        ManagedKind::Directory | ManagedKind::Tree => {
            assert!(metadata.file_type().is_dir());
        }
        ManagedKind::Symlink => {
            assert!(metadata.file_type().is_symlink());
            assert_eq!(fs::read_link(path).unwrap(), Path::new("destination"));
        }
    }
}

fn assert_status_modified_and_commit_stale(
    engine: &Engine,
    prepared: &malm_engine::PreparedDeploymentV1,
) {
    assert_eq!(
        engine
            .inspect_namespace_status_v1(&NamespaceStatusRequestV1::new(
                NamespaceName::new("canonical").unwrap(),
            ))
            .unwrap()
            .status(),
        NamespaceStatusKindV1::EnabledModified
    );
    assert!(matches!(
        engine.commit_v1(&CommitRequestV1::new(
            prepared.plan_id().clone(),
            ApprovalV1::new(
                prepared.plan_id().clone(),
                prepared.approval_digest().clone(),
            ),
        )),
        Err(CommitError::StaleTarget(_) | CommitError::InvalidJournal(_))
    ));
}

fn publish_nested_tree(engine: &Engine) -> Digest {
    let contents = b"nested mode fixture\n";
    let file = file_object_digest_v1(contents).unwrap();
    engine.publish_file_object_v1(&file, contents).unwrap();
    let child = TreeObjectV1::new(
        0o750,
        vec![
            TreeEntryV1::file(
                TreePathSegmentV1::new("file.txt").unwrap(),
                0o640,
                file,
                contents.len() as u64,
            )
            .unwrap(),
        ],
    )
    .unwrap();
    let child_digest = tree_object_digest_v1(&child);
    engine
        .publish_tree_object_v1(&child_digest, &child)
        .unwrap();
    let link = SymlinkObjectV1::new("sub/file.txt").unwrap();
    let link_digest = symlink_object_digest_v1(&link);
    engine
        .publish_symlink_object_v1(&link_digest, &link)
        .unwrap();
    let root = TreeObjectV1::new(
        0o700,
        vec![
            TreeEntryV1::safe_relative_symlink(
                TreePathSegmentV1::new("current").unwrap(),
                link_digest,
            ),
            TreeEntryV1::directory(TreePathSegmentV1::new("sub").unwrap(), 0o750, child_digest)
                .unwrap(),
        ],
    )
    .unwrap();
    let root_digest = tree_object_digest_v1(&root);
    engine.publish_tree_object_v1(&root_digest, &root).unwrap();
    root_digest
}

fn nested_tree_request(expected_head: Option<Digest>, tree: Digest) -> PrepareRequestV1 {
    request(
        expected_head,
        vec![
            PrepareOperationV1::place_tree(DeploymentName::new("home").unwrap(), "managed", tree)
                .unwrap(),
        ],
    )
}

#[test]
fn every_pairwise_target_kind_change_is_a_reviewed_replacement() {
    let _test_guard = test_guard();
    for from in MANAGED_KINDS {
        for to in MANAGED_KINDS {
            if from == to {
                continue;
            }
            let temp = tempfile::tempdir().unwrap();
            let target = temp.path().join("target");
            fs::create_dir(&target).unwrap();
            let engine = engine(&temp, &target);
            engine.initialize_store().unwrap();
            let objects = publish_kind_objects(&engine);
            let initial = engine
                .prepare_v1(&kind_request(None, from, false, &objects))
                .unwrap();
            let initial = commit(&engine, &initial);
            let replacement = engine
                .prepare_v1(&kind_request(
                    Some(initial.head().clone()),
                    to,
                    true,
                    &objects,
                ))
                .unwrap();
            assert_eq!(replacement.operations().len(), 1, "{from:?} -> {to:?}");
            assert!(
                replacement.operations()[0].replaces_existing(),
                "{from:?} -> {to:?}"
            );
            commit(&engine, &replacement);
            assert_managed_kind(&target, to);
        }
    }
}

#[test]
fn directory_mode_change_replaces_the_inode_with_the_exact_reviewed_mode() {
    let _test_guard = test_guard();
    let temp = tempfile::tempdir().unwrap();
    let target = temp.path().join("target");
    fs::create_dir(&target).unwrap();
    let engine = engine(&temp, &target);
    engine.initialize_store().unwrap();
    let first = engine
        .prepare_v1(&request(
            None,
            vec![
                PrepareOperationV1::ensure_directory(
                    DeploymentName::new("home").unwrap(),
                    "managed",
                    0o750,
                )
                .unwrap(),
            ],
        ))
        .unwrap();
    let first = commit(&engine, &first);
    let old_inode = fs::metadata(target.join("managed")).unwrap().ino();
    let replacement = engine
        .prepare_v1(&request(
            Some(first.head().clone()),
            vec![
                PrepareOperationV1::ensure_directory(
                    DeploymentName::new("home").unwrap(),
                    "managed",
                    0o700,
                )
                .unwrap(),
            ],
        ))
        .unwrap();
    assert!(matches!(
        replacement.operations(),
        [PrepareOperationV1::EnsureDirectory {
            mode: 0o700,
            replace_existing: true,
            ..
        }]
    ));
    commit(&engine, &replacement);
    let metadata = fs::metadata(target.join("managed")).unwrap();
    assert_eq!(metadata.permissions().mode() & 0o7777, 0o700);
    assert_ne!(metadata.ino(), old_inode);
}

#[test]
fn special_permission_drift_is_modified_and_blocks_commit_for_files_and_directories() {
    let _test_guard = test_guard();
    for kind in [ManagedKind::File, ManagedKind::Directory] {
        for special in [0o4000, 0o2000, 0o1000] {
            let temp = tempfile::tempdir().unwrap();
            let target = temp.path().join("target");
            fs::create_dir(&target).unwrap();
            let engine = engine(&temp, &target);
            engine.initialize_store().unwrap();
            let objects = publish_kind_objects(&engine);
            let initial = engine
                .prepare_v1(&kind_request(None, kind, false, &objects))
                .unwrap();
            let initial = commit(&engine, &initial);
            let exact = engine
                .prepare_v1(&kind_request(
                    Some(initial.head().clone()),
                    kind,
                    false,
                    &objects,
                ))
                .unwrap();
            let base = if kind == ManagedKind::File {
                0o600
            } else {
                0o700
            };
            fs::set_permissions(
                target.join("managed"),
                fs::Permissions::from_mode(base | special),
            )
            .unwrap();

            assert_status_modified_and_commit_stale(&engine, &exact);
            assert_eq!(
                fs::symlink_metadata(target.join("managed"))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o7777,
                base | special
            );
        }
    }
}

#[test]
fn nested_tree_special_permission_drift_is_modified_and_blocks_commit() {
    let _test_guard = test_guard();
    for (relative_path, base, special) in [
        ("managed", 0o700, 0o1000),
        ("managed/sub", 0o750, 0o2000),
        ("managed/sub/file.txt", 0o640, 0o4000),
    ] {
        let temp = tempfile::tempdir().unwrap();
        let target = temp.path().join("target");
        fs::create_dir(&target).unwrap();
        let engine = engine(&temp, &target);
        engine.initialize_store().unwrap();
        let tree = publish_nested_tree(&engine);
        let initial = engine
            .prepare_v1(&nested_tree_request(None, tree.clone()))
            .unwrap();
        let initial = commit(&engine, &initial);
        let exact = engine
            .prepare_v1(&nested_tree_request(Some(initial.head().clone()), tree))
            .unwrap();
        fs::set_permissions(
            target.join(relative_path),
            fs::Permissions::from_mode(base | special),
        )
        .unwrap();

        assert_status_modified_and_commit_stale(&engine, &exact);
    }
}

#[test]
fn hard_linked_symlink_aliases_are_modified_and_block_commit_at_all_tree_depths() {
    let _test_guard = test_guard();
    for nested in [false, true] {
        let temp = tempfile::tempdir().unwrap();
        let target = temp.path().join("target");
        fs::create_dir(&target).unwrap();
        let engine = engine(&temp, &target);
        engine.initialize_store().unwrap();
        let (initial, exact, link) = if nested {
            let tree = publish_nested_tree(&engine);
            let initial = engine
                .prepare_v1(&nested_tree_request(None, tree.clone()))
                .unwrap();
            let initial = commit(&engine, &initial);
            let exact = engine
                .prepare_v1(&nested_tree_request(Some(initial.head().clone()), tree))
                .unwrap();
            (initial, exact, target.join("managed/current"))
        } else {
            let objects = publish_kind_objects(&engine);
            let initial = engine
                .prepare_v1(&kind_request(None, ManagedKind::Symlink, false, &objects))
                .unwrap();
            let initial = commit(&engine, &initial);
            let exact = engine
                .prepare_v1(&kind_request(
                    Some(initial.head().clone()),
                    ManagedKind::Symlink,
                    false,
                    &objects,
                ))
                .unwrap();
            (initial, exact, target.join("managed"))
        };
        let _ = initial;
        let alias = target.join("symlink-alias");
        fs::hard_link(&link, &alias).unwrap();
        assert_eq!(fs::symlink_metadata(&link).unwrap().nlink(), 2);

        assert_status_modified_and_commit_stale(&engine, &exact);
        assert!(
            fs::symlink_metadata(alias)
                .unwrap()
                .file_type()
                .is_symlink()
        );
    }
}

#[cfg(feature = "failpoints")]
const CRASH_ROOT_ENV: &str = "MALM_CANONICAL_COMMIT_CRASH_ROOT";
#[cfg(feature = "failpoints")]
const CRASH_PLAN_ENV: &str = "MALM_CANONICAL_COMMIT_CRASH_PLAN";
#[cfg(feature = "failpoints")]
const CRASH_CHILD_TEST: &str = "crash_canonical_commit_child";

#[cfg(feature = "failpoints")]
fn reopened_engine(root: &Path) -> Engine {
    Engine::new(
        EngineConfig::from_state_home(root.join("state"), StoreAccess::ReadWrite)
            .unwrap()
            .with_target_authority(DeploymentName::new("home").unwrap(), root.join("target"))
            .unwrap(),
        EnginePorts::system(),
    )
}

#[cfg(feature = "failpoints")]
fn crash_commit_at(root: &Path, prepared: &malm_engine::PreparedDeploymentV1, failpoint: &str) {
    let output = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", CRASH_CHILD_TEST, "--nocapture"])
        .env(CRASH_ROOT_ENV, root)
        .env(CRASH_PLAN_ENV, prepared.plan_id().to_string())
        .env("MALM_FAILPOINT", failpoint)
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !output.status.success() && stderr.contains(&format!("failpoint {failpoint}: aborting")),
        "child did not abort at {failpoint}\nstatus: {:?}\nstdout:\n{}\nstderr:\n{stderr}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
    );
}

#[cfg(feature = "failpoints")]
#[test]
fn every_pairwise_kind_change_rolls_back_and_rolls_forward_after_crashes() {
    let _test_guard = test_guard();
    for from in MANAGED_KINDS {
        for to in MANAGED_KINDS {
            if from == to {
                continue;
            }
            let temp = tempfile::tempdir().unwrap();
            let target = temp.path().join("target");
            fs::create_dir(&target).unwrap();
            let engine = engine(&temp, &target);
            engine.initialize_store().unwrap();
            let objects = publish_kind_objects(&engine);
            let initial = engine
                .prepare_v1(&kind_request(None, from, false, &objects))
                .unwrap();
            let initial = commit(&engine, &initial);
            let replacement = engine
                .prepare_v1(&kind_request(
                    Some(initial.head().clone()),
                    to,
                    true,
                    &objects,
                ))
                .unwrap();

            crash_commit_at(
                temp.path(),
                &replacement,
                "v1.commit.burst.after_final_sync",
            );
            engine.recover_v1().unwrap();
            assert_managed_kind(&target, from);

            let replacement = engine
                .prepare_v1(&kind_request(
                    Some(initial.head().clone()),
                    to,
                    true,
                    &objects,
                ))
                .unwrap();
            crash_commit_at(temp.path(), &replacement, "v1.commit.after_catalog");
            engine.recover_v1().unwrap();
            assert_managed_kind(&target, to);
        }
    }
}

#[cfg(feature = "failpoints")]
#[test]
fn directory_mode_change_rolls_back_and_rolls_forward_after_crashes() {
    let _test_guard = test_guard();
    let temp = tempfile::tempdir().unwrap();
    let target = temp.path().join("target");
    fs::create_dir(&target).unwrap();
    let engine = engine(&temp, &target);
    engine.initialize_store().unwrap();
    let initial = engine
        .prepare_v1(&request(
            None,
            vec![
                PrepareOperationV1::ensure_directory(
                    DeploymentName::new("home").unwrap(),
                    "managed",
                    0o750,
                )
                .unwrap(),
            ],
        ))
        .unwrap();
    let initial = commit(&engine, &initial);
    let replacement = engine
        .prepare_v1(&request(
            Some(initial.head().clone()),
            vec![
                PrepareOperationV1::ensure_directory(
                    DeploymentName::new("home").unwrap(),
                    "managed",
                    0o700,
                )
                .unwrap(),
            ],
        ))
        .unwrap();

    crash_commit_at(
        temp.path(),
        &replacement,
        "v1.commit.burst.after_final_sync",
    );
    engine.recover_v1().unwrap();
    assert_eq!(
        fs::metadata(target.join("managed"))
            .unwrap()
            .permissions()
            .mode()
            & 0o7777,
        0o750
    );

    let replacement = engine
        .prepare_v1(&request(
            Some(initial.head().clone()),
            vec![
                PrepareOperationV1::ensure_directory(
                    DeploymentName::new("home").unwrap(),
                    "managed",
                    0o700,
                )
                .unwrap(),
            ],
        ))
        .unwrap();
    crash_commit_at(temp.path(), &replacement, "v1.commit.after_catalog");
    engine.recover_v1().unwrap();
    assert_eq!(
        fs::metadata(target.join("managed"))
            .unwrap()
            .permissions()
            .mode()
            & 0o7777,
        0o700
    );
}

#[cfg(feature = "failpoints")]
#[test]
fn crash_canonical_commit_child() {
    let _test_guard = test_guard();
    let Some(root) = std::env::var_os(CRASH_ROOT_ENV) else {
        return;
    };
    let plan_id = PreparedId::new(std::env::var(CRASH_PLAN_ENV).unwrap()).unwrap();
    let engine = reopened_engine(&PathBuf::from(root));
    let prepared = engine.plan_v1(&plan_id).unwrap();
    commit(&engine, &prepared);
    panic!("configured commit failpoint did not fire");
}

#[cfg(feature = "failpoints")]
#[test]
fn crash_before_catalog_rolls_back_a_canonical_symlink() {
    let _test_guard = test_guard();
    let temp = tempfile::tempdir().unwrap();
    let target = temp.path().join("target");
    fs::create_dir(&target).unwrap();
    let engine = engine(&temp, &target);
    engine.initialize_store().unwrap();

    let object = SymlinkObjectV1::new("destination").unwrap();
    let digest = symlink_object_digest_v1(&object);
    engine.publish_symlink_object_v1(&digest, &object).unwrap();
    let prepared = engine
        .prepare_v1(&request(
            None,
            vec![
                PrepareOperationV1::place_symlink(
                    DeploymentName::new("home").unwrap(),
                    "link",
                    digest,
                )
                .unwrap(),
            ],
        ))
        .unwrap();

    crash_commit_at(temp.path(), &prepared, "v1.commit.burst.after_final_sync");
    assert_eq!(
        fs::read_link(target.join("link")).unwrap(),
        Path::new("destination")
    );

    let restarted = reopened_engine(temp.path());
    let recovered = restarted.recover_v1().unwrap();
    let namespace = NamespaceName::new("canonical").unwrap();
    assert_eq!(recovered.namespace(), Some(&namespace));
    assert!(recovered.head().is_none());
    assert!(!target.join("link").exists());
    assert!(
        restarted
            .inspect_state_v1(&namespace)
            .unwrap()
            .head()
            .is_none()
    );
}

#[cfg(feature = "failpoints")]
#[test]
fn crash_after_catalog_rolls_forward_a_nonempty_canonical_tree() {
    let _test_guard = test_guard();
    let temp = tempfile::tempdir().unwrap();
    let target = temp.path().join("target");
    fs::create_dir(&target).unwrap();
    let engine = engine(&temp, &target);
    engine.initialize_store().unwrap();

    let contents = b"durable canonical tree\n";
    let file = file_object_digest_v1(contents).unwrap();
    engine.publish_file_object_v1(&file, contents).unwrap();
    let tree = TreeObjectV1::new(
        0o700,
        vec![
            TreeEntryV1::file(
                TreePathSegmentV1::new("file.txt").unwrap(),
                0o600,
                file,
                contents.len() as u64,
            )
            .unwrap(),
        ],
    )
    .unwrap();
    let digest = tree_object_digest_v1(&tree);
    engine.publish_tree_object_v1(&digest, &tree).unwrap();
    let prepared = engine
        .prepare_v1(&request(
            None,
            vec![
                PrepareOperationV1::place_tree(
                    DeploymentName::new("home").unwrap(),
                    "tree",
                    digest,
                )
                .unwrap(),
            ],
        ))
        .unwrap();

    crash_commit_at(temp.path(), &prepared, "v1.commit.after_catalog");
    assert_eq!(fs::read(target.join("tree/file.txt")).unwrap(), contents);

    let restarted = reopened_engine(temp.path());
    let recovered = restarted.recover_v1().unwrap();
    let namespace = NamespaceName::new("canonical").unwrap();
    assert_eq!(recovered.namespace(), Some(&namespace));
    assert!(recovered.head().is_some());
    assert_eq!(fs::read(target.join("tree/file.txt")).unwrap(), contents);
    assert_eq!(
        restarted
            .inspect_namespace_status_v1(&NamespaceStatusRequestV1::new(namespace))
            .unwrap()
            .status(),
        NamespaceStatusKindV1::EnabledExact
    );
}

#[cfg(feature = "failpoints")]
#[test]
fn crash_before_catalog_rolls_back_namespace_removal() {
    let _test_guard = test_guard();
    let temp = tempfile::tempdir().unwrap();
    let target = temp.path().join("target");
    fs::create_dir(&target).unwrap();
    let engine = engine(&temp, &target);
    engine.initialize_store().unwrap();

    let object = SymlinkObjectV1::new("destination").unwrap();
    let digest = symlink_object_digest_v1(&object);
    engine.publish_symlink_object_v1(&digest, &object).unwrap();
    let prepared = engine
        .prepare_v1(&request(
            None,
            vec![
                PrepareOperationV1::place_symlink(
                    DeploymentName::new("home").unwrap(),
                    "link",
                    digest,
                )
                .unwrap(),
            ],
        ))
        .unwrap();
    let previous = commit(&engine, &prepared).head().clone();
    let removal = engine
        .prepare_namespace_removal_v1(&NamespaceRemovalRequestV1::new(
            NamespaceName::new("canonical").unwrap(),
            NamespaceRemovalHistoryV1::Drop,
        ))
        .unwrap();

    crash_commit_at(temp.path(), &removal, "v1.commit.burst.after_final_sync");
    assert!(!target.join("link").exists());

    let restarted = reopened_engine(temp.path());
    let recovered = restarted.recover_v1().unwrap();
    assert_eq!(recovered.head(), Some(&previous));
    assert_eq!(
        fs::read_link(target.join("link")).unwrap(),
        Path::new("destination")
    );
    assert_eq!(
        restarted
            .inspect_state_v1(&NamespaceName::new("canonical").unwrap())
            .unwrap()
            .head(),
        Some(&previous)
    );
}

#[cfg(feature = "failpoints")]
#[test]
fn crash_after_catalog_rolls_forward_namespace_removal() {
    let _test_guard = test_guard();
    let temp = tempfile::tempdir().unwrap();
    let target = temp.path().join("target");
    fs::create_dir(&target).unwrap();
    let engine = engine(&temp, &target);
    engine.initialize_store().unwrap();

    let object = SymlinkObjectV1::new("destination").unwrap();
    let digest = symlink_object_digest_v1(&object);
    engine.publish_symlink_object_v1(&digest, &object).unwrap();
    let prepared = engine
        .prepare_v1(&request(
            None,
            vec![
                PrepareOperationV1::place_symlink(
                    DeploymentName::new("home").unwrap(),
                    "link",
                    digest,
                )
                .unwrap(),
            ],
        ))
        .unwrap();
    commit(&engine, &prepared);
    let removal = engine
        .prepare_namespace_removal_v1(&NamespaceRemovalRequestV1::new(
            NamespaceName::new("canonical").unwrap(),
            NamespaceRemovalHistoryV1::Drop,
        ))
        .unwrap();

    crash_commit_at(temp.path(), &removal, "v1.commit.after_catalog");
    assert!(!target.join("link").exists());

    let restarted = reopened_engine(temp.path());
    let recovered = restarted.recover_v1().unwrap();
    assert!(recovered.head().is_none());
    assert!(!target.join("link").exists());
    assert!(
        restarted
            .inspect_state_v1(&NamespaceName::new("canonical").unwrap())
            .unwrap()
            .head()
            .is_none()
    );
}

fn restore_fixture_request(expected_head: Option<Digest>, with_nested: bool) -> PrepareRequestV1 {
    let authority = DeploymentName::new("home").unwrap();
    let mut artifacts = vec![
        PrepareArtifactV1::new(
            ArtifactId::new("root/two").unwrap(),
            b"root file\n".to_vec(),
            "text/plain",
        )
        .unwrap(),
    ];
    let mut operations = vec![
        PrepareOperationV1::place_file(
            authority.clone(),
            "two",
            ArtifactId::new("root/two").unwrap(),
            0o600,
        )
        .unwrap(),
    ];
    if with_nested {
        artifacts.push(
            PrepareArtifactV1::new(
                ArtifactId::new("nested/one").unwrap(),
                b"nested file\n".to_vec(),
                "text/plain",
            )
            .unwrap(),
        );
        operations.push(
            PrepareOperationV1::place_file(
                authority,
                "a/b/one",
                ArtifactId::new("nested/one").unwrap(),
                0o600,
            )
            .unwrap(),
        );
    }
    PrepareRequestV1::from(PrepareRequestPartsV1 {
        namespace: NamespaceName::new("canonical").unwrap(),
        expected_head,
        graph_digest: Digest::sha256(b"canonical graph"),
        inputs: vec![],
        artifacts,
        transforms: vec![],
        findings: vec![],
        operations,
    })
}

#[test]
fn deleted_ancestors_and_leaves_restore_through_hand_built_requests() {
    let _test_guard = test_guard();
    let temp = tempfile::tempdir().unwrap();
    let target = temp.path().join("target");
    fs::create_dir(&target).unwrap();
    fs::create_dir_all(target.join("a/b")).unwrap();
    let engine = engine(&temp, &target);
    engine.initialize_store().unwrap();

    let initial = engine
        .prepare_v1(&restore_fixture_request(None, true))
        .unwrap();
    let applied = commit(&engine, &initial);

    // Removing the complete nested skeleton requires reconciliation to emit
    // directory operations before restoring its retained leaf.
    fs::remove_dir_all(target.join("a")).unwrap();
    let restore = engine
        .prepare_v1(&restore_fixture_request(Some(applied.head().clone()), true))
        .unwrap();
    assert!(
        restore
            .findings()
            .iter()
            .any(|finding| finding.code() == "restore-missing-directory"
                && finding.message().contains("home:a/b")
                && !finding.approval_required()),
        "nested ancestors synthesize advisory creations: {:?}",
        restore.findings()
    );
    let restored = commit(&engine, &restore);
    assert_eq!(
        fs::read_to_string(target.join("a/b/one")).unwrap(),
        "nested file\n"
    );

    // A missing ancestor already satisfies every removal below it, including
    // removals for namespace-owned directories in that absent subtree.
    fs::remove_dir_all(target.join("a")).unwrap();
    let drop_nested = engine
        .prepare_v1(&restore_fixture_request(
            Some(restored.head().clone()),
            false,
        ))
        .unwrap();
    commit(&engine, &drop_nested);
    assert!(!target.join("a").exists());
    assert_eq!(
        fs::read_to_string(target.join("two")).unwrap(),
        "root file\n"
    );
}

#[test]
fn externally_recreated_pending_ancestors_fail_closed_at_commit() {
    let _test_guard = test_guard();
    let temp = tempfile::tempdir().unwrap();
    let target = temp.path().join("target");
    fs::create_dir(&target).unwrap();
    fs::create_dir_all(target.join("a/b")).unwrap();
    let engine = engine(&temp, &target);
    engine.initialize_store().unwrap();
    let initial = engine
        .prepare_v1(&restore_fixture_request(None, true))
        .unwrap();
    let applied = commit(&engine, &initial);

    fs::remove_dir_all(target.join("a")).unwrap();
    let restore = engine
        .prepare_v1(&restore_fixture_request(Some(applied.head().clone()), true))
        .unwrap();

    // External recreation after prepare invalidates the parent pin. Commit
    // must refuse before mutation, with the absence check as a second guard.
    fs::create_dir(target.join("a")).unwrap();
    let error = engine
        .commit_v1(&CommitRequestV1::new(
            restore.plan_id().clone(),
            ApprovalV1::new(restore.plan_id().clone(), restore.approval_digest().clone()),
        ))
        .unwrap_err();
    let rendered = format!("{error}");
    assert!(
        rendered.contains("identity changed") || rendered.contains("created externally"),
        "external recreation fails the commit closed: {rendered}"
    );
    assert!(
        !target.join("a/b").exists(),
        "the refused commit mutated nothing"
    );

    // Removing the externally created directory and preparing again captures
    // current absence and produces a committable plan.
    fs::remove_dir(target.join("a")).unwrap();
    let fresh = engine
        .prepare_v1(&restore_fixture_request(Some(applied.head().clone()), true))
        .unwrap();
    commit(&engine, &fresh);
    assert_eq!(
        fs::read_to_string(target.join("a/b/one")).unwrap(),
        "nested file\n"
    );
}

#[test]
fn unrestorable_deleted_targets_refuse_with_the_typed_error() {
    let _test_guard = test_guard();
    let temp = tempfile::tempdir().unwrap();
    let target = temp.path().join("target");
    fs::create_dir(&target).unwrap();
    let engine = engine(&temp, &target);
    engine.initialize_store().unwrap();
    let initial = engine
        .prepare_v1(&restore_fixture_request(None, false))
        .unwrap();
    let applied = commit(&engine, &initial);

    fs::remove_file(target.join("two")).unwrap();
    // An assertion-only request carries no artifact bytes, so the deleted
    // file cannot be recreated from it.
    let request = PrepareRequestV1::from(PrepareRequestPartsV1 {
        namespace: NamespaceName::new("canonical").unwrap(),
        expected_head: Some(applied.head().clone()),
        graph_digest: Digest::sha256(b"canonical graph"),
        inputs: vec![],
        artifacts: vec![],
        transforms: vec![],
        findings: vec![],
        operations: vec![
            PrepareOperationV1::assert_exact(
                DeploymentName::new("home").unwrap(),
                "two",
                malm_types::PrepareTargetStateV1::file(Digest::sha256(b"root file\n"), 10, 0o600)
                    .unwrap(),
            )
            .unwrap(),
        ],
    });
    let error = engine.prepare_v1(&request).unwrap_err();
    assert!(
        format!("{error}").contains("deleted outside malm"),
        "the refusal names the deletion: {error}"
    );
}

#[cfg(feature = "failpoints")]
#[test]
fn deleted_ancestor_restores_roll_back_and_roll_forward_after_crashes() {
    let _test_guard = test_guard();
    let temp = tempfile::tempdir().unwrap();
    let target = temp.path().join("target");
    fs::create_dir(&target).unwrap();
    fs::create_dir_all(target.join("a/b")).unwrap();
    let engine = engine(&temp, &target);
    engine.initialize_store().unwrap();
    let initial = engine
        .prepare_v1(&restore_fixture_request(None, true))
        .unwrap();
    let applied = commit(&engine, &initial);
    fs::remove_dir_all(target.join("a")).unwrap();

    // Every pre-catalog crash rolls back created directories and staging.
    // Each attempt re-prepares because recovery can change parent identity.
    // `ensure.before_identity` has separate fail-closed durability coverage.
    for failpoint in [
        "v1.commit.before_operation",
        "v1.commit.ensure.after_create",
        "v1.commit.after_operation",
        "v1.commit.place.after_identity",
        "v1.commit.place.after_staging",
        "v1.commit.place.after_backup_intent",
        "v1.commit.burst.after_final_sync",
        "v1.commit.verify.before_final_rebound",
    ] {
        let restore = engine
            .prepare_v1(&restore_fixture_request(Some(applied.head().clone()), true))
            .unwrap();
        crash_commit_at(temp.path(), &restore, failpoint);
        engine.recover_v1().unwrap();
        assert!(
            !target.join("a").exists(),
            "recovery after {failpoint} restores the deleted-directory world"
        );
    }

    // Once the catalog points at the new generation, recovery rolls forward
    // and completes every journaled target operation.
    let restore = engine
        .prepare_v1(&restore_fixture_request(Some(applied.head().clone()), true))
        .unwrap();
    crash_commit_at(temp.path(), &restore, "v1.commit.after_catalog");
    engine.recover_v1().unwrap();
    assert_eq!(
        fs::read_to_string(target.join("a/b/one")).unwrap(),
        "nested file\n"
    );
    assert_eq!(
        fs::metadata(target.join("a")).unwrap().permissions().mode() & 0o7777,
        0o755
    );
}

#[cfg(feature = "failpoints")]
#[test]
fn recovery_refuses_externally_replaced_created_ancestors() {
    let _test_guard = test_guard();
    let temp = tempfile::tempdir().unwrap();
    let target = temp.path().join("target");
    fs::create_dir(&target).unwrap();
    fs::create_dir_all(target.join("a/b")).unwrap();
    let engine = engine(&temp, &target);
    engine.initialize_store().unwrap();
    let initial = engine
        .prepare_v1(&restore_fixture_request(None, true))
        .unwrap();
    let applied = commit(&engine, &initial);
    fs::remove_dir_all(target.join("a")).unwrap();
    let restore = engine
        .prepare_v1(&restore_fixture_request(Some(applied.head().clone()), true))
        .unwrap();

    // After the first operation journals and creates `a`, replacing it with a
    // different inode invalidates the journaled identity. Recovery must refuse
    // rather than mutate the externally created directory.
    crash_commit_at(temp.path(), &restore, "v1.commit.after_operation");
    fs::remove_dir(target.join("a")).unwrap();
    fs::create_dir(target.join("a")).unwrap();
    let error = engine.recover_v1().unwrap_err();
    let rendered = format!("{error}");
    assert!(
        rendered.contains("identity changed") || rendered.contains("externally"),
        "foreign replacement fails recovery closed: {rendered}"
    );
}

#[test]
fn asserted_owned_directories_tolerate_canonical_child_mutations() {
    let _test_guard = test_guard();
    let temp = tempfile::tempdir().unwrap();
    let target = temp.path().join("target");
    fs::create_dir(&target).unwrap();
    let engine = engine(&temp, &target);
    engine.initialize_store().unwrap();
    let authority = DeploymentName::new("home").unwrap();

    let first = SymlinkObjectV1::new("one").unwrap();
    let first_digest = symlink_object_digest_v1(&first);
    engine
        .publish_symlink_object_v1(&first_digest, &first)
        .unwrap();
    let second = SymlinkObjectV1::new("two").unwrap();
    let second_digest = symlink_object_digest_v1(&second);
    engine
        .publish_symlink_object_v1(&second_digest, &second)
        .unwrap();

    // Create the directory through restoration so the namespace owns it.
    let initial = engine
        .prepare_v1(&request(
            None,
            vec![
                PrepareOperationV1::ensure_directory(authority.clone(), "owned", 0o755).unwrap(),
                PrepareOperationV1::place_symlink(
                    authority.clone(),
                    "owned/link",
                    first_digest.clone(),
                )
                .unwrap(),
            ],
        ))
        .unwrap();
    let applied = commit(&engine, &initial);

    // Replacing the child changes the asserted directory's mtime before its
    // phased revalidation; the assertion must still hold.
    let replace = engine
        .prepare_v1(&request(
            Some(applied.head().clone()),
            vec![
                PrepareOperationV1::ensure_directory(authority.clone(), "owned", 0o755).unwrap(),
                PrepareOperationV1::replace_symlink(authority, "owned/link", second_digest)
                    .unwrap(),
            ],
        ))
        .unwrap();
    assert!(
        replace.operations().iter().any(|operation| matches!(
            operation,
            PrepareOperationV1::AssertExact { .. }
        ) && operation.relative_path() == "owned"),
        "the unchanged owned directory reconciles to an exact assertion"
    );
    commit(&engine, &replace);
    assert_eq!(
        fs::read_link(target.join("owned/link")).unwrap(),
        Path::new("two")
    );
}
