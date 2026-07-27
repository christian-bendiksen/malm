use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File},
    io,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::Path,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
};

use malm_engine::{
    ApprovalV1, CommitRequestV1, ConfigEntryPointV1, DiagnosticSink, Engine, EngineConfig,
    EnginePorts, FormatComponentAuthorizationV1, FsckRequestV1, GitAcquisitionConfig,
    GitAcquisitionIssue, GitObjectFormat, GitPackFile, GitProcessPort, MovingSelectorV1,
    PrepareArtifactV1, PrepareOperationV1, PrepareRequestPartsV1, PrepareRequestV1, ProcessFacts,
    ProfileSwitchRequestV1, ProgressSink, PruneRequestV1, RecoveryOutcomeV1, RetentionObjectV1,
    RetentionPinRequestV1, SecureRandomPort, StoreAccess, TrackedRootAcquisitionGrantsV1,
    TrackedRootError, TrackedRootInfrastructureV1, TrackedRootPrepareRequestPartsV1,
    TrackedRootPrepareRequestV1, TrackedRootUpdateOutcomeV1, TrackedRootUpdateRequestV1,
};
use malm_pack::{
    DependencySourceV1, GitObjectId, GitSourceV1, GitUrl, LocalLocator, LockV1, LockedDependencyV1,
    LockedPackV1, LockedSourceV1, PackDependencyV1, PackFileV1, PackManifestV1, PackPath,
    PackSubdir, encode_lock_v1, encode_pack_v1, pack_content_digest,
};
use malm_tree::{TreeEntryKindV1, file_object_digest_v1};
use malm_types::{
    Alias, ArtifactId, ContributionName, DeploymentName, Digest, NamespaceName, PackageId,
};

const SOURCE_URL: &str = "https://example.invalid/tracked.git";
const DEPENDENCY_URL: &str = "https://example.invalid/dependency.git";
const SELECTOR: &str = "refs/heads/main";
const SOURCE_SUBDIR: &str = "packs/root";
const CONFIG_ENTRY: &str = "config/deployment.kdl";

fn revision(digit: char) -> String {
    format!("sha1-{}", digit.to_string().repeat(40))
}

fn raw_revision(tagged: &str) -> &str {
    tagged.strip_prefix("sha1-").unwrap()
}

fn pack_path(value: &str) -> PackPath {
    PackPath::new(value).unwrap()
}

struct Snapshot {
    files: Vec<GitPackFile>,
    pack_digest: Digest,
}

fn snapshot(contents: &[u8], dependency: bool) -> Snapshot {
    build_snapshot(contents, dependency, &[], &[])
}

/// A tracked root whose manifest narrows capture roots, committed alongside a
/// file outside those roots. Its lock records the narrowed digest.
fn narrowed_snapshot(contents: &[u8]) -> Snapshot {
    build_snapshot(
        contents,
        false,
        &["files", CONFIG_ENTRY],
        &[("docs/notes.md", b"outside the capture roots\n")],
    )
}

fn build_snapshot(
    contents: &[u8],
    dependency: bool,
    capture_roots: &[&str],
    uncaptured: &[(&str, &[u8])],
) -> Snapshot {
    let source_path = pack_path("files/theme.conf");
    let config_path = pack_path(CONFIG_ENTRY);
    let dependency_source = GitSourceV1::new(
        GitUrl::new(DEPENDENCY_URL).unwrap(),
        GitObjectId::new(revision('d')).unwrap(),
        PackSubdir::new(".").unwrap(),
    );
    let dependencies = dependency
        .then(|| {
            PackDependencyV1::new(
                Alias::new("dependency").unwrap(),
                PackageId::new("com.example.dependency").unwrap(),
                DependencySourceV1::Git(dependency_source.clone()),
            )
        })
        .into_iter()
        .collect();
    let manifest = PackManifestV1::new(
        PackageId::new("com.example.tracked").unwrap(),
        vec![],
        dependencies,
        vec![],
        vec![],
        vec![source_path.clone()],
        vec![],
    )
    .unwrap()
    .with_config_documents(vec![config_path.clone()])
    .unwrap()
    .with_capture_roots(capture_roots.iter().map(|root| pack_path(root)).collect())
    .unwrap();
    let raw_digest = Digest::sha256(contents);
    let object_digest = file_object_digest_v1(contents).unwrap();
    let config = format!(
        r#"rich-config schema-version=1 default-profile="desktop" {{
    includes {{}}
    modules {{}}
    variables {{}}
    fragments {{}}
    slots {{}}
    statements {{}}
    profiles {{
        profile "desktop" abstract=#false {{
            extends {{}}
            statements {{}}
            outputs {{
                regular-file "configuration" destination="config/theme.conf" source="{}" source-kind="asset" raw-digest="{raw_digest}" object-digest="{object_digest}" byte-len={} executable=#true
            }}
        }}
        profile "portable" abstract=#false {{
            extends {{}}
            statements {{}}
            outputs {{
                regular-file "configuration" destination="config/theme.conf" source="{}" source-kind="asset" raw-digest="{raw_digest}" object-digest="{object_digest}" byte-len={} executable=#true
            }}
        }}
    }}
}}"#,
        source_path.as_str(),
        contents.len(),
        source_path.as_str(),
        contents.len(),
    );
    let logical = vec![
        PackFileV1::new(pack_path("malm-pack.kdl"), encode_pack_v1(&manifest)),
        PackFileV1::new(config_path, config.into_bytes()),
        PackFileV1::new(source_path, contents),
    ];
    let pack_digest =
        pack_content_digest(logical.iter().map(|file| (file.path(), file.bytes()))).unwrap();
    let root_dependencies = dependency
        .then(|| {
            let dependency_pack = dependency_pack();
            LockedDependencyV1::new(
                Alias::new("dependency").unwrap(),
                dependency_pack.node_id().clone(),
            )
        })
        .into_iter()
        .collect::<Vec<_>>();
    let root = LockedPackV1::new(
        PackageId::new("com.example.tracked").unwrap(),
        LockedSourceV1::Root,
        pack_digest.clone(),
        root_dependencies,
        vec![],
    )
    .unwrap();
    let mut nodes = vec![root.clone()];
    if dependency {
        nodes.push(dependency_pack());
    }
    let lock = LockV1::new(root.node_id().clone(), nodes).unwrap();
    let mut files = logical
        .into_iter()
        .map(|file| {
            let (path, bytes) = file.into_parts();
            if path.as_str() == "files/theme.conf" {
                GitPackFile::with_mode(path.into_inner(), bytes, 0o755).unwrap()
            } else {
                GitPackFile::new(path.into_inner(), bytes)
            }
        })
        .collect::<Vec<_>>();
    files.push(GitPackFile::new(
        malm_pack::LOCK_FILE,
        encode_lock_v1(&lock),
    ));
    for (path, bytes) in uncaptured {
        files.push(GitPackFile::new(*path, bytes.to_vec()));
    }
    Snapshot { files, pack_digest }
}

fn dependency_pack() -> LockedPackV1 {
    let manifest = PackManifestV1::new(
        PackageId::new("com.example.dependency").unwrap(),
        vec![],
        vec![],
        vec![],
        vec![],
        vec![],
        vec![],
    )
    .unwrap();
    let files = [PackFileV1::new(
        pack_path("malm-pack.kdl"),
        encode_pack_v1(&manifest),
    )];
    let digest = pack_content_digest(files.iter().map(|file| (file.path(), file.bytes()))).unwrap();
    LockedPackV1::new(
        PackageId::new("com.example.dependency").unwrap(),
        LockedSourceV1::Git(GitSourceV1::new(
            GitUrl::new(DEPENDENCY_URL).unwrap(),
            GitObjectId::new(revision('d')).unwrap(),
            PackSubdir::new(".").unwrap(),
        )),
        digest,
        vec![],
        vec![],
    )
    .unwrap()
}

struct FakeGit {
    tip: Mutex<String>,
    move_after_resolve: Mutex<Option<String>>,
    snapshots: BTreeMap<String, Vec<GitPackFile>>,
    fetched: Mutex<Vec<String>>,
    denied: AtomicBool,
}

impl FakeGit {
    fn new(snapshots: BTreeMap<String, Vec<GitPackFile>>, tip: String) -> Self {
        Self {
            tip: Mutex::new(tip),
            move_after_resolve: Mutex::new(None),
            snapshots,
            fetched: Mutex::new(Vec::new()),
            denied: AtomicBool::new(false),
        }
    }

    fn set_tip(&self, revision: &str) {
        *self.tip.lock().unwrap() = revision.to_owned();
    }

    fn move_after_next_resolution(&self, revision: &str) {
        *self.move_after_resolve.lock().unwrap() = Some(revision.to_owned());
    }

    fn deny(&self, denied: bool) {
        self.denied.store(denied, Ordering::Release);
    }

    fn check_allowed(&self) {
        assert!(
            !self.denied.load(Ordering::Acquire),
            "offline operation invoked the Git capability"
        );
    }
}

impl GitProcessPort for FakeGit {
    fn resolve_revision(
        &self,
        _config: &GitAcquisitionConfig,
        url: &str,
        selector: &str,
        _output_limit: u64,
    ) -> Result<String, GitAcquisitionIssue> {
        self.check_allowed();
        assert_eq!(url, SOURCE_URL);
        assert_eq!(selector, SELECTOR);
        let resolved = self.tip.lock().unwrap().clone();
        if let Some(next) = self.move_after_resolve.lock().unwrap().take() {
            *self.tip.lock().unwrap() = next;
        }
        Ok(resolved)
    }

    fn initialize(
        &self,
        _config: &GitAcquisitionConfig,
        _scratch: &File,
        object_format: GitObjectFormat,
        _output_limit: u64,
    ) -> Result<(), GitAcquisitionIssue> {
        self.check_allowed();
        assert_eq!(object_format, GitObjectFormat::Sha1);
        Ok(())
    }

    fn fetch(
        &self,
        _config: &GitAcquisitionConfig,
        _scratch: &File,
        url: &str,
        object_id: &str,
        _output_limit: u64,
    ) -> Result<(), GitAcquisitionIssue> {
        self.check_allowed();
        assert_eq!(url, SOURCE_URL);
        self.fetched.lock().unwrap().push(object_id.to_owned());
        Ok(())
    }

    fn read_pack(
        &self,
        _config: &GitAcquisitionConfig,
        _scratch: &File,
        object_format: GitObjectFormat,
        object_id: &str,
        subdir: &str,
    ) -> Result<Vec<GitPackFile>, GitAcquisitionIssue> {
        self.check_allowed();
        assert_eq!(object_format, GitObjectFormat::Sha1);
        assert_eq!(subdir, SOURCE_SUBDIR);
        Ok(self.snapshots[object_id].clone())
    }
}

#[derive(Default)]
struct FixedRandom;

impl SecureRandomPort for FixedRandom {
    fn fill(&self, output: &mut [u8]) -> io::Result<()> {
        output.fill(0x42);
        Ok(())
    }
}

struct NoopSink;

impl ProgressSink for NoopSink {
    fn emit(&self, _event: malm_engine::ProgressEvent) {}
}

impl DiagnosticSink for NoopSink {
    fn emit(&self, _event: malm_engine::DiagnosticEvent<'_>) {}
}

fn make_engine(temp: &tempfile::TempDir, target: &Path, git: Arc<FakeGit>) -> Engine {
    let state_home = temp.path().join("state");
    if !state_home.exists() {
        fs::create_dir(&state_home).unwrap();
        fs::set_permissions(&state_home, fs::Permissions::from_mode(0o700)).unwrap();
    }
    let ports = EnginePorts::new(
        ProcessFacts::new(fs::metadata(&state_home).unwrap().uid(), Some(4_096)),
        Arc::new(FixedRandom),
        git,
        Arc::new(NoopSink),
        Arc::new(NoopSink),
    );
    Engine::new(
        EngineConfig::from_state_home(&state_home, StoreAccess::ReadWrite)
            .unwrap()
            .with_target_authority(DeploymentName::new("home").unwrap(), target)
            .unwrap(),
        ports,
    )
}

fn scratch(temp: &tempfile::TempDir, name: &str) -> TrackedRootInfrastructureV1 {
    let root = temp.path().join(name);
    fs::create_dir(&root).unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    TrackedRootInfrastructureV1::new(
        GitAcquisitionConfig::new("/usr/bin/git").unwrap(),
        root,
        BTreeMap::new(),
    )
}

fn prepare_request(
    temp: &tempfile::TempDir,
    namespace: &str,
    scratch_name: &str,
) -> TrackedRootPrepareRequestV1 {
    TrackedRootPrepareRequestV1::try_from(TrackedRootPrepareRequestPartsV1 {
        source_url: GitUrl::new(SOURCE_URL).unwrap(),
        moving_selector: MovingSelectorV1::new(SELECTOR).unwrap(),
        source_subdir: PackSubdir::new(SOURCE_SUBDIR).unwrap(),
        config_entry_point: ConfigEntryPointV1::new(CONFIG_ENTRY).unwrap(),
        profile: None,
        namespace: NamespaceName::new(namespace).unwrap(),
        target_authority: DeploymentName::new("home").unwrap(),
        component_authorization: FormatComponentAuthorizationV1::default(),
        acquisition_grants: TrackedRootAcquisitionGrantsV1::default(),
        infrastructure: scratch(temp, scratch_name),
    })
    .unwrap()
}

fn commit(engine: &Engine, prepared: &malm_engine::PreparedDeploymentV1) -> Digest {
    engine
        .commit_v1(&CommitRequestV1::new(
            prepared.plan_id().clone(),
            ApprovalV1::new(
                prepared.plan_id().clone(),
                prepared.approval_digest().clone(),
            ),
        ))
        .unwrap()
        .head()
        .clone()
}

fn canonical_tree_closure(
    engine: &Engine,
    root: &Digest,
) -> (BTreeSet<Digest>, BTreeSet<Digest>, BTreeSet<Digest>) {
    let mut trees = BTreeSet::new();
    let mut files = BTreeSet::new();
    let mut symlinks = BTreeSet::new();
    let mut pending = vec![root.clone()];
    while let Some(digest) = pending.pop() {
        if !trees.insert(digest.clone()) {
            continue;
        }
        for entry in engine.load_tree_object_v1(&digest).unwrap().entries() {
            match entry.kind() {
                TreeEntryKindV1::File { digest, .. } => {
                    files.insert(digest.clone());
                }
                TreeEntryKindV1::Directory { digest } => pending.push(digest.clone()),
                TreeEntryKindV1::SafeRelativeSymlink { digest } => {
                    symlinks.insert(digest.clone());
                }
            }
        }
    }
    (trees, files, symlinks)
}

fn fake_with_three_revisions() -> (Arc<FakeGit>, Snapshot, Snapshot, Snapshot) {
    let first = snapshot(b"version=one\n", false);
    let second = snapshot(b"version=two\n", false);
    let third = snapshot(b"version=three\n", true);
    let snapshots = BTreeMap::from([
        (raw_revision(&revision('1')).to_owned(), first.files.clone()),
        (
            raw_revision(&revision('2')).to_owned(),
            second.files.clone(),
        ),
        (raw_revision(&revision('3')).to_owned(), third.files.clone()),
    ]);
    (
        Arc::new(FakeGit::new(snapshots, revision('1'))),
        first,
        second,
        third,
    )
}

#[test]
fn offline_profile_switch_preserves_tracked_authority_and_never_invokes_git() {
    let temp = tempfile::tempdir().unwrap();
    let target = temp.path().join("target");
    fs::create_dir(&target).unwrap();
    fs::create_dir(target.join("config")).unwrap();
    let (git, _, _, _) = fake_with_three_revisions();
    let engine = make_engine(&temp, &target, git.clone());
    engine.initialize_store().unwrap();
    let initial = engine
        .prepare_tracked_root_v1(&prepare_request(&temp, "switch", "switch-scratch"))
        .unwrap();
    let initial_tracking = initial.tracking_review().unwrap().clone();
    let head = commit(&engine, &initial);
    git.deny(true);

    let switched = engine
        .prepare_profile_switch_v1(&ProfileSwitchRequestV1::new(
            NamespaceName::new("switch").unwrap(),
            ContributionName::new("portable").unwrap(),
        ))
        .unwrap();
    let tracking = switched.tracking_review().unwrap();

    assert_eq!(switched.expected_head(), Some(&head));
    assert_eq!(tracking.source_locator(), initial_tracking.source_locator());
    assert_eq!(
        tracking.moving_selector(),
        initial_tracking.moving_selector()
    );
    assert_eq!(
        tracking.applied_revision(),
        initial_tracking.applied_revision()
    );
    assert_eq!(
        tracking.root_tree_digest(),
        initial_tracking.root_tree_digest()
    );
    assert_eq!(tracking.source_subdir(), initial_tracking.source_subdir());
    assert_eq!(
        tracking.config_entry_point(),
        initial_tracking.config_entry_point()
    );
    assert_eq!(tracking.selected_profile().as_str(), "portable");
    assert_eq!(
        tracking.target_authority(),
        initial_tracking.target_authority()
    );
    assert_eq!(
        tracking.acquisition_grants(),
        initial_tracking.acquisition_grants()
    );
    assert_eq!(
        tracking.component_grants(),
        initial_tracking.component_grants()
    );
}

#[test]
fn tracked_source_tree_closure_survives_prune_and_is_fsck_authority() {
    let temp = tempfile::tempdir().unwrap();
    let target = temp.path().join("target");
    fs::create_dir(&target).unwrap();
    fs::create_dir(target.join("config")).unwrap();
    let (git, _, _, _) = fake_with_three_revisions();
    let engine = make_engine(&temp, &target, git);
    engine.initialize_store().unwrap();
    let prepared = engine
        .prepare_tracked_root_v1(&prepare_request(&temp, "desktop", "scratch-retention"))
        .unwrap();
    let root = prepared.tracked_root().unwrap().root_tree_digest().clone();
    let (trees, files, symlinks) = canonical_tree_closure(&engine, &root);
    commit(&engine, &prepared);

    let before = engine.fsck_v1(&FsckRequestV1::new()).unwrap();
    assert!(
        before.is_clean(),
        "unexpected findings: {:?}",
        before.findings()
    );
    engine.prune_v1(&PruneRequestV1::new(vec![])).unwrap();

    for digest in trees {
        engine.load_tree_object_v1(&digest).unwrap();
    }
    for digest in files {
        engine.load_file_object_v1(&digest).unwrap();
    }
    for digest in symlinks {
        engine.load_symlink_object_v1(&digest).unwrap();
    }
    let after = engine.fsck_v1(&FsckRequestV1::new()).unwrap();
    assert!(
        after.is_clean(),
        "unexpected findings: {:?}",
        after.findings()
    );
}

#[test]
fn explicitly_removed_tracked_plan_does_not_retain_its_source_tree() {
    let temp = tempfile::tempdir().unwrap();
    let target = temp.path().join("target");
    fs::create_dir(&target).unwrap();
    fs::create_dir(target.join("config")).unwrap();
    let (git, _, _, _) = fake_with_three_revisions();
    let engine = make_engine(&temp, &target, git);
    engine.initialize_store().unwrap();
    let prepared = engine
        .prepare_tracked_root_v1(&prepare_request(
            &temp,
            "desktop",
            "scratch-removed-retention",
        ))
        .unwrap();
    let root = prepared.tracked_root().unwrap().root_tree_digest().clone();

    engine
        .prune_v1(&PruneRequestV1::new(vec![prepared.plan_id().clone()]))
        .unwrap();

    assert!(engine.load_tree_object_v1(&root).is_err());
    assert!(engine.fsck_v1(&FsckRequestV1::new()).unwrap().is_clean());
}

#[test]
fn newly_pinned_generation_requires_its_indirect_tracked_tree() {
    let temp = tempfile::tempdir().unwrap();
    let target = temp.path().join("target");
    fs::create_dir(&target).unwrap();
    fs::create_dir(target.join("config")).unwrap();
    let (git, _, _, _) = fake_with_three_revisions();
    let engine = make_engine(&temp, &target, git.clone());
    engine.initialize_store().unwrap();
    let first = engine
        .prepare_tracked_root_v1(&prepare_request(&temp, "desktop", "scratch-first-pin"))
        .unwrap();
    let first_root = first.tracked_root().unwrap().root_tree_digest().clone();
    let first_head = commit(&engine, &first);
    git.set_tip(&revision('2'));
    let second = engine
        .update_v1(&TrackedRootUpdateRequestV1::new(
            NamespaceName::new("desktop").unwrap(),
            scratch(&temp, "scratch-second-pin"),
        ))
        .unwrap()
        .into_prepared()
        .unwrap();
    commit(&engine, &second);
    fs::remove_file(
        engine
            .config()
            .state_root()
            .join("objects/trees")
            .join(first_root.as_str()),
    )
    .unwrap();
    let prepared_count = fs::read_dir(engine.config().state_root().join("prepared"))
        .unwrap()
        .count();

    assert!(
        engine
            .prepare_pin_v1(&RetentionPinRequestV1::new(
                NamespaceName::new("desktop").unwrap(),
                RetentionObjectV1::StateGeneration { digest: first_head },
            ))
            .is_err()
    );
    assert_eq!(
        fs::read_dir(engine.config().state_root().join("prepared"))
            .unwrap()
            .count(),
        prepared_count
    );
}

#[test]
fn initial_no_change_and_advancing_update_pin_exact_bytes_and_commit_offline() {
    let temp = tempfile::tempdir().unwrap();
    let target = temp.path().join("target");
    fs::create_dir(&target).unwrap();
    fs::create_dir(target.join("config")).unwrap();
    let (git, first, _, _) = fake_with_three_revisions();
    let engine = make_engine(&temp, &target, git.clone());
    engine.initialize_store().unwrap();

    let initial = engine
        .prepare_tracked_root_v1(&prepare_request(&temp, "desktop", "scratch-initial"))
        .unwrap();
    assert_eq!(
        initial.tracked_root().unwrap().applied_revision(),
        revision('1')
    );
    let record_path = engine
        .config()
        .state_root()
        .join("prepared")
        .join(initial.plan_id().as_str());
    let record =
        malm_store::decode_prepared_record_v1(initial.plan_id(), &fs::read(&record_path).unwrap())
            .unwrap();
    let tracked = record.tracked_root().unwrap();
    assert_eq!(tracked.applied_revision().as_str(), revision('1'));
    assert_eq!(tracked.source_subdir().as_str(), SOURCE_SUBDIR);
    assert_eq!(tracked.selected_profile().as_str(), "desktop");
    assert_ne!(tracked.root_tree_digest(), &first.pack_digest);
    let root_tree = engine
        .load_tree_object_v1(tracked.root_tree_digest())
        .unwrap();
    let files_tree = root_tree
        .entries()
        .iter()
        .find(|entry| entry.name().as_str() == "files")
        .unwrap();
    let TreeEntryKindV1::Directory { digest } = files_tree.kind() else {
        panic!("files must be represented by a canonical child tree")
    };
    let files_tree = engine.load_tree_object_v1(digest).unwrap();
    assert_eq!(
        files_tree
            .entries()
            .iter()
            .find(|entry| entry.name().as_str() == "theme.conf")
            .unwrap()
            .mode(),
        0o755
    );
    let first_head = commit(&engine, &initial);
    assert_eq!(
        fs::read(target.join("config/theme.conf")).unwrap(),
        b"version=one\n"
    );

    git.set_tip(&revision('1'));
    let no_change = engine
        .update_v1(&TrackedRootUpdateRequestV1::new(
            NamespaceName::new("desktop").unwrap(),
            scratch(&temp, "scratch-no-change"),
        ))
        .unwrap();
    let TrackedRootUpdateOutcomeV1::NoChange(no_change) = no_change else {
        panic!("unchanged exact revision unexpectedly prepared a plan")
    };
    assert_eq!(no_change.generation(), &first_head);
    assert_eq!(no_change.applied_revision(), revision('1'));

    git.set_tip(&revision('2'));
    git.move_after_next_resolution(&revision('3'));
    let advanced = engine
        .update_v1(&TrackedRootUpdateRequestV1::new(
            NamespaceName::new("desktop").unwrap(),
            scratch(&temp, "scratch-advanced"),
        ))
        .unwrap()
        .into_prepared()
        .unwrap();
    assert_eq!(
        advanced.tracked_root().unwrap().applied_revision(),
        revision('2')
    );
    assert_eq!(
        git.fetched.lock().unwrap().last().unwrap(),
        raw_revision(&revision('2'))
    );
    let plan_bytes = fs::read(
        engine
            .config()
            .state_root()
            .join("prepared")
            .join(advanced.plan_id().as_str()),
    )
    .unwrap();

    git.deny(true);
    drop(engine);
    let restarted = make_engine(&temp, &target, git.clone());
    assert_eq!(restarted.plan_v1(advanced.plan_id()).unwrap(), advanced);
    assert_eq!(
        fs::read(
            restarted
                .config()
                .state_root()
                .join("prepared")
                .join(advanced.plan_id().as_str())
        )
        .unwrap(),
        plan_bytes
    );
    commit(&restarted, &advanced);
    assert_eq!(
        fs::read(target.join("config/theme.conf")).unwrap(),
        b"version=two\n"
    );
    assert_eq!(
        restarted.recover_v1().unwrap(),
        RecoveryOutcomeV1::NoTransaction
    );
}

/// A tracked root's lock records the digest of its captured files, so acquisition
/// must narrow the fetched tree the way local capture narrows a checkout. Without
/// that, the committed file outside the roots moves the acquired digest and every
/// tracked operation fails with `RootLockMismatch`.
#[test]
fn tracked_root_capture_roots_narrow_the_acquired_tree_to_its_locked_digest() {
    let temp = tempfile::tempdir().unwrap();
    let target = temp.path().join("target");
    fs::create_dir(&target).unwrap();
    fs::create_dir(target.join("config")).unwrap();
    let narrowed = narrowed_snapshot(b"version=narrowed\n");
    assert!(
        narrowed
            .files
            .iter()
            .any(|file| file.path() == "docs/notes.md"),
        "the fixture must commit a file outside the capture roots"
    );
    let git = Arc::new(FakeGit::new(
        BTreeMap::from([(
            raw_revision(&revision('1')).to_owned(),
            narrowed.files.clone(),
        )]),
        revision('1'),
    ));
    let engine = make_engine(&temp, &target, git);
    engine.initialize_store().unwrap();

    let prepared = engine
        .prepare_tracked_root_v1(&prepare_request(&temp, "narrowed", "narrowed-scratch"))
        .unwrap();

    // The lock records the captured set alone.
    let committed = |path: &str| {
        narrowed
            .files
            .iter()
            .find(|file| file.path() == path)
            .unwrap()
            .bytes()
            .to_vec()
    };
    assert_eq!(
        engine.load_pack_object_v1(&narrowed.pack_digest).unwrap(),
        vec![
            PackFileV1::new(pack_path(CONFIG_ENTRY), committed(CONFIG_ENTRY)),
            PackFileV1::new(pack_path("files/theme.conf"), b"version=narrowed\n"),
            PackFileV1::new(pack_path("malm-pack.kdl"), committed("malm-pack.kdl")),
        ],
        "the published pack holds exactly the captured files"
    );
    let root_tree = engine
        .load_tree_object_v1(prepared.tracked_root().unwrap().root_tree_digest())
        .unwrap();
    assert!(
        !root_tree
            .entries()
            .iter()
            .any(|entry| entry.name().as_str() == "docs"),
        "uncaptured entries must not reach the canonical source tree"
    );
    commit(&engine, &prepared);
}

#[test]
fn prepared_tracking_review_projects_every_persisted_logical_authority() {
    let temp = tempfile::tempdir().unwrap();
    let target = temp.path().join("target");
    fs::create_dir(&target).unwrap();
    fs::create_dir(target.join("config")).unwrap();
    let (git, _, _, _) = fake_with_three_revisions();
    let engine = make_engine(&temp, &target, git.clone());
    engine.initialize_store().unwrap();
    let component = Digest::sha256(b"future component grant");
    let request = TrackedRootPrepareRequestV1::try_from(TrackedRootPrepareRequestPartsV1 {
        source_url: GitUrl::new(SOURCE_URL).unwrap(),
        moving_selector: MovingSelectorV1::new(SELECTOR).unwrap(),
        source_subdir: PackSubdir::new(SOURCE_SUBDIR).unwrap(),
        config_entry_point: ConfigEntryPointV1::new(CONFIG_ENTRY).unwrap(),
        profile: None,
        namespace: NamespaceName::new("review").unwrap(),
        target_authority: DeploymentName::new("home").unwrap(),
        component_authorization: FormatComponentAuthorizationV1::new([component.clone()]),
        acquisition_grants: TrackedRootAcquisitionGrantsV1::new(
            BTreeSet::from([LocalLocator::new("../shared-pack").unwrap()]),
            BTreeSet::from([GitUrl::new(DEPENDENCY_URL).unwrap()]),
        )
        .unwrap(),
        infrastructure: scratch(&temp, "scratch-review"),
    })
    .unwrap();
    let prepared = engine.prepare_tracked_root_v1(&request).unwrap();
    assert_eq!(engine.plan_v1(prepared.plan_id()).unwrap(), prepared);
    let review = prepared.tracking_review().unwrap();
    assert_eq!(review.source_locator(), SOURCE_URL);
    assert_eq!(review.source_subdir(), SOURCE_SUBDIR);
    assert_eq!(review.config_entry_point(), CONFIG_ENTRY);
    assert_eq!(review.selected_profile().as_str(), "desktop");
    assert_eq!(review.target_authority().as_str(), "home");
    assert_eq!(review.component_grants(), std::slice::from_ref(&component));
    assert_eq!(review.acquisition_grants().len(), 2);
    assert!(
        review
            .acquisition_grants()
            .iter()
            .any(|grant| grant.locator() == "../shared-pack")
    );
    assert!(
        review
            .acquisition_grants()
            .iter()
            .any(|grant| grant.locator() == DEPENDENCY_URL)
    );

    commit(&engine, &prepared);
    git.set_tip(&revision('2'));
    let updated = engine
        .update_v1(&TrackedRootUpdateRequestV1::new(
            NamespaceName::new("review").unwrap(),
            scratch(&temp, "scratch-review-update"),
        ))
        .unwrap()
        .into_prepared()
        .unwrap();
    assert_eq!(
        updated.tracking_review().unwrap().component_grants(),
        [component]
    );
}

#[test]
fn update_cannot_widen_persisted_dependency_grants() {
    let temp = tempfile::tempdir().unwrap();
    let target = temp.path().join("target");
    fs::create_dir(&target).unwrap();
    fs::create_dir(target.join("config")).unwrap();
    let (git, _, _, _) = fake_with_three_revisions();
    let engine = make_engine(&temp, &target, git.clone());
    engine.initialize_store().unwrap();
    let initial = engine
        .prepare_tracked_root_v1(&prepare_request(&temp, "desktop", "scratch-initial"))
        .unwrap();
    commit(&engine, &initial);

    git.set_tip(&revision('3'));
    let error = engine
        .update_v1(&TrackedRootUpdateRequestV1::new(
            NamespaceName::new("desktop").unwrap(),
            scratch(&temp, "scratch-ungranted"),
        ))
        .unwrap_err();
    assert!(matches!(
        error,
        TrackedRootError::GraphAcquisition(
            malm_engine::GraphAcquisitionError::GitSourceNotGranted { ref url, .. }
        ) if url.as_str() == DEPENDENCY_URL
    ));
}

#[test]
fn selected_tracking_is_required_enabled_and_well_formed_and_explicit_prepare_clears_it() {
    let temp = tempfile::tempdir().unwrap();
    let target = temp.path().join("target");
    fs::create_dir(&target).unwrap();
    fs::create_dir(target.join("config")).unwrap();
    let (git, _, _, _) = fake_with_three_revisions();
    let engine = make_engine(&temp, &target, git.clone());
    engine.initialize_store().unwrap();
    let initial = engine
        .prepare_tracked_root_v1(&prepare_request(&temp, "desktop", "scratch-initial"))
        .unwrap();
    let initial_head = commit(&engine, &initial);

    let artifact_id = ArtifactId::new("manual/configuration").unwrap();
    let explicit = engine
        .prepare_v1(&PrepareRequestV1::from(PrepareRequestPartsV1 {
            namespace: NamespaceName::new("desktop").unwrap(),
            expected_head: Some(initial_head),
            graph_digest: Digest::sha256(b"explicit deployment"),
            inputs: vec![],
            artifacts: vec![
                PrepareArtifactV1::new(
                    artifact_id.clone(),
                    b"manual=true\n".to_vec(),
                    "text/plain",
                )
                .unwrap(),
            ],
            transforms: vec![],
            findings: vec![],
            operations: vec![
                PrepareOperationV1::place_file(
                    DeploymentName::new("home").unwrap(),
                    "config/manual.conf",
                    artifact_id,
                    0o644,
                )
                .unwrap(),
            ],
        }))
        .unwrap();
    let explicit_head = commit(&engine, &explicit);
    let explicit_generation = engine
        .inspect_generation_details_v1(&malm_engine::GenerationInspectionRequestV1::new(
            NamespaceName::new("desktop").unwrap(),
            explicit_head,
        ))
        .unwrap();
    assert!(explicit_generation.tracked_root().is_none());
    git.deny(true);
    assert!(matches!(
        engine.update_v1(&TrackedRootUpdateRequestV1::new(
            NamespaceName::new("desktop").unwrap(),
            scratch(&temp, "scratch-missing"),
        )),
        Err(TrackedRootError::MissingTracking { .. })
    ));
}

#[test]
fn disabled_and_corrupt_selected_generations_are_rejected_before_git() {
    let disabled_temp = tempfile::tempdir().unwrap();
    let disabled_target = disabled_temp.path().join("target");
    fs::create_dir(&disabled_target).unwrap();
    fs::create_dir(disabled_target.join("config")).unwrap();
    let (disabled_git, _, _, _) = fake_with_three_revisions();
    let disabled_engine = make_engine(&disabled_temp, &disabled_target, disabled_git.clone());
    disabled_engine.initialize_store().unwrap();
    let initial = disabled_engine
        .prepare_tracked_root_v1(&prepare_request(
            &disabled_temp,
            "desktop",
            "scratch-initial",
        ))
        .unwrap();
    commit(&disabled_engine, &initial);
    let disabled = disabled_engine
        .prepare_disable_v1(&NamespaceName::new("desktop").unwrap())
        .unwrap();
    commit(&disabled_engine, &disabled);
    disabled_git.deny(true);
    assert!(matches!(
        disabled_engine.update_v1(&TrackedRootUpdateRequestV1::new(
            NamespaceName::new("desktop").unwrap(),
            scratch(&disabled_temp, "scratch-disabled"),
        )),
        Err(TrackedRootError::Disabled { .. })
    ));

    let corrupt_temp = tempfile::tempdir().unwrap();
    let corrupt_target = corrupt_temp.path().join("target");
    fs::create_dir(&corrupt_target).unwrap();
    fs::create_dir(corrupt_target.join("config")).unwrap();
    let (corrupt_git, _, _, _) = fake_with_three_revisions();
    let corrupt_engine = make_engine(&corrupt_temp, &corrupt_target, corrupt_git.clone());
    corrupt_engine.initialize_store().unwrap();
    let initial = corrupt_engine
        .prepare_tracked_root_v1(&prepare_request(
            &corrupt_temp,
            "desktop",
            "scratch-initial",
        ))
        .unwrap();
    let head = commit(&corrupt_engine, &initial);
    let generation = corrupt_engine
        .config()
        .state_root()
        .join("state/generations")
        .join(head.as_str());
    fs::set_permissions(&generation, fs::Permissions::from_mode(0o600)).unwrap();
    fs::write(&generation, b"{}\n").unwrap();
    fs::set_permissions(&generation, fs::Permissions::from_mode(0o400)).unwrap();
    corrupt_git.deny(true);
    assert!(matches!(
        corrupt_engine.update_v1(&TrackedRootUpdateRequestV1::new(
            NamespaceName::new("desktop").unwrap(),
            scratch(&corrupt_temp, "scratch-corrupt"),
        )),
        Err(TrackedRootError::State(_))
    ));
}

#[test]
fn custom_ports_without_resolution_remain_deterministically_unavailable() {
    struct ExactOnly;

    impl GitProcessPort for ExactOnly {
        fn initialize(
            &self,
            _config: &GitAcquisitionConfig,
            _scratch: &File,
            _object_format: GitObjectFormat,
            _output_limit: u64,
        ) -> Result<(), GitAcquisitionIssue> {
            Ok(())
        }

        fn fetch(
            &self,
            _config: &GitAcquisitionConfig,
            _scratch: &File,
            _url: &str,
            _object_id: &str,
            _output_limit: u64,
        ) -> Result<(), GitAcquisitionIssue> {
            Ok(())
        }

        fn read_pack(
            &self,
            _config: &GitAcquisitionConfig,
            _scratch: &File,
            _object_format: GitObjectFormat,
            _object_id: &str,
            _subdir: &str,
        ) -> Result<Vec<GitPackFile>, GitAcquisitionIssue> {
            Ok(vec![])
        }
    }

    assert!(matches!(
        ExactOnly.resolve_revision(
            &GitAcquisitionConfig::new("/usr/bin/git").unwrap(),
            SOURCE_URL,
            SELECTOR,
            1024,
        ),
        Err(GitAcquisitionIssue::SelectorResolutionUnavailable)
    ));
}
