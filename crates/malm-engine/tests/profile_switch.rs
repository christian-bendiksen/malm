use std::{
    fs::{self, File},
    io,
    os::unix::fs::PermissionsExt,
    sync::{
        Arc, Condvar, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
};

use malm_config::{TransformFailureV1, TransformRequestV1, TransformResponseV1};
use malm_engine::{
    ApprovalV1, CommitRequestV1, DiagnosticSink, Engine, EngineConfig, EngineError, EnginePorts,
    FormatComponentAuthorizationV1, FormatComponentExecutionIssue, FormatComponentExecutionPort,
    GitAcquisitionConfig, GitAcquisitionIssue, GitObjectFormat, GitProcessPort,
    HistoryRetentionRequestV1, NamespaceStatusKindV1, NamespaceStatusRequestV1, PackObjectIssue,
    PrepareInputKindV1, PrepareInputV1, PrepareOperationV1, PrepareRequestPartsV1,
    PrepareRequestV1, PreparedStoreIssue, ProcessFacts, ProfileSwitchError, ProfileSwitchRequestV1,
    ProgressSink, SecureRandomPort, StaticDeploymentPrepareRequestV1, StaticGraphAcquisitionV1,
    StaticPrepareError, StoreAccess,
};
use malm_pack::{
    BundledComponentV1, ComponentInterfaceV1, DependencySourceV1, LocalLocator, LockV1,
    LockedComponentV1, LockedDependencyV1, LockedPackV1, LockedSourceV1, PackDependencyV1,
    PackFileV1, PackManifestV1, PackPath, encode_pack_v1, pack_content_digest,
};
use malm_tree::file_object_digest_v1;
use malm_types::{
    Alias, ContributionName, DeploymentName, Digest, NamespaceName, PackageId, PrepareTargetStateV1,
};

const NAMESPACE: &str = "workstation";

#[derive(Default)]
struct FixedRandom;

impl SecureRandomPort for FixedRandom {
    fn fill(&self, output: &mut [u8]) -> io::Result<()> {
        output.fill(0x51);
        Ok(())
    }
}

#[derive(Default)]
struct NoopSink;

impl ProgressSink for NoopSink {
    fn emit(&self, _event: malm_engine::ProgressEvent) {}
}

impl DiagnosticSink for NoopSink {
    fn emit(&self, _event: malm_engine::DiagnosticEvent<'_>) {}
}

#[derive(Default)]
struct DenyGit {
    calls: AtomicUsize,
}

impl DenyGit {
    fn denied<T>(&self) -> T {
        self.calls.fetch_add(1, Ordering::Relaxed);
        panic!("offline profile switch invoked Git")
    }
}

impl GitProcessPort for DenyGit {
    fn resolve_revision(
        &self,
        _config: &GitAcquisitionConfig,
        _url: &str,
        _selector: &str,
        _output_limit: u64,
    ) -> Result<String, GitAcquisitionIssue> {
        self.denied()
    }

    fn initialize(
        &self,
        _config: &GitAcquisitionConfig,
        _scratch: &File,
        _object_format: GitObjectFormat,
        _output_limit: u64,
    ) -> Result<(), GitAcquisitionIssue> {
        self.denied()
    }

    fn fetch(
        &self,
        _config: &GitAcquisitionConfig,
        _scratch: &File,
        _url: &str,
        _object_id: &str,
        _output_limit: u64,
    ) -> Result<(), GitAcquisitionIssue> {
        self.denied()
    }

    fn read_pack(
        &self,
        _config: &GitAcquisitionConfig,
        _scratch: &File,
        _object_format: GitObjectFormat,
        _object_id: &str,
        _subdir: &str,
    ) -> Result<Vec<malm_engine::GitPackFile>, GitAcquisitionIssue> {
        self.denied()
    }
}

struct PinnedComponent {
    calls: AtomicUsize,
    expected_digest: Digest,
}

impl FormatComponentExecutionPort for PinnedComponent {
    fn invoke(
        &self,
        authorization: &FormatComponentAuthorizationV1,
        _identity: &malm_config::TransformIdentityV1,
        _component_bytes: &[u8],
        _request: &TransformRequestV1,
    ) -> Result<Result<TransformResponseV1, TransformFailureV1>, FormatComponentExecutionIssue>
    {
        self.calls.fetch_add(1, Ordering::Relaxed);
        assert!(authorization.permits(&self.expected_digest));
        Ok(Ok(TransformResponseV1::new(
            b"pinned component output\n",
            "text/plain",
            vec![],
        )
        .unwrap()))
    }
}

#[derive(Default)]
struct BlockState {
    armed: bool,
    entered: bool,
    released: bool,
}

#[derive(Default)]
struct BlockingComponent {
    state: Mutex<BlockState>,
    changed: Condvar,
}

impl BlockingComponent {
    fn arm(&self) {
        let mut state = self.state.lock().unwrap();
        state.armed = true;
        state.entered = false;
        state.released = false;
    }

    fn wait_until_entered(&self) {
        let mut state = self.state.lock().unwrap();
        while !state.entered {
            state = self.changed.wait(state).unwrap();
        }
    }

    fn release(&self) {
        let mut state = self.state.lock().unwrap();
        state.released = true;
        self.changed.notify_all();
    }
}

impl FormatComponentExecutionPort for BlockingComponent {
    fn invoke(
        &self,
        _authorization: &FormatComponentAuthorizationV1,
        _identity: &malm_config::TransformIdentityV1,
        _component_bytes: &[u8],
        _request: &TransformRequestV1,
    ) -> Result<Result<TransformResponseV1, TransformFailureV1>, FormatComponentExecutionIssue>
    {
        let mut state = self.state.lock().unwrap();
        if state.armed {
            state.entered = true;
            self.changed.notify_all();
            while !state.released {
                state = self.changed.wait(state).unwrap();
            }
        }
        drop(state);
        Ok(Ok(TransformResponseV1::new(
            b"authorized component output\n",
            "text/plain",
            vec![],
        )
        .unwrap()))
    }
}

struct Fixture {
    lock: LockV1,
    objects: Vec<(Digest, Vec<PackFileV1>)>,
    old_bytes: Vec<u8>,
    new_bytes: Vec<u8>,
}

fn regular_fixture() -> Fixture {
    let dependency_manifest = PackManifestV1::new(
        PackageId::new("com.example.switch.dependency").unwrap(),
        vec![],
        vec![],
        vec![],
        vec![],
        vec![],
        vec![],
    )
    .unwrap();
    let dependency_files = vec![PackFileV1::new(
        PackPath::new("malm-pack.kdl").unwrap(),
        encode_pack_v1(&dependency_manifest),
    )];
    let dependency_digest = digest(&dependency_files);
    let locator = LocalLocator::new("packs/dependency").unwrap();
    let dependency = LockedPackV1::new(
        dependency_manifest.package_id().clone(),
        LockedSourceV1::Local(locator.clone()),
        dependency_digest.clone(),
        vec![],
        vec![],
    )
    .unwrap();

    let old_bytes = b"theme=dark\n".to_vec();
    let new_bytes = b"theme=light\n".to_vec();
    let old_path = PackPath::new("assets/dark.conf").unwrap();
    let new_path = PackPath::new("assets/light.conf").unwrap();
    let config_path = PackPath::new(malm_config::CONFIG_FILE).unwrap();
    let config = format!(
        r#"rich-config schema-version=1 default-profile="dark" {{
    includes {{}}
    modules {{}}
    variables {{}}
    fragments {{}}
    slots {{}}
    statements {{}}
    profiles {{
        profile "dark" abstract=#false {{
            extends {{}}
            statements {{}}
            outputs {{
                regular-file "theme" destination="config/theme.conf" source="{}" source-kind="asset" raw-digest="{}" object-digest="{}" byte-len={} executable=#false
            }}
        }}
        profile "light" abstract=#false {{
            extends {{}}
            statements {{}}
            outputs {{
                regular-file "theme" destination="config/theme.conf" source="{}" source-kind="asset" raw-digest="{}" object-digest="{}" byte-len={} executable=#false
            }}
        }}
        profile "empty" abstract=#false {{
            extends {{}}
            statements {{}}
            outputs {{}}
        }}
    }}
}}"#,
        old_path,
        Digest::sha256(&old_bytes),
        file_object_digest_v1(&old_bytes).unwrap(),
        old_bytes.len(),
        new_path,
        Digest::sha256(&new_bytes),
        file_object_digest_v1(&new_bytes).unwrap(),
        new_bytes.len(),
    );
    let root_manifest = PackManifestV1::new(
        PackageId::new("com.example.switch.root").unwrap(),
        vec![],
        vec![PackDependencyV1::new(
            Alias::new("dependency").unwrap(),
            dependency_manifest.package_id().clone(),
            DependencySourceV1::Local(locator),
        )],
        vec![],
        vec![],
        vec![old_path.clone(), new_path.clone()],
        vec![],
    )
    .unwrap()
    .with_config_documents(vec![config_path.clone()])
    .unwrap();
    let root_files = vec![
        PackFileV1::new(
            PackPath::new("malm-pack.kdl").unwrap(),
            encode_pack_v1(&root_manifest),
        ),
        PackFileV1::new(config_path, config),
        PackFileV1::new(old_path, old_bytes.clone()),
        PackFileV1::new(new_path, new_bytes.clone()),
    ];
    let root_digest = digest(&root_files);
    let root = LockedPackV1::new(
        root_manifest.package_id().clone(),
        LockedSourceV1::Root,
        root_digest.clone(),
        vec![LockedDependencyV1::new(
            Alias::new("dependency").unwrap(),
            dependency.node_id().clone(),
        )],
        vec![],
    )
    .unwrap();
    let lock = LockV1::new(root.node_id().clone(), vec![root, dependency]).unwrap();
    Fixture {
        lock,
        objects: vec![
            (root_digest, root_files),
            (dependency_digest, dependency_files),
        ],
        old_bytes,
        new_bytes,
    }
}

fn synthesized_parent_fixture() -> Fixture {
    let old_bytes = b"font=monospace\n".to_vec();
    let asset_path = PackPath::new("assets/fuzzel.ini").unwrap();
    let config_path = PackPath::new(malm_config::CONFIG_FILE).unwrap();
    let config = format!(
        r#"rich-config schema-version=1 default-profile="fuzzel" {{
    includes {{}}
    modules {{}}
    variables {{}}
    fragments {{}}
    slots {{}}
    statements {{}}
    profiles {{
        profile "fuzzel" abstract=#false {{
            extends {{}}
            statements {{}}
            outputs {{
                regular-file "fuzzel" destination=".config/fuzzel/fuzzel.ini" source="{}" source-kind="asset" raw-digest="{}" object-digest="{}" byte-len={} executable=#false
            }}
        }}
        profile "empty" abstract=#false {{
            extends {{}}
            statements {{}}
            outputs {{}}
        }}
        profile "other-empty" abstract=#false {{
            extends {{}}
            statements {{}}
            outputs {{}}
        }}
    }}
}}"#,
        asset_path,
        Digest::sha256(&old_bytes),
        file_object_digest_v1(&old_bytes).unwrap(),
        old_bytes.len(),
    );
    let manifest = PackManifestV1::new(
        PackageId::new("com.example.switch.synthesized-parent").unwrap(),
        vec![],
        vec![],
        vec![],
        vec![],
        vec![asset_path.clone()],
        vec![],
    )
    .unwrap()
    .with_config_documents(vec![config_path.clone()])
    .unwrap();
    let files = vec![
        PackFileV1::new(
            PackPath::new("malm-pack.kdl").unwrap(),
            encode_pack_v1(&manifest),
        ),
        PackFileV1::new(config_path, config),
        PackFileV1::new(asset_path, old_bytes.clone()),
    ];
    let content_digest = digest(&files);
    let root = LockedPackV1::new(
        manifest.package_id().clone(),
        LockedSourceV1::Root,
        content_digest.clone(),
        vec![],
        vec![],
    )
    .unwrap();
    Fixture {
        lock: LockV1::new(root.node_id().clone(), vec![root]).unwrap(),
        objects: vec![(content_digest, files)],
        old_bytes,
        new_bytes: vec![],
    }
}

fn new_component_fixture() -> (Fixture, Digest) {
    let old_bytes = b"ordinary profile\n".to_vec();
    let asset_path = PackPath::new("assets/ordinary.txt").unwrap();
    let component_path = PackPath::new("components/new.wasm").unwrap();
    let component_bytes = b"new component bytes";
    let component_digest = Digest::sha256(component_bytes);
    let execution_profile = Digest::sha256(b"component execution profile");
    let component = BundledComponentV1::new(
        ContributionName::new("new-formatter").unwrap(),
        component_path.clone(),
        component_digest.clone(),
        ComponentInterfaceV1::FormatComponentV1,
    );
    let locked_component =
        LockedComponentV1::from_declaration(&component, execution_profile.clone());
    let config_path = PackPath::new(malm_config::CONFIG_FILE).unwrap();
    let config = format!(
        r#"rich-config schema-version=1 default-profile="ordinary" {{
    includes {{}}
    modules {{}}
    variables {{}}
    fragments {{}}
    slots {{}}
    statements {{}}
    profiles {{
        profile "ordinary" abstract=#false {{
            extends {{}}
            statements {{}}
            outputs {{
                regular-file "ordinary" destination="config/result.txt" source="{}" source-kind="asset" raw-digest="{}" object-digest="{}" byte-len={} executable=#false
            }}
        }}
        profile "component" abstract=#false {{
            extends {{}}
            statements {{}}
            outputs {{
                format-file "component" destination="config/result.txt" executable=#false {{
                    component "new-formatter" digest="{component_digest}" interface="format-component/v1"
                    options {{}}
                    resources {{}}
                }}
            }}
        }}
    }}
}}"#,
        asset_path,
        Digest::sha256(&old_bytes),
        file_object_digest_v1(&old_bytes).unwrap(),
        old_bytes.len(),
    );
    let manifest = PackManifestV1::new(
        PackageId::new("com.example.switch.component").unwrap(),
        vec![],
        vec![],
        vec![],
        vec![],
        vec![asset_path.clone()],
        vec![component.clone()],
    )
    .unwrap()
    .with_config_documents(vec![config_path.clone()])
    .unwrap();
    let files = vec![
        PackFileV1::new(
            PackPath::new("malm-pack.kdl").unwrap(),
            encode_pack_v1(&manifest),
        ),
        PackFileV1::new(config_path, config),
        PackFileV1::new(asset_path, old_bytes.clone()),
        PackFileV1::new(component_path, component_bytes),
    ];
    let content_digest = digest(&files);
    let root = LockedPackV1::new(
        manifest.package_id().clone(),
        LockedSourceV1::Root,
        content_digest.clone(),
        vec![],
        vec![locked_component],
    )
    .unwrap();
    (
        Fixture {
            lock: LockV1::new(root.node_id().clone(), vec![root]).unwrap(),
            objects: vec![(content_digest, files)],
            old_bytes,
            new_bytes: vec![],
        },
        component_digest,
    )
}

fn authorized_component_fixture() -> (Fixture, Digest) {
    let component_path = PackPath::new("components/formatter.wasm").unwrap();
    let component_bytes = b"authorized component bytes";
    let component_digest = Digest::sha256(component_bytes);
    let execution_profile = Digest::sha256(b"authorized execution profile");
    let component = BundledComponentV1::new(
        ContributionName::new("formatter").unwrap(),
        component_path.clone(),
        component_digest.clone(),
        ComponentInterfaceV1::FormatComponentV1,
    );
    let locked_component =
        LockedComponentV1::from_declaration(&component, execution_profile.clone());
    let config_path = PackPath::new(malm_config::CONFIG_FILE).unwrap();
    let config = format!(
        r#"rich-config schema-version=1 default-profile="first" {{
    includes {{}}
    modules {{}}
    variables {{}}
    fragments {{}}
    slots {{}}
    statements {{}}
    profiles {{
        profile "first" abstract=#false {{
            extends {{}}
            statements {{}}
            outputs {{
                format-file "result" destination="config/result.txt" executable=#false {{
                    component "formatter" digest="{component_digest}" interface="format-component/v1"
                    options {{}}
                    resources {{}}
                }}
            }}
        }}
        profile "second" abstract=#false {{
            extends {{}}
            statements {{}}
            outputs {{
                format-file "result" destination="config/result.txt" executable=#false {{
                    component "formatter" digest="{component_digest}" interface="format-component/v1"
                    options {{}}
                    resources {{}}
                }}
            }}
        }}
    }}
}}"#,
    );
    let manifest = PackManifestV1::new(
        PackageId::new("com.example.switch.authorized-component").unwrap(),
        vec![],
        vec![],
        vec![],
        vec![],
        vec![],
        vec![component.clone()],
    )
    .unwrap()
    .with_config_documents(vec![config_path.clone()])
    .unwrap();
    let files = vec![
        PackFileV1::new(
            PackPath::new("malm-pack.kdl").unwrap(),
            encode_pack_v1(&manifest),
        ),
        PackFileV1::new(config_path, config),
        PackFileV1::new(component_path, component_bytes),
    ];
    let content_digest = digest(&files);
    let root = LockedPackV1::new(
        manifest.package_id().clone(),
        LockedSourceV1::Root,
        content_digest.clone(),
        vec![],
        vec![locked_component],
    )
    .unwrap();
    (
        Fixture {
            lock: LockV1::new(root.node_id().clone(), vec![root]).unwrap(),
            objects: vec![(content_digest, files)],
            old_bytes: vec![],
            new_bytes: vec![],
        },
        component_digest,
    )
}

fn digest(files: &[PackFileV1]) -> Digest {
    pack_content_digest(files.iter().map(|file| (file.path(), file.bytes()))).unwrap()
}

fn ports(git: Arc<DenyGit>) -> EnginePorts {
    EnginePorts::new(
        ProcessFacts::new(rustix::process::geteuid().as_raw(), Some(4_096)),
        Arc::new(FixedRandom),
        git,
        Arc::new(NoopSink),
        Arc::new(NoopSink),
    )
}

fn engine(temp: &tempfile::TempDir, ports: EnginePorts) -> Engine {
    let state = temp.path().join("state");
    let target = temp.path().join("target");
    if !state.exists() {
        fs::create_dir(&state).unwrap();
        fs::set_permissions(&state, fs::Permissions::from_mode(0o700)).unwrap();
    }
    if !target.exists() {
        fs::create_dir_all(target.join("config")).unwrap();
    }
    Engine::new(
        EngineConfig::from_state_home(&state, StoreAccess::ReadWrite)
            .unwrap()
            .with_target_authority(DeploymentName::new("home").unwrap(), target)
            .unwrap(),
        ports,
    )
}

fn seed(
    engine: &Engine,
    fixture: &Fixture,
    initial_profile: &str,
    component_grants: impl IntoIterator<Item = Digest>,
) -> Digest {
    engine.initialize_store().unwrap();
    for (digest, files) in &fixture.objects {
        engine.publish_pack_object_v1(digest, files).unwrap();
    }
    let plan = engine
        .prepare_static_deployment_v1(&StaticDeploymentPrepareRequestV1::new(
            fixture.lock.clone(),
            StaticGraphAcquisitionV1::cached(),
            FormatComponentAuthorizationV1::new(component_grants),
            Some(ContributionName::new(initial_profile).unwrap()),
            NamespaceName::new(NAMESPACE).unwrap(),
            DeploymentName::new("home").unwrap(),
        ))
        .unwrap();
    engine
        .commit_v1(&CommitRequestV1::new(
            plan.plan_id().clone(),
            ApprovalV1::new(plan.plan_id().clone(), plan.approval_digest().clone()),
        ))
        .unwrap()
        .head()
        .clone()
}

fn switch_request(profile: &str) -> ProfileSwitchRequestV1 {
    ProfileSwitchRequestV1::new(
        NamespaceName::new(NAMESPACE).unwrap(),
        ContributionName::new(profile).unwrap(),
    )
}

fn object_path(engine: &Engine, digest: &Digest) -> std::path::PathBuf {
    engine
        .config()
        .state_root()
        .join("objects/pack-manifests")
        .join(digest.as_str())
}

#[test]
fn exact_static_switch_reconstructs_every_pack_without_git_or_source() {
    let temp = tempfile::tempdir().unwrap();
    let fixture = regular_fixture();
    let git = Arc::new(DenyGit::default());
    let engine = engine(&temp, ports(git.clone()));
    let head = seed(&engine, &fixture, "dark", []);
    assert_eq!(
        fs::read(temp.path().join("target/config/theme.conf")).unwrap(),
        fixture.old_bytes
    );

    let plan = engine
        .prepare_profile_switch_v1(&switch_request("light"))
        .unwrap();

    assert_eq!(plan.expected_head(), Some(&head));
    assert_eq!(
        plan.graph_digest(),
        &malm_pack::lock_graph_digest(&fixture.lock)
    );
    assert!(plan.tracking_review().is_none());
    assert_eq!(
        plan.inputs()
            .iter()
            .filter(|input| input.kind() == PrepareInputKindV1::Source)
            .count(),
        2
    );
    assert_eq!(git.calls.load(Ordering::Relaxed), 0);

    engine
        .commit_v1(&CommitRequestV1::new(
            plan.plan_id().clone(),
            ApprovalV1::new(plan.plan_id().clone(), plan.approval_digest().clone()),
        ))
        .unwrap();
    assert_eq!(
        fs::read(temp.path().join("target/config/theme.conf")).unwrap(),
        fixture.new_bytes
    );
}

#[test]
fn exact_only_switch_commits_with_the_final_publication_proof() {
    let temp = tempfile::tempdir().unwrap();
    let fixture = regular_fixture();
    let engine = engine(&temp, ports(Arc::new(DenyGit::default())));
    seed(&engine, &fixture, "dark", []);

    let plan = engine
        .prepare_profile_switch_v1(&switch_request("dark"))
        .unwrap();
    assert!(matches!(
        plan.operations(),
        [PrepareOperationV1::AssertExact { .. }]
    ));
    engine
        .commit_v1(&CommitRequestV1::new(
            plan.plan_id().clone(),
            ApprovalV1::new(plan.plan_id().clone(), plan.approval_digest().clone()),
        ))
        .unwrap();
    assert_eq!(
        engine
            .inspect_namespace_status_v1(&NamespaceStatusRequestV1::new(
                NamespaceName::new(NAMESPACE).unwrap(),
            ))
            .unwrap()
            .status(),
        NamespaceStatusKindV1::EnabledExact
    );
}

#[test]
fn empty_static_profile_retains_its_target_authority_for_later_switches() {
    let temp = tempfile::tempdir().unwrap();
    let fixture = regular_fixture();
    let engine = engine(&temp, ports(Arc::new(DenyGit::default())));
    seed(&engine, &fixture, "dark", []);

    let empty = engine
        .prepare_profile_switch_v1(&switch_request("empty"))
        .unwrap();
    engine
        .commit_v1(&CommitRequestV1::new(
            empty.plan_id().clone(),
            ApprovalV1::new(empty.plan_id().clone(), empty.approval_digest().clone()),
        ))
        .unwrap();
    assert!(!temp.path().join("target/config/theme.conf").exists());

    let light = engine
        .prepare_profile_switch_v1(&switch_request("light"))
        .unwrap();
    engine
        .commit_v1(&CommitRequestV1::new(
            light.plan_id().clone(),
            ApprovalV1::new(light.plan_id().clone(), light.approval_digest().clone()),
        ))
        .unwrap();
    assert_eq!(
        fs::read(temp.path().join("target/config/theme.conf")).unwrap(),
        fixture.new_bytes
    );
}

#[test]
fn synthesized_parent_is_held_exact_for_descendant_removal_then_cleaned() {
    let temp = tempfile::tempdir().unwrap();
    let fixture = synthesized_parent_fixture();
    let engine = engine(&temp, ports(Arc::new(DenyGit::default())));
    fs::create_dir(temp.path().join("target/.config")).unwrap();
    seed(&engine, &fixture, "fuzzel", []);
    let parent = temp.path().join("target/.config/fuzzel");
    let child = parent.join("fuzzel.ini");
    assert_eq!(fs::read(&child).unwrap(), fixture.old_bytes);

    let empty = engine
        .prepare_profile_switch_v1(&switch_request("empty"))
        .unwrap();
    assert!(empty.operations().iter().any(|operation| matches!(
        operation,
        PrepareOperationV1::AssertExact {
            relative_path,
            state: PrepareTargetStateV1::Directory { mode: 0o755 },
            ..
        } if relative_path == ".config/fuzzel"
    )));
    assert!(empty.operations().iter().any(|operation| matches!(
        operation,
        PrepareOperationV1::RemoveLeaf { relative_path, .. }
            if relative_path == ".config/fuzzel/fuzzel.ini"
    )));
    assert_eq!(empty.operations().len(), 2);
    engine
        .commit_v1(&CommitRequestV1::new(
            empty.plan_id().clone(),
            ApprovalV1::new(empty.plan_id().clone(), empty.approval_digest().clone()),
        ))
        .unwrap();
    assert!(parent.is_dir());
    assert!(!child.exists());
    assert_eq!(
        engine
            .inspect_namespace_status_v1(&NamespaceStatusRequestV1::new(
                NamespaceName::new(NAMESPACE).unwrap(),
            ))
            .unwrap()
            .status(),
        NamespaceStatusKindV1::EnabledExact
    );

    let other_empty = engine
        .prepare_profile_switch_v1(&switch_request("other-empty"))
        .unwrap();
    assert!(matches!(
        other_empty.operations(),
        [PrepareOperationV1::RemoveLeaf { relative_path, .. }]
            if relative_path == ".config/fuzzel"
    ));
    engine
        .commit_v1(&CommitRequestV1::new(
            other_empty.plan_id().clone(),
            ApprovalV1::new(
                other_empty.plan_id().clone(),
                other_empty.approval_digest().clone(),
            ),
        ))
        .unwrap();
    assert!(!parent.exists());
    assert!(temp.path().join("target/.config").is_dir());
    assert_eq!(
        engine
            .inspect_namespace_status_v1(&NamespaceStatusRequestV1::new(
                NamespaceName::new(NAMESPACE).unwrap(),
            ))
            .unwrap()
            .status(),
        NamespaceStatusKindV1::EnabledExact
    );

    fs::create_dir(&parent).unwrap();
    assert_eq!(
        engine
            .inspect_namespace_status_v1(&NamespaceStatusRequestV1::new(
                NamespaceName::new(NAMESPACE).unwrap(),
            ))
            .unwrap()
            .status(),
        NamespaceStatusKindV1::EnabledUnexpected
    );
}

#[test]
fn lifecycle_heads_carry_the_active_pack_authority() {
    let temp = tempfile::tempdir().unwrap();
    let fixture = regular_fixture();
    let engine = engine(&temp, ports(Arc::new(DenyGit::default())));
    seed(&engine, &fixture, "dark", []);

    let retention = engine
        .prepare_history_retention_v1(
            &HistoryRetentionRequestV1::new(NamespaceName::new(NAMESPACE).unwrap(), 1).unwrap(),
        )
        .unwrap();
    assert_eq!(
        retention
            .inputs()
            .iter()
            .filter(|input| input.kind() == PrepareInputKindV1::Source)
            .count(),
        2
    );
    engine
        .commit_v1(&CommitRequestV1::new(
            retention.plan_id().clone(),
            ApprovalV1::new(
                retention.plan_id().clone(),
                retention.approval_digest().clone(),
            ),
        ))
        .unwrap();

    let light = engine
        .prepare_profile_switch_v1(&switch_request("light"))
        .unwrap();
    engine
        .commit_v1(&CommitRequestV1::new(
            light.plan_id().clone(),
            ApprovalV1::new(light.plan_id().clone(), light.approval_digest().clone()),
        ))
        .unwrap();
    assert_eq!(
        fs::read(temp.path().join("target/config/theme.conf")).unwrap(),
        fixture.new_bytes
    );
}

#[test]
fn missing_and_corrupt_retained_pack_objects_are_rejected() {
    for corrupt in [false, true] {
        let temp = tempfile::tempdir().unwrap();
        let fixture = regular_fixture();
        let engine = engine(&temp, ports(Arc::new(DenyGit::default())));
        seed(&engine, &fixture, "dark", []);
        let path = object_path(&engine, &fixture.objects[1].0);
        if corrupt {
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
            fs::write(&path, b"corrupt retained pack").unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o400)).unwrap();
        } else {
            fs::remove_file(&path).unwrap();
        }

        let error = engine
            .prepare_profile_switch_v1(&switch_request("light"))
            .unwrap_err();
        assert!(
            matches!(
                error,
                ProfileSwitchError::PackObject {
                    source: EngineError::PackObject {
                        reason: PackObjectIssue::Missing
                            | PackObjectIssue::DigestMismatch { .. }
                            | PackObjectIssue::InvalidEncoding { .. },
                        ..
                    },
                    ..
                }
            ),
            "unexpected retained-object error: {error:?}"
        );
    }
}

#[test]
fn reconstructed_graph_must_match_the_active_prepared_graph_identity() {
    let temp = tempfile::tempdir().unwrap();
    let fixture = regular_fixture();
    let engine = engine(&temp, ports(Arc::new(DenyGit::default())));
    engine.initialize_store().unwrap();
    for (digest, files) in &fixture.objects {
        engine.publish_pack_object_v1(digest, files).unwrap();
    }
    let forged_graph = Digest::sha256(b"different active graph identity");
    let mut inputs = vec![
        PrepareInputV1::new(
            PrepareInputKindV1::Lock,
            "locked-graph",
            forged_graph.clone(),
        )
        .unwrap(),
        PrepareInputV1::new(
            PrepareInputKindV1::Other,
            "locked-component-profiles",
            Digest::sha256(b"malm-locked-component-profiles-v1\0"),
        )
        .unwrap(),
    ];
    inputs.extend(fixture.lock.nodes().iter().map(|node| {
        PrepareInputV1::new(
            PrepareInputKindV1::Source,
            format!("pack:{}", node.node_id()),
            node.content_digest().clone(),
        )
        .unwrap()
    }));
    let active = engine
        .prepare_v1(&PrepareRequestV1::from(PrepareRequestPartsV1 {
            namespace: NamespaceName::new(NAMESPACE).unwrap(),
            expected_head: None,
            graph_digest: forged_graph.clone(),
            inputs,
            artifacts: vec![],
            transforms: vec![],
            findings: vec![],
            operations: vec![],
        }))
        .unwrap();
    engine
        .commit_v1(&CommitRequestV1::new(
            active.plan_id().clone(),
            ApprovalV1::new(active.plan_id().clone(), active.approval_digest().clone()),
        ))
        .unwrap();

    assert!(matches!(
        engine.prepare_profile_switch_v1(&switch_request("light")),
        Err(ProfileSwitchError::GraphIdentityMismatch {
            retained,
            assembled,
        }) if retained == forged_graph && assembled == malm_pack::lock_graph_digest(&fixture.lock)
    ));
}

#[test]
fn profile_switch_rejects_missing_retained_component_profiles_without_host_fallback() {
    let temp = tempfile::tempdir().unwrap();
    let (fixture, _) = new_component_fixture();
    let component_port = Arc::new(PinnedComponent {
        calls: AtomicUsize::new(0),
        expected_digest: Digest::sha256(b"unused"),
    });
    let engine = engine(
        &temp,
        ports(Arc::new(DenyGit::default())).with_format_component_execution(component_port.clone()),
    );
    engine.initialize_store().unwrap();
    for (digest, files) in &fixture.objects {
        engine.publish_pack_object_v1(digest, files).unwrap();
    }
    let graph_digest = malm_pack::lock_graph_digest(&fixture.lock);
    let mut inputs = vec![
        PrepareInputV1::new(
            PrepareInputKindV1::Lock,
            "locked-graph",
            graph_digest.clone(),
        )
        .unwrap(),
    ];
    inputs.extend(fixture.lock.nodes().iter().map(|node| {
        PrepareInputV1::new(
            PrepareInputKindV1::Source,
            format!("pack:{}", node.node_id()),
            node.content_digest().clone(),
        )
        .unwrap()
    }));
    let active = engine
        .prepare_v1(&PrepareRequestV1::from(PrepareRequestPartsV1 {
            namespace: NamespaceName::new(NAMESPACE).unwrap(),
            expected_head: None,
            graph_digest,
            inputs,
            artifacts: vec![],
            transforms: vec![],
            findings: vec![],
            operations: vec![],
        }))
        .unwrap();
    engine
        .commit_v1(&CommitRequestV1::new(
            active.plan_id().clone(),
            ApprovalV1::new(active.plan_id().clone(), active.approval_digest().clone()),
        ))
        .unwrap();

    assert!(matches!(
        engine.prepare_profile_switch_v1(&switch_request("component")),
        Err(ProfileSwitchError::InvalidRetainedGraph { detail })
            if detail.contains("locked-component-profiles")
    ));
    assert_eq!(component_port.calls.load(Ordering::Relaxed), 0);
}

#[test]
fn absent_disabled_and_drifted_namespaces_are_rejected_before_graph_loading() {
    let absent_temp = tempfile::tempdir().unwrap();
    let absent = engine(&absent_temp, ports(Arc::new(DenyGit::default())));
    absent.initialize_store().unwrap();
    assert!(matches!(
        absent.prepare_profile_switch_v1(&switch_request("light")),
        Err(ProfileSwitchError::NamespaceNotFound { .. })
    ));

    let drift_temp = tempfile::tempdir().unwrap();
    let fixture = regular_fixture();
    let drifted = engine(&drift_temp, ports(Arc::new(DenyGit::default())));
    seed(&drifted, &fixture, "dark", []);
    fs::write(
        drift_temp.path().join("target/config/theme.conf"),
        b"drifted\n",
    )
    .unwrap();
    fs::remove_file(object_path(&drifted, &fixture.objects[1].0)).unwrap();
    assert!(matches!(
        drifted.prepare_profile_switch_v1(&switch_request("light")),
        Err(ProfileSwitchError::NamespaceNotExact {
            status: NamespaceStatusKindV1::EnabledModified,
            ..
        })
    ));

    let disabled_temp = tempfile::tempdir().unwrap();
    let fixture = regular_fixture();
    let disabled = engine(&disabled_temp, ports(Arc::new(DenyGit::default())));
    seed(&disabled, &fixture, "dark", []);
    let plan = disabled
        .prepare_disable_v1(&NamespaceName::new(NAMESPACE).unwrap())
        .unwrap();
    disabled
        .commit_v1(&CommitRequestV1::new(
            plan.plan_id().clone(),
            ApprovalV1::new(plan.plan_id().clone(), plan.approval_digest().clone()),
        ))
        .unwrap();
    assert!(matches!(
        disabled.prepare_profile_switch_v1(&switch_request("light")),
        Err(ProfileSwitchError::NamespaceDisabled { .. })
    ));
}

#[test]
fn profile_can_select_a_manifest_pinned_component_without_a_prior_grant() {
    let temp = tempfile::tempdir().unwrap();
    let (fixture, component) = new_component_fixture();
    let component_port = Arc::new(PinnedComponent {
        calls: AtomicUsize::new(0),
        expected_digest: component.clone(),
    });
    let engine = engine(
        &temp,
        ports(Arc::new(DenyGit::default())).with_format_component_execution(component_port.clone()),
    );
    seed(&engine, &fixture, "ordinary", []);

    let plan = engine
        .prepare_profile_switch_v1(&switch_request("component"))
        .unwrap();
    assert_eq!(component_port.calls.load(Ordering::Relaxed), 1);
    assert_eq!(
        plan.artifacts()[0].digest(),
        &Digest::sha256(b"pinned component output\n")
    );
}

#[test]
fn profile_switch_publishes_with_the_observed_head_precondition() {
    let temp = tempfile::tempdir().unwrap();
    let (fixture, component) = authorized_component_fixture();
    let git = Arc::new(DenyGit::default());
    let component_port = Arc::new(BlockingComponent::default());
    let primary = engine(
        &temp,
        ports(git.clone()).with_format_component_execution(component_port.clone()),
    );
    seed(&primary, &fixture, "first", [component]);
    component_port.arm();
    let switching = engine(
        &temp,
        ports(git).with_format_component_execution(component_port.clone()),
    );

    let worker = std::thread::spawn(move || {
        switching
            .prepare_profile_switch_v1(&switch_request("second"))
            .map_err(Box::new)
    });
    component_port.wait_until_entered();
    let competing = primary
        .prepare_history_retention_v1(
            &HistoryRetentionRequestV1::new(NamespaceName::new(NAMESPACE).unwrap(), 8).unwrap(),
        )
        .unwrap();
    primary
        .commit_v1(&CommitRequestV1::new(
            competing.plan_id().clone(),
            ApprovalV1::new(
                competing.plan_id().clone(),
                competing.approval_digest().clone(),
            ),
        ))
        .unwrap();
    component_port.release();

    let error = worker.join().unwrap().unwrap_err();
    assert!(matches!(
        *error,
        ProfileSwitchError::Static(StaticPrepareError::Store(EngineError::PreparedStore {
            reason: PreparedStoreIssue::StaleNamespaceHead { .. },
            ..
        }))
    ));
}
