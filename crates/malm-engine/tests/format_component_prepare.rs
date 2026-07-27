use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::{Arc, Mutex};

use malm_config::{
    RichDiagnosticLocationV1, RichDiagnosticSeverityV1, RichDiagnosticV1, RichNameV1,
    SourceLocationV1, SourceRangeV1, TransformFailureKindV1, TransformFailureV1,
    TransformImplementationV1, TransformOutputRangeV1, TransformRequestV1, TransformResponseV1,
};
use malm_engine::{
    ApprovalV1, CommitRequestV1, Engine, EngineConfig, EnginePorts, FormatComponentAuthorizationV1,
    FormatComponentExecutionIssue, FormatComponentExecutionPort, StaticPrepareError, StaticProfile,
    StoreAccess,
};
use malm_module_graph::{PackObjectSourceV1, assemble_locked_graph_v1};
use malm_pack::{
    BundledComponentV1, ComponentInterfaceV1, LockV1, LockedComponentV1, LockedPackV1,
    LockedSourceV1, PackFileV1, PackManifestV1, PackPath, encode_pack_v1, pack_content_digest,
};
use malm_types::{
    ContributionName, DeploymentName, Digest, NamespaceName, PackageId, PrepareInputKindV1,
    PrepareTransformDiagnosticLocationV1, PrepareTransformDiagnosticSeverityV1,
    PreparedPlanInspectionRequestV1,
};

const COMPONENT_BYTES: &[u8] = b"format component fixture";

struct Objects(BTreeMap<Digest, Vec<PackFileV1>>);

impl PackObjectSourceV1 for Objects {
    type Error = std::convert::Infallible;

    fn load_pack(&self, digest: &Digest) -> Result<Vec<PackFileV1>, Self::Error> {
        Ok(self.0[digest].clone())
    }
}

#[derive(Clone, Copy)]
enum FakeResult {
    Success,
    SemanticFailure,
    InfrastructureFailure,
}

struct FakeComponentPort {
    result: FakeResult,
    calls: Mutex<usize>,
    expected_component: Digest,
    expected_profile: Digest,
}

impl FakeComponentPort {
    fn calls(&self) -> usize {
        *self.calls.lock().unwrap()
    }
}

impl FormatComponentExecutionPort for FakeComponentPort {
    fn invoke(
        &self,
        authorization: &FormatComponentAuthorizationV1,
        identity: &malm_config::TransformIdentityV1,
        component_bytes: &[u8],
        request: &TransformRequestV1,
    ) -> Result<Result<TransformResponseV1, TransformFailureV1>, FormatComponentExecutionIssue>
    {
        *self.calls.lock().unwrap() += 1;
        assert!(authorization.permits(&self.expected_component));
        assert_eq!(component_bytes, COMPONENT_BYTES);
        assert!(request.options().is_empty());
        assert!(request.resources().is_empty());
        assert!(matches!(
            identity.implementation(),
            TransformImplementationV1::Component {
                component_digest,
                interface_version,
                execution_profile_digest,
            } if component_digest == &self.expected_component
                && interface_version == "format-component/v1"
                && execution_profile_digest == &self.expected_profile
        ));
        match self.result {
            FakeResult::Success => {
                let source_document = request
                    .document()
                    .source_documents()
                    .keys()
                    .next()
                    .unwrap()
                    .clone();
                Ok(Ok(TransformResponseV1::new(
                    b"component output\n".to_vec(),
                    "text/plain",
                    vec![
                        RichDiagnosticV1::new(
                            RichDiagnosticSeverityV1::Warning,
                            RichNameV1::new("fixture-warning").unwrap(),
                            "review component output",
                            Some(RichDiagnosticLocationV1::Source(SourceLocationV1::new(
                                source_document,
                                SourceRangeV1::new(12, 24).unwrap(),
                            ))),
                            vec!["source note".to_owned(), "review note".to_owned()],
                        )
                        .unwrap(),
                        RichDiagnosticV1::new(
                            RichDiagnosticSeverityV1::Info,
                            RichNameV1::new("fixture-info").unwrap(),
                            "generated output detail",
                            Some(RichDiagnosticLocationV1::Output(
                                TransformOutputRangeV1::new(2, 8).unwrap(),
                            )),
                            vec![],
                        )
                        .unwrap(),
                    ],
                )
                .unwrap()))
            }
            FakeResult::SemanticFailure => Ok(Err(TransformFailureV1::new(
                TransformFailureKindV1::UnsupportedFormat,
                "fixture rejected the format",
                Vec::new(),
            )
            .unwrap())),
            FakeResult::InfrastructureFailure => {
                Err(FormatComponentExecutionIssue::new("fixture runtime failed"))
            }
        }
    }
}

fn name(value: &str) -> ContributionName {
    ContributionName::new(value).unwrap()
}

fn graph(
    execution_profile: &Digest,
    declare_config: bool,
) -> (malm_module_graph::AssembledLockedGraphV1, Digest) {
    graph_with_optional_second_output(execution_profile, declare_config, false)
}

fn graph_with_optional_second_output(
    execution_profile: &Digest,
    declare_config: bool,
    second_output: bool,
) -> (malm_module_graph::AssembledLockedGraphV1, Digest) {
    let component_digest = Digest::sha256(COMPONENT_BYTES);
    let component_path = PackPath::new("components/formatter.wasm").unwrap();
    let component = BundledComponentV1::new(
        name("formatter"),
        component_path.clone(),
        component_digest.clone(),
        ComponentInterfaceV1::FormatComponentV1,
    );
    let locked_component =
        LockedComponentV1::from_declaration(&component, execution_profile.clone());
    let config_path = PackPath::new(malm_config::CONFIG_FILE).unwrap();
    let second_output = if second_output {
        format!(
            r#"                format-file "other" destination="other.txt" executable=#false {{
                    component "formatter-other" digest="{component_digest}" interface="format-component/v1"
                    options {{}}
                    resources {{}}
                }}
"#
        )
    } else {
        String::new()
    };
    let config = format!(
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
                format-file "settings" destination="settings.txt" executable=#false {{
                    component "formatter" digest="{component_digest}" interface="format-component/v1"
                    options {{}}
                    resources {{}}
                }}
{second_output}            }}
        }}
    }}
}}"#
    );
    let manifest = PackManifestV1::new(
        PackageId::new("com.example.format-component").unwrap(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        vec![component.clone()],
    )
    .unwrap();
    let manifest = if declare_config {
        manifest
            .with_config_documents(vec![config_path.clone()])
            .unwrap()
    } else {
        manifest
    };
    let mut files = vec![
        PackFileV1::new(
            PackPath::new("malm-pack.kdl").unwrap(),
            encode_pack_v1(&manifest),
        ),
        PackFileV1::new(component_path, COMPONENT_BYTES),
        PackFileV1::new(config_path, config.into_bytes()),
    ];
    files.sort_by(|left, right| left.path().cmp(right.path()));
    let content_digest =
        pack_content_digest(files.iter().map(|file| (file.path(), file.bytes()))).unwrap();
    let root = LockedPackV1::new(
        PackageId::new("com.example.format-component").unwrap(),
        LockedSourceV1::Root,
        content_digest.clone(),
        Vec::new(),
        vec![locked_component],
    )
    .unwrap();
    let lock = LockV1::new(root.node_id().clone(), vec![root]).unwrap();
    let graph =
        assemble_locked_graph_v1(&lock, &Objects(BTreeMap::from([(content_digest, files)])))
            .unwrap();
    (graph, component_digest)
}

fn graph_with_two_component_outputs(
    execution_profile: &Digest,
) -> (malm_module_graph::AssembledLockedGraphV1, Digest) {
    graph_with_optional_second_output(execution_profile, true, true)
}

fn engine(state: &Path, target: &Path, port: Arc<FakeComponentPort>) -> Engine {
    fs::create_dir(state).unwrap();
    fs::set_permissions(state, fs::Permissions::from_mode(0o700)).unwrap();
    fs::create_dir(target).unwrap();
    Engine::new(
        EngineConfig::from_state_home(state, StoreAccess::ReadWrite)
            .unwrap()
            .with_target_authority(DeploymentName::new("home").unwrap(), target)
            .unwrap(),
        EnginePorts::system().with_format_component_execution(port),
    )
}

fn prepared_entries(engine: &Engine) -> usize {
    fs::read_dir(engine.config().state_root().join("prepared"))
        .map(|entries| entries.count())
        .unwrap_or(0)
}

#[test]
fn config_entry_point_must_be_declared_by_the_exact_locked_pack() {
    let temp = tempfile::tempdir().unwrap();
    let state = temp.path().join("state");
    let target = temp.path().join("target");
    let profile = Digest::sha256(b"execution profile");
    let (graph, component) = graph(&profile, false);
    let port = Arc::new(FakeComponentPort {
        result: FakeResult::Success,
        calls: Mutex::new(0),
        expected_component: component,
        expected_profile: profile,
    });
    let engine = engine(&state, &target, port.clone());
    engine.initialize_store().unwrap();

    assert!(matches!(
        engine.prepare_static_profile_v1(
            StaticProfile {
                graph: &graph,
                component_authorization: &FormatComponentAuthorizationV1::default(),
                namespace: NamespaceName::new("component").unwrap(),
                target_authority: DeploymentName::new("home").unwrap(),
                expected_head: None,
            },
            None,
        ),
        Err(StaticPrepareError::UndeclaredConfigDocument { path, .. })
            if path.as_str() == malm_config::CONFIG_FILE
    ));
    assert_eq!(port.calls(), 0);
    assert_eq!(prepared_entries(&engine), 0);
}

#[test]
fn exact_component_prepare_persists_provenance_and_commits_without_runtime() {
    let temp = tempfile::tempdir().unwrap();
    let state = temp.path().join("state");
    let target = temp.path().join("target");
    let profile = Digest::sha256(b"execution profile");
    let (graph, component) = graph(&profile, true);
    let port = Arc::new(FakeComponentPort {
        result: FakeResult::Success,
        calls: Mutex::new(0),
        expected_component: component.clone(),
        expected_profile: profile.clone(),
    });
    let engine = engine(&state, &target, port.clone());
    engine.initialize_store().unwrap();

    let prepared = engine
        .prepare_static_profile_v1(
            StaticProfile {
                graph: &graph,
                component_authorization: &FormatComponentAuthorizationV1::default(),
                namespace: NamespaceName::new("component").unwrap(),
                target_authority: DeploymentName::new("home").unwrap(),
                expected_head: None,
            },
            None,
        )
        .unwrap();
    assert_eq!(port.calls(), 1);
    assert_eq!(
        prepared.artifacts()[0].digest(),
        &Digest::sha256(b"component output\n")
    );
    assert_eq!(prepared.transforms().len(), 1);
    assert!(matches!(
        prepared.transforms()[0].implementation(),
        malm_types::PrepareTransformImplementationV1::Component {
            component_digest,
            execution_profile_digest,
            interface_version,
            ..
        } if component_digest == &component
            && execution_profile_digest == &profile
            && interface_version == "format-component/v1"
    ));
    assert!(prepared.findings().iter().any(|finding| {
        finding.code() == "transform-warning-settings-0" && finding.approval_required()
    }));
    assert!(prepared.inputs().iter().any(|input| {
        input.kind() == PrepareInputKindV1::Other
            && input.name().starts_with("locked-component-profile:")
            && input.digest() == &profile
    }));
    assert!(prepared.inputs().iter().any(|input| {
        input.kind() == PrepareInputKindV1::Other && input.name() == "locked-component-profiles"
    }));
    let diagnostics = prepared.transforms()[0].diagnostics();
    assert_eq!(diagnostics.len(), 2);
    assert_eq!(
        diagnostics[0].severity(),
        PrepareTransformDiagnosticSeverityV1::Warning
    );
    assert_eq!(diagnostics[0].code(), "fixture-warning");
    assert_eq!(diagnostics[0].message(), "review component output");
    assert_eq!(diagnostics[0].notes(), ["source note", "review note"]);
    assert!(matches!(
        diagnostics[0].primary(),
        Some(PrepareTransformDiagnosticLocationV1::Source(source))
            if source.document_path() == "malm.kdl"
                && source.source_byte_len() >= 24
                && source.start() == 12
                && source.end() == 24
    ));
    assert!(matches!(
        diagnostics[1].primary(),
        Some(PrepareTransformDiagnosticLocationV1::Output(output))
            if output.start() == 2 && output.end() == 8
    ));
    assert!(!target.join("settings.txt").exists());
    let stored_record = fs::read(
        engine
            .config()
            .state_root()
            .join("prepared")
            .join(prepared.plan_id().as_str()),
    )
    .unwrap();
    assert!(
        !stored_record
            .windows(temp.path().as_os_str().len())
            .any(|window| { window == temp.path().as_os_str().as_encoded_bytes() })
    );
    drop(engine);

    let restarted = Engine::new(
        EngineConfig::from_state_home(&state, StoreAccess::ReadWrite)
            .unwrap()
            .with_target_authority(DeploymentName::new("home").unwrap(), &target)
            .unwrap(),
        EnginePorts::system(),
    );
    assert_eq!(restarted.plan_v1(prepared.plan_id()).unwrap(), prepared);
    let inspected = restarted
        .inspect_transform_provenance_v1(&PreparedPlanInspectionRequestV1::new(
            prepared.plan_id().clone(),
        ))
        .unwrap();
    assert_eq!(inspected.transforms(), prepared.transforms());
    restarted
        .commit_v1(&CommitRequestV1::new(
            prepared.plan_id().clone(),
            ApprovalV1::new(
                prepared.plan_id().clone(),
                prepared.approval_digest().clone(),
            ),
        ))
        .unwrap();
    assert_eq!(
        fs::read(target.join("settings.txt")).unwrap(),
        b"component output\n"
    );
}

#[test]
fn repeated_component_invocations_record_one_immutable_component_input() {
    let temp = tempfile::tempdir().unwrap();
    let state = temp.path().join("state");
    let target = temp.path().join("target");
    let profile = Digest::sha256(b"execution profile");
    let (graph, component) = graph_with_two_component_outputs(&profile);
    let port = Arc::new(FakeComponentPort {
        result: FakeResult::Success,
        calls: Mutex::new(0),
        expected_component: component.clone(),
        expected_profile: profile,
    });
    let engine = engine(&state, &target, port.clone());
    engine.initialize_store().unwrap();

    let prepared = engine
        .prepare_static_profile_v1(
            StaticProfile {
                graph: &graph,
                component_authorization: &FormatComponentAuthorizationV1::default(),
                namespace: NamespaceName::new("component").unwrap(),
                target_authority: DeploymentName::new("home").unwrap(),
                expected_head: None,
            },
            None,
        )
        .unwrap();

    assert_eq!(port.calls(), 2);
    assert_eq!(prepared.transforms().len(), 2);
    assert_eq!(
        prepared
            .inputs()
            .iter()
            .filter(|input| input.kind() == PrepareInputKindV1::Component)
            .count(),
        1
    );
}

#[test]
fn component_failures_publish_no_partial_plan() {
    for (index, result) in [
        FakeResult::SemanticFailure,
        FakeResult::InfrastructureFailure,
    ]
    .into_iter()
    .enumerate()
    {
        let temp = tempfile::tempdir().unwrap();
        let state = temp.path().join(format!("state-{index}"));
        let target = temp.path().join(format!("target-{index}"));
        let profile = Digest::sha256(b"execution profile");
        let (graph, component) = graph(&profile, true);
        let port = Arc::new(FakeComponentPort {
            result,
            calls: Mutex::new(0),
            expected_component: component.clone(),
            expected_profile: profile,
        });
        let engine = engine(&state, &target, port.clone());
        engine.initialize_store().unwrap();
        let error = engine
            .prepare_static_profile_v1(
                StaticProfile {
                    graph: &graph,
                    component_authorization: &FormatComponentAuthorizationV1::default(),
                    namespace: NamespaceName::new("component").unwrap(),
                    target_authority: DeploymentName::new("home").unwrap(),
                    expected_head: None,
                },
                None,
            )
            .unwrap_err();
        match result {
            FakeResult::SemanticFailure => {
                assert!(matches!(error, StaticPrepareError::TransformSemantic(_)));
            }
            FakeResult::InfrastructureFailure => assert!(matches!(
                error,
                StaticPrepareError::FormatComponentInfrastructure(_)
            )),
            FakeResult::Success => unreachable!(),
        }
        assert_eq!(port.calls(), 1);
        assert_eq!(prepared_entries(&engine), 0);
        assert!(!target.join("settings.txt").exists());
    }
}
