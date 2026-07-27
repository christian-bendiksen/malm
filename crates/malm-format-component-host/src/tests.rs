use std::collections::BTreeMap;

use malm_config::{
    CanonicalJsonTransformV1, CanonicalTypedDocumentV1, CapturedAuthorityGraphV1,
    CapturedAuthorityV1, CapturedConfigDocumentV1, CapturedDocumentIdV1, CapturedDocumentSetV1,
    CapturedIncludeV1, DeclaredTransformResourceV1, DocumentAuthorityV1, RichDocumentBodyV1,
    RichExpressionV1, RichKeyV1, RichNameV1, RichStatementV1, SourceRangeV1, TargetPathV1,
    TransformIdentityV1, TransformOptionV1, TransformRequestV1, TypedValueV1,
    evaluate_rich_config_v1, run_format_transform_invocation_v1, run_format_transform_v1,
};
use malm_format_component_api::{FormatComponentAuthorizationV1, WIT_SOURCE};
use malm_types::{Alias, ContributionName, Digest};
use wit_component::{ComponentEncoder, StringEncoding, dummy_module, embed_component_metadata};
use wit_parser::{ManglingAndAbi, Resolve, UnresolvedPackageGroup};

use super::{
    ComponentAdmissionError, FormatComponentHost, FormatComponentInvocationError,
    execution_profile_digest_v1, runtime,
};

fn fixture_component() -> Vec<u8> {
    let (resolve, world) = wit_world();
    let mut module = dummy_module(&resolve, world, ManglingAndAbi::Standard32);
    component_from_core(&mut module, &resolve, world)
}

fn wit_world() -> (Resolve, wit_parser::WorldId) {
    let group = UnresolvedPackageGroup::parse("malm-format-component.wit", WIT_SOURCE).unwrap();
    let mut resolve = Resolve::default();
    let package = resolve.push_group(group).unwrap();
    let world = resolve
        .select_world(package, Some("malm-format-component"))
        .unwrap();
    (resolve, world)
}

fn component_from_core(
    module: &mut Vec<u8>,
    resolve: &Resolve,
    world: wit_parser::WorldId,
) -> Vec<u8> {
    embed_component_metadata(module, resolve, world, StringEncoding::UTF8).unwrap();
    ComponentEncoder::default()
        .module(module)
        .unwrap()
        .validate(true)
        .encode()
        .unwrap()
}

fn result_component(output: &[u8], media_type: &str, body: &str) -> Vec<u8> {
    let (resolve, world) = wit_world();
    let output_offset = 64_u32;
    let media_offset = 256_u32;
    let mut result = vec![0_u8; 28];
    result[4..8].copy_from_slice(&output_offset.to_le_bytes());
    result[8..12].copy_from_slice(&u32::try_from(output.len()).unwrap().to_le_bytes());
    result[12..16].copy_from_slice(&media_offset.to_le_bytes());
    result[16..20].copy_from_slice(&u32::try_from(media_type.len()).unwrap().to_le_bytes());
    let wat = format!(
        r#"(module
            (memory (export "cm32p2_memory") 1)
            (global $heap (mut i32) (i32.const 4096))
            (func (export "cm32p2||transform")
                (param i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32)
                (result i32)
                {body}
                i32.const 0)
            (func (export "cm32p2||transform_post") (param i32))
            (func (export "cm32p2_realloc")
                (param $old-ptr i32) (param $old-size i32) (param $align i32) (param $new-size i32)
                (result i32)
                (local $result i32)
                global.get $heap
                local.get $align
                i32.const 1
                i32.sub
                i32.add
                i32.const 0
                local.get $align
                i32.sub
                i32.and
                local.tee $result
                local.get $new-size
                i32.add
                global.set $heap
                local.get $result)
            (func (export "cm32p2_initialize"))
            (data (i32.const 0) "{}")
            (data (i32.const {output_offset}) "{}")
            (data (i32.const {media_offset}) "{}"))"#,
        wat_bytes(&result),
        wat_bytes(output),
        wat_bytes(media_type.as_bytes()),
    );
    let mut module = wat::parse_str(wat).unwrap();
    component_from_core(&mut module, &resolve, world)
}

fn edge_observing_component() -> Vec<u8> {
    result_component(
        b"complete canonical input\n",
        "text/plain",
        r#"
            local.get 8
            i32.const 2
            i32.ne
            if
                i32.const 8
                i32.const 0
                i32.store
            end
            local.get 7
            i32.const 64
            i32.add
            i32.load8_u
            i32.const 1
            i32.ne
            if
                i32.const 8
                i32.const 0
                i32.store
            end
            local.get 7
            i32.const 72
            i32.add
            i32.load
            i32.const 3
            i32.ne
            if
                i32.const 8
                i32.const 0
                i32.store
            end
            local.get 7
            i32.const 68
            i32.add
            i32.load
            i32.load8_u
            i32.const 100
            i32.ne
            if
                i32.const 8
                i32.const 0
                i32.store
            end
            local.get 7
            i32.const 76
            i32.add
            i32.load8_u
            i32.const 0
            i32.ne
            if
                i32.const 8
                i32.const 0
                i32.store
            end
            local.get 7
            i32.const 164
            i32.add
            i32.load8_u
            i32.const 1
            i32.ne
            if
                i32.const 8
                i32.const 0
                i32.store
            end
            local.get 7
            i32.const 172
            i32.add
            i32.load
            i32.const 13
            i32.ne
            if
                i32.const 8
                i32.const 0
                i32.store
            end
            local.get 7
            i32.const 168
            i32.add
            i32.load
            i32.load8_u
            i32.const 115
            i32.ne
            if
                i32.const 8
                i32.const 0
                i32.store
            end
        "#,
    )
}

fn wat_bytes(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("\\{byte:02x}")).collect()
}

fn request() -> TransformRequestV1 {
    let key = |value| RichKeyV1::new(value).unwrap();
    let document = CanonicalTypedDocumentV1::new(
        TypedValueV1::record(BTreeMap::from([
            (key("boolean"), TypedValueV1::boolean(true)),
            (key("float"), TypedValueV1::float(1.5).unwrap()),
            (key("integer"), TypedValueV1::integer(-2)),
            (
                key("list"),
                TypedValueV1::list(vec![TypedValueV1::null(), TypedValueV1::unsigned(3)]).unwrap(),
            ),
            (
                key("collection"),
                TypedValueV1::collection(BTreeMap::from([(
                    key("entry"),
                    TypedValueV1::string("value").unwrap(),
                )]))
                .unwrap(),
            ),
            (
                key("path"),
                TypedValueV1::path(TargetPathV1::new("config/file").unwrap()),
            ),
            (
                key("record"),
                TypedValueV1::record(BTreeMap::from([(
                    key("nested"),
                    TypedValueV1::string("text").unwrap(),
                )]))
                .unwrap(),
            ),
        ]))
        .unwrap(),
    )
    .unwrap();
    let resource_bytes = b"declared resource".to_vec();
    TransformRequestV1::new(
        document,
        vec![
            TransformOptionV1::new(
                RichNameV1::new("option").unwrap(),
                TypedValueV1::boolean(true),
            )
            .unwrap(),
        ],
        vec![
            DeclaredTransformResourceV1::new(
                RichNameV1::new("resource").unwrap(),
                Digest::sha256(&resource_bytes),
                resource_bytes,
            )
            .unwrap(),
        ],
    )
    .unwrap()
}

fn provenance_request() -> TransformRequestV1 {
    let root_authority = DocumentAuthorityV1::new(
        ContributionName::new("root").unwrap(),
        Digest::sha256(b"root authority"),
    );
    let dependency_authority = DocumentAuthorityV1::new(
        ContributionName::new("dependency").unwrap(),
        Digest::sha256(b"dependency authority"),
    );
    let root_id = CapturedDocumentIdV1::new(root_authority.clone(), "malm.kdl".parse().unwrap());
    let include_id = CapturedDocumentIdV1::new(
        dependency_authority.clone(),
        "included.kdl".parse().unwrap(),
    );
    let module_id =
        CapturedDocumentIdV1::new(dependency_authority.clone(), "module.kdl".parse().unwrap());
    let dependency_alias = Alias::new("dep").unwrap();
    let module_name = ContributionName::new("shared-module").unwrap();
    let root_range = SourceRangeV1::new(1, 4).unwrap();
    let module_range = SourceRangeV1::new(5, 9).unwrap();
    let statement_range = SourceRangeV1::new(10, 16).unwrap();
    let root = CapturedConfigDocumentV1::new(
        root_id.clone(),
        vec![b'x'; 32],
        vec![
            CapturedIncludeV1::direct_include(
                include_id.clone(),
                dependency_alias.clone(),
                root_range,
            ),
            CapturedIncludeV1::module(
                module_id.clone(),
                module_name.clone(),
                Some(dependency_alias.clone()),
                module_range,
            ),
        ],
        RichDocumentBodyV1::new(
            vec![],
            vec![],
            vec![RichStatementV1::Emit {
                key: RichKeyV1::new("value").unwrap(),
                value: RichExpressionV1::literal(TypedValueV1::string("complete").unwrap()),
                range: statement_range,
            }],
        )
        .unwrap(),
    )
    .unwrap();
    let empty_body = || RichDocumentBodyV1::new(vec![], vec![], vec![]).unwrap();
    let included =
        CapturedConfigDocumentV1::new(include_id, b"included".to_vec(), vec![], empty_body())
            .unwrap();
    let module =
        CapturedConfigDocumentV1::new(module_id, b"module".to_vec(), vec![], empty_body()).unwrap();
    let graph = CapturedAuthorityGraphV1::new(
        root_authority.clone(),
        vec![
            CapturedAuthorityV1::new(
                root_authority,
                vec![(dependency_alias, dependency_authority.clone())],
                vec![],
                vec!["malm.kdl".parse().unwrap()],
            )
            .unwrap(),
            CapturedAuthorityV1::new(
                dependency_authority,
                vec![],
                vec![(module_name, "module.kdl".parse().unwrap())],
                vec!["included.kdl".parse().unwrap()],
            )
            .unwrap(),
        ],
    )
    .unwrap();
    let documents = CapturedDocumentSetV1::new(graph, vec![root, included, module]).unwrap();
    let evaluated = evaluate_rich_config_v1(&documents, &root_id, &BTreeMap::new()).unwrap();
    let resource_bytes = b"complete declared resource".to_vec();
    TransformRequestV1::new(
        evaluated.document().clone(),
        vec![
            TransformOptionV1::new(
                RichNameV1::new("complete-option").unwrap(),
                TypedValueV1::unsigned(42),
            )
            .unwrap(),
        ],
        vec![
            DeclaredTransformResourceV1::new(
                RichNameV1::new("complete-resource").unwrap(),
                Digest::sha256(&resource_bytes),
                resource_bytes,
            )
            .unwrap(),
        ],
    )
    .unwrap()
}

#[test]
fn profile_identity_is_stable_and_exposed_before_admission() {
    let first = FormatComponentHost::new().unwrap();
    let second = FormatComponentHost::new().unwrap();
    assert_eq!(
        first.execution_profile_digest(),
        second.execution_profile_digest()
    );
    assert_eq!(
        first.execution_profile_digest(),
        &execution_profile_digest_v1()
    );
}

#[test]
fn guest_binding_receives_every_canonical_document_identity_field() {
    let request = provenance_request();
    let binding = super::conversion::to_binding_request(&request);
    let document = request.document();

    assert_eq!(binding.contract_version, request.contract_version());
    assert_eq!(binding.document.version, document.version());
    assert_eq!(binding.document.root.root, 1);
    assert!(matches!(
        &binding.document.root.values[0],
        super::bindings::TypedValueV1::Text(value) if value == "complete"
    ));
    assert!(matches!(
        &binding.document.root.values[1],
        super::bindings::TypedValueV1::RecordValue(fields)
            if fields.len() == 1 && fields[0].name == "value" && fields[0].value == 0
    ));
    assert_eq!(
        binding.document.source_documents.len(),
        document.source_documents().len()
    );
    for (actual, (expected_id, expected_identity)) in binding
        .document
        .source_documents
        .iter()
        .zip(document.source_documents())
    {
        assert_eq!(
            actual.id.authority_label,
            expected_id.authority().label().as_str()
        );
        assert_eq!(
            actual.id.authority_identity,
            expected_id.authority().identity().as_str()
        );
        assert_eq!(actual.id.path, expected_id.path().as_str());
        assert_eq!(actual.digest, expected_identity.digest().as_str());
        assert_eq!(actual.byte_len, expected_identity.byte_len());
    }

    assert_eq!(binding.document.includes.len(), document.includes().len());
    for (actual, expected) in binding.document.includes.iter().zip(document.includes()) {
        assert_eq!(
            actual.source.document.authority_label,
            expected.source().document().authority().label().as_str()
        );
        assert_eq!(
            actual.source.document.authority_identity,
            expected.source().document().authority().identity().as_str()
        );
        assert_eq!(
            actual.source.document.path,
            expected.source().document().path().as_str()
        );
        assert_eq!(actual.source.range.start, expected.source().range().start());
        assert_eq!(actual.source.range.end, expected.source().range().end());
        assert_eq!(
            actual.target.authority_label,
            expected.target().authority().label().as_str()
        );
        assert_eq!(
            actual.target.authority_identity,
            expected.target().authority().identity().as_str()
        );
        assert_eq!(actual.target.path, expected.target().path().as_str());
        assert_eq!(actual.target_digest, expected.target_digest().as_str());
        assert_eq!(
            actual.dependency_alias.as_deref(),
            expected.dependency().map(Alias::as_str)
        );
        match (&actual.edge_kind, expected.kind()) {
            (
                super::bindings::DocumentEdgeKindV1::IncludeEdge,
                malm_config::CapturedDocumentEdgeKindV1::Include,
            ) => {}
            (
                super::bindings::DocumentEdgeKindV1::ModuleEdge(actual_name),
                malm_config::CapturedDocumentEdgeKindV1::Module { name },
            ) => assert_eq!(actual_name, name.as_str()),
            pair => panic!("component edge kind differs from canonical input: {pair:?}"),
        }
    }
    assert!(
        binding
            .document
            .includes
            .iter()
            .any(|include| include.dependency_alias.as_deref() == Some("dep"))
    );
    assert!(binding.document.includes.iter().any(|include| matches!(
        &include.edge_kind,
        super::bindings::DocumentEdgeKindV1::ModuleEdge(name) if name == "shared-module"
    )));

    assert_eq!(
        binding.document.provenance.len(),
        document.provenance().len()
    );
    for (actual, (expected_path, expected_records)) in binding
        .document
        .provenance
        .iter()
        .zip(document.provenance())
    {
        assert_eq!(
            actual.path,
            expected_path
                .segments()
                .iter()
                .map(|segment| segment.as_str().to_owned())
                .collect::<Vec<_>>()
        );
        assert_eq!(actual.records.len(), expected_records.len());
        for (actual_record, expected_record) in actual.records.iter().zip(expected_records) {
            assert_eq!(actual_record.sequence, expected_record.sequence());
            assert_eq!(
                actual_record.location.document.authority_label,
                expected_record
                    .location()
                    .document()
                    .authority()
                    .label()
                    .as_str()
            );
            assert_eq!(
                actual_record.location.document.authority_identity,
                expected_record
                    .location()
                    .document()
                    .authority()
                    .identity()
                    .as_str()
            );
            assert_eq!(
                actual_record.location.document.path,
                expected_record.location().document().path().as_str()
            );
            assert_eq!(
                actual_record.location.range.start,
                expected_record.location().range().start()
            );
            assert_eq!(
                actual_record.location.range.end,
                expected_record.location().range().end()
            );
            assert!(matches!(
                (&actual_record.operation, expected_record.operation()),
                (
                    super::bindings::ProvenanceOperationV1::Emit,
                    malm_config::ProvenanceOperationV1::Emit
                )
            ));
            assert_eq!(actual_record.frames.len(), expected_record.frames().len());
        }
    }
    assert_eq!(binding.options.len(), request.options().len());
    assert_eq!(binding.options[0].name, "complete-option");
    assert_eq!(binding.options[0].value.root, 0);
    assert!(matches!(
        binding.options[0].value.values.as_slice(),
        [super::bindings::TypedValueV1::Unsigned(42)]
    ));
    assert_eq!(binding.resources.len(), request.resources().len());
    assert_eq!(binding.resources[0].name, "complete-resource");
    assert_eq!(
        binding.resources[0].digest,
        Digest::sha256(b"complete declared resource").as_str()
    );
    assert_eq!(binding.resources[0].bytes, b"complete declared resource");
}

#[test]
fn built_in_and_component_receive_the_same_complete_canonical_input() {
    let complete_request = provenance_request();
    let canonical_request =
        TransformRequestV1::new(complete_request.document().clone(), vec![], vec![]).unwrap();
    let built_in = run_format_transform_v1(&CanonicalJsonTransformV1, &canonical_request).unwrap();

    let host = FormatComponentHost::new().unwrap();
    let bytes = edge_observing_component();
    let digest = Digest::sha256(&bytes);
    let admitted = host
        .admit_component(
            &FormatComponentAuthorizationV1::new([digest.clone()]),
            &digest,
            &bytes,
        )
        .unwrap();
    let identity = TransformIdentityV1::component(
        RichNameV1::new("edge-observer").unwrap(),
        digest,
        malm_format_component_api::FORMAT_COMPONENT_INTERFACE_V1,
        host.execution_profile_digest().clone(),
    )
    .unwrap();
    let component = run_format_transform_invocation_v1(identity, &canonical_request, || {
        admitted.transform(&canonical_request)
    })
    .unwrap();

    assert_eq!(component.response().output(), b"complete canonical input\n");
    assert_eq!(
        component.provenance().document_digest(),
        built_in.provenance().document_digest()
    );
    assert_eq!(
        component.provenance().resources(),
        built_in.provenance().resources()
    );

    let incomplete = admitted.transform(&request()).unwrap().unwrap();
    assert!(incomplete.output().is_empty());
}

#[test]
fn admission_requires_exact_authorization_and_digest() {
    let host = FormatComponentHost::new().unwrap();
    let bytes = fixture_component();
    let digest = Digest::sha256(&bytes);

    assert!(matches!(
        host.admit_component(&FormatComponentAuthorizationV1::default(), &digest, &bytes),
        Err(ComponentAdmissionError::UnauthorizedDigest { .. })
    ));

    let authorization = FormatComponentAuthorizationV1::new([digest.clone()]);
    let admitted = host
        .admit_component(&authorization, &digest, &bytes)
        .unwrap();
    assert_eq!(admitted.digest(), &digest);
    assert_eq!(admitted.byte_len(), bytes.len());

    let wrong = Digest::sha256(b"wrong component");
    let authorization = FormatComponentAuthorizationV1::new([wrong.clone()]);
    assert!(matches!(
        host.admit_component(&authorization, &wrong, &bytes),
        Err(ComponentAdmissionError::DigestMismatch { .. })
    ));
}

#[test]
fn admission_rejects_core_modules_and_every_root_import() {
    let host = FormatComponentHost::new().unwrap();
    let core = wat::parse_str("(module)").unwrap();
    let core_digest = Digest::sha256(&core);
    assert!(matches!(
        host.admit_component(
            &FormatComponentAuthorizationV1::new([core_digest.clone()]),
            &core_digest,
            &core,
        ),
        Err(ComponentAdmissionError::CoreModule)
    ));

    let imported = wat::parse_str("(component (import \"clock\" (func)))").unwrap();
    let imported_digest = Digest::sha256(&imported);
    assert!(matches!(
        host.admit_component(
            &FormatComponentAuthorizationV1::new([imported_digest.clone()]),
            &imported_digest,
            &imported,
        ),
        Err(ComponentAdmissionError::ImportsNotAllowed { count: 1 })
    ));
}

#[test]
fn admission_rejects_disabled_core_proposals_inside_components() {
    for (source, feature) in [
        (
            "(component (core module (memory 1 1 shared)))",
            wasmparser::WasmFeatures::THREADS,
        ),
        (
            r#"(component
                (core module
                    (func (result v128)
                        v128.const i32x4 0 0 0 0
                        v128.const i32x4 0 0 0 0
                        i8x16.relaxed_swizzle)))"#,
            wasmparser::WasmFeatures::RELAXED_SIMD,
        ),
        (
            "(component (core module (memory i64 1)))",
            wasmparser::WasmFeatures::MEMORY64,
        ),
    ] {
        let bytes = wat::parse_str(source).unwrap();
        let mut enabled = super::wasm_features_v1();
        enabled.insert(feature);
        wasmparser::Validator::new_with_features(enabled)
            .validate_all(&bytes)
            .expect("fixture is valid when only its reviewed proposal is enabled");

        let host = FormatComponentHost::new().unwrap();
        let digest = Digest::sha256(&bytes);
        assert!(matches!(
            host.admit_component(
                &FormatComponentAuthorizationV1::new([digest.clone()]),
                &digest,
                &bytes,
            ),
            Err(ComponentAdmissionError::InvalidComponent { .. })
        ));
    }
}

#[test]
fn guest_traps_remain_infrastructure_errors() {
    let host = FormatComponentHost::new().unwrap();
    let bytes = fixture_component();
    let digest = Digest::sha256(&bytes);
    let admitted = host
        .admit_component(
            &FormatComponentAuthorizationV1::new([digest.clone()]),
            &digest,
            &bytes,
        )
        .unwrap();
    assert!(matches!(
        admitted.transform(&request()),
        Err(FormatComponentInvocationError::GuestTrap { .. })
    ));
}

#[test]
fn nonempty_request_and_response_round_trip_deterministically() {
    let host = FormatComponentHost::new().unwrap();
    let bytes = result_component(b"component output\n", "text/plain", "");
    let digest = Digest::sha256(&bytes);
    let admitted = host
        .admit_component(
            &FormatComponentAuthorizationV1::new([digest.clone()]),
            &digest,
            &bytes,
        )
        .unwrap();
    let expected = admitted.transform(&request()).unwrap().unwrap();
    assert_eq!(expected.output(), b"component output\n");
    assert_eq!(expected.media_type(), "text/plain");
    assert!(expected.diagnostics().is_empty());
    for _ in 0..8 {
        assert_eq!(admitted.transform(&request()).unwrap().unwrap(), expected);
    }
}

#[test]
fn concurrent_fresh_stores_return_identical_results() {
    let host = FormatComponentHost::new().unwrap();
    let bytes = result_component(b"concurrent\n", "text/plain", "");
    let digest = Digest::sha256(&bytes);
    let admitted = host
        .admit_component(
            &FormatComponentAuthorizationV1::new([digest.clone()]),
            &digest,
            &bytes,
        )
        .unwrap();
    std::thread::scope(|scope| {
        let handles = (0..4)
            .map(|_| {
                let admitted = &admitted;
                scope.spawn(move || {
                    (0..8)
                        .map(|_| admitted.transform(&request()).unwrap().unwrap())
                        .collect::<Vec<_>>()
                })
            })
            .collect::<Vec<_>>();
        for handle in handles {
            assert!(handle.join().unwrap().iter().all(|response| {
                response.output() == b"concurrent\n" && response.media_type() == "text/plain"
            }));
        }
    });
}

#[test]
fn malformed_lifted_response_is_not_a_semantic_failure() {
    let host = FormatComponentHost::new().unwrap();
    let bytes = result_component(b"output", "not-a-media-type", "");
    let digest = Digest::sha256(&bytes);
    let admitted = host
        .admit_component(
            &FormatComponentAuthorizationV1::new([digest.clone()]),
            &digest,
            &bytes,
        )
        .unwrap();
    assert!(matches!(
        admitted.transform(&request()),
        Err(FormatComponentInvocationError::MalformedOutput { .. })
    ));
}

#[test]
fn malformed_source_range_is_rejected_at_the_component_boundary() {
    let request = provenance_request();
    let (document, identity) = request.document().source_documents().iter().next().unwrap();
    let end = u32::try_from(identity.byte_len()).unwrap() + 1;
    let response = super::bindings::TransformResponseV1 {
        output: b"output".to_vec(),
        media_type: "text/plain".to_owned(),
        diagnostics: vec![super::bindings::DiagnosticV1 {
            severity: super::bindings::DiagnosticSeverityV1::Warning,
            code: "invalid.source-range".to_owned(),
            message: "range exceeds source".to_owned(),
            primary: Some(super::bindings::DiagnosticLocationV1::Source(
                super::bindings::SourceLocationV1 {
                    document: super::bindings::DocumentIdV1 {
                        authority_label: document.authority().label().as_str().to_owned(),
                        authority_identity: document.authority().identity().as_str().to_owned(),
                        path: document.path().as_str().to_owned(),
                    },
                    range: super::bindings::SourceRangeV1 { start: 0, end },
                },
            )),
            notes: vec![],
        }],
    };
    assert!(super::conversion::from_binding_response(response, &request).is_err());
}

#[test]
fn scalar_and_simd_nan_results_are_canonicalized() {
    let host = FormatComponentHost::new().unwrap();
    let body = r#"
        i32.const 64
        f32.const nan:0x12345
        f32.const 0
        f32.add
        f32.store
        i32.const 68
        f64.const nan:0x123456789abcd
        f64.const 0
        f64.add
        f64.store
        i32.const 76
        v128.const f32x4 nan:0x12345 nan:0x23456 nan:0x34567 nan:0x45678
        f32.const 0
        f32x4.splat
        f32x4.add
        v128.store
    "#;
    let bytes = result_component(&[0; 28], "application/octet-stream", body);
    let digest = Digest::sha256(&bytes);
    let admitted = host
        .admit_component(
            &FormatComponentAuthorizationV1::new([digest.clone()]),
            &digest,
            &bytes,
        )
        .unwrap();
    let response = admitted.transform(&request()).unwrap().unwrap();
    let mut expected = Vec::new();
    expected.extend_from_slice(&f32::NAN.to_bits().to_le_bytes());
    expected.extend_from_slice(&f64::NAN.to_bits().to_le_bytes());
    for _ in 0..4 {
        expected.extend_from_slice(&f32::NAN.to_bits().to_le_bytes());
    }
    assert_eq!(response.output(), expected);
}

#[test]
fn memory_growth_beyond_the_profile_is_a_semantic_resource_limit() {
    let host = FormatComponentHost::new().unwrap();
    let bytes = result_component(
        b"unreachable",
        "text/plain",
        "i32.const 8192 memory.grow drop",
    );
    let digest = Digest::sha256(&bytes);
    let admitted = host
        .admit_component(
            &FormatComponentAuthorizationV1::new([digest.clone()]),
            &digest,
            &bytes,
        )
        .unwrap();
    let failure = admitted
        .transform(&request())
        .unwrap()
        .expect_err("memory limit must be a semantic failure");
    assert_eq!(
        failure.kind(),
        malm_config::TransformFailureKindV1::ResourceLimit
    );
}

#[test]
fn fuel_exhaustion_is_a_semantic_resource_limit() {
    let host = FormatComponentHost::new().unwrap();
    let bytes = result_component(b"fuel\n", "text/plain", "");
    let digest = Digest::sha256(&bytes);
    let admitted = host
        .admit_component(
            &FormatComponentAuthorizationV1::new([digest.clone()]),
            &digest,
            &bytes,
        )
        .unwrap();
    let request = super::conversion::to_binding_request(&request());
    let succeeds = |fuel| {
        runtime::transform(
            &admitted.pre,
            &request,
            admitted.profile.runtime_limits,
            fuel,
            admitted.epoch_deadline_ticks,
        )
        .is_ok()
    };
    let mut lower = 0;
    let mut upper = admitted.profile.runtime_limits.transform_fuel;
    assert!(succeeds(upper));
    while lower < upper {
        let middle = lower + (upper - lower) / 2;
        if succeeds(middle) {
            upper = middle;
        } else {
            lower = middle + 1;
        }
    }
    assert!(lower > 0);
    for _ in 0..4 {
        assert!(succeeds(lower));
        assert!(matches!(
            runtime::transform(
                &admitted.pre,
                &request,
                admitted.profile.runtime_limits,
                lower - 1,
                admitted.epoch_deadline_ticks,
            ),
            Err(runtime::RuntimeCallError::ResourceLimit(
                runtime::ResourceLimitKind::Fuel
            ))
        ));
    }
}

#[test]
fn epoch_expiry_is_only_infrastructure_cancellation() {
    let host = FormatComponentHost::new().unwrap();
    let bytes = result_component(b"epoch\n", "text/plain", "");
    let digest = Digest::sha256(&bytes);
    let admitted = host
        .admit_component(
            &FormatComponentAuthorizationV1::new([digest.clone()]),
            &digest,
            &bytes,
        )
        .unwrap();
    let request = super::conversion::to_binding_request(&request());
    assert!(matches!(
        runtime::force_epoch_cancellation(&admitted.pre, &request, admitted.profile.runtime_limits,),
        runtime::RuntimeCallError::Invocation(
            FormatComponentInvocationError::InfrastructureCancellation
        )
    ));
}
