use std::collections::{BTreeMap, BTreeSet};

use malm_config::{
    CanonicalJsonTransformV1, CanonicalTypedDocumentV1, CapturedAuthorityGraphV1,
    CapturedAuthorityV1, CapturedConfigDocumentV1, CapturedDocumentIdV1, CapturedDocumentSetV1,
    CapturedIncludeV1, DeclaredTransformResourceV1, DocumentAuthorityV1, EvaluationFrameV1,
    FormatTransformV1, FragmentDeclarationV1, MAX_CONFIG_DOCUMENT_BYTES, MAX_RICH_COLLECTION_ITEMS,
    MAX_RICH_DIAGNOSTIC_BYTES, MAX_RICH_INCLUDE_DEPTH, MAX_RICH_LOOP_ITERATIONS,
    MAX_RICH_NAME_BYTES, OrderedPatchV1, PatchOperationV1, PatchStepV1, ProvenanceOperationV1,
    RichConditionV1, RichDiagnosticLocationV1, RichDiagnosticSeverityV1, RichDiagnosticV1,
    RichDocumentBodyV1, RichExpressionV1, RichKeyV1, RichNameV1, RichStatementV1, RichValuePathV1,
    SourceRangeV1, TransformContractErrorV1, TransformExecutionErrorV1, TransformFailureKindV1,
    TransformFailureV1, TransformIdentityV1, TransformOptionV1, TransformOutputRangeV1,
    TransformRequestV1, TransformResponseV1, TypedRecordFieldV1, TypedValueKindV1,
    TypedValueTypeV1, TypedValueV1, VariableDeclarationV1, canonical_typed_document_bytes_v1,
    canonical_typed_document_digest_v1, evaluate_rich_config_v1,
    format_transform_request_digest_v1, format_transform_response_digest_v1,
    run_format_transform_v1,
};
use malm_pack::PackPath;
use malm_types::{ContributionName, Digest};

fn rich_name(value: &str) -> RichNameV1 {
    RichNameV1::new(value).unwrap()
}

fn key(value: &str) -> RichKeyV1 {
    RichKeyV1::new(value).unwrap()
}

fn range() -> SourceRangeV1 {
    SourceRangeV1::synthetic()
}

fn authority(label: &str, identity: &[u8]) -> DocumentAuthorityV1 {
    DocumentAuthorityV1::new(
        ContributionName::new(label).unwrap(),
        Digest::sha256(identity),
    )
}

fn document_id(authority: &DocumentAuthorityV1, path: &str) -> CapturedDocumentIdV1 {
    CapturedDocumentIdV1::new(authority.clone(), PackPath::new(path).unwrap())
}

fn literal(value: TypedValueV1) -> RichExpressionV1 {
    RichExpressionV1::literal(value)
}

fn path(segments: &[&str]) -> RichValuePathV1 {
    RichValuePathV1::new(segments.iter().map(|segment| key(segment)).collect()).unwrap()
}

fn empty_document(
    id: CapturedDocumentIdV1,
    includes: Vec<CapturedIncludeV1>,
    body: RichDocumentBodyV1,
) -> CapturedConfigDocumentV1 {
    CapturedConfigDocumentV1::new(id, Vec::new(), includes, body).unwrap()
}

fn local_document_set(
    documents: Vec<CapturedConfigDocumentV1>,
) -> Result<CapturedDocumentSetV1, malm_config::RichConfigErrorV1> {
    let root = documents
        .first()
        .expect("test document set is nonempty")
        .id()
        .authority()
        .clone();
    let mut paths = BTreeSet::new();
    for document in &documents {
        if document.id().authority() == &root {
            paths.insert(document.id().path().clone());
        }
        for include in document.includes() {
            if include.target().authority() == &root {
                paths.insert(include.target().path().clone());
            }
        }
    }
    let authority = CapturedAuthorityV1::new(
        root.clone(),
        Vec::new(),
        Vec::new(),
        paths.into_iter().collect(),
    )?;
    let authorities = CapturedAuthorityGraphV1::new(root, vec![authority])?;
    CapturedDocumentSetV1::new(authorities, documents)
}

#[test]
fn typed_values_apply_recursive_defaults_and_have_canonical_btree_identity() {
    let fields = BTreeMap::from([
        (
            key("accent"),
            TypedRecordFieldV1::optional(TypedValueTypeV1::string()),
        ),
        (
            key("enabled"),
            TypedRecordFieldV1::defaulted(TypedValueTypeV1::boolean(), TypedValueV1::boolean(true))
                .unwrap(),
        ),
        (
            key("labels"),
            TypedRecordFieldV1::required(
                TypedValueTypeV1::list(TypedValueTypeV1::string()).unwrap(),
            ),
        ),
        (
            key("ports"),
            TypedRecordFieldV1::required(
                TypedValueTypeV1::collection(TypedValueTypeV1::unsigned()).unwrap(),
            ),
        ),
    ]);
    let schema = TypedValueTypeV1::record(fields).unwrap();
    let input = TypedValueV1::record(BTreeMap::from([
        (
            key("labels"),
            TypedValueV1::list(vec![
                TypedValueV1::string("primary").unwrap(),
                TypedValueV1::string("fallback").unwrap(),
            ])
            .unwrap(),
        ),
        (
            key("ports"),
            TypedValueV1::collection(BTreeMap::from([
                (key("admin"), TypedValueV1::unsigned(9001)),
                (key("main"), TypedValueV1::unsigned(8080)),
            ]))
            .unwrap(),
        ),
    ]))
    .unwrap();

    let resolved = schema.resolve(&input).unwrap();
    let record = resolved.as_record().unwrap();
    assert_eq!(record.get("accent").unwrap().kind(), TypedValueKindV1::Null);
    assert_eq!(record.get("enabled").unwrap().as_bool(), Some(true));
    assert_eq!(record.get("labels").unwrap().as_list().unwrap().len(), 2);
    assert_eq!(
        record
            .get("ports")
            .unwrap()
            .as_collection()
            .unwrap()
            .keys()
            .map(RichKeyV1::as_str)
            .collect::<Vec<_>>(),
        ["admin", "main"]
    );

    let first = CanonicalTypedDocumentV1::new(resolved.clone()).unwrap();
    let reordered = TypedValueV1::record(BTreeMap::from([
        (key("ports"), record.get("ports").unwrap().clone()),
        (key("labels"), record.get("labels").unwrap().clone()),
        (key("enabled"), record.get("enabled").unwrap().clone()),
        (key("accent"), record.get("accent").unwrap().clone()),
    ]))
    .unwrap();
    let second = CanonicalTypedDocumentV1::new(reordered).unwrap();
    assert_eq!(first, second);
    assert_eq!(
        canonical_typed_document_bytes_v1(&first).unwrap(),
        canonical_typed_document_bytes_v1(&second).unwrap()
    );
    assert_eq!(
        canonical_typed_document_digest_v1(&first).unwrap(),
        canonical_typed_document_digest_v1(&second).unwrap()
    );

    let unknown = TypedValueV1::record(BTreeMap::from([
        (key("labels"), TypedValueV1::list(Vec::new()).unwrap()),
        (
            key("ports"),
            TypedValueV1::collection(BTreeMap::new()).unwrap(),
        ),
        (key("unknown"), TypedValueV1::integer(1)),
    ]))
    .unwrap();
    assert!(schema.resolve(&unknown).is_err());
    assert!(
        schema
            .resolve(&TypedValueV1::string("wrong").unwrap())
            .is_err()
    );
}

#[test]
fn includes_variables_fragments_conditions_loops_and_ordered_patches_evaluate_together() {
    let auth = authority("root", b"locked-root-pack");
    let shared_id = document_id(&auth, "config/shared.kdl");
    let root_id = document_id(&auth, "malm.kdl");

    let item_expressions = BTreeMap::from([
        (key("z-last"), literal(TypedValueV1::integer(30))),
        (key("a-first"), literal(TypedValueV1::integer(10))),
    ]);
    let variables = vec![
        VariableDeclarationV1::defaulted(
            rich_name("enabled"),
            TypedValueTypeV1::boolean(),
            literal(TypedValueV1::boolean(true)),
            range(),
        ),
        VariableDeclarationV1::computed(
            rich_name("items"),
            TypedValueTypeV1::collection(TypedValueTypeV1::integer()).unwrap(),
            RichExpressionV1::Collection(item_expressions),
            range(),
        ),
        VariableDeclarationV1::optional(rich_name("maybe"), TypedValueTypeV1::string(), range()),
        VariableDeclarationV1::required(rich_name("theme"), TypedValueTypeV1::string(), range()),
        VariableDeclarationV1::computed(
            rich_name("title"),
            TypedValueTypeV1::string(),
            RichExpressionV1::Conditional {
                condition: Box::new(RichConditionV1::Equal {
                    left: Box::new(RichExpressionV1::variable(rich_name("theme"))),
                    right: Box::new(literal(TypedValueV1::string("dark").unwrap())),
                    negated: false,
                }),
                then_value: Box::new(literal(TypedValueV1::string("Night").unwrap())),
                else_value: Box::new(literal(TypedValueV1::string("Day").unwrap())),
            },
            range(),
        ),
    ];

    let settings = RichExpressionV1::Record(BTreeMap::from([
        (
            key("enabled"),
            RichExpressionV1::variable(rich_name("enabled")),
        ),
        (key("maybe"), RichExpressionV1::variable(rich_name("maybe"))),
        (key("theme"), RichExpressionV1::variable(rich_name("theme"))),
        (key("title"), RichExpressionV1::variable(rich_name("title"))),
    ]));
    let fragment = FragmentDeclarationV1::new(
        rich_name("base"),
        vec![
            RichStatementV1::Emit {
                key: key("settings"),
                value: settings,
                range: range(),
            },
            RichStatementV1::Emit {
                key: key("sequence"),
                value: literal(TypedValueV1::list(Vec::new()).unwrap()),
                range: range(),
            },
            RichStatementV1::Emit {
                key: key("bindings"),
                value: literal(TypedValueV1::collection(BTreeMap::new()).unwrap()),
                range: range(),
            },
        ],
        range(),
    )
    .unwrap();
    let shared_body = RichDocumentBodyV1::new(variables, vec![fragment], Vec::new()).unwrap();
    let shared = empty_document(shared_id.clone(), Vec::new(), shared_body);

    let append_range_value = OrderedPatchV1::new(vec![PatchStepV1::new(
        PatchOperationV1::ListAppend {
            path: path(&["sequence"]),
            value: RichExpressionV1::variable(rich_name("number")),
        },
        range(),
    )])
    .unwrap();
    let insert_item = OrderedPatchV1::new(vec![PatchStepV1::new(
        PatchOperationV1::CollectionInsert {
            path: path(&["bindings"]),
            key: RichExpressionV1::variable(rich_name("item-key")),
            value: RichExpressionV1::variable(rich_name("item-value")),
        },
        range(),
    )])
    .unwrap();
    let final_patch = OrderedPatchV1::new(vec![
        PatchStepV1::new(
            PatchOperationV1::Set {
                path: path(&["settings", "title"]),
                value: literal(TypedValueV1::string("intermediate").unwrap()),
            },
            range(),
        ),
        PatchStepV1::new(
            PatchOperationV1::Set {
                path: path(&["settings", "title"]),
                value: literal(TypedValueV1::string("final").unwrap()),
            },
            range(),
        ),
        PatchStepV1::new(
            PatchOperationV1::Set {
                path: path(&["settings", "enabled"]),
                value: literal(TypedValueV1::boolean(false)),
            },
            range(),
        ),
    ])
    .unwrap();
    let root_body = RichDocumentBodyV1::new(
        Vec::new(),
        Vec::new(),
        vec![
            RichStatementV1::Compose {
                fragment: rich_name("base"),
                range: range(),
            },
            RichStatementV1::Conditional {
                condition: RichConditionV1::Boolean(Box::new(RichExpressionV1::variable(
                    rich_name("enabled"),
                ))),
                then_statements: vec![RichStatementV1::Emit {
                    key: key("mode"),
                    value: literal(TypedValueV1::string("on").unwrap()),
                    range: range(),
                }],
                else_statements: vec![RichStatementV1::Emit {
                    key: key("mode"),
                    value: literal(TypedValueV1::string("off").unwrap()),
                    range: range(),
                }],
                range: range(),
            },
            RichStatementV1::Range {
                binding: rich_name("number"),
                from: 1,
                through: 3,
                statements: vec![RichStatementV1::Patch(append_range_value)],
                range: range(),
            },
            RichStatementV1::ForEach {
                value_binding: rich_name("item-value"),
                key_binding: Some(rich_name("item-key")),
                iterable: RichExpressionV1::variable(rich_name("items")),
                statements: vec![RichStatementV1::Patch(insert_item)],
                range: range(),
            },
            RichStatementV1::Patch(final_patch),
        ],
    )
    .unwrap();
    let root = empty_document(
        root_id.clone(),
        vec![CapturedIncludeV1::new(shared_id.clone(), range())],
        root_body,
    );
    let documents = local_document_set(vec![root, shared]).unwrap();
    let supplied = BTreeMap::from([(rich_name("theme"), TypedValueV1::string("dark").unwrap())]);

    let first = evaluate_rich_config_v1(&documents, &root_id, &supplied).unwrap();
    let second = evaluate_rich_config_v1(&documents, &root_id, &supplied).unwrap();
    assert_eq!(first, second);
    assert_eq!(
        canonical_typed_document_digest_v1(first.document()).unwrap(),
        canonical_typed_document_digest_v1(second.document()).unwrap()
    );
    let golden: serde_json::Value = serde_json::from_str(include_str!(
        "../../../schemas/config/v1/fixtures/golden/rich-ir.json"
    ))
    .unwrap();
    assert_eq!(
        canonical_typed_document_digest_v1(first.document())
            .unwrap()
            .as_str(),
        golden["canonical_typed_document"]
    );
    assert!(first.diagnostics().is_empty());
    assert_eq!(first.includes().len(), 1);
    assert_eq!(first.document().includes(), first.includes());
    assert_eq!(first.includes()[0].target(), &shared_id);
    assert_eq!(first.document().source_documents().len(), 2);

    let root = first.document().root().as_record().unwrap();
    assert_eq!(
        root.keys().map(RichKeyV1::as_str).collect::<Vec<_>>(),
        ["bindings", "mode", "sequence", "settings"]
    );
    assert_eq!(root.get("mode").unwrap().as_string(), Some("on"));
    assert_eq!(
        root.get("sequence")
            .unwrap()
            .as_list()
            .unwrap()
            .iter()
            .map(TypedValueV1::as_integer)
            .collect::<Vec<_>>(),
        [Some(1), Some(2), Some(3)]
    );
    let bindings = root.get("bindings").unwrap().as_collection().unwrap();
    assert_eq!(
        bindings.keys().map(RichKeyV1::as_str).collect::<Vec<_>>(),
        ["a-first", "z-last"]
    );
    assert_eq!(bindings.get("a-first").unwrap().as_integer(), Some(10));
    let settings = root.get("settings").unwrap().as_record().unwrap();
    assert_eq!(settings.get("title").unwrap().as_string(), Some("final"));
    assert_eq!(settings.get("enabled").unwrap().as_bool(), Some(false));
    assert_eq!(
        settings.get("maybe").unwrap().kind(),
        TypedValueKindV1::Null
    );
    assert_eq!(
        first.variables().get("title").unwrap().value().as_string(),
        Some("Night")
    );

    let sequence_provenance = first
        .document()
        .provenance()
        .get(&path(&["sequence"]))
        .unwrap();
    assert_eq!(sequence_provenance.len(), 4);
    assert!(matches!(
        sequence_provenance[0].operation(),
        ProvenanceOperationV1::Emit
    ));
    assert!(sequence_provenance[1..].iter().all(|record| {
        record
            .frames()
            .iter()
            .any(|frame| matches!(frame, EvaluationFrameV1::Loop { binding, .. } if binding.as_str() == "number"))
    }));
    let title_provenance = first
        .document()
        .provenance()
        .get(&path(&["settings", "title"]))
        .unwrap();
    assert_eq!(title_provenance.len(), 2);
    assert!(title_provenance[0].sequence() < title_provenance[1].sequence());
}

#[test]
fn include_graph_rejects_missing_cycles_forged_authority_and_invalid_ranges() {
    let root_authority = authority("root", b"root");
    let dependency_authority = authority("dependency", b"dependency");
    let root_id = document_id(&root_authority, "malm.kdl");
    let child_id = document_id(&root_authority, "child.kdl");
    let dependency_id = document_id(&dependency_authority, "child.kdl");

    let missing_set = local_document_set(vec![empty_document(
        root_id.clone(),
        vec![CapturedIncludeV1::new(child_id.clone(), range())],
        RichDocumentBodyV1::empty(),
    )])
    .unwrap();
    let error = missing_set
        .evaluate(&root_id, &BTreeMap::new())
        .unwrap_err();
    assert_eq!(error.diagnostics()[0].code().as_str(), "missing-include");

    let confined = local_document_set(vec![
        empty_document(
            root_id.clone(),
            vec![CapturedIncludeV1::new(dependency_id.clone(), range())],
            RichDocumentBodyV1::empty(),
        ),
        empty_document(dependency_id, Vec::new(), RichDocumentBodyV1::empty()),
    ])
    .unwrap_err();
    assert!(
        confined
            .to_string()
            .contains("include path is not declared")
    );

    let cyclic = local_document_set(vec![
        empty_document(
            root_id.clone(),
            vec![CapturedIncludeV1::new(child_id.clone(), range())],
            RichDocumentBodyV1::empty(),
        ),
        empty_document(
            child_id.clone(),
            vec![CapturedIncludeV1::new(root_id.clone(), range())],
            RichDocumentBodyV1::empty(),
        ),
    ])
    .unwrap();
    let error = cyclic.evaluate(&root_id, &BTreeMap::new()).unwrap_err();
    assert_eq!(error.diagnostics()[0].code().as_str(), "include-cycle");
    assert!(error.diagnostics()[0].notes()[0].contains("malm.kdl"));

    let invalid_range = SourceRangeV1::new(0, 2).unwrap();
    let invalid = local_document_set(vec![
        CapturedConfigDocumentV1::new(
            root_id.clone(),
            b"x".to_vec(),
            vec![CapturedIncludeV1::new(child_id.clone(), invalid_range)],
            RichDocumentBodyV1::empty(),
        )
        .unwrap(),
        empty_document(child_id, Vec::new(), RichDocumentBodyV1::empty()),
    ])
    .unwrap();
    let error = invalid.evaluate(&root_id, &BTreeMap::new()).unwrap_err();
    assert_eq!(
        error.diagnostics()[0].code().as_str(),
        "invalid-source-range"
    );

    let deep_ids = (0..=MAX_RICH_INCLUDE_DEPTH)
        .map(|index| document_id(&root_authority, &format!("depth/d{index}.kdl")))
        .collect::<Vec<_>>();
    let deep_documents = deep_ids
        .iter()
        .enumerate()
        .map(|(index, id)| {
            let includes = deep_ids
                .get(index + 1)
                .map(|target| vec![CapturedIncludeV1::new(target.clone(), range())])
                .unwrap_or_default();
            empty_document(id.clone(), includes, RichDocumentBodyV1::empty())
        })
        .collect();
    let deep = local_document_set(deep_documents).unwrap();
    let error = deep.evaluate(&deep_ids[0], &BTreeMap::new()).unwrap_err();
    assert_eq!(
        error.diagnostics()[0].code().as_str(),
        "include-depth-limit"
    );

    let left_id = document_id(&root_authority, "left.kdl");
    let right_id = document_id(&root_authority, "right.kdl");
    let ordered = local_document_set(vec![
        empty_document(
            root_id.clone(),
            vec![
                CapturedIncludeV1::new(left_id.clone(), range()),
                CapturedIncludeV1::new(right_id.clone(), range()),
            ],
            RichDocumentBodyV1::empty(),
        ),
        empty_document(left_id.clone(), Vec::new(), RichDocumentBodyV1::empty()),
        empty_document(right_id.clone(), Vec::new(), RichDocumentBodyV1::empty()),
    ])
    .unwrap();
    let reversed = local_document_set(vec![
        empty_document(
            root_id.clone(),
            vec![
                CapturedIncludeV1::new(right_id.clone(), range()),
                CapturedIncludeV1::new(left_id.clone(), range()),
            ],
            RichDocumentBodyV1::empty(),
        ),
        empty_document(left_id, Vec::new(), RichDocumentBodyV1::empty()),
        empty_document(right_id, Vec::new(), RichDocumentBodyV1::empty()),
    ])
    .unwrap();
    let ordered = ordered.evaluate(&root_id, &BTreeMap::new()).unwrap();
    let reversed = reversed.evaluate(&root_id, &BTreeMap::new()).unwrap();
    assert_eq!(ordered.document().root(), reversed.document().root());
    assert_ne!(
        canonical_typed_document_digest_v1(ordered.document()).unwrap(),
        canonical_typed_document_digest_v1(reversed.document()).unwrap()
    );
}

#[test]
fn evaluator_reports_variable_fragment_patch_and_loop_failures_deterministically() {
    let auth = authority("root", b"root");
    let id = document_id(&auth, "malm.kdl");

    let variable_cycle = RichDocumentBodyV1::new(
        vec![
            VariableDeclarationV1::computed(
                rich_name("a"),
                TypedValueTypeV1::integer(),
                RichExpressionV1::variable(rich_name("b")),
                range(),
            ),
            VariableDeclarationV1::computed(
                rich_name("b"),
                TypedValueTypeV1::integer(),
                RichExpressionV1::variable(rich_name("a")),
                range(),
            ),
        ],
        Vec::new(),
        Vec::new(),
    )
    .unwrap();
    let documents =
        local_document_set(vec![empty_document(id.clone(), Vec::new(), variable_cycle)]).unwrap();
    let error = documents.evaluate(&id, &BTreeMap::new()).unwrap_err();
    assert_eq!(error.diagnostics()[0].code().as_str(), "variable-cycle");

    let fragment_a = FragmentDeclarationV1::new(
        rich_name("a"),
        vec![RichStatementV1::Compose {
            fragment: rich_name("b"),
            range: range(),
        }],
        range(),
    )
    .unwrap();
    let fragment_b = FragmentDeclarationV1::new(
        rich_name("b"),
        vec![RichStatementV1::Compose {
            fragment: rich_name("a"),
            range: range(),
        }],
        range(),
    )
    .unwrap();
    let fragment_cycle = RichDocumentBodyV1::new(
        Vec::new(),
        vec![fragment_a, fragment_b],
        vec![RichStatementV1::Compose {
            fragment: rich_name("a"),
            range: range(),
        }],
    )
    .unwrap();
    let documents =
        local_document_set(vec![empty_document(id.clone(), Vec::new(), fragment_cycle)]).unwrap();
    let error = documents.evaluate(&id, &BTreeMap::new()).unwrap_err();
    assert_eq!(error.diagnostics()[0].code().as_str(), "fragment-cycle");

    let bad_patch = RichDocumentBodyV1::new(
        Vec::new(),
        Vec::new(),
        vec![RichStatementV1::Patch(
            OrderedPatchV1::new(vec![PatchStepV1::new(
                PatchOperationV1::CollectionReplace {
                    path: path(&["missing"]),
                    key: literal(TypedValueV1::string("key").unwrap()),
                    value: literal(TypedValueV1::integer(1)),
                },
                range(),
            )])
            .unwrap(),
        )],
    )
    .unwrap();
    let documents =
        local_document_set(vec![empty_document(id.clone(), Vec::new(), bad_patch)]).unwrap();
    let error = documents.evaluate(&id, &BTreeMap::new()).unwrap_err();
    assert_eq!(error.diagnostics()[0].code().as_str(), "invalid-patch");

    let loop_limit = RichDocumentBodyV1::new(
        Vec::new(),
        Vec::new(),
        vec![RichStatementV1::Range {
            binding: rich_name("index"),
            from: 0,
            through: i64::try_from(MAX_RICH_LOOP_ITERATIONS).unwrap(),
            statements: Vec::new(),
            range: range(),
        }],
    )
    .unwrap();
    let documents =
        local_document_set(vec![empty_document(id.clone(), Vec::new(), loop_limit)]).unwrap();
    let first = documents.evaluate(&id, &BTreeMap::new()).unwrap_err();
    let second = documents.evaluate(&id, &BTreeMap::new()).unwrap_err();
    assert_eq!(first, second);
    assert_eq!(
        first.diagnostics()[0].code().as_str(),
        "loop-iteration-limit"
    );

    let mut deep_expression = literal(
        TypedValueV1::record(BTreeMap::from([(
            key("next"),
            TypedValueV1::record(BTreeMap::new()).unwrap(),
        )]))
        .unwrap(),
    );
    for _ in 0..=malm_config::MAX_RICH_VALUE_DEPTH {
        deep_expression = RichExpressionV1::Select {
            value: Box::new(deep_expression),
            key: key("next"),
        };
    }
    let deep_body = RichDocumentBodyV1::new(
        Vec::new(),
        Vec::new(),
        vec![RichStatementV1::Emit {
            key: key("deep"),
            value: deep_expression,
            range: range(),
        }],
    )
    .unwrap();
    let documents =
        local_document_set(vec![empty_document(id.clone(), Vec::new(), deep_body)]).unwrap();
    let error = documents.evaluate(&id, &BTreeMap::new()).unwrap_err();
    assert_eq!(
        error.diagnostics()[0].code().as_str(),
        "expression-depth-limit"
    );
}

#[test]
fn every_ordered_patch_kind_observes_prior_operations() {
    let auth = authority("root", b"patches");
    let id = document_id(&auth, "malm.kdl");
    let patch = OrderedPatchV1::new(vec![
        PatchStepV1::new(
            PatchOperationV1::Set {
                path: path(&["state", "keep"]),
                value: literal(TypedValueV1::integer(3)),
            },
            range(),
        ),
        PatchStepV1::new(
            PatchOperationV1::Unset {
                path: path(&["state", "drop"]),
                optional: false,
            },
            range(),
        ),
        PatchStepV1::new(
            PatchOperationV1::Unset {
                path: path(&["state", "absent"]),
                optional: true,
            },
            range(),
        ),
        PatchStepV1::new(
            PatchOperationV1::ListAppend {
                path: path(&["list"]),
                value: literal(TypedValueV1::integer(2)),
            },
            range(),
        ),
        PatchStepV1::new(
            PatchOperationV1::CollectionReplace {
                path: path(&["collection"]),
                key: literal(TypedValueV1::string("first").unwrap()),
                value: literal(TypedValueV1::integer(10)),
            },
            range(),
        ),
        PatchStepV1::new(
            PatchOperationV1::CollectionRemove {
                path: path(&["collection"]),
                key: literal(TypedValueV1::string("second").unwrap()),
                optional: false,
            },
            range(),
        ),
        PatchStepV1::new(
            PatchOperationV1::CollectionInsert {
                path: path(&["collection"]),
                key: literal(TypedValueV1::string("third").unwrap()),
                value: literal(TypedValueV1::integer(3)),
            },
            range(),
        ),
        PatchStepV1::new(
            PatchOperationV1::CollectionRemove {
                path: path(&["collection"]),
                key: literal(TypedValueV1::string("absent").unwrap()),
                optional: true,
            },
            range(),
        ),
        PatchStepV1::new(
            PatchOperationV1::CollectionReplaceAll {
                path: path(&["collection"]),
                values: BTreeMap::from([
                    (key("z"), literal(TypedValueV1::integer(26))),
                    (key("a"), literal(TypedValueV1::integer(1))),
                ]),
            },
            range(),
        ),
    ])
    .unwrap();
    let body = RichDocumentBodyV1::new(
        Vec::new(),
        Vec::new(),
        vec![
            RichStatementV1::Emit {
                key: key("state"),
                value: literal(
                    TypedValueV1::record(BTreeMap::from([
                        (key("drop"), TypedValueV1::integer(2)),
                        (key("keep"), TypedValueV1::integer(1)),
                    ]))
                    .unwrap(),
                ),
                range: range(),
            },
            RichStatementV1::Emit {
                key: key("list"),
                value: literal(TypedValueV1::list(vec![TypedValueV1::integer(1)]).unwrap()),
                range: range(),
            },
            RichStatementV1::Emit {
                key: key("collection"),
                value: literal(
                    TypedValueV1::collection(BTreeMap::from([
                        (key("first"), TypedValueV1::integer(1)),
                        (key("second"), TypedValueV1::integer(2)),
                    ]))
                    .unwrap(),
                ),
                range: range(),
            },
            RichStatementV1::Patch(patch),
        ],
    )
    .unwrap();
    let documents = local_document_set(vec![empty_document(id.clone(), Vec::new(), body)]).unwrap();
    let evaluated = documents.evaluate(&id, &BTreeMap::new()).unwrap();
    let root = evaluated.document().root().as_record().unwrap();
    let state = root.get("state").unwrap().as_record().unwrap();
    assert_eq!(state.len(), 1);
    assert_eq!(state.get("keep").unwrap().as_integer(), Some(3));
    assert_eq!(
        root.get("list")
            .unwrap()
            .as_list()
            .unwrap()
            .iter()
            .map(TypedValueV1::as_integer)
            .collect::<Vec<_>>(),
        [Some(1), Some(2)]
    );
    let collection = root.get("collection").unwrap().as_collection().unwrap();
    assert_eq!(
        collection.keys().map(RichKeyV1::as_str).collect::<Vec<_>>(),
        ["a", "z"]
    );
    assert_eq!(collection.get("a").unwrap().as_integer(), Some(1));
    assert!(
        evaluated
            .document()
            .provenance()
            .contains_key(&path(&["state", "absent"]))
    );
}

#[test]
fn rich_model_limits_fail_before_unbounded_evaluation() {
    assert!(RichNameV1::new(format!("a{}", "b".repeat(MAX_RICH_NAME_BYTES))).is_err());
    assert!(RichKeyV1::new("line\nbreak").is_err());
    assert!(SourceRangeV1::new(2, 1).is_err());
    assert!(
        TypedValueV1::list(
            (0..=MAX_RICH_COLLECTION_ITEMS)
                .map(|_| TypedValueV1::boolean(true))
                .collect()
        )
        .is_err()
    );
    assert!(
        CapturedConfigDocumentV1::new(
            document_id(&authority("root", b"root"), "malm.kdl"),
            vec![0; MAX_CONFIG_DOCUMENT_BYTES + 1],
            Vec::new(),
            RichDocumentBodyV1::empty(),
        )
        .is_err()
    );
}

#[derive(Clone, Copy)]
struct ResourceEchoTransform;

impl FormatTransformV1 for ResourceEchoTransform {
    fn identity(&self) -> TransformIdentityV1 {
        TransformIdentityV1::new(rich_name("resource-echo"), "test/1").unwrap()
    }

    fn transform(
        &self,
        request: &TransformRequestV1,
    ) -> Result<TransformResponseV1, TransformFailureV1> {
        let resource = request.resources().get("payload").unwrap();
        let enabled = request
            .options()
            .get("enabled")
            .unwrap()
            .value()
            .as_bool()
            .unwrap();
        let mut output = format!("enabled={enabled};").into_bytes();
        output.extend_from_slice(resource.bytes());
        TransformResponseV1::new(output, "text/plain", Vec::new()).map_err(|error| {
            TransformFailureV1::new(
                TransformFailureKindV1::InvalidResult,
                error.to_string(),
                Vec::new(),
            )
            .unwrap()
        })
    }
}

#[test]
fn transform_contract_sorts_explicit_inputs_and_records_stable_provenance() {
    let root = TypedValueV1::record(BTreeMap::from([
        (key("zeta"), TypedValueV1::integer(2)),
        (key("alpha"), TypedValueV1::integer(1)),
    ]))
    .unwrap();
    let document = CanonicalTypedDocumentV1::new(root).unwrap();
    let resource =
        DeclaredTransformResourceV1::capture(rich_name("payload"), b"bytes".to_vec()).unwrap();
    let request = TransformRequestV1::new(
        document,
        vec![
            TransformOptionV1::new(rich_name("unused"), TypedValueV1::integer(1)).unwrap(),
            TransformOptionV1::new(rich_name("enabled"), TypedValueV1::boolean(true)).unwrap(),
        ],
        vec![resource],
    )
    .unwrap();
    assert_eq!(
        request
            .options()
            .keys()
            .map(RichNameV1::as_str)
            .collect::<Vec<_>>(),
        ["enabled", "unused"]
    );

    let first = run_format_transform_v1(&ResourceEchoTransform, &request).unwrap();
    let second = run_format_transform_v1(&ResourceEchoTransform, &request).unwrap();
    assert_eq!(first, second);
    assert_eq!(first.response().output(), b"enabled=true;bytes");
    assert_eq!(first.response().media_type(), "text/plain");
    assert_eq!(first.provenance().resources().len(), 1);
    assert_eq!(
        first.provenance().document_digest(),
        &canonical_typed_document_digest_v1(request.document()).unwrap()
    );
    assert_ne!(
        first.provenance().request_digest(),
        first.provenance().response_digest()
    );
    assert_eq!(
        first.provenance().request_digest(),
        &format_transform_request_digest_v1(first.provenance().identity(), &request).unwrap()
    );
    assert_eq!(
        first.provenance().response_digest(),
        &format_transform_response_digest_v1(first.response()).unwrap()
    );
}

#[test]
fn canonical_json_builtin_uses_the_common_transform_boundary() {
    let root = TypedValueV1::record(BTreeMap::from([
        (key("alpha"), TypedValueV1::integer(1)),
        (
            key("collection"),
            TypedValueV1::collection(BTreeMap::from([
                (key("z"), TypedValueV1::string("last").unwrap()),
                (key("a"), TypedValueV1::string("first").unwrap()),
            ]))
            .unwrap(),
        ),
        (
            key("list"),
            TypedValueV1::list(vec![TypedValueV1::boolean(true), TypedValueV1::null()]).unwrap(),
        ),
    ]))
    .unwrap();
    let request = TransformRequestV1::new(
        CanonicalTypedDocumentV1::new(root).unwrap(),
        vec![TransformOptionV1::new(rich_name("pretty"), TypedValueV1::boolean(false)).unwrap()],
        Vec::new(),
    )
    .unwrap();
    let execution = run_format_transform_v1(&CanonicalJsonTransformV1, &request).unwrap();
    assert_eq!(
        execution.response().output(),
        br#"{"alpha":1,"collection":{"a":"first","z":"last"},"list":[true,null]}
"#
    );
    assert_eq!(execution.response().media_type(), "application/json");
    assert_eq!(
        execution.provenance().identity().name().as_str(),
        "canonical-json"
    );

    let with_resource = TransformRequestV1::new(
        request.document().clone(),
        Vec::new(),
        vec![DeclaredTransformResourceV1::capture(rich_name("extra"), b"x".to_vec()).unwrap()],
    )
    .unwrap();
    assert!(matches!(
        run_format_transform_v1(&CanonicalJsonTransformV1, &with_resource),
        Err(TransformExecutionErrorV1::TransformFailed(_))
    ));
}

#[derive(Clone, Copy)]
struct InvalidFailureTransform;

impl FormatTransformV1 for InvalidFailureTransform {
    fn identity(&self) -> TransformIdentityV1 {
        TransformIdentityV1::new(rich_name("bad-failure"), "test/1").unwrap()
    }

    fn transform(
        &self,
        _request: &TransformRequestV1,
    ) -> Result<TransformResponseV1, TransformFailureV1> {
        let diagnostic = RichDiagnosticV1::new(
            RichDiagnosticSeverityV1::Error,
            rich_name("output-on-failure"),
            "unavailable output",
            Some(RichDiagnosticLocationV1::Output(
                TransformOutputRangeV1::new(0, 1).unwrap(),
            )),
            Vec::new(),
        )
        .unwrap();
        Err(
            TransformFailureV1::new(TransformFailureKindV1::Internal, "failed", vec![diagnostic])
                .unwrap(),
        )
    }
}

#[derive(Clone, Copy)]
struct OutOfBoundsSourceDiagnosticTransform;

impl FormatTransformV1 for OutOfBoundsSourceDiagnosticTransform {
    fn identity(&self) -> TransformIdentityV1 {
        TransformIdentityV1::new(rich_name("bad-source-range"), "test/1").unwrap()
    }

    fn transform(
        &self,
        request: &TransformRequestV1,
    ) -> Result<TransformResponseV1, TransformFailureV1> {
        let document = request.document().source_documents().keys().next().unwrap();
        let diagnostic = RichDiagnosticV1::new(
            RichDiagnosticSeverityV1::Warning,
            rich_name("bad-source-range"),
            "range exceeds source",
            Some(RichDiagnosticLocationV1::Source(
                malm_config::SourceLocationV1::new(
                    document.clone(),
                    SourceRangeV1::new(0, 1).unwrap(),
                ),
            )),
            vec![],
        )
        .unwrap();
        Ok(TransformResponseV1::new(b"x".to_vec(), "text/plain", vec![diagnostic]).unwrap())
    }
}

#[test]
fn transform_boundary_rejects_bad_resources_and_malformed_results() {
    let bad_digest = DeclaredTransformResourceV1::new(
        rich_name("payload"),
        Digest::sha256(b"different"),
        b"bytes".to_vec(),
    );
    assert!(matches!(
        bad_digest,
        Err(TransformContractErrorV1::ResourceDigestMismatch(_))
    ));

    let document =
        CanonicalTypedDocumentV1::new(TypedValueV1::record(BTreeMap::new()).unwrap()).unwrap();
    let duplicate = TransformRequestV1::new(
        document.clone(),
        vec![
            TransformOptionV1::new(rich_name("same"), TypedValueV1::integer(1)).unwrap(),
            TransformOptionV1::new(rich_name("same"), TypedValueV1::integer(2)).unwrap(),
        ],
        Vec::new(),
    );
    assert!(matches!(
        duplicate,
        Err(TransformContractErrorV1::DuplicateOption(_))
    ));

    let request = TransformRequestV1::new(document, Vec::new(), Vec::new()).unwrap();
    assert!(matches!(
        run_format_transform_v1(&InvalidFailureTransform, &request),
        Err(TransformExecutionErrorV1::InvalidResponse(
            TransformContractErrorV1::OutputDiagnosticOnFailure
        ))
    ));

    let auth = authority("root", b"source range");
    let source_id = document_id(&auth, "malm.kdl");
    let source = empty_document(
        source_id.clone(),
        vec![],
        RichDocumentBodyV1::new(vec![], vec![], vec![]).unwrap(),
    );
    let documents = local_document_set(vec![source]).unwrap();
    let evaluated = evaluate_rich_config_v1(&documents, &source_id, &BTreeMap::new()).unwrap();
    assert_eq!(
        evaluated.document().source_documents()[&source_id].byte_len(),
        0
    );
    let source_request =
        TransformRequestV1::new(evaluated.document().clone(), vec![], vec![]).unwrap();
    assert!(matches!(
        run_format_transform_v1(&OutOfBoundsSourceDiagnosticTransform, &source_request),
        Err(TransformExecutionErrorV1::InvalidResponse(
            TransformContractErrorV1::InvalidDiagnosticSourceRange
        ))
    ));

    let error = RichDiagnosticV1::new(
        RichDiagnosticSeverityV1::Error,
        rich_name("a-code"),
        "error",
        None,
        Vec::new(),
    )
    .unwrap();
    assert!(matches!(
        TransformResponseV1::new(b"x".to_vec(), "text/plain", vec![error.clone()]),
        Err(TransformContractErrorV1::ErrorDiagnosticOnSuccess)
    ));
    let info = RichDiagnosticV1::new(
        RichDiagnosticSeverityV1::Info,
        rich_name("z-code"),
        "info",
        None,
        Vec::new(),
    )
    .unwrap();
    let warning = RichDiagnosticV1::new(
        RichDiagnosticSeverityV1::Warning,
        rich_name("a-code"),
        "warning",
        None,
        Vec::new(),
    )
    .unwrap();
    let response =
        TransformResponseV1::new(b"x".to_vec(), "text/plain", vec![info, warning.clone()]).unwrap();
    assert_eq!(response.diagnostics()[0].code().as_str(), "a-code");
    assert!(
        TransformResponseV1::new(b"x".to_vec(), "text/plain", vec![warning.clone(), warning],)
            .is_err()
    );
    assert!(
        RichDiagnosticV1::new(
            RichDiagnosticSeverityV1::Info,
            rich_name("too-large"),
            "x".repeat(MAX_RICH_DIAGNOSTIC_BYTES + 1),
            None,
            Vec::new(),
        )
        .is_err()
    );
}
