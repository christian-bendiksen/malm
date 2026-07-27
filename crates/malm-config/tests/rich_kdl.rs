use std::collections::{BTreeMap, BTreeSet};

use malm_config::{
    CanonicalJsonTransformV1, CanonicalTypedDocumentV1, CapturedAuthorityGraphV1,
    CapturedAuthorityV1, CapturedDocumentEdgeKindV1, CapturedDocumentIdV1, DesiredOutputKindV1,
    DocumentAuthorityV1, KeyValueTransformV1, ParsedRichConfigDocumentV1, ParsedRichConfigSetV1,
    PlainTextTransformV1, RichDiagnosticLocationV1, RichNameV1, TransformOptionV1,
    TransformRequestV1, TypedValueV1, decode_rich_config_document_v1, run_format_transform_v1,
};
use malm_pack::PackPath;
use malm_types::{Alias, ContributionName, Digest};

const RICH_ROOT: &[u8] = include_bytes!("../../../schemas/config/v1/fixtures/valid/rich-full.kdl");
const RICH_SHARED: &[u8] =
    include_bytes!("../../../schemas/config/v1/fixtures/valid/rich-shared.kdl");

fn authority() -> DocumentAuthorityV1 {
    DocumentAuthorityV1::new(
        ContributionName::new("root").unwrap(),
        Digest::sha256(b"abc"),
    )
}

fn id(path: &str) -> CapturedDocumentIdV1 {
    CapturedDocumentIdV1::new(authority(), PackPath::new(path).unwrap())
}

fn name(value: &str) -> RichNameV1 {
    RichNameV1::new(value).unwrap()
}

fn parsed_set_from(
    sources: Vec<ParsedRichConfigDocumentV1>,
) -> Result<ParsedRichConfigSetV1, malm_config::RichConfigErrorV1> {
    let root = sources
        .first()
        .expect("test source set is nonempty")
        .id()
        .authority()
        .clone();
    let mut paths = BTreeSet::new();
    for source in &sources {
        paths.insert(source.id().path().clone());
        paths.extend(
            source
                .includes()
                .iter()
                .map(|include| include.path().clone()),
        );
    }
    let authority = CapturedAuthorityV1::new(
        root.clone(),
        Vec::new(),
        Vec::new(),
        paths.into_iter().collect(),
    )?;
    let authorities = CapturedAuthorityGraphV1::new(root, vec![authority])?;
    ParsedRichConfigSetV1::new(authorities, sources)
}

fn parsed_set() -> ParsedRichConfigSetV1 {
    parsed_set_from(vec![
        decode_rich_config_document_v1(id("rich-full.kdl"), RICH_ROOT).unwrap(),
        decode_rich_config_document_v1(id("rich-shared.kdl"), RICH_SHARED).unwrap(),
    ])
    .unwrap()
}

#[test]
fn captured_source_digest_goldens_match_the_exact_valid_fixture_bytes() {
    let golden: serde_json::Value = serde_json::from_str(include_str!(
        "../../../schemas/config/v1/fixtures/golden/digests.json"
    ))
    .unwrap();
    assert_eq!(
        Digest::sha256(RICH_ROOT).as_str(),
        golden["root_config"].as_str().unwrap()
    );
    assert_eq!(
        Digest::sha256(RICH_SHARED).as_str(),
        golden["module"].as_str().unwrap()
    );
}

#[test]
fn direct_dependency_includes_and_modules_resolve_through_locked_authority_scope() {
    let root_authority = authority();
    let dependency_authority = DocumentAuthorityV1::new(
        ContributionName::new("theme-pack").unwrap(),
        Digest::sha256(b"theme pack"),
    );
    let root_path = PackPath::new("malm.kdl").unwrap();
    let include_path = PackPath::new("config/shared.kdl").unwrap();
    let module_path = PackPath::new("modules/palette.kdl").unwrap();
    let dependency = Alias::new("theme").unwrap();
    let authorities = CapturedAuthorityGraphV1::new(
        root_authority.clone(),
        vec![
            CapturedAuthorityV1::new(
                root_authority.clone(),
                vec![(dependency.clone(), dependency_authority.clone())],
                Vec::new(),
                vec![root_path.clone()],
            )
            .unwrap(),
            CapturedAuthorityV1::new(
                dependency_authority.clone(),
                Vec::new(),
                vec![(
                    ContributionName::new("palette").unwrap(),
                    module_path.clone(),
                )],
                vec![include_path.clone()],
            )
            .unwrap(),
        ],
    )
    .unwrap();
    let root_id = CapturedDocumentIdV1::new(root_authority, root_path);
    let include_id = CapturedDocumentIdV1::new(dependency_authority.clone(), include_path);
    let module_id = CapturedDocumentIdV1::new(dependency_authority, module_path);
    let root = br#"rich-config schema-version=1 default-profile="default" {
    includes { include path="config/shared.kdl" dependency="theme" }
    modules { module "palette" dependency="theme" }
    variables { }
    fragments { }
    slots { }
    statements { }
    profiles {
        profile "default" abstract=#false {
            extends { }
            statements { }
            outputs { }
        }
    }
}"#;
    let included = br#"rich-config schema-version=1 {
    includes { }
    modules { }
    variables { }
    fragments { }
    slots { }
    statements { emit "included" { value { bool #true } } }
    profiles { }
}"#;
    let module = br#"rich-config schema-version=1 {
    includes { }
    modules { }
    variables { }
    fragments { }
    slots { }
    statements { emit "module" { value { string "palette" } } }
    profiles { }
}"#;
    let set = ParsedRichConfigSetV1::new(
        authorities,
        vec![
            decode_rich_config_document_v1(root_id.clone(), root).unwrap(),
            decode_rich_config_document_v1(include_id.clone(), included).unwrap(),
            decode_rich_config_document_v1(module_id.clone(), module).unwrap(),
        ],
    )
    .unwrap();

    let evaluated = set.evaluate(&root_id, None, &BTreeMap::new()).unwrap();
    let document = evaluated.evaluation().document();
    let record = document.root().as_record().unwrap();
    assert_eq!(record.get("included").unwrap().as_bool(), Some(true));
    assert_eq!(record.get("module").unwrap().as_string(), Some("palette"));
    assert!(document.source_documents().contains_key(&include_id));
    assert!(document.source_documents().contains_key(&module_id));
    assert!(matches!(
        evaluated.evaluation().includes()[0].kind(),
        CapturedDocumentEdgeKindV1::Include
    ));
    assert!(matches!(
        evaluated.evaluation().includes()[1].kind(),
        CapturedDocumentEdgeKindV1::Module { name } if name.as_str() == "palette"
    ));
}

#[test]
fn rich_kdl_lowers_profiles_includes_slots_and_outputs_into_the_existing_ir() {
    let sources = parsed_set();
    let evaluated = sources
        .evaluate(&id("rich-full.kdl"), None, &BTreeMap::new())
        .unwrap();
    assert_eq!(
        evaluated,
        sources
            .evaluate(
                &id("rich-full.kdl"),
                Some(&name("desktop")),
                &BTreeMap::new()
            )
            .unwrap()
    );

    assert_eq!(evaluated.selected_profile().as_str(), "desktop");
    assert_eq!(evaluated.evaluation().includes().len(), 1);
    assert_eq!(
        evaluated
            .active_slots()
            .get("config-provider")
            .unwrap()
            .iter()
            .map(RichNameV1::as_str)
            .collect::<Vec<_>>(),
        ["settings-file", "settings-link"]
    );
    let root = evaluated
        .evaluation()
        .document()
        .root()
        .as_record()
        .unwrap();
    assert_eq!(
        root.get("profile-label").unwrap().as_string(),
        Some("night")
    );
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
    let items = root.get("items").unwrap().as_collection().unwrap();
    assert_eq!(items.get("a").unwrap().as_integer(), Some(10));
    assert_eq!(items.get("z").unwrap().as_integer(), Some(26));
    let settings = root.get("settings").unwrap().as_record().unwrap();
    assert_eq!(
        settings.get("title").unwrap().as_string(),
        Some("Configured")
    );
    assert_eq!(
        settings
            .get("ports")
            .unwrap()
            .as_collection()
            .unwrap()
            .get("main")
            .unwrap()
            .as_unsigned(),
        Some(8080)
    );

    let outputs = evaluated.desired_outputs().outputs();
    assert_eq!(outputs.len(), 4);
    assert!(matches!(
        outputs.get("settings-file").unwrap().kind(),
        DesiredOutputKindV1::RegularFile {
            executable: false,
            ..
        }
    ));
    assert!(matches!(
        outputs.get("settings-link").unwrap().kind(),
        DesiredOutputKindV1::Symlink { target } if target.as_str() == "app/config.txt"
    ));
    assert!(matches!(
        outputs.get("shared-tree").unwrap().kind(),
        DesiredOutputKindV1::CanonicalTree { .. }
    ));
    assert!(matches!(
        outputs.get("archive-tree").unwrap().kind(),
        DesiredOutputKindV1::DecodedArchive { decoder, .. }
            if decoder.as_str() == "malm.posix-ustar.none"
    ));
    assert!(
        outputs
            .values()
            .all(|output| { output.source().range().start() < output.source().range().end() })
    );

    let provenance = evaluated.evaluation().document().provenance();
    assert!(
        provenance
            .values()
            .flatten()
            .all(|record| { record.location().range().start() < record.location().range().end() })
    );
}

#[test]
fn parsed_ir_routes_three_builtin_formats_through_the_common_runner() {
    let evaluated = parsed_set()
        .evaluate(&id("rich-full.kdl"), None, &BTreeMap::new())
        .unwrap();
    let document = evaluated.evaluation().document().clone();

    let json_request = TransformRequestV1::new(document.clone(), Vec::new(), Vec::new()).unwrap();
    let json = run_format_transform_v1(&CanonicalJsonTransformV1, &json_request).unwrap();
    assert_eq!(
        json.response().output(),
        include_bytes!("../../../schemas/config/v1/fixtures/golden/rich-canonical.json")
    );

    let text_request = TransformRequestV1::new(
        document,
        vec![
            TransformOptionV1::new(name("trailing-newline"), TypedValueV1::boolean(true)).unwrap(),
        ],
        Vec::new(),
    )
    .unwrap();
    let text = run_format_transform_v1(&PlainTextTransformV1, &text_request).unwrap();
    assert_eq!(
        text.response().output(),
        include_bytes!("../../../schemas/config/v1/fixtures/golden/rich-plain-text.txt")
    );

    let flat = CanonicalTypedDocumentV1::new(
        TypedValueV1::record(BTreeMap::from([
            (
                malm_config::RichKeyV1::new("message").unwrap(),
                TypedValueV1::string("line\nnext").unwrap(),
            ),
            (
                malm_config::RichKeyV1::new("ratio").unwrap(),
                TypedValueV1::float(1.0).unwrap(),
            ),
            (
                malm_config::RichKeyV1::new("count").unwrap(),
                TypedValueV1::integer(2),
            ),
            (
                malm_config::RichKeyV1::new("alpha").unwrap(),
                TypedValueV1::boolean(true),
            ),
            (
                malm_config::RichKeyV1::new("empty").unwrap(),
                TypedValueV1::null(),
            ),
        ]))
        .unwrap(),
    )
    .unwrap();
    let key_value_request = TransformRequestV1::new(
        flat,
        vec![
            TransformOptionV1::new(name("separator"), TypedValueV1::string(": ").unwrap()).unwrap(),
        ],
        Vec::new(),
    )
    .unwrap();
    let key_value = run_format_transform_v1(&KeyValueTransformV1, &key_value_request).unwrap();
    assert_eq!(
        key_value.response().output(),
        include_bytes!("../../../schemas/config/v1/fixtures/golden/rich-key-value.txt")
    );
    assert_ne!(
        json.provenance().request_digest(),
        text.provenance().request_digest()
    );
}

#[test]
fn format_file_requires_one_closed_transform_and_explicit_inputs() {
    let digest = Digest::sha256(b"component");
    let resource = Digest::sha256(b"resource");
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
                format-file "settings" destination="settings.json" executable=#false {{
                    component "formatter" digest="{digest}" interface="format-component/v1"
                    options {{
                        option "pretty" {{
                            bool #true
                        }}
                    }}
                    resources {{
                        resource "schema" source="schemas/settings.json" source-kind="schema" raw-digest="{resource}" object-digest="{resource}" byte-len=8
                    }}
                }}
            }}
        }}
    }}
}}"#
    );
    let document = id("format.kdl");
    let parsed = decode_rich_config_document_v1(document.clone(), source.as_bytes()).unwrap();
    let set = parsed_set_from(vec![parsed]).unwrap();
    let evaluated = set.evaluate(&document, None, &BTreeMap::new()).unwrap();
    let output = evaluated
        .desired_outputs()
        .outputs()
        .get("settings")
        .unwrap();
    assert!(matches!(
        output.kind(),
        DesiredOutputKindV1::TransformedFile {
            transform: malm_config::FormatTransformSelectionV1::Component {
                name,
                component_digest,
            },
            options,
            resources,
            executable: false,
        } if name.as_str() == "formatter"
            && component_digest == &digest
            && options.len() == 1
            && resources.len() == 1
    ));

    for malformed in [
        source.replace(
            "                    component \"formatter\"",
            "                    built-in \"canonical-json\"\n                    component \"formatter\"",
        ),
        source.replace("                    options {\n", "                    choices {\n"),
        source.replace("interface=\"format-component/v1\"", "interface=\"other/v1\""),
        source.replace(
            "interface=\"format-component/v1\"",
            "interface=\"format-component/v1\" execution-profile=\"sha256-1111111111111111111111111111111111111111111111111111111111111111\"",
        ),
    ] {
        assert!(decode_rich_config_document_v1(id("malformed-format.kdl"), malformed.as_bytes()).is_err());
    }
}

#[test]
fn rich_kdl_is_strict_and_rejects_unsafe_or_overfull_declarations() {
    let malformed =
        include_bytes!("../../../schemas/config/v1/fixtures/malformed/rich-unknown-node.kdl");
    let error = decode_rich_config_document_v1(id("malformed.kdl"), malformed).unwrap_err();
    assert!(error.range().is_some());

    assert!(
        decode_rich_config_document_v1(
            id("unsupported.kdl"),
            include_bytes!("../../../schemas/config/v1/fixtures/unsupported/rich-version-2.kdl"),
        )
        .is_err()
    );

    let unknown_property = String::from_utf8(RICH_ROOT.to_vec())
        .unwrap()
        .replace("schema-version=1", "schema-version=1 surprise=#true");
    assert!(
        decode_rich_config_document_v1(id("unknown.kdl"), unknown_property.as_bytes()).is_err()
    );

    let unsafe_symlink = String::from_utf8(RICH_ROOT.to_vec())
        .unwrap()
        .replace("target=\"app/config.txt\"", "target=\"../escape\"");
    assert!(decode_rich_config_document_v1(id("unsafe.kdl"), unsafe_symlink.as_bytes()).is_err());

    let one_provider = String::from_utf8(RICH_SHARED.to_vec())
        .unwrap()
        .replace("max=2", "max=1");
    let sources = parsed_set_from(vec![
        decode_rich_config_document_v1(id("rich-full.kdl"), RICH_ROOT).unwrap(),
        decode_rich_config_document_v1(id("rich-shared.kdl"), one_provider.as_bytes()).unwrap(),
    ])
    .unwrap();
    let error = sources
        .evaluate(&id("rich-full.kdl"), None, &BTreeMap::new())
        .unwrap_err();
    assert_eq!(
        error.diagnostics()[0].code().as_str(),
        "slot-provider-limit"
    );
    assert!(matches!(
        error.diagnostics()[0].primary(),
        Some(RichDiagnosticLocationV1::Source(_))
    ));

    let overlapping = String::from_utf8(RICH_ROOT.to_vec()).unwrap().replace(
        "destination=\".local/share/archive-tree\"",
        "destination=\".config/app\"",
    );
    let sources = parsed_set_from(vec![
        decode_rich_config_document_v1(id("rich-full.kdl"), overlapping.as_bytes()).unwrap(),
        decode_rich_config_document_v1(id("rich-shared.kdl"), RICH_SHARED).unwrap(),
    ])
    .unwrap();
    let error = sources
        .evaluate(&id("rich-full.kdl"), None, &BTreeMap::new())
        .unwrap_err();
    assert_eq!(
        error.diagnostics()[0].code().as_str(),
        "overlapping-output-destination"
    );

    let cyclic_shared = String::from_utf8(RICH_SHARED.to_vec()).unwrap().replace(
        "extends {\n            }\n            statements",
        "extends {\n                profile \"desktop\"\n            }\n            statements",
    );
    let sources = parsed_set_from(vec![
        decode_rich_config_document_v1(id("rich-full.kdl"), RICH_ROOT).unwrap(),
        decode_rich_config_document_v1(id("rich-shared.kdl"), cyclic_shared.as_bytes()).unwrap(),
    ])
    .unwrap();
    let error = sources
        .evaluate(&id("rich-full.kdl"), None, &BTreeMap::new())
        .unwrap_err();
    assert_eq!(error.diagnostics()[0].code().as_str(), "profile-cycle");
}

#[test]
fn rich_kdl_covers_all_expression_condition_and_patch_shapes() {
    let bytes = br#"
rich-config schema-version=1 default-profile="main" {
    includes {
    }
    modules {
    }
    variables {
        input "optional-text" optional=#true {
            type "string"
        }
        let "float-value" {
            type "float"
            expression {
                float 1.5
            }
        }
        let "path-value" {
            type "path"
            expression {
                path "config/file"
            }
        }
        let "selected" {
            type "string"
            expression {
                select key="chosen" {
                    value {
                        record {
                            field "chosen" {
                                string "yes"
                            }
                        }
                    }
                }
            }
        }
    }
    fragments {
    }
    slots {
    }
    statements {
        emit "literal-null" {
            value {
                "null"
            }
        }
        emit "optional-null" {
            value {
                variable "optional-text"
            }
        }
        emit "float" {
            value {
                variable "float-value"
            }
        }
        emit "path" {
            value {
                variable "path-value"
            }
        }
        emit "selected" {
            value {
                variable "selected"
            }
        }
    }
    profiles {
        profile "main" abstract=#false {
            extends {
            }
            statements {
                when {
                    condition {
                        all {
                            condition {
                                not {
                                    condition {
                                        is-set {
                                            value {
                                                variable "optional-text"
                                            }
                                        }
                                    }
                                }
                            }
                            condition {
                                any {
                                    condition {
                                        equal negated=#false {
                                            left {
                                                variable "selected"
                                            }
                                            right {
                                                string "yes"
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                    then {
                        emit "condition" {
                            value {
                                bool #true
                            }
                        }
                    }
                    else {
                        emit "condition" {
                            value {
                                bool #false
                            }
                        }
                    }
                }
                emit "scratch" {
                    value {
                        record {
                            field "drop" {
                                string "value"
                            }
                        }
                    }
                }
                emit "replacement" {
                    value {
                        collection {
                            item "old" {
                                integer 0
                            }
                        }
                    }
                }
                patch {
                    unset path="scratch.drop" optional=#false
                    collection-replace-all path="replacement" {
                        item "b" {
                            integer 2
                        }
                        item "a" {
                            integer 1
                        }
                    }
                }
            }
            outputs {
            }
        }
    }
}
"#;
    let source = decode_rich_config_document_v1(id("expressions.kdl"), bytes).unwrap();
    let result = parsed_set_from(vec![source])
        .unwrap()
        .evaluate(&id("expressions.kdl"), None, &BTreeMap::new())
        .unwrap();
    let root = result.evaluation().document().root().as_record().unwrap();
    assert_eq!(root.get("literal-null").unwrap().kind().as_str(), "null");
    assert_eq!(root.get("optional-null").unwrap().kind().as_str(), "null");
    assert_eq!(root.get("float").unwrap().as_float().unwrap().get(), 1.5);
    assert_eq!(
        root.get("path").unwrap().as_path().unwrap().as_str(),
        "config/file"
    );
    assert_eq!(root.get("selected").unwrap().as_string(), Some("yes"));
    assert_eq!(root.get("condition").unwrap().as_bool(), Some(true));
    assert!(root.get("scratch").unwrap().as_record().unwrap().is_empty());
    assert_eq!(
        root.get("replacement")
            .unwrap()
            .as_collection()
            .unwrap()
            .keys()
            .map(malm_config::RichKeyV1::as_str)
            .collect::<Vec<_>>(),
        ["a", "b"]
    );
}
