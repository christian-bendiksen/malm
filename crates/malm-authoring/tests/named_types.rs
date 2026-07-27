use malm_authoring::{
    AUTHORING_CONFIG_FILE, AuthoringSourceSetV1, check_authoring_workspace_v1,
    evaluate_authoring_profile_v1, resolve_authoring_vars_v1,
};

fn sources(document: &str) -> AuthoringSourceSetV1 {
    let mut sources = AuthoringSourceSetV1::new();
    sources
        .insert(AUTHORING_CONFIG_FILE, document.as_bytes().to_vec())
        .expect("capture authoring document");
    sources
}

fn report(document: &str) -> String {
    evaluate_authoring_profile_v1(&sources(document), AUTHORING_CONFIG_FILE, "p", &[])
        .expect_err("source should be rejected")
        .to_string()
}

fn workspace_report(document: &str) -> (usize, String) {
    let checked = check_authoring_workspace_v1(&sources(document), AUTHORING_CONFIG_FILE)
        .expect("check authoring workspace");
    (checked.error_count(), checked.report().to_owned())
}

#[test]
fn named_types_forward_refs_nested_lookup_defaults_collections_and_patches() {
    let document = r#"config target="~" default-profile="base"
module "m" {
    description "named types"
    types {
        record "device" {
            fields {
                field "options" type="options" required=#true
            }
        }
        record "options" {
            fields {
                field "enabled" type="bool" required=#true default=#true
                field "direction" type="direction" required=#true
                field "label" type="string?"
            }
        }
        enum "direction" { values "left" "right" }
    }
    inputs {
        input "settings" type="options" {
            default { direction "left" }
        }
        input "devices" type="collection<device>" {
            defaults {
                item "z-first" { options { direction "right" } }
                item "a-second" { options { direction "left" } }
            }
        }
    }
    outputs {
        render "out" format="test-format" component-renderer="test-renderer" {
            enabled (ref)"settings.enabled"
            direction (ref)"settings.direction"
            devices {
                @for-each "device" in="devices" {
                    - {
                        key (ref)"device.key"
                        enabled (ref)"device.options.enabled"
                        direction (ref)"device.options.direction"
                    }
                }
            }
        }
    }
}
profile "base" { use "m" }
profile "p" {
    extends "base"
    use "m" {
        patch {
            set "settings.enabled" #false
            collection "devices" {
                replace "z-first" { options { direction "left" } }
            }
        }
    }
}
"#;

    let evaluated =
        evaluate_authoring_profile_v1(&sources(document), AUTHORING_CONFIG_FILE, "p", &[])
            .expect("evaluate named types");
    let render = evaluated.outputs()[0]
        .component_render()
        .expect("component document");
    let root = render.document().root().as_record().expect("root record");
    assert_eq!(root["enabled"].as_bool(), Some(false));
    assert_eq!(root["direction"].as_string(), Some("left"));
    let devices = root["devices"].as_list().expect("device list");
    assert_eq!(devices.len(), 2);
    let first = devices[0].as_record().expect("first device");
    let second = devices[1].as_record().expect("second device");
    assert_eq!(first["key"].as_string(), Some("z-first"));
    assert_eq!(first["enabled"].as_bool(), Some(true));
    assert_eq!(first["direction"].as_string(), Some("left"));
    assert_eq!(second["key"].as_string(), Some("a-second"));
    assert_eq!(second["direction"].as_string(), Some("left"));
}

#[test]
fn legacy_type_spellings_remain_accepted() {
    let document = r#"config target="~" default-profile="p"
module "m" {
    description "legacy"
    inputs {
        input "mode" type="enum" default="left" { values "left" "right" }
        input "names" type="list" item-type="string" { default "one" "two" }
        input "settings" type="record" {
            fields { field "enabled" type="bool" required=#true }
            default { enabled #true }
        }
        input "documents" type="collection" item-type="kdl-document" {
            defaults { item "one" { value "kept" } }
        }
        input "maybe" type="string" optional=#true
    }
    outputs {
        render "out" format="text" {
            @line (ref)"mode"
            @line (ref)"settings.enabled"
        }
    }
}
profile "p" { use "m" }
"#;
    let evaluated =
        evaluate_authoring_profile_v1(&sources(document), AUTHORING_CONFIG_FILE, "p", &[])
            .expect("evaluate legacy spellings");
    assert_eq!(evaluated.outputs()[0].bytes(), Some(&b"left\ntrue\n"[..]));
}

#[test]
fn named_enum_and_record_items_work_in_lists_and_generic_collections() {
    let document = r#"config target="~" default-profile="p"
module "m" {
    description "generic named items"
    types {
        enum "direction" { values "left" "right" }
        record "option" {
            fields { field "direction" type="direction" required=#true }
        }
    }
    inputs {
        input "directions" type="list<direction>" { default "right" "left" }
        input "presets" type="collection<direction>" {
            defaults {
                item "z-first" "left"
                item "a-second" "right"
            }
        }
        input "options" type="list<option>" {
            defaults {
                item { direction "left" }
                item { direction "right" }
            }
        }
    }
    outputs {
        render "out" format="test-format" component-renderer="test-renderer" {
            directions {
                @for-each "direction" in="directions" { - (ref)"direction" }
            }
            presets {
                @for-each "preset" in="presets" {
                    - { key (ref)"preset.key"; value (ref)"preset" }
                }
            }
            options {
                @for-each "option" in="options" { - (ref)"option.direction" }
            }
        }
    }
}
profile "p" { use "m" }
"#;
    let evaluated =
        evaluate_authoring_profile_v1(&sources(document), AUTHORING_CONFIG_FILE, "p", &[])
            .expect("evaluate generic named items");
    let render = evaluated.outputs()[0]
        .component_render()
        .expect("component document");
    let root = render.document().root().as_record().expect("root record");
    let strings = |name: &str| {
        root[name]
            .as_list()
            .expect("list")
            .iter()
            .map(|value| value.as_string().expect("string"))
            .collect::<Vec<_>>()
    };
    assert_eq!(strings("directions"), ["right", "left"]);
    assert_eq!(strings("options"), ["left", "right"]);
    let presets = root["presets"].as_list().expect("preset list");
    assert_eq!(
        presets[0].as_record().unwrap()["key"].as_string(),
        Some("z-first")
    );
    assert_eq!(
        presets[1].as_record().unwrap()["key"].as_string(),
        Some("a-second")
    );
}

#[test]
fn explicit_empty_aggregate_constructors_override_defaults() {
    let document = r#"config target="~" default-profile="p"
module "m" {
    description "empty aggregates"
    types {
        record "settings" {
            fields { field "label" type="string" }
        }
    }
    inputs {
        input "names" type="list<string>" { default "one" }
        input "settings" type="settings" { default { label "old" } }
        input "items" type="collection<string>" {
            defaults { item "one" "old" }
        }
    }
}
profile "p" {
    use "m" {
        with {
            (list)names
            (record)settings {}
            (collection)items {}
        }
    }
}
"#;
    let source_set = sources(document);
    let vars = resolve_authoring_vars_v1(&source_set, AUTHORING_CONFIG_FILE, "p", &[])
        .expect("resolve explicit empty values");
    let value = |name: &str| {
        vars.iter()
            .find(|var| var.name() == name)
            .expect("resolved variable")
            .rendered_value()
    };
    assert_eq!(value("names"), "[]");
    assert_eq!(value("settings"), "{label=#null}");
    assert_eq!(value("items"), "collection[]");
}

#[test]
fn named_type_diagnostics_cover_unknown_cycles_duplicates_collisions_and_depth() {
    let cases = [
        (
            r#"types {
                record "r" { fields { field "x" type="missing" } }
            }
            inputs { input "x" type="r" }"#,
            "error[MALM2007]: unknown module-scoped type `missing`",
        ),
        (
            r#"types {
                record "a" { fields { field "b" type="b" } }
                record "b" { fields { field "a" type="a" } }
            }
            inputs { input "x" type="a" }"#,
            "error[MALM2008]: type declaration cycle:",
        ),
        (
            r#"types {
                enum "x" { values "a" }
                enum "x" { values "b" }
            }"#,
            "error[MALM1004]: duplicate type declaration `x`",
        ),
        (
            r#"types {
                enum "string" { values "a" }
            }"#,
            "error[MALM1004]: type declaration `string` collides with a built-in type",
        ),
    ];
    for (body, expected) in cases {
        let document = format!(
            "config target=\"~\" default-profile=\"p\"\nmodule \"m\" {{\n description \"d\"\n {body}\n}}\nprofile \"p\" {{ use \"m\" }}\n"
        );
        let report = report(&document);
        assert!(report.contains(expected), "missing {expected:?}:\n{report}");
    }

    let mut body = String::from("types {\n");
    for index in 0..35 {
        body.push_str(&format!(
            "record \"r{index}\" {{ fields {{ field \"next\" type=\"r{}\" required=#true }} }}\n",
            index + 1
        ));
    }
    body.push_str("record \"r35\" { fields { field \"done\" type=\"bool\" required=#true } }\n}\ninputs { input \"x\" type=\"r0\" }\n");
    let document = format!(
        "config target=\"~\" default-profile=\"p\"\nmodule \"m\" {{\n description \"d\"\n {body}\n}}\nprofile \"p\" {{ use \"m\" }}\n"
    );
    assert!(
        report(&document).contains("error[MALM2009]"),
        "deep named type graph was not rejected"
    );

    let mut body = String::from("types {\n");
    body.push_str("record \"r35\" { fields { field \"done\" type=\"bool\" required=#true } }\n");
    for index in (0..35).rev() {
        body.push_str(&format!(
            "record \"r{index}\" {{ fields {{ field \"next\" type=\"r{}\" required=#true }} }}\n",
            index + 1
        ));
    }
    body.push_str("}\ninputs { input \"x\" type=\"r0\" }\n");
    let document = format!(
        "config target=\"~\" default-profile=\"p\"\nmodule \"m\" {{\n description \"d\"\n {body}\n}}\nprofile \"p\" {{ use \"m\" }}\n"
    );
    assert!(
        report(&document).contains("error[MALM2009]"),
        "leaf-first deep named type graph bypassed the cache depth check"
    );
}

#[test]
fn invalid_enum_defaults_overrides_and_duplicate_type_modifiers_are_rejected() {
    let bad_default = r#"config target="~" default-profile="p"
module "m" {
    description "d"
    types {
        enum "direction" { values "left" "right" }
        record "options" {
            fields { field "enabled" type="bool" default="yes" }
        }
    }
    inputs { input "direction" type="direction" default="up" }
}
profile "p" { use "m" }
"#;
    let default_report = report(bad_default);
    assert!(
        default_report.contains("field `enabled` default: expected bool"),
        "{default_report}"
    );

    let bad_override = r#"config target="~" default-profile="p"
module "m" {
    description "d"
    types { enum "direction" { values "left" "right" } }
    inputs { input "direction" type="direction" default="left" }
}
profile "p" { use "m" { with { direction "up" } } }
"#;
    let override_report = report(bad_override);
    assert!(
        override_report.contains("enum value `up` is not allowed"),
        "{override_report}"
    );

    for input in [
        r#"input "x" type="string?" optional=#true"#,
        r#"input "x" type="list<string>" item-type="string""#,
    ] {
        let document = format!(
            "config target=\"~\" default-profile=\"p\"\nmodule \"m\" {{\n description \"d\"\n inputs {{ {input} }}\n}}\nprofile \"p\" {{ use \"m\" }}\n"
        );
        assert!(report(&document).contains("error[MALM1004]"));
    }
}

#[test]
fn branching_and_inline_type_nesting_limits_are_enforced() {
    let mut body = String::from("types {\n");
    body.push_str("record \"t13\" { fields { field \"value\" type=\"bool\" } }\n");
    for index in (0..13).rev() {
        body.push_str(&format!(
            "record \"t{index}\" {{ fields {{ field \"left\" type=\"t{}\"; field \"right\" type=\"t{}\" }} }}\n",
            index + 1,
            index + 1
        ));
    }
    body.push_str("}\ninputs { input \"x\" type=\"t0\" }\n");
    let document = format!(
        "config target=\"~\" default-profile=\"p\"\nmodule \"m\" {{\n description \"d\"\n {body}\n}}\nprofile \"p\" {{ use \"m\" }}\n"
    );
    let complexity_report = report(&document);
    assert!(
        complexity_report.contains("error[MALM2010]")
            && complexity_report.contains("maximum of 4096 type nodes"),
        "branching type graph was not bounded:\n{complexity_report}"
    );

    let mut body = String::from("types {\n");
    body.push_str("record \"base10\" { fields { field \"value\" type=\"bool\" } }\n");
    for index in (0..10).rev() {
        body.push_str(&format!(
            "record \"base{index}\" {{ fields {{ field \"left\" type=\"base{}\"; field \"right\" type=\"base{}\" }} }}\n",
            index + 1,
            index + 1
        ));
    }
    for index in 0..40 {
        body.push_str(&format!(
            "record \"wrapper{index}\" {{ fields {{ field \"value\" type=\"base0\" }} }}\n"
        ));
    }
    body.push_str("}\n");
    let document = format!(
        "config target=\"~\" default-profile=\"p\"\nmodule \"m\" {{\n description \"d\"\n {body}\n}}\nprofile \"p\" {{ use \"m\" }}\n"
    );
    let module_complexity_report = report(&document);
    assert!(
        module_complexity_report.contains("error[MALM2010]")
            && module_complexity_report.contains("maximum of 65536 retained and cached type nodes"),
        "module-wide expanded type cache was not bounded:\n{module_complexity_report}"
    );

    let mut body = String::from("types {\n");
    body.push_str("record \"base10\" { fields { field \"value\" type=\"bool\" } }\n");
    for index in (0..10).rev() {
        body.push_str(&format!(
            "record \"base{index}\" {{ fields {{ field \"left\" type=\"base{}\"; field \"right\" type=\"base{}\" }} }}\n",
            index + 1,
            index + 1
        ));
    }
    body.push_str("}\ninputs {\n");
    for index in 0..40 {
        body.push_str(&format!("input \"value{index}\" type=\"base0?\"\n"));
    }
    body.push_str("}\n");
    let document = format!(
        "config target=\"~\" default-profile=\"p\"\nmodule \"m\" {{\n description \"d\"\n {body}\n}}\nprofile \"p\" {{ use \"m\" }}\n"
    );
    let retained_complexity_report = report(&document);
    assert!(
        retained_complexity_report.contains("error[MALM2010]")
            && retained_complexity_report
                .contains("maximum of 65536 retained and cached type nodes"),
        "repeated input type clones escaped the module budget:\n{retained_complexity_report}"
    );

    let mut declarations = String::from("types {\n");
    for index in 0..=4096 {
        declarations.push_str(&format!("enum \"mode{index}\" {{ values \"one\" }}\n"));
    }
    declarations.push_str("}\n");
    let document = format!(
        "config target=\"~\" default-profile=\"p\"\nmodule \"m\" {{\n description \"d\"\n {declarations}\n}}\nprofile \"p\" {{ use \"m\" }}\n"
    );
    let declaration_report = report(&document);
    assert!(
        declaration_report.contains("more than the maximum of 4096 named types"),
        "named declaration count was not bounded during parsing:\n{declaration_report}"
    );

    let large_value = "x".repeat(256 * 1024 + 1);
    let document = format!(
        "config target=\"~\" default-profile=\"p\"\nmodule \"m\" {{\n description \"d\"\n types {{ enum \"large\" {{\n values \"{large_value}\"\n }} }}\n}}\nprofile \"p\" {{ use \"m\" }}\n"
    );
    let byte_report = report(&document);
    assert!(
        byte_report.contains("maximum of 262144 string bytes"),
        "expanded schema text was not bounded:\n{byte_report}"
    );

    let shared_value = "x".repeat(128 * 1024);
    let mut inputs = String::new();
    for index in 0..40 {
        inputs.push_str(&format!("input \"value{index}\" type=\"shared?\"\n"));
    }
    let document = format!(
        "config target=\"~\" default-profile=\"p\"\nmodule \"m\" {{\n description \"d\"\n types {{ enum \"shared\" {{\n values \"{shared_value}\"\n }} }}\n inputs {{ {inputs} }}\n}}\nprofile \"p\" {{ use \"m\" }}\n"
    );
    let module_byte_report = report(&document);
    let message = "maximum of 4194304 cached and retained string bytes";
    assert!(
        module_byte_report.contains(message),
        "retained schema text escaped the module budget:\n{module_byte_report}"
    );
    assert_eq!(
        module_byte_report.matches(message).count(),
        1,
        "module exhaustion should stop resolving later inputs"
    );

    let mut field = String::from("field \"done\" type=\"bool\"");
    for _ in 0..20 {
        field = format!("field \"next\" type=\"record\" {{ fields {{ {field} }} }}");
    }
    let document = format!(
        "config target=\"~\" default-profile=\"p\"\nmodule \"m\" {{\n description \"d\"\n inputs {{ input \"x\" type=\"record\" {{ fields {{ {field} }} }} }}\n}}\nprofile \"p\" {{ use \"m\" }}\n"
    );
    let depth_report = report(&document);
    assert!(
        depth_report.contains("error[MALM4001]")
            && depth_report.contains("document nesting exceeds the maximum depth"),
        "deep inline record syntax was not bounded before recursive parsing:\n{depth_report}"
    );
}

#[test]
fn field_defaults_and_optional_unset_have_consistent_static_types() {
    let defaulted = r#"config target="~" default-profile="p"
module "m" {
    description "d"
    types {
        record "settings" {
            fields { field "enabled" type="bool" default=#true }
        }
    }
    inputs { input "settings" type="settings" { default {} } }
}
profile "p" { use "m" { patch { unset "settings.enabled" } } }
"#;
    let default_report = report(defaulted);
    assert!(
        default_report.contains("field `settings.enabled` has a default")
            && default_report.contains("cannot make its non-optional value null"),
        "defaulted field was cleared to a runtime null:\n{default_report}"
    );

    let required_optional = r#"config target="~" default-profile="p"
module "m" {
    description "d"
    types {
        record "settings" {
            fields { field "label" type="string?" required=#true }
        }
    }
    inputs { input "settings" type="settings" { default { label "old" } } }
    outputs { render "out" format="text" { @line (ref?)"settings.label" } }
}
profile "p" { use "m" { patch { unset "settings.label" } } }
"#;
    let required_report = report(required_optional);
    assert!(
        required_report.contains("field `settings.label` is required")
            && required_report.contains("`unset` clears only optional fields"),
        "required optional field was cleared:\n{required_report}"
    );
}

#[test]
fn optional_collection_patch_requires_a_base_collection() {
    let document = r#"config target="~" default-profile="p"
module "m" {
    description "d"
    inputs { input "items" type="collection<string>?" }
}
profile "p" {
    use "m" { patch { collection "items" { append "one" "value" } } }
}
"#;
    let report = report(document);
    assert!(
        report.contains("collection patch `m.items` needs a base collection"),
        "optional collection patch was silently discarded:\n{report}"
    );
}

#[test]
fn singular_named_record_list_defaults_and_overlapping_bindings_work() {
    let document = r#"config target="~" default-profile="p"
module "m" {
    description "d"
    types {
        record "payload" {
            fields { field "value" type="string" required=#true }
        }
        record "shadow" {
            fields { field "other" type="string" required=#true }
        }
        enum "mode" { values "one" "two" }
    }
    inputs {
        input "outer" type="list<payload?>" { default { value "longest" } }
        input "inner" type="list<shadow>" {
            defaults { item { other "short" } }
        }
        input "modes" type="list<mode>" { default {} }
    }
    outputs {
        render "out" format="text" {
            @for-each "a.b" in="outer" {
                @for-each "a" in="inner" { @line (ref)"a.b.value" }
            }
        }
    }
}
profile "p" { use "m" }
"#;
    let evaluated =
        evaluate_authoring_profile_v1(&sources(document), AUTHORING_CONFIG_FILE, "p", &[])
            .expect("evaluate singular named record default and dotted bindings");
    assert_eq!(evaluated.outputs()[0].bytes(), Some(&b"longest\n"[..]));
}

#[test]
fn aggregate_field_defaults_and_duplicate_override_properties_are_rejected() {
    let aggregate_default = r#"config target="~" default-profile="p"
module "m" {
    description "d"
    types {
        record "settings" {
            fields { field "names" type="list<string>" default="one" }
        }
    }
    inputs { input "settings" type="settings" }
}
profile "p" { use "m" }
"#;
    let aggregate_report = report(aggregate_default);
    assert!(
        aggregate_report.contains("error[MALM2004]")
            && aggregate_report.contains("aggregate field defaults are not supported"),
        "scalar-to-list promotion leaked into field defaults:\n{aggregate_report}"
    );

    let duplicate_property = r#"config target="~" default-profile="p"
module "m" {
    description "d"
    types {
        record "entry" {
            fields { field "value" type="int" required=#true }
        }
    }
    inputs { input "items" type="collection<entry>" }
}
profile "p" {
    use "m" { with { items { item "one" value=1 value=2 } } }
}
"#;
    let duplicate_report = report(duplicate_property);
    assert!(
        duplicate_report.contains("field `value` is set twice"),
        "duplicate compact override property was silently replaced:\n{duplicate_report}"
    );
}

#[test]
fn enum_list_markers_and_collection_keys_are_unambiguous() {
    let malformed_enum_list = r#"config target="~" default-profile="p"
module "m" {
    description "d"
    types { enum "mode" { values "one" "two" } }
    inputs {
        input "modes" type="list<mode>" { defaults { item {} } }
    }
}
profile "p" { use "m" }
"#;
    let enum_report = report(malformed_enum_list);
    assert!(
        enum_report.contains("expected enum{one, two}, got kdl-document"),
        "record-list syntax masqueraded as an empty named-enum list:\n{enum_report}"
    );

    for body in [
        r#"inputs {
            input "items" type="collection<string>" {
                defaults { item "" "value" }
            }
        }"#,
        r#"inputs { input "items" type="collection<string>" }
        "#,
    ] {
        let profile = if body.contains("defaults") {
            "profile \"p\" { use \"m\" }"
        } else {
            "profile \"p\" { use \"m\" { patch { collection \"items\" { append \"\" \"value\" } } } }"
        };
        let document = format!(
            "config target=\"~\" default-profile=\"p\"\nmodule \"m\" {{ description \"d\"; {body} }}\n{profile}\n"
        );
        let key_report = report(&document);
        assert!(
            key_report.contains("requires a plain, non-empty string key argument"),
            "empty collection key was accepted:\n{key_report}"
        );
    }

    let items = "item {}\n".repeat(4097);
    let oversized_list = format!(
        r#"config target="~" default-profile="p"
module "m" {{
    description "d"
    types {{
        record "entry" {{ fields {{ field "label" type="string?" }} }}
    }}
    inputs {{ input "items" type="list<entry>" }}
}}
profile "p" {{ use "m" {{ with {{ items {{ {items} }} }} }} }}
"#
    );
    let list_report = report(&oversized_list);
    assert!(
        list_report.contains("collection has 4097 items, exceeding the maximum of 4096"),
        "KDL-backed list override escaped the collection limit:\n{list_report}"
    );
}

#[test]
fn types_are_module_scoped_and_extensions_see_base_types() {
    let extension = r#"config target="~" default-profile="p"
module "m" {
    description "d"
    types { enum "mode" { values "one" "two" } }
}
extend-module "m" {
    inputs { input "mode" type="mode" default="one" }
}
profile "p" { use "m" }
"#;
    evaluate_authoring_profile_v1(&sources(extension), AUTHORING_CONFIG_FILE, "p", &[])
        .expect("extension input resolves a base-module type");

    let isolation = r#"config target="~" default-profile="p"
module "one" {
    description "d"
    types { enum "mode" { values "one" "two" } }
}
module "two" {
    description "d"
    inputs { input "mode" type="mode" default="one" }
}
profile "p" { use "two" }
"#;
    let isolation_report = report(isolation);
    assert!(
        isolation_report.contains("unknown module-scoped type `mode`"),
        "named type leaked across module scope:\n{isolation_report}"
    );
}

#[test]
fn unknown_with_annotations_are_diagnosed() {
    let document = r#"config target="~" default-profile="p"
module "m" { description "d" inputs { input "x" type="list<string>" } }
profile "p" { use "m" { with { (mystery)x } } }
"#;
    let report = report(document);
    assert!(
        report.contains("unknown `with` aggregate annotation `(mystery)`"),
        "{report}"
    );
}

fn variant_module() -> &'static str {
    r#"config target="~" default-profile="p"
module "m" {
    description "tagged variants"
    types {
        enum "direction" { values "left" "right" }
        enum "action" { values "press" "release" }
        variant "bind-argument" discriminator="kind" {
            case "none"
            case "value" {
                fields { field "value" type="string" required=#true }
            }
            case "record" {
                fields {
                    field "direction" type="direction?"
                    field "action" type="action?"
                }
            }
        }
    }
    inputs {
        input "argument" type="bind-argument" {
            default { invoke "record" { direction "left" } }
        }
    }
    outputs {
        render "out" format="test-format" component-renderer="test-renderer" {
            kind (ref)"argument.kind"
            direction (ref?)"argument.direction"
            action (ref?)"argument.action"
        }
    }
}
profile "p" { use "m" }
"#
}

#[test]
fn variant_declaration_and_usage_lower_to_record() {
    let evaluated =
        evaluate_authoring_profile_v1(&sources(variant_module()), AUTHORING_CONFIG_FILE, "p", &[])
            .expect("evaluate variant module");
    let render = evaluated.outputs()[0]
        .component_render()
        .expect("component document");
    let root = render.document().root().as_record().expect("root record");
    assert_eq!(root["kind"].as_string(), Some("record"));
    assert_eq!(root["direction"].as_string(), Some("left"));
    // `(ref?)` omits the unset `action` field from the canonical record.
    assert!(root.get("action").is_none());
}

#[test]
fn variant_bare_case_invocation_lowers_to_discriminator_only() {
    let document = r#"config target="~" default-profile="p"
module "m" {
    description "bare case"
    types {
        variant "arg" discriminator="kind" {
            case "none"
            case "value" { fields { field "value" type="string" required=#true } }
        }
    }
    inputs {
        input "x" type="arg" { default { invoke "none" } }
    }
}
profile "p" { use "m" }
"#;
    let vars = resolve_authoring_vars_v1(&sources(document), AUTHORING_CONFIG_FILE, "p", &[])
        .expect("resolve bare case variant");
    let value = vars
        .iter()
        .find(|var| var.name() == "x")
        .expect("resolved x")
        .rendered_value();
    assert_eq!(value, "{kind=none}");
}

#[test]
fn variant_optional_field_lookups_and_compiled_record_path_resolve() {
    let evaluated =
        evaluate_authoring_profile_v1(&sources(variant_module()), AUTHORING_CONFIG_FILE, "p", &[])
            .expect("evaluate");
    let root = evaluated.outputs()[0]
        .component_render()
        .expect("component document")
        .document()
        .root()
        .as_record()
        .expect("root record");
    assert_eq!(root["kind"].as_string(), Some("record"));
    // Fields from inactive cases are absent from the lowered record.
    assert!(root.get("value").is_none());
}

#[test]
fn variant_inside_record_field_invokes_within_default_block() {
    let document = r#"config target="~" default-profile="p"
module "m" {
    description "nested variant"
    types {
        enum "direction" { values "left" "right" }
        variant "arg" discriminator="kind" {
            case "none"
            case "record" { fields { field "direction" type="direction?" } }
        }
        record "wrapper" {
            fields { field "argument" type="arg" required=#true }
        }
    }
    inputs {
        input "settings" type="wrapper" { default { argument { invoke "record" { direction "right" } } } }
    }
    outputs {
        render "out" format="test-format" component-renderer="test-renderer" {
            kind (ref)"settings.argument.kind"
            direction (ref?)"settings.argument.direction"
        }
    }
}
profile "p" { use "m" }
"#;
    let evaluated =
        evaluate_authoring_profile_v1(&sources(document), AUTHORING_CONFIG_FILE, "p", &[])
            .expect("evaluate nested variant");
    let root = evaluated.outputs()[0]
        .component_render()
        .expect("component document")
        .document()
        .root()
        .as_record()
        .expect("root record");
    assert_eq!(root["kind"].as_string(), Some("record"));
    assert_eq!(root["direction"].as_string(), Some("right"));
}

#[test]
fn variant_in_collection_lowering_and_render() {
    let document = r#"config target="~" default-profile="p"
module "m" {
    description "variant collection"
    types {
        enum "direction" { values "left" "right" }
        enum "action" { values "press" "release" }
        variant "arg" discriminator="kind" {
            case "none"
            case "record" {
                fields {
                    field "direction" type="direction?"
                    field "action" type="action?"
                }
            }
        }
    }
    inputs {
        input "bindings" type="collection<arg>" {
            defaults {
                item "focus-left" { invoke "record" { direction "left"; action "press" } }
                item "release" { invoke "record" { action "release" } }
                item "none" { invoke "none" }
            }
        }
    }
    outputs {
        render "out" format="test-format" component-renderer="test-renderer" {
            bindings {
                @for-each "binding" in="bindings" {
                    - (ref)"binding.kind"
                }
            }
        }
    }
}
profile "p" { use "m" }
"#;
    let evaluated =
        evaluate_authoring_profile_v1(&sources(document), AUTHORING_CONFIG_FILE, "p", &[])
            .expect("evaluate variant collection");
    let root = evaluated.outputs()[0]
        .component_render()
        .expect("component document")
        .document()
        .root()
        .as_record()
        .expect("root record");
    let bindings = root["bindings"].as_list().expect("bindings list");
    assert_eq!(bindings.len(), 3);
    assert_eq!(bindings[0].as_string(), Some("record"));
    assert_eq!(bindings[1].as_string(), Some("record"));
    assert_eq!(bindings[2].as_string(), Some("none"));

    let document = r#"config target="~" default-profile="p"
module "m" {
    description "homogeneous variant collection"
    types {
        enum "direction" { values "left" "right" }
        enum "action" { values "press" "release" }
        variant "arg" discriminator="kind" {
            case "record" {
                fields {
                    field "direction" type="direction?"
                    field "action" type="action?"
                }
            }
        }
    }
    inputs {
        input "bindings" type="collection<arg>" {
            defaults {
                item "focus-left" { invoke "record" { direction "left"; action "press" } }
                item "release" { invoke "record" { action "release" } }
            }
        }
    }
    outputs {
        render "out" format="test-format" component-renderer="test-renderer" {
            bindings {
                @for-each "binding" in="bindings" {
                    - {
                        key (ref)"binding.key"
                        kind (ref)"binding.kind"
                        direction (ref?)"binding.direction"
                        action (ref?)"binding.action"
                    }
                }
            }
        }
    }
}
profile "p" { use "m" }
"#;
    let evaluated =
        evaluate_authoring_profile_v1(&sources(document), AUTHORING_CONFIG_FILE, "p", &[])
            .expect("evaluate homogeneous variant collection");
    let root = evaluated.outputs()[0]
        .component_render()
        .expect("component document")
        .document()
        .root()
        .as_record()
        .expect("root record");
    let bindings = root["bindings"].as_list().expect("bindings list");
    assert_eq!(bindings.len(), 2);
    let first = bindings[0].as_record().expect("first binding");
    assert_eq!(first["key"].as_string(), Some("focus-left"));
    assert_eq!(first["kind"].as_string(), Some("record"));
    assert_eq!(first["direction"].as_string(), Some("left"));
    assert_eq!(first["action"].as_string(), Some("press"));
    let second = bindings[1].as_record().expect("second binding");
    assert_eq!(second["kind"].as_string(), Some("record"));
    assert_eq!(second["action"].as_string(), Some("release"));
    // `(ref?)` omits the unset `direction` field.
    assert!(second.get("direction").is_none());
}

#[test]
fn variant_renderer_lowers_record_with_discriminator() {
    let document = r#"config target="~" default-profile="p"
module "m" {
    description "renderer lowering"
    types {
        variant "arg" discriminator="kind" {
            case "value" { fields { field "value" type="string" required=#true } }
        }
    }
    inputs { input "x" type="arg" { default { invoke "value" { value "ok" } } } }
    outputs {
        render "out" format="test-format" component-renderer="test-renderer" {
            data (ref)"x"
        }
    }
}
profile "p" { use "m" }
"#;
    let evaluated =
        evaluate_authoring_profile_v1(&sources(document), AUTHORING_CONFIG_FILE, "p", &[])
            .expect("evaluate renderer lowering");
    let root = evaluated.outputs()[0]
        .component_render()
        .expect("component document")
        .document()
        .root()
        .as_record()
        .expect("root record");
    let record = root["data"].as_record().expect("lowered record");
    assert_eq!(record["kind"].as_string(), Some("value"));
    assert_eq!(record["value"].as_string(), Some("ok"));
}

#[test]
fn variant_profile_overrides_and_patches() {
    let document = r#"config target="~" default-profile="p"
module "m" {
    description "overrides"
    types {
        enum "direction" { values "left" "right" }
        variant "arg" discriminator="kind" {
            case "record" { fields { field "direction" type="direction?" } }
        }
    }
    inputs {
        input "argument" type="arg" { default { invoke "record" { direction "left" } } }
    }
    outputs {
        render "out" format="test-format" component-renderer="test-renderer" {
            kind (ref)"argument.kind"
            direction (ref?)"argument.direction"
        }
    }
}
profile "p" {
    use "m" {
        with { argument { invoke "record" { direction "right" } } }
    }
}
"#;
    let evaluated =
        evaluate_authoring_profile_v1(&sources(document), AUTHORING_CONFIG_FILE, "p", &[])
            .expect("evaluate override");
    let root = evaluated.outputs()[0]
        .component_render()
        .expect("component document")
        .document()
        .root()
        .as_record()
        .expect("root record");
    assert_eq!(root["kind"].as_string(), Some("record"));
    assert_eq!(root["direction"].as_string(), Some("right"));

    let document = r#"config target="~" default-profile="p"
module "m" {
    description "patches"
    types {
        enum "direction" { values "left" "right" }
        variant "arg" discriminator="kind" {
            case "record" {
                fields {
                    field "direction" type="direction?"
                    field "label" type="string?"
                }
            }
        }
    }
    inputs {
        input "argument" type="arg" { default { invoke "record" { direction "left" } } }
    }
    outputs {
        render "out" format="test-format" component-renderer="test-renderer" {
            kind (ref)"argument.kind"
            direction (ref?)"argument.direction"
            label (ref?)"argument.label"
        }
    }
}
profile "p" {
    use "m" {
        patch {
            set "argument.label" "patched"
            set "argument.direction" "right"
        }
    }
}
"#;
    let evaluated =
        evaluate_authoring_profile_v1(&sources(document), AUTHORING_CONFIG_FILE, "p", &[])
            .expect("evaluate patch");
    let root = evaluated.outputs()[0]
        .component_render()
        .expect("component document")
        .document()
        .root()
        .as_record()
        .expect("root record");
    assert_eq!(root["kind"].as_string(), Some("record"));
    assert_eq!(root["direction"].as_string(), Some("right"));
    assert_eq!(root["label"].as_string(), Some("patched"));
}

#[test]
fn variant_unknown_case_missing_invoke_multiple_invokes_and_wrong_field_errors() {
    let unknown_case = r#"config target="~" default-profile="p"
module "m" {
    description "x"
    types { variant "v" discriminator="kind" { case "a"; case "b" } }
    inputs { input "x" type="v" { default { invoke "c" } } }
}
profile "p" { use "m" }
"#;
    let unknown_report = report(unknown_case);
    assert!(
        unknown_report.contains("unknown variant case `c`"),
        "unknown case rejected:\n{unknown_report}"
    );

    let missing_invoke = r#"config target="~" default-profile="p"
module "m" {
    description "x"
    types { variant "v" discriminator="kind" { case "a" } }
    inputs { input "x" type="v" { default { a "stray" } } }
}
profile "p" { use "m" }
"#;
    let missing_report = report(missing_invoke);
    assert!(
        missing_report.contains("variant inputs use `invoke"),
        "missing invoke rejected:\n{missing_report}"
    );

    let multiple_invoke = r#"config target="~" default-profile="p"
module "m" {
    description "x"
    types { variant "v" discriminator="kind" { case "a"; case "b" } }
    inputs { input "x" type="v" { default { invoke "a"; invoke "b" } } }
}
profile "p" { use "m" }
"#;
    let multi_report = report(multiple_invoke);
    assert!(
        multi_report.contains("variant input must invoke exactly one case"),
        "multiple invokes rejected:\n{multi_report}"
    );

    let wrong_field = r#"config target="~" default-profile="p"
module "m" {
    description "x"
    types {
        variant "v" discriminator="kind" {
            case "a" { fields { field "value" type="string" required=#true } }
        }
    }
    inputs { input "x" type="v" { default { invoke "a" { other "value" } } } }
}
profile "p" { use "m" }
"#;
    let wrong_report = report(wrong_field);
    assert!(
        wrong_report.contains("unknown field `other`"),
        "wrong field on case rejected:\n{wrong_report}"
    );
}

#[test]
fn variant_declaration_errors_duplicate_case_discriminator_collision_missing_property() {
    let duplicate = r#"config target="~" default-profile="p"
module "m" {
    description "x"
    types { variant "v" discriminator="kind" { case "a"; case "a" } }
    inputs { input "x" type="v" }
}
profile "p" { use "m" }
"#;
    let dup_report = report(duplicate);
    assert!(
        dup_report.contains("duplicate case `a`"),
        "duplicate case rejected:\n{dup_report}"
    );

    let collision = r#"config target="~" default-profile="p"
module "m" {
    description "x"
    types {
        variant "v" discriminator="kind" {
            case "a" { fields { field "kind" type="string" required=#true } }
        }
    }
    inputs { input "x" type="v" }
}
profile "p" { use "m" }
"#;
    let collision_report = report(collision);
    assert!(
        collision_report.contains("case `a` field `kind` collides with the variant discriminator"),
        "discriminator collision rejected:\n{collision_report}"
    );

    let missing_disc = r#"config target="~" default-profile="p"
module "m" {
    description "x"
    types { variant "v" { case "a" } }
    inputs { input "x" type="v" }
}
profile "p" { use "m" }
"#;
    let disc_report = report(missing_disc);
    assert!(
        disc_report.contains("missing the required property `discriminator=`"),
        "missing discriminator rejected:\n{disc_report}"
    );

    let empty_variant = r#"config target="~" default-profile="p"
module "m" {
    description "x"
    types { variant "v" discriminator="kind" }
    inputs { input "x" type="v" }
}
profile "p" { use "m" }
"#;
    let empty_report = report(empty_variant);
    assert!(
        empty_report.contains("variant declaration must declare at least one case"),
        "empty variant rejected:\n{empty_report}"
    );
}

#[test]
fn variant_dotted_lookup_descends_through_case_fields() {
    let document = r#"config target="~" default-profile="p"
module "m" {
    description "recursive lookup"
    types {
        enum "direction" { values "left" "right" }
        variant "outer" discriminator="kind" {
            case "outer-a" {
                fields { field "inner-arg" type="inner" required=#true }
            }
        }
        variant "inner" discriminator="kind" {
            case "inner-a" { fields { field "direction" type="direction?" } }
        }
    }
    inputs {
        input "x" type="outer" {
            default { invoke "outer-a" { inner-arg { invoke "inner-a" { direction "left" } } } }
        }
    }
    outputs {
        render "out" format="test-format" component-renderer="test-renderer" {
            kind (ref)"x.kind"
            inner-kind (ref)"x.inner-arg.kind"
            inner-direction (ref?)"x.inner-arg.direction"
        }
    }
}
profile "p" { use "m" }
"#;
    let evaluated =
        evaluate_authoring_profile_v1(&sources(document), AUTHORING_CONFIG_FILE, "p", &[])
            .expect("evaluate recursive variant");
    let root = evaluated.outputs()[0]
        .component_render()
        .expect("component document")
        .document()
        .root()
        .as_record()
        .expect("root record");
    assert_eq!(root["kind"].as_string(), Some("outer-a"));
    assert_eq!(root["inner-kind"].as_string(), Some("inner-a"));
    assert_eq!(root["inner-direction"].as_string(), Some("left"));
}

#[test]
fn float_range_refinement_accepts_in_range_and_rejects_out_of_range() {
    let document = r#"config target="~" default-profile="p"
module "m" {
    description "opacity"
    types { refine "opacity" base="float" min=0.0 max=1.0 }
    inputs { input "opacity" type="opacity" default=0.5 }
    outputs {
        render "out" format="text" { @line (ref)"opacity" }
    }
}
profile "p" { use "m" }
"#;
    let evaluated =
        evaluate_authoring_profile_v1(&sources(document), AUTHORING_CONFIG_FILE, "p", &[])
            .expect("evaluate in-range opacity");
    assert_eq!(evaluated.outputs()[0].bytes(), Some(&b"0.5\n"[..]));

    let too_high = r#"config target="~" default-profile="p"
module "m" {
    description "opacity"
    types { refine "opacity" base="float" min=0.0 max=1.0 }
    inputs { input "opacity" type="opacity" default=2.0 }
}
profile "p" { use "m" }
"#;
    let too_high_report = report(too_high);
    assert!(
        too_high_report.contains("is above the maximum of 1.0"),
        "max violation not reported:\n{too_high_report}"
    );

    let too_low = r#"config target="~" default-profile="p"
module "m" {
    description "opacity"
    types { refine "opacity" base="float" min=0.0 max=1.0 }
    inputs { input "opacity" type="opacity" default=-0.5 }
}
profile "p" { use "m" }
"#;
    let too_low_report = report(too_low);
    assert!(
        too_low_report.contains("is below the minimum of 0.0"),
        "min violation not reported:\n{too_low_report}"
    );

    // Integer literals are accepted for a float base when exactly representable.
    let int_default = r#"config target="~" default-profile="p"
module "m" {
    description "opacity"
    types { refine "opacity" base="float" min=0.0 max=1.0 }
    inputs { input "opacity" type="opacity" default=1 }
    outputs { render "out" format="text" { @line (ref)"opacity" } }
}
profile "p" { use "m" }
"#;
    let evaluated =
        evaluate_authoring_profile_v1(&sources(int_default), AUTHORING_CONFIG_FILE, "p", &[])
            .expect("evaluate int-coerced opacity");
    assert_eq!(evaluated.outputs()[0].bytes(), Some(&b"1.0\n"[..]));
}

#[test]
fn int_min_refinement_accepts_positive_and_rejects_zero() {
    let document = r#"config target="~" default-profile="p"
module "m" {
    description "positive"
    types { refine "positive-pixels" base="int" min=1 }
    inputs { input "size" type="positive-pixels" default=8 }
    outputs {
        render "out" format="text" { @line (ref)"size" }
    }
}
profile "p" { use "m" }
"#;
    let evaluated =
        evaluate_authoring_profile_v1(&sources(document), AUTHORING_CONFIG_FILE, "p", &[])
            .expect("evaluate positive");
    assert_eq!(evaluated.outputs()[0].bytes(), Some(&b"8\n"[..]));

    let zero = r#"config target="~" default-profile="p"
module "m" {
    description "positive"
    types { refine "positive-pixels" base="int" min=1 }
    inputs { input "size" type="positive-pixels" default=0 }
}
profile "p" { use "m" }
"#;
    let zero_report = report(zero);
    assert!(
        zero_report.contains("is below the minimum of 1"),
        "min violation not reported:\n{zero_report}"
    );
}

#[test]
fn uint_refinement_rejects_negative_values() {
    let document = r#"config target="~" default-profile="p"
module "m" {
    description "uint"
    types { refine "uint" base="int" min=0 }
    inputs { input "count" type="uint" default=5 }
    outputs { render "out" format="text" { @line (ref)"count" } }
}
profile "p" { use "m" }
"#;
    let evaluated =
        evaluate_authoring_profile_v1(&sources(document), AUTHORING_CONFIG_FILE, "p", &[])
            .expect("evaluate uint");
    assert_eq!(evaluated.outputs()[0].bytes(), Some(&b"5\n"[..]));

    let negative = r#"config target="~" default-profile="p"
module "m" {
    description "uint"
    types { refine "uint" base="int" min=0 }
    inputs { input "count" type="uint" default=-1 }
}
profile "p" { use "m" }
"#;
    let negative_report = report(negative);
    assert!(
        negative_report.contains("is below the minimum of 0"),
        "min violation not reported:\n{negative_report}"
    );
}

#[test]
fn string_identifier_format_validates_lowercase_pattern() {
    let document = r#"config target="~" default-profile="p"
module "m" {
    description "identifier"
    types { refine "theme-id" base="string" format="identifier" }
    inputs { input "theme" type="theme-id" default="astral-light" }
    outputs { render "out" format="text" { @line (ref)"theme" } }
}
profile "p" { use "m" }
"#;
    let evaluated =
        evaluate_authoring_profile_v1(&sources(document), AUTHORING_CONFIG_FILE, "p", &[])
            .expect("evaluate identifier");
    assert_eq!(evaluated.outputs()[0].bytes(), Some(&b"astral-light\n"[..]));

    for bad in [
        "Astral",
        "with_underscore",
        "1oops",
        "",
        "has space",
        "café",
    ] {
        let document = format!(
            r#"config target="~" default-profile="p"
module "m" {{
    description "identifier"
    types {{ refine "theme-id" base="string" format="identifier" }}
    inputs {{ input "theme" type="theme-id" default="{bad}" }}
}}
profile "p" {{ use "m" }}
"#
        );
        let report = report(&document);
        assert!(
            report.contains("format `identifier` rejected"),
            "identifier `{bad}` should be rejected:\n{report}"
        );
    }
}

#[test]
fn string_srgb_color_format_validates_hex_pattern() {
    let document = r##"config target="~" default-profile="p"
module "m" {
    description "srgb"
    types { refine "srgb-color" base="string" format="srgb-color" }
    inputs { input "accent" type="srgb-color" default="#1e1e2e" }
    outputs { render "out" format="text" { @line (ref)"accent" } }
}
profile "p" { use "m" }
"##;
    let evaluated =
        evaluate_authoring_profile_v1(&sources(document), AUTHORING_CONFIG_FILE, "p", &[])
            .expect("evaluate srgb 6-digit");
    assert_eq!(evaluated.outputs()[0].bytes(), Some(&b"#1e1e2e\n"[..]));

    let alpha = r##"config target="~" default-profile="p"
module "m" {
    description "srgb"
    types { refine "srgb-color" base="string" format="srgb-color" }
    inputs { input "accent" type="srgb-color" default="#1e1e2eff" }
    outputs { render "out" format="text" { @line (ref)"accent" } }
}
profile "p" { use "m" }
"##;
    let evaluated = evaluate_authoring_profile_v1(&sources(alpha), AUTHORING_CONFIG_FILE, "p", &[])
        .expect("evaluate srgb 8-digit");
    assert_eq!(evaluated.outputs()[0].bytes(), Some(&b"#1e1e2eff\n"[..]));

    for bad in ["1e1e2e", "#1e1e2", "#1e1e2eg", "red", "", "#GGGGGG"] {
        let document = format!(
            r##"config target="~" default-profile="p"
module "m" {{
    description "srgb"
    types {{ refine "srgb-color" base="string" format="srgb-color" }}
    inputs {{ input "accent" type="srgb-color" default="{bad}" }}
}}
profile "p" {{ use "m" }}
"##
        );
        let report = report(&document);
        assert!(
            report.contains("format `srgb-color` rejected"),
            "color `{bad}` should be rejected:\n{report}"
        );
    }
}

#[test]
fn string_shell_command_format_requires_non_empty() {
    let document = r#"config target="~" default-profile="p"
module "m" {
    description "shell"
    types { refine "shell-command" base="string" format="shell-command" }
    inputs { input "command" type="shell-command" default="echo hello" }
    outputs { render "out" format="text" { @line (ref)"command" } }
}
profile "p" { use "m" }
"#;
    let evaluated =
        evaluate_authoring_profile_v1(&sources(document), AUTHORING_CONFIG_FILE, "p", &[])
            .expect("evaluate shell-command");
    assert_eq!(evaluated.outputs()[0].bytes(), Some(&b"echo hello\n"[..]));

    let empty = r#"config target="~" default-profile="p"
module "m" {
    description "shell"
    types { refine "shell-command" base="string" format="shell-command" }
    inputs { input "command" type="shell-command" default="" }
}
profile "p" { use "m" }
"#;
    let empty_report = report(empty);
    assert!(
        empty_report.contains("shell-command must not be empty"),
        "empty shell-command rejected:\n{empty_report}"
    );
}

#[test]
fn string_target_path_format_rejects_absolute_and_escaping_paths() {
    let document = r#"config target="~" default-profile="p"
module "m" {
    description "target-path"
    types { refine "target-path" base="string" format="target-path" }
    inputs { input "dest" type="target-path" default="malm/out.txt" }
    outputs { render "out" format="text" { @line (ref)"dest" } }
}
profile "p" { use "m" }
"#;
    let evaluated =
        evaluate_authoring_profile_v1(&sources(document), AUTHORING_CONFIG_FILE, "p", &[])
            .expect("evaluate target-path");
    assert_eq!(evaluated.outputs()[0].bytes(), Some(&b"malm/out.txt\n"[..]));

    for bad in ["/abs/path", "../escape", "./local", "a//b", ""] {
        let document = format!(
            r#"config target="~" default-profile="p"
module "m" {{
    description "target-path"
    types {{ refine "target-path" base="string" format="target-path" }}
    inputs {{ input "dest" type="target-path" default="{bad}" }}
}}
profile "p" {{ use "m" }}
"#
        );
        let report = report(&document);
        assert!(
            report.contains("format `target-path` rejected"),
            "target-path `{bad}` should be rejected:\n{report}"
        );
    }
}

#[test]
fn string_mime_type_format_uses_rfc_6838_restricted_names() {
    for valid in [
        "text/plain",
        "application/xhtml+xml",
        "inode/directory",
        "x-scheme-handler/http",
        "application/vnd.example_widget+json",
        "Text/Plain",
    ] {
        let document = format!(
            r#"config target="~" default-profile="p"
module "m" {{
    description "MIME type"
    types {{ refine "mime-type" base="string" format="mime-type" }}
    inputs {{ input "mime" type="mime-type" default="{valid}" }}
    outputs {{ render "out" format="text" {{ @line (ref)"mime" }} }}
}}
profile "p" {{ use "m" }}
"#
        );
        let evaluated =
            evaluate_authoring_profile_v1(&sources(&document), AUTHORING_CONFIG_FILE, "p", &[])
                .expect("evaluate MIME type");
        assert_eq!(
            evaluated.outputs()[0].bytes(),
            Some(format!("{valid}\n").as_bytes())
        );
    }

    let too_long_subtype = format!("text/{}", "a".repeat(128));
    for bad in [
        "text",
        "/plain",
        "text/",
        "text/plain/extra",
        "text/*",
        "text/pl@in",
        "text/café",
        "text/plain;charset=utf-8",
        &too_long_subtype,
    ] {
        let document = format!(
            r#"config target="~" default-profile="p"
module "m" {{
    description "MIME type"
    types {{ refine "mime-type" base="string" format="mime-type" }}
    inputs {{ input "mime" type="mime-type" default="{bad}" }}
}}
profile "p" {{ use "m" }}
"#
        );
        let report = report(&document);
        assert!(
            report.contains("format `mime-type` rejected"),
            "MIME type `{bad}` should be rejected:\n{report}"
        );
    }
}

#[test]
fn string_desktop_file_id_format_requires_an_id_with_desktop_suffix() {
    for valid in [
        "firefox.desktop",
        "org.gnome.Nautilus.desktop",
        "Helix.desktop",
        "vendor-suite_app.desktop",
        "wine-Programs-Example App.desktop",
        "org.example.Éditeur.desktop",
    ] {
        let document = format!(
            r#"config target="~" default-profile="p"
module "m" {{
    description "desktop file ID"
    types {{ refine "desktop-file-id" base="string" format="desktop-file-id" }}
    inputs {{ input "id" type="desktop-file-id" default="{valid}" }}
    outputs {{ render "out" format="text" {{ @line (ref)"id" }} }}
}}
profile "p" {{ use "m" }}
"#
        );
        let evaluated =
            evaluate_authoring_profile_v1(&sources(&document), AUTHORING_CONFIG_FILE, "p", &[])
                .expect("evaluate desktop-file ID");
        assert_eq!(
            evaluated.outputs()[0].bytes(),
            Some(format!("{valid}\n").as_bytes())
        );
    }

    for bad in [
        "",
        ".desktop",
        "firefox",
        "firefox.desktop.backup",
        "applications/firefox.desktop",
        "firefox.desktop/backup.desktop",
        "bad\\t.desktop",
    ] {
        let document = format!(
            r#"config target="~" default-profile="p"
module "m" {{
    description "desktop file ID"
    types {{ refine "desktop-file-id" base="string" format="desktop-file-id" }}
    inputs {{ input "id" type="desktop-file-id" default="{bad}" }}
}}
profile "p" {{ use "m" }}
"#
        );
        let report = report(&document);
        assert!(
            report.contains("format `desktop-file-id` rejected"),
            "desktop-file ID `{bad}` should be rejected:\n{report}"
        );
    }
}

#[test]
fn path_refinement_acts_as_a_named_alias() {
    let document = r#"config target="~" default-profile="p"
module "m" {
    description "path refine"
    types { refine "target-path" base="path" }
    inputs { input "dest" type="target-path" default="~/.config/malm/out" }
    outputs { render "out" format="text" { @line (ref)"dest" } }
}
profile "p" { use "m" }
"#;
    let evaluated =
        evaluate_authoring_profile_v1(&sources(document), AUTHORING_CONFIG_FILE, "p", &[])
            .expect("evaluate path refine");
    assert_eq!(
        evaluated.outputs()[0].bytes(),
        Some(&b"~/.config/malm/out\n"[..])
    );
}

#[test]
fn list_string_refinement_enforces_item_count_bounds() {
    let document = r#"config target="~" default-profile="p"
module "m" {
    description "argv"
    types { refine "argv" base="list<string>" min=1 max=4 }
    inputs { input "argv" type="argv" }
    outputs {
        render "out" format="test-format" component-renderer="test-renderer" {
            argv (ref)"argv"
        }
    }
}
profile "p" {
    use "m" { with { argv "malm" "check" } }
}
"#;
    let evaluated =
        evaluate_authoring_profile_v1(&sources(document), AUTHORING_CONFIG_FILE, "p", &[])
            .expect("evaluate argv");
    let root = evaluated.outputs()[0]
        .component_render()
        .expect("component document")
        .document()
        .root()
        .as_record()
        .expect("root record");
    let argv = root["argv"].as_list().expect("argv list");
    assert_eq!(argv.len(), 2);
    assert_eq!(argv[0].as_string(), Some("malm"));
    assert_eq!(argv[1].as_string(), Some("check"));

    let too_few = r#"config target="~" default-profile="p"
module "m" {
    description "argv"
    types { refine "argv" base="list<string>" min=1 max=4 }
    inputs { input "argv" type="argv" }
}
profile "p" {
    use "m" { with { (list)argv } }
}
"#;
    let too_few_report = report(too_few);
    assert!(
        too_few_report.contains("below the minimum of 1"),
        "min item count violation not reported:\n{too_few_report}"
    );

    let too_many = r#"config target="~" default-profile="p"
module "m" {
    description "argv"
    types { refine "argv" base="list<string>" min=1 max=2 }
    inputs { input "argv" type="argv" }
}
profile "p" {
    use "m" { with { argv "a" "b" "c" } }
}
"#;
    let too_many_report = report(too_many);
    assert!(
        too_many_report.contains("above the maximum of 2"),
        "max item count violation not reported:\n{too_many_report}"
    );
}

#[test]
fn refine_used_in_record_fields_and_collection_items() {
    let document = r#"config target="~" default-profile="p"
module "m" {
    description "refine composites"
    types {
        refine "opacity" base="float" min=0.0 max=1.0
        refine "theme-id" base="string" format="identifier"
        record "theme" {
            fields {
                field "id" type="theme-id" required=#true
                field "opacity" type="opacity" required=#true
            }
        }
    }
    inputs {
        input "current" type="theme" {
            default { id "astral-light"; opacity 0.8 }
        }
        input "themes" type="collection<theme>" {
            defaults {
                item "primary" { id "day"; opacity 1.0 }
                item "fallback" { id "dim"; opacity 0.2 }
            }
        }
    }
    outputs {
        render "out" format="test-format" component-renderer="test-renderer" {
            current-id (ref)"current.id"
            opacity (ref)"current.opacity"
            themes {
                @for-each "theme" in="themes" {
                    - { id (ref)"theme.id"; opacity (ref)"theme.opacity" }
                }
            }
        }
    }
}
profile "p" { use "m" }
"#;
    let evaluated =
        evaluate_authoring_profile_v1(&sources(document), AUTHORING_CONFIG_FILE, "p", &[])
            .expect("evaluate refine composites");
    let root = evaluated.outputs()[0]
        .component_render()
        .expect("component document")
        .document()
        .root()
        .as_record()
        .expect("root record");
    assert_eq!(root["current-id"].as_string(), Some("astral-light"));
    assert!(
        (root["opacity"]
            .as_float()
            .map(|f| f.get())
            .unwrap_or(f64::NAN)
            - 0.8)
            .abs()
            < 1e-9,
        "opacity should be 0.8, got {:?}",
        root["opacity"].as_float().map(|f| f.get())
    );
    let themes = root["themes"].as_list().expect("themes list");
    assert_eq!(themes.len(), 2);
    let first = themes[0].as_record().expect("primary");
    assert_eq!(first["id"].as_string(), Some("day"));
    assert!(
        (first["opacity"]
            .as_float()
            .map(|f| f.get())
            .unwrap_or(f64::NAN)
            - 1.0)
            .abs()
            < 1e-9
    );

    let bad_opacity = r#"config target="~" default-profile="p"
module "m" {
    description "refine composites"
    types {
        refine "opacity" base="float" min=0.0 max=1.0
        record "theme" {
            fields { field "opacity" type="opacity" required=#true }
        }
    }
    inputs {
        input "current" type="theme" { default { opacity 2.0 } }
    }
}
profile "p" { use "m" }
"#;
    let bad_report = report(bad_opacity);
    assert!(
        bad_report.contains("is above the maximum of 1.0"),
        "nested field refine not validated:\n{bad_report}"
    );
}

#[test]
fn refine_accepts_profile_overrides() {
    let document = r#"config target="~" default-profile="p"
module "m" {
    description "override"
    types { refine "opacity" base="float" min=0.0 max=1.0 }
    inputs { input "opacity" type="opacity" default=0.5 }
    outputs { render "out" format="text" { @line (ref)"opacity" } }
}
profile "p" {
    use "m" { with { opacity 0.25 } }
}
"#;
    let evaluated =
        evaluate_authoring_profile_v1(&sources(document), AUTHORING_CONFIG_FILE, "p", &[])
            .expect("evaluate refine override");
    assert_eq!(evaluated.outputs()[0].bytes(), Some(&b"0.25\n"[..]));

    let out_of_range = r#"config target="~" default-profile="p"
module "m" {
    description "override"
    types { refine "opacity" base="float" min=0.0 max=1.0 }
    inputs { input "opacity" type="opacity" default=0.5 }
}
profile "p" {
    use "m" { with { opacity 5.0 } }
}
"#;
    let override_report = report(out_of_range);
    assert!(
        override_report.contains("is above the maximum of 1.0"),
        "out-of-range override not rejected:\n{override_report}"
    );
}

#[test]
fn refine_declaration_property_incompatibilities_are_rejected() {
    let format_on_int = r#"config target="~" default-profile="p"
module "m" {
    description "x"
    types { refine "uint" base="int" min=0 format="identifier" }
    inputs { input "count" type="uint" default=0 }
}
profile "p" { use "m" }
"#;
    let format_on_int_report = report(format_on_int);
    assert!(
        format_on_int_report.contains("refine `format=` is only allowed with a `string` base"),
        "format on int must be rejected:\n{format_on_int_report}"
    );

    let min_on_bool = r#"config target="~" default-profile="p"
module "m" {
    description "x"
    types { refine "flag" base="bool" min=0 }
    inputs { input "flag" type="flag" default=#true }
}
profile "p" { use "m" }
"#;
    let min_on_bool_report = report(min_on_bool);
    assert!(
        min_on_bool_report.contains("not allowed with a `bool` base"),
        "min on bool must be rejected:\n{min_on_bool_report}"
    );

    let missing_base = r#"config target="~" default-profile="p"
module "m" {
    description "x"
    types { refine "uint" min=0 }
    inputs { input "count" type="uint" default=0 }
}
profile "p" { use "m" }
"#;
    let missing_base_report = report(missing_base);
    assert!(
        missing_base_report.contains("missing the required property `base=`"),
        "missing base must be reported:\n{missing_base_report}"
    );

    let unknown_format = r#"config target="~" default-profile="p"
module "m" {
    description "x"
    types { refine "theme" base="string" format="hex-color" }
    inputs { input "theme" type="theme" default="x" }
}
profile "p" { use "m" }
"#;
    let unknown_format_report = report(unknown_format);
    assert!(
        unknown_format_report
            .contains("not one of: desktop-file-id, identifier, mime-type, srgb-color, shell-command, target-path"),
        "unknown format must be reported:\n{unknown_format_report}"
    );

    let unknown_base = r#"config target="~" default-profile="p"
module "m" {
    description "x"
    types { refine "alias-scalar" base="missing-type" }
    inputs { input "v" type="alias-scalar" default=0 }
}
profile "p" { use "m" }
"#;
    let unknown_base_report = report(unknown_base);
    assert!(
        unknown_base_report.contains(
            "refine `base=` must be a scalar (bool, int, float, string, path) or `list<string>`"
        ),
        "unknown base type must be rejected as not a scalar:\n{unknown_base_report}"
    );

    let list_int_base = r#"config target="~" default-profile="p"
module "m" {
    description "x"
    types { refine "argv" base="list<int>" }
    inputs { input "v" type="argv" }
}
profile "p" { use "m" }
"#;
    let list_int_report = report(list_int_base);
    assert!(
        list_int_report.contains("only accepts `list<string>` items"),
        "non-string list base must be rejected:\n{list_int_report}"
    );
}

#[test]
fn refine_renders_base_type_canonical_value_in_component_document() {
    let document = r#"config target="~" default-profile="p"
module "m" {
    description "renderer"
    types {
        refine "opacity" base="float" min=0.0 max=1.0
        refine "theme-id" base="string" format="identifier"
    }
    inputs {
        input "opacity" type="opacity" default=0.75
        input "theme" type="theme-id" default="astral-light"
    }
    outputs {
        render "out" format="test-format" component-renderer="test-renderer" {
            opacity (ref)"opacity"
            theme (ref)"theme"
        }
    }
}
profile "p" { use "m" }
"#;
    let evaluated =
        evaluate_authoring_profile_v1(&sources(document), AUTHORING_CONFIG_FILE, "p", &[])
            .expect("evaluate refine renderer");
    let root = evaluated.outputs()[0]
        .component_render()
        .expect("component document")
        .document()
        .root()
        .as_record()
        .expect("root record");
    assert_eq!(root["opacity"].as_float().map(|f| f.get()), Some(0.75));
    assert_eq!(root["theme"].as_string(), Some("astral-light"));
}

#[test]
fn refine_unit_label_is_documentation_only() {
    let document = r#"config target="~" default-profile="p"
module "m" {
    description "unit"
    types { refine "duration-ms" base="int" unit="ms" min=0 }
    inputs { input "duration" type="duration-ms" default=250 }
    outputs { render "out" format="text" { @line (ref)"duration" } }
}
profile "p" { use "m" }
"#;
    let evaluated =
        evaluate_authoring_profile_v1(&sources(document), AUTHORING_CONFIG_FILE, "p", &[])
            .expect("evaluate duration-ms");
    assert_eq!(evaluated.outputs()[0].bytes(), Some(&b"250\n"[..]));
}

/// Returns a shared nested-record module without a profile declaration.
fn recursive_patch_module() -> &'static str {
    r#"config target="~" default-profile="p"
module "m" {
    description "recursive patches"
    types {
        record "keyboard-settings" {
            fields {
                field "repeat-delay" type="int" required=#true default=250
                field "variant" type="string?"
            }
        }
        record "settings" {
            fields {
                field "keyboard" type="keyboard-settings" required=#true
                field "theme" type="string" required=#true default="dark"
            }
        }
    }
    inputs {
        input "settings" type="settings" {
            default { keyboard { variant "us" } }
        }
        input "devices" type="collection<string>" {
            defaults { item "mouse" "logitech" }
        }
    }
    outputs {
        render "out" format="test-format" component-renderer="test-renderer" {
            repeat-delay (ref)"settings.keyboard.repeat-delay"
            variant (ref?)"settings.keyboard.variant"
            theme (ref)"settings.theme"
            devices {
                @for-each "device" in="devices" {
                    - { key (ref)"device.key"; value (ref)"device" }
                }
            }
        }
    }
}
"#
}

#[test]
fn recursive_set_on_two_level_nested_record_writes_the_leaf() {
    let document = format!(
        "{module}profile \"p\" {{ use \"m\" {{ patch {{ set \"settings.theme\" \"light\" }} }} }}",
        module = recursive_patch_module()
    );
    let evaluated =
        evaluate_authoring_profile_v1(&sources(&document), AUTHORING_CONFIG_FILE, "p", &[])
            .expect("evaluate recursive 2-level set");
    let root = evaluated.outputs()[0]
        .component_render()
        .expect("component document")
        .document()
        .root()
        .as_record()
        .expect("root record");
    assert_eq!(root["theme"].as_string(), Some("light"));
    // Fields not targeted by the patch retain their defaults.
    assert_eq!(root["repeat-delay"].as_integer(), Some(250));
    assert_eq!(root["variant"].as_string(), Some("us"));
}

#[test]
fn recursive_set_on_three_level_nested_record_writes_the_leaf() {
    let document = format!(
        "{module}profile \"p\" {{ use \"m\" {{ patch {{ set \"settings.keyboard.repeat-delay\" 400 }} }} }}",
        module = recursive_patch_module()
    );
    let evaluated =
        evaluate_authoring_profile_v1(&sources(&document), AUTHORING_CONFIG_FILE, "p", &[])
            .expect("evaluate recursive 3-level set");
    let root = evaluated.outputs()[0]
        .component_render()
        .expect("component document")
        .document()
        .root()
        .as_record()
        .expect("root record");
    assert_eq!(root["repeat-delay"].as_integer(), Some(400));
    assert_eq!(root["variant"].as_string(), Some("us"));
    assert_eq!(root["theme"].as_string(), Some("dark"));
}

#[test]
fn recursive_unset_on_a_nested_optional_field_clears_it() {
    let document = format!(
        "{module}profile \"p\" {{ use \"m\" {{ patch {{ unset \"settings.keyboard.variant\" }} }} }}",
        module = recursive_patch_module()
    );
    let evaluated =
        evaluate_authoring_profile_v1(&sources(&document), AUTHORING_CONFIG_FILE, "p", &[])
            .expect("evaluate recursive unset");
    let root = evaluated.outputs()[0]
        .component_render()
        .expect("component document")
        .document()
        .root()
        .as_record()
        .expect("root record");
    // `(ref?)` omits the cleared field from the rendered record.
    assert!(root.get("variant").is_none());
    assert_eq!(root["repeat-delay"].as_integer(), Some(250));
}

#[test]
fn recursive_set_errors_when_an_intermediate_record_is_null() {
    // An unset optional intermediate record cannot receive a nested patch.
    let document = r#"config target="~" default-profile="p"
module "m" {
    description "null intermediate"
    types {
        record "keyboard-settings" {
            fields { field "repeat-delay" type="int" required=#true default=250 }
        }
        record "settings" {
            fields { field "keyboard" type="keyboard-settings?" }
        }
    }
    inputs { input "settings" type="settings" { default {} } }
    outputs { render "out" format="text" { @line (ref)"settings.keyboard.repeat-delay" } }
}
profile "p" { use "m" { patch { set "settings.keyboard.repeat-delay" 400 } } }
"#;
    let report = report(document);
    assert!(
        report.contains("`set \"settings.keyboard.repeat-delay\"` needs a base record")
            && report.contains("intermediate field `keyboard` on path `settings` is null"),
        "recursive set through a null intermediate record was not surfaced:\n{report}"
    );
}

#[test]
fn recursive_set_errors_when_an_intermediate_field_is_unknown() {
    let document = format!(
        "{module}profile \"p\" {{ use \"m\" {{ patch {{ set \"settings.keyboard.unknown-field\" 1 }} }} }}",
        module = recursive_patch_module()
    );
    let report = report(&document);
    assert!(
        report.contains("record `settings.keyboard` has no field `unknown-field`"),
        "recursive set with an unknown intermediate field was not surfaced:\n{report}"
    );
}

#[test]
fn recursive_set_errors_when_an_intermediate_field_is_not_a_record() {
    let document = format!(
        "{module}profile \"p\" {{ use \"m\" {{ patch {{ set \"settings.theme.foo\" 1 }} }} }}",
        module = recursive_patch_module()
    );
    let report = report(&document);
    assert!(
        report.contains("is not a record; cannot navigate into `theme`"),
        "recursive set through a non-record intermediate was not surfaced:\n{report}"
    );
}

#[test]
fn ordered_patch_stream_applies_set_then_collection_in_authored_order() {
    let document = format!(
        "{module}profile \"p\" {{ use \"m\" {{ patch {{ set \"settings.theme\" \"light\"; collection \"devices\" {{ append \"trackball\" \"kensington\" }} }} }} }}",
        module = recursive_patch_module()
    );
    let evaluated =
        evaluate_authoring_profile_v1(&sources(&document), AUTHORING_CONFIG_FILE, "p", &[])
            .expect("evaluate ordered set-then-collection");
    let root = evaluated.outputs()[0]
        .component_render()
        .expect("component document")
        .document()
        .root()
        .as_record()
        .expect("root record");
    assert_eq!(root["theme"].as_string(), Some("light"));
    let devices = root["devices"].as_list().expect("device list");
    assert_eq!(devices.len(), 2);
    let first = devices[0].as_record().expect("first device");
    let second = devices[1].as_record().expect("second device");
    assert_eq!(first["key"].as_string(), Some("mouse"));
    assert_eq!(first["value"].as_string(), Some("logitech"));
    assert_eq!(second["key"].as_string(), Some("trackball"));
    assert_eq!(second["value"].as_string(), Some("kensington"));
}

#[test]
fn ordered_patch_stream_applies_collection_then_set_in_authored_order() {
    let document = format!(
        "{module}profile \"p\" {{ use \"m\" {{ patch {{ collection \"devices\" {{ append \"trackball\" \"kensington\" }}; set \"settings.theme\" \"light\" }} }} }}",
        module = recursive_patch_module()
    );
    let evaluated =
        evaluate_authoring_profile_v1(&sources(&document), AUTHORING_CONFIG_FILE, "p", &[])
            .expect("evaluate ordered collection-then-set");
    let root = evaluated.outputs()[0]
        .component_render()
        .expect("component document")
        .document()
        .root()
        .as_record()
        .expect("root record");
    assert_eq!(root["theme"].as_string(), Some("light"));
    let devices = root["devices"].as_list().expect("device list");
    assert_eq!(devices.len(), 2);
    let second = devices[1].as_record().expect("second device");
    assert_eq!(second["key"].as_string(), Some("trackball"));
}

#[test]
fn ordered_patch_stream_interleaves_recursive_set_and_collection_patch() {
    let document = format!(
        "{module}profile \"p\" {{
    use \"m\" {{
        patch {{
            set \"settings.keyboard.repeat-delay\" 350
            collection \"devices\" {{ replace \"mouse\" \"logitech-mx\" }}
            set \"settings.keyboard.variant\" \"dvorak\"
        }}
    }}
}}",
        module = recursive_patch_module()
    );
    let evaluated =
        evaluate_authoring_profile_v1(&sources(&document), AUTHORING_CONFIG_FILE, "p", &[])
            .expect("evaluate interleaved recursive set + collection patch");
    let root = evaluated.outputs()[0]
        .component_render()
        .expect("component document")
        .document()
        .root()
        .as_record()
        .expect("root record");
    assert_eq!(root["repeat-delay"].as_integer(), Some(350));
    assert_eq!(root["variant"].as_string(), Some("dvorak"));
    assert_eq!(root["theme"].as_string(), Some("dark"));
    let devices = root["devices"].as_list().expect("device list");
    assert_eq!(devices.len(), 1);
    let device = devices[0].as_record().expect("device");
    assert_eq!(device["key"].as_string(), Some("mouse"));
    assert_eq!(device["value"].as_string(), Some("logitech-mx"));
}

#[test]
fn ordered_patch_stream_preserves_cross_kind_diagnostic_order() {
    let set_then_collection = format!(
        "{module}profile \"p\" {{ use \"m\" {{ patch {{ set \"settings.unknown\" 1; collection \"devices\" {{ remove \"missing\" }} }} }} }}",
        module = recursive_patch_module()
    );
    let first_report = report(&set_then_collection);
    let set_error = first_report
        .find("has no field `unknown`")
        .expect("field-patch diagnostic");
    let collection_error = first_report
        .find("`remove \"missing\"`")
        .expect("collection-patch diagnostic");
    assert!(
        set_error < collection_error,
        "diagnostics were reordered:\n{first_report}"
    );

    let collection_then_set = format!(
        "{module}profile \"p\" {{ use \"m\" {{ patch {{ collection \"devices\" {{ remove \"missing\" }}; set \"settings.unknown\" 1 }} }} }}",
        module = recursive_patch_module()
    );
    let second_report = report(&collection_then_set);
    let collection_error = second_report
        .find("`remove \"missing\"`")
        .expect("collection-patch diagnostic");
    let set_error = second_report
        .find("has no field `unknown`")
        .expect("field-patch diagnostic");
    assert!(
        collection_error < set_error,
        "diagnostics were reordered:\n{second_report}"
    );
}

#[test]
fn recursive_set_renders_in_component_document() {
    let document = format!(
        "{module}profile \"p\" {{
    use \"m\" {{
        patch {{
            set \"settings.keyboard.repeat-delay\" 500
            set \"settings.keyboard.variant\" \"colemak\"
            set \"settings.theme\" \"light\"
        }}
    }}
}}",
        module = recursive_patch_module()
    );
    let evaluated =
        evaluate_authoring_profile_v1(&sources(&document), AUTHORING_CONFIG_FILE, "p", &[])
            .expect("evaluate recursive patch render");
    let root = evaluated.outputs()[0]
        .component_render()
        .expect("component document")
        .document()
        .root()
        .as_record()
        .expect("root record");
    assert_eq!(root["repeat-delay"].as_integer(), Some(500));
    assert_eq!(root["variant"].as_string(), Some("colemak"));
    assert_eq!(root["theme"].as_string(), Some("light"));
}

#[test]
fn recursive_set_path_still_rejects_legacy_one_dot_violations() {
    let document = format!(
        "{module}profile \"p\" {{ use \"m\" {{ patch {{ set \"settings.\" \"light\" }} }} }}",
        module = recursive_patch_module()
    );
    let report = report(&document);
    assert!(
        report.contains("`set` takes a dotted `input.field[.subfield...]` path"),
        "trailing-dot recursive path was silently accepted:\n{report}"
    );
}

#[test]
fn computed_default_renders_from_a_global() {
    let document = r#"config target="~/.config" default-profile="p"
variables {
    global.display.width "1920"
    global.display.height "1080"
}
module "m" {
    description "computed defaults"
    inputs {
        input "mode" type="string" default=(f)"{{global.display.width}}x{{global.display.height}}"
    }
    outputs {
        render "out.txt" format="text" { @line (ref)"mode" }
    }
}
profile "p" { use "m" }
"#;
    let evaluated =
        evaluate_authoring_profile_v1(&sources(document), AUTHORING_CONFIG_FILE, "p", &[])
            .expect("evaluate computed default");
    assert_eq!(evaluated.outputs()[0].bytes().unwrap(), b"1920x1080\n");
}

#[test]
fn computed_default_sees_a_with_override_on_its_dependency() {
    let document = r#"config target="~/.config" default-profile="p"
module "m" {
    description "depends on a with-supplied input"
    inputs {
        input "multiplier" type="int" default=2
        input "scaled" type="int" default=(f)"{{multiplier}}"
    }
    outputs {
        render "out.txt" format="text" { @line (ref)"scaled" }
    }
}
profile "p" {
    use "m" {
        with { multiplier 5 }
    }
}
"#;
    let evaluated =
        evaluate_authoring_profile_v1(&sources(document), AUTHORING_CONFIG_FILE, "p", &[])
            .expect("evaluate computed default with dependency");
    assert_eq!(evaluated.outputs()[0].bytes().unwrap(), b"5\n");
}

#[test]
fn computed_default_references_profile_name() {
    let document = r#"config target="~/.config" default-profile="p"
module "m" {
    description "profile name built-in"
    inputs {
        input "label" type="string" default=(f)"profile {{profile.name}}"
    }
    outputs {
        render "out.txt" format="text" { @line (ref)"label" }
    }
}
profile "p" { use "m" }
"#;
    let evaluated =
        evaluate_authoring_profile_v1(&sources(document), AUTHORING_CONFIG_FILE, "p", &[])
            .expect("evaluate profile.name computed default");
    assert_eq!(evaluated.outputs()[0].bytes().unwrap(), b"profile p\n");
}

#[test]
fn with_override_suppresses_evaluation_of_a_computed_default() {
    let document = r#"config target="~/.config" default-profile="p"
module "m" {
    description "override wins"
    inputs {
        input "label" type="string" default=(f)"{{profile.name}}"
    }
    outputs {
        render "out.txt" format="text" { @line (ref)"label" }
    }
}
profile "p" {
    use "m" {
        with { label "explicit" }
    }
}
"#;
    let evaluated =
        evaluate_authoring_profile_v1(&sources(document), AUTHORING_CONFIG_FILE, "p", &[])
            .expect("evaluate override-wins default");
    assert_eq!(evaluated.outputs()[0].bytes().unwrap(), b"explicit\n");
}

#[test]
fn computed_default_chain_resolves_in_topological_order() {
    let document = r#"config target="~/.config" default-profile="p"
module "m" {
    description "chain"
    inputs {
        input "alpha" type="int" default=7
        input "beta" type="int" default=(f)"{{alpha}}"
        input "gamma" type="int" default=(f)"{{beta}}"
    }
    outputs {
        render "out.txt" format="text" {
            @line (ref)"alpha"
            @line (ref)"beta"
            @line (ref)"gamma"
        }
    }
}
profile "p" { use "m" }
"#;
    let evaluated =
        evaluate_authoring_profile_v1(&sources(document), AUTHORING_CONFIG_FILE, "p", &[])
            .expect("evaluate computed default chain");
    assert_eq!(evaluated.outputs()[0].bytes().unwrap(), b"7\n7\n7\n",);
}

#[test]
fn computed_default_cycle_is_detected_and_reported() {
    let document = r#"config target="~/.config" default-profile="p"
module "m" {
    description "cycle"
    inputs {
        input "alpha" type="string" default=(f)"{{beta}}"
        input "beta" type="string" default=(f)"{{alpha}}"
    }
    outputs {
        render "out.txt" format="text" { @line (ref)"alpha" }
    }
}
profile "p" { use "m" }
"#;
    let report = report(document);
    assert!(
        report.contains("computed default cycle:"),
        "computed default cycle was not surfaced:\n{report}"
    );
    assert!(
        report.contains("alpha") && report.contains("beta"),
        "cycle diagnostic missing members:\n{report}"
    );
}

#[test]
fn computed_default_coerces_template_result_to_int() {
    let document = r#"config target="~/.config" default-profile="p"
module "m" {
    description "int coercion"
    inputs {
        input "pixels" type="int" default=(f)"250"
    }
    outputs {
        render "out.txt" format="text" { @line (ref)"pixels" }
    }
}
profile "p" { use "m" }
"#;
    let evaluated =
        evaluate_authoring_profile_v1(&sources(document), AUTHORING_CONFIG_FILE, "p", &[])
            .expect("evaluate int computed default");
    assert_eq!(evaluated.outputs()[0].bytes().unwrap(), b"250\n");
}

#[test]
fn computed_default_flows_into_component_render_output() {
    let document = r#"config target="~/.config" default-profile="p"
variables {
    global.accent "teal"
}
module "m" {
    description "component render"
    inputs {
        input "color" type="string" default=(f)"{{global.accent}}"
    }
    outputs {
        render "out.kdl" format="kdl" {
            color (ref)"color"
        }
    }
}
profile "p" { use "m" }
"#;
    let evaluated =
        evaluate_authoring_profile_v1(&sources(document), AUTHORING_CONFIG_FILE, "p", &[])
            .expect("evaluate component computed default");
    // KDL leaves bareword-safe strings unquoted.
    assert_eq!(evaluated.outputs()[0].bytes().unwrap(), b"color teal\n",);
}

#[test]
fn computed_default_referencing_unknown_name_errors_at_evaluation_time() {
    let document = r#"config target="~/.config" default-profile="p"
module "m" {
    description "unknown reference"
    inputs {
        input "label" type="string" default=(f)"{{does-not-exist}}"
    }
    outputs {
        render "out.txt" format="text" { @line (ref)"label" }
    }
}
profile "p" { use "m" }
"#;
    let report = report(document);
    assert!(
        report.contains("computed default for input")
            && report.contains("`does-not-exist` is not defined"),
        "unknown reference in computed default was not surfaced:\n{report}"
    );
}

#[test]
fn computed_default_accepts_child_node_spelling() {
    let document = r#"config target="~/.config" default-profile="p"
variables {
    global.greeting "hello"
}
module "m" {
    description "child node form"
    inputs {
        input "label" type="string" {
            default (f)"{{global.greeting}} world"
        }
    }
    outputs {
        render "out.txt" format="text" { @line (ref)"label" }
    }
}
profile "p" { use "m" }
"#;
    let evaluated =
        evaluate_authoring_profile_v1(&sources(document), AUTHORING_CONFIG_FILE, "p", &[])
            .expect("evaluate child-node computed default");
    assert_eq!(evaluated.outputs()[0].bytes().unwrap(), b"hello world\n");
}

#[test]
fn computed_default_rejects_unknown_type_annotations() {
    let document = r#"config target="~/.config" default-profile="p"
module "m" {
    description "annotation validation"
    inputs {
        input "label" type="string" default=(raw)"hello"
    }
    outputs {
        render "out.txt" format="text" { @line (ref)"label" }
    }
}
profile "p" { use "m" }
"#;
    let report = report(document);
    assert!(
        report.contains("accepts only the `(f)` type annotation"),
        "unknown annotation on default= was not surfaced:\n{report}"
    );
}

#[test]
fn computed_default_runs_refine_validation_on_the_rendered_value() {
    let document = r##"config target="~/.config" default-profile="p"
module "m" {
    description "refine + computed default"
    types {
        refine "srgb-color" base="string" format="srgb-color"
    }
    inputs {
        input "accent" type="srgb-color" default=(f)"#1e1e2e"
    }
    outputs {
        render "out.txt" format="text" { @line (ref)"accent" }
    }
}
profile "p" { use "m" }
"##;
    let evaluated =
        evaluate_authoring_profile_v1(&sources(document), AUTHORING_CONFIG_FILE, "p", &[])
            .expect("evaluate refine + computed default");
    assert_eq!(evaluated.outputs()[0].bytes().unwrap(), b"#1e1e2e\n");
}

#[test]
fn computed_default_rejects_aggregate_input_types() {
    let document = r#"config target="~/.config" default-profile="p"
module "m" {
    description "aggregate input"
    inputs {
        input "tags" type="list<string>" default=(f)"hello"
    }
    outputs {
        render "out.txt" format="text" { @line (ref)"tags" }
    }
}
profile "p" { use "m" }
"#;
    let report = report(document);
    assert!(
        report.contains("aggregate inputs declare defaults with their typed child block"),
        "computed default on an aggregate input was not rejected:\n{report}"
    );
}

#[test]
fn computed_default_on_optional_input_is_evaluated_when_no_override_applies() {
    let document = r#"config target="~/.config" default-profile="p"
variables {
    global.accent "teal"
}
module "m" {
    description "optional + computed default"
    inputs {
        input "color" type="string?" default=(f)"{{global.accent}}"
    }
    outputs {
        render "out.txt" format="text" {
            @if-present "color" { @line (ref)"color" }
        }
    }
}
profile "p" { use "m" }
"#;
    let evaluated =
        evaluate_authoring_profile_v1(&sources(document), AUTHORING_CONFIG_FILE, "p", &[])
            .expect("evaluate optional computed default");
    assert_eq!(evaluated.outputs()[0].bytes().unwrap(), b"teal\n");
}

#[test]
fn computed_default_transitive_cycle_is_reported_with_all_members() {
    let document = r#"config target="~/.config" default-profile="p"
module "m" {
    description "transitive cycle"
    inputs {
        input "alpha" type="string" default=(f)"{{delta}}"
        input "beta" type="string" default=(f)"{{alpha}}"
        input "gamma" type="string" default=(f)"{{beta}}"
        input "delta" type="string" default=(f)"{{gamma}}"
    }
    outputs { render "out.txt" format="text" { @line (ref)"alpha" } }
}
profile "p" { use "m" }
"#;
    let report = report(document);
    assert!(
        report.contains("computed default cycle:"),
        "transitive cycle was not surfaced:\n{report}"
    );
    for member in ["alpha", "beta", "gamma", "delta"] {
        assert!(
            report.contains(member),
            "cycle diagnostic missing member `{member}`:\n{report}"
        );
    }
}

#[test]
fn computed_default_with_unparseable_int_is_rejected() {
    let document = r#"config target="~/.config" default-profile="p"
module "m" {
    description "bad int result"
    inputs {
        input "pixels" type="int" default=(f)"not-an-int"
    }
    outputs { render "out.txt" format="text" { @line (ref)"pixels" } }
}
profile "p" { use "m" }
"#;
    let report = report(document);
    assert!(
        report.contains("template produced `not-an-int`, which is not a valid int"),
        "unparseable int computed default was not surfaced:\n{report}"
    );
}

#[test]
fn computed_default_appears_in_resolved_authoring_vars() {
    let document = r#"config target="~/.config" default-profile="p"
variables {
    global.greeting "hello"
}
module "m" {
    description "vars report"
    inputs {
        input "label" type="string" default=(f)"{{global.greeting}}"
    }
    outputs { render "out.txt" format="text" { @line (ref)"label" } }
}
profile "p" { use "m" }
"#;
    let vars = resolve_authoring_vars_v1(&sources(document), AUTHORING_CONFIG_FILE, "p", &[])
        .expect("resolve authoring vars");
    let label = vars
        .iter()
        .find(|var| var.name() == "label")
        .expect("label var present");
    assert_eq!(label.rendered_value(), "hello");
    assert_eq!(label.origin(), "default");
}

#[test]
fn type_alias_resolution_covers_scalar_list_and_optional() {
    let document = r#"config target="~/.config" default-profile="p"
module "m" {
    description "aliases"
    types {
        alias "workspace-selector" type="string"
        alias "int-list" type="list<int>"
        enum "direction" { values "left" "right" }
        alias "direction-or-null" type="direction?"
    }
    inputs {
        input "selector" type="workspace-selector" default="primary"
        input "values" type="int-list"
        input "heading" type="direction-or-null"
    }
    outputs {
        render "out.txt" format="text" {
            @line (ref)"selector"
            @for-each "value" in="values" { @line (ref)"value" }
            @if-present "heading" { @line (ref)"heading" }
        }
    }
}
profile "p" { use "m" { with { values 3 1 2 } } }
"#;
    let evaluated =
        evaluate_authoring_profile_v1(&sources(document), AUTHORING_CONFIG_FILE, "p", &[])
            .expect("evaluate alias module");
    assert_eq!(
        evaluated.outputs()[0].bytes().unwrap(),
        b"primary\n3\n1\n2\n"
    );

    let with_override = r#"config target="~/.config" default-profile="p"
module "m" {
    description "alias override"
    types {
        enum "direction" { values "left" "right" }
        alias "direction-or-null" type="direction?"
    }
    inputs { input "heading" type="direction-or-null" }
    outputs { render "out.txt" format="text" { @line (ref?)"heading" } }
}
profile "p" { use "m" { with { heading "right" } } }
"#;
    let evaluated =
        evaluate_authoring_profile_v1(&sources(with_override), AUTHORING_CONFIG_FILE, "p", &[])
            .expect("evaluate alias override");
    assert_eq!(evaluated.outputs()[0].bytes().unwrap(), b"right\n");

    let bad_default = r#"config target="~" default-profile="p"
module "m" {
    description "alias error"
    types { alias "task-id" type="int" }
    inputs { input "id" type="task-id" default="not-an-int" }
}
profile "p" { use "m" }
"#;
    let bad_report = report(bad_default);
    assert!(
        bad_report.contains("expected int, got string `not-an-int`"),
        "alias coercion error not surfaced:\n{bad_report}"
    );
}

#[test]
fn type_alias_collides_with_reserved_keyword_and_rejects_extra_props() {
    let collision = r#"config target="~" default-profile="p"
module "m" {
    description "x"
    types { alias "map" type="int" }
    inputs { input "x" type="map" }
}
profile "p" { use "m" }
"#;
    assert!(
        report(collision).contains("type declaration `map` collides with a built-in type"),
        "alias name collision with reserved keyword"
    );

    let extra_prop = r#"config target="~" default-profile="p"
module "m" {
    description "x"
    types { alias "extra" type="int" default=0 }
    inputs { input "x" type="extra" }
}
profile "p" { use "m" }
"#;
    let extra_report = report(extra_prop);
    assert!(
        extra_report.contains("`alias` has unknown property `default` (allowed: type)"),
        "alias extra property not rejected:\n{extra_report}"
    );

    let stray_children = r#"config target="~" default-profile="p"
module "m" {
    description "x"
    types { alias "extra" type="int" { values "a" } }
    inputs { input "x" type="extra" }
}
profile "p" { use "m" }
"#;
    let stray_report = report(stray_children);
    assert!(
        stray_report.contains("`alias` has unknown child `values`"),
        "alias stray child node not rejected:\n{stray_report}"
    );
}

#[test]
fn map_with_sorted_keys_and_profile_override_reorders_after_patch() {
    let document = r#"config target="~/.config" default-profile="p"
module "m" {
    description "sorted map defaults"
    inputs {
        input "settings" type="map<int>" {
            defaults {
                item "zeta" 3
                item "alpha" 1
                item "mid" 2
            }
        }
    }
}
profile "p" {
    use "m" {
        patch {
            collection "settings" { append "banana" 5 }
            collection "settings" { replace "alpha" 10 }
        }
    }
}
"#;
    let vars = resolve_authoring_vars_v1(&sources(document), AUTHORING_CONFIG_FILE, "p", &[])
        .expect("resolve map vars");
    let settings = vars
        .iter()
        .find(|var| var.name() == "settings")
        .expect("settings var")
        .rendered_value();
    assert_eq!(settings, "collection[alpha, banana, mid, zeta]");
}

#[test]
fn map_without_a_default_is_empty_never_required() {
    let document = r#"config target="~/.config" default-profile="p"
module "m" {
    description "optional map"
    inputs { input "settings" type="map<int>?" }
}
profile "p" { use "m" }
"#;
    let vars = resolve_authoring_vars_v1(&sources(document), AUTHORING_CONFIG_FILE, "p", &[])
        .expect("resolve optional map");
    let settings = vars
        .iter()
        .find(|var| var.name() == "settings")
        .expect("settings var")
        .rendered_value();
    assert_eq!(settings, "#null");
}

#[test]
fn tuple_with_correct_arity_and_per_position_coercion() {
    let document = r#"config target="~/.config" default-profile="p"
module "m" {
    description "tuple"
    inputs { input "position" type="tuple<string, int>" { default "origin" 0 } }
    outputs {
        render "out" format="test-format" component-renderer="test-renderer" {
            position (ref)"position"
        }
    }
}
profile "p" {
    use "m" { with { position "label" 7 } }
}
"#;
    let evaluated =
        evaluate_authoring_profile_v1(&sources(document), AUTHORING_CONFIG_FILE, "p", &[])
            .expect("evaluate tuple");
    let root = evaluated.outputs()[0]
        .component_render()
        .expect("component document")
        .document()
        .root()
        .as_record()
        .expect("root record");
    let position = root["position"].as_list().expect("position list");
    assert_eq!(position.len(), 2);
    assert_eq!(position[0].as_string(), Some("label"));
    assert_eq!(position[1].as_integer(), Some(7));
}

#[test]
fn tuple_with_wrong_arity_is_rejected() {
    let too_few = r#"config target="~" default-profile="p"
module "m" {
    description "tuple arity"
    inputs { input "position" type="tuple<int, int, int>" }
}
profile "p" { use "m" { with { position 1 2 } } }
"#;
    let too_few_report = report(too_few);
    assert!(
        too_few_report.contains("tuple expected exactly 3 values, got 2"),
        "tuple arity underflow not rejected:\n{too_few_report}"
    );

    let too_many = r#"config target="~" default-profile="p"
module "m" {
    description "tuple arity"
    inputs { input "position" type="tuple<int, int, int>" }
}
profile "p" { use "m" { with { position 1 2 3 4 } } }
"#;
    let too_many_report = report(too_many);
    assert!(
        too_many_report.contains("tuple expected exactly 3 values, got 4"),
        "tuple arity overflow not rejected:\n{too_many_report}"
    );
}

#[test]
fn tuple_with_wrong_element_type_is_rejected() {
    let bad = r#"config target="~" default-profile="p"
module "m" {
    description "tuple element type"
    inputs { input "position" type="tuple<int, int, int>" }
}
profile "p" { use "m" { with { position "x" 2 3 } } }
"#;
    let bad_report = report(bad);
    assert!(
        bad_report.contains("expected int, got string `x`"),
        "tuple per-position type not validated:\n{bad_report}"
    );
}

#[test]
fn empty_and_oversized_tuples_are_rejected() {
    let empty = r#"config target="~" default-profile="p"
module "m" {
    description "x"
    inputs { input "empty" type="tuple<>" }
}
profile "p" { use "m" }
"#;
    let empty_report = report(empty);
    assert!(
        empty_report.contains("invalid type expression `tuple<>`"),
        "empty tuple was not rejected:\n{empty_report}"
    );

    let mut elements = String::new();
    for index in 0..33 {
        if index > 0 {
            elements.push_str(", ");
        }
        elements.push_str("int");
    }
    let document = format!(
        "config target=\"~\" default-profile=\"p\"\nmodule \"m\" {{\n description \"d\"\n inputs {{ input \"x\" type=\"tuple<{elements}>\" }}\n}}\nprofile \"p\" {{ use \"m\" }}\n"
    );
    let oversized_report = report(&document);
    assert!(
        oversized_report.contains("tuple declares more than the maximum of 32 elements"),
        "oversized tuple was not rejected:\n{oversized_report}"
    );
}

#[test]
fn set_with_duplicates_is_deduplicated_and_sorted() {
    let document = r#"config target="~/.config" default-profile="p"
module "m" {
    description "set strings"
    inputs {
        input "tags" type="set<string>" { default "gamma" "alpha" "alpha" "beta" }
    }
    outputs {
        render "out" format="test-format" component-renderer="test-renderer" {
            tags (ref)"tags"
        }
    }
}
profile "p" { use "m" }
"#;
    let evaluated =
        evaluate_authoring_profile_v1(&sources(document), AUTHORING_CONFIG_FILE, "p", &[])
            .expect("evaluate set");
    let root = evaluated.outputs()[0]
        .component_render()
        .expect("component document")
        .document()
        .root()
        .as_record()
        .expect("root record");
    let tags = root["tags"].as_list().expect("tags list");
    assert_eq!(tags.len(), 3);
    assert_eq!(tags[0].as_string(), Some("alpha"));
    assert_eq!(tags[1].as_string(), Some("beta"));
    assert_eq!(tags[2].as_string(), Some("gamma"));
}

#[test]
fn set_of_numbers_sorts_numerically() {
    let document = r#"config target="~/.config" default-profile="p"
module "m" {
    description "set ints"
    inputs { input "xs" type="set<int>" { default 3 1 2 1 } }
}
profile "p" { use "m" }
"#;
    let vars = resolve_authoring_vars_v1(&sources(document), AUTHORING_CONFIG_FILE, "p", &[])
        .expect("resolve set");
    let xs = vars
        .iter()
        .find(|var| var.name() == "xs")
        .expect("xs var")
        .rendered_value();
    assert_eq!(xs, "[1, 2, 3]");
}

#[test]
fn set_with_profile_override_replaces_the_default_and_deduplicates() {
    let document = r#"config target="~/.config" default-profile="p"
module "m" {
    description "set override"
    inputs { input "tags" type="set<string>" { default "alpha" "beta" } }
    outputs {
        render "out" format="test-format" component-renderer="test-renderer" {
            tags (ref)"tags"
        }
    }
}
profile "p" { use "m" { with { tags "gamma" "alpha" "delta" } } }
"#;
    let evaluated =
        evaluate_authoring_profile_v1(&sources(document), AUTHORING_CONFIG_FILE, "p", &[])
            .expect("evaluate set override");
    let root = evaluated.outputs()[0]
        .component_render()
        .expect("component document")
        .document()
        .root()
        .as_record()
        .expect("root record");
    let tags = root["tags"].as_list().expect("tags list");
    assert_eq!(tags.len(), 3);
    assert_eq!(tags[0].as_string(), Some("alpha"));
    assert_eq!(tags[1].as_string(), Some("delta"));
    assert_eq!(tags[2].as_string(), Some("gamma"));
}

#[test]
fn map_tuple_and_set_are_canonicalized_in_component_documents() {
    let document = r#"config target="~/.config" default-profile="p"
module "m" {
    description "canonical reductions"
    inputs {
        input "settings" type="map<int>" {
            defaults {
                item "zeta" 3
                item "alpha" 1
            }
        }
        input "coords" type="tuple<int, int>" { default 4 5 }
        input "tags" type="set<string>" { default "gamma" "alpha" "alpha" "beta" }
    }
    outputs {
        render "out" format="test-format" component-renderer="test-renderer" {
            settings (ref)"settings"
            coords (ref)"coords"
            tags (ref)"tags"
        }
    }
}
profile "p" { use "m" }
"#;
    let evaluated =
        evaluate_authoring_profile_v1(&sources(document), AUTHORING_CONFIG_FILE, "p", &[])
            .expect("evaluate canonical reductions");
    let root = evaluated.outputs()[0]
        .component_render()
        .expect("component document")
        .document()
        .root()
        .as_record()
        .expect("root record");

    let settings = root["settings"]
        .as_collection()
        .expect("settings collection");
    let keys: Vec<&str> = settings
        .keys()
        .map(malm_config::RichKeyV1::as_str)
        .collect();
    assert_eq!(keys, ["alpha", "zeta"]);

    let coords = root["coords"].as_list().expect("coords list");
    assert_eq!(coords.len(), 2);
    assert_eq!(coords[0].as_integer(), Some(4));
    assert_eq!(coords[1].as_integer(), Some(5));

    let tags = root["tags"].as_list().expect("tags list");
    assert_eq!(tags.len(), 3);
    assert_eq!(tags[0].as_string(), Some("alpha"));
    assert_eq!(tags[1].as_string(), Some("beta"));
    assert_eq!(tags[2].as_string(), Some("gamma"));
}

#[test]
fn map_iterates_with_a_synthetic_key_binding_in_for_each_blocks() {
    let document = r#"config target="~/.config" default-profile="p"
module "m" {
    description "map iteration"
    inputs {
        input "settings" type="map<int>" {
            defaults {
                item "zeta" 3
                item "alpha" 1
            }
        }
    }
    outputs {
        render "out" format="test-format" component-renderer="test-renderer" {
            settings {
                @for-each "entry" in="settings" {
                    - { key (ref)"entry.key"; value (ref)"entry" }
                }
            }
        }
    }
}
profile "p" { use "m" }
"#;
    let evaluated =
        evaluate_authoring_profile_v1(&sources(document), AUTHORING_CONFIG_FILE, "p", &[])
            .expect("evaluate map for-each");
    let root = evaluated.outputs()[0]
        .component_render()
        .expect("component document")
        .document()
        .root()
        .as_record()
        .expect("root record");
    let settings = root["settings"].as_list().expect("settings list");
    assert_eq!(settings.len(), 2);
    let first = settings[0].as_record().expect("first entry");
    let second = settings[1].as_record().expect("second entry");
    assert_eq!(first["key"].as_string(), Some("alpha"));
    assert_eq!(first["value"].as_integer(), Some(1));
    assert_eq!(second["key"].as_string(), Some("zeta"));
    assert_eq!(second["value"].as_integer(), Some(3));
}

#[test]
fn computed_default_leaf_declared_after_its_dependent_is_checked_and_evaluated() {
    let document = r#"config target="~" default-profile="p"
module "m" {
    description "computed leaf order"
    inputs {
        input "derived" type="string" default=(f)"{{leaf}}"
        input "leaf" type="string" default=(f)"ready"
    }
    outputs { render "out" format="text" { @line (ref)"derived" } }
}
profile "p" { use "m" }
"#;

    let (errors, checked) = workspace_report(document);
    assert_eq!(
        errors, 0,
        "workspace checker rejected computed leaves:\n{checked}"
    );
    let evaluated =
        evaluate_authoring_profile_v1(&sources(document), AUTHORING_CONFIG_FILE, "p", &[])
            .expect("evaluate dependency-free computed leaf first");
    assert_eq!(evaluated.outputs()[0].bytes(), Some(&b"ready\n"[..]));
}

#[test]
fn computed_default_child_form_rejects_every_extra_shape() {
    for (declaration, expected) in [
        (
            r#"default (f)"value" "ignored""#,
            "expects 1 positional argument(s), found 2",
        ),
        (
            r#"default (f)"value" ignored="property""#,
            "unknown property `ignored`",
        ),
        (
            r#"default (f)"value" { ignored "child" }"#,
            "unknown child `ignored`",
        ),
        (r#"default (f)1"#, "requires a string template"),
    ] {
        let document = format!(
            "config target=\"~\" default-profile=\"p\"\nmodule \"m\" {{ description \"d\"; inputs {{ input \"x\" type=\"string\" {{ {declaration} }} }} }}\nprofile \"p\" {{ use \"m\" }}\n"
        );
        let (errors, checked) = workspace_report(&document);
        assert!(errors > 0, "malformed computed default was accepted");
        assert!(
            checked.contains(expected),
            "missing {expected:?} for {declaration:?}:\n{checked}"
        );
    }
}

#[test]
fn large_computed_default_cycle_is_reported_without_recursive_walking() {
    const COUNT: usize = 2048;
    let mut inputs = String::new();
    for index in 0..COUNT {
        let next = (index + 1) % COUNT;
        inputs.push_str(&format!(
            "input \"v{index}\" type=\"string\" default=(f)\"{{{{v{next}}}}}\"\n"
        ));
    }
    let document = format!(
        "config target=\"~\" default-profile=\"p\"\nmodule \"m\" {{ description \"cycle\"; inputs {{ {inputs} }} }}\nprofile \"p\" {{ use \"m\" }}\n"
    );
    let (errors, checked) = workspace_report(&document);
    assert!(errors > 0);
    assert!(
        checked.contains("computed default cycle:"),
        "large cycle was not diagnosed:\n{checked}"
    );
}

#[test]
fn alias_edges_count_toward_depth_and_nested_optionals_are_rejected_after_resolution() {
    let mut declarations = String::from("alias \"a35\" type=\"string\"\n");
    for index in (0..35).rev() {
        declarations.push_str(&format!("alias \"a{index}\" type=\"a{}\"\n", index + 1));
    }
    let deep = format!(
        "config target=\"~\" default-profile=\"p\"\nmodule \"m\" {{ description \"aliases\"; types {{ {declarations} }}\ninputs {{ input \"x\" type=\"a0\" }} }}\nprofile \"p\" {{ use \"m\" }}\n"
    );
    let (_, deep_report) = workspace_report(&deep);
    assert!(
        deep_report.contains("error[MALM2009]") && deep_report.contains("maximum depth of 32"),
        "alias-only depth bypassed the expansion limit:\n{deep_report}"
    );

    let nested_optional = r#"config target="~" default-profile="p"
module "m" {
    description "optional alias"
    types { alias "maybe" type="string?" }
    inputs { input "x" type="maybe?" }
}
profile "p" { use "m" }
"#;
    let (_, optional_report) = workspace_report(nested_optional);
    assert!(
        optional_report
            .contains("optional type is declared more than once after named type resolution"),
        "optional<optional<T>> survived alias resolution:\n{optional_report}"
    );
}

#[test]
fn long_alias_cycle_stops_at_the_depth_limit_without_overflowing() {
    const COUNT: usize = 512;
    let mut declarations = String::new();
    for index in 0..COUNT {
        declarations.push_str(&format!(
            "alias \"a{index}\" type=\"a{}\"\n",
            (index + 1) % COUNT
        ));
    }
    let document = format!(
        "config target=\"~\" default-profile=\"p\"\nmodule \"m\" {{ description \"cycle\"; types {{ {declarations} }}\ninputs {{ input \"x\" type=\"a0\" }} }}\nprofile \"p\" {{ use \"m\" }}\n"
    );
    let (errors, checked) = workspace_report(&document);
    assert!(errors > 0);
    assert!(
        checked.contains("error[MALM2009]") || checked.contains("error[MALM2008]"),
        "long alias cycle did not terminate with a bounded diagnostic:\n{checked}"
    );
}

#[test]
fn implicit_aggregate_defaults_are_normalized_after_aliases_but_tuples_are_required() {
    let document = r#"config target="~" default-profile="p"
module "m" {
    description "normalized defaults"
    types {
        alias "names" type="list<string>"
        alias "entries" type="collection<int>"
        alias "lookup" type="map<int>"
        alias "tags" type="set<string>"
        alias "point" type="tuple<int, int>"
    }
    inputs {
        input "direct-list" type="list<string>"
        input "alias-list" type="names"
        input "direct-collection" type="collection<int>"
        input "alias-collection" type="entries"
        input "direct-map" type="map<int>"
        input "alias-map" type="lookup"
        input "direct-set" type="set<string>"
        input "alias-set" type="tags"
        input "direct-tuple" type="tuple<int, int>"
        input "alias-tuple" type="point"
    }
}
profile "p" {
    use "m" {
        with {
            direct-tuple 1 2
            alias-tuple 3 4
        }
    }
}
"#;
    let (errors, checked) = workspace_report(document);
    assert_eq!(
        errors, 0,
        "valid tuple overrides were rejected by synthesized defaults:\n{checked}"
    );
    let vars = resolve_authoring_vars_v1(&sources(document), AUTHORING_CONFIG_FILE, "p", &[])
        .expect("resolve normalized defaults");
    let rendered = |name: &str| {
        vars.iter()
            .find(|var| var.name() == name)
            .expect("resolved input")
            .rendered_value()
    };
    for name in ["direct-list", "alias-list", "direct-set", "alias-set"] {
        assert_eq!(rendered(name), "[]", "{name}");
    }
    for name in [
        "direct-collection",
        "alias-collection",
        "direct-map",
        "alias-map",
    ] {
        assert_eq!(rendered(name), "collection[]", "{name}");
    }
    assert_eq!(rendered("direct-tuple"), "[1, 2]");
    assert_eq!(rendered("alias-tuple"), "[3, 4]");

    let missing = document.replace(
        "profile \"p\" {\n    use \"m\" {\n        with {\n            direct-tuple 1 2\n            alias-tuple 3 4\n        }\n    }\n}",
        "profile \"p\" { use \"m\" }",
    );
    let (_, missing_report) = workspace_report(&missing);
    assert!(
        missing_report.contains("missing required input `direct-tuple`")
            && missing_report.contains("missing required input `alias-tuple`"),
        "tuples without defaults were not required:\n{missing_report}"
    );
}

#[test]
fn refinement_integer_bounds_remain_exact_and_invalid_schemas_fail_workspace_checking() {
    let valid = r#"config target="~" default-profile="p"
module "m" {
    description "exact bound"
    types { refine "exact" base="int" min=9007199254740993 max=9007199254740993 }
    inputs { input "value" type="exact" default=9007199254740993 }
}
profile "p" { use "m" }
"#;
    let (errors, checked) = workspace_report(valid);
    assert_eq!(errors, 0, "exact i64 bound rejected:\n{checked}");

    let below = valid.replace("default=9007199254740993", "default=9007199254740992");
    let (_, below_report) = workspace_report(&below);
    assert!(
        below_report.contains("below the minimum of 9007199254740993"),
        "integer bound was rounded through f64:\n{below_report}"
    );

    let above = valid.replace(
        "min=9007199254740993 max=9007199254740993",
        "max=9007199254740992",
    );
    let (_, above_report) = workspace_report(&above);
    assert!(
        above_report.contains("above the maximum of 9007199254740992"),
        "integer maximum was rounded through f64:\n{above_report}"
    );

    for (declaration, expected) in [
        (
            r#"refine "inverted" base="int" min=2 max=1"#,
            "`min=` must not be greater than `max=`",
        ),
        (
            r#"refine "optional" base="int?" min=0"#,
            "`base=` must not be optional",
        ),
        (
            r#"refine "label" base="string" unit="ms""#,
            "`unit=` is only allowed with an `int` or `float` base",
        ),
    ] {
        let document = format!(
            "config target=\"~\" default-profile=\"p\"\nmodule \"m\" {{ description \"invalid refine\"; types {{ {declaration} }} }}\nprofile \"p\" {{ use \"m\" }}\n"
        );
        let (errors, checked) = workspace_report(&document);
        assert!(errors > 0);
        assert!(
            checked.contains(expected),
            "missing {expected:?} for {declaration:?}:\n{checked}"
        );
    }
}

#[test]
fn refined_operational_types_work_across_static_checker_paths() {
    let document = r#"config target="~" default-profile="p"
module "m" {
    description "operational refinements"
    types {
        refine "enabled" base="bool"
        refine "label" base="string" format="identifier"
        refine "args" base="list<string>" min=1
    }
    inputs {
        input "enabled" type="enabled" default=#true
        input "label" type="label" default="ready"
        input "args" type="args"
    }
    outputs {
        render "out.txt" format="text" {
            @if "enabled" { @line (ref)"label" }
            @if "label" is="ready" { @line (f)"{{enabled:bool}}" }
            @if-nonempty "args" {
                @for-each "arg" in="args" { @line (ref)"arg" }
                @line (f)"{{args:toml-array}}"
            }
        }
        render "out.kdl" format="kdl" {
            enabled (ref)"enabled"
            label (ref)"label"
        }
    }
}
profile "p" { use "m" { with { args "one" "two" } } }
"#;
    let (errors, checked) = workspace_report(document);
    assert_eq!(
        errors, 0,
        "refined base behavior diverged in the workspace checker:\n{checked}"
    );
    let evaluated =
        evaluate_authoring_profile_v1(&sources(document), AUTHORING_CONFIG_FILE, "p", &[])
            .expect("evaluate operational refinements");
    assert_eq!(
        evaluated.outputs()[0].bytes(),
        Some(&b"ready\ntrue\none\ntwo\n[\"one\", \"two\"]\n"[..])
    );
    assert_eq!(
        evaluated.outputs()[1].bytes(),
        Some(&b"enabled #true\nlabel ready\n"[..])
    );
}

#[test]
fn variant_patches_use_only_the_active_case_and_revalidate_the_result() {
    let document = r#"config target="~" default-profile="p"
module "m" {
    description "variant patch correctness"
    types {
        variant "choice" discriminator="kind" {
            case "alpha" {
                fields {
                    field "required" type="string" required=#true
                    field "defaulted" type="string" default="kept"
                    field "optional" type="string?"
                }
            }
            case "beta" { fields { field "inactive" type="string?" } }
        }
    }
    inputs {
        input "choice" type="choice" {
            default { invoke "alpha" { required "present" } }
        }
    }
    outputs {
        render "out" format="test-format" component-renderer="test-renderer" {
            @insert-fields "choice"
        }
    }
}
profile "p" { use "m" { patch { set "choice.optional" "patched" } } }
"#;
    let (errors, checked) = workspace_report(document);
    assert_eq!(
        errors, 0,
        "workspace checker rejected active patch:\n{checked}"
    );
    let evaluated =
        evaluate_authoring_profile_v1(&sources(document), AUTHORING_CONFIG_FILE, "p", &[])
            .expect("evaluate active-case patch");
    let root = evaluated.outputs()[0]
        .component_render()
        .unwrap()
        .document()
        .root()
        .as_record()
        .unwrap();
    assert_eq!(root["kind"].as_string(), Some("alpha"));
    assert_eq!(root["required"].as_string(), Some("present"));
    assert_eq!(root["defaulted"].as_string(), Some("kept"));
    assert_eq!(root["optional"].as_string(), Some("patched"));

    for (patch, expected) in [
        (
            r#"set "choice.inactive" "wrong""#,
            "is not in active case `alpha`",
        ),
        (
            r#"set "choice.kind" "beta""#,
            "variant discriminator `choice.kind` cannot be set or unset",
        ),
        (
            r#"unset "choice.kind""#,
            "variant discriminator `choice.kind` cannot be set or unset",
        ),
        (
            r#"unset "choice.required""#,
            "field `choice.required` is required",
        ),
        (
            r#"unset "choice.defaulted""#,
            "field `choice.defaulted` has a default",
        ),
    ] {
        let invalid = document.replace(r#"set "choice.optional" "patched""#, patch);
        let (errors, checked) = workspace_report(&invalid);
        assert!(errors > 0, "invalid variant patch passed checking: {patch}");
        assert!(
            checked.contains(expected),
            "missing {expected:?} for {patch:?}:\n{checked}"
        );
    }
}

#[test]
fn recursive_patch_prefers_the_longest_input_and_exact_dotted_field() {
    let document = r#"config target="~" default-profile="p"
module "m" {
    description "dotted patch names"
    types {
        record "keyboard" {
            fields { field "leaf.name" type="string" required=#true }
        }
    }
    inputs {
        input "settings" type="keyboard" { default { leaf.name "outer" } }
        input "settings.keyboard" type="keyboard" { default { leaf.name "inner" } }
    }
    outputs {
        render "out" format="test-format" component-renderer="test-renderer" {
            value (ref)"settings.keyboard.leaf.name"
        }
    }
}
profile "p" {
    use "m" { patch { set "settings.keyboard.leaf.name" "patched" } }
}
"#;
    let (errors, checked) = workspace_report(document);
    assert_eq!(errors, 0, "dotted patch failed checking:\n{checked}");
    let evaluated =
        evaluate_authoring_profile_v1(&sources(document), AUTHORING_CONFIG_FILE, "p", &[])
            .expect("evaluate dotted patch precedence");
    let root = evaluated.outputs()[0]
        .component_render()
        .unwrap()
        .document()
        .root()
        .as_record()
        .unwrap();
    assert_eq!(root["value"].as_string(), Some("patched"));
}

#[test]
fn profile_layers_apply_parent_patch_before_child_whole_input_write() {
    let document = r#"config target="~" default-profile="child"
module "m" {
    description "layered operations"
    types {
        record "settings" {
            fields { field "theme" type="string" required=#true }
        }
    }
    inputs { input "settings" type="settings" { default { theme "default" } } }
    outputs { render "out" format="text" { @line (ref)"settings.theme" } }
}
profile "parent" {
    use "m" { patch { set "settings.theme" "parent-patch" } }
}
profile "child" {
    extends "parent"
    use "m" { with { settings { theme "child-with" } } }
}
"#;
    let (errors, checked) = workspace_report(document);
    assert_eq!(errors, 0, "layered profile failed checking:\n{checked}");
    let evaluated =
        evaluate_authoring_profile_v1(&sources(document), AUTHORING_CONFIG_FILE, "child", &[])
            .expect("evaluate layered operations");
    assert_eq!(evaluated.outputs()[0].bytes(), Some(&b"child-with\n"[..]));
}

#[test]
fn lowered_aggregate_shapes_pass_field_and_document_insertion_checks() {
    let document = r#"config target="~" default-profile="p"
module "m" {
    description "lowered aggregate checks"
    types {
        variant "choice" discriminator="kind" {
            case "value" { fields { field "payload" type="string" required=#true } }
        }
    }
    inputs {
        input "choice" type="choice" { default { invoke "value" { payload "ok" } } }
        input "coords" type="tuple<int, int>" { default 4 5 }
        input "tags" type="set<string>" { default "b" "a" }
        input "settings" type="map<int>" { defaults { item "z" 2; item "a" 1 } }
        input "snippets" type="map<kdl-document>" {
            defaults { item "one" { inserted "yes" } }
        }
    }
    outputs {
        render "component" format="test-format" component-renderer="test-renderer" {
            @insert-fields "choice"
            coords (ref)"coords"
            tags (ref)"tags"
            settings (ref)"settings"
            @insert-documents "snippets"
        }
        render "raw.kdl" format="kdl" { @insert-documents "snippets" }
    }
}
profile "p" { use "m" }
"#;
    let (errors, checked) = workspace_report(document);
    assert_eq!(errors, 0, "lowered aggregates failed checking:\n{checked}");
    let evaluated =
        evaluate_authoring_profile_v1(&sources(document), AUTHORING_CONFIG_FILE, "p", &[])
            .expect("evaluate lowered aggregates");
    let root = evaluated.outputs()[0]
        .component_render()
        .unwrap()
        .document()
        .root()
        .as_record()
        .unwrap();
    assert_eq!(root["kind"].as_string(), Some("value"));
    assert_eq!(root["payload"].as_string(), Some("ok"));
    assert_eq!(root["coords"].as_list().unwrap().len(), 2);
    assert_eq!(root["tags"].as_list().unwrap().len(), 2);
    assert_eq!(root["settings"].as_collection().unwrap().len(), 2);
    assert_eq!(root["inserted"].as_string(), Some("yes"));
    assert!(
        std::str::from_utf8(evaluated.outputs()[1].bytes().unwrap())
            .unwrap()
            .contains("inserted yes")
    );
}

#[test]
fn dotted_lookup_supports_map_keys_tuple_indices_and_exact_inputs() {
    let document = r#"config target="~" default-profile="p"
module "m" {
    description "aggregate lookup"
    inputs {
        input "lookup" type="map<string>" {
            defaults { item "beta" "map-beta"; item "dotted.key" "map-dotted" }
        }
        input "lookup.beta" type="string" default="exact-input"
        input "pair" type="tuple<string, int>" { default "first" 2 }
    }
    outputs {
        render "out" format="test-format" component-renderer="test-renderer" {
            exact (ref)"lookup.beta"
            dotted (ref?)"lookup.dotted.key"
            first (ref)"pair.0"
            second (ref)"pair.1"
            @if-present "lookup.missing" { missing "present" }
            @else { missing "absent" }
        }
    }
}
profile "p" { use "m" }
"#;
    let (errors, checked) = workspace_report(document);
    assert_eq!(errors, 0, "aggregate lookups failed checking:\n{checked}");
    let evaluated =
        evaluate_authoring_profile_v1(&sources(document), AUTHORING_CONFIG_FILE, "p", &[])
            .expect("evaluate aggregate lookups");
    let root = evaluated.outputs()[0]
        .component_render()
        .unwrap()
        .document()
        .root()
        .as_record()
        .unwrap();
    assert_eq!(root["exact"].as_string(), Some("exact-input"));
    assert_eq!(root["dotted"].as_string(), Some("map-dotted"));
    assert_eq!(root["first"].as_string(), Some("first"));
    assert_eq!(root["second"].as_integer(), Some(2));
    assert_eq!(root["missing"].as_string(), Some("absent"));
}

#[test]
fn sets_are_scalar_only_and_support_nonempty_predicates() {
    let document = r#"config target="~" default-profile="p"
module "m" {
    description "set predicates"
    inputs { input "tags" type="set<string>" { default "b" "a" "a" } }
    outputs {
        render "out" format="text" {
            @if-nonempty "tags" { @line "nonempty" }
        }
    }
}
profile "p" { use "m" }
"#;
    let (errors, checked) = workspace_report(document);
    assert_eq!(errors, 0, "set nonempty failed checking:\n{checked}");
    let evaluated =
        evaluate_authoring_profile_v1(&sources(document), AUTHORING_CONFIG_FILE, "p", &[])
            .expect("evaluate set nonempty");
    assert_eq!(evaluated.outputs()[0].bytes(), Some(&b"nonempty\n"[..]));

    let aggregate = r#"config target="~" default-profile="p"
module "m" {
    description "aggregate set"
    types { record "entry" { fields { field "name" type="string" } } }
    inputs { input "entries" type="set<entry>" }
}
profile "p" { use "m" }
"#;
    let (errors, checked) = workspace_report(aggregate);
    assert!(errors > 0);
    assert!(
        checked.contains("sets accept only scalar element types"),
        "aggregate set was not rejected:\n{checked}"
    );
}

#[test]
fn direct_kdl_equality_uses_the_parsed_is_and_is_not_predicates() {
    let document = r#"config target="~" default-profile="p"
module "m" {
    description "direct kdl equality"
    inputs { input "mode" type="string" default="on" }
    outputs {
        render "out.kdl" format="kdl" {
            @if "mode" is="on" {
                selected "equal"
            }
            @else { selected "wrong" }
            @if "mode" is-not="off" { not-off #true }
        }
    }
}
profile "p" { use "m" }
"#;
    let (errors, checked) = workspace_report(document);
    assert_eq!(errors, 0, "direct KDL equality failed checking:\n{checked}");
    let evaluated =
        evaluate_authoring_profile_v1(&sources(document), AUTHORING_CONFIG_FILE, "p", &[])
            .expect("evaluate direct KDL equality");
    let output = std::str::from_utf8(evaluated.outputs()[0].bytes().unwrap()).unwrap();
    assert!(output.contains("selected equal"), "{output}");
    assert!(output.contains("not-off #true"), "{output}");
    assert!(!output.contains("wrong"), "{output}");
}
