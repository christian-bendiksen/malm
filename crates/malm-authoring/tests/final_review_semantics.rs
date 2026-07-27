use malm_authoring::{
    AUTHORING_CONFIG_FILE, AuthoringSourceSetV1, EvaluatedAuthoringProfileV1,
    check_authoring_workspace_v1, evaluate_authoring_profile_v1,
};

fn sources(document: &str) -> AuthoringSourceSetV1 {
    sources_with(document, &[])
}

fn sources_with(document: &str, extras: &[(&str, &str)]) -> AuthoringSourceSetV1 {
    let mut sources = AuthoringSourceSetV1::new();
    sources
        .insert(AUTHORING_CONFIG_FILE, document.as_bytes().to_vec())
        .expect("capture authoring document");
    for (path, content) in extras {
        sources
            .insert(path, content.as_bytes().to_vec())
            .expect("capture supporting authoring source");
    }
    sources
}

fn evaluate(document: &str) -> EvaluatedAuthoringProfileV1 {
    evaluate_authoring_profile_v1(&sources(document), AUTHORING_CONFIG_FILE, "p", &[])
        .expect("evaluate final-review fixture")
}

fn evaluation_report(document: &str) -> String {
    evaluation_report_with(document, &[])
}

fn evaluation_report_with(document: &str, extras: &[(&str, &str)]) -> String {
    evaluate_authoring_profile_v1(
        &sources_with(document, extras),
        AUTHORING_CONFIG_FILE,
        "p",
        &[],
    )
    .expect_err("fixture should be rejected")
    .to_string()
}

fn workspace_report(document: &str) -> (usize, String) {
    let checked = check_authoring_workspace_v1(&sources(document), AUTHORING_CONFIG_FILE)
        .expect("check authoring workspace");
    (checked.error_count(), checked.report().to_owned())
}

fn output_text<'a>(evaluated: &'a EvaluatedAuthoringProfileV1, destination: &str) -> &'a str {
    let output = evaluated
        .outputs()
        .iter()
        .find(|output| output.destination() == destination)
        .unwrap_or_else(|| panic!("missing output {destination}"));
    std::str::from_utf8(output.bytes().expect("byte output")).expect("UTF-8 output")
}

#[test]
fn equality_is_shared_across_requirements_and_every_render_context() {
    let document = r#"config target="~" default-profile="p"
module "m" {
    description "predicate equality"
    requires {
        @if "target" is="/tmp/equal" { command "path-requirement" }
        @if "values.missing" is="value" { command "wrong-requirement" }
        @if "values.missing" is-not="value" { command "absent-requirement" }
    }
    inputs {
        input "target" type="path" default="/tmp/equal"
        input "values" type="map<string>"
    }
    outputs {
        render "requirements.txt" format="line-list" { @requirements }
        render "direct.kdl" format="kdl" {
            @if "target" is="/tmp/equal" { selected "path" }
            @if "values.missing" is="value" { wrong #true }
            @if "values.missing" is-not="value" { absent #true }
        }
        render "text.txt" format="text" {
            @if "target" is="/tmp/equal" { @line "path" }
            @if "values.missing" is="value" { @line "wrong" }
            @if "values.missing" is-not="value" { @line "absent" }
        }
        render "component" format="test-format" component-renderer="test-renderer" {
            @if "target" is="/tmp/equal" { selected "path" }
            @if "values.missing" is="value" { wrong #true }
            @if "values.missing" is-not="value" { absent #true }
        }
        render "generic.xml" format="xml" {
            root {
                @if "target" is="/tmp/equal" { selected "path" }
                @if "values.missing" is="value" { wrong "value" }
                @if "values.missing" is-not="value" { absent "value" }
            }
        }
    }
}
profile "p" { use "m" }
"#;

    let (errors, checked) = workspace_report(document);
    assert_eq!(errors, 0, "predicate fixture failed checking:\n{checked}");
    let evaluated = evaluate(document);

    let requirements = output_text(&evaluated, "requirements.txt");
    assert!(requirements.contains("path-requirement"), "{requirements}");
    assert!(
        requirements.contains("absent-requirement"),
        "{requirements}"
    );
    assert!(
        !requirements.contains("wrong-requirement"),
        "{requirements}"
    );

    for destination in ["direct.kdl", "text.txt", "generic.xml"] {
        let output = output_text(&evaluated, destination);
        assert!(output.contains("path"), "{destination}:\n{output}");
        assert!(output.contains("absent"), "{destination}:\n{output}");
        assert!(!output.contains("wrong"), "{destination}:\n{output}");
    }

    let component = evaluated
        .outputs()
        .iter()
        .find(|output| output.destination() == "component")
        .expect("component output")
        .component_render()
        .expect("component render")
        .document()
        .root()
        .as_record()
        .expect("component root");
    assert_eq!(component["selected"].as_string(), Some("path"));
    assert_eq!(component["absent"].as_bool(), Some(true));
    assert!(!component.contains_key("wrong"));
}

#[test]
fn sibling_conflicts_compare_canonical_values_and_retain_real_conflicts() {
    let equivalent = r#"config target="~" default-profile="p"
module "m" {
    description "canonical sibling values"
    types {
        record "nested" { fields { field "label" type="string" required=#true } }
        record "settings" {
            fields {
                field "enabled" type="bool" required=#true
                field "nested" type="nested" required=#true
            }
        }
    }
    inputs {
        input "mapping" type="map<int>"
        input "tags" type="set<string>"
        input "settings" type="settings"
        input "target" type="path"
    }
}
profile "left" {
    use "m" {
        with {
            mapping { item "z" 2; item "a" 1 }
            tags "b" "a" "a"
            settings enabled=#true { nested label="same" }
            target "/tmp/parent/../same"
        }
    }
}
profile "right" {
    use "m" {
        with {
            mapping { item "a" 1; item "z" 2 }
            tags "a" "b"
            settings { enabled #true; nested { label "same" } }
            target "/tmp/same"
        }
    }
}
profile "p" { extends "left" "right" }
"#;
    let (errors, checked) = workspace_report(equivalent);
    assert_eq!(errors, 0, "canonical siblings conflicted:\n{checked}");
    evaluate(equivalent);

    let conflicting = equivalent.replacen(
        "mapping { item \"a\" 1; item \"z\" 2 }",
        "mapping { item \"a\" 1; item \"z\" 3 }",
        1,
    );
    let report = evaluation_report(&conflicting);
    assert!(report.contains("error[MALM3006]"), "{report}");
    assert!(
        report.contains("sibling parents `left` and `right`"),
        "{report}"
    );
    assert!(report.contains("also set here"), "{report}");
}

#[test]
fn aggregate_alias_computed_default_is_rejected_even_when_overridden() {
    let document = r#"config target="~" default-profile="p"
module "m" {
    description "aggregate computed alias"
    types { alias "entries" type="map<int>" }
    inputs { input "values" type="entries" default=(f)"suppressed" }
}
profile "p" { use "m" { with { values { item "one" 1 } } } }
"#;

    let (errors, checked) = workspace_report(document);
    assert!(errors > 0);
    assert!(
        checked.contains("computed defaults require a scalar input type")
            && checked.contains("got map<int>"),
        "{checked}"
    );
    let evaluated = evaluation_report(document);
    assert!(
        evaluated.contains("computed defaults require a scalar input type"),
        "{evaluated}"
    );
}

#[test]
fn variant_shared_fields_require_compatible_resolved_types() {
    for cases in [
        r#"case "text" { fields { field "shared" type="text" } }
            case "number" { fields { field "shared" type="int" } }"#,
        r#"case "number" { fields { field "shared" type="int" } }
            case "text" { fields { field "shared" type="text" } }"#,
    ] {
        let document = format!(
            r#"config target="~" default-profile="p"
module "m" {{
    description "incompatible shared variant field"
    types {{
        alias "text" type="string"
        variant "choice" discriminator="kind" {{ {cases} }}
    }}
    inputs {{ input "choice" type="choice?" }}
}}
profile "p" {{ use "m" }}
"#
        );
        let (errors, checked) = workspace_report(&document);
        assert!(errors > 0);
        assert!(
            checked.contains("variant field `shared` has incompatible resolved types")
                && checked.contains("first declared with this type here"),
            "{checked}"
        );
    }

    let compatible = r#"config target="~" default-profile="p"
module "m" {
    description "compatible shared variant field"
    types {
        alias "text" type="string"
        variant "choice" discriminator="kind" {
            case "first" { fields { field "shared" type="text" required=#true } }
            case "second" { fields { field "shared" type="string" required=#true } }
        }
    }
    inputs { input "choice" type="choice" { default { invoke "second" { shared "ok" } } } }
    outputs {
        render "component" format="test-format" component-renderer="test-renderer" {
            shared (ref?)"choice.shared"
        }
    }
}
profile "p" { use "m" }
"#;
    let (errors, checked) = workspace_report(compatible);
    assert_eq!(errors, 0, "compatible shared field failed:\n{checked}");
    let evaluated = evaluate(compatible);
    let root = evaluated.outputs()[0]
        .component_render()
        .expect("component render")
        .document()
        .root()
        .as_record()
        .expect("component root");
    assert_eq!(root["shared"].as_string(), Some("ok"));
}

#[test]
fn dotted_map_lookup_prefers_an_exact_aggregate_key_and_keeps_missing_optional() {
    let document = r#"config target="~" default-profile="p"
module "m" {
    description "exact aggregate map key"
    types { record "entry" { fields { field "label" type="string" required=#true } } }
    inputs {
        input "lookup" type="map<entry>" {
            defaults { item "dotted.key" label="exact" }
        }
    }
    outputs {
        render "component" format="test-format" component-renderer="test-renderer" {
            exact (ref?)"lookup.dotted.key"
            @if-present "lookup.missing.key" { missing "wrong" }
            @else { missing "absent" }
        }
    }
}
profile "p" { use "m" }
"#;
    let (errors, checked) = workspace_report(document);
    assert_eq!(errors, 0, "exact map lookup failed checking:\n{checked}");
    let evaluated = evaluate(document);
    let root = evaluated.outputs()[0]
        .component_render()
        .expect("component render")
        .document()
        .root()
        .as_record()
        .expect("component root");
    let exact = root["exact"].as_record().expect("exact aggregate payload");
    assert_eq!(exact["label"].as_string(), Some("exact"));
    assert_eq!(root["missing"].as_string(), Some("absent"));
}

#[test]
fn dotted_aggregate_map_lookup_splits_only_when_the_exact_key_is_absent() {
    let document = r#"config target="~" default-profile="p"
module "m" {
    description "exact and traversed aggregate map keys"
    types { record "entry" { fields { field "label" type="string" required=#true } } }
    inputs {
        input "lookup" type="map<entry>" {
            defaults {
                item "exact.key" label="whole-record"
                item "split" label="field-value"
            }
        }
    }
    outputs {
        render "component" format="test-format" component-renderer="test-renderer" {
            exact (ref?)"lookup.exact.key"
        }
        render "out.kdl" format="kdl" {
            @if-present "lookup.split.label" { split (ref)"lookup.split.label" }
            @if-present "lookup.missing.label" { missing (ref)"lookup.missing.label" }
            @else { missing "absent" }
        }
    }
}
profile "p" { use "m" }
"#;
    let (errors, checked) = workspace_report(document);
    assert_eq!(errors, 0, "aggregate map traversal disagreed:\n{checked}");

    let evaluated = evaluate(document);
    let root = evaluated.outputs()[0]
        .component_render()
        .expect("component render")
        .document()
        .root()
        .as_record()
        .expect("component root");
    assert_eq!(
        root["exact"].as_record().expect("exact map item")["label"].as_string(),
        Some("whole-record")
    );
    assert_eq!(
        output_text(&evaluated, "out.kdl"),
        "split field-value\nmissing absent\n"
    );
}

#[test]
fn variant_patch_prefers_exact_discriminator_prefixed_field() {
    let document = r#"config target="~" default-profile="p"
module "m" {
    description "discriminator-prefixed field"
    types {
        variant "choice" discriminator="kind" {
            case "active" { fields { field "kind.label" type="string?" } }
        }
    }
    inputs {
        input "choice" type="choice" { default { invoke "active" { kind.label "before" } } }
    }
    outputs {
        render "component" format="test-format" component-renderer="test-renderer" {
            label (ref?)"choice.kind.label"
        }
    }
}
profile "p" { use "m" { patch { set "choice.kind.label" "after" } } }
"#;
    let (errors, checked) = workspace_report(document);
    assert_eq!(errors, 0, "exact variant field patch failed:\n{checked}");
    let evaluated = evaluate(document);
    let root = evaluated.outputs()[0]
        .component_render()
        .expect("component render")
        .document()
        .root()
        .as_record()
        .expect("component root");
    assert_eq!(root["label"].as_string(), Some("after"));

    let mutation = document.replace(
        "set \"choice.kind.label\" \"after\"",
        "set \"choice.kind.missing\" \"after\"",
    );
    let report = evaluation_report(&mutation);
    assert!(
        report.contains("variant discriminator `choice.kind` cannot be set or unset"),
        "{report}"
    );
}

#[test]
fn deep_profile_chains_and_cycles_terminate_without_recursive_graph_walking() {
    const COUNT: usize = 4096;
    let mut chain = String::from(
        "config target=\"~\" default-profile=\"p\"\nmodule \"m\" { description \"deep\"; outputs { render \"out\" format=\"text\" { @line \"ok\" } } }\nprofile \"p0\" { use \"m\" }\n",
    );
    for index in 1..COUNT {
        chain.push_str(&format!(
            "profile \"p{index}\" {{ extends \"p{}\" }}\n",
            index - 1
        ));
    }
    let evaluated = evaluate_authoring_profile_v1(
        &sources(&chain),
        AUTHORING_CONFIG_FILE,
        &format!("p{}", COUNT - 1),
        &[],
    )
    .expect("evaluate deep profile chain");
    assert_eq!(evaluated.outputs()[0].bytes(), Some(&b"ok\n"[..]));

    let mut cycle = String::from("config target=\"~\" default-profile=\"p\"\n");
    for index in 0..COUNT {
        cycle.push_str(&format!(
            "profile \"c{index}\" {{ extends \"c{}\" }}\n",
            (index + 1) % COUNT
        ));
    }
    let report = evaluate_authoring_profile_v1(&sources(&cycle), AUTHORING_CONFIG_FILE, "c0", &[])
        .expect_err("deep profile cycle should be rejected")
        .to_string();
    assert!(report.contains("profile inheritance cycle:"), "{report}");
}

#[test]
fn profile_documents_are_structurally_validated_during_recursive_coercion() {
    let direct = r#"config target="~" default-profile="p"
module "m" {
    description "profile document structure"
    inputs { input "documents" type="collection<kdl-document>" }
}
profile "p" {
    use "m" { with { documents { item "bad" { @splice "removed" } } } }
}
"#;
    let report = evaluation_report(direct);
    assert!(
        report.contains("`@splice` was removed; use `@insert-documents`")
            && report.contains("malm.kdl"),
        "{report}"
    );

    let nested = r#"config target="~" default-profile="p"
module "m" {
    description "nested profile document structure"
    types {
        record "envelope" {
            fields { field "payload" type="kdl-document" required=#true }
        }
    }
    inputs { input "envelope" type="envelope" }
}
profile "p" {
    use "m" { with { envelope { payload { @splice "removed" } } } }
}
"#;
    let report = evaluation_report(nested);
    assert!(report.contains("`@splice` was removed"), "{report}");

    let mut payload = String::from("leaf \"value\"");
    for index in 0..17 {
        payload = format!("level-{index} {{ {payload} }}");
    }
    let deep = format!(
        r#"config target="~" default-profile="p"
module "m" {{
    description "deep profile document"
    inputs {{ input "documents" type="collection<kdl-document>" }}
}}
profile "p" {{
    use "m" {{ with {{ documents {{ item "deep" {{ {payload} }} }} }} }}
}}
"#
    );
    let report = evaluation_report(&deep);
    assert!(
        report.contains("document nesting exceeds the maximum depth"),
        "{report}"
    );
}

#[test]
fn kdl_fragment_structure_is_reported_at_its_authoring_source_declaration() {
    let document = r#"config target="~" default-profile="p"
module "m" {
    description "fragment structure"
    fragments {
        fragment "payload" format="kdl-v2" { default "./payload.kdl" }
    }
    outputs {
        render "out.kdl" format="kdl" { @include-fragment fragment="payload" }
    }
}
profile "p" { use "m" }
"#;
    let report = evaluation_report_with(document, &[("payload.kdl", "@splice \"removed\"\n")]);
    assert!(report.contains("`@splice` was removed"), "{report}");
    assert!(report.contains("--> malm.kdl:"), "{report}");
    assert!(
        report.contains("while validating fragment `payload` source payload.kdl"),
        "{report}"
    );
    assert!(!report.contains("--> payload.kdl:"), "{report}");
}

#[test]
fn inactive_component_insertions_cannot_hide_invalid_or_mixed_shapes() {
    for payload in [r#"- "list-root""#, r#"named "record"; - "list""#] {
        let document = format!(
            r#"config target="~" default-profile="p"
module "m" {{
    description "inactive component insertion"
    inputs {{
        input "enabled" type="bool" default=#false
        input "documents" type="collection<kdl-document>" {{
            defaults {{ item "payload" {{ {payload} }} }}
        }}
    }}
    outputs {{
        render "out" format="test-format" component-renderer="renderer" {{
            stable "record"
            @if "enabled" {{ @insert-documents "documents" }}
        }}
    }}
}}
profile "p" {{ use "m" }}
"#
        );
        let report = evaluation_report(&document);
        assert!(
            report.contains("component document")
                && (report.contains("root must be a record")
                    || report.contains("cannot mix named record fields")),
            "payload {payload:?}:\n{report}"
        );
    }
}

#[test]
fn xml_else_adjacency_uses_the_unfiltered_sibling_sequence() {
    let document = r#"config target="~" default-profile="p"
module "m" {
    description "XML else adjacency"
    inputs { input "enabled" type="bool" default=#false }
    outputs {
        render "out.xml" format="xml" {
            root {
                @if "enabled" { selected "yes" }
                attr "id" "between"
                @else { selected "no" }
            }
        }
    }
}
profile "p" { use "m" }
"#;
    let report = evaluation_report(document);
    assert!(report.contains("must immediately follow"), "{report}");
}

#[test]
fn direct_variant_discriminator_makes_invoke_an_ordinary_case_field() {
    let document = r#"config target="~" default-profile="p"
module "m" {
    description "direct invoke field"
    types {
        variant "choice" discriminator="kind" {
            case "active" {
                fields { field "invoke" type="string" required=#true }
            }
        }
    }
    inputs {
        input "choice" type="choice" {
            default kind="active" { invoke "ordinary-field" }
        }
    }
    outputs {
        render "out" format="test-format" component-renderer="renderer" {
            invoke (ref?)"choice.invoke"
        }
    }
}
profile "p" { use "m" }
"#;
    let (errors, checked) = workspace_report(document);
    assert_eq!(errors, 0, "direct invoke field failed checking:\n{checked}");
    let evaluated = evaluate(document);
    let root = evaluated.outputs()[0]
        .component_render()
        .expect("component render")
        .document()
        .root()
        .as_record()
        .expect("component record");
    assert_eq!(root["invoke"].as_string(), Some("ordinary-field"));
}

#[test]
fn component_transform_names_are_validated_during_authoring_parse() {
    let document = r#"config target="~" default-profile="p"
module "m" {
    description "invalid transform name"
    outputs {
        render "out.txt" format="text" {
            @component-transform "Invalid_Name"
            @line "value"
        }
    }
}
profile "p" { use "m" }
"#;
    let report = evaluation_report(document);
    assert!(
        report.contains("`@component-transform` name")
            && report.contains("not a contribution identifier"),
        "{report}"
    );
}

#[test]
fn lit_still_escapes_control_shaped_keys_in_inserted_documents() {
    let document = r#"config target="~" default-profile="p"
module "m" {
    description "inserted lit"
    inputs {
        input "documents" type="collection<kdl-document>" {
            defaults { item "literal" { @lit "@if" "literal-value" } }
        }
    }
    outputs {
        render "out.json" format="json" { @insert-documents "documents" }
    }
}
profile "p" { use "m" }
"#;
    let (errors, checked) = workspace_report(document);
    assert_eq!(errors, 0, "inserted @lit failed checking:\n{checked}");
    let evaluated = evaluate(document);
    assert_eq!(
        output_text(&evaluated, "out.json"),
        "{\n  \"@if\": \"literal-value\"\n}\n"
    );
}

#[test]
fn lit_and_escaped_nodes_remove_the_target_entry_without_losing_earlier_properties() {
    let document = r#"config target="~" default-profile="p"
module "m" {
    description "literal target entry identity"
    inputs { input "value" type="string" default="resolved" }
    outputs {
        render "out.json" format="json" {
            @lit before=(ref)"value" "@if" after="tail"
        }
        render "out.kdl" format="kdl" {
            node before=(ref)"value" "@if" "payload" after="tail"
        }
    }
}
profile "p" { use "m" }
"#;
    let (errors, checked) = workspace_report(document);
    assert_eq!(errors, 0, "literal escapes failed checking:\n{checked}");
    let evaluated = evaluate(document);
    assert_eq!(
        output_text(&evaluated, "out.json"),
        "{\n  \"@if\": { \"before\": \"resolved\", \"after\": \"tail\" }\n}\n"
    );
    assert_eq!(
        output_text(&evaluated, "out.kdl"),
        "@if before=resolved payload after=tail\n"
    );
}

#[test]
fn lit_and_escaped_nodes_validate_duplicate_properties_annotations_and_refs() {
    let fixtures = [
        (
            r#"@lit value="missing-target""#,
            "requires a literal key as its first argument",
        ),
        (
            r#"@lit "" "payload""#,
            "key must be a non-empty plain string",
        ),
        (
            r#"@lit duplicate=1 "key" duplicate=2"#,
            "property `duplicate=` is set twice",
        ),
        (
            r#"@lit "key" value=(unknown)"payload""#,
            "unknown value annotation `(unknown)`",
        ),
        (
            r#"@lit value=(ref)"missing" "key""#,
            "`missing` is not defined",
        ),
    ];
    for (body, expected) in fixtures {
        let document = format!(
            r#"config target="~" default-profile="p"
module "m" {{
    description "invalid lit"
    outputs {{ render "out.json" format="json" {{ {body} }} }}
}}
profile "p" {{ use "m" }}
"#
        );
        let (_, report) = workspace_report(&document);
        assert!(report.contains(expected), "missing {expected:?}:\n{report}");
    }

    for (body, expected) in [
        (
            r#"node value="missing-target""#,
            "requires a literal target node name",
        ),
        (
            r#"node duplicate=1 "@if" duplicate=2"#,
            "sets property `duplicate` twice",
        ),
        (
            r#"node value=(ref)"missing" "@if""#,
            "`missing` is not defined",
        ),
        (
            r#"node value=(ref)1 "@if""#,
            "a `(ref)` value must be a string",
        ),
    ] {
        let document = format!(
            r#"config target="~" default-profile="p"
module "m" {{
    description "invalid escaped node"
    outputs {{ render "out.kdl" format="kdl" {{ {body} }} }}
}}
profile "p" {{ use "m" }}
"#
        );
        let (_, report) = workspace_report(&document);
        assert!(report.contains(expected), "missing {expected:?}:\n{report}");
    }
}
