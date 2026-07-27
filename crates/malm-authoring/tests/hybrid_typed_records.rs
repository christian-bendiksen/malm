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

fn checked_sources(document: &str) -> AuthoringSourceSetV1 {
    let sources = sources(document);
    let checked = check_authoring_workspace_v1(&sources, AUTHORING_CONFIG_FILE)
        .expect("check authoring workspace");
    assert_eq!(checked.error_count(), 0, "{}", checked.report());
    sources
}

fn report(document: &str) -> String {
    evaluate_authoring_profile_v1(&sources(document), AUTHORING_CONFIG_FILE, "p", &[])
        .expect_err("fixture should be rejected")
        .to_string()
}

fn fixture(hybrid: bool) -> String {
    let settings_default = if hybrid {
        r#"default enabled=#true count=1 ratio=1.5 target="~/base" direction="left" {
                nested label="default"
                tags "base"
            }"#
    } else {
        r#"default {
                enabled #true
                count 1
                ratio 1.5
                target "~/base"
                direction "left"
                nested { label "default" }
                tags "base"
            }"#
    };
    let list_item = if hybrid {
        r#"item enabled=#true count=2 ratio=2.5 target="~/list" direction="right" {
                    nested label="list"
                    tags "list"
                }"#
    } else {
        r#"item {
                    enabled #true
                    count 2
                    ratio 2.5
                    target "~/list"
                    direction "right"
                    nested { label "list" }
                    tags "list"
                }"#
    };
    let collection_item = if hybrid {
        r#"item "first" enabled=#true count=3 ratio=3.5 target="~/collection" direction="left" {
                    nested label="collection"
                    tags "collection"
                }"#
    } else {
        r#"item "first" {
                    enabled #true
                    count 3
                    ratio 3.5
                    target "~/collection"
                    direction "left"
                    nested { label "collection" }
                    tags "collection"
                }"#
    };
    let map_item = if hybrid {
        r#"item "z" enabled=#true count=4 ratio=4.5 target="~/map" direction="right" {
                    nested label="map"
                    tags "map"
                }"#
    } else {
        r#"item "z" {
                    enabled #true
                    count 4
                    ratio 4.5
                    target "~/map"
                    direction "right"
                    nested { label "map" }
                    tags "map"
                }"#
    };
    let direct_variant = if hybrid {
        r#"default kind="record" direction="left" { nested label="direct" }"#
    } else {
        r#"default { invoke "record" { direction "left"; nested { label "direct" } } }"#
    };
    let invoke_variant = if hybrid {
        r#"default { invoke "record" direction="right" { nested label="invoke" } }"#
    } else {
        r#"default { invoke "record" { direction "right"; nested { label "invoke" } } }"#
    };
    let with_settings = if hybrid {
        r#"settings enabled=#false count=5 ratio=5.5 target="~/profile" direction="right" note="hybrid" {
                nested label="profile"
                tags "profile"
            }
            argument kind="record" direction="right" { nested label="profile-argument" }
            mapped {
                item "z" enabled=#false count=9 ratio=9.5 target="~/mapped-with" direction="left" note=#null {
                    nested label="mapped-with"
                    tags "mapped-with"
                }
            }"#
    } else {
        r#"settings {
                enabled #false
                count 5
                ratio 5.5
                target "~/profile"
                direction "right"
                note "hybrid"
                nested { label "profile" }
                tags "profile"
            }
            argument { invoke "record" { direction "right"; nested { label "profile-argument" } } }
            mapped {
                item "z" {
                    enabled #false
                    count 9
                    ratio 9.5
                    target "~/mapped-with"
                    direction "left"
                    note #null
                    nested { label "mapped-with" }
                    tags "mapped-with"
                }
            }"#
    };
    let replace = if hybrid {
        r#"replace "first" enabled=#true count=6 ratio=6.5 target="~/replace" direction="right" {
                        nested label="replace"
                        tags "replace"
                    }"#
    } else {
        r#"replace "first" {
                        enabled #true
                        count 6
                        ratio 6.5
                        target "~/replace"
                        direction "right"
                        nested { label "replace" }
                        tags "replace"
                    }"#
    };
    let append = if hybrid {
        r#"append "second" enabled=#false count=7 ratio=7.5 target="~/append" direction="left" {
                        nested label="append"
                        tags "append"
                    }"#
    } else {
        r#"append "second" {
                        enabled #false
                        count 7
                        ratio 7.5
                        target "~/append"
                        direction "left"
                        nested { label "append" }
                        tags "append"
                    }"#
    };
    let replace_all = if hybrid {
        r#"item "final" enabled=#true count=8 ratio=8.5 target="~/final" direction="right" {
                            nested label="final"
                            tags "final"
                        }"#
    } else {
        r#"item "final" {
                            enabled #true
                            count 8
                            ratio 8.5
                            target "~/final"
                            direction "right"
                            nested { label "final" }
                            tags "final"
                        }"#
    };

    format!(
        r#"config target="~" default-profile="p"
module "m" {{
    description "hybrid typed records"
    types {{
        enum "direction" {{ values "left" "right" }}
        refine "positive" base="int" min=1
        refine "tag-list" base="list<string>" min=1
        record "nested" {{
            fields {{ field "label" type="string" required=#true }}
        }}
        record "entry" {{
            fields {{
                field "enabled" type="bool" required=#true
                field "count" type="positive" required=#true
                field "ratio" type="float" required=#true
                field "target" type="path" required=#true
                field "direction" type="direction" required=#true
                field "note" type="string?"
                field "nested" type="nested" required=#true
                field "tags" type="tag-list" required=#true
            }}
        }}
        variant "argument" discriminator="kind" {{
            case "none"
            case "record" {{
                fields {{
                    field "direction" type="direction" required=#true
                    field "nested" type="nested" required=#true
                }}
            }}
        }}
    }}
    inputs {{
        input "settings" type="entry" {{ {settings_default} }}
        input "entries" type="list<entry>" {{ defaults {{ {list_item} }} }}
        input "items" type="collection<entry>" {{ defaults {{ {collection_item} }} }}
        input "mapped" type="map<entry>" {{ defaults {{ {map_item} }} }}
        input "argument" type="argument" {{ {direct_variant} }}
        input "constructed" type="argument" {{ {invoke_variant} }}
    }}
    outputs {{
        render "out" format="test-format" component-renderer="test-renderer" {{
            settings {{
                enabled (ref)"settings.enabled"
                count (ref)"settings.count"
                ratio (ref)"settings.ratio"
                target (ref)"settings.target"
                direction (ref)"settings.direction"
                nested (ref)"settings.nested.label"
                tags (ref)"settings.tags"
            }}
            entries {{ @for-each "entry" in="entries" {{ - (ref)"entry.nested.label" }} }}
            items {{ @for-each "item" in="items" {{ - (ref)"item.nested.label" }} }}
            mapped {{ @for-each "item" in="mapped" {{ - (ref)"item.nested.label" }} }}
            argument {{
                kind (ref)"argument.kind"
                direction (ref?)"argument.direction"
                nested (ref?)"argument.nested.label"
            }}
            constructed {{
                kind (ref)"constructed.kind"
                direction (ref?)"constructed.direction"
                nested (ref?)"constructed.nested.label"
            }}
        }}
    }}
}}
profile "p" {{
    use "m" {{
        with {{ {with_settings} }}
        patch {{
            collection "items" {{
                {replace}
                {append}
                replace-all {{ {replace_all} }}
            }}
        }}
    }}
}}
"#
    )
}

#[test]
fn hybrid_and_child_forms_lower_and_render_identically_in_every_value_context() {
    let child = fixture(false);
    let hybrid = fixture(true);
    let child_sources = checked_sources(&child);
    let hybrid_sources = checked_sources(&hybrid);

    let child_vars = resolve_authoring_vars_v1(&child_sources, AUTHORING_CONFIG_FILE, "p", &[])
        .expect("resolve child-form values");
    let hybrid_vars = resolve_authoring_vars_v1(&hybrid_sources, AUTHORING_CONFIG_FILE, "p", &[])
        .expect("resolve hybrid values");
    let rendered_vars = |vars: &[malm_authoring::ResolvedVarV1]| {
        vars.iter()
            .map(|var| (var.name().to_owned(), var.rendered_value().to_owned()))
            .collect::<Vec<_>>()
    };
    assert_eq!(rendered_vars(&child_vars), rendered_vars(&hybrid_vars));

    let child_evaluated =
        evaluate_authoring_profile_v1(&child_sources, AUTHORING_CONFIG_FILE, "p", &[])
            .expect("evaluate child form");
    let hybrid_evaluated =
        evaluate_authoring_profile_v1(&hybrid_sources, AUTHORING_CONFIG_FILE, "p", &[])
            .expect("evaluate hybrid form");
    assert_eq!(child_evaluated.outputs(), hybrid_evaluated.outputs());
}

fn wrapped(body: &str) -> String {
    format!(
        r#"config target="~" default-profile="p"
module "m" {{
    description "diagnostic"
    types {{
        record "nested" {{ fields {{ field "label" type="string" required=#true }} }}
        record "entry" {{
            fields {{
                field "enabled" type="bool" required=#true
                field "nested" type="nested" required=#true
            }}
        }}
        variant "argument" discriminator="kind" {{
            case "none"
            case "record" {{ fields {{ field "enabled" type="bool"; field "nested" type="nested" }} }}
            case "value" {{ fields {{ field "value" type="string" }} }}
        }}
    }}
    inputs {{ {body} }}
}}
profile "p" {{ use "m" }}
"#
    )
}

#[test]
fn hybrid_records_reject_cross_form_duplicates_and_invalid_properties() {
    let cases = [
        (
            r#"input "x" type="entry" { default enabled=#true enabled=#false { nested label="x" } }"#,
            "field `enabled` is set twice",
        ),
        (
            r#"input "x" type="entry" { default enabled=#true { enabled #false; nested label="x" } }"#,
            "field `enabled` is set twice",
        ),
        (
            r#"input "x" type="entry" { default enabled=#true { nested label="x"; nested label="y" } }"#,
            "field `nested` is set twice",
        ),
        (
            r#"input "x" type="entry" { default enabled=#true mystery="x" { nested label="x" } }"#,
            "unknown field `mystery`",
        ),
        (
            r#"input "x" type="entry" { default enabled=#true nested="x" }"#,
            "aggregate field of type record must be authored as a child node",
        ),
        (
            r#"input "x" type="entry" { default enabled="yes" { nested label="x" } }"#,
            "expected bool, got string `yes`",
        ),
    ];
    for (input, expected) in cases {
        let report = report(&wrapped(input));
        assert!(report.contains(expected), "missing {expected:?}:\n{report}");
    }
}

#[test]
fn direct_and_invoke_variants_validate_discriminators_and_active_fields() {
    let cases = [
        (
            r#"input "x" type="argument" { default enabled=#true }"#,
            "missing discriminator property `kind=`",
        ),
        (
            r#"input "x" type="argument" { default kind=1 }"#,
            "discriminator property `kind=` must be a string",
        ),
        (
            r#"input "x" type="argument" { default kind="missing" }"#,
            "unknown variant case `missing`",
        ),
        (
            r#"input "x" type="argument" { default kind="none" value="inactive" }"#,
            "field `value` is not active for variant case `none`",
        ),
        (
            r#"input "x" type="argument" { default kind="record" { invoke "record" } }"#,
            "unknown field `invoke`",
        ),
        (
            r#"input "x" type="argument" { default { invoke "record" kind="record" } }"#,
            "discriminator property `kind=` is not allowed",
        ),
        (
            r#"input "x" type="argument" { default { invoke "record" ignored=#true } }"#,
            "unknown field `ignored`",
        ),
        (
            r#"input "x" type="argument" { default { invoke "record" enabled=#true { enabled #false } } }"#,
            "field `enabled` is set twice",
        ),
    ];
    for (input, expected) in cases {
        let report = report(&wrapped(input));
        assert!(report.contains(expected), "missing {expected:?}:\n{report}");
    }
}

#[test]
fn raw_record_literals_cannot_escape_into_non_record_values() {
    let document = r#"config target="~" default-profile="p"
module "m" {
    description "raw escape"
    inputs { input "document" type="kdl-document" }
}
profile "p" { use "m" { with { document field="value" } } }
"#;
    let report = report(document);
    assert!(
        report.contains("expected kdl-document, got raw-record-literal `raw-record-literal`"),
        "{report}"
    );
}
