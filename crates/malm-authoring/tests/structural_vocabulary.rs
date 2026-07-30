use malm_authoring::{
    AUTHORING_CONFIG_FILE, AuthoringSourceSetV1, EvaluatedAuthoringProfileV1,
    evaluate_authoring_profile_v1,
};

fn sources(document: &str, extras: &[(&str, &str)]) -> AuthoringSourceSetV1 {
    let mut sources = AuthoringSourceSetV1::new();
    sources
        .insert(AUTHORING_CONFIG_FILE, document.as_bytes().to_vec())
        .expect("capture authoring document");
    for (path, content) in extras {
        sources
            .insert(path, content.as_bytes().to_vec())
            .expect("capture extra source");
    }
    sources
}

fn evaluate(document: &str, extras: &[(&str, &str)]) -> EvaluatedAuthoringProfileV1 {
    evaluate_authoring_profile_v1(&sources(document, extras), AUTHORING_CONFIG_FILE, "p", &[])
        .expect("evaluate canonical structural vocabulary")
}

fn report(document: &str) -> String {
    evaluate_authoring_profile_v1(&sources(document, &[]), AUTHORING_CONFIG_FILE, "p", &[])
        .expect_err("removed or malformed structural syntax must fail")
        .to_string()
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
fn canonical_controls_work_across_every_authoring_context() {
    let document = r#"config target="~" default-profile="p"
module "m" {
    description "canonical structural vocabulary"
    requires {
        @if "enabled" { command "skipped" }
        @else { command "condition-else" }
        @if-present "present" { command "present" }
        @if-nonempty "items" { command "nonempty" }
    }
    inputs {
        input "enabled" type="bool" default=#false
        input "present" type="string?" default="value"
        input "items" type="list<string>" { default "one" }
        input "settings" type="record" {
            fields { field "alpha" type="int" required=#true }
            default { alpha 1 }
        }
        input "direct-documents" type="collection<kdl-document>" {
            defaults { item "one" { inserted "direct" } }
        }
        input "render-documents" type="collection<kdl-document>" {
            defaults { item "one" { @line "inserted-render" } }
        }
        input "xml-documents" type="collection<kdl-document>" {
            defaults { item "one" { inserted "xml" } }
        }
        input "css-documents" type="collection<kdl-document>" {
            defaults { item "one" { inserted "css" } }
        }
    }
    fragments {
        fragment "text-fragment" format="text" { default "./fragment.txt" }
        fragment "kdl-fragment" format="kdl-v2" { default "./fragment.kdl" }
    }
    outputs {
        @if "enabled" { render "skipped.txt" format="text" { @line "wrong" } }
        @else { render "declaration-else.txt" format="text" { @line "declaration-else" } }
        @for-each "item" in="items" {
            render (f)"declaration-{{item}}.txt" format="text" { @line (ref)"item" }
        }
        @for-range "number" from=1 through=1 {
            render (f)"range-{{number}}.txt" format="text" { @line (ref)"number" }
        }
        render "requirements.txt" format="line-list" { @requirements }
        render "direct.kdl" format="kdl" {
            @if "enabled" { wrong #true }
            @else { selected "direct-else" }
            @if-present "present" { present (ref)"present" }
            @if-nonempty "items" { nonempty #true }
            @for-each "item" in="items" { iterated (ref)"item" }
            @for-range "number" from=2 through=2 { ranged (ref)"number" }
            @insert-documents "direct-documents"
            @include-fragment fragment="kdl-fragment"
            if "literal"
            when "literal"
            each "literal"
            range "literal"
            splice "literal"
            compose "literal"
        }
        render "render.txt" format="text" {
            @raw-text "raw-text\n"
            @include-file "./included.txt"
            @include-fragment "text-fragment"
            @if "enabled" { @line "wrong" }
            @else { @line "render-else" }
            @if-present "present" { @line (ref)"present" }
            @if-nonempty "items" { @line "render-nonempty" }
            @for-each "item" in="items" { @line (ref)"item" }
            @for-range "number" from=3 through=3 { @line (ref)"number" }
            @insert-documents "render-documents"
        }
        render "component" format="test-format" component-renderer="test-renderer" {
            @component-transform "test-transform"
            @if "enabled" { wrong "value" }
            @else { selected "component-else" }
            @insert-fields "settings"
            @insert-documents "direct-documents"
            if "literal"
            when "literal"
            each "literal"
            range "literal"
            splice "literal"
            compose "literal"
        }
        render "out.xml" format="xml" {
            root {
                @if "enabled" { wrong "value" }
                @else { selected "xml-else" }
                @if-present "present" { present (ref)"present" }
                @if-nonempty "items" { nonempty "yes" }
                @for-each "item" in="items" { item (ref)"item" }
                @for-range "number" from=4 through=4 { number (ref)"number" }
                @insert-documents "xml-documents"
                @comment "xml comment"
            }
        }
        render "out.css" format="css" {
            @if "enabled" { skipped { color "red" } }
            @else { selected { color "green" } }
            @if-present "present" { present (ref)"present" }
            @if-nonempty "items" { nonempty "yes" }
            @for-each "item" in="items" { item (ref)"item" }
            @for-range "number" from=5 through=5 { number (ref)"number" }
            @insert-documents "css-documents"
            @comment "css comment"
        }
    }
}
profile "p" { use "m" }
"#;

    let evaluated = evaluate(
        document,
        &[
            ("included.txt", "included-file\n"),
            ("fragment.txt", "included-fragment\n"),
            ("fragment.kdl", "fragment-node \"yes\"\n"),
        ],
    );

    let destinations = evaluated
        .outputs()
        .iter()
        .map(|output| output.destination())
        .collect::<Vec<_>>();
    assert!(destinations.contains(&"declaration-else.txt"));
    assert!(destinations.contains(&"declaration-one.txt"));
    assert!(destinations.contains(&"range-1.txt"));
    assert!(!destinations.contains(&"skipped.txt"));

    let requirements = output_text(&evaluated, "requirements.txt");
    assert!(requirements.contains("condition-else"), "{requirements}");
    assert!(requirements.contains("present"), "{requirements}");
    assert!(requirements.contains("nonempty"), "{requirements}");
    assert!(!requirements.contains("skipped"), "{requirements}");

    let direct = output_text(&evaluated, "direct.kdl");
    for expected in [
        "selected direct-else",
        "present value",
        "nonempty #true",
        "iterated one",
        "ranged 2",
        "inserted direct",
        "fragment-node yes",
        "if literal",
        "when literal",
        "each literal",
        "range literal",
        "splice literal",
        "compose literal",
    ] {
        assert!(direct.contains(expected), "missing {expected:?}:\n{direct}");
    }

    let render = output_text(&evaluated, "render.txt");
    for expected in [
        "raw-text",
        "included-file",
        "included-fragment",
        "render-else",
        "value",
        "render-nonempty",
        "one",
        "3",
        "inserted-render",
    ] {
        assert!(render.contains(expected), "missing {expected:?}:\n{render}");
    }

    let component = evaluated
        .outputs()
        .iter()
        .find(|output| output.destination() == "component")
        .expect("component output");
    assert_eq!(component.transforms(), ["test-transform"]);
    let record = component
        .component_render()
        .expect("component render")
        .document()
        .root()
        .as_record()
        .expect("component record");
    for name in [
        "alpha", "compose", "each", "if", "inserted", "range", "selected", "splice", "when",
    ] {
        assert!(record.contains_key(name), "missing component field {name}");
    }

    let xml = output_text(&evaluated, "out.xml");
    assert!(xml.contains("<selected>"), "{xml}");
    assert!(xml.contains("xml-else"), "{xml}");
    assert!(xml.contains("<inserted>"), "{xml}");
    assert!(xml.contains("xml"), "{xml}");
    assert!(xml.contains("<!-- xml comment -->"), "{xml}");

    let css = output_text(&evaluated, "out.css");
    assert!(css.contains("selected {"), "{css}");
    assert!(css.contains("inserted: css;"), "{css}");
    assert!(css.contains("/* css comment */"), "{css}");
}

#[test]
fn removed_spellings_are_diagnostics_not_aliases() {
    let render_cases = [
        ("@when \"enabled\" { @line \"x\" }", "@if"),
        ("@when-set \"present\" { @line \"x\" }", "@if-present"),
        ("@when-nonempty \"items\" { @line \"x\" }", "@if-nonempty"),
        ("@each \"item\" in=\"items\" {}", "@for-each"),
        ("@range \"number\" from=1 through=1 {}", "@for-range"),
        ("@spread \"settings\"", "@insert-fields"),
        ("@splice \"documents\"", "@insert-documents"),
        ("@file \"./file\"", "@include-file"),
        ("@compose \"fragment\"", "@include-fragment"),
        ("@raw \"text\"", "@raw-text"),
        ("@transform \"component\"", "@component-transform"),
    ];
    for (removed, canonical) in render_cases {
        let document = format!(
            r#"config target="~" default-profile="p"
module "m" {{
    description "removed render spelling"
    inputs {{
        input "enabled" type="bool" default=#true
        input "present" type="string?"
        input "items" type="list<string>"
        input "settings" type="record" {{ fields {{ field "x" type="string" }} }}
        input "documents" type="collection<kdl-document>"
    }}
    outputs {{ render "out" format="text" {{ {removed} }} }}
}}
profile "p" {{ use "m" }}
"#,
        );
        let error = report(&document);
        assert!(
            error.contains(canonical),
            "{removed:?} did not direct users to {canonical:?}:\n{error}"
        );
    }

    let old_renderer = r#"config target="~" default-profile="p"
module "m" {
    description "removed renderer property"
    outputs { render "out" format="test-format" renderer="component" { value "x" } }
}
profile "p" { use "m" }
"#;
    assert!(report(old_renderer).contains("component-renderer="));

    for output in [
        r#"render "out.kdl" format="kdl" { @when "enabled" { value "x" } }"#,
        r#"render "out.xml" format="xml" {
            root { @when "enabled" { value "x" } }
        }"#,
        r#"render "out.css" format="css" {
            @when "enabled" { value "x" }
        }"#,
        r#"render "out" format="test-format" component-renderer="renderer" {
            @when "enabled" { value "x" }
        }"#,
    ] {
        let document = format!(
            r#"config target="~" default-profile="p"
module "m" {{
    description "removed cross-context spelling"
    inputs {{ input "enabled" type="bool" default=#true }}
    outputs {{ {output} }}
}}
profile "p" {{ use "m" }}
"#,
        );
        let error = report(&document);
        assert!(error.contains("@if"), "{output}:\n{error}");
    }

    for (removed, canonical) in [
        ("when", "@if"),
        ("when-set", "@if-present"),
        ("when-nonempty", "@if-nonempty"),
        ("each", "@for-each"),
        ("range", "@for-range"),
    ] {
        let document = format!(
            r#"config target="~" default-profile="p"
module "m" {{
    description "removed declaration spelling"
    inputs {{ input "value" type="bool" default=#true }}
    outputs {{ {removed} "value" {{ render "out" format="text" {{ @line "x" }} }} }}
}}
profile "p" {{ use "m" }}
"#,
        );
        let error = report(&document);
        assert!(error.contains(canonical), "{removed}:\n{error}");
    }
}

#[test]
fn else_is_rejected_when_nested_or_not_immediately_adjacent() {
    let cases = [
        r#"render "out.kdl" format="kdl" {
            @if "enabled" { selected "yes"; @else { selected "nested" } }
        }"#,
        r#"render "out.txt" format="text" {
            @if "enabled" { @line "yes" }
            @line "between"
            @else { @line "no" }
        }"#,
        r#"render "out.xml" format="xml" {
            root {
                @if "enabled" { selected "yes" }
                between "value"
                @else { selected "no" }
            }
        }"#,
        r#"render "out.css" format="css" {
            @if "enabled" { selected "yes" }
            between "value"
            @else { selected "no" }
        }"#,
        r#"render "out" format="test-format" component-renderer="renderer" {
            @if "enabled" { selected "yes" }
            between "value"
            @else { selected "no" }
        }"#,
    ];
    for output in cases {
        let document = format!(
            r#"config target="~" default-profile="p"
module "m" {{
    description "invalid else placement"
    inputs {{ input "enabled" type="bool" default=#true }}
    outputs {{ {output} }}
}}
profile "p" {{ use "m" }}
"#,
        );
        let error = report(&document);
        assert!(error.contains("immediately follow"), "{output}:\n{error}");
    }

    for declaration in [
        r#"requires {
            @if "enabled" { command "yes" }
            command "between"
            @else { command "no" }
        }"#,
        r#"outputs {
            @if "enabled" { render "yes" format="text" { @line "yes" } }
            render "between" format="text" { @line "between" }
            @else { render "no" format="text" { @line "no" } }
        }"#,
    ] {
        let document = format!(
            r#"config target="~" default-profile="p"
module "m" {{
    description "invalid declaration else"
    inputs {{ input "enabled" type="bool" default=#true }}
    {declaration}
}}
profile "p" {{ use "m" }}
"#,
        );
        assert!(report(&document).contains("immediately follow"));
    }
}

/// The accepted asset formats must be exactly the ones deployment implements,
/// or a pack passes `source check` and then fails at deploy.
#[test]
fn asset_formats_are_limited_to_the_ones_deployment_implements() {
    fn document(format: &str) -> String {
        format!(
            r#"config target="~/.config" default-profile="p"
assets {{
    asset "theme-pack" {{
        url "https://example.com/theme"
        dst "~/.local/share/themes"
        format "{format}"
        sha256 "{digest}"
        path "vendor/theme"
    }}
}}
module "m" {{
    description "d"
    outputs {{
        render "m/out.conf" format="text" {{
            @line "x"
        }}
    }}
}}
profile "p" {{
    use "m"
}}
"#,
            digest = "0".repeat(64)
        )
    }

    for format in ["zip", "7z", "tar.gz", ""] {
        assert_eq!(
            report(&document(format)),
            format!("asset `theme-pack`: unknown format `{format}` (allowed: tar, tar-xz, tar-gz)")
        );
    }

    for format in ["tar", "tar-xz", "tar-gz"] {
        let evaluated = evaluate(&document(format), &[]);
        assert_eq!(
            evaluated.assets().len(),
            1,
            "format `{format}` must reach evaluation"
        );
        assert_eq!(evaluated.assets()[0].format, format);
    }
}
