//! Pins user-visible diagnostic text, including labels that distinguish body
//! syntaxes and source-ordered diagnostics from every emitter.
//!
//! These are byte-exact assertions on rendered reports. Any change here is a
//! change to what users read; update it only deliberately.

use malm_authoring::{AUTHORING_CONFIG_FILE, AuthoringSourceSetV1, evaluate_authoring_profile_v1};

/// Evaluates a single-document workspace for profile `p` and returns the
/// rendered diagnostics report.
fn report(body: &str) -> String {
    let mut sources = AuthoringSourceSetV1::new();
    sources
        .insert(AUTHORING_CONFIG_FILE, body.as_bytes().to_vec())
        .expect("capture root document");
    match evaluate_authoring_profile_v1(&sources, AUTHORING_CONFIG_FILE, "p", &[]) {
        Ok(_) => panic!("expected the source to fail evaluation"),
        Err(error) => error.to_string(),
    }
}

#[test]
fn insert_documents_label_is_canonical_in_both_walkers() {
    let render = report(
        r#"config target="~/.config" default-profile="p"
module "m" {
    description "d"
    inputs { input "x" type="string" default="v" }
    outputs {
        render "out.txt" format="text" {
            @insert-documents "x"
        }
    }
}
profile "p" { use "m" }
"#,
    );
    assert!(
        render.contains("`@insert-documents` requires a collection<kdl-document>, found `x`"),
        "render-body insertion label changed:\n{render}"
    );

    let config = report(
        r#"config target="~/.config" default-profile="p"
module "m" {
    description "d"
    inputs { input "x" type="string" default="v" }
    outputs {
        render "out.css" format="css" {
            @insert-documents "x"
        }
    }
}
profile "p" { use "m" }
"#,
    );
    assert!(
        config.contains("`@insert-documents` requires a collection<kdl-document>, found `x`"),
        "config-file insertion label changed:\n{config}"
    );
}

#[test]
fn every_emitter_accumulates_diagnostics_in_source_order() {
    let report = report(
        r#"config target="~/.config" default-profile="p"
module "m" {
    description "d"
    outputs {
        render "out.txt" format="text" {
            @line (ref)"a"
            @line (ref)"b"
            @line (ref)"c"
        }
        render "out.json" format="json" {
            key (ref)"d"
            key2 (ref)"e"
        }
        render "out.css" format="css" {
            body { color (ref)"f" }
        }
        render "out.xml" format="xml" {
            root { attr "a" (ref)"g" }
        }
        render "out.ini" format="ini" {
            section { key (ref)"h" }
        }
        render "out.toml" format="toml" {
            key (ref)"i"
        }
        render "out.lua" format="lua" {
            key (ref)"j"
        }
        render "out.kdl" format="kdl" {
            key (ref)"k"
        }
    }
}
profile "p" { use "m" }
"#,
    );
    let messages: Vec<&str> = report
        .lines()
        .filter(|line| line.starts_with("error["))
        .collect();
    assert_eq!(
        messages,
        [
            "error[MALM2102]: `a` is not defined",
            "error[MALM2102]: `b` is not defined",
            "error[MALM2102]: `c` is not defined",
            "error[MALM2102]: `d` is not defined",
            "error[MALM2102]: `e` is not defined",
            "error[MALM2102]: `f` is not defined",
            "error[MALM2102]: `g` is not defined",
            "error[MALM2102]: `h` is not defined",
            "error[MALM2102]: `i` is not defined",
            "error[MALM2102]: `j` is not defined",
            "error[MALM2102]: `k` is not defined",
        ],
        "emitters must report every failure, in source order:\n{report}"
    );
}

#[test]
fn report_rendering_is_byte_exact() {
    let report = report(
        r#"config target="~/.config" default-profile="p"
module "m" {
    description "d"
    inputs { input "x" bogus="1" }
}
profile "p" { use "m" }
"#,
    );
    assert_eq!(
        report,
        "error[MALM1003]: `input` has unknown property `bogus` (allowed: type, default, optional, item-type)\n  \
         --> malm.kdl:4:24\n    \
         |\n  \
         4 |     inputs { input \"x\" bogus=\"1\" }\n    \
         |                        ^^^^^^^^^\n\n\
         error[MALM3001]: profile `p` uses unknown module `m`\n  \
         --> malm.kdl:6:15\n    \
         |\n  \
         6 | profile \"p\" { use \"m\" }\n    \
         |               ^^^^^^^^\n  \
         help: no modules are declared\n\n",
    );
}

#[test]
fn authoring_error_display_is_verbatim() {
    use malm_authoring::{AuthoringErrorV1, MAX_AUTHORING_SOURCE_BYTES};

    assert_eq!(
        AuthoringErrorV1::InvalidSourcePath {
            path: "/abs".to_owned()
        }
        .to_string(),
        "invalid authoring source path \"/abs\""
    );
    assert_eq!(
        AuthoringErrorV1::SourceTooLarge {
            path: "big.kdl".to_owned(),
            byte_len: 9,
        }
        .to_string(),
        format!("authoring source \"big.kdl\" is 9 bytes; limit {MAX_AUTHORING_SOURCE_BYTES}")
    );
    assert_eq!(
        AuthoringErrorV1::TooManySources { limit: 7 }.to_string(),
        "authoring source set exceeds 7 files"
    );
    assert_eq!(
        AuthoringErrorV1::Workspace {
            message: "m".to_owned()
        }
        .to_string(),
        "m"
    );
    assert_eq!(
        AuthoringErrorV1::Evaluation {
            report: "r".to_owned()
        }
        .to_string(),
        "r"
    );
    let error: &dyn std::error::Error = &AuthoringErrorV1::TooManySources { limit: 1 };
    assert!(error.source().is_none(), "source() must stay None");
}

#[test]
fn hybrid_record_boundary_diagnostics_are_pinned() {
    let first_error = |body: &str| {
        report(body)
            .lines()
            .find(|line| line.starts_with("error["))
            .expect("diagnostic headline")
            .to_owned()
    };

    let duplicate = first_error(
        r#"config target="~" default-profile="p"
module "m" {
    description "d"
    types {
        record "entry" { fields { field "enabled" type="bool" required=#true } }
    }
    inputs {
        input "x" type="entry" { default enabled=#true { enabled #false } }
    }
}
profile "p" { use "m" }
"#,
    );
    assert_eq!(
        duplicate,
        "error[MALM1004]: input `x` default: field `enabled` is set twice"
    );

    let aggregate_property = first_error(
        r#"config target="~" default-profile="p"
module "m" {
    description "d"
    types {
        record "nested" { fields { field "label" type="string" } }
        record "entry" { fields { field "nested" type="nested" required=#true } }
    }
    inputs { input "x" type="entry" { default nested="not-a-record" } }
}
profile "p" { use "m" }
"#,
    );
    assert_eq!(
        aggregate_property,
        "error[MALM2005]: input `x` default.nested: aggregate field of type record must be authored as a child node"
    );

    let direct_invoke_field = first_error(
        r#"config target="~" default-profile="p"
module "m" {
    description "d"
    types { variant "argument" discriminator="kind" { case "none" } }
    inputs {
        input "x" type="argument" { default kind="none" { invoke "none" } }
    }
}
profile "p" { use "m" }
"#,
    );
    assert_eq!(
        direct_invoke_field,
        "error[MALM2005]: input `x` default: unknown field `invoke` (variants are closed)"
    );

    let raw_escape = first_error(
        r#"config target="~" default-profile="p"
module "m" {
    description "d"
    inputs { input "document" type="kdl-document" }
}
profile "p" { use "m" { with { document field="value" } } }
"#,
    );
    assert_eq!(
        raw_escape,
        "error[MALM2001]: input `m.document`: expected kdl-document, got raw-record-literal `raw-record-literal`"
    );
}
