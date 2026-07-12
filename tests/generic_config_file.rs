//! Render tests for XML and CSS nodes, KDL output, validator chaining,
//! structural injection, and shared budgets.

mod common;

use common::TestEnv;

fn read_home(env: &TestEnv, path: &str) -> String {
    std::fs::read_to_string(env.home().join(path)).expect("read generated config")
}

#[test]
fn xml_and_css_keep_their_body_vocabulary_under_render() {
    let env = TestEnv::new();
    env.write_config(
        r##"config target="~" default-profile="p"
module "m" {
    outputs {
        render "app.xml" format="xml" declaration=#true {
            root {
                attr "name" "a&b"
                child "hello <world>"
                empty "blank"
                repeat "tag" "one" "two"
                repeat "tag-with-attribute" {
                    attr "kind" "example"
                    value "content"
                }
            }
        }
        render "app.css" format="css" {
            comment "generated"
            field ":root" { field "--accent" "#ffaa00" }
            at-rule "media" "(min-width: 10px)" { field ".item" { color "red" } }
        }
        render "lines" format="line-list" { @line "first"; @line "second" }
        render "scalar" format="scalar" final-newline=#false { @line "one-2" }
    }
}
profile "p" { use "m" }
"##,
    );
    env.apply_ok();
    assert_eq!(
        read_home(&env, "app.xml"),
        concat!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n",
            "<root name=\"a&amp;b\">\n",
            "  <child>\n    hello &lt;world&gt;\n  </child>\n",
            "  <blank />\n",
            "  <tag>one</tag>\n",
            "  <tag>two</tag>\n",
            "  <tag-with-attribute kind=\"example\">\n    content\n  </tag-with-attribute>\n",
            "</root>\n",
        )
    );
    assert_eq!(
        read_home(&env, "app.css"),
        "/* generated */\n:root {\n  --accent: #ffaa00;\n}\n@media (min-width: 10px) {\n  .item {\n    color: red;\n  }\n}\n"
    );
    assert_eq!(read_home(&env, "lines"), "first\nsecond\n");
    assert_eq!(read_home(&env, "scalar"), "one-2");
}

#[test]
fn removed_spellings_and_bad_render_options_fail_clearly() {
    for (output, expected) in [
        (
            "config-file to=\"o\" format=\"json\" { object {} }",
            "`config-file` was removed",
        ),
        (
            "text-file to=\"o\" { emit-line \"x\" }",
            "`text-file` was removed",
        ),
        (
            "kdl-file to=\"o\" dialect=\"v2\" { document { node } }",
            "`kdl-file` was removed",
        ),
        (
            "render \"o\" format=\"hyprlang\" {}",
            "unsupported render format `hyprlang`",
        ),
        (
            "render \"o\" format=\"kdl\" version=3 { node }",
            "version `3` is invalid",
        ),
        (
            "render \"o\" format=\"json\" version=2 { k 1 }",
            "unknown property `version`",
        ),
        (
            "render \"o\" format=\"json\" separator=\"=\" { k 1 }",
            "unknown property `separator`",
        ),
    ] {
        let env = TestEnv::new();
        env.write_config(&format!(
            "config target=\"~\" default-profile=\"p\"\nmodule \"m\" {{ outputs {{ {output} }} }}\nprofile \"p\" {{ use \"m\" }}\n"
        ));
        let failure = env.fail(&["plan"]);
        assert!(
            failure.contains(expected),
            "expected {expected}:\n{failure}"
        );
    }
}

#[test]
fn null_rejecting_formats_fail_on_nested_aggregate_nulls() {
    for (format, expected) in [
        ("toml", "TOML does not support null"),
        ("lua", "Lua config data does not support null"),
    ] {
        let env = TestEnv::new();
        env.write_config(&format!(
            r#"config target="~" default-profile="p"
module "m" {{
    inputs {{
        input "metadata" type="record" {{
            fields {{ field "note" type="string" }}
            default {{}}
        }}
    }}
    outputs {{ render "o" format="{format}" {{ metadata (ref)"metadata" }} }}
}}
profile "p" {{ use "m" }}
"#
        ));
        let failure = env.fail(&["plan"]);
        assert!(failure.contains(expected), "{format}: {failure}");
    }
}

#[test]
fn fstrings_require_non_optional_scalars() {
    let env = TestEnv::new();
    env.write_config(
        r#"config target="~" default-profile="p"
module "m" {
    inputs { input "maybe" type="string" optional=#true }
    outputs {
        render "o.json" format="json" {
            endpoint (f)"https://{{maybe}}"
        }
    }
}
profile "p" { use "m" }
"#,
    );
    let failure = env.fail(&["plan"]);
    assert!(
        failure.contains("does not accept optional<string>"),
        "{failure}"
    );
}

#[test]
fn splice_duplicates_are_rejected_after_expansion() {
    let env = TestEnv::new();
    env.write_config(
        r#"config target="~" default-profile="p"
module "m" {
    inputs {
        input "parts" type="collection" item-type="kdl-document" {
            defaults { item "a" { value 1 }; item "b" { value 2 } }
        }
    }
    outputs {
        render "o.json" format="json" {
            value 0
            @splice "parts"
        }
    }
}
profile "p" { use "m" }
"#,
    );
    let failure = env.fail(&["plan"]);
    assert!(
        failure.contains("duplicate or redefined key `value` after expansion"),
        "{failure}"
    );
}

#[test]
fn kdl_render_uses_direct_nodes_escape_and_validator_chain() {
    let env = TestEnv::new();
    env.write_config(
        r#"config target="~" default-profile="p"
module "m" {
    outputs {
        render "secondary.kdl" format="kdl" version=1 validate="json" {
            enabled #true
        }
    }
}
profile "p" { use "m" }
"#,
    );
    let failure = env.fail(&["plan"]);
    assert!(failure.contains("is not valid json"), "{failure}");

    env.write_repo_file("fragment.kdl", "raw-node \"ok\"\n");
    env.write_config(
        r#"config target="~" default-profile="p"
module "m" {
    fragments {
        fragment "raw" format="kdl-v2" cardinality="one" {
            default "fragment.kdl"
        }
    }
    outputs {
        render "intrinsic.kdl" format="kdl" version=2 {
            @compose fragment="raw"
        }
    }
}
profile "p" { use "m" }
"#,
    );
    env.apply_ok();
    assert_eq!(read_home(&env, "intrinsic.kdl"), "raw-node ok\n");

    env.write_config(
        r#"config target="~" default-profile="p"
module "m" {
    outputs {
        render "literal.kdl" format="kdl" version=2 {
            node "compose" fragment="literal"
        }
    }
}
profile "p" { use "m" }
"#,
    );
    env.apply_ok();
    let output = read_home(&env, "literal.kdl");
    assert!(output.contains("compose fragment=literal"), "{output}");
}

#[test]
fn intrinsic_and_secondary_validators_are_chained() {
    let env = TestEnv::new();
    env.write_config(
        r#"config target="~" default-profile="p"
module "m" {
    outputs {
        render "o.json" format="json" validate="toml" {
            name "valid JSON but not TOML"
        }
    }
}
profile "p" { use "m" }
"#,
    );
    let failure = env.fail(&["plan"]);
    assert!(failure.contains("is not valid toml"), "{failure}");

    env.write_config(
        "config target=\"~\" default-profile=\"p\"\nmodule \"m\" { outputs { render \"o\" format=\"json\" validate=\"unknown\" { k 1 } } }\nprofile \"p\" { use \"m\" }\n",
    );
    let failure = env.fail(&["plan"]);
    assert!(
        failure.contains("unknown artifact validator `unknown`"),
        "{failure}"
    );
}

#[test]
fn target_encoders_reject_structural_injection_and_escape_toml_paths() {
    let env = TestEnv::new();
    env.write_config(
        r##"config target="~" default-profile="p"
module "m" {
    outputs {
        render "safe.toml" format="toml" {
            @lit "a.b" { item 1 }
            plain { @lit "quoted name" { item 2 } }
        }
    }
}
profile "p" { use "m" }
"##,
    );
    env.apply_ok();
    assert_eq!(
        read_home(&env, "safe.toml"),
        "[\"a.b\"]\nitem = 1\n\n[plain]\n[plain.\"quoted name\"]\nitem = 2\n"
    );

    env.write_config(
        r##"config target="~" default-profile="p"
module "m" {
    inputs { input "css-value" type="string" default="red; background: url(bad)" }
    outputs {
        render "unsafe.css" format="css" {
            ".item" { color (ref)"css-value" }
        }
    }
}
profile "p" { use "m" }
"##,
    );
    let failure = env.fail(&["plan"]);
    assert!(
        failure.contains("CSS value contains structural syntax"),
        "{failure}"
    );
}

#[test]
fn target_names_cannot_change_ini_or_xml_structure() {
    for (output, expected) in [
        (
            "render \"o.ini\" format=\"ini\" { @lit \"#disabled\" 1 }",
            "contains structural syntax",
        ),
        (
            "render \"o.xml\" format=\"xml\" { root { empty \"1invalid\" } }",
            "invalid XML name",
        ),
    ] {
        let env = TestEnv::new();
        env.write_config(&format!(
            "config target=\"~\" default-profile=\"p\"\nmodule \"m\" {{ outputs {{ {output} }} }}\nprofile \"p\" {{ use \"m\" }}\n"
        ));
        let failure = env.fail(&["plan"]);
        assert!(
            failure.contains(expected),
            "expected {expected}:\n{failure}"
        );
    }
}

#[test]
fn controls_share_the_global_render_budget() {
    let env = TestEnv::new();
    env.write_config(
        r#"config target="~" default-profile="p"
module "m" {
    outputs {
        render "o" format="key-value" {
            @range "n" from=1 through=100000 { n (ref)"n" }
        }
    }
}
profile "p" { use "m" }
"#,
    );
    let failure = env.fail(&["plan"]);
    assert!(failure.contains("MALM4001"), "{failure}");
}
