//! Integration tests for v2 controls, typed values, codecs, collections,
//! fragments, profile patches, and KDL rendering.

mod common;

use common::TestEnv;

fn read_home(env: &TestEnv, rel: &str) -> String {
    std::fs::read_to_string(env.home().join(rel)).expect("read deployed file")
}

#[test]
fn when_selects_branches_structurally() {
    let env = TestEnv::new();
    env.write_config(
        "config target=\"~\" default-profile=\"p\"\n\
         module \"m\" {\n\
             inputs {\n\
                 input \"flag-on\" type=\"bool\" default=#true\n\
                 input \"flag-off\" type=\"bool\" default=#false\n\
             }\n\
             outputs {\n\
                 render \"out.txt\" format=\"text\" {\n\
                     @line \"start\"\n\
                     @when \"flag-on\" {\n\
                         @line \"on-line\"\n\
                     }\n\
                     @when \"flag-off\" {\n\
                         @line \"off-line\"\n\
                     }\n\
                     @else {\n\
                         @line \"else-line\"\n\
                     }\n\
                     @line \"end\"\n\
                 }\n\
             }\n\
         }\n\
         profile \"p\" { use \"m\" }\n",
    );
    env.apply_ok();
    assert_eq!(
        read_home(&env, "out.txt"),
        "start\non-line\nelse-line\nend\n"
    );
}

#[test]
fn there_is_no_implicit_truthiness() {
    let env = TestEnv::new();
    env.write_config(
        "config target=\"~\" default-profile=\"p\"\n\
         module \"m\" {\n\
             inputs { input \"count\" type=\"int\" default=0 }\n\
             outputs {\n\
                 render \"out.txt\" format=\"text\" {\n\
                     @when \"count\" { @line \"x\" }\n\
                 }\n\
             }\n\
         }\n\
         profile \"p\" { use \"m\" }\n",
    );
    let output = env.fail(&["plan"]);
    assert!(
        output.contains("`when` requires bool") && output.contains("MALM2304"),
        "expected the typed-predicate error, got:\n{output}"
    );
}

#[test]
fn output_conditions_use_the_short_grammar() {
    let env = TestEnv::new();
    env.write_config(
        "config target=\"~\" default-profile=\"p\"\n\
         module \"m\" {\n\
             inputs {\n\
                 input \"enabled\" type=\"bool\" default=#true\n\
                 input \"optional\" type=\"string\" optional=#true\n\
                 input \"items\" type=\"list\" item-type=\"string\" { default \"one\" }\n\
             }\n\
             outputs {\n\
                 when \"enabled\" { render \"enabled\" format=\"text\" { @line \"yes\" } }\n\
                 when-set \"optional\" { render \"set\" format=\"text\" { @line \"bad\" }\n\
                     else { render \"unset\" format=\"text\" { @line \"yes\" } }\n\
                 }\n\
                 when-nonempty \"items\" { render \"nonempty\" format=\"text\" { @line \"yes\" } }\n\
             }\n\
         }\n\
         profile \"p\" { use \"m\" }\n",
    );
    env.apply_ok();
    assert_eq!(read_home(&env, "enabled"), "yes\n");
    assert_eq!(read_home(&env, "unset"), "yes\n");
    assert_eq!(read_home(&env, "nonempty"), "yes\n");
}

#[test]
fn optionals_use_set_and_null_clears_them() {
    let env = TestEnv::new();
    env.write_config(
        "config target=\"~\" default-profile=\"child\"\n\
         module \"m\" {\n\
             inputs { input \"blur-size\" type=\"int\" optional=#true }\n\
             outputs {\n\
                 render \"out.txt\" format=\"text\" {\n\
                     @when-set \"blur-size\" {\n\
                         @line (ref)\"blur-size\"\n\
                     }\n\
                     @else { @line \"unset\" }\n\
                 }\n\
             }\n\
         }\n\
         profile \"parent\" { use \"m\" { with { blur-size 8 } } }\n\
         profile \"child\" {\n\
             extends \"parent\"\n\
             use \"m\" { with { blur-size #null } }\n\
         }\n",
    );
    env.apply_ok();
    assert_eq!(
        read_home(&env, "out.txt"),
        "unset\n",
        "the descendant profile cleared the optional with #null"
    );
    // Clearing the child value must not change its parent.
    env.ok(&["apply", "-y", "--profile", "parent"]);
    assert_eq!(read_home(&env, "out.txt"), "8\n");
}

#[test]
fn each_iterates_lists_in_declared_order() {
    let env = TestEnv::new();
    env.write_config(
        "config target=\"~\" default-profile=\"p\"\n\
         module \"m\" {\n\
             inputs {\n\
                 input \"rules\" type=\"list\" item-type=\"string\" { default \"ruleA\" \"ruleB\" }\n\
                 input \"empty\" type=\"list\" item-type=\"string\"\n\
             }\n\
             outputs {\n\
                 render \"out.txt\" format=\"text\" {\n\
                     @each \"r\" in=\"rules\" {\n\
                         @line (ref)\"r\"\n\
                     }\n\
                     @when-nonempty \"empty\" {\n\
                         @line \"never\"\n\
                     }\n\
                 }\n\
             }\n\
         }\n\
         profile \"p\" { use \"m\" }\n",
    );
    env.apply_ok();
    assert_eq!(read_home(&env, "out.txt"), "ruleA\nruleB\n");
}

#[test]
fn with_block_overrides_list_input_with_multiple_args() {
    let env = TestEnv::new();
    env.write_repo_file("m/a.tpl", "[{{r:text}}]\n");
    env.write_config(
        "config target=\"~\" default-profile=\"p\"\n\
         module \"m\" {\n\
             inputs { input \"rules\" type=\"list\" item-type=\"string\" { default \"unused\" } }\n\
             outputs {\n\
                 render \"out.txt\" format=\"text\" {\n\
                     @each \"r\" in=\"rules\" { @file \"m/a.tpl\" interpolate=#true }\n\
                 }\n\
             }\n\
         }\n\
         profile \"p\" {\n\
             use \"m\" { with { rules \"x\" \"y\" \"z\" } }\n\
         }\n",
    );
    env.apply_ok();
    assert_eq!(read_home(&env, "out.txt"), "[x]\n[y]\n[z]\n");
}

#[test]
fn range_stamps_a_template_per_iteration() {
    let env = TestEnv::new();
    env.write_repo_file("m/tag.tpl", "tag {{n:int}}\n");
    env.write_config(
        "config target=\"~\" default-profile=\"p\"\n\
         module \"m\" {\n\
             outputs {\n\
                 render \"out.txt\" format=\"text\" {\n\
                     @range \"n\" from=1 through=3 {\n\
                         @file \"m/tag.tpl\" interpolate=#true\n\
                     }\n\
                 }\n\
             }\n\
         }\n\
         profile \"p\" { use \"m\" }\n",
    );
    env.apply_ok();
    assert_eq!(read_home(&env, "out.txt"), "tag 1\ntag 2\ntag 3\n");
}

#[test]
fn codecs_encode_typed_scalars() {
    let env = TestEnv::new();
    env.write_repo_file(
        "m/a.tpl",
        "i={{i:int}} f={{f:float}} b={{b:bool}} s={{s:text}}\n\
         toml={{s:toml-string}}\n\
         json={{s:json}}\n\
         sh={{s:shell-word}}\n\
         lit={{literal \"{{verbatim}}\"}}\n",
    );
    env.write_config(
        "config target=\"~\" default-profile=\"p\"\n\
         module \"m\" {\n\
             inputs {\n\
                 input \"i\" type=\"int\" default=7\n\
                 input \"f\" type=\"float\" default=0.5\n\
                 input \"b\" type=\"bool\" default=#true\n\
                 input \"s\" type=\"string\" default=\"a \\\"b\\\"\"\n\
             }\n\
             outputs { render \"out.txt\" format=\"text\" { @file \"m/a.tpl\" interpolate=#true } }\n\
         }\n\
         profile \"p\" { use \"m\" }\n",
    );
    env.apply_ok();
    assert_eq!(
        read_home(&env, "out.txt"),
        "i=7 f=0.5 b=true s=a \"b\"\n\
         toml=\"a \\\"b\\\"\"\n\
         json=\"a \\\"b\\\"\"\n\
         sh='a \"b\"'\n\
         lit={{verbatim}}\n"
            .replace("         ", ""),
    );
}

#[test]
fn toml_array_codec_encodes_typed_lists() {
    let env = TestEnv::new();
    env.write_repo_file(
        "m/config.toml.tpl",
        "names = {{names:toml-array}}\nports = {{ports:toml-array}}\nenabled = {{enabled:toml-array}}\n",
    );
    env.write_config(
        "config target=\"~\" default-profile=\"p\"\n\
         module \"m\" {\n\
             inputs {\n\
                 input \"names\" type=\"list\" item-type=\"string\" { default \"a \\\"b\\\"\" \"c\\\\d\" }\n\
                 input \"ports\" type=\"list\" item-type=\"int\" { default 80 443 }\n\
                 input \"enabled\" type=\"list\" item-type=\"bool\"\n\
             }\n\
             outputs {\n\
                 render \"config.toml\" format=\"text\" validate=\"toml\" { @file \"m/config.toml.tpl\" interpolate=#true }\n\
             }\n\
         }\n\
         profile \"p\" { use \"m\" }\n",
    );
    env.apply_ok();
    assert_eq!(
        read_home(&env, "config.toml"),
        "names = [\"a \\\"b\\\"\", \"c\\\\d\"]\nports = [80, 443]\nenabled = []\n"
    );
}

#[test]
fn toml_array_codec_rejects_scalar_inputs_statically() {
    let env = TestEnv::new();
    env.write_repo_file("m/config.toml.tpl", "value = {{name:toml-array}}\n");
    env.write_config(
        "config target=\"~\" default-profile=\"p\"\n\
         module \"m\" {\n\
             inputs { input \"name\" type=\"string\" default=\"malm\" }\n\
             outputs { render \"config.toml\" format=\"text\" { @file \"m/config.toml.tpl\" interpolate=#true } }\n\
         }\n\
         profile \"p\" { use \"m\" }\n",
    );
    let output = env.fail(&["plan"]);
    assert!(
        output.contains("codec `toml-array` does not accept string"),
        "expected a toml-array type error, got:\n{output}"
    );
}

#[test]
fn templates_reject_control_flow_and_unknown_codecs() {
    let env = TestEnv::new();
    env.write_repo_file("m/a.tpl", "{{#if x}}nope{{/if}}\n");
    env.write_config(
        "config target=\"~\" default-profile=\"p\"\n\
         module \"m\" {\n\
             outputs { render \"out.txt\" format=\"text\" { @file \"m/a.tpl\" interpolate=#true } }\n\
         }\n\
         profile \"p\" { use \"m\" }\n",
    );
    let output = env.fail(&["plan"]);
    assert!(
        output.contains("substitution-only"),
        "expected the substitution-only rejection, got:\n{output}"
    );

    env.write_repo_file("m/a.tpl", "{{x:frobnicate}}\n");
    let output = env.fail(&["plan"]);
    assert!(
        output.contains("unknown codec"),
        "expected an unknown-codec error, got:\n{output}"
    );
}

#[test]
fn module_relative_sources_resolve_against_the_declaring_file() {
    let env = TestEnv::new();
    env.write_repo_file(
        "mods/m/m.kdl",
        "module \"m\" {\n\
             inputs { input \"greeting\" type=\"string\" default=\"hello\" }\n\
             outputs {\n\
                 render \"rendered.txt\" format=\"text\" { @file \"./tpl/a.tpl\" interpolate=#true }\n\
                 file \"./data.txt\" to=\"data.txt\"\n\
                 dir \"./tree\" to=\"tree\"\n\
             }\n\
         }\n",
    );
    env.write_repo_file("mods/m/tpl/a.tpl", "{{greeting:text}}\n");
    env.write_repo_file("mods/m/data.txt", "verbatim\n");
    env.write_repo_file("mods/m/tree/inner.txt", "leaf\n");
    env.write_config(
        "config target=\"~\" default-profile=\"p\"\n\
         include \"mods/m/m.kdl\"\n\
         profile \"p\" { use \"m\" }\n",
    );
    env.apply_ok();
    assert_eq!(read_home(&env, "rendered.txt"), "hello\n");
    assert_eq!(read_home(&env, "data.txt"), "verbatim\n");
    assert_eq!(read_home(&env, "tree/inner.txt"), "leaf\n");
}

#[test]
fn dot_slash_source_rejects_parent_traversal() {
    let env = TestEnv::new();
    env.write_repo_file(
        "mods/m/m.kdl",
        "module \"m\" { outputs { file \"./../../escape.txt\" to=\"x\" } }\n",
    );
    env.write_repo_file("escape.txt", "nope\n");
    env.write_config(
        "config target=\"~\" default-profile=\"p\"\n\
         include \"mods/m/m.kdl\"\n\
         profile \"p\" { use \"m\" }\n",
    );
    let output = env.fail(&["plan"]);
    assert!(
        output.contains(".."),
        "expected a `..` rejection, got:\n{output}"
    );
}

#[test]
fn dot_slash_source_cannot_become_absolute() {
    let env = TestEnv::new();
    env.write_config(
        "config target=\"~\" default-profile=\"p\"\n\
         module \"m\" { outputs { file \".//etc/hostname\" to=\"x\" } }\n\
         profile \"p\" { use \"m\" }\n",
    );
    let output = env.fail(&["plan"]);
    assert!(
        output.contains("must be repository-relative"),
        "expected an absolute source rejection, got:\n{output}"
    );
}

#[test]
fn text_file_composes_multiple_parts_in_order() {
    let env = TestEnv::new();
    env.write_repo_file("m/header.conf", "# header\n");
    env.write_repo_file("m/body.tpl", "value={{v:int}}\n");
    env.write_config(
        "config target=\"~\" default-profile=\"p\"\n\
         module \"m\" {\n\
             inputs { input \"v\" type=\"int\" default=3 }\n\
             outputs {\n\
                 render \"out.conf\" format=\"text\" {\n\
                     @file \"m/header.conf\"\n\
                     @file \"m/body.tpl\" interpolate=#true\n\
                     @line \"tail-end\"\n\
                 }\n\
             }\n\
         }\n\
         profile \"p\" { use \"m\" }\n",
    );
    env.apply_ok();
    assert_eq!(read_home(&env, "out.conf"), "# header\nvalue=3\ntail-end\n");
}

#[test]
fn kdl_config_file_generates_structurally_with_refs_and_splice() {
    let env = TestEnv::new();
    env.write_config(
        "config target=\"~\" default-profile=\"p\"\n\
         module \"m\" {\n\
             inputs {\n\
                 input \"gaps\" type=\"int\" default=12\n\
                 input \"numlock\" type=\"bool\" default=#true\n\
                 input \"bindings\" type=\"collection\" item-type=\"kdl-document\" {\n\
                     defaults {\n\
                         item \"focus-left\" { Mod+H { focus-column-left } }\n\
                         item \"focus-right\" { Mod+L { focus-column-right } }\n\
                     }\n\
                 }\n\
             }\n\
             outputs {\n\
                 render \"niri/config.kdl\" format=\"kdl\" version=1 {\n\
                         layout { gaps (ref)\"gaps\" }\n\
                         input {\n\
                             when \"numlock\" { numlock }\n\
                         }\n\
                         binds { splice \"bindings\" }\n\
                 }\n\
             }\n\
         }\n\
         profile \"p\" {\n\
             use \"m\" {\n\
                 patch {\n\
                     collection \"bindings\" {\n\
                         replace \"focus-left\" { Mod+Left { focus-column-left } }\n\
                         remove \"focus-right\"\n\
                         append \"quit\" { Mod+Q { quit } }\n\
                     }\n\
                 }\n\
             }\n\
         }\n",
    );
    env.apply_ok();
    let out = read_home(&env, "niri/config.kdl");
    assert!(out.contains("gaps 12"), "ref inserted typed scalar:\n{out}");
    assert!(out.contains("numlock"), "when branch kept:\n{out}");
    assert!(
        out.contains("Mod+Left") && !out.contains("Mod+H"),
        "replace preserved position and dropped the old payload:\n{out}"
    );
    assert!(
        !out.contains("focus-column-right"),
        "removed key is gone:\n{out}"
    );
    assert!(out.contains("Mod+Q"), "appended key present:\n{out}");
    // Replacement keeps its position ahead of appended entries.
    let left = out.find("Mod+Left").unwrap();
    let quit = out.find("Mod+Q").unwrap();
    assert!(left < quit, "replace preserves position:\n{out}");
}

#[test]
fn collection_patches_enforce_key_discipline() {
    let env = TestEnv::new();
    let config = |patch: &str| {
        format!(
            "config target=\"~\" default-profile=\"p\"\n\
             module \"m\" {{\n\
                 inputs {{\n\
                     input \"binds\" type=\"collection\" item-type=\"kdl-document\" {{\n\
                         defaults {{ item \"a\" {{ node-a }} }}\n\
                     }}\n\
                 }}\n\
                 outputs {{\n\
                     render \"out.kdl\" format=\"kdl\" version=2 {{\n\
                         root {{ splice \"binds\" }}\n\
                     }}\n\
                 }}\n\
             }}\n\
             profile \"p\" {{ use \"m\" {{ patch {{ collection \"binds\" {{ {patch} }} }} }} }}\n"
        )
    };
    env.write_config(&config("replace \"missing\" { x }"));
    let output = env.fail(&["plan"]);
    assert!(output.contains("key does not exist"), "{output}");

    env.write_config(&config("append \"a\" { x }"));
    let output = env.fail(&["plan"]);
    assert!(output.contains("key already exists"), "{output}");

    env.write_config(&config("remove \"missing\""));
    let output = env.fail(&["plan"]);
    assert!(output.contains("key does not exist"), "{output}");

    env.write_config(&config("remove \"missing\" optional=#true"));
    env.ok(&["plan"]);
}

#[test]
fn fragments_compose_and_profiles_replace_them() {
    let env = TestEnv::new();
    env.write_repo_file("mods/m/fragments/effects.kdl", "shadow {\n    on\n}\n");
    env.write_repo_file(
        "mods/m/m.kdl",
        "module \"m\" {\n\
             fragments {\n\
                 fragment \"effects\" format=\"kdl-v1\" cardinality=\"one\" {\n\
                     default \"./fragments/effects.kdl\"\n\
                 }\n\
             }\n\
             outputs {\n\
                 render \"effects.kdl\" format=\"kdl\" version=1 {\n\
                     compose fragment=\"effects\"\n\
                 }\n\
             }\n\
         }\n",
    );
    // A profile fragment resolves relative to the profile file.
    env.write_repo_file("profiles/astral/effects.kdl", "blur {\n    passes 4\n}\n");
    env.write_repo_file(
        "profiles/astral/astral.kdl",
        "profile \"astral\" {\n\
             use \"m\" {\n\
                 fragments { replace \"effects\" source=\"./effects.kdl\" }\n\
             }\n\
         }\n",
    );
    env.write_config(
        "config target=\"~\" default-profile=\"stock\"\n\
         include \"mods/m/m.kdl\"\n\
         include \"profiles/astral/astral.kdl\"\n\
         profile \"stock\" { use \"m\" }\n",
    );
    env.apply_ok();
    assert_eq!(read_home(&env, "effects.kdl"), "shadow {\n    on\n}\n");

    env.ok(&["apply", "-y", "--profile", "astral"]);
    assert_eq!(read_home(&env, "effects.kdl"), "blur {\n    passes 4\n}\n");
}

#[test]
fn inline_kdl_fragments_follow_profiles_order_and_convert_versions() {
    let env = TestEnv::new();
    env.write_repo_file("legacy.kdl", "legacy true\n");
    env.write_repo_file("legacy-alt.kdl", "replacement false\n");
    env.write_repo_file("modern.kdl", "modern #true\n");
    env.write_config(
        "config target=\"~\" default-profile=\"stock\"\n\
         module \"m\" {\n\
             fragments {\n\
                 fragment \"legacy\" format=\"kdl-v1\" cardinality=\"one\" { default \"legacy.kdl\" }\n\
                 fragment \"modern\" format=\"kdl-v2\" cardinality=\"one\" { default \"modern.kdl\" }\n\
             }\n\
             outputs {\n\
                 render \"v2.kdl\" format=\"kdl\" version=2 {\n\
                         before\n\
                         compose fragment=\"legacy\"\n\
                         after\n\
                 }\n\
                 render \"v1.kdl\" format=\"kdl\" version=1 {\n\
                         first\n\
                         compose fragment=\"modern\"\n\
                         last\n\
                 }\n\
             }\n\
         }\n\
         profile \"stock\" { use \"m\" }\n\
         profile \"alternate\" { use \"m\" {\n\
             fragments { replace \"legacy\" source=\"legacy-alt.kdl\" }\n\
         } }\n",
    );

    env.apply_ok();
    let v2 = read_home(&env, "v2.kdl");
    assert!(
        v2.contains("legacy #true"),
        "v1 fragment converted to v2:\n{v2}"
    );
    assert!(v2.find("before").unwrap() < v2.find("legacy").unwrap());
    assert!(v2.find("legacy").unwrap() < v2.find("after").unwrap());
    let v1 = read_home(&env, "v1.kdl");
    assert!(
        v1.contains("modern true"),
        "v2 fragment converted to v1:\n{v1}"
    );
    assert!(v1.find("first").unwrap() < v1.find("modern").unwrap());
    assert!(v1.find("modern").unwrap() < v1.find("last").unwrap());

    env.ok(&["apply", "-y", "--profile", "alternate"]);
    let replaced = read_home(&env, "v2.kdl");
    assert!(replaced.contains("replacement #false"), "{replaced}");
    assert!(!replaced.contains("legacy"), "{replaced}");
}

#[test]
fn inline_kdl_fragments_expand_controls_refs_and_splices() {
    let env = TestEnv::new();
    env.write_repo_file(
        "body.kdl",
        "when \"enabled\" { selected (ref)\"value\" }\n\
         splice \"nodes\"\n",
    );
    env.write_config(
        "config target=\"~\" default-profile=\"p\"\n\
         module \"m\" {\n\
             inputs {\n\
                 input \"enabled\" type=\"bool\" default=#true\n\
                 input \"value\" type=\"int\" default=7\n\
                  input \"nodes\" type=\"collection\" item-type=\"kdl-document\" {\n\
                      defaults { item \"one\" {\n\
                          when \"enabled\" {\n\
                              from-collection (ref)\"value\"\n\
                              node \"when\" \"literal\" enabled=(ref)\"enabled\" {\n\
                                  node \"splice\" \"child\"\n\
                              }\n\
                          }\n\
                      } }\n\
                 }\n\
             }\n\
             fragments { fragment \"body\" format=\"kdl-v2\" cardinality=\"one\" {\n\
                 default \"body.kdl\"\n\
             } }\n\
             outputs { render \"out.kdl\" format=\"kdl\" version=2 {\n\
                     start\n\
                     compose fragment=\"body\"\n\
                     finish\n\
             } }\n\
         }\n\
         profile \"p\" { use \"m\" }\n",
    );
    env.apply_ok();
    let out = read_home(&env, "out.kdl");
    assert!(out.contains("selected 7"), "{out}");
    assert!(out.contains("from-collection 7"), "{out}");
    assert!(out.contains("when literal enabled=#true"), "{out}");
    assert!(out.contains("splice child"), "{out}");
    assert!(out.find("start").unwrap() < out.find("selected").unwrap());
    assert!(out.find("from-collection").unwrap() < out.find("finish").unwrap());
}

#[test]
fn inline_kdl_fragment_contracts_are_checked_statically() {
    let env = TestEnv::new();
    let config = |fragments: &str, compose: &str| {
        format!(
            "config target=\"~\" default-profile=\"p\"\n\
             module \"m\" {{\n\
                 fragments {{ {fragments} }}\n\
                 outputs {{ render \"out.kdl\" format=\"kdl\" version=2 {{\n\
                     start\n\
                     compose fragment=\"{compose}\"\n\
                 }} }}\n\
             }}\n\
             profile \"p\" {{ use \"m\" }}\n"
        )
    };

    env.write_config(&config("", "missing"));
    let missing = env.fail(&["check", "--all-profiles"]);
    assert!(
        missing.contains("undeclared fragment `missing`"),
        "{missing}"
    );

    env.write_repo_file("plain.txt", "plain\n");
    env.write_config(&config(
        "fragment \"plain\" format=\"text\" cardinality=\"one\" { default \"plain.txt\" }",
        "plain",
    ));
    let format = env.fail(&["check", "--all-profiles"]);
    assert!(
        format.contains("requires format `kdl-v1` or `kdl-v2`"),
        "{format}"
    );

    env.write_repo_file("node.kdl", "node\n");
    env.write_config(&config(
        "fragment \"many\" format=\"kdl-v2\" cardinality=\"many\" { default \"node.kdl\" }",
        "many",
    ));
    let cardinality = env.fail(&["check", "--all-profiles"]);
    assert!(
        cardinality.contains("requires cardinality `one`"),
        "{cardinality}"
    );
}

#[test]
fn inline_kdl_fragments_reject_malformed_and_unconfined_sources() {
    let env = TestEnv::new();
    let config = |source: &str| {
        format!(
            "config target=\"~\" default-profile=\"p\"\n\
             module \"m\" {{\n\
                 fragments {{ fragment \"body\" format=\"kdl-v2\" cardinality=\"one\" {{\n\
                     default \"{source}\"\n\
                 }} }}\n\
                 outputs {{ render \"out.kdl\" format=\"kdl\" version=2 {{\n\
                     compose fragment=\"body\"\n\
                 }} }}\n\
             }}\n\
             profile \"p\" {{ use \"m\" }}\n"
        )
    };

    env.write_repo_file("bad.kdl", "node {\n");
    env.write_config(&config("bad.kdl"));
    let malformed = env.fail(&["plan"]);
    assert!(
        malformed.contains("fragment `body`") && malformed.contains("not valid kdl-v2"),
        "{malformed}"
    );

    env.write_config(&config("../outside.kdl"));
    let escaped = env.fail(&["check", "--all-profiles"]);
    assert!(
        escaped.contains("source must not contain `..`"),
        "{escaped}"
    );
}

#[test]
fn inline_kdl_fragments_detect_include_and_splice_cycles() {
    let env = TestEnv::new();
    env.write_repo_file("loop.kdl", "compose fragment=\"loop\"\n");
    env.write_config(
        "config target=\"~\" default-profile=\"p\"\n\
         module \"m\" {\n\
             fragments { fragment \"loop\" format=\"kdl-v2\" cardinality=\"one\" {\n\
                 default \"loop.kdl\"\n\
             } }\n\
             outputs { render \"out.kdl\" format=\"kdl\" version=2 {\n\
                 start\n\
                 compose fragment=\"loop\"\n\
             } }\n\
         }\n\
         profile \"p\" { use \"m\" }\n",
    );
    let direct = env.fail(&["plan"]);
    assert!(direct.contains("KDL expansion cycle detected"), "{direct}");
    assert!(
        direct.contains("fragment:loop -> fragment:loop"),
        "{direct}"
    );

    env.write_repo_file("loop.kdl", "splice \"docs\"\n");
    env.write_config(
        "config target=\"~\" default-profile=\"p\"\n\
         module \"m\" {\n\
             inputs { input \"docs\" type=\"collection\" item-type=\"kdl-document\" {\n\
                 defaults { item \"back\" { compose fragment=\"loop\" } }\n\
             } }\n\
             fragments { fragment \"loop\" format=\"kdl-v2\" cardinality=\"one\" {\n\
                 default \"loop.kdl\"\n\
             } }\n\
             outputs { render \"out.kdl\" format=\"kdl\" version=2 {\n\
                 start\n\
                 compose fragment=\"loop\"\n\
             } }\n\
         }\n\
         profile \"p\" { use \"m\" }\n",
    );
    let mixed = env.fail(&["plan"]);
    assert!(mixed.contains("KDL expansion cycle detected"), "{mixed}");
    assert!(mixed.contains("collection:docs"), "{mixed}");
}

#[test]
fn inline_kdl_fragment_reads_share_the_render_budget() {
    let env = TestEnv::new();
    env.write_repo_file("node.kdl", "node\n");
    let includes = "compose fragment=\"body\"\n".repeat(1025);
    env.write_config(&format!(
        "config target=\"~\" default-profile=\"p\"\n\
         module \"m\" {{\n\
             fragments {{ fragment \"body\" format=\"kdl-v2\" cardinality=\"one\" {{\n\
                 default \"node.kdl\"\n\
             }} }}\n\
             outputs {{ render \"out.kdl\" format=\"kdl\" version=2 {{\n\
                 {includes}\n\
             }} }}\n\
         }}\n\
         profile \"p\" {{ use \"m\" }}\n"
    ));
    let output = env.fail(&["plan"]);
    assert!(output.contains("MALM4001"), "{output}");
    assert!(output.contains("source files"), "{output}");
}

#[test]
fn records_are_closed_and_field_typed() {
    let env = TestEnv::new();
    env.write_repo_file(
        "m/entry.tpl",
        "label={{entry.label:text}} cmd={{entry.command:shell-word}}\n",
    );
    let config = |with: &str| {
        format!(
            "config target=\"~\" default-profile=\"p\"\n\
             module \"m\" {{\n\
                 inputs {{\n\
                     input \"entry\" type=\"record\" optional=#true {{\n\
                         fields {{\n\
                             field \"label\" type=\"string\" required=#true\n\
                             field \"command\" type=\"string\" required=#true\n\
                             field \"keywords\" type=\"list\" item-type=\"string\"\n\
                         }}\n\
                     }}\n\
                 }}\n\
                 outputs {{\n\
                     render \"out.txt\" format=\"text\" {{\n\
                         @when-set \"entry\" {{ @file \"m/entry.tpl\" interpolate=#true }}\n\
                     }}\n\
                 }}\n\
             }}\n\
             profile \"p\" {{ use \"m\" {{ with {{ {with} }} }} }}\n"
        )
    };
    env.write_config(&config(
        "entry { label \"Restart\"; command \"systemctl reboot\" }",
    ));
    env.apply_ok();
    assert_eq!(
        read_home(&env, "out.txt"),
        "label=Restart cmd='systemctl reboot'\n"
    );

    env.write_config(&config("entry { label \"x\"; bogus \"y\"; command \"c\" }"));
    let output = env.fail(&["plan"]);
    assert!(
        output.contains("unknown field `bogus`"),
        "records are closed:\n{output}"
    );

    env.write_config(&config("entry { label \"x\" }"));
    let output = env.fail(&["plan"]);
    assert!(
        output.contains("missing required field `command`"),
        "{output}"
    );
}

#[test]
fn sibling_profile_conflicts_error_unless_the_child_resolves() {
    let env = TestEnv::new();
    let config = |child_extra: &str| {
        format!(
            "config target=\"~\" default-profile=\"child\"\n\
             module \"m\" {{\n\
                 inputs {{ input \"gaps\" type=\"int\" default=0 }}\n\
                 outputs {{ render \"o\" format=\"text\" {{ @line (ref)\"gaps\" }} }}\n\
             }}\n\
             profile \"a\" {{ use \"m\" {{ with {{ gaps 1 }} }} }}\n\
             profile \"b\" {{ use \"m\" {{ with {{ gaps 2 }} }} }}\n\
             profile \"child\" {{ extends \"a\" \"b\"\n{child_extra} }}\n"
        )
    };
    env.write_config(&config(""));
    let output = env.fail(&["plan"]);
    assert!(
        output.contains("sibling parents"),
        "expected the sibling-conflict error, got:\n{output}"
    );

    env.write_config(&config("use \"m\" { with { gaps 3 } }"));
    env.apply_ok();
    assert_eq!(read_home(&env, "o"), "3\n");
}

#[test]
fn text_file_validation_catches_malformed_output() {
    let env = TestEnv::new();
    env.write_config(
        "config target=\"~\" default-profile=\"p\"\n\
         module \"m\" {\n\
             outputs {\n\
                 render \"o.json\" format=\"text\" validate=\"json\" { @line \"{not json\" }\n\
             }\n\
         }\n\
         profile \"p\" { use \"m\" }\n",
    );
    let output = env.fail(&["plan"]);
    assert!(
        output.contains("not valid json"),
        "expected the artifact validator to fire, got:\n{output}"
    );
}

#[test]
fn generated_kdl_is_reparsed_under_the_target_version() {
    let env = TestEnv::new();
    // V1 output converts the v2 `#true` literal to `true`.
    env.write_config(
        "config target=\"~\" default-profile=\"p\"\n\
         module \"m\" {\n\
             inputs { input \"on\" type=\"bool\" default=#true }\n\
             outputs {\n\
                 render \"o.kdl\" format=\"kdl\" version=1 {\n\
                     feature enabled=(ref)\"on\"\n\
                 }\n\
             }\n\
         }\n\
         profile \"p\" { use \"m\" }\n",
    );
    env.apply_ok();
    let out = read_home(&env, "o.kdl");
    assert!(
        out.contains("enabled=true") && !out.contains("#true"),
        "KDL v1 serialization:\n{out}"
    );
}

#[test]
fn scoped_inputs_report_qualified_names_in_vars() {
    let env = TestEnv::new();
    env.write_config(
        "config target=\"~\" default-profile=\"p\"\n\
         module \"lock-idle\" {\n\
             inputs { input \"blur-size\" type=\"int\" optional=#true }\n\
             outputs {}\n\
         }\n\
         profile \"p\" { use \"lock-idle\" { with { blur-size 8 } } }\n",
    );
    let output = env.ok(&["vars"]);
    assert!(
        output.contains("lock-idle.blur-size"),
        "vars must show qualified names, got:\n{output}"
    );
}

#[test]
fn budgets_bound_total_expansion_work() {
    let env = TestEnv::new();
    env.write_config(
        "config target=\"~\" default-profile=\"p\"\n\
         module \"m\" {\n\
             outputs {\n\
                 render \"o\" format=\"text\" {\n\
                     @range \"i\" from=1 through=100000 { @line \"x\" }\n\
                 }\n\
             }\n\
         }\n\
         profile \"p\" { use \"m\" }\n",
    );
    let output = env.fail(&["plan"]);
    assert!(
        output.contains("MALM4001"),
        "expected a budget error, got:\n{output}"
    );
    assert_eq!(
        output.matches("MALM4001").count(),
        1,
        "expansion must stop after the first budget error:\n{output}"
    );
}

#[test]
fn enums_and_optional_record_fields_refine_inside_set_branches() {
    let env = TestEnv::new();
    env.write_config(
        "config target=\"~\" default-profile=\"p\"\n\
         module \"m\" {\n\
             inputs {\n\
                 input \"mode\" type=\"enum\" optional=#true default=\"dark\" {\n\
                     values \"dark\" \"light\"\n\
                 }\n\
                 input \"entry\" type=\"record\" {\n\
                     fields {\n\
                         field \"label\" type=\"string\" required=#true\n\
                         field \"note\" type=\"string\"\n\
                     }\n\
                     default { label \"main\" }\n\
                 }\n\
             }\n\
             outputs {\n\
                 render \"typed.kdl\" format=\"kdl\" version=2 {\n\
                         (target.node)root (target.entry)\"keep\" {\n\
                             when-set \"mode\" {\n\
                                 selected \"{{mode:text}}\"\n\
                             }\n\
                             when-set \"entry.note\" {\n\
                                 note \"{{entry.note:text}}\"\n\
                                 else { absent }\n\
                             }\n\
                         }\n\
                 }\n\
             }\n\
         }\n\
         profile \"p\" { use \"m\" }\n",
    );
    env.apply_ok();
    let output = read_home(&env, "typed.kdl");
    assert!(output.contains("(target.node)root"), "{output}");
    assert!(output.contains("(target.entry)keep"), "{output}");
    assert!(output.contains("selected dark"), "{output}");
    assert!(output.contains("absent"), "{output}");
}

#[test]
fn optional_interpolation_requires_a_set_guard() {
    let env = TestEnv::new();
    env.write_config(
        "config target=\"~\" default-profile=\"p\"\n\
         module \"m\" {\n\
             inputs { input \"name\" type=\"string\" optional=#true }\n\
             outputs {\n\
                 render \"o.kdl\" format=\"kdl\" version=2 {\n\
                     value \"{{name:text}}\"\n\
                 }\n\
             }\n\
         }\n\
         profile \"p\" { use \"m\" }\n",
    );
    let output = env.fail(&["plan"]);
    assert!(
        output.contains("codec `text` does not accept optional<string>"),
        "{output}"
    );
}

#[test]
fn enum_values_are_checked() {
    let env = TestEnv::new();
    env.write_config(
        "config target=\"~\" default-profile=\"p\"\n\
         module \"m\" {\n\
             inputs { input \"mode\" type=\"enum\" { values \"dark\" \"light\" } }\n\
             outputs {}\n\
         }\n\
         profile \"p\" { use \"m\" { with { mode \"blue\" } } }\n",
    );
    let output = env.fail(&["plan"]);
    assert!(
        output.contains("enum value `blue` is not allowed"),
        "{output}"
    );
}

#[test]
fn aggregate_default_shapes_are_strict() {
    let env = TestEnv::new();
    env.write_config(
        "config target=\"~\" default-profile=\"p\"\n\
         module \"m\" {\n\
             inputs { input \"name\" type=\"string\" { default \"not-valid\" } }\n\
             outputs {}\n\
         }\n\
         profile \"p\" { use \"m\" }\n",
    );
    let output = env.fail(&["plan"]);
    assert!(output.contains("unknown child `default`"), "{output}");
}

#[test]
fn profile_diamonds_converge_after_a_branch_resolves_its_value() {
    let env = TestEnv::new();
    env.write_config(
        "config target=\"~\" default-profile=\"child\"\n\
         module \"m\" {\n\
             inputs { input \"value\" type=\"int\" default=0 }\n\
             outputs { render \"o\" format=\"text\" { @line (ref)\"value\" } }\n\
         }\n\
         profile \"a\" { use \"m\" { with { value 1 } } }\n\
         profile \"b\" { use \"m\" { with { value 2 } } }\n\
         profile \"resolved-b\" {\n\
             extends \"b\"\n\
             use \"m\" { with { value 1 } }\n\
         }\n\
         profile \"child\" { extends \"a\" \"resolved-b\" }\n",
    );
    env.apply_ok();
    assert_eq!(read_home(&env, "o"), "1\n");
}

#[test]
fn duplicate_profiles_require_explicit_extend_profile() {
    let env = TestEnv::new();
    let base = "config target=\"~\" default-profile=\"p\"\nmodule \"m\" { outputs {} }\n";
    env.write_config(&format!(
        "{base}profile \"p\" {{ use \"m\" }}\nprofile \"p\" {{ use \"m\" }}\n"
    ));
    let output = env.fail(&["plan"]);
    assert!(output.contains("profile `p` is declared twice"), "{output}");

    env.write_config(&format!(
        "{base}profile \"p\" {{}}\nextend-profile \"p\" {{ use \"m\" }}\n"
    ));
    env.ok(&["plan"]);
}

#[test]
fn duplicate_globals_are_explicit_errors() {
    let env = TestEnv::new();
    env.write_config(
        "config target=\"~\" default-profile=\"p\"\n\
         variables { global.color \"red\" }\n\
         variables { global.color \"blue\" }\n\
         profile \"p\" {}\n",
    );
    let output = env.fail(&["plan"]);
    assert!(
        output.contains("global `global.color` is declared twice"),
        "{output}"
    );

    env.write_config(
        "config target=\"~\" default-profile=\"p\"\n\
         variables { global.color \"red\" }\n\
         variables { global.color \"blue\" override=#true }\n\
         profile \"p\" {}\n",
    );
    env.ok(&["plan"]);

    env.write_config(
        "config target=\"~\" default-profile=\"p\"\n\
         variables { global.color \"red\" }\n\
         variables { global.color 2 override=#true }\n\
         profile \"p\" {}\n",
    );
    let output = env.fail(&["plan"]);
    assert!(output.contains("override changes its type"), "{output}");
}

#[test]
fn integer_to_float_coercion_is_exact() {
    let env = TestEnv::new();
    env.write_config(
        "config target=\"~\" default-profile=\"p\"\n\
         module \"m\" {\n\
             inputs { input \"value\" type=\"float\" default=9007199254740993 }\n\
             outputs {}\n\
         }\n\
         profile \"p\" { use \"m\" }\n",
    );
    let output = env.fail(&["plan"]);
    assert!(
        output.contains("cannot be represented exactly as a float"),
        "{output}"
    );
}

#[test]
fn structural_kdl_rejects_out_of_range_ranges_at_the_source() {
    let env = TestEnv::new();
    env.write_config(
        "config target=\"~\" default-profile=\"p\"\n\
         module \"m\" {\n\
             outputs {\n\
                 render \"o.kdl\" format=\"kdl\" version=2 {\n\
                         range \"n\" from=0 through=9223372036854775808 { value }\n\
                 }\n\
             }\n\
         }\n\
         profile \"p\" { use \"m\" }\n",
    );
    let output = env.fail(&["plan"]);
    assert!(
        output.contains("out of range for a 64-bit integer"),
        "{output}"
    );
    assert!(output.contains("through=9223372036854775808"), "{output}");
}

#[test]
fn direct_kdl_splice_cycles_are_rejected() {
    let env = TestEnv::new();
    env.write_config(
        "config target=\"~\" default-profile=\"p\"\n\
         module \"m\" {\n\
             inputs {\n\
                 input \"docs\" type=\"collection\" item-type=\"kdl-document\" {\n\
                     defaults {\n\
                         item \"self\" { splice \"docs\" }\n\
                     }\n\
                 }\n\
             }\n\
             outputs {\n\
                 render \"out.kdl\" format=\"kdl\" version=2 {\n\
                     root { splice \"docs\" }\n\
                 }\n\
             }\n\
         }\n\
         profile \"p\" { use \"m\" }\n",
    );
    let output = env.fail(&["plan"]);
    assert!(output.contains("splice cycle detected"), "{output}");
}

#[test]
fn indirect_kdl_splice_cycles_are_rejected() {
    let env = TestEnv::new();
    env.write_config(
        "config target=\"~\" default-profile=\"p\"\n\
         module \"m\" {\n\
             inputs {\n\
                 input \"a\" type=\"collection\" item-type=\"kdl-document\" {\n\
                     defaults { item \"a\" { splice \"b\" } }\n\
                 }\n\
                 input \"b\" type=\"collection\" item-type=\"kdl-document\" {\n\
                     defaults { item \"b\" { splice \"a\" } }\n\
                 }\n\
             }\n\
             outputs {\n\
                 render \"out.kdl\" format=\"kdl\" version=2 {\n\
                     root { splice \"a\" }\n\
                 }\n\
             }\n\
         }\n\
         profile \"p\" { use \"m\" }\n",
    );
    let output = env.fail(&["plan"]);
    assert!(output.contains("splice cycle detected"), "{output}");
}

#[test]
fn collection_documents_are_structurally_validated_at_declaration() {
    let env = TestEnv::new();
    env.write_config(
        "config target=\"~\" default-profile=\"p\"\n\
         module \"m\" {\n\
             inputs {\n\
                 input \"docs\" type=\"collection\" item-type=\"kdl-document\" {\n\
                     defaults { item \"bad\" { else { literal } } }\n\
                 }\n\
             }\n\
             outputs {}\n\
         }\n\
         profile \"p\" { use \"m\" }\n",
    );
    let output = env.fail(&["check", "--all-profiles"]);
    assert!(output.contains("`else` is not valid here"), "{output}");
    assert!(
        output.contains("while validating collection default"),
        "{output}"
    );
}

#[test]
fn collection_patch_documents_reject_misplaced_controls() {
    let env = TestEnv::new();
    env.write_config(
        "config target=\"~\" default-profile=\"p\"\n\
         module \"m\" {\n\
             inputs {\n\
                 input \"docs\" type=\"collection\" item-type=\"kdl-document\" {\n\
                      defaults { item \"ok\" { ordinary } }\n\
                 }\n\
             }\n\
             outputs {}\n\
         }\n\
         profile \"p\" { use \"m\" {\n\
             patch { collection \"docs\" { append \"bad\" { else { literal } } } }\n\
         } }\n",
    );
    let output = env.fail(&["check", "--all-profiles"]);
    assert!(output.contains("`else` is not valid here"), "{output}");
    assert!(
        output.contains("while validating collection patch append"),
        "{output}"
    );
}

#[test]
fn fragment_formats_are_validated_at_declaration() {
    let env = TestEnv::new();
    env.write_config(
        "config target=\"~\" default-profile=\"p\"\n\
         module \"m\" {\n\
             fragments { fragment \"f\" format=\"made-up\" cardinality=\"many\" }\n\
             outputs {}\n\
         }\n\
         profile \"p\" { use \"m\" }\n",
    );
    let output = env.fail(&["check", "--all-profiles"]);
    assert!(
        output.contains("declares unknown format `made-up`"),
        "{output}"
    );
    assert!(output.contains("known validators"), "{output}");

    env.write_repo_file("bad.json", "{not-json");
    env.write_config(
        "config target=\"~\" default-profile=\"p\"\n\
         module \"m\" {\n\
             fragments { fragment \"f\" format=\"json\" cardinality=\"many\" {\n\
                 default \"bad.json\"\n\
             } }\n\
             outputs {}\n\
         }\n\
         profile \"p\" { use \"m\" }\n",
    );
    let output = env.fail(&["check", "--all-profiles"]);
    assert!(
        output.contains("source") && output.contains("not valid json"),
        "{output}"
    );
}

#[test]
fn abstract_profiles_are_checked_discoverable_and_not_selectable() {
    let env = TestEnv::new();
    env.write_config(
        "config target=\"~\" default-profile=\"concrete\"\n\
         module \"m\" { outputs { render \"out\" format=\"text\" { @raw \"ok\" } } }\n\
         profile \"base\" abstract=#true { use \"m\" }\n\
         profile \"concrete\" { extends \"base\" }\n",
    );
    env.ok(&["check", "--all-profiles"]);
    let profiles = env.ok(&["profiles"]);
    assert!(
        profiles.contains("base") && profiles.contains("abstract"),
        "{profiles}"
    );
    let selectable = env.ok(&["profiles", "--selectable"]);
    assert!(!selectable.contains("base"), "{selectable}");
    assert!(selectable.contains("concrete"), "{selectable}");

    let output = env.fail(&["plan", "--profile", "base"]);
    assert!(output.contains("profile `base` is abstract"), "{output}");
    let output = env.fail(&["apply", "-y", "--profile", "base"]);
    assert!(output.contains("profile `base` is abstract"), "{output}");
    let render_dir = env.repo().join("abstract-render");
    let output = env.fail(&[
        "render",
        "--output",
        render_dir.to_str().unwrap(),
        "--profile",
        "base",
    ]);
    assert!(output.contains("profile `base` is abstract"), "{output}");
    env.ok(&["plan", "--profile", "concrete"]);
}

#[test]
fn conditional_requirements_are_typed_and_evaluated_per_instance() {
    let env = TestEnv::new();
    let missing = env.repo().join("definitely-missing-requirement");
    env.write_config(&format!(
        "config target=\"~\" default-profile=\"off\"\n\
         module \"m\" {{\n\
             inputs {{ input \"needed\" type=\"bool\" default=#false }}\n\
             requires {{\n\
                 when \"needed\" {{ file \"{}\" }}\n\
             }}\n\
             outputs {{}}\n\
         }}\n\
         profile \"off\" {{ use \"m\" }}\n\
         profile \"on\" {{ use \"m\" {{ with {{ needed #true }} }} }}\n",
        missing.display()
    ));
    let off = env.ok(&["doctor", "--profile", "off"]);
    assert!(off.contains("no module declares requirements"), "{off}");
    let on = env.fail(&["doctor", "--profile", "on"]);
    assert!(
        on.contains("MISSING") && on.contains("definitely-missing"),
        "{on}"
    );

    env.write_config(
        "config target=\"~\" default-profile=\"p\"\n\
         module \"m\" {\n\
             inputs { input \"count\" type=\"int\" default=1 }\n\
             requires { when \"count\" { feature \"x\" } }\n\
             outputs {}\n\
         }\n\
         profile \"p\" { use \"m\" }\n",
    );
    let output = env.fail(&["check", "--all-profiles"]);
    assert!(output.contains("`when` requires bool"), "{output}");
}

#[test]
fn check_module_compiles_every_profile_that_uses_it() {
    let env = TestEnv::new();
    env.write_config(
        "config target=\"~\" default-profile=\"good\"\n\
         module \"m\" {\n\
             inputs { input \"broken\" type=\"bool\" default=#false }\n\
             outputs { render \"out.json\" format=\"text\" validate=\"json\" {\n\
                 @when \"broken\" { @raw \"{\" }\n\
                 @else { @raw \"{}\" }\n\
             } }\n\
         }\n\
         profile \"good\" { use \"m\" }\n\
         profile \"bad\" { use \"m\" { with { broken #true } } }\n",
    );
    let output = env.fail(&["check", "--module", "m"]);
    assert!(output.contains("profile bad"), "{output}");
    assert!(output.contains("not valid json"), "{output}");
}
