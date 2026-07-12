//! Golden output tests for rendering one body vocabulary in six formats.

mod common;

use common::TestEnv;

fn read_home(env: &TestEnv, path: &str) -> String {
    std::fs::read_to_string(env.home().join(path)).expect("read generated config")
}

#[test]
fn six_formats_render_the_binds_example() {
    let env = TestEnv::new();
    let body = r#"
            binds {
                screenshot (ref)"screenshot-key"
                launcher "SUPER+A"
                terminal "SUPER+RETURN"
            }
"#;
    let mut config = String::from(
        "config target=\"~\" default-profile=\"p\"\n\
         module \"m\" {\n\
             inputs { input \"screenshot-key\" type=\"string\" default=\"ALT+SPACE\" }\n\
             outputs {\n",
    );
    for (path, format) in [
        ("binds.json", "json"),
        ("binds.toml", "toml"),
        ("binds.kdl", "kdl"),
        ("binds.ini", "ini"),
        ("binds.conf", "text"),
        ("binds.lua", "lua"),
    ] {
        config.push_str(&format!(
            "        render \"{path}\" format=\"{format}\" {{{body}        }}\n"
        ));
    }
    config.push_str("    }\n}\nprofile \"p\" { use \"m\" }\n");
    env.write_config(&config);
    env.apply_ok();

    assert_eq!(
        read_home(&env, "binds.json"),
        concat!(
            "{\n",
            "  \"binds\": {\n",
            "    \"screenshot\": \"ALT+SPACE\",\n",
            "    \"launcher\": \"SUPER+A\",\n",
            "    \"terminal\": \"SUPER+RETURN\"\n",
            "  }\n",
            "}\n",
        )
    );
    assert_eq!(
        read_home(&env, "binds.toml"),
        concat!(
            "[binds]\n",
            "screenshot = \"ALT+SPACE\"\n",
            "launcher = \"SUPER+A\"\n",
            "terminal = \"SUPER+RETURN\"\n",
        )
    );
    assert_eq!(
        read_home(&env, "binds.ini"),
        concat!(
            "[binds]\n",
            "screenshot=ALT+SPACE\n",
            "launcher=SUPER+A\n",
            "terminal=SUPER+RETURN\n",
        )
    );
    assert_eq!(
        read_home(&env, "binds.conf"),
        concat!(
            "binds {\n",
            "    screenshot = ALT+SPACE\n",
            "    launcher = SUPER+A\n",
            "    terminal = SUPER+RETURN\n",
            "}\n",
        )
    );
    assert_eq!(
        read_home(&env, "binds.lua"),
        concat!(
            "return {\n",
            "    binds = {\n",
            "        screenshot = \"ALT+SPACE\",\n",
            "        launcher = \"SUPER+A\",\n",
            "        terminal = \"SUPER+RETURN\",\n",
            "    },\n",
            "}\n",
        )
    );
    // KDL v2 emits bare strings where its grammar permits them.
    assert_eq!(
        read_home(&env, "binds.kdl"),
        concat!(
            "binds {\n",
            "    screenshot ALT+SPACE\n",
            "    launcher SUPER+A\n",
            "    terminal SUPER+RETURN\n",
            "}\n",
        )
    );
}

#[test]
fn toml_arrays_props_and_named_sections() {
    let env = TestEnv::new();
    env.write_config(
        r##"config target="~" default-profile="p"
module "m" {
    outputs {
        render "walker.toml" format="toml" {
            providers {
                max_results 256
                default "desktopapplications" "websearch"
                prefixes {
                    - prefix="/" provider="providerlist"
                    - prefix="." provider="files"
                }
            }
            keybinds "extra" {
                quick_activate "F1"
            }
            position x=0 y=5
        }
    }
}
profile "p" { use "m" }
"##,
    );
    env.apply_ok();
    assert_eq!(
        read_home(&env, "walker.toml"),
        concat!(
            "position = { x = 0, y = 5 }\n",
            "\n[providers]\n",
            "max_results = 256\n",
            "default = [\"desktopapplications\", \"websearch\"]\n",
            "\n[[providers.prefixes]]\n",
            "prefix = \"/\"\n",
            "provider = \"providerlist\"\n",
            "\n[[providers.prefixes]]\n",
            "prefix = \".\"\n",
            "provider = \"files\"\n",
            "\n[keybinds.extra]\n",
            "quick_activate = \"F1\"\n",
        )
    );
}

#[test]
fn controls_and_annotations_compose_across_formats() {
    let env = TestEnv::new();
    env.write_config(
        r##"config target="~" default-profile="p"
module "m" {
    inputs {
        input "names" type="list" item-type="string" { default "one" "two" }
        input "dark" type="bool" default=#true
        input "blur" type="int" optional=#true
        input "w" type="int" default=3840
        input "h" type="int" default=2400
        input "r" type="float" default=120.001
        input "extra" type="collection" item-type="kdl-document" {
            defaults {
                item "xkb" { xkb_layout "us" }
            }
        }
    }
    outputs {
        render "flags.conf" format="text" separator="=" layout="flat" {
            @each "b" in="names" { bind (ref)"b" }
            @range "i" from=1 through=3 { ws (f)"tag-{{i}}" }
            @when "dark" { theme "dark" }
            @else { theme "light" }
            blur_size (ref?)"blur"
            @splice "extra"
            @comment "done"
        }
        render "each.json" format="json" {
            bind {
                @each "b" in="names" { - (ref)"b" }
            }
        }
        render "kanshi.conf" format="text" separator=" " {
            profile "docked" {
                output "eDP-1" {
                    mode (f)"{{w}}x{{h}}@{{r}}Hz"
                    scale 2.5
                }
            }
        }
        render "quoted.conf" format="text" {
            color_theme "current" @quote="double"
            truecolor #true
        }
        render "prog.lua" format="lua" {
            hooks {
                on_start (raw)"function() require('gnist').start() end"
            }
        }
    }
}
profile "p" { use "m" }
"##,
    );
    env.apply_ok();

    assert_eq!(
        read_home(&env, "flags.conf"),
        concat!(
            "bind=one\n",
            "bind=two\n",
            "ws=tag-1\n",
            "ws=tag-2\n",
            "ws=tag-3\n",
            "theme=dark\n",
            "xkb_layout=us\n",
            "# done\n",
        )
    );
    assert_eq!(
        read_home(&env, "each.json"),
        concat!(
            "{\n",
            "  \"bind\": [\n",
            "    \"one\",\n",
            "    \"two\"\n",
            "  ]\n",
            "}\n",
        )
    );
    assert_eq!(
        read_home(&env, "kanshi.conf"),
        concat!(
            "profile docked {\n",
            "    output eDP-1 {\n",
            "        mode 3840x2400@120.001Hz\n",
            "        scale 2.5\n",
            "    }\n",
            "}\n",
        )
    );
    assert_eq!(
        read_home(&env, "quoted.conf"),
        concat!("color_theme = \"current\"\n", "truecolor = true\n",)
    );
    assert_eq!(
        read_home(&env, "prog.lua"),
        concat!(
            "return {\n",
            "    hooks = {\n",
            "        on_start = function() require('gnist').start() end,\n",
            "    },\n",
            "}\n",
        )
    );
}

#[test]
fn record_collections_spread_and_equality() {
    let env = TestEnv::new();
    env.write_config(
        r##"config target="~" default-profile="p"
module "m" {
    inputs {
        input "spawn-binds" type="collection" item-type="record" {
            fields {
                field "chord" type="string" required=#true
                field "cmd" type="string" required=#true
            }
            defaults {
                item "menu" chord="Space" cmd="gnist-menu"
                item "term" { chord "Return"; cmd "kitty" }
            }
        }
        input "settings" type="record" {
            fields {
                field "border-px" type="int" required=#true
                field "smart-gaps" type="bool" required=#true
                field "extra-opt" type="string"
            }
            default { border-px 3; smart-gaps #true }
        }
        input "compositor" type="enum" default="mango" { values "mango" "niri" }
    }
    outputs {
        render "binds.conf" format="text" separator="=" layout="flat" {
            @each "b" in="spawn-binds" { bind (f)"{{b.key}},{{b.chord}},{{b.cmd}}" }
        }
        render "settings.conf" format="text" separator="=" layout="flat" {
            @spread "settings" case="snake_case"
        }
        render "settings.toml" format="toml" {
            window { @spread "settings" case="snake_case" }
        }
        render "which.conf" format="text" separator="=" layout="flat" {
            @when "compositor" is="mango" { engine "mango-ipc" }
            @else { engine "other" }
            @when "compositor" is-not="niri" { not_niri #true }
        }
    }
}
profile "p" {
    use "m" {
        patch { collection "spawn-binds" { replace "menu" chord="A" cmd="walker" } }
    }
}
"##,
    );
    env.apply_ok();
    assert_eq!(
        read_home(&env, "binds.conf"),
        "bind=menu,A,walker\nbind=term,Return,kitty\n"
    );
    assert_eq!(
        read_home(&env, "settings.conf"),
        "border_px=3\nsmart_gaps=true\n"
    );
    assert_eq!(
        read_home(&env, "settings.toml"),
        "[window]\nborder_px = 3\nsmart_gaps = true\n"
    );
    assert_eq!(
        read_home(&env, "which.conf"),
        "engine=mango-ipc\nnot_niri=true\n"
    );
}

#[test]
fn outputs_directives_fstring_paths_and_kdl_aliases() {
    let env = TestEnv::new();
    env.write_config(
        r##"config target="~" default-profile="p"
module "m" {
    inputs {
        input "gtk-versions" type="list" item-type="string" { default "3.0" "4.0" }
        input "engine" type="enum" default="awww" { values "awww" "swww" }
        input "numlock" type="bool" default=#true
    }
    requires {
        @when "engine" is="swww" { command "definitely-not-installed-xyz" }
    }
    outputs {
        @each "v" in="gtk-versions" {
            render (f)"gtk-{{v}}/settings.ini" format="ini" {
                Settings { gtk-theme-name "adw" }
            }
        }
        render "niri.kdl" format="kdl" {
            input {
                @when "numlock" { numlock }
            }
        }
    }
}
profile "p" { use "m" }
"##,
    );
    env.apply_ok();
    for version in ["3.0", "4.0"] {
        assert_eq!(
            read_home(&env, &format!("gtk-{version}/settings.ini")),
            "[Settings]\ngtk-theme-name=adw\n"
        );
    }
    assert_eq!(read_home(&env, "niri.kdl"), "input {\n    numlock\n}\n");
}

#[test]
fn file_compose_and_lua_program_mode() {
    let env = TestEnv::new();
    env.write_repo_file("banner.txt", "## banner ##\n");
    env.write_repo_file("motd.tpl", "hello {{user}}\n");
    env.write_repo_file("extras.conf", "extra=1\n");
    env.write_config(
        r##"config target="~" default-profile="p"
module "m" {
    inputs {
        input "user" type="string" default="christian"
        input "mod-key" type="string" default="SUPER"
        input "terminal-cmd" type="string" default="kitty -e 'x'"
    }
    fragments {
        fragment "extras" format="text" cardinality="one" { default "extras.conf" }
    }
    outputs {
        render "app.conf" format="text" separator="=" layout="flat" {
            greeting "hi"
            @file "banner.txt"
            @file "motd.tpl" interpolate=#true
            @compose "extras"
        }
        render "hooks.lua" format="lua" {
            @raw "local hl = require('hyprland')"
            @line (f)"hl.bind(\"{{mod-key}} + Return\", hl.dsp.exec_cmd({{terminal-cmd:lua}}))"
            @raw "hl.done()"
        }
    }
}
profile "p" { use "m" }
"##,
    );
    env.apply_ok();
    assert_eq!(
        read_home(&env, "app.conf"),
        concat!(
            "greeting=hi\n",
            "## banner ##\n",
            "hello christian\n",
            "extra=1\n",
        )
    );
    assert_eq!(
        read_home(&env, "hooks.lua"),
        concat!(
            "local hl = require('hyprland')\n",
            "hl.bind(\"SUPER + Return\", hl.dsp.exec_cmd(\"kitty -e 'x'\"))\n",
            "hl.done()\n",
        )
    );
}

#[test]
fn patch_set_and_unset_record_fields_across_layers() {
    let env = TestEnv::new();
    env.write_config(
        r##"config target="~" default-profile="p"
module "m" {
    inputs {
        input "settings" type="record" {
            fields {
                field "border-px" type="int" required=#true
                field "extra-opt" type="string"
            }
            default { border-px 3 }
        }
    }
    outputs {
        render "s.conf" format="text" separator="=" layout="flat" {
            @spread "settings" case="snake_case"
        }
    }
}
profile "base" {
    use "m" { patch { set "settings.extra-opt" "from-base" } }
}
profile "p" {
    extends "base"
    use "m" { patch { set "settings.border-px" 5; unset "settings.extra-opt" } }
}
"##,
    );
    env.apply_ok();
    assert_eq!(read_home(&env, "s.conf"), "border_px=5\n");
}
