mod common;

use std::collections::BTreeSet;

use common::TestEnv;

const INVENTORY: &str = include_str!("../docs/cli-command-inventory.txt");

fn inventory() -> BTreeSet<&'static str> {
    INVENTORY.lines().filter(|line| !line.is_empty()).collect()
}

fn direct_children<'a>(paths: &'a BTreeSet<&str>, parent: &str) -> BTreeSet<&'a str> {
    paths
        .iter()
        .filter_map(|path| {
            let remainder = if parent.is_empty() {
                *path
            } else {
                path.strip_prefix(parent)?.strip_prefix(' ')?
            };
            (!remainder.contains(' ')).then_some(remainder)
        })
        .collect()
}

fn help_commands(help: &str) -> BTreeSet<&str> {
    let commands = help
        .split_once("Commands:\n")
        .expect("Clap help has a Commands section")
        .1
        .split_once("\nOptions:")
        .expect("Clap help has an Options section")
        .0;
    commands
        .lines()
        .filter_map(|line| line.split_whitespace().next())
        .collect()
}

#[test]
fn checked_in_inventory_matches_clap_help_recursively() {
    let env = TestEnv::new();
    let paths = inventory();
    let groups = std::iter::once("")
        .chain(paths.iter().copied().filter(|path| {
            let prefix = format!("{path} ");
            paths.iter().any(|candidate| candidate.starts_with(&prefix))
        }))
        .collect::<Vec<_>>();

    for group in groups {
        let mut arguments = group.split_whitespace().collect::<Vec<_>>();
        arguments.push("--help");
        let output = env.malm(&arguments);
        assert!(
            output.status.success(),
            "malm {group} --help failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(output.stderr.is_empty());
        let help = String::from_utf8(output.stdout).unwrap();
        assert_eq!(
            help_commands(&help),
            direct_children(&paths, group),
            "inventory differs below {group:?}"
        );
    }

    let root_help = env.malm(&["--help"]);
    let root_help = String::from_utf8(root_help.stdout).unwrap();
    assert!(!root_help.contains("experimental"));
    assert!(!root_help.contains("legacy"));
    assert!(!root_help.contains(" v1"));
    assert!(!env.state_root().exists());
}

#[test]
fn every_inventoried_group_and_leaf_has_direct_help() {
    let env = TestEnv::new();
    for operation in inventory() {
        let mut arguments = operation.split_whitespace().collect::<Vec<_>>();
        arguments.push("--help");
        let output = env.malm(&arguments);
        assert!(
            output.status.success(),
            "malm {operation} --help failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(output.stderr.is_empty());
    }
    assert!(!env.state_root().exists());
}

#[test]
fn source_lock_help_pins_the_supported_host_capability_shape() {
    let env = TestEnv::new();
    let output = env.malm(&["source", "lock", "create", "--help"]);
    assert!(output.status.success());
    let help = String::from_utf8(output.stdout).unwrap();
    assert!(help.contains("--source <PACK_ROOT>"));
    assert!(help.contains("[default: .]"));
    assert!(help.contains("--git-executable <ABSOLUTE_PATH>"));
    assert!(help.contains("--allow-local <LOCATOR>"));
    assert!(help.contains("--allow-git <HTTPS_URL>"));
    assert!(
        help.contains("--git-scratch <HTTPS_URL> <GIT_OBJECT_ID> <PACK_SUBDIR> <ABSOLUTE_PATH>")
    );
    for unsupported in [
        "--lock <",
        "--cached",
        "--target",
        "--namespace",
        "--profile",
        "--allow-component",
    ] {
        assert!(
            !help.contains(unsupported),
            "source lock help exposed unsupported option {unsupported}"
        );
    }
    assert!(!env.state_root().exists());
}

#[test]
fn component_host_profile_is_exact_and_storeless() {
    let env = TestEnv::new();
    let expected =
        malm_format_component_adapter::current_host_execution_profile_digest_v1().to_string();

    let human = env.malm(&["component", "host-profile"]);
    assert!(human.status.success());
    assert!(human.stderr.is_empty());
    let human = String::from_utf8(human.stdout).unwrap();
    assert!(human.contains("Format component host"));
    assert!(human.contains("format-component/v1"));
    assert!(human.contains(&expected));

    let json = env.malm(&["component", "host-profile", "--format", "json"]);
    assert!(json.status.success());
    assert!(json.stderr.is_empty());
    let json: serde_json::Value = serde_json::from_slice(&json.stdout).unwrap();
    assert_eq!(json["command"], "component.host-profile");
    assert_eq!(json["data"]["interface"], "format-component/v1");
    assert_eq!(json["data"]["execution_profile"], expected);
    assert!(!env.state_root().exists());
}

#[test]
fn removed_flat_commands_aliases_and_global_flags_are_rejected_before_state_access() {
    let env = TestEnv::new();
    for arguments in [
        &["v1"][..],
        &["validate"][..],
        &["doctor"][..],
        &["profiles"][..],
        &["prepare", "--help"][..],
        &["apply", "--help"][..],
        &["lock", "--help"][..],
        &["track", "--help"][..],
        &["update", "--help"][..],
        &["switch", "--help"][..],
        &["commit", "--help"][..],
        &["status", "--help"][..],
        &["fsck", "--help"][..],
        &["store", "initialize"][..],
        &["--json", "source", "check"][..],
        &["--profile", "desktop", "deploy"][..],
        &["--repo", ".", "namespace", "status"][..],
        &["--config", "malm.kdl", "source", "check"][..],
        &["--state", "default", "namespace", "status"][..],
        &["plan", "create", "--allow-component", "sha256-deadbeef"][..],
        &["plan", "track", "--allow-component", "sha256-deadbeef"][..],
        &["deploy", "--allow-component", "sha256-deadbeef"][..],
    ] {
        let output = env.malm(arguments);
        assert_eq!(
            output.status.code(),
            Some(2),
            "removed surface unexpectedly parsed: {arguments:?}"
        );
    }
    assert!(!env.state_root().exists());
}

#[test]
fn output_options_are_domain_scoped_and_machine_remains_strict() {
    let env = TestEnv::new();

    let root = String::from_utf8(env.malm(&["--help"]).stdout).unwrap();
    assert!(!root.contains("--format"));
    assert!(!root.contains("--color"));
    assert!(!root.contains("--verbose"));
    assert!(!root.contains("--profile"));

    let source = String::from_utf8(env.malm(&["source", "--help"]).stdout).unwrap();
    assert!(source.contains("--format <FORMAT>"));
    assert!(source.contains("--color <COLOR>"));
    assert!(source.contains("--verbose"));

    let render = String::from_utf8(env.malm(&["source", "render", "--help"]).stdout).unwrap();
    assert!(render.contains("--profile <PROFILE>"));
    let deploy = String::from_utf8(env.malm(&["deploy", "--help"]).stdout).unwrap();
    assert!(deploy.contains("--profile <PROFILE>"));
    assert!(!deploy.contains("--allow-component"));
    let create = String::from_utf8(env.malm(&["plan", "create", "--help"]).stdout).unwrap();
    assert!(!create.contains("--allow-component"));
    let track = String::from_utf8(env.malm(&["plan", "track", "--help"]).stdout).unwrap();
    assert!(!track.contains("--allow-component"));

    let machine = String::from_utf8(env.malm(&["machine", "--help"]).stdout).unwrap();
    assert!(!machine.contains("--format"));
    assert!(!machine.contains("--color"));
    assert!(!machine.contains("--verbose"));
    assert!(!env.state_root().exists());
}
