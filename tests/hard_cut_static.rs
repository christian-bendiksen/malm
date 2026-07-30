use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;

const REMOVED_PRODUCTION_SPELLINGS: &[&str] = &[
    "V1Cmd",
    "V1StoreCmd",
    "V1TargetFlags",
    "v1_deployment",
    "v1_machine",
    "v1_store",
    "malm-v1",
    "plugin/v1",
    "format.json",
    "store.json",
    "experimental",
];

const REMOVED_DIRECT_DEPENDENCIES: &[&str] = &[
    "dag",
    "dirs",
    "globset",
    "miette",
    "owo-colors",
    "petgraph",
    "rayon",
    "roxmltree",
    "semver",
    "tar",
    "time",
    "toml",
    "tree-sitter",
    "tree-sitter-bash",
    "tree-sitter-css",
    "tree-sitter-lua",
    "ureq",
    "walkdir",
    "xz2",
    "zip",
];

const REMOVED_WORKSPACE_PACKAGES: &[&str] = &[
    "dag",
    "malm-plugin-api",
    "malm-plugin-adapter",
    "malm-plugin-host",
];

fn workspace() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn files_below(root: &Path) -> Vec<PathBuf> {
    if !root.exists() {
        return Vec::new();
    }
    let mut files = Vec::new();
    let mut pending = vec![root.to_path_buf()];
    while let Some(directory) = pending.pop() {
        let mut entries = std::fs::read_dir(&directory)
            .unwrap_or_else(|error| panic!("read {}: {error}", directory.display()))
            .map(|entry| entry.unwrap().path())
            .collect::<Vec<_>>();
        entries.sort();
        for path in entries {
            if path.is_dir() {
                pending.push(path);
            } else {
                files.push(path);
            }
        }
    }
    files.sort();
    files
}

fn cargo_metadata() -> serde_json::Value {
    let output = Command::new(env!("CARGO"))
        .args([
            "metadata",
            "--locked",
            "--all-features",
            "--format-version",
            "1",
        ])
        .current_dir(workspace())
        .output()
        .expect("run cargo metadata for hard-cut gate");
    assert!(
        output.status.success(),
        "cargo metadata failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}

#[test]
fn root_source_tree_contains_only_final_adapters() {
    let root = workspace();
    let source = root.join("src");
    let actual = files_below(&source)
        .into_iter()
        .map(|path| path.strip_prefix(&source).unwrap().to_path_buf())
        .collect::<BTreeSet<_>>();
    let expected = [
        "api.rs",
        "cli/args.rs",
        "cli/contracts.rs",
        "cli/deployment.rs",
        "cli/dispatch.rs",
        "cli/ids.rs",
        "cli/interactive.rs",
        "cli/machine.rs",
        "cli/mod.rs",
        "cli/output.rs",
        "cli/store.rs",
        "lib.rs",
        "main.rs",
    ]
    .into_iter()
    .map(PathBuf::from)
    .collect();
    assert_eq!(actual, expected);

    assert!(files_below(&root.join("crates/dag")).is_empty());
    for plugin in [
        "crates/malm-plugin-api",
        "crates/malm-plugin-adapter",
        "crates/malm-plugin-host",
        "schemas/plugin",
    ] {
        assert!(
            files_below(&root.join(plugin)).is_empty(),
            "obsolete plugin contract remains at {plugin}"
        );
    }
}

#[test]
fn removed_symbols_paths_features_and_dependencies_cannot_return() {
    let root = workspace();
    let lock = std::fs::read_to_string(root.join("Cargo.lock")).unwrap();
    let metadata = cargo_metadata();
    let workspace_members = metadata["workspace_members"]
        .as_array()
        .unwrap()
        .iter()
        .map(|member| member.as_str().unwrap())
        .collect::<BTreeSet<_>>();
    let workspace_packages = metadata["packages"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|package| workspace_members.contains(package["id"].as_str().unwrap()))
        .collect::<Vec<_>>();

    let mut manifests = BTreeSet::from([root.join("Cargo.toml")]);
    manifests.extend(
        files_below(&root.join("crates"))
            .into_iter()
            .filter(|path| path.file_name().is_some_and(|name| name == "Cargo.toml")),
    );
    let metadata_manifests = workspace_packages
        .iter()
        .map(|package| PathBuf::from(package["manifest_path"].as_str().unwrap()))
        .collect::<BTreeSet<_>>();
    assert_eq!(manifests, metadata_manifests);

    for package in &workspace_packages {
        let package_name = package["name"].as_str().unwrap();
        assert!(
            !REMOVED_WORKSPACE_PACKAGES.contains(&package_name),
            "removed workspace package {package_name:?} returned in metadata"
        );
        assert!(
            !package["features"].get("fuzzing").is_some(),
            "removed fuzzing feature returned in {package_name}"
        );
        for dependency in package["dependencies"].as_array().unwrap() {
            let dependency = dependency["name"].as_str().unwrap();
            assert!(
                !REMOVED_DIRECT_DEPENDENCIES.contains(&dependency),
                "workspace package {package_name} directly declares removed dependency {dependency}"
            );
        }
    }

    let lock_packages = lock
        .lines()
        .filter_map(|line| {
            line.strip_prefix("name = \"")
                .and_then(|name| name.strip_suffix('"'))
        })
        .collect::<BTreeSet<_>>();
    for package in REMOVED_WORKSPACE_PACKAGES {
        assert!(
            !lock_packages.contains(package),
            "removed workspace package {package:?} returned in Cargo.lock"
        );
    }

    // Do not reject `miette` transitively because kdl 6.5.0 depends on it. The
    // gate above rejects only a direct workspace declaration of the predecessor
    // dependency.
}

#[test]
fn removed_production_spellings_are_confined_to_explicit_negative_tests() {
    let root = workspace();
    let allowlist =
        std::fs::read_to_string(root.join(".github/removed-spelling-test-allowlist.txt"))
            .unwrap()
            .lines()
            .map(PathBuf::from)
            .collect::<BTreeSet<_>>();
    assert!(!allowlist.is_empty());

    let mut rust_sources = files_below(&root.join("src"));
    rust_sources.extend(
        files_below(&root.join("crates"))
            .into_iter()
            .filter(|path| path.extension().is_some_and(|extension| extension == "rs")),
    );
    rust_sources.extend(
        files_below(&root.join("tests"))
            .into_iter()
            .filter(|path| path.extension().is_some_and(|extension| extension == "rs")),
    );

    let mut used_allowlist = BTreeSet::new();
    for path in rust_sources {
        let relative = path.strip_prefix(&root).unwrap().to_path_buf();
        let source = std::fs::read_to_string(&path).unwrap();
        let found = REMOVED_PRODUCTION_SPELLINGS
            .iter()
            .filter(|spelling| source.contains(**spelling))
            .copied()
            .collect::<Vec<_>>();
        if found.is_empty() {
            continue;
        }
        assert!(
            allowlist.contains(&relative),
            "removed production spellings {found:?} occur outside the negative-test allowlist in {}",
            relative.display()
        );
        assert!(
            relative.starts_with("tests") || relative.starts_with("crates/malm-root/tests"),
            "removed-spelling allowlist entry is not a negative test: {}",
            relative.display()
        );
        used_allowlist.insert(relative);
    }
    assert_eq!(used_allowlist, allowlist);
}

#[test]
fn removed_docs_and_transitional_test_names_are_absent() {
    let root = workspace();
    for removed in [
        "docs/v1-cli.md",
        "docs/v1-operation-inventory.md",
        "docs/profiles.md",
        "docs/templating.md",
        "docs/workflow-effect-classification.md",
    ] {
        assert!(
            !root.join(removed).exists(),
            "obsolete document remains: {removed}"
        );
    }
    let transitional = files_below(&root.join("tests"))
        .into_iter()
        .filter_map(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .map(str::to_owned)
        })
        .filter(|name| name.starts_with("v1_"))
        .collect::<Vec<_>>();
    assert!(
        transitional.is_empty(),
        "transitional test filenames remain: {transitional:?}"
    );
}

#[test]
fn tracked_prepare_commands_are_required_successor_surface() {
    let root = workspace();
    let inventory = std::fs::read_to_string(root.join("docs/cli-command-inventory.txt")).unwrap();
    let commands = inventory.lines().collect::<BTreeSet<_>>();
    assert!(commands.contains("plan"));
    assert!(commands.contains("plan track"));
    assert!(commands.contains("plan refresh"));
    assert!(!commands.contains("v1"));

    let arguments = std::fs::read_to_string(root.join("src/cli/args.rs")).unwrap();
    let dispatch = std::fs::read_to_string(root.join("src/cli/deployment.rs")).unwrap();
    assert!(arguments.contains("Track(TrackOptions)"));
    assert!(arguments.contains("Refresh(RefreshOptions)"));
    assert!(dispatch.contains("prepare_tracked_root_v1(&request)"));
    assert!(dispatch.contains("update_v1(&request)"));

    let machine = std::fs::read_to_string(root.join("crates/malm-machine/src/model.rs")).unwrap();
    assert!(!machine.contains("    Track,\n"));
    assert!(!machine.contains("    Update,\n"));
}

#[test]
fn explicit_lock_commands_are_required_host_only_successor_surface() {
    let root = workspace();
    let inventory = std::fs::read_to_string(root.join("docs/cli-command-inventory.txt")).unwrap();
    let commands = inventory.lines().collect::<BTreeSet<_>>();
    assert!(commands.contains("source"));
    assert!(commands.contains("source lock"));
    assert!(commands.contains("source lock create"));
    assert!(commands.contains("source lock update"));

    let arguments = std::fs::read_to_string(root.join("src/cli/args.rs")).unwrap();
    let dispatch = std::fs::read_to_string(root.join("src/cli/deployment.rs")).unwrap();
    assert!(arguments.contains("pub enum LockCmd"));
    assert!(dispatch.contains("engine.create_lock_v1(&source, &inputs, &git)"));
    assert!(dispatch.contains("engine.update_lock_v1(&source, &inputs, &git)"));

    let machine = std::fs::read_to_string(root.join("crates/malm-machine/src/model.rs")).unwrap();
    assert!(!machine.contains("    CreateLock,"));
    assert!(!machine.contains("    UpdateLock,"));
}

#[test]
fn rich_contract_fixtures_use_the_rich_grammar() {
    let root = workspace();
    let fixtures = root.join("schemas/config/v1/fixtures");
    for path in files_below(&fixtures)
        .into_iter()
        .filter(|path| path.extension().is_some_and(|extension| extension == "kdl"))
    {
        let source = std::fs::read_to_string(&path).unwrap();
        assert!(
            source.trim_start().starts_with("rich-config "),
            "non-rich config fixture remains at {}",
            path.display()
        );
    }

    let descriptor_schema =
        std::fs::read_to_string(root.join("schemas/root/v1/schema.json")).unwrap();
    assert!(descriptor_schema.contains("Malm final-root descriptor v1"));
    assert!(!descriptor_schema.contains("format.json"));
    assert!(!descriptor_schema.contains("store.json"));
}
