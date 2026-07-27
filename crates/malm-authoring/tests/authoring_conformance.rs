//! Byte-exact conformance tests against the generated smia pack.
//!
//! The smia repository's `packs/smia/pack-inventory.json` maps every profile
//! to its deployed files and content digests, and `packs/smia/assets/files/`
//! holds every unique blob under its own digest. Together they are a complete
//! expected-output oracle for the authoring evaluator.
//!
//! Set `SMIA_ROOT=/path/to/smia` to run these tests; without it every test
//! skips. `all_profiles_render_byte_exact` is ignored by default because it
//! evaluates the complete external corpus.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use malm_authoring::{AUTHORING_CONFIG_FILE, AuthoringSourceSetV1, evaluate_authoring_profile_v1};
use malm_types::Digest;

/// Reviewed differences from the pack snapshot, keyed by profile and
/// destination. Listed differences are reported but do not fail conformance.
const APPROVED_DIVERGENCES: &[(&str, &str)] = &[
    // The live smia-profiles script includes switch-commit-and-refresh, which
    // is tracked by the live manifest rather than this pack snapshot.
    ("hyprland", ".local/bin/smia-profiles"),
    ("hyprland-astral", ".local/bin/smia-profiles"),
    ("mango", ".local/bin/smia-profiles"),
    ("mango-astral", ".local/bin/smia-profiles"),
    ("niri", ".local/bin/smia-profiles"),
    ("niri-astral", ".local/bin/smia-profiles"),
    // smia-refresh uses `smia-session --apply-theme`, and its coordinated
    // restart is the only Waybar restyle during a profile switch.
    ("hyprland", ".local/bin/smia-refresh"),
    ("hyprland-astral", ".local/bin/smia-refresh"),
    ("mango", ".local/bin/smia-refresh"),
    ("mango-astral", ".local/bin/smia-refresh"),
    ("niri", ".local/bin/smia-refresh"),
    ("niri-astral", ".local/bin/smia-refresh"),
    // The live Waybar service and configuration intentionally differ from the
    // pack snapshot.
    ("hyprland", ".config/smia/services.d/waybar"),
    ("mango", ".config/smia/services.d/waybar"),
    ("niri", ".config/smia/services.d/waybar"),
    ("hyprland-astral", ".config/smia/services.d/waybar"),
    ("mango-astral", ".config/smia/services.d/waybar"),
    ("niri-astral", ".config/smia/services.d/waybar"),
    ("hyprland", ".config/waybar/config.jsonc"),
    ("mango", ".config/waybar/config.jsonc"),
    ("niri", ".config/waybar/config.jsonc"),
];

fn smia_root() -> Option<PathBuf> {
    let root = PathBuf::from(std::env::var_os("SMIA_ROOT")?);
    assert!(
        root.join("packs/smia/pack-inventory.json").is_file(),
        "SMIA_ROOT {} has no packs/smia/pack-inventory.json",
        root.display()
    );
    Some(root)
}

fn load_inventory(root: &Path) -> serde_json::Value {
    let path = root.join("packs/smia/pack-inventory.json");
    let bytes = fs::read(&path).expect("read pack-inventory.json");
    serde_json::from_slice(&bytes).expect("parse pack-inventory.json")
}

fn as_str<'a>(value: &'a serde_json::Value, key: &str) -> &'a str {
    value[key].as_str().unwrap_or_else(|| {
        panic!("inventory field {key} is not a string in {value}");
    })
}

/// Recursively captures one directory tree into the source set.
fn capture_tree(sources: &mut AuthoringSourceSetV1, base: &Path, dir: &Path) {
    let mut entries: Vec<_> = fs::read_dir(dir)
        .unwrap_or_else(|error| panic!("read_dir {}: {error}", dir.display()))
        .map(|entry| entry.expect("dir entry").path())
        .collect();
    entries.sort();
    for path in entries {
        let metadata = fs::symlink_metadata(&path).expect("metadata");
        if metadata.file_type().is_symlink() {
            continue;
        }
        if metadata.file_type().is_dir() {
            capture_tree(sources, base, &path);
            continue;
        }
        let relative = path
            .strip_prefix(base)
            .expect("path under base")
            .to_str()
            .unwrap_or_else(|| panic!("non-UTF-8 source path {}", path.display()));
        let bytes = fs::read(&path).expect("read source file");
        sources
            .insert(relative, bytes)
            .unwrap_or_else(|error| panic!("capture {relative}: {error}"));
    }
}

/// Captures the desktop authoring corpus: root `malm.kdl`, the `malm/`
/// source tree, and the repo-owned `gnist/` payload trees its outputs deploy.
fn capture_desktop_sources(root: &Path) -> AuthoringSourceSetV1 {
    let mut sources = AuthoringSourceSetV1::new();
    let root_config = fs::read(root.join(AUTHORING_CONFIG_FILE)).expect("read root malm.kdl");
    sources
        .insert(AUTHORING_CONFIG_FILE, root_config)
        .expect("capture root malm.kdl");
    capture_tree(&mut sources, root, &root.join("malm"));
    if root.join("gnist").is_dir() {
        capture_tree(&mut sources, root, &root.join("gnist"));
    }
    sources
}

/// Captures the system-models authoring corpus rooted at `system-models/`.
fn capture_system_sources(root: &Path) -> AuthoringSourceSetV1 {
    let base = root.join("system-models");
    let mut sources = AuthoringSourceSetV1::new();
    capture_tree(&mut sources, &base, &base);
    sources
}

/// Maps an authoring-spelled destination onto the golden destination used by
/// the pack inventory, mirroring the recorded provenance mapping:
/// desktop: `HOME/X -> X; every other regular path -> .config/PATH`;
/// system: `HOME/X -> X; all other entries rejected`.
fn golden_destination(kind: &str, authored: &str) -> Option<String> {
    if let Some(home_relative) = authored.strip_prefix("~/") {
        return Some(home_relative.to_owned());
    }
    match kind {
        "desktop" => Some(format!(".config/{authored}")),
        "system" => None,
        other => panic!("unknown profile kind {other:?}"),
    }
}

#[test]
fn oracle_blob_store_matches_inventory() {
    let Some(root) = smia_root() else {
        eprintln!("skipped: SMIA_ROOT is not set");
        return;
    };
    let inventory = load_inventory(&root);
    assert_eq!(inventory["schema_version"], 1, "inventory schema version");

    let file_assets = inventory["file_assets"].as_array().expect("file_assets");
    let counts = &inventory["counts"];
    assert_eq!(
        file_assets.len() as u64,
        counts["unique_file_assets"].as_u64().expect("count"),
        "unique file-asset count"
    );

    let mut blob_paths = BTreeMap::new();
    for asset in file_assets {
        let path = as_str(asset, "path");
        let raw_digest = as_str(asset, "raw_digest");
        let byte_len = asset["byte_len"].as_u64().expect("byte_len");
        let bytes = fs::read(root.join("packs/smia").join(path))
            .unwrap_or_else(|error| panic!("read blob {path}: {error}"));
        assert_eq!(bytes.len() as u64, byte_len, "blob length for {path}");
        assert_eq!(
            Digest::sha256(&bytes).as_str(),
            raw_digest,
            "blob digest for {path}"
        );
        assert!(
            path.ends_with(raw_digest),
            "content-addressed path {path} does not end with its digest"
        );
        blob_paths.insert(path.to_owned(), raw_digest.to_owned());
    }

    let profiles = inventory["profiles"].as_array().expect("profiles");
    assert_eq!(
        profiles.len() as u64,
        counts["profiles"].as_u64().expect("count"),
        "profile count"
    );
    let mut file_outputs = 0u64;
    for profile in profiles {
        for file in profile["files"].as_array().expect("profile files") {
            file_outputs += 1;
            let asset = as_str(file, "asset");
            let raw_digest = as_str(file, "raw_digest");
            assert_eq!(
                blob_paths.get(asset).map(String::as_str),
                Some(raw_digest),
                "profile {} file {} references unknown or mismatched asset {asset}",
                as_str(profile, "name"),
                as_str(file, "destination"),
            );
        }
    }
    assert_eq!(
        file_outputs,
        counts["file_outputs"].as_u64().expect("count"),
        "file-output count"
    );
}

#[test]
fn authoring_source_corpus_is_capturable() {
    let Some(root) = smia_root() else {
        eprintln!("skipped: SMIA_ROOT is not set");
        return;
    };

    let desktop = capture_desktop_sources(&root);
    let kdl_documents = desktop
        .iter()
        .filter(|(path, _)| path.ends_with(".kdl"))
        .count();
    assert!(
        kdl_documents >= 40,
        "expected at least 40 desktop authoring documents, found {kdl_documents}"
    );
    for (path, bytes) in desktop.iter() {
        if path.ends_with(".kdl") {
            assert!(
                std::str::from_utf8(bytes).is_ok(),
                "authoring document {path} is not UTF-8"
            );
        }
    }

    let system = capture_system_sources(&root);
    let system_documents = system
        .iter()
        .filter(|(path, _)| path.ends_with(".kdl"))
        .count();
    assert!(
        system_documents >= 4,
        "expected at least 4 system-model documents, found {system_documents}"
    );
}

/// Returns destinations marked `source_kind: "synthesized"` in pack
/// provenance. They are outside authoring-renderer conformance because the
/// profile and requirement manifests are generated natively.
fn synthesized_destinations(root: &Path) -> std::collections::BTreeSet<(String, String)> {
    let path = root.join("packs/smia/pack-provenance.json");
    let bytes = fs::read(&path).expect("read pack-provenance.json");
    let provenance: serde_json::Value =
        serde_json::from_slice(&bytes).expect("parse pack-provenance.json");
    let mut synthesized = std::collections::BTreeSet::new();
    for profile in provenance["profiles"].as_array().expect("profiles") {
        let name = as_str(profile, "name");
        for output in profile["outputs"].as_array().expect("outputs") {
            if output["source_kind"] == "synthesized" {
                synthesized.insert((name.to_owned(), as_str(output, "destination").to_owned()));
            }
        }
    }
    synthesized
}

/// Checks that every rendered inventory output matches the authoring sources.
///
/// This is ignored by default because it requires an external smia repository
/// through `SMIA_ROOT`.
#[test]
#[ignore]
fn all_profiles_render_byte_exact() {
    let Some(root) = smia_root() else {
        eprintln!("skipped: SMIA_ROOT is not set");
        return;
    };
    let inventory = load_inventory(&root);
    let synthesized = synthesized_destinations(&root);
    let desktop_sources = capture_desktop_sources(&root);
    let system_sources = capture_system_sources(&root);

    let mut failures = Vec::new();
    for profile in inventory["profiles"].as_array().expect("profiles") {
        let name = as_str(profile, "name");
        let kind = as_str(profile, "kind");
        let sources = match kind {
            "desktop" => &desktop_sources,
            "system" => &system_sources,
            other => panic!("unknown profile kind {other:?}"),
        };

        let evaluated =
            match evaluate_authoring_profile_v1(sources, AUTHORING_CONFIG_FILE, name, &[]) {
                Ok(evaluated) => evaluated,
                Err(error) => {
                    failures.push(format!("{name}: evaluation failed: {error}"));
                    continue;
                }
            };

        let mut rendered = BTreeMap::new();
        for output in evaluated.outputs() {
            if let Some(destination) = golden_destination(kind, output.destination()) {
                rendered.insert(destination, output);
            }
        }

        let mut compared = 0usize;
        let mut skipped = 0usize;
        for file in profile["files"].as_array().expect("profile files") {
            let destination = as_str(file, "destination");
            if synthesized.contains(&(name.to_owned(), destination.to_owned())) {
                skipped += 1;
                continue;
            }
            compared += 1;
            let raw_digest = as_str(file, "raw_digest");
            let executable = file["executable"].as_bool().expect("executable");
            let Some(output) = rendered.get(destination) else {
                failures.push(format!("{name}: {destination}: not rendered"));
                continue;
            };
            let approved = APPROVED_DIVERGENCES.contains(&(name, destination));
            let actual = Digest::sha256(
                output
                    .bytes()
                    .expect("golden outputs do not use component renderers"),
            );
            if actual.as_str() != raw_digest && !approved {
                failures.push(format!(
                    "{name}: {destination}: digest mismatch (rendered {actual}, golden {raw_digest})"
                ));
            }
            if output.executable() != executable {
                failures.push(format!(
                    "{name}: {destination}: executable {} but golden {executable}",
                    output.executable()
                ));
            }
        }
        eprintln!("{name}: compared {compared} outputs, skipped {skipped} synthesized");
    }

    assert!(
        failures.is_empty(),
        "{} conformance failures:\n{}",
        failures.len(),
        failures.join("\n")
    );
}
