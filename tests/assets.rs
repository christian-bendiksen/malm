//! End-to-end asset update and permission tests using archive objects seeded
//! directly into the isolated CAS, with no network access.

mod common;

use common::TestEnv;
use sha2::{Digest, Sha256};
use std::io::{Cursor, Write};
use std::os::unix::fs::PermissionsExt;

fn archive(version: &str) -> (Vec<u8>, String) {
    named_archive("Demo", version)
}

fn named_archive(name: &str, version: &str) -> (Vec<u8>, String) {
    let mut writer = zip::ZipWriter::new(Cursor::new(Vec::new()));
    let directory = zip::write::SimpleFileOptions::default().unix_permissions(0o755);
    let file = zip::write::SimpleFileOptions::default().unix_permissions(0o644);
    writer.add_directory(format!("{name}/"), directory).unwrap();
    writer.start_file(format!("{name}/version"), file).unwrap();
    writer.write_all(version.as_bytes()).unwrap();
    let bytes = writer.finish().unwrap().into_inner();
    let sha = hex::encode(Sha256::digest(&bytes));
    (bytes, sha)
}

fn multi_asset_config(entries: &[(&str, &str, &str)]) -> String {
    let assets: String = entries
        .iter()
        .map(|(name, sha, check)| {
            format!(
                "    asset \"{name}\" {{\n        url \"https://example.invalid/{name}.zip\"\n        dst \"~/.local/share/icons\"\n        format \"zip\"\n        sha256 \"{sha}\"\n        installed-check \"{check}\"\n    }}\n"
            )
        })
        .collect();
    format!(
        "{}\nassets {{\n{assets}}}\n",
        common::basic_config(&["file \"files/bashrc\" to=\"~/.bashrc\""])
    )
}

fn whole_tree_archive(version: &str) -> (Vec<u8>, String) {
    let mut writer = zip::ZipWriter::new(Cursor::new(Vec::new()));
    let file = zip::write::SimpleFileOptions::default().unix_permissions(0o644);
    writer.start_file("version", file).unwrap();
    writer.write_all(version.as_bytes()).unwrap();
    let bytes = writer.finish().unwrap().into_inner();
    let sha = hex::encode(Sha256::digest(&bytes));
    (bytes, sha)
}

fn config(sha: &str, installed_check: &str) -> String {
    format!(
        "{}\nassets {{\n    asset \"demo\" {{\n        url \"https://example.invalid/demo.zip\"\n        dst \"~/.local/share/icons\"\n        format \"zip\"\n        sha256 \"{sha}\"\n        installed-check \"{installed_check}\"\n    }}\n}}\n",
        common::basic_config(&["file \"files/bashrc\" to=\"~/.bashrc\""])
    )
}

fn seed_archive(env: &TestEnv, bytes: &[u8], sha: &str) {
    let marker = env.state_root().join("format.json");
    if !marker.exists() {
        std::fs::create_dir_all(marker.parent().unwrap()).unwrap();
        std::fs::write(&marker, "{\n  \"version\": 2\n}\n").unwrap();
    }
    let path = env
        .state_root()
        .join("objects/assets/archives")
        .join(format!("sha256-{sha}"));
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, bytes).unwrap();
}

#[test]
fn changed_sha_replaces_readonly_owned_asset_despite_installed_check() {
    let env = TestEnv::new();
    env.write_repo_file("files/bashrc", "export TEST=1\n");
    let (v1, sha1) = archive("v1");
    seed_archive(&env, &v1, &sha1);
    env.write_config(&config(&sha1, "Demo/version"));
    env.apply_ok();

    let parent = env.home().join(".local/share/icons");
    let target = parent.join("Demo");
    assert_eq!(
        std::fs::read_to_string(target.join("version")).unwrap(),
        "v1"
    );
    assert_ne!(
        std::fs::symlink_metadata(&parent)
            .unwrap()
            .permissions()
            .mode()
            & 0o200,
        0,
        "shared extraction parent must remain owner-writable"
    );
    assert_eq!(
        std::fs::symlink_metadata(&target)
            .unwrap()
            .permissions()
            .mode()
            & 0o222,
        0,
        "owned asset root must be sealed"
    );

    let (v2, sha2) = archive("v2");
    seed_archive(&env, &v2, &sha2);
    env.write_config(&config(&sha2, "Demo/version"));
    env.apply_ok();

    assert_eq!(
        std::fs::read_to_string(target.join("version")).unwrap(),
        "v2"
    );
    assert_eq!(
        std::fs::symlink_metadata(&target)
            .unwrap()
            .permissions()
            .mode()
            & 0o222,
        0,
        "updated asset root must remain sealed"
    );

    let ownership: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(env.state_dir("default").join("ownership.json")).unwrap(),
    )
    .unwrap();
    assert!(
        ownership["entries"]
            .as_array()
            .unwrap()
            .iter()
            .any(|entry| {
                entry["owner"]["kind"] == "asset"
                    && entry["owner"]["name"] == "demo"
                    && entry["asset_declaration"]["sha256"] == sha2
            })
    );

    let transaction_count = env.transaction_count();
    env.apply_ok();
    assert_eq!(
        env.transaction_count(),
        transaction_count,
        "unchanged declaration and concrete target lock should be a true no-op"
    );
}

#[test]
fn readonly_whole_root_migrates_to_writable_shared_parent() {
    let env = TestEnv::new();
    env.write_repo_file("files/bashrc", "export TEST=1\n");
    let (v1, sha1) = whole_tree_archive("v1");
    seed_archive(&env, &v1, &sha1);
    env.write_config(&config(&sha1, "version"));
    env.apply_ok();

    let parent = env.home().join(".local/share/icons");
    assert_eq!(
        std::fs::read_to_string(parent.join("version")).unwrap(),
        "v1"
    );
    assert_eq!(
        std::fs::symlink_metadata(&parent)
            .unwrap()
            .permissions()
            .mode()
            & 0o222,
        0,
        "legacy whole-root placement is sealed"
    );

    let (v2, sha2) = archive("v2");
    seed_archive(&env, &v2, &sha2);
    env.write_config(&config(&sha2, "Demo/version"));
    env.apply_ok();

    assert!(std::fs::symlink_metadata(parent.join("version")).is_err());
    assert_eq!(
        std::fs::read_to_string(parent.join("Demo/version")).unwrap(),
        "v2"
    );
    assert_ne!(
        std::fs::symlink_metadata(&parent)
            .unwrap()
            .permissions()
            .mode()
            & 0o200,
        0,
        "merge extraction parent becomes writable"
    );
    assert_eq!(
        std::fs::symlink_metadata(parent.join("Demo"))
            .unwrap()
            .permissions()
            .mode()
            & 0o222,
        0,
        "concrete child remains sealed"
    );
}

#[test]
fn shared_root_ownership_handoff_is_declaration_order_independent() {
    let env = TestEnv::new();
    env.write_repo_file("files/bashrc", "export TEST=1\n");
    let (a1, a1_sha) = named_archive("Old", "a1");
    let (b1, b1_sha) = named_archive("B", "b1");
    seed_archive(&env, &a1, &a1_sha);
    seed_archive(&env, &b1, &b1_sha);
    env.write_config(&multi_asset_config(&[
        ("a", &a1_sha, "Old/version"),
        ("b", &b1_sha, "B/version"),
    ]));
    env.apply_ok();

    let (b2, b2_sha) = named_archive("Old", "b2");
    let (a2, a2_sha) = named_archive("New", "a2");
    seed_archive(&env, &b2, &b2_sha);
    seed_archive(&env, &a2, &a2_sha);
    // The claimant is deliberately declared first. Obsolete placement removal
    // must still release Old before b installs it.
    env.write_config(&multi_asset_config(&[
        ("b", &b2_sha, "Old/version"),
        ("a", &a2_sha, "New/version"),
    ]));
    env.apply_ok();

    let parent = env.home().join(".local/share/icons");
    assert_eq!(
        std::fs::read_to_string(parent.join("Old/version")).unwrap(),
        "b2"
    );
    assert_eq!(
        std::fs::read_to_string(parent.join("New/version")).unwrap(),
        "a2"
    );
    assert!(std::fs::symlink_metadata(parent.join("B")).is_err());
}
