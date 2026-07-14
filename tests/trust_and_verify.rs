//! Trust flag compatibility, remote-only enforcement, and snapshot content
//! verification.

mod common;

use common::TestEnv;
use std::os::unix::fs::PermissionsExt;

#[test]
fn deprecated_trust_flag_warns_and_maps_to_the_split_flags() {
    let env = TestEnv::with_basic_config();
    // The deprecated alias must warn even when its remote-only replacement fails.
    let output = env.malm(&["apply", "-y", "--trust"]);
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!output.status.success());
    assert!(combined.contains("deprecated"), "output:\n{combined}");
    assert!(combined.contains("--trust-remote"), "output:\n{combined}");
}

#[test]
fn trust_remote_is_rejected_for_local_applies() {
    let env = TestEnv::with_basic_config();
    let output = env.fail(&["apply", "-y", "--trust-remote"]);
    assert!(
        output.contains("only applies to a remote apply"),
        "output:\n{output}"
    );
}

#[test]
fn remote_config_path_is_rejected_before_fetching() {
    let env = TestEnv::new();
    let output = env.fail(&[
        "--config",
        "../malm.kdl",
        "plan",
        "https://example.invalid/dots.git",
        "--branch",
        "main",
    ]);
    assert!(
        output.contains("remote config path must not contain"),
        "output:\n{output}"
    );
}

#[test]
fn checkout_verify_detects_a_corrupted_snapshot() {
    let env = TestEnv::with_basic_config();
    env.apply_ok();
    env.write_repo_file("files/bashrc", "export TEST=2\n");
    env.apply_ok();

    // Tamper with an inactive snapshot in the content-addressed store.
    let first = env.transaction_ids()[0].clone();
    let manifest = env.manifest_json(&first);
    let snapshot_id = manifest["source_snapshot_id"].as_str().unwrap();
    let snapshot_repo = env
        .state_root()
        .join("objects/sources")
        .join(snapshot_id)
        .join("repo");
    std::fs::set_permissions(&snapshot_repo, std::fs::Permissions::from_mode(0o700)).unwrap();
    std::fs::write(snapshot_repo.join("planted"), "tampered").unwrap();

    let output = env.fail(&["state", "checkout", &first, "-y", "--verify"]);
    assert!(output.contains("corrupt"), "output:\n{output}");

    // Fsck verifies active objects only; checkout verifies this older snapshot.
    env.ok(&["state", "fsck", "--verify-objects"]);
}

/// Persist the local-include grant so replaying a snapshot uses the original
/// trust decision.
#[test]
fn apply_records_the_local_include_grant_in_the_manifest() {
    let env = TestEnv::with_basic_config();
    env.apply_ok();

    let id = env.transaction_ids()[0].clone();
    let manifest = env.manifest_json(&id);
    assert_eq!(
        manifest["allow_local_includes"], true,
        "local applies record their include grant:\n{manifest}"
    );
}

#[test]
fn failed_update_preserves_existing_tracking_bytes() {
    let env = TestEnv::with_basic_config();
    env.apply_ok();
    let path = env.state_dir("default").join("tracking.json");
    let tracking = r#"{
  "version": 2,
  "url": "https://example.invalid/dots.git",
  "branch": "main",
  "applied_commit": "not-a-commit",
  "applied_at": 1700000000,
  "allow_local_includes": false,
  "profile": "main"
}"#;
    std::fs::write(&path, tracking).unwrap();

    let output = env.fail(&["update", "-y"]);
    assert!(output.contains("applied commit"), "output:\n{output}");
    assert_eq!(std::fs::read_to_string(path).unwrap(), tracking);
}

#[test]
fn source_less_remote_reapply_reconciles_commit_profile_and_nested_config() {
    let env = TestEnv::new();
    env.write_repo_file("files/bashrc", "export TEST=1\n");
    env.write_repo_file(
        "nested/malm.kdl",
        "config target=\"~\" default-profile=\"main\"\n\
         module \"basic\" { outputs { file \"files/bashrc\" to=\"~/.bashrc\" } }\n\
         profile \"main\" { use \"basic\" }\n\
         profile \"other\" { use \"basic\" }\n",
    );
    env.ok(&["--config", "nested/malm.kdl", "apply", "-y"]);

    let commit = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    let old_commit = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let url = "https://example.com/dots.git";
    let id = env.transaction_ids()[0].clone();
    let manifest_path = env.transactions_dir().join(&id).join("manifest.json");
    let mut manifest = env.manifest_json(&id);
    manifest["source"] = serde_json::json!({"kind": {"type": "git", "url": url, "commit": commit}});
    std::fs::write(
        &manifest_path,
        serde_json::to_string_pretty(&manifest).unwrap(),
    )
    .unwrap();

    let ownership_path = env.state_dir("default").join("ownership.json");
    let mut ownership: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&ownership_path).unwrap()).unwrap();
    ownership["source"] =
        serde_json::json!({"kind": {"type": "git", "url": url, "commit": commit}});
    std::fs::write(
        &ownership_path,
        serde_json::to_string_pretty(&ownership).unwrap(),
    )
    .unwrap();

    let tracking_path = env.state_dir("default").join("tracking.json");
    let tracking = serde_json::json!({
        "version": 2,
        "url": url,
        "branch": "main",
        "applied_commit": old_commit,
        "applied_at": 1,
        "allow_local_includes": false,
        "config": "nested/malm.kdl",
        "profile": "main",
    });
    std::fs::write(
        &tracking_path,
        serde_json::to_string_pretty(&tracking).unwrap(),
    )
    .unwrap();

    let output = env.malm_without_repo(&["apply", "-y"]);
    assert!(
        output.status.success(),
        "source-less reapply failed:\n{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let reconciled: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&tracking_path).unwrap()).unwrap();
    assert_eq!(reconciled["applied_commit"], commit);
    assert_eq!(reconciled["config"], "nested/malm.kdl");
    assert_eq!(reconciled["profile"], "main");

    let output = env.malm_without_repo(&["apply", "-y", "--profile", "other"]);
    assert!(
        output.status.success(),
        "profile reapply failed:\n{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        tracking_path.exists(),
        "source-less profile changes should preserve tracking"
    );
    let reconciled: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&tracking_path).unwrap()).unwrap();
    assert_eq!(reconciled["config"], "nested/malm.kdl");
    assert_eq!(reconciled["profile"], "other");

    let output = env.malm_without_repo(&["apply", "-y"]);
    assert!(
        output.status.success(),
        "second source-less reapply failed:\n{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let reconciled: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&tracking_path).unwrap()).unwrap();
    assert_eq!(reconciled["config"], "nested/malm.kdl");
    assert_eq!(reconciled["profile"], "other");
}
