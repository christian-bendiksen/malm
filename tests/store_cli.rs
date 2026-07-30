mod common;

use std::os::unix::ffi::OsStringExt;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::process::Command;

use common::TestEnv;

#[test]
fn lifecycle_uses_engine_statuses_and_exact_human_output() {
    let env = TestEnv::new();
    assert_success_output(
        env.malm_without_repo(&["store", "status"]),
        &store_output(
            &env.state_root(),
            "Store is not initialized",
            "absent",
            true,
        ),
    );
    assert!(!env.state_root().exists());

    std::fs::create_dir(env.state_root()).unwrap();
    std::fs::set_permissions(env.state_root(), std::fs::Permissions::from_mode(0o700)).unwrap();
    assert_success_output(
        env.malm_without_repo(&["store", "status"]),
        &store_output(
            &env.state_root(),
            "Store needs initialization",
            "uninitialized",
            true,
        ),
    );
    assert_success_output(
        env.malm_without_repo(&["store", "init"]),
        &store_output(&env.state_root(), "Store is ready", "ready", false),
    );
    let marker = env.state_root().join("descriptor.json");
    let first = std::fs::metadata(&marker).unwrap();
    assert_eq!(
        std::fs::read(&marker).unwrap(),
        b"{\"format\":\"malm-state\",\"version\":1}\n"
    );

    assert_success_output(
        env.malm_without_repo(&["store", "init"]),
        &store_output(&env.state_root(), "Store is ready", "ready", false),
    );
    assert_success_output(
        env.malm_without_repo(&["store", "status"]),
        &store_output(&env.state_root(), "Store is ready", "ready", false),
    );
    let second = std::fs::metadata(marker).unwrap();
    assert_eq!(first.dev(), second.dev());
    assert_eq!(first.ino(), second.ino());
}

#[test]
fn inaccessible_experimental_sibling_is_never_inspected() {
    let env = TestEnv::new();
    let sibling = env.state_root().parent().unwrap().join("malm-v1");
    let sentinel = sibling.join("sentinel");
    std::fs::create_dir(&sibling).unwrap();
    std::fs::write(&sentinel, b"experimental").unwrap();
    std::fs::set_permissions(&sentinel, std::fs::Permissions::from_mode(0o400)).unwrap();
    std::fs::set_permissions(&sibling, std::fs::Permissions::from_mode(0o000)).unwrap();
    let before_root = std::fs::metadata(&sibling).unwrap();

    assert_success_output(
        env.malm_without_repo(&["store", "status"]),
        &store_output(
            &env.state_root(),
            "Store is not initialized",
            "absent",
            true,
        ),
    );
    assert_success_output(
        env.malm_without_repo(&["store", "init"]),
        &store_output(&env.state_root(), "Store is ready", "ready", false),
    );

    let after_root = std::fs::metadata(&sibling).unwrap();
    assert_metadata_unchanged(&before_root, &after_root);
    std::fs::set_permissions(&sibling, std::fs::Permissions::from_mode(0o700)).unwrap();
    assert_eq!(std::fs::read(&sentinel).unwrap(), b"experimental");
}

#[test]
fn store_init_creates_a_missing_state_parent_with_private_mode() {
    let env = TestEnv::new();
    let state_home = env.state_root().parent().unwrap().to_path_buf();
    std::fs::remove_dir(&state_home).unwrap();
    assert_success_output(
        env.malm_without_repo(&["store", "status"]),
        &store_output(
            &env.state_root(),
            "Store is not initialized",
            "absent",
            true,
        ),
    );
    assert!(!state_home.exists(), "store status must not create anything");

    assert_success_output(
        env.malm_without_repo(&["store", "init"]),
        &store_output(&env.state_root(), "Store is ready", "ready", false),
    );
    let mode = std::fs::metadata(&state_home).unwrap().mode() & 0o7777;
    assert_eq!(mode, 0o700);
    assert!(env.state_root().join("descriptor.json").is_file());
}

#[test]
fn store_init_creates_nested_missing_state_parents() {
    let env = TestEnv::new();
    let state_home = env.state_root().parent().unwrap().to_path_buf();
    std::fs::remove_dir(&state_home).unwrap();
    let nested = state_home.join("nested/state");

    let output = Command::new(env!("CARGO_BIN_EXE_malm"))
        .args(["store", "init"])
        .env("HOME", env.home())
        .env("XDG_STATE_HOME", &nested)
        .env_remove("MALM_FAILPOINT")
        .output()
        .unwrap();
    assert_success_output(
        output,
        &store_output(&nested.join("malm"), "Store is ready", "ready", false),
    );
    for directory in [&state_home, &state_home.join("nested"), &nested] {
        let mode = std::fs::metadata(directory).unwrap().mode() & 0o7777;
        assert_eq!(mode, 0o700, "{}", directory.display());
    }
    assert!(nested.join("malm/descriptor.json").is_file());
}

#[test]
fn store_init_refuses_to_create_beneath_an_unsafe_ancestor() {
    let env = TestEnv::new();
    let state_home = env.state_root().parent().unwrap().to_path_buf();
    std::fs::remove_dir(&state_home).unwrap();
    let ancestor = state_home.parent().unwrap().to_path_buf();
    std::fs::set_permissions(&ancestor, std::fs::Permissions::from_mode(0o770)).unwrap();

    let refused = env.malm_without_repo(&["store", "init"]);
    assert_eq!(refused.status.code(), Some(2));
    assert!(refused.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&refused.stderr);
    assert!(stderr.contains("state parent"), "{stderr}");
    assert!(!state_home.exists());

    std::fs::set_permissions(&ancestor, std::fs::Permissions::from_mode(0o700)).unwrap();
}

#[test]
fn malformed_store_propagates_as_a_cli_error() {
    let env = TestEnv::new();
    std::fs::create_dir(env.state_root()).unwrap();
    std::fs::set_permissions(env.state_root(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let marker = env.state_root().join("descriptor.json");
    let original = b"{\"format\":\"malm-state\",\"version\":2}\n";
    std::fs::write(&marker, original).unwrap();
    std::fs::set_permissions(&marker, std::fs::Permissions::from_mode(0o600)).unwrap();
    let malformed = env.malm_without_repo(&["store", "init"]);
    assert_eq!(malformed.status.code(), Some(2));
    assert!(malformed.stdout.is_empty());
    assert!(String::from_utf8_lossy(&malformed.stderr).contains("unsupported store schema"));
    assert_eq!(std::fs::read(marker).unwrap(), original);
}

#[test]
fn unset_xdg_uses_home_fallback_with_json_envelope() {
    let env = TestEnv::new();
    let fallback = env.home().join(".local/state");
    std::fs::create_dir_all(&fallback).unwrap();
    std::fs::set_permissions(&fallback, std::fs::Permissions::from_mode(0o700)).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_malm"))
        .args(["store", "init"])
        .env("HOME", env.home())
        .env_remove("XDG_STATE_HOME")
        .env_remove("MALM_FAILPOINT")
        .output()
        .unwrap();
    assert_success_output(
        output,
        &store_output(&fallback.join("malm"), "Store is ready", "ready", false),
    );
    assert!(fallback.join("malm/descriptor.json").is_file());
    assert!(!env.state_root().exists());

    let json = Command::new(env!("CARGO_BIN_EXE_malm"))
        .args(["store", "--format", "json", "status"])
        .env("HOME", env.home())
        .env_remove("XDG_STATE_HOME")
        .env_remove("MALM_FAILPOINT")
        .output()
        .unwrap();
    assert!(json.status.success());
    assert!(json.stderr.is_empty());
    let json: serde_json::Value = serde_json::from_slice(&json.stdout).unwrap();
    assert_eq!(json.as_object().unwrap().len(), 5);
    assert_eq!(json["schema_version"], 1);
    assert_eq!(json["command"], "store.status");
    assert_eq!(json["outcome"], "ok");
    assert_eq!(json["data"]["status"], "ready");
    assert_eq!(
        json["data"]["path"],
        fallback.join("malm").to_str().unwrap()
    );
    assert_eq!(json["diagnostics"], serde_json::json!([]));

    let ignored_global = env.malm_without_repo(&["--profile", "ignored", "store", "status"]);
    assert_eq!(ignored_global.status.code(), Some(2));
    assert!(ignored_global.stdout.is_empty());
    assert!(String::from_utf8_lossy(&ignored_global.stderr).contains("--profile"));
}

#[test]
fn unset_xdg_creates_the_home_fallback_state_parent() {
    let env = TestEnv::new();
    let fallback = env.home().join(".local/state");
    assert!(!env.home().join(".local").exists());

    let output = Command::new(env!("CARGO_BIN_EXE_malm"))
        .args(["store", "init"])
        .env("HOME", env.home())
        .env_remove("XDG_STATE_HOME")
        .env_remove("MALM_FAILPOINT")
        .output()
        .unwrap();
    assert_success_output(
        output,
        &store_output(&fallback.join("malm"), "Store is ready", "ready", false),
    );
    for directory in [&env.home().join(".local"), &fallback] {
        let mode = std::fs::metadata(directory).unwrap().mode() & 0o7777;
        assert_eq!(mode, 0o700, "{}", directory.display());
    }
    assert!(fallback.join("malm/descriptor.json").is_file());
    assert!(!env.state_root().exists());
}

#[test]
fn absolute_non_utf8_xdg_does_not_require_home() {
    let env = TestEnv::new();
    let mut state_home = env.home().parent().unwrap().to_path_buf();
    state_home.push(std::ffi::OsString::from_vec(b"state-\xff".to_vec()));
    std::fs::create_dir(&state_home).unwrap();
    std::fs::set_permissions(&state_home, std::fs::Permissions::from_mode(0o700)).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_malm"))
        .args(["store", "init"])
        .env_remove("HOME")
        .env("XDG_STATE_HOME", &state_home)
        .env_remove("MALM_FAILPOINT")
        .output()
        .unwrap();

    assert_success_output(
        output,
        &store_output(&state_home.join("malm"), "Store is ready", "ready", false),
    );
    let json = Command::new(env!("CARGO_BIN_EXE_malm"))
        .args(["store", "status", "--format", "json"])
        .env_remove("HOME")
        .env("XDG_STATE_HOME", &state_home)
        .env_remove("MALM_FAILPOINT")
        .output()
        .unwrap();
    assert!(
        json.status.success(),
        "{}",
        String::from_utf8_lossy(&json.stderr)
    );
    assert!(json.stderr.is_empty());
    let envelope: serde_json::Value = serde_json::from_slice(&json.stdout).unwrap();
    assert_eq!(envelope["outcome"], "ok");
    assert!(envelope["data"]["path"].is_string());
    assert!(state_home.join("malm/descriptor.json").is_file());
    assert!(!env.home().join(".local/state/malm").exists());
}

#[test]
fn present_empty_or_relative_xdg_is_rejected_without_home_fallback() {
    let env = TestEnv::new();
    let fallback = env.home().join(".local/state");
    std::fs::create_dir_all(&fallback).unwrap();
    std::fs::set_permissions(&fallback, std::fs::Permissions::from_mode(0o700)).unwrap();

    for xdg in ["", "relative-state"] {
        let output = Command::new(env!("CARGO_BIN_EXE_malm"))
            .args(["store", "init"])
            .env("HOME", env.home())
            .env("XDG_STATE_HOME", xdg)
            .env_remove("MALM_FAILPOINT")
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(2), "XDG_STATE_HOME={xdg:?}");
        assert!(output.stdout.is_empty());
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("XDG_STATE_HOME"),
            "XDG_STATE_HOME={xdg:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    assert!(!fallback.join("malm").exists());
}

fn assert_success_output(output: std::process::Output, expected: &str) {
    assert!(
        output.status.success(),
        "command failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&output.stdout), expected);
    assert!(output.stderr.is_empty());
}

fn store_output(path: &std::path::Path, title: &str, status: &str, show_next: bool) -> String {
    let mut output = format!(
        "{title}\n  Path    {}\n  Status  {status}\n",
        path.display()
    );
    if show_next {
        output.push_str("\nNext\n  malm store init\n");
    }
    output
}

fn assert_metadata_unchanged(before: &std::fs::Metadata, after: &std::fs::Metadata) {
    assert_eq!(before.dev(), after.dev());
    assert_eq!(before.ino(), after.ino());
    assert_eq!(before.mode(), after.mode());
    assert_eq!(before.nlink(), after.nlink());
    assert_eq!(before.uid(), after.uid());
    assert_eq!(before.gid(), after.gid());
    assert_eq!(before.size(), after.size());
    assert_eq!(before.atime(), after.atime());
    assert_eq!(before.atime_nsec(), after.atime_nsec());
    assert_eq!(before.mtime(), after.mtime());
    assert_eq!(before.mtime_nsec(), after.mtime_nsec());
    assert_eq!(before.ctime(), after.ctime());
    assert_eq!(before.ctime_nsec(), after.ctime_nsec());
}
