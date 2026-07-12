//! State-root hardening tests for symlink and permission attacks. Mutating
//! commands refuse unsafe state, while fsck reports it.

mod common;

use common::TestEnv;
use std::os::unix::fs::PermissionsExt;

#[test]
fn apply_refuses_a_symlinked_state_subtree() {
    let env = TestEnv::with_basic_config();
    env.apply_ok();

    // Redirect transaction writes to an attacker-controlled directory.
    let transactions = env.transactions_dir();
    let elsewhere = env.state_root().join("elsewhere");
    std::fs::rename(&transactions, &elsewhere).unwrap();
    std::os::unix::fs::symlink(&elsewhere, &transactions).unwrap();

    let output = env.fail(&["apply", "-y"]);
    assert!(
        output.contains("not trustworthy") || output.contains("symlink"),
        "apply must refuse a symlinked state subtree, got:\n{output}"
    );
}

#[test]
fn apply_refuses_a_world_writable_state_root() {
    let env = TestEnv::with_basic_config();
    env.apply_ok();

    let root = env.state_root();
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o777)).unwrap();

    let output = env.fail(&["apply", "-y"]);
    assert!(
        output.contains("writable by group or other") && output.contains("chmod go-w"),
        "apply must refuse with a chmod remedy, got:\n{output}"
    );

    // Restoring safe permissions must unblock apply.
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o755)).unwrap();
    env.apply_ok();
}

#[test]
fn fsck_reports_insecure_state_root_instead_of_refusing() {
    let env = TestEnv::with_basic_config();
    env.apply_ok();

    let root = env.state_root();
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o777)).unwrap();

    let output = env.malm(&["state", "fsck"]);
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    assert_eq!(output.status.code(), Some(1), "fsck exits 1 on findings");
    assert!(
        stdout.contains("state-root-insecure"),
        "fsck output:\n{stdout}"
    );

    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o755)).unwrap();
    env.ok(&["state", "fsck"]);
}

#[test]
fn first_apply_creates_a_private_state_root() {
    let env = TestEnv::with_basic_config();
    env.apply_ok();

    let mode = std::fs::metadata(env.state_root())
        .unwrap()
        .permissions()
        .mode()
        & 0o7777;
    assert_eq!(
        mode & 0o022,
        0,
        "state root must not be group/world writable"
    );
}

#[test]
fn legacy_store_without_format_marker_is_rejected_with_reset_guidance() {
    let env = TestEnv::with_basic_config();
    env.apply_ok();
    std::fs::remove_file(env.state_root().join("format.json")).unwrap();

    let output = env.fail(&["apply", "-y"]);
    assert!(output.contains("incompatible Malm state/CAS format"));
    assert!(output.contains("Legacy state is not migrated"));
    assert!(output.contains("move") && output.contains("malm apply"));
}

#[test]
fn old_ownership_schema_is_rejected_instead_of_migrated() {
    let env = TestEnv::with_basic_config();
    env.apply_ok();
    let path = env.state_dir("default").join("ownership.json");
    let mut ownership: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    ownership["version"] = 2.into();
    std::fs::write(&path, serde_json::to_string_pretty(&ownership).unwrap()).unwrap();

    let output = env.fail(&["apply", "-y"]);
    assert!(output.contains("expected exactly 3, got 2"));
    assert!(output.contains("Legacy state is not migrated"));
}

/// Preflight must inspect each transaction directory because a nested symlink
/// can redirect journal and backup writes.
#[test]
fn preflight_rejects_symlinked_transaction_dir() {
    let env = TestEnv::with_basic_config();
    env.apply_ok();

    let id = env.transaction_ids()[0].clone();
    let tx_dir = env.transactions_dir().join(&id);
    let elsewhere = env.state_root().join("elsewhere-tx");
    std::fs::rename(&tx_dir, &elsewhere).unwrap();
    std::os::unix::fs::symlink(&elsewhere, &tx_dir).unwrap();

    let output = env.fail(&["apply", "-y"]);
    assert!(
        output.contains("not trustworthy") || output.contains("symlink"),
        "apply must refuse a symlinked transaction dir, got:\n{output}"
    );

    let fsck = env.malm(&["state", "fsck"]);
    assert!(
        !fsck.status.success()
            && String::from_utf8_lossy(&fsck.stdout).contains("state-root-insecure"),
        "fsck must report the insecure dir"
    );
}

/// A symlink at `targets.lock` could redirect state writes. Preflight must
/// reject it even though the open also uses `O_NOFOLLOW`.
#[test]
fn preflight_rejects_symlink_in_malm_root() {
    let env = TestEnv::with_basic_config();
    env.apply_ok();

    // Point the lock path at a file outside the state root.
    let guard = env.state_root().join("targets.lock");
    let _ = std::fs::remove_file(&guard);
    std::os::unix::fs::symlink("/etc/hostname", &guard).unwrap();

    let output = env.fail(&["apply", "-y"]);
    assert!(
        output.contains("symlink") || output.contains("not trustworthy"),
        "apply must refuse a symlinked root child, got:\n{output}"
    );
}

// Trusted local configs may target paths outside their declared root. Remote
// destinations outside the home directory are blocked unless explicitly
// allowed, as tested in `src/policy/destination.rs`.
