//! Disable and enable tests for restoration, safety checks, retention,
//! dry runs, and crash recovery.
#![cfg(feature = "failpoints")]

mod common;

use common::TestEnv;

#[test]
fn disable_enable_roundtrip_restores_the_deployment() {
    let env = TestEnv::with_basic_config();
    env.apply_ok();

    env.ok(&["state", "disable", "-y"]);
    assert!(
        std::fs::symlink_metadata(env.deployed_bashrc()).is_err(),
        "disable removes deployed files"
    );
    assert_eq!(
        env.state_mode("default").as_deref(),
        Some("disabled"),
        "state record marks the state disabled"
    );
    assert!(
        env.source_pointer("default").is_none(),
        "a disabled state materializes nothing, so the source pointer is gone"
    );

    let status = env.ok(&["status"]);
    assert!(
        status.contains("disabled"),
        "status must say disabled, got:\n{status}"
    );

    env.ok(&["state", "enable", "-y"]);
    env.assert_bashrc_deployed("export TEST=1\n");
    assert_eq!(
        env.state_mode("default").as_deref(),
        Some("enabled"),
        "enable flips the state record back"
    );
    env.ok(&["status"]);
    env.ok(&["state", "fsck"]);
}

#[test]
fn apply_refuses_a_disabled_state_unless_reenabled() {
    let env = TestEnv::with_basic_config();
    env.apply_ok();
    env.ok(&["state", "disable", "-y"]);

    let refused = env.fail(&["apply", "-y"]);
    assert!(
        refused.contains("state enable") && refused.contains("--reenable"),
        "apply must point at enable/--reenable, got:\n{refused}"
    );

    env.ok(&["apply", "-y", "--reenable"]);
    env.assert_bashrc_deployed("export TEST=1\n");
    assert_eq!(
        env.state_mode("default").as_deref(),
        Some("enabled"),
        "--reenable apply re-enables via its own finalizer"
    );
}

#[test]
fn disable_is_idempotent() {
    let env = TestEnv::with_basic_config();
    env.apply_ok();

    env.ok(&["state", "disable", "-y"]);
    let second = env.ok(&["state", "disable", "-y"]);
    assert!(
        second.contains("already disabled"),
        "second disable output:\n{second}"
    );
}

#[test]
fn enable_requires_a_disabled_state() {
    let env = TestEnv::with_basic_config();
    env.apply_ok();

    let output = env.fail(&["state", "enable", "-y"]);
    assert!(output.contains("not disabled"), "output:\n{output}");
}

#[test]
fn gc_retains_the_restore_target_while_disabled() {
    let env = TestEnv::with_basic_config();
    env.apply_ok();
    env.write_repo_file("files/bashrc", "export TEST=2\n");
    env.apply_ok();

    env.ok(&["state", "disable", "-y"]);
    env.ok(&["state", "prune", "--keep", "1"]);

    env.ok(&["state", "enable", "-y"]);
    env.assert_bashrc_deployed("export TEST=2\n");
}

#[test]
fn destroy_works_on_a_disabled_state() {
    let env = TestEnv::with_basic_config();
    env.apply_ok();
    env.ok(&["state", "disable", "-y"]);

    env.ok(&["state", "destroy", "default", "-y"]);
    assert!(!env.state_dir("default").exists(), "state records removed");
}

#[test]
fn disable_refuses_drifted_owned_target_by_default() {
    let env = TestEnv::with_basic_config();
    env.apply_ok();

    // Replacing the managed symlink with a file creates drift.
    std::fs::remove_file(env.deployed_bashrc()).unwrap();
    std::fs::write(env.deployed_bashrc(), "user edit\n").unwrap();

    let refused = env.fail(&["state", "disable", "-y"]);
    assert!(
        refused.contains("cannot be safely removed") && refused.contains("--keep-modified"),
        "strict disable must refuse and point at --keep-modified, got:\n{refused}"
    );
    assert_ne!(
        env.state_mode("default").as_deref(),
        Some("disabled"),
        "a refused disable must not mark the state disabled"
    );
}

#[test]
fn disable_keep_modified_retains_ownership_for_kept_targets() {
    let env = TestEnv::with_basic_config();
    env.apply_ok();

    std::fs::remove_file(env.deployed_bashrc()).unwrap();
    std::fs::write(env.deployed_bashrc(), "user edit\n").unwrap();

    let output = env.ok(&["state", "disable", "-y", "--keep-modified"]);
    assert!(
        output.contains("kept 1 modified target"),
        "output must state what was kept, got:\n{output}"
    );
    assert_eq!(env.state_mode("default").as_deref(), Some("disabled"));

    // Keep ownership and state records aligned so the file is not orphaned.
    let record = env.state_record("default").expect("state record");
    let kept = record["kept_targets"].as_array().expect("kept_targets");
    assert_eq!(kept.len(), 1, "record lists the kept target");
    let ownership = std::fs::read_to_string(env.state_dir("default").join("ownership.json"))
        .expect("ownership index");
    assert!(
        ownership.contains(".bashrc"),
        "ownership retains the kept entry:\n{ownership}"
    );

    env.ok(&["state", "fsck"]);
}

/// Enable must preserve files retained by `--keep-modified` unless
/// `--replace-kept` explicitly allows backup and replacement.
#[test]
fn enable_refuses_kept_modified_targets_without_force() {
    let env = TestEnv::with_basic_config();
    env.apply_ok();

    std::fs::remove_file(env.deployed_bashrc()).unwrap();
    std::fs::write(env.deployed_bashrc(), "user edit\n").unwrap();
    env.ok(&["state", "disable", "-y", "--keep-modified"]);

    let out = env.fail(&["state", "enable", "-y"]);
    assert!(
        out.contains("--replace-kept"),
        "enable must point at --replace-kept, got:\n{out}"
    );
    assert_eq!(
        std::fs::read_to_string(env.deployed_bashrc()).unwrap(),
        "user edit\n",
        "the kept file is untouched"
    );
    assert_eq!(env.state_mode("default").as_deref(), Some("disabled"));

    env.ok(&["state", "enable", "-y", "--replace-kept"]);
    env.assert_bashrc_deployed("export TEST=1\n");
    env.ok(&["state", "fsck"]);
}

#[test]
fn disable_dry_run_changes_nothing() {
    let env = TestEnv::with_basic_config();
    env.apply_ok();

    let output = env.ok(&["state", "disable", "-y", "--dry-run"]);
    assert!(
        output.contains("would remove") && output.contains("no changes made"),
        "dry-run output:\n{output}"
    );
    env.assert_bashrc_deployed("export TEST=1\n");
    assert_eq!(
        env.state_mode("default").as_deref(),
        Some("enabled"),
        "dry-run must not disable"
    );
    assert_eq!(env.transaction_count(), 1, "dry-run records no transaction");
}

/// A crash before the Disabled record is written must be detected by fsck and
/// recovered by rolling the disable forward.
#[test]
fn crash_before_record_write_recovers_to_disabled() {
    let env = TestEnv::with_basic_config();
    env.apply_ok();

    let output = env.malm_with_env(
        &["state", "disable", "-y"],
        &[("MALM_FAILPOINT", "disable.before_record")],
    );
    assert!(!output.status.success(), "disable must crash at failpoint");
    assert!(
        std::fs::symlink_metadata(env.deployed_bashrc()).is_err(),
        "the disable transaction already removed the deployment"
    );
    assert_ne!(
        env.state_mode("default").as_deref(),
        Some("disabled"),
        "the disabled state record was never written"
    );

    let fsck = env.malm(&["state", "fsck"]);
    assert_eq!(fsck.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&fsck.stdout).contains("roll-forward"),
        "fsck must flag the interrupted transaction"
    );

    env.ok(&["state", "recover", "--all", "-y"]);
    assert_eq!(
        env.state_mode("default").as_deref(),
        Some("disabled"),
        "recover finishes the disabled state record"
    );
    env.ok(&["state", "fsck"]);

    env.ok(&["state", "enable", "-y"]);
    env.assert_bashrc_deployed("export TEST=1\n");
}

/// At `disable.after_metadata`, ownership is committed but the pointer and
/// enabled state record remain. Recovery must finish disabling the state.
#[test]
fn crash_after_metadata_recovers_to_disabled() {
    let env = TestEnv::with_basic_config();
    env.apply_ok();
    let old_pointer = env.source_pointer("default").expect("pointer installed");

    let output = env.malm_with_env(
        &["state", "disable", "-y"],
        &[("MALM_FAILPOINT", "disable.after_metadata")],
    );
    assert!(!output.status.success(), "disable must crash at failpoint");

    // Pointer removal follows the metadata failpoint.
    assert_eq!(
        env.source_pointer("default").as_ref(),
        Some(&old_pointer),
        "pointer must stay until the disable rolls forward"
    );
    assert_ne!(
        env.state_mode("default").as_deref(),
        Some("disabled"),
        "the disabled record was never written"
    );

    let ids = env.transaction_ids();
    let crashed = env.manifest_json(ids.last().unwrap());
    assert_eq!(
        crashed["phase"].as_str(),
        Some("metadata_committed"),
        "phase must be metadata_committed at this crash point"
    );

    env.ok(&["state", "recover", "--all", "-y"]);
    assert_eq!(
        env.state_mode("default").as_deref(),
        Some("disabled"),
        "recover finishes the disable"
    );
    assert!(
        env.source_pointer("default").is_none(),
        "recover removes the source pointer"
    );
    env.ok(&["state", "fsck"]);
}

/// A zero-op disable still needs a completed transaction for recovery and
/// auditing.
#[test]
fn zero_op_disable_records_disable_transaction() {
    let env = TestEnv::with_basic_config();
    env.apply_ok();
    std::fs::remove_file(env.deployed_bashrc()).expect("remove deployed symlink manually");

    env.ok(&["state", "disable", "-y"]);
    assert_eq!(env.state_mode("default").as_deref(), Some("disabled"));

    let disable_tx = env
        .transaction_ids()
        .into_iter()
        .find(|id| env.manifest_json(id)["kind"] == "disable")
        .expect("zero-op disable still records a disable transaction");
    let manifest = env.manifest_json(&disable_tx);
    assert_eq!(manifest["status"], "completed");
    assert_eq!(
        manifest["operations"].as_array().map(Vec::len),
        Some(0),
        "the transaction carries zero filesystem operations"
    );

    env.ok(&["state", "fsck"]);
}

/// A journaled zero-op disable must still roll forward if it crashes before
/// writing the state record.
#[test]
fn zero_op_disable_crash_before_record_is_recoverable() {
    let env = TestEnv::with_basic_config();
    env.apply_ok();
    std::fs::remove_file(env.deployed_bashrc()).expect("remove deployed symlink manually");

    let output = env.malm_with_env(
        &["state", "disable", "-y"],
        &[("MALM_FAILPOINT", "disable.before_record")],
    );
    assert!(!output.status.success(), "disable must crash at failpoint");
    assert_ne!(
        env.state_mode("default").as_deref(),
        Some("disabled"),
        "the disabled state record was never written"
    );

    env.ok(&["state", "recover", "--all", "-y"]);
    assert_eq!(
        env.state_mode("default").as_deref(),
        Some("disabled"),
        "recover finishes the disabled state record"
    );
    env.ok(&["state", "fsck"]);
}

/// Rerunning disable must also converge after a crash before the record write.
#[test]
fn crash_in_disable_converges_on_rerun() {
    let env = TestEnv::with_basic_config();
    env.apply_ok();

    let output = env.malm_with_env(
        &["state", "disable", "-y"],
        &[("MALM_FAILPOINT", "disable.before_record")],
    );
    assert!(!output.status.success(), "disable must crash at failpoint");

    env.ok(&["state", "disable", "-y"]);
    assert_eq!(env.state_mode("default").as_deref(), Some("disabled"));

    env.ok(&["state", "enable", "-y"]);
    env.assert_bashrc_deployed("export TEST=1\n");
}

#[test]
fn state_list_shows_the_disabled_badge() {
    let env = TestEnv::with_basic_config();
    env.apply_ok();
    env.ok(&["state", "disable", "-y"]);

    let list = env.ok(&["state", "list"]);
    assert!(list.contains("disabled"), "state list output:\n{list}");
}

#[test]
fn state_log_does_not_mark_old_apply_active_after_disable() {
    let env = TestEnv::with_basic_config();
    env.apply_ok();
    env.ok(&["state", "disable", "-y"]);

    let log = env.ok(&["state", "log"]);
    assert!(
        !log.contains("active"),
        "a disabled state has no active deployment:\n{log}"
    );
    assert!(
        log.contains("restore"),
        "the restore target is annotated instead:\n{log}"
    );
}

#[test]
fn state_pin_current_refuses_when_disabled() {
    let env = TestEnv::with_basic_config();
    env.apply_ok();
    env.ok(&["state", "disable", "-y"]);

    let refused = env.fail(&["state", "pin", "current"]);
    assert!(
        refused.contains("disabled") && refused.contains("restore"),
        "pin current must explain the disabled state, got:\n{refused}"
    );
}
