//! Fsck and recovery tests for detection, mutation gating, rollback,
//! roll-forward, dry runs, and idempotency.
#![cfg(feature = "failpoints")]

mod common;

use common::TestEnv;

fn latest_status(env: &TestEnv) -> String {
    let ids = env.transaction_ids();
    let manifest = env.manifest_json(ids.last().expect("at least one transaction"));
    manifest["status"].as_str().unwrap_or_default().to_owned()
}

#[test]
fn fsck_is_clean_after_a_normal_apply() {
    let env = TestEnv::with_basic_config();
    env.apply_ok();

    let output = env.malm(&["state", "fsck"]);
    assert!(
        output.status.success(),
        "fsck expected clean, got:\n{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

/// An operation applied before a crash must be detected, block further apply,
/// and roll back before normal work resumes.
#[test]
fn rollback_after_mid_apply_crash() {
    let env = TestEnv::with_basic_config();
    env.apply_ok();

    // Crash after the second apply creates its new symlink.
    env.write_repo_file("files/profile", "new file\n");
    env.write_config(&common::basic_config(&[
        "file \"files/bashrc\" to=\"~/.bashrc\"",
        "file \"files/profile\" to=\"~/.profile\"",
    ]));
    env.malm_with_env(&["apply", "-y"], &[("MALM_FAILPOINT", "apply.after_op=2")]);
    assert!(
        env.home().join(".profile").is_symlink(),
        "crash happened after the op applied"
    );

    // Detection and mutation gating must agree that recovery is required.
    let fsck = env.malm(&["state", "fsck"]);
    let fsck_out = String::from_utf8_lossy(&fsck.stdout).into_owned();
    assert_eq!(fsck.status.code(), Some(1), "fsck exits 1 on findings");
    assert!(
        fsck_out.contains("transaction-needs-rollback"),
        "fsck output:\n{fsck_out}"
    );

    let refused = env.fail(&["apply", "-y"]);
    assert!(
        refused.contains("malm state recover"),
        "apply must point at recover, got:\n{refused}"
    );

    // Rollback removes the partial deployment.
    env.ok(&["state", "recover", "--all", "-y"]);
    assert!(
        std::fs::symlink_metadata(env.home().join(".profile")).is_err(),
        "created symlink must be removed by rollback"
    );
    env.assert_bashrc_deployed("export TEST=1\n");
    assert_eq!(latest_status(&env), "rolled_back");

    // Once clean, the same apply can complete.
    env.ok(&["state", "fsck"]);
    env.apply_ok();
    assert!(env.home().join(".profile").is_symlink());
}

/// Rollback restores a real file that the crashed apply had backed up.
#[test]
fn rollback_restores_backed_up_file() {
    let env = TestEnv::with_basic_config();
    env.apply_ok();

    std::fs::write(env.home().join(".profile"), "precious contents\n").unwrap();
    env.write_repo_file("files/profile", "managed\n");
    env.write_config(&common::basic_config(&[
        "file \"files/bashrc\" to=\"~/.bashrc\"",
        "file \"files/profile\" to=\"~/.profile\" on-conflict=\"backup\"",
    ]));
    env.malm_with_env(&["apply", "-y"], &[("MALM_FAILPOINT", "apply.after_op=2")]);
    assert!(
        env.home().join(".profile").is_symlink(),
        "the original file was replaced before the crash"
    );

    env.ok(&["state", "recover", "--all", "-y"]);

    let meta = std::fs::symlink_metadata(env.home().join(".profile")).unwrap();
    assert!(meta.file_type().is_file(), "original file restored");
    assert_eq!(
        std::fs::read_to_string(env.home().join(".profile")).unwrap(),
        "precious contents\n"
    );
}

/// Rollback never clobbers a destination that changed after the crash.
#[test]
fn rollback_skips_externally_changed_targets() {
    let env = TestEnv::with_basic_config();
    env.apply_ok();

    env.write_repo_file("files/profile", "new file\n");
    env.write_config(&common::basic_config(&[
        "file \"files/bashrc\" to=\"~/.bashrc\"",
        "file \"files/profile\" to=\"~/.profile\"",
    ]));
    env.malm_with_env(&["apply", "-y"], &[("MALM_FAILPOINT", "apply.after_op=2")]);

    // Simulate a user replacing the crashed apply's symlink.
    let profile = env.home().join(".profile");
    std::fs::remove_file(&profile).unwrap();
    std::os::unix::fs::symlink("/somewhere/else", &profile).unwrap();

    let out = env.ok(&["state", "recover", "--all", "-y"]);
    assert!(out.contains("skipped"), "recover output:\n{out}");
    assert_eq!(
        std::fs::read_link(&profile).unwrap(),
        std::path::PathBuf::from("/somewhere/else"),
        "external symlink untouched"
    );
    assert_eq!(latest_status(&env), "rolled_back");
}

/// Once filesystem changes are complete, recovery must finish metadata and
/// activate the new snapshot instead of rolling back.
#[test]
fn roll_forward_after_metadata_crash() {
    let env = TestEnv::with_basic_config();
    env.apply_ok();
    let old_pointer = env.source_pointer("default").expect("pointer installed");

    env.write_repo_file("files/bashrc", "export TEST=2\n");
    env.apply_expect_crash("apply.after_fs");
    env.assert_bashrc_deployed("export TEST=1\n");

    let fsck = env.malm(&["state", "fsck"]);
    assert_eq!(fsck.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&fsck.stdout).contains("transaction-needs-roll-forward"),
        "fsck must flag the interrupted activation"
    );

    env.ok(&["state", "recover", "--all", "-y"]);

    assert_ne!(
        env.source_pointer("default").as_ref(),
        Some(&old_pointer),
        "recover must activate the applied snapshot"
    );
    env.assert_bashrc_deployed("export TEST=2\n");
    assert_eq!(latest_status(&env), "completed");
    env.ok(&["state", "fsck"]);
    env.ok(&["status"]);
}

#[test]
fn recover_dry_run_changes_nothing() {
    let env = TestEnv::with_basic_config();
    env.apply_ok();

    env.write_repo_file("files/profile", "new file\n");
    env.write_config(&common::basic_config(&[
        "file \"files/bashrc\" to=\"~/.bashrc\"",
        "file \"files/profile\" to=\"~/.profile\"",
    ]));
    env.malm_with_env(&["apply", "-y"], &[("MALM_FAILPOINT", "apply.after_op=2")]);

    let out = env.ok(&["state", "recover", "--all", "--dry-run"]);
    assert!(out.contains("would undo"), "dry-run output:\n{out}");
    assert!(
        env.home().join(".profile").is_symlink(),
        "dry-run must not touch the filesystem"
    );
    assert_ne!(latest_status(&env), "rolled_back");
}

#[test]
fn recover_twice_is_idempotent() {
    let env = TestEnv::with_basic_config();
    env.apply_ok();

    env.write_repo_file("files/profile", "new file\n");
    env.write_config(&common::basic_config(&[
        "file \"files/bashrc\" to=\"~/.bashrc\"",
        "file \"files/profile\" to=\"~/.profile\"",
    ]));
    env.malm_with_env(&["apply", "-y"], &[("MALM_FAILPOINT", "apply.after_op=2")]);

    env.ok(&["state", "recover", "--all", "-y"]);
    let second = env.ok(&["state", "recover", "--all", "-y"]);
    assert!(
        second.contains("nothing to recover"),
        "second recover output:\n{second}"
    );
    env.assert_bashrc_deployed("export TEST=1\n");
}

#[test]
fn recover_of_a_completed_transaction_is_a_noop() {
    let env = TestEnv::with_basic_config();
    env.apply_ok();
    let id = env.transaction_ids()[0].clone();

    let out = env.ok(&["state", "recover", &id, "-y"]);
    assert!(out.contains("nothing to recover"), "output:\n{out}");
}

/// Fsck must report tracking metadata that disagrees with the live source.
/// Tracking is written outside the finalizer and can remain stale after a crash.
#[test]
fn fsck_reports_desynced_tracking() {
    let env = TestEnv::with_basic_config();
    env.apply_ok();

    let tracking = serde_json::json!({
        "version": 2,
        "url": "https://example.com/dotfiles.git",
        "branch": "main",
        "applied_commit": "0123456789abcdef0123456789abcdef01234567",
        "applied_at": 1,
        "allow_local_includes": false,
        "profile": "main",
    });
    std::fs::write(
        env.state_dir("default").join("tracking.json"),
        serde_json::to_string_pretty(&tracking).unwrap(),
    )
    .unwrap();

    let output = env.malm(&["state", "fsck"]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        !output.status.success() && stdout.contains("tracking-desynced"),
        "fsck must flag stale tracking, got:\n{stdout}"
    );
}

#[test]
fn roll_forward_restores_retained_stale_ownership() {
    let env = TestEnv::with_basic_config();
    env.apply_ok();
    std::fs::remove_file(env.deployed_bashrc()).unwrap();
    std::fs::write(env.deployed_bashrc(), "user replacement\n").unwrap();
    env.write_config(&common::basic_config(&[]));

    env.apply_expect_crash("apply.after_fs");
    let id = env.transaction_ids().pop().unwrap();
    let manifest = env.manifest_json(&id);
    assert_eq!(manifest["retained_ownership"].as_array().unwrap().len(), 1);

    env.ok(&["state", "recover", &id, "-y"]);
    let ownership = std::fs::read_to_string(env.state_dir("default").join("ownership.json"))
        .expect("read recovered ownership");
    assert!(ownership.contains(".bashrc"), "ownership:\n{ownership}");
}

#[test]
fn zero_operation_metadata_repair_rolls_forward_as_a_rewrite() {
    let env = TestEnv::new();
    env.write_config("config target=\"~\"\n");
    env.apply_ok();

    let bogus = env.home().join("bogus-target");
    let targets = serde_json::json!({ bogus.display().to_string(): "default" });
    std::fs::write(
        env.state_root().join("targets.json"),
        serde_json::to_string_pretty(&targets).unwrap(),
    )
    .unwrap();

    env.apply_expect_crash("apply.after_fs");
    let id = env.transaction_ids().pop().unwrap();
    let manifest = env.manifest_json(&id);
    assert_eq!(manifest["operations"].as_array().unwrap().len(), 0);
    assert_eq!(manifest["metadata_intent"], "rewrite");

    env.ok(&["state", "recover", &id, "-y"]);
    let repaired: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(env.state_root().join("targets.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(repaired, serde_json::json!({}));
}

#[test]
fn zero_operation_source_anchor_rolls_forward_without_rewriting_metadata() {
    let env = TestEnv::new();
    env.write_config("config target=\"~\"\n");
    env.apply_ok();
    let ownership_path = env.state_dir("default").join("ownership.json");
    let ownership_before = std::fs::read(&ownership_path).unwrap();

    env.write_repo_file("unreferenced", "new source bytes\n");
    env.apply_expect_crash("apply.after_fs");
    let id = env.transaction_ids().pop().unwrap();
    let manifest = env.manifest_json(&id);
    assert_eq!(manifest["operations"].as_array().unwrap().len(), 0);
    assert_eq!(manifest["metadata_intent"], "preserve");

    env.ok(&["state", "recover", &id, "-y"]);
    assert_eq!(std::fs::read(ownership_path).unwrap(), ownership_before);
}
