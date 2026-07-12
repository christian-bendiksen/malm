//! Apply crash tests for each durable boundary. They pin the on-disk state and
//! keep the old deployment active until the source pointer is swapped.
//!
//! Requires the `failpoints` cargo feature (`cargo test --features failpoints`).
#![cfg(feature = "failpoints")]

mod common;

use common::TestEnv;

fn phase_of(manifest: &serde_json::Value) -> &str {
    manifest["phase"].as_str().unwrap_or("<none>")
}

fn status_of(manifest: &serde_json::Value) -> &str {
    manifest["status"].as_str().unwrap_or("<none>")
}

/// Before any operation runs, deployment targets and the source pointer stay
/// untouched.
#[test]
fn crash_after_manifest_write_leaves_filesystem_untouched() {
    let env = TestEnv::with_basic_config();
    env.apply_expect_crash("apply.after_manifest_write");

    assert!(
        std::fs::symlink_metadata(env.deployed_bashrc()).is_err(),
        "no filesystem mutation may happen before the journal exists"
    );
    assert_eq!(env.source_pointer("default"), None, "pointer not installed");

    let ids = env.transaction_ids();
    assert_eq!(ids.len(), 1);
    let manifest = env.manifest_json(&ids[0]);
    assert_eq!(status_of(&manifest), "started");
    assert_eq!(phase_of(&manifest), "manifest_written");
}

/// A crash after journaling an operation but before its mutation must leave
/// the old deployment active.
#[test]
fn crash_mid_ops_keeps_previous_deployment_active() {
    let env = TestEnv::with_basic_config();
    env.apply_ok();
    env.assert_bashrc_deployed("export TEST=1\n");
    let old_pointer = env.source_pointer("default").expect("pointer installed");

    env.write_repo_file("files/bashrc", "export TEST=2\n");
    // Add a target because changing source content alone creates no symlink op.
    env.write_repo_file("files/profile", "new file\n");
    env.write_config(&common::basic_config(&[
        "file \"files/bashrc\" to=\"~/.bashrc\"",
        "file \"files/profile\" to=\"~/.profile\"",
    ]));
    env.apply_expect_crash("apply.mid_ops");

    assert_eq!(
        env.source_pointer("default").as_ref(),
        Some(&old_pointer),
        "old snapshot must stay active through a mid-apply crash"
    );
    env.assert_bashrc_deployed("export TEST=1\n");
}

/// Once filesystem work is durable, the manifest replaces the ops journal,
/// but the old pointer remains active until the later pointer swap.
#[test]
fn crash_after_fs_keeps_old_pointer() {
    let env = TestEnv::with_basic_config();
    env.apply_ok();
    let old_pointer = env.source_pointer("default").expect("pointer installed");

    env.write_repo_file("files/bashrc", "export TEST=2\n");
    env.apply_expect_crash("apply.after_fs");

    assert_eq!(
        env.source_pointer("default").as_ref(),
        Some(&old_pointer),
        "pointer swaps only after metadata commit"
    );
    env.assert_bashrc_deployed("export TEST=1\n");

    let ids = env.transaction_ids();
    assert_eq!(ids.len(), 2);
    let crashed = env.manifest_json(&ids[1]);
    assert_eq!(status_of(&crashed), "filesystem_applied");
    assert_eq!(phase_of(&crashed), "filesystem_applied");
    assert!(
        !env.ops_journal_exists(&ids[1]),
        "ops journal is cleared once the manifest records the full apply"
    );
}

/// Committed metadata must not activate new content before the pointer swap.
#[test]
fn crash_after_metadata_keeps_old_content() {
    let env = TestEnv::with_basic_config();
    env.apply_ok();
    let old_pointer = env.source_pointer("default").expect("pointer installed");

    env.write_repo_file("files/bashrc", "export TEST=2\n");
    env.apply_expect_crash("apply.after_metadata");

    assert_eq!(env.source_pointer("default").as_ref(), Some(&old_pointer));
    env.assert_bashrc_deployed("export TEST=1\n");

    let ids = env.transaction_ids();
    let crashed = env.manifest_json(&ids[1]);
    assert_eq!(phase_of(&crashed), "metadata_committed");
}

/// The pointer swap activates new content even if the state record and
/// completed status have not been written.
#[test]
fn crash_after_pointer_swap_activates_new_content() {
    let env = TestEnv::with_basic_config();
    env.apply_ok();
    let old_pointer = env.source_pointer("default").expect("pointer installed");

    env.write_repo_file("files/bashrc", "export TEST=2\n");
    env.apply_expect_crash("apply.after_pointer_swap");

    let new_pointer = env.source_pointer("default").expect("pointer installed");
    assert_ne!(new_pointer, old_pointer, "pointer swapped");
    env.assert_bashrc_deployed("export TEST=2\n");

    let ids = env.transaction_ids();
    let crashed = env.manifest_json(&ids[1]);
    assert_eq!(phase_of(&crashed), "active_pointer_swapped");
    assert_ne!(status_of(&crashed), "completed");
}

/// Reapplying after a post-filesystem crash must converge from the previous
/// state record to a completed deployment.
#[test]
fn reapply_after_crash_converges() {
    for failpoint in [
        "apply.after_fs",
        "apply.after_metadata",
        "apply.after_pointer_swap",
    ] {
        let env = TestEnv::with_basic_config();
        env.apply_ok();
        env.write_repo_file("files/bashrc", "export TEST=2\n");
        env.apply_expect_crash(failpoint);

        env.apply_ok();
        env.assert_bashrc_deployed("export TEST=2\n");
        env.ok(&["status"]);

        let ids = env.transaction_ids();
        let latest = env.manifest_json(ids.last().expect("at least one transaction"));
        assert_eq!(
            status_of(&latest),
            "completed",
            "converged after crash at {failpoint}"
        );
    }
}

/// If the state record names an incomplete transaction, mutations must wait
/// for recovery instead of falling back to the journal. Read-only commands
/// remain available.
#[test]
fn crash_after_record_blocks_mutations_until_recover() {
    let env = TestEnv::with_basic_config();
    env.apply_ok();
    env.write_repo_file("files/bashrc", "export TEST=2\n");
    env.apply_expect_crash("apply.after_record");

    for args in [
        vec!["apply", "-y"],
        vec!["state", "disable", "-y"],
        vec!["state", "pin", "current"],
    ] {
        let out = env.fail(&args);
        assert!(
            out.contains("mid-transition") && out.contains("state recover"),
            "{args:?} must refuse with a recover hint, got:\n{out}"
        );
    }
    // Status still renders the drift, and the transaction log remains usable.
    let status = env.malm(&["status"]);
    assert!(
        String::from_utf8_lossy(&status.stdout).contains("STATUS"),
        "status must render mid-transition"
    );
    env.ok(&["state", "log"]);

    env.ok(&["state", "recover", "--all", "-y"]);
    env.apply_ok();
    env.assert_bashrc_deployed("export TEST=2\n");
}

/// At `destroy.after_metadata`, the pointer and state record are still live.
/// Recovery must finish the irreversible destroy rather than roll it back.
#[test]
fn crash_after_destroy_metadata_recovers_to_destroyed() {
    let env = TestEnv::with_basic_config();
    env.apply_ok();
    let old_pointer = env.source_pointer("default").expect("pointer installed");

    let output = env.malm_with_env(
        &["state", "destroy", "default", "-y"],
        &[("MALM_FAILPOINT", "destroy.after_metadata")],
    );
    assert!(!output.status.success(), "destroy must crash at failpoint");

    // Pointer removal and the Destroyed record both follow this failpoint.
    assert_eq!(
        env.source_pointer("default").as_ref(),
        Some(&old_pointer),
        "pointer must stay until the destroy rolls forward"
    );
    assert_ne!(
        env.state_mode("default").as_deref(),
        Some("destroyed"),
        "destroyed record was never written"
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
        Some("destroyed"),
        "recover finishes the destroy"
    );
    assert!(
        env.source_pointer("default").is_none(),
        "recover removes the source pointer on destroy"
    );
}

/// Recovery must be resumable after its own crash. This sequence interrupts
/// apply after metadata, then interrupts recovery after the pointer swap, and
/// verifies that a second recovery completes the transaction.
#[test]
fn crash_during_recover_is_re_entrant() {
    let env = TestEnv::with_basic_config();
    env.apply_ok();
    let old_pointer = env.source_pointer("default").expect("pointer installed");

    env.write_repo_file("files/bashrc", "export TEST=2\n");
    env.apply_expect_crash("apply.after_metadata");
    // The apply crash leaves the old pointer and content active.
    assert_eq!(env.source_pointer("default").as_ref(), Some(&old_pointer));
    env.assert_bashrc_deployed("export TEST=1\n");

    // Recovery swaps the pointer before writing the enabled state record.
    let out = env.malm_with_env(
        &["state", "recover", "--all", "-y"],
        &[("MALM_FAILPOINT", "recover.apply.after_pointer")],
    );
    assert!(!out.status.success(), "recover must crash at the failpoint");

    let new_pointer = env
        .source_pointer("default")
        .expect("pointer was swapped before the crash");
    assert_ne!(new_pointer, old_pointer, "recover swapped the pointer");
    env.assert_bashrc_deployed("export TEST=2\n");
    // The phase records the pointer swap, but completion is still pending.
    let ids = env.transaction_ids();
    let crashed_tx = env.manifest_json(ids.last().unwrap());
    assert_eq!(
        crashed_tx["phase"].as_str(),
        Some("active_pointer_swapped"),
        "phase advanced past the pointer before the crash"
    );
    assert_ne!(
        crashed_tx["status"].as_str(),
        Some("completed"),
        "the crashed transaction must not be completed yet"
    );

    // Resume from the recorded pointer-swap phase.
    env.ok(&["state", "recover", "--all", "-y"]);
    let ids = env.transaction_ids();
    let latest = env.manifest_json(ids.last().unwrap());
    assert_eq!(latest["status"].as_str(), Some("completed"));
    env.ok(&["state", "fsck"]);
    env.assert_bashrc_deployed("export TEST=2\n");
}
