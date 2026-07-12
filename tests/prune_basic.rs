//! Prune and usage tests for retention, dry runs, and unreadable metadata.

mod common;

use common::TestEnv;

fn env_with_two_transactions() -> TestEnv {
    let env = TestEnv::with_basic_config();
    env.apply_ok();
    env.write_repo_file("files/bashrc", "export TEST=2\n");
    env.apply_ok();
    assert_eq!(env.transaction_count(), 2);
    env
}

#[test]
fn prune_keeps_the_active_transaction() {
    let env = env_with_two_transactions();
    env.ok(&["state", "prune", "--keep", "1"]);

    assert_eq!(env.transaction_count(), 1, "old transaction pruned");
    env.assert_bashrc_deployed("export TEST=2\n");
    env.ok(&["status"]);
}

#[test]
fn prune_dry_run_deletes_nothing() {
    let env = env_with_two_transactions();
    env.ok(&["state", "prune", "--keep", "1", "--dry-run"]);

    assert_eq!(env.transaction_count(), 2, "dry-run must not delete");
}

#[test]
fn usage_reports_without_mutating() {
    let env = env_with_two_transactions();
    env.ok(&["state", "usage"]);

    assert_eq!(env.transaction_count(), 2);
}

#[test]
fn prune_fails_closed_on_unreadable_ownership() {
    let env = env_with_two_transactions();
    std::fs::write(env.state_dir("default").join("ownership.json"), "garbage").unwrap();

    let output = env.fail(&["state", "prune", "--keep", "1"]);
    assert!(
        output.contains("--force") && output.contains("fsck"),
        "fail-closed message must offer fsck and --force, got:\n{output}"
    );
    assert_eq!(env.transaction_count(), 2, "nothing may be deleted");
}

#[test]
fn prune_force_over_retains_broken_namespace() {
    let env = env_with_two_transactions();
    std::fs::write(env.state_dir("default").join("ownership.json"), "garbage").unwrap();

    env.ok(&["state", "prune", "--keep", "1", "--force"]);
    assert_eq!(
        env.transaction_count(),
        2,
        "--force retains everything the broken state's history references"
    );
}

#[test]
fn prune_aborts_on_unreadable_manifest_even_with_force() {
    let env = env_with_two_transactions();
    let first = env.transaction_ids()[0].clone();
    std::fs::write(
        env.transactions_dir().join(&first).join("manifest.json"),
        "garbage",
    )
    .unwrap();

    env.fail(&["state", "prune", "--keep", "1"]);
    env.fail(&["state", "prune", "--keep", "1", "--force"]);
    assert_eq!(env.transaction_count(), 2, "nothing may be deleted");
}

#[test]
fn usage_still_reports_with_unreadable_ownership() {
    let env = env_with_two_transactions();
    std::fs::write(env.state_dir("default").join("ownership.json"), "garbage").unwrap();

    env.ok(&["state", "usage"]);
    assert_eq!(env.transaction_count(), 2);
}
