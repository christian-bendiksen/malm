//! Destroy removes a deployment and its state while retaining transaction
//! history.

mod common;

use common::TestEnv;

#[test]
fn destroy_removes_deployment_and_state_records() {
    let env = TestEnv::with_basic_config();
    env.apply_ok();
    env.ok(&["state", "destroy", "default", "-y"]);

    assert!(
        std::fs::symlink_metadata(env.deployed_bashrc()).is_err(),
        "deployed symlink must be removed"
    );
    assert!(
        !env.state_dir("default").exists(),
        "state directory must be removed"
    );
    assert!(
        env.transaction_count() > 0,
        "transaction history is kept for undo"
    );
}

/// Even with no files to remove, destroy must leave a completed transaction
/// after deleting the state directory.
#[test]
fn zero_op_destroy_records_destroy_transaction() {
    let env = TestEnv::with_basic_config();
    env.apply_ok();
    std::fs::remove_file(env.deployed_bashrc()).expect("remove deployed symlink manually");

    env.ok(&["state", "destroy", "default", "-y"]);
    assert!(
        !env.state_dir("default").exists(),
        "state directory must be removed"
    );

    let destroy_tx = env
        .transaction_ids()
        .into_iter()
        .find(|id| env.manifest_json(id)["kind"] == "destroy")
        .expect("zero-op destroy still records a destroy transaction");
    let manifest = env.manifest_json(&destroy_tx);
    assert_eq!(manifest["status"], "completed");
    assert_eq!(
        manifest["operations"].as_array().map(Vec::len),
        Some(0),
        "the transaction carries zero filesystem operations"
    );
}

#[test]
fn destroy_of_default_state_requires_explicit_name() {
    let env = TestEnv::with_basic_config();
    env.apply_ok();
    env.fail(&["state", "destroy", "-y"]);

    env.assert_bashrc_deployed("export TEST=1\n");
}
