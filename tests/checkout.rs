//! Checkout restores a deployment from an earlier transaction.

mod common;

use common::TestEnv;

#[test]
fn checkout_restores_a_previous_transaction() {
    let env = TestEnv::with_basic_config();
    env.apply_ok();
    env.write_repo_file("files/bashrc", "export TEST=2\n");
    env.apply_ok();
    env.assert_bashrc_deployed("export TEST=2\n");

    let first = env.transaction_ids()[0].clone();
    env.ok(&["state", "checkout", &first, "-y"]);

    env.assert_bashrc_deployed("export TEST=1\n");
    env.ok(&["status"]);
}

#[test]
fn checkout_refuses_a_non_deploying_transaction() {
    let env = TestEnv::with_basic_config();
    env.apply_ok();
    env.ok(&["state", "disable", "-y"]);

    let disable_tx = env
        .transaction_ids()
        .into_iter()
        .find(|id| env.manifest_json(id)["kind"] == "disable")
        .expect("disable transaction recorded");

    let out = env.fail(&["state", "checkout", &disable_tx, "-y"]);
    assert!(
        out.contains("does not record a deployment"),
        "unexpected error output:\n{out}"
    );

    // The state stays disabled and enable still restores it.
    env.ok(&["state", "enable", "-y"]);
    env.assert_bashrc_deployed("export TEST=1\n");
}
