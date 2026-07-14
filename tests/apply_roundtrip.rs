//! Apply integration tests for initial deployment, no-op reapply, status, and
//! transactions created by source changes.

mod common;

use common::TestEnv;

#[test]
fn apply_deploys_symlink_and_records_transaction() {
    let env = TestEnv::with_basic_config();
    env.apply_ok();

    env.assert_bashrc_deployed("export TEST=1\n");
    assert_eq!(env.transaction_count(), 1, "one recorded transaction");
    assert_eq!(
        env.state_mode("default").as_deref(),
        Some("enabled"),
        "state record marks the state enabled"
    );
    assert!(
        env.state_dir("default").join("ownership.json").is_file(),
        "ownership index exists"
    );
    assert!(
        env.state_dir("default").join("current").is_symlink(),
        "source pointer exists"
    );
}

#[test]
fn config_required_state_rejects_the_wrong_namespace() {
    let env = TestEnv::new();
    env.write_config(
        "config target=\"~\" default-profile=\"main\" required-state=\"protected\"\n\
         module \"basic\" { outputs { render \"basic.conf\" format=\"text\" { @line \"ok\" } } }\n\
         profile \"main\" { use \"basic\" }\n",
    );

    env.ok(&["--state", "protected", "check"]);
    let output = env.fail(&["check"]);
    assert!(
        output.contains("config requires Malm state 'protected'")
            && output.contains("--state protected"),
        "output:\n{output}"
    );
}

#[test]
fn config_required_state_must_be_a_valid_state_name() {
    let env = TestEnv::new();
    env.write_config("config target=\"~\" required-state=\"../escape\"\n");

    let output = env.fail(&["check"]);
    assert!(
        output.contains("invalid `required-state`"),
        "output:\n{output}"
    );
}

#[test]
fn reapply_without_changes_is_a_noop() {
    let env = TestEnv::with_basic_config();
    env.apply_ok();
    let second = env.apply_ok();

    assert!(
        second.contains("No changes"),
        "expected no-op re-apply, got:\n{second}"
    );
    assert_eq!(env.transaction_count(), 1, "no-op must not record");
}

#[test]
fn status_is_clean_after_apply() {
    let env = TestEnv::with_basic_config();
    env.apply_ok();
    env.ok(&["status"]);
}

#[test]
fn changed_source_records_a_new_transaction() {
    let env = TestEnv::with_basic_config();
    env.apply_ok();

    env.write_repo_file("files/bashrc", "export TEST=2\n");
    env.apply_ok();

    env.assert_bashrc_deployed("export TEST=2\n");
    assert_eq!(
        env.transaction_count(),
        2,
        "content change records a transaction"
    );
}

#[test]
fn modified_stale_target_remains_owned() {
    let env = TestEnv::with_basic_config();
    env.apply_ok();
    std::fs::remove_file(env.deployed_bashrc()).unwrap();
    std::fs::write(env.deployed_bashrc(), "user replacement\n").unwrap();
    env.write_config(&common::basic_config(&[]));

    env.apply_ok();

    let ownership = std::fs::read_to_string(env.state_dir("default").join("ownership.json"))
        .expect("read ownership");
    assert!(ownership.contains(".bashrc"), "ownership:\n{ownership}");
    let latest = env.transaction_ids().pop().unwrap();
    let manifest = env.manifest_json(&latest);
    assert_eq!(manifest["retained_ownership"].as_array().unwrap().len(), 1);
}

#[test]
fn default_profile_is_persisted_as_the_effective_profile() {
    let env = TestEnv::with_basic_config();
    env.apply_ok();

    let manifest = env.manifest_json(&env.transaction_ids()[0]);
    assert_eq!(manifest["profile"], "main");
    let ownership: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(env.state_dir("default").join("ownership.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(ownership["profile"], "main");
}

#[test]
fn check_all_profiles_runs_full_read_only_planning() {
    let env = TestEnv::new();
    env.write_config(
        "config target=\"~\" default-profile=\"good\"\n\
         module \"good-module\" { outputs { render \"good.conf\" format=\"text\" { @line \"ok\" } } }\n\
         module \"bad-module\" { outputs { render \"bad.conf\" format=\"text\" { @line \"bad\" } } }\n\
         profile \"good\" { use \"good-module\" }\n\
         profile \"bad\" { use \"bad-module\" }\n",
    );
    std::fs::create_dir(env.home().join("bad.conf")).unwrap();

    let output = env.fail(&["check", "--all-profiles"]);
    assert!(output.contains("profile bad"), "output:\n{output}");
    assert!(
        output.contains("destination is a directory"),
        "output:\n{output}"
    );
    assert!(
        !env.home().join("good.conf").exists(),
        "check must not deploy planned outputs"
    );
}

#[test]
fn symlink_source_resolves_a_path_input_reference() {
    let env = TestEnv::new();
    env.write_config(
        "config target=\"~\" default-profile=\"p\"\n\
         slots { slot \"s\" max=1 }\n\
         module \"m\" {\n\
             slot \"s\"\n\
             inputs { input \"helpers\" type=\"path\" default=\"~/tools/helpers.bash\" }\n\
             outputs {\n\
                  symlink source=(ref)\"helpers\" to=\"~/.helpers\" if-missing=\"allow\"\n\
             }\n\
         }\n\
         profile \"p\" { use \"m\" }\n",
    );
    env.apply_ok();

    let link = env.home().join(".helpers");
    assert!(link.is_symlink(), "symlink from path input deployed");
    assert_eq!(
        std::fs::read_link(&link).expect("read deployed symlink"),
        env.home().join("tools/helpers.bash"),
        "symlink source resolved from the typed path input"
    );
}

#[test]
fn external_include_provenance_change_records_a_new_anchor() {
    let env = TestEnv::new();
    let include = env.home().join("profile.kdl");
    std::fs::write(
        &include,
        "module \"basic\" { outputs { file \"files/bashrc\" to=\"~/.bashrc\" } }\n\
         profile \"main\" { use \"basic\" }\n",
    )
    .unwrap();
    env.write_repo_file("files/bashrc", "export TEST=1\n");
    env.write_config(&format!(
        "config target=\"~\" default-profile=\"main\"\ninclude {:?}\n",
        include.display().to_string()
    ));
    env.apply_ok();

    // A comment changes provenance without changing the plan or snapshot.
    std::fs::write(
        &include,
        "// provenance changed\n\
         module \"basic\" { outputs { file \"files/bashrc\" to=\"~/.bashrc\" } }\n\
         profile \"main\" { use \"basic\" }\n",
    )
    .unwrap();
    env.apply_ok();

    assert_eq!(env.transaction_count(), 2);
    let ids = env.transaction_ids();
    let first = env.manifest_json(&ids[0]);
    let second = env.manifest_json(&ids[1]);
    assert_eq!(first["source_snapshot_id"], second["source_snapshot_id"]);
    assert_ne!(first["config_files"], second["config_files"]);
}
