mod common;

use std::fs;

use common::TestEnv;
use malm::{
    ApprovalV1, CommitRequestV1, FormatComponentAuthorizationV1, ProfileSwitchRequestV1,
    StaticDeploymentPrepareRequestV1, StaticGraphAcquisitionV1,
};
use malm_pack::{
    LockV1, LockedPackV1, LockedSourceV1, PackFileV1, PackManifestV1, PackPath, encode_pack_v1,
    lock_graph_digest, pack_content_digest,
};
use malm_tree::file_object_digest_v1;
use malm_types::{ContributionName, DeploymentName, Digest, NamespaceName, PackageId};
fn fixture() -> (LockV1, Digest, Vec<PackFileV1>) {
    let dark = b"theme=dark\n";
    let light = b"theme=light\n";
    let dark_path = PackPath::new("assets/dark.conf").unwrap();
    let light_path = PackPath::new("assets/light.conf").unwrap();
    let config_path = PackPath::new(malm_config::CONFIG_FILE).unwrap();
    let config = format!(
        r#"rich-config schema-version=1 default-profile="dark" {{
    includes {{}}
    modules {{}}
    variables {{}}
    fragments {{}}
    slots {{}}
    statements {{}}
    profiles {{
        profile "dark" abstract=#false {{
            extends {{}}
            statements {{}}
            outputs {{
                regular-file "theme" destination="config/theme.conf" source="{}" source-kind="asset" raw-digest="{}" object-digest="{}" byte-len={} executable=#false
            }}
        }}
        profile "light" abstract=#false {{
            extends {{}}
            statements {{}}
            outputs {{
                regular-file "theme" destination="config/theme.conf" source="{}" source-kind="asset" raw-digest="{}" object-digest="{}" byte-len={} executable=#false
            }}
        }}
    }}
}}"#,
        dark_path,
        Digest::sha256(dark),
        file_object_digest_v1(dark).unwrap(),
        dark.len(),
        light_path,
        Digest::sha256(light),
        file_object_digest_v1(light).unwrap(),
        light.len(),
    );
    let manifest = PackManifestV1::new(
        PackageId::new("com.example.switch.cli").unwrap(),
        vec![],
        vec![],
        vec![],
        vec![],
        vec![dark_path.clone(), light_path.clone()],
        vec![],
    )
    .unwrap()
    .with_config_documents(vec![config_path.clone()])
    .unwrap();
    let files = vec![
        PackFileV1::new(
            PackPath::new("malm-pack.kdl").unwrap(),
            encode_pack_v1(&manifest),
        ),
        PackFileV1::new(config_path, config),
        PackFileV1::new(dark_path, dark),
        PackFileV1::new(light_path, light),
    ];
    let digest = pack_content_digest(files.iter().map(|file| (file.path(), file.bytes()))).unwrap();
    let root = LockedPackV1::new(
        manifest.package_id().clone(),
        LockedSourceV1::Root,
        digest.clone(),
        vec![],
        vec![],
    )
    .unwrap();
    (
        LockV1::new(root.node_id().clone(), vec![root]).unwrap(),
        digest,
        files,
    )
}

fn seed(env: &TestEnv) -> (Digest, Digest) {
    fs::create_dir(env.home().join("config")).unwrap();
    let engine = env.engine();
    engine.initialize_store().unwrap();
    let (lock, digest, files) = fixture();
    engine.publish_pack_object_v1(&digest, &files).unwrap();
    let initial = engine
        .prepare_static_deployment_v1(&StaticDeploymentPrepareRequestV1::new(
            lock.clone(),
            StaticGraphAcquisitionV1::cached(),
            FormatComponentAuthorizationV1::default(),
            Some(ContributionName::new("dark").unwrap()),
            NamespaceName::new("cli-switch").unwrap(),
            DeploymentName::new("home").unwrap(),
        ))
        .unwrap();
    let head = engine
        .commit_v1(&CommitRequestV1::new(
            initial.plan_id().clone(),
            ApprovalV1::new(initial.plan_id().clone(), initial.approval_digest().clone()),
        ))
        .unwrap()
        .head()
        .clone();
    (head, lock_graph_digest(&lock))
}

#[test]
fn cli_switch_json_and_human_output_match_the_engine_plan() {
    let env = TestEnv::new();
    let (head, graph) = seed(&env);
    let expected = env
        .engine()
        .prepare_profile_switch_v1(&ProfileSwitchRequestV1::new(
            NamespaceName::new("cli-switch").unwrap(),
            ContributionName::new("light").unwrap(),
        ))
        .unwrap();

    let json = env.malm(&[
        "plan",
        "--format",
        "json",
        "switch-profile",
        "light",
        "--namespace",
        "cli-switch",
    ]);
    assert!(
        json.status.success(),
        "switch JSON failed: {}",
        String::from_utf8_lossy(&json.stderr)
    );
    let envelope: serde_json::Value = serde_json::from_slice(&json.stdout).unwrap();
    assert_eq!(envelope.as_object().unwrap().len(), 5);
    assert_eq!(envelope["schema_version"], 1);
    assert_eq!(envelope["command"], "plan.switch-profile");
    assert_eq!(envelope["outcome"], "planned");
    assert_eq!(envelope["diagnostics"], serde_json::json!([]));
    let json = &envelope["data"];
    assert_eq!(json["plan_id"], expected.plan_id().as_str());
    assert_eq!(json["namespace"], "cli-switch");
    assert_eq!(json["expected_head"], head.as_str());
    assert_eq!(json["graph_digest"], graph.as_str());
    assert_eq!(json["transition"]["kind"], "reconcile");
    assert_eq!(json["tracked_root"], serde_json::Value::Null);
    assert_eq!(json["operation_count"], 1);

    let human = env.malm(&[
        "plan",
        "switch-profile",
        "light",
        "--namespace",
        "cli-switch",
    ]);
    assert!(
        human.status.success(),
        "switch human output failed: {}",
        String::from_utf8_lossy(&human.stderr)
    );
    let human = String::from_utf8(human.stdout).unwrap();
    assert!(human.contains("Plan ready"));
    assert!(human.contains(&format!("plan:{}", &expected.plan_id().as_str()[3..15])));
    assert!(human.contains("cli-switch"));
    assert!(human.contains("reconcile desired state"));
    assert!(human.contains("home:config/theme.conf"));
}

#[test]
fn cli_switch_plan_applies_a_routine_owned_switch_and_refuses_nothing() {
    let env = TestEnv::new();
    let (_head, _graph) = seed(&env);
    assert_eq!(
        fs::read(env.home().join("config/theme.conf")).unwrap(),
        b"theme=dark\n"
    );

    // The namespace head owns every touched target, so replacement is advisory
    // and `--yes` can commit without prompting.
    let planned = env.malm(&[
        "plan",
        "--format",
        "json",
        "switch-profile",
        "light",
        "--namespace",
        "cli-switch",
    ]);
    assert!(planned.status.success());
    let planned: serde_json::Value = serde_json::from_slice(&planned.stdout).unwrap();
    let plan = &planned["data"];
    let output = env.malm(&["plan", "apply", plan["plan_id"].as_str().unwrap(), "--yes"]);
    assert!(
        output.status.success(),
        "plan apply --yes failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        fs::read(env.home().join("config/theme.conf")).unwrap(),
        b"theme=light\n",
        "the switch committed and deployed the selected profile"
    );

    // A non-terminal invocation without `--yes` leaves the plan uncommitted and exits 1.
    let planned = env.malm(&[
        "plan",
        "--format",
        "json",
        "switch-profile",
        "dark",
        "--namespace",
        "cli-switch",
    ]);
    assert!(planned.status.success());
    let planned: serde_json::Value = serde_json::from_slice(&planned.stdout).unwrap();
    let output = env.malm(&[
        "plan",
        "apply",
        planned["data"]["plan_id"].as_str().unwrap(),
    ]);
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(
        fs::read(env.home().join("config/theme.conf")).unwrap(),
        b"theme=light\n",
        "a non-interactive run without --yes leaves the target untouched"
    );
}

#[test]
fn cli_switch_exposes_only_namespace_and_target_host_options() {
    let env = TestEnv::new();
    let output = env.malm(&["plan", "switch-profile", "--help"]);
    assert!(output.status.success());
    let help = String::from_utf8(output.stdout).unwrap();
    assert!(help.contains("<PROFILE>"));
    assert!(help.contains("--namespace <NAMESPACE>"));
    assert!(help.contains("--target <NAME=ABSOLUTE_PATH>"));
    for forbidden in [
        "--source",
        "--lock",
        "--cached",
        "--allow-local",
        "--allow-git",
        "--git-scratch",
        "--git-executable",
        "--root-scratch",
        "--allow-component",
        "--plan-only",
        "--yes",
    ] {
        assert!(
            !help.contains(forbidden),
            "switch exposed acquisition option {forbidden}"
        );
    }
    assert!(!env.state_root().exists());
}
