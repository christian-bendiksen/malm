//! End-to-end proof that authoring roots reach the same locked graph, durable
//! prepare, reconciliation, and offline commit boundaries as rich config.

use std::{fs, os::unix::fs::PermissionsExt};

use malm_engine::{
    ApprovalV1, CommitRequestV1, Engine, EngineConfig, EnginePorts, FormatComponentAuthorizationV1,
    StaticDeploymentPrepareRequestV1, StaticGraphAcquisitionV1, StoreAccess,
};
use malm_pack::{
    LockV1, LockedPackV1, LockedSourceV1, PackFileV1, PackManifestV1, PackPath, encode_pack_v1,
    pack_content_digest,
};
use malm_types::{ContributionName, DeploymentName, Digest, NamespaceName, PackageId};

const NAMESPACE: &str = "workstation";

const ROOT_CONFIG: &str = r#"config target="~/.config" default-profile="calm"

module "greeter" {
    description "renders a greeting and copies a native fragment"

    inputs {
        input "name" type="string" default="world"
    }

    outputs {
        render "greeter/greeting.conf" format="key-value" separator="=" quote="none" {
            "greeting" (f)"hello {{name}}"
        }
        render "~/.local/bin/greet" format="text" executable=#true {
            @include-file "./greeter/greet.tpl" interpolate=#true
        }
        file "./greeter/static.conf" to="greeter/static.conf"
        symlink "~/.config/greeter/greeting.conf" to="greeter/current.conf" if-missing="allow"
    }
}

profile "calm" {
    use "greeter"
}

profile "loud" {
    use "greeter" {
        with {
            name "everyone"
        }
    }
}

profile "empty" {}
"#;

const GREET_TEMPLATE: &str = "#!/bin/sh\necho \"hello {{name:text}}\"\n";
const STATIC_CONF: &str = "static=true\n";

fn fixture() -> (LockV1, Digest, Vec<PackFileV1>) {
    let manifest = PackManifestV1::new(
        PackageId::new("com.example.authoring").unwrap(),
        vec![],
        vec![],
        vec![
            PackPath::new("greeter/greet.tpl").unwrap(),
            PackPath::new("greeter/static.conf").unwrap(),
        ],
        vec![],
        vec![],
        vec![],
    )
    .unwrap()
    .with_config_documents(vec![PackPath::new(malm_config::CONFIG_FILE).unwrap()])
    .unwrap();
    let files = vec![
        PackFileV1::new(
            PackPath::new("malm-pack.kdl").unwrap(),
            encode_pack_v1(&manifest),
        ),
        PackFileV1::new(
            PackPath::new(malm_config::CONFIG_FILE).unwrap(),
            ROOT_CONFIG.as_bytes().to_vec(),
        ),
        PackFileV1::new(
            PackPath::new("greeter/greet.tpl").unwrap(),
            GREET_TEMPLATE.as_bytes().to_vec(),
        ),
        PackFileV1::new(
            PackPath::new("greeter/static.conf").unwrap(),
            STATIC_CONF.as_bytes().to_vec(),
        ),
    ];
    let content_digest =
        pack_content_digest(files.iter().map(|file| (file.path(), file.bytes()))).unwrap();
    let root = LockedPackV1::new(
        manifest.package_id().clone(),
        LockedSourceV1::Root,
        content_digest.clone(),
        vec![],
        vec![],
    )
    .unwrap();
    let lock = LockV1::new(root.node_id().clone(), vec![root]).unwrap();
    (lock, content_digest, files)
}

fn engine(temp: &tempfile::TempDir) -> Engine {
    let state = temp.path().join("state");
    let target = temp.path().join("target");
    if !state.exists() {
        fs::create_dir(&state).unwrap();
        fs::set_permissions(&state, fs::Permissions::from_mode(0o700)).unwrap();
    }
    // The Engine does not create unmanaged target roots; this operator-owned
    // skeleton supplies the parent authority required before preparation.
    fs::create_dir_all(target.join(".config/greeter")).unwrap();
    fs::create_dir_all(target.join(".local/bin")).unwrap();
    Engine::new(
        EngineConfig::from_state_home(&state, StoreAccess::ReadWrite)
            .unwrap()
            .with_target_authority(DeploymentName::new("home").unwrap(), target)
            .unwrap(),
        EnginePorts::system(),
    )
}

fn request(lock: LockV1, profile: Option<&str>) -> StaticDeploymentPrepareRequestV1 {
    StaticDeploymentPrepareRequestV1::new(
        lock,
        StaticGraphAcquisitionV1::cached(),
        FormatComponentAuthorizationV1::default(),
        profile.map(|name| ContributionName::new(name).unwrap()),
        NamespaceName::new(NAMESPACE).unwrap(),
        DeploymentName::new("home").unwrap(),
    )
}

#[test]
fn authoring_root_prepares_and_commits_through_the_static_path() {
    let temp = tempfile::tempdir().unwrap();
    let (lock, content_digest, files) = fixture();
    let engine = engine(&temp);
    engine.initialize_store().unwrap();
    engine
        .publish_pack_object_v1(&content_digest, &files)
        .unwrap();

    let plan = engine
        .prepare_static_deployment_v1(&request(lock.clone(), None))
        .unwrap();

    let operations = plan.operations();
    assert_eq!(operations.len(), 4, "three files and one symlink");
    let target = temp.path().join("target");
    assert!(!target.join(".config/greeter/greeting.conf").exists());

    engine
        .commit_v1(&CommitRequestV1::new(
            plan.plan_id().clone(),
            ApprovalV1::new(plan.plan_id().clone(), plan.approval_digest().clone()),
        ))
        .unwrap();

    assert_eq!(
        fs::read_to_string(target.join(".config/greeter/greeting.conf")).unwrap(),
        "greeting=hello world\n"
    );
    assert_eq!(
        fs::read_to_string(target.join(".config/greeter/static.conf")).unwrap(),
        STATIC_CONF
    );
    let script = target.join(".local/bin/greet");
    assert_eq!(
        fs::read_to_string(&script).unwrap(),
        "#!/bin/sh\necho \"hello world\"\n"
    );
    let mode = fs::metadata(&script).unwrap().permissions().mode();
    assert_eq!(mode & 0o111, 0o111, "declared executable mode is applied");
    let link = target.join(".config/greeter/current.conf");
    assert_eq!(
        fs::read_link(&link).unwrap().to_str().unwrap(),
        "greeting.conf",
        "symlink target is spelled relative to the link parent"
    );
}

#[test]
fn pre_existing_unmanaged_files_adopt_behind_replace_findings() {
    let temp = tempfile::tempdir().unwrap();
    let (lock, content_digest, files) = fixture();
    let engine = engine(&temp);
    engine.initialize_store().unwrap();
    engine
        .publish_pack_object_v1(&content_digest, &files)
        .unwrap();

    // A pre-existing file outside namespace ownership becomes an
    // approval-gated adoption rather than requiring manual deletion.
    let target = temp.path().join("target");
    let existing = target.join(".config/greeter/greeting.conf");
    fs::write(&existing, "greeting=handwritten\n").unwrap();

    let plan = engine
        .prepare_static_deployment_v1(&request(lock.clone(), None))
        .unwrap();
    let adoption: Vec<_> = plan
        .findings()
        .iter()
        .filter(|finding| finding.code() == "replace-existing")
        .collect();
    assert_eq!(
        adoption.len(),
        1,
        "one adoption finding for the present leaf"
    );
    assert!(adoption[0].approval_required());
    assert!(adoption[0].message().contains("greeter/greeting.conf"));

    engine
        .commit_v1(&CommitRequestV1::new(
            plan.plan_id().clone(),
            ApprovalV1::new(plan.plan_id().clone(), plan.approval_digest().clone()),
        ))
        .unwrap();
    assert_eq!(
        fs::read_to_string(&existing).unwrap(),
        "greeting=hello world\n",
        "the approved replacement deploys the rendered bytes"
    );

    // After adoption, namespace ownership converts unchanged targets to exact
    // assertions and removes the replacement finding.
    let second = engine
        .prepare_static_deployment_v1(&request(lock, None))
        .unwrap();
    assert!(
        second
            .findings()
            .iter()
            .all(|finding| !finding.approval_required()),
        "a quiet repeat apply carries no approval-required findings"
    );
    assert!(
        second.operations().iter().all(|operation| matches!(
            operation,
            malm_types::PrepareOperationV1::AssertExact { .. }
        )),
        "unchanged owned targets reconcile to exact assertions"
    );
    engine
        .commit_v1(&CommitRequestV1::new(
            second.plan_id().clone(),
            ApprovalV1::new(second.plan_id().clone(), second.approval_digest().clone()),
        ))
        .unwrap();
}

#[test]
fn locally_modified_targets_restore_behind_approval_findings() {
    let temp = tempfile::tempdir().unwrap();
    let (lock, content_digest, files) = fixture();
    let engine = engine(&temp);
    engine.initialize_store().unwrap();
    engine
        .publish_pack_object_v1(&content_digest, &files)
        .unwrap();
    let plan = engine
        .prepare_static_deployment_v1(&request(lock.clone(), None))
        .unwrap();
    engine
        .commit_v1(&CommitRequestV1::new(
            plan.plan_id().clone(),
            ApprovalV1::new(plan.plan_id().clone(), plan.approval_digest().clone()),
        ))
        .unwrap();

    // A hand edit changes managed content without changing namespace ownership.
    let target = temp.path().join("target");
    let modified = target.join(".config/greeter/greeting.conf");
    fs::write(&modified, "greeting=my local tweak\n").unwrap();

    // Reconciliation replaces the stale assertion with a restore from retained
    // bytes, gated because the restore discards the local edit.
    let restore = engine
        .prepare_static_deployment_v1(&request(lock.clone(), None))
        .unwrap();
    let findings: Vec<_> = restore
        .findings()
        .iter()
        .filter(|finding| finding.code() == "restore-modified")
        .collect();
    assert_eq!(
        findings.len(),
        1,
        "one restore finding for the drifted file"
    );
    assert!(findings[0].approval_required());
    assert!(findings[0].message().contains("greeter/greeting.conf"));
    assert!(findings[0].message().contains("local modifications"));

    engine
        .commit_v1(&CommitRequestV1::new(
            restore.plan_id().clone(),
            ApprovalV1::new(restore.plan_id().clone(), restore.approval_digest().clone()),
        ))
        .unwrap();
    assert_eq!(
        fs::read_to_string(&modified).unwrap(),
        "greeting=hello world\n",
        "the approved restore reinstates the managed content"
    );

    // Once bytes match retained state, reconciliation emits no restore finding.
    let quiet = engine
        .prepare_static_deployment_v1(&request(lock, None))
        .unwrap();
    assert!(
        quiet
            .findings()
            .iter()
            .all(|finding| !finding.approval_required()),
        "no approval findings once the drift is restored"
    );
}

fn commit(engine: &Engine, plan: &malm_engine::PreparedDeploymentV1) {
    engine
        .commit_v1(&CommitRequestV1::new(
            plan.plan_id().clone(),
            ApprovalV1::new(plan.plan_id().clone(), plan.approval_digest().clone()),
        ))
        .unwrap();
}

#[test]
fn deleted_managed_directories_are_restored_with_advisory_findings() {
    let temp = tempfile::tempdir().unwrap();
    let (lock, content_digest, files) = fixture();
    let engine = engine(&temp);
    engine.initialize_store().unwrap();
    engine
        .publish_pack_object_v1(&content_digest, &files)
        .unwrap();
    let plan = engine
        .prepare_static_deployment_v1(&request(lock.clone(), None))
        .unwrap();
    commit(&engine, &plan);

    // Deleting the managed subtree exercises ancestor creation and leaf
    // restoration from retained state.
    let target = temp.path().join("target");
    fs::remove_dir_all(target.join(".config/greeter")).unwrap();

    let restore = engine
        .prepare_static_deployment_v1(&request(lock.clone(), None))
        .unwrap();
    let directory_findings: Vec<_> = restore
        .findings()
        .iter()
        .filter(|finding| finding.code() == "restore-missing-directory")
        .collect();
    assert_eq!(
        directory_findings.len(),
        1,
        "one advisory finding for the recreated ancestor directory: {:?}",
        restore.findings()
    );
    assert!(!directory_findings[0].approval_required());
    assert!(directory_findings[0].message().contains(".config/greeter"));
    let leaf_findings: Vec<_> = restore
        .findings()
        .iter()
        .filter(|finding| finding.code() == "restore-missing")
        .collect();
    assert_eq!(
        leaf_findings.len(),
        3,
        "two deleted files and one deleted symlink restore: {:?}",
        restore.findings()
    );
    assert!(
        leaf_findings
            .iter()
            .all(|finding| !finding.approval_required()),
        "restoring deleted managed content destroys nothing"
    );

    commit(&engine, &restore);
    let directory = target.join(".config/greeter");
    assert_eq!(
        fs::metadata(&directory).unwrap().permissions().mode() & 0o7777,
        0o755,
        "recreated ancestor directories take the conventional mode"
    );
    assert_eq!(
        fs::read_to_string(directory.join("greeting.conf")).unwrap(),
        "greeting=hello world\n"
    );
    assert_eq!(
        fs::read_to_string(directory.join("static.conf")).unwrap(),
        STATIC_CONF
    );
    assert_eq!(
        fs::read_link(directory.join("current.conf"))
            .unwrap()
            .to_str()
            .unwrap(),
        "greeting.conf"
    );

    // Restoration adds the directory to namespace ownership, so later plans
    // assert its exact state.
    let quiet = engine
        .prepare_static_deployment_v1(&request(lock.clone(), None))
        .unwrap();
    assert!(
        quiet
            .findings()
            .iter()
            .all(|finding| !finding.approval_required())
    );
    assert!(
        quiet.operations().iter().any(|operation| matches!(
            operation,
            malm_types::PrepareOperationV1::AssertExact { .. }
        ) && operation.relative_path()
            == ".config/greeter"),
        "the restored directory is asserted as an owned target"
    );
    commit(&engine, &quiet);

    // A later deletion follows the owned-directory restore path rather than
    // first-time ancestor creation.
    fs::remove_dir_all(&directory).unwrap();
    let again = engine
        .prepare_static_deployment_v1(&request(lock, None))
        .unwrap();
    assert!(
        again
            .findings()
            .iter()
            .any(|finding| finding.code() == "restore-missing"
                && finding.message().contains(".config/greeter")
                && !finding.approval_required()),
        "a re-deleted owned directory restores behind the advisory finding: {:?}",
        again.findings()
    );
    commit(&engine, &again);
    assert_eq!(
        fs::read_to_string(directory.join("greeting.conf")).unwrap(),
        "greeting=hello world\n"
    );
}

#[test]
fn deleted_managed_files_are_restored_with_advisory_findings() {
    let temp = tempfile::tempdir().unwrap();
    let (lock, content_digest, files) = fixture();
    let engine = engine(&temp);
    engine.initialize_store().unwrap();
    engine
        .publish_pack_object_v1(&content_digest, &files)
        .unwrap();
    let plan = engine
        .prepare_static_deployment_v1(&request(lock.clone(), None))
        .unwrap();
    commit(&engine, &plan);

    let target = temp.path().join("target");
    let deleted = target.join(".config/greeter/greeting.conf");
    fs::remove_file(&deleted).unwrap();

    let restore = engine
        .prepare_static_deployment_v1(&request(lock.clone(), None))
        .unwrap();
    let findings: Vec<_> = restore
        .findings()
        .iter()
        .filter(|finding| finding.code() == "restore-missing")
        .collect();
    assert_eq!(
        findings.len(),
        1,
        "one restore finding for the deleted file"
    );
    assert!(
        !findings[0].approval_required(),
        "recreating a deleted file destroys nothing"
    );
    assert!(findings[0].message().contains("greeter/greeting.conf"));
    assert!(
        restore
            .findings()
            .iter()
            .all(|finding| finding.code() != "restore-missing-directory"),
        "the intact parent directory needs no recreation"
    );

    commit(&engine, &restore);
    assert_eq!(
        fs::read_to_string(&deleted).unwrap(),
        "greeting=hello world\n"
    );

    let quiet = engine
        .prepare_static_deployment_v1(&request(lock, None))
        .unwrap();
    assert!(
        quiet
            .findings()
            .iter()
            .all(|finding| !finding.approval_required())
    );
}

#[test]
fn deleted_and_modified_targets_reconcile_in_one_plan() {
    let temp = tempfile::tempdir().unwrap();
    let (lock, content_digest, files) = fixture();
    let engine = engine(&temp);
    engine.initialize_store().unwrap();
    engine
        .publish_pack_object_v1(&content_digest, &files)
        .unwrap();
    let plan = engine
        .prepare_static_deployment_v1(&request(lock.clone(), None))
        .unwrap();
    commit(&engine, &plan);

    let target = temp.path().join("target");
    fs::remove_dir_all(target.join(".config/greeter")).unwrap();
    fs::write(target.join(".local/bin/greet"), "#!/bin/sh\necho tweaked\n").unwrap();

    let reconcile = engine
        .prepare_static_deployment_v1(&request(lock, None))
        .unwrap();
    let modified: Vec<_> = reconcile
        .findings()
        .iter()
        .filter(|finding| finding.code() == "restore-modified")
        .collect();
    assert_eq!(modified.len(), 1);
    assert!(
        modified[0].approval_required(),
        "overwriting local edits stays approval-gated"
    );
    assert!(
        reconcile
            .findings()
            .iter()
            .any(|finding| finding.code() == "restore-missing-directory"
                && !finding.approval_required()),
        "deletion restores stay advisory alongside the gated drift restore"
    );

    commit(&engine, &reconcile);
    assert_eq!(
        fs::read_to_string(target.join(".config/greeter/greeting.conf")).unwrap(),
        "greeting=hello world\n"
    );
    assert_eq!(
        fs::read_to_string(target.join(".local/bin/greet")).unwrap(),
        "#!/bin/sh\necho \"hello world\"\n"
    );
}

#[test]
fn profile_selection_changes_rendered_bytes_and_plan_identity() {
    let temp = tempfile::tempdir().unwrap();
    let (lock, content_digest, files) = fixture();
    let engine = engine(&temp);
    engine.initialize_store().unwrap();
    engine
        .publish_pack_object_v1(&content_digest, &files)
        .unwrap();

    let calm = engine
        .prepare_static_deployment_v1(&request(lock.clone(), Some("calm")))
        .unwrap();
    let calm_again = engine
        .prepare_static_deployment_v1(&request(lock.clone(), Some("calm")))
        .unwrap();
    let loud = engine
        .prepare_static_deployment_v1(&request(lock, Some("loud")))
        .unwrap();

    assert_eq!(
        calm.plan_id(),
        calm_again.plan_id(),
        "identical inputs mint identical plans"
    );
    assert_ne!(calm.plan_id(), loud.plan_id());
    let loud_greeting = loud
        .artifacts()
        .iter()
        .find(|artifact| artifact.id().as_str() == "authoring/output-0000")
        .expect("first rendered output");
    let bytes = engine
        .artifact_v1(loud.plan_id(), loud_greeting.id())
        .unwrap();
    assert_eq!(bytes.bytes(), b"greeting=hello everyone\n");
}

#[test]
fn abstract_or_unknown_profiles_fail_closed() {
    let temp = tempfile::tempdir().unwrap();
    let (lock, content_digest, files) = fixture();
    let engine = engine(&temp);
    engine.initialize_store().unwrap();
    engine
        .publish_pack_object_v1(&content_digest, &files)
        .unwrap();

    let error = engine
        .prepare_static_deployment_v1(&request(lock, Some("missing")))
        .unwrap_err();
    let rendered = format!("{error:?}");
    assert!(
        rendered.contains("missing"),
        "unknown profile is reported: {rendered}"
    );
}

mod asset_fixture {
    const BLOCK: usize = 512;

    fn write_octal(field: &mut [u8], mut value: u64) {
        let digits = field.len() - 1;
        field.fill(b'0');
        *field.last_mut().unwrap() = 0;
        for byte in field[..digits].iter_mut().rev() {
            *byte = b'0' + (value & 7) as u8;
            value >>= 3;
        }
        assert_eq!(value, 0);
    }

    fn header(path: &[u8], mode: u64, size: u64, typeflag: u8) -> [u8; BLOCK] {
        let mut header = [0_u8; BLOCK];
        header[..path.len()].copy_from_slice(path);
        write_octal(&mut header[100..108], mode);
        write_octal(&mut header[108..116], 0);
        write_octal(&mut header[116..124], 0);
        write_octal(&mut header[124..136], size);
        write_octal(&mut header[136..148], 1_700_000_000);
        header[156] = typeflag;
        header[257..263].copy_from_slice(b"ustar\0");
        header[263..265].copy_from_slice(b"00");
        write_octal(&mut header[329..337], 0);
        write_octal(&mut header[337..345], 0);
        header[148..156].fill(b' ');
        let sum: u64 = header.iter().map(|byte| u64::from(*byte)).sum();
        let mut digits = [0u8; 6];
        write_octal(&mut digits[..], 0);
        let mut checksum = [b'0'; 6];
        let mut value = sum;
        for byte in checksum.iter_mut().rev() {
            *byte = b'0' + (value & 7) as u8;
            value >>= 3;
        }
        header[148..154].copy_from_slice(&checksum);
        header[154] = 0;
        header[155] = b' ';
        header
    }

    /// Returns an xz-compressed tar with `theme/colors.conf` inside.
    pub fn payload() -> (Vec<u8>, &'static [u8]) {
        const CONTENT: &[u8] = b"accent=teal\n";
        let mut tar = Vec::new();
        tar.extend_from_slice(&header(b"theme", 0o755, 0, b'5'));
        tar.extend_from_slice(&header(
            b"theme/colors.conf",
            0o644,
            CONTENT.len() as u64,
            b'0',
        ));
        tar.extend_from_slice(CONTENT);
        tar.resize(tar.len() + (BLOCK - CONTENT.len() % BLOCK), 0);
        tar.resize(tar.len() + 2 * BLOCK, 0);
        let mut compressed = Vec::new();
        lzma_rs::xz_compress(&mut std::io::Cursor::new(&tar), &mut compressed).unwrap();
        (compressed, CONTENT)
    }
}

#[test]
fn vendored_assets_deploy_as_archive_trees() {
    let (compressed, content) = asset_fixture::payload();
    let sha256 = {
        let digest = Digest::sha256(&compressed);
        digest.as_str()["sha256-".len()..].to_owned()
    };

    let root_config = format!(
        r#"config target="~/.config" default-profile="calm"

assets {{
    asset "theme-pack" {{
        url "https://example.com/theme.tar.xz"
        dst "~/.local/share/themes"
        format "tar-xz"
        sha256 "{sha256}"
        path "vendor/theme.tar.xz"
    }}
}}

module "noop" {{
    description "keeps the profile non-empty"
    outputs {{
        render "noop/marker.conf" format="text" {{
            @line "present"
        }}
    }}
}}

profile "calm" {{
    use "noop"
}}
"#
    );

    let manifest = PackManifestV1::new(
        PackageId::new("com.example.assets").unwrap(),
        vec![],
        vec![],
        vec![],
        vec![],
        vec![PackPath::new("vendor/theme.tar.xz").unwrap()],
        vec![],
    )
    .unwrap()
    .with_config_documents(vec![PackPath::new(malm_config::CONFIG_FILE).unwrap()])
    .unwrap();
    let files = vec![
        PackFileV1::new(
            PackPath::new("malm-pack.kdl").unwrap(),
            encode_pack_v1(&manifest),
        ),
        PackFileV1::new(
            PackPath::new(malm_config::CONFIG_FILE).unwrap(),
            root_config.into_bytes(),
        ),
        PackFileV1::new(PackPath::new("vendor/theme.tar.xz").unwrap(), compressed),
    ];
    let content_digest =
        pack_content_digest(files.iter().map(|file| (file.path(), file.bytes()))).unwrap();
    let root = LockedPackV1::new(
        manifest.package_id().clone(),
        LockedSourceV1::Root,
        content_digest.clone(),
        vec![],
        vec![],
    )
    .unwrap();
    let lock = LockV1::new(root.node_id().clone(), vec![root]).unwrap();

    let temp = tempfile::tempdir().unwrap();
    let engine = engine(&temp);
    let target = temp.path().join("target");
    fs::create_dir_all(target.join(".config/noop")).unwrap();
    fs::create_dir_all(target.join(".local/share/themes")).unwrap();
    engine.initialize_store().unwrap();
    engine
        .publish_pack_object_v1(&content_digest, &files)
        .unwrap();

    let plan = engine
        .prepare_static_deployment_v1(&request(lock, None))
        .unwrap();
    engine
        .commit_v1(&CommitRequestV1::new(
            plan.plan_id().clone(),
            ApprovalV1::new(plan.plan_id().clone(), plan.approval_digest().clone()),
        ))
        .unwrap();

    assert_eq!(
        fs::read(target.join(".local/share/themes/theme-pack/theme/colors.conf")).unwrap(),
        content,
        "archive root deployed at dst/<asset-name>"
    );
    assert_eq!(
        fs::read_to_string(target.join(".config/noop/marker.conf")).unwrap(),
        "present\n"
    );
}

#[test]
fn declared_overlays_layer_values_and_change_plan_identity() {
    const OVERLAY_ROOT: &str = r#"config target="~/.config" default-profile="calm"

overlay "local" path="~/.config/malm/local.kdl" optional=#true

module "greeter" {
    description "renders one overlayable greeting"
    inputs {
        input "name" type="string" default="world"
    }
    outputs {
        render "greeter/greeting.conf" format="key-value" separator="=" quote="none" {
            "greeting" (f)"hello {{name}}"
        }
    }
}

profile "calm" {
    use "greeter"
}
"#;
    let manifest = PackManifestV1::new(
        PackageId::new("com.example.overlay").unwrap(),
        vec![],
        vec![],
        vec![],
        vec![],
        vec![],
        vec![],
    )
    .unwrap()
    .with_config_documents(vec![PackPath::new(malm_config::CONFIG_FILE).unwrap()])
    .unwrap();
    let files = vec![
        PackFileV1::new(
            PackPath::new("malm-pack.kdl").unwrap(),
            encode_pack_v1(&manifest),
        ),
        PackFileV1::new(
            PackPath::new(malm_config::CONFIG_FILE).unwrap(),
            OVERLAY_ROOT.as_bytes().to_vec(),
        ),
    ];
    let content_digest =
        pack_content_digest(files.iter().map(|file| (file.path(), file.bytes()))).unwrap();
    let root = LockedPackV1::new(
        manifest.package_id().clone(),
        LockedSourceV1::Root,
        content_digest.clone(),
        vec![],
        vec![],
    )
    .unwrap();
    let lock = LockV1::new(root.node_id().clone(), vec![root]).unwrap();

    let temp = tempfile::tempdir().unwrap();
    let engine = engine(&temp);
    let target = temp.path().join("target");
    engine.initialize_store().unwrap();
    engine
        .publish_pack_object_v1(&content_digest, &files)
        .unwrap();

    // An absent optional overlay uses defaults and contributes no applied input.
    let plain = engine
        .prepare_static_deployment_v1(&request(lock.clone(), None))
        .unwrap();
    assert_eq!(
        plain.artifacts()[0].digest(),
        &Digest::sha256(b"greeting=hello world\n"),
    );
    assert!(
        plain
            .inputs()
            .iter()
            .all(|input| !input.name().starts_with("overlay:")),
        "no overlay inputs are captured when the file is absent"
    );

    // A present overlay changes rendered bytes and plan identity and is retained
    // as both a captured input and an advisory finding.
    fs::create_dir_all(target.join(".config/malm")).unwrap();
    fs::write(
        target.join(".config/malm/local.kdl"),
        "extend-profile \"calm\" {\n    use \"greeter\" {\n        with {\n            name \"local\"\n        }\n    }\n}\n",
    )
    .unwrap();
    let layered = engine
        .prepare_static_deployment_v1(&request(lock.clone(), None))
        .unwrap();
    assert_eq!(
        layered.artifacts()[0].digest(),
        &Digest::sha256(b"greeting=hello local\n"),
    );
    assert_ne!(plain.plan_id(), layered.plan_id());
    assert!(
        layered
            .inputs()
            .iter()
            .any(|input| input.name() == "overlay:local:bytes"),
        "overlay bytes are a captured plan input"
    );
    assert!(
        layered
            .findings()
            .iter()
            .any(|finding| finding.code() == "AUTHORING-OVERLAY-APPLIED"
                && !finding.approval_required()),
        "the applied overlay is announced as an advisory finding"
    );

    // Unchanged overlay bytes reproduce the plan identity.
    let repeated = engine
        .prepare_static_deployment_v1(&request(lock, None))
        .unwrap();
    assert_eq!(layered.plan_id(), repeated.plan_id());
}

mod transform_harness {
    use std::sync::{Arc, Mutex};

    use malm_config::{
        RichDiagnosticSeverityV1, RichDiagnosticV1, RichNameV1, TransformFailureV1,
        TransformRequestV1, TransformResponseV1,
    };
    use malm_engine::{
        FormatComponentAuthorizationV1, FormatComponentExecutionIssue, FormatComponentExecutionPort,
    };

    pub const COMPONENT_BYTES: &[u8] = b"fake authoring transform component";

    /// Prefixes content deterministically for transform tests.
    pub struct FakeTransformPort {
        pub severity: Option<RichDiagnosticSeverityV1>,
        pub calls: Mutex<Vec<Vec<u8>>>,
    }

    impl FakeTransformPort {
        pub fn new(severity: Option<RichDiagnosticSeverityV1>) -> Arc<Self> {
            Arc::new(Self {
                severity,
                calls: Mutex::new(Vec::new()),
            })
        }
    }

    impl FormatComponentExecutionPort for FakeTransformPort {
        fn invoke(
            &self,
            authorization: &FormatComponentAuthorizationV1,
            _identity: &malm_config::TransformIdentityV1,
            component_bytes: &[u8],
            request: &TransformRequestV1,
        ) -> Result<Result<TransformResponseV1, TransformFailureV1>, FormatComponentExecutionIssue>
        {
            assert_eq!(component_bytes, COMPONENT_BYTES);
            assert!(authorization.permits(&malm_types::Digest::sha256(COMPONENT_BYTES)));
            assert!(request.options().is_empty());
            let content = request
                .resources()
                .values()
                .next()
                .unwrap()
                .bytes()
                .to_vec();
            self.calls.lock().unwrap().push(content.clone());
            let diagnostics = self
                .severity
                .map(|severity| {
                    RichDiagnosticV1::new(
                        severity,
                        RichNameV1::new("fake-transform").unwrap(),
                        "transform diagnostic",
                        None,
                        vec![],
                    )
                    .unwrap()
                })
                .into_iter()
                .collect();
            let mut output = b"transformed:".to_vec();
            output.extend_from_slice(&content);
            Ok(Ok(TransformResponseV1::new(
                output,
                "text/plain",
                diagnostics,
            )
            .unwrap()))
        }
    }
}

mod renderer_harness {
    use std::sync::{Arc, Mutex};

    use malm_config::{
        RichDiagnosticSeverityV1, RichDiagnosticV1, RichNameV1, TransformFailureV1,
        TransformRequestV1, TransformResponseV1,
    };
    use malm_engine::{
        FormatComponentAuthorizationV1, FormatComponentExecutionIssue, FormatComponentExecutionPort,
    };

    #[derive(Debug, Eq, PartialEq)]
    pub enum Call {
        Renderer {
            format: String,
            keys: Vec<String>,
            path: String,
        },
        Transform {
            content: Vec<u8>,
        },
    }

    pub struct FakeRendererPort {
        pub calls: Mutex<Vec<Call>>,
    }

    impl FakeRendererPort {
        pub fn new() -> Arc<Self> {
            Arc::new(Self {
                calls: Mutex::new(Vec::new()),
            })
        }
    }

    impl FormatComponentExecutionPort for FakeRendererPort {
        fn invoke(
            &self,
            authorization: &FormatComponentAuthorizationV1,
            identity: &malm_config::TransformIdentityV1,
            component_bytes: &[u8],
            request: &TransformRequestV1,
        ) -> Result<Result<TransformResponseV1, TransformFailureV1>, FormatComponentExecutionIssue>
        {
            assert_eq!(component_bytes, super::transform_harness::COMPONENT_BYTES);
            assert!(authorization.permits(&malm_types::Digest::sha256(component_bytes)));
            if request.resources().is_empty() {
                assert_eq!(identity.name().as_str(), "authoring-output-0000-renderer");
                assert_eq!(request.options().len(), 1);
                let option = request.options().values().next().unwrap();
                assert_eq!(option.name().as_str(), "format");
                let format = option.value().as_string().unwrap().to_owned();
                assert!(request.document().source_documents().is_empty());
                assert!(request.document().includes().is_empty());
                assert!(request.document().provenance().is_empty());
                let record = request.document().root().as_record().unwrap();
                let keys = record.keys().map(|key| key.as_str().to_owned()).collect();
                let path = record["path"].as_string().unwrap().to_owned();
                self.calls
                    .lock()
                    .unwrap()
                    .push(Call::Renderer { format, keys, path });
                return Ok(Ok(TransformResponseV1::new(
                    b"renderer-output\n".to_vec(),
                    "text/x-lua",
                    vec![
                        RichDiagnosticV1::new(
                            RichDiagnosticSeverityV1::Warning,
                            RichNameV1::new("renderer-warning").unwrap(),
                            "review renderer output",
                            None,
                            vec![],
                        )
                        .unwrap(),
                    ],
                )
                .unwrap()));
            }

            assert_eq!(identity.name().as_str(), "formatter");
            assert!(request.options().is_empty());
            assert_eq!(request.resources().len(), 1);
            assert!(request.document().root().as_record().unwrap().is_empty());
            let content = request
                .resources()
                .values()
                .next()
                .unwrap()
                .bytes()
                .to_vec();
            self.calls.lock().unwrap().push(Call::Transform {
                content: content.clone(),
            });
            let mut output = b"transformed:".to_vec();
            output.extend_from_slice(&content);
            Ok(Ok(
                TransformResponseV1::new(output, "text/x-lua", vec![]).unwrap()
            ))
        }
    }
}

fn transform_fixture(with_stages: bool) -> (LockV1, Digest, Vec<PackFileV1>, Digest) {
    let stages = if with_stages {
        "            @component-transform \"formatter\"\n            @component-transform \"formatter\"\n"
    } else {
        ""
    };
    let config = format!(
        r#"config target="~/.config" default-profile="calm"

module "themed" {{
    description "renders one transformed lua table"
    outputs {{
        render "themed/theme.lua" format="lua" {{
{stages}
            @line "return {{}}"
        }}
    }}
}}

profile "calm" {{
    use "themed"
}}
"#
    );
    let component_digest = Digest::sha256(transform_harness::COMPONENT_BYTES);
    let component = malm_pack::BundledComponentV1::new(
        ContributionName::new("formatter").unwrap(),
        PackPath::new("components/formatter.wasm").unwrap(),
        component_digest.clone(),
        malm_pack::ComponentInterfaceV1::FormatComponentV1,
    );
    let locked_component = malm_pack::LockedComponentV1::from_declaration(
        &component,
        Digest::sha256(b"formatter execution profile"),
    );
    let manifest = PackManifestV1::new(
        PackageId::new("com.example.transformed").unwrap(),
        vec![],
        vec![],
        vec![],
        vec![],
        vec![],
        vec![component],
    )
    .unwrap()
    .with_config_documents(vec![PackPath::new(malm_config::CONFIG_FILE).unwrap()])
    .unwrap();
    let files = vec![
        PackFileV1::new(
            PackPath::new("malm-pack.kdl").unwrap(),
            encode_pack_v1(&manifest),
        ),
        PackFileV1::new(
            PackPath::new(malm_config::CONFIG_FILE).unwrap(),
            config.into_bytes(),
        ),
        PackFileV1::new(
            PackPath::new("components/formatter.wasm").unwrap(),
            transform_harness::COMPONENT_BYTES.to_vec(),
        ),
    ];
    let content_digest =
        pack_content_digest(files.iter().map(|file| (file.path(), file.bytes()))).unwrap();
    let root = LockedPackV1::new(
        manifest.package_id().clone(),
        LockedSourceV1::Root,
        content_digest.clone(),
        vec![],
        vec![locked_component],
    )
    .unwrap();
    let lock = LockV1::new(root.node_id().clone(), vec![root]).unwrap();
    (lock, content_digest, files, component_digest)
}

fn renderer_fixture() -> (LockV1, Digest, Vec<PackFileV1>) {
    let config = r#"config target="~/.config" default-profile="calm"

module "themed" {
    description "renders a canonical document with a component"
    inputs {
        input "theme-path" type="path" default="~/.themes/current"
    }
    outputs {
        render "themed/theme.lua" format="lua-plugin" component-renderer="formatter" {
            @component-transform "formatter"
            zed 2
            alpha (f)"profile-{{profile.name}}"
            path (ref)"theme-path"
        }
    }
}

profile "calm" {
    use "themed"
}
"#;
    let component_digest = Digest::sha256(transform_harness::COMPONENT_BYTES);
    let component = malm_pack::BundledComponentV1::new(
        ContributionName::new("formatter").unwrap(),
        PackPath::new("components/formatter.wasm").unwrap(),
        component_digest,
        malm_pack::ComponentInterfaceV1::FormatComponentV1,
    );
    let locked_component = malm_pack::LockedComponentV1::from_declaration(
        &component,
        Digest::sha256(b"formatter execution profile"),
    );
    let manifest = PackManifestV1::new(
        PackageId::new("com.example.renderer").unwrap(),
        vec![],
        vec![],
        vec![],
        vec![],
        vec![],
        vec![component],
    )
    .unwrap()
    .with_config_documents(vec![PackPath::new(malm_config::CONFIG_FILE).unwrap()])
    .unwrap();
    let files = vec![
        PackFileV1::new(
            PackPath::new("malm-pack.kdl").unwrap(),
            encode_pack_v1(&manifest),
        ),
        PackFileV1::new(
            PackPath::new(malm_config::CONFIG_FILE).unwrap(),
            config.as_bytes().to_vec(),
        ),
        PackFileV1::new(
            PackPath::new("components/formatter.wasm").unwrap(),
            transform_harness::COMPONENT_BYTES.to_vec(),
        ),
    ];
    let content_digest =
        pack_content_digest(files.iter().map(|file| (file.path(), file.bytes()))).unwrap();
    let root = LockedPackV1::new(
        manifest.package_id().clone(),
        LockedSourceV1::Root,
        content_digest.clone(),
        vec![],
        vec![locked_component],
    )
    .unwrap();
    let lock = LockV1::new(root.node_id().clone(), vec![root]).unwrap();
    (lock, content_digest, files)
}

fn transform_engine(
    temp: &tempfile::TempDir,
    port: std::sync::Arc<dyn malm_engine::FormatComponentExecutionPort>,
) -> Engine {
    let state = temp.path().join("state");
    let target = temp.path().join("target");
    fs::create_dir(&state).unwrap();
    fs::set_permissions(&state, fs::Permissions::from_mode(0o700)).unwrap();
    fs::create_dir_all(target.join(".config/themed")).unwrap();
    Engine::new(
        EngineConfig::from_state_home(&state, StoreAccess::ReadWrite)
            .unwrap()
            .with_target_authority(DeploymentName::new("home").unwrap(), target)
            .unwrap(),
        EnginePorts::system().with_format_component_execution(port),
    )
}

#[test]
fn declared_component_transforms_produce_deployed_bytes() {
    use malm_config::RichDiagnosticSeverityV1;

    let (lock, content_digest, files, _) = transform_fixture(true);
    let temp = tempfile::tempdir().unwrap();
    let port = transform_harness::FakeTransformPort::new(None);
    let engine = transform_engine(&temp, port.clone());
    engine.initialize_store().unwrap();
    engine
        .publish_pack_object_v1(&content_digest, &files)
        .unwrap();

    let plan = engine
        .prepare_static_deployment_v1(&request(lock.clone(), None))
        .unwrap();
    assert!(plan.findings().is_empty());
    assert_eq!(plan.transforms().len(), 2);
    {
        let calls = port.calls.lock().unwrap();
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0], b"return {}\n");
        assert_eq!(calls[1], b"transformed:return {}\n");
    }
    engine
        .commit_v1(&CommitRequestV1::new(
            plan.plan_id().clone(),
            ApprovalV1::new(plan.plan_id().clone(), plan.approval_digest().clone()),
        ))
        .unwrap();
    assert_eq!(
        fs::read_to_string(temp.path().join("target/.config/themed/theme.lua")).unwrap(),
        "transformed:transformed:return {}\n"
    );

    let temp = tempfile::tempdir().unwrap();
    let port = transform_harness::FakeTransformPort::new(Some(RichDiagnosticSeverityV1::Warning));
    let engine = transform_engine(&temp, port);
    engine.initialize_store().unwrap();
    engine
        .publish_pack_object_v1(&content_digest, &files)
        .unwrap();
    let plan = engine
        .prepare_static_deployment_v1(&request(lock, None))
        .unwrap();
    assert!(
        plan.findings()
            .iter()
            .any(|finding| finding.approval_required()
                && finding.message().contains("transform diagnostic")),
        "transform warnings require explicit approval"
    );
}

#[test]
fn component_renderer_runs_before_output_transforms_with_canonical_inputs() {
    use renderer_harness::Call;

    let (lock, content_digest, files) = renderer_fixture();
    let temp = tempfile::tempdir().unwrap();
    let port = renderer_harness::FakeRendererPort::new();
    let engine = transform_engine(&temp, port.clone());
    engine.initialize_store().unwrap();
    engine
        .publish_pack_object_v1(&content_digest, &files)
        .unwrap();

    let plan = engine
        .prepare_static_deployment_v1(&request(lock, None))
        .unwrap();
    assert_eq!(
        *port.calls.lock().unwrap(),
        [
            Call::Renderer {
                format: "lua-plugin".to_owned(),
                keys: vec!["alpha".to_owned(), "path".to_owned(), "zed".to_owned()],
                path: "~/.themes/current".to_owned(),
            },
            Call::Transform {
                content: b"renderer-output\n".to_vec(),
            },
        ],
        "the renderer receives structured data first and its bytes feed the transform"
    );
    assert_eq!(plan.transforms().len(), 2);
    assert!(
        plan.transforms()
            .iter()
            .any(|provenance| provenance.name() == "authoring-output-0000-renderer")
    );
    assert_eq!(
        plan.transforms()
            .iter()
            .filter(|provenance| provenance.resources().is_empty())
            .count(),
        1
    );
    assert!(plan.transforms().iter().any(|provenance| {
        provenance.resources().len() == 1 && provenance.resources()[0].name() == "content"
    }));
    assert!(plan.findings().iter().any(|finding| {
        finding.code() == "transform-warning-authoring-output-0000-renderer-0"
            && finding.approval_required()
    }));
    assert_eq!(
        plan.inputs()
            .iter()
            .filter(|input| input.kind() == malm_types::PrepareInputKindV1::Component)
            .count(),
        1,
        "renderer and transform share one immutable component input"
    );
    let artifact = plan
        .artifacts()
        .iter()
        .find(|artifact| artifact.id().as_str() == "authoring/output-0000")
        .unwrap();
    assert_eq!(
        engine
            .artifact_v1(plan.plan_id(), artifact.id())
            .unwrap()
            .bytes(),
        b"transformed:renderer-output\n"
    );

    commit(&engine, &plan);
    assert_eq!(
        fs::read(temp.path().join("target/.config/themed/theme.lua")).unwrap(),
        b"transformed:renderer-output\n"
    );
}

#[test]
fn byte_identical_inputs_reuse_the_retained_evaluation() {
    let (lock, content_digest, files, _) = transform_fixture(true);
    let temp = tempfile::tempdir().unwrap();
    let port = transform_harness::FakeTransformPort::new(None);
    let engine = transform_engine(&temp, port.clone());
    engine.initialize_store().unwrap();
    engine
        .publish_pack_object_v1(&content_digest, &files)
        .unwrap();

    let plan = engine
        .prepare_static_deployment_v1(&request(lock.clone(), None))
        .unwrap();
    assert_eq!(
        port.calls.lock().unwrap().len(),
        2,
        "first prepare runs both stages"
    );
    engine
        .commit_v1(&CommitRequestV1::new(
            plan.plan_id().clone(),
            ApprovalV1::new(plan.plan_id().clone(), plan.approval_digest().clone()),
        ))
        .unwrap();

    // Graph, profile, overlays, and evaluator identity fully key reuse, so an
    // exact match needs neither rendering nor component execution.
    let reused = engine
        .prepare_static_deployment_v1(&request(lock.clone(), None))
        .unwrap();
    assert_eq!(
        port.calls.lock().unwrap().len(),
        2,
        "reuse does not re-invoke the transform component"
    );
    assert!(
        reused
            .findings()
            .iter()
            .any(|finding| finding.code() == "AUTHORING-TRANSFORMS-CARRIED"
                && !finding.approval_required()),
        "carried provenance is announced"
    );
    assert!(
        !reused.transforms().is_empty(),
        "the carried transform provenance is part of the reused plan"
    );

    // Reuse still detects live drift and restores from the retained blob only
    // after approval.
    let themed = temp.path().join("target/.config/themed/theme.lua");
    fs::write(
        &themed,
        "return { local_tweak = true }
",
    )
    .unwrap();
    let drifted = engine
        .prepare_static_deployment_v1(&request(lock, None))
        .unwrap();
    assert_eq!(
        port.calls.lock().unwrap().len(),
        2,
        "drift does not change the evaluation inputs, so reuse still holds"
    );
    assert!(
        drifted
            .findings()
            .iter()
            .any(|finding| finding.code() == "restore-modified" && finding.approval_required()),
        "fresh drift detection on the reused plan"
    );
    engine
        .commit_v1(&CommitRequestV1::new(
            drifted.plan_id().clone(),
            ApprovalV1::new(drifted.plan_id().clone(), drifted.approval_digest().clone()),
        ))
        .unwrap();
    assert_eq!(
        fs::read_to_string(&themed).unwrap(),
        "transformed:transformed:return {}
",
        "the approved restore reinstates the managed content from the blob"
    );
}

#[test]
fn profile_switches_reuse_retained_evaluations_without_the_pack() {
    use malm_engine::ProfileSwitchRequestV1;

    let temp = tempfile::tempdir().unwrap();
    let (lock, content_digest, files) = fixture();
    let engine = engine(&temp);
    engine.initialize_store().unwrap();
    engine
        .publish_pack_object_v1(&content_digest, &files)
        .unwrap();

    // Committing both profiles gives each selection an independently retained
    // evaluation for later profile switches.
    let calm = engine
        .prepare_static_deployment_v1(&request(lock.clone(), Some("calm")))
        .unwrap();
    engine
        .commit_v1(&CommitRequestV1::new(
            calm.plan_id().clone(),
            ApprovalV1::new(calm.plan_id().clone(), calm.approval_digest().clone()),
        ))
        .unwrap();
    let loud = engine
        .prepare_profile_switch_v1(&ProfileSwitchRequestV1::new(
            NamespaceName::new(NAMESPACE).unwrap(),
            ContributionName::new("loud").unwrap(),
        ))
        .unwrap();
    engine
        .commit_v1(&CommitRequestV1::new(
            loud.plan_id().clone(),
            ApprovalV1::new(loud.plan_id().clone(), loud.approval_digest().clone()),
        ))
        .unwrap();

    // Remove pack objects to prove that retained records and blobs are enough
    // for an exact reuse match.
    let packs = temp.path().join("state/malm/objects/packs");
    for entry in fs::read_dir(&packs).unwrap() {
        fs::remove_file(entry.unwrap().path()).unwrap();
    }

    let back = engine
        .prepare_profile_switch_v1(&ProfileSwitchRequestV1::new(
            NamespaceName::new(NAMESPACE).unwrap(),
            ContributionName::new("calm").unwrap(),
        ))
        .unwrap();
    let reuse_notices = back
        .findings()
        .iter()
        .filter(|finding| finding.code() == "AUTHORING-EVALUATION-REUSED")
        .collect::<Vec<_>>();
    assert_eq!(reuse_notices.len(), 1, "one reuse produces one notice");
    assert!(!reuse_notices[0].message().contains("  "));
    engine
        .commit_v1(&CommitRequestV1::new(
            back.plan_id().clone(),
            ApprovalV1::new(back.plan_id().clone(), back.approval_digest().clone()),
        ))
        .unwrap();
    assert_eq!(
        fs::read_to_string(temp.path().join("target/.config/greeter/greeting.conf")).unwrap(),
        "greeting=hello world\n",
        "the pack-free switch deployed calm's bytes from retained blobs"
    );

    let loud_again = engine
        .prepare_profile_switch_v1(&ProfileSwitchRequestV1::new(
            NamespaceName::new(NAMESPACE).unwrap(),
            ContributionName::new("loud").unwrap(),
        ))
        .unwrap();
    commit(&engine, &loud_again);
    let calm_again = engine
        .prepare_profile_switch_v1(&ProfileSwitchRequestV1::new(
            NamespaceName::new(NAMESPACE).unwrap(),
            ContributionName::new("calm").unwrap(),
        ))
        .unwrap();
    assert_eq!(
        calm_again
            .findings()
            .iter()
            .filter(|finding| finding.code() == "AUTHORING-EVALUATION-REUSED")
            .count(),
        1,
        "a notice carried by the reusable record is replaced, not accumulated"
    );
}

#[test]
fn reused_empty_profile_drops_historical_reconciliation_removals() {
    use malm_engine::ProfileSwitchRequestV1;
    use malm_types::PrepareOperationV1;

    let temp = tempfile::tempdir().unwrap();
    let (lock, content_digest, files) = fixture();
    let engine = engine(&temp);
    engine.initialize_store().unwrap();
    engine
        .publish_pack_object_v1(&content_digest, &files)
        .unwrap();

    let calm = engine
        .prepare_static_deployment_v1(&request(lock, Some("calm")))
        .unwrap();
    commit(&engine, &calm);

    let empty_request = ProfileSwitchRequestV1::new(
        NamespaceName::new(NAMESPACE).unwrap(),
        ContributionName::new("empty").unwrap(),
    );
    let empty = engine.prepare_profile_switch_v1(&empty_request).unwrap();
    assert!(
        empty
            .operations()
            .iter()
            .any(|operation| matches!(operation, PrepareOperationV1::RemoveLeaf { .. })),
        "the first empty-profile plan reconciles the populated predecessor"
    );
    commit(&engine, &empty);

    let empty_again = engine.prepare_profile_switch_v1(&empty_request).unwrap();
    assert!(
        empty_again
            .findings()
            .iter()
            .any(|finding| finding.code() == "AUTHORING-EVALUATION-REUSED")
    );
    assert!(
        empty_again
            .operations()
            .iter()
            .all(|operation| !matches!(operation, PrepareOperationV1::RemoveLeaf { .. })),
        "historical reconciliation removals are not reusable declarations"
    );
}

#[test]
fn observed_identities_prove_unmodified_files_without_reading_them() {
    let temp = tempfile::tempdir().unwrap();
    let (lock, content_digest, files) = fixture();
    let engine = engine(&temp);
    engine.initialize_store().unwrap();
    engine
        .publish_pack_object_v1(&content_digest, &files)
        .unwrap();
    let plan = engine
        .prepare_static_deployment_v1(&request(lock.clone(), None))
        .unwrap();
    engine
        .commit_v1(&CommitRequestV1::new(
            plan.plan_id().clone(),
            ApprovalV1::new(plan.plan_id().clone(), plan.approval_digest().clone()),
        ))
        .unwrap();
    let observed_path = temp.path().join("state/malm/state/observed.json");
    assert!(
        observed_path.is_file(),
        "the commit recorded observed identities"
    );

    // An untouched file exercises the identity-cache hit. Userspace cannot
    // create "changed content with matching identity": writes, metadata
    // changes, renames, and hard links all advance ctime, which userspace
    // cannot restore. This is the cache proof's security foundation.
    let target = temp.path().join("target/.config/greeter/greeting.conf");
    let cached = engine
        .prepare_static_deployment_v1(&request(lock.clone(), None))
        .unwrap();
    engine
        .commit_v1(&CommitRequestV1::new(
            cached.plan_id().clone(),
            ApprovalV1::new(cached.plan_id().clone(), cached.approval_digest().clone()),
        ))
        .unwrap();

    // A write changes ctime, forcing a content read and approval-gated restore.
    fs::write(&target, "greeting=hand edit\n").unwrap();
    let drifted = engine
        .prepare_static_deployment_v1(&request(lock, None))
        .unwrap();
    assert!(
        drifted
            .findings()
            .iter()
            .any(|finding| finding.code() == "restore-modified" && finding.approval_required()),
        "a modified file is never proven by a stale observation"
    );
}

#[test]
fn a_different_profile_misses_the_reuse_and_evaluates() {
    let temp = tempfile::tempdir().unwrap();
    let (lock, content_digest, files) = fixture();
    let engine = engine(&temp);
    engine.initialize_store().unwrap();
    engine
        .publish_pack_object_v1(&content_digest, &files)
        .unwrap();
    let calm = engine
        .prepare_static_deployment_v1(&request(lock.clone(), Some("calm")))
        .unwrap();
    engine
        .commit_v1(&CommitRequestV1::new(
            calm.plan_id().clone(),
            ApprovalV1::new(calm.plan_id().clone(), calm.approval_digest().clone()),
        ))
        .unwrap();

    // The selected profile is part of evaluation identity, so changing it
    // requires evaluation and produces different rendered bytes.
    let loud = engine
        .prepare_static_deployment_v1(&request(lock, Some("loud")))
        .unwrap();
    let greeting = loud
        .artifacts()
        .iter()
        .find(|artifact| artifact.id().as_str() == "authoring/output-0000")
        .unwrap();
    let bytes = engine.artifact_v1(loud.plan_id(), greeting.id()).unwrap();
    assert_eq!(
        bytes.bytes(),
        b"greeting=hello everyone
"
    );
    assert!(
        loud.findings()
            .iter()
            .all(|finding| finding.code() != "AUTHORING-TRANSFORMS-CARRIED"),
        "a miss carries nothing"
    );
}

#[test]
fn bundled_but_undeclared_components_have_no_effect() {
    let (lock, content_digest, files, _) = transform_fixture(false);
    let temp = tempfile::tempdir().unwrap();
    let port = transform_harness::FakeTransformPort::new(None);
    let engine = transform_engine(&temp, port.clone());
    engine.initialize_store().unwrap();
    engine
        .publish_pack_object_v1(&content_digest, &files)
        .unwrap();

    let plan = engine
        .prepare_static_deployment_v1(&request(lock, None))
        .unwrap();
    assert_eq!(port.calls.lock().unwrap().len(), 0, "no component runs");
    assert!(plan.transforms().is_empty());
    assert!(plan.findings().is_empty());
}

#[test]
fn deletion_restores_compose_with_evaluation_reuse() {
    let (lock, content_digest, files, _) = transform_fixture(true);
    let temp = tempfile::tempdir().unwrap();
    let port = transform_harness::FakeTransformPort::new(None);
    let engine = transform_engine(&temp, port.clone());
    engine.initialize_store().unwrap();
    engine
        .publish_pack_object_v1(&content_digest, &files)
        .unwrap();

    let plan = engine
        .prepare_static_deployment_v1(&request(lock.clone(), None))
        .unwrap();
    commit(&engine, &plan);
    assert_eq!(port.calls.lock().unwrap().len(), 2);

    // Live deletion does not change evaluation identity. Evaluation is reused,
    // while a separate reconciliation pass creates fresh restore operations.
    fs::remove_dir_all(temp.path().join("target/.config/themed")).unwrap();
    let restore = engine
        .prepare_static_deployment_v1(&request(lock.clone(), None))
        .unwrap();
    assert_eq!(
        port.calls.lock().unwrap().len(),
        2,
        "deletion does not force a re-evaluation"
    );
    assert!(
        restore
            .findings()
            .iter()
            .any(|finding| finding.code() == "AUTHORING-TRANSFORMS-CARRIED"),
        "the reused record still carries transform provenance"
    );
    assert!(
        restore
            .findings()
            .iter()
            .any(|finding| finding.code() == "restore-missing-directory"
                && !finding.approval_required()),
        "the deleted directory is recreated: {:?}",
        restore.findings()
    );
    assert!(
        restore
            .findings()
            .iter()
            .any(|finding| finding.code() == "restore-missing" && !finding.approval_required()),
        "the deleted rendered file is restored from the retained blob"
    );

    commit(&engine, &restore);
    assert_eq!(
        fs::read_to_string(temp.path().join("target/.config/themed/theme.lua")).unwrap(),
        "transformed:transformed:return {}\n"
    );

    // Reconciliation regenerates restore findings from current target state;
    // the retained evaluation does not carry stale findings forward.
    let quiet = engine
        .prepare_static_deployment_v1(&request(lock, None))
        .unwrap();
    assert!(
        quiet.findings().iter().all(|finding| {
            finding.code() != "restore-missing" && finding.code() != "restore-missing-directory"
        }),
        "stale restore findings are stripped from reused records: {:?}",
        quiet.findings()
    );
}

#[test]
fn asserted_owned_directories_tolerate_child_replacements() {
    let temp = tempfile::tempdir().unwrap();
    let (lock, content_digest, files) = fixture();
    let engine = engine(&temp);
    engine.initialize_store().unwrap();
    engine
        .publish_pack_object_v1(&content_digest, &files)
        .unwrap();
    let plan = engine
        .prepare_static_deployment_v1(&request(lock.clone(), Some("calm")))
        .unwrap();
    commit(&engine, &plan);

    // Restore the directory to establish namespace ownership.
    let target = temp.path().join("target");
    fs::remove_dir_all(target.join(".config/greeter")).unwrap();
    let restore = engine
        .prepare_static_deployment_v1(&request(lock.clone(), Some("calm")))
        .unwrap();
    commit(&engine, &restore);

    // Replacing a child legitimately changes the asserted directory's mtime;
    // the directory assertion must still verify.
    let switched = engine
        .prepare_static_deployment_v1(&request(lock.clone(), Some("loud")))
        .unwrap();
    assert!(
        switched.operations().iter().any(|operation| matches!(
            operation,
            malm_types::PrepareOperationV1::AssertExact { .. }
        ) && operation.relative_path()
            == ".config/greeter"),
        "the owned directory is asserted while its child is replaced"
    );
    commit(&engine, &switched);
    assert_eq!(
        fs::read_to_string(target.join(".config/greeter/greeting.conf")).unwrap(),
        "greeting=hello everyone\n"
    );
}

#[test]
fn unspecified_profile_keeps_the_deployed_profile() {
    let temp = tempfile::tempdir().unwrap();
    let (lock, content_digest, files) = fixture();
    let engine = engine(&temp);
    engine.initialize_store().unwrap();
    engine
        .publish_pack_object_v1(&content_digest, &files)
        .unwrap();

    let first = engine
        .prepare_static_deployment_v1(&request(lock.clone(), None))
        .unwrap();
    assert!(
        first
            .inputs()
            .iter()
            .any(|input| input.name() == "static-profile:calm"),
        "no deployment yet: the declared default applies"
    );
    commit(&engine, &first);

    let loud = engine
        .prepare_static_deployment_v1(&request(lock.clone(), Some("loud")))
        .unwrap();
    commit(&engine, &loud);

    // Reconciliation keeps the deployed profile instead of switching to the default.
    let reconcile = engine
        .prepare_static_deployment_v1(&request(lock.clone(), None))
        .unwrap();
    assert!(
        reconcile
            .inputs()
            .iter()
            .any(|input| input.name() == "static-profile:loud"),
        "an unspecified profile keeps the deployed profile: {:?}",
        reconcile
            .inputs()
            .iter()
            .map(|input| input.name().to_owned())
            .filter(|name| name.starts_with("static-profile:"))
            .collect::<Vec<_>>()
    );
    let greeting = reconcile
        .artifacts()
        .iter()
        .find(|artifact| artifact.id().as_str() == "authoring/output-0000")
        .expect("rendered greeting");
    assert_eq!(
        engine
            .artifact_v1(reconcile.plan_id(), greeting.id())
            .unwrap()
            .bytes(),
        b"greeting=hello everyone\n",
        "the reconcile renders the deployed profile's content"
    );

    let back = engine
        .prepare_static_deployment_v1(&request(lock, Some("calm")))
        .unwrap();
    assert!(
        back.inputs()
            .iter()
            .any(|input| input.name() == "static-profile:calm")
    );
}
