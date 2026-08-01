mod common;

use std::fs;
use std::io::Write;
use std::os::unix::ffi::OsStringExt;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use common::TestEnv;
use malm::{
    ApprovalV1, CommitRequestV1, PrepareArtifactV1, PrepareOperationV1, PrepareRequestPartsV1,
    PrepareRequestV1,
};
use malm_machine::{
    MachineRequestV1, MachineResultV1, RequestEnvelopeV1, RequestIdV1, ServerFrameV1,
    decode_server_frame_v1, encode_request_v1,
};
use malm_pack::{
    DependencySourceV1, GitObjectId, GitSourceV1, GitUrl, LocalLocator, LockV1, LockedDependencyV1,
    LockedPackV1, LockedSourceV1, PackDependencyV1, PackFileV1, PackManifestV1, PackModuleV1,
    PackPath, PackSubdir, decode_lock_v1, encode_lock_v1, encode_pack_v1, lock_graph_digest,
    pack_content_digest,
};
use malm_tree::file_object_digest_v1;
use malm_types::{
    Alias, ArtifactId, ContributionName, DeploymentName, Digest, NamespaceName, PackageId,
    PreparedId,
};
fn request() -> PrepareRequestV1 {
    let artifact = ArtifactId::new("config/file").unwrap();
    PrepareRequestV1::from(PrepareRequestPartsV1 {
        namespace: NamespaceName::new("workstation").unwrap(),
        expected_head: None,
        graph_digest: Digest::sha256(b"CLI graph"),
        inputs: vec![],
        artifacts: vec![
            PrepareArtifactV1::new(
                artifact.clone(),
                b"CLI prepared bytes\n".to_vec(),
                "text/plain",
            )
            .unwrap(),
        ],
        transforms: vec![],
        findings: vec![],
        operations: vec![
            PrepareOperationV1::place_file(
                DeploymentName::new("home").unwrap(),
                "config/file.conf",
                artifact,
                0o600,
            )
            .unwrap(),
        ],
    })
}

fn json_envelope(output: &std::process::Output) -> serde_json::Value {
    let envelope: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(envelope.as_object().unwrap().len(), 5);
    assert_eq!(envelope["schema_version"], 1);
    assert!(envelope["command"].is_string());
    assert!(envelope["outcome"].is_string());
    assert_eq!(envelope["diagnostics"], serde_json::json!([]));
    assert!(envelope.get("data").is_some());
    envelope
}

fn json_data(output: &std::process::Output) -> serde_json::Value {
    json_envelope(output)["data"].clone()
}

fn write_static_pack(env: &TestEnv) {
    let source_path = PackPath::new("files/theme.conf").unwrap();
    let asset_path = PackPath::new("assets/palette.bin").unwrap();
    let config_path = PackPath::new(malm_config::CONFIG_FILE).unwrap();
    let source_bytes = b"theme=dark\n";
    let asset_bytes = b"\0\xffpalette\n";
    let source_raw = Digest::sha256(source_bytes);
    let source_object = file_object_digest_v1(source_bytes).unwrap();
    let asset_raw = Digest::sha256(asset_bytes);
    let asset_object = file_object_digest_v1(asset_bytes).unwrap();
    let config = format!(
        r#"rich-config schema-version=1 default-profile="desktop" {{
    includes {{}}
    modules {{}}
    variables {{}}
    fragments {{}}
    slots {{}}
    statements {{}}
    profiles {{
        profile "desktop" abstract=#false {{
            extends {{}}
            statements {{}}
            outputs {{
                regular-file "config" destination="config/theme.conf" source="{}" source-kind="asset" raw-digest="{source_raw}" object-digest="{source_object}" byte-len={} executable=#false
                regular-file "palette" destination="share/palette.bin" source="{}" source-kind="asset" raw-digest="{asset_raw}" object-digest="{asset_object}" byte-len={} executable=#false
            }}
        }}
    }}
}}"#,
        source_path.as_str(),
        source_bytes.len(),
        asset_path.as_str(),
        asset_bytes.len(),
    );
    let manifest = PackManifestV1::new(
        PackageId::new("com.example.root").unwrap(),
        vec![],
        vec![],
        vec![],
        vec![],
        vec![source_path.clone(), asset_path.clone()],
        vec![],
    )
    .unwrap()
    .with_config_documents(vec![config_path.clone()])
    .unwrap();
    let mut files = vec![
        PackFileV1::new(
            PackPath::new("malm-pack.kdl").unwrap(),
            encode_pack_v1(&manifest),
        ),
        PackFileV1::new(config_path, config.into_bytes()),
        PackFileV1::new(source_path, source_bytes),
        PackFileV1::new(asset_path, asset_bytes),
    ];
    files.sort_by(|left, right| left.path().cmp(right.path()));
    let digest = pack_content_digest(files.iter().map(|file| (file.path(), file.bytes()))).unwrap();
    for file in &files {
        let path = env.repo().join(file.path().as_str());
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, file.bytes()).unwrap();
    }
    let root = LockedPackV1::new(
        PackageId::new("com.example.root").unwrap(),
        LockedSourceV1::Root,
        digest,
        vec![],
        vec![],
    )
    .unwrap();
    let lock = LockV1::new(root.node_id().clone(), vec![root]).unwrap();
    fs::write(env.repo().join("malm.lock"), encode_lock_v1(&lock)).unwrap();
}

fn write_lock_pack(
    root: &Path,
    package_id: &str,
    dependencies: Vec<PackDependencyV1>,
    module_bytes: &[u8],
) {
    let module_path = PackPath::new("modules/main.kdl").unwrap();
    let manifest = PackManifestV1::new(
        PackageId::new(package_id).unwrap(),
        vec![PackModuleV1::new(
            ContributionName::new("main").unwrap(),
            module_path.clone(),
        )],
        dependencies,
        vec![],
        vec![],
        vec![],
        vec![],
    )
    .unwrap();
    fs::create_dir_all(root.join("modules")).unwrap();
    fs::write(root.join("malm-pack.kdl"), encode_pack_v1(&manifest)).unwrap();
    fs::write(root.join(module_path.as_str()), module_bytes).unwrap();
}

struct RemoteStaticFixture {
    url: GitUrl,
    digest: Digest,
    commit: String,
    repository: PathBuf,
}

fn run_git(arguments: &[&str]) -> Vec<u8> {
    let output = Command::new("/usr/bin/git")
        .args(arguments)
        .env_clear()
        .env("LC_ALL", "C")
        .env("HOME", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_AUTHOR_DATE", "2000-01-01T00:00:00Z")
        .env("GIT_COMMITTER_DATE", "2000-01-01T00:00:00Z")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "git {arguments:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    output.stdout
}

fn write_remote_static_pack(env: &TestEnv) -> RemoteStaticFixture {
    let repository = env.repo().parent().unwrap().join("remote-git");
    run_git(&[
        "init",
        "--quiet",
        "--object-format=sha1",
        repository.to_str().unwrap(),
    ]);
    let remote_manifest = include_bytes!("../schemas/pack/v1/fixtures/valid/minimal.kdl");
    fs::write(repository.join("malm-pack.kdl"), remote_manifest).unwrap();
    fs::write(repository.join("remote-data"), b"remote locked bytes\n").unwrap();
    run_git(&["-C", repository.to_str().unwrap(), "add", "--all"]);
    run_git(&[
        "-C",
        repository.to_str().unwrap(),
        "-c",
        "user.name=Malm Test",
        "-c",
        "user.email=malm@example.invalid",
        "commit",
        "--quiet",
        "-m",
        "remote fixture",
    ]);
    let commit = String::from_utf8(run_git(&[
        "-C",
        repository.to_str().unwrap(),
        "rev-parse",
        "HEAD",
    ]))
    .unwrap()
    .trim()
    .to_owned();
    let mut remote_files = [
        PackFileV1::new(PackPath::new("malm-pack.kdl").unwrap(), remote_manifest),
        PackFileV1::new(
            PackPath::new("remote-data").unwrap(),
            b"remote locked bytes\n",
        ),
    ];
    remote_files.sort_by(|left, right| left.path().cmp(right.path()));
    let digest =
        pack_content_digest(remote_files.iter().map(|file| (file.path(), file.bytes()))).unwrap();
    let url = GitUrl::new("https://example.invalid/remote.git").unwrap();
    let source = GitSourceV1::new(
        url.clone(),
        GitObjectId::new(format!("sha1-{commit}")).unwrap(),
        PackSubdir::new(".").unwrap(),
    );

    let source_path = PackPath::new("files/theme.conf").unwrap();
    let config_path = PackPath::new(malm_config::CONFIG_FILE).unwrap();
    let source_bytes = b"theme=remote\n";
    let source_raw = Digest::sha256(source_bytes);
    let source_object = file_object_digest_v1(source_bytes).unwrap();
    let config = format!(
        r#"rich-config schema-version=1 default-profile="desktop" {{
    includes {{}}
    modules {{}}
    variables {{}}
    fragments {{}}
    slots {{}}
    statements {{}}
    profiles {{
        profile "desktop" abstract=#false {{
            extends {{}}
            statements {{}}
            outputs {{
                regular-file "config" destination="config/theme.conf" source="{}" source-kind="asset" raw-digest="{source_raw}" object-digest="{source_object}" byte-len={} executable=#false
            }}
        }}
    }}
}}"#,
        source_path.as_str(),
        source_bytes.len(),
    );
    let dependency_alias = Alias::new("remote").unwrap();
    let manifest = PackManifestV1::new(
        PackageId::new("com.example.root").unwrap(),
        vec![],
        vec![PackDependencyV1::new(
            dependency_alias.clone(),
            PackageId::new("com.example.minimal").unwrap(),
            DependencySourceV1::Git(source.clone()),
        )],
        vec![],
        vec![],
        vec![source_path.clone()],
        vec![],
    )
    .unwrap()
    .with_config_documents(vec![config_path.clone()])
    .unwrap();
    let mut root_files = vec![
        PackFileV1::new(
            PackPath::new("malm-pack.kdl").unwrap(),
            encode_pack_v1(&manifest),
        ),
        PackFileV1::new(config_path, config.into_bytes()),
        PackFileV1::new(source_path, source_bytes),
    ];
    root_files.sort_by(|left, right| left.path().cmp(right.path()));
    for file in &root_files {
        let path = env.repo().join(file.path().as_str());
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, file.bytes()).unwrap();
    }
    let root_digest =
        pack_content_digest(root_files.iter().map(|file| (file.path(), file.bytes()))).unwrap();
    let remote_node = LockedPackV1::new(
        PackageId::new("com.example.minimal").unwrap(),
        LockedSourceV1::Git(source),
        digest.clone(),
        vec![],
        vec![],
    )
    .unwrap();
    let root_node = LockedPackV1::new(
        PackageId::new("com.example.root").unwrap(),
        LockedSourceV1::Root,
        root_digest,
        vec![LockedDependencyV1::new(
            dependency_alias,
            remote_node.node_id().clone(),
        )],
        vec![],
    )
    .unwrap();
    let lock = LockV1::new(root_node.node_id().clone(), vec![root_node, remote_node]).unwrap();
    fs::write(env.repo().join("malm.lock"), encode_lock_v1(&lock)).unwrap();
    RemoteStaticFixture {
        url,
        digest,
        commit,
        repository,
    }
}

fn write_git_wrapper(parent: &Path, remote: &Path, log: &Path) -> PathBuf {
    let wrapper = parent.join("git-wrapper");
    let script = format!(
        "#!/bin/sh\n\
         log={}\n\
         real=/usr/bin/git\n\
         remote={}\n\
         printf '%s\\000' BEGIN >> \"$log\"\n\
         fetch=0\n\
         resolve=0\n\
         git_dir=.\n\
         last=\n\
         for arg in \"$@\"; do\n\
           printf '%s\\000' \"$arg\" >> \"$log\"\n\
           case \"$arg\" in\n\
             --git-dir=*) git_dir=${{arg#--git-dir=}} ;;\n\
             fetch) fetch=1 ;;\n\
             ls-remote) resolve=1 ;;\n\
           esac\n\
           last=$arg\n\
         done\n\
         printf '%s\\000' END >> \"$log\"\n\
         if [ \"$resolve\" = 1 ]; then\n\
           GIT_ALLOW_PROTOCOL=file exec \"$real\" -c protocol.file.allow=always ls-remote --refs --exit-code -- \"$remote\" \"$last\"\n\
         fi\n\
         if [ \"$fetch\" = 1 ]; then\n\
           GIT_ALLOW_PROTOCOL=file exec \"$real\" -c protocol.file.allow=always --git-dir=\"$git_dir\" fetch --quiet --no-tags --no-write-fetch-head --no-recurse-submodules --no-auto-maintenance --no-write-commit-graph \"$remote\" \"$last\"\n\
         fi\n\
         exec \"$real\" \"$@\"\n",
        shell_literal(log),
        shell_literal(remote),
    );
    fs::write(&wrapper, script).unwrap();
    fs::set_permissions(&wrapper, fs::Permissions::from_mode(0o700)).unwrap();
    wrapper
}

fn shell_literal(path: &Path) -> String {
    format!("'{}'", path.to_string_lossy().replace('\'', "'\\''"))
}

fn logged_arguments(path: &Path) -> Vec<String> {
    fs::read(path)
        .unwrap()
        .split(|byte| *byte == 0)
        .filter(|part| !part.is_empty())
        .map(|part| String::from_utf8(part.to_vec()).unwrap())
        .collect()
}

const TRACKED_URL: &str = "https://example.invalid/tracked.git";
const TRACKED_DEPENDENCY_URL: &str = "https://example.invalid/tracked-dependency.git";
const TRACKED_SELECTOR: &str = "refs/heads/main";

fn private_directory(path: &Path) {
    fs::create_dir(path).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
}

#[test]
fn local_lock_cli_create_and_update_publish_exact_views() {
    let env = TestEnv::new();
    let dependency_root = env.repo().parent().unwrap().join("lock-dependency");
    let locator = LocalLocator::new("../lock-dependency").unwrap();
    let dependency_package = PackageId::new("com.example.lock-dependency").unwrap();
    write_lock_pack(
        &dependency_root,
        dependency_package.as_str(),
        vec![],
        b"dependency one\n",
    );
    write_lock_pack(
        &env.repo(),
        "com.example.lock-root",
        vec![PackDependencyV1::new(
            Alias::new("dependency").unwrap(),
            dependency_package,
            DependencySourceV1::Local(locator.clone()),
        )],
        b"root\n",
    );

    let not_ready = env.malm_without_repo(&[
        "source",
        "lock",
        "create",
        "--source",
        env.repo().to_str().unwrap(),
        "--git-executable",
        "/definitely/missing/git",
        "--allow-local",
        locator.as_str(),
    ]);
    assert_eq!(not_ready.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&not_ready.stderr).contains("store is not ready"),
        "{}",
        String::from_utf8_lossy(&not_ready.stderr)
    );
    assert!(!env.repo().join("malm.lock").exists());

    assert!(env.malm_without_repo(&["store", "init"]).status.success());

    let denied = env.malm_without_repo(&[
        "source",
        "lock",
        "create",
        "--source",
        env.repo().to_str().unwrap(),
        "--git-executable",
        "/definitely/missing/git",
    ]);
    assert_eq!(denied.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&denied.stderr).contains("was not explicitly granted"),
        "{}",
        String::from_utf8_lossy(&denied.stderr)
    );
    assert!(!env.repo().join("malm.lock").exists());

    let created = env.malm_without_repo(&[
        "source",
        "--format",
        "json",
        "lock",
        "create",
        "--source",
        env.repo().to_str().unwrap(),
        "--git-executable",
        "/definitely/missing/git",
        "--allow-local",
        locator.as_str(),
    ]);
    assert!(
        created.status.success(),
        "{}",
        String::from_utf8_lossy(&created.stderr)
    );
    assert!(created.stderr.is_empty());
    let created = json_data(&created);
    let lock_bytes = fs::read(env.repo().join("malm.lock")).unwrap();
    let lock = decode_lock_v1(&lock_bytes).unwrap();
    let first_graph = lock_graph_digest(&lock);
    assert_eq!(lock.nodes().len(), 2);
    assert_eq!(
        created,
        serde_json::json!({
            "publication": "created",
            "source": env.repo(),
            "git_executable": "/definitely/missing/git",
            "graph_digest": first_graph.as_str(),
            "pack_count": lock.nodes().len(),
        })
    );

    let unchanged = env.malm_without_repo(&[
        "source",
        "lock",
        "update",
        "--source",
        env.repo().to_str().unwrap(),
        "--git-executable",
        "/definitely/missing/git",
        "--allow-local",
        locator.as_str(),
    ]);
    assert!(
        unchanged.status.success(),
        "{}",
        String::from_utf8_lossy(&unchanged.stderr)
    );
    let unchanged = String::from_utf8(unchanged.stdout).unwrap();
    assert!(unchanged.contains("Source lock is current"), "{unchanged}");
    assert!(unchanged.contains("Packs  2"), "{unchanged}");
    assert!(
        unchanged.contains(&format!("graph:{}", &first_graph.as_str()[7..19])),
        "{unchanged}"
    );

    write_lock_pack(
        &dependency_root,
        "com.example.lock-dependency",
        vec![],
        b"dependency two\n",
    );
    let updated = env.malm_without_repo(&[
        "source",
        "--format",
        "json",
        "lock",
        "update",
        "--source",
        env.repo().to_str().unwrap(),
        "--git-executable",
        "/definitely/missing/git",
        "--allow-local",
        locator.as_str(),
    ]);
    assert!(
        updated.status.success(),
        "{}",
        String::from_utf8_lossy(&updated.stderr)
    );
    let updated = json_data(&updated);
    let updated_lock = decode_lock_v1(&fs::read(env.repo().join("malm.lock")).unwrap()).unwrap();
    let updated_graph = lock_graph_digest(&updated_lock);
    assert_ne!(updated_graph, first_graph);
    assert_eq!(updated["publication"], "updated");
    assert_eq!(updated["graph_digest"], updated_graph.as_str());
    assert_eq!(updated["pack_count"], updated_lock.nodes().len());
}

#[test]
fn lock_cli_rejects_invalid_typed_capabilities_before_store_access() {
    let env = TestEnv::new();
    let source = env.repo();
    let source = source.to_str().unwrap();
    let first_scratch = env.repo().parent().unwrap().join("first-scratch");
    let second_scratch = env.repo().parent().unwrap().join("second-scratch");
    let first_scratch = first_scratch.to_str().unwrap();
    let second_scratch = second_scratch.to_str().unwrap();
    let oid_a = format!("sha1-{}", "a".repeat(40));
    let oid_b = format!("sha1-{}", "b".repeat(40));
    let reject = |arguments: &[&str], expected: Option<&str>| {
        let output = env.malm_without_repo(arguments);
        assert_eq!(
            output.status.code(),
            Some(2),
            "malm {arguments:?} unexpectedly succeeded"
        );
        if let Some(expected) = expected {
            assert!(
                String::from_utf8_lossy(&output.stderr).contains(expected),
                "malm {arguments:?} did not report {expected:?}: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
    };

    reject(&["source", "lock", "create", "--source", source], None);
    reject(
        &[
            "source",
            "lock",
            "create",
            "--source",
            "relative-pack",
            "--git-executable",
            "/usr/bin/git",
        ],
        Some("canonicalize source relative-pack"),
    );
    reject(
        &[
            "source",
            "lock",
            "create",
            "--source",
            "",
            "--git-executable",
            "/usr/bin/git",
        ],
        None,
    );
    reject(
        &[
            "source",
            "lock",
            "create",
            "--source",
            source,
            "--git-executable",
            "git",
        ],
        Some("Git executable must be absolute"),
    );
    reject(
        &[
            "source",
            "lock",
            "create",
            "--source",
            source,
            "--git-executable",
            "",
        ],
        None,
    );
    reject(
        &[
            "source",
            "lock",
            "create",
            "--source",
            source,
            "--git-executable",
            "/usr/bin/git",
            "--allow-local",
            "../dependency",
            "--allow-local",
            "../dependency",
        ],
        Some("configured more than once"),
    );
    reject(
        &[
            "source",
            "lock",
            "create",
            "--source",
            source,
            "--git-executable",
            "/usr/bin/git",
            "--allow-git",
            "https://EXAMPLE.invalid/repository.git",
            "--allow-git",
            "https://example.invalid/repository.git",
        ],
        Some("configured more than once"),
    );
    reject(
        &[
            "source",
            "lock",
            "create",
            "--source",
            source,
            "--git-executable",
            "/usr/bin/git",
            "--git-scratch",
            "https://EXAMPLE.invalid/repository.git",
            &oid_a,
            ".",
            first_scratch,
            "--git-scratch",
            "https://example.invalid/repository.git",
            &oid_a,
            ".",
            second_scratch,
        ],
        Some("configured more than once"),
    );
    reject(
        &[
            "source",
            "lock",
            "create",
            "--source",
            source,
            "--git-executable",
            "/usr/bin/git",
            "--git-scratch",
            "https://example.invalid/one.git",
            &oid_a,
            ".",
            first_scratch,
            "--git-scratch",
            "https://example.invalid/two.git",
            &oid_b,
            ".",
            first_scratch,
        ],
        Some("cannot serve multiple Git sources"),
    );
    reject(
        &[
            "source",
            "lock",
            "create",
            "--source",
            source,
            "--git-executable",
            "/usr/bin/git",
            "--git-scratch",
            "https://example.invalid/repository.git",
            &oid_a,
            ".",
            "relative-scratch",
        ],
        Some("--git-scratch path must be absolute"),
    );
    reject(
        &[
            "source",
            "lock",
            "create",
            "--source",
            source,
            "--git-executable",
            "/usr/bin/git",
            "--git-scratch",
            "https://example.invalid/repository.git",
            &oid_a,
            ".",
            "",
        ],
        None,
    );
    reject(
        &[
            "source",
            "lock",
            "create",
            "--source",
            source,
            "--git-executable",
            "/usr/bin/git",
            "--git-scratch",
            "https://example.invalid/repository.git",
            &oid_a,
            ".",
        ],
        None,
    );
    for forbidden in ["--lock", "--cached", "--target", "--allow-component"] {
        reject(
            &[
                "source",
                "lock",
                "create",
                "--source",
                source,
                "--git-executable",
                "/usr/bin/git",
                forbidden,
                "value",
            ],
            None,
        );
    }
    assert!(!env.state_root().exists());
}

fn write_tracked_revision(repository: &Path, contents: &[u8], dependency: bool) -> String {
    let source_path = PackPath::new("files/tracked.conf").unwrap();
    let config_path = PackPath::new("malm.kdl").unwrap();
    let source_raw = Digest::sha256(contents);
    let source_object = file_object_digest_v1(contents).unwrap();
    let config = format!(
        r#"rich-config schema-version=1 default-profile="desktop" {{
    includes {{}}
    modules {{}}
    variables {{}}
    fragments {{}}
    slots {{}}
    statements {{}}
    profiles {{
        profile "desktop" abstract=#false {{
            extends {{}}
            statements {{}}
            outputs {{
                regular-file "tracked" destination="config/tracked.conf" source="{}" source-kind="asset" raw-digest="{source_raw}" object-digest="{source_object}" byte-len={} executable=#false
            }}
        }}
    }}
}}"#,
        source_path.as_str(),
        contents.len(),
    );

    let dependency_alias = Alias::new("dependency").unwrap();
    let dependency_package = PackageId::new("com.example.tracked-dependency").unwrap();
    let dependency_source = GitSourceV1::new(
        GitUrl::new(TRACKED_DEPENDENCY_URL).unwrap(),
        GitObjectId::new(format!("sha1-{}", "d".repeat(40))).unwrap(),
        PackSubdir::new(".").unwrap(),
    );
    let manifest = PackManifestV1::new(
        PackageId::new("com.example.tracked").unwrap(),
        vec![],
        dependency
            .then(|| {
                PackDependencyV1::new(
                    dependency_alias.clone(),
                    dependency_package.clone(),
                    DependencySourceV1::Git(dependency_source.clone()),
                )
            })
            .into_iter()
            .collect(),
        vec![],
        vec![],
        vec![source_path.clone()],
        vec![],
    )
    .unwrap()
    .with_config_documents(vec![config_path.clone()])
    .unwrap();
    let mut files = vec![
        PackFileV1::new(
            PackPath::new("malm-pack.kdl").unwrap(),
            encode_pack_v1(&manifest),
        ),
        PackFileV1::new(config_path, config.into_bytes()),
        PackFileV1::new(source_path, contents),
    ];
    files.sort_by(|left, right| left.path().cmp(right.path()));
    let root_digest =
        pack_content_digest(files.iter().map(|file| (file.path(), file.bytes()))).unwrap();

    let dependency_node = dependency.then(|| {
        let dependency_manifest = PackManifestV1::new(
            dependency_package.clone(),
            vec![],
            vec![],
            vec![],
            vec![],
            vec![],
            vec![],
        )
        .unwrap();
        let dependency_files = [PackFileV1::new(
            PackPath::new("malm-pack.kdl").unwrap(),
            encode_pack_v1(&dependency_manifest),
        )];
        let dependency_digest = pack_content_digest(
            dependency_files
                .iter()
                .map(|file| (file.path(), file.bytes())),
        )
        .unwrap();
        LockedPackV1::new(
            dependency_package,
            LockedSourceV1::Git(dependency_source),
            dependency_digest,
            vec![],
            vec![],
        )
        .unwrap()
    });
    let root = LockedPackV1::new(
        PackageId::new("com.example.tracked").unwrap(),
        LockedSourceV1::Root,
        root_digest,
        dependency_node
            .as_ref()
            .map(|node| LockedDependencyV1::new(dependency_alias, node.node_id().clone()))
            .into_iter()
            .collect(),
        vec![],
    )
    .unwrap();
    let mut nodes = vec![root.clone()];
    nodes.extend(dependency_node);
    let lock = LockV1::new(root.node_id().clone(), nodes).unwrap();

    for file in files {
        let path = repository.join(file.path().as_str());
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, file.bytes()).unwrap();
    }
    fs::write(repository.join("malm.lock"), encode_lock_v1(&lock)).unwrap();
    run_git(&["-C", repository.to_str().unwrap(), "add", "--all"]);
    run_git(&[
        "-C",
        repository.to_str().unwrap(),
        "-c",
        "user.name=Malm Test",
        "-c",
        "user.email=malm@example.invalid",
        "commit",
        "--quiet",
        "-m",
        std::str::from_utf8(contents).unwrap().trim(),
    ]);
    String::from_utf8(run_git(&[
        "-C",
        repository.to_str().unwrap(),
        "rev-parse",
        "HEAD",
    ]))
    .unwrap()
    .trim()
    .to_owned()
}

#[test]
fn tracked_cli_rejects_malformed_relative_and_duplicate_authority_before_git() {
    let env = TestEnv::new();
    let fixture_root = env.repo().parent().unwrap().to_path_buf();
    let log = fixture_root.join("invalid-track-git.log");
    let wrapper = write_git_wrapper(&fixture_root, &env.repo(), &log);
    let scratch = fixture_root.join("invalid-track-scratch");
    private_directory(&scratch);

    let malformed = env.malm_without_repo(&[
        "plan",
        "track",
        "--source-url",
        "http://example.invalid/tracked.git",
        "--selector",
        TRACKED_SELECTOR,
        "--git-executable",
        wrapper.to_str().unwrap(),
        "--root-scratch",
        scratch.to_str().unwrap(),
    ]);
    assert_eq!(malformed.status.code(), Some(2));

    let relative = env.malm_without_repo(&[
        "plan",
        "track",
        "--source-url",
        TRACKED_URL,
        "--selector",
        TRACKED_SELECTOR,
        "--git-executable",
        wrapper.to_str().unwrap(),
        "--root-scratch",
        "relative-scratch",
    ]);
    assert_eq!(relative.status.code(), Some(2));

    let duplicate = env.malm_without_repo(&[
        "plan",
        "track",
        "--source-url",
        TRACKED_URL,
        "--selector",
        TRACKED_SELECTOR,
        "--allow-git",
        TRACKED_DEPENDENCY_URL,
        "--allow-git",
        TRACKED_DEPENDENCY_URL,
        "--git-executable",
        wrapper.to_str().unwrap(),
        "--root-scratch",
        scratch.to_str().unwrap(),
    ]);
    assert_eq!(duplicate.status.code(), Some(2));

    let target = format!("home={}", env.home().display());
    let duplicate_target = env.malm_without_repo(&[
        "plan",
        "track",
        "--source-url",
        TRACKED_URL,
        "--selector",
        TRACKED_SELECTOR,
        "--target",
        &target,
        "--target",
        &target,
        "--git-executable",
        wrapper.to_str().unwrap(),
        "--root-scratch",
        scratch.to_str().unwrap(),
    ]);
    assert_eq!(duplicate_target.status.code(), Some(2));

    assert!(!log.exists(), "invalid authority launched Git");
    assert!(!env.state_root().exists());
}

#[test]
fn track_and_update_prepare_reviewable_exact_plans_and_commit_offline() {
    let env = TestEnv::new();
    fs::create_dir(env.home().join("config")).unwrap();
    assert!(env.malm_without_repo(&["store", "init"]).status.success());

    let fixture_root = env.repo().parent().unwrap().to_path_buf();
    let repository = fixture_root.join("tracked-remote");
    run_git(&[
        "init",
        "--quiet",
        "--object-format=sha1",
        "--initial-branch=main",
        repository.to_str().unwrap(),
    ]);
    let first_revision = write_tracked_revision(&repository, b"version=one\n", false);
    let log = fixture_root.join("tracked-git.log");
    let wrapper = write_git_wrapper(&fixture_root, &repository, &log);
    let initial_scratch = fixture_root.join("tracked-initial-scratch");
    private_directory(&initial_scratch);

    let initial = env.malm_without_repo(&[
        "plan",
        "--format",
        "json",
        "track",
        "--profile",
        "desktop",
        "--source-url",
        TRACKED_URL,
        "--selector",
        TRACKED_SELECTOR,
        "--namespace",
        "workstation",
        "--git-executable",
        wrapper.to_str().unwrap(),
        "--root-scratch",
        initial_scratch.to_str().unwrap(),
    ]);
    assert!(
        initial.status.success(),
        "{}",
        String::from_utf8_lossy(&initial.stderr)
    );
    let initial = json_data(&initial);
    assert_eq!(initial["namespace"], "workstation");
    assert_eq!(initial["tracked_root"]["moving_selector"], TRACKED_SELECTOR);
    assert_eq!(
        initial["tracked_root"]["applied_revision"],
        format!("sha1-{first_revision}")
    );
    assert!(!env.home().join("config/tracked.conf").exists());
    let initial_plan = initial["plan_id"].as_str().unwrap();
    let reviewed = env.malm_without_repo(&["plan", "--format", "json", "show", initial_plan]);
    assert!(reviewed.status.success());
    assert_eq!(json_data(&reviewed), initial);

    let git_before_commit = fs::read(&log).unwrap();
    fs::remove_file(&wrapper).unwrap();
    let committed = env.malm_without_repo(&[
        "plan",
        "--format",
        "json",
        "apply",
        initial_plan,
        "--approval",
        initial["approval_digest"].as_str().unwrap(),
    ]);
    assert!(
        committed.status.success(),
        "{}",
        String::from_utf8_lossy(&committed.stderr)
    );
    assert_eq!(fs::read(&log).unwrap(), git_before_commit);
    assert_eq!(
        fs::read(env.home().join("config/tracked.conf")).unwrap(),
        b"version=one\n"
    );
    let committed = json_data(&committed);
    let first_head = committed["generation"].as_str().unwrap();
    let wrapper = write_git_wrapper(&fixture_root, &repository, &log);

    let no_change_scratch = fixture_root.join("tracked-no-change-scratch");
    private_directory(&no_change_scratch);
    let no_change = env.malm_without_repo(&[
        "plan",
        "--format",
        "json",
        "refresh",
        "--namespace",
        "workstation",
        "--git-executable",
        wrapper.to_str().unwrap(),
        "--root-scratch",
        no_change_scratch.to_str().unwrap(),
    ]);
    assert!(
        no_change.status.success(),
        "{}",
        String::from_utf8_lossy(&no_change.stderr)
    );
    let no_change = json_envelope(&no_change);
    assert_eq!(no_change["outcome"], "up_to_date");
    let no_change = &no_change["data"];
    assert_eq!(no_change["namespace"], "workstation");
    assert_eq!(no_change["selected_head"], first_head);
    assert_eq!(
        no_change["exact_revision"],
        format!("sha1-{first_revision}")
    );
    assert_eq!(
        no_change["root_tree_digest"],
        initial["tracked_root"]["root_tree_digest"]
    );

    let no_change_text_scratch = fixture_root.join("tracked-no-change-text-scratch");
    private_directory(&no_change_text_scratch);
    let no_change_text = env.malm_without_repo(&[
        "plan",
        "refresh",
        "--namespace",
        "workstation",
        "--git-executable",
        wrapper.to_str().unwrap(),
        "--root-scratch",
        no_change_text_scratch.to_str().unwrap(),
    ]);
    assert!(no_change_text.status.success());
    let no_change_text = String::from_utf8(no_change_text.stdout).unwrap();
    assert!(
        no_change_text.contains("Already up to date"),
        "{no_change_text}"
    );
    assert!(no_change_text.contains("workstation"), "{no_change_text}");
    assert!(
        no_change_text.contains(&format!("gen:{}", &first_head[7..19])),
        "{no_change_text}"
    );
    assert!(
        no_change_text.contains(&format!("sha1-{first_revision}")),
        "{no_change_text}"
    );

    let second_revision = write_tracked_revision(&repository, b"version=two\n", false);
    let advancing_scratch = fixture_root.join("tracked-advancing-scratch");
    private_directory(&advancing_scratch);
    let advanced = env.malm_without_repo(&[
        "plan",
        "--format",
        "json",
        "refresh",
        "--namespace",
        "workstation",
        "--git-executable",
        wrapper.to_str().unwrap(),
        "--root-scratch",
        advancing_scratch.to_str().unwrap(),
    ]);
    assert!(
        advanced.status.success(),
        "{}",
        String::from_utf8_lossy(&advanced.stderr)
    );
    let advanced = json_data(&advanced);
    assert_eq!(advanced["expected_head"], first_head);
    assert_eq!(
        advanced["tracked_root"]["applied_revision"],
        format!("sha1-{second_revision}")
    );
    assert_eq!(
        fs::read(env.home().join("config/tracked.conf")).unwrap(),
        b"version=one\n"
    );
    let advanced_plan = advanced["plan_id"].as_str().unwrap();
    let reviewed = env.malm_without_repo(&["plan", "--format", "json", "show", advanced_plan]);
    assert!(reviewed.status.success());
    assert_eq!(json_data(&reviewed), advanced);

    let git_before_commit = fs::read(&log).unwrap();
    fs::remove_file(&wrapper).unwrap();
    let committed = env.malm_without_repo(&[
        "plan",
        "--format",
        "json",
        "apply",
        advanced_plan,
        "--approval",
        advanced["approval_digest"].as_str().unwrap(),
    ]);
    assert!(
        committed.status.success(),
        "{}",
        String::from_utf8_lossy(&committed.stderr)
    );
    assert_eq!(fs::read(&log).unwrap(), git_before_commit);
    assert_eq!(
        fs::read(env.home().join("config/tracked.conf")).unwrap(),
        b"version=two\n"
    );
    let wrapper = write_git_wrapper(&fixture_root, &repository, &log);

    write_tracked_revision(&repository, b"version=three\n", true);
    let widening_scratch = fixture_root.join("tracked-widening-scratch");
    private_directory(&widening_scratch);
    let before_widening_attempt = fs::read(&log).unwrap();
    let widening = env.malm_without_repo(&[
        "plan",
        "refresh",
        "--namespace",
        "workstation",
        "--allow-git",
        TRACKED_DEPENDENCY_URL,
        "--git-executable",
        wrapper.to_str().unwrap(),
        "--root-scratch",
        widening_scratch.to_str().unwrap(),
    ]);
    assert_eq!(widening.status.code(), Some(2));
    assert_eq!(fs::read(&log).unwrap(), before_widening_attempt);

    let denied_scratch = fixture_root.join("tracked-denied-scratch");
    private_directory(&denied_scratch);
    let denied = env.malm_without_repo(&[
        "plan",
        "refresh",
        "--namespace",
        "workstation",
        "--git-executable",
        wrapper.to_str().unwrap(),
        "--root-scratch",
        denied_scratch.to_str().unwrap(),
    ]);
    assert_eq!(denied.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&denied.stderr).contains("was not explicitly granted"),
        "{}",
        String::from_utf8_lossy(&denied.stderr)
    );
    assert!(
        !logged_arguments(&log)
            .iter()
            .any(|argument| argument == TRACKED_DEPENDENCY_URL),
        "ungranted dependency URL reached Git"
    );
    assert_eq!(
        fs::read(env.home().join("config/tracked.conf")).unwrap(),
        b"version=two\n"
    );
}

#[test]
fn plan_artifact_commit_state_recover_and_prune_use_engine_records() {
    let env = TestEnv::new();
    fs::create_dir(env.home().join("config")).unwrap();
    let embedded = env.engine();
    embedded.initialize_store().unwrap();
    let prepared = embedded.prepare_v1(&request()).unwrap();
    let plan_id = prepared.plan_id().as_str();
    let approval = prepared.approval_digest().as_str();

    let plan = env.malm_without_repo(&["plan", "--format", "json", "show", plan_id]);
    assert!(
        plan.status.success(),
        "{}",
        String::from_utf8_lossy(&plan.stderr)
    );
    let plan_json = json_data(&plan);
    assert_eq!(plan_json["plan_id"], plan_id);
    assert_eq!(plan_json["namespace"], "workstation");
    assert_eq!(plan_json["expected_head"], serde_json::Value::Null);
    assert_eq!(plan_json["approval_digest"], approval);
    assert_eq!(plan_json["inputs"], serde_json::json!([]));
    assert_eq!(plan_json["transforms"], serde_json::json!([]));
    assert_eq!(plan_json["operation_count"], 1);
    assert_eq!(plan_json["operations"][0]["operation"], "place_file");
    assert_eq!(plan_json["operations"][0]["authority"], "home");
    assert_eq!(
        plan_json["operations"][0]["relative_path"],
        "config/file.conf"
    );
    assert_eq!(plan_json["operations"][0]["artifact_id"], "config/file");
    assert_eq!(plan_json["operations"][0]["replace_existing"], false);
    assert_eq!(plan_json["artifacts"][0]["id"], "config/file");

    let output_path = env.repo().join("exported-artifact");
    let artifact = env.malm_without_repo(&[
        "plan",
        "--format",
        "json",
        "artifact",
        "export",
        plan_id,
        "config/file",
        "--output",
        output_path.to_str().unwrap(),
    ]);
    assert!(
        artifact.status.success(),
        "{}",
        String::from_utf8_lossy(&artifact.stderr)
    );
    assert_eq!(fs::read(&output_path).unwrap(), b"CLI prepared bytes\n");
    let mut non_utf8_output = env.repo();
    non_utf8_output.push(std::ffi::OsString::from_vec(b"artifact-\xff".to_vec()));
    let non_utf8 = Command::new(env!("CARGO_BIN_EXE_malm"))
        .args([
            std::ffi::OsString::from("plan"),
            std::ffi::OsString::from("artifact"),
            std::ffi::OsString::from("export"),
            std::ffi::OsString::from(plan_id),
            std::ffi::OsString::from("config/file"),
            std::ffi::OsString::from("--output"),
            non_utf8_output.as_os_str().to_owned(),
        ])
        .env("HOME", env.home())
        .env("XDG_STATE_HOME", env.state_home())
        .env_remove("MALM_FAILPOINT")
        .output()
        .unwrap();
    assert!(
        non_utf8.status.success(),
        "{}",
        String::from_utf8_lossy(&non_utf8.stderr)
    );
    assert_eq!(fs::read(non_utf8_output).unwrap(), b"CLI prepared bytes\n");

    let wrong = env.malm_without_repo(&[
        "plan",
        "apply",
        plan_id,
        "--approval",
        Digest::sha256(b"wrong").as_str(),
    ]);
    assert_eq!(wrong.status.code(), Some(2));
    assert!(!env.home().join("config/file.conf").exists());

    let committed = env.malm_without_repo(&[
        "plan",
        "--format",
        "json",
        "apply",
        plan_id,
        "--approval",
        approval,
    ]);
    assert!(
        committed.status.success(),
        "{}",
        String::from_utf8_lossy(&committed.stderr)
    );
    let committed_json = json_data(&committed);
    let head = committed_json["generation"].as_str().unwrap();
    assert_eq!(committed_json["plan_id"], plan_id);
    assert_eq!(committed_json["namespace"], "workstation");
    assert_eq!(
        committed_json["previous_generation"],
        serde_json::Value::Null
    );
    assert_eq!(committed_json["removed"], false);
    assert_eq!(
        fs::read(env.home().join("config/file.conf")).unwrap(),
        b"CLI prepared bytes\n"
    );

    let generation_short = format!("gen:{}", &head[7..19]);
    for command in ["show", "desired", "retention", "tracking"] {
        let inspected = env.malm_without_repo(&[
            "namespace",
            "generation",
            command,
            &generation_short,
            "--namespace",
            "workstation",
        ]);
        assert!(
            inspected.status.success(),
            "{command}: {}",
            String::from_utf8_lossy(&inspected.stderr)
        );
        let rendered = String::from_utf8(inspected.stdout).unwrap();
        assert!(rendered.contains(&generation_short), "{rendered}");
        assert!(
            !rendered.contains("sha256-") || command == "desired",
            "{rendered}"
        );
    }
    let restore = env.malm_without_repo(&[
        "plan",
        "restore",
        &generation_short,
        "--namespace",
        "workstation",
    ]);
    assert!(
        restore.status.success(),
        "{}",
        String::from_utf8_lossy(&restore.stderr)
    );
    let restore_point = env.malm_without_repo(&[
        "plan",
        "retention",
        "restore-point",
        "add",
        &generation_short,
        "--namespace",
        "workstation",
    ]);
    assert!(
        restore_point.status.success(),
        "{}",
        String::from_utf8_lossy(&restore_point.stderr)
    );
    let blob = plan_json["artifacts"][0]["digest"].as_str().unwrap();
    let blob_short = format!("blob:{}", &blob[7..19]);
    let pin = env.malm_without_repo(&[
        "plan",
        "retention",
        "pin",
        "artifact-blob",
        &blob_short,
        "--namespace",
        "workstation",
    ]);
    assert!(
        pin.status.success(),
        "{}",
        String::from_utf8_lossy(&pin.stderr)
    );
    let wrong_generation_domain = env.malm_without_repo(&[
        "namespace",
        "generation",
        "show",
        &format!("tree:{}", &head[7..19]),
        "--namespace",
        "workstation",
    ]);
    assert_eq!(wrong_generation_domain.status.code(), Some(2));

    let state = env.malm_without_repo(&[
        "namespace",
        "--format",
        "json",
        "show",
        "--namespace",
        "workstation",
    ]);
    assert!(state.status.success());
    let state_json = json_data(&state);
    assert_eq!(state_json["namespace"], "workstation");
    assert_eq!(state_json["head"], head);
    fs::write(env.home().join("config/file.conf"), b"modified\n").unwrap();
    let status = env.malm_without_repo(&[
        "namespace",
        "--format",
        "json",
        "status",
        "--namespace",
        "workstation",
    ]);
    assert_eq!(status.status.code(), Some(1));
    assert!(status.stderr.is_empty());
    let status_json = json_data(&status);
    assert_eq!(status_json["status"], "enabled_modified");
    assert_eq!(status_json["targets"][0]["status"], "modified");
    fs::write(env.home().join("config/file.conf"), b"CLI prepared bytes\n").unwrap();
    let recovered = env.malm_without_repo(&["store", "recover"]);
    assert!(recovered.status.success());
    let recovered = String::from_utf8(recovered.stdout).unwrap();
    assert!(recovered.contains("No recovery needed"), "{recovered}");
    assert!(
        recovered.contains("No interrupted transaction was found"),
        "{recovered}"
    );

    let active_prune = env.malm_without_repo(&["plan", "delete", plan_id]);
    assert_eq!(active_prune.status.code(), Some(2));
    assert!(embedded.plan_v1(prepared.plan_id()).is_ok());

    let disposable = embedded
        .prepare_v1(&PrepareRequestV1::from(PrepareRequestPartsV1 {
            namespace: NamespaceName::new("workstation").unwrap(),
            expected_head: Some(Digest::new(head.to_owned()).unwrap()),
            graph_digest: Digest::sha256(b"disposable"),
            inputs: vec![],
            artifacts: vec![],
            transforms: vec![],
            findings: vec![],
            operations: vec![],
        }))
        .unwrap();
    let pruned = env.malm_without_repo(&[
        "plan",
        "--format",
        "json",
        "delete",
        disposable.plan_id().as_str(),
    ]);
    assert!(pruned.status.success());
    let pruned_json = json_data(&pruned);
    assert_eq!(pruned_json["removed"]["prepared_records"], 1);
    assert!(embedded.plan_v1(disposable.plan_id()).is_err());
    assert!(env.state_root().join("descriptor.json").is_file());
}

#[test]
fn namespace_removal_commit_reports_nullable_heads_in_json_and_explicit_text() {
    let env = TestEnv::new();
    let embedded = env.engine();
    embedded.initialize_store().unwrap();

    let seed = |namespace: &str| {
        let prepared = embedded
            .prepare_v1(&PrepareRequestV1::from(PrepareRequestPartsV1 {
                namespace: NamespaceName::new(namespace).unwrap(),
                expected_head: None,
                graph_digest: Digest::sha256(format!("{namespace} removal seed")),
                inputs: vec![],
                artifacts: vec![],
                transforms: vec![],
                findings: vec![],
                operations: vec![],
            }))
            .unwrap();
        embedded
            .commit_v1(&CommitRequestV1::new(
                prepared.plan_id().clone(),
                ApprovalV1::new(
                    prepared.plan_id().clone(),
                    prepared.approval_digest().clone(),
                ),
            ))
            .unwrap()
            .head()
            .clone()
    };

    let json_head = seed("json-removal");
    let plan = env.malm_without_repo(&[
        "plan",
        "--format",
        "json",
        "remove",
        "--namespace",
        "json-removal",
    ]);
    assert!(
        plan.status.success(),
        "{}",
        String::from_utf8_lossy(&plan.stderr)
    );
    let plan = json_data(&plan);
    let plan_id = plan["plan_id"].as_str().unwrap();
    let approval = plan["approval_digest"].as_str().unwrap();
    let committed = env.malm_without_repo(&[
        "plan",
        "--format",
        "json",
        "apply",
        plan_id,
        "--approval",
        approval,
    ]);
    assert!(
        committed.status.success(),
        "{}",
        String::from_utf8_lossy(&committed.stderr)
    );
    let committed = json_data(&committed);
    assert_eq!(committed["namespace"], "json-removal");
    assert_eq!(committed["previous_generation"], json_head.as_str());
    assert_eq!(committed["generation"], serde_json::Value::Null);
    assert_eq!(committed["removed"], true);

    let text_head = seed("text-removal");
    let plan = env.malm_without_repo(&[
        "plan",
        "--format",
        "json",
        "remove",
        "--namespace",
        "text-removal",
    ]);
    assert!(
        plan.status.success(),
        "{}",
        String::from_utf8_lossy(&plan.stderr)
    );
    let plan = json_data(&plan);
    let plan_id = plan["plan_id"].as_str().unwrap();
    let approval = plan["approval_digest"].as_str().unwrap();
    let committed = env.malm_without_repo(&["plan", "apply", plan_id, "--approval", approval]);
    assert!(
        committed.status.success(),
        "{}",
        String::from_utf8_lossy(&committed.stderr)
    );
    let committed = String::from_utf8(committed.stdout).unwrap();
    assert!(committed.contains("Namespace removed"), "{committed}");
    assert!(committed.contains("text-removal"), "{committed}");
    assert!(
        committed.contains(&format!("gen:{}", &text_head.as_str()[7..19])),
        "{committed}"
    );
    assert!(
        committed.contains(&format!("plan:{}", &plan_id[3..15])),
        "{committed}"
    );
    assert!(
        embedded
            .inspect_state_v1(&NamespaceName::new("json-removal").unwrap())
            .unwrap()
            .head()
            .is_none()
    );
    assert!(
        embedded
            .inspect_state_v1(&NamespaceName::new("text-removal").unwrap())
            .unwrap()
            .head()
            .is_none()
    );
}

#[test]
fn fsck_cli_returns_a_structured_nonzero_result_without_repairing_corruption() {
    let env = TestEnv::new();
    fs::create_dir(env.home().join("config")).unwrap();
    let embedded = env.engine();
    embedded.initialize_store().unwrap();
    let prepared = embedded.prepare_v1(&request()).unwrap();
    embedded
        .commit_v1(&CommitRequestV1::new(
            prepared.plan_id().clone(),
            ApprovalV1::new(
                prepared.plan_id().clone(),
                prepared.approval_digest().clone(),
            ),
        ))
        .unwrap();
    let blob = env
        .state_root()
        .join("objects/blobs")
        .join(prepared.artifacts()[0].digest().as_str());
    fs::set_permissions(&blob, fs::Permissions::from_mode(0o600)).unwrap();
    fs::write(&blob, b"corrupt\n").unwrap();
    fs::set_permissions(&blob, fs::Permissions::from_mode(0o400)).unwrap();
    let before = fs::read(&blob).unwrap();

    let fsck = env.malm_without_repo(&["store", "--format", "json", "verify"]);
    assert_eq!(fsck.status.code(), Some(1));
    assert!(fsck.stderr.is_empty());
    let report = json_data(&fsck);
    assert_eq!(report["clean"], false);
    assert!(
        report["findings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|finding| {
                matches!(
                    finding["code"].as_str(),
                    Some("corrupt_artifact_blob" | "artifact_length_mismatch")
                )
            })
    );
    assert_eq!(fs::read(blob).unwrap(), before);
}

#[test]
fn local_locked_profile_prepares_and_commits_through_final_cli_commands() {
    let env = TestEnv::new();
    write_static_pack(&env);
    fs::create_dir(env.home().join("config")).unwrap();
    fs::create_dir(env.home().join("share")).unwrap();
    let initialized = env.malm_without_repo(&["store", "init"]);
    assert!(initialized.status.success());

    let prepared = env.malm_without_repo(&[
        "plan",
        "--format",
        "json",
        "create",
        "--profile",
        "desktop",
        "--source",
        env.repo().to_str().unwrap(),
        "--namespace",
        "workstation",
    ]);
    assert!(
        prepared.status.success(),
        "{}",
        String::from_utf8_lossy(&prepared.stderr)
    );
    let prepared = json_data(&prepared);
    let plan_id = PreparedId::new(prepared["plan_id"].as_str().unwrap()).unwrap();
    let approval = prepared["approval_digest"].as_str().unwrap().to_owned();
    assert_eq!(prepared["operation_count"], 2);
    assert_eq!(prepared["artifacts"][0]["id"], "rich/config");
    assert_eq!(
        prepared["artifacts"][0]["media_type"],
        "application/octet-stream"
    );
    assert_eq!(prepared["artifacts"][1]["id"], "rich/palette");
    assert!(
        prepared["inputs"]
            .as_array()
            .unwrap()
            .iter()
            .any(|input| input["kind"] == "source")
    );
    assert!(
        prepared["inputs"]
            .as_array()
            .unwrap()
            .iter()
            .any(|input| input["kind"] == "asset" && input["name"] == "pack-file:palette:raw")
    );
    assert_eq!(prepared["transforms"], serde_json::json!([]));

    let engine_plan = env.engine().plan_v1(&plan_id).unwrap();
    assert_eq!(engine_plan.operation_count(), 2);
    assert_eq!(engine_plan.artifacts().len(), 2);

    let request_id = RequestIdV1::new("reload-static-plan").unwrap();
    let request =
        RequestEnvelopeV1::new(request_id.clone(), MachineRequestV1::Plan(plan_id.clone()));
    let mut machine = Command::new(env!("CARGO_BIN_EXE_malm"))
        .arg("machine")
        .env("HOME", env.home())
        .env("XDG_STATE_HOME", env.state_home())
        .env_remove("MALM_FAILPOINT")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    machine
        .stdin
        .take()
        .unwrap()
        .write_all(&encode_request_v1(&request).unwrap())
        .unwrap();
    let machine = machine.wait_with_output().unwrap();
    assert!(
        machine.status.success(),
        "{}",
        String::from_utf8_lossy(&machine.stderr)
    );
    assert!(machine.stderr.is_empty());
    let frames = machine
        .stdout
        .split_inclusive(|byte| *byte == b'\n')
        .map(|record| decode_server_frame_v1(record).unwrap())
        .collect::<Vec<_>>();
    let [
        ServerFrameV1::Started {
            request_id: started_id,
            ..
        },
        ServerFrameV1::Result {
            request_id: result_id,
            sequence: 1,
            result: MachineResultV1::Plan(machine_plan),
        },
    ] = frames.as_slice()
    else {
        panic!("machine plan returned unexpected frames: {frames:?}")
    };
    assert_eq!(started_id, &request_id);
    assert_eq!(result_id, &request_id);
    assert_eq!(machine_plan, &engine_plan);

    let planned = env.malm_without_repo(&["plan", "--format", "json", "show", plan_id.as_str()]);
    assert!(
        planned.status.success(),
        "{}",
        String::from_utf8_lossy(&planned.stderr)
    );
    assert_eq!(prepared, json_data(&planned));
    assert!(!env.home().join("config/theme.conf").exists());

    let exported = env.repo().join("rendered-theme.conf");
    let artifact = env.malm_without_repo(&[
        "plan",
        "artifact",
        "export",
        plan_id.as_str(),
        "rich/config",
        "--output",
        exported.to_str().unwrap(),
    ]);
    assert!(
        artifact.status.success(),
        "{}",
        String::from_utf8_lossy(&artifact.stderr)
    );
    assert_eq!(fs::read(exported).unwrap(), b"theme=dark\n");
    let exported_asset = env.repo().join("palette.bin");
    let artifact = env.malm_without_repo(&[
        "plan",
        "artifact",
        "export",
        plan_id.as_str(),
        "rich/palette",
        "--output",
        exported_asset.to_str().unwrap(),
    ]);
    assert!(
        artifact.status.success(),
        "{}",
        String::from_utf8_lossy(&artifact.stderr)
    );
    assert_eq!(fs::read(exported_asset).unwrap(), b"\0\xffpalette\n");
    fs::remove_dir_all(env.repo()).unwrap();

    let committed = env.malm_without_repo(&[
        "plan",
        "apply",
        plan_id.as_str(),
        "--approval",
        approval.as_str(),
    ]);
    assert!(
        committed.status.success(),
        "{}",
        String::from_utf8_lossy(&committed.stderr)
    );
    assert_eq!(
        fs::read(env.home().join("config/theme.conf")).unwrap(),
        b"theme=dark\n"
    );
    assert_eq!(
        fs::read(env.home().join("share/palette.bin")).unwrap(),
        b"\0\xffpalette\n"
    );
    assert!(env.state_root().join("descriptor.json").is_file());
}

#[test]
fn remote_locked_profile_requires_explicit_authority_and_reuses_verified_cache() {
    let env = TestEnv::new();
    let fixture = write_remote_static_pack(&env);
    fs::create_dir(env.home().join("config")).unwrap();
    let initialized = env.malm_without_repo(&["store", "init"]);
    assert!(initialized.status.success());

    let root = env.repo();
    let parent = root.parent().unwrap();
    let log = parent.join("git.log");
    let wrapper = write_git_wrapper(parent, &fixture.repository, &log);
    let scratch = parent.join("git-scratch");
    fs::create_dir(&scratch).unwrap();
    fs::set_permissions(&scratch, fs::Permissions::from_mode(0o700)).unwrap();
    let scratch_grant = format!("{}={}", fixture.digest, scratch.display());

    let denied = env.malm_without_repo(&[
        "plan",
        "create",
        "--profile",
        "desktop",
        "--source",
        env.repo().to_str().unwrap(),
        "--git-executable",
        wrapper.to_str().unwrap(),
        "--git-scratch",
        &scratch_grant,
    ]);
    assert!(!denied.status.success());
    assert!(
        String::from_utf8_lossy(&denied.stderr).contains("was not explicitly granted"),
        "{}",
        String::from_utf8_lossy(&denied.stderr)
    );
    assert!(!log.exists(), "denied URL authority must not launch Git");

    let missing_scratch = env.malm_without_repo(&[
        "plan",
        "create",
        "--profile",
        "desktop",
        "--source",
        env.repo().to_str().unwrap(),
        "--allow-git",
        fixture.url.as_str(),
        "--git-executable",
        wrapper.to_str().unwrap(),
    ]);
    assert!(!missing_scratch.status.success());
    assert!(
        String::from_utf8_lossy(&missing_scratch.stderr)
            .contains("missing caller-owned Git scratch directory"),
        "{}",
        String::from_utf8_lossy(&missing_scratch.stderr)
    );
    assert!(!log.exists(), "missing scratch must not launch Git");

    let prepared = env.malm_without_repo(&[
        "plan",
        "--format",
        "json",
        "create",
        "--profile",
        "desktop",
        "--source",
        env.repo().to_str().unwrap(),
        "--namespace",
        "workstation",
        "--allow-git",
        fixture.url.as_str(),
        "--git-scratch",
        &scratch_grant,
        "--git-executable",
        wrapper.to_str().unwrap(),
    ]);
    assert!(
        prepared.status.success(),
        "{}",
        String::from_utf8_lossy(&prepared.stderr)
    );
    let prepared = json_data(&prepared);
    let plan_id = prepared["plan_id"].as_str().unwrap();
    assert_eq!(prepared["operation_count"], 1);
    assert_eq!(prepared["artifacts"][0]["id"], "rich/config");
    assert_eq!(
        prepared["inputs"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|input| input["kind"] == "source")
            .count(),
        2
    );
    assert_eq!(prepared["transforms"], serde_json::json!([]));
    assert_eq!(
        env.engine().load_pack_object_v1(&fixture.digest).unwrap()[1].bytes(),
        b"remote locked bytes\n"
    );
    let arguments = logged_arguments(&log);
    assert!(arguments.iter().any(|argument| argument == "fetch"));
    assert!(
        arguments
            .iter()
            .any(|argument| argument == fixture.url.as_str())
    );
    assert!(arguments.iter().any(|argument| argument == &fixture.commit));

    let invalid_executable = env.malm_without_repo(&[
        "plan",
        "create",
        "--profile",
        "desktop",
        "--source",
        env.repo().to_str().unwrap(),
        "--allow-git",
        fixture.url.as_str(),
        "--git-executable",
        "git",
    ]);
    assert!(!invalid_executable.status.success());
    assert!(
        String::from_utf8_lossy(&invalid_executable.stderr)
            .contains("Git executable must be absolute"),
        "{}",
        String::from_utf8_lossy(&invalid_executable.stderr)
    );

    fs::remove_file(&wrapper).unwrap();
    let reused = env.malm_without_repo(&[
        "plan",
        "--format",
        "json",
        "create",
        "--profile",
        "desktop",
        "--source",
        env.repo().to_str().unwrap(),
        "--namespace",
        "workstation",
        "--allow-git",
        fixture.url.as_str(),
        "--git-executable",
        "/definitely/missing/git",
    ]);
    assert!(
        reused.status.success(),
        "{}",
        String::from_utf8_lossy(&reused.stderr)
    );
    assert_eq!(json_data(&reused)["plan_id"], plan_id);

    let cached = env.malm_without_repo(&[
        "plan",
        "--format",
        "json",
        "create",
        "--profile",
        "desktop",
        "--source",
        env.repo().to_str().unwrap(),
        "--namespace",
        "workstation",
        "--cached",
    ]);
    assert!(
        cached.status.success(),
        "{}",
        String::from_utf8_lossy(&cached.stderr)
    );
    assert_eq!(json_data(&cached)["plan_id"], plan_id);
    assert!(env.state_root().join("descriptor.json").is_file());
}

#[test]
fn checkout_cli_prepares_a_reviewable_offline_restore_plan() {
    let env = TestEnv::new();
    fs::create_dir(env.home().join("config")).unwrap();
    let embedded = env.engine();
    embedded.initialize_store().unwrap();
    let first = embedded.prepare_v1(&request()).unwrap();
    let first_outcome = embedded
        .commit_v1(&CommitRequestV1::new(
            first.plan_id().clone(),
            ApprovalV1::new(first.plan_id().clone(), first.approval_digest().clone()),
        ))
        .unwrap();
    let artifact = ArtifactId::new("config/file").unwrap();
    let second = embedded
        .prepare_v1(&PrepareRequestV1::from(PrepareRequestPartsV1 {
            namespace: NamespaceName::new("workstation").unwrap(),
            expected_head: Some(first_outcome.head().clone()),
            graph_digest: Digest::sha256(b"second CLI graph"),
            inputs: vec![],
            artifacts: vec![
                PrepareArtifactV1::new(
                    artifact.clone(),
                    b"changed CLI bytes\n".to_vec(),
                    "text/plain",
                )
                .unwrap(),
            ],
            transforms: vec![],
            findings: vec![],
            operations: vec![
                PrepareOperationV1::replace_file(
                    DeploymentName::new("home").unwrap(),
                    "config/file.conf",
                    artifact,
                    0o600,
                )
                .unwrap(),
            ],
        }))
        .unwrap();
    embedded
        .commit_v1(&CommitRequestV1::new(
            second.plan_id().clone(),
            ApprovalV1::new(second.plan_id().clone(), second.approval_digest().clone()),
        ))
        .unwrap();

    let checkout = env.malm_without_repo(&[
        "plan",
        "--format",
        "json",
        "restore",
        first_outcome.head().as_str(),
        "--namespace",
        "workstation",
    ]);
    assert!(
        checkout.status.success(),
        "{}",
        String::from_utf8_lossy(&checkout.stderr)
    );
    let checkout = json_data(&checkout);
    assert_eq!(checkout["operation_count"], 1);
    assert_eq!(checkout["operations"][0]["operation"], "place_file");
    assert_eq!(checkout["operations"][0]["replace_existing"], true);
    assert!(
        checkout["findings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|finding| finding["code"] == "checkout")
    );
    assert!(
        checkout["findings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|finding| finding["code"] == "replace-existing")
    );
    assert_eq!(
        fs::read(env.home().join("config/file.conf")).unwrap(),
        b"changed CLI bytes\n"
    );

    let committed = env.malm_without_repo(&[
        "plan",
        "apply",
        checkout["plan_id"].as_str().unwrap(),
        "--approval",
        checkout["approval_digest"].as_str().unwrap(),
    ]);
    assert!(
        committed.status.success(),
        "{}",
        String::from_utf8_lossy(&committed.stderr)
    );
    assert_eq!(
        fs::read(env.home().join("config/file.conf")).unwrap(),
        b"CLI prepared bytes\n"
    );
    assert!(env.state_root().join("descriptor.json").is_file());
}

/// Writes a locked authoring pack into the test repository.
fn write_authoring_pack(env: &TestEnv) {
    let config_path = PackPath::new(malm_config::CONFIG_FILE).unwrap();
    let config = br#"config target="~/.config" default-profile="calm"

module "greeter" {
    description "renders one greeting"
    outputs {
        render "greeter/greeting.conf" format="key-value" separator="=" quote="none" {
            "greeting" "hello"
        }
    }
}

profile "calm" {
    use "greeter"
}
"#;
    let manifest = PackManifestV1::new(
        PackageId::new("com.example.authoring").unwrap(),
        vec![],
        vec![],
        vec![],
        vec![],
        vec![],
        vec![],
    )
    .unwrap()
    .with_config_documents(vec![config_path.clone()])
    .unwrap();
    let files = {
        let mut files = vec![
            PackFileV1::new(
                PackPath::new("malm-pack.kdl").unwrap(),
                encode_pack_v1(&manifest),
            ),
            PackFileV1::new(config_path, config.to_vec()),
        ];
        files.sort_by(|left, right| left.path().cmp(right.path()));
        files
    };
    let digest = pack_content_digest(files.iter().map(|file| (file.path(), file.bytes()))).unwrap();
    for file in &files {
        let path = env.repo().join(file.path().as_str());
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, file.bytes()).unwrap();
    }
    let root = LockedPackV1::new(
        PackageId::new("com.example.authoring").unwrap(),
        LockedSourceV1::Root,
        digest,
        vec![],
        vec![],
    )
    .unwrap();
    let lock = LockV1::new(root.node_id().clone(), vec![root]).unwrap();
    fs::write(env.repo().join("malm.lock"), encode_lock_v1(&lock)).unwrap();
}

#[test]
fn absent_store_is_rejected_up_front_with_the_bootstrap_hint() {
    let env = TestEnv::new();
    write_authoring_pack(&env);
    let source = env.repo().to_str().unwrap().to_owned();

    for arguments in [
        vec!["source", "lock", "create", "--source", &source],
        vec!["source", "lock", "update", "--source", &source],
        vec!["plan", "create", "--source", &source],
        vec!["deploy", "--source", &source],
        vec!["plan", "apply", "plan:0123456789ab"],
    ] {
        let output = env.malm(&arguments);
        assert_eq!(output.status.code(), Some(2), "{arguments:?}");
        assert!(output.stdout.is_empty(), "{arguments:?}");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("error[store-not-ready]"),
            "{arguments:?}: {stderr}"
        );
        assert!(stderr.contains("malm store init"), "{arguments:?}: {stderr}");
    }
    assert!(!env.state_root().exists());
}

#[test]
fn unmanaged_directory_conflict_lists_only_paths_and_static_remediation() {
    let env = TestEnv::new();
    write_authoring_pack(&env);
    assert!(env.malm(&["store", "init"]).status.success());
    let blocking = env.home().join(".config/greeter/greeting.conf");
    fs::create_dir_all(&blocking).unwrap();
    fs::write(blocking.join("stale.txt"), b"stale").unwrap();
    fs::write(blocking.join("old.txt"), b"old").unwrap();

    let source = env.repo().to_str().unwrap().to_owned();
    let refused = env.malm(&["plan", "create", "--source", &source]);
    assert_eq!(refused.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&refused.stderr);
    assert!(stderr.contains("error[unsafe-target]"), "{stderr}");
    assert!(stderr.contains("Blocked directories"), "{stderr}");
    assert!(stderr.contains(blocking.to_str().unwrap()), "{stderr}");
    assert!(stderr.contains("Back up, move, or remove every listed directory"), "{stderr}");
    assert!(!stderr.contains("old.txt"), "{stderr}");
    assert!(!stderr.contains("stale.txt"), "{stderr}");
    assert!(!stderr.contains("mv --"), "{stderr}");
    assert_eq!(fs::read(blocking.join("stale.txt")).unwrap(), b"stale");

    let deploy = env.malm(&["deploy", "--source", &source]);
    assert_eq!(deploy.status.code(), Some(2));
    let deploy_stderr = String::from_utf8_lossy(&deploy.stderr);
    assert!(
        deploy_stderr.contains("error[unsafe-target]"),
        "{deploy_stderr}"
    );
    assert!(
        deploy_stderr.contains(blocking.to_str().unwrap()),
        "{deploy_stderr}"
    );

    let json = env.malm(&[
        "plan",
        "create",
        "--source",
        &source,
        "--format",
        "json",
    ]);
    assert_eq!(json.status.code(), Some(2));
    let envelope: serde_json::Value = serde_json::from_slice(&json.stderr).unwrap();
    assert_eq!(envelope["data"], serde_json::Value::Null);
    assert_eq!(envelope["error"]["category"], "conflict");
    assert_eq!(envelope["error"]["code"], "unsafe-target");
    assert_eq!(envelope["diagnostics"].as_array().unwrap().len(), 1);
    assert_eq!(
        envelope["diagnostics"][0],
        serde_json::json!({
            "severity": "error",
            "code": "directory-occupancy-conflict",
            "message": blocking.to_str().unwrap(),
        })
    );

    let moved = env.home().join(".config/greeter/greeting.conf.backup");
    fs::rename(&blocking, &moved).unwrap();
    let prepared = env.malm(&["plan", "create", "--source", &source]);
    assert!(
        prepared.status.success(),
        "{}",
        String::from_utf8_lossy(&prepared.stderr)
    );
    assert!(moved.join("stale.txt").is_file());
}

#[test]
fn apply_without_consent_publishes_the_plan_and_fails_closed() {
    let env = TestEnv::new();
    write_authoring_pack(&env);
    fs::create_dir_all(env.home().join(".config/greeter")).unwrap();
    assert!(env.malm(&["store", "init"]).status.success());

    let source = env.repo().to_str().unwrap().to_owned();
    // Test invocations are non-terminal, so deploy fails closed: it publishes
    // the durable plan, prints the manual apply command, and exits 1.
    let output = env.malm(&["deploy", "--source", &source]);
    assert_eq!(output.status.code(), Some(1));
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("Plan ready"), "{stdout}");
    assert!(stdout.contains("Not applied"), "{stdout}");
    assert!(stdout.contains("malm plan apply plan:"), "{stdout}");
    assert!(!env.home().join(".config/greeter/greeting.conf").exists());

    // The published plan remains listed and can be addressed explicitly.
    let listing = env.malm(&["plan", "--format", "json", "list"]);
    assert!(listing.status.success());
    let listing = json_data(&listing);
    let plan_id = listing["plans"][0]["plan_id"].as_str().unwrap();
    let plan = env.malm(&["plan", "show", plan_id]);
    assert!(plan.status.success());
    let plan_stdout = String::from_utf8(plan.stdout).unwrap();
    assert!(plan_stdout.contains("Plan ready"), "{plan_stdout}");
    assert!(
        plan_stdout.contains(&format!("plan:{}", &plan_id[3..15])),
        "{plan_stdout}"
    );

    // Applying without `--approval` also fails closed outside a terminal.
    let applied = env.malm(&["plan", "apply", plan_id]);
    assert_eq!(applied.status.code(), Some(1));
    let applied_stdout = String::from_utf8(applied.stdout).unwrap();
    assert!(applied_stdout.contains("Not applied"), "{applied_stdout}");
    assert!(!env.home().join(".config/greeter/greeting.conf").exists());
}

#[test]
fn apply_with_yes_commits_a_findingless_plan() {
    let env = TestEnv::new();
    write_authoring_pack(&env);
    fs::create_dir_all(env.home().join(".config/greeter")).unwrap();
    assert!(env.malm(&["store", "init"]).status.success());

    let source = env.repo().to_str().unwrap().to_owned();
    let output = env.malm(&["deploy", "--source", &source, "--yes"]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("Applied"), "{stdout}");
    assert!(stdout.contains("default"), "{stdout}");
    assert_eq!(
        fs::read_to_string(env.home().join(".config/greeter/greeting.conf")).unwrap(),
        "greeting=hello\n"
    );
}

#[test]
fn source_render_confines_outputs_and_maps_the_home_target() {
    let env = TestEnv::new();
    write_authoring_pack(&env);
    let config_path = env.repo().join(malm_config::CONFIG_FILE);
    let config = fs::read_to_string(&config_path)
        .unwrap()
        .replace("target=\"~/.config\"", "target=\"~\"")
        .replace(
            "        }\n    }\n}\n\nprofile",
            "        }\n        symlink \"~/greeter/greeting.conf\" to=\"greeter/current.conf\" if-missing=\"allow\"\n    }\n}\n\nprofile",
        );
    fs::write(&config_path, config).unwrap();
    let source = env.repo().to_str().unwrap().to_owned();
    let output_root = env.home().join("rendered");
    let output = env.malm(&[
        "source",
        "render",
        "--source",
        &source,
        "--output",
        output_root.to_str().unwrap(),
        "--format",
        "json",
    ]);

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        fs::read_to_string(output_root.join("greeter/greeting.conf")).unwrap(),
        "greeting=hello\n"
    );
    assert_eq!(
        fs::metadata(output_root.join("greeter/greeting.conf"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o644
    );
    assert!(!output_root.join("~/greeter/greeting.conf").exists());
    assert_eq!(
        fs::read_link(output_root.join("greeter/current.conf")).unwrap(),
        Path::new("greeting.conf")
    );

    let config = fs::read_to_string(&config_path)
        .unwrap()
        .replace("target=\"~\"", "target=\"~/.config\"");
    fs::write(&config_path, config).unwrap();
    let external = env.home().join("external");
    fs::create_dir(&external).unwrap();
    let hostile_root = env.home().join("hostile-render");
    fs::create_dir(&hostile_root).unwrap();
    fs::create_dir(hostile_root.join(".config")).unwrap();
    std::os::unix::fs::symlink(&external, hostile_root.join(".config/greeter")).unwrap();
    let hostile = env.malm(&[
        "source",
        "render",
        "--source",
        &source,
        "--output",
        hostile_root.to_str().unwrap(),
    ]);
    assert_eq!(hostile.status.code(), Some(2));
    assert!(!external.join("greeting.conf").exists());
}

#[test]
fn source_render_rejects_component_transforms_before_creating_output() {
    let env = TestEnv::new();
    write_authoring_pack(&env);
    let config_path = env.repo().join(malm_config::CONFIG_FILE);
    let config = fs::read_to_string(&config_path).unwrap().replace(
        "            \"greeting\" \"hello\"",
        "            @component-transform \"formatter\"\n            \"greeting\" \"hello\"",
    );
    fs::write(&config_path, config).unwrap();
    let output_root = env.home().join("rendered-with-transform");
    let output = env.malm(&[
        "source",
        "render",
        "--source",
        env.repo().to_str().unwrap(),
        "--output",
        output_root.to_str().unwrap(),
    ]);

    assert_eq!(output.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("source render cannot execute component transforms"),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!output_root.exists());
}

#[test]
fn source_render_rejects_component_renderers_before_creating_output() {
    let env = TestEnv::new();
    write_authoring_pack(&env);
    let config_path = env.repo().join(malm_config::CONFIG_FILE);
    let config = fs::read_to_string(&config_path).unwrap().replace(
        "render \"greeter/greeting.conf\" format=\"key-value\" separator=\"=\" quote=\"none\"",
        "render \"greeter/greeting.conf\" format=\"lua-plugin\" component-renderer=\"formatter\"",
    );
    fs::write(&config_path, config).unwrap();
    let output_root = env.home().join("rendered-with-component-renderer");
    let output = env.malm(&[
        "source",
        "render",
        "--source",
        env.repo().to_str().unwrap(),
        "--output",
        output_root.to_str().unwrap(),
    ]);

    assert_eq!(output.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("source render cannot execute component transforms or renderers"),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!output_root.exists());
}

#[test]
fn json_deploy_refusals_are_error_envelopes() {
    let env = TestEnv::new();
    write_authoring_pack(&env);
    fs::create_dir_all(env.home().join(".config/greeter")).unwrap();
    fs::write(
        env.home().join(".config/greeter/greeting.conf"),
        "unmanaged\n",
    )
    .unwrap();
    assert!(env.malm(&["store", "init"]).status.success());
    let source = env.repo().to_str().unwrap().to_owned();

    let confirmation = env.malm(&["deploy", "--source", &source, "--format", "json"]);
    assert_eq!(confirmation.status.code(), Some(1));
    assert!(confirmation.stdout.is_empty());
    let confirmation: serde_json::Value = serde_json::from_slice(&confirmation.stderr).unwrap();
    assert_eq!(confirmation["error"]["code"], "confirmation-required");

    let approval = env.malm(&["deploy", "--source", &source, "--yes", "--format", "json"]);
    assert_eq!(approval.status.code(), Some(2));
    assert!(approval.stdout.is_empty());
    let approval: serde_json::Value = serde_json::from_slice(&approval.stderr).unwrap();
    assert_eq!(approval["error"]["code"], "approval-required");
    assert_eq!(
        fs::read_to_string(env.home().join(".config/greeter/greeting.conf")).unwrap(),
        "unmanaged\n"
    );
}

#[test]
fn missing_default_profile_is_a_structured_invalid_request() {
    let env = TestEnv::new();
    write_authoring_pack(&env);
    let config_path = env.repo().join(malm_config::CONFIG_FILE);
    let config = fs::read_to_string(&config_path)
        .unwrap()
        .replace(" default-profile=\"calm\"", "");
    fs::write(config_path, config).unwrap();
    let source = env.repo().to_str().unwrap().to_owned();

    let output = env.malm(&["source", "vars", "--source", &source, "--format", "json"]);
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    let envelope: serde_json::Value = serde_json::from_slice(&output.stderr).unwrap();
    assert_eq!(envelope["error"]["category"], "invalid_request");
    assert_eq!(envelope["error"]["code"], "profile-required");
}

#[test]
fn plan_prefix_resolution_is_unique_or_fails() {
    let env = TestEnv::new();
    write_authoring_pack(&env);
    fs::create_dir_all(env.home().join(".config/greeter")).unwrap();
    assert!(env.malm(&["store", "init"]).status.success());
    let source = env.repo().to_str().unwrap().to_owned();
    assert_eq!(
        env.malm(&["deploy", "--source", &source]).status.code(),
        Some(1)
    );

    let listing = env.malm(&["plan", "--format", "json", "list"]);
    assert!(listing.status.success());
    let listing = json_data(&listing);
    let full = listing["plans"][0]["plan_id"].as_str().unwrap();
    let short = format!("plan:{}", &full[3..15]);
    let by_prefix = env.malm(&["plan", "show", &short]);
    assert!(by_prefix.status.success());
    assert!(
        String::from_utf8(by_prefix.stdout)
            .unwrap()
            .contains(&short),
        "prefix resolves to the plan's displayed identifier"
    );
    for command in ["inputs", "transforms"] {
        let selected = env.malm(&["plan", command, &short]);
        assert!(
            selected.status.success(),
            "{command}: {}",
            String::from_utf8_lossy(&selected.stderr)
        );
    }
    let artifacts = env.malm(&["plan", "artifact", "list", &short]);
    assert!(artifacts.status.success());
    let selected = env.malm(&["plan", "--format", "json", "show", &short]);
    let selected = json_data(&selected);
    let artifact = selected["artifacts"][0]["id"].as_str().unwrap();
    assert!(
        env.malm(&["plan", "artifact", "show", &short, artifact])
            .status
            .success()
    );
    let exported = env.home().join("short-id-artifact");
    assert!(
        env.malm(&[
            "plan",
            "artifact",
            "export",
            &short,
            artifact,
            "--output",
            exported.to_str().unwrap(),
        ])
        .status
        .success()
    );
    assert_eq!(env.malm(&["plan", "apply", &short]).status.code(), Some(1));

    for invalid in [
        "plan:abcdefg",
        "plan:ABCDEF12",
        "plan:abcdef12...",
        "gen:abcdef12",
        "pp-abcdef12",
    ] {
        let rejected = env.malm(&["plan", "show", invalid]);
        assert_eq!(rejected.status.code(), Some(2), "accepted {invalid}");
    }

    let too_long = format!("plan:{}", "a".repeat(65));
    let rejected = env.malm(&["plan", "show", &too_long]);
    assert_eq!(rejected.status.code(), Some(2));

    let unknown = env.malm(&["plan", "show", "plan:0123456789abcdef"]);
    assert_eq!(unknown.status.code(), Some(2));

    let verbose = env.malm(&["plan", "show", &short, "-v"]);
    assert!(verbose.status.success());
    assert!(String::from_utf8(verbose.stdout).unwrap().contains(full));

    let deleted = env.malm(&["plan", "delete", &short]);
    assert!(
        deleted.status.success(),
        "{}",
        String::from_utf8_lossy(&deleted.stderr)
    );
}

#[test]
fn canonical_tree_short_ids_are_kind_scoped_and_verbose_is_canonical() {
    let env = TestEnv::new();
    let engine = env.engine();
    engine.initialize_store().unwrap();
    let tree = malm_tree::TreeObjectV1::new(0o755, vec![]).unwrap();
    let digest = malm_tree::tree_object_digest_v1(&tree);
    engine.publish_tree_object_v1(&digest, &tree).unwrap();
    let short = format!("tree:{}", &digest.as_str()[7..19]);

    let shown = env.malm_without_repo(&["object", "tree", "show", &short]);
    assert!(
        shown.status.success(),
        "{}",
        String::from_utf8_lossy(&shown.stderr)
    );
    let shown = String::from_utf8(shown.stdout).unwrap();
    assert!(shown.contains(&short), "{shown}");
    assert!(!shown.contains("..."), "{shown}");

    let verbose = env.malm_without_repo(&["object", "tree", "show", &short, "-v"]);
    assert!(verbose.status.success());
    assert!(
        String::from_utf8(verbose.stdout)
            .unwrap()
            .contains(digest.as_str())
    );

    let wrong_domain = format!("file:{}", &digest.as_str()[7..19]);
    assert_eq!(
        env.malm_without_repo(&["object", "tree", "show", &wrong_domain])
            .status
            .code(),
        Some(2)
    );
}
