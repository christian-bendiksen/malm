use super::*;
use malm_types::ArtifactId;
use malm_types::ContributionName;
use malm_types::DeploymentName;
use malm_types::Digest;
use malm_types::NamespaceName;
use malm_types::PreparedId;

pub(crate) fn identity(inode: u64) -> FileIdentityV1 {
    FileIdentityV1 {
        device: 1,
        inode,
        user_id: 1_000,
        group_id: 1_000,
        mode: 0o100_644,
        links: 1,
        size: 0,
        modified_seconds: 0,
        modified_nanoseconds: 0,
        changed_seconds: 0,
        changed_nanoseconds: 0,
    }
}

pub(crate) fn record() -> PreparedRecordV1 {
    let artifact = PreparedArtifactV1::new(
        ArtifactId::new("config/file").unwrap(),
        Digest::sha256(b"content"),
        7,
        "text/plain",
    )
    .unwrap();
    let observation = TargetObservationV1::new(
        DeploymentName::new("home").unwrap(),
        ".config/example",
        identity(1),
        vec![identity(2)],
        identity(3),
        LeafObservationV1::Absent,
    )
    .unwrap();
    let desired_snapshot = DesiredSnapshotV1::new(vec![
        StateTargetV1::new(
            DeploymentName::new("home").unwrap(),
            ".config/example",
            StateTargetStateV1::File {
                file: Some(
                    StateFileV1::new(artifact.digest().clone(), artifact.byte_len(), 0o600)
                        .unwrap(),
                ),
            },
        )
        .unwrap(),
    ])
    .unwrap();
    PreparedRecordV1::try_from(PreparedRecordPartsV1 {
        namespace: NamespaceName::new("workstation").unwrap(),
        expected_head: None,
        graph_digest: Digest::sha256(b"graph"),
        inputs: vec![
            PreparedInputV1::new(
                PreparedInputKindV1::Config,
                "root-config",
                Digest::sha256(b"config"),
            )
            .unwrap(),
        ],
        artifacts: vec![artifact],
        transforms: vec![],
        findings: vec![PolicyFindingV1::new("create", "create one file", true).unwrap()],
        operations: vec![PreparedOperationV1::PlaceFile {
            observation,
            artifact_id: ArtifactId::new("config/file").unwrap(),
            mode: 0o600,
            replace_existing: false,
        }],
        desired_snapshot,
    })
    .unwrap()
}

pub(crate) fn state_target(authority: &str, relative_path: &str, present: bool) -> StateTargetV1 {
    StateTargetV1 {
        authority: DeploymentName::new(authority).unwrap(),
        relative_path: relative_path.to_owned(),
        state: StateTargetStateV1::Directory {
            directory: present.then_some(StateDirectoryV1 { mode: 0o700 }),
        },
    }
}

pub(crate) fn test_generation(
    namespace: &str,
    mut targets: Vec<StateTargetV1>,
) -> StateGenerationV1 {
    targets.sort_by(|left, right| {
        (left.authority(), left.relative_path()).cmp(&(right.authority(), right.relative_path()))
    });
    let namespace = NamespaceName::new(namespace).unwrap();
    let desired_snapshot = DesiredSnapshotV1::new(targets).unwrap();
    let desired_snapshot_digest = desired_snapshot_digest_v1(&namespace, &desired_snapshot);
    StateGenerationV1 {
        schema_version: PREPARED_RECORD_SCHEMA_VERSION,
        namespace,
        plan_id: PreparedId::from_digest(&Digest::sha256(b"test plan")),
        previous_generation: None,
        transition: PreparedTransitionV1::Reconcile,
        lifecycle: LifecycleStateV1::Enabled,
        restore_point: None,
        retention: RetentionAuthorityV1::default(),
        tracked_root: None,
        desired_snapshot,
        desired_snapshot_digest,
        artifacts: vec![],
        transforms: vec![],
    }
}

pub(crate) fn tracked_root(label: &str, revision_digit: char) -> TrackedRootV1 {
    TrackedRootV1::new(
        TrackedRootSourceLocatorV1::new(format!("https://example.com/{label}.git")).unwrap(),
        MovingSelectorV1::new("refs/heads/main").unwrap(),
        ExactRevisionV1::new(format!("sha1-{}", revision_digit.to_string().repeat(40))).unwrap(),
        Digest::sha256(format!("{label} root tree")),
        ConfigEntryPointV1::new("malm.kdl").unwrap(),
        ContributionName::new("desktop").unwrap(),
        vec![
            AcquisitionGrantV1::new(
                AcquisitionGrantKindV1::GitSource,
                format!("https://example.com/{label}-dependency.git"),
            )
            .unwrap(),
            AcquisitionGrantV1::new(
                AcquisitionGrantKindV1::LocalSource,
                format!("../{label}-local"),
            )
            .unwrap(),
        ],
    )
    .unwrap()
}
