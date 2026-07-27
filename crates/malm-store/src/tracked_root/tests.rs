use super::*;
use crate::DesiredSnapshotV1;
use crate::PreparedRecordPartsV1;
use crate::PreparedRecordV1;
use crate::StateGenerationV1;
use crate::prepared_id_v1;
use crate::state_generation_digest_v1;
use crate::test_fixtures::tracked_root;

#[test]
fn tracked_root_values_are_strict_sorted_and_bounded() {
    let tracked = tracked_root("primary", '1');
    let kinds = tracked
        .acquisition_grants()
        .iter()
        .map(AcquisitionGrantV1::kind)
        .collect::<Vec<_>>();
    assert_eq!(
        kinds,
        vec![
            AcquisitionGrantKindV1::LocalSource,
            AcquisitionGrantKindV1::GitSource,
        ]
    );
    assert_eq!(tracked.schema_version(), TRACKED_ROOT_SCHEMA_VERSION);
    assert_eq!(tracked.selected_profile().as_str(), "desktop");
    assert!(tracked.source_subdir().is_root());
    let nested = tracked
        .clone()
        .with_source_subdir(TrackedRootSubdirV1::new("packs/root").unwrap())
        .unwrap();
    assert_eq!(nested.source_subdir().as_str(), "packs/root");
    assert!(TrackedRootSubdirV1::new("../root").is_err());
    assert!(
        AcquisitionGrantV1::new(
            AcquisitionGrantKindV1::FormatComponent,
            Digest::sha256(b"component").as_str(),
        )
        .is_ok()
    );
    assert!(
        AcquisitionGrantV1::new(AcquisitionGrantKindV1::FormatComponent, "sha256-short").is_err()
    );
    assert!(AcquisitionGrantV1::new(AcquisitionGrantKindV1::TargetAuthority, "home").is_ok());
    assert!(AcquisitionGrantV1::new(AcquisitionGrantKindV1::TargetAuthority, "home/path").is_err());

    assert!(matches!(
        MovingSelectorV1::new(format!("sha1-{}", "1".repeat(40))),
        Err(PreparedRecordError::InvalidField {
            field: "tracked-root moving selector",
            ..
        })
    ));
    assert!(MovingSelectorV1::new("1".repeat(40)).is_err());
    assert!(MovingSelectorV1::new("a".repeat(MAX_TRACKED_ROOT_MOVING_SELECTOR_BYTES)).is_ok());
    assert!(matches!(
        MovingSelectorV1::new("a".repeat(MAX_TRACKED_ROOT_MOVING_SELECTOR_BYTES + 1)),
        Err(PreparedRecordError::InvalidField {
            field: "tracked-root moving selector",
            ..
        })
    ));
    assert!(TrackedRootSourceLocatorV1::new("https://example.com/").is_ok());
    assert!(TrackedRootSourceLocatorV1::new("https://example.com").is_err());
    assert!(TrackedRootSourceLocatorV1::new("https://EXAMPLE.com/root.git").is_err());
    assert!(TrackedRootSourceLocatorV1::new("https://example.com:443/root.git").is_err());
    assert!(
        TrackedRootSourceLocatorV1::new(format!(
            "https://example.com/{}",
            "x".repeat(MAX_TRACKED_ROOT_SOURCE_LOCATOR_BYTES)
        ))
        .is_err()
    );
    assert!(ConfigEntryPointV1::new(".git/config").is_err());
    assert!(matches!(
        AcquisitionGrantV1::new(
            AcquisitionGrantKindV1::LocalSource,
            "x".repeat(MAX_ACQUISITION_GRANT_LOCATOR_BYTES + 1),
        ),
        Err(PreparedRecordError::InvalidField {
            field: "acquisition grant locator",
            ..
        })
    ));

    let grants = (0..=MAX_TRACKED_ROOT_ACQUISITION_GRANTS)
        .map(|index| {
            AcquisitionGrantV1::new(
                AcquisitionGrantKindV1::LocalSource,
                format!("dependency-{index:05}"),
            )
            .unwrap()
        })
        .collect();
    assert!(matches!(
        TrackedRootV1::new(
            TrackedRootSourceLocatorV1::new("https://example.com/root.git").unwrap(),
            MovingSelectorV1::new("main").unwrap(),
            ExactRevisionV1::new(format!("sha1-{}", "2".repeat(40))).unwrap(),
            Digest::sha256(b"root tree"),
            ConfigEntryPointV1::new("malm.kdl").unwrap(),
            ContributionName::new("default").unwrap(),
            grants,
        ),
        Err(PreparedRecordError::LimitExceeded {
            field: "tracked-root acquisition grants",
            limit: MAX_TRACKED_ROOT_ACQUISITION_GRANTS,
            actual,
        }) if actual == MAX_TRACKED_ROOT_ACQUISITION_GRANTS + 1
    ));

    let grants = (0..(MAX_TRACKED_ROOT_ACQUISITION_BYTES / 4_000 + 2))
        .map(|index| {
            AcquisitionGrantV1::new(
                AcquisitionGrantKindV1::GitSource,
                format!(
                    "https://assets.example.com/{index:04}/{}",
                    "x".repeat(4_000)
                ),
            )
            .unwrap()
        })
        .collect();
    assert!(matches!(
        TrackedRootV1::new(
            TrackedRootSourceLocatorV1::new("https://example.com/root.git").unwrap(),
            MovingSelectorV1::new("main").unwrap(),
            ExactRevisionV1::new(format!("sha1-{}", "2".repeat(40))).unwrap(),
            Digest::sha256(b"root tree"),
            ConfigEntryPointV1::new("malm.kdl").unwrap(),
            ContributionName::new("default").unwrap(),
            grants,
        ),
        Err(PreparedRecordError::LimitExceeded {
            field: "tracked-root acquisition grant bytes",
            limit: MAX_TRACKED_ROOT_ACQUISITION_BYTES,
            ..
        })
    ));
}

#[test]
fn prepared_tracking_is_complete_state_not_an_implicit_predecessor_delta() {
    let namespace = NamespaceName::new("workstation").unwrap();
    let first_tracking = tracked_root("first", '1');
    let replacement_tracking = tracked_root("replacement", '2');
    let prepare = |expected_head, tracking| {
        PreparedRecordV1::try_from(PreparedRecordPartsV1 {
            namespace: namespace.clone(),
            expected_head,
            graph_digest: Digest::sha256(b"graph"),
            inputs: vec![],
            artifacts: vec![],
            transforms: vec![],
            findings: vec![],
            operations: vec![],
            desired_snapshot: DesiredSnapshotV1::empty(),
        })
        .unwrap()
        .with_tracked_root(tracking)
        .unwrap()
    };

    let first_plan = prepare(None, Some(first_tracking.clone()));
    let first =
        StateGenerationV1::from_prepared(prepared_id_v1(&first_plan), None, None, &first_plan)
            .unwrap();
    assert_eq!(first.tracked_root(), Some(&first_tracking));

    let first_digest = state_generation_digest_v1(&first);
    let replacement_plan = prepare(
        Some(first_digest.clone()),
        Some(replacement_tracking.clone()),
    );
    assert_eq!(replacement_plan.tracked_root(), Some(&replacement_tracking));
    let replaced = StateGenerationV1::from_prepared(
        prepared_id_v1(&replacement_plan),
        Some(first_digest),
        Some(&first),
        &replacement_plan,
    )
    .unwrap();
    assert_eq!(replaced.tracked_root(), Some(&replacement_tracking));

    let replaced_digest = state_generation_digest_v1(&replaced);
    let clear_plan = prepare(Some(replaced_digest.clone()), None);
    assert_eq!(clear_plan.tracked_root(), None);
    let cleared = StateGenerationV1::from_prepared(
        prepared_id_v1(&clear_plan),
        Some(replaced_digest),
        Some(&replaced),
        &clear_plan,
    )
    .unwrap();
    assert_eq!(cleared.tracked_root(), None);

    let mut forged = cleared.clone();
    forged.lifecycle = LifecycleStateV1::Disabled;
    let rebuilt = StateGenerationV1::from_prepared(
        prepared_id_v1(&clear_plan),
        cleared.previous_generation().cloned(),
        Some(&replaced),
        &clear_plan,
    )
    .unwrap();
    assert_ne!(rebuilt, forged);
    forged = cleared.clone();
    forged.tracked_root = Some(first_tracking);
    assert_ne!(rebuilt, forged);
}
