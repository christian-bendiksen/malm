use super::*;
use crate::MAX_DESIRED_TARGETS;
use crate::PreparedRecordPartsV1;
use crate::StateDirectoryV1;
use crate::StateFileV1;
use crate::StateSymlinkV1;
use crate::StateTreeV1;
use crate::TargetObservationV1;
use crate::decode_state_generation_v1;
use crate::encode_state_generation_v1;
use crate::prepared_id_v1;
use crate::test_fixtures::identity;
use crate::test_fixtures::state_target;
use crate::test_fixtures::test_generation;

#[test]
fn normal_enabled_transition_turns_omitted_targets_into_removal_tombstones() {
    let namespace = NamespaceName::new("workstation").unwrap();
    let authority = DeploymentName::new("home").unwrap();
    let artifact = PreparedArtifactV1::new(
        ArtifactId::new("config/file").unwrap(),
        Digest::sha256(b"content"),
        7,
        "text/plain",
    )
    .unwrap();
    let place = PreparedOperationV1::PlaceFile {
        observation: TargetObservationV1::new(
            authority.clone(),
            "config/file",
            identity(1),
            vec![],
            identity(2),
            LeafObservationV1::Absent,
        )
        .unwrap(),
        artifact_id: artifact.id().clone(),
        mode: 0o600,
        replace_existing: false,
    };
    let first_snapshot = reconcile_desired_snapshot_v1(
        None,
        vec![
            StateTargetV1::new(
                authority.clone(),
                "config/file",
                StateTargetStateV1::File {
                    file: Some(
                        StateFileV1::new(artifact.digest().clone(), artifact.byte_len(), 0o600)
                            .unwrap(),
                    ),
                },
            )
            .unwrap(),
        ],
    )
    .unwrap();
    let first_record = PreparedRecordV1::try_from(PreparedRecordPartsV1 {
        namespace: namespace.clone(),
        expected_head: None,
        graph_digest: Digest::sha256(b"first graph"),
        inputs: vec![],
        artifacts: vec![artifact],
        transforms: vec![],
        findings: vec![],
        operations: vec![place],
        desired_snapshot: first_snapshot,
    })
    .unwrap();
    let first =
        StateGenerationV1::from_prepared(prepared_id_v1(&first_record), None, None, &first_record)
            .unwrap();
    assert!(matches!(
        first.targets()[0].state(),
        StateTargetStateV1::File { file: Some(_) }
    ));

    let first_digest = state_generation_digest_v1(&first);
    let remove = PreparedOperationV1::RemoveLeaf {
        observation: TargetObservationV1::new(
            authority,
            "config/file",
            identity(1),
            vec![],
            identity(2),
            LeafObservationV1::Present(identity(3)),
        )
        .unwrap(),
    };
    let second_snapshot =
        reconcile_desired_snapshot_v1(Some(first.desired_snapshot()), vec![]).unwrap();
    assert!(matches!(
        second_snapshot.targets()[0].state(),
        StateTargetStateV1::File { file: None }
    ));
    let second_record = PreparedRecordV1::try_from(PreparedRecordPartsV1 {
        namespace: namespace.clone(),
        expected_head: Some(first_digest.clone()),
        graph_digest: Digest::sha256(b"second graph"),
        inputs: vec![],
        artifacts: vec![],
        transforms: vec![],
        findings: vec![],
        operations: vec![remove],
        desired_snapshot: second_snapshot.clone(),
    })
    .unwrap();
    let second = StateGenerationV1::from_prepared(
        prepared_id_v1(&second_record),
        Some(first_digest),
        Some(&first),
        &second_record,
    )
    .unwrap();
    assert!(matches!(
        second.targets()[0].state(),
        StateTargetStateV1::File { file: None }
    ));
    assert_eq!(second.desired_snapshot(), &second_snapshot);
    let digest = state_generation_digest_v1(&second);
    assert_eq!(
        decode_state_generation_v1(&digest, &encode_state_generation_v1(&second)).unwrap(),
        second
    );

    let mut forged_generation = second;
    forged_generation.desired_snapshot_digest = Digest::sha256(b"forged state");
    let forged = encode_state_generation_v1(&forged_generation);
    assert!(matches!(
        decode_state_generation_v1(&Digest::sha256(&forged), &forged),
        Err(StateRecordError::InvalidState(_))
    ));
}

#[test]
fn reconciliation_requires_every_pairwise_kind_and_directory_mode_change() {
    let authority = DeploymentName::new("home").unwrap();
    let states = [
        StateTargetStateV1::File {
            file: Some(StateFileV1::new(Digest::sha256(b"file"), 4, 0o600).unwrap()),
        },
        StateTargetStateV1::Directory {
            directory: Some(StateDirectoryV1::new(0o750).unwrap()),
        },
        StateTargetStateV1::Symlink {
            symlink: Some(StateSymlinkV1::new(Digest::sha256(b"symlink"))),
        },
        StateTargetStateV1::Tree {
            tree: Some(StateTreeV1::new(Digest::sha256(b"tree"))),
        },
    ];
    for (from_index, from) in states.iter().enumerate() {
        for (to_index, to) in states.iter().enumerate() {
            if from_index == to_index {
                continue;
            }
            let previous = DesiredSnapshotV1::new(vec![
                StateTargetV1::new(authority.clone(), "managed", from.clone()).unwrap(),
            ])
            .unwrap();
            let next = reconcile_desired_snapshot_v1(
                Some(&previous),
                vec![StateTargetV1::new(authority.clone(), "managed", to.clone()).unwrap()],
            )
            .unwrap();
            assert_eq!(next.targets()[0].state(), to);
            let required = required_target_mutations_v1(
                Some((LifecycleStateV1::Enabled, &previous)),
                LifecycleStateV1::Enabled,
                &next,
            )
            .unwrap();
            assert_eq!(required.len(), 1, "{from_index} -> {to_index}");
            assert!(matches!(
                (&required[0], to),
                (
                    RequiredTargetMutationV1::PlaceFile { .. },
                    StateTargetStateV1::File { .. }
                ) | (
                    RequiredTargetMutationV1::EnsureDirectory { .. },
                    StateTargetStateV1::Directory { .. }
                ) | (
                    RequiredTargetMutationV1::PlaceSymlink { .. },
                    StateTargetStateV1::Symlink { .. }
                ) | (
                    RequiredTargetMutationV1::PlaceTree { .. },
                    StateTargetStateV1::Tree { .. }
                )
            ));
        }
    }

    let previous = DesiredSnapshotV1::new(vec![
        StateTargetV1::new(
            authority.clone(),
            "managed",
            StateTargetStateV1::Directory {
                directory: Some(StateDirectoryV1::new(0o750).unwrap()),
            },
        )
        .unwrap(),
    ])
    .unwrap();
    let next = reconcile_desired_snapshot_v1(
        Some(&previous),
        vec![
            StateTargetV1::new(
                authority,
                "managed",
                StateTargetStateV1::Directory {
                    directory: Some(StateDirectoryV1::new(0o700).unwrap()),
                },
            )
            .unwrap(),
        ],
    )
    .unwrap();
    assert!(matches!(
        required_target_mutations_v1(
            Some((LifecycleStateV1::Enabled, &previous)),
            LifecycleStateV1::Enabled,
            &next,
        )
        .unwrap()
        .as_slice(),
        [RequiredTargetMutationV1::EnsureDirectory { mode: 0o700, .. }]
    ));
}

#[test]
fn ownership_projection_rejects_exact_cross_namespace_conflicts() {
    let alpha = test_generation("alpha", vec![state_target("home", "config/file", true)]);
    let beta = test_generation("beta", vec![state_target("home", "config/file", true)]);

    assert_eq!(
        OwnershipProjectionV1::from_selected_generations([
            (beta.namespace(), &beta),
            (alpha.namespace(), &alpha),
        ])
        .unwrap_err(),
        OwnershipProjectionError::Conflict {
            overlap: OwnershipOverlapKindV1::Exact,
            authority: DeploymentName::new("home").unwrap(),
            first_namespace: NamespaceName::new("alpha").unwrap(),
            first_path: "config/file".to_owned(),
            second_namespace: NamespaceName::new("beta").unwrap(),
            second_path: "config/file".to_owned(),
        }
    );
}

#[test]
fn ownership_projection_rejects_ancestor_conflicts_in_both_directions_and_orders() {
    for (alpha_path, beta_path) in [("a", "a/b"), ("a/b", "a")] {
        let alpha = test_generation("alpha", vec![state_target("home", alpha_path, true)]);
        let beta = test_generation("beta", vec![state_target("home", beta_path, true)]);
        let forward = OwnershipProjectionV1::from_selected_generations([
            (alpha.namespace(), &alpha),
            (beta.namespace(), &beta),
        ])
        .unwrap_err();
        let reverse = OwnershipProjectionV1::from_selected_generations([
            (beta.namespace(), &beta),
            (alpha.namespace(), &alpha),
        ])
        .unwrap_err();

        assert_eq!(forward, reverse);
        assert!(matches!(
            forward,
            OwnershipProjectionError::Conflict {
                overlap: OwnershipOverlapKindV1::AncestorDescendant,
                first_path,
                second_path,
                ..
            } if first_path == "a" && second_path == "a/b"
        ));
    }
}

#[test]
fn ownership_projection_distinguishes_lexical_prefixes_and_authorities() {
    let alpha = test_generation("alpha", vec![state_target("home", "a", true)]);
    let beta = test_generation("beta", vec![state_target("home", "a-b", true)]);
    assert!(
        OwnershipProjectionV1::from_selected_generations([
            (alpha.namespace(), &alpha),
            (beta.namespace(), &beta),
        ])
        .is_ok()
    );

    let other_authority = test_generation("beta", vec![state_target("root", "a/b", true)]);
    assert!(
        OwnershipProjectionV1::from_selected_generations([
            (alpha.namespace(), &alpha),
            (other_authority.namespace(), &other_authority),
        ])
        .is_ok()
    );
}

#[test]
fn ownership_projection_detects_separator_masked_ancestor_conflicts() {
    let ancestor = test_generation("alpha", vec![state_target("home", "a", true)]);
    let lexical = test_generation("beta", vec![state_target("home", "a-b", true)]);
    let descendant = test_generation("gamma", vec![state_target("home", "a/b", true)]);

    assert!(matches!(
        OwnershipProjectionV1::from_selected_generations([
            (ancestor.namespace(), &ancestor),
            (lexical.namespace(), &lexical),
            (descendant.namespace(), &descendant),
        ]),
        Err(OwnershipProjectionError::Conflict {
            overlap: OwnershipOverlapKindV1::AncestorDescendant,
            first_namespace,
            second_namespace,
            ..
        }) if first_namespace.as_str() == "alpha" && second_namespace.as_str() == "gamma"
    ));
}

#[test]
fn ownership_projection_ignores_absent_tombstones() {
    let alpha = test_generation("alpha", vec![state_target("home", "shared", false)]);
    let beta = test_generation("beta", vec![state_target("home", "shared", true)]);
    let projection = OwnershipProjectionV1::from_selected_generations([
        (alpha.namespace(), &alpha),
        (beta.namespace(), &beta),
    ])
    .unwrap();

    assert_eq!(projection.claims().len(), 1);
    assert_eq!(
        projection.exact_owner(&DeploymentName::new("home").unwrap(), "shared"),
        Some(beta.namespace())
    );
}

#[test]
fn ownership_projection_does_not_follow_unselected_history() {
    let retained = test_generation("alpha", vec![state_target("home", "shared", true)]);
    let mut selected = test_generation("alpha", vec![state_target("home", "shared", false)]);
    selected.previous_generation = Some(state_generation_digest_v1(&retained));
    let beta = test_generation("beta", vec![state_target("home", "shared", true)]);

    let projection = OwnershipProjectionV1::from_selected_generations([
        (selected.namespace(), &selected),
        (beta.namespace(), &beta),
    ])
    .unwrap();
    assert_eq!(projection.claims().len(), 1);
    assert_eq!(projection.claims()[0].namespace(), beta.namespace());
}

#[test]
fn ownership_projection_rejects_namespace_generation_mismatches() {
    let generation = test_generation("generation", vec![state_target("home", "a", true)]);
    let selected = NamespaceName::new("selected").unwrap();

    assert_eq!(
        OwnershipProjectionV1::from_selected_generations([(&selected, &generation)]).unwrap_err(),
        OwnershipProjectionError::NamespaceMismatch {
            selected_namespace: selected,
            generation_namespace: NamespaceName::new("generation").unwrap(),
        }
    );
}

#[test]
fn ownership_projection_reports_a_deterministic_canonical_conflict() {
    let alpha = test_generation("alpha", vec![state_target("home", "a", true)]);
    let beta = test_generation("beta", vec![state_target("home", "a/b", true)]);
    let gamma = test_generation("gamma", vec![state_target("home", "z", true)]);
    let zeta = test_generation("zeta", vec![state_target("home", "z/child", true)]);

    let first = OwnershipProjectionV1::from_selected_generations([
        (zeta.namespace(), &zeta),
        (gamma.namespace(), &gamma),
        (beta.namespace(), &beta),
        (alpha.namespace(), &alpha),
    ])
    .unwrap_err();
    let second = OwnershipProjectionV1::from_selected_generations([
        (alpha.namespace(), &alpha),
        (beta.namespace(), &beta),
        (gamma.namespace(), &gamma),
        (zeta.namespace(), &zeta),
    ])
    .unwrap_err();

    assert_eq!(first, second);
    assert!(matches!(
        first,
        OwnershipProjectionError::Conflict {
            first_namespace,
            first_path,
            second_namespace,
            second_path,
            ..
        } if first_namespace.as_str() == "alpha"
            && first_path == "a"
            && second_namespace.as_str() == "beta"
            && second_path == "a/b"
    ));
}

#[test]
fn ownership_projection_exposes_canonical_claims_and_exact_lookup() {
    let alpha = test_generation(
        "alpha",
        vec![
            state_target("home", "zeta", true),
            state_target("home", "beta/child", true),
            state_target("home", "alpha", true),
        ],
    );
    let beta = test_generation("beta", vec![state_target("cache", "z", true)]);
    let projection = OwnershipProjectionV1::from_selected_generations([
        (alpha.namespace(), &alpha),
        (beta.namespace(), &beta),
    ])
    .unwrap();

    let claims = projection
        .claims()
        .iter()
        .map(|claim| {
            (
                claim.authority().as_str(),
                claim.relative_path(),
                claim.namespace().as_str(),
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(
        claims,
        vec![
            ("cache", "z", "beta"),
            ("home", "alpha", "alpha"),
            ("home", "beta/child", "alpha"),
            ("home", "zeta", "alpha"),
        ]
    );
    assert_eq!(
        projection.exact_owner(&DeploymentName::new("home").unwrap(), "beta/child"),
        Some(alpha.namespace())
    );
    assert_eq!(
        projection.exact_owner(&DeploymentName::new("home").unwrap(), "missing"),
        None
    );
}

#[test]
fn ownership_projection_finds_exact_ancestor_and_descendant_claims() {
    let owner = test_generation("alpha", vec![state_target("home", "a/b", true)]);
    let projection =
        OwnershipProjectionV1::from_selected_generations([(owner.namespace(), &owner)]).unwrap();
    let authority = DeploymentName::new("home").unwrap();
    let requester = NamespaceName::new("beta").unwrap();
    let expected = Some(&projection.claims()[0]);

    assert_eq!(
        projection.conflicting_claim(&authority, "a/b", &requester),
        expected
    );
    assert_eq!(
        projection.conflicting_claim(&authority, "a/b/c", &requester),
        expected
    );
    assert_eq!(
        projection.conflicting_claim(&authority, "a", &requester),
        expected
    );
}

#[test]
fn ownership_projection_conflict_query_respects_logical_boundaries() {
    let owner = test_generation(
        "alpha",
        vec![
            state_target("home", "a-b", true),
            state_target("home", "self", true),
            state_target("root", "authority", true),
        ],
    );
    let projection =
        OwnershipProjectionV1::from_selected_generations([(owner.namespace(), &owner)]).unwrap();
    let home = DeploymentName::new("home").unwrap();
    let requester = NamespaceName::new("beta").unwrap();

    assert_eq!(projection.conflicting_claim(&home, "a", &requester), None);
    assert_eq!(
        projection.conflicting_claim(&home, "self", owner.namespace()),
        None
    );
    assert_eq!(
        projection.conflicting_claim(&home, "authority", &requester),
        None
    );
}

#[test]
fn ownership_projection_conflict_query_selects_the_canonical_first_claim() {
    let alpha = test_generation("alpha", vec![state_target("home", "a/c", true)]);
    let zeta = test_generation("zeta", vec![state_target("home", "a/b", true)]);
    let first = OwnershipProjectionV1::from_selected_generations([
        (alpha.namespace(), &alpha),
        (zeta.namespace(), &zeta),
    ])
    .unwrap();
    let second = OwnershipProjectionV1::from_selected_generations([
        (zeta.namespace(), &zeta),
        (alpha.namespace(), &alpha),
    ])
    .unwrap();
    let authority = DeploymentName::new("home").unwrap();
    let requester = NamespaceName::new("requester").unwrap();

    let first_claim = first
        .conflicting_claim(&authority, "a", &requester)
        .unwrap();
    let second_claim = second
        .conflicting_claim(&authority, "a", &requester)
        .unwrap();
    assert_eq!(first_claim, second_claim);
    assert_eq!(first_claim.namespace(), zeta.namespace());
    assert_eq!(first_claim.relative_path(), "a/b");
}

#[test]
fn ownership_projection_enforces_the_global_present_claim_limit() {
    let repeated = state_target("home", "a", true);
    let mut full = test_generation("alpha", vec![]);
    full.desired_snapshot.0 = vec![repeated; MAX_OWNERSHIP_CLAIMS];
    let overflow = test_generation("beta", vec![state_target("home", "b", true)]);

    assert_eq!(
        OwnershipProjectionV1::from_selected_generations([
            (full.namespace(), &full),
            (overflow.namespace(), &overflow),
        ])
        .unwrap_err(),
        OwnershipProjectionError::TooManyClaims {
            limit: MAX_OWNERSHIP_CLAIMS,
            actual: MAX_OWNERSHIP_CLAIMS + 1,
        }
    );

    let authority_targets = (0..=MAX_OWNERSHIP_AUTHORITIES)
        .map(|index| state_target(&format!("authority-{index:02}"), "target", true))
        .collect();
    let authorities = test_generation("gamma", authority_targets);
    let forward = OwnershipProjectionV1::from_selected_generations([
        (full.namespace(), &full),
        (overflow.namespace(), &overflow),
        (authorities.namespace(), &authorities),
    ])
    .unwrap_err();
    let reverse = OwnershipProjectionV1::from_selected_generations([
        (authorities.namespace(), &authorities),
        (overflow.namespace(), &overflow),
        (full.namespace(), &full),
    ])
    .unwrap_err();
    assert_eq!(forward, reverse);
    assert!(matches!(
        forward,
        OwnershipProjectionError::TooManyClaims { .. }
    ));
}

#[test]
fn ownership_projection_bounds_absent_target_slots() {
    let absent = state_target("home", "a", false);
    let mut first = test_generation("alpha", vec![]);
    first.desired_snapshot.0 = vec![absent.clone(); MAX_DESIRED_TARGETS];
    let mut second = test_generation("beta", vec![]);
    second.desired_snapshot.0 = vec![absent; MAX_DESIRED_TARGETS];
    let overflow = test_generation("gamma", vec![state_target("home", "b", false)]);

    assert_eq!(
        OwnershipProjectionV1::from_selected_generations([
            (first.namespace(), &first),
            (second.namespace(), &second),
            (overflow.namespace(), &overflow),
        ])
        .unwrap_err(),
        OwnershipProjectionError::TooManyTargetSlots {
            limit: MAX_OWNERSHIP_TARGET_SLOTS,
            actual: MAX_OWNERSHIP_TARGET_SLOTS + 1,
        }
    );
}

#[test]
fn ownership_projection_bounds_selected_generations_and_rejects_duplicates() {
    let generation = test_generation("alpha", vec![]);
    let repeated = std::iter::repeat_n(
        (generation.namespace(), &generation),
        MAX_OWNERSHIP_GENERATIONS + 1,
    );
    assert_eq!(
        OwnershipProjectionV1::from_selected_generations(repeated).unwrap_err(),
        OwnershipProjectionError::TooManyGenerations {
            limit: MAX_OWNERSHIP_GENERATIONS,
            actual: MAX_OWNERSHIP_GENERATIONS + 1,
        }
    );

    assert_eq!(
        OwnershipProjectionV1::from_selected_generations([
            (generation.namespace(), &generation),
            (generation.namespace(), &generation),
        ])
        .unwrap_err(),
        OwnershipProjectionError::DuplicateNamespace(generation.namespace().clone())
    );
}

#[test]
fn ownership_projection_bounds_distinct_authorities() {
    let targets = (0..=MAX_OWNERSHIP_AUTHORITIES)
        .map(|index| state_target(&format!("authority-{index:02}"), "target", true))
        .collect();
    let generation = test_generation("alpha", targets);

    assert_eq!(
        OwnershipProjectionV1::from_selected_generations([(generation.namespace(), &generation,)])
            .unwrap_err(),
        OwnershipProjectionError::TooManyAuthorities {
            limit: MAX_OWNERSHIP_AUTHORITIES,
            actual: MAX_OWNERSHIP_AUTHORITIES + 1,
        }
    );
}
