use crate::MAX_OWNERSHIP_AUTHORITIES;
use crate::MAX_OWNERSHIP_CLAIMS;
use crate::MAX_OWNERSHIP_GENERATIONS;
use crate::MAX_OWNERSHIP_TARGET_SLOTS;
use crate::MAX_PREPARED_OPERATIONS;
use crate::prepared::ArchiveProvenanceV1;
use crate::prepared::LeafObservationV1;
use crate::prepared::PreparedArtifactV1;
use crate::prepared::PreparedOperationV1;
use crate::prepared::PreparedRecordV1;
use crate::prepared::validate_operation_semantics;
use crate::state::DesiredSnapshotV1;
use crate::state::StateGenerationV1;
use crate::state::StateRecordError;
use crate::state::StateTargetStateV1;
use crate::state::StateTargetV1;
use crate::state::prepared_error_as_state;
use crate::state::state_generation_digest_v1;
use crate::state::validate_state_generation;
use crate::state::validate_state_targets;
use crate::tracked_root::LifecycleStateV1;
use crate::tracked_root::PreparedTransitionV1;
use crate::tracked_root::RestorePointV1;
use crate::tracked_root::validate_restore_point;
use crate::tracked_root::validate_retention_authority;
use crate::tracked_root::validate_selected_restore_authority;
use crate::validate::append_text;
use crate::validate::compare_relative_paths;
use crate::validate::reject_destination_prefixes;
use crate::validate::reject_duplicates;
use crate::validate::relative_path_is_ancestor;
use malm_types::ArtifactId;
use malm_types::DeploymentName;
use malm_types::Digest;
use malm_types::NamespaceName;
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::fmt;

/// A present logical target claim in a transient ownership projection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OwnershipClaimV1 {
    namespace: NamespaceName,
    authority: DeploymentName,
    relative_path: String,
}

impl OwnershipClaimV1 {
    #[must_use]
    pub const fn namespace(&self) -> &NamespaceName {
        &self.namespace
    }
    #[must_use]
    pub const fn authority(&self) -> &DeploymentName {
        &self.authority
    }
    #[must_use]
    pub fn relative_path(&self) -> &str {
        &self.relative_path
    }
}

/// The relationship between two conflicting ownership claims.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OwnershipOverlapKindV1 {
    Exact,
    AncestorDescendant,
    PhysicalAuthorityAlias,
}

impl fmt::Display for OwnershipOverlapKindV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Exact => "exact",
            Self::AncestorDescendant => "ancestor/descendant",
            Self::PhysicalAuthorityAlias => "physical authority alias",
        })
    }
}

/// Read-only ownership derived from exactly the supplied selected generations.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OwnershipProjectionV1 {
    claims: Vec<OwnershipClaimV1>,
}

impl OwnershipProjectionV1 {
    /// Projects present claims from the selected generation snapshots.
    pub fn from_selected_generations<'a>(
        generations: impl IntoIterator<Item = (&'a NamespaceName, &'a StateGenerationV1)>,
    ) -> Result<Self, OwnershipProjectionError> {
        let mut selected_generations: Vec<(&NamespaceName, &StateGenerationV1)> = Vec::new();
        for generation in generations {
            if selected_generations.len() == MAX_OWNERSHIP_GENERATIONS {
                return Err(OwnershipProjectionError::TooManyGenerations {
                    limit: MAX_OWNERSHIP_GENERATIONS,
                    actual: MAX_OWNERSHIP_GENERATIONS + 1,
                });
            }
            selected_generations.push(generation);
        }
        let mut claims = Vec::new();
        let mut mismatch = None;
        let mut namespaces = BTreeSet::new();
        let mut duplicate_namespace = None;
        let mut target_slots = 0_usize;

        for &(selected_namespace, generation) in &selected_generations {
            if selected_namespace != generation.namespace() {
                let candidate = (selected_namespace.clone(), generation.namespace().clone());
                if mismatch.as_ref().is_none_or(|current| &candidate < current) {
                    mismatch = Some(candidate);
                }
            }
            if !namespaces.insert(selected_namespace)
                && duplicate_namespace
                    .as_ref()
                    .is_none_or(|current| selected_namespace < current)
            {
                duplicate_namespace = Some(selected_namespace.clone());
            }
            target_slots = target_slots.saturating_add(generation.targets().len());
        }

        if let Some((selected_namespace, generation_namespace)) = mismatch {
            return Err(OwnershipProjectionError::NamespaceMismatch {
                selected_namespace,
                generation_namespace,
            });
        }
        if let Some(namespace) = duplicate_namespace {
            return Err(OwnershipProjectionError::DuplicateNamespace(namespace));
        }
        if target_slots > MAX_OWNERSHIP_TARGET_SLOTS {
            return Err(OwnershipProjectionError::TooManyTargetSlots {
                limit: MAX_OWNERSHIP_TARGET_SLOTS,
                actual: target_slots,
            });
        }

        let mut present_claims = 0_usize;
        let mut authorities = BTreeSet::new();
        let mut too_many_authorities = false;
        for (_, generation) in &selected_generations {
            if !generation.lifecycle_state().is_enabled() {
                continue;
            }
            for target in generation
                .targets()
                .iter()
                .filter(|target| target.is_present())
            {
                present_claims = present_claims.saturating_add(1);
                if !authorities.contains(target.authority()) {
                    if authorities.len() == MAX_OWNERSHIP_AUTHORITIES {
                        too_many_authorities = true;
                    } else {
                        authorities.insert(target.authority());
                    }
                }
            }
        }
        if present_claims > MAX_OWNERSHIP_CLAIMS {
            return Err(OwnershipProjectionError::TooManyClaims {
                limit: MAX_OWNERSHIP_CLAIMS,
                actual: present_claims,
            });
        }
        if too_many_authorities {
            return Err(OwnershipProjectionError::TooManyAuthorities {
                limit: MAX_OWNERSHIP_AUTHORITIES,
                actual: MAX_OWNERSHIP_AUTHORITIES + 1,
            });
        }

        claims.reserve(present_claims);
        for (selected_namespace, generation) in selected_generations {
            if !generation.lifecycle_state().is_enabled() {
                continue;
            }
            for target in generation
                .targets()
                .iter()
                .filter(|target| target.is_present())
            {
                claims.push(OwnershipClaimV1 {
                    namespace: selected_namespace.clone(),
                    authority: target.authority().clone(),
                    relative_path: target.relative_path().to_owned(),
                });
            }
        }

        claims.sort_by(|left, right| {
            left.authority
                .cmp(&right.authority)
                .then_with(|| compare_relative_paths(&left.relative_path, &right.relative_path))
                .then_with(|| left.namespace.cmp(&right.namespace))
        });

        let mut ancestors = Vec::<usize>::with_capacity(64);
        for current_index in 0..claims.len() {
            let current = &claims[current_index];
            if ancestors
                .last()
                .is_some_and(|&index| claims[index].authority != current.authority)
            {
                ancestors.clear();
            }
            while let Some(&previous_index) = ancestors.last() {
                let previous_path = &claims[previous_index].relative_path;
                if previous_path == &current.relative_path
                    || relative_path_is_ancestor(previous_path, &current.relative_path)
                {
                    break;
                }
                ancestors.pop();
            }

            if let Some(&conflicting_index) = ancestors
                .iter()
                .rev()
                .find(|&&index| claims[index].namespace != current.namespace)
            {
                let conflicting = &claims[conflicting_index];
                let overlap = if conflicting.relative_path == current.relative_path {
                    OwnershipOverlapKindV1::Exact
                } else {
                    OwnershipOverlapKindV1::AncestorDescendant
                };
                return Err(OwnershipProjectionError::Conflict {
                    overlap,
                    authority: current.authority.clone(),
                    first_namespace: conflicting.namespace.clone(),
                    first_path: conflicting.relative_path.clone(),
                    second_namespace: current.namespace.clone(),
                    second_path: current.relative_path.clone(),
                });
            }

            if ancestors
                .last()
                .is_none_or(|&index| claims[index].relative_path != current.relative_path)
            {
                ancestors.push(current_index);
            }
        }

        Ok(Self { claims })
    }

    /// Returns claims in canonical authority, component-path, namespace order.
    #[must_use]
    pub fn claims(&self) -> &[OwnershipClaimV1] {
        &self.claims
    }

    /// Returns the namespace owning exactly `authority` and `relative_path`.
    #[must_use]
    pub fn exact_owner(
        &self,
        authority: &DeploymentName,
        relative_path: &str,
    ) -> Option<&NamespaceName> {
        let claim = self
            .claims
            .get(self.claim_lower_bound(authority, relative_path))?;
        (claim.authority() == authority && claim.relative_path() == relative_path)
            .then_some(claim.namespace())
    }

    /// Returns the canonical first claim by another namespace that overlaps a path.
    /// Overlap uses slash-delimited components, not lexical string prefixes.
    #[must_use]
    pub fn conflicting_claim(
        &self,
        authority: &DeploymentName,
        relative_path: &str,
        requesting_namespace: &NamespaceName,
    ) -> Option<&OwnershipClaimV1> {
        for (separator, _) in relative_path.match_indices('/') {
            let ancestor_path = &relative_path[..separator];
            let start = self.claim_lower_bound(authority, ancestor_path);
            for claim in &self.claims[start..] {
                if claim.authority() != authority || claim.relative_path() != ancestor_path {
                    break;
                }
                if claim.namespace() != requesting_namespace {
                    return Some(claim);
                }
            }
        }

        let start = self.claim_lower_bound(authority, relative_path);
        for claim in &self.claims[start..] {
            if claim.authority() != authority {
                break;
            }
            if claim.relative_path() == relative_path {
                if claim.namespace() != requesting_namespace {
                    return Some(claim);
                }
                continue;
            }
            if !relative_path_is_ancestor(relative_path, claim.relative_path()) {
                break;
            }
            if claim.namespace() != requesting_namespace {
                return Some(claim);
            }
        }
        None
    }

    fn claim_lower_bound(&self, authority: &DeploymentName, relative_path: &str) -> usize {
        self.claims.partition_point(|claim| {
            claim
                .authority
                .cmp(authority)
                .then_with(|| compare_relative_paths(&claim.relative_path, relative_path))
                .is_lt()
        })
    }
}

/// Failure to derive a bounded, conflict-free ownership projection.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
#[non_exhaustive]
pub enum OwnershipProjectionError {
    #[error("ownership generation count {actual} exceeds limit {limit}")]
    TooManyGenerations { limit: usize, actual: usize },
    #[error("duplicate selected ownership namespace {0}")]
    DuplicateNamespace(NamespaceName),
    #[error("ownership authority count {actual} exceeds limit {limit}")]
    TooManyAuthorities { limit: usize, actual: usize },
    #[error("ownership target-slot count {actual} exceeds limit {limit}")]
    TooManyTargetSlots { limit: usize, actual: usize },
    #[error(
        "selected namespace {selected_namespace} differs from generation namespace {generation_namespace}"
    )]
    NamespaceMismatch {
        selected_namespace: NamespaceName,
        generation_namespace: NamespaceName,
    },
    #[error("ownership claim count {actual} exceeds limit {limit}")]
    TooManyClaims { limit: usize, actual: usize },
    #[error(
        "ownership conflict ({overlap}) for authority {authority}: namespace {first_namespace} path {first_path:?} overlaps namespace {second_namespace} path {second_path:?}"
    )]
    Conflict {
        overlap: OwnershipOverlapKindV1,
        authority: DeploymentName,
        first_namespace: NamespaceName,
        first_path: String,
        second_namespace: NamespaceName,
        second_path: String,
    },
}

/// A filesystem mutation required by two desired and lifecycle states.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RequiredTargetMutationV1 {
    EnsureDirectory {
        authority: DeploymentName,
        relative_path: String,
        mode: u32,
    },
    PlaceFile {
        authority: DeploymentName,
        relative_path: String,
        digest: Digest,
        byte_len: u64,
        mode: u32,
    },
    PlaceSymlink {
        authority: DeploymentName,
        relative_path: String,
        object: Digest,
    },
    PlaceTree {
        authority: DeploymentName,
        relative_path: String,
        tree: Digest,
        archive_provenance: Option<ArchiveProvenanceV1>,
    },
    RemoveLeaf {
        authority: DeploymentName,
        relative_path: String,
    },
    AssertExact {
        authority: DeploymentName,
        relative_path: String,
        state: StateTargetStateV1,
    },
}

impl RequiredTargetMutationV1 {
    #[must_use]
    pub const fn authority(&self) -> &DeploymentName {
        match self {
            Self::EnsureDirectory { authority, .. }
            | Self::PlaceFile { authority, .. }
            | Self::PlaceSymlink { authority, .. }
            | Self::PlaceTree { authority, .. }
            | Self::RemoveLeaf { authority, .. }
            | Self::AssertExact { authority, .. } => authority,
        }
    }

    #[must_use]
    pub fn relative_path(&self) -> &str {
        match self {
            Self::EnsureDirectory { relative_path, .. }
            | Self::PlaceFile { relative_path, .. }
            | Self::PlaceSymlink { relative_path, .. }
            | Self::PlaceTree { relative_path, .. }
            | Self::RemoveLeaf { relative_path, .. }
            | Self::AssertExact { relative_path, .. } => relative_path,
        }
    }
}

/// Merges a newly evaluated declaration set with cumulative predecessor tombstones.
pub fn reconcile_desired_snapshot_v1(
    previous: Option<&DesiredSnapshotV1>,
    declared_targets: Vec<StateTargetV1>,
) -> Result<DesiredSnapshotV1, StateRecordError> {
    if let Some(previous) = previous {
        validate_state_targets(previous.targets())?;
    }
    let declared = DesiredSnapshotV1::new(declared_targets)?;
    let mut targets = previous
        .map(DesiredSnapshotV1::targets)
        .unwrap_or_default()
        .to_vec();
    for target in &mut targets {
        target.state = absent_target_state(&target.state);
    }
    for target in declared.0 {
        let key = (target.authority(), target.relative_path());
        match targets.binary_search_by(|candidate| {
            (candidate.authority(), candidate.relative_path()).cmp(&key)
        }) {
            Ok(index) => targets[index] = target,
            Err(index) => targets.insert(index, target),
        }
    }
    DesiredSnapshotV1::new(targets)
}

/// Returns the complete canonical effective mutation set for a lifecycle transition.
pub fn required_target_mutations_v1(
    previous: Option<(LifecycleStateV1, &DesiredSnapshotV1)>,
    next_lifecycle: LifecycleStateV1,
    next: &DesiredSnapshotV1,
) -> Result<Vec<RequiredTargetMutationV1>, StateRecordError> {
    validate_state_targets(next.targets())?;
    if let Some((_, previous)) = previous {
        validate_state_targets(previous.targets())?;
    }

    let mut mutations = Vec::new();
    let mut keys = BTreeSet::new();
    if let Some((_, snapshot)) = previous {
        keys.extend(snapshot.targets().iter().map(|target| {
            (
                target.authority().clone(),
                target.relative_path().to_owned(),
            )
        }));
    }
    keys.extend(next.targets().iter().map(|target| {
        (
            target.authority().clone(),
            target.relative_path().to_owned(),
        )
    }));
    for (authority, relative_path) in keys.iter().cloned() {
        let previous_target = previous.and_then(|(_, snapshot)| {
            snapshot
                .targets()
                .binary_search_by(|candidate| {
                    (candidate.authority(), candidate.relative_path())
                        .cmp(&(&authority, relative_path.as_str()))
                })
                .ok()
                .map(|index| &snapshot.targets()[index])
        });
        let next_target = next
            .targets()
            .binary_search_by(|candidate| {
                (candidate.authority(), candidate.relative_path())
                    .cmp(&(&authority, relative_path.as_str()))
            })
            .ok()
            .map(|index| &next.targets()[index]);
        let reference_state = next_target
            .map(StateTargetV1::state)
            .or_else(|| previous_target.map(StateTargetV1::state))
            .expect("a union target key has a state");
        let before = match (previous, previous_target) {
            (Some((lifecycle, _)), Some(previous_target)) if lifecycle.is_enabled() => {
                previous_target.state.clone()
            }
            _ => absent_target_state(reference_state),
        };
        let after = match (next_lifecycle.is_enabled(), next_target) {
            (true, Some(target)) => target.state.clone(),
            _ => absent_target_state(reference_state),
        };
        // Do not remove a managed directory while it has managed descendants.
        // Remove the descendants and release ownership, but leave the container
        // because it may hold user files. A later transition can remove it once
        // no effective descendants remain.
        let releases_structural_directory = matches!(
            &before,
            StateTargetStateV1::Directory { directory: Some(_) }
        ) && !state_is_present(&after)
            && keys.iter().any(|(candidate_authority, candidate_path)| {
                candidate_authority == &authority
                    && relative_path_is_ancestor(&relative_path, candidate_path)
                    && (effective_target_is_present(
                        previous,
                        (candidate_authority.as_str(), candidate_path.as_str()),
                    ) || effective_target_is_present(
                        Some((next_lifecycle, next)),
                        (candidate_authority.as_str(), candidate_path.as_str()),
                    ))
            });
        if releases_structural_directory {
            continue;
        }
        if before == after {
            if state_is_present(&after) {
                mutations.push(RequiredTargetMutationV1::AssertExact {
                    authority,
                    relative_path,
                    state: after,
                });
            }
            continue;
        }
        let mutation = match after {
            StateTargetStateV1::File { file: Some(file) } => RequiredTargetMutationV1::PlaceFile {
                authority: authority.clone(),
                relative_path: relative_path.clone(),
                digest: file.digest,
                byte_len: file.byte_len,
                mode: file.mode,
            },
            StateTargetStateV1::Directory {
                directory: Some(directory),
            } => RequiredTargetMutationV1::EnsureDirectory {
                authority: authority.clone(),
                relative_path: relative_path.clone(),
                mode: directory.mode,
            },
            StateTargetStateV1::Symlink {
                symlink: Some(symlink),
            } => RequiredTargetMutationV1::PlaceSymlink {
                authority: authority.clone(),
                relative_path: relative_path.clone(),
                object: symlink.object,
            },
            StateTargetStateV1::Tree { tree: Some(tree) } => RequiredTargetMutationV1::PlaceTree {
                authority: authority.clone(),
                relative_path: relative_path.clone(),
                tree: tree.tree,
                archive_provenance: tree.archive_provenance,
            },
            StateTargetStateV1::File { file: None }
            | StateTargetStateV1::Directory { directory: None }
            | StateTargetStateV1::Symlink { symlink: None }
            | StateTargetStateV1::Tree { tree: None } => {
                if !state_is_present(&before) {
                    return Err(StateRecordError::InvalidState(
                        "an absent desired target cannot require removal".to_owned(),
                    ));
                }
                RequiredTargetMutationV1::RemoveLeaf {
                    authority,
                    relative_path,
                }
            }
        };
        mutations.push(mutation);
    }
    Ok(mutations)
}

/// Validates a complete operation manifest against exact lifecycle and desired states.
pub fn validate_operation_manifest_v1(
    previous: Option<(LifecycleStateV1, &DesiredSnapshotV1)>,
    next_lifecycle: LifecycleStateV1,
    next: &DesiredSnapshotV1,
    artifacts: &[PreparedArtifactV1],
    operations: &[PreparedOperationV1],
) -> Result<(), StateRecordError> {
    if operations.len() > MAX_PREPARED_OPERATIONS {
        return Err(StateRecordError::InvalidState(format!(
            "operation count {} exceeds limit {MAX_PREPARED_OPERATIONS}",
            operations.len()
        )));
    }
    reject_duplicates(
        "operation destination",
        operations.iter().map(|operation| {
            (
                operation.observation().authority().as_str(),
                operation.observation().relative_path(),
            )
        }),
    )
    .map_err(prepared_error_as_state)?;
    reject_destination_prefixes(operations).map_err(prepared_error_as_state)?;
    for operation in operations {
        validate_operation_semantics(operation).map_err(prepared_error_as_state)?;
    }

    let required = required_target_mutations_v1(previous, next_lifecycle, next)?;
    let required_by_destination = required
        .iter()
        .map(|mutation| {
            (
                (mutation.authority().as_str(), mutation.relative_path()),
                mutation,
            )
        })
        .collect::<BTreeMap<_, _>>();
    let artifact_count = artifacts.len();
    let artifacts = artifacts
        .iter()
        .map(|artifact| (artifact.id(), artifact))
        .collect::<BTreeMap<_, _>>();
    if artifacts.len() != artifact_count {
        return Err(StateRecordError::InvalidState(
            "operation manifest artifact identifiers must be unique".to_owned(),
        ));
    }
    let mut satisfied = BTreeSet::new();

    for operation in operations {
        let observation = operation.observation();
        let key = (
            observation.authority().as_str(),
            observation.relative_path(),
        );
        if matches!(operation, PreparedOperationV1::AssertAbsent { .. }) {
            if effective_target_is_present(previous, key)
                || effective_target_is_present(Some((next_lifecycle, next)), key)
            {
                return Err(StateRecordError::InvalidState(format!(
                    "absence assertion conflicts with effective desired target {}:{}",
                    key.0, key.1
                )));
            }
            continue;
        }
        let required = required_by_destination.get(&key).ok_or_else(|| {
            StateRecordError::InvalidState(format!(
                "operation at {}:{} is not required by the lifecycle transition",
                key.0, key.1
            ))
        })?;
        validate_required_operation(
            required,
            operation,
            effective_target_is_present(previous, key),
            matches!(required, RequiredTargetMutationV1::EnsureDirectory { .. })
                && operations.iter().any(|candidate| {
                    candidate.observation().authority() == operation.observation().authority()
                        && relative_path_is_ancestor(
                            operation.observation().relative_path(),
                            candidate.observation().relative_path(),
                        )
                }),
            &artifacts,
        )?;
        satisfied.insert(key);
    }

    if let Some(missing) = required.iter().find(|mutation| {
        !satisfied.contains(&(mutation.authority().as_str(), mutation.relative_path()))
    }) {
        return Err(StateRecordError::InvalidState(format!(
            "operation manifest omits required mutation at {}:{}",
            missing.authority(),
            missing.relative_path()
        )));
    }
    Ok(())
}

/// Attests a prepared record against its exact predecessor generation.
pub fn validate_prepared_transition_v1(
    previous: Option<&StateGenerationV1>,
    prepared: &PreparedRecordV1,
) -> Result<(), StateRecordError> {
    match (previous, prepared.expected_head()) {
        (None, None) => {}
        (None, Some(_)) => {
            return Err(StateRecordError::InvalidState(
                "prepared transition names a predecessor but none was supplied".to_owned(),
            ));
        }
        (Some(_), None) => {
            return Err(StateRecordError::InvalidState(
                "prepared transition omits its supplied predecessor".to_owned(),
            ));
        }
        (Some(previous), Some(expected)) => {
            validate_state_generation(previous)?;
            if previous.namespace() != prepared.namespace() {
                return Err(StateRecordError::InvalidState(
                    "prepared transition crosses namespace history".to_owned(),
                ));
            }
            if state_generation_digest_v1(previous) != *expected {
                return Err(StateRecordError::InvalidState(
                    "prepared transition predecessor digest differs from supplied generation"
                        .to_owned(),
                ));
            }
        }
    }
    validate_state_targets(prepared.desired_snapshot.targets())?;
    if let Some(restore_point) = prepared.restore_point() {
        validate_restore_point(restore_point, Some(prepared.namespace()))
            .map_err(prepared_error_as_state)?;
    }
    validate_retention_authority(prepared.retention_authority(), Some(prepared.namespace()))
        .map_err(prepared_error_as_state)?;
    if !matches!(
        prepared.transition(),
        PreparedTransitionV1::NamespaceRemoval { .. }
    ) {
        validate_selected_restore_authority(
            prepared.lifecycle_state(),
            prepared.restore_point(),
            prepared.retention_authority(),
        )
        .map_err(prepared_error_as_state)?;
    }
    let digest = desired_snapshot_digest_v1(prepared.namespace(), prepared.desired_snapshot());
    if digest != *prepared.desired_snapshot_digest() {
        return Err(StateRecordError::InvalidState(
            "prepared desired-snapshot digest differs from its complete snapshot".to_owned(),
        ));
    }
    validate_prepared_transition_kind(previous, prepared)?;
    validate_operation_manifest_v1(
        previous.map(|generation| (generation.lifecycle_state(), generation.desired_snapshot())),
        prepared.lifecycle_state(),
        prepared.desired_snapshot(),
        prepared.artifacts(),
        prepared.operations(),
    )
}

fn validate_prepared_transition_kind(
    previous: Option<&StateGenerationV1>,
    prepared: &PreparedRecordV1,
) -> Result<(), StateRecordError> {
    let invalid = |reason: &str| StateRecordError::InvalidState(reason.to_owned());
    match prepared.transition() {
        PreparedTransitionV1::Reconcile => {
            if prepared.lifecycle_state() != LifecycleStateV1::Enabled
                || prepared.restore_point().is_some()
            {
                return Err(invalid(
                    "reconciliation must publish an enabled generation without a selected restore point",
                ));
            }
        }
        PreparedTransitionV1::Disable => {
            let previous = previous.ok_or_else(|| invalid("disable requires a predecessor"))?;
            if previous.lifecycle_state() != LifecycleStateV1::Enabled
                || prepared.lifecycle_state() != LifecycleStateV1::Disabled
                || !prepared.desired_snapshot().is_empty()
                || prepared.tracked_root().is_some()
            {
                return Err(invalid(
                    "disable must transition enabled state to a disabled empty snapshot with tracking held only by its restore point",
                ));
            }
            let point = prepared
                .restore_point()
                .ok_or_else(|| invalid("disable requires an explicit restore point"))?;
            validate_restore_point_generation(point, previous)?;
            if !prepared
                .retention_authority()
                .restore_points()
                .contains(point)
            {
                return Err(invalid(
                    "disable restore point must be retained by the next authority",
                ));
            }
        }
        PreparedTransitionV1::Enable { restore_point } => {
            let previous = previous.ok_or_else(|| invalid("enable requires a predecessor"))?;
            if previous.lifecycle_state() != LifecycleStateV1::Disabled
                || previous.restore_point() != Some(restore_point.as_ref())
                || restore_point.lifecycle() != LifecycleStateV1::Enabled
                || prepared.lifecycle_state() != LifecycleStateV1::Enabled
                || prepared.restore_point().is_some()
                || prepared.desired_snapshot_digest() != restore_point.desired_snapshot_digest()
                || prepared.tracked_root() != restore_point.tracked_root()
            {
                return Err(invalid(
                    "enable must exactly restore the selected disabled generation's enabled restore point",
                ));
            }
        }
        PreparedTransitionV1::Checkout { .. } => {
            if previous.is_none() {
                return Err(invalid("checkout must append from a selected current head"));
            }
        }
        PreparedTransitionV1::RetentionAuthority => {
            let previous = previous
                .ok_or_else(|| invalid("retention-authority update requires a predecessor"))?;
            if prepared.lifecycle_state() != previous.lifecycle_state()
                || prepared.restore_point() != previous.restore_point()
                || prepared.tracked_root() != previous.tracked_root()
                || prepared.desired_snapshot() != previous.desired_snapshot()
            {
                return Err(invalid(
                    "retention-authority update cannot change selected lifecycle state",
                ));
            }
        }
        PreparedTransitionV1::NamespaceRemoval { .. } => {
            let previous = previous
                .ok_or_else(|| invalid("namespace removal requires a selected predecessor"))?;
            if prepared.lifecycle_state() != LifecycleStateV1::Disabled
                || !prepared.desired_snapshot().is_empty()
                || prepared.restore_point().is_some()
                || prepared.tracked_root().is_some()
                || prepared.retention_authority() != previous.retention_authority()
            {
                return Err(invalid(
                    "namespace removal must reconcile to empty state and explicitly drop the prior authority",
                ));
            }
        }
    }
    Ok(())
}

fn validate_restore_point_generation(
    point: &RestorePointV1,
    generation: &StateGenerationV1,
) -> Result<(), StateRecordError> {
    if point.namespace() != generation.namespace()
        || point.generation() != &state_generation_digest_v1(generation)
        || point.lifecycle() != generation.lifecycle_state()
        || point.desired_snapshot_digest() != generation.desired_snapshot_digest()
        || point.tracked_root() != generation.tracked_root()
    {
        return Err(StateRecordError::InvalidState(
            "restore point does not identify the exact referenced generation state".to_owned(),
        ));
    }
    Ok(())
}

/// Computes the domain-separated identity of a complete desired snapshot.
#[must_use]
pub fn desired_snapshot_digest_v1(
    namespace: &NamespaceName,
    snapshot: &DesiredSnapshotV1,
) -> Digest {
    let mut bytes = b"malm-desired-snapshot-v1\0".to_vec();
    append_text(&mut bytes, namespace.as_str());
    let encoded = serde_json::to_vec(snapshot).expect("validated desired snapshots serialize");
    bytes.extend_from_slice(
        &u64::try_from(encoded.len())
            .expect("bounded desired snapshots fit in u64")
            .to_be_bytes(),
    );
    bytes.extend_from_slice(&encoded);
    Digest::sha256(bytes)
}

fn absent_target_state(state: &StateTargetStateV1) -> StateTargetStateV1 {
    match state {
        StateTargetStateV1::File { .. } => StateTargetStateV1::File { file: None },
        StateTargetStateV1::Directory { .. } => StateTargetStateV1::Directory { directory: None },
        StateTargetStateV1::Symlink { .. } => StateTargetStateV1::Symlink { symlink: None },
        StateTargetStateV1::Tree { .. } => StateTargetStateV1::Tree { tree: None },
    }
}

pub(crate) fn state_is_present(state: &StateTargetStateV1) -> bool {
    match state {
        StateTargetStateV1::File { file } => file.is_some(),
        StateTargetStateV1::Directory { directory } => directory.is_some(),
        StateTargetStateV1::Symlink { symlink } => symlink.is_some(),
        StateTargetStateV1::Tree { tree } => tree.is_some(),
    }
}

fn effective_target_is_present(
    state: Option<(LifecycleStateV1, &DesiredSnapshotV1)>,
    key: (&str, &str),
) -> bool {
    let Some((lifecycle, snapshot)) = state else {
        return false;
    };
    if !lifecycle.is_enabled() {
        return false;
    }
    snapshot
        .targets()
        .binary_search_by(|target| (target.authority().as_str(), target.relative_path()).cmp(&key))
        .is_ok_and(|index| snapshot.targets()[index].is_present())
}

fn validate_required_operation(
    required: &RequiredTargetMutationV1,
    operation: &PreparedOperationV1,
    before_present: bool,
    structural_directory: bool,
    artifacts: &BTreeMap<&ArtifactId, &PreparedArtifactV1>,
) -> Result<(), StateRecordError> {
    let observed_present = matches!(
        operation.observation().leaf(),
        LeafObservationV1::Present(_)
    );
    let observation_matches_before = observed_present == before_present;
    // A placement's `replace_existing` flag must match whether the observed
    // leaf is present. This permits matching state, adoption of an unowned leaf
    // with the required replace-existing finding, and recreation of a deleted
    // managed leaf with an advisory restore-missing finding.
    let valid = match (required, operation) {
        (
            RequiredTargetMutationV1::EnsureDirectory { mode: required, .. },
            PreparedOperationV1::EnsureDirectory { mode, .. },
        ) => mode == required && observation_matches_before,
        (
            RequiredTargetMutationV1::EnsureDirectory { mode: required, .. },
            PreparedOperationV1::AssertExact {
                state:
                    StateTargetStateV1::Directory {
                        directory: Some(directory),
                    },
                ..
            },
        ) => {
            !before_present
                && observed_present
                && structural_directory
                && directory.mode == *required
        }
        (
            RequiredTargetMutationV1::PlaceFile {
                digest,
                byte_len,
                mode: required_mode,
                ..
            },
            PreparedOperationV1::PlaceFile {
                artifact_id,
                mode,
                replace_existing,
                ..
            },
        ) => {
            let artifact = artifacts.get(artifact_id).ok_or_else(|| {
                StateRecordError::InvalidState(format!(
                    "operation references unknown artifact {artifact_id}"
                ))
            })?;
            artifact.digest() == digest
                && artifact.byte_len() == *byte_len
                && mode == required_mode
                && *replace_existing == observed_present
        }
        (
            RequiredTargetMutationV1::PlaceSymlink {
                object: required, ..
            },
            PreparedOperationV1::PlaceSymlink {
                object,
                replace_existing,
                ..
            },
        ) => object == required && *replace_existing == observed_present,
        (
            RequiredTargetMutationV1::PlaceTree {
                tree: required_tree,
                archive_provenance: required_provenance,
                ..
            },
            PreparedOperationV1::PlaceTree {
                tree,
                archive_provenance,
                replace_existing,
                ..
            },
        ) => {
            tree == required_tree
                && archive_provenance == required_provenance
                && *replace_existing == observed_present
        }
        (RequiredTargetMutationV1::RemoveLeaf { .. }, PreparedOperationV1::RemoveLeaf { .. }) => {
            before_present
        }
        (
            RequiredTargetMutationV1::AssertExact {
                state: required, ..
            },
            PreparedOperationV1::AssertExact { state, .. },
        ) => before_present && observation_matches_before && state == required,
        // A drifted asserted target may be restored with a placement whose
        // content matches the asserted state. Restoring a locally modified leaf
        // requires the approval-bearing restore-modified finding. Restoring a
        // deleted managed leaf uses a plain placement and the advisory
        // restore-missing finding because it destroys no existing content.
        (
            RequiredTargetMutationV1::AssertExact {
                state: StateTargetStateV1::File { file: Some(file) },
                ..
            },
            PreparedOperationV1::PlaceFile {
                artifact_id,
                mode,
                replace_existing,
                ..
            },
        ) => {
            let artifact = artifacts.get(artifact_id).ok_or_else(|| {
                StateRecordError::InvalidState(format!(
                    "operation references unknown artifact {artifact_id}"
                ))
            })?;
            before_present
                && *replace_existing == observed_present
                && artifact.digest() == file.digest()
                && artifact.byte_len() == file.byte_len()
                && *mode == file.mode()
        }
        (
            RequiredTargetMutationV1::AssertExact {
                state:
                    StateTargetStateV1::Symlink {
                        symlink: Some(symlink),
                    },
                ..
            },
            PreparedOperationV1::PlaceSymlink {
                object,
                replace_existing,
                ..
            },
        ) => before_present && !observed_present && !*replace_existing && *object == symlink.object,
        (
            RequiredTargetMutationV1::AssertExact {
                state: StateTargetStateV1::Tree { tree: Some(tree) },
                ..
            },
            PreparedOperationV1::PlaceTree {
                tree: placed_tree,
                archive_provenance,
                replace_existing,
                ..
            },
        ) => {
            before_present
                && !observed_present
                && !*replace_existing
                && *placed_tree == tree.tree
                && *archive_provenance == tree.archive_provenance
        }
        (
            RequiredTargetMutationV1::AssertExact {
                state:
                    StateTargetStateV1::Directory {
                        directory: Some(directory),
                    },
                ..
            },
            PreparedOperationV1::EnsureDirectory { mode, .. },
        ) => before_present && !observed_present && *mode == directory.mode,
        _ => false,
    };
    if !valid {
        return Err(StateRecordError::InvalidState(format!(
            "operation at {}:{} does not match its required lifecycle mutation",
            required.authority(),
            required.relative_path()
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests;
