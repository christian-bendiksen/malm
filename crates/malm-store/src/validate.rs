use crate::MAX_TRANSFORM_DIAGNOSTIC_NOTES;
use crate::MAX_TRANSFORM_DIAGNOSTIC_TEXT_BYTES;
use crate::MAX_TRANSFORM_DIAGNOSTICS;
use crate::MAX_TRANSFORM_RESOURCES;
use crate::prepared::PreparedOperationV1;
use crate::prepared::PreparedRecordError;
use crate::prepared::TransformDiagnosticV1;
use crate::prepared::TransformResourceV1;
use crate::state::StateTargetStateV1;
use malm_types::serde_util::bounded_seq;
use std::collections::BTreeSet;

pub(crate) fn append_text(bytes: &mut Vec<u8>, value: &str) {
    bytes.extend_from_slice(
        &u64::try_from(value.len())
            .expect("bounded text lengths fit in u64")
            .to_be_bytes(),
    );
    bytes.extend_from_slice(value.as_bytes());
}

pub(crate) fn validate_label(field: &'static str, value: &str) -> Result<(), PreparedRecordError> {
    malm_types::validate_label(field, value).map_err(Into::into)
}

pub(crate) fn validate_text(
    field: &'static str,
    value: &str,
    limit: usize,
) -> Result<(), PreparedRecordError> {
    malm_types::validate_text(field, value, limit).map_err(Into::into)
}

pub(crate) fn validate_relative_path(value: &str) -> Result<(), PreparedRecordError> {
    malm_types::validate_relative_path(value).map_err(Into::into)
}

pub(crate) fn validate_diagnostic_code(value: &str) -> Result<(), PreparedRecordError> {
    malm_types::validate_diagnostic_code(value).map_err(Into::into)
}

pub(crate) fn validate_diagnostic_text(
    field: &'static str,
    value: &str,
) -> Result<(), PreparedRecordError> {
    check_limit(field, value.len(), MAX_TRANSFORM_DIAGNOSTIC_TEXT_BYTES)
}

pub(crate) fn deserialize_transform_resources<'de, D>(
    deserializer: D,
) -> Result<Vec<TransformResourceV1>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    bounded_seq(deserializer, MAX_TRANSFORM_RESOURCES, "transform resources")
}

pub(crate) fn deserialize_transform_diagnostics<'de, D>(
    deserializer: D,
) -> Result<Vec<TransformDiagnosticV1>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    bounded_seq(
        deserializer,
        MAX_TRANSFORM_DIAGNOSTICS,
        "transform diagnostics",
    )
}

pub(crate) fn deserialize_transform_diagnostic_notes<'de, D>(
    deserializer: D,
) -> Result<Vec<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    bounded_seq(
        deserializer,
        MAX_TRANSFORM_DIAGNOSTIC_NOTES,
        "transform diagnostic notes",
    )
}

pub(crate) fn check_limit(
    field: &'static str,
    actual: usize,
    limit: usize,
) -> Result<(), PreparedRecordError> {
    if actual > limit {
        Err(PreparedRecordError::LimitExceeded {
            field,
            limit,
            actual,
        })
    } else {
        Ok(())
    }
}

pub(crate) fn reject_duplicates<T: Ord>(
    field: &'static str,
    values: impl IntoIterator<Item = T>,
) -> Result<(), PreparedRecordError> {
    let mut seen = BTreeSet::new();
    for value in values {
        if !seen.insert(value) {
            return Err(PreparedRecordError::Duplicate { field });
        }
    }
    Ok(())
}

/// How an operation's destination may relate to destinations nested below
/// it in the same plan.
#[derive(Clone, Copy, PartialEq)]
enum DestinationShape {
    /// An ensured or exactly asserted directory may enclose any destination.
    /// Restoring ancestor directories requires this shape.
    Directory,
    /// A removed leaf may enclose only removals and absence assertions. This is
    /// how an owned directory tree is dropped. Commit can execute the removal
    /// only after everything below is gone, and its `REMOVEDIR` unlink remains
    /// the fail-closed guard.
    Removal,
    /// Everything else is a leaf and must not enclose anything.
    Leaf,
}

pub(crate) fn reject_destination_prefixes(
    operations: &[PreparedOperationV1],
) -> Result<(), PreparedRecordError> {
    // Checking adjacent sorted pairs is sufficient. An ancestor's successor is
    // its shallowest enclosed descendant, and every intermediate destination
    // is also a descendant.
    let mut destinations = operations
        .iter()
        .map(|operation| {
            let shape = match operation {
                PreparedOperationV1::EnsureDirectory { .. }
                | PreparedOperationV1::AssertExact {
                    state: StateTargetStateV1::Directory { directory: Some(_) },
                    ..
                } => DestinationShape::Directory,
                PreparedOperationV1::RemoveLeaf { .. } => DestinationShape::Removal,
                _ => DestinationShape::Leaf,
            };
            let absence_shaped = matches!(
                operation,
                PreparedOperationV1::RemoveLeaf { .. } | PreparedOperationV1::AssertAbsent { .. }
            );
            (
                operation.observation().authority().as_str(),
                operation.observation().relative_path(),
                shape,
                absence_shaped,
            )
        })
        .collect::<Vec<_>>();
    destinations.sort_unstable_by(|left, right| {
        left.0
            .cmp(right.0)
            .then_with(|| compare_relative_paths(left.1, right.1))
    });
    for pair in destinations.windows(2) {
        let [
            (left_authority, left_path, left_shape, _),
            (right_authority, right_path, _, right_absence),
        ] = pair
        else {
            unreachable!()
        };
        if left_authority == right_authority && relative_path_is_ancestor(left_path, right_path) {
            let allowed = match left_shape {
                DestinationShape::Directory => true,
                DestinationShape::Removal => *right_absence,
                DestinationShape::Leaf => false,
            };
            if !allowed {
                return Err(PreparedRecordError::InvalidField {
                    field: "operation destination",
                    reason: "destinations must not be ancestors or descendants of one another",
                });
            }
        }
    }
    Ok(())
}

pub(crate) fn compare_relative_paths(left: &str, right: &str) -> std::cmp::Ordering {
    left.split('/').cmp(right.split('/'))
}

pub(crate) fn relative_path_is_ancestor(ancestor: &str, descendant: &str) -> bool {
    descendant
        .strip_prefix(ancestor)
        .is_some_and(|suffix| suffix.starts_with('/'))
}
