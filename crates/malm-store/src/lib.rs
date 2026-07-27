//! Pure canonical records for the isolated Malm `store/v1` contract.
//!
//! This crate validates and encodes caller-provided values only; it performs no I/O.

use std::{fmt, marker::PhantomData};

use serde::Deserialize;

/// Deserializes every element in a length-bounded sequence.
///
/// Unlike `malm_types::serde_util::bounded_seq`, this function does not reject
/// from `size_hint` before reading or skip an overflowing element as
/// `IgnoredAny`. It parses the overflowing element first, so malformed input
/// past the limit reports a parse error instead of a limit error. Limit errors
/// use `"at most {limit} {expecting_noun}"` and
/// `"{overflow_subject} exceeds {limit} {overflow_noun}"`.
fn bounded_seq_eager<'de, D, T>(
    deserializer: D,
    limit: usize,
    expecting_noun: &'static str,
    overflow_subject: &'static str,
    overflow_noun: &'static str,
) -> Result<Vec<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    struct EagerVisitor<T> {
        limit: usize,
        expecting_noun: &'static str,
        overflow_subject: &'static str,
        overflow_noun: &'static str,
        element: PhantomData<T>,
    }

    impl<'de, T> serde::de::Visitor<'de> for EagerVisitor<T>
    where
        T: Deserialize<'de>,
    {
        type Value = Vec<T>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(formatter, "at most {} {}", self.limit, self.expecting_noun)
        }

        fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
        where
            A: serde::de::SeqAccess<'de>,
        {
            let mut items =
                Vec::with_capacity(sequence.size_hint().unwrap_or_default().min(self.limit));
            while let Some(item) = sequence.next_element()? {
                if items.len() == self.limit {
                    return Err(serde::de::Error::custom(format_args!(
                        "{} exceeds {} {}",
                        self.overflow_subject, self.limit, self.overflow_noun
                    )));
                }
                items.push(item);
            }
            Ok(items)
        }
    }

    deserializer.deserialize_seq(EagerVisitor {
        limit,
        expecting_noun,
        overflow_subject,
        overflow_noun,
        element: PhantomData,
    })
}

/// Implemented prepared-record schema version.
pub const PREPARED_RECORD_SCHEMA_VERSION: u32 = 1;
/// Maximum canonical bytes in one prepared record.
pub const MAX_PREPARED_RECORD_BYTES: usize = 16 * 1024 * 1024;
/// Maximum immutable artifacts referenced by one plan.
pub const MAX_PREPARED_ARTIFACTS: usize = 16_384;
/// Maximum bytes in one artifact blob.
pub const MAX_ARTIFACT_BLOB_BYTES: u64 = 256 * 1024 * 1024;
/// Maximum aggregate bytes across unique artifact blobs in one plan.
pub const MAX_PREPARED_UNIQUE_ARTIFACT_BYTES: u64 = 256 * 1024 * 1024;
/// Maximum ordered target operations in one plan.
pub const MAX_PREPARED_OPERATIONS: usize = 65_536;
/// Maximum cumulative target slots retained in one complete desired snapshot.
pub const MAX_DESIRED_TARGETS: usize = 65_536;
/// Maximum present claims in one global ownership projection.
pub const MAX_OWNERSHIP_CLAIMS: usize = 65_536;
/// Maximum cumulative target slots in one global ownership projection.
pub const MAX_OWNERSHIP_TARGET_SLOTS: usize = 131_072;
/// Maximum selected generations supplied to one ownership projection.
pub const MAX_OWNERSHIP_GENERATIONS: usize = 4_096;
/// Maximum distinct target authorities in one global ownership projection.
pub const MAX_OWNERSHIP_AUTHORITIES: usize = 64;
/// Maximum provenance inputs in one plan.
pub const MAX_PREPARED_INPUTS: usize = 65_536;
/// Maximum format transforms in one plan.
pub const MAX_TRANSFORM_PROVENANCE: usize = 16_384;
/// Maximum declared resource identities retained for one transform.
pub const MAX_TRANSFORM_RESOURCES: usize = malm_types::MAX_TRANSFORM_RESOURCES_V1;
/// Maximum successful diagnostics retained for one transform.
pub const MAX_TRANSFORM_DIAGNOSTICS: usize = malm_types::MAX_TRANSFORM_DIAGNOSTICS_V1;
/// Maximum bytes in one transform diagnostic message or note.
pub const MAX_TRANSFORM_DIAGNOSTIC_TEXT_BYTES: usize =
    malm_types::MAX_TRANSFORM_DIAGNOSTIC_TEXT_BYTES_V1;
/// Maximum notes retained by one transform diagnostic.
pub const MAX_TRANSFORM_DIAGNOSTIC_NOTES: usize = malm_types::MAX_TRANSFORM_DIAGNOSTIC_NOTES_V1;
/// Maximum aggregate diagnostic message and note bytes retained for one transform.
pub const MAX_TRANSFORM_DIAGNOSTIC_TOTAL_TEXT_BYTES: usize =
    malm_types::MAX_TRANSFORM_DIAGNOSTIC_TOTAL_TEXT_BYTES_V1;
/// Maximum policy findings in one plan.
pub const MAX_POLICY_FINDINGS: usize = 16_384;
/// Maximum canonical bytes in one state generation.
pub const MAX_STATE_RECORD_BYTES: usize = 4 * 1024 * 1024;
/// Implemented state-catalog schema version.
pub const STATE_CATALOG_SCHEMA_VERSION: u32 = 1;
/// Maximum namespace heads in one state catalog.
pub const MAX_STATE_CATALOG_HEADS: usize = 4_096;
/// Maximum canonical bytes in one state catalog.
pub const MAX_STATE_CATALOG_BYTES: usize = 4 * 1024 * 1024;
/// Implemented embedded tracked-root schema version.
pub const TRACKED_ROOT_SCHEMA_VERSION: u32 = 1;
/// Maximum bytes in one canonical tracked-root source locator.
pub const MAX_TRACKED_ROOT_SOURCE_LOCATOR_BYTES: usize = 2_048;
/// Maximum bytes in one canonical moving selector.
pub const MAX_TRACKED_ROOT_MOVING_SELECTOR_BYTES: usize = 1_024;
/// Maximum bytes in one tracked-root Git repository subdirectory.
pub const MAX_TRACKED_ROOT_SOURCE_SUBDIR_BYTES: usize = 1_024;
/// Maximum bytes in one tracked-root config entry point.
pub const MAX_TRACKED_ROOT_CONFIG_ENTRY_POINT_BYTES: usize = 1_024;
/// Maximum bytes in one persisted acquisition-grant locator.
pub const MAX_ACQUISITION_GRANT_LOCATOR_BYTES: usize = 4_096;
/// Maximum acquisition grants persisted by one tracked root.
pub const MAX_TRACKED_ROOT_ACQUISITION_GRANTS: usize = 8_192;
/// Maximum aggregate locator bytes persisted by one tracked root.
pub const MAX_TRACKED_ROOT_ACQUISITION_BYTES: usize = 4 * 1024 * 1024;
/// Default bounded predecessor history retained for a namespace.
pub const DEFAULT_HISTORY_RETENTION_GENERATIONS: u32 = 256;
/// Maximum bounded predecessor history retained for one namespace.
pub const MAX_HISTORY_RETENTION_GENERATIONS: u32 = 65_536;
/// Maximum explicit restore points carried by one namespace generation.
pub const MAX_RESTORE_POINTS: usize = 4_096;
/// Maximum explicit immutable-object pins carried by one namespace generation.
pub const MAX_EXPLICIT_PINS: usize = 16_384;

mod ownership;
mod prepared;
mod state;
mod tracked_root;
mod validate;

pub use ownership::*;
pub use prepared::*;
pub use state::*;
pub use tracked_root::*;

#[cfg(test)]
mod test_fixtures;
