//! Stable semantic DTOs shared by Engine and its adapters.

/// Store lifecycle operation exposed through the stable Engine DTO boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StoreOperationV1 {
    Status,
    Initialize,
}

/// A request for a store lifecycle operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StoreRequestV1 {
    operation: StoreOperationV1,
}

impl StoreRequestV1 {
    #[must_use]
    pub const fn status() -> Self {
        Self {
            operation: StoreOperationV1::Status,
        }
    }

    #[must_use]
    pub const fn initialize() -> Self {
        Self {
            operation: StoreOperationV1::Initialize,
        }
    }

    #[must_use]
    pub const fn operation(self) -> StoreOperationV1 {
        self.operation
    }
}

/// The lifecycle state of the final store.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StoreStatusV1 {
    Absent,
    Uninitialized,
    Ready,
}

/// The result of a successful store lifecycle request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StoreResultV1 {
    operation: StoreOperationV1,
    status: StoreStatusV1,
}

impl StoreResultV1 {
    #[must_use]
    pub const fn status(status: StoreStatusV1) -> Self {
        Self {
            operation: StoreOperationV1::Status,
            status,
        }
    }

    #[must_use]
    pub const fn initialized() -> Self {
        Self {
            operation: StoreOperationV1::Initialize,
            status: StoreStatusV1::Ready,
        }
    }

    #[must_use]
    pub const fn operation(self) -> StoreOperationV1 {
        self.operation
    }
    #[must_use]
    pub const fn store_status(self) -> StoreStatusV1 {
        self.status
    }
}

/// A store operation failure code.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StoreErrorCodeV1 {
    ReadOnlyStore,
    StoreNotReady,
    StateParentMissing,
    UnsafeDirectory,
    RootObservationChanged,
    StateParentObservationChanged,
    MalformedStoreMetadata,
    UnsupportedStoreVersion,
    Io,
    Internal,
}

/// Invalid combinations used to construct a store error.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[non_exhaustive]
pub enum StoreErrorValidationError {
    #[error("a ready store cannot be reported as not ready")]
    ReadyStoreNotReady,
    #[error("an unsupported store version must differ from the expected version")]
    MatchingStoreVersions,
}

/// The state authority involved in an observation failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StoreRootV1 {
    V1,
}

/// The directory involved in a store safety failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StoreDirectoryV1 {
    StateParent,
    V1Root,
}

/// A directory safety failure without host-specific path data.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DirectorySafetyReasonV1 {
    WrongOwner,
    GroupOrOtherWritable,
    SpecialModeBitsSet,
    UnexpectedMode,
    AncestryLimitExceeded,
}

/// A malformed final-root descriptor failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StoreMetadataReasonV1 {
    MarkerMissingWithOtherEntries,
    MarkerNotRegular,
    MarkerTooLarge,
    UnexpectedRootEntry,
    InvalidRootEntry,
    WrongOwner,
    UnexpectedMode,
    MultipleLinks,
    ObservationChanged,
    InvalidDescriptor,
}

/// Path-free details attached to a store error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StoreErrorDetailsV1 {
    None,
    CurrentStatus(StoreStatusV1),
    UnsafeDirectory {
        directory: StoreDirectoryV1,
        reason: DirectorySafetyReasonV1,
    },
    RootObservation(StoreRootV1),
    StoreMetadata(StoreMetadataReasonV1),
    UnsupportedVersion {
        expected: u32,
        found: u32,
    },
}

/// Owned stable failure from the Engine store lifecycle DTO boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StoreErrorV1 {
    code: StoreErrorCodeV1,
    details: StoreErrorDetailsV1,
}

impl StoreErrorV1 {
    #[must_use]
    pub const fn read_only_store() -> Self {
        Self::without_details(StoreErrorCodeV1::ReadOnlyStore)
    }

    pub const fn store_not_ready(status: StoreStatusV1) -> Result<Self, StoreErrorValidationError> {
        if matches!(status, StoreStatusV1::Ready) {
            return Err(StoreErrorValidationError::ReadyStoreNotReady);
        }
        Ok(Self {
            code: StoreErrorCodeV1::StoreNotReady,
            details: StoreErrorDetailsV1::CurrentStatus(status),
        })
    }

    #[must_use]
    pub const fn state_parent_missing() -> Self {
        Self::without_details(StoreErrorCodeV1::StateParentMissing)
    }

    #[must_use]
    pub const fn unsafe_directory(
        directory: StoreDirectoryV1,
        reason: DirectorySafetyReasonV1,
    ) -> Self {
        Self {
            code: StoreErrorCodeV1::UnsafeDirectory,
            details: StoreErrorDetailsV1::UnsafeDirectory { directory, reason },
        }
    }

    #[must_use]
    pub const fn root_observation_changed(root: StoreRootV1) -> Self {
        Self {
            code: StoreErrorCodeV1::RootObservationChanged,
            details: StoreErrorDetailsV1::RootObservation(root),
        }
    }

    #[must_use]
    pub const fn state_parent_observation_changed() -> Self {
        Self::without_details(StoreErrorCodeV1::StateParentObservationChanged)
    }

    #[must_use]
    pub const fn malformed_store_metadata(reason: StoreMetadataReasonV1) -> Self {
        Self {
            code: StoreErrorCodeV1::MalformedStoreMetadata,
            details: StoreErrorDetailsV1::StoreMetadata(reason),
        }
    }

    pub const fn unsupported_store_version(
        expected: u32,
        found: u32,
    ) -> Result<Self, StoreErrorValidationError> {
        if expected == found {
            return Err(StoreErrorValidationError::MatchingStoreVersions);
        }
        Ok(Self {
            code: StoreErrorCodeV1::UnsupportedStoreVersion,
            details: StoreErrorDetailsV1::UnsupportedVersion { expected, found },
        })
    }

    #[must_use]
    pub const fn io() -> Self {
        Self::without_details(StoreErrorCodeV1::Io)
    }

    #[must_use]
    pub const fn internal() -> Self {
        Self::without_details(StoreErrorCodeV1::Internal)
    }

    const fn without_details(code: StoreErrorCodeV1) -> Self {
        Self {
            code,
            details: StoreErrorDetailsV1::None,
        }
    }

    #[must_use]
    pub const fn code(self) -> StoreErrorCodeV1 {
        self.code
    }
    #[must_use]
    pub const fn details(self) -> StoreErrorDetailsV1 {
        self.details
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn store_requests_and_results_preserve_operation_identity() {
        assert_eq!(
            StoreRequestV1::status().operation(),
            StoreOperationV1::Status
        );
        assert_eq!(
            StoreRequestV1::initialize().operation(),
            StoreOperationV1::Initialize
        );
        assert_eq!(
            StoreResultV1::status(StoreStatusV1::Absent).operation(),
            StoreOperationV1::Status
        );
        assert_eq!(
            StoreResultV1::initialized().store_status(),
            StoreStatusV1::Ready
        );
    }

    #[test]
    fn store_errors_cannot_form_mismatched_code_detail_pairs() {
        let error = StoreErrorV1::unsupported_store_version(1, 2).unwrap();
        assert_eq!(error.code(), StoreErrorCodeV1::UnsupportedStoreVersion);
        assert_eq!(
            error.details(),
            StoreErrorDetailsV1::UnsupportedVersion {
                expected: 1,
                found: 2,
            }
        );

        assert!(StoreErrorV1::store_not_ready(StoreStatusV1::Ready).is_err());
        assert!(StoreErrorV1::unsupported_store_version(1, 1).is_err());
    }
}
