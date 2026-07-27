//! Identifier types shared by Malm components.

mod deployment_api;
mod engine_api;
mod lifecycle_api;
pub mod serde_util;
mod validate;
mod validated;

pub use validate::ValidationError;
pub use validate::{
    validate_diagnostic_code, validate_label, validate_relative_path, validate_text,
};

/// Converts `usize` to `u64` without overflow on supported Rust targets.
///
/// This relies on Rust targets having a `usize` width of at most 64 bits.
#[must_use]
pub const fn usize_to_u64(value: usize) -> u64 {
    value as u64
}

pub use deployment_api::{
    ApplyOutcomeV1, ApprovalV1, ArchiveProvenanceV1, ArtifactDescriptorV1, ArtifactV1,
    CheckoutRequestV1, CommitRequestV1, DeploymentDtoError, FORMAT_COMPONENT_INTERFACE_V1,
    MAX_TRANSFORM_DIAGNOSTIC_NOTES_V1, MAX_TRANSFORM_DIAGNOSTIC_TEXT_BYTES_V1,
    MAX_TRANSFORM_DIAGNOSTIC_TOTAL_TEXT_BYTES_V1, MAX_TRANSFORM_DIAGNOSTICS_V1,
    MAX_TRANSFORM_RESOURCES_V1, MAX_TRANSFORM_SOURCE_DOCUMENT_BYTES_V1, PolicyFindingV1,
    PrepareArtifactV1, PrepareInputKindV1, PrepareInputV1, PrepareOperationV1,
    PreparePolicyFindingV1, PrepareRequestPartsV1, PrepareRequestV1, PrepareTargetStateV1,
    PrepareTransformDiagnosticLocationV1, PrepareTransformDiagnosticSeverityV1,
    PrepareTransformDiagnosticV1, PrepareTransformImplementationV1,
    PrepareTransformOutputLocationV1, PrepareTransformProvenanceV1, PrepareTransformResourceV1,
    PrepareTransformSourceLocationV1, PreparedDeploymentPartsV1, PreparedDeploymentV1,
    PreparedTrackingAcquisitionGrantV1, PreparedTrackingAcquisitionKindV1,
    PreparedTrackingReviewPartsV1, PreparedTrackingReviewV1, PruneOutcomeV1, PruneRequestV1,
    RecoveryOutcomeV1, RetentionObjectV1, StateViewV1, TrackedRootNoChangeV1,
    TrackedRootUpdateOutcomeV1, policy_approval_digest_v1, policy_finding_id_v1,
};
pub use engine_api::{
    DirectorySafetyReasonV1, StoreDirectoryV1, StoreErrorCodeV1, StoreErrorDetailsV1, StoreErrorV1,
    StoreErrorValidationError, StoreMetadataReasonV1, StoreOperationV1, StoreRequestV1,
    StoreResultV1, StoreRootV1, StoreStatusV1,
};
pub use lifecycle_api::{
    ArtifactBytesInspectionRequestV1, ArtifactMetadataInspectionRequestV1,
    ArtifactMetadataInspectionV1, CanonicalTreeEntryInspectionV1,
    CanonicalTreeEntryKindInspectionV1, CanonicalTreeInspectionRequestV1,
    CanonicalTreeInspectionV1, CapturedInputsInspectionV1, CatalogInspectionRequestV1,
    CatalogInspectionV1, CatalogNamespaceInspectionV1, DesiredSnapshotInspectionRequestV1,
    DesiredSnapshotInspectionV1, DesiredTargetInspectionV1, DesiredTargetStateInspectionV1,
    DisableRequestV1, EnableRequestV1, FsckFindingCodeV1, FsckFindingV1, FsckReportPartsV1,
    FsckReportV1, FsckRequestV1, FsckSeverityV1, FsckStoreAreaV1, FsckSubjectV1,
    GenerationInspectionPartsV1, GenerationInspectionRequestV1, GenerationInspectionV1,
    GenerationInventoryRequestV1, GenerationInventoryV1, HistoryRetentionRequestV1,
    InspectionDtoError, InspectionLimitsV1, LifecycleRequestV1, LifecycleStateViewV1,
    LifecycleTransitionViewV1, MAX_FSCK_DECODED_BYTES_V1, MAX_FSCK_FINDINGS_V1,
    MAX_FSCK_OBJECTS_V1, MAX_FSCK_OBSERVED_BYTES_V1, MAX_FSCK_TARGETS_V1,
    MAX_HISTORY_GENERATIONS_V1, MAX_INSPECTION_ARTIFACT_BYTES_V1, MAX_INSPECTION_DECODED_BYTES_V1,
    MAX_INSPECTION_ITEMS_V1, MAX_STATUS_OBSERVED_BYTES_V1, MAX_STATUS_TARGETS_V1,
    NamespaceHistoryRequestV1, NamespaceHistoryV1, NamespaceInspectionRequestV1,
    NamespaceInspectionV1, NamespaceRemovalHistoryV1, NamespaceRemovalRequestV1,
    NamespaceStatusKindV1, NamespaceStatusPartsV1, NamespaceStatusRequestV1, NamespaceStatusV1,
    ObjectInventoryKindV1, ObjectInventoryRequestV1, ObjectInventoryV1,
    PreparedPlanInspectionRequestV1, RestorePointInspectionV1, RestorePointRequestV1,
    RetentionAuthorityInspectionV1, RetentionInspectionV1, RetentionPinRequestV1,
    TargetStatusKindV1, TargetStatusV1, TrackedRootInspectionV1, TrackingInspectionV1,
    TransformProvenanceInspectionV1,
};

use serde::{Deserialize, Serialize};
use sha2::{Digest as ShaDigest, Sha256};
use std::fmt;

/// Identifies the type of value that failed validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IdentifierKind {
    Digest,
    PackageId,
    ContributionName,
    Alias,
    ArtifactId,
    DeploymentName,
    NamespaceName,
    PreparedId,
}

impl IdentifierKind {
    const fn maximum_len(self) -> usize {
        match self {
            Self::Digest => 71,
            Self::PackageId => 253,
            Self::ContributionName => 63,
            Self::Alias => 32,
            Self::ArtifactId => 255,
            Self::DeploymentName => 128,
            Self::NamespaceName => 128,
            Self::PreparedId => 67,
        }
    }
}

impl fmt::Display for IdentifierKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Digest => "digest",
            Self::PackageId => "package ID",
            Self::ContributionName => "contribution name",
            Self::Alias => "alias",
            Self::ArtifactId => "artifact ID",
            Self::DeploymentName => "deployment name",
            Self::NamespaceName => "namespace name",
            Self::PreparedId => "prepared ID",
        })
    }
}

/// An identifier validation error.
///
/// Invalid input is retained unless it exceeds the identifier's maximum
/// length. Overlong input is discarded and represented only by its byte
/// length.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("invalid {kind} {}: {reason}", RedactableValue(.value, .value_len))]
pub struct IdentifierError {
    kind: IdentifierKind,
    value: Option<String>,
    value_len: usize,
    reason: &'static str,
}

/// Formats the value, using its byte length when the value was discarded.
struct RedactableValue<'a>(&'a Option<String>, &'a usize);

impl fmt::Display for RedactableValue<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            Some(value) => write!(formatter, "{value:?}"),
            None => write!(formatter, "<redacted: {} bytes>", self.1),
        }
    }
}

impl IdentifierError {
    fn new(kind: IdentifierKind, value: String, reason: &'static str) -> Self {
        let value_len = value.len();
        let value = (value_len <= kind.maximum_len()).then_some(value);

        Self {
            kind,
            value,
            value_len,
            reason,
        }
    }

    pub const fn kind(&self) -> IdentifierKind {
        self.kind
    }

    pub fn value(&self) -> Option<&str> {
        self.value.as_deref()
    }

    pub const fn value_len(&self) -> usize {
        self.value_len
    }

    pub const fn is_value_redacted(&self) -> bool {
        self.value.is_none()
    }

    pub const fn reason(&self) -> &'static str {
        self.reason
    }
}

crate::validated_string! {
    /// A SHA-256 digest encoded as `sha256-` and 64 lowercase hexadecimal digits.
    pub struct Digest;
    error: IdentifierError;
    validate: validate_digest;
    make_error: |value, reason| IdentifierError::new(IdentifierKind::Digest, value, reason);
    impl: serde;
}

impl Digest {
    /// Computes the SHA-256 digest of `bytes`.
    pub fn sha256(bytes: impl AsRef<[u8]>) -> Self {
        Self::from_sha256(Sha256::new_with_prefix(bytes))
    }

    /// Finalizes `hasher` as an algorithm-tagged digest.
    #[must_use]
    pub fn from_sha256(hasher: Sha256) -> Self {
        const HEX: &[u8; 16] = b"0123456789abcdef";

        let hash = hasher.finalize();
        let mut value = String::with_capacity(71);
        value.push_str("sha256-");
        for &byte in hash.iter() {
            value.push(HEX[usize::from(byte >> 4)] as char);
            value.push(HEX[usize::from(byte & 0x0f)] as char);
        }
        Self(value)
    }
}

/// The content-derived identity of a locked pack node.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct PackNodeId(Digest);

impl PackNodeId {
    #[must_use]
    pub const fn new(digest: Digest) -> Self {
        Self(digest)
    }

    #[must_use]
    pub const fn digest(&self) -> &Digest {
        &self.0
    }

    #[must_use]
    pub fn into_digest(self) -> Digest {
        self.0
    }
}

impl fmt::Display for PackNodeId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl AsRef<str> for PackNodeId {
    fn as_ref(&self) -> &str {
        self.0.as_str()
    }
}

impl From<Digest> for PackNodeId {
    fn from(digest: Digest) -> Self {
        Self::new(digest)
    }
}

crate::validated_string! {
    /// A lowercase reverse-DNS package ID.
    pub struct PackageId;
    error: IdentifierError;
    validate: validate_package_id;
    make_error: |value, reason| IdentifierError::new(IdentifierKind::PackageId, value, reason);
    impl: serde;
}

crate::validated_string! {
    /// A lowercase contribution name of at most 63 bytes.
    pub struct ContributionName;
    error: IdentifierError;
    validate: validate_contribution_name;
    make_error: |value, reason| {
        IdentifierError::new(IdentifierKind::ContributionName, value, reason)
    };
    impl: serde;
}

crate::validated_string! {
    /// A lowercase alias of at most 32 bytes.
    pub struct Alias;
    error: IdentifierError;
    validate: validate_alias;
    make_error: |value, reason| IdentifierError::new(IdentifierKind::Alias, value, reason);
    impl: serde;
}

crate::validated_string! {
    /// A relative, slash-separated artifact identifier.
    pub struct ArtifactId;
    error: IdentifierError;
    validate: validate_artifact_id;
    make_error: |value, reason| IdentifierError::new(IdentifierKind::ArtifactId, value, reason);
    impl: serde;
}

crate::validated_string! {
    /// A deployment name containing ASCII letters, digits, underscores, or hyphens.
    pub struct DeploymentName;
    error: IdentifierError;
    validate: validate_deployment_name;
    make_error: |value, reason| IdentifierError::new(IdentifierKind::DeploymentName, value, reason);
    impl: serde;
}

crate::validated_string! {
    /// A state namespace name containing ASCII letters, digits, underscores, or hyphens.
    pub struct NamespaceName;
    error: IdentifierError;
    validate: validate_namespace_name;
    make_error: |value, reason| IdentifierError::new(IdentifierKind::NamespaceName, value, reason);
    impl: serde;
}

crate::validated_string! {
    /// A prepared-plan ID encoded as `pp-` followed by a full SHA-256 value.
    pub struct PreparedId;
    error: IdentifierError;
    validate: validate_prepared_id;
    make_error: |value, reason| IdentifierError::new(IdentifierKind::PreparedId, value, reason);
    impl: serde;
}

impl PreparedId {
    /// Derives a plan ID from a canonical record digest.
    #[must_use]
    pub fn from_digest(digest: &Digest) -> Self {
        Self(format!("pp-{}", &digest.as_str()[7..]))
    }

    /// Converts this plan ID to an algorithm-tagged digest.
    #[must_use]
    pub fn digest(&self) -> Digest {
        Digest::new(format!("sha256-{}", &self.0[3..]))
            .expect("validated prepared IDs contain a complete SHA-256 value")
    }
}

type ValidationResult = Result<(), &'static str>;

fn is_lowercase_letter(byte: u8) -> bool {
    byte.is_ascii_lowercase()
}

fn is_lowercase_alphanumeric(byte: u8) -> bool {
    byte.is_ascii_lowercase() || byte.is_ascii_digit()
}

fn validate_digest(value: &str) -> ValidationResult {
    let bytes = value.as_bytes();
    if bytes.len() != 71 {
        return Err("must be exactly 71 bytes");
    }
    if !bytes.starts_with(b"sha256-") {
        return Err("must start with \"sha256-\"");
    }
    if !bytes[7..]
        .iter()
        .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err("digest must contain only lowercase hexadecimal digits");
    }
    Ok(())
}

fn validate_package_id(value: &str) -> ValidationResult {
    if value.len() > 253 {
        return Err("must be at most 253 bytes");
    }
    if !value.contains('.') {
        return Err("must contain at least two dot-separated segments");
    }

    for segment in value.split('.') {
        let Some((&first, rest)) = segment.as_bytes().split_first() else {
            return Err("must not contain empty segments");
        };
        if !is_lowercase_letter(first) {
            return Err("each segment must start with a lowercase ASCII letter");
        }
        if segment.ends_with('-') {
            return Err("segments must not end with a hyphen");
        }
        if !rest
            .iter()
            .all(|&byte| is_lowercase_alphanumeric(byte) || byte == b'-')
        {
            return Err("segments may contain only lowercase ASCII letters, digits, and hyphens");
        }
    }
    Ok(())
}

fn validate_simple_name(value: &str, max_len: usize, too_long: &'static str) -> ValidationResult {
    if value.len() > max_len {
        return Err(too_long);
    }

    let Some((&first, rest)) = value.as_bytes().split_first() else {
        return Err("must not be empty");
    };
    if !is_lowercase_letter(first) {
        return Err("must start with a lowercase ASCII letter");
    }
    if !rest
        .iter()
        .all(|&byte| is_lowercase_alphanumeric(byte) || byte == b'-')
    {
        return Err("may contain only lowercase ASCII letters, digits, and hyphens");
    }
    Ok(())
}

fn validate_contribution_name(value: &str) -> ValidationResult {
    validate_simple_name(value, 63, "must be at most 63 bytes")
}

fn validate_alias(value: &str) -> ValidationResult {
    validate_simple_name(value, 32, "must be at most 32 bytes")
}

fn validate_artifact_id(value: &str) -> ValidationResult {
    if value.len() > 255 {
        return Err("must be at most 255 bytes");
    }

    let Some((&first, _)) = value.as_bytes().split_first() else {
        return Err("must not be empty");
    };
    if !is_lowercase_letter(first) {
        return Err("must start with a lowercase ASCII letter");
    }
    if !value
        .as_bytes()
        .iter()
        .all(|&byte| is_lowercase_alphanumeric(byte) || matches!(byte, b'-' | b'_' | b'.' | b'/'))
    {
        return Err(
            "may contain only lowercase ASCII letters, digits, hyphens, underscores, dots, and slashes",
        );
    }
    if value.split('/').any(str::is_empty) {
        return Err("must not contain empty path segments");
    }
    if value
        .split('/')
        .any(|segment| matches!(segment, "." | ".."))
    {
        return Err("must not contain dot path segments");
    }
    Ok(())
}

fn validate_deployment_name(value: &str) -> ValidationResult {
    validate_safe_identifier(value, 128, "must be at most 128 bytes")
}

fn validate_namespace_name(value: &str) -> ValidationResult {
    validate_safe_identifier(value, 128, "must be at most 128 bytes")
}

fn validate_safe_identifier(
    value: &str,
    max_len: usize,
    too_long: &'static str,
) -> ValidationResult {
    if value.len() > max_len {
        return Err(too_long);
    }
    if value.is_empty() {
        return Err("must not be empty");
    }
    if !value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        return Err("may contain only ASCII letters, digits, underscores, and hyphens");
    }
    Ok(())
}

fn validate_prepared_id(value: &str) -> ValidationResult {
    let bytes = value.as_bytes();
    if bytes.len() != 67 {
        return Err("must be exactly 67 bytes");
    }
    if !bytes.starts_with(b"pp-") {
        return Err("must start with \"pp-\"");
    }
    if !bytes[3..]
        .iter()
        .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err("prepared ID must contain only lowercase hexadecimal digits");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::de::value::{Error as ValueError, StringDeserializer};

    const EMPTY_SHA256: &str =
        "sha256-e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    const ABC_SHA256: &str =
        "sha256-ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    const PREPARED_ID: &str = "pp-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn deserialize<T>(value: &str) -> Result<T, ValueError>
    where
        T: for<'de> Deserialize<'de>,
    {
        T::deserialize(StringDeserializer::new(value.to_owned()))
    }

    fn assert_serializable<T: Serialize>() {}

    #[test]
    fn sha256_is_deterministic_and_matches_known_vectors() {
        assert_eq!(Digest::sha256([]).as_str(), EMPTY_SHA256);
        assert_eq!(Digest::sha256(b"abc").as_str(), ABC_SHA256);
        assert_eq!(Digest::sha256(b"abc"), Digest::sha256(b"abc"));
    }

    #[test]
    fn from_sha256_matches_the_one_shot_constructor() {
        assert_eq!(Digest::from_sha256(Sha256::new()).as_str(), EMPTY_SHA256);

        let mut hasher = Sha256::new();
        hasher.update(b"ab");
        hasher.update(b"c");
        assert_eq!(Digest::from_sha256(hasher), Digest::sha256(b"abc"));
    }

    fn normalize_token(value: &str) -> Result<String, &'static str> {
        let normalized = value.to_ascii_lowercase();
        validate_alias(&normalized)?;
        Ok(normalized)
    }

    crate::validated_string! {
        struct NormalizedToken;
        error: IdentifierError;
        normalize: normalize_token;
        make_error: |value, reason| IdentifierError::new(IdentifierKind::Alias, value, reason);
        impl: from_string, borrow_str;
    }

    #[test]
    fn validated_string_supports_normalize_and_optional_impls() {
        let token = NormalizedToken::new("Stable").unwrap();
        assert_eq!(token.as_str(), "stable");
        assert_eq!(token.to_string(), "stable");
        assert_eq!("Stable".parse::<NormalizedToken>().unwrap(), token);
        assert_eq!(std::borrow::Borrow::<str>::borrow(&token), "stable");
        assert_eq!(String::from(token), "stable");

        let error = NormalizedToken::new("2Fast").unwrap_err();
        assert_eq!(error.kind(), IdentifierKind::Alias);
        assert_eq!(error.value(), Some("2Fast"));
        assert_eq!(error.reason(), "must start with a lowercase ASCII letter");
    }

    #[test]
    fn digest_validates_format_and_string_traits() {
        let digest = Digest::new(ABC_SHA256).unwrap();
        let parsed: Digest = ABC_SHA256.parse().unwrap();

        assert_eq!(digest, parsed);
        assert_eq!(digest.to_string(), ABC_SHA256);
        assert_eq!(digest.as_ref(), ABC_SHA256);
        assert_eq!(digest.clone().into_inner(), ABC_SHA256);

        assert!(Digest::new("sha256-abc").is_err());
        assert!(Digest::new(format!("sha256-{}", "A".repeat(64))).is_err());
        assert!(Digest::new(format!("sha256-{}g", "0".repeat(63))).is_err());
        assert!(Digest::new(format!("sha512-{}", "0".repeat(64))).is_err());
    }

    #[test]
    fn package_id_enforces_reverse_dns_segments() {
        for value in ["com.example", "io.malm.package-2", "a.b"] {
            assert_eq!(PackageId::new(value).unwrap().as_str(), value);
        }

        for value in [
            "",
            "example",
            ".example",
            "com.",
            "com..example",
            "Com.example",
            "com.Example",
            "com.2example",
            "com.example-",
            "com.ex_ample",
            "com.exämple",
        ] {
            assert!(PackageId::new(value).is_err(), "accepted {value:?}");
        }
    }

    #[test]
    fn package_id_honors_total_length_boundary() {
        let maximum = format!("a.{}", "b".repeat(251));
        let overlong = format!("a.{}", "b".repeat(252));

        assert_eq!(maximum.len(), 253);
        assert!(PackageId::new(maximum).is_ok());
        assert_eq!(overlong.len(), 254);
        assert!(PackageId::new(overlong).is_err());
    }

    #[test]
    fn contribution_name_and_alias_validate_boundaries() {
        let contribution_maximum = format!("a{}", "0".repeat(62));
        let alias_maximum = format!("a{}", "-".repeat(31));

        assert!(ContributionName::new("a").is_ok());
        assert!(ContributionName::new(&contribution_maximum).is_ok());
        assert!(ContributionName::new(format!("{contribution_maximum}0")).is_err());
        assert!(ContributionName::new("release-").is_ok());
        assert!(ContributionName::new("Release").is_err());
        assert!(ContributionName::new("release_name").is_err());

        assert!(Alias::new("a").is_ok());
        assert!(Alias::new(&alias_maximum).is_ok());
        assert!(Alias::new(format!("{alias_maximum}-")).is_err());
        assert!(Alias::new("2fast").is_err());
        assert!(Alias::new("alias.name").is_err());
    }

    #[test]
    fn artifact_id_accepts_safe_paths_and_rejects_traversal_shapes() {
        for value in [
            "a",
            "bin/tool",
            "lib/libmalm.so",
            "share/doc/read_me-2",
            "a/.hidden",
            "a/.../b",
            "a/-/_",
        ] {
            assert_eq!(ArtifactId::new(value).unwrap().as_str(), value);
        }

        for value in [
            "",
            "/absolute",
            "a/",
            "a//b",
            "a/./b",
            "a/../b",
            "a/../../b",
            "a\\..\\b",
            "a/%2e%2e/b",
            "A/path",
            "a/path with space",
        ] {
            assert!(ArtifactId::new(value).is_err(), "accepted {value:?}");
        }
    }

    #[test]
    fn artifact_id_honors_length_boundary() {
        assert!(ArtifactId::new("a".repeat(255)).is_ok());
        assert!(ArtifactId::new("a".repeat(256)).is_err());
    }

    #[test]
    fn deployment_name_matches_the_public_character_set() {
        for value in ["a", "Release_2026-07", "0", "_-A"] {
            assert_eq!(DeploymentName::new(value).unwrap().as_str(), value);
        }

        assert!(DeploymentName::new("").is_err());
        assert!(DeploymentName::new("release.name").is_err());
        assert!(DeploymentName::new("release/name").is_err());
        assert!(DeploymentName::new("a".repeat(128)).is_ok());
        assert!(DeploymentName::new("a".repeat(129)).is_err());
    }

    #[test]
    fn namespace_name_uses_the_bounded_safe_identifier_profile() {
        for value in ["a", "Release_2026-07", "0", "_-A"] {
            assert_eq!(NamespaceName::new(value).unwrap().as_str(), value);
        }

        for value in ["", "release.name", "release/name", "white space", "näme"] {
            assert!(NamespaceName::new(value).is_err(), "accepted {value:?}");
        }
        assert!(NamespaceName::new("a".repeat(128)).is_ok());
        let error = NamespaceName::new("a".repeat(129)).unwrap_err();
        assert_eq!(error.kind(), IdentifierKind::NamespaceName);
        assert_eq!(error.value_len(), 129);
        assert!(error.is_value_redacted());
    }

    #[test]
    fn deployment_modes_remain_recovery_readable() {
        let authority = DeploymentName::new("home").unwrap();
        let artifact = ArtifactId::new("config/file").unwrap();

        assert!(
            PrepareOperationV1::place_file(authority.clone(), "file", artifact.clone(), 0o400)
                .is_ok()
        );
        assert!(
            PrepareOperationV1::place_file(authority.clone(), "file", artifact, 0o200).is_err()
        );
        assert!(PrepareOperationV1::ensure_directory(authority.clone(), "dir", 0o500).is_ok());
        assert!(PrepareOperationV1::ensure_directory(authority, "dir", 0o300).is_err());
    }

    #[test]
    fn prepared_id_requires_exact_lowercase_hex_format() {
        let prepared = PreparedId::new(PREPARED_ID).unwrap();

        assert_eq!(prepared.to_string(), PREPARED_ID);
        assert!(PreparedId::new("pp-0123").is_err());
        assert!(PreparedId::new(format!("pp-{}", "A".repeat(64))).is_err());
        assert!(PreparedId::new(format!("id-{}", "0".repeat(64))).is_err());
        assert!(PreparedId::new(format!("pp-{}g", "0".repeat(63))).is_err());
        let digest = Digest::sha256(b"prepared plan");
        let prepared = PreparedId::from_digest(&digest);
        assert_eq!(prepared.digest(), digest);
    }

    #[test]
    fn from_str_and_display_are_available_for_every_identifier() {
        assert_eq!(
            ABC_SHA256.parse::<Digest>().unwrap().to_string(),
            ABC_SHA256
        );
        assert_eq!(
            "com.example".parse::<PackageId>().unwrap().to_string(),
            "com.example"
        );
        assert_eq!(
            "contribution-1"
                .parse::<ContributionName>()
                .unwrap()
                .to_string(),
            "contribution-1"
        );
        assert_eq!("stable".parse::<Alias>().unwrap().to_string(), "stable");
        assert_eq!(
            "bin/tool".parse::<ArtifactId>().unwrap().to_string(),
            "bin/tool"
        );
        assert_eq!(
            "Blue_1".parse::<DeploymentName>().unwrap().to_string(),
            "Blue_1"
        );
        assert_eq!(
            "Blue_1".parse::<NamespaceName>().unwrap().to_string(),
            "Blue_1"
        );
        assert_eq!(
            PREPARED_ID.parse::<PreparedId>().unwrap().to_string(),
            PREPARED_ID
        );
    }

    #[test]
    fn serde_deserialization_validates_every_identifier() {
        assert_eq!(
            deserialize::<Digest>(ABC_SHA256).unwrap().as_str(),
            ABC_SHA256
        );
        assert_eq!(
            deserialize::<PackageId>("com.example").unwrap().as_str(),
            "com.example"
        );
        assert_eq!(
            deserialize::<ContributionName>("contribution")
                .unwrap()
                .as_str(),
            "contribution"
        );
        assert_eq!(deserialize::<Alias>("stable").unwrap().as_str(), "stable");
        assert_eq!(
            deserialize::<ArtifactId>("bin/tool").unwrap().as_str(),
            "bin/tool"
        );
        assert_eq!(
            deserialize::<DeploymentName>("Blue_1").unwrap().as_str(),
            "Blue_1"
        );
        assert_eq!(
            deserialize::<NamespaceName>("Blue_1").unwrap().as_str(),
            "Blue_1"
        );
        assert_eq!(
            deserialize::<PreparedId>(PREPARED_ID).unwrap().as_str(),
            PREPARED_ID
        );

        assert!(deserialize::<Digest>("sha256-invalid").is_err());
        assert!(deserialize::<PackageId>("Example").is_err());
        assert!(deserialize::<ContributionName>("Contribution").is_err());
        assert!(deserialize::<Alias>("alias_name").is_err());
        assert!(deserialize::<ArtifactId>("a/../secret").is_err());
        assert!(deserialize::<DeploymentName>("blue.green").is_err());
        assert!(deserialize::<NamespaceName>("blue.green").is_err());
        assert!(deserialize::<PreparedId>("pp-invalid").is_err());
    }

    #[test]
    fn all_identifiers_implement_serialize() {
        assert_serializable::<Digest>();
        assert_serializable::<PackageId>();
        assert_serializable::<ContributionName>();
        assert_serializable::<Alias>();
        assert_serializable::<ArtifactId>();
        assert_serializable::<DeploymentName>();
        assert_serializable::<NamespaceName>();
        assert_serializable::<PreparedId>();
        assert_serializable::<PackNodeId>();
    }

    #[test]
    fn pack_node_id_is_a_validated_transparent_digest() {
        let digest = Digest::sha256(b"pack node");
        let node = PackNodeId::new(digest.clone());

        assert_eq!(node.digest(), &digest);
        assert_eq!(node.as_ref(), digest.as_str());
        assert_eq!(node.to_string(), digest.to_string());
        assert_eq!(node.clone().into_digest(), digest);
    }

    #[test]
    fn validation_errors_are_structured_and_deterministic() {
        let error = Alias::new("Bad").unwrap_err();

        assert_eq!(error.kind(), IdentifierKind::Alias);
        assert_eq!(error.value(), Some("Bad"));
        assert_eq!(error.value_len(), 3);
        assert!(!error.is_value_redacted());
        assert_eq!(error.reason(), "must start with a lowercase ASCII letter");
        assert_eq!(
            error.to_string(),
            "invalid alias \"Bad\": must start with a lowercase ASCII letter"
        );

        fn assert_std_error<T: std::error::Error>() {}
        assert_std_error::<IdentifierError>();
    }

    #[test]
    fn only_overlong_error_values_are_redacted() {
        let invalid_at_limit = format!("a{}!", "b".repeat(30));
        let visible = Alias::new(&invalid_at_limit).unwrap_err();
        assert_eq!(invalid_at_limit.len(), 32);
        assert_eq!(visible.value(), Some(invalid_at_limit.as_str()));
        assert!(!visible.is_value_redacted());

        let overlong = "a".repeat(33);
        let redacted = Alias::new(&overlong).unwrap_err();
        assert_eq!(redacted.kind(), IdentifierKind::Alias);
        assert_eq!(redacted.value(), None);
        assert_eq!(redacted.value_len(), 33);
        assert!(redacted.is_value_redacted());
        assert_eq!(redacted.reason(), "must be at most 32 bytes");
        assert_eq!(
            redacted.to_string(),
            "invalid alias <redacted: 33 bytes>: must be at most 32 bytes"
        );
        assert!(!format!("{redacted:?}").contains(&overlong));
    }
}
