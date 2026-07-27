#![forbid(unsafe_code)]
//! Pure contracts for locating and admitting the final Malm state root.
//!
//! Callers provide all paths and descriptor bytes. This crate does not access
//! the filesystem, environment, processes, or network.

use std::{
    fmt,
    path::{Path, PathBuf},
};

use serde::{
    Deserialize,
    de::{MapAccess, Visitor},
};
use serde_json::Value;

/// State-root leaf below the selected state-home directory.
pub const PRODUCTION_ROOT_LEAF: &str = "malm";
/// Final-root descriptor filename.
pub const DESCRIPTOR_FILENAME: &str = "descriptor.json";
/// Store format accepted by the v1 descriptor decoder.
pub const DESCRIPTOR_FORMAT: &str = "malm-state";
/// Store version accepted by the v1 descriptor decoder.
pub const DESCRIPTOR_VERSION: u32 = 1;
/// Maximum descriptor size.
pub const MAX_DESCRIPTOR_BYTES: usize = 4_096;
/// The only accepted byte representation of a v1 final-root descriptor.
pub const DESCRIPTOR_CANONICAL_BYTES: &[u8] = b"{\"format\":\"malm-state\",\"version\":1}\n";
/// Required mode for final-root directories.
pub const CONTAINER_MODE: u32 = 0o700;
/// Required mode for mutable final-root files.
pub const MUTABLE_FILE_MODE: u32 = 0o600;

/// Required filesystem kind for a top-level final-root entry.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum FinalRootEntryKind {
    Descriptor,
    Directory,
    Lock,
}

/// One leaf in the closed top-level final-root layout.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct FinalRootEntry {
    name: &'static str,
    kind: FinalRootEntryKind,
}

impl FinalRootEntry {
    const fn new(name: &'static str, kind: FinalRootEntryKind) -> Self {
        Self { name, kind }
    }

    #[must_use]
    pub const fn name(self) -> &'static str {
        self.name
    }

    #[must_use]
    pub const fn kind(self) -> FinalRootEntryKind {
        self.kind
    }

    /// Returns the required permission and special mode bits.
    #[must_use]
    pub const fn mode(self) -> u32 {
        match self.kind {
            FinalRootEntryKind::Directory => CONTAINER_MODE,
            FinalRootEntryKind::Descriptor | FinalRootEntryKind::Lock => MUTABLE_FILE_MODE,
        }
    }
}

/// Complete allowlist for the top level of a descriptor-bearing final root.
pub const FINAL_ROOT_ENTRIES: &[FinalRootEntry] = &[
    FinalRootEntry::new(DESCRIPTOR_FILENAME, FinalRootEntryKind::Descriptor),
    FinalRootEntry::new("state", FinalRootEntryKind::Directory),
    FinalRootEntry::new("objects", FinalRootEntryKind::Directory),
    FinalRootEntry::new("prepared", FinalRootEntryKind::Directory),
    FinalRootEntry::new("transactions", FinalRootEntryKind::Directory),
    FinalRootEntry::new("transaction.lock", FinalRootEntryKind::Lock),
    FinalRootEntry::new("maintenance.lock", FinalRootEntryKind::Lock),
];

/// Classifies an exact byte filename under the closed final-root allowlist.
#[must_use]
pub fn final_root_entry(name: &[u8]) -> Option<FinalRootEntry> {
    FINAL_ROOT_ENTRIES
        .iter()
        .copied()
        .find(|entry| entry.name().as_bytes() == name)
}

/// An admitted final-root descriptor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DescriptorV1 {
    format: &'static str,
    version: u32,
}

impl DescriptorV1 {
    #[must_use]
    pub const fn format(&self) -> &'static str {
        self.format
    }

    #[must_use]
    pub const fn version(&self) -> u32 {
        self.version
    }
}

/// The descriptor admitted by [`decode_descriptor_v1`].
pub const DESCRIPTOR_V1: DescriptorV1 = DescriptorV1 {
    format: DESCRIPTOR_FORMAT,
    version: DESCRIPTOR_VERSION,
};

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum DescriptorField {
    Format,
    Version,
}

impl DescriptorField {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Format => "format",
            Self::Version => "version",
        }
    }
}

impl fmt::Display for DescriptorField {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JsonValueType {
    Null,
    Boolean,
    Number,
    String,
    Array,
    Object,
}

impl JsonValueType {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Null => "null",
            Self::Boolean => "boolean",
            Self::Number => "number",
            Self::String => "string",
            Self::Array => "array",
            Self::Object => "object",
        }
    }
}

impl fmt::Display for JsonValueType {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl JsonValueType {
    fn of(value: &Value) -> Self {
        match value {
            Value::Null => Self::Null,
            Value::Bool(_) => Self::Boolean,
            Value::Number(_) => Self::Number,
            Value::String(_) => Self::String,
            Value::Array(_) => Self::Array,
            Value::Object(_) => Self::Object,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DescriptorValueType {
    String,
    UnsignedInteger,
}

impl DescriptorValueType {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::String => "string",
            Self::UnsignedInteger => "unsigned integer",
        }
    }
}

impl fmt::Display for DescriptorValueType {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Failure to admit descriptor bytes.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum DescriptorDecodeError {
    #[error("descriptor has {actual} bytes; limit is {limit}")]
    TooLarge { limit: usize, actual: usize },
    #[error("descriptor is malformed JSON")]
    MalformedJson,
    #[error("descriptor must be an object, found {actual}")]
    ExpectedObject { actual: JsonValueType },
    #[error("descriptor field {field:?} is duplicated")]
    DuplicateField { field: DescriptorField },
    #[error("descriptor field {field:?} is unknown")]
    UnknownField { field: String },
    #[error("descriptor field {field:?} is missing")]
    MissingField { field: DescriptorField },
    #[error("descriptor field {field:?} must be {expected}, found {actual}")]
    WrongType {
        field: DescriptorField,
        expected: DescriptorValueType,
        actual: JsonValueType,
    },
    #[error("unsupported descriptor format {found:?}; expected {expected:?}")]
    UnsupportedFormat {
        expected: &'static str,
        found: String,
    },
    #[error("unsupported descriptor version {found}; expected {expected}")]
    UnsupportedVersion { expected: u32, found: u64 },
    #[error("descriptor bytes are not canonical")]
    NonCanonical,
}

struct DescriptorWire {
    format: Value,
    version: Value,
}

struct ParsedDescriptor(Result<DescriptorWire, DescriptorDecodeError>);

impl<'de> Deserialize<'de> for ParsedDescriptor {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_map(DescriptorVisitor)
    }
}

/// Rejects duplicate keys while visiting a JSON object.
///
/// Other top-level types fail before this visitor runs. The decoder then reads
/// them as [`Value`] to report their type.
struct DescriptorVisitor;

impl<'de> Visitor<'de> for DescriptorVisitor {
    type Value = ParsedDescriptor;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a final-root descriptor object")
    }

    fn visit_map<M>(self, mut map: M) -> Result<Self::Value, M::Error>
    where
        M: MapAccess<'de>,
    {
        let mut format = None;
        let mut version = None;
        let mut first_error = None;

        while let Some(field) = map.next_key::<String>()? {
            let value = map.next_value::<Value>()?;
            match field.as_str() {
                "format" if format.is_some() => {
                    first_error.get_or_insert(DescriptorDecodeError::DuplicateField {
                        field: DescriptorField::Format,
                    });
                }
                "format" => format = Some(value),
                "version" if version.is_some() => {
                    first_error.get_or_insert(DescriptorDecodeError::DuplicateField {
                        field: DescriptorField::Version,
                    });
                }
                "version" => version = Some(value),
                _ => {
                    first_error.get_or_insert(DescriptorDecodeError::UnknownField { field });
                }
            }
        }

        if let Some(error) = first_error {
            return Ok(ParsedDescriptor(Err(error)));
        }
        let Some(format) = format else {
            return Ok(ParsedDescriptor(Err(DescriptorDecodeError::MissingField {
                field: DescriptorField::Format,
            })));
        };
        let Some(version) = version else {
            return Ok(ParsedDescriptor(Err(DescriptorDecodeError::MissingField {
                field: DescriptorField::Version,
            })));
        };

        Ok(ParsedDescriptor(Ok(DescriptorWire { format, version })))
    }
}

/// Strictly decodes one complete, bounded v1 final-root descriptor.
///
/// Compatibility errors take precedence over canonicality errors.
pub fn decode_descriptor_v1(bytes: &[u8]) -> Result<DescriptorV1, DescriptorDecodeError> {
    if bytes.len() > MAX_DESCRIPTOR_BYTES {
        return Err(DescriptorDecodeError::TooLarge {
            limit: MAX_DESCRIPTOR_BYTES,
            actual: bytes.len(),
        });
    }

    let wire = match serde_json::from_slice(bytes) {
        Ok(ParsedDescriptor(parsed)) => parsed?,
        Err(_) => {
            // Re-read failed objects as generic values to distinguish a wrong
            // top-level type from malformed JSON.
            let value: Value =
                serde_json::from_slice(bytes).map_err(|_| DescriptorDecodeError::MalformedJson)?;
            return Err(DescriptorDecodeError::ExpectedObject {
                actual: JsonValueType::of(&value),
            });
        }
    };
    let Some(format) = wire.format.as_str() else {
        return Err(DescriptorDecodeError::WrongType {
            field: DescriptorField::Format,
            expected: DescriptorValueType::String,
            actual: JsonValueType::of(&wire.format),
        });
    };
    let Some(version) = wire.version.as_u64() else {
        return Err(DescriptorDecodeError::WrongType {
            field: DescriptorField::Version,
            expected: DescriptorValueType::UnsignedInteger,
            actual: JsonValueType::of(&wire.version),
        });
    };

    if format != DESCRIPTOR_FORMAT {
        return Err(DescriptorDecodeError::UnsupportedFormat {
            expected: DESCRIPTOR_FORMAT,
            found: format.to_owned(),
        });
    }
    if version != u64::from(DESCRIPTOR_VERSION) {
        return Err(DescriptorDecodeError::UnsupportedVersion {
            expected: DESCRIPTOR_VERSION,
            found: version,
        });
    }
    if bytes != DESCRIPTOR_CANONICAL_BYTES {
        return Err(DescriptorDecodeError::NonCanonical);
    }

    Ok(DESCRIPTOR_V1)
}

/// Resolves the production root from explicit environment values.
///
/// `HOME` is required only for the fallback when `XDG_STATE_HOME` is absent.
/// This function does not read the environment or inspect the filesystem.
pub fn resolve_root(
    home: Option<&Path>,
    xdg_state_home: Option<&Path>,
) -> Result<PathBuf, RootPathError> {
    match xdg_state_home {
        Some(path) if path.as_os_str().is_empty() => Err(RootPathError::XdgStateHomeEmpty),
        Some(path) if !path.is_absolute() => Err(RootPathError::XdgStateHomeNotAbsolute {
            xdg_state_home: path.to_path_buf(),
        }),
        Some(path) => {
            validate_normalized_authority_path(path, PathAuthority::XdgStateHome)?;
            Ok(path.join(PRODUCTION_ROOT_LEAF))
        }
        None => Ok(require_home(home)?
            .join(".local")
            .join("state")
            .join(PRODUCTION_ROOT_LEAF)),
    }
}

/// Validates an explicit `HOME` value for a fallback root or target.
pub fn require_home(home: Option<&Path>) -> Result<&Path, RootPathError> {
    let home = home.ok_or(RootPathError::HomeMissing)?;
    if home.as_os_str().is_empty() {
        return Err(RootPathError::HomeEmpty);
    }
    if !home.is_absolute() {
        return Err(RootPathError::HomeNotAbsolute {
            home: home.to_path_buf(),
        });
    }
    validate_normalized_authority_path(home, PathAuthority::Home)?;
    Ok(home)
}

#[derive(Clone, Copy)]
enum PathAuthority {
    Home,
    XdgStateHome,
    InjectedRoot,
}

impl PathAuthority {
    const fn dot_component_error(self, path: PathBuf) -> RootPathError {
        match self {
            Self::Home => RootPathError::HomeDotComponent { home: path },
            Self::XdgStateHome => RootPathError::XdgStateHomeDotComponent {
                xdg_state_home: path,
            },
            Self::InjectedRoot => RootPathError::InjectedRootDotComponent { root: path },
        }
    }

    const fn parent_component_error(self, path: PathBuf) -> RootPathError {
        match self {
            Self::Home => RootPathError::HomeParentComponent { home: path },
            Self::XdgStateHome => RootPathError::XdgStateHomeParentComponent {
                xdg_state_home: path,
            },
            Self::InjectedRoot => RootPathError::InjectedRootParentComponent { root: path },
        }
    }

    const fn not_normalized_error(self, path: PathBuf) -> RootPathError {
        match self {
            Self::Home => RootPathError::HomeNotNormalized { home: path },
            Self::XdgStateHome => RootPathError::XdgStateHomeNotNormalized {
                xdg_state_home: path,
            },
            Self::InjectedRoot => RootPathError::InjectedRootNotNormalized { root: path },
        }
    }
}

fn validate_normalized_authority_path(
    path: &Path,
    authority: PathAuthority,
) -> Result<(), RootPathError> {
    let display = path.to_string_lossy();
    for component in display.split(['/', std::path::MAIN_SEPARATOR]) {
        match component {
            "." => return Err(authority.dot_component_error(path.to_path_buf())),
            ".." => return Err(authority.parent_component_error(path.to_path_buf())),
            _ => {}
        }
    }
    let normalized = path.components().collect::<PathBuf>();
    if normalized.as_os_str() != path.as_os_str() {
        return Err(authority.not_normalized_error(path.to_path_buf()));
    }
    Ok(())
}

/// Validates an explicitly injected final-root path.
///
/// Validation is lexical: the path must already be absolute and normalized,
/// must not be a filesystem root, and must contain no `.` or `..` component.
pub fn validate_injected_root(root: &Path) -> Result<(), RootPathError> {
    if !root.is_absolute() {
        return Err(RootPathError::InjectedRootNotAbsolute {
            root: root.to_path_buf(),
        });
    }
    validate_normalized_authority_path(root, PathAuthority::InjectedRoot)?;
    if root.parent().is_none() {
        return Err(RootPathError::InjectedRootIsFilesystemRoot {
            root: root.to_path_buf(),
        });
    }
    Ok(())
}

/// Failure to resolve or validate a final-root path.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum RootPathError {
    #[error("HOME must be present")]
    HomeMissing,
    #[error("HOME must not be empty")]
    HomeEmpty,
    #[error("HOME must be absolute, found {home:?}")]
    HomeNotAbsolute { home: PathBuf },
    #[error("HOME contains a dot component: {home:?}")]
    HomeDotComponent { home: PathBuf },
    #[error("HOME contains a parent component: {home:?}")]
    HomeParentComponent { home: PathBuf },
    #[error("HOME is not normalized: {home:?}")]
    HomeNotNormalized { home: PathBuf },
    #[error("XDG_STATE_HOME must not be empty")]
    XdgStateHomeEmpty,
    #[error("XDG_STATE_HOME must be absolute, found {xdg_state_home:?}")]
    XdgStateHomeNotAbsolute { xdg_state_home: PathBuf },
    #[error("XDG_STATE_HOME contains a dot component: {xdg_state_home:?}")]
    XdgStateHomeDotComponent { xdg_state_home: PathBuf },
    #[error("XDG_STATE_HOME contains a parent component: {xdg_state_home:?}")]
    XdgStateHomeParentComponent { xdg_state_home: PathBuf },
    #[error("XDG_STATE_HOME is not normalized: {xdg_state_home:?}")]
    XdgStateHomeNotNormalized { xdg_state_home: PathBuf },
    #[error("injected root must be absolute, found {root:?}")]
    InjectedRootNotAbsolute { root: PathBuf },
    #[error("injected root must not be a filesystem root, found {root:?}")]
    InjectedRootIsFilesystemRoot { root: PathBuf },
    #[error("injected root contains a dot component: {root:?}")]
    InjectedRootDotComponent { root: PathBuf },
    #[error("injected root contains a parent component: {root:?}")]
    InjectedRootParentComponent { root: PathBuf },
    #[error("injected root is not normalized: {root:?}")]
    InjectedRootNotNormalized { root: PathBuf },
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum RecordFamilyV1 {
    GlobalCatalog,
    NamespaceGeneration,
    DesiredSnapshot,
    TrackedRoot,
    PreparedRecord,
    TransactionJournal,
    Blob,
    Symlink,
    Tree,
    ArchiveDeclaration,
    ArchiveProvenance,
    ConfigIr,
    Transform,
    Lifecycle,
    Inspection,
    Fsck,
    Retention,
}

impl RecordFamilyV1 {
    pub const ALL: &'static [Self] = &[
        Self::GlobalCatalog,
        Self::NamespaceGeneration,
        Self::DesiredSnapshot,
        Self::TrackedRoot,
        Self::PreparedRecord,
        Self::TransactionJournal,
        Self::Blob,
        Self::Symlink,
        Self::Tree,
        Self::ArchiveDeclaration,
        Self::ArchiveProvenance,
        Self::ConfigIr,
        Self::Transform,
        Self::Lifecycle,
        Self::Inspection,
        Self::Fsck,
        Self::Retention,
    ];

    #[must_use]
    pub const fn identifier(self) -> &'static str {
        match self {
            Self::GlobalCatalog => "global-catalog",
            Self::NamespaceGeneration => "namespace-generation",
            Self::DesiredSnapshot => "desired-snapshot",
            Self::TrackedRoot => "tracked-root",
            Self::PreparedRecord => "prepared-record",
            Self::TransactionJournal => "transaction-journal",
            Self::Blob => "blob",
            Self::Symlink => "symlink",
            Self::Tree => "tree",
            Self::ArchiveDeclaration => "archive-declaration",
            Self::ArchiveProvenance => "archive-provenance",
            Self::ConfigIr => "config-ir",
            Self::Transform => "transform",
            Self::Lifecycle => "lifecycle",
            Self::Inspection => "inspection",
            Self::Fsck => "fsck",
            Self::Retention => "retention",
        }
    }
}

impl fmt::Display for RecordFamilyV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.identifier())
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum OperationV1 {
    Deployment,
    Update,
    Lifecycle,
    Status,
    History,
    Fsck,
    Retention,
    Inspection,
}

impl OperationV1 {
    pub const ALL: &'static [Self] = &[
        Self::Deployment,
        Self::Update,
        Self::Lifecycle,
        Self::Status,
        Self::History,
        Self::Fsck,
        Self::Retention,
        Self::Inspection,
    ];

    #[must_use]
    pub const fn identifier(self) -> &'static str {
        match self {
            Self::Deployment => "deployment",
            Self::Update => "update",
            Self::Lifecycle => "lifecycle",
            Self::Status => "status",
            Self::History => "history",
            Self::Fsck => "fsck",
            Self::Retention => "retention",
            Self::Inspection => "inspection",
        }
    }
}

impl fmt::Display for OperationV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.identifier())
    }
}

#[cfg(test)]
mod tests {
    use super::{PRODUCTION_ROOT_LEAF, RootPathError, require_home, resolve_root};
    use std::path::{Path, PathBuf};

    #[test]
    fn environment_path_authorities_must_already_be_normalized() {
        assert!(matches!(
            resolve_root(
                Some(Path::new("/home/user")),
                Some(Path::new("/state/./data"))
            ),
            Err(RootPathError::XdgStateHomeDotComponent { .. })
        ));
        assert!(matches!(
            resolve_root(
                Some(Path::new("/home/user")),
                Some(Path::new("/state/../data"))
            ),
            Err(RootPathError::XdgStateHomeParentComponent { .. })
        ));
        assert!(matches!(
            resolve_root(Some(Path::new("/home/./user")), None),
            Err(RootPathError::HomeDotComponent { .. })
        ));
        assert!(matches!(
            require_home(Some(Path::new("/home/user/../other"))),
            Err(RootPathError::HomeParentComponent { .. })
        ));
        assert_eq!(
            resolve_root(Some(Path::new("/home/user")), Some(Path::new("/state"))).unwrap(),
            PathBuf::from("/state").join(PRODUCTION_ROOT_LEAF)
        );
    }
}
