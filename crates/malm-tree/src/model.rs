use std::{collections::BTreeMap, fmt};

use malm_types::Digest;

use crate::{
    MAX_SYMLINK_TARGET_BYTES, MAX_TREE_AGGREGATE_FILE_BYTES, MAX_TREE_ENTRIES, MAX_TREE_FILE_BYTES,
    MAX_TREE_SEGMENT_BYTES,
};

/// Fixed mode for a safe relative symlink entry.
pub const NORMALIZED_SYMLINK_MODE: u32 = 0o777;

/// The kind of bounded UTF-8 value rejected by the tree model.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TreeValueKindV1 {
    PathSegment,
    SymlinkTarget,
}

impl fmt::Display for TreeValueKindV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::PathSegment => "tree path segment",
            Self::SymlinkTarget => "symlink target",
        })
    }
}

/// Failure to construct a bounded UTF-8 tree value.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
#[error("invalid {kind} ({value_len} bytes): {reason}")]
pub struct TreeValueError {
    kind: TreeValueKindV1,
    value_len: usize,
    reason: &'static str,
}

impl TreeValueError {
    fn new(kind: TreeValueKindV1, value_len: usize, reason: &'static str) -> Self {
        Self {
            kind,
            value_len,
            reason,
        }
    }

    #[must_use]
    pub const fn kind(&self) -> TreeValueKindV1 {
        self.kind
    }

    #[must_use]
    pub const fn value_len(&self) -> usize {
        self.value_len
    }

    #[must_use]
    pub const fn reason(&self) -> &'static str {
        self.reason
    }
}

/// A UTF-8 child name in a canonical tree object.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct TreePathSegmentV1(String);

impl TreePathSegmentV1 {
    /// Validates a complete child name.
    pub fn new(value: impl Into<String>) -> Result<Self, TreeValueError> {
        let value = value.into();
        validate_path_segment(&value)?;
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    #[must_use]
    pub fn into_inner(self) -> String {
        self.0
    }
}

impl fmt::Display for TreePathSegmentV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl AsRef<str> for TreePathSegmentV1 {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

/// A canonical object containing a symlink's UTF-8 target.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SymlinkObjectV1 {
    target: String,
}

impl SymlinkObjectV1 {
    /// Validates the scalar bounds on a symlink target.
    ///
    /// Relative-path safety is contextual and is enforced by [`crate::TreeGraphV1`].
    pub fn new(target: impl Into<String>) -> Result<Self, TreeValueError> {
        let target = target.into();
        validate_symlink_target(&target)?;
        Ok(Self { target })
    }

    #[must_use]
    pub fn target(&self) -> &str {
        &self.target
    }

    #[must_use]
    pub fn into_target(self) -> String {
        self.target
    }
}

/// A logical node category with mode validation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TreeNodeKindV1 {
    RootDirectory,
    File,
    Directory,
    SafeRelativeSymlink,
}

impl fmt::Display for TreeNodeKindV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::RootDirectory => "root directory",
            Self::File => "file",
            Self::Directory => "directory",
            Self::SafeRelativeSymlink => "safe relative symlink",
        })
    }
}

/// The object referenced by a direct child entry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TreeEntryKindV1 {
    /// A file blob and its exact byte length.
    File { digest: Digest, byte_len: u64 },
    /// A canonical child tree.
    Directory { digest: Digest },
    /// A symlink admitted only after graph safety validation.
    SafeRelativeSymlink { digest: Digest },
}

impl TreeEntryKindV1 {
    #[must_use]
    pub const fn digest(&self) -> &Digest {
        match self {
            Self::File { digest, .. }
            | Self::Directory { digest }
            | Self::SafeRelativeSymlink { digest } => digest,
        }
    }

    /// Returns the file length, if this is a file entry.
    #[must_use]
    pub const fn file_byte_len(&self) -> Option<u64> {
        match self {
            Self::File { byte_len, .. } => Some(*byte_len),
            Self::Directory { .. } | Self::SafeRelativeSymlink { .. } => None,
        }
    }

    #[must_use]
    pub const fn node_kind(&self) -> TreeNodeKindV1 {
        match self {
            Self::File { .. } => TreeNodeKindV1::File,
            Self::Directory { .. } => TreeNodeKindV1::Directory,
            Self::SafeRelativeSymlink { .. } => TreeNodeKindV1::SafeRelativeSymlink,
        }
    }
}

/// A direct child in a canonical tree object.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TreeEntryV1 {
    name: TreePathSegmentV1,
    mode: u32,
    kind: TreeEntryKindV1,
}

impl TreeEntryV1 {
    /// Creates a file entry with a normalized permission-only mode.
    pub fn file(
        name: TreePathSegmentV1,
        mode: u32,
        digest: Digest,
        byte_len: u64,
    ) -> Result<Self, TreeValidationError> {
        let entry = Self {
            name,
            mode,
            kind: TreeEntryKindV1::File { digest, byte_len },
        };
        validate_entry(&entry)?;
        Ok(entry)
    }

    /// Creates a directory entry with a normalized permission-only mode.
    pub fn directory(
        name: TreePathSegmentV1,
        mode: u32,
        digest: Digest,
    ) -> Result<Self, TreeValidationError> {
        let entry = Self {
            name,
            mode,
            kind: TreeEntryKindV1::Directory { digest },
        };
        validate_entry(&entry)?;
        Ok(entry)
    }

    /// Creates a safe relative symlink with its fixed mode.
    #[must_use]
    pub fn safe_relative_symlink(name: TreePathSegmentV1, digest: Digest) -> Self {
        Self {
            name,
            mode: NORMALIZED_SYMLINK_MODE,
            kind: TreeEntryKindV1::SafeRelativeSymlink { digest },
        }
    }

    #[must_use]
    pub const fn name(&self) -> &TreePathSegmentV1 {
        &self.name
    }

    #[must_use]
    pub const fn mode(&self) -> u32 {
        self.mode
    }

    #[must_use]
    pub const fn kind(&self) -> &TreeEntryKindV1 {
        &self.kind
    }
}

/// A canonical directory and its sorted direct children.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TreeObjectV1 {
    root_mode: u32,
    entries: Vec<TreeEntryV1>,
}

impl TreeObjectV1 {
    /// Validates and sorts direct entries by their UTF-8 bytes.
    pub fn new(root_mode: u32, mut entries: Vec<TreeEntryV1>) -> Result<Self, TreeValidationError> {
        validate_directory_mode(TreeNodeKindV1::RootDirectory, root_mode)?;
        if entries.len() > MAX_TREE_ENTRIES {
            return Err(TreeValidationError::TooManyEntries {
                limit: MAX_TREE_ENTRIES,
                actual: entries.len(),
            });
        }
        for entry in &entries {
            validate_entry(entry)?;
        }
        entries.sort_by(|left, right| left.name.cmp(&right.name));
        for pair in entries.windows(2) {
            if pair[0].name == pair[1].name {
                return Err(TreeValidationError::DuplicateName(pair[0].name.clone()));
            }
        }
        validate_file_lengths(&entries)?;
        Ok(Self { root_mode, entries })
    }

    #[must_use]
    pub const fn root_mode(&self) -> u32 {
        self.root_mode
    }

    /// Returns children in canonical UTF-8 byte order.
    #[must_use]
    pub fn entries(&self) -> &[TreeEntryV1] {
        &self.entries
    }
}

/// An invalid tree structure, mode, or resource declaration.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
#[non_exhaustive]
pub enum TreeValidationError {
    #[error("unsupported {kind} mode {mode:#o}")]
    UnsupportedMode { kind: TreeNodeKindV1, mode: u32 },
    #[error("tree has {actual} entries; limit is {limit}")]
    TooManyEntries { limit: usize, actual: usize },
    #[error("duplicate tree child {0:?}")]
    DuplicateName(TreePathSegmentV1),
    #[error("tree file {name:?} declares {actual} bytes; limit is {limit}")]
    FileTooLarge {
        name: TreePathSegmentV1,
        limit: u64,
        actual: u64,
    },
    #[error("tree declares {actual} aggregate file bytes; limit is {limit}")]
    AggregateFileBytesExceeded { limit: u64, actual: u64 },
    #[error("zero-byte tree file {name:?} has noncanonical object digest {actual}")]
    EmptyFileDigest {
        name: TreePathSegmentV1,
        actual: Digest,
    },
    #[error("file object {digest} has conflicting lengths {first} and {second}")]
    ConflictingFileLength {
        digest: Digest,
        first: u64,
        second: u64,
    },
}

pub(crate) fn validate_entry(entry: &TreeEntryV1) -> Result<(), TreeValidationError> {
    match &entry.kind {
        TreeEntryKindV1::File { digest, byte_len } => {
            validate_file_mode(entry.mode)?;
            if *byte_len > MAX_TREE_FILE_BYTES {
                return Err(TreeValidationError::FileTooLarge {
                    name: entry.name.clone(),
                    limit: MAX_TREE_FILE_BYTES,
                    actual: *byte_len,
                });
            }
            if *byte_len == 0
                && digest
                    != &crate::file_object_digest_v1(&[])
                        .expect("empty file is within the canonical object bound")
            {
                return Err(TreeValidationError::EmptyFileDigest {
                    name: entry.name.clone(),
                    actual: digest.clone(),
                });
            }
        }
        TreeEntryKindV1::Directory { .. } => {
            validate_directory_mode(TreeNodeKindV1::Directory, entry.mode)?;
        }
        TreeEntryKindV1::SafeRelativeSymlink { .. } if entry.mode != NORMALIZED_SYMLINK_MODE => {
            return Err(TreeValidationError::UnsupportedMode {
                kind: TreeNodeKindV1::SafeRelativeSymlink,
                mode: entry.mode,
            });
        }
        TreeEntryKindV1::SafeRelativeSymlink { .. } => {}
    }
    Ok(())
}

fn validate_file_lengths(entries: &[TreeEntryV1]) -> Result<(), TreeValidationError> {
    let mut total = 0_u64;
    let mut lengths = BTreeMap::new();
    for entry in entries {
        let TreeEntryKindV1::File { digest, byte_len } = &entry.kind else {
            continue;
        };
        total = total.saturating_add(*byte_len);
        if total > MAX_TREE_AGGREGATE_FILE_BYTES {
            return Err(TreeValidationError::AggregateFileBytesExceeded {
                limit: MAX_TREE_AGGREGATE_FILE_BYTES,
                actual: total,
            });
        }
        if let Some(first) = lengths.insert(digest, *byte_len)
            && first != *byte_len
        {
            return Err(TreeValidationError::ConflictingFileLength {
                digest: digest.clone(),
                first,
                second: *byte_len,
            });
        }
    }
    Ok(())
}

fn validate_file_mode(mode: u32) -> Result<(), TreeValidationError> {
    if mode & !0o777 != 0 || mode & 0o400 == 0 {
        return Err(TreeValidationError::UnsupportedMode {
            kind: TreeNodeKindV1::File,
            mode,
        });
    }
    Ok(())
}

pub(crate) fn validate_directory_mode(
    kind: TreeNodeKindV1,
    mode: u32,
) -> Result<(), TreeValidationError> {
    if mode & !0o777 != 0 || mode & 0o500 != 0o500 {
        return Err(TreeValidationError::UnsupportedMode { kind, mode });
    }
    Ok(())
}

fn validate_path_segment(value: &str) -> Result<(), TreeValueError> {
    let invalid = |reason| TreeValueError::new(TreeValueKindV1::PathSegment, value.len(), reason);
    if value.is_empty() {
        return Err(invalid("must not be empty"));
    }
    if value.len() > MAX_TREE_SEGMENT_BYTES {
        return Err(invalid("must be at most 255 bytes"));
    }
    if matches!(value, "." | "..") {
        return Err(invalid("must not be dot or dot-dot"));
    }
    if value.contains('/') {
        return Err(invalid("must not contain slash"));
    }
    if value.contains('\\') {
        return Err(invalid("must not contain backslash"));
    }
    if value.chars().any(char::is_control) {
        return Err(invalid("must not contain control characters"));
    }
    Ok(())
}

fn validate_symlink_target(value: &str) -> Result<(), TreeValueError> {
    let invalid = |reason| TreeValueError::new(TreeValueKindV1::SymlinkTarget, value.len(), reason);
    if value.is_empty() {
        return Err(invalid("must not be empty"));
    }
    if value.len() > MAX_SYMLINK_TARGET_BYTES {
        return Err(invalid("must be at most 4096 bytes"));
    }
    if value.chars().any(char::is_control) {
        return Err(invalid("must not contain NUL or control characters"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn segment(value: &str) -> TreePathSegmentV1 {
        TreePathSegmentV1::new(value).unwrap()
    }

    #[test]
    fn scalar_boundaries_use_utf8_bytes_and_reject_ambiguous_names() {
        assert!(TreePathSegmentV1::new("a".repeat(MAX_TREE_SEGMENT_BYTES)).is_ok());
        assert!(TreePathSegmentV1::new("a".repeat(MAX_TREE_SEGMENT_BYTES + 1)).is_err());
        assert!(TreePathSegmentV1::new("é".repeat(127)).is_ok());
        assert!(TreePathSegmentV1::new("é".repeat(128)).is_err());
        for invalid in ["", ".", "..", "a/b", "a\\b", "a\0b", "a\u{85}b"] {
            assert!(
                TreePathSegmentV1::new(invalid).is_err(),
                "accepted {invalid:?}"
            );
        }

        assert!(SymlinkObjectV1::new("x".repeat(MAX_SYMLINK_TARGET_BYTES)).is_ok());
        assert!(SymlinkObjectV1::new("x".repeat(MAX_SYMLINK_TARGET_BYTES + 1)).is_err());
        for invalid in ["", "bad\0target", "bad\nline", "bad\u{85}target"] {
            assert!(SymlinkObjectV1::new(invalid).is_err());
        }
    }

    #[test]
    fn tree_constructor_sorts_and_rejects_duplicate_or_unsupported_entries() {
        let empty = crate::file_object_digest_v1(&[]).unwrap();
        let b = TreeEntryV1::file(segment("b"), 0o644, empty.clone(), 0).unwrap();
        let a = TreeEntryV1::file(segment("a"), 0o600, empty.clone(), 0).unwrap();
        let tree = TreeObjectV1::new(0o755, vec![b, a.clone()]).unwrap();
        assert_eq!(tree.entries()[0].name().as_str(), "a");
        assert_eq!(tree.entries()[1].name().as_str(), "b");
        assert!(matches!(
            TreeObjectV1::new(0o755, vec![a.clone(), a]),
            Err(TreeValidationError::DuplicateName(_))
        ));
        assert!(TreeObjectV1::new(0o4755, vec![]).is_err());
        assert!(TreeEntryV1::file(segment("bad"), 0o200, empty, 0).is_err());
        assert!(TreeEntryV1::directory(segment("bad"), 0o600, Digest::sha256(b"tree")).is_err());
    }

    #[test]
    fn file_and_local_aggregate_limits_are_closed() {
        let digest = Digest::sha256(b"large object identity");
        assert!(
            TreeEntryV1::file(segment("large"), 0o644, digest.clone(), MAX_TREE_FILE_BYTES).is_ok()
        );
        assert!(matches!(
            TreeEntryV1::file(
                segment("too-large"),
                0o644,
                digest.clone(),
                MAX_TREE_FILE_BYTES + 1
            ),
            Err(TreeValidationError::FileTooLarge { .. })
        ));
        let first = TreeEntryV1::file(
            segment("first"),
            0o644,
            digest,
            MAX_TREE_AGGREGATE_FILE_BYTES,
        )
        .unwrap();
        let second = TreeEntryV1::file(segment("second"), 0o644, Digest::sha256(b"x"), 1).unwrap();
        assert!(matches!(
            TreeObjectV1::new(0o755, vec![first, second]),
            Err(TreeValidationError::AggregateFileBytesExceeded { .. })
        ));
    }
}
