use std::{fmt, str};

use malm_types::Digest;

use crate::{
    MAX_FILE_OBJECT_BYTES, MAX_SYMLINK_OBJECT_BYTES, MAX_SYMLINK_TARGET_BYTES, MAX_TREE_ENTRIES,
    MAX_TREE_FILE_BYTES, MAX_TREE_OBJECT_BYTES, MAX_TREE_SEGMENT_BYTES, NORMALIZED_SYMLINK_MODE,
    SymlinkObjectV1, TREE_OBJECT_ENCODING_VERSION, TreeEntryKindV1, TreeEntryV1, TreeNodeKindV1,
    TreeObjectV1, TreePathSegmentV1, TreeValidationError, TreeValueError,
};

const FILE_DOMAIN: &[u8] = b"malm-file-object\0";
const SYMLINK_DOMAIN: &[u8] = b"malm-symlink-object\0";
const TREE_DOMAIN: &[u8] = b"malm-tree-object\0";
const DIGEST_TEXT_BYTES: usize = 71;
const FILE_TAG: u8 = 0;
const DIRECTORY_TAG: u8 = 1;
const SAFE_RELATIVE_SYMLINK_TAG: u8 = 2;

/// Canonical object category used in decoder errors.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ObjectKindV1 {
    File,
    Symlink,
    Tree,
}

impl fmt::Display for ObjectKindV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::File => "file object",
            Self::Symlink => "symlink object",
            Self::Tree => "tree object",
        })
    }
}

/// Encodes file bytes as a domain-separated canonical object.
pub fn encode_file_object_v1(bytes: &[u8]) -> Result<Vec<u8>, ObjectReadError> {
    if bytes.len() > MAX_TREE_FILE_BYTES as usize {
        return Err(ObjectReadError::TooLarge {
            object: ObjectKindV1::File,
            limit: MAX_TREE_FILE_BYTES as usize,
            actual: bytes.len(),
        });
    }
    let mut encoder = Encoder::new(FILE_DOMAIN);
    encoder.u64(bytes.len() as u64);
    encoder.raw(bytes);
    Ok(encoder.finish())
}

/// Computes a file object's SHA-256 ID.
pub fn file_object_digest_v1(bytes: &[u8]) -> Result<Digest, ObjectReadError> {
    encode_file_object_v1(bytes).map(Digest::sha256)
}

/// Decodes canonical domain-separated file object bytes.
pub fn decode_file_object_v1(bytes: &[u8]) -> Result<&[u8], ObjectReadError> {
    preflight_size(ObjectKindV1::File, bytes.len(), MAX_FILE_OBJECT_BYTES)?;
    let mut reader = Reader::new(ObjectKindV1::File, bytes);
    reader.domain(FILE_DOMAIN)?;
    reader.version()?;
    let length = reader.u64()?;
    if length > MAX_TREE_FILE_BYTES {
        return Err(ObjectReadError::TooLarge {
            object: ObjectKindV1::File,
            limit: MAX_TREE_FILE_BYTES as usize,
            actual: usize::try_from(length).unwrap_or(usize::MAX),
        });
    }
    let contents =
        reader.take(
            usize::try_from(length).map_err(|_| ObjectReadError::TooLarge {
                object: ObjectKindV1::File,
                limit: MAX_TREE_FILE_BYTES as usize,
                actual: usize::MAX,
            })?,
        )?;
    reader.end()?;
    Ok(contents)
}

/// Decodes canonical file bytes and verifies the expected object ID.
pub fn decode_verified_file_object_v1<'a>(
    expected: &Digest,
    bytes: &'a [u8],
) -> Result<&'a [u8], ObjectReadError> {
    decode_verified(ObjectKindV1::File, expected, bytes, decode_file_object_v1)
}

/// A canonical object decoding failure.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
#[non_exhaustive]
pub enum ObjectReadError {
    #[error("{object} is {actual} bytes; limit is {limit}")]
    TooLarge {
        object: ObjectKindV1,
        limit: usize,
        actual: usize,
    },
    #[error("truncated {object}")]
    Truncated { object: ObjectKindV1 },
    #[error("invalid {object}: {reason}")]
    InvalidEncoding {
        object: ObjectKindV1,
        reason: &'static str,
    },
    #[error("unsupported {object} encoding {found}; expected {expected}")]
    UnsupportedVersion {
        object: ObjectKindV1,
        expected: u16,
        found: u16,
    },
    #[error("{0}")]
    InvalidValue(#[source] TreeValueError),
    #[error("invalid tree object: {0}")]
    InvalidTree(#[source] TreeValidationError),
    #[error("{object} digest mismatch: expected {expected}, computed {actual}")]
    DigestMismatch {
        object: ObjectKindV1,
        expected: Digest,
        actual: Digest,
    },
}

/// Encodes a symlink as domain-separated canonical bytes.
#[must_use]
pub fn encode_symlink_object_v1(object: &SymlinkObjectV1) -> Vec<u8> {
    let mut encoder = Encoder::new(SYMLINK_DOMAIN);
    encoder.text(object.target());
    encoder.finish()
}

/// Computes a symlink object's SHA-256 ID.
#[must_use]
pub fn symlink_object_digest_v1(object: &SymlinkObjectV1) -> Digest {
    Digest::sha256(encode_symlink_object_v1(object))
}

/// Decodes canonical domain-separated symlink object bytes.
pub fn decode_symlink_object_v1(bytes: &[u8]) -> Result<SymlinkObjectV1, ObjectReadError> {
    preflight_size(ObjectKindV1::Symlink, bytes.len(), MAX_SYMLINK_OBJECT_BYTES)?;
    let mut reader = Reader::new(ObjectKindV1::Symlink, bytes);
    reader.domain(SYMLINK_DOMAIN)?;
    reader.version()?;
    let target = reader.text(MAX_SYMLINK_TARGET_BYTES, "symlink target is too long")?;
    let target =
        str::from_utf8(target).map_err(|_| reader.invalid("symlink target is not UTF-8"))?;
    let object = SymlinkObjectV1::new(target).map_err(ObjectReadError::InvalidValue)?;
    reader.end()?;
    check_canonical(
        ObjectKindV1::Symlink,
        &encode_symlink_object_v1(&object),
        bytes,
    )?;
    Ok(object)
}

/// Decodes canonical symlink bytes and verifies the expected object ID.
pub fn decode_verified_symlink_object_v1(
    expected: &Digest,
    bytes: &[u8],
) -> Result<SymlinkObjectV1, ObjectReadError> {
    decode_verified(
        ObjectKindV1::Symlink,
        expected,
        bytes,
        decode_symlink_object_v1,
    )
}

/// Encodes a tree as domain-separated canonical bytes.
#[must_use]
pub fn encode_tree_object_v1(object: &TreeObjectV1) -> Vec<u8> {
    let mut encoder = Encoder::new(TREE_DOMAIN);
    encoder.u32(object.root_mode());
    encoder.u64(malm_types::usize_to_u64(object.entries().len()));
    for entry in object.entries() {
        encoder.text(entry.name().as_str());
        let tag = match entry.kind() {
            TreeEntryKindV1::File { .. } => FILE_TAG,
            TreeEntryKindV1::Directory { .. } => DIRECTORY_TAG,
            TreeEntryKindV1::SafeRelativeSymlink { .. } => SAFE_RELATIVE_SYMLINK_TAG,
        };
        encoder.u8(tag);
        encoder.u32(entry.mode());
        encoder.text(entry.kind().digest().as_str());
        if let TreeEntryKindV1::File { byte_len, .. } = entry.kind() {
            encoder.u64(*byte_len);
        }
    }
    encoder.finish()
}

/// Computes a tree object's SHA-256 ID.
#[must_use]
pub fn tree_object_digest_v1(object: &TreeObjectV1) -> Digest {
    Digest::sha256(encode_tree_object_v1(object))
}

/// Decodes canonical domain-separated tree object bytes.
pub fn decode_tree_object_v1(bytes: &[u8]) -> Result<TreeObjectV1, ObjectReadError> {
    preflight_size(ObjectKindV1::Tree, bytes.len(), MAX_TREE_OBJECT_BYTES)?;
    let mut reader = Reader::new(ObjectKindV1::Tree, bytes);
    reader.domain(TREE_DOMAIN)?;
    reader.version()?;
    let root_mode = reader.u32()?;
    let count = reader.u64()?;
    if count > MAX_TREE_ENTRIES as u64 {
        return Err(ObjectReadError::InvalidTree(
            TreeValidationError::TooManyEntries {
                limit: MAX_TREE_ENTRIES,
                actual: usize::try_from(count).unwrap_or(usize::MAX),
            },
        ));
    }

    let mut entries = Vec::with_capacity(count as usize);
    let mut previous: Option<TreePathSegmentV1> = None;
    for _ in 0..count {
        let name = reader.text(MAX_TREE_SEGMENT_BYTES, "tree path segment is too long")?;
        let name =
            str::from_utf8(name).map_err(|_| reader.invalid("tree path segment is not UTF-8"))?;
        let name = TreePathSegmentV1::new(name).map_err(ObjectReadError::InvalidValue)?;
        if previous.as_ref().is_some_and(|previous| previous >= &name) {
            return Err(reader.invalid("entries are not strictly ordered by UTF-8 name bytes"));
        }
        previous = Some(name.clone());

        let tag = reader.u8()?;
        let mode = reader.u32()?;
        let digest = reader.digest()?;
        let entry = match tag {
            FILE_TAG => {
                let byte_len = reader.u64()?;
                TreeEntryV1::file(name, mode, digest, byte_len)
                    .map_err(ObjectReadError::InvalidTree)?
            }
            DIRECTORY_TAG => {
                TreeEntryV1::directory(name, mode, digest).map_err(ObjectReadError::InvalidTree)?
            }
            SAFE_RELATIVE_SYMLINK_TAG if mode == NORMALIZED_SYMLINK_MODE => {
                TreeEntryV1::safe_relative_symlink(name, digest)
            }
            SAFE_RELATIVE_SYMLINK_TAG => {
                return Err(ObjectReadError::InvalidTree(
                    TreeValidationError::UnsupportedMode {
                        kind: TreeNodeKindV1::SafeRelativeSymlink,
                        mode,
                    },
                ));
            }
            _ => {
                return Err(reader.invalid("unknown tree entry tag"));
            }
        };
        entries.push(entry);
    }
    reader.end()?;
    let object = TreeObjectV1::new(root_mode, entries).map_err(ObjectReadError::InvalidTree)?;
    check_canonical(ObjectKindV1::Tree, &encode_tree_object_v1(&object), bytes)?;
    Ok(object)
}

/// Decodes canonical tree bytes and verifies the expected object ID.
pub fn decode_verified_tree_object_v1(
    expected: &Digest,
    bytes: &[u8],
) -> Result<TreeObjectV1, ObjectReadError> {
    decode_verified(ObjectKindV1::Tree, expected, bytes, decode_tree_object_v1)
}

fn decode_verified<'a, T>(
    object: ObjectKindV1,
    expected: &Digest,
    bytes: &'a [u8],
    decode: fn(&'a [u8]) -> Result<T, ObjectReadError>,
) -> Result<T, ObjectReadError> {
    let value = decode(bytes)?;
    verify_digest(object, expected, bytes)?;
    Ok(value)
}

fn check_canonical(
    object: ObjectKindV1,
    canonical: &[u8],
    bytes: &[u8],
) -> Result<(), ObjectReadError> {
    if canonical == bytes {
        Ok(())
    } else {
        Err(ObjectReadError::InvalidEncoding {
            object,
            reason: "bytes are not canonical",
        })
    }
}

fn preflight_size(
    object: ObjectKindV1,
    actual: usize,
    limit: usize,
) -> Result<(), ObjectReadError> {
    if actual > limit {
        Err(ObjectReadError::TooLarge {
            object,
            limit,
            actual,
        })
    } else {
        Ok(())
    }
}

fn verify_digest(
    object: ObjectKindV1,
    expected: &Digest,
    bytes: &[u8],
) -> Result<(), ObjectReadError> {
    let actual = Digest::sha256(bytes);
    if &actual == expected {
        Ok(())
    } else {
        Err(ObjectReadError::DigestMismatch {
            object,
            expected: expected.clone(),
            actual,
        })
    }
}

struct Encoder {
    bytes: Vec<u8>,
}

impl Encoder {
    fn new(domain: &[u8]) -> Self {
        let mut encoder = Self { bytes: Vec::new() };
        encoder.raw(domain);
        encoder.u16(TREE_OBJECT_ENCODING_VERSION);
        encoder
    }

    fn finish(self) -> Vec<u8> {
        self.bytes
    }

    fn raw(&mut self, bytes: &[u8]) {
        self.bytes.extend_from_slice(bytes);
    }

    fn u8(&mut self, value: u8) {
        self.bytes.push(value);
    }

    fn u16(&mut self, value: u16) {
        self.raw(&value.to_be_bytes());
    }

    fn u32(&mut self, value: u32) {
        self.raw(&value.to_be_bytes());
    }

    fn u64(&mut self, value: u64) {
        self.raw(&value.to_be_bytes());
    }

    fn text(&mut self, value: &str) {
        self.u64(malm_types::usize_to_u64(value.len()));
        self.raw(value.as_bytes());
    }
}

struct Reader<'a> {
    object: ObjectKindV1,
    remaining: &'a [u8],
}

impl<'a> Reader<'a> {
    const fn new(object: ObjectKindV1, bytes: &'a [u8]) -> Self {
        Self {
            object,
            remaining: bytes,
        }
    }

    const fn invalid(&self, reason: &'static str) -> ObjectReadError {
        ObjectReadError::InvalidEncoding {
            object: self.object,
            reason,
        }
    }

    fn domain(&mut self, expected: &[u8]) -> Result<(), ObjectReadError> {
        let actual = self.take(expected.len())?;
        if actual == expected {
            Ok(())
        } else {
            Err(self.invalid("wrong domain prefix"))
        }
    }

    fn version(&mut self) -> Result<(), ObjectReadError> {
        let found = self.u16()?;
        if found == TREE_OBJECT_ENCODING_VERSION {
            Ok(())
        } else {
            Err(ObjectReadError::UnsupportedVersion {
                object: self.object,
                expected: TREE_OBJECT_ENCODING_VERSION,
                found,
            })
        }
    }

    fn end(&self) -> Result<(), ObjectReadError> {
        if self.remaining.is_empty() {
            Ok(())
        } else {
            Err(self.invalid("trailing bytes"))
        }
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], ObjectReadError> {
        if self.remaining.len() < len {
            return Err(ObjectReadError::Truncated {
                object: self.object,
            });
        }
        let (value, remaining) = self.remaining.split_at(len);
        self.remaining = remaining;
        Ok(value)
    }

    fn u8(&mut self) -> Result<u8, ObjectReadError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, ObjectReadError> {
        let bytes: [u8; 2] = self.take(2)?.try_into().expect("exact u16 width");
        Ok(u16::from_be_bytes(bytes))
    }

    fn u32(&mut self) -> Result<u32, ObjectReadError> {
        let bytes: [u8; 4] = self.take(4)?.try_into().expect("exact u32 width");
        Ok(u32::from_be_bytes(bytes))
    }

    fn u64(&mut self) -> Result<u64, ObjectReadError> {
        let bytes: [u8; 8] = self.take(8)?.try_into().expect("exact u64 width");
        Ok(u64::from_be_bytes(bytes))
    }

    fn text(
        &mut self,
        maximum: usize,
        too_long: &'static str,
    ) -> Result<&'a [u8], ObjectReadError> {
        let len = self.u64()?;
        if len > maximum as u64 {
            return Err(self.invalid(too_long));
        }
        self.take(len as usize)
    }

    fn digest(&mut self) -> Result<Digest, ObjectReadError> {
        let bytes = self.text(DIGEST_TEXT_BYTES, "entry digest is too long")?;
        if bytes.len() != DIGEST_TEXT_BYTES {
            return Err(self.invalid("entry digest has the wrong length"));
        }
        let value = str::from_utf8(bytes).map_err(|_| self.invalid("entry digest is not UTF-8"))?;
        Digest::new(value).map_err(|_| self.invalid("entry digest is not canonical SHA-256"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn segment(value: &str) -> TreePathSegmentV1 {
        TreePathSegmentV1::new(value).unwrap()
    }

    #[test]
    fn canonical_objects_round_trip_and_bind_domains() {
        let symlink = SymlinkObjectV1::new("bin/tool").unwrap();
        let symlink_bytes = encode_symlink_object_v1(&symlink);
        assert_eq!(decode_symlink_object_v1(&symlink_bytes).unwrap(), symlink);

        let tree = TreeObjectV1::new(
            0o755,
            vec![TreeEntryV1::safe_relative_symlink(
                segment("tool"),
                symlink_object_digest_v1(&symlink),
            )],
        )
        .unwrap();
        let tree_bytes = encode_tree_object_v1(&tree);
        assert_eq!(decode_tree_object_v1(&tree_bytes).unwrap(), tree);
        assert_ne!(Digest::sha256(&symlink_bytes), Digest::sha256(&tree_bytes));
    }

    #[test]
    fn decoders_reject_trailing_truncated_unsupported_and_wrong_identity() {
        let object = SymlinkObjectV1::new("target").unwrap();
        let bytes = encode_symlink_object_v1(&object);
        assert!(matches!(
            decode_symlink_object_v1(&bytes[..bytes.len() - 1]),
            Err(ObjectReadError::Truncated { .. })
        ));
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(matches!(
            decode_symlink_object_v1(&trailing),
            Err(ObjectReadError::InvalidEncoding {
                reason: "trailing bytes",
                ..
            })
        ));
        let mut unsupported = bytes.clone();
        unsupported[SYMLINK_DOMAIN.len()..SYMLINK_DOMAIN.len() + 2]
            .copy_from_slice(&2_u16.to_be_bytes());
        assert!(matches!(
            decode_symlink_object_v1(&unsupported),
            Err(ObjectReadError::UnsupportedVersion { found: 2, .. })
        ));
        assert!(matches!(
            decode_verified_symlink_object_v1(&Digest::sha256(b"wrong"), &bytes),
            Err(ObjectReadError::DigestMismatch { .. })
        ));
    }
}
