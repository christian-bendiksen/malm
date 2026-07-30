use std::{io, io::Read, io::Write};

use malm_types::Digest;
use sha2::{Digest as ShaDigest, Sha256};

use crate::{
    MAX_PACK_FILE_BYTES, MAX_PACK_OBJECT_BYTES, MAX_PACK_TREE_BYTES, MAX_PACK_TREE_ENTRIES,
    PACK_MANIFEST_FILE, PackFileV1, PackPath, PackTreeError, ValueError,
    canonical::Encoder,
    model::{
        MAX_PACK_PATH_BYTES, PACK_CONTENT_DOMAIN, encode_pack_entries, validated_pack_entries,
    },
    pack_content_digest,
};

const DOMAIN: &[u8] = PACK_CONTENT_DOMAIN;
/// Encoding version written and accepted by this module.
const ENCODING_VERSION: u16 = 1;

/// Failure to write a canonical pack object.
#[derive(Debug, thiserror::Error)]
pub enum PackObjectWriteError {
    #[error("invalid pack tree: {0}")]
    InvalidTree(#[source] PackTreeError),
    #[error("write canonical pack object: {0}")]
    Io(#[source] io::Error),
}

/// Failure to read a canonical pack object.
#[derive(Debug, thiserror::Error)]
pub enum PackObjectReadError {
    #[error("invalid pack object: {0}")]
    InvalidEncoding(&'static str),
    #[error("unsupported pack-object encoding: expected {expected}, found {found}")]
    UnsupportedVersion { expected: u16, found: u16 },
    #[error("{0}")]
    InvalidPath(#[source] ValueError),
    #[error("invalid pack tree: {0}")]
    InvalidTree(#[source] PackTreeError),
    #[error("pack-object digest mismatch: expected {expected}, computed {actual}")]
    DigestMismatch { expected: Digest, actual: Digest },
    #[error("read canonical pack object: {0}")]
    Io(#[source] io::Error),
}

/// Writes a canonical pack object and returns its SHA-256 ID.
pub fn write_pack_object_v1<W: Write>(
    files: &[PackFileV1],
    writer: &mut W,
) -> Result<Digest, PackObjectWriteError> {
    write_pack_object_entries_v1(files.iter().map(|file| (file.path(), file.bytes())), writer)
}

/// Writes a canonical pack object from borrowed entries.
pub fn write_pack_object_entries_v1<'a, W: Write>(
    entries: impl IntoIterator<Item = (&'a PackPath, &'a [u8])>,
    writer: &mut W,
) -> Result<Digest, PackObjectWriteError> {
    let entries = validated_pack_entries(entries).map_err(PackObjectWriteError::InvalidTree)?;
    // One encoder keeps the stream and digest framing identical.
    let mut encoder = Encoder::writing(DOMAIN, writer);
    encode_pack_entries(&mut encoder, &entries);
    encoder.finish_written().map_err(PackObjectWriteError::Io)
}

/// Reads, validates, and verifies a canonical pack object.
pub fn read_pack_object_v1<R: Read>(
    reader: &mut R,
    expected_digest: &Digest,
) -> Result<Vec<PackFileV1>, PackObjectReadError> {
    let mut reader = HashingReader::new(reader);
    let mut domain = vec![0_u8; DOMAIN.len()];
    reader.read_exact(&mut domain)?;
    if domain != DOMAIN {
        return Err(PackObjectReadError::InvalidEncoding("wrong domain prefix"));
    }
    let version = reader.read_u16()?;
    if version != ENCODING_VERSION {
        return Err(PackObjectReadError::UnsupportedVersion {
            expected: ENCODING_VERSION,
            found: version,
        });
    }
    let count = reader.read_u64()?;
    if count > MAX_PACK_TREE_ENTRIES as u64 {
        return Err(PackObjectReadError::InvalidTree(
            PackTreeError::TooManyEntries {
                limit: MAX_PACK_TREE_ENTRIES,
                actual: usize::try_from(count).unwrap_or(usize::MAX),
            },
        ));
    }

    let mut files = Vec::with_capacity(count as usize);
    let mut previous: Option<PackPath> = None;
    let mut total_file_bytes = 0_u64;
    for _ in 0..count {
        let path_len = reader.read_u64()?;
        if path_len == 0 || path_len > MAX_PACK_PATH_BYTES as u64 {
            return Err(PackObjectReadError::InvalidEncoding(
                "path length is outside pack/v1 limits",
            ));
        }
        let mut path_bytes = vec![0_u8; path_len as usize];
        reader.read_exact(&mut path_bytes)?;
        let path_text = std::str::from_utf8(&path_bytes)
            .map_err(|_| PackObjectReadError::InvalidEncoding("path is not UTF-8"))?;
        let path = PackPath::new(path_text).map_err(PackObjectReadError::InvalidPath)?;
        if previous.as_ref().is_some_and(|previous| previous >= &path) {
            return Err(PackObjectReadError::InvalidEncoding(
                "paths are not strictly increasing",
            ));
        }
        previous = Some(path.clone());

        let file_len = reader.read_u64()?;
        if file_len > MAX_PACK_FILE_BYTES {
            return Err(PackObjectReadError::InvalidTree(
                PackTreeError::FileTooLarge {
                    path,
                    limit: MAX_PACK_FILE_BYTES,
                    actual: file_len,
                },
            ));
        }
        total_file_bytes = total_file_bytes.saturating_add(file_len);
        if total_file_bytes > MAX_PACK_TREE_BYTES {
            return Err(PackObjectReadError::InvalidTree(
                PackTreeError::TreeTooLarge {
                    limit: MAX_PACK_TREE_BYTES,
                    actual: total_file_bytes,
                },
            ));
        }
        let file_len = usize::try_from(file_len)
            .map_err(|_| PackObjectReadError::InvalidEncoding("file length does not fit memory"))?;
        let mut bytes = vec![0_u8; file_len];
        reader.read_exact(&mut bytes)?;
        files.push(PackFileV1::new(path, bytes));
    }

    let mut trailing = [0_u8; 1];
    if reader
        .read(&mut trailing)
        .map_err(PackObjectReadError::Io)?
        != 0
    {
        return Err(PackObjectReadError::InvalidEncoding("trailing bytes"));
    }
    if reader.bytes_read() > MAX_PACK_OBJECT_BYTES {
        return Err(PackObjectReadError::InvalidEncoding(
            "encoded object exceeds its byte limit",
        ));
    }

    let actual = reader.finish();
    if &actual != expected_digest {
        return Err(PackObjectReadError::DigestMismatch {
            expected: expected_digest.clone(),
            actual,
        });
    }
    let logical = pack_content_digest(files.iter().map(|file| (file.path(), file.bytes())))
        .map_err(PackObjectReadError::InvalidTree)?;
    if &logical != expected_digest {
        return Err(PackObjectReadError::DigestMismatch {
            expected: expected_digest.clone(),
            actual: logical,
        });
    }
    if files
        .iter()
        .all(|file| file.path().as_str() != PACK_MANIFEST_FILE)
    {
        return Err(PackObjectReadError::InvalidTree(
            PackTreeError::MissingManifest,
        ));
    }
    Ok(files)
}

struct HashingReader<'a, R> {
    inner: &'a mut R,
    hasher: Sha256,
    bytes_read: u64,
}

impl<'a, R: Read> HashingReader<'a, R> {
    fn new(inner: &'a mut R) -> Self {
        Self {
            inner,
            hasher: Sha256::new(),
            bytes_read: 0,
        }
    }

    fn read_exact(&mut self, bytes: &mut [u8]) -> Result<(), PackObjectReadError> {
        self.inner.read_exact(bytes).map_err(|error| {
            if error.kind() == io::ErrorKind::UnexpectedEof {
                PackObjectReadError::InvalidEncoding("truncated object")
            } else {
                PackObjectReadError::Io(error)
            }
        })?;
        self.hasher.update(&*bytes);
        self.bytes_read = self
            .bytes_read
            .saturating_add(malm_types::usize_to_u64(bytes.len()));
        if self.bytes_read > MAX_PACK_OBJECT_BYTES {
            return Err(PackObjectReadError::InvalidEncoding(
                "encoded object exceeds its byte limit",
            ));
        }
        Ok(())
    }

    fn read_u16(&mut self) -> Result<u16, PackObjectReadError> {
        let mut bytes = [0_u8; 2];
        self.read_exact(&mut bytes)?;
        Ok(u16::from_be_bytes(bytes))
    }

    fn read_u64(&mut self) -> Result<u64, PackObjectReadError> {
        let mut bytes = [0_u8; 8];
        self.read_exact(&mut bytes)?;
        Ok(u64::from_be_bytes(bytes))
    }

    const fn bytes_read(&self) -> u64 {
        self.bytes_read
    }

    fn finish(self) -> Digest {
        Digest::from_sha256(self.hasher)
    }
}

impl<R: Read> Read for HashingReader<'_, R> {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        let read = self.inner.read(bytes)?;
        self.hasher.update(&bytes[..read]);
        self.bytes_read = self.bytes_read.saturating_add(read as u64);
        Ok(read)
    }
}
