//! Streaming decoder for the fixed Malm archive/v1 profile.
//!
//! The decoder accepts only uncompressed POSIX ustar. Callers provide a
//! [`std::io::Read`], exact payload length, and SHA-256 digest. This crate does
//! not open paths or use other system capabilities.

#![forbid(unsafe_code)]

mod decoder;
mod model;

pub use decoder::{ArchiveDecodeError, decode_archive_v1, decode_posix_ustar_v1};
pub use model::{
    ARCHIVE_DECODER_IDENTITY_V1, ARCHIVE_DECODER_NAME, ARCHIVE_DECODER_VERSION,
    ARCHIVE_SCHEMA_VERSION, ArchiveCompressionV1, ArchiveContainerV1, ArchiveDeclarationV1,
    ArchiveDecoderIdentityV1, ArchiveLimitsV1, ArchiveObjectsV1, ArchiveProvenanceV1,
    ArchiveResourceV1, CanonicalSymlinkObjectV1, CanonicalTreeObjectV1, DEFAULT_MAX_ENTRIES,
    DEFAULT_MAX_EXPANDED_FILE_BYTES, DEFAULT_MAX_FILE_BYTES, DEFAULT_MAX_METADATA_BYTES,
    DEFAULT_MAX_OBJECT_BYTES, DEFAULT_MAX_PATH_BYTES, DEFAULT_MAX_PATH_DEPTH,
    DEFAULT_MAX_PATH_SEGMENT_BYTES, DEFAULT_MAX_PAYLOAD_BYTES, DEFAULT_MAX_READ_OPERATIONS,
    DEFAULT_MAX_SYMLINK_TARGET_BYTES, DEFAULT_MAX_WORK_UNITS, DecodedArchiveV1,
};

/// Size of a POSIX ustar record.
pub const USTAR_BLOCK_BYTES: usize = 512;
