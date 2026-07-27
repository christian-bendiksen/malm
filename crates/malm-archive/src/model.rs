use std::collections::BTreeMap;

use malm_tree::{SymlinkObjectV1, TreeGraphV1, TreeObjectV1};
use malm_types::Digest;

/// Supported declaration and provenance schema version.
pub const ARCHIVE_SCHEMA_VERSION: u16 = 1;
/// Stable name of the trusted built-in decoder.
pub const ARCHIVE_DECODER_NAME: &str = "malm.posix-ustar.none";
/// Frozen behavior version of the trusted built-in decoder.
pub const ARCHIVE_DECODER_VERSION: u16 = 1;

/// Default maximum payload length, 384 MiB.
pub const DEFAULT_MAX_PAYLOAD_BYTES: u64 = 384 * 1024 * 1024;
/// Default maximum bytes in a regular-file entry.
pub const DEFAULT_MAX_FILE_BYTES: u64 = malm_tree::MAX_TREE_FILE_BYTES;
/// Default maximum total logical file bytes.
pub const DEFAULT_MAX_EXPANDED_FILE_BYTES: u64 = malm_tree::MAX_TREE_AGGREGATE_FILE_BYTES;
/// Default maximum entries, including synthesized parent directories.
pub const DEFAULT_MAX_ENTRIES: u64 = malm_tree::MAX_TREE_ENTRIES as u64;
/// Default maximum UTF-8 bytes in a logical path.
pub const DEFAULT_MAX_PATH_BYTES: u64 = malm_tree::MAX_TREE_PATH_BYTES as u64;
/// Default maximum components in a logical path.
pub const DEFAULT_MAX_PATH_DEPTH: u64 = malm_tree::MAX_TREE_DEPTH as u64;
/// Default maximum UTF-8 bytes in a path component.
pub const DEFAULT_MAX_PATH_SEGMENT_BYTES: u64 = malm_tree::MAX_TREE_SEGMENT_BYTES as u64;
/// Default maximum UTF-8 bytes in a symlink target.
pub const DEFAULT_MAX_SYMLINK_TARGET_BYTES: u64 = malm_tree::MAX_SYMLINK_TARGET_BYTES as u64;
/// Default maximum ustar header metadata, 64 MiB.
pub const DEFAULT_MAX_METADATA_BYTES: u64 = 64 * 1024 * 1024;
/// Default maximum retained canonical object bytes, 384 MiB.
pub const DEFAULT_MAX_OBJECT_BYTES: u64 = 384 * 1024 * 1024;
/// Default maximum `Read` calls, including the final EOF probe.
pub const DEFAULT_MAX_READ_OPERATIONS: u64 = DEFAULT_MAX_PAYLOAD_BYTES + 1;
/// Default decoder work budget.
pub const DEFAULT_MAX_WORK_UNITS: u64 = 10_000_000;

/// Containers supported by archive/v1.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ArchiveContainerV1 {
    /// POSIX ustar in a tar stream.
    Tar,
}

impl ArchiveContainerV1 {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Tar => "tar",
        }
    }
}

/// Compression methods supported by archive/v1.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ArchiveCompressionV1 {
    /// An uncompressed ustar stream.
    None,
}

impl ArchiveCompressionV1 {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
        }
    }
}

/// Stable decoder implementation identity persisted in archive provenance.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ArchiveDecoderIdentityV1 {
    name: &'static str,
    version: u16,
}

impl ArchiveDecoderIdentityV1 {
    #[must_use]
    pub const fn name(self) -> &'static str {
        self.name
    }

    #[must_use]
    pub const fn version(self) -> u16 {
        self.version
    }
}

/// Identity of the sole archive/v1 decoder.
pub const ARCHIVE_DECODER_IDENTITY_V1: ArchiveDecoderIdentityV1 = ArchiveDecoderIdentityV1 {
    name: ARCHIVE_DECODER_NAME,
    version: ARCHIVE_DECODER_VERSION,
};

/// Exact, digest-pinned declaration granted to the trusted decoder.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArchiveDeclarationV1 {
    container: ArchiveContainerV1,
    compression: ArchiveCompressionV1,
    decoder_version: u16,
    payload_byte_len: u64,
    payload_digest: Digest,
}

impl ArchiveDeclarationV1 {
    /// Declares an exact uncompressed POSIX ustar payload.
    #[must_use]
    pub fn posix_ustar(payload_byte_len: u64, payload_digest: Digest) -> Self {
        Self {
            container: ArchiveContainerV1::Tar,
            compression: ArchiveCompressionV1::None,
            decoder_version: ARCHIVE_DECODER_VERSION,
            payload_byte_len,
            payload_digest,
        }
    }

    #[must_use]
    pub const fn schema_version(&self) -> u16 {
        ARCHIVE_SCHEMA_VERSION
    }

    #[must_use]
    pub const fn container(&self) -> ArchiveContainerV1 {
        self.container
    }

    #[must_use]
    pub const fn compression(&self) -> ArchiveCompressionV1 {
        self.compression
    }

    #[must_use]
    pub const fn decoder_version(&self) -> u16 {
        self.decoder_version
    }

    #[must_use]
    pub const fn payload_byte_len(&self) -> u64 {
        self.payload_byte_len
    }

    #[must_use]
    pub const fn payload_digest(&self) -> &Digest {
        &self.payload_digest
    }
}

/// Caller-selected resource limits for one decode.
///
/// `malm-tree` limits remain hard upper bounds. A zero limit is valid and
/// rejects any input that uses the resource.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ArchiveLimitsV1 {
    /// Maximum payload bytes read under the declaration.
    pub max_payload_bytes: u64,
    /// Maximum bytes in a regular-file entry.
    pub max_file_bytes: u64,
    /// Maximum total logical file bytes.
    pub max_expanded_file_bytes: u64,
    /// Maximum file, directory, and symlink entries.
    pub max_entries: u64,
    /// Maximum UTF-8 bytes in a slash-joined path.
    pub max_path_bytes: u64,
    /// Maximum path components.
    pub max_path_depth: u64,
    /// Maximum UTF-8 bytes in a path component.
    pub max_path_segment_bytes: u64,
    /// Maximum UTF-8 bytes in a symlink target.
    pub max_symlink_target_bytes: u64,
    /// Maximum ustar header bytes processed as metadata.
    pub max_metadata_bytes: u64,
    /// Maximum canonical bytes retained in the result.
    pub max_object_bytes: u64,
    /// Maximum `Read` calls, including retries and EOF.
    pub max_read_operations: u64,
    /// Maximum parsing and tree-construction work units.
    pub max_work_units: u64,
}

impl Default for ArchiveLimitsV1 {
    fn default() -> Self {
        Self {
            max_payload_bytes: DEFAULT_MAX_PAYLOAD_BYTES,
            max_file_bytes: DEFAULT_MAX_FILE_BYTES,
            max_expanded_file_bytes: DEFAULT_MAX_EXPANDED_FILE_BYTES,
            max_entries: DEFAULT_MAX_ENTRIES,
            max_path_bytes: DEFAULT_MAX_PATH_BYTES,
            max_path_depth: DEFAULT_MAX_PATH_DEPTH,
            max_path_segment_bytes: DEFAULT_MAX_PATH_SEGMENT_BYTES,
            max_symlink_target_bytes: DEFAULT_MAX_SYMLINK_TARGET_BYTES,
            max_metadata_bytes: DEFAULT_MAX_METADATA_BYTES,
            max_object_bytes: DEFAULT_MAX_OBJECT_BYTES,
            max_read_operations: DEFAULT_MAX_READ_OPERATIONS,
            max_work_units: DEFAULT_MAX_WORK_UNITS,
        }
    }
}

/// Resource category used in limit errors.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ArchiveResourceV1 {
    PayloadBytes,
    FileBytes,
    ExpandedFileBytes,
    Entries,
    PathBytes,
    PathDepth,
    PathSegmentBytes,
    SymlinkTargetBytes,
    MetadataBytes,
    ObjectBytes,
    ReadOperations,
    WorkUnits,
}

/// Canonical bytes and model for a tree object.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CanonicalTreeObjectV1 {
    object: TreeObjectV1,
    bytes: Vec<u8>,
}

impl CanonicalTreeObjectV1 {
    pub(crate) fn new(object: TreeObjectV1, bytes: Vec<u8>) -> Self {
        Self { object, bytes }
    }

    #[must_use]
    pub const fn object(&self) -> &TreeObjectV1 {
        &self.object
    }

    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// Canonical bytes and model for a symlink object.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CanonicalSymlinkObjectV1 {
    object: SymlinkObjectV1,
    bytes: Vec<u8>,
}

impl CanonicalSymlinkObjectV1 {
    pub(crate) fn new(object: SymlinkObjectV1, bytes: Vec<u8>) -> Self {
        Self { object, bytes }
    }

    #[must_use]
    pub const fn object(&self) -> &SymlinkObjectV1 {
        &self.object
    }

    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// Looks up canonical bytes in file, tree, then symlink order.
///
/// This order must match the bucket checks in `insert_file`, `insert_tree`, and
/// `insert_symlink`. Changing it can confuse repeated inserts with cross-bucket
/// digest collisions.
pub(crate) fn object_bytes_by_digest<'a>(
    file_blobs: &'a BTreeMap<Digest, Vec<u8>>,
    trees: &'a BTreeMap<Digest, CanonicalTreeObjectV1>,
    symlinks: &'a BTreeMap<Digest, CanonicalSymlinkObjectV1>,
    digest: &Digest,
) -> Option<&'a [u8]> {
    file_blobs
        .get(digest)
        .map(Vec::as_slice)
        .or_else(|| trees.get(digest).map(CanonicalTreeObjectV1::bytes))
        .or_else(|| symlinks.get(digest).map(CanonicalSymlinkObjectV1::bytes))
}

/// Canonical objects produced by a successful decode.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArchiveObjectsV1 {
    file_blobs: BTreeMap<Digest, Vec<u8>>,
    trees: BTreeMap<Digest, CanonicalTreeObjectV1>,
    symlinks: BTreeMap<Digest, CanonicalSymlinkObjectV1>,
}

impl ArchiveObjectsV1 {
    pub(crate) fn new(
        file_blobs: BTreeMap<Digest, Vec<u8>>,
        trees: BTreeMap<Digest, CanonicalTreeObjectV1>,
        symlinks: BTreeMap<Digest, CanonicalSymlinkObjectV1>,
    ) -> Self {
        Self {
            file_blobs,
            trees,
            symlinks,
        }
    }

    #[must_use]
    pub const fn file_blobs(&self) -> &BTreeMap<Digest, Vec<u8>> {
        &self.file_blobs
    }

    #[must_use]
    pub const fn trees(&self) -> &BTreeMap<Digest, CanonicalTreeObjectV1> {
        &self.trees
    }

    #[must_use]
    pub const fn symlinks(&self) -> &BTreeMap<Digest, CanonicalSymlinkObjectV1> {
        &self.symlinks
    }

    /// Returns canonical bytes for any object ID in the result.
    #[must_use]
    pub fn object_bytes(&self, digest: &Digest) -> Option<&[u8]> {
        object_bytes_by_digest(&self.file_blobs, &self.trees, &self.symlinks, digest)
    }
}

/// Immutable record of the exact archive input and trusted decoder result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArchiveProvenanceV1 {
    declaration: ArchiveDeclarationV1,
    decoder: ArchiveDecoderIdentityV1,
    root_digest: Digest,
}

impl ArchiveProvenanceV1 {
    pub(crate) fn new(declaration: ArchiveDeclarationV1, root_digest: Digest) -> Self {
        Self {
            declaration,
            decoder: ARCHIVE_DECODER_IDENTITY_V1,
            root_digest,
        }
    }

    #[must_use]
    pub const fn schema_version(&self) -> u16 {
        ARCHIVE_SCHEMA_VERSION
    }

    #[must_use]
    pub const fn declaration(&self) -> &ArchiveDeclarationV1 {
        &self.declaration
    }

    #[must_use]
    pub const fn decoder(&self) -> ArchiveDecoderIdentityV1 {
        self.decoder
    }

    #[must_use]
    pub const fn root_digest(&self) -> &Digest {
        &self.root_digest
    }
}

/// A verified archive/v1 decode result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DecodedArchiveV1 {
    provenance: ArchiveProvenanceV1,
    objects: ArchiveObjectsV1,
    graph: TreeGraphV1,
}

impl DecodedArchiveV1 {
    pub(crate) fn new(
        provenance: ArchiveProvenanceV1,
        objects: ArchiveObjectsV1,
        graph: TreeGraphV1,
    ) -> Self {
        Self {
            provenance,
            objects,
            graph,
        }
    }

    #[must_use]
    pub const fn provenance(&self) -> &ArchiveProvenanceV1 {
        &self.provenance
    }

    #[must_use]
    pub const fn root_digest(&self) -> &Digest {
        self.provenance.root_digest()
    }

    #[must_use]
    pub const fn objects(&self) -> &ArchiveObjectsV1 {
        &self.objects
    }

    #[must_use]
    pub const fn tree_graph(&self) -> &TreeGraphV1 {
        &self.graph
    }
}
