use std::{
    collections::{BTreeMap, btree_map::Entry},
    io::{self, Read},
    str,
};

use malm_tree::{
    SymlinkObjectV1, TreeEntryV1, TreeGraphError, TreeGraphV1, TreeObjectV1, TreePathSegmentV1,
    TreeValidationError, TreeValueError, encode_file_object_v1, encode_symlink_object_v1,
    encode_tree_object_v1, symlink_object_digest_v1, tree_object_digest_v1,
};
use malm_types::Digest;
use sha2::{Digest as ShaDigest, Sha256};

use crate::{
    ARCHIVE_DECODER_VERSION, ArchiveDeclarationV1, ArchiveLimitsV1, ArchiveObjectsV1,
    ArchiveProvenanceV1, ArchiveResourceV1, CanonicalSymlinkObjectV1, CanonicalTreeObjectV1,
    DecodedArchiveV1, USTAR_BLOCK_BYTES,
};

const ROOT_AND_IMPLICIT_DIRECTORY_MODE: u32 = 0o755;
const FILE_CHUNK_BYTES: usize = 8192;

/// Deterministic failure to decode and completely verify one archive payload.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
#[non_exhaustive]
pub enum ArchiveDecodeError {
    #[error("unsupported archive decoder version {found}; expected {expected}")]
    UnsupportedDecoderVersion { expected: u16, found: u16 },
    #[error("archive {resource:?} resource use is {actual}; limit is {limit}")]
    ResourceLimitExceeded {
        resource: ArchiveResourceV1,
        limit: u64,
        actual: u64,
    },
    #[error("archive payload read failed: {kind:?}")]
    ReadError { kind: io::ErrorKind },
    #[error("archive payload ended at {actual} bytes; expected {expected}")]
    TruncatedPayload { expected: u64, actual: u64 },
    #[error("archive reader contains trailing bytes")]
    TrailingBytes,
    #[error("archive payload has {bytes_after_terminator} bytes after its terminator")]
    TrailingPayloadData { bytes_after_terminator: u64 },
    #[error("archive payload digest mismatch: expected {expected}, computed {actual}")]
    PayloadDigestMismatch { expected: Digest, actual: Digest },
    #[error("ustar header block {block} has checksum {stored:o}; computed {computed:o}")]
    InvalidChecksum {
        block: u64,
        stored: u64,
        computed: u64,
    },
    #[error("malformed ustar header block {block}: {reason}")]
    MalformedHeader { block: u64, reason: &'static str },
    #[error("malformed ustar entry at block {block}: {reason}")]
    MalformedEntry { block: u64, reason: &'static str },
    #[error("malformed ustar terminator: {reason}")]
    MalformedTerminator { reason: &'static str },
    #[error("invalid ustar path at block {block}: {reason}")]
    InvalidPath { block: u64, reason: &'static str },
    #[error("unsafe symlink target for {path:?}: {reason}")]
    UnsafeSymlinkTarget { path: String, reason: &'static str },
    #[error("duplicate archive path {path:?}")]
    DuplicatePath { path: String },
    #[error("archive node-kind collision at {path:?}")]
    PathKindCollision { path: String },
    #[error("archive path {path:?} descends beneath a non-directory")]
    DescendantBelowNonDirectory { path: String },
    #[error("archive non-directory {path:?} collides with existing descendants")]
    FileDescendantCollision { path: String },
    #[error("hard-link entry at ustar block {block} is forbidden")]
    HardLink { block: u64 },
    #[error("sparse entry at ustar block {block} is forbidden")]
    SparseEntry { block: u64 },
    #[error("special ustar entry type {typeflag:#04x} at block {block} is forbidden")]
    SpecialEntry { block: u64, typeflag: u8 },
    #[error("unsupported ustar extension {typeflag:#04x} at block {block}")]
    UnsupportedExtension { block: u64, typeflag: u8 },
    #[error("unsupported ustar entry type {typeflag:#04x} at block {block}")]
    UnsupportedEntryType { block: u64, typeflag: u8 },
    #[error("unsupported archive mode {mode:#o} at {path:?}")]
    UnsupportedMode { path: String, mode: u32 },
    #[error("distinct archive objects have digest {digest}")]
    ObjectDigestCollision { digest: Digest },
    #[error("invalid archive object: {0}")]
    InvalidObject(#[source] malm_tree::ObjectReadError),
    #[error("invalid archive tree value: {0}")]
    InvalidTreeValue(#[source] TreeValueError),
    #[error("invalid archive tree: {0}")]
    InvalidTree(#[source] TreeValidationError),
    #[error("invalid archive tree graph: {0}")]
    InvalidTreeGraph(#[source] TreeGraphError),
}

/// Decodes the exact declared archive using the frozen archive/v1 decoder.
///
/// Except for declaration preflight failures, the decoder drains exactly the
/// declared payload before returning a format error. It then probes the reader
/// once for forbidden trailing bytes and verifies the complete payload digest.
pub fn decode_archive_v1<R: Read>(
    reader: R,
    declaration: ArchiveDeclarationV1,
    limits: ArchiveLimitsV1,
) -> Result<DecodedArchiveV1, ArchiveDecodeError> {
    if declaration.decoder_version() != ARCHIVE_DECODER_VERSION {
        return Err(ArchiveDecodeError::UnsupportedDecoderVersion {
            expected: ARCHIVE_DECODER_VERSION,
            found: declaration.decoder_version(),
        });
    }
    check_limit(
        ArchiveResourceV1::PayloadBytes,
        declaration.payload_byte_len(),
        limits.max_payload_bytes,
    )?;

    let mut payload = ExactPayloadReader::new(
        reader,
        declaration.payload_byte_len(),
        limits.max_read_operations,
    );
    let parsed = parse_ustar(&mut payload, limits);
    let actual_payload_digest = payload.drain_verify_end()?;
    if &actual_payload_digest != declaration.payload_digest() {
        return Err(ArchiveDecodeError::PayloadDigestMismatch {
            expected: declaration.payload_digest().clone(),
            actual: actual_payload_digest,
        });
    }
    let parsed = parsed?;
    finalize_archive(parsed, declaration)
}

/// Decodes a payload using the fixed tar/none declaration.
pub fn decode_posix_ustar_v1<R: Read>(
    reader: R,
    expected_payload_len: u64,
    expected_payload_digest: Digest,
    limits: ArchiveLimitsV1,
) -> Result<DecodedArchiveV1, ArchiveDecodeError> {
    decode_archive_v1(
        reader,
        ArchiveDeclarationV1::posix_ustar(expected_payload_len, expected_payload_digest),
        limits,
    )
}

struct ExactPayloadReader<R> {
    inner: R,
    expected: u64,
    consumed: u64,
    read_operations: u64,
    max_read_operations: u64,
    hasher: Sha256,
}

impl<R: Read> ExactPayloadReader<R> {
    fn new(inner: R, expected: u64, max_read_operations: u64) -> Self {
        Self {
            inner,
            expected,
            consumed: 0,
            read_operations: 0,
            max_read_operations,
            hasher: Sha256::new(),
        }
    }

    fn remaining(&self) -> u64 {
        self.expected - self.consumed
    }

    fn read_exact_payload(&mut self, output: &mut [u8]) -> Result<(), ArchiveDecodeError> {
        let mut offset = 0;
        while offset < output.len() {
            let remaining = self.remaining();
            if remaining == 0 {
                return Err(ArchiveDecodeError::TruncatedPayload {
                    expected: self.expected,
                    actual: self.consumed,
                });
            }
            let requested = (output.len() - offset).min(u64_to_usize(remaining));
            match self.charged_read(&mut output[offset..offset + requested])? {
                0 => {
                    return Err(ArchiveDecodeError::TruncatedPayload {
                        expected: self.expected,
                        actual: self.consumed,
                    });
                }
                count => {
                    self.hasher.update(&output[offset..offset + count]);
                    self.consumed += count as u64;
                    offset += count;
                }
            }
        }
        Ok(())
    }

    fn drain_verify_end(mut self) -> Result<Digest, ArchiveDecodeError> {
        let mut buffer = [0_u8; FILE_CHUNK_BYTES];
        while self.remaining() != 0 {
            let count = u64_to_usize(self.remaining()).min(buffer.len());
            self.read_exact_payload(&mut buffer[..count])?;
        }

        let mut trailing = [0_u8; 1];
        if self.charged_read(&mut trailing)? != 0 {
            return Err(ArchiveDecodeError::TrailingBytes);
        }
        Ok(Digest::from_sha256(self.hasher))
    }

    /// Reads from the inner reader and charges every attempt, including retries.
    fn charged_read(&mut self, output: &mut [u8]) -> Result<usize, ArchiveDecodeError> {
        loop {
            self.charge_read()?;
            match self.inner.read(output) {
                Ok(count) => return Ok(count),
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => {
                    return Err(ArchiveDecodeError::ReadError { kind: error.kind() });
                }
            }
        }
    }

    fn charge_read(&mut self) -> Result<(), ArchiveDecodeError> {
        charge(
            &mut self.read_operations,
            1,
            ArchiveResourceV1::ReadOperations,
            self.max_read_operations,
        )
    }
}

struct ParsedArchive {
    root: DirectoryNode,
    objects: ObjectAccumulator,
    limits: ArchiveLimitsV1,
    object_bytes: u64,
    work_units: u64,
}

/// Caller limits clamped to the corresponding `malm-tree` limits.
#[derive(Clone, Copy)]
struct EffectiveLimits {
    file_bytes: u64,
    expanded_file_bytes: u64,
    entries: u64,
    path_bytes: u64,
    path_depth: u64,
    path_segment_bytes: u64,
    symlink_target_bytes: u64,
}

impl EffectiveLimits {
    fn new(limits: &ArchiveLimitsV1) -> Self {
        Self {
            file_bytes: effective_limit(limits.max_file_bytes, malm_tree::MAX_TREE_FILE_BYTES),
            expanded_file_bytes: effective_limit(
                limits.max_expanded_file_bytes,
                malm_tree::MAX_TREE_AGGREGATE_FILE_BYTES,
            ),
            entries: effective_limit(limits.max_entries, malm_tree::MAX_TREE_ENTRIES as u64),
            path_bytes: effective_limit(
                limits.max_path_bytes,
                malm_tree::MAX_TREE_PATH_BYTES as u64,
            ),
            path_depth: effective_limit(limits.max_path_depth, malm_tree::MAX_TREE_DEPTH as u64),
            path_segment_bytes: effective_limit(
                limits.max_path_segment_bytes,
                malm_tree::MAX_TREE_SEGMENT_BYTES as u64,
            ),
            symlink_target_bytes: effective_limit(
                limits.max_symlink_target_bytes,
                malm_tree::MAX_SYMLINK_TARGET_BYTES as u64,
            ),
        }
    }
}

struct ParseState {
    root: DirectoryNode,
    objects: ObjectAccumulator,
    limits: ArchiveLimitsV1,
    effective: EffectiveLimits,
    logical_entries: u64,
    expanded_file_bytes: u64,
    metadata_bytes: u64,
    object_bytes: u64,
    work_units: u64,
}

impl ParseState {
    fn new(limits: ArchiveLimitsV1) -> Self {
        Self {
            root: DirectoryNode::root(),
            objects: ObjectAccumulator::default(),
            effective: EffectiveLimits::new(&limits),
            limits,
            logical_entries: 0,
            expanded_file_bytes: 0,
            metadata_bytes: 0,
            object_bytes: 0,
            work_units: 0,
        }
    }

    fn charge_metadata_block(&mut self) -> Result<(), ArchiveDecodeError> {
        charge(
            &mut self.metadata_bytes,
            USTAR_BLOCK_BYTES as u64,
            ArchiveResourceV1::MetadataBytes,
            self.limits.max_metadata_bytes,
        )?;
        self.charge_work(1)
    }

    fn charge_work(&mut self, amount: u64) -> Result<(), ArchiveDecodeError> {
        charge(
            &mut self.work_units,
            amount,
            ArchiveResourceV1::WorkUnits,
            self.limits.max_work_units,
        )
    }

    fn into_parsed(self) -> ParsedArchive {
        ParsedArchive {
            root: self.root,
            objects: self.objects,
            limits: self.limits,
            object_bytes: self.object_bytes,
            work_units: self.work_units,
        }
    }
}

#[derive(Default)]
struct ObjectAccumulator {
    file_blobs: BTreeMap<Digest, Vec<u8>>,
    trees: BTreeMap<Digest, CanonicalTreeObjectV1>,
    symlinks: BTreeMap<Digest, CanonicalSymlinkObjectV1>,
}

impl ObjectAccumulator {
    fn bytes_for_digest(&self, digest: &Digest) -> Option<&[u8]> {
        crate::model::object_bytes_by_digest(&self.file_blobs, &self.trees, &self.symlinks, digest)
    }

    fn ensure_digest_bytes(&self, digest: &Digest, bytes: &[u8]) -> Result<(), ArchiveDecodeError> {
        if self
            .bytes_for_digest(digest)
            .is_some_and(|existing| existing != bytes)
        {
            return Err(ArchiveDecodeError::ObjectDigestCollision {
                digest: digest.clone(),
            });
        }
        Ok(())
    }

    /// Checks collisions and charges bytes for a new object.
    ///
    /// Returns `true` when the caller must insert the object.
    fn admit_object(
        &self,
        digest: &Digest,
        bytes: &[u8],
        already_stored: bool,
        object_bytes: &mut u64,
        limit: u64,
    ) -> Result<bool, ArchiveDecodeError> {
        self.ensure_digest_bytes(digest, bytes)?;
        if already_stored {
            return Ok(false);
        }
        charge(
            object_bytes,
            bytes.len() as u64,
            ArchiveResourceV1::ObjectBytes,
            limit,
        )?;
        Ok(true)
    }

    fn insert_file(
        &mut self,
        digest: Digest,
        bytes: Vec<u8>,
        object_bytes: &mut u64,
        limit: u64,
    ) -> Result<(), ArchiveDecodeError> {
        let already_stored = self.file_blobs.contains_key(&digest);
        if self.admit_object(&digest, &bytes, already_stored, object_bytes, limit)? {
            debug_assert_eq!(digest, Digest::sha256(&bytes));
            self.file_blobs.insert(digest, bytes);
        }
        Ok(())
    }

    fn insert_symlink(
        &mut self,
        digest: Digest,
        object: SymlinkObjectV1,
        bytes: Vec<u8>,
        object_bytes: &mut u64,
        limit: u64,
    ) -> Result<(), ArchiveDecodeError> {
        let already_stored = self.symlinks.contains_key(&digest);
        if self.admit_object(&digest, &bytes, already_stored, object_bytes, limit)? {
            debug_assert_eq!(digest, Digest::sha256(&bytes));
            self.symlinks
                .insert(digest, CanonicalSymlinkObjectV1::new(object, bytes));
        }
        Ok(())
    }

    fn insert_tree(
        &mut self,
        digest: Digest,
        object: TreeObjectV1,
        bytes: Vec<u8>,
        object_bytes: &mut u64,
        limit: u64,
    ) -> Result<(), ArchiveDecodeError> {
        let already_stored = self.trees.contains_key(&digest);
        if self.admit_object(&digest, &bytes, already_stored, object_bytes, limit)? {
            debug_assert_eq!(digest, Digest::sha256(&bytes));
            self.trees
                .insert(digest, CanonicalTreeObjectV1::new(object, bytes));
        }
        Ok(())
    }

    fn into_public(self) -> ArchiveObjectsV1 {
        ArchiveObjectsV1::new(self.file_blobs, self.trees, self.symlinks)
    }
}

struct DirectoryNode {
    mode: u32,
    explicit: bool,
    children: BTreeMap<String, Node>,
}

impl DirectoryNode {
    fn root() -> Self {
        Self {
            mode: ROOT_AND_IMPLICIT_DIRECTORY_MODE,
            explicit: true,
            children: BTreeMap::new(),
        }
    }

    fn implicit() -> Self {
        Self {
            mode: ROOT_AND_IMPLICIT_DIRECTORY_MODE,
            explicit: false,
            children: BTreeMap::new(),
        }
    }

    fn explicit(mode: u32) -> Self {
        Self {
            mode,
            explicit: true,
            children: BTreeMap::new(),
        }
    }
}

enum Node {
    File {
        mode: u32,
        digest: Digest,
        byte_len: u64,
    },
    Directory(DirectoryNode),
    Symlink {
        digest: Digest,
    },
}

struct Header {
    path: String,
    components: Vec<String>,
    mode: u32,
    size: u64,
    kind: HeaderKind,
}

#[derive(Clone)]
enum HeaderKind {
    File,
    Directory,
    Symlink { target: String },
}

fn parse_ustar<R: Read>(
    payload: &mut ExactPayloadReader<R>,
    limits: ArchiveLimitsV1,
) -> Result<ParsedArchive, ArchiveDecodeError> {
    let mut state = ParseState::new(limits);
    loop {
        if payload.remaining() < USTAR_BLOCK_BYTES as u64 {
            return Err(ArchiveDecodeError::MalformedTerminator {
                reason: "missing complete first zero block",
            });
        }
        state.charge_metadata_block()?;
        let block_index = payload.consumed / USTAR_BLOCK_BYTES as u64;
        let mut block = [0_u8; USTAR_BLOCK_BYTES];
        payload.read_exact_payload(&mut block)?;
        if is_zero_block(&block) {
            if payload.remaining() < USTAR_BLOCK_BYTES as u64 {
                return Err(ArchiveDecodeError::MalformedTerminator {
                    reason: "first zero block is not followed by a complete second zero block",
                });
            }
            state.charge_metadata_block()?;
            let mut second = [0_u8; USTAR_BLOCK_BYTES];
            payload.read_exact_payload(&mut second)?;
            if !is_zero_block(&second) {
                return Err(ArchiveDecodeError::MalformedTerminator {
                    reason: "first zero block is not followed by a zero block",
                });
            }
            if payload.remaining() != 0 {
                return Err(ArchiveDecodeError::TrailingPayloadData {
                    bytes_after_terminator: payload.remaining(),
                });
            }
            return Ok(state.into_parsed());
        }

        let header = parse_header(&block, block_index, &mut state)?;
        match header.kind.clone() {
            HeaderKind::File => decode_file_entry(payload, header, &mut state)?,
            HeaderKind::Directory => insert_directory_entry(header, &mut state)?,
            HeaderKind::Symlink { target } => {
                insert_symlink_entry(header, target, &mut state)?;
            }
        }
    }
}

fn parse_header(
    block: &[u8; USTAR_BLOCK_BYTES],
    block_index: u64,
    state: &mut ParseState,
) -> Result<Header, ArchiveDecodeError> {
    verify_checksum(block, block_index)?;
    if &block[257..263] != b"ustar\0" {
        return malformed_header(block_index, "magic is not POSIX ustar");
    }
    if &block[263..265] != b"00" {
        return malformed_header(block_index, "ustar version is not 00");
    }
    if block[500..512].iter().any(|byte| *byte != 0) {
        return malformed_header(block_index, "reserved header bytes are nonzero");
    }

    let mode = parse_octal(&block[100..108], block_index, HeaderField::Mode)?;
    let mode = u32::try_from(mode).map_err(|_| ArchiveDecodeError::MalformedHeader {
        block: block_index,
        reason: "mode does not fit u32",
    })?;
    parse_octal(&block[108..116], block_index, HeaderField::Uid)?;
    parse_octal(&block[116..124], block_index, HeaderField::Gid)?;
    let size = parse_octal(&block[124..136], block_index, HeaderField::Size)?;
    parse_octal(&block[136..148], block_index, HeaderField::Mtime)?;
    validate_ignored_text(&block[265..297], block_index, HeaderField::UserName)?;
    validate_ignored_text(&block[297..329], block_index, HeaderField::GroupName)?;
    if parse_optional_octal(&block[329..337], block_index, HeaderField::DeviceMajor)? != 0
        || parse_optional_octal(&block[337..345], block_index, HeaderField::DeviceMinor)? != 0
    {
        return malformed_header(
            block_index,
            "device numbers must be zero for an allowed entry",
        );
    }

    let typeflag = block[156];
    match typeflag {
        b'1' => return Err(ArchiveDecodeError::HardLink { block: block_index }),
        b'S' => return Err(ArchiveDecodeError::SparseEntry { block: block_index }),
        b'3' | b'4' | b'6' | b'7' => {
            return Err(ArchiveDecodeError::SpecialEntry {
                block: block_index,
                typeflag,
            });
        }
        b'x' | b'g' | b'L' | b'K' | b'D' | b'M' | b'N' | b'V' => {
            return Err(ArchiveDecodeError::UnsupportedExtension {
                block: block_index,
                typeflag,
            });
        }
        b'0' | b'2' | b'5' => {}
        _ => {
            return Err(ArchiveDecodeError::UnsupportedEntryType {
                block: block_index,
                typeflag,
            });
        }
    }

    let path = parse_header_path(block, block_index)?;
    let components = validate_path(&path, block_index, state)?;
    let link = field_bytes(&block[157..257], block_index, HeaderField::LinkName)?;
    let kind = match typeflag {
        b'0' => {
            if !link.is_empty() {
                return malformed_entry(block_index, "regular file has a link name");
            }
            validate_mode(&path, mode, NodeModeKind::File)?;
            HeaderKind::File
        }
        b'5' => {
            if size != 0 {
                return malformed_entry(block_index, "directory size is not zero");
            }
            if !link.is_empty() {
                return malformed_entry(block_index, "directory has a link name");
            }
            validate_mode(&path, mode, NodeModeKind::Directory)?;
            HeaderKind::Directory
        }
        b'2' => {
            if size != 0 {
                return malformed_entry(block_index, "symlink size is not zero");
            }
            validate_mode(&path, mode, NodeModeKind::Symlink)?;
            let target =
                str::from_utf8(link).map_err(|_| ArchiveDecodeError::UnsafeSymlinkTarget {
                    path: path.clone(),
                    reason: "target is not UTF-8",
                })?;
            validate_symlink_target(&path, &components, target, state)?;
            HeaderKind::Symlink {
                target: target.to_owned(),
            }
        }
        _ => unreachable!("typeflag allowlist was checked"),
    };

    Ok(Header {
        path,
        components,
        mode,
        size,
        kind,
    })
}

fn decode_file_entry<R: Read>(
    payload: &mut ExactPayloadReader<R>,
    header: Header,
    state: &mut ParseState,
) -> Result<(), ArchiveDecodeError> {
    check_limit(
        ArchiveResourceV1::FileBytes,
        header.size,
        state.effective.file_bytes,
    )?;
    let next_expanded = state.expanded_file_bytes.saturating_add(header.size);
    check_limit(
        ArchiveResourceV1::ExpandedFileBytes,
        next_expanded,
        state.effective.expanded_file_bytes,
    )?;
    state.expanded_file_bytes = next_expanded;

    reserve_leaf_path(&header.path, &header.components, state)?;
    let padding = padding_len(header.size);
    let declared_body = header.size.saturating_add(padding as u64);
    if payload.remaining() < declared_body {
        return malformed_entry(
            payload.consumed / USTAR_BLOCK_BYTES as u64,
            "file body extends beyond the declared payload",
        );
    }
    state.charge_work(div_ceil_512(header.size))?;

    let file_len =
        usize::try_from(header.size).map_err(|_| ArchiveDecodeError::ResourceLimitExceeded {
            resource: ArchiveResourceV1::FileBytes,
            limit: usize::MAX as u64,
            actual: header.size,
        })?;
    let mut bytes = Vec::with_capacity(file_len);
    let mut buffer = [0_u8; FILE_CHUNK_BYTES];
    let mut remaining = header.size;
    while remaining != 0 {
        let count = u64_to_usize(remaining).min(buffer.len());
        payload.read_exact_payload(&mut buffer[..count])?;
        bytes.extend_from_slice(&buffer[..count]);
        remaining -= count as u64;
    }
    if padding != 0 {
        let mut padding_bytes = [0_u8; USTAR_BLOCK_BYTES - 1];
        payload.read_exact_payload(&mut padding_bytes[..padding])?;
        if padding_bytes[..padding].iter().any(|byte| *byte != 0) {
            return malformed_entry(
                payload.consumed / USTAR_BLOCK_BYTES as u64,
                "file padding is nonzero",
            );
        }
    }
    let encoded = encode_file_object_v1(&bytes).map_err(ArchiveDecodeError::InvalidObject)?;
    let digest = Digest::sha256(&encoded);
    state.objects.insert_file(
        digest.clone(),
        encoded,
        &mut state.object_bytes,
        state.limits.max_object_bytes,
    )?;
    insert_leaf(
        &header.path,
        &header.components,
        Node::File {
            mode: header.mode,
            digest,
            byte_len: header.size,
        },
        state,
    )
}

fn insert_directory_entry(
    header: Header,
    state: &mut ParseState,
) -> Result<(), ArchiveDecodeError> {
    let (name, parent, logical_entries, entry_limit) =
        split_and_ensure_parent(&header.components, &header.path, state)?;
    match parent.children.entry(name.clone()) {
        Entry::Vacant(slot) => {
            charge(logical_entries, 1, ArchiveResourceV1::Entries, entry_limit)?;
            slot.insert(Node::Directory(DirectoryNode::explicit(header.mode)));
            Ok(())
        }
        Entry::Occupied(mut slot) => match slot.get_mut() {
            Node::Directory(directory) if !directory.explicit => {
                directory.explicit = true;
                directory.mode = header.mode;
                Ok(())
            }
            Node::Directory(_) => Err(ArchiveDecodeError::DuplicatePath { path: header.path }),
            Node::File { .. } | Node::Symlink { .. } => {
                Err(ArchiveDecodeError::PathKindCollision { path: header.path })
            }
        },
    }
}

fn insert_symlink_entry(
    header: Header,
    target: String,
    state: &mut ParseState,
) -> Result<(), ArchiveDecodeError> {
    reserve_leaf_path(&header.path, &header.components, state)?;
    let object = SymlinkObjectV1::new(target).map_err(ArchiveDecodeError::InvalidTreeValue)?;
    let digest = symlink_object_digest_v1(&object);
    let bytes = encode_symlink_object_v1(&object);
    debug_assert_eq!(digest, Digest::sha256(&bytes));
    state.objects.insert_symlink(
        digest.clone(),
        object,
        bytes,
        &mut state.object_bytes,
        state.limits.max_object_bytes,
    )?;
    insert_leaf(
        &header.path,
        &header.components,
        Node::Symlink { digest },
        state,
    )
}

fn reserve_leaf_path(
    path: &str,
    components: &[String],
    state: &mut ParseState,
) -> Result<(), ArchiveDecodeError> {
    let (name, parent, logical_entries, entry_limit) =
        split_and_ensure_parent(components, path, state)?;
    match parent.children.get(name) {
        None => check_limit(
            ArchiveResourceV1::Entries,
            logical_entries.saturating_add(1),
            entry_limit,
        ),
        Some(Node::Directory(directory)) if !directory.children.is_empty() => {
            Err(ArchiveDecodeError::FileDescendantCollision {
                path: path.to_owned(),
            })
        }
        Some(Node::Directory(_)) => Err(ArchiveDecodeError::PathKindCollision {
            path: path.to_owned(),
        }),
        Some(Node::File { .. }) | Some(Node::Symlink { .. }) => {
            Err(ArchiveDecodeError::DuplicatePath {
                path: path.to_owned(),
            })
        }
    }
}

fn insert_leaf(
    path: &str,
    components: &[String],
    node: Node,
    state: &mut ParseState,
) -> Result<(), ArchiveDecodeError> {
    let (name, parent, logical_entries, entry_limit) =
        split_and_ensure_parent(components, path, state)?;
    if parent.children.contains_key(name) {
        return Err(ArchiveDecodeError::DuplicatePath {
            path: path.to_owned(),
        });
    }
    charge(logical_entries, 1, ArchiveResourceV1::Entries, entry_limit)?;
    parent.children.insert(name.clone(), node);
    Ok(())
}

/// Splits a validated path and creates any missing parent directories.
///
/// The returned counter and limit let the caller charge its leaf insertion.
fn split_and_ensure_parent<'c, 's>(
    components: &'c [String],
    path: &str,
    state: &'s mut ParseState,
) -> Result<(&'c String, &'s mut DirectoryNode, &'s mut u64, u64), ArchiveDecodeError> {
    let (name, parents) = components
        .split_last()
        .expect("validated path has at least one component");
    let ParseState {
        root,
        logical_entries,
        effective,
        ..
    } = state;
    let parent = ensure_parent_directory(root, parents, path, logical_entries, effective.entries)?;
    Ok((name, parent, logical_entries, effective.entries))
}

fn ensure_parent_directory<'a>(
    root: &'a mut DirectoryNode,
    parents: &[String],
    complete_path: &str,
    entry_count: &mut u64,
    entry_limit: u64,
) -> Result<&'a mut DirectoryNode, ArchiveDecodeError> {
    let mut directory = root;
    for component in parents {
        let node = match directory.children.entry(component.clone()) {
            Entry::Vacant(slot) => {
                charge(entry_count, 1, ArchiveResourceV1::Entries, entry_limit)?;
                slot.insert(Node::Directory(DirectoryNode::implicit()))
            }
            Entry::Occupied(slot) => slot.into_mut(),
        };
        directory = match node {
            Node::Directory(directory) => directory,
            Node::File { .. } | Node::Symlink { .. } => {
                return Err(ArchiveDecodeError::DescendantBelowNonDirectory {
                    path: complete_path.to_owned(),
                });
            }
        };
    }
    Ok(directory)
}

fn finalize_archive(
    parsed: ParsedArchive,
    declaration: ArchiveDeclarationV1,
) -> Result<DecodedArchiveV1, ArchiveDecodeError> {
    let ParsedArchive {
        root,
        mut objects,
        limits,
        mut object_bytes,
        mut work_units,
    } = parsed;
    let root_digest = build_tree(
        root,
        &mut objects,
        &mut object_bytes,
        &mut work_units,
        limits,
    )?;
    let graph = TreeGraphV1::new(
        root_digest.clone(),
        objects.trees.values().map(|object| object.object().clone()),
        objects
            .symlinks
            .values()
            .map(|object| object.object().clone()),
    )
    .map_err(ArchiveDecodeError::InvalidTreeGraph)?;
    let provenance = ArchiveProvenanceV1::new(declaration, root_digest);
    Ok(DecodedArchiveV1::new(
        provenance,
        objects.into_public(),
        graph,
    ))
}

fn build_tree(
    directory: DirectoryNode,
    objects: &mut ObjectAccumulator,
    object_bytes: &mut u64,
    work_units: &mut u64,
    limits: ArchiveLimitsV1,
) -> Result<Digest, ArchiveDecodeError> {
    let mut entries = Vec::with_capacity(directory.children.len());
    for (name, node) in directory.children {
        charge(
            work_units,
            1,
            ArchiveResourceV1::WorkUnits,
            limits.max_work_units,
        )?;
        let name = TreePathSegmentV1::new(name).map_err(ArchiveDecodeError::InvalidTreeValue)?;
        let entry = match node {
            Node::File {
                mode,
                digest,
                byte_len,
            } => TreeEntryV1::file(name, mode, digest, byte_len)
                .map_err(ArchiveDecodeError::InvalidTree)?,
            Node::Directory(child) => {
                let mode = child.mode;
                let digest = build_tree(child, objects, object_bytes, work_units, limits)?;
                TreeEntryV1::directory(name, mode, digest)
                    .map_err(ArchiveDecodeError::InvalidTree)?
            }
            Node::Symlink { digest } => TreeEntryV1::safe_relative_symlink(name, digest),
        };
        entries.push(entry);
    }
    let object =
        TreeObjectV1::new(directory.mode, entries).map_err(ArchiveDecodeError::InvalidTree)?;
    let digest = tree_object_digest_v1(&object);
    let bytes = encode_tree_object_v1(&object);
    objects.insert_tree(
        digest.clone(),
        object,
        bytes,
        object_bytes,
        limits.max_object_bytes,
    )?;
    Ok(digest)
}

fn parse_header_path(
    block: &[u8; USTAR_BLOCK_BYTES],
    block_index: u64,
) -> Result<String, ArchiveDecodeError> {
    let name = field_bytes(&block[0..100], block_index, HeaderField::Name)?;
    if name.is_empty() {
        return Err(ArchiveDecodeError::InvalidPath {
            block: block_index,
            reason: "name is empty",
        });
    }
    let prefix = field_bytes(&block[345..500], block_index, HeaderField::Prefix)?;
    let name = str::from_utf8(name).map_err(|_| ArchiveDecodeError::InvalidPath {
        block: block_index,
        reason: "name is not UTF-8",
    })?;
    let prefix = str::from_utf8(prefix).map_err(|_| ArchiveDecodeError::InvalidPath {
        block: block_index,
        reason: "prefix is not UTF-8",
    })?;
    if prefix.is_empty() {
        Ok(name.to_owned())
    } else {
        Ok(format!("{prefix}/{name}"))
    }
}

fn validate_path(
    path: &str,
    block_index: u64,
    state: &mut ParseState,
) -> Result<Vec<String>, ArchiveDecodeError> {
    if path.starts_with('/') {
        return invalid_path(block_index, "absolute paths are forbidden");
    }
    if path.contains('\\') {
        return invalid_path(block_index, "backslashes are forbidden");
    }
    if path.chars().any(char::is_control) {
        return invalid_path(block_index, "control characters are forbidden");
    }
    check_limit(
        ArchiveResourceV1::PathBytes,
        path.len() as u64,
        state.effective.path_bytes,
    )?;

    let mut components = Vec::new();
    for component in path.split('/') {
        if component.is_empty() {
            return invalid_path(block_index, "empty path components are forbidden");
        }
        if matches!(component, "." | "..") {
            return invalid_path(block_index, "dot and dot-dot components are forbidden");
        }
        check_limit(
            ArchiveResourceV1::PathSegmentBytes,
            component.len() as u64,
            state.effective.path_segment_bytes,
        )?;
        components.push(component.to_owned());
    }
    check_limit(
        ArchiveResourceV1::PathDepth,
        components.len() as u64,
        state.effective.path_depth,
    )?;
    state.charge_work(components.len() as u64)?;
    Ok(components)
}

fn validate_symlink_target(
    path: &str,
    path_components: &[String],
    target: &str,
    state: &mut ParseState,
) -> Result<(), ArchiveDecodeError> {
    let unsafe_target = |reason| ArchiveDecodeError::UnsafeSymlinkTarget {
        path: path.to_owned(),
        reason,
    };
    if target.is_empty() {
        return Err(unsafe_target("target is empty"));
    }
    if target.starts_with('/') {
        return Err(unsafe_target("target must be relative"));
    }
    if target.contains('\\') {
        return Err(unsafe_target("target contains backslash"));
    }
    if target.chars().any(char::is_control) {
        return Err(unsafe_target("target contains a control character"));
    }
    check_limit(
        ArchiveResourceV1::SymlinkTargetBytes,
        target.len() as u64,
        state.effective.symlink_target_bytes,
    )?;

    let mut target_depth = 0_u64;
    for component in target.split('/') {
        if component.is_empty() || matches!(component, "." | "..") {
            return Err(unsafe_target(
                "target must contain only nonempty canonical path components",
            ));
        }
        check_limit(
            ArchiveResourceV1::PathSegmentBytes,
            component.len() as u64,
            state.effective.path_segment_bytes,
        )?;
        target_depth += 1;
    }
    let parent_depth = path_components.len().saturating_sub(1) as u64;
    let resolved_depth = parent_depth.saturating_add(target_depth);
    check_limit(
        ArchiveResourceV1::PathDepth,
        resolved_depth,
        state.effective.path_depth,
    )?;
    let parent_bytes = path
        .rsplit_once('/')
        .map_or(0_u64, |(parent, _)| parent.len() as u64);
    let resolved_bytes = if parent_bytes == 0 {
        target.len() as u64
    } else {
        parent_bytes
            .saturating_add(1)
            .saturating_add(target.len() as u64)
    };
    check_limit(
        ArchiveResourceV1::PathBytes,
        resolved_bytes,
        state.effective.path_bytes,
    )?;
    state.charge_work(target_depth)?;
    Ok(())
}

enum NodeModeKind {
    File,
    Directory,
    Symlink,
}

fn validate_mode(path: &str, mode: u32, kind: NodeModeKind) -> Result<(), ArchiveDecodeError> {
    let supported = match kind {
        NodeModeKind::File => mode & !0o777 == 0 && mode & 0o400 != 0,
        NodeModeKind::Directory => mode & !0o777 == 0 && mode & 0o500 == 0o500,
        NodeModeKind::Symlink => mode == 0o777,
    };
    if supported {
        Ok(())
    } else {
        Err(ArchiveDecodeError::UnsupportedMode {
            path: path.to_owned(),
            mode,
        })
    }
}

fn verify_checksum(
    block: &[u8; USTAR_BLOCK_BYTES],
    block_index: u64,
) -> Result<(), ArchiveDecodeError> {
    let field = &block[148..156];
    if field[6] != 0
        || field[7] != b' '
        || !field[..6].iter().all(|byte| matches!(*byte, b'0'..=b'7'))
    {
        return malformed_header(
            block_index,
            "checksum field is not six octal digits, NUL, space",
        );
    }
    let stored = parse_octal_digits(&field[..6], block_index, HeaderField::Checksum)?;
    let computed = block
        .iter()
        .enumerate()
        .map(|(index, byte)| {
            if (148..156).contains(&index) {
                u64::from(b' ')
            } else {
                u64::from(*byte)
            }
        })
        .sum();
    if stored == computed {
        Ok(())
    } else {
        Err(ArchiveDecodeError::InvalidChecksum {
            block: block_index,
            stored,
            computed,
        })
    }
}

#[derive(Clone, Copy)]
enum HeaderField {
    Mode,
    Uid,
    Gid,
    Size,
    Mtime,
    DeviceMajor,
    DeviceMinor,
    Checksum,
    Name,
    Prefix,
    LinkName,
    UserName,
    GroupName,
}

impl HeaderField {
    const fn numeric_reason(self) -> &'static str {
        match self {
            Self::Mode => "mode is not a fixed-width NUL-terminated octal field",
            Self::Uid => "uid is not a fixed-width NUL-terminated octal field",
            Self::Gid => "gid is not a fixed-width NUL-terminated octal field",
            Self::Size => "size is not a fixed-width NUL-terminated octal field",
            Self::Mtime => "mtime is not a fixed-width NUL-terminated octal field",
            Self::DeviceMajor => "device major is not an empty or fixed-width octal field",
            Self::DeviceMinor => "device minor is not an empty or fixed-width octal field",
            Self::Checksum => "checksum field is invalid",
            _ => "numeric field is invalid",
        }
    }

    const fn text_field_reason(self) -> &'static str {
        match self {
            Self::Name => "name has bytes after its NUL terminator",
            Self::Prefix => "prefix has bytes after its NUL terminator",
            Self::LinkName => "link name has bytes after its NUL terminator",
            Self::UserName => "user name has bytes after its NUL terminator",
            Self::GroupName => "group name has bytes after its NUL terminator",
            _ => "text field has bytes after its NUL terminator",
        }
    }

    const fn ignored_text_reason(self) -> &'static str {
        match self {
            Self::UserName => "user name is not control-free UTF-8",
            Self::GroupName => "group name is not control-free UTF-8",
            _ => "ignored text metadata is not control-free UTF-8",
        }
    }
}

fn parse_octal(
    field: &[u8],
    block_index: u64,
    name: HeaderField,
) -> Result<u64, ArchiveDecodeError> {
    let Some((&terminator, digits)) = field.split_last() else {
        return malformed_header(block_index, "empty numeric field");
    };
    if terminator != 0
        || digits.is_empty()
        || !digits.iter().all(|byte| matches!(*byte, b'0'..=b'7'))
    {
        return Err(ArchiveDecodeError::MalformedHeader {
            block: block_index,
            reason: name.numeric_reason(),
        });
    }
    parse_octal_digits(digits, block_index, name)
}

fn parse_optional_octal(
    field: &[u8],
    block_index: u64,
    name: HeaderField,
) -> Result<u64, ArchiveDecodeError> {
    if field.iter().all(|byte| *byte == 0) {
        Ok(0)
    } else {
        parse_octal(field, block_index, name)
    }
}

fn parse_octal_digits(
    digits: &[u8],
    block_index: u64,
    name: HeaderField,
) -> Result<u64, ArchiveDecodeError> {
    let mut value = 0_u64;
    for digit in digits {
        value = value
            .checked_mul(8)
            .and_then(|value| value.checked_add(u64::from(*digit - b'0')))
            .ok_or(ArchiveDecodeError::MalformedHeader {
                block: block_index,
                reason: name.numeric_reason(),
            })?;
    }
    Ok(value)
}

fn field_bytes(
    field: &[u8],
    block_index: u64,
    name: HeaderField,
) -> Result<&[u8], ArchiveDecodeError> {
    if let Some(end) = field.iter().position(|byte| *byte == 0) {
        if field[end..].iter().any(|byte| *byte != 0) {
            return Err(ArchiveDecodeError::MalformedHeader {
                block: block_index,
                reason: name.text_field_reason(),
            });
        }
        Ok(&field[..end])
    } else {
        Ok(field)
    }
}

fn validate_ignored_text(
    field: &[u8],
    block_index: u64,
    name: HeaderField,
) -> Result<(), ArchiveDecodeError> {
    let bytes = field_bytes(field, block_index, name)?;
    let value = str::from_utf8(bytes).map_err(|_| ArchiveDecodeError::MalformedHeader {
        block: block_index,
        reason: name.ignored_text_reason(),
    })?;
    if value.chars().any(char::is_control) {
        return Err(ArchiveDecodeError::MalformedHeader {
            block: block_index,
            reason: name.ignored_text_reason(),
        });
    }
    Ok(())
}

fn is_zero_block(block: &[u8; USTAR_BLOCK_BYTES]) -> bool {
    block.iter().all(|byte| *byte == 0)
}

fn padding_len(size: u64) -> usize {
    let remainder = (size % USTAR_BLOCK_BYTES as u64) as usize;
    if remainder == 0 {
        0
    } else {
        USTAR_BLOCK_BYTES - remainder
    }
}

fn div_ceil_512(value: u64) -> u64 {
    let blocks = value / USTAR_BLOCK_BYTES as u64;
    if value.is_multiple_of(USTAR_BLOCK_BYTES as u64) {
        blocks
    } else {
        blocks + 1
    }
}

fn charge(
    current: &mut u64,
    amount: u64,
    resource: ArchiveResourceV1,
    limit: u64,
) -> Result<(), ArchiveDecodeError> {
    let actual = current.saturating_add(amount);
    check_limit(resource, actual, limit)?;
    *current = actual;
    Ok(())
}

fn check_limit(
    resource: ArchiveResourceV1,
    actual: u64,
    limit: u64,
) -> Result<(), ArchiveDecodeError> {
    if actual > limit {
        Err(ArchiveDecodeError::ResourceLimitExceeded {
            resource,
            limit,
            actual,
        })
    } else {
        Ok(())
    }
}

fn effective_limit(caller: u64, canonical: u64) -> u64 {
    caller.min(canonical)
}

fn malformed_header<T>(block: u64, reason: &'static str) -> Result<T, ArchiveDecodeError> {
    Err(ArchiveDecodeError::MalformedHeader { block, reason })
}

fn malformed_entry<T>(block: u64, reason: &'static str) -> Result<T, ArchiveDecodeError> {
    Err(ArchiveDecodeError::MalformedEntry { block, reason })
}

fn invalid_path<T>(block: u64, reason: &'static str) -> Result<T, ArchiveDecodeError> {
    Err(ArchiveDecodeError::InvalidPath { block, reason })
}

fn u64_to_usize(value: u64) -> usize {
    usize::try_from(value).unwrap_or(usize::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    const NO_OBJECT_LIMIT: u64 = u64::MAX;

    fn symlink_object(target: &str) -> (SymlinkObjectV1, Vec<u8>) {
        let object = SymlinkObjectV1::new(target).expect("test symlink target is valid");
        let bytes = encode_symlink_object_v1(&object);
        (object, bytes)
    }

    fn tree_object(mode: u32) -> (TreeObjectV1, Vec<u8>) {
        let object = TreeObjectV1::new(mode, Vec::new()).expect("empty tree is valid");
        let bytes = encode_tree_object_v1(&object);
        (object, bytes)
    }

    #[test]
    fn conflicting_file_bytes_for_one_digest_collide() {
        let mut objects = ObjectAccumulator::default();
        let mut object_bytes = 0_u64;
        let digest = Digest::sha256(b"first");
        objects
            .insert_file(
                digest.clone(),
                b"first".to_vec(),
                &mut object_bytes,
                NO_OBJECT_LIMIT,
            )
            .expect("first insert is accepted");

        let error = objects
            .insert_file(
                digest.clone(),
                b"second".to_vec(),
                &mut object_bytes,
                NO_OBJECT_LIMIT,
            )
            .expect_err("conflicting bytes for one digest are rejected");

        assert_eq!(
            error,
            ArchiveDecodeError::ObjectDigestCollision {
                digest: digest.clone()
            }
        );
        assert_eq!(objects.bytes_for_digest(&digest), Some(b"first".as_slice()));
        assert_eq!(object_bytes, 5);
    }

    #[test]
    fn repeated_identical_file_bytes_are_charged_once() {
        let mut objects = ObjectAccumulator::default();
        let mut object_bytes = 0_u64;
        let digest = Digest::sha256(b"first");
        for _ in 0..3 {
            objects
                .insert_file(
                    digest.clone(),
                    b"first".to_vec(),
                    &mut object_bytes,
                    NO_OBJECT_LIMIT,
                )
                .expect("identical repeats are accepted");
        }
        assert_eq!(object_bytes, 5);
    }

    #[test]
    fn conflicting_symlink_bytes_for_one_digest_collide() {
        let mut objects = ObjectAccumulator::default();
        let mut object_bytes = 0_u64;
        let (first, first_bytes) = symlink_object("a");
        let (_, other_bytes) = symlink_object("bb");
        let digest = Digest::sha256(&first_bytes);
        objects
            .insert_symlink(
                digest.clone(),
                first,
                first_bytes,
                &mut object_bytes,
                NO_OBJECT_LIMIT,
            )
            .expect("first insert is accepted");

        let (other, _) = symlink_object("bb");
        let error = objects
            .insert_symlink(
                digest.clone(),
                other,
                other_bytes,
                &mut object_bytes,
                NO_OBJECT_LIMIT,
            )
            .expect_err("conflicting bytes for one digest are rejected");

        assert_eq!(error, ArchiveDecodeError::ObjectDigestCollision { digest });
    }

    #[test]
    fn conflicting_tree_bytes_for_one_digest_collide() {
        let mut objects = ObjectAccumulator::default();
        let mut object_bytes = 0_u64;
        let (first, first_bytes) = tree_object(0o755);
        let (_, other_bytes) = tree_object(0o700);
        let digest = Digest::sha256(&first_bytes);
        objects
            .insert_tree(
                digest.clone(),
                first,
                first_bytes,
                &mut object_bytes,
                NO_OBJECT_LIMIT,
            )
            .expect("first insert is accepted");

        let (other, _) = tree_object(0o700);
        let error = objects
            .insert_tree(
                digest.clone(),
                other,
                other_bytes,
                &mut object_bytes,
                NO_OBJECT_LIMIT,
            )
            .expect_err("conflicting bytes for one digest are rejected");

        assert_eq!(error, ArchiveDecodeError::ObjectDigestCollision { digest });
    }

    #[test]
    fn one_digest_cannot_hold_two_object_kinds_with_distinct_bytes() {
        let mut objects = ObjectAccumulator::default();
        let mut object_bytes = 0_u64;
        let (symlink, symlink_bytes) = symlink_object("a");
        let digest = Digest::sha256(&symlink_bytes);
        objects
            .insert_symlink(
                digest.clone(),
                symlink,
                symlink_bytes,
                &mut object_bytes,
                NO_OBJECT_LIMIT,
            )
            .expect("first insert is accepted");

        let error = objects
            .insert_file(
                digest.clone(),
                b"distinct".to_vec(),
                &mut object_bytes,
                NO_OBJECT_LIMIT,
            )
            .expect_err("a cross-kind digest conflict is rejected");

        assert_eq!(error, ArchiveDecodeError::ObjectDigestCollision { digest });
    }
}
