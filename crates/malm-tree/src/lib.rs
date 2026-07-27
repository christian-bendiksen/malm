//! Pure canonical object models for immutable Malm trees.
//!
//! This crate only validates caller-provided models and bytes. It does not use
//! the filesystem, processes, network, plugins, or a store.

#![forbid(unsafe_code)]

mod codec;
mod graph;
mod model;

pub use codec::{
    ObjectKindV1, ObjectReadError, decode_file_object_v1, decode_symlink_object_v1,
    decode_tree_object_v1, decode_verified_file_object_v1, decode_verified_symlink_object_v1,
    decode_verified_tree_object_v1, encode_file_object_v1, encode_symlink_object_v1,
    encode_tree_object_v1, file_object_digest_v1, symlink_object_digest_v1, tree_object_digest_v1,
};
pub use graph::{TreeGraphError, TreeGraphV1, TreeSummaryV1};
pub use model::{
    NORMALIZED_SYMLINK_MODE, SymlinkObjectV1, TreeEntryKindV1, TreeEntryV1, TreeNodeKindV1,
    TreeObjectV1, TreePathSegmentV1, TreeValidationError, TreeValueError, TreeValueKindV1,
};

/// Supported canonical object encoding version.
pub const TREE_OBJECT_ENCODING_VERSION: u16 = 1;
/// Maximum UTF-8 bytes in a symlink target.
pub const MAX_SYMLINK_TARGET_BYTES: usize = 4096;
/// Maximum UTF-8 bytes in a tree path segment.
pub const MAX_TREE_SEGMENT_BYTES: usize = 255;
/// Maximum UTF-8 bytes in a slash-joined tree path.
pub const MAX_TREE_PATH_BYTES: usize = 4096;
/// Maximum path depth below a tree root.
pub const MAX_TREE_DEPTH: usize = 64;
/// Maximum logical entries in a tree graph.
pub const MAX_TREE_ENTRIES: usize = 100_000;
/// Maximum bytes represented by a regular-file entry.
pub const MAX_TREE_FILE_BYTES: u64 = 256 * 1024 * 1024;
/// Maximum total regular-file bytes in a logical tree.
pub const MAX_TREE_AGGREGATE_FILE_BYTES: u64 = 256 * 1024 * 1024;
/// Maximum canonical size of a regular-file object.
pub const MAX_FILE_OBJECT_BYTES: usize = 17 + 2 + 8 + MAX_TREE_FILE_BYTES as usize;
/// Maximum canonical size of a symlink object.
pub const MAX_SYMLINK_OBJECT_BYTES: usize = 20 + 2 + 8 + MAX_SYMLINK_TARGET_BYTES;
/// Maximum canonical size of a tree object.
pub const MAX_TREE_OBJECT_BYTES: usize =
    17 + 2 + 4 + 8 + MAX_TREE_ENTRIES * (8 + MAX_TREE_SEGMENT_BYTES + 1 + 4 + 8 + 71 + 8);
