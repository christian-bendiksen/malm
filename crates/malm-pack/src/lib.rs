//! Contracts for versioned Malm packs and locked pack graphs.
//!
//! This crate only parses and validates supplied bytes. It does not access the
//! filesystem, source acquisition, network, CLI, or store.

mod canonical;
mod lock;
mod model;
mod object;
mod pack;

pub use lock::{
    LockReadError, LockV1, LockValidationError, LockedComponentV1, LockedDependencyV1,
    LockedPackV1, LockedSourceV1, decode_lock_v1, encode_lock_v1, lock_graph_digest, pack_node_id,
};
pub use model::{
    BundledComponentV1, ComponentInterfaceV1, DependencySourceV1, GitObjectId, GitSourceV1, GitUrl,
    LocalLocator, PackDependencyV1, PackFileV1, PackManifestV1, PackModuleV1, PackPath, PackSubdir,
    PackTreeError, PackValidationError, ValueError, classify_pack_tree_path, pack_content_digest,
};
pub use object::{
    PackObjectReadError, PackObjectWriteError, read_pack_object_v1, write_pack_object_entries_v1,
    write_pack_object_v1,
};
pub use pack::{PackReadError, decode_pack_v1, encode_pack_v1};

/// Supported pack schema version.
pub const PACK_SCHEMA_VERSION: u32 = 1;

/// Required manifest filename at the pack root.
pub const PACK_MANIFEST_FILE: &str = "malm-pack.kdl";

/// Lock filename excluded from pack trees.
pub const LOCK_FILE: &str = "malm.lock";

/// Lock staging filename excluded from pack trees.
pub const LOCK_STAGING_FILE: &str = ".malm-lock.tmp";

/// Maximum encoded manifest size.
pub const MAX_PACK_MANIFEST_BYTES: usize = 1024 * 1024;

/// Maximum files in a logical pack tree.
pub const MAX_PACK_TREE_ENTRIES: usize = 100_000;

/// Maximum total bytes in a logical pack tree.
pub const MAX_PACK_TREE_BYTES: u64 = 1024 * 1024 * 1024;

/// Maximum bytes in a logical pack file.
pub const MAX_PACK_FILE_BYTES: u64 = 256 * 1024 * 1024;

/// Maximum encoded size of a canonical pack object.
pub const MAX_PACK_OBJECT_BYTES: u64 =
    MAX_PACK_TREE_BYTES + (MAX_PACK_TREE_ENTRIES as u64 * (16 + 1024)) + 64;

/// Supported lock schema version.
pub const LOCK_SCHEMA_VERSION: u32 = 1;

/// Maximum encoded lock size.
pub const MAX_LOCK_BYTES: usize = 16 * 1024 * 1024;

/// Maximum nodes in a locked graph.
pub const MAX_LOCK_NODES: usize = 4096;

/// Maximum edges in a locked graph.
pub const MAX_LOCK_EDGES: usize = 16_384;
