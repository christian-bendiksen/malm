//! Batched durability primitives shared by the object and prepared stores.
//!
//! Both stores publish content the same way: write bytes into an anonymous
//! inode, make them durable, then link the inode under a content-addressed
//! name. Paying a barrier per entry costs one device round trip each, which
//! dominates publication of many small entries, so entries are staged in
//! chunks and one barrier is paid per chunk. Nothing is named before its bytes
//! are durable.
//!
//! See `docs/architecture.md` for the ordering this depends on.

use std::fs::File;
use std::path::Path;

use rustix::fs::fsync;

use super::{EngineError, errno_error, io_error};

/// Upper bound on entries staged before a barrier. Every staged entry holds an
/// open descriptor until its chunk is linked, so this caps descriptor use
/// independently of how many entries are published. Measured barrier cost
/// flattens well before this point, so a larger window buys nothing.
const MAX_STAGED_ENTRIES: usize = 512;

/// Descriptors left for everything other than staged entries when the process
/// limit is the binding constraint.
const STAGED_DESCRIPTOR_RESERVE: u64 = 64;

/// Entries to stage before each barrier, bounded by the process descriptor
/// limit so that staging cannot exhaust descriptors however many entries a
/// publication writes.
pub(crate) fn staged_chunk_size(open_file_soft_limit: Option<u64>) -> usize {
    let Some(limit) = open_file_soft_limit else {
        return MAX_STAGED_ENTRIES;
    };
    let reserve = (limit / 4).max(STAGED_DESCRIPTOR_RESERVE);
    let available = limit.saturating_sub(reserve);
    usize::try_from(available)
        .unwrap_or(MAX_STAGED_ENTRIES)
        .clamp(1, MAX_STAGED_ENTRIES)
}

/// Pushes a staged entry's bytes to the device. Writes no metadata and flushes
/// no device cache.
pub(crate) fn start_writeback(file: &File, path: &Path) -> Result<(), EngineError> {
    use std::os::fd::AsRawFd;

    // SAFETY: `file` owns a valid open descriptor for the duration of the call,
    // and an offset and length of zero request the whole file.
    let result = unsafe {
        libc::sync_file_range(
            file.as_raw_fd(),
            0,
            0,
            libc::SYNC_FILE_RANGE_WRITE | libc::SYNC_FILE_RANGE_WAIT_AFTER,
        )
    };
    if result != 0 {
        return Err(io_error(
            "start staged entry writeback",
            path,
            std::io::Error::last_os_error(),
        ));
    }
    Ok(())
}

/// Flushes the device cache for the entries staged since the previous barrier.
///
/// Callers must not link any entry in the chunk before this returns.
pub(crate) fn barrier(file: &File, path: &Path) -> Result<(), EngineError> {
    fsync(file).map_err(|source| errno_error("sync staged entries", path, source))
}
