//! Durable atomic writes and staged-tree placement.
//!
//! New file data is synced before rename, and parent directories are synced
//! after directory-entry changes for POSIX crash durability.

use anyhow::{Context, Result};
use std::fs;
use std::io::Write;
use std::path::Path;
use tempfile::Builder;
use walkdir::WalkDir;

pub fn write(path: &Path, contents: impl AsRef<[u8]>) -> Result<()> {
    let dir = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("atomic write path has no parent: {}", path.display()))?;
    fs::create_dir_all(dir).with_context(|| format!("create {}", dir.display()))?;

    let mut tmp = Builder::new()
        .prefix(".malm-tmp.")
        .tempfile_in(dir)
        .with_context(|| format!("create secure temp file in {}", dir.display()))?;

    tmp.write_all(contents.as_ref())
        .with_context(|| format!("write {}", tmp.path().display()))?;

    tmp.as_file()
        .sync_all()
        .with_context(|| format!("sync {}", tmp.path().display()))?;

    tmp.persist(path)
        .map_err(|e| e.error)
        .with_context(|| format!("atomically persist to {}", path.display()))?;

    let dir_file =
        fs::File::open(dir).with_context(|| format!("open {} for sync", dir.display()))?;
    dir_file
        .sync_all()
        .with_context(|| format!("sync directory {}", dir.display()))?;

    Ok(())
}

/// fsync a regular file's data and metadata. Required before a rename makes a
/// file's contents visible, and after copying a user-owned file to a backup
/// location.
pub(crate) fn sync_file(path: &Path) -> Result<()> {
    fs::File::open(path)
        .and_then(|file| file.sync_all())
        .with_context(|| format!("sync {}", path.display()))
}

/// fsync a directory: persists dirent additions, removals, and renames within
/// that directory. A rename or unlink is not durable unless this runs on the
/// parent directory afterwards.
pub(crate) fn sync_dir(path: &Path) -> Result<()> {
    let file = fs::File::open(path).with_context(|| format!("open {} for sync", path.display()))?;
    file.sync_all()
        .with_context(|| format!("sync directory {}", path.display()))
}

/// fsync the parent directory of `path`, if it has one.
pub(crate) fn sync_parent_dir(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        sync_dir(parent)?;
    }
    Ok(())
}

/// Best-effort directory fsync: ignores errors. Used inside the CAS, where an
/// unsupported directory fsync must not fail placement of an object that is
/// already durable by other means, and for staged-tree sub-directories whose
/// dirent changes become durable when the staging root is renamed and its new
/// parent is fsynced.
pub(crate) fn sync_dir_best_effort(path: &Path) {
    if let Ok(handle) = fs::File::open(path) {
        let _ = handle.sync_all();
    }
}

/// fsync every regular file and directory beneath `root`. File-data fsync
/// failures propagate (the data is load-bearing); directory fsyncs are
/// best-effort within the staged tree, because the rename that makes the tree
/// visible is paired with a [`sync_parent_dir`] on the destination.
pub(crate) fn sync_tree(root: &Path) -> Result<()> {
    for entry in WalkDir::new(root).follow_links(false) {
        let entry = entry.with_context(|| format!("walk {}", root.display()))?;
        let file_type = entry.file_type();
        if file_type.is_file() {
            sync_file(entry.path())?;
        } else if file_type.is_dir() {
            sync_dir_best_effort(entry.path());
        }
    }
    Ok(())
}

/// Atomically replace `dst` with `staged` and durably record the change in the
/// destination directory.
///
/// `fs::rename` atomically replaces `dst`. POSIX does not guarantee the
/// replacement survives power loss unless `dst`'s parent directory is fsynced
/// afterwards, so this syncs the parent directory once the rename wins. The
/// staged content must already be durable (or carry no data, e.g. a symlink).
/// To place tree content that still needs syncing, use
/// [`place_tree_durable`].
pub(crate) fn swap_durable(staged: &Path, dst: &Path) -> Result<()> {
    fs::rename(staged, dst).with_context(|| format!("atomically swap {}", dst.display()))?;
    sync_parent_dir(dst)
}

/// fsync every file and directory in a staged tree, atomically place it at
/// `dst` (refusing to clobber an existing entry), then sync the destination
/// directory. Works for a single staged file too ([`sync_tree`] syncs a file
/// root in place).
pub(crate) fn place_tree_durable(staged: &Path, dst: &Path) -> Result<()> {
    sync_tree(staged)?;
    crate::fs::util::rename_noreplace(staged, dst)?;
    sync_parent_dir(dst)
}
