//! `PathIdentity`: a dev/inode/mode/size/mtime/ctime fingerprint used to
//! detect a path changing between inspection and mutation (TOCTOU guard).

use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
// ctime is included because it cannot be forged from userspace:
// restoring mtime after a swap does not restore ctime.
pub(crate) struct PathIdentity {
    device: u64,
    inode: u64,
    mode: u32,
    size: u64,
    modified_seconds: i64,
    modified_nanoseconds: i64,
    changed_seconds: i64,
    changed_nanoseconds: i64,
}

impl PathIdentity {
    pub(crate) fn capture(path: &Path) -> std::io::Result<Self> {
        let metadata = fs::symlink_metadata(path)?;
        Ok(Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            mode: metadata.mode(),
            size: metadata.size(),
            modified_seconds: metadata.mtime(),
            modified_nanoseconds: metadata.mtime_nsec(),
            changed_seconds: metadata.ctime(),
            changed_nanoseconds: metadata.ctime_nsec(),
        })
    }

    pub(crate) fn ensure_unchanged(self, path: &Path) -> anyhow::Result<()> {
        let current = Self::capture(path)
            .map_err(anyhow::Error::from)
            .with_context(|| format!("re-inspect {}", path.display()))?;
        if current != self {
            anyhow::bail!(
                "{} changed during apply; refusing to overwrite or remove it",
                path.display()
            );
        }
        Ok(())
    }
}

use anyhow::Context;

#[derive(Debug, Clone)]
pub enum FilesystemPathState {
    Missing,
    File,
    Directory,
    Symlink { target: PathBuf },
    BrokenSymlink,
    Other,
}

pub fn inspect_filesystem_path(path: &Path) -> FilesystemPathState {
    match fs::symlink_metadata(path) {
        Err(_) => FilesystemPathState::Missing,
        Ok(meta) if meta.file_type().is_symlink() => match path.read_link() {
            Err(_) => FilesystemPathState::Other,
            Ok(target) => {
                if symlink_target_is_reachable(path, &target) {
                    FilesystemPathState::Symlink { target }
                } else {
                    FilesystemPathState::BrokenSymlink
                }
            }
        },
        Ok(meta) if meta.file_type().is_dir() => FilesystemPathState::Directory,
        Ok(meta) if meta.file_type().is_file() => FilesystemPathState::File,
        Ok(_) => FilesystemPathState::Other,
    }
}

pub(crate) fn symlink_target_is_reachable(link: &Path, raw_target: &Path) -> bool {
    if raw_target.is_absolute() {
        raw_target.exists()
    } else {
        link.parent()
            .unwrap_or(Path::new("."))
            .join(raw_target)
            .exists()
    }
}
