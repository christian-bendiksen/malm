//! Move/copy/rename primitives: cross-device move, metadata-preserving
//! recursive copy, and atomic no-clobber rename.

use crate::fs::atomic;
use crate::fs::inspect::PathIdentity;
use anyhow::{Context, Result};
use std::fs;
use std::path::Path;

/// Move `from` to `to`, durably.
///
/// On the same filesystem this is an atomic `rename`; the inode's data is
/// already durable, so only the directory-entry change in the source and
/// destination directories is synced. Across filesystems it falls back to a
/// copy + remove: the copy is fsynced (every file and directory) before the
/// original is removed, so a crash cannot lose the only copy of the bytes.
pub fn move_path(from: &Path, to: &Path) -> Result<()> {
    if let Some(parent) = to.parent().filter(|p| !p.as_os_str().is_empty()) {
        fs::create_dir_all(parent)
            .with_context(|| format!("create parent for {}", to.display()))?;
    }
    match fs::rename(from, to) {
        Ok(()) => {
            atomic::sync_parent_dir(to)?;
            atomic::sync_parent_dir(from)?;
            return Ok(());
        }
        // EXDEV requires a copy followed by removal.
        Err(e) if e.raw_os_error() == Some(libc::EXDEV) => {}
        Err(e) => {
            return Err(e)
                .with_context(|| format!("rename {} -> {}", from.display(), to.display()));
        }
    }
    // The copy+remove fallback is not atomic: the source could be swapped
    // between the copy and the remove, deleting content that was never
    // copied. Only remove the original if it is still the inspected object.
    let identity = PathIdentity::capture(from)
        .with_context(|| format!("inspect {} before cross-device move", from.display()))?;
    copy_recursive(from, to)?;
    // Sync the copied contents before removing the original. The directory
    // entries are synced after removal.
    atomic::sync_tree(to).with_context(|| format!("sync moved tree {}", to.display()))?;
    if let Err(err) = identity.ensure_unchanged(from) {
        let _ = remove_path(to); // the copy may be inconsistent
        return Err(err).context("source changed during cross-device move; copy discarded");
    }
    remove_path(from)?;
    atomic::sync_parent_dir(to)?;
    atomic::sync_parent_dir(from)?;
    Ok(())
}

pub fn copy_recursive(src: &Path, dst: &Path) -> Result<()> {
    let file_type = fs::symlink_metadata(src)
        .with_context(|| format!("stat {}", src.display()))?
        .file_type();
    if file_type.is_symlink() {
        let target = fs::read_link(src)?;
        if let Some(parent) = dst.parent().filter(|p| !p.as_os_str().is_empty()) {
            fs::create_dir_all(parent)
                .with_context(|| format!("create parent for {}", dst.display()))?;
        }
        std::os::unix::fs::symlink(target, dst)
            .with_context(|| format!("recreate symlink {}", dst.display()))?;
        if let Ok(meta) = fs::symlink_metadata(src) {
            let atime = filetime::FileTime::from_last_access_time(&meta);
            let mtime = filetime::FileTime::from_last_modification_time(&meta);
            let _ = filetime::set_symlink_file_times(dst, atime, mtime);
        }
    } else if file_type.is_dir() {
        fs::create_dir_all(dst).with_context(|| format!("create {}", dst.display()))?;
        for entry in fs::read_dir(src).with_context(|| format!("read dir {}", src.display()))? {
            let entry = entry?;
            copy_recursive(&entry.path(), &dst.join(entry.file_name()))?;
        }
        apply_metadata(src, dst)?;
    } else if file_type.is_file() {
        if let Some(parent) = dst.parent() {
            fs::create_dir_all(parent)?;
        }
        copy_regular_file_preserving_metadata(src, dst)?;
    } else {
        anyhow::bail!("cannot copy special file: {}", src.display());
    }
    Ok(())
}

pub fn rename_noreplace(from: &Path, to: &Path) -> Result<()> {
    rename_noreplace_platform(from, to)
}

#[cfg(any(
    target_os = "android",
    target_os = "linux",
    target_os = "macos",
    target_os = "ios",
    target_os = "tvos",
    target_os = "watchos"
))]
fn rename_noreplace_platform(from: &Path, to: &Path) -> Result<()> {
    use rustix::fs::{CWD, RenameFlags, renameat_with};

    renameat_with(CWD, from, CWD, to, RenameFlags::NOREPLACE)
        .map_err(std::io::Error::from)
        .with_context(|| {
            format!(
                "atomically place {} without replacing {}",
                from.display(),
                to.display()
            )
        })
}

#[cfg(not(any(
    target_os = "android",
    target_os = "linux",
    target_os = "macos",
    target_os = "ios",
    target_os = "tvos",
    target_os = "watchos"
)))]
fn rename_noreplace_platform(from: &Path, to: &Path) -> Result<()> {
    anyhow::bail!(
        "atomic no-replace rename is unsupported on this platform ({} → {})",
        from.display(),
        to.display()
    )
}

pub fn is_already_exists(error: &anyhow::Error) -> bool {
    error
        .chain()
        .filter_map(|cause| cause.downcast_ref::<std::io::Error>())
        .any(|io| io.kind() == std::io::ErrorKind::AlreadyExists)
}

/// Copy a regular file with its permissions, times, and xattrs. The source
/// must be a regular file. Symlinks are not followed and directories are
/// rejected, so a caller can never be redirected through a planted symlink.
pub fn copy_regular_file_preserving_metadata(src: &Path, dst: &Path) -> Result<()> {
    let meta = fs::symlink_metadata(src).with_context(|| format!("stat {}", src.display()))?;
    if !meta.file_type().is_file() {
        anyhow::bail!(
            "expected a regular file, found {}: {}",
            if meta.file_type().is_symlink() {
                "a symlink"
            } else if meta.file_type().is_dir() {
                "a directory"
            } else {
                "a special file"
            },
            src.display()
        );
    }
    fs::copy(src, dst).with_context(|| format!("copy {}", dst.display()))?;
    apply_metadata_from(&meta, src, dst)
}

fn apply_metadata_from(meta: &fs::Metadata, src: &Path, dst: &Path) -> Result<()> {
    fs::set_permissions(dst, meta.permissions())
        .with_context(|| format!("set mode on {}", dst.display()))?;
    let atime = filetime::FileTime::from_last_access_time(meta);
    let mtime = filetime::FileTime::from_last_modification_time(meta);
    filetime::set_file_times(dst, atime, mtime)
        .with_context(|| format!("set times on {}", dst.display()))?;
    copy_xattrs(src, dst);
    Ok(())
}

fn apply_metadata(src: &Path, dst: &Path) -> Result<()> {
    let meta = fs::symlink_metadata(src).with_context(|| format!("stat {}", src.display()))?;
    apply_metadata_from(&meta, src, dst)
}

fn copy_xattrs(src: &Path, dst: &Path) {
    let Ok(names) = xattr::list(src) else {
        return;
    };
    for name in names {
        // Copy only the user-visible namespace. The `security.*` namespace
        // (e.g. SELinux labels) is reassigned by the kernel/SELinux policy on
        // the destination path, and `trusted.*` is root-only and should not
        // ride along across a trust boundary (CAS payload -> user home).
        let Some(name) = name.to_str() else {
            continue;
        };
        if !name.starts_with("user.") {
            continue;
        }
        if let Ok(Some(value)) = xattr::get(src, name) {
            let _ = xattr::set(dst, name, &value);
        }
    }
}

pub fn remove_path(path: &Path) -> Result<()> {
    if fs::symlink_metadata(path)?.file_type().is_dir() {
        fs::remove_dir_all(path).with_context(|| format!("remove dir {}", path.display()))
    } else {
        fs::remove_file(path).with_context(|| format!("remove {}", path.display()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn move_path_renames_within_the_same_filesystem() {
        let dir = tempfile::tempdir().unwrap();
        let from = dir.path().join("src/tree");
        fs::create_dir_all(from.join("nested")).unwrap();
        fs::write(from.join("nested/file"), b"payload").unwrap();

        let to = dir.path().join("dst/tree");
        move_path(&from, &to).unwrap();

        assert!(!from.exists());
        assert_eq!(fs::read(to.join("nested/file")).unwrap(), b"payload");
    }
}
