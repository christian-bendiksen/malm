//! Manages the `current` source pointer. Deployed symlinks resolve through this
//! pointer, so replacing it atomically activates the whole snapshot. The state
//! record tracks which transaction is live.

use crate::paths::xdg_state_home;
use anyhow::{Context, Result};
use std::io;
use std::path::{Path, PathBuf};

pub fn source_pointer_path(state_namespace: &str) -> PathBuf {
    xdg_state_home()
        .join("malm/states")
        .join(state_namespace)
        .join("current")
}

pub fn read_source_pointer(state_namespace: &str) -> Result<Option<PathBuf>> {
    let path = source_pointer_path(state_namespace);
    match std::fs::read_link(&path) {
        Ok(target) => Ok(Some(target)),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e).with_context(|| format!("read link {}", path.display())),
    }
}

pub fn set_source_pointer(state_namespace: &str, object_root: &Path) -> Result<()> {
    let pointer = source_pointer_path(state_namespace);
    let parent = pointer
        .parent()
        .context("source pointer has no parent directory")?;
    std::fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    // Include the PID so concurrent processes use different staging symlinks.
    let staged = parent.join(format!(".current.malm-tmp.{}", std::process::id()));
    let _ = std::fs::remove_file(&staged);
    std::os::unix::fs::symlink(object_root, &staged)
        .with_context(|| format!("stage source pointer -> {}", object_root.display()))?;
    std::fs::rename(&staged, &pointer).with_context(|| {
        let _ = std::fs::remove_file(&staged);
        format!("install source pointer {}", pointer.display())
    })?;
    if let Ok(dir) = std::fs::File::open(parent) {
        let _ = dir.sync_all();
    }
    Ok(())
}

/// Restore `previous`, or remove the pointer if none existed.
///
/// Recovery uses this for pre-phase applies that swapped the pointer before
/// completing the filesystem transaction.
pub fn restore_source_pointer(state_namespace: &str, previous: Option<&Path>) -> Result<()> {
    match previous {
        Some(object_root) => set_source_pointer(state_namespace, object_root),
        None => {
            let pointer = source_pointer_path(state_namespace);
            match std::fs::remove_file(&pointer) {
                Ok(()) => Ok(()),
                Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
                Err(e) => {
                    Err(e).with_context(|| format!("clear source pointer {}", pointer.display()))
                }
            }
        }
    }
}
