//! Locates `malm.kdl` for a source: explicit/default path for local
//! repos; for remote repos additionally rejects symlinks and oversized files.

use anyhow::{Context, Result};
use std::fs;
use std::path::{Path, PathBuf};

const MAX_REMOTE_CONFIG_BYTES: u64 = 1024 * 1024;

pub(crate) fn local_config_path(source_root: &Path, explicit: Option<PathBuf>) -> PathBuf {
    explicit
        .map(|config| {
            if config.is_absolute() {
                config
            } else {
                source_root.join(config)
            }
        })
        .unwrap_or_else(|| source_root.join("malm.kdl"))
}

pub(crate) fn remote_config_path(source_root: &Path) -> Result<PathBuf> {
    let path = source_root.join("malm.kdl");
    let metadata =
        fs::symlink_metadata(&path).with_context(|| format!("stat {}", path.display()))?;
    if metadata.file_type().is_symlink() {
        anyhow::bail!("remote config must not be a symlink: {}", path.display());
    }
    if !metadata.file_type().is_file() {
        anyhow::bail!("remote config must be a regular file: {}", path.display());
    }
    if metadata.len() > MAX_REMOTE_CONFIG_BYTES {
        anyhow::bail!(
            "remote config is too large ({} bytes, max {MAX_REMOTE_CONFIG_BYTES}): {}",
            metadata.len(),
            path.display()
        );
    }
    Ok(path)
}
