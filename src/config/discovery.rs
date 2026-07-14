//! Locates `malm.kdl` for a source: explicit/default path for local
//! repos; for remote repos additionally rejects symlinks and oversized files.

use anyhow::{Context, Result};
use std::fs;
use std::path::{Component, Path, PathBuf};

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

pub(crate) fn validate_remote_config_relative(path: &Path) -> Result<()> {
    if path.as_os_str().is_empty() || path.is_absolute() {
        anyhow::bail!(
            "remote config path must be repository-relative: {}",
            path.display()
        );
    }
    for component in path.components() {
        let Component::Normal(name) = component else {
            anyhow::bail!(
                "remote config path must not contain `.`, `..`, a root, or a prefix: {}",
                path.display()
            );
        };
        if name == std::ffi::OsStr::new("~") {
            anyhow::bail!("remote config path must not use `~`: {}", path.display());
        }
    }
    Ok(())
}

pub(crate) fn remote_config_path(source_root: &Path, explicit: Option<&Path>) -> Result<PathBuf> {
    let relative = explicit.unwrap_or_else(|| Path::new("malm.kdl"));
    validate_remote_config_relative(relative)?;

    let component_count = relative.components().count();
    let mut path = source_root.to_path_buf();
    for (index, component) in relative.components().enumerate() {
        let Component::Normal(name) = component else {
            unreachable!("validated normal remote config components")
        };
        path.push(name);
        let metadata =
            fs::symlink_metadata(&path).with_context(|| format!("stat {}", path.display()))?;
        if metadata.file_type().is_symlink() {
            anyhow::bail!(
                "remote config path must not contain symlinks: {}",
                path.display()
            );
        }
        if index + 1 == component_count {
            if !metadata.file_type().is_file() {
                anyhow::bail!("remote config must be a regular file: {}", path.display());
            }
        } else if !metadata.file_type().is_dir() {
            anyhow::bail!(
                "remote config parent must be a directory: {}",
                path.display()
            );
        }
    }

    let metadata = fs::symlink_metadata(&path)
        .with_context(|| format!("stat remote config {}", path.display()))?;
    if metadata.len() > MAX_REMOTE_CONFIG_BYTES {
        anyhow::bail!(
            "remote config is too large ({} bytes, max {MAX_REMOTE_CONFIG_BYTES}): {}",
            metadata.len(),
            path.display()
        );
    }
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn remote_config_relative_path_rejects_escapes() {
        for path in [
            "",
            "/tmp/malm.kdl",
            "../malm.kdl",
            "./malm.kdl",
            "~/malm.kdl",
        ] {
            assert!(
                validate_remote_config_relative(Path::new(path)).is_err(),
                "accepted {path:?}"
            );
        }
        validate_remote_config_relative(Path::new("system-models/malm.kdl")).unwrap();
    }

    #[test]
    fn remote_config_path_rejects_symlinked_components() {
        let root = tempfile::tempdir().unwrap();
        let real = root.path().join("real");
        fs::create_dir(&real).unwrap();
        fs::write(real.join("malm.kdl"), "config target=\"~\"").unwrap();
        std::os::unix::fs::symlink(&real, root.path().join("linked")).unwrap();
        assert!(remote_config_path(root.path(), Some(Path::new("linked/malm.kdl"))).is_err());
    }
}
