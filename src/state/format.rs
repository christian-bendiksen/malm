//! Checks the global state and CAS format. Incompatible stores cannot be
//! migrated safely because object identities and recovery records share an
//! authority boundary.

use crate::fs::atomic;
use crate::paths::xdg_state_home;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::io;
use std::path::{Path, PathBuf};

const STORE_FORMAT_VERSION: u32 = 2;

#[derive(Serialize, Deserialize)]
struct StoreFormat {
    version: u32,
}

fn root() -> PathBuf {
    xdg_state_home().join("malm")
}

fn marker_path() -> PathBuf {
    root().join("format.json")
}

pub fn ensure_current_for_mutation() -> Result<()> {
    if read_marker()?.is_some() {
        return Ok(());
    }
    let root = root();
    if has_legacy_data(&root)? {
        return Err(incompatible_store_error(&root, "missing format marker"));
    }
    let marker = StoreFormat {
        version: STORE_FORMAT_VERSION,
    };
    let json = serde_json::to_string_pretty(&marker).context("serialize store format marker")?;
    atomic::write(&marker_path(), json).context("initialize Malm store format")
}

/// Allow an absent store, but reject an existing pre-marker store.
pub fn require_current_if_present() -> Result<()> {
    if read_marker()?.is_some() {
        return Ok(());
    }
    let root = root();
    if has_legacy_data(&root)? {
        return Err(incompatible_store_error(&root, "missing format marker"));
    }
    Ok(())
}

fn read_marker() -> Result<Option<StoreFormat>> {
    let path = marker_path();
    let raw = match std::fs::read_to_string(&path) {
        Ok(raw) => raw,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error).with_context(|| format!("read {}", path.display())),
    };
    let marker: StoreFormat = serde_json::from_str(&raw).map_err(|error| {
        incompatible_store_error(
            &root(),
            &format!("unreadable format marker {}: {error}", path.display()),
        )
    })?;
    if marker.version != STORE_FORMAT_VERSION {
        return Err(incompatible_store_error(
            &root(),
            &format!(
                "store format version {} (this Malm requires exactly {STORE_FORMAT_VERSION})",
                marker.version
            ),
        ));
    }
    Ok(Some(marker))
}

fn has_legacy_data(root: &Path) -> Result<bool> {
    let entries = match std::fs::read_dir(root) {
        Ok(entries) => entries,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error).with_context(|| format!("read {}", root.display())),
    };
    for entry in entries {
        let entry = entry.with_context(|| format!("read entry in {}", root.display()))?;
        let name = entry.file_name();
        if name == "targets.lock" {
            continue;
        }
        if matches!(name.to_str(), Some("cache" | "sources")) && entry.file_type()?.is_dir() {
            continue;
        }
        if matches!(name.to_str(), Some("states" | "objects" | "transactions"))
            && entry.file_type()?.is_dir()
            && std::fs::read_dir(entry.path())?.next().is_none()
        {
            continue;
        }
        return Ok(true);
    }
    Ok(false)
}

pub fn incompatible_schema(path: &Path, expected: u32, actual: &str) -> anyhow::Error {
    incompatible_store_error(
        &root(),
        &format!(
            "unsupported schema in {}: expected exactly {expected}, got {actual}",
            path.display()
        ),
    )
}

fn incompatible_store_error(root: &Path, detail: &str) -> anyhow::Error {
    anyhow::anyhow!(
        "incompatible Malm state/CAS format: {detail}. Legacy state is not migrated. \
         To clean-reset, move `{root}` aside as a backup (or remove it after backing it up), \
         then run `malm apply` again",
        root = root.display()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schema_error_has_actionable_clean_reset_instructions() {
        let error = incompatible_schema(Path::new("ownership.json"), 3, "2");
        let message = error.to_string();
        assert!(message.contains("Legacy state is not migrated"));
        assert!(message.contains("move"));
        assert!(message.contains("malm apply"));
    }

    #[test]
    fn fetched_sources_do_not_make_an_unmarked_store_legacy() {
        let root = tempfile::tempdir().unwrap();
        let cache = root.path().join("cache/git/repository.git");
        let source = root.path().join("sources/git/repository/commit");
        std::fs::create_dir_all(&cache).unwrap();
        std::fs::create_dir_all(&source).unwrap();
        std::fs::write(cache.join("HEAD"), "ref: refs/heads/main\n").unwrap();
        std::fs::write(source.join("malm.kdl"), "config target=\"~\"\n").unwrap();

        assert!(!has_legacy_data(root.path()).unwrap());
    }

    #[test]
    fn authoritative_records_still_make_an_unmarked_store_legacy() {
        let root = tempfile::tempdir().unwrap();
        let state = root.path().join("states/default");
        std::fs::create_dir_all(&state).unwrap();
        std::fs::write(state.join("state.json"), "{}").unwrap();

        assert!(has_legacy_data(root.path()).unwrap());
    }
}
