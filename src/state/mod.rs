//! The persisted state layer: per-state records, the transaction journal,
//! GC, integrity checking, and cross-state locking.

use anyhow::{Context, Result};

pub mod active_deployment;
pub mod format;
pub mod gc;
pub mod integrity;
pub mod ownership;
pub mod ownership_store;
pub mod pins;
pub mod record;
pub mod target_lock;
pub mod tracking;
pub mod transaction;
use crate::paths::xdg_state_home;

pub fn state_namespaces() -> Result<Vec<String>> {
    format::require_current_if_present()?;
    let states_dir = xdg_state_home().join("malm/states");
    let entries = match std::fs::read_dir(&states_dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e).with_context(|| format!("read {}", states_dir.display())),
    };
    let mut names = Vec::new();
    for entry in entries {
        let entry = entry.with_context(|| format!("read entry in {}", states_dir.display()))?;
        if !entry.file_type()?.is_dir() {
            continue;
        }
        if let Some(name) = entry.file_name().to_str() {
            names.push(name.to_owned());
        }
    }
    names.sort();
    Ok(names)
}

pub fn ensure_state_exists(name: &str) -> Result<()> {
    let state_dir = xdg_state_home().join("malm/states").join(name);
    if state_dir.is_dir() {
        return Ok(());
    }
    let known = state_namespaces()?;
    if known.is_empty() {
        anyhow::bail!("state '{name}' does not exist; no states are recorded");
    }
    anyhow::bail!(
        "state '{name}' does not exist; known states: {} — see `malm state list`",
        known.join(", ")
    );
}
