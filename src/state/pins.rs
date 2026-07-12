//! GC pins: per-state lists of transactions protected from pruning.

use crate::fs::atomic;
use crate::paths::xdg_state_home;
use anyhow::{Context, Result};
use std::collections::HashSet;
use std::io;
use std::path::PathBuf;

fn pins_path_for(state_namespace: &str) -> PathBuf {
    xdg_state_home()
        .join("malm/states")
        .join(state_namespace)
        .join("pins.json")
}

pub fn read_pins(state_namespace: &str) -> Result<Vec<String>> {
    let path = pins_path_for(state_namespace);
    match std::fs::read_to_string(&path) {
        Ok(raw) => serde_json::from_str(&raw).with_context(|| format!("parse {}", path.display())),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(e) => Err(e).with_context(|| format!("read {}", path.display())),
    }
}

fn write_pins(state_namespace: &str, mut pins: Vec<String>) -> Result<()> {
    pins.sort();
    pins.dedup();
    let path = pins_path_for(state_namespace);
    let json = serde_json::to_string_pretty(&pins).context("serialize pins")?;
    atomic::write(&path, json).with_context(|| format!("write {}", path.display()))
}

pub fn add_pin(state_namespace: &str, transaction_id: &str) -> Result<bool> {
    let mut pins = read_pins(state_namespace)?;
    if pins.iter().any(|id| id == transaction_id) {
        return Ok(false);
    }
    pins.push(transaction_id.to_owned());
    write_pins(state_namespace, pins)?;
    Ok(true)
}

pub fn remove_pin(state_namespace: &str, transaction_id: &str) -> Result<bool> {
    let mut pins = read_pins(state_namespace)?;
    let before = pins.len();
    pins.retain(|id| id != transaction_id);
    if pins.len() == before {
        return Ok(false);
    }
    write_pins(state_namespace, pins)?;
    Ok(true)
}

pub fn all_pinned_ids() -> Result<HashSet<String>> {
    let mut ids = HashSet::new();
    let states_dir = xdg_state_home().join("malm/states");
    let entries = match std::fs::read_dir(&states_dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(ids),
        Err(e) => return Err(e).with_context(|| format!("read {}", states_dir.display())),
    };
    for entry in entries {
        let entry = entry.with_context(|| format!("read entry in {}", states_dir.display()))?;
        let name = entry.file_name();
        let Some(namespace) = name.to_str() else {
            continue;
        };
        if crate::app::validation::validate_name(namespace, "state name").is_err() {
            crate::warn_term!(
                "warning: ignoring state directory with an invalid name: {namespace:?}"
            );
            continue;
        }
        ids.extend(read_pins(namespace)?);
    }
    Ok(ids)
}
