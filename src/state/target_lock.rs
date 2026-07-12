//! Global target ownership and cross-process locking. Every mutation acquires
//! the exclusive guard, which first runs state-root hardening.

use crate::fs::lock::lock_exclusive_with_feedback;
use crate::fs::{atomic, lock};
use crate::paths::{normalize_lexical, xdg_state_home};
use crate::policy::destination::resolve_destination_physically;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io;
use std::path::{Path, PathBuf};

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct TargetLock(BTreeMap<PathBuf, String>);

pub struct TargetLockGuard {
    file: File,
}

impl Drop for TargetLockGuard {
    fn drop(&mut self) {
        lock::unlock(&self.file);
    }
}

impl TargetLock {
    pub fn lock_path() -> PathBuf {
        xdg_state_home().join("malm/targets.json")
    }

    pub fn guard_path() -> PathBuf {
        xdg_state_home().join("malm/targets.lock")
    }

    /// Acquire the exclusive mutation guard after hardening the state root.
    pub fn acquire_guard() -> Result<TargetLockGuard> {
        crate::state::integrity::preflight::preflight_mutating()?;
        let file = Self::open_guard_file()?;
        lock_exclusive_with_feedback(&file, "target lock")?;
        Ok(TargetLockGuard { file })
    }

    /// Acquire a shared lock for a consistent read. Readers can run together,
    /// but exclude mutations. Fsck reports hardening issues; read-only commands
    /// do not run the mutating preflight.
    pub fn acquire_shared_guard() -> Result<TargetLockGuard> {
        crate::state::format::require_current_if_present()?;
        let file = Self::open_guard_file()?;
        lock::lock_shared_with_feedback(&file, "target lock")?;
        Ok(TargetLockGuard { file })
    }

    fn open_guard_file() -> Result<File> {
        let path = Self::guard_path();
        let dir = path
            .parent()
            .expect("target lock guard path always has a parent");
        std::fs::create_dir_all(dir).with_context(|| format!("create {}", dir.display()))?;
        // O_NOFOLLOW rejects a symlink at the guard path. Following one would
        // lock the wrong file, and the former File::create path could also
        // truncate the symlink target.
        use std::os::unix::fs::OpenOptionsExt;
        match OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&path)
        {
            Ok(file) => Ok(file),
            Err(e) if e.raw_os_error() == Some(libc::ELOOP) => anyhow::bail!(
                "guard file {} is a symlink and will not be followed; remove it and re-run",
                path.display()
            ),
            Err(e) => Err(e).with_context(|| format!("open {}", path.display())),
        }
    }

    pub fn load() -> Result<Self> {
        let path = Self::lock_path();
        match std::fs::read_to_string(&path) {
            Ok(raw) => {
                serde_json::from_str(&raw).with_context(|| format!("parse {}", path.display()))
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(e).with_context(|| format!("read {}", path.display())),
        }
    }

    pub fn save(&self) -> Result<()> {
        let path = Self::lock_path();
        let json = serde_json::to_string_pretty(&self.0).context("serialize target lock")?;
        atomic::write(&path, json).with_context(|| format!("write {}", path.display()))
    }

    pub fn conflicts_for(
        &self,
        targets: &[PathBuf],
        state_namespace: &str,
    ) -> Vec<(PathBuf, PathBuf, String)> {
        let mut conflicts = Vec::new();
        for target in targets {
            for (existing_path, owner) in &self.0 {
                if owner.as_str() != state_namespace && lock_conflicts(existing_path, target) {
                    conflicts.push((target.clone(), existing_path.clone(), owner.clone()));
                }
            }
        }
        conflicts.sort();
        conflicts.dedup();
        conflicts
    }

    pub fn check_no_conflicts(&self, targets: &[PathBuf], state_namespace: &str) -> Result<()> {
        let conflicts = self.conflicts_for(targets, state_namespace);
        if conflicts.is_empty() {
            return Ok(());
        }

        let mut msg = format!(
            "{} path conflict(s) detected with other Malm states:",
            conflicts.len()
        );

        for (target, existing, owner) in &conflicts {
            if target == existing {
                msg.push_str(&format!(
                    "\n  {}  (already owned by state \"{}\")",
                    target.display(),
                    owner
                ));
            } else {
                msg.push_str(&format!(
                    "\n  {}  (overlaps with {} owned by state \"{}\")",
                    target.display(),
                    existing.display(),
                    owner
                ));
            }
        }

        msg.push_str(
            "\n\nUse --state to select the owning state, or resolve the conflict manually to ensure no paths overlap.",
        );
        anyhow::bail!("{msg}")
    }

    pub fn targets_for(&self, state_namespace: &str) -> std::collections::BTreeSet<&Path> {
        self.0
            .iter()
            .filter(|(_, owner)| owner.as_str() == state_namespace)
            .map(|(path, _)| path.as_path())
            .collect()
    }

    pub fn update_state(&mut self, current_targets: &[PathBuf], state_namespace: &str) {
        self.0.retain(|_, owner| owner != state_namespace);
        for target in current_targets {
            self.0.insert(target.clone(), state_namespace.to_owned());
        }
    }
}

pub(crate) fn physical_key(path: &Path) -> PathBuf {
    let norm = normalize_lexical(path);
    resolve_destination_physically(&norm).unwrap_or(norm)
}

fn paths_overlap(a: &Path, b: &Path) -> bool {
    a == b || a.starts_with(b) || b.starts_with(a)
}

// Compare lexical and resolved paths so different spellings of one location
// still conflict.
fn lock_conflicts(existing: &Path, candidate: &Path) -> bool {
    if paths_overlap(existing, candidate) {
        return true;
    }

    let existing_physical = physical_key(existing);
    let candidate_physical = physical_key(candidate);

    paths_overlap(&existing_physical, &candidate_physical)
}
