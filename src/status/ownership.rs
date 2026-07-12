//! Drift, source-pointer, and target-lock checks for deployed states.

use crate::cas::{EntryKind, TreeWalk, object_present, sources_dir, walk_tree};
use crate::source::SourceIdentity;
use crate::source::store::SourceSnapshot;
use crate::state::active_deployment::{read_source_pointer, source_pointer_path};
use crate::state::ownership::{OwnerKind, OwnershipIndex};
use crate::state::ownership_store::read_ownership_for;
use crate::state::target_lock::TargetLock;
use anyhow::Result;
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

#[derive(Debug)]
pub struct ManagedPathStatus {
    pub path: PathBuf,
    pub expected: Option<PathBuf>,
    pub owner: String,
    pub status: &'static str,
}

#[derive(Debug)]
pub struct OwnershipStatusReport {
    pub source: Option<SourceIdentity>,
    pub results: Vec<ManagedPathStatus>,
    pub source_pointer: SourcePointerHealth,
    pub target_lock: TargetLockHealth,
    pub has_drift: bool,
}

#[derive(Debug, Clone)]
pub struct TargetLockConflict {
    pub target: PathBuf,
    pub conflicts_with: PathBuf,
    pub state: String,
}

#[derive(Debug, Clone)]
pub enum TargetLockHealth {
    Ok,
    Repairable,
    ForeignConflict(Vec<TargetLockConflict>),
}

impl TargetLockHealth {
    pub fn is_ok(&self) -> bool {
        matches!(self, Self::Ok)
    }

    pub fn label(&self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Repairable => "repairable",
            Self::ForeignConflict(_) => "foreign-conflict",
        }
    }
}

impl OwnershipStatusReport {
    pub fn is_empty(&self) -> bool {
        self.results.is_empty()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourcePointerHealth {
    Ok,
    Drift,
    Missing,
    Orphaned,
    TargetMissing,
    Malformed,
}

impl SourcePointerHealth {
    pub fn label(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Drift => "drift",
            Self::Missing => "missing",
            Self::Orphaned => "orphaned",
            Self::TargetMissing => "target-missing",
            Self::Malformed => "malformed",
        }
    }

    pub fn is_ok(self) -> bool {
        matches!(self, Self::Ok)
    }
}

// Active deployment and pointer must either agree or both be absent.
fn evaluate_source_pointer(state_namespace: &str) -> Result<SourcePointerHealth> {
    let pointer_path = source_pointer_path(state_namespace);
    if let Ok(meta) = fs::symlink_metadata(&pointer_path)
        && !meta.file_type().is_symlink()
    {
        return Ok(SourcePointerHealth::Malformed);
    }

    let active = crate::state::record::live_source_snapshot_id(state_namespace)?;
    let pointer = read_source_pointer(state_namespace)?
        .as_deref()
        .and_then(pointer_object_id);

    Ok(match (active.as_deref(), pointer.as_deref()) {
        (Some(active), Some(pointer)) if active == pointer => {
            if source_object_on_disk(active) {
                SourcePointerHealth::Ok
            } else {
                SourcePointerHealth::TargetMissing
            }
        }
        (Some(_), Some(_)) => SourcePointerHealth::Drift,
        (Some(_), None) => SourcePointerHealth::Missing,
        (None, Some(_)) => SourcePointerHealth::Orphaned,
        (None, None) => SourcePointerHealth::Ok,
    })
}

fn source_object_on_disk(id: &str) -> bool {
    SourceSnapshot::from_id(id)
        .and_then(|snapshot| snapshot.require_on_disk())
        .is_ok()
}

fn pointer_object_id(pointer: &Path) -> Option<String> {
    pointer
        .strip_prefix(sources_dir())
        .ok()
        .and_then(|rel| rel.components().next())
        .map(|component| component.as_os_str().to_string_lossy().into_owned())
}

pub fn evaluate(state_namespace: &str, inspect_assets: bool) -> Result<OwnershipStatusReport> {
    let ownership = read_ownership_for(state_namespace)?;
    let mut has_drift = false;
    let mut results = Vec::new();

    for entry in ownership.iter() {
        match &entry.owner {
            OwnerKind::Stale { .. } => {
                has_drift = true;
                results.push(ManagedPathStatus {
                    path: entry.target.clone(),
                    expected: Some(entry.source.clone()),
                    owner: entry.owner.label().to_owned(),
                    status: "stale-corrupt",
                });
            }
            OwnerKind::Asset { .. } => {
                let installed = entry.target.exists() || entry.target.is_symlink();
                let payload_lost = entry.source != entry.target
                    && !object_present(&entry.source, true).unwrap_or(false);
                let status = if !installed {
                    has_drift = true;
                    "missing"
                } else if payload_lost {
                    has_drift = true;
                    "payload-missing"
                } else if inspect_assets && asset_drifted(&entry.target, &entry.source) {
                    has_drift = true;
                    "drift"
                } else {
                    "present"
                };
                results.push(ManagedPathStatus {
                    path: entry.target.clone(),
                    expected: None,
                    owner: entry.owner.label(),
                    status,
                });
            }
            OwnerKind::Dir { .. }
            | OwnerKind::File { .. }
            | OwnerKind::TemplateFile { .. }
            | OwnerKind::TemplateDir { .. }
            | OwnerKind::Symlink => {
                let actual = entry.target.read_link().ok();
                let link_matches = actual.as_deref() == Some(entry.source.as_path());
                let require_source = !matches!(entry.owner, OwnerKind::Symlink);
                let status = if !link_matches {
                    has_drift = true;
                    "drift"
                } else if require_source && fs::symlink_metadata(&entry.source).is_err() {
                    has_drift = true;
                    "source-missing"
                } else {
                    "ok"
                };
                results.push(ManagedPathStatus {
                    path: entry.target.clone(),
                    expected: Some(entry.source.clone()),
                    owner: entry.owner.label(),
                    status,
                });
            }
        }
    }

    let source_pointer = evaluate_source_pointer(state_namespace)?;
    if !source_pointer.is_ok() {
        has_drift = true;
    }

    let target_lock = evaluate_target_lock(state_namespace, &ownership)?;
    if !target_lock.is_ok() {
        has_drift = true;
    }

    Ok(OwnershipStatusReport {
        source: ownership.source,
        results,
        source_pointer,
        target_lock,
        has_drift,
    })
}

fn evaluate_target_lock(
    state_namespace: &str,
    ownership: &OwnershipIndex,
) -> Result<TargetLockHealth> {
    let lock = TargetLock::load()?;
    let owned: Vec<PathBuf> = ownership.iter().map(|entry| entry.target.clone()).collect();

    let conflicts = lock.conflicts_for(&owned, state_namespace);
    if !conflicts.is_empty() {
        return Ok(TargetLockHealth::ForeignConflict(
            conflicts
                .into_iter()
                .map(|(target, conflicts_with, state)| TargetLockConflict {
                    target,
                    conflicts_with,
                    state,
                })
                .collect(),
        ));
    }

    let owned_set: std::collections::BTreeSet<&Path> = owned.iter().map(PathBuf::as_path).collect();
    if owned_set != lock.targets_for(state_namespace) {
        return Ok(TargetLockHealth::Repairable);
    }
    Ok(TargetLockHealth::Ok)
}

fn asset_drifted(dst: &Path, archive: &Path) -> bool {
    if !archive.exists() {
        return false;
    }
    match (tree_fingerprint(dst), tree_fingerprint(archive)) {
        (Ok(live), Ok(recorded)) => live != recorded,
        _ => true,
    }
}

#[derive(Debug, PartialEq, Eq)]
enum FingerprintKind {
    Directory,
    File {
        size: u64,
        mtime: i64,
        mtime_nsec: i64,
    },
    Symlink {
        target: PathBuf,
    },
    Other,
}

#[derive(Debug, PartialEq, Eq)]
struct FingerprintEntry {
    path: PathBuf,
    mode: u32,
    kind: FingerprintKind,
}

// Avoid content hashing so status stays fast on large asset trees.
fn tree_fingerprint(root: &Path) -> Result<Vec<FingerprintEntry>> {
    let entries = walk_tree(
        root,
        TreeWalk {
            include_root: true,
            skip_top_level_git: false,
            tolerate_special: true,
        },
    )?;
    entries
        .into_iter()
        .map(|entry| {
            let kind = match entry.kind {
                EntryKind::File => FingerprintKind::File {
                    size: entry.metadata.size(),
                    mtime: entry.metadata.mtime(),
                    mtime_nsec: entry.metadata.mtime_nsec(),
                },
                EntryKind::Dir => FingerprintKind::Directory,
                EntryKind::Symlink => FingerprintKind::Symlink {
                    target: fs::read_link(&entry.abs)?,
                },
                EntryKind::Other => FingerprintKind::Other,
            };
            Ok(FingerprintEntry {
                mode: entry.mode() & 0o7777,
                path: entry.rel,
                kind,
            })
        })
        .collect()
}
