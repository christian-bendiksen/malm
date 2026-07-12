//! Stores each state's ownership index and projects deployment plans into it.

use crate::fs::atomic;
use crate::paths::xdg_state_home;
use crate::planning::plan::{DeploymentPlan, Operation};
use crate::source::{SourceIdentity, SourceKind};
use crate::state::ownership::{
    OWNERSHIP_VERSION, OwnerKind, OwnershipEntry, OwnershipIndex, OwnershipWriteContext,
};
use anyhow::{Context, Result};
use std::io;
use std::path::{Path, PathBuf};

impl OwnershipIndex {
    pub fn save_for_state(&self, state_namespace: &str) -> Result<()> {
        let path = ownership_path_for(state_namespace);
        let json = serde_json::to_string_pretty(self).context("serialize ownership index")?;
        atomic::write(&path, json).with_context(|| format!("write {}", path.display()))
    }
}

fn ownership_path_for(state_namespace: &str) -> PathBuf {
    xdg_state_home()
        .join("malm/states")
        .join(state_namespace)
        .join("ownership.json")
}

// A new commit from the same Git URL is an update, not an identity conflict.
// Local source identity is its path.
pub fn check_identity_against(
    index: &OwnershipIndex,
    new_source: &SourceIdentity,
    state_namespace: &str,
) -> Result<()> {
    match &index.source {
        None => Ok(()),
        Some(recorded) => {
            let is_match = match (recorded, new_source) {
                (
                    SourceIdentity {
                        kind: SourceKind::Local { path: p1 },
                    },
                    SourceIdentity {
                        kind: SourceKind::Local { path: p2 },
                    },
                ) => p1 == p2,

                (
                    SourceIdentity {
                        kind: SourceKind::Git { url: u1, .. },
                    },
                    SourceIdentity {
                        kind: SourceKind::Git { url: u2, .. },
                    },
                ) => u1 == u2,

                _ => false,
            };

            if is_match {
                Ok(())
            } else {
                anyhow::bail!(
                    "Malm state \"{}\" is already owned by {}.\n\
                    To reset, remove: {}",
                    state_namespace,
                    recorded.display_label(),
                    ownership_path_for(state_namespace).display()
                )
            }
        }
    }
}

pub fn write_ownership_for(
    plan: &DeploymentPlan,
    ctx: &OwnershipWriteContext<'_>,
    asset_sources: &std::collections::HashMap<String, Vec<(PathBuf, PathBuf)>>,
) -> Result<()> {
    let mut index = OwnershipIndex::new(
        ctx.state_namespace.to_owned(),
        ctx.source.cloned(),
        ctx.config.map(|p| p.to_path_buf()),
        ctx.profile.map(|s| s.to_owned()),
    );

    for op in plan.operations() {
        match op {
            Operation::CreateSymlink {
                source: src,
                target: dst,
                owner,
                ..
            } => index.entries.push(OwnershipEntry {
                target: dst.clone(),
                source: src.clone(),
                owner: owner
                    .persisted()
                    .ok_or_else(|| anyhow::anyhow!("stale owner cannot own {}", dst.display()))?,
                transaction: ctx.transaction_id.map(|s| s.to_owned()),
            }),
            // Merge placement creates one managed tree per top-level payload
            // directory. Record each placement, not the shared extraction root.
            Operation::InstallAsset {
                name, target: dst, ..
            } => {
                let placements = asset_sources
                    .get(name.as_str())
                    .filter(|rows| !rows.is_empty())
                    .ok_or_else(|| {
                        anyhow::anyhow!(
                            "missing asset source mapping for {} (asset `{}`)",
                            dst.display(),
                            name
                        )
                    })?;
                for (target, payload) in placements {
                    index.entries.push(OwnershipEntry {
                        target: target.clone(),
                        source: payload.clone(),
                        owner: OwnerKind::Asset { name: name.clone() },
                        transaction: ctx.transaction_id.map(|s| s.to_owned()),
                    });
                }
            }
            // Nothing changed on disk, so keep the asset's existing provenance.
            Operation::KeepAsset {
                name,
                target: dst,
                previous,
            } => {
                let mut entry = previous.clone().unwrap_or_else(|| OwnershipEntry {
                    target: dst.clone(),
                    source: dst.clone(),
                    owner: OwnerKind::Asset { name: name.clone() },
                    transaction: ctx.transaction_id.map(|id| id.to_owned()),
                });
                entry.target = dst.clone();
                entry.owner = OwnerKind::Asset { name: name.clone() };
                index.entries.push(entry);
            }
            Operation::RestoreAsset {
                name,
                target: dst,
                payload,
                ..
            } => index.entries.push(OwnershipEntry {
                target: dst.clone(),
                source: payload.clone(),
                owner: OwnerKind::Asset { name: name.clone() },
                transaction: ctx.transaction_id.map(|s| s.to_owned()),
            }),
            Operation::RemovePath { .. } | Operation::RemoveAsset { .. } => {}
        }
    }
    for retained in plan.retained_ownership() {
        if !index
            .entries
            .iter()
            .any(|entry| entry.target == retained.target)
        {
            index.entries.push(retained.clone());
        }
    }

    index.save_for_state(ctx.state_namespace)
}

pub fn read_ownership_for(state_namespace: &str) -> Result<OwnershipIndex> {
    crate::state::format::require_current_if_present()?;
    read_from_path(&ownership_path_for(state_namespace), state_namespace)
}

fn read_from_path(path: &Path, state_namespace: &str) -> Result<OwnershipIndex> {
    let raw = match std::fs::read_to_string(path) {
        Ok(r) => r,
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            return Ok(OwnershipIndex::new(
                state_namespace.to_owned(),
                None,
                None,
                None,
            ));
        }
        Err(e) => return Err(e).with_context(|| format!("read {}", path.display())),
    };

    let value: serde_json::Value =
        serde_json::from_str(&raw).with_context(|| format!("parse {}", path.display()))?;
    let version = value.get("version").and_then(serde_json::Value::as_u64);
    if version != Some(OWNERSHIP_VERSION.into()) {
        let actual = version
            .map(|value| value.to_string())
            .unwrap_or_else(|| "missing".to_owned());
        return Err(crate::state::format::incompatible_schema(
            path,
            OWNERSHIP_VERSION,
            &actual,
        ));
    }
    serde_json::from_value(value).with_context(|| format!("parse {}", path.display()))
}
