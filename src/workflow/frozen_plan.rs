//! Rebuilds a deployment plan from a recorded transaction manifest.
//!
//! Checkout uses it to re-deploy a transaction; recovery uses it to finish a
//! crashed apply's metadata. Recorded paths are revalidated: sources must stay
//! in the snapshot repository, rendered store, or asset store; destinations are
//! normalized absolute paths outside Malm's state.

use crate::cas::asset_payloads_dir;
use crate::config::{ConflictPolicy, MissingSourcePolicy};
use crate::paths::{normalize_lexical, xdg_config_home, xdg_state_home};
use crate::planning::plan::{DeploymentPlan, Operation};
use crate::policy::destination::resolve_destination_physically;
use crate::source::store::SourceSnapshot;
use crate::state::active_deployment::source_pointer_path;
use crate::state::ownership::{OwnerKind, OwnershipEntry};
use crate::state::transaction::{OperationStatus, RecordedOp, TransactionManifest};
use anyhow::{Context, Result};
use std::path::{Path, PathBuf};

/// Rebuild the frozen plan a manifest describes: applied symlink/asset ops
/// plus the recorded desired end-state. Stale removals are the caller's
/// concern (checkout wants them; recovery does not re-execute the plan).
pub(crate) fn frozen_plan_from_manifest(
    manifest: &TransactionManifest,
    namespace: &str,
    snapshot: &SourceSnapshot,
) -> Result<DeploymentPlan> {
    let repository_root = snapshot.repository();
    let rendered_root = snapshot.rendered();
    let asset_root = asset_payloads_dir();
    let alias_root = source_pointer_path(namespace);
    let object_root = snapshot.root();

    let mut frozen = DeploymentPlan::new();
    for op in &manifest.operations {
        match op {
            RecordedOp::CreateSymlink {
                status: OperationStatus::Applied,
                owner,
                src,
                dst,
                ..
            } => {
                validate_recorded_destination(dst)?;
                let resolved_src = resolve_recorded_source(src, &alias_root, object_root);
                validate_recorded_source(&resolved_src, owner, repository_root, rendered_root)
                    .with_context(|| {
                        format!(
                            "refusing to reuse {}: invalid recorded source {} for {}",
                            manifest.id,
                            src.display(),
                            owner.label()
                        )
                    })?;
                frozen.push(Operation::CreateSymlink {
                    owner: owner.clone(),
                    source: src.clone(),
                    target: dst.clone(),
                    policy: MissingSourcePolicy::RequireSource,
                    conflict: ConflictPolicy::Backup,
                });
            }
            RecordedOp::InstallAsset {
                status: OperationStatus::Applied,
                name,
                url,
                dst,
                payload,
                declaration,
                ..
            } => {
                validate_recorded_destination(dst)?;
                validate_physical_containment(payload, &asset_root, "asset store").with_context(
                    || {
                        format!(
                            "refusing to reuse {}: recorded asset payload {} is outside the asset store",
                            manifest.id,
                            payload.display()
                        )
                    },
                )?;
                frozen.push(Operation::RestoreAsset {
                    name: name.clone(),
                    url: url.clone(),
                    payload: payload.clone(),
                    target: dst.clone(),
                    declaration: declaration.clone(),
                });
            }
            RecordedOp::CreateSymlink { .. }
            | RecordedOp::InstallAsset { .. }
            | RecordedOp::RemovePath { .. }
            | RecordedOp::RemoveAsset { .. } => {}
        }
    }
    let mut planned_targets: std::collections::BTreeSet<PathBuf> = frozen
        .operations()
        .iter()
        .filter_map(|op| op.managed_target_after_apply().map(Path::to_path_buf))
        .collect();
    for link in &manifest.desired_links {
        if planned_targets.contains(&link.target) {
            continue;
        }
        validate_recorded_destination(&link.target)?;
        let resolved_src = resolve_recorded_source(&link.source, &alias_root, object_root);
        validate_recorded_source(&resolved_src, &link.owner, repository_root, rendered_root)
            .with_context(|| {
                format!(
                    "refusing to reuse {}: invalid recorded source {} for {}",
                    manifest.id,
                    link.source.display(),
                    link.owner.label()
                )
            })?;
        planned_targets.insert(link.target.clone());
        frozen.push(Operation::CreateSymlink {
            owner: link.owner.clone(),
            source: link.source.clone(),
            target: link.target.clone(),
            policy: MissingSourcePolicy::RequireSource,
            conflict: ConflictPolicy::Backup,
        });
    }
    for asset in &manifest.desired_assets {
        validate_recorded_destination(&asset.target)?;
        let archived = asset.source != asset.target;
        if archived {
            validate_physical_containment(&asset.source, &asset_root, "asset store").with_context(
                || {
                    format!(
                        "refusing to reuse {}: preserved asset source {} is outside the asset store",
                        manifest.id,
                        asset.source.display()
                    )
                },
            )?;
        }

        if std::fs::symlink_metadata(&asset.target).is_ok() {
            frozen.push(Operation::KeepAsset {
                name: asset.name.clone(),
                target: asset.target.clone(),
                previous: Some(OwnershipEntry {
                    target: asset.target.clone(),
                    source: asset.source.clone(),
                    owner: OwnerKind::Asset {
                        name: asset.name.clone(),
                    },
                    transaction: asset.transaction.clone(),
                    asset_declaration: asset.declaration.clone(),
                }),
                declaration: asset.declaration.clone(),
            });
        } else if archived {
            let url = manifest
                .operations
                .iter()
                .find_map(|operation| match operation {
                    RecordedOp::InstallAsset { name, url, dst, .. }
                        if name == &asset.name && dst == &asset.target =>
                    {
                        Some(url.clone())
                    }
                    _ => None,
                })
                .unwrap_or_else(|| "<preserved-asset>".to_owned());
            frozen.push(Operation::RestoreAsset {
                name: asset.name.clone(),
                url,
                payload: asset.source.clone(),
                target: asset.target.clone(),
                declaration: asset.declaration.clone(),
            });
        } else {
            anyhow::bail!(
                "cannot reuse transaction {}: externally satisfied asset '{}' is missing at {} and has no Malm archive",
                manifest.id,
                asset.name,
                asset.target.display()
            );
        }
    }
    for retained in &manifest.retained_ownership {
        validate_recorded_destination(&retained.target)?;
        frozen.retain_ownership(retained.clone());
    }

    Ok(frozen)
}

pub(crate) fn resolve_recorded_source(
    source: &Path,
    alias_root: &Path,
    object_root: &Path,
) -> PathBuf {
    match source.strip_prefix(alias_root) {
        Ok(rel) => object_root.join(rel),
        Err(_) => source.to_path_buf(),
    }
}

fn validate_recorded_source(
    source: &Path,
    owner: &OwnerKind,
    repository_root: &Path,
    rendered_root: &Path,
) -> Result<()> {
    match owner {
        OwnerKind::Dir { .. } | OwnerKind::File { .. } => {
            validate_physical_containment(source, repository_root, "snapshot repository")
        }
        OwnerKind::TemplateFile { .. } => validate_rendered_source(source, rendered_root),
        OwnerKind::TemplateDir { .. } => {
            let in_rendered = match (source.canonicalize(), rendered_root.canonicalize()) {
                (Ok(src_canon), Ok(root_canon)) => src_canon.starts_with(&root_canon),
                _ => source.starts_with(rendered_root),
            };
            if in_rendered {
                validate_rendered_source(source, rendered_root)
            } else {
                validate_physical_containment(source, repository_root, "snapshot repository")
            }
        }
        OwnerKind::Symlink => Ok(()),
        OwnerKind::Asset { .. } | OwnerKind::Stale { .. } => {
            anyhow::bail!("owner cannot create a recorded symlink")
        }
    }
}

fn validate_rendered_source(source: &Path, rendered_root: &Path) -> Result<()> {
    if source.parent() != Some(rendered_root) {
        anyhow::bail!(
            "template source must be directly inside {}",
            rendered_root.display()
        );
    }
    let rendered_metadata = std::fs::symlink_metadata(rendered_root).with_context(|| {
        format!(
            "inspect rendered template directory {}",
            rendered_root.display()
        )
    })?;
    if !rendered_metadata.file_type().is_dir() || rendered_metadata.file_type().is_symlink() {
        anyhow::bail!(
            "rendered template root is not a directory: {}",
            rendered_root.display()
        );
    }
    let source_metadata = std::fs::symlink_metadata(source)
        .with_context(|| format!("inspect rendered template {}", source.display()))?;
    if !source_metadata.file_type().is_file() || source_metadata.file_type().is_symlink() {
        anyhow::bail!(
            "rendered template source is not a regular file: {}",
            source.display()
        );
    }
    validate_physical_containment(source, rendered_root, "rendered template store")
}

pub(crate) fn validate_recorded_destination(path: &Path) -> Result<()> {
    let normalized = normalize_lexical(path);
    if !path.is_absolute() || normalized != path {
        anyhow::bail!(
            "recorded destination must be an absolute normalized path: {}",
            path.display()
        );
    }

    let internal_roots = [
        xdg_state_home().join("malm"),
        xdg_config_home().join("malm"),
    ];
    let physical = resolve_destination_physically(path);
    if internal_roots.iter().any(|root| {
        normalized.starts_with(root)
            || physical
                .as_deref()
                .is_some_and(|resolved| resolved.starts_with(root))
    }) {
        anyhow::bail!(
            "recorded destination is inside Malm's internal state: {}",
            path.display()
        );
    }
    Ok(())
}

fn validate_physical_containment(path: &Path, root: &Path, label: &str) -> Result<()> {
    let normalized_root = normalize_lexical(root);
    let normalized_path = normalize_lexical(path);
    let relative = normalized_path
        .strip_prefix(&normalized_root)
        .with_context(|| format!("{} is outside the {label}", path.display()))?;

    let canonical_root = normalized_root
        .canonicalize()
        .with_context(|| format!("canonicalize {label} root {}", root.display()))?;

    let mut cursor = normalized_root.clone();
    for component in relative.components() {
        cursor.push(component.as_os_str());
        let metadata = std::fs::symlink_metadata(&cursor)
            .with_context(|| format!("inspect recorded {label} path {}", cursor.display()))?;
        if metadata.file_type().is_symlink() {
            match cursor.canonicalize() {
                Ok(resolved) if resolved.starts_with(&canonical_root) => {}
                Ok(_) => {
                    anyhow::bail!(
                        "recorded path {} physically escapes the {label}",
                        path.display()
                    );
                }
                Err(_) if cursor == normalized_path => {
                    let target = std::fs::read_link(&cursor)
                        .with_context(|| format!("read recorded symlink {}", cursor.display()))?;
                    let parent = cursor.parent().unwrap_or(normalized_root.as_path());
                    let physical_parent = parent.canonicalize().with_context(|| {
                        format!("canonicalize recorded {label} parent {}", parent.display())
                    })?;
                    let resolved = if target.is_absolute() {
                        normalize_lexical(&target)
                    } else {
                        normalize_lexical(&physical_parent.join(target))
                    };
                    if !resolved.starts_with(&canonical_root) {
                        anyhow::bail!(
                            "recorded path {} physically escapes the {label}",
                            path.display()
                        );
                    }
                    return Ok(());
                }
                Err(error) => {
                    return Err(error).with_context(|| {
                        format!("canonicalize recorded {label} path {}", cursor.display())
                    });
                }
            }
        }
    }

    let canonical_path = normalized_path
        .canonicalize()
        .with_context(|| format!("canonicalize recorded {label} path {}", path.display()))?;
    if !canonical_path.starts_with(&canonical_root) {
        anyhow::bail!(
            "recorded path {} physically escapes the {label}",
            path.display()
        );
    }
    Ok(())
}
