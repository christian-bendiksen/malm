//! Plans removal of no-longer-declared targets that still match ownership.
//!
//! Callers have different contracts:
//! - apply/checkout use best-effort cleanup. Unremovable targets stay on disk
//!   but leave ownership when the new plan replaces it.
//! - disable/destroy account for every owned target. Each is removed or
//!   reported as blocked so it can be refused or deliberately retained.

use crate::planning::plan::{DeclarationOwner, DeploymentPlan, Operation};
use crate::state::ownership::{OwnerKind, OwnershipEntry, OwnershipIndex};
use std::collections::HashSet;

pub(crate) fn plan_stale_removals(plan: &mut DeploymentPlan, ownership: &OwnershipIndex) {
    let plan_targets: HashSet<std::path::PathBuf> = plan
        .operations()
        .iter()
        .filter_map(|op| op.affected_target())
        .map(|p| p.to_path_buf())
        .collect();

    // Never delete user-modified content: anything that no longer matches
    // the recorded source is left in place with a warning.
    for entry in ownership.iter() {
        let path = &entry.target;
        if plan_targets.contains(path.as_path()) {
            continue;
        }
        if path.read_link().ok().as_deref() == Some(entry.source.as_path()) {
            plan.push(Operation::RemovePath {
                owner: DeclarationOwner::Stale {
                    previous: Box::new(entry.owner.clone()),
                },
                path: path.clone(),
                expected_symlink_target: Some(entry.source.clone()),
            });
        } else if matches!(entry.owner, OwnerKind::Asset { .. })
            && (path.exists() || path.is_symlink())
        {
            plan.retain_ownership(entry.clone());
            plan.add_warning(format!(
                "{} is a no-longer-declared {}; left in place — remove it manually if unwanted",
                path.display(),
                entry.owner.label()
            ));
        } else if path.exists() || path.is_symlink() {
            plan.retain_ownership(entry.clone());
            plan.add_warning(format!(
                "{} was managed by {} but has been modified — leaving as-is",
                path.display(),
                entry.owner.label()
            ));
        }
    }
}

/// A target disable/destroy could not safely remove, with its ownership
/// entry (retained if the caller decides to keep it) and the reason.
pub(crate) struct BlockedRemoval {
    pub entry: OwnershipEntry,
    pub reason: String,
}

/// Plan the removal of *every* owned target for disable/destroy: clean
/// symlinks and unmodified assets are removed (assets verified against
/// their CAS payload both here and again at execution time); anything
/// drifted, modified, or unverifiable is returned as blocked.
pub(crate) fn plan_undeploy_removals(
    plan: &mut DeploymentPlan,
    ownership: &OwnershipIndex,
) -> Vec<BlockedRemoval> {
    let mut blocked = Vec::new();

    for entry in ownership.iter() {
        let path = &entry.target;
        let gone = !path.exists() && !path.is_symlink();
        if gone {
            continue;
        }
        match &entry.owner {
            OwnerKind::Asset { name } => match asset_matches_payload(path, &entry.source) {
                Ok(true) => plan.push(Operation::RemoveAsset {
                    name: name.clone(),
                    target: path.clone(),
                    payload: entry.source.clone(),
                }),
                Ok(false) => blocked.push(BlockedRemoval {
                    entry: entry.clone(),
                    reason: "installed asset was modified since installation".to_owned(),
                }),
                Err(error) => blocked.push(BlockedRemoval {
                    entry: entry.clone(),
                    reason: format!("installed asset could not be verified: {error:#}"),
                }),
            },
            _ => {
                if path.read_link().ok().as_deref() == Some(entry.source.as_path()) {
                    plan.push(Operation::RemovePath {
                        owner: DeclarationOwner::Stale {
                            previous: Box::new(entry.owner.clone()),
                        },
                        path: path.clone(),
                        expected_symlink_target: Some(entry.source.clone()),
                    });
                } else {
                    blocked.push(BlockedRemoval {
                        entry: entry.clone(),
                        reason: "target was modified since deployment (no longer the recorded \
                                 symlink)"
                            .to_owned(),
                    });
                }
            }
        }
    }

    blocked
}

fn asset_matches_payload(
    target: &std::path::Path,
    payload: &std::path::Path,
) -> anyhow::Result<bool> {
    let Some(expected) = payload.file_name().and_then(|leaf| leaf.to_str()) else {
        anyhow::bail!("recorded payload {} has no object id", payload.display());
    };
    if !payload.is_dir() {
        anyhow::bail!(
            "recorded payload {} is missing from the store",
            payload.display()
        );
    }
    Ok(crate::cas::tree_hash(target)? == expected)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::ownership::OwnershipIndex;

    fn ownership_with(entries: Vec<OwnershipEntry>) -> OwnershipIndex {
        let mut index = OwnershipIndex::new("test".to_owned(), None, None, None);
        index.entries = entries;
        index
    }

    #[test]
    fn undeploy_removes_clean_symlinks_and_blocks_drifted_ones() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("src");
        std::fs::write(&source, "content").unwrap();
        let clean = dir.path().join("clean");
        std::os::unix::fs::symlink(&source, &clean).unwrap();
        let drifted = dir.path().join("drifted");
        std::fs::write(&drifted, "user edit").unwrap();

        let ownership = ownership_with(vec![
            OwnershipEntry {
                target: clean.clone(),
                source: source.clone(),
                owner: OwnerKind::Symlink,
                transaction: None,
            },
            OwnershipEntry {
                target: drifted.clone(),
                source,
                owner: OwnerKind::Symlink,
                transaction: None,
            },
        ]);

        let mut plan = DeploymentPlan::new();
        let blocked = plan_undeploy_removals(&mut plan, &ownership);

        assert_eq!(plan.operations().len(), 1);
        assert!(matches!(
            &plan.operations()[0],
            Operation::RemovePath { path, .. } if path == &clean
        ));
        assert_eq!(blocked.len(), 1);
        assert_eq!(blocked[0].entry.target, drifted);
    }

    #[test]
    fn undeploy_removes_unmodified_assets_and_blocks_modified_ones() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("asset");
        std::fs::create_dir(&target).unwrap();
        std::fs::write(target.join("file"), "payload content").unwrap();
        let hash = crate::cas::tree_hash(&target).unwrap();
        let payload = dir.path().join(&hash);
        std::fs::create_dir(&payload).unwrap();

        let entry = OwnershipEntry {
            target: target.clone(),
            source: payload,
            owner: OwnerKind::Asset {
                name: "tool".to_owned(),
            },
            transaction: None,
        };

        let mut plan = DeploymentPlan::new();
        let blocked = plan_undeploy_removals(&mut plan, &ownership_with(vec![entry.clone()]));
        assert!(blocked.is_empty(), "unmodified asset is removable");
        assert!(matches!(
            &plan.operations()[0],
            Operation::RemoveAsset { target: t, .. } if t == &target
        ));

        std::fs::write(target.join("file"), "user modified").unwrap();
        let mut plan = DeploymentPlan::new();
        let blocked = plan_undeploy_removals(&mut plan, &ownership_with(vec![entry]));
        assert!(plan.operations().is_empty());
        assert_eq!(blocked.len(), 1, "modified asset is blocked");
        assert!(blocked[0].reason.contains("modified"));
    }

    #[test]
    fn undeploy_ignores_targets_that_no_longer_exist() {
        let dir = tempfile::tempdir().unwrap();
        let ownership = ownership_with(vec![OwnershipEntry {
            target: dir.path().join("gone"),
            source: dir.path().join("src"),
            owner: OwnerKind::Symlink,
            transaction: None,
        }]);

        let mut plan = DeploymentPlan::new();
        let blocked = plan_undeploy_removals(&mut plan, &ownership);
        assert!(plan.operations().is_empty());
        assert!(blocked.is_empty());
    }

    #[test]
    fn apply_retains_ownership_of_modified_stale_target() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("modified");
        std::fs::write(&target, "user contents").unwrap();
        let entry = OwnershipEntry {
            target: target.clone(),
            source: dir.path().join("old-source"),
            owner: OwnerKind::File {
                source: "old-source".to_owned(),
            },
            transaction: Some("old-transaction".to_owned()),
        };
        let mut plan = DeploymentPlan::new();

        plan_stale_removals(&mut plan, &ownership_with(vec![entry.clone()]));

        assert!(plan.operations().is_empty());
        assert_eq!(plan.retained_ownership().len(), 1);
        assert_eq!(plan.retained_ownership()[0].target, target);
        assert_eq!(plan.retained_ownership()[0].transaction, entry.transaction);
    }
}
