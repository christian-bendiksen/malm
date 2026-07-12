//! Evaluates plan operations against the filesystem for previews, risk checks,
//! and JSON output.

use crate::config::{ConflictPolicy, MissingSourcePolicy};
use crate::fs::inspect::{FilesystemPathState, inspect_filesystem_path};
use crate::planning::plan::{DeploymentPlan, Operation};
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PreviewAction {
    Keep,
    Create,
    Replace,
    Remove,
    Download,
    Error,
}

#[derive(Debug, Clone)]
pub struct TargetEvaluation {
    pub owner: String,
    pub target: std::path::PathBuf,
    pub source: Option<std::path::PathBuf>,
    pub action: PreviewAction,
    pub actual: FilesystemPathState,
}

pub fn evaluate_plan_targets(plan: &DeploymentPlan) -> Vec<TargetEvaluation> {
    plan.operations()
        .iter()
        .map(evaluate_operation_target)
        .collect()
}

fn evaluate_operation_target(op: &Operation) -> TargetEvaluation {
    match op {
        Operation::CreateSymlink {
            source: src,
            target: dst,
            policy,
            conflict,
            owner,
        } => {
            let actual = inspect_filesystem_path(dst);
            let action = evaluate_symlink_target(src, *policy, *conflict, &actual);
            TargetEvaluation {
                owner: owner.label(),
                target: dst.clone(),
                source: Some(src.clone()),
                action,
                actual,
            }
        }
        Operation::RemovePath { path, owner, .. } => {
            let actual = inspect_filesystem_path(path);
            TargetEvaluation {
                owner: owner.label(),
                target: path.clone(),
                source: None,
                action: PreviewAction::Remove,
                actual,
            }
        }
        Operation::InstallAsset {
            name,
            target: target_path,
            ..
        }
        | Operation::RestoreAsset {
            name,
            target: target_path,
            ..
        } => TargetEvaluation {
            owner: format!("asset \"{name}\""),
            target: target_path.clone(),
            source: None,
            action: PreviewAction::Download,
            actual: inspect_filesystem_path(target_path),
        },
        Operation::KeepAsset {
            name,
            target: target_path,
            ..
        } => TargetEvaluation {
            owner: format!("asset \"{name}\""),
            target: target_path.clone(),
            source: None,
            action: PreviewAction::Keep,
            actual: inspect_filesystem_path(target_path),
        },
        Operation::RemoveAsset {
            name,
            target: target_path,
            ..
        } => TargetEvaluation {
            owner: format!("asset \"{name}\""),
            target: target_path.clone(),
            source: None,
            action: PreviewAction::Remove,
            actual: inspect_filesystem_path(target_path),
        },
    }
}

// Order matters: missing-source policy first (may allow a dangling
// link), then conflict policy decides Error vs Replace for an occupied
// target.
fn evaluate_symlink_target(
    src: &Path,
    policy: MissingSourcePolicy,
    conflict: ConflictPolicy,
    actual: &FilesystemPathState,
) -> PreviewAction {
    match actual {
        FilesystemPathState::Symlink { target } if target == src => PreviewAction::Keep,
        FilesystemPathState::Missing => {
            if !policy.allow_missing_source() && !src.exists() && !src.is_symlink() {
                PreviewAction::Error
            } else {
                PreviewAction::Create
            }
        }
        FilesystemPathState::Directory => PreviewAction::Error,
        FilesystemPathState::Symlink { .. } | FilesystemPathState::BrokenSymlink => {
            let broken_source =
                !policy.allow_missing_source() && !src.exists() && !src.is_symlink();
            if broken_source || conflict == ConflictPolicy::Fail {
                PreviewAction::Error
            } else {
                PreviewAction::Replace
            }
        }
        FilesystemPathState::File | FilesystemPathState::Other => {
            if conflict == ConflictPolicy::Fail {
                PreviewAction::Error
            } else {
                PreviewAction::Replace
            }
        }
    }
}
