//! Validates declaration paths, rejecting source escapes and resolving targets.

use crate::paths::{expand_tilde, normalize_lexical};
use crate::planning::plan::DeploymentPlan;
use std::path::{Component, Path};

pub(super) fn reject_target_escape(raw: &str, kind: &str, plan: &mut DeploymentPlan) -> bool {
    if raw.is_empty() || raw == "." {
        return false;
    }
    let expanded = expand_tilde(raw);
    // Absolute destinations are allowed by design; policy (not planning)
    // decides whether they are safe.
    if expanded.is_absolute() {
        return false;
    }
    if has_parent_component(&expanded) {
        plan.add_error(format!(
            "{kind} destination escapes target base: {raw}; use `symlink` if this is intentional"
        ));
        return true;
    }
    false
}

pub(super) fn has_parent_component(path: &Path) -> bool {
    path.components().any(|c| matches!(c, Component::ParentDir))
}

pub fn resolve_target_path(raw: &str, target_root: &Path) -> std::path::PathBuf {
    if raw.is_empty() || raw == "." {
        return normalize_lexical(target_root);
    }
    let p = expand_tilde(raw);
    let joined = if p.is_absolute() {
        p
    } else {
        target_root.join(&p)
    };
    normalize_lexical(&joined)
}
