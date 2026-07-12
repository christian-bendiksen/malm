//! Finds risky destinations and snapshot-escaping sources in remote plans.

use crate::paths::{home_dir, home_dir_canonical, xdg_config_home, xdg_state_home};
use crate::planning::plan::{DeploymentPlan, Operation};
use crate::policy::advisory::user_path_dirs;
use crate::policy::asset_policy::unverified_asset_finding;
use crate::policy::destination::{DestinationKind, DestinationPolicyContext};
use crate::policy::model::PolicyFinding;
use crate::policy::overrides::RemotePolicyOverrides;
use crate::policy::source_escape::{classify_external_source, source_escapes_source_root};
use std::path::{Path, PathBuf};

// Report the original repo path, not the staging/rendered location.
fn remap_source(src: &Path, remap: Option<(&Path, &Path)>) -> PathBuf {
    match remap {
        Some((from, to)) => match src.strip_prefix(from) {
            Ok(rel) => to.join(rel),
            Err(_) => src.to_path_buf(),
        },
        None => src.to_path_buf(),
    }
}

pub fn collect_remote_policy_findings(
    plan: &DeploymentPlan,
    source_root: &Path,
    rendered_root: Option<&Path>,
    source_remap: Option<(&Path, &Path)>,
    allow: RemotePolicyOverrides,
) -> Vec<PolicyFinding> {
    let home = home_dir();
    let ctx = DestinationPolicyContext {
        home: &home,
        home_canonical: home_dir_canonical(),
        path_dirs: user_path_dirs(&home),
        malm_dirs: vec![
            xdg_state_home().join("malm"),
            xdg_config_home().join("malm"),
        ],
        allow,
    };
    let mut violations = Vec::new();

    for op in plan.operations() {
        match op {
            Operation::CreateSymlink {
                target: dst,
                source: src,
                owner,
                ..
            } => {
                let label = owner.label();
                ctx.push_destination_findings(
                    dst,
                    &label,
                    DestinationKind::Symlink,
                    &mut violations,
                );

                let mapped = remap_source(src, source_remap);
                // A source escapes only when it is outside both the source and
                // rendered roots; rendered files may live outside the repo.
                let escapes = source_escapes_source_root(&mapped, source_root)
                    && rendered_root.is_none_or(|root| source_escapes_source_root(&mapped, root));
                if escapes
                    && let Some((kind, severity, reason, flag)) =
                        classify_external_source(&mapped, &home, allow)
                {
                    violations.push(PolicyFinding {
                        target: Some(dst.clone()),
                        owner: label.clone(),
                        category: kind,
                        severity,
                        reason,
                        allow_flag: flag,
                    });
                }
            }

            Operation::InstallAsset {
                name,
                target: dst,
                sha256,
                ..
            } => {
                let label = format!("asset \"{name}\"");

                if !allow.unverified_assets && sha256.is_none() {
                    violations.push(unverified_asset_finding(label.clone()));
                }

                ctx.push_destination_findings(dst, &label, DestinationKind::Asset, &mut violations);
            }

            Operation::KeepAsset {
                name, target: dst, ..
            }
            | Operation::RestoreAsset {
                name, target: dst, ..
            } => {
                let label = format!("asset \"{name}\"");
                ctx.push_destination_findings(dst, &label, DestinationKind::Asset, &mut violations);
            }

            Operation::RemovePath { .. } | Operation::RemoveAsset { .. } => {}
        }
    }

    violations
}
