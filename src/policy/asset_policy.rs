//! Checks asset checksums and destinations before planning.

use crate::config::Config;
use crate::paths::{
    expand_tilde, home_dir, home_dir_canonical, normalize_lexical, xdg_config_home, xdg_state_home,
};
use crate::policy::advisory::user_path_dirs;
use crate::policy::destination::{DestinationKind, DestinationPolicyContext};
use crate::policy::model::{PolicyFinding, PolicyFindingKind, PolicySeverity};
use crate::policy::overrides::RemotePolicyOverrides;
use std::path::Path;

pub(super) fn unverified_asset_finding(owner: String) -> PolicyFinding {
    PolicyFinding {
        target: None,
        owner,
        category: PolicyFindingKind::AssetWithoutChecksum,
        severity: PolicySeverity::Block,
        reason: "assets from remote configs must have a sha256 checksum for verification",
        allow_flag: "--allow-unverified-assets",
    }
}

pub fn collect_asset_declaration_findings(
    cfg: &Config,
    allow: RemotePolicyOverrides,
) -> Vec<PolicyFinding> {
    let Some(manifest) = &cfg.assets else {
        return Vec::new();
    };

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
    for entry in &manifest.assets {
        let label = format!("asset \"{}\"", entry.name);
        let dst = normalize_lexical(&expand_tilde(&entry.dst));

        if !allow.unverified_assets && entry.sha256.is_none() {
            violations.push(unverified_asset_finding(label.clone()));
        }

        ctx.push_destination_findings(&dst, &label, DestinationKind::Asset, &mut violations);

        if let Some(raw) = &entry.installed_check {
            let p = Path::new(raw);
            let relative = !raw.starts_with('~')
                && !p.is_absolute()
                && !p
                    .components()
                    .any(|c| matches!(c, std::path::Component::ParentDir));
            if relative {
                let check = normalize_lexical(&dst.join(raw));
                ctx.push_destination_findings(
                    &check,
                    &label,
                    DestinationKind::Asset,
                    &mut violations,
                );
            }
        }
    }

    violations
}
