//! Plans whether to keep, restore, or download each asset.

use crate::assets::{AssetManifest, installed_check_satisfied};
use crate::cas::{object_present, payload_merge_entries};
use crate::paths::normalize_lexical;
use crate::planning::destination::{reject_target_escape, resolve_target_path};
use crate::planning::plan::{DeploymentPlan, Operation};
use crate::state::ownership::{OwnerKind, OwnershipIndex};
use std::path::{Component, Path};

pub fn build_asset_plan(
    manifest: &AssetManifest,
    target_root: &Path,
    ownership: &OwnershipIndex,
    untrusted: bool,
) -> DeploymentPlan {
    let mut plan = DeploymentPlan::new();

    for entry in &manifest.assets {
        if reject_target_escape(&entry.dst, "asset", &mut plan) {
            continue;
        }
        let dst = resolve_target_path(&entry.dst, target_root);

        let require_sha256 = entry
            .require_sha256
            .unwrap_or(manifest.config.require_sha256);
        if require_sha256 && entry.sha256.is_none() {
            plan.add_error(format!(
                "{}: sha256 required (set `require-sha256 #false` on the asset, or require-sha256=#false on the assets block)",
                entry.name
            ));
            continue;
        }

        // Installed-check paths must stay relative to the destination. Absolute,
        // `~`, or `..` paths could probe arbitrary locations.
        let check = match &entry.installed_check {
            None => dst.clone(),
            Some(raw) => {
                let p = Path::new(raw);
                if raw.starts_with('~')
                    || p.is_absolute()
                    || p.components().any(|c| matches!(c, Component::ParentDir))
                {
                    plan.add_error(format!(
                        "{}: installed-check must be a path relative to the asset destination: {raw}",
                        entry.name
                    ));
                    continue;
                }
                normalize_lexical(&dst.join(raw))
            }
        };

        let satisfied = match installed_check_satisfied(&dst, &check, untrusted) {
            Ok(s) => s,
            Err(symlink) => {
                plan.add_warning(format!(
                    "{}: installed-check path crosses a symlink ({}); ignoring it for this untrusted source",
                    entry.name,
                    symlink.display()
                ));
                false
            }
        };
        // Merge-placed assets record one ownership entry per placed payload
        // directory under `dst`; whole-tree installs record exactly one at
        // `dst` itself. Records outside the current destination (the config
        // moved it) are ignored here and handled by stale cleanup.
        let recorded: Vec<_> = ownership
            .iter()
            .filter(
                |owned| matches!(&owned.owner, OwnerKind::Asset { name } if name == &entry.name),
            )
            .filter(|owned| owned.target == dst || owned.target.starts_with(&dst))
            .cloned()
            .collect();

        let declaration = entry.declaration();
        let declaration_changed = !recorded.is_empty()
            && recorded.iter().any(|owned| match &owned.asset_declaration {
                Some(previous) => previous != &declaration,
                // Older externally-satisfied entries have no archive to
                // compare. Adopt the current declaration without replacing
                // their bytes when the installed check still succeeds.
                None => owned.source != owned.target,
            });

        // Once an asset is owned, its pinned declaration is authoritative.
        // `installed-check` detects external/adopted installs and missing
        // payloads; it must not mask a changed URL, checksum, or format.
        if declaration_changed {
            plan.push(Operation::InstallAsset {
                name: entry.name.clone(),
                url: entry.url.clone(),
                target: dst,
                sha256: entry.sha256.clone(),
                format: entry.format,
                refresh_font_cache: entry.refresh_font_cache,
                declaration: Some(declaration),
                previous: recorded,
            });
            continue;
        }

        if satisfied {
            // A kept asset must remain restorable from the CAS. Reinstall now if
            // any recorded payload is missing.
            let keepable = recorded.iter().all(|prev| {
                prev.source == prev.target || object_present(&prev.source, true).unwrap_or(false)
            });
            if keepable {
                if recorded.is_empty() {
                    plan.push(Operation::KeepAsset {
                        name: entry.name.clone(),
                        target: dst,
                        previous: None,
                        declaration: Some(declaration),
                    });
                } else {
                    for prev in &recorded {
                        plan.push(Operation::KeepAsset {
                            name: entry.name.clone(),
                            target: prev.target.clone(),
                            previous: Some(prev.clone()),
                            declaration: Some(declaration.clone()),
                        });
                    }
                }
                continue;
            }
        }

        let restorable = !recorded.is_empty()
            && recorded.iter().all(|prev| {
                prev.source != prev.target
                    && object_present(&prev.source, true).unwrap_or(false)
                    // A pre-merge whole-root record for a mergeable payload
                    // must never be re-materialized over a possibly shared
                    // parent directory; fall through to a fresh install,
                    // which places per entry and migrates the record.
                    && (prev.target != dst
                        || payload_merge_entries(&prev.source)
                            .map(|entries| entries.is_none())
                            .unwrap_or(false))
            });
        if restorable {
            for prev in &recorded {
                plan.push(Operation::RestoreAsset {
                    name: entry.name.clone(),
                    url: entry.url.clone(),
                    payload: prev.source.clone(),
                    target: prev.target.clone(),
                    declaration: Some(declaration.clone()),
                });
            }
            continue;
        }

        plan.push(Operation::InstallAsset {
            name: entry.name.clone(),
            url: entry.url.clone(),
            target: dst,
            sha256: entry.sha256.clone(),
            format: entry.format,
            refresh_font_cache: entry.refresh_font_cache,
            declaration: Some(declaration),
            previous: recorded,
        });
    }

    plan
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::assets::{ArchiveFormat, AssetConfig, AssetEntry, AssetManifest};
    use crate::state::ownership::{OwnerKind, OwnershipEntry, OwnershipIndex};

    fn manifest(name: &str, dst: &str, check: &str) -> AssetManifest {
        AssetManifest {
            config: AssetConfig {
                require_sha256: false,
            },
            assets: vec![AssetEntry {
                name: name.to_owned(),
                url: "https://example.invalid/a.tar.xz".to_owned(),
                dst: dst.to_owned(),
                format: ArchiveFormat::TarXz,
                sha256: None,
                installed_check: Some(check.to_owned()),
                refresh_font_cache: false,
                require_sha256: None,
            }],
        }
    }

    fn adopted_entry(name: &str, target: std::path::PathBuf) -> OwnershipEntry {
        OwnershipEntry {
            source: target.clone(), // source == target: keepable without a CAS payload
            target,
            owner: OwnerKind::Asset {
                name: name.to_owned(),
            },
            transaction: None,
            asset_declaration: Some(crate::assets::AssetDeclaration {
                url: "https://example.invalid/a.tar.xz".to_owned(),
                sha256: None,
                format: ArchiveFormat::TarXz,
                installed_check: Some("adw-gtk3".to_owned()),
                refresh_font_cache: false,
            }),
        }
    }

    #[test]
    fn satisfied_asset_keeps_every_recorded_placement() {
        let root = tempfile::tempdir().unwrap();
        let themes = root.path().join("themes");
        std::fs::create_dir_all(themes.join("adw-gtk3")).unwrap();
        std::fs::create_dir_all(themes.join("adw-gtk3-dark")).unwrap();

        let mut ownership = OwnershipIndex::new("test".to_owned(), None, None, None);
        ownership
            .entries
            .push(adopted_entry("adw", themes.join("adw-gtk3")));
        ownership
            .entries
            .push(adopted_entry("adw", themes.join("adw-gtk3-dark")));

        let plan = build_asset_plan(
            &manifest("adw", "themes", "adw-gtk3"),
            root.path(),
            &ownership,
            false,
        );
        assert!(plan.errors().is_empty(), "{:?}", plan.errors());
        let kept: Vec<_> = plan
            .operations()
            .iter()
            .filter_map(|op| match op {
                Operation::KeepAsset {
                    target,
                    previous: Some(_),
                    ..
                } => Some(target.clone()),
                _ => None,
            })
            .collect();
        assert_eq!(
            kept,
            vec![themes.join("adw-gtk3"), themes.join("adw-gtk3-dark")]
        );
    }

    #[test]
    fn records_outside_the_destination_plan_a_fresh_install() {
        let root = tempfile::tempdir().unwrap();
        let mut ownership = OwnershipIndex::new("test".to_owned(), None, None, None);
        ownership
            .entries
            .push(adopted_entry("adw", root.path().join("old-place/adw-gtk3")));

        let plan = build_asset_plan(
            &manifest("adw", "themes", "adw-gtk3"),
            root.path(),
            &ownership,
            false,
        );
        assert!(
            matches!(
                plan.operations(),
                [Operation::InstallAsset { target, .. }] if target == &root.path().join("themes")
            ),
            "{:?}",
            plan.operations()
        );
    }

    #[test]
    fn changed_owned_declaration_ignores_satisfied_installed_check() {
        let root = tempfile::tempdir().unwrap();
        let themes = root.path().join("themes");
        std::fs::create_dir_all(themes.join("adw-gtk3")).unwrap();

        let mut current = manifest("adw", "themes", "adw-gtk3");
        current.assets[0].sha256 = Some("bb".repeat(32));
        let mut previous = adopted_entry("adw", themes.join("adw-gtk3"));
        previous.asset_declaration.as_mut().unwrap().sha256 = Some("aa".repeat(32));
        let mut ownership = OwnershipIndex::new("test".to_owned(), None, None, None);
        ownership.entries.push(previous);

        let plan = build_asset_plan(&current, root.path(), &ownership, false);

        assert!(plan.errors().is_empty(), "{:?}", plan.errors());
        assert!(matches!(
            plan.operations(),
            [Operation::InstallAsset { declaration: Some(found), previous, .. }]
                if found.sha256.as_deref() == Some("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
                    && previous.len() == 1
        ));
    }

    #[test]
    fn legacy_adopted_asset_without_declaration_is_not_replaced() {
        let root = tempfile::tempdir().unwrap();
        let themes = root.path().join("themes");
        std::fs::create_dir_all(themes.join("adw-gtk3")).unwrap();

        let mut previous = adopted_entry("adw", themes.join("adw-gtk3"));
        previous.asset_declaration = None;
        let mut ownership = OwnershipIndex::new("test".to_owned(), None, None, None);
        ownership.entries.push(previous);

        let plan = build_asset_plan(
            &manifest("adw", "themes", "adw-gtk3"),
            root.path(),
            &ownership,
            false,
        );

        assert!(matches!(
            plan.operations(),
            [Operation::KeepAsset {
                declaration: Some(_),
                previous: Some(_),
                ..
            }]
        ));
    }

    #[test]
    fn legacy_archived_asset_without_declaration_refreshes_once() {
        let root = tempfile::tempdir().unwrap();
        let target = root.path().join("themes/adw-gtk3");
        std::fs::create_dir_all(&target).unwrap();
        let mut previous = adopted_entry("adw", target);
        previous.source = root.path().join("cas/old-payload");
        previous.asset_declaration = None;
        let mut ownership = OwnershipIndex::new("test".to_owned(), None, None, None);
        ownership.entries.push(previous);

        let plan = build_asset_plan(
            &manifest("adw", "themes", "adw-gtk3"),
            root.path(),
            &ownership,
            false,
        );

        assert!(matches!(
            plan.operations(),
            [Operation::InstallAsset { previous, .. }] if previous.len() == 1
        ));
    }
}
