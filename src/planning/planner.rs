//! Builds a plan by resolving, type-checking, expanding, and validating the
//! selected profile, then materializing generated artifacts and planning asset
//! and stale-target operations.

use crate::config::{Config, MissingSourcePolicy, ProfileSelection};
use crate::fs::atomic;
use crate::lang::budget::Limits;
use crate::lang::compile::{CompileOptions, compile_profile};
use crate::lang::diag::Severity;
use crate::planning::assets::build_asset_plan;
use crate::planning::destination::{reject_target_escape, resolve_target_path};
use crate::planning::output::{OutputBudget, compile_ignore_patterns};
use crate::planning::plan::{DeclarationOwner, DeploymentPlan, Operation};
use crate::planning::stale::plan_stale_removals;
use crate::source::TrustMode;
use crate::state::ownership::OwnershipIndex;
use sha2::{Digest, Sha256};
use std::path::Path;
use walkdir::WalkDir;

pub(crate) fn detect_hostname() -> Option<String> {
    std::fs::read_to_string("/etc/hostname")
        .map(|s| s.trim().to_owned())
        .ok()
        .filter(|s| !s.is_empty())
        .or_else(|| {
            std::env::var("HOSTNAME")
                .ok()
                .map(|s| s.trim().to_owned())
                .filter(|s| !s.is_empty())
        })
}

pub(crate) fn build_deployment_plan_with_render_root(
    cfg: &Config,
    source_root: &Path,
    target_root: &Path,
    render_root: &Path,
    profile: &ProfileSelection,
    ownership: &OwnershipIndex,
    trust_mode: TrustMode,
) -> DeploymentPlan {
    let mut plan = DeploymentPlan::new();
    plan.extend_warnings(cfg.warnings.iter().cloned());

    let untrusted = matches!(trust_mode, TrustMode::Untrusted);

    let Some(selected) = profile.selected() else {
        if profile.is_missing_default() {
            plan.add_warning(
                "no active profile - run with `--profile <name>` or set \
                 `default-profile` in malm.kdl"
                    .to_owned(),
            );
        }
        // An explicit `--profile none` still plans asset and stale-removal
        // work.
        finish_plan(cfg, target_root, ownership, untrusted, &mut plan);
        return plan;
    };

    let mut diagnostics = crate::lang::diag::Diagnostics::new();
    let options = CompileOptions {
        target_root: target_root.display().to_string(),
        hostname: (!untrusted).then(detect_hostname).flatten(),
        restrict_source_root: untrusted,
        limits: Limits::default(),
    };
    let compiled = compile_profile(&cfg.workspace, selected, &options, &mut diagnostics);

    for diagnostic in diagnostics.items() {
        let rendered = diagnostic.render(&cfg.sources);
        match diagnostic.severity {
            Severity::Error => plan.add_error(rendered.trim_end().to_owned()),
            Severity::Warning => plan.add_warning(rendered.trim_end().to_owned()),
        }
    }
    let Some(compiled) = compiled else {
        return plan;
    };
    if plan.has_errors() {
        return plan;
    }

    let mut generated = compiled.generated;
    // Mutating pipelines pass a private source snapshot here. Resolve raw
    // file and directory outputs onto that tree before any existence checks
    // or directory walks, so planning cannot observe bytes newer than the
    // snapshot that will be hashed and published.
    if source_root != cfg.workspace.source_root {
        for file in &mut generated.files {
            if let Ok(relative) = file.source.strip_prefix(&cfg.workspace.source_root) {
                file.source = source_root.join(relative);
            }
        }
        for dir in &mut generated.dirs {
            if let Ok(relative) = dir.source.strip_prefix(&cfg.workspace.source_root) {
                dir.source = source_root.join(relative);
            }
        }
    }

    // Write generated artifacts to the private staging root and plan one
    // symlink per artifact. Planning writes nowhere else.
    for artifact in &generated.artifacts {
        if reject_target_escape(&artifact.to, "output", &mut plan) {
            continue;
        }
        let destination = resolve_target_path(&artifact.to, target_root);
        let label = format!("{}:{}", artifact.instance, artifact.to);
        match write_rendered(render_root, &label, &destination, artifact) {
            Ok(rendered_path) => {
                plan.push(Operation::CreateSymlink {
                    owner: DeclarationOwner::TemplateFile { source: label },
                    source: rendered_path,
                    target: destination,
                    policy: MissingSourcePolicy::RequireSource,
                    conflict: crate::config::ConflictPolicy::Backup,
                });
            }
            Err(error) => plan.add_error(format!("write generated {}: {error:#}", artifact.to)),
        }
    }

    for file in &generated.files {
        if reject_target_escape(&file.to, "file", &mut plan) {
            continue;
        }
        if !file.source.exists() && !file.source.is_symlink() {
            if file.optional {
                continue;
            }
            plan.add_error(format!("file not found: {}", file.source.display()));
            continue;
        }
        plan.push(Operation::CreateSymlink {
            owner: DeclarationOwner::File {
                source: file.source_label.clone(),
            },
            source: file.source.clone(),
            target: resolve_target_path(&file.to, target_root),
            policy: MissingSourcePolicy::RequireSource,
            conflict: file.on_conflict,
        });
    }

    let mut output_budget = OutputBudget::new(Limits::default());
    for dir in &generated.dirs {
        if output_budget.exhausted() {
            break;
        }
        plan_dir(dir, target_root, &mut output_budget, &mut plan);
    }

    for symlink in &generated.symlinks {
        let src = crate::paths::expand_tilde(&symlink.source);
        let dst = crate::paths::normalize_lexical(&crate::paths::expand_tilde(&symlink.to));
        if !dst.is_absolute() {
            plan.add_error(format!(
                "symlink destination must be an absolute or ~-prefixed path: {}",
                symlink.to
            ));
            continue;
        }
        let escapes = untrusted
            && crate::policy::source_escapes_source_root(&src, &cfg.workspace.source_root);
        if !escapes {
            if symlink.if_missing == MissingSourcePolicy::RequireSource
                && !src.exists()
                && !src.is_symlink()
            {
                if symlink.optional {
                    continue;
                }
                plan.add_error(format!("symlink source not found: {}", src.display()));
                continue;
            }
            if symlink.optional && !src.exists() && !src.is_symlink() {
                continue;
            }
        }
        plan.push(Operation::CreateSymlink {
            owner: DeclarationOwner::Symlink,
            source: src,
            target: dst,
            policy: symlink.if_missing,
            conflict: crate::config::ConflictPolicy::Backup,
        });
    }

    let dir_target_errors: Vec<String> = plan
        .operations()
        .iter()
        .filter_map(|op| match op {
            Operation::CreateSymlink {
                target: dst, owner, ..
            } if std::fs::symlink_metadata(dst)
                .map(|m| m.file_type().is_dir())
                .unwrap_or(false) =>
            {
                Some(format!(
                    "destination is a directory (remove it manually): {} [{}]",
                    dst.display(),
                    owner.label()
                ))
            }
            _ => None,
        })
        .collect();
    for err in dir_target_errors {
        plan.add_error(err);
    }

    if plan.has_errors() {
        return plan;
    }

    finish_plan(cfg, target_root, ownership, untrusted, &mut plan);
    plan
}

fn finish_plan(
    cfg: &Config,
    target_root: &Path,
    ownership: &OwnershipIndex,
    untrusted: bool,
    plan: &mut DeploymentPlan,
) {
    if let Some(manifest) = &cfg.assets {
        plan.extend(build_asset_plan(
            manifest,
            target_root,
            ownership,
            untrusted,
        ));
    }
    if plan.has_errors() {
        return;
    }
    plan_stale_removals(plan, ownership);
    plan.validate_target_relationships();
}

fn plan_dir(
    dir: &crate::lang::expand::DirOut,
    target_root: &Path,
    budget: &mut OutputBudget,
    plan: &mut DeploymentPlan,
) {
    if !dir.source.exists() {
        if dir.optional {
            return;
        }
        plan.add_error(format!("dir not found: {}", dir.source.display()));
        return;
    }
    let dst_str = dir.to.clone().unwrap_or_else(|| {
        Path::new(&dir.source_label)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or(dir.source_label.as_str())
            .to_owned()
    });
    if reject_target_escape(&dst_str, "dir", plan) {
        return;
    }
    let dst_dir = resolve_target_path(&dst_str, target_root);
    let ignore = match compile_ignore_patterns(&dir.ignore) {
        Ok(ignore) => ignore,
        Err(error) => {
            plan.add_error(error.to_string());
            return;
        }
    };

    if dst_dir.is_symlink() {
        plan.push(Operation::RemovePath {
            owner: DeclarationOwner::Dir {
                source: dir.source_label.clone(),
            },
            path: dst_dir.clone(),
            expected_symlink_target: dst_dir.read_link().ok(),
        });
    }

    for entry in WalkDir::new(&dir.source).min_depth(1).sort_by_file_name() {
        let entry = match entry {
            Ok(e) => e,
            Err(e) => {
                plan.add_error(format!("walk {}: {:#}", dir.source.display(), e));
                return;
            }
        };
        if let Err(error) = budget.count_directory_entry() {
            plan.add_error(format!("dir `{}`: {error}", dir.source_label));
            return;
        }
        let path = entry.path();
        if path.is_dir() && !path.is_symlink() {
            continue;
        }
        let rel = match path.strip_prefix(&dir.source) {
            Ok(r) => r,
            Err(e) => {
                plan.add_error(format!("strip prefix in {}: {e:#}", dir.source.display()));
                continue;
            }
        };
        if ignore.as_ref().is_some_and(|g| g.is_match(rel)) {
            continue;
        }
        plan.push(Operation::CreateSymlink {
            owner: DeclarationOwner::Dir {
                source: dir.source_label.clone(),
            },
            source: path.to_path_buf(),
            target: dst_dir.join(rel),
            policy: MissingSourcePolicy::RequireSource,
            conflict: dir.on_conflict,
        });
    }
}

/// Write one generated artifact into the staging render root. The file name
/// hashes declaration identity, destination, and content with 0-byte
/// separators so no field boundary can be forged by crafted values.
fn write_rendered(
    render_root: &Path,
    label: &str,
    destination: &Path,
    artifact: &crate::lang::artifact::Artifact,
) -> anyhow::Result<std::path::PathBuf> {
    use anyhow::Context;

    let output_sha256 = hex::encode(Sha256::digest(artifact.content.as_bytes()));
    let mut name_hasher = Sha256::new();
    name_hasher.update(label.as_bytes());
    name_hasher.update([0]);
    name_hasher.update(destination.display().to_string().as_bytes());
    name_hasher.update([0]);
    name_hasher.update(output_sha256.as_bytes());
    let name = format!("{}.rendered", hex::encode(name_hasher.finalize()));
    let output_path = render_root.join(name);
    atomic::write(&output_path, artifact.content.as_bytes())?;
    use std::os::unix::fs::PermissionsExt;
    let mode = if artifact.executable { 0o755 } else { 0o644 };
    std::fs::set_permissions(&output_path, std::fs::Permissions::from_mode(mode))
        .with_context(|| format!("set permissions on {}", output_path.display()))?;
    Ok(output_path)
}
