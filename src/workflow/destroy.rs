//! Destroys a state transactionally when metadata is intact, or uses guarded
//! best-effort cleanup when it is not.

use crate::app::context::GlobalCtx;
use crate::app::prompt::confirm;
use crate::app::validation::validate_name;
use crate::config::{Config, LoadedConfigSource};
use crate::domain::id::StateName;
use crate::output::print_plan;
use crate::paths::{home_dir, normalize_lexical, xdg_state_home};
use crate::planning::plan::DeploymentPlan;
use crate::planning::stale::plan_undeploy_removals;
use crate::source::store::SourceSnapshot;
use crate::source::{ResolvedSource, SourceIdentity, SourceKind, TrustMode};
use crate::state::ensure_state_exists;
use crate::state::ownership::OwnershipIndex;
use crate::state::ownership_store::read_ownership_for;
use crate::state::record::{live_source_snapshot_id, restore_deployment_id};
use crate::state::target_lock::TargetLock;
use crate::state::transaction::TransactionKind;
use crate::workflow::pipeline::DeploymentPipeline;
use anyhow::{Context, Result};
use owo_colors::OwoColorize;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

pub fn run(ctx: &GlobalCtx, name: Option<&str>, yes: bool) -> Result<()> {
    let name = match name {
        Some(name) => name,
        None if ctx.state_namespace.as_str() != "default" => ctx.state_namespace.as_str(),
        None => anyhow::bail!(
            "specify the state to destroy: `malm state destroy <name>` \
             — see `malm state list`"
        ),
    };
    validate_name(name, "state name")?;
    ensure_state_flag_matches(ctx.state_namespace.as_str(), name)?;

    let state_dir = xdg_state_home().join("malm/states").join(name);
    ensure_state_exists(name)?;

    let ownership = if state_dir.join("ownership.json").is_file() {
        match read_ownership_for(name) {
            Ok(index) => Some(index),
            Err(error) => {
                println!(
                    "  {} cannot read ownership index: {error:#}",
                    "!".yellow().bold()
                );
                None
            }
        }
    } else {
        println!("  {} state has no ownership index", "!".yellow().bold());
        None
    };
    // A disabled state has no live deployment; fall back to its restore
    // target's snapshot so destroy can still run transactionally.
    let snapshot_id = live_source_snapshot_id(name).ok().flatten().or_else(|| {
        restore_deployment_id(name)
            .ok()
            .flatten()
            .and_then(|id| {
                crate::state::transaction::TransactionStore::new()
                    .read(&id)
                    .ok()
            })
            .map(|manifest| manifest.source_snapshot_id.as_str().to_owned())
    });
    let snapshot = snapshot_id
        .and_then(|id| SourceSnapshot::from_id(&id).ok())
        .filter(|snapshot| snapshot.require_on_disk().is_ok());

    match (ownership, snapshot) {
        (Some(ownership), Some(snapshot)) => {
            destroy_via_transaction(ctx, name, &ownership, &snapshot, yes)?;
        }
        (ownership, _) => {
            destroy_best_effort(name, ownership.as_ref(), yes)?;
        }
    }

    {
        let _guard = TargetLock::acquire_guard()?;
        let mut lock = TargetLock::load()?;
        lock.update_state(&[], name);
        lock.save().context("clear target lock entries")?;
    }
    std::fs::remove_dir_all(&state_dir)
        .with_context(|| format!("remove {}", state_dir.display()))?;

    println!(
        "\n  {} destroyed state '{name}' · {}",
        "✓".green().bold(),
        format!(
            "history kept for undo (`malm -s {name} state log`) \
             · `malm state prune` reclaims it as it ages out"
        )
        .dimmed()
    );
    Ok(())
}

fn ensure_state_flag_matches(flag: &str, name: &str) -> Result<()> {
    if flag != "default" && flag != name {
        anyhow::bail!(
            "--state {flag:?} conflicts with the state named on the command line ({name:?}); \
             `state destroy` takes the state as its positional argument"
        );
    }
    Ok(())
}

fn destroy_via_transaction(
    ctx: &GlobalCtx,
    name: &str,
    ownership: &OwnershipIndex,
    snapshot: &SourceSnapshot,
    yes: bool,
) -> Result<()> {
    let mut plan = DeploymentPlan::new();
    let blocked = plan_undeploy_removals(&mut plan, ownership);
    plan.validate_target_relationships();

    // Destroy deletes the state's records, so anything left in place becomes
    // untracked. List it explicitly before asking for confirmation.
    for removal in &blocked {
        println!(
            "  {} leaving {} in place ({}); it will no longer be tracked",
            "!".yellow().bold(),
            crate::output::display::format_short_path(&removal.entry.target),
            removal.reason
        );
    }

    if plan.operations().is_empty() {
        // Even with no operations, destroy needs a transaction recording the
        // lifecycle change.
        println!("  state '{name}' owns no removable targets");
    } else {
        print_plan(&plan, false);
    }
    confirm_destroy(name, yes)?;

    let mut destroy_ctx = ctx.clone();
    destroy_ctx.state_namespace = StateName::parse(name)?;
    destroy_ctx.profile = None;

    let repository_root = snapshot.repository().to_path_buf();
    let identity = ownership.source.clone().unwrap_or_else(|| SourceIdentity {
        kind: SourceKind::Local {
            path: repository_root.clone(),
        },
    });
    let trust_mode = match &identity.kind {
        SourceKind::Local { .. } => TrustMode::Trusted,
        SourceKind::Git { .. } => TrustMode::Untrusted,
    };
    let loaded = LoadedConfigSource {
        config: Config::empty(),
        resolved: ResolvedSource {
            source_root: repository_root.clone(),
            identity,
            trust_mode,
        },
        config_path: ownership
            .config
            .clone()
            .unwrap_or_else(|| repository_root.join("malm.kdl")),
        target_root: home_dir(),
        provenance: Vec::new(),
        external_includes_skipped: Vec::new(),
        // A destroy removes targets; no config is read.
        allow_local_includes: false,
    };

    let recorded_repo = match ownership.source.as_ref().map(|source| &source.kind) {
        Some(SourceKind::Local { path }) => Some(path.clone()),
        _ => None,
    };
    let pipeline = DeploymentPipeline::prepare_from_manifest(
        &destroy_ctx,
        loaded,
        plan,
        snapshot.id(),
        recorded_repo,
        TransactionKind::Destroy,
    )?;
    let pipeline = pipeline.approve_for_execution(Default::default())?;
    pipeline.execute(true)
}

fn destroy_best_effort(name: &str, ownership: Option<&OwnershipIndex>, yes: bool) -> Result<()> {
    println!(
        "  {} state '{name}' has incomplete metadata; using best-effort cleanup (no transaction will be recorded)",
        "!".yellow().bold()
    );

    let _guard = TargetLock::acquire_guard()?;

    let lock = TargetLock::load()?;
    let mut candidates: BTreeMap<PathBuf, Option<PathBuf>> = lock
        .targets_for(name)
        .into_iter()
        .map(|target| (target.to_path_buf(), None))
        .collect();
    if let Some(index) = ownership {
        for entry in index.iter() {
            candidates.insert(entry.target.clone(), Some(entry.source.clone()));
        }
    }

    let malm_root = xdg_state_home().join("malm");
    let mut removable = Vec::new();
    let mut kept = Vec::new();
    for (target, expected) in candidates {
        match classify_orphan(&target, expected.as_deref(), &malm_root) {
            OrphanDisposition::Absent => {}
            OrphanDisposition::Removable => removable.push(target),
            OrphanDisposition::Keep(reason) => kept.push((target, reason)),
        }
    }

    for (target, reason) in &kept {
        println!(
            "  {} leaving {} in place ({reason})",
            "!".yellow().bold(),
            crate::output::display::path(target)
        );
    }

    if removable.is_empty() {
        println!("  nothing to remove");
        return confirm_destroy(name, yes);
    }

    println!("  will remove {} symlink(s):", removable.len());
    for target in &removable {
        println!("    {}", crate::output::display::path(target));
    }
    confirm_destroy(name, yes)?;

    for target in &removable {
        std::fs::remove_file(target).with_context(|| format!("remove {}", target.display()))?;
    }
    println!("  removed {} symlink(s)", removable.len());
    Ok(())
}

enum OrphanDisposition {
    Absent,
    Removable,
    Keep(&'static str),
}

// Only remove a symlink that matches the recorded source or points into
// Malm's own state dir; anything else may be the user's and is kept.
fn classify_orphan(
    target: &Path,
    expected_source: Option<&Path>,
    malm_root: &Path,
) -> OrphanDisposition {
    let Ok(metadata) = std::fs::symlink_metadata(target) else {
        return OrphanDisposition::Absent;
    };
    if !metadata.file_type().is_symlink() {
        return OrphanDisposition::Keep("not a symlink");
    }
    let Ok(link) = std::fs::read_link(target) else {
        return OrphanDisposition::Keep("unreadable symlink");
    };
    if expected_source.is_some_and(|source| source == link) {
        return OrphanDisposition::Removable;
    }
    let resolved = if link.is_absolute() {
        normalize_lexical(&link)
    } else {
        let parent = target.parent().unwrap_or_else(|| Path::new("/"));
        normalize_lexical(&parent.join(&link))
    };
    if resolved.starts_with(malm_root) {
        OrphanDisposition::Removable
    } else {
        OrphanDisposition::Keep("does not point into Malm's state directory")
    }
}

fn confirm_destroy(name: &str, yes: bool) -> Result<()> {
    if yes {
        return Ok(());
    }
    if !confirm(&format!("\n  destroy state '{name}'?"))? {
        anyhow::bail!("aborted");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_flag_must_match_positional_name() {
        assert!(ensure_state_flag_matches("default", "scratch").is_ok());
        assert!(ensure_state_flag_matches("scratch", "scratch").is_ok());
        assert!(ensure_state_flag_matches("other", "scratch").is_err());
    }

    #[test]
    fn classify_orphan_dispositions() {
        let dir = tempfile::tempdir().expect("tempdir");
        let malm_root = dir.path().join("state/malm");
        std::fs::create_dir_all(&malm_root).expect("malm root");

        let missing = dir.path().join("missing");
        assert!(matches!(
            classify_orphan(&missing, None, &malm_root),
            OrphanDisposition::Absent
        ));

        let regular = dir.path().join("regular");
        std::fs::write(&regular, "data").expect("write file");
        assert!(matches!(
            classify_orphan(&regular, None, &malm_root),
            OrphanDisposition::Keep("not a symlink")
        ));

        let internal = dir.path().join("internal");
        std::os::unix::fs::symlink(malm_root.join("states/dead/current/x"), &internal)
            .expect("symlink");
        assert!(matches!(
            classify_orphan(&internal, None, &malm_root),
            OrphanDisposition::Removable
        ));

        let external_target = dir.path().join("elsewhere");
        let external = dir.path().join("external");
        std::os::unix::fs::symlink(&external_target, &external).expect("symlink");
        assert!(matches!(
            classify_orphan(&external, None, &malm_root),
            OrphanDisposition::Keep(_)
        ));

        assert!(matches!(
            classify_orphan(&external, Some(&external_target), &malm_root),
            OrphanDisposition::Removable
        ));
    }
}
