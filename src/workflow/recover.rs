//! `malm state recover` repairs interrupted transactions.
//!
//! Transactions at `FilesystemApplied` roll forward by finishing metadata and
//! activation. Earlier phases roll back journaled operations newest-first.
//!
//! Rollback first checks each operation's artifact. It only undoes artifacts
//! that still match what Malm created; external changes are reported and left
//! alone. Re-running recovery converges.

use crate::app::context::GlobalCtx;
use crate::app::prompt::confirm;
use crate::cas::{sources_object_dir, tree_hash};
use crate::domain::id::StateName;
use crate::failpoint;
use crate::fs::util::{move_path, remove_path};
use crate::sanitize::terminal;
use crate::source::store::SourceSnapshot;
use crate::state::active_deployment::{restore_source_pointer, set_source_pointer};
use crate::state::ownership::OwnershipIndex;
use crate::state::ownership_store::read_ownership_for;
use crate::state::record::{StateMode, StateRecord, latest_completed_apply_id, live_deployment_id};
use crate::state::target_lock::TargetLock;
use crate::state::transaction::{
    ApplyMetadataIntent, ApplyPhase, PreviousState, RecordedOp, TransactionKind,
    TransactionManifest, TransactionStatus, TransactionStore, transaction_alias,
};
use crate::workflow::bookkeeping::commit_apply_metadata;
use crate::workflow::frozen_plan::frozen_plan_from_manifest;
use anyhow::{Context, Result};
use owo_colors::OwoColorize;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

pub struct RecoverOpts {
    pub all: bool,
    pub dry_run: bool,
    pub yes: bool,
}

/// Exit code 0 = fully recovered (or nothing to do); 1 = recovered with
/// findings (e.g. a missing backup), leaving the transaction failed.
pub fn run(_ctx: &GlobalCtx, reference: Option<&str>, opts: &RecoverOpts) -> Result<i32> {
    let _guard = TargetLock::acquire_guard()?;
    let store = TransactionStore::new();

    let targets: Vec<TransactionManifest> = if opts.all {
        store
            .list_all()?
            .into_iter()
            .filter(|manifest| manifest.needs_rollback() || manifest.needs_roll_forward())
            .collect()
    } else {
        let reference =
            reference.context("pass a transaction reference or --all to recover everything")?;
        let id = store.resolve_reference(reference)?;
        let manifest = store.read(&id)?;
        if !manifest.needs_rollback() && !manifest.needs_roll_forward() {
            println!(
                "\n  {} transaction {} is {}; nothing to recover",
                "✓".green().bold(),
                transaction_alias(&id),
                manifest.status.label()
            );
            return Ok(0);
        }
        vec![manifest]
    };

    if targets.is_empty() {
        println!("\n  {} nothing to recover", "✓".green().bold());
        return Ok(0);
    }

    println!();
    for manifest in &targets {
        let direction = if manifest.needs_roll_forward() {
            "roll forward (finish metadata and activation)"
        } else {
            "roll back (undo partially applied changes)"
        };
        println!(
            "  {}  {} · state '{}' · {direction}",
            transaction_alias(manifest.id.as_str()).bold(),
            manifest.status.label().dimmed(),
            manifest.state_namespace(),
        );
    }

    if !opts.dry_run && !opts.yes && !confirm("\nRecovery may modify deployed files. Continue?")? {
        anyhow::bail!("recovery aborted");
    }

    let mut incomplete = false;
    for manifest in targets {
        let complete = if manifest.needs_roll_forward() {
            roll_forward(&store, &manifest, opts.dry_run)?
        } else {
            roll_back(&store, &manifest, opts.dry_run)?
        };
        incomplete |= !complete;
    }

    Ok(if incomplete { 1 } else { 0 })
}

/// Finish metadata for a transaction that reached `FilesystemApplied` before
/// crashing. Apply activates the deployment; Disable and Destroy finish their
/// respective state records.
fn roll_forward(
    store: &TransactionStore,
    manifest: &TransactionManifest,
    dry_run: bool,
) -> Result<bool> {
    let namespace = manifest.state_namespace().to_owned();
    let id = manifest.id.as_str().to_owned();
    let alias = transaction_alias(&id);

    let snapshot = SourceSnapshot::from_id(manifest.source_snapshot_id.as_str())?;
    snapshot.require_on_disk()?;

    if dry_run {
        let steps = match manifest.kind {
            TransactionKind::Apply => "ownership + target lock, source pointer, state record",
            TransactionKind::Disable => {
                "retained ownership + target lock, pointer removal, disabled state record"
            }
            TransactionKind::Destroy => {
                "cleared ownership + target lock, pointer removal, destroyed state record"
            }
        };
        println!("  would roll forward {alias}: {steps}, completed");
        return Ok(true);
    }

    match manifest.kind {
        TransactionKind::Apply => roll_forward_apply(store, manifest, &namespace, &snapshot)?,
        TransactionKind::Disable => roll_forward_disable(store, manifest, &namespace)?,
        TransactionKind::Destroy => roll_forward_destroy(store, manifest, &namespace)?,
    }

    store
        .mark_completed(&id)
        .context("mark recovered transaction completed")?;

    println!("  {} rolled forward {alias}", "✓".green().bold());
    Ok(true)
}

fn roll_forward_apply(
    store: &TransactionStore,
    manifest: &TransactionManifest,
    namespace: &str,
    snapshot: &SourceSnapshot,
) -> Result<()> {
    let id = manifest.id.as_str().to_owned();

    let mut phase = manifest.effective_phase();

    if phase < ApplyPhase::MetadataCommitted {
        if manifest.metadata_intent == ApplyMetadataIntent::Rewrite {
            let frozen = frozen_plan_from_manifest(manifest, namespace, snapshot)?;
            let managed: Vec<PathBuf> = frozen
                .operations()
                .iter()
                .filter_map(|op| op.managed_target_after_apply().map(Path::to_path_buf))
                .chain(
                    frozen
                        .retained_ownership()
                        .iter()
                        .map(|entry| entry.target.clone()),
                )
                .collect();
            let recover_ctx = GlobalCtx {
                repo: manifest.repo.clone(),
                config: manifest.config.clone(),
                profile: manifest.profile.clone(),
                state_namespace: StateName::parse(namespace)?,
                json: false,
                // Recovery only uses existing CAS snapshots, so it cannot make
                // the network request guarded by SSRF policy.
                allow_ssrf: false,
            };
            let config_path = manifest
                .config
                .clone()
                .unwrap_or_else(|| snapshot.repository().join("malm.kdl"));
            commit_apply_metadata(
                manifest.source.as_ref(),
                &config_path,
                &frozen,
                &managed,
                manifest.profile.as_deref(),
                &recover_ctx,
                Some(&id),
            )
            .context("commit post-apply metadata during recovery")?;
        }
        store.advance_phase(&id, ApplyPhase::MetadataCommitted)?;
        phase = ApplyPhase::MetadataCommitted;
        failpoint!("recover.apply.after_metadata");
    }

    if phase < ApplyPhase::ActivePointerSwapped {
        set_source_pointer(namespace, snapshot.root())
            .context("activate the recovered source snapshot")?;
        store.advance_phase(&id, ApplyPhase::ActivePointerSwapped)?;
        failpoint!("recover.apply.after_pointer");
    }

    StateRecord::set(namespace, StateMode::enabled(id)).context("persist state record")
}

fn roll_forward_disable(
    store: &TransactionStore,
    manifest: &TransactionManifest,
    namespace: &str,
) -> Result<()> {
    let id = manifest.id.as_str().to_owned();

    // Keep ownership only for deliberately retained targets. Filtering the
    // current index converges even if the crashed disable already rewrote it.
    let ownership = read_ownership_for(namespace)?;
    let kept: Vec<_> = ownership
        .iter()
        .filter(|entry| manifest.kept_targets.contains(&entry.target))
        .cloned()
        .collect();
    let mut phase = manifest.effective_phase();

    if phase < ApplyPhase::MetadataCommitted {
        let mut lock = TargetLock::load().context("load target lock")?;
        lock.update_state(&manifest.kept_targets, namespace);
        lock.save().context("persist target lock")?;
        let mut index = OwnershipIndex::new(
            namespace.to_owned(),
            ownership.source.clone(),
            ownership.config.clone(),
            ownership.profile.clone(),
        );
        index.entries = kept;
        index.save_for_state(namespace)?;
        store.advance_phase(&id, ApplyPhase::MetadataCommitted)?;
        phase = ApplyPhase::MetadataCommitted;
    }

    if phase < ApplyPhase::ActivePointerSwapped {
        restore_source_pointer(namespace, None).context("remove the source pointer")?;
        store.advance_phase(&id, ApplyPhase::ActivePointerSwapped)?;
    }

    // Older Disable manifests predate the recorded restore target; the
    // newest completed apply is what disable would have recorded.
    let restore = match &manifest.restore_transaction {
        Some(restore) => restore.clone(),
        None => latest_completed_apply_id(namespace)?.with_context(|| {
            format!(
                "cannot finish disabling state '{namespace}': no completed deployment to record \
                 as its restore target"
            )
        })?,
    };
    StateRecord::set(
        namespace,
        StateMode::disabled(restore, manifest.kept_targets.clone()),
    )
    .context("persist disabled state record")
}

fn roll_forward_destroy(
    store: &TransactionStore,
    manifest: &TransactionManifest,
    namespace: &str,
) -> Result<()> {
    let id = manifest.id.as_str().to_owned();
    let mut phase = manifest.effective_phase();

    if phase < ApplyPhase::MetadataCommitted {
        let mut lock = TargetLock::load().context("load target lock")?;
        lock.update_state(&[], namespace);
        lock.save().context("persist target lock")?;
        let ownership = read_ownership_for(namespace)?;
        let mut index = OwnershipIndex::new(
            namespace.to_owned(),
            ownership.source.clone(),
            ownership.config.clone(),
            ownership.profile.clone(),
        );
        index.entries = Vec::new();
        index.save_for_state(namespace)?;
        store.advance_phase(&id, ApplyPhase::MetadataCommitted)?;
        phase = ApplyPhase::MetadataCommitted;
    }

    if phase < ApplyPhase::ActivePointerSwapped {
        restore_source_pointer(namespace, None).context("remove the source pointer")?;
        store.advance_phase(&id, ApplyPhase::ActivePointerSwapped)?;
    }

    StateRecord::set(namespace, StateMode::destroyed(Some(id)))
        .context("persist destroyed state record")
}

enum UndoOutcome {
    Converged,
    Undone(String),
    WouldUndo(String),
    Skipped(String),
    MissingBackup(String),
}

/// Undo the journaled operations of a mid-mutation crash, newest first.
fn roll_back(
    store: &TransactionStore,
    manifest: &TransactionManifest,
    dry_run: bool,
) -> Result<bool> {
    let namespace = manifest.state_namespace().to_owned();
    let id = manifest.id.as_str().to_owned();
    let alias = transaction_alias(&id);
    let mut complete = true;

    for op in manifest.operations.iter().rev() {
        match undo_op(op, !dry_run)? {
            UndoOutcome::Converged => {}
            UndoOutcome::Undone(what) => {
                println!("  {} {}", "↩".cyan().bold(), terminal(&what));
            }
            UndoOutcome::WouldUndo(what) => println!("  would undo: {}", terminal(&what)),
            UndoOutcome::Skipped(why) => {
                println!("  {} skipped: {}", "!".yellow().bold(), terminal(&why));
            }
            UndoOutcome::MissingBackup(what) => {
                eprintln!("  {} {}", "✗".red().bold(), terminal(&what));
                complete = false;
            }
        }
    }

    // Pre-phase applies swapped the source pointer before filesystem changes.
    // Restore the last completed deployment's pointer.
    if manifest.phase.is_none() && !dry_run {
        let previous_root = match live_deployment_id(&namespace)? {
            Some(active) => Some(sources_object_dir(
                store.read(&active)?.source_snapshot_id.as_str(),
            )?),
            None => None,
        };
        restore_source_pointer(&namespace, previous_root.as_deref())
            .context("restore the previous source pointer")?;
    }

    if dry_run {
        return Ok(true);
    }

    if complete {
        store.update(&id, |manifest| {
            manifest.status = TransactionStatus::RolledBack;
        })?;
        store.clear_ops_log(&id)?;
        println!("  {} rolled back {alias}", "✓".green().bold());
    } else {
        eprintln!(
            "  {} {alias} was only partially rolled back (see findings above); it stays \
             failed and its remaining backups are retained",
            "✗".red().bold()
        );
    }
    Ok(complete)
}

fn undo_op(op: &RecordedOp, act: bool) -> Result<UndoOutcome> {
    match op {
        RecordedOp::CreateSymlink {
            src, dst, previous, ..
        } => undo_symlink_create(src, dst, previous, act),
        RecordedOp::RemovePath { path, previous, .. } => undo_remove(path, previous, act),
        RecordedOp::InstallAsset {
            dst,
            payload,
            previous,
            name,
            ..
        } => undo_asset_install(name, dst, payload, previous, act),
        RecordedOp::RemoveAsset {
            name,
            dst,
            payload,
            quarantine,
            ..
        } => undo_asset_remove(name, dst, payload, quarantine.as_deref(), act),
    }
}

/// Undo an asset removal. Prefers moving the quarantined tree back (the
/// exact removed bytes, including mtimes/xattrs); falls back to reinstalling
/// the CAS payload for pre-quarantine manifests or a missing quarantine.
fn undo_asset_remove(
    name: &str,
    dst: &Path,
    payload: &Path,
    quarantine: Option<&Path>,
    act: bool,
) -> Result<UndoOutcome> {
    match fs::symlink_metadata(dst) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error).with_context(|| format!("inspect {}", dst.display())),
        Ok(_) => {
            // Do not displace a new occupant. Matching content means the
            // removal never happened, so rollback has already converged.
            let converged = payload
                .file_name()
                .and_then(|leaf| leaf.to_str())
                .is_some_and(|expected| {
                    tree_hash(dst)
                        .map(|actual| actual == expected)
                        .unwrap_or(false)
                });
            return Ok(if converged {
                UndoOutcome::Converged
            } else {
                UndoOutcome::Skipped(format!(
                    "asset '{name}' destination {} is occupied by other content",
                    dst.display()
                ))
            });
        }
    }

    if let Some(quarantine) = quarantine.filter(|q| fs::symlink_metadata(q).is_ok()) {
        let what = format!("restore quarantined asset '{name}' at {}", dst.display());
        if !act {
            return Ok(UndoOutcome::WouldUndo(what));
        }
        move_path(quarantine, dst)
            .with_context(|| format!("restore quarantined asset to {}", dst.display()))?;
        return Ok(UndoOutcome::Undone(what));
    }

    if !payload.is_dir() {
        return Ok(UndoOutcome::MissingBackup(format!(
            "cannot reinstall asset '{name}' at {}: payload {} is missing",
            dst.display(),
            payload.display()
        )));
    }
    let what = format!("reinstall removed asset '{name}' at {}", dst.display());
    if !act {
        return Ok(UndoOutcome::WouldUndo(what));
    }
    if let Some(parent) = dst.parent().filter(|p| !p.as_os_str().is_empty()) {
        fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    }
    let leaf = dst.file_name().unwrap_or_default().to_string_lossy();
    let staged = dst.with_file_name(format!(".{leaf}.malm-recover.{}", std::process::id()));
    let _ = remove_path(&staged);
    if let Err(error) = crate::fs::util::copy_recursive(payload, &staged) {
        let _ = remove_path(&staged);
        return Err(error).with_context(|| format!("stage asset payload for {}", dst.display()));
    }
    if let Err(error) = crate::fs::util::rename_noreplace(&staged, dst) {
        let _ = remove_path(&staged);
        return Err(error).with_context(|| format!("atomically reinstall {}", dst.display()));
    }
    Ok(UndoOutcome::Undone(what))
}

fn undo_symlink_create(
    src: &Path,
    dst: &Path,
    previous: &PreviousState,
    act: bool,
) -> Result<UndoOutcome> {
    let metadata = match fs::symlink_metadata(dst) {
        Ok(metadata) => Some(metadata),
        Err(error) if error.kind() == io::ErrorKind::NotFound => None,
        Err(error) => return Err(error).with_context(|| format!("inspect {}", dst.display())),
    };

    match metadata {
        None => match previous {
            PreviousState::Missing => Ok(UndoOutcome::Converged),
            PreviousState::Symlink { old_target } | PreviousState::BrokenSymlink { old_target } => {
                let what = format!(
                    "restore symlink {} -> {}",
                    dst.display(),
                    old_target.display()
                );
                if !act {
                    return Ok(UndoOutcome::WouldUndo(what));
                }
                std::os::unix::fs::symlink(old_target, dst)
                    .with_context(|| format!("recreate previous symlink {}", dst.display()))?;
                Ok(UndoOutcome::Undone(what))
            }
            PreviousState::Backed { backup, .. } => restore_backup_to(backup, dst, act),
        },
        Some(metadata) if metadata.file_type().is_symlink() => {
            let current_target = dst
                .read_link()
                .with_context(|| format!("read link {}", dst.display()))?;
            if current_target != src {
                if let PreviousState::Symlink { old_target }
                | PreviousState::BrokenSymlink { old_target } = previous
                    && &current_target == old_target
                {
                    return Ok(UndoOutcome::Converged);
                }
                return Ok(UndoOutcome::Skipped(format!(
                    "{} changed externally (now points at {})",
                    dst.display(),
                    current_target.display()
                )));
            }
            // The symlink is ours; put back what was there before.
            match previous {
                PreviousState::Missing => {
                    let what = format!("remove created symlink {}", dst.display());
                    if !act {
                        return Ok(UndoOutcome::WouldUndo(what));
                    }
                    fs::remove_file(dst)
                        .with_context(|| format!("remove created symlink {}", dst.display()))?;
                    Ok(UndoOutcome::Undone(what))
                }
                PreviousState::Symlink { old_target }
                | PreviousState::BrokenSymlink { old_target } => {
                    let what = format!(
                        "restore symlink {} -> {}",
                        dst.display(),
                        old_target.display()
                    );
                    if !act {
                        return Ok(UndoOutcome::WouldUndo(what));
                    }
                    replace_with_symlink(old_target, dst)?;
                    Ok(UndoOutcome::Undone(what))
                }
                PreviousState::Backed { backup, .. } => {
                    if !backup.exists() {
                        return Ok(UndoOutcome::MissingBackup(format!(
                            "cannot restore {}: backup {} is missing",
                            dst.display(),
                            backup.display()
                        )));
                    }
                    let what = format!("restore original file at {}", dst.display());
                    if !act {
                        return Ok(UndoOutcome::WouldUndo(what));
                    }
                    fs::remove_file(dst)
                        .with_context(|| format!("remove created symlink {}", dst.display()))?;
                    move_path(backup, dst)
                        .with_context(|| format!("restore backup to {}", dst.display()))?;
                    Ok(UndoOutcome::Undone(what))
                }
            }
        }
        Some(_) => match previous {
            // A regular file where we would have created a symlink: the
            // original was never replaced (the swap is atomic). Leave it.
            PreviousState::Backed { .. } => Ok(UndoOutcome::Converged),
            _ => Ok(UndoOutcome::Skipped(format!(
                "{} changed externally (now a regular path)",
                dst.display()
            ))),
        },
    }
}

fn undo_remove(path: &Path, previous: &PreviousState, act: bool) -> Result<UndoOutcome> {
    let PreviousState::Symlink { old_target } = previous else {
        return Ok(UndoOutcome::Skipped(format!(
            "{} was removed but its previous state is not a symlink record",
            path.display()
        )));
    };
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let what = format!(
                "restore removed symlink {} -> {}",
                path.display(),
                old_target.display()
            );
            if !act {
                return Ok(UndoOutcome::WouldUndo(what));
            }
            std::os::unix::fs::symlink(old_target, path)
                .with_context(|| format!("recreate removed symlink {}", path.display()))?;
            Ok(UndoOutcome::Undone(what))
        }
        Err(error) => Err(error).with_context(|| format!("inspect {}", path.display())),
        Ok(metadata) if metadata.file_type().is_symlink() => {
            let current = path
                .read_link()
                .with_context(|| format!("read link {}", path.display()))?;
            if &current == old_target {
                Ok(UndoOutcome::Converged)
            } else {
                Ok(UndoOutcome::Skipped(format!(
                    "{} changed externally (now points at {})",
                    path.display(),
                    current.display()
                )))
            }
        }
        Ok(_) => Ok(UndoOutcome::Skipped(format!(
            "{} changed externally (no longer a symlink)",
            path.display()
        ))),
    }
}

fn undo_asset_install(
    name: &str,
    dst: &Path,
    payload: &Path,
    previous: &PreviousState,
    act: bool,
) -> Result<UndoOutcome> {
    let metadata = match fs::symlink_metadata(dst) {
        Ok(metadata) => Some(metadata),
        Err(error) if error.kind() == io::ErrorKind::NotFound => None,
        Err(error) => return Err(error).with_context(|| format!("inspect {}", dst.display())),
    };

    match metadata {
        None => match previous {
            PreviousState::Backed { backup, .. } => restore_backup_to(backup, dst, act),
            _ => Ok(UndoOutcome::Converged),
        },
        Some(metadata) => {
            let is_our_payload = metadata.file_type().is_dir()
                && payload
                    .file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|expected| {
                        tree_hash(dst)
                            .map(|actual| actual == expected)
                            .unwrap_or(false)
                    });
            if !is_our_payload {
                let retained = match previous {
                    PreviousState::Backed { backup, .. } if backup.exists() => {
                        format!(" (previous contents retained at {})", backup.display())
                    }
                    _ => String::new(),
                };
                return Ok(UndoOutcome::Skipped(format!(
                    "asset '{name}' at {} changed externally{retained}",
                    dst.display()
                )));
            }
            let what = format!("remove installed asset '{name}' at {}", dst.display());
            if !act {
                return Ok(UndoOutcome::WouldUndo(what));
            }
            remove_path(dst)
                .with_context(|| format!("remove installed asset {}", dst.display()))?;
            match previous {
                PreviousState::Backed { backup, .. } => {
                    match restore_backup_to(backup, dst, act)? {
                        UndoOutcome::Undone(_) | UndoOutcome::Converged => Ok(UndoOutcome::Undone(
                            format!("{what}; previous contents restored"),
                        )),
                        other => Ok(other),
                    }
                }
                _ => Ok(UndoOutcome::Undone(what)),
            }
        }
    }
}

fn restore_backup_to(backup: &Path, dst: &Path, act: bool) -> Result<UndoOutcome> {
    if !backup.exists() {
        return Ok(UndoOutcome::MissingBackup(format!(
            "cannot restore {}: backup {} is missing",
            dst.display(),
            backup.display()
        )));
    }
    let what = format!("restore original contents at {}", dst.display());
    if !act {
        return Ok(UndoOutcome::WouldUndo(what));
    }
    move_path(backup, dst).with_context(|| format!("restore backup to {}", dst.display()))?;
    Ok(UndoOutcome::Undone(what))
}

fn replace_with_symlink(target: &Path, dst: &Path) -> Result<()> {
    let name = dst.file_name().unwrap_or_default().to_string_lossy();
    let staged = dst.with_file_name(format!(".{name}.malm-recover.{}", std::process::id()));
    let _ = fs::remove_file(&staged);
    std::os::unix::fs::symlink(target, &staged)
        .with_context(|| format!("stage recovery symlink for {}", dst.display()))?;
    if let Err(error) = crate::fs::atomic::swap_durable(&staged, dst) {
        let _ = fs::remove_file(&staged);
        return Err(anyhow::anyhow!(
            "atomically restore {}: {error}",
            dst.display()
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Asset-removal rollback prefers the exact quarantined bytes over
    /// reinstalling the CAS payload.
    #[test]
    fn undo_asset_remove_restores_from_quarantine() {
        let dir = tempfile::tempdir().unwrap();
        let quarantine = dir.path().join("backups/asset");
        fs::create_dir_all(&quarantine).unwrap();
        fs::write(quarantine.join("file"), b"exact bytes").unwrap();
        let dst = dir.path().join("deployed/asset");
        let payload = dir.path().join("cas/does-not-exist");

        let outcome = undo_asset_remove("demo", &dst, &payload, Some(&quarantine), true).unwrap();
        assert!(matches!(outcome, UndoOutcome::Undone(_)));
        assert_eq!(fs::read(dst.join("file")).unwrap(), b"exact bytes");
        assert!(fs::symlink_metadata(&quarantine).is_err());
    }

    /// Pre-quarantine manifests (quarantine: None) with a missing payload
    /// still surface the existing missing-backup outcome.
    #[test]
    fn undo_asset_remove_without_quarantine_needs_the_payload() {
        let dir = tempfile::tempdir().unwrap();
        let dst = dir.path().join("deployed/asset");
        let payload = dir.path().join("cas/does-not-exist");

        let outcome = undo_asset_remove("demo", &dst, &payload, None, true).unwrap();
        assert!(matches!(outcome, UndoOutcome::MissingBackup(_)));
    }
}
