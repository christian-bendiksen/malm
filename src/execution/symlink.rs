//! Creates symlinks with source policy checks, journaled backups, atomic swaps,
//! and TOCTOU identity checks around the backup.

use crate::config::{ConflictPolicy, MissingSourcePolicy};
use crate::execution::session::ApplySession;
use crate::execution::{SourceResolver, captured_identity};
use crate::fs::inspect::{PathIdentity, symlink_target_is_reachable};
use crate::fs::util::copy_regular_file_preserving_metadata;
use crate::planning::plan::DeclarationOwner;
use crate::state::transaction::{OperationStatus, PathKind, PreviousState};
use anyhow::{Context, Result};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

pub(super) fn execute_symlink_create(
    src: &Path,
    dst: &Path,
    policy: MissingSourcePolicy,
    conflict: ConflictPolicy,
    owner: &DeclarationOwner,
    resolver: &SourceResolver,
    session: &mut ApplySession,
) -> Result<()> {
    if policy == MissingSourcePolicy::RequireSource {
        // The alias still points at the previous snapshot during execution,
        // so stat the source inside the real object root.
        let on_disk = resolver.on_disk(src);
        if !on_disk.exists() && !on_disk.is_symlink() {
            anyhow::bail!("source does not exist: {}", src.display());
        }
    }

    // Already points at the desired source: idempotent no-op, nothing
    // journaled.
    if dst.read_link().ok().as_deref() == Some(src) {
        return Ok(());
    }

    let previous = match fs::symlink_metadata(dst) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => PreviousState::Missing,
        Err(e) => return Err(e).with_context(|| format!("stat {}", dst.display())),
        Ok(meta) if meta.file_type().is_dir() => {
            anyhow::bail!(
                "destination is a directory: {}; remove it manually",
                dst.display()
            );
        }
        Ok(meta) if meta.file_type().is_symlink() => {
            let old_target = dst
                .read_link()
                .with_context(|| format!("read link {}", dst.display()))?;
            if symlink_target_is_reachable(dst, &old_target) {
                PreviousState::Symlink { old_target }
            } else {
                PreviousState::BrokenSymlink { old_target }
            }
        }
        Ok(meta) => PreviousState::Backed {
            backup: session.backup_path_for(dst),
            path_kind: PathKind::of(meta.file_type()),
        },
    };
    let expected_identity = match previous {
        PreviousState::Missing => None,
        _ => Some(
            PathIdentity::capture(dst)
                .with_context(|| format!("capture identity for {}", dst.display()))?,
        ),
    };

    if conflict == ConflictPolicy::Fail && !matches!(previous, PreviousState::Missing) {
        anyhow::bail!(
            "destination exists and on-conflict=\"fail\": {}",
            dst.display()
        );
    }

    let op_index = session.journal_symlink_started(
        owner.clone(),
        src.to_path_buf(),
        dst.to_path_buf(),
        previous.clone(),
    )?;

    let result = (|| -> Result<()> {
        if let Some(parent) = dst.parent().filter(|p| !p.as_os_str().is_empty()) {
            fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
        }

        match &previous {
            PreviousState::Missing => match std::os::unix::fs::symlink(src, dst) {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                    anyhow::bail!(
                        "{} was created by another process during apply; refusing to overwrite",
                        dst.display()
                    );
                }
                Err(e) => {
                    return Err(e).with_context(|| format!("create symlink {}", dst.display()));
                }
            },
            // Check identity before and after the backup copy because the
            // destination must not change while the copy runs.
            PreviousState::Backed { backup, .. } => {
                let identity = captured_identity(expected_identity.as_ref(), dst)?;
                let staged = stage_symlink(src, dst, op_index)?;
                if let Some(parent) = backup.parent() {
                    fs::create_dir_all(parent)
                        .with_context(|| format!("create backup dir {}", parent.display()))?;
                }
                if let Err(e) = identity.ensure_unchanged(dst) {
                    let _ = fs::remove_file(&staged);
                    return Err(e);
                }
                if let Err(e) = copy_regular_file_preserving_metadata(dst, backup) {
                    let _ = fs::remove_file(&staged);
                    return Err(e).with_context(|| format!("copy backup {}", dst.display()));
                }
                // The backup is the only durable copy of the user's original
                // file once the swap below overwrites `dst`: fsync the bytes
                // and the backup directory before proceeding.
                if let Err(e) = crate::fs::atomic::sync_file(backup) {
                    let _ = fs::remove_file(&staged);
                    return Err(e);
                }
                if let Err(e) = crate::fs::atomic::sync_parent_dir(backup) {
                    let _ = fs::remove_file(&staged);
                    return Err(e);
                }
                if let Err(e) = identity.ensure_unchanged(dst) {
                    let _ = fs::remove_file(&staged);
                    return Err(e);
                }
                commit_staged(&staged, dst)?;
                println!("  ! backed up {}", crate::output::display::path(dst));
            }
            PreviousState::Symlink { .. } | PreviousState::BrokenSymlink { .. } => {
                let identity = captured_identity(expected_identity.as_ref(), dst)?;
                let staged = stage_symlink(src, dst, op_index)?;
                if let Err(e) = identity.ensure_unchanged(dst) {
                    let _ = fs::remove_file(&staged);
                    return Err(e);
                }
                commit_staged(&staged, dst)?;
            }
        }

        Ok(())
    })();

    session.mark_operation(
        op_index,
        if result.is_ok() {
            OperationStatus::Applied
        } else {
            OperationStatus::Failed
        },
    );

    result?;

    Ok(())
}

fn stage_symlink(src: &Path, dst: &Path, op_index: usize) -> Result<PathBuf> {
    let name = dst.file_name().unwrap_or_default().to_string_lossy();
    let staged = dst.with_file_name(format!(
        ".{name}.malm-tmp.{}.{op_index}",
        std::process::id()
    ));
    let _ = fs::remove_file(&staged);
    std::os::unix::fs::symlink(src, &staged)
        .with_context(|| format!("stage symlink for {}", dst.display()))?;
    Ok(staged)
}

fn commit_staged(staged: &Path, dst: &Path) -> Result<()> {
    if let Err(e) = crate::fs::atomic::swap_durable(staged, dst) {
        let _ = fs::remove_file(staged);
        return Err(e);
    }
    Ok(())
}
