//! Builds asset payloads in the CAS, then places them atomically with backup
//! and failure recovery.

use crate::assets::{ArchiveFormat, AssetDeclaration, download_archive, extract_archive};
use crate::cas::{
    asset_archive_object, asset_payload_object, cached_asset_payload, object_present, objects_dir,
    record_asset_payload, store_blob, store_tree, tree_hash,
};
use crate::execution::captured_identity;
use crate::execution::session::ApplySession;
use crate::fs::inspect::PathIdentity;
use crate::fs::util::{copy_recursive, make_tree_removable, move_managed_tree, remove_path};
use crate::output::display::format_short_path;
use crate::state::transaction::{OperationStatus, PathKind, PreviousState};
use anyhow::{Context, Result};
use owo_colors::OwoColorize;
use std::fs;
use std::io;
use std::os::unix::fs::MetadataExt;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

pub(super) struct AssetInstall<'a> {
    pub name: &'a str,
    pub url: &'a str,
    pub dst: &'a Path,
    pub sha256: &'a Option<String>,
    pub refresh_font_cache: bool,
    pub declaration: &'a Option<AssetDeclaration>,
}

/// Install a prefetched asset payload at its destination. The payload must
/// already be present in the CAS (see `prefetch::prefetch_assets`).
///
/// With `merge_entries` (every top-level payload entry is a directory), each
/// entry is placed as its own managed tree at `dst/<entry>` so several assets
/// can extract into one shared parent (themes, icons, fonts). Without it the
/// whole payload is placed at `dst` as a single tree.
pub(super) fn execute_asset_install(
    request: AssetInstall<'_>,
    payload_object: &Path,
    merge: Option<&[String]>,
    session: &mut ApplySession,
) -> Result<()> {
    let archive_sha256 = request.sha256.as_ref().map(|s| s.to_ascii_lowercase());
    place_payload(
        request.name,
        request.url,
        payload_object,
        archive_sha256,
        request.dst,
        merge,
        request.refresh_font_cache,
        request.declaration,
        session,
    )
}

/// Materialize a payload as one managed tree per top-level directory when
/// `merge` is set, or as one tree at `dst` otherwise. Install and restore share
/// this path so a mergeable payload never replaces its shared parent.
#[allow(clippy::too_many_arguments)]
pub(super) fn place_payload(
    name: &str,
    url: &str,
    payload_object: &Path,
    archive_sha256: Option<String>,
    dst: &Path,
    merge: Option<&[String]>,
    refresh_font_cache: bool,
    declaration: &Option<AssetDeclaration>,
    session: &mut ApplySession,
) -> Result<()> {
    let Some(entries) = merge else {
        return materialize_asset(
            MaterializeAsset {
                name,
                url,
                payload_object,
                archive_sha256,
                dst,
                refresh_font_cache,
                declaration,
            },
            session,
        );
    };

    for entry in entries {
        let entry_object = entry_payload_object(payload_object, entry)
            .with_context(|| format!("stage payload entry `{entry}` for asset '{name}'"))?;
        materialize_asset(
            MaterializeAsset {
                name,
                url,
                payload_object: &entry_object,
                archive_sha256: archive_sha256.clone(),
                dst: &dst.join(entry),
                refresh_font_cache: false,
                declaration,
            },
            session,
        )?;
    }
    if refresh_font_cache {
        refresh_font_cache_best_effort();
    }
    Ok(())
}

/// Store one top-level directory as a content-addressed tree. Its basename is
/// the tree hash, matching whole-payload ownership, verification, and rollback.
fn entry_payload_object(payload_object: &Path, entry: &str) -> Result<PathBuf> {
    let source = payload_object.join(entry);
    let hash = tree_hash(&source).with_context(|| format!("hash {}", source.display()))?;
    let object = asset_payload_object(&hash)?;
    store_tree(&source, &object).with_context(|| format!("store {}", object.display()))?;
    Ok(object)
}

/// Download or reuse, verify, extract, and store a payload in the CAS without
/// touching the target filesystem.
pub(super) fn build_asset_payload_object(
    name: &str,
    url: &str,
    sha256: &Option<String>,
    format: ArchiveFormat,
    allow_ssrf: bool,
) -> Result<PathBuf> {
    let mut _temp_archive: Option<tempfile::TempPath> = None;

    let archive_path: PathBuf = if let Some(sha) = sha256 {
        let archive_id = archive_object_id(sha);
        let archive_object = asset_archive_object(&archive_id)?;
        if !object_present(&archive_object, false)? {
            let tmp = download_archive(name, url, format, Some(sha.as_str()), allow_ssrf)?;
            store_blob(&tmp, &archive_object)
                .with_context(|| format!("store archive object for {name}"))?;
        }
        // With a sha we can reuse both the cached archive and the
        // archive->payload index; without one every install re-downloads.
        if let Some(payload) = cached_asset_payload(&archive_id, format.extension())? {
            return Ok(payload);
        }
        archive_object
    } else {
        let tmp = download_archive(name, url, format, None, allow_ssrf)?;
        let path = tmp.to_path_buf();
        _temp_archive = Some(tmp);
        path
    };

    let staging = tempfile::Builder::new()
        .prefix(".malm-asset-extract-")
        .tempdir_in(staging_base()?)
        .context("create asset extraction staging dir")?;
    extract_archive(&archive_path, format, staging.path())
        .with_context(|| format!("extract archive for {name}"))?;

    let payload_hash =
        tree_hash(staging.path()).with_context(|| format!("hash extracted payload for {name}"))?;
    let payload_object = asset_payload_object(&payload_hash)?;
    store_tree(staging.path(), &payload_object)
        .with_context(|| format!("store payload object for {name}"))?;

    if let Some(sha) = sha256
        && let Err(error) =
            record_asset_payload(&archive_object_id(sha), format.extension(), &payload_hash)
    {
        crate::warn_term!("warning: could not record asset payload index for {name}: {error:#}");
    }
    Ok(payload_object)
}

pub(super) struct MaterializeAsset<'a> {
    pub name: &'a str,
    pub url: &'a str,
    pub payload_object: &'a Path,
    pub archive_sha256: Option<String>,
    pub dst: &'a Path,
    pub refresh_font_cache: bool,
    pub declaration: &'a Option<AssetDeclaration>,
}

pub(super) fn materialize_asset(
    request: MaterializeAsset<'_>,
    session: &mut ApplySession,
) -> Result<()> {
    let MaterializeAsset {
        name,
        url,
        payload_object,
        archive_sha256,
        dst,
        refresh_font_cache,
        declaration,
    } = request;
    if !object_present(payload_object, true)? {
        anyhow::bail!(
            "asset payload for '{name}' is gone ({}); this transaction can no longer be applied",
            payload_object.display()
        );
    }

    let previous = match fs::symlink_metadata(dst) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => PreviousState::Missing,
        Err(e) => return Err(e).with_context(|| format!("stat {}", dst.display())),
        Ok(meta) => {
            let path_kind = PathKind::of(meta.file_type());
            PreviousState::Backed {
                backup: session.backup_path_for(dst),
                path_kind,
                original_mode: matches!(path_kind, PathKind::File | PathKind::Directory)
                    .then(|| meta.permissions().mode() & 0o7777),
                original_device: Some(meta.dev()),
                original_inode: Some(meta.ino()),
            }
        }
    };
    let expected_identity = match &previous {
        PreviousState::Backed { .. } => Some(
            PathIdentity::capture(dst)
                .with_context(|| format!("capture identity for {}", dst.display()))?,
        ),
        _ => None,
    };

    let op_index = session.journal_asset_started(
        name.to_owned(),
        url.to_owned(),
        dst.to_path_buf(),
        payload_object.to_path_buf(),
        archive_sha256.clone(),
        declaration.clone(),
        previous.clone(),
    )?;

    let mut placed = false;
    let mut result = (|| -> Result<()> {
        if let PreviousState::Backed { backup, .. } = &previous {
            backup_existing_destination(
                dst,
                backup,
                captured_identity(expected_identity.as_ref(), dst)?,
            )?;
            let target_str = format_short_path(dst);
            println!("  {} backed up {}", "!".yellow().bold(), target_str);
        }

        materialize_payload(payload_object, dst)?;
        placed = true;

        if refresh_font_cache {
            refresh_font_cache_best_effort();
        }

        let target_str = format_short_path(dst);
        println!("  {}  {}", "✓".green().bold(), target_str);
        Ok(())
    })();

    // If placement started, remove it before restoring the backup. Otherwise,
    // only restore the backup.
    if result.is_err() {
        let cleanup = match &previous {
            PreviousState::Backed { backup, .. } => {
                restore_asset_backup_after_failed_install(dst, backup, placed)
            }
            PreviousState::Missing
            | PreviousState::Symlink { .. }
            | PreviousState::BrokenSymlink { .. } => {
                if placed {
                    remove_partial_install(dst)
                } else {
                    Ok(())
                }
            }
        };
        if let Err(cleanup_err) = cleanup {
            result = result.with_context(|| {
                format!(
                    "also failed to clean up asset destination {} after a failed install: {cleanup_err:#}",
                    dst.display()
                )
            });
        }
    }

    session.mark_operation(
        op_index,
        if result.is_ok() {
            OperationStatus::Applied
        } else {
            OperationStatus::Failed
        },
    );

    result
}

/// Remove an installed asset, but only when its on-disk content still
/// hashes to the recorded CAS payload. A modified asset is never deleted.
///
/// The removal is a quarantine-rename, not an in-place delete: the tree is
/// atomically renamed into the transaction's backups dir and re-verified
/// *there*, so content swapped in after the pre-check can never be deleted
/// (it is moved back instead). The quarantined tree also gives rollback the
/// exact removed bytes; the CAS payload remains the fallback.
pub(super) fn execute_asset_remove(
    name: &str,
    dst: &Path,
    payload: &Path,
    session: &mut ApplySession,
) -> Result<()> {
    let (original_mode, original_device, original_inode) = match fs::symlink_metadata(dst) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e).with_context(|| format!("stat {}", dst.display())),
        Ok(metadata) => (
            metadata.permissions().mode() & 0o7777,
            metadata.dev(),
            metadata.ino(),
        ),
    };

    let expected = payload
        .file_name()
        .and_then(|leaf| leaf.to_str())
        .with_context(|| format!("asset payload {} has no object id", payload.display()))?;
    let actual = tree_hash(dst)
        .with_context(|| format!("hash installed asset '{name}' at {}", dst.display()))?;
    if actual != expected {
        anyhow::bail!(
            "refusing to remove asset '{name}' at {}: content changed since installation",
            dst.display()
        );
    }
    if !object_present(payload, true)? {
        anyhow::bail!(
            "refusing to remove asset '{name}' at {}: its payload {} is gone from the store, \
             so the removal could not be rolled back",
            dst.display(),
            payload.display()
        );
    }

    let quarantine = session.backup_path_for(dst);
    let op_index = session.journal_remove_asset_started(
        name.to_owned(),
        dst.to_path_buf(),
        payload.to_path_buf(),
        quarantine.clone(),
        Some(original_mode),
        Some(original_device),
        Some(original_inode),
    )?;

    let result = quarantine_asset(name, dst, &quarantine, expected);
    session.mark_operation(
        op_index,
        if result.is_ok() {
            OperationStatus::Applied
        } else {
            OperationStatus::Failed
        },
    );
    if result.is_ok() {
        println!(
            "  {} removed {}",
            "✓".green().bold(),
            format_short_path(dst)
        );
    }
    result
}

/// Rename `dst` into the transaction-local quarantine and verify the
/// captured tree still matches the expected object id; a mismatch (content
/// swapped after the pre-check) moves it back untouched.
fn quarantine_asset(name: &str, dst: &Path, quarantine: &Path, expected: &str) -> Result<()> {
    move_managed_tree(dst, quarantine, None)
        .with_context(|| format!("quarantine installed asset {}", dst.display()))?;
    crate::failpoint!("asset.remove.after_quarantine");
    let captured =
        tree_hash(quarantine).with_context(|| format!("hash quarantined asset '{name}'"))?;
    if captured != expected {
        move_managed_tree(quarantine, dst, None).with_context(|| {
            format!(
                "restore swapped content to {} (it remains in {})",
                dst.display(),
                quarantine.display()
            )
        })?;
        anyhow::bail!(
            "refusing to remove asset '{name}' at {}: content changed during removal",
            dst.display()
        );
    }
    Ok(())
}

fn archive_object_id(sha256: &str) -> String {
    format!("sha256-{}", sha256.to_ascii_lowercase())
}

fn staging_base() -> Result<PathBuf> {
    let base = objects_dir();
    fs::create_dir_all(&base).with_context(|| format!("create {}", base.display()))?;
    Ok(base)
}

fn materialize_payload(payload_object: &Path, dst: &Path) -> Result<()> {
    if let Some(parent) = dst.parent().filter(|p| !p.as_os_str().is_empty()) {
        fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    }

    let staged = staged_path(dst);
    let _ = remove_path(&staged);

    if let Err(e) = copy_recursive(payload_object, &staged) {
        let _ = remove_path(&staged);
        return Err(e).with_context(|| format!("stage asset payload for {}", dst.display()));
    }
    // Sync the staged files before exposing the tree at `dst`, then sync the
    // destination directory so the rename survives a crash.
    if let Err(e) = crate::fs::atomic::place_tree_durable(&staged, dst) {
        let _ = remove_path(&staged);
        return Err(e).with_context(|| format!("atomically place {}", dst.display()));
    }
    Ok(())
}

fn staged_path(dst: &Path) -> PathBuf {
    let name = dst.file_name().unwrap_or_default().to_string_lossy();
    dst.with_file_name(format!(".{name}.malm-asset-tmp.{}", std::process::id()))
}

pub(super) fn backup_existing_destination(
    dst: &Path,
    backup: &Path,
    expected_identity: &PathIdentity,
) -> Result<()> {
    if let Some(parent) = backup.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("create backup dir {}", parent.display()))?;
    }
    expected_identity.ensure_unchanged(dst)?;
    move_managed_tree(dst, backup, None).with_context(|| format!("back up {}", dst.display()))
}

fn remove_partial_install(dst: &Path) -> Result<()> {
    if fs::symlink_metadata(dst).is_ok() {
        make_tree_removable(dst)?;
        remove_path(dst)
            .with_context(|| format!("remove partial asset install {}", dst.display()))?;
    }
    Ok(())
}

pub(super) fn restore_asset_backup_after_failed_install(
    dst: &Path,
    backup: &Path,
    remove_malm_placement: bool,
) -> Result<()> {
    match fs::symlink_metadata(backup) {
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            // The backup rename can fail before touching `dst` (for example,
            // when its parent is not writable). In that state the original is
            // already where rollback wants it, so there is nothing to restore.
            if !remove_malm_placement && fs::symlink_metadata(dst).is_ok() {
                return Ok(());
            }
            anyhow::bail!(
                "cannot restore {}: backup {} is missing",
                dst.display(),
                backup.display()
            );
        }
        Err(error) => {
            return Err(error).with_context(|| format!("inspect backup {}", backup.display()));
        }
    }

    if remove_malm_placement && fs::symlink_metadata(dst).is_ok() {
        make_tree_removable(dst)?;
        remove_path(dst)
            .with_context(|| format!("remove partial asset install {}", dst.display()))?;
    }

    let name = dst.file_name().unwrap_or_default().to_string_lossy();
    let staged = dst.with_file_name(format!(".{name}.malm-asset-restore.{}", std::process::id()));
    let _ = remove_path(&staged);
    copy_recursive(backup, &staged)
        .with_context(|| format!("stage previous asset destination {}", dst.display()))?;
    if let Err(error) = crate::fs::atomic::place_tree_durable(&staged, dst) {
        let _ = remove_path(&staged);
        anyhow::bail!(
            "refusing to replace a concurrent occupant at {}; backup retained at {}: {error:#}",
            dst.display(),
            backup.display()
        );
    }
    make_tree_removable(backup)?;
    remove_path(backup).with_context(|| format!("remove restored backup {}", backup.display()))?;
    // The backup is gone; sync its directory so the removal is durable.
    crate::fs::atomic::sync_parent_dir(backup)?;

    let target_str = format_short_path(dst);
    println!("  {} restored {}", "!".yellow().bold(), target_str);
    Ok(())
}

/// Refresh the fontconfig cache after installing font assets.
///
/// `fc-cache` is looked up in fixed system locations only, never via `$PATH`:
/// the `refresh-font-cache` flag is controllable by a remote config, and a
/// writable PATH entry (e.g. `~/.local/bin`) could otherwise turn that flag
/// into execution of an attacker-placed binary. Failures are reported as
/// warnings, not apply failures. The asset is already installed, and
/// a missing/stale font cache is recoverable by the user.
fn refresh_font_cache_best_effort() {
    for candidate in ["/usr/bin/fc-cache", "/bin/fc-cache"] {
        match std::process::Command::new(candidate).arg("-f").status() {
            Ok(status) if status.success() => return,
            Ok(status) => {
                crate::warn_term!(
                    "warning: fc-cache exited with {status}; font cache may be stale"
                );
                return;
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
            Err(e) => {
                crate::warn_term!("warning: could not run fc-cache at {candidate}: {e}");
                return;
            }
        }
    }
    crate::warn_term!("warning: fc-cache not found in /usr/bin or /bin; font cache not refreshed");
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    /// The TOCTOU guard: content swapped in after the pre-check hash must
    /// never be deleted. It is quarantined, detected, and moved back.
    #[test]
    fn asset_remove_does_not_delete_concurrent_replacement() {
        let dir = tempfile::tempdir().unwrap();
        let dst = dir.path().join("asset");
        fs::create_dir_all(&dst).unwrap();
        fs::write(dst.join("swapped-in"), b"user data, not ours").unwrap();
        fs::set_permissions(&dst, fs::Permissions::from_mode(0o700)).unwrap();

        let quarantine = dir.path().join("backups/asset");
        let err = quarantine_asset("demo", &dst, &quarantine, "sha256-notthecontent")
            .expect_err("mismatched content must refuse removal");
        assert!(
            err.to_string().contains("content changed during removal"),
            "unexpected error: {err:#}"
        );
        assert_eq!(
            fs::read(dst.join("swapped-in")).unwrap(),
            b"user data, not ours",
            "the replacement is restored untouched"
        );
        assert_eq!(
            fs::symlink_metadata(&dst).unwrap().permissions().mode() & 0o777,
            0o700,
            "the replacement mode is restored untouched"
        );
        assert!(
            fs::symlink_metadata(&quarantine).is_err(),
            "nothing is left behind in quarantine"
        );
    }

    #[test]
    fn asset_remove_quarantines_matching_content() {
        let dir = tempfile::tempdir().unwrap();
        let dst = dir.path().join("asset");
        fs::create_dir_all(&dst).unwrap();
        fs::write(dst.join("file"), b"payload").unwrap();
        let expected = tree_hash(&dst).unwrap();

        let quarantine = dir.path().join("backups/asset");
        quarantine_asset("demo", &dst, &quarantine, &expected).unwrap();

        assert!(fs::symlink_metadata(&dst).is_err(), "destination removed");
        assert_eq!(
            fs::read(quarantine.join("file")).unwrap(),
            b"payload",
            "the exact bytes survive in quarantine"
        );
    }

    #[test]
    fn failed_backup_without_backup_leaf_leaves_original_in_place() {
        let dir = tempfile::tempdir().unwrap();
        let dst = dir.path().join("asset");
        fs::create_dir(&dst).unwrap();
        fs::write(dst.join("original"), b"precious").unwrap();
        let backup = dir.path().join("backups/asset");

        restore_asset_backup_after_failed_install(&dst, &backup, false).unwrap();

        assert_eq!(fs::read(dst.join("original")).unwrap(), b"precious");
        assert!(fs::symlink_metadata(&backup).is_err());
    }

    #[test]
    fn readonly_asset_root_can_be_replaced_from_writable_parent() {
        let dir = tempfile::tempdir().unwrap();
        let dst = dir.path().join("asset");
        fs::create_dir(&dst).unwrap();
        fs::write(dst.join("version"), b"old").unwrap();
        fs::set_permissions(&dst, fs::Permissions::from_mode(0o555)).unwrap();

        let payload = dir.path().join("payload");
        fs::create_dir(&payload).unwrap();
        fs::write(payload.join("version"), b"new").unwrap();
        fs::set_permissions(payload.join("version"), fs::Permissions::from_mode(0o444)).unwrap();
        fs::set_permissions(&payload, fs::Permissions::from_mode(0o555)).unwrap();

        let backup = dir.path().join("backups/asset");
        let identity = PathIdentity::capture(&dst).unwrap();
        backup_existing_destination(&dst, &backup, &identity).unwrap();
        materialize_payload(&payload, &dst).unwrap();

        assert_eq!(fs::read(dst.join("version")).unwrap(), b"new");
        assert_eq!(
            fs::symlink_metadata(&dst).unwrap().permissions().mode() & 0o222,
            0,
            "owned asset root remains sealed"
        );
        assert_eq!(fs::read(backup.join("version")).unwrap(), b"old");

        make_tree_removable(dir.path()).unwrap();
    }
}
