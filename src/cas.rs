//! Content-addressed storage for blobs, source trees, and asset data.
//! Objects use deterministic SHA-256 identities and atomic placement after
//! staged contents have been synced.

use crate::fs::atomic;
use crate::fs::util::{copy_regular_file_preserving_metadata, is_already_exists, rename_noreplace};
use crate::paths::xdg_state_home;
use anyhow::{Context, Result};
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::Read;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

const HASH_PREFIX: &str = "sha256-";

pub fn objects_dir() -> PathBuf {
    xdg_state_home().join("malm/objects")
}

pub fn blobs_dir() -> PathBuf {
    objects_dir().join("blobs")
}

pub fn sources_dir() -> PathBuf {
    objects_dir().join("sources")
}

pub fn asset_archives_dir() -> PathBuf {
    objects_dir().join("assets/archives")
}

pub fn asset_payloads_dir() -> PathBuf {
    objects_dir().join("assets/payloads")
}

pub fn asset_index_dir() -> PathBuf {
    objects_dir().join("assets/index")
}

pub fn tree_blob_index_dir() -> PathBuf {
    objects_dir().join("tree-blobs")
}

fn tree_blob_index_path(object_id: &str) -> Result<PathBuf> {
    validate_object_id(object_id)?;
    Ok(tree_blob_index_dir().join(format!("{object_id}.json")))
}

pub fn record_tree_blobs(object_id: &str, blobs: &[String]) -> Result<()> {
    record_tree_blobs_in(&tree_blob_index_dir(), object_id, blobs)
}

fn record_tree_blobs_in(index_dir: &Path, object_id: &str, blobs: &[String]) -> Result<()> {
    validate_object_id(object_id)?;
    let path = index_dir.join(format!("{object_id}.json"));
    let json = serde_json::to_string(blobs).context("serialize tree blob index")?;
    atomic::write(&path, json).with_context(|| format!("write {}", path.display()))
}

pub fn recorded_tree_blobs(object_id: &str) -> Result<Option<Vec<String>>> {
    let path = tree_blob_index_path(object_id)?;
    let raw = match fs::read_to_string(&path) {
        Ok(raw) => raw,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error).with_context(|| format!("read {}", path.display())),
    };
    let Ok(blobs) = serde_json::from_str::<Vec<String>>(&raw) else {
        let _ = fs::remove_file(&path);
        return Ok(None);
    };
    if blobs.iter().any(|id| validate_object_id(id).is_err()) {
        let _ = fs::remove_file(&path);
        return Ok(None);
    }
    Ok(Some(blobs))
}

pub fn sources_object_dir(hash: &str) -> Result<PathBuf> {
    object_path(&sources_dir(), hash)
}

pub fn asset_archive_object(hash: &str) -> Result<PathBuf> {
    object_path(&asset_archives_dir(), hash)
}

pub fn asset_payload_object(hash: &str) -> Result<PathBuf> {
    object_path(&asset_payloads_dir(), hash)
}

fn object_path(base: &Path, hash: &str) -> Result<PathBuf> {
    validate_object_id(hash)?;
    Ok(base.join(hash))
}

pub fn validate_object_id(id: &str) -> Result<()> {
    let Some(hex) = id.strip_prefix(HASH_PREFIX) else {
        anyhow::bail!("object id must start with `{HASH_PREFIX}`: {id:?}");
    };
    if hex.len() != 64 || !hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        anyhow::bail!("object id must be `{HASH_PREFIX}<64 lowercase hex digits>`: {id:?}");
    }
    Ok(())
}

#[derive(Serialize, Deserialize)]
struct AssetIndexEntry {
    archive: String,
    format: String,
    payload: String,
}

fn asset_index_path(index_dir: &Path, archive_id: &str) -> Result<PathBuf> {
    validate_object_id(archive_id)?;
    Ok(index_dir.join(format!("{archive_id}.json")))
}

pub fn cached_asset_payload(archive_id: &str, format: &str) -> Result<Option<PathBuf>> {
    cached_asset_payload_in(
        &asset_index_dir(),
        &asset_payloads_dir(),
        archive_id,
        format,
    )
}

fn cached_asset_payload_in(
    index_dir: &Path,
    payloads_dir: &Path,
    archive_id: &str,
    format: &str,
) -> Result<Option<PathBuf>> {
    let path = asset_index_path(index_dir, archive_id)?;
    let raw = match fs::read_to_string(&path) {
        Ok(raw) => raw,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error).with_context(|| format!("read {}", path.display())),
    };
    let discard = |path: &Path| {
        let _ = fs::remove_file(path);
        Ok(None)
    };
    let entry: AssetIndexEntry = match serde_json::from_str(&raw) {
        Ok(entry) => entry,
        Err(_) => return discard(&path),
    };
    if entry.archive != archive_id || validate_object_id(&entry.payload).is_err() {
        return discard(&path);
    }
    if entry.format != format {
        return Ok(None);
    }
    let payload = object_path(payloads_dir, &entry.payload)?;
    if existing_object(&payload, true)? {
        Ok(Some(payload))
    } else {
        Ok(None)
    }
}

pub fn record_asset_payload(archive_id: &str, format: &str, payload_id: &str) -> Result<()> {
    record_asset_payload_in(&asset_index_dir(), archive_id, format, payload_id)
}

fn record_asset_payload_in(
    index_dir: &Path,
    archive_id: &str,
    format: &str,
    payload_id: &str,
) -> Result<()> {
    validate_object_id(payload_id)?;
    let path = asset_index_path(index_dir, archive_id)?;
    let entry = AssetIndexEntry {
        archive: archive_id.to_owned(),
        format: format.to_owned(),
        payload: payload_id.to_owned(),
    };
    let json = serde_json::to_string_pretty(&entry).context("serialize asset index entry")?;
    atomic::write(&path, json).with_context(|| format!("write {}", path.display()))
}

fn existing_object(path: &Path, expect_dir: bool) -> Result<bool> {
    let meta = match fs::symlink_metadata(path) {
        Ok(meta) => meta,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error).with_context(|| format!("stat {}", path.display())),
    };
    let file_type = meta.file_type();
    if file_type.is_symlink() {
        anyhow::bail!(
            "object {} is a symlink, not a content object",
            path.display()
        );
    }
    if expect_dir && !file_type.is_dir() {
        anyhow::bail!("object {} exists but is not a directory", path.display());
    }
    if !expect_dir && !file_type.is_file() {
        anyhow::bail!("object {} exists but is not a regular file", path.display());
    }
    Ok(true)
}

pub fn object_present(path: &Path, expect_dir: bool) -> Result<bool> {
    existing_object(path, expect_dir)
}

fn require_existing_object(path: &Path, expect_dir: bool) -> Result<()> {
    if existing_object(path, expect_dir)? {
        Ok(())
    } else {
        anyhow::bail!("no object at {} after a rename race", path.display());
    }
}

pub fn hash_file(path: &Path) -> Result<String> {
    let mut file = File::open(path).with_context(|| format!("open {}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let read = file
            .read(&mut buf)
            .with_context(|| format!("read {}", path.display()))?;
        if read == 0 {
            break;
        }
        hasher.update(&buf[..read]);
    }
    Ok(format!("{HASH_PREFIX}{}", hex::encode(hasher.finalize())))
}

/// Return sorted top-level directory names for a mergeable asset payload.
/// Payloads with loose files, symlinks, or no entries return `None` and own
/// the destination as one tree.
pub fn payload_merge_entries(payload_object: &Path) -> Result<Option<Vec<String>>> {
    let mut names = Vec::new();
    for entry in fs::read_dir(payload_object)
        .with_context(|| format!("read asset payload {}", payload_object.display()))?
    {
        let entry =
            entry.with_context(|| format!("read asset payload {}", payload_object.display()))?;
        if !entry
            .file_type()
            .with_context(|| format!("inspect payload entry {:?}", entry.file_name()))?
            .is_dir()
        {
            return Ok(None);
        }
        let name = entry
            .file_name()
            .into_string()
            .map_err(|raw| anyhow::anyhow!("asset payload entry has a non-UTF-8 name: {raw:?}"))?;
        names.push(name);
    }
    if names.is_empty() {
        return Ok(None);
    }
    names.sort();
    Ok(Some(names))
}

pub fn tree_hash(dir: &Path) -> Result<String> {
    let entries = sorted_entries(dir)?;
    // Hash file contents in parallel, then combine them in sorted order.
    let entries_ref: Vec<&Entry> = entries.iter().collect();
    let file_hashes = precompute_file_hashes(&entries_ref)?;
    let mut hasher = Sha256::new();
    for entry in &entries {
        hash_tree_entry(&mut hasher, &entry.rel, entry, &file_hashes)?;
    }
    Ok(format!("{HASH_PREFIX}{}", hex::encode(hasher.finalize())))
}

/// Hash regular files in parallel for the deterministic sequential combine.
fn precompute_file_hashes(entries: &[&Entry]) -> Result<HashMap<PathBuf, String>> {
    entries
        .par_iter()
        .filter(|e| e.kind == EntryKind::File)
        .map(|e| hash_file(&e.abs).map(|hash| (e.abs.clone(), hash)))
        .collect()
}

fn hash_tree_entry(
    hasher: &mut Sha256,
    rel: &Path,
    entry: &Entry,
    file_hashes: &HashMap<PathBuf, String>,
) -> Result<()> {
    let rel_bytes = rel.as_os_str().as_encoded_bytes();
    hasher.update((rel_bytes.len() as u64).to_le_bytes());
    hasher.update(rel_bytes);
    hasher.update([entry.kind_tag()]);
    // CAS trees are sealed by removing write bits. Hash the sealed mode so a
    // staged writable tree and its immutable stored representation have the
    // same content identity; execute and special bits remain significant.
    hasher.update(readonly_mode(entry.mode() & 0o7777).to_le_bytes());
    match entry.kind {
        EntryKind::Dir | EntryKind::Other => {}
        EntryKind::File => {
            let hash = file_hashes
                .get(&entry.abs)
                .with_context(|| format!("missing precomputed hash for {}", entry.abs.display()))?;
            hasher.update(hash.as_bytes());
        }
        EntryKind::Symlink => {
            let target = fs::read_link(&entry.abs)
                .with_context(|| format!("read link {}", entry.abs.display()))?;
            let bytes = target.as_os_str().as_encoded_bytes();
            hasher.update((bytes.len() as u64).to_le_bytes());
            hasher.update(bytes);
        }
    }
    Ok(())
}

pub fn store_blob(src_file: &Path, dest_object: &Path) -> Result<()> {
    if existing_object(dest_object, false)? {
        return Ok(());
    }
    let parent = dest_object
        .parent()
        .context("object path has no parent directory")?;
    fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    let staging = tempfile::Builder::new()
        .prefix(".malm-blob-")
        .tempfile_in(parent)
        .with_context(|| format!("stage blob in {}", parent.display()))?;
    copy_regular_file_preserving_metadata(src_file, staging.path())?;
    seal_file(staging.path())?;
    place_staged(staging.into_temp_path(), dest_object)
}

pub fn store_tree(src_dir: &Path, dest_object_dir: &Path) -> Result<()> {
    store_tree_with_blobs(
        src_dir,
        dest_object_dir,
        &blobs_dir(),
        &tree_blob_index_dir(),
    )
}

fn store_tree_with_blobs(
    src_dir: &Path,
    dest_object_dir: &Path,
    blobs: &Path,
    tree_blob_index: &Path,
) -> Result<()> {
    if existing_object(dest_object_dir, true)? {
        return Ok(());
    }
    let parent = dest_object_dir
        .parent()
        .context("object path has no parent directory")?;
    fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    let staging = tempfile::Builder::new()
        .prefix(".malm-tree-stage-")
        .tempdir_in(parent)
        .with_context(|| format!("stage tree in {}", parent.display()))?;
    let tree_blobs = materialize_into(src_dir, staging.path(), blobs)?;
    seal_tree(staging.path())?;
    atomic::sync_tree(staging.path())
        .with_context(|| format!("sync staged tree for {}", dest_object_dir.display()))?;

    let staging_path = staging.keep();
    match rename_noreplace(&staging_path, dest_object_dir) {
        Ok(()) => {
            if let Some(id) = dest_object_dir.file_name().and_then(|name| name.to_str()) {
                // Record the index only after the tree has been placed.
                record_tree_blobs_in(tree_blob_index, id, &tree_blobs)
                    .with_context(|| format!("record tree blobs for {id}"))?;
            }
            Ok(())
        }
        Err(error) if is_already_exists(&error) => {
            let result = require_existing_object(dest_object_dir, true);
            remove_sealed_tree(&staging_path);
            result
        }
        Err(error) => {
            remove_sealed_tree(&staging_path);
            Err(error).with_context(|| format!("install object {}", dest_object_dir.display()))
        }
    }
}

fn materialize_into(src_dir: &Path, dest_dir: &Path, blobs: &Path) -> Result<Vec<String>> {
    let mut tree_blobs = Vec::new();
    let mut dir_modes: Vec<(PathBuf, u32)> = Vec::new();
    for entry in sorted_entries(src_dir)? {
        let dest = dest_dir.join(&entry.rel);
        match entry.kind {
            EntryKind::Other => {}
            EntryKind::Dir => {
                fs::create_dir_all(&dest).with_context(|| format!("create {}", dest.display()))?;
                dir_modes.push((dest.clone(), entry.mode() & 0o7777));
            }
            EntryKind::Symlink => {
                let target = fs::read_link(&entry.abs)
                    .with_context(|| format!("read link {}", entry.abs.display()))?;
                if let Some(parent) = dest.parent() {
                    fs::create_dir_all(parent)?;
                }
                std::os::unix::fs::symlink(&target, &dest)
                    .with_context(|| format!("recreate symlink {}", dest.display()))?;
            }
            EntryKind::File => {
                let hash = intern_blob(&entry.abs, blobs)?;
                let blob = object_path(blobs, &hash)?;
                link_blob_into(&blob, &dest, entry.mode() & 0o7777)?;
                tree_blobs.push(hash);
            }
        }
    }
    for (dir, mode) in dir_modes.iter().rev() {
        fs::set_permissions(dir, fs::Permissions::from_mode(*mode))
            .with_context(|| format!("set mode on {}", dir.display()))?;
    }
    tree_blobs.sort();
    tree_blobs.dedup();
    Ok(tree_blobs)
}

fn intern_blob(path: &Path, blobs: &Path) -> Result<String> {
    let hash = hash_file(path)?;
    let dest = object_path(blobs, &hash)?;
    if existing_object(&dest, false)? {
        return Ok(hash);
    }
    fs::create_dir_all(blobs).with_context(|| format!("create {}", blobs.display()))?;
    let staging = tempfile::Builder::new()
        .prefix(".malm-blob-")
        .tempfile_in(blobs)
        .with_context(|| format!("stage blob in {}", blobs.display()))?;
    copy_regular_file_preserving_metadata(path, staging.path())?;
    seal_file(staging.path())?;
    place_staged(staging.into_temp_path(), &dest)?;
    Ok(hash)
}

fn place_staged(staged: tempfile::TempPath, dest: &Path) -> Result<()> {
    // Flush the staged contents before the rename makes the object visible;
    // recovery and checkout trust CAS objects to be durable once placed.
    atomic::sync_file(&staged)
        .with_context(|| format!("sync staged object for {}", dest.display()))?;
    match rename_noreplace(&staged, dest) {
        Ok(()) => {
            staged.keep().ok();
            if let Some(dir) = dest.parent() {
                atomic::sync_dir_best_effort(dir);
            }
            Ok(())
        }
        // Losing the rename race is fine as long as the winner left a valid
        // object.
        Err(error) if is_already_exists(&error) => require_existing_object(dest, false),
        Err(error) => Err(error).with_context(|| format!("install object {}", dest.display())),
    }
}

// Fallback chain: reflink, then copy. CAS objects must never share an inode:
// chmod or accidental writes through one tree must not mutate another object.
fn link_blob_into(blob: &Path, dest: &Path, mode: u32) -> Result<()> {
    if let Some(parent) = dest.parent() {
        fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    }

    if try_reflink(blob, dest) {
        fs::set_permissions(dest, fs::Permissions::from_mode(readonly_mode(mode)))
            .with_context(|| format!("set mode on {}", dest.display()))?;
        return Ok(());
    }

    copy_regular_file_preserving_metadata(blob, dest)?;
    fs::set_permissions(dest, fs::Permissions::from_mode(readonly_mode(mode)))
        .with_context(|| format!("set mode on {}", dest.display()))?;
    Ok(())
}

fn readonly_mode(mode: u32) -> u32 {
    mode & !0o222
}

fn seal_file(path: &Path) -> Result<()> {
    let mode = fs::symlink_metadata(path)
        .with_context(|| format!("stat staged object {}", path.display()))?
        .permissions()
        .mode()
        & 0o7777;
    fs::set_permissions(path, fs::Permissions::from_mode(readonly_mode(mode)))
        .with_context(|| format!("seal staged object {}", path.display()))
}

fn seal_tree(root: &Path) -> Result<()> {
    let mut directories = Vec::new();
    for entry in walk_tree(
        root,
        TreeWalk {
            include_root: true,
            skip_top_level_git: false,
            tolerate_special: false,
        },
    )? {
        match entry.kind {
            EntryKind::File => seal_file(&entry.abs)?,
            EntryKind::Dir => {
                let mode = entry.mode() & 0o7777;
                directories.push((entry.abs, mode));
            }
            EntryKind::Symlink => {}
            EntryKind::Other => unreachable!("special entries were rejected"),
        }
    }
    for (directory, mode) in directories.into_iter().rev() {
        fs::set_permissions(&directory, fs::Permissions::from_mode(readonly_mode(mode)))
            .with_context(|| format!("seal staged directory {}", directory.display()))?;
    }
    Ok(())
}

fn remove_sealed_tree(root: &Path) {
    let _ = make_tree_removable(root);
    let _ = fs::remove_dir_all(root);
}

fn make_tree_removable(root: &Path) -> Result<()> {
    let entries = walk_tree(
        root,
        TreeWalk {
            include_root: true,
            skip_top_level_git: false,
            tolerate_special: true,
        },
    )?;
    for entry in entries
        .into_iter()
        .filter(|entry| entry.kind == EntryKind::Dir)
    {
        fs::set_permissions(&entry.abs, fs::Permissions::from_mode(0o700))
            .with_context(|| format!("make CAS directory removable {}", entry.abs.display()))?;
    }
    Ok(())
}

/// Remove one unreachable CAS object. Tree objects are sealed read-only, so
/// GC must make their directories owner-accessible immediately before
/// deletion; this is never used for a reachable object.
pub fn remove_unreachable_object(path: &Path) -> Result<()> {
    let metadata =
        fs::symlink_metadata(path).with_context(|| format!("stat {}", path.display()))?;
    if metadata.file_type().is_symlink() {
        anyhow::bail!(
            "refusing to prune symlink at CAS object path {}",
            path.display()
        );
    }
    if metadata.is_dir() {
        make_tree_removable(path)?;
        fs::remove_dir_all(path).with_context(|| format!("prune {}", path.display()))
    } else if metadata.is_file() {
        fs::remove_file(path).with_context(|| format!("prune {}", path.display()))
    } else {
        anyhow::bail!(
            "refusing to prune special file at CAS object path {}",
            path.display()
        )
    }
}

fn try_reflink(src: &Path, dst: &Path) -> bool {
    let Ok(src_file) = File::open(src) else {
        return false;
    };
    let Ok(dst_file) = File::create(dst) else {
        return false;
    };
    match rustix::fs::ioctl_ficlone(&dst_file, &src_file) {
        Ok(()) => true,
        Err(_) => {
            drop(dst_file);
            let _ = fs::remove_file(dst);
            false
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum EntryKind {
    Dir,
    File,
    Symlink,
    Other,
}

pub(crate) struct Entry {
    pub rel: PathBuf,
    pub abs: PathBuf,
    pub kind: EntryKind,
    pub metadata: fs::Metadata,
}

impl Entry {
    fn kind_tag(&self) -> u8 {
        match self.kind {
            EntryKind::Dir => b'd',
            EntryKind::File => b'f',
            EntryKind::Symlink => b'l',
            EntryKind::Other => b'?',
        }
    }

    pub fn mode(&self) -> u32 {
        self.metadata.permissions().mode()
    }
}

#[derive(Clone, Copy)]
pub(crate) struct TreeWalk {
    pub include_root: bool,
    pub skip_top_level_git: bool,
    pub tolerate_special: bool,
}

pub(crate) fn walk_tree(dir: &Path, options: TreeWalk) -> Result<Vec<Entry>> {
    let min_depth = usize::from(!options.include_root);
    let mut entries = Vec::new();
    for entry in WalkDir::new(dir)
        .min_depth(min_depth)
        .sort_by_file_name()
        .into_iter()
        .filter_entry(|e| {
            !(options.skip_top_level_git && e.depth() == 1 && e.file_name() == ".git")
        })
    {
        let entry = entry.with_context(|| format!("walk {}", dir.display()))?;
        let abs = entry.path().to_path_buf();
        let rel = abs.strip_prefix(dir).unwrap_or(&abs).to_path_buf();
        let file_type = entry.file_type();
        let kind = if file_type.is_dir() {
            EntryKind::Dir
        } else if file_type.is_file() {
            EntryKind::File
        } else if file_type.is_symlink() {
            EntryKind::Symlink
        } else if options.tolerate_special {
            EntryKind::Other
        } else {
            anyhow::bail!("unsupported file type in tree: {}", abs.display());
        };
        let metadata = entry
            .metadata()
            .with_context(|| format!("stat {}", abs.display()))?;
        entries.push(Entry {
            rel,
            abs,
            kind,
            metadata,
        });
    }
    Ok(entries)
}

fn sorted_entries(dir: &Path) -> Result<Vec<Entry>> {
    walk_tree(
        dir,
        TreeWalk {
            include_root: false,
            skip_top_level_git: true,
            tolerate_special: false,
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::source::store::copy_source_repo;
    use std::os::unix::fs::{MetadataExt, symlink};

    #[test]
    fn composed_hash_matches_staged_tree_hash() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("staging");
        let repo = root.join("repo");
        let rendered = root.join("rendered");
        fs::create_dir_all(repo.join("nested")).unwrap();
        fs::create_dir_all(&rendered).unwrap();
        fs::write(repo.join("a.conf"), "alpha").unwrap();
        fs::write(repo.join("nested/b.conf"), "beta").unwrap();
        fs::write(rendered.join("out.rendered"), "rendered").unwrap();
        symlink("a.conf", repo.join("link")).unwrap();
        fs::set_permissions(repo.join("nested"), fs::Permissions::from_mode(0o700)).unwrap();

        let staged = tree_hash(&root).unwrap();
        let composed = tree_hash(&root).unwrap();
        assert_eq!(staged, composed);

        fs::write(repo.join("a.conf"), "changed").unwrap();
        let changed = tree_hash(&root).unwrap();
        assert_ne!(staged, changed);
    }

    #[test]
    fn copied_repo_hashes_like_the_source() {
        let tmp = tempfile::tempdir().unwrap();
        let source = tmp.path().join("source");
        fs::create_dir_all(source.join(".git")).unwrap();
        fs::create_dir_all(source.join("files")).unwrap();
        fs::write(source.join(".git/HEAD"), "ref").unwrap();
        fs::write(source.join("files/x"), "x").unwrap();
        fs::set_permissions(source.join("files"), fs::Permissions::from_mode(0o750)).unwrap();

        let copy = tmp.path().join("copy");
        copy_source_repo(&source, &copy).unwrap();

        assert!(!copy.join(".git").exists());
        assert_eq!(tree_hash(&source).unwrap(), tree_hash(&copy).unwrap());
        assert_eq!(tree_hash(&source).unwrap(), tree_hash(&copy).unwrap());
    }

    #[test]
    fn stored_tree_is_read_only_without_losing_executable_bits() {
        let tmp = tempfile::tempdir().unwrap();
        let source = tmp.path().join("source");
        fs::create_dir(&source).unwrap();
        let script = source.join("script");
        fs::write(&script, "#!/bin/sh\nexit 0\n").unwrap();
        fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();
        let hash = tree_hash(&source).unwrap();
        let object = tmp.path().join(&hash);
        let blobs = tmp.path().join("blobs");
        let tree_blob_index = tmp.path().join("tree-blobs");

        store_tree_with_blobs(&source, &object, &blobs, &tree_blob_index).unwrap();

        let mode = fs::metadata(object.join("script"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode & 0o222, 0, "stored files must not be writable");
        assert_ne!(mode & 0o111, 0, "stored scripts must remain executable");
        let blob = blobs.join(hash_file(&script).unwrap());
        assert_ne!(
            fs::metadata(blob).unwrap().ino(),
            fs::metadata(object.join("script")).unwrap().ino(),
            "tree files must not hardlink CAS blobs"
        );
        assert_eq!(tree_hash(&object).unwrap(), hash);
    }
}
