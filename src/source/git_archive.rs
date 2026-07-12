//! Materializes a git commit into the source cache via `git archive`, with
//! hardened tar unpacking and a SHA-256 tree digest marker that detects
//! cache tampering.

use crate::cas::{EntryKind, TreeWalk, walk_tree};
use crate::fs::atomic;
use crate::fs::lock::lock_exclusive_with_feedback;
use crate::fs::util::{remove_path, rename_noreplace};
use crate::source::git_process::git_run;
use crate::source::git_url::source_dir_for_url_commit;
use anyhow::{Context, Result};
use sha2::{Digest, Sha256};
use std::ffi::OsStr;
use std::io::Read;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

pub fn materialize_commit(url: &str, cache: &Path, commit: &str) -> Result<PathBuf> {
    if commit.is_empty() || !commit.chars().all(|c| c.is_ascii_hexdigit()) {
        anyhow::bail!("commit SHA must be hex digits: {commit:?}");
    }
    let dest = source_dir_for_url_commit(url, commit);
    let parent = dest.parent().expect("source path always has a parent");
    std::fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    let lock_path = parent.join(format!(".{commit}.malm-materialize.lock"));
    let lock = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(&lock_path)
        .with_context(|| format!("open materialization lock {}", lock_path.display()))?;
    lock_exclusive_with_feedback(&lock, "source materialization lock")?;
    let marker = parent.join(format!(".{commit}.malm-tree-sha256"));

    if cached_tree_is_intact(&dest, &marker) {
        return Ok(dest);
    }
    if std::fs::symlink_metadata(&dest).is_ok() {
        remove_path(&dest)
            .with_context(|| format!("remove invalid cached source {}", dest.display()))?;
    }
    if std::fs::symlink_metadata(&marker).is_ok() {
        remove_path(&marker)
            .with_context(|| format!("remove invalid cache marker {}", marker.display()))?;
    }

    let tarball = tempfile::Builder::new()
        .prefix("malm-archive-")
        .suffix(".tar")
        .tempfile_in(parent)
        .context("create archive temp file")?;
    git_run(&[
        OsStr::new("-C"),
        cache.as_os_str(),
        OsStr::new("archive"),
        OsStr::new("--format=tar"),
        OsStr::new("-o"),
        tarball.path().as_os_str(),
        OsStr::new(commit),
    ])
    .with_context(|| format!("git archive {commit}"))?;

    let staging = tempfile::Builder::new()
        .prefix(".malm-source-stage-")
        .tempdir_in(parent)
        .context("create source staging dir")?;
    unpack_repo_tar(tarball.path(), staging.path())
        .with_context(|| format!("unpack archive for {commit}"))?;

    let staging_path = staging.keep();
    match rename_noreplace(&staging_path, &dest) {
        Ok(()) => {
            let digest = tree_digest(&dest)?;
            // Publish the digest only after the complete staged tree is renamed.
            atomic::write(&marker, digest)?;
            Ok(dest)
        }
        Err(e) => {
            let _ = std::fs::remove_dir_all(&staging_path);
            Err(e).with_context(|| format!("install source tree {}", dest.display()))
        }
    }
}

fn cached_tree_is_intact(dest: &Path, marker: &Path) -> bool {
    if !std::fs::symlink_metadata(dest).is_ok_and(|meta| meta.file_type().is_dir())
        || !std::fs::symlink_metadata(marker).is_ok_and(|meta| meta.file_type().is_file())
    {
        return false;
    }
    let Ok(expected) = std::fs::read_to_string(marker) else {
        return false;
    };
    tree_digest(dest).is_ok_and(|actual| actual == expected.trim())
}

// Field set and 0x00/0xff separators are the on-disk cache contract;
// changing either invalidates every cached source.
fn tree_digest(root: &Path) -> Result<String> {
    let entries = walk_tree(
        root,
        TreeWalk {
            include_root: true,
            skip_top_level_git: false,
            tolerate_special: false,
        },
    )?;

    let mut hasher = Sha256::new();
    for entry in entries {
        hasher.update(entry.rel.as_os_str().as_bytes());
        hasher.update([0]);
        hasher.update(entry.mode().to_le_bytes());
        match entry.kind {
            EntryKind::Dir => hasher.update(b"d"),
            EntryKind::Symlink => {
                hasher.update(b"l");
                hasher.update(std::fs::read_link(&entry.abs)?.as_os_str().as_bytes());
            }
            EntryKind::File => {
                hasher.update(b"f");
                let mut file = std::fs::File::open(&entry.abs)?;
                let mut buffer = [0_u8; 64 * 1024];
                loop {
                    let read = file.read(&mut buffer)?;
                    if read == 0 {
                        break;
                    }
                    hasher.update(&buffer[..read]);
                }
            }
            EntryKind::Other => {
                anyhow::bail!(
                    "cached source contains unsupported file type: {}",
                    entry.abs.display()
                );
            }
        }
        hasher.update([0xff]);
    }
    Ok(hex::encode(hasher.finalize()))
}

const MAX_REPO_ENTRIES: u64 = 200_000;
const MAX_REPO_BYTES: u64 = 1024 * 1024 * 1024;
const MAX_REPO_FILE_BYTES: u64 = 256 * 1024 * 1024;
const MAX_REPO_DEPTH: usize = 64;

fn unpack_repo_tar(tarball: &Path, dst: &Path) -> Result<()> {
    use std::path::Component;

    std::fs::create_dir_all(dst).with_context(|| format!("create {}", dst.display()))?;
    let file =
        std::fs::File::open(tarball).with_context(|| format!("open {}", tarball.display()))?;
    let mut archive = tar::Archive::new(file);
    archive.set_overwrite(true);

    let mut total: u64 = 0;
    let mut count: u64 = 0;
    for entry in archive.entries().context("read repo archive")? {
        let mut entry = entry.context("read repo archive entry")?;
        let path = entry
            .path()
            .context("read repo archive entry path")?
            .into_owned();

        if path.is_absolute()
            || path
                .components()
                .any(|c| matches!(c, Component::ParentDir | Component::Prefix(_)))
        {
            anyhow::bail!("repo archive contains unsafe path: {}", path.display());
        }
        let out = dst.join(&path);
        if entry.header().entry_type() == tar::EntryType::Link {
            anyhow::bail!("repo archive contains a hardlink entry: {}", path.display());
        }
        if entry.header().entry_type() == tar::EntryType::Symlink {
            let link_target = entry
                .link_name()
                .with_context(|| format!("read symlink target {}", path.display()))?
                .ok_or_else(|| {
                    anyhow::anyhow!("symlink entry {} has no link name", path.display())
                })?
                .into_owned();
            let link_parent = out.parent().unwrap_or(dst);
            if crate::paths::symlink_target_escapes(&link_target, link_parent, dst) {
                anyhow::bail!(
                    "repo archive contains symlink with unsafe target: {}",
                    path.display()
                );
            }
        }
        if let Ok(mode) = entry.header().mode()
            && mode & 0o7000 != 0
        {
            anyhow::bail!(
                "repo archive contains setuid/setgid/sticky entry: {}",
                path.display()
            );
        }
        if path.components().count() > MAX_REPO_DEPTH {
            anyhow::bail!("repo archive path is too deeply nested: {}", path.display());
        }

        count += 1;
        if count > MAX_REPO_ENTRIES {
            anyhow::bail!("repository has too many files (max {MAX_REPO_ENTRIES})");
        }
        let size = entry.header().size().unwrap_or(0);
        if size > MAX_REPO_FILE_BYTES {
            anyhow::bail!(
                "repository file exceeds {MAX_REPO_FILE_BYTES} bytes: {}",
                path.display()
            );
        }
        total = total.saturating_add(size);
        if total > MAX_REPO_BYTES {
            anyhow::bail!("repository unpacks to more than {MAX_REPO_BYTES} bytes");
        }

        if let Some(parent) = out.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("create {}", parent.display()))?;
        }
        entry
            .unpack(&out)
            .with_context(|| format!("unpack {}", out.display()))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{cached_tree_is_intact, tree_digest};
    use std::os::unix::fs::symlink;

    #[test]
    fn intact_requires_a_real_dir_and_a_matching_digest() {
        let tmp = tempfile::tempdir().unwrap();
        let dest = tmp.path().join("commit");
        let marker = tmp.path().join(".commit.malm-tree-sha256");

        assert!(!cached_tree_is_intact(&dest, &marker));

        std::fs::create_dir_all(&dest).unwrap();
        assert!(!cached_tree_is_intact(&dest, &marker));

        std::fs::write(dest.join("file"), b"contents").unwrap();
        std::fs::write(&marker, tree_digest(&dest).unwrap()).unwrap();
        assert!(cached_tree_is_intact(&dest, &marker));

        std::fs::write(dest.join("file"), b"tampered").unwrap();
        assert!(!cached_tree_is_intact(&dest, &marker));

        std::fs::write(dest.join("file"), b"contents").unwrap();
        assert!(cached_tree_is_intact(&dest, &marker));

        let link = tmp.path().join("link");
        let link_marker = tmp.path().join(".link.marker");
        symlink(&dest, &link).unwrap();
        std::fs::write(&link_marker, "x").unwrap();
        assert!(!cached_tree_is_intact(&link, &link_marker));

        let dir_marker = tmp.path().join(".dir.marker");
        std::fs::create_dir(&dir_marker).unwrap();
        assert!(!cached_tree_is_intact(&dest, &dir_marker));
    }
}
