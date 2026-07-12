//! Content-addressed source snapshots containing repository and rendered trees.

use crate::cas::{EntryKind, TreeWalk, sources_dir, validate_object_id, walk_tree};
use crate::fs::util::copy_regular_file_preserving_metadata;
use anyhow::{Context, Result};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct SourceSnapshot {
    id: String,
    root: PathBuf,
    repository: PathBuf,
    rendered: PathBuf,
}

impl SourceSnapshot {
    pub fn from_id(id: &str) -> Result<Self> {
        Self::from_base(&snapshot_store_dir(), id)
    }

    fn from_base(base: &Path, id: &str) -> Result<Self> {
        validate_object_id(id)?;
        let root = base.join(id);
        Ok(Self {
            id: id.to_owned(),
            repository: root.join("repo"),
            rendered: root.join("rendered"),
            root,
        })
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn repository(&self) -> &Path {
        &self.repository
    }

    pub fn rendered(&self) -> &Path {
        &self.rendered
    }

    pub fn require_on_disk(&self) -> Result<()> {
        let root_metadata = fs::symlink_metadata(&self.root)
            .with_context(|| format!("inspect source snapshot {}", self.root.display()))?;
        // Symlink checks are not redundant with is_dir(): a swapped store entry
        // must not redirect reads outside the snapshot.
        if !root_metadata.file_type().is_dir() || root_metadata.file_type().is_symlink() {
            anyhow::bail!(
                "source snapshot root is not a directory: {}",
                self.root.display()
            );
        }
        validate_snapshot_component(&self.root, &snapshot_store_dir(), "source snapshot")?;
        let metadata = fs::symlink_metadata(&self.repository).with_context(|| {
            format!("inspect snapshot repository {}", self.repository.display())
        })?;
        if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
            anyhow::bail!(
                "source snapshot repository is not a directory: {}",
                self.repository.display()
            );
        }
        let rendered_metadata = fs::symlink_metadata(&self.rendered)
            .with_context(|| format!("inspect snapshot rendered {}", self.rendered.display()))?;
        if !rendered_metadata.file_type().is_dir() || rendered_metadata.file_type().is_symlink() {
            anyhow::bail!(
                "source snapshot rendered tree is not a directory: {}",
                self.rendered.display()
            );
        }
        Ok(())
    }

    /// Re-hash a snapshot for explicit `--verify` and `fsck --verify-objects` checks.
    /// The CAS trusts objects after writing them, so normal reads skip this work.
    pub fn verify_content(&self) -> Result<()> {
        let actual = crate::cas::tree_hash(&self.root)
            .with_context(|| format!("hash source snapshot {}", self.root.display()))?;
        if actual != self.id {
            anyhow::bail!(
                "source snapshot {} is corrupt: contents hash to {actual}; \
                 re-run `malm apply` to rebuild it",
                self.id
            );
        }
        Ok(())
    }
}

pub fn snapshot_store_dir() -> PathBuf {
    sources_dir()
}

pub fn copy_source_repo(source_dir: &Path, dest_repo: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    fs::create_dir_all(dest_repo).with_context(|| format!("create {}", dest_repo.display()))?;
    let root_mode = fs::symlink_metadata(source_dir)
        .with_context(|| format!("stat {}", source_dir.display()))?
        .permissions()
        .mode();
    let mut directory_modes = Vec::new();

    for entry in walk_tree(
        source_dir,
        TreeWalk {
            include_root: false,
            skip_top_level_git: true,
            tolerate_special: false,
        },
    )? {
        let dest_path = dest_repo.join(&entry.rel);
        match entry.kind {
            EntryKind::Dir => {
                fs::create_dir_all(&dest_path)
                    .with_context(|| format!("create store dir: {}", dest_path.display()))?;
                fs::set_permissions(
                    &dest_path,
                    fs::Permissions::from_mode((entry.mode() & 0o7777) | 0o700),
                )
                .with_context(|| format!("set mode on {}", dest_path.display()))?;
                directory_modes.push((dest_path, entry.mode() & 0o7777));
            }
            EntryKind::File => {
                copy_regular_file_preserving_metadata(&entry.abs, &dest_path)
                    .with_context(|| format!("copy to store: {}", dest_path.display()))?;
            }
            EntryKind::Symlink => {
                let link_target = fs::read_link(&entry.abs)
                    .with_context(|| format!("read link {}", entry.abs.display()))?;
                let link_parent = dest_path.parent().unwrap_or(dest_repo);
                if crate::paths::symlink_target_escapes(&link_target, link_parent, dest_repo) {
                    anyhow::bail!(
                        "repo snapshot contains symlink with unsafe target: {}",
                        entry.abs.display()
                    );
                }
                std::os::unix::fs::symlink(&link_target, &dest_path).with_context(|| {
                    format!("recreate symlink in store: {}", dest_path.display())
                })?;
            }
            EntryKind::Other => {
                anyhow::bail!(
                    "unsupported file type in repo snapshot: {}",
                    entry.abs.display()
                );
            }
        }
    }
    for (path, mode) in directory_modes.into_iter().rev() {
        fs::set_permissions(&path, fs::Permissions::from_mode(mode))
            .with_context(|| format!("restore mode on {}", path.display()))?;
    }
    fs::set_permissions(dest_repo, fs::Permissions::from_mode(root_mode & 0o7777))
        .with_context(|| format!("restore mode on {}", dest_repo.display()))?;
    Ok(())
}

fn validate_snapshot_component(path: &Path, base: &Path, label: &str) -> Result<()> {
    let canonical_base = base
        .canonicalize()
        .with_context(|| format!("canonicalize snapshot store {}", base.display()))?;
    let canonical_path = path
        .canonicalize()
        .with_context(|| format!("canonicalize {label} {}", path.display()))?;
    if canonical_path.parent() != Some(canonical_base.as_path()) {
        anyhow::bail!("{} is outside the snapshot store", path.display());
    }
    Ok(())
}
