//! Serial plan execution and source resolution from state aliases to objects.

mod asset;
mod asset_restore;
pub mod executor;
mod prefetch;
mod remove;
mod session;
mod symlink;

use crate::fs::inspect::PathIdentity;
use anyhow::Result;
use std::path::{Path, PathBuf};

/// Resolves plan sources for on-disk inspection during execution.
///
/// Plans record sources through `states/<ns>/current`, but that alias changes
/// only at the end of a successful apply. During execution it still names the
/// previous snapshot, or nothing on the first apply, so source checks must
/// inspect the new object's root instead.
pub(crate) struct SourceResolver {
    alias_root: PathBuf,
    object_root: PathBuf,
}

impl SourceResolver {
    pub fn new(alias_root: PathBuf, object_root: PathBuf) -> Self {
        Self {
            alias_root,
            object_root,
        }
    }

    /// The path to inspect on disk for a plan source path.
    pub fn on_disk(&self, path: &Path) -> PathBuf {
        match path.strip_prefix(&self.alias_root) {
            Ok(rel) => self.object_root.join(rel),
            Err(_) => path.to_path_buf(),
        }
    }
}

fn captured_identity<'a>(
    identity: Option<&'a PathIdentity>,
    dst: &Path,
) -> Result<&'a PathIdentity> {
    identity.ok_or_else(|| {
        anyhow::anyhow!(
            "no identity was captured for existing destination {}",
            dst.display()
        )
    })
}
