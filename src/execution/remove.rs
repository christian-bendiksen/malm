//! Removes a symlink only if an identity re-check confirms its recorded target.

use crate::execution::session::ApplySession;
use crate::fs::inspect::PathIdentity;
use crate::planning::plan::DeclarationOwner;
use crate::state::transaction::{OperationStatus, PreviousState};
use anyhow::{Context, Result};
use std::fs;
use std::path::{Path, PathBuf};

pub(super) fn execute(
    path: &Path,
    owner: &DeclarationOwner,
    expected_symlink_target: Option<&PathBuf>,
    session: &mut ApplySession,
) -> Result<()> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(error).with_context(|| format!("inspect {}", path.display()));
        }
    };
    if !metadata.file_type().is_symlink() {
        let found = if metadata.file_type().is_dir() {
            "a directory"
        } else if metadata.file_type().is_file() {
            "a regular file"
        } else {
            "a non-symlink"
        };
        anyhow::bail!(
            "refusing to remove {}; expected a symlink but found {found}",
            path.display(),
        );
    }
    let old_target = path
        .read_link()
        .with_context(|| format!("read link {}", path.display()))?;

    // If the link was re-pointed since planning, it is no longer ours to
    // remove.
    if let Some(expected) = expected_symlink_target
        && old_target.as_path() != expected.as_path()
    {
        anyhow::bail!(
            "refusing to remove {}; expected symlink target {}, actual {}",
            path.display(),
            expected.display(),
            old_target.display()
        );
    }

    let previous = PreviousState::Symlink { old_target };
    let expected_identity = PathIdentity::capture(path)
        .with_context(|| format!("capture identity for {}", path.display()))?;

    let op_index = session.journal_remove_started(owner.clone(), path.to_path_buf(), previous)?;

    let result = expected_identity
        .ensure_unchanged(path)
        .and_then(|()| fs::remove_file(path).with_context(|| format!("remove {}", path.display())));
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
