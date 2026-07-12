//! Decides whether an asset's installed-check is satisfied. For untrusted
//! sources the probe walks each component and reports any symlink instead
//! of following it.

use std::path::{Path, PathBuf};

// Err(path) means "a symlink sits in the way" and is deliberately distinct
// from Ok(false) so the caller can refuse instead of reinstalling.
pub fn installed_check_satisfied(
    dst: &Path,
    check: &Path,
    untrusted: bool,
) -> Result<bool, PathBuf> {
    use std::fs::symlink_metadata;

    if !untrusted {
        return Ok(check.exists());
    }

    let rel = check.strip_prefix(dst).unwrap_or(Path::new(""));
    let has_subpath = rel.components().next().is_some();
    match symlink_metadata(dst) {
        Err(_) => return Ok(false),
        Ok(meta) if has_subpath && meta.file_type().is_symlink() => {
            return Err(dst.to_path_buf());
        }
        Ok(_) => {}
    }

    let mut cursor = dst.to_path_buf();
    for comp in rel.components() {
        cursor.push(comp);
        match symlink_metadata(&cursor) {
            Ok(meta) if meta.file_type().is_symlink() => return Err(cursor),
            Ok(_) => {}
            Err(_) => return Ok(false),
        }
    }
    Ok(true)
}
