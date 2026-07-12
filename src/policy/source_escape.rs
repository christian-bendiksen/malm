//! Detects symlink sources that escape the snapshot and classifies their target.

use crate::paths::normalize_lexical;
use crate::policy::model::PolicyFindingKind;
use crate::policy::model::PolicySeverity;
use crate::policy::overrides::RemotePolicyOverrides;
use crate::{paths::starts_with_home, paths::strip_home_prefix};
use std::path::{Path, PathBuf};

pub(super) fn classify_external_source(
    src: &Path,
    _home: &Path,
    allow: RemotePolicyOverrides,
) -> Option<(
    PolicyFindingKind,
    PolicySeverity,
    &'static str,
    &'static str,
)> {
    match resolve_path_without_leaf_following(src) {
        Some(landing) if is_secret_store(&landing) => (!allow.secrets).then_some((
            PolicyFindingKind::CredentialStore,
            PolicySeverity::Block,
            "symlink source points into a credential store",
            "--allow-secrets",
        )),
        Some(landing) if starts_with_home(&landing) => Some((
            PolicyFindingKind::InHomeSymlinkSource,
            PolicySeverity::Notice,
            "symlink source is outside the repository but within your home directory",
            "",
        )),
        Some(_) => (!allow.external_symlink_sources).then_some((
            PolicyFindingKind::ExternalSymlinkSource,
            PolicySeverity::Block,
            "symlink source resolves outside your home directory",
            "--allow-external-symlink-sources",
        )),
        None => {
            let lexical = normalize_lexical(src);
            if starts_with_home(&lexical) {
                Some((
                    PolicyFindingKind::UnverifiableSymlink,
                    PolicySeverity::Notice,
                    "symlink source is currently broken or unverifiable, but within home directory",
                    "",
                ))
            } else {
                (!allow.external_symlink_sources).then_some((
                    PolicyFindingKind::UnverifiableSymlink,
                    PolicySeverity::Block,
                    "symlink source is broken and resolves outside your home directory",
                    "--allow-external-symlink-sources",
                ))
            }
        }
    }
}

// Fail closed: anything we cannot resolve counts as escaping.
pub fn source_escapes_source_root(src: &Path, source_root: &Path) -> bool {
    let Ok(source_root) = source_root.canonicalize() else {
        return true;
    };
    match resolve_path_without_leaf_following(src) {
        Some(resolved) => !resolved.starts_with(&source_root),
        None => true,
    }
}

fn is_secret_store(path: &Path) -> bool {
    let Some(rel) = strip_home_prefix(path) else {
        return false;
    };
    matches!(
        rel.components().next().and_then(|c| c.as_os_str().to_str()),
        Some(".ssh") | Some(".gnupg") | Some(".password-store")
    )
}

// The leaf is never followed: a source that IS a symlink stays
// unverifiable rather than being resolved through it.
fn resolve_path_without_leaf_following(path: &Path) -> Option<PathBuf> {
    let mut cursor = path;
    loop {
        match cursor.canonicalize() {
            Ok(real) => {
                let tail = path.strip_prefix(cursor).unwrap_or_else(|_| Path::new(""));
                return Some(normalize_lexical(&real.join(tail)));
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                match std::fs::symlink_metadata(cursor) {
                    Ok(meta) if meta.file_type().is_symlink() => return None,
                    _ => cursor = cursor.parent()?,
                }
            }
            Err(_) => return None,
        }
    }
}
