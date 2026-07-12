//! Path utilities: home/XDG resolution, tilde expansion, lexical
//! normalization, and repo-relative resolution with symlink hardening.

use std::path::{Component, Path, PathBuf};
use std::sync::OnceLock;

static HOME_DIR: OnceLock<PathBuf> = OnceLock::new();

/// Resolve and cache the user's home directory at process start.
///
/// XDG, tilde, and display helpers cannot return errors, so the CLI resolves
/// `$HOME` once while it can still report a useful failure.
pub fn init_home_dir() -> anyhow::Result<PathBuf> {
    let home = dirs::home_dir().ok_or_else(|| {
        anyhow::anyhow!("could not determine home directory; ensure $HOME is set")
    })?;
    let _ = HOME_DIR.set(home.clone());
    Ok(home)
}

pub fn home_dir() -> PathBuf {
    // Library callers may skip initialization; the CLI always resolves this up front.
    HOME_DIR.get().cloned().unwrap_or_else(|| {
        dirs::home_dir().expect("could not determine home directory; ensure $HOME is set")
    })
}

pub fn now_unix() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub fn home_dir_canonical() -> PathBuf {
    home_dir().canonicalize().unwrap_or_else(|_| home_dir())
}

/// Returns true if `path` is inside the user's home directory, checking both
/// the lexical ($HOME) and canonical (symlink-resolved) forms to handle
/// symlinked home directories correctly.
pub fn starts_with_home(path: &Path) -> bool {
    let home = home_dir();
    if path.starts_with(&home) {
        return true;
    }
    let canonical = home_dir_canonical();
    canonical != home && path.starts_with(&canonical)
}

/// Strips the home prefix from `path`, trying both lexical and canonical forms.
pub fn strip_home_prefix(path: &Path) -> Option<PathBuf> {
    let home = home_dir();
    if let Ok(rel) = path.strip_prefix(&home) {
        return Some(rel.to_path_buf());
    }
    let canonical = home_dir_canonical();
    if canonical != home
        && let Ok(rel) = path.strip_prefix(&canonical)
    {
        return Some(rel.to_path_buf());
    }
    None
}

pub fn xdg_config_home() -> PathBuf {
    std::env::var("XDG_CONFIG_HOME")
        .ok()
        .filter(|s| !s.is_empty())
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .unwrap_or_else(|| home_dir().join(".config"))
}

pub fn xdg_state_home() -> PathBuf {
    std::env::var("XDG_STATE_HOME")
        .ok()
        .filter(|s| !s.is_empty())
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .unwrap_or_else(|| home_dir().join(".local/state"))
}

pub fn expand_tilde(s: &str) -> PathBuf {
    match s.strip_prefix("~/") {
        Some(rest) => home_dir().join(rest),
        None if s == "~" => home_dir(),
        None => PathBuf::from(s),
    }
}

pub fn resolve_target_root(target: &str) -> anyhow::Result<PathBuf> {
    let root = normalize_lexical(&expand_tilde(target));
    if !root.is_absolute() {
        anyhow::bail!("config target must be an absolute or ~-relative path, got: {target:?}");
    }
    Ok(root)
}
pub fn normalize_lexical(path: &Path) -> PathBuf {
    let mut stack: Vec<Component<'_>> = Vec::new();
    for comp in path.components() {
        match comp {
            Component::CurDir => {}
            Component::ParentDir => match stack.last() {
                Some(Component::Normal(_)) => {
                    stack.pop();
                }
                Some(Component::RootDir) => {}
                _ => stack.push(Component::ParentDir),
            },
            other => stack.push(other),
        }
    }
    if stack.is_empty() {
        return PathBuf::from(".");
    }
    let mut out = PathBuf::new();
    for comp in stack {
        out.push(comp.as_os_str());
    }
    out
}

/// Returns `true` if a symlink `target` (relative or absolute) resolves outside
/// `root` when anchored at `link_parent`. Absolute targets always escape.
pub fn symlink_target_escapes(target: &Path, link_parent: &Path, root: &Path) -> bool {
    if target.is_absolute() {
        return true;
    }
    let resolved = normalize_lexical(&link_parent.join(target));
    !resolved.starts_with(root)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_lexical_empty_to_dot() {
        assert_eq!(normalize_lexical(Path::new("a/..")), PathBuf::from("."));
        assert_eq!(normalize_lexical(Path::new(".")), PathBuf::from("."));
    }

    #[test]
    fn normalize_lexical_resolves_parent_dirs() {
        assert_eq!(
            normalize_lexical(Path::new("/foo/bar/../baz")),
            PathBuf::from("/foo/baz")
        );
    }

    #[test]
    fn symlink_target_escapes_detects_absolute() {
        let root = Path::new("/tmp/repo");
        assert!(symlink_target_escapes(
            Path::new("/etc/passwd"),
            Path::new("/tmp/repo/dir"),
            root
        ));
    }

    #[test]
    fn symlink_target_escapes_detects_relative_escape() {
        let root = Path::new("/tmp/repo");
        assert!(symlink_target_escapes(
            Path::new("../../../etc/passwd"),
            Path::new("/tmp/repo/dir/subdir"),
            root
        ));
    }

    #[test]
    fn symlink_target_escapes_allows_in_tree_relative() {
        let root = Path::new("/tmp/repo");
        assert!(!symlink_target_escapes(
            Path::new("../sibling/file"),
            Path::new("/tmp/repo/dir"),
            root
        ));
    }

    #[test]
    fn symlink_target_escapes_allows_direct_child() {
        let root = Path::new("/tmp/repo");
        assert!(!symlink_target_escapes(
            Path::new("file.txt"),
            Path::new("/tmp/repo/dir"),
            root
        ));
    }
}
