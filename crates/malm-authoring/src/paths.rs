//! Lexical path helpers for the authoring evaluator.
//!
//! These helpers do not access the filesystem or environment.

use std::path::{Component, Path, PathBuf};

/// Removes `.` and folds `..` without accessing the filesystem.
pub(crate) fn normalize_lexical(path: &Path) -> PathBuf {
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
