//! Hardens the state root before mutation. Trusted directories must not be
//! symlinks, must belong to the current user, and must not be writable by group
//! or other users.
//!
//! Child directories are opened descriptor-relative with `openat` and
//! `O_NOFOLLOW`, so validation never follows a symlinked child.

use crate::paths::xdg_state_home;
use anyhow::{Context, Result};
use rustix::fs::{FsWord, Mode, NFS_SUPER_MAGIC, OFlags, openat, statfs};
use std::fmt::Write as _;
use std::fs::File;
use std::path::{Path, PathBuf};

pub struct PreflightIssue {
    pub path: PathBuf,
    pub problem: String,
    pub remedy: String,
}

const MANAGED_SUBDIRS: [&str; 3] = ["states", "objects", "transactions"];

/// Verify the state root before mutation, creating missing directories with
/// mode 0700. Any security issue fails closed with a suggested fix.
pub fn preflight_mutating() -> Result<()> {
    let issues = scan_state_root(true)?;
    if issues.is_empty() {
        crate::state::format::ensure_current_for_mutation()?;
        return Ok(());
    }
    let mut message =
        String::from("refusing to touch Malm's state directory; it is not trustworthy:");
    for issue in &issues {
        let _ = write!(
            message,
            "\n  {}: {}\n    fix: {}",
            issue.path.display(),
            issue.problem,
            issue.remedy
        );
    }
    anyhow::bail!("{message}");
}

/// Inspect the state root and managed subtrees. When requested, create missing
/// directories with mode 0700 instead of reporting them.
pub fn scan_state_root(create_missing: bool) -> Result<Vec<PreflightIssue>> {
    let mut issues = Vec::new();

    let base = xdg_state_home();
    std::fs::create_dir_all(&base).with_context(|| format!("create {}", base.display()))?;
    let base_fd =
        File::open(&base).with_context(|| format!("open state base {}", base.display()))?;

    let root_path = base.join("malm");
    let Some(root_fd) = open_checked_dir(&base_fd, &base, "malm", create_missing, &mut issues)?
    else {
        return Ok(issues);
    };
    check_dir_security(&root_fd, &root_path, &mut issues);

    // Linux BSD flock is local to each NFS client. Two hosts could both acquire
    // this lock and corrupt shared state, so reject network filesystems.
    check_not_network_fs(&root_path, &mut issues);

    // The managed-subdirectory walk does not inspect loose root files such as
    // format.json, targets.json, and targets.lock. Reject any root symlink;
    // open_guard_file also protects the lock itself with O_NOFOLLOW.
    check_root_children(&root_path, &mut issues)?;

    for name in MANAGED_SUBDIRS {
        let path = root_path.join(name);
        let Some(fd) = open_checked_dir(&root_fd, &root_path, name, create_missing, &mut issues)?
        else {
            continue;
        };
        check_dir_security(&fd, &path, &mut issues);

        // Namespace records, transaction journals and backups, and materialized
        // CAS roots are all trusted state, so check their directories too.
        let depth = match name {
            "states" | "transactions" => 1,
            "objects" => 2,
            _ => 0,
        };
        check_children(&fd, &path, depth, &mut issues)?;
    }

    Ok(issues)
}

/// Reject known network filesystem types, where Linux BSD `flock` cannot
/// coordinate clients on different hosts.
fn check_not_network_fs(path: &Path, issues: &mut Vec<PreflightIssue>) {
    let Ok(stat) = statfs(path) else {
        return;
    };
    const CIFS_SMB_MAGIC: FsWord = 0xFF53_4D42;
    const CEPH_MAGIC: FsWord = 0x00C3_6400;
    const LUSTRE_MAGIC: FsWord = 0x0BD0_0BD0;
    let is_network = matches!(
        stat.f_type,
        NFS_SUPER_MAGIC | CIFS_SMB_MAGIC | CEPH_MAGIC | LUSTRE_MAGIC
    );
    if is_network {
        issues.push(PreflightIssue {
            path: path.to_path_buf(),
            problem:
                "is on a network filesystem (NFS/CIFS/Ceph/Lustre); Malm's process lock is not safe across network clients"
                    .to_owned(),
            remedy: "move XDG_STATE_HOME to a local filesystem (e.g. ~/.local/state on a local disk)"
                .to_owned(),
        });
    }
}

/// Reject symlinks directly under the Malm root.
///
/// The root and managed subdirectories are opened with
/// `O_NOFOLLOW | O_DIRECTORY`, but loose root files are outside that walk. A
/// symlink there, especially at `targets.lock`, must be rejected before the
/// state root is trusted.
fn check_root_children(root_path: &Path, issues: &mut Vec<PreflightIssue>) -> Result<()> {
    let entries = std::fs::read_dir(root_path)
        .with_context(|| format!("read malm root {}", root_path.display()))?;
    for entry in entries {
        let entry = entry.with_context(|| format!("read entry in {}", root_path.display()))?;
        let file_type = entry
            .file_type()
            .with_context(|| format!("inspect entry in {}", root_path.display()))?;
        if file_type.is_symlink() {
            let path = root_path.join(entry.file_name());
            issues.push(PreflightIssue {
                path: path.clone(),
                problem: "is a symlink inside the Malm state root".to_owned(),
                remedy: format!("inspect and remove it (`rm {}`)", path.display()),
            });
        }
    }
    Ok(())
}

/// Check child directories to `depth` using descriptor-relative,
/// `O_NOFOLLOW` opens. Plain files are skipped; symlinks are reported.
fn check_children(
    parent_fd: &File,
    parent_path: &Path,
    depth: u32,
    issues: &mut Vec<PreflightIssue>,
) -> Result<()> {
    if depth == 0 {
        return Ok(());
    }
    let entries = std::fs::read_dir(parent_path)
        .with_context(|| format!("read {}", parent_path.display()))?;
    for entry in entries {
        let entry = entry.with_context(|| format!("read entry in {}", parent_path.display()))?;
        let file_type = entry
            .file_type()
            .with_context(|| format!("inspect entry in {}", parent_path.display()))?;
        if !file_type.is_dir() && !file_type.is_symlink() {
            continue;
        }
        let child_name = entry.file_name();
        let Some(child) = child_name.to_str() else {
            continue;
        };
        let child_path = parent_path.join(child);
        if let Some(child_fd) = open_checked_dir(parent_fd, parent_path, child, false, issues)? {
            check_dir_security(&child_fd, &child_path, issues);
            check_children(&child_fd, &child_path, depth - 1, issues)?;
        }
    }
    Ok(())
}

/// Open a child directory without following symlinks. Report non-directories,
/// and create missing entries with mode 0700 when requested.
fn open_checked_dir(
    parent_fd: &File,
    parent_path: &Path,
    name: &str,
    create_missing: bool,
    issues: &mut Vec<PreflightIssue>,
) -> Result<Option<File>> {
    let path = parent_path.join(name);
    let flags = OFlags::NOFOLLOW | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::RDONLY;
    match openat(parent_fd, name, flags, Mode::empty()) {
        Ok(fd) => Ok(Some(File::from(fd))),
        Err(rustix::io::Errno::NOENT) => {
            if create_missing {
                rustix::fs::mkdirat(parent_fd, name, Mode::from_raw_mode(0o700))
                    .map_err(std::io::Error::from)
                    .with_context(|| format!("create {}", path.display()))?;
                match openat(parent_fd, name, flags, Mode::empty()) {
                    Ok(fd) => Ok(Some(File::from(fd))),
                    Err(errno) => Err(std::io::Error::from(errno))
                        .with_context(|| format!("open created directory {}", path.display())),
                }
            } else {
                Ok(None)
            }
        }
        // ELOOP and ENOTDIR mean the entry is a symlink or not a directory.
        Err(rustix::io::Errno::LOOP) | Err(rustix::io::Errno::NOTDIR) => {
            issues.push(PreflightIssue {
                path: path.clone(),
                problem: "is a symlink or not a real directory".to_owned(),
                remedy: format!(
                    "inspect and remove it, then re-run (`ls -ld {}`)",
                    path.display()
                ),
            });
            Ok(None)
        }
        Err(errno) => Err(std::io::Error::from(errno))
            .with_context(|| format!("open state directory {}", path.display())),
    }
}

fn check_dir_security(fd: &File, path: &Path, issues: &mut Vec<PreflightIssue>) {
    let stat = match rustix::fs::fstat(fd) {
        Ok(stat) => stat,
        Err(errno) => {
            issues.push(PreflightIssue {
                path: path.to_path_buf(),
                problem: format!("cannot stat: {}", std::io::Error::from(errno)),
                remedy: "check filesystem health".to_owned(),
            });
            return;
        }
    };

    let euid = unsafe { libc::geteuid() };
    if stat.st_uid != euid {
        issues.push(PreflightIssue {
            path: path.to_path_buf(),
            problem: format!(
                "is owned by uid {}, not the current user (uid {euid})",
                stat.st_uid
            ),
            remedy: format!("chown -R $(id -un) {}", path.display()),
        });
    }

    let mode = stat.st_mode & 0o7777;
    if mode & 0o022 != 0 {
        issues.push(PreflightIssue {
            path: path.to_path_buf(),
            problem: format!("is writable by group or other (mode {mode:04o})"),
            remedy: format!("chmod go-w {}", path.display()),
        });
    }
}
