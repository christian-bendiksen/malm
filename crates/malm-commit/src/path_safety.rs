//! Proves physical path relationships and keeps filesystem paths pinned while
//! a commit runs.

use std::{
    ffi::{OsStr, OsString},
    fs::File,
    io::{self, Read},
    os::unix::ffi::OsStringExt,
    path::{Component, Path, PathBuf},
};

use rustix::fs::{
    AtFlags, FileType, Mode, Stat, StatxFlags, fstat, open, openat, openat2, statat, statx,
};

use crate::{
    CommitConfigError, CommitError, RESOLVE_FLAGS, ROOT_DIRECTORY_FLAGS, StoreHandles,
    require_pinned_entry,
};

/// Rejects `directory` when it is physically inside the protected store root.
///
/// This check is directional. It allows an ancestor of the store root. Callers
/// that also need to reject ancestors must use
/// [`reject_protected_destination_directory`] or perform the reverse check.
pub(crate) fn reject_protected_traversal_directory(
    store: &StoreHandles,
    directory: &File,
    directory_path: &Path,
) -> Result<(), CommitError> {
    let overlaps = directory_contains(&store.root, directory, &store.root_path)?
        || directory_is_mount_alias_of(&store.root, &store.root_path, directory, directory_path)?;
    if overlaps {
        return Err(CommitError::UnsafeTarget(
            "target is physically inside protected state".to_owned(),
        ));
    }
    Ok(())
}

pub(crate) fn reject_protected_destination_directory(
    store: &StoreHandles,
    directory: &File,
    directory_path: &Path,
) -> Result<(), CommitError> {
    reject_protected_traversal_directory(store, directory, directory_path)?;
    let contains_state = directory_contains(directory, &store.root, directory_path)?
        || directory_is_mount_alias_of(directory, directory_path, &store.root, &store.root_path)?;
    if contains_state {
        return Err(CommitError::UnsafeTarget(
            "target is physically inside protected state".to_owned(),
        ));
    }
    Ok(())
}

pub(crate) fn prove_safe_existing_directory_leaf(
    store: &StoreHandles,
    parent: &File,
    leaf: &OsStr,
    path: &Path,
    observed: &Stat,
) -> Result<(), CommitError> {
    if FileType::from_raw_mode(observed.st_mode) != FileType::Directory {
        return Ok(());
    }
    let directory = match openat2(
        parent,
        leaf,
        ROOT_DIRECTORY_FLAGS,
        Mode::empty(),
        RESOLVE_FLAGS,
    ) {
        Ok(directory) => File::from(directory),
        Err(rustix::io::Errno::NOENT | rustix::io::Errno::NOTDIR | rustix::io::Errno::LOOP) => {
            return Err(CommitError::StaleTarget(
                "target directory changed while opening".to_owned(),
            ));
        }
        Err(source) => return Err(io_error("open target directory leaf", path, source)),
    };
    let opened = fstat(&directory)
        .map_err(|source| io_error("inspect target directory leaf", path, source))?;
    if !same_snapshot(observed, &opened) {
        return Err(CommitError::StaleTarget(
            "target directory changed while opening".to_owned(),
        ));
    }
    reject_protected_destination_directory(store, &directory, path)?;
    let final_stat = require_pinned_entry(parent, leaf, &directory, path, "target directory leaf")?;
    if !same_snapshot(&opened, &final_stat) {
        return Err(CommitError::StaleTarget(
            "target directory changed during protected-state verification".to_owned(),
        ));
    }
    Ok(())
}

pub(crate) fn directory_is_mount_alias_of(
    protected: &File,
    protected_path: &Path,
    candidate: &File,
    candidate_path: &Path,
) -> Result<bool, CommitError> {
    let protected_stat = fstat(protected)
        .map_err(|source| io_error("inspect protected root", protected_path, source))?;
    let candidate_stat = fstat(candidate)
        .map_err(|source| io_error("inspect target mount", candidate_path, source))?;
    if protected_stat.st_dev != candidate_stat.st_dev {
        return Ok(false);
    }
    let protected_mount = mount_id(protected, protected_path)?;
    let candidate_mount = mount_id(candidate, candidate_path)?;
    if protected_mount == candidate_mount {
        return Ok(false);
    }
    let protected_record = load_mount_record(protected_mount)?;
    let candidate_record = load_mount_record(candidate_mount)?;
    if protected_record.device != candidate_record.device {
        return Ok(false);
    }
    let protected_internal = protected_record.filesystem_path(protected_path)?;
    let candidate_internal = candidate_record.filesystem_path(candidate_path)?;
    Ok(candidate_internal == protected_internal
        || candidate_internal.starts_with(protected_internal))
}

pub(crate) fn mount_id(file: &File, path: &Path) -> Result<u64, CommitError> {
    let stat = statx(
        file,
        "",
        AtFlags::EMPTY_PATH | AtFlags::NO_AUTOMOUNT,
        StatxFlags::MNT_ID,
    )
    .map_err(|source| io_error("inspect filesystem mount identity", path, source))?;
    if !StatxFlags::from_bits_retain(stat.stx_mask).contains(StatxFlags::MNT_ID) {
        return Err(CommitError::UnsafeTarget(
            "kernel did not report a mount identity for protected-root proof".to_owned(),
        ));
    }
    Ok(stat.stx_mnt_id)
}

pub(crate) struct MountRecord {
    device: Vec<u8>,
    root: PathBuf,
    mount_point: PathBuf,
}

impl MountRecord {
    pub(crate) fn filesystem_path(&self, visible: &Path) -> Result<PathBuf, CommitError> {
        let relative = visible.strip_prefix(&self.mount_point).map_err(|_| {
            CommitError::UnsafeTarget(
                "mount identity does not contain the validated target path".to_owned(),
            )
        })?;
        Ok(normalize_mount_path(self.root.join(relative)))
    }
}

pub(crate) fn load_mount_record(mount_id: u64) -> Result<MountRecord, CommitError> {
    const MAX_MOUNTINFO_BYTES: u64 = 4 * 1024 * 1024;
    let path = Path::new("/proc/self/mountinfo");
    let mut file = File::open(path).map_err(|source| CommitError::Io {
        operation: "open process mount table",
        path: path.to_path_buf(),
        source,
    })?;
    let mut bytes = Vec::new();
    (&mut file)
        .take(MAX_MOUNTINFO_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|source| CommitError::Io {
            operation: "read process mount table",
            path: path.to_path_buf(),
            source,
        })?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_MOUNTINFO_BYTES {
        return Err(CommitError::UnsafeTarget(
            "process mount table exceeds its size limit".to_owned(),
        ));
    }
    for line in bytes.split(|byte| *byte == b'\n') {
        let fields = line
            .split(|byte| byte.is_ascii_whitespace())
            .filter(|field| !field.is_empty())
            .collect::<Vec<_>>();
        if fields.len() < 6
            || std::str::from_utf8(fields[0])
                .ok()
                .and_then(|field| field.parse::<u64>().ok())
                != Some(mount_id)
        {
            continue;
        }
        return Ok(MountRecord {
            device: fields[2].to_vec(),
            root: decode_mount_path(fields[3])?,
            mount_point: decode_mount_path(fields[4])?,
        });
    }
    Err(CommitError::UnsafeTarget(format!(
        "mount identity {mount_id} is absent from the process mount table"
    )))
}

pub(crate) fn decode_mount_path(field: &[u8]) -> Result<PathBuf, CommitError> {
    let mut decoded = Vec::with_capacity(field.len());
    let mut index = 0;
    while index < field.len() {
        if field[index] != b'\\' {
            decoded.push(field[index]);
            index += 1;
            continue;
        }
        if index + 3 >= field.len()
            || !field[index + 1..=index + 3]
                .iter()
                .all(|byte| (b'0'..=b'7').contains(byte))
        {
            return Err(CommitError::UnsafeTarget(
                "process mount table contains an invalid path escape".to_owned(),
            ));
        }
        let value = (field[index + 1] - b'0') * 64
            + (field[index + 2] - b'0') * 8
            + (field[index + 3] - b'0');
        decoded.push(value);
        index += 4;
    }
    let path = PathBuf::from(OsString::from_vec(decoded));
    if !path.is_absolute() {
        return Err(CommitError::UnsafeTarget(
            "process mount table contains a relative path".to_owned(),
        ));
    }
    Ok(path)
}

pub(crate) fn normalize_mount_path(path: PathBuf) -> PathBuf {
    let mut normalized = PathBuf::from("/");
    for component in path.components() {
        match component {
            Component::RootDir | Component::CurDir => {}
            Component::ParentDir => {
                normalized.pop();
            }
            Component::Normal(part) => normalized.push(part),
            Component::Prefix(_) => {}
        }
    }
    normalized
}

pub(crate) fn directory_contains(
    ancestor: &File,
    descendant: &File,
    path: &Path,
) -> Result<bool, CommitError> {
    let ancestor_stat =
        fstat(ancestor).map_err(|source| io_error("inspect ancestry root", path, source))?;
    let mut current = descendant.try_clone().map_err(|source| CommitError::Io {
        operation: "clone ancestry handle",
        path: path.to_path_buf(),
        source,
    })?;
    for _ in 0..4_096 {
        let current_stat =
            fstat(&current).map_err(|source| io_error("inspect ancestry", path, source))?;
        if same_object(&ancestor_stat, &current_stat) {
            return Ok(true);
        }
        let parent = openat(&current, "..", ROOT_DIRECTORY_FLAGS, Mode::empty())
            .map(File::from)
            .map_err(|source| io_error("open physical ancestor", path, source))?;
        let parent_stat =
            fstat(&parent).map_err(|source| io_error("inspect physical ancestor", path, source))?;
        if same_object(&current_stat, &parent_stat) {
            return Ok(false);
        }
        current = parent;
    }
    Err(CommitError::UnsafeTarget(
        "physical ancestry exceeds 4096 directories".to_owned(),
    ))
}

pub(crate) struct PinnedDirectory {
    handle: File,
    leaf: Option<OsString>,
}

pub(crate) struct PinnedChain {
    directories: Vec<PinnedDirectory>,
}

impl PinnedChain {
    pub(crate) fn open(path: &Path) -> Result<Self, CommitError> {
        let filesystem_root = open("/", ROOT_DIRECTORY_FLAGS, Mode::empty())
            .map(File::from)
            .map_err(|source| io_error("open filesystem root", path, source))?;
        let mut directories = vec![PinnedDirectory {
            handle: filesystem_root,
            leaf: None,
        }];
        for component in path.components() {
            let Component::Normal(leaf) = component else {
                continue;
            };
            // Do not use NO_XDEV here. A configured authority may be on a
            // different filesystem from `/`. After pinning the state root,
            // `require_no_bind_mount_aliases` rejects misleading mount aliases.
            let handle = openat2(
                &directories.last().expect("root exists").handle,
                leaf,
                ROOT_DIRECTORY_FLAGS,
                Mode::empty(),
                RESOLVE_FLAGS,
            )
            .map(File::from)
            .map_err(|source| io_error("open authority path", path, source))?;
            directories.push(PinnedDirectory {
                handle,
                leaf: Some(leaf.to_os_string()),
            });
        }
        Ok(Self { directories })
    }

    pub(crate) fn directory(&self) -> &File {
        &self.directories.last().expect("root exists").handle
    }

    pub(crate) fn parent_directory(&self) -> &File {
        assert!(
            self.directories.len() >= 2,
            "parent_directory requires at least one ancestor"
        );
        &self.directories[self.directories.len() - 2].handle
    }

    pub(crate) fn ensure_bound(&self, path: &Path) -> Result<(), CommitError> {
        for pair in self.directories.windows(2) {
            let [parent, child] = pair else {
                unreachable!()
            };
            let leaf = child.leaf.as_deref().expect("non-root has leaf");
            let bound = statat(&parent.handle, leaf, AtFlags::SYMLINK_NOFOLLOW)
                .map_err(|source| io_error("revalidate authority path", path, source))?;
            let pinned = fstat(&child.handle)
                .map_err(|source| io_error("inspect pinned authority path", path, source))?;
            if !same_object(&bound, &pinned) {
                return Err(CommitError::StaleTarget(
                    "authority path binding changed".to_owned(),
                ));
            }
        }
        Ok(())
    }

    /// Rejects a child reached through a different mount on the same device as
    /// its parent. A normal cross-device mount changes `st_dev`; a same-device
    /// mount-ID change indicates a bind mount or same-device submount, either of
    /// which makes the configured path an unreliable statement of location.
    pub(crate) fn require_no_bind_mount_aliases(&self, path: &Path) -> Result<(), CommitError> {
        for pair in self.directories.windows(2) {
            let [parent, child] = pair else {
                unreachable!()
            };
            let parent_stat = fstat(&parent.handle)
                .map_err(|source| io_error("inspect authority parent", path, source))?;
            let child_stat = fstat(&child.handle)
                .map_err(|source| io_error("inspect authority child", path, source))?;
            if parent_stat.st_dev == child_stat.st_dev {
                let parent_mount = mount_id(&parent.handle, path)?;
                let child_mount = mount_id(&child.handle, path)?;
                if parent_mount != child_mount {
                    return Err(CommitError::UnsafeTarget(
                        "authority path crosses a bind-mount alias".to_owned(),
                    ));
                }
            }
        }
        Ok(())
    }
}

pub(crate) fn normalize_absolute(path: PathBuf) -> Result<PathBuf, CommitConfigError> {
    if !path.is_absolute() {
        return Err(CommitConfigError::PathMustBeAbsolute(path));
    }
    let original = path.clone();
    let mut parts = Vec::new();
    for component in path.components() {
        match component {
            Component::RootDir | Component::CurDir => {}
            Component::ParentDir => {
                if parts.is_empty() {
                    return Err(CommitConfigError::PathEscapesRoot(original));
                }
                parts.pop();
            }
            Component::Normal(part) => parts.push(part.to_os_string()),
            Component::Prefix(_) => return Err(CommitConfigError::PathMustBeAbsolute(original)),
        }
    }
    if parts.is_empty() {
        return Err(CommitConfigError::FilesystemRootNotAllowed);
    }
    let mut normalized = PathBuf::from("/");
    normalized.extend(parts);
    Ok(normalized)
}

pub(crate) fn overlaps(left: &Path, right: &Path) -> bool {
    left == right || left.starts_with(right) || right.starts_with(left)
}

pub(crate) fn same_object(left: &Stat, right: &Stat) -> bool {
    left.st_dev == right.st_dev && left.st_ino == right.st_ino
}

pub(crate) fn same_snapshot(left: &Stat, right: &Stat) -> bool {
    same_object(left, right)
        && left.st_mode == right.st_mode
        && left.st_uid == right.st_uid
        && left.st_gid == right.st_gid
        && left.st_nlink == right.st_nlink
        && left.st_size == right.st_size
        && left.st_mtime == right.st_mtime
        && left.st_mtime_nsec == right.st_mtime_nsec
        && left.st_ctime == right.st_ctime
        && left.st_ctime_nsec == right.st_ctime_nsec
}

pub(crate) fn io_error(
    operation: &'static str,
    path: &Path,
    source: rustix::io::Errno,
) -> CommitError {
    CommitError::Io {
        operation,
        path: path.to_path_buf(),
        source: io::Error::from(source),
    }
}

#[cfg(test)]
mod tests {
    use super::normalize_absolute;
    use crate::CommitConfigError;
    use std::path::PathBuf;

    #[test]
    fn normalize_absolute_rejects_escaping_parent_dirs() {
        for path in ["/foo/../../bar", "/../bar", "/a/../.."] {
            assert!(
                matches!(
                    normalize_absolute(PathBuf::from(path)),
                    Err(CommitConfigError::PathEscapesRoot(_))
                ),
                "{path} should be rejected"
            );
        }
    }

    #[test]
    fn normalize_absolute_preserves_valid_paths() {
        assert_eq!(
            normalize_absolute(PathBuf::from("/foo/bar/../baz")).unwrap(),
            PathBuf::from("/foo/baz")
        );
        assert_eq!(
            normalize_absolute(PathBuf::from("/foo/./bar")).unwrap(),
            PathBuf::from("/foo/bar")
        );
        assert_eq!(
            normalize_absolute(PathBuf::from("/foo/bar")).unwrap(),
            PathBuf::from("/foo/bar")
        );
    }
}
