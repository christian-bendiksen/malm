use std::ffi::OsString;
use std::fs::File;
use std::io::{self, Read};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::{Component, Path, PathBuf};

use malm_pack::{
    LOCK_STAGING_FILE, LocalLocator, MAX_PACK_FILE_BYTES, MAX_PACK_TREE_BYTES,
    MAX_PACK_TREE_ENTRIES, PACK_MANIFEST_FILE, PackFileV1, PackPath, PackTreeError,
    classify_pack_tree_path,
};
use malm_types::Digest;
use rustix::fs::{AtFlags, FileType, Mode, OFlags, Stat, fstat, open, openat2, statat};

use super::mount_identity::directory_is_mount_alias_of;
use super::{
    DIRECTORY_FLAGS, DiscoveredPackV1, Engine, EngineError, PackCaptureIssue,
    PackObjectPublication, RESOLVE_FLAGS, ROOT_DIRECTORY_FLAGS, ROOT_RESOLVE_FLAGS, ReadyStoreRoot,
    StoreAccess, directory_contains, errno_error, io_error, paths_overlap, same_file_snapshot,
    same_object,
};

// A valid pack needs at most 31 directories per file. One extra factor bounds
// empty-directory work without reducing the logical file limit.
const MAX_CAPTURE_ENTRIES: usize = MAX_PACK_TREE_ENTRIES * 32;
const SOURCE_FILE_FLAGS: OFlags = OFlags::RDONLY
    .union(OFlags::NONBLOCK)
    .union(OFlags::NOFOLLOW)
    .union(OFlags::CLOEXEC);

pub(super) fn capture_and_publish(
    engine: &Engine,
    source_root: &Path,
    expected_digest: &Digest,
) -> Result<PackObjectPublication, EngineError> {
    capture_and_publish_with(engine, source_root, expected_digest, |_, _| {})
}

/// Publishes a local pack and returns verification over the exact captured bytes.
pub(super) fn capture_discovered(
    engine: &Engine,
    source_root: &Path,
    expected_digest: &Digest,
) -> Result<DiscoveredPackV1, EngineError> {
    capture_with(engine, source_root, Some(expected_digest), |_, _| {})
}

pub(super) fn discover_and_publish_pinned(
    engine: &Engine,
    source_root: &Path,
    source: &PinnedSourceRoot,
) -> Result<DiscoveredPackV1, EngineError> {
    if engine.config.store_access() != StoreAccess::ReadWrite {
        return Err(EngineError::ReadOnlyStore);
    }
    let source_root = normalize_source_root(source_root)?;
    reject_lexical_state_overlap(engine, &source_root)?;
    if source.path != source_root {
        return Err(changed(&source_root, &source_root));
    }
    capture_pinned_with(engine, &source_root, source, None, |_, _| {})
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CaptureStage {
    EntryObserved,
    FileRead,
    DirectoryEnumerated,
    TreeCaptured,
}

fn capture_and_publish_with(
    engine: &Engine,
    source_root: &Path,
    expected_digest: &Digest,
    hook: impl FnMut(CaptureStage, &Path),
) -> Result<PackObjectPublication, EngineError> {
    capture_with(engine, source_root, Some(expected_digest), hook)
        .map(|discovered| discovered.publication)
}

fn capture_with(
    engine: &Engine,
    source_root: &Path,
    expected_digest: Option<&Digest>,
    hook: impl FnMut(CaptureStage, &Path),
) -> Result<DiscoveredPackV1, EngineError> {
    if engine.config.store_access() != StoreAccess::ReadWrite {
        return Err(EngineError::ReadOnlyStore);
    }

    let source_root = normalize_source_root(source_root)?;
    reject_lexical_state_overlap(engine, &source_root)?;
    let source = PinnedSourceRoot::open(&source_root)?;
    capture_pinned_with(engine, &source_root, &source, expected_digest, hook)
}

fn capture_pinned_with(
    engine: &Engine,
    source_root: &Path,
    source: &PinnedSourceRoot,
    expected_digest: Option<&Digest>,
    mut hook: impl FnMut(CaptureStage, &Path),
) -> Result<DiscoveredPackV1, EngineError> {
    let ready = engine.open_ready_store()?;
    ready.revalidate()?;
    reject_physical_state_overlap(&ready, source.directory(), source_root)?;
    source.revalidate()?;

    let manifest = declared_manifest(source.directory());
    let mut collector = Collector::new(source_root, manifest, &mut hook);
    collector.walk_directory(source.directory(), "", source_root)?;
    (collector.hook)(CaptureStage::TreeCaptured, source_root);
    source.revalidate()?;
    ready.revalidate()?;

    let mut files = std::mem::take(&mut collector.files);
    drop(collector);
    files.sort_by(|left, right| left.path().cmp(right.path()));
    // Verify the digest, manifest, and references once, then publish and
    // assemble from those exact bytes without rereading the source.
    let pack =
        malm_module_graph::VerifiedPackV1::from_untrusted_files(files).map_err(
            |error| match error {
                malm_module_graph::PackVerificationError::InvalidTree(error) => {
                    map_tree_error(source_root, error)
                }
                malm_module_graph::PackVerificationError::MissingManifest => capture_error(
                    source_root,
                    &source_root.join(PACK_MANIFEST_FILE),
                    PackCaptureIssue::MissingManifest,
                ),
                other => capture_error(
                    source_root,
                    &source_root.join(PACK_MANIFEST_FILE),
                    PackCaptureIssue::InvalidPack {
                        detail: other.to_string(),
                    },
                ),
            },
        )?;
    if let Some(expected_digest) = expected_digest
        && pack.content_digest() != expected_digest
    {
        return Err(capture_error(
            source_root,
            source_root,
            PackCaptureIssue::DigestMismatch {
                expected: expected_digest.clone(),
                actual: pack.content_digest().clone(),
            },
        ));
    }

    source.revalidate()?;
    ready.revalidate()?;
    let digest = pack.content_digest().clone();
    let publication = super::pack_store::publish_verified(engine, &digest, &pack)?;
    Ok(DiscoveredPackV1::new(digest, pack, publication))
}

/// Any missing, oversized, or malformed manifest yields no manifest so the walk
/// captures everything and post-capture verification reports the real problem
/// with its canonical error.
fn declared_manifest(directory: &File) -> Option<malm_pack::PackManifestV1> {
    let opened = openat2(
        directory,
        PACK_MANIFEST_FILE,
        SOURCE_FILE_FLAGS,
        Mode::empty(),
        ROOT_RESOLVE_FLAGS,
    )
    .ok()?;
    let mut file = File::from(opened);
    let mut bytes = Vec::new();
    let limit = malm_types::usize_to_u64(malm_pack::MAX_PACK_MANIFEST_BYTES);
    if Read::by_ref(&mut file)
        .take(limit.saturating_add(1))
        .read_to_end(&mut bytes)
        .is_err()
        || bytes.len() > malm_pack::MAX_PACK_MANIFEST_BYTES
    {
        return None;
    }
    malm_pack::decode_pack_v1(&bytes).ok()
}

pub(super) fn normalize_source_root(source_root: &Path) -> Result<PathBuf, EngineError> {
    if !source_root.is_absolute() {
        return Err(capture_error(
            source_root,
            source_root,
            PackCaptureIssue::SourceRootMustBeAbsolute,
        ));
    }

    let mut parts = Vec::<OsString>::new();
    for component in source_root.components() {
        match component {
            Component::RootDir | Component::CurDir => {}
            Component::ParentDir => {
                parts.pop();
            }
            Component::Normal(part) => parts.push(part.to_os_string()),
            Component::Prefix(_) => {
                return Err(capture_error(
                    source_root,
                    source_root,
                    PackCaptureIssue::SourceRootMustBeAbsolute,
                ));
            }
        }
    }
    let mut normalized = PathBuf::from("/");
    normalized.extend(parts);
    Ok(normalized)
}

pub(super) fn reject_lexical_state_overlap(
    engine: &Engine,
    source_root: &Path,
) -> Result<(), EngineError> {
    if paths_overlap(source_root, engine.config.state_root()) {
        return Err(capture_error(
            source_root,
            source_root,
            PackCaptureIssue::ProtectedStateOverlap,
        ));
    }
    Ok(())
}

pub(super) fn reject_physical_state_overlap(
    ready: &ReadyStoreRoot<'_>,
    source: &File,
    source_root: &Path,
) -> Result<(), EngineError> {
    let ancestry_overlap = directory_contains(source, &ready.state, ready.config.state_parent())?
        || directory_contains(&ready.state, source, ready.config.state_parent())?;
    let mount_overlap = !ancestry_overlap
        && (directory_is_mount_alias_of(
            &ready.state,
            ready.config.state_root(),
            source,
            source_root,
        )? || directory_is_mount_alias_of(
            source,
            source_root,
            &ready.state,
            ready.config.state_root(),
        )?);
    if ancestry_overlap || mount_overlap {
        return Err(capture_error(
            source_root,
            source_root,
            PackCaptureIssue::ProtectedStateOverlap,
        ));
    }
    Ok(())
}

struct PinnedSourceDirectory {
    handle: File,
    leaf: Option<OsString>,
}

pub(super) struct PinnedSourceRoot {
    path: PathBuf,
    directories: Vec<PinnedSourceDirectory>,
}

impl PinnedSourceRoot {
    pub(super) fn open(path: &Path) -> Result<Self, EngineError> {
        let filesystem_root = File::from(open("/", ROOT_DIRECTORY_FLAGS, Mode::empty()).map_err(
            |source| errno_error("pin filesystem root for source capture", path, source),
        )?);
        let mut directories = vec![PinnedSourceDirectory {
            handle: filesystem_root,
            leaf: None,
        }];
        let mut current_path = PathBuf::from("/");

        for component in path.components() {
            let Component::Normal(leaf) = component else {
                continue;
            };
            current_path.push(leaf);
            let parent = &directories
                .last()
                .expect("filesystem root starts the source chain")
                .handle;
            let observed = match statat(parent, leaf, AtFlags::SYMLINK_NOFOLLOW) {
                Ok(stat) => stat,
                Err(rustix::io::Errno::NOENT) => {
                    return Err(capture_error(
                        path,
                        &current_path,
                        PackCaptureIssue::SourceRootMissing,
                    ));
                }
                Err(rustix::io::Errno::NOTDIR) => {
                    return Err(capture_error(
                        path,
                        &current_path,
                        PackCaptureIssue::SourceRootNotDirectory,
                    ));
                }
                Err(source) => {
                    return Err(errno_error(
                        "inspect local pack source path",
                        &current_path,
                        source,
                    ));
                }
            };
            match FileType::from_raw_mode(observed.st_mode) {
                FileType::Directory => {}
                FileType::Symlink => {
                    return Err(capture_error(
                        path,
                        &current_path,
                        PackCaptureIssue::SymbolicLink,
                    ));
                }
                _ => {
                    return Err(capture_error(
                        path,
                        &current_path,
                        PackCaptureIssue::SourceRootNotDirectory,
                    ));
                }
            }
            let opened = openat2(
                parent,
                leaf,
                ROOT_DIRECTORY_FLAGS,
                Mode::empty(),
                RESOLVE_FLAGS,
            )
            .map(File::from)
            .map_err(|source| map_root_open_error(path, &current_path, source))?;
            let opened_stat = fstat(&opened).map_err(|source| {
                errno_error(
                    "inspect pinned local pack source path",
                    &current_path,
                    source,
                )
            })?;
            if FileType::from_raw_mode(opened_stat.st_mode) != FileType::Directory
                || !same_object(&observed, &opened_stat)
            {
                return Err(changed(path, &current_path));
            }
            directories.push(PinnedSourceDirectory {
                handle: opened,
                leaf: Some(leaf.to_os_string()),
            });
        }

        let last = directories
            .last_mut()
            .expect("filesystem root starts the source chain");
        let directory = openat2(
            &last.handle,
            ".",
            DIRECTORY_FLAGS.union(OFlags::NOFOLLOW),
            Mode::empty(),
            RESOLVE_FLAGS,
        )
        .map(File::from)
        .map_err(|source| map_root_open_error(path, path, source))?;
        let pinned_stat = fstat(&last.handle)
            .map_err(|source| errno_error("inspect pinned local pack root", path, source))?;
        let directory_stat = fstat(&directory)
            .map_err(|source| errno_error("inspect opened local pack root", path, source))?;
        if !same_object(&pinned_stat, &directory_stat) {
            return Err(changed(path, path));
        }
        last.handle = directory;

        let source = Self {
            path: path.to_path_buf(),
            directories,
        };
        source.revalidate()?;
        Ok(source)
    }

    pub(super) fn directory(&self) -> &File {
        &self
            .directories
            .last()
            .expect("filesystem root starts the source chain")
            .handle
    }

    pub(super) fn path(&self) -> &Path {
        &self.path
    }

    pub(super) fn descriptor_count(&self) -> usize {
        self.directories.len()
    }

    pub(super) fn resolved_locator_descriptor_count(&self, locator: &LocalLocator) -> usize {
        let mut count = self.directories.len();
        if locator.as_str() == "." {
            return count;
        }
        for component in locator.as_str().split('/') {
            if component == ".." {
                count = count.saturating_sub(1).max(1);
            } else {
                count += 1;
            }
        }
        count
    }

    pub(super) fn resolve_locator(&self, locator: &LocalLocator) -> Result<Self, EngineError> {
        let mut retained = self.directories.len();
        let mut path = self.path.clone();
        let mut normal = Vec::new();
        if locator.as_str() != "." {
            for component in locator.as_str().split('/') {
                if component == ".." {
                    retained = retained.saturating_sub(1).max(1);
                    path.pop();
                } else {
                    normal.push(component);
                }
            }
        }

        let mut directories = self.directories[..retained]
            .iter()
            .map(|directory| {
                directory
                    .handle
                    .try_clone()
                    .map(|handle| PinnedSourceDirectory {
                        handle,
                        leaf: directory.leaf.clone(),
                    })
                    .map_err(|source| io_error("clone pinned local source ancestor", &path, source))
            })
            .collect::<Result<Vec<_>, _>>()?;
        for component in normal {
            path.push(component);
            let parent = &directories
                .last()
                .expect("filesystem root starts the source chain")
                .handle;
            let observed = statat(parent, component, AtFlags::SYMLINK_NOFOLLOW)
                .map_err(|source| map_root_open_error(&path, &path, source))?;
            if FileType::from_raw_mode(observed.st_mode) != FileType::Directory {
                return Err(capture_error(
                    &path,
                    &path,
                    if FileType::from_raw_mode(observed.st_mode) == FileType::Symlink {
                        PackCaptureIssue::SymbolicLink
                    } else {
                        PackCaptureIssue::SourceRootNotDirectory
                    },
                ));
            }
            let opened = openat2(
                parent,
                component,
                ROOT_DIRECTORY_FLAGS,
                Mode::empty(),
                RESOLVE_FLAGS,
            )
            .map(File::from)
            .map_err(|source| map_root_open_error(&path, &path, source))?;
            let opened_stat = fstat(&opened)
                .map_err(|source| errno_error("inspect resolved local source", &path, source))?;
            if FileType::from_raw_mode(opened_stat.st_mode) != FileType::Directory
                || !same_object(&observed, &opened_stat)
            {
                return Err(changed(&path, &path));
            }
            directories.push(PinnedSourceDirectory {
                handle: opened,
                leaf: Some(OsString::from(component)),
            });
        }

        let last = directories
            .last_mut()
            .expect("filesystem root starts the source chain");
        let directory = openat2(
            &last.handle,
            ".",
            DIRECTORY_FLAGS.union(OFlags::NOFOLLOW),
            Mode::empty(),
            RESOLVE_FLAGS,
        )
        .map(File::from)
        .map_err(|source| map_root_open_error(&path, &path, source))?;
        let pinned_stat = fstat(&last.handle)
            .map_err(|source| errno_error("inspect resolved local source", &path, source))?;
        let directory_stat = fstat(&directory)
            .map_err(|source| errno_error("inspect opened resolved local source", &path, source))?;
        if !same_object(&pinned_stat, &directory_stat) {
            return Err(changed(&path, &path));
        }
        last.handle = directory;

        let source = Self { path, directories };
        source.revalidate()?;
        Ok(source)
    }

    pub(super) fn revalidate(&self) -> Result<(), EngineError> {
        for pair in self.directories.windows(2) {
            let [parent, child] = pair else {
                unreachable!("source-chain windows have two entries");
            };
            let leaf = child
                .leaf
                .as_deref()
                .expect("non-root source-chain entries have a leaf");
            let bound = match statat(&parent.handle, leaf, AtFlags::SYMLINK_NOFOLLOW) {
                Ok(stat) => stat,
                Err(rustix::io::Errno::NOENT | rustix::io::Errno::NOTDIR) => {
                    return Err(changed(&self.path, &self.path));
                }
                Err(source) => {
                    return Err(errno_error(
                        "revalidate local pack source binding",
                        &self.path,
                        source,
                    ));
                }
            };
            let pinned = fstat(&child.handle).map_err(|source| {
                errno_error("inspect pinned local pack source", &self.path, source)
            })?;
            if FileType::from_raw_mode(bound.st_mode) != FileType::Directory
                || !same_object(&bound, &pinned)
            {
                return Err(changed(&self.path, &self.path));
            }
        }
        Ok(())
    }
}

fn map_root_open_error(root: &Path, path: &Path, source: rustix::io::Errno) -> EngineError {
    match source {
        rustix::io::Errno::NOENT => capture_error(root, path, PackCaptureIssue::SourceRootMissing),
        rustix::io::Errno::NOTDIR => {
            capture_error(root, path, PackCaptureIssue::SourceRootNotDirectory)
        }
        rustix::io::Errno::LOOP => capture_error(root, path, PackCaptureIssue::SymbolicLink),
        _ => errno_error(
            "open local pack source without following links",
            path,
            source,
        ),
    }
}

struct Collector<'a, F> {
    root: &'a Path,
    files: Vec<PackFileV1>,
    total_bytes: u64,
    visited_entries: usize,
    /// Manifest that declares the capture allowlist; absent captures everything.
    manifest: Option<malm_pack::PackManifestV1>,
    hook: &'a mut F,
}

impl<'a, F> Collector<'a, F>
where
    F: FnMut(CaptureStage, &Path),
{
    fn new(root: &'a Path, manifest: Option<malm_pack::PackManifestV1>, hook: &'a mut F) -> Self {
        Self {
            root,
            files: Vec::new(),
            total_bytes: 0,
            visited_entries: 0,
            manifest,
            hook,
        }
    }

    /// Returns whether a logical path is inside the capture allowlist.
    ///
    /// The manifest holds the single definition, shared with Git tree capture.
    /// With no manifest everything passes and post-capture verification reports
    /// the real problem.
    fn within_capture_roots(&self, logical: &str) -> bool {
        self.manifest
            .as_ref()
            .is_none_or(|manifest| manifest.covers_capture_path(logical))
    }

    fn walk_directory(
        &mut self,
        directory: &File,
        relative: &str,
        directory_path: &Path,
    ) -> Result<(), EngineError> {
        let initial = fstat(directory).map_err(|source| {
            errno_error(
                "inspect local pack source directory",
                directory_path,
                source,
            )
        })?;
        if FileType::from_raw_mode(initial.st_mode) != FileType::Directory {
            return Err(changed(self.root, directory_path));
        }
        let names = self.read_initial_names(directory, directory_path)?;
        (self.hook)(CaptureStage::DirectoryEnumerated, directory_path);

        for name in &names {
            let name_bytes = name.as_bytes();
            if matches!(name_bytes, b".git" | b"malm.lock")
                || name_bytes == LOCK_STAGING_FILE.as_bytes()
            {
                continue;
            }
            let entry_path = directory_path.join(name);
            let name = std::str::from_utf8(name_bytes).map_err(|_| {
                capture_error(self.root, &entry_path, PackCaptureIssue::NonUtf8Name)
            })?;
            let logical = if relative.is_empty() {
                name.to_owned()
            } else {
                format!("{relative}/{name}")
            };
            let logical_path = classify_pack_tree_path(logical).map_err(|error| {
                capture_error(
                    self.root,
                    &entry_path,
                    PackCaptureIssue::InvalidPath {
                        detail: error.to_string(),
                    },
                )
            })?;
            let Some(logical_path) = logical_path else {
                continue;
            };
            if !self.within_capture_roots(logical_path.as_str()) {
                continue;
            }
            let observed = match statat(directory, name, AtFlags::SYMLINK_NOFOLLOW) {
                Ok(stat) => stat,
                Err(rustix::io::Errno::NOENT | rustix::io::Errno::NOTDIR) => {
                    return Err(changed(self.root, &entry_path));
                }
                Err(source) => {
                    return Err(errno_error(
                        "inspect local pack source entry",
                        &entry_path,
                        source,
                    ));
                }
            };
            (self.hook)(CaptureStage::EntryObserved, &entry_path);
            match FileType::from_raw_mode(observed.st_mode) {
                FileType::Directory => self.walk_child_directory(
                    directory,
                    name,
                    logical_path.as_str(),
                    &entry_path,
                    &observed,
                )?,
                FileType::RegularFile => {
                    self.capture_file(directory, name, logical_path, &entry_path, &observed)?;
                }
                FileType::Symlink => {
                    return Err(capture_error(
                        self.root,
                        &entry_path,
                        PackCaptureIssue::SymbolicLink,
                    ));
                }
                _ => {
                    return Err(capture_error(
                        self.root,
                        &entry_path,
                        PackCaptureIssue::UnsupportedFileType,
                    ));
                }
            }
        }

        let final_names = reread_names(directory, directory_path, names.len())?;
        if names != final_names {
            return Err(changed(self.root, directory_path));
        }
        let final_stat = fstat(directory).map_err(|source| {
            errno_error(
                "reinspect local pack source directory",
                directory_path,
                source,
            )
        })?;
        if !same_file_snapshot(&initial, &final_stat) {
            return Err(changed(self.root, directory_path));
        }
        Ok(())
    }

    fn read_initial_names(
        &mut self,
        directory: &File,
        directory_path: &Path,
    ) -> Result<Vec<OsString>, EngineError> {
        let names = super::dir_entry_names(directory).map_err(|source| {
            io_error(
                "open local pack source directory for enumeration",
                directory_path,
                source,
            )
        })?;
        if self.visited_entries + names.len() > MAX_CAPTURE_ENTRIES {
            return Err(capture_error(
                self.root,
                directory_path,
                PackCaptureIssue::TraversalLimitExceeded {
                    limit: MAX_CAPTURE_ENTRIES,
                },
            ));
        }
        self.visited_entries += names.len();
        let mut names: Vec<OsString> = names.into_iter().map(OsString::from_vec).collect();
        names.sort_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
        Ok(names)
    }

    fn walk_child_directory(
        &mut self,
        parent: &File,
        name: &str,
        relative: &str,
        path: &Path,
        observed: &Stat,
    ) -> Result<(), EngineError> {
        let child = openat2(
            parent,
            name,
            DIRECTORY_FLAGS.union(OFlags::NOFOLLOW),
            Mode::empty(),
            ROOT_RESOLVE_FLAGS,
        )
        .map(File::from)
        .map_err(|source| map_entry_open_error(self.root, path, source))?;
        let opened = fstat(&child)
            .map_err(|source| errno_error("inspect opened pack source directory", path, source))?;
        if FileType::from_raw_mode(opened.st_mode) != FileType::Directory
            || !same_file_snapshot(observed, &opened)
        {
            return Err(changed(self.root, path));
        }

        self.walk_directory(&child, relative, path)?;
        let final_stat = fstat(&child)
            .map_err(|source| errno_error("reinspect pack source directory", path, source))?;
        let bound = stat_bound(parent, name, self.root, path)?;
        if !same_file_snapshot(&opened, &final_stat) || !same_file_snapshot(&opened, &bound) {
            return Err(changed(self.root, path));
        }
        Ok(())
    }

    fn capture_file(
        &mut self,
        parent: &File,
        name: &str,
        logical_path: PackPath,
        path: &Path,
        observed: &Stat,
    ) -> Result<(), EngineError> {
        let size = validate_source_file(self.root, path, observed)?;
        if self.files.len() == MAX_PACK_TREE_ENTRIES {
            return Err(capture_error(
                self.root,
                path,
                PackCaptureIssue::TooManyFiles {
                    limit: MAX_PACK_TREE_ENTRIES,
                    actual: MAX_PACK_TREE_ENTRIES + 1,
                },
            ));
        }
        let new_total = self.total_bytes.saturating_add(size);
        if new_total > MAX_PACK_TREE_BYTES {
            return Err(capture_error(
                self.root,
                path,
                PackCaptureIssue::TreeTooLarge {
                    limit: MAX_PACK_TREE_BYTES,
                    actual: new_total,
                },
            ));
        }

        let mut file = openat2(
            parent,
            name,
            SOURCE_FILE_FLAGS,
            Mode::empty(),
            ROOT_RESOLVE_FLAGS,
        )
        .map(File::from)
        .map_err(|source| map_entry_open_error(self.root, path, source))?;
        let opened = fstat(&file)
            .map_err(|source| errno_error("inspect opened local pack source file", path, source))?;
        validate_source_file(self.root, path, &opened)?;
        if !same_file_snapshot(observed, &opened) {
            return Err(changed(self.root, path));
        }

        let size_usize = usize::try_from(size).map_err(|_| {
            capture_error(
                self.root,
                path,
                PackCaptureIssue::FileTooLarge {
                    limit: MAX_PACK_FILE_BYTES,
                    actual: size,
                },
            )
        })?;
        let mut bytes = Vec::new();
        bytes.try_reserve_exact(size_usize).map_err(|error| {
            io_error(
                "reserve memory for local pack source file",
                path,
                io::Error::other(error.to_string()),
            )
        })?;
        Read::by_ref(&mut file)
            .take(size.saturating_add(1))
            .read_to_end(&mut bytes)
            .map_err(|source| io_error("read local pack source file", path, source))?;
        (self.hook)(CaptureStage::FileRead, path);

        let final_stat = fstat(&file)
            .map_err(|source| errno_error("reinspect local pack source file", path, source))?;
        validate_source_file(self.root, path, &final_stat)?;
        let bound = stat_bound(parent, name, self.root, path)?;
        validate_source_file(self.root, path, &bound)?;
        if bytes.len() != size_usize
            || !same_file_snapshot(&opened, &final_stat)
            || !same_file_snapshot(&opened, &bound)
        {
            return Err(changed(self.root, path));
        }

        self.total_bytes = new_total;
        self.files.push(PackFileV1::new(logical_path, bytes));
        Ok(())
    }
}

fn reread_names(
    directory: &File,
    directory_path: &Path,
    expected_len: usize,
) -> Result<Vec<OsString>, EngineError> {
    let mut names = super::dir_entry_names(directory)
        .map_err(|source| {
            io_error(
                "reopen local pack source directory for enumeration",
                directory_path,
                source,
            )
        })?
        .into_iter()
        .map(OsString::from_vec)
        .collect::<Vec<_>>();
    // One extra name is enough to prove that the directory changed.
    if names.len() > expected_len + 1 {
        names.truncate(expected_len + 1);
    }
    names.sort_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
    Ok(names)
}

fn validate_source_file(root: &Path, path: &Path, stat: &Stat) -> Result<u64, EngineError> {
    if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile {
        return Err(changed(root, path));
    }
    if stat.st_nlink != 1 {
        return Err(capture_error(
            root,
            path,
            PackCaptureIssue::UnexpectedLinks {
                expected: 1,
                actual: stat.st_nlink,
            },
        ));
    }
    if stat.st_size < 0 {
        return Err(changed(root, path));
    }
    let size = stat.st_size as u64;
    if size > MAX_PACK_FILE_BYTES {
        return Err(capture_error(
            root,
            path,
            PackCaptureIssue::FileTooLarge {
                limit: MAX_PACK_FILE_BYTES,
                actual: size,
            },
        ));
    }
    Ok(size)
}

fn stat_bound(parent: &File, name: &str, root: &Path, path: &Path) -> Result<Stat, EngineError> {
    match statat(parent, name, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(stat) => Ok(stat),
        Err(rustix::io::Errno::NOENT | rustix::io::Errno::NOTDIR) => Err(changed(root, path)),
        Err(source) => Err(errno_error(
            "revalidate local pack source entry binding",
            path,
            source,
        )),
    }
}

fn map_entry_open_error(root: &Path, path: &Path, source: rustix::io::Errno) -> EngineError {
    match source {
        rustix::io::Errno::XDEV => capture_error(root, path, PackCaptureIssue::MountBoundary),
        rustix::io::Errno::NOENT | rustix::io::Errno::NOTDIR | rustix::io::Errno::LOOP => {
            changed(root, path)
        }
        _ => errno_error(
            "open local pack source entry without following links",
            path,
            source,
        ),
    }
}

fn map_tree_error(root: &Path, error: PackTreeError) -> EngineError {
    match error {
        PackTreeError::MissingManifest => capture_error(
            root,
            &root.join(PACK_MANIFEST_FILE),
            PackCaptureIssue::MissingManifest,
        ),
        PackTreeError::TooManyEntries { limit, actual } => {
            capture_error(root, root, PackCaptureIssue::TooManyFiles { limit, actual })
        }
        PackTreeError::FileTooLarge {
            path,
            limit,
            actual,
        } => capture_error(
            root,
            &root.join(path.as_str()),
            PackCaptureIssue::FileTooLarge { limit, actual },
        ),
        PackTreeError::TreeTooLarge { limit, actual } => {
            capture_error(root, root, PackCaptureIssue::TreeTooLarge { limit, actual })
        }
        PackTreeError::DuplicatePath(path) => capture_error(
            root,
            &root.join(path.as_str()),
            PackCaptureIssue::InvalidPack {
                detail: format!("duplicate pack path {path:?}"),
            },
        ),
    }
}

fn changed(root: &Path, path: &Path) -> EngineError {
    capture_error(root, path, PackCaptureIssue::ObservationChanged)
}

fn capture_error(root: &Path, path: &Path, reason: PackCaptureIssue) -> EngineError {
    EngineError::PackCapture {
        root: root.to_path_buf(),
        path: path.to_path_buf(),
        reason,
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use malm_pack::pack_content_digest;

    use super::*;
    use crate::{EngineConfig, StoreStatus};

    const MINIMAL_PACK: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../schemas/pack/v1/fixtures/valid/minimal.kdl"
    ));

    fn initialized_engine(temp: &tempfile::TempDir) -> Engine {
        let state_home = temp.path().join("state");
        std::fs::create_dir(&state_home).unwrap();
        std::fs::set_permissions(&state_home, std::fs::Permissions::from_mode(0o700)).unwrap();
        let engine = Engine::new(
            EngineConfig::from_state_home(&state_home, StoreAccess::ReadWrite).unwrap(),
            crate::EnginePorts::system(),
        );
        assert_eq!(
            engine.initialize_store().unwrap().status(),
            StoreStatus::Ready
        );
        engine
    }

    fn source_fixture(temp: &tempfile::TempDir) -> (PathBuf, PathBuf, Digest) {
        let source = temp.path().join("source");
        std::fs::create_dir(&source).unwrap();
        std::fs::write(source.join(PACK_MANIFEST_FILE), MINIMAL_PACK).unwrap();
        let data = source.join("data");
        std::fs::write(&data, b"data").unwrap();
        let files = [
            PackFileV1::new(PackPath::new(PACK_MANIFEST_FILE).unwrap(), MINIMAL_PACK),
            PackFileV1::new(PackPath::new("data").unwrap(), b"data"),
        ];
        let digest =
            pack_content_digest(files.iter().map(|file| (file.path(), file.bytes()))).unwrap();
        (source, data, digest)
    }

    fn assert_changed(error: &EngineError) {
        assert!(matches!(
            error,
            EngineError::PackCapture {
                reason: PackCaptureIssue::ObservationChanged,
                ..
            }
        ));
    }

    #[test]
    fn file_replacement_between_observation_and_open_is_rejected() {
        let temp = tempfile::tempdir().unwrap();
        let engine = initialized_engine(&temp);
        let (source, data, digest) = source_fixture(&temp);
        let outside = temp.path().join("outside");
        std::fs::write(&outside, b"outside bytes").unwrap();
        let mut replaced = false;

        let error = capture_and_publish_with(&engine, &source, &digest, |stage, path| {
            if !replaced && stage == CaptureStage::EntryObserved && path == data {
                std::fs::remove_file(&data).unwrap();
                std::os::unix::fs::symlink(&outside, &data).unwrap();
                replaced = true;
            }
        })
        .unwrap_err();

        assert_changed(&error);
        assert_eq!(std::fs::read(outside).unwrap(), b"outside bytes");
        assert!(!engine.config.state_root().join("objects").exists());
    }

    #[test]
    fn in_place_change_after_file_read_is_rejected() {
        let temp = tempfile::tempdir().unwrap();
        let engine = initialized_engine(&temp);
        let (source, data, digest) = source_fixture(&temp);
        let mut changed_file = false;

        let error = capture_and_publish_with(&engine, &source, &digest, |stage, path| {
            if !changed_file && stage == CaptureStage::FileRead && path == data {
                std::fs::write(&data, b"changed after read").unwrap();
                changed_file = true;
            }
        })
        .unwrap_err();

        assert_changed(&error);
        assert!(!engine.config.state_root().join("objects").exists());
    }

    #[test]
    fn directory_entry_added_during_capture_is_rejected() {
        let temp = tempfile::tempdir().unwrap();
        let engine = initialized_engine(&temp);
        let (source, _, digest) = source_fixture(&temp);
        let mut added = false;

        let error = capture_and_publish_with(&engine, &source, &digest, |stage, path| {
            if !added && stage == CaptureStage::DirectoryEnumerated && path == source {
                std::fs::write(source.join("late"), b"late bytes").unwrap();
                added = true;
            }
        })
        .unwrap_err();

        assert_changed(&error);
        assert!(!engine.config.state_root().join("objects").exists());
    }

    #[test]
    fn source_root_replacement_after_capture_is_rejected() {
        let temp = tempfile::tempdir().unwrap();
        let engine = initialized_engine(&temp);
        let (source, _, digest) = source_fixture(&temp);
        let displaced = temp.path().join("displaced-source");
        let mut replaced = false;

        let error = capture_and_publish_with(&engine, &source, &digest, |stage, path| {
            if !replaced && stage == CaptureStage::TreeCaptured && path == source {
                std::fs::rename(&source, &displaced).unwrap();
                std::fs::create_dir(&source).unwrap();
                std::fs::write(source.join(PACK_MANIFEST_FILE), MINIMAL_PACK).unwrap();
                replaced = true;
            }
        })
        .unwrap_err();

        assert_changed(&error);
        assert!(!engine.config.state_root().join("objects").exists());
    }

    #[test]
    fn retained_source_pin_rejects_a_rebound_path_before_discovery() {
        let temp = tempfile::tempdir().unwrap();
        let engine = initialized_engine(&temp);
        let (source, _, _) = source_fixture(&temp);
        let pinned = PinnedSourceRoot::open(&source).unwrap();
        let displaced = temp.path().join("displaced-source");
        let attacker = temp.path().join("attacker-source");
        std::fs::create_dir(&attacker).unwrap();
        std::fs::write(attacker.join(PACK_MANIFEST_FILE), MINIMAL_PACK).unwrap();
        std::fs::write(attacker.join("data"), b"attacker bytes").unwrap();
        std::fs::rename(&source, &displaced).unwrap();
        std::fs::rename(&attacker, &source).unwrap();

        let error = discover_and_publish_pinned(&engine, &source, &pinned).unwrap_err();

        assert_changed(&error);
        assert!(!engine.config.state_root().join("objects").exists());
    }

    #[test]
    fn local_locator_resolution_stays_beneath_the_retained_root() {
        let temp = tempfile::tempdir().unwrap();
        let (source, _, _) = source_fixture(&temp);
        std::fs::create_dir(source.join("dependency")).unwrap();
        let pinned = PinnedSourceRoot::open(&source).unwrap();
        let displaced = temp.path().join("displaced-source");
        let attacker = temp.path().join("attacker-source");
        std::fs::create_dir(&attacker).unwrap();
        std::fs::create_dir(attacker.join("dependency")).unwrap();
        std::fs::rename(&source, &displaced).unwrap();
        std::fs::rename(&attacker, &source).unwrap();

        let error = match pinned.resolve_locator(&LocalLocator::new("dependency").unwrap()) {
            Ok(_) => panic!("rebound root unexpectedly resolved a local locator"),
            Err(error) => error,
        };

        assert_changed(&error);
    }

    #[test]
    fn hard_link_added_after_file_read_is_rejected() {
        let temp = tempfile::tempdir().unwrap();
        let engine = initialized_engine(&temp);
        let (source, data, digest) = source_fixture(&temp);
        let alias = temp.path().join("outside-alias");
        let mut linked = false;

        let error = capture_and_publish_with(&engine, &source, &digest, |stage, path| {
            if !linked && stage == CaptureStage::FileRead && path == data {
                std::fs::hard_link(&data, &alias).unwrap();
                linked = true;
            }
        })
        .unwrap_err();

        assert!(matches!(
            error,
            EngineError::PackCapture {
                reason: PackCaptureIssue::UnexpectedLinks {
                    expected: 1,
                    actual: 2
                },
                ..
            }
        ));
        assert!(!engine.config.state_root().join("objects").exists());
    }
}
