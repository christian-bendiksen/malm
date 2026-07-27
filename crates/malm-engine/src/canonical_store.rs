use std::{
    error::Error,
    fmt,
    fs::File,
    io::{Read, Write},
    path::{Path, PathBuf},
};

use malm_archive::{ArchiveDeclarationV1, ArchiveLimitsV1, DecodedArchiveV1, decode_archive_v1};
use malm_tree::{
    MAX_FILE_OBJECT_BYTES, MAX_SYMLINK_OBJECT_BYTES, MAX_TREE_AGGREGATE_FILE_BYTES, MAX_TREE_DEPTH,
    MAX_TREE_ENTRIES, MAX_TREE_OBJECT_BYTES, MAX_TREE_PATH_BYTES, ObjectReadError, SymlinkObjectV1,
    TreeEntryKindV1, TreeEntryV1, TreeGraphV1, TreeObjectV1, TreePathSegmentV1,
    decode_file_object_v1, decode_symlink_object_v1, decode_tree_object_v1,
    decode_verified_file_object_v1, decode_verified_symlink_object_v1,
    decode_verified_tree_object_v1, encode_file_object_v1, encode_symlink_object_v1,
    encode_tree_object_v1, symlink_object_digest_v1, tree_object_digest_v1,
};
use malm_types::Digest;
use rustix::fs::{
    AtFlags, FileType, Mode, OFlags, Stat, fchmod, fstat, fsync, linkat, mkdirat, openat2, statat,
};

use super::{
    DIRECTORY_FLAGS, Engine, EngineError, ROOT_RESOLVE_FLAGS, ReadyStoreRoot, StoreAccess,
    errno_error, io_error, prepared_store::PreparedPublicationLock, same_file_snapshot,
    same_object,
};

const OBJECTS_DIR: &str = "objects";
const CONTAINER_MODE: u32 = 0o700;
const OBJECT_MODE: u32 = 0o400;

/// Canonical immutable object category stored by the Engine.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum CanonicalObjectKind {
    /// Domain-separated regular-file contents.
    File,
    /// Domain-separated symbolic-link target text.
    Symlink,
    /// Domain-separated canonical directory entries.
    Tree,
}

impl CanonicalObjectKind {
    const fn directory(self) -> &'static str {
        match self {
            Self::File => "files",
            Self::Symlink => "symlinks",
            Self::Tree => "trees",
        }
    }

    const fn maximum_bytes(self) -> u64 {
        match self {
            Self::File => MAX_FILE_OBJECT_BYTES as u64,
            Self::Symlink => MAX_SYMLINK_OBJECT_BYTES as u64,
            Self::Tree => MAX_TREE_OBJECT_BYTES as u64,
        }
    }
}

impl fmt::Display for CanonicalObjectKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::File => "file",
            Self::Symlink => "symlink",
            Self::Tree => "tree",
        })
    }
}

/// Durable outcome of publishing one immutable canonical object.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CanonicalObjectPublication {
    /// This operation linked the canonical digest name.
    Published,
    /// A pre-existing object was fully verified and reused.
    Reused,
}

/// Typed reason a canonical object or one of its private containers was rejected.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
#[non_exhaustive]
pub enum CanonicalObjectIssue {
    /// The requested object is not present.
    #[error("object is not cached")]
    Missing,
    /// An object-store container is not a directory.
    #[error("canonical-object container is not a directory")]
    ContainerNotDirectory,
    /// The digest entry is not a regular file.
    #[error("object is not a regular file")]
    ObjectNotRegular,
    /// A container or object has an unexpected owner.
    #[error("owner uid must be {expected_uid}, found {actual_uid}")]
    WrongOwner {
        /// Required effective user ID.
        expected_uid: u32,
        /// Observed user ID.
        actual_uid: u32,
    },
    /// A container or object has unexpected permission or special bits.
    #[error("mode must be {expected:04o}, found {actual:04o}")]
    UnexpectedMode {
        /// Required exact mode.
        expected: u32,
        /// Observed mode.
        actual: u32,
    },
    /// An immutable object has an unexpected hard-link count.
    #[error("link count must be {expected}, found {actual}")]
    UnexpectedLinks {
        /// Required link count.
        expected: u64,
        /// Observed link count.
        actual: u64,
    },
    /// Canonical encoded bytes exceed the per-kind decoder bound.
    #[error("object is {actual} bytes; limit is {limit}")]
    ObjectTooLarge {
        /// Maximum accepted bytes.
        limit: u64,
        /// Observed bytes.
        actual: u64,
    },
    /// Canonical encoded bytes do not have the requested identity.
    #[error("object bytes compute digest {actual}")]
    DigestMismatch {
        /// Digest computed from the bytes.
        actual: Digest,
    },
    /// Bytes are malformed, noncanonical, or from another object domain.
    #[error("{detail}")]
    InvalidEncoding {
        /// Deterministic strict-decoder detail.
        detail: String,
    },
    /// A pinned object, container, or binding changed during the operation.
    #[error("canonical-object observation changed during the operation")]
    ObservationChanged,
}

/// Failure to decode a complete archive or publish its verified object set.
#[derive(Debug)]
#[non_exhaustive]
pub enum ArchivePublicationError {
    /// Exact payload or archive semantic verification failed before store mutation.
    Decode {
        /// Trusted archive decoder failure.
        source: malm_archive::ArchiveDecodeError,
    },
    /// Publication into the pinned private canonical-object store failed.
    Store {
        /// Underlying Engine root or canonical-object failure.
        source: EngineError,
    },
    /// Trusted decoding produced a tree other than the reviewed declaration.
    UnexpectedRoot { expected: Digest, actual: Digest },
}

impl fmt::Display for ArchivePublicationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Decode { source } => write!(formatter, "decode archive/v1 payload: {source}"),
            Self::Store { source } => write!(formatter, "publish archive/v1 objects: {source}"),
            Self::UnexpectedRoot { expected, actual } => write!(
                formatter,
                "decoded archive root is {actual}, reviewed config requires {expected}"
            ),
        }
    }
}

impl Error for ArchivePublicationError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        // The cause already appears in Display, and source() would duplicate it.
        None
    }
}

/// Canonical object identity and diagnostic path for one validation operation.
#[derive(Clone, Copy)]
struct CanonicalTarget<'a> {
    kind: CanonicalObjectKind,
    digest: &'a Digest,
    path: &'a Path,
}

impl<'a> CanonicalTarget<'a> {
    const fn new(kind: CanonicalObjectKind, digest: &'a Digest, path: &'a Path) -> Self {
        Self { kind, digest, path }
    }

    fn error(self, reason: CanonicalObjectIssue) -> EngineError {
        EngineError::CanonicalObject {
            kind: self.kind,
            digest: self.digest.clone(),
            path: self.path.to_path_buf(),
            reason,
        }
    }
}

pub(super) fn publish_file(
    engine: &Engine,
    expected_digest: &Digest,
    contents: &[u8],
) -> Result<CanonicalObjectPublication, EngineError> {
    let kind = CanonicalObjectKind::File;
    let path = object_path(engine.config().state_root(), kind, expected_digest);
    let bytes = encode_file_object_v1(contents).map_err(|error| {
        map_read_error(CanonicalTarget::new(kind, expected_digest, &path), error)
    })?;
    publish_encoded(engine, kind, expected_digest, &bytes)
}

pub(super) fn publish_symlink(
    engine: &Engine,
    expected_digest: &Digest,
    object: &SymlinkObjectV1,
) -> Result<CanonicalObjectPublication, EngineError> {
    publish_encoded(
        engine,
        CanonicalObjectKind::Symlink,
        expected_digest,
        &encode_symlink_object_v1(object),
    )
}

pub(super) fn publish_tree(
    engine: &Engine,
    expected_digest: &Digest,
    object: &TreeObjectV1,
) -> Result<CanonicalObjectPublication, EngineError> {
    publish_encoded(
        engine,
        CanonicalObjectKind::Tree,
        expected_digest,
        &encode_tree_object_v1(object),
    )
}

pub(super) fn load_file(engine: &Engine, digest: &Digest) -> Result<Vec<u8>, EngineError> {
    let kind = CanonicalObjectKind::File;
    let path = object_path(engine.config().state_root(), kind, digest);
    let target = CanonicalTarget::new(kind, digest, &path);
    let bytes = load_encoded(engine, kind, digest)?;
    decode_file_object_v1(&bytes)
        .map(<[u8]>::to_vec)
        .map_err(|error| map_read_error(target, error))
}

pub(super) fn load_symlink(
    engine: &Engine,
    digest: &Digest,
) -> Result<SymlinkObjectV1, EngineError> {
    let kind = CanonicalObjectKind::Symlink;
    let path = object_path(engine.config().state_root(), kind, digest);
    let target = CanonicalTarget::new(kind, digest, &path);
    let bytes = load_encoded(engine, kind, digest)?;
    decode_symlink_object_v1(&bytes).map_err(|error| map_read_error(target, error))
}

pub(super) fn load_tree(engine: &Engine, digest: &Digest) -> Result<TreeObjectV1, EngineError> {
    let kind = CanonicalObjectKind::Tree;
    let path = object_path(engine.config().state_root(), kind, digest);
    let target = CanonicalTarget::new(kind, digest, &path);
    let bytes = load_encoded(engine, kind, digest)?;
    decode_tree_object_v1(&bytes).map_err(|error| map_read_error(target, error))
}

pub(super) fn load_safe_symlink(
    engine: &Engine,
    digest: &Digest,
) -> Result<SymlinkObjectV1, EngineError> {
    let object = load_symlink(engine, digest)?;
    let root = TreeObjectV1::new(
        0o700,
        vec![TreeEntryV1::safe_relative_symlink(
            TreePathSegmentV1::new("link").expect("fixed tree segment is valid"),
            digest.clone(),
        )],
    )
    .expect("fixed standalone symlink validation tree is valid");
    let root_digest = tree_object_digest_v1(&root);
    let kind = CanonicalObjectKind::Symlink;
    let path = object_path(engine.config().state_root(), kind, digest);
    TreeGraphV1::new(root_digest, [root], [object.clone()]).map_err(|error| {
        CanonicalTarget::new(kind, digest, &path).error(CanonicalObjectIssue::InvalidEncoding {
            detail: error.to_string(),
        })
    })?;
    Ok(object)
}

pub(super) fn load_tree_graph(engine: &Engine, root: &Digest) -> Result<TreeGraphV1, EngineError> {
    let mut pending = vec![(root.clone(), 0_usize, 0_usize)];
    let mut trees = std::collections::BTreeMap::new();
    let mut symlinks = std::collections::BTreeMap::new();
    let mut verified_files = std::collections::BTreeSet::new();
    let mut logical_entries = 0_usize;
    let mut logical_file_bytes = 0_u64;
    while let Some((digest, depth, prefix_bytes)) = pending.pop() {
        if !trees.contains_key(&digest) {
            trees.insert(digest.clone(), load_tree(engine, &digest)?);
        }
        let tree = trees
            .get(&digest)
            .expect("the canonical tree was loaded above");
        for entry in tree.entries() {
            let entry_depth = depth.saturating_add(1);
            if entry_depth > MAX_TREE_DEPTH {
                return Err(invalid_tree_graph(
                    engine,
                    root,
                    "tree depth exceeds the canonical graph limit while loading",
                ));
            }
            let path_bytes = prefix_bytes
                .checked_add(usize::from(prefix_bytes != 0))
                .and_then(|bytes| bytes.checked_add(entry.name().as_str().len()))
                .unwrap_or(usize::MAX);
            if path_bytes > MAX_TREE_PATH_BYTES {
                return Err(invalid_tree_graph(
                    engine,
                    root,
                    "tree path bytes exceed the canonical graph limit while loading",
                ));
            }
            if logical_entries == MAX_TREE_ENTRIES {
                return Err(invalid_tree_graph(
                    engine,
                    root,
                    "logical tree entries exceed the canonical graph limit while loading",
                ));
            }
            logical_entries += 1;
            match entry.kind() {
                TreeEntryKindV1::File { digest, byte_len } => {
                    logical_file_bytes =
                        logical_file_bytes.checked_add(*byte_len).ok_or_else(|| {
                            invalid_tree_graph(
                                engine,
                                root,
                                "logical tree file bytes overflow while loading",
                            )
                        })?;
                    if logical_file_bytes > MAX_TREE_AGGREGATE_FILE_BYTES {
                        return Err(invalid_tree_graph(
                            engine,
                            root,
                            "logical tree file bytes exceed the canonical graph limit while loading",
                        ));
                    }
                    if verified_files.insert(digest.clone()) {
                        let bytes = load_file(engine, digest)?;
                        if u64::try_from(bytes.len()).unwrap_or(u64::MAX) != *byte_len {
                            let kind = CanonicalObjectKind::File;
                            let path = object_path(engine.config().state_root(), kind, digest);
                            return Err(CanonicalTarget::new(kind, digest, &path).error(
                                CanonicalObjectIssue::InvalidEncoding {
                                    detail: "tree file length differs from its canonical object"
                                        .to_owned(),
                                },
                            ));
                        }
                    }
                }
                TreeEntryKindV1::Directory { digest } => {
                    pending.push((digest.clone(), entry_depth, path_bytes));
                }
                TreeEntryKindV1::SafeRelativeSymlink { digest } => {
                    if !symlinks.contains_key(digest) {
                        let object = load_symlink(engine, digest)?;
                        if symlink_object_digest_v1(&object) != *digest {
                            unreachable!("verified symlink load checks its identity")
                        }
                        symlinks.insert(digest.clone(), object);
                    }
                }
            }
        }
    }
    TreeGraphV1::new(root.clone(), trees.into_values(), symlinks.into_values())
        .map_err(|error| invalid_tree_graph(engine, root, error.to_string()))
}

fn invalid_tree_graph(engine: &Engine, root: &Digest, detail: impl Into<String>) -> EngineError {
    let kind = CanonicalObjectKind::Tree;
    let path = object_path(engine.config().state_root(), kind, root);
    CanonicalTarget::new(kind, root, &path).error(CanonicalObjectIssue::InvalidEncoding {
        detail: detail.into(),
    })
}

pub(super) fn decode_and_publish<R: Read>(
    engine: &Engine,
    reader: R,
    declaration: ArchiveDeclarationV1,
    limits: ArchiveLimitsV1,
) -> Result<DecodedArchiveV1, ArchivePublicationError> {
    decode_and_publish_with(engine, reader, declaration, limits, |_, _| {})
}

pub(super) fn decode_and_publish_expected<R: Read>(
    engine: &Engine,
    reader: R,
    declaration: ArchiveDeclarationV1,
    limits: ArchiveLimitsV1,
    expected_root: &Digest,
) -> Result<DecodedArchiveV1, ArchivePublicationError> {
    let decoded = decode_archive_v1(reader, declaration, limits)
        .map_err(|source| ArchivePublicationError::Decode { source })?;
    if decoded.root_digest() != expected_root {
        return Err(ArchivePublicationError::UnexpectedRoot {
            expected: expected_root.clone(),
            actual: decoded.root_digest().clone(),
        });
    }
    publish_archive_with(engine, &decoded, &mut |_, _| {})
        .map_err(|source| ArchivePublicationError::Store { source })?;
    Ok(decoded)
}

fn decode_and_publish_with<R, F>(
    engine: &Engine,
    reader: R,
    declaration: ArchiveDeclarationV1,
    limits: ArchiveLimitsV1,
    mut before_link: F,
) -> Result<DecodedArchiveV1, ArchivePublicationError>
where
    R: Read,
    F: FnMut(CanonicalObjectKind, &Digest),
{
    let decoded = decode_archive_v1(reader, declaration, limits)
        .map_err(|source| ArchivePublicationError::Decode { source })?;
    publish_archive_with(engine, &decoded, &mut before_link)
        .map_err(|source| ArchivePublicationError::Store { source })?;
    Ok(decoded)
}

fn publish_archive_with<F>(
    engine: &Engine,
    decoded: &DecodedArchiveV1,
    before_link: &mut F,
) -> Result<(), EngineError>
where
    F: FnMut(CanonicalObjectKind, &Digest),
{
    if engine.config().store_access() != StoreAccess::ReadWrite {
        return Err(EngineError::ReadOnlyStore);
    }
    let ready = engine.open_ready_store()?;
    ready.revalidate()?;
    let publication_lock = PreparedPublicationLock::acquire(engine, &ready)?;
    publication_lock.revalidate(&ready)?;

    if let Some((first_digest, _)) = decoded.objects().file_blobs().first_key_value() {
        let directories =
            ObjectDirectories::open(&ready, CanonicalObjectKind::File, first_digest, true)?
                .expect("archive publication creates the file-object container");
        for (digest, bytes) in decoded.objects().file_blobs() {
            publish_to(
                &ready,
                &directories,
                CanonicalObjectKind::File,
                digest,
                bytes,
                before_link,
            )?;
        }
    }

    if let Some((first_digest, _)) = decoded.objects().symlinks().first_key_value() {
        let directories =
            ObjectDirectories::open(&ready, CanonicalObjectKind::Symlink, first_digest, true)?
                .expect("archive publication creates the symlink-object container");
        for (digest, object) in decoded.objects().symlinks() {
            publish_to(
                &ready,
                &directories,
                CanonicalObjectKind::Symlink,
                digest,
                object.bytes(),
                before_link,
            )?;
        }
    }

    let root_digest = decoded.root_digest();
    let root = decoded
        .objects()
        .trees()
        .get(root_digest)
        .expect("a verified archive retains its root tree object");
    let first_tree_digest = decoded
        .objects()
        .trees()
        .first_key_value()
        .map(|(digest, _)| digest)
        .expect("a verified archive contains at least its root tree");
    let directories =
        ObjectDirectories::open(&ready, CanonicalObjectKind::Tree, first_tree_digest, true)?
            .expect("archive publication creates the tree-object container");
    for (digest, object) in decoded.objects().trees() {
        if digest != root_digest {
            publish_to(
                &ready,
                &directories,
                CanonicalObjectKind::Tree,
                digest,
                object.bytes(),
                before_link,
            )?;
        }
    }
    ready.revalidate()?;
    publish_to(
        &ready,
        &directories,
        CanonicalObjectKind::Tree,
        root_digest,
        root.bytes(),
        before_link,
    )?;
    publication_lock.revalidate(&ready)?;
    ready.revalidate()
}

fn publish_encoded(
    engine: &Engine,
    kind: CanonicalObjectKind,
    expected_digest: &Digest,
    bytes: &[u8],
) -> Result<CanonicalObjectPublication, EngineError> {
    publish_encoded_with(engine, kind, expected_digest, bytes, |_, _| {})
}

fn publish_encoded_with<F>(
    engine: &Engine,
    kind: CanonicalObjectKind,
    expected_digest: &Digest,
    bytes: &[u8],
    mut before_link: F,
) -> Result<CanonicalObjectPublication, EngineError>
where
    F: FnMut(CanonicalObjectKind, &Digest),
{
    if engine.config().store_access() != StoreAccess::ReadWrite {
        return Err(EngineError::ReadOnlyStore);
    }
    let path = object_path(engine.config().state_root(), kind, expected_digest);
    verify_canonical(CanonicalTarget::new(kind, expected_digest, &path), bytes)?;
    let ready = engine.open_ready_store()?;
    ready.revalidate()?;
    let publication_lock = PreparedPublicationLock::acquire(engine, &ready)?;
    publication_lock.revalidate(&ready)?;
    let directories = ObjectDirectories::open(&ready, kind, expected_digest, true)?
        .expect("canonical-object publication creates missing containers");
    let publication = publish_to(
        &ready,
        &directories,
        kind,
        expected_digest,
        bytes,
        &mut before_link,
    )?;
    publication_lock.revalidate(&ready)?;
    Ok(publication)
}

fn publish_to<F>(
    ready: &ReadyStoreRoot<'_>,
    directories: &ObjectDirectories,
    kind: CanonicalObjectKind,
    expected_digest: &Digest,
    bytes: &[u8],
    before_link: &mut F,
) -> Result<CanonicalObjectPublication, EngineError>
where
    F: FnMut(CanonicalObjectKind, &Digest),
{
    let path = object_path(ready.config.state_root(), kind, expected_digest);
    let target = CanonicalTarget::new(kind, expected_digest, &path);
    verify_canonical(target, bytes)?;
    directories.revalidate(ready, expected_digest)?;
    // A cached object is only stat-validated: publication proved its bytes
    // when it was written, and every load digest-checks them again, so a
    // corrupt entry still fails closed at the first consumer.
    match statat(
        &directories.kind,
        expected_digest.as_str(),
        AtFlags::SYMLINK_NOFOLLOW,
    ) {
        Ok(stat) => {
            validate_object_stat(target, &stat, 1, ready.expected_user_id)?;
            return Ok(CanonicalObjectPublication::Reused);
        }
        Err(rustix::io::Errno::NOENT) => {}
        Err(source) => {
            return Err(errno_error("inspect canonical object", &path, source));
        }
    }

    let mut temporary = openat2(
        &directories.kind,
        ".",
        OFlags::TMPFILE | OFlags::RDWR | OFlags::CLOEXEC,
        Mode::from_raw_mode(OBJECT_MODE),
        ROOT_RESOLVE_FLAGS,
    )
    .map(File::from)
    .map_err(|source| errno_error("create unnamed canonical object", &path, source))?;
    fchmod(&temporary, Mode::from_raw_mode(OBJECT_MODE))
        .map_err(|source| errno_error("set unnamed canonical-object mode", &path, source))?;
    temporary
        .write_all(bytes)
        .map_err(|source| io_error("write unnamed canonical object", &path, source))?;
    temporary
        .flush()
        .map_err(|source| io_error("flush unnamed canonical object", &path, source))?;
    fsync(&temporary)
        .map_err(|source| errno_error("sync unnamed canonical object", &path, source))?;
    let staged = fstat(&temporary)
        .map_err(|source| errno_error("inspect unnamed canonical object", &path, source))?;
    validate_object_stat(target, &staged, 0, ready.expected_user_id)?;

    directories.revalidate(ready, expected_digest)?;
    before_link(kind, expected_digest);
    directories.revalidate(ready, expected_digest)?;
    match linkat(
        &temporary,
        "",
        &directories.kind,
        expected_digest.as_str(),
        AtFlags::EMPTY_PATH,
    ) {
        Ok(()) => {
            let published = ensure_object_bound(
                &directories.kind,
                target,
                &temporary,
                ready.expected_user_id,
            )?;
            validate_object_stat(target, &published, 1, ready.expected_user_id)?;
            fsync(&temporary)
                .map_err(|source| errno_error("sync published canonical object", &path, source))?;
            fsync(&directories.kind).map_err(|source| {
                errno_error(
                    "sync canonical-object directory",
                    &directories.kind_path,
                    source,
                )
            })?;
            directories.revalidate(ready, expected_digest)?;
            Ok(CanonicalObjectPublication::Published)
        }
        Err(rustix::io::Errno::EXIST) => {
            read_existing(ready, directories, kind, expected_digest, true)?;
            Ok(CanonicalObjectPublication::Reused)
        }
        Err(source) => Err(errno_error(
            "publish canonical object without replacement",
            &path,
            source,
        )),
    }
}

fn load_encoded(
    engine: &Engine,
    kind: CanonicalObjectKind,
    digest: &Digest,
) -> Result<Vec<u8>, EngineError> {
    let ready = engine.open_ready_store()?;
    ready.revalidate()?;
    let path = object_path(engine.config().state_root(), kind, digest);
    let Some(directories) = ObjectDirectories::open(&ready, kind, digest, false)? else {
        return Err(CanonicalTarget::new(kind, digest, &path).error(CanonicalObjectIssue::Missing));
    };
    read_existing(&ready, &directories, kind, digest, false)
}

struct ObjectDirectories {
    objects: File,
    kind: File,
    objects_path: PathBuf,
    kind_path: PathBuf,
    object_kind: CanonicalObjectKind,
}

impl ObjectDirectories {
    fn open(
        ready: &ReadyStoreRoot<'_>,
        kind: CanonicalObjectKind,
        digest: &Digest,
        create: bool,
    ) -> Result<Option<Self>, EngineError> {
        let objects_path = ready.config.state_root().join(OBJECTS_DIR);
        let Some(objects) = open_container(
            &ready.state_io,
            OBJECTS_DIR,
            CanonicalTarget::new(kind, digest, &objects_path),
            create,
            ready.expected_user_id,
        )?
        else {
            return Ok(None);
        };
        let kind_path = objects_path.join(kind.directory());
        let Some(kind_directory) = open_container(
            &objects,
            kind.directory(),
            CanonicalTarget::new(kind, digest, &kind_path),
            create,
            ready.expected_user_id,
        )?
        else {
            return Ok(None);
        };
        let directories = Self {
            objects,
            kind: kind_directory,
            objects_path,
            kind_path,
            object_kind: kind,
        };
        directories.revalidate(ready, digest)?;
        Ok(Some(directories))
    }

    fn revalidate(&self, ready: &ReadyStoreRoot<'_>, digest: &Digest) -> Result<(), EngineError> {
        ensure_container_bound(
            &ready.state_io,
            OBJECTS_DIR,
            &self.objects,
            CanonicalTarget::new(self.object_kind, digest, &self.objects_path),
            ready.expected_user_id,
        )?;
        ensure_container_bound(
            &self.objects,
            self.object_kind.directory(),
            &self.kind,
            CanonicalTarget::new(self.object_kind, digest, &self.kind_path),
            ready.expected_user_id,
        )?;
        ready.revalidate()
    }
}

fn open_container(
    parent: &File,
    leaf: &str,
    target: CanonicalTarget<'_>,
    create: bool,
    expected_uid: u32,
) -> Result<Option<File>, EngineError> {
    let path = target.path;
    let observed = match statat(parent, leaf, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(stat) => stat,
        Err(rustix::io::Errno::NOENT) if !create => return Ok(None),
        Err(rustix::io::Errno::NOENT) => {
            match mkdirat(parent, leaf, Mode::from_raw_mode(CONTAINER_MODE)) {
                Ok(()) | Err(rustix::io::Errno::EXIST) => {}
                Err(source) => {
                    return Err(errno_error(
                        "create canonical-object container",
                        path,
                        source,
                    ));
                }
            }
            statat(parent, leaf, AtFlags::SYMLINK_NOFOLLOW).map_err(|source| {
                errno_error("inspect created canonical-object container", path, source)
            })?
        }
        Err(source) => {
            return Err(errno_error(
                "inspect canonical-object container",
                path,
                source,
            ));
        }
    };
    validate_container_stat(target, &observed, expected_uid)?;
    let directory = openat2(
        parent,
        leaf,
        DIRECTORY_FLAGS | OFlags::NOFOLLOW | OFlags::NOATIME,
        Mode::empty(),
        ROOT_RESOLVE_FLAGS,
    )
    .map(File::from)
    .map_err(|source| {
        errno_error(
            "open canonical-object container without following symlinks",
            path,
            source,
        )
    })?;
    let opened = fstat(&directory)
        .map_err(|source| errno_error("inspect opened canonical-object container", path, source))?;
    validate_container_stat(target, &opened, expected_uid)?;
    if !same_object(&observed, &opened) {
        return Err(target.error(CanonicalObjectIssue::ObservationChanged));
    }
    if create {
        fsync(&directory)
            .map_err(|source| errno_error("sync canonical-object container", path, source))?;
        fsync(parent).map_err(|source| {
            errno_error("sync canonical-object container parent", path, source)
        })?;
    }
    Ok(Some(directory))
}

fn validate_container_stat(
    target: CanonicalTarget<'_>,
    stat: &Stat,
    expected_uid: u32,
) -> Result<(), EngineError> {
    if FileType::from_raw_mode(stat.st_mode) != FileType::Directory {
        return Err(target.error(CanonicalObjectIssue::ContainerNotDirectory));
    }
    validate_owner(target, stat, expected_uid)?;
    let mode = stat.st_mode & 0o7777;
    if mode != CONTAINER_MODE {
        return Err(target.error(CanonicalObjectIssue::UnexpectedMode {
            expected: CONTAINER_MODE,
            actual: mode,
        }));
    }
    Ok(())
}

fn ensure_container_bound(
    parent: &File,
    leaf: &str,
    directory: &File,
    target: CanonicalTarget<'_>,
    expected_uid: u32,
) -> Result<(), EngineError> {
    let path = target.path;
    let pinned = fstat(directory)
        .map_err(|source| errno_error("inspect pinned canonical-object container", path, source))?;
    validate_container_stat(target, &pinned, expected_uid)?;
    let bound = statat(parent, leaf, AtFlags::SYMLINK_NOFOLLOW).map_err(|source| {
        if source == rustix::io::Errno::NOENT {
            target.error(CanonicalObjectIssue::ObservationChanged)
        } else {
            errno_error(
                "revalidate canonical-object container binding",
                path,
                source,
            )
        }
    })?;
    validate_container_stat(target, &bound, expected_uid)?;
    if !same_object(&pinned, &bound) {
        return Err(target.error(CanonicalObjectIssue::ObservationChanged));
    }
    Ok(())
}

fn read_existing(
    ready: &ReadyStoreRoot<'_>,
    directories: &ObjectDirectories,
    kind: CanonicalObjectKind,
    digest: &Digest,
    sync: bool,
) -> Result<Vec<u8>, EngineError> {
    let path = object_path(ready.config.state_root(), kind, digest);
    let target = CanonicalTarget::new(kind, digest, &path);
    for _ in 0..3 {
        let observed = match statat(
            &directories.kind,
            digest.as_str(),
            AtFlags::SYMLINK_NOFOLLOW,
        ) {
            Ok(stat) => stat,
            Err(rustix::io::Errno::NOENT) => {
                return Err(target.error(CanonicalObjectIssue::Missing));
            }
            Err(source) => return Err(errno_error("inspect canonical object", &path, source)),
        };
        validate_object_stat(target, &observed, 1, ready.expected_user_id)?;
        let mut object = match openat2(
            &directories.kind,
            digest.as_str(),
            OFlags::RDONLY
                | OFlags::NONBLOCK
                | OFlags::NOFOLLOW
                | OFlags::NOATIME
                | OFlags::CLOEXEC,
            Mode::empty(),
            ROOT_RESOLVE_FLAGS,
        ) {
            Ok(object) => File::from(object),
            Err(rustix::io::Errno::NOENT | rustix::io::Errno::LOOP) => continue,
            Err(source) => {
                return Err(errno_error(
                    "open canonical object without following symlinks",
                    &path,
                    source,
                ));
            }
        };
        let opened = fstat(&object)
            .map_err(|source| errno_error("inspect opened canonical object", &path, source))?;
        if !same_file_snapshot(&observed, &opened) {
            continue;
        }
        validate_object_stat(target, &opened, 1, ready.expected_user_id)?;

        let maximum = kind.maximum_bytes();
        let capacity = u64::try_from(opened.st_size).unwrap_or(0).min(maximum);
        let mut bytes = Vec::with_capacity(usize::try_from(capacity).unwrap_or(0));
        Read::by_ref(&mut object)
            .take(maximum.saturating_add(1))
            .read_to_end(&mut bytes)
            .map_err(|source| io_error("read canonical object", &path, source))?;

        let after =
            ensure_object_bound(&directories.kind, target, &object, ready.expected_user_id)?;
        if !same_file_snapshot(&opened, &after) {
            continue;
        }
        let actual = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
        let verification = if actual > maximum {
            Err(target.error(CanonicalObjectIssue::ObjectTooLarge {
                limit: maximum,
                actual,
            }))
        } else {
            verify_canonical(target, &bytes)
        };
        let confirmed =
            ensure_object_bound(&directories.kind, target, &object, ready.expected_user_id)?;
        if !same_file_snapshot(&opened, &confirmed) {
            continue;
        }
        directories.revalidate(ready, digest)?;
        verification?;
        if sync {
            fsync(&object)
                .map_err(|source| errno_error("sync existing canonical object", &path, source))?;
            fsync(&directories.kind).map_err(|source| {
                errno_error(
                    "sync canonical-object directory",
                    &directories.kind_path,
                    source,
                )
            })?;
            let synced =
                ensure_object_bound(&directories.kind, target, &object, ready.expected_user_id)?;
            if !same_file_snapshot(&opened, &synced) {
                continue;
            }
        }
        directories.revalidate(ready, digest)?;
        return Ok(bytes);
    }
    Err(target.error(CanonicalObjectIssue::ObservationChanged))
}

fn ensure_object_bound(
    parent: &File,
    target: CanonicalTarget<'_>,
    object: &File,
    expected_uid: u32,
) -> Result<Stat, EngineError> {
    let path = target.path;
    let pinned = fstat(object)
        .map_err(|source| errno_error("inspect pinned canonical object", path, source))?;
    let bound = match statat(parent, target.digest.as_str(), AtFlags::SYMLINK_NOFOLLOW) {
        Ok(stat) => stat,
        Err(rustix::io::Errno::NOENT) => {
            return Err(target.error(CanonicalObjectIssue::ObservationChanged));
        }
        Err(source) => {
            return Err(errno_error(
                "revalidate canonical-object binding",
                path,
                source,
            ));
        }
    };
    if !same_object(&pinned, &bound) {
        return Err(target.error(CanonicalObjectIssue::ObservationChanged));
    }
    validate_object_stat(target, &pinned, 1, expected_uid)?;
    validate_object_stat(target, &bound, 1, expected_uid)?;
    Ok(pinned)
}

fn validate_object_stat(
    target: CanonicalTarget<'_>,
    stat: &Stat,
    expected_links: u64,
    expected_uid: u32,
) -> Result<(), EngineError> {
    if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile {
        return Err(target.error(CanonicalObjectIssue::ObjectNotRegular));
    }
    validate_owner(target, stat, expected_uid)?;
    let mode = stat.st_mode & 0o7777;
    if mode != OBJECT_MODE {
        return Err(target.error(CanonicalObjectIssue::UnexpectedMode {
            expected: OBJECT_MODE,
            actual: mode,
        }));
    }
    if stat.st_nlink != expected_links {
        return Err(target.error(CanonicalObjectIssue::UnexpectedLinks {
            expected: expected_links,
            actual: stat.st_nlink,
        }));
    }
    let actual = u64::try_from(stat.st_size).unwrap_or(u64::MAX);
    let limit = target.kind.maximum_bytes();
    if actual > limit {
        return Err(target.error(CanonicalObjectIssue::ObjectTooLarge { limit, actual }));
    }
    Ok(())
}

fn validate_owner(
    target: CanonicalTarget<'_>,
    stat: &Stat,
    expected_uid: u32,
) -> Result<(), EngineError> {
    if stat.st_uid != expected_uid {
        return Err(target.error(CanonicalObjectIssue::WrongOwner {
            expected_uid,
            actual_uid: stat.st_uid,
        }));
    }
    Ok(())
}

fn verify_canonical(target: CanonicalTarget<'_>, bytes: &[u8]) -> Result<(), EngineError> {
    let digest = target.digest;
    let result = match target.kind {
        CanonicalObjectKind::File => decode_verified_file_object_v1(digest, bytes).map(|_| ()),
        CanonicalObjectKind::Symlink => {
            decode_verified_symlink_object_v1(digest, bytes).map(|_| ())
        }
        CanonicalObjectKind::Tree => decode_verified_tree_object_v1(digest, bytes).map(|_| ()),
    };
    result.map_err(|error| map_read_error(target, error))
}

fn map_read_error(target: CanonicalTarget<'_>, error: ObjectReadError) -> EngineError {
    let reason = match error {
        ObjectReadError::TooLarge { limit, actual, .. } => CanonicalObjectIssue::ObjectTooLarge {
            limit: u64::try_from(limit).unwrap_or(u64::MAX),
            actual: u64::try_from(actual).unwrap_or(u64::MAX),
        },
        ObjectReadError::DigestMismatch { actual, .. } => {
            CanonicalObjectIssue::DigestMismatch { actual }
        }
        error => CanonicalObjectIssue::InvalidEncoding {
            detail: error.to_string(),
        },
    };
    target.error(reason)
}

fn object_path(root: &Path, kind: CanonicalObjectKind, digest: &Digest) -> PathBuf {
    root.join(OBJECTS_DIR)
        .join(kind.directory())
        .join(digest.as_str())
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;
    use std::os::unix::fs::PermissionsExt;

    use malm_tree::{TreeEntryV1, TreePathSegmentV1, file_object_digest_v1, tree_object_digest_v1};

    use super::*;
    use crate::{EngineConfig, EnginePorts, StoreStatus};

    fn initialized_engine(temp: &tempfile::TempDir) -> Engine {
        let state_home = temp.path().join("state");
        std::fs::create_dir(&state_home).unwrap();
        std::fs::set_permissions(&state_home, std::fs::Permissions::from_mode(0o700)).unwrap();
        let engine = Engine::new(
            EngineConfig::from_state_home(&state_home, StoreAccess::ReadWrite).unwrap(),
            EnginePorts::system(),
        );
        assert_eq!(
            engine.initialize_store().unwrap().status(),
            StoreStatus::Ready
        );
        engine
    }

    #[test]
    fn tree_graph_depth_is_rejected_before_the_out_of_bounds_object_is_read() {
        let temp = tempfile::tempdir().unwrap();
        let engine = initialized_engine(&temp);
        let leaf = TreeObjectV1::new(0o755, vec![]).unwrap();
        let leaf_digest = tree_object_digest_v1(&leaf);
        publish_tree(&engine, &leaf_digest, &leaf).unwrap();
        let mut child = leaf_digest.clone();
        for _ in 0..=MAX_TREE_DEPTH {
            let parent = TreeObjectV1::new(
                0o755,
                vec![
                    TreeEntryV1::directory(TreePathSegmentV1::new("child").unwrap(), 0o755, child)
                        .unwrap(),
                ],
            )
            .unwrap();
            child = tree_object_digest_v1(&parent);
            publish_tree(&engine, &child, &parent).unwrap();
        }
        let root = child;
        std::fs::set_permissions(
            object_path(
                engine.config().state_root(),
                CanonicalObjectKind::Tree,
                &leaf_digest,
            ),
            std::fs::Permissions::from_mode(0o600),
        )
        .unwrap();

        assert!(matches!(
            load_tree_graph(&engine, &root),
            Err(EngineError::CanonicalObject {
                kind: CanonicalObjectKind::Tree,
                digest,
                reason: CanonicalObjectIssue::InvalidEncoding { detail },
                ..
            }) if digest == root && detail.contains("depth")
        ));
    }

    #[test]
    fn corrupt_concurrent_winner_is_preserved_and_rejected() {
        let temp = tempfile::tempdir().unwrap();
        let engine = initialized_engine(&temp);
        let contents = b"canonical contents";
        let bytes = encode_file_object_v1(contents).unwrap();
        let digest = file_object_digest_v1(contents).unwrap();
        let path = object_path(
            engine.config().state_root(),
            CanonicalObjectKind::File,
            &digest,
        );

        let error = publish_encoded_with(
            &engine,
            CanonicalObjectKind::File,
            &digest,
            &bytes,
            |_, _| {
                std::fs::write(&path, b"corrupt winner").unwrap();
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(OBJECT_MODE))
                    .unwrap();
            },
        )
        .unwrap_err();

        assert!(matches!(
            error,
            EngineError::CanonicalObject {
                kind: CanonicalObjectKind::File,
                ..
            }
        ));
        assert_eq!(std::fs::read(path).unwrap(), b"corrupt winner");
    }

    #[test]
    fn archive_root_link_is_attempted_after_every_referenced_object() {
        let temp = tempfile::tempdir().unwrap();
        let engine = initialized_engine(&temp);
        let payload = one_file_archive("nested/file.txt", b"payload");
        let declaration =
            ArchiveDeclarationV1::posix_ustar(payload.len() as u64, Digest::sha256(&payload));
        let expected = decode_archive_v1(
            Cursor::new(&payload),
            declaration.clone(),
            ArchiveLimitsV1::default(),
        )
        .unwrap();
        let root_digest = expected.root_digest().clone();
        let expected_links = expected
            .objects()
            .file_blobs()
            .keys()
            .map(|digest| (CanonicalObjectKind::File, digest.clone()))
            .chain(
                expected
                    .objects()
                    .symlinks()
                    .keys()
                    .map(|digest| (CanonicalObjectKind::Symlink, digest.clone())),
            )
            .chain(
                expected
                    .objects()
                    .trees()
                    .keys()
                    .filter(|digest| *digest != &root_digest)
                    .map(|digest| (CanonicalObjectKind::Tree, digest.clone())),
            )
            .collect::<Vec<_>>();
        let mut links = Vec::new();

        let decoded = decode_and_publish_with(
            &engine,
            Cursor::new(payload),
            declaration,
            ArchiveLimitsV1::default(),
            |kind, digest| {
                if kind == CanonicalObjectKind::Tree && digest == &root_digest {
                    for (expected_kind, expected_digest) in &expected_links {
                        assert!(
                            object_path(
                                engine.config().state_root(),
                                *expected_kind,
                                expected_digest,
                            )
                            .is_file()
                        );
                    }
                    assert!(
                        !object_path(
                            engine.config().state_root(),
                            CanonicalObjectKind::Tree,
                            &root_digest,
                        )
                        .exists()
                    );
                }
                links.push((kind, digest.clone()));
            },
        )
        .unwrap();

        assert_eq!(decoded.root_digest(), &root_digest);
        assert_eq!(
            links.last(),
            Some(&(CanonicalObjectKind::Tree, root_digest))
        );
        for expected_link in expected_links {
            assert!(links[..links.len() - 1].contains(&expected_link));
        }
    }

    #[test]
    fn reviewed_archive_root_mismatch_publishes_no_canonical_objects() {
        let temp = tempfile::tempdir().unwrap();
        let engine = initialized_engine(&temp);
        let payload = one_file_archive("file.txt", b"payload");
        let declaration =
            ArchiveDeclarationV1::posix_ustar(payload.len() as u64, Digest::sha256(&payload));
        let decoded = decode_archive_v1(
            Cursor::new(&payload),
            declaration.clone(),
            ArchiveLimitsV1::default(),
        )
        .unwrap();
        let expected = Digest::sha256(b"different reviewed tree");

        assert!(matches!(
            decode_and_publish_expected(
                &engine,
                Cursor::new(payload),
                declaration,
                ArchiveLimitsV1::default(),
                &expected,
            ),
            Err(ArchivePublicationError::UnexpectedRoot { actual, .. })
                if actual == *decoded.root_digest()
        ));
        for digest in decoded.objects().file_blobs().keys() {
            assert!(
                !object_path(
                    engine.config().state_root(),
                    CanonicalObjectKind::File,
                    digest,
                )
                .exists()
            );
        }
        for digest in decoded.objects().trees().keys() {
            assert!(
                !object_path(
                    engine.config().state_root(),
                    CanonicalObjectKind::Tree,
                    digest,
                )
                .exists()
            );
        }
    }

    #[test]
    fn direct_tree_fixture_uses_domain_separated_file_identity() {
        let contents = b"payload";
        let file_digest = file_object_digest_v1(contents).unwrap();
        assert_ne!(file_digest, Digest::sha256(contents));
        let tree = TreeObjectV1::new(
            0o755,
            vec![
                TreeEntryV1::file(
                    TreePathSegmentV1::new("file").unwrap(),
                    0o644,
                    file_digest,
                    contents.len() as u64,
                )
                .unwrap(),
            ],
        )
        .unwrap();
        assert_eq!(
            tree_object_digest_v1(&tree),
            Digest::sha256(encode_tree_object_v1(&tree))
        );
    }

    fn one_file_archive(path: &str, contents: &[u8]) -> Vec<u8> {
        const BLOCK: usize = 512;
        let mut header = [0_u8; BLOCK];
        header[..path.len()].copy_from_slice(path.as_bytes());
        write_octal(&mut header[100..108], 0o644);
        write_octal(&mut header[108..116], 0);
        write_octal(&mut header[116..124], 0);
        write_octal(&mut header[124..136], contents.len() as u64);
        write_octal(&mut header[136..148], 0);
        header[156] = b'0';
        header[257..263].copy_from_slice(b"ustar\0");
        header[263..265].copy_from_slice(b"00");
        write_octal(&mut header[329..337], 0);
        write_octal(&mut header[337..345], 0);
        header[148..156].fill(b' ');
        let checksum = header.iter().map(|byte| u64::from(*byte)).sum();
        write_octal_digits(&mut header[148..154], checksum);
        header[154] = 0;
        header[155] = b' ';

        let mut archive = header.to_vec();
        archive.extend_from_slice(contents);
        archive.resize(archive.len().next_multiple_of(BLOCK), 0);
        archive.resize(archive.len() + 2 * BLOCK, 0);
        archive
    }

    fn write_octal(field: &mut [u8], mut value: u64) {
        let digits = field.len() - 1;
        field.fill(b'0');
        *field.last_mut().unwrap() = 0;
        for byte in field[..digits].iter_mut().rev() {
            *byte = b'0' + (value & 7) as u8;
            value >>= 3;
        }
        assert_eq!(value, 0);
    }

    fn write_octal_digits(field: &mut [u8], mut value: u64) {
        field.fill(b'0');
        for byte in field.iter_mut().rev() {
            *byte = b'0' + (value & 7) as u8;
            value >>= 3;
        }
        assert_eq!(value, 0);
    }
}
