use std::{
    fs::File,
    io::Write,
    path::{Path, PathBuf},
};

use malm_pack::{
    MAX_PACK_OBJECT_BYTES, PackFileV1, PackObjectReadError, pack_content_digest,
    read_pack_object_v1,
};
use malm_types::Digest;
use rustix::fs::{
    AtFlags, FileType, Mode, OFlags, Stat, fchmod, fstat, fsync, linkat, mkdirat, openat, openat2,
    statat,
};

use super::{
    DIRECTORY_FLAGS, Engine, EngineError, PackObjectIssue, PackObjectPublication,
    ROOT_RESOLVE_FLAGS, ReadyStoreRoot, StoreAccess, errno_error, io_error,
    prepared_store::PreparedPublicationLock, same_file_snapshot, same_object,
};

const OBJECTS_DIR: &str = "objects";
const PACKS_DIR: &str = "packs";
const PACK_MANIFESTS_DIR: &str = "pack-manifests";

/// Domain for deduplicated pack manifests whose members live in the blob store.
/// Reassembly verifies each blob and must reproduce the digest-named pack.
/// Legacy monolithic objects remain readable until pruned.
const PACK_MANIFEST_OBJECT_DOMAIN: &[u8] = b"malm-pack-manifest-object-v1\0";
const PACK_MANIFEST_OBJECT_VERSION: u16 = 1;
const MAX_PACK_MANIFEST_OBJECT_BYTES: u64 = 128 * 1024 * 1024;

/// One member reference inside a pack manifest object.
pub(super) struct PackManifestMemberV1 {
    pub(super) path: malm_pack::PackPath,
    pub(super) blob: Digest,
    pub(super) byte_len: u64,
}

fn encode_pack_manifest_object(members: &[PackManifestMemberV1]) -> Vec<u8> {
    // The decoder requires the logical pack's strict path order.
    let mut ordered: Vec<&PackManifestMemberV1> = members.iter().collect();
    ordered.sort_by(|left, right| left.path.as_str().cmp(right.path.as_str()));
    let members = ordered;
    let mut bytes = Vec::new();
    bytes.extend_from_slice(PACK_MANIFEST_OBJECT_DOMAIN);
    bytes.extend_from_slice(&PACK_MANIFEST_OBJECT_VERSION.to_be_bytes());
    bytes.extend_from_slice(&(members.len() as u64).to_be_bytes());
    for member in members {
        let path = member.path.as_str().as_bytes();
        bytes.extend_from_slice(&(path.len() as u64).to_be_bytes());
        bytes.extend_from_slice(path);
        let digest = member.blob.as_str().as_bytes();
        bytes.extend_from_slice(&(digest.len() as u64).to_be_bytes());
        bytes.extend_from_slice(digest);
        bytes.extend_from_slice(&member.byte_len.to_be_bytes());
    }
    bytes
}

/// Strictly decodes a manifest object; every structural violation fails.
pub(super) fn decode_pack_manifest_object(
    bytes: &[u8],
) -> Result<Vec<PackManifestMemberV1>, String> {
    let rest = bytes
        .strip_prefix(PACK_MANIFEST_OBJECT_DOMAIN)
        .ok_or("wrong pack manifest domain")?;
    let (version, mut rest) = rest.split_at_checked(2).ok_or("truncated version")?;
    if u16::from_be_bytes(version.try_into().expect("split length")) != PACK_MANIFEST_OBJECT_VERSION
    {
        return Err("unsupported pack manifest version".to_owned());
    }
    let (count, tail) = rest.split_at_checked(8).ok_or("truncated count")?;
    rest = tail;
    let count = usize::try_from(u64::from_be_bytes(count.try_into().expect("split length")))
        .map_err(|_| "member count overflows")?;
    if count > 100_000 {
        return Err("member count exceeds the pack entry limit".to_owned());
    }
    let mut take = |length: usize| -> Result<&[u8], String> {
        let (value, tail) = rest.split_at_checked(length).ok_or("truncated member")?;
        rest = tail;
        Ok(value)
    };
    let mut members = Vec::with_capacity(count);
    let mut previous: Option<String> = None;
    for _ in 0..count {
        let path_len = usize::try_from(u64::from_be_bytes(
            take(8)?.try_into().expect("split length"),
        ))
        .map_err(|_| "path length overflows")?;
        if path_len > 1024 {
            return Err("member path exceeds the pack path limit".to_owned());
        }
        let path = std::str::from_utf8(take(path_len)?)
            .map_err(|_| "member path is not UTF-8")?
            .to_owned();
        if previous
            .as_deref()
            .is_some_and(|last| last >= path.as_str())
        {
            return Err("member paths are not strictly ordered".to_owned());
        }
        let digest_len = usize::try_from(u64::from_be_bytes(
            take(8)?.try_into().expect("split length"),
        ))
        .map_err(|_| "digest length overflows")?;
        if digest_len > 128 {
            return Err("member digest exceeds the identifier limit".to_owned());
        }
        let blob = std::str::from_utf8(take(digest_len)?)
            .map_err(|_| "member digest is not UTF-8")?
            .to_owned();
        let byte_len = u64::from_be_bytes(take(8)?.try_into().expect("split length"));
        members.push(PackManifestMemberV1 {
            path: malm_pack::PackPath::new(path.clone())
                .map_err(|error| format!("invalid member path: {error}"))?,
            blob: Digest::new(blob).map_err(|error| format!("invalid member digest: {error}"))?,
            byte_len,
        });
        previous = Some(path);
    }
    if !rest.is_empty() {
        return Err("trailing bytes after the final member".to_owned());
    }
    Ok(members)
}
const CONTAINER_MODE: u32 = 0o700;
const OBJECT_MODE: u32 = 0o400;

/// Pack identity and diagnostic path for one validation operation.
#[derive(Clone, Copy)]
struct PackTarget<'a> {
    digest: &'a Digest,
    path: &'a Path,
}

impl<'a> PackTarget<'a> {
    const fn new(digest: &'a Digest, path: &'a Path) -> Self {
        Self { digest, path }
    }

    fn error(self, reason: PackObjectIssue) -> EngineError {
        EngineError::PackObject {
            digest: self.digest.clone(),
            path: self.path.to_path_buf(),
            reason,
        }
    }
}

pub(super) fn publish(
    engine: &Engine,
    expected_digest: &Digest,
    files: &[PackFileV1],
) -> Result<PackObjectPublication, EngineError> {
    publish_with(engine, expected_digest, files, || {})
}

fn publish_with(
    engine: &Engine,
    expected_digest: &Digest,
    files: &[PackFileV1],
    before_link: impl FnOnce(),
) -> Result<PackObjectPublication, EngineError> {
    if engine.config.store_access() != StoreAccess::ReadWrite {
        return Err(EngineError::ReadOnlyStore);
    }
    let object_path = object_path(engine.config.state_root(), expected_digest);
    let target = PackTarget::new(expected_digest, &object_path);
    let actual = pack_content_digest(files.iter().map(|file| (file.path(), file.bytes())))
        .map_err(|error| {
            target.error(PackObjectIssue::InvalidEncoding {
                detail: error.to_string(),
            })
        })?;
    if &actual != expected_digest {
        return Err(target.error(PackObjectIssue::DigestMismatch { actual }));
    }

    let ready = engine.open_ready_store()?;
    ready.revalidate()?;
    let publication_lock = PreparedPublicationLock::acquire(engine, &ready)?;
    publication_lock.revalidate(&ready)?;
    let directories = PackDirectories::open(&ready, expected_digest, true)?
        .expect("publication creates missing object containers");
    directories.revalidate(&ready, expected_digest)?;

    if object_exists(&directories.packs, target)? {
        read_existing(&ready, &directories, expected_digest)?;
        sync_existing(&ready, &directories, expected_digest)?;
        publication_lock.revalidate(&ready)?;
        return Ok(PackObjectPublication::Reused);
    }
    let manifests = directories
        .manifests
        .as_ref()
        .expect("publication creates the pack-manifest container");
    let manifest_path = directories.manifests_path.join(expected_digest.as_str());
    if object_exists(manifests, PackTarget::new(expected_digest, &manifest_path))? {
        require_manifest_shape(&ready, manifests, expected_digest, &manifest_path)?;
        publication_lock.revalidate(&ready)?;
        return Ok(PackObjectPublication::Reused);
    }

    publish_manifest(
        &ready,
        &directories,
        &publication_lock,
        expected_digest,
        files.iter().map(|file| (file.path(), file.bytes())),
        Some(before_link),
    )
}

/// Publishes one already-verified pack without re-reading a cached object.
///
/// The caller proved the content digest over these exact entries in this
/// process. A cached object is only stat-validated here; its bytes are fully
/// digest-checked again on every load, so corruption still fails closed at
/// the first consumer. A fresh write keeps the full write-time digest check.
pub(super) fn publish_verified(
    engine: &Engine,
    verified_digest: &Digest,
    pack: &malm_module_graph::VerifiedPackV1,
) -> Result<PackObjectPublication, EngineError> {
    if engine.config.store_access() != StoreAccess::ReadWrite {
        return Err(EngineError::ReadOnlyStore);
    }
    let object_path = object_path(engine.config.state_root(), verified_digest);

    let ready = engine.open_ready_store()?;
    ready.revalidate()?;
    let publication_lock = PreparedPublicationLock::acquire(engine, &ready)?;
    publication_lock.revalidate(&ready)?;
    let directories = PackDirectories::open(&ready, verified_digest, true)?
        .expect("publication creates missing object containers");
    directories.revalidate(&ready, verified_digest)?;
    let manifests = directories
        .manifests
        .as_ref()
        .expect("publication creates the pack-manifest container");

    // Both persisted representations are valid cache entries.
    if object_exists(
        &directories.packs,
        PackTarget::new(verified_digest, &object_path),
    )? {
        sync_existing(&ready, &directories, verified_digest)?;
        publication_lock.revalidate(&ready)?;
        return Ok(PackObjectPublication::Reused);
    }
    let manifest_path = directories.manifests_path.join(verified_digest.as_str());
    if object_exists(manifests, PackTarget::new(verified_digest, &manifest_path))? {
        require_manifest_shape(&ready, manifests, verified_digest, &manifest_path)?;
        publication_lock.revalidate(&ready)?;
        return Ok(PackObjectPublication::Reused);
    }

    publish_manifest(
        &ready,
        &directories,
        &publication_lock,
        verified_digest,
        pack.files(),
        None::<fn()>,
    )
}

/// Makes every member durable before linking its no-replace manifest from an
/// unnamed file, so a crash cannot expose a partial pack. The optional hook
/// runs between the container revalidations that guard the link.
fn publish_manifest<'a>(
    ready: &ReadyStoreRoot<'_>,
    directories: &PackDirectories,
    publication_lock: &PreparedPublicationLock,
    digest: &Digest,
    members: impl Iterator<Item = (&'a malm_pack::PackPath, &'a [u8])>,
    before_link: Option<impl FnOnce()>,
) -> Result<PackObjectPublication, EngineError> {
    let manifests = directories
        .manifests
        .as_ref()
        .expect("publication creates the pack-manifest container");
    let manifest_path = directories.manifests_path.join(digest.as_str());

    let prepared_directories = crate::prepared_store::PreparedDirectories::open(ready, true)?
        .expect("publication creates missing object containers");
    let mut entries = Vec::new();
    for (path, bytes) in members {
        let blob = Digest::sha256(bytes);
        crate::prepared_store::publish_blob(ready, &prepared_directories, &blob, bytes)?;
        entries.push(PackManifestMemberV1 {
            path: path.clone(),
            blob,
            byte_len: malm_types::usize_to_u64(bytes.len()),
        });
    }
    let encoded = encode_pack_manifest_object(&entries);

    let mut temporary = openat(
        manifests,
        ".",
        OFlags::TMPFILE | OFlags::RDWR | OFlags::CLOEXEC,
        Mode::from_raw_mode(OBJECT_MODE),
    )
    .map(File::from)
    .map_err(|source| errno_error("create unnamed pack manifest", &manifest_path, source))?;
    fchmod(&temporary, Mode::from_raw_mode(OBJECT_MODE)).map_err(|source| {
        errno_error(
            "set unnamed pack manifest permissions",
            &manifest_path,
            source,
        )
    })?;
    temporary
        .write_all(&encoded)
        .map_err(|source| io_error("write unnamed pack manifest", &manifest_path, source))?;
    temporary
        .flush()
        .map_err(|source| io_error("flush unnamed pack manifest", &manifest_path, source))?;
    fsync(&temporary)
        .map_err(|source| errno_error("sync unnamed pack manifest", &manifest_path, source))?;

    directories.revalidate(ready, digest)?;
    if let Some(before_link) = before_link {
        before_link();
        directories.revalidate(ready, digest)?;
    }
    match linkat(
        &temporary,
        "",
        manifests,
        digest.as_str(),
        AtFlags::EMPTY_PATH,
    ) {
        Ok(()) => {
            fsync(manifests).map_err(|source| {
                errno_error(
                    "sync pack-manifest directory",
                    &directories.manifests_path,
                    source,
                )
            })?;
            directories.revalidate(ready, digest)?;
            publication_lock.revalidate(ready)?;
            Ok(PackObjectPublication::Published)
        }
        Err(rustix::io::Errno::EXIST) => {
            publication_lock.revalidate(ready)?;
            Ok(PackObjectPublication::Reused)
        }
        Err(source) => Err(errno_error(
            "publish pack manifest without replacement",
            &manifest_path,
            source,
        )),
    }
}

fn sync_existing(
    ready: &ReadyStoreRoot<'_>,
    directories: &PackDirectories,
    digest: &Digest,
) -> Result<(), EngineError> {
    let path = object_path(ready.config.state_root(), digest);
    let object = openat2(
        &directories.packs,
        digest.as_str(),
        OFlags::RDONLY | OFlags::NONBLOCK | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
        ROOT_RESOLVE_FLAGS,
    )
    .map(File::from)
    .map_err(|source| errno_error("open existing v1 pack object for sync", &path, source))?;
    let target = PackTarget::new(digest, &path);
    let stat = ensure_object_bound(&directories.packs, &object, target, ready.expected_user_id)?;
    validate_object_stat(target, &stat, 1, ready.expected_user_id)?;
    fsync(&object).map_err(|source| errno_error("sync existing v1 pack object", &path, source))?;
    fsync(&directories.packs).map_err(|source| {
        errno_error(
            "sync existing v1 pack-object directory",
            &directories.packs_path,
            source,
        )
    })?;
    directories.revalidate(ready, digest)
}

pub(super) fn load(engine: &Engine, digest: &Digest) -> Result<Vec<PackFileV1>, EngineError> {
    let ready = engine.open_ready_store()?;
    ready.revalidate()?;
    let object_path = object_path(engine.config.state_root(), digest);
    let Some(directories) = PackDirectories::open(&ready, digest, false)? else {
        return Err(PackTarget::new(digest, &object_path).error(PackObjectIssue::Missing));
    };
    if let Some(manifests) = &directories.manifests {
        let manifest_path = directories.manifests_path.join(digest.as_str());
        if object_exists(manifests, PackTarget::new(digest, &manifest_path))? {
            return load_from_manifest(engine, &ready, &directories, digest);
        }
    }
    read_existing(&ready, &directories, digest)
}

/// Stat-validates and decodes a manifest before reuse. Full digest proof runs
/// when the pack is loaded.
fn require_manifest_shape(
    ready: &ReadyStoreRoot<'_>,
    manifests: &File,
    digest: &Digest,
    manifest_path: &Path,
) -> Result<(), EngineError> {
    let observed = statat(manifests, digest.as_str(), AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|source| errno_error("inspect pack manifest", manifest_path, source))?;
    let target = PackTarget::new(digest, manifest_path);
    validate_object_stat(target, &observed, 1, ready.expected_user_id)?;
    if u64::try_from(observed.st_size).unwrap_or(u64::MAX) > MAX_PACK_MANIFEST_OBJECT_BYTES {
        return Err(target.error(PackObjectIssue::InvalidEncoding {
            detail: "pack manifest exceeds the size limit".to_owned(),
        }));
    }
    let mut object = openat2(
        manifests,
        digest.as_str(),
        OFlags::RDONLY | OFlags::NONBLOCK | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
        ROOT_RESOLVE_FLAGS,
    )
    .map(File::from)
    .map_err(|source| errno_error("open pack manifest", manifest_path, source))?;
    let mut bytes = Vec::new();
    std::io::Read::read_to_end(&mut object, &mut bytes)
        .map_err(|source| io_error("read pack manifest", manifest_path, source))?;
    decode_pack_manifest_object(&bytes)
        .map(drop)
        .map_err(|detail| target.error(PackObjectIssue::InvalidEncoding { detail }))
}

/// Reassembles a pack from verified blobs and requires its content digest to
/// match the manifest name.
fn load_from_manifest(
    engine: &Engine,
    ready: &ReadyStoreRoot<'_>,
    directories: &PackDirectories,
    digest: &Digest,
) -> Result<Vec<PackFileV1>, EngineError> {
    let manifests = directories
        .manifests
        .as_ref()
        .expect("caller proved the manifest container exists");
    let manifest_path = directories.manifests_path.join(digest.as_str());
    let observed = statat(manifests, digest.as_str(), AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|source| errno_error("inspect pack manifest", &manifest_path, source))?;
    let target = PackTarget::new(digest, &manifest_path);
    validate_object_stat(target, &observed, 1, ready.expected_user_id)?;
    let mut object = openat2(
        manifests,
        digest.as_str(),
        OFlags::RDONLY | OFlags::NONBLOCK | OFlags::NOFOLLOW | OFlags::NOATIME | OFlags::CLOEXEC,
        Mode::empty(),
        ROOT_RESOLVE_FLAGS,
    )
    .map(File::from)
    .map_err(|source| errno_error("open pack manifest", &manifest_path, source))?;
    let stat = fstat(&object)
        .map_err(|source| errno_error("inspect opened pack manifest", &manifest_path, source))?;
    if !same_object(&observed, &stat) {
        return Err(target.error(PackObjectIssue::ObservationChanged));
    }
    validate_object_stat(target, &stat, 1, ready.expected_user_id)?;
    if u64::try_from(stat.st_size).unwrap_or(u64::MAX) > MAX_PACK_MANIFEST_OBJECT_BYTES {
        return Err(target.error(PackObjectIssue::InvalidEncoding {
            detail: "pack manifest exceeds the size limit".to_owned(),
        }));
    }
    let mut bytes = Vec::new();
    std::io::Read::read_to_end(&mut object, &mut bytes)
        .map_err(|source| io_error("read pack manifest", &manifest_path, source))?;
    let members = decode_pack_manifest_object(&bytes)
        .map_err(|detail| target.error(PackObjectIssue::InvalidEncoding { detail }))?;
    let files = members
        .into_iter()
        .map(|member| {
            let bytes = crate::prepared_store::load_blob_by_digest(engine, &member.blob)?;
            if malm_types::usize_to_u64(bytes.len()) != member.byte_len {
                return Err(target.error(PackObjectIssue::InvalidEncoding {
                    detail: format!(
                        "member {} length differs from its manifest entry",
                        member.path
                    ),
                }));
            }
            Ok(PackFileV1::new(member.path, bytes))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let actual = pack_content_digest(files.iter().map(|file| (file.path(), file.bytes())))
        .map_err(|error| {
            target.error(PackObjectIssue::InvalidEncoding {
                detail: error.to_string(),
            })
        })?;
    if &actual != digest {
        return Err(target.error(PackObjectIssue::DigestMismatch { actual }));
    }
    Ok(files)
}

struct PackDirectories {
    objects: File,
    packs: File,
    /// Absent on legacy stores opened read-only; publication creates it.
    manifests: Option<File>,
    objects_path: PathBuf,
    packs_path: PathBuf,
    manifests_path: PathBuf,
}

impl PackDirectories {
    fn open(
        ready: &ReadyStoreRoot<'_>,
        digest: &Digest,
        create: bool,
    ) -> Result<Option<Self>, EngineError> {
        let objects_path = ready.config.state_root().join(OBJECTS_DIR);
        let target = PackTarget::new(digest, &objects_path);
        let Some(objects) = open_container(
            &ready.state_io,
            OBJECTS_DIR,
            target,
            create,
            ready.expected_user_id,
        )?
        else {
            return Ok(None);
        };
        let packs_path = objects_path.join(PACKS_DIR);
        let target = PackTarget::new(digest, &packs_path);
        let Some(packs) =
            open_container(&objects, PACKS_DIR, target, create, ready.expected_user_id)?
        else {
            return Ok(None);
        };
        let manifests_path = objects_path.join(PACK_MANIFESTS_DIR);
        let target = PackTarget::new(digest, &manifests_path);
        let manifests = open_container(
            &objects,
            PACK_MANIFESTS_DIR,
            target,
            create,
            ready.expected_user_id,
        )?;
        let directories = Self {
            objects,
            packs,
            manifests,
            objects_path,
            packs_path,
            manifests_path,
        };
        directories.revalidate(ready, digest)?;
        Ok(Some(directories))
    }

    fn revalidate(&self, ready: &ReadyStoreRoot<'_>, digest: &Digest) -> Result<(), EngineError> {
        ensure_container_bound(
            &ready.state_io,
            OBJECTS_DIR,
            &self.objects,
            PackTarget::new(digest, &self.objects_path),
            ready.expected_user_id,
        )?;
        ensure_container_bound(
            &self.objects,
            PACKS_DIR,
            &self.packs,
            PackTarget::new(digest, &self.packs_path),
            ready.expected_user_id,
        )?;
        if let Some(manifests) = &self.manifests {
            ensure_container_bound(
                &self.objects,
                PACK_MANIFESTS_DIR,
                manifests,
                PackTarget::new(digest, &self.manifests_path),
                ready.expected_user_id,
            )?;
        }
        ready.revalidate()
    }
}

fn open_container(
    parent: &File,
    leaf: &str,
    target: PackTarget<'_>,
    create: bool,
    expected_user_id: u32,
) -> Result<Option<File>, EngineError> {
    let path = target.path;
    let observed = match statat(parent, leaf, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(stat) => stat,
        Err(rustix::io::Errno::NOENT) if !create => return Ok(None),
        Err(rustix::io::Errno::NOENT) => {
            match mkdirat(parent, leaf, Mode::from_raw_mode(CONTAINER_MODE)) {
                Ok(()) => {}
                Err(rustix::io::Errno::EXIST) => {}
                Err(source) => {
                    return Err(errno_error("create v1 pack-object container", path, source));
                }
            }
            statat(parent, leaf, AtFlags::SYMLINK_NOFOLLOW).map_err(|source| {
                errno_error("inspect created v1 pack-object container", path, source)
            })?
        }
        Err(source) => {
            return Err(errno_error(
                "inspect v1 pack-object container",
                path,
                source,
            ));
        }
    };
    validate_container_stat(target, &observed, expected_user_id)?;
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
            "open v1 pack-object container without following symlinks",
            path,
            source,
        )
    })?;
    let opened = fstat(&directory)
        .map_err(|source| errno_error("inspect opened pack-object container", path, source))?;
    validate_container_stat(target, &opened, expected_user_id)?;
    if !same_object(&observed, &opened) {
        return Err(target.error(PackObjectIssue::ObservationChanged));
    }
    if create {
        fsync(&directory)
            .map_err(|source| errno_error("sync v1 pack-object container", path, source))?;
        fsync(parent)
            .map_err(|source| errno_error("sync v1 pack-object container parent", path, source))?;
    }
    Ok(Some(directory))
}

fn validate_container_stat(
    target: PackTarget<'_>,
    stat: &Stat,
    expected_user_id: u32,
) -> Result<(), EngineError> {
    if FileType::from_raw_mode(stat.st_mode) != FileType::Directory {
        return Err(target.error(PackObjectIssue::ContainerNotDirectory));
    }
    validate_owner(target, stat, expected_user_id)?;
    let mode = stat.st_mode & 0o7777;
    if mode != CONTAINER_MODE {
        return Err(target.error(PackObjectIssue::UnexpectedMode {
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
    target: PackTarget<'_>,
    expected_user_id: u32,
) -> Result<(), EngineError> {
    let path = target.path;
    let pinned = fstat(directory)
        .map_err(|source| errno_error("inspect pinned pack-object container", path, source))?;
    validate_container_stat(target, &pinned, expected_user_id)?;
    let bound = statat(parent, leaf, AtFlags::SYMLINK_NOFOLLOW).map_err(|source| {
        if source == rustix::io::Errno::NOENT {
            target.error(PackObjectIssue::ObservationChanged)
        } else {
            errno_error("revalidate pack-object container binding", path, source)
        }
    })?;
    validate_container_stat(target, &bound, expected_user_id)?;
    if !same_object(&pinned, &bound) {
        return Err(target.error(PackObjectIssue::ObservationChanged));
    }
    Ok(())
}

fn object_exists(parent: &File, target: PackTarget<'_>) -> Result<bool, EngineError> {
    match statat(parent, target.digest.as_str(), AtFlags::SYMLINK_NOFOLLOW) {
        Ok(_) => Ok(true),
        Err(rustix::io::Errno::NOENT) => Ok(false),
        Err(source) => Err(errno_error("inspect v1 pack object", target.path, source)),
    }
}

fn read_existing(
    ready: &ReadyStoreRoot<'_>,
    directories: &PackDirectories,
    digest: &Digest,
) -> Result<Vec<PackFileV1>, EngineError> {
    let path = object_path(ready.config.state_root(), digest);
    let target = PackTarget::new(digest, &path);
    for _ in 0..3 {
        let observed = match statat(
            &directories.packs,
            digest.as_str(),
            AtFlags::SYMLINK_NOFOLLOW,
        ) {
            Ok(stat) => stat,
            Err(rustix::io::Errno::NOENT) => {
                return Err(target.error(PackObjectIssue::Missing));
            }
            Err(source) => return Err(errno_error("inspect v1 pack object", &path, source)),
        };
        validate_object_stat(target, &observed, 1, ready.expected_user_id)?;
        let mut object = match openat2(
            &directories.packs,
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
                    "open v1 pack object without following symlinks",
                    &path,
                    source,
                ));
            }
        };
        let opened = fstat(&object)
            .map_err(|source| errno_error("inspect opened v1 pack object", &path, source))?;
        if !same_object(&observed, &opened) {
            continue;
        }
        validate_object_stat(target, &opened, 1, ready.expected_user_id)?;
        let files = read_pack_object_v1(&mut object, digest)
            .map_err(|error| map_read_error(target, error))?;
        let final_stat =
            ensure_object_bound(&directories.packs, &object, target, ready.expected_user_id)?;
        if !same_file_snapshot(&opened, &final_stat) {
            continue;
        }
        directories.revalidate(ready, digest)?;
        return Ok(files);
    }
    Err(target.error(PackObjectIssue::ObservationChanged))
}

fn ensure_object_bound(
    parent: &File,
    object: &File,
    target: PackTarget<'_>,
    expected_user_id: u32,
) -> Result<Stat, EngineError> {
    let path = target.path;
    let pinned = fstat(object)
        .map_err(|source| errno_error("inspect pinned v1 pack object", path, source))?;
    let bound = match statat(parent, target.digest.as_str(), AtFlags::SYMLINK_NOFOLLOW) {
        Ok(stat) => stat,
        Err(rustix::io::Errno::NOENT) => {
            return Err(target.error(PackObjectIssue::ObservationChanged));
        }
        Err(source) => {
            return Err(errno_error(
                "revalidate v1 pack-object binding",
                path,
                source,
            ));
        }
    };
    if !same_object(&pinned, &bound) {
        return Err(target.error(PackObjectIssue::ObservationChanged));
    }
    validate_object_stat(target, &pinned, 1, expected_user_id)?;
    validate_object_stat(target, &bound, 1, expected_user_id)?;
    Ok(pinned)
}

fn validate_object_stat(
    target: PackTarget<'_>,
    stat: &Stat,
    expected_links: u64,
    expected_user_id: u32,
) -> Result<(), EngineError> {
    if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile {
        return Err(target.error(PackObjectIssue::ObjectNotRegular));
    }
    validate_owner(target, stat, expected_user_id)?;
    let mode = stat.st_mode & 0o7777;
    if mode != OBJECT_MODE {
        return Err(target.error(PackObjectIssue::UnexpectedMode {
            expected: OBJECT_MODE,
            actual: mode,
        }));
    }
    if stat.st_nlink != expected_links {
        return Err(target.error(PackObjectIssue::UnexpectedLinks {
            expected: expected_links,
            actual: stat.st_nlink,
        }));
    }
    if stat.st_size < 0 || stat.st_size as u64 > MAX_PACK_OBJECT_BYTES {
        return Err(target.error(PackObjectIssue::ObjectTooLarge {
            limit: MAX_PACK_OBJECT_BYTES,
            actual: stat.st_size.max(0) as u64,
        }));
    }
    Ok(())
}

fn validate_owner(
    target: PackTarget<'_>,
    stat: &Stat,
    expected_user_id: u32,
) -> Result<(), EngineError> {
    if stat.st_uid != expected_user_id {
        return Err(target.error(PackObjectIssue::WrongOwner {
            expected_uid: expected_user_id,
            actual_uid: stat.st_uid,
        }));
    }
    Ok(())
}

fn object_path(root: &Path, digest: &Digest) -> PathBuf {
    root.join(OBJECTS_DIR).join(PACKS_DIR).join(digest.as_str())
}

fn map_read_error(target: PackTarget<'_>, error: PackObjectReadError) -> EngineError {
    match error {
        PackObjectReadError::DigestMismatch { actual, .. } => {
            target.error(PackObjectIssue::DigestMismatch { actual })
        }
        PackObjectReadError::Io(source) => io_error("read v1 pack object", target.path, source),
        error => target.error(PackObjectIssue::InvalidEncoding {
            detail: error.to_string(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    use super::*;
    use crate::{EngineConfig, StoreStatus};

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

    fn fixture() -> (Digest, Vec<PackFileV1>) {
        let files = vec![PackFileV1::new(
            malm_pack::PackPath::new("malm-pack.kdl").unwrap(),
            include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../schemas/pack/v1/fixtures/valid/minimal.kdl"
            )),
        )];
        let digest =
            pack_content_digest(files.iter().map(|file| (file.path(), file.bytes()))).unwrap();
        (digest, files)
    }

    #[test]
    fn concurrent_manifest_winner_is_reused_not_replaced() {
        let temp = tempfile::tempdir().unwrap();
        let engine = initialized_engine(&temp);
        let (digest, files) = fixture();
        let manifest_path = engine
            .config
            .state_root()
            .join(OBJECTS_DIR)
            .join(PACK_MANIFESTS_DIR)
            .join(digest.as_str());

        // A concurrent winner is reused without replacement; load re-proves
        // its manifest against the digest name.
        let winner = encode_pack_manifest_object(
            &files
                .iter()
                .map(|file| PackManifestMemberV1 {
                    path: file.path().clone(),
                    blob: Digest::sha256(file.bytes()),
                    byte_len: u64::try_from(file.bytes().len()).unwrap(),
                })
                .collect::<Vec<_>>(),
        );
        let outcome = publish_with(&engine, &digest, &files, || {
            std::fs::write(&manifest_path, &winner).unwrap();
            std::fs::set_permissions(&manifest_path, std::fs::Permissions::from_mode(OBJECT_MODE))
                .unwrap();
        })
        .unwrap();
        assert_eq!(outcome, PackObjectPublication::Reused);
        assert_eq!(
            std::fs::read(&manifest_path).unwrap(),
            winner,
            "the winner's manifest bytes survive"
        );
        assert_eq!(load(&engine, &digest).unwrap(), files);
    }

    #[test]
    fn publication_is_no_replace_and_idempotent() {
        let temp = tempfile::tempdir().unwrap();
        let engine = initialized_engine(&temp);
        let (digest, files) = fixture();

        assert_eq!(
            publish(&engine, &digest, &files).unwrap(),
            PackObjectPublication::Published
        );
        let manifest_path = engine
            .config
            .state_root()
            .join(OBJECTS_DIR)
            .join(PACK_MANIFESTS_DIR)
            .join(digest.as_str());
        let before = std::fs::metadata(&manifest_path).unwrap();
        assert_eq!(before.mode() & 0o7777, OBJECT_MODE);
        assert_eq!(before.nlink(), 1);
        assert_eq!(load(&engine, &digest).unwrap(), files);
        let member = Digest::sha256(files[0].bytes());
        assert!(
            engine
                .config
                .state_root()
                .join("objects/blobs")
                .join(member.as_str())
                .is_file(),
            "the member bytes are a shared artifact blob"
        );

        assert_eq!(
            publish(&engine, &digest, &files).unwrap(),
            PackObjectPublication::Reused
        );
        let after = std::fs::metadata(manifest_path).unwrap();
        assert_eq!(before.dev(), after.dev());
        assert_eq!(before.ino(), after.ino());
    }

    #[test]
    fn legacy_monolithic_objects_stay_readable() {
        let temp = tempfile::tempdir().unwrap();
        let engine = initialized_engine(&temp);
        let (digest, files) = fixture();

        // Seed the legacy monolithic representation with canonical modes.
        let objects = engine.config.state_root().join("objects");
        let packs = objects.join("packs");
        std::fs::create_dir_all(&packs).unwrap();
        for directory in [&objects, &packs] {
            std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let mut encoded = Vec::new();
        malm_pack::write_pack_object_v1(&files, &mut encoded).unwrap();
        let path = packs.join(digest.as_str());
        std::fs::write(&path, &encoded).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(OBJECT_MODE)).unwrap();

        assert_eq!(load(&engine, &digest).unwrap(), files);
        // Publication must reuse the legacy object without replacing it.
        assert_eq!(
            publish(&engine, &digest, &files).unwrap(),
            PackObjectPublication::Reused
        );
        assert_eq!(std::fs::read(&path).unwrap(), encoded);
    }
}
