use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::{self, Read, Write};
use std::path::Path;

use malm_pack::{
    DependencySourceV1, GitSourceV1, LOCK_FILE, LOCK_STAGING_FILE, LockV1, LockedComponentV1,
    LockedDependencyV1, LockedPackV1, LockedSourceV1, MAX_LOCK_BYTES, MAX_LOCK_EDGES,
    MAX_LOCK_NODES, PackManifestV1, encode_lock_v1, pack_node_id,
};
use malm_types::{Digest, PackageId};
use rustix::fs::{
    AtFlags, FileType, FlockOperation, Mode, OFlags, RenameFlags, Stat, fchmod, flock, fstat,
    fsync, linkat, openat, openat2, renameat_with, statat, unlinkat,
};

use super::graph_acquisition::resolve_locator;
use super::pack_capture::{
    PinnedSourceRoot, normalize_source_root, reject_lexical_state_overlap,
    reject_physical_state_overlap,
};
use super::{
    DiscoveredPackV1, Engine, EngineError, GitAcquisitionConfig, LockFileIssue,
    LockFilePublication, LockOperationError, LockOperationOutcome, LockResolutionInputs,
    PackObjectIssue, PackObjectPublication, ROOT_RESOLVE_FLAGS, StoreAccess, same_file_snapshot,
    same_object,
};

const LOCK_MODE: u32 = 0o644;
const MAX_PROCESSED_PACK_BYTES: u64 = malm_module_graph::MAX_GRAPH_OBJECT_BYTES * 2;
const LOCK_FILE_FLAGS: OFlags = OFlags::RDONLY
    .union(OFlags::NONBLOCK)
    .union(OFlags::NOFOLLOW)
    .union(OFlags::CLOEXEC);

#[derive(Clone, Copy)]
enum Operation {
    Create,
    Update,
}

struct ExistingLock {
    file: File,
    snapshot: Stat,
    bytes: Vec<u8>,
    lock: LockV1,
}

struct DiscoveredNode {
    digest: Digest,
    manifest: PackManifestV1,
    pin: Option<PinnedSourceRoot>,
}

struct DiscoveredDependency {
    pack: DiscoveredPackV1,
    pin: Option<PinnedSourceRoot>,
}

struct CooperativeRootLock<'a> {
    directory: &'a File,
}

impl Drop for CooperativeRootLock<'_> {
    fn drop(&mut self) {
        let _ = flock(self.directory, FlockOperation::Unlock);
    }
}

pub(super) fn create(
    engine: &Engine,
    root_source: &Path,
    inputs: &LockResolutionInputs,
    git: &GitAcquisitionConfig,
) -> Result<LockOperationOutcome, LockOperationError> {
    operate(engine, root_source, inputs, git, Operation::Create)
}

pub(super) fn update(
    engine: &Engine,
    root_source: &Path,
    inputs: &LockResolutionInputs,
    git: &GitAcquisitionConfig,
) -> Result<LockOperationOutcome, LockOperationError> {
    operate(engine, root_source, inputs, git, Operation::Update)
}

fn operate(
    engine: &Engine,
    root_source: &Path,
    inputs: &LockResolutionInputs,
    git: &GitAcquisitionConfig,
    operation: Operation,
) -> Result<LockOperationOutcome, LockOperationError> {
    let expected_user_id = engine.effective_user_id();
    if engine.config().store_access() != StoreAccess::ReadWrite {
        return Err(source_error(
            LockedSourceV1::Root,
            EngineError::ReadOnlyStore,
        ));
    }
    let ready = engine
        .open_ready_store()
        .map_err(|error| source_error(LockedSourceV1::Root, error))?;
    ready
        .revalidate()
        .map_err(|error| source_error(LockedSourceV1::Root, error))?;
    let root_path = normalize_source_root(root_source)
        .map_err(|error| source_error(LockedSourceV1::Root, error))?;
    reject_lexical_state_overlap(engine, &root_path)
        .map_err(|error| source_error(LockedSourceV1::Root, error))?;
    let root = PinnedSourceRoot::open(&root_path)
        .map_err(|error| source_error(LockedSourceV1::Root, error))?;
    reject_physical_state_overlap(&ready, root.directory(), &root_path)
        .map_err(|error| source_error(LockedSourceV1::Root, error))?;
    root.revalidate()
        .map_err(|error| source_error(LockedSourceV1::Root, error))?;

    let lock_path = root_path.join(LOCK_FILE);
    match flock(root.directory(), FlockOperation::NonBlockingLockExclusive) {
        Ok(()) => {}
        Err(rustix::io::Errno::WOULDBLOCK) => {
            return Err(lock_file_error(&lock_path, LockFileIssue::Busy));
        }
        Err(source) => return Err(lock_io("lock root pack directory", &lock_path, source)),
    }
    let _operation_lock = CooperativeRootLock {
        directory: root.directory(),
    };
    let existing = match operation {
        Operation::Create => {
            require_absent(root.directory(), &lock_path)?;
            None
        }
        Operation::Update => Some(read_existing(
            root.directory(),
            &lock_path,
            expected_user_id,
        )?),
    };
    cleanup_staging(
        root.directory(),
        &root_path.join(LOCK_STAGING_FILE),
        expected_user_id,
    )?;
    let old_lock = existing.as_ref().map(|existing| &existing.lock);
    let (lock, discovered, mut processed_bytes) =
        resolve_graph(engine, &root_path, &root, inputs, git, old_lock)?;
    let bytes = encode_lock_v1(&lock);
    if bytes.len() > MAX_LOCK_BYTES {
        return Err(LockOperationError::EncodedLockTooLarge {
            limit: MAX_LOCK_BYTES,
            actual: bytes.len(),
        });
    }
    validate_local_snapshots(engine, &root_path, &root, &discovered, &mut processed_bytes)?;
    engine
        .assemble_cached_pack_graph_raw(&lock)
        .map_err(|source| LockOperationError::Assembly { source })?;
    ready
        .revalidate()
        .map_err(|error| source_error(LockedSourceV1::Root, error))?;
    root.revalidate()
        .map_err(|error| source_error(LockedSourceV1::Root, error))?;

    let publication = match (operation, existing) {
        (Operation::Create, None) => {
            publish_create(&root, &lock_path, &bytes, expected_user_id)?;
            LockFilePublication::Created
        }
        (Operation::Update, Some(existing)) if existing.bytes == bytes => {
            revalidate_existing(root.directory(), &lock_path, &existing, expected_user_id)?;
            fsync(&existing.file)
                .map_err(|source| lock_io("sync unchanged lock", &lock_path, source))?;
            fsync(root.directory())
                .map_err(|source| lock_io("sync unchanged root directory", &lock_path, source))?;
            root.revalidate()
                .map_err(|error| source_error(LockedSourceV1::Root, error))?;
            revalidate_existing(root.directory(), &lock_path, &existing, expected_user_id)?;
            LockFilePublication::Unchanged
        }
        (Operation::Update, Some(existing)) => {
            publish_update(&root, &lock_path, &existing, &bytes, expected_user_id)?;
            LockFilePublication::Updated
        }
        _ => unreachable!("operation determines existing-lock state"),
    };
    Ok(LockOperationOutcome::new(lock, publication))
}

fn resolve_graph(
    engine: &Engine,
    root_path: &Path,
    root: &PinnedSourceRoot,
    inputs: &LockResolutionInputs,
    git: &GitAcquisitionConfig,
    old_lock: Option<&LockV1>,
) -> Result<(LockV1, BTreeMap<LockedSourceV1, DiscoveredNode>, u64), LockOperationError> {
    let old_git = old_lock
        .into_iter()
        .flat_map(LockV1::nodes)
        .filter_map(|node| match node.source() {
            LockedSourceV1::Git(source) => Some((source.clone(), node.content_digest().clone())),
            LockedSourceV1::Root | LockedSourceV1::Local(_) => None,
        })
        .collect::<BTreeMap<_, _>>();

    let root_pack = super::pack_capture::discover_and_publish_pinned(engine, root_path, root)
        .map_err(|error| source_error(LockedSourceV1::Root, error))?;
    let mut unique_digests = BTreeSet::from([root_pack.digest.clone()]);
    let mut unique_bytes = root_pack.total_bytes;
    let mut processed_bytes = root_pack.total_bytes;
    if unique_bytes > malm_module_graph::MAX_GRAPH_OBJECT_BYTES {
        return Err(LockOperationError::ResourceLimitExceeded {
            resource: "unique pack bytes",
            limit: malm_module_graph::MAX_GRAPH_OBJECT_BYTES,
            actual: unique_bytes,
        });
    }
    let descriptor_limit = pinned_descriptor_limit(engine);
    let mut pinned_descriptors = root.descriptor_count() as u64;
    if pinned_descriptors > descriptor_limit {
        return Err(LockOperationError::ResourceLimitExceeded {
            resource: "pinned source descriptors",
            limit: descriptor_limit,
            actual: pinned_descriptors,
        });
    }
    let mut discovered = BTreeMap::from([(
        LockedSourceV1::Root,
        DiscoveredNode {
            manifest: root_pack.manifest().clone(),
            digest: root_pack.digest,
            pin: None,
        },
    )]);
    let mut pending = BTreeSet::from([LockedSourceV1::Root]);
    let mut edge_count = 0_usize;

    while let Some(source) = pending.pop_first() {
        let dependencies = discovered[&source].manifest.dependencies().to_vec();
        edge_count = edge_count.saturating_add(dependencies.len());
        if edge_count > MAX_LOCK_EDGES {
            return Err(LockOperationError::Validation {
                source: malm_pack::LockValidationError::TooManyEdges {
                    limit: MAX_LOCK_EDGES,
                    actual: edge_count,
                },
            });
        }
        for dependency in dependencies {
            let target_source = locked_source(dependency.source());
            if !discovered.contains_key(&target_source) {
                if discovered.len() == MAX_LOCK_NODES {
                    return Err(LockOperationError::Validation {
                        source: malm_pack::LockValidationError::TooManyNodes {
                            limit: MAX_LOCK_NODES,
                            actual: MAX_LOCK_NODES + 1,
                        },
                    });
                }
                let discovered_dependency = discover_dependency(
                    &DependencyResolution {
                        engine,
                        root_path,
                        root,
                        inputs,
                        git,
                        old_git: &old_git,
                        descriptor_limit,
                    },
                    &target_source,
                    &mut pinned_descriptors,
                )?;
                processed_bytes =
                    processed_bytes.saturating_add(discovered_dependency.pack.total_bytes);
                if processed_bytes > MAX_PROCESSED_PACK_BYTES {
                    return Err(LockOperationError::ResourceLimitExceeded {
                        resource: "processed pack bytes",
                        limit: MAX_PROCESSED_PACK_BYTES,
                        actual: processed_bytes,
                    });
                }
                if unique_digests.insert(discovered_dependency.pack.digest.clone()) {
                    unique_bytes =
                        unique_bytes.saturating_add(discovered_dependency.pack.total_bytes);
                    if unique_bytes > malm_module_graph::MAX_GRAPH_OBJECT_BYTES {
                        return Err(LockOperationError::ResourceLimitExceeded {
                            resource: "unique pack bytes",
                            limit: malm_module_graph::MAX_GRAPH_OBJECT_BYTES,
                            actual: unique_bytes,
                        });
                    }
                }
                validate_package(
                    &target_source,
                    dependency.package_id(),
                    discovered_dependency.pack.manifest(),
                )?;
                discovered.insert(
                    target_source.clone(),
                    DiscoveredNode {
                        manifest: discovered_dependency.pack.manifest().clone(),
                        digest: discovered_dependency.pack.digest,
                        pin: discovered_dependency.pin,
                    },
                );
                pending.insert(target_source);
            } else {
                validate_package(
                    &target_source,
                    dependency.package_id(),
                    &discovered[&target_source].manifest,
                )?;
            }
        }
    }

    let node_ids = discovered
        .iter()
        .map(|(source, pack)| {
            (
                source.clone(),
                pack_node_id(source, pack.manifest.package_id(), &pack.digest),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let execution_profile = inputs.format_component_execution_profile();
    if execution_profile.is_none()
        && discovered
            .values()
            .any(|pack| !pack.manifest.components().is_empty())
    {
        return Err(LockOperationError::MissingFormatComponentExecutionProfile);
    }
    let mut nodes = Vec::with_capacity(discovered.len());
    for (source, pack) in &discovered {
        let dependencies = pack
            .manifest
            .dependencies()
            .iter()
            .map(|dependency| {
                let target = locked_source(dependency.source());
                LockedDependencyV1::new(dependency.alias().clone(), node_ids[&target].clone())
            })
            .collect();
        let components = pack
            .manifest
            .components()
            .iter()
            .map(|component| {
                LockedComponentV1::from_declaration(
                    component,
                    execution_profile
                        .expect("component presence requires a preflighted execution profile")
                        .clone(),
                )
            })
            .collect();
        nodes.push(
            LockedPackV1::new(
                pack.manifest.package_id().clone(),
                source.clone(),
                pack.digest.clone(),
                dependencies,
                components,
            )
            .map_err(|source| LockOperationError::Validation { source })?,
        );
    }
    let root_node_id = node_ids[&LockedSourceV1::Root].clone();
    let lock = LockV1::new(root_node_id, nodes)
        .map_err(|source| LockOperationError::Validation { source })?;
    Ok((lock, discovered, processed_bytes))
}

/// Fixed capabilities, pins, and resource budget for one dependency walk.
struct DependencyResolution<'a> {
    engine: &'a Engine,
    root_path: &'a Path,
    root: &'a PinnedSourceRoot,
    inputs: &'a LockResolutionInputs,
    git: &'a GitAcquisitionConfig,
    old_git: &'a BTreeMap<GitSourceV1, Digest>,
    descriptor_limit: u64,
}

fn discover_dependency(
    resolution: &DependencyResolution<'_>,
    source: &LockedSourceV1,
    pinned_descriptors: &mut u64,
) -> Result<DiscoveredDependency, LockOperationError> {
    let &DependencyResolution {
        engine,
        root_path,
        root,
        inputs,
        git,
        old_git,
        descriptor_limit,
    } = resolution;
    match source {
        LockedSourceV1::Root => unreachable!("dependencies never use the root source variant"),
        LockedSourceV1::Local(locator) => {
            if !inputs.local_locators().contains(locator) {
                return Err(LockOperationError::LocalSourceNotGranted {
                    locator: locator.clone(),
                });
            }
            let source_path = normalize_source_root(&resolve_locator(root_path, locator))
                .map_err(|error| source_error(source.clone(), error))?;
            reject_lexical_state_overlap(engine, &source_path)
                .map_err(|error| source_error(source.clone(), error))?;
            let required = root.resolved_locator_descriptor_count(locator) as u64;
            let actual = pinned_descriptors.saturating_add(required);
            if actual > descriptor_limit {
                return Err(LockOperationError::ResourceLimitExceeded {
                    resource: "pinned source descriptors",
                    limit: descriptor_limit,
                    actual,
                });
            }
            let pin = root
                .resolve_locator(locator)
                .map_err(|error| source_error(source.clone(), error))?;
            if pin.path() != source_path {
                return Err(source_error(
                    source.clone(),
                    EngineError::PackCapture {
                        root: source_path.clone(),
                        path: source_path.clone(),
                        reason: super::PackCaptureIssue::ObservationChanged,
                    },
                ));
            }
            *pinned_descriptors = actual;
            let pack = super::pack_capture::discover_and_publish_pinned(engine, &source_path, &pin)
                .map_err(|error| source_error(source.clone(), error))?;
            Ok(DiscoveredDependency {
                pack,
                pin: Some(pin),
            })
        }
        LockedSourceV1::Git(git_source) => {
            if !inputs.git_urls().contains(git_source.url()) {
                return Err(LockOperationError::GitSourceNotGranted {
                    url: git_source.url().clone(),
                });
            }
            let expected = old_git.get(git_source);
            let scratch = inputs.git_scratch_roots().get(git_source);
            if expected.is_none() && scratch.is_none() {
                return Err(LockOperationError::MissingGitScratch {
                    git_source: git_source.clone(),
                });
            }
            if let (Some(expected), None) = (expected, scratch) {
                let files = match engine.load_pack_object_raw(expected) {
                    Ok(files) => files,
                    Err(EngineError::PackObject {
                        reason: PackObjectIssue::Missing,
                        ..
                    }) => {
                        return Err(LockOperationError::MissingGitScratch {
                            git_source: git_source.clone(),
                        });
                    }
                    Err(error) => return Err(source_error(source.clone(), error)),
                };
                let verified = malm_module_graph::VerifiedPackV1::from_files(expected, files)
                    .map_err(|error| LockOperationError::CachedPackInvalid {
                        source_identity: source.clone(),
                        digest: expected.clone(),
                        detail: error.to_string(),
                    })?;
                let pack = DiscoveredPackV1::new(
                    expected.clone(),
                    verified,
                    PackObjectPublication::Reused,
                );
                return Ok(DiscoveredDependency { pack, pin: None });
            }
            let scratch_path = scratch
                .expect("new or uncached Git sources require scratch")
                .as_path();
            let result = if let Some(expected) = expected {
                super::git_acquisition::acquire_for_lock(
                    engine,
                    git_source,
                    Some(expected),
                    git,
                    scratch_path,
                )
            } else {
                super::git_acquisition::discover_and_publish(engine, git_source, git, scratch_path)
            };
            result
                .map(|pack| DiscoveredDependency { pack, pin: None })
                .map_err(|error| source_error(source.clone(), error))
        }
    }
}

fn validate_local_snapshots(
    engine: &Engine,
    root_path: &Path,
    root: &PinnedSourceRoot,
    discovered: &BTreeMap<LockedSourceV1, DiscoveredNode>,
    processed_bytes: &mut u64,
) -> Result<(), LockOperationError> {
    for (source, initial) in discovered {
        let (source_path, pin) = match source {
            LockedSourceV1::Root => (root_path.to_path_buf(), root),
            LockedSourceV1::Local(locator) => (
                resolve_locator(root_path, locator),
                initial
                    .pin
                    .as_ref()
                    .expect("local discovered nodes retain their source pin"),
            ),
            LockedSourceV1::Git(_) => continue,
        };
        let final_pack =
            super::pack_capture::discover_and_publish_pinned(engine, &source_path, pin)
                .map_err(|error| source_error(source.clone(), error))?;
        *processed_bytes = processed_bytes.saturating_add(final_pack.total_bytes);
        if *processed_bytes > MAX_PROCESSED_PACK_BYTES {
            return Err(LockOperationError::ResourceLimitExceeded {
                resource: "processed pack bytes",
                limit: MAX_PROCESSED_PACK_BYTES,
                actual: *processed_bytes,
            });
        }
        if final_pack.digest != initial.digest {
            return Err(LockOperationError::SourceChanged {
                source_identity: source.clone(),
                expected: initial.digest.clone(),
                actual: final_pack.digest,
            });
        }
    }
    Ok(())
}

fn validate_package(
    source: &LockedSourceV1,
    expected: &PackageId,
    manifest: &PackManifestV1,
) -> Result<(), LockOperationError> {
    if manifest.package_id() != expected {
        return Err(LockOperationError::PackageMismatch {
            source_identity: source.clone(),
            expected: expected.clone(),
            actual: manifest.package_id().clone(),
        });
    }
    Ok(())
}

fn locked_source(source: &DependencySourceV1) -> LockedSourceV1 {
    match source {
        DependencySourceV1::Git(source) => LockedSourceV1::Git(source.clone()),
        DependencySourceV1::Local(locator) => LockedSourceV1::Local(locator.clone()),
    }
}

fn pinned_descriptor_limit(engine: &Engine) -> u64 {
    const INFRASTRUCTURE_MAXIMUM: u64 = 16_384;
    let available = engine
        .open_file_soft_limit()
        .unwrap_or(INFRASTRUCTURE_MAXIMUM)
        .min(INFRASTRUCTURE_MAXIMUM);
    available.saturating_sub((available / 4).max(64))
}

fn require_absent(root: &File, path: &Path) -> Result<(), LockOperationError> {
    match statat(root, LOCK_FILE, AtFlags::SYMLINK_NOFOLLOW) {
        Err(rustix::io::Errno::NOENT) => Ok(()),
        Ok(_) => Err(lock_file_error(path, LockFileIssue::AlreadyExists)),
        Err(source) => Err(lock_io("inspect lock destination", path, source)),
    }
}

fn read_existing(
    root: &File,
    path: &Path,
    expected_user_id: u32,
) -> Result<ExistingLock, LockOperationError> {
    let observed = match statat(root, LOCK_FILE, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(stat) => stat,
        Err(rustix::io::Errno::NOENT) => {
            return Err(lock_file_error(path, LockFileIssue::Missing));
        }
        Err(source) => return Err(lock_io("inspect existing lock", path, source)),
    };
    validate_lock_stat(path, &observed, 1, expected_user_id)?;
    let mut file = openat2(
        root,
        LOCK_FILE,
        LOCK_FILE_FLAGS,
        Mode::empty(),
        ROOT_RESOLVE_FLAGS,
    )
    .map(File::from)
    .map_err(|source| match source {
        rustix::io::Errno::NOENT | rustix::io::Errno::NOTDIR | rustix::io::Errno::LOOP => {
            lock_file_error(path, LockFileIssue::ObservationChanged)
        }
        _ => lock_io("open existing lock without following links", path, source),
    })?;
    let opened = fstat(&file).map_err(|source| lock_io("inspect opened lock", path, source))?;
    validate_lock_stat(path, &opened, 1, expected_user_id)?;
    if !same_file_snapshot(&observed, &opened) {
        return Err(lock_file_error(path, LockFileIssue::ObservationChanged));
    }
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take((MAX_LOCK_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|source| lock_std_io("read existing lock", path, source))?;
    if bytes.len() > MAX_LOCK_BYTES {
        return Err(lock_file_error(
            path,
            LockFileIssue::TooLarge {
                limit: MAX_LOCK_BYTES,
                actual: bytes.len(),
            },
        ));
    }
    let final_stat = bound_lock_stat(root, path, &file, expected_user_id)?;
    if !same_file_snapshot(&opened, &final_stat) {
        return Err(lock_file_error(path, LockFileIssue::ObservationChanged));
    }
    let lock = malm_pack::decode_lock_v1(&bytes)
        .map_err(|source| lock_file_error(path, LockFileIssue::Invalid { source }))?;
    Ok(ExistingLock {
        file,
        snapshot: final_stat,
        bytes,
        lock,
    })
}

fn revalidate_existing(
    root: &File,
    path: &Path,
    existing: &ExistingLock,
    expected_user_id: u32,
) -> Result<(), LockOperationError> {
    let current = bound_lock_stat(root, path, &existing.file, expected_user_id)?;
    if !same_file_snapshot(&existing.snapshot, &current) {
        return Err(lock_file_error(path, LockFileIssue::ObservationChanged));
    }
    Ok(())
}

fn bound_lock_stat(
    root: &File,
    path: &Path,
    file: &File,
    expected_user_id: u32,
) -> Result<Stat, LockOperationError> {
    let opened = fstat(file).map_err(|source| lock_io("reinspect opened lock", path, source))?;
    let bound = match statat(root, LOCK_FILE, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(stat) => stat,
        Err(rustix::io::Errno::NOENT | rustix::io::Errno::NOTDIR) => {
            return Err(lock_file_error(path, LockFileIssue::ObservationChanged));
        }
        Err(source) => return Err(lock_io("reinspect lock binding", path, source)),
    };
    validate_lock_stat(path, &opened, 1, expected_user_id)?;
    validate_lock_stat(path, &bound, 1, expected_user_id)?;
    if !same_object(&opened, &bound) {
        return Err(lock_file_error(path, LockFileIssue::ObservationChanged));
    }
    Ok(opened)
}

fn validate_lock_stat(
    path: &Path,
    stat: &Stat,
    expected_links: u64,
    expected_user_id: u32,
) -> Result<(), LockOperationError> {
    if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile {
        return Err(lock_file_error(path, LockFileIssue::NotRegular));
    }
    if stat.st_uid != expected_user_id {
        return Err(lock_file_error(
            path,
            LockFileIssue::WrongOwner {
                expected_uid: expected_user_id,
                actual_uid: stat.st_uid,
            },
        ));
    }
    let mode = stat.st_mode & 0o7777;
    if mode != LOCK_MODE {
        return Err(lock_file_error(
            path,
            LockFileIssue::UnexpectedMode {
                expected: LOCK_MODE,
                actual: mode,
            },
        ));
    }
    if stat.st_nlink != expected_links {
        return Err(lock_file_error(
            path,
            LockFileIssue::UnexpectedLinks {
                expected: expected_links,
                actual: stat.st_nlink,
            },
        ));
    }
    let size = u64::try_from(stat.st_size).unwrap_or(u64::MAX);
    if size > MAX_LOCK_BYTES as u64 {
        return Err(lock_file_error(
            path,
            LockFileIssue::TooLarge {
                limit: MAX_LOCK_BYTES,
                actual: usize::try_from(size).unwrap_or(usize::MAX),
            },
        ));
    }
    Ok(())
}

fn publish_create(
    root: &PinnedSourceRoot,
    path: &Path,
    bytes: &[u8],
    expected_user_id: u32,
) -> Result<(), LockOperationError> {
    let temporary = write_temporary(root.directory(), path, bytes, expected_user_id)?;
    root.revalidate()
        .map_err(|error| source_error(LockedSourceV1::Root, error))?;
    require_absent(root.directory(), path)?;
    match linkat(
        &temporary,
        "",
        root.directory(),
        LOCK_FILE,
        AtFlags::EMPTY_PATH,
    ) {
        Ok(()) => {}
        Err(rustix::io::Errno::EXIST) => {
            return Err(lock_file_error(path, LockFileIssue::AlreadyExists));
        }
        Err(source) => return Err(lock_io("publish lock without replacement", path, source)),
    }
    verify_published(root, path, &temporary, bytes, expected_user_id)?;
    Ok(())
}

fn publish_update(
    root: &PinnedSourceRoot,
    path: &Path,
    existing: &ExistingLock,
    bytes: &[u8],
    expected_user_id: u32,
) -> Result<(), LockOperationError> {
    let temporary = write_temporary(root.directory(), path, bytes, expected_user_id)?;
    link_staging(root.directory(), path, &temporary)?;
    let result = (|| {
        root.revalidate()
            .map_err(|error| source_error(LockedSourceV1::Root, error))?;
        revalidate_existing(root.directory(), path, existing, expected_user_id)?;
        renameat_with(
            root.directory(),
            LOCK_STAGING_FILE,
            root.directory(),
            LOCK_FILE,
            RenameFlags::empty(),
        )
        .map_err(|source| lock_io("atomically replace lock", path, source))?;
        verify_published(root, path, &temporary, bytes, expected_user_id)
    })();
    if result.is_err() {
        cleanup_staging(
            root.directory(),
            &path.with_file_name(LOCK_STAGING_FILE),
            expected_user_id,
        )?;
    }
    result
}

fn write_temporary(
    root: &File,
    path: &Path,
    bytes: &[u8],
    expected_user_id: u32,
) -> Result<File, LockOperationError> {
    let mut temporary = openat(
        root,
        ".",
        OFlags::TMPFILE | OFlags::RDWR | OFlags::CLOEXEC,
        Mode::from_raw_mode(LOCK_MODE),
    )
    .map(File::from)
    .map_err(|source| lock_io("create unnamed lock file", path, source))?;
    fchmod(&temporary, Mode::from_raw_mode(LOCK_MODE))
        .map_err(|source| lock_io("set generated lock permissions", path, source))?;
    temporary
        .write_all(bytes)
        .and_then(|()| temporary.flush())
        .map_err(|source| lock_std_io("write generated lock", path, source))?;
    fsync(&temporary).map_err(|source| lock_io("sync generated lock", path, source))?;
    let stat =
        fstat(&temporary).map_err(|source| lock_io("inspect generated lock", path, source))?;
    validate_lock_stat(path, &stat, 0, expected_user_id)?;
    Ok(temporary)
}

fn link_staging(root: &File, path: &Path, temporary: &File) -> Result<(), LockOperationError> {
    match linkat(temporary, "", root, LOCK_STAGING_FILE, AtFlags::EMPTY_PATH) {
        Ok(()) => Ok(()),
        Err(source) => Err(lock_io("link generated lock staging file", path, source)),
    }
}

fn cleanup_staging(
    root: &File,
    path: &Path,
    expected_user_id: u32,
) -> Result<(), LockOperationError> {
    let observed = match statat(root, LOCK_STAGING_FILE, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(stat) => stat,
        Err(rustix::io::Errno::NOENT) => return Ok(()),
        Err(source) => return Err(lock_io("inspect lock staging file", path, source)),
    };
    validate_lock_stat(path, &observed, 1, expected_user_id)?;
    let mut file = openat2(
        root,
        LOCK_STAGING_FILE,
        LOCK_FILE_FLAGS,
        Mode::empty(),
        ROOT_RESOLVE_FLAGS,
    )
    .map(File::from)
    .map_err(|source| match source {
        rustix::io::Errno::NOENT | rustix::io::Errno::NOTDIR | rustix::io::Errno::LOOP => {
            lock_file_error(path, LockFileIssue::ObservationChanged)
        }
        _ => lock_io(
            "open lock staging file without following links",
            path,
            source,
        ),
    })?;
    let opened =
        fstat(&file).map_err(|source| lock_io("inspect opened lock staging file", path, source))?;
    validate_lock_stat(path, &opened, 1, expected_user_id)?;
    if !same_file_snapshot(&observed, &opened) {
        return Err(lock_file_error(path, LockFileIssue::ObservationChanged));
    }
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take((MAX_LOCK_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|source| lock_std_io("read lock staging file", path, source))?;
    if bytes.len() > MAX_LOCK_BYTES {
        return Err(lock_file_error(
            path,
            LockFileIssue::TooLarge {
                limit: MAX_LOCK_BYTES,
                actual: bytes.len(),
            },
        ));
    }
    let final_stat = fstat(&file)
        .map_err(|source| lock_io("reinspect opened lock staging file", path, source))?;
    let bound = statat(root, LOCK_STAGING_FILE, AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|source| lock_io("reinspect lock staging binding", path, source))?;
    validate_lock_stat(path, &final_stat, 1, expected_user_id)?;
    validate_lock_stat(path, &bound, 1, expected_user_id)?;
    if !same_file_snapshot(&opened, &final_stat) || !same_file_snapshot(&opened, &bound) {
        return Err(lock_file_error(path, LockFileIssue::ObservationChanged));
    }
    let lock = malm_pack::decode_lock_v1(&bytes)
        .map_err(|_| lock_file_error(path, LockFileIssue::UnsafeStaging))?;
    if encode_lock_v1(&lock) != bytes {
        return Err(lock_file_error(path, LockFileIssue::UnsafeStaging));
    }
    unlinkat(root, LOCK_STAGING_FILE, AtFlags::empty())
        .map_err(|source| lock_io("remove lock staging file", path, source))?;
    fsync(root).map_err(|source| lock_io("sync lock staging cleanup", path, source))?;
    Ok(())
}

fn verify_published(
    root: &PinnedSourceRoot,
    path: &Path,
    temporary: &File,
    bytes: &[u8],
    expected_user_id: u32,
) -> Result<(), LockOperationError> {
    let published = bound_lock_stat(root.directory(), path, temporary, expected_user_id)?;
    validate_lock_stat(path, &published, 1, expected_user_id)?;
    fsync(root.directory()).map_err(|source| lock_io("sync root pack directory", path, source))?;
    root.revalidate()
        .map_err(|error| source_error(LockedSourceV1::Root, error))?;
    let verified = read_existing(root.directory(), path, expected_user_id)?;
    if verified.bytes != bytes {
        return Err(lock_file_error(path, LockFileIssue::ObservationChanged));
    }
    Ok(())
}

fn source_error(source_identity: LockedSourceV1, source: EngineError) -> LockOperationError {
    LockOperationError::Source {
        source_identity,
        source,
    }
}

fn lock_file_error(path: &Path, reason: LockFileIssue) -> LockOperationError {
    LockOperationError::LockFile {
        path: path.to_path_buf(),
        reason,
    }
}

fn lock_io(operation: &'static str, path: &Path, source: rustix::io::Errno) -> LockOperationError {
    lock_std_io(operation, path, io::Error::from(source))
}

fn lock_std_io(operation: &'static str, path: &Path, source: io::Error) -> LockOperationError {
    lock_file_error(path, LockFileIssue::Io { operation, source })
}
