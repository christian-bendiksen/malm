mod process;

use std::error::Error;
use std::fmt;
use std::fs::File;
use std::io::{self, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use malm_pack::{
    GitSourceV1, LOCK_STAGING_FILE, MAX_PACK_FILE_BYTES, MAX_PACK_TREE_BYTES,
    MAX_PACK_TREE_ENTRIES, PackFileV1, PackPath, PackSubdir, PackTreeError,
    classify_pack_tree_path, pack_content_digest,
};
use malm_types::Digest;
use rustix::fs::{Dir, FileType, fstat};

use super::pack_capture::{
    PinnedSourceRoot, normalize_source_root, reject_lexical_state_overlap,
    reject_physical_state_overlap,
};
use super::ports::GitPackFile;
use super::{
    DiscoveredPackV1, Engine, EngineError, PackCaptureIssue, PackObjectIssue,
    PackObjectPublication, ReadyStoreRoot, StoreAccess,
};

/// Default and maximum wall-clock limit for one Git subprocess.
pub const MAX_GIT_ACQUISITION_TIMEOUT: Duration = Duration::from_secs(600);
/// Default and maximum regular-file growth allowed during one Git fetch.
pub const MAX_GIT_TRANSFER_BYTES: u64 = MAX_PACK_TREE_BYTES * 2;
const MAX_CONTROL_OUTPUT_BYTES: u64 = 64 * 1024;
const MAX_COMMIT_BYTES: u64 = 16 * 1024 * 1024;
const MAX_RAW_TREE_BYTES: u64 = 128 * 1024 * 1024;
const MAX_TOTAL_RAW_TREE_BYTES: u64 = MAX_PACK_TREE_BYTES;
const MAX_BATCH_HEADER_BYTES: usize = 160;
const MAX_GIT_TRAVERSAL_ENTRIES: usize = MAX_PACK_TREE_ENTRIES * 32;

/// Explicit Git executable and subprocess budget for v1 acquisition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GitAcquisitionConfig {
    executable: PathBuf,
    timeout: Duration,
    transfer_limit: u64,
}

impl GitAcquisitionConfig {
    /// Uses the fixed maximum timeout with an explicit absolute executable.
    pub fn new(executable: impl Into<PathBuf>) -> Result<Self, GitAcquisitionConfigError> {
        Self::with_limits(
            executable,
            MAX_GIT_ACQUISITION_TIMEOUT,
            MAX_GIT_TRANSFER_BYTES,
        )
    }

    /// Uses an explicit positive timeout no greater than ten minutes.
    pub fn with_timeout(
        executable: impl Into<PathBuf>,
        timeout: Duration,
    ) -> Result<Self, GitAcquisitionConfigError> {
        Self::with_limits(executable, timeout, MAX_GIT_TRANSFER_BYTES)
    }

    /// Uses explicit positive process and transfer limits within fixed ceilings.
    pub fn with_limits(
        executable: impl Into<PathBuf>,
        timeout: Duration,
        transfer_limit: u64,
    ) -> Result<Self, GitAcquisitionConfigError> {
        let executable = executable.into();
        if !executable.is_absolute() {
            return Err(GitAcquisitionConfigError::ExecutableMustBeAbsolute { executable });
        }
        if timeout.is_zero() {
            return Err(GitAcquisitionConfigError::TimeoutMustBePositive);
        }
        if timeout > MAX_GIT_ACQUISITION_TIMEOUT {
            return Err(GitAcquisitionConfigError::TimeoutTooLarge {
                actual: timeout,
                maximum: MAX_GIT_ACQUISITION_TIMEOUT,
            });
        }
        if transfer_limit == 0 {
            return Err(GitAcquisitionConfigError::TransferLimitMustBePositive);
        }
        if transfer_limit > MAX_GIT_TRANSFER_BYTES {
            return Err(GitAcquisitionConfigError::TransferLimitTooLarge {
                actual: transfer_limit,
                maximum: MAX_GIT_TRANSFER_BYTES,
            });
        }
        Ok(Self {
            executable,
            timeout,
            transfer_limit,
        })
    }

    /// Returns the caller-selected executable without consulting `PATH`.
    #[must_use]
    pub fn executable(&self) -> &Path {
        &self.executable
    }

    /// Returns the per-process wall-clock limit.
    #[must_use]
    pub const fn timeout(&self) -> Duration {
        self.timeout
    }

    /// Returns the maximum regular-file growth allowed during fetch.
    #[must_use]
    pub const fn transfer_limit(&self) -> u64 {
        self.transfer_limit
    }
}

/// Invalid explicit Git process configuration.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
#[non_exhaustive]
pub enum GitAcquisitionConfigError {
    /// Executable lookup through ambient `PATH` is not allowed.
    #[error("Git executable must be absolute, got {}", executable.display())]
    ExecutableMustBeAbsolute {
        /// Rejected executable path.
        executable: PathBuf,
    },
    /// A zero timeout cannot bound a subprocess.
    #[error("Git timeout must be positive")]
    TimeoutMustBePositive,
    /// The requested timeout exceeds the fixed infrastructure ceiling.
    #[error("Git timeout {}s exceeds maximum {}s", actual.as_secs_f64(), maximum.as_secs())]
    TimeoutTooLarge {
        /// Requested timeout.
        actual: Duration,
        /// Maximum timeout.
        maximum: Duration,
    },
    /// A zero-byte transfer budget cannot admit a Git fetch.
    #[error("Git transfer limit must be positive")]
    TransferLimitMustBePositive,
    /// The requested transfer budget exceeds the fixed infrastructure ceiling.
    #[error("Git transfer limit {actual} bytes exceeds maximum {maximum} bytes")]
    TransferLimitTooLarge {
        /// Requested bytes.
        actual: u64,
        /// Maximum bytes.
        maximum: u64,
    },
}

/// Git subprocess stage associated with a bounded process failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GitCommandStage {
    /// Resolve one explicitly granted moving root selector.
    ResolveSelector,
    /// Initialize a fresh bare scratch repository.
    Initialize,
    /// Fetch the one exact locked object ID.
    Fetch,
    /// Read and validate raw Git objects.
    ReadObjects,
}

impl fmt::Display for GitCommandStage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::ResolveSelector => "resolve moving selector",
            Self::Initialize => "initialize scratch repository",
            Self::Fetch => "fetch exact object",
            Self::ReadObjects => "read Git objects",
        })
    }
}

/// Bounded subprocess stream.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GitOutputStream {
    /// Standard output.
    Stdout,
    /// Standard error.
    Stderr,
}

impl fmt::Display for GitOutputStream {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Stdout => "stdout",
            Self::Stderr => "stderr",
        })
    }
}

/// Raw Git object kind required by the acquisition parser.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GitObjectKind {
    /// Commit object selected by the lock.
    Commit,
    /// Tree object traversed without checkout semantics.
    Tree,
    /// Blob object retained as a logical pack file.
    Blob,
}

impl GitObjectKind {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Commit => "commit",
            Self::Tree => "tree",
            Self::Blob => "blob",
        }
    }
}

impl fmt::Display for GitObjectKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Typed exact-Git acquisition or raw-object validation failure.
#[derive(Debug)]
#[non_exhaustive]
pub enum GitAcquisitionIssue {
    /// The selected custom process adapter does not grant moving-reference resolution.
    SelectorResolutionUnavailable,
    /// `ls-remote` output did not identify exactly one supported full commit ID.
    InvalidSelectorOutput {
        /// Deterministic strict-parser detail.
        detail: String,
    },
    /// Scratch must be an explicit absolute path.
    ScratchRootMustBeAbsolute,
    /// Scratch does not exist.
    ScratchRootMissing,
    /// Scratch or an intermediate component is not a directory.
    ScratchRootNotDirectory,
    /// Scratch includes a symbolic path component.
    ScratchRootSymbolicLink,
    /// Scratch is not owned by the effective user.
    ScratchRootWrongOwner {
        /// Required owner.
        expected_uid: u32,
        /// Observed owner.
        actual_uid: u32,
    },
    /// Scratch does not have exact private permissions.
    ScratchRootUnexpectedMode {
        /// Required mode.
        expected: u32,
        /// Observed mode.
        actual: u32,
    },
    /// Caller-owned scratch must be empty on a cache miss.
    ScratchRootNotEmpty,
    /// Scratch overlaps a protected Engine state authority.
    ProtectedStateOverlap,
    /// Scratch pathname binding changed during acquisition.
    ScratchRootObservationChanged,
    /// Git process setup, I/O, supervision, or pipe access failed.
    ProcessIo {
        /// Process stage.
        stage: GitCommandStage,
        /// Static operation description.
        operation: &'static str,
        /// Underlying host failure.
        source: io::Error,
    },
    /// A subprocess exceeded its explicit wall-clock budget.
    Timeout {
        /// Process stage.
        stage: GitCommandStage,
        /// Enforced limit.
        limit: Duration,
    },
    /// A control stream exceeded its fixed capture budget.
    OutputLimitExceeded {
        /// Process stage.
        stage: GitCommandStage,
        /// Stream that exceeded the limit.
        stream: GitOutputStream,
        /// Maximum captured bytes.
        limit: u64,
    },
    /// Fetch-created regular files exceeded the explicit transfer budget.
    TransferLimitExceeded {
        /// Process stage.
        stage: GitCommandStage,
        /// Maximum aggregate growth in bytes.
        limit: u64,
    },
    /// Git exited unsuccessfully.
    ProcessFailed {
        /// Process stage.
        stage: GitCommandStage,
        /// Exit code, absent when terminated by a signal.
        code: Option<i32>,
        /// Bounded control-safe diagnostic text.
        detail: String,
    },
    /// A requested object is absent from the freshly fetched repository.
    MissingObject {
        /// Full raw hexadecimal object ID.
        oid: String,
    },
    /// The exact object or one of its descendants has another Git type.
    UnexpectedObjectType {
        /// Full raw hexadecimal object ID.
        oid: String,
        /// Required kind.
        expected: GitObjectKind,
        /// Returned type token.
        actual: String,
    },
    /// One raw object exceeds its bounded parser budget.
    ObjectTooLarge {
        /// Full raw hexadecimal object ID.
        oid: String,
        /// Required kind.
        kind: GitObjectKind,
        /// Maximum bytes.
        limit: u64,
        /// Header-declared bytes.
        actual: u64,
    },
    /// Commit, tree, or batch framing is malformed.
    MalformedObject {
        /// Object kind being parsed.
        kind: GitObjectKind,
        /// Deterministic parser detail.
        detail: String,
    },
    /// The selected pack subdirectory is absent.
    MissingSubdir {
        /// Required selector.
        subdir: PackSubdir,
    },
    /// A selected subdirectory component is not a tree.
    SubdirNotTree {
        /// Selected path through the failing component.
        path: PackPath,
        /// Raw Git mode.
        mode: String,
    },
    /// One non-reserved committed path name is not UTF-8.
    NonUtf8Name {
        /// Valid parent path, absent at the selected tree root.
        parent: Option<PackPath>,
    },
    /// One selected-tree path is invalid under pack/v1.
    InvalidPath {
        /// Deterministic path validation detail.
        detail: String,
    },
    /// A selected committed entry is a symbolic link.
    SymbolicLink {
        /// Rejected path.
        path: PackPath,
    },
    /// A selected committed entry is a Git submodule link.
    Gitlink {
        /// Rejected path.
        path: PackPath,
    },
    /// A selected committed entry uses another unsupported mode.
    UnsupportedMode {
        /// Rejected path.
        path: PackPath,
        /// Raw mode token.
        mode: String,
    },
    /// Recursive tree work exceeded its fixed entry budget.
    TraversalLimitExceeded {
        /// Maximum entries outside excluded subtrees.
        limit: usize,
    },
    /// The selected tree contains too many regular files.
    TooManyFiles {
        /// Maximum files.
        limit: usize,
        /// First over-limit count.
        actual: usize,
    },
    /// Combined raw tree objects exceed their parser budget.
    RawTreesTooLarge {
        /// Maximum raw tree bytes.
        limit: u64,
        /// Observed raw tree bytes.
        actual: u64,
    },
    /// Selected logical blob bytes exceed the pack limit.
    TreeTooLarge {
        /// Maximum logical bytes.
        limit: u64,
        /// Observed logical bytes.
        actual: u64,
    },
    /// Canonical selected-tree bytes differ from the lock.
    DigestMismatch {
        /// Locked digest.
        expected: Digest,
        /// Captured digest.
        actual: Digest,
    },
    /// Selected bytes do not form a semantically valid pack.
    InvalidPack {
        /// Deterministic verification detail.
        detail: String,
    },
}

impl fmt::Display for GitAcquisitionIssue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SelectorResolutionUnavailable => formatter
                .write_str("the configured Git process adapter cannot resolve moving selectors"),
            Self::InvalidSelectorOutput { detail } => {
                write!(formatter, "invalid Git selector resolution: {detail}")
            }
            Self::ScratchRootMustBeAbsolute => formatter.write_str("scratch root must be absolute"),
            Self::ScratchRootMissing => formatter.write_str("scratch root does not exist"),
            Self::ScratchRootNotDirectory => {
                formatter.write_str("scratch root path contains a non-directory")
            }
            Self::ScratchRootSymbolicLink => {
                formatter.write_str("scratch root path contains a symbolic link")
            }
            Self::ScratchRootWrongOwner {
                expected_uid,
                actual_uid,
            } => write!(
                formatter,
                "scratch owner uid must be {expected_uid}, found {actual_uid}"
            ),
            Self::ScratchRootUnexpectedMode { expected, actual } => write!(
                formatter,
                "scratch mode must be {expected:04o}, found {actual:04o}"
            ),
            Self::ScratchRootNotEmpty => formatter.write_str("scratch root must be empty"),
            Self::ProtectedStateOverlap => {
                formatter.write_str("scratch overlaps the protected state root")
            }
            Self::ScratchRootObservationChanged => {
                formatter.write_str("scratch root binding changed during acquisition")
            }
            Self::ProcessIo {
                stage,
                operation,
                source,
            } => write!(formatter, "{stage}: {operation}: {source}"),
            Self::Timeout { stage, limit } => {
                write!(
                    formatter,
                    "{stage} exceeded the {}s timeout",
                    limit.as_secs_f64()
                )
            }
            Self::OutputLimitExceeded {
                stage,
                stream,
                limit,
            } => write!(formatter, "{stage} {stream} exceeded {limit} bytes"),
            Self::TransferLimitExceeded { stage, limit } => {
                write!(
                    formatter,
                    "{stage} exceeded the {limit}-byte transfer limit"
                )
            }
            Self::ProcessFailed {
                stage,
                code,
                detail,
            } => {
                write!(formatter, "{stage} failed with exit code {code:?}")?;
                if !detail.is_empty() {
                    write!(formatter, ": {detail}")?;
                }
                Ok(())
            }
            Self::MissingObject { oid } => write!(formatter, "Git object {oid} is missing"),
            Self::UnexpectedObjectType {
                oid,
                expected,
                actual,
            } => write!(
                formatter,
                "Git object {oid} must be {expected}, found {actual}"
            ),
            Self::ObjectTooLarge {
                oid,
                kind,
                limit,
                actual,
            } => write!(
                formatter,
                "Git {kind} object {oid} is {actual} bytes; limit is {limit}"
            ),
            Self::MalformedObject { kind, detail } => {
                write!(formatter, "malformed Git {kind} object: {detail}")
            }
            Self::MissingSubdir { subdir } => {
                write!(formatter, "Git pack subdirectory {subdir} is missing")
            }
            Self::SubdirNotTree { path, mode } => {
                write!(
                    formatter,
                    "Git pack subdirectory {path} has mode {mode}, not a tree"
                )
            }
            Self::NonUtf8Name { parent } => match parent {
                Some(parent) => write!(
                    formatter,
                    "Git tree below {parent} contains a non-UTF-8 name"
                ),
                None => formatter.write_str("Git tree contains a non-UTF-8 name"),
            },
            Self::InvalidPath { detail } => formatter.write_str(detail),
            Self::SymbolicLink { path } => {
                write!(formatter, "Git tree path {path} is a symbolic link")
            }
            Self::Gitlink { path } => write!(formatter, "Git tree path {path} is a submodule link"),
            Self::UnsupportedMode { path, mode } => {
                write!(
                    formatter,
                    "Git tree path {path} has unsupported mode {mode}"
                )
            }
            Self::TraversalLimitExceeded { limit } => {
                write!(formatter, "Git tree traversal exceeds {limit} entries")
            }
            Self::TooManyFiles { limit, actual } => {
                write!(
                    formatter,
                    "Git tree contains {actual} files; limit is {limit}"
                )
            }
            Self::RawTreesTooLarge { limit, actual } => write!(
                formatter,
                "Git raw tree data is {actual} bytes; limit is {limit}"
            ),
            Self::TreeTooLarge { limit, actual } => write!(
                formatter,
                "Git selected tree contains {actual} blob bytes; limit is {limit}"
            ),
            Self::DigestMismatch { expected, actual } => write!(
                formatter,
                "Git pack digest mismatch: lock requires {expected}, captured {actual}"
            ),
            Self::InvalidPack { detail } => write!(formatter, "invalid Git pack: {detail}"),
        }
    }
}

impl Error for GitAcquisitionIssue {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        // The cause already appears in Display, and source() would duplicate it.
        None
    }
}

pub(super) fn acquire_and_publish(
    engine: &Engine,
    git_source: &GitSourceV1,
    expected_digest: &Digest,
    config: &GitAcquisitionConfig,
    scratch_root: &Path,
) -> Result<PackObjectPublication, EngineError> {
    acquire_for_lock(
        engine,
        git_source,
        Some(expected_digest),
        config,
        scratch_root,
    )
    .map(|discovered| discovered.publication)
}

pub(super) fn discover_and_publish(
    engine: &Engine,
    git_source: &GitSourceV1,
    config: &GitAcquisitionConfig,
    scratch_root: &Path,
) -> Result<DiscoveredPackV1, EngineError> {
    acquire_for_lock(engine, git_source, None, config, scratch_root)
}

pub(super) fn acquire_for_lock(
    engine: &Engine,
    git_source: &GitSourceV1,
    expected_digest: Option<&Digest>,
    config: &GitAcquisitionConfig,
    scratch_root: &Path,
) -> Result<DiscoveredPackV1, EngineError> {
    if let Some(expected_digest) = expected_digest
        && let Some(cached) = reuse_cached(engine, git_source, expected_digest, scratch_root)?
    {
        return Ok(cached);
    }
    let (scratch_root, scratch, ready) =
        open_fetched_scratch(engine, git_source, config, scratch_root)?;
    let format = GitObjectFormat::from_tagged(git_source.commit().as_str());
    let oid = format.raw_oid(git_source.commit().as_str());
    let files = engine
        .git_process()
        .read_pack(
            config,
            scratch.directory(),
            format,
            oid,
            git_source.subdir().as_str(),
        )
        .map_err(|reason| git_error(git_source, &scratch_root, reason))
        .map(narrow_to_capture_roots)?
        .into_iter()
        .map(|file| {
            let (path, bytes, _) = file.into_mode_parts();
            let path = classify_pack_tree_path(path).map_err(|error| {
                git_error(
                    git_source,
                    &scratch_root,
                    GitAcquisitionIssue::InvalidPath {
                        detail: error.to_string(),
                    },
                )
            })?;
            Ok(path.map(|path| PackFileV1::new(path, bytes)))
        })
        .collect::<Result<Vec<_>, EngineError>>()?
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();

    let actual = pack_content_digest(files.iter().map(|file| (file.path(), file.bytes())))
        .map_err(|error| git_error(git_source, &scratch_root, map_pack_tree_error(error)))?;
    if let Some(expected_digest) = expected_digest
        && &actual != expected_digest
    {
        return Err(git_error(
            git_source,
            &scratch_root,
            GitAcquisitionIssue::DigestMismatch {
                expected: expected_digest.clone(),
                actual,
            },
        ));
    }
    let pack = malm_module_graph::VerifiedPackV1::from_files(&actual, files)
        .map_err(|error| git_error(git_source, &scratch_root, verification_reason(error)))?;
    revalidate_scratch(git_source, &scratch_root, &scratch)?;
    ready.revalidate()?;
    let publication = super::pack_store::publish_verified(engine, &actual, &pack)?;
    Ok(DiscoveredPackV1::new(actual, pack, publication))
}

/// Pins a private scratch root, rejects state overlap, and revalidates it after
/// repository initialization and fetch.
fn open_fetched_scratch<'a>(
    engine: &'a Engine,
    source: &GitSourceV1,
    config: &GitAcquisitionConfig,
    scratch_root: &Path,
) -> Result<(PathBuf, PinnedSourceRoot, ReadyStoreRoot<'a>), EngineError> {
    if engine.config().store_access() != StoreAccess::ReadWrite {
        return Err(EngineError::ReadOnlyStore);
    }
    let scratch_root = normalize_scratch(engine, source, scratch_root)?;
    let ready = engine.open_ready_store()?;
    ready.revalidate()?;
    let scratch = PinnedSourceRoot::open(&scratch_root)
        .map_err(|error| map_scratch_error(source, &scratch_root, error))?;
    reject_physical_state_overlap(&ready, scratch.directory(), &scratch_root)
        .map_err(|error| map_scratch_error(source, &scratch_root, error))?;
    validate_scratch(engine, source, &scratch_root, &scratch)?;
    ready.revalidate()?;

    let format = GitObjectFormat::from_tagged(source.commit().as_str());
    let oid = format.raw_oid(source.commit().as_str());
    engine
        .git_process()
        .initialize(
            config,
            scratch.directory(),
            format,
            MAX_CONTROL_OUTPUT_BYTES,
        )
        .map_err(|reason| git_error(source, &scratch_root, reason))?;
    revalidate_scratch(source, &scratch_root, &scratch)?;
    engine
        .git_process()
        .fetch(
            config,
            scratch.directory(),
            source.url().as_str(),
            oid,
            MAX_CONTROL_OUTPUT_BYTES,
        )
        .map_err(|reason| git_error(source, &scratch_root, reason))?;
    revalidate_scratch(source, &scratch_root, &scratch)?;
    Ok((scratch_root, scratch, ready))
}

pub(super) fn resolve_moving_revision(
    engine: &Engine,
    url: &malm_pack::GitUrl,
    selector: &str,
    config: &GitAcquisitionConfig,
) -> Result<String, GitAcquisitionIssue> {
    engine
        .git_process()
        .resolve_revision(config, url.as_str(), selector, MAX_CONTROL_OUTPUT_BYTES)
}

pub(super) struct ExactGitCheckout {
    config: GitAcquisitionConfig,
    root_source: GitSourceV1,
    scratch_root: PathBuf,
    scratch: PinnedSourceRoot,
}

impl ExactGitCheckout {
    pub(super) fn acquire(
        engine: &Engine,
        source: &GitSourceV1,
        config: &GitAcquisitionConfig,
        scratch_root: &Path,
    ) -> Result<Self, EngineError> {
        let (scratch_root, scratch, ready) =
            open_fetched_scratch(engine, source, config, scratch_root)?;
        ready.revalidate()?;
        Ok(Self {
            config: config.clone(),
            root_source: source.clone(),
            scratch_root,
            scratch,
        })
    }

    pub(super) fn read_pack(
        &self,
        engine: &Engine,
        subdir: &PackSubdir,
    ) -> Result<Vec<GitPackFile>, EngineError> {
        let source = GitSourceV1::new(
            self.root_source.url().clone(),
            self.root_source.commit().clone(),
            subdir.clone(),
        );
        revalidate_scratch(&source, &self.scratch_root, &self.scratch)?;
        let ready = engine.open_ready_store()?;
        ready.revalidate()?;
        let format = GitObjectFormat::from_tagged(source.commit().as_str());
        let oid = format.raw_oid(source.commit().as_str());
        let files = engine
            .git_process()
            .read_pack(
                &self.config,
                self.scratch.directory(),
                format,
                oid,
                subdir.as_str(),
            )
            .map_err(|reason| git_error(&source, &self.scratch_root, reason))?;
        revalidate_scratch(&source, &self.scratch_root, &self.scratch)?;
        ready.revalidate()?;
        Ok(narrow_to_capture_roots(files))
    }
}

/// Narrows an acquired Git tree to the capture roots its manifest declares.
///
/// Local capture prunes non-captured paths during its walk, so this must narrow
/// the same way. Otherwise one commit has two content digests and no lock admits
/// both. `malm.lock` is not pack content and stays for the tracked-root caller,
/// which validates and strips it.
///
/// A missing, oversized, or malformed manifest narrows nothing, as in the local
/// walk, so strict pack verification reports the real problem.
pub(super) fn narrow_to_capture_roots(files: Vec<GitPackFile>) -> Vec<GitPackFile> {
    let Some(manifest) = files
        .iter()
        .find(|file| file.path() == malm_pack::PACK_MANIFEST_FILE)
        .filter(|file| file.bytes().len() <= malm_pack::MAX_PACK_MANIFEST_BYTES)
        .and_then(|file| malm_pack::decode_pack_v1(file.bytes()).ok())
    else {
        return files;
    };
    if manifest.capture_roots().is_empty() {
        return files;
    }
    files
        .into_iter()
        .filter(|file| {
            file.path() == malm_pack::LOCK_FILE || manifest.covers_capture_path(file.path())
        })
        .collect()
}

fn reuse_cached(
    engine: &Engine,
    git_source: &GitSourceV1,
    expected_digest: &Digest,
    diagnostic_scratch: &Path,
) -> Result<Option<DiscoveredPackV1>, EngineError> {
    let files = match engine.load_pack_object_raw(expected_digest) {
        Ok(files) => files,
        Err(EngineError::PackObject {
            reason: PackObjectIssue::Missing,
            ..
        }) => return Ok(None),
        Err(error) => return Err(error),
    };
    let pack = malm_module_graph::VerifiedPackV1::from_files(expected_digest, files)
        .map_err(|error| git_error(git_source, diagnostic_scratch, verification_reason(error)))?;
    Ok(Some(DiscoveredPackV1::new(
        expected_digest.clone(),
        pack,
        PackObjectPublication::Reused,
    )))
}

fn verification_reason(error: malm_module_graph::PackVerificationError) -> GitAcquisitionIssue {
    GitAcquisitionIssue::InvalidPack {
        detail: error.to_string(),
    }
}

fn normalize_scratch(
    engine: &Engine,
    git_source: &GitSourceV1,
    scratch_root: &Path,
) -> Result<PathBuf, EngineError> {
    let normalized = normalize_source_root(scratch_root)
        .map_err(|error| map_scratch_error(git_source, scratch_root, error))?;
    reject_lexical_state_overlap(engine, &normalized)
        .map_err(|error| map_scratch_error(git_source, &normalized, error))?;
    Ok(normalized)
}

fn validate_scratch(
    engine: &Engine,
    git_source: &GitSourceV1,
    scratch_root: &Path,
    scratch: &PinnedSourceRoot,
) -> Result<(), EngineError> {
    let stat = fstat(scratch.directory()).map_err(|source| {
        git_error(
            git_source,
            scratch_root,
            GitAcquisitionIssue::ProcessIo {
                stage: GitCommandStage::Initialize,
                operation: "inspect scratch root",
                source: io::Error::from(source),
            },
        )
    })?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::Directory {
        return Err(git_error(
            git_source,
            scratch_root,
            GitAcquisitionIssue::ScratchRootNotDirectory,
        ));
    }
    let expected_user_id = engine.effective_user_id();
    if stat.st_uid != expected_user_id {
        return Err(git_error(
            git_source,
            scratch_root,
            GitAcquisitionIssue::ScratchRootWrongOwner {
                expected_uid: expected_user_id,
                actual_uid: stat.st_uid,
            },
        ));
    }
    let mode = stat.st_mode & 0o7777;
    if mode != 0o700 {
        return Err(git_error(
            git_source,
            scratch_root,
            GitAcquisitionIssue::ScratchRootUnexpectedMode {
                expected: 0o700,
                actual: mode,
            },
        ));
    }
    if !directory_is_empty(scratch.directory(), git_source, scratch_root)? {
        return Err(git_error(
            git_source,
            scratch_root,
            GitAcquisitionIssue::ScratchRootNotEmpty,
        ));
    }
    Ok(())
}

fn directory_is_empty(
    directory: &File,
    git_source: &GitSourceV1,
    scratch_root: &Path,
) -> Result<bool, EngineError> {
    let mut stream = Dir::read_from(directory).map_err(|source| {
        git_error(
            git_source,
            scratch_root,
            GitAcquisitionIssue::ProcessIo {
                stage: GitCommandStage::Initialize,
                operation: "open scratch root for enumeration",
                source: io::Error::from(source),
            },
        )
    })?;
    while let Some(entry) = stream.read() {
        let entry = entry.map_err(|source| {
            git_error(
                git_source,
                scratch_root,
                GitAcquisitionIssue::ProcessIo {
                    stage: GitCommandStage::Initialize,
                    operation: "enumerate scratch root",
                    source: io::Error::from(source),
                },
            )
        })?;
        if !matches!(entry.file_name().to_bytes(), b"." | b"..") {
            return Ok(false);
        }
    }
    Ok(true)
}

fn revalidate_scratch(
    git_source: &GitSourceV1,
    scratch_root: &Path,
    scratch: &PinnedSourceRoot,
) -> Result<(), EngineError> {
    scratch
        .revalidate()
        .map_err(|error| map_scratch_error(git_source, scratch_root, error))
}

fn map_scratch_error(
    git_source: &GitSourceV1,
    scratch_root: &Path,
    error: EngineError,
) -> EngineError {
    let reason = match error {
        EngineError::PackCapture { reason, .. } => match reason {
            PackCaptureIssue::SourceRootMustBeAbsolute => {
                GitAcquisitionIssue::ScratchRootMustBeAbsolute
            }
            PackCaptureIssue::SourceRootMissing => GitAcquisitionIssue::ScratchRootMissing,
            PackCaptureIssue::SourceRootNotDirectory => {
                GitAcquisitionIssue::ScratchRootNotDirectory
            }
            PackCaptureIssue::SymbolicLink => GitAcquisitionIssue::ScratchRootSymbolicLink,
            PackCaptureIssue::ProtectedStateOverlap => GitAcquisitionIssue::ProtectedStateOverlap,
            PackCaptureIssue::ObservationChanged => {
                GitAcquisitionIssue::ScratchRootObservationChanged
            }
            _ => GitAcquisitionIssue::ScratchRootObservationChanged,
        },
        error => return error,
    };
    git_error(git_source, scratch_root, reason)
}

fn map_pack_tree_error(error: PackTreeError) -> GitAcquisitionIssue {
    GitAcquisitionIssue::InvalidPack {
        detail: error.to_string(),
    }
}

fn git_error(
    git_source: &GitSourceV1,
    scratch_root: &Path,
    reason: GitAcquisitionIssue,
) -> EngineError {
    EngineError::GitAcquisition {
        git_source: Box::new(git_source.clone()),
        scratch_root: scratch_root.to_path_buf(),
        reason,
    }
}

/// Git object hash format selected by an exact locked object ID.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum GitObjectFormat {
    Sha1,
    Sha256,
}

impl GitObjectFormat {
    fn from_tagged(tagged: &str) -> Self {
        if tagged.starts_with("sha1-") {
            Self::Sha1
        } else {
            debug_assert!(tagged.starts_with("sha256-"));
            Self::Sha256
        }
    }

    /// Returns Git's canonical object-format name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Sha1 => "sha1",
            Self::Sha256 => "sha256",
        }
    }

    const fn hex_len(self) -> usize {
        match self {
            Self::Sha1 => 40,
            Self::Sha256 => 64,
        }
    }

    const fn raw_len(self) -> usize {
        match self {
            Self::Sha1 => 20,
            Self::Sha256 => 32,
        }
    }

    fn raw_oid(self, tagged: &str) -> &str {
        &tagged[tagged.len() - self.hex_len()..]
    }

    fn validate_hex(self, value: &str) -> bool {
        value.len() == self.hex_len()
            && value
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    }
}

pub(super) fn read_pack_stream<R: Read, W: Write>(
    reader: R,
    writer: W,
    format: GitObjectFormat,
    commit_oid: &str,
    subdir: &PackSubdir,
) -> Result<Vec<GitPackFile>, GitAcquisitionIssue> {
    let mut batch = Batch::new(reader, writer, format);
    let commit = batch.object(commit_oid, GitObjectKind::Commit, MAX_COMMIT_BYTES)?;
    let root_tree = parse_commit_tree(&commit, format)?;
    let mut budget = TraversalBudget::default();
    let selected_tree = resolve_subdir(&mut batch, format, &root_tree, subdir, &mut budget)?;
    capture_tree(&mut batch, format, &selected_tree, &mut budget)
}

struct Batch<R, W> {
    reader: BufReader<R>,
    writer: W,
    format: GitObjectFormat,
}

#[derive(Default)]
struct TraversalBudget {
    entries: usize,
    raw_tree_bytes: u64,
}

impl TraversalBudget {
    fn charge_tree(&mut self, bytes: usize) -> Result<(), GitAcquisitionIssue> {
        self.raw_tree_bytes = self.raw_tree_bytes.saturating_add(bytes as u64);
        if self.raw_tree_bytes > MAX_TOTAL_RAW_TREE_BYTES {
            return Err(GitAcquisitionIssue::RawTreesTooLarge {
                limit: MAX_TOTAL_RAW_TREE_BYTES,
                actual: self.raw_tree_bytes,
            });
        }
        Ok(())
    }

    fn charge_entry(&mut self) -> Result<(), GitAcquisitionIssue> {
        if self.entries == MAX_GIT_TRAVERSAL_ENTRIES {
            return Err(GitAcquisitionIssue::TraversalLimitExceeded {
                limit: MAX_GIT_TRAVERSAL_ENTRIES,
            });
        }
        self.entries += 1;
        Ok(())
    }
}

impl<R: Read, W: Write> Batch<R, W> {
    fn new(reader: R, writer: W, format: GitObjectFormat) -> Self {
        Self {
            reader: BufReader::new(reader),
            writer,
            format,
        }
    }

    fn object(
        &mut self,
        oid: &str,
        expected: GitObjectKind,
        limit: u64,
    ) -> Result<Vec<u8>, GitAcquisitionIssue> {
        if !self.format.validate_hex(oid) {
            return Err(malformed(
                expected,
                "requested object ID has the wrong format",
            ));
        }
        self.writer
            .write_all(oid.as_bytes())
            .map_err(|source| process_io("write cat-file request", source))?;
        self.writer
            .write_all(b"\n")
            .and_then(|()| self.writer.flush())
            .map_err(|source| process_io("flush cat-file request", source))?;

        let header = read_header(&mut self.reader)?;
        let fields = header.split(|byte| *byte == b' ').collect::<Vec<_>>();
        if fields.len() == 2 && fields[1] == b"missing" {
            return Err(GitAcquisitionIssue::MissingObject {
                oid: oid.to_owned(),
            });
        }
        if fields.len() != 3 {
            return Err(malformed(expected, "invalid cat-file batch header"));
        }
        let returned_oid = std::str::from_utf8(fields[0])
            .map_err(|_| malformed(expected, "batch object ID is not ASCII"))?;
        if returned_oid != oid || !self.format.validate_hex(returned_oid) {
            return Err(malformed(expected, "batch returned another object ID"));
        }
        let actual_type = std::str::from_utf8(fields[1])
            .map_err(|_| malformed(expected, "batch object type is not ASCII"))?;
        if actual_type != expected.as_str() {
            return Err(GitAcquisitionIssue::UnexpectedObjectType {
                oid: oid.to_owned(),
                expected,
                actual: actual_type.to_owned(),
            });
        }
        let size_text = std::str::from_utf8(fields[2])
            .map_err(|_| malformed(expected, "batch object size is not ASCII"))?;
        if size_text.is_empty() || !size_text.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(malformed(expected, "batch object size is not decimal"));
        }
        let size = size_text
            .parse::<u64>()
            .map_err(|_| malformed(expected, "batch object size overflows u64"))?;
        if size > limit {
            return Err(GitAcquisitionIssue::ObjectTooLarge {
                oid: oid.to_owned(),
                kind: expected,
                limit,
                actual: size,
            });
        }
        let size_usize = usize::try_from(size)
            .map_err(|_| malformed(expected, "batch object size does not fit memory"))?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(size_usize)
            .map_err(|_| malformed(expected, "cannot reserve memory for batch object"))?;
        bytes.resize(size_usize, 0);
        self.reader
            .read_exact(&mut bytes)
            .map_err(|source| process_io("read cat-file object body", source))?;
        let mut separator = [0_u8; 1];
        self.reader
            .read_exact(&mut separator)
            .map_err(|source| process_io("read cat-file object separator", source))?;
        if separator != *b"\n" {
            return Err(malformed(expected, "batch object body lacks final newline"));
        }
        Ok(bytes)
    }
}

fn read_header(reader: &mut impl Read) -> Result<Vec<u8>, GitAcquisitionIssue> {
    let mut header = Vec::new();
    loop {
        let mut byte = [0_u8; 1];
        reader
            .read_exact(&mut byte)
            .map_err(|source| process_io("read cat-file batch header", source))?;
        if byte[0] == b'\n' {
            return Ok(header);
        }
        if header.len() == MAX_BATCH_HEADER_BYTES {
            return Err(malformed(
                GitObjectKind::Blob,
                "cat-file batch header exceeds its limit",
            ));
        }
        header.push(byte[0]);
    }
}

fn parse_commit_tree(bytes: &[u8], format: GitObjectFormat) -> Result<String, GitAcquisitionIssue> {
    let Some(headers_end) = bytes.windows(2).position(|window| window == b"\n\n") else {
        return Err(malformed(
            GitObjectKind::Commit,
            "commit has no header terminator",
        ));
    };
    let mut tree = None;
    for line in bytes[..headers_end].split(|byte| *byte == b'\n') {
        let Some(value) = line.strip_prefix(b"tree ") else {
            continue;
        };
        let value = std::str::from_utf8(value)
            .map_err(|_| malformed(GitObjectKind::Commit, "tree ID is not ASCII"))?;
        if !format.validate_hex(value) {
            return Err(malformed(
                GitObjectKind::Commit,
                "tree ID has the wrong object format",
            ));
        }
        if tree.replace(value.to_owned()).is_some() {
            return Err(malformed(
                GitObjectKind::Commit,
                "commit contains duplicate tree headers",
            ));
        }
    }
    tree.ok_or_else(|| malformed(GitObjectKind::Commit, "commit has no tree header"))
}

fn resolve_subdir<R: Read, W: Write>(
    batch: &mut Batch<R, W>,
    format: GitObjectFormat,
    root_tree: &str,
    subdir: &PackSubdir,
    budget: &mut TraversalBudget,
) -> Result<String, GitAcquisitionIssue> {
    let PackSubdir::Path(subdir_path) = subdir else {
        return Ok(root_tree.to_owned());
    };
    let mut current_tree = root_tree.to_owned();
    let mut selected = String::new();
    for segment in subdir_path.as_str().split('/') {
        let entries = read_tree(batch, format, &current_tree, budget)?;
        let Some(entry) = entries
            .iter()
            .find(|entry| entry.name == segment.as_bytes())
        else {
            return Err(GitAcquisitionIssue::MissingSubdir {
                subdir: subdir.clone(),
            });
        };
        if !selected.is_empty() {
            selected.push('/');
        }
        selected.push_str(segment);
        let path =
            PackPath::new(selected.clone()).expect("subdir prefixes remain valid pack paths");
        if entry.mode != TreeMode::Tree {
            return Err(GitAcquisitionIssue::SubdirNotTree {
                path,
                mode: entry.mode.as_str().to_owned(),
            });
        }
        current_tree = entry.oid.clone();
    }
    Ok(current_tree)
}

fn capture_tree<R: Read, W: Write>(
    batch: &mut Batch<R, W>,
    format: GitObjectFormat,
    selected_tree: &str,
    budget: &mut TraversalBudget,
) -> Result<Vec<GitPackFile>, GitAcquisitionIssue> {
    let mut stack = vec![(selected_tree.to_owned(), String::new())];
    let mut blobs = Vec::<(String, String, u32)>::new();

    while let Some((tree_oid, parent)) = stack.pop() {
        for entry in read_tree(batch, format, &tree_oid, budget)? {
            if entry.name == b".git" || entry.name == LOCK_STAGING_FILE.as_bytes() {
                continue;
            }
            let name =
                std::str::from_utf8(&entry.name).map_err(|_| GitAcquisitionIssue::NonUtf8Name {
                    parent: if parent.is_empty() {
                        None
                    } else {
                        Some(PackPath::new(parent.clone()).expect("parent path was validated"))
                    },
                })?;
            let logical = if parent.is_empty() {
                name.to_owned()
            } else {
                format!("{parent}/{name}")
            };
            let path = classify_git_tree_path(logical)?;
            let Some(path) = path else {
                continue;
            };
            match entry.mode {
                TreeMode::Tree if path == malm_pack::LOCK_FILE => {
                    return Err(GitAcquisitionIssue::InvalidPath {
                        detail: "tracked root malm.lock must be a regular file".to_owned(),
                    });
                }
                TreeMode::Tree => stack.push((entry.oid, path)),
                TreeMode::Regular(mode) => {
                    if blobs.len() == MAX_PACK_TREE_ENTRIES {
                        return Err(GitAcquisitionIssue::TooManyFiles {
                            limit: MAX_PACK_TREE_ENTRIES,
                            actual: MAX_PACK_TREE_ENTRIES + 1,
                        });
                    }
                    blobs.push((path, entry.oid, mode));
                }
                TreeMode::Symlink if path == malm_pack::LOCK_FILE => {
                    return Err(GitAcquisitionIssue::InvalidPath {
                        detail: "tracked root malm.lock must be a regular file".to_owned(),
                    });
                }
                TreeMode::Symlink => {
                    return Err(GitAcquisitionIssue::SymbolicLink {
                        path: PackPath::new(path).expect("non-lock selected paths are pack paths"),
                    });
                }
                TreeMode::Gitlink if path == malm_pack::LOCK_FILE => {
                    return Err(GitAcquisitionIssue::InvalidPath {
                        detail: "tracked root malm.lock must be a regular file".to_owned(),
                    });
                }
                TreeMode::Gitlink => {
                    return Err(GitAcquisitionIssue::Gitlink {
                        path: PackPath::new(path).expect("non-lock selected paths are pack paths"),
                    });
                }
                TreeMode::Unsupported(ref mode) => {
                    return Err(GitAcquisitionIssue::UnsupportedMode {
                        path: PackPath::new(path).map_err(|error| {
                            GitAcquisitionIssue::InvalidPath {
                                detail: error.to_string(),
                            }
                        })?,
                        mode: mode.clone(),
                    });
                }
            }
        }
    }

    blobs.sort_by(|left, right| left.0.cmp(&right.0));
    let mut files = Vec::with_capacity(blobs.len());
    let mut total = 0_u64;
    for (path, oid, mode) in blobs {
        let bytes = batch.object(&oid, GitObjectKind::Blob, MAX_PACK_FILE_BYTES)?;
        total = total.saturating_add(bytes.len() as u64);
        if total > MAX_PACK_TREE_BYTES {
            return Err(GitAcquisitionIssue::TreeTooLarge {
                limit: MAX_PACK_TREE_BYTES,
                actual: total,
            });
        }
        files.push(
            GitPackFile::with_mode(path, bytes, mode)
                .expect("raw Git parser emits only normalized regular-file modes"),
        );
    }
    Ok(files)
}

fn classify_git_tree_path(logical: String) -> Result<Option<String>, GitAcquisitionIssue> {
    if logical == malm_pack::LOCK_FILE {
        return Ok(Some(logical));
    }
    classify_pack_tree_path(logical)
        .map(|path| path.map(PackPath::into_inner))
        .map_err(|error| GitAcquisitionIssue::InvalidPath {
            detail: error.to_string(),
        })
}

fn read_tree<R: Read, W: Write>(
    batch: &mut Batch<R, W>,
    format: GitObjectFormat,
    oid: &str,
    budget: &mut TraversalBudget,
) -> Result<Vec<TreeEntry>, GitAcquisitionIssue> {
    let bytes = batch.object(oid, GitObjectKind::Tree, MAX_RAW_TREE_BYTES)?;
    budget.charge_tree(bytes.len())?;
    parse_tree(&bytes, format, budget)
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum TreeMode {
    Tree,
    Regular(u32),
    Symlink,
    Gitlink,
    Unsupported(String),
}

impl TreeMode {
    fn from_bytes(bytes: &[u8]) -> Self {
        match bytes {
            b"40000" => Self::Tree,
            b"100644" => Self::Regular(0o644),
            b"100755" => Self::Regular(0o755),
            b"120000" => Self::Symlink,
            b"160000" => Self::Gitlink,
            _ => Self::Unsupported(String::from_utf8_lossy(bytes).into_owned()),
        }
    }

    fn as_str(&self) -> &str {
        match self {
            Self::Tree => "40000",
            Self::Regular(0o644) => "100644",
            Self::Regular(0o755) => "100755",
            Self::Regular(_) => unreachable!("regular modes are normalized while parsing"),
            Self::Symlink => "120000",
            Self::Gitlink => "160000",
            Self::Unsupported(mode) => mode,
        }
    }
}

struct TreeEntry {
    mode: TreeMode,
    name: Vec<u8>,
    oid: String,
}

fn parse_tree(
    bytes: &[u8],
    format: GitObjectFormat,
    budget: &mut TraversalBudget,
) -> Result<Vec<TreeEntry>, GitAcquisitionIssue> {
    let mut entries = Vec::new();
    let mut position = 0_usize;
    while position < bytes.len() {
        let Some(space) = bytes[position..].iter().position(|byte| *byte == b' ') else {
            return Err(malformed(
                GitObjectKind::Tree,
                "tree entry has no mode separator",
            ));
        };
        let mode_end = position + space;
        let mode = TreeMode::from_bytes(&bytes[position..mode_end]);
        position = mode_end + 1;
        let Some(nul) = bytes[position..].iter().position(|byte| *byte == 0) else {
            return Err(malformed(
                GitObjectKind::Tree,
                "tree entry has no name terminator",
            ));
        };
        let name_end = position + nul;
        let name = bytes[position..name_end].to_vec();
        if name.is_empty() || name.contains(&b'/') {
            return Err(malformed(
                GitObjectKind::Tree,
                "tree entry has an invalid raw name",
            ));
        }
        budget.charge_entry()?;
        position = name_end + 1;
        let oid_end = position.saturating_add(format.raw_len());
        if oid_end > bytes.len() {
            return Err(malformed(
                GitObjectKind::Tree,
                "tree entry has a truncated object ID",
            ));
        }
        let oid = encode_hex(&bytes[position..oid_end]);
        position = oid_end;
        entries.push(TreeEntry { mode, name, oid });
    }
    let mut names = entries
        .iter()
        .map(|entry| entry.name.as_slice())
        .collect::<Vec<_>>();
    names.sort_unstable();
    if names.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(malformed(
            GitObjectKind::Tree,
            "tree contains duplicate names",
        ));
    }
    Ok(entries)
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[usize::from(byte >> 4)] as char);
        output.push(HEX[usize::from(byte & 0x0f)] as char);
    }
    output
}

fn process_io(operation: &'static str, source: io::Error) -> GitAcquisitionIssue {
    GitAcquisitionIssue::ProcessIo {
        stage: GitCommandStage::ReadObjects,
        operation,
        source,
    }
}

fn malformed(kind: GitObjectKind, detail: impl Into<String>) -> GitAcquisitionIssue {
    GitAcquisitionIssue::MalformedObject {
        kind,
        detail: detail.into(),
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;

    const MINIMAL_PACK: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../schemas/pack/v1/fixtures/valid/minimal.kdl"
    ));

    #[test]
    fn command_configuration_requires_explicit_bounded_inputs() {
        assert!(matches!(
            GitAcquisitionConfig::new("git"),
            Err(GitAcquisitionConfigError::ExecutableMustBeAbsolute { .. })
        ));
        assert!(matches!(
            GitAcquisitionConfig::with_timeout("/usr/bin/git", Duration::ZERO),
            Err(GitAcquisitionConfigError::TimeoutMustBePositive)
        ));
        assert!(matches!(
            GitAcquisitionConfig::with_timeout(
                "/usr/bin/git",
                MAX_GIT_ACQUISITION_TIMEOUT + Duration::from_secs(1)
            ),
            Err(GitAcquisitionConfigError::TimeoutTooLarge { .. })
        ));
        let config =
            GitAcquisitionConfig::with_timeout("/usr/bin/git", Duration::from_millis(250)).unwrap();
        assert_eq!(config.executable(), Path::new("/usr/bin/git"));
        assert_eq!(config.timeout(), Duration::from_millis(250));
        assert_eq!(config.transfer_limit(), MAX_GIT_TRANSFER_BYTES);
        assert!(matches!(
            GitAcquisitionConfig::with_limits("/usr/bin/git", Duration::from_millis(250), 0),
            Err(GitAcquisitionConfigError::TransferLimitMustBePositive)
        ));
        assert!(matches!(
            GitAcquisitionConfig::with_limits(
                "/usr/bin/git",
                Duration::from_millis(250),
                MAX_GIT_TRANSFER_BYTES + 1
            ),
            Err(GitAcquisitionConfigError::TransferLimitTooLarge { .. })
        ));
        let config = GitAcquisitionConfig::with_limits(
            "/usr/bin/git",
            Duration::from_millis(250),
            64 * 1024,
        )
        .unwrap();
        assert_eq!(config.transfer_limit(), 64 * 1024);
    }

    #[test]
    fn batch_parser_reads_exact_commit_tree_and_blob_bytes() {
        let commit_oid = "11".repeat(20);
        let tree_oid = "22".repeat(20);
        let manifest_oid = "33".repeat(20);
        let data_oid = "44".repeat(20);
        let commit = format!(
            "tree {tree_oid}\nauthor Test <test@example.com> 0 +0000\ncommitter Test <test@example.com> 0 +0000\n\nmessage\n"
        );
        let tree = tree_bytes(&[
            (b"100755", b"data.bin", 0x44),
            (b"100644", b"malm-pack.kdl", 0x33),
        ]);
        let data = [0_u8, 1, 2, 255];
        let mut stream = Vec::new();
        frame(&mut stream, &commit_oid, "commit", commit.as_bytes());
        frame(&mut stream, &tree_oid, "tree", &tree);
        frame(&mut stream, &data_oid, "blob", &data);
        frame(&mut stream, &manifest_oid, "blob", MINIMAL_PACK);

        let files = read_pack_stream(
            Cursor::new(stream),
            Vec::new(),
            GitObjectFormat::Sha1,
            &commit_oid,
            &PackSubdir::Root,
        )
        .unwrap();

        assert_eq!(files.len(), 2);
        assert_eq!(files[0].path(), "data.bin");
        assert_eq!(files[0].bytes(), data);
        assert_eq!(files[0].mode(), 0o755);
        assert_eq!(files[1].path(), "malm-pack.kdl");
        assert_eq!(files[1].bytes(), MINIMAL_PACK);
        assert_eq!(files[1].mode(), 0o644);
    }

    fn manifest_with_capture_roots(roots: &[&str]) -> Vec<u8> {
        let manifest = malm_pack::decode_pack_v1(MINIMAL_PACK)
            .unwrap()
            .with_capture_roots(
                roots
                    .iter()
                    .map(|root| PackPath::new(*root).unwrap())
                    .collect(),
            )
            .unwrap();
        malm_pack::encode_pack_v1(&manifest).into_bytes()
    }

    fn paths(files: &[GitPackFile]) -> Vec<&str> {
        files.iter().map(GitPackFile::path).collect()
    }

    #[test]
    fn declared_capture_roots_narrow_an_acquired_tree_and_keep_the_lock() {
        let manifest = manifest_with_capture_roots(&["captured", "kept.conf"]);
        let files = vec![
            GitPackFile::new("malm-pack.kdl", manifest),
            GitPackFile::new("malm.lock", b"lock bytes".to_vec()),
            GitPackFile::new("captured/inside.conf", b"inside\n".to_vec()),
            GitPackFile::new("kept.conf", b"kept\n".to_vec()),
            GitPackFile::new("uncaptured.md", b"outside\n".to_vec()),
            GitPackFile::new("elsewhere/deep/skipped.bin", b"outside\n".to_vec()),
        ];

        assert_eq!(
            paths(&narrow_to_capture_roots(files)),
            [
                "malm-pack.kdl",
                "malm.lock",
                "captured/inside.conf",
                "kept.conf"
            ]
        );
    }

    #[test]
    fn a_tree_narrows_nothing_without_declared_roots_or_a_usable_manifest() {
        let undeclared = vec![
            GitPackFile::new("malm-pack.kdl", MINIMAL_PACK.to_vec()),
            GitPackFile::new("anything.md", b"kept\n".to_vec()),
        ];
        assert_eq!(
            paths(&narrow_to_capture_roots(undeclared)),
            ["malm-pack.kdl", "anything.md"]
        );

        // A malformed or oversized manifest cannot be trusted to narrow. The
        // whole tree passes through and strict verification reports the real
        // problem with its canonical error.
        let malformed = vec![
            GitPackFile::new("malm-pack.kdl", b"not a manifest".to_vec()),
            GitPackFile::new("anything.md", b"kept\n".to_vec()),
        ];
        assert_eq!(
            paths(&narrow_to_capture_roots(malformed)),
            ["malm-pack.kdl", "anything.md"]
        );

        let mut oversized = manifest_with_capture_roots(&["captured"]);
        oversized.resize(malm_pack::MAX_PACK_MANIFEST_BYTES + 1, b'\n');
        let oversized = vec![
            GitPackFile::new("malm-pack.kdl", oversized),
            GitPackFile::new("anything.md", b"kept\n".to_vec()),
        ];
        assert_eq!(
            paths(&narrow_to_capture_roots(oversized)),
            ["malm-pack.kdl", "anything.md"]
        );

        // A missing manifest is a verification failure, not a narrowing one.
        let absent = vec![GitPackFile::new("anything.md", b"kept\n".to_vec())];
        assert_eq!(paths(&narrow_to_capture_roots(absent)), ["anything.md"]);
    }

    #[test]
    fn reserved_tree_is_pruned_before_symlink_validation() {
        let commit_oid = "11".repeat(20);
        let tree_oid = "22".repeat(20);
        let manifest_oid = "33".repeat(20);
        let lock_oid = "44".repeat(20);
        let commit = format!("tree {tree_oid}\n\nmessage\n");
        let tree = tree_bytes(&[
            (b"120000", b".git", 0x55),
            (b"120000", b".malm-lock.tmp", 0x66),
            (b"100644", b"malm-pack.kdl", 0x33),
            (b"100644", b"malm.lock", 0x44),
        ]);
        let mut stream = Vec::new();
        frame(&mut stream, &commit_oid, "commit", commit.as_bytes());
        frame(&mut stream, &tree_oid, "tree", &tree);
        frame(&mut stream, &manifest_oid, "blob", MINIMAL_PACK);
        frame(&mut stream, &lock_oid, "blob", b"canonical lock bytes");

        let files = read_pack_stream(
            Cursor::new(stream),
            Vec::new(),
            GitObjectFormat::Sha1,
            &commit_oid,
            &PackSubdir::Root,
        )
        .unwrap();

        assert_eq!(files.len(), 2);
        assert_eq!(files[0].path(), "malm-pack.kdl");
        assert_eq!(files[1].path(), "malm.lock");
    }

    #[test]
    fn exact_object_must_itself_be_a_commit() {
        let oid = "11".repeat(20);
        let mut stream = Vec::new();
        frame(&mut stream, &oid, "tag", b"object data");

        assert!(matches!(
            read_pack_stream(
                Cursor::new(stream),
                Vec::new(),
                GitObjectFormat::Sha1,
                &oid,
                &PackSubdir::Root,
            ),
            Err(GitAcquisitionIssue::UnexpectedObjectType {
                expected: GitObjectKind::Commit,
                actual,
                ..
            }) if actual == "tag"
        ));
    }

    #[test]
    fn selected_symlinks_and_non_utf8_names_are_rejected() {
        let commit_oid = "11".repeat(20);
        let tree_oid = "22".repeat(20);
        let commit = format!("tree {tree_oid}\n\nmessage\n");
        let symlink_tree = tree_bytes(&[(b"120000", b"linked", 0x55)]);
        let mut symlink_stream = Vec::new();
        frame(
            &mut symlink_stream,
            &commit_oid,
            "commit",
            commit.as_bytes(),
        );
        frame(&mut symlink_stream, &tree_oid, "tree", &symlink_tree);
        assert!(matches!(
            read_pack_stream(
                Cursor::new(symlink_stream),
                Vec::new(),
                GitObjectFormat::Sha1,
                &commit_oid,
                &PackSubdir::Root,
            ),
            Err(GitAcquisitionIssue::SymbolicLink { path }) if path.as_str() == "linked"
        ));

        let non_utf8_tree = tree_bytes(&[(b"100644", &[b'n', 0xff], 0x66)]);
        let mut non_utf8_stream = Vec::new();
        frame(
            &mut non_utf8_stream,
            &commit_oid,
            "commit",
            commit.as_bytes(),
        );
        frame(&mut non_utf8_stream, &tree_oid, "tree", &non_utf8_tree);
        assert!(matches!(
            read_pack_stream(
                Cursor::new(non_utf8_stream),
                Vec::new(),
                GitObjectFormat::Sha1,
                &commit_oid,
                &PackSubdir::Root,
            ),
            Err(GitAcquisitionIssue::NonUtf8Name { parent: None })
        ));
    }

    #[test]
    fn traversal_budget_is_shared_and_charged_before_more_entries() {
        let mut raw = TraversalBudget {
            entries: 0,
            raw_tree_bytes: MAX_TOTAL_RAW_TREE_BYTES,
        };
        assert!(matches!(
            raw.charge_tree(1),
            Err(GitAcquisitionIssue::RawTreesTooLarge {
                limit: MAX_TOTAL_RAW_TREE_BYTES,
                ..
            })
        ));

        let mut entries = TraversalBudget {
            entries: MAX_GIT_TRAVERSAL_ENTRIES,
            raw_tree_bytes: 0,
        };
        assert!(matches!(
            entries.charge_entry(),
            Err(GitAcquisitionIssue::TraversalLimitExceeded {
                limit: MAX_GIT_TRAVERSAL_ENTRIES
            })
        ));
    }

    fn frame(output: &mut Vec<u8>, oid: &str, kind: &str, bytes: &[u8]) {
        output.extend_from_slice(format!("{oid} {kind} {}\n", bytes.len()).as_bytes());
        output.extend_from_slice(bytes);
        output.push(b'\n');
    }

    fn tree_bytes(entries: &[(&[u8], &[u8], u8)]) -> Vec<u8> {
        let mut tree = Vec::new();
        for (mode, name, oid_byte) in entries {
            tree.extend_from_slice(mode);
            tree.push(b' ');
            tree.extend_from_slice(name);
            tree.push(0);
            tree.extend_from_slice(&[*oid_byte; 20]);
        }
        tree
    }
}
