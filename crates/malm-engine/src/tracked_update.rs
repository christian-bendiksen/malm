use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    fmt,
    path::{Path, PathBuf},
};

use malm_pack::{
    GitObjectId, GitSourceV1, GitUrl, LocalLocator, LockedSourceV1, PackFileV1, PackPath,
    PackSubdir, classify_pack_tree_path, decode_lock_v1, encode_lock_v1, pack_content_digest,
};
use malm_store::{
    AcquisitionGrantKindV1, AcquisitionGrantV1, ConfigEntryPointV1, ExactRevisionV1,
    LifecycleStateV1, MovingSelectorV1, TrackedRootSourceLocatorV1, TrackedRootSubdirV1,
    TrackedRootV1,
};
use malm_tree::{
    TreeEntryV1, TreeGraphV1, TreeObjectV1, TreePathSegmentV1, file_object_digest_v1,
    tree_object_digest_v1,
};
use malm_types::{
    ContributionName, DeploymentName, Digest, NamespaceName, PreparedDeploymentV1,
    TrackedRootNoChangeV1, TrackedRootUpdateOutcomeV1,
};

use crate::{
    CommitError, Engine, EngineError, GitAcquisitionConfig, GitAcquisitionIssue,
    GraphAcquisitionError, PackObjectIssue, StaticPrepareError, canonical_store, config_prepare,
    git_acquisition,
};

/// Persistable source authorities granted to initial tracked-root prepare.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct TrackedRootAcquisitionGrantsV1 {
    local_sources: BTreeSet<LocalLocator>,
    git_sources: BTreeSet<GitUrl>,
}

impl TrackedRootAcquisitionGrantsV1 {
    pub fn new(
        local_sources: BTreeSet<LocalLocator>,
        git_sources: BTreeSet<GitUrl>,
    ) -> Result<Self, TrackedRootRequestError> {
        let actual = local_sources.len().saturating_add(git_sources.len());
        if actual > malm_store::MAX_TRACKED_ROOT_ACQUISITION_GRANTS {
            return Err(TrackedRootRequestError::too_many_grants(actual));
        }
        let grant_bytes = local_sources
            .iter()
            .map(|locator| locator.as_str().len())
            .chain(git_sources.iter().map(|url| url.as_str().len()))
            .try_fold(0_usize, usize::checked_add)
            .unwrap_or(usize::MAX);
        if grant_bytes > malm_store::MAX_TRACKED_ROOT_ACQUISITION_BYTES {
            return Err(TrackedRootRequestError::too_many_grant_bytes(grant_bytes));
        }
        Ok(Self {
            local_sources,
            git_sources,
        })
    }

    #[must_use]
    pub const fn local_sources(&self) -> &BTreeSet<LocalLocator> {
        &self.local_sources
    }

    #[must_use]
    pub const fn git_sources(&self) -> &BTreeSet<GitUrl> {
        &self.git_sources
    }
}

/// Prepare-only process and scratch authority. None of these host paths are persisted.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrackedRootInfrastructureV1 {
    git: GitAcquisitionConfig,
    root_scratch: PathBuf,
    dependency_scratch_roots: BTreeMap<Digest, PathBuf>,
}

impl TrackedRootInfrastructureV1 {
    #[must_use]
    pub fn new(
        git: GitAcquisitionConfig,
        root_scratch: impl Into<PathBuf>,
        dependency_scratch_roots: BTreeMap<Digest, PathBuf>,
    ) -> Self {
        Self {
            git,
            root_scratch: root_scratch.into(),
            dependency_scratch_roots,
        }
    }

    #[must_use]
    pub const fn git(&self) -> &GitAcquisitionConfig {
        &self.git
    }

    #[must_use]
    pub fn root_scratch(&self) -> &Path {
        &self.root_scratch
    }

    #[must_use]
    pub const fn dependency_scratch_roots(&self) -> &BTreeMap<Digest, PathBuf> {
        &self.dependency_scratch_roots
    }
}

/// Complete authority for an initial moving-root deployment prepare.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrackedRootPrepareRequestV1 {
    source_url: GitUrl,
    moving_selector: MovingSelectorV1,
    source_subdir: PackSubdir,
    config_entry_point: ConfigEntryPointV1,
    profile: Option<ContributionName>,
    namespace: NamespaceName,
    target_authority: DeploymentName,
    component_authorization: malm_format_component_api::FormatComponentAuthorizationV1,
    acquisition_grants: TrackedRootAcquisitionGrantsV1,
    infrastructure: TrackedRootInfrastructureV1,
}

/// Named constituent parts of one [`TrackedRootPrepareRequestV1`], one field per
/// authority the request carries.
///
/// The conversion into [`TrackedRootPrepareRequestV1`] is the only way to build
/// one, and it enforces the same acquisition-grant count and byte budgets.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrackedRootPrepareRequestPartsV1 {
    pub source_url: GitUrl,
    pub moving_selector: MovingSelectorV1,
    pub source_subdir: PackSubdir,
    pub config_entry_point: ConfigEntryPointV1,
    pub profile: Option<ContributionName>,
    pub namespace: NamespaceName,
    pub target_authority: DeploymentName,
    pub component_authorization: malm_format_component_api::FormatComponentAuthorizationV1,
    pub acquisition_grants: TrackedRootAcquisitionGrantsV1,
    pub infrastructure: TrackedRootInfrastructureV1,
}

impl TryFrom<TrackedRootPrepareRequestPartsV1> for TrackedRootPrepareRequestV1 {
    type Error = TrackedRootRequestError;

    fn try_from(parts: TrackedRootPrepareRequestPartsV1) -> Result<Self, Self::Error> {
        let TrackedRootPrepareRequestPartsV1 {
            source_url,
            moving_selector,
            source_subdir,
            config_entry_point,
            profile,
            namespace,
            target_authority,
            component_authorization,
            acquisition_grants,
            infrastructure,
        } = parts;
        let actual = acquisition_grants
            .local_sources
            .len()
            .saturating_add(acquisition_grants.git_sources.len())
            .saturating_add(component_authorization.digests().len())
            .saturating_add(1);
        if actual > malm_store::MAX_TRACKED_ROOT_ACQUISITION_GRANTS {
            return Err(TrackedRootRequestError::too_many_grants(actual));
        }
        let grant_bytes = acquisition_grants
            .local_sources
            .iter()
            .map(|locator| locator.as_str().len())
            .chain(
                acquisition_grants
                    .git_sources
                    .iter()
                    .map(|url| url.as_str().len()),
            )
            .chain(
                component_authorization
                    .digests()
                    .map(|digest| digest.as_str().len()),
            )
            .chain([target_authority.as_str().len()])
            .try_fold(0_usize, usize::checked_add)
            .unwrap_or(usize::MAX);
        if grant_bytes > malm_store::MAX_TRACKED_ROOT_ACQUISITION_BYTES {
            return Err(TrackedRootRequestError::too_many_grant_bytes(grant_bytes));
        }
        Ok(Self {
            source_url,
            moving_selector,
            source_subdir,
            config_entry_point,
            profile,
            namespace,
            target_authority,
            component_authorization,
            acquisition_grants,
            infrastructure,
        })
    }
}

impl TrackedRootPrepareRequestV1 {
    #[must_use]
    pub const fn source_url(&self) -> &GitUrl {
        &self.source_url
    }

    #[must_use]
    pub const fn moving_selector(&self) -> &MovingSelectorV1 {
        &self.moving_selector
    }

    #[must_use]
    pub const fn source_subdir(&self) -> &PackSubdir {
        &self.source_subdir
    }

    #[must_use]
    pub const fn config_entry_point(&self) -> &ConfigEntryPointV1 {
        &self.config_entry_point
    }

    #[must_use]
    pub const fn profile(&self) -> Option<&ContributionName> {
        self.profile.as_ref()
    }

    #[must_use]
    pub const fn namespace(&self) -> &NamespaceName {
        &self.namespace
    }

    #[must_use]
    pub const fn target_authority(&self) -> &DeploymentName {
        &self.target_authority
    }

    #[must_use]
    pub const fn component_authorization(
        &self,
    ) -> &malm_format_component_api::FormatComponentAuthorizationV1 {
        &self.component_authorization
    }

    #[must_use]
    pub const fn acquisition_grants(&self) -> &TrackedRootAcquisitionGrantsV1 {
        &self.acquisition_grants
    }

    #[must_use]
    pub const fn infrastructure(&self) -> &TrackedRootInfrastructureV1 {
        &self.infrastructure
    }
}

/// Infrastructure-only request for updating the currently selected tracked generation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrackedRootUpdateRequestV1 {
    namespace: NamespaceName,
    infrastructure: TrackedRootInfrastructureV1,
}

impl TrackedRootUpdateRequestV1 {
    #[must_use]
    pub const fn new(
        namespace: NamespaceName,
        infrastructure: TrackedRootInfrastructureV1,
    ) -> Self {
        Self {
            namespace,
            infrastructure,
        }
    }

    #[must_use]
    pub const fn namespace(&self) -> &NamespaceName {
        &self.namespace
    }

    #[must_use]
    pub const fn infrastructure(&self) -> &TrackedRootInfrastructureV1 {
        &self.infrastructure
    }
}

/// Invalid bounded construction of an initial tracked-root request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrackedRootRequestError {
    field: &'static str,
    limit: usize,
    actual: usize,
}

impl TrackedRootRequestError {
    const fn too_many_grants(actual: usize) -> Self {
        Self {
            field: "tracked-root acquisition grants",
            limit: malm_store::MAX_TRACKED_ROOT_ACQUISITION_GRANTS,
            actual,
        }
    }

    const fn too_many_grant_bytes(actual: usize) -> Self {
        Self {
            field: "tracked-root acquisition grant bytes",
            limit: malm_store::MAX_TRACKED_ROOT_ACQUISITION_BYTES,
            actual,
        }
    }

    #[must_use]
    pub const fn field(&self) -> &'static str {
        self.field
    }

    #[must_use]
    pub const fn limit(&self) -> usize {
        self.limit
    }

    #[must_use]
    pub const fn actual(&self) -> usize {
        self.actual
    }
}

impl fmt::Display for TrackedRootRequestError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let unit = if self.field.ends_with("bytes") {
            "bytes"
        } else {
            "entries"
        };
        write!(
            formatter,
            "{} has {} {}; limit is {}",
            self.field, self.actual, unit, self.limit
        )
    }
}

impl Error for TrackedRootRequestError {}

/// Failure while resolving and preparing an initial or advancing tracked root.
// The cause already appears in Display, and source() would duplicate it.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum TrackedRootError {
    #[error("{0}")]
    Resolution(GitAcquisitionIssue),
    #[error("moving selector returned an invalid revision: {0}")]
    InvalidResolvedRevision(malm_pack::ValueError),
    #[error("{0}")]
    State(CommitError),
    #[error("namespace {namespace} has no tracked root")]
    MissingTracking { namespace: NamespaceName },
    #[error("namespace {namespace} is disabled and cannot be updated")]
    Disabled { namespace: NamespaceName },
    #[error(
        "namespace {namespace} changed during tracked update: expected {expected}, found {actual:?}"
    )]
    StaleNamespace {
        namespace: NamespaceName,
        expected: Digest,
        actual: Option<Digest>,
    },
    #[error("invalid selected tracked-root state: {detail}")]
    InvalidTrackedState { detail: String },
    #[error("tracked root is missing malm.lock")]
    MissingRootLock,
    #[error("invalid tracked root lock: {0}")]
    InvalidRootLock(malm_pack::LockReadError),
    #[error("tracked root malm.lock is not canonical lock/v1 bytes")]
    NonCanonicalRootLock,
    #[error("tracked root lock requires pack {expected}, acquired {actual}")]
    RootLockMismatch { expected: Digest, actual: Digest },
    #[error(
        "exact revision {revision} changed tree identity: expected {expected}, acquired {actual}"
    )]
    RevisionContentChanged {
        revision: String,
        expected: Digest,
        actual: Digest,
    },
    #[error("{0}")]
    GraphAcquisition(GraphAcquisitionError),
    #[error("{0}")]
    GraphAssembly(malm_module_graph::GraphAssemblyError<EngineError>),
    #[error("{0}")]
    Source(EngineError),
    #[error("{0}")]
    Static(StaticPrepareError),
}

pub(super) fn prepare(
    engine: &Engine,
    request: &TrackedRootPrepareRequestV1,
) -> Result<PreparedDeploymentV1, TrackedRootError> {
    TrackedRootSourceLocatorV1::new(request.source_url().as_str())
        .map_err(|error| invalid_tracked(error.to_string()))?;
    TrackedRootSubdirV1::new(request.source_subdir().as_str())
        .map_err(|error| invalid_tracked(error.to_string()))?;
    let persisted_grants = initial_persisted_grants(request)?;
    let revision = resolve_revision(
        engine,
        request.source_url(),
        request.moving_selector(),
        request.infrastructure().git(),
    )?;
    let authorities = PersistedAuthorities::from_initial(request);
    let acquired = acquire_graph(
        engine,
        request.source_url(),
        &revision,
        request.source_subdir(),
        &authorities,
        request.infrastructure(),
    )?;
    let config_entry = PackPath::new(request.config_entry_point().as_str())
        .map_err(|error| invalid_tracked(error.to_string()))?;
    let selected_profile =
        config_prepare::selected_profile(&acquired.graph, &config_entry, request.profile())
            .map_err(TrackedRootError::Static)?;
    let tracked_root = tracked_root(
        ResolvedTracking {
            source_url: request.source_url(),
            selector: request.moving_selector(),
            revision: &revision,
            root_tree_digest: &acquired.root_tree_digest,
            source_subdir: request.source_subdir(),
            config_entry: request.config_entry_point(),
        },
        selected_profile.clone(),
        persisted_grants,
    )?;
    let expected_head = engine
        .committer_v1()
        .and_then(|committer| committer.inspect_state_v1(request.namespace()))
        .map_err(TrackedRootError::State)?
        .head()
        .cloned();
    config_prepare::prepare(
        config_prepare::StaticPrepareContext {
            engine,
            graph: &acquired.graph,
            component_authorization: request.component_authorization(),
            namespace: request.namespace().clone(),
            target_authority: request.target_authority().clone(),
            expected_head,
            tracked_root: Some(&tracked_root),
        },
        Some(&selected_profile),
        Some(&config_entry),
    )
    .map_err(TrackedRootError::Static)
}

pub(super) fn update(
    engine: &Engine,
    request: &TrackedRootUpdateRequestV1,
) -> Result<TrackedRootUpdateOutcomeV1, TrackedRootError> {
    let committer = engine.committer_v1().map_err(TrackedRootError::State)?;
    let head = committer
        .inspect_state_v1(request.namespace())
        .map_err(TrackedRootError::State)?
        .head()
        .cloned()
        .ok_or_else(|| TrackedRootError::MissingTracking {
            namespace: request.namespace().clone(),
        })?;
    let generation = committer
        .inspect_generation_v1(&head)
        .map_err(TrackedRootError::State)?;
    if generation.namespace() != request.namespace() {
        return Err(invalid_tracked(
            "selected generation belongs to another namespace",
        ));
    }
    if generation.lifecycle_state() != LifecycleStateV1::Enabled {
        return Err(TrackedRootError::Disabled {
            namespace: request.namespace().clone(),
        });
    }
    let current =
        generation
            .tracked_root()
            .cloned()
            .ok_or_else(|| TrackedRootError::MissingTracking {
                namespace: request.namespace().clone(),
            })?;
    let authorities = PersistedAuthorities::from_tracked(&current)?;
    let source_url = GitUrl::new(current.source_locator().as_str())
        .map_err(|error| invalid_tracked(error.to_string()))?;
    let source_subdir = PackSubdir::new(current.source_subdir().as_str())
        .map_err(|error| invalid_tracked(error.to_string()))?;
    let config_entry = PackPath::new(current.config_entry_point().as_str())
        .map_err(|error| invalid_tracked(error.to_string()))?;
    let revision = resolve_revision(
        engine,
        &source_url,
        current.moving_selector(),
        request.infrastructure().git(),
    )?;
    let acquired = acquire_graph(
        engine,
        &source_url,
        &revision,
        &source_subdir,
        &authorities,
        request.infrastructure(),
    )?;

    if revision.as_str() == current.applied_revision().as_str() {
        if acquired.root_tree_digest != *current.root_tree_digest() {
            return Err(TrackedRootError::RevisionContentChanged {
                revision: revision.as_str().to_owned(),
                expected: current.root_tree_digest().clone(),
                actual: acquired.root_tree_digest,
            });
        }
        ensure_head(engine, request.namespace(), &head)?;
        return Ok(TrackedRootUpdateOutcomeV1::NoChange(
            TrackedRootNoChangeV1::new(
                request.namespace().clone(),
                head,
                revision.as_str().to_owned(),
                current.root_tree_digest().clone(),
            ),
        ));
    }

    let selected_profile = current.selected_profile().clone();
    config_prepare::selected_profile(&acquired.graph, &config_entry, Some(&selected_profile))
        .map_err(TrackedRootError::Static)?;
    let next_tracking = tracked_root(
        ResolvedTracking {
            source_url: &source_url,
            selector: current.moving_selector(),
            revision: &revision,
            root_tree_digest: &acquired.root_tree_digest,
            source_subdir: &source_subdir,
            config_entry: current.config_entry_point(),
        },
        selected_profile.clone(),
        current.acquisition_grants().to_vec(),
    )?;
    let prepared = config_prepare::prepare(
        config_prepare::StaticPrepareContext {
            engine,
            graph: &acquired.graph,
            component_authorization: &authorities.component_authorization,
            namespace: request.namespace().clone(),
            target_authority: authorities.target_authority,
            expected_head: Some(head),
            tracked_root: Some(&next_tracking),
        },
        Some(&selected_profile),
        Some(&config_entry),
    )
    .map_err(TrackedRootError::Static)?;
    Ok(TrackedRootUpdateOutcomeV1::Prepared(Box::new(prepared)))
}

fn resolve_revision(
    engine: &Engine,
    url: &GitUrl,
    selector: &MovingSelectorV1,
    git: &GitAcquisitionConfig,
) -> Result<GitObjectId, TrackedRootError> {
    let revision = git_acquisition::resolve_moving_revision(engine, url, selector.as_str(), git)
        .map_err(TrackedRootError::Resolution)?;
    GitObjectId::new(revision).map_err(TrackedRootError::InvalidResolvedRevision)
}

fn ensure_head(
    engine: &Engine,
    namespace: &NamespaceName,
    expected: &Digest,
) -> Result<(), TrackedRootError> {
    let actual = engine
        .committer_v1()
        .and_then(|committer| committer.inspect_state_v1(namespace))
        .map_err(TrackedRootError::State)?
        .head()
        .cloned();
    if actual.as_ref() != Some(expected) {
        return Err(TrackedRootError::StaleNamespace {
            namespace: namespace.clone(),
            expected: expected.clone(),
            actual,
        });
    }
    Ok(())
}

struct AcquiredTrackedGraph {
    graph: malm_module_graph::AssembledLockedGraphV1,
    root_tree_digest: Digest,
}

fn acquire_graph(
    engine: &Engine,
    source_url: &GitUrl,
    revision: &GitObjectId,
    source_subdir: &PackSubdir,
    authorities: &PersistedAuthorities,
    infrastructure: &TrackedRootInfrastructureV1,
) -> Result<AcquiredTrackedGraph, TrackedRootError> {
    let source = GitSourceV1::new(source_url.clone(), revision.clone(), source_subdir.clone());
    let checkout = git_acquisition::ExactGitCheckout::acquire(
        engine,
        &source,
        infrastructure.git(),
        infrastructure.root_scratch(),
    )
    .map_err(TrackedRootError::Source)?;
    let root_files = checkout
        .read_pack(engine, source_subdir)
        .map_err(TrackedRootError::Source)?;
    let root = normalize_git_files(root_files, true)?;
    let root_digest = verified_pack_digest(&root.files)?;
    let lock_bytes = root.lock.ok_or(TrackedRootError::MissingRootLock)?;
    let lock = decode_lock_v1(&lock_bytes).map_err(TrackedRootError::InvalidRootLock)?;
    if encode_lock_v1(&lock) != lock_bytes {
        return Err(TrackedRootError::NonCanonicalRootLock);
    }
    let locked_root = lock
        .node(lock.root_node_id())
        .expect("validated lock retains its root node");
    if locked_root.content_digest() != &root_digest {
        return Err(TrackedRootError::RootLockMismatch {
            expected: locked_root.content_digest().clone(),
            actual: root_digest,
        });
    }
    preflight_graph_grants(engine, &lock, authorities, infrastructure)?;
    engine
        .publish_pack_object_raw(locked_root.content_digest(), &root.files)
        .map_err(TrackedRootError::Source)?;
    let root_tree_digest = publish_canonical_pack_tree(engine, &root.files, &root.modes)?;

    for node in lock.nodes() {
        let LockedSourceV1::Local(locator) = node.source() else {
            continue;
        };
        let local_subdir = resolve_local_subdir(source_subdir, locator)?;
        let files = checkout
            .read_pack(engine, &local_subdir)
            .map_err(TrackedRootError::Source)?;
        let files = normalize_git_files(files, false)?.files;
        verify_expected_pack(&files, node.content_digest())?;
        engine
            .publish_pack_object_raw(node.content_digest(), &files)
            .map_err(|source| {
                TrackedRootError::GraphAcquisition(GraphAcquisitionError::Source {
                    node_id: node.node_id().clone(),
                    source,
                })
            })?;
    }

    let mut handled = BTreeSet::new();
    for node in lock.nodes() {
        let LockedSourceV1::Git(git_source) = node.source() else {
            continue;
        };
        if !handled.insert(node.content_digest().clone()) {
            continue;
        }
        match engine.load_pack_object_raw(node.content_digest()) {
            Ok(_) => continue,
            Err(EngineError::PackObject {
                reason: PackObjectIssue::Missing,
                ..
            }) => {}
            Err(source) => {
                return Err(TrackedRootError::GraphAcquisition(
                    GraphAcquisitionError::Source {
                        node_id: node.node_id().clone(),
                        source,
                    },
                ));
            }
        }
        let scratch = infrastructure
            .dependency_scratch_roots()
            .get(node.content_digest())
            .expect("missing dependency scratch was preflighted");
        engine
            .acquire_git_pack_raw(
                git_source,
                node.content_digest(),
                infrastructure.git(),
                scratch,
            )
            .map_err(|source| {
                TrackedRootError::GraphAcquisition(GraphAcquisitionError::Source {
                    node_id: node.node_id().clone(),
                    source,
                })
            })?;
    }

    let graph = engine
        .assemble_cached_pack_graph_raw(&lock)
        .map_err(TrackedRootError::GraphAssembly)?;
    Ok(AcquiredTrackedGraph {
        graph,
        root_tree_digest,
    })
}

fn preflight_graph_grants(
    engine: &Engine,
    lock: &malm_pack::LockV1,
    authorities: &PersistedAuthorities,
    infrastructure: &TrackedRootInfrastructureV1,
) -> Result<(), TrackedRootError> {
    for node in lock.nodes() {
        match node.source() {
            LockedSourceV1::Root => {}
            LockedSourceV1::Local(locator) if authorities.local_sources.contains(locator) => {}
            LockedSourceV1::Local(locator) => {
                return Err(TrackedRootError::GraphAcquisition(
                    GraphAcquisitionError::LocalSourceNotGranted {
                        node_id: node.node_id().clone(),
                        locator: locator.clone(),
                    },
                ));
            }
            LockedSourceV1::Git(source) if authorities.git_sources.contains(source.url()) => {
                match engine.load_pack_object_raw(node.content_digest()) {
                    Ok(_) => {}
                    Err(EngineError::PackObject {
                        reason: PackObjectIssue::Missing,
                        ..
                    }) if infrastructure
                        .dependency_scratch_roots()
                        .contains_key(node.content_digest()) => {}
                    Err(EngineError::PackObject {
                        reason: PackObjectIssue::Missing,
                        ..
                    }) => {
                        return Err(TrackedRootError::GraphAcquisition(
                            GraphAcquisitionError::MissingGitScratch {
                                digest: node.content_digest().clone(),
                            },
                        ));
                    }
                    Err(source) => {
                        return Err(TrackedRootError::GraphAcquisition(
                            GraphAcquisitionError::Source {
                                node_id: node.node_id().clone(),
                                source,
                            },
                        ));
                    }
                }
            }
            LockedSourceV1::Git(source) => {
                return Err(TrackedRootError::GraphAcquisition(
                    GraphAcquisitionError::GitSourceNotGranted {
                        node_id: node.node_id().clone(),
                        url: source.url().clone(),
                    },
                ));
            }
        }
    }
    Ok(())
}

struct NormalizedGitFiles {
    files: Vec<PackFileV1>,
    modes: BTreeMap<PackPath, u32>,
    lock: Option<Vec<u8>>,
}

fn normalize_git_files(
    files: Vec<crate::GitPackFile>,
    require_lock: bool,
) -> Result<NormalizedGitFiles, TrackedRootError> {
    let mut normalized = Vec::new();
    let mut modes = BTreeMap::new();
    let mut lock = None;
    for file in files {
        let (path, bytes, mode) = file.into_mode_parts();
        if path == malm_pack::LOCK_FILE {
            if mode != 0o644 {
                return Err(invalid_tracked("malm.lock must have normalized mode 0644"));
            }
            if lock.replace(bytes).is_some() {
                return Err(invalid_tracked("tracked root contains malm.lock twice"));
            }
            continue;
        }
        let Some(path) =
            classify_pack_tree_path(path).map_err(|error| invalid_tracked(error.to_string()))?
        else {
            continue;
        };
        if modes.insert(path.clone(), mode).is_some() {
            return Err(invalid_tracked(
                "Git adapter returned one path more than once",
            ));
        }
        normalized.push(PackFileV1::new(path, bytes));
    }
    if require_lock && lock.is_none() {
        return Err(TrackedRootError::MissingRootLock);
    }
    Ok(NormalizedGitFiles {
        files: normalized,
        modes,
        lock,
    })
}

fn verified_pack_digest(files: &[PackFileV1]) -> Result<Digest, TrackedRootError> {
    let digest = pack_content_digest(files.iter().map(|file| (file.path(), file.bytes())))
        .map_err(|error| invalid_tracked(error.to_string()))?;
    malm_module_graph::verify_pack_files_v1(&digest, files)
        .map_err(|error| invalid_tracked(error.to_string()))?;
    Ok(digest)
}

fn verify_expected_pack(files: &[PackFileV1], expected: &Digest) -> Result<(), TrackedRootError> {
    malm_module_graph::verify_pack_files_v1(expected, files)
        .map(|_| ())
        .map_err(|error| invalid_tracked(error.to_string()))
}

fn resolve_local_subdir(
    root: &PackSubdir,
    locator: &LocalLocator,
) -> Result<PackSubdir, TrackedRootError> {
    let mut segments = match root {
        PackSubdir::Root => Vec::new(),
        PackSubdir::Path(path) => path.as_str().split('/').map(str::to_owned).collect(),
    };
    if locator.as_str() != "." {
        for segment in locator.as_str().split('/') {
            if segment == ".." {
                if segments.pop().is_none() {
                    return Err(invalid_tracked(
                        "local pack locator escapes the tracked Git repository",
                    ));
                }
            } else {
                segments.push(segment.to_owned());
            }
        }
    }
    let path = if segments.is_empty() {
        ".".to_owned()
    } else {
        segments.join("/")
    };
    PackSubdir::new(path).map_err(|error| invalid_tracked(error.to_string()))
}

#[derive(Default)]
struct CanonicalDirectory {
    files: BTreeMap<String, CanonicalFile>,
    directories: BTreeMap<String, CanonicalDirectory>,
}

struct CanonicalFile {
    digest: Digest,
    byte_len: u64,
    mode: u32,
}

fn publish_canonical_pack_tree(
    engine: &Engine,
    files: &[PackFileV1],
    modes: &BTreeMap<PackPath, u32>,
) -> Result<Digest, TrackedRootError> {
    let mut root = CanonicalDirectory::default();
    for file in files {
        let digest = file_object_digest_v1(file.bytes())
            .map_err(|error| invalid_tracked(error.to_string()))?;
        canonical_store::publish_file(engine, &digest, file.bytes())
            .map_err(TrackedRootError::Source)?;
        let mode = *modes
            .get(file.path())
            .ok_or_else(|| invalid_tracked("tracked pack file is missing its Git mode"))?;
        root.insert(
            file.path(),
            CanonicalFile {
                digest,
                byte_len: file.bytes().len() as u64,
                mode,
            },
        )?;
    }

    let mut trees = Vec::new();
    let root_digest = root.build(&mut trees)?;
    TreeGraphV1::new(root_digest.clone(), trees.iter().cloned(), [])
        .map_err(|error| invalid_tracked(error.to_string()))?;
    for tree in trees {
        let digest = tree_object_digest_v1(&tree);
        canonical_store::publish_tree(engine, &digest, &tree).map_err(TrackedRootError::Source)?;
    }
    Ok(root_digest)
}

impl CanonicalDirectory {
    fn insert(&mut self, path: &PackPath, file: CanonicalFile) -> Result<(), TrackedRootError> {
        let mut segments = path.as_str().split('/').peekable();
        let mut directory = self;
        while let Some(segment) = segments.next() {
            if segments.peek().is_none() {
                if directory.directories.contains_key(segment)
                    || directory.files.insert(segment.to_owned(), file).is_some()
                {
                    return Err(invalid_tracked(
                        "tracked pack paths have a file/tree conflict",
                    ));
                }
                return Ok(());
            }
            if directory.files.contains_key(segment) {
                return Err(invalid_tracked(
                    "tracked pack paths have a file/tree conflict",
                ));
            }
            directory = directory.directories.entry(segment.to_owned()).or_default();
        }
        Err(invalid_tracked("tracked pack path is empty"))
    }

    fn build(&self, trees: &mut Vec<TreeObjectV1>) -> Result<Digest, TrackedRootError> {
        let mut entries = Vec::with_capacity(self.files.len() + self.directories.len());
        for (name, file) in &self.files {
            entries.push(
                TreeEntryV1::file(
                    TreePathSegmentV1::new(name)
                        .map_err(|error| invalid_tracked(error.to_string()))?,
                    file.mode,
                    file.digest.clone(),
                    file.byte_len,
                )
                .map_err(|error| invalid_tracked(error.to_string()))?,
            );
        }
        for (name, directory) in &self.directories {
            let digest = directory.build(trees)?;
            entries.push(
                TreeEntryV1::directory(
                    TreePathSegmentV1::new(name)
                        .map_err(|error| invalid_tracked(error.to_string()))?,
                    0o755,
                    digest,
                )
                .map_err(|error| invalid_tracked(error.to_string()))?,
            );
        }
        let tree = TreeObjectV1::new(0o755, entries)
            .map_err(|error| invalid_tracked(error.to_string()))?;
        let digest = tree_object_digest_v1(&tree);
        trees.push(tree);
        Ok(digest)
    }
}

fn initial_persisted_grants(
    request: &TrackedRootPrepareRequestV1,
) -> Result<Vec<AcquisitionGrantV1>, TrackedRootError> {
    let mut grants = Vec::new();
    for locator in request.acquisition_grants().local_sources() {
        grants.push(
            AcquisitionGrantV1::new(AcquisitionGrantKindV1::LocalSource, locator.as_str())
                .map_err(|error| invalid_tracked(error.to_string()))?,
        );
    }
    for url in request.acquisition_grants().git_sources() {
        grants.push(
            AcquisitionGrantV1::new(AcquisitionGrantKindV1::GitSource, url.as_str())
                .map_err(|error| invalid_tracked(error.to_string()))?,
        );
    }
    for digest in request.component_authorization().digests() {
        grants.push(
            AcquisitionGrantV1::new(AcquisitionGrantKindV1::FormatComponent, digest.as_str())
                .map_err(|error| invalid_tracked(error.to_string()))?,
        );
    }
    grants.push(
        AcquisitionGrantV1::new(
            AcquisitionGrantKindV1::TargetAuthority,
            request.target_authority().as_str(),
        )
        .map_err(|error| invalid_tracked(error.to_string()))?,
    );
    Ok(grants)
}

/// The exact source identity one tracking record pins: where the root came
/// from, which moving selector chose it, and which revision, tree, subdir,
/// and entry point that choice resolved to.
struct ResolvedTracking<'a> {
    source_url: &'a GitUrl,
    selector: &'a MovingSelectorV1,
    revision: &'a GitObjectId,
    root_tree_digest: &'a Digest,
    source_subdir: &'a PackSubdir,
    config_entry: &'a ConfigEntryPointV1,
}

fn tracked_root(
    resolved: ResolvedTracking<'_>,
    selected_profile: ContributionName,
    grants: Vec<AcquisitionGrantV1>,
) -> Result<TrackedRootV1, TrackedRootError> {
    let ResolvedTracking {
        source_url,
        selector,
        revision,
        root_tree_digest,
        source_subdir,
        config_entry,
    } = resolved;
    TrackedRootV1::new(
        TrackedRootSourceLocatorV1::new(source_url.as_str())
            .map_err(|error| invalid_tracked(error.to_string()))?,
        selector.clone(),
        ExactRevisionV1::new(revision.as_str())
            .map_err(|error| invalid_tracked(error.to_string()))?,
        root_tree_digest.clone(),
        config_entry.clone(),
        selected_profile,
        grants,
    )
    .and_then(|tracked| {
        tracked.with_source_subdir(TrackedRootSubdirV1::new(source_subdir.as_str())?)
    })
    .map_err(|error| invalid_tracked(error.to_string()))
}

struct PersistedAuthorities {
    local_sources: BTreeSet<LocalLocator>,
    git_sources: BTreeSet<GitUrl>,
    component_authorization: malm_format_component_api::FormatComponentAuthorizationV1,
    target_authority: DeploymentName,
}

impl PersistedAuthorities {
    fn from_initial(request: &TrackedRootPrepareRequestV1) -> Self {
        Self {
            local_sources: request.acquisition_grants().local_sources().clone(),
            git_sources: request.acquisition_grants().git_sources().clone(),
            component_authorization: request.component_authorization().clone(),
            target_authority: request.target_authority().clone(),
        }
    }

    fn from_tracked(tracked: &TrackedRootV1) -> Result<Self, TrackedRootError> {
        let mut local_sources = BTreeSet::new();
        let mut git_sources = BTreeSet::new();
        let mut format_components = BTreeSet::new();
        let mut target_authorities = BTreeSet::new();
        for grant in tracked.acquisition_grants() {
            match grant.kind() {
                AcquisitionGrantKindV1::LocalSource => {
                    local_sources.insert(
                        LocalLocator::new(grant.locator().as_str())
                            .map_err(|error| invalid_tracked(error.to_string()))?,
                    );
                }
                AcquisitionGrantKindV1::GitSource => {
                    git_sources.insert(
                        GitUrl::new(grant.locator().as_str())
                            .map_err(|error| invalid_tracked(error.to_string()))?,
                    );
                }
                AcquisitionGrantKindV1::FormatComponent => {
                    format_components.insert(
                        Digest::new(grant.locator().as_str())
                            .map_err(|error| invalid_tracked(error.to_string()))?,
                    );
                }
                AcquisitionGrantKindV1::TargetAuthority => {
                    target_authorities.insert(
                        DeploymentName::new(grant.locator().as_str())
                            .map_err(|error| invalid_tracked(error.to_string()))?,
                    );
                }
            }
        }
        let target_authority = target_authorities
            .pop_first()
            .filter(|_| target_authorities.is_empty())
            .ok_or_else(|| {
                invalid_tracked("tracking must persist exactly one target authority grant")
            })?;
        Ok(Self {
            local_sources,
            git_sources,
            component_authorization: malm_format_component_api::FormatComponentAuthorizationV1::new(
                format_components,
            ),
            target_authority,
        })
    }
}

fn invalid_tracked(detail: impl Into<String>) -> TrackedRootError {
    TrackedRootError::InvalidTrackedState {
        detail: detail.into(),
    }
}

/// Initial tracked deployment prepare request.
pub type TrackedDeploymentPrepareRequestV1 = TrackedRootPrepareRequestV1;
/// Tracked-root update request.
pub type UpdateRequestV1 = TrackedRootUpdateRequestV1;
/// Tracked-root update outcome.
pub type UpdateOutcomeV1 = TrackedRootUpdateOutcomeV1;
