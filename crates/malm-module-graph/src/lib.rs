//! Offline assembly and private module lookup for validated lock graphs.
//!
//! The source capability supplies cached pack files by digest. It cannot fetch,
//! update locks, discover files, or write. Assembly verifies cached content,
//! not current Git or local sources. Prepare must acquire each locked source,
//! detect local drift, and publish immutable objects before assembly.

use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

use thiserror::Error;

use malm_pack::{
    LockV1, LockValidationError, LockedComponentV1, LockedSourceV1, PackManifestV1, PackPath,
    PackReadError, PackTreeError, decode_pack_v1, lock_graph_digest, pack_content_digest,
};
use malm_types::{Alias, ContributionName, Digest, PackNodeId};

pub use malm_pack::PackFileV1;

/// Maximum module-scope entries in an assembled graph.
pub const MAX_GRAPH_MODULES: usize = 65_536;

/// Maximum unique verified file bytes retained during assembly.
pub const MAX_GRAPH_OBJECT_BYTES: u64 = 1024 * 1024 * 1024;

/// Read-only access to cached pack objects.
///
/// Implementations must return every file for `content_digest`. Missing or
/// corrupt objects are errors. This call must not fetch or repair objects.
pub trait PackObjectSourceV1 {
    /// Source-specific error.
    type Error;

    /// Loads a cached pack tree by locked content digest.
    fn load_pack(&self, content_digest: &Digest) -> Result<Vec<PackFileV1>, Self::Error>;
}

/// Failure to verify supplied pack bytes.
#[derive(Debug, Error)]
pub enum PackVerificationError {
    #[error("invalid pack tree: {0}")]
    InvalidTree(#[source] PackTreeError),
    #[error("pack content digest mismatch: expected {expected}, computed {actual}")]
    DigestMismatch { expected: Digest, actual: Digest },
    #[error("pack object is missing malm-pack.kdl")]
    MissingManifest,
    #[error("invalid pack manifest: {0}")]
    InvalidManifest(#[source] PackReadError),
    #[error("declared {kind} path {path:?} is absent from the pack")]
    MissingDeclaredPath { kind: &'static str, path: PackPath },
    #[error("component {path:?} digest mismatch: expected {expected}, computed {actual}")]
    ComponentDigestMismatch {
        path: PackPath,
        expected: Digest,
        actual: Digest,
    },
}

/// A manifest whose tree and components match one digest.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedPackV1 {
    content_digest: Digest,
    manifest: PackManifestV1,
    files: Arc<BTreeMap<PackPath, Arc<Vec<u8>>>>,
    total_bytes: u64,
}

impl VerifiedPackV1 {
    /// Verifies an in-memory pack against its locked digest.
    pub fn from_files(
        expected_digest: &Digest,
        files: Vec<PackFileV1>,
    ) -> Result<Self, PackVerificationError> {
        let pack = Self::from_untrusted_files(files)?;
        require_content_digest(expected_digest, pack.content_digest())?;
        Ok(pack)
    }

    /// Verifies an in-memory pack and computes its digest in the same pass.
    pub fn from_untrusted_files(files: Vec<PackFileV1>) -> Result<Self, PackVerificationError> {
        let content_digest =
            pack_content_digest(files.iter().map(|file| (file.path(), file.bytes())))
                .map_err(PackVerificationError::InvalidTree)?;
        let manifest = check_manifest_references(&files)?;

        let total_bytes = files.iter().fold(0_u64, |total, file| {
            total.saturating_add(malm_types::usize_to_u64(file.bytes().len()))
        });
        let by_path = files
            .into_iter()
            .map(|file| {
                let (path, bytes) = file.into_parts();
                (path, Arc::new(bytes))
            })
            .collect::<BTreeMap<_, _>>();

        Ok(Self {
            content_digest,
            manifest,
            files: Arc::new(by_path),
            total_bytes,
        })
    }

    #[must_use]
    pub const fn content_digest(&self) -> &Digest {
        &self.content_digest
    }

    /// Returns the manifest covered by the digest.
    #[must_use]
    pub const fn manifest(&self) -> &PackManifestV1 {
        &self.manifest
    }

    /// Returns bytes from the verified pack.
    #[must_use]
    pub fn file(&self, path: &PackPath) -> Option<&[u8]> {
        self.files.get(path).map(|bytes| bytes.as_slice())
    }

    /// Iterates over verified files in canonical path order.
    pub fn files(&self) -> impl Iterator<Item = (&PackPath, &[u8])> {
        self.files
            .iter()
            .map(|(path, bytes)| (path, bytes.as_slice()))
    }

    #[must_use]
    pub const fn total_bytes(&self) -> u64 {
        self.total_bytes
    }
}

/// Verifies borrowed pack files without retaining or copying them.
///
/// Source acquisition can call this before publication to keep invalid packs
/// out of the CAS.
pub fn verify_pack_files_v1(
    expected_digest: &Digest,
    files: &[PackFileV1],
) -> Result<PackManifestV1, PackVerificationError> {
    let actual_digest = pack_content_digest(files.iter().map(|file| (file.path(), file.bytes())))
        .map_err(PackVerificationError::InvalidTree)?;
    require_content_digest(expected_digest, &actual_digest)?;
    check_manifest_references(files)
}

fn require_content_digest(expected: &Digest, actual: &Digest) -> Result<(), PackVerificationError> {
    if actual != expected {
        return Err(PackVerificationError::DigestMismatch {
            expected: expected.clone(),
            actual: actual.clone(),
        });
    }
    Ok(())
}

/// Validates manifest references without recomputing the tree digest.
fn check_manifest_references(
    files: &[PackFileV1],
) -> Result<PackManifestV1, PackVerificationError> {
    let by_path = files
        .iter()
        .map(|file| (file.path().as_str(), file.bytes()))
        .collect::<BTreeMap<_, _>>();
    let manifest_bytes = by_path
        .get(malm_pack::PACK_MANIFEST_FILE)
        .copied()
        .ok_or(PackVerificationError::MissingManifest)?;
    let manifest =
        decode_pack_v1(manifest_bytes).map_err(PackVerificationError::InvalidManifest)?;

    let declared_sections: [(&'static str, Box<dyn Iterator<Item = &PackPath> + '_>); 5] = [
        (
            "module",
            Box::new(manifest.modules().iter().map(|module| module.path())),
        ),
        (
            "config document",
            Box::new(manifest.config_documents().iter()),
        ),
        ("template", Box::new(manifest.templates().iter())),
        ("schema", Box::new(manifest.schemas().iter())),
        ("asset", Box::new(manifest.assets().iter())),
    ];
    for (kind, paths) in declared_sections {
        for path in paths {
            require_path(&by_path, kind, path)?;
        }
    }
    let mut component_digests = BTreeMap::new();
    for component in manifest.components() {
        let bytes = require_path(&by_path, "component", component.path())?;
        let actual = component_digests
            .entry(component.path().as_str())
            .or_insert_with(|| Digest::sha256(bytes));
        if actual != component.digest() {
            return Err(PackVerificationError::ComponentDigestMismatch {
                path: component.path().clone(),
                expected: component.digest().clone(),
                actual: actual.clone(),
            });
        }
    }

    Ok(manifest)
}

fn require_path<'a>(
    files: &BTreeMap<&str, &'a [u8]>,
    kind: &'static str,
    path: &PackPath,
) -> Result<&'a [u8], PackVerificationError> {
    files
        .get(path.as_str())
        .copied()
        .ok_or_else(|| PackVerificationError::MissingDeclaredPath {
            kind,
            path: path.clone(),
        })
}

/// Canonical ID of a module in a locked graph.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct ModuleIdV1 {
    pack_node_id: PackNodeId,
    local_name: ContributionName,
}

impl ModuleIdV1 {
    const fn new(pack_node_id: PackNodeId, local_name: ContributionName) -> Self {
        Self {
            pack_node_id,
            local_name,
        }
    }

    #[must_use]
    pub const fn pack_node_id(&self) -> &PackNodeId {
        &self.pack_node_id
    }

    #[must_use]
    pub const fn local_name(&self) -> &ContributionName {
        &self.local_name
    }
}

/// A module reference before private-scope resolution.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ModuleReferenceV1 {
    /// An unqualified module in the current pack.
    Local(ContributionName),
    /// A module in a directly aliased dependency.
    Direct {
        /// Alias in the importing pack.
        dependency: Alias,
        /// Local name in the target pack.
        module: ContributionName,
    },
}

/// A private module resolution failure.
#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum ModuleResolutionError {
    #[error("unknown importing pack node {0}")]
    UnknownPack(PackNodeId),
    #[error("pack {from} has no local module {module}")]
    UnknownLocalModule {
        from: PackNodeId,
        module: ContributionName,
    },
    #[error("pack {from} has no direct dependency alias {alias}")]
    UnknownDependencyAlias { from: PackNodeId, alias: Alias },
    #[error("pack {from} alias {alias} targets {target}, which has no module {module}")]
    UnknownDependencyModule {
        from: PackNodeId,
        alias: Alias,
        target: PackNodeId,
        module: ContributionName,
    },
}

/// Failure to select a component from a verified lock graph.
#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum ComponentResolutionError {
    #[error("unknown component pack {0}")]
    UnknownPack(PackNodeId),
    #[error("pack {node_id} has no component {name}")]
    UnknownComponent {
        node_id: PackNodeId,
        name: ContributionName,
    },
    #[error("verified pack {node_id} lacks component bytes at {path}")]
    MissingVerifiedBytes { node_id: PackNodeId, path: PackPath },
}

/// Borrowed component bytes with verified graph provenance.
#[derive(Clone, Copy, Debug)]
pub struct VerifiedComponentV1<'graph> {
    /// Locked-graph digest.
    pub graph_digest: &'graph Digest,
    /// Locked node containing the component.
    pub node_id: &'graph PackNodeId,
    /// Locked source for this occurrence.
    pub source: &'graph LockedSourceV1,
    /// Digest of the containing pack.
    pub pack_content_digest: &'graph Digest,
    /// Component declaration covered by the manifest and lock.
    pub declaration: &'graph LockedComponentV1,
    /// Bytes verified against the declaration.
    pub bytes: &'graph [u8],
}

impl VerifiedComponentV1<'_> {
    #[must_use]
    pub const fn is_remote(&self) -> bool {
        matches!(self.source, LockedSourceV1::Git(_))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct PackScopeV1 {
    modules: BTreeMap<ContributionName, ModuleIdV1>,
    dependencies: BTreeMap<Alias, PackNodeId>,
}

/// A verified offline pack graph with a private scope for each lock node.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AssembledLockedGraphV1 {
    graph_digest: Digest,
    root_node_id: PackNodeId,
    lock: LockV1,
    packs: BTreeMap<PackNodeId, Arc<VerifiedPackV1>>,
    scopes: BTreeMap<PackNodeId, PackScopeV1>,
    dependency_order: Vec<PackNodeId>,
}

impl AssembledLockedGraphV1 {
    #[must_use]
    pub const fn graph_digest(&self) -> &Digest {
        &self.graph_digest
    }

    #[must_use]
    pub const fn root_node_id(&self) -> &PackNodeId {
        &self.root_node_id
    }

    #[must_use]
    pub fn pack(&self, node_id: &PackNodeId) -> Option<&VerifiedPackV1> {
        self.packs.get(node_id).map(Arc::as_ref)
    }

    /// Returns the validated lock retained for policy provenance.
    #[must_use]
    pub const fn lock(&self) -> &LockV1 {
        &self.lock
    }

    /// Returns nodes in deterministic dependency-before-importer order.
    #[must_use]
    pub fn dependency_order(&self) -> &[PackNodeId] {
        &self.dependency_order
    }

    /// Selects a component with its locked-source provenance.
    pub fn component(
        &self,
        node_id: &PackNodeId,
        name: &ContributionName,
    ) -> Result<VerifiedComponentV1<'_>, ComponentResolutionError> {
        let node = self
            .lock
            .node(node_id)
            .ok_or_else(|| ComponentResolutionError::UnknownPack(node_id.clone()))?;
        let declaration = node
            .components()
            .binary_search_by(|component| component.name().cmp(name))
            .ok()
            .map(|index| &node.components()[index])
            .ok_or_else(|| ComponentResolutionError::UnknownComponent {
                node_id: node_id.clone(),
                name: name.clone(),
            })?;
        let pack = self
            .packs
            .get(node_id)
            .expect("assembled graph retains every locked pack");
        let bytes = pack.file(declaration.path()).ok_or_else(|| {
            ComponentResolutionError::MissingVerifiedBytes {
                node_id: node_id.clone(),
                path: declaration.path().clone(),
            }
        })?;
        Ok(VerifiedComponentV1 {
            graph_digest: &self.graph_digest,
            node_id: node.node_id(),
            source: node.source(),
            pack_content_digest: node.content_digest(),
            declaration,
            bytes,
        })
    }

    /// Resolves only local or directly aliased modules in `from`.
    pub fn resolve_module(
        &self,
        from: &PackNodeId,
        reference: &ModuleReferenceV1,
    ) -> Result<&ModuleIdV1, ModuleResolutionError> {
        let scope = self
            .scopes
            .get(from)
            .ok_or_else(|| ModuleResolutionError::UnknownPack(from.clone()))?;
        match reference {
            ModuleReferenceV1::Local(module) => {
                scope
                    .modules
                    .get(module)
                    .ok_or_else(|| ModuleResolutionError::UnknownLocalModule {
                        from: from.clone(),
                        module: module.clone(),
                    })
            }
            ModuleReferenceV1::Direct { dependency, module } => {
                let target = scope.dependencies.get(dependency).ok_or_else(|| {
                    ModuleResolutionError::UnknownDependencyAlias {
                        from: from.clone(),
                        alias: dependency.clone(),
                    }
                })?;
                self.scopes[target].modules.get(module).ok_or_else(|| {
                    ModuleResolutionError::UnknownDependencyModule {
                        from: from.clone(),
                        alias: dependency.clone(),
                        target: target.clone(),
                        module: module.clone(),
                    }
                })
            }
        }
    }
}

/// Failure to assemble a cached graph.
#[derive(Debug, Error)]
pub enum GraphAssemblyError<E> {
    #[error("load cached pack {digest}: {source}")]
    ObjectLoad { digest: Digest, source: E },
    #[error("verify cached pack {digest}: {source}")]
    ObjectVerification {
        digest: Digest,
        source: PackVerificationError,
    },
    #[error("{0}")]
    ManifestAgreement(#[source] LockValidationError),
    #[error("assembled graph {resource} is {actual}; limit is {limit}")]
    LimitExceeded {
        resource: &'static str,
        limit: u64,
        actual: u64,
    },
}

/// Loads and verifies each unique locked object without network or mutation.
pub fn assemble_locked_graph_v1<S>(
    lock: &LockV1,
    objects: &S,
) -> Result<AssembledLockedGraphV1, GraphAssemblyError<S::Error>>
where
    S: PackObjectSourceV1,
{
    assemble_locked_graph_with_verified_v1(lock, objects, &BTreeMap::new())
}

/// Assembles a lock graph and reuses caller-verified packs.
///
/// Supplied packs must come from [`VerifiedPackV1`]. They are looked up only by
/// the lock's content digest, so a mismatched key is ignored.
pub fn assemble_locked_graph_with_verified_v1<S>(
    lock: &LockV1,
    objects: &S,
    verified: &BTreeMap<Digest, Arc<VerifiedPackV1>>,
) -> Result<AssembledLockedGraphV1, GraphAssemblyError<S::Error>>
where
    S: PackObjectSourceV1,
{
    let mut by_digest: BTreeMap<Digest, Arc<VerifiedPackV1>> = BTreeMap::new();
    let mut packs = BTreeMap::new();
    let mut total_object_bytes = 0_u64;
    for node in lock.nodes() {
        let pack = if let Some(pack) = by_digest.get(node.content_digest()) {
            Arc::clone(pack)
        } else if let Some(pack) = verified.get(node.content_digest()) {
            charge_object_bytes(&mut total_object_bytes, pack.total_bytes())?;
            by_digest.insert(node.content_digest().clone(), Arc::clone(pack));
            Arc::clone(pack)
        } else {
            let files = objects.load_pack(node.content_digest()).map_err(|source| {
                GraphAssemblyError::ObjectLoad {
                    digest: node.content_digest().clone(),
                    source,
                }
            })?;
            let pack =
                VerifiedPackV1::from_files(node.content_digest(), files).map_err(|source| {
                    GraphAssemblyError::ObjectVerification {
                        digest: node.content_digest().clone(),
                        source,
                    }
                })?;
            charge_object_bytes(&mut total_object_bytes, pack.total_bytes())?;
            let pack = Arc::new(pack);
            by_digest.insert(node.content_digest().clone(), Arc::clone(&pack));
            pack
        };
        lock.validate_manifest(node.node_id(), pack.manifest())
            .map_err(GraphAssemblyError::ManifestAgreement)?;
        packs.insert(node.node_id().clone(), pack);
    }

    let module_count = lock
        .nodes()
        .iter()
        .map(|node| packs[node.node_id()].manifest().modules().len())
        .sum::<usize>();
    if module_count > MAX_GRAPH_MODULES {
        return Err(GraphAssemblyError::LimitExceeded {
            resource: "module entries",
            limit: malm_types::usize_to_u64(MAX_GRAPH_MODULES),
            actual: malm_types::usize_to_u64(module_count),
        });
    }

    let scopes = lock
        .nodes()
        .iter()
        .map(|node| {
            let manifest = packs[node.node_id()].manifest();
            let modules = manifest
                .modules()
                .iter()
                .map(|module| {
                    let id = ModuleIdV1::new(node.node_id().clone(), module.name().clone());
                    (module.name().clone(), id)
                })
                .collect();
            let dependencies = node
                .dependencies()
                .iter()
                .map(|edge| (edge.alias().clone(), edge.target_node_id().clone()))
                .collect();
            (
                node.node_id().clone(),
                PackScopeV1 {
                    modules,
                    dependencies,
                },
            )
        })
        .collect();

    Ok(AssembledLockedGraphV1 {
        graph_digest: lock_graph_digest(lock),
        root_node_id: lock.root_node_id().clone(),
        lock: lock.clone(),
        packs,
        scopes,
        dependency_order: dependency_order(lock),
    })
}

/// Charges newly retained object bytes to the shared graph budget.
fn charge_object_bytes<E>(
    total_object_bytes: &mut u64,
    additional: u64,
) -> Result<(), GraphAssemblyError<E>> {
    *total_object_bytes = total_object_bytes.saturating_add(additional);
    if *total_object_bytes > MAX_GRAPH_OBJECT_BYTES {
        return Err(GraphAssemblyError::LimitExceeded {
            resource: "unique object bytes",
            limit: MAX_GRAPH_OBJECT_BYTES,
            actual: *total_object_bytes,
        });
    }
    Ok(())
}

fn dependency_order(lock: &LockV1) -> Vec<PackNodeId> {
    let mut remaining = lock
        .nodes()
        .iter()
        .map(|node| {
            let unique_targets = node
                .dependencies()
                .iter()
                .map(|edge| edge.target_node_id())
                .collect::<BTreeSet<_>>()
                .len();
            (node.node_id().clone(), unique_targets)
        })
        .collect::<BTreeMap<_, _>>();
    let mut dependents: BTreeMap<PackNodeId, Vec<PackNodeId>> = BTreeMap::new();
    for node in lock.nodes() {
        for edge in node.dependencies() {
            dependents
                .entry(edge.target_node_id().clone())
                .or_default()
                .push(node.node_id().clone());
        }
    }
    for nodes in dependents.values_mut() {
        nodes.sort();
        nodes.dedup();
    }

    let mut ready = remaining
        .iter()
        .filter(|(_, count)| **count == 0)
        .map(|(node, _)| node.clone())
        .collect::<BTreeSet<_>>();
    let mut order = Vec::with_capacity(lock.nodes().len());
    while let Some(node) = ready.pop_first() {
        order.push(node.clone());
        if let Some(importers) = dependents.get(&node) {
            for importer in importers {
                let count = remaining
                    .get_mut(importer)
                    .expect("validated edge importer exists");
                *count -= 1;
                if *count == 0 {
                    ready.insert(importer.clone());
                }
            }
        }
    }
    debug_assert_eq!(order.len(), lock.nodes().len());
    order
}

#[cfg(test)]
mod tests {
    use std::{convert::Infallible, error::Error as _, io};

    use super::*;

    #[test]
    fn object_bytes_budget_accepts_the_limit_and_rejects_the_next_byte() {
        let mut total = 0_u64;
        charge_object_bytes::<Infallible>(&mut total, MAX_GRAPH_OBJECT_BYTES)
            .expect("charging exactly the budget succeeds");
        assert_eq!(total, MAX_GRAPH_OBJECT_BYTES);

        let error = charge_object_bytes::<Infallible>(&mut total, 1)
            .expect_err("one byte past the budget fails");
        let GraphAssemblyError::LimitExceeded {
            resource,
            limit,
            actual,
        } = &error
        else {
            panic!("expected LimitExceeded, got {error:?}");
        };
        assert_eq!(*resource, "unique object bytes");
        assert_eq!(*limit, MAX_GRAPH_OBJECT_BYTES);
        assert_eq!(*actual, MAX_GRAPH_OBJECT_BYTES + 1);
        assert_eq!(
            error.to_string(),
            format!(
                "assembled graph unique object bytes is {}; limit is {}",
                MAX_GRAPH_OBJECT_BYTES + 1,
                MAX_GRAPH_OBJECT_BYTES
            )
        );
    }

    #[test]
    fn object_bytes_budget_saturates_instead_of_wrapping() {
        let mut total = u64::MAX - 1;
        let error = charge_object_bytes::<Infallible>(&mut total, u64::MAX)
            .expect_err("a saturated total exceeds the budget");
        assert_eq!(total, u64::MAX);
        assert!(matches!(
            error,
            GraphAssemblyError::LimitExceeded {
                resource: "unique object bytes",
                limit: MAX_GRAPH_OBJECT_BYTES,
                actual: u64::MAX,
            }
        ));
    }

    #[test]
    fn error_displays_and_source_chains_match_the_hand_written_impls() {
        let digest = Digest::sha256(b"object");
        let node_id = PackNodeId::new(Digest::sha256(b"node"));

        let tree_error = PackTreeError::MissingManifest;
        let tree_text = tree_error.to_string();
        let error = PackVerificationError::InvalidTree(tree_error);
        assert_eq!(error.to_string(), format!("invalid pack tree: {tree_text}"));
        assert_eq!(error.source().expect("has source").to_string(), tree_text);

        let read_error = PackReadError::InvalidUtf8;
        let read_text = read_error.to_string();
        let error = PackVerificationError::InvalidManifest(read_error);
        assert_eq!(
            error.to_string(),
            format!("invalid pack manifest: {read_text}")
        );
        assert_eq!(error.source().expect("has source").to_string(), read_text);

        let error = PackVerificationError::MissingManifest;
        assert_eq!(error.to_string(), "pack object is missing malm-pack.kdl");
        assert!(error.source().is_none());

        let io_error = io::Error::other("cache miss");
        let error = GraphAssemblyError::ObjectLoad {
            digest: digest.clone(),
            source: io_error,
        };
        assert_eq!(
            error.to_string(),
            format!("load cached pack {digest}: cache miss")
        );
        assert_eq!(
            error.source().expect("has source").to_string(),
            "cache miss"
        );

        let error = GraphAssemblyError::<io::Error>::ObjectVerification {
            digest: digest.clone(),
            source: PackVerificationError::MissingManifest,
        };
        assert_eq!(
            error.to_string(),
            format!("verify cached pack {digest}: pack object is missing malm-pack.kdl")
        );
        assert_eq!(
            error.source().expect("has source").to_string(),
            "pack object is missing malm-pack.kdl"
        );

        let lock_error = LockValidationError::DuplicateNode(node_id.clone());
        let lock_text = lock_error.to_string();
        let error = GraphAssemblyError::<io::Error>::ManifestAgreement(lock_error);
        assert_eq!(error.to_string(), lock_text);
        assert_eq!(error.source().expect("has source").to_string(), lock_text);

        let error = GraphAssemblyError::<io::Error>::LimitExceeded {
            resource: "module entries",
            limit: 1,
            actual: 2,
        };
        assert!(error.source().is_none());

        let error = ModuleResolutionError::UnknownPack(node_id.clone());
        assert_eq!(
            error.to_string(),
            format!("unknown importing pack node {node_id}")
        );
        assert!(error.source().is_none());

        let error = ComponentResolutionError::UnknownPack(node_id.clone());
        assert_eq!(
            error.to_string(),
            format!("unknown component pack {node_id}")
        );
        assert!(error.source().is_none());
    }
}
