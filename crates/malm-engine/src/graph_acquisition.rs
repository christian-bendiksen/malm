use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use malm_pack::{LocalLocator, LockV1, LockedSourceV1};
use malm_types::Digest;

use super::{
    Engine, EngineError, GitAcquisitionConfig, GraphAcquisitionError, GraphAcquisitionInputs,
    PackObjectIssue,
};

pub(super) fn acquire(
    engine: &Engine,
    root_source: &Path,
    lock: &LockV1,
    inputs: &GraphAcquisitionInputs,
    git: &GitAcquisitionConfig,
) -> Result<malm_module_graph::AssembledLockedGraphV1, GraphAcquisitionError> {
    validate_mixed_grants(lock, inputs)?;
    let missing_git = missing_git_objects(engine, lock)?;
    for digest in &missing_git {
        if !inputs.git_scratch_roots().contains_key(digest) {
            return Err(GraphAcquisitionError::MissingGitScratch {
                digest: digest.clone(),
            });
        }
    }

    let mut handled_git = BTreeSet::new();
    for node in lock.nodes() {
        let LockedSourceV1::Git(git_source) = node.source() else {
            continue;
        };
        if !missing_git.contains(node.content_digest()) {
            continue;
        }
        if !handled_git.insert(node.content_digest().clone()) {
            continue;
        }
        let scratch = inputs
            .git_scratch_roots()
            .get(node.content_digest())
            .expect("missing Git scratch was preflighted");
        engine
            .acquire_git_pack_raw(git_source, node.content_digest(), git, scratch)
            .map_err(|source| GraphAcquisitionError::Source {
                node_id: node.node_id().clone(),
                source,
            })?;
    }

    let verified = acquire_local_sources(engine, root_source, lock)?;
    engine
        .assemble_pack_graph_with_verified_raw(lock, &verified)
        .map_err(|source| GraphAcquisitionError::Assembly { source })
}

pub(super) fn acquire_local(
    engine: &Engine,
    root_source: &Path,
    lock: &LockV1,
    granted_locators: &BTreeSet<LocalLocator>,
) -> Result<malm_module_graph::AssembledLockedGraphV1, GraphAcquisitionError> {
    // Complete authority validation precedes every source read and CAS write.
    for node in lock.nodes() {
        match node.source() {
            LockedSourceV1::Root => {}
            LockedSourceV1::Local(locator) if granted_locators.contains(locator) => {}
            LockedSourceV1::Local(locator) => {
                return Err(GraphAcquisitionError::LocalSourceNotGranted {
                    node_id: node.node_id().clone(),
                    locator: locator.clone(),
                });
            }
            LockedSourceV1::Git(git_source) => {
                return Err(GraphAcquisitionError::UnsupportedGitSource {
                    node_id: node.node_id().clone(),
                    git_source: git_source.clone(),
                });
            }
        }
    }

    let verified = acquire_local_sources(engine, root_source, lock)?;

    engine
        .assemble_pack_graph_with_verified_raw(lock, &verified)
        .map_err(|source| GraphAcquisitionError::Assembly { source })
}

fn validate_mixed_grants(
    lock: &LockV1,
    inputs: &GraphAcquisitionInputs,
) -> Result<(), GraphAcquisitionError> {
    for node in lock.nodes() {
        match node.source() {
            LockedSourceV1::Root => {}
            LockedSourceV1::Local(locator) if inputs.local_locators().contains(locator) => {}
            LockedSourceV1::Local(locator) => {
                return Err(GraphAcquisitionError::LocalSourceNotGranted {
                    node_id: node.node_id().clone(),
                    locator: locator.clone(),
                });
            }
            LockedSourceV1::Git(git_source) if inputs.git_urls().contains(git_source.url()) => {}
            LockedSourceV1::Git(git_source) => {
                return Err(GraphAcquisitionError::GitSourceNotGranted {
                    node_id: node.node_id().clone(),
                    url: git_source.url().clone(),
                });
            }
        }
    }
    Ok(())
}

fn missing_git_objects(
    engine: &Engine,
    lock: &LockV1,
) -> Result<BTreeSet<Digest>, GraphAcquisitionError> {
    let mut missing = BTreeSet::new();
    let mut observed = BTreeMap::<Digest, malm_types::PackNodeId>::new();
    for node in lock.nodes() {
        if !matches!(node.source(), LockedSourceV1::Git(_))
            || observed.contains_key(node.content_digest())
        {
            continue;
        }
        observed.insert(node.content_digest().clone(), node.node_id().clone());
        match engine.load_pack_object_raw(node.content_digest()) {
            Ok(_) => {}
            Err(EngineError::PackObject {
                reason: PackObjectIssue::Missing,
                ..
            }) => {
                missing.insert(node.content_digest().clone());
            }
            Err(source) => {
                return Err(GraphAcquisitionError::Source {
                    node_id: node.node_id().clone(),
                    source,
                });
            }
        }
    }
    Ok(missing)
}

/// Captures every local source and returns the verified packs by digest so
/// assembly consumes the exact captured bytes without re-reading the store.
fn acquire_local_sources(
    engine: &Engine,
    root_source: &Path,
    lock: &LockV1,
) -> Result<
    BTreeMap<Digest, std::sync::Arc<malm_module_graph::VerifiedPackV1>>,
    GraphAcquisitionError,
> {
    let mut verified = BTreeMap::new();
    let root = lock
        .node(lock.root_node_id())
        .expect("validated lock root node exists");
    let captured =
        super::pack_capture::capture_discovered(engine, root_source, root.content_digest())
            .map_err(|source| GraphAcquisitionError::Source {
                node_id: root.node_id().clone(),
                source,
            })?;
    verified.insert(
        captured.digest.clone(),
        std::sync::Arc::clone(&captured.pack),
    );

    for node in lock.nodes() {
        let LockedSourceV1::Local(locator) = node.source() else {
            continue;
        };
        let source_root = resolve_locator(root_source, locator);
        let captured =
            super::pack_capture::capture_discovered(engine, &source_root, node.content_digest())
                .map_err(|source| GraphAcquisitionError::Source {
                    node_id: node.node_id().clone(),
                    source,
                })?;
        verified.insert(
            captured.digest.clone(),
            std::sync::Arc::clone(&captured.pack),
        );
    }
    Ok(verified)
}

pub(super) fn resolve_locator(root_source: &Path, locator: &LocalLocator) -> PathBuf {
    if locator.as_str() == "." {
        return root_source.to_path_buf();
    }

    let mut resolved = root_source.to_path_buf();
    for component in locator.as_str().split('/') {
        if component == ".." {
            resolved.pop();
        } else {
            resolved.push(component);
        }
    }
    resolved
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn locators_are_always_relative_to_the_root_pack() {
        let root = Path::new("/work/root");
        assert_eq!(
            resolve_locator(root, &LocalLocator::new("packs/leaf").unwrap()),
            Path::new("/work/root/packs/leaf")
        );
        assert_eq!(
            resolve_locator(root, &LocalLocator::new("../shared").unwrap()),
            Path::new("/work/shared")
        );
        assert_eq!(
            resolve_locator(root, &LocalLocator::new(".").unwrap()),
            root
        );
    }
}
