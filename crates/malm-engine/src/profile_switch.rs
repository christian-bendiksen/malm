use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    error::Error,
    fmt,
};

use malm_pack::{
    DependencySourceV1, LockV1, LockedComponentV1, LockedDependencyV1, LockedPackV1,
    LockedSourceV1, PackDependencyV1, PackManifestV1, PackPath, pack_node_id,
};
use malm_store::{AcquisitionGrantKindV1, LifecycleStateV1, PreparedInputKindV1};
use malm_types::{
    ContributionName, DeploymentName, Digest, NamespaceName, NamespaceStatusKindV1,
    NamespaceStatusRequestV1, PackNodeId, PrepareInputKindV1, PrepareInputV1, PreparedDeploymentV1,
};

use crate::{CommitError, Engine, EngineError, StaticPrepareError, config_prepare, prepared_store};

/// Request to evaluate another profile from the active generation's exact retained pack graph.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProfileSwitchRequestV1 {
    namespace: NamespaceName,
    profile: ContributionName,
}

impl ProfileSwitchRequestV1 {
    #[must_use]
    pub const fn new(namespace: NamespaceName, profile: ContributionName) -> Self {
        Self { namespace, profile }
    }

    #[must_use]
    pub const fn namespace(&self) -> &NamespaceName {
        &self.namespace
    }

    #[must_use]
    pub const fn profile(&self) -> &ContributionName {
        &self.profile
    }
}

/// Failure while preparing an offline profile switch from selected retained authority.
#[derive(Debug)]
#[non_exhaustive]
pub enum ProfileSwitchError {
    State(CommitError),
    NamespaceNotFound {
        namespace: NamespaceName,
    },
    NamespaceDisabled {
        namespace: NamespaceName,
    },
    NamespaceNotExact {
        namespace: NamespaceName,
        status: NamespaceStatusKindV1,
    },
    RetainedPlan(EngineError),
    InvalidRetainedGraph {
        detail: String,
    },
    PackObject {
        node_id: PackNodeId,
        digest: Digest,
        source: EngineError,
    },
    PackVerification {
        node_id: PackNodeId,
        digest: Digest,
        source: malm_module_graph::PackVerificationError,
    },
    LockValidation(malm_pack::LockValidationError),
    GraphAssembly(malm_module_graph::GraphAssemblyError<EngineError>),
    GraphIdentityMismatch {
        retained: Digest,
        assembled: Digest,
    },
    Static(StaticPrepareError),
}

impl fmt::Display for ProfileSwitchError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::State(error) => error.fmt(formatter),
            Self::NamespaceNotFound { namespace } => {
                write!(formatter, "namespace {namespace} does not exist")
            }
            Self::NamespaceDisabled { namespace } => {
                write!(formatter, "namespace {namespace} is disabled")
            }
            Self::NamespaceNotExact { namespace, status } => write!(
                formatter,
                "namespace {namespace} is not exact (status {})",
                status_name(*status)
            ),
            Self::RetainedPlan(error) => write!(formatter, "load retained prepared plan: {error}"),
            Self::InvalidRetainedGraph { detail } => {
                write!(formatter, "invalid retained pack graph authority: {detail}")
            }
            Self::PackObject {
                node_id,
                digest,
                source,
            } => write!(
                formatter,
                "load retained pack {node_id} with content digest {digest}: {source}"
            ),
            Self::PackVerification {
                node_id,
                digest,
                source,
            } => write!(
                formatter,
                "verify retained pack {node_id} with content digest {digest}: {source}"
            ),
            Self::LockValidation(error) => {
                write!(formatter, "rebuild retained lock graph: {error}")
            }
            Self::GraphAssembly(error) => {
                write!(formatter, "assemble retained pack graph: {error}")
            }
            Self::GraphIdentityMismatch {
                retained,
                assembled,
            } => write!(
                formatter,
                "retained graph identity is {retained}, reconstructed graph is {assembled}"
            ),
            Self::Static(error) => error.fmt(formatter),
        }
    }
}

impl Error for ProfileSwitchError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        // The cause already appears in Display, and source() would duplicate it.
        None
    }
}

pub(super) fn prepare(
    engine: &Engine,
    request: &ProfileSwitchRequestV1,
) -> Result<PreparedDeploymentV1, ProfileSwitchError> {
    let committer = engine.committer_v1().map_err(ProfileSwitchError::State)?;
    let status = committer
        .inspect_namespace_status_v1(&NamespaceStatusRequestV1::new(request.namespace().clone()))
        .map_err(ProfileSwitchError::State)?;
    match status.status() {
        NamespaceStatusKindV1::EnabledExact => {}
        NamespaceStatusKindV1::NotFound => {
            return Err(ProfileSwitchError::NamespaceNotFound {
                namespace: request.namespace().clone(),
            });
        }
        NamespaceStatusKindV1::Disabled => {
            return Err(ProfileSwitchError::NamespaceDisabled {
                namespace: request.namespace().clone(),
            });
        }
        status => {
            return Err(ProfileSwitchError::NamespaceNotExact {
                namespace: request.namespace().clone(),
                status,
            });
        }
    }
    let head = status
        .head()
        .cloned()
        .expect("an exact namespace status has a selected head");
    let generation = committer
        .inspect_generation_v1(&head)
        .map_err(ProfileSwitchError::State)?;
    if generation.namespace() != request.namespace()
        || generation.lifecycle_state() != LifecycleStateV1::Enabled
    {
        return Err(invalid_graph(
            "selected generation disagrees with the exact namespace status",
        ));
    }
    let retained = prepared_store::load_retained_graph_record(engine, &generation)
        .map_err(ProfileSwitchError::RetainedPlan)?
        .ok_or_else(|| invalid_graph("selected generation retains no pack graph authority"))?;
    if retained.namespace() != request.namespace() {
        return Err(invalid_graph(
            "selected generation's prepared plan belongs to another namespace",
        ));
    }
    validate_lock_input(&retained)?;
    let locked_component_profiles = retained_component_profiles(&retained)?;

    // An exact retained match can switch without pack access. Live overlay
    // recapture gates the match; misses and new consent shapes reconstruct.
    if generation.tracked_root().is_none()
        && let Some(plan) = try_reuse_without_pack(engine, request, &head, &retained)?
    {
        return Ok(plan);
    }

    let graph = reconstruct_graph(engine, &retained, locked_component_profiles)?;
    if graph.graph_digest() != retained.graph_digest() {
        return Err(ProfileSwitchError::GraphIdentityMismatch {
            retained: retained.graph_digest().clone(),
            assembled: graph.graph_digest().clone(),
        });
    }

    let authorization = malm_format_component_api::FormatComponentAuthorizationV1::new(
        retained
            .inputs()
            .iter()
            .filter(|input| input.kind() == PreparedInputKindV1::Component)
            .map(|input| input.digest().clone()),
    );
    let target_authority = selected_target_authority(&retained)?;
    let config_entry = selected_config_entry(&retained, generation.tracked_root())?;
    let tracked_root = match generation.tracked_root() {
        Some(tracked) => {
            let selected =
                config_prepare::selected_profile(&graph, &config_entry, Some(request.profile()))
                    .map_err(ProfileSwitchError::Static)?;
            let tracked = tracked
                .clone()
                .with_selected_profile(selected)
                .map_err(|error| invalid_graph(error.to_string()))?;
            Some(tracked)
        }
        None => None,
    };

    config_prepare::prepare(
        config_prepare::StaticPrepareContext {
            engine,
            graph: &graph,
            component_authorization: &authorization,
            namespace: request.namespace().clone(),
            target_authority,
            expected_head: Some(head),
            tracked_root: tracked_root.as_ref(),
        },
        Some(request.profile()),
        Some(&config_entry),
    )
    .map_err(ProfileSwitchError::Static)
}

/// Attempts a pack-free switch from a retained matching evaluation.
fn try_reuse_without_pack(
    engine: &Engine,
    request: &ProfileSwitchRequestV1,
    head: &Digest,
    retained: &malm_store::PreparedRecordV1,
) -> Result<Option<PreparedDeploymentV1>, ProfileSwitchError> {
    // Recompute declaration identities; any inconsistency disables reuse.
    let mut declarations = Vec::new();
    for input in retained.inputs() {
        let Some(rest) = input.name().strip_prefix("overlay-declaration:") else {
            continue;
        };
        let Some((name, rest)) = rest.split_once(':') else {
            return Ok(None);
        };
        let Some((requirement, path)) = rest.split_once(':') else {
            return Ok(None);
        };
        let declaration = crate::authoring_prepare::OverlayDeclarationV1 {
            name: name.to_owned(),
            path: path.to_owned(),
            optional: match requirement {
                "opt" => true,
                "req" => false,
                _ => return Ok(None),
            },
        };
        if &declaration.identity() != input.digest() {
            return Ok(None);
        }
        declarations.push(declaration);
    }
    let has_declaration_inputs = !declarations.is_empty()
        || retained
            .inputs()
            .iter()
            .all(|input| !input.name().starts_with("overlay:"));
    if !has_declaration_inputs {
        // Older records without declaration inputs require full evaluation.
        return Ok(None);
    }

    // Full reconstruction reports canonical errors for incomplete records.
    let Ok(target_authority) = selected_target_authority(retained) else {
        return Ok(None);
    };
    let Ok(config_entry) = selected_config_entry(retained, None) else {
        return Ok(None);
    };
    let overlays =
        match crate::authoring_prepare::read_overlay_files(engine, declarations, &target_authority)
        {
            Ok(overlays) => overlays,
            // Full reconstruction reports the canonical overlay error.
            Err(_) => return Ok(None),
        };

    let mut core = vec![
        PrepareInputV1::new(
            PrepareInputKindV1::Other,
            format!(
                "{}{}",
                config_prepare::STATIC_CONFIG_ENTRY_INPUT_PREFIX,
                config_entry
            ),
            config_prepare::static_config_entry_digest(&config_entry),
        )
        .map_err(|error| invalid_graph(error.to_string()))?,
        PrepareInputV1::new(
            PrepareInputKindV1::Other,
            format!(
                "{}{}",
                config_prepare::STATIC_TARGET_AUTHORITY_INPUT_PREFIX,
                target_authority
            ),
            config_prepare::static_target_authority_digest(&target_authority),
        )
        .map_err(|error| invalid_graph(error.to_string()))?,
        PrepareInputV1::new(
            PrepareInputKindV1::Other,
            format!(
                "{}{}",
                config_prepare::STATIC_PROFILE_INPUT_PREFIX,
                request.profile()
            ),
            config_prepare::static_profile_digest(request.profile().as_str()),
        )
        .map_err(|error| invalid_graph(error.to_string()))?,
        PrepareInputV1::new(
            PrepareInputKindV1::Lock,
            "locked-graph",
            retained.graph_digest().clone(),
        )
        .map_err(|error| invalid_graph(error.to_string()))?,
        crate::authoring_prepare::evaluator_input()
            .map_err(|error| invalid_graph(error.to_string()))?,
    ];
    for input in retained.inputs() {
        if input.kind() == PreparedInputKindV1::Source && input.name().starts_with("pack:") {
            core.push(
                PrepareInputV1::new(
                    PrepareInputKindV1::Source,
                    input.name(),
                    input.digest().clone(),
                )
                .map_err(|error| invalid_graph(error.to_string()))?,
            );
        } else if input.kind() == PreparedInputKindV1::Other
            && (input.name() == config_prepare::LOCKED_COMPONENT_PROFILES_INPUT
                || input
                    .name()
                    .starts_with(config_prepare::LOCKED_COMPONENT_PROFILE_INPUT_PREFIX))
        {
            core.push(
                PrepareInputV1::new(
                    PrepareInputKindV1::Other,
                    input.name(),
                    input.digest().clone(),
                )
                .map_err(|error| invalid_graph(error.to_string()))?,
            );
        }
    }
    core.extend(
        crate::authoring_prepare::overlay_inputs(&overlays)
            .map_err(|error| invalid_graph(error.to_string()))?,
    );

    let Some(reused) = crate::prepare_reuse::find_reusable_evaluation(
        engine,
        request.namespace(),
        retained.graph_digest(),
        &core,
    ) else {
        return Ok(None);
    };
    let overlay_findings = crate::authoring_prepare::overlay_applied_findings(&overlays.applied)
        .map_err(|error| invalid_graph(error.to_string()))?;
    match crate::prepare_reuse::submit_reused(
        engine,
        request.namespace().clone(),
        Some(head.clone()),
        retained.graph_digest().clone(),
        reused,
        overlay_findings,
    ) {
        Ok(plan) => Ok(Some(plan)),
        Err(error) if crate::prepare_reuse::is_consent_shape_refusal(&error) => Ok(None),
        Err(error) => Err(ProfileSwitchError::Static(StaticPrepareError::Store(error))),
    }
}

fn validate_lock_input(retained: &malm_store::PreparedRecordV1) -> Result<(), ProfileSwitchError> {
    let inputs = retained
        .inputs()
        .iter()
        .filter(|input| input.kind() == PreparedInputKindV1::Lock)
        .collect::<Vec<_>>();
    let [input] = inputs.as_slice() else {
        return Err(invalid_graph(
            "the active prepared plan must contain exactly one lock input",
        ));
    };
    if input.name() != "locked-graph" || input.digest() != retained.graph_digest() {
        return Err(invalid_graph(
            "the active prepared plan's locked-graph input does not match its graph identity",
        ));
    }
    Ok(())
}

fn retained_component_profiles(
    retained: &malm_store::PreparedRecordV1,
) -> Result<BTreeMap<(PackNodeId, ContributionName), Digest>, ProfileSwitchError> {
    let summaries = retained
        .inputs()
        .iter()
        .filter(|input| input.name() == config_prepare::LOCKED_COMPONENT_PROFILES_INPUT)
        .collect::<Vec<_>>();
    let [summary] = summaries.as_slice() else {
        return Err(invalid_graph(
            "the active prepared plan must contain exactly one locked-component-profiles input",
        ));
    };
    if summary.kind() != PreparedInputKindV1::Other {
        return Err(invalid_graph(
            "the locked-component-profiles input has the wrong kind",
        ));
    }

    let mut encoded = BTreeMap::new();
    let mut profiles = BTreeMap::new();
    for input in retained.inputs() {
        let Some(rest) = input
            .name()
            .strip_prefix(config_prepare::LOCKED_COMPONENT_PROFILE_INPUT_PREFIX)
        else {
            continue;
        };
        if input.kind() != PreparedInputKindV1::Other {
            return Err(invalid_graph(
                "a locked component profile input has the wrong kind",
            ));
        }
        let (node, name) = rest
            .split_once(':')
            .ok_or_else(|| invalid_graph("a locked component profile input name is malformed"))?;
        let node =
            PackNodeId::new(Digest::new(node.to_owned()).map_err(|error| {
                invalid_graph(format!("invalid component pack node ID: {error}"))
            })?);
        let name = ContributionName::new(name.to_owned())
            .map_err(|error| invalid_graph(format!("invalid locked component name: {error}")))?;
        let canonical = format!(
            "{}{}:{}",
            config_prepare::LOCKED_COMPONENT_PROFILE_INPUT_PREFIX,
            node,
            name
        );
        if input.name() != canonical {
            return Err(invalid_graph(
                "a locked component profile input name is not canonical",
            ));
        }
        if encoded.insert(canonical, input.digest().clone()).is_some()
            || profiles
                .insert((node, name), input.digest().clone())
                .is_some()
        {
            return Err(invalid_graph(
                "one locked component profile is retained more than once",
            ));
        }
    }
    if summary.digest() != &config_prepare::locked_component_profiles_digest(&encoded) {
        return Err(invalid_graph(
            "the locked-component-profiles input does not match its entries",
        ));
    }
    Ok(profiles)
}

struct RetainedPack {
    digest: Digest,
    manifest: PackManifestV1,
    verified: std::sync::Arc<malm_module_graph::VerifiedPackV1>,
}

fn reconstruct_graph(
    engine: &Engine,
    retained: &malm_store::PreparedRecordV1,
    mut component_profiles: BTreeMap<(PackNodeId, ContributionName), Digest>,
) -> Result<malm_module_graph::AssembledLockedGraphV1, ProfileSwitchError> {
    let mut packs = BTreeMap::<PackNodeId, RetainedPack>::new();
    for input in retained
        .inputs()
        .iter()
        .filter(|input| input.kind() == PreparedInputKindV1::Source)
    {
        let node_text = input.name().strip_prefix("pack:").ok_or_else(|| {
            invalid_graph(format!(
                "source input {:?} is not named pack:NODE_ID",
                input.name()
            ))
        })?;
        let node_id = PackNodeId::new(
            Digest::new(node_text.to_owned())
                .map_err(|error| invalid_graph(format!("invalid pack input node ID: {error}")))?,
        );
        if input.name() != format!("pack:{node_id}") {
            return Err(invalid_graph("pack input name is not canonical"));
        }
        let files = engine
            .load_pack_object_raw(input.digest())
            .map_err(|source| ProfileSwitchError::PackObject {
                node_id: node_id.clone(),
                digest: input.digest().clone(),
                source,
            })?;
        let verified = malm_module_graph::VerifiedPackV1::from_files(input.digest(), files)
            .map_err(|source| ProfileSwitchError::PackVerification {
                node_id: node_id.clone(),
                digest: input.digest().clone(),
                source,
            })?;
        if packs
            .insert(
                node_id,
                RetainedPack {
                    digest: input.digest().clone(),
                    manifest: verified.manifest().clone(),
                    verified: std::sync::Arc::new(verified),
                },
            )
            .is_some()
        {
            return Err(invalid_graph("one pack node ID is retained more than once"));
        }
    }
    if packs.is_empty() {
        return Err(invalid_graph("the active prepared plan has no pack inputs"));
    }

    let roots = packs
        .iter()
        .filter(|(node_id, pack)| {
            &pack_node_id(
                &LockedSourceV1::Root,
                pack.manifest.package_id(),
                &pack.digest,
            ) == *node_id
        })
        .map(|(node_id, _)| node_id.clone())
        .collect::<Vec<_>>();
    let [root_node_id] = roots.as_slice() else {
        return Err(invalid_graph(
            "retained pack inputs do not identify exactly one root node",
        ));
    };

    let mut sources = BTreeMap::from([(root_node_id.clone(), LockedSourceV1::Root)]);
    let mut edges = BTreeMap::<PackNodeId, Vec<LockedDependencyV1>>::new();
    let mut pending = VecDeque::from([root_node_id.clone()]);
    while let Some(importer) = pending.pop_front() {
        for dependency in packs[&importer].manifest.dependencies() {
            let source = locked_source(dependency.source());
            let candidates = dependency_candidates(&packs, dependency, &source);
            let [target] = candidates.as_slice() else {
                return Err(invalid_graph(format!(
                    "dependency {} from pack {importer} does not identify exactly one retained node",
                    dependency.alias()
                )));
            };
            if let Some(previous) = sources.insert(target.clone(), source.clone()) {
                if previous != source {
                    return Err(invalid_graph(format!(
                        "retained node {target} is selected through conflicting sources"
                    )));
                }
            } else {
                pending.push_back(target.clone());
            }
            edges
                .entry(importer.clone())
                .or_default()
                .push(LockedDependencyV1::new(
                    dependency.alias().clone(),
                    target.clone(),
                ));
        }
    }
    if sources.len() != packs.len() {
        return Err(invalid_graph(
            "the active prepared plan contains an unreachable pack input",
        ));
    }

    let mut nodes = Vec::with_capacity(packs.len());
    for (node_id, pack) in &packs {
        let components = pack
            .manifest
            .components()
            .iter()
            .map(|declaration| {
                let profile = component_profiles
                    .remove(&(node_id.clone(), declaration.name().clone()))
                    .ok_or_else(|| {
                        invalid_graph(format!(
                            "retained pack {node_id} component {} has no locked execution profile",
                            declaration.name()
                        ))
                    })?;
                Ok(LockedComponentV1::from_declaration(declaration, profile))
            })
            .collect::<Result<Vec<_>, ProfileSwitchError>>()?;
        let node = LockedPackV1::new(
            pack.manifest.package_id().clone(),
            sources[node_id].clone(),
            pack.digest.clone(),
            edges.remove(node_id).unwrap_or_default(),
            components,
        )
        .map_err(ProfileSwitchError::LockValidation)?;
        if node.node_id() != node_id {
            return Err(ProfileSwitchError::LockValidation(
                malm_pack::LockValidationError::NodeIdMismatch {
                    found: node_id.clone(),
                    expected: node.node_id().clone(),
                },
            ));
        }
        nodes.push(node);
    }
    if !component_profiles.is_empty() {
        return Err(invalid_graph(
            "the active prepared plan retains profiles for unknown locked components",
        ));
    }
    let lock =
        LockV1::new(root_node_id.clone(), nodes).map_err(ProfileSwitchError::LockValidation)?;
    // Assemble from the verified packs above without rereading the store.
    let verified = packs
        .values()
        .map(|pack| (pack.digest.clone(), std::sync::Arc::clone(&pack.verified)))
        .collect::<BTreeMap<_, _>>();
    engine
        .assemble_pack_graph_with_verified_raw(&lock, &verified)
        .map_err(ProfileSwitchError::GraphAssembly)
}

fn dependency_candidates(
    packs: &BTreeMap<PackNodeId, RetainedPack>,
    dependency: &PackDependencyV1,
    source: &LockedSourceV1,
) -> Vec<PackNodeId> {
    packs
        .iter()
        .filter(|(node_id, pack)| {
            pack.manifest.package_id() == dependency.package_id()
                && &pack_node_id(source, dependency.package_id(), &pack.digest) == *node_id
        })
        .map(|(node_id, _)| node_id.clone())
        .collect()
}

fn locked_source(source: &DependencySourceV1) -> LockedSourceV1 {
    match source {
        DependencySourceV1::Git(source) => LockedSourceV1::Git(source.clone()),
        DependencySourceV1::Local(locator) => LockedSourceV1::Local(locator.clone()),
    }
}

fn selected_target_authority(
    retained: &malm_store::PreparedRecordV1,
) -> Result<DeploymentName, ProfileSwitchError> {
    let persisted = retained_static_target_authority(retained)?;
    if let Some(tracked) = retained.tracked_root() {
        let authorities = tracked
            .acquisition_grants()
            .iter()
            .filter(|grant| grant.kind() == AcquisitionGrantKindV1::TargetAuthority)
            .map(|grant| DeploymentName::new(grant.locator().as_str().to_owned()))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| invalid_graph(error.to_string()))?;
        let [authority] = authorities.as_slice() else {
            return Err(invalid_graph(
                "tracked authority must contain exactly one target grant",
            ));
        };
        if persisted
            .as_ref()
            .is_some_and(|persisted| persisted != authority)
        {
            return Err(invalid_graph(
                "static target-authority input disagrees with tracked authority",
            ));
        }
        return Ok(authority.clone());
    }

    if let Some(authority) = persisted {
        return Ok(authority);
    }

    let mut authorities = retained
        .desired_snapshot()
        .targets()
        .iter()
        .filter(|target| target.is_present())
        .map(|target| target.authority().clone())
        .collect::<BTreeSet<_>>();
    let authority = authorities.pop_first().filter(|_| authorities.is_empty());
    authority.ok_or_else(|| {
        invalid_graph(
            "legacy static profile switch requires exactly one present retained target authority",
        )
    })
}

fn retained_static_target_authority(
    retained: &malm_store::PreparedRecordV1,
) -> Result<Option<DeploymentName>, ProfileSwitchError> {
    let inputs = retained
        .inputs()
        .iter()
        .filter(|input| input.kind() == PreparedInputKindV1::Other)
        .filter_map(|input| {
            input
                .name()
                .strip_prefix(config_prepare::STATIC_TARGET_AUTHORITY_INPUT_PREFIX)
                .map(|value| (input, value))
        })
        .collect::<Vec<_>>();
    let ([] | [_]) = inputs.as_slice() else {
        return Err(invalid_graph(
            "active prepared plan contains multiple static target-authority inputs",
        ));
    };
    let Some((input, value)) = inputs.first() else {
        return Ok(None);
    };
    let authority = DeploymentName::new((*value).to_owned())
        .map_err(|error| invalid_graph(error.to_string()))?;
    if input.name()
        != format!(
            "{}{authority}",
            config_prepare::STATIC_TARGET_AUTHORITY_INPUT_PREFIX
        )
        || input.digest() != &config_prepare::static_target_authority_digest(&authority)
    {
        return Err(invalid_graph(
            "static target-authority input is not canonical",
        ));
    }
    Ok(Some(authority))
}

fn selected_config_entry(
    retained: &malm_store::PreparedRecordV1,
    tracked: Option<&malm_store::TrackedRootV1>,
) -> Result<PackPath, ProfileSwitchError> {
    let inputs = retained
        .inputs()
        .iter()
        .filter(|input| input.kind() == PreparedInputKindV1::Other)
        .filter_map(|input| {
            input
                .name()
                .strip_prefix(config_prepare::STATIC_CONFIG_ENTRY_INPUT_PREFIX)
                .map(|value| (input, value))
        })
        .collect::<Vec<_>>();
    let ([] | [_]) = inputs.as_slice() else {
        return Err(invalid_graph(
            "active prepared plan contains multiple static config-entry inputs",
        ));
    };
    let persisted = inputs
        .first()
        .map(|(input, value)| {
            let entry = PackPath::new(*value).map_err(|error| invalid_graph(error.to_string()))?;
            if input.name()
                != format!(
                    "{}{entry}",
                    config_prepare::STATIC_CONFIG_ENTRY_INPUT_PREFIX
                )
                || input.digest() != &config_prepare::static_config_entry_digest(&entry)
            {
                return Err(invalid_graph("static config-entry input is not canonical"));
            }
            Ok(entry)
        })
        .transpose()?;
    if let Some(tracked) = tracked {
        let entry = PackPath::new(tracked.config_entry_point().as_str())
            .map_err(|error| invalid_graph(error.to_string()))?;
        if persisted
            .as_ref()
            .is_some_and(|persisted| persisted != &entry)
        {
            return Err(invalid_graph(
                "static config-entry input disagrees with tracked authority",
            ));
        }
        return Ok(entry);
    }
    persisted.map_or_else(
        || {
            PackPath::new(malm_config::CONFIG_FILE)
                .map_err(|error| invalid_graph(error.to_string()))
        },
        Ok,
    )
}

fn invalid_graph(detail: impl Into<String>) -> ProfileSwitchError {
    ProfileSwitchError::InvalidRetainedGraph {
        detail: detail.into(),
    }
}

const fn status_name(status: NamespaceStatusKindV1) -> &'static str {
    match status {
        NamespaceStatusKindV1::NotFound => "not-found",
        NamespaceStatusKindV1::EnabledExact => "enabled-exact",
        NamespaceStatusKindV1::EnabledModified => "enabled-modified",
        NamespaceStatusKindV1::EnabledMissing => "enabled-missing",
        NamespaceStatusKindV1::EnabledUnexpected => "enabled-unexpected",
        NamespaceStatusKindV1::Disabled => "disabled",
        NamespaceStatusKindV1::Stale => "stale",
        NamespaceStatusKindV1::IncompatibleOrCorrupt => "incompatible-or-corrupt",
        NamespaceStatusKindV1::RecoveryRequired => "recovery-required",
    }
}
