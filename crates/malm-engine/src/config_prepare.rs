use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    io::Cursor,
};

use malm_config::{
    BuiltInFormatTransformV1, CanonicalJsonTransformV1, CapturedAuthorityGraphV1,
    CapturedAuthorityV1, CapturedDocumentIdV1, CapturedPackFileReferenceV1,
    DeclaredTransformResourceV1, DesiredOutputKindV1, EvaluatedRichConfigV1,
    FormatTransformSelectionV1, KeyValueTransformV1, PackResourceKindV1,
    ParsedRichConfigDocumentV1, ParsedRichConfigSetV1, PlainTextTransformV1,
    RichDiagnosticLocationV1, RichDiagnosticSeverityV1, RichDiagnosticV1, RichNameV1,
    TransformExecutionErrorV1, TransformImplementationV1, TransformInvocationErrorV1,
    TransformRequestV1, canonical_typed_document_digest_v1, decode_rich_config_document_v1,
    run_format_transform_invocation_v1, run_format_transform_v1,
};
use malm_format_component_api::FormatComponentAuthorizationV1;
use malm_tree::file_object_digest_v1;
use malm_types::{
    ArtifactId, ContributionName, DeploymentName, Digest, PrepareArtifactV1, PrepareInputKindV1,
    PrepareInputV1, PrepareOperationV1, PrepareRequestPartsV1, PrepareRequestV1,
    PrepareTransformDiagnosticLocationV1, PrepareTransformDiagnosticSeverityV1,
    PrepareTransformDiagnosticV1, PrepareTransformImplementationV1,
    PrepareTransformOutputLocationV1, PrepareTransformProvenanceV1, PrepareTransformResourceV1,
    PrepareTransformSourceLocationV1, PreparedDeploymentV1,
};

use crate::{
    ArchivePublicationError, Engine, EngineError, FormatComponentExecutionIssue, canonical_store,
    prepared_store,
};

pub(crate) const STATIC_CONFIG_ENTRY_INPUT_PREFIX: &str = "static-config-entry:";
pub(crate) const STATIC_TARGET_AUTHORITY_INPUT_PREFIX: &str = "static-target-authority:";
pub(crate) const STATIC_PROFILE_INPUT_PREFIX: &str = "static-profile:";
pub(crate) const LOCKED_COMPONENT_PROFILE_INPUT_PREFIX: &str = "locked-component-profile:";
pub(crate) const LOCKED_COMPONENT_PROFILES_INPUT: &str = "locked-component-profiles";

/// Capabilities and selected state shared by both static config dialects.
pub(crate) struct StaticPrepareContext<'a> {
    pub(crate) engine: &'a Engine,
    pub(crate) graph: &'a malm_module_graph::AssembledLockedGraphV1,
    pub(crate) component_authorization: &'a FormatComponentAuthorizationV1,
    pub(crate) namespace: malm_types::NamespaceName,
    pub(crate) target_authority: DeploymentName,
    pub(crate) expected_head: Option<Digest>,
    pub(crate) tracked_root: Option<&'a malm_store::TrackedRootV1>,
}

pub(crate) fn prepare(
    context: StaticPrepareContext<'_>,
    profile: Option<&ContributionName>,
    config_entry: Option<&malm_pack::PackPath>,
) -> Result<PreparedDeploymentV1, StaticPrepareError> {
    let config_entry = config_entry.cloned().unwrap_or_else(|| {
        malm_pack::PackPath::new(malm_config::CONFIG_FILE)
            .expect("conventional root config path is valid")
    });
    // Reconciliation keeps the deployed profile. The source default applies
    // only before deployment, while an explicit profile always wins.
    let deployed = match profile {
        Some(_) => None,
        None => deployed_static_profile(context.engine, &context.namespace),
    };
    let profile = profile.or(deployed.as_ref());
    if entry_is_authoring_dialect(context.graph, &config_entry)? {
        let inputs = vec![
            PrepareInputV1::new(
                PrepareInputKindV1::Other,
                format!("{STATIC_CONFIG_ENTRY_INPUT_PREFIX}{config_entry}"),
                static_config_entry_digest(&config_entry),
            )
            .map_err(StaticPrepareError::InvalidGeneratedRequest)?,
            PrepareInputV1::new(
                PrepareInputKindV1::Other,
                format!(
                    "{STATIC_TARGET_AUTHORITY_INPUT_PREFIX}{}",
                    context.target_authority
                ),
                static_target_authority_digest(&context.target_authority),
            )
            .map_err(StaticPrepareError::InvalidGeneratedRequest)?,
        ];
        return crate::authoring_prepare::prepare(context, profile, &config_entry, inputs);
    }
    let StaticPrepareContext {
        engine,
        graph,
        component_authorization,
        namespace,
        target_authority,
        expected_head,
        tracked_root,
    } = context;
    let selected = profile
        .map(|profile| RichNameV1::new(profile.as_str()))
        .transpose()
        .map_err(StaticPrepareError::invalid_config)?;
    let (evaluated, mut inputs) = evaluate_graph(graph, &config_entry, selected.as_ref())?;
    inputs.push(
        PrepareInputV1::new(
            PrepareInputKindV1::Other,
            format!("{STATIC_CONFIG_ENTRY_INPUT_PREFIX}{config_entry}"),
            static_selection_digest(b"malm-static-config-entry-v1\0", config_entry.as_str()),
        )
        .map_err(StaticPrepareError::InvalidGeneratedRequest)?,
    );
    inputs.push(
        PrepareInputV1::new(
            PrepareInputKindV1::Other,
            format!("{STATIC_TARGET_AUTHORITY_INPUT_PREFIX}{target_authority}"),
            static_selection_digest(
                b"malm-static-target-authority-v1\0",
                target_authority.as_str(),
            ),
        )
        .map_err(StaticPrepareError::InvalidGeneratedRequest)?,
    );
    let base = PrepareRequestV1::from(PrepareRequestPartsV1 {
        namespace,
        expected_head,
        graph_digest: graph.graph_digest().clone(),
        inputs,
        artifacts: Vec::new(),
        transforms: Vec::new(),
        findings: Vec::new(),
        operations: Vec::new(),
    });
    prepare_rich_outputs(
        engine,
        graph,
        component_authorization,
        &base,
        target_authority,
        &evaluated,
        tracked_root,
    )
}

/// Reads the enabled head's `static-profile:` input. Missing, disabled, and
/// older records return `None`, preserving pre-deployment default selection.
pub(crate) fn deployed_static_profile(
    engine: &Engine,
    namespace: &malm_types::NamespaceName,
) -> Option<ContributionName> {
    let committer = engine.committer_v1().ok()?;
    let lineage = committer.inspect_lineage_v1(namespace, 1).ok()?;
    let (_, generation) = lineage.first()?;
    if !generation.lifecycle_state().is_enabled() {
        return None;
    }
    let record = prepared_store::load_record(engine, generation.plan_id()).ok()?;
    let name = record.inputs().iter().find_map(|input| {
        input
            .name()
            .strip_prefix(STATIC_PROFILE_INPUT_PREFIX)
            .map(str::to_owned)
    })?;
    ContributionName::new(name).ok()
}

pub(crate) fn static_config_entry_digest(config_entry: &malm_pack::PackPath) -> Digest {
    static_selection_digest(b"malm-static-config-entry-v1\0", config_entry.as_str())
}

pub(crate) fn static_target_authority_digest(authority: &DeploymentName) -> Digest {
    static_selection_digest(b"malm-static-target-authority-v1\0", authority.as_str())
}

/// Domain-separated identity for the selected profile.
pub(crate) fn static_profile_digest(profile: &str) -> Digest {
    static_selection_digest(b"malm-static-profile-v1\0", profile)
}

fn static_selection_digest(domain: &[u8], value: &str) -> Digest {
    let mut bytes = domain.to_vec();
    append_identity_text(&mut bytes, value);
    Digest::sha256(bytes)
}

pub(crate) fn selected_profile(
    graph: &malm_module_graph::AssembledLockedGraphV1,
    config_entry: &malm_pack::PackPath,
    requested: Option<&ContributionName>,
) -> Result<ContributionName, StaticPrepareError> {
    if entry_is_authoring_dialect(graph, config_entry)? {
        return crate::authoring_prepare::selected_profile(graph, config_entry, requested);
    }
    let selected = requested
        .map(|profile| RichNameV1::new(profile.as_str()))
        .transpose()
        .map_err(StaticPrepareError::invalid_config)?;
    let (evaluated, _) = evaluate_graph(graph, config_entry, selected.as_ref())?;
    ContributionName::new(evaluated.selected_profile().as_str())
        .map_err(StaticPrepareError::invalid_config)
}

/// The two grammars are disjoint at the first top-level node (`config` vs
/// `rich-config`). Either dialect requires a root-pack config declaration.
fn entry_is_authoring_dialect(
    graph: &malm_module_graph::AssembledLockedGraphV1,
    config_entry: &malm_pack::PackPath,
) -> Result<bool, StaticPrepareError> {
    let authorities = captured_authority_graph(graph)?;
    let (entry_node, entry_pack) = pack_for_authority(graph, authorities.root())?;
    if entry_pack
        .manifest()
        .config_documents()
        .binary_search(config_entry)
        .is_err()
    {
        return Err(StaticPrepareError::UndeclaredConfigDocument {
            node: entry_node.node_id().clone(),
            path: config_entry.clone(),
        });
    }
    let bytes = entry_pack
        .file(config_entry)
        .ok_or(StaticPrepareError::MissingRootConfig)?;
    Ok(malm_authoring::is_authoring_root_document(bytes))
}

fn evaluate_graph(
    graph: &malm_module_graph::AssembledLockedGraphV1,
    config_entry: &malm_pack::PackPath,
    selected: Option<&RichNameV1>,
) -> Result<(EvaluatedRichConfigV1, Vec<PrepareInputV1>), StaticPrepareError> {
    let authorities = captured_authority_graph(graph)?;
    let entry = CapturedDocumentIdV1::new(authorities.root().clone(), config_entry.clone());
    let (entry_node, entry_pack) = pack_for_authority(graph, entry.authority())?;
    if entry_pack
        .manifest()
        .config_documents()
        .binary_search(config_entry)
        .is_err()
    {
        return Err(StaticPrepareError::UndeclaredConfigDocument {
            node: entry_node.node_id().clone(),
            path: config_entry.clone(),
        });
    }
    let mut pending = VecDeque::from([entry.clone()]);
    let mut queued = BTreeSet::from([entry.clone()]);
    let mut sources = BTreeMap::<CapturedDocumentIdV1, ParsedRichConfigDocumentV1>::new();

    while let Some(id) = pending.pop_front() {
        let (_, pack) = pack_for_authority(graph, id.authority())?;
        let bytes = pack.file(id.path()).ok_or_else(|| {
            if id == entry {
                StaticPrepareError::MissingRootConfig
            } else {
                StaticPrepareError::MissingConfigDocument(id.clone())
            }
        })?;
        let parsed = decode_rich_config_document_v1(id.clone(), bytes)
            .map_err(StaticPrepareError::invalid_config)?;
        let mut targets = Vec::with_capacity(
            parsed
                .includes()
                .len()
                .saturating_add(parsed.modules().len()),
        );
        for include in parsed.includes() {
            targets.push(
                authorities
                    .resolve_include(id.authority(), include)
                    .map_err(StaticPrepareError::invalid_config)?,
            );
        }
        for module in parsed.modules() {
            targets.push(
                authorities
                    .resolve_module(id.authority(), module)
                    .map_err(StaticPrepareError::invalid_config)?,
            );
        }
        if sources.insert(id.clone(), parsed).is_some() {
            return Err(StaticPrepareError::InvalidConfig(format!(
                "config document {id} was captured more than once"
            )));
        }
        for target in targets {
            if queued.insert(target.clone()) {
                pending.push_back(target);
            }
        }
    }

    let mut inputs = vec![
        PrepareInputV1::new(
            PrepareInputKindV1::Lock,
            "locked-graph",
            graph.graph_digest().clone(),
        )
        .map_err(StaticPrepareError::InvalidGeneratedRequest)?,
    ];
    for node_id in graph.dependency_order() {
        let node = graph
            .lock()
            .node(node_id)
            .expect("assembled graph retains every locked node");
        inputs.push(
            PrepareInputV1::new(
                PrepareInputKindV1::Source,
                format!("pack:{node_id}"),
                node.content_digest().clone(),
            )
            .map_err(StaticPrepareError::InvalidGeneratedRequest)?,
        );
    }
    inputs.extend(locked_component_profile_inputs(graph)?);
    for (index, (id, source)) in sources.iter().enumerate() {
        inputs.push(
            PrepareInputV1::new(
                PrepareInputKindV1::Config,
                format!("config-document:{index}:bytes"),
                source.digest().clone(),
            )
            .map_err(StaticPrepareError::InvalidGeneratedRequest)?,
        );
        inputs.push(
            PrepareInputV1::new(
                PrepareInputKindV1::Config,
                format!("config-document:{index}:identity"),
                captured_document_identity(id),
            )
            .map_err(StaticPrepareError::InvalidGeneratedRequest)?,
        );
    }
    let parsed = ParsedRichConfigSetV1::new(authorities, sources.into_values().collect())
        .map_err(StaticPrepareError::invalid_config)?;
    let evaluated = parsed
        .evaluate(&entry, selected, &BTreeMap::new())
        .map_err(StaticPrepareError::invalid_config)?;
    Ok((evaluated, inputs))
}

pub(crate) fn locked_component_profile_inputs(
    graph: &malm_module_graph::AssembledLockedGraphV1,
) -> Result<Vec<PrepareInputV1>, StaticPrepareError> {
    let mut inputs = Vec::new();
    let mut profiles = BTreeMap::new();
    for node in graph.lock().nodes() {
        for component in node.components() {
            let name = format!(
                "{LOCKED_COMPONENT_PROFILE_INPUT_PREFIX}{}:{}",
                node.node_id(),
                component.name()
            );
            profiles.insert(name.clone(), component.execution_profile().clone());
            inputs.push(
                PrepareInputV1::new(
                    PrepareInputKindV1::Other,
                    name,
                    component.execution_profile().clone(),
                )
                .map_err(StaticPrepareError::InvalidGeneratedRequest)?,
            );
        }
    }
    inputs.push(
        PrepareInputV1::new(
            PrepareInputKindV1::Other,
            LOCKED_COMPONENT_PROFILES_INPUT,
            locked_component_profiles_digest(&profiles),
        )
        .map_err(StaticPrepareError::InvalidGeneratedRequest)?,
    );
    Ok(inputs)
}

pub(crate) fn locked_component_profiles_digest(profiles: &BTreeMap<String, Digest>) -> Digest {
    let mut bytes = b"malm-locked-component-profiles-v1\0".to_vec();
    for (name, profile) in profiles {
        append_identity_text(&mut bytes, name);
        append_identity_text(&mut bytes, profile.as_str());
    }
    Digest::sha256(bytes)
}

pub(crate) fn captured_authority_graph(
    graph: &malm_module_graph::AssembledLockedGraphV1,
) -> Result<CapturedAuthorityGraphV1, StaticPrepareError> {
    let mut exact = BTreeMap::new();
    for node in graph.lock().nodes() {
        exact.insert(node.node_id().clone(), document_authority(graph, node)?);
    }
    let root = exact[graph.root_node_id()].clone();
    let mut authorities = Vec::with_capacity(graph.lock().nodes().len());
    for node in graph.lock().nodes() {
        let pack = graph
            .pack(node.node_id())
            .expect("assembled graph retains every locked pack");
        let dependencies = node
            .dependencies()
            .iter()
            .map(|edge| (edge.alias().clone(), exact[edge.target_node_id()].clone()))
            .collect();
        let modules = pack
            .manifest()
            .modules()
            .iter()
            .map(|module| (module.name().clone(), module.path().clone()))
            .collect();
        authorities.push(
            CapturedAuthorityV1::new(
                exact[node.node_id()].clone(),
                dependencies,
                modules,
                pack.manifest().config_documents().to_vec(),
            )
            .map_err(StaticPrepareError::invalid_config)?,
        );
    }
    CapturedAuthorityGraphV1::new(root, authorities).map_err(StaticPrepareError::invalid_config)
}

fn document_authority(
    graph: &malm_module_graph::AssembledLockedGraphV1,
    node: &malm_pack::LockedPackV1,
) -> Result<malm_config::DocumentAuthorityV1, StaticPrepareError> {
    let label = if node.node_id() == graph.root_node_id() {
        "root".to_owned()
    } else {
        let hexadecimal = node
            .node_id()
            .digest()
            .as_str()
            .strip_prefix("sha256-")
            .expect("validated digest has its fixed prefix");
        format!("pack-{}", &hexadecimal[..58])
    };
    let label = ContributionName::new(label).map_err(StaticPrepareError::InvalidIdentifier)?;
    Ok(malm_config::DocumentAuthorityV1::new(
        label,
        node.content_digest().clone(),
    ))
}

fn captured_document_identity(id: &CapturedDocumentIdV1) -> Digest {
    let mut bytes = b"malm-captured-config-document\0".to_vec();
    append_identity_text(&mut bytes, id.authority().label().as_str());
    append_identity_text(&mut bytes, id.authority().identity().as_str());
    append_identity_text(&mut bytes, id.path().as_str());
    Digest::sha256(bytes)
}

fn append_identity_text(bytes: &mut Vec<u8>, value: &str) {
    bytes.extend_from_slice(&u64::try_from(value.len()).unwrap_or(u64::MAX).to_be_bytes());
    bytes.extend_from_slice(value.as_bytes());
}

pub(crate) fn prepare_rich_outputs(
    engine: &Engine,
    graph: &malm_module_graph::AssembledLockedGraphV1,
    authorization: &FormatComponentAuthorizationV1,
    request: &PrepareRequestV1,
    target_authority: DeploymentName,
    evaluated: &EvaluatedRichConfigV1,
    tracked_root: Option<&malm_store::TrackedRootV1>,
) -> Result<PreparedDeploymentV1, StaticPrepareError> {
    if request.graph_digest() != graph.graph_digest() {
        return Err(StaticPrepareError::GraphDigestMismatch {
            request: request.graph_digest().clone(),
            assembled: graph.graph_digest().clone(),
        });
    }
    if !request.artifacts().is_empty()
        || !request.operations().is_empty()
        || !request.transforms().is_empty()
    {
        return Err(StaticPrepareError::InvalidConfig(
            "rich-output base request must contain only captured inputs and findings".to_owned(),
        ));
    }

    let mut inputs = request.inputs().to_vec();
    let rich_ir = canonical_typed_document_digest_v1(evaluated.evaluation().document())
        .map_err(StaticPrepareError::invalid_config)?;
    inputs.push(
        PrepareInputV1::new(PrepareInputKindV1::Config, "rich-config-ir", rich_ir)
            .map_err(StaticPrepareError::InvalidGeneratedRequest)?,
    );
    inputs.push(
        PrepareInputV1::new(
            PrepareInputKindV1::Other,
            format!(
                "{STATIC_PROFILE_INPUT_PREFIX}{}",
                evaluated.selected_profile().as_str()
            ),
            static_profile_digest(evaluated.selected_profile().as_str()),
        )
        .map_err(StaticPrepareError::InvalidGeneratedRequest)?,
    );
    let mut artifacts = Vec::new();
    let mut findings = request.findings().to_vec();
    let mut transforms = Vec::new();
    let mut operations = Vec::with_capacity(evaluated.desired_outputs().outputs().len());

    for output in evaluated.desired_outputs().outputs().values() {
        let destination = output.destination().as_str();
        let operation = match output.kind() {
            DesiredOutputKindV1::RegularFile { source, executable } => {
                let bytes = materialize_pack_file(
                    engine,
                    graph,
                    source,
                    output.name().as_str(),
                    &mut inputs,
                )?;
                let artifact_id = ArtifactId::new(format!("rich/{}", output.name()))
                    .map_err(StaticPrepareError::InvalidIdentifier)?;
                artifacts.push(
                    PrepareArtifactV1::new(artifact_id.clone(), bytes, "application/octet-stream")
                        .map_err(StaticPrepareError::InvalidGeneratedRequest)?,
                );
                PrepareOperationV1::place_file(
                    target_authority.clone(),
                    destination,
                    artifact_id,
                    if *executable { 0o755 } else { 0o644 },
                )
            }
            DesiredOutputKindV1::Symlink { target } => {
                let object = malm_tree::SymlinkObjectV1::new(target.as_str())
                    .map_err(StaticPrepareError::invalid_config)?;
                let digest = malm_tree::symlink_object_digest_v1(&object);
                canonical_store::publish_symlink(engine, &digest, &object)
                    .map_err(StaticPrepareError::Store)?;
                PrepareOperationV1::place_symlink(target_authority.clone(), destination, digest)
            }
            DesiredOutputKindV1::CanonicalTree { tree } => {
                canonical_store::load_tree_graph(engine, tree)
                    .map_err(StaticPrepareError::Store)?;
                PrepareOperationV1::place_tree(target_authority.clone(), destination, tree.clone())
            }
            DesiredOutputKindV1::DecodedArchive {
                payload,
                decoder,
                decoder_version,
                expected_tree,
            } => {
                let payload_bytes = materialize_pack_file(
                    engine,
                    graph,
                    payload,
                    output.name().as_str(),
                    &mut inputs,
                )?;
                validate_archive_decoder(decoder, *decoder_version)?;
                let declaration = malm_archive::ArchiveDeclarationV1::posix_ustar(
                    payload.byte_len(),
                    payload.raw_digest().clone(),
                );
                let decoded = canonical_store::decode_and_publish_expected(
                    engine,
                    Cursor::new(payload_bytes),
                    declaration,
                    malm_archive::ArchiveLimitsV1::default(),
                    expected_tree,
                )
                .map_err(StaticPrepareError::Archive)?;
                debug_assert_eq!(decoded.root_digest(), expected_tree);
                inputs.push(
                    PrepareInputV1::new(
                        PrepareInputKindV1::Other,
                        format!("archive:{}:decoder", output.name()),
                        archive_decoder_digest(decoder, *decoder_version),
                    )
                    .map_err(StaticPrepareError::InvalidGeneratedRequest)?,
                );
                inputs.push(
                    PrepareInputV1::new(
                        PrepareInputKindV1::Other,
                        format!("archive:{}:tree", output.name()),
                        expected_tree.clone(),
                    )
                    .map_err(StaticPrepareError::InvalidGeneratedRequest)?,
                );
                PrepareOperationV1::place_archive_tree(
                    target_authority.clone(),
                    destination,
                    expected_tree.clone(),
                    malm_types::ArchiveProvenanceV1::new(
                        payload.raw_digest().clone(),
                        format!("{}/v{decoder_version}", decoder.as_str()),
                    )
                    .map_err(StaticPrepareError::InvalidGeneratedRequest)?,
                )
            }
            DesiredOutputKindV1::TransformedFile {
                transform,
                options,
                resources,
                executable,
            } => {
                let mut declared_resources = Vec::with_capacity(resources.len());
                for resource in resources {
                    let bytes = materialize_pack_file(
                        engine,
                        graph,
                        resource.source(),
                        &format!("{}:{}", output.name(), resource.name()),
                        &mut inputs,
                    )?;
                    declared_resources.push(
                        DeclaredTransformResourceV1::new(
                            resource.name().clone(),
                            resource.source().raw_digest().clone(),
                            bytes,
                        )
                        .map_err(|error| {
                            StaticPrepareError::TransformContract(error.to_string())
                        })?,
                    );
                }
                let transform_request = TransformRequestV1::new(
                    evaluated.evaluation().document().clone(),
                    options.clone(),
                    declared_resources,
                )
                .map_err(StaticPrepareError::transform_contract)?;
                let (execution, implementation) = execute_transform(
                    engine,
                    graph,
                    authorization,
                    transform,
                    &transform_request,
                    &mut inputs,
                )?;
                append_transform_findings(&mut findings, output.name().as_str(), &execution)?;
                let artifact_id = ArtifactId::new(format!("rich/{}", output.name()))
                    .map_err(StaticPrepareError::InvalidIdentifier)?;
                artifacts.push(
                    PrepareArtifactV1::new(
                        artifact_id.clone(),
                        execution.response().output().to_vec(),
                        execution.response().media_type(),
                    )
                    .map_err(StaticPrepareError::InvalidGeneratedRequest)?,
                );
                append_transform_provenance(
                    &mut transforms,
                    transform_provenance_view(
                        &execution,
                        implementation,
                        transform_request.document(),
                    )?,
                )?;
                PrepareOperationV1::place_file(
                    target_authority.clone(),
                    destination,
                    artifact_id,
                    if *executable { 0o755 } else { 0o644 },
                )
            }
        }
        .map_err(StaticPrepareError::InvalidGeneratedRequest)?;
        operations.push(operation);
    }

    let generated = PrepareRequestV1::from(PrepareRequestPartsV1 {
        namespace: request.namespace().clone(),
        expected_head: request.expected_head().cloned(),
        graph_digest: request.graph_digest().clone(),
        inputs,
        artifacts,
        transforms,
        findings,
        operations,
    });
    prepared_store::submit_prepared(engine, &generated, tracked_root)
        .map_err(StaticPrepareError::Store)
}

pub(crate) fn execute_transform(
    engine: &Engine,
    graph: &malm_module_graph::AssembledLockedGraphV1,
    _authorization: &FormatComponentAuthorizationV1,
    transform: &FormatTransformSelectionV1,
    request: &TransformRequestV1,
    inputs: &mut Vec<PrepareInputV1>,
) -> Result<
    (
        malm_config::TransformExecutionV1,
        PrepareTransformImplementationV1,
    ),
    StaticPrepareError,
> {
    match transform {
        FormatTransformSelectionV1::BuiltIn(built_in) => {
            let execution = match built_in {
                BuiltInFormatTransformV1::CanonicalJson => {
                    run_format_transform_v1(&CanonicalJsonTransformV1, request)
                }
                BuiltInFormatTransformV1::PlainText => {
                    run_format_transform_v1(&PlainTextTransformV1, request)
                }
                BuiltInFormatTransformV1::KeyValue => {
                    run_format_transform_v1(&KeyValueTransformV1, request)
                }
            }
            .map_err(map_builtin_transform_error)?;
            let TransformImplementationV1::BuiltIn { implementation } =
                execution.provenance().identity().implementation()
            else {
                unreachable!("built-in transform returned a component identity");
            };
            let implementation = PrepareTransformImplementationV1::built_in(implementation.clone())
                .map_err(StaticPrepareError::InvalidGeneratedRequest)?;
            Ok((execution, implementation))
        }
        FormatTransformSelectionV1::Component {
            name,
            component_digest,
        } => {
            let component = resolve_transform_component(graph, component_digest)?;
            execute_component(engine, component, name.clone(), request, inputs)
        }
    }
}

/// Invokes an exact component occurrence, preserving occurrence-specific provenance.
pub(crate) fn execute_component(
    engine: &Engine,
    component: malm_module_graph::VerifiedComponentV1<'_>,
    transform_name: RichNameV1,
    request: &TransformRequestV1,
    inputs: &mut Vec<PrepareInputV1>,
) -> Result<
    (
        malm_config::TransformExecutionV1,
        PrepareTransformImplementationV1,
    ),
    StaticPrepareError,
> {
    let component_digest = component.declaration.digest();
    let execution_profile_digest = component.declaration.execution_profile();
    let authorization = FormatComponentAuthorizationV1::new([component_digest.clone()]);
    let identity = malm_config::TransformIdentityV1::component(
        transform_name,
        component_digest.clone(),
        component.declaration.interface().as_str(),
        execution_profile_digest.clone(),
    )
    .map_err(StaticPrepareError::transform_contract)?;
    let port_identity = identity.clone();
    let execution = run_format_transform_invocation_v1(identity, request, || {
        engine.ports.format_component_execution().invoke(
            &authorization,
            &port_identity,
            component.bytes,
            request,
        )
    })
    .map_err(map_component_transform_error)?;
    let implementation = PrepareTransformImplementationV1::component(
        component.node_id.clone(),
        component.pack_content_digest.clone(),
        component.declaration.path().as_str(),
        component_digest.clone(),
        component.declaration.interface().as_str(),
        execution_profile_digest.clone(),
    )
    .map_err(StaticPrepareError::InvalidGeneratedRequest)?;
    let input_name = format!(
        "format-component:{}:{}",
        component.node_id,
        component.declaration.name()
    );
    if !inputs
        .iter()
        .any(|input| input.kind() == PrepareInputKindV1::Component && input.name() == input_name)
    {
        inputs.push(
            PrepareInputV1::new(
                PrepareInputKindV1::Component,
                input_name,
                component_digest.clone(),
            )
            .map_err(StaticPrepareError::InvalidGeneratedRequest)?,
        );
    }
    Ok((execution, implementation))
}

fn resolve_transform_component<'a>(
    graph: &'a malm_module_graph::AssembledLockedGraphV1,
    digest: &Digest,
) -> Result<malm_module_graph::VerifiedComponentV1<'a>, StaticPrepareError> {
    let mut matches = Vec::new();
    for node in graph.lock().nodes() {
        for component in node
            .components()
            .iter()
            .filter(|component| component.digest() == digest)
        {
            matches.push((node.node_id(), component));
        }
    }
    let [(node_id, declaration)] = matches.as_slice() else {
        return Err(if matches.is_empty() {
            StaticPrepareError::UnknownFormatComponent(digest.clone())
        } else {
            StaticPrepareError::AmbiguousFormatComponent(digest.clone())
        });
    };
    graph
        .component(node_id, declaration.name())
        .map_err(StaticPrepareError::invalid_config)
}

fn materialize_pack_file(
    engine: &Engine,
    graph: &malm_module_graph::AssembledLockedGraphV1,
    reference: &CapturedPackFileReferenceV1,
    use_name: &str,
    inputs: &mut Vec<PrepareInputV1>,
) -> Result<Vec<u8>, StaticPrepareError> {
    let (node, pack) = pack_for_authority(graph, reference.authority())?;
    let declared_paths = match reference.kind() {
        PackResourceKindV1::Asset => pack.manifest().assets(),
        PackResourceKindV1::Template => pack.manifest().templates(),
        PackResourceKindV1::Schema => pack.manifest().schemas(),
    };
    if declared_paths.binary_search(reference.path()).is_err() {
        return Err(StaticPrepareError::UndeclaredPackFile {
            node: node.node_id().clone(),
            path: reference.path().clone(),
            kind: reference.kind(),
        });
    }
    let bytes = pack
        .file(reference.path())
        .ok_or_else(|| StaticPrepareError::MissingPackFile {
            node: node.node_id().clone(),
            path: reference.path().clone(),
        })?;
    let actual_len = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
    if actual_len != reference.byte_len() {
        return Err(StaticPrepareError::PackFileLengthMismatch {
            node: node.node_id().clone(),
            path: reference.path().clone(),
            expected: reference.byte_len(),
            actual: actual_len,
        });
    }
    let raw_digest = Digest::sha256(bytes);
    if &raw_digest != reference.raw_digest() {
        return Err(StaticPrepareError::PackFileDigestMismatch {
            node: node.node_id().clone(),
            path: reference.path().clone(),
            domain: "raw",
            expected: reference.raw_digest().clone(),
            actual: raw_digest,
        });
    }
    let object_digest = file_object_digest_v1(bytes).map_err(StaticPrepareError::invalid_config)?;
    if &object_digest != reference.object_digest() {
        return Err(StaticPrepareError::PackFileDigestMismatch {
            node: node.node_id().clone(),
            path: reference.path().clone(),
            domain: "canonical file",
            expected: reference.object_digest().clone(),
            actual: object_digest,
        });
    }
    canonical_store::publish_file(engine, reference.object_digest(), bytes)
        .map_err(StaticPrepareError::Store)?;
    inputs.push(
        PrepareInputV1::new(
            PrepareInputKindV1::Asset,
            format!("pack-file:{use_name}:raw"),
            reference.raw_digest().clone(),
        )
        .map_err(StaticPrepareError::InvalidGeneratedRequest)?,
    );
    inputs.push(
        PrepareInputV1::new(
            PrepareInputKindV1::Other,
            format!("pack-file:{use_name}:object"),
            reference.object_digest().clone(),
        )
        .map_err(StaticPrepareError::InvalidGeneratedRequest)?,
    );
    Ok(bytes.to_vec())
}

pub(crate) fn pack_for_authority<'a>(
    graph: &'a malm_module_graph::AssembledLockedGraphV1,
    authority: &malm_config::DocumentAuthorityV1,
) -> Result<
    (
        &'a malm_pack::LockedPackV1,
        &'a malm_module_graph::VerifiedPackV1,
    ),
    StaticPrepareError,
> {
    let mut matched = None;
    for node in graph.lock().nodes() {
        if &document_authority(graph, node)? == authority {
            if matched.is_some() {
                return Err(StaticPrepareError::AmbiguousDocumentAuthority(
                    authority.clone(),
                ));
            }
            matched = Some((
                node,
                graph
                    .pack(node.node_id())
                    .expect("assembled graph retains every locked pack"),
            ));
        }
    }
    matched.ok_or_else(|| StaticPrepareError::UnknownDocumentAuthority(authority.clone()))
}

fn validate_archive_decoder(decoder: &RichNameV1, version: u16) -> Result<(), StaticPrepareError> {
    if decoder.as_str() != malm_archive::ARCHIVE_DECODER_NAME
        || version != malm_archive::ARCHIVE_DECODER_VERSION
    {
        return Err(StaticPrepareError::UnsupportedArchiveDecoder {
            name: decoder.as_str().to_owned(),
            version,
        });
    }
    Ok(())
}

fn archive_decoder_digest(decoder: &RichNameV1, version: u16) -> Digest {
    let mut bytes = b"malm-archive-decoder-identity\0".to_vec();
    bytes.extend_from_slice(decoder.as_str().as_bytes());
    bytes.extend_from_slice(&version.to_be_bytes());
    Digest::sha256(bytes)
}

fn map_builtin_transform_error(error: TransformExecutionErrorV1) -> StaticPrepareError {
    match error {
        TransformExecutionErrorV1::InvalidRequest(error)
        | TransformExecutionErrorV1::InvalidResponse(error) => {
            StaticPrepareError::TransformContract(error.to_string())
        }
        TransformExecutionErrorV1::TransformFailed(failure) => {
            StaticPrepareError::TransformSemantic(failure)
        }
    }
}

fn map_component_transform_error(
    error: TransformInvocationErrorV1<FormatComponentExecutionIssue>,
) -> StaticPrepareError {
    match error {
        TransformInvocationErrorV1::InvalidRequest(error)
        | TransformInvocationErrorV1::InvalidResponse(error) => {
            StaticPrepareError::TransformContract(error.to_string())
        }
        TransformInvocationErrorV1::TransformFailed(failure) => {
            StaticPrepareError::TransformSemantic(failure)
        }
        TransformInvocationErrorV1::Infrastructure(error) => {
            StaticPrepareError::FormatComponentInfrastructure(error)
        }
    }
}

pub(crate) fn append_transform_findings(
    findings: &mut Vec<malm_types::PreparePolicyFindingV1>,
    output: &str,
    execution: &malm_config::TransformExecutionV1,
) -> Result<(), StaticPrepareError> {
    for (index, diagnostic) in execution.response().diagnostics().iter().enumerate() {
        let (severity, approval_required) = match diagnostic.severity() {
            RichDiagnosticSeverityV1::Error => ("error", true),
            RichDiagnosticSeverityV1::Warning => ("warning", true),
            RichDiagnosticSeverityV1::Info => ("info", false),
        };
        findings.push(
            malm_types::PreparePolicyFindingV1::new(
                format!("transform-{severity}-{output}-{index}"),
                diagnostic.message(),
                approval_required,
            )
            .map_err(StaticPrepareError::InvalidGeneratedRequest)?,
        );
    }
    Ok(())
}

pub(crate) fn transform_provenance_view(
    execution: &malm_config::TransformExecutionV1,
    implementation: PrepareTransformImplementationV1,
    document: &malm_config::CanonicalTypedDocumentV1,
) -> Result<PrepareTransformProvenanceV1, StaticPrepareError> {
    let provenance = execution.provenance();
    let resources = provenance
        .resources()
        .iter()
        .map(|(name, digest)| PrepareTransformResourceV1::new(name.as_str(), digest.clone()))
        .collect::<Result<Vec<_>, _>>()
        .map_err(StaticPrepareError::InvalidGeneratedRequest)?;
    let diagnostics = execution
        .response()
        .diagnostics()
        .iter()
        .map(|diagnostic| transform_diagnostic_view(diagnostic, document))
        .collect::<Result<Vec<_>, _>>()?;
    PrepareTransformProvenanceV1::new(
        provenance.identity().name().as_str(),
        implementation,
        provenance.request_digest().clone(),
        provenance.document_digest().clone(),
        resources,
        provenance.response_digest().clone(),
        diagnostics,
    )
    .map_err(StaticPrepareError::InvalidGeneratedRequest)
}

fn transform_diagnostic_view(
    diagnostic: &RichDiagnosticV1,
    document: &malm_config::CanonicalTypedDocumentV1,
) -> Result<PrepareTransformDiagnosticV1, StaticPrepareError> {
    let severity = match diagnostic.severity() {
        RichDiagnosticSeverityV1::Error => {
            return Err(StaticPrepareError::TransformContract(
                "successful transform contains an error diagnostic".to_owned(),
            ));
        }
        RichDiagnosticSeverityV1::Warning => PrepareTransformDiagnosticSeverityV1::Warning,
        RichDiagnosticSeverityV1::Info => PrepareTransformDiagnosticSeverityV1::Info,
    };
    let primary = match diagnostic.primary() {
        Some(RichDiagnosticLocationV1::Source(location)) => {
            let source_identity = document
                .source_documents()
                .get(location.document())
                .ok_or_else(|| {
                    StaticPrepareError::TransformContract(
                        "transform diagnostic references an unknown source document".to_owned(),
                    )
                })?;
            Some(PrepareTransformDiagnosticLocationV1::Source(
                PrepareTransformSourceLocationV1::new(
                    location.document().authority().label().clone(),
                    location.document().authority().identity().clone(),
                    location.document().path().as_str(),
                    source_identity.byte_len(),
                    location.range().start(),
                    location.range().end(),
                )
                .map_err(StaticPrepareError::InvalidGeneratedRequest)?,
            ))
        }
        Some(RichDiagnosticLocationV1::Output(range)) => {
            Some(PrepareTransformDiagnosticLocationV1::Output(
                PrepareTransformOutputLocationV1::new(range.start(), range.end())
                    .map_err(StaticPrepareError::InvalidGeneratedRequest)?,
            ))
        }
        None => None,
    };
    PrepareTransformDiagnosticV1::new(
        severity,
        diagnostic.code().as_str(),
        diagnostic.message(),
        primary,
        diagnostic.notes().to_vec(),
    )
    .map_err(StaticPrepareError::InvalidGeneratedRequest)
}

pub(crate) fn append_transform_provenance(
    transforms: &mut Vec<PrepareTransformProvenanceV1>,
    provenance: PrepareTransformProvenanceV1,
) -> Result<(), StaticPrepareError> {
    if let Some(existing) = transforms
        .iter()
        .find(|existing| existing.request_digest() == provenance.request_digest())
    {
        if existing != &provenance {
            return Err(StaticPrepareError::TransformContract(
                "identical transform request produced conflicting provenance".to_owned(),
            ));
        }
        return Ok(());
    }
    transforms.push(provenance);
    Ok(())
}

/// Failure while capturing and evaluating rich config from a verified locked graph.
// The cause already appears in Display, and source() would duplicate it.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum StaticPrepareError {
    #[error("root pack has no rich malm.kdl")]
    MissingRootConfig,
    #[error("captured config document {0} is absent from its pack")]
    MissingConfigDocument(CapturedDocumentIdV1),
    #[error("locked pack {node} does not declare config entry point {path}")]
    UndeclaredConfigDocument {
        node: malm_types::PackNodeId,
        path: malm_pack::PackPath,
    },
    #[error("prepare request graph {request} does not match assembled graph {assembled}")]
    GraphDigestMismatch { request: Digest, assembled: Digest },
    #[error("invalid rich config: {0}")]
    InvalidConfig(String),
    #[error("unknown locked pack authority {}@{}", .0.label(), .0.identity())]
    UnknownDocumentAuthority(malm_config::DocumentAuthorityV1),
    #[error("locked pack authority {}@{} is ambiguous", .0.label(), .0.identity())]
    AmbiguousDocumentAuthority(malm_config::DocumentAuthorityV1),
    #[error("locked pack {node} lacks declared file {path}")]
    MissingPackFile {
        node: malm_types::PackNodeId,
        path: malm_pack::PackPath,
    },
    #[error("locked pack {node} does not declare {path} as a {}", kind.as_str())]
    UndeclaredPackFile {
        node: malm_types::PackNodeId,
        path: malm_pack::PackPath,
        kind: PackResourceKindV1,
    },
    #[error("locked pack {node} file {path} has {actual} bytes, config reviewed {expected}")]
    PackFileLengthMismatch {
        node: malm_types::PackNodeId,
        path: malm_pack::PackPath,
        expected: u64,
        actual: u64,
    },
    #[error(
        "locked pack {node} file {path} {domain} digest is {actual}, config reviewed {expected}"
    )]
    PackFileDigestMismatch {
        node: malm_types::PackNodeId,
        path: malm_pack::PackPath,
        domain: &'static str,
        expected: Digest,
        actual: Digest,
    },
    #[error("{0}")]
    InvalidIdentifier(malm_types::IdentifierError),
    #[error("{0}")]
    InvalidGeneratedRequest(malm_types::DeploymentDtoError),
    #[error("locked graph has no format component {0}")]
    UnknownFormatComponent(Digest),
    #[error("locked graph contains multiple declarations for format component {0}")]
    AmbiguousFormatComponent(Digest),
    #[error("invalid format-transform contract value: {0}")]
    TransformContract(String),
    #[error("format transform returned {:?}: {}", .0.kind(), .0.message())]
    TransformSemantic(malm_config::TransformFailureV1),
    #[error("format-component infrastructure failed: {0}")]
    FormatComponentInfrastructure(FormatComponentExecutionIssue),
    #[error("unsupported archive decoder {name:?} version {version}")]
    UnsupportedArchiveDecoder { name: String, version: u16 },
    #[error("{0}")]
    Archive(ArchivePublicationError),
    #[error("{0}")]
    Store(EngineError),
}

impl StaticPrepareError {
    pub(crate) fn invalid_config(error: impl std::fmt::Display) -> Self {
        Self::InvalidConfig(error.to_string())
    }

    pub(crate) fn transform_contract(error: impl std::fmt::Display) -> Self {
        Self::TransformContract(error.to_string())
    }
}
