//! Evaluates authoring-dialect roots and lowers their outputs into durable plans.
//!
//! Plan identity covers the locked graph and pack bytes, evaluator semantics,
//! static selections, and live overlay captures. Reuse may skip evaluation,
//! but target observation, reconciliation, and drift detection always run fresh.

use std::io::Cursor;
use std::path::Path;

use malm_authoring::{
    AssetEntry, AuthoringSourceSetV1, OverlaySourceV1, RenderedOutputContentV1,
    evaluate_authoring_profile_v1,
};
use malm_types::{
    ArtifactId, ContributionName, DeploymentName, Digest, PrepareArtifactV1, PrepareInputKindV1,
    PrepareInputV1, PrepareOperationV1, PreparePolicyFindingV1, PrepareRequestPartsV1,
    PrepareRequestV1, PreparedDeploymentV1,
};

use crate::{
    Engine, canonical_store,
    config_prepare::{
        StaticPrepareContext, StaticPrepareError, captured_authority_graph, pack_for_authority,
    },
    prepared_store,
};

const EVALUATOR_INPUT_DOMAIN: &[u8] = b"malm-authoring-evaluator-v1\0";

const DECOMPRESSOR_INPUT_DOMAIN: &[u8] = b"malm-authoring-asset-decompressor-v1\0";

const EXTERNAL_INCLUDE_FINDING: &str = "AUTHORING-EXTERNAL-INCLUDE-SKIPPED";

const OVERLAY_APPLIED_FINDING: &str = "AUTHORING-OVERLAY-APPLIED";

const OVERLAY_IDENTITY_DOMAIN: &[u8] = b"malm-authoring-overlay-identity-v1\0";

const SYMLINK_SKIPPED_FINDING: &str = "AUTHORING-SYMLINK-SKIPPED";

/// Maximum decompressed bytes admitted from one vendored asset archive.
const MAX_DECOMPRESSED_ASSET_BYTES: u64 = 512 * 1024 * 1024;

/// Authoring roots currently reject pack dependencies.
fn authoring_root_pack(
    graph: &malm_module_graph::AssembledLockedGraphV1,
) -> Result<(&malm_pack::LockedPackV1, &malm_module_graph::VerifiedPackV1), StaticPrepareError> {
    if graph.dependency_order().len() > 1 {
        return Err(StaticPrepareError::InvalidConfig(
            "authoring roots do not support pack dependencies yet".to_owned(),
        ));
    }
    let authorities = captured_authority_graph(graph)?;
    pack_for_authority(graph, authorities.root())
}

fn capture_sources(
    pack: &malm_module_graph::VerifiedPackV1,
) -> Result<AuthoringSourceSetV1, StaticPrepareError> {
    let mut sources = AuthoringSourceSetV1::new();
    for (path, bytes) in pack.files() {
        sources
            .insert(path.as_str(), bytes.to_vec())
            .map_err(StaticPrepareError::invalid_config)?;
    }
    Ok(sources)
}

pub(crate) fn selected_profile(
    graph: &malm_module_graph::AssembledLockedGraphV1,
    config_entry: &malm_pack::PackPath,
    requested: Option<&ContributionName>,
) -> Result<ContributionName, StaticPrepareError> {
    if let Some(profile) = requested {
        return Ok(profile.clone());
    }
    let (_, pack) = authoring_root_pack(graph)?;
    let sources = capture_sources(pack)?;
    let name = malm_authoring::default_authoring_profile_v1(&sources, config_entry.as_str())
        .map_err(StaticPrepareError::invalid_config)?;
    ContributionName::new(name).map_err(StaticPrepareError::invalid_config)
}

/// Evaluates one authoring profile and prepares its durable plan.
pub(crate) fn prepare(
    context: StaticPrepareContext<'_>,
    profile: Option<&ContributionName>,
    config_entry: &malm_pack::PackPath,
    mut inputs: Vec<PrepareInputV1>,
) -> Result<PreparedDeploymentV1, StaticPrepareError> {
    let StaticPrepareContext {
        engine,
        graph,
        component_authorization: _,
        namespace,
        target_authority,
        expected_head,
        tracked_root,
    } = context;
    let (node, pack) = authoring_root_pack(graph)?;
    let sources = capture_sources(pack)?;

    let profile_name = match profile {
        Some(profile) => profile.as_str().to_owned(),
        None => malm_authoring::default_authoring_profile_v1(&sources, config_entry.as_str())
            .map_err(StaticPrepareError::invalid_config)?,
    };
    let overlays = read_declared_overlays(engine, &sources, config_entry, &target_authority)?;

    inputs.push(
        PrepareInputV1::new(
            PrepareInputKindV1::Other,
            format!(
                "{}{profile_name}",
                crate::config_prepare::STATIC_PROFILE_INPUT_PREFIX
            ),
            crate::config_prepare::static_profile_digest(&profile_name),
        )
        .map_err(StaticPrepareError::InvalidGeneratedRequest)?,
    );
    inputs.push(
        PrepareInputV1::new(
            PrepareInputKindV1::Lock,
            "locked-graph",
            graph.graph_digest().clone(),
        )
        .map_err(StaticPrepareError::InvalidGeneratedRequest)?,
    );
    inputs.push(
        PrepareInputV1::new(
            PrepareInputKindV1::Source,
            format!("pack:{}", node.node_id()),
            node.content_digest().clone(),
        )
        .map_err(StaticPrepareError::InvalidGeneratedRequest)?,
    );
    inputs.extend(crate::config_prepare::locked_component_profile_inputs(
        graph,
    )?);
    inputs.push(evaluator_input()?);

    inputs.extend(overlay_inputs(&overlays)?);

    let overlay_findings = overlay_applied_findings(&overlays.applied)?;

    // Byte-identical inputs may reuse a deterministic evaluation result.
    // Observation, reconciliation, and drift detection still run fresh.
    if tracked_root.is_none()
        && let Some(reused) = crate::prepare_reuse::find_reusable_evaluation(
            engine,
            &namespace,
            graph.graph_digest(),
            &inputs,
        )
    {
        match crate::prepare_reuse::submit_reused(
            engine,
            namespace.clone(),
            expected_head.clone(),
            graph.graph_digest().clone(),
            reused,
            overlay_findings.clone(),
        ) {
            Ok(plan) => return Ok(plan),
            Err(error) if crate::prepare_reuse::is_consent_shape_refusal(&error) => {}
            Err(error) => return Err(StaticPrepareError::Store(error)),
        }
    }

    let evaluated = evaluate_authoring_profile_v1(
        &sources,
        config_entry.as_str(),
        &profile_name,
        &overlays.supplied,
    )
    .map_err(StaticPrepareError::invalid_config)?;

    let mut findings = overlay_findings;
    for skipped in evaluated.external_includes_skipped() {
        findings.push(
            PreparePolicyFindingV1::new(
                EXTERNAL_INCLUDE_FINDING,
                format!(
                    "external include {skipped:?} was not read; machine-local values \
                     require an explicit overlay"
                ),
                false,
            )
            .map_err(StaticPrepareError::InvalidGeneratedRequest)?,
        );
    }

    // Replacement requests may adopt unmanaged files only with approval.
    // Plain placements preserve the `fail` policy by rejecting present,
    // unowned leaves. The store derives exact operations from current state.
    let mut artifacts = Vec::with_capacity(evaluated.outputs().len());
    let mut artifact_bytes = 0_u64;
    let mut transforms = Vec::new();
    let mut operations = Vec::with_capacity(evaluated.outputs().len() + evaluated.symlinks().len());
    for (index, output) in evaluated.outputs().iter().enumerate() {
        let destination = home_relative_destination(evaluated.target(), output.destination())?;
        let artifact_id = ArtifactId::new(format!("authoring/output-{index:04}"))
            .map_err(StaticPrepareError::InvalidIdentifier)?;
        let (bytes, media_type) = transform_output(
            engine,
            graph,
            index,
            output,
            TransformAccumulator {
                inputs: &mut inputs,
                findings: &mut findings,
                transforms: &mut transforms,
            },
        )?;
        reserve_authoring_artifact_bytes(&mut artifact_bytes, bytes.len(), output.destination())?;
        artifacts.push(
            PrepareArtifactV1::new(artifact_id.clone(), bytes, media_type)
                .map_err(StaticPrepareError::InvalidGeneratedRequest)?,
        );
        let mode = if output.executable() { 0o755 } else { 0o644 };
        let operation = if output.replace() {
            PrepareOperationV1::replace_file(
                target_authority.clone(),
                destination,
                artifact_id,
                mode,
            )
        } else {
            PrepareOperationV1::place_file(target_authority.clone(), destination, artifact_id, mode)
        };
        operations.push(operation.map_err(StaticPrepareError::InvalidGeneratedRequest)?);
    }
    for asset in evaluated.assets() {
        lower_asset(
            engine,
            &sources,
            asset,
            evaluated.target(),
            &target_authority,
            &mut inputs,
            &mut operations,
        )?;
    }
    let mut skipped_symlinks: Vec<String> = Vec::new();
    for symlink in evaluated.symlinks() {
        let link = home_relative_destination(evaluated.target(), symlink.destination())?;
        let Some(target_home_relative) = symlink.target().strip_prefix("~/") else {
            return Err(StaticPrepareError::InvalidConfig(format!(
                "symlink `{}`: only `~/`-relative targets are supported, found {:?}",
                symlink.destination(),
                symlink.target()
            )));
        };
        let relative_target = relative_symlink_target(&link, target_home_relative);
        // Canonical symlinks allow only downward segments. Upward links stay
        // runtime-managed and are reported instead of entering the store.
        if relative_target
            .split('/')
            .any(|segment| segment == ".." || segment == "." || segment.is_empty())
        {
            skipped_symlinks.push(format!("{link} -> {}", symlink.target()));
            continue;
        }
        let object = malm_tree::SymlinkObjectV1::new(relative_target)
            .map_err(StaticPrepareError::invalid_config)?;
        let digest = malm_tree::symlink_object_digest_v1(&object);
        canonical_store::publish_symlink(engine, &digest, &object)
            .map_err(StaticPrepareError::Store)?;
        operations.push(
            PrepareOperationV1::replace_symlink(target_authority.clone(), link, digest)
                .map_err(StaticPrepareError::InvalidGeneratedRequest)?,
        );
    }
    if !skipped_symlinks.is_empty() {
        findings.push(
            PreparePolicyFindingV1::new(
                SYMLINK_SKIPPED_FINDING,
                format!(
                    "{} symlink(s) with upward-relative targets are managed at \
                     runtime, not deployed: {}",
                    skipped_symlinks.len(),
                    skipped_symlinks.join(", ")
                ),
                false,
            )
            .map_err(StaticPrepareError::InvalidGeneratedRequest)?,
        );
    }

    let generated = PrepareRequestV1::from(PrepareRequestPartsV1 {
        namespace,
        expected_head,
        graph_digest: graph.graph_digest().clone(),
        inputs,
        artifacts,
        transforms,
        findings,
        operations,
    });
    prepared_store::submit_prepared(engine, &generated, tracked_root)
        .map_err(StaticPrepareError::Store)
}

/// Inputs, findings, and provenance accumulated by one output pipeline.
struct TransformAccumulator<'a> {
    inputs: &'a mut Vec<PrepareInputV1>,
    findings: &'a mut Vec<PreparePolicyFindingV1>,
    transforms: &'a mut Vec<malm_types::PrepareTransformProvenanceV1>,
}

fn transform_output(
    engine: &Engine,
    graph: &malm_module_graph::AssembledLockedGraphV1,
    output_index: usize,
    output: &malm_authoring::RenderedOutputV1,
    accumulator: TransformAccumulator<'_>,
) -> Result<(Vec<u8>, String), StaticPrepareError> {
    let TransformAccumulator {
        inputs,
        findings,
        transforms,
    } = accumulator;
    let (mut bytes, mut media_type) = match output.content() {
        RenderedOutputContentV1::Bytes(bytes) => (
            checked_authoring_response_bytes(bytes, output.destination())?,
            "application/octet-stream".to_owned(),
        ),
        RenderedOutputContentV1::Component(render) => {
            let component_name = ContributionName::new(render.renderer()).map_err(|error| {
                StaticPrepareError::InvalidConfig(format!(
                    "output {:?} declares invalid renderer component name: {error}",
                    output.destination()
                ))
            })?;
            let component = graph
                .component(graph.root_node_id(), &component_name)
                .map_err(|_| {
                    StaticPrepareError::InvalidConfig(format!(
                        "output {:?} declares renderer component `{component_name}`, which the root pack does not bundle",
                        output.destination()
                    ))
            })?;
            let request = component_renderer_request(render)?;
            let stage_name = format!("authoring-output-{output_index:04}-renderer");
            let (execution, implementation) = crate::config_prepare::execute_component(
                engine,
                component,
                malm_config::RichNameV1::new(stage_name.clone())
                    .map_err(StaticPrepareError::invalid_config)?,
                &request,
                inputs,
            )?;
            crate::config_prepare::append_transform_findings(findings, &stage_name, &execution)?;
            crate::config_prepare::append_transform_provenance(
                transforms,
                crate::config_prepare::transform_provenance_view(
                    &execution,
                    implementation,
                    request.document(),
                )?,
            )?;
            (
                checked_authoring_response_bytes(
                    execution.response().output(),
                    output.destination(),
                )?,
                execution.response().media_type().to_owned(),
            )
        }
    };
    for (stage_index, component_name) in output.transforms().iter().enumerate() {
        let component_name = ContributionName::new(component_name).map_err(|error| {
            StaticPrepareError::InvalidConfig(format!(
                "output {:?} declares invalid transform component name: {error}",
                output.destination()
            ))
        })?;
        let component = graph
            .component(graph.root_node_id(), &component_name)
            .map_err(|_| {
                StaticPrepareError::InvalidConfig(format!(
                    "output {:?} declares transform component `{component_name}`, which the root pack does not bundle",
                    output.destination()
                ))
            })?;
        let request = output_transform_request(&bytes)?;
        let (execution, implementation) = crate::config_prepare::execute_component(
            engine,
            component,
            malm_config::RichNameV1::new(component_name.as_str())
                .map_err(StaticPrepareError::invalid_config)?,
            &request,
            inputs,
        )?;
        crate::config_prepare::append_transform_findings(
            findings,
            &format!("authoring-output-{output_index:04}-transform-{stage_index:02}"),
            &execution,
        )?;
        crate::config_prepare::append_transform_provenance(
            transforms,
            crate::config_prepare::transform_provenance_view(
                &execution,
                implementation,
                request.document(),
            )?,
        )?;
        bytes =
            checked_authoring_response_bytes(execution.response().output(), output.destination())?;
        media_type = execution.response().media_type().to_owned();
    }
    Ok((bytes, media_type))
}

fn checked_authoring_response_bytes(
    bytes: &[u8],
    destination: &str,
) -> Result<Vec<u8>, StaticPrepareError> {
    check_authoring_response_len(bytes.len(), destination)?;
    Ok(bytes.to_vec())
}

fn check_authoring_response_len(
    byte_len: usize,
    destination: &str,
) -> Result<u64, StaticPrepareError> {
    let byte_len = u64::try_from(byte_len).map_err(|_| {
        StaticPrepareError::InvalidConfig(format!(
            "authoring output {destination:?} byte length overflows"
        ))
    })?;
    if byte_len > malm_store::MAX_ARTIFACT_BLOB_BYTES {
        return Err(StaticPrepareError::InvalidConfig(format!(
            "authoring output {destination:?} has {byte_len} bytes; per-artifact limit is {}",
            malm_store::MAX_ARTIFACT_BLOB_BYTES
        )));
    }
    Ok(byte_len)
}

/// Counts every retained buffer, not only unique digests, to bound prepare-time memory.
fn reserve_authoring_artifact_bytes(
    total: &mut u64,
    byte_len: usize,
    destination: &str,
) -> Result<(), StaticPrepareError> {
    let byte_len = check_authoring_response_len(byte_len, destination)?;
    let projected = total.checked_add(byte_len).ok_or_else(|| {
        StaticPrepareError::InvalidConfig("authoring artifact byte total overflows".to_owned())
    })?;
    if projected > malm_store::MAX_PREPARED_UNIQUE_ARTIFACT_BYTES {
        return Err(StaticPrepareError::InvalidConfig(format!(
            "authoring artifacts exceed the prepared-plan byte limit of {} bytes",
            malm_store::MAX_PREPARED_UNIQUE_ARTIFACT_BYTES
        )));
    }
    *total = projected;
    Ok(())
}

/// Renderer requests carry the document and format but grant no resources.
fn component_renderer_request(
    render: &malm_authoring::DeferredComponentRenderV1,
) -> Result<malm_config::TransformRequestV1, StaticPrepareError> {
    let option = malm_config::TransformOptionV1::new(
        malm_config::RichNameV1::new("format")
            .expect("constant component renderer option name is valid"),
        malm_config::TypedValueV1::string(render.format())
            .map_err(StaticPrepareError::transform_contract)?,
    )
    .map_err(StaticPrepareError::transform_contract)?;
    malm_config::TransformRequestV1::new(render.document().clone(), vec![option], Vec::new())
        .map_err(StaticPrepareError::transform_contract)
}

/// Transform requests grant only the current `content` bytes.
fn output_transform_request(
    content: &[u8],
) -> Result<malm_config::TransformRequestV1, StaticPrepareError> {
    let document = malm_config::CanonicalTypedDocumentV1::new(
        malm_config::TypedValueV1::record(std::collections::BTreeMap::new())
            .map_err(StaticPrepareError::transform_contract)?,
    )
    .map_err(StaticPrepareError::transform_contract)?;
    let resource = malm_config::DeclaredTransformResourceV1::new(
        malm_config::RichNameV1::new("content").map_err(StaticPrepareError::transform_contract)?,
        Digest::sha256(content),
        content.to_vec(),
    )
    .map_err(StaticPrepareError::transform_contract)?;
    malm_config::TransformRequestV1::new(document, Vec::new(), vec![resource])
        .map_err(StaticPrepareError::transform_contract)
}

/// Verifies a vendored payload and deploys its canonical tree at `dst/<asset-name>`.
/// Siblings under `dst` remain unmanaged.
fn lower_asset(
    engine: &Engine,
    sources: &AuthoringSourceSetV1,
    asset: &AssetEntry,
    target: &str,
    target_authority: &DeploymentName,
    inputs: &mut Vec<PrepareInputV1>,
    operations: &mut Vec<PrepareOperationV1>,
) -> Result<(), StaticPrepareError> {
    let name = &asset.name;
    let Some(path) = &asset.path else {
        return Err(StaticPrepareError::InvalidConfig(format!(
            "asset `{name}`: deployment requires a vendored `path` inside the pack \
             (`url` is acquisition provenance only)"
        )));
    };
    let Some(payload) = sources.get(path) else {
        return Err(StaticPrepareError::InvalidConfig(format!(
            "asset `{name}`: vendored payload not captured: {path}"
        )));
    };
    if let Some(declared) = &asset.sha256 {
        let actual = Digest::sha256(payload);
        let actual_hex = &actual.as_str()["sha256-".len()..];
        if actual_hex != declared {
            return Err(StaticPrepareError::InvalidConfig(format!(
                "asset `{name}`: vendored payload {path} has sha256 {actual_hex}, \
                 declared {declared}"
            )));
        }
    }

    let tar = match asset.format.as_str() {
        "tar" => payload.to_vec(),
        "tar-xz" => decompress_xz(name, payload)?,
        other => {
            return Err(StaticPrepareError::InvalidConfig(format!(
                "asset `{name}`: format `{other}` is not supported for deployment yet \
                 (supported: tar, tar-xz)"
            )));
        }
    };
    let tar_digest = Digest::sha256(&tar);
    let declaration =
        malm_archive::ArchiveDeclarationV1::posix_ustar(tar.len() as u64, tar_digest.clone());
    let decoded = canonical_store::decode_and_publish(
        engine,
        Cursor::new(tar),
        declaration,
        malm_archive::ArchiveLimitsV1::default(),
    )
    .map_err(StaticPrepareError::Archive)?;

    let mut decompressor_identity = DECOMPRESSOR_INPUT_DOMAIN.to_vec();
    decompressor_identity.extend_from_slice(b"xz/1");
    inputs.push(
        PrepareInputV1::new(
            PrepareInputKindV1::Other,
            format!("asset:{name}:decompressor"),
            Digest::sha256(decompressor_identity),
        )
        .map_err(StaticPrepareError::InvalidGeneratedRequest)?,
    );
    inputs.push(
        PrepareInputV1::new(
            PrepareInputKindV1::Other,
            format!("asset:{name}:tree"),
            decoded.root_digest().clone(),
        )
        .map_err(StaticPrepareError::InvalidGeneratedRequest)?,
    );

    let destination = home_relative_destination(target, &asset.dst)?;
    let tree_path = format!("{destination}/{name}");
    let provenance = malm_types::ArchiveProvenanceV1::new(
        tar_digest.clone(),
        format!(
            "{}/v{}",
            malm_archive::ARCHIVE_DECODER_NAME,
            malm_archive::ARCHIVE_DECODER_VERSION
        ),
    )
    .map_err(StaticPrepareError::InvalidGeneratedRequest)?;
    operations.push(
        PrepareOperationV1::replace_archive_tree(
            target_authority.clone(),
            tree_path,
            decoded.root_digest().clone(),
            provenance,
        )
        .map_err(StaticPrepareError::InvalidGeneratedRequest)?,
    );
    Ok(())
}

/// Enforces the decompressed-size limit in the sink, before memory can grow past it.
fn decompress_xz(name: &str, payload: &[u8]) -> Result<Vec<u8>, StaticPrepareError> {
    struct BoundedSink {
        bytes: Vec<u8>,
        limit: u64,
    }
    impl std::io::Write for BoundedSink {
        fn write(&mut self, chunk: &[u8]) -> std::io::Result<usize> {
            let projected = (self.bytes.len() as u64).saturating_add(chunk.len() as u64);
            if projected > self.limit {
                return Err(std::io::Error::other("decompressed payload exceeds limit"));
            }
            self.bytes.extend_from_slice(chunk);
            Ok(chunk.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    let mut reader = std::io::BufReader::new(Cursor::new(payload));
    let mut sink = BoundedSink {
        bytes: Vec::new(),
        limit: MAX_DECOMPRESSED_ASSET_BYTES,
    };
    lzma_rs::xz_decompress(&mut reader, &mut sink).map_err(|error| {
        StaticPrepareError::InvalidConfig(format!(
            "asset `{name}`: xz decompression failed: {error}"
        ))
    })?;
    Ok(sink.bytes)
}

/// One applied overlay's captured identity for inputs and findings.
pub(crate) struct AppliedOverlay {
    pub(crate) name: String,
    pub(crate) path: String,
    pub(crate) bytes_digest: Digest,
    pub(crate) identity: Digest,
}

/// One declared overlay, independent of whether its file exists.
#[derive(Clone)]
pub(crate) struct OverlayDeclarationV1 {
    pub(crate) name: String,
    pub(crate) path: String,
    pub(crate) optional: bool,
}

impl OverlayDeclarationV1 {
    pub(crate) fn identity(&self) -> Digest {
        let mut identity = OVERLAY_IDENTITY_DOMAIN.to_vec();
        identity.extend_from_slice(self.name.as_bytes());
        identity.push(0);
        identity.extend_from_slice(self.path.as_bytes());
        Digest::sha256(identity)
    }

    /// Records the declaration so profile switches can recapture it without pack access.
    pub(crate) fn input(&self) -> Result<PrepareInputV1, StaticPrepareError> {
        let requirement = if self.optional { "opt" } else { "req" };
        PrepareInputV1::new(
            PrepareInputKindV1::Config,
            format!(
                "overlay-declaration:{}:{requirement}:{}",
                self.name, self.path
            ),
            self.identity(),
        )
        .map_err(StaticPrepareError::InvalidGeneratedRequest)
    }
}

/// The host-read overlay documents plus their captured identities.
pub(crate) struct ReadOverlays {
    pub(crate) supplied: Vec<OverlaySourceV1>,
    pub(crate) applied: Vec<AppliedOverlay>,
    pub(crate) declarations: Vec<OverlayDeclarationV1>,
}

/// `~/`-relative paths resolve against the deployment's target authority
/// root. A missing optional overlay is skipped; a missing required overlay
/// fails. Captured bytes become plan inputs, and each later switch recaptures
/// them so changed host state cannot match a retained evaluation.
fn read_declared_overlays(
    engine: &Engine,
    sources: &AuthoringSourceSetV1,
    config_entry: &malm_pack::PackPath,
    target_authority: &DeploymentName,
) -> Result<ReadOverlays, StaticPrepareError> {
    let declarations = malm_authoring::declared_overlays_v1(sources, config_entry.as_str())
        .map_err(StaticPrepareError::invalid_config)?
        .into_iter()
        .map(|declaration| OverlayDeclarationV1 {
            name: declaration.name().to_owned(),
            path: declaration.path().to_owned(),
            optional: declaration.optional(),
        })
        .collect::<Vec<_>>();
    read_overlay_files(engine, declarations, target_authority)
}

pub(crate) fn read_overlay_files(
    engine: &Engine,
    declarations: Vec<OverlayDeclarationV1>,
    target_authority: &DeploymentName,
) -> Result<ReadOverlays, StaticPrepareError> {
    let mut supplied = Vec::new();
    let mut applied = Vec::new();
    for declaration in &declarations {
        let name = declaration.name.as_str();
        let resolved = if let Some(rest) = declaration.path.strip_prefix("~/") {
            let Some(root) = engine.config().target_root(target_authority) else {
                return Err(StaticPrepareError::InvalidConfig(format!(
                    "overlay `{name}`: no target authority root to resolve {} against",
                    declaration.path
                )));
            };
            root.join(rest)
        } else {
            std::path::PathBuf::from(&declaration.path)
        };
        let bytes = match std::fs::read(&resolved) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                if declaration.optional {
                    continue;
                }
                return Err(StaticPrepareError::InvalidConfig(format!(
                    "overlay `{name}`: required file {} is missing",
                    resolved.display()
                )));
            }
            Err(error) => {
                return Err(StaticPrepareError::InvalidConfig(format!(
                    "overlay `{name}`: read {}: {error}",
                    resolved.display()
                )));
            }
        };
        applied.push(AppliedOverlay {
            name: name.to_owned(),
            path: declaration.path.clone(),
            bytes_digest: Digest::sha256(&bytes),
            identity: declaration.identity(),
        });
        supplied.push(OverlaySourceV1::new(name.to_owned(), bytes));
    }
    Ok(ReadOverlays {
        supplied,
        applied,
        declarations,
    })
}

/// Records every declaration and the bytes and identity of each applied overlay.
pub(crate) fn overlay_inputs(
    overlays: &ReadOverlays,
) -> Result<Vec<PrepareInputV1>, StaticPrepareError> {
    let mut inputs = Vec::new();
    for declaration in &overlays.declarations {
        inputs.push(declaration.input()?);
    }
    for applied in &overlays.applied {
        inputs.push(
            PrepareInputV1::new(
                PrepareInputKindV1::Config,
                format!("overlay:{}:bytes", applied.name),
                applied.bytes_digest.clone(),
            )
            .map_err(StaticPrepareError::InvalidGeneratedRequest)?,
        );
        inputs.push(
            PrepareInputV1::new(
                PrepareInputKindV1::Config,
                format!("overlay:{}:identity", applied.name),
                applied.identity.clone(),
            )
            .map_err(StaticPrepareError::InvalidGeneratedRequest)?,
        );
    }
    Ok(inputs)
}

pub(crate) fn overlay_applied_findings(
    applied: &[AppliedOverlay],
) -> Result<Vec<PreparePolicyFindingV1>, StaticPrepareError> {
    applied
        .iter()
        .map(|applied| {
            PreparePolicyFindingV1::new(
                OVERLAY_APPLIED_FINDING,
                format!(
                    "machine-local overlay `{}` applied from {} ({})",
                    applied.name, applied.path, applied.bytes_digest
                ),
                false,
            )
            .map_err(StaticPrepareError::InvalidGeneratedRequest)
        })
        .collect()
}

pub(crate) fn evaluator_input() -> Result<PrepareInputV1, StaticPrepareError> {
    let mut evaluator_identity = EVALUATOR_INPUT_DOMAIN.to_vec();
    evaluator_identity.extend_from_slice(
        malm_authoring::AUTHORING_EVALUATOR_VERSION
            .to_string()
            .as_bytes(),
    );
    PrepareInputV1::new(
        PrepareInputKindV1::Other,
        "authoring-evaluator",
        Digest::sha256(evaluator_identity),
    )
    .map_err(StaticPrepareError::InvalidGeneratedRequest)
}

/// Maps an authoring-spelled destination onto a home-authority path.
///
/// `~/x` destinations bypass the target directory; other relative paths
/// resolve below the configured target, which must itself be `~` or
/// `~/...`-relative.
fn home_relative_destination(
    target: &str,
    destination: &str,
) -> Result<String, StaticPrepareError> {
    if let Some(home_relative) = destination.strip_prefix("~/") {
        return Ok(home_relative.to_owned());
    }
    if destination == "~" || Path::new(destination).is_absolute() {
        return Err(StaticPrepareError::InvalidConfig(format!(
            "unsupported output destination {destination:?}"
        )));
    }
    if target == "~" {
        return Ok(destination.to_owned());
    }
    let Some(target_relative) = target.strip_prefix("~/") else {
        return Err(StaticPrepareError::InvalidConfig(format!(
            "config target {target:?} must be `~` or `~/`-relative"
        )));
    };
    Ok(format!("{target_relative}/{destination}"))
}

fn relative_symlink_target(link: &str, target: &str) -> String {
    let link_parent: Vec<&str> = {
        let mut segments: Vec<&str> = link.split('/').collect();
        segments.pop();
        segments
    };
    let target_segments: Vec<&str> = target.split('/').collect();
    let common = link_parent
        .iter()
        .zip(target_segments.iter())
        .take_while(|(left, right)| left == right)
        .count();
    let mut spelled: Vec<&str> = vec![".."; link_parent.len() - common];
    spelled.extend(&target_segments[common..]);
    spelled.join("/")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn destinations_map_onto_the_home_authority() {
        assert_eq!(
            home_relative_destination("~/.config", "hypr/hyprland.lua").unwrap(),
            ".config/hypr/hyprland.lua"
        );
        assert_eq!(
            home_relative_destination("~/.config", "~/.bashrc").unwrap(),
            ".bashrc"
        );
        assert_eq!(home_relative_destination("~", "x/y").unwrap(), "x/y");
        assert!(home_relative_destination("/etc", "x").is_err());
        assert!(home_relative_destination("~/.config", "/abs").is_err());
    }

    #[test]
    fn symlink_targets_are_spelled_relative_to_the_link_parent() {
        assert_eq!(
            relative_symlink_target(
                ".config/btop/themes/current.theme",
                ".config/gnist/themes/current/btop.theme"
            ),
            "../../gnist/themes/current/btop.theme"
        );
        assert_eq!(relative_symlink_target("a/link", "a/target"), "target");
        assert_eq!(relative_symlink_target("link", "dir/target"), "dir/target");
    }

    #[test]
    fn component_response_and_authoring_aggregate_limits_accept_exact_boundaries() {
        assert_eq!(
            check_authoring_response_len(malm_store::MAX_ARTIFACT_BLOB_BYTES as usize, "exact",)
                .unwrap(),
            malm_store::MAX_ARTIFACT_BLOB_BYTES
        );
        assert!(
            check_authoring_response_len(
                malm_store::MAX_ARTIFACT_BLOB_BYTES as usize + 1,
                "oversized",
            )
            .is_err()
        );

        let half = malm_store::MAX_PREPARED_UNIQUE_ARTIFACT_BYTES / 2;
        let mut total = 0;
        reserve_authoring_artifact_bytes(&mut total, half as usize, "first").unwrap();
        reserve_authoring_artifact_bytes(
            &mut total,
            (malm_store::MAX_PREPARED_UNIQUE_ARTIFACT_BYTES - half) as usize,
            "second",
        )
        .unwrap();
        assert_eq!(total, malm_store::MAX_PREPARED_UNIQUE_ARTIFACT_BYTES);
        assert!(reserve_authoring_artifact_bytes(&mut total, 1, "third").is_err());
        assert_eq!(
            total,
            malm_store::MAX_PREPARED_UNIQUE_ARTIFACT_BYTES,
            "a rejected response must not change the retained total"
        );
    }
}
