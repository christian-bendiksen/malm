//! Reuse of retained evaluation results for byte-identical inputs.
//!
//! Evaluation is deterministic over the plan's digest-identified inputs, so an
//! exact retained match can reuse artifacts, operations, findings, and transform
//! provenance. Target observation, drift detection, head reconciliation, and
//! mandatory findings still run fresh. Stored blobs and commit inputs are
//! digest-verified, and carried transform provenance remains visible.

use malm_store::{
    PreparedArtifactV1, PreparedOperationV1, PreparedRecordV1, TransformProvenanceV1,
};
use malm_types::{
    Digest, NamespaceName, PrepareInputV1, PrepareOperationV1, PreparePolicyFindingV1,
    PrepareTransformProvenanceV1, PreparedId,
};

use super::{Engine, prepared_store};

/// Findings regenerated from live state rather than copied from retained plans.
const REGENERATED_FINDING_CODES: &[&str] = &[
    "replace-existing",
    "remove-existing",
    "restore-modified",
    "restore-missing",
    "restore-missing-directory",
    "AUTHORING-OVERLAY-APPLIED",
    "AUTHORING-EVALUATION-REUSED",
    "AUTHORING-TRANSFORMS-CARRIED",
];

/// Input families derived deterministically from core inputs.
const DERIVED_INPUT_PREFIXES: &[&str] = &["format-component:", "asset:"];

/// Bounded retained lineage searched before falling back to evaluation.
const MAX_REUSE_WALK: usize = 8;

/// The reusable evaluation product of a retained plan.
pub(crate) struct ReusableEvaluation {
    pub(crate) inputs: Vec<PrepareInputV1>,
    /// Stored blob descriptors; prepare does not load their bytes.
    pub(crate) artifacts: Vec<PreparedArtifactV1>,
    pub(crate) transforms: Vec<PrepareTransformProvenanceV1>,
    pub(crate) findings: Vec<PreparePolicyFindingV1>,
    pub(crate) operations: Vec<PrepareOperationV1>,
}

/// Finds the newest retained generation whose plan captured exactly the
/// given core evaluation inputs, and reconstitutes its evaluation product.
///
/// Returns `None` when no retained plan matches; every load is
/// digest-verified by the underlying store, so a corrupted record or blob
/// fails closed rather than matching.
pub(crate) fn find_reusable_evaluation(
    engine: &Engine,
    namespace: &NamespaceName,
    graph_digest: &Digest,
    core_inputs: &[PrepareInputV1],
) -> Option<ReusableEvaluation> {
    let committer = engine.committer_v1().ok()?;
    // Probe the common shallow lineage first, then spend the remaining bounded
    // search only after a miss. Each generation receives full validation.
    const SHALLOW_WALK: usize = 2;
    let probe = |skip: usize, limit: usize| -> Option<ReusableEvaluation> {
        let lineage = committer.inspect_lineage_v1(namespace, limit).ok()?;
        for (_, generation) in lineage.into_iter().skip(skip) {
            let plan_id = generation.plan_id().clone();
            let Ok(record) = prepared_store::load_record(engine, &plan_id) else {
                continue;
            };
            if record.graph_digest() != graph_digest {
                continue;
            }
            if !record_matches_core(&record, core_inputs) {
                continue;
            }
            match reconstitute(engine, plan_id, &record) {
                Ok(reused) => return Some(reused),
                // A missing or corrupt blob only disables reuse; the full
                // evaluation path re-derives and re-publishes everything.
                Err(_) => continue,
            }
        }
        None
    };
    probe(0, SHALLOW_WALK).or_else(|| probe(SHALLOW_WALK, MAX_REUSE_WALK))
}

/// A record matches when it carries every core input byte-identically and
/// nothing else beyond the derived families.
fn record_matches_core(record: &PreparedRecordV1, core_inputs: &[PrepareInputV1]) -> bool {
    let recorded: std::collections::BTreeMap<&str, &Digest> = record
        .inputs()
        .iter()
        .map(|input| (input.name(), input.digest()))
        .collect();
    if recorded.len() != record.inputs().len() {
        return false;
    }
    for input in core_inputs {
        if recorded.get(input.name()) != Some(&input.digest()) {
            return false;
        }
    }
    let core_names: std::collections::BTreeSet<&str> =
        core_inputs.iter().map(|input| input.name()).collect();
    record.inputs().iter().all(|input| {
        core_names.contains(input.name())
            || DERIVED_INPUT_PREFIXES
                .iter()
                .any(|prefix| input.name().starts_with(prefix))
    })
}

fn reconstitute(
    engine: &Engine,
    plan_id: PreparedId,
    record: &PreparedRecordV1,
) -> Result<ReusableEvaluation, super::EngineError> {
    let reuse_notice = PreparePolicyFindingV1::new(
        "AUTHORING-EVALUATION-REUSED",
        format!(
            "evaluation reused from plan {plan_id}: every captured evaluation input is byte-identical"
        ),
        false,
    )
    .map_err(|error| prepared_store::invalid_record(engine, error))?;
    let inputs = record
        .inputs()
        .iter()
        .map(|input| prepared_store::input_view(&plan_id, input))
        .collect::<Result<Vec<_>, _>>()?;
    let artifacts = record.artifacts().to_vec();
    let transforms = record
        .transforms()
        .iter()
        .map(|transform| transform_carry(&plan_id, transform))
        .collect::<Result<Vec<_>, _>>()?;
    let mut findings = record
        .findings()
        .iter()
        .filter(|finding| !REGENERATED_FINDING_CODES.contains(&finding.code()))
        .map(|finding| {
            PreparePolicyFindingV1::new(
                finding.code(),
                finding.message(),
                finding.approval_required(),
            )
            .map_err(|error| prepared_store::invalid_record(engine, error))
        })
        .collect::<Result<Vec<_>, _>>()?;
    findings.push(reuse_notice);
    if !transforms.is_empty() {
        findings.push(
            PreparePolicyFindingV1::new(
                "AUTHORING-TRANSFORMS-CARRIED",
                format!(
                    "output transform provenance carried from plan {plan_id}: every captured \
                     evaluation input is byte-identical"
                ),
                false,
            )
            .map_err(|error| prepared_store::invalid_record(engine, error))?,
        );
    }
    let operations = record
        .operations()
        .iter()
        // RemoveLeaf reflects the retained plan's old predecessor, not
        // evaluation. Fresh reconciliation must derive removals again.
        .filter(|operation| !matches!(operation, PreparedOperationV1::RemoveLeaf { .. }))
        .map(prepared_store::operation_view)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(ReusableEvaluation {
        inputs,
        artifacts,
        transforms,
        findings,
        operations,
    })
}

/// Submits a reused evaluation through the prepared store; host-state work
/// (observation, reconciliation, drift, mandatory findings) runs fresh.
pub(crate) fn submit_reused(
    engine: &Engine,
    namespace: NamespaceName,
    expected_head: Option<Digest>,
    graph_digest: Digest,
    reused: ReusableEvaluation,
    extra_findings: Vec<PreparePolicyFindingV1>,
) -> Result<super::PreparedDeploymentV1, super::EngineError> {
    let mut findings = reused.findings;
    findings.extend(extra_findings);
    let generated = malm_types::PrepareRequestV1::from(malm_types::PrepareRequestPartsV1 {
        namespace,
        expected_head,
        graph_digest,
        inputs: reused.inputs,
        artifacts: Vec::new(),
        transforms: reused.transforms,
        findings,
        operations: reused.operations,
    });
    prepared_store::prepare_with_retained_artifacts(engine, &generated, reused.artifacts)
}

/// Detects live consent states that retained operations cannot express.
/// Full evaluation derives current consent in these cases.
pub(crate) fn is_consent_shape_refusal(error: &super::EngineError) -> bool {
    matches!(
        error,
        super::EngineError::PreparedStore {
            reason: super::PreparedStoreIssue::UnsafeTarget { detail },
            ..
        } if detail.contains("requires the leaf to be absent")
    ) || matches!(
        error,
        // Fall back if shared ancestor synthesis still cannot cover the shape.
        super::EngineError::PreparedStore {
            reason: super::PreparedStoreIssue::MissingManagedAncestor { .. },
            ..
        }
    )
}

fn transform_carry(
    plan_id: &PreparedId,
    transform: &TransformProvenanceV1,
) -> Result<PrepareTransformProvenanceV1, super::EngineError> {
    prepared_store::transform_view(plan_id, transform)
}
