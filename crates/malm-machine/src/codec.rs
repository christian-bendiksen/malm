use std::collections::HashSet;
use std::fmt;

use malm_types::{
    ApplyOutcomeV1, ApprovalV1, ArchiveProvenanceV1, ArtifactDescriptorV1, ArtifactId,
    ArtifactMetadataInspectionRequestV1, ArtifactMetadataInspectionV1, ArtifactV1,
    CanonicalTreeEntryInspectionV1, CanonicalTreeEntryKindInspectionV1,
    CanonicalTreeInspectionRequestV1, CanonicalTreeInspectionV1, CapturedInputsInspectionV1,
    CatalogInspectionRequestV1, CatalogInspectionV1, CatalogNamespaceInspectionV1,
    CheckoutRequestV1, CommitRequestV1, ContributionName, DeploymentName,
    DesiredSnapshotInspectionRequestV1, DesiredSnapshotInspectionV1, DesiredTargetInspectionV1,
    DesiredTargetStateInspectionV1, Digest, DirectorySafetyReasonV1, FsckFindingCodeV1,
    FsckFindingV1, FsckReportPartsV1, FsckReportV1, FsckRequestV1, FsckSeverityV1, FsckStoreAreaV1,
    FsckSubjectV1, GenerationInspectionPartsV1, GenerationInspectionRequestV1,
    GenerationInspectionV1, HistoryRetentionRequestV1, LifecycleRequestV1, LifecycleStateViewV1,
    LifecycleTransitionViewV1, MAX_TRANSFORM_DIAGNOSTIC_NOTES_V1, MAX_TRANSFORM_DIAGNOSTICS_V1,
    MAX_TRANSFORM_RESOURCES_V1, NamespaceHistoryRequestV1, NamespaceHistoryV1,
    NamespaceInspectionRequestV1, NamespaceInspectionV1, NamespaceName, NamespaceRemovalHistoryV1,
    NamespaceRemovalRequestV1, NamespaceStatusKindV1, NamespaceStatusPartsV1,
    NamespaceStatusRequestV1, NamespaceStatusV1, PackNodeId, PolicyFindingV1, PrepareArtifactV1,
    PrepareInputKindV1, PrepareInputV1, PrepareOperationV1, PreparePolicyFindingV1,
    PrepareRequestPartsV1, PrepareRequestV1, PrepareTargetStateV1,
    PrepareTransformDiagnosticLocationV1, PrepareTransformDiagnosticSeverityV1,
    PrepareTransformDiagnosticV1, PrepareTransformImplementationV1,
    PrepareTransformOutputLocationV1, PrepareTransformProvenanceV1, PrepareTransformResourceV1,
    PrepareTransformSourceLocationV1, PreparedDeploymentPartsV1, PreparedDeploymentV1, PreparedId,
    PreparedPlanInspectionRequestV1, PreparedTrackingAcquisitionGrantV1,
    PreparedTrackingAcquisitionKindV1, PreparedTrackingReviewPartsV1, PreparedTrackingReviewV1,
    PruneOutcomeV1, PruneRequestV1, RecoveryOutcomeV1, RestorePointInspectionV1,
    RestorePointRequestV1, RetentionAuthorityInspectionV1, RetentionInspectionV1,
    RetentionObjectV1, RetentionPinRequestV1, StateViewV1, StoreDirectoryV1, StoreRootV1,
    StoreStatusV1, TargetStatusKindV1, TargetStatusV1, TrackedRootInspectionV1,
    TrackingInspectionV1, TransformProvenanceInspectionV1, policy_approval_digest_v1,
    policy_finding_id_v1, serde_util::bounded_seq,
};
use serde::de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};

use crate::{
    DiagnosticSeverityV1, MACHINE_SCHEMA_VERSION, MAX_MACHINE_ARRAY_ITEMS, MAX_MACHINE_FRAME_BYTES,
    MAX_MACHINE_JSON_DEPTH, MAX_MACHINE_OBJECT_MEMBERS, MAX_MACHINE_VALUES, MachineCodeV1,
    MachineDiagnosticV1, MachineErrorCategoryV1, MachineErrorCodeV1, MachineErrorDetailsV1,
    MachineErrorV1, MachineOperationV1, MachineRequestV1, MachineResultV1, MachineTextV1,
    MachineValidationError, RequestEnvelopeV1, RequestIdV1, SchemaFamilyV1, ServerFrameV1,
};

const DUPLICATE_MARKER: &str = "__malm_machine_duplicate_key__";
const DEPTH_MARKER: &str = "__malm_machine_depth__";
const OBJECT_MARKER: &str = "__malm_machine_object_members__";
const ARRAY_MARKER: &str = "__malm_machine_array_items__";
const VALUES_MARKER: &str = "__malm_machine_values__";

/// A strict failure while decoding one machine record.
#[derive(Debug)]
#[non_exhaustive]
pub enum MachineReadError {
    TooLarge { limit: usize, actual: usize },
    InvalidUtf8,
    InvalidFraming(&'static str),
    TooDeep { limit: usize },
    TooManyObjectMembers { limit: usize },
    TooManyArrayItems { limit: usize },
    TooManyValues { limit: usize },
    DuplicateKey,
    MalformedJson(String),
    UnsupportedVersion { expected: u32, found: u32 },
    InvalidEnvelope(String),
    InvalidSemantics(MachineValidationError),
}

impl fmt::Display for MachineReadError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLarge { limit, actual } => {
                write!(
                    formatter,
                    "machine record is {actual} bytes; limit is {limit}"
                )
            }
            Self::InvalidUtf8 => formatter.write_str("machine record is not UTF-8"),
            Self::InvalidFraming(reason) => write!(formatter, "invalid machine framing: {reason}"),
            Self::TooDeep { limit } => write!(formatter, "machine JSON depth exceeds {limit}"),
            Self::TooManyObjectMembers { limit } => {
                write!(formatter, "machine JSON object exceeds {limit} members")
            }
            Self::TooManyArrayItems { limit } => {
                write!(formatter, "machine JSON array exceeds {limit} items")
            }
            Self::TooManyValues { limit } => {
                write!(formatter, "machine JSON record exceeds {limit} values")
            }
            Self::DuplicateKey => formatter.write_str("machine JSON contains a duplicate key"),
            Self::MalformedJson(detail) => write!(formatter, "malformed machine JSON: {detail}"),
            Self::UnsupportedVersion { expected, found } => write!(
                formatter,
                "unsupported machine schema: expected exactly {expected}, found {found}"
            ),
            Self::InvalidEnvelope(detail) => {
                write!(formatter, "invalid machine/v1 envelope: {detail}")
            }
            Self::InvalidSemantics(error) => {
                write!(formatter, "invalid machine/v1 envelope: {error}")
            }
        }
    }
}

impl std::error::Error for MachineReadError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidSemantics(error) => Some(error),
            _ => None,
        }
    }
}

/// A deterministic failure while encoding a machine record.
#[derive(Debug)]
#[non_exhaustive]
pub enum MachineWriteError {
    TooLarge { limit: usize, actual: usize },
    InvalidSemantics(MachineValidationError),
    RejectedByDecoder(Box<MachineReadError>),
    Serialization(String),
}

impl fmt::Display for MachineWriteError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLarge { limit, actual } => write!(
                formatter,
                "encoded machine record is {actual} bytes; limit is {limit}"
            ),
            Self::InvalidSemantics(error) => {
                write!(formatter, "cannot encode invalid machine/v1 model: {error}")
            }
            Self::RejectedByDecoder(error) => {
                write!(
                    formatter,
                    "encoded machine/v1 record is not self-decodable: {error}"
                )
            }
            Self::Serialization(detail) => {
                write!(formatter, "cannot encode machine/v1 record: {detail}")
            }
        }
    }
}

impl std::error::Error for MachineWriteError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidSemantics(error) => Some(error),
            Self::RejectedByDecoder(error) => Some(error.as_ref()),
            Self::TooLarge { .. } | Self::Serialization(_) => None,
        }
    }
}

/// Decodes one strict LF-terminated client request record.
pub fn decode_request_v1(bytes: &[u8]) -> Result<RequestEnvelopeV1, MachineReadError> {
    let payload = preflight(bytes)?;
    validate_version(payload)?;
    let wire: RequestEnvelopeWireV1 = serde_json::from_slice(payload)
        .map_err(|error| MachineReadError::InvalidEnvelope(error.to_string()))?;
    let request_id =
        RequestIdV1::new(wire.request_id).map_err(MachineReadError::InvalidSemantics)?;
    let request = request_from_wire(wire.request)?;
    Ok(RequestEnvelopeV1::new(request_id, request))
}

/// Decodes one strict LF-terminated server event or terminal record.
pub fn decode_server_frame_v1(bytes: &[u8]) -> Result<ServerFrameV1, MachineReadError> {
    let payload = preflight(bytes)?;
    validate_version(payload)?;
    let wire: ServerEnvelopeWireV1 = serde_json::from_slice(payload)
        .map_err(|error| MachineReadError::InvalidEnvelope(error.to_string()))?;
    match wire {
        ServerEnvelopeWireV1::Event(wire) => {
            if wire.sequence != 0 {
                return Err(MachineReadError::InvalidSemantics(
                    MachineValidationError::InvalidSequence {
                        frame: "event",
                        sequence: wire.sequence,
                    },
                ));
            }
            let request_id =
                RequestIdV1::new(wire.request_id).map_err(MachineReadError::InvalidSemantics)?;
            let EventWireV1::Started { operation } = wire.event;
            Ok(ServerFrameV1::started(
                request_id,
                operation_from_wire(operation),
            ))
        }
        ServerEnvelopeWireV1::Result(wire) => {
            let request_id =
                RequestIdV1::new(wire.request_id).map_err(MachineReadError::InvalidSemantics)?;
            let result = result_from_wire(wire.result)?;
            ServerFrameV1::result(request_id, wire.sequence, result)
                .map_err(MachineReadError::InvalidSemantics)
        }
        ServerEnvelopeWireV1::Error(wire) => {
            let request_id = wire
                .request_id
                .into_option()
                .map(RequestIdV1::new)
                .transpose()
                .map_err(MachineReadError::InvalidSemantics)?;
            let error = error_from_wire(wire.error)?;
            ServerFrameV1::error(request_id, wire.sequence, error)
                .map_err(MachineReadError::InvalidSemantics)
        }
    }
}

/// Encodes one canonical compact LF-terminated request record.
pub fn encode_request_v1(request: &RequestEnvelopeV1) -> Result<Vec<u8>, MachineWriteError> {
    let bytes = encode_wire(&RequestEnvelopeWireV1 {
        schema_version: MACHINE_SCHEMA_VERSION,
        request_id: request.request_id().as_str().to_owned(),
        frame_type: RequestFrameTypeWireV1::Request,
        request: request_to_wire(request.request()).map_err(MachineWriteError::InvalidSemantics)?,
    })?;
    let decoded = decode_request_v1(&bytes).map_err(write_decoder_error)?;
    if &decoded != request {
        return Err(MachineWriteError::Serialization(
            "encoded request does not reconstruct the original semantic model".to_owned(),
        ));
    }
    Ok(bytes)
}

/// Encodes one canonical compact LF-terminated server record.
pub fn encode_server_frame_v1(frame: &ServerFrameV1) -> Result<Vec<u8>, MachineWriteError> {
    frame
        .validate()
        .map_err(MachineWriteError::InvalidSemantics)?;
    if let ServerFrameV1::Result { result, .. } = frame {
        validate_result_review(result).map_err(MachineWriteError::InvalidSemantics)?;
    }
    let wire = match frame {
        ServerFrameV1::Started {
            request_id,
            operation,
        } => ServerEnvelopeWireV1::Event(EventEnvelopeWireV1 {
            schema_version: MACHINE_SCHEMA_VERSION,
            request_id: request_id.as_str().to_owned(),
            sequence: 0,
            frame_type: EventFrameTypeWireV1::Event,
            event: EventWireV1::Started {
                operation: operation_to_wire(*operation),
            },
        }),
        ServerFrameV1::Result {
            request_id,
            sequence,
            result,
        } => ServerEnvelopeWireV1::Result(ResultEnvelopeWireV1 {
            schema_version: MACHINE_SCHEMA_VERSION,
            request_id: request_id.as_str().to_owned(),
            sequence: *sequence,
            frame_type: ResultFrameTypeWireV1::Result,
            result: result_to_wire(result),
        }),
        ServerFrameV1::Error {
            request_id,
            sequence,
            error,
        } => ServerEnvelopeWireV1::Error(ErrorEnvelopeWireV1 {
            schema_version: MACHINE_SCHEMA_VERSION,
            request_id: request_id
                .as_ref()
                .map_or(NullableRequestIdWire::Null(()), |id| {
                    NullableRequestIdWire::Id(id.as_str().to_owned())
                }),
            sequence: *sequence,
            frame_type: ErrorFrameTypeWireV1::Error,
            error: error_to_wire(error),
        }),
    };
    let bytes = encode_wire(&wire)?;
    let decoded = decode_server_frame_v1(&bytes).map_err(write_decoder_error)?;
    if &decoded != frame {
        return Err(MachineWriteError::Serialization(
            "encoded server frame does not reconstruct the original semantic model".to_owned(),
        ));
    }
    Ok(bytes)
}

fn write_decoder_error(error: MachineReadError) -> MachineWriteError {
    match error {
        MachineReadError::TooLarge { limit, actual } => {
            MachineWriteError::TooLarge { limit, actual }
        }
        error => MachineWriteError::RejectedByDecoder(Box::new(error)),
    }
}

fn validate_result_review(result: &MachineResultV1) -> Result<(), MachineValidationError> {
    let Some(deployment) = reviewed_deployment(result) else {
        return Ok(());
    };
    let mut finding_ids = HashSet::new();
    for finding in deployment.findings() {
        if finding.id()
            != &policy_finding_id_v1(
                finding.code(),
                finding.message(),
                finding.approval_required(),
            )
        {
            return Err(MachineValidationError::InvalidPreparedDeployment(
                "policy finding ID does not match its contents",
            ));
        }
        if !finding_ids.insert(finding.id()) {
            return Err(MachineValidationError::InvalidPreparedDeployment(
                "policy finding IDs must be unique",
            ));
        }
    }
    let expected = policy_approval_digest_v1(
        deployment
            .findings()
            .iter()
            .map(|finding| (finding.id().clone(), finding.approval_required())),
    );
    if deployment.approval_digest() != &expected {
        return Err(MachineValidationError::InvalidPreparedDeployment(
            "approval digest does not match policy findings",
        ));
    }
    Ok(())
}

/// Maps a rejected request to a bounded uncorrelated terminal frame.
///
/// A request becomes correlatable only after the complete envelope is valid.
/// Parser details and rejected input are never copied into this frame.
#[must_use]
pub fn request_error_frame_v1(error: &MachineReadError) -> ServerFrameV1 {
    let error = match error {
        MachineReadError::TooLarge { .. }
        | MachineReadError::TooDeep { .. }
        | MachineReadError::TooManyObjectMembers { .. }
        | MachineReadError::TooManyArrayItems { .. }
        | MachineReadError::TooManyValues { .. } => MachineErrorV1::frame_resource_limit(),
        MachineReadError::InvalidUtf8
        | MachineReadError::InvalidFraming(_)
        | MachineReadError::DuplicateKey
        | MachineReadError::MalformedJson(_) => MachineErrorV1::malformed_json(),
        MachineReadError::UnsupportedVersion { expected, found }
            if *expected == MACHINE_SCHEMA_VERSION && *found != *expected =>
        {
            MachineErrorV1::unsupported_machine_version(*found)
        }
        MachineReadError::UnsupportedVersion { .. } => MachineErrorV1::invalid_request(),
        MachineReadError::InvalidEnvelope(_) | MachineReadError::InvalidSemantics(_) => {
            MachineErrorV1::invalid_request()
        }
    };
    ServerFrameV1::uncorrelated_error(error)
}

fn preflight(bytes: &[u8]) -> Result<&[u8], MachineReadError> {
    if bytes.len() > MAX_MACHINE_FRAME_BYTES {
        return Err(MachineReadError::TooLarge {
            limit: MAX_MACHINE_FRAME_BYTES,
            actual: bytes.len(),
        });
    }
    std::str::from_utf8(bytes).map_err(|_| MachineReadError::InvalidUtf8)?;
    let Some(payload) = bytes.strip_suffix(b"\n") else {
        return Err(MachineReadError::InvalidFraming(
            "record must end with one LF byte",
        ));
    };
    if payload.is_empty() {
        return Err(MachineReadError::InvalidFraming("record is empty"));
    }
    if payload.contains(&b'\n') || payload.contains(&b'\r') {
        return Err(MachineReadError::InvalidFraming(
            "record must contain exactly one terminal LF and no CR",
        ));
    }

    let mut budget = JsonBudget::default();
    let mut deserializer = serde_json::Deserializer::from_slice(payload);
    BudgetSeed {
        budget: &mut budget,
    }
    .deserialize(&mut deserializer)
    .map_err(classify_budget_error)?;
    deserializer
        .end()
        .map_err(|error| MachineReadError::MalformedJson(error.to_string()))?;
    Ok(payload)
}

fn classify_budget_error(error: serde_json::Error) -> MachineReadError {
    let detail = error.to_string();
    if detail.contains(DUPLICATE_MARKER) {
        MachineReadError::DuplicateKey
    } else if detail.contains(DEPTH_MARKER) {
        MachineReadError::TooDeep {
            limit: MAX_MACHINE_JSON_DEPTH,
        }
    } else if detail.contains(OBJECT_MARKER) {
        MachineReadError::TooManyObjectMembers {
            limit: MAX_MACHINE_OBJECT_MEMBERS,
        }
    } else if detail.contains(ARRAY_MARKER) {
        MachineReadError::TooManyArrayItems {
            limit: MAX_MACHINE_ARRAY_ITEMS,
        }
    } else if detail.contains(VALUES_MARKER) {
        MachineReadError::TooManyValues {
            limit: MAX_MACHINE_VALUES,
        }
    } else {
        MachineReadError::MalformedJson(detail)
    }
}

fn validate_version(payload: &[u8]) -> Result<(), MachineReadError> {
    let probe: VersionProbe = serde_json::from_slice(payload)
        .map_err(|_| MachineReadError::InvalidEnvelope("missing schema_version".to_owned()))?;
    let found = probe
        .schema_version
        .as_u64()
        .and_then(|version| u32::try_from(version).ok())
        .ok_or_else(|| {
            MachineReadError::InvalidEnvelope(
                "schema_version must be an unsigned 32-bit integer".to_owned(),
            )
        })?;
    if found != MACHINE_SCHEMA_VERSION {
        return Err(MachineReadError::UnsupportedVersion {
            expected: MACHINE_SCHEMA_VERSION,
            found,
        });
    }
    Ok(())
}

fn encode_wire(wire: &impl Serialize) -> Result<Vec<u8>, MachineWriteError> {
    let mut bytes = serde_json::to_vec(wire)
        .map_err(|error| MachineWriteError::Serialization(error.to_string()))?;
    bytes.push(b'\n');
    if bytes.len() > MAX_MACHINE_FRAME_BYTES {
        return Err(MachineWriteError::TooLarge {
            limit: MAX_MACHINE_FRAME_BYTES,
            actual: bytes.len(),
        });
    }
    Ok(bytes)
}

#[derive(Default)]
struct JsonBudget {
    depth: usize,
    values: usize,
}

impl JsonBudget {
    fn value<E: de::Error>(&mut self) -> Result<(), E> {
        self.values += 1;
        if self.values > MAX_MACHINE_VALUES {
            Err(E::custom(VALUES_MARKER))
        } else {
            Ok(())
        }
    }

    fn enter<E: de::Error>(&mut self) -> Result<(), E> {
        self.depth += 1;
        if self.depth > MAX_MACHINE_JSON_DEPTH {
            Err(E::custom(DEPTH_MARKER))
        } else {
            Ok(())
        }
    }

    fn leave(&mut self) {
        self.depth -= 1;
    }
}

struct BudgetSeed<'a> {
    budget: &'a mut JsonBudget,
}

impl<'de> DeserializeSeed<'de> for BudgetSeed<'_> {
    type Value = ();

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(BudgetVisitor {
            budget: self.budget,
        })
    }
}

struct BudgetVisitor<'a> {
    budget: &'a mut JsonBudget,
}

impl<'de> Visitor<'de> for BudgetVisitor<'_> {
    type Value = ();

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("bounded JSON without duplicate keys")
    }

    fn visit_bool<E>(self, _value: bool) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        self.budget.value()
    }

    fn visit_i64<E>(self, _value: i64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        self.budget.value()
    }

    fn visit_u64<E>(self, _value: u64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        self.budget.value()
    }

    fn visit_f64<E>(self, _value: f64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        self.budget.value()
    }

    fn visit_str<E>(self, _value: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        self.budget.value()
    }

    fn visit_string<E>(self, _value: String) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        self.budget.value()
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        self.budget.value()
    }

    fn visit_none<E>(self) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        self.budget.value()
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        self.budget.value()?;
        self.budget.enter()?;
        let mut items = 0;
        while sequence
            .next_element_seed(BudgetSeed {
                budget: self.budget,
            })?
            .is_some()
        {
            items += 1;
            if items > MAX_MACHINE_ARRAY_ITEMS {
                return Err(de::Error::custom(ARRAY_MARKER));
            }
        }
        self.budget.leave();
        Ok(())
    }

    fn visit_map<A>(self, mut object: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        self.budget.value()?;
        self.budget.enter()?;
        let mut members = 0;
        let mut seen = HashSet::new();
        while let Some(key) = object.next_key::<String>()? {
            members += 1;
            if members > MAX_MACHINE_OBJECT_MEMBERS {
                return Err(de::Error::custom(OBJECT_MARKER));
            }
            if !seen.insert(key) {
                return Err(de::Error::custom(DUPLICATE_MARKER));
            }
            object.next_value_seed(BudgetSeed {
                budget: self.budget,
            })?;
        }
        self.budget.leave();
        Ok(())
    }
}

#[derive(Deserialize)]
struct VersionProbe {
    schema_version: serde_json::Value,
}

#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum RequestFrameTypeWireV1 {
    Request,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RequestEnvelopeWireV1 {
    schema_version: u32,
    request_id: String,
    #[serde(rename = "type")]
    frame_type: RequestFrameTypeWireV1,
    request: RequestWireV1,
}

/// Keep this enum literal. Workspace source-contract tests parse its exact
/// request inventory, and every frozen payload shape must remain visible here.
#[derive(Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
enum RequestWireV1 {
    StoreStatus {},
    InitializeStore {},
    Prepare {
        namespace: NamespaceName,
        expected_head: Option<Digest>,
        graph_digest: Digest,
        inputs: Vec<PrepareInputWireV1>,
        artifacts: Vec<PrepareArtifactWireV1>,
        findings: Vec<PrepareFindingWireV1>,
        operations: Vec<PrepareOperationWireV1>,
    },
    Plan {
        plan_id: PreparedId,
    },
    Artifact {
        plan_id: PreparedId,
        artifact_id: ArtifactId,
    },
    Commit {
        plan_id: PreparedId,
        approval_digest: Digest,
    },
    State {
        namespace: NamespaceName,
    },
    Recover {},
    Prune {
        plan_ids: Vec<PreparedId>,
    },
    Checkout {
        namespace: NamespaceName,
        target_generation: Digest,
    },
    Disable {
        namespace: NamespaceName,
    },
    Enable {
        namespace: NamespaceName,
    },
    RemoveNamespace {
        namespace: NamespaceName,
        history: NamespaceRemovalHistoryWireV1,
    },
    SetHistoryRetention {
        namespace: NamespaceName,
        generations: u32,
    },
    Pin {
        namespace: NamespaceName,
        object: RetentionObjectWireV1,
    },
    Unpin {
        namespace: NamespaceName,
        object: RetentionObjectWireV1,
    },
    AddRestorePoint {
        namespace: NamespaceName,
        generation: Digest,
    },
    DropRestorePoint {
        namespace: NamespaceName,
        generation: Digest,
    },
    Catalog {
        max_namespaces: u64,
        max_decoded_bytes: u64,
    },
    Namespace {
        namespace: NamespaceName,
        max_decoded_bytes: u64,
    },
    History {
        namespace: NamespaceName,
        max_generations: u64,
        max_decoded_bytes: u64,
    },
    Generation {
        namespace: NamespaceName,
        generation: Digest,
        max_generations: u64,
        max_decoded_bytes: u64,
    },
    DesiredSnapshot {
        namespace: NamespaceName,
        generation: Digest,
        max_targets: u64,
        max_decoded_bytes: u64,
    },
    CanonicalTree {
        tree: Digest,
        max_entries: u64,
        max_decoded_bytes: u64,
    },
    ArtifactMetadata {
        plan_id: PreparedId,
        artifact_id: ArtifactId,
        max_decoded_bytes: u64,
    },
    CapturedInputs {
        plan_id: PreparedId,
        max_items: u64,
        max_decoded_bytes: u64,
    },
    TransformProvenance {
        plan_id: PreparedId,
        max_items: u64,
        max_decoded_bytes: u64,
    },
    Retention {
        namespace: NamespaceName,
        generation: Digest,
        max_generations: u64,
        max_decoded_bytes: u64,
    },
    Tracking {
        namespace: NamespaceName,
        generation: Digest,
        max_generations: u64,
        max_decoded_bytes: u64,
    },
    Status {
        namespace: NamespaceName,
        max_targets: u64,
        max_observed_bytes: u64,
    },
    Fsck {
        max_findings: u64,
        max_objects: u64,
        max_decoded_bytes: u64,
        observe_targets: bool,
        max_target_observations: u64,
        max_observed_bytes: u64,
    },
}

#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum NamespaceRemovalHistoryWireV1 {
    Drop,
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum RetentionObjectWireV1 {
    PreparedPlan { plan_id: PreparedId },
    StateGeneration { digest: Digest },
    ArtifactBlob { digest: Digest },
    PackObject { digest: Digest },
    CanonicalFile { digest: Digest },
    CanonicalSymlink { digest: Digest },
    CanonicalTree { digest: Digest },
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PrepareInputWireV1 {
    kind: PrepareInputKindWireV1,
    name: String,
    digest: Digest,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PrepareArtifactWireV1 {
    id: ArtifactId,
    bytes_hex: String,
    media_type: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PrepareFindingWireV1 {
    code: String,
    message: String,
    approval_required: bool,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ArchiveProvenanceWireV1 {
    payload: Digest,
    decoder: String,
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum PrepareTargetStateWireV1 {
    File {
        digest: Digest,
        byte_len: u64,
        mode: u32,
    },
    Directory {
        mode: u32,
    },
    Symlink {
        object: Digest,
    },
    Tree {
        tree: Digest,
        archive_provenance: Option<ArchiveProvenanceWireV1>,
    },
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
enum PrepareOperationWireV1 {
    EnsureDirectory {
        authority: DeploymentName,
        relative_path: String,
        mode: u32,
        replace_existing: bool,
    },
    PlaceFile {
        authority: DeploymentName,
        relative_path: String,
        artifact_id: ArtifactId,
        mode: u32,
        replace_existing: bool,
    },
    PlaceSymlink {
        authority: DeploymentName,
        relative_path: String,
        object: Digest,
        replace_existing: bool,
    },
    PlaceTree {
        authority: DeploymentName,
        relative_path: String,
        tree: Digest,
        archive_provenance: Option<ArchiveProvenanceWireV1>,
        replace_existing: bool,
    },
    RemoveLeaf {
        authority: DeploymentName,
        relative_path: String,
    },
    AssertAbsent {
        authority: DeploymentName,
        relative_path: String,
    },
    AssertExact {
        authority: DeploymentName,
        relative_path: String,
        state: PrepareTargetStateWireV1,
    },
}

#[derive(Serialize, Deserialize)]
#[serde(untagged)]
#[allow(clippy::large_enum_variant)]
enum ServerEnvelopeWireV1 {
    Event(EventEnvelopeWireV1),
    Result(ResultEnvelopeWireV1),
    Error(ErrorEnvelopeWireV1),
}

#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum EventFrameTypeWireV1 {
    Event,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct EventEnvelopeWireV1 {
    schema_version: u32,
    request_id: String,
    sequence: u64,
    #[serde(rename = "type")]
    frame_type: EventFrameTypeWireV1,
    event: EventWireV1,
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
enum EventWireV1 {
    Started { operation: OperationWireV1 },
}

#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum ResultFrameTypeWireV1 {
    Result,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ResultEnvelopeWireV1 {
    schema_version: u32,
    request_id: String,
    sequence: u64,
    #[serde(rename = "type")]
    frame_type: ResultFrameTypeWireV1,
    result: ResultWireV1,
}

/// Keep this enum literal. Workspace source-contract tests parse its exact
/// result inventory, and every frozen payload shape must remain visible here.
#[derive(Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
enum ResultWireV1 {
    StoreStatus {
        status: StoreStatusWireV1,
    },
    InitializeStore {
        status: StoreStatusWireV1,
    },
    Prepare {
        deployment: PreparedDeploymentWireV1,
    },
    Plan {
        deployment: PreparedDeploymentWireV1,
    },
    Artifact {
        artifact: ArtifactWireV1,
    },
    Commit {
        outcome: ApplyOutcomeWireV1,
    },
    State {
        state: StateViewWireV1,
    },
    Recover {
        outcome: RecoveryOutcomeWireV1,
    },
    Prune {
        outcome: PruneOutcomeWireV1,
    },
    Checkout {
        deployment: PreparedDeploymentWireV1,
    },
    Disable {
        deployment: PreparedDeploymentWireV1,
    },
    Enable {
        deployment: PreparedDeploymentWireV1,
    },
    RemoveNamespace {
        deployment: PreparedDeploymentWireV1,
    },
    SetHistoryRetention {
        deployment: PreparedDeploymentWireV1,
    },
    Pin {
        deployment: PreparedDeploymentWireV1,
    },
    Unpin {
        deployment: PreparedDeploymentWireV1,
    },
    AddRestorePoint {
        deployment: PreparedDeploymentWireV1,
    },
    DropRestorePoint {
        deployment: PreparedDeploymentWireV1,
    },
    Catalog {
        catalog: CatalogInspectionWireV1,
    },
    Namespace {
        namespace: NamespaceInspectionWireV1,
    },
    History {
        history: NamespaceHistoryWireV1,
    },
    Generation {
        generation: GenerationInspectionWireV1,
    },
    DesiredSnapshot {
        snapshot: DesiredSnapshotInspectionWireV1,
    },
    CanonicalTree {
        tree: CanonicalTreeInspectionWireV1,
    },
    ArtifactMetadata {
        artifact: ArtifactMetadataInspectionWireV1,
    },
    CapturedInputs {
        inputs: CapturedInputsInspectionWireV1,
    },
    TransformProvenance {
        provenance: TransformProvenanceInspectionWireV1,
    },
    Retention {
        retention: RetentionInspectionWireV1,
    },
    Tracking {
        tracking: TrackingInspectionWireV1,
    },
    Status {
        status: NamespaceStatusWireV1,
    },
    Fsck {
        report: FsckReportWireV1,
    },
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PreparedDeploymentWireV1 {
    plan_id: PreparedId,
    namespace: NamespaceName,
    expected_head: Option<Digest>,
    transition: LifecycleTransitionWireV1,
    lifecycle: LifecycleStateWireV1,
    restore_point: Option<RestorePointInspectionWireV1>,
    retention: RetentionAuthorityInspectionWireV1,
    tracked_root: Option<PreparedTrackingReviewWireV1>,
    graph_digest: Digest,
    inputs: Vec<PrepareInputWireV1>,
    transforms: Vec<TransformProvenanceWireV1>,
    artifacts: Vec<ArtifactDescriptorWireV1>,
    findings: Vec<PolicyFindingWireV1>,
    approval_digest: Digest,
    operations: Vec<PrepareOperationWireV1>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CatalogNamespaceInspectionWireV1 {
    namespace: NamespaceName,
    generation: Digest,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CatalogInspectionWireV1 {
    digest: Digest,
    namespaces: Vec<CatalogNamespaceInspectionWireV1>,
    decoded_bytes: u64,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct NamespaceInspectionWireV1 {
    namespace: NamespaceName,
    head: Option<Digest>,
    generation: Option<GenerationInspectionWireV1>,
    decoded_bytes: u64,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct NamespaceHistoryWireV1 {
    namespace: NamespaceName,
    head: Option<Digest>,
    generations: Vec<GenerationInspectionWireV1>,
    decoded_bytes: u64,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct GenerationInspectionWireV1 {
    namespace: NamespaceName,
    generation: Digest,
    lifecycle: LifecycleStateWireV1,
    desired_snapshot_digest: Digest,
    target_count: u64,
    present_target_count: u64,
    absent_target_count: u64,
    plan_id: PreparedId,
    predecessor: Option<Digest>,
    tracked_root: Option<TrackedRootInspectionWireV1>,
    transition: LifecycleTransitionWireV1,
    restore_point: Option<RestorePointInspectionWireV1>,
    retention: RetentionAuthorityInspectionWireV1,
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum LifecycleTransitionWireV1 {
    Reconcile {},
    Disable {},
    Enable { restore_generation: Digest },
    Checkout { source_generation: Digest },
    RetentionAuthority {},
    NamespaceRemoval { drops_history: bool },
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RestorePointInspectionWireV1 {
    generation: Digest,
    lifecycle: LifecycleStateWireV1,
    desired_snapshot_digest: Digest,
    tracked_root: Option<TrackedRootInspectionWireV1>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RetentionAuthorityInspectionWireV1 {
    history_generations: u32,
    restore_points: Vec<RestorePointInspectionWireV1>,
    explicit_pins: Vec<RetentionObjectWireV1>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DesiredSnapshotInspectionWireV1 {
    namespace: NamespaceName,
    generation: Digest,
    digest: Digest,
    targets: Vec<DesiredTargetInspectionWireV1>,
    decoded_bytes: u64,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DesiredTargetInspectionWireV1 {
    authority: DeploymentName,
    relative_path: String,
    state: DesiredTargetStateInspectionWireV1,
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum DesiredTargetStateInspectionWireV1 {
    File {
        digest: Option<Digest>,
        byte_len: Option<u64>,
        mode: Option<u32>,
    },
    Directory {
        mode: Option<u32>,
    },
    Symlink {
        object: Option<Digest>,
    },
    Tree {
        tree: Option<Digest>,
        archive_provenance: Option<ArchiveProvenanceWireV1>,
    },
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CanonicalTreeInspectionWireV1 {
    tree: Digest,
    root_mode: u32,
    entries: Vec<CanonicalTreeEntryInspectionWireV1>,
    decoded_bytes: u64,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CanonicalTreeEntryInspectionWireV1 {
    relative_path: String,
    mode: u32,
    object: CanonicalTreeEntryKindInspectionWireV1,
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum CanonicalTreeEntryKindInspectionWireV1 {
    File { digest: Digest, byte_len: u64 },
    Directory { digest: Digest },
    Symlink { digest: Digest },
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ArtifactMetadataInspectionWireV1 {
    plan_id: PreparedId,
    descriptor: ArtifactDescriptorWireV1,
    decoded_bytes: u64,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CapturedInputsInspectionWireV1 {
    plan_id: PreparedId,
    graph_digest: Digest,
    inputs: Vec<PrepareInputWireV1>,
    decoded_bytes: u64,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TransformProvenanceInspectionWireV1 {
    plan_id: PreparedId,
    transforms: Vec<TransformProvenanceWireV1>,
    decoded_bytes: u64,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RetentionInspectionWireV1 {
    namespace: NamespaceName,
    generation: Digest,
    authority: RetentionAuthorityInspectionWireV1,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TrackingInspectionWireV1 {
    namespace: NamespaceName,
    generation: Digest,
    tracked_root: Option<TrackedRootInspectionWireV1>,
}

#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum NamespaceStatusKindWireV1 {
    NotFound,
    EnabledExact,
    EnabledModified,
    EnabledMissing,
    EnabledUnexpected,
    Disabled,
    Stale,
    IncompatibleOrCorrupt,
    RecoveryRequired,
}

#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum TargetStatusKindWireV1 {
    Exact,
    Modified,
    Missing,
    Unexpected,
    Stale,
    Incompatible,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct NamespaceStatusWireV1 {
    namespace: NamespaceName,
    head: Option<Digest>,
    lifecycle: Option<LifecycleStateWireV1>,
    desired_snapshot_digest: Option<Digest>,
    status: NamespaceStatusKindWireV1,
    targets: Vec<TargetStatusWireV1>,
    observed_bytes: u64,
    detail: Option<String>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TargetStatusWireV1 {
    authority: DeploymentName,
    relative_path: String,
    status: TargetStatusKindWireV1,
}

#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum FsckSeverityWireV1 {
    Error,
    Warning,
}

#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum FsckFindingCodeWireV1 {
    InvalidDescriptor,
    RecoveryRequired,
    InvalidJournal,
    MissingCatalog,
    InvalidCatalog,
    MissingGeneration,
    InvalidGeneration,
    CyclicHistory,
    CrossNamespaceHistory,
    SharedGeneration,
    MissingPreparedPlan,
    InvalidPreparedPlan,
    InvalidPreparedTransition,
    MissingArtifactBlob,
    CorruptArtifactBlob,
    ArtifactLengthMismatch,
    MissingPackObject,
    CorruptPackObject,
    MissingCanonicalObject,
    CorruptCanonicalObject,
    InvalidLockMetadata,
    InvalidStaging,
    MalformedStoreEntry,
    UnreachableImmutableObject,
    TargetDrift,
    TargetObservationFailed,
    AuthorityChanged,
    InvalidOwnership,
    TraversalLimitExceeded,
    DecodedByteLimitExceeded,
    FindingLimitExceeded,
}

#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum FsckStoreAreaWireV1 {
    Root,
    State,
    Generations,
    Prepared,
    Transactions,
    Objects,
    ArtifactBlobs,
    PackObjects,
    CanonicalFiles,
    CanonicalSymlinks,
    CanonicalTrees,
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum FsckSubjectWireV1 {
    StoreDescriptor {},
    TransactionLock {},
    MaintenanceLock {},
    Journal {},
    JournalStaging {},
    Catalog {},
    CatalogStaging {},
    Namespace {
        namespace: NamespaceName,
    },
    Generation {
        digest: Digest,
    },
    PreparedPlan {
        plan_id: PreparedId,
    },
    ArtifactBlob {
        digest: Digest,
    },
    PackObject {
        digest: Digest,
    },
    CanonicalFile {
        digest: Digest,
    },
    CanonicalSymlink {
        digest: Digest,
    },
    CanonicalTree {
        digest: Digest,
    },
    Target {
        authority: DeploymentName,
        relative_path: String,
    },
    StoreArea {
        area: FsckStoreAreaWireV1,
    },
    Retention {},
    Ownership {},
    Coverage {},
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FsckFindingWireV1 {
    code: FsckFindingCodeWireV1,
    severity: FsckSeverityWireV1,
    subject: FsckSubjectWireV1,
    detail: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FsckReportWireV1 {
    findings: Vec<FsckFindingWireV1>,
    checked_generations: u64,
    checked_prepared_plans: u64,
    checked_artifact_blobs: u64,
    checked_pack_objects: u64,
    checked_canonical_files: u64,
    checked_canonical_symlinks: u64,
    checked_canonical_trees: u64,
    checked_targets: u64,
    decoded_bytes: u64,
    observed_bytes: u64,
    findings_truncated: bool,
    complete: bool,
}

#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum LifecycleStateWireV1 {
    Enabled,
    Disabled,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TrackedRootInspectionWireV1 {
    moving_selector: String,
    applied_revision: String,
    root_tree_digest: Digest,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PreparedTrackingReviewWireV1 {
    source_locator: String,
    moving_selector: String,
    applied_revision: String,
    root_tree_digest: Digest,
    source_subdir: String,
    config_entry_point: String,
    selected_profile: ContributionName,
    target_authority: DeploymentName,
    acquisition_grants: Vec<PreparedTrackingAcquisitionGrantWireV1>,
    component_grants: Vec<Digest>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PreparedTrackingAcquisitionGrantWireV1 {
    kind: PreparedTrackingAcquisitionKindWireV1,
    locator: String,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum PreparedTrackingAcquisitionKindWireV1 {
    LocalSource,
    GitSource,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TransformProvenanceWireV1 {
    name: String,
    implementation: TransformImplementationWireV1,
    request_digest: Digest,
    document_digest: Digest,
    #[serde(deserialize_with = "deserialize_transform_resource_wires")]
    resources: Vec<TransformResourceWireV1>,
    response_digest: Digest,
    #[serde(deserialize_with = "deserialize_transform_diagnostic_wires")]
    diagnostics: Vec<TransformDiagnosticWireV1>,
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
enum TransformImplementationWireV1 {
    BuiltIn {
        implementation: String,
    },
    Component {
        pack_node_id: PackNodeId,
        pack_content_digest: Digest,
        component_path: String,
        component_digest: Digest,
        interface_version: String,
        execution_profile_digest: Digest,
    },
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TransformResourceWireV1 {
    name: String,
    digest: Digest,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum TransformDiagnosticSeverityWireV1 {
    Error,
    Warning,
    Info,
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum TransformDiagnosticLocationWireV1 {
    Source {
        authority_label: ContributionName,
        authority_identity: Digest,
        document_path: String,
        source_byte_len: u64,
        start: u32,
        end: u32,
    },
    Output {
        start: u64,
        end: u64,
    },
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TransformDiagnosticWireV1 {
    severity: TransformDiagnosticSeverityWireV1,
    code: String,
    message: String,
    primary: Option<TransformDiagnosticLocationWireV1>,
    #[serde(deserialize_with = "deserialize_transform_diagnostic_note_wires")]
    notes: Vec<String>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ArtifactDescriptorWireV1 {
    id: ArtifactId,
    digest: Digest,
    byte_len: u64,
    media_type: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyFindingWireV1 {
    id: Digest,
    code: String,
    message: String,
    approval_required: bool,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ArtifactWireV1 {
    descriptor: ArtifactDescriptorWireV1,
    bytes_hex: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ApplyOutcomeWireV1 {
    plan_id: PreparedId,
    namespace: NamespaceName,
    previous_head: Option<Digest>,
    head: Option<Digest>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StateViewWireV1 {
    namespace: NamespaceName,
    head: Option<Digest>,
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
enum RecoveryOutcomeWireV1 {
    NoTransaction {},
    Recovered {
        namespace: NamespaceName,
        head: Option<Digest>,
    },
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PruneOutcomeWireV1 {
    prepared_records: u64,
    artifact_blobs: u64,
    state_generations: u64,
    pack_objects: u64,
    canonical_files: u64,
    canonical_symlinks: u64,
    canonical_trees: u64,
}

#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum ErrorFrameTypeWireV1 {
    Error,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ErrorEnvelopeWireV1 {
    schema_version: u32,
    request_id: NullableRequestIdWire,
    sequence: u64,
    #[serde(rename = "type")]
    frame_type: ErrorFrameTypeWireV1,
    error: ErrorWireV1,
}

#[derive(Serialize, Deserialize)]
#[serde(untagged)]
enum NullableRequestIdWire {
    Id(String),
    Null(()),
}

impl NullableRequestIdWire {
    fn into_option(self) -> Option<String> {
        match self {
            Self::Id(request_id) => Some(request_id),
            Self::Null(()) => None,
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ErrorWireV1 {
    category: ErrorCategoryWireV1,
    code: ErrorCodeWireV1,
    message: String,
    details: ErrorDetailsWireV1,
    diagnostics: Vec<DiagnosticWireV1>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DiagnosticWireV1 {
    severity: DiagnosticSeverityWireV1,
    code: String,
    message: String,
}

/// Keep this enum literal. `rename_all` derives the frozen operation identifiers
/// from these variant names, so generation would hide the wire strings. The
/// conversions to and from `MachineOperationV1` remain explicit.
#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum OperationWireV1 {
    StoreStatus,
    InitializeStore,
    Prepare,
    Plan,
    Artifact,
    Commit,
    State,
    Recover,
    Prune,
    Checkout,
    Disable,
    Enable,
    RemoveNamespace,
    SetHistoryRetention,
    Pin,
    Unpin,
    AddRestorePoint,
    DropRestorePoint,
    Catalog,
    Namespace,
    History,
    Generation,
    DesiredSnapshot,
    CanonicalTree,
    ArtifactMetadata,
    CapturedInputs,
    TransformProvenance,
    Retention,
    Tracking,
    Status,
    Fsck,
}

#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum PrepareInputKindWireV1 {
    Source,
    Config,
    Lock,
    Component,
    Asset,
    Other,
}

#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum StoreStatusWireV1 {
    Absent,
    Uninitialized,
    Ready,
}

#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum DiagnosticSeverityWireV1 {
    Error,
    Warning,
    Notice,
}

#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum ErrorCategoryWireV1 {
    InvalidRequest,
    Unsupported,
    NotFound,
    PermissionDenied,
    Conflict,
    ResourceLimit,
    Unavailable,
    Internal,
}

#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum ErrorCodeWireV1 {
    MalformedJson,
    InvalidRequest,
    UnsupportedMachineVersion,
    FrameResourceLimit,
    ReadOnlyStore,
    StoreNotReady,
    StateParentMissing,
    UnsafeDirectory,
    RootObservationChanged,
    StateParentObservationChanged,
    MalformedStoreMetadata,
    UnsupportedStoreVersion,
    StoreIo,
    PlanNotFound,
    ArtifactNotFound,
    ApprovalMismatch,
    StalePlan,
    RecoveryRequired,
    OperationBusy,
    InvalidDeployment,
    UnsafeTarget,
    CorruptStore,
    CorruptArtifact,
    DeploymentIo,
    InternalEngineError,
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
enum ErrorDetailsWireV1 {
    None {},
    CurrentStatus {
        status: StoreStatusWireV1,
    },
    UnsafeDirectory {
        directory: StoreDirectoryWireV1,
        reason: DirectorySafetyWireV1,
    },
    RootObservation {
        root: StoreRootWireV1,
    },
    StoreMetadata {
        reason: StoreMetadataWireV1,
    },
    UnsupportedSchema {
        schema: SchemaFamilyWireV1,
        expected: u32,
        found: u32,
    },
}

#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum StoreDirectoryWireV1 {
    StateParent,
    V1Root,
}

#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum DirectorySafetyWireV1 {
    WrongOwner,
    GroupOrOtherWritable,
    SpecialModeBitsSet,
    UnexpectedMode,
    AncestryLimitExceeded,
}

#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum StoreRootWireV1 {
    V1,
}

#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum StoreMetadataWireV1 {
    MarkerMissingWithOtherEntries,
    MarkerNotRegular,
    MarkerTooLarge,
    UnexpectedRootEntry,
    InvalidRootEntry,
    WrongOwner,
    UnexpectedMode,
    MultipleLinks,
    ObservationChanged,
    InvalidDescriptor,
}

#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum SchemaFamilyWireV1 {
    Machine,
    Store,
}

fn request_to_wire(request: &MachineRequestV1) -> Result<RequestWireV1, MachineValidationError> {
    Ok(match request {
        MachineRequestV1::StoreStatus => RequestWireV1::StoreStatus {},
        MachineRequestV1::InitializeStore => RequestWireV1::InitializeStore {},
        MachineRequestV1::Prepare(request) => {
            if !request.transforms().is_empty() {
                return Err(MachineValidationError::UnsupportedRequest(
                    "transform provenance can be generated only by Engine",
                ));
            }
            RequestWireV1::Prepare {
                namespace: request.namespace().clone(),
                expected_head: request.expected_head().cloned(),
                graph_digest: request.graph_digest().clone(),
                inputs: request.inputs().iter().map(input_to_wire).collect(),
                artifacts: request
                    .artifacts()
                    .iter()
                    .map(prepare_artifact_to_wire)
                    .collect(),
                findings: request
                    .findings()
                    .iter()
                    .map(finding_request_to_wire)
                    .collect(),
                operations: request
                    .operations()
                    .iter()
                    .map(operation_request_to_wire)
                    .collect(),
            }
        }
        MachineRequestV1::Plan(plan_id) => RequestWireV1::Plan {
            plan_id: plan_id.clone(),
        },
        MachineRequestV1::Artifact {
            plan_id,
            artifact_id,
        } => RequestWireV1::Artifact {
            plan_id: plan_id.clone(),
            artifact_id: artifact_id.clone(),
        },
        MachineRequestV1::Commit(request) => RequestWireV1::Commit {
            plan_id: request.plan_id().clone(),
            approval_digest: request.approval().findings_digest().clone(),
        },
        MachineRequestV1::State(namespace) => RequestWireV1::State {
            namespace: namespace.clone(),
        },
        MachineRequestV1::Recover => RequestWireV1::Recover {},
        MachineRequestV1::Prune(request) => RequestWireV1::Prune {
            plan_ids: request.plan_ids().to_vec(),
        },
        MachineRequestV1::Checkout(request) => RequestWireV1::Checkout {
            namespace: request.namespace().clone(),
            target_generation: request.target_generation().clone(),
        },
        MachineRequestV1::Disable(request) => RequestWireV1::Disable {
            namespace: request.namespace().clone(),
        },
        MachineRequestV1::Enable(request) => RequestWireV1::Enable {
            namespace: request.namespace().clone(),
        },
        MachineRequestV1::RemoveNamespace(request) => RequestWireV1::RemoveNamespace {
            namespace: request.namespace().clone(),
            history: match request.history() {
                NamespaceRemovalHistoryV1::Drop => NamespaceRemovalHistoryWireV1::Drop,
            },
        },
        MachineRequestV1::SetHistoryRetention(request) => RequestWireV1::SetHistoryRetention {
            namespace: request.namespace().clone(),
            generations: request.generations(),
        },
        MachineRequestV1::Pin(request) => RequestWireV1::Pin {
            namespace: request.namespace().clone(),
            object: retention_object_to_wire(request.object()),
        },
        MachineRequestV1::Unpin(request) => RequestWireV1::Unpin {
            namespace: request.namespace().clone(),
            object: retention_object_to_wire(request.object()),
        },
        MachineRequestV1::AddRestorePoint(request) => RequestWireV1::AddRestorePoint {
            namespace: request.namespace().clone(),
            generation: request.generation().clone(),
        },
        MachineRequestV1::DropRestorePoint(request) => RequestWireV1::DropRestorePoint {
            namespace: request.namespace().clone(),
            generation: request.generation().clone(),
        },
        MachineRequestV1::Catalog(request) => RequestWireV1::Catalog {
            max_namespaces: machine_item_limit(request.max_namespaces())?,
            max_decoded_bytes: request.max_decoded_bytes(),
        },
        MachineRequestV1::Namespace(request) => RequestWireV1::Namespace {
            namespace: request.namespace().clone(),
            max_decoded_bytes: request.max_decoded_bytes(),
        },
        MachineRequestV1::History(request) => RequestWireV1::History {
            namespace: request.namespace().clone(),
            max_generations: machine_item_limit(request.max_generations())?,
            max_decoded_bytes: request.max_decoded_bytes(),
        },
        MachineRequestV1::Generation(request) => RequestWireV1::Generation {
            namespace: request.namespace().clone(),
            generation: request.generation().clone(),
            max_generations: machine_item_limit(request.max_generations())?,
            max_decoded_bytes: request.max_decoded_bytes(),
        },
        MachineRequestV1::DesiredSnapshot(request) => RequestWireV1::DesiredSnapshot {
            namespace: request.namespace().clone(),
            generation: request.generation().clone(),
            max_targets: machine_item_limit(request.max_targets())?,
            max_decoded_bytes: request.max_decoded_bytes(),
        },
        MachineRequestV1::CanonicalTree(request) => RequestWireV1::CanonicalTree {
            tree: request.tree().clone(),
            max_entries: machine_item_limit(request.max_entries())?,
            max_decoded_bytes: request.max_decoded_bytes(),
        },
        MachineRequestV1::ArtifactMetadata(request) => RequestWireV1::ArtifactMetadata {
            plan_id: request.plan_id().clone(),
            artifact_id: request.artifact_id().clone(),
            max_decoded_bytes: request.max_decoded_bytes(),
        },
        MachineRequestV1::CapturedInputs(request) => RequestWireV1::CapturedInputs {
            plan_id: request.plan_id().clone(),
            max_items: machine_item_limit(request.max_items())?,
            max_decoded_bytes: request.max_decoded_bytes(),
        },
        MachineRequestV1::TransformProvenance(request) => RequestWireV1::TransformProvenance {
            plan_id: request.plan_id().clone(),
            max_items: machine_item_limit(request.max_items())?,
            max_decoded_bytes: request.max_decoded_bytes(),
        },
        MachineRequestV1::Retention(request) => RequestWireV1::Retention {
            namespace: request.namespace().clone(),
            generation: request.generation().clone(),
            max_generations: machine_item_limit(request.max_generations())?,
            max_decoded_bytes: request.max_decoded_bytes(),
        },
        MachineRequestV1::Tracking(request) => RequestWireV1::Tracking {
            namespace: request.namespace().clone(),
            generation: request.generation().clone(),
            max_generations: machine_item_limit(request.max_generations())?,
            max_decoded_bytes: request.max_decoded_bytes(),
        },
        MachineRequestV1::Status(request) => RequestWireV1::Status {
            namespace: request.namespace().clone(),
            max_targets: machine_item_limit(request.max_targets())?,
            max_observed_bytes: request.max_observed_bytes(),
        },
        MachineRequestV1::Fsck(request) => RequestWireV1::Fsck {
            max_findings: machine_item_limit(request.max_findings())?,
            max_objects: malm_types::usize_to_u64(request.max_objects()),
            max_decoded_bytes: request.max_decoded_bytes(),
            observe_targets: request.observes_targets(),
            max_target_observations: if request.observes_targets() {
                machine_item_limit(request.max_target_observations())?
            } else {
                malm_types::usize_to_u64(MAX_MACHINE_ARRAY_ITEMS)
            },
            max_observed_bytes: request.max_observed_bytes(),
        },
    })
}

fn request_from_wire(request: RequestWireV1) -> Result<MachineRequestV1, MachineReadError> {
    Ok(match request {
        RequestWireV1::StoreStatus {} => MachineRequestV1::StoreStatus,
        RequestWireV1::InitializeStore {} => MachineRequestV1::InitializeStore,
        RequestWireV1::Prepare {
            namespace,
            expected_head,
            graph_digest,
            inputs,
            artifacts,
            findings,
            operations,
        } => MachineRequestV1::Prepare(PrepareRequestV1::from(PrepareRequestPartsV1 {
            namespace,
            expected_head,
            graph_digest,
            inputs: inputs
                .into_iter()
                .map(input_from_wire)
                .collect::<Result<_, _>>()?,
            artifacts: artifacts
                .into_iter()
                .map(prepare_artifact_from_wire)
                .collect::<Result<_, _>>()?,
            transforms: Vec::new(),
            findings: findings
                .into_iter()
                .map(finding_request_from_wire)
                .collect::<Result<_, _>>()?,
            operations: operations
                .into_iter()
                .map(operation_request_from_wire)
                .collect::<Result<_, _>>()?,
        })),
        RequestWireV1::Plan { plan_id } => MachineRequestV1::Plan(plan_id),
        RequestWireV1::Artifact {
            plan_id,
            artifact_id,
        } => MachineRequestV1::Artifact {
            plan_id,
            artifact_id,
        },
        RequestWireV1::Commit {
            plan_id,
            approval_digest,
        } => MachineRequestV1::Commit(CommitRequestV1::new(
            plan_id.clone(),
            ApprovalV1::new(plan_id, approval_digest),
        )),
        RequestWireV1::State { namespace } => MachineRequestV1::State(namespace),
        RequestWireV1::Recover {} => MachineRequestV1::Recover,
        RequestWireV1::Prune { plan_ids } => MachineRequestV1::Prune(PruneRequestV1::new(plan_ids)),
        RequestWireV1::Checkout {
            namespace,
            target_generation,
        } => MachineRequestV1::Checkout(CheckoutRequestV1::new(namespace, target_generation)),
        RequestWireV1::Disable { namespace } => {
            MachineRequestV1::Disable(LifecycleRequestV1::new(namespace))
        }
        RequestWireV1::Enable { namespace } => {
            MachineRequestV1::Enable(LifecycleRequestV1::new(namespace))
        }
        RequestWireV1::RemoveNamespace { namespace, history } => {
            MachineRequestV1::RemoveNamespace(NamespaceRemovalRequestV1::new(
                namespace,
                match history {
                    NamespaceRemovalHistoryWireV1::Drop => NamespaceRemovalHistoryV1::Drop,
                },
            ))
        }
        RequestWireV1::SetHistoryRetention {
            namespace,
            generations,
        } => MachineRequestV1::SetHistoryRetention(
            HistoryRetentionRequestV1::new(namespace, generations)
                .map_err(inspection_read_error)?,
        ),
        RequestWireV1::Pin { namespace, object } => MachineRequestV1::Pin(
            RetentionPinRequestV1::new(namespace, retention_object_from_wire(object)),
        ),
        RequestWireV1::Unpin { namespace, object } => MachineRequestV1::Unpin(
            RetentionPinRequestV1::new(namespace, retention_object_from_wire(object)),
        ),
        RequestWireV1::AddRestorePoint {
            namespace,
            generation,
        } => MachineRequestV1::AddRestorePoint(RestorePointRequestV1::new(namespace, generation)),
        RequestWireV1::DropRestorePoint {
            namespace,
            generation,
        } => MachineRequestV1::DropRestorePoint(RestorePointRequestV1::new(namespace, generation)),
        RequestWireV1::Catalog {
            max_namespaces,
            max_decoded_bytes,
        } => MachineRequestV1::Catalog(
            CatalogInspectionRequestV1::with_limits(
                machine_wire_items(max_namespaces)?,
                max_decoded_bytes,
            )
            .map_err(inspection_read_error)?,
        ),
        RequestWireV1::Namespace {
            namespace,
            max_decoded_bytes,
        } => MachineRequestV1::Namespace(
            NamespaceInspectionRequestV1::with_limit(namespace, max_decoded_bytes)
                .map_err(inspection_read_error)?,
        ),
        RequestWireV1::History {
            namespace,
            max_generations,
            max_decoded_bytes,
        } => MachineRequestV1::History(
            NamespaceHistoryRequestV1::with_limits(
                namespace,
                machine_wire_items(max_generations)?,
                max_decoded_bytes,
            )
            .map_err(inspection_read_error)?,
        ),
        RequestWireV1::Generation {
            namespace,
            generation,
            max_generations,
            max_decoded_bytes,
        } => MachineRequestV1::Generation(
            GenerationInspectionRequestV1::with_limits(
                namespace,
                generation,
                machine_wire_items(max_generations)?,
                max_decoded_bytes,
            )
            .map_err(inspection_read_error)?,
        ),
        RequestWireV1::DesiredSnapshot {
            namespace,
            generation,
            max_targets,
            max_decoded_bytes,
        } => MachineRequestV1::DesiredSnapshot(
            DesiredSnapshotInspectionRequestV1::with_limits(
                namespace,
                generation,
                machine_wire_items(max_targets)?,
                max_decoded_bytes,
            )
            .map_err(inspection_read_error)?,
        ),
        RequestWireV1::CanonicalTree {
            tree,
            max_entries,
            max_decoded_bytes,
        } => MachineRequestV1::CanonicalTree(
            CanonicalTreeInspectionRequestV1::with_limits(
                tree,
                machine_wire_items(max_entries)?,
                max_decoded_bytes,
            )
            .map_err(inspection_read_error)?,
        ),
        RequestWireV1::ArtifactMetadata {
            plan_id,
            artifact_id,
            max_decoded_bytes,
        } => MachineRequestV1::ArtifactMetadata(
            ArtifactMetadataInspectionRequestV1::with_limit(
                plan_id,
                artifact_id,
                max_decoded_bytes,
            )
            .map_err(inspection_read_error)?,
        ),
        RequestWireV1::CapturedInputs {
            plan_id,
            max_items,
            max_decoded_bytes,
        } => MachineRequestV1::CapturedInputs(
            PreparedPlanInspectionRequestV1::with_limits(
                plan_id,
                machine_wire_items(max_items)?,
                max_decoded_bytes,
            )
            .map_err(inspection_read_error)?,
        ),
        RequestWireV1::TransformProvenance {
            plan_id,
            max_items,
            max_decoded_bytes,
        } => MachineRequestV1::TransformProvenance(
            PreparedPlanInspectionRequestV1::with_limits(
                plan_id,
                machine_wire_items(max_items)?,
                max_decoded_bytes,
            )
            .map_err(inspection_read_error)?,
        ),
        RequestWireV1::Retention {
            namespace,
            generation,
            max_generations,
            max_decoded_bytes,
        } => MachineRequestV1::Retention(
            GenerationInspectionRequestV1::with_limits(
                namespace,
                generation,
                machine_wire_items(max_generations)?,
                max_decoded_bytes,
            )
            .map_err(inspection_read_error)?,
        ),
        RequestWireV1::Tracking {
            namespace,
            generation,
            max_generations,
            max_decoded_bytes,
        } => MachineRequestV1::Tracking(
            GenerationInspectionRequestV1::with_limits(
                namespace,
                generation,
                machine_wire_items(max_generations)?,
                max_decoded_bytes,
            )
            .map_err(inspection_read_error)?,
        ),
        RequestWireV1::Status {
            namespace,
            max_targets,
            max_observed_bytes,
        } => MachineRequestV1::Status(
            NamespaceStatusRequestV1::with_limits(
                namespace,
                machine_wire_items(max_targets)?,
                max_observed_bytes,
            )
            .map_err(inspection_read_error)?,
        ),
        RequestWireV1::Fsck {
            max_findings,
            max_objects,
            max_decoded_bytes,
            observe_targets,
            max_target_observations,
            max_observed_bytes,
        } => {
            let request = FsckRequestV1::with_limits(
                machine_wire_items(max_findings)?,
                usize::try_from(max_objects).map_err(|_| {
                    MachineReadError::InvalidEnvelope(
                        "fsck object limit does not fit this platform".to_owned(),
                    )
                })?,
                max_decoded_bytes,
            )
            .map_err(inspection_read_error)?;
            MachineRequestV1::Fsck(if observe_targets {
                request
                    .with_target_observations(
                        machine_wire_items(max_target_observations)?,
                        max_observed_bytes,
                    )
                    .map_err(inspection_read_error)?
            } else {
                request
            })
        }
    })
}

fn machine_item_limit(value: usize) -> Result<u64, MachineValidationError> {
    if value == 0 {
        return Err(MachineValidationError::UnsupportedRequest(
            "inspection item limit must be positive",
        ));
    }
    if value > MAX_MACHINE_ARRAY_ITEMS {
        return Err(MachineValidationError::UnsupportedRequest(
            "inspection item limit exceeds the machine/v1 array limit",
        ));
    }
    Ok(malm_types::usize_to_u64(value))
}

fn machine_wire_items(value: u64) -> Result<usize, MachineReadError> {
    let value = usize::try_from(value).map_err(|_| {
        MachineReadError::InvalidEnvelope(
            "inspection item limit does not fit this platform".to_owned(),
        )
    })?;
    if value == 0 {
        return Err(MachineReadError::InvalidEnvelope(
            "inspection item limit must be positive".to_owned(),
        ));
    }
    if value > MAX_MACHINE_ARRAY_ITEMS {
        return Err(MachineReadError::InvalidEnvelope(
            "inspection item limit exceeds the machine/v1 array limit".to_owned(),
        ));
    }
    Ok(value)
}

fn inspection_read_error(error: malm_types::InspectionDtoError) -> MachineReadError {
    MachineReadError::InvalidEnvelope(error.to_string())
}

fn retention_object_to_wire(object: &RetentionObjectV1) -> RetentionObjectWireV1 {
    match object {
        RetentionObjectV1::PreparedPlan { plan_id } => RetentionObjectWireV1::PreparedPlan {
            plan_id: plan_id.clone(),
        },
        RetentionObjectV1::StateGeneration { digest } => RetentionObjectWireV1::StateGeneration {
            digest: digest.clone(),
        },
        RetentionObjectV1::ArtifactBlob { digest } => RetentionObjectWireV1::ArtifactBlob {
            digest: digest.clone(),
        },
        RetentionObjectV1::PackObject { digest } => RetentionObjectWireV1::PackObject {
            digest: digest.clone(),
        },
        RetentionObjectV1::CanonicalFile { digest } => RetentionObjectWireV1::CanonicalFile {
            digest: digest.clone(),
        },
        RetentionObjectV1::CanonicalSymlink { digest } => RetentionObjectWireV1::CanonicalSymlink {
            digest: digest.clone(),
        },
        RetentionObjectV1::CanonicalTree { digest } => RetentionObjectWireV1::CanonicalTree {
            digest: digest.clone(),
        },
    }
}

fn retention_object_from_wire(object: RetentionObjectWireV1) -> RetentionObjectV1 {
    match object {
        RetentionObjectWireV1::PreparedPlan { plan_id } => {
            RetentionObjectV1::PreparedPlan { plan_id }
        }
        RetentionObjectWireV1::StateGeneration { digest } => {
            RetentionObjectV1::StateGeneration { digest }
        }
        RetentionObjectWireV1::ArtifactBlob { digest } => {
            RetentionObjectV1::ArtifactBlob { digest }
        }
        RetentionObjectWireV1::PackObject { digest } => RetentionObjectV1::PackObject { digest },
        RetentionObjectWireV1::CanonicalFile { digest } => {
            RetentionObjectV1::CanonicalFile { digest }
        }
        RetentionObjectWireV1::CanonicalSymlink { digest } => {
            RetentionObjectV1::CanonicalSymlink { digest }
        }
        RetentionObjectWireV1::CanonicalTree { digest } => {
            RetentionObjectV1::CanonicalTree { digest }
        }
    }
}

const fn operation_to_wire(operation: MachineOperationV1) -> OperationWireV1 {
    match operation {
        MachineOperationV1::StoreStatus => OperationWireV1::StoreStatus,
        MachineOperationV1::InitializeStore => OperationWireV1::InitializeStore,
        MachineOperationV1::Prepare => OperationWireV1::Prepare,
        MachineOperationV1::Plan => OperationWireV1::Plan,
        MachineOperationV1::Artifact => OperationWireV1::Artifact,
        MachineOperationV1::Commit => OperationWireV1::Commit,
        MachineOperationV1::State => OperationWireV1::State,
        MachineOperationV1::Recover => OperationWireV1::Recover,
        MachineOperationV1::Prune => OperationWireV1::Prune,
        MachineOperationV1::Checkout => OperationWireV1::Checkout,
        MachineOperationV1::Disable => OperationWireV1::Disable,
        MachineOperationV1::Enable => OperationWireV1::Enable,
        MachineOperationV1::RemoveNamespace => OperationWireV1::RemoveNamespace,
        MachineOperationV1::SetHistoryRetention => OperationWireV1::SetHistoryRetention,
        MachineOperationV1::Pin => OperationWireV1::Pin,
        MachineOperationV1::Unpin => OperationWireV1::Unpin,
        MachineOperationV1::AddRestorePoint => OperationWireV1::AddRestorePoint,
        MachineOperationV1::DropRestorePoint => OperationWireV1::DropRestorePoint,
        MachineOperationV1::Catalog => OperationWireV1::Catalog,
        MachineOperationV1::Namespace => OperationWireV1::Namespace,
        MachineOperationV1::History => OperationWireV1::History,
        MachineOperationV1::Generation => OperationWireV1::Generation,
        MachineOperationV1::DesiredSnapshot => OperationWireV1::DesiredSnapshot,
        MachineOperationV1::CanonicalTree => OperationWireV1::CanonicalTree,
        MachineOperationV1::ArtifactMetadata => OperationWireV1::ArtifactMetadata,
        MachineOperationV1::CapturedInputs => OperationWireV1::CapturedInputs,
        MachineOperationV1::TransformProvenance => OperationWireV1::TransformProvenance,
        MachineOperationV1::Retention => OperationWireV1::Retention,
        MachineOperationV1::Tracking => OperationWireV1::Tracking,
        MachineOperationV1::Status => OperationWireV1::Status,
        MachineOperationV1::Fsck => OperationWireV1::Fsck,
    }
}

const fn operation_from_wire(operation: OperationWireV1) -> MachineOperationV1 {
    match operation {
        OperationWireV1::StoreStatus => MachineOperationV1::StoreStatus,
        OperationWireV1::InitializeStore => MachineOperationV1::InitializeStore,
        OperationWireV1::Prepare => MachineOperationV1::Prepare,
        OperationWireV1::Plan => MachineOperationV1::Plan,
        OperationWireV1::Artifact => MachineOperationV1::Artifact,
        OperationWireV1::Commit => MachineOperationV1::Commit,
        OperationWireV1::State => MachineOperationV1::State,
        OperationWireV1::Recover => MachineOperationV1::Recover,
        OperationWireV1::Prune => MachineOperationV1::Prune,
        OperationWireV1::Checkout => MachineOperationV1::Checkout,
        OperationWireV1::Disable => MachineOperationV1::Disable,
        OperationWireV1::Enable => MachineOperationV1::Enable,
        OperationWireV1::RemoveNamespace => MachineOperationV1::RemoveNamespace,
        OperationWireV1::SetHistoryRetention => MachineOperationV1::SetHistoryRetention,
        OperationWireV1::Pin => MachineOperationV1::Pin,
        OperationWireV1::Unpin => MachineOperationV1::Unpin,
        OperationWireV1::AddRestorePoint => MachineOperationV1::AddRestorePoint,
        OperationWireV1::DropRestorePoint => MachineOperationV1::DropRestorePoint,
        OperationWireV1::Catalog => MachineOperationV1::Catalog,
        OperationWireV1::Namespace => MachineOperationV1::Namespace,
        OperationWireV1::History => MachineOperationV1::History,
        OperationWireV1::Generation => MachineOperationV1::Generation,
        OperationWireV1::DesiredSnapshot => MachineOperationV1::DesiredSnapshot,
        OperationWireV1::CanonicalTree => MachineOperationV1::CanonicalTree,
        OperationWireV1::ArtifactMetadata => MachineOperationV1::ArtifactMetadata,
        OperationWireV1::CapturedInputs => MachineOperationV1::CapturedInputs,
        OperationWireV1::TransformProvenance => MachineOperationV1::TransformProvenance,
        OperationWireV1::Retention => MachineOperationV1::Retention,
        OperationWireV1::Tracking => MachineOperationV1::Tracking,
        OperationWireV1::Status => MachineOperationV1::Status,
        OperationWireV1::Fsck => MachineOperationV1::Fsck,
    }
}

/// Returns the prepared deployment carried by a result, if any.
///
/// The exhaustive match defines which results require policy review, so a new
/// result variant cannot silently skip that decision.
const fn reviewed_deployment(result: &MachineResultV1) -> Option<&PreparedDeploymentV1> {
    match result {
        MachineResultV1::StoreStatus(_) => None,
        MachineResultV1::InitializeStore => None,
        MachineResultV1::Prepare(deployment) => Some(deployment),
        MachineResultV1::Plan(deployment) => Some(deployment),
        MachineResultV1::Artifact(_) => None,
        MachineResultV1::Commit(_) => None,
        MachineResultV1::State(_) => None,
        MachineResultV1::Recover(_) => None,
        MachineResultV1::Prune(_) => None,
        MachineResultV1::Checkout(deployment) => Some(deployment),
        MachineResultV1::Disable(deployment) => Some(deployment),
        MachineResultV1::Enable(deployment) => Some(deployment),
        MachineResultV1::RemoveNamespace(deployment) => Some(deployment),
        MachineResultV1::SetHistoryRetention(deployment) => Some(deployment),
        MachineResultV1::Pin(deployment) => Some(deployment),
        MachineResultV1::Unpin(deployment) => Some(deployment),
        MachineResultV1::AddRestorePoint(deployment) => Some(deployment),
        MachineResultV1::DropRestorePoint(deployment) => Some(deployment),
        MachineResultV1::Catalog(_) => None,
        MachineResultV1::Namespace(_) => None,
        MachineResultV1::History(_) => None,
        MachineResultV1::Generation(_) => None,
        MachineResultV1::DesiredSnapshot(_) => None,
        MachineResultV1::CanonicalTree(_) => None,
        MachineResultV1::ArtifactMetadata(_) => None,
        MachineResultV1::CapturedInputs(_) => None,
        MachineResultV1::TransformProvenance(_) => None,
        MachineResultV1::Retention(_) => None,
        MachineResultV1::Tracking(_) => None,
        MachineResultV1::Status(_) => None,
        MachineResultV1::Fsck(_) => None,
    }
}

/// Converts a semantic result to its frozen wire shape.
///
/// Each arm names the exact `ResultWireV1` field for its payload.
/// `InitializeStore` has no semantic payload but must report ready status on
/// the wire, so it is handled explicitly first.
fn result_to_wire(result: &MachineResultV1) -> ResultWireV1 {
    match result {
        MachineResultV1::InitializeStore => ResultWireV1::InitializeStore {
            status: StoreStatusWireV1::Ready,
        },
        MachineResultV1::StoreStatus(payload) => ResultWireV1::StoreStatus {
            status: status_to_wire(*payload),
        },
        MachineResultV1::Prepare(payload) => ResultWireV1::Prepare {
            deployment: prepared_to_wire(payload),
        },
        MachineResultV1::Plan(payload) => ResultWireV1::Plan {
            deployment: prepared_to_wire(payload),
        },
        MachineResultV1::Artifact(payload) => ResultWireV1::Artifact {
            artifact: artifact_to_wire(payload),
        },
        MachineResultV1::Commit(payload) => ResultWireV1::Commit {
            outcome: apply_outcome_to_wire(payload),
        },
        MachineResultV1::State(payload) => ResultWireV1::State {
            state: state_to_wire(payload),
        },
        MachineResultV1::Recover(payload) => ResultWireV1::Recover {
            outcome: recovery_to_wire(payload),
        },
        MachineResultV1::Prune(payload) => ResultWireV1::Prune {
            outcome: prune_to_wire(*payload),
        },
        MachineResultV1::Checkout(payload) => ResultWireV1::Checkout {
            deployment: prepared_to_wire(payload),
        },
        MachineResultV1::Disable(payload) => ResultWireV1::Disable {
            deployment: prepared_to_wire(payload),
        },
        MachineResultV1::Enable(payload) => ResultWireV1::Enable {
            deployment: prepared_to_wire(payload),
        },
        MachineResultV1::RemoveNamespace(payload) => ResultWireV1::RemoveNamespace {
            deployment: prepared_to_wire(payload),
        },
        MachineResultV1::SetHistoryRetention(payload) => ResultWireV1::SetHistoryRetention {
            deployment: prepared_to_wire(payload),
        },
        MachineResultV1::Pin(payload) => ResultWireV1::Pin {
            deployment: prepared_to_wire(payload),
        },
        MachineResultV1::Unpin(payload) => ResultWireV1::Unpin {
            deployment: prepared_to_wire(payload),
        },
        MachineResultV1::AddRestorePoint(payload) => ResultWireV1::AddRestorePoint {
            deployment: prepared_to_wire(payload),
        },
        MachineResultV1::DropRestorePoint(payload) => ResultWireV1::DropRestorePoint {
            deployment: prepared_to_wire(payload),
        },
        MachineResultV1::Catalog(payload) => ResultWireV1::Catalog {
            catalog: catalog_to_wire(payload),
        },
        MachineResultV1::Namespace(payload) => ResultWireV1::Namespace {
            namespace: namespace_to_wire(payload),
        },
        MachineResultV1::History(payload) => ResultWireV1::History {
            history: history_to_wire(payload),
        },
        MachineResultV1::Generation(payload) => ResultWireV1::Generation {
            generation: generation_to_wire(payload),
        },
        MachineResultV1::DesiredSnapshot(payload) => ResultWireV1::DesiredSnapshot {
            snapshot: desired_snapshot_to_wire(payload),
        },
        MachineResultV1::CanonicalTree(payload) => ResultWireV1::CanonicalTree {
            tree: canonical_tree_to_wire(payload),
        },
        MachineResultV1::ArtifactMetadata(payload) => ResultWireV1::ArtifactMetadata {
            artifact: artifact_metadata_to_wire(payload),
        },
        MachineResultV1::CapturedInputs(payload) => ResultWireV1::CapturedInputs {
            inputs: captured_inputs_to_wire(payload),
        },
        MachineResultV1::TransformProvenance(payload) => ResultWireV1::TransformProvenance {
            provenance: transform_inspection_to_wire(payload),
        },
        MachineResultV1::Retention(payload) => ResultWireV1::Retention {
            retention: retention_to_wire(payload),
        },
        MachineResultV1::Tracking(payload) => ResultWireV1::Tracking {
            tracking: tracking_to_wire(payload),
        },
        MachineResultV1::Status(payload) => ResultWireV1::Status {
            status: namespace_status_to_wire(payload),
        },
        MachineResultV1::Fsck(payload) => ResultWireV1::Fsck {
            report: fsck_to_wire(payload),
        },
    }
}

/// Converts a frozen wire result to its semantic shape.
///
/// This is the exact inverse of `result_to_wire`, with arms in the same order.
/// `InitializeStore` is the only case that can reject its input because a
/// successful initialization must report the store as ready.
fn result_from_wire(result: ResultWireV1) -> Result<MachineResultV1, MachineReadError> {
    match result {
        ResultWireV1::InitializeStore {
            status: StoreStatusWireV1::Ready,
        } => Ok(MachineResultV1::InitializeStore),
        ResultWireV1::InitializeStore { .. } => Err(MachineReadError::InvalidEnvelope(
            "successful initialize_store result must report ready".to_owned(),
        )),
        ResultWireV1::StoreStatus { status } => {
            Ok(MachineResultV1::StoreStatus(status_from_wire(status)))
        }
        ResultWireV1::Prepare { deployment } => {
            Ok(MachineResultV1::Prepare(prepared_from_wire(deployment)?))
        }
        ResultWireV1::Plan { deployment } => {
            Ok(MachineResultV1::Plan(prepared_from_wire(deployment)?))
        }
        ResultWireV1::Artifact { artifact } => {
            Ok(MachineResultV1::Artifact(artifact_from_wire(artifact)?))
        }
        ResultWireV1::Commit { outcome } => {
            Ok(MachineResultV1::Commit(apply_outcome_from_wire(outcome)?))
        }
        ResultWireV1::State { state } => Ok(MachineResultV1::State(state_from_wire(state))),
        ResultWireV1::Recover { outcome } => {
            Ok(MachineResultV1::Recover(recovery_from_wire(outcome)))
        }
        ResultWireV1::Prune { outcome } => Ok(MachineResultV1::Prune(prune_from_wire(outcome))),
        ResultWireV1::Checkout { deployment } => {
            Ok(MachineResultV1::Checkout(prepared_from_wire(deployment)?))
        }
        ResultWireV1::Disable { deployment } => {
            Ok(MachineResultV1::Disable(prepared_from_wire(deployment)?))
        }
        ResultWireV1::Enable { deployment } => {
            Ok(MachineResultV1::Enable(prepared_from_wire(deployment)?))
        }
        ResultWireV1::RemoveNamespace { deployment } => Ok(MachineResultV1::RemoveNamespace(
            prepared_from_wire(deployment)?,
        )),
        ResultWireV1::SetHistoryRetention { deployment } => Ok(
            MachineResultV1::SetHistoryRetention(prepared_from_wire(deployment)?),
        ),
        ResultWireV1::Pin { deployment } => {
            Ok(MachineResultV1::Pin(prepared_from_wire(deployment)?))
        }
        ResultWireV1::Unpin { deployment } => {
            Ok(MachineResultV1::Unpin(prepared_from_wire(deployment)?))
        }
        ResultWireV1::AddRestorePoint { deployment } => Ok(MachineResultV1::AddRestorePoint(
            prepared_from_wire(deployment)?,
        )),
        ResultWireV1::DropRestorePoint { deployment } => Ok(MachineResultV1::DropRestorePoint(
            prepared_from_wire(deployment)?,
        )),
        ResultWireV1::Catalog { catalog } => {
            Ok(MachineResultV1::Catalog(catalog_from_wire(catalog)))
        }
        ResultWireV1::Namespace { namespace } => {
            Ok(MachineResultV1::Namespace(namespace_from_wire(namespace)?))
        }
        ResultWireV1::History { history } => {
            Ok(MachineResultV1::History(history_from_wire(history)?))
        }
        ResultWireV1::Generation { generation } => Ok(MachineResultV1::Generation(
            generation_from_wire(generation)?,
        )),
        ResultWireV1::DesiredSnapshot { snapshot } => Ok(MachineResultV1::DesiredSnapshot(
            desired_snapshot_from_wire(snapshot)?,
        )),
        ResultWireV1::CanonicalTree { tree } => Ok(MachineResultV1::CanonicalTree(
            canonical_tree_from_wire(tree),
        )),
        ResultWireV1::ArtifactMetadata { artifact } => Ok(MachineResultV1::ArtifactMetadata(
            artifact_metadata_from_wire(artifact)?,
        )),
        ResultWireV1::CapturedInputs { inputs } => Ok(MachineResultV1::CapturedInputs(
            captured_inputs_from_wire(inputs)?,
        )),
        ResultWireV1::TransformProvenance { provenance } => Ok(
            MachineResultV1::TransformProvenance(transform_inspection_from_wire(provenance)?),
        ),
        ResultWireV1::Retention { retention } => {
            Ok(MachineResultV1::Retention(retention_from_wire(retention)?))
        }
        ResultWireV1::Tracking { tracking } => {
            Ok(MachineResultV1::Tracking(tracking_from_wire(tracking)?))
        }
        ResultWireV1::Status { status } => {
            Ok(MachineResultV1::Status(namespace_status_from_wire(status)))
        }
        ResultWireV1::Fsck { report } => Ok(MachineResultV1::Fsck(fsck_from_wire(report))),
    }
}

const fn status_to_wire(value: StoreStatusV1) -> StoreStatusWireV1 {
    match value {
        <StoreStatusV1>::Absent => <StoreStatusWireV1>::Absent,
        <StoreStatusV1>::Uninitialized => <StoreStatusWireV1>::Uninitialized,
        <StoreStatusV1>::Ready => <StoreStatusWireV1>::Ready,
    }
}

const fn status_from_wire(value: StoreStatusWireV1) -> StoreStatusV1 {
    match value {
        <StoreStatusWireV1>::Absent => <StoreStatusV1>::Absent,
        <StoreStatusWireV1>::Uninitialized => <StoreStatusV1>::Uninitialized,
        <StoreStatusWireV1>::Ready => <StoreStatusV1>::Ready,
    }
}

fn catalog_to_wire(catalog: &CatalogInspectionV1) -> CatalogInspectionWireV1 {
    CatalogInspectionWireV1 {
        digest: catalog.digest().clone(),
        namespaces: catalog
            .namespaces()
            .iter()
            .map(|namespace| CatalogNamespaceInspectionWireV1 {
                namespace: namespace.namespace().clone(),
                generation: namespace.generation().clone(),
            })
            .collect(),
        decoded_bytes: catalog.decoded_bytes(),
    }
}

fn catalog_from_wire(catalog: CatalogInspectionWireV1) -> CatalogInspectionV1 {
    CatalogInspectionV1::new(
        catalog.digest,
        catalog
            .namespaces
            .into_iter()
            .map(|namespace| {
                CatalogNamespaceInspectionV1::new(namespace.namespace, namespace.generation)
            })
            .collect(),
        catalog.decoded_bytes,
    )
}

fn namespace_to_wire(namespace: &NamespaceInspectionV1) -> NamespaceInspectionWireV1 {
    NamespaceInspectionWireV1 {
        namespace: namespace.namespace().clone(),
        head: namespace.head().cloned(),
        generation: namespace.generation().map(generation_to_wire),
        decoded_bytes: namespace.decoded_bytes(),
    }
}

fn namespace_from_wire(
    namespace: NamespaceInspectionWireV1,
) -> Result<NamespaceInspectionV1, MachineReadError> {
    Ok(NamespaceInspectionV1::new(
        namespace.namespace,
        namespace.head,
        namespace.generation.map(generation_from_wire).transpose()?,
        namespace.decoded_bytes,
    ))
}

fn history_to_wire(history: &NamespaceHistoryV1) -> NamespaceHistoryWireV1 {
    NamespaceHistoryWireV1 {
        namespace: history.namespace().clone(),
        head: history.head().cloned(),
        generations: history
            .generations()
            .iter()
            .map(generation_to_wire)
            .collect(),
        decoded_bytes: history.decoded_bytes(),
    }
}

fn history_from_wire(
    history: NamespaceHistoryWireV1,
) -> Result<NamespaceHistoryV1, MachineReadError> {
    Ok(NamespaceHistoryV1::new(
        history.namespace,
        history.head,
        history
            .generations
            .into_iter()
            .map(generation_from_wire)
            .collect::<Result<_, _>>()?,
        history.decoded_bytes,
    ))
}

fn generation_to_wire(generation: &GenerationInspectionV1) -> GenerationInspectionWireV1 {
    GenerationInspectionWireV1 {
        namespace: generation.namespace().clone(),
        generation: generation.generation().clone(),
        lifecycle: lifecycle_to_wire(generation.lifecycle()),
        desired_snapshot_digest: generation.desired_snapshot_digest().clone(),
        target_count: generation.target_count(),
        present_target_count: generation.present_target_count(),
        absent_target_count: generation.absent_target_count(),
        plan_id: generation.plan_id().clone(),
        predecessor: generation.predecessor().cloned(),
        tracked_root: generation.tracked_root().map(tracked_root_to_wire),
        transition: transition_to_wire(generation.transition()),
        restore_point: generation.restore_point().map(restore_point_to_wire),
        retention: retention_authority_to_wire(generation.retention_authority()),
    }
}

fn generation_from_wire(
    generation: GenerationInspectionWireV1,
) -> Result<GenerationInspectionV1, MachineReadError> {
    Ok(GenerationInspectionV1::from(GenerationInspectionPartsV1 {
        namespace: generation.namespace,
        generation: generation.generation,
        lifecycle: lifecycle_from_wire(generation.lifecycle),
        desired_snapshot_digest: generation.desired_snapshot_digest,
        target_count: generation.target_count,
        present_target_count: generation.present_target_count,
        absent_target_count: generation.absent_target_count,
        plan_id: generation.plan_id,
        predecessor: generation.predecessor,
        tracked_root: generation
            .tracked_root
            .map(tracked_root_from_wire)
            .transpose()?,
    })
    .with_authority(
        transition_from_wire(generation.transition),
        generation
            .restore_point
            .map(restore_point_from_wire)
            .transpose()?,
        retention_authority_from_wire(generation.retention)?,
    ))
}

fn transition_to_wire(transition: &LifecycleTransitionViewV1) -> LifecycleTransitionWireV1 {
    match transition {
        LifecycleTransitionViewV1::Reconcile => LifecycleTransitionWireV1::Reconcile {},
        LifecycleTransitionViewV1::Disable => LifecycleTransitionWireV1::Disable {},
        LifecycleTransitionViewV1::Enable { restore_generation } => {
            LifecycleTransitionWireV1::Enable {
                restore_generation: restore_generation.clone(),
            }
        }
        LifecycleTransitionViewV1::Checkout { source_generation } => {
            LifecycleTransitionWireV1::Checkout {
                source_generation: source_generation.clone(),
            }
        }
        LifecycleTransitionViewV1::RetentionAuthority => {
            LifecycleTransitionWireV1::RetentionAuthority {}
        }
        LifecycleTransitionViewV1::NamespaceRemoval { drops_history } => {
            LifecycleTransitionWireV1::NamespaceRemoval {
                drops_history: *drops_history,
            }
        }
    }
}

fn transition_from_wire(transition: LifecycleTransitionWireV1) -> LifecycleTransitionViewV1 {
    match transition {
        LifecycleTransitionWireV1::Reconcile {} => LifecycleTransitionViewV1::Reconcile,
        LifecycleTransitionWireV1::Disable {} => LifecycleTransitionViewV1::Disable,
        LifecycleTransitionWireV1::Enable { restore_generation } => {
            LifecycleTransitionViewV1::Enable { restore_generation }
        }
        LifecycleTransitionWireV1::Checkout { source_generation } => {
            LifecycleTransitionViewV1::Checkout { source_generation }
        }
        LifecycleTransitionWireV1::RetentionAuthority {} => {
            LifecycleTransitionViewV1::RetentionAuthority
        }
        LifecycleTransitionWireV1::NamespaceRemoval { drops_history } => {
            LifecycleTransitionViewV1::NamespaceRemoval { drops_history }
        }
    }
}

fn restore_point_to_wire(point: &RestorePointInspectionV1) -> RestorePointInspectionWireV1 {
    RestorePointInspectionWireV1 {
        generation: point.generation().clone(),
        lifecycle: lifecycle_to_wire(point.lifecycle()),
        desired_snapshot_digest: point.desired_snapshot_digest().clone(),
        tracked_root: point.tracked_root().map(tracked_root_to_wire),
    }
}

fn restore_point_from_wire(
    point: RestorePointInspectionWireV1,
) -> Result<RestorePointInspectionV1, MachineReadError> {
    Ok(RestorePointInspectionV1::new(
        point.generation,
        lifecycle_from_wire(point.lifecycle),
        point.desired_snapshot_digest,
        point.tracked_root.map(tracked_root_from_wire).transpose()?,
    ))
}

fn retention_authority_to_wire(
    authority: &RetentionAuthorityInspectionV1,
) -> RetentionAuthorityInspectionWireV1 {
    RetentionAuthorityInspectionWireV1 {
        history_generations: authority.history_generations(),
        restore_points: authority
            .restore_points()
            .iter()
            .map(restore_point_to_wire)
            .collect(),
        explicit_pins: authority
            .explicit_pins()
            .iter()
            .map(retention_object_to_wire)
            .collect(),
    }
}

fn retention_authority_from_wire(
    authority: RetentionAuthorityInspectionWireV1,
) -> Result<RetentionAuthorityInspectionV1, MachineReadError> {
    Ok(RetentionAuthorityInspectionV1::new(
        authority.history_generations,
        authority
            .restore_points
            .into_iter()
            .map(restore_point_from_wire)
            .collect::<Result<_, _>>()?,
        authority
            .explicit_pins
            .into_iter()
            .map(retention_object_from_wire)
            .collect(),
    ))
}

fn desired_snapshot_to_wire(
    snapshot: &DesiredSnapshotInspectionV1,
) -> DesiredSnapshotInspectionWireV1 {
    DesiredSnapshotInspectionWireV1 {
        namespace: snapshot.namespace().clone(),
        generation: snapshot.generation().clone(),
        digest: snapshot.digest().clone(),
        targets: snapshot
            .targets()
            .iter()
            .map(desired_target_to_wire)
            .collect(),
        decoded_bytes: snapshot.decoded_bytes(),
    }
}

fn desired_target_to_wire(target: &DesiredTargetInspectionV1) -> DesiredTargetInspectionWireV1 {
    let state = match target.state() {
        DesiredTargetStateInspectionV1::File {
            digest,
            byte_len,
            mode,
        } => DesiredTargetStateInspectionWireV1::File {
            digest: digest.clone(),
            byte_len: *byte_len,
            mode: *mode,
        },
        DesiredTargetStateInspectionV1::Directory { mode } => {
            DesiredTargetStateInspectionWireV1::Directory { mode: *mode }
        }
        DesiredTargetStateInspectionV1::Symlink { object } => {
            DesiredTargetStateInspectionWireV1::Symlink {
                object: object.clone(),
            }
        }
        DesiredTargetStateInspectionV1::Tree {
            tree,
            archive_provenance,
        } => DesiredTargetStateInspectionWireV1::Tree {
            tree: tree.clone(),
            archive_provenance: archive_provenance.as_ref().map(archive_provenance_to_wire),
        },
    };
    DesiredTargetInspectionWireV1 {
        authority: target.authority().clone(),
        relative_path: target.relative_path().to_owned(),
        state,
    }
}

fn desired_snapshot_from_wire(
    snapshot: DesiredSnapshotInspectionWireV1,
) -> Result<DesiredSnapshotInspectionV1, MachineReadError> {
    Ok(DesiredSnapshotInspectionV1::new(
        snapshot.namespace,
        snapshot.generation,
        snapshot.digest,
        snapshot
            .targets
            .into_iter()
            .map(desired_target_from_wire)
            .collect::<Result<_, _>>()?,
        snapshot.decoded_bytes,
    ))
}

fn desired_target_from_wire(
    target: DesiredTargetInspectionWireV1,
) -> Result<DesiredTargetInspectionV1, MachineReadError> {
    let state = match target.state {
        DesiredTargetStateInspectionWireV1::File {
            digest,
            byte_len,
            mode,
        } => DesiredTargetStateInspectionV1::File {
            digest,
            byte_len,
            mode,
        },
        DesiredTargetStateInspectionWireV1::Directory { mode } => {
            DesiredTargetStateInspectionV1::Directory { mode }
        }
        DesiredTargetStateInspectionWireV1::Symlink { object } => {
            DesiredTargetStateInspectionV1::Symlink { object }
        }
        DesiredTargetStateInspectionWireV1::Tree {
            tree,
            archive_provenance,
        } => DesiredTargetStateInspectionV1::Tree {
            tree,
            archive_provenance: archive_provenance
                .map(archive_provenance_from_wire)
                .transpose()?,
        },
    };
    Ok(DesiredTargetInspectionV1::new(
        target.authority,
        target.relative_path,
        state,
    ))
}

fn canonical_tree_to_wire(tree: &CanonicalTreeInspectionV1) -> CanonicalTreeInspectionWireV1 {
    CanonicalTreeInspectionWireV1 {
        tree: tree.tree().clone(),
        root_mode: tree.root_mode(),
        entries: tree
            .entries()
            .iter()
            .map(|entry| CanonicalTreeEntryInspectionWireV1 {
                relative_path: entry.relative_path().to_owned(),
                mode: entry.mode(),
                object: match entry.kind() {
                    CanonicalTreeEntryKindInspectionV1::File { digest, byte_len } => {
                        CanonicalTreeEntryKindInspectionWireV1::File {
                            digest: digest.clone(),
                            byte_len: *byte_len,
                        }
                    }
                    CanonicalTreeEntryKindInspectionV1::Directory { digest } => {
                        CanonicalTreeEntryKindInspectionWireV1::Directory {
                            digest: digest.clone(),
                        }
                    }
                    CanonicalTreeEntryKindInspectionV1::Symlink { digest } => {
                        CanonicalTreeEntryKindInspectionWireV1::Symlink {
                            digest: digest.clone(),
                        }
                    }
                },
            })
            .collect(),
        decoded_bytes: tree.decoded_bytes(),
    }
}

fn canonical_tree_from_wire(tree: CanonicalTreeInspectionWireV1) -> CanonicalTreeInspectionV1 {
    CanonicalTreeInspectionV1::new(
        tree.tree,
        tree.root_mode,
        tree.entries
            .into_iter()
            .map(|entry| {
                CanonicalTreeEntryInspectionV1::new(
                    entry.relative_path,
                    entry.mode,
                    match entry.object {
                        CanonicalTreeEntryKindInspectionWireV1::File { digest, byte_len } => {
                            CanonicalTreeEntryKindInspectionV1::File { digest, byte_len }
                        }
                        CanonicalTreeEntryKindInspectionWireV1::Directory { digest } => {
                            CanonicalTreeEntryKindInspectionV1::Directory { digest }
                        }
                        CanonicalTreeEntryKindInspectionWireV1::Symlink { digest } => {
                            CanonicalTreeEntryKindInspectionV1::Symlink { digest }
                        }
                    },
                )
            })
            .collect(),
        tree.decoded_bytes,
    )
}

fn artifact_metadata_to_wire(
    artifact: &ArtifactMetadataInspectionV1,
) -> ArtifactMetadataInspectionWireV1 {
    ArtifactMetadataInspectionWireV1 {
        plan_id: artifact.plan_id().clone(),
        descriptor: artifact_descriptor_to_wire(artifact.descriptor()),
        decoded_bytes: artifact.decoded_bytes(),
    }
}

fn artifact_metadata_from_wire(
    artifact: ArtifactMetadataInspectionWireV1,
) -> Result<ArtifactMetadataInspectionV1, MachineReadError> {
    Ok(ArtifactMetadataInspectionV1::new(
        artifact.plan_id,
        artifact_descriptor_from_wire(artifact.descriptor)?,
        artifact.decoded_bytes,
    ))
}

fn captured_inputs_to_wire(inputs: &CapturedInputsInspectionV1) -> CapturedInputsInspectionWireV1 {
    CapturedInputsInspectionWireV1 {
        plan_id: inputs.plan_id().clone(),
        graph_digest: inputs.graph_digest().clone(),
        inputs: inputs.inputs().iter().map(input_to_wire).collect(),
        decoded_bytes: inputs.decoded_bytes(),
    }
}

fn captured_inputs_from_wire(
    inputs: CapturedInputsInspectionWireV1,
) -> Result<CapturedInputsInspectionV1, MachineReadError> {
    Ok(CapturedInputsInspectionV1::new(
        inputs.plan_id,
        inputs.graph_digest,
        inputs
            .inputs
            .into_iter()
            .map(input_from_wire)
            .collect::<Result<_, _>>()?,
        inputs.decoded_bytes,
    ))
}

fn transform_inspection_to_wire(
    provenance: &TransformProvenanceInspectionV1,
) -> TransformProvenanceInspectionWireV1 {
    TransformProvenanceInspectionWireV1 {
        plan_id: provenance.plan_id().clone(),
        transforms: provenance
            .transforms()
            .iter()
            .map(transform_to_wire)
            .collect(),
        decoded_bytes: provenance.decoded_bytes(),
    }
}

fn transform_inspection_from_wire(
    provenance: TransformProvenanceInspectionWireV1,
) -> Result<TransformProvenanceInspectionV1, MachineReadError> {
    Ok(TransformProvenanceInspectionV1::new(
        provenance.plan_id,
        provenance
            .transforms
            .into_iter()
            .map(transform_from_wire)
            .collect::<Result<_, _>>()?,
        provenance.decoded_bytes,
    ))
}

fn retention_to_wire(retention: &RetentionInspectionV1) -> RetentionInspectionWireV1 {
    RetentionInspectionWireV1 {
        namespace: retention.namespace().clone(),
        generation: retention.generation().clone(),
        authority: retention_authority_to_wire(retention.authority()),
    }
}

fn retention_from_wire(
    retention: RetentionInspectionWireV1,
) -> Result<RetentionInspectionV1, MachineReadError> {
    Ok(RetentionInspectionV1::new(
        retention.namespace,
        retention.generation,
        retention_authority_from_wire(retention.authority)?,
    ))
}

fn tracking_to_wire(tracking: &TrackingInspectionV1) -> TrackingInspectionWireV1 {
    TrackingInspectionWireV1 {
        namespace: tracking.namespace().clone(),
        generation: tracking.generation().clone(),
        tracked_root: tracking.tracked_root().map(tracked_root_to_wire),
    }
}

fn tracking_from_wire(
    tracking: TrackingInspectionWireV1,
) -> Result<TrackingInspectionV1, MachineReadError> {
    Ok(TrackingInspectionV1::new(
        tracking.namespace,
        tracking.generation,
        tracking
            .tracked_root
            .map(tracked_root_from_wire)
            .transpose()?,
    ))
}

const fn namespace_status_kind_to_wire(value: NamespaceStatusKindV1) -> NamespaceStatusKindWireV1 {
    match value {
        <NamespaceStatusKindV1>::NotFound => <NamespaceStatusKindWireV1>::NotFound,
        <NamespaceStatusKindV1>::EnabledExact => <NamespaceStatusKindWireV1>::EnabledExact,
        <NamespaceStatusKindV1>::EnabledModified => <NamespaceStatusKindWireV1>::EnabledModified,
        <NamespaceStatusKindV1>::EnabledMissing => <NamespaceStatusKindWireV1>::EnabledMissing,
        <NamespaceStatusKindV1>::EnabledUnexpected => {
            <NamespaceStatusKindWireV1>::EnabledUnexpected
        }
        <NamespaceStatusKindV1>::Disabled => <NamespaceStatusKindWireV1>::Disabled,
        <NamespaceStatusKindV1>::Stale => <NamespaceStatusKindWireV1>::Stale,
        <NamespaceStatusKindV1>::IncompatibleOrCorrupt => {
            <NamespaceStatusKindWireV1>::IncompatibleOrCorrupt
        }
        <NamespaceStatusKindV1>::RecoveryRequired => <NamespaceStatusKindWireV1>::RecoveryRequired,
    }
}

const fn namespace_status_kind_from_wire(
    value: NamespaceStatusKindWireV1,
) -> NamespaceStatusKindV1 {
    match value {
        <NamespaceStatusKindWireV1>::NotFound => <NamespaceStatusKindV1>::NotFound,
        <NamespaceStatusKindWireV1>::EnabledExact => <NamespaceStatusKindV1>::EnabledExact,
        <NamespaceStatusKindWireV1>::EnabledModified => <NamespaceStatusKindV1>::EnabledModified,
        <NamespaceStatusKindWireV1>::EnabledMissing => <NamespaceStatusKindV1>::EnabledMissing,
        <NamespaceStatusKindWireV1>::EnabledUnexpected => {
            <NamespaceStatusKindV1>::EnabledUnexpected
        }
        <NamespaceStatusKindWireV1>::Disabled => <NamespaceStatusKindV1>::Disabled,
        <NamespaceStatusKindWireV1>::Stale => <NamespaceStatusKindV1>::Stale,
        <NamespaceStatusKindWireV1>::IncompatibleOrCorrupt => {
            <NamespaceStatusKindV1>::IncompatibleOrCorrupt
        }
        <NamespaceStatusKindWireV1>::RecoveryRequired => <NamespaceStatusKindV1>::RecoveryRequired,
    }
}

const fn target_status_kind_to_wire(value: TargetStatusKindV1) -> TargetStatusKindWireV1 {
    match value {
        <TargetStatusKindV1>::Exact => <TargetStatusKindWireV1>::Exact,
        <TargetStatusKindV1>::Modified => <TargetStatusKindWireV1>::Modified,
        <TargetStatusKindV1>::Missing => <TargetStatusKindWireV1>::Missing,
        <TargetStatusKindV1>::Unexpected => <TargetStatusKindWireV1>::Unexpected,
        <TargetStatusKindV1>::Stale => <TargetStatusKindWireV1>::Stale,
        <TargetStatusKindV1>::Incompatible => <TargetStatusKindWireV1>::Incompatible,
    }
}

const fn target_status_kind_from_wire(value: TargetStatusKindWireV1) -> TargetStatusKindV1 {
    match value {
        <TargetStatusKindWireV1>::Exact => <TargetStatusKindV1>::Exact,
        <TargetStatusKindWireV1>::Modified => <TargetStatusKindV1>::Modified,
        <TargetStatusKindWireV1>::Missing => <TargetStatusKindV1>::Missing,
        <TargetStatusKindWireV1>::Unexpected => <TargetStatusKindV1>::Unexpected,
        <TargetStatusKindWireV1>::Stale => <TargetStatusKindV1>::Stale,
        <TargetStatusKindWireV1>::Incompatible => <TargetStatusKindV1>::Incompatible,
    }
}

fn namespace_status_to_wire(status: &NamespaceStatusV1) -> NamespaceStatusWireV1 {
    NamespaceStatusWireV1 {
        namespace: status.namespace().clone(),
        head: status.head().cloned(),
        lifecycle: status.lifecycle().map(lifecycle_to_wire),
        desired_snapshot_digest: status.desired_snapshot_digest().cloned(),
        status: namespace_status_kind_to_wire(status.status()),
        targets: status
            .targets()
            .iter()
            .map(|target| TargetStatusWireV1 {
                authority: target.authority().clone(),
                relative_path: target.relative_path().to_owned(),
                status: target_status_kind_to_wire(target.status()),
            })
            .collect(),
        observed_bytes: status.observed_bytes(),
        detail: status.detail().map(str::to_owned),
    }
}

fn namespace_status_from_wire(status: NamespaceStatusWireV1) -> NamespaceStatusV1 {
    NamespaceStatusV1::from(NamespaceStatusPartsV1 {
        namespace: status.namespace,
        head: status.head,
        lifecycle: status.lifecycle.map(lifecycle_from_wire),
        desired_snapshot_digest: status.desired_snapshot_digest,
        status: namespace_status_kind_from_wire(status.status),
        targets: status
            .targets
            .into_iter()
            .map(|target| {
                TargetStatusV1::new(
                    target.authority,
                    target.relative_path,
                    target_status_kind_from_wire(target.status),
                )
            })
            .collect(),
        observed_bytes: status.observed_bytes,
        detail: status.detail,
    })
}

fn fsck_to_wire(report: &FsckReportV1) -> FsckReportWireV1 {
    FsckReportWireV1 {
        findings: report.findings().iter().map(fsck_finding_to_wire).collect(),
        checked_generations: report.checked_generations(),
        checked_prepared_plans: report.checked_prepared_plans(),
        checked_artifact_blobs: report.checked_artifact_blobs(),
        checked_pack_objects: report.checked_pack_objects(),
        checked_canonical_files: report.checked_canonical_files(),
        checked_canonical_symlinks: report.checked_canonical_symlinks(),
        checked_canonical_trees: report.checked_canonical_trees(),
        checked_targets: report.checked_targets(),
        decoded_bytes: report.decoded_bytes(),
        observed_bytes: report.observed_bytes(),
        findings_truncated: report.findings_truncated(),
        complete: report.complete(),
    }
}

fn fsck_from_wire(report: FsckReportWireV1) -> FsckReportV1 {
    FsckReportV1::from(FsckReportPartsV1 {
        findings: report
            .findings
            .into_iter()
            .map(fsck_finding_from_wire)
            .collect(),
        checked_generations: report.checked_generations,
        checked_prepared_plans: report.checked_prepared_plans,
        checked_artifact_blobs: report.checked_artifact_blobs,
        checked_pack_objects: report.checked_pack_objects,
        checked_canonical_files: report.checked_canonical_files,
        checked_canonical_symlinks: report.checked_canonical_symlinks,
        checked_canonical_trees: report.checked_canonical_trees,
        checked_targets: report.checked_targets,
        decoded_bytes: report.decoded_bytes,
        observed_bytes: report.observed_bytes,
        findings_truncated: report.findings_truncated,
        complete: report.complete,
    })
}

fn fsck_finding_to_wire(finding: &FsckFindingV1) -> FsckFindingWireV1 {
    FsckFindingWireV1 {
        code: fsck_code_to_wire(finding.code()),
        severity: match finding.severity() {
            FsckSeverityV1::Error => FsckSeverityWireV1::Error,
            FsckSeverityV1::Warning => FsckSeverityWireV1::Warning,
        },
        subject: fsck_subject_to_wire(finding.subject()),
        detail: finding.detail().to_owned(),
    }
}

fn fsck_finding_from_wire(finding: FsckFindingWireV1) -> FsckFindingV1 {
    FsckFindingV1::new(
        fsck_code_from_wire(finding.code),
        match finding.severity {
            FsckSeverityWireV1::Error => FsckSeverityV1::Error,
            FsckSeverityWireV1::Warning => FsckSeverityV1::Warning,
        },
        fsck_subject_from_wire(finding.subject),
        finding.detail,
    )
}

fn fsck_subject_to_wire(subject: &FsckSubjectV1) -> FsckSubjectWireV1 {
    match subject {
        FsckSubjectV1::StoreDescriptor => FsckSubjectWireV1::StoreDescriptor {},
        FsckSubjectV1::TransactionLock => FsckSubjectWireV1::TransactionLock {},
        FsckSubjectV1::MaintenanceLock => FsckSubjectWireV1::MaintenanceLock {},
        FsckSubjectV1::Journal => FsckSubjectWireV1::Journal {},
        FsckSubjectV1::JournalStaging => FsckSubjectWireV1::JournalStaging {},
        FsckSubjectV1::Catalog => FsckSubjectWireV1::Catalog {},
        FsckSubjectV1::CatalogStaging => FsckSubjectWireV1::CatalogStaging {},
        FsckSubjectV1::Namespace(namespace) => FsckSubjectWireV1::Namespace {
            namespace: namespace.clone(),
        },
        FsckSubjectV1::Generation(digest) => FsckSubjectWireV1::Generation {
            digest: digest.clone(),
        },
        FsckSubjectV1::PreparedPlan(plan_id) => FsckSubjectWireV1::PreparedPlan {
            plan_id: plan_id.clone(),
        },
        FsckSubjectV1::ArtifactBlob(digest) => FsckSubjectWireV1::ArtifactBlob {
            digest: digest.clone(),
        },
        FsckSubjectV1::PackObject(digest) => FsckSubjectWireV1::PackObject {
            digest: digest.clone(),
        },
        FsckSubjectV1::CanonicalFile(digest) => FsckSubjectWireV1::CanonicalFile {
            digest: digest.clone(),
        },
        FsckSubjectV1::CanonicalSymlink(digest) => FsckSubjectWireV1::CanonicalSymlink {
            digest: digest.clone(),
        },
        FsckSubjectV1::CanonicalTree(digest) => FsckSubjectWireV1::CanonicalTree {
            digest: digest.clone(),
        },
        FsckSubjectV1::Target {
            authority,
            relative_path,
        } => FsckSubjectWireV1::Target {
            authority: authority.clone(),
            relative_path: relative_path.clone(),
        },
        FsckSubjectV1::StoreArea(area) => FsckSubjectWireV1::StoreArea {
            area: fsck_area_to_wire(*area),
        },
        FsckSubjectV1::Retention => FsckSubjectWireV1::Retention {},
        FsckSubjectV1::Ownership => FsckSubjectWireV1::Ownership {},
        FsckSubjectV1::Coverage => FsckSubjectWireV1::Coverage {},
    }
}

fn fsck_subject_from_wire(subject: FsckSubjectWireV1) -> FsckSubjectV1 {
    match subject {
        FsckSubjectWireV1::StoreDescriptor {} => FsckSubjectV1::StoreDescriptor,
        FsckSubjectWireV1::TransactionLock {} => FsckSubjectV1::TransactionLock,
        FsckSubjectWireV1::MaintenanceLock {} => FsckSubjectV1::MaintenanceLock,
        FsckSubjectWireV1::Journal {} => FsckSubjectV1::Journal,
        FsckSubjectWireV1::JournalStaging {} => FsckSubjectV1::JournalStaging,
        FsckSubjectWireV1::Catalog {} => FsckSubjectV1::Catalog,
        FsckSubjectWireV1::CatalogStaging {} => FsckSubjectV1::CatalogStaging,
        FsckSubjectWireV1::Namespace { namespace } => FsckSubjectV1::Namespace(namespace),
        FsckSubjectWireV1::Generation { digest } => FsckSubjectV1::Generation(digest),
        FsckSubjectWireV1::PreparedPlan { plan_id } => FsckSubjectV1::PreparedPlan(plan_id),
        FsckSubjectWireV1::ArtifactBlob { digest } => FsckSubjectV1::ArtifactBlob(digest),
        FsckSubjectWireV1::PackObject { digest } => FsckSubjectV1::PackObject(digest),
        FsckSubjectWireV1::CanonicalFile { digest } => FsckSubjectV1::CanonicalFile(digest),
        FsckSubjectWireV1::CanonicalSymlink { digest } => FsckSubjectV1::CanonicalSymlink(digest),
        FsckSubjectWireV1::CanonicalTree { digest } => FsckSubjectV1::CanonicalTree(digest),
        FsckSubjectWireV1::Target {
            authority,
            relative_path,
        } => FsckSubjectV1::Target {
            authority,
            relative_path,
        },
        FsckSubjectWireV1::StoreArea { area } => {
            FsckSubjectV1::StoreArea(fsck_area_from_wire(area))
        }
        FsckSubjectWireV1::Retention {} => FsckSubjectV1::Retention,
        FsckSubjectWireV1::Ownership {} => FsckSubjectV1::Ownership,
        FsckSubjectWireV1::Coverage {} => FsckSubjectV1::Coverage,
    }
}

const fn fsck_code_to_wire(value: FsckFindingCodeV1) -> FsckFindingCodeWireV1 {
    match value {
        <FsckFindingCodeV1>::InvalidDescriptor => <FsckFindingCodeWireV1>::InvalidDescriptor,
        <FsckFindingCodeV1>::RecoveryRequired => <FsckFindingCodeWireV1>::RecoveryRequired,
        <FsckFindingCodeV1>::InvalidJournal => <FsckFindingCodeWireV1>::InvalidJournal,
        <FsckFindingCodeV1>::MissingCatalog => <FsckFindingCodeWireV1>::MissingCatalog,
        <FsckFindingCodeV1>::InvalidCatalog => <FsckFindingCodeWireV1>::InvalidCatalog,
        <FsckFindingCodeV1>::MissingGeneration => <FsckFindingCodeWireV1>::MissingGeneration,
        <FsckFindingCodeV1>::InvalidGeneration => <FsckFindingCodeWireV1>::InvalidGeneration,
        <FsckFindingCodeV1>::CyclicHistory => <FsckFindingCodeWireV1>::CyclicHistory,
        <FsckFindingCodeV1>::CrossNamespaceHistory => {
            <FsckFindingCodeWireV1>::CrossNamespaceHistory
        }
        <FsckFindingCodeV1>::SharedGeneration => <FsckFindingCodeWireV1>::SharedGeneration,
        <FsckFindingCodeV1>::MissingPreparedPlan => <FsckFindingCodeWireV1>::MissingPreparedPlan,
        <FsckFindingCodeV1>::InvalidPreparedPlan => <FsckFindingCodeWireV1>::InvalidPreparedPlan,
        <FsckFindingCodeV1>::InvalidPreparedTransition => {
            <FsckFindingCodeWireV1>::InvalidPreparedTransition
        }
        <FsckFindingCodeV1>::MissingArtifactBlob => <FsckFindingCodeWireV1>::MissingArtifactBlob,
        <FsckFindingCodeV1>::CorruptArtifactBlob => <FsckFindingCodeWireV1>::CorruptArtifactBlob,
        <FsckFindingCodeV1>::ArtifactLengthMismatch => {
            <FsckFindingCodeWireV1>::ArtifactLengthMismatch
        }
        <FsckFindingCodeV1>::MissingPackObject => <FsckFindingCodeWireV1>::MissingPackObject,
        <FsckFindingCodeV1>::CorruptPackObject => <FsckFindingCodeWireV1>::CorruptPackObject,
        <FsckFindingCodeV1>::MissingCanonicalObject => {
            <FsckFindingCodeWireV1>::MissingCanonicalObject
        }
        <FsckFindingCodeV1>::CorruptCanonicalObject => {
            <FsckFindingCodeWireV1>::CorruptCanonicalObject
        }
        <FsckFindingCodeV1>::InvalidLockMetadata => <FsckFindingCodeWireV1>::InvalidLockMetadata,
        <FsckFindingCodeV1>::InvalidStaging => <FsckFindingCodeWireV1>::InvalidStaging,
        <FsckFindingCodeV1>::MalformedStoreEntry => <FsckFindingCodeWireV1>::MalformedStoreEntry,
        <FsckFindingCodeV1>::UnreachableImmutableObject => {
            <FsckFindingCodeWireV1>::UnreachableImmutableObject
        }
        <FsckFindingCodeV1>::TargetDrift => <FsckFindingCodeWireV1>::TargetDrift,
        <FsckFindingCodeV1>::TargetObservationFailed => {
            <FsckFindingCodeWireV1>::TargetObservationFailed
        }
        <FsckFindingCodeV1>::AuthorityChanged => <FsckFindingCodeWireV1>::AuthorityChanged,
        <FsckFindingCodeV1>::InvalidOwnership => <FsckFindingCodeWireV1>::InvalidOwnership,
        <FsckFindingCodeV1>::TraversalLimitExceeded => {
            <FsckFindingCodeWireV1>::TraversalLimitExceeded
        }
        <FsckFindingCodeV1>::DecodedByteLimitExceeded => {
            <FsckFindingCodeWireV1>::DecodedByteLimitExceeded
        }
        <FsckFindingCodeV1>::FindingLimitExceeded => <FsckFindingCodeWireV1>::FindingLimitExceeded,
    }
}

const fn fsck_code_from_wire(value: FsckFindingCodeWireV1) -> FsckFindingCodeV1 {
    match value {
        <FsckFindingCodeWireV1>::InvalidDescriptor => <FsckFindingCodeV1>::InvalidDescriptor,
        <FsckFindingCodeWireV1>::RecoveryRequired => <FsckFindingCodeV1>::RecoveryRequired,
        <FsckFindingCodeWireV1>::InvalidJournal => <FsckFindingCodeV1>::InvalidJournal,
        <FsckFindingCodeWireV1>::MissingCatalog => <FsckFindingCodeV1>::MissingCatalog,
        <FsckFindingCodeWireV1>::InvalidCatalog => <FsckFindingCodeV1>::InvalidCatalog,
        <FsckFindingCodeWireV1>::MissingGeneration => <FsckFindingCodeV1>::MissingGeneration,
        <FsckFindingCodeWireV1>::InvalidGeneration => <FsckFindingCodeV1>::InvalidGeneration,
        <FsckFindingCodeWireV1>::CyclicHistory => <FsckFindingCodeV1>::CyclicHistory,
        <FsckFindingCodeWireV1>::CrossNamespaceHistory => {
            <FsckFindingCodeV1>::CrossNamespaceHistory
        }
        <FsckFindingCodeWireV1>::SharedGeneration => <FsckFindingCodeV1>::SharedGeneration,
        <FsckFindingCodeWireV1>::MissingPreparedPlan => <FsckFindingCodeV1>::MissingPreparedPlan,
        <FsckFindingCodeWireV1>::InvalidPreparedPlan => <FsckFindingCodeV1>::InvalidPreparedPlan,
        <FsckFindingCodeWireV1>::InvalidPreparedTransition => {
            <FsckFindingCodeV1>::InvalidPreparedTransition
        }
        <FsckFindingCodeWireV1>::MissingArtifactBlob => <FsckFindingCodeV1>::MissingArtifactBlob,
        <FsckFindingCodeWireV1>::CorruptArtifactBlob => <FsckFindingCodeV1>::CorruptArtifactBlob,
        <FsckFindingCodeWireV1>::ArtifactLengthMismatch => {
            <FsckFindingCodeV1>::ArtifactLengthMismatch
        }
        <FsckFindingCodeWireV1>::MissingPackObject => <FsckFindingCodeV1>::MissingPackObject,
        <FsckFindingCodeWireV1>::CorruptPackObject => <FsckFindingCodeV1>::CorruptPackObject,
        <FsckFindingCodeWireV1>::MissingCanonicalObject => {
            <FsckFindingCodeV1>::MissingCanonicalObject
        }
        <FsckFindingCodeWireV1>::CorruptCanonicalObject => {
            <FsckFindingCodeV1>::CorruptCanonicalObject
        }
        <FsckFindingCodeWireV1>::InvalidLockMetadata => <FsckFindingCodeV1>::InvalidLockMetadata,
        <FsckFindingCodeWireV1>::InvalidStaging => <FsckFindingCodeV1>::InvalidStaging,
        <FsckFindingCodeWireV1>::MalformedStoreEntry => <FsckFindingCodeV1>::MalformedStoreEntry,
        <FsckFindingCodeWireV1>::UnreachableImmutableObject => {
            <FsckFindingCodeV1>::UnreachableImmutableObject
        }
        <FsckFindingCodeWireV1>::TargetDrift => <FsckFindingCodeV1>::TargetDrift,
        <FsckFindingCodeWireV1>::TargetObservationFailed => {
            <FsckFindingCodeV1>::TargetObservationFailed
        }
        <FsckFindingCodeWireV1>::AuthorityChanged => <FsckFindingCodeV1>::AuthorityChanged,
        <FsckFindingCodeWireV1>::InvalidOwnership => <FsckFindingCodeV1>::InvalidOwnership,
        <FsckFindingCodeWireV1>::TraversalLimitExceeded => {
            <FsckFindingCodeV1>::TraversalLimitExceeded
        }
        <FsckFindingCodeWireV1>::DecodedByteLimitExceeded => {
            <FsckFindingCodeV1>::DecodedByteLimitExceeded
        }
        <FsckFindingCodeWireV1>::FindingLimitExceeded => <FsckFindingCodeV1>::FindingLimitExceeded,
    }
}

const fn fsck_area_to_wire(value: FsckStoreAreaV1) -> FsckStoreAreaWireV1 {
    match value {
        <FsckStoreAreaV1>::Root => <FsckStoreAreaWireV1>::Root,
        <FsckStoreAreaV1>::State => <FsckStoreAreaWireV1>::State,
        <FsckStoreAreaV1>::Generations => <FsckStoreAreaWireV1>::Generations,
        <FsckStoreAreaV1>::Prepared => <FsckStoreAreaWireV1>::Prepared,
        <FsckStoreAreaV1>::Transactions => <FsckStoreAreaWireV1>::Transactions,
        <FsckStoreAreaV1>::Objects => <FsckStoreAreaWireV1>::Objects,
        <FsckStoreAreaV1>::ArtifactBlobs => <FsckStoreAreaWireV1>::ArtifactBlobs,
        <FsckStoreAreaV1>::PackObjects => <FsckStoreAreaWireV1>::PackObjects,
        <FsckStoreAreaV1>::CanonicalFiles => <FsckStoreAreaWireV1>::CanonicalFiles,
        <FsckStoreAreaV1>::CanonicalSymlinks => <FsckStoreAreaWireV1>::CanonicalSymlinks,
        <FsckStoreAreaV1>::CanonicalTrees => <FsckStoreAreaWireV1>::CanonicalTrees,
    }
}

const fn fsck_area_from_wire(value: FsckStoreAreaWireV1) -> FsckStoreAreaV1 {
    match value {
        <FsckStoreAreaWireV1>::Root => <FsckStoreAreaV1>::Root,
        <FsckStoreAreaWireV1>::State => <FsckStoreAreaV1>::State,
        <FsckStoreAreaWireV1>::Generations => <FsckStoreAreaV1>::Generations,
        <FsckStoreAreaWireV1>::Prepared => <FsckStoreAreaV1>::Prepared,
        <FsckStoreAreaWireV1>::Transactions => <FsckStoreAreaV1>::Transactions,
        <FsckStoreAreaWireV1>::Objects => <FsckStoreAreaV1>::Objects,
        <FsckStoreAreaWireV1>::ArtifactBlobs => <FsckStoreAreaV1>::ArtifactBlobs,
        <FsckStoreAreaWireV1>::PackObjects => <FsckStoreAreaV1>::PackObjects,
        <FsckStoreAreaWireV1>::CanonicalFiles => <FsckStoreAreaV1>::CanonicalFiles,
        <FsckStoreAreaWireV1>::CanonicalSymlinks => <FsckStoreAreaV1>::CanonicalSymlinks,
        <FsckStoreAreaWireV1>::CanonicalTrees => <FsckStoreAreaV1>::CanonicalTrees,
    }
}

const fn input_kind_to_wire(value: PrepareInputKindV1) -> PrepareInputKindWireV1 {
    match value {
        <PrepareInputKindV1>::Source => <PrepareInputKindWireV1>::Source,
        <PrepareInputKindV1>::Config => <PrepareInputKindWireV1>::Config,
        <PrepareInputKindV1>::Lock => <PrepareInputKindWireV1>::Lock,
        <PrepareInputKindV1>::Component => <PrepareInputKindWireV1>::Component,
        <PrepareInputKindV1>::Asset => <PrepareInputKindWireV1>::Asset,
        <PrepareInputKindV1>::Other => <PrepareInputKindWireV1>::Other,
    }
}

const fn input_kind_from_wire(value: PrepareInputKindWireV1) -> PrepareInputKindV1 {
    match value {
        <PrepareInputKindWireV1>::Source => <PrepareInputKindV1>::Source,
        <PrepareInputKindWireV1>::Config => <PrepareInputKindV1>::Config,
        <PrepareInputKindWireV1>::Lock => <PrepareInputKindV1>::Lock,
        <PrepareInputKindWireV1>::Component => <PrepareInputKindV1>::Component,
        <PrepareInputKindWireV1>::Asset => <PrepareInputKindV1>::Asset,
        <PrepareInputKindWireV1>::Other => <PrepareInputKindV1>::Other,
    }
}

fn input_to_wire(input: &PrepareInputV1) -> PrepareInputWireV1 {
    PrepareInputWireV1 {
        kind: input_kind_to_wire(input.kind()),
        name: input.name().to_owned(),
        digest: input.digest().clone(),
    }
}

fn input_from_wire(input: PrepareInputWireV1) -> Result<PrepareInputV1, MachineReadError> {
    PrepareInputV1::new(input_kind_from_wire(input.kind), input.name, input.digest)
        .map_err(deployment_read_error)
}

fn transform_to_wire(transform: &PrepareTransformProvenanceV1) -> TransformProvenanceWireV1 {
    TransformProvenanceWireV1 {
        name: transform.name().to_owned(),
        implementation: match transform.implementation() {
            PrepareTransformImplementationV1::BuiltIn { implementation } => {
                TransformImplementationWireV1::BuiltIn {
                    implementation: implementation.clone(),
                }
            }
            PrepareTransformImplementationV1::Component {
                pack_node_id,
                pack_content_digest,
                component_path,
                component_digest,
                interface_version,
                execution_profile_digest,
            } => TransformImplementationWireV1::Component {
                pack_node_id: pack_node_id.clone(),
                pack_content_digest: pack_content_digest.clone(),
                component_path: component_path.clone(),
                component_digest: component_digest.clone(),
                interface_version: interface_version.clone(),
                execution_profile_digest: execution_profile_digest.clone(),
            },
        },
        request_digest: transform.request_digest().clone(),
        document_digest: transform.document_digest().clone(),
        resources: transform
            .resources()
            .iter()
            .map(|resource| TransformResourceWireV1 {
                name: resource.name().to_owned(),
                digest: resource.digest().clone(),
            })
            .collect(),
        response_digest: transform.response_digest().clone(),
        diagnostics: transform
            .diagnostics()
            .iter()
            .map(transform_diagnostic_to_wire)
            .collect(),
    }
}

fn transform_diagnostic_to_wire(
    diagnostic: &PrepareTransformDiagnosticV1,
) -> TransformDiagnosticWireV1 {
    TransformDiagnosticWireV1 {
        severity: match diagnostic.severity() {
            PrepareTransformDiagnosticSeverityV1::Error => TransformDiagnosticSeverityWireV1::Error,
            PrepareTransformDiagnosticSeverityV1::Warning => {
                TransformDiagnosticSeverityWireV1::Warning
            }
            PrepareTransformDiagnosticSeverityV1::Info => TransformDiagnosticSeverityWireV1::Info,
        },
        code: diagnostic.code().to_owned(),
        message: diagnostic.message().to_owned(),
        primary: diagnostic.primary().map(|location| match location {
            PrepareTransformDiagnosticLocationV1::Source(source) => {
                TransformDiagnosticLocationWireV1::Source {
                    authority_label: source.authority_label().clone(),
                    authority_identity: source.authority_identity().clone(),
                    document_path: source.document_path().to_owned(),
                    source_byte_len: source.source_byte_len(),
                    start: source.start(),
                    end: source.end(),
                }
            }
            PrepareTransformDiagnosticLocationV1::Output(output) => {
                TransformDiagnosticLocationWireV1::Output {
                    start: output.start(),
                    end: output.end(),
                }
            }
        }),
        notes: diagnostic.notes().to_vec(),
    }
}

fn transform_from_wire(
    transform: TransformProvenanceWireV1,
) -> Result<PrepareTransformProvenanceV1, MachineReadError> {
    let implementation = match transform.implementation {
        TransformImplementationWireV1::BuiltIn { implementation } => {
            PrepareTransformImplementationV1::built_in(implementation)
        }
        TransformImplementationWireV1::Component {
            pack_node_id,
            pack_content_digest,
            component_path,
            component_digest,
            interface_version,
            execution_profile_digest,
        } => PrepareTransformImplementationV1::component(
            pack_node_id,
            pack_content_digest,
            component_path,
            component_digest,
            interface_version,
            execution_profile_digest,
        ),
    }
    .map_err(deployment_read_error)?;
    let resources = transform
        .resources
        .into_iter()
        .map(|resource| PrepareTransformResourceV1::new(resource.name, resource.digest))
        .collect::<Result<Vec<_>, _>>()
        .map_err(deployment_read_error)?;
    let diagnostics = transform
        .diagnostics
        .into_iter()
        .map(transform_diagnostic_from_wire)
        .collect::<Result<Vec<_>, _>>()?;
    PrepareTransformProvenanceV1::new(
        transform.name,
        implementation,
        transform.request_digest,
        transform.document_digest,
        resources,
        transform.response_digest,
        diagnostics,
    )
    .map_err(deployment_read_error)
}

fn transform_diagnostic_from_wire(
    diagnostic: TransformDiagnosticWireV1,
) -> Result<PrepareTransformDiagnosticV1, MachineReadError> {
    let severity = match diagnostic.severity {
        TransformDiagnosticSeverityWireV1::Error => PrepareTransformDiagnosticSeverityV1::Error,
        TransformDiagnosticSeverityWireV1::Warning => PrepareTransformDiagnosticSeverityV1::Warning,
        TransformDiagnosticSeverityWireV1::Info => PrepareTransformDiagnosticSeverityV1::Info,
    };
    let primary = match diagnostic.primary {
        Some(TransformDiagnosticLocationWireV1::Source {
            authority_label,
            authority_identity,
            document_path,
            source_byte_len,
            start,
            end,
        }) => Some(PrepareTransformDiagnosticLocationV1::Source(
            PrepareTransformSourceLocationV1::new(
                authority_label,
                authority_identity,
                document_path,
                source_byte_len,
                start,
                end,
            )
            .map_err(deployment_read_error)?,
        )),
        Some(TransformDiagnosticLocationWireV1::Output { start, end }) => {
            Some(PrepareTransformDiagnosticLocationV1::Output(
                PrepareTransformOutputLocationV1::new(start, end).map_err(deployment_read_error)?,
            ))
        }
        None => None,
    };
    PrepareTransformDiagnosticV1::new(
        severity,
        diagnostic.code,
        diagnostic.message,
        primary,
        diagnostic.notes,
    )
    .map_err(deployment_read_error)
}

fn prepare_artifact_to_wire(artifact: &PrepareArtifactV1) -> PrepareArtifactWireV1 {
    PrepareArtifactWireV1 {
        id: artifact.id().clone(),
        bytes_hex: encode_hex(artifact.bytes()),
        media_type: artifact.media_type().to_owned(),
    }
}

fn prepare_artifact_from_wire(
    artifact: PrepareArtifactWireV1,
) -> Result<PrepareArtifactV1, MachineReadError> {
    PrepareArtifactV1::new(
        artifact.id,
        decode_hex(&artifact.bytes_hex)?,
        artifact.media_type,
    )
    .map_err(deployment_read_error)
}

fn finding_request_to_wire(finding: &PreparePolicyFindingV1) -> PrepareFindingWireV1 {
    PrepareFindingWireV1 {
        code: finding.code().to_owned(),
        message: finding.message().to_owned(),
        approval_required: finding.approval_required(),
    }
}

fn finding_request_from_wire(
    finding: PrepareFindingWireV1,
) -> Result<PreparePolicyFindingV1, MachineReadError> {
    PreparePolicyFindingV1::new(finding.code, finding.message, finding.approval_required)
        .map_err(deployment_read_error)
}

fn archive_provenance_to_wire(provenance: &ArchiveProvenanceV1) -> ArchiveProvenanceWireV1 {
    ArchiveProvenanceWireV1 {
        payload: provenance.payload().clone(),
        decoder: provenance.decoder().to_owned(),
    }
}

fn archive_provenance_from_wire(
    provenance: ArchiveProvenanceWireV1,
) -> Result<ArchiveProvenanceV1, MachineReadError> {
    ArchiveProvenanceV1::new(provenance.payload, provenance.decoder).map_err(deployment_read_error)
}

fn target_state_to_wire(state: &PrepareTargetStateV1) -> PrepareTargetStateWireV1 {
    match state {
        PrepareTargetStateV1::File {
            digest,
            byte_len,
            mode,
        } => PrepareTargetStateWireV1::File {
            digest: digest.clone(),
            byte_len: *byte_len,
            mode: *mode,
        },
        PrepareTargetStateV1::Directory { mode } => {
            PrepareTargetStateWireV1::Directory { mode: *mode }
        }
        PrepareTargetStateV1::Symlink { object } => PrepareTargetStateWireV1::Symlink {
            object: object.clone(),
        },
        PrepareTargetStateV1::Tree {
            tree,
            archive_provenance,
        } => PrepareTargetStateWireV1::Tree {
            tree: tree.clone(),
            archive_provenance: archive_provenance.as_ref().map(archive_provenance_to_wire),
        },
    }
}

fn target_state_from_wire(
    state: PrepareTargetStateWireV1,
) -> Result<PrepareTargetStateV1, MachineReadError> {
    match state {
        PrepareTargetStateWireV1::File {
            digest,
            byte_len,
            mode,
        } => PrepareTargetStateV1::file(digest, byte_len, mode).map_err(deployment_read_error),
        PrepareTargetStateWireV1::Directory { mode } => {
            PrepareTargetStateV1::directory(mode).map_err(deployment_read_error)
        }
        PrepareTargetStateWireV1::Symlink { object } => Ok(PrepareTargetStateV1::symlink(object)),
        PrepareTargetStateWireV1::Tree {
            tree,
            archive_provenance: None,
        } => Ok(PrepareTargetStateV1::tree(tree)),
        PrepareTargetStateWireV1::Tree {
            tree,
            archive_provenance: Some(provenance),
        } => Ok(PrepareTargetStateV1::archive_tree(
            tree,
            archive_provenance_from_wire(provenance)?,
        )),
    }
}

fn operation_request_to_wire(operation: &PrepareOperationV1) -> PrepareOperationWireV1 {
    match operation {
        PrepareOperationV1::EnsureDirectory {
            authority,
            relative_path,
            mode,
            replace_existing,
        } => PrepareOperationWireV1::EnsureDirectory {
            authority: authority.clone(),
            relative_path: relative_path.clone(),
            mode: *mode,
            replace_existing: *replace_existing,
        },
        PrepareOperationV1::PlaceFile {
            authority,
            relative_path,
            artifact_id,
            mode,
            replace_existing,
        } => PrepareOperationWireV1::PlaceFile {
            authority: authority.clone(),
            relative_path: relative_path.clone(),
            artifact_id: artifact_id.clone(),
            mode: *mode,
            replace_existing: *replace_existing,
        },
        PrepareOperationV1::PlaceSymlink {
            authority,
            relative_path,
            object,
            replace_existing,
        } => PrepareOperationWireV1::PlaceSymlink {
            authority: authority.clone(),
            relative_path: relative_path.clone(),
            object: object.clone(),
            replace_existing: *replace_existing,
        },
        PrepareOperationV1::PlaceTree {
            authority,
            relative_path,
            tree,
            archive_provenance,
            replace_existing,
        } => PrepareOperationWireV1::PlaceTree {
            authority: authority.clone(),
            relative_path: relative_path.clone(),
            tree: tree.clone(),
            archive_provenance: archive_provenance.as_ref().map(archive_provenance_to_wire),
            replace_existing: *replace_existing,
        },
        PrepareOperationV1::RemoveLeaf {
            authority,
            relative_path,
        } => PrepareOperationWireV1::RemoveLeaf {
            authority: authority.clone(),
            relative_path: relative_path.clone(),
        },
        PrepareOperationV1::AssertAbsent {
            authority,
            relative_path,
        } => PrepareOperationWireV1::AssertAbsent {
            authority: authority.clone(),
            relative_path: relative_path.clone(),
        },
        PrepareOperationV1::AssertExact {
            authority,
            relative_path,
            state,
        } => PrepareOperationWireV1::AssertExact {
            authority: authority.clone(),
            relative_path: relative_path.clone(),
            state: target_state_to_wire(state),
        },
    }
}

fn operation_request_from_wire(
    operation: PrepareOperationWireV1,
) -> Result<PrepareOperationV1, MachineReadError> {
    match operation {
        PrepareOperationWireV1::EnsureDirectory {
            authority,
            relative_path,
            mode,
            replace_existing: false,
        } => PrepareOperationV1::ensure_directory(authority, relative_path, mode),
        PrepareOperationWireV1::EnsureDirectory {
            authority,
            relative_path,
            mode,
            replace_existing: true,
        } => PrepareOperationV1::replace_directory(authority, relative_path, mode),
        PrepareOperationWireV1::PlaceFile {
            authority,
            relative_path,
            artifact_id,
            mode,
            replace_existing: false,
        } => PrepareOperationV1::place_file(authority, relative_path, artifact_id, mode),
        PrepareOperationWireV1::PlaceFile {
            authority,
            relative_path,
            artifact_id,
            mode,
            replace_existing: true,
        } => PrepareOperationV1::replace_file(authority, relative_path, artifact_id, mode),
        PrepareOperationWireV1::PlaceSymlink {
            authority,
            relative_path,
            object,
            replace_existing: false,
        } => PrepareOperationV1::place_symlink(authority, relative_path, object),
        PrepareOperationWireV1::PlaceSymlink {
            authority,
            relative_path,
            object,
            replace_existing: true,
        } => PrepareOperationV1::replace_symlink(authority, relative_path, object),
        PrepareOperationWireV1::PlaceTree {
            authority,
            relative_path,
            tree,
            archive_provenance: None,
            replace_existing: false,
        } => PrepareOperationV1::place_tree(authority, relative_path, tree),
        PrepareOperationWireV1::PlaceTree {
            authority,
            relative_path,
            tree,
            archive_provenance: None,
            replace_existing: true,
        } => PrepareOperationV1::replace_tree(authority, relative_path, tree),
        PrepareOperationWireV1::PlaceTree {
            authority,
            relative_path,
            tree,
            archive_provenance: Some(provenance),
            replace_existing: false,
        } => PrepareOperationV1::place_archive_tree(
            authority,
            relative_path,
            tree,
            archive_provenance_from_wire(provenance)?,
        ),
        PrepareOperationWireV1::PlaceTree {
            authority,
            relative_path,
            tree,
            archive_provenance: Some(provenance),
            replace_existing: true,
        } => PrepareOperationV1::replace_archive_tree(
            authority,
            relative_path,
            tree,
            archive_provenance_from_wire(provenance)?,
        ),
        PrepareOperationWireV1::RemoveLeaf {
            authority,
            relative_path,
        } => PrepareOperationV1::remove_leaf(authority, relative_path),
        PrepareOperationWireV1::AssertAbsent {
            authority,
            relative_path,
        } => PrepareOperationV1::assert_absent(authority, relative_path),
        PrepareOperationWireV1::AssertExact {
            authority,
            relative_path,
            state,
        } => PrepareOperationV1::assert_exact(
            authority,
            relative_path,
            target_state_from_wire(state)?,
        ),
    }
    .map_err(deployment_read_error)
}

fn prepared_to_wire(deployment: &PreparedDeploymentV1) -> PreparedDeploymentWireV1 {
    PreparedDeploymentWireV1 {
        plan_id: deployment.plan_id().clone(),
        namespace: deployment.namespace().clone(),
        expected_head: deployment.expected_head().cloned(),
        transition: transition_to_wire(deployment.transition()),
        lifecycle: lifecycle_to_wire(deployment.lifecycle_state()),
        restore_point: deployment.restore_point().map(restore_point_to_wire),
        retention: retention_authority_to_wire(deployment.retention_authority()),
        tracked_root: deployment.tracking_review().map(prepared_tracking_to_wire),
        graph_digest: deployment.graph_digest().clone(),
        inputs: deployment.inputs().iter().map(input_to_wire).collect(),
        transforms: deployment
            .transforms()
            .iter()
            .map(transform_to_wire)
            .collect(),
        artifacts: deployment
            .artifacts()
            .iter()
            .map(artifact_descriptor_to_wire)
            .collect(),
        findings: deployment
            .findings()
            .iter()
            .map(policy_finding_to_wire)
            .collect(),
        approval_digest: deployment.approval_digest().clone(),
        operations: deployment
            .operations()
            .iter()
            .map(operation_request_to_wire)
            .collect(),
    }
}

fn prepared_from_wire(
    deployment: PreparedDeploymentWireV1,
) -> Result<PreparedDeploymentV1, MachineReadError> {
    let findings = deployment
        .findings
        .into_iter()
        .map(policy_finding_from_wire)
        .collect::<Result<Vec<_>, _>>()?;
    let mut finding_ids = HashSet::new();
    if findings
        .iter()
        .any(|finding| !finding_ids.insert(finding.id().as_str()))
    {
        return Err(MachineReadError::InvalidEnvelope(
            "prepared result repeats a policy finding ID".to_owned(),
        ));
    }
    let expected_approval = policy_approval_digest_v1(
        findings
            .iter()
            .map(|finding| (finding.id().clone(), finding.approval_required())),
    );
    if deployment.approval_digest != expected_approval {
        return Err(MachineReadError::InvalidEnvelope(
            "prepared result approval digest does not match its findings".to_owned(),
        ));
    }
    let lifecycle = lifecycle_from_wire(deployment.lifecycle);
    let transition = transition_from_wire(deployment.transition);
    let restore_point = deployment
        .restore_point
        .map(restore_point_from_wire)
        .transpose()?;
    let retention = retention_authority_from_wire(deployment.retention)?;
    let tracked_root = deployment
        .tracked_root
        .map(prepared_tracking_from_wire)
        .transpose()?;
    Ok(PreparedDeploymentV1::from(PreparedDeploymentPartsV1 {
        plan_id: deployment.plan_id,
        namespace: deployment.namespace,
        expected_head: deployment.expected_head,
        graph_digest: deployment.graph_digest,
        inputs: deployment
            .inputs
            .into_iter()
            .map(input_from_wire)
            .collect::<Result<_, _>>()?,
        transforms: deployment
            .transforms
            .into_iter()
            .map(transform_from_wire)
            .collect::<Result<_, _>>()?,
        artifacts: deployment
            .artifacts
            .into_iter()
            .map(artifact_descriptor_from_wire)
            .collect::<Result<_, _>>()?,
        findings,
        approval_digest: deployment.approval_digest,
        operations: deployment
            .operations
            .into_iter()
            .map(operation_request_from_wire)
            .collect::<Result<_, _>>()?,
    })
    .with_transition(transition)
    .with_lifecycle_state(lifecycle)
    .with_restore_point(restore_point)
    .with_retention_authority(retention)
    .with_tracking_review(tracked_root))
}

fn prepared_tracking_to_wire(tracked: &PreparedTrackingReviewV1) -> PreparedTrackingReviewWireV1 {
    PreparedTrackingReviewWireV1 {
        source_locator: tracked.source_locator().to_owned(),
        moving_selector: tracked.moving_selector().to_owned(),
        applied_revision: tracked.applied_revision().to_owned(),
        root_tree_digest: tracked.root_tree_digest().clone(),
        source_subdir: tracked.source_subdir().to_owned(),
        config_entry_point: tracked.config_entry_point().to_owned(),
        selected_profile: tracked.selected_profile().clone(),
        target_authority: tracked.target_authority().clone(),
        acquisition_grants: tracked
            .acquisition_grants()
            .iter()
            .map(|grant| PreparedTrackingAcquisitionGrantWireV1 {
                kind: match grant.kind() {
                    PreparedTrackingAcquisitionKindV1::LocalSource => {
                        PreparedTrackingAcquisitionKindWireV1::LocalSource
                    }
                    PreparedTrackingAcquisitionKindV1::GitSource => {
                        PreparedTrackingAcquisitionKindWireV1::GitSource
                    }
                },
                locator: grant.locator().to_owned(),
            })
            .collect(),
        component_grants: tracked.component_grants().to_vec(),
    }
}

fn prepared_tracking_from_wire(
    tracked: PreparedTrackingReviewWireV1,
) -> Result<PreparedTrackingReviewV1, MachineReadError> {
    let acquisition_grants = tracked
        .acquisition_grants
        .into_iter()
        .map(|grant| {
            PreparedTrackingAcquisitionGrantV1::new(
                match grant.kind {
                    PreparedTrackingAcquisitionKindWireV1::LocalSource => {
                        PreparedTrackingAcquisitionKindV1::LocalSource
                    }
                    PreparedTrackingAcquisitionKindWireV1::GitSource => {
                        PreparedTrackingAcquisitionKindV1::GitSource
                    }
                },
                grant.locator,
            )
        })
        .collect::<Result<Vec<_>, _>>()
        .map_err(deployment_read_error)?;
    PreparedTrackingReviewV1::try_from(PreparedTrackingReviewPartsV1 {
        source_locator: tracked.source_locator,
        moving_selector: tracked.moving_selector,
        applied_revision: tracked.applied_revision,
        root_tree_digest: tracked.root_tree_digest,
        source_subdir: tracked.source_subdir,
        config_entry_point: tracked.config_entry_point,
        selected_profile: tracked.selected_profile,
        target_authority: tracked.target_authority,
        acquisition_grants,
        component_grants: tracked.component_grants,
    })
    .map_err(deployment_read_error)
}

const fn lifecycle_to_wire(value: LifecycleStateViewV1) -> LifecycleStateWireV1 {
    match value {
        <LifecycleStateViewV1>::Enabled => <LifecycleStateWireV1>::Enabled,
        <LifecycleStateViewV1>::Disabled => <LifecycleStateWireV1>::Disabled,
    }
}

const fn lifecycle_from_wire(value: LifecycleStateWireV1) -> LifecycleStateViewV1 {
    match value {
        <LifecycleStateWireV1>::Enabled => <LifecycleStateViewV1>::Enabled,
        <LifecycleStateWireV1>::Disabled => <LifecycleStateViewV1>::Disabled,
    }
}

fn tracked_root_to_wire(tracked: &TrackedRootInspectionV1) -> TrackedRootInspectionWireV1 {
    TrackedRootInspectionWireV1 {
        moving_selector: tracked.moving_selector().to_owned(),
        applied_revision: tracked.applied_revision().to_owned(),
        root_tree_digest: tracked.root_tree_digest().clone(),
    }
}

fn tracked_root_from_wire(
    tracked: TrackedRootInspectionWireV1,
) -> Result<TrackedRootInspectionV1, MachineReadError> {
    if tracked.moving_selector.is_empty()
        || tracked.moving_selector.len() > 1024
        || tracked.moving_selector.chars().any(char::is_control)
    {
        return Err(MachineReadError::InvalidEnvelope(
            "tracked-root moving selector is invalid".to_owned(),
        ));
    }
    let revision = tracked.applied_revision.as_bytes();
    let valid_revision = [
        (b"sha1-".as_slice(), 40_usize),
        (b"sha256-".as_slice(), 64_usize),
    ]
    .into_iter()
    .any(|(prefix, digits)| {
        revision.strip_prefix(prefix).is_some_and(|suffix| {
            suffix.len() == digits
                && suffix
                    .iter()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
        })
    });
    if !valid_revision {
        return Err(MachineReadError::InvalidEnvelope(
            "tracked-root applied revision is invalid".to_owned(),
        ));
    }
    Ok(TrackedRootInspectionV1::new(
        tracked.moving_selector,
        tracked.applied_revision,
        tracked.root_tree_digest,
    ))
}

fn artifact_descriptor_to_wire(artifact: &ArtifactDescriptorV1) -> ArtifactDescriptorWireV1 {
    ArtifactDescriptorWireV1 {
        id: artifact.id().clone(),
        digest: artifact.digest().clone(),
        byte_len: artifact.byte_len(),
        media_type: artifact.media_type().to_owned(),
    }
}

fn artifact_descriptor_from_wire(
    artifact: ArtifactDescriptorWireV1,
) -> Result<ArtifactDescriptorV1, MachineReadError> {
    PrepareArtifactV1::new(artifact.id.clone(), Vec::new(), artifact.media_type.clone())
        .map_err(deployment_read_error)?;
    Ok(ArtifactDescriptorV1::new(
        artifact.id,
        artifact.digest,
        artifact.byte_len,
        artifact.media_type,
    ))
}

fn policy_finding_to_wire(finding: &PolicyFindingV1) -> PolicyFindingWireV1 {
    PolicyFindingWireV1 {
        id: finding.id().clone(),
        code: finding.code().to_owned(),
        message: finding.message().to_owned(),
        approval_required: finding.approval_required(),
    }
}

fn policy_finding_from_wire(
    finding: PolicyFindingWireV1,
) -> Result<PolicyFindingV1, MachineReadError> {
    PreparePolicyFindingV1::new(
        finding.code.clone(),
        finding.message.clone(),
        finding.approval_required,
    )
    .map_err(deployment_read_error)?;
    let expected = policy_finding_id_v1(&finding.code, &finding.message, finding.approval_required);
    if finding.id != expected {
        return Err(MachineReadError::InvalidEnvelope(
            "policy finding ID does not match its contents".to_owned(),
        ));
    }
    Ok(PolicyFindingV1::new(
        finding.id,
        finding.code,
        finding.message,
        finding.approval_required,
    ))
}

fn artifact_to_wire(artifact: &ArtifactV1) -> ArtifactWireV1 {
    ArtifactWireV1 {
        descriptor: artifact_descriptor_to_wire(artifact.descriptor()),
        bytes_hex: encode_hex(artifact.bytes()),
    }
}

fn artifact_from_wire(artifact: ArtifactWireV1) -> Result<ArtifactV1, MachineReadError> {
    let descriptor = artifact_descriptor_from_wire(artifact.descriptor)?;
    let bytes = decode_hex(&artifact.bytes_hex)?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) != descriptor.byte_len()
        || Digest::sha256(&bytes) != *descriptor.digest()
    {
        return Err(MachineReadError::InvalidEnvelope(
            "artifact bytes differ from their descriptor".to_owned(),
        ));
    }
    Ok(ArtifactV1::new(descriptor, bytes))
}

fn apply_outcome_to_wire(outcome: &ApplyOutcomeV1) -> ApplyOutcomeWireV1 {
    ApplyOutcomeWireV1 {
        plan_id: outcome.plan_id().clone(),
        namespace: outcome.namespace().clone(),
        previous_head: outcome.previous_head().cloned(),
        head: outcome.next_head().cloned(),
    }
}

fn apply_outcome_from_wire(
    outcome: ApplyOutcomeWireV1,
) -> Result<ApplyOutcomeV1, MachineReadError> {
    match outcome.head {
        Some(head) => Ok(ApplyOutcomeV1::new(
            outcome.plan_id,
            outcome.namespace,
            outcome.previous_head,
            head,
        )),
        None => outcome
            .previous_head
            .map(|previous_head| {
                ApplyOutcomeV1::removed(outcome.plan_id, outcome.namespace, previous_head)
            })
            .ok_or_else(|| {
                MachineReadError::InvalidEnvelope(
                    "namespace-removal commit result requires a previous head".to_owned(),
                )
            }),
    }
}

fn state_to_wire(state: &StateViewV1) -> StateViewWireV1 {
    StateViewWireV1 {
        namespace: state.namespace().clone(),
        head: state.head().cloned(),
    }
}

fn state_from_wire(state: StateViewWireV1) -> StateViewV1 {
    StateViewV1::new(state.namespace, state.head)
}

fn recovery_to_wire(outcome: &RecoveryOutcomeV1) -> RecoveryOutcomeWireV1 {
    match outcome {
        RecoveryOutcomeV1::NoTransaction => RecoveryOutcomeWireV1::NoTransaction {},
        RecoveryOutcomeV1::Recovered { namespace, head } => RecoveryOutcomeWireV1::Recovered {
            namespace: namespace.clone(),
            head: head.clone(),
        },
    }
}

fn recovery_from_wire(outcome: RecoveryOutcomeWireV1) -> RecoveryOutcomeV1 {
    match outcome {
        RecoveryOutcomeWireV1::NoTransaction {} => RecoveryOutcomeV1::NoTransaction,
        RecoveryOutcomeWireV1::Recovered { namespace, head } => {
            RecoveryOutcomeV1::recovered(namespace, head)
        }
    }
}

const fn prune_to_wire(outcome: PruneOutcomeV1) -> PruneOutcomeWireV1 {
    PruneOutcomeWireV1 {
        prepared_records: outcome.prepared_records,
        artifact_blobs: outcome.artifact_blobs,
        state_generations: outcome.state_generations,
        pack_objects: outcome.pack_objects,
        canonical_files: outcome.canonical_files,
        canonical_symlinks: outcome.canonical_symlinks,
        canonical_trees: outcome.canonical_trees,
    }
}

const fn prune_from_wire(outcome: PruneOutcomeWireV1) -> PruneOutcomeV1 {
    PruneOutcomeV1 {
        prepared_records: outcome.prepared_records,
        artifact_blobs: outcome.artifact_blobs,
        state_generations: outcome.state_generations,
        pack_objects: outcome.pack_objects,
        canonical_files: outcome.canonical_files,
        canonical_symlinks: outcome.canonical_symlinks,
        canonical_trees: outcome.canonical_trees,
    }
}

fn deployment_read_error(error: impl fmt::Display) -> MachineReadError {
    MachineReadError::InvalidEnvelope(format!("invalid deployment DTO: {error}"))
}

fn deserialize_transform_resource_wires<'de, D: Deserializer<'de>>(
    d: D,
) -> Result<Vec<TransformResourceWireV1>, D::Error> {
    bounded_seq(d, MAX_TRANSFORM_RESOURCES_V1, "transform resources")
}

fn deserialize_transform_diagnostic_wires<'de, D: Deserializer<'de>>(
    d: D,
) -> Result<Vec<TransformDiagnosticWireV1>, D::Error> {
    bounded_seq(d, MAX_TRANSFORM_DIAGNOSTICS_V1, "transform diagnostics")
}

fn deserialize_transform_diagnostic_note_wires<'de, D: Deserializer<'de>>(
    d: D,
) -> Result<Vec<String>, D::Error> {
    bounded_seq(
        d,
        MAX_TRANSFORM_DIAGNOSTIC_NOTES_V1,
        "transform diagnostic notes",
    )
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

fn decode_hex(encoded: &str) -> Result<Vec<u8>, MachineReadError> {
    if !encoded.len().is_multiple_of(2)
        || !encoded
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(MachineReadError::InvalidEnvelope(
            "byte strings must use an even number of lowercase hexadecimal digits".to_owned(),
        ));
    }
    encoded
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let high = hex_nibble(pair[0]);
            let low = hex_nibble(pair[1]);
            Ok((high << 4) | low)
        })
        .collect()
}

fn hex_nibble(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        _ => unreachable!("validated hexadecimal digit"),
    }
}

fn error_to_wire(error: &MachineErrorV1) -> ErrorWireV1 {
    ErrorWireV1 {
        category: category_to_wire(error.category()),
        code: error_code_to_wire(error.code()),
        message: error.message().as_str().to_owned(),
        details: error_details_to_wire(error.details()),
        diagnostics: error
            .diagnostics()
            .iter()
            .map(|diagnostic| DiagnosticWireV1 {
                severity: severity_to_wire(diagnostic.severity()),
                code: diagnostic.code().as_str().to_owned(),
                message: diagnostic.message().as_str().to_owned(),
            })
            .collect(),
    }
}

fn error_from_wire(error: ErrorWireV1) -> Result<MachineErrorV1, MachineReadError> {
    let diagnostics = error
        .diagnostics
        .into_iter()
        .map(|diagnostic| {
            Ok(MachineDiagnosticV1::new(
                severity_from_wire(diagnostic.severity),
                MachineCodeV1::new(diagnostic.code).map_err(MachineReadError::InvalidSemantics)?,
                MachineTextV1::new(diagnostic.message)
                    .map_err(MachineReadError::InvalidSemantics)?,
            ))
        })
        .collect::<Result<Vec<_>, MachineReadError>>()?;
    MachineErrorV1::new(
        category_from_wire(error.category),
        error_code_from_wire(error.code),
        MachineTextV1::new(error.message).map_err(MachineReadError::InvalidSemantics)?,
        error_details_from_wire(error.details),
        diagnostics,
    )
    .map_err(MachineReadError::InvalidSemantics)
}

const fn category_to_wire(value: MachineErrorCategoryV1) -> ErrorCategoryWireV1 {
    match value {
        <MachineErrorCategoryV1>::InvalidRequest => <ErrorCategoryWireV1>::InvalidRequest,
        <MachineErrorCategoryV1>::Unsupported => <ErrorCategoryWireV1>::Unsupported,
        <MachineErrorCategoryV1>::NotFound => <ErrorCategoryWireV1>::NotFound,
        <MachineErrorCategoryV1>::PermissionDenied => <ErrorCategoryWireV1>::PermissionDenied,
        <MachineErrorCategoryV1>::Conflict => <ErrorCategoryWireV1>::Conflict,
        <MachineErrorCategoryV1>::ResourceLimit => <ErrorCategoryWireV1>::ResourceLimit,
        <MachineErrorCategoryV1>::Unavailable => <ErrorCategoryWireV1>::Unavailable,
        <MachineErrorCategoryV1>::Internal => <ErrorCategoryWireV1>::Internal,
    }
}

const fn category_from_wire(value: ErrorCategoryWireV1) -> MachineErrorCategoryV1 {
    match value {
        <ErrorCategoryWireV1>::InvalidRequest => <MachineErrorCategoryV1>::InvalidRequest,
        <ErrorCategoryWireV1>::Unsupported => <MachineErrorCategoryV1>::Unsupported,
        <ErrorCategoryWireV1>::NotFound => <MachineErrorCategoryV1>::NotFound,
        <ErrorCategoryWireV1>::PermissionDenied => <MachineErrorCategoryV1>::PermissionDenied,
        <ErrorCategoryWireV1>::Conflict => <MachineErrorCategoryV1>::Conflict,
        <ErrorCategoryWireV1>::ResourceLimit => <MachineErrorCategoryV1>::ResourceLimit,
        <ErrorCategoryWireV1>::Unavailable => <MachineErrorCategoryV1>::Unavailable,
        <ErrorCategoryWireV1>::Internal => <MachineErrorCategoryV1>::Internal,
    }
}

const fn error_code_to_wire(value: MachineErrorCodeV1) -> ErrorCodeWireV1 {
    match value {
        <MachineErrorCodeV1>::MalformedJson => <ErrorCodeWireV1>::MalformedJson,
        <MachineErrorCodeV1>::InvalidRequest => <ErrorCodeWireV1>::InvalidRequest,
        <MachineErrorCodeV1>::UnsupportedMachineVersion => {
            <ErrorCodeWireV1>::UnsupportedMachineVersion
        }
        <MachineErrorCodeV1>::FrameResourceLimit => <ErrorCodeWireV1>::FrameResourceLimit,
        <MachineErrorCodeV1>::ReadOnlyStore => <ErrorCodeWireV1>::ReadOnlyStore,
        <MachineErrorCodeV1>::StoreNotReady => <ErrorCodeWireV1>::StoreNotReady,
        <MachineErrorCodeV1>::StateParentMissing => <ErrorCodeWireV1>::StateParentMissing,
        <MachineErrorCodeV1>::UnsafeDirectory => <ErrorCodeWireV1>::UnsafeDirectory,
        <MachineErrorCodeV1>::RootObservationChanged => <ErrorCodeWireV1>::RootObservationChanged,
        <MachineErrorCodeV1>::StateParentObservationChanged => {
            <ErrorCodeWireV1>::StateParentObservationChanged
        }
        <MachineErrorCodeV1>::MalformedStoreMetadata => <ErrorCodeWireV1>::MalformedStoreMetadata,
        <MachineErrorCodeV1>::UnsupportedStoreVersion => <ErrorCodeWireV1>::UnsupportedStoreVersion,
        <MachineErrorCodeV1>::StoreIo => <ErrorCodeWireV1>::StoreIo,
        <MachineErrorCodeV1>::PlanNotFound => <ErrorCodeWireV1>::PlanNotFound,
        <MachineErrorCodeV1>::ArtifactNotFound => <ErrorCodeWireV1>::ArtifactNotFound,
        <MachineErrorCodeV1>::ApprovalMismatch => <ErrorCodeWireV1>::ApprovalMismatch,
        <MachineErrorCodeV1>::StalePlan => <ErrorCodeWireV1>::StalePlan,
        <MachineErrorCodeV1>::RecoveryRequired => <ErrorCodeWireV1>::RecoveryRequired,
        <MachineErrorCodeV1>::OperationBusy => <ErrorCodeWireV1>::OperationBusy,
        <MachineErrorCodeV1>::InvalidDeployment => <ErrorCodeWireV1>::InvalidDeployment,
        <MachineErrorCodeV1>::UnsafeTarget => <ErrorCodeWireV1>::UnsafeTarget,
        <MachineErrorCodeV1>::CorruptStore => <ErrorCodeWireV1>::CorruptStore,
        <MachineErrorCodeV1>::CorruptArtifact => <ErrorCodeWireV1>::CorruptArtifact,
        <MachineErrorCodeV1>::DeploymentIo => <ErrorCodeWireV1>::DeploymentIo,
        <MachineErrorCodeV1>::InternalEngineError => <ErrorCodeWireV1>::InternalEngineError,
    }
}

const fn error_code_from_wire(value: ErrorCodeWireV1) -> MachineErrorCodeV1 {
    match value {
        <ErrorCodeWireV1>::MalformedJson => <MachineErrorCodeV1>::MalformedJson,
        <ErrorCodeWireV1>::InvalidRequest => <MachineErrorCodeV1>::InvalidRequest,
        <ErrorCodeWireV1>::UnsupportedMachineVersion => {
            <MachineErrorCodeV1>::UnsupportedMachineVersion
        }
        <ErrorCodeWireV1>::FrameResourceLimit => <MachineErrorCodeV1>::FrameResourceLimit,
        <ErrorCodeWireV1>::ReadOnlyStore => <MachineErrorCodeV1>::ReadOnlyStore,
        <ErrorCodeWireV1>::StoreNotReady => <MachineErrorCodeV1>::StoreNotReady,
        <ErrorCodeWireV1>::StateParentMissing => <MachineErrorCodeV1>::StateParentMissing,
        <ErrorCodeWireV1>::UnsafeDirectory => <MachineErrorCodeV1>::UnsafeDirectory,
        <ErrorCodeWireV1>::RootObservationChanged => <MachineErrorCodeV1>::RootObservationChanged,
        <ErrorCodeWireV1>::StateParentObservationChanged => {
            <MachineErrorCodeV1>::StateParentObservationChanged
        }
        <ErrorCodeWireV1>::MalformedStoreMetadata => <MachineErrorCodeV1>::MalformedStoreMetadata,
        <ErrorCodeWireV1>::UnsupportedStoreVersion => <MachineErrorCodeV1>::UnsupportedStoreVersion,
        <ErrorCodeWireV1>::StoreIo => <MachineErrorCodeV1>::StoreIo,
        <ErrorCodeWireV1>::PlanNotFound => <MachineErrorCodeV1>::PlanNotFound,
        <ErrorCodeWireV1>::ArtifactNotFound => <MachineErrorCodeV1>::ArtifactNotFound,
        <ErrorCodeWireV1>::ApprovalMismatch => <MachineErrorCodeV1>::ApprovalMismatch,
        <ErrorCodeWireV1>::StalePlan => <MachineErrorCodeV1>::StalePlan,
        <ErrorCodeWireV1>::RecoveryRequired => <MachineErrorCodeV1>::RecoveryRequired,
        <ErrorCodeWireV1>::OperationBusy => <MachineErrorCodeV1>::OperationBusy,
        <ErrorCodeWireV1>::InvalidDeployment => <MachineErrorCodeV1>::InvalidDeployment,
        <ErrorCodeWireV1>::UnsafeTarget => <MachineErrorCodeV1>::UnsafeTarget,
        <ErrorCodeWireV1>::CorruptStore => <MachineErrorCodeV1>::CorruptStore,
        <ErrorCodeWireV1>::CorruptArtifact => <MachineErrorCodeV1>::CorruptArtifact,
        <ErrorCodeWireV1>::DeploymentIo => <MachineErrorCodeV1>::DeploymentIo,
        <ErrorCodeWireV1>::InternalEngineError => <MachineErrorCodeV1>::InternalEngineError,
    }
}
const fn severity_to_wire(value: DiagnosticSeverityV1) -> DiagnosticSeverityWireV1 {
    match value {
        <DiagnosticSeverityV1>::Error => <DiagnosticSeverityWireV1>::Error,
        <DiagnosticSeverityV1>::Warning => <DiagnosticSeverityWireV1>::Warning,
        <DiagnosticSeverityV1>::Notice => <DiagnosticSeverityWireV1>::Notice,
    }
}

const fn severity_from_wire(value: DiagnosticSeverityWireV1) -> DiagnosticSeverityV1 {
    match value {
        <DiagnosticSeverityWireV1>::Error => <DiagnosticSeverityV1>::Error,
        <DiagnosticSeverityWireV1>::Warning => <DiagnosticSeverityV1>::Warning,
        <DiagnosticSeverityWireV1>::Notice => <DiagnosticSeverityV1>::Notice,
    }
}
const fn directory_to_wire(value: StoreDirectoryV1) -> StoreDirectoryWireV1 {
    match value {
        <StoreDirectoryV1>::StateParent => <StoreDirectoryWireV1>::StateParent,
        <StoreDirectoryV1>::V1Root => <StoreDirectoryWireV1>::V1Root,
    }
}

const fn directory_from_wire(value: StoreDirectoryWireV1) -> StoreDirectoryV1 {
    match value {
        <StoreDirectoryWireV1>::StateParent => <StoreDirectoryV1>::StateParent,
        <StoreDirectoryWireV1>::V1Root => <StoreDirectoryV1>::V1Root,
    }
}
const fn safety_to_wire(value: DirectorySafetyReasonV1) -> DirectorySafetyWireV1 {
    match value {
        <DirectorySafetyReasonV1>::WrongOwner => <DirectorySafetyWireV1>::WrongOwner,
        <DirectorySafetyReasonV1>::GroupOrOtherWritable => {
            <DirectorySafetyWireV1>::GroupOrOtherWritable
        }
        <DirectorySafetyReasonV1>::SpecialModeBitsSet => {
            <DirectorySafetyWireV1>::SpecialModeBitsSet
        }
        <DirectorySafetyReasonV1>::UnexpectedMode => <DirectorySafetyWireV1>::UnexpectedMode,
        <DirectorySafetyReasonV1>::AncestryLimitExceeded => {
            <DirectorySafetyWireV1>::AncestryLimitExceeded
        }
    }
}

const fn safety_from_wire(value: DirectorySafetyWireV1) -> DirectorySafetyReasonV1 {
    match value {
        <DirectorySafetyWireV1>::WrongOwner => <DirectorySafetyReasonV1>::WrongOwner,
        <DirectorySafetyWireV1>::GroupOrOtherWritable => {
            <DirectorySafetyReasonV1>::GroupOrOtherWritable
        }
        <DirectorySafetyWireV1>::SpecialModeBitsSet => {
            <DirectorySafetyReasonV1>::SpecialModeBitsSet
        }
        <DirectorySafetyWireV1>::UnexpectedMode => <DirectorySafetyReasonV1>::UnexpectedMode,
        <DirectorySafetyWireV1>::AncestryLimitExceeded => {
            <DirectorySafetyReasonV1>::AncestryLimitExceeded
        }
    }
}
const fn root_to_wire(value: StoreRootV1) -> StoreRootWireV1 {
    match value {
        <StoreRootV1>::V1 => <StoreRootWireV1>::V1,
    }
}

const fn root_from_wire(value: StoreRootWireV1) -> StoreRootV1 {
    match value {
        <StoreRootWireV1>::V1 => <StoreRootV1>::V1,
    }
}

fn error_details_to_wire(details: MachineErrorDetailsV1) -> ErrorDetailsWireV1 {
    match details {
        MachineErrorDetailsV1::None => ErrorDetailsWireV1::None {},
        MachineErrorDetailsV1::CurrentStatus(status) => ErrorDetailsWireV1::CurrentStatus {
            status: status_to_wire(status),
        },
        MachineErrorDetailsV1::UnsafeDirectory { directory, reason } => {
            ErrorDetailsWireV1::UnsafeDirectory {
                directory: directory_to_wire(directory),
                reason: safety_to_wire(reason),
            }
        }
        MachineErrorDetailsV1::RootObservation(root) => ErrorDetailsWireV1::RootObservation {
            root: root_to_wire(root),
        },
        MachineErrorDetailsV1::StoreMetadata(reason) => ErrorDetailsWireV1::StoreMetadata {
            reason: metadata_to_wire(reason),
        },
        MachineErrorDetailsV1::UnsupportedSchema {
            schema,
            expected,
            found,
        } => ErrorDetailsWireV1::UnsupportedSchema {
            schema: schema_to_wire(schema),
            expected,
            found,
        },
    }
}

fn error_details_from_wire(details: ErrorDetailsWireV1) -> MachineErrorDetailsV1 {
    match details {
        ErrorDetailsWireV1::None {} => MachineErrorDetailsV1::None,
        ErrorDetailsWireV1::CurrentStatus { status } => {
            MachineErrorDetailsV1::CurrentStatus(status_from_wire(status))
        }
        ErrorDetailsWireV1::UnsafeDirectory { directory, reason } => {
            MachineErrorDetailsV1::UnsafeDirectory {
                directory: directory_from_wire(directory),
                reason: safety_from_wire(reason),
            }
        }
        ErrorDetailsWireV1::RootObservation { root } => {
            MachineErrorDetailsV1::RootObservation(root_from_wire(root))
        }
        ErrorDetailsWireV1::StoreMetadata { reason } => {
            MachineErrorDetailsV1::StoreMetadata(metadata_from_wire(reason))
        }
        ErrorDetailsWireV1::UnsupportedSchema {
            schema,
            expected,
            found,
        } => MachineErrorDetailsV1::UnsupportedSchema {
            schema: schema_from_wire(schema),
            expected,
            found,
        },
    }
}

const fn metadata_to_wire(value: malm_types::StoreMetadataReasonV1) -> StoreMetadataWireV1 {
    match value {
        <malm_types::StoreMetadataReasonV1>::MarkerMissingWithOtherEntries => {
            <StoreMetadataWireV1>::MarkerMissingWithOtherEntries
        }
        <malm_types::StoreMetadataReasonV1>::MarkerNotRegular => {
            <StoreMetadataWireV1>::MarkerNotRegular
        }
        <malm_types::StoreMetadataReasonV1>::MarkerTooLarge => {
            <StoreMetadataWireV1>::MarkerTooLarge
        }
        <malm_types::StoreMetadataReasonV1>::UnexpectedRootEntry => {
            <StoreMetadataWireV1>::UnexpectedRootEntry
        }
        <malm_types::StoreMetadataReasonV1>::InvalidRootEntry => {
            <StoreMetadataWireV1>::InvalidRootEntry
        }
        <malm_types::StoreMetadataReasonV1>::WrongOwner => <StoreMetadataWireV1>::WrongOwner,
        <malm_types::StoreMetadataReasonV1>::UnexpectedMode => {
            <StoreMetadataWireV1>::UnexpectedMode
        }
        <malm_types::StoreMetadataReasonV1>::MultipleLinks => <StoreMetadataWireV1>::MultipleLinks,
        <malm_types::StoreMetadataReasonV1>::ObservationChanged => {
            <StoreMetadataWireV1>::ObservationChanged
        }
        <malm_types::StoreMetadataReasonV1>::InvalidDescriptor => {
            <StoreMetadataWireV1>::InvalidDescriptor
        }
    }
}

const fn metadata_from_wire(value: StoreMetadataWireV1) -> malm_types::StoreMetadataReasonV1 {
    match value {
        <StoreMetadataWireV1>::MarkerMissingWithOtherEntries => {
            <malm_types::StoreMetadataReasonV1>::MarkerMissingWithOtherEntries
        }
        <StoreMetadataWireV1>::MarkerNotRegular => {
            <malm_types::StoreMetadataReasonV1>::MarkerNotRegular
        }
        <StoreMetadataWireV1>::MarkerTooLarge => {
            <malm_types::StoreMetadataReasonV1>::MarkerTooLarge
        }
        <StoreMetadataWireV1>::UnexpectedRootEntry => {
            <malm_types::StoreMetadataReasonV1>::UnexpectedRootEntry
        }
        <StoreMetadataWireV1>::InvalidRootEntry => {
            <malm_types::StoreMetadataReasonV1>::InvalidRootEntry
        }
        <StoreMetadataWireV1>::WrongOwner => <malm_types::StoreMetadataReasonV1>::WrongOwner,
        <StoreMetadataWireV1>::UnexpectedMode => {
            <malm_types::StoreMetadataReasonV1>::UnexpectedMode
        }
        <StoreMetadataWireV1>::MultipleLinks => <malm_types::StoreMetadataReasonV1>::MultipleLinks,
        <StoreMetadataWireV1>::ObservationChanged => {
            <malm_types::StoreMetadataReasonV1>::ObservationChanged
        }
        <StoreMetadataWireV1>::InvalidDescriptor => {
            <malm_types::StoreMetadataReasonV1>::InvalidDescriptor
        }
    }
}
const fn schema_to_wire(value: SchemaFamilyV1) -> SchemaFamilyWireV1 {
    match value {
        <SchemaFamilyV1>::Machine => <SchemaFamilyWireV1>::Machine,
        <SchemaFamilyV1>::Store => <SchemaFamilyWireV1>::Store,
    }
}

const fn schema_from_wire(value: SchemaFamilyWireV1) -> SchemaFamilyV1 {
    match value {
        <SchemaFamilyWireV1>::Machine => <SchemaFamilyV1>::Machine,
        <SchemaFamilyWireV1>::Store => <SchemaFamilyV1>::Store,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// States which operation results carry prepared deployments.
    ///
    /// This explicit list is independent of `reviewed_deployment`, so it can
    /// verify that function's review partition.
    fn review_expectations() -> Vec<(MachineOperationV1, bool)> {
        vec![
            (MachineOperationV1::StoreStatus, false),
            (MachineOperationV1::InitializeStore, false),
            (MachineOperationV1::Prepare, true),
            (MachineOperationV1::Plan, true),
            (MachineOperationV1::Artifact, false),
            (MachineOperationV1::Commit, false),
            (MachineOperationV1::State, false),
            (MachineOperationV1::Recover, false),
            (MachineOperationV1::Prune, false),
            (MachineOperationV1::Checkout, true),
            (MachineOperationV1::Disable, true),
            (MachineOperationV1::Enable, true),
            (MachineOperationV1::RemoveNamespace, true),
            (MachineOperationV1::SetHistoryRetention, true),
            (MachineOperationV1::Pin, true),
            (MachineOperationV1::Unpin, true),
            (MachineOperationV1::AddRestorePoint, true),
            (MachineOperationV1::DropRestorePoint, true),
            (MachineOperationV1::Catalog, false),
            (MachineOperationV1::Namespace, false),
            (MachineOperationV1::History, false),
            (MachineOperationV1::Generation, false),
            (MachineOperationV1::DesiredSnapshot, false),
            (MachineOperationV1::CanonicalTree, false),
            (MachineOperationV1::ArtifactMetadata, false),
            (MachineOperationV1::CapturedInputs, false),
            (MachineOperationV1::TransformProvenance, false),
            (MachineOperationV1::Retention, false),
            (MachineOperationV1::Tracking, false),
            (MachineOperationV1::Status, false),
            (MachineOperationV1::Fsck, false),
        ]
    }

    fn namespace() -> NamespaceName {
        NamespaceName::new("review").expect("static namespace is valid")
    }

    fn plan_id() -> PreparedId {
        PreparedId::from_digest(&Digest::sha256(b"review plan"))
    }

    fn descriptor() -> ArtifactDescriptorV1 {
        ArtifactDescriptorV1::new(
            ArtifactId::new("review/artifact").expect("static artifact ID is valid"),
            Digest::sha256([]),
            0,
            "application/octet-stream".to_owned(),
        )
    }

    fn deployment() -> PreparedDeploymentV1 {
        PreparedDeploymentV1::from(PreparedDeploymentPartsV1 {
            plan_id: plan_id(),
            namespace: namespace(),
            expected_head: None,
            graph_digest: Digest::sha256(b"review graph"),
            inputs: vec![],
            transforms: vec![],
            artifacts: vec![],
            findings: vec![],
            approval_digest: policy_approval_digest_v1([]),
            operations: vec![],
        })
    }

    fn generation() -> GenerationInspectionV1 {
        GenerationInspectionV1::from(GenerationInspectionPartsV1 {
            namespace: namespace(),
            generation: Digest::sha256(b"review generation"),
            lifecycle: LifecycleStateViewV1::Enabled,
            desired_snapshot_digest: Digest::sha256(b"review snapshot"),
            target_count: 0,
            present_target_count: 0,
            absent_target_count: 0,
            plan_id: plan_id(),
            predecessor: None,
            tracked_root: None,
        })
        .with_authority(
            LifecycleTransitionViewV1::Reconcile,
            None,
            RetentionAuthorityInspectionV1::new(4, vec![], vec![]),
        )
    }

    /// Provides one result per operation in `MachineOperationV1::ALL` order.
    ///
    /// The coverage assertion in the guard test below fails if a new operation
    /// joins the inventory without a sample here, so the review partition can
    /// never be checked over a stale subset of the results.
    fn sample_results() -> Vec<MachineResultV1> {
        let digest = Digest::sha256(b"review generation");
        vec![
            MachineResultV1::StoreStatus(StoreStatusV1::Ready),
            MachineResultV1::InitializeStore,
            MachineResultV1::Prepare(deployment()),
            MachineResultV1::Plan(deployment()),
            MachineResultV1::Artifact(ArtifactV1::new(descriptor(), Vec::new())),
            MachineResultV1::Commit(ApplyOutcomeV1::new(
                plan_id(),
                namespace(),
                None,
                digest.clone(),
            )),
            MachineResultV1::State(StateViewV1::new(namespace(), Some(digest.clone()))),
            MachineResultV1::Recover(RecoveryOutcomeV1::recovered(
                namespace(),
                Some(digest.clone()),
            )),
            MachineResultV1::Prune(PruneOutcomeV1 {
                prepared_records: 1,
                artifact_blobs: 2,
                state_generations: 3,
                pack_objects: 4,
                canonical_files: 5,
                canonical_symlinks: 6,
                canonical_trees: 7,
            }),
            MachineResultV1::Checkout(deployment()),
            MachineResultV1::Disable(deployment()),
            MachineResultV1::Enable(deployment()),
            MachineResultV1::RemoveNamespace(deployment()),
            MachineResultV1::SetHistoryRetention(deployment()),
            MachineResultV1::Pin(deployment()),
            MachineResultV1::Unpin(deployment()),
            MachineResultV1::AddRestorePoint(deployment()),
            MachineResultV1::DropRestorePoint(deployment()),
            MachineResultV1::Catalog(CatalogInspectionV1::new(
                Digest::sha256(b"review catalog"),
                vec![CatalogNamespaceInspectionV1::new(
                    namespace(),
                    digest.clone(),
                )],
                10,
            )),
            MachineResultV1::Namespace(NamespaceInspectionV1::new(
                namespace(),
                Some(digest.clone()),
                Some(generation()),
                20,
            )),
            MachineResultV1::History(NamespaceHistoryV1::new(
                namespace(),
                Some(digest.clone()),
                vec![generation()],
                20,
            )),
            MachineResultV1::Generation(generation()),
            MachineResultV1::DesiredSnapshot(DesiredSnapshotInspectionV1::new(
                namespace(),
                digest.clone(),
                Digest::sha256(b"review snapshot"),
                vec![],
                10,
            )),
            MachineResultV1::CanonicalTree(CanonicalTreeInspectionV1::new(
                Digest::sha256(b"review tree"),
                0o700,
                vec![],
                10,
            )),
            MachineResultV1::ArtifactMetadata(ArtifactMetadataInspectionV1::new(
                plan_id(),
                descriptor(),
                10,
            )),
            MachineResultV1::CapturedInputs(CapturedInputsInspectionV1::new(
                plan_id(),
                Digest::sha256(b"review graph"),
                vec![],
                10,
            )),
            MachineResultV1::TransformProvenance(TransformProvenanceInspectionV1::new(
                plan_id(),
                vec![],
                10,
            )),
            MachineResultV1::Retention(RetentionInspectionV1::new(
                namespace(),
                digest.clone(),
                RetentionAuthorityInspectionV1::new(4, vec![], vec![]),
            )),
            MachineResultV1::Tracking(TrackingInspectionV1::new(namespace(), digest.clone(), None)),
            MachineResultV1::Status(NamespaceStatusV1::from(NamespaceStatusPartsV1 {
                namespace: namespace(),
                head: None,
                lifecycle: None,
                desired_snapshot_digest: None,
                status: NamespaceStatusKindV1::NotFound,
                targets: vec![],
                observed_bytes: 0,
                detail: None,
            })),
            MachineResultV1::Fsck(FsckReportV1::from(FsckReportPartsV1 {
                findings: vec![],
                checked_generations: 0,
                checked_prepared_plans: 0,
                checked_artifact_blobs: 0,
                checked_pack_objects: 0,
                checked_canonical_files: 0,
                checked_canonical_symlinks: 0,
                checked_canonical_trees: 0,
                checked_targets: 0,
                decoded_bytes: 0,
                observed_bytes: 0,
                findings_truncated: false,
                complete: true,
            })),
        ]
    }

    /// Verifies that policy review covers every deployment-returning operation.
    ///
    /// `validate_result_review` checks only results returned by
    /// `reviewed_deployment`. A deployment mapped to `None` would ship without
    /// review, so this test compares the full partition with the independent
    /// operation inventory.
    #[test]
    fn every_deployment_result_is_reviewed() {
        let samples = sample_results();
        let covered: Vec<MachineOperationV1> =
            samples.iter().map(MachineResultV1::operation).collect();
        assert_eq!(
            covered,
            MachineOperationV1::ALL.to_vec(),
            "sample_results must hold one result per operation in inventory order"
        );

        let expectations = review_expectations();
        assert_eq!(expectations.len(), MachineOperationV1::ALL.len());
        assert!(
            expectations.iter().any(|(_, reviewed)| *reviewed),
            "the inventory must still contain deployment-returning operations"
        );

        for ((operation, carries_deployment), sample) in expectations.iter().zip(&samples) {
            assert_eq!(sample.operation(), *operation);
            assert_eq!(
                reviewed_deployment(sample).is_some(),
                *carries_deployment,
                "{} is reviewed by reviewed_deployment but the inventory disagrees",
                operation.as_str()
            );
        }
    }
}
