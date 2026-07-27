//! Strict contracts for Malm `config/v1` documents and canonical rich IR.
//!
//! This crate only parses or evaluates supplied values and captured bytes. It
//! cannot access the filesystem, environment, network, processes, clock,
//! randomness, CLI, deployment targets, source acquisition, or store, and it
//! cannot perform effectful rendering.

mod rich;
mod rich_canonical;
mod rich_eval;
mod rich_kdl;
mod rich_workspace;
mod syntax;
mod transform;
mod value;

pub use rich::{
    CanonicalTypedDocumentV1, CapturedAuthorityGraphV1, CapturedAuthorityV1,
    CapturedConfigDocumentV1, CapturedDocumentEdgeKindV1, CapturedDocumentIdV1,
    CapturedDocumentSetV1, CapturedIncludeV1, CapturedSourceIdentityV1, DocumentAuthorityV1,
    EvaluationFrameV1, FragmentDeclarationV1, IncludeProvenanceV1, OrderedPatchV1,
    PatchOperationV1, PatchStepV1, ProvenanceOperationV1, ProvenanceRecordV1, RichConditionV1,
    RichConfigErrorV1, RichDiagnosticLocationV1, RichDiagnosticSeverityV1, RichDiagnosticV1,
    RichDocumentBodyV1, RichExpressionV1, RichIncludeReferenceV1, RichKeyV1, RichModuleReferenceV1,
    RichNameV1, RichStatementV1, RichValuePathV1, SourceLocationV1, SourceRangeV1,
    TransformOutputRangeV1, TypedRecordFieldV1, TypedScalarTypeV1, TypedValueKindV1,
    TypedValueTypeKindV1, TypedValueTypeV1, TypedValueV1, VariableDeclarationV1,
};
pub use rich_canonical::{canonical_typed_document_bytes_v1, canonical_typed_document_digest_v1};
pub use rich_eval::{
    ResolvedVariableV1, RichEvaluationErrorV1, RichEvaluationV1, evaluate_rich_config_v1,
};
pub use rich_kdl::{RichConfigReadErrorV1, decode_rich_config_document_v1};
pub use rich_workspace::{
    BuiltInFormatTransformV1, CapturedPackFileReferenceV1, DesiredOutputKindV1, DesiredOutputSetV1,
    DesiredOutputV1, EvaluatedRichConfigV1, FormatTransformSelectionV1, PackResourceKindV1,
    ParsedRichConfigDocumentPartsV1, ParsedRichConfigDocumentV1, ParsedRichConfigSetV1,
    RichOutputDeclarationV1, RichOutputSiteV1, RichProfileV1, RichSlotV1, SafeRelativeSymlinkV1,
    TransformResourceReferenceV1,
};
pub use syntax::RichSyntaxErrorV1;
pub use transform::{
    CanonicalJsonTransformV1, DeclaredTransformResourceV1, FormatTransformV1, KeyValueTransformV1,
    PlainTextTransformV1, TransformContractErrorV1, TransformExecutionErrorV1,
    TransformExecutionV1, TransformFailureKindV1, TransformFailureV1, TransformIdentityV1,
    TransformImplementationV1, TransformInvocationErrorV1, TransformOptionV1,
    TransformProvenanceV1, TransformRequestV1, TransformResponseV1,
    format_transform_request_digest_v1, format_transform_response_digest_v1,
    run_format_transform_invocation_v1, run_format_transform_v1,
};
pub use value::{ConfigValueError, FiniteFloatV1, TargetPathV1};

/// Implemented config schema version.
pub const CONFIG_SCHEMA_VERSION: u32 = 1;

/// Conventional root configuration filename in the root pack.
pub const CONFIG_FILE: &str = "malm.kdl";

/// Maximum encoded bytes in one root or module config document.
pub const MAX_CONFIG_DOCUMENT_BYTES: usize = 1024 * 1024;

/// Maximum lexical KDL child-block nesting before parsing.
pub const MAX_CONFIG_NESTING_DEPTH: usize = 64;

/// Maximum nested KDL block comments before parsing.
pub const MAX_CONFIG_COMMENT_NESTING_DEPTH: usize = 64;

/// Maximum bytes in one target-relative path.
pub const MAX_TARGET_PATH_BYTES: usize = 4096;

/// Maximum segments in one target-relative path.
pub const MAX_TARGET_PATH_SEGMENTS: usize = 64;

/// Canonical typed rich-config IR version.
pub const RICH_CONFIG_IR_VERSION: u32 = 1;

/// Version of the capability-free format `transform` contract.
pub const FORMAT_TRANSFORM_VERSION: u32 = 1;

/// Exact pack, lock, and component-host interface spelling for the transform ABI.
pub use malm_types::FORMAT_COMPONENT_INTERFACE_V1;

/// Maximum bytes in a variable, fragment, diagnostic-code, or option name.
pub const MAX_RICH_NAME_BYTES: usize = 128;

/// Maximum bytes in one record or keyed-collection key.
pub const MAX_RICH_KEY_BYTES: usize = 1024;

/// Maximum bytes in one rich string value.
pub const MAX_RICH_TEXT_BYTES: usize = 1024 * 1024;

/// Maximum recursive depth of a rich type or value.
pub const MAX_RICH_VALUE_DEPTH: usize = 64;

/// Maximum items in one list, record, or keyed collection.
pub const MAX_RICH_COLLECTION_ITEMS: usize = 16_384;

/// Maximum values reachable from one canonical document root.
pub const MAX_RICH_TOTAL_VALUES: usize = 262_144;

/// Maximum explicit documents in one captured evaluation universe.
pub const MAX_RICH_DOCUMENTS: usize = 1024;

/// Maximum exact pack authorities in one supplied locked graph.
pub const MAX_RICH_AUTHORITIES: usize = malm_pack::MAX_LOCK_NODES;

/// Maximum includes declared by one captured document.
pub const MAX_RICH_INCLUDES_PER_DOCUMENT: usize = 1024;

/// Maximum include edges in one complete captured document set.
pub const MAX_RICH_TOTAL_INCLUDES: usize = 16_384;

/// Maximum reachable include depth.
pub const MAX_RICH_INCLUDE_DEPTH: usize = 64;

/// Maximum aggregate captured config bytes supplied to one evaluation.
pub const MAX_RICH_TOTAL_CAPTURED_BYTES: usize = 64 * 1024 * 1024;

/// Maximum named variables in one evaluated include closure.
pub const MAX_RICH_VARIABLES: usize = 4096;

/// Maximum named fragments in one evaluated include closure.
pub const MAX_RICH_FRAGMENTS: usize = 4096;

/// Maximum profile declarations in one evaluated include closure.
pub const MAX_RICH_PROFILES: usize = 4096;

/// Maximum direct parents of one rich profile.
pub const MAX_RICH_PROFILE_PARENTS: usize = 64;

/// Maximum reachable rich profile inheritance depth.
pub const MAX_RICH_PROFILE_DEPTH: usize = 64;

/// Maximum slot declarations in one evaluated include closure.
pub const MAX_RICH_SLOTS: usize = 1024;

/// Maximum providers admitted by one bounded slot.
pub const MAX_RICH_SLOT_PROVIDERS: usize = 1024;

/// Maximum desired output declarations in one selected profile closure.
pub const MAX_RICH_OUTPUTS: usize = 16_384;

/// Maximum statements or ordered patch steps in one evaluation.
pub const MAX_RICH_STATEMENTS: usize = 262_144;

/// Maximum iterations of one bounded loop.
pub const MAX_RICH_LOOP_ITERATIONS: usize = 4096;

/// Maximum aggregate loop iterations in one evaluation.
pub const MAX_RICH_TOTAL_LOOP_ITERATIONS: usize = 65_536;

/// Maximum expression or statement work units in one evaluation.
pub const MAX_RICH_EVALUATION_STEPS: usize = 1_048_576;

/// Maximum provenance records in one canonical typed document.
pub const MAX_RICH_PROVENANCE_RECORDS: usize = 262_144;

/// Maximum structured diagnostics in one result.
pub const MAX_RICH_DIAGNOSTICS: usize = 256;

/// Maximum bytes in one diagnostic message or note.
pub const MAX_RICH_DIAGNOSTIC_BYTES: usize = 16 * 1024;

/// Maximum notes attached to one diagnostic.
pub const MAX_RICH_DIAGNOSTIC_NOTES: usize = 64;

/// Maximum aggregate diagnostic text bytes in one result.
pub const MAX_RICH_TOTAL_DIAGNOSTIC_BYTES: usize = 1024 * 1024;

/// Maximum canonical binary typed-document bytes.
pub const MAX_CANONICAL_TYPED_DOCUMENT_BYTES: usize = 64 * 1024 * 1024;

/// Maximum explicit options supplied to one format transform.
pub const MAX_TRANSFORM_OPTIONS: usize = 256;

/// Maximum declared byte resources supplied to one format transform.
pub const MAX_TRANSFORM_RESOURCES: usize = 1024;

/// Maximum bytes in one declared transform resource.
pub const MAX_TRANSFORM_RESOURCE_BYTES: usize = 64 * 1024 * 1024;

/// Maximum aggregate declared transform resource bytes.
pub const MAX_TRANSFORM_TOTAL_RESOURCE_BYTES: usize = 256 * 1024 * 1024;

/// Maximum bytes returned by one format transform.
pub const MAX_TRANSFORM_OUTPUT_BYTES: usize = 64 * 1024 * 1024;
