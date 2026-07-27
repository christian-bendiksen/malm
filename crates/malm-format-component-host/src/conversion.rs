use std::fmt;

use malm_config as config;

use crate::bindings;

#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
#[error("{reason}")]
pub(crate) struct ConversionError {
    reason: String,
}

impl ConversionError {
    fn new(reason: impl Into<String>) -> Self {
        Self {
            reason: reason.into(),
        }
    }
}

fn conversion_error(error: impl fmt::Display) -> ConversionError {
    ConversionError::new(error.to_string())
}

pub(crate) fn to_binding_request(
    request: &config::TransformRequestV1,
) -> bindings::TransformRequestV1 {
    bindings::TransformRequestV1 {
        contract_version: request.contract_version(),
        document: to_binding_document(request.document()),
        options: request
            .options()
            .values()
            .map(|option| bindings::TransformOptionV1 {
                name: option.name().as_str().to_owned(),
                value: to_binding_value(option.value()),
            })
            .collect(),
        resources: request
            .resources()
            .values()
            .map(|resource| bindings::DeclaredResourceV1 {
                name: resource.name().as_str().to_owned(),
                digest: resource.digest().as_str().to_owned(),
                bytes: resource.bytes().to_vec(),
            })
            .collect(),
    }
}

fn to_binding_document(
    document: &config::CanonicalTypedDocumentV1,
) -> bindings::CanonicalTypedDocumentV1 {
    bindings::CanonicalTypedDocumentV1 {
        version: document.version(),
        root: to_binding_value(document.root()),
        source_documents: document
            .source_documents()
            .iter()
            .map(|(id, identity)| bindings::SourceDocumentV1 {
                id: to_binding_document_id(id),
                digest: identity.digest().as_str().to_owned(),
                byte_len: identity.byte_len(),
            })
            .collect(),
        includes: document
            .includes()
            .iter()
            .map(|include| bindings::IncludeProvenanceV1 {
                source: to_binding_source_location(include.source()),
                target: to_binding_document_id(include.target()),
                target_digest: include.target_digest().as_str().to_owned(),
                dependency_alias: include.dependency().map(|alias| alias.as_str().to_owned()),
                edge_kind: match include.kind() {
                    config::CapturedDocumentEdgeKindV1::Include => {
                        bindings::DocumentEdgeKindV1::IncludeEdge
                    }
                    config::CapturedDocumentEdgeKindV1::Module { name } => {
                        bindings::DocumentEdgeKindV1::ModuleEdge(name.as_str().to_owned())
                    }
                },
            })
            .collect(),
        provenance: document
            .provenance()
            .iter()
            .map(|(path, records)| bindings::ValueProvenanceV1 {
                path: path
                    .segments()
                    .iter()
                    .map(|segment| segment.as_str().to_owned())
                    .collect(),
                records: records.iter().map(to_binding_provenance).collect(),
            })
            .collect(),
    }
}

fn to_binding_value(value: &config::TypedValueV1) -> bindings::CanonicalValueV1 {
    fn push_value(value: &config::TypedValueV1, values: &mut Vec<bindings::TypedValueV1>) -> u32 {
        let node = match value.kind() {
            config::TypedValueKindV1::Null => bindings::TypedValueV1::NullValue,
            config::TypedValueKindV1::Boolean => {
                bindings::TypedValueV1::Boolean(value.as_bool().expect("boolean kind has value"))
            }
            config::TypedValueKindV1::Integer => {
                bindings::TypedValueV1::Signed(value.as_integer().expect("integer kind has value"))
            }
            config::TypedValueKindV1::Unsigned => bindings::TypedValueV1::Unsigned(
                value.as_unsigned().expect("unsigned kind has value"),
            ),
            config::TypedValueKindV1::Float => bindings::TypedValueV1::FloatingPoint(
                value.as_float().expect("float kind has value").get(),
            ),
            config::TypedValueKindV1::String => bindings::TypedValueV1::Text(
                value.as_string().expect("string kind has value").to_owned(),
            ),
            config::TypedValueKindV1::Path => bindings::TypedValueV1::Path(
                value
                    .as_path()
                    .expect("path kind has value")
                    .as_str()
                    .to_owned(),
            ),
            config::TypedValueKindV1::List => bindings::TypedValueV1::ListValue(
                value
                    .as_list()
                    .expect("list kind has value")
                    .iter()
                    .map(|value| push_value(value, values))
                    .collect(),
            ),
            config::TypedValueKindV1::Record => bindings::TypedValueV1::RecordValue(
                value
                    .as_record()
                    .expect("record kind has value")
                    .iter()
                    .map(|(name, value)| bindings::ValueFieldV1 {
                        name: name.as_str().to_owned(),
                        value: push_value(value, values),
                    })
                    .collect(),
            ),
            config::TypedValueKindV1::Collection => bindings::TypedValueV1::CollectionValue(
                value
                    .as_collection()
                    .expect("collection kind has value")
                    .iter()
                    .map(|(name, value)| bindings::ValueFieldV1 {
                        name: name.as_str().to_owned(),
                        value: push_value(value, values),
                    })
                    .collect(),
            ),
        };
        let id = u32::try_from(values.len()).expect("validated transform values fit in u32");
        values.push(node);
        id
    }

    let mut values = Vec::new();
    let root = push_value(value, &mut values);
    bindings::CanonicalValueV1 { root, values }
}

fn to_binding_document_id(id: &config::CapturedDocumentIdV1) -> bindings::DocumentIdV1 {
    bindings::DocumentIdV1 {
        authority_label: id.authority().label().as_str().to_owned(),
        authority_identity: id.authority().identity().as_str().to_owned(),
        path: id.path().as_str().to_owned(),
    }
}

fn to_binding_source_location(location: &config::SourceLocationV1) -> bindings::SourceLocationV1 {
    bindings::SourceLocationV1 {
        document: to_binding_document_id(location.document()),
        range: bindings::SourceRangeV1 {
            start: location.range().start(),
            end: location.range().end(),
        },
    }
}

fn to_binding_provenance(record: &config::ProvenanceRecordV1) -> bindings::ProvenanceRecordV1 {
    bindings::ProvenanceRecordV1 {
        sequence: record.sequence(),
        location: to_binding_source_location(record.location()),
        operation: match record.operation() {
            config::ProvenanceOperationV1::VariableSupplied => {
                bindings::ProvenanceOperationV1::VariableSupplied
            }
            config::ProvenanceOperationV1::VariableDefault => {
                bindings::ProvenanceOperationV1::VariableDefault
            }
            config::ProvenanceOperationV1::VariableOptionalAbsent => {
                bindings::ProvenanceOperationV1::VariableOptionalAbsent
            }
            config::ProvenanceOperationV1::VariableComputed => {
                bindings::ProvenanceOperationV1::VariableComputed
            }
            config::ProvenanceOperationV1::Emit => bindings::ProvenanceOperationV1::Emit,
            config::ProvenanceOperationV1::Patch { operation } => {
                bindings::ProvenanceOperationV1::Patch(*operation)
            }
        },
        frames: record
            .frames()
            .iter()
            .map(|frame| match frame {
                config::EvaluationFrameV1::Fragment(name) => {
                    bindings::EvaluationFrameV1::Fragment(name.as_str().to_owned())
                }
                config::EvaluationFrameV1::Conditional { then_branch } => {
                    bindings::EvaluationFrameV1::Conditional(*then_branch)
                }
                config::EvaluationFrameV1::Loop { binding, iteration } => {
                    bindings::EvaluationFrameV1::LoopFrame(bindings::LoopFrameV1 {
                        binding: binding.as_str().to_owned(),
                        iteration: *iteration,
                    })
                }
            })
            .collect(),
    }
}

pub(crate) fn from_binding_response(
    response: bindings::TransformResponseV1,
    request: &config::TransformRequestV1,
) -> Result<config::TransformResponseV1, ConversionError> {
    config::TransformResponseV1::new(
        response.output,
        response.media_type,
        response
            .diagnostics
            .into_iter()
            .map(|diagnostic| from_binding_diagnostic(diagnostic, request))
            .collect::<Result<Vec<_>, _>>()?,
    )
    .map_err(conversion_error)
}

pub(crate) fn from_binding_failure(
    failure: bindings::TransformFailureV1,
    request: &config::TransformRequestV1,
) -> Result<config::TransformFailureV1, ConversionError> {
    config::TransformFailureV1::new(
        match failure.kind {
            bindings::TransformFailureKindV1::InvalidRequest => {
                config::TransformFailureKindV1::InvalidRequest
            }
            bindings::TransformFailureKindV1::UnsupportedFormat => {
                config::TransformFailureKindV1::UnsupportedFormat
            }
            bindings::TransformFailureKindV1::ResourceLimit => {
                config::TransformFailureKindV1::ResourceLimit
            }
            bindings::TransformFailureKindV1::InvalidResult => {
                config::TransformFailureKindV1::InvalidResult
            }
            bindings::TransformFailureKindV1::Internal => config::TransformFailureKindV1::Internal,
        },
        failure.message,
        failure
            .diagnostics
            .into_iter()
            .map(|diagnostic| from_binding_diagnostic(diagnostic, request))
            .collect::<Result<Vec<_>, _>>()?,
    )
    .map_err(conversion_error)
}

fn from_binding_diagnostic(
    diagnostic: bindings::DiagnosticV1,
    request: &config::TransformRequestV1,
) -> Result<config::RichDiagnosticV1, ConversionError> {
    let severity = match diagnostic.severity {
        bindings::DiagnosticSeverityV1::Error => config::RichDiagnosticSeverityV1::Error,
        bindings::DiagnosticSeverityV1::Warning => config::RichDiagnosticSeverityV1::Warning,
        bindings::DiagnosticSeverityV1::Info => config::RichDiagnosticSeverityV1::Info,
    };
    let primary = diagnostic
        .primary
        .map(|location| from_binding_location(location, request))
        .transpose()?;
    config::RichDiagnosticV1::new(
        severity,
        config::RichNameV1::new(diagnostic.code).map_err(conversion_error)?,
        diagnostic.message,
        primary,
        diagnostic.notes,
    )
    .map_err(conversion_error)
}

fn from_binding_location(
    location: bindings::DiagnosticLocationV1,
    request: &config::TransformRequestV1,
) -> Result<config::RichDiagnosticLocationV1, ConversionError> {
    match location {
        bindings::DiagnosticLocationV1::Output(range) => {
            config::TransformOutputRangeV1::new(range.start, range.end)
                .map(config::RichDiagnosticLocationV1::Output)
                .map_err(conversion_error)
        }
        bindings::DiagnosticLocationV1::Source(location) => {
            let (document, source_identity) = request
                .document()
                .source_documents()
                .iter()
                .find(|(candidate, _)| document_id_matches(candidate, &location.document))
                .ok_or_else(|| {
                    ConversionError::new(
                        "component diagnostic references a document absent from the request",
                    )
                })?;
            let range = config::SourceRangeV1::new(location.range.start, location.range.end)
                .map_err(conversion_error)?;
            if u64::from(range.end()) > source_identity.byte_len() {
                return Err(ConversionError::new(
                    "component diagnostic range exceeds its captured source document",
                ));
            }
            Ok(config::RichDiagnosticLocationV1::Source(
                config::SourceLocationV1::new(document.clone(), range),
            ))
        }
    }
}

fn document_id_matches(
    candidate: &config::CapturedDocumentIdV1,
    supplied: &bindings::DocumentIdV1,
) -> bool {
    candidate.authority().label().as_str() == supplied.authority_label
        && candidate.authority().identity().as_str() == supplied.authority_identity
        && candidate.path().as_str() == supplied.path
}
