use std::collections::BTreeMap;

use malm_types::Digest;

use crate::rich::insert_unique;
use crate::rich::{
    CanonicalTypedDocumentV1, RichConfigErrorV1, RichDiagnosticLocationV1,
    RichDiagnosticSeverityV1, RichDiagnosticV1, RichNameV1, TypedValueDataV1, TypedValueV1,
    canonical_diagnostics,
};
use crate::rich_canonical::{
    canonical_typed_document_bytes_v1, canonical_typed_document_digest_v1, canonical_value_bytes_v1,
};
use crate::{
    FORMAT_TRANSFORM_VERSION, MAX_CANONICAL_TYPED_DOCUMENT_BYTES, MAX_RICH_DIAGNOSTIC_BYTES,
    MAX_TRANSFORM_OPTIONS, MAX_TRANSFORM_OUTPUT_BYTES, MAX_TRANSFORM_RESOURCE_BYTES,
    MAX_TRANSFORM_RESOURCES, MAX_TRANSFORM_TOTAL_RESOURCE_BYTES,
};

/// Deterministic validation failure at the format-transform boundary.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
#[non_exhaustive]
pub enum TransformContractErrorV1 {
    // Do not use `#[error(transparent)]`. `source()` must return the inner
    // `RichConfigErrorV1`, not that error's source.
    #[error("{0}")]
    RichModel(#[source] RichConfigErrorV1),
    #[error("unsupported transform contract version {actual}; expected exactly {expected}")]
    UnsupportedVersion { expected: u32, actual: u32 },
    #[error("duplicate transform option {0}")]
    DuplicateOption(RichNameV1),
    #[error("duplicate declared transform resource {0}")]
    DuplicateResource(RichNameV1),
    #[error("declared resource {0} bytes do not match its digest")]
    ResourceDigestMismatch(RichNameV1),
    #[error("invalid transform identity: {0}")]
    InvalidIdentity(&'static str),
    #[error("invalid transform response media type")]
    InvalidMediaType,
    #[error("transform diagnostic references an unknown source document")]
    UnknownDiagnosticSource,
    #[error("transform diagnostic range exceeds its captured source document")]
    InvalidDiagnosticSourceRange,
    #[error("transform diagnostic has an invalid output byte range")]
    InvalidDiagnosticOutputRange,
    #[error("failed transform diagnostic cannot reference unavailable output")]
    OutputDiagnosticOnFailure,
    #[error("successful transform response contains an error diagnostic")]
    ErrorDiagnosticOnSuccess,
}

impl From<RichConfigErrorV1> for TransformContractErrorV1 {
    fn from(error: RichConfigErrorV1) -> Self {
        Self::RichModel(error)
    }
}

/// The closed implementation identity of a format transform.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum TransformImplementationV1 {
    BuiltIn {
        implementation: String,
    },
    Component {
        component_digest: Digest,
        interface_version: String,
        execution_profile_digest: Digest,
    },
}

/// Stable semantic identity of a built-in or exact component transform.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct TransformIdentityV1 {
    contract_version: u32,
    name: RichNameV1,
    implementation: TransformImplementationV1,
}

impl TransformIdentityV1 {
    pub fn new(
        name: RichNameV1,
        implementation: impl Into<String>,
    ) -> Result<Self, TransformContractErrorV1> {
        Self::built_in(name, implementation)
    }

    pub fn built_in(
        name: RichNameV1,
        implementation: impl Into<String>,
    ) -> Result<Self, TransformContractErrorV1> {
        let identity = Self {
            contract_version: FORMAT_TRANSFORM_VERSION,
            name,
            implementation: TransformImplementationV1::BuiltIn {
                implementation: implementation.into(),
            },
        };
        identity.validate()?;
        Ok(identity)
    }

    pub fn component(
        name: RichNameV1,
        component_digest: Digest,
        interface_version: impl Into<String>,
        execution_profile_digest: Digest,
    ) -> Result<Self, TransformContractErrorV1> {
        let identity = Self {
            contract_version: FORMAT_TRANSFORM_VERSION,
            name,
            implementation: TransformImplementationV1::Component {
                component_digest,
                interface_version: interface_version.into(),
                execution_profile_digest,
            },
        };
        identity.validate()?;
        Ok(identity)
    }

    fn validate(&self) -> Result<(), TransformContractErrorV1> {
        if self.contract_version != FORMAT_TRANSFORM_VERSION {
            return Err(TransformContractErrorV1::UnsupportedVersion {
                expected: FORMAT_TRANSFORM_VERSION,
                actual: self.contract_version,
            });
        }
        match &self.implementation {
            TransformImplementationV1::BuiltIn { implementation } => {
                validate_identity_text("implementation version", implementation)?;
            }
            TransformImplementationV1::Component {
                interface_version, ..
            } => {
                if interface_version != crate::FORMAT_COMPONENT_INTERFACE_V1 {
                    return Err(TransformContractErrorV1::InvalidIdentity(
                        "component interface must be exactly format-component/v1",
                    ));
                }
            }
        }
        Ok(())
    }
}

impl TransformIdentityV1 {
    #[must_use]
    pub const fn contract_version(&self) -> u32 {
        self.contract_version
    }
    #[must_use]
    pub const fn name(&self) -> &RichNameV1 {
        &self.name
    }
    #[must_use]
    pub const fn implementation(&self) -> &TransformImplementationV1 {
        &self.implementation
    }
}

fn validate_identity_text(
    field: &'static str,
    value: &str,
) -> Result<(), TransformContractErrorV1> {
    if value.is_empty() {
        return Err(TransformContractErrorV1::InvalidIdentity(match field {
            "implementation version" => "implementation version must not be empty",
            _ => "identity text must not be empty",
        }));
    }
    if value.len() > 256 {
        return Err(TransformContractErrorV1::InvalidIdentity(match field {
            "implementation version" => "implementation version must be at most 256 bytes",
            _ => "identity text must be at most 256 bytes",
        }));
    }
    if value.chars().any(char::is_control) {
        return Err(TransformContractErrorV1::InvalidIdentity(match field {
            "implementation version" => {
                "implementation version must not contain control characters"
            }
            _ => "identity text must not contain control characters",
        }));
    }
    Ok(())
}

/// An explicit typed option supplied to a format transform.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransformOptionV1 {
    name: RichNameV1,
    value: TypedValueV1,
}

impl TransformOptionV1 {
    pub fn new(name: RichNameV1, value: TypedValueV1) -> Result<Self, TransformContractErrorV1> {
        value.validate()?;
        Ok(Self { name, value })
    }
}

impl TransformOptionV1 {
    #[must_use]
    pub const fn name(&self) -> &RichNameV1 {
        &self.name
    }
    #[must_use]
    pub const fn value(&self) -> &TypedValueV1 {
        &self.value
    }
}

/// Exact declared resource bytes available to a transform invocation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeclaredTransformResourceV1 {
    name: RichNameV1,
    digest: Digest,
    bytes: Vec<u8>,
}

impl DeclaredTransformResourceV1 {
    pub fn new(
        name: RichNameV1,
        digest: Digest,
        bytes: impl Into<Vec<u8>>,
    ) -> Result<Self, TransformContractErrorV1> {
        let resource = Self {
            name,
            digest,
            bytes: bytes.into(),
        };
        resource.validate()?;
        Ok(resource)
    }

    pub fn capture(
        name: RichNameV1,
        bytes: impl Into<Vec<u8>>,
    ) -> Result<Self, TransformContractErrorV1> {
        let bytes = bytes.into();
        let digest = Digest::sha256(&bytes);
        Self::new(name, digest, bytes)
    }

    fn validate(&self) -> Result<(), TransformContractErrorV1> {
        if self.bytes.len() > MAX_TRANSFORM_RESOURCE_BYTES {
            return Err(RichConfigErrorV1::LimitExceeded {
                resource: "transform resource bytes",
                limit: MAX_TRANSFORM_RESOURCE_BYTES,
                actual: self.bytes.len(),
            }
            .into());
        }
        if Digest::sha256(&self.bytes) != self.digest {
            return Err(TransformContractErrorV1::ResourceDigestMismatch(
                self.name.clone(),
            ));
        }
        Ok(())
    }
}

impl DeclaredTransformResourceV1 {
    #[must_use]
    pub const fn name(&self) -> &RichNameV1 {
        &self.name
    }
    #[must_use]
    pub const fn digest(&self) -> &Digest {
        &self.digest
    }
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// The complete capability-free input to a version-1 format transform.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransformRequestV1 {
    contract_version: u32,
    document: CanonicalTypedDocumentV1,
    options: BTreeMap<RichNameV1, TransformOptionV1>,
    resources: BTreeMap<RichNameV1, DeclaredTransformResourceV1>,
}

impl TransformRequestV1 {
    pub fn new(
        document: CanonicalTypedDocumentV1,
        options: Vec<TransformOptionV1>,
        resources: Vec<DeclaredTransformResourceV1>,
    ) -> Result<Self, TransformContractErrorV1> {
        if options.len() > MAX_TRANSFORM_OPTIONS {
            return Err(RichConfigErrorV1::LimitExceeded {
                resource: "transform options",
                limit: MAX_TRANSFORM_OPTIONS,
                actual: options.len(),
            }
            .into());
        }
        if resources.len() > MAX_TRANSFORM_RESOURCES {
            return Err(RichConfigErrorV1::LimitExceeded {
                resource: "transform resources",
                limit: MAX_TRANSFORM_RESOURCES,
                actual: resources.len(),
            }
            .into());
        }
        let mut options_by_name = BTreeMap::new();
        for option in options {
            let name = option.name.clone();
            insert_unique(
                &mut options_by_name,
                name,
                option,
                TransformContractErrorV1::DuplicateOption,
            )?;
        }
        let mut resources_by_name = BTreeMap::new();
        for resource in resources {
            let name = resource.name.clone();
            insert_unique(
                &mut resources_by_name,
                name,
                resource,
                TransformContractErrorV1::DuplicateResource,
            )?;
        }
        let request = Self {
            contract_version: FORMAT_TRANSFORM_VERSION,
            document,
            options: options_by_name,
            resources: resources_by_name,
        };
        request.validate()?;
        Ok(request)
    }

    pub fn validate(&self) -> Result<(), TransformContractErrorV1> {
        if self.contract_version != FORMAT_TRANSFORM_VERSION {
            return Err(TransformContractErrorV1::UnsupportedVersion {
                expected: FORMAT_TRANSFORM_VERSION,
                actual: self.contract_version,
            });
        }
        canonical_typed_document_bytes_v1(&self.document)?;
        if self.options.len() > MAX_TRANSFORM_OPTIONS {
            return Err(RichConfigErrorV1::LimitExceeded {
                resource: "transform options",
                limit: MAX_TRANSFORM_OPTIONS,
                actual: self.options.len(),
            }
            .into());
        }
        let mut option_bytes = 0_usize;
        for (name, option) in &self.options {
            if name != &option.name {
                return Err(TransformContractErrorV1::InvalidIdentity(
                    "option map key does not match option name",
                ));
            }
            option.value.validate()?;
            option_bytes =
                option_bytes.saturating_add(canonical_value_bytes_v1(&option.value)?.len());
        }
        if option_bytes > MAX_CANONICAL_TYPED_DOCUMENT_BYTES {
            return Err(RichConfigErrorV1::LimitExceeded {
                resource: "canonical transform option bytes",
                limit: MAX_CANONICAL_TYPED_DOCUMENT_BYTES,
                actual: option_bytes,
            }
            .into());
        }
        if self.resources.len() > MAX_TRANSFORM_RESOURCES {
            return Err(RichConfigErrorV1::LimitExceeded {
                resource: "transform resources",
                limit: MAX_TRANSFORM_RESOURCES,
                actual: self.resources.len(),
            }
            .into());
        }
        let mut total_resource_bytes = 0_usize;
        for (name, resource) in &self.resources {
            if name != &resource.name {
                return Err(TransformContractErrorV1::InvalidIdentity(
                    "resource map key does not match resource name",
                ));
            }
            resource.validate()?;
            total_resource_bytes = total_resource_bytes.saturating_add(resource.bytes.len());
        }
        if total_resource_bytes > MAX_TRANSFORM_TOTAL_RESOURCE_BYTES {
            return Err(RichConfigErrorV1::LimitExceeded {
                resource: "total transform resource bytes",
                limit: MAX_TRANSFORM_TOTAL_RESOURCE_BYTES,
                actual: total_resource_bytes,
            }
            .into());
        }
        Ok(())
    }
}

impl TransformRequestV1 {
    #[must_use]
    pub const fn contract_version(&self) -> u32 {
        self.contract_version
    }
    #[must_use]
    pub const fn document(&self) -> &CanonicalTypedDocumentV1 {
        &self.document
    }
    #[must_use]
    pub const fn options(&self) -> &BTreeMap<RichNameV1, TransformOptionV1> {
        &self.options
    }
    #[must_use]
    pub const fn resources(&self) -> &BTreeMap<RichNameV1, DeclaredTransformResourceV1> {
        &self.resources
    }
}

/// Successful transform output and its structured diagnostics.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransformResponseV1 {
    output: Vec<u8>,
    media_type: String,
    diagnostics: Vec<RichDiagnosticV1>,
}

impl TransformResponseV1 {
    pub fn new(
        output: impl Into<Vec<u8>>,
        media_type: impl Into<String>,
        diagnostics: Vec<RichDiagnosticV1>,
    ) -> Result<Self, TransformContractErrorV1> {
        let diagnostics = canonical_diagnostics(diagnostics)?;
        if diagnostics
            .iter()
            .any(|diagnostic| diagnostic.severity() == RichDiagnosticSeverityV1::Error)
        {
            return Err(TransformContractErrorV1::ErrorDiagnosticOnSuccess);
        }
        let response = Self {
            output: output.into(),
            media_type: media_type.into(),
            diagnostics,
        };
        response.validate_shape()?;
        Ok(response)
    }

    fn validate_shape(&self) -> Result<(), TransformContractErrorV1> {
        if self.output.len() > MAX_TRANSFORM_OUTPUT_BYTES {
            return Err(RichConfigErrorV1::LimitExceeded {
                resource: "transform output bytes",
                limit: MAX_TRANSFORM_OUTPUT_BYTES,
                actual: self.output.len(),
            }
            .into());
        }
        if !valid_media_type(&self.media_type) {
            return Err(TransformContractErrorV1::InvalidMediaType);
        }
        if canonical_diagnostics(self.diagnostics.clone())? != self.diagnostics {
            return Err(TransformContractErrorV1::InvalidIdentity(
                "transform diagnostics are not in canonical order",
            ));
        }
        if self
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.severity() == RichDiagnosticSeverityV1::Error)
        {
            return Err(TransformContractErrorV1::ErrorDiagnosticOnSuccess);
        }
        Ok(())
    }
}

impl TransformResponseV1 {
    #[must_use]
    pub fn output(&self) -> &[u8] {
        &self.output
    }
    #[must_use]
    pub fn media_type(&self) -> &str {
        &self.media_type
    }
    #[must_use]
    pub fn diagnostics(&self) -> &[RichDiagnosticV1] {
        &self.diagnostics
    }
}

/// Closed failure classes returned by a transform implementation.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum TransformFailureKindV1 {
    InvalidRequest,
    UnsupportedFormat,
    ResourceLimit,
    InvalidResult,
    Internal,
}

/// A bounded failure returned through the transform function boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransformFailureV1 {
    kind: TransformFailureKindV1,
    message: String,
    diagnostics: Vec<RichDiagnosticV1>,
}

impl TransformFailureV1 {
    pub fn new(
        kind: TransformFailureKindV1,
        message: impl Into<String>,
        diagnostics: Vec<RichDiagnosticV1>,
    ) -> Result<Self, TransformContractErrorV1> {
        let message = message.into();
        if message.len() > MAX_RICH_DIAGNOSTIC_BYTES {
            return Err(RichConfigErrorV1::LimitExceeded {
                resource: "transform failure message bytes",
                limit: MAX_RICH_DIAGNOSTIC_BYTES,
                actual: message.len(),
            }
            .into());
        }
        Ok(Self {
            kind,
            message,
            diagnostics: canonical_diagnostics(diagnostics)?,
        })
    }
}

impl TransformFailureV1 {
    #[must_use]
    pub const fn kind(&self) -> TransformFailureKindV1 {
        self.kind
    }
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }
    #[must_use]
    pub fn diagnostics(&self) -> &[RichDiagnosticV1] {
        &self.diagnostics
    }
}

/// The semantic transform boundary. Runtime and component execution are supplied elsewhere.
pub trait FormatTransformV1 {
    fn identity(&self) -> TransformIdentityV1;

    fn transform(
        &self,
        request: &TransformRequestV1,
    ) -> Result<TransformResponseV1, TransformFailureV1>;
}

/// Canonical provenance for a successful transform invocation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransformProvenanceV1 {
    identity: TransformIdentityV1,
    request_digest: Digest,
    document_digest: Digest,
    resources: BTreeMap<RichNameV1, Digest>,
    response_digest: Digest,
}

impl TransformProvenanceV1 {
    #[must_use]
    pub const fn identity(&self) -> &TransformIdentityV1 {
        &self.identity
    }
    #[must_use]
    pub const fn request_digest(&self) -> &Digest {
        &self.request_digest
    }
    #[must_use]
    pub const fn document_digest(&self) -> &Digest {
        &self.document_digest
    }
    #[must_use]
    pub const fn resources(&self) -> &BTreeMap<RichNameV1, Digest> {
        &self.resources
    }
    #[must_use]
    pub const fn response_digest(&self) -> &Digest {
        &self.response_digest
    }
}

/// A validated response with deterministic invocation provenance.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransformExecutionV1 {
    response: TransformResponseV1,
    provenance: TransformProvenanceV1,
}

impl TransformExecutionV1 {
    #[must_use]
    pub const fn response(&self) -> &TransformResponseV1 {
        &self.response
    }
    #[must_use]
    pub const fn provenance(&self) -> &TransformProvenanceV1 {
        &self.provenance
    }
}

/// A failure before, during, or after the implementation call.
///
/// The variants have no `#[source]`, so `source()` returns `None` for all of them.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum TransformExecutionErrorV1 {
    #[error("invalid transform request: {0}")]
    InvalidRequest(TransformContractErrorV1),
    #[error("transform failed: {}", .0.message)]
    TransformFailed(TransformFailureV1),
    #[error("invalid transform response: {0}")]
    InvalidResponse(TransformContractErrorV1),
}

/// A runner failure that keeps infrastructure errors separate from semantic errors.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TransformInvocationErrorV1<E> {
    InvalidRequest(TransformContractErrorV1),
    TransformFailed(TransformFailureV1),
    InvalidResponse(TransformContractErrorV1),
    Infrastructure(E),
}

/// Validates the request and response while invoking a version-1 format transform.
pub fn run_format_transform_v1(
    transform: &dyn FormatTransformV1,
    request: &TransformRequestV1,
) -> Result<TransformExecutionV1, TransformExecutionErrorV1> {
    let identity = transform.identity();
    match run_format_transform_invocation_v1(identity, request, || {
        Ok::<_, std::convert::Infallible>(transform.transform(request))
    }) {
        Ok(execution) => Ok(execution),
        Err(TransformInvocationErrorV1::InvalidRequest(error)) => {
            Err(TransformExecutionErrorV1::InvalidRequest(error))
        }
        Err(TransformInvocationErrorV1::TransformFailed(failure)) => {
            Err(TransformExecutionErrorV1::TransformFailed(failure))
        }
        Err(TransformInvocationErrorV1::InvalidResponse(error)) => {
            Err(TransformExecutionErrorV1::InvalidResponse(error))
        }
        Err(TransformInvocationErrorV1::Infrastructure(never)) => match never {},
    }
}

/// Validates and fingerprints an invocation from a built-in transform or host port.
pub fn run_format_transform_invocation_v1<E>(
    identity: TransformIdentityV1,
    request: &TransformRequestV1,
    invoke: impl FnOnce() -> Result<Result<TransformResponseV1, TransformFailureV1>, E>,
) -> Result<TransformExecutionV1, TransformInvocationErrorV1<E>> {
    request
        .validate()
        .map_err(TransformInvocationErrorV1::InvalidRequest)?;
    identity
        .validate()
        .map_err(TransformInvocationErrorV1::InvalidRequest)?;
    let request_digest = format_transform_request_digest_v1(&identity, request)
        .map_err(TransformInvocationErrorV1::InvalidRequest)?;
    let response = match invoke().map_err(TransformInvocationErrorV1::Infrastructure)? {
        Ok(response) => response,
        Err(failure) => {
            validate_failure_for(&failure, request)
                .map_err(TransformInvocationErrorV1::InvalidResponse)?;
            return Err(TransformInvocationErrorV1::TransformFailed(failure));
        }
    };
    validate_response_for(&response, request)
        .map_err(TransformInvocationErrorV1::InvalidResponse)?;
    let document_digest = canonical_typed_document_digest_v1(request.document())
        .map_err(|error| TransformInvocationErrorV1::InvalidRequest(error.into()))?;
    let resources = request
        .resources
        .iter()
        .map(|(name, resource)| (name.clone(), resource.digest.clone()))
        .collect();
    let response_digest = format_transform_response_digest_v1(&response)
        .map_err(TransformInvocationErrorV1::InvalidResponse)?;
    Ok(TransformExecutionV1 {
        response,
        provenance: TransformProvenanceV1 {
            identity,
            request_digest,
            document_digest,
            resources,
            response_digest,
        },
    })
}

fn validate_response_for(
    response: &TransformResponseV1,
    request: &TransformRequestV1,
) -> Result<(), TransformContractErrorV1> {
    response.validate_shape()?;
    for diagnostic in &response.diagnostics {
        if diagnostic.severity() == RichDiagnosticSeverityV1::Error {
            return Err(TransformContractErrorV1::ErrorDiagnosticOnSuccess);
        }
        validate_diagnostic_location(diagnostic, request, Some(response.output.len()))?;
    }
    Ok(())
}

fn validate_failure_for(
    failure: &TransformFailureV1,
    request: &TransformRequestV1,
) -> Result<(), TransformContractErrorV1> {
    for diagnostic in &failure.diagnostics {
        validate_diagnostic_location(diagnostic, request, None)?;
    }
    Ok(())
}

fn validate_diagnostic_location(
    diagnostic: &RichDiagnosticV1,
    request: &TransformRequestV1,
    output_len: Option<usize>,
) -> Result<(), TransformContractErrorV1> {
    match diagnostic.primary() {
        Some(RichDiagnosticLocationV1::Source(location)) => {
            let Some(source_identity) =
                request.document.source_documents().get(location.document())
            else {
                return Err(TransformContractErrorV1::UnknownDiagnosticSource);
            };
            if u64::from(location.range().end()) > source_identity.byte_len() {
                return Err(TransformContractErrorV1::InvalidDiagnosticSourceRange);
            }
        }
        Some(RichDiagnosticLocationV1::Output(range)) => {
            let Some(output_len) = output_len else {
                return Err(TransformContractErrorV1::OutputDiagnosticOnFailure);
            };
            if range.end() > u64::try_from(output_len).unwrap_or(u64::MAX) {
                return Err(TransformContractErrorV1::InvalidDiagnosticOutputRange);
            }
        }
        None => {}
    }
    Ok(())
}

fn valid_media_type(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.contains('/')
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'+' | b'-' | b'.'))
}

/// Fingerprints a transform identity and all canonical request inputs.
pub fn format_transform_request_digest_v1(
    identity: &TransformIdentityV1,
    request: &TransformRequestV1,
) -> Result<Digest, TransformContractErrorV1> {
    identity.validate()?;
    request.validate()?;
    let mut bytes = Vec::new();
    put_text(&mut bytes, "malm-format-transform-request");
    put_u32(&mut bytes, FORMAT_TRANSFORM_VERSION);
    put_text(&mut bytes, identity.name.as_str());
    match &identity.implementation {
        TransformImplementationV1::BuiltIn { implementation } => {
            bytes.push(0);
            put_text(&mut bytes, implementation);
        }
        TransformImplementationV1::Component {
            component_digest,
            interface_version,
            execution_profile_digest,
        } => {
            bytes.push(1);
            put_text(&mut bytes, component_digest.as_str());
            put_text(&mut bytes, interface_version);
            put_text(&mut bytes, execution_profile_digest.as_str());
        }
    }
    put_text(
        &mut bytes,
        canonical_typed_document_digest_v1(&request.document)?.as_str(),
    );
    put_len(&mut bytes, request.options.len());
    for (name, option) in &request.options {
        put_text(&mut bytes, name.as_str());
        put_bytes(&mut bytes, &canonical_value_bytes_v1(&option.value)?);
    }
    put_len(&mut bytes, request.resources.len());
    for (name, resource) in &request.resources {
        put_text(&mut bytes, name.as_str());
        put_text(&mut bytes, resource.digest.as_str());
        put_len(&mut bytes, resource.bytes.len());
    }
    Ok(Digest::sha256(bytes))
}

/// Fingerprints a bounded transform response independently of its implementation.
pub fn format_transform_response_digest_v1(
    response: &TransformResponseV1,
) -> Result<Digest, TransformContractErrorV1> {
    response.validate_shape()?;
    let mut bytes = Vec::new();
    put_text(&mut bytes, "malm-format-transform-response");
    put_u32(&mut bytes, FORMAT_TRANSFORM_VERSION);
    put_text(&mut bytes, &response.media_type);
    put_bytes(&mut bytes, &response.output);
    put_len(&mut bytes, response.diagnostics.len());
    for diagnostic in &response.diagnostics {
        bytes.push(match diagnostic.severity() {
            RichDiagnosticSeverityV1::Error => 0,
            RichDiagnosticSeverityV1::Warning => 1,
            RichDiagnosticSeverityV1::Info => 2,
        });
        put_text(&mut bytes, diagnostic.code().as_str());
        put_text(&mut bytes, diagnostic.message());
        match diagnostic.primary() {
            None => bytes.push(0),
            Some(RichDiagnosticLocationV1::Source(location)) => {
                bytes.push(1);
                put_text(&mut bytes, location.document().authority().label().as_str());
                put_text(
                    &mut bytes,
                    location.document().authority().identity().as_str(),
                );
                put_text(&mut bytes, location.document().path().as_str());
                put_u32(&mut bytes, location.range().start());
                put_u32(&mut bytes, location.range().end());
            }
            Some(RichDiagnosticLocationV1::Output(range)) => {
                bytes.push(2);
                put_u64(&mut bytes, range.start());
                put_u64(&mut bytes, range.end());
            }
        }
        put_len(&mut bytes, diagnostic.notes().len());
        for note in diagnostic.notes() {
            put_text(&mut bytes, note);
        }
    }
    Ok(Digest::sha256(bytes))
}

fn put_u32(bytes: &mut Vec<u8>, value: u32) {
    bytes.extend_from_slice(&value.to_be_bytes());
}

fn put_u64(bytes: &mut Vec<u8>, value: u64) {
    bytes.extend_from_slice(&value.to_be_bytes());
}

fn put_len(bytes: &mut Vec<u8>, value: usize) {
    put_u64(bytes, u64::try_from(value).unwrap_or(u64::MAX));
}

fn put_bytes(output: &mut Vec<u8>, value: &[u8]) {
    put_len(output, value.len());
    output.extend_from_slice(value);
}

fn put_text(output: &mut Vec<u8>, value: &str) {
    put_bytes(output, value.as_bytes());
}

/// Built-in canonical JSON transform, routed through [`FormatTransformV1`].
#[derive(Clone, Copy, Debug, Default)]
pub struct CanonicalJsonTransformV1;

impl FormatTransformV1 for CanonicalJsonTransformV1 {
    fn identity(&self) -> TransformIdentityV1 {
        TransformIdentityV1::new(
            RichNameV1::new("canonical-json").expect("constant transform name is valid"),
            "malm-config-canonical-json/1",
        )
        .expect("constant transform identity is valid")
    }

    fn transform(
        &self,
        request: &TransformRequestV1,
    ) -> Result<TransformResponseV1, TransformFailureV1> {
        let pretty_name = RichNameV1::new("pretty").expect("constant option name is valid");
        reject_unexpected_inputs(
            request,
            &[&pretty_name],
            "canonical-json accepts only the optional boolean `pretty` option",
            "canonical-json does not accept resources",
        )?;
        let pretty = match request.options.get(&pretty_name) {
            Some(option) => option.value.as_bool().ok_or_else(|| {
                transform_failure(
                    TransformFailureKindV1::InvalidRequest,
                    "canonical-json option `pretty` must be boolean",
                )
            })?,
            None => false,
        };
        let mut writer = JsonWriter::new(pretty);
        writer.write_value(request.document.root(), 0)?;
        writer.append(b"\n")?;
        TransformResponseV1::new(writer.finish(), "application/json", Vec::new()).map_err(|error| {
            transform_failure(
                TransformFailureKindV1::InvalidResult,
                format!("built-in response validation failed: {error}"),
            )
        })
    }
}

/// Built-in exact text-field transform routed through [`FormatTransformV1`].
#[derive(Clone, Copy, Debug, Default)]
pub struct PlainTextTransformV1;

impl FormatTransformV1 for PlainTextTransformV1 {
    fn identity(&self) -> TransformIdentityV1 {
        TransformIdentityV1::new(
            RichNameV1::new("plain-text").expect("constant transform name is valid"),
            "malm-config-plain-text/1",
        )
        .expect("constant transform identity is valid")
    }

    fn transform(
        &self,
        request: &TransformRequestV1,
    ) -> Result<TransformResponseV1, TransformFailureV1> {
        let field_name = RichNameV1::new("field").expect("constant option name is valid");
        let newline_name =
            RichNameV1::new("trailing-newline").expect("constant option name is valid");
        reject_unexpected_inputs(
            request,
            &[&field_name, &newline_name],
            "plain-text accepts only `field` and `trailing-newline` options",
            "plain-text does not accept resources",
        )?;
        let field = match request.options.get(&field_name) {
            Some(option) => option.value.as_string().ok_or_else(|| {
                transform_failure(
                    TransformFailureKindV1::InvalidRequest,
                    "plain-text option `field` must be a string",
                )
            })?,
            None => "text",
        };
        let trailing_newline = match request.options.get(&newline_name) {
            Some(option) => option.value.as_bool().ok_or_else(|| {
                transform_failure(
                    TransformFailureKindV1::InvalidRequest,
                    "plain-text option `trailing-newline` must be boolean",
                )
            })?,
            None => false,
        };
        let root = request
            .document
            .root()
            .as_record()
            .expect("canonical document roots are records");
        let value = root.get(field).ok_or_else(|| {
            transform_failure(
                TransformFailureKindV1::InvalidRequest,
                format!("plain-text document has no field {field:?}"),
            )
        })?;
        let text = match &value.0 {
            TypedValueDataV1::String(value) => value.as_str(),
            TypedValueDataV1::Path(value) => value.as_str(),
            _ => {
                return Err(transform_failure(
                    TransformFailureKindV1::InvalidRequest,
                    "plain-text selected field must be a string or path",
                ));
            }
        };
        let mut output = text.as_bytes().to_vec();
        if output.len() > MAX_TRANSFORM_OUTPUT_BYTES {
            return Err(transform_failure(
                TransformFailureKindV1::ResourceLimit,
                "plain-text output exceeds its byte limit",
            ));
        }
        if trailing_newline && !output.ends_with(b"\n") {
            append_builtin_output(&mut output, b"\n", "plain-text")?;
        }
        TransformResponseV1::new(output, "text/plain", Vec::new()).map_err(|error| {
            transform_failure(
                TransformFailureKindV1::InvalidResult,
                format!("built-in response validation failed: {error}"),
            )
        })
    }
}

/// Built-in deterministic flat key-value transform routed through the common boundary.
#[derive(Clone, Copy, Debug, Default)]
pub struct KeyValueTransformV1;

impl FormatTransformV1 for KeyValueTransformV1 {
    fn identity(&self) -> TransformIdentityV1 {
        TransformIdentityV1::new(
            RichNameV1::new("key-value").expect("constant transform name is valid"),
            "malm-config-key-value/1",
        )
        .expect("constant transform identity is valid")
    }

    fn transform(
        &self,
        request: &TransformRequestV1,
    ) -> Result<TransformResponseV1, TransformFailureV1> {
        let separator_name = RichNameV1::new("separator").expect("constant option name is valid");
        reject_unexpected_inputs(
            request,
            &[&separator_name],
            "key-value accepts only the optional string `separator` option",
            "key-value does not accept resources",
        )?;
        let separator = match request.options.get(&separator_name) {
            Some(option) => option.value.as_string().ok_or_else(|| {
                transform_failure(
                    TransformFailureKindV1::InvalidRequest,
                    "key-value option `separator` must be a string",
                )
            })?,
            None => "=",
        };
        if separator.is_empty() || separator.len() > 16 || separator.chars().any(char::is_control) {
            return Err(transform_failure(
                TransformFailureKindV1::InvalidRequest,
                "key-value separator must be 1..=16 non-control bytes",
            ));
        }
        let root = request
            .document
            .root()
            .as_record()
            .expect("canonical document roots are records");
        let mut output = Vec::new();
        for (key, value) in root {
            append_builtin_output(&mut output, key.as_str().as_bytes(), "key-value")?;
            append_builtin_output(&mut output, separator.as_bytes(), "key-value")?;
            write_key_value_scalar(&mut output, value)?;
            append_builtin_output(&mut output, b"\n", "key-value")?;
        }
        TransformResponseV1::new(output, "text/plain", Vec::new()).map_err(|error| {
            transform_failure(
                TransformFailureKindV1::InvalidResult,
                format!("built-in response validation failed: {error}"),
            )
        })
    }
}

fn write_key_value_scalar(
    output: &mut Vec<u8>,
    value: &TypedValueV1,
) -> Result<(), TransformFailureV1> {
    match &value.0 {
        TypedValueDataV1::Null => Ok(()),
        TypedValueDataV1::Boolean(value) => {
            append_builtin_output(output, value.to_string().as_bytes(), "key-value")
        }
        TypedValueDataV1::Integer(value) => {
            append_builtin_output(output, value.to_string().as_bytes(), "key-value")
        }
        TypedValueDataV1::Unsigned(value) => {
            append_builtin_output(output, value.to_string().as_bytes(), "key-value")
        }
        TypedValueDataV1::Float(value) => {
            let mut text = value.get().to_string();
            if !text.contains(['.', 'e', 'E']) {
                text.push_str(".0");
            }
            append_builtin_output(output, text.as_bytes(), "key-value")
        }
        TypedValueDataV1::String(value) => write_escaped_key_value(output, value),
        TypedValueDataV1::Path(value) => write_escaped_key_value(output, value.as_str()),
        TypedValueDataV1::List(_)
        | TypedValueDataV1::Record(_)
        | TypedValueDataV1::Collection(_) => Err(transform_failure(
            TransformFailureKindV1::InvalidRequest,
            "key-value root fields must be scalar values",
        )),
    }
}

fn write_escaped_key_value(output: &mut Vec<u8>, value: &str) -> Result<(), TransformFailureV1> {
    for character in value.chars() {
        match character {
            '\\' => append_builtin_output(output, b"\\\\", "key-value")?,
            '\n' => append_builtin_output(output, b"\\n", "key-value")?,
            '\r' => append_builtin_output(output, b"\\r", "key-value")?,
            '\t' => append_builtin_output(output, b"\\t", "key-value")?,
            character if character.is_control() => {
                append_builtin_output(
                    output,
                    format!("\\u{{{:x}}}", u32::from(character)).as_bytes(),
                    "key-value",
                )?;
            }
            character => {
                let mut encoded = [0_u8; 4];
                append_builtin_output(
                    output,
                    character.encode_utf8(&mut encoded).as_bytes(),
                    "key-value",
                )?;
            }
        }
    }
    Ok(())
}

fn append_builtin_output(
    output: &mut Vec<u8>,
    value: &[u8],
    transform: &str,
) -> Result<(), TransformFailureV1> {
    if output.len().saturating_add(value.len()) > MAX_TRANSFORM_OUTPUT_BYTES {
        return Err(transform_failure(
            TransformFailureKindV1::ResourceLimit,
            format!("{transform} output exceeds {MAX_TRANSFORM_OUTPUT_BYTES} bytes"),
        ));
    }
    output.extend_from_slice(value);
    Ok(())
}

/// Checks common option and resource rules for the built-in transforms.
///
/// Callers supply permitted option names and exact rejection messages. Unknown
/// options are checked before unexpected resources to preserve error order.
fn reject_unexpected_inputs(
    request: &TransformRequestV1,
    permitted_options: &[&RichNameV1],
    unknown_option: &'static str,
    unexpected_resources: &'static str,
) -> Result<(), TransformFailureV1> {
    if request
        .options
        .keys()
        .any(|name| !permitted_options.contains(&name))
    {
        return Err(transform_failure(
            TransformFailureKindV1::InvalidRequest,
            unknown_option,
        ));
    }
    if !request.resources.is_empty() {
        return Err(transform_failure(
            TransformFailureKindV1::InvalidRequest,
            unexpected_resources,
        ));
    }
    Ok(())
}

fn transform_failure(
    kind: TransformFailureKindV1,
    message: impl Into<String>,
) -> TransformFailureV1 {
    TransformFailureV1::new(kind, message, Vec::new())
        .expect("built-in transform failure is bounded")
}

struct JsonWriter {
    output: Vec<u8>,
    pretty: bool,
}

impl JsonWriter {
    fn new(pretty: bool) -> Self {
        Self {
            output: Vec::new(),
            pretty,
        }
    }

    fn finish(self) -> Vec<u8> {
        self.output
    }

    fn append(&mut self, bytes: &[u8]) -> Result<(), TransformFailureV1> {
        let actual = self.output.len().saturating_add(bytes.len());
        if actual > MAX_TRANSFORM_OUTPUT_BYTES {
            return Err(transform_failure(
                TransformFailureKindV1::ResourceLimit,
                format!("JSON output exceeds {MAX_TRANSFORM_OUTPUT_BYTES} bytes"),
            ));
        }
        self.output.extend_from_slice(bytes);
        Ok(())
    }

    fn write_value(
        &mut self,
        value: &TypedValueV1,
        depth: usize,
    ) -> Result<(), TransformFailureV1> {
        match &value.0 {
            TypedValueDataV1::Null => self.append(b"null"),
            TypedValueDataV1::Boolean(true) => self.append(b"true"),
            TypedValueDataV1::Boolean(false) => self.append(b"false"),
            TypedValueDataV1::Integer(value) => self.append(value.to_string().as_bytes()),
            TypedValueDataV1::Unsigned(value) => self.append(value.to_string().as_bytes()),
            TypedValueDataV1::Float(value) => {
                let mut text = value.get().to_string();
                if !text.contains(['.', 'e', 'E']) {
                    text.push_str(".0");
                }
                self.append(text.as_bytes())
            }
            TypedValueDataV1::String(value) => self.write_string(value),
            TypedValueDataV1::Path(value) => self.write_string(value.as_str()),
            TypedValueDataV1::List(values) => self.write_list(values, depth),
            TypedValueDataV1::Record(values) | TypedValueDataV1::Collection(values) => {
                self.write_map(values, depth)
            }
        }
    }

    fn write_list(
        &mut self,
        values: &[TypedValueV1],
        depth: usize,
    ) -> Result<(), TransformFailureV1> {
        self.append(b"[")?;
        for (index, value) in values.iter().enumerate() {
            if index != 0 {
                self.append(b",")?;
            }
            self.separator(depth + 1)?;
            self.write_value(value, depth + 1)?;
        }
        if !values.is_empty() {
            self.separator(depth)?;
        }
        self.append(b"]")
    }

    fn write_map(
        &mut self,
        values: &BTreeMap<crate::RichKeyV1, TypedValueV1>,
        depth: usize,
    ) -> Result<(), TransformFailureV1> {
        self.append(b"{")?;
        for (index, (key, value)) in values.iter().enumerate() {
            if index != 0 {
                self.append(b",")?;
            }
            self.separator(depth + 1)?;
            self.write_string(key.as_str())?;
            self.append(if self.pretty { b": " } else { b":" })?;
            self.write_value(value, depth + 1)?;
        }
        if !values.is_empty() {
            self.separator(depth)?;
        }
        self.append(b"}")
    }

    fn separator(&mut self, depth: usize) -> Result<(), TransformFailureV1> {
        if self.pretty {
            self.append(b"\n")?;
            for _ in 0..depth {
                self.append(b"  ")?;
            }
        }
        Ok(())
    }

    fn write_string(&mut self, value: &str) -> Result<(), TransformFailureV1> {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        self.append(b"\"")?;
        for character in value.chars() {
            match character {
                '"' => self.append(b"\\\"")?,
                '\\' => self.append(b"\\\\")?,
                '\u{08}' => self.append(b"\\b")?,
                '\u{0c}' => self.append(b"\\f")?,
                '\n' => self.append(b"\\n")?,
                '\r' => self.append(b"\\r")?,
                '\t' => self.append(b"\\t")?,
                character if character <= '\u{1f}' => {
                    let value = character as u8;
                    self.append(&[
                        b'\\',
                        b'u',
                        b'0',
                        b'0',
                        HEX[usize::from(value >> 4)],
                        HEX[usize::from(value & 0x0f)],
                    ])?;
                }
                character => {
                    let mut encoded = [0_u8; 4];
                    self.append(character.encode_utf8(&mut encoded).as_bytes())?;
                }
            }
        }
        self.append(b"\"")
    }
}
