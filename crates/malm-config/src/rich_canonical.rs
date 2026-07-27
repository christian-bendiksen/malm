use malm_types::Digest;

use crate::MAX_CANONICAL_TYPED_DOCUMENT_BYTES;
use crate::rich::{
    CanonicalTypedDocumentV1, CapturedDocumentEdgeKindV1, CapturedDocumentIdV1, EvaluationFrameV1,
    ProvenanceOperationV1, ProvenanceRecordV1, RichConfigErrorV1, RichValuePathV1,
    TypedValueDataV1, TypedValueV1,
};

/// Encodes the complete typed document and source provenance in canonical binary form.
pub fn canonical_typed_document_bytes_v1(
    document: &CanonicalTypedDocumentV1,
) -> Result<Vec<u8>, RichConfigErrorV1> {
    document.validate()?;
    let mut encoder = Encoder::new();
    encoder.raw(b"malm-canonical-typed-document\0")?;
    encoder.u32(document.version())?;
    encode_value(&mut encoder, document.root())?;

    encoder.len(document.source_documents().len())?;
    for (id, identity) in document.source_documents() {
        encode_document_id(&mut encoder, id)?;
        encoder.text(identity.digest().as_str())?;
        encoder.u64(identity.byte_len())?;
    }

    encoder.len(document.includes().len())?;
    for include in document.includes() {
        encode_document_id(&mut encoder, include.source().document())?;
        encoder.u32(include.source().range().start())?;
        encoder.u32(include.source().range().end())?;
        encode_document_id(&mut encoder, include.target())?;
        encoder.text(include.target_digest().as_str())?;
        match include.dependency() {
            None => encoder.tag(0)?,
            Some(alias) => {
                encoder.tag(1)?;
                encoder.text(alias.as_str())?;
            }
        }
        match include.kind() {
            CapturedDocumentEdgeKindV1::Include => encoder.tag(0)?,
            CapturedDocumentEdgeKindV1::Module { name } => {
                encoder.tag(1)?;
                encoder.text(name.as_str())?;
            }
        }
    }

    encoder.len(document.provenance().len())?;
    for (path, records) in document.provenance() {
        encode_path(&mut encoder, path)?;
        encoder.len(records.len())?;
        for record in records {
            encode_provenance(&mut encoder, record)?;
        }
    }
    Ok(encoder.finish())
}

/// Computes the SHA-256 identity of canonical typed-document bytes.
pub fn canonical_typed_document_digest_v1(
    document: &CanonicalTypedDocumentV1,
) -> Result<Digest, RichConfigErrorV1> {
    canonical_typed_document_bytes_v1(document).map(Digest::sha256)
}

pub(crate) fn canonical_value_bytes_v1(value: &TypedValueV1) -> Result<Vec<u8>, RichConfigErrorV1> {
    value.validate()?;
    let mut encoder = Encoder::new();
    encoder.raw(b"malm-canonical-typed-value\0")?;
    encode_value(&mut encoder, value)?;
    Ok(encoder.finish())
}

struct Encoder {
    bytes: Vec<u8>,
}

impl Encoder {
    fn new() -> Self {
        Self { bytes: Vec::new() }
    }

    fn finish(self) -> Vec<u8> {
        self.bytes
    }

    fn raw(&mut self, value: &[u8]) -> Result<(), RichConfigErrorV1> {
        let actual = self.bytes.len().saturating_add(value.len());
        if actual > MAX_CANONICAL_TYPED_DOCUMENT_BYTES {
            return Err(RichConfigErrorV1::LimitExceeded {
                resource: "canonical typed document bytes",
                limit: MAX_CANONICAL_TYPED_DOCUMENT_BYTES,
                actual,
            });
        }
        self.bytes.extend_from_slice(value);
        Ok(())
    }

    fn tag(&mut self, value: u8) -> Result<(), RichConfigErrorV1> {
        self.raw(&[value])
    }

    fn u32(&mut self, value: u32) -> Result<(), RichConfigErrorV1> {
        self.raw(&value.to_be_bytes())
    }

    fn u64(&mut self, value: u64) -> Result<(), RichConfigErrorV1> {
        self.raw(&value.to_be_bytes())
    }

    fn i64(&mut self, value: i64) -> Result<(), RichConfigErrorV1> {
        self.raw(&value.to_be_bytes())
    }

    fn len(&mut self, value: usize) -> Result<(), RichConfigErrorV1> {
        self.u64(u64::try_from(value).unwrap_or(u64::MAX))
    }

    fn bytes(&mut self, value: &[u8]) -> Result<(), RichConfigErrorV1> {
        self.len(value.len())?;
        self.raw(value)
    }

    fn text(&mut self, value: &str) -> Result<(), RichConfigErrorV1> {
        self.bytes(value.as_bytes())
    }
}

fn encode_value(encoder: &mut Encoder, value: &TypedValueV1) -> Result<(), RichConfigErrorV1> {
    match &value.0 {
        TypedValueDataV1::Null => encoder.tag(0),
        TypedValueDataV1::Boolean(value) => {
            encoder.tag(1)?;
            encoder.tag(u8::from(*value))
        }
        TypedValueDataV1::Integer(value) => {
            encoder.tag(2)?;
            encoder.i64(*value)
        }
        TypedValueDataV1::Unsigned(value) => {
            encoder.tag(3)?;
            encoder.u64(*value)
        }
        TypedValueDataV1::Float(value) => {
            encoder.tag(4)?;
            encoder.u64(value.get().to_bits())
        }
        TypedValueDataV1::String(value) => {
            encoder.tag(5)?;
            encoder.text(value)
        }
        TypedValueDataV1::Path(value) => {
            encoder.tag(6)?;
            encoder.text(value.as_str())
        }
        TypedValueDataV1::List(values) => {
            encoder.tag(7)?;
            encoder.len(values.len())?;
            for value in values {
                encode_value(encoder, value)?;
            }
            Ok(())
        }
        TypedValueDataV1::Record(values) => {
            encoder.tag(8)?;
            encoder.len(values.len())?;
            for (name, value) in values {
                encoder.text(name.as_str())?;
                encode_value(encoder, value)?;
            }
            Ok(())
        }
        TypedValueDataV1::Collection(values) => {
            encoder.tag(9)?;
            encoder.len(values.len())?;
            for (key, value) in values {
                encoder.text(key.as_str())?;
                encode_value(encoder, value)?;
            }
            Ok(())
        }
    }
}

fn encode_document_id(
    encoder: &mut Encoder,
    id: &CapturedDocumentIdV1,
) -> Result<(), RichConfigErrorV1> {
    encoder.text(id.authority().label().as_str())?;
    encoder.text(id.authority().identity().as_str())?;
    encoder.text(id.path().as_str())
}

fn encode_path(encoder: &mut Encoder, path: &RichValuePathV1) -> Result<(), RichConfigErrorV1> {
    encoder.len(path.segments().len())?;
    for segment in path.segments() {
        encoder.text(segment.as_str())?;
    }
    Ok(())
}

fn encode_provenance(
    encoder: &mut Encoder,
    record: &ProvenanceRecordV1,
) -> Result<(), RichConfigErrorV1> {
    encoder.u64(record.sequence())?;
    encode_document_id(encoder, record.location().document())?;
    encoder.u32(record.location().range().start())?;
    encoder.u32(record.location().range().end())?;
    match record.operation() {
        ProvenanceOperationV1::VariableSupplied => encoder.tag(0)?,
        ProvenanceOperationV1::VariableDefault => encoder.tag(1)?,
        ProvenanceOperationV1::VariableOptionalAbsent => encoder.tag(2)?,
        ProvenanceOperationV1::VariableComputed => encoder.tag(3)?,
        ProvenanceOperationV1::Emit => encoder.tag(4)?,
        ProvenanceOperationV1::Patch { operation } => {
            encoder.tag(5)?;
            encoder.u32(*operation)?;
        }
    }
    encoder.len(record.frames().len())?;
    for frame in record.frames() {
        match frame {
            EvaluationFrameV1::Fragment(name) => {
                encoder.tag(0)?;
                encoder.text(name.as_str())?;
            }
            EvaluationFrameV1::Conditional { then_branch } => {
                encoder.tag(1)?;
                encoder.tag(u8::from(*then_branch))?;
            }
            EvaluationFrameV1::Loop { binding, iteration } => {
                encoder.tag(2)?;
                encoder.text(binding.as_str())?;
                encoder.u32(*iteration)?;
            }
        }
    }
    Ok(())
}
