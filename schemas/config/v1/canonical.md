# Canonical typed-document identity (`config/v1`)

This contract defines the exact binary preimage and SHA-256 identity of a
`CanonicalTypedDocumentV1`. Evaluator, store, engine, and format-transform
implementers use it whenever independently constructed rich IR must have one
stable identity.

Captured KDL source has no canonical source encoding. Each source keeps the
SHA-256 digest and byte length of its exact captured bytes, so comments,
whitespace, and alternative valid KDL spellings change source identity. The
typed-document encoding below includes those source identities rather than the
source bytes themselves.

## Encoding primitives

The encoder emits fields consecutively with no padding, alignment, or trailing
marker.

| Notation | Encoding |
| --- | --- |
| `tag(n)` | one unsigned byte `n` |
| `u32(n)` | four-byte unsigned big-endian integer |
| `u64(n)` | eight-byte unsigned big-endian integer |
| `i64(n)` | eight-byte two's-complement big-endian integer |
| `len(n)` | `u64(n)` |
| `bytes(b)` | `len(byte_length(b))`, then exact bytes `b` |
| `text(s)` | `bytes(UTF-8(s))` |

Every collection count, path-segment count, diagnostic note count, and byte or
text length is encoded with `len`. Source ranges are `u32`; captured source
lengths and transform output ranges use `u64` where their enclosing contract
specifies them.

Canonical maps iterate in ascending key order. For strings this is exact UTF-8
byte order. A document ID map sorts by `(authority label, authority digest,
pack path)`. A value-path map sorts lexicographically by its key-segment vector.
Lists, include/module edges, provenance records for one path, and evaluation
frames retain their semantic vector order.

## Typed document preimage

`canonical_typed_document_bytes_v1(document)` first validates the complete
document, then emits:

```text
raw bytes  "malm-canonical-typed-document\0"
u32        document IR version, exactly 1
value      tagged record root

len        source-document count
repeat source documents in canonical document-ID order:
    document-id
    text    exact source SHA-256 digest spelling
    u64     exact captured source byte length

len        include/module edge count
repeat edges in semantic order:
    document-id  source document
    u32          source range start
    u32          source range end
    document-id  target document
    text         target source SHA-256 digest spelling
    dependency
    edge-kind

len        value-path entry count
repeat entries in canonical value-path order:
    value-path
    len     provenance record count
    repeat records in retained sequence order:
        provenance-record
```

The domain prefix is raw and includes its final NUL byte. It does not have a
length prefix. The encoded document must not exceed 67,108,864 bytes.

## Typed values

Every value starts with one tag:

| Tag | Kind | Payload |
| ---: | --- | --- |
| 0 | null | none |
| 1 | boolean | `tag(0)` for false or `tag(1)` for true |
| 2 | signed integer | `i64(value)` |
| 3 | unsigned integer | `u64(value)` |
| 4 | float | `u64(normalized_binary64_bits)` |
| 5 | string | `text(value)` |
| 6 | target path | `text(validated_path)` |
| 7 | list | `len(count)`, then each value in list order |
| 8 | record | `len(count)`, then `text(key)` and value for each canonical key |
| 9 | keyed collection | `len(count)`, then `text(key)` and value for each canonical key |

Record and collection tags remain distinct even though both encode sorted key
maps. Negative zero is normalized to positive zero before its bits are encoded.
Non-finite floats cannot enter the IR. Signed integers, unsigned integers, and
floats use distinct tags even when they have the same mathematical value.

## Document IDs and source identities

A document ID emits three length-prefixed UTF-8 strings:

```text
text  authority label
text  authority digest
text  pack path
```

Each source-document entry then emits its own exact SHA-256 source digest and
captured byte length. Source entries are a canonical map, so caller insertion
order has no effect.

Validation rejects more than 1,024 source documents, a source length above the
per-document limit, or a source identity that violates its validated component
types.

## Include and module edges

Each edge begins with the source document ID and its half-open source range,
then the target document ID and target source digest. Its optional dependency is
encoded as:

| Tag | Dependency payload |
| ---: | --- |
| 0 | absent |
| 1 | `text(direct_dependency_alias)` |

The edge kind follows:

| Tag | Edge payload |
| ---: | --- |
| 0 | include, no additional payload |
| 1 | module, then `text(module_contribution_name)` |

Edges are not sorted. Their traversal order is semantic and is encoded exactly.
Validation rejects more than 16,384 edges, an unknown source or target document,
a source range beyond its captured byte length, or a target digest that does not
match the target's source-document entry.

## Value paths and provenance

A value path emits `len(segment_count)` followed by `text(segment)` for each
`RichKeyV1` segment. Path entries are sorted canonically. A path can remain in
provenance after an unset or collection removal; it need not identify a value
still present in the root.

Each provenance record emits:

```text
u64          globally unique sequence number
document-id  source document
u32          source range start
u32          source range end
operation
len          evaluation frame count
repeat frames in evaluation-stack order:
    frame
```

Operation tags are:

| Tag | Operation | Additional payload |
| ---: | --- | --- |
| 0 | supplied variable | none |
| 1 | defaulted variable | none |
| 2 | absent optional variable | none |
| 3 | computed variable | none |
| 4 | document `emit` | none |
| 5 | ordered patch | `u32(operation_index)` |

The operation index is the zero-based position within its `OrderedPatchV1`.
Canonical document evaluation currently stores emit and patch records in the
value-path map; the other operation tags are reserved by the shared provenance
model and have this fixed encoding if present.

Evaluation frames are:

| Tag | Frame | Payload |
| ---: | --- | --- |
| 0 | fragment | `text(fragment_name)` |
| 1 | conditional | `tag(0)` for else or `tag(1)` for then |
| 2 | loop | `text(value_or_range_binding)`, then `u32(zero_based_iteration)` |

Validation permits at most 262,144 provenance records and 64 frames per record.
Every provenance source document must be present, and every range must fit its
captured byte length. Sequence numbers must be globally unique; within one
value path they must be strictly increasing.

## Standalone typed values

Format-transform option fingerprints use the same tagged value production with
a separate domain:

```text
raw bytes  "malm-canonical-typed-value\0"
value      one validated typed value
```

The domain is raw and NUL-terminated. The value encoding has no IR version or
source-provenance fields. These complete bytes, including the domain, are
length-prefixed inside the transform request preimage.

## Digest and compatibility

`canonical_typed_document_digest_v1` is SHA-256 over the complete bytes returned
by `canonical_typed_document_bytes_v1`. No field may be omitted merely because
it is empty; empty vectors and maps still emit their zero `len`.

Transform request and response identities use separate domains and are defined
in [transform.md](transform.md#request-fingerprint). The golden typed-document
digest in [`fixtures/golden/rich-ir.json`](fixtures/golden/rich-ir.json) pins
the evaluator's canonical conformance document.

Version 1 fixes every domain byte, tag, field order, integer width, length
encoding, map order, and retained semantic vector order described here. An
incompatible identity change requires a new contract version.
