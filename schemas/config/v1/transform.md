# Format transform contract (`config/v1`)

The `config/v1` format-transform contract is the pure boundary that turns a
canonical typed document into bounded output bytes. Built-in implementers,
format-component authors, hosts, and engine adapters use it to agree on request
validation, response validation, diagnostics, identity, and provenance.

Contract version 1 defines one function-shaped semantic boundary:

```text
transform(canonical typed document, explicit typed options,
          declared named resource bytes)
  -> bounded output bytes and structured diagnostics
```

Built-in and component transforms use this same semantic request and response.
Every invocation validates the complete request and transform identity before
execution, then validates a returned success or failure before accepting it.

## Capability boundary

The transform model is ABI-neutral and grants no ambient capability. A request
contains every value and byte the transform can observe. Resource names do not
authorize discovery, and a transform cannot open a path, read the environment,
access a network or process, observe a clock or randomness source, inspect Malm
state or a deployment target, or publish output directly.

This contract does not define component loading, authorization, compilation,
instantiation, scheduling, or runtime limits. A host may invoke a component only
after enforcing the independent component admission contract and its matching
locked execution profile. There is no native-command, effectful-provider, or
predecessor-ABI compatibility branch.

## Transform identity

Every invocation has a `TransformIdentityV1` containing contract version 1, a
`RichNameV1` transform name, and exactly one implementation identity:

| Implementation | Identity fields |
| --- | --- |
| Built-in | nonempty implementation-version text of at most 256 UTF-8 bytes and no control characters |
| Component | exact component SHA-256 digest, interface string, and execution-profile digest |

A component interface must be exactly `format-component/v1`. Both the component
digest and execution-profile digest participate in request identity. An invalid
contract version or identity is rejected before the implementation runs.

The three standard built-in identities are:

| Transform | Implementation version |
| --- | --- |
| `canonical-json` | `malm-config-canonical-json/1` |
| `plain-text` | `malm-config-plain-text/1` |
| `key-value` | `malm-config-key-value/1` |

## Request

A `TransformRequestV1` contains contract version 1, one complete
`CanonicalTypedDocumentV1`, a canonical name-sorted option map, and a canonical
name-sorted resource map.

Each option has a unique `RichNameV1` and one validated `TypedValueV1`. The map
key must equal the option's own name. Duplicate names are rejected before a
request exists. Validation canonical-encodes every option independently and
checks their aggregate encoded size.

Each declared resource has a unique `RichNameV1`, a declared SHA-256 digest,
and exact bytes. The map key must equal the resource's own name. Construction,
request validation, and therefore every invocation recompute SHA-256 and reject
a mismatch. Per-resource and aggregate bytes are bounded. A resource is found
only in this map; its name is not a filesystem or pack lookup capability.

Request validation also validates and canonical-encodes the complete typed
document. Any invalid root, source identity, provenance reference, ordering
rule, or canonical-byte limit is an invalid request.

## Invocation sequence and errors

`run_format_transform_invocation_v1` performs these steps in order:

1. Validate the complete request.
2. Validate the supplied transform identity.
3. Compute the request fingerprint.
4. Invoke the implementation or host port exactly once.
5. Validate a returned transform failure, or validate a successful response
   against the request.
6. For success, compute document and response digests and return invocation
   provenance.

`run_format_transform_v1` exposes three semantic error classes:

| Error | Meaning |
| --- | --- |
| `InvalidRequest` | request, identity, or pre-execution fingerprint validation failed |
| `TransformFailed` | the implementation returned a well-formed semantic failure |
| `InvalidResponse` | a returned success or failure violated the boundary |

The host-port runner additionally keeps `Infrastructure` errors separate from
all three semantic classes. A trap, host admission failure, or transport error
must not be relabeled as a transform's semantic failure. A malformed success or
failure is a boundary error and must not be accepted as `TransformFailed`.

## Successful response

A `TransformResponseV1` contains exact opaque output bytes, an ASCII media type,
and canonical structured diagnostics.

The output is at most 67,108,864 bytes. A media type is valid only when it is
nonempty, at most 128 bytes, contains `/`, and contains only ASCII letters,
digits, `/`, `+`, `-`, or `.`. This is the complete version 1 media-type profile.

Success diagnostics are sorted by their complete structured tuple and unique.
An error-severity diagnostic makes the success invalid. A warning or info
diagnostic may have no primary location, one source location, or one output
location:

- A source location must name a source document present in the request's typed
  document and end within that document's exact captured byte length.
- An output location is a half-open ordered byte range and must end within the
  returned output.

The response is revalidated after execution even when an in-process constructor
already validated its shape.

## Transform failure

A `TransformFailureV1` has one closed failure kind, a message of at most 16,384
UTF-8 bytes, and canonical diagnostics. The closed kinds are:

- `InvalidRequest`;
- `UnsupportedFormat`;
- `ResourceLimit`;
- `InvalidResult`;
- `Internal`.

These semantic-model variant names map, in the same order, to the WIT cases
`invalid-request`, `unsupported-format`, `resource-limit`, `invalid-result`, and
`internal`.

Failure diagnostics may use source locations under the same document and range
rules as success. They cannot use output locations because no successful output
exists. A failure with an output diagnostic is an invalid response, not a valid
transform failure.

## Diagnostic model

Each diagnostic contains severity, a stable lowercase `RichNameV1` code,
bounded message, optional primary location, and bounded notes. The canonical
sort tuple is the complete field tuple in that order. Severity order is error,
warning, then info; the remaining validated fields provide deterministic
tie-breaking. Exact duplicate diagnostics are rejected.

The shared ceilings are 256 diagnostics, 16,384 bytes per message or note, 64
notes per diagnostic, and 1,048,576 aggregate message and note bytes. These
limits apply to success and failure results.

## Request fingerprint

`format_transform_request_digest_v1(identity, request)` is SHA-256 over the
following preimage. `text`, `bytes`, `len`, `u32`, and tags use the encodings
defined in [canonical.md](canonical.md#encoding-primitives).

```text
text  "malm-format-transform-request"
u32   transform contract version, exactly 1
text  transform name
implementation
text  canonical typed-document digest

len   option count
repeat options in canonical name order:
    text   option name
    bytes  complete canonical typed-value bytes

len   resource count
repeat resources in canonical name order:
    text  resource name
    text  declared SHA-256 digest
    len   exact resource byte length
```

The request domain is length-prefixed text and has no NUL terminator. A built-in
implementation emits `tag(0)` and its implementation-version text. A component
emits `tag(1)`, component digest text, interface text, and execution-profile
digest text, in that order.

Each option's `bytes` payload is the complete standalone value encoding that
starts with raw `malm-canonical-typed-value\0`, followed by the tagged value.
Resource bytes are not repeated directly in the request preimage; the validated
SHA-256 digest binds their exact bytes, and the preimage separately binds their
length.

## Response fingerprint

`format_transform_response_digest_v1(response)` is SHA-256 over:

```text
text   "malm-format-transform-response"
u32    transform contract version, exactly 1
text   media type
bytes  exact output
len    diagnostic count
repeat diagnostics in canonical order:
    tag   severity: 0 error, 1 warning, 2 info
    text  code
    text  message
    diagnostic-location
    len   note count
    repeat notes in retained order:
        text  note
```

The response domain is length-prefixed text and has no NUL terminator. A
diagnostic location uses `tag(0)` for absent, `tag(1)` for source, or `tag(2)`
for output. A source location then emits authority label text, authority digest
text, pack-path text, `u32(start)`, and `u32(end)`. An output location emits
`u64(start)` and `u64(end)`.

The digest function validates request-independent response shape. Invocation
provenance records the digest only after request-relative source and output
locations also pass validation. Error severity is assigned tag 0 as part of the
closed diagnostic encoding, but it cannot occur in a valid success.

## Successful invocation provenance

`TransformProvenanceV1` binds:

- the complete validated transform identity;
- the request digest;
- the canonical typed-document digest;
- a canonical name-sorted map of each resource name to its validated digest;
- the response digest.

This lets preparation persist identities from before and after execution
without treating implementation or caller map order as semantic.

## Canonical JSON built-in

`canonical-json` accepts only optional boolean option `pretty`, which defaults
to `#false`. It rejects every resource. Unknown options are rejected before
unexpected resources.

Records and keyed collections become JSON objects in canonical key order. Lists
retain order. Null, booleans, signed and unsigned integers, finite floats,
strings, and paths become their natural JSON values; paths are strings. A float
always retains a decimal point or exponent, appending `.0` when necessary, so
an integer and float remain textually distinct.

JSON strings escape quote and backslash, use `\b`, `\f`, `\n`, `\r`, and `\t`
for those controls, encode other U+0000 through U+001F controls as lowercase
`\u00xx`, and retain all other UTF-8 characters. Compact output has no optional
whitespace. Pretty output uses two spaces per nesting level and deterministic
line breaks. Both forms end with exactly one LF emitted by the transform. The
media type is `application/json`.

## Plain text built-in

`plain-text` accepts only optional string option `field` and optional boolean
option `trailing-newline`; it rejects every resource. `field` defaults to
`text`, and `trailing-newline` defaults to false. Unknown options are rejected
before unexpected resources.

The root is a record. The selected field must exist and contain a string or
path. Its exact UTF-8 bytes are returned. When `trailing-newline` is true, one LF
is appended only if the selected bytes do not already end in LF. Existing
trailing newlines are not normalized or removed. The media type is `text/plain`.

## Key/value built-in

`key-value` accepts only optional string option `separator`, which defaults to
`=`. It rejects every resource. Unknown options are rejected before unexpected
resources. The separator must be 1 through 16 UTF-8 bytes and contain no control
character.

Every root record field must be scalar. Fields are emitted in canonical key
order as exact key bytes, separator bytes, encoded value bytes, and LF. Null
emits an empty value; booleans use `true` or `false`; signed and unsigned
integers use decimal text; finite floats retain a decimal point or exponent.

Strings and paths escape backslash as `\\`, LF as `\n`, CR as `\r`, tab as
`\t`, and every other control character as `\u{lowercase-hex-code-point}`.
Other UTF-8 characters are emitted exactly. Lists, records, and collections as
field values are rejected. The media type is `text/plain`.

## Fixed limits

| Limit | Maximum |
| --- | ---: |
| Contract version | exactly 1 |
| `MAX_TRANSFORM_OPTIONS` | 256 options |
| Aggregate canonical option bytes | 67,108,864 bytes |
| `MAX_TRANSFORM_RESOURCES` | 1,024 resources |
| `MAX_TRANSFORM_RESOURCE_BYTES` | 67,108,864 bytes per resource |
| `MAX_TRANSFORM_TOTAL_RESOURCE_BYTES` | 268,435,456 aggregate resource bytes |
| `MAX_TRANSFORM_OUTPUT_BYTES` | 67,108,864 output bytes |
| Built-in implementation-version text | 256 bytes |
| Response media type | 128 bytes |
| Transform failure message | 16,384 bytes |

The canonical document, each typed value, and all diagnostics remain subject to
their independent [rich IR limits](rich-ir.md#fixed-limits). A built-in that
would exceed the output limit returns `ResourceLimit`; a component host must
also enforce its independently locked runtime profile.

## Compatibility

Version 1 fixes the request and response data, identity fields, validation and
error classification, diagnostic model, fingerprint preimages, built-in names,
options, byte rendering, media types, and limits. The
[`format-component/v1` interface](../../format-component/v1/README.md) adapts
this semantic contract to WebAssembly. An incompatible semantic or identity
change requires a new version.
