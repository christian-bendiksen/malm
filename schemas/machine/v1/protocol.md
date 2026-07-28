# Malm process protocol rules (`machine/v1`)

This page defines the normative wire and processing rules for `machine/v1`.
Client, codec, and process-adapter implementations need it in addition to the
[request](request.schema.json) and [server](server.schema.json) JSON Schemas.

## Terms and boundary

A **record** is one complete LF-terminated JSON value. An **accepted request** is
a complete request record that has passed framing, structural, resource, and
semantic validation. A response is **correlated** only after acceptance, when it
carries the accepted `request_id`. An **uncorrelated error** has
`request_id: null` because no request was accepted.

The protocol carries semantic operation data, not authority to select host
paths or capabilities. The process adapter constructs Engine with any permitted
state root and target authority.

## Record framing and decoding

Each record is UTF-8 JSON followed by exactly one LF byte. A record must be
nonempty before that LF, must not contain a literal CR or another LF byte, and
must be at most 1 MiB including the terminal LF. JSON strings may contain escaped
`\n` and `\t` values where the field's profile permits them.

Readers reject duplicate object keys, unknown or missing fields, trailing data,
and non-integer version or sequence values. Every protocol object is closed. The
schema version uses an unsigned 32-bit integer token and must be exactly `1`. A
different value in that unsigned 32-bit domain is an unsupported version.
Negative, floating, and larger version values are invalid envelopes.

JSON Schema counts string characters and treats all mathematically integral JSON
numbers alike. Strict UTF-8 byte ceilings, the exact integer token profile,
duplicate-key rejection, the requirement that unsupported `expected` and
`found` versions differ, and record framing are therefore normative reader
checks in addition to the structural schemas.

## Canonical writing

The canonical writer emits compact JSON with no insignificant whitespace, then
one LF. Envelope fields occur in this order:

- Request: `schema_version`, `request_id`, `type`, `request`.
- Event: `schema_version`, `request_id`, `sequence`, `type`, `event`.
- Result: `schema_version`, `request_id`, `sequence`, `type`, `result`.
- Error: `schema_version`, `request_id`, `sequence`, `type`, `error`.

Nested fields follow schema order. The golden fixtures pin exact output bytes.
Input field order has no semantic meaning.

## Process transport

`malm machine` accepts exactly one request record per process invocation. It
reads at most one byte beyond the 1 MiB limit. For a rejected record, it emits
one bounded uncorrelated error and does not invoke Engine. For an accepted
record, it flushes the `started` event before invoking Engine.

An Engine failure produces a correlated terminal error and process exit code
`2`. A successful result uses exit code `0`.

## Request envelope

`request_id` is an opaque ASCII identifier selected by the caller. It is 1
through 128 bytes long and contains only letters, digits, `.`, `_`, `:`, or `-`.
It is used only for correlation and grants no authority.

These are two minimal records; each is input to a separate process invocation:

```json
{"schema_version":1,"request_id":"req-1","type":"request","request":{"type":"store_status"}}
{"schema_version":1,"request_id":"req-2","type":"request","request":{"type":"initialize_store"}}
```

Every request variant and its closed fields are normative in
[`request.schema.json`](request.schema.json).

## Operation set

The implemented request variants are exactly these 31 operations:

| Group | Operations |
| --- | --- |
| Store | `store_status`, `initialize_store` |
| Deployment and retained state | `prepare`, `plan`, `artifact`, `commit`, `state`, `recover`, `prune` |
| Lifecycle and retention plans | `checkout`, `disable`, `enable`, `remove_namespace`, `set_history_retention`, `pin`, `unpin`, `add_restore_point`, `drop_restore_point` |
| Bounded inspection | `catalog`, `namespace`, `history`, `generation`, `desired_snapshot`, `canonical_tree`, `artifact_metadata`, `captured_inputs`, `transform_provenance`, `retention`, `tracking`, `status`, `fsck` |

Lock creation and update, tracked-root prepare, and tracked update are not
request variants. They select absolute pack, Git executable, or scratch paths
and remain human or embedded host operations. A `lock_create`, `lock_update`,
`track`, or `update` discriminator is invalid in `machine/v1`, as is any injected
host-path field.

Prepare carries logical authorities and bounded artifact bytes encoded as
lowercase hexadecimal, never host paths. Its operation set carries canonical
symlink and tree digests, optional archive payload and decoder provenance, and
tagged exact target state. These nested records are closed, and all nullable
semantic fields are emitted explicitly. Commit carries the prepared plan ID and
the exact findings approval digest.

Checkout and lifecycle or retention changes prepare normal reviewed plans; they
do not commit implicitly. The operations in the bounded inspection group are
inspection requests and carry their explicit budgets in the request schema.

The checked-in [machine operation inventory](../../../docs/machine-operation-inventory.tsv)
and [cross-adapter operation matrix](../../../docs/operation-matrix.tsv) are
tested against the Rust request and result models, runtime wire codecs, schemas,
and adapter dispatch.

## Host authority

Roots and host capabilities are selected only when Engine is constructed. A
machine request can never select them.

The process adapter maps the logical `home` target authority to its
construction-time home directory for these target-bearing requests: `prepare`,
`commit`, `recover`, `checkout`, `disable`, `enable`, `remove_namespace`,
`set_history_retention`, `pin`, `unpin`, `add_restore_point`,
`drop_restore_point`, `status`, and `fsck` when `observe_targets` is true. Other
requests receive no target authority.

## Accepted response stream

After accepting a complete request, the process emits exactly:

1. One `started` event at sequence `0`, with the same request ID and operation.
2. One result or correlated error at sequence `1`, with the same request ID.
3. No further records.

A successful result operation must match its request. Successful initialization
always reports `ready`. `ResponseStreamValidatorV1` enforces request-ID
correlation, operation matching, ordering, sequencing, and termination without
performing I/O.

The record model reserves positive sequence values through
`9007199254740991`, the largest integer represented exactly by interoperable
JSON implementations. The implemented two-record stream uses only `0` and `1`.

### Reviewed deployment integrity

Prepared deployment results expose the immutable input list and complete
Engine-generated transform provenance. Each transform binds all of the
following:

- Its name.
- Either a built-in implementation label or the component's pack-node,
  pack-content, component-path, component, interface-version, and
  execution-profile identities.
- The request, typed-document, declared-resource, and response digests.
- Every bounded successful diagnostic.

Successful diagnostics are strictly canonical and unique, cannot have error
severity, and bind the exact captured source byte length for every source range.
Results also expose the exact enabled or disabled lifecycle and an optional,
complete, credential-free prepared tracking review. That review contains the
source locator and selector, applied revision and canonical root tree digest,
source subdirectory, config entry point, selected profile, target authority,
sorted acquisition grants, and any retained compatibility component-grant
records. Post-commit tracking inspection remains redacted to selector, revision,
and tree identity.

Machine prepare requests cannot supply transform provenance themselves. Readers
recompute every policy finding ID from its code, message, and approval flag,
reject duplicate finding IDs, and recompute the approval digest. A structurally
valid result with an inconsistent review binding is an invalid envelope.

## Rejected requests

If request decoding fails, no request has been accepted. The only response is
one uncorrelated error with explicit `"request_id":null` and sequence `0`. Even
when a rejected object contains a syntactically valid request ID, the response
must not echo it. Parser messages and rejected bytes are never copied into
protocol errors.

Malformed UTF-8, invalid framing, duplicate keys, and malformed JSON map to
`malformed-json`. Record, depth, object-member, array-item, and aggregate-value
limits map to `frame-resource-limit`. A `schema_version` other than `1` in the
unsigned 32-bit domain maps to `unsupported-machine-version`. Invalid envelopes
and invalid semantics map to `invalid-request`.

## Terminal errors

Every terminal error has a closed category, a stable kebab-case code, a bounded
human-readable message, typed details, and zero through 256 diagnostics.
Messages are informational and must never drive compatibility logic. Error and
diagnostic text permits newline and tab but rejects other control characters.
Diagnostic codes start with a lowercase ASCII letter and contain only lowercase
ASCII letters, digits, and hyphens.

| Code | Category | Required details |
| --- | --- | --- |
| `malformed-json` | `invalid_request` | `none` |
| `invalid-request` | `invalid_request` | `none` |
| `unsupported-machine-version` | `unsupported` | machine `unsupported_schema` |
| `frame-resource-limit` | `resource_limit` | `none` |
| `read-only-store` | `permission_denied` | `none` |
| `store-not-ready` | `conflict` | non-ready `current_status` |
| `state-parent-missing` | `not_found` | `none` |
| `unsafe-directory` | `conflict` | `unsafe_directory` |
| `root-observation-changed` | `conflict` | `root_observation` |
| `state-parent-observation-changed` | `conflict` | `none` |
| `malformed-store-metadata` | `conflict` | `store_metadata` |
| `unsupported-store-version` | `unsupported` | store `unsupported_schema` |
| `store-io` | `unavailable` | `none` |
| `plan-not-found` | `not_found` | `none` |
| `artifact-not-found` | `not_found` | `none` |
| `approval-mismatch` | `conflict` | `none` |
| `stale-plan` | `conflict` | `none` |
| `recovery-required` | `conflict` | `none` |
| `operation-busy` | `conflict` | `none` |
| `invalid-deployment` | `conflict` | `none` |
| `unsafe-target` | `conflict` | `none` |
| `corrupt-store` | `conflict` | `none` |
| `corrupt-artifact` | `conflict` | `none` |
| `deployment-io` | `unavailable` | `none` |
| `internal-engine-error` | `internal` | `none` |

For every `unsupported_schema` detail, `expected` and `found` must differ.
Stable store errors contain no paths, user IDs, permission modes, host error
text, or private model data.

## Resource limits

| Resource | Limit |
| --- | ---: |
| Complete encoded record | 1 MiB |
| JSON object or array nesting | 64 |
| Members in one object | 128 |
| Items in one array | 4,096 |
| Aggregate JSON values | 65,536 |
| Request ID | 128 bytes |
| Diagnostic code | 64 bytes |
| One message | 65,536 UTF-8 bytes |
| Diagnostics in one error | 256 |
| Sequence | 9,007,199,254,740,991 |

Object keys do not count toward aggregate JSON values. Each object, array, and
scalar value does. Operation-specific string, collection, and inspection-budget
limits in the structural schemas are also normative.

Transport adapters must enforce the record-byte limit while reading. The pure
slice decoder assumes its caller already holds one complete record.
