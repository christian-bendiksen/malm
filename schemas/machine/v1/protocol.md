# machine/v1 Protocol

## Records

Each record is UTF-8 JSON followed by exactly one LF byte. A record cannot
contain a literal CR or another LF byte and is at most 1 MiB including the
terminal LF. JSON strings may contain escaped `\n` and `\t` values where the
field profile permits them.

Readers reject duplicate object keys, unknown or missing fields, trailing data,
and non-integer version or sequence values. Every object is closed. The schema
version is an unsigned 32-bit integer and must be exactly `1`. Version values in
that domain other than `1` are unsupported; negative, floating, and larger
values are invalid envelopes.

JSON Schema counts string characters and treats all mathematically integral JSON
numbers the same. The stricter UTF-8 byte ceilings, exact integer token profile,
duplicate-key rule, unequal unsupported-version values, and framing constraints
are therefore normative reader checks in addition to the structural schemas.

The canonical writer emits compact JSON without insignificant whitespace and
then one LF. Envelope fields occur in this order:

- requests: `schema_version`, `request_id`, `type`, `request`.
- events: `schema_version`, `request_id`, `sequence`, `type`, `event`.
- results: `schema_version`, `request_id`, `sequence`, `type`, `result`.
- errors: `schema_version`, `request_id`, `sequence`, `type`, `error`.

Nested fields follow schema order. Golden fixtures pin exact output bytes.
Input field order is not semantic.

The `malm machine` transport accepts exactly one request record per
process invocation. It reads at most one byte beyond the 1 MiB limit, emits one
uncorrelated bounded error for a rejected record, and otherwise flushes the
started record before invoking Engine. Engine failures produce a correlated
terminal error and process exit code `2`; successful results use exit code `0`.

## Requests

`request_id` is an opaque ASCII identifier selected by the caller. It is 1
through 128 bytes long and contains only letters, digits, `.`, `_`, `:`, or `-`.
It is used only for correlation and grants no authority.

The implemented request variants are exactly:

`store_status`, `initialize_store`, `prepare`, `plan`, `artifact`, `commit`,
`state`, `recover`, `prune`, `checkout`, `disable`, `enable`,
`remove_namespace`, `set_history_retention`, `pin`, `unpin`,
`add_restore_point`, `drop_restore_point`, `catalog`, `namespace`, `history`,
`generation`, `desired_snapshot`, `canonical_tree`, `artifact_metadata`,
`captured_inputs`, `transform_provenance`, `retention`, `tracking`, `status`, and
`fsck`.

Lock creation/update, tracked-root prepare, and tracked update are not request
variants. They select absolute pack, Git executable, or scratch paths and remain
human/embedded host operations. A `lock_create`, `lock_update`, `track`, or
`update` discriminator, and any injected host-path field, is invalid in
machine/v1.

The checked-in
[machine operation inventory](../../../docs/machine-operation-inventory.tsv)
and [cross-adapter operation matrix](../../../docs/operation-matrix.tsv) are
tested against the Rust request/result models, runtime wire codecs, schemas, and
adapter dispatch.

Two minimal requests are:

```json
{"schema_version":1,"request_id":"req-1","type":"request","request":{"type":"store_status"}}
{"schema_version":1,"request_id":"req-2","type":"request","request":{"type":"initialize_store"}}
```

Every variant's closed fields are normative in `request.schema.json`. Prepare
carries logical authorities and bounded artifact bytes as lowercase hexadecimal,
never host paths. Its operation set carries canonical symlink/tree digests,
optional archive payload/decoder provenance, and tagged exact target state.
Those nested records are closed and all nullable semantic fields are emitted
explicitly. Commit carries the prepared plan ID and exact findings approval
digest. Checkout and lifecycle/retention changes prepare normal reviewed plans;
they do not commit implicitly. Catalog, namespace, history, generation, desired
snapshot, canonical tree, artifact metadata, captured inputs, transform
provenance, retention, tracking, status, and fsck are bounded inspection
requests.

Roots and host capabilities are selected only when the Engine is constructed.
They are never accepted from a machine request. The process adapter maps the
logical `home` target authority to its construction-time home directory for
every target-bearing request: `prepare`, `commit`, `recover`, `checkout`,
`disable`, `enable`, `remove_namespace`, `set_history_retention`, `pin`,
`unpin`, `add_restore_point`, `drop_restore_point`, `status`, and `fsck` when
`observe_targets` is true. Other requests receive no target authority.

## Response Streams

After a complete request is accepted, its stream is exactly:

1. One `started` event at sequence `0`, with the same request ID and operation.
2. One result or correlated error at sequence `1`, with the same request ID.
3. No further records.

A successful result operation must match its request. Successful initialization
always reports `ready`. `ResponseStreamValidatorV1` enforces these rules without
performing I/O.

Prepared deployment results expose the immutable input list and complete
Engine-generated transform provenance. Each transform binds its name; either a
built-in implementation label or the component's pack-node, pack-content,
component-path, component, interface-version, and execution-profile identities;
the request, typed-document, declared-resource, and response digests; and every
bounded successful diagnostic. Successful diagnostics are strictly canonical
and unique, cannot have error severity, and bind the exact captured source byte
length for every source range. Results also expose the exact enabled/disabled
lifecycle and optional complete credential-free prepared tracking review:
source locator and selector, applied revision and canonical root tree digest,
source subdirectory, config entry point, selected profile, target authority,
sorted acquisition grants, and any retained compatibility component-grant
records. Post-commit tracking inspection remains redacted to selector, revision,
and tree identity. Machine prepare requests cannot supply transform provenance
themselves. Readers recompute every policy finding ID from its code, message,
and approval flag, reject duplicate IDs, and recompute the approval digest. A
structurally valid result with an inconsistent review binding is an invalid
envelope.

The record model reserves positive sequence values through
`9007199254740991`, the largest integer represented exactly by interoperable
JSON implementations. The implemented two-record stream uses only `0` and `1`.

If request decoding fails, no request has been accepted. The response is one
uncorrelated error with explicit `"request_id":null` and sequence `0`. Even if a
rejected object contains a syntactically valid ID, it is not echoed. Parser
messages and rejected bytes are never copied into protocol errors.

## Errors

Every terminal error has a closed category, stable kebab-case code, bounded
human message, typed details, and zero through 256 diagnostics. Messages are
informational and must never drive compatibility logic. Diagnostic codes start
with a lowercase ASCII letter and contain only lowercase letters, digits, and
hyphens.

| Code | Category | Required details |
|---|---|---|
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

For unsupported schemas, `expected` and `found` must differ. Stable store errors
contain no paths, user IDs, permission modes, host error text, or private model
data.

## Limits

| Resource | Limit |
|---|---:|
| complete encoded record | 1 MiB |
| JSON object/array nesting | 64 |
| members in one object | 128 |
| items in one array | 4,096 |
| aggregate JSON values | 65,536 |
| request ID | 128 bytes |
| diagnostic code | 64 bytes |
| one message | 65,536 UTF-8 bytes |
| diagnostics in one error | 256 |
| sequence | 9,007,199,254,740,991 |

Object keys do not count as aggregate values. Each object, array, and scalar
value does. Transport adapters must enforce the record-byte limit while reading;
the pure slice decoder assumes its caller already holds one complete record.
