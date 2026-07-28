# Malm format component interface (`format-component/v1`)

`format-component/v1` is the capability-free WebAssembly component interface
for Malm format transforms. Component authors implement it to receive a
canonical typed configuration document, explicit options, and declared resource
bytes, then return bounded output or a structured failure. Host and
configuration implementers use it when admitting a component and converting
between the semantic transform model and WebAssembly values.

Use this interface for a formatter bundled in a pack. It is not a general plugin
API and grants no filesystem, network, environment, process, clock, randomness,
Malm state, or deployment-target access.

## Normative interface

WIT, or WebAssembly Interface Types, defines the values and function exchanged
between a component and its host. The normative package is
`malm:format-component@1.0.0`. Its `malm-format-component` world has no imports
and exports exactly this one function:

```wit
export transform: func(request: transform-request-v1) -> result<transform-response-v1, transform-failure-v1>;
```

The pack and lock interface identifier is exactly `format-component/v1`. There
is no parallel JSON Schema or JSON decoder; the WIT file is the ABI contract.

## Value map

| WIT area | What it carries |
| --- | --- |
| `canonical-value-v1` and `typed-value-v1` | An indexed graph of null, boolean, signed, unsigned, floating-point, text, path, list, record, and keyed-collection values |
| `canonical-typed-document-v1` | The root value plus source documents, include edges, and value provenance |
| `transform-option-v1` | One explicitly named typed option |
| `declared-resource-v1` | One resource name, declared SHA-256 digest, and exact bytes |
| `transform-response-v1` | Opaque output bytes, media type, and diagnostics |
| `transform-failure-v1` | A closed failure kind, message, and diagnostics |

The exact record fields, integer widths, variant cases, and list element types
are normative in the [WIT source](../../../crates/malm-format-component-api/wit/malm-format-component.wit).

## Semantic processing

The WIT types describe transport across the component boundary. The
[`config/v1` transform contract](../../config/v1/transform.md) adds the
normative semantic checks applied before and after every call.

The host validates the complete request before execution. Options and resources
are name-sorted and unique. Each resource digest must match its exact bytes;
resources are supplied explicitly and are never discovered by name. The
canonical typed document includes the source and provenance identities needed
to validate returned source locations.

A successful response contains bounded opaque bytes, a validated ASCII media
type, and canonical unique diagnostics. Success diagnostics cannot have `error`
severity. A source range must name a source document in the request and remain
within its captured byte length. An output range must remain within the returned
output bytes.

A failure kind is exactly one of `invalid-request`, `unsupported-format`,
`resource-limit`, `invalid-result`, or `internal`. Failure diagnostics cannot
refer to output because no successful output exists. A malformed success or
failure value is a component-boundary error, not a transform failure.

## Semantic limits

These transform-specific limits are enforced by the version 1 semantic model
used at the WIT boundary:

| Resource | Limit |
| --- | ---: |
| Canonical typed-document bytes | 64 MiB |
| Transform options | 256 |
| Aggregate canonical option bytes | 64 MiB |
| Declared resources | 1,024 |
| One declared resource | 64 MiB |
| Aggregate declared resource bytes | 256 MiB |
| Transform output bytes | 64 MiB |
| Response media type | 128 ASCII bytes |
| Diagnostics in one response or failure | 256 |
| Diagnostic code | 128 bytes |
| One diagnostic message or note | 16 KiB |
| Failure message | 16 KiB |
| Notes on one diagnostic | 64 |
| Aggregate diagnostic text | 1 MiB |

Component binary size, fuel, memory, table, instance, stack, and transfer limits
belong to the deterministic host execution profile rather than the WIT type
system. The [host admission contract](../../../docs/format-component-admission.md)
describes that separate boundary.

## Compatibility

Version 1 is the exact package, world, function, and types in the WIT file. An
incompatible type or function change requires a new interface version. There is
no predecessor ABI or compatibility adapter.

## Contract files

| File | Audience and purpose |
| --- | --- |
| [Normative WIT](../../../crates/malm-format-component-api/wit/malm-format-component.wit) | Component and host implementers |
| [Transform contract](../../config/v1/transform.md) | Request, response, diagnostic, identity, and validation semantics |
| [Rendering guide](../../../docs/authoring/rendering-components.md) | Pack authors selecting component renderers and transform stages |
| [Host admission contract](../../../docs/format-component-admission.md) | Runtime maintainers admitting and invoking untrusted components |
| [Configuration identity](../../config/v1/canonical.md) | Implementers computing canonical typed-document identities |
| [Golden WIT digest](fixtures/golden/wit.sha256) | Maintainers checking the exact interface bytes |
