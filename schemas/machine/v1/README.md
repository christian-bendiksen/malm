# Malm process protocol (`machine/v1`)

`machine/v1` is Malm's strict JSONL request and response contract for process
integrations. Client authors use it when one CLI JSON result is not enough, and
adapter or codec implementers use it to exchange stable semantic Engine data
without exposing private Rust models or host capabilities.

`malm machine` reads exactly one bounded request record per process invocation.
After accepting the complete request, it emits exactly two correlated records:
a `started` event at sequence `0`, followed by one result or error at sequence
`1`. If the request record is rejected, it emits one uncorrelated error with
`request_id: null` and sequence `0`. A rejected record's claimed request ID is
not echoed, and Engine is not invoked.

## Boundary

Requests carry stable semantic data. They never carry state-root paths, target
paths, Git executable paths, scratch paths, credentials, operating-system error
text, or private Engine models. Operations that need those host capabilities
remain outside `machine/v1`; the process adapter selects permitted roots and
target authority while constructing Engine.

## Contract map

| File | Use it for |
| --- | --- |
| [`protocol.md`](protocol.md) | Normative framing, canonical writing, request processing, response sequencing, errors, and resource limits |
| [`request.schema.json`](request.schema.json) | Closed request envelope and all 31 request payload shapes |
| [`server.schema.json`](server.schema.json) | Event, result, error, and typed detail shapes |
| [`fixtures/`](fixtures/) | Complete golden, valid, malformed, and unsupported records |
| [Operation inventory](../../../docs/machine-operation-inventory.tsv) | Audited operation and adapter coverage |
| [Cross-adapter matrix](../../../docs/operation-matrix.tsv) | Human, machine, and embedded operation equivalence |

JSON Schema defines the structural record shapes. The protocol and strict codec
add checks for byte framing, duplicate keys, integer token domains, resource
budgets, canonical writer output, stream correlation, and semantic integrity.

## Compatibility

Version 1 fixes all 31 operations, their fields, framing, sequencing, errors,
and resource limits. Every record requires `schema_version: 1`. An incompatible
operation, field, wire, or processing change requires a new machine version.
