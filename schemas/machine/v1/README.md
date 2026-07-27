# machine/v1

`malm machine` reads exactly one bounded JSONL request per process invocation.
An accepted request gets two correlated response records: `started` at sequence
`0`, then either a result or an error at sequence `1`. A rejected request record
gets one uncorrelated error with `request_id: null` and sequence `0`; its claimed
request ID is not echoed and Engine is not invoked.

This protocol is for process integrations and implementers of the machine
adapter or pure record codec. Requests contain stable semantic data, not state
root paths, target paths, Git executables, scratch paths, credentials,
operating-system errors, or private Engine models. Operations that require those
host capabilities remain outside this protocol.

Compatibility: version 1 fixes all 31 operations, fields, framing, sequencing,
errors, and resource limits. `schema_version` must be `1`; an incompatible
operation or field change requires a new machine version.

- **Implement framing, sequencing, and errors:** [protocol](protocol.md)
- **Validate client records:** [request schema](request.schema.json)
- **Validate server records:** [server schema](server.schema.json)
- **Inspect complete streams:** [fixtures](fixtures/)
- **Choose an available operation:** [operation inventory](../../../docs/machine-operation-inventory.tsv)
