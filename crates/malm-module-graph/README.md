# malm-module-graph

`malm-module-graph` verifies locked pack contents and exposes their modules
offline. It is for preparation and evaluation code that consumes a completed
lock from a local cache.

The crate exists because a structurally valid lock is not enough: every cached
pack must also match its locked content digest, manifest declarations, and
component digests before its modules can be trusted.

## Verify Cached Packs

`VerifiedPackV1::from_files` checks a supplied pack against an expected digest.
`verify_pack_files_v1` performs the same checks without retaining the files.
Both validate the manifest and every declared component.

## Assemble A Locked Graph

`assemble_locked_graph_v1` loads each unique pack through
`PackObjectSourceV1`, a read-only cache interface keyed by content digest.
`assemble_locked_graph_with_verified_v1` reuses packs already verified by the
caller. Both return `AssembledLockedGraphV1` only after lock and manifest data
agree.

## Resolve Direct Dependencies

Module visibility follows direct lock edges. If A directly depends on B, and B
directly depends on C, A can resolve its own modules and B's modules through
A's alias for B. A cannot reach C through B; B can resolve C, and A can resolve
C only if A also declares a direct dependency on C.

`resolve_module` applies this rule. `component` returns verified component bytes
with locked-source provenance, while `dependency_order` returns a deterministic
dependency-before-importer order.

## Boundary

Assembly reads already cached packs only. Source acquisition and configuration
evaluation remain outside this crate.

See the [pack/v1 schema](../../schemas/pack/v1/README.md), the
[lock/v1 schema](../../schemas/lock/v1/README.md), and the [crate API](src/lib.rs).
