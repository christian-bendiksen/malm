# malm-store

`malm-store` defines and validates Malm store records without performing I/O. It
is for engine and storage-adapter code that persists prepared and selected state.

The crate exists so durable record shapes, canonical identities, and transition
rules do not depend on a particular filesystem or transaction implementation.
Each valid persisted record has one canonical JSON encoding. Prepared records
and state generations derive their identities from those bytes.

Catalog heads and lifecycle, tracking, restore, and retention choices are
recorded explicitly. Callers do not infer the selected state from directory
contents.

## Persist A Reviewed Plan

`PreparedRecordV1` binds a complete reviewed plan to its immutable inputs,
artifacts, operations, policy findings, and provenance. Use
`encode_prepared_record_v1`, `decode_prepared_record_v1`, and `prepared_id_v1`
to store, admit, and identify it.

## Select Namespace State

`StateGenerationV1` records one immutable namespace result, and
`StateCatalogV1` selects one generation head per namespace. Their codecs admit
canonical records; `state_generation_digest_v1` computes a generation identity.

## Reconcile Targets

`DesiredSnapshotV1` describes complete target slots, including retained absent
slots. `reconcile_desired_snapshot_v1` and `required_target_mutations_v1`
compare desired and observed state. `OwnershipProjectionV1` derives current
claims from selected enabled generations.

## Validate Lifecycle Changes

`TrackedRootV1` carries lifecycle, source tracking, restore, and retention
choices. `validate_prepared_transition_v1` checks that a prepared plan can move
from its recorded prior state to its proposed state.

## Boundary

This crate defines, encodes, and validates records. A storage adapter handles
state-root access, locking, transactions, recovery, and publication.

See the [store/v1 schema](../../schemas/store/v1/README.md) and the
[crate API](src/lib.rs).
