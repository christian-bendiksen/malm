# Malm persisted store contract (`store/v1`)

`store/v1` defines Malm's private on-disk representation for saved plans,
immutable inputs and outputs, namespace history, selected namespace state,
transactions, crash recovery, and retention. Normal users access this state
through the CLI. Storage adapters, commit and recovery code, inspectors, and
retention implementations use this contract when they read or modify a Malm
state root.

The contract applies only after [`root/v1`](../../root/v1/README.md) has located
and admitted the final state root. Start with the detailed contract when
implementing persisted behavior, or use the map below to find a specific
boundary.

## Contract map

| File or topic | Use it for |
| --- | --- |
| [Prepared plans and immutable dependencies](contract.md#prepared-plans-and-immutable-dependencies) | Record fields, identities, transforms, desired snapshots, and policy binding |
| [Namespace state](contract.md#namespace-state) | Generations, catalog admission, lifecycle history, and tracked roots |
| [Transactions and recovery](contract.md#transactions-and-recovery) | Journal authority, durable target publication, and crash recovery |
| [Retention](contract.md#retention) | Reachability, pins, deletion, and bounded maintenance |
| [`pack-object.md`](pack-object.md) | Pack cache encodings, layouts, publication, and read verification |
| [`fixtures/valid/`](fixtures/valid/) | Minimal accepted public records |
| [`fixtures/golden/`](fixtures/golden/) | Exact canonical bytes and pinned record identities |
| [`fixtures/malformed/`](fixtures/malformed/) | Records that strict readers must reject |
| [`fixtures/unsupported/`](fixtures/unsupported/) | Well-formed but unsupported versions |

Related boundaries:

- [`root/v1`](../../root/v1/README.md) defines root resolution, admission, and
  the closed top-level layout.
- [`pack/v1` source capture](../../pack/v1/source-capture.md) defines stable
  local capture before pack publication.
- The [CLI guide](../../../docs/cli.md#set-up-the-store) covers initialization,
  verification, recovery, and cleanup for operators.

## Compatibility

Version 1 freezes persisted record fields, layouts, encodings, identities,
durability rules, lifecycle transitions, and recovery behavior. Readers do not
import or mutate predecessor state. An incompatible change requires a new
schema version.

Store records intentionally have no parallel JSON Schema. The strict record
codecs and the fixtures define their exact persisted forms.
