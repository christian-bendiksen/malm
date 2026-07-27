# store/v1

`store/v1` is Malm's on-disk format for saved plans, immutable inputs and
outputs, deployment history, namespace state, and crash-recovery records. It
also defines safe retention of that history. Normal users operate it through
the CLI; this landing page is for store, commit, recovery, inspection, and
retention implementers.

Compatibility: version 1 fixes the record fields, layouts, encodings,
identities, durability rules, and lifecycle transitions. Predecessor state is
not imported, and an incompatible change requires a new version. Store records
have no parallel JSON Schema; strict readers enforce their exact persisted
forms.

The detailed contract is the authority for record contents, paths, byte
encodings, publication, transactions, recovery, and retention.

- **Implement persisted store behavior:** [detailed contract](contract.md)
- **Locate and admit the store:** [state-root contract](../../root/v1/README.md)
- **Read or publish pack objects:** [pack-object contract](pack-object.md)
- **Inspect record examples:** [fixtures](fixtures/)
- **Operate and recover a store:** [CLI reference](../../../docs/cli.md#set-up-the-store)
