# lock/v1

`malm.lock` makes pack dependencies reproducible by recording the complete
transitive graph and each exact local or Git source, pack content, graph node,
dependency alias, and bundled component identity. Prepare validates and uses
that graph instead of resolving mutable dependencies. Normal prepare never
rewrites the lock, and commit does not read it.

This contract is for lock generators, source-acquisition implementers, and
prepare-time validators. Compatibility: version 1 fixes the JSON fields, graph
semantics, identity encodings, limits, and acquisition behavior.
`schema_version` must be the integer token `1`; an incompatible change requires
a new version.

- **Create or update `malm.lock`:** [discovery and publication guide](creation-update.md)
- **Acquire a root and local-only graph:** [local acquisition guide](local-acquisition.md)
- **Acquire one exact Git source:** [Git acquisition guide](git-acquisition.md)
- **Acquire a complete mixed graph:** [graph acquisition guide](graph-acquisition.md)
- **Implement the JSON reader:** [structural schema](schema.json)
- **Compute node and graph identities:** [identity encoding](canonical.md)
- **Inspect accepted and rejected locks:** [fixtures](fixtures/)
