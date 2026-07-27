# root/v1

A state root is the private on-disk directory where Malm keeps all persistent
state. This contract tells root resolvers, store initialization, and inspection
tools how to locate that directory and validate its top-level contents.

If `XDG_STATE_HOME` is set, Malm uses `XDG_STATE_HOME/malm`; the value must be
nonempty and absolute. If it is unset, Malm uses `HOME/.local/state/malm`, and
`HOME` must be nonempty and absolute. An invalid set `XDG_STATE_HOME` does not
fall back to `HOME`. Every one of these paths must also be lexically normalized,
including an explicitly supplied root.

The root is identified by `descriptor.json`. Its only accepted bytes are this
compact JSON object followed by exactly one LF:

```json
{"format":"malm-state","version":1}
```

The descriptor is a mode-`0600` regular file. The only other permitted
top-level entries are mode-`0700` directories named `state`, `objects`,
`prepared`, and `transactions`, plus mode-`0600` regular files named
`transaction.lock` and `maintenance.lock`. The contract also checks ownership,
link counts, sizes, and exact bytes. Unknown entries make the root incompatible,
and rejection does not mutate it.

Compatibility: `root/v1` fixes root resolution, descriptor bytes, allowed
entries, and metadata rules. No predecessor descriptor is accepted; an
incompatible change requires a new version.

- **Validate descriptor data:** [semantic JSON Schema](schema.json)
- **Inspect descriptor examples:** [fixtures](fixtures/)
- **Implement resolution and admission:** [root implementation](../../../crates/malm-root/src/lib.rs)
- **Understand records below the root:** [store contract](../../store/v1/README.md)
