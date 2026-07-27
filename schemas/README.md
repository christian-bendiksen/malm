# Malm Data Format Contracts

Most users do not need these files. Start with the
[documentation index](../docs/index.md) for setup, authoring, and CLI guidance.

Malm persists state across runs and exchanges data across process and component
boundaries. These contracts keep independent readers and writers in agreement,
make stored identities reproducible, and require incompatible or corrupt data to
be rejected instead of guessed at.

| Format | Use this contract to |
| --- | --- |
| [CLI JSON](cli/v1/README.md) | parse one structured result or error from normal CLI execution |
| [State root](root/v1/README.md) | locate and admit Malm's persistent state directory |
| [Configuration](config/v1/README.md) | implement rich KDL syntax, evaluation, and typed data |
| [Pack](pack/v1/README.md) | read a pack manifest or compute a pack's stable identity |
| [Dependency lock](lock/v1/README.md) | reproduce and validate the exact transitive pack graph |
| [Machine protocol](machine/v1/README.md) | exchange process requests and response frames over JSONL |
| [Store](store/v1/README.md) | read saved plans, history, objects, and recovery records |
| [Tree objects](tree/v1/README.md) | encode immutable file, symlink, and directory objects |
| [Archive input](archive/v1/README.md) | decode the accepted uncompressed tar profile into tree objects |
| [Format components](format-component/v1/README.md) | implement the WebAssembly transform interface |

## Shared Terms

- A **schema** is a machine-checkable description of allowed data.
- A **wire format** is the exact byte representation exchanged across a boundary.
- **Canonical** data has one required deterministic byte representation.
- A **fixture** is a checked-in input or expected result used by conformance tests.
- A **content-addressed** object's identifier is derived from its complete bytes.
- A frozen **`v1` contract** keeps its documented format stable. The version
  applies to the data or interface, not CLI spelling or implementation type
  names; an incompatible change requires a new version.

## Maintainers

[`conformance-inventory.tsv`](conformance-inventory.tsv) maps the normative
schemas, WIT interface, and fixtures to executable checks enforced by
[`tests/schema_inventory.rs`](../tests/schema_inventory.rs). JSON Schemas use
Draft 2020-12; strict decoders additionally enforce framing, duplicate-key,
canonical-byte, and semantic rules that JSON Schema cannot express.
