# Malm schema contracts

Malm persists data across runs and exchanges values across CLI, process, and
WebAssembly boundaries. These contracts are for client authors, embedders, and
maintainers who need to implement those boundaries without depending on private
Rust types. Most users should start with the [documentation index](../docs/index.md)
for setup, authoring, and command guidance.

The contracts keep independent readers and writers in agreement, make stored
identities reproducible, and require incompatible or corrupt data to be rejected
rather than guessed at.

## Contract map

| Contract | Boundary | Start here |
| --- | --- | --- |
| CLI JSON | One structured result or error from a normal command | [`cli/v1`](cli/v1/README.md) |
| State root | Persistent state-root resolution and top-level admission | [`root/v1`](root/v1/README.md) |
| Configuration | Rich KDL syntax, evaluation, canonical typed data, and transforms | [`config/v1`](config/v1/README.md) |
| Pack | Pack manifests and stable pack identity | [`pack/v1`](pack/v1/README.md) |
| Dependency lock | The exact reproducible transitive pack graph | [`lock/v1`](lock/v1/README.md) |
| Machine protocol | Process requests and response frames over JSONL | [`machine/v1`](machine/v1/README.md) |
| Store | Saved plans, history, objects, and recovery records | [`store/v1`](store/v1/README.md) |
| Tree objects | Immutable file, symlink, and directory objects | [`tree/v1`](tree/v1/README.md) |
| Archive input | The accepted uncompressed tar profile and its tree conversion | [`archive/v1`](archive/v1/README.md) |
| Format components | The WebAssembly transform interface | [`format-component/v1`](format-component/v1/README.md) |

## How to read these contracts

A **schema** is a machine-checkable description of allowed data. The JSON
Schemas in this tree use Draft 2020-12 and define structural constraints such as
required fields, closed objects, value domains, and collection limits. Where a
contract defines strict decoding, its decoder must also enforce the normative
checks that JSON Schema cannot express, including framing, duplicate-key
rejection, exact integer tokens, canonical bytes, and cross-field semantics.
Read the contract README and detailed protocol pages as well as the schema.

A **wire format** is the exact byte representation exchanged across a boundary.
**Canonical** data has one required deterministic byte representation. A
**content-addressed** object's identifier is derived from its content rather
than its storage location. Most contracts hash complete canonical bytes; a
contract that uses another logical preimage defines it explicitly. **CAS** means
content-addressed store.

A **fixture** is checked-in conformance evidence. `golden` fixtures pin exact
writer output, while `valid`, `malformed`, and `unsupported` fixtures exercise
reader behavior where those categories apply.

A frozen **`v1` contract** keeps its documented data or interface stable. The
version does not freeze CLI spelling or private implementation type names. An
incompatible data, wire, or interface change requires a new version.

## Conformance and maintenance

[`conformance-inventory.tsv`](conformance-inventory.tsv) maps every normative
schema and WIT interface, all golden fixtures, and the registered reader fixture
corpora to executable evidence. The inventory itself is checked by
[`tests/schema_inventory.rs`](../tests/schema_inventory.rs), which also compiles
the JSON Schemas and runs the registered JSON fixture corpora. Contract-specific
test suites cover the additional fixtures and the strict-decoder or exact-byte
requirements outside the JSON data model.
