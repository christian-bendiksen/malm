# Reproducible dependency locks (`lock/v1`)

The `lock/v1` contract defines `malm.lock`, the complete reproducible graph of a
root pack and all transitive local or exact Git dependencies. Lock generators
use it when freezing current manifests. Acquisition and prepare-time validators
use it later to obtain and verify those exact bytes without resolving mutable
dependencies again.

Each node binds a source identity, package ID, pack content digest, outgoing
dependency aliases, and bundled component records. Prepare validates and uses
the complete graph. Normal prepare never rewrites `malm.lock`, and commit does
not read it.

In this contract, **CAS** means the content-addressed store that holds verified
immutable pack objects by their logical pack digest.

## Contract map

| File | Use it to |
|---|---|
| [JSON Schema](schema.json) | inspect the structural JSON shape and scalar patterns |
| [Canonical identities](canonical.md) | compute pack node IDs and the semantic graph digest |
| [Creation and update](creation-update.md) | discover a graph and durably create or replace the root lock |
| [Root and local acquisition](local-acquisition.md) | acquire an already locked graph that contains no Git nodes |
| [Exact Git acquisition](git-acquisition.md) | acquire one exact commit and selected pack subdirectory |
| [Complete graph acquisition](graph-acquisition.md) | acquire and assemble a mixed root, local, and Git graph |
| [Fixtures](fixtures/) | inspect valid, malformed, unsupported, and golden lock data |

## JSON model

The top-level object has exactly these fields:

| Field | Meaning |
|---|---|
| `schema_version` | The integer `1` |
| `root_node_id` | The canonical ID of the one root-source node |
| `nodes` | Every node reachable from the root |

Each node contains `node_id`, `package_id`, `source`, `content_digest`,
`dependencies`, and `components`. A source has one of three exact forms:

| `source.kind` | Additional fields | Meaning |
|---|---|---|
| `root` | none | The caller-selected root pack containing this lock |
| `git` | `url`, `commit`, `subdir` | One normalized HTTPS URL, full Git object ID, and pack selector |
| `local` | `locator` | One canonical path relative to the root pack |

A dependency record contains `alias` and `target_node_id`. A component record
contains `name`, `path`, `digest`, `interface`, and `execution_profile`; the only
accepted interface is `format-component/v1`.

The strict reader rejects duplicate object keys, unknown fields, missing or
wrongly typed fields, malformed validated strings, and any `schema_version`
other than the integer `1`. JSON formatting and input array order are not
semantic. The canonical writer emits deterministic pretty JSON followed by one
newline.

## Graph requirements

A valid lock has exactly one `root` source, and `root_node_id` names that node.
Every `node_id` must match its canonical source, package, and content identity.
Node IDs are unique. Each non-root exact source appears in only one node.

Within a node, dependency aliases and component names are unique. Every edge
targets an existing node. The graph must be acyclic, and every node must be
reachable from the root. Distinct aliases may target the same node and remain
distinct edge-scoped names.

Acquisition additionally verifies each cached or captured pack against its
node: content digest, package ID, source, dependencies, component declarations,
declared files, and component bytes must all agree.

## Fixed limits

| Resource | Maximum |
|---|---:|
| Encoded `malm.lock` | 16 MiB |
| Nodes | 4,096 |
| Edges across the graph | 16,384 |
| Dependencies in one node | 256 |
| Components in one node | 256 |

Underlying pack capture, Git acquisition, and graph assembly have additional
limits in their linked contracts.

## Compatibility

Version 1 fixes the JSON fields, strict decoding, graph semantics, identity
encodings, resource limits, and acquisition behavior. `schema_version` must be
the integer token `1`. Any incompatible change requires a new lock version.
