# Canonical lock identities (`lock/v1`)

This contract defines the two SHA-256 identities derived from a validated
`lock/v1` model: the ID of one locked pack node and the digest of the complete
graph. Lock writers, readers, graph assemblers, and provenance consumers use
these encodings instead of hashing JSON bytes.

## Shared framing

Every preimage starts with its ASCII domain, including the trailing NUL byte,
followed by a big-endian `u16` encoding version equal to `1`.

| Value | Encoding |
|---|---|
| Text or arbitrary bytes | Big-endian `u64` byte length, then exact bytes |
| Sequence | Big-endian `u64` item count, then encoded items |
| Variant | One-byte tag, then the fields for that variant |

Text lengths count UTF-8 bytes. Compute SHA-256 over the complete preimage and
render the result as `sha256-` followed by 64 lowercase hexadecimal digits.

## Pack node ID

The pack node preimage uses the domain `malm-pack-node\0`. Encode these values
in order:

1. The source variant.
2. The package ID as framed text.
3. The pack content digest as framed text.

Encode the source variant as follows:

| Source | Encoding |
|---|---|
| Root | Tag `0` |
| Git | Tag `1`, then framed Git URL, commit, and subdir text |
| Local | Tag `2`, then framed local-locator text |

Dependencies and components do not enter a node ID. They do enter the complete
graph digest below.

## Graph digest

The graph preimage uses the domain `malm-lock-graph\0`. Encode these values in
order:

1. The lock schema version as a big-endian `u64`; for `lock/v1`, it is `1`.
2. The root node ID as framed text.
3. The node count as a big-endian `u64`.
4. Every node in increasing node-ID order.

For each node, encode:

1. Node ID, package ID, the source variant above, and content digest.
2. Dependency count, followed by dependencies sorted by alias and then target
   node ID. Each dependency encodes its alias and target node ID as framed text.
3. Component count, followed by components sorted by name and path. Each
   component encodes, in order, `name`, `path`, `digest`, `interface`, and
   `execution_profile` as framed text.

Multiple aliases to one target remain separate dependency records. The graph
digest is derived from this semantic model and is not stored as a field in
`malm.lock`. JSON whitespace, object-field order, and input array order do not
affect it. The [golden fixtures](fixtures/golden/digests.json) pin both identity
algorithms.
