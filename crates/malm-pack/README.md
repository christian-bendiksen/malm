# malm-pack

`malm-pack` defines and validates pack manifests, pack objects, and lock graphs.
It is for source resolvers, caches, and graph assemblers that need reproducible
pack identities.

The crate exists to separate moving source discovery from the fixed inputs used
by preparation. A lock records the exact root, Git, or local source selection
and content digest for every reachable pack. Validation then keeps that selected
graph internally consistent.

## Describe A Pack

`decode_pack_v1` validates a `malm-pack.kdl` manifest, and `encode_pack_v1`
emits its normalized form. `PackManifestV1` describes modules, configuration
documents, direct dependencies, resources, and bundled components.

## Identify And Store Content

`PackPath` and `PackFileV1` model a logical regular-file bundle.
`pack_content_digest` covers every included path and byte. The
`read_pack_object_v1` and `write_pack_object_v1` functions use the canonical
persistent representation of that bundle.

## Freeze Source Selection

`LockedSourceV1`, `LockedPackV1`, and `LockV1` bind source identity, package ID,
content digest, dependency aliases, and components. `decode_lock_v1` validates
`malm.lock`; `encode_lock_v1` writes its canonical JSON form.

Lock validation checks node identities, exact-source conflicts, edge targets,
cycles, and reachability from the root. `LockV1::validate_manifest` checks that
a selected node and its direct edges agree with the corresponding manifest.
`pack_node_id` and `lock_graph_digest` expose the resulting stable identities.

## Boundary

This crate validates supplied values and bytes. Source adapters decide how to
scan, fetch, and update a lock before passing the fixed selection here.

See the [pack/v1 schema](../../schemas/pack/v1/README.md), the
[lock/v1 schema](../../schemas/lock/v1/README.md), and the [crate API](src/lib.rs).
