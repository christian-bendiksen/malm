# malm-tree

`malm-tree` models and validates immutable file, symlink, and directory objects.
It is for storage, archive, and deployment code that needs stable tree identity.

The crate exists because host filesystems differ in traversal and metadata
behavior. Malm instead hashes canonical bytes built from caller-supplied file
contents, validated path segments, safe relative symlink targets, and recorded
modes. The same logical content therefore has the same identity on every host.

## Build Logical Trees

`TreeObjectV1` holds a directory mode and sorted direct children.
`TreeEntryV1` references a file object, child tree, or `SymlinkObjectV1`.
Constructors validate names, modes, ordering, sizes, and symlink targets before
an object can be encoded.

## Encode And Verify Objects

The `encode_*_object_v1` functions produce canonical object bytes, and the
matching digest functions compute their content identities. Use
`decode_*_object_v1` to validate stored bytes or `decode_verified_*_object_v1`
to validate both encoding and an expected digest.

```rust
use malm_tree::{
    decode_verified_file_object_v1, encode_file_object_v1, file_object_digest_v1,
};

let object = encode_file_object_v1(b"hello")?;
let digest = file_object_digest_v1(b"hello")?;
assert_eq!(decode_verified_file_object_v1(&digest, &object)?, b"hello");
# Ok::<(), malm_tree::ObjectReadError>(())
```

## Validate A Tree Graph

`TreeGraphV1::new` checks every tree and symlink object reachable from a root
tree digest. It rejects missing tree or symlink objects, cycles, unsafe links,
mode mismatches, and resource-limit violations. File entries carry a digest and
size, but the storage layer checks whether those file objects exist. The graph
exposes aggregate counts through `TreeSummaryV1`.

## Boundary

This crate receives logical models and bytes; host adapters perform filesystem
walking and materialization.

See the [tree/v1 schema](../../schemas/tree/v1/README.md), the
[canonical encoding](../../schemas/tree/v1/canonical.md), and the
[crate API](src/lib.rs).
