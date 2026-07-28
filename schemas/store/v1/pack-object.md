# Canonical pack storage contract (`store/v1`)

This contract defines how Malm stores a verified logical `pack/v1` file set in
the `store/v1` cache. Pack publishers, cache readers, retention code, and store
inspectors use it after the final state root has passed
[`root/v1`](../../root/v1/README.md) admission.

A logical pack has one `sha256-<64 lowercase hex digits>` identity. The store
may represent that identity as one canonical monolithic object or as a
deduplicated manifest whose members are blob objects. Both representations must
reconstruct the same logical file set and `pack/v1` content digest. The
monolithic encoding remains the exact logical digest preimage.

Unless a paragraph says otherwise, the requirements below are normative.

## Terms and layouts

- A **logical pack** is the validated, strictly ordered set of regular files
  covered by the `pack/v1` content digest.
- A **monolithic object** stores the complete logical pack encoding in one
  file under `objects/packs`.
- A **pack manifest object** stores ordered references to member blobs under
  `objects/pack-manifests`.
- A **member blob** stores one member's exact bytes under `objects/blobs` and
  is named by the SHA-256 of those bytes.

All paths below are relative to the pinned final store root:

```text
objects/                              current user, directory, mode 0700
objects/packs/                        current user, directory, mode 0700
objects/packs/sha256-<64 lowercase hex digits>
                                      current user, regular file, mode 0400,
                                      exactly one hard link
objects/pack-manifests/               current user, directory, mode 0700
objects/pack-manifests/sha256-<64 lowercase hex digits>
                                      current user, regular file, mode 0400,
                                      exactly one hard link
objects/blobs/                        current user, directory, mode 0700
objects/blobs/sha256-<64 lowercase hex digits>
                                      current user, regular file, mode 0400,
                                      exactly one hard link
```

Every component is opened relative to pinned directory descriptors without
following symbolic links, magic links, or mount traversal. Readers check
metadata and namespace bindings before and after content access. A replacement,
disappearance, binding mismatch, or mutable observation is an error.
Filesystem metadata, timestamps, and extended attributes are not identity
inputs.

## Logical pack limits

Every representation enforces the `pack/v1` limits:

- At most 100,000 entries.
- At most 1 GiB of combined logical file bytes.
- At most 256 MiB in one file.
- At most 1,024 bytes in one path, together with all other `PackPath` segment
  and depth limits.
- Exactly one entry for each path, in strictly increasing exact UTF-8 path-byte
  order.
- A required `malm-pack.kdl` entry.

## Monolithic object encoding

A monolithic object is one regular file whose complete contents are this
canonical `pack/v1` content-digest stream:

```text
bytes  "malm-pack-content\0"
u16be  encoding version = 1
u64be  regular-file count
repeat for every file sorted by exact UTF-8 path bytes:
    u64be  path byte length
    bytes  path
    u64be  file byte length
    bytes  exact file content
```

Integers are unsigned and use network byte order. The stream contains no
padding or trailing bytes. Its encoded-size limit is:

```text
1 GiB + 100,000 * (16 + 1,024) + 64 bytes
```

The object identity is `sha256-` followed by the lowercase hexadecimal SHA-256
of the complete encoded file. Because the encoding is exactly the logical
`pack/v1` digest preimage, the stored-byte identity and logical pack-tree
identity must be equal. A reader verifies both identities independently.

## Deduplicated manifest encoding

A pack manifest object is named by the logical pack identity, not by the
SHA-256 of the manifest object's own bytes. Its complete binary encoding is:

```text
bytes  "malm-pack-manifest-object-v1\0"
u16be  encoding version = 1
u64be  member count
repeat for every member sorted by exact UTF-8 path bytes:
    u64be  path byte length
    bytes  path
    u64be  blob digest text byte length
    bytes  blob digest text
    u64be  exact member byte length
```

The manifest is limited to 128 MiB. It contains at most 100,000 members. Each
path is a valid `PackPath` of at most 1,024 bytes, appears once, and is strictly
increasing. Each digest is a full canonical SHA-256 identifier and its encoded
text length is at most 128 bytes. The stream has no trailing bytes.

For each member, `objects/blobs/<digest>` must contain exactly the recorded
number of bytes, and the blob's SHA-256 must equal `digest`. After loading every
member, the reader rebuilds the ordered logical pack and recomputes the
`pack/v1` content digest. That digest must equal the manifest filename.

## Publication

Publication requires a read-write Engine and a validated version 1
`descriptor.json`. It holds `maintenance.lock` so publication cannot race
reference-aware retention.

The publisher performs these steps in order:

1. Validate the logical file set and its required `pack/v1` digest before
   accessing the store.
2. Create and pin any missing private containers without replacing entries.
   Validate their owner, type, and exact mode, and sync each new namespace
   entry.
3. For a deduplicated representation, publish every member blob durably by its
   exact SHA-256 before publishing the manifest.
4. Write the complete object to an unnamed mode-`0400` file and sync it. For a
   monolithic object, also verify the resulting stored-byte digest and metadata.
5. Revalidate `descriptor.json`, the final root, all containers, the
   `maintenance.lock` binding, and relevant namespace bindings.
6. Link the unnamed file at the logical digest name without replacement, then
   sync the containing directory.

If another publisher wins, the losing publisher never replaces or removes the
winner. It reports reuse only after reading and completely verifying the
winner. Malformed or unsafe existing entries are preserved and rejected rather
than repaired.

## Reading

Reading requires a validated final root but works with a read-only Engine. A
reader prefers a pack manifest object when both representations exist;
monolithic `objects/packs` entries remain readable for compatibility.

Missing containers or objects are cache misses and never cause state creation.
The reader opens every entry without following links, enforces the filesystem
invariants and size bounds above, parses the complete canonical stream, rejects
trailing bytes, and revalidates every pinned binding.

For a manifest representation, the reader verifies each referenced blob's
metadata, exact length, and digest, then verifies the reconstructed logical
pack digest. For a monolithic representation, it verifies both the complete
stored-file digest and the independently reconstructed logical digest. Reading
never fetches, repairs, publishes, or otherwise mutates an object.
