# store/v1 Canonical Pack Object

## Identity And Encoding

A pack object is one regular file whose complete contents are the canonical
`pack/v1` content-digest stream:

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

Integers are unsigned and use network byte order. Paths are strict `pack/v1`
paths, occur once, and are strictly increasing. `malm-pack.kdl` is required.
There are no padding or trailing bytes. The limits from `pack/v1` apply: at
most 100,000 entries, 1 GiB combined logical file bytes, and 256 MiB for one
file. The encoded file is additionally bounded by:

```text
1 GiB + 100,000 * (16 + 1,024) + 64 bytes
```

The object identity is `sha256-` followed by the lowercase hexadecimal SHA-256
of the complete encoded file. Because this encoding is exactly the logical
pack-digest preimage, the stored-byte identity and logical tree identity must
be equal. A reader verifies both identities independently.

## Filesystem Layout

Relative to the pinned final store root, the layout is:

```text
objects/                              current user, directory, mode 0700
objects/packs/                        current user, directory, mode 0700
objects/packs/sha256-<64 lowercase hex digits>
                                      current user, regular file, mode 0400,
                                      exactly one hard link
```

Every component is opened relative to pinned directory descriptors without
following symbolic links, magic links, or mount traversal. Metadata and
namespace bindings are checked before and after content access. A mismatch,
replacement, disappearance, or mutable observation is an error. Filesystem
metadata, timestamps, and extended attributes are not identity inputs.

## Publication

Publication requires a read-write Engine and a validated final `descriptor.json`
1 descriptor. The writer:

1. Validates the logical file set and its expected digest before store access.
2. Creates and pins missing private containers without replacing existing
   entries, validates their owner, type, and exact mode, and syncs each new
   namespace entry.
3. Creates an unnamed file in `objects/packs`, sets exact mode `0400`, writes
   canonical bytes, verifies the resulting digest and metadata, and syncs it.
4. Revalidates the descriptor, final store root, containers,
   and namespace bindings.
5. Links the unnamed file at its digest name with no replacement, verifies the
   binding and complete object, and syncs `objects/packs`.

If another publisher wins, the losing writer does not replace or remove the
winner. It reports reuse only after reading and completely verifying the
winner. Corrupt or unsafe existing entries are preserved and rejected rather
than repaired.

## Reading

Reading requires the validated final root descriptor but works with
a read-only Engine. Missing containers or objects are reported as cache misses
without creating state. The reader opens each entry without following links,
requires the filesystem invariants above, enforces the encoded-size bound,
parses the complete canonical stream, rejects trailing bytes, verifies both
digests, and revalidates every pinned binding before returning logical files.
Reading never fetches, repairs, publishes, or otherwise mutates an object.
