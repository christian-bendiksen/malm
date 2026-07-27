# tree/v1 Canonical Objects

All integers are unsigned big-endian values. `text` is a `u64` UTF-8 byte
length followed by those exact bytes. Object identity is `Digest::sha256` of
the complete canonical byte sequence, including its object-specific domain.

## Regular File Object

```text
bytes  "malm-file-object\0"
u16    encoding version = 1
u64    exact content byte length
bytes  exact regular-file contents
```

Every regular-file digest in a tree, archive result, desired snapshot, or
canonical-file CAS path is `file_object_digest_v1(contents)`: SHA-256 of this
complete domain-separated object. It is never SHA-256 of the unframed content
bytes.

## Symlink Object

```text
bytes  "malm-symlink-object\0"
u16    encoding version = 1
text   target
```

The target is nonempty UTF-8 of at most 4096 bytes and contains no NUL, C0, or
C1 control character. The standalone object preserves target text; admission
as a safe relative tree entry is contextual and is described below.

## Tree Object

```text
bytes  "malm-tree-object\0"
u16    encoding version = 1
u32    root permission mode
u64    direct entry count
repeat for entries in strictly increasing exact UTF-8 name-byte order:
    text   child name
    u8     kind: file = 0, directory = 1, safe-relative-symlink = 2
    u32    normalized permission mode
    text   referenced Digest (`sha256-` plus 64 lowercase hex digits)
    if kind == file:
        u64    exact file byte length
```

Modes contain permission bits only. File modes must retain owner read;
directory and root modes must retain owner read and search. A symlink mode is
exactly `0777`. A parent directory entry's mode must equal its referenced child
tree's root mode.

Child names are nonempty UTF-8 segments of at most 255 bytes. Empty, `.`, `..`,
slash, backslash, NUL, and control-containing segments are rejected. A decoder
does not reorder entries: duplicates and malformed order are noncanonical.

## Complete Graph

A closed graph resolves directory digests to tree objects and symlink digests
to symlink objects. Every reference must exist. Safe relative symlink targets
are nonempty slash-separated canonical child segments: absolute targets,
backslashes, empty segments, `.` and `..` are rejected. Their root-relative
resolved path remains within the depth and path-byte budgets. A symlink target
that traverses another symlink creates a dependency edge; cyclic dependencies
are rejected. Directory-reference cycles are also rejected.

One logical rooted graph has at most 100,000 entries, depth 64, and paths of at
most 4096 UTF-8 bytes. Each file and the aggregate logical file bytes are at
most 256 MiB. Reusing one object at multiple paths counts once per logical path.
Zero-byte files use `file_object_digest_v1(&[])`, including the file-object
domain, version, and zero length. One file digest cannot declare conflicting
lengths.

The crate is an object/model boundary only. It does not read files, resolve
components, publish objects, or integrate with `malm-store`.
