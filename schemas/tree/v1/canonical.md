# Canonical immutable tree objects (`tree/v1`)

This is the normative binary contract for Malm file, symlink, and directory
objects and for the logical graphs built from them. Codec, archive, store,
inspection, and deployment implementations use it whenever object bytes or
tree identity must agree across boundaries.

## Terms and common representation

An **object** is one complete domain-separated byte sequence defined below. Its
**identity** is `Digest::sha256` of that entire sequence. A **tree object**
represents one directory and only its direct children. A **logical path** is a
root-relative sequence of child names joined with `/`. A **closed graph** starts
at one root tree digest and supplies every reachable tree and symlink object.

All integers are unsigned and use big-endian byte order. The notation `text`
means a `u64` UTF-8 byte length followed by exactly that many bytes. A referenced
`Digest` is text containing exactly 71 bytes: `sha256-` followed by 64 lowercase
hexadecimal digits.

Every object starts with its exact object-specific domain followed by a `u16`
encoding version equal to `1`. The domain, version, every length prefix, and all
content bytes participate in its identity.

## Regular-file objects

```text
bytes  "malm-file-object\0"
u16    encoding version = 1
u64    exact content byte length
bytes  exact regular-file contents
```

The content length may be at most 256 MiB (`268,435,456` bytes). The object must
end immediately after the declared contents.

Every regular-file digest in a tree, archive result, desired snapshot, or
canonical-file content-addressed store (CAS) path is
`file_object_digest_v1(contents)`: SHA-256 of this complete canonical object. It
is never SHA-256 of the unframed content bytes. This rule also applies to empty
files.

## Symlink objects

```text
bytes  "malm-symlink-object\0"
u16    encoding version = 1
text   target
```

The target must be nonempty UTF-8 of at most 4,096 bytes. It may not contain
NUL, a C0 control character, or a C1 control character.

The standalone object preserves target text exactly. It does not by itself
claim that the target is a safe relative tree entry. Closed-graph validation
applies the contextual path rules under [Symlink safety](#symlink-safety).

## Tree objects

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

A tree object may contain at most 100,000 direct entries. Each child name must
be one nonempty UTF-8 segment of at most 255 bytes. A name may not be `.`, `..`,
or contain slash, backslash, NUL, or any Unicode control character.

Entries must already be in strictly increasing order by their exact UTF-8 name
bytes. A model constructor may sort caller-supplied entries before encoding,
but a decoder must not repair or reorder encoded input. Duplicate names and
non-increasing order are noncanonical and must be rejected.

### Modes

Modes contain permission bits only; any bit outside `0777` is unsupported.

- A file mode must retain owner read (`0400`).
- A directory entry mode and a tree's root mode must retain owner read and
  search (`0500`).
- A safe-relative-symlink mode must be exactly `0777`.
- A directory entry's mode must equal the root mode of its referenced child
  tree.

### File declarations

Each file entry declares both an object digest and an exact content byte length.
The length may be at most 256 MiB. File lengths in one tree object may total at
most 256 MiB, counting each direct logical entry.

A zero-byte file must use `file_object_digest_v1(&[])`, including the file
domain, version, and zero length. One file digest may not declare conflicting
lengths.

## Strict decoding and identity verification

A decoder must reject an object before unbounded allocation if its complete
input exceeds the applicable maximum canonical size:

| Object kind | Maximum canonical bytes |
| --- | ---: |
| File | 268,435,483 |
| Symlink | 4,126 |
| Tree | 35,500,031 |

These bounds include the domain, version, framing, and maximum content. The tree
bound includes 100,000 maximum-size file entries.

For every object kind, a strict decoder must reject a wrong domain, truncation,
an encoding version other than `1`, an out-of-range length or count, and any
trailing byte. It must also reject invalid UTF-8, noncanonical digest text,
unknown tree-entry tags, invalid names or targets, unsupported modes, malformed
entry ordering, duplicate names, invalid file-length declarations, and any
other violation of the object rules above.

A verified decoder first validates the complete canonical object and then
compares its computed identity with the expected digest. A mismatch is an
error. Decoders do not infer an object kind from another domain and do not
accept an alternate representation.

## Closed tree graphs

A closed graph starts from a root digest that must identify a supplied tree
object. Each reachable directory entry must identify a supplied tree object,
and each reachable symlink entry must identify a supplied symlink object. File
entries carry a digest and length claim, but this graph boundary does not load
or require file object bytes; the storage boundary verifies those objects.

Graph validation recomputes tree and symlink identities from their canonical
models. Distinct indexed objects with one digest are rejected as an object
digest collision. A directory-reference cycle is rejected. The same tree
object may appear at multiple noncyclic logical paths, but each placement is
walked and accounted independently.

The graph also rejects a directory entry whose mode differs from its child
tree's root mode, a missing reachable tree or symlink object, an unsafe symlink,
a symlink dependency cycle, inconsistent file lengths, or any logical resource
limit violation.

### Symlink safety

For a symlink admitted as a safe relative tree entry, its target must be a
nonempty relative path made only of canonical child-name segments. Absolute
targets, backslashes, empty segments, `.`, and `..` are rejected. Target
segments therefore also obey the 255-byte and control-character rules.

The root-relative resolved target is formed relative to the symlink's parent.
It must remain within the graph's depth and path-byte limits. Validation treats
the target as data and does not access or follow a host path.

If any path prefix traversed by a resolved target is another symlink entry, the
source symlink has a dependency on that entry. The symlink dependency graph
must be acyclic.

### Logical resource limits

All maxima are inclusive. Logical counts use saturating failure semantics and
cannot wrap.

| Resource | Maximum | Accounting rule |
| --- | ---: | --- |
| Direct entries in one tree object | 100,000 | Count each encoded direct child. |
| Entries in one rooted graph | 100,000 | Count every reachable logical placement; exclude the root object. Shared objects count again at each path. |
| Path depth | 64 | Count child-name segments below the root. Apply the same bound to root-relative resolved symlink targets. |
| Path bytes | 4,096 | Count UTF-8 bytes in the slash-joined root-relative path. Apply the same bound to resolved symlink targets. |
| Child-name bytes | 255 | Count UTF-8 bytes in one child or target segment. |
| Symlink-target bytes | 4,096 | Count UTF-8 bytes in the standalone target text. |
| One file | 256 MiB | Use the file entry's exact logical byte length. |
| Aggregate file bytes | 256 MiB | Sum every logical file placement in the rooted graph. Reused file or subtree objects count at every path. |

One file digest may not declare different lengths anywhere in the rooted graph.
The canonical empty-file digest rule applies at every placement.

## Capability and compatibility boundary

This contract and the `malm-tree` crate are object and model boundaries only.
They do not walk or materialize a filesystem, follow host symlinks, execute a
process, access the network, publish objects, or integrate directly with
`malm-store`.

Version 1 fixes all bytes, identities, validation rules, graph semantics, and
limits above. Any incompatible change requires a new version.
