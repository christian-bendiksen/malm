# Canonical pack content digest (`pack/v1`)

This contract defines the stable identity of one logical `pack/v1` file tree.
Pack builders, acquisition adapters, content-addressed store (CAS)
implementations, and lock writers use it whenever independently observed pack
bytes must produce the same digest.

## Digest preimage

Compute SHA-256 over this complete binary stream:

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

All integers are unsigned and use big-endian byte order. Lengths count bytes,
not Unicode scalar values. Each path occurs exactly once, and paths are encoded
in strictly increasing order by their exact UTF-8 bytes. The resulting digest
is written as `sha256-` followed by 64 lowercase hexadecimal digits.

## Included content

`malm-pack.kdl` is required and is an ordinary file in the stream. Its exact
bytes therefore bind all module, configuration-document, resource, dependency,
and component declarations. Every selected resource payload is also represented
by its exact pack path and file bytes.

Before hashing, omit every path that has a component named `.git`, `malm.lock`,
or `.malm-lock.tmp`. Every remaining entry must have a valid `PackPath` and must
be a regular file with exactly one hard link at source capture.

The encoding does not represent directories. It also excludes ownership,
permissions, timestamps, extended attributes, and inode identity. Changing only
one of those values does not change the logical digest; changing an included
path or any included file byte does.

## Resource limits

| Resource | Maximum |
|---|---:|
| Included regular files | 100,000 |
| One included file | 256 MiB |
| Combined included file bytes | 1 GiB |

These limits apply before an implementation performs an unbounded read or
allocation.

## Adapter responsibilities

This encoding identifies a logical tree; it does not make a filesystem
observation safe. The [local source-capture adapter](source-capture.md) must
observe stable files and reject symbolic links, extra hard links, special files,
and changes during capture. A `store/v1` adapter must independently check
canonical object bytes, digest agreement, and safe persisted metadata.
