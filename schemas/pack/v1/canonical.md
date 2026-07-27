# pack/v1 Canonical Content Digest

Pack content identity is SHA-256 over this binary stream:

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

`malm-pack.kdl` is required and included, so its module, config-document,
resource, dependency, and component declarations are covered by this digest.
Every selected resource payload is itself an exact pack path in this stream.
Any path with a `.git`, `malm.lock`, or
`.malm-lock.tmp` component is reserved and omitted before hashing. Every other
included entry must be a regular, single-link file with a valid pack path. Empty
directories, directory entries, ownership, permissions, timestamps, xattrs,
and inode identity are not encoded.

A pack contains at most 100,000 files and 1 GiB of file bytes. One file is at
most 256 MiB. Source capture must observe stable files and reject symlinks,
hard links, special files, or changes during capture; capture remains part of
the [`source-capture`](source-capture.md) adapter. The implemented `store/v1`
adapter independently enforces canonical bytes and safe metadata for each
persisted pack object.
