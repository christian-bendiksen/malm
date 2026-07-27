# lock/v1 Canonical Identities

Every encoding starts with its ASCII domain including the trailing NUL, then a
big-endian `u16` encoding version equal to `1`. Text and byte values are framed
as a big-endian `u64` length followed by exact bytes. Sequence counts are
big-endian `u64`. Variant tags are one byte.

## Pack Node ID

The `malm-pack-node\0` encoding contains, in order:

1. Source: tag `0` for root; tag `1` plus Git URL, commit, and subdir; or tag
   `2` plus local locator.
2. Package ID text.
3. Pack content digest text.

The SHA-256 result uses `sha256-` plus 64 lowercase hexadecimal digits.

## Graph Digest

The `malm-lock-graph\0` encoding contains the lock schema version as `u64`, the
root node ID, and all nodes sorted by node ID. Each node encodes its ID, package
ID, source, content digest, alias edges sorted by alias then target, and bundled
components sorted by name and path. Every component encodes name, path, digest,
and interface. Multiple distinct aliases to the same target remain distinct.

The graph digest is computed from this semantic model and is not a field in
`malm.lock`; JSON formatting and input array order therefore do not affect it.
