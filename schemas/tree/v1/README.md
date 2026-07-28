# Immutable tree object contract (`tree/v1`)

`tree/v1` defines canonical binary objects for regular-file contents, symlink
targets, and directory entries, together with the rules for a closed logical
tree graph. Use it when implementing object codecs, archive conversion,
content-addressed storage, tree inspection, or deployment validation.

Each complete object's encoded bytes determine its SHA-256 identity. Directory
objects reference children by identity, and changing any encoded content
creates a new object rather than mutating an existing one. A closed graph must
supply every reachable tree and symlink object and satisfy the path, link,
cycle, mode, and logical resource rules.

This is a binary contract. It has no JSON Schema and does not describe a host
filesystem layout.

## Contract map

| File or directory | Use it to |
| --- | --- |
| [Canonical object contract](canonical.md) | implement exact file, symlink, and tree encodings; strict decoding; hashing; graph validation; and limits |
| [`fixtures/golden/`](fixtures/golden/) | compare accepted canonical bytes for empty and nonempty files, a symlink, an empty tree, and a populated tree |
| [`fixtures/golden/digests.txt`](fixtures/golden/digests.txt) | compare the exact SHA-256 identities of the golden objects |
| [`fixtures/malformed/`](fixtures/malformed/) | verify rejection of wrong domains, truncation, trailing bytes, invalid values, invalid ordering, unsupported modes or tags, excessive counts, and unsupported symlink encoding |
| [`fixtures/unsupported/`](fixtures/unsupported/) | verify that encoding version `2` is reported as unsupported for every object kind |
| [Archive contract](../../archive/v1/README.md) | build a tree graph from the accepted uncompressed ustar profile |

Golden and rejection fixtures are lowercase hexadecimal byte sequences. The
malformed and unsupported corpora test decoder behavior; they do not define
alternative canonical encodings or a version 2 format.

## Compatibility

Version 1 fixes every domain string, field width, integer byte order, tag,
ordering rule, mode rule, digest calculation, graph rule, decoder rejection,
and resource limit. Any incompatible encoding or semantic change requires a
new contract version.
