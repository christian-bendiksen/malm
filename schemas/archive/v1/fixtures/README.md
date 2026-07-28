# Archive conformance fixtures (`archive/v1`)

This corpus gives archive producers, decoder implementers, and reviewers exact
accepted bytes plus representative declaration, provenance, malformed, and
unsupported-version cases for `archive/v1`.

Files ending in `.hex` encode payload bytes as lowercase hexadecimal. Readers
of these archive fixtures ignore ASCII whitespace between digits; the remaining
digits must form complete byte pairs. JSON files are semantic declaration or
provenance projections. They are not tar input or persisted store records.

## Fixture map

| Classification | Contents | Expected result |
| --- | --- | --- |
| [`golden/`](golden/) | exact empty ustar payload, its payload and root-tree digests, and matching declaration and provenance projections | decode and validate exactly |
| [`valid/`](valid/) | accepted declaration and provenance projections for the golden payload | validate against the corresponding schema |
| [`malformed/`](malformed/) | a declaration with an unknown field, provenance with an invalid decoder name, and a one-record terminator payload | reject |
| [`unsupported/`](unsupported/) | declaration and provenance projections selecting `schema_version: 2` | reject as unsupported by the version 1 schemas |

The golden payload [`empty-ustar.hex`](golden/empty-ustar.hex) is exactly 1,024
zero bytes: two 512-byte terminator records and no entries. Its
[`digests.txt`](golden/digests.txt) freezes both the payload digest and the
canonical empty root-tree digest. The golden declaration and provenance bind
those values to `malm.posix-ustar.none` version `1`. The files under `valid/`
currently repeat those accepted semantic projections.

[`malformed/single-zero-block.hex`](malformed/single-zero-block.hex) is exactly
one 512-byte zero record. When decoded under a declaration matching its own
length and SHA-256 digest, payload verification succeeds but ustar framing must
still fail because the second terminator record is missing.

The files under `unsupported/` exercise rejection only. They do not define an
`archive/v2` format.

See the [trusted decoder contract](../canonical.md) for normative behavior, the
[archive entry point](../README.md) for the contract map, and the
[`tree/v1` contract](../../../tree/v1/README.md) for the resulting objects.
