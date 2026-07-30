# Archive input and trusted ustar decoder (`archive/v1`)

`archive/v1` defines how Malm verifies one declared archive payload and converts
it into immutable [`tree/v1`](../../tree/v1/README.md) objects. Use this contract
when producing archive declarations, reviewing archive provenance, or
implementing the trusted decoder for untrusted input.

The only accepted payload is an uncompressed POSIX ustar stream. The decoder
accepts the complete POSIX numeric-field profile and the conventional directory
trailing slash, and no GNU extension. It verifies the declared byte length and
SHA-256 digest, accepts regular files, directories, and safe relative symlinks,
and builds a closed tree graph without extracting host paths. The stream must end with exactly two all-zero
512-byte records. Blocking-factor padding and every other trailing byte are
rejected.

The decoder does not sniff content, negotiate formats, decompress data, fall
back to another decoder, access the filesystem or network, or execute a
process. A failed decode returns no partial result.

## Contract map

| File | Use it to |
| --- | --- |
| [Trusted decoder contract](canonical.md) | implement exact stream framing, ustar parsing, path handling, object construction, rejection, and resource accounting |
| [Declaration schema](declaration.schema.json) | validate the caller's exact payload and decoder declaration |
| [Provenance schema](provenance.schema.json) | validate the declaration, decoder identity, and root digest recorded after success |
| [Fixture guide](fixtures/README.md) | understand accepted bytes, projections, malformed cases, and unsupported-version cases |
| [Tree object contract](../../tree/v1/README.md) | encode and validate the objects produced by a successful decode |

The declaration and provenance JSON documents are semantic projections. They
are neither tar input nor persisted store records.

## Compatibility

Version 1 fixes the declaration and provenance shapes, decoder behavior,
accepted tar profile, object-construction rules, and decoder identity
`malm.posix-ustar.none` version `1`. Any incompatible change requires a new
contract version.
