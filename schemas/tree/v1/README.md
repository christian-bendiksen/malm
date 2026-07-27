# tree/v1

`tree/v1` defines immutable binary objects for regular-file contents, symlink
targets, and a directory's direct entries. Directory objects refer to child
objects by identity; a closed tree graph supplies every referenced tree and
symlink object. Changing content creates a new object rather than modifying an
existing one.

Each object's complete encoded bytes determine its SHA-256 identity. This
contract is for tree codec, archive, and store implementers; it is binary and has
no JSON Schema.

Compatibility: version 1 fixes the binary encodings, object and graph rules,
limits, and digest calculation. An incompatible encoding or semantic change
requires a new version.

- **Encode, decode, or hash objects:** [exact object contract](canonical.md)
- **Compare accepted bytes and identities:** [golden cases](fixtures/golden/)
- **Check decoder rejection:** [malformed and unsupported cases](fixtures/)
- **Build trees from tar input:** [archive contract](../../archive/v1/README.md)
