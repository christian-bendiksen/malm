# archive/v1

`archive/v1` accepts one uncompressed strict POSIX ustar stream. It verifies the
declared byte length and SHA-256 digest, accepts only regular files, directories,
and safe relative symlinks, and builds immutable `tree/v1` objects without
extracting host paths. The stream must end with exactly two all-zero 512-byte
records; blocking-factor padding and any other trailing byte are rejected.

There is no compression, content sniffing, fallback decoder, filesystem access,
process execution, network access, or partial publication. This contract is for
callers that declare archive inputs and implementers of the trusted decoder
`malm.posix-ustar.none` behavior version `1`.

Compatibility: version 1 fixes the declaration, decoder behavior, accepted tar
profile, and output object rules. An incompatible change requires a new version.
The declaration and provenance JSON documents are semantic projections, not tar
input or persisted store records.

- **Implement exact tar decoding and conversion:** [decoder contract](canonical.md)
- **Validate an archive declaration:** [declaration schema](declaration.schema.json)
- **Validate successful provenance:** [provenance schema](provenance.schema.json)
- **Inspect decoder examples:** [fixture guide](fixtures/README.md)
- **Encode resulting objects:** [tree objects](../../tree/v1/README.md)
