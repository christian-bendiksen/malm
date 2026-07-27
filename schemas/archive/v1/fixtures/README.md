# archive/v1 fixtures

The tar payload examples encode exact uncompressed ustar bytes as whitespace-
tolerant hexadecimal. The golden empty archive is exactly two zero 512-byte
terminator records. The malformed hex example has only one zero record: its
declared length and digest are valid, but its tar framing is not.

This corpus is for archive decoder implementers and reviewers checking payload
behavior plus declaration and provenance projections. The JSON files describe
those projections; they are not tar input or persisted store records.

Compatibility: these cases cover `archive/v1` and `schema_version: 1`. Files in
`unsupported/` select version 2 only to verify rejection; they do not define a
version 2 format.

- **Compare exact accepted bytes and digests:** [golden cases](golden/)
- **Check accepted projections:** [valid cases](valid/)
- **Check framing and projection rejection:** [malformed cases](malformed/)
- **Check version rejection:** [unsupported cases](unsupported/)
- **Implement the decoder:** [exact decoder rules](../canonical.md)
- **Understand the corpus:** [archive overview](../README.md)
