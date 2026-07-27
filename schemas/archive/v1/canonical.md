# archive/v1 Trusted Decoder Contract

## Declaration

An archive declaration fixes all of these values before reading begins:

```text
schema_version    1
container         "tar"
compression       "none"
decoder_version   1
payload_byte_len  exact unsigned byte length
payload_digest    SHA-256 of exactly payload_byte_len bytes
```

The decoder identity recorded in successful provenance is
`malm.posix-ustar.none` version `1`. No content sniffing, compression,
fallback decoder, or format negotiation is permitted.

## Stream Framing

The decoder reads through `std::io::Read`. After declaration preflight, it
consumes exactly `payload_byte_len` bytes even when a structural archive error
is found, unless the reader truncates, returns an I/O error, or exhausts the
explicit read-operation budget. It then performs one EOF probe. A byte after
the declared payload, an early EOF, or a SHA-256 mismatch is an error.

The tar stream consists of 512-byte records and ends with exactly two all-zero
records. A missing, partial, or nonzero second record is malformed. Any byte,
including an additional zero record, inside the declared payload after those
two records is trailing data. Blocking-factor padding is not accepted.

## Header Profile

Every nonzero header is exactly the POSIX ustar layout with magic `ustar\0` and
version `00`. The unsigned checksum is six octal digits, NUL, and space; during
calculation all eight checksum bytes are spaces. Numeric mode, UID, GID, size,
and mtime fields are full-width octal digits followed by NUL. GNU base-256 and
space-terminated numeric forms are not accepted. Device fields are either all
NUL or full-width NUL-terminated octal zero. Reserved bytes 500 through 511 are
zero.

Name, prefix, link-name, user-name, and group-name fields are NUL-terminated
with only NUL after the first terminator, or occupy their complete field. User
and group names are optional control-free UTF-8 ownership metadata. Numeric
UID/GID, user/group names, and mtime are validated and then ignored. No other
metadata is ignored. Nonzero device numbers and nonempty link names on files or
directories are errors.

The only entry typeflags are:

```text
'0' regular file
'2' symbolic link
'5' directory
```

The historical NUL regular-file flag is not in the allowlist. Hard links,
character/block devices, FIFOs, contiguous files, GNU sparse entries, PAX local
or global headers, GNU long-name or long-link records, and every other GNU or
unknown extension are errors. Directory and symlink sizes are zero. File data
is followed by zero bytes through its containing 512-byte record.

## Paths And Links

The ustar prefix and name are joined with one slash. The result is nonempty
UTF-8 and relative. Every slash-separated component is nonempty, is neither
`.` nor `..`, and contains no slash, backslash, NUL, or Unicode control
character. Consequently leading, repeated, and trailing slashes are errors.
No percent decoding, Unicode normalization, case folding, host path parsing, or
separator conversion occurs.

Symlink link-name bytes are nonempty control-free UTF-8. The target is relative
and consists only of the same canonical components; absolute targets,
backslashes, empty components, `.` and `..` are rejected. Its root-relative
resolved byte length and depth are bounded. Targets are represented as data and
never followed.

Each normalized path may occur at most once. An explicit directory may appear
after descendants that caused that directory to be synthesized, but two
explicit entries for one path are duplicates. A non-directory cannot have a
descendant, replace a directory, or replace a synthesized directory with
descendants.

## Canonical Objects

The root and every parent omitted from the tar stream use mode `0755`. A later
explicit entry sets a synthesized directory's mode. Regular-file and directory
modes retain exactly their permission bits and must satisfy `tree/v1`; bits
outside `0777` are rejected. Symlink headers must have mode `0777`, matching the
fixed `tree/v1` symlink mode.

Regular-file bytes are raw SHA-256-addressed blobs. Symlink targets become
canonical `SymlinkObjectV1` bytes. Direct children are sorted by exact UTF-8
name bytes and become canonical `TreeObjectV1` bytes, built bottom-up. The
result includes every object byte sequence and digest, a closed validated
`TreeGraphV1`, its root digest, and declaration/decoder provenance.

Archive order and accepted ownership/timestamp metadata do not affect object
bytes. Repeated equal file content has one blob identity but remains independent
logical placements; hard-link topology is never preserved.

## Resource Accounting

Callers supply every ceiling. `tree/v1` limits remain hard maxima if a caller
sets a larger value.

- Payload bytes are checked before the first read.
- File bytes are checked before allocating or reading one file body.
- Expanded file bytes are the sum of all logical regular-file sizes.
- Entry count includes files, symlinks, explicit directories, and synthesized
  parent directories; the root is excluded.
- Path bytes, path depth, path-component bytes, and symlink-target bytes are
  measured as UTF-8 bytes or component counts.
- Metadata bytes count each 512-byte nonzero header and both terminator blocks.
- Object bytes count unique retained bytes in each file, symlink, or tree object
  map.
- Read operations count every call to the caller-supplied `Read`, including
  interrupted retries and the final EOF probe.
- One work unit is charged per header or terminator block, path or target
  component, file data record, and canonical tree entry constructed.

All counters use saturating failure semantics. File bodies are read in fixed
chunks only after per-file and aggregate expanded limits pass. The final object
set may remain in memory within the declared limits.
