# Trusted archive decoder contract (`archive/v1`)

This is the normative contract for converting a declared, uncompressed POSIX
ustar payload into canonical `tree/v1` objects. Archive producers need it to
create acceptable input; decoder and security reviewers need it to reproduce
the exact accepted language, failure behavior, and resource accounting.

## Terms and boundary

A **payload** is the exact byte sequence bound by the declaration. A **record**
is one 512-byte ustar block. An **entry** is one nonzero header together with
any file body and record padding. A **canonical component** is one valid UTF-8
path segment as defined under [Paths and symlink targets](#paths-and-symlink-targets).
A **synthesized directory** is a parent directory that the decoder creates when
an entry names a descendant before naming that parent explicitly.

The decoder reads only from the caller's `std::io::Read`. It does not perform
compression, content sniffing, format negotiation, fallback decoding,
filesystem access, process execution, or network access. It constructs the
entire result in memory and returns no partial result on failure.

## Declaration and decoder selection

The declaration fixes every value below before the decoder reads any payload
byte:

```text
schema_version    1
container         "tar"
compression       "none"
decoder_version   1
payload_byte_len  exact unsigned byte length
payload_digest    SHA-256 of exactly payload_byte_len bytes
```

`payload_digest` uses the canonical text form `sha256-` followed by 64
lowercase hexadecimal digits. The declaration contains every listed field and
no additional field. See [declaration.schema.json](declaration.schema.json) for
the JSON projection.

The successful provenance records decoder name `malm.posix-ustar.none` and
decoder version `1`. No payload content may alter decoder selection.

An unsupported decoder version or a declared payload length above
`max_payload_bytes` fails preflight before the first read.

## Payload reading and stream framing

After preflight, the decoder consumes exactly `payload_byte_len` bytes. If it
finds a parsing or resource error while processing the archive, it still drains
the rest of the declared payload before returning that error. Draining stops
only if the reader ends early, returns an I/O error, or exhausts
`max_read_operations`.

After consuming the declared payload, the decoder makes one EOF probe. It
rejects an early EOF, any byte returned by that probe, and any mismatch between
`payload_digest` and the SHA-256 digest of the complete declared payload.

The payload is a sequence of 512-byte records. Exactly two consecutive all-zero
records terminate it:

- A missing or partial first terminator record is malformed.
- The second record must be complete and all zero. A missing, partial, or
  nonzero second record is malformed.
- The declared payload must end immediately after the second record. Any
  remaining byte, including an additional zero record, is trailing payload
  data.
- A byte available outside the declared payload is also an error.

Consequently, conventional tar blocking-factor padding is not accepted.

## POSIX ustar header profile

Every nonzero header must use this exact 512-byte layout. Offsets are zero
based; widths are bytes.

| Offset | Width | Field | Required representation |
| ---: | ---: | --- | --- |
| 0 | 100 | name | bounded text field |
| 100 | 8 | mode | terminated octal number |
| 108 | 8 | UID | terminated octal number |
| 116 | 8 | GID | terminated octal number |
| 124 | 12 | size | terminated octal number |
| 136 | 12 | mtime | terminated octal number |
| 148 | 8 | checksum | terminated octal number |
| 156 | 1 | typeflag | one allowed byte listed below |
| 157 | 100 | link name | bounded text field |
| 257 | 6 | magic | exact bytes `ustar\0` |
| 263 | 2 | version | exact bytes `00` |
| 265 | 32 | user name | bounded text field |
| 297 | 32 | group name | bounded text field |
| 329 | 8 | device major | blank, or a terminated octal number encoding zero |
| 337 | 8 | device minor | blank, or a terminated octal number encoding zero |
| 345 | 155 | prefix | bounded text field |
| 500 | 12 | reserved | all zero |

A bounded text field either occupies its complete field or ends at its first
NUL. If it contains a NUL, every byte from that NUL through the end of the field
must also be NUL.

A terminated octal number is zero or more leading spaces, then one or more
octal digits `0` through `7`, then one or more terminator bytes, each NUL or
space, filling the exact field width. A field must contain at least one digit
and at least one terminator, so an absent terminator, a digit run preceded by
anything but spaces, and any byte after the first terminator that is neither
NUL nor space are all rejected. One numeric field therefore never carries two
numbers. A blank field contains only NUL and space bytes; only the device
fields accept it, and it means zero.

The checksum is the unsigned sum of all header bytes after treating all eight
checksum-field bytes as spaces. The historical signed sum is not a second
accepted encoding, and GNU base-256 numbers are not accepted.

User and group names may be empty. If present, they must be control-free UTF-8.
The decoder validates and then ignores UID, GID, user name, group name, and
mtime. It does not ignore any other metadata. Device numbers must be zero.

### Entry types and bodies

Only these typeflags are accepted:

```text
'0' regular file
'2' symbolic link
'5' directory
```

A directory entry may carry the conventional single trailing slash on its
joined path. The decoder removes exactly one trailing slash, and only from a
directory path, before applying every path rule and path budget below. It
removes nothing when the remainder would be empty or would itself end in a
slash, so `/`, `//`, and `dir//` still fail. No other entry type is normalized.

The historical NUL regular-file typeflag is not accepted. The decoder also
rejects all of the following:

- hard links;
- character devices, block devices, FIFOs, and contiguous files;
- GNU sparse entries;
- PAX local and global headers;
- GNU long-name and long-link records;
- every other GNU or unknown extension or entry type.

A regular file may have a nonzero size, but its link name must be empty. Its
body consists of exactly the declared bytes followed by zero padding through
the containing 512-byte record. Nonzero padding or a body that extends beyond
the declared payload is malformed.

A directory must have size zero and an empty link name. A symlink must have size
zero; its link name carries the target and is validated below.

## Paths and symlink targets

For each entry, the ustar name must be nonempty. If the prefix is nonempty, the
decoder joins the prefix and name with exactly one slash; otherwise it uses the
name alone. The resulting path must be nonempty, UTF-8, and relative.

Each slash-separated path component must be nonempty and must not be `.` or
`..`. A component may not contain slash, backslash, NUL, or any Unicode control
character. These rules reject leading and repeated slashes everywhere, and
reject a trailing slash on every entry except the normalized directory form
described under entry types.

The decoder does not percent-decode, normalize Unicode, fold case, parse a host
path, convert separators, or otherwise transform a path.

A symlink target must be nonempty, control-free UTF-8. It must be relative and
contain only slash-separated canonical components. Absolute targets,
backslashes, empty components, `.`, and `..` are rejected. The decoder applies
the path-component limit to target components and applies the path-byte and
depth limits to the root-relative target obtained by joining the target to the
symlink's parent path.

Symlink targets remain data. The decoder never follows them on a host. The
resulting closed tree graph additionally rejects cyclic symlink dependencies.

## Path uniqueness and synthesized directories

Each normalized path may have at most one explicit archive entry. Descendants
may first cause a parent directory to be synthesized; one later explicit
directory entry for that path is allowed and sets its mode. A second explicit
entry is a duplicate. A directory named `dir/` and one named `dir` are the same
path, so the second of them is that duplicate.

A file or symlink cannot have a descendant. A non-directory cannot replace a
directory, and it cannot replace a synthesized directory that already has
descendants. These collision rules apply regardless of archive order.

## Canonical object construction

The root and every synthesized directory start with mode `0755`. A later
explicit directory entry replaces a synthesized directory's mode.

Modes contain permission bits only:

- A regular-file mode must fit within `0777` and retain owner read (`0400`).
- A directory mode must fit within `0777` and retain owner read and search
  (`0500`).
- A symlink header mode must be exactly `0777`, which is the fixed `tree/v1`
  symlink mode.

The decoder retains accepted regular-file and directory permission bits
exactly. Ownership and timestamp metadata do not enter any object encoding.

Regular-file contents become canonical, domain-separated `tree/v1` file object
bytes. Symlink targets become canonical `SymlinkObjectV1` bytes. For each
directory, direct children are sorted by their exact UTF-8 name bytes and
encoded into canonical `TreeObjectV1` bytes. Trees are built bottom-up.

Each complete canonical byte sequence is addressed by its SHA-256 digest. Equal
file contents therefore share one retained file object identity, but every
archive placement remains a separate logical entry and is charged separately.
Hard-link topology is never preserved.

A successful result contains the unique retained file, symlink, and tree object
bytes and digests; a closed, validated `TreeGraphV1`; its root tree digest; and
provenance containing the exact declaration and decoder identity. Distinct
bytes under one digest, including across object kinds, are rejected as an
object-digest collision.

Archive order and accepted UID, GID, ownership-name, and mtime values do not
change canonical object bytes. They do change the declared payload identity
when their input bytes differ.

## Resource limits and accounting

Callers supply every ceiling through `ArchiveLimitsV1`. A zero ceiling is valid
and rejects any input that consumes that resource. Limits are inclusive: use
equal to a ceiling is accepted. The corresponding `tree/v1` maximum remains a
hard upper bound when the caller supplies a larger value.

| Resource | Default ceiling | Accounting rule |
| --- | ---: | --- |
| Payload bytes | 384 MiB | Check `payload_byte_len` before the first read. |
| File bytes | 256 MiB | Check each logical regular-file size before allocating or reading its body. The `tree/v1` per-file maximum is also 256 MiB. |
| Expanded file bytes | 256 MiB | Sum every logical regular-file size, including repeated equal contents. The `tree/v1` aggregate maximum is also 256 MiB. |
| Entries | 100,000 | Count files, symlinks, explicit directories, and synthesized parent directories. Exclude the root. The `tree/v1` maximum is also 100,000. |
| Path bytes | 4,096 | Measure UTF-8 bytes in each slash-joined entry path and resolved symlink target. The `tree/v1` maximum is also 4,096. |
| Path depth | 64 | Count components in each entry path and resolved symlink target. The `tree/v1` maximum is also 64. |
| Path-component bytes | 255 | Measure UTF-8 bytes in each entry-path and symlink-target component. The `tree/v1` maximum is also 255. |
| Symlink-target bytes | 4,096 | Measure UTF-8 bytes in the target text before object construction. The `tree/v1` maximum is also 4,096. |
| Metadata bytes | 64 MiB | Charge 512 bytes for every nonzero header and for each of the two terminator records. |
| Object bytes | 384 MiB | Sum unique canonical bytes retained in the file, symlink, and tree object maps. Repeated identical objects are charged once. |
| Read operations | 402,653,185 | Count every call to the caller-supplied `Read`, including interrupted attempts, retries, draining, and the final EOF probe. This default is 384 MiB plus one. |
| Work units | 10,000,000 | Charge one per header or terminator record, path or target component, file data record, and canonical tree entry constructed. |

One file data record is each started 512-byte record of declared file content;
a zero-byte file charges no file-data-record work. File bodies are read into
memory in fixed chunks of at most 8,192 bytes only after both per-file and
expanded-file limits pass.

All counter additions fail with saturating semantics rather than wrapping. The
final unique object set may remain in memory only within the declared limits.

## Rejection and compatibility

The decoder fails closed on declaration mismatch, payload truncation, trailing
bytes, digest mismatch, I/O failure, malformed framing or headers, unsupported
entry types or metadata forms, unsafe or colliding paths, invalid modes,
nonzero padding, unsafe symlink targets, object or graph inconsistency, and any
resource-limit violation. Apart from removing one trailing slash from a
directory path, it never repairs, normalizes, guesses, or partially publishes
rejected input.

Version 1 fixes this complete behavior, including accepted bytes, validation
order that affects reading and accounting, canonical outputs, and decoder
identity. An incompatible change requires a new version. Widening the accepted
byte profile is compatible and keeps version 1 when the canonical output of
every previously accepted payload is unchanged byte for byte. Narrowing the
profile, or changing any canonical output, requires a new version.
