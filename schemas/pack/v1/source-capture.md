# Local source capture (`pack/v1`)

The `pack/v1` local capture adapter turns one explicitly authorized filesystem
directory into the logical regular-file set covered by a required pack digest,
then publishes matching bytes through the `store/v1` pack-object
content-addressed store (CAS). Engine integrators and lock acquisition code use
this adapter after policy has selected a specific local directory.

## Boundary and preconditions

The adapter accepts an explicit source directory and a digest already required
by a lock. It does not discover or update that digest, resolve a `LocalLocator`,
authorize a host path, access Git or the network, or write `malm.lock`.

The caller must resolve the root-relative locator and apply root-consumer policy
before granting the resulting directory. The Engine must have a ready,
read-write final store. A valid cached object does not bypass capture: the
adapter always reads current local bytes and compares them with the locked
digest. The `lock/v1` [root and local graph adapter](../../lock/v1/local-acquisition.md)
implements the multi-node orchestration and explicit grant boundary.

## Source authority

The source root must be an explicit absolute path. The adapter normalizes it
lexically without consulting the current directory or process environment. It
pins every path component without following symbolic or magic links and
revalidates the complete binding chain after capture.

The source must not overlap the final state root in either direction, whether
the overlap is lexical or physical. Traversal may start on any mounted
filesystem, but it must not cross a nested mount below the selected root. These
rules keep every traversed name within the authority the caller granted.

## Tree selection

The adapter inspects directory entries relative to pinned directory
descriptors. It prunes an entry whose exact raw name is `.git`, `malm.lock`, or
`.malm-lock.tmp` before checking its type or decoding its name. The entry and
its complete subtree are therefore excluded even if they would otherwise be
invalid. Every other observed name must be UTF-8, and every complete
slash-separated relative path must be a valid `PackPath`.

The source's own [`malm-pack.kdl`](grammar.md) may declare capture roots. The
manifest is always captured. The walk enters an ancestor directory when a
declared root is below it and reads only selected files and directory trees. If
the manifest is missing, oversized, or malformed, capture narrows nothing; the
strict verification stage then reports the underlying manifest failure. The
[Git acquisition adapter](../../lock/v1/git-acquisition.md) applies the same
selection.

Directories are traversal containers and contribute no digest bytes. Every
included leaf must be a regular file with exactly one hard link. The adapter
rejects symbolic links, sockets, FIFOs, devices, and unknown entry types without
following or copying them.

Ownership, mode, timestamps, extended attributes, and inode identity do not
enter the digest. The adapter performs no explicit source write. Any access-time
update remains a property of the source filesystem and mount policy.

## Resource limits

Capture enforces these limits before unbounded reads:

| Resource | Maximum |
|---|---:|
| Included regular files | 100,000 |
| One included file | 256 MiB |
| Combined included file bytes | 1 GiB |
| Directory entries other than `.` and `..` outside pruned subtrees | 3,200,000 |

All `PackPath` byte, segment, and depth limits also apply. The traversal-entry
ceiling bounds work on empty directories and excluded entries while still
allowing the maximum file count at the maximum path depth.
Dot-prefixed names count like any other name; only the literal `.` and `..`
entries are excluded. Entries below a pruned directory are never enumerated.

## Stable observation

For each included file, capture first compares no-follow namespace metadata
with the opened descriptor. It reads at most the observed size plus one byte,
then compares the final descriptor and namespace binding. Type, device, inode,
mode, owner, group, link count, size, modification time, and change time must
remain stable. Access time is ignored.

For each directory, capture compares the exact raw name set before and after
recursion. Descriptor metadata and the parent binding must also remain stable.
Any detected replacement, addition, removal, metadata change, hard-link change,
or in-place file change fails the operation. Captured bytes are never read from
a replacement outside the pinned tree.

These checks define one stable descriptor-based observation. They do not promise
a filesystem-wide instantaneous snapshot while arbitrary writers are active.

## Verification and publication

After traversal, the adapter sorts files by exact validated path and hashes them
with the [canonical content encoding](canonical.md). A digest mismatch is local
drift and fails even when the old object remains cached. It then verifies the
strict manifest, every declared module and resource path, and each bundled
component digest.

Only matching, semantically valid bytes reach the `store/v1` no-replace
publisher. A failure before publication creates no pack object. Reuse of a
concurrent or existing object is valid only after the CAS reader fully verifies
its metadata, canonical bytes, and digest.

Once published, the immutable object remains valid if the source later changes
or disappears. A later normal prepare still recaptures the local origin and
reports drift or absence instead of silently using that cached object.
