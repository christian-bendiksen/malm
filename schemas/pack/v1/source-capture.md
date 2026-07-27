# pack/v1 Local Source Capture

## Scope

The local capture adapter converts one explicit filesystem directory into the
logical regular-file set covered by the `pack/v1` content digest and publishes
it through the `store/v1` pack-object CAS. It is used only with a digest already
required by a lock. It does not discover or update a digest, resolve a
`LocalLocator`, authorize a host path, access Git or the network, or write
`malm.lock`.

The caller must resolve the root-relative locator and apply root-consumer policy
before granting the resulting directory to this adapter. The Engine requires a
ready read-write final store. A valid cached object never skips local capture:
current local bytes are always recaptured and compared with the locked digest.
The `lock/v1` [root/local graph adapter](../../lock/v1/local-acquisition.md)
provides the implemented multi-node orchestration and explicit grant boundary.

## Root Authority

The source root must be an explicit absolute path. It is normalized lexically;
the current directory and process environment are not consulted. Every path
component is pinned without following symbolic or magic links, and the complete
binding chain is revalidated after capture. The source must not lexically or
physically overlap the final state root in either direction.

Traversal may begin on any mounted filesystem but does not cross a nested mount
below the selected root. This prevents an included name from changing the
filesystem authority traversed by the capture.

## Tree Selection

Directory entries are inspected relative to pinned directory descriptors. An
entry whose exact raw name is `.git`, `malm.lock`, or `.malm-lock.tmp` is pruned
before type or name validation, so its complete subtree is excluded. Every other
entry name must be UTF-8, and its complete slash-separated relative path must be
a valid `PackPath`.

The walk is narrowed to the capture roots declared by the source's own
[`malm-pack.kdl`](grammar.md). The manifest is always captured. A directory is
entered when a declared root lives beneath it. A missing, oversized, or
malformed manifest narrows nothing, and verification reports the real problem.
The [Git acquisition adapter](../../lock/v1/git-acquisition.md) narrows to the
same declared roots.

Directories are traversal containers and do not contribute bytes. Every
included leaf must be a regular file with exactly one hard link. Symbolic links,
sockets, FIFOs, devices, and unknown entry types are rejected without following
or copying them. Ownership, mode, timestamps, xattrs, and inode identity are not
digest inputs. The adapter performs no explicit source write; any access-time
update is controlled by the source filesystem and mount policy.

Capture enforces the `pack/v1` limits before unbounded reads:

- 100,000 included regular files.
- 256 MiB for one included file.
- 1 GiB of combined included file bytes.
- All `PackPath` byte, segment, and depth limits.

Traversal outside pruned subtrees is additionally bounded to 3,200,000 non-dot
directory entries. This bounds empty-directory and excluded-entry work while
remaining sufficient for the maximum file count and path depth.

## Stable Observation

For each included file, capture compares no-follow metadata with the opened
descriptor, reads at most the observed size plus one byte, then compares the
final descriptor and namespace binding. Type, device, inode, mode, owner,
group, link count, size, modification time, and change time must remain stable;
access time is ignored. Directories are enumerated before and after recursion,
their exact raw name sets must match, and their descriptor metadata and parent
bindings must remain stable.

These checks define a stable descriptor-based observation, not a promise of a
filesystem-wide instantaneous snapshot under arbitrary writers. Any detected
replacement, addition, removal, metadata change, hard-link change, or in-place
file change fails the operation. Captured bytes are never taken from a
replacement outside the pinned tree.

## Verification And Publication

After traversal, files are sorted by exact validated path and hashed with the
canonical content encoding. A mismatch with the required digest is local drift
and fails even if the old object is already cached. The adapter then verifies
the strict manifest, every declared module/resource path, and each bundled
component digest before publication.

Only a matching, semantically valid capture is passed to the existing
`store/v1` no-replace publisher. Failure before that point creates no pack
object. A concurrent or existing object is reused only after the CAS reader
fully verifies its metadata, canonical bytes, and digest. The immutable object
remains valid if the source later changes or disappears; a later normal prepare
still recaptures the local origin and reports drift or absence.
