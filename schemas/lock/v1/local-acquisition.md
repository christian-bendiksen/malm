# Root and local graph acquisition (`lock/v1`)

The local-only `lock/v1` acquisition operation verifies and publishes every
`Root` and `Local` node in an already validated `LockV1`, then invokes the
offline module-graph assembler. Prepare and embedding code use it when the
reviewed graph contains no Git source.

It does not create or update a lock, use Git or the network, parse deployment
configuration, or write a graph-specific persistent record.

## Inputs and authority

The caller supplies one explicit absolute root-pack directory, one validated
complete lock, and an exact set of granted `LocalLocator` values. Publication
requires a ready read-write store.

The caller-selected root is implicitly granted. Every `Local` node must appear
in the grant set, even when its locator stays within the root. This conservative
boundary keeps interactive or organization-specific policy outside Engine and
prevents lock contents from granting local filesystem authority by themselves.

## Preflight

Before any source read or CAS mutation, the operation scans the complete lock.
It rejects a local locator that is absent from the grant set and rejects every
Git node as unsupported by this local-only operation.

A missing grant or mixed Git graph therefore cannot publish even the root
object as a side effect. The [exact Git adapter](git-acquisition.md) shares the
downstream CAS and verification stages. The general [complete graph adapter](graph-acquisition.md)
composes both source kinds; this operation remains intentionally local-only.

## Root-relative resolution

Every local locator is resolved lexically from the root-pack directory, never
from the directory of the pack that declares the dependency. `.` selects the
root directory. Leading `..` components walk upward from that directory, and
all remaining components walk downward.

A validated `LocalLocator` is at most 4,096 UTF-8 bytes and 64 segments.
Validation has already rejected absolute paths, internal parent segments, dot
segments other than the single `.`, empty segments, backslashes, control
characters, and `.git`, `malm.lock`, or `.malm-lock.tmp` components.

The operation passes the resulting absolute path to the `pack/v1`
[local source-capture adapter](../../pack/v1/source-capture.md). That adapter
independently rejects symbolic path components, state-root overlap, nested
mounts, unsafe entries, unstable observations, and digest drift.

## Acquisition sequence

1. Recapture and publish the root at its locked content digest.
2. Resolve, recapture, and publish every local node at its locked digest.
3. Load all resulting objects through the read-only CAS capability.
4. Re-verify pack bytes, strict manifests, declared files, component digests,
   package identities, source identities, dependency aliases, and target nodes.
5. Return the complete graph in deterministic dependency-before-importer order,
   retaining the validated lock as provenance.

The assembler permits at most 1 GiB of unique verified pack-file bytes and
65,536 module-scope entries. Each source also remains subject to all `pack/v1`
capture limits.

## Cache and failure semantics

A valid CAS hit never suppresses local capture. Current drift or a missing local
origin fails even when the old locked object remains available to explicitly
offline consumers. Normal acquisition never rewrites `malm.lock`.

CAS publication is content-addressed, not transaction-scoped. If a later node
fails after earlier matching nodes were published, those independently valid
immutable objects may remain as unreferenced cache entries. No assembled graph
or lock update is published.
