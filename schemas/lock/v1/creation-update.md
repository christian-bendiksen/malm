# lock/v1 Explicit Creation and Update

## Scope

Lock creation and update are explicit Engine operations. They discover the
complete graph declared by the current `pack/v1` manifests, verify and publish
every pack object, assemble the graph offline, and durably write the generated
root `malm.lock`. Normal locked acquisition and prepare never invoke these
operations or rewrite a lock, and commit does not read or resolve one.

Creation requires `malm.lock` to be absent. Update requires an existing, safe,
strictly valid lock/v1 file. Neither operation resolves branches, tags, commit
prefixes, versions, registries, or mutable selectors. Updating means rebuilding
the complete reachable closure from current manifests; removed dependencies
and their now-unreachable nodes disappear from the generated lock.

## Explicit Inputs

The Engine caller supplies:

- One explicit absolute root-pack directory.
- Exact granted `LocalLocator` values.
- Exact granted normalized Git URLs.
- Caller-owned empty Git scratch roots keyed by exact `GitSourceV1` identity.
- The exact `format-component/v1` execution-profile digest to record if the
  graph contains components.
- One explicit bounded Git process configuration.

The supported human adapter is:

```text
malm source lock create|update [--format json] \
  [--source PACK_ROOT] [--git-executable ABSOLUTE_PATH] \
  [--allow-local LOCATOR ...] [--allow-git HTTPS_URL ...] \
  [--git-scratch HTTPS_URL GIT_OBJECT_ID PACK_SUBDIR ABSOLUTE_PATH]...
```

The CLI defaults `--source` to the current directory and resolves a relative
source before calling Engine. When `--git-executable` is omitted, it finds `git`
on `PATH` and canonicalizes that path. It also supplies the current host
execution-profile digest. `--format json` affects only CLI presentation. These
are adapter choices, not Engine defaults: the Engine operation receives an
explicit absolute pack root, lock-resolution inputs, and Git process
configuration.

Each repeated scratch option consumes exactly the four displayed values and is
keyed by the resulting typed `GitSourceV1`. The adapter rejects normalized
duplicate grants, duplicate exact source keys, reused exact scratch paths, and
empty or relative scratch paths before Engine execution. The Engine Git
configuration is required even when the graph has no Git dependencies. This
host-path-bearing operation is not part of machine/v1. It uses a ready
read-write store, constructs no target authority, and installs no component
execution port.

Discovery checks each authority before accessing the newly encountered source.
Unlike acquisition of an already complete lock, all transitive authorities
cannot be preflighted before source reads because a parent manifest introduces
them. A missing dynamic grant or scratch root fails without writing a lock;
independently valid pack objects published earlier in discovery may remain.

## Source Discovery

The root and every local source use the hardened stable local capture adapter.
Every local locator, including one declared by a remote pack, is resolved from
the original retained root descriptor chain rather than an ambient pathname or
the importing pack. Each resulting source descriptor remains pinned through
final recapture and lock publication. Root and local sources are always
recaptured, even during update and despite CAS hits. Retained source descriptors
are bounded below the process `RLIMIT_NOFILE` ceiling with reserved headroom.

A Git source that is new to the lock has no known independent content digest.
Creation therefore fetches its exact full commit into the scratch root keyed by
that exact URL, commit, and subdirectory selector. The selected raw tree is
verified and its canonical digest is then recorded. During update, an unchanged
exact Git source may reuse the digest in the old lock only when that CAS object
remains present and fully verified. A missing object requires new empty scratch;
a corrupt object fails and is never silently repaired.

Discovery is keyed by exact `LockedSourceV1` identity. Repeated aliases to one
source produce one node and retain every edge-scoped alias. Distinct sources
remain distinct nodes even when their content digests match. Each dependency's
required package ID must match the discovered manifest. Node and edge ceilings,
duplicate aliases, conflicting sources, dangling edges, cycles, and complete
root reachability are enforced when the lock/v1 candidate is validated.

Before publication, every root/local source is captured again and must have the
same digest used to construct the candidate. The generated lock must fit the
16 MiB encoded limit, and unique discovered pack bytes share the assembler's
1 GiB graph ceiling. Initial discovery plus final local recapture also has a
2 GiB cumulative processed-byte ceiling, including repeated source identities
that resolve to equal bytes. The read-only assembler must reload every unique
CAS object and verify manifest, component, dependency, package, source, and
private scope agreement.

## Lock File Boundary

The fixed destination is `malm.lock` in the pinned root-pack directory. Existing
locks accepted for update must be current-user-owned regular files with mode
`0644`, one hard link, bounded size, stable metadata and binding, and strict
lock/v1 bytes. Symlinks, special files, extra hard links, malformed or
unsupported locks, and concurrent observations are preserved and rejected.

Generated bytes are canonical pretty JSON with one final newline. A
non-blocking exclusive advisory lock on the pinned root directory serializes
cooperating Engine lock operations; contention fails with a typed busy result.
Publication uses a same-directory unnamed file with exact mode `0644`; data is
synced before visibility and the root directory is synced after its directory
entry changes. Creation links without replacement. Update links the unnamed
file at reserved `.malm-lock.tmp`, revalidates the originally opened lock, and
atomically renames the staging file over it. A stale staging entry is removed
only when descriptor-pinned inspection proves it is a complete canonical
lock/v1 file with generated ownership, mode, link count, and size; other caller
data is preserved and rejected. Cleanup is synced before discovery, and the
staging name is excluded from every pack tree. Canonically identical update
output syncs but does not rewrite the file and preserves its inode.

The root directory and every path component remain descriptor-pinned and are
revalidated before and after publication. A concurrent change observed before
the publication point fails closed. As with any POSIX rename, an uncoordinated
external writer racing in the final revalidation-to-rename interval is outside
the operation's cooperative concurrency contract.

## Failure Semantics

No invalid, incomplete, cyclic, oversized, or unassembled candidate becomes the
root lock. Create never replaces an existing entry. Update validates the old
lock before source capture and publishes only one complete replacement. CAS
population is intentionally not rolled back: immutable verified objects are
safe to retain after a later source, graph, or lock-file failure. No predecessor
state root is opened for mutation.
