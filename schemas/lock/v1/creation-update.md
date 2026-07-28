# Creating and updating dependency locks (`lock/v1`)

The `lock/v1` creation and update operations discover the complete graph
declared by current `pack/v1` manifests, verify and publish every pack object,
assemble the candidate offline, and durably write the root `malm.lock`. CLI and
Engine callers use these explicit operations when they intentionally want to
freeze or refresh source selection.

Normal locked acquisition and prepare never invoke these operations and never
rewrite a lock. Commit does not read or resolve `malm.lock`.

## Operation boundary

Creation requires `malm.lock` to be absent. Update requires an existing, safe,
strictly valid `lock/v1` file. Neither operation resolves branches, tags, commit
prefixes, versions, registries, or any other mutable selector.

Update rebuilds the complete reachable closure from current manifests. It does
not patch the old graph in place. Removed dependencies and nodes that become
unreachable are absent from the generated lock.

Both operations require a ready read-write store. They construct no target
authority, install no component execution port, and never open a predecessor
state root for mutation.

## Explicit Engine inputs

The Engine caller supplies:

| Input | Requirement |
|---|---|
| Root pack | One explicit absolute directory |
| Local authority | Exact granted `LocalLocator` values |
| Network authority | Exact granted normalized Git URLs |
| Git scratch | Caller-owned empty roots keyed by exact `GitSourceV1` identity |
| Component profile | The exact `format-component/v1` execution-profile digest if any component is discovered |
| Git processes | One explicit bounded `GitAcquisitionConfig` |

The Git configuration is required even when the discovered graph contains no
Git dependency.

## Human CLI adapter

The supported CLI shape is:

```text
malm source [--format json] lock create|update \
  [--source PACK_ROOT] [--git-executable ABSOLUTE_PATH] \
  [--allow-local LOCATOR ...] [--allow-git HTTPS_URL ...] \
  [--git-scratch HTTPS_URL GIT_OBJECT_ID PACK_SUBDIR ABSOLUTE_PATH]...
```

The CLI defaults `--source` to the current directory and resolves a relative
source before calling Engine. If `--git-executable` is absent, the CLI finds
`git` on `PATH` and canonicalizes the result. It supplies the current host
execution-profile digest. `--format json` changes presentation only.

These behaviors are CLI adapter choices, not Engine defaults. Engine always
receives an explicit absolute root, typed lock-resolution inputs, and an
explicit Git process configuration. This host-path-bearing operation is not
part of `machine/v1`.

Each `--git-scratch` occurrence consumes exactly the four displayed values. Its
key is the resulting typed `GitSourceV1`, which consists of the normalized URL,
full object ID, and pack subdirectory. Before Engine execution, the CLI rejects
normalized duplicate grants, duplicate exact source keys, a scratch path reused
for another source, and empty or relative scratch paths.

## Authority during discovery

An already complete lock can be preflighted as a whole. Discovery cannot:
transitive authorities become visible only after reading each parent manifest.
The operation therefore checks the relevant grant before accessing every newly
encountered source.

A missing dynamic grant or scratch root fails without writing a lock. Verified
pack objects published for earlier sources may remain in the CAS.

## Source discovery

The root and every local source use the hardened stable local capture adapter.
Every `LocalLocator`, including one declared by a remote pack, is resolved from
the original retained root descriptor chain. Resolution never starts from an
ambient pathname or the importing pack. The resulting source descriptor stays
pinned through final recapture and lock publication.

Root and local sources are always recaptured from current bytes, including
during update and despite CAS hits. The operation bounds retained source
descriptors below the process `RLIMIT_NOFILE` ceiling with reserved headroom.

A Git source new to the lock has no independently known pack content digest.
The operation fetches its exact full commit into the scratch root keyed by that
exact URL, commit, and subdirectory, verifies the selected raw tree, computes
the canonical pack digest, and records that digest.

During update, an unchanged exact Git source may reuse the digest from the old
lock only if the corresponding CAS object is still present and fully verified.
A missing object requires new empty scratch. A corrupt or unsafe object fails
and is never silently repaired.

## Candidate graph construction

Discovery is keyed by exact `LockedSourceV1` identity. Repeated aliases to one
source produce one node while retaining every edge-scoped alias. Distinct
sources remain distinct nodes even when their content digests are equal. Every
dependency's required package ID must equal the package ID in the discovered
manifest.

Candidate validation enforces node and edge ceilings, unique aliases, one node
per exact non-root source, existing edge targets, acyclicity, and complete
reachability from the root. It also requires exactly one root source and
canonical node IDs.

If any discovered manifest declares a component, the caller must have supplied
the exact execution-profile digest. The operation records that profile on every
`format-component/v1` component record.

Before lock publication, the operation captures every root and local source
again through its retained descriptor. Each final digest must equal the digest
used to construct the candidate. The read-only assembler then reloads every
unique CAS object and verifies manifest, component, dependency, package, source,
and private-scope agreement.

## Resource ceilings

| Resource | Maximum |
|---|---:|
| Encoded generated lock | 16 MiB |
| Lock nodes | 4,096 |
| Lock edges | 16,384 |
| Unique discovered pack-file bytes assembled | 1 GiB |
| Initial discovery plus final local recapture bytes | 2 GiB |

The 2 GiB processed-byte ceiling counts distinct source identities again when
they resolve to equal bytes. Pack-level and Git-process limits also apply.

## Lock-file authority

The destination is fixed as `malm.lock` in the pinned root-pack directory. An
existing lock accepted for update must be a current-user-owned regular file with
mode `0644`, exactly one hard link, bounded size, stable metadata and binding,
and bytes accepted by the strict `lock/v1` reader. Symlinks, special files,
extra hard links, malformed or unsupported locks, and concurrent observations
are preserved and rejected.

A non-blocking exclusive advisory lock on the pinned root directory serializes
cooperating Engine lock operations. Contention returns a typed busy failure.
Generated bytes are canonical pretty JSON with one final newline.

Before discovery, the operation handles the reserved `.malm-lock.tmp` entry. It
removes a stale entry only after descriptor-pinned inspection proves that the
entry is a complete canonical `lock/v1` file with generated ownership, mode,
link count, and size. It preserves and rejects any other caller data. Cleanup is
synced, and `.malm-lock.tmp` is excluded from every pack tree.

Publication uses a same-directory unnamed file with exact mode `0644`. The data
is synced before visibility, and the root directory is synced after its entry
changes.

Creation links the unnamed file at `malm.lock` without replacement. Update links
the file at `.malm-lock.tmp`, revalidates the originally opened lock, and
atomically renames the staging entry over it. If generated update bytes are
canonically identical to the existing bytes, the operation syncs but does not
rewrite the file and preserves its inode.

The root directory and every path component remain descriptor-pinned and are
revalidated before and after publication. Any concurrent change observed before
the publication point fails closed. As with any POSIX rename, an uncoordinated
external writer racing in the final revalidation-to-rename interval is outside
the cooperative concurrency contract.

## Failure semantics

No invalid, incomplete, cyclic, oversized, or unassembled candidate becomes the
root lock. Create never replaces an existing entry. Update validates the old
lock before source capture and publishes only one complete replacement.

CAS population is intentionally not rolled back. Immutable verified objects
remain safe to retain after a later source, graph, or lock-file failure.
