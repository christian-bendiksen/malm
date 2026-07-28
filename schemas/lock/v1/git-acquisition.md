# Exact Git source acquisition (`lock/v1`)

The exact Git adapter acquires one `GitSourceV1` whose pack content digest is
already locked independently, verifies the selected committed bytes, and
publishes the pack through the `store/v1` CAS. Engine callers use it directly
for one source, through [complete graph acquisition](graph-acquisition.md), or
as the transport used by explicit [lock creation and update](creation-update.md).

A `GitSourceV1` contains one normalized HTTPS URL, one full SHA-1 or SHA-256
object ID, and either the repository root or an explicit `PackSubdir`. The
adapter does not resolve branches, tags, prefixes, default branches, version
ranges, registries, or fallback references. It writes no lock or deployment
state record; its only persistent result is immutable pack-object CAS content.

## Cache-first boundary

The adapter checks the locked pack-object CAS before inspecting Git process
configuration or scratch. It semantically re-verifies and reuses a valid object
without process or network access. Reuse therefore succeeds even when the
supplied executable and scratch path no longer exist.

A missing object continues to acquisition. A corrupt or unsafe CAS entry fails
and is never treated as a cache miss, replaced, or repaired.

## Explicit host capabilities

On a cache miss, the caller supplies:

- An absolute Git executable path. Engine never consults `PATH`.
- A positive timeout for each Git process, no greater than 600 seconds.
- A positive fetch-transfer limit, no greater than 2 GiB.
- One explicit, existing, empty scratch directory.

Scratch must be a real directory owned by the current user with exact mode
`0700`. No path component may be symbolic, and scratch must not overlap the Malm
state root in either lexical or physical direction. The adapter pins scratch by
descriptor before use and starts Git with that descriptor as its current
directory. Later pathname replacement therefore cannot redirect Git writes.
The complete binding chain is revalidated between stages.

Scratch is caller-owned temporary authority, not a persistent v1 Git cache. The
adapter does not remove it after success or failure. A persistent mirror would
need a separate `store/v1` layout, durability, retention, and recovery contract.

## Acquisition sequence

On a cache miss, the adapter:

1. Validates and pins the empty scratch directory and the ready read-write
   store.
2. Initializes a fresh bare repository using the hash algorithm named by the
   locked object ID.
3. Fetches exactly the full raw hexadecimal object ID from the granted HTTPS
   URL.
4. Reads the commit, trees, and blobs through `git cat-file --batch`.
5. Selects the requested repository root or pack subdirectory, applies pack
   path and capture-root rules, and computes the canonical pack digest.
6. Verifies the strict manifest, declared files, component digests, and locked
   content digest before no-replace CAS publication.

The fetch has no destination ref, tags, `FETCH_HEAD`, submodule recursion,
checkout, archive, or fallback refspec. Its source selection is equivalent to:

```text
git --git-dir=. fetch --no-tags --no-write-fetch-head <https-url> <full-oid>
```

The implementation also disables progress, automatic maintenance, and
commit-graph writes and performs a depth-one fetch. If a server refuses a direct
full-OID want, acquisition fails. The adapter does not broaden the request to a
branch, tag, advertised-ref wildcard, or default branch.

## Process confinement

Each Git process starts in a new process group. A no-new-privileges seccomp
filter rejects non-native syscall ABIs, normalizes the x86-64 x32 syscall bit,
and denies `setsid` and `setpgid`. The filter is inherited across fork and exec,
so descendants cannot leave the bounded group.

Malm drains bounded control output concurrently. A timeout or output overflow
kills and reaps the complete process group. During fetch, the child and every
descendant inherit an `RLIMIT_FSIZE` ceiling equal to the transfer limit, so no
one temporary packfile can grow beyond that limit.

Malm also measures descriptor-relative regular-file storage below scratch while
fetch runs. It accounts for apparent and allocated size relative to the
post-initialization baseline. Aggregate growth beyond the limit kills and reaps
the complete group. Measurement follows no symbolic link and crosses no mount
boundary.

The supervisor observes the group leader without reaping it. After the leader
exits, Malm first kills residual group members, then reaps the leader and runs
final output and scratch-budget checks. A helper cannot evade the timeout by
holding a pipe open or continuing to mutate scratch after its leader exits.
Scratch measurement has its own entry, nesting, time, and early-byte bounds, so
supervision work cannot bypass the process budget.

## Deterministic Git environment

The adapter clears the environment and supplies only deterministic locale and
Git hardening values. In particular:

- Interactive prompts and askpass helpers are disabled.
- System and global Git configuration are disabled.
- Replacement objects and pathspec interpretation are disabled.
- Only HTTPS transport is allowed.
- HTTP redirects are disabled, keeping the granted URL as the sole network
  authority for fetch.
- File and ext protocols are disabled.
- Hooks, credential helpers, automatic maintenance, and commit-graph writes are
  disabled.
- Fetch and transfer object checking are enabled.
- Proxy, loader, ambient `HOME`, XDG, credential, and arbitrary `GIT_*`
  variables are not inherited.

## Raw object validation

All source bytes come from `git cat-file --batch`. Archive attributes, checkout
filters, executable checkout modes, and working-tree configuration cannot alter
them.

1. The exact requested OID must itself have type `commit`. A tag object is
   rejected and never peeled.
2. The raw commit must contain exactly one full-width tree header for the
   repository object format.
3. The adapter resolves a selected subdirectory one raw tree component at a
   time. Every component must exist with tree mode `40000`.
4. Raw trees must use Git's binary mode, name, and OID framing without duplicate
   names. SHA-1 tree IDs are 20 bytes; SHA-256 tree IDs are 32 bytes.
5. Reserved `.git` and `.malm-lock.tmp` names are pruned before type and UTF-8
   checks. Nested `malm.lock` components are also pruned. A root `malm.lock` may
   be retained temporarily only for the tracked-root caller described below.
6. Every other name must be UTF-8, and every complete path must be a valid
   `PackPath`.
7. Modes `100644` and `100755` are accepted as regular blobs. Mode `120000`
   symbolic links, mode `160000` gitlinks, and every other mode are rejected.
8. Every batch response must match the requested full OID, expected type,
   declared size, and exact binary framing.

Traversal-entry and raw-tree-byte budgets are shared across subdirectory
selection and selected-tree capture. File count, one-file bytes, and aggregate
logical file bytes are independently bounded.

## Capture-root narrowing

After raw selection, the adapter narrows the selected tree to capture roots from
the acquired tree's own `malm-pack.kdl`. It never takes those roots from host
state. This matches [local source capture](../../pack/v1/source-capture.md), so
one source tree has one pack digest under either adapter.

The manifest is always retained. If it is missing, oversized, or malformed,
narrowing keeps the whole selected tree and strict verification reports the
actual manifest problem. A root `malm.lock` is not pack content; it survives
narrowing only for a tracked-root caller that validates and strips it. Ordinary
pack publication omits it.

Traversal, entry, raw-tree-byte, and logical-byte limits apply before narrowing.
A commit whose uncaptured files exceed a limit is rejected.

The adapter computes the canonical pack digest and runs strict manifest,
declaration, and component checks before publication. Before it reports
publication success, the CAS publisher must independently reconstruct and
verify the canonical pack digest.

## Resource limits

| Resource | Maximum |
|---|---:|
| One Git process | 600 seconds |
| Fetch transfer and aggregate scratch growth | 2 GiB |
| One bounded control stream | 64 KiB |
| Raw commit object | 16 MiB |
| One raw tree object | 128 MiB |
| Combined raw tree bytes | 1 GiB |
| Batch response header | 160 bytes |
| Tree entries across selection and capture | 3,200,000 |
| Selected regular files | 100,000 |
| One selected blob | 256 MiB |
| Combined selected blob bytes | 1 GiB |
| Entries visited by one scratch measurement | 500,000 |
| Scratch measurement nesting below its root | 128 directories |
| Initial scratch-baseline measurement | 1 second |

Later scratch measurements remain within the subprocess deadline and stop early
after proving a byte-limit violation. Every object and tree parser allocation is
bounded by the corresponding limit above.
