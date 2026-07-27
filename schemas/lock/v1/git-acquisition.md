# lock/v1 Exact Git Acquisition

## Scope

The exact Git adapter acquires one `GitSourceV1` whose pack content digest was
locked independently, then publishes the selected pack through the `store/v1`
CAS. It supports full SHA-1 and SHA-256 commit object IDs and repository-root or
explicit `PackSubdir` selection. It does not resolve branches, tags, prefixes, default
branches, version ranges, or registries, and it never writes the state
root.

The adapter is exposed as a one-node Engine operation, through complete
[`graph acquisition`](graph-acquisition.md), and as the exact-source transport
used by explicit [`lock creation and update`](creation-update.md).

## Explicit Host Capability

The caller supplies:

- An absolute Git executable path. `PATH` is never consulted.
- A positive per-process timeout no greater than 600 seconds.
- A positive fetch-transfer limit no greater than 2 GiB.
- An explicit existing empty scratch directory.

Scratch must be a real, current-user-owned directory with exact mode `0700`, no
symbolic component, and no lexical or physical overlap with either Malm state
root. It is pinned by descriptor before use. Git starts with that descriptor as
its current directory, so later pathname replacement cannot redirect writes.
The binding chain is revalidated between stages.

Scratch is caller-owned temporary authority, not a persistent v1 Git cache. The
adapter does not remove it after success or failure. A later persistent mirror
would require a separate `store/v1` layout, durability, retention, and recovery
contract.

## Cache-First Behavior

The locked pack-object CAS is checked before Git configuration or scratch is
inspected. A valid object is semantically re-verified and reused with no process
or network access; this works even if the supplied executable and scratch no
longer exist. Missing objects continue to acquisition. Corrupt or unsafe CAS
entries fail and are never treated as cache misses or repaired.

## Process Boundary

Each Git process starts in a new process group. A no-new-privileges seccomp
filter rejects non-native syscall ABIs, normalizes the x86-64 x32 syscall bit,
and denies `setsid` and `setpgid`. It is inherited across fork and exec, so
descendants cannot leave that bounded group. Malm concurrently drains bounded
control output and kills and reaps the complete group on timeout or output
overflow. During fetch, the child process and every descendant inherit an
`RLIMIT_FSIZE` ceiling equal to the transfer limit, so no temporary packfile can
grow beyond that limit. Malm also measures descriptor-relative regular-file
storage below scratch while fetch runs. Apparent and allocated sizes are both
accounted, relative to the post-initialization baseline; aggregate growth beyond
the limit kills and reaps the complete process group. Measurement never follows
symbolic links or crosses a mount boundary.

The supervisor checks the group leader without reaping it. When the leader exits,
Malm first kills any residual group members, then reaps the leader and performs
final output and scratch-budget checks. A helper cannot escape the timeout by
holding a pipe open or continuing to mutate scratch after its leader exits.
Scratch measurement itself has fixed entry and nesting ceilings, a deadline,
and an early byte cutoff, so supervision work cannot bypass the process budget.

The environment is cleared, then only deterministic locale and Git hardening
variables are supplied. In particular:

- Interactive prompts and askpass helpers are disabled.
- System and global Git configuration are disabled.
- Replacement objects and pathspec interpretation are disabled.
- Only HTTPS transport is allowed.
- HTTP redirects are disabled, so the granted URL remains the sole network
  authority for the fetch.
- File and ext protocols are disabled.
- Hooks, credentials helpers, automatic maintenance, and commit-graph writes
  are disabled.
- Fetch and transfer object checking are enabled.
- Proxy, loader, HOME, XDG, credential, and arbitrary `GIT_*` variables are not
  inherited.

The fresh bare repository uses the hash algorithm named by the locked object ID.
Fetch requests exactly the full raw hexadecimal OID, with no destination ref,
tags, `FETCH_HEAD`, submodules, checkout, archive, or fallback refspec:

```text
git --git-dir=. fetch --no-tags --no-write-fetch-head <https-url> <full-oid>
```

A server that refuses direct full-OID wants causes acquisition failure. The
adapter does not broaden the fetch to a branch, tag, advertised-ref wildcard, or
default branch.

## Raw Object Selection

All source bytes are read through `git cat-file --batch`; archive attributes,
checkout filters, executable modes, and working-tree configuration cannot alter
content.

1. The exact requested OID must itself return type `commit`. Tag objects are
   rejected and never peeled.
2. The raw commit must contain exactly one full-width tree header for the
   repository object format.
3. A selected subdirectory is resolved one raw tree component at a time and
   every component must have tree mode `40000`.
4. Raw tree objects use Git's binary mode/name/OID framing. SHA-1 tree IDs are
   20 bytes and SHA-256 tree IDs are 32 bytes.
5. Exact `.git`, `malm.lock`, and `.malm-lock.tmp` names are pruned before type
   and UTF-8 checks.
6. Other names must form valid UTF-8 `PackPath` values.
7. Modes `100644` and `100755` are accepted as regular blobs. Mode `120000`
   symlinks, mode `160000` gitlinks, and every other mode are rejected.
8. Blob responses must match the requested full OID, type, declared size, and
   exact binary framing.

Traversal entries and raw tree bytes share one budget across subdirectory
selection and selected-tree capture. File count, one-file bytes, and aggregate
logical bytes are also bounded. The canonical pack digest and strict
manifest/declaration/component checks run before publication, and the CAS
publisher independently recomputes and verifies canonical bytes.

The selected tree is narrowed to the capture roots declared by its own
`malm-pack.kdl`, matching the
[local capture](../../pack/v1/source-capture.md). Declared roots are read from
the acquired manifest bytes, not from the host. A missing, oversized, or
malformed manifest narrows nothing, and the strict manifest check below reports
the real problem. `malm.lock` is not pack content; it survives narrowing for the
tracked-root caller that validates and strips it.

Traversal, entry, and byte limits apply to the selected tree before narrowing.
A commit whose uncaptured files exceed a limit is refused.

## Bounded Resources

The adapter bounds subprocess time, output, temporary packfile size, aggregate
scratch growth, and every object/tree parser allocation.
