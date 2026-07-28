# Complete graph acquisition (`lock/v1`)

The complete `lock/v1` acquisition operation verifies every root, local, and
exact Git node in an already validated `LockV1`, publishes missing immutable
pack objects, and invokes the offline private-module graph assembler. Prepare
implementers use it when they have a reviewed mixed-source lock and need the
verified graph without changing that lock.

The operation never creates, updates, or writes `malm.lock`. It also performs no
deployment configuration, component transform, rendering, asset processing, or
target work.

## Inputs

The caller supplies:

- One explicit absolute root-pack directory.
- One validated, complete `LockV1`.
- The exact granted `LocalLocator` values.
- The exact granted normalized Git URLs.
- Caller-owned empty Git scratch roots keyed by missing pack content digest.
- One explicit bounded Git process configuration.

Publication requires a ready read-write store. Fully cached Git content can
avoid process and scratch access, but the Git configuration remains an explicit
operation input.

## Authority preflight

Before any source capture, Git execution, or CAS mutation, the operation scans
the complete lock. Every local locator and every Git URL must appear in its
corresponding grant set, including sources whose pack bytes are cached.

Cache inspection during preflight is read-only. Every unique missing Git
content digest must have a scratch root. A fully verified cached Git object
requires no scratch. A corrupt or unsafe cached object is an error, not a cache
miss.

As a result, a missing local grant, missing Git grant, missing scratch root, or
corrupt cached object fails before publication of even the root pack. Authority
validation is independent of graph traversal order.

## Acquisition sequence

1. Inspect each unique Git content digest and identify the missing objects.
2. Acquire each unique missing digest through the [exact Git adapter](git-acquisition.md).
3. Recapture and publish the root and every local origin through the
   [root and local adapter](local-acquisition.md).
4. Assemble the complete graph from read-only verified object access.

Different lock nodes with the same pack digest share one verified object. After
that object exists, another exact source identity does not require network
access because the reviewed lock independently binds that source to the same
bytes. Local nodes are different: every local origin is recaptured even when
its locked digest already exists in the CAS, so cached bytes cannot conceal
current drift or a missing origin.

## Offline assembly

The final read-only assembler verifies:

- Canonical object bytes and logical pack content digests.
- Strict manifests, every declared file, and every component digest.
- Package, source, component, dependency-alias, and target-node agreement.
- Complete closure, private direct-dependency scopes, and deterministic
  dependency-before-importer order.

Assembly retains at most 1 GiB of unique verified pack-file bytes and at most
65,536 module-scope entries. Underlying pack and Git adapter limits also apply.

The returned graph retains the unchanged lock as provenance. If all Git objects
are cached, a later invocation may use an unavailable executable and no scratch;
only current root and local origins are read.

## Failure and persistence

Acquisition is not a transaction over CAS population. Independently valid
content-addressed objects may remain if a later source or assembly step fails.
No graph-specific record or lock update is persisted.

The separate explicit [creation and update operation](creation-update.md)
discovers unknown digests and writes the generated root lock. Complete graph
acquisition always requires an already reviewed lock and never invokes creation
or update implicitly.
