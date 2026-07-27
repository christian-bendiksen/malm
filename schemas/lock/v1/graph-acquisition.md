# lock/v1 Complete Graph Acquisition

## Scope

Complete graph acquisition verifies every root, local, and exact Git node in an
already validated `LockV1`, publishes missing immutable pack
objects, and invokes the offline private-module graph assembler. It never
creates, updates, or writes a lock and performs no deployment configuration,
component-transform, render, asset, or target work.

Inputs are:

- One explicit absolute root-pack directory.
- One validated complete lock.
- Exact granted `LocalLocator` values.
- Exact granted normalized Git URLs.
- Caller-owned empty Git scratch roots keyed by missing pack content digest.
- One explicit bounded Git process configuration.

## Authority Preflight

Before source capture, Git execution, or CAS mutation, every local locator and
Git URL in the complete lock must appear in its corresponding grant set. Cache
inspection is read-only. Each unique missing Git content digest must have a
scratch root; a fully verified cached Git object requires no scratch.

This makes the authority boundary independent of graph traversal order. A
missing local grant, missing Git grant, missing scratch root, or corrupt cached
object fails before the root pack is published.

## Acquisition

Unique Git content digests are acquired first through the
[exact Git adapter](git-acquisition.md). Different lock nodes with the same pack
digest share one verified object; once present, another exact source identity
does not require network access because the reviewed lock binds that source to
the same independently verified bytes.

The root and every local origin are then processed through the
[local graph adapter](local-acquisition.md). Unlike immutable Git nodes, local
nodes are always recaptured, so cached bytes cannot conceal current drift or a
missing origin.

Finally, the read-only assembler reloads every object and verifies:

- Canonical object and logical pack digests.
- Strict manifests and every declared file/component digest.
- Package, source, component, dependency-alias, and target-node agreement.
- Complete closure, private direct-dependency scopes, and deterministic order.

The returned graph retains the unchanged lock as provenance. If all Git objects
are cached, a later invocation can run with an unavailable executable and
without scratch; only current local origins are read.

As with individual CAS publication, acquisition is not a transaction over
cache population. Independently valid content-addressed objects may remain if a
later source fails, but no graph record or lock update is persisted.

The separate explicit [`creation/update operation`](creation-update.md)
discovers unknown digests and writes the generated root lock. This acquisition
operation continues to require an already reviewed complete lock and never
invokes creation or update implicitly.
