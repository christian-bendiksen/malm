# lock/v1 Root And Local Graph Acquisition

## Scope

Local graph acquisition verifies and publishes every `Root` and `Local` node in
an already validated `LockV1`, then invokes the offline module
graph assembler. It does not create or update a lock, use Git or the network,
parse deployment configuration, or write any graph-specific persistent record.

Inputs are:

- One explicit absolute root-pack directory.
- One validated complete lock.
- An explicit set of granted `LocalLocator` values.

The root source is the caller-selected authority and is implicitly granted.
Every `Local` lock node, including a locator that does not escape the root,
must appear in the exact grant set. This conservative adapter boundary keeps
interactive or organization-specific policy outside Engine and ensures that no
local filesystem authority is inferred from lock contents alone.

## Preflight

Before any source read or CAS mutation, the operation scans the complete lock:

- Every local locator must be explicitly granted.
- Any Git node is rejected as unsupported by this local-only operation.

Consequently, a missing grant or mixed Git graph cannot publish even the root
object as a side effect. The separate [exact Git adapter](git-acquisition.md)
shares the downstream CAS and verification stages. The general
[`graph-acquisition`](graph-acquisition.md) operation composes both source kinds;
this narrower operation remains intentionally local-only.

## Root-Relative Resolution

Every local locator is resolved lexically from the root pack directory, never
from the directory of the pack declaring the dependency. `.` selects the root
directory. Leading `..` components walk upward from the root directory, and all
remaining components walk downward. `LocalLocator` validation has already
rejected absolute paths, internal parent segments, dot segments, empty segments,
backslashes, controls, and reserved `.git`, `malm.lock`, or `.malm-lock.tmp`
components.

The resulting absolute path is passed to the `pack/v1` local source-capture
adapter, which independently rejects symbolic path components, state-root
overlap, nested mounts, unsafe entries, unstable observations, and digest drift.

## Acquisition Sequence

After preflight, the operation:

1. Recaptures and publishes the root node at its locked content digest.
2. Resolves, recaptures, and publishes every local node at its locked digest.
3. Loads all resulting objects through the read-only CAS capability.
4. Re-verifies pack bytes, strict manifests, declared files, component digests,
   package identities, source identities, dependency aliases, and target nodes.
5. Returns the complete graph in deterministic dependency-before-importer
   order with the validated lock retained as provenance.

A valid CAS hit never suppresses local capture. Current drift or a missing local
origin fails even when the old locked object remains available for explicitly
offline consumers. Normal acquisition never rewrites `malm.lock`.

CAS publication is content-addressed rather than transaction-scoped. If a later
node fails after earlier matching nodes were published, those independently
valid immutable objects may remain as unreferenced cache entries; no assembled
graph or lock update is published.
