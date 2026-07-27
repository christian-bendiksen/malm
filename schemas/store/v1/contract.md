# store/v1

- Status: Frozen v1 contract
- Coverage: Root, pack/blob/canonical CAS, prepared lifecycle and retention
  authority, journaled namespace transitions, namespaced state catalog,
  reference-aware retention, and complete public-record fixture conformance

## Scope

This contract covers immutable pack and blob objects, prepared records, the
transaction journal, namespaced state generations, embedded lifecycle and
tracked-root state, the namespace-head catalog, and
reference-aware retention under the final state root. Global target ownership is
derived from enabled catalog-selected generations and is never persisted as a
second authority. Tracking is generation state, not a mutable side record.

## Fixture Index

| Record | Valid | Golden | Rejection fixtures | Conformance |
| --- | --- | --- | --- | --- |
| Prepared record | `valid/prepared-record.json` | `golden/prepared-record.json`, identity in `golden/digests.json` | `malformed/prepared-record-*`, `unsupported/prepared-record-*` | `malm-store/tests/contracts.rs` |
| State generation | `valid/state-generation.json` | `golden/state-generation.json`, identity in `golden/digests.json` | `malformed/state-generation-*`, `unsupported/state-generation-*` | `malm-store/tests/contracts.rs` |
| State catalog | `valid/state-catalog.json` | `golden/state-catalog.json`, identity in `golden/digests.json` | `malformed/state-catalog-*`, `unsupported/state-catalog-version-2.json` | `malm-store/tests/contracts.rs` |
| Transaction journal | `valid/transaction-journal.json` | `golden/transaction-journal.json` | `malformed/transaction-journal-*`, `unsupported/transaction-journal-version-2.json` | Private `malm-commit` codec unit tests |

All JSON record fixtures include their final LF. Golden prepared and generation
records are linked: the generation is derived from the prepared record. The
golden catalog names both fixture generations and the valid catalog names the
minimal generation. There are intentionally no ownership or target-lock record
fixtures because those records are not authoritative parts of this model.

Prepared records must bind all operation inputs and preconditions. Commit reads
only supported store/v1 records and verified local objects; missing or corrupt
data is an error and is never regenerated. Store/v1 data lives under
the admitted final `$XDG_STATE_HOME/malm` root and never imports predecessor
state.

Layouts, canonical bytes, digest algorithms, and durability rules below are the
frozen store/v1 contract. They cannot be reinterpreted by a later v1 milestone;
an incompatible change requires a new schema version.

## Root Descriptor

The final descriptor, production-root resolver, closed top-level allowlist,
metadata rules, canonical fixtures, and no-replace publication contract are
defined exclusively by [`root/v1`](../../root/v1/README.md). Store records are
admitted only after that descriptor and complete top-level shape validate.

## Pack Objects

Canonical pack objects live at `objects/packs/sha256-<64 lowercase hex digits>`.
Their exact binary encoding, filesystem invariants, publication sequence, and
read verification are defined in [`pack-object.md`](pack-object.md). The object
bytes are the `pack/v1` content-digest preimage, so the filename digest is both
the SHA-256 of the complete stored file and the logical pack-tree identity.

The `objects` and `objects/packs` containers are current-user-owned directories
with exact mode `0700`. Objects are current-user-owned regular files with exact
mode `0400` and one link. Readers reject malformed metadata, unsafe entry types,
oversized or noncanonical bytes, digest mismatches, and observations that change
during access. Publication is durable and no-replace; an existing object is
reused only after complete verification and is never repaired implicitly.
Local filesystem selection and stable capture before publication are defined by
the `pack/v1` [`source-capture`](../../pack/v1/source-capture.md) contract.

## Prepared Plans And Blobs

Prepared records live at `prepared/pp-<64 lowercase hex digits>`. The identifier
is the complete SHA-256 of the canonical compact JSON record including its final
LF. Records are current-user-owned regular files with exact mode `0400` and one
link. Readers bound size, reject unknown fields and unsupported versions,
re-encode to prove canonical form, and verify the complete filename digest.
Writers enforce the same 16 MiB encoded limit before publication.

A record binds schema versions, namespace, expected active generation, a closed
transition kind, complete next lifecycle, optional selected restore point,
retention authority, optional tracked-root state, locked graph and input digests,
artifact metadata, generated format-transform provenance, policy findings and
approval digest, ordered closed operations, target observations, the complete
canonical next `DesiredSnapshotV1`, and its domain-separated digest. The
snapshot is mandatory plan content, never reconstructed from operations while
decoding, committing, or recovering. Transition, lifecycle, restore, retention,
and tracked-root fields are mandatory in canonical bytes.
Canonical records encode every lifecycle, retention, restore-point, pin, and
tracking choice explicitly; readers never derive those values from API defaults.
Transform provenance can be generated only through Engine-controlled built-in
or format-component execution; a plain prepare request cannot claim it.
Each successful transform retains its closed implementation identity, request,
typed-document, resource, and response digests and every exact bounded
diagnostic. Successful diagnostics retain warning or info severity, original
code, message, optional source-or-output range, and notes; error severity,
duplicates, and noncanonical ordering are rejected. Source locations contain
only a locked-pack authority label and digest, a canonical pack-relative
document path, and the captured source's exact byte length; ranges cannot exceed
that length. Host paths are neither accepted nor persisted. One transform
retains at most 1,024 resources, 256 diagnostics, 64 notes per diagnostic, 16
KiB per message or note, and 1 MiB of aggregate diagnostic text. These fields
are canonical prepared-record and generation bytes and therefore participate in
both identities. Policy
findings remain the separate approval projection of successful diagnostics.
Target observations include owner, group, mode, link count, size, mtime, and
ctime. Closed operations reject contradictory leaf type, conflict, and mode
semantics before they become content-addressed records. The closed set includes
regular-file, safe-relative-symlink, canonical-tree, and archive-provenanced-tree
placement plus directory ensure, leaf removal, absent assertion, and exact
semantic assertion. Removal is idempotent when an owned target is already
absent. Ordinary directory removal is limited to an observed empty directory;
a previously managed canonical tree is instead verified recursively before its
nonempty root enters the same journaled backup transition. When a managed
directory contains effective managed descendants, the transition removes those
descendants and releases directory ownership without unlinking the structural
container. This preserves unmanaged sibling entries and lets disable/remove
transitions complete without treating a parent as an independently empty leaf.
`assert-absent` binds absence, while `assert-exact` binds an unchanged present
target and all canonical object identities without mutating it.

Desired snapshots contain at most 65,536 strictly ordered authority/path slots.
Normal reconciliation is cumulative: every predecessor slot remains present in
the next snapshot or becomes a same-kind tombstone.
Newly evaluated declarations are merged with those tombstones. Lifecycle
transitions may instead select an exact retained snapshot or the required empty
snapshot. Before publication, the predecessor and successor slots determine the
exact required target mutations, and the observed operation manifest must agree
with them without further filesystem access. The transition must also agree
with the expected predecessor, namespace, desired digest, transition kind,
selected restore point, and retention authority. Disable removes every formerly
effective target and publishes disabled state with an empty snapshot and no
active tracking, while retaining the prior enabled generation as an exact
restore point. Enable exactly restores that retained generation. Checkout
appends the selected retained state while preserving cumulative tombstones for
current slots absent from the source generation. Namespace removal reconciles
to empty state and is the only transition that removes a catalog head without
publishing a generation.
Mutation operations that are missing, extra, wrong-kind, or bound to the wrong
artifact metadata are rejected.

Policy findings supplied by a prepare request are additive. After all target
observations are captured, Engine adds a mandatory `replace-existing` finding
for each replacement operation whose leaf is present and a mandatory
`remove-existing` finding for each removal whose leaf is present. Both require
approval and identify only the logical authority and relative path. An absent
replacement or removal gets no generic destructive finding; if an absent leaf
appears later, commit rejects the stale observation instead of replacing or
removing it. Callers and transforms cannot suppress these mandatory findings.
Unsafe ownership, links, target kinds, state overlap, corruption, and missing
authority remain hard errors rather than approvable findings.

A finding ID is SHA-256 over `malm-policy-finding-v1\0`, length-framed code and
message bytes, and one approval-required byte. Findings are canonically sorted
by ID. The approval digest is SHA-256 over `malm-plan-approval-v1\0` followed by
the length-framed IDs of approval-required findings in that order. Exact
duplicate finding IDs are rejected. Commit accepts only this persisted binding
and never reevaluates findings.

Artifact bytes live at `objects/blobs/sha256-<64 lowercase hex digits>`. Blob
containers use mode `0700`; blob objects use mode `0400` and one link. Prepare
publishes synced unnamed files with no replacement and publishes the prepared
record only after every referenced blob is durable. A shared
`maintenance.lock` prevents publication from racing reference-aware retention.
One plan may reference at most 256 MiB of unique blob bytes. Repeated artifact
IDs sharing one digest are loaded and published once. Canonical file, symlink,
and tree objects live under `objects/files`, `objects/symlinks`, and
`objects/trees` with the same private-container and immutable-entry metadata.
Prepared publication re-verifies every referenced symlink target and complete
tree closure while holding `maintenance.lock`, so retention cannot remove an
object between preflight and prepared-record publication.

## State And Transactions

Immutable state generations live at
`state/generations/sha256-<64 lowercase hex digits>`. `state/catalog.json` is the
canonical mode-`0600` authority for independent namespace heads. It contains at
most 4,096 `NamespaceHeadV1` entries, strictly sorted and unique by a validated
`[A-Za-z0-9_-]+` namespace name of at most 128 bytes. Each head binds one full
generation digest. Catalog readers cap canonical bytes at 4 MiB, reject unknown
fields, malformed identifiers, unsupported versions, duplicates, noncanonical
ordering, and noncanonical JSON, and compute the catalog digest over the exact
compact JSON bytes including the final LF.

Generations bind their namespace, committed plan, prior generation in that
namespace, transition kind, lifecycle, selected restore point, retention
authority, optional tracked-root state, complete desired snapshot and digest,
artifact ownership, and complete transform provenance. This authority is copied
only from the prepared record that creates the generation; operations never
derive or replace it. Rebuilding a transition attests those exact fields plus
the lifecycle-aware operation manifest and artifacts. A target slot records
authority, relative path, file, directory, symlink, or tree kind, and
present-or-absent state. Present files bind digest, byte length, and mode;
present directories bind mode; symlinks bind their canonical object digest; and
trees bind their canonical root plus optional archive payload/decoder
provenance.
The desired-snapshot digest uses `malm-desired-snapshot-v1\0`, the length-framed
namespace, and the length-framed canonical snapshot JSON. Readers recompute it,
and live commit independently rebuilds every transition from its prepared plan
and exact predecessor. Prior links form one bounded retained generation chain
per catalog namespace. Once verified pruning removes history below the configured
floor, the floor generation's content-addressed predecessor field remains as a
weak historical identity and its copied authority is verified directly against
its retained prepared record.

`LifecycleStateV1` is closed to `enabled` and `disabled`. A disabled selected
generation has an empty desired snapshot and no active tracking, contributes no
ownership claims, and carries an exact restore point for its prior enabled
generation. Re-enabling appends a generation restored from that immutable point;
it does not move the catalog head backward. Namespace removal is only removal of
that namespace's catalog head. There is no `removed` lifecycle generation that
remains selected while pretending not to own state.

`TrackedRootV1` is an embedded schema version 1 record. It binds a canonical
credential-free HTTPS source locator (2,048 bytes), symbolic moving selector
(1,024 bytes), full `sha1-` or `sha256-` applied revision, SHA-256 root-tree
digest, root-relative config entry point (1,024 bytes), resolved profile, and
persisted acquisition grants. It also binds a canonical root-relative source
subdirectory, which may be `.`. Grants are closed to `local-source`, `git-source`,
`format-component`, and `target-authority`. They are strictly sorted and unique
by kind and locator, with limits of 8,192 entries, 4,096 bytes per locator, and
4 MiB of aggregate locator text.
Locators are credential-free logical authority; Git executables, scratch paths,
credentials, and other host capabilities are never persisted. Moving selectors
cannot be exact revisions. Prepared plans always encode the
complete optional value: repeating it carries tracking, a different value
replaces tracking, and `null` clears tracking. Generation derivation never
infers any of those choices from the predecessor.

Every present target in an enabled catalog-selected generation is one transient
ownership claim; disabled snapshots, absent tombstones, and unselected retained
history claim nothing. The derived projection is capped at 65,536 claims. It
deterministically rejects exact cross-namespace conflicts and path-component
ancestor/descendant conflicts without
confusing lexical prefixes such as `a` and `a-b`. Commit also pins every required
target authority and rejects nested or bind-mounted authority aliases. Prepare
checks the current projection before publishing a blob or plan, and commit
recomputes it under `transaction.lock`, so an unrelated namespace advance does
not stale a plan unless it creates an ownership conflict. Missing authority
mappings fail closed.

Catalog admission traverses each selected predecessor chain through its
configured retained-history bound, capped at 65,536 generations across the
catalog. Each retained generation, namespace edge, committed plan, and derived
transition is verified; the retained floor is verified against its prepared
authority without requiring a predecessor that verified pruning has removed.
Missing non-floor edges, cycles, cross-namespace histories, and non-derived
records block inspection and mutation rather than falling back to a directory
scan.

An in-progress commit owns `transaction.lock` and publishes the canonical
mode-`0600` journal at `transactions/current.json` before target mutation. The
journal binds the exact prepared plan, affected namespace, prior and optional
next generation, and prior and next catalog digests. Only namespace removal has
no next generation; its next catalog omits the reviewed namespace head. Each
operation also records the identity of its created inode and the monotonic phase
of any replacement or removal backup. Backup intent is
durable before rename and carries the stable SHA-256 of a regular-file source;
after rename and parent-directory sync it advances to an identified phase
containing the exact prepared-source identity while retaining that digest.
Journal updates are complete unnamed files linked as an update, atomically
exchanged with the pinned current inode, and verified on both sides before the
prior version is removed. Recovery distinguishes an interrupted pre-exchange candidate from a
post-exchange previous version. Commit validates plan derivation, legal phase
progression, the identified backup against the immutable prepared source
identity, and exact target content during recovery, so structurally forged or
non-plan-equivalent canonical journals are rejected. The versioned reader
rejects the former `backup_identity` journal shape rather than migrating an
incomplete transaction.
The canonical phase encoding is illustrated by
[`fixtures/valid/transaction-journal.json`](fixtures/valid/transaction-journal.json);
the fixture demonstrates wire shape rather than a complete plan-derived
transaction.

Readers cap each current or staged journal at 56 MiB and bound its operation
sequence to 65,536 entries during deserialization, before allocating an
attacker-selected unbounded vector. A staged update is never promoted while
loading: recovery validates canonical bytes, monotonic single-field progression,
and complete plan-derived semantics before using it. A pre-exchange candidate is
cleaned by removing the prior current journal durably before the candidate; a
post-exchange previous version is removed before the authoritative current
journal. An update-only crash state is revalidated and resumed rather than
promoted.

Target mutation uses pinned descriptor-relative beneath/no-follow operations.
Physical exclusion includes mount-ID proof for same-filesystem bind aliases.
Replacement and removal backups and cleanup quarantine entries use names
derived from the full plan digest and operation index. File and mutable
store-control staging use unnamed inodes until their complete bytes and
identities are durable. Symlinks are staged as exact no-follow link inodes.
Trees are recursively materialized only beneath a private staging root from a
fully verified canonical closure, with independent regular files rather than
hard links, then atomically renamed at the managed root. Mutable journal and
catalog replacement uses pinned exchange plus byte and binding verification, so
a substituted source or
destination is restored or retained fail-closed rather than silently discarded.
Before catalog publication, recovery rolls operations back in reverse order.
After publication, recovery verifies the exact prepared state and removes
validated backups through transaction quarantine. It never re-resolves source,
config, graph, policy, assets, or format components.
During rollback only, an intent-phase backup may be restored when it matches the
immutable prepared leaf under relocation-stable identity fields and, for a
regular file, the durable pre-rename source digest. Backup cleanup and
roll-forward always require the exact identified post-rename identity. If a
rename captures a concurrently substituted inode, live commit pins that backup,
restores the same inode, and returns stale. A crash before that restoration is
complete retains the intent journal and fails closed; arbitrary raced identities
are never persisted as authority for automatic recovery.

Linux cannot create an unnamed directory or atomically journal the new inode
number produced by `mkdir`. A crash in the narrow interval after a directory
staging inode becomes named but before its identity update is durable therefore
fails closed: recovery preserves the entry and journal and requires explicit
intervention. It never guesses directory ownership from a reserved name or
deletes unidentified target content. Replacement and removal backup windows use
durable intent plus the prepared source identity and recover automatically; all
boundaries after durable identity publication recover to the prior or exact
prepared state.

The effective user and private final store are trusted publication authority,
not a cryptographic authenticity boundary against another malicious process
with the same UID. Cleanup quarantine entries are pinned and rechecked
immediately before `unlinkat`; Linux has no atomic compare-inode-and-unlink operation, so excluding
substitution in the final syscall interval requires exclusive namespace
authority or non-removing cleanup.

## Retention

Retention accepts an explicit set of prepared plan identifiers. It holds both
`transaction.lock` and `maintenance.lock`, refuses to run while a recovery
journal exists, and rejects removal of any plan selected by retained authority.
Roots include every catalog head through its configured bounded history,
restore-point generations, explicit prepared/generation/blob/pack/canonical
pins, non-selected prepared plans, and their blob, pack, canonical object, and
tree-closure dependencies. The current journal is excluded by refusing to prune
until recovery completes. Pack and prepared publication take the shared
maintenance exclusion, so no newly published root can race reachability.
New restore points and explicit pins, including their prepared, generation,
blob, pack, and canonical closures, are reverified while that exclusion is held
and again under the transaction exclusion before commit.
Retention validates all enumerated prepared records, generations, blobs, packs,
and canonical file/symlink/tree objects before deleting selected plans and any
verified immutable objects unreachable from retained authority. Generation
removal proceeds newest-to-oldest and syncs each removal, making a retained
history-floor predecessor edge weak only after its predecessor is durably gone.
A crash can leak an unreferenced immutable object but cannot remove a live or
recoverable object. Retention deduplicates blob verification and applies a 512
MiB aggregate work budget to decoded records, generations, and verified object
bytes.

The reader never enumerates, repairs, migrates, or mutates a predecessor root or
any sibling state tree.
