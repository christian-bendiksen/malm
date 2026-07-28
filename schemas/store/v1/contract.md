# Persisted state, transaction, and retention contract (`store/v1`)

`store/v1` is Malm's frozen contract for persisted plans, immutable objects,
namespace state, target transactions, crash recovery, and reference-aware
retention. Implementers of store I/O, commit, recovery, inspection, and
retention use it after the final state root has passed `root/v1` admission.

- **Status:** Frozen version 1 contract.
- **Coverage:** Root-relative layouts; pack, blob, and canonical object stores;
  prepared plans; namespace generations and catalog selection; lifecycle and
  tracking state; target ownership; transactions; recovery; and retention.

All requirements in this document are normative unless a paragraph is
explicitly labeled as explanatory context.

## Boundary and terms

The **final state root** is the admitted `$XDG_STATE_HOME/malm` directory, or
the admitted fallback selected by [`root/v1`](../../root/v1/README.md). This
contract never reads, imports, repairs, migrates, or mutates a predecessor root
or sibling state tree.

A **prepared record** is an immutable, reviewed plan and all preconditions for
one state transition. A **generation** is the immutable namespace state derived
from one committed prepared record. The mutable **catalog** selects at most one
generation head for each namespace. A **desired snapshot** is the complete,
cumulative set of target slots for one generation, including absent
tombstones. A **retention authority** is the history bound, restore points, and
explicit immutable-object pins copied into a prepared record and its
generation.

An **enabled selected generation** contributes ownership for its present target
slots. Disabled generations, absent tombstones, and retained generations not
selected by the catalog contribute no ownership. This global ownership
projection is always derived; it is never persisted as a second authority.
Tracking is also generation state, not a mutable side record.

Commit consumes only supported `store/v1` records and verified local objects.
Missing or corrupt data is an error and is never regenerated from source.

## Compatibility and root admission

Version 1 freezes the layouts, record fields, canonical bytes, digest
algorithms, durability rules, lifecycle transitions, rejection behavior, and
recovery sequence in this document. A later milestone cannot reinterpret those
rules while calling the result `store/v1`; an incompatible change requires a
new schema version.

The production root resolver, final `descriptor.json`, closed top-level
allowlist, metadata requirements, canonical fixtures, and no-replace root
publication are defined exclusively by
[`root/v1`](../../root/v1/README.md). A store reader must validate that
descriptor and the complete top-level shape before admitting any record below
the root.

Store records have no parallel JSON Schema. Their strict codecs, semantic
validation, and [fixtures](fixtures/) define the persisted forms.

## Store map

Paths in this table are relative to the pinned final state root.

| Path | Authority |
| --- | --- |
| `prepared/pp-<64 lowercase hex digits>` | Immutable prepared records |
| `objects/blobs/sha256-<64 lowercase hex digits>` | Exact artifact and deduplicated pack-member bytes |
| `objects/packs/sha256-<64 lowercase hex digits>` | Monolithic canonical pack objects |
| `objects/pack-manifests/sha256-<64 lowercase hex digits>` | Deduplicated pack manifests named by logical pack identity |
| `objects/files/sha256-<64 lowercase hex digits>` | Canonical file objects |
| `objects/symlinks/sha256-<64 lowercase hex digits>` | Canonical safe-relative-symlink objects |
| `objects/trees/sha256-<64 lowercase hex digits>` | Canonical tree objects |
| `state/generations/sha256-<64 lowercase hex digits>` | Immutable namespace generations |
| `state/catalog.json` | Mutable namespace-head authority |
| `transactions/current.json` | Current target-transaction journal |
| `transaction.lock` | Store-wide commit and recovery exclusion |
| `maintenance.lock` | Publication and retention exclusion |

Private containers are current-user-owned directories with exact mode `0700`.
Immutable entries are current-user-owned regular files with exact mode `0400`
and exactly one hard link. Mutable catalog and journal files have exact mode
`0600`. Readers use pinned descriptor-relative, beneath, no-follow operations
and reject unsafe types, owners, modes, link counts, sizes, bindings, or
observations that change during access.

## Pack cache

The logical identity of every cached pack is
`sha256-<64 lowercase hex digits>`. A pack may be stored as a monolithic object
under `objects/packs` or as a deduplicated manifest under
`objects/pack-manifests` whose exact member bytes live under `objects/blobs`.
Monolithic entries remain readable for compatibility; readers prefer a manifest
when both representations exist.

The exact binary encodings, limits, filesystem invariants, publication order,
and full read verification are defined by
[`pack-object.md`](pack-object.md). A monolithic object's bytes are exactly the
`pack/v1` content-digest preimage, so its filename digest is both the SHA-256 of
the complete stored file and the logical pack-tree identity. A manifest is
instead named by the logical identity and is accepted for use only after every
member blob and the reconstructed logical digest verify.

Pack publication is durable and no-replace. Existing entries are never
implicitly repaired, and an existing object is reused only after complete
verification. Local filesystem selection and stable capture before publication
are defined by the `pack/v1`
[`source-capture`](../../pack/v1/source-capture.md) contract.

## Prepared plans and immutable dependencies

### Record identity and admission

A prepared record lives at `prepared/pp-<64 lowercase hex digits>`. Its
identifier is the complete SHA-256 of the canonical compact JSON record,
including exactly one final LF. The encoded record is limited to 16 MiB.

Writers enforce that limit before publication. Readers bound input before
decoding, reject missing or unknown fields and unsupported versions, re-encode
the decoded value to prove canonical form, and verify the complete filename
digest. Canonical records encode transition, lifecycle, restore-point,
retention, pin, and tracking choices as persisted state rather than deriving
them from API defaults.

### Bound plan content

Every prepared record binds these complete fields:

- `schema_version` and the closed `schema_versions` set.
- `namespace` and the optional expected catalog head `expected_head`.
- The closed `transition`, next `lifecycle`, optional selected
  `restore_point`, complete `retention`, and complete optional `tracked_root`.
- `graph_digest`, ordered immutable `inputs`, artifact metadata in
  `artifacts`, and generated format-transform provenance in `transforms`.
- Canonically ordered policy `findings` and their `approval_digest`.
- The ordered closed target `operations`, including complete target
  observations.
- The complete canonical `desired_snapshot` and its domain-separated
  `desired_snapshot_digest`.

The snapshot is mandatory plan content. Decode, commit, and recovery never
reconstruct it from operations. Transition, lifecycle, restore-point,
retention, and tracked-root values are part of the canonical bytes and identity.

A record contains at most 65,536 inputs, 16,384 artifacts, 16,384 transforms,
16,384 findings, 65,536 operations, and 65,536 desired target slots. Fields
whose canonical order is defined must also be unique.

### Transform provenance

Only Engine-controlled built-in or format-component execution may generate
persisted transform provenance. A plain prepare request cannot claim it.

Each successful transform retains its closed implementation identity, request
digest, typed-document digest, strictly ordered resource identities, response
digest, and every exact bounded diagnostic. A successful diagnostic may have
only `warning` or `info` severity and retains its original code, message,
optional source-or-output range, and ordered notes. Readers reject `error`
severity, duplicate diagnostics, and noncanonical diagnostic order.

A source location contains only a locked-pack authority label and digest, a
canonical pack-relative document path, the captured source's exact byte length,
and a range within that length. Host paths are neither accepted nor persisted.
The captured source length is limited to 1 MiB. Output ranges must also have
`start <= end`.

One transform retains at most 1,024 resources and 256 diagnostics. One
diagnostic retains at most 64 notes. Each message or note is at most 16 KiB,
and all diagnostic message and note text for one transform totals at most 1
MiB. Transform provenance is copied into the generation and participates in
both prepared-record and generation identities. Policy findings remain the
separate approval projection of successful diagnostics.

### Target observations and operations

A target observation binds its authority and relative path, the traversal
anchor, existing ancestor and parent identities, and whether the leaf was
absent or present. A present identity includes owner, group, mode, link count,
size, mtime, and ctime. `missing_ancestors` records a trailing suffix of absent
parent segments; such an observation requires an absent leaf and matching
traversal shape. Its canonical zero value is omitted.

The closed operation set is:

- `ensure-directory`.
- `place-file`.
- `place-symlink` for a canonical safe-relative-symlink object.
- `place-tree`, with optional archive payload and decoder provenance.
- `remove-leaf`.
- `assert-absent`.
- `assert-exact`.

Readers reject contradictory leaf type, conflict, replacement, artifact, and
mode semantics before an operation becomes part of a content-addressed record.
File and directory modes contain only permission bits. Files remain
owner-readable; directories remain owner-readable and owner-searchable.
Operations at one destination are unique, and disallowed ancestor/descendant
destination combinations are rejected.

`remove-leaf` is idempotent when an owned target is already absent. Ordinary
directory removal is limited to an observed empty directory. A previously
managed canonical tree is instead verified recursively before its nonempty root
enters the same journaled backup transition.

When a managed directory contains effective managed descendants, a transition
removes those descendants and releases ownership of the directory without
unlinking the structural container. This preserves unmanaged siblings and lets
disable and removal transitions finish without treating the parent as an
independently empty leaf.

`assert-absent` binds absence. `assert-exact` binds an unchanged present target
and all canonical object identities without mutating the target. A mutation
manifest that has a missing, extra, wrong-kind, or wrong-artifact operation is
rejected. Artifact identity, byte length, and mode must all match the required
mutation.

### Desired snapshots and transitions

Target slots are strictly ordered by authority and path. A slot records its
authority, relative path, closed kind (`file`, `directory`, `symlink`, or
`tree`), and present or absent state. Present files bind digest, exact byte
length, and mode. Present directories bind mode. Present symlinks bind their
canonical object digest. Present trees bind their canonical root and optional
archive payload and decoder provenance.

Normal reconciliation is cumulative. Every predecessor slot remains in the
next snapshot or becomes a tombstone of the same kind, and newly evaluated
declarations are merged with those tombstones. Lifecycle transitions may
instead select an exact retained snapshot or the required empty snapshot.

Before publication, predecessor and successor snapshots determine the exact
required target mutations without further filesystem access. The observed
operation manifest must agree with those mutations and with the expected
predecessor, namespace, desired digest, transition kind, selected restore point,
and retention authority.

The closed transitions have these requirements:

| Transition | Required state change |
| --- | --- |
| `reconcile` | Publishes an enabled generation with no selected restore point and preserves cumulative slots. |
| `disable` | Starts from enabled state, removes every formerly effective target, publishes disabled state with an empty snapshot and no active tracking, and retains the prior enabled generation as the exact selected restore point. |
| `enable` | Starts from disabled state and appends a new enabled generation that exactly restores the selected retained generation, including its snapshot and tracking. It never moves the catalog head backward. |
| `checkout` | Starts from a selected current head, appends the selected retained state, and preserves same-kind tombstones for current slots absent from the source generation. |
| `retention-authority` | Requires a predecessor and changes only retention authority, not selected lifecycle, restore point, tracked root, or desired snapshot. |
| `namespace-removal` | Requires a selected predecessor, reconciles to disabled empty state with no selected restore point or tracking, carries the predecessor's retention authority in the prepared record, explicitly uses the closed `drop` history disposition, and is the only transition that removes a catalog head without publishing a generation. |

There is no `removed` lifecycle generation.

The desired-snapshot digest is SHA-256 over
`malm-desired-snapshot-v1\0`, the length-framed namespace, and the
length-framed canonical snapshot JSON. Readers recompute it.

### Policy binding

Findings supplied by a prepare request are additive. After all target
observations are captured, Engine adds a mandatory approval-required
`replace-existing` finding for each replacement whose leaf is present and a
mandatory approval-required `remove-existing` finding for each removal whose
leaf is present. These findings identify only the logical authority and relative
path.

An absent replacement or removal receives no generic destructive finding. If a
leaf observed absent appears before commit, commit rejects stale state rather
than replacing or removing it. Callers and transforms cannot suppress mandatory
findings. Unsafe ownership, links, target kinds, state overlap, corruption, and
missing authority are hard errors, not approvable findings.

A finding ID is SHA-256 over `malm-policy-finding-v1\0`, the length-framed
code and message bytes, and one approval-required byte. Findings are sorted by
ID, and exact duplicate IDs are rejected. The approval digest is SHA-256 over
`malm-plan-approval-v1\0` followed by the length-framed IDs of
approval-required findings in that order. Commit accepts only this persisted
binding and never reevaluates findings.

### Blobs and canonical objects

Artifact bytes live at `objects/blobs/sha256-<64 lowercase hex digits>`. One
blob is limited to 256 MiB, and one plan may reference at most 256 MiB of unique
blob bytes. Artifact IDs that share a digest are loaded and published only
once.

Prepare publishes synced unnamed blob files without replacement. Every
referenced blob is durable before the prepared record is linked. A crash may
therefore leave an unreferenced durable blob, but it cannot expose a prepared
record whose required blob was not first made durable. `maintenance.lock`
prevents publication from racing reference-aware retention.

Canonical file, symlink, and tree objects live under `objects/files`,
`objects/symlinks`, and `objects/trees`, with the same private-container and
immutable-entry metadata. While holding `maintenance.lock`, prepared
publication re-verifies each referenced symlink target and each complete tree
closure so retention cannot remove an object between preflight and record
publication.

## Namespace state

### Generations and catalog

Immutable generations live at
`state/generations/sha256-<64 lowercase hex digits>`. Their identity is the
SHA-256 of canonical compact JSON including its final LF. A generation is
limited to 4 MiB, uses version 1, rejects unknown fields and noncanonical bytes,
and must match its filename digest.

Each generation binds `namespace`, committed `plan_id`, optional
`previous_generation`, `transition`, `lifecycle`, optional selected
`restore_point`, complete `retention`, optional `tracked_root`, complete
`desired_snapshot` and digest, artifact ownership, and complete transform
provenance. These values are copied only from the prepared record that creates
the generation. Operations never derive or replace them.

Live commit independently rebuilds the transition from the prepared record and
exact predecessor, attesting all copied fields, the lifecycle-aware operation
manifest, and artifacts. `namespace-removal` cannot produce a generation.

`state/catalog.json` is the canonical mode-`0600` authority for independent
namespace heads. It contains at most 4,096 `NamespaceHeadV1` entries. Heads are
strictly sorted and unique by namespace. A namespace matches
`[A-Za-z0-9_-]+` and is at most 128 bytes; each head binds one full generation
digest.

Catalog readers cap canonical bytes at 4 MiB, reject missing or unknown fields,
malformed identifiers, unsupported versions, duplicates, noncanonical order,
and noncanonical JSON. The catalog digest is SHA-256 over the exact compact JSON
bytes including the final LF.

### Lifecycle, restore points, and history

`LifecycleStateV1` is closed to `enabled` and `disabled`. A disabled selected
generation has an empty desired snapshot, no active tracking, and an exact
restore point for its prior enabled generation. It contributes no ownership.
Re-enabling appends a generation restored from that immutable point. Namespace
removal deletes only that namespace's catalog head.

Prior links form one bounded retained generation chain per catalog namespace.
The history count is in `1..=65536` and defaults to 256 when constructing new
authority. The value is mandatory in canonical persisted records; readers do
not supply that constructor default. Once verified pruning removes history
below that floor, the floor generation's content-addressed predecessor remains
as a weak historical identity. The floor's copied authority is then verified
directly against its retained prepared record without requiring the removed
predecessor.

One retention authority contains at most 4,096 restore points and 16,384
explicit pins. Restore points are strictly ordered and unique by generation;
pins are strictly ordered and unique. A disabled generation's selected restore
point must occur exactly in its retention authority.

### Tracked roots

`TrackedRootV1` is an embedded version 1 record. It binds:

- A canonical credential-free HTTPS `source_locator`, limited to 2,048 bytes.
- A symbolic `moving_selector`, limited to 1,024 bytes. It cannot be an exact
  revision.
- A full lowercase hexadecimal `applied_revision`: `sha1-` plus 40 digits or
  `sha256-` plus 64 digits.
- A SHA-256 `root_tree_digest`.
- A canonical root-relative `source_subdir`, limited to 1,024 bytes and allowed
  to be `.`. Canonical JSON omits this field when its value is `.`.
- A root-relative `config_entry_point`, limited to 1,024 bytes.
- The resolved `selected_profile` and complete persisted `acquisition_grants`.

Grant kinds are closed to `local-source`, `git-source`, `format-component`, and
`target-authority`. Grants are strictly sorted and unique by kind and locator.
One tracked root has at most 8,192 grants, each locator is at most 4,096 bytes,
and aggregate locator text is at most 4 MiB.

Locators are credential-free logical authority. Git executables, scratch paths,
credentials, and other host capabilities are never persisted. A prepared plan
always supplies the complete optional `tracked_root`: repeating it preserves
tracking, a different value replaces tracking, and `null` clears tracking.
Generation derivation never infers that choice from the predecessor.

### Derived ownership and catalog admission

Each present target in an enabled catalog-selected generation contributes one
transient ownership claim. The projection is capped at 4,096 selected
generations, 131,072 total target slots, 64 target authorities, and 65,536
present claims. It deterministically rejects duplicate namespace selections,
namespace mismatches, exact cross-namespace path conflicts, and
path-component ancestor/descendant conflicts. Lexical prefixes such as `a` and
`a-b` do not conflict.

Commit pins every required target authority and rejects nested or bind-mounted
authority aliases, including same-filesystem aliases proved by mount ID.
Prepare checks the current projection before publishing any blob or plan.
Commit recomputes it under `transaction.lock`, so an unrelated namespace
advance does not stale a plan unless it creates an ownership conflict. Missing
authority mappings fail closed.

Catalog admission traverses each selected predecessor chain through its
configured history bound and allows at most 65,536 generations across the
catalog. It verifies each retained generation, namespace edge, committed plan,
and derived transition. The retained floor is verified against prepared
authority without requiring an intentionally pruned predecessor.

Missing non-floor edges, cycles, cross-namespace histories, and records not
derived from their plans block inspection and mutation. Readers never fall back
to reconstructing authority from a directory scan.

## Transactions and recovery

### Journal authority and wire form

An in-progress commit owns `transaction.lock` and publishes the canonical
mode-`0600` journal at `transactions/current.json` before the first target
mutation. Its canonical compact JSON ends in one LF and contains:

- `schema_version`, fixed at 1.
- The affected `namespace` and exact prepared `plan_id`.
- `previous_catalog` and `next_catalog` digests.
- Optional `previous_generation` and `next_generation` digests.
- One ordered journal operation for every prepared operation.

Only `namespace-removal` has `next_generation: null`; its next catalog omits the
reviewed namespace head. The previous and next catalog digests must differ, and
the catalog transition may change only the journaled namespace.

Each journal operation records optional `created_identity` and optional
`backup`. A backup has a monotonic closed state:

- `intent` is durable before the backup rename. It carries the stable SHA-256
  of a regular-file source; non-regular sources carry `null`.
- `identified` is published after rename and parent-directory sync. It carries
  the exact relocated prepared-source identity and retains the same optional
  source digest.

The old `backup_identity` shape is rejected rather than migrated. The valid
[journal fixture](fixtures/valid/transaction-journal.json) illustrates the
wire form and phases, but it is not a complete plan-derived transaction.

Readers cap each current or staged journal at 56 MiB and deserialize at most
65,536 operations before allocating an attacker-selected unbounded sequence.
They reject missing or unknown fields, unsupported versions, noncanonical
bytes, illegal phase progressions, changed immutable transaction fields,
operation states inconsistent with the prepared plan, and next generations not
derived from that plan.

### Durable journal updates

A journal update is written and synced as an unnamed complete file, linked at
`transactions/.current.json.update`, and atomically exchanged with the pinned
`current.json` inode. Both sides and their bytes are verified after exchange.
The prior version is removed only after that verification, and the transaction
directory is synced. A remaining `.current.json.new` entry is invalid.

Loading never promotes a staged update. The loader validates canonical bytes
and monotonic per-operation progression to distinguish a pre-exchange candidate
from a post-exchange previous version. A candidate is cleaned by durably
removing the prior current journal before the candidate. A post-exchange
previous version is removed before the authoritative current journal. An
update-only crash state is revalidated and resumed rather than promoted.

### Target publication

Target mutation uses pinned descriptor-relative beneath and no-follow
operations. Replacement and removal backups, staging names, and cleanup
quarantine names derive from the full plan digest and operation index.

Regular files and mutable store-control files remain unnamed until their
complete bytes and identities are durable. Symlinks are staged as exact
no-follow link inodes. Trees are recursively materialized beneath a private
staging root only from a fully verified canonical closure, using independent
regular files rather than hard links, and are atomically renamed at the managed
root.

Mutable journal and catalog replacement uses pinned exchange plus byte and
binding verification. If the source or destination is substituted, the
implementation restores or retains it fail-closed rather than silently
discarding it.

### Recovery decision and sequence

Recovery first validates the prepared plan, exact catalog transition, legal
journal phase progression, immutable prepared-source identities, canonical
objects, and exact target content and semantics. Structurally forged or
non-plan-equivalent canonical journals are rejected. Recovery never re-resolves
source, config, graph, policy, assets, or format components.

If the catalog still has `previous_catalog`, recovery rolls operations back in
reverse order and retains the previous catalog. If the catalog has
`next_catalog`, every operation must be in its complete roll-forward phase;
recovery verifies the exact prepared state and removes validated backups
through transaction quarantine. A catalog matching neither exact digest is an
error.

During rollback only, an intent-phase backup may be restored when it matches
the immutable prepared leaf under relocation-stable identity fields and, for a
regular file, the durable pre-rename source digest. Backup cleanup and
roll-forward always require the exact identified post-rename identity.

If a rename captures a concurrently substituted inode, live commit pins and
restores that same inode, then returns stale. A crash before restoration
finishes retains the intent journal and fails closed. Arbitrary raced identities
are never persisted as recovery authority.

### Fail-closed limits

Linux cannot create an unnamed directory or atomically journal the new inode
number produced by `mkdir`. A crash after a directory staging inode becomes
named but before its identity update is durable therefore fails closed:
recovery preserves the entry and journal and requires explicit intervention.
It never guesses ownership from a reserved name or deletes unidentified target
content.

Replacement and removal backup windows use durable intent plus the prepared
source identity and recover automatically. Every boundary after durable
identity publication recovers to the previous or exact prepared state.

The effective user and private final store are trusted publication authority,
not a cryptographic authenticity boundary against another malicious process
with the same UID. Cleanup quarantine entries are pinned and checked
immediately before `unlinkat`. Linux has no atomic compare-inode-and-unlink
operation, so excluding substitution in that final syscall interval requires
exclusive namespace authority or non-removing cleanup.

## Retention

Retention accepts an explicit set of prepared plan identifiers; sweep mode may
also select every plan outside the retained closure. It holds both
`transaction.lock` and `maintenance.lock`, refuses to run while any recovery
journal exists, and rejects removal of a plan selected by retained authority.

The retained roots are:

- Every catalog head through that generation's configured bounded history.
- Every exact restore-point generation.
- Explicit prepared-plan, generation, blob, pack, canonical-file,
  canonical-symlink, and canonical-tree pins.
- Prepared plans not selected for deletion.
- Every blob, pack, canonical object, and tree closure reachable from those
  plans and generations, including deduplicated pack member blobs.

The current journal is excluded by refusing to prune until recovery completes.
Pack, canonical-object, blob, and prepared-record publication take the shared
maintenance exclusion, so a newly published root cannot race reachability. New
restore points and explicit pins, including all their prepared, generation,
blob, pack, canonical, and tree closures, are reverified while that exclusion
is held and again under transaction exclusion before commit.

Before deletion, retention validates enumerated prepared records, generations,
blobs, pack representations, and canonical file, symlink, and tree objects. It
then removes selected plans and verified immutable objects unreachable from
retained authority. A deduplicated retained pack also retains and length-checks
every referenced member blob.

Generation removal proceeds newest-to-oldest and syncs every removal. A
retained floor's predecessor edge becomes weak only after that predecessor is
durably gone. A crash may leak an unreachable immutable object, but it cannot
remove a live or recoverable object.

Retention deduplicates blob verification, bounds an enumerated store directory
to 1,000,000 entries, and applies a 512 MiB aggregate work budget to decoded
prepared records, generations, pack manifests, and verified canonical object
bytes.

## Fixture conformance

All JSON record fixtures include their final LF. Golden prepared and generation
records are linked: the generation is derived from the prepared record. The
golden catalog names both fixture generations, while the valid catalog names
the minimal generation. Ownership and target-lock records have no fixtures
because they are derived or transient, not persisted authority.

| Record | Accepted fixture | Golden bytes and identity | Required rejection coverage | Conformance code |
| --- | --- | --- | --- | --- |
| Prepared record | [`valid/prepared-record.json`](fixtures/valid/prepared-record.json) | [`golden/prepared-record.json`](fixtures/golden/prepared-record.json), [`golden/digests.json`](fixtures/golden/digests.json) | `malformed/prepared-record-*`, `unsupported/prepared-record-*` | `malm-store/tests/contracts.rs` |
| State generation | [`valid/state-generation.json`](fixtures/valid/state-generation.json) | [`golden/state-generation.json`](fixtures/golden/state-generation.json), [`golden/digests.json`](fixtures/golden/digests.json) | `malformed/state-generation-*`, `unsupported/state-generation-*` | `malm-store/tests/contracts.rs` |
| State catalog | [`valid/state-catalog.json`](fixtures/valid/state-catalog.json) | [`golden/state-catalog.json`](fixtures/golden/state-catalog.json), [`golden/digests.json`](fixtures/golden/digests.json) | `malformed/state-catalog-*`, `unsupported/state-catalog-version-2.json` | `malm-store/tests/contracts.rs` |
| Transaction journal | [`valid/transaction-journal.json`](fixtures/valid/transaction-journal.json) | [`golden/transaction-journal.json`](fixtures/golden/transaction-journal.json) | `malformed/transaction-journal-*`, `unsupported/transaction-journal-version-2.json` | Private `malm-commit` codec tests |

Strict readers must reject every corresponding malformed and unsupported
fixture rather than ignoring fields, applying defaults not defined by the
canonical codec, or importing an older record shape.
