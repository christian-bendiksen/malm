# Canonical rich intermediate representation (`config/v1`)

The `config/v1` rich IR is Malm's sole pure semantic layer for lower-level rich
configuration. Evaluator, engine, embedded-API, and format-transform
implementers use it after source parsing and before any effectful preparation or
publication. The [rich KDL grammar](rich-grammar.md) is one input adapter; any
other adapter must construct the same closed declarations, preserve the same
semantic order, and pass the same validation and limits.

There is no predecessor parser, fallback document kind, or ambient input in this
contract.

## Terms

A **`ContributionName`** is 1 to 63 ASCII bytes. It starts with a lowercase
letter; every remaining byte is a lowercase letter, digit, or hyphen. An
**authority** is the exact pair of a `ContributionName` authority label and its
locked pack digest. A **document ID** is an exact `(authority label, authority
digest, PackPath)` tuple. A **captured document** combines one document ID, its
exact bytes and SHA-256 digest, resolved composition edges, and a validated
semantic body.

A **source range** is a half-open byte range `[start, end)` in one captured
document. A **value path** is a nonempty sequence of record or collection keys.
A **canonical order** is ascending validated string order, which is also UTF-8
byte order for these strings. Lists and explicit composition vectors instead
retain semantic declaration order.

## Evaluation boundary

Low-level evaluation receives exactly:

- one captured-document entry ID;
- one finite captured authority graph and captured document set;
- one canonical name-sorted map of explicitly supplied typed variables.

`ParsedRichConfigSetV1::evaluate` additionally receives an optional selected
profile. If the caller supplies one, it wins. Otherwise the entry source's
`default-profile` selects the profile; evaluation fails if neither exists.

The evaluator has no callback for opening a path, reading an environment
variable, fetching a URL, running a process, reading a clock, obtaining
randomness, observing a terminal or target, or consulting state. Captured bytes
are retained and digested for provenance, but evaluation uses only validated
declarations and never infers declarations by rereading provenance bytes.

## Authority and captured-set admission

The authority graph has one declared root and a canonical map of exact
authorities. Every authority label and identity is unique. Every dependency
alias is unique within its source authority and names another exact authority in
the graph. The complete graph must be acyclic, and every supplied authority must
be reachable from the root. Module paths are unique, config-document paths are
unique, and any one pack path may serve only one role; the two sets cannot
overlap.

An include without `dependency` resolves within its source authority. An
include with `dependency` resolves within that source authority's named direct
dependency. A module follows the same scope rule and then resolves its declared
export name to a path. The resolved path must be declared by the exact selected
pack. An edge is rejected if it forges the expected authority, digest, path,
dependency alias, or module export.

Every captured document must claim an authority in the graph. Document IDs are
unique. Direct targets within one document are unique, including across include
and module edge kinds. Per-document bytes and edge counts, aggregate captured
bytes, aggregate edges, and document counts are bounded before evaluation.

## Include and module composition

The entry must belong to the locked root authority and must be captured.
Depth-first traversal visits each document's resolved edges in semantic order,
visits each target before appending its source document to evaluation order, and
evaluates each document at most once. A shared target in a diamond therefore
contributes one body. Within parsed KDL, all written includes precede all written
modules in the edge sequence, while each section retains its internal order.

Missing targets, cycles, excessive depth, invalid source ranges, or any captured
document unreachable from the entry are hard errors. An unreachable supplied
document is not ignored and confers no authority; the complete captured set is
rejected.

Every traversed edge produces ordered `IncludeProvenanceV1` containing its
source document and range, resolved target document ID and digest, optional
dependency alias, and edge kind. This vector is part of canonical typed-document
identity, so reversing semantically ordered edges can change the digest even
when the root value is unchanged.

## Types and canonical values

The scalar value kinds are:

- null;
- boolean;
- signed 64-bit integer;
- unsigned 64-bit integer;
- finite normalized IEEE-754 binary64 float;
- bounded UTF-8 string;
- validated target-relative path.

Negative zero is normalized to positive zero. NaN and infinities cannot enter
the model. Integer, unsigned, and float values remain distinct and are never
implicitly coerced.

The aggregate kinds are:

- a recursively typed list, retaining item order;
- a closed record, stored in canonical key order;
- a keyed recursively typed collection, stored in canonical key order.

A list or collection schema has exactly one item type, and every item must
conform to it. A record schema rejects undeclared fields. For each declared
field, resolution uses an explicitly present value first, otherwise a declared
default, otherwise typed null for an optional field, and otherwise fails for a
missing required field. A present null is valid only when that field is
optional; it does not trigger the default. Null cannot inhabit a required field
or a list or collection item during schema conformance. Record defaults are
resolved recursively when the schema is built.

Types and values are independently checked for recursive depth, aggregate item
count, total node count, key size, string size, and target-path validity.

`CanonicalTypedDocumentV1` has IR version 1 and always has a record root. It may
also contain a canonical map of source document identities, an ordered include
provenance vector, and a canonical map from value paths to ordered provenance
records. Construction rejects a non-record root, unsupported version, invalid
source references or ranges, mismatched include target digests, unordered or
duplicate provenance sequences, and every applicable limit. Its exact binary
identity is defined in [canonical.md](canonical.md).

## Variables

Each variable has one `RichNameV1`, one closed type, one source range, and one of
these declaration modes:

- required input;
- optional input;
- defaulted input;
- optional defaulted input;
- computed `let` value.

Variable names are globally unique across the reachable closure. Supplied names
may target only declared inputs. An unknown supplied name, a supplied computed
variable, or an invalid supplied value is rejected. A missing required input
fails. A missing optional input without a default resolves to typed null.

Defaults and computed expressions may reference variables declared in any
reachable document. Resolution follows those dependencies, caches each result,
and rejects unknown references and cycles. Independent variable roots are
started in canonical name order. Every result is conformed recursively to its
declared type.

`RichEvaluationV1::variables` is a canonical name-sorted map. Each resolved
variable includes provenance identifying whether its value was supplied,
defaulted, absent optional, or computed. This variable-result map is returned by
evaluation, but it is not a separate field in `CanonicalTypedDocumentV1`; the
effects of variables that reach emitted values are represented by the root
value and document contribution provenance.

## Expressions and conditions

Expressions are limited to typed literals, variable or lexical-loop references,
list construction, record construction, keyed-collection construction,
record/collection key selection, and conditional selection. Lists evaluate in
written order. Record and collection expressions evaluate in canonical key
order. Selection rejects a non-record or non-collection value and a missing key.
Only the selected branch of a conditional expression is evaluated.

Conditions are explicit boolean tests, set/null tests, exact typed equality or
inequality, negation, `all`, and `any`. No value has implicit truthiness.
`is-set` is false only for null. `all` and `any` short circuit in written order;
an empty `all` is true and an empty `any` is false.

Expression and condition structure is preflighted before execution. Nesting,
aggregate terms, literal values, and total expression-node work are bounded.
Runtime expression and condition evaluation also consumes the global
deterministic work budget.

## Profiles, slots, and desired outputs

Parsed workspace evaluation first collects all reachable profile and slot
declarations into globally unique canonical maps. It validates every profile's
parent references, duplicate parents, inheritance depth, and cycles before
selection, including profiles outside the selected inheritance closure.

An abstract profile may be inherited but cannot be selected. Effective profile
order is a depth-first traversal of each parent's written order. Each ancestor
is emitted once after its own parents, followed by the selected profile. Profile
statements and outputs retain that effective order. Base document statements
from include composition execute before effective profile statements.

Each selected output may name one globally declared slot. The evaluator records
providers in effective profile and output declaration order and rejects a
provider after the slot's declared maximum has been reached. A missing slot is
an error.

Desired outputs are returned in a name-sorted `DesiredOutputSetV1`. Names must
be unique across the effective profile closure; inherited declarations do not
override one another. Destinations are validated target-relative paths, must be
unique, and cannot have an ancestor or descendant overlap.

The five desired-output kinds are:

- a regular file binding an exact pack-file reference and executable bit;
- a symlink containing a bounded safe relative slash path;
- a canonical tree binding one exact tree digest;
- a decoded archive binding an exact asset reference, decoder name and `u16`
  version, and expected tree digest;
- a transformed file binding one built-in or exact component selector, sorted
  explicit options and resources, and executable bit.

A pack-file reference binds an exact authority, `PackPath`, manifest resource
kind, raw-byte digest, canonical file-object digest, and byte length. Evaluation
resolves only the authority scope. It does not read, verify, decode, execute, or
store any object. Those operations belong to preparation, where the exact pack
and component identities are checked before publication.

## Statements and fragments

Documents, fragments, and profiles contain ordered statement vectors. A
statement can emit one root field, compose a named fragment, select a
conditional branch, execute a bounded loop, or apply an ordered patch.

`emit` evaluates its expression and inserts one record field at the document
root. Emitting an existing root key is an error. Included document statements
run before including document statements; otherwise statements retain written
order.

Fragments are globally unique and stored by name, while each fragment body
retains statement order. `compose` executes that body at the call site and
records a fragment frame. Unknown fragments, composition cycles, and excessive
composition depth are errors.

`for-each` accepts only a list or keyed collection. Lists bind each value and,
if requested, its unsigned zero-based index. Collections iterate in canonical
key order and bind each value and, if requested, its string key. `for-range`
iterates inclusive signed integers and requires `from <= through`. A loop's key
and value bindings must differ, and nested loops cannot shadow any enclosing
loop binding. The complete iteration count is checked before body execution;
both per-loop and aggregate iteration counts are bounded.

Every statement and expression consumes a global deterministic work unit at its
defined evaluation point. Loop expansion cannot bypass the statement, value,
provenance, collection, or work budgets.

## Ordered patch semantics

`OrderedPatchV1` retains its vector order exactly. Later operations observe the
complete result of earlier operations:

- `set` inserts or replaces a root field or a field in an existing record;
- `unset` removes such a field and requires presence unless optional;
- `list-append` requires an existing list and appends one evaluated value;
- collection insert requires an absent key;
- collection replace requires a present key;
- collection remove requires a present key unless optional;
- collection replace-all requires an existing collection and replaces all of
  its contents with the evaluated canonical key map.

Intermediate path traversal may cross records or collections, but the parent of
`set` and `unset` must be a record. Dynamic collection keys must evaluate to
bounded strings valid as `RichKeyV1`. Every operation rechecks collection,
value, path, work, and provenance limits. A failed operation publishes no
successful result.

## Diagnostics and provenance

A rich diagnostic contains a severity, stable lowercase `RichNameV1` code,
bounded UTF-8 message, optional primary source or transform-output location,
and bounded notes. Diagnostic vectors are sorted by the complete structured
diagnostic tuple and must not contain duplicates. This makes caller insertion
order and map traversal irrelevant.

Evaluation failures are structured diagnostics, not partial documents. Source
locations bind an exact document ID and half-open range and must remain within
the captured byte length. Diagnostic counts, message and note bytes, notes per
diagnostic, and aggregate text are independently bounded.

Successful evaluation records every reachable document digest and every
validated include or module edge. Each document contribution from `emit` or a
patch is keyed by canonical value path and contains a globally unique monotonic
sequence number, exact source location, operation, and current fragment,
conditional-branch, and loop frames. Records for one path must be in strictly
increasing sequence order.

An unset or collection removal records the removed path even though no value
remains there. This tombstone keeps the deletion explainable. Collection
replace-all removes stale descendant provenance and records the replacement at
the collection path.

## Fixed limits

The public `MAX_RICH_*` constants and the related source, path, diagnostic, and
canonical-byte constants are part of this versioned contract. A limit is
inclusive: a value equal to the maximum is admitted unless another rule rejects
it.

### Source and graph limits

| Constant | Maximum |
| --- | ---: |
| `MAX_CONFIG_DOCUMENT_BYTES` | 1,048,576 bytes |
| `MAX_CONFIG_NESTING_DEPTH` | 64 levels |
| `MAX_CONFIG_COMMENT_NESTING_DEPTH` | 64 levels |
| `MAX_RICH_DOCUMENTS` | 1,024 documents |
| `MAX_RICH_AUTHORITIES` | 4,096 exact authorities |
| `MAX_RICH_INCLUDES_PER_DOCUMENT` | 1,024 edges |
| `MAX_RICH_TOTAL_INCLUDES` | 16,384 edges |
| `MAX_RICH_INCLUDE_DEPTH` | 64 documents |
| `MAX_RICH_TOTAL_CAPTURED_BYTES` | 67,108,864 bytes |

### Names, values, and declarations

| Constant | Maximum |
| --- | ---: |
| `MAX_RICH_NAME_BYTES` | 128 bytes |
| `MAX_RICH_KEY_BYTES` | 1,024 bytes |
| `MAX_RICH_TEXT_BYTES` | 1,048,576 bytes per string |
| `MAX_TARGET_PATH_BYTES` | 4,096 bytes |
| `MAX_TARGET_PATH_SEGMENTS` | 64 segments |
| `MAX_RICH_VALUE_DEPTH` | 64 type, value, expression, statement, fragment, path, or provenance-frame levels where applicable |
| `MAX_RICH_COLLECTION_ITEMS` | 16,384 items in one list, record, collection, replacement, or condition term vector where applicable |
| `MAX_RICH_TOTAL_VALUES` | 262,144 values from one root, or 262,144 nodes in one validated type schema |
| `MAX_RICH_VARIABLES` | 4,096 variables |
| `MAX_RICH_FRAGMENTS` | 4,096 fragments |
| `MAX_RICH_PROFILES` | 4,096 profiles |
| `MAX_RICH_PROFILE_PARENTS` | 64 direct parents per profile |
| `MAX_RICH_PROFILE_DEPTH` | 64 inheritance levels |
| `MAX_RICH_SLOTS` | 1,024 slots |
| `MAX_RICH_SLOT_PROVIDERS` | 1,024 providers permitted by one slot |
| `MAX_RICH_OUTPUTS` | 16,384 desired outputs |

### Evaluation, diagnostics, and identity

| Constant | Maximum |
| --- | ---: |
| `MAX_RICH_STATEMENTS` | 262,144 statements and ordered patch steps in one evaluation where applicable |
| `MAX_RICH_LOOP_ITERATIONS` | 4,096 iterations in one loop |
| `MAX_RICH_TOTAL_LOOP_ITERATIONS` | 65,536 iterations in one evaluation |
| `MAX_RICH_EVALUATION_STEPS` | 1,048,576 expression or statement work units |
| `MAX_RICH_PROVENANCE_RECORDS` | 262,144 canonical document provenance records |
| `MAX_RICH_DIAGNOSTICS` | 256 diagnostics |
| `MAX_RICH_DIAGNOSTIC_BYTES` | 16,384 bytes per message or note |
| `MAX_RICH_DIAGNOSTIC_NOTES` | 64 notes per diagnostic |
| `MAX_RICH_TOTAL_DIAGNOSTIC_BYTES` | 1,048,576 aggregate message and note bytes |
| `MAX_CANONICAL_TYPED_DOCUMENT_BYTES` | 67,108,864 encoded bytes |

Captured source bytes, typed values, type schemas, diagnostic text, and the
canonical binary document have independent aggregate limits. Transform-specific
option, resource, and output ceilings are listed in
[transform.md](transform.md#fixed-limits).
