# config/v1 Canonical Rich IR

## Scope

This rich contract is the sole pure configuration semantic layer. The
[rich KDL grammar](rich-grammar.md) is one input adapter. Any embedded API
adapter must provide the same closed declarations, preserve the same semantic
ordering, and pass the same validation and resource limits before evaluation.
There is no predecessor parser or fallback document kind.

Evaluation receives exactly:

- one captured-document entry point;
- a finite captured authority graph and document set;
- a canonical name-sorted map of explicitly supplied typed variables.

Parsed workspace evaluation additionally receives an optional selected profile.
It validates every reachable profile parent and cycle, emits each ancestor once
in written parent order, then applies the selected profile. Abstract profiles
may be inherited but not selected. Slot declarations bound the number of
selected output providers.

There is no callback for opening a path, reading an environment variable,
fetching a URL, running a process, reading a clock, obtaining randomness,
observing a terminal or target, or consulting state. Captured bytes are retained
and digested for provenance. Evaluation uses the validated declarations; it
does not infer declarations from provenance bytes.

## Documents And Includes

A document ID is an exact `(authority label, authority digest, pack path)`
tuple. An include edge names another complete ID and has a source byte range.
Depth-first evaluation processes included bodies before the including body and
evaluates each document at most once, including across diamonds. Include
declaration order is semantic.

Every include target must have exactly the same authority label and digest as
its source. Cross-authority includes fail even when the target bytes were
captured. Missing targets, cycles, duplicate direct targets, excessive depth,
invalid source ranges, and every document/count/byte limit are hard errors.
Documents outside the reachable closure are not evaluated and confer no
authority.

## Types And Values

Scalar values are null, boolean, signed 64-bit integer, unsigned 64-bit integer,
finite normalized IEEE-754 float, bounded UTF-8 string, and validated
target-relative path. Aggregate values are:

- ordered recursively typed lists;
- closed records in canonical key order;
- keyed recursively typed collections in canonical key order.

Record and collection keys use canonical byte ordering. Lists retain declaration
order.
When a value is resolved against a list or collection schema, every item must
match that schema's one item type. Schema-conformed records reject undeclared
fields. Required fields must be present, defaulted fields are materialized
recursively, and absent optional fields materialize as typed null. Null does not
inhabit required fields or collection/list item types. Types and values are
recursively bounded by depth, item, value, key, and text limits. Integers and
floats are not implicitly coerced.

`CanonicalTypedDocumentV1` always has a record root. Its canonical binary form
uses explicit type tags, big-endian fixed-width numbers and lengths, UTF-8 byte
strings, list order, and sorted map order. Record and collection tags are
distinct. Signed zero is normalized and non-finite floats cannot enter the
model. Source-document identities and ordered provenance records are included
in the encoding. SHA-256 over those complete bytes is the typed-document
identity.

## Variables And Expressions

Variables have one declared type and are one of required input, optional input,
defaulted input, optional/defaulted input, or computed value. Supplied values may
target only input variables. Defaults and computed expressions can reference
variables declared in any reachable document. Resolution follows dependencies,
uses canonical name order for independent roots, and rejects cycles or unknown
references.

Expressions contain only literals, variable references, list/record/collection
construction, record/collection key selection, and conditional selection.
Conditions are explicit boolean tests, set/null tests, exact typed equality or
inequality, negation, all, and any. No value has implicit truthiness. `all` and
`any` short circuit in written order.

## Statements, Fragments, Loops, And Patches

Statements emit one root field, compose a named fragment, choose a conditional
branch, run a bounded loop, or apply an ordered patch. Duplicate root emission
is an error. Fragment declarations are name-sorted; composition retains body
order and rejects unknown names, cycles, and excessive depth.

`for-each` accepts only a list or keyed collection. Lists expose an unsigned
index and value; collections expose the canonical string key and value.
Inclusive integer ranges require `from <= through`. Every individual loop and
the aggregate evaluation have fixed iteration limits. Lexical bindings cannot
shadow an enclosing loop binding. Expressions and statements also consume a
global deterministic work budget.

An `OrderedPatchV1` retains its vector order exactly. Operations are record set
or unset, list append, collection insert, replace, remove, or replace-all.
Insert requires absence, replace requires presence, and non-optional removal
requires presence. Later operations observe every earlier result. Dynamic
collection keys must evaluate to bounded strings. Values remain bounded after
mutation.

## Diagnostics And Provenance

Failures contain bounded structured diagnostics with stable lowercase codes,
severity, message, optional exact source/output location, and bounded notes.
Diagnostic vectors are sorted by the complete diagnostic tuple, making caller
insertion or map traversal irrelevant.

Successful evaluation records every reachable document digest, every validated
include edge, each resolved variable origin, and every emit/patch source.
Document provenance is keyed by canonical value path. Each record carries a
monotonic sequence number and its fragment, conditional-branch, and loop frames.
Removal provenance is retained as a tombstone path so a deleted contribution is
still explainable.

Profile evaluation also returns a name-sorted desired-output set. Regular files
reference one exact object digest and execution bit. Symlinks contain a bounded
relative slash path with no empty or dot segments. Canonical trees reference one
tree digest. Decoded archives bind the source archive digest, versioned decoder
name, and expected decoded tree digest. Destinations are target-relative,
unique, and non-overlapping. No declaration reads, verifies, decodes, or stores
an object.

## Fixed Limits

The public `MAX_RICH_*` constants are part of this versioned contract. Important
ceilings include 1,024 documents, 16,384 total include edges, 64
include/profile/type/value levels, 4,096 variables, 4,096 fragments, 4,096
profiles, 1,024 slots, 16,384 desired outputs or items per aggregate, 4,096
iterations per loop, 65,536 aggregate loop iterations, 1,048,576 evaluation
work units, and 262,144 values, statements, or provenance records where applicable. Captured
and canonical byte forms have independent aggregate limits.
