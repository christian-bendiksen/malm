# Malm rich configuration contract (`config/v1`)

`config/v1` defines Malm's version 1 `rich-config` source language, its pure
evaluation model, the canonical typed result, and the boundary used to format
that result. Configuration and pack authors normally use the higher-level
[authoring guide](../../../docs/authoring-types.md). Parser, evaluator, engine,
and format-component implementers use this directory when they need the exact
lower-level contract.

A `rich-config` document is strict UTF-8 KDL v2. Evaluation combines one entry
document with a finite locked authority graph, captured documents, and explicit
typed variables. It produces a canonical record, source and value provenance,
structured diagnostics, and, when a profile is selected, a desired set of
files, symlinks, trees, archives, or transformed files.

## Processing boundary

The contract has four stages:

1. Parse exact captured bytes and retain each accepted KDL node's half-open byte
   range.
2. Resolve includes, module exports, and pack-file authority scopes only against
   the supplied locked authority graph, while retaining exact component
   selectors for prepare-time admission.
3. Evaluate declarations, expressions, profiles, statements, loops, and patches
   into a `CanonicalTypedDocumentV1` and a bounded desired-output set.
4. Pass that canonical document, explicit options, and declared resource bytes
   through the version 1 format-transform boundary.

Parsing and evaluation have no ambient filesystem, environment, network,
process, clock, randomness, terminal, state, or deployment-target access.
Acquisition supplies captured bytes and authority. Engine adapters perform
object verification, archive decoding, component execution, storage, and
publication after pure evaluation.

## Contract map

| File | Use it to |
| --- | --- |
| [Document grammar](grammar.md) | understand the source envelope, top-level sections, authority references, and output declarations |
| [Complete rich KDL grammar](rich-grammar.md) | implement every type, expression, condition, statement, patch, profile, slot, and output node |
| [Canonical rich IR](rich-ir.md) | implement typed values, include and profile composition, evaluation, diagnostics, provenance, and fixed limits |
| [Canonical identity](canonical.md) | encode and hash the complete typed document and its provenance |
| [Format transform contract](transform.md) | validate, invoke, fingerprint, or implement built-in and component transforms |
| [Fixtures](fixtures/) | inspect accepted KDL, rejected KDL, source digests, typed-document identity, and built-in output goldens |

For Rust integrations, the corresponding implementation surface is the
[`malm-config` crate](../../../crates/malm-config/README.md). To check or render
authoring source, use the [source commands](../../../docs/cli.md#check-or-render-a-pack).

## Compatibility

Version 1 fixes the `rich-config` KDL syntax, typed data model, evaluation and
ordering semantics, limits, canonical identity encoding, and transform
boundary. The `config/v1` decoder accepts exactly `schema-version=1` and does
not fall back to predecessor `config` or `module` document kinds.

The current higher-level authoring language has a separate `config` root and is
dispatched before `config/v1` decoding. That separate language does not make a
`config` root valid input to `decode_rich_config_document_v1`. Any incompatible
change to this contract requires a new version.
