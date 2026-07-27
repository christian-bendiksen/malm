# malm-config

`malm-config` is a Rust library for parsing and evaluating Malm's version 1 rich
configuration language. It is for evaluator implementers and Rust embedders.

KDL is a human-readable, node-oriented document language. This crate accepts
strict `rich-config` KDL as captured bytes. Configuration authors should start
with the [Create a Malm Pack](../../docs/authoring-types.md) and
[`malm-authoring`](../malm-authoring/README.md) instead of this implementation
API.

The crate exists to make evaluation deterministic: every document belongs to an
exact pack label and content digest, and every direct dependency is supplied in
a finite captured graph. Evaluation receives no ambient input.

## Parse

`decode_rich_config_document_v1` parses and validates one captured document.
`ParsedRichConfigSetV1` combines parsed documents with a
`CapturedAuthorityGraphV1`, resolving their declared includes and modules into
a finite `CapturedDocumentSetV1`.

## Evaluate

`evaluate_rich_config_v1` evaluates an entry document using only the captured
documents and supplied typed values. `ParsedRichConfigSetV1::evaluate` adds
profile selection and desired-output evaluation across a parsed set.

## Use Results

`RichEvaluationV1` contains the typed document, diagnostics, and resolved input
information. `CanonicalTypedDocumentV1` and `TypedValueV1` represent typed data;
the canonical byte and digest functions give evaluated data a stable identity.
`EvaluatedRichConfigV1` and `DesiredOutputSetV1` expose selected profile outputs.

## Run Transforms

`FormatTransformV1` defines a pure byte-transform contract.
`TransformRequestV1` and `TransformResponseV1` carry bounded inputs and outputs,
while `run_format_transform_v1` validates and fingerprints an invocation.

## Boundary

Callers supply every document, value, and resource byte. This library parses,
evaluates, and validates transforms; acquisition and deployment I/O remain in
adapters.

See the [config/v1 schema](../../schemas/config/v1/README.md) and the
[crate API](src/lib.rs).
