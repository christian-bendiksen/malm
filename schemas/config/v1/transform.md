# config/v1 Format Transform Contract

## Boundary

Contract version 1 defines one function-shaped semantic boundary:

```text
transform(canonical typed document, explicit typed options,
          declared named resource bytes)
  -> bounded output bytes and structured diagnostics
```

Built-in and component transforms use this same semantic request, response,
identity, diagnostic, and provenance boundary. Every invocation validates the
complete request and transform identity before execution and validates the
complete success or failure response afterward. Canonical JSON, exact plain
text, and flat key/value built-ins are conformance implementations of the same
boundary.

The semantic model is ABI-neutral. It does not define component loading,
authorization, compilation, instantiation, scheduling, or execution. A host
adapter may invoke a component only after enforcing the independent component
admission and runtime profile. There is no native-command, effectful-provider, or
predecessor-ABI compatibility branch in this contract.

## Request

Options are canonical name-sorted typed values. Duplicate names are rejected
before a request exists. Resources contain a canonical name, declared SHA-256
digest, and exact bytes. Request admission and every invocation recompute the
digest and enforce individual and aggregate byte limits. Resource bytes are
never discovered by name.

The request fingerprint binds the contract version, transform name and
implementation version, complete canonical typed-document digest, every sorted
option value, and every sorted resource name, digest, and byte length. A digest
binds each resource's exact bytes. Request and response fingerprints let prepare
persist identities before and after execution.

## Response

A successful response has bounded opaque bytes, a validated ASCII media type,
and strictly ordered unique canonical diagnostics. Error-severity diagnostics
are invalid on success. Source locations must refer to a source document carried
by the input IR, bind that document's exact captured byte length, and remain
within it. Output ranges must be ordered and within the returned bytes.

A failure has one closed failure kind, a bounded message, and diagnostics.
Failure diagnostics cannot refer to output because no successful output exists.
Malformed success and failure values are boundary errors, not transform
failures.

Successful invocation provenance binds the validated transform identity,
request digest, canonical document digest, sorted resource identities, and
response digest. The response digest includes the media type, exact output
bytes, and complete canonical diagnostics.

## Canonical JSON

The `canonical-json` built-in accepts only an optional boolean `pretty` option
and no resources. Records and keyed collections become JSON objects in canonical
key order; lists retain order; null, booleans, signed/unsigned integers, finite
floats, strings, and paths preserve their natural JSON representation. Floats
retain a decimal point or exponent so integer and float values remain textually
distinguishable. Strings use deterministic JSON escaping and output ends in one
newline.

## Plain Text

The `plain-text` built-in selects the root field named by the optional string
`field` option, defaulting to `text`. The selected value must be a string or
path. Exact UTF-8 bytes are returned; optional boolean `trailing-newline`
appends one LF only when the bytes do not already end in LF. Resources are
rejected.

## Key/Value

The `key-value` built-in accepts a flat record of scalar values and an optional
1-to-16-byte non-control `separator`, defaulting to `=`. Fields are emitted in
canonical key order as `key`, separator, value, and LF. Null emits an empty
value; strings and paths deterministically escape backslash and control
characters. Aggregate field values and resources are rejected.
