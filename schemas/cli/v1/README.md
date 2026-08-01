# Malm CLI JSON envelope (`cli/v1`)

`cli/v1` is the structured output envelope for normal human-facing commands run
with `--format json`. Shell scripts that invoke one command and consume one
result or error should use this contract. Process integrations that need a
request protocol, correlation IDs, and typed operations should use
[`machine/v1`](../../machine/v1/README.md) instead.

`--help` remains human-readable help and is not `cli/v1` output. The `malm
machine` command also uses only `machine/v1`, not this envelope.

## Output channels and framing

On success, Malm writes one UTF-8 JSON object followed by one LF byte to stdout.
On failure, it leaves stdout empty and writes one UTF-8 error object followed by
one LF byte to stderr. JSON mode emits no prompts, progress, ANSI styling, or
unstructured advice.

## Envelope shape

Every envelope is a closed object. Unknown envelope fields are rejected.

| Field | Success | Failure |
| --- | --- | --- |
| `schema_version` | Exactly `1` | Exactly `1` |
| `command` | Stable command name | Stable command name, or `malm` for argument parsing errors |
| `outcome` | Non-`error` success value | Exactly `error` |
| `data` | Command-specific object | `null` |
| `diagnostics` | Array of 0 through 256 diagnostics | Array of 0 through 256 diagnostics |
| `error` | Absent | Required closed error object |

`command` contains 1 through 128 characters and matches
`^[a-z]+(?:[.-][a-z]+)*(?:\.[a-z]+(?:[.-][a-z]+)*)*$`. A successful `outcome`
contains at most 64 characters, matches `^[a-z][a-z0-9_]*$`, and must not equal
`error`. The envelope schema deliberately types successful `data` only as an
object; the selected command defines that object's fields.

Each diagnostic is a closed object with `severity`, `code`, and `message`:

- `severity` is `error`, `warning`, or `notice`.
- `code` starts with a lowercase ASCII letter, then contains only lowercase
  ASCII letters, digits, or `-`, and is at most 64 characters.
- `message` is at most 8,192 characters.

The failure-only `error` object contains `category`, `code`, `message`, and
`help`. `category` is one of `invalid_request`, `unsupported`, `not_found`,
`permission_denied`, `conflict`, `resource_limit`, `unavailable`, or `internal`.
`code` has the same lexical profile and 64-character limit as a diagnostic code.
`message` is at most 8,192 characters. `help` is either `null` or a string of at
most 8,192 characters. Messages and help are human-readable text, not fields to
parse for compatibility decisions.

When target preparation finds occupied directory leaves that must be moved or
removed, the failure remains category `conflict` with code `unsafe-target` and
`data` remains `null`. Its `diagnostics` contains one error diagnostic per
retained absolute path, up to the envelope limit of 256, using code
`directory-occupancy-conflict`. The primary message reports the total conflict
count and the number of additional omitted paths.

JSON Schema length limits count Unicode characters. Implementations must also
produce valid UTF-8 and the output framing described above.

## Identities

Structured identity fields always contain complete canonical IDs, such as
`pp-...` or `sha256-...`. A command may accept a typed short selector, but the
envelope never substitutes that selector for a structured identity. Rejected
selector text may appear in the human-readable error `message`; clients must not
parse that message as an identity field.

## Compatibility

`cli/v1` requires `schema_version: 1`. An incompatible change to the envelope
requires a new CLI JSON version. Command names, success outcomes, and
command-specific `data` remain part of the selected command's contract rather
than a process request protocol.

## Contract files

| File | Purpose |
| --- | --- |
| [`envelope.schema.json`](envelope.schema.json) | Draft 2020-12 envelope validation |
| [`fixtures/`](fixtures/) | Golden, valid, malformed, and unsupported examples |
| [CLI guide](../../../docs/cli.md) | Commands, arguments, and scripting workflow |
| [`machine/v1`](../../machine/v1/README.md) | Correlated process request protocol |
