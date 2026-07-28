# Malm state root contract (`root/v1`)

A **state root** is the private on-disk directory that contains all persistent
Malm state. Root resolvers, store initialization code, and inspection or recovery
tools use `root/v1` to select that directory and admit its top-level layout
without mistaking unrelated, corrupt, or incompatible data for a Malm store.

## Root resolution

Production resolution uses this fixed precedence:

1. If `XDG_STATE_HOME` is set, use `XDG_STATE_HOME/malm`.
2. Otherwise, use `HOME/.local/state/malm`.

The selected environment value must be nonempty, absolute, and already
lexically normalized. A set but invalid `XDG_STATE_HOME` is an error; resolution
must not fall back to `HOME`. When a valid `XDG_STATE_HOME` is present, `HOME` is
not required.

An explicitly supplied root must also be absolute and already lexically
normalized, and it must not itself be a filesystem root. These checks are
lexical: `.` and `..` components, repeated separators, and a trailing separator
that changes the normalized path are rejected rather than resolved.

## Descriptor bytes

The file `descriptor.json` identifies an admitted final root. A strict reader
accepts only the following compact JSON object followed by exactly one LF byte:

```json
{"format":"malm-state","version":1}
```

The complete descriptor is bounded to 4,096 bytes before parsing. The reader
rejects malformed JSON, a non-object top level, duplicate, unknown, or missing
fields, wrong field types, unsupported `format` or `version` values, and every
noncanonical encoding of the otherwise equivalent object. This includes changes
to field order, whitespace, escaping, or the terminal LF. The semantic JSON
Schema cannot express duplicate-key rejection or this exact-byte requirement.

## State-parent admission

The **state parent** is the existing directory that directly contains the final
state root. Malm does not create it. A filesystem adapter must open its absolute
path component by component without following symlinks, pin the resulting
directory chain, and reject a binding that changes during admission.

The state parent must be a directory owned by the current effective user. Its
mode must have no special bits and no group or other write permission. No exact
mode is required; `0700` is the recommended private mode.

## Root admission

The final root must be a directory owned by the current effective user with
exact mode `0700`. An absent root or an existing empty root may be initialized.
A nonempty root without `descriptor.json` is incompatible and must not be
initialized implicitly. Once the descriptor is present, the top-level allowlist
is closed:

| Entry | Required kind | Required mode | Additional checks |
| --- | --- | --- | --- |
| `descriptor.json` | Regular file | `0600` | Current effective user, exactly one link, at most 4,096 bytes, exact canonical bytes |
| `state` | Directory | `0700` | Current effective user |
| `objects` | Directory | `0700` | Current effective user |
| `prepared` | Directory | `0700` | Current effective user |
| `transactions` | Directory | `0700` | Current effective user |
| `transaction.lock` | Regular file | `0600` | Current effective user, exactly one link, empty |
| `maintenance.lock` | Regular file | `0600` | Current effective user, exactly one link, empty |

The entries other than `descriptor.json` are permitted when present; this table
does not require every container or lock to exist at all times. Symlinks and
other filesystem kinds do not satisfy the listed kinds. Modes are exact and
include permission and special-mode bits. Any unknown top-level entry,
incompatible metadata, or change observed while admission is in progress causes
rejection. Rejection must leave the root unchanged, including when the root
contains a predecessor or experimental descriptor.

## Initialization and publication

To create an absent root, build and pin an empty mode-`0700` staging directory
under the state parent, validate it as a final root, and rename it to the final
leaf without replacement. If another initializer wins, discard the staging
directory and admit the winner normally. Never replace or remove the winner.

Publish `descriptor.json` from a fully written, mode-`0600` temporary file. Sync
the file, link it at the final name without replacement, then sync the final
root. If the name already exists, accept it only after complete descriptor and
layout admission. Before initialization reports success, sync the final root
and then the state parent, and revalidate the pinned parent, root, descriptor,
and top-level layout.

## Compatibility

`root/v1` fixes root resolution, descriptor bytes, the top-level allowlist, and
its metadata rules. No predecessor descriptor is accepted. An incompatible
change requires a new root contract version.

## Contract files

| File | Purpose |
| --- | --- |
| [`schema.json`](schema.json) | Structural descriptor validation |
| [`fixtures/`](fixtures/) | Golden, valid, malformed, and unsupported descriptor cases |
| [`malm-root`](../../../crates/malm-root/src/lib.rs) | Pure path, descriptor, and allowlist implementation |
| [Engine root adapter](../../../crates/malm-engine/src/lib.rs) | Filesystem admission and no-replace publication |
| [Store contract](../../store/v1/README.md) | Records and objects below the admitted root |
