# Architecture

Malm turns configuration source into a saved, reviewable change. It keeps
reading and evaluating source separate from changing managed files.

```text
source pack -> lock -> plan -> review -> apply
                         |                 |
                         v                 v
                    state store <---- recovery
```

The human CLI, the `machine/v1` interface, and Rust embedders use the same
`Engine` for work that reads or changes saved state. Source checking and
rendering can run without opening the state store.

## Source Pack

A source pack is a directory containing `malm-pack.kdl`, configuration files,
and named profiles such as `desktop`. Packs using the lower-level rich
configuration format may refer to other local or Git packs. The authoring format
described in this documentation currently prepares plans from one pack without
dependencies.

Authoring commands can check, render, and inspect a pack directly. This makes
them useful in an editor or CI job even when no Malm state store exists.

## Lock

`malm.lock` records the complete pack graph by exact content and, for Git,
exact commits. Lock creation and update may read explicitly selected local
directories or HTTPS Git repositories. Downloaded pack content is verified and
saved as immutable objects.

A Git dependency in `malm-pack.kdl` already names a full commit ID. Locking
verifies that commit and records the pack content found there. Moving branches
are supported separately by `plan track` and `plan refresh`; they do not make
ordinary pack dependencies move over time.

## Plan

Plan creation loads the locked graph, evaluates the selected profile, verifies
resources, runs any selected format components, and observes the current target
files. It saves the inputs, desired files, target observations, and findings as
an immutable plan. It does not change managed targets.

The saved plan is the handoff between source processing and application.
Switching a saved deployment to another profile also creates a plan from
verified objects already in the store; it does not fetch source again.

## Review

A plan has an exact identifier. Human and automated callers can load that plan,
show its file changes and findings, and approve that exact content. If source or
target observations change, a new plan is needed rather than quietly changing
the reviewed one.

This catches mistakes before mutation. For example, a profile that removes an
unexpected file is visible during review while the target is still untouched.

## Apply

Apply uses only the approved plan and verified local objects. It does not read
the source pack, contact Git, evaluate configuration, decode source archives, or
start WebAssembly.

Before changing files, apply checks that the saved state and target files still
match the plan's observations. A single store-wide lock prevents two Malm
operations from publishing or applying conflicting state at the same time.

Keeping apply small has practical value: a reviewed laptop configuration can be
applied while offline, and a broken source checkout cannot alter an already
approved change.

## State Store And Recovery

The default state root is `$XDG_STATE_HOME/malm`, or
`$HOME/.local/state/malm` when `XDG_STATE_HOME` is unset. Its descriptor marks a
supported Malm store. Plans, pack content, file objects, deployment generations,
and the current head of each namespace live below this root.

One directory outside the state root is also written. Preparing a plan whose
outputs need a format component writes a WebAssembly compile cache to
`$XDG_CACHE_HOME/malm/wasmtime`, or `$HOME/.cache/malm/wasmtime` when
`XDG_CACHE_HOME` is unset. It only speeds up repeated component execution.
Commands that invoke no component do not create it, and it is safe to delete.

Objects are immutable and generations contain complete desired snapshots. This
makes inspection and retention simpler: old generations keep referring to the
exact data they used instead of sharing a mutable copy.

Apply records a durable journal before changing managed files. After a crash,
recovery uses that journal to restore the previous state or finish the approved
state, depending on how far publication progressed. It does not guess from the
current source tree and does not need Git or WebAssembly. A power loss during
apply can therefore be repaired even when the original repository is gone.

Lifecycle and retention changes also use plans, review, and apply. Inspection is
read-only. Cleanup removes objects only when saved state no longer refers to them.

## Crate Layers

```text
CLI and machine adapter       Rust embedder
           \                    /
                 malm-engine
                /           \
       source and prepare   malm-commit
                \           /
          root, store, tree, and types

optional component adapter -> component host and API
```

- `malm-types`, `malm-root`, `malm-tree`, and `malm-store` define shared data,
  paths, saved records, and file identities.
- `malm-pack`, `malm-module-graph`, `malm-config`, `malm-authoring`, and
  `malm-archive` load and evaluate locked source.
- `malm-commit` applies plans, maintains retained generations, and recovers
  interrupted work using only the small storage layer below it.
- The three `malm-format-component-*` crates provide optional WebAssembly
  transforms for plan creation.
- `malm-engine` coordinates the layers. `malm-machine` defines `machine/v1`
  messages, while the root `malm` package contains the CLI and host adapters.

See [Dependency Boundaries](dependency-boundaries.md) for the enforced edges.

## Platform And Security Limits

Full mutation, recovery, and durability support is limited to 64-bit GNU/Linux
on x86_64 and aarch64. Malm trusts the current user and a private state root. It
does not protect against root, another malicious process running as the same
user, injected code, stolen open file descriptors, or a filesystem that lies
about Linux durability operations.

Malm opens directories without following symlinks, keeps handles to checked
directories, checks ownership and permissions, and records changes before
publishing them. WebAssembly components run without WASI or imported host
functions and under fixed memory, time, and output limits.

Linux cannot make every check and the following rename or removal one atomic
operation. Concurrent changes can therefore make Malm stop. A rare crash after
directory creation can also require manual inspection. See the
[recovery CLI guidance](cli.md#recovery-and-cleanup) for recovery commands.

An incompatible nonempty state root is never changed automatically. See
[Clean Reset](clean-reset.md) for that case, [Engine Host Ports](engine-host-ports.md)
for Rust integration, and the [CLI reference](cli.md) for command behavior.
