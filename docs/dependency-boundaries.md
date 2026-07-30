# Dependency Boundaries

This guide is for contributors changing crate dependencies or moving code
between crates. The split keeps source processing, optional WebAssembly, and
filesystem recovery from becoming one large failure surface.

Arrows below mean "may depend on":

```text
malm CLI
  |---> malm-engine
  |       |---> source and prepare crates
  |       `---> malm-commit ---> malm-root, malm-store, malm-types
  |
  `---> malm-format-component-adapter
          |---> malm-engine
          `---> malm-format-component-host
                    `---> component API and shared types

malm-machine ---> malm-types
```

Rust embedders can use `malm-engine` without the component adapter. The root
`malm` package uses both when a CLI operation may run a format component.

## Layers

The foundation crates have few dependencies and no workflow decisions:

- `malm-types` contains shared identifiers and records.
- `malm-root` handles state-root paths.
- `malm-tree` describes file, symlink, and tree identities.
- `malm-store` describes saved plans and deployment state.
- `malm-pack` describes packs and locks.

Source and prepare build on that foundation:

- `malm-module-graph` assembles a graph from a lock.
- `malm-config` and `malm-authoring` parse and evaluate configuration.
- `malm-archive` decodes declared archives into trees.
- `malm-engine` coordinates acquisition, evaluation, plan storage, review,
  apply, inspection, and maintenance.

WebAssembly stays on an optional side branch:

- `malm-format-component-api` defines component identity and admission data.
- `malm-format-component-host` owns Wasmtime and runs transforms.
- `malm-format-component-adapter` implements Engine's component port.

`malm-machine` contains only `machine/v1` messages. It does not open files,
read the environment, run processes, use the network, or open the state store.

## Why Commit And Recovery Stay Small

`malm-commit`'s only workspace dependencies are `malm-root`, `malm-store`, and
`malm-types`. It also uses external libraries for Linux system calls, JSON,
hashing, and error handling. It does not depend on pack fetching, configuration
parsers, archive decoding, component crates, or Wasmtime.

This lets apply and recovery work from the reviewed plan when the source tree
has moved or the network is unavailable. Recovery after a crash avoids source,
configuration, and archive parsers and Wasmtime, not all parsers; it still
decodes saved JSON records. A bad component can fail plan creation, but it
cannot run while Malm is restoring interrupted filesystem work.

Engine depends on both preparation crates and `malm-commit`, but calls into the
commit layer only with verified saved data. The component adapter points toward
Engine to implement its port; Engine never depends on the adapter or host.

Engine decompresses vendored assets in process, with `lzma-rs` for `tar-xz` and
`flate2` for `tar-gz`. Both are pure Rust and both write through one bounded sink
that stops at the decompressed-size limit before memory grows, so neither format
widens what an asset can do. `flate2` was previously a removed dependency; it is
declared again deliberately, because gzip and xz are both ordinary ways to ship a
third-party archive and the authoring validator must not advertise a format the
engine cannot deploy. Shelling out to `gzip` or `xz` is not an option here —
`tests/dependency_boundaries.rs` confines `Command::new` to the Git port.

## Enforcement

`tests/dependency_boundaries.rs` reads Cargo metadata and checks workspace
edges, direct external dependencies, transitive sources, selected features, and
reviewed parser and runtime versions. It also rejects direct network use below
Engine's Git port and checks that commit has no path to prepare or component
runtime crates.

The test is a guardrail, not a substitute for reviewing what a dependency can
do at runtime.

## Changing A Dependency

1. Decide which layer owns the behavior. Prefer passing data through an existing
   interface over adding a dependency from a lower layer to a higher one.
2. Update the relevant `Cargo.toml`.
3. Update the matching package rule in `tests/dependency_boundaries.rs`. Add the
   direct workspace or external dependency, its allowed transitive set, and any
   feature or exact-version policy that applies.
4. Update this document when the diagram or layer description changes.
5. Run the focused check:

   ```sh
   cargo test --locked --test dependency_boundaries --features failpoints
   ```

6. Run the workspace checks from [Contributing](../CONTRIBUTING.md) before
   submitting the change. Changes to the component runtime must also keep its
   recorded execution-profile inputs in sync with the reviewed versions and
   features.
