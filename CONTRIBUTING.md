# Contributing

Malm requires Rust 1.95.0 and a 64-bit GNU/Linux host running on x86_64 or
aarch64 for the complete mutation, recovery, and durability test surface.

## Build And Test

Use locked dependencies:

```sh
cargo build --locked
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
cargo test --locked --workspace --all-features
RUSTDOCFLAGS='-D warnings' cargo doc --locked --workspace --no-deps
```

The `failpoints` feature enables crash-injection tests. It is valid for tests
and rejected by release builds.

Some filesystem tests require `strace` or a mount namespace. Set
`MALM_REQUIRE_STRACE=1` or `MALM_REQUIRE_MOUNT_NAMESPACE=1` when a missing or
skipped capability must fail the run.

Two suites skip without their environment. The authoring conformance tests need
`SMIA_ROOT` set to an external pack checkout. The cross-version rejection test
needs `MALM_REQUIRE_LEGACY_EXECUTABLE=1` and `LEGACY_MALM` set to a built
designated predecessor binary.

## Dependency Boundaries

Workspace dependencies are an architectural policy, not a local convenience.
Before adding an external crate, check the package allowlist in
`tests/dependency_boundaries.rs`. A policy change must update that test, the
relevant `Cargo.toml`, and [Dependency Boundaries](docs/dependency-boundaries.md)
together.

Keep prepare-only dependencies out of commit and recovery. In particular,
`malm-engine`, `malm-machine`, and `malm-commit` must not acquire a dependency
path to the format-component runtime.

## Comments

Use comments to explain invariants, security boundaries, durability ordering,
or a non-obvious reason for a choice. Do not narrate the code or preserve a
history of how it was refactored. Keep contract rationale next to the code that
depends on it.

## Contract-Sensitive Changes

Treat versioned schemas, canonical encodings, persisted records, machine frames,
CLI JSON, operation inventories, error codes, and exact diagnostic text as
contracts. Change their definitions, fixtures, documentation, and conformance
tests together.

`tests/operation_inventory.rs` checks literal operation names across source and
the inventories in `docs/`. Keep all restatements synchronized. Do not hide a
required literal behind generated source unless the test and contract are
deliberately changed.

`tests/hard_cut_static.rs` rejects removed production spellings outside the
negative-test allowlist in `.github/removed-spelling-test-allowlist.txt`. Do not
weaken that check to accommodate a new compatibility path.

Several outer error wrappers include an inner error in their `Display` text but
intentionally do not mark it as a Rust error source. Chaining it as `#[source]`
would print the same suffix twice. Preserve the nearby rationale and pinned
tests when changing those types.

The machine operation enum and codec use exhaustive hand-written matches in
several places. A variant change must update every mapping in one change; the
compiler and inventory tests provide the drift checks.
