# malm-root

`malm-root` selects and validates the location of Malm's private state. It is for
embedders and filesystem adapters that need one predictable state-root policy.

The crate exists to keep path selection and root admission independent of
ambient process state. Callers supply the relevant paths, so the same inputs
produce the same root in applications, tests, and recovery tools.

## Select State

`resolve_root` applies a fixed order: a supplied `XDG_STATE_HOME` selects
`$XDG_STATE_HOME/malm`; otherwise a supplied `HOME` selects
`$HOME/.local/state/malm`. `require_home` validates the fallback input.

`validate_injected_root` handles an embedder-selected root. It requires an
absolute, already normalized path that is not itself a filesystem root.

```rust
use malm_root::resolve_root;
use std::path::Path;

let root = resolve_root(Some(Path::new("/home/alex")), None)?;
assert_eq!(root, Path::new("/home/alex/.local/state/malm"));
# Ok::<(), malm_root::RootPathError>(())
```

## Admit A Root

Every final root carries `descriptor.json`, a small marker that identifies the
store format and version. `decode_descriptor_v1` accepts only the exact
canonical version 1 descriptor, preventing an incompatible or accidental
directory from being treated as Malm state.

`FINAL_ROOT_ENTRIES` and `final_root_entry` define the allowed top-level layout,
including required entry kinds and modes. `RecordFamilyV1` and `OperationV1`
provide stable inventory names used by adapters.

## Boundary

This crate is pure path, descriptor, and layout policy. The adapter that calls
it reads environment values and performs all filesystem work.

See the [root/v1 schema](../../schemas/root/v1/README.md) and the
[crate API](src/lib.rs).
