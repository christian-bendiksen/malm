# Engine Host Ports

This guide is for Rust developers who embed Malm in another process. CLI users
should use the [CLI reference](cli.md) instead.

`Engine` owns workflow logic, but the embedding application chooses its paths
and host services. A port is a caller-selected implementation of a host service
such as Git or component execution.

## What The Caller Provides

Construction has two parts:

- `EngineConfig` selects the state root, read-only or read-write store access,
  and any named managed-target roots.
- `EnginePorts` supplies process facts, secure randomness, Git execution, an
  optional format-component runner, and progress and diagnostic sinks.

Filesystem operations are not a replaceable port. Engine contains the Linux
code that opens paths without following symlinks, checks metadata, and makes
durable changes. The caller selects which paths it may use through
`EngineConfig` and through operation inputs such as source and scratch roots.

Git is different. Engine asks the caller's `GitProcessPort` to perform the
limited Git work needed for an exact source. The operation still supplies the
approved URLs, Git settings, and scratch directories.

Format components are also separate. If an operation selects a WebAssembly
transform, Engine sends its verified identity, bytes, and request to the
caller's `FormatComponentExecutionPort`. Apply and recovery never use this
port.

Engine does not discover `HOME`, XDG directories, the current directory,
terminal state, or application policy. Build a new Engine when its paths,
process user, or open-file limit change.

## Small Construction Example

This example selects the state directory, uses the system randomness and Git
implementation, and opts in to the in-process component host:

```rust
use std::path::Path;
use std::sync::Arc;

use malm_engine::{Engine, EngineConfig, EnginePorts, StoreAccess};
use malm_format_component_adapter::InProcessFormatComponentExecutionPort;

fn make_engine(state_home: &Path) -> Result<Engine, Box<dyn std::error::Error>> {
    let config = EngineConfig::from_state_home(
        state_home,
        StoreAccess::ReadWrite,
    )?;
    let component = Arc::new(InProcessFormatComponentExecutionPort::new()?);
    let ports = EnginePorts::system()
        .with_format_component_execution(component);

    Ok(Engine::new(config, ports))
}
```

`from_state_home` appends the `malm` state-root name. Use
`EngineConfig::new` when the final root path is already known. Add named managed
targets to the config before constructing the Engine.

## System Ports

`EnginePorts::system()` is the normal starting point. It records the current
effective user ID and open-file soft limit, uses operating-system secure
randomness, installs Malm's restricted Git process runner, and uses no-op event
sinks.

The system set does not enable component execution. This keeps Wasmtime out of
processes and operations that do not need it. Install the workspace's
`InProcessFormatComponentExecutionPort`, as above, only when the application
supports format components.

## Custom Ports

Use `EnginePorts::new` to provide your own process facts, randomness, Git
implementation, and event sinks. Then use
`with_format_component_execution` if component execution is supported. Port
implementations are shared across calls and must be `Send + Sync`.

Custom ports are useful for a controlled Git service, deterministic test
fixtures, or application-specific event handling. Engine validates paths,
manifests, object identities, and size limits in data returned by Git. It cannot
prove that a custom Git implementation fetched those bytes from the claimed
remote, so the embedding application must trust that implementation.

Progress and diagnostic sinks are observers, not a second result channel. Keep
their callbacks fast and avoid calling the same Engine from inside a callback.

## API Documentation

The public Rustdoc comments and exact signatures are attached to these type
definitions:

- [`Engine`](../crates/malm-engine/src/lib.rs#L1488)
- [`EngineConfig`](../crates/malm-engine/src/lib.rs#L217) and
  [`StoreAccess`](../crates/malm-engine/src/lib.rs#L161)
- [`EnginePorts`](../crates/malm-engine/src/ports.rs#L217)
- [`GitProcessPort`](../crates/malm-engine/src/ports.rs#L130)
- [`FormatComponentExecutionPort`](../crates/malm-engine/src/ports.rs#L206)
- [`InProcessFormatComponentExecutionPort`](../crates/malm-format-component-adapter/src/lib.rs#L19)

For rendered local API documentation, run:

```sh
cargo doc --locked -p malm-engine -p malm-format-component-adapter --no-deps
```

Then open `target/doc/malm_engine/index.html` and
`target/doc/malm_format_component_adapter/index.html`.

See [Architecture](architecture.md) for the full workflow and
[Dependency Boundaries](dependency-boundaries.md) for the crate split.
