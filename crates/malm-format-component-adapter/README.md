# malm-format-component-adapter

`malm-format-component-adapter` connects Engine's
`FormatComponentExecutionPort` to the in-process WebAssembly component host.
Engine supplies verified authorization, component identity and bytes, and a
transform request; the adapter checks the identity and host policy, then asks the
host to admit and invoke the component.

This crate is for Rust embedders that opt in to component execution. The stock
CLI installs the same adapter only on workflows that may need components.

## Use

Create `InProcessFormatComponentExecutionPort` and install it on `EnginePorts`.

```rust
use malm_engine::{EnginePorts, FormatComponentExecutionIssue};
use malm_format_component_adapter::InProcessFormatComponentExecutionPort;
use std::sync::Arc;

fn engine_ports() -> Result<EnginePorts, FormatComponentExecutionIssue> {
    let component_port = Arc::new(InProcessFormatComponentExecutionPort::new()?);
    Ok(EnginePorts::system().with_format_component_execution(component_port))
}
```

Host construction is lazy. `with_compile_cache` may reuse compiled WebAssembly
code; the cache affects startup and compilation work only, not execution,
results, or execution-profile identity. Operations that invoke no component do
not initialize Wasmtime or touch the cache.

## Profiles And Checks

A user profile is a named configuration selection that determines desired
outputs. It is distinct from the execution-profile digest recorded in a lock,
which identifies the host's complete runtime and resource policy. The adapter
requires that locked digest to match the current host and requires the supported
interface before admission. The host then enforces exact-digest authorization,
validates the bytes, and runs the component within its limits.

`current_host_execution_profile_digest_v1` reports the current policy identity
without constructing Wasmtime or touching its cache.

## Boundary

The adapter does not choose components, create authorization, fetch bytes, or
persist them. Engine uses it during prepare and authorized offline profile
switching; commit, recovery, inspection, and cleanup do not call it.

See [Engine Host Ports](../../docs/engine-host-ports.md),
[Format Component Admission](../../docs/format-component-admission.md), and
[Dependency Boundaries](../../docs/dependency-boundaries.md).
