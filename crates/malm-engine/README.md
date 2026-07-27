# malm-engine

`malm-engine` is the shared stateful workflow used by Malm's human CLI, the
machine protocol, and Rust applications. CLI users should start with the
[CLI reference](../../docs/cli.md); embedders use this crate's `Engine` API.

The storeless `malm source check`, `source render`, `source vars`, and
`component host-profile` paths call narrower tooling directly. They do not
construct Engine or open the state store.

## Stateful Workflow

1. `prepare_static_deployment_v1` acquires and verifies inputs, evaluates a
   selected profile, observes targets, and publishes an immutable plan without
   changing them.
2. `plan_v1` reloads and verifies that plan for review.
3. After the caller approves the exact plan and findings, `commit_v1` applies it
   from verified local data.
4. If application is interrupted, `recover_v1` reconciles the journal to the
   prior state or the exact approved state.

Profile switching, lifecycle changes, retention, acquisition, and inspection
use the same Engine boundary.

## Construction And Calls

`Engine::new` takes `EngineConfig` and `EnginePorts`. Construction fixes the
state root, store access, named target roots, process facts, and the selected
implementations for secure randomness, Git, component execution, progress, and
diagnostics for the Engine's lifetime.

Per-operation inputs separately grant any source roots, local and Git access,
scratch directories, and Git configuration. The `SecureRandomPort` is selected
at construction, but random bytes are requested on demand only by operations
that need them; the bytes are not sampled or fixed by `Engine::new`.

`EnginePorts::system()` samples the effective user ID and open-file limit and
installs system entropy, the constrained Git adapter, an unavailable component
port, and no-op observers. Embedders may install a component adapter or provide
all ports explicitly.

## Boundary

Engine does not read `HOME`, XDG variables, the current directory, or terminal
state. It does not parse CLI arguments, prompt, or format terminal output.

Custom ports join the caller's trust boundary. Engine validates returned data,
but cannot prove that a custom Git adapter fetched it from the named remote.
Component execution is prepare-only; commit and recovery use verified local
plan data and do not require a WebAssembly runtime.

See [Engine Host Ports](../../docs/engine-host-ports.md),
[Architecture](../../docs/architecture.md), and
[Dependency Boundaries](../../docs/dependency-boundaries.md).
