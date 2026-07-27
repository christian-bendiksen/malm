# Format Components

A format component is a WebAssembly component bundled in a pack. It can render
a typed Malm document into a custom file format, or transform bytes produced by
another renderer. Pack authors choose where a component is used, while component
developers implement Malm's versioned `transform` interface.

See [Rendering And Components](authoring/rendering-components.md) for the pack
syntax used to select a renderer or add an ordered transform.

## Add A Component To A Pack

1. Build a WebAssembly component that implements Malm's
   [`transform` interface](../schemas/format-component/v1/README.md).
2. Copy the component into the pack and calculate its SHA-256 digest with
   `sha256sum`.
3. Declare its path, digest, and `format-component/v1` interface in
   `malm-pack.kdl`.
4. Select it as a renderer or transform using the
   [authoring syntax](authoring/rendering-components.md#optionally-use-a-component).
5. [Create or update `malm.lock`](cli.md#lock-sources), then
   [create and review a plan](cli.md#create-review-and-apply-plans).

## What A Component Can Access

Malm gives a component only the data in its request: a typed document, explicit
options, and named resource bytes. A transform returns output bytes and may
return structured diagnostics.

Components have no ambient access. Malm does not give them WASI, files, the
network, environment variables, processes, clocks, randomness, Malm state, or
deployment targets.

## How Malm Checks A Component

A pack declares the component file, its SHA-256 digest, and the
`format-component/v1` interface. Malm records the selected component when it
locks the pack.

Before running the component, Malm checks that its bytes match the locked digest
and that it is a valid WebAssembly component for the exact v1 interface. The
interface has no imports and one `transform` export. Malformed components, core
WebAssembly modules, unexpected imports, and interface mismatches are rejected.

Malm also checks that the recorded runtime rules, called the execution profile,
match the component host. This prevents a component from running under different
rules than the ones recorded when the source was locked.

## Resource Limits

Malm limits component size, request and response sizes, memory, stack use,
runtime objects, data transfer, and execution work. Each call uses a fresh
isolated runtime store. A component that traps or exceeds a limit cannot publish
a partially prepared plan.

These limits are controlled by Malm rather than by the pack or the component.

## Exact Interface Details

The [format-component/v1 contract](../schemas/format-component/v1/README.md)
links to the WIT interface file and defines requests, responses, diagnostics,
and compatibility. The [pack manifest guide](../schemas/pack/v1/grammar.md)
defines how a pack declares a component.
