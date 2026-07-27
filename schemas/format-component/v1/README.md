# format-component/v1

This interface lets a WebAssembly transform receive a typed configuration
document, options, and declared resource bytes, then return bounded output or a
structured failure. It is for component authors and for host and configuration
implementers. The interface grants no filesystem, network, process, clock,
randomness, state, or target access.

WIT, or WebAssembly Interface Types, defines the values and function exchanged
between a component and its host. The normative WIT package is
`malm:format-component@1.0.0`; its `malm-format-component` world has no imports
and exports exactly one `transform` function. There is no parallel JSON schema
or JSON decoder.

Compatibility: version 1 is the exact package, world, and types in the WIT file.
An incompatible type or function change requires a new interface version. There
is no predecessor ABI or compatibility adapter.

## Component Authors

- **Implement the guest interface:** [normative WIT](../../../crates/malm-format-component-api/wit/malm-format-component.wit)
- **Understand requests, responses, and diagnostics:** [transform contract](../../config/v1/transform.md)
- **Declare renderers and transform stages:** [rendering guide](../../../docs/authoring/rendering-components.md)

## Host Implementers

- **Admit and invoke components:** [host contract](../../../docs/format-component-admission.md)
- **Compute typed-document identities:** [configuration identity](../../config/v1/canonical.md)
- **Check the pinned interface bytes:** [golden WIT digest](fixtures/golden/wit.sha256)
