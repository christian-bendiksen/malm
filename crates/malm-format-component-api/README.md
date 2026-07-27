# malm-format-component-api

`malm-format-component-api` is the shared policy boundary between Engine and the
WebAssembly component host. It is for maintainers and embedders implementing
component execution; applications normally use Engine and its adapter instead.

Engine derives a `FormatComponentAuthorizationV1` from verified source. The
adapter passes that authorization, an expected SHA-256 digest, and exact
component bytes to the host. Before parsing or execution, the host requires the
expected digest to appear in the authorized set and requires the bytes to match
it. Authorization grants no filesystem, network, process, or other capability.

## Public API

- `FORMAT_COMPONENT_INTERFACE_V1` is the exact interface name recorded in packs
  and locks: `format-component/v1`.
- `WIT_SOURCE` contains the normative WebAssembly Interface Types (WIT) text for
  the request, success, and failure values.
- `FormatComponentAuthorizationV1::new` stores permitted digests in canonical
  order, and `digests` iterates in that order.
- `FormatComponentAuthorizationV1::permits` tests one exact digest.

## Boundary

This crate does not parse configuration, choose or fetch a component, validate
WebAssembly, or execute code. It contains stable identifiers and authorization
policy only; admission and invocation belong to the separate host crate.

See the [normative WIT](wit/malm-format-component.wit),
[`format-component/v1`](../../schemas/format-component/v1/README.md), and
[Format Component Admission](../../docs/format-component-admission.md).
