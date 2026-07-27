# malm-types

`malm-types` defines Malm's common identifiers, requests, and results. It is for
Rust crate authors and embedders that exchange values across Malm boundaries.

The crate exists so every layer uses the same validated vocabulary without
depending on the engine, store implementation, or command-line adapter.
Validation happens when values are constructed or decoded, not independently
in each consumer.

## Identify Values

Use `Digest`, `PackNodeId`, `PackageId`, `ArtifactId`, `DeploymentName`,
`NamespaceName`, and `PreparedId` for common identities. Their constructors
enforce the spelling and size rules used throughout Malm. `Digest::sha256`
computes the algorithm-tagged content digest.

For fields that are not identifiers, helpers such as `validate_text`,
`validate_label`, `validate_diagnostic_code`, and `validate_relative_path`
apply the shared bounded-value rules.

## Send Requests

Deployment requests include preparation, checkout, commit, and pruning.
Lifecycle requests cover enabling, disabling, history, inspection, status,
verification, and retention. Store adapters use `StoreRequestV1` as their
common operation input.

## Return Results

Preparation and deployment return values such as `PreparedDeploymentV1` and
`ApplyOutcomeV1`. Store operations return `StoreResultV1` or `StoreErrorV1`.
Inspection, status, history, and verification records provide the corresponding
structured results.

## Boundary

This crate defines values and validates their shape; consuming crates perform
the operations. It has no dependencies on other workspace crates.

See the [contract index](../../schemas/README.md) and the [crate API](src/lib.rs).
