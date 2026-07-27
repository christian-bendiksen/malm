# malm-authoring

`malm-authoring` turns explicitly supplied Malm source into the desired files
and symlinks for one named profile. It is for Rust callers building authoring
checks or previews; command-line users should use `malm source check`, `render`,
and `vars`.

## Workflow

1. Supply an `AuthoringSourceSetV1`, a map from source-relative paths to exact
   captured bytes. It must contain `malm.kdl`, reachable includes, templates,
   fragments, and referenced native files.
2. The crate parses the KDL documents, resolves modules and includes, composes
   the selected profile (a named choice of modules and input values), and checks
   types, patches, references, and output declarations.
3. Evaluation returns `EvaluatedAuthoringProfileV1`: ordered desired file bytes,
   symlink declarations, metadata, and deferred component render requests.

Callers may also supply `OverlaySourceV1` values for declared value-only
overlays. A deferred component request identifies a sandboxed WebAssembly
formatter for Engine to invoke later; this crate never runs it.

## Boundary

Evaluation is pure: the same sources, overlays, and profile produce the same
result. The crate does not read files, environment variables, target directories,
or Malm state. It does not fetch sources, run commands or components, publish a
plan, or change targets.

Source paths and input sizes are bounded. Missing files, invalid paths, type
errors, and unsupported output forms return errors instead of being guessed.

## API

- `evaluate_authoring_profile_v1` evaluates one selectable profile.
- `check_authoring_workspace_v1` checks every module and profile.
- `default_authoring_profile_v1` returns the configured default profile.
- `resolve_authoring_vars_v1` reports resolved inputs and their origins.
- `declared_overlays_v1` lists overlays for the caller to load explicitly.

See [Authoring Types](../../docs/authoring/types.md),
[Profiles And Patches](../../docs/authoring/profiles-patches.md), and
[Rendering And Components](../../docs/authoring/rendering-components.md).
