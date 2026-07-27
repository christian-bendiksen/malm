# pack/v1

A pack is a distributable logical tree of regular files. Its required
`malm-pack.kdl` manifest names the package and declares modules, configuration
documents, dependencies, templates, data schemas, assets, and WebAssembly
components. Bundled schemas are inert resources, and bundling a component does
not execute it.

A pack's stable identity is SHA-256 over a versioned encoding of every included
regular file's exact UTF-8 path and bytes, including the manifest. Empty
directories and filesystem metadata are not identity inputs. This contract is
for pack authors, lock generators, source-acquisition code, and configuration
implementers.

Compatibility: version 1 fixes the manifest grammar, validation, path rules,
resource limits, and content identity. `schema-version=1` is required; an
incompatible change requires a new pack version.

- **Write or parse a manifest:** [KDL grammar](grammar.md)
- **Compute stable pack identity:** [content digest encoding](canonical.md)
- **Capture a local pack safely:** [source capture](source-capture.md)
- **Inspect accepted and rejected manifests:** [fixtures](fixtures/)
- **Decode archive assets:** [archive contract](../../archive/v1/README.md)
- **Persist immutable pack objects:** [store pack-object contract](../../store/v1/pack-object.md)
