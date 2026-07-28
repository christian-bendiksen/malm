# Pack manifests and content identity (`pack/v1`)

The `pack/v1` contract defines a distributable logical tree of regular files,
its required `malm-pack.kdl` manifest, and the digest that gives the tree a
stable identity. Pack authors use it when declaring source, while lock writers,
source adapters, stores, and configuration readers use it when validating or
moving that source between boundaries.

The manifest names the package and declares modules, configuration documents,
dependencies, templates, data schemas, assets, and WebAssembly components.
Bundled schemas are inert resources. Declaring or bundling a component does not
execute it.

A pack's identity is SHA-256 over a versioned encoding of every included
regular file's exact UTF-8 path and bytes, including `malm-pack.kdl`. Empty
directories and filesystem metadata do not affect that identity.

## Contract map

| File | Use it to |
|---|---|
| [KDL grammar](grammar.md) | write, parse, or validate `malm-pack.kdl` |
| [Canonical content digest](canonical.md) | compute or verify the stable pack identity |
| [Local source capture](source-capture.md) | turn an authorized directory into locked pack bytes safely |
| [Fixtures](fixtures/) | inspect accepted, rejected, and canonical manifests and digests |

Related contracts define how Malm [decodes archive assets](../../archive/v1/README.md)
and [persists immutable pack objects](../../store/v1/pack-object.md).

## Compatibility

Version 1 fixes the manifest grammar, semantic validation, path rules, resource
limits, and content-identity encoding. Every manifest must set
`schema-version=1`. Any incompatible change requires a new pack version.
