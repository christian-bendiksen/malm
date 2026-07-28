# Rich configuration document grammar (`config/v1`)

This page defines the outer `config/v1` KDL document, composition references,
and desired-output declarations. It is the starting point for `rich-config`
parser and engine implementers. The [complete rich KDL grammar](rich-grammar.md)
defines every nested type, expression, condition, statement, fragment, patch,
slot, and profile production.

## Source envelope

An input is exact captured bytes. It must be valid UTF-8, valid KDL v2, no more
than 1,048,576 bytes, no more than 64 lexical child-block levels, and no more
than 64 nested block comments. The document must contain exactly one top-level
`rich-config` node.

The parser rejects node annotations, value annotations, duplicate properties,
unknown properties, an unexpected argument or body, a missing required argument
or body, and any unknown or repeated child at every grammar level. Empty bodies
remain explicit where the grammar requires a body.

## Document shape

```kdl
rich-config schema-version=1 default-profile="desktop" {
    includes {
        include path="shared.kdl"
        include path="dependency.kdl" dependency="theme"
    }
    modules {
        module "terminal"
        module "palette" dependency="theme"
    }
    variables { }
    fragments { }
    slots { }
    statements { }
    profiles { }
}
```

The root has no arguments, requires the integer property `schema-version=1`,
permits only the optional string property `default-profile`, and requires a
body. The seven shown sections must each occur exactly once. Every section has
no arguments or properties and requires a body, including when empty.

`default-profile` may be omitted from any parsed source. During parsed workspace
evaluation, an explicit caller selection wins. Otherwise the entry document's
`default-profile` is required. A default on an included document does not select
the profile.

## Includes, modules, and authority

An include selects a manifest-declared configuration document. A module selects
a manifest-declared module export:

| Node | Arguments | Required properties | Optional properties | Body |
| --- | --- | --- | --- | --- |
| `include` | none | `path` string `PackPath` | `dependency` string alias | forbidden |
| `module` | one string contribution name | none | `dependency` string alias | forbidden |

Without `dependency`, resolution stays in the source document's exact pack
authority. With `dependency`, resolution enters the named direct dependency of
that authority. It cannot discover paths, skip to an undeclared transitive
pack, or choose an authority by content alone.

Acquisition supplies the complete finite graph of authority labels, locked pack
digests, direct dependency aliases, declared config-document paths, and module
name-to-path exports. Parsed-set construction and evaluation resolve references
against that graph. The graph must contain its root, contain every exact
dependency target, be acyclic, and contain no authority unreachable from its
root. Missing paths or exports, undeclared aliases, forged identities or paths,
duplicate direct targets, missing captured targets, include cycles, excessive
depth, and captured documents unreachable from the entry are hard errors.

Declaration order is semantic. Includes retain their written order, modules
retain their written order, and the composition edge sequence contains all
includes followed by all modules. Depth-first evaluation processes each target
before its source and processes a target at most once across diamonds. Every
resolved edge and target digest remains in typed-document provenance.

## Desired outputs

Profiles can declare five output forms. Every output has one string `RichNameV1`
argument, a required `destination` target path, and an optional `slot` name.

```kdl
regular-file "config" destination=".config/app/config" source="assets/config" source-kind="asset" raw-digest="sha256-..." object-digest="sha256-..." byte-len=42 executable=#false
symlink "link" destination=".config/app-link" target="app/config"
canonical-tree "tree" destination=".local/share/app" digest="sha256-..."
decoded-archive "sdk" destination=".local/share/sdk" source="assets/sdk.tar" source-kind="asset" raw-digest="sha256-..." object-digest="sha256-..." byte-len=1024 decoder="malm.posix-ustar.none" decoder-version=1 tree-digest="sha256-..."
format-file "settings" destination=".config/app/settings.json" executable=#false {
    built-in "canonical-json"
    options { }
    resources {
        resource "schema" source="schemas/settings.json" source-kind="schema" raw-digest="sha256-..." object-digest="sha256-..." byte-len=128
    }
}
```

| Output | Additional required properties | Additional optional properties | Body |
| --- | --- | --- | --- |
| `regular-file` | `source`, `source-kind`, `raw-digest`, `object-digest`, `byte-len`, `executable` | `dependency` | forbidden |
| `symlink` | `target` | none | forbidden |
| `canonical-tree` | `digest` | none | forbidden |
| `decoded-archive` | `source`, `source-kind`, `raw-digest`, `object-digest`, `byte-len`, `decoder`, `decoder-version`, `tree-digest` | `dependency` | forbidden |
| `format-file` | `executable` | none | required |

`decoder-version` must fit `u16`. A decoded archive's `source-kind` must be
`asset`. Decoder support and the expected decoded tree digest are checked during
preparation; parsing only validates and retains their names and identities.

## Pack-file references

Every regular file, decoded archive, and transform resource binds all of these
fields:

- `source`: a `PackPath` in the selected pack;
- `source-kind`: exactly `asset`, `template`, or `schema`;
- `raw-digest`: SHA-256 of the exact source bytes;
- `object-digest`: the canonical file-object digest;
- `byte-len`: the exact nonnegative `u64` byte length;
- optional `dependency`: a declared direct dependency alias.

The selected `source-kind` and path must agree with the exact target pack
manifest. During preparation, the engine verifies manifest membership, byte
length, raw digest, and canonical file-object digest before publishing the
object. Configuration parsing and evaluation do not read or publish those
bytes.

## Transform selectors

A `format-file` body contains exactly one `built-in` or `component` selector,
exactly one `options` section, and exactly one `resources` section. The two
sections require bodies even when empty.

The built-in selector has one string argument and accepts only
`canonical-json`, `plain-text`, or `key-value`. A component selector has one
transform-name argument and requires `digest` and
`interface="format-component/v1"`; it permits no other property. Preparation
must resolve the digest to exactly one matching locked component and use that
component's locked execution profile. See the [transform contract](transform.md)
for request and execution rules.

Each `option` has one name argument and a body containing exactly one recursively
typed literal value. Variable references, selection, and conditional
expressions are not options. Each `resource` has one name argument, a bodyless
pack-file reference, and may select one direct dependency. Option names and
resource names are unique; their evaluated vectors are sorted by name.

## Path and output validation

A destination is a nonempty target-relative slash path. It is at most 4,096
UTF-8 bytes and 64 segments; each segment is at most 255 bytes. Absolute paths,
backslashes, controls, empty segments, `.` segments, and `..` segments are
rejected.

A symlink target follows the same byte, segment, separator, control, and lexical
dot rules. It is relative to the symlink rather than to the deployment target.

Across the selected profile closure, output names and destinations must be
unique. No destination may be an ancestor of another destination. Slot
provider bounds and every collection, byte, nesting, expansion, and diagnostic
limit are checked before a plan can be published. The complete limits are in
the [canonical rich IR contract](rich-ir.md#fixed-limits).
