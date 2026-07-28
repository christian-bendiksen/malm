# Pack manifest grammar (`pack/v1`)

The `pack/v1` manifest contract defines the strict KDL representation of
`malm-pack.kdl`. Pack authors use it to declare a pack, and manifest readers and
lock generators use it to obtain the same validated semantic model from any
accepted KDL spelling.

A manifest is a UTF-8 KDL v2 document with exactly one top-level `pack` node.
A `PackPath` is a validated path relative to the logical pack root. A
`LocalLocator` is a separately validated path relative to the root pack and may
start with parent segments. The two path types are not interchangeable.

The following complete manifest shows every required section:

```kdl
pack schema-version=1 package-id="com.example.desktop" {
    modules {
        module "terminal" path="modules/terminal.kdl"
    }
    config-documents {
        document "config/desktop.kdl"
    }
    dependencies {
        dependency "common" package-id="com.example.common" {
            local workspace-path="packs/common"
        }
        dependency "theme" package-id="org.example.theme" {
            git url="https://example.org/theme.git" commit="sha1-0123456789abcdef0123456789abcdef01234567" subdir="."
        }
    }
    templates {
        template "templates/settings.toml"
    }
    schemas {
        schema "schemas/settings.schema.json"
    }
    assets {
        asset "assets/logo.svg"
    }
    components {
        component "settings-formatter" path="components/settings.wasm" digest="sha256-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" interface="format-component/v1"
    }
}
```

## Node reference

| Node | Arguments | Required properties | Body |
|---|---:|---|---|
| `pack` | 0 | `schema-version` integer, `package-id` string | Seven required sections and optional `captures` |
| `modules` | 0 | none | Zero or more `module` nodes |
| `module` | 1 string name | `path` string | Forbidden |
| `config-documents` | 0 | none | Zero or more `document` nodes |
| `document` | 1 string path | none | Forbidden |
| `dependencies` | 0 | none | Zero or more `dependency` nodes |
| `dependency` | 1 string alias | `package-id` string | Exactly one `git` or `local` node |
| `git` | 0 | `url`, `commit`, `subdir` strings | Forbidden |
| `local` | 0 | `workspace-path` string | Forbidden |
| `templates` | 0 | none | Zero or more `template` nodes |
| `template` | 1 string path | none | Forbidden |
| `schemas` | 0 | none | Zero or more `schema` nodes |
| `schema` | 1 string path | none | Forbidden |
| `assets` | 0 | none | Zero or more `asset` nodes |
| `asset` | 1 string path | none | Forbidden |
| `components` | 0 | none | Zero or more `component` nodes |
| `component` | 1 string name | `path`, `digest`, `interface` strings | Forbidden |
| `captures` | 0 | none | Zero or more `include` nodes |
| `include` | 1 string path | none | Forbidden |

## Document structure

The seven sections from `modules` through `components` must each appear exactly
once. Every section keeps its body braces when it is empty. The `captures`
section is optional and may appear at most once.

Each node has exactly the arguments, properties, and body shape listed above.
All listed properties are required. Nodes and entries must not have KDL type
annotations. The reader rejects unknown nodes, extra arguments or properties,
unknown children, duplicate properties, missing or forbidden bodies, and a
dependency with either zero or more than one source child.

Comments, property order, section order, and different valid KDL v2 string
spellings can decode to the same model. They do not change the semantic model,
but their exact manifest bytes remain part of the whole-tree pack digest. The
canonical writer emits deterministic KDL, including the section order shown in
the example.

## Capture selection

Use `captures` to narrow source acquisition. Each `include` argument names one
file or directory tree. The manifest is always selected. `malm.lock` remains a
reserved path and never enters pack content; a Git tracked-root flow may retain
the root lock temporarily for its separate lock validation.

Capture roots are syntactically valid `PackPath` values, but acquisition does
not require each root to exist and does not verify it as a declaration. Roots
only narrow which source entries are read. The content digest always covers
exactly the files that survive capture.

An absent `captures` section and an empty capture-root list both mean capture
the whole source tree. The canonical writer omits `captures` when that list is
empty, preserving the manifest bytes and digest of packs that need no roots.

The [local capture adapter](source-capture.md) and the
[Git acquisition adapter](../../lock/v1/git-acquisition.md) apply the same root
selection. The same source tree therefore has one content digest under either
adapter.

## Names and uniqueness

A `package-id` is a lowercase reverse-DNS name of at most 253 ASCII bytes. It
contains at least two nonempty dot-separated segments. Every segment starts with
a lowercase letter, ends with a lowercase letter or digit, and otherwise
contains only lowercase letters, digits, or hyphens.

Module and component names are 1 to 63 ASCII bytes. Dependency aliases are 1 to
32 ASCII bytes. Each starts with a lowercase letter; every remaining byte is a
lowercase letter, digit, or hyphen.

Module names, component names, and dependency aliases must be unique in their
respective sections. Template, schema, asset, and capture-root paths must also
be unique in their sections. Module paths and configuration-document paths are
sorted and unique within their own sections, and one path cannot serve both
roles.

A component `interface` must be exactly `format-component/v1`. The execution
profile is not written here. Malm resolves it while creating or updating the
lock.

## Git dependencies

A Git `url`:

- Is at most 2,048 UTF-8 bytes.
- Must be an absolute HTTPS URL with a host.
- Must not have leading or trailing whitespace, control characters,
  backslashes, embedded credentials, query strings, or fragments.

Malm normalizes the host spelling, IDNA DNS names, IPv6 addresses, default
ports, and dot segments before using the URL.

A `commit` is `sha1-` followed by 40 lowercase hex digits, or `sha256-` followed
by 64. Use `subdir="."` for the repository root. Any other `subdir` follows the
pack path rules below.

## Local dependencies

A `workspace-path` is a slash path relative to the root pack, not the
dependency that declares it. `.` selects the root pack.

Parent segments (`..`) are allowed only as a leading prefix. Every such escape
needs root-consumer policy, so a local path can only read outside the pack when
an operator allowed it. A path introduced by a remote-derived pack needs policy
no matter how it is spelled.

Each `LocalLocator` is at most 4,096 UTF-8 bytes and 64 segments. Except for the
single value `.`, it must not be empty, absolute, contain empty or internal dot
segments, use backslashes, contain control characters, or enter `.git`,
`malm.lock`, or `.malm-lock.tmp`. A non-parent segment is at most 255 bytes.

## Pack paths and resources

Pack paths are case-sensitive UTF-8 Linux paths with slash separators.

Each path:

- Is relative.
- Is at most 1,024 bytes and 32 segments.
- Has segments of at most 255 bytes.
- Must not be empty, `.`, `..`, contain a backslash or control character, or
  include a segment named `.git`, `malm.lock`, or `.malm-lock.tmp`.

Templates, schemas, and assets are exact pack files available to rich output
and transform-resource references. External payload declarations are not part
of this grammar.

## Rejection conditions

Malm rejects a manifest that violates any structural, scalar, path, uniqueness,
or resource rule in this contract. In particular, rejection includes:

- Invalid UTF-8, malformed KDL v2, more or less than one top-level `pack` node,
  or a top-level node with another name.
- A `schema-version` other than the integer `1`.
- Unknown nodes, arguments, properties, or children; duplicate properties; or
  any KDL type annotation.
- A required section that is absent or repeated, or a repeated optional
  `captures` section.
- A body where one is forbidden, a missing required body, or a dependency with
  neither or both of `git` and `local`.
- Duplicate module names, component names, dependency aliases, or paths that
  must be unique; or one path used as both a module and configuration document.
- An unsupported component interface, malformed source selector, invalid name
  or path, or a collection over its fixed limit.

## Fixed limits

| Limit | Maximum |
|---|---|
| Encoded manifest | 1 MiB |
| Modules | 4,096 |
| Config documents | 4,096 |
| Direct dependencies | 256 |
| Template paths | 4,096 |
| Schema paths | 4,096 |
| Assets | 4,096 |
| Components | 256 |
| Capture roots | 4,096 |

Each captured tree is also subject to the file-count and byte limits in the
[canonical content contract](canonical.md).
