# pack/v1 KDL Grammar

`malm-pack.kdl` is a UTF-8 KDL v2 file with one top-level `pack` node. Here is
a complete manifest with every section:

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

## Node Reference

| Node | Arguments | Required properties | Body |
|---|---:|---|---|
| `pack` | 0 | `schema-version` integer, `package-id` string | Seven required sections plus optional `captures` |
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

## Required And Optional Sections

The seven sections through `components` must each appear exactly once. They
keep their braces even when empty. The `captures` section is optional and may
appear at most once.

Use `captures` to limit which local files enter the pack. Its `include` paths
list the files and directories to include. The manifest and lock files are
always captured, whether or not `captures` is declared.

When `captures` is omitted, the canonical writer leaves it out entirely. This
keeps existing manifests and their digests unchanged when no capture roots are
needed.

Capture roots are not verified. They only narrow what gets read. The whole-tree
pack digest covers exactly the captured files, with or without declared roots.

The [local capture](source-capture.md) and the
[Git acquisition adapter](../../lock/v1/git-acquisition.md) both narrow to the
roots declared here. One source tree has one digest under either adapter.

## What Malm Rejects

- Unknown nodes, arguments, properties, or children.
- Duplicate properties on the same node.
- A node that forbids a body having one.
- A section node appearing more than once.
- A node that must have one `git` or `local` child having neither or both.

Comments and different valid KDL v2 string spellings decode to the same model,
so they do not change what Malm sees. Their exact bytes are still part of the
whole-tree pack digest.

## Names And Interfaces

`package-id`, module names, component names, and dependency aliases follow the
`malm-types` v1 name profile.

A component `interface` must be exactly `format-component/v1`. The execution
profile is not written here. Malm resolves it while creating or updating the
lock.

## Git Dependencies

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

## Local Dependencies

A `workspace-path` is a slash path relative to the root pack, not the
dependency that declares it. `.` selects the root pack.

Parent segments (`..`) are allowed only as a leading prefix. Every such escape
needs root-consumer policy, so a local path can only read outside the pack when
an operator allowed it. A path introduced by a remote-derived pack needs policy
no matter how it is spelled.

## Paths And Limits

Pack paths are case-sensitive UTF-8 Linux paths with slash separators.

Each path:

- Is relative.
- Is at most 1,024 bytes and 32 segments.
- Has segments of at most 255 bytes.
- Must not be empty, `.`, `..`, contain a backslash or control character, or
  include a segment named `.git`, `malm.lock`, or `.malm-lock.tmp`.

Module paths and config-document paths are sorted and unique within their own
section. One path cannot serve both roles.

Templates, schemas, and assets are exact pack files available to rich output
and transform-resource references. External payload declarations are not part
of this grammar.

## Fixed Limits

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

Each pack file is also subject to the pack-tree byte limits.
