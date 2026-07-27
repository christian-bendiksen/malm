# config/v1 KDL Grammar

The only accepted document has a `rich-config` root. It is UTF-8 KDL v2, at
most 1 MiB, and contains every required section exactly once:

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

Unknown nodes, properties, arguments, bodies, duplicate properties, and value
or node annotations are errors. `default-profile` is optional only when the
caller explicitly selects a profile.

An include names a declared config-document path in the current pack or one
direct dependency. A module names an export in the current pack or one direct
dependency. Neither carries an authority digest: acquisition supplies the exact
authority graph and the parser resolves each edge against that graph. Missing,
undeclared, forged, transitive, cyclic, or unreachable references fail closed.

The complete expression, statement, patch, profile, slot, and type grammar is
specified in [rich-grammar.md](rich-grammar.md).

## Outputs

Profiles may declare these output forms:

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

Pack-file references require `source`, `source-kind`, `raw-digest`,
`object-digest`, and `byte-len`, with optional `dependency`. `source-kind` is
`asset`, `template`, or `schema` and must agree with the exact target pack
manifest. Archive payloads must be assets. Engine verifies both byte identities
and the declared length before publishing canonical objects.

`format-file` contains exactly one built-in or component selector and exactly
one `options` and `resources` section. Component selectors bind the exact
component digest and `format-component/v1` interface. Execution profile ownership
belongs to the matching locked component.

All target paths and symlink targets are safe relative paths. Output names and
destinations are unique, destination ancestry cannot overlap, and every fixed
collection, byte count, nesting depth, expansion, and diagnostic count is
bounded before plan publication.
