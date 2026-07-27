# config/v1 Rich KDL Grammar

## Document

Rich sources are UTF-8 KDL v2 under fixed byte, lexical nesting, and comment
nesting limits. They use one top-level node:

```kdl
rich-config schema-version=1 default-profile="desktop" {
    includes { }
    modules { }
    variables { }
    fragments { }
    slots { }
    statements { }
    profiles { }
}
```

All seven sections occur exactly once and retain explicit bodies when empty.
`default-profile` is optional on any source but is required on the evaluated
entry unless the caller explicitly selects a profile. Unknown nodes,
properties, arguments, bodies, duplicate properties, and annotations are
errors at every level. `decode_rich_config_document_v1` records each KDL node's
exact half-open byte range.

## Includes

Includes name a declared path in the current pack or one direct dependency:

```kdl
include path="shared.kdl"
include path="theme.kdl" dependency="theme"
```

`path` is a `PackPath`; `dependency` is an optional direct dependency alias.
Acquisition supplies exact authority labels, locked pack digests, declared
config-document paths, and dependency scope. Resolution cannot discover paths
or address an undeclared transitive pack. Include order is semantic.

Modules select manifest exports under the same scope rules:

```kdl
module "terminal"
module "palette" dependency="theme"
```

Module composition and include composition both retain exact resolved edge
provenance in the canonical typed document.

## Types And Variables

Scalar types are `bool`, `integer`, `unsigned`, `float`, `string`, and `path`:

```kdl
input "theme" optional=#false {
    type "string"
    default { string "dark" }
}
let "enabled" {
    type "bool"
    expression { bool #true }
}
```

`input` requires `optional` and one `type`; `default` is optional. `let`
requires one `type` and one `expression`. Recursive aggregate types are:

```kdl
type "list" { item-type { type "string" } }
type "collection" { item-type { type "integer" } }
type "record" {
    field "title" optional=#false {
        type "string"
        default { string "Malm" }
    }
}
```

Record-field defaults must be literal scalar/list/record/collection values.
Variable defaults may use any expression and are type-checked during evaluation.

## Expressions

Every expression wrapper contains exactly one expression node. Scalar literals
are `"null"`, `bool`, `integer`, `unsigned`, `float`, `string`, and `path`.
The null node is quoted because `null` is reserved by KDL. References and
aggregates are:

```kdl
variable "theme"
list { item { string "one" } }
record { field "name" { variable "theme" } }
collection { item "stable-key" { integer 1 } }
select key="name" { value { variable "record-value" } }
if-value {
    condition { equal negated=#false { left { variable "theme" } right { string "dark" } } }
    then { string "night" }
    else { string "day" }
}
```

Conditions are `boolean`, `is-set`, `equal` with required `negated`, `not`,
`all`, and `any`. `boolean` and `is-set` contain one `value` expression. `not`
contains one `condition`; `all` and `any` contain zero or more `condition`
wrappers. Equality contains exactly `left` and `right` expressions.

## Statements And Fragments

Fragments contain one `statements` section. Statement forms are:

```kdl
emit "key" { value { string "value" } }
compose "fragment-name"
when {
    condition { boolean { value { variable "enabled" } } }
    then { emit "mode" { value { string "on" } } }
    else { emit "mode" { value { string "off" } } }
}
for-each "item" key-binding="key" {
    iterable { variable "items" }
    do { /* statements */ }
}
for-range "index" from=1 through=4 { do { /* statements */ } }
```

`key-binding` is optional. Ranges are inclusive. Loop and expansion limits are
applied before body execution.

An ordered `patch` body accepts these operations:

```kdl
set path="record.field" { value { string "new" } }
unset path="record.field" optional=#false
list-append path="list" { value { integer 1 } }
collection-insert path="items" { key { string "a" } value { integer 1 } }
collection-replace path="items" { key { string "a" } value { integer 2 } }
collection-remove path="items" optional=#true { key { string "missing" } }
collection-replace-all path="items" {
    item "a" { integer 1 }
    item "b" { integer 2 }
}
```

Patch paths are nonempty dot-separated rich keys. Operations execute in written
order.

## Profiles, Slots, And Outputs

Slots are globally unique and have an integer maximum from 1 through the fixed
provider limit:

```kdl
slot "config-provider" max=2
```

Profiles are globally unique across the reachable include closure:

```kdl
profile "desktop" abstract=#false {
    extends { profile "base" }
    statements { /* rich statements */ }
    outputs { /* desired outputs */ }
}
```

All three sections are required. Parent order and statement order are semantic.
Object output forms are bodyless and may carry optional `slot`:

```kdl
regular-file "config" destination=".config/app/config" source="assets/config" source-kind="asset" raw-digest="sha256-..." object-digest="sha256-..." byte-len=42 executable=#false slot="config-provider"
symlink "link" destination=".config/app-link" target="app/config"
canonical-tree "tree" destination=".local/share/app" digest="sha256-..."
decoded-archive "archive" destination=".local/share/sdk" source="assets/sdk.tar" source-kind="asset" raw-digest="sha256-..." object-digest="sha256-..." byte-len=1024 decoder="malm.posix-ustar.none" decoder-version=1 tree-digest="sha256-..."
```

`format-file` requires one closed transform selector plus explicit `options` and
`resources` sections, even when both are empty:

```kdl
format-file "settings" destination=".config/app/settings.json" executable=#false {
    built-in "canonical-json"
    options {
        option "pretty" {
            bool #true
        }
    }
    resources {
        resource "schema" source="schemas/settings.json" source-kind="schema" raw-digest="sha256-..." object-digest="sha256-..." byte-len=128
    }
}
```

The selector is exactly one `built-in` or `component`. A component selector has
one transform name and required `digest` and `interface="format-component/v1"`
properties. Its execution profile comes from the matching locked component.
Options must be explicit typed literal
expressions. Resources name an exact pack file, its manifest section, raw-byte
digest, canonical file-object digest, and exact length. Any pack-file reference
may add `dependency` to select a direct locked dependency.

The parser and evaluator retain only validated paths, booleans, decoder names,
digests, transform selectors, explicit options/resources, and source
provenance. They do not resolve objects, decode archives, invoke components, or
access a target.
