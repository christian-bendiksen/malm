# Complete rich KDL grammar (`config/v1`)

This contract defines every KDL production accepted by
`decode_rich_config_document_v1`. It is for parser implementers and for authors
who need the exact lower-level `rich-config` language rather than Malm's
higher-level `config` authoring dialect.

The grammar is closed. A node accepts only the arguments, properties, and body
listed for it. Unless a production explicitly permits repetition, a named child
is required exactly once or optional at most once. Unknown nodes, properties,
arguments, bodies, duplicate properties, node annotations, and value
annotations are errors at every level.

## Lexical envelope

Source is UTF-8 KDL v2 and is limited before semantic parsing:

| Resource | Maximum |
| --- | ---: |
| One encoded document | 1,048,576 bytes |
| Lexical KDL child-block depth | 64 |
| Nested KDL block comments | 64 |

The decoder retains the exact captured bytes and records each accepted KDL
node's exact half-open byte range. It does not rewrite source, normalize KDL
spelling, or define a canonical source encoder.

## Document

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

The document contains exactly one top-level `rich-config` node. That node has no
arguments, requires integer `schema-version=1`, permits optional string
`default-profile`, and requires a body. The seven sections shown above each have
no arguments or properties, occur exactly once, and require a body even when
empty.

`default-profile` is a `RichNameV1`. It may be absent on any parsed document.
Parsed workspace evaluation uses an explicit caller-selected profile when
present; otherwise the entry document must supply `default-profile`. Defaults
on included documents do not participate in selection.

## Names, keys, and paths

`RichNameV1` is used for variables, fragments, loop bindings, profiles, slots,
outputs, decoders, transforms, options, and resources. It is 1 to 128 bytes and
consists of nonempty dot-separated segments. Each segment starts with a
lowercase ASCII letter; remaining bytes are lowercase ASCII letters, digits,
hyphens, or underscores.

`RichKeyV1` is used for record fields, collection keys, emitted root fields, and
patch-path segments. It is nonempty UTF-8, at most 1,024 bytes, and contains no
control character. Records and keyed collections store keys in canonical byte
order.

A `PackPath` follows the [pack path rules](../../pack/v1/grammar.md#pack-paths-and-resources).
A target path is a nonempty relative slash path of at most 4,096 bytes and 64
segments, with each segment at most 255 bytes. It cannot contain controls,
backslashes, empty segments, `.`, or `..`.

A patch `path` is a nonempty dot-separated sequence of `RichKeyV1` segments and
contains at most 64 segments. Dots separate path segments.

## Includes and modules

The `includes` body contains zero or more `include` nodes. The `modules` body
contains zero or more `module` nodes:

```kdl
include path="shared.kdl"
include path="theme.kdl" dependency="theme"
module "terminal"
module "palette" dependency="theme"
```

| Node | Arguments | Required properties | Optional properties | Body |
| --- | --- | --- | --- | --- |
| `include` | none | `path` string `PackPath` | `dependency` string alias | forbidden |
| `module` | one string contribution name | none | `dependency` string alias | forbidden |

An absent `dependency` selects the current exact pack authority. A present alias
selects one declared direct dependency. Includes must name a declared
config-document path; modules must name a declared export. Resolution uses only
the supplied locked authority graph. Include order and module order are
semantic, and every resolved edge retains its exact source range and target
provenance. See [document grammar](grammar.md#includes-modules-and-authority)
for graph rejection rules.

## Type declarations

The scalar type nodes are bodyless:

```kdl
type "bool"
type "integer"
type "unsigned"
type "float"
type "string"
type "path"
```

Every `type` node has exactly one string argument and no properties. Only
`list`, `record`, and `collection` require bodies. A list or collection body
contains exactly one `item-type` wrapper, which has no arguments or properties
and a body containing exactly one nested `type` node:

```kdl
type "list" {
    item-type {
        type "string"
    }
}
type "collection" {
    item-type {
        type "integer"
    }
}
```

A record body contains zero or more `field` nodes:

```kdl
type "record" {
    field "title" optional=#false {
        type "string"
        default {
            string "Malm"
        }
    }
}
```

Each `field` has exactly one string `RichKeyV1` argument, requires the boolean
property `optional`, and requires a body. Its body contains exactly one `type`
and at most one `default`. Field names are unique. A field `default` wrapper
contains exactly one recursively composed literal null, scalar, list, record,
or collection expression. It cannot contain a variable, `select`, or
`if-value`. The default must conform to the field type. Recursive defaults and
types are subject to the normal depth, item, and total-value limits.

## Variables

The `variables` section contains only `input` and `let` declarations:

```kdl
input "theme" optional=#false {
    type "string"
    default {
        string "dark"
    }
}
let "enabled" {
    type "bool"
    expression {
        bool #true
    }
}
```

| Node | Arguments | Required properties | Children |
| --- | --- | --- | --- |
| `input` | one string `RichNameV1` | `optional` boolean | exactly one `type`; optional `default` expression wrapper |
| `let` | one string `RichNameV1` | none | exactly one `type` and one `expression` wrapper |

Variable names are globally unique across the reachable document closure. An
input default may use any expression and is type-checked during evaluation. A
`let` is computed and cannot be supplied by the caller.

The four input states are determined only by `optional` and `default`:

| `optional` | `default` | Meaning when not supplied |
| --- | --- | --- |
| `#false` | absent | required input; evaluation fails |
| `#true` | absent | typed null |
| `#false` | present | evaluate and type-check the default |
| `#true` | present | evaluate and type-check the default |

## Expression wrappers and literals

Every expression wrapper has no arguments or properties, requires a body, and
contains exactly one expression node. This rule applies to `default`,
`expression`, `value`, `iterable`, `left`, `right`, and expression-context
`key`, `then`, and `else` wrappers.

The scalar expressions are:

| Expression | Arguments | Body | Result |
| --- | --- | --- | --- |
| `"null"` | none | forbidden | null |
| `bool` | one KDL boolean | forbidden | boolean |
| `integer` | one KDL integer in `i64` range | forbidden | signed integer |
| `unsigned` | one KDL integer in `u64` range | forbidden | unsigned integer |
| `float` | one finite KDL float | forbidden | normalized IEEE-754 float |
| `string` | one string | forbidden | bounded UTF-8 string |
| `path` | one string target path | forbidden | validated target-relative path |
| `variable` | one string `RichNameV1` | forbidden | named variable or lexical loop binding |

The null node name must be quoted because `null` is reserved by KDL v2. Integer,
unsigned, and float are distinct types and are never implicitly coerced.
Negative zero is normalized to positive zero; non-finite floats are rejected.

Aggregate expressions are:

```kdl
list {
    item { string "one" }
}
record {
    field "name" { variable "theme" }
}
collection {
    item "stable-key" { integer 1 }
}
```

`list` has no arguments or properties and requires a body of zero or more
`item` wrappers. Each wrapper has no arguments or properties and contains
exactly one expression. `record` and `collection` also have no arguments or
properties and require bodies. A record contains zero or more `field` nodes;
a collection contains zero or more `item` nodes. Each map child has one string
`RichKeyV1` argument, no properties, and exactly one expression child. Duplicate
keys are rejected.

Selection reads one key from a record or keyed collection:

```kdl
select key="name" {
    value { variable "record-value" }
}
```

`select` has no arguments, requires one string `key` property, and contains
exactly one `value` expression wrapper. Evaluation rejects any non-record and
non-collection value or a missing key.

A conditional expression requires all three shown children:

```kdl
if-value {
    condition {
        equal negated=#false {
            left { variable "theme" }
            right { string "dark" }
        }
    }
    then { string "night" }
    else { string "day" }
}
```

`if-value` has no arguments or properties. `condition` contains exactly one
condition; `then` and `else` each contain exactly one expression. Only the
selected branch is evaluated.

## Conditions

Conditions form a closed language:

| Condition | Properties | Children |
| --- | --- | --- |
| `boolean` | none | exactly one `value` expression wrapper |
| `is-set` | none | exactly one `value` expression wrapper |
| `equal` | required boolean `negated` | exactly one `left` and one `right` expression wrapper |
| `not` | none | exactly one `condition` wrapper |
| `all` | none | zero or more `condition` wrappers |
| `any` | none | zero or more `condition` wrappers |

Every condition node has no arguments and requires a body. `boolean` accepts
only a boolean result; there is no implicit truthiness. `is-set` is true exactly
when its expression is not null. Equality compares complete typed values, and
`negated=#true` returns inequality. `not` negates its child. `all` and `any`
short circuit in written order; empty `all` is true and empty `any` is false.

## Fragments and statements

The `fragments` section contains zero or more declarations:

```kdl
fragment "base-document" {
    statements {
        emit "text" { value { string "value" } }
    }
}
```

A `fragment` has one string `RichNameV1` argument, no properties, and a required
body containing exactly one `statements` section. The section has no arguments
or properties, requires a body, and contains zero or more statements. Fragment
names are globally unique across the reachable closure.

The `statements` section, fragment statement bodies, profile statement bodies,
loop bodies, and conditional branches accept these statement forms:

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
    do { /* zero or more statements */ }
}
for-range "index" from=1 through=4 {
    do { /* zero or more statements */ }
}
patch { /* zero or more patch operations */ }
```

| Statement | Arguments | Properties | Children or body |
| --- | --- | --- | --- |
| `emit` | one string `RichKeyV1` | none | exactly one `value` expression wrapper |
| `compose` | one string `RichNameV1` | none | body forbidden |
| `when` | none | none | exactly one `condition`, `then`, and `else`; branches contain statements |
| `for-each` | one value-binding `RichNameV1` | optional string `key-binding` | exactly one `iterable` expression wrapper and one statement `do` body |
| `for-range` | one binding `RichNameV1` | required `from` and `through` `i64` integers | exactly one statement `do` body |
| `patch` | none | none | zero or more ordered patch operations |

Ranges are inclusive and require `from <= through`. A `for-each` iterable must
evaluate to a list or keyed collection. List key bindings receive an unsigned
zero-based index; collection key bindings receive the canonical string key.
The key binding is optional. A loop cannot use one name for both bindings or
shadow an enclosing loop binding. Per-loop and aggregate iteration limits are
checked before executing a loop body.

## Ordered patches

Patch operations execute in written order. Later operations observe every
earlier result.

```kdl
patch {
    set path="record.field" { value { string "new" } }
    unset path="record.field" optional=#false
    list-append path="list" { value { integer 1 } }
    collection-insert path="items" {
        key { string "a" }
        value { integer 1 }
    }
    collection-replace path="items" {
        key { string "a" }
        value { integer 2 }
    }
    collection-remove path="items" optional=#true {
        key { string "missing" }
    }
    collection-replace-all path="items" {
        item "a" { integer 1 }
        item "b" { integer 2 }
    }
}
```

| Operation | Required properties | Body |
| --- | --- | --- |
| `set` | string `path` | exactly one `value` expression wrapper |
| `unset` | string `path`, boolean `optional` | forbidden |
| `list-append` | string `path` | exactly one `value` expression wrapper |
| `collection-insert` | string `path` | exactly one `key` and one `value` expression wrapper |
| `collection-replace` | string `path` | exactly one `key` and one `value` expression wrapper |
| `collection-remove` | string `path`, boolean `optional` | exactly one `key` expression wrapper |
| `collection-replace-all` | string `path` | zero or more `item` children |

Patch operations have no arguments. Each `collection-replace-all` item has one
string `RichKeyV1` argument, no properties, and exactly one direct expression
child; item keys are unique. Dynamic collection keys must evaluate to strings
that satisfy `RichKeyV1`.

`set` replaces or inserts a root field or a field whose parent is a record.
`unset` removes such a field and fails on absence unless `optional=#true`.
`list-append` requires an existing list. Collection insert requires absence;
replace requires presence; remove requires presence unless `optional=#true`.
Replace-all requires an existing collection and atomically replaces its keyed
contents after evaluating the replacement expressions.

## Slots and profiles

The `slots` section contains zero or more bodyless declarations:

```kdl
slot "config-provider" max=2
```

A `slot` has one string `RichNameV1` argument and required integer property
`max`. It has no body. `max` is in `1..=1024`. Slot names are globally unique
across the reachable closure. A selected profile closure cannot contribute more
outputs to a slot than its declared maximum.

The `profiles` section contains zero or more profiles:

```kdl
profile "desktop" abstract=#false {
    extends {
        profile "base"
    }
    statements { /* zero or more rich statements */ }
    outputs { /* zero or more desired outputs */ }
}
```

A `profile` has one string `RichNameV1` argument, requires boolean property
`abstract`, and requires a body containing exactly one `extends`, `statements`,
and `outputs` section. Each section has no arguments or properties and requires
a body. `extends` contains zero or more bodyless `profile` nodes, each with one
string `RichNameV1` argument. Duplicate direct parents are rejected.

Profile names are globally unique. All parent references and cycles are
validated across the reachable document closure. Parent order and statement
order are semantic. Each ancestor is applied once, before its child, in written
depth-first parent order. Abstract profiles may be inherited but cannot be
selected.

## Output declarations

Every output has one string `RichNameV1` argument, required string
`destination`, and optional string `slot`. Object outputs are bodyless:

```kdl
regular-file "config" destination=".config/app/config" source="assets/config" source-kind="asset" raw-digest="sha256-..." object-digest="sha256-..." byte-len=42 executable=#false slot="config-provider"
symlink "link" destination=".config/app-link" target="app/config"
canonical-tree "tree" destination=".local/share/app" digest="sha256-..."
decoded-archive "archive" destination=".local/share/sdk" source="assets/sdk.tar" source-kind="asset" raw-digest="sha256-..." object-digest="sha256-..." byte-len=1024 decoder="malm.posix-ustar.none" decoder-version=1 tree-digest="sha256-..."
```

| Output | Required properties in addition to `destination` | Optional properties | Body |
| --- | --- | --- | --- |
| `regular-file` | `source`, `source-kind`, `raw-digest`, `object-digest`, `byte-len`, `executable` | `slot`, `dependency` | forbidden |
| `symlink` | `target` | `slot` | forbidden |
| `canonical-tree` | `digest` | `slot` | forbidden |
| `decoded-archive` | `source`, `source-kind`, `raw-digest`, `object-digest`, `byte-len`, `decoder`, `decoder-version`, `tree-digest` | `slot`, `dependency` | forbidden |

`source`, `source-kind`, `raw-digest`, `object-digest`, `byte-len`, and optional
`dependency` form a pack-file reference. `source-kind` is exactly `asset`,
`template`, or `schema`; decoded archives require `asset`. `byte-len` is a
nonnegative `u64`. `decoder-version` is a nonnegative `u16`. Digest strings use
`sha256-` followed by 64 lowercase hexadecimal digits.

A symlink target is nonempty relative UTF-8 with slash separators, at most 4,096
bytes and 64 segments, and at most 255 bytes per segment. It rejects an initial
slash, backslashes, controls, empty segments, `.`, and `..`.

### Formatted files

`format-file` requires a body and the boolean property `executable`:

```kdl
format-file "settings" destination=".config/app/settings.json" executable=#false {
    built-in "canonical-json"
    options {
        option "pretty" { bool #true }
    }
    resources {
        resource "schema" source="schemas/settings.json" source-kind="schema" raw-digest="sha256-..." object-digest="sha256-..." byte-len=128
    }
}
```

Its body contains exactly one selector, exactly one `options`, and exactly one
`resources` section. Both sections have no arguments or properties and require
bodies even when empty.

| Selector | Arguments | Required properties | Body |
| --- | --- | --- | --- |
| `built-in` | one string, exactly `canonical-json`, `plain-text`, or `key-value` | none | forbidden |
| `component` | one string transform `RichNameV1` | `digest`, `interface` strings | forbidden |

A component `interface` must be exactly `format-component/v1`. The digest binds
the exact component. Its execution profile comes from the matching locked
component and is not a KDL property.

Each `option` has one string `RichNameV1` argument, no properties, and exactly
one direct recursively typed literal expression. Each `resource` has one string
`RichNameV1` argument, the required pack-file properties, optional `dependency`,
and no body. Option names and resource names are unique. See the
[format transform contract](transform.md) for built-in option semantics,
resource validation, and invocation limits.

## Evaluation boundary and rejection

Parsing retains only validated declarations, exact source bytes and ranges,
paths, booleans, names, digests, lengths, transform selectors, options, and
resource references. It does not open pack files, resolve canonical objects,
decode archives, invoke components, or inspect a deployment target.

Evaluation additionally rejects unresolved or cyclic includes, profiles,
variables, or fragments; duplicate global declarations or root emissions;
invalid types, selections, conditions, loops, or patches; unsafe or overlapping
destinations; unknown slots or too many providers; and every fixed resource
limit. Exact semantics and ceilings are defined by the
[canonical rich IR contract](rich-ir.md).
