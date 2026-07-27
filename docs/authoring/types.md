# Define Reusable Configuration

Use inputs for values that may change between profiles. Keep values that always
move together in one record, and name repeated shapes in a module's `types`
block.

## Start With Inputs

This module offers a few simple choices:

```kdl
module "terminal" {
    description "terminal settings"
    inputs {
        input "family" type="string" default="Iosevka"
        input "size" type="int" default=12
        input "antialias" type="bool" default=#true
        input "title" type="string?"
        input "fallbacks" type="list<string>" {
            default "monospace" "sans-serif"
        }
    }
}
```

An input is a named value owned by a module. A default makes the input usable
without extra profile configuration. The common scalar types are `bool`, `int`,
`float`, `string`, and `path`. Add `?` to allow `#null`.

`list<T>` is an ordered list. Its default uses several KDL arguments. Profiles
can replace it in the same shape:

```kdl
profile "large-text" {
    use "terminal" {
        with {
            size 16
            fallbacks "monospace" "serif"
        }
    }
}
```

The `with` block chooses input values for this module instance. Each entry
replaces that complete input.

## Group Related Values

A record gives names and types to related fields. An enum limits a string to a
short set of choices:

```kdl
module "terminal" {
    description "terminal settings"
    types {
        enum "theme-name" {
            values "light" "dark"
        }
        record "font-settings" {
            fields {
                field "family" type="string" required=#true
                field "size" type="int" required=#true default=12
                field "style" type="string?" required=#false
            }
        }
    }
    inputs {
        input "theme" type="theme-name" default="dark"
        input "font" type="font-settings" {
            default family="Iosevka"
        }
    }
}
```

Types declared in `types` are reusable inside that module. Omitting a field
fails only when the field is required, has a non-optional type, and has no field
default. An omitted field with a default uses that default. Other allowed
omissions, including optional fields, become `#null`.

Scalar record fields can be KDL properties, as in
`default family="Iosevka"`. Child nodes are useful when a field contains
another record or list:

```kdl
default enabled=#true {
    font family="Iosevka" size=12
    tags "terminal" "desktop"
}
```

Use the same shape in a profile. Remember that this replaces the whole record:

```kdl
with {
    theme "light"
    font family="Iosevka Aile" size=15 style="regular"
}
```

Use a [patch](profiles-patches.md#change-one-nested-field) when only one nested
field should change.

## Keep Keyed Values

A collection is an ordered set of named items. It is useful for key bindings,
devices, or named servers:

```kdl
types {
    record "binding" {
        fields {
            field "keys" type="string" required=#true
            field "action" type="string" required=#true
        }
    }
}
inputs {
    input "bindings" type="collection<binding>" {
        defaults {
            item "copy" keys="Ctrl+C" action="copy"
            item "paste" keys="Ctrl+V" action="paste"
        }
    }
}
```

Each item has a stable key such as `copy`. A list is addressed by position; a
collection is addressed by key. `map<T>` has the same item shape but sorts its
keys. `set<T>` sorts and removes duplicate scalar values.

## Derive A Scalar Default

A scalar default can refer to another input with a formatted string:

```kdl
inputs {
    input "theme" type="string" default="dark"
    input "title" type="string" default=(f)"{{theme}} terminal"
}
```

Malm resolves `title` after applying profile values. If a profile supplies
`title`, that value is used instead.

## Render Optional Values

Use `(ref)` to insert a required value. Use `@if-present` before reading an
optional value:

```kdl
render "terminal/settings.json" format="json" {
    theme (ref)"theme"
    @if-present "title" {
        title (ref)"title"
    }
}
```

This guide covers the common types used by most packs.
