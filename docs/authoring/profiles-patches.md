# Compose Profiles And Override Values

A profile chooses module instances and their input values. Start with a shared
profile, then extend it for each setup you want to select.

## Share A Base Profile

```kdl
profile "base" abstract=#true {
    use "terminal"
    use "editor"
}

profile "work" {
    extends "base"
    use "terminal" {
        with {
            theme "light"
        }
    }
}

profile "evening" {
    extends "base"
    use "terminal" {
        with {
            theme "dark"
        }
    }
}
```

`extends` composes an existing profile into another profile. An abstract profile
is available for composition but cannot be selected directly. The later
`use "terminal"` adds values to the same module instance selected by `base`.

Set the usual choice on the root config node:

```kdl
config target="~/.config" default-profile="work"
```

Select another profile with `--profile evening` when rendering a preview or
creating a plan.

## Replace A Complete Input

Use `with` when the complete value is easy to state:

```kdl
profile "presentation" {
    extends "base"
    use "terminal" {
        with {
            theme "light"
            font family="Iosevka Aile" size=20 style="regular"
            fallbacks "monospace" "sans-serif"
        }
    }
}
```

Each `with` entry replaces one input. This is simple for scalars and lists. For
a record, include every required, non-optional field that has no field default.

## Change One Nested Field

A patch changes part of an existing value. Use `set` with a dotted path to keep
the other fields:

```kdl
profile "large-text" {
    extends "base"
    use "terminal" {
        patch {
            set "font.size" 16
            set "font.style" "semibold"
        }
    }
}
```

Here, `patch` is an ordered list of small changes. Each `set` sees the result of
the previous operation. Every intermediate record must already exist.

Use `unset` to clear a field declared `required=#false`, such as the optional
`style` field from the record in [Define Reusable
Configuration](types.md#group-related-values):

```kdl
patch {
    unset "font.style"
}
```

An optional type alone does not make a required field clearable. A
non-optional field with a default is also not clearable because `unset` would
make its value null.

The path starts with the input name. It may continue through nested records,
such as `appearance.font.size`.

## Update A Collection

Collection patches work with stable item keys:

```kdl
patch {
    collection "bindings" {
        replace "copy" keys="Super+C" action="copy"
        append "new-tab" keys="Super+T" action="new-tab"
        remove "paste"
    }
}
```

`replace` keeps an existing key in its current position. `append` adds a new
key. `remove` deletes a key. Use `replace-all` when the whole collection should
be restated:

```kdl
patch {
    collection "bindings" {
        replace-all {
            item "copy" keys="Super+C" action="copy"
            item "paste" keys="Super+V" action="paste"
        }
    }
}
```

## Compose More Than One Parent

A profile may extend several parents:

```kdl
profile "laptop-work" {
    extends "laptop" "work"
}
```

Keep sibling parents focused on separate inputs. If they assign different
values to the same module input, Malm asks you to resolve the conflict in an
explicit profile layer.

## Add A Machine-Local Overlay

An overlay is an optional KDL file outside the pack that supplies local values.
Declare its path in the root `malm.kdl`:

```kdl
overlay "local" path="~/.config/malm/local.kdl" optional=#true
```

The local file can extend an existing profile:

```kdl
extend-profile "work" {
    use "terminal" {
        with {
            size 14
        }
    }
}
```

Overlays are for values tied to one machine. Keep modules, outputs, and included
files in the pack. `malm source render` and `malm source vars` read declared
overlays only when passed `--overlays`. Applied overlays are shown as plan
inputs during deployment.

Run `malm source vars --source ./my-pack --profile work` to inspect resolved
inputs and where each value came from. For the Rust evaluation contract, see the
[`malm-authoring` crate docs](../../crates/malm-authoring/README.md).
