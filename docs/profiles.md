# Malm profiles

Profiles activate modules and provide values for a particular setup. This complete `malm.kdl`
defines a reusable base and a selectable laptop profile:

```kdl
config target="~" default-profile="laptop"
module "terminal" {
    inputs {
        input "font-size" type="int" default=10
        input "shell" type="string" default="/bin/sh"
    }
    outputs {
        render (f)".config/example-terminal/{{instance.name:text}}.conf" format="text" separator="=" layout="flat" {
            font-size (ref)"font-size"
            shell (ref)"shell"
        }
    }
}
profile "base" abstract=#true {
    use "terminal" { with { shell "/bin/bash" } }
}
profile "laptop" {
    extends "base"
    use "terminal" { with { font-size 12 } }
}
```

The active terminal gets `shell` from `base`, `font-size` from `laptop`, and anything else from
module defaults. Inspect it before applying it:

```sh
malm check --all-profiles
malm --profile laptop vars
malm --profile laptop plan
```

## Activate modules with `use`
`use "terminal"` activates one module instance. Its alias defaults to the module name. Give
instances explicit aliases when the same module is needed more than once:

```kdl
profile "desktop" {
    use "terminal" as="work" { with { shell "/bin/bash" } }
    use "terminal" as="recovery" { with { shell "/bin/sh" } }
}
```

The alias identifies an instance while profiles are combined. Repeating `use` with the same alias
and module adds another layer; it does not create a new instance or reset unmentioned values:

```kdl
profile "base" { use "terminal" as="main" { with { shell "/bin/bash" } } }
profile "large" {
    extends "base"
    use "terminal" as="main" { with { font-size 16 } }
}
```

Here `main` keeps the inherited shell. One alias cannot name different modules in the same
resolved profile.

## Inherit profiles with `extends`
`extends` accepts one or more profile names:

```kdl
profile "desktop" abstract=#true {
    use "terminal"
    use "notifications"
}
profile "work" abstract=#true { use "terminal" { with { shell "/bin/bash" } } }
profile "workstation" {
    extends "desktop" "work"
    use "terminal" { with { font-size 14 } }
}
```

Malm recursively emits each parent's ancestors before that parent, processes parent branches in
written order, emits each profile once, and applies the selected profile last. This order controls
activation and ordered operations such as patches and fragment changes. Descendant `with` values
replace ancestor values for the same input.

If incomparable profile layers set the same input with different complete `with` values,
resolution reports a conflict. Resolve it in the child, or in a later branch layer that makes the
remaining incomparable values equal. Equal values are accepted. This check applies to whole-input
values; patches are ordered operations.

An `abstract=#true` profile is a reusable inheritance layer. It is validated and listed, but cannot
be selected for `plan`, `apply`, or `render`. Concrete profiles can extend it.

## Set complete values with `with`
A `with` entry supplies a complete value matching the module's input type:

```kdl
use "launcher" {
    with {
        theme "dark"
        fallback-fonts "Inter" "Noto Sans" "sans-serif"
        command { executable "walker"; arguments "--theme" "dark"; }
        actions {
            item { label "Lock"; command "loginctl lock-session" }
            item { label "Logout"; command "systemctl --user exit" }
        }
        notification-sound #null
    }
}
```

| Input type | Form |
|---|---|
| Scalar or enum | `name value` |
| List | `name value1 value2` |
| One-item list | `name value` |
| Record | `name { field value; other value; }` |
| List of records | `name { item { field value; }; item { field value; }; }` |
| Cleared optional | `name #null` |

A complete record must include every required field; optional fields may be omitted. `#null` works
only for optional inputs. Lists and collections are not optional because empty values represent
absence.

Do not mix arguments with a children block, put `#null` in a list, or repeat an input inside one
`with` block. Use `patch` when only part of a record or keyed collection should change.

## Patch record fields
`set` and `unset` edit one top-level record field while preserving the rest:

```kdl
profile "minimal" {
    use "window-manager" {
        patch {
            set "appearance.border-width" 0
            set "appearance.fonts" "Inter" "Noto Sans"
            unset "appearance.subtitle"
        }
    }
}
```

The path must be exactly `input.field`, with one dot. Nested paths are not supported. The input must
be a record and the field must exist in its schema. `set` takes one scalar, or several scalars for a
list field; it cannot take a children block or build a record-valued field. `unset` takes no value
and clears only an optional field. It cannot clear a required field, and `set` cannot use `#null` in
place of `unset`.

A record must exist before it can be patched. If an optional record is `#null`, or a required record
has no default, set the complete record with `with` first.

Malm resolves complete `with` values first, then applies record patches in profile order and
declaration order. Later operations on the same field win, so patch the field in the child when it
should override parent patches.

## Patch keyed collections
Collections are ordered items identified by stable string keys:

```kdl
use "window-manager" {
    patch {
        collection "bindings" {
            replace "terminal" { Mod+Return { spawn "foot" } }
            append "lock" { Mod+L { spawn "loginctl" "lock-session" } }
            remove "legacy-menu" optional=#true
        }
        collection "commands" {
            replace-all {
                item "build" "cargo build"
                item "test" "cargo test"
            }
        }
    }
}
```

| Operation | Effect |
|---|---|
| `replace "key" value` | Replace an existing item, preserving its position. |
| `append "key" value` | Add a new item at the end. |
| `remove "key"` | Remove an existing item. |
| `remove "key" optional=#true` | Remove the item if it exists. |
| `replace-all { item "key" value; }` | Rebuild the collection in listed order. |

`replace` requires an existing key, `append` requires a new key, and plain `remove` requires an
existing key. Keys in `replace-all` must be unique. Later operations see earlier results across
repeated `use` declarations and inherited profiles.

The payload must match the collection's `item-type`. String items use a second argument. Record
items can use properties, as in `replace "menu" chord="Alt+Space" command="walker"`, or field nodes
in a block. `kdl-document` items use a block in the syntax expected by the consuming output.

## Replace slot providers
Slots name roles filled by modules:

```kdl
slots { slot "compositor" max=1 }
module "sway" { slot "compositor"; outputs {} }
module "niri" {
    slot "compositor"
    inputs { input "gaps" type="int" default=8 }
    outputs {}
}
profile "sway-base" abstract=#true { use "sway" }
profile "niri-desktop" {
    extends "sway-base"
    replace slot="compositor" module="niri" { with { gaps 12 } }
}
```

Slot `max` defaults to `1`; `max="many"` allows any number of providers. For a single-provider slot,
`replace` deactivates the current provider and activates a module that declares the same slot. An
active provider must exist. Use `use` for an empty or multi-provider slot. `replace` also supports
`as=`, `with`, `patch`, and `fragments`.

## Change fragments
Fragments are named source files declared by a module:

```kdl
use "status-bar" {
    fragments {
        replace "config" source="./status-bar/config.jsonc"
        replace "style" source="./status-bar/base.css"
        append "style" source="./status-bar/compact.css"
    }
}
```

`replace` resets the fragment's source list to one source. `append` adds a source and works only with
`cardinality="many"`; a `cardinality="one"` fragment must use `replace`. Operations follow profile
linearization and declaration order.

A `./path` source resolves relative to the file containing the profile or `extend-profile`. Other
relative sources resolve from the workspace root. Malm rejects absolute paths, the path `~`, a `~/`
prefix, `..`, and `.//` prefixes.

## Organize configuration explicitly
Malm loads the root configuration and only the files named by `include`. It does not automatically
load a host file or a personal local file:

```kdl
config target="~" default-profile="workstation"
include "modules/terminal.kdl"
include "profiles/desktop.kdl"
include "machines/workstation.kdl" optional=#true
include "~/.config/malm/local.kdl" optional=#true
```

Relative includes start from the including file and may not escape the repository. `optional=#true`
permits a missing file. A `~/` or absolute include is an explicit local path; remote configuration
needs permission before Malm reads it. Relative includes reached from such a local file are confined
to that file's directory tree.

The `machines/workstation.kdl` and `~/.config/malm/local.kdl` names are only organization
conventions. Choose other names, omit them, or include several. Their contents participate only
when explicitly included.

### Extend a module or profile
`extend-module` adds new inputs, fragments, requirements, or outputs to an existing module:

```kdl
extend-module "display-manager" {
    inputs { input "internal-output" type="string" default="eDP-1" }
    requires { command "wlr-randr" }
}
```

It cannot redeclare an existing input or fragment. Added inputs are ordinary module inputs, so
profiles can configure them normally.

`extend-profile` adds parents, `use` entries, or `replace` entries to an existing profile:

```kdl
extend-profile "workstation" { use "terminal" { with { font-size 13 } } }
```

The target profile must exist. Its new entries are appended and then follow the normal inheritance
rules; an included local file gets no special precedence. Declare a profile once and use
`extend-profile` for additional explicit layers. An extension cannot change whether the profile is
abstract.

### Declare variables
`variables` defines scalar values in the `global.*` namespace:

```kdl
variables { global.font-family "Inter"; global.display-scale 1.5; global.reduce-motion #false; }
```

Globals are available to modules, but are separate from module inputs. They do not override `with`
or `patch` values. Replacing an existing global requires `override=#true` and must preserve its
value type:

```kdl
variables { global.font-family "Iosevka" override=#true }
```

An override needs an earlier declaration. Globals cannot be `#null`; use an optional module input
when absence is meaningful.

## Inspect profiles and values
```sh
malm profiles
malm profiles --selectable
malm --profile workstation vars
malm --profile workstation --json vars
```

`malm profiles` includes abstract profiles; `--selectable` hides them. `malm vars` shows built-ins,
globals and their origins, active instances, final input values, and value origins for the selected
or default profile. Inputs are qualified by alias, such as `work.font-size`. Use global `--repo` or
`--config` to inspect a different local configuration.

## Choose the operation
| Goal | Use |
|---|---|
| Activate or add an instance | `use`, with `as=` when needed |
| Share profile configuration | `extends` and an abstract profile |
| Swap a single slot provider | `replace slot= module=` |
| Assign a complete scalar, list, record, or optional | `with` |
| Change one record field | `patch` with `set` or `unset` |
| Edit keyed items | `collection` with `append`, `replace`, `remove`, or `replace-all` |
| Change module source files | `fragments` with `replace` or `append` |
| Add declarations from an included file | `extend-module` or `extend-profile` |
| Share scalar values across modules | `variables` |

Use `with` to replace a complete value. Use `patch` to retain unmentioned inherited record fields
or collection items.
