# Malm templating and rendering

Malm renders configuration from typed module inputs. You describe the shape of
the output in KDL, then use references where values should be inserted.

Use `malm check` while editing to validate `malm.kdl`. Use `malm render` to
write generated files into a preview directory, and `malm plan` to see what a
deployment would change.

## A complete example

This configuration renders a TOML file for an editor:

```kdl
config target="~" default-profile="main"

module "editor" {
    inputs {
        input "theme" type="enum" default="light" {
            values "light" "dark"
        }
        input "font-size" type="int" default=12
        input "show-tabs" type="bool" default=#true
    }

    outputs {
        render ".config/example-editor/settings.toml" format="toml" {
            editor {
                theme (ref)"theme"
                font-size (ref)"font-size"
                message (f)"Using the {{theme}} theme"

                tabs {
                    visible (ref)"show-tabs"
                }
            }
        }
    }
}

profile "main" {
    use "editor" {
        with {
            theme "dark"
            font-size 14
        }
    }
}
```

The result is:

```toml
[editor]
theme = "dark"
font-size = 14
message = "Using the dark theme"

[editor.tabs]
visible = true
```

Try it without deploying anything:

```sh
malm --repo . check
malm --repo . render --output ./preview
```

The generated file will be at
`preview/.config/example-editor/settings.toml`.

## Choose an output format

Every rendered file starts with a `render` declaration:

```kdl
render "path/to/file" format="toml" {
    // output body
}
```

The most common formats share the same basic structure:

| Format | Typical use |
|---|---|
| `json` | Strict JSON |
| `jsonc` | JSON with comments |
| `toml` | TOML configuration |
| `ini` | INI files |
| `text` | Key-value files and line-oriented formats |
| `lua` | Lua data tables or small Lua programs |

KDL, XML, and CSS are also supported, but their bodies follow the structure of
the target format rather than the shared structure described below.

## Describe structured data

For JSON, JSONC, TOML, INI, text, and Lua, ordinary KDL nodes describe values
and sections:

```kdl
name "malm"
enabled #true
ports 8080 8081

server {
    host "localhost"
    timeout 30
}

windows {
    - title="terminal" floating=#false
    - title="picture-in-picture" floating=#true
}
```

Malm handles the punctuation and escaping for the selected format. Some shapes
do not make sense in every format. For example, INI cannot represent an array
of objects. `malm check` reports those problems before you deploy.

Text output has a few useful options:

```kdl
render ".config/app/settings.conf" format="text" separator="=" layout="flat" {
    theme "dark"
    font-size 12
}
```

This produces:

```text
theme=dark
font-size=12
```

## Insert typed values with `(ref)`

Use `(ref)` when an input should become a value in the generated document:

```kdl
enabled (ref)"enabled"
port (ref)"port"
theme (ref)"theme"
```

The value keeps its type. A boolean remains a boolean, an integer remains an
integer, and a list becomes an array when the output format supports arrays.
This is usually better than turning everything into text.

References can point to module inputs, record fields, loop variables, globals,
and built-in values such as `profile.name` and `machine.hostname`.

### Optional values

Use `(ref?)` when an optional value should disappear from the output when it is
unset:

```kdl
accent (ref?)"accent"
```

If `accent` has no value, Malm omits the whole entry.

For several entries controlled by the same optional, use `@when-set`:

```kdl
@when-set "accent" {
    accent (ref)"accent"
    use-custom-accent #true
}
@else {
    use-custom-accent #false
}
```

## Build strings with `(f)`

Use `(f)` when you need to combine values into one string:

```kdl
mode (f)"{{width}}x{{height}}@{{refresh}}Hz"
label (f)"Profile: {{profile.name}}"
```

Plain strings do not interpolate. This stays exactly as written:

```kdl
shell-example "${HOME}/bin"
```

Placeholders use one of these forms:

| Form | Meaning |
|---|---|
| `{{name}}` | Insert a scalar as text |
| `{{name:codec}}` | Encode a value for another syntax |
| `{{literal "{{text}}"}}` | Insert literal braces |

Useful codecs include:

| Codec | Use |
|---|---|
| `json` | Encode a scalar as JSON |
| `toml-string` | Encode a TOML string |
| `shell-word` | Quote one POSIX shell argument |
| `lua` | Encode a scalar as a Lua literal |
| `raw` | Insert scalar text without escaping |

Prefer `(ref)` when the value stands on its own. Use `(f)` only when you are
building a larger string.

## Conditions

Use `@when` for boolean inputs or simple comparisons:

```kdl
@when "notifications" {
    notifications-enabled #true
}

@when "theme" is="dark" {
    contrast "high"
}
@else {
    contrast "normal"
}
```

`@else` must immediately follow the matching condition. Malm does not treat
arbitrary values as true or false; `@when` without either `is=` or `is-not=`
expects a boolean.

## Loops

Use `@each` to repeat output for a list or collection:

```kdl
@each "plugin" in="plugins" {
    @line (f)"plugin={{plugin}}"
}
```

Use `@range` for a fixed numeric range:

```kdl
@range "workspace" from=1 through=4 {
    @line (f)"workspace={{workspace}}"
}
```

Both ends of a range are included.

Use `@spread` to turn a record's fields into entries:

```kdl
@spread "appearance" case="snake_case"
```

For profile-driven structured additions, collection patching, and fragments,
see [Profiles](profiles.md).

## Include files

Use `@file` when a script or block of text is easier to maintain as a normal
repository file:

```kdl
render ".local/bin/apply-theme" format="text" executable=#true {
    @file "./apply-theme.sh" interpolate=#true
}
```

`interpolate=#true` applies the same `{{name}}` placeholders used by `(f)`.
Without it, the file is inserted as ordinary text.

A path beginning with `./` is relative to the file that declares the module.
Other relative paths start at the repository root. Source paths cannot use
absolute paths, `~`, or `..`.

Fragments are named source files declared by a module. A module can provide
default sources, and profiles can replace them. In a text render, use
`@compose "fragment-name"` to insert the resulting text. KDL outputs use
`compose fragment="fragment-name"`.

## KDL, XML, and CSS

These formats use bodies designed for the target language.

A KDL output looks like normal KDL with typed references where values are
needed:

```kdl
render ".config/niri/config.kdl" format="kdl" version=2 {
    layout {
        gaps (ref)"gaps"
    }
}
```

XML uses element nodes with helpers such as `attr`, `empty`, and `repeat`:

```kdl
render ".config/app/config.xml" format="xml" declaration=#true {
    settings {
        attr "name" "example"
        theme (ref)"theme"
    }
}
```

CSS uses declaration and selector nodes. `field` is useful for selectors and
custom properties that are awkward KDL node names:

```kdl
render ".config/app/theme.css" format="css" {
    field ":root" {
        field "--accent" (ref)"accent"
    }
    field ".window" {
        color (ref)"foreground"
        border (f)"1px solid {{accent}}"
    }
}
```

CSS declaration values accept `(f)` when literal CSS text and typed values need
to be composed. They use the same placeholders and codecs as other formatted
values. Optional placeholders must be guarded with `when-set`, and the rendered
value is still rejected if it introduces CSS declaration or block structure.

Run `malm check` after changing one of these bodies. Their rules are stricter
than the shared JSON, TOML, INI, text, and Lua structure.

## Preview before applying

A normal editing loop is:

```sh
malm --repo . check
malm --repo . render --output ./preview
malm --repo . plan
malm --repo . apply
```

`check` validates the configuration. `render` lets you inspect generated files.
`plan` previews deployment operations. `apply` writes the selected deployment.

Use a new or empty preview directory. `render` can replace files already
present in that directory, and a failed render can leave earlier outputs in
place.
