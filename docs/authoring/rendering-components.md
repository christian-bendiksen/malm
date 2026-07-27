# Render Files And Include Sources

An output is a target file produced by a module. Declare outputs in the module
that owns their inputs:

```kdl
outputs {
    render "terminal/config" format="text" {
        @line (f)"theme={{theme}}"
        @line (f)"font={{font.family}}"
        @line (f)"size={{font.size}}"
    }
}
```

The destination is relative to `config target=`, unless it starts with `~/`.
`@line` writes one scalar value followed by a newline. `(f)` marks a formatted
string. Use `(ref)` when the whole value comes from one input:

```kdl
@line (ref)"theme"
```

## Render Structured Formats

JSON, JSONC, TOML, INI, Lua, KDL, XML, and CSS have built-in renderers. The
body stays close to the shape of the target format.

JSON objects use named nodes. A block of `-` nodes becomes an array:

```kdl
render "terminal/settings.json" format="json" {
    theme (ref)"theme"
    font {
        family (ref)"font.family"
        size (ref)"font.size"
    }
    plugins {
        @for-each "plugin" in="plugins" {
            - (ref)"plugin"
        }
    }
}
```

For a dark theme, the default font, and `plugins` containing `git` and
`search`, this renders:

```json
{
  "theme": "dark",
  "font": {
    "family": "Iosevka",
    "size": 12
  },
  "plugins": [
    "git",
    "search"
  ]
}
```

TOML tables and INI sections also use child blocks:

```kdl
render "terminal/settings.toml" format="toml" {
    theme (ref)"theme"
    font {
        family (ref)"font.family"
        size (ref)"font.size"
    }
}

render "terminal/settings.ini" format="ini" {
    general {
        theme (ref)"theme"
    }
    font {
        family (ref)"font.family"
        size (ref)"font.size"
    }
}
```

KDL output uses ordinary KDL nodes. Malm controls keep their `@` prefix, so
unsigiled names remain output data:

```kdl
render "terminal/settings.kdl" format="kdl" {
    theme (ref)"theme"
    font family=(ref)"font.family" size=(ref)"font.size"
}
```

XML uses one root element. `attr` adds an attribute:

```kdl
render "terminal/settings.xml" format="xml" declaration=#true {
    settings {
        attr "theme" (ref)"theme"
        font (ref)"font.family"
    }
}
```

CSS uses blocks for rules and values for declarations. Use `field` when a name
is easier to write as a string:

```kdl
render "terminal/colors.css" format="css" {
    field ":root" {
        field "--accent" (ref)"accent"
    }
}
```

Use `format="text"` for free-form text. `key-value`, `line-list`, and `scalar`
are text layouts for common simple files.

## Choose What To Render

Use conditions and loops inside an output:

```kdl
render "terminal/config" format="text" {
    @if "antialias" {
        @line "antialias=true"
    }
    @if-present "title" {
        @line (f)"title={{title}}"
    }
    @if-nonempty "plugins" {
        @for-each "plugin" in="plugins" {
            @line (f)"plugin={{plugin}}"
        }
    }
}
```

`@if` reads a boolean. `@if-present` checks an optional value.
`@if-nonempty` accepts non-optional lists, sets, maps, and collections; it does
not accept strings. `@for-each` binds one item at a time. If a condition has an
`@else`, place it immediately after the condition.

## Include A File From The Pack

For a text or Lua program output, include a source file relative to the module's
KDL file:

```kdl
render "terminal/config" format="text" {
    @include-file "./config-header.txt"
    @line (f)"theme={{theme}}"
}
```

The included file must be captured with the pack. It is not read from the
target machine. Add `interpolate=#true` to resolve `{{input}}` placeholders in
the included text:

```kdl
@include-file "./config-body.txt" interpolate=#true
```

## Optionally Use A Component

A component is a sandboxed WebAssembly formatter bundled in the pack. Use one
when the built-in formats do not match the target file. Declare the component in
`malm-pack.kdl`, then select it on an output:

```kdl
render "terminal/theme.lua" format="lua" component-renderer="lua-renderer" {
    theme (ref)"theme"
    font {
        family (ref)"font.family"
        size (ref)"font.size"
    }
}
```

Malm resolves the body to typed data and passes it to `lua-renderer`. A component
can also transform bytes produced by a built-in renderer:

```kdl
render "terminal/theme.lua" format="lua" {
    @component-transform "check-lua"
    theme (ref)"theme"
}
```

Transforms run in declaration order. A component must implement Malm's WIT
interface, be copied into the pack, and be declared in `malm-pack.kdl` with its
SHA-256 digest. See [Format Components](../format-component-admission.md) for
those steps.

`malm source render` does not execute components. It refuses the render when any
selected output uses a component renderer or transform, and names those outputs
in the error. To inspect component output, create a plan, use the plan ID to
list its artifacts, and then show or export the component-produced artifact:

```sh
malm plan create --source ./my-pack --profile work
malm plan artifact list <PLAN>
malm plan artifact show <PLAN> <ID>
malm plan artifact export <PLAN> <ID> --output ./theme.lua
```

For component manifest fields and the guest interface, see the
[format-component/v1 schema](../../schemas/format-component/v1/README.md).
