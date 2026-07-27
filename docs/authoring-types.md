# Create a Malm Pack

A small pack can start with two files:

```text
my-pack/
|-- malm-pack.kdl
`-- malm.kdl
```

`malm-pack.kdl` describes the files that belong to the pack. Start with this
manifest and choose a package ID that you control:

```kdl
pack schema-version=1 package-id="com.example.my-pack" {
    modules {
    }
    config-documents {
        document "malm.kdl"
    }
    dependencies {
    }
    templates {
    }
    schemas {
    }
    assets {
    }
    components {
    }
}
```

Keep the `dependencies` section empty for this authoring workflow. Authoring
plans currently use one pack. Dependency graphs are available to the lower-level
rich configuration format, but not to authoring plan preparation.

Malm files use KDL. A KDL node has a name, arguments, properties, and sometimes
a child block. For example, `document "malm.kdl"` has one string argument,
while `pack schema-version=1` has an integer property. Braces contain child
nodes. Newlines usually separate nodes.

Put the configuration itself in `malm.kdl`:

```kdl
config target="~/.config" default-profile="desktop"

module "terminal" {
    description "terminal settings"
    inputs {
        input "font-size" type="int" default=12
    }
    outputs {
        render "terminal/config" format="text" {
            @line (f)"font-size={{font-size}}"
        }
    }
}

profile "desktop" {
    use "terminal"
}
```

A module is a reusable piece of configuration. It declares the values it needs
and the files it can produce. Here, `font-size` is an input: a named value that
profiles may choose. Its default is the integer `12`.

An output is a file produced by a module. The `render` node above writes
`terminal/config` below the configured target. `(f)` marks a formatted string,
and `{{font-size}}` inserts the resolved input value.

A profile is a named setup. It chooses modules and may supply their inputs. The
`desktop` profile uses `terminal`, so it gets that module's output.

Check the source before rendering it:

```sh
malm source check --source ./my-pack
malm source render --source ./my-pack --profile desktop --output ./preview
```

The preview contains `.config/terminal/config` with this content:

```text
font-size=12
```

## Build From Here

- [Define reusable configuration and choose values](authoring/types.md) with
  scalar inputs, records, enums, lists, collections, and defaults.
- [Compose profiles and override nested values](authoring/profiles-patches.md)
  with `extends`, `with`, patches, and optional local overlays.
- [Render files and include source files](authoring/rendering-components.md) in
  text, JSON, JSONC, TOML, INI, KDL, XML, CSS, or Lua. The same page covers
  optional WebAssembly components.
- [Use the source commands](cli.md#check-or-render-a-pack) to check, inspect,
  and preview a pack.

For the complete manifest contract, see the [pack/v1 schema](../schemas/pack/v1/README.md)
and its [KDL grammar](../schemas/pack/v1/grammar.md). Rust integrations can use
the [`malm-authoring` crate docs](../crates/malm-authoring/README.md).
