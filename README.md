# Malm

Malm is a declarative configuration manager for Linux. You describe your
configuration in `malm.kdl`, group it into profiles, and let Malm render and
deploy the result.

Malm can:

- Render JSON, TOML, INI, text, Lua, KDL, XML, and CSS files.
- Deploy files and directories from a configuration repository.
- Keep separate profiles for different machines or setups.
- Preview changes before applying them.
- Track deployed files and report drift.
- Recover from interrupted deployments.

## Install

Malm currently builds from source and requires Linux, Rust 1.95 or newer, and
Cargo.

From a Malm source checkout:

```sh
cargo install --locked --path .
```

Git is also required when using remote configuration repositories.

## Quick start

Create a directory for your configuration and add a `malm.kdl` file:

```kdl
config target="~" default-profile="main"

module "terminal" {
    inputs {
        input "theme" type="enum" default="light" {
            values "light" "dark"
        }
    }

    outputs {
        render ".config/example-terminal/settings.toml" format="toml" {
            appearance {
                theme (ref)"theme"
            }
        }
    }
}

profile "main" {
    use "terminal" {
        with {
            theme "dark"
        }
    }
}
```

This renders:

```toml
[appearance]
theme = "dark"
```

Run these commands from the directory containing `malm.kdl`:

```sh
malm --repo . check
malm --repo . plan
malm --repo . render --output ./preview
malm --repo . apply
malm status
```

Each command has a separate job:

| Command | What it does |
|---|---|
| `malm check` | Validates the configuration without deploying. Use `--all-profiles` to validate every profile. |
| `malm plan` | Shows the filesystem changes Malm would make. |
| `malm render --output DIR` | Writes the selected profile's outputs to a preview directory without deploying them. |
| `malm apply` | Applies the selected profile. |
| `malm status` | Checks the deployed configuration for drift. |

Use a new or empty directory with `malm render`. Existing files in the output
directory may be replaced.

## Deploy repository files

Not every file needs to be generated. A module can also deploy files and
directories already stored in the repository:

```kdl
module "dotfiles" {
    outputs {
        file "files/gitconfig" to="~/.gitconfig"
        dir "config/nvim" to="~/.config/nvim"
    }
}

profile "main" {
    use "dotfiles"
}
```

Malm deploys managed symlinks to an internal snapshot of the repository. If a
regular file already exists at a managed destination, the default conflict
policy backs it up before replacing it.

## Profiles

Profiles activate modules and provide input values. They can inherit from one
another:

```kdl
profile "base" abstract=#true {
    use "terminal"
}

profile "work" {
    extends "base"
    use "terminal" {
        with {
            theme "light"
        }
    }
}
```

Select a profile with the global `--profile` option:

```sh
malm --repo . --profile work plan
malm --repo . --profile work apply
```

See [Profiles](docs/profiles.md) for inheritance, patches, collections, slots,
and fragments.

## Work with another repository

Use `--repo` when the configuration is not in the current directory:

```sh
malm --repo ~/dotfiles check
malm --repo ~/dotfiles plan
malm --repo ~/dotfiles apply
```

Malm looks for `malm.kdl` at the repository root. Use `--config` for another
path inside that repository:

```sh
malm --repo ~/dotfiles --config hosts/laptop.kdl check
```

## Remote repositories

Remote repositories must use HTTPS. Review a specific revision before applying
it:

```sh
malm plan https://example.com/user/dotfiles.git --commit "$COMMIT_SHA"
malm apply https://example.com/user/dotfiles.git \
    --commit "$COMMIT_SHA" \
    --trust-remote
```

A remote apply requires `--trust-remote` and one of `--commit`, `--tag`, or
`--branch`. An exact commit is the easiest option to review and reproduce.

To follow a branch:

```sh
malm apply https://example.com/user/dotfiles.git \
    --branch main \
    --trust-remote \
    --track
malm update
```

Remote configurations cannot read local absolute or home-relative includes
unless `--allow-local-includes` is granted explicitly.

## State and recovery

Malm records deployments under `$XDG_STATE_HOME/malm`, or
`~/.local/state/malm` when `XDG_STATE_HOME` is unset.

Useful commands include:

| Command | What it does |
|---|---|
| `malm state list` | Lists deployment states. |
| `malm state log` | Shows transaction history. |
| `malm state checkout ID` | Restores a previous deployment. |
| `malm state disable` | Removes deployed targets while keeping a restore point. |
| `malm state enable` | Restores a disabled deployment. |
| `malm state fsck` | Checks state records. |
| `malm state recover --all` | Attempts to recover interrupted transactions. |
| `malm state prune --dry-run` | Previews removal of old history. |

Use `--state NAME` to keep independent deployments:

```sh
malm --state laptop --repo . apply
malm --state laptop status
```

If a deployment is interrupted, Malm blocks further mutations until recovery
has handled the unfinished transaction.

## Other useful commands

```sh
malm profiles
malm vars
malm doctor
```

`profiles` lists available profiles. `vars` shows resolved values for the
selected profile. `doctor` checks command and file requirements declared by
active modules; it does not install packages.

## Further reading

- [Profiles](docs/profiles.md)
- [Templating and rendering](docs/templating.md)
