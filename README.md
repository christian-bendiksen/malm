# Malm

Malm deploys configuration files from a source pack. A pack is a directory that
declares its configuration files and named profiles, such as `desktop`.

Malm records the exact source inputs, creates a saved plan for review, and then
applies only that reviewed plan. Applying a plan does not read the source again
or use the network.

## Requirements

Malm requires Rust 1.95.0 and 64-bit GNU/Linux on x86_64 or aarch64. Git is
required only for packs and dependencies acquired from Git.

Run this command from the repository root. Cargo is the build tool included with
Rust. It puts `malm` in `~/.cargo/bin`, which must be in `PATH`.

```sh
cargo install --locked --path .
```

To build without installing, run `cargo build --locked --release` and use
`./target/release/malm` in place of `malm` below.

## Basic Workflow

Start with a pack that contains `malm-pack.kdl` and a root `malm.kdl`. If you do
not have a pack, read [Create a Malm Pack](docs/authoring-types.md) for the
configuration and the [pack manifest guide](schemas/pack/v1/grammar.md) for
`malm-pack.kdl`.

Before initializing the store, its state parent must already exist and be owned
by the current user. It must not be writable by the group or other users, and it
must not have special permission bits. The parent is `$XDG_STATE_HOME`, or
`$HOME/.local/state` when `XDG_STATE_HOME` is unset. For a missing parent, create
a private directory first:

```sh
state_parent=${XDG_STATE_HOME:-"$HOME/.local/state"}
install -d -m 700 "$state_parent"
```

Replace `/absolute/path/to/pack` with the pack's full path. The commands below
run from any directory:

1. Initialize the state store for plans and other saved data.

   ```sh
   malm store init
   ```

2. Record the pack's exact inputs in `malm.lock`.

   ```sh
   malm source lock create --source /absolute/path/to/pack
   ```

3. Prepare and save the `desktop` profile without applying it.

   ```sh
   malm plan create --source /absolute/path/to/pack --profile desktop
   ```

4. Review the saved plan. Replace `PLAN_ID` with the identifier from step 3.

   ```sh
   malm plan show PLAN_ID
   ```

5. Apply that exact plan. At an interactive terminal, Malm shows it again and
   asks for consent.

   ```sh
   malm plan apply PLAN_ID
   ```

See the [CLI reference](docs/cli.md) for automation and other workflows.

## Clean Reset Warning

Fresh installs can skip this section. Malm does not convert saved state from
older layouts. If this machine has run an older Malm build, read
[Clean Reset](docs/clean-reset.md) before using saved Malm state.

## Documentation

- Write configuration: [Create a Malm Pack](docs/authoring-types.md) and
  [Pack Manifest](schemas/pack/v1/grammar.md)
- Run or automate Malm: [CLI Reference](docs/cli.md)
- Find other guides: [Documentation Index](docs/index.md)
- Understand the design: [Architecture](docs/architecture.md)
- Contribute changes: [Contributing](CONTRIBUTING.md)
- Implement a data contract: [Versioned Schemas](schemas/README.md)
