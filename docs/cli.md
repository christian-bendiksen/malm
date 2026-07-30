# Malm Command-Line Guide

## Get Help

Start with the built-in help. Add `--help` after a group or command to see its current options and required arguments.

```sh
malm --help
malm plan --help
malm plan apply --help
```

Use `malm --version` to print the installed version. The top-level command groups are `source`, `plan`, `namespace`, `store`, `object`, and `component`. The top-level leaf commands are `deploy` and `machine`.

## Normal Workflow

The usual workflow locks the source graph, prepares a saved plan, reviews it, and then applies that plan.

```sh
malm source lock create --source .
malm plan create --source . --profile workstation
malm plan show plan:0123abcd
malm plan apply plan:0123abcd
```

Use the plan ID printed by `plan create`; `plan:0123abcd` only illustrates the short form. Preparing with `plan create` does not apply anything.
`plan apply` uses the saved plan, so review it before approving changes.

`deploy` combines the common plan, review, and interactive apply flow:

```sh
malm deploy --source . --profile workstation
```

`--yes` skips the prompt only when no finding requires approval. Destructive findings require explicit approval.
Automation should use `plan create`, review the result, and pass its reported digest to `plan apply --approval <APPROVAL>`.

## Common Choices

Human command groups and `deploy` support `--format human|json`, `--color auto|always|never`, and `-v` or `--verbose`. `NO_COLOR` and `TERM=dumb` also suppress color.
The default namespace is `default`. Targets use `--target <NAME=ABSOLUTE_PATH>` and default to `home=$HOME`; repeat the option when needed. `--target-authority <TARGET_AUTHORITY>` selects which target a plan deploys into and defaults to `home`.

For scripts, use `--format json` on a normal command. The following example
creates a plan and reads its full ID and approval digest with `jq`:

```sh
set -e

plan_json=$(malm plan --format json create --source . --profile workstation)
plan_id=$(printf '%s\n' "$plan_json" | jq -er '.data.plan_id')
approval=$(printf '%s\n' "$plan_json" | jq -er '.data.approval_digest')

malm plan show "$plan_id"
# Stop here until the plan has been reviewed and approved.
malm plan apply "$plan_id" --approval "$approval"
```

Normal command errors are written to standard error and return a nonzero exit status, so `set -e` stops this script rather than continuing with missing or invalid values. See the [CLI JSON schema](../schemas/cli/v1/README.md) for exact JSON details.

## Set Up the Store

Check whether Malm's state store is ready, then initialize it once if needed. `malm store init` also creates a missing state parent (for example `~/.local/state`) with mode 700, as long as its deepest existing ancestor is user-owned and private.

```sh
malm store status
malm store init
malm store status
```

<a id="source-commands"></a>
## Check or Render a Pack

Validate a source pack before locking or planning it, or render a profile into an explicit directory to inspect the resulting files.

```sh
malm source check --source ./config
malm source render --source ./config --profile workstation --output ./rendered
malm source vars --source ./config --profile workstation
malm source vars --source ./config --profile workstation editor
```

`-o` is the short form of `--output`. Add `--overlays` to `render` or `vars` when declared machine-local overlays should be included.
The optional final argument to `vars` limits output to one input name. See the [authoring overview](authoring-types.md) for pack and profile syntax.

## Lock Sources

Create `malm.lock` after the pack checks successfully. Use `update` when the lock already exists and dependencies need to be resolved again. A pack with no dependencies needs no source grants:

```sh
malm source lock create --source ./config
malm source lock update --source ./config
```

The authoring guide uses this dependency-free form. Although source locking can
record a dependency graph, authoring plan preparation currently accepts only a
single pack. The dependency options below are for packs using the lower-level
rich configuration format.

If the pack declares a local dependency, grant its exact locator with `--allow-local`. Repeat the option when the pack has more than one local dependency:

```sh
malm source lock create --source . --allow-local vendor/theme
```

For an HTTPS Git dependency, grant its URL with `--allow-git`. New Git content
also needs temporary scratch space. Every scratch directory must be fresh,
empty, private, and used by only one operation. Run `malm source lock create
--help` or `malm source lock update --help` for those options.

The [dependency lock schema](../schemas/lock/v1/README.md) explains the lock
file itself.

## Create, Review, and Apply Plans

Create a plan from the current directory, another pack root, or a chosen lock.
A pack without dependencies needs no extra source grants.

```sh
malm plan create
malm plan create --source ./config --lock ./config/malm.lock --profile laptop
malm plan create --source ./config --allow-local vendor/theme
malm plan create --source ./config --allow-git https://example.com/theme.git
malm plan create --source ./config --cached
```

When the lock contains dependencies, grant the same local paths or Git URLs
that the plan needs to read. `--cached` uses only pack objects already in the
store. Run `malm plan create --help` when Git content needs new scratch space.

Review saved plans and their captured data:

```sh
malm plan list
malm plan show <PLAN>
malm plan inputs <PLAN>
malm plan transforms <PLAN>
malm plan artifact list <PLAN>
malm plan artifact show <PLAN> <ID>
malm plan artifact export <PLAN> <ID> --output ./artifact.bin
```

Apply interactively, allow an unprompted safe apply, or provide the exact approval digest printed during review:

```sh
malm plan apply <PLAN>
malm plan apply <PLAN> --yes
malm plan apply <PLAN> --approval <APPROVAL>
```

Apply uses the saved plan rather than creating a new one. A full plan ID starts with `pp-`; a displayed `plan:<hex>` short ID can also be used.

## Switch Profiles

Prepare a profile-change plan from the selected namespace's retained inputs:

```sh
malm plan switch-profile laptop --namespace default
```

Profile switching is offline. It creates a saved plan and does not apply it; review the returned plan ID with `plan show`, then use `plan apply`.

## Tracked Sources

The resolved commit must carry a `malm.lock` that is a regular file with mode `0644`, holds canonical `lock/v1` bytes, and requires the pack digest of that commit. Otherwise the operation fails with `tracked root is missing malm.lock`, `tracked root malm.lock is not canonical lock/v1 bytes`, or `tracked root lock requires pack <expected>, acquired <actual>`.
`malm source lock create` and `malm source lock update` write the lock of a local pack only. Commit the refreshed lock with the source it covers.

Track a moving Git selector by creating its first plan. `mktemp -d` creates a fresh directory, and `chmod` makes the required mode explicit:

```sh
track_scratch=$(mktemp -d)
chmod 0700 "$track_scratch"
malm plan track --source-url https://example.com/config.git \
  --selector refs/heads/main --git-executable /usr/bin/git \
  --root-scratch "$track_scratch"
```

`--source-subdir <SOURCE_SUBDIR>` and `--config-entry <CONFIG_ENTRY>` choose the pack and entry point; their defaults are `.` and `malm.kdl`.
Later, resolve the selector again and prepare an update plan with a separate fresh directory:

```sh
refresh_scratch=$(mktemp -d)
chmod 0700 "$refresh_scratch"
malm plan refresh --namespace default --git-executable /usr/bin/git \
  --root-scratch "$refresh_scratch"
```

Both commands prepare saved plans for separate review and apply. Each scratch directory must be empty, private, and used for only one operation. Never reuse a populated scratch directory. For tracked packs with Git dependencies, run `malm plan track --help` or `malm plan refresh --help` for the advanced scratch options.

## Lifecycle, Status, and History

Lifecycle actions prepare plans, so review and apply each returned plan:

```sh
malm plan disable --namespace default
malm plan enable --namespace default
malm plan remove --namespace default
malm plan restore <GENERATION> --namespace default
```

Inspect deployed namespaces, target status, and history directly:

```sh
malm namespace list
malm namespace show --namespace default
malm namespace status --namespace default
malm namespace history --namespace default
malm namespace generation show <GENERATION> --namespace default
malm namespace generation desired <GENERATION> --namespace default
malm namespace generation retention <GENERATION> --namespace default
malm namespace generation tracking <GENERATION> --namespace default
```

Use `--target <NAME=ABSOLUTE_PATH>` with `namespace status` for another target. A full generation ID starts with `sha256-`; `gen:<hex>` is the short form.
Retention changes are plans too:

```sh
malm plan retention set-history 10 --namespace default
malm plan retention pin <KIND> <OBJECT> --namespace default
malm plan retention unpin <KIND> <OBJECT> --namespace default
malm plan retention restore-point add <GENERATION> --namespace default
malm plan retention restore-point drop <GENERATION> --namespace default
```

Run `malm plan retention pin --help` for the accepted object kinds.

## Recovery and Cleanup

Verify the store alone or include managed-target observations:

```sh
malm store verify
malm store verify --observe-targets
```

After an interrupted apply or target transaction, run recovery before resuming normal work. Supply the same explicit targets used by that operation.

```sh
malm store recover
malm store recover --target home=/home/alice
```

If `malm store recover` fails, do not delete its journal or staging data and do not run `malm store gc`. Save the error output, back up the state root, and inspect it with `malm store verify` before asking for help.

After recovery succeeds, preview garbage collection before deleting anything:

```sh
malm store gc --dry-run
malm store gc
malm plan delete <PLAN_IDS>...
```

For diagnosis, `malm object tree show <TREE>` displays a retained tree,
and `malm component host-profile` reports the local component host profile.

## Machine Integration

`malm machine` reads one JSON request from standard input and writes JSON lines to standard output. For example, this request checks whether the store exists:

```sh
printf '%s\n' '{"schema_version":1,"request_id":"req-1","type":"request","request":{"type":"store_status"}}' | malm machine
```

When the store is absent, the two output lines are:

```jsonl
{"schema_version":1,"request_id":"req-1","sequence":0,"type":"event","event":{"type":"started","operation":"store_status"}}
{"schema_version":1,"request_id":"req-1","sequence":1,"type":"result","result":{"type":"store_status","status":"absent"}}
```

An accepted record produces a `started` line and then either a result or an operation error. A rejected record is invalid or unsupported; Malm does not run it, writes an error line, and exits nonzero. Use `machine` for integrations rather than as another spelling for the human commands. See the [machine protocol schema](../schemas/machine/v1/README.md) for exact requests and responses,
or the [schema index](../schemas/README.md) for all published data formats.
