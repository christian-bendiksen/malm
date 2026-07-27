# Clean Reset

A reset is needed when the current `malm` root is incompatible and nonempty.
Merely having run an older Malm version, or having a sibling `malm-v1`
directory, does not require one.

Malm does not convert old state. It also does not change an incompatible state
directory, so you can move that directory aside before starting again.

## Back Up The Old State

Stop every Malm process that can manage the same files. Find the state parent:

- If `XDG_STATE_HOME` is set, the parent is its value.
- Otherwise, the parent is `$HOME/.local/state`.

Move the complete `malm` directory to a backup name. Do not copy individual
files from it into the new directory. Set `state_parent` to the absolute parent
you found above:

```sh
state_parent="/absolute/path/to/state-parent"
mv -- "$state_parent/malm" "$state_parent/malm.backup"
```

Malm ignores a sibling `malm-v1` directory. Moving it is optional archival
cleanup; if you do move it, use a separate backup name. Keep any backups until
the new deployment is working as expected.

## Start Fresh

The state parent must already exist before initialization. It must be owned by
the current user, have no special permission bits, and have no group or other
write permission. When `XDG_STATE_HOME` is set, it must be an absolute,
normalized path. An invalid set value is an error; Malm does not fall back to
`$HOME/.local/state`.

For example, to create a new private parent at the default fallback path:

```sh
install -d -m 0700 -- "$HOME/.local/state"
```

Initialize an empty state directory:

```sh
malm store init
```

Then recreate the source lock and plans from your pack. Follow the
[basic workflow](../README.md#basic-workflow) to prepare, review, and apply a new
plan.

A reset does not remove files that Malm already deployed. Check those files
before applying the first new plan, and do not delete the backup until you no
longer need it.
