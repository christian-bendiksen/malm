# malm-commit

`malm-commit` applies an approved immutable plan to Malm state and managed
targets. After review and approval, Engine uses this crate for commit, recovery,
inspection, and stored-object cleanup.

Ordinary users should use the Malm CLI, and Rust applications should use
`malm_engine::Engine`. This crate is the lower-level state transition boundary
for maintainers and specialized embedders.

## Commit Checks

Commit works only from the local store. Before changing a target, it rechecks
the plan and approval, current namespace state, ownership, path safety, recorded
target observations, and every referenced object digest. Missing, corrupt,
stale, unsafe, or unauthorized data is an error; commit does not fetch source,
parse configuration, render output, or start a component runtime.

A global lock serializes cooperating Malm transactions. Named target authorities
grant access only to their configured filesystem roots.

## Crash Recovery

Before mutation, commit durably records what transaction is in progress. After
an interruption, `recover_v1` uses that journal to restore the prior state or,
after catalog publication, finish the exact approved state. It does not infer
intent from whatever files happen to exist.

Most process and machine crash points are recoverable. If a newly created
directory cannot be identified safely, recovery stops instead of guessing and
may require manual action.

## Security Limits

The crate does not defend against root, a malicious process with the same
effective user ID, or a filesystem that violates the required Linux syscall and
durability semantics.

## API

`CommitConfig::new` takes the exact state root, effective user ID, and the
optional finite soft `RLIMIT_NOFILE`. Passing a finite limit lets descriptor
budget checks reject plans the process cannot pin safely; `None` represents no
finite ceiling. Add required roots with `with_target_authority`, then construct
`Committer`.

Its main methods are `commit_v1`, `recover_v1`, `inspect_state_v1`, the bounded
inspection methods, `prune_v1`, and `preview_prune_v1`.

See [Architecture](../../docs/architecture.md),
[`store/v1`](../../schemas/store/v1/README.md), and
[`root/v1`](../../schemas/root/v1/README.md).
