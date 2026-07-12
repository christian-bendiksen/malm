//! CLI validation, context setup, workflow dispatch, and exit-code mapping.
use crate::app::context::GlobalCtx;
use crate::app::validation::{validate_commit_sha, validate_name};
use crate::cli::{Args, Cmd, RemotePolicyOverrideFlags, StateCmd};
use crate::domain::id::StateName;
use crate::output::transaction_log;
use crate::policy::overrides::RemotePolicyOverrides;
use crate::source::git::{validate_branch_name, validate_tag_name};
use crate::workflow::{
    apply, check, checkout, destroy, disable, doctor, enable, fsck, gc, plan, profiles, recover,
    render, state_list, status, update, vars,
};
use anyhow::Result;
use clap::Parser;

/// Convert clap `--allow-*` flags without coupling policy types to clap.
impl From<RemotePolicyOverrideFlags> for RemotePolicyOverrides {
    fn from(f: RemotePolicyOverrideFlags) -> Self {
        Self {
            external_symlink_sources: f.allow_external_symlink_sources,
            outside_home: f.allow_outside_home,
            unverified_assets: f.allow_unverified_assets,
            secrets: f.allow_secrets,
        }
    }
}

pub fn run() -> Result<i32> {
    let args = Args::parse();
    // Resolve $HOME once, up front, so a missing home directory is a clean
    // error here rather than an expect-panic deep in a later path/XDG call.
    crate::paths::init_home_dir()?;
    validate_name(&args.state, "state name")?;
    // Must stay in sync with supports_json() below and the command list in
    // the error message.
    if args.json && !supports_json(&args.cmd) {
        anyhow::bail!(
            "--json is supported only by plan, status, vars, state log, state list, \
              profiles, state fsck, and state disable --dry-run"
        );
    }
    let mut ctx = GlobalCtx {
        repo: args.repo,
        config: args.config,
        profile: args.profile,
        state_namespace: StateName::new(args.state)?,
        json: args.json,
        allow_ssrf: false,
    };
    let exit_code = match args.cmd {
        Cmd::Apply {
            source,
            yes,
            trust,
            trust_remote,
            allow_local_includes,
            commit,
            branch,
            tag,
            track,
            reenable,
            allow,
            allow_ssrf,
        } => {
            ctx.allow_ssrf = allow_ssrf;
            if let Some(ref sha) = commit {
                validate_commit_sha(sha)?;
            }
            if let Some(ref name) = branch {
                validate_branch_name(name)?;
            }
            if let Some(ref name) = tag {
                validate_tag_name(name)?;
            }
            run_ok(apply::run(
                &ctx,
                source,
                apply::RemoteApplyOpts {
                    yes,
                    trust,
                    trust_remote,
                    allow_local_includes,
                    commit,
                    branch,
                    tag,
                    track,
                    reenable,
                },
                allow.into(),
            ))?
        }
        Cmd::Plan {
            source,
            branch,
            tag,
            commit,
            trust,
            allow_local_includes,
            verbose,
        } => {
            if let Some(ref sha) = commit {
                validate_commit_sha(sha)?;
            }
            if let Some(ref name) = branch {
                validate_branch_name(name)?;
            }
            if let Some(ref name) = tag {
                validate_tag_name(name)?;
            }
            plan::run(
                &ctx,
                source,
                plan::PlanOpts {
                    branch,
                    tag,
                    commit,
                    trust,
                    allow_local_includes,
                    verbose,
                },
            )?
        }
        Cmd::Update {
            yes,
            allow_local_includes,
            allow,
            allow_ssrf,
        } => {
            ctx.allow_ssrf = allow_ssrf;
            run_ok(update::run(&ctx, yes, allow.into(), allow_local_includes))?
        }
        Cmd::Check {
            source,
            branch,
            tag,
            commit,
            all_profiles,
            module,
            allow,
        } => {
            if let Some(ref sha) = commit {
                validate_commit_sha(sha)?;
            }
            if let Some(ref name) = branch {
                validate_branch_name(name)?;
            }
            if let Some(ref name) = tag {
                validate_tag_name(name)?;
            }
            run_ok(check::run(
                &ctx,
                source,
                branch,
                tag,
                commit,
                allow.into(),
                check::CheckOpts {
                    all_profiles,
                    module,
                },
            ))?
        }
        Cmd::Render { output } => run_ok(render::run(&ctx, output))?,
        Cmd::Doctor {} => run_ok(doctor::run(&ctx))?,
        Cmd::Profiles { selectable } => run_ok(profiles::run(&ctx, selectable))?,
        // Preserve status's drift exit code.
        Cmd::Status { quiet, verbose } => status::run(&ctx, quiet, verbose)?.code(),
        Cmd::Vars { source } => run_ok(vars::run(&ctx, source))?,
        Cmd::State { cmd } => match cmd {
            StateCmd::List => run_ok(state_list::run(&ctx))?,
            StateCmd::Log => run_ok(transaction_log::print_transaction_log(&ctx))?,
            StateCmd::Checkout { id, yes, verify } => run_ok(checkout::run(
                &ctx,
                &id,
                checkout::CheckoutOpts { yes, verify },
            ))?,
            StateCmd::Destroy { name, yes } => run_ok(destroy::run(&ctx, name.as_deref(), yes))?,
            StateCmd::Prune {
                keep,
                keep_per_state,
                dry_run,
                verbose,
                force,
            } => run_ok(gc::run(
                &ctx,
                gc::PruneArgs {
                    keep,
                    keep_per_state,
                    dry_run,
                    verbose,
                    force,
                },
            ))?,
            StateCmd::Usage {
                keep,
                keep_per_state,
            } => run_ok(gc::run_usage(&ctx, keep, keep_per_state))?,
            StateCmd::Pin { reference } => run_ok(gc::run_pin(&ctx, &reference))?,
            StateCmd::Unpin { reference } => run_ok(gc::run_unpin(&ctx, &reference))?,
            StateCmd::Disable {
                name,
                yes,
                keep_modified,
                dry_run,
            } => run_ok(disable::run(
                &ctx,
                name.as_deref(),
                disable::DisableOpts {
                    yes,
                    keep_modified,
                    dry_run,
                },
            ))?,
            StateCmd::Enable {
                name,
                yes,
                replace_kept,
            } => run_ok(enable::run(&ctx, name.as_deref(), yes, replace_kept))?,
            StateCmd::Fsck { verify_objects } => fsck::run(&ctx, verify_objects)?,
            StateCmd::Recover {
                reference,
                all,
                dry_run,
                yes,
            } => recover::run(
                &ctx,
                reference.as_deref(),
                &recover::RecoverOpts { all, dry_run, yes },
            )?,
        },
    };
    Ok(exit_code)
}

fn supports_json(command: &Cmd) -> bool {
    matches!(
        command,
        Cmd::Plan { .. }
            | Cmd::Status { .. }
            | Cmd::Vars { .. }
            | Cmd::Profiles { .. }
            | Cmd::State {
                cmd: StateCmd::Log
                    | StateCmd::List
                    | StateCmd::Fsck { .. }
                    | StateCmd::Disable { dry_run: true, .. }
            }
    )
}

fn run_ok(result: Result<()>) -> Result<i32> {
    result.map(|()| 0)
}
