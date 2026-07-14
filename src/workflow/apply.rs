//! Runs `apply` from a remote URL, local repo, active deployment, or the
//! default state, with remote trust and disabled-state checks.

use crate::app::context::GlobalCtx;
use crate::app::prompt::confirm;
use crate::config::{LoadedConfigSource, ProfileSelection, load_local_config, load_remote_config};
use crate::lang::text::shell_word;
use crate::output::display::format_short_path;
use crate::output::meta::print_loaded_source;
use crate::policy::RemotePolicyOverrides;
use crate::source::git::redact_url;
use crate::source::{GitReference, SourceKind, git};
use crate::state::record::{StateMode, StateRecord};
use crate::state::tracking::TrackedRemote;
use crate::state::transaction::{TransactionStore, transaction_alias};
use crate::workflow::source_resolution::{self, LocalSource};
use anyhow::{Context, Result};

pub struct RemoteApplyOpts {
    pub yes: bool,
    /// Deprecated alias implying both --trust-remote and --allow-local-includes.
    pub trust: bool,
    pub trust_remote: bool,
    /// Let a remote config read local files it names via `~/` or absolute includes.
    pub allow_local_includes: bool,
    pub commit: Option<String>,
    pub branch: Option<String>,
    pub tag: Option<String>,
    pub track: bool,
    /// Deploy the current config to a disabled state and clear its marker.
    pub reenable: bool,
}

impl RemoteApplyOpts {
    /// Expand the deprecated --trust alias into remote trust and local-include access.
    fn resolve_trust(&mut self) {
        if self.trust {
            eprintln!(
                "warning: --trust is deprecated; use --trust-remote (and \
                 --allow-local-includes if the config reads local files)"
            );
            self.trust_remote = true;
            self.allow_local_includes = true;
        }
    }
}

pub fn run(
    ctx: &GlobalCtx,
    source: Option<String>,
    mut opts: RemoteApplyOpts,
    allow: RemotePolicyOverrides,
) -> Result<()> {
    opts.resolve_trust();
    let disabled = matches!(
        StateRecord::load_for_state(ctx.state_namespace.as_str())?.map(|record| record.mode),
        Some(StateMode::Disabled { .. })
    );
    if disabled && !opts.reenable {
        anyhow::bail!(
            "state '{ns}' is disabled; `malm state enable {ns}` restores its previous \
             deployment, or re-run apply with --reenable to deploy the current config and \
             re-enable it",
            ns = ctx.state_namespace
        );
    }
    let expect_reenable = disabled && opts.reenable;

    dispatch(ctx, source, opts, allow)?;

    // A successful apply finalizes the state as Enabled. An empty plan creates
    // no transaction, so the state remains disabled.
    if expect_reenable {
        match StateRecord::load_for_state(ctx.state_namespace.as_str())?.map(|record| record.mode) {
            Some(StateMode::Disabled { .. }) => println!(
                "  state '{}' remains disabled: the apply recorded no deployment",
                ctx.state_namespace
            ),
            _ => println!("  re-enabled state '{}'", ctx.state_namespace),
        }
    }
    Ok(())
}

fn dispatch(
    ctx: &GlobalCtx,
    source: Option<String>,
    opts: RemoteApplyOpts,
    allow: RemotePolicyOverrides,
) -> Result<()> {
    match source {
        Some(url) if git::is_remote_url(&url) => run_remote(ctx, &url, opts, allow),
        Some(path) => anyhow::bail!(
            "local paths must be specified with --repo so a path is never mistaken \
             for a repository URL; use `malm apply --repo {path}`"
        ),
        None => {
            ensure_local_apply_flags(&opts)?;

            let mut active_ctx = ctx.clone();
            match source_resolution::classify_local_source(&active_ctx)? {
                LocalSource::Explicit | LocalSource::CwdConfig => run_local(&active_ctx, opts.yes),
                // Bare `malm apply` rebuilds the source from the active transaction.
                LocalSource::Active(active_id) => {
                    let manifest = TransactionStore::new().read(&active_id)?;
                    let label = manifest
                        .source
                        .as_ref()
                        .map(|s| s.display_label())
                        .or_else(|| manifest.repo.as_ref().map(|r| r.display().to_string()))
                        .unwrap_or_else(|| active_id.clone());

                    println!(
                        "No source specified: re-applying active deployment (<store:{}>)\n  source: {}",
                        transaction_alias(&active_id),
                        label
                    );

                    let (loaded, repo) =
                        source_resolution::load_from_manifest(&mut active_ctx, &manifest)?;
                    ensure_selectable_profile(&active_ctx, &loaded)?;
                    let applied_source = loaded.resolved.identity.clone();
                    let applied_config = loaded.tracked_config_path()?;

                    if !active_ctx.json {
                        print_loaded_source(&loaded);
                    }

                    let pipeline =
                        DeploymentPipeline::prepare_for_reapply(&active_ctx, loaded, repo)?;
                    let effective_profile = pipeline.effective_profile().map(str::to_owned);
                    pipeline
                        .approve_for_execution(manifest.allow)?
                        .execute(opts.yes)?;

                    TrackedRemote::reconcile_with_source(
                        ctx.state_namespace.as_str(),
                        &applied_source,
                        applied_config.as_deref(),
                        effective_profile.as_deref(),
                    )
                    .context("reconcile tracking state after active re-apply")?;
                    Ok(())
                }
                LocalSource::DefaultStateRepo(id) => {
                    let manifest = TransactionStore::new().read(&id)?;
                    let repo = manifest.repo.clone().ok_or_else(|| {
                        anyhow::anyhow!(
                            "default state's transaction {} has no repository path",
                            manifest.id
                        )
                    })?;
                    confirm_default_repo_adoption(ctx.state_namespace.as_str(), &repo, opts.yes)?;
                    active_ctx.repo = Some(repo);
                    run_local(&active_ctx, opts.yes)
                }
            }
        }
    }
}

fn confirm_default_repo_adoption(
    state: &str,
    repo: &std::path::Path,
    auto_confirm: bool,
) -> Result<()> {
    if auto_confirm {
        println!(
            "No source specified: state '{state}' has no deployment; \
             applying repo from state \"default\" ({})",
            repo.display()
        );
        return Ok(());
    }
    let question = format!(
        "\n  state '{state}' has no deployment; apply the default state's repo ({}) to it?",
        format_short_path(repo)
    );
    if !confirm(&question)? {
        anyhow::bail!("aborted; pass --repo <path> to choose a source explicitly");
    }
    Ok(())
}

fn ensure_local_apply_flags(opts: &RemoteApplyOpts) -> Result<()> {
    let offending = if opts.trust_remote {
        "--trust-remote"
    } else if opts.allow_local_includes {
        "--allow-local-includes"
    } else if opts.commit.is_some() {
        "--commit"
    } else if opts.branch.is_some() {
        "--branch"
    } else if opts.tag.is_some() {
        "--tag"
    } else if opts.track {
        "--track"
    } else {
        return Ok(());
    };
    anyhow::bail!("{offending} only applies to a remote apply (provide a repository URL)");
}

use crate::workflow::pipeline::DeploymentPipeline;

fn run_local(ctx: &GlobalCtx, yes: bool) -> Result<()> {
    let loaded = load_local_config(ctx)?;
    ensure_selectable_profile(ctx, &loaded)?;
    let applied_source = loaded.resolved.identity.clone();
    if !ctx.json {
        print_loaded_source(&loaded);
    }

    let pipeline = DeploymentPipeline::prepare_for_apply(ctx, loaded)?;
    let effective_profile = pipeline.effective_profile().map(str::to_owned);
    pipeline
        .approve_for_execution(RemotePolicyOverrides::default())?
        .execute(yes)?;

    TrackedRemote::reconcile_with_source(
        ctx.state_namespace.as_str(),
        &applied_source,
        None,
        effective_profile.as_deref(),
    )
    .context("reconcile tracking state after local apply")?;
    Ok(())
}

fn run_remote(
    ctx: &GlobalCtx,
    url: &str,
    opts: RemoteApplyOpts,
    allow: RemotePolicyOverrides,
) -> Result<()> {
    git::require_https(url)?;

    if !opts.trust_remote {
        anyhow::bail!(
            "Remote apply requires --trust-remote.\n\
             Run `malm plan {}` first to inspect the config, \
             then add --trust-remote to proceed.",
            redact_url(url)
        );
    }

    // Exactly one of --commit/--branch/--tag; --track needs a branch because
    // an exact commit can never advance.
    let (reference, branch_name, ref_flag) = match (opts.commit, opts.branch, opts.tag) {
        (Some(c), None, None) => {
            let flag = format!("--commit {c}");
            (GitReference::Commit(c), None, flag)
        }
        (None, Some(b), None) => (
            GitReference::Branch(b.clone()),
            Some(b.clone()),
            format!("--branch {b}"),
        ),
        (None, None, Some(t)) => {
            let flag = format!("--tag {t}");
            (GitReference::Tag(t), None, flag)
        }
        (None, None, None) => anyhow::bail!(
            "Remote apply requires --commit <sha>, --branch <name>, or --tag <name>.\n\
             Example: malm apply {url} --branch main --trust-remote"
        ),
        _ => {
            anyhow::bail!("--commit, --branch, and --tag are mutually exclusive; use one of them")
        }
    };

    if opts.track && branch_name.is_none() {
        anyhow::bail!("--track requires --branch (cannot track an exact commit)");
    }

    let loaded = load_remote_config(
        url,
        reference,
        ctx.config.as_deref(),
        opts.allow_local_includes,
    )?;
    if !loaded.external_includes_skipped.is_empty() {
        let paths = loaded
            .external_includes_skipped
            .iter()
            .map(|path| format!("  {}", format_short_path(path)))
            .collect::<Vec<_>>()
            .join("\n");
        let track_flag = if opts.track { " --track" } else { "" };
        let config_flag = ctx
            .config
            .as_deref()
            .map(|path| format!(" --config {}", shell_word(&path.display().to_string())))
            .unwrap_or_default();
        anyhow::bail!(
            "the remote config requests local includes:\n{paths}\n\
             re-run with --allow-local-includes to let it read them:\n  \
             malm apply {url} {ref_flag} --trust-remote{track_flag} --allow-local-includes{config_flag}",
            url = redact_url(url)
        );
    }
    ensure_selectable_profile(ctx, &loaded)?;
    let tracked_config = loaded.tracked_config_path()?;
    if !ctx.json {
        print_loaded_source(&loaded);
    }

    let resolved_commit = match &loaded.resolved.identity.kind {
        SourceKind::Git { commit, .. } => commit.clone(),
        SourceKind::Local { .. } => {
            anyhow::bail!("internal error: local source identity in remote apply path")
        }
    };
    let applied_source = loaded.resolved.identity.clone();
    let pipeline = DeploymentPipeline::prepare_for_apply(ctx, loaded)?;
    let effective_profile = pipeline.effective_profile().map(str::to_owned);
    pipeline.approve_for_execution(allow)?.execute(opts.yes)?;

    if opts.track
        && let Some(branch) = &branch_name
    {
        let state = TrackedRemote::new(
            url.to_owned(),
            branch.clone(),
            resolved_commit,
            opts.allow_local_includes,
            tracked_config,
            effective_profile,
        );
        state
            .save_for_state(ctx.state_namespace.as_str())
            .context("save tracking state (deployment succeeded)")?;
        println!("tracking branch set up; use `malm update` to apply future commits");
    } else {
        TrackedRemote::reconcile_with_applied(
            ctx.state_namespace.as_str(),
            &applied_source,
            branch_name.as_deref(),
            tracked_config.as_deref(),
            effective_profile.as_deref(),
        )
        .context("reconcile tracking state after remote apply")?;
    }

    Ok(())
}

fn ensure_selectable_profile(ctx: &GlobalCtx, loaded: &LoadedConfigSource) -> Result<()> {
    let selection = ProfileSelection::resolve(&loaded.config, ctx.profile.as_deref())?;
    selection.ensure_selectable(&loaded.config)
}
