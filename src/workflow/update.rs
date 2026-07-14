//! Updates a tracked branch, re-applying and persisting it only when its tip
//! changes.

use crate::app::context::GlobalCtx;
use crate::app::validation::{short_commit, validate_resolved_commit_sha};
use crate::config::load_remote_config;
use crate::policy::RemotePolicyOverrides;
use crate::sanitize::terminal;
use crate::source::{GitReference, git};
use crate::state::tracking::TrackedRemote;
use crate::workflow::pipeline::DeploymentPipeline;
use anyhow::Context;
use anyhow::Result;
use owo_colors::OwoColorize;

pub fn run(
    ctx: &GlobalCtx,
    yes: bool,
    allow: RemotePolicyOverrides,
    allow_local_includes: bool,
) -> Result<()> {
    if matches!(
        crate::state::record::StateRecord::load_for_state(ctx.state_namespace.as_str())?
            .map(|record| record.mode),
        Some(crate::state::record::StateMode::Disabled { .. })
    ) {
        anyhow::bail!(
            "state '{ns}' is disabled; `malm state enable {ns}` restores its previous \
             deployment before updating",
            ns = ctx.state_namespace
        );
    }
    let tracking =
        TrackedRemote::load_for_state(ctx.state_namespace.as_str())?.ok_or_else(|| {
            anyhow::anyhow!(
                "no tracked repository for state \"{}\"\n\
             Set up tracking with: malm apply <url> --branch <name> --track --trust-remote",
                ctx.state_namespace
            )
        })?;

    git::check_git_available()?;
    git::validate_branch_name(&tracking.branch).context("validate tracked branch")?;
    git::require_https(&tracking.url)?;
    validate_resolved_commit_sha(&tracking.applied_commit)
        .context("validate tracked applied commit")?;

    let cache = git::cache_dir_for_url(&tracking.url);

    println!(
        "\n  {}  {}",
        "UPDATE".bold(),
        format!(
            "{} · {} @ {}",
            git::redact_url(&tracking.url),
            tracking.branch,
            short_commit(&tracking.applied_commit, 8)
        )
        .dimmed()
    );

    git::ensure_fetched(&tracking.url)?;

    let latest_commit = git::resolve_branch_to_commit(&cache, &tracking.branch)
        .with_context(|| format!("resolve branch '{}'", tracking.branch))?;

    let commit_changed = latest_commit != tracking.applied_commit;
    if commit_changed {
        println!("  latest commit:  {}", short_commit(&latest_commit, 8));
    }

    let new_commits = git::log_oneline_range(&cache, &tracking.applied_commit, &latest_commit)
        .context("read tracked commit range")?;
    if !new_commits.is_empty() {
        println!("\nNew commits ({}):", new_commits.len());
        for line in &new_commits {
            println!("  {}", terminal(line));
        }
    }

    // Honor only local-include access granted when tracking began or granted
    // again here. A remote cannot gain local access by adding an include.
    let local_includes_granted = tracking.allow_local_includes || allow_local_includes;
    let reference = GitReference::Commit(latest_commit.clone());
    let loaded = load_remote_config(
        &tracking.url,
        reference,
        tracking.config.as_deref(),
        local_includes_granted,
    )?;
    reject_ungranted_local_includes(&loaded.external_includes_skipped)?;

    // Keep the effective profile selected when tracking began. Changing the
    // default profile must not switch what this state deploys.
    let mut update_ctx = ctx.clone();
    update_ctx.profile = Some(
        tracking
            .profile
            .clone()
            .unwrap_or_else(|| "none".to_owned()),
    );

    DeploymentPipeline::prepare_for_apply(&update_ctx, loaded)?
        .approve_for_execution(allow)?
        .execute(yes)?;

    let new_tracking = TrackedRemote::new(
        tracking.url.clone(),
        tracking.branch.clone(),
        latest_commit.clone(),
        local_includes_granted,
        tracking.config.clone(),
        tracking.profile.clone(),
    );

    new_tracking
        .save_for_state(ctx.state_namespace.as_str())
        .context("update tracking state (deployment succeeded)")?;

    if commit_changed {
        println!(
            "\n  {} updated to {}",
            "✓".green().bold(),
            short_commit(&latest_commit, 8)
        );
    } else {
        println!(
            "\n  {} up to date · {}",
            "✓".green().bold(),
            short_commit(&latest_commit, 8)
        );
    }
    Ok(())
}

/// Reject new local includes from a tracked remote until the user explicitly
/// grants access again.
fn reject_ungranted_local_includes(skipped: &[std::path::PathBuf]) -> Result<()> {
    if skipped.is_empty() {
        return Ok(());
    }
    let paths = skipped
        .iter()
        .map(|path| format!("  {}", crate::output::display::format_short_path(path)))
        .collect::<Vec<_>>()
        .join("\n");
    anyhow::bail!(
        "the tracked remote now requests local includes it was never granted:\n{paths}\n\
         re-run `malm update --allow-local-includes` to let it read them"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn update_refuses_new_local_includes_without_explicit_permission() {
        let skipped = vec![PathBuf::from("/home/user/.ssh/config")];
        let error = reject_ungranted_local_includes(&skipped).unwrap_err();
        let message = format!("{error:#}");
        assert!(message.contains("never granted"), "message: {message}");
        assert!(
            message.contains("--allow-local-includes"),
            "message: {message}"
        );
    }

    #[test]
    fn update_accepts_configs_without_local_includes() {
        assert!(reject_ungranted_local_includes(&[]).is_ok());
    }
}
