//! Produces a read-only human or JSON preview with policy findings.

use crate::app::context::GlobalCtx;
use crate::config::{ProfileSelection, load_remote_config};
use crate::output::meta::print_loaded_source;
use crate::output::{plan_to_json, print_policy_violations};
use crate::planning::plan::DeploymentPlan;
use crate::policy::{PolicyFinding, RemotePolicyOverrides};
use crate::source::{GitReference, SourceKind, git};
use crate::workflow::pipeline::DeploymentPipeline;
use crate::workflow::source_resolution::load_resolved_local;
use anyhow::Result;
use owo_colors::OwoColorize;

pub struct PlanOpts {
    pub branch: Option<String>,
    pub tag: Option<String>,
    pub commit: Option<String>,
    /// Deprecated alias for --allow-local-includes.
    pub trust: bool,
    pub allow_local_includes: bool,
    pub verbose: bool,
}

pub fn run(ctx: &GlobalCtx, source: Option<String>, opts: PlanOpts) -> Result<i32> {
    let PlanOpts {
        branch,
        tag,
        commit,
        trust,
        mut allow_local_includes,
        verbose,
    } = opts;
    if trust {
        eprintln!("warning: --trust is deprecated for plan; use --allow-local-includes");
        allow_local_includes = true;
    }
    match source {
        Some(url) if git::is_remote_url(&url) => {
            // Preserve the user's ref choice for the suggested `apply` command.
            // A bare `plan` resolves the default branch, then records its commit.
            let (reference, ref_flag) = match (branch, tag, commit) {
                (Some(b), None, None) => (
                    GitReference::Branch(b.clone()),
                    Some(format!("--branch {b}")),
                ),
                (None, Some(t), None) => (GitReference::Tag(t.clone()), Some(format!("--tag {t}"))),
                (None, None, Some(c)) => (
                    GitReference::Commit(c.clone()),
                    Some(format!("--commit {c}")),
                ),
                (None, None, None) => (GitReference::DefaultBranch, None),
                _ => anyhow::bail!("specify at most one of --branch, --tag, or --commit"),
            };

            if !ctx.json {
                let clean_url = git::redact_url(&url)
                    .trim_start_matches("https://")
                    .trim_start_matches("git@")
                    .to_owned();

                println!("  {} fetching {}...", "↓".cyan().bold(), clean_url);
            }

            let loaded = load_remote_config(&url, reference, allow_local_includes)?;
            let selection = ProfileSelection::resolve(&loaded.config, ctx.profile.as_deref())?;
            selection.ensure_selectable(&loaded.config)?;
            if !ctx.json {
                print_loaded_source(&loaded);
            }

            // Save the resolved commit and local-include grant before consuming
            // `loaded`; both may be needed by the suggested `apply` command.
            let resolved_commit = match &loaded.resolved.identity.kind {
                SourceKind::Git { commit, .. } => Some(commit.clone()),
                SourceKind::Local { .. } => None,
            };
            let needs_local_includes =
                allow_local_includes || !loaded.external_includes_skipped.is_empty();

            let pipeline = DeploymentPipeline::prepare_read_only(ctx, loaded)?;
            let violations = pipeline.remote_policy_findings(RemotePolicyOverrides::default());

            if ctx.json {
                println!("{}", plan_to_json(&pipeline.plan, &violations)?);
                return Ok(plan_exit_code(&pipeline.plan, &violations));
            }

            pipeline.preview(verbose);

            if !violations.is_empty() {
                print_policy_violations(&violations);
            }

            // Print a ready-to-run command only for an applyable config. For a
            // bare `plan`, prefer the resolved branch name and fall back to the
            // exact previewed commit.
            let ref_flag = ref_flag
                .or_else(|| {
                    git::default_branch_name(&git::cache_dir_for_url(&url))
                        .ok()
                        .map(|branch| format!("--branch {branch}"))
                })
                .or_else(|| resolved_commit.map(|commit| format!("--commit {commit}")));
            if !pipeline.plan.has_errors()
                && let Some(ref_flag) = ref_flag
            {
                let local_flag = if needs_local_includes {
                    " --allow-local-includes"
                } else {
                    ""
                };
                println!(
                    "\n  {} apply this config:\n    malm apply {} {ref_flag} --trust-remote{local_flag}",
                    "→".cyan().bold(),
                    git::redact_url(&url),
                );
            }

            Ok(plan_exit_code(&pipeline.plan, &violations))
        }
        local_source => {
            if branch.is_some() || tag.is_some() || commit.is_some() {
                anyhow::bail!("--branch, --tag, and --commit require a remote preview source");
            }
            if allow_local_includes {
                anyhow::bail!(
                    "--allow-local-includes only applies to a remote preview \
                     (provide a repository URL)"
                );
            }

            let mut active_ctx = ctx.clone();
            if let Some(path) = local_source {
                active_ctx.repo = Some(std::path::PathBuf::from(path));
            }

            let loaded = load_resolved_local(&mut active_ctx)?;
            let selection =
                ProfileSelection::resolve(&loaded.config, active_ctx.profile.as_deref())?;
            selection.ensure_selectable(&loaded.config)?;
            if !active_ctx.json {
                print_loaded_source(&loaded);
            }
            let pipeline = DeploymentPipeline::prepare_read_only(&active_ctx, loaded)?;

            if active_ctx.json {
                println!("{}", plan_to_json(&pipeline.plan, &[])?);
                return Ok(plan_exit_code(&pipeline.plan, &[]));
            }

            pipeline.preview(verbose);
            Ok(plan_exit_code(&pipeline.plan, &[]))
        }
    }
}

fn plan_exit_code(plan: &DeploymentPlan, violations: &[PolicyFinding]) -> i32 {
    if plan.has_errors() || violations.iter().any(PolicyFinding::is_block) {
        1
    } else {
        0
    }
}
