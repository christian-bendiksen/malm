//! Validates the workspace. Loading checks every module and profile;
//! `--all-profiles` also compiles every profile, while `--module` limits the
//! report to one module.

use crate::app::context::GlobalCtx;
use crate::config::{ProfileSelection, load_local_config, load_remote_config};
use crate::lang::budget::Limits;
use crate::lang::compile::{CompileOptions, compile_profile_module};
use crate::lang::diag::Severity as DiagnosticSeverity;
use crate::lang::resolve::resolve_profile;
use crate::output::print_policy_violations;
use crate::planning::plan::DeploymentPlan;
use crate::planning::planner::build_deployment_plan_with_render_root;
use crate::planning::planner::detect_hostname;
use crate::policy::{
    PolicyFinding, RemotePolicyOverrides, collect_asset_declaration_findings,
    collect_external_include_findings, collect_remote_policy_findings, dedup_findings,
};
use crate::source::{GitReference, TrustMode, git};
use crate::state::ownership_store::read_ownership_for;
use crate::workflow::pipeline::DeploymentPipeline;
use anyhow::Result;
use owo_colors::OwoColorize;

pub struct CheckOpts {
    pub all_profiles: bool,
    pub module: Option<String>,
}

pub fn run(
    ctx: &GlobalCtx,
    source: Option<String>,
    branch: Option<String>,
    tag: Option<String>,
    commit: Option<String>,
    allow: RemotePolicyOverrides,
    opts: CheckOpts,
) -> Result<()> {
    match source {
        Some(url) if git::is_remote_url(&url) => {
            let reference = match (branch, tag, commit) {
                (Some(b), None, None) => GitReference::Branch(b),
                (None, Some(t), None) => GitReference::Tag(t),
                (None, None, Some(c)) => GitReference::Commit(c),
                (None, None, None) => GitReference::DefaultBranch,
                _ => anyhow::bail!("specify at most one of --branch, --tag, or --commit"),
            };
            let loaded = load_remote_config(&url, reference, ctx.config.as_deref(), false)?;
            if opts.all_profiles || opts.module.is_some() {
                return check_workspace_wide(ctx, &loaded, allow, &opts);
            }
            let pipeline = DeploymentPipeline::prepare_read_only(ctx, loaded)?;
            let violations = pipeline.remote_policy_findings(allow);
            print_check_report(&pipeline.plan, &violations)
        }
        local_source => {
            if branch.is_some() || tag.is_some() || commit.is_some() {
                anyhow::bail!("--branch, --tag, and --commit require a remote source");
            }

            let mut active_ctx = ctx.clone();
            if let Some(path) = local_source {
                active_ctx.repo = Some(std::path::PathBuf::from(path));
            }

            let loaded = load_local_config(&active_ctx)?;
            if opts.all_profiles || opts.module.is_some() {
                return check_workspace_wide(&active_ctx, &loaded, allow, &opts);
            }
            let pipeline = DeploymentPipeline::prepare_read_only(&active_ctx, loaded)?;
            print_check_report(&pipeline.plan, &[])
        }
    }
}

/// Validate beyond the selected profile. Loading has already type-checked all
/// workspace declarations. `--all-profiles` plans every profile; `--module`
/// expands and validates each instance of that module without including
/// unrelated outputs.
fn check_workspace_wide(
    ctx: &GlobalCtx,
    loaded: &crate::config::LoadedConfigSource,
    allow: RemotePolicyOverrides,
    opts: &CheckOpts,
) -> Result<()> {
    let cfg = &loaded.config;
    let untrusted = matches!(loaded.resolved.trust_mode, TrustMode::Untrusted);

    if let Some(module) = &opts.module {
        if !cfg.workspace.modules.contains_key(module) {
            anyhow::bail!(
                "module `{module}` is not declared (known modules: {})",
                cfg.workspace
                    .modules
                    .keys()
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }
        return check_module_instances(loaded, module, untrusted);
    }

    let mut failed_profiles = 0usize;
    let ownership = read_ownership_for(ctx.state_namespace.as_str())?;
    let profile_names: Vec<String> = cfg
        .workspace
        .profiles
        .iter()
        .map(|profile| profile.name.clone())
        .collect();
    for name in &profile_names {
        let render_workspace = tempfile::Builder::new()
            .prefix("malm-check-profile-")
            .tempdir()?;
        let selection = ProfileSelection::resolve(cfg, Some(name))?;
        let plan = build_deployment_plan_with_render_root(
            cfg,
            &loaded.resolved.source_root,
            &loaded.target_root,
            render_workspace.path(),
            &selection,
            &ownership,
            loaded.resolved.trust_mode,
        );
        let violations = if untrusted {
            let mut findings = collect_remote_policy_findings(
                &plan,
                &loaded.resolved.source_root,
                Some(render_workspace.path()),
                None,
                allow,
            );
            findings.extend(collect_asset_declaration_findings(cfg, allow));
            findings.extend(collect_external_include_findings(&loaded.provenance));
            dedup_findings(&mut findings);
            findings
        } else {
            Vec::new()
        };
        let errors = plan.errors().len();
        let blocks = violations
            .iter()
            .filter(|finding| finding.is_block())
            .count();
        if errors == 0 && blocks == 0 {
            println!(
                "  {} profile {name} ({} planned operations)",
                "✓".green().bold(),
                plan.operations().len()
            );
        } else {
            failed_profiles += 1;
            println!(
                "  {} profile {name}: {errors} planning error(s), {blocks} policy block(s)",
                "✗".red().bold()
            );
            for error in plan.errors() {
                for line in error.lines() {
                    println!("     {line}");
                }
            }
            print_policy_violations(&violations);
        }
    }
    if failed_profiles > 0 {
        anyhow::bail!("{failed_profiles} profile(s) failed validation");
    }
    let summary = format!("all {} profiles valid", profile_names.len());
    println!("\n  {}  {}", "CHECK".bold(), summary.dimmed());
    Ok(())
}

fn check_module_instances(
    loaded: &crate::config::LoadedConfigSource,
    module: &str,
    untrusted: bool,
) -> Result<()> {
    let cfg = &loaded.config;
    let options = CompileOptions {
        target_root: loaded.target_root.display().to_string(),
        hostname: (!untrusted).then(detect_hostname).flatten(),
        restrict_source_root: untrusted,
        limits: Limits::default(),
    };
    let mut checked_profiles = 0usize;
    let mut failed_profiles = 0usize;
    for profile in &cfg.workspace.profiles {
        let mut resolution_diagnostics = crate::lang::diag::Diagnostics::new();
        let uses_module =
            resolve_profile(&cfg.workspace, &profile.name, &mut resolution_diagnostics)
                .is_some_and(|resolved| {
                    resolved
                        .instances
                        .iter()
                        .any(|instance| instance.module == module)
                });
        if !uses_module {
            continue;
        }
        checked_profiles += 1;
        let mut diagnostics = crate::lang::diag::Diagnostics::new();
        let _ = compile_profile_module(
            &cfg.workspace,
            &profile.name,
            module,
            &options,
            &mut diagnostics,
        );
        if diagnostics.has_errors() {
            failed_profiles += 1;
            println!(
                "  {} profile {}: {} compiler error(s)",
                "✗".red().bold(),
                profile.name,
                diagnostics.error_count()
            );
            for diagnostic in diagnostics.items() {
                if diagnostic.severity == DiagnosticSeverity::Error {
                    eprint!("{}", diagnostic.render(&cfg.sources));
                }
            }
        } else {
            println!("  {} profile {}", "✓".green().bold(), profile.name);
        }
    }
    if failed_profiles != 0 {
        anyhow::bail!("module `{module}` failed validation in {failed_profiles} profile(s)");
    }
    println!(
        "\n  {}  {}",
        "CHECK".bold(),
        format!("module {module} valid in all {checked_profiles} using profile(s)").dimmed()
    );
    Ok(())
}

fn print_check_report(plan: &DeploymentPlan, violations: &[PolicyFinding]) -> Result<()> {
    let errors = plan.errors().len();
    let blocks = violations.iter().filter(|v| v.is_block()).count();

    if errors == 0 && blocks == 0 {
        println!(
            "\n  {}  {}",
            "CHECK".bold(),
            format!("valid · {} operations", plan.operations().len()).dimmed()
        );
    } else {
        println!(
            "\n  {}  {}",
            "CHECK".bold(),
            format!("{errors} error(s) · {blocks} blocked").red().bold()
        );
    }

    if errors > 0 {
        println!("\n  {}  {}", "✗".red().bold(), "Errors".red().bold());
        for issue in plan.errors() {
            for line in issue.lines() {
                println!("     {line}");
            }
        }
    }

    if !plan.warnings().is_empty() {
        println!(
            "\n  {}  {}",
            "!".yellow().bold(),
            "Warnings".yellow().bold()
        );
        for warning in plan.warnings() {
            for line in warning.lines() {
                println!("     {line}");
            }
        }
    }

    if !violations.is_empty() {
        print_policy_violations(violations);
    }

    if errors == 0 && blocks == 0 {
        Ok(())
    } else {
        anyhow::bail!("validation failed: {errors} error(s), {blocks} policy block(s)")
    }
}
