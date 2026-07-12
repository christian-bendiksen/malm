//! Reports the selected profile's declared command, file, and feature
//! requirements. It never installs packages or manages services.

use crate::app::context::GlobalCtx;
use crate::config::ProfileSelection;
use crate::lang::diag::Diagnostics;
use crate::lang::doctor::{RequirementStatus, run_doctor};
use crate::lang::typecheck::check_profile;
use crate::workflow::source_resolution::load_resolved_local;
use anyhow::Result;
use owo_colors::OwoColorize;

pub fn run(ctx: &GlobalCtx) -> Result<()> {
    let mut active_ctx = ctx.clone();
    let loaded = load_resolved_local(&mut active_ctx)?;
    let cfg = &loaded.config;
    let selection = ProfileSelection::resolve(cfg, active_ctx.profile.as_deref())?;
    let Some(selected) = selection.selected() else {
        anyhow::bail!("doctor requires a profile: pass --profile <name>");
    };

    let mut diagnostics = Diagnostics::new();
    let Some(typed) = check_profile(&cfg.workspace, selected, &mut diagnostics) else {
        anyhow::bail!("profile `{selected}` not found");
    };
    if diagnostics.has_errors() {
        anyhow::bail!(
            "{}\nprofile `{selected}` has {} error(s); fix them before running doctor",
            diagnostics.render(&cfg.sources).trim_end(),
            diagnostics.error_count()
        );
    }

    let report = run_doctor(&cfg.workspace, &typed);
    println!(
        "\n  {}  {}",
        "DOCTOR".bold(),
        format!("profile {selected}").dimmed()
    );
    if report.instances.is_empty() {
        println!("\n  {}", "(no module declares requirements)".dimmed());
        return Ok(());
    }
    for (instance, requirements) in &report.instances {
        println!("\n  {} {}", "module".bold(), instance);
        for requirement in requirements {
            let (mark, status) = match requirement.status {
                RequirementStatus::Satisfied => ("✓".green().bold().to_string(), String::new()),
                RequirementStatus::Missing => (
                    "✗".red().bold().to_string(),
                    " MISSING".red().bold().to_string(),
                ),
                RequirementStatus::Unchecked => (
                    "•".dimmed().to_string(),
                    " (unchecked)".dimmed().to_string(),
                ),
            };
            let detail = requirement
                .detail
                .as_deref()
                .map(|d| format!("  {}", d.dimmed()))
                .unwrap_or_default();
            println!(
                "     {mark} {} {}{status}{detail}",
                requirement.kind.label(),
                requirement.subject,
            );
        }
    }
    let missing = report.missing_count();
    if missing > 0 {
        anyhow::bail!("{missing} requirement(s) missing");
    }
    Ok(())
}
