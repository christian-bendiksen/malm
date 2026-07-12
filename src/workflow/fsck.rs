//! Checks every state's records for consistency without modifying them.

use crate::app::context::GlobalCtx;
use crate::state::integrity::checks::{CheckOptions, run_checks};
use crate::state::integrity::report::{Finding, Severity};
use crate::state::target_lock::TargetLock;
use anyhow::{Context, Result};
use owo_colors::OwoColorize;

/// Check every state's on-disk records. The target lock prevents observing a
/// torn mid-apply snapshot.
///
/// Exit code 0 when clean, 1 when findings exist.
pub fn run(ctx: &GlobalCtx, verify_objects: bool) -> Result<i32> {
    // Shared lock: fsck must be able to diagnose a state root the mutating
    // preflight would refuse to touch.
    let _guard = TargetLock::acquire_shared_guard()?;

    let findings = run_checks(&CheckOptions { verify_objects })?;

    if ctx.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&findings).context("serialize fsck findings")?
        );
    } else {
        print_human(&findings);
    }

    let worst = findings.iter().map(|finding| finding.severity).max();
    Ok(match worst {
        Some(Severity::Error) | Some(Severity::Warning) => 1,
        Some(Severity::Notice) | None => 0,
    })
}

fn print_human(findings: &[Finding]) {
    if findings.is_empty() {
        println!("\n  {} state records are consistent", "✓".green().bold());
        return;
    }

    let errors = count(findings, Severity::Error);
    let warnings = count(findings, Severity::Warning);
    let notices = count(findings, Severity::Notice);

    println!(
        "\n  {}  {}",
        "FSCK".bold(),
        format!("{errors} errors · {warnings} warnings · {notices} notices").dimmed()
    );

    for finding in findings {
        let tag = match finding.severity {
            Severity::Error => "✗".red().bold().to_string(),
            Severity::Warning => "!".yellow().bold().to_string(),
            Severity::Notice => "·".dimmed().to_string(),
        };
        println!("\n  {tag} [{}] {}", finding.code.dimmed(), finding.message);
        if let Some(remedy) = &finding.remedy {
            println!("     {}", format!("fix: {remedy}").dimmed());
        }
    }
    println!();
}

fn count(findings: &[Finding], severity: Severity) -> usize {
    findings
        .iter()
        .filter(|finding| finding.severity == severity)
        .count()
}
