//! Risk gate: fails on blocked operations and asks for confirmation on
//! medium/high risk unless --yes.

use crate::app::prompt::confirm;
use crate::output::display::format_short_path;
use crate::policy::risk::{RiskLevel, RiskReport};
use anyhow::Result;
use owo_colors::OwoColorize;

pub(crate) fn confirm_high_risk_operations(report: &RiskReport, auto_confirm: bool) -> Result<()> {
    if report.has_blocked() {
        eprintln!("\n  {}  {}", "✗".red().bold(), "blocked".red().bold());
        for item in report.at_level(RiskLevel::Blocked) {
            eprintln!(
                "     {}   {}",
                format_short_path(&item.target),
                item.reason.dimmed()
            );
        }
        anyhow::bail!("plan contains blocked operations");
    }

    if !report.needs_confirmation() || auto_confirm {
        return Ok(());
    }

    let review: Vec<_> = report
        .items
        .iter()
        .filter(|item| matches!(item.level, RiskLevel::Medium | RiskLevel::High))
        .collect();

    eprintln!(
        "\n  {}  {} need review",
        "⚠".yellow().bold(),
        format!("{} operations", review.len()).bold()
    );
    for item in &review {
        eprintln!(
            "     {}   {}",
            format_short_path(&item.target),
            item.reason.dimmed()
        );
    }

    if !confirm("\n  proceed?")? {
        anyhow::bail!("aborted");
    }

    Ok(())
}
