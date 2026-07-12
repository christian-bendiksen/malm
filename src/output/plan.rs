//! Human rendering of `malm plan`: sectioned actions, summary line with
//! risk badge, warnings and errors.

use crate::output::display::{Unit, format_short_path, unit_row, units};
use crate::planning::evaluation::{PreviewAction, TargetEvaluation, evaluate_plan_targets};
use crate::planning::plan::DeploymentPlan;
use crate::policy::risk::{RiskLevel, assess_plan};
use owo_colors::OwoColorize;
use std::fmt;

const SECTION_ORDER: [PreviewAction; 5] = [
    PreviewAction::Replace,
    PreviewAction::Create,
    PreviewAction::Download,
    PreviewAction::Remove,
    PreviewAction::Keep,
];

pub fn print_plan(plan: &DeploymentPlan, verbose: bool) {
    let entries = evaluate_plan_targets(plan);
    let risk = assess_plan(plan);
    print!(
        "{}",
        PlanReport {
            plan,
            entries: &entries,
            risk_level: risk.max_level(),
            verbose,
        }
    );
}

struct PlanReport<'a> {
    plan: &'a DeploymentPlan,
    entries: &'a [TargetEvaluation],
    risk_level: Option<RiskLevel>,
    verbose: bool,
}

impl fmt::Display for PlanReport<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let sections: Vec<(PreviewAction, Vec<Unit>)> = SECTION_ORDER
            .into_iter()
            .filter_map(|action| {
                let action_entries: Vec<&TargetEvaluation> = self
                    .entries
                    .iter()
                    .filter(|entry| entry.action == action)
                    .collect();
                (!action_entries.is_empty()).then(|| (action, units(&action_entries)))
            })
            .collect();

        let change: usize = sections
            .iter()
            .filter(|(action, _)| is_change(*action))
            .map(|(_, units)| units.len())
            .sum();
        let unchanged: usize = sections
            .iter()
            .find(|(action, _)| *action == PreviewAction::Keep)
            .map_or(0, |(_, units)| units.len());
        // Plan-level errors and per-target Error evaluations are distinct
        // sources; both count toward the summary.
        let errors = self.plan.errors().len()
            + self
                .entries
                .iter()
                .filter(|entry| entry.action == PreviewAction::Error)
                .count();

        writeln!(
            f,
            "\n  {}  {}  {}",
            "PLAN".bold(),
            plan_summary(errors, change, unchanged).dimmed(),
            risk_badge(self.risk_level)
        )?;

        print_attention(f, self.plan, self.entries)?;

        if self.verbose {
            for (action, units) in &sections {
                let noun = if units.len() == 1 {
                    "declaration"
                } else {
                    "declarations"
                };
                writeln!(
                    f,
                    "\n  {}  {}",
                    action_heading(*action),
                    format!("{} {}", units.len(), noun).dimmed()
                )?;
                for unit in units {
                    writeln!(f, "     {}", unit_row(unit))?;
                }
            }
        } else if change + unchanged > 0 {
            writeln!(f, "\n  {}", "run `malm plan -v` for details".dimmed())?;
        }

        Ok(())
    }
}

fn is_change(action: PreviewAction) -> bool {
    matches!(
        action,
        PreviewAction::Replace
            | PreviewAction::Create
            | PreviewAction::Download
            | PreviewAction::Remove
    )
}

fn plan_summary(errors: usize, change: usize, unchanged: usize) -> String {
    if errors > 0 {
        format!("{errors} blocked, {change} to change")
    } else if change > 0 {
        format!("{change} to change · {unchanged} unchanged")
    } else {
        format!("no changes · {unchanged} unchanged")
    }
}

fn risk_badge(risk: Option<RiskLevel>) -> String {
    match risk {
        Some(RiskLevel::Blocked) => "risk blocked".red().bold().to_string(),
        Some(RiskLevel::High) => "risk high".red().bold().to_string(),
        Some(RiskLevel::Medium) => "risk medium".yellow().bold().to_string(),
        Some(RiskLevel::Low) | None => "risk low".green().bold().to_string(),
    }
}

fn action_heading(action: PreviewAction) -> String {
    match action {
        PreviewAction::Error => "Errors".red().bold().to_string(),
        PreviewAction::Replace => "Replace".yellow().bold().to_string(),
        PreviewAction::Create | PreviewAction::Download => {
            action_label(action).green().bold().to_string()
        }
        PreviewAction::Remove => "Remove".red().bold().to_string(),
        PreviewAction::Keep => "Unchanged".dimmed().bold().to_string(),
    }
}

fn action_label(action: PreviewAction) -> &'static str {
    match action {
        PreviewAction::Error => "Errors",
        PreviewAction::Replace => "Replace",
        PreviewAction::Create => "Create",
        PreviewAction::Download => "Download",
        PreviewAction::Remove => "Remove",
        PreviewAction::Keep => "Unchanged",
    }
}

fn print_attention(
    f: &mut fmt::Formatter<'_>,
    plan: &DeploymentPlan,
    entries: &[TargetEvaluation],
) -> fmt::Result {
    if !plan.warnings().is_empty() {
        writeln!(
            f,
            "\n  {}  {}",
            "!".yellow().bold(),
            "Warnings".yellow().bold()
        )?;
        for msg in plan.warnings() {
            writeln!(f, "     {msg}")?;
        }
    }

    let error_entries: Vec<&TargetEvaluation> = entries
        .iter()
        .filter(|entry| entry.action == PreviewAction::Error)
        .collect();
    if plan.errors().is_empty() && error_entries.is_empty() {
        return Ok(());
    }

    writeln!(f, "\n  {}  {}", "✗".red().bold(), "Errors".red().bold())?;
    for entry in error_entries {
        writeln!(f, "     {}", format_short_path(&entry.target))?;
        if let Some(source) = &entry.source {
            writeln!(
                f,
                "       {} {}",
                "source".dimmed(),
                format_short_path(source).dimmed()
            )?;
        }
    }
    for msg in plan.errors() {
        if let Some(first) = msg.lines().next() {
            writeln!(f, "     {first}")?;
        }
    }
    Ok(())
}
