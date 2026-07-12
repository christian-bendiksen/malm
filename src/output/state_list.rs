//! Table rendering for `malm state list`.

use crate::app::context::GlobalCtx;
use crate::app::validation::short_commit;
use crate::output::display::format_short_path;
use crate::source::{SourceIdentity, SourceKind};
use crate::workflow::state_list::{StateStatus, StateSummary};
use anyhow::Result;
use owo_colors::OwoColorize;
use std::fmt;

pub fn render(ctx: &GlobalCtx, summaries: &[StateSummary]) -> Result<()> {
    if ctx.json {
        let json = serde_json::to_string_pretty(summaries)?;
        println!("{json}");
        return Ok(());
    }

    if summaries.is_empty() {
        println!(
            "\n  {}  {}",
            "STATES".bold(),
            "no states recorded · run `malm apply` to create one".dimmed()
        );
        return Ok(());
    }

    print!(
        "{}",
        StateListReport {
            summaries,
            selected: ctx.state_namespace.as_str(),
        }
    );
    Ok(())
}

struct StateListReport<'a> {
    summaries: &'a [StateSummary],
    selected: &'a str,
}

impl fmt::Display for StateListReport<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let noun = if self.summaries.len() == 1 {
            "state"
        } else {
            "states"
        };
        writeln!(
            f,
            "\n  {}  {}",
            "STATES".bold(),
            format!("{} {noun}", self.summaries.len()).dimmed()
        )?;
        writeln!(f)?;

        for summary in self.summaries {
            writeln!(f, "{}", entry_line(summary))?;
        }

        writeln!(f)?;
        if !self.summaries.iter().any(|s| s.selected) {
            writeln!(
                f,
                "  {} state '{}' is selected but has no records yet",
                "!".yellow().bold(),
                self.selected
            )?;
        }
        writeln!(
            f,
            "  {}",
            "select with `--state <name>` · `malm state log` for history".dimmed()
        )
    }
}

fn entry_line(summary: &StateSummary) -> String {
    let dot = status_dot(summary.status);
    let name = format!("{:<14}", summary.name);
    let name = if summary.selected {
        name.bold().to_string()
    } else {
        name
    };
    let badge = status_badge(summary.status);
    let date = summary.last_applied.as_deref().unwrap_or("-");
    // ISO-8601 timestamp: the first 10 bytes are the date and always ASCII.
    let date = format!("{:<12}", &date[..date.len().min(10)]);
    let txns = format!("{:<8}", format!("{} txns", summary.transactions));
    let targets = match summary.targets {
        Some(count) => format!("{:<12}", format!("{count} targets")),
        None => format!("{:<12}", "? targets"),
    };
    let source = source_label(summary.source.as_ref());

    let mut line = format!("  {dot}  {name}{badge}{date}{txns}{targets}{source}");
    if summary.selected {
        line.push_str(&format!("  {}", "· selected".dimmed()));
    }
    if let Some(tracking) = &summary.tracking {
        line.push_str(&format!(
            "  {}",
            format!("· tracking {}", tracking.branch).dimmed()
        ));
    }
    if summary.pins > 0 {
        line.push_str(&format!(
            "  {}",
            format!("· pinned {}", summary.pins).dimmed()
        ));
    }
    if let Some(error) = &summary.error {
        line.push_str(&format!("  {}", format!("· {error}").red().dimmed()));
    }
    line
}

fn status_dot(status: StateStatus) -> String {
    match status {
        StateStatus::Deployed => "●".green().bold().to_string(),
        StateStatus::Disabled => "◌".dimmed().to_string(),
        StateStatus::Incomplete => "●".yellow().to_string(),
        StateStatus::Failed | StateStatus::Broken => "●".red().bold().to_string(),
        StateStatus::Empty => "○".dimmed().to_string(),
    }
}

fn status_badge(status: StateStatus) -> String {
    match status {
        StateStatus::Deployed => format!("{:<12}", "deployed").green().to_string(),
        StateStatus::Disabled => format!("{:<12}", "disabled").yellow().to_string(),
        StateStatus::Incomplete => format!("{:<12}", "incomplete").dimmed().to_string(),
        StateStatus::Failed => format!("{:<12}", "failed").red().bold().to_string(),
        StateStatus::Empty => format!("{:<12}", "empty").dimmed().to_string(),
        StateStatus::Broken => format!("{:<12}", "broken").red().bold().to_string(),
    }
}

fn source_label(source: Option<&SourceIdentity>) -> String {
    let Some(source) = source else {
        return "-".dimmed().to_string();
    };
    match &source.kind {
        SourceKind::Local { path } => {
            format!("local {}", format_short_path(path))
        }
        SourceKind::Git { url, commit } => {
            let host = url
                .trim_start_matches("https://")
                .trim_start_matches("git@");
            format!("{host} @{}", short_commit(commit, 7))
        }
    }
}
