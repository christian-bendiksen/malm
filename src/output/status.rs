//! Human and JSON rendering for `malm status`.

use crate::output::display::{common_ancestor, format_short_path, owner_kind};
use crate::source::SourceIdentity;
use crate::state::transaction::transaction_alias;
use crate::status::ownership::{
    ManagedPathStatus, OwnershipStatusReport, SourcePointerHealth, TargetLockHealth,
};
use anyhow::Result;
use owo_colors::OwoColorize;
use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};

pub fn print(
    report: &OwnershipStatusReport,
    state_namespace: &str,
    active_id: &str,
    verbose: bool,
) {
    print!(
        "{}",
        StatusView {
            state_namespace,
            source: report.source.as_ref(),
            active_id,
            results: &report.results,
            source_pointer: report.source_pointer,
            target_lock: &report.target_lock,
            verbose,
        }
    );
}

pub fn to_json(report: &OwnershipStatusReport, state_namespace: &str) -> Result<String> {
    use serde_json::json;

    let entries: Vec<_> = report
        .results
        .iter()
        .map(|entry| {
            json!({
                "path": entry.path.display().to_string(),
                "expected": entry.expected.as_ref().map(|path| path.display().to_string()),
                "owner": entry.owner,
                "status": entry.status,
            })
        })
        .collect();

    let lock_issues: Vec<_> = match &report.target_lock {
        TargetLockHealth::ForeignConflict(conflicts) => conflicts
            .iter()
            .map(|c| {
                json!({
                    "target": c.target.display().to_string(),
                    "conflicts_with": c.conflicts_with.display().to_string(),
                    "state": c.state,
                })
            })
            .collect(),
        _ => Vec::new(),
    };
    let payload = json!({
        "state": state_namespace,
        "source_pointer": { "status": report.source_pointer.label() },
        "target_lock": { "status": report.target_lock.label(), "issues": lock_issues },
        "entries": entries,
    });
    Ok(serde_json::to_string_pretty(&payload)?)
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Health {
    Ok,
    Drift,
    Missing,
}

// Any unrecognized status sorts as drift. New statuses are
// visible by default instead of silently "ok".
fn health(status: &str) -> Health {
    match status {
        "ok" | "present" => Health::Ok,
        "missing" => Health::Missing,
        _ => Health::Drift,
    }
}

struct StatusUnit {
    kind: &'static str,
    dest: PathBuf,
    count: usize,
    issues: usize,
    worst: Health,
    link_target: Option<PathBuf>,
}

fn status_units(results: &[ManagedPathStatus]) -> Vec<StatusUnit> {
    let mut groups: BTreeMap<String, Vec<&ManagedPathStatus>> = BTreeMap::new();
    for entry in results {
        let collapses = matches!(owner_kind(&entry.owner), "dir" | "stale");
        let key = if collapses {
            entry.owner.clone()
        } else {
            format!("{}\u{0}{}", entry.owner, entry.path.display())
        };
        groups.entry(key).or_default().push(entry);
    }

    let mut units: Vec<StatusUnit> = groups
        .into_values()
        .map(|items| {
            let kind = owner_kind(&items[0].owner);
            let dest = if items.len() == 1 {
                items[0].path.clone()
            } else {
                let paths: Vec<&Path> = items.iter().map(|entry| entry.path.as_path()).collect();
                common_ancestor(&paths)
            };
            let issues = items
                .iter()
                .filter(|entry| health(entry.status) != Health::Ok)
                .count();
            let worst = items
                .iter()
                .map(|entry| health(entry.status))
                .max()
                .unwrap_or(Health::Ok);
            let link_target = if kind == "symlink" {
                items[0].expected.clone()
            } else {
                None
            };
            StatusUnit {
                kind,
                dest,
                count: items.len(),
                issues,
                worst,
                link_target,
            }
        })
        .collect();

    units.sort_by(|a, b| {
        b.worst
            .cmp(&a.worst)
            .then_with(|| a.kind.cmp(b.kind))
            .then_with(|| a.dest.cmp(&b.dest))
    });
    units
}

fn kind_display(kind: &str) -> &str {
    if kind == "symlink" { "link" } else { kind }
}

fn status_row(unit: &StatusUnit) -> String {
    let badge = match unit.worst {
        Health::Ok => format!("{:<8}", "ok").green().to_string(),
        Health::Drift => format!("{:<8}", "drift").yellow().bold().to_string(),
        Health::Missing => format!("{:<8}", "missing").red().bold().to_string(),
    };
    let kind = format!("{:<9}", kind_display(unit.kind))
        .dimmed()
        .to_string();
    let mut row = format!("{badge}{kind}{}", format_short_path(&unit.dest));

    if unit.count > 1 {
        let detail = if unit.issues > 0 {
            format!("   {}/{} affected", unit.issues, unit.count)
        } else {
            format!("   {} files", unit.count)
        };
        row.push_str(&detail.dimmed().to_string());
    }
    if let Some(target) = &unit.link_target {
        row.push_str(
            &format!("  →  {}", format_short_path(target))
                .dimmed()
                .to_string(),
        );
    }
    row
}

struct StatusView<'a> {
    state_namespace: &'a str,
    source: Option<&'a SourceIdentity>,
    active_id: &'a str,
    results: &'a [ManagedPathStatus],
    source_pointer: SourcePointerHealth,
    target_lock: &'a TargetLockHealth,
    verbose: bool,
}

impl StatusView<'_> {
    fn has_object_corruption(&self) -> bool {
        matches!(self.source_pointer, SourcePointerHealth::TargetMissing)
            || self
                .results
                .iter()
                .any(|r| matches!(r.status, "source-missing" | "payload-missing"))
    }
}

fn pointer_badge(health: SourcePointerHealth) -> String {
    match health {
        SourcePointerHealth::Ok => health.label().green().to_string(),
        SourcePointerHealth::Drift => health.label().yellow().bold().to_string(),
        SourcePointerHealth::Missing
        | SourcePointerHealth::Orphaned
        | SourcePointerHealth::TargetMissing
        | SourcePointerHealth::Malformed => health.label().red().bold().to_string(),
    }
}

impl fmt::Display for StatusView<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let total = self.results.len();
        let drift = self
            .results
            .iter()
            .filter(|entry| health(entry.status) == Health::Drift)
            .count();
        let missing = self
            .results
            .iter()
            .filter(|entry| health(entry.status) == Health::Missing)
            .count();
        let ok = total - drift - missing;

        let pointer_ok = self.source_pointer.is_ok();

        let mut summary = format!("{total} managed · {ok} ok");
        if drift > 0 {
            summary.push_str(&format!(" · {drift} drift"));
        }
        if missing > 0 {
            summary.push_str(&format!(" · {missing} missing"));
        }
        if !pointer_ok {
            summary.push_str(&format!(" · pointer {}", self.source_pointer.label()));
        }
        let lock_ok = self.target_lock.is_ok();
        if !lock_ok {
            summary.push_str(&format!(" · lock {}", self.target_lock.label()));
        }
        writeln!(f, "\n  {}  {}", "STATUS".bold(), summary.dimmed())?;

        writeln!(f, "  {}   {}", "state".dimmed(), self.state_namespace)?;
        if let Some(source) = self.source {
            let label = format_short_path(Path::new(&source.display_label()));
            writeln!(f, "  {}  {label}", "source".dimmed())?;
        }
        if self.active_id != "<none>" {
            let short = transaction_alias(self.active_id);
            writeln!(f, "  {}  {short}", "active".dimmed())?;
        }
        if !self.source_pointer.is_ok() || self.verbose {
            writeln!(
                f,
                "  {} {}",
                "pointer".dimmed(),
                pointer_badge(self.source_pointer)
            )?;
        }
        if !lock_ok || self.verbose {
            let badge = if lock_ok {
                "ok".green().to_string()
            } else {
                self.target_lock.label().red().bold().to_string()
            };
            writeln!(f, "  {}    {badge}", "lock".dimmed())?;
        }

        if total == 0 && pointer_ok && lock_ok {
            writeln!(f, "\n  {}", "no configuration is managed".dimmed())?;
            return Ok(());
        }

        if total > 0 {
            let units = status_units(self.results);
            let shown: Vec<&StatusUnit> = if self.verbose {
                units.iter().collect()
            } else {
                units
                    .iter()
                    .filter(|unit| unit.worst != Health::Ok)
                    .collect()
            };
            if !shown.is_empty() {
                writeln!(f)?;
                for unit in shown {
                    writeln!(f, "     {}", status_row(unit))?;
                }
            }
        }

        // Footer precedence: a lock conflict explains more than corruption,
        // which explains more than plain drift; show only the most specific.
        if drift + missing == 0 && pointer_ok && lock_ok {
            writeln!(f, "\n  {} synced with ownership state", "✓".green().bold())?;
        } else if matches!(self.target_lock, TargetLockHealth::ForeignConflict(_)) {
            writeln!(
                f,
                "\n  {} lock conflict with another state — resolve it or select the \
                 owning state with {}",
                "!".red().bold(),
                "`--state`".cyan()
            )?;
        } else if self.has_object_corruption() {
            writeln!(
                f,
                "\n  {} content objects missing — run {} to re-deploy; a partially \
                 corrupted object must be removed manually to rebuild",
                "!".red().bold(),
                "`malm apply`".cyan()
            )?;
        } else {
            writeln!(
                f,
                "\n  {} drifted — run {} to restore",
                "!".yellow().bold(),
                "`malm apply`".cyan()
            )?;
        }
        Ok(())
    }
}
