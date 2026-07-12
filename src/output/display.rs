//! Sanitized paths, owner grouping, and compact path display.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use owo_colors::OwoColorize;

use crate::app::validation::short_commit;
use crate::paths::{home_dir, xdg_state_home};
use crate::planning::evaluation::TargetEvaluation;
use crate::sanitize::terminal;
use crate::state::transaction::transaction_alias;

pub const KIND_ORDER: [&str; 7] = [
    "dir",
    "template-dir",
    "file",
    "template",
    "symlink",
    "asset",
    "stale",
];

/// Sanitized full-path display for user-facing output. Paths can carry
/// attacker-chosen bytes (repo file names, archive entries); never print
/// them raw to a terminal.
pub fn path(path: &Path) -> String {
    terminal(&path.display().to_string()).into_owned()
}

pub fn owner_kind(label: &str) -> &'static str {
    match label.split_whitespace().next().unwrap_or("item") {
        "dir" => "dir",
        "file" => "file",
        "template-file" => "template",
        "template-dir" => "template-dir",
        "symlink" | "link" => "symlink",
        "asset" => "asset",
        "stale" => "stale",
        _ => "asset",
    }
}

fn kind_rank(kind: &str) -> usize {
    KIND_ORDER
        .iter()
        .position(|candidate| *candidate == kind)
        .unwrap_or(KIND_ORDER.len())
}

fn kind_display(kind: &str) -> &str {
    if kind == "symlink" { "link" } else { kind }
}

pub fn common_ancestor(paths: &[&Path]) -> PathBuf {
    let Some((first, rest)) = paths.split_first() else {
        return PathBuf::new();
    };
    let mut prefix = first.to_path_buf();
    for path in rest {
        let mut common = PathBuf::new();
        for (a, b) in prefix.components().zip(path.components()) {
            if a == b {
                common.push(a.as_os_str());
            } else {
                break;
            }
        }
        prefix = common;
    }
    prefix
}

pub struct Unit {
    pub kind: &'static str,
    pub dest: PathBuf,
    pub count: usize,
    pub link_target: Option<PathBuf>,
    /// Asset name shown when multiple assets share an extraction root.
    pub detail: Option<String>,
}

pub fn units(entries: &[&TargetEvaluation]) -> Vec<Unit> {
    let mut groups: BTreeMap<String, Vec<&TargetEvaluation>> = BTreeMap::new();
    for entry in entries {
        // dir/template-dir/stale entries collapse into one row per declaration;
        // file-like entries stay one row per target.
        let collapses = matches!(owner_kind(&entry.owner), "dir" | "template-dir" | "stale");
        let key = if collapses {
            entry.owner.clone()
        } else {
            format!("{}\u{0}{}", entry.owner, entry.target.display())
        };
        groups.entry(key).or_default().push(entry);
    }

    let mut units: Vec<Unit> = groups
        .into_values()
        .map(|items| {
            let kind = owner_kind(&items[0].owner);
            let dest = if items.len() == 1 {
                items[0].target.clone()
            } else {
                let targets: Vec<&Path> = items.iter().map(|e| e.target.as_path()).collect();
                common_ancestor(&targets)
            };
            let link_target = if kind == "symlink" {
                items.first().and_then(|entry| entry.source.clone())
            } else {
                None
            };
            let detail = if kind == "asset" {
                items[0]
                    .owner
                    .split_once(' ')
                    .map(|(_, name)| terminal(name).into_owned())
            } else {
                None
            };
            Unit {
                kind,
                dest,
                count: items.len(),
                link_target,
                detail,
            }
        })
        .collect();

    units.sort_by(|a, b| {
        kind_rank(a.kind)
            .cmp(&kind_rank(b.kind))
            .then(b.count.cmp(&a.count))
            .then_with(|| a.dest.cmp(&b.dest))
    });
    units
}

pub fn unit_row(unit: &Unit) -> String {
    let kind = format!("{:<13}", kind_display(unit.kind));
    let mut row = format!("{}{}", kind.dimmed(), format_short_path(&unit.dest));
    if unit.count > 1 {
        row.push_str(&format!("   {} files", unit.count).dimmed().to_string());
    }
    if let Some(target) = &unit.link_target {
        row.push_str(
            &format!("  →  {}", format_short_path(target))
                .dimmed()
                .to_string(),
        );
    }
    if let Some(detail) = &unit.detail {
        row.push_str(&format!("   {detail}").dimmed().to_string());
    }
    row
}

fn format_short_commit(commit: &str) -> String {
    short_commit(commit, 8)
}

pub fn format_short_path(path: &Path) -> String {
    terminal(&format_short_path_inner(path)).into_owned()
}

fn format_short_path_inner(path: &Path) -> String {
    let state_dir = xdg_state_home().join("malm");

    // Recover a compact repository label when the cache layout matches.
    if let Ok(stripped) = path.strip_prefix(state_dir.join("sources/git")) {
        let mut components = stripped.components();
        if let (Some(folder), Some(commit)) = (components.next(), components.next()) {
            let folder_str = folder.as_os_str().to_string_lossy();
            let commit_str = commit.as_os_str().to_string_lossy();

            let short_commit = format_short_commit(&commit_str);

            let clean_folder = folder_str
                .rsplit_once('_')
                .map(|(name, _)| name)
                .unwrap_or(&folder_str);
            let mut clean_name = clean_folder.replace('_', "/");

            if clean_folder.len() >= 40 {
                clean_name.push_str("...");
            }

            return format!("<cache> {clean_name} @ {short_commit}");
        }
    }

    if let Ok(stripped) = path.strip_prefix(state_dir.join("store")) {
        let mut components = stripped.components();
        if let Some(tx_id) = components.next() {
            let short_tx = transaction_alias(&tx_id.as_os_str().to_string_lossy());
            let rest = components.as_path().display();
            return format!("<store:{short_tx}>/{rest}");
        }
    }

    let home = home_dir();
    if let Ok(stripped) = path.strip_prefix(&home) {
        format!("~/{}", stripped.display())
    } else {
        path.display().to_string()
    }
}
