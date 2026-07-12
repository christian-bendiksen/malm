//! Rendering for `malm state log`: the five most recent transactions for
//! the current state, newest first.

use crate::app::context::GlobalCtx;
use crate::app::validation::short_commit;
use crate::output::display::format_short_path;
use crate::source::SourceKind;
use crate::state::ensure_state_exists;
use crate::state::ownership::unix_to_iso8601;
use crate::state::record::{live_deployment_id, restore_deployment_id};
use crate::state::transaction::{
    OperationStatus, TransactionKind, TransactionManifest, TransactionStatus, TransactionStore,
    transaction_alias,
};
use anyhow::Result;
use owo_colors::OwoColorize;
use std::fmt;

pub fn print_transaction_log(ctx: &GlobalCtx) -> Result<()> {
    let store = TransactionStore::new();
    let mut manifests = store.list_all()?;
    retain_state(&mut manifests, ctx.state_namespace.as_str());

    if manifests.is_empty() && ctx.state_namespace.as_str() != "default" {
        ensure_state_exists(ctx.state_namespace.as_str())?;
    }

    if ctx.json {
        let json = serde_json::to_string_pretty(&manifests)?;
        println!("{json}");
        return Ok(());
    }

    if manifests.is_empty() {
        println!("\n  {}  {}", "HISTORY".bold(), "no transactions".dimmed());
        return Ok(());
    }

    // Sorted by manifest mtime, not started_at: metadata repairs and
    // recovery re-writes should bubble a transaction back up the log.
    manifests.sort_by_cached_key(|m| {
        let path = store.transaction_dir(m.id.as_str()).join("manifest.json");
        std::cmp::Reverse(
            std::fs::metadata(&path)
                .and_then(|meta| meta.modified())
                .unwrap_or(std::time::SystemTime::UNIX_EPOCH),
        )
    });

    // A disabled state has no live deployment; its restore target is
    // annotated instead of being falsely marked active.
    let active_id = live_deployment_id(ctx.state_namespace.as_str())?;
    let restore_id = restore_deployment_id(ctx.state_namespace.as_str())?;
    let total = manifests.len();
    manifests.truncate(5);

    print!(
        "{}",
        TransactionLogReport {
            manifests: &manifests,
            active_id: active_id.as_deref(),
            restore_id: restore_id.as_deref(),
            state_namespace: ctx.state_namespace.as_str(),
            total,
        }
    );
    Ok(())
}

fn retain_state(manifests: &mut Vec<TransactionManifest>, state_namespace: &str) {
    manifests.retain(|manifest| manifest.state_namespace() == state_namespace);
}

struct TransactionLogReport<'a> {
    manifests: &'a [TransactionManifest],
    active_id: Option<&'a str>,
    restore_id: Option<&'a str>,
    state_namespace: &'a str,
    total: usize,
}

impl fmt::Display for TransactionLogReport<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let noun = if self.total == 1 {
            "transaction"
        } else {
            "transactions"
        };
        writeln!(
            f,
            "\n  {}  {}",
            "HISTORY".bold(),
            format!("{} {noun} · {}", self.total, self.state_namespace).dimmed()
        )?;
        writeln!(f)?;

        for manifest in self.manifests {
            let marker = if self.active_id == Some(manifest.id.as_str()) {
                EntryMarker::Active
            } else if self.restore_id == Some(manifest.id.as_str()) {
                EntryMarker::Restore
            } else {
                EntryMarker::None
            };
            writeln!(f, "{}", entry_line(manifest, marker))?;
        }
        Ok(())
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum EntryMarker {
    Active,
    /// The non-live deployment a disabled state would restore.
    Restore,
    None,
}

fn entry_line(manifest: &TransactionManifest, marker: EntryMarker) -> String {
    let dot = match marker {
        EntryMarker::Active => "●".green().bold().to_string(),
        EntryMarker::Restore => "◌".yellow().to_string(),
        EntryMarker::None => "○".dimmed().to_string(),
    };
    let badge = match marker {
        EntryMarker::Active => format!("{:<8}", "active").green().to_string(),
        EntryMarker::Restore => format!("{:<8}", "restore").yellow().to_string(),
        EntryMarker::None => format!("{:<8}", ""),
    };
    let alias = format!("{:<14}", transaction_alias(manifest.id.as_str()));
    let date = unix_to_iso8601(manifest.started_at);
    let date = format!("{:<12}", &date[..date.len().min(10)]);

    let applied = manifest
        .operations
        .iter()
        .filter(|op| op.status() == OperationStatus::Applied)
        .count();
    let ops = format!("{:<8}", format!("{applied} ops"));

    let source = source_label(manifest);
    let status = status_tag(manifest.status);
    let kind = match manifest.kind {
        TransactionKind::Destroy => format!("  {}", "· destroy".red()),
        TransactionKind::Disable => format!("  {}", "· disable".yellow()),
        TransactionKind::Apply => String::new(),
    };

    format!("  {dot}  {badge}{alias}{date}{ops}{source}{kind}{status}")
}

fn source_label(manifest: &TransactionManifest) -> String {
    if let Some(source) = &manifest.source {
        return match &source.kind {
            SourceKind::Local { path } => {
                format!("local {}", format_short_path(path))
            }
            SourceKind::Git { url, commit } => {
                let host = url
                    .trim_start_matches("https://")
                    .trim_start_matches("git@");
                format!("{host} @{}", short_commit(commit, 7))
            }
        };
    }
    if let Some(repo) = &manifest.repo {
        return format!("local {}", format_short_path(repo));
    }
    "unknown".dimmed().to_string()
}

fn status_tag(status: TransactionStatus) -> String {
    match status {
        TransactionStatus::Completed => String::new(),
        TransactionStatus::Failed | TransactionStatus::MetadataFailed => {
            format!("  {}", "· failed".red().bold())
        }
        TransactionStatus::Started | TransactionStatus::FilesystemApplied => {
            format!("  {}", "· incomplete".dimmed())
        }
        TransactionStatus::RolledBack => format!("  {}", "· rolled back".dimmed()),
    }
}
