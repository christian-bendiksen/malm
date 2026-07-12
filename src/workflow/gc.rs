//! Implements the state GC commands with human-readable byte accounting.

use crate::app::context::GlobalCtx;
use crate::state::gc::{Breakdown, CategoryUsage, PruneOptions, prune, usage};
use crate::state::pins::{add_pin, remove_pin};
use crate::state::record::{live_deployment_id_strict, restore_deployment_id};
use crate::state::target_lock::TargetLock;
use crate::state::transaction::{TransactionStore, transaction_alias};
use anyhow::{Result, anyhow};
use owo_colors::OwoColorize;

pub struct PruneArgs {
    pub keep: usize,
    pub keep_per_state: Option<usize>,
    pub dry_run: bool,
    pub verbose: bool,
    pub force: bool,
}

pub fn run(_ctx: &GlobalCtx, args: PruneArgs) -> Result<()> {
    let PruneArgs {
        keep,
        keep_per_state,
        dry_run,
        verbose,
        force,
    } = args;
    let _guard = TargetLock::acquire_guard()?;
    let report = prune(PruneOptions {
        keep,
        keep_per_state,
        dry_run,
        force,
    })?;
    let freed = human_bytes(report.breakdown.reclaimable_bytes());
    let count = report.breakdown.pruned_transactions();
    let noun = if count == 1 {
        "transaction"
    } else {
        "transactions"
    };
    let (verb, freed_label) = if report.dry_run {
        ("would prune", "would free")
    } else {
        ("pruned", "freed")
    };
    println!(
        "\n  {} {verb} {count} {noun} · {freed_label} {freed}",
        "✓".green().bold()
    );
    let retained = report.breakdown.transactions.reachable.count;
    if count == 0 && retained > 0 {
        let window = match keep_per_state {
            Some(per) => format!("newest {per} per state"),
            None => format!("newest {keep}"),
        };
        let noun = if retained == 1 {
            "transaction"
        } else {
            "transactions"
        };
        println!(
            "  {}",
            format!(
                "all {retained} {noun} retained ({window}, plus active and pinned) \
                 · tighten with --keep or --keep-per-state"
            )
            .dimmed()
        );
    }
    if verbose || dry_run {
        println!();
        print_breakdown(&report.breakdown);
    }
    Ok(())
}

pub fn run_usage(_ctx: &GlobalCtx, keep: usize, keep_per_state: Option<usize>) -> Result<()> {
    // Shared lock: read-only, but must not observe a torn store mid-apply.
    let _guard = TargetLock::acquire_shared_guard()?;
    let breakdown = usage(keep, keep_per_state)?;
    println!("\n  Malm state usage\n");
    print_breakdown(&breakdown);
    Ok(())
}

pub fn run_pin(ctx: &GlobalCtx, reference: &str) -> Result<()> {
    let _guard = TargetLock::acquire_guard()?;
    let id = resolve(ctx, reference)?;
    if add_pin(ctx.state_namespace.as_str(), &id)? {
        println!("  {} pinned {}", "✓".green().bold(), transaction_alias(&id));
    } else {
        println!("  already pinned {}", transaction_alias(&id));
    }
    Ok(())
}

pub fn run_unpin(ctx: &GlobalCtx, reference: &str) -> Result<()> {
    let _guard = TargetLock::acquire_guard()?;
    let id = resolve(ctx, reference)?;
    if remove_pin(ctx.state_namespace.as_str(), &id)? {
        println!(
            "  {} unpinned {}",
            "✓".green().bold(),
            transaction_alias(&id)
        );
    } else {
        println!("  {} was not pinned", transaction_alias(&id));
    }
    Ok(())
}

fn resolve(ctx: &GlobalCtx, reference: &str) -> Result<String> {
    let id = if reference == "current" {
        match live_deployment_id_strict(ctx.state_namespace.as_str())? {
            Some(id) => id,
            None => {
                if let Some(restore) = restore_deployment_id(ctx.state_namespace.as_str())? {
                    anyhow::bail!(
                        "state '{}' is disabled and has no live deployment; its restore \
                         target is {} — pin that explicitly if you mean it",
                        ctx.state_namespace,
                        transaction_alias(&restore)
                    );
                }
                return Err(anyhow!(
                    "no active transaction in state '{}' to pin",
                    ctx.state_namespace
                ));
            }
        }
    } else {
        TransactionStore::new().resolve_reference(reference)?
    };

    let manifest = TransactionStore::new().read(&id)?;
    if manifest.state_namespace() != ctx.state_namespace.as_str() {
        return Err(anyhow!(
            "transaction {} belongs to state '{}', not '{}'",
            transaction_alias(&id),
            manifest.state_namespace(),
            ctx.state_namespace
        ));
    }
    Ok(id)
}

fn print_breakdown(breakdown: &Breakdown) {
    row("transactions", breakdown.transactions);
    row("blobs", breakdown.blobs);
    row("source objects", breakdown.sources);
    row("asset archives", breakdown.asset_archives);
    row("asset payloads", breakdown.asset_payloads);
    row("git sources", breakdown.git_sources);
    row("git cache", breakdown.git_cache);
    println!(
        "\n    source objects and asset payloads may share storage with blobs; the freed\n    \
         total avoids double-counting and may under-report bytes actually reclaimed (a\n    \
         copy fallback on filesystems without reflink can hold real duplicate bytes).\n    \
         git sources and git cache hold their own bytes and are added to the total."
    );
}

fn row(label: &str, usage: CategoryUsage) {
    let total = usage.reachable.bytes + usage.reclaimable.bytes;
    println!(
        "    {label:<16} {:>10} · reachable {:>10} · reclaimable {:>10}",
        human_bytes(total),
        human_bytes(usage.reachable.bytes),
        human_bytes(usage.reclaimable.bytes),
    );
}

fn human_bytes(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} {}", UNITS[unit])
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}
