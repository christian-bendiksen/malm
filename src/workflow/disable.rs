//! Undeploys a state's targets without deleting its records. A `Disable`
//! transaction finalizes the state as Disabled, so no crash window separates
//! the filesystem and mode changes.
//!
//! By default, every owned target must be removed. `--keep-modified` allows
//! drifted or modified targets to remain and retains their ownership entries.

use crate::app::context::GlobalCtx;
use crate::app::prompt::confirm;
use crate::app::validation::validate_name;
use crate::config::{Config, LoadedConfigSource};
use crate::domain::id::StateName;
use crate::output::display::format_short_path;
use crate::output::print_plan;
use crate::paths::home_dir;
use crate::planning::plan::{DeploymentPlan, Operation};
use crate::planning::stale::{BlockedRemoval, plan_undeploy_removals};
use crate::source::store::SourceSnapshot;
use crate::source::{ResolvedSource, SourceIdentity, SourceKind, TrustMode};
use crate::state::ensure_state_exists;
use crate::state::ownership::OwnershipEntry;
use crate::state::ownership_store::read_ownership_for;
use crate::state::record::{
    StateMode, StateRecord, live_deployment_id_strict, live_source_snapshot_id_strict,
};
use crate::state::transaction::{TransactionKind, transaction_alias};
use crate::workflow::pipeline::{DeploymentPipeline, DisableFinalize};
use anyhow::{Context, Result};
use owo_colors::OwoColorize;
use std::path::PathBuf;

#[derive(Clone, Copy, Default)]
pub struct DisableOpts {
    pub yes: bool,
    /// Proceed when some owned targets cannot be safely removed, recording
    /// them as deliberately kept instead of refusing.
    pub keep_modified: bool,
    /// Show what would happen without changing anything.
    pub dry_run: bool,
}

pub fn run(ctx: &GlobalCtx, name: Option<&str>, opts: DisableOpts) -> Result<()> {
    let name = resolve_state_name(ctx, name, "disable")?;
    validate_name(name, "state name")?;
    ensure_state_exists(name)?;

    if matches!(
        StateRecord::load_for_state(name)?.map(|record| record.mode),
        Some(StateMode::Disabled { .. })
    ) {
        println!(
            "  {} state '{name}' is already disabled · `malm state enable {name}` restores it",
            "✓".green().bold()
        );
        return Ok(());
    }

    let Some(last_active) = live_deployment_id_strict(name)? else {
        anyhow::bail!(
            "state '{name}' has no completed deployment to disable; \
             `malm state destroy {name}` removes its records entirely"
        );
    };

    let ownership =
        read_ownership_for(name).with_context(|| format!("read ownership for state '{name}'"))?;
    let snapshot_id = live_source_snapshot_id_strict(name)?
        .context("state has an active transaction but no source snapshot")?;
    let snapshot = SourceSnapshot::from_id(&snapshot_id)?;
    snapshot.require_on_disk()?;

    let mut plan = DeploymentPlan::new();
    let blocked = plan_undeploy_removals(&mut plan, &ownership);
    plan.validate_target_relationships();

    if !blocked.is_empty() && !opts.keep_modified {
        let listing = blocked_listing(&blocked);
        anyhow::bail!(
            "cannot disable state '{name}': {} owned target(s) cannot be safely removed:\n\
             {listing}\n\
             re-run with --keep-modified to disable anyway and keep them tracked",
            blocked.len()
        );
    }
    let kept_entries: Vec<OwnershipEntry> = blocked
        .iter()
        .map(|removal| removal.entry.clone())
        .collect();
    let kept_targets: Vec<PathBuf> = kept_entries
        .iter()
        .map(|entry| entry.target.clone())
        .collect();

    let (symlink_removals, asset_removals) = removal_counts(&plan);

    if opts.dry_run {
        if ctx.json {
            print_dry_run_json(name, &plan, &blocked)?;
        } else {
            print_dry_run(name, &plan, &blocked);
        }
        return Ok(());
    }

    if !plan.operations().is_empty() {
        print_plan(&plan, false);
    }
    if !blocked.is_empty() {
        println!("\n  kept in place (still tracked):");
        for removal in &blocked {
            println!(
                "    {} — {}",
                format_short_path(&removal.entry.target),
                removal.reason
            );
        }
    }
    if !opts.yes
        && !confirm(&format!(
            "\n  disable state '{name}'? (deployed files are removed; \
             `malm state enable {name}` restores them)"
        ))?
    {
        anyhow::bail!("aborted");
    }

    if plan.operations().is_empty() {
        // A zero-op Disable still goes through the pipeline so the mode change
        // is recorded durably.
        println!("  state '{name}' owns no removable targets");
    }
    {
        let mut disable_ctx = ctx.clone();
        disable_ctx.state_namespace = StateName::parse(name)?;
        disable_ctx.profile = None;

        let repository_root = snapshot.repository().to_path_buf();
        let identity = ownership.source.clone().unwrap_or_else(|| SourceIdentity {
            kind: SourceKind::Local {
                path: repository_root.clone(),
            },
        });
        let trust_mode = match &identity.kind {
            SourceKind::Local { .. } => TrustMode::Trusted,
            SourceKind::Git { .. } => TrustMode::Untrusted,
        };
        let loaded = LoadedConfigSource {
            config: Config::empty(),
            resolved: ResolvedSource {
                source_root: repository_root.clone(),
                identity,
                trust_mode,
            },
            config_path: ownership
                .config
                .clone()
                .unwrap_or_else(|| repository_root.join("malm.kdl")),
            target_root: home_dir(),
            provenance: Vec::new(),
            external_includes_skipped: Vec::new(),
            // A disable removes targets; no config is read.
            allow_local_includes: false,
        };
        let recorded_repo = match ownership.source.as_ref().map(|source| &source.kind) {
            Some(SourceKind::Local { path }) => Some(path.clone()),
            _ => None,
        };

        let pipeline = DeploymentPipeline::prepare_from_manifest(
            &disable_ctx,
            loaded,
            plan,
            snapshot.id(),
            recorded_repo,
            TransactionKind::Disable,
        )?
        .with_disable_finalize(DisableFinalize {
            restore_transaction: last_active.clone(),
            kept_entries,
        });
        let pipeline = pipeline.approve_for_execution(Default::default())?;
        pipeline.execute(true)?;
    }

    let mut summary = format!("removed {symlink_removals} symlink(s)");
    if asset_removals > 0 {
        summary.push_str(&format!(", {asset_removals} asset(s)"));
    }
    if !kept_targets.is_empty() {
        summary.push_str(&format!("; kept {} modified target(s)", kept_targets.len()));
    }
    println!(
        "\n  {} disabled state '{name}' · {summary} · {}",
        "✓".green().bold(),
        format!(
            "`malm state enable {name}` restores deployment {}",
            transaction_alias(&last_active)
        )
        .dimmed()
    );
    Ok(())
}

fn removal_counts(plan: &DeploymentPlan) -> (usize, usize) {
    let assets = plan
        .operations()
        .iter()
        .filter(|op| matches!(op, Operation::RemoveAsset { .. }))
        .count();
    (plan.operations().len() - assets, assets)
}

fn blocked_listing(blocked: &[BlockedRemoval]) -> String {
    blocked
        .iter()
        .map(|removal| {
            format!(
                "  {} — {}",
                format_short_path(&removal.entry.target),
                removal.reason
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn print_dry_run(name: &str, plan: &DeploymentPlan, blocked: &[BlockedRemoval]) {
    println!("\n  {}  state '{name}'", "DISABLE (dry run)".bold());
    if plan.operations().is_empty() {
        println!("  nothing to remove");
    } else {
        println!("  would remove:");
        for op in plan.operations() {
            if let Some(target) = op.affected_target() {
                let kind = match op {
                    Operation::RemoveAsset { .. } => "asset",
                    _ => "symlink",
                };
                println!("    {} ({kind})", format_short_path(target));
            }
        }
    }
    if !blocked.is_empty() {
        println!("  cannot safely remove (would need --keep-modified):");
        for removal in blocked {
            println!(
                "    {} — {}",
                format_short_path(&removal.entry.target),
                removal.reason
            );
        }
    }
    println!("\n  no changes made");
}

fn print_dry_run_json(name: &str, plan: &DeploymentPlan, blocked: &[BlockedRemoval]) -> Result<()> {
    let would_remove: Vec<_> = plan
        .operations()
        .iter()
        .filter_map(|op| {
            let kind = match op {
                Operation::RemoveAsset { .. } => "asset",
                _ => "symlink",
            };
            op.affected_target()
                .map(|target| serde_json::json!({ "target": target, "kind": kind }))
        })
        .collect();
    let cannot_remove: Vec<_> = blocked
        .iter()
        .map(|removal| {
            serde_json::json!({
                "target": removal.entry.target,
                "reason": removal.reason,
            })
        })
        .collect();
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "state": name,
            "dry_run": true,
            "would_remove": would_remove,
            "cannot_remove": cannot_remove,
        }))?
    );
    Ok(())
}

pub(crate) fn resolve_state_name<'a>(
    ctx: &'a GlobalCtx,
    name: Option<&'a str>,
    verb: &str,
) -> Result<&'a str> {
    let name = match name {
        Some(name) => name,
        None if ctx.state_namespace.as_str() != "default" => ctx.state_namespace.as_str(),
        None => "default",
    };
    if ctx.state_namespace.as_str() != "default" && ctx.state_namespace.as_str() != name {
        anyhow::bail!(
            "--state {:?} conflicts with the state named on the command line ({name:?}); \
             `state {verb}` takes the state as its positional argument",
            ctx.state_namespace
        );
    }
    Ok(name)
}
