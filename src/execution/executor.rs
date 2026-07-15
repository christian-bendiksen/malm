//! Prefetches assets, journals and applies operations in dependency order, then
//! marks the transaction filesystem-applied.

use crate::execution::asset::{AssetInstall, execute_asset_install};
use crate::execution::asset_restore::execute_asset_restore;
use crate::execution::prefetch::{PrefetchedAssets, prefetch_assets};
use crate::execution::session::ApplySession;
use crate::execution::symlink::execute_symlink_create;
use crate::execution::{SourceResolver, remove};
use crate::failpoint;
use crate::planning::graph::build_operation_graph;
use crate::planning::plan::{DeploymentPlan, Operation};
use crate::state::transaction::{
    DesiredAsset, DesiredLink, TransactionManifest, TransactionMeta, TransactionStore,
};
use anyhow::{Context, Result};

pub fn apply_plan(
    plan: &DeploymentPlan,
    meta: TransactionMeta,
    record_even_if_empty: bool,
    resolver: &SourceResolver,
    allow_ssrf: bool,
) -> Result<Option<String>> {
    let store = TransactionStore::new();
    apply_plan_with_store(
        plan,
        meta,
        record_even_if_empty,
        resolver,
        &store,
        allow_ssrf,
    )
}

fn apply_plan_with_store(
    plan: &DeploymentPlan,
    meta: TransactionMeta,
    record_even_if_empty: bool,
    resolver: &SourceResolver,
    store: &TransactionStore,
    allow_ssrf: bool,
) -> Result<Option<String>> {
    if plan.has_errors() {
        anyhow::bail!(
            "{} error(s) in plan:\n{}",
            plan.errors().len(),
            plan.errors().join("\n")
        );
    }

    for warning in plan.warnings() {
        crate::warn_term!("warning: {warning}");
    }

    let populate_desired_state = |manifest: &mut TransactionManifest| {
        manifest.desired_links = plan
            .operations()
            .iter()
            .filter_map(|operation| match operation {
                Operation::CreateSymlink {
                    source,
                    target,
                    owner,
                    ..
                } => Some(DesiredLink {
                    target: target.clone(),
                    source: source.clone(),
                    owner: owner.clone(),
                }),
                _ => None,
            })
            .collect();
        manifest.desired_assets = plan
            .operations()
            .iter()
            .filter_map(|operation| match operation {
                Operation::KeepAsset {
                    name,
                    target,
                    previous,
                    declaration,
                } => Some(DesiredAsset {
                    name: name.clone(),
                    target: target.clone(),
                    source: previous
                        .as_ref()
                        .map(|entry| entry.source.clone())
                        .unwrap_or_else(|| target.clone()),
                    transaction: previous
                        .as_ref()
                        .and_then(|entry| entry.transaction.clone()),
                    declaration: declaration.clone(),
                }),
                _ => None,
            })
            .collect();
        manifest.retained_ownership = plan.retained_ownership().to_vec();
    };

    // A source-only change produces no ops but must still record a
    // transaction ("source anchoring") so checkout/GC see the new snapshot.
    if plan.operations().is_empty() {
        if !record_even_if_empty {
            println!("  0 operations - no changes needed");
            return Ok(None);
        }
        let mut manifest = TransactionManifest::new(meta.id.clone(), meta);
        populate_desired_state(&mut manifest);
        manifest.mark_filesystem_applied();
        let id = manifest.id.clone();
        store
            .write(&manifest)
            .context("persist source-anchoring transaction manifest")?;
        failpoint!("apply.after_fs");
        println!("\n  No filesystem changes; recorded transaction {id} to update state records");
        return Ok(Some(id.as_str().to_owned()));
    }

    let graph = match plan.operation_graph() {
        Some(graph) => graph.clone(),
        None => build_operation_graph(plan.operations())?,
    };

    // Stage every payload in the CAS before mutating targets. Downloads run in
    // parallel, but all must succeed before target changes begin.
    let prefetched = prefetch_assets(plan, allow_ssrf)?;

    let tx_id = meta.id.clone();
    let mut manifest = TransactionManifest::new(tx_id, meta);
    populate_desired_state(&mut manifest);

    let mut session = ApplySession::begin(manifest, store.clone())?;
    failpoint!("apply.after_manifest_write");

    // Release obsolete concrete asset placements before any new owner can
    // claim them. Doing this as a pre-phase makes shared-root ownership
    // handoffs independent of declaration/topological order.
    if let Err(error) = remove_obsolete_asset_placements(plan, &prefetched, &mut session) {
        let alias = session.alias();
        session.fail();
        return Err(error).context(format!(
            "failed to remove obsolete asset placements before apply — run `malm state recover \
             {alias}` to restore the previous state"
        ));
    }

    // Apply mutations serially in dependency order so recovery can replay the
    // deterministic journal in reverse.
    for batch in graph.batched_topo_sorted() {
        for (applied_in_batch, &op_idx) in batch.iter().enumerate() {
            failpoint!("apply.mid_ops");
            if let Err(err) = execute_operation(
                &plan.operations()[op_idx],
                &prefetched,
                op_idx,
                resolver,
                &mut session,
            ) {
                let alias = session.alias();
                session.fail();
                let total = batch.len();
                return Err(err).context(format!(
                    "operation #{op_idx} failed after {applied_in_batch} of {total} operations in \
                     this batch were processed — run `malm state recover \
                     {alias}` to restore the previous state"
                ));
            }
            failpoint!("apply.after_op");
        }
        session.persist_progress()?;
    }

    // Nothing was journaled, every kept asset already had an owner, and
    // history exists. Recording this transaction would add only noise.
    let all_kept_assets_owned = plan
        .operations()
        .iter()
        .all(|op| !matches!(op, Operation::KeepAsset { previous: None, .. }));

    let has_existing_logs = store.has_transactions()?;

    if !record_even_if_empty
        && session.operation_count() == 0
        && all_kept_assets_owned
        && has_existing_logs
    {
        session.discard()?;
        println!("\n  No changes.");
        return Ok(None);
    }

    let finished = session.finish_filesystem_applied()?;
    failpoint!("apply.after_fs");
    let id = finished.manifest.id;

    println!("\n  Filesystem changes applied (transaction {id})");
    Ok(Some(id.as_str().to_owned()))
}

fn execute_operation(
    op: &Operation,
    prefetched: &PrefetchedAssets,
    op_index: usize,
    resolver: &SourceResolver,
    session: &mut ApplySession,
) -> Result<()> {
    match op {
        Operation::CreateSymlink {
            source: src,
            target: dst,
            policy,
            conflict,
            owner,
        } => execute_symlink_create(src, dst, *policy, *conflict, owner, resolver, session),
        Operation::RemovePath {
            path,
            owner,
            expected_symlink_target,
        } => remove::execute(path, owner, expected_symlink_target.as_ref(), session),
        Operation::InstallAsset {
            name,
            url,
            target: dst,
            sha256,
            refresh_font_cache,
            declaration,
            ..
        } => {
            let payload = prefetched.payload_for(op_index, name)?.to_path_buf();
            execute_asset_install(
                AssetInstall {
                    name,
                    url,
                    dst,
                    sha256,
                    refresh_font_cache: *refresh_font_cache,
                    declaration,
                },
                &payload,
                prefetched.merge_entries_for(op_index),
                session,
            )
        }
        Operation::RemoveAsset {
            name,
            target: dst,
            payload,
        } => crate::execution::asset::execute_asset_remove(name, dst, payload, session),
        Operation::KeepAsset { .. } => Ok(()),
        Operation::RestoreAsset {
            name,
            url,
            payload,
            target: dst,
            declaration,
        } => execute_asset_restore(name, url, payload, dst, declaration, session),
    }
}

fn remove_obsolete_asset_placements(
    plan: &DeploymentPlan,
    prefetched: &PrefetchedAssets,
    session: &mut ApplySession,
) -> Result<()> {
    for (op_index, operation) in plan.operations().iter().enumerate() {
        let Operation::InstallAsset {
            name,
            target,
            previous,
            ..
        } = operation
        else {
            continue;
        };
        let placements: std::collections::HashSet<_> = match prefetched.merge_entries_for(op_index)
        {
            Some(entries) => entries.iter().map(|entry| target.join(entry)).collect(),
            None => std::iter::once(target.clone()).collect(),
        };
        for owned in previous
            .iter()
            .filter(|owned| !placements.contains(&owned.target))
            .filter(|owned| owned.source != owned.target)
        {
            crate::execution::asset::execute_asset_remove(
                name,
                &owned.target,
                &owned.source,
                session,
            )?;
        }
    }
    Ok(())
}
