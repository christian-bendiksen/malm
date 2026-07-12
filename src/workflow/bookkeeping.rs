//! Commits post-apply metadata: the target lock first, then ownership, mapping
//! asset targets to CAS payloads.

use crate::app::context::GlobalCtx;
use crate::planning::plan::DeploymentPlan;
use crate::source::SourceIdentity;
use crate::state::ownership::OwnershipWriteContext;
use crate::state::ownership_store::write_ownership_for;
use crate::state::target_lock::TargetLock;
use crate::state::transaction::{RecordedOp, TransactionStore};
use anyhow::{Context, Result};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

pub(crate) fn commit_apply_metadata(
    source: Option<&SourceIdentity>,
    config_path: &Path,
    plan: &DeploymentPlan,
    plan_targets: &[PathBuf],
    effective_profile: Option<&str>,
    ctx: &GlobalCtx,
    tx_id: Option<&str>,
) -> Result<()> {
    let mut lock = TargetLock::load().context("load target lock")?;
    lock.update_state(plan_targets, ctx.state_namespace.as_str());
    lock.save().context("persist target lock")?;

    let asset_sources = asset_payload_sources(tx_id)?;

    write_ownership_for(
        plan,
        &OwnershipWriteContext {
            state_namespace: ctx.state_namespace.as_str(),
            source,
            config: Some(config_path),
            profile: effective_profile,
            transaction_id: tx_id,
        },
        &asset_sources,
    )
    .context("persist ownership index")?;

    Ok(())
}

// Keyed by asset name: a merge-placed install records one (target, payload)
// row per placed payload directory, a whole-tree install exactly one.
fn asset_payload_sources(tx_id: Option<&str>) -> Result<HashMap<String, Vec<(PathBuf, PathBuf)>>> {
    let Some(id) = tx_id else {
        return Ok(HashMap::new());
    };
    let manifest = TransactionStore::new()
        .read(id)
        .with_context(|| format!("read manifest for {id}"))?;
    let mut sources: HashMap<String, Vec<(PathBuf, PathBuf)>> = HashMap::new();
    for op in &manifest.operations {
        if let RecordedOp::InstallAsset {
            name, dst, payload, ..
        } = op
        {
            sources
                .entry(name.clone())
                .or_default()
                .push((dst.clone(), payload.clone()));
        }
    }
    Ok(sources)
}
