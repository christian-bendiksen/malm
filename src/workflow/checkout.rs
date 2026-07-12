//! Re-deploys a recorded transaction through the normal pipeline, including
//! stale removals based on current ownership.

use crate::app::context::GlobalCtx;
use crate::config::{Config, LoadedConfigSource};
use crate::paths::home_dir;
use crate::planning::stale::plan_stale_removals;
use crate::source::store::SourceSnapshot;
use crate::source::{ResolvedSource, SourceIdentity, SourceKind, TrustMode};
use crate::state::ownership_store::read_ownership_for;
use crate::state::tracking::TrackedRemote;
use crate::state::transaction::{
    TransactionKind, TransactionStatus, TransactionStore, transaction_alias,
};
use crate::workflow::frozen_plan::frozen_plan_from_manifest;
use crate::workflow::pipeline::DeploymentPipeline;
use anyhow::{Context, Result};
use owo_colors::OwoColorize;

#[derive(Clone, Copy, Default)]
pub struct CheckoutOpts {
    pub yes: bool,
    /// Re-hash the source snapshot against its content address before use.
    pub verify: bool,
}

pub fn run(ctx: &GlobalCtx, id: &str, opts: CheckoutOpts) -> Result<()> {
    let store = TransactionStore::new();
    let full_id = store.resolve_reference(id)?;
    let manifest = store.read(&full_id)?;

    if manifest.state_namespace() != ctx.state_namespace.as_str() {
        anyhow::bail!(
            "transaction {} belongs to state '{}', not '{}'",
            manifest.id,
            manifest.state_namespace(),
            ctx.state_namespace
        );
    }

    if manifest.status != TransactionStatus::Completed {
        anyhow::bail!(
            "cannot check out transaction {} because its status is '{}'; \
             only completed transactions can be checked out",
            manifest.id,
            manifest.status.label()
        );
    }

    // Disable/Destroy record the *removal* of a deployment; materializing one
    // as an Apply would enable a state whose plan undeploys everything.
    if !manifest.kind.deploys() {
        anyhow::bail!(
            "transaction {} is a {} transaction and does not record a deployment; \
             only apply transactions can be checked out (`malm -s {} state log` lists them)",
            manifest.id,
            manifest.kind.label(),
            manifest.state_namespace()
        );
    }

    let allow = manifest.allow;

    let source_snapshot = SourceSnapshot::from_id(manifest.source_snapshot_id.as_str())?;
    source_snapshot.require_on_disk()?;
    if opts.verify {
        source_snapshot.verify_content()?;
    }

    println!(
        "\n  {} checking out {}",
        "⟳".cyan().bold(),
        transaction_alias(&full_id)
    );

    let mut frozen =
        frozen_plan_from_manifest(&manifest, ctx.state_namespace.as_str(), &source_snapshot)?;

    let ownership = read_ownership_for(ctx.state_namespace.as_str())
        .context("read current ownership for checkout")?;
    // The frozen plan restores the recorded state. Stale removals use current
    // ownership to remove anything deployed since.
    plan_stale_removals(&mut frozen, &ownership);

    frozen.validate_target_relationships();

    let mut checkout_ctx = ctx.clone();
    if let Some(p) = manifest.profile.clone() {
        checkout_ctx.profile = Some(p);
    }

    let repository_root = source_snapshot.repository();
    let identity = manifest.source.clone().unwrap_or_else(|| SourceIdentity {
        kind: SourceKind::Local {
            path: repository_root.to_path_buf(),
        },
    });
    let trust_mode = match &identity.kind {
        SourceKind::Local { .. } => TrustMode::Trusted,
        SourceKind::Git { .. } => TrustMode::Untrusted,
    };

    let resolved = ResolvedSource {
        source_root: repository_root.to_path_buf(),
        identity,
        trust_mode,
    };
    let loaded = LoadedConfigSource {
        config: Config::empty(),
        resolved,
        config_path: manifest
            .config
            .clone()
            .unwrap_or_else(|| repository_root.join("malm.kdl")),
        target_root: home_dir(),
        provenance: Vec::new(),
        external_includes_skipped: Vec::new(),
        // The new transaction re-records the original grant.
        allow_local_includes: manifest.allow_local_includes,
    };

    let pipeline = DeploymentPipeline::prepare_from_manifest(
        &checkout_ctx,
        loaded,
        frozen,
        manifest.source_snapshot_id.as_str(),
        manifest.repo.clone(),
        TransactionKind::Apply,
    )?;
    let pipeline = pipeline.approve_for_execution(allow)?;
    pipeline.execute(opts.yes)?;

    // Checkout is a deployment, so its finalizer records the state as Enabled.
    TrackedRemote::reconcile_with_active_state(ctx.state_namespace.as_str())
        .context("reconcile tracking state after checkout")?;

    println!(
        "  {} checked out {}",
        "✓".green().bold(),
        transaction_alias(&full_id)
    );
    Ok(())
}
