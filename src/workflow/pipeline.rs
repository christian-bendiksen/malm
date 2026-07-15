//! Shared deployment pipeline from `Planned` to `ExecutionReady`: snapshot
//! staging, source rebasing, policy and risk gates, execution, and
//! crash-ordered finalization.

use crate::app::context::GlobalCtx;
use crate::cas::{object_present, objects_dir, sources_object_dir, store_tree, tree_hash};
use crate::config::{LoadedConfigSource, ProfileSelection, reload_staged_config};
use crate::domain::id::TransactionId;
use crate::domain::owner::OwnerKind;
use crate::execution::SourceResolver;
use crate::execution::executor::apply_plan;
use crate::failpoint;
use crate::output::{print_plan, print_policy_violations};
use crate::planning::plan::{DeploymentPlan, Operation};
use crate::planning::planner::build_deployment_plan_with_render_root;
use crate::policy::model::{PolicyFindingKind, PolicySeverity};
use crate::policy::risk::{RiskReport, assess_plan};
use crate::policy::{
    PolicyFinding, RemotePolicyOverrides, collect_asset_declaration_findings,
    collect_external_include_findings, collect_remote_policy_findings, dedup_findings,
};
use crate::source::TrustMode;
use crate::source::store::{SourceSnapshot, copy_source_repo};
use crate::state::active_deployment::{
    restore_source_pointer, set_source_pointer, source_pointer_path,
};
use crate::state::integrity::ensure_no_rollback_needed;
use crate::state::ownership::{OwnershipEntry, OwnershipIndex};
use crate::state::ownership_store::{check_identity_against, read_ownership_for};
use crate::state::record::{StateMode, StateRecord, live_deployment_id_strict};
use crate::state::target_lock::{TargetLock, TargetLockGuard};
use crate::state::transaction::{
    ApplyMetadataIntent, ApplyPhase, TransactionKind, TransactionMeta, TransactionStore,
    new_transaction_id, transaction_alias,
};
use crate::workflow::bookkeeping::commit_apply_metadata;
use crate::workflow::policy_gate::reject_if_blocked;
use crate::workflow::risk_prompt::confirm_high_risk_operations;
use anyhow::{Context, Result};
use owo_colors::OwoColorize;
use std::path::{Path, PathBuf};

// Deployed symlinks record the states/<ns>/current alias, not the object
// root: swapping that one symlink atomically activates a whole snapshot.
fn rebase_source_paths(plan: &mut DeploymentPlan, old_root: &Path, new_root: &Path) {
    plan.rebase_source_paths(old_root, new_root);
}

fn planned_ownership_signature(
    plan: &DeploymentPlan,
) -> std::collections::BTreeSet<(PathBuf, PathBuf, String)> {
    let mut signature: std::collections::BTreeSet<_> = plan
        .operations()
        .iter()
        .filter_map(|op| match op {
            Operation::CreateSymlink {
                source,
                target,
                owner,
                ..
            } => Some((target.clone(), source.clone(), owner.persisted()?.label())),
            Operation::KeepAsset {
                name,
                target,
                previous,
                ..
            } => {
                let source = previous
                    .as_ref()
                    .map(|prev| prev.source.clone())
                    .unwrap_or_else(|| target.clone());
                Some((
                    target.clone(),
                    source,
                    OwnerKind::Asset { name: name.clone() }.label(),
                ))
            }
            Operation::RestoreAsset {
                name,
                target,
                payload,
                ..
            } => Some((
                target.clone(),
                payload.clone(),
                OwnerKind::Asset { name: name.clone() }.label(),
            )),
            Operation::InstallAsset { .. }
            | Operation::RemovePath { .. }
            | Operation::RemoveAsset { .. } => None,
        })
        .collect();
    signature.extend(plan.retained_ownership().iter().map(|entry| {
        (
            entry.target.clone(),
            entry.source.clone(),
            entry.owner.label(),
        )
    }));
    signature
}

pub struct Planned {
    prepared: Option<PreparedSnapshot>,
}

struct PreparedSnapshot {
    tx_id: TransactionId,
    source: SourceSnapshot,
}

impl PreparedSnapshot {
    fn reused(tx_id: TransactionId, source: SourceSnapshot) -> Self {
        Self { tx_id, source }
    }
}

pub struct ExecutionReady {
    snapshot: PreparedSnapshot,
    pub report: RiskReport,
    pub managed_targets: Vec<PathBuf>,
    pub allow: RemotePolicyOverrides,
}

/// What a `Disable` transaction's finalizer needs beyond the plan: the
/// deployment `state enable` restores, and the ownership entries of targets
/// deliberately left in place (`--keep-modified`).
pub struct DisableFinalize {
    pub restore_transaction: String,
    pub kept_entries: Vec<OwnershipEntry>,
}

pub struct DeploymentPipeline<'a, State> {
    ctx: &'a GlobalCtx,
    loaded: LoadedConfigSource,
    effective_profile: Option<String>,
    pub plan: DeploymentPlan,
    plan_source_root: PathBuf,
    recorded_repo: Option<PathBuf>,
    recorded_source_root: PathBuf,
    kind: TransactionKind,
    disable_finalize: Option<DisableFinalize>,
    lock_guard: Option<TargetLockGuard>,
    render_workspace: Option<tempfile::TempDir>,
    state: State,
}

impl<'a> DeploymentPipeline<'a, Planned> {
    pub fn prepare_for_apply(ctx: &'a GlobalCtx, loaded: LoadedConfigSource) -> Result<Self> {
        let guard = TargetLock::acquire_guard()?;
        ensure_no_rollback_needed(ctx.state_namespace.as_str())?;
        Self::build(ctx, loaded, Some(guard), true, None)
    }

    pub fn prepare_for_reapply(
        ctx: &'a GlobalCtx,
        loaded: LoadedConfigSource,
        recorded_repo: PathBuf,
    ) -> Result<Self> {
        let guard = TargetLock::acquire_guard()?;
        ensure_no_rollback_needed(ctx.state_namespace.as_str())?;
        Self::build(ctx, loaded, Some(guard), true, Some(recorded_repo))
    }

    pub fn prepare_read_only(ctx: &'a GlobalCtx, loaded: LoadedConfigSource) -> Result<Self> {
        Self::build(ctx, loaded, None, false, None)
    }

    pub fn prepare_from_manifest(
        ctx: &'a GlobalCtx,
        loaded: LoadedConfigSource,
        frozen_plan: DeploymentPlan,
        source_snapshot_id: &str,
        recorded_repo: Option<PathBuf>,
        kind: TransactionKind,
    ) -> Result<Self> {
        let guard = TargetLock::acquire_guard()?;
        ensure_no_rollback_needed(ctx.state_namespace.as_str())?;
        let tx_id = new_transaction_id();
        let source = SourceSnapshot::from_id(source_snapshot_id)?;
        source.require_on_disk()?;
        // Frozen plans already carry the effective profile in their manifest;
        // lifecycle callers intentionally use Config::empty(), so resolving it
        // against the placeholder config would reject a valid recorded name.
        let effective_profile = ctx.profile.clone().filter(|profile| profile != "none");
        let recorded_source_root = loaded.resolved.source_root.clone();
        Ok(Self {
            ctx,
            loaded,
            effective_profile,
            plan: frozen_plan,
            plan_source_root: source.repository().to_path_buf(),
            recorded_repo,
            recorded_source_root,
            kind,
            disable_finalize: None,
            lock_guard: Some(guard),
            render_workspace: None,
            state: Planned {
                prepared: Some(PreparedSnapshot::reused(tx_id, source)),
            },
        })
    }

    /// Attach the disable-specific finalization inputs; required for
    /// `TransactionKind::Disable` pipelines.
    pub fn with_disable_finalize(mut self, finalize: DisableFinalize) -> Self {
        self.disable_finalize = Some(finalize);
        self
    }

    fn build(
        ctx: &'a GlobalCtx,
        loaded: LoadedConfigSource,
        lock_guard: Option<TargetLockGuard>,
        prepare: bool,
        recorded_repo: Option<PathBuf>,
    ) -> Result<Self> {
        let ownership = read_ownership_for(ctx.state_namespace.as_str())?;
        let recorded_source_root = loaded.resolved.source_root.clone();
        let recorded_repo =
            Some(recorded_repo.unwrap_or_else(|| loaded.resolved.source_root.clone()));

        if prepare {
            check_identity_against(
                &ownership,
                &loaded.resolved.identity,
                ctx.state_namespace.as_str(),
            )?;
        }

        let (loaded, profile, plan, plan_source_root, prepared, render_workspace) = if prepare {
            let tx_id = new_transaction_id();

            let objects_base = objects_dir();
            std::fs::create_dir_all(&objects_base)
                .with_context(|| format!("create {}", objects_base.display()))?;
            let staging = tempfile::Builder::new()
                .prefix(".malm-source-stage-")
                .tempdir_in(&objects_base)
                .context("create source staging directory")?;
            let staged_rendered = staging.path().join("rendered");
            std::fs::create_dir_all(&staged_rendered)
                .with_context(|| format!("create {}", staged_rendered.display()))?;

            let source_root = loaded.resolved.source_root.clone();
            let staged_repo = staging.path().join("repo");
            // Snapshot source bytes before planning, then rebase the plan to
            // this private copy. Live files cannot change between identity
            // calculation and CAS publication.
            copy_source_repo(&source_root, &staged_repo)?;
            let loaded = reload_staged_config(&loaded, staged_repo.clone())?;
            let profile = ProfileSelection::resolve(&loaded.config, ctx.profile.as_deref())?;
            let mut plan = build_deployment_plan_with_render_root(
                &loaded.config,
                &staged_repo,
                &loaded.target_root,
                &staged_rendered,
                &profile,
                &ownership,
                loaded.resolved.trust_mode,
            );
            if plan.has_errors() {
                anyhow::bail!(
                    "{} error(s) in plan:\n{}",
                    plan.errors().len(),
                    plan.errors().join("\n")
                );
            }

            let hash = tree_hash(staging.path()).context("hash staged source snapshot")?;
            let object = sources_object_dir(&hash)?;
            if !object_present(&object, true)? {
                store_tree(staging.path(), &object).context("store source snapshot")?;
            }
            let source = SourceSnapshot::from_id(&hash)?;

            let alias_root = source_pointer_path(ctx.state_namespace.as_str());
            rebase_source_paths(&mut plan, &staged_repo, &alias_root.join("repo"));
            rebase_source_paths(&mut plan, &staged_rendered, &alias_root.join("rendered"));

            let plan_source_root = source.repository().to_path_buf();
            (
                loaded,
                profile,
                plan,
                plan_source_root,
                Some(PreparedSnapshot::reused(tx_id, source)),
                None,
            )
        } else {
            let profile = ProfileSelection::resolve(&loaded.config, ctx.profile.as_deref())?;
            let render_workspace = tempfile::Builder::new()
                .prefix("malm-render-preview-")
                .tempdir()
                .context("create template preview workspace")?;
            let render_root = render_workspace.path().to_path_buf();
            let plan = build_deployment_plan_with_render_root(
                &loaded.config,
                &loaded.resolved.source_root,
                &loaded.target_root,
                &render_root,
                &profile,
                &ownership,
                loaded.resolved.trust_mode,
            );
            let plan_source_root = loaded.resolved.source_root.clone();
            (
                loaded,
                profile,
                plan,
                plan_source_root,
                None,
                Some(render_workspace),
            )
        };
        let effective_profile = profile.selected().map(str::to_owned);

        Ok(Self {
            ctx,
            loaded,
            effective_profile,
            plan,
            plan_source_root,
            recorded_repo,
            recorded_source_root,
            kind: TransactionKind::Apply,
            disable_finalize: None,
            lock_guard,
            render_workspace,
            state: Planned { prepared },
        })
    }

    pub fn remote_policy_findings(&self, allow: RemotePolicyOverrides) -> Vec<PolicyFinding> {
        match self.loaded.resolved.trust_mode {
            TrustMode::Trusted => Vec::new(),
            TrustMode::Untrusted => {
                let alias_root = source_pointer_path(self.ctx.state_namespace.as_str());
                let source_remap = self
                    .state
                    .prepared
                    .as_ref()
                    .map(|prepared| (alias_root.as_path(), prepared.source.root()));
                let rendered_root: Option<PathBuf> =
                    match (self.state.prepared.as_ref(), self.render_workspace.as_ref()) {
                        (Some(prepared), _) => Some(prepared.source.root().join("rendered")),
                        (None, Some(workspace)) => Some(workspace.path().to_path_buf()),
                        _ => None,
                    };
                let mut violations = collect_remote_policy_findings(
                    &self.plan,
                    &self.plan_source_root,
                    rendered_root.as_deref(),
                    source_remap,
                    allow,
                );
                violations.extend(collect_asset_declaration_findings(
                    &self.loaded.config,
                    allow,
                ));
                violations.extend(collect_external_include_findings(&self.loaded.provenance));
                for path in &self.loaded.external_includes_skipped {
                    violations.push(PolicyFinding { target: Some(path.clone()), owner: "local configuration include".to_owned(), category: PolicyFindingKind::LocalInclude, severity: PolicySeverity::Notice, reason: "remote config requests a local include; skipped in preview \u{2014} run `plan --allow-local-includes` to read it", allow_flag: "" });
                }
                dedup_findings(&mut violations);
                violations
            }
        }
    }

    pub fn approve_for_execution(
        self,
        allow_policy: RemotePolicyOverrides,
    ) -> Result<DeploymentPipeline<'a, ExecutionReady>> {
        let violations = self.remote_policy_findings(allow_policy);

        print_policy_violations(&violations);
        reject_if_blocked(&violations)?;

        let report = assess_plan(&self.plan);

        let managed_targets: Vec<PathBuf> = self
            .plan
            .operations()
            .iter()
            .filter_map(|op| op.managed_target_after_apply().map(|p| p.to_path_buf()))
            .chain(
                self.plan
                    .retained_ownership()
                    .iter()
                    .map(|entry| entry.target.clone()),
            )
            .collect();

        let lock = TargetLock::load()?;
        lock.check_no_conflicts(&managed_targets, self.ctx.state_namespace.as_str())?;

        let snapshot = self
            .state
            .prepared
            .expect("approve_for_execution requires a mutating (prepared) pipeline");

        Ok(DeploymentPipeline {
            ctx: self.ctx,
            loaded: self.loaded,
            effective_profile: self.effective_profile,
            plan: self.plan,
            plan_source_root: self.plan_source_root,
            recorded_repo: self.recorded_repo,
            recorded_source_root: self.recorded_source_root,
            kind: self.kind,
            disable_finalize: self.disable_finalize,
            lock_guard: self.lock_guard,
            render_workspace: self.render_workspace,
            state: ExecutionReady {
                snapshot,
                report,
                managed_targets,
                allow: allow_policy,
            },
        })
    }

    pub fn preview(&self, verbose: bool) {
        print_plan(&self.plan, verbose);
    }

    pub fn effective_profile(&self) -> Option<&str> {
        self.effective_profile.as_deref()
    }
}

impl<'a> DeploymentPipeline<'a, ExecutionReady> {
    pub fn execute(self, auto_confirm: bool) -> Result<()> {
        confirm_high_risk_operations(&self.state.report, auto_confirm)?;

        let namespace = self.ctx.state_namespace.clone();
        let metadata_needs_repair = self.metadata_needs_repair(namespace.as_str())?;
        let anchor_changed = self.deployment_anchor_changed(namespace.as_str())?;

        // Lifecycle transitions (disable/destroy) must always leave a
        // transaction behind, even with zero filesystem operations. The
        // finalizer is the only durable path for the mode change.
        let record_even_if_empty = anchor_changed || !self.kind.deploys() || metadata_needs_repair;
        let metadata_intent =
            if self.kind.deploys() && self.plan.operations().is_empty() && !metadata_needs_repair {
                ApplyMetadataIntent::Preserve
            } else {
                ApplyMetadataIntent::Rewrite
            };

        self.commit(record_even_if_empty, metadata_intent)
    }

    fn metadata_needs_repair(&self, namespace: &str) -> Result<bool> {
        use std::collections::BTreeSet;

        let planned_sig = planned_ownership_signature(&self.plan);
        let ownership = read_ownership_for(namespace)?;
        if ownership.source.as_ref() != Some(&self.loaded.resolved.identity)
            || ownership.config.as_deref() != Some(self.loaded.config_path.as_path())
            || ownership.profile.as_deref() != self.effective_profile.as_deref()
        {
            return Ok(true);
        }
        let current_sig: BTreeSet<(PathBuf, PathBuf, String)> = ownership
            .iter()
            .map(|entry| {
                (
                    entry.target.clone(),
                    entry.source.clone(),
                    entry.owner.label(),
                )
            })
            .collect();
        if planned_sig != current_sig {
            return Ok(true);
        }

        let planned_targets: BTreeSet<&Path> = self
            .state
            .managed_targets
            .iter()
            .map(PathBuf::as_path)
            .collect();
        let lock = TargetLock::load()?;
        Ok(lock.targets_for(namespace) != planned_targets)
    }

    fn deployment_anchor_changed(&self, namespace: &str) -> Result<bool> {
        let Some(active_id) = live_deployment_id_strict(namespace)? else {
            return Ok(true);
        };
        let manifest = TransactionStore::new().read(&active_id)?;
        Ok(
            manifest.source_snapshot_id.as_str() != self.state.snapshot.source.id()
                || manifest.source.as_ref() != Some(&self.loaded.resolved.identity)
                || manifest.config.as_deref() != Some(self.loaded.config_path.as_path())
                || manifest.profile.as_deref() != self.effective_profile.as_deref()
                || manifest.config_files != self.config_files()
                || manifest.allow_local_includes != self.loaded.allow_local_includes,
        )
    }

    fn config_files(&self) -> Vec<crate::config::ConfigFileProvenance> {
        let mut config_files = self.loaded.provenance.clone();
        for input in self.plan.config_inputs() {
            let mut provenance = input.provenance.clone();
            if let Ok(relative) = provenance
                .path
                .strip_prefix(&self.loaded.resolved.source_root)
            {
                provenance.path = self.recorded_source_root.join(relative);
            }
            if !config_files.contains(&provenance) {
                config_files.push(provenance);
            }
        }
        config_files
    }

    fn commit(
        self,
        record_even_if_empty: bool,
        metadata_intent: ApplyMetadataIntent,
    ) -> Result<()> {
        let config_files = self.config_files();

        let namespace = self.ctx.state_namespace.clone();
        let object_root = self.state.snapshot.source.root().to_path_buf();
        let resolver =
            SourceResolver::new(source_pointer_path(namespace.as_str()), object_root.clone());

        let meta = TransactionMeta {
            id: self.state.snapshot.tx_id.clone(),
            kind: self.kind,
            source_snapshot_id: crate::domain::id::ObjectId::parse(
                self.state.snapshot.source.id(),
            )?,
            repo: self.recorded_repo.clone(),
            config: Some(self.loaded.config_path.clone()),
            profile: self.effective_profile.clone(),
            state_namespace: Some(namespace.as_str().to_owned()),
            source: Some(self.loaded.resolved.identity.clone()),
            allow: self.state.allow,
            config_files,
            restore_transaction: self
                .disable_finalize
                .as_ref()
                .map(|finalize| finalize.restore_transaction.clone()),
            kept_targets: self
                .disable_finalize
                .as_ref()
                .map(|finalize| {
                    finalize
                        .kept_entries
                        .iter()
                        .map(|entry| entry.target.clone())
                        .collect()
                })
                .unwrap_or_default(),
            allow_local_includes: self.loaded.allow_local_includes,
            metadata_intent,
        };

        let tx_id = apply_plan(
            &self.plan,
            meta,
            record_even_if_empty,
            &resolver,
            self.ctx.allow_ssrf,
        )?;

        let Some(id) = tx_id.as_deref() else {
            return Ok(());
        };

        // The filesystem is fully applied. Everything from here on is
        // metadata and the state-mode transition, ordered so a crash at any
        // point leaves the previous mode authoritative and the transaction
        // recoverable: ownership + target lock, then the source-pointer
        // change (the activation event), then state.json, then Completed.
        let store = TransactionStore::new();
        let finalize = match self.kind {
            TransactionKind::Apply => finalize_apply(
                &store,
                id,
                namespace.as_str(),
                &object_root,
                &self.loaded,
                &self.plan,
                &self.state.managed_targets,
                self.effective_profile.as_deref(),
                self.ctx,
            ),
            TransactionKind::Disable => {
                let finalize = self
                    .disable_finalize
                    .as_ref()
                    .context("internal error: a Disable pipeline requires with_disable_finalize");
                finalize
                    .and_then(|f| finalize_disable(&store, id, namespace.as_str(), &self.loaded, f))
            }
            TransactionKind::Destroy => {
                finalize_destroy(&store, id, namespace.as_str(), &self.loaded)
            }
        };

        if let Err(err) = finalize {
            let _ = store.mark_metadata_failed(id);
            return Err(err).context(
                "finalize the transaction (filesystem changes were applied and kept; \
                 run `malm state recover` to repair state metadata)",
            );
        }

        println!(
            "\n  {} applied · {}",
            "✓".green().bold(),
            format!("transaction {}", transaction_alias(id)).dimmed()
        );

        Ok(())
    }
}

/// Apply finalization: the completed deployment becomes the live one. This
/// inherently (re-)enables the state. It replaces the Disabled record, so no
/// out-of-band marker handling exists.
#[allow(clippy::too_many_arguments)]
fn finalize_apply(
    store: &TransactionStore,
    id: &str,
    namespace: &str,
    object_root: &Path,
    loaded: &LoadedConfigSource,
    plan: &DeploymentPlan,
    managed_targets: &[PathBuf],
    effective_profile: Option<&str>,
    ctx: &GlobalCtx,
) -> Result<()> {
    commit_apply_metadata(
        Some(&loaded.resolved.identity),
        &loaded.config_path,
        plan,
        managed_targets,
        effective_profile,
        ctx,
        Some(id),
    )
    .context("commit post-apply metadata")?;
    store.advance_phase(id, ApplyPhase::MetadataCommitted)?;
    failpoint!("apply.after_metadata");

    set_source_pointer(namespace, object_root).context("activate the new source snapshot")?;
    store.advance_phase(id, ApplyPhase::ActivePointerSwapped)?;
    failpoint!("apply.after_pointer_swap");

    StateRecord::set(namespace, StateMode::enabled(id)).context("persist state record")?;
    failpoint!("apply.after_record");
    store
        .mark_completed(id)
        .context("mark transaction completed")?;
    Ok(())
}

/// Disable finalization: ownership keeps only the entries for targets
/// deliberately left in place, the source pointer is removed (nothing is
/// materialized any more), and the state record turns Disabled with its
/// restore target.
fn finalize_disable(
    store: &TransactionStore,
    id: &str,
    namespace: &str,
    loaded: &LoadedConfigSource,
    finalize: &DisableFinalize,
) -> Result<()> {
    write_retained_metadata(namespace, loaded, &finalize.kept_entries)
        .context("commit post-disable metadata")?;
    store.advance_phase(id, ApplyPhase::MetadataCommitted)?;
    failpoint!("disable.after_metadata");

    restore_source_pointer(namespace, None).context("remove the source pointer")?;
    store.advance_phase(id, ApplyPhase::ActivePointerSwapped)?;
    failpoint!("disable.before_record");

    let kept_targets = finalize
        .kept_entries
        .iter()
        .map(|entry| entry.target.clone())
        .collect();
    StateRecord::set(
        namespace,
        StateMode::disabled(finalize.restore_transaction.clone(), kept_targets),
    )
    .context("persist disabled state record")?;
    store
        .mark_completed(id)
        .context("mark transaction completed")?;
    Ok(())
}

/// Destroy finalization: no ownership, no pointer, a Destroyed record for
/// the window before the state directory itself is removed.
fn finalize_destroy(
    store: &TransactionStore,
    id: &str,
    namespace: &str,
    loaded: &LoadedConfigSource,
) -> Result<()> {
    write_retained_metadata(namespace, loaded, &[]).context("commit post-destroy metadata")?;
    store.advance_phase(id, ApplyPhase::MetadataCommitted)?;
    failpoint!("destroy.after_metadata");

    restore_source_pointer(namespace, None).context("remove the source pointer")?;
    store.advance_phase(id, ApplyPhase::ActivePointerSwapped)?;

    StateRecord::set(namespace, StateMode::destroyed(Some(id.to_owned())))
        .context("persist destroyed state record")?;
    store
        .mark_completed(id)
        .context("mark transaction completed")?;
    Ok(())
}

/// Write ownership and target lock down to exactly `kept`. This is the disable/destroy
/// analog of `commit_apply_metadata`. Never silently orphans: what stays on
/// disk stays owned.
fn write_retained_metadata(
    namespace: &str,
    loaded: &LoadedConfigSource,
    kept: &[OwnershipEntry],
) -> Result<()> {
    let kept_targets: Vec<PathBuf> = kept.iter().map(|entry| entry.target.clone()).collect();
    let mut lock = TargetLock::load().context("load target lock")?;
    lock.update_state(&kept_targets, namespace);
    lock.save().context("persist target lock")?;

    let mut index = OwnershipIndex::new(
        namespace.to_owned(),
        Some(loaded.resolved.identity.clone()),
        Some(loaded.config_path.clone()),
        None,
    );
    index.entries = kept.to_vec();
    index.save_for_state(namespace)
}
