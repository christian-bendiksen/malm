//! Adapts durable deployment operations to human-readable and JSON output.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io::{Read, Write as _};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result, ensure};
use malm_pack::{
    GitObjectId, GitSourceV1, GitUrl, LocalLocator, MAX_LOCK_BYTES, PackSubdir, decode_lock_v1,
    lock_graph_digest,
};
use malm_types::{
    ArtifactId, ArtifactMetadataInspectionRequestV1, ArtifactMetadataInspectionV1,
    CanonicalTreeEntryKindInspectionV1, CanonicalTreeInspectionRequestV1,
    CanonicalTreeInspectionV1, CapturedInputsInspectionV1, CatalogInspectionRequestV1,
    CatalogInspectionV1, CheckoutRequestV1, ContributionName, DeploymentName,
    DesiredSnapshotInspectionRequestV1, DesiredSnapshotInspectionV1,
    DesiredTargetStateInspectionV1, Digest, FsckFindingCodeV1, FsckReportV1, FsckRequestV1,
    FsckSeverityV1, FsckStoreAreaV1, FsckSubjectV1, GenerationInspectionRequestV1,
    GenerationInspectionV1, GenerationInventoryRequestV1, GenerationInventoryV1,
    HistoryRetentionRequestV1, LifecycleRequestV1, LifecycleStateViewV1, LifecycleTransitionViewV1,
    NamespaceHistoryRequestV1, NamespaceHistoryV1, NamespaceInspectionRequestV1,
    NamespaceInspectionV1, NamespaceName, NamespaceRemovalHistoryV1, NamespaceRemovalRequestV1,
    NamespaceStatusKindV1, NamespaceStatusRequestV1, NamespaceStatusV1, ObjectInventoryKindV1,
    ObjectInventoryRequestV1, ObjectInventoryV1, PrepareTargetStateV1, PreparedId,
    PreparedPlanInspectionRequestV1, PreparedTrackingAcquisitionKindV1, PreparedTrackingReviewV1,
    RecoveryOutcomeV1, RestorePointInspectionV1, RestorePointRequestV1,
    RetentionAuthorityInspectionV1, RetentionInspectionV1, RetentionObjectV1,
    RetentionPinRequestV1, TargetStatusKindV1, TrackedRootInspectionV1, TrackingInspectionV1,
    TransformProvenanceInspectionV1,
};
use rustix::fs::{
    AtFlags, FileType, Mode, OFlags, RenameFlags, ResolveFlags, fchmod, fstat, fsync, mkdirat,
    open, openat2, renameat_with, statat, symlinkat, unlinkat,
};
use rustix::process::geteuid;

use crate::cli::ids::{
    IdDomain, display_digest, display_digest_unique, display_plan, display_plan_unique,
    resolve_digest, resolve_plan,
};
use crate::cli::output::{Output, Tone, json_path, out_line};
use crate::cli::{Cmd, LockCmd, RetentionObjectKind};
use crate::{
    ApprovalV1, CommitRequestV1, Engine, EngineOperation, EnginePorts,
    FormatComponentAuthorizationV1, GitAcquisitionConfig, GraphAcquisitionInputs,
    LockFilePublication, LockOperationOutcome, LockResolutionInputs, MovingSelectorV1,
    PrepareInputKindV1, PrepareOperationV1, PrepareTransformDiagnosticLocationV1,
    PrepareTransformDiagnosticSeverityV1, PrepareTransformDiagnosticV1,
    PrepareTransformImplementationV1, PreparedDeploymentV1, ProfileSwitchRequestV1, PruneRequestV1,
    StaticDeploymentPrepareRequestV1, StaticGraphAcquisitionV1, StoreAccess,
    TrackedRootAcquisitionGrantsV1, TrackedRootInfrastructureV1, TrackedRootNoChangeV1,
    TrackedRootPrepareRequestPartsV1, TrackedRootPrepareRequestV1, TrackedRootUpdateOutcomeV1,
    TrackedRootUpdateRequestV1,
};

pub fn run(command: &Cmd, output: &Output, selected_profile: Option<&str>) -> Result<i32> {
    let contract = crate::cli::contracts::cli_contract(command);
    let access = contract
        .effect()
        .store_access()
        .expect("deployment commands have a fixed store-access effect");
    let mut exit_code = 0;
    match command {
        Cmd::ComponentHostProfile => {
            let profile = malm_format_component_adapter::current_host_execution_profile_digest_v1();
            output.emit(
                "inspected",
                || {
                    serde_json::json!({
                        "interface": malm_format_component_adapter::FORMAT_COMPONENT_INTERFACE_V1,
                        "execution_profile": profile.as_str(),
                    })
                },
                |rendered| {
                    out_line(
                        rendered,
                        format_args!("{}", output.heading("Format component host", Tone::Neutral)),
                    );
                    out_line(
                        rendered,
                        format_args!(
                            "  Interface  {}",
                            malm_format_component_adapter::FORMAT_COMPONENT_INTERFACE_V1
                        ),
                    );
                    out_line(rendered, format_args!("  Profile    {profile}"));
                },
            )?;
            Ok(())
        }
        Cmd::Prepare {
            source,
            lock,
            cached,
            namespace,
            target_authority,
            targets,
            local_locators,
            git_urls,
            git_scratch,
            git_executable,
        } => {
            contract.assert_engine_operation(EngineOperation::PrepareStaticDeploymentV1);
            let source = resolve_source_root(Some(source))?;
            let (engine, request) = static_prepare_request(
                access,
                &StaticPrepareOptions {
                    source: &source,
                    lock,
                    cached: *cached,
                    namespace,
                    target_authority,
                    targets,
                    local_locators,
                    git_urls,
                    git_scratch,
                    git_executable,
                },
                selected_profile,
                output,
            )?;
            let plan = engine.prepare_static_deployment_v1(&request)?;
            print_plan(&plan, output)
        }
        Cmd::Apply {
            source,
            lock,
            cached,
            namespace,
            target_authority,
            targets,
            local_locators,
            git_urls,
            git_scratch,
            git_executable,
            yes,
        } => {
            contract.assert_engine_operation(EngineOperation::PrepareStaticDeploymentV1);
            contract.assert_engine_operation(EngineOperation::CommitV1);
            let source = resolve_source_root(source.as_deref())?;
            ensure_lock_exists(&source, lock.as_deref())?;
            let (engine, request) = static_prepare_request(
                access,
                &StaticPrepareOptions {
                    source: &source,
                    lock,
                    cached: *cached,
                    namespace,
                    target_authority,
                    targets,
                    local_locators,
                    git_urls,
                    git_scratch,
                    git_executable,
                },
                selected_profile,
                output,
            )?;
            let plan = engine.prepare_static_deployment_v1(&request)?;
            let consent = crate::cli::interactive::review(&plan, &[], output, *yes, false)?;
            if consent == crate::cli::interactive::Consent::Commit {
                let outcome =
                    engine.commit_v1(&crate::cli::interactive::consented_commit_request(&plan))?;
                print_commit_outcome(&outcome, Some(&plan), &[], output)?;
            } else {
                exit_code = consent.declined_exit_code();
            }
            Ok(())
        }
        Cmd::Check { source } => {
            let source = resolve_source_root(source.as_deref())?;
            let sources = capture_authoring_sources(&source)?;
            let report = malm_authoring::check_authoring_workspace_v1(
                &sources,
                malm_authoring::AUTHORING_CONFIG_FILE,
            )
            .map_err(|error| anyhow::anyhow!("{error}"))?;
            output.emit(
                if report.error_count() == 0 {
                    "valid"
                } else {
                    "invalid"
                },
                || {
                    serde_json::json!({
                        "profiles": report.profiles(),
                        "default_profile": report.default_profile(),
                        "error_count": report.error_count(),
                        "rendered_diagnostics": report.report(),
                    })
                },
                |rendered| {
                    if !report.report().is_empty() {
                        rendered.push_str(report.report());
                        if !rendered.ends_with('\n') {
                            rendered.push('\n');
                        }
                    }
                    let title = if report.error_count() == 0 {
                        output.heading("Source is valid", Tone::Success)
                    } else {
                        output.heading("Source has errors", Tone::Attention)
                    };
                    out_line(rendered, format_args!("{title}"));
                    out_line(
                        rendered,
                        format_args!("  Profiles  {}", report.profiles().len()),
                    );
                    if !report.profiles().is_empty() {
                        out_line(
                            rendered,
                            format_args!("  Available {}", report.profiles().join(", ")),
                        );
                    }
                    if let Some(default) = report.default_profile() {
                        out_line(rendered, format_args!("  Default   {default}"));
                    }
                    out_line(
                        rendered,
                        format_args!("  Errors    {}", report.error_count()),
                    );
                },
            )?;
            if report.error_count() > 0 {
                exit_code = 1;
            }
            Ok(())
        }
        Cmd::Render {
            source,
            output: destination,
            overlays,
        } => {
            let source = resolve_source_root(source.as_deref())?;
            let sources = capture_authoring_sources(&source)?;
            let profile = resolve_authoring_profile(&sources, selected_profile)?;
            let supplied = if *overlays {
                read_host_overlays(&sources)?
            } else {
                Vec::new()
            };
            let evaluated = malm_authoring::evaluate_authoring_profile_v1(
                &sources,
                malm_authoring::AUTHORING_CONFIG_FILE,
                &profile,
                &supplied,
            )
            .map_err(|error| anyhow::anyhow!("{error}"))?;
            render_to_directory(&evaluated, destination, output)
        }
        Cmd::Vars {
            source,
            name,
            overlays,
        } => {
            let source = resolve_source_root(source.as_deref())?;
            let sources = capture_authoring_sources(&source)?;
            let profile = resolve_authoring_profile(&sources, selected_profile)?;
            let supplied = if *overlays {
                read_host_overlays(&sources)?
            } else {
                Vec::new()
            };
            let vars = malm_authoring::resolve_authoring_vars_v1(
                &sources,
                malm_authoring::AUTHORING_CONFIG_FILE,
                &profile,
                &supplied,
            )
            .map_err(|error| anyhow::anyhow!("{error}"))?;
            print_vars(&vars, name.as_deref(), output)
        }
        Cmd::Track {
            source_url,
            selector,
            source_subdir,
            config_entry,
            namespace,
            target_authority,
            targets,
            local_locators,
            git_urls,
            git_scratch,
            git_executable,
            root_scratch,
        } => {
            contract.assert_engine_operation(EngineOperation::PrepareTrackedRootV1);
            let source_url = GitUrl::new(source_url.clone())?;
            let selector = MovingSelectorV1::new(selector.clone())?;
            let source_subdir = PackSubdir::new(source_subdir.clone())?;
            let config_entry = crate::ConfigEntryPointV1::new(config_entry.clone())?;
            let profile = selected_profile
                .map(|profile| ContributionName::new(profile.to_owned()))
                .transpose()?;
            let namespace = NamespaceName::new(namespace.clone())?;
            let target_authority = DeploymentName::new(target_authority.clone())?;
            let local_grants =
                parse_unique_authorities(local_locators, "--allow-local", |value| {
                    Ok(LocalLocator::new(value)?)
                })?;
            let git_grants =
                parse_unique_authorities(git_urls, "--allow-git", |value| Ok(GitUrl::new(value)?))?;
            let infrastructure = tracked_infrastructure(git_executable, root_scratch, git_scratch)?;
            let request =
                TrackedRootPrepareRequestV1::try_from(TrackedRootPrepareRequestPartsV1 {
                    source_url,
                    moving_selector: selector,
                    source_subdir,
                    config_entry_point: config_entry,
                    profile,
                    namespace,
                    target_authority,
                    component_authorization: FormatComponentAuthorizationV1::default(),
                    acquisition_grants: TrackedRootAcquisitionGrantsV1::new(
                        local_grants,
                        git_grants,
                    )?,
                    infrastructure,
                })?;
            let engine = engine_with_output(access, targets, true, true, output)?;
            let plan = engine.prepare_tracked_root_v1(&request)?;
            print_plan(&plan, output)
        }
        Cmd::Update {
            namespace,
            targets,
            git_scratch,
            git_executable,
            root_scratch,
        } => {
            contract.assert_engine_operation(EngineOperation::UpdateTrackedRootV1);
            let request = TrackedRootUpdateRequestV1::new(
                NamespaceName::new(namespace.clone())?,
                tracked_infrastructure(git_executable, root_scratch, git_scratch)?,
            );
            let engine = engine_with_output(access, targets, true, true, output)?;
            match engine.update_v1(&request)? {
                TrackedRootUpdateOutcomeV1::Prepared(plan) => print_plan(&plan, output),
                TrackedRootUpdateOutcomeV1::NoChange(no_change) => {
                    print_tracked_no_change(&no_change, output)
                }
            }
        }
        Cmd::Switch { namespace, targets } => {
            contract.assert_engine_operation(EngineOperation::PrepareProfileSwitchV1);
            let profile = ContributionName::new(
                selected_profile
                    .expect("plan switch-profile always supplies a profile")
                    .to_owned(),
            )?;
            let request =
                ProfileSwitchRequestV1::new(NamespaceName::new(namespace.clone())?, profile);
            let engine = engine_with_output(access, targets, true, true, output)?;
            let plan = engine.prepare_profile_switch_v1(&request)?;
            print_plan(&plan, output)
        }
        Cmd::Plan { plan_id } => {
            contract.assert_engine_operation(EngineOperation::InspectPlanV1);
            contract.assert_engine_operation(EngineOperation::InspectPlanIndexV1);
            let engine = engine(access, &[], false, false)?;
            let plans = engine.list_plans_v1()?;
            let plan_id = resolve_plan_reference(&plans, plan_id.as_deref())?;
            let plan = engine.plan_v1(&plan_id)?;
            let candidates = plan_candidates(&plans);
            print_plan_with_candidates(&plan, &candidates, output)
        }
        Cmd::PlanList => {
            contract.assert_engine_operation(EngineOperation::InspectPlanIndexV1);
            contract.assert_engine_operation(EngineOperation::InspectPlanV1);
            let engine = engine(access, &[], false, false)?;
            let plans = engine.list_plans_v1()?;
            let mut listed = Vec::with_capacity(plans.len());
            for entry in &plans {
                listed.push((entry, engine.plan_v1(entry.plan_id())?));
            }
            output.emit(
                "listed",
                || {
                    serde_json::json!({
                        "plans": listed.iter().map(|(entry, plan)| serde_json::json!({
                            "plan_id": entry.plan_id().as_str(),
                            "namespace": plan.namespace().as_str(),
                            "transition": lifecycle_transition_json(plan.transition()),
                            "change_count": plan.operations().iter().filter(|operation| operation_change_line(plan, operation).is_some()).count(),
                            "approval_required": plan.findings().iter().filter(|finding| finding.approval_required()).count(),
                            "modified_seconds": entry.modified_seconds(),
                            "modified_nanoseconds": entry.modified_nanoseconds(),
                        })).collect::<Vec<_>>(),
                    })
                },
                |rendered| {
                let candidates = plan_candidates(&plans);
                if plans.is_empty() {
                    out_line(rendered, format_args!("No durable plans"));
                } else {
                    out_line(rendered, format_args!("{}",
                        output.heading(&format!("Plans  {}", plans.len()), Tone::Neutral)));
                    for (entry, plan) in &listed {
                        let change_count = plan
                            .operations()
                            .iter()
                            .filter(|operation| operation_change_line(plan, operation).is_some())
                            .count();
                        let approval_count = plan
                            .findings()
                            .iter()
                            .filter(|finding| finding.approval_required())
                            .count();
                        let review = if approval_count == 0 {
                            "clear".to_owned()
                        } else {
                            format!("{approval_count} approvals")
                        };
                        out_line(rendered, format_args!("  {}  {:<16}  {:<24}  {} changes  {}",
                            display_plan_unique(entry.plan_id(), &candidates, output.verbose()),
                            plan.namespace(),
                            lifecycle_transition_label(plan.transition()),
                            change_count,
                            review));
                    }
                }
                },
            )?;
            Ok(())
        }
        Cmd::ArtifactList { plan_id } => {
            contract.assert_engine_operation(EngineOperation::InspectPlanV1);
            contract.assert_engine_operation(EngineOperation::InspectPlanIndexV1);
            let engine = engine(access, &[], false, false)?;
            let plans = engine.list_plans_v1()?;
            let plan_id = resolve_plan_reference(&plans, Some(plan_id))?;
            let plan = engine.plan_v1(&plan_id)?;
            let candidates = plan_candidates(&plans);
            let data = serde_json::json!({
                "plan_id": plan.plan_id().as_str(),
                "artifacts": plan.artifacts().iter().map(|artifact| serde_json::json!({
                    "id": artifact.id().as_str(),
                    "digest": artifact.digest().as_str(),
                    "byte_len": artifact.byte_len(),
                    "media_type": artifact.media_type(),
                })).collect::<Vec<_>>(),
            });
            output.emit(
                "listed",
                || data,
                |rendered| {
                    out_line(
                        rendered,
                        format_args!(
                            "{}",
                            output.heading(
                                &format!("Artifacts  {}", plan.artifacts().len()),
                                Tone::Neutral
                            )
                        ),
                    );
                    out_line(
                        rendered,
                        format_args!(
                            "  Plan  {}",
                            display_plan_unique(plan.plan_id(), &candidates, output.verbose())
                        ),
                    );
                    for artifact in plan.artifacts() {
                        out_line(
                            rendered,
                            format_args!(
                                "  {}  {}  {}",
                                artifact.id(),
                                human_bytes(artifact.byte_len()),
                                artifact.media_type()
                            ),
                        );
                        if output.verbose() {
                            out_line(rendered, format_args!("    {}", artifact.digest()));
                        }
                    }
                },
            )?;
            Ok(())
        }
        Cmd::Artifact {
            plan_id,
            id,
            output: destination,
        } => {
            contract.assert_engine_operation(EngineOperation::LoadArtifactV1);
            contract.assert_engine_operation(EngineOperation::InspectPlanIndexV1);
            let engine = engine(access, &[], false, false)?;
            let plans = engine.list_plans_v1()?;
            let plan_id = resolve_plan_reference(&plans, Some(plan_id))?;
            let artifact = engine.artifact_v1(&plan_id, &ArtifactId::new(id.clone())?)?;
            std::fs::write(destination, artifact.bytes())
                .with_context(|| format!("write artifact export {}", destination.display()))?;
            output.emit(
                "exported",
                || {
                    serde_json::json!({
                        "artifact_id": artifact.descriptor().id().as_str(),
                        "digest": artifact.descriptor().digest().as_str(),
                        "byte_len": artifact.descriptor().byte_len(),
                        "media_type": artifact.descriptor().media_type(),
                        "output": json_path(destination),
                    })
                },
                |rendered| {
                    out_line(
                        rendered,
                        format_args!("{}", output.heading("Artifact exported", Tone::Success)),
                    );
                    out_line(
                        rendered,
                        format_args!("  Artifact  {}", artifact.descriptor().id()),
                    );
                    out_line(
                        rendered,
                        format_args!(
                            "  Size      {}",
                            human_bytes(artifact.descriptor().byte_len())
                        ),
                    );
                    out_line(
                        rendered,
                        format_args!("  Output    {}", destination.display()),
                    );
                    if output.verbose() {
                        out_line(
                            rendered,
                            format_args!("  Digest    {}", artifact.descriptor().digest()),
                        );
                    }
                },
            )?;
            Ok(())
        }
        Cmd::Commit {
            plan_id,
            approval,
            targets,
            yes,
        } => {
            contract.assert_engine_operation(EngineOperation::CommitV1);
            contract.assert_engine_operation(EngineOperation::InspectPlanV1);
            contract.assert_engine_operation(EngineOperation::InspectPlanIndexV1);
            let engine = engine_with_output(access, targets, true, false, output)?;
            let plans = engine.list_plans_v1()?;
            let plan_id = resolve_plan_reference(&plans, plan_id.as_deref())?;
            let Some(approval) = approval else {
                // Without an approval digest, review the durable plan just as
                // `apply` does before asking for consent.
                let plan = engine.plan_v1(&plan_id)?;
                let candidates = plan_candidates(&plans);
                let consent =
                    crate::cli::interactive::review(&plan, &candidates, output, *yes, false)?;
                if consent == crate::cli::interactive::Consent::Commit {
                    let outcome = engine
                        .commit_v1(&crate::cli::interactive::consented_commit_request(&plan))?;
                    let candidates = plan_candidates(&plans);
                    print_commit_outcome(&outcome, Some(&plan), &candidates, output)?;
                    return Ok(0);
                }
                return Ok(consent.declined_exit_code());
            };
            let outcome = engine.commit_v1(&CommitRequestV1::new(
                plan_id.clone(),
                ApprovalV1::new(plan_id, Digest::new(approval.clone())?),
            ))?;
            let candidates = plan_candidates(&plans);
            print_commit_outcome(&outcome, None, &candidates, output)?;
            Ok(())
        }
        Cmd::Checkout {
            generation,
            namespace,
            targets,
        } => {
            contract.assert_engine_operation(EngineOperation::PrepareCheckoutV1);
            contract.assert_engine_operation(EngineOperation::InspectGenerationInventoryV1);
            let engine = engine(access, targets, true, false)?;
            let (namespace, generation, inventory) =
                resolve_generation(namespace, generation, |request| {
                    engine.inspect_generation_inventory_v1(request)
                })?;
            let plan =
                engine.prepare_checkout_v1(&CheckoutRequestV1::new(namespace, generation))?;
            print_plan_with_generation_candidates(&plan, inventory.generations(), output)
        }
        Cmd::Recover { targets } => {
            contract.assert_engine_operation(EngineOperation::RecoverV1);
            let engine = engine_with_output(access, targets, true, false, output)?;
            print_recovery(&engine.recover_v1()?, output)
        }
        Cmd::Prune { plan_ids, dry_run } => {
            contract.assert_engine_operation(EngineOperation::PruneV1);
            contract.assert_engine_operation(EngineOperation::InspectPlanIndexV1);
            let engine = engine_with_output(access, &[], false, false, output)?;
            let plans = engine.list_plans_v1()?;
            let plan_ids = plan_ids
                .iter()
                .map(|reference| resolve_plan_reference(&plans, Some(reference)))
                .collect::<Result<Vec<_>>>()?;
            // Bare `malm prune` sweeps plans not referenced by a retained
            // generation, restore point, or pin. Explicit plan IDs retain the
            // exact-request semantics.
            let request = if plan_ids.is_empty() {
                PruneRequestV1::new(Vec::new()).sweep_unreferenced()
            } else {
                PruneRequestV1::new(plan_ids)
            };
            let outcome = if *dry_run {
                engine.preview_prune_v1(&request)?
            } else {
                engine.prune_v1(&request)?
            };
            let removed = serde_json::json!({
                "prepared_records": outcome.prepared_records,
                "artifact_blobs": outcome.artifact_blobs,
                "state_generations": outcome.state_generations,
                "pack_objects": outcome.pack_objects,
                "canonical_files": outcome.canonical_files,
                "canonical_symlinks": outcome.canonical_symlinks,
                "canonical_trees": outcome.canonical_trees,
            });
            output.emit(
                if *dry_run { "previewed" } else { "collected" },
                || {
                    serde_json::json!({
                        "dry_run": dry_run,
                        "removed": removed,
                    })
                },
                |rendered| {
                    let title = if *dry_run {
                        "Garbage collection preview"
                    } else if output.command() == "store.gc" {
                        "Garbage collection complete"
                    } else {
                        "Plans deleted"
                    };
                    out_line(
                        rendered,
                        format_args!("{}", output.heading(title, Tone::Success)),
                    );
                    out_line(
                        rendered,
                        format_args!("  Plans       {}", outcome.prepared_records),
                    );
                    out_line(
                        rendered,
                        format_args!("  Artifacts   {}", outcome.artifact_blobs),
                    );
                    out_line(
                        rendered,
                        format_args!("  Generations {}", outcome.state_generations),
                    );
                    let object_count = outcome.pack_objects
                        + outcome.canonical_files
                        + outcome.canonical_symlinks
                        + outcome.canonical_trees;
                    out_line(rendered, format_args!("  Objects     {object_count}"));
                    if output.verbose() {
                        out_line(
                            rendered,
                            format_args!("  Pack objects       {}", outcome.pack_objects),
                        );
                        out_line(
                            rendered,
                            format_args!("  Canonical files    {}", outcome.canonical_files),
                        );
                        out_line(
                            rendered,
                            format_args!("  Canonical symlinks {}", outcome.canonical_symlinks),
                        );
                        out_line(
                            rendered,
                            format_args!("  Canonical trees    {}", outcome.canonical_trees),
                        );
                    }
                },
            )?;
            Ok(())
        }
        Cmd::Disable { namespace, target } => {
            contract.assert_engine_operation(EngineOperation::PrepareDisableV1);
            let engine = engine(access, &target.targets, true, false)?;
            let plan = engine.prepare_disable_v1(&LifecycleRequestV1::new(NamespaceName::new(
                namespace.clone(),
            )?))?;
            print_plan(&plan, output)
        }
        Cmd::Enable { namespace, target } => {
            contract.assert_engine_operation(EngineOperation::PrepareEnableV1);
            let engine = engine(access, &target.targets, true, false)?;
            let plan = engine.prepare_enable_v1(&LifecycleRequestV1::new(NamespaceName::new(
                namespace.clone(),
            )?))?;
            print_plan(&plan, output)
        }
        Cmd::RemoveNamespace { namespace, target } => {
            contract.assert_engine_operation(EngineOperation::PrepareNamespaceRemovalV1);
            let engine = engine(access, &target.targets, true, false)?;
            let plan = engine.prepare_namespace_removal_v1(&NamespaceRemovalRequestV1::new(
                NamespaceName::new(namespace.clone())?,
                NamespaceRemovalHistoryV1::Drop,
            ))?;
            print_plan(&plan, output)
        }
        Cmd::SetHistoryRetention {
            generations,
            namespace,
            target,
        } => {
            contract.assert_engine_operation(EngineOperation::PrepareRetentionAuthorityV1);
            let engine = engine(access, &target.targets, true, false)?;
            let plan = engine.prepare_history_retention_v1(&HistoryRetentionRequestV1::new(
                NamespaceName::new(namespace.clone())?,
                *generations,
            )?)?;
            print_plan(&plan, output)
        }
        Cmd::Pin {
            kind,
            object,
            namespace,
            target,
        } => {
            contract.assert_engine_operation(EngineOperation::PrepareRetentionAuthorityV1);
            let engine = engine(access, &target.targets, true, false)?;
            contract.assert_engine_operation(EngineOperation::InspectPlanIndexV1);
            contract.assert_engine_operation(EngineOperation::InspectGenerationInventoryV1);
            contract.assert_engine_operation(EngineOperation::InspectObjectInventoryV1);
            let namespace = NamespaceName::new(namespace.clone())?;
            let object = resolve_retention_object(
                *kind,
                object,
                || engine.list_plans_v1(),
                || {
                    engine.inspect_generation_inventory_v1(&GenerationInventoryRequestV1::new(
                        namespace.clone(),
                    ))
                },
                |kind| engine.inspect_object_inventory_v1(&ObjectInventoryRequestV1::new(kind)),
            )?;
            let request = RetentionPinRequestV1::new(namespace, object);
            print_plan(&engine.prepare_pin_v1(&request)?, output)
        }
        Cmd::Unpin {
            kind,
            object,
            namespace,
            target,
        } => {
            contract.assert_engine_operation(EngineOperation::PrepareRetentionAuthorityV1);
            let engine = engine(access, &target.targets, true, false)?;
            contract.assert_engine_operation(EngineOperation::InspectPlanIndexV1);
            contract.assert_engine_operation(EngineOperation::InspectGenerationInventoryV1);
            contract.assert_engine_operation(EngineOperation::InspectObjectInventoryV1);
            let namespace = NamespaceName::new(namespace.clone())?;
            let object = resolve_retention_object(
                *kind,
                object,
                || engine.list_plans_v1(),
                || {
                    engine.inspect_generation_inventory_v1(&GenerationInventoryRequestV1::new(
                        namespace.clone(),
                    ))
                },
                |kind| engine.inspect_object_inventory_v1(&ObjectInventoryRequestV1::new(kind)),
            )?;
            let request = RetentionPinRequestV1::new(namespace, object);
            print_plan(&engine.prepare_unpin_v1(&request)?, output)
        }
        Cmd::AddRestorePoint {
            generation,
            namespace,
            target,
        } => {
            contract.assert_engine_operation(EngineOperation::PrepareRetentionAuthorityV1);
            let engine = engine(access, &target.targets, true, false)?;
            contract.assert_engine_operation(EngineOperation::InspectGenerationInventoryV1);
            let (namespace, generation, inventory) =
                resolve_generation(namespace, generation, |request| {
                    engine.inspect_generation_inventory_v1(request)
                })?;
            let request = RestorePointRequestV1::new(namespace, generation);
            print_plan_with_generation_candidates(
                &engine.prepare_restore_point_v1(&request)?,
                inventory.generations(),
                output,
            )
        }
        Cmd::DropRestorePoint {
            generation,
            namespace,
            target,
        } => {
            contract.assert_engine_operation(EngineOperation::PrepareRetentionAuthorityV1);
            let engine = engine(access, &target.targets, true, false)?;
            contract.assert_engine_operation(EngineOperation::InspectGenerationInventoryV1);
            let (namespace, generation, inventory) =
                resolve_generation(namespace, generation, |request| {
                    engine.inspect_generation_inventory_v1(request)
                })?;
            let request = RestorePointRequestV1::new(namespace, generation);
            print_plan_with_generation_candidates(
                &engine.prepare_drop_restore_point_v1(&request)?,
                inventory.generations(),
                output,
            )
        }
        Cmd::Catalog => {
            contract.assert_engine_operation(EngineOperation::InspectCatalogV1);
            let engine = engine(access, &[], false, false)?;
            print_catalog(
                &engine.inspect_catalog_v1(&CatalogInspectionRequestV1::new())?,
                output,
            )
        }
        Cmd::Namespace { namespace } => {
            contract.assert_engine_operation(EngineOperation::InspectNamespaceV1);
            let engine = engine(access, &[], false, false)?;
            print_namespace(
                &engine.inspect_namespace_v1(&NamespaceInspectionRequestV1::new(
                    NamespaceName::new(namespace.clone())?,
                ))?,
                output,
            )
        }
        Cmd::History { namespace } => {
            contract.assert_engine_operation(EngineOperation::InspectNamespaceHistoryV1);
            let engine = engine(access, &[], false, false)?;
            print_history(
                &engine.inspect_namespace_history_v1(&NamespaceHistoryRequestV1::new(
                    NamespaceName::new(namespace.clone())?,
                ))?,
                output,
            )
        }
        Cmd::Generation {
            generation,
            namespace,
        } => {
            contract.assert_engine_operation(EngineOperation::InspectGenerationV1);
            contract.assert_engine_operation(EngineOperation::InspectGenerationInventoryV1);
            let engine = engine(access, &[], false, false)?;
            let (namespace, generation, inventory) =
                resolve_generation(namespace, generation, |request| {
                    engine.inspect_generation_inventory_v1(request)
                })?;
            let request = GenerationInspectionRequestV1::new(namespace, generation);
            print_generation(
                &engine.inspect_generation_details_v1(&request)?,
                inventory.generations(),
                output,
            )
        }
        Cmd::DesiredSnapshot {
            generation,
            namespace,
        } => {
            contract.assert_engine_operation(EngineOperation::InspectDesiredSnapshotV1);
            contract.assert_engine_operation(EngineOperation::InspectGenerationInventoryV1);
            let engine = engine(access, &[], false, false)?;
            let (namespace, generation, inventory) =
                resolve_generation(namespace, generation, |request| {
                    engine.inspect_generation_inventory_v1(request)
                })?;
            let request = DesiredSnapshotInspectionRequestV1::new(namespace, generation);
            print_desired_snapshot(
                &engine.inspect_desired_snapshot_v1(&request)?,
                inventory.generations(),
                output,
            )
        }
        Cmd::CanonicalTree { tree } => {
            contract.assert_engine_operation(EngineOperation::InspectCanonicalTreeV1);
            contract.assert_engine_operation(EngineOperation::InspectObjectInventoryV1);
            let engine = engine(access, &[], false, false)?;
            let inventory = engine.inspect_object_inventory_v1(&ObjectInventoryRequestV1::new(
                ObjectInventoryKindV1::CanonicalTree,
            ))?;
            let tree = resolve_digest(tree, IdDomain::Tree, inventory.objects())?;
            print_canonical_tree(
                &engine.inspect_canonical_tree_v1(&CanonicalTreeInspectionRequestV1::new(tree))?,
                inventory.objects(),
                output,
            )
        }
        Cmd::ArtifactMetadata { plan_id, id } => {
            contract.assert_engine_operation(EngineOperation::InspectArtifactMetadataV1);
            contract.assert_engine_operation(EngineOperation::InspectPlanIndexV1);
            let engine = engine(access, &[], false, false)?;
            let plans = engine.list_plans_v1()?;
            let candidates = plan_candidates(&plans);
            let request = ArtifactMetadataInspectionRequestV1::new(
                resolve_plan_reference(&plans, Some(plan_id))?,
                ArtifactId::new(id.clone())?,
            );
            print_artifact_metadata(
                &engine.inspect_artifact_metadata_v1(&request)?,
                &candidates,
                output,
            )
        }
        Cmd::CapturedInputs { plan_id } => {
            contract.assert_engine_operation(EngineOperation::InspectCapturedInputsV1);
            contract.assert_engine_operation(EngineOperation::InspectPlanIndexV1);
            let engine = engine(access, &[], false, false)?;
            let plans = engine.list_plans_v1()?;
            let candidates = plan_candidates(&plans);
            let request = PreparedPlanInspectionRequestV1::new(resolve_plan_reference(
                &plans,
                Some(plan_id),
            )?);
            print_captured_inputs(
                &engine.inspect_captured_inputs_v1(&request)?,
                &candidates,
                output,
            )
        }
        Cmd::TransformProvenance { plan_id } => {
            contract.assert_engine_operation(EngineOperation::InspectTransformProvenanceV1);
            contract.assert_engine_operation(EngineOperation::InspectPlanIndexV1);
            let engine = engine(access, &[], false, false)?;
            let plans = engine.list_plans_v1()?;
            let candidates = plan_candidates(&plans);
            let request = PreparedPlanInspectionRequestV1::new(resolve_plan_reference(
                &plans,
                Some(plan_id),
            )?);
            print_transform_provenance(
                &engine.inspect_transform_provenance_v1(&request)?,
                &candidates,
                output,
            )
        }
        Cmd::Retention {
            generation,
            namespace,
        } => {
            contract.assert_engine_operation(EngineOperation::InspectRetentionV1);
            contract.assert_engine_operation(EngineOperation::InspectGenerationInventoryV1);
            let engine = engine(access, &[], false, false)?;
            let (namespace, generation, inventory) =
                resolve_generation(namespace, generation, |request| {
                    engine.inspect_generation_inventory_v1(request)
                })?;
            let request = GenerationInspectionRequestV1::new(namespace, generation);
            print_retention(
                &engine.inspect_retention_authority_v1(&request)?,
                inventory.generations(),
                output,
            )
        }
        Cmd::Tracking {
            generation,
            namespace,
        } => {
            contract.assert_engine_operation(EngineOperation::InspectTrackingV1);
            contract.assert_engine_operation(EngineOperation::InspectGenerationInventoryV1);
            let engine = engine(access, &[], false, false)?;
            let (namespace, generation, inventory) =
                resolve_generation(namespace, generation, |request| {
                    engine.inspect_generation_inventory_v1(request)
                })?;
            let request = GenerationInspectionRequestV1::new(namespace, generation);
            print_tracking(
                &engine.inspect_tracking_v1(&request)?,
                inventory.generations(),
                output,
            )
        }
        Cmd::Status { namespace, target } => {
            contract.assert_engine_operation(EngineOperation::InspectNamespaceStatusV1);
            let engine = engine(access, &target.targets, true, false)?;
            let status = engine.inspect_namespace_status_v1(&NamespaceStatusRequestV1::new(
                NamespaceName::new(namespace.clone())?,
            ))?;
            exit_code = match status.status() {
                NamespaceStatusKindV1::NotFound
                | NamespaceStatusKindV1::EnabledExact
                | NamespaceStatusKindV1::Disabled => 0,
                NamespaceStatusKindV1::EnabledModified
                | NamespaceStatusKindV1::EnabledMissing
                | NamespaceStatusKindV1::EnabledUnexpected => 1,
                NamespaceStatusKindV1::Stale
                | NamespaceStatusKindV1::IncompatibleOrCorrupt
                | NamespaceStatusKindV1::RecoveryRequired => 2,
            };
            print_status(&status, output)
        }
        Cmd::Fsck {
            observe_targets,
            target,
        } => {
            contract.assert_engine_operation(EngineOperation::FsckV1);
            ensure!(
                *observe_targets || target.targets.is_empty(),
                "--target requires --observe-targets"
            );
            let engine =
                engine_with_output(access, &target.targets, *observe_targets, false, output)?;
            let request = FsckRequestV1::new();
            let request = if *observe_targets {
                request.with_target_observations(
                    request.max_target_observations(),
                    request.max_observed_bytes(),
                )?
            } else {
                request
            };
            let report = engine.fsck_v1(&request)?;
            if !report.is_clean() {
                exit_code = 1;
            }
            print_fsck(&report, output)
        }
        Cmd::Store { .. } | Cmd::Lock { .. } => {
            unreachable!("dispatched by the CLI router")
        }
    }?;
    Ok(exit_code)
}

pub(super) fn run_lock(command: &LockCmd, output: &Output) -> Result<()> {
    let contract = crate::cli::contracts::lock_contract(command);
    let access = contract
        .effect()
        .store_access()
        .expect("lock commands have a fixed store-access effect");
    let options = lock_options(command);
    let source = if options.source.is_absolute() {
        options.source.clone()
    } else {
        options
            .source
            .canonicalize()
            .with_context(|| format!("canonicalize source {}", options.source.display()))?
    };
    let local_locators =
        parse_unique_authorities(&options.local_locators, "--allow-local", |value| {
            Ok(LocalLocator::new(value)?)
        })?;
    let git_urls = parse_unique_authorities(&options.git_urls, "--allow-git", |value| {
        Ok(GitUrl::new(value)?)
    })?;
    let git_scratch_roots = parse_lock_git_scratch(&options.git_scratch)?;
    let inputs = LockResolutionInputs::new(local_locators, git_urls, git_scratch_roots)
        .with_format_component_execution_profile(
            malm_format_component_adapter::current_host_execution_profile_digest_v1(),
        );
    let git_executable = resolve_git_executable(options.git_executable.as_deref())?;
    let git = GitAcquisitionConfig::new(&git_executable)?;
    let config = crate::cli::SuccessorEnvironment::ambient()?.engine_config(access)?;
    let engine = Engine::new(config, output.engine_ports(EnginePorts::system()));
    let outcome = match command {
        LockCmd::Create(_) => {
            contract.assert_engine_operation(EngineOperation::CreateLockV1);
            engine.create_lock_v1(&source, &inputs, &git)?
        }
        LockCmd::Update(_) => {
            contract.assert_engine_operation(EngineOperation::UpdateLockV1);
            engine.update_lock_v1(&source, &inputs, &git)?
        }
    };
    print_lock(&outcome, &source, &git_executable, output)
}

fn lock_options(command: &LockCmd) -> &crate::cli::args::LockOptions {
    match command {
        LockCmd::Create(options) | LockCmd::Update(options) => options,
    }
}

fn parse_lock_git_scratch(values: &[String]) -> Result<BTreeMap<GitSourceV1, PathBuf>> {
    ensure!(
        values.len().is_multiple_of(4),
        "--git-scratch must provide HTTPS_URL GIT_OBJECT_ID PACK_SUBDIR ABSOLUTE_PATH"
    );
    let mut scratch = BTreeMap::new();
    let mut paths = BTreeSet::new();
    for values in values.chunks_exact(4) {
        let source = GitSourceV1::new(
            GitUrl::new(values[0].clone())?,
            GitObjectId::new(values[1].clone())?,
            PackSubdir::new(values[2].clone())?,
        );
        ensure!(
            !values[3].is_empty(),
            "--git-scratch path must not be empty"
        );
        let path = PathBuf::from(&values[3]);
        ensure!(path.is_absolute(), "--git-scratch path must be absolute");
        ensure!(
            scratch.insert(source.clone(), path.clone()).is_none(),
            "--git-scratch source {} {} {} is configured more than once",
            source.url(),
            source.commit(),
            source.subdir()
        );
        ensure!(
            paths.insert(path),
            "one --git-scratch path cannot serve multiple Git sources"
        );
    }
    Ok(scratch)
}

fn print_lock(
    outcome: &LockOperationOutcome,
    source: &Path,
    git_executable: &Path,
    output: &Output,
) -> Result<()> {
    let publication = lock_publication_name(outcome.publication());
    let graph_digest = lock_graph_digest(outcome.lock());
    output.emit(
        publication,
        || {
            serde_json::json!({
                "publication": publication,
                "source": json_path(source),
                "git_executable": json_path(git_executable),
                "graph_digest": graph_digest.as_str(),
                "pack_count": outcome.lock().nodes().len(),
            })
        },
        |rendered| {
            let title = match outcome.publication() {
                LockFilePublication::Created => "Source lock created",
                LockFilePublication::Updated => "Source lock updated",
                LockFilePublication::Unchanged => "Source lock is current",
            };
            let tone = if matches!(outcome.publication(), LockFilePublication::Unchanged) {
                Tone::Neutral
            } else {
                Tone::Success
            };
            out_line(rendered, format_args!("{}", output.heading(title, tone)));
            out_line(rendered, format_args!("  Source {}", source.display()));
            out_line(
                rendered,
                format_args!("  Packs  {}", outcome.lock().nodes().len()),
            );
            out_line(
                rendered,
                format_args!(
                    "  Graph  {}",
                    display_digest(IdDomain::Graph, &graph_digest, output.verbose())
                ),
            );
            if output.verbose() {
                out_line(
                    rendered,
                    format_args!("  Git    {}", git_executable.display()),
                );
            }
        },
    )?;
    Ok(())
}

const fn lock_publication_name(publication: LockFilePublication) -> &'static str {
    match publication {
        LockFilePublication::Created => "created",
        LockFilePublication::Updated => "updated",
        LockFilePublication::Unchanged => "unchanged",
    }
}

fn object_domain(kind: RetentionObjectKind) -> (IdDomain, ObjectInventoryKindV1) {
    match kind {
        RetentionObjectKind::ArtifactBlob => (IdDomain::Blob, ObjectInventoryKindV1::ArtifactBlob),
        RetentionObjectKind::PackObject => (IdDomain::Pack, ObjectInventoryKindV1::PackObject),
        RetentionObjectKind::CanonicalFile => {
            (IdDomain::File, ObjectInventoryKindV1::CanonicalFile)
        }
        RetentionObjectKind::CanonicalSymlink => {
            (IdDomain::Symlink, ObjectInventoryKindV1::CanonicalSymlink)
        }
        RetentionObjectKind::CanonicalTree => {
            (IdDomain::Tree, ObjectInventoryKindV1::CanonicalTree)
        }
        RetentionObjectKind::PreparedPlan | RetentionObjectKind::StateGeneration => {
            unreachable!("plan and generation retention selectors have dedicated inventories")
        }
    }
}

fn retention_digest_object(kind: RetentionObjectKind, digest: Digest) -> RetentionObjectV1 {
    match kind {
        RetentionObjectKind::ArtifactBlob => RetentionObjectV1::ArtifactBlob { digest },
        RetentionObjectKind::PackObject => RetentionObjectV1::PackObject { digest },
        RetentionObjectKind::CanonicalFile => RetentionObjectV1::CanonicalFile { digest },
        RetentionObjectKind::CanonicalSymlink => RetentionObjectV1::CanonicalSymlink { digest },
        RetentionObjectKind::CanonicalTree => RetentionObjectV1::CanonicalTree { digest },
        RetentionObjectKind::PreparedPlan | RetentionObjectKind::StateGeneration => {
            unreachable!("plan and generation retention selectors have dedicated inventories")
        }
    }
}

/// Resolves a retention selector against the inventory for its object kind.
///
/// Injected loaders keep selector parsing independent of Engine and store
/// access. Resolution invokes only the loader for the selected object domain.
fn resolve_retention_object<PE, GE, OE>(
    kind: RetentionObjectKind,
    object: &str,
    plans: impl FnOnce() -> Result<Vec<crate::PlanIndexEntryV1>, PE>,
    generations: impl FnOnce() -> Result<GenerationInventoryV1, GE>,
    objects: impl FnOnce(ObjectInventoryKindV1) -> Result<ObjectInventoryV1, OE>,
) -> Result<RetentionObjectV1>
where
    anyhow::Error: From<PE> + From<GE> + From<OE>,
{
    match kind {
        RetentionObjectKind::PreparedPlan => {
            let plans = plans()?;
            Ok(RetentionObjectV1::PreparedPlan {
                plan_id: resolve_plan_reference(&plans, Some(object))?,
            })
        }
        RetentionObjectKind::StateGeneration => {
            let inventory = generations()?;
            Ok(RetentionObjectV1::StateGeneration {
                digest: resolve_digest(object, IdDomain::Generation, inventory.generations())?,
            })
        }
        kind => {
            let (domain, inventory_kind) = object_domain(kind);
            let inventory = objects(inventory_kind)?;
            let digest = resolve_digest(object, domain, inventory.objects())?;
            Ok(retention_digest_object(kind, digest))
        }
    }
}

/// Resolves a namespace and generation selector in the bounded inventory.
///
/// Injecting inventory access keeps parsing and short-ID resolution separate
/// from the Engine operation that supplies durable state.
fn resolve_generation<E>(
    namespace: &str,
    generation: &str,
    inventory: impl FnOnce(&GenerationInventoryRequestV1) -> Result<GenerationInventoryV1, E>,
) -> Result<(NamespaceName, Digest, GenerationInventoryV1)>
where
    anyhow::Error: From<E>,
{
    let namespace = NamespaceName::new(namespace.to_owned())?;
    let inventory = inventory(&GenerationInventoryRequestV1::new(namespace.clone()))?;
    let generation = resolve_digest(generation, IdDomain::Generation, inventory.generations())?;
    Ok((namespace, generation, inventory))
}

fn plan_candidates(plans: &[crate::PlanIndexEntryV1]) -> Vec<PreparedId> {
    plans.iter().map(|entry| entry.plan_id().clone()).collect()
}

fn read_lock(path: &Path) -> Result<Vec<u8>> {
    let mut file = File::open(path).with_context(|| format!("open lock {}", path.display()))?;
    let mut bytes = Vec::new();
    (&mut file)
        .take(malm_types::usize_to_u64(MAX_LOCK_BYTES + 1))
        .read_to_end(&mut bytes)
        .with_context(|| format!("read lock {}", path.display()))?;
    ensure!(
        bytes.len() <= MAX_LOCK_BYTES,
        "lock {} exceeds the {} byte limit",
        path.display(),
        MAX_LOCK_BYTES
    );
    Ok(bytes)
}

fn parse_git_scratch(values: &[String]) -> Result<BTreeMap<Digest, PathBuf>> {
    let mut scratch = BTreeMap::new();
    let mut paths = BTreeSet::new();
    for value in values {
        let (digest, path) = value
            .split_once('=')
            .context("--git-scratch must be DIGEST=ABSOLUTE_PATH")?;
        ensure!(!path.is_empty(), "--git-scratch path must not be empty");
        let digest = Digest::new(digest.to_owned())?;
        let path = PathBuf::from(path);
        ensure!(path.is_absolute(), "--git-scratch path must be absolute");
        ensure!(
            scratch.insert(digest.clone(), path.clone()).is_none(),
            "--git-scratch digest {digest} is configured more than once"
        );
        ensure!(
            paths.insert(path),
            "one --git-scratch path cannot serve multiple digests"
        );
    }
    Ok(scratch)
}

fn parse_unique_authorities<T: Ord>(
    values: &[String],
    option: &str,
    mut parse: impl FnMut(String) -> Result<T>,
) -> Result<BTreeSet<T>> {
    let mut authorities = BTreeSet::new();
    for value in values {
        let authority = parse(value.clone())?;
        ensure!(
            authorities.insert(authority),
            "{option} authority {value} is configured more than once"
        );
    }
    Ok(authorities)
}

fn tracked_infrastructure(
    git_executable: &Path,
    root_scratch: &Path,
    git_scratch: &[String],
) -> Result<TrackedRootInfrastructureV1> {
    ensure!(
        root_scratch.is_absolute(),
        "--root-scratch must be an absolute path"
    );
    let dependency_scratch = parse_git_scratch(git_scratch)?;
    ensure!(
        dependency_scratch.values().all(|path| path != root_scratch),
        "--root-scratch cannot also be used as --git-scratch"
    );
    Ok(TrackedRootInfrastructureV1::new(
        GitAcquisitionConfig::new(git_executable)?,
        root_scratch,
        dependency_scratch,
    ))
}

fn engine(
    access: StoreAccess,
    targets: &[String],
    default_home: bool,
    format_components: bool,
) -> Result<Engine> {
    engine_inner(access, targets, default_home, format_components, None)
}

fn engine_with_output(
    access: StoreAccess,
    targets: &[String],
    default_home: bool,
    format_components: bool,
    output: &Output,
) -> Result<Engine> {
    engine_inner(
        access,
        targets,
        default_home,
        format_components,
        Some(output),
    )
}

fn engine_inner(
    access: StoreAccess,
    targets: &[String],
    default_home: bool,
    format_components: bool,
    output: Option<&Output>,
) -> Result<Engine> {
    let environment = crate::cli::SuccessorEnvironment::ambient()?;
    let mut config = environment.engine_config(access)?;
    if targets.is_empty() && default_home {
        config = config.with_target_authority(DeploymentName::new("home")?, environment.home()?)?;
    } else {
        for target in targets {
            let (name, path) = target
                .split_once('=')
                .context("--target must be NAME=ABSOLUTE_PATH")?;
            config = config.with_target_authority(
                DeploymentName::new(name.to_owned())?,
                PathBuf::from(path),
            )?;
        }
    }
    let mut ports = EnginePorts::system();
    if format_components {
        // The cache contains Wasmtime machine code keyed by component content
        // and compiler configuration. Deleting it only forces recompilation.
        let port = match compile_cache_directory() {
            Some(cache_dir) => {
                malm_format_component_adapter::InProcessFormatComponentExecutionPort::with_compile_cache(
                    &cache_dir,
                )?
            }
            None => malm_format_component_adapter::InProcessFormatComponentExecutionPort::new()?,
        };
        ports = ports.with_format_component_execution(Arc::new(port));
    }
    if let Some(output) = output {
        ports = output.engine_ports(ports);
    }
    Ok(Engine::new(config, ports))
}

fn compile_cache_directory() -> Option<PathBuf> {
    let base = match std::env::var_os("XDG_CACHE_HOME") {
        Some(cache) if !cache.is_empty() => PathBuf::from(cache),
        _ => PathBuf::from(std::env::var_os("HOME")?).join(".cache"),
    };
    Some(base.join("malm").join("wasmtime"))
}

/// Inputs shared by the `prepare` and `apply` static-deployment paths.
struct StaticPrepareOptions<'a> {
    source: &'a Path,
    lock: &'a Option<PathBuf>,
    cached: bool,
    namespace: &'a str,
    target_authority: &'a str,
    targets: &'a [String],
    local_locators: &'a [String],
    git_urls: &'a [String],
    git_scratch: &'a [String],
    git_executable: &'a Option<PathBuf>,
}

/// Builds the engine and static-deployment request.
///
/// This host-side boundary resolves paths, process authority, and acquisition
/// inputs but does not prepare a plan; the caller invokes the selected Engine
/// operation.
fn static_prepare_request(
    access: StoreAccess,
    options: &StaticPrepareOptions<'_>,
    selected_profile: Option<&str>,
    output: &Output,
) -> Result<(Engine, StaticDeploymentPrepareRequestV1)> {
    ensure!(
        options.source.is_absolute(),
        "--source must be an absolute pack root"
    );
    let engine = engine_with_output(access, options.targets, true, true, output)?;
    let lock_path = options
        .lock
        .clone()
        .unwrap_or_else(|| options.source.join(malm_pack::LOCK_FILE));
    let lock = decode_lock_v1(&read_lock(&lock_path)?)?;
    let acquisition = if options.cached {
        StaticGraphAcquisitionV1::cached()
    } else {
        let local_grants = options
            .local_locators
            .iter()
            .cloned()
            .map(LocalLocator::new)
            .collect::<std::result::Result<BTreeSet<_>, _>>()?;
        let git_grants = options
            .git_urls
            .iter()
            .cloned()
            .map(GitUrl::new)
            .collect::<std::result::Result<BTreeSet<_>, _>>()?;
        let scratch = parse_git_scratch(options.git_scratch)?;
        let inputs = GraphAcquisitionInputs::new(local_grants, git_grants, scratch);
        let git = if git_grants_needed(&inputs) || options.git_executable.is_some() {
            Some(GitAcquisitionConfig::new(&resolve_git_executable(
                options.git_executable.as_deref(),
            )?)?)
        } else {
            None
        };
        StaticGraphAcquisitionV1::acquire(options.source, inputs, git)
    };
    let profile = selected_profile
        .map(|profile| ContributionName::new(profile.to_owned()))
        .transpose()?;
    let request = StaticDeploymentPrepareRequestV1::new(
        lock,
        acquisition,
        FormatComponentAuthorizationV1::default(),
        profile,
        NamespaceName::new(options.namespace.to_owned())?,
        DeploymentName::new(options.target_authority.to_owned())?,
    );
    Ok((engine, request))
}

fn git_grants_needed(inputs: &GraphAcquisitionInputs) -> bool {
    !inputs.git_urls().is_empty() || !inputs.git_scratch_roots().is_empty()
}

/// Resolves the trusted Git executable to an absolute path.
///
/// An explicit path takes precedence. Otherwise this human adapter finds and
/// canonicalizes the first `git` on PATH; the Engine API itself does not search.
fn resolve_git_executable(explicit: Option<&Path>) -> Result<PathBuf> {
    if let Some(path) = explicit {
        return Ok(path.to_path_buf());
    }
    let path_variable = std::env::var_os("PATH").context("PATH is not set")?;
    for directory in std::env::split_paths(&path_variable) {
        let candidate = directory.join("git");
        if candidate.is_file() {
            let resolved = candidate
                .canonicalize()
                .with_context(|| format!("canonicalize {}", candidate.display()))?;
            return Ok(resolved);
        }
    }
    anyhow::bail!("no `git` found on PATH; pass --git-executable ABSOLUTE_PATH")
}

fn print_commit_outcome(
    outcome: &malm_types::ApplyOutcomeV1,
    plan: Option<&PreparedDeploymentV1>,
    plan_candidates: &[PreparedId],
    output: &Output,
) -> Result<()> {
    let application = serde_json::json!({
        "plan_id": outcome.plan_id().as_str(),
        "namespace": outcome.namespace().as_str(),
        "previous_generation": outcome.previous_head().map(Digest::as_str),
        "generation": outcome.next_head().map(Digest::as_str),
        "removed": outcome.next_head().is_none(),
    });
    output.emit(
        "applied",
        || match plan {
            Some(plan) => serde_json::json!({
                "plan": plan_json(plan),
                "application": application,
            }),
            None => application,
        },
        |rendered| {
            let title = if outcome.next_head().is_some() {
                "Applied"
            } else {
                "Namespace removed"
            };
            out_line(
                rendered,
                format_args!("{}", output.heading(title, Tone::Success)),
            );
            out_line(
                rendered,
                format_args!("  Namespace   {}", outcome.namespace()),
            );
            match (outcome.previous_head(), outcome.next_head()) {
                (Some(previous), Some(next)) => {
                    out_line(
                        rendered,
                        format_args!(
                            "  Generation  {} -> {}",
                            display_digest(IdDomain::Generation, previous, output.verbose()),
                            display_digest(IdDomain::Generation, next, output.verbose())
                        ),
                    );
                }
                (None, Some(next)) => {
                    out_line(
                        rendered,
                        format_args!(
                            "  Generation  {}",
                            display_digest(IdDomain::Generation, next, output.verbose())
                        ),
                    );
                }
                (Some(previous), None) => {
                    out_line(
                        rendered,
                        format_args!(
                            "  Previous    {}",
                            display_digest(IdDomain::Generation, previous, output.verbose())
                        ),
                    );
                }
                (None, None) => {}
            }
            out_line(
                rendered,
                format_args!(
                    "  Plan        {}",
                    display_plan_unique(outcome.plan_id(), plan_candidates, output.verbose())
                ),
            );
        },
    )
}

/// Resolves a plan selector in the bounded durable-plan index.
///
/// An omitted reference selects the newest plan for internal callers.
fn resolve_plan_reference(
    plans: &[crate::PlanIndexEntryV1],
    reference: Option<&str>,
) -> Result<PreparedId> {
    match reference {
        None => {
            let newest = plans
                .first()
                .context("no durable plans exist; run prepare or apply first")?;
            Ok(newest.plan_id().clone())
        }
        Some(reference) => resolve_plan(reference, &plan_candidates(plans)),
    }
}

/// Resolves the explicit source root or uses the current directory.
///
/// The resolved directory must contain the root authoring configuration.
fn resolve_source_root(explicit: Option<&Path>) -> Result<PathBuf> {
    let root = match explicit {
        Some(path) => path.to_path_buf(),
        None => std::env::current_dir().context("resolve current directory")?,
    };
    let root = if root.is_absolute() {
        root
    } else {
        root.canonicalize()
            .with_context(|| format!("canonicalize {}", root.display()))?
    };
    ensure!(
        root.join(malm_authoring::AUTHORING_CONFIG_FILE).is_file(),
        "{} has no {}",
        root.display(),
        malm_authoring::AUTHORING_CONFIG_FILE
    );
    Ok(root)
}

/// Reports the exact bootstrap command when the pack does not yet have a lock.
fn ensure_lock_exists(source: &Path, lock: Option<&Path>) -> Result<()> {
    let lock_path = lock
        .map(Path::to_path_buf)
        .unwrap_or_else(|| source.join(malm_pack::LOCK_FILE));
    ensure!(
        lock_path.is_file(),
        "no lock at {}; create it once with:\n    malm source lock create --source {}",
        lock_path.display(),
        source.display()
    );
    Ok(())
}

/// Captures authoring sources for commands that do not use the store.
///
/// The manifest's `captures` allowlist bounds the walk. Regular files follow
/// Engine capture semantics; symlinks outside the allowlist are skipped, while
/// symlinks inside it are rejected.
fn capture_authoring_sources(root: &Path) -> Result<malm_authoring::AuthoringSourceSetV1> {
    let capture_roots = std::fs::read(root.join(malm_pack::PACK_MANIFEST_FILE))
        .ok()
        .and_then(|bytes| malm_pack::decode_pack_v1(&bytes).ok())
        .map(|manifest| {
            manifest
                .capture_roots()
                .iter()
                .map(|path| path.as_str().to_owned())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let within = |logical: &str| -> bool {
        if capture_roots.is_empty() || logical == malm_pack::PACK_MANIFEST_FILE {
            return true;
        }
        capture_roots.iter().any(|declared| {
            logical == declared
                || logical
                    .strip_prefix(declared.as_str())
                    .is_some_and(|rest| rest.starts_with('/'))
                || declared
                    .strip_prefix(logical)
                    .is_some_and(|rest| rest.starts_with('/'))
        })
    };
    let mut sources = malm_authoring::AuthoringSourceSetV1::new();
    let mut pending = vec![root.to_path_buf()];
    while let Some(directory) = pending.pop() {
        let mut entries = std::fs::read_dir(&directory)
            .with_context(|| format!("read {}", directory.display()))?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        entries.sort_by_key(std::fs::DirEntry::file_name);
        for entry in entries {
            let path = entry.path();
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                anyhow::bail!("non-UTF-8 source name under {}", directory.display());
            };
            if matches!(name, ".git" | "malm.lock") {
                continue;
            }
            let logical = path
                .strip_prefix(root)
                .expect("walk stays under the root")
                .to_str()
                .expect("segments validated UTF-8")
                .to_owned();
            if !within(&logical) {
                continue;
            }
            let kind = entry.file_type()?;
            if kind.is_symlink() {
                anyhow::bail!("symlink in captured sources: {}", path.display());
            }
            if kind.is_dir() {
                pending.push(path);
            } else {
                let bytes =
                    std::fs::read(&path).with_context(|| format!("read {}", path.display()))?;
                sources
                    .insert(&logical, bytes)
                    .map_err(|error| anyhow::anyhow!("capture {logical}: {error}"))?;
            }
        }
    }
    Ok(sources)
}

fn resolve_authoring_profile(
    sources: &malm_authoring::AuthoringSourceSetV1,
    selected: Option<&str>,
) -> Result<String> {
    if let Some(selected) = selected {
        return Ok(selected.to_owned());
    }
    malm_authoring::default_authoring_profile_v1(sources, malm_authoring::AUTHORING_CONFIG_FILE)
        .map_err(|error| anyhow::anyhow!("{error}"))
}

/// Reads declared machine-local overlays for commands that do not use the store.
///
/// Paths beginning with `~/` resolve against the ambient home directory.
fn read_host_overlays(
    sources: &malm_authoring::AuthoringSourceSetV1,
) -> Result<Vec<malm_authoring::OverlaySourceV1>> {
    let declarations =
        malm_authoring::declared_overlays_v1(sources, malm_authoring::AUTHORING_CONFIG_FILE)
            .map_err(|error| anyhow::anyhow!("{error}"))?;
    let environment = crate::cli::SuccessorEnvironment::ambient()?;
    let mut supplied = Vec::new();
    for declaration in declarations {
        let resolved = match declaration.path().strip_prefix("~/") {
            Some(rest) => environment.home()?.join(rest),
            None => PathBuf::from(declaration.path()),
        };
        match std::fs::read(&resolved) {
            Ok(bytes) => {
                supplied.push(malm_authoring::OverlaySourceV1::new(
                    declaration.name().to_owned(),
                    bytes,
                ));
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                ensure!(
                    declaration.optional(),
                    "overlay `{}`: required file {} is missing",
                    declaration.name(),
                    resolved.display()
                );
            }
            Err(error) => {
                anyhow::bail!(
                    "overlay `{}`: read {}: {error}",
                    declaration.name(),
                    resolved.display()
                );
            }
        }
    }
    Ok(supplied)
}

fn render_to_directory(
    evaluated: &malm_authoring::EvaluatedAuthoringProfileV1,
    destination_root: &Path,
    output: &Output,
) -> Result<()> {
    let component_outputs = evaluated
        .outputs()
        .iter()
        .filter(|rendered| {
            rendered.component_render().is_some() || !rendered.transforms().is_empty()
        })
        .map(|rendered| rendered.destination())
        .collect::<Vec<_>>();
    ensure!(
        component_outputs.is_empty(),
        "source render cannot execute component transforms or renderers; use deploy for: {}",
        component_outputs.join(", ")
    );
    let root = open_render_root(destination_root)?;
    let mut rendered_bindings = Vec::new();
    let mut files = Vec::new();
    for (index, rendered) in evaluated.outputs().iter().enumerate() {
        let destination = render_destination(evaluated.target(), rendered.destination())?;
        let relative = Path::new(&destination);
        let mode = if rendered.executable() { 0o755 } else { 0o644 };
        let bytes = rendered
            .bytes()
            .expect("component-backed outputs were rejected before creating the output root");
        root.revalidate()?;
        rendered_bindings.extend(
            write_rendered_file(&root, relative, bytes, mode, index)
                .with_context(|| format!("write {}", destination_root.join(relative).display()))?,
        );
        root.revalidate()?;
        files.push((destination, bytes.len(), rendered.executable()));
    }
    let mut symlinks = Vec::new();
    for (index, symlink) in evaluated.symlinks().iter().enumerate() {
        let destination = render_destination(evaluated.target(), symlink.destination())?;
        let target = symlink.target().strip_prefix("~/").with_context(|| {
            format!(
                "symlink {:?} target {:?} must be `~/`-relative",
                symlink.destination(),
                symlink.target()
            )
        })?;
        validate_render_relative(target, "symlink target")?;
        let relative_target = relative_render_symlink_target(&destination, target);
        root.revalidate()?;
        rendered_bindings.extend(
            write_rendered_symlink(
                &root,
                Path::new(&destination),
                &relative_target,
                evaluated.outputs().len() + index,
            )
            .with_context(|| {
                format!(
                    "write symlink {}",
                    destination_root.join(&destination).display()
                )
            })?,
        );
        root.revalidate()?;
        symlinks.push((destination, relative_target));
    }
    root.revalidate()?;
    revalidate_render_bindings(&rendered_bindings)?;
    files.sort();
    symlinks.sort();
    output.emit(
        "rendered",
        || {
            serde_json::json!({
                "profile": evaluated.profile(),
                "output": json_path(destination_root),
                "outputs": files.iter().map(|(destination, bytes, executable)| serde_json::json!({
                    "kind": "file",
                    "destination": destination,
                    "byte_len": bytes,
                    "executable": executable,
                })).chain(symlinks.iter().map(|(destination, target)| serde_json::json!({
                    "kind": "symlink",
                    "destination": destination,
                    "target": target,
                }))).collect::<Vec<_>>(),
            })
        },
        |rendered| {
            out_line(
                rendered,
                format_args!("{}", output.heading("Source rendered", Tone::Success)),
            );
            out_line(rendered, format_args!("  Profile  {}", evaluated.profile()));
            out_line(
                rendered,
                format_args!("  Output   {}", destination_root.display()),
            );
            out_line(rendered, format_args!("  Files    {}", files.len()));
            out_line(rendered, format_args!("  Symlinks {}", symlinks.len()));
            let total_bytes: usize = files.iter().map(|(_, bytes, _)| *bytes).sum();
            out_line(
                rendered,
                format_args!("  Size     {}", human_bytes(total_bytes as u64)),
            );
            if output.verbose() && (!files.is_empty() || !symlinks.is_empty()) {
                out_line(rendered, format_args!("\nFiles"));
                for (destination, bytes, executable) in &files {
                    out_line(
                        rendered,
                        format_args!(
                            "  {}  {}  {}",
                            destination,
                            human_bytes(*bytes as u64),
                            if *executable { "0755" } else { "0644" }
                        ),
                    );
                }
                for (destination, target) in &symlinks {
                    out_line(rendered, format_args!("  {destination} -> {target}"));
                }
            }
        },
    )?;
    Ok(())
}

fn render_destination(target: &str, destination: &str) -> Result<String> {
    let mapped = if let Some(home_relative) = destination.strip_prefix("~/") {
        home_relative.to_owned()
    } else {
        ensure!(
            destination != "~" && !Path::new(destination).is_absolute(),
            "unsupported render destination {destination:?}"
        );
        if target == "~" {
            destination.to_owned()
        } else {
            let target = target.strip_prefix("~/").with_context(|| {
                format!("config target {target:?} must be `~` or `~/`-relative")
            })?;
            format!("{target}/{destination}")
        }
    };
    validate_render_relative(&mapped, "render destination")?;
    Ok(mapped)
}

fn validate_render_relative(value: &str, label: &str) -> Result<()> {
    let path = Path::new(value);
    ensure!(
        !value.is_empty()
            && !path.is_absolute()
            && path
                .components()
                .all(|component| matches!(component, std::path::Component::Normal(_))),
        "{label} {value:?} escapes the output directory"
    );
    Ok(())
}

fn relative_render_symlink_target(link: &str, target: &str) -> String {
    let mut link_parent = link.split('/').collect::<Vec<_>>();
    link_parent.pop();
    let target = target.split('/').collect::<Vec<_>>();
    let common = link_parent
        .iter()
        .zip(&target)
        .take_while(|(left, right)| left == right)
        .count();
    let mut relative = vec![".."; link_parent.len() - common];
    relative.extend_from_slice(&target[common..]);
    relative.join("/")
}

struct RenderBinding {
    parent: File,
    name: OsString,
    child: File,
}

struct RenderRoot {
    directory: File,
    bindings: Vec<RenderBinding>,
}

impl RenderRoot {
    fn revalidate(&self) -> Result<()> {
        revalidate_render_bindings(&self.bindings)?;
        validate_render_root(&self.directory)
    }
}

fn open_render_root(destination_root: &Path) -> Result<RenderRoot> {
    let absolute = std::path::absolute(destination_root)
        .with_context(|| format!("resolve output directory {}", destination_root.display()))?;
    let mut directory = File::from(
        open(
            "/",
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .context("open filesystem root for output traversal")?,
    );
    let mut bindings = Vec::new();
    for component in absolute.components() {
        match component {
            std::path::Component::RootDir => {}
            std::path::Component::Normal(segment) => {
                let child = open_or_create_render_directory(&directory, segment, &absolute, false)?;
                bindings.push(RenderBinding {
                    parent: directory.try_clone()?,
                    name: segment.to_owned(),
                    child: child.try_clone()?,
                });
                directory = child;
            }
            _ => anyhow::bail!(
                "output directory {} must use a normalized path",
                destination_root.display()
            ),
        }
    }
    let root = RenderRoot {
        directory,
        bindings,
    };
    root.revalidate()?;
    Ok(root)
}

fn validate_render_root(directory: &File) -> Result<()> {
    let stat = fstat(directory)?;
    ensure!(
        FileType::from_raw_mode(stat.st_mode) == FileType::Directory,
        "output root is not a directory"
    );
    ensure!(
        stat.st_uid == geteuid().as_raw(),
        "output root must be owned by the current user"
    );
    ensure!(
        stat.st_mode & 0o022 == 0,
        "output root must not be writable by group or other users"
    );
    Ok(())
}

fn revalidate_render_bindings(bindings: &[RenderBinding]) -> Result<()> {
    for binding in bindings {
        let bound = statat(&binding.parent, &binding.name, AtFlags::SYMLINK_NOFOLLOW)?;
        let opened = fstat(&binding.child)?;
        ensure!(
            bound.st_dev == opened.st_dev
                && bound.st_ino == opened.st_ino
                && FileType::from_raw_mode(opened.st_mode) == FileType::Directory,
            "output directory binding changed during render"
        );
    }
    Ok(())
}

fn open_or_create_render_directory(
    parent: &File,
    segment: &OsStr,
    display_path: &Path,
    confined: bool,
) -> Result<File> {
    let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW;
    let mut resolve =
        ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS;
    if confined {
        resolve |= ResolveFlags::NO_XDEV;
    }
    match openat2(parent, segment, flags, Mode::empty(), resolve) {
        Ok(directory) => Ok(File::from(directory)),
        Err(rustix::io::Errno::NOENT) => {
            let created = match mkdirat(parent, segment, Mode::from_raw_mode(0o755)) {
                Ok(()) => true,
                Err(rustix::io::Errno::EXIST) => false,
                Err(error) => {
                    return Err(error).with_context(|| {
                        format!("create output directory {}", display_path.display())
                    });
                }
            };
            let directory = File::from(
                openat2(parent, segment, flags, Mode::empty(), resolve)
                    .with_context(|| format!("open output directory {}", display_path.display()))?,
            );
            if created {
                fchmod(&directory, Mode::from_raw_mode(0o755)).with_context(|| {
                    format!("set output directory mode for {}", display_path.display())
                })?;
                fsync(parent).with_context(|| {
                    format!(
                        "sync output directory parent for {}",
                        display_path.display()
                    )
                })?;
            }
            Ok(directory)
        }
        Err(error) => {
            Err(error).with_context(|| format!("open output directory {}", display_path.display()))
        }
    }
}

fn write_rendered_file(
    root: &RenderRoot,
    relative: &Path,
    bytes: &[u8],
    mode: u32,
    index: usize,
) -> Result<Vec<RenderBinding>> {
    let (parent, file_name, bindings) = open_render_parent(root, relative)?;
    revalidate_render_bindings(&bindings)?;
    let temporary = OsString::from(format!(".malm-render-{}-{index}.tmp", std::process::id()));
    let resolve = ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS;
    let mut temporary_created = false;
    let result = (|| -> Result<()> {
        let mut file = File::from(openat2(
            &parent,
            &temporary,
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::from_raw_mode(mode),
            resolve,
        )?);
        temporary_created = true;
        fchmod(&file, Mode::from_raw_mode(mode))?;
        file.write_all(bytes)?;
        file.sync_all()?;
        renameat_with(
            &parent,
            &temporary,
            &parent,
            &file_name,
            RenameFlags::empty(),
        )?;
        fsync(&parent)?;
        revalidate_render_bindings(&bindings)?;
        Ok(())
    })();
    if let Err(error) = result {
        if temporary_created {
            let _ = unlinkat(&parent, &temporary, AtFlags::empty());
        }
        return Err(error);
    }
    Ok(bindings)
}

fn write_rendered_symlink(
    root: &RenderRoot,
    relative: &Path,
    target: &str,
    index: usize,
) -> Result<Vec<RenderBinding>> {
    let (parent, file_name, bindings) = open_render_parent(root, relative)?;
    revalidate_render_bindings(&bindings)?;
    let temporary = OsString::from(format!(
        ".malm-render-link-{}-{index}.tmp",
        std::process::id()
    ));
    let mut temporary_created = false;
    let result = (|| -> Result<()> {
        symlinkat(target, &parent, &temporary)?;
        temporary_created = true;
        renameat_with(
            &parent,
            &temporary,
            &parent,
            &file_name,
            RenameFlags::empty(),
        )?;
        fsync(&parent)?;
        revalidate_render_bindings(&bindings)?;
        Ok(())
    })();
    if let Err(error) = result {
        if temporary_created {
            let _ = unlinkat(&parent, &temporary, AtFlags::empty());
        }
        return Err(error);
    }
    Ok(bindings)
}

fn open_render_parent(
    root: &RenderRoot,
    relative: &Path,
) -> Result<(File, OsString, Vec<RenderBinding>)> {
    let mut parent = root.directory.try_clone()?;
    let components = relative.components().collect::<Vec<_>>();
    let (file_name, directories) = components
        .split_last()
        .context("render destination must name a file")?;
    let mut bindings = Vec::new();
    for component in directories {
        let std::path::Component::Normal(segment) = component else {
            anyhow::bail!("render destination must be relative and normalized");
        };
        let child = open_or_create_render_directory(&parent, segment, relative, true)?;
        bindings.push(RenderBinding {
            parent: parent.try_clone()?,
            name: (*segment).to_owned(),
            child: child.try_clone()?,
        });
        parent = child;
    }
    let std::path::Component::Normal(file_name) = file_name else {
        anyhow::bail!("render destination must name a normal file");
    };
    Ok((parent, file_name.to_os_string(), bindings))
}

fn print_vars(
    vars: &[malm_authoring::ResolvedVarV1],
    name: Option<&str>,
    output: &Output,
) -> Result<()> {
    let selected: Vec<_> = vars
        .iter()
        .filter(|var| name.is_none_or(|name| var.name() == name))
        .collect();
    output.emit(
        "resolved",
        || {
            serde_json::json!({
                "vars": selected.iter().map(|var| serde_json::json!({
                    "instance": var.instance(),
                    "name": var.name(),
                    "value": var.rendered_value(),
                    "origin": var.origin(),
                })).collect::<Vec<_>>(),
            })
        },
        |rendered| {
            out_line(
                rendered,
                format_args!(
                    "{}",
                    output.heading(
                        &format!("Resolved variables  {}", selected.len()),
                        Tone::Neutral
                    )
                ),
            );
            for var in &selected {
                out_line(
                    rendered,
                    format_args!(
                        "  {}.{} = {}  ({})",
                        var.instance(),
                        var.name(),
                        var.rendered_value(),
                        var.origin()
                    ),
                );
            }
        },
    )?;
    Ok(())
}

pub(super) fn print_plan(plan: &PreparedDeploymentV1, output: &Output) -> Result<()> {
    let outcome = if output.command() == "plan.show" {
        "inspected"
    } else {
        "planned"
    };
    print_plan_view(plan, &[], &[], output, outcome, true)
}

fn print_plan_with_candidates(
    plan: &PreparedDeploymentV1,
    candidates: &[PreparedId],
    output: &Output,
) -> Result<()> {
    print_plan_view(plan, candidates, &[], output, "inspected", true)
}

fn print_plan_with_generation_candidates(
    plan: &PreparedDeploymentV1,
    candidates: &[Digest],
    output: &Output,
) -> Result<()> {
    print_plan_view(plan, &[], candidates, output, "planned", true)
}

pub(super) fn print_plan_review(
    plan: &PreparedDeploymentV1,
    candidates: &[PreparedId],
    output: &Output,
    outcome: &str,
) -> Result<()> {
    print_plan_view(plan, candidates, &[], output, outcome, false)
}

pub(super) fn plan_changes_managed_targets(plan: &PreparedDeploymentV1) -> bool {
    plan.operations().iter().any(|operation| {
        !matches!(
            operation,
            PrepareOperationV1::AssertAbsent { .. } | PrepareOperationV1::AssertExact { .. }
        )
    })
}

fn print_plan_view(
    plan: &PreparedDeploymentV1,
    plan_candidates: &[PreparedId],
    generation_candidates: &[Digest],
    output: &Output,
    outcome: &str,
    show_next: bool,
) -> Result<()> {
    output.emit(
        outcome,
        || plan_json(plan),
        |rendered| {
            let approval_count = plan
                .findings()
                .iter()
                .filter(|finding| finding.approval_required())
                .count();
            let advisory_count = plan.findings().len().saturating_sub(approval_count);
            let tone = if approval_count == 0 {
                Tone::Success
            } else {
                Tone::Attention
            };
            let title = if approval_count == 0 {
                "Plan ready"
            } else {
                "Plan requires approval"
            };
            let mutation_count = plan
                .operations()
                .iter()
                .filter(|operation| operation_change_line(plan, operation).is_some())
                .count();
            let precondition_count = plan.operations().len().saturating_sub(mutation_count);

            out_line(rendered, format_args!("{}", output.heading(title, tone)));
            out_line(
                rendered,
                format_args!(
                    "  Plan        {}",
                    display_plan_unique(plan.plan_id(), plan_candidates, output.verbose())
                ),
            );
            out_line(rendered, format_args!("  Namespace   {}", plan.namespace()));
            out_line(
                rendered,
                format_args!(
                    "  Transition  {}",
                    lifecycle_transition_label(plan.transition())
                ),
            );
            match plan.expected_head() {
                Some(head) => {
                    out_line(
                        rendered,
                        format_args!(
                            "  Base        {} ({})",
                            display_digest_unique(
                                IdDomain::Generation,
                                head,
                                generation_candidates,
                                output.verbose()
                            ),
                            lifecycle_state_name(plan.lifecycle_state())
                        ),
                    );
                }
                None => {
                    out_line(rendered, format_args!("  Base        new namespace"));
                }
            }

            if let Some(tracked) = plan.tracking_review() {
                out_line(rendered, format_args!("\nSource"));
                out_line(
                    rendered,
                    format_args!("  Repository  {}", tracked.source_locator()),
                );
                out_line(
                    rendered,
                    format_args!("  Selector    {}", tracked.moving_selector()),
                );
                out_line(
                    rendered,
                    format_args!("  Revision    {}", tracked.applied_revision()),
                );
                out_line(
                    rendered,
                    format_args!("  Profile     {}", tracked.selected_profile()),
                );
            }

            out_line(rendered, format_args!("\nChanges  {mutation_count}"));
            if mutation_count == 0 {
                out_line(rendered, format_args!("  No managed target changes."));
            } else {
                for operation in plan.operations() {
                    if let Some(line) = operation_change_line(plan, operation) {
                        out_line(rendered, format_args!("  {line}"));
                    }
                }
            }

            if approval_count > 0 {
                out_line(
                    rendered,
                    format_args!("\nApproval required  {approval_count}"),
                );
                for finding in plan
                    .findings()
                    .iter()
                    .filter(|finding| finding.approval_required())
                {
                    out_line(rendered, format_args!("  ! {}", finding.code()));
                    write_wrapped_text(rendered, finding.message(), "    ", "    ");
                }
            }

            if advisory_count > 0 {
                let mut advisories = BTreeMap::<&str, Vec<&str>>::new();
                for finding in plan
                    .findings()
                    .iter()
                    .filter(|finding| !finding.approval_required())
                {
                    advisories
                        .entry(finding.code())
                        .or_default()
                        .push(finding.message());
                }
                out_line(rendered, format_args!("\nAdvisories  {}", advisories.len()));
                for (code, messages) in advisories {
                    out_line(
                        rendered,
                        format_args!("  {}", advisory_summary(code, &messages, output.verbose())),
                    );
                }
            }

            if output.verbose() {
                out_line(rendered, format_args!("\nTechnical"));
                out_line(
                    rendered,
                    format_args!(
                        "  {} inputs, {} transforms, {} artifacts, {} preconditions",
                        plan.inputs().len(),
                        plan.transforms().len(),
                        plan.artifacts().len(),
                        precondition_count
                    ),
                );
                if !plan.findings().is_empty() {
                    out_line(rendered, format_args!("\nFinding details"));
                    for finding in plan.findings() {
                        let marker = if finding.approval_required() {
                            '!'
                        } else {
                            'i'
                        };
                        out_line(rendered, format_args!("  {marker} {}", finding.code()));
                        write_wrapped_text(rendered, finding.message(), "    ", "    ");
                    }
                }
                out_line(rendered, format_args!("\nIdentities"));
                out_line(rendered, format_args!("  Plan        {}", plan.plan_id()));
                out_line(
                    rendered,
                    format_args!("  Graph       {}", plan.graph_digest()),
                );
                out_line(
                    rendered,
                    format_args!("  Approval    {}", plan.approval_digest()),
                );
                if let Some(expected) = plan.expected_head() {
                    out_line(rendered, format_args!("  Base        {expected}"));
                }
                if !plan.inputs().is_empty() {
                    out_line(rendered, format_args!("\nInputs"));
                    for input in plan.inputs() {
                        out_line(
                            rendered,
                            format_args!(
                                "  {}  {}  {}",
                                input_kind_name(input.kind()),
                                input.name(),
                                input.digest()
                            ),
                        );
                    }
                }
                if !plan.artifacts().is_empty() {
                    out_line(rendered, format_args!("\nArtifacts"));
                    for artifact in plan.artifacts() {
                        out_line(
                            rendered,
                            format_args!(
                                "  {}  {}  {}  {}",
                                artifact.id(),
                                human_bytes(artifact.byte_len()),
                                artifact.media_type(),
                                artifact.digest()
                            ),
                        );
                    }
                }
                if precondition_count > 0 {
                    out_line(rendered, format_args!("\nPreconditions"));
                    for operation in plan.operations() {
                        match operation {
                            PrepareOperationV1::AssertAbsent {
                                authority,
                                relative_path,
                            } => {
                                out_line(
                                    rendered,
                                    format_args!("  absent  {authority}:{relative_path}"),
                                );
                            }
                            PrepareOperationV1::AssertExact {
                                authority,
                                relative_path,
                                state,
                            } => {
                                out_line(
                                    rendered,
                                    format_args!(
                                        "  exact   {authority}:{relative_path}  {}",
                                        target_state_text(state)
                                    ),
                                );
                            }
                            _ => {}
                        }
                    }
                }
            }

            if show_next {
                out_line(rendered, format_args!("\nNext"));
                out_line(
                    rendered,
                    format_args!(
                        "  malm plan apply {}",
                        display_plan_unique(plan.plan_id(), plan_candidates, output.verbose())
                    ),
                );
            }
        },
    )
}

fn plan_json(plan: &PreparedDeploymentV1) -> serde_json::Value {
    serde_json::json!({
        "plan_id": plan.plan_id().as_str(),
        "namespace": plan.namespace().as_str(),
        "expected_head": plan.expected_head().map(Digest::as_str),
        "transition": lifecycle_transition_json(plan.transition()),
        "lifecycle": lifecycle_state_name(plan.lifecycle_state()),
        "restore_point": plan.restore_point().map(restore_point_json),
        "retention": retention_authority_json(plan.retention_authority()),
        "tracked_root": plan.tracking_review().map(prepared_tracking_json),
        "graph_digest": plan.graph_digest().as_str(),
        "inputs": plan.inputs().iter().map(|input| serde_json::json!({
            "kind": input_kind_name(input.kind()),
            "name": input.name(),
            "digest": input.digest().as_str(),
        })).collect::<Vec<_>>(),
        "transforms": plan.transforms().iter().map(transform_provenance_json).collect::<Vec<_>>(),
        "approval_digest": plan.approval_digest().as_str(),
        "operation_count": plan.operation_count(),
        "operations": plan.operations().iter().map(operation_json).collect::<Vec<_>>(),
        "artifacts": plan.artifacts().iter().map(|artifact| serde_json::json!({
            "id": artifact.id().as_str(),
            "digest": artifact.digest().as_str(),
            "byte_len": artifact.byte_len(),
            "media_type": artifact.media_type(),
        })).collect::<Vec<_>>(),
        "findings": plan.findings().iter().map(|finding| serde_json::json!({
            "id": finding.id().as_str(),
            "code": finding.code(),
            "message": finding.message(),
            "approval_required": finding.approval_required(),
        })).collect::<Vec<_>>(),
    })
}

fn advisory_summary(code: &str, messages: &[&str], verbose: bool) -> String {
    let count = messages.len();
    match code {
        "AUTHORING-EVALUATION-REUSED" => messages
            .last()
            .and_then(|message| {
                message
                    .strip_prefix("evaluation reused from plan ")?
                    .split_once(':')
                    .and_then(|(plan, _)| PreparedId::new(plan.to_owned()).ok())
                    .map(|plan| format!("Evaluation reused from {}.", display_plan(&plan, verbose)))
            })
            .unwrap_or_else(|| "A byte-identical evaluation was reused.".to_owned()),
        "AUTHORING-OVERLAY-APPLIED" if count == 1 => messages
            .first()
            .and_then(|message| message.split('`').nth(1))
            .map_or_else(
                || "A machine-local overlay was applied.".to_owned(),
                |name| format!("Machine-local overlay `{name}` applied."),
            ),
        "AUTHORING-OVERLAY-APPLIED" => {
            format!("{count} machine-local overlays applied.")
        }
        "AUTHORING-SYMLINK-SKIPPED" => {
            let symlinks = first_number(messages).unwrap_or(count);
            format!(
                "{symlinks} runtime-managed {} skipped.",
                plural(symlinks, "symlink", "symlinks")
            )
        }
        "AUTHORING-TRANSFORMS-CARRIED" => {
            "Output transforms reused from a byte-identical plan.".to_owned()
        }
        "AUTHORING-EXTERNAL-INCLUDE-SKIPPED" => {
            format!(
                "{count} external {} skipped.",
                plural(count, "include", "includes")
            )
        }
        "restore-missing" => format!(
            "{count} missing managed {} will be restored.",
            plural(count, "target", "targets")
        ),
        "restore-missing-directory" => format!(
            "{count} missing managed {} will be restored.",
            plural(count, "directory", "directories")
        ),
        "replace-existing" => format!(
            "{count} managed target {}.",
            plural(count, "replacement", "replacements")
        ),
        "remove-existing" => format!(
            "{count} managed target {}.",
            plural(count, "removal", "removals")
        ),
        _ if count == 1 => sentence_case(&compact_message(messages[0], 92)),
        _ => format!(
            "{} (+{} related {})",
            sentence_case(&compact_message(messages[0], 64)),
            count - 1,
            plural(count - 1, "advisory", "advisories")
        ),
    }
}

const fn plural<'a>(count: usize, singular: &'a str, plural: &'a str) -> &'a str {
    if count == 1 { singular } else { plural }
}

fn first_number(messages: &[&str]) -> Option<usize> {
    messages
        .iter()
        .flat_map(|message| message.split_whitespace())
        .find_map(|word| {
            word.trim_matches(|character: char| !character.is_ascii_digit())
                .parse()
                .ok()
        })
}

fn compact_message(message: &str, limit: usize) -> String {
    let compact = message.split_whitespace().collect::<Vec<_>>().join(" ");
    if compact.chars().count() <= limit {
        return compact;
    }
    let mut shortened = compact
        .chars()
        .take(limit.saturating_sub(3))
        .collect::<String>();
    if let Some(boundary) = shortened.rfind(' ') {
        shortened.truncate(boundary);
    }
    shortened.push_str("...");
    shortened
}

fn sentence_case(message: &str) -> String {
    let mut characters = message.chars();
    let Some(first) = characters.next() else {
        return String::new();
    };
    first.to_uppercase().chain(characters).collect()
}

fn write_wrapped_text(rendered: &mut String, text: &str, first: &str, continuation: &str) {
    const WIDTH: usize = 96;
    let mut prefix = first;
    let mut line = String::new();
    for word in text.split_whitespace() {
        let next_len = prefix.chars().count()
            + line.chars().count()
            + usize::from(!line.is_empty())
            + word.chars().count();
        if !line.is_empty() && next_len > WIDTH {
            out_line(rendered, format_args!("{prefix}{line}"));
            prefix = continuation;
            line.clear();
        }
        if !line.is_empty() {
            line.push(' ');
        }
        line.push_str(word);
    }
    if line.is_empty() {
        out_line(rendered, format_args!("{prefix}"));
    } else {
        out_line(rendered, format_args!("{prefix}{line}"));
    }
}

fn operation_change_line(
    plan: &PreparedDeploymentV1,
    operation: &PrepareOperationV1,
) -> Option<String> {
    match operation {
        PrepareOperationV1::EnsureDirectory {
            authority,
            relative_path,
            mode,
            replace_existing,
        } => Some(format!(
            "{} {authority}:{relative_path}  directory, {mode:04o}",
            change_marker(*replace_existing)
        )),
        PrepareOperationV1::PlaceFile {
            authority,
            relative_path,
            artifact_id,
            mode,
            replace_existing,
        } => {
            let size = plan
                .artifacts()
                .iter()
                .find(|artifact| artifact.id() == artifact_id)
                .map_or_else(
                    || "unknown size".to_owned(),
                    |artifact| human_bytes(artifact.byte_len()),
                );
            Some(format!(
                "{} {authority}:{relative_path}  file, {size}, {mode:04o}",
                change_marker(*replace_existing)
            ))
        }
        PrepareOperationV1::PlaceSymlink {
            authority,
            relative_path,
            replace_existing,
            ..
        } => Some(format!(
            "{} {authority}:{relative_path}  symlink",
            change_marker(*replace_existing)
        )),
        PrepareOperationV1::PlaceTree {
            authority,
            relative_path,
            replace_existing,
            ..
        } => Some(format!(
            "{} {authority}:{relative_path}  tree",
            change_marker(*replace_existing)
        )),
        PrepareOperationV1::RemoveLeaf {
            authority,
            relative_path,
        } => Some(format!("- {authority}:{relative_path}")),
        PrepareOperationV1::AssertAbsent { .. } | PrepareOperationV1::AssertExact { .. } => None,
    }
}

const fn change_marker(replace_existing: bool) -> char {
    if replace_existing { '~' } else { '+' }
}

fn human_bytes(bytes: u64) -> String {
    const KIB: f64 = 1024.0;
    const MIB: f64 = KIB * 1024.0;
    let bytes = bytes as f64;
    if bytes >= MIB {
        format!("{:.1} MiB", bytes / MIB)
    } else if bytes >= KIB {
        format!("{:.1} KiB", bytes / KIB)
    } else {
        format!("{} B", bytes as u64)
    }
}

fn lifecycle_transition_label(transition: &LifecycleTransitionViewV1) -> &'static str {
    match transition {
        LifecycleTransitionViewV1::Reconcile => "reconcile desired state",
        LifecycleTransitionViewV1::Disable => "disable namespace",
        LifecycleTransitionViewV1::Enable { .. } => "enable namespace",
        LifecycleTransitionViewV1::Checkout { .. } => "restore generation",
        LifecycleTransitionViewV1::RetentionAuthority => "update retention",
        LifecycleTransitionViewV1::NamespaceRemoval { .. } => "remove namespace",
    }
}

fn print_tracked_no_change(no_change: &TrackedRootNoChangeV1, output: &Output) -> Result<()> {
    output.emit(
        "up_to_date",
        || {
            serde_json::json!({
                "namespace": no_change.namespace().as_str(),
                "selected_head": no_change.generation().as_str(),
                "exact_revision": no_change.applied_revision(),
                "root_tree_digest": no_change.root_tree_digest().as_str(),
            })
        },
        |rendered| {
            out_line(
                rendered,
                format_args!("{}", output.heading("Already up to date", Tone::Success)),
            );
            out_line(
                rendered,
                format_args!("  Namespace  {}", no_change.namespace()),
            );
            out_line(
                rendered,
                format_args!(
                    "  Generation {}",
                    display_digest(
                        IdDomain::Generation,
                        no_change.generation(),
                        output.verbose()
                    )
                ),
            );
            out_line(
                rendered,
                format_args!("  Revision   {}", no_change.applied_revision()),
            );
            if output.verbose() {
                out_line(
                    rendered,
                    format_args!("  Tree       {}", no_change.root_tree_digest()),
                );
            }
        },
    )?;
    Ok(())
}

const fn lifecycle_state_name(state: LifecycleStateViewV1) -> &'static str {
    match state {
        LifecycleStateViewV1::Enabled => "enabled",
        LifecycleStateViewV1::Disabled => "disabled",
    }
}

fn lifecycle_transition_json(transition: &LifecycleTransitionViewV1) -> serde_json::Value {
    match transition {
        LifecycleTransitionViewV1::Reconcile => serde_json::json!({ "kind": "reconcile" }),
        LifecycleTransitionViewV1::Disable => serde_json::json!({ "kind": "disable" }),
        LifecycleTransitionViewV1::Enable { restore_generation } => serde_json::json!({
            "kind": "enable",
            "restore_generation": restore_generation.as_str(),
        }),
        LifecycleTransitionViewV1::Checkout { source_generation } => serde_json::json!({
            "kind": "checkout",
            "source_generation": source_generation.as_str(),
        }),
        LifecycleTransitionViewV1::RetentionAuthority => {
            serde_json::json!({ "kind": "retention_authority" })
        }
        LifecycleTransitionViewV1::NamespaceRemoval { drops_history } => serde_json::json!({
            "kind": "namespace_removal",
            "drops_history": drops_history,
        }),
    }
}

fn tracked_root_json(tracked: &TrackedRootInspectionV1) -> serde_json::Value {
    serde_json::json!({
        "moving_selector": tracked.moving_selector(),
        "applied_revision": tracked.applied_revision(),
        "root_tree_digest": tracked.root_tree_digest().as_str(),
    })
}

fn prepared_tracking_json(tracked: &PreparedTrackingReviewV1) -> serde_json::Value {
    serde_json::json!({
        "source_locator": tracked.source_locator(),
        "moving_selector": tracked.moving_selector(),
        "applied_revision": tracked.applied_revision(),
        "root_tree_digest": tracked.root_tree_digest().as_str(),
        "source_subdir": tracked.source_subdir(),
        "config_entry_point": tracked.config_entry_point(),
        "selected_profile": tracked.selected_profile().as_str(),
        "target_authority": tracked.target_authority().as_str(),
        "acquisition_grants": tracked.acquisition_grants().iter().map(|grant| serde_json::json!({
            "kind": match grant.kind() {
                PreparedTrackingAcquisitionKindV1::LocalSource => "local_source",
                PreparedTrackingAcquisitionKindV1::GitSource => "git_source",
            },
            "locator": grant.locator(),
        })).collect::<Vec<_>>(),
        "component_grants": tracked.component_grants().iter().map(Digest::as_str).collect::<Vec<_>>(),
    })
}

fn restore_point_json(restore: &RestorePointInspectionV1) -> serde_json::Value {
    serde_json::json!({
        "generation": restore.generation().as_str(),
        "lifecycle": lifecycle_state_name(restore.lifecycle()),
        "desired_snapshot_digest": restore.desired_snapshot_digest().as_str(),
        "tracked_root": restore.tracked_root().map(tracked_root_json),
    })
}

fn retention_object_json(object: &RetentionObjectV1) -> serde_json::Value {
    match object {
        RetentionObjectV1::PreparedPlan { plan_id } => serde_json::json!({
            "kind": "prepared_plan",
            "plan_id": plan_id.as_str(),
        }),
        RetentionObjectV1::StateGeneration { digest } => serde_json::json!({
            "kind": "state_generation",
            "digest": digest.as_str(),
        }),
        RetentionObjectV1::ArtifactBlob { digest } => serde_json::json!({
            "kind": "artifact_blob",
            "digest": digest.as_str(),
        }),
        RetentionObjectV1::PackObject { digest } => serde_json::json!({
            "kind": "pack_object",
            "digest": digest.as_str(),
        }),
        RetentionObjectV1::CanonicalFile { digest } => serde_json::json!({
            "kind": "canonical_file",
            "digest": digest.as_str(),
        }),
        RetentionObjectV1::CanonicalSymlink { digest } => serde_json::json!({
            "kind": "canonical_symlink",
            "digest": digest.as_str(),
        }),
        RetentionObjectV1::CanonicalTree { digest } => serde_json::json!({
            "kind": "canonical_tree",
            "digest": digest.as_str(),
        }),
    }
}

fn retention_object_label(
    object: &RetentionObjectV1,
    authority: &RetentionAuthorityInspectionV1,
    verbose: bool,
) -> String {
    match object {
        RetentionObjectV1::PreparedPlan { plan_id } => {
            let candidates = authority
                .explicit_pins()
                .iter()
                .filter_map(|pin| match pin {
                    RetentionObjectV1::PreparedPlan { plan_id } => Some(plan_id.clone()),
                    _ => None,
                })
                .collect::<Vec<_>>();
            display_plan_unique(plan_id, &candidates, verbose)
        }
        RetentionObjectV1::StateGeneration { digest } => display_digest_unique(
            IdDomain::Generation,
            digest,
            &retained_generation_candidates(authority),
            verbose,
        ),
        RetentionObjectV1::ArtifactBlob { digest } => display_retained_digest(
            IdDomain::Blob,
            digest,
            authority,
            |pin| match pin {
                RetentionObjectV1::ArtifactBlob { digest } => Some(digest.clone()),
                _ => None,
            },
            verbose,
        ),
        RetentionObjectV1::PackObject { digest } => display_retained_digest(
            IdDomain::Pack,
            digest,
            authority,
            |pin| match pin {
                RetentionObjectV1::PackObject { digest } => Some(digest.clone()),
                _ => None,
            },
            verbose,
        ),
        RetentionObjectV1::CanonicalFile { digest } => display_retained_digest(
            IdDomain::File,
            digest,
            authority,
            |pin| match pin {
                RetentionObjectV1::CanonicalFile { digest } => Some(digest.clone()),
                _ => None,
            },
            verbose,
        ),
        RetentionObjectV1::CanonicalSymlink { digest } => display_retained_digest(
            IdDomain::Symlink,
            digest,
            authority,
            |pin| match pin {
                RetentionObjectV1::CanonicalSymlink { digest } => Some(digest.clone()),
                _ => None,
            },
            verbose,
        ),
        RetentionObjectV1::CanonicalTree { digest } => display_retained_digest(
            IdDomain::Tree,
            digest,
            authority,
            |pin| match pin {
                RetentionObjectV1::CanonicalTree { digest } => Some(digest.clone()),
                _ => None,
            },
            verbose,
        ),
    }
}

fn display_retained_digest(
    domain: IdDomain,
    digest: &Digest,
    authority: &RetentionAuthorityInspectionV1,
    select: impl Fn(&RetentionObjectV1) -> Option<Digest>,
    verbose: bool,
) -> String {
    let candidates = authority
        .explicit_pins()
        .iter()
        .filter_map(select)
        .collect::<Vec<_>>();
    display_digest_unique(domain, digest, &candidates, verbose)
}

fn retained_generation_candidates(authority: &RetentionAuthorityInspectionV1) -> Vec<Digest> {
    authority
        .restore_points()
        .iter()
        .map(|point| point.generation().clone())
        .chain(
            authority
                .explicit_pins()
                .iter()
                .filter_map(|pin| match pin {
                    RetentionObjectV1::StateGeneration { digest } => Some(digest.clone()),
                    _ => None,
                }),
        )
        .collect()
}

fn retention_authority_json(authority: &RetentionAuthorityInspectionV1) -> serde_json::Value {
    serde_json::json!({
        "history_generations": authority.history_generations(),
        "restore_points": authority.restore_points().iter().map(restore_point_json).collect::<Vec<_>>(),
        "explicit_pins": authority.explicit_pins().iter().map(retention_object_json).collect::<Vec<_>>(),
    })
}

fn write_retention_authority(
    rendered: &mut String,
    authority: &RetentionAuthorityInspectionV1,
    show_entries: bool,
    verbose_ids: bool,
) {
    out_line(
        rendered,
        format_args!(
            "  Retention   {} generations, {} restore points, {} pins",
            authority.history_generations(),
            authority.restore_points().len(),
            authority.explicit_pins().len()
        ),
    );
    if show_entries {
        let generations = retained_generation_candidates(authority);
        for restore in authority.restore_points() {
            write_restore_point(rendered, restore, &generations, verbose_ids);
        }
        for pin in authority.explicit_pins() {
            out_line(
                rendered,
                format_args!(
                    "    Pin       {}",
                    retention_object_label(pin, authority, verbose_ids)
                ),
            );
        }
    }
}

fn write_restore_point(
    rendered: &mut String,
    restore: &RestorePointInspectionV1,
    generation_candidates: &[Digest],
    verbose_ids: bool,
) {
    out_line(
        rendered,
        format_args!(
            "    Restore   {}  {}  snapshot {}",
            display_digest_unique(
                IdDomain::Generation,
                restore.generation(),
                generation_candidates,
                verbose_ids
            ),
            lifecycle_state_name(restore.lifecycle()),
            restore.desired_snapshot_digest()
        ),
    );
    if let Some(tracked) = restore.tracked_root() {
        out_line(
            rendered,
            format_args!(
                "      Tracking {} -> {}  tree {}",
                tracked.moving_selector(),
                tracked.applied_revision(),
                tracked.root_tree_digest()
            ),
        );
    }
}

fn write_tracked_root(
    rendered: &mut String,
    tracked: Option<&TrackedRootInspectionV1>,
    show_tree: bool,
    verbose_ids: bool,
) {
    match tracked {
        Some(tracked) => {
            out_line(
                rendered,
                format_args!(
                    "  Tracking    {} -> {}",
                    tracked.moving_selector(),
                    tracked.applied_revision()
                ),
            );
            if show_tree {
                out_line(
                    rendered,
                    format_args!(
                        "  Root tree   {}",
                        display_digest(IdDomain::Tree, tracked.root_tree_digest(), verbose_ids)
                    ),
                );
            }
        }
        None => {
            out_line(rendered, format_args!("  Tracking    none"));
        }
    }
}

fn generation_json(generation: &GenerationInspectionV1) -> serde_json::Value {
    serde_json::json!({
        "namespace": generation.namespace().as_str(),
        "generation": generation.generation().as_str(),
        "lifecycle": lifecycle_state_name(generation.lifecycle()),
        "desired_snapshot_digest": generation.desired_snapshot_digest().as_str(),
        "target_count": generation.target_count(),
        "present_target_count": generation.present_target_count(),
        "absent_target_count": generation.absent_target_count(),
        "plan_id": generation.plan_id().as_str(),
        "predecessor": generation.predecessor().map(Digest::as_str),
        "tracked_root": generation.tracked_root().map(tracked_root_json),
        "transition": lifecycle_transition_json(generation.transition()),
        "restore_point": generation.restore_point().map(restore_point_json),
        "retention": retention_authority_json(generation.retention_authority()),
    })
}

fn print_generation(
    generation: &GenerationInspectionV1,
    candidates: &[Digest],
    output: &Output,
) -> Result<()> {
    output.emit(
        "inspected",
        || generation_json(generation),
        |rendered| {
            out_line(
                rendered,
                format_args!("{}", output.heading("Generation", Tone::Neutral)),
            );
            out_line(
                rendered,
                format_args!("  Namespace   {}", generation.namespace()),
            );
            out_line(
                rendered,
                format_args!(
                    "  Generation  {}",
                    display_digest_unique(
                        IdDomain::Generation,
                        generation.generation(),
                        candidates,
                        output.verbose()
                    )
                ),
            );
            out_line(
                rendered,
                format_args!(
                    "  State       {}",
                    lifecycle_state_name(generation.lifecycle())
                ),
            );
            out_line(
                rendered,
                format_args!(
                    "  Transition  {}",
                    lifecycle_transition_label(generation.transition())
                ),
            );
            out_line(
                rendered,
                format_args!(
                    "  Targets     {} total, {} present, {} absent",
                    generation.target_count(),
                    generation.present_target_count(),
                    generation.absent_target_count()
                ),
            );
            out_line(
                rendered,
                format_args!(
                    "  Plan        {}",
                    display_plan(generation.plan_id(), output.verbose())
                ),
            );
            write_tracked_root(
                rendered,
                generation.tracked_root(),
                output.verbose(),
                output.verbose(),
            );
            write_retention_authority(
                rendered,
                generation.retention_authority(),
                output.verbose(),
                output.verbose(),
            );
            if output.verbose() {
                out_line(
                    rendered,
                    format_args!("  Desired     {}", generation.desired_snapshot_digest()),
                );
                match generation.predecessor() {
                    Some(predecessor) => {
                        out_line(rendered, format_args!("  Predecessor {predecessor}"));
                    }
                    None => {
                        out_line(rendered, format_args!("  Predecessor none"));
                    }
                }
            }
        },
    )?;
    Ok(())
}

fn print_catalog(catalog: &CatalogInspectionV1, output: &Output) -> Result<()> {
    output.emit(
        "listed",
        || {
            serde_json::json!({
                "digest": catalog.digest().as_str(),
                "namespaces": catalog.namespaces().iter().map(|entry| serde_json::json!({
                    "namespace": entry.namespace().as_str(),
                    "generation": entry.generation().as_str(),
                })).collect::<Vec<_>>(),
                "decoded_bytes": catalog.decoded_bytes(),
            })
        },
        |rendered| {
            out_line(
                rendered,
                format_args!(
                    "{}",
                    output.heading(
                        &format!("Namespaces  {}", catalog.namespaces().len()),
                        Tone::Neutral
                    )
                ),
            );
            let candidates = catalog
                .namespaces()
                .iter()
                .map(|entry| entry.generation().clone())
                .collect::<Vec<_>>();
            for entry in catalog.namespaces() {
                out_line(
                    rendered,
                    format_args!(
                        "  {:<20} {}",
                        entry.namespace(),
                        display_digest_unique(
                            IdDomain::Generation,
                            entry.generation(),
                            &candidates,
                            output.verbose()
                        )
                    ),
                );
            }
            if output.verbose() {
                out_line(rendered, format_args!("\n  Index   {}", catalog.digest()));
                out_line(
                    rendered,
                    format_args!("  Decoded {}", human_bytes(catalog.decoded_bytes())),
                );
            }
        },
    )?;
    Ok(())
}

fn print_namespace(namespace: &NamespaceInspectionV1, output: &Output) -> Result<()> {
    output.emit(
        "inspected",
        || {
            serde_json::json!({
                "namespace": namespace.namespace().as_str(),
                "head": namespace.head().map(Digest::as_str),
                "generation": namespace.generation().map(generation_json),
                "decoded_bytes": namespace.decoded_bytes(),
            })
        },
        |rendered| {
            let title = match namespace.head() {
                Some(_) => format!("Namespace {}", namespace.namespace()),
                None => format!("Namespace {} is not deployed", namespace.namespace()),
            };
            out_line(
                rendered,
                format_args!("{}", output.heading(&title, Tone::Neutral)),
            );
            if let Some(generation) = namespace.generation() {
                out_line(
                    rendered,
                    format_args!(
                        "  State       {}",
                        lifecycle_state_name(generation.lifecycle())
                    ),
                );
                out_line(
                    rendered,
                    format_args!(
                        "  Generation  {}",
                        display_digest(
                            IdDomain::Generation,
                            generation.generation(),
                            output.verbose()
                        )
                    ),
                );
                out_line(
                    rendered,
                    format_args!("  Targets     {}", generation.target_count()),
                );
                out_line(
                    rendered,
                    format_args!(
                        "  Plan        {}",
                        display_plan(generation.plan_id(), output.verbose())
                    ),
                );
                write_tracked_root(
                    rendered,
                    generation.tracked_root(),
                    output.verbose(),
                    output.verbose(),
                );
                write_retention_authority(
                    rendered,
                    generation.retention_authority(),
                    output.verbose(),
                    output.verbose(),
                );
            }
            if output.verbose() {
                out_line(
                    rendered,
                    format_args!("  Decoded     {}", human_bytes(namespace.decoded_bytes())),
                );
            }
        },
    )?;
    Ok(())
}

fn print_history(history: &NamespaceHistoryV1, output: &Output) -> Result<()> {
    output.emit("listed", || serde_json::json!({
                "namespace": history.namespace().as_str(),
                "head": history.head().map(Digest::as_str),
                "generations": history.generations().iter().map(generation_json).collect::<Vec<_>>(),
                "decoded_bytes": history.decoded_bytes(),
            }), |rendered| {
        out_line(rendered, format_args!("{}",
            output.heading(
                &format!("History for {}", history.namespace()),
                Tone::Neutral
            )));
        if history.generations().is_empty() {
            out_line(rendered, format_args!("  No retained generations."));
        } else {
            let candidates = history
                .generations()
                .iter()
                .map(|generation| generation.generation().clone())
                .collect::<Vec<_>>();
            for (index, generation) in history.generations().iter().enumerate() {
                let reference = if index == 0 {
                    "HEAD".to_owned()
                } else {
                    format!("HEAD~{index}")
                };
                out_line(rendered, format_args!("  {:<7} {}  {:<8}  {}  {} targets",
                    reference,
                    display_digest_unique(
                        IdDomain::Generation,
                        generation.generation(),
                        &candidates,
                        output.verbose()
                    ),
                    lifecycle_state_name(generation.lifecycle()),
                    lifecycle_transition_label(generation.transition()),
                    generation.target_count()));
            }
        }
        if output.verbose() {
            out_line(rendered, format_args!("\n  Decoded  {}",
                human_bytes(history.decoded_bytes())));
        }
    })?;
    Ok(())
}

fn desired_target_state_json(state: &DesiredTargetStateInspectionV1) -> serde_json::Value {
    match state {
        DesiredTargetStateInspectionV1::File {
            digest,
            byte_len,
            mode,
        } => serde_json::json!({
            "kind": "file",
            "digest": digest.as_ref().map(Digest::as_str),
            "byte_len": byte_len,
            "mode": mode,
        }),
        DesiredTargetStateInspectionV1::Directory { mode } => serde_json::json!({
            "kind": "directory",
            "mode": mode,
        }),
        DesiredTargetStateInspectionV1::Symlink { object } => serde_json::json!({
            "kind": "symlink",
            "object": object.as_ref().map(Digest::as_str),
        }),
        DesiredTargetStateInspectionV1::Tree {
            tree,
            archive_provenance,
        } => serde_json::json!({
            "kind": "tree",
            "tree": tree.as_ref().map(Digest::as_str),
            "archive_provenance": archive_provenance.as_ref().map(|provenance| serde_json::json!({
                "payload": provenance.payload().as_str(),
                "decoder": provenance.decoder(),
            })),
        }),
    }
}

fn desired_target_state_text(state: &DesiredTargetStateInspectionV1, verbose: bool) -> String {
    match state {
        DesiredTargetStateInspectionV1::File {
            digest,
            byte_len,
            mode,
        } => {
            let digest = digest.as_ref().map_or_else(
                || "none".to_owned(),
                |digest| display_digest(IdDomain::File, digest, verbose),
            );
            format!(
                "file digest={} byte_len={} mode={}",
                digest,
                byte_len.map_or_else(|| "none".to_owned(), |value| value.to_string()),
                mode.map_or_else(|| "none".to_owned(), |value| format!("{value:04o}"))
            )
        }
        DesiredTargetStateInspectionV1::Directory { mode } => format!(
            "directory mode={}",
            mode.map_or_else(|| "none".to_owned(), |value| format!("{value:04o}"))
        ),
        DesiredTargetStateInspectionV1::Symlink { object } => format!(
            "symlink object={}",
            object.as_ref().map_or_else(
                || "none".to_owned(),
                |digest| display_digest(IdDomain::Symlink, digest, verbose)
            )
        ),
        DesiredTargetStateInspectionV1::Tree {
            tree,
            archive_provenance,
        } => {
            let tree = tree.as_ref().map_or_else(
                || "none".to_owned(),
                |digest| display_digest(IdDomain::Tree, digest, verbose),
            );
            format!(
                "tree tree={} archive={}",
                tree,
                archive_provenance
                    .as_ref()
                    .map_or_else(|| "none".to_owned(), archive_provenance_text)
            )
        }
    }
}

fn print_desired_snapshot(
    snapshot: &DesiredSnapshotInspectionV1,
    generation_candidates: &[Digest],
    output: &Output,
) -> Result<()> {
    output.emit(
        "inspected",
        || {
            serde_json::json!({
                "namespace": snapshot.namespace().as_str(),
                "generation": snapshot.generation().as_str(),
                "digest": snapshot.digest().as_str(),
                "targets": snapshot.targets().iter().map(|target| serde_json::json!({
                    "authority": target.authority().as_str(),
                    "relative_path": target.relative_path(),
                    "state": desired_target_state_json(target.state()),
                })).collect::<Vec<_>>(),
                "decoded_bytes": snapshot.decoded_bytes(),
            })
        },
        |rendered| {
            out_line(
                rendered,
                format_args!(
                    "{}",
                    output.heading(
                        &format!("Desired state  {} targets", snapshot.targets().len()),
                        Tone::Neutral
                    )
                ),
            );
            out_line(
                rendered,
                format_args!("  Namespace   {}", snapshot.namespace()),
            );
            out_line(
                rendered,
                format_args!(
                    "  Generation  {}",
                    display_digest_unique(
                        IdDomain::Generation,
                        snapshot.generation(),
                        generation_candidates,
                        output.verbose()
                    )
                ),
            );
            for target in snapshot.targets() {
                out_line(
                    rendered,
                    format_args!(
                        "  {}:{}  {}",
                        target.authority(),
                        target.relative_path(),
                        desired_target_state_text(target.state(), output.verbose())
                    ),
                );
            }
            if output.verbose() {
                out_line(
                    rendered,
                    format_args!("\n  Snapshot  {}", snapshot.digest()),
                );
                out_line(
                    rendered,
                    format_args!("  Decoded   {}", human_bytes(snapshot.decoded_bytes())),
                );
            }
        },
    )?;
    Ok(())
}

fn canonical_entry_json(kind: &CanonicalTreeEntryKindInspectionV1) -> serde_json::Value {
    match kind {
        CanonicalTreeEntryKindInspectionV1::File { digest, byte_len } => serde_json::json!({
            "kind": "file",
            "digest": digest.as_str(),
            "byte_len": byte_len,
        }),
        CanonicalTreeEntryKindInspectionV1::Directory { digest } => serde_json::json!({
            "kind": "directory",
            "digest": digest.as_str(),
        }),
        CanonicalTreeEntryKindInspectionV1::Symlink { digest } => serde_json::json!({
            "kind": "symlink",
            "digest": digest.as_str(),
        }),
    }
}

fn canonical_entry_text(
    kind: &CanonicalTreeEntryKindInspectionV1,
    files: &[Digest],
    symlinks: &[Digest],
    trees: &[Digest],
    verbose: bool,
) -> String {
    match kind {
        CanonicalTreeEntryKindInspectionV1::File { digest, byte_len } => {
            format!(
                "file digest={} byte_len={byte_len}",
                display_digest_unique(IdDomain::File, digest, files, verbose)
            )
        }
        CanonicalTreeEntryKindInspectionV1::Directory { digest } => {
            format!(
                "directory digest={}",
                display_digest_unique(IdDomain::Tree, digest, trees, verbose)
            )
        }
        CanonicalTreeEntryKindInspectionV1::Symlink { digest } => {
            format!(
                "symlink digest={}",
                display_digest_unique(IdDomain::Symlink, digest, symlinks, verbose)
            )
        }
    }
}

fn print_canonical_tree(
    tree: &CanonicalTreeInspectionV1,
    tree_inventory: &[Digest],
    output: &Output,
) -> Result<()> {
    output.emit(
        "inspected",
        || {
            serde_json::json!({
                "tree": tree.tree().as_str(),
                "root_mode": tree.root_mode(),
                "entries": tree.entries().iter().map(|entry| serde_json::json!({
                    "relative_path": entry.relative_path(),
                    "mode": entry.mode(),
                    "object": canonical_entry_json(entry.kind()),
                })).collect::<Vec<_>>(),
                "decoded_bytes": tree.decoded_bytes(),
            })
        },
        |rendered| {
            out_line(
                rendered,
                format_args!(
                    "{}",
                    output.heading(
                        &format!("Canonical tree  {} entries", tree.entries().len()),
                        Tone::Neutral
                    )
                ),
            );
            out_line(
                rendered,
                format_args!(
                    "  Tree  {}",
                    display_digest_unique(
                        IdDomain::Tree,
                        tree.tree(),
                        tree_inventory,
                        output.verbose()
                    )
                ),
            );
            out_line(rendered, format_args!("  Mode  {:04o}", tree.root_mode()));
            let files = tree
                .entries()
                .iter()
                .filter_map(|entry| match entry.kind() {
                    CanonicalTreeEntryKindInspectionV1::File { digest, .. } => Some(digest.clone()),
                    _ => None,
                })
                .collect::<Vec<_>>();
            let symlinks = tree
                .entries()
                .iter()
                .filter_map(|entry| match entry.kind() {
                    CanonicalTreeEntryKindInspectionV1::Symlink { digest } => Some(digest.clone()),
                    _ => None,
                })
                .collect::<Vec<_>>();
            let trees = tree
                .entries()
                .iter()
                .filter_map(|entry| match entry.kind() {
                    CanonicalTreeEntryKindInspectionV1::Directory { digest } => {
                        Some(digest.clone())
                    }
                    _ => None,
                })
                .chain(tree_inventory.iter().cloned())
                .collect::<Vec<_>>();
            for entry in tree.entries() {
                out_line(
                    rendered,
                    format_args!(
                        "  {}  {}  mode={:04o}",
                        entry.relative_path(),
                        canonical_entry_text(
                            entry.kind(),
                            &files,
                            &symlinks,
                            &trees,
                            output.verbose()
                        ),
                        entry.mode()
                    ),
                );
            }
            if output.verbose() {
                out_line(
                    rendered,
                    format_args!("\n  Decoded  {}", human_bytes(tree.decoded_bytes())),
                );
            }
        },
    )?;
    Ok(())
}

fn print_artifact_metadata(
    artifact: &ArtifactMetadataInspectionV1,
    plan_candidates: &[PreparedId],
    output: &Output,
) -> Result<()> {
    let descriptor = artifact.descriptor();
    output.emit(
        "inspected",
        || {
            serde_json::json!({
                "plan_id": artifact.plan_id().as_str(),
                "descriptor": {
                    "id": descriptor.id().as_str(),
                    "digest": descriptor.digest().as_str(),
                    "byte_len": descriptor.byte_len(),
                    "media_type": descriptor.media_type(),
                },
                "decoded_bytes": artifact.decoded_bytes(),
            })
        },
        |rendered| {
            out_line(
                rendered,
                format_args!("{}", output.heading("Artifact", Tone::Neutral)),
            );
            out_line(
                rendered,
                format_args!(
                    "  Plan        {}",
                    display_plan_unique(artifact.plan_id(), plan_candidates, output.verbose())
                ),
            );
            out_line(rendered, format_args!("  Artifact    {}", descriptor.id()));
            out_line(
                rendered,
                format_args!("  Size        {}", human_bytes(descriptor.byte_len())),
            );
            out_line(
                rendered,
                format_args!("  Media type  {}", descriptor.media_type()),
            );
            out_line(
                rendered,
                format_args!(
                    "  Digest      {}",
                    display_digest(IdDomain::Blob, descriptor.digest(), output.verbose())
                ),
            );
            if output.verbose() {
                out_line(
                    rendered,
                    format_args!("  Decoded     {}", human_bytes(artifact.decoded_bytes())),
                );
            }
        },
    )?;
    Ok(())
}

fn print_captured_inputs(
    inputs: &CapturedInputsInspectionV1,
    plan_candidates: &[PreparedId],
    output: &Output,
) -> Result<()> {
    output.emit(
        "inspected",
        || {
            serde_json::json!({
                "plan_id": inputs.plan_id().as_str(),
                "graph_digest": inputs.graph_digest().as_str(),
                "inputs": inputs.inputs().iter().map(|input| serde_json::json!({
                    "kind": input_kind_name(input.kind()),
                    "name": input.name(),
                    "digest": input.digest().as_str(),
                })).collect::<Vec<_>>(),
                "decoded_bytes": inputs.decoded_bytes(),
            })
        },
        |rendered| {
            out_line(
                rendered,
                format_args!(
                    "{}",
                    output.heading(
                        &format!("Captured inputs  {}", inputs.inputs().len()),
                        Tone::Neutral
                    )
                ),
            );
            out_line(
                rendered,
                format_args!(
                    "  Plan   {}",
                    display_plan_unique(inputs.plan_id(), plan_candidates, output.verbose())
                ),
            );
            out_line(
                rendered,
                format_args!(
                    "  Graph  {}",
                    display_digest(IdDomain::Graph, inputs.graph_digest(), output.verbose())
                ),
            );
            for input in inputs.inputs() {
                out_line(
                    rendered,
                    format_args!(
                        "  {:<10} {}  {}",
                        input_kind_name(input.kind()),
                        input.name(),
                        input.digest()
                    ),
                );
            }
            if output.verbose() {
                out_line(
                    rendered,
                    format_args!("\n  Decoded  {}", human_bytes(inputs.decoded_bytes())),
                );
            }
        },
    )?;
    Ok(())
}

fn transform_provenance_json(transform: &crate::PrepareTransformProvenanceV1) -> serde_json::Value {
    let implementation = match transform.implementation() {
        PrepareTransformImplementationV1::BuiltIn { implementation } => serde_json::json!({
            "kind": "built-in",
            "implementation": implementation,
        }),
        PrepareTransformImplementationV1::Component {
            pack_node_id,
            pack_content_digest,
            component_path,
            component_digest,
            interface_version,
            execution_profile_digest,
        } => serde_json::json!({
            "kind": "component",
            "pack_node_id": pack_node_id.to_string(),
            "pack_content_digest": pack_content_digest.as_str(),
            "component_path": component_path,
            "component_digest": component_digest.as_str(),
            "interface_version": interface_version,
            "execution_profile_digest": execution_profile_digest.as_str(),
        }),
    };
    serde_json::json!({
        "name": transform.name(),
        "implementation": implementation,
        "request_digest": transform.request_digest().as_str(),
        "document_digest": transform.document_digest().as_str(),
        "resources": transform.resources().iter().map(|resource| serde_json::json!({
            "name": resource.name(),
            "digest": resource.digest().as_str(),
        })).collect::<Vec<_>>(),
        "response_digest": transform.response_digest().as_str(),
        "diagnostics": transform.diagnostics().iter().map(transform_diagnostic_json).collect::<Vec<_>>(),
    })
}

fn transform_diagnostic_json(diagnostic: &PrepareTransformDiagnosticV1) -> serde_json::Value {
    let primary = diagnostic.primary().map(|location| match location {
        PrepareTransformDiagnosticLocationV1::Source(source) => serde_json::json!({
            "kind": "source",
            "authority_label": source.authority_label().as_str(),
            "authority_identity": source.authority_identity().as_str(),
            "document_path": source.document_path(),
            "start": source.start(),
            "end": source.end(),
        }),
        PrepareTransformDiagnosticLocationV1::Output(output) => serde_json::json!({
            "kind": "output",
            "start": output.start(),
            "end": output.end(),
        }),
    });
    serde_json::json!({
        "severity": transform_diagnostic_severity_name(diagnostic.severity()),
        "code": diagnostic.code(),
        "message": diagnostic.message(),
        "primary": primary,
        "notes": diagnostic.notes(),
    })
}

const fn transform_diagnostic_severity_name(
    severity: PrepareTransformDiagnosticSeverityV1,
) -> &'static str {
    match severity {
        PrepareTransformDiagnosticSeverityV1::Error => "error",
        PrepareTransformDiagnosticSeverityV1::Warning => "warning",
        PrepareTransformDiagnosticSeverityV1::Info => "info",
    }
}

fn transform_diagnostic_location_text(
    location: Option<&PrepareTransformDiagnosticLocationV1>,
) -> String {
    match location {
        Some(PrepareTransformDiagnosticLocationV1::Source(source)) => format!(
            "source:{}@{}:{}:{}..{}",
            source.authority_label(),
            source.authority_identity(),
            source.document_path(),
            source.start(),
            source.end()
        ),
        Some(PrepareTransformDiagnosticLocationV1::Output(output)) => {
            format!("output:{}..{}", output.start(), output.end())
        }
        None => "none".to_owned(),
    }
}

fn write_transform(rendered: &mut String, transform: &crate::PrepareTransformProvenanceV1) {
    match transform.implementation() {
        PrepareTransformImplementationV1::BuiltIn { implementation } => {
            out_line(
                rendered,
                format_args!("  {}  built-in:{implementation}", transform.name()),
            );
        }
        PrepareTransformImplementationV1::Component {
            pack_node_id,
            pack_content_digest,
            component_path,
            component_digest,
            interface_version,
            execution_profile_digest,
        } => {
            out_line(rendered, format_args!("  {}  component", transform.name()));
            out_line(rendered, format_args!("    Path       {component_path}"));
            out_line(rendered, format_args!("    Component  {component_digest}"));
            out_line(rendered, format_args!("    Interface  {interface_version}"));
            out_line(rendered, format_args!("    Pack node  {pack_node_id}"));
            out_line(
                rendered,
                format_args!("    Pack       {pack_content_digest}"),
            );
            out_line(
                rendered,
                format_args!("    Profile    {execution_profile_digest}"),
            );
        }
    }
    out_line(
        rendered,
        format_args!("    Request    {}", transform.request_digest()),
    );
    out_line(
        rendered,
        format_args!("    Document   {}", transform.document_digest()),
    );
    out_line(
        rendered,
        format_args!("    Response   {}", transform.response_digest()),
    );
    for resource in transform.resources() {
        out_line(
            rendered,
            format_args!("    Resource   {}  {}", resource.name(), resource.digest()),
        );
    }
    for diagnostic in transform.diagnostics() {
        out_line(
            rendered,
            format_args!(
                "    {}[{}]: {}",
                transform_diagnostic_severity_name(diagnostic.severity()),
                diagnostic.code(),
                diagnostic.message()
            ),
        );
        out_line(
            rendered,
            format_args!(
                "      At {}",
                transform_diagnostic_location_text(diagnostic.primary())
            ),
        );
        for note in diagnostic.notes() {
            out_line(rendered, format_args!("      Note: {note}"));
        }
    }
}

fn print_transform_provenance(
    provenance: &TransformProvenanceInspectionV1,
    plan_candidates: &[PreparedId],
    output: &Output,
) -> Result<()> {
    output.emit("inspected", || serde_json::json!({
                "plan_id": provenance.plan_id().as_str(),
                "transforms": provenance.transforms().iter().map(transform_provenance_json).collect::<Vec<_>>(),
                "decoded_bytes": provenance.decoded_bytes(),
            }), |rendered| {
        out_line(rendered, format_args!("{}",
            output.heading(
                &format!("Transforms  {}", provenance.transforms().len()),
                Tone::Neutral
            )));
        out_line(rendered, format_args!("  Plan  {}",
            display_plan_unique(provenance.plan_id(), plan_candidates, output.verbose())));
        if provenance.transforms().is_empty() {
            out_line(rendered, format_args!("  No transforms were executed."));
        } else {
            for transform in provenance.transforms() {
                write_transform(rendered, transform);
            }
        }
        if output.verbose() {
            out_line(rendered, format_args!("\n  Decoded  {}",
                human_bytes(provenance.decoded_bytes())));
        }
    })?;
    Ok(())
}

fn print_retention(
    retention: &RetentionInspectionV1,
    generation_candidates: &[Digest],
    output: &Output,
) -> Result<()> {
    output.emit(
        "inspected",
        || {
            serde_json::json!({
                "namespace": retention.namespace().as_str(),
                "generation": retention.generation().as_str(),
                "authority": retention_authority_json(retention.authority()),
            })
        },
        |rendered| {
            out_line(
                rendered,
                format_args!("{}", output.heading("Retention", Tone::Neutral)),
            );
            out_line(
                rendered,
                format_args!("  Namespace   {}", retention.namespace()),
            );
            out_line(
                rendered,
                format_args!(
                    "  Generation  {}",
                    display_digest_unique(
                        IdDomain::Generation,
                        retention.generation(),
                        generation_candidates,
                        output.verbose()
                    )
                ),
            );
            write_retention_authority(rendered, retention.authority(), true, output.verbose());
        },
    )?;
    Ok(())
}

fn print_tracking(
    tracking: &TrackingInspectionV1,
    generation_candidates: &[Digest],
    output: &Output,
) -> Result<()> {
    output.emit(
        "inspected",
        || {
            serde_json::json!({
                "namespace": tracking.namespace().as_str(),
                "generation": tracking.generation().as_str(),
                "tracked_root": tracking.tracked_root().map(tracked_root_json),
            })
        },
        |rendered| {
            out_line(
                rendered,
                format_args!("{}", output.heading("Tracking", Tone::Neutral)),
            );
            out_line(
                rendered,
                format_args!("  Namespace   {}", tracking.namespace()),
            );
            out_line(
                rendered,
                format_args!(
                    "  Generation  {}",
                    display_digest_unique(
                        IdDomain::Generation,
                        tracking.generation(),
                        generation_candidates,
                        output.verbose()
                    )
                ),
            );
            write_tracked_root(rendered, tracking.tracked_root(), true, output.verbose());
        },
    )?;
    Ok(())
}

// JSON emits machine-contract snake_case statuses; terminal output uses
// descriptive phrases instead.
const fn namespace_status_name(status: NamespaceStatusKindV1) -> &'static str {
    match status {
        NamespaceStatusKindV1::NotFound => "not_found",
        NamespaceStatusKindV1::EnabledExact => "enabled_exact",
        NamespaceStatusKindV1::EnabledModified => "enabled_modified",
        NamespaceStatusKindV1::EnabledMissing => "enabled_missing",
        NamespaceStatusKindV1::EnabledUnexpected => "enabled_unexpected",
        NamespaceStatusKindV1::Disabled => "disabled",
        NamespaceStatusKindV1::Stale => "stale",
        NamespaceStatusKindV1::IncompatibleOrCorrupt => "incompatible_or_corrupt",
        NamespaceStatusKindV1::RecoveryRequired => "recovery_required",
    }
}

const fn namespace_status_title(status: NamespaceStatusKindV1) -> (&'static str, Tone) {
    match status {
        NamespaceStatusKindV1::NotFound => ("Namespace is not deployed", Tone::Neutral),
        NamespaceStatusKindV1::EnabledExact => ("Namespace is healthy", Tone::Success),
        NamespaceStatusKindV1::EnabledModified
        | NamespaceStatusKindV1::EnabledMissing
        | NamespaceStatusKindV1::EnabledUnexpected => ("Drift detected", Tone::Attention),
        NamespaceStatusKindV1::Disabled => ("Namespace is disabled", Tone::Neutral),
        NamespaceStatusKindV1::Stale => ("Namespace state is stale", Tone::Attention),
        NamespaceStatusKindV1::IncompatibleOrCorrupt => ("Namespace state is invalid", Tone::Error),
        NamespaceStatusKindV1::RecoveryRequired => ("Recovery required", Tone::Error),
    }
}

const fn target_status_name(status: TargetStatusKindV1) -> &'static str {
    match status {
        TargetStatusKindV1::Exact => "exact",
        TargetStatusKindV1::Modified => "modified",
        TargetStatusKindV1::Missing => "missing",
        TargetStatusKindV1::Unexpected => "unexpected",
        TargetStatusKindV1::Stale => "stale",
        TargetStatusKindV1::Incompatible => "incompatible",
    }
}

fn print_status(status: &NamespaceStatusV1, output: &Output) -> Result<()> {
    output.emit(
        namespace_status_name(status.status()),
        || {
            serde_json::json!({
                "namespace": status.namespace().as_str(),
                "head": status.head().map(Digest::as_str),
                "lifecycle": status.lifecycle().map(lifecycle_state_name),
                "desired_snapshot_digest": status.desired_snapshot_digest().map(Digest::as_str),
                "status": namespace_status_name(status.status()),
                "targets": status.targets().iter().map(|target| serde_json::json!({
                    "authority": target.authority().as_str(),
                    "relative_path": target.relative_path(),
                    "status": target_status_name(target.status()),
                })).collect::<Vec<_>>(),
                "observed_bytes": status.observed_bytes(),
                "detail": status.detail(),
            })
        },
        |rendered| {
            let (title, tone) = namespace_status_title(status.status());
            out_line(rendered, format_args!("{}", output.heading(title, tone)));
            out_line(
                rendered,
                format_args!("  Namespace   {}", status.namespace()),
            );
            if let Some(head) = status.head() {
                out_line(
                    rendered,
                    format_args!(
                        "  Generation  {}",
                        display_digest(IdDomain::Generation, head, output.verbose())
                    ),
                );
            }
            if let Some(lifecycle) = status.lifecycle() {
                out_line(
                    rendered,
                    format_args!("  State       {}", lifecycle_state_name(lifecycle)),
                );
            }
            let exact = status
                .targets()
                .iter()
                .filter(|target| matches!(target.status(), TargetStatusKindV1::Exact))
                .count();
            let changed = status.targets().len().saturating_sub(exact);
            out_line(
                rendered,
                format_args!("  Targets     {changed} changed, {exact} exact"),
            );
            for target in status.targets().iter().filter(|target| {
                output.verbose() || !matches!(target.status(), TargetStatusKindV1::Exact)
            }) {
                let marker = if matches!(target.status(), TargetStatusKindV1::Exact) {
                    '='
                } else {
                    '~'
                };
                out_line(
                    rendered,
                    format_args!(
                        "  {marker} {}:{}  {}",
                        target.authority(),
                        target.relative_path(),
                        target_status_name(target.status())
                    ),
                );
            }
            if let Some(detail) = status.detail() {
                out_line(rendered, format_args!("\n  {detail}"));
            }
            if output.verbose() {
                if let Some(snapshot) = status.desired_snapshot_digest() {
                    out_line(rendered, format_args!("  Desired     {snapshot}"));
                }
                out_line(
                    rendered,
                    format_args!("  Observed    {}", human_bytes(status.observed_bytes())),
                );
            }
        },
    )?;
    Ok(())
}

const fn fsck_code_name(code: FsckFindingCodeV1) -> &'static str {
    match code {
        FsckFindingCodeV1::InvalidDescriptor => "invalid_descriptor",
        FsckFindingCodeV1::RecoveryRequired => "recovery_required",
        FsckFindingCodeV1::InvalidJournal => "invalid_journal",
        FsckFindingCodeV1::MissingCatalog => "missing_catalog",
        FsckFindingCodeV1::InvalidCatalog => "invalid_catalog",
        FsckFindingCodeV1::MissingGeneration => "missing_generation",
        FsckFindingCodeV1::InvalidGeneration => "invalid_generation",
        FsckFindingCodeV1::CyclicHistory => "cyclic_history",
        FsckFindingCodeV1::CrossNamespaceHistory => "cross_namespace_history",
        FsckFindingCodeV1::SharedGeneration => "shared_generation",
        FsckFindingCodeV1::MissingPreparedPlan => "missing_prepared_plan",
        FsckFindingCodeV1::InvalidPreparedPlan => "invalid_prepared_plan",
        FsckFindingCodeV1::InvalidPreparedTransition => "invalid_prepared_transition",
        FsckFindingCodeV1::MissingArtifactBlob => "missing_artifact_blob",
        FsckFindingCodeV1::CorruptArtifactBlob => "corrupt_artifact_blob",
        FsckFindingCodeV1::ArtifactLengthMismatch => "artifact_length_mismatch",
        FsckFindingCodeV1::MissingPackObject => "missing_pack_object",
        FsckFindingCodeV1::CorruptPackObject => "corrupt_pack_object",
        FsckFindingCodeV1::MissingCanonicalObject => "missing_canonical_object",
        FsckFindingCodeV1::CorruptCanonicalObject => "corrupt_canonical_object",
        FsckFindingCodeV1::InvalidLockMetadata => "invalid_lock_metadata",
        FsckFindingCodeV1::InvalidStaging => "invalid_staging",
        FsckFindingCodeV1::MalformedStoreEntry => "malformed_store_entry",
        FsckFindingCodeV1::UnreachableImmutableObject => "unreachable_immutable_object",
        FsckFindingCodeV1::TargetDrift => "target_drift",
        FsckFindingCodeV1::TargetObservationFailed => "target_observation_failed",
        FsckFindingCodeV1::AuthorityChanged => "authority_changed",
        FsckFindingCodeV1::InvalidOwnership => "invalid_ownership",
        FsckFindingCodeV1::TraversalLimitExceeded => "traversal_limit_exceeded",
        FsckFindingCodeV1::DecodedByteLimitExceeded => "decoded_byte_limit_exceeded",
        FsckFindingCodeV1::FindingLimitExceeded => "finding_limit_exceeded",
    }
}

const fn fsck_store_area_name(area: FsckStoreAreaV1) -> &'static str {
    match area {
        FsckStoreAreaV1::Root => "root",
        FsckStoreAreaV1::State => "state",
        FsckStoreAreaV1::Generations => "generations",
        FsckStoreAreaV1::Prepared => "prepared",
        FsckStoreAreaV1::Transactions => "transactions",
        FsckStoreAreaV1::Objects => "objects",
        FsckStoreAreaV1::ArtifactBlobs => "artifact_blobs",
        FsckStoreAreaV1::PackObjects => "pack_objects",
        FsckStoreAreaV1::CanonicalFiles => "canonical_files",
        FsckStoreAreaV1::CanonicalSymlinks => "canonical_symlinks",
        FsckStoreAreaV1::CanonicalTrees => "canonical_trees",
    }
}

/// Defines one shared fsck-subject row for both output formats.
///
/// JSON uses the snake_case kind and optional named identity directly. Human
/// output replaces `_` with `-` and joins the identity with `:`.
fn fsck_subject_parts(subject: &FsckSubjectV1) -> (&'static str, Option<(&'static str, String)>) {
    match subject {
        FsckSubjectV1::StoreDescriptor => ("store_descriptor", None),
        FsckSubjectV1::TransactionLock => ("transaction_lock", None),
        FsckSubjectV1::MaintenanceLock => ("maintenance_lock", None),
        FsckSubjectV1::Journal => ("journal", None),
        FsckSubjectV1::JournalStaging => ("journal_staging", None),
        FsckSubjectV1::Catalog => ("catalog", None),
        FsckSubjectV1::CatalogStaging => ("catalog_staging", None),
        FsckSubjectV1::Namespace(namespace) => (
            "namespace",
            Some(("namespace", namespace.as_str().to_owned())),
        ),
        FsckSubjectV1::Generation(digest) => {
            ("generation", Some(("digest", digest.as_str().to_owned())))
        }
        FsckSubjectV1::PreparedPlan(plan_id) => (
            "prepared_plan",
            Some(("plan_id", plan_id.as_str().to_owned())),
        ),
        FsckSubjectV1::ArtifactBlob(digest) => (
            "artifact_blob",
            Some(("digest", digest.as_str().to_owned())),
        ),
        FsckSubjectV1::PackObject(digest) => {
            ("pack_object", Some(("digest", digest.as_str().to_owned())))
        }
        FsckSubjectV1::CanonicalFile(digest) => (
            "canonical_file",
            Some(("digest", digest.as_str().to_owned())),
        ),
        FsckSubjectV1::CanonicalSymlink(digest) => (
            "canonical_symlink",
            Some(("digest", digest.as_str().to_owned())),
        ),
        FsckSubjectV1::CanonicalTree(digest) => (
            "canonical_tree",
            Some(("digest", digest.as_str().to_owned())),
        ),
        FsckSubjectV1::StoreArea(area) => (
            "store_area",
            Some(("area", fsck_store_area_name(*area).to_owned())),
        ),
        FsckSubjectV1::Retention => ("retention", None),
        FsckSubjectV1::Ownership => ("ownership", None),
        FsckSubjectV1::Coverage => ("coverage", None),
        FsckSubjectV1::Target { .. } => {
            unreachable!("two-field target subjects render outside the shared table")
        }
    }
}

fn fsck_subject_json(subject: &FsckSubjectV1) -> serde_json::Value {
    if let FsckSubjectV1::Target {
        authority,
        relative_path,
    } = subject
    {
        return serde_json::json!({
            "kind": "target",
            "authority": authority.as_str(),
            "relative_path": relative_path,
        });
    }
    let (kind, field) = fsck_subject_parts(subject);
    let mut object = serde_json::Map::new();
    object.insert("kind".to_owned(), kind.into());
    if let Some((field, value)) = field {
        object.insert(field.to_owned(), value.into());
    }
    serde_json::Value::Object(object)
}

fn fsck_subject_label(subject: &FsckSubjectV1) -> String {
    if let FsckSubjectV1::Target {
        authority,
        relative_path,
    } = subject
    {
        return format!("target:{authority}:{relative_path}");
    }
    let (kind, field) = fsck_subject_parts(subject);
    let kind = kind.replace('_', "-");
    match field {
        None => kind,
        Some((_, value)) => format!("{kind}:{value}"),
    }
}

fn print_fsck(report: &FsckReportV1, output: &Output) -> Result<()> {
    output.emit(
        if report.is_clean() {
            "clean"
        } else {
            "findings"
        },
        || {
            serde_json::json!({
                "clean": report.is_clean(),
                "findings": report.findings().iter().map(|finding| serde_json::json!({
                    "code": fsck_code_name(finding.code()),
                    "severity": match finding.severity() {
                        FsckSeverityV1::Error => "error",
                        FsckSeverityV1::Warning => "warning",
                    },
                    "subject": fsck_subject_json(finding.subject()),
                    "detail": finding.detail(),
                })).collect::<Vec<_>>(),
                "checked_generations": report.checked_generations(),
                "checked_prepared_plans": report.checked_prepared_plans(),
                "checked_artifact_blobs": report.checked_artifact_blobs(),
                "checked_pack_objects": report.checked_pack_objects(),
                "checked_canonical_files": report.checked_canonical_files(),
                "checked_canonical_symlinks": report.checked_canonical_symlinks(),
                "checked_canonical_trees": report.checked_canonical_trees(),
                "checked_targets": report.checked_targets(),
                "decoded_bytes": report.decoded_bytes(),
                "observed_bytes": report.observed_bytes(),
                "findings_truncated": report.findings_truncated(),
                "complete": report.complete(),
            })
        },
        |rendered| {
            let title = if report.is_clean() {
                output.heading("Store verified", Tone::Success)
            } else {
                output.heading("Store verification found problems", Tone::Attention)
            };
            out_line(rendered, format_args!("{title}"));
            let error_count = report
                .findings()
                .iter()
                .filter(|finding| matches!(finding.severity(), FsckSeverityV1::Error))
                .count();
            let warning_count = report.findings().len().saturating_sub(error_count);
            out_line(
                rendered,
                format_args!("  Findings     {error_count} errors, {warning_count} warnings"),
            );
            out_line(
                rendered,
                format_args!(
                    "  Checked      {} generations, {} plans, {} targets",
                    report.checked_generations(),
                    report.checked_prepared_plans(),
                    report.checked_targets()
                ),
            );
            for finding in report.findings() {
                let severity = match finding.severity() {
                    FsckSeverityV1::Error => "error",
                    FsckSeverityV1::Warning => "warning",
                };
                let marker = if matches!(finding.severity(), FsckSeverityV1::Error) {
                    'x'
                } else {
                    '!'
                };
                out_line(
                    rendered,
                    format_args!(
                        "\n  {marker} {severity}[{}] {}",
                        fsck_code_name(finding.code()),
                        fsck_subject_label(finding.subject())
                    ),
                );
                out_line(rendered, format_args!("    {}", finding.detail()));
            }
            if !report.is_clean() {
                out_line(rendered, format_args!("\nNo changes were made."));
            }
            if output.verbose() {
                out_line(
                    rendered,
                    format_args!(
                        "\nObjects\n  {} artifacts, {} packs, {} files, {} symlinks, {} trees",
                        report.checked_artifact_blobs(),
                        report.checked_pack_objects(),
                        report.checked_canonical_files(),
                        report.checked_canonical_symlinks(),
                        report.checked_canonical_trees()
                    ),
                );
                out_line(
                    rendered,
                    format_args!(
                        "  {} decoded, {} observed",
                        human_bytes(report.decoded_bytes()),
                        human_bytes(report.observed_bytes())
                    ),
                );
                out_line(
                    rendered,
                    format_args!("  Complete    {}", report.complete()),
                );
                out_line(
                    rendered,
                    format_args!("  Truncated   {}", report.findings_truncated()),
                );
            }
        },
    )?;
    Ok(())
}

const fn input_kind_name(kind: PrepareInputKindV1) -> &'static str {
    match kind {
        PrepareInputKindV1::Source => "source",
        PrepareInputKindV1::Config => "config",
        PrepareInputKindV1::Lock => "lock",
        PrepareInputKindV1::Component => "component",
        PrepareInputKindV1::Asset => "asset",
        PrepareInputKindV1::Other => "other",
    }
}

fn operation_json(operation: &PrepareOperationV1) -> serde_json::Value {
    match operation {
        PrepareOperationV1::EnsureDirectory {
            authority,
            relative_path,
            mode,
            replace_existing,
        } => serde_json::json!({
            "operation": "ensure_directory",
            "authority": authority.as_str(),
            "relative_path": relative_path,
            "mode": mode,
            "replace_existing": replace_existing,
        }),
        PrepareOperationV1::PlaceFile {
            authority,
            relative_path,
            artifact_id,
            mode,
            replace_existing,
        } => serde_json::json!({
            "operation": "place_file",
            "authority": authority.as_str(),
            "relative_path": relative_path,
            "artifact_id": artifact_id.as_str(),
            "mode": mode,
            "replace_existing": replace_existing,
        }),
        PrepareOperationV1::PlaceSymlink {
            authority,
            relative_path,
            object,
            replace_existing,
        } => serde_json::json!({
            "operation": "place_symlink",
            "authority": authority.as_str(),
            "relative_path": relative_path,
            "object": object.as_str(),
            "replace_existing": replace_existing,
        }),
        PrepareOperationV1::PlaceTree {
            authority,
            relative_path,
            tree,
            archive_provenance,
            replace_existing,
        } => serde_json::json!({
            "operation": "place_tree",
            "authority": authority.as_str(),
            "relative_path": relative_path,
            "tree": tree.as_str(),
            "archive_provenance": archive_provenance.as_ref().map(|provenance| serde_json::json!({
                "payload": provenance.payload().as_str(),
                "decoder": provenance.decoder(),
            })),
            "replace_existing": replace_existing,
        }),
        PrepareOperationV1::RemoveLeaf {
            authority,
            relative_path,
        } => serde_json::json!({
            "operation": "remove_leaf",
            "authority": authority.as_str(),
            "relative_path": relative_path,
        }),
        PrepareOperationV1::AssertAbsent {
            authority,
            relative_path,
        } => serde_json::json!({
            "operation": "assert_absent",
            "authority": authority.as_str(),
            "relative_path": relative_path,
        }),
        PrepareOperationV1::AssertExact {
            authority,
            relative_path,
            state,
        } => serde_json::json!({
            "operation": "assert_exact",
            "authority": authority.as_str(),
            "relative_path": relative_path,
            "state": target_state_json(state),
        }),
    }
}

fn archive_provenance_text(provenance: &malm_types::ArchiveProvenanceV1) -> String {
    format!(
        "payload={} decoder={}",
        provenance.payload(),
        provenance.decoder()
    )
}

fn target_state_text(state: &PrepareTargetStateV1) -> String {
    match state {
        PrepareTargetStateV1::File {
            digest,
            byte_len,
            mode,
        } => format!("file digest={digest} byte_len={byte_len} mode={mode:04o}"),
        PrepareTargetStateV1::Directory { mode } => {
            format!("directory mode={mode:04o}")
        }
        PrepareTargetStateV1::Symlink { object } => format!("symlink object={object}"),
        PrepareTargetStateV1::Tree {
            tree,
            archive_provenance,
        } => format!(
            "tree tree={tree} archive={}",
            archive_provenance
                .as_ref()
                .map_or_else(|| "none".to_owned(), archive_provenance_text)
        ),
    }
}

fn target_state_json(state: &PrepareTargetStateV1) -> serde_json::Value {
    match state {
        PrepareTargetStateV1::File {
            digest,
            byte_len,
            mode,
        } => serde_json::json!({
            "kind": "file",
            "digest": digest.as_str(),
            "byte_len": byte_len,
            "mode": mode,
        }),
        PrepareTargetStateV1::Directory { mode } => serde_json::json!({
            "kind": "directory",
            "mode": mode,
        }),
        PrepareTargetStateV1::Symlink { object } => serde_json::json!({
            "kind": "symlink",
            "object": object.as_str(),
        }),
        PrepareTargetStateV1::Tree {
            tree,
            archive_provenance,
        } => serde_json::json!({
            "kind": "tree",
            "tree": tree.as_str(),
            "archive_provenance": archive_provenance.as_ref().map(|provenance| serde_json::json!({
                "payload": provenance.payload().as_str(),
                "decoder": provenance.decoder(),
            })),
        }),
    }
}

fn print_recovery(outcome: &RecoveryOutcomeV1, output: &Output) -> Result<()> {
    match outcome {
        RecoveryOutcomeV1::NoTransaction if output.is_json() => {
            output.json("clean", serde_json::json!({ "status": "no_transaction" }))?;
        }
        RecoveryOutcomeV1::NoTransaction => output.human(&format!(
            "{}\n  No interrupted transaction was found.\n",
            output.heading("No recovery needed", Tone::Success)
        ))?,
        RecoveryOutcomeV1::Recovered { namespace, head } if output.is_json() => output.json(
            "recovered",
            serde_json::json!({
                "status": "recovered",
                "namespace": namespace.as_str(),
                "head": head.as_ref().map(Digest::as_str),
            }),
        )?,
        RecoveryOutcomeV1::Recovered { namespace, head } => {
            let mut rendered = String::new();
            out_line(
                &mut rendered,
                format_args!("{}", output.heading("Recovery completed", Tone::Success)),
            );
            out_line(&mut rendered, format_args!("  Namespace  {namespace}"));
            match head {
                Some(head) => {
                    out_line(
                        &mut rendered,
                        format_args!(
                            "  Generation {}",
                            display_digest(IdDomain::Generation, head, output.verbose())
                        ),
                    );
                }
                None => {
                    out_line(&mut rendered, format_args!("  Generation none"));
                }
            }
            output.human(&rendered)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{advisory_summary, write_wrapped_text};

    #[test]
    fn authoring_advisories_have_compact_semantic_summaries() {
        assert_eq!(
            advisory_summary(
                "AUTHORING-EVALUATION-REUSED",
                &[
                    "evaluation reused from plan pp-1111111111111111111111111111111111111111111111111111111111111111: every captured evaluation input is byte-identical",
                    "evaluation reused from plan pp-2222222222222222222222222222222222222222222222222222222222222222: every captured evaluation input is byte-identical",
                ],
                false,
            ),
            "Evaluation reused from plan:222222222222."
        );
        assert_eq!(
            advisory_summary(
                "AUTHORING-OVERLAY-APPLIED",
                &[
                    "machine-local overlay `local` applied from ~/.config/malm/local.kdl (sha256-example)"
                ],
                false,
            ),
            "Machine-local overlay `local` applied."
        );
        assert_eq!(
            advisory_summary(
                "AUTHORING-SYMLINK-SKIPPED",
                &["5 symlink(s) with upward-relative targets are managed at runtime"],
                false,
            ),
            "5 runtime-managed symlinks skipped."
        );
        assert_eq!(
            advisory_summary(
                "AUTHORING-TRANSFORMS-CARRIED",
                &["output transform provenance carried from a retained plan"],
                false,
            ),
            "Output transforms reused from a byte-identical plan."
        );
    }

    #[test]
    fn verbose_finding_details_are_wrapped_and_whitespace_normalized() {
        let mut rendered = String::new();
        write_wrapped_text(
            &mut rendered,
            "machine-local overlay values were loaded from a path with                      intentionally excessive whitespace for wrapping coverage",
            "    ",
            "    ",
        );

        assert!(!rendered.contains("with                      intentionally"));
        assert!(
            rendered.lines().all(|line| line.chars().count() <= 96),
            "{rendered}"
        );
    }
}
