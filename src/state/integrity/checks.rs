//! Read-only consistency detectors for `malm state fsck`.

use crate::app::validation::{short_commit, validate_name};
use crate::cas::{sources_object_dir, tree_hash};
use crate::state::active_deployment::read_source_pointer;
use crate::state::integrity::report::{Finding, Severity};
use crate::state::ownership::OwnerKind;
use crate::state::ownership_store::read_ownership_for;
use crate::state::record::{StateMode, StateRecord, live_deployment_id};
use crate::state::state_namespaces;
use crate::state::target_lock::TargetLock;
use crate::state::transaction::{
    PreviousState, RecordedOp, TransactionKind, TransactionManifest, TransactionStatus,
    TransactionStore, transaction_alias, transactions_dir,
};
use anyhow::{Context, Result};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

pub struct CheckOptions {
    /// Verify active source snapshots against their content address.
    pub verify_objects: bool,
}

pub fn run_checks(options: &CheckOptions) -> Result<Vec<Finding>> {
    let mut findings = Vec::new();
    let store = TransactionStore::new();

    for issue in crate::state::integrity::preflight::scan_state_root(false)? {
        findings.push(
            Finding::new(
                Severity::Error,
                "state-root-insecure",
                format!("{}: {}", issue.path.display(), issue.problem),
            )
            .with_remedy(issue.remedy),
        );
    }

    check_transactions(&store, &mut findings)?;

    let mut manifests = store.list_all()?;
    manifests.sort_by(|a, b| (b.completed_at, &b.id).cmp(&(a.completed_at, &a.id)));

    for namespace in state_namespaces()? {
        check_namespace(&store, &namespace, options, &mut findings)?;
        check_disable_consistency(&store, &namespace, &manifests, &mut findings);
        check_tracking(&store, &namespace, &mut findings);
    }

    sort_findings(&mut findings);
    Ok(findings)
}

fn sort_findings(findings: &mut [Finding]) {
    findings.sort_by(|left, right| {
        right
            .severity
            .cmp(&left.severity)
            .then_with(|| left.namespace.cmp(&right.namespace))
            .then_with(|| left.transaction.cmp(&right.transaction))
            .then_with(|| left.code.cmp(right.code))
            .then_with(|| left.message.cmp(&right.message))
            .then_with(|| left.remedy.cmp(&right.remedy))
    });
}

fn check_transactions(store: &TransactionStore, findings: &mut Vec<Finding>) -> Result<()> {
    let dir = transactions_dir();
    let entries = match std::fs::read_dir(&dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error).with_context(|| format!("read {}", dir.display())),
    };

    for entry in entries {
        let entry = entry.with_context(|| format!("read entry in {}", dir.display()))?;
        let name = entry.file_name();
        let Some(id) = name.to_str() else {
            findings.push(Finding::new(
                Severity::Error,
                "transaction-invalid-name",
                format!("transaction directory has a non-UTF-8 name: {name:?}"),
            ));
            continue;
        };
        if !entry.path().join("manifest.json").exists() {
            findings.push(
                Finding::new(
                    Severity::Warning,
                    "transaction-no-manifest",
                    format!("transaction directory {id} has no manifest.json"),
                )
                .for_transaction(id),
            );
            continue;
        }
        let manifest = match store.read(id) {
            Ok(manifest) => manifest,
            Err(error) => {
                findings.push(
                    Finding::new(
                        Severity::Error,
                        "transaction-unreadable",
                        format!("transaction {id} is unreadable: {error:#}"),
                    )
                    .for_transaction(id),
                );
                continue;
            }
        };

        let alias = transaction_alias(id);
        if manifest.needs_rollback() {
            findings.push(
                Finding::new(
                    Severity::Error,
                    "transaction-needs-rollback",
                    format!(
                        "transaction {alias} crashed mid-apply with partially applied \
                         filesystem changes ({} journaled operations)",
                        manifest.operations.len()
                    ),
                )
                .for_namespace(manifest.state_namespace())
                .for_transaction(id)
                .with_remedy(format!("malm state recover {alias}")),
            );
        } else if manifest.needs_roll_forward() {
            findings.push(
                Finding::new(
                    Severity::Error,
                    "transaction-needs-roll-forward",
                    format!(
                        "transaction {alias} applied its filesystem changes but never \
                         finished committing metadata (phase: {})",
                        manifest.effective_phase().label()
                    ),
                )
                .for_namespace(manifest.state_namespace())
                .for_transaction(id)
                .with_remedy(format!(
                    "malm state recover {alias} (or re-run `malm apply`)"
                )),
            );
        } else if matches!(
            manifest.status,
            TransactionStatus::Started | TransactionStatus::Failed
        ) {
            findings.push(
                Finding::new(
                    Severity::Notice,
                    "transaction-failed-clean",
                    format!(
                        "transaction {alias} failed before touching the filesystem; \
                         `malm state prune` reclaims it as it ages out"
                    ),
                )
                .for_namespace(manifest.state_namespace())
                .for_transaction(id),
            );
        }

        if matches!(
            manifest.status,
            TransactionStatus::Completed | TransactionStatus::RolledBack
        ) && manifest_has_retained_backups(&manifest)
        {
            findings.push(
                Finding::new(
                    Severity::Notice,
                    "transaction-leftover-backups",
                    format!(
                        "finished transaction {alias} still holds backups of replaced files \
                         (kept until the transaction is pruned)"
                    ),
                )
                .for_namespace(manifest.state_namespace())
                .for_transaction(id),
            );
        }
    }
    Ok(())
}

fn manifest_has_retained_backups(manifest: &TransactionManifest) -> bool {
    manifest.operations.iter().any(|operation| match operation {
        RecordedOp::CreateSymlink { previous, .. }
        | RecordedOp::RemovePath { previous, .. }
        | RecordedOp::InstallAsset { previous, .. } => {
            matches!(previous, PreviousState::Backed { backup, .. }
                if std::fs::symlink_metadata(backup).is_ok())
        }
        RecordedOp::RemoveAsset { quarantine, .. } => quarantine
            .as_ref()
            .is_some_and(|path| std::fs::symlink_metadata(path).is_ok()),
    })
}

fn check_namespace(
    store: &TransactionStore,
    namespace: &str,
    options: &CheckOptions,
    findings: &mut Vec<Finding>,
) -> Result<()> {
    if validate_name(namespace, "state name").is_err() {
        findings.push(
            Finding::new(
                Severity::Warning,
                "namespace-invalid-name",
                format!(
                    "state directory {namespace:?} has an invalid name and is ignored by \
                     Malm commands"
                ),
            )
            .for_namespace(namespace),
        );
        return Ok(());
    }

    // state.json must name a transaction consistent with its mode. The
    // transaction manifest remains the status authority.
    let state_record = match StateRecord::load_for_state(namespace) {
        Ok(record) => record,
        Err(error) => {
            findings.push(
                Finding::new(
                    Severity::Error,
                    "state-record-unreadable",
                    format!("the state record for '{namespace}' is unreadable: {error:#}"),
                )
                .for_namespace(namespace)
                .with_remedy("re-run `malm apply` to rewrite it"),
            );
            None
        }
    };
    match state_record.as_ref().map(|record| &record.mode) {
        Some(StateMode::Enabled { live_transaction }) => match store.read(live_transaction) {
            Ok(manifest) => {
                if manifest.status != TransactionStatus::Completed {
                    findings.push(
                        Finding::new(
                            Severity::Warning,
                            "state-record-not-completed",
                            format!(
                                "state '{namespace}' records live transaction {} with status \
                                 '{}'",
                                transaction_alias(live_transaction),
                                manifest.status.label()
                            ),
                        )
                        .for_namespace(namespace)
                        .for_transaction(live_transaction)
                        .with_remedy(format!(
                            "malm state recover {}",
                            transaction_alias(live_transaction)
                        )),
                    );
                } else if !manifest.kind.deploys() {
                    findings.push(
                        Finding::new(
                            Severity::Warning,
                            "state-record-wrong-kind",
                            format!(
                                "state '{namespace}' records a non-deploying transaction as \
                                 its live deployment"
                            ),
                        )
                        .for_namespace(namespace)
                        .for_transaction(live_transaction),
                    );
                }
            }
            Err(_) => {
                findings.push(
                    Finding::new(
                        Severity::Warning,
                        "state-record-missing-transaction",
                        format!(
                            "the state record for '{namespace}' references missing \
                             transaction {}",
                            transaction_alias(live_transaction)
                        ),
                    )
                    .for_namespace(namespace)
                    .for_transaction(live_transaction)
                    .with_remedy("re-run `malm apply` to rewrite it"),
                );
            }
        },
        Some(StateMode::Destroyed { .. }) => {
            findings.push(
                Finding::new(
                    Severity::Notice,
                    "state-destroyed-leftover",
                    format!(
                        "state '{namespace}' finished a destroy but its directory was never \
                         removed"
                    ),
                )
                .for_namespace(namespace)
                .with_remedy(format!("re-run `malm state destroy {namespace}`")),
            );
        }
        // Disabled states are checked by check_disable_consistency.
        Some(StateMode::Disabled { .. }) | None => {}
    }

    // An active source pointer must resolve and match the transaction snapshot.
    // Disabled states must not retain one.
    let active_id = live_deployment_id(namespace)?;
    if matches!(
        state_record.as_ref().map(|record| &record.mode),
        Some(StateMode::Disabled { .. })
    ) && read_source_pointer(namespace)?.is_some()
    {
        findings.push(
            Finding::new(
                Severity::Warning,
                "disabled-source-pointer-present",
                format!("state '{namespace}' is disabled but still has a source pointer"),
            )
            .for_namespace(namespace)
            .with_remedy(format!("re-run `malm state disable {namespace}`")),
        );
    }
    let pointer = match read_source_pointer(namespace) {
        Ok(pointer) => pointer,
        Err(error) => {
            findings.push(
                Finding::new(
                    Severity::Error,
                    "source-pointer-unreadable",
                    format!("source pointer for state '{namespace}' is unreadable: {error:#}"),
                )
                .for_namespace(namespace),
            );
            None
        }
    };
    match (&pointer, &active_id) {
        (Some(target), _) if !target.is_dir() => {
            findings.push(
                Finding::new(
                    Severity::Error,
                    "source-pointer-dangling",
                    format!(
                        "source pointer for state '{namespace}' dangles: {} does not exist",
                        target.display()
                    ),
                )
                .for_namespace(namespace)
                .with_remedy("re-run `malm apply` to restore the snapshot"),
            );
        }
        (Some(target), Some(active_id)) => {
            if let Ok(manifest) = store.read(active_id)
                && let Ok(expected) = sources_object_dir(manifest.source_snapshot_id.as_str())
                && target != &expected
            {
                findings.push(
                    Finding::new(
                        Severity::Warning,
                        "source-pointer-mismatch",
                        format!(
                            "source pointer for state '{namespace}' points at {} but the \
                             active transaction {} recorded snapshot {}",
                            target.display(),
                            transaction_alias(active_id),
                            manifest.source_snapshot_id
                        ),
                    )
                    .for_namespace(namespace)
                    .for_transaction(active_id)
                    .with_remedy("re-run `malm apply`"),
                );
            }
        }
        (None, Some(active_id)) => {
            findings.push(
                Finding::new(
                    Severity::Error,
                    "source-pointer-missing",
                    format!(
                        "state '{namespace}' has an active deployment ({}) but no source \
                         pointer; deployed symlinks are dangling",
                        transaction_alias(active_id)
                    ),
                )
                .for_namespace(namespace)
                .with_remedy("re-run `malm apply`"),
            );
        }
        (Some(_), None) | (None, None) => {}
    }

    // Compare ownership with the filesystem and target lock. Targets retained
    // by disable are already known to be modified, so skip their drift checks.
    let deliberately_kept: BTreeSet<PathBuf> = match state_record.as_ref().map(|r| &r.mode) {
        Some(StateMode::Disabled { kept_targets, .. }) => kept_targets.iter().cloned().collect(),
        _ => BTreeSet::new(),
    };
    match read_ownership_for(namespace) {
        Ok(ownership) => {
            let mut owned_targets: BTreeSet<&Path> = BTreeSet::new();
            for entry in ownership.iter() {
                owned_targets.insert(entry.target.as_path());
                if !deliberately_kept.contains(&entry.target) {
                    check_ownership_entry(namespace, entry, findings);
                }
            }

            match TargetLock::load() {
                Ok(lock) => {
                    let locked: BTreeSet<&Path> = lock.targets_for(namespace);
                    for missing in owned_targets.difference(&locked) {
                        findings.push(
                            Finding::new(
                                Severity::Warning,
                                "target-lock-missing-entry",
                                format!(
                                    "{} is owned by state '{namespace}' but absent from the \
                                     target lock",
                                    missing.display()
                                ),
                            )
                            .for_namespace(namespace)
                            .with_remedy("re-run `malm apply` to repair state metadata"),
                        );
                    }
                    for stray in locked.difference(&owned_targets) {
                        findings.push(
                            Finding::new(
                                Severity::Warning,
                                "target-lock-stray-entry",
                                format!(
                                    "{} is registered to state '{namespace}' in the target \
                                     lock but has no ownership record",
                                    stray.display()
                                ),
                            )
                            .for_namespace(namespace)
                            .with_remedy("re-run `malm apply` to repair state metadata"),
                        );
                    }
                }
                Err(error) => {
                    findings.push(Finding::new(
                        Severity::Error,
                        "target-lock-unreadable",
                        format!("target lock is unreadable: {error:#}"),
                    ));
                }
            }
        }
        Err(error) => {
            findings.push(
                Finding::new(
                    Severity::Error,
                    "ownership-unreadable",
                    format!("ownership index for state '{namespace}' is unreadable: {error:#}"),
                )
                .for_namespace(namespace),
            );
        }
    }

    if options.verify_objects
        && let Some(active_id) = &active_id
        && let Ok(manifest) = store.read(active_id)
    {
        let expected = manifest.source_snapshot_id.as_str().to_owned();
        match sources_object_dir(&expected) {
            Ok(root) if root.is_dir() => match tree_hash(&root) {
                Ok(actual) if actual == expected => {}
                Ok(actual) => {
                    findings.push(
                        Finding::new(
                            Severity::Error,
                            "snapshot-corrupt",
                            format!(
                                "active source snapshot for state '{namespace}' hashes to \
                                 {actual} but is stored as {expected}"
                            ),
                        )
                        .for_namespace(namespace)
                        .for_transaction(active_id)
                        .with_remedy("re-run `malm apply` to rebuild the snapshot"),
                    );
                }
                Err(error) => {
                    findings.push(
                        Finding::new(
                            Severity::Error,
                            "snapshot-unreadable",
                            format!(
                                "cannot hash active source snapshot for state \
                                 '{namespace}': {error:#}"
                            ),
                        )
                        .for_namespace(namespace),
                    );
                }
            },
            Ok(root) => {
                findings.push(
                    Finding::new(
                        Severity::Error,
                        "snapshot-missing",
                        format!(
                            "active source snapshot for state '{namespace}' is missing: {}",
                            root.display()
                        ),
                    )
                    .for_namespace(namespace)
                    .with_remedy("re-run `malm apply` to rebuild the snapshot"),
                );
            }
            Err(error) => {
                findings.push(
                    Finding::new(
                        Severity::Error,
                        "snapshot-invalid-id",
                        format!(
                            "active transaction for state '{namespace}' records an invalid \
                             snapshot id: {error:#}"
                        ),
                    )
                    .for_namespace(namespace),
                );
            }
        }
    }

    Ok(())
}

/// Report tracking that lags the live deployment.
///
/// Tracking is saved after deployment finalization, so a crash between those
/// writes can leave the old commit in `tracking.json`. The next mutation
/// reconciles it, while fsck reports the mismatch in the meantime.
fn check_tracking(store: &TransactionStore, namespace: &str, findings: &mut Vec<Finding>) {
    let tracking = match crate::state::tracking::TrackedRemote::load_for_state(namespace) {
        Ok(Some(tracking)) => tracking,
        Ok(None) => return,
        Err(error) => {
            findings.push(
                Finding::new(
                    Severity::Warning,
                    "tracking-unreadable",
                    format!("tracking state for '{namespace}' is unreadable: {error:#}"),
                )
                .with_remedy("run `malm update` to rebuild or remove it")
                .for_namespace(namespace),
            );
            return;
        }
    };

    // Use lenient resolution so fsck still works during a transition.
    let Ok(Some(live_id)) = live_deployment_id(namespace) else {
        return;
    };
    let Ok(manifest) = store.read(&live_id) else {
        return;
    };

    match manifest.source.as_ref().map(|source| &source.kind) {
        Some(crate::source::SourceKind::Git { url, commit }) => {
            if *url != tracking.url {
                findings.push(
                    Finding::new(
                        Severity::Warning,
                        "tracking-desynced",
                        format!(
                            "tracking for state '{namespace}' points at a different remote \
                             than the live deployment"
                        ),
                    )
                    .with_remedy("run `malm update` (or re-apply) to reconcile tracking")
                    .for_namespace(namespace),
                );
            } else if *commit != tracking.applied_commit {
                findings.push(
                    Finding::new(
                        Severity::Warning,
                        "tracking-desynced",
                        format!(
                            "tracking for state '{namespace}' records commit {} but the live \
                             deployment applied {}",
                            &short_commit(&tracking.applied_commit, 12),
                            &short_commit(commit, 12)
                        ),
                    )
                    .with_remedy("run `malm update` (or re-apply) to reconcile tracking")
                    .for_namespace(namespace),
                );
            }
        }
        _ => {
            findings.push(
                Finding::new(
                    Severity::Warning,
                    "tracking-desynced",
                    format!(
                        "state '{namespace}' has tracking metadata but its live deployment \
                         is not a tracked remote"
                    ),
                )
                .with_remedy("the next apply removes stale tracking")
                .for_namespace(namespace),
            );
        }
    }
}

/// Check that a disabled record has a completed restore target and owns only
/// deliberately retained targets. A completed disable without that record
/// means the mode transition did not finish; rerunning disable converges.
fn check_disable_consistency(
    store: &TransactionStore,
    namespace: &str,
    manifests_newest_first: &[TransactionManifest],
    findings: &mut Vec<Finding>,
) {
    // Unreadable records are already reported by check_namespace.
    let mode = StateRecord::load_for_state(namespace)
        .ok()
        .flatten()
        .map(|record| record.mode);

    match mode {
        Some(StateMode::Disabled {
            restore_transaction,
            kept_targets,
            ..
        }) => {
            match store.read(&restore_transaction) {
                Ok(manifest) if manifest.status == TransactionStatus::Completed => {}
                Ok(manifest) => {
                    findings.push(
                        Finding::new(
                            Severity::Error,
                            "disabled-record-invalid",
                            format!(
                                "state '{namespace}' is disabled but its restore target {} \
                                 has status '{}'",
                                transaction_alias(&restore_transaction),
                                manifest.status.label()
                            ),
                        )
                        .for_namespace(namespace)
                        .for_transaction(&restore_transaction),
                    );
                }
                Err(_) => {
                    findings.push(
                        Finding::new(
                            Severity::Error,
                            "disabled-record-invalid",
                            format!(
                                "state '{namespace}' is disabled but its restore target {} \
                                 is missing",
                                transaction_alias(&restore_transaction)
                            ),
                        )
                        .for_namespace(namespace)
                        .for_transaction(&restore_transaction),
                    );
                }
            }
            if let Ok(ownership) = read_ownership_for(namespace) {
                let unexpected: Vec<_> = ownership
                    .iter()
                    .filter(|entry| !kept_targets.contains(&entry.target))
                    .map(|entry| entry.target.display().to_string())
                    .collect();
                if !unexpected.is_empty() {
                    findings.push(
                        Finding::new(
                            Severity::Warning,
                            "disabled-but-owns-targets",
                            format!(
                                "state '{namespace}' is disabled but still records owned \
                                 targets it did not deliberately keep: {}",
                                unexpected.join(", ")
                            ),
                        )
                        .for_namespace(namespace)
                        .with_remedy(format!("re-run `malm state disable {namespace}`")),
                    );
                }
            }
        }
        _ => {
            let newest_completed = manifests_newest_first.iter().find(|manifest| {
                manifest.state_namespace() == namespace
                    && manifest.status == TransactionStatus::Completed
            });
            if let Some(manifest) = newest_completed
                && manifest.kind == TransactionKind::Disable
            {
                findings.push(
                    Finding::new(
                        Severity::Error,
                        "disable-incomplete",
                        format!(
                            "state '{namespace}' was disabled (transaction {}) but the \
                             disabled state record was never written",
                            transaction_alias(manifest.id.as_str())
                        ),
                    )
                    .for_namespace(namespace)
                    .for_transaction(manifest.id.as_str())
                    .with_remedy(format!("re-run `malm state disable {namespace}`")),
                );
            }
        }
    }
}

fn check_ownership_entry(
    namespace: &str,
    entry: &crate::state::ownership::OwnershipEntry,
    findings: &mut Vec<Finding>,
) {
    let target: &PathBuf = &entry.target;
    let metadata = match std::fs::symlink_metadata(target) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            findings.push(
                Finding::new(
                    Severity::Warning,
                    "ownership-target-missing",
                    format!(
                        "{} is owned by state '{namespace}' but missing from the filesystem",
                        target.display()
                    ),
                )
                .for_namespace(namespace)
                .with_remedy("re-run `malm apply` to redeploy it"),
            );
            return;
        }
        Err(error) => {
            findings.push(
                Finding::new(
                    Severity::Warning,
                    "ownership-target-unreadable",
                    format!(
                        "cannot inspect owned target {}: {error:#}",
                        target.display()
                    ),
                )
                .for_namespace(namespace),
            );
            return;
        }
    };

    match &entry.owner {
        OwnerKind::Asset { .. } => {}
        _ => {
            if !metadata.file_type().is_symlink() {
                findings.push(
                    Finding::new(
                        Severity::Warning,
                        "ownership-target-not-symlink",
                        format!(
                            "{} is owned by state '{namespace}' but is no longer a symlink",
                            target.display()
                        ),
                    )
                    .for_namespace(namespace)
                    .with_remedy("run `malm status` to inspect drift"),
                );
            } else if let Ok(actual) = std::fs::read_link(target)
                && actual != entry.source
            {
                findings.push(
                    Finding::new(
                        Severity::Warning,
                        "ownership-target-diverted",
                        format!(
                            "{} points at {} instead of the recorded source {}",
                            target.display(),
                            actual.display(),
                            entry.source.display()
                        ),
                    )
                    .for_namespace(namespace)
                    .with_remedy("run `malm status` to inspect drift"),
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finding_order_is_total_and_deterministic() {
        let mut findings = vec![
            Finding::new(Severity::Warning, "z", "same").for_namespace("b"),
            Finding::new(Severity::Error, "b", "error"),
            Finding::new(Severity::Warning, "a", "same").for_namespace("a"),
            Finding::new(Severity::Warning, "b", "same").for_namespace("a"),
        ];
        sort_findings(&mut findings);
        let keys: Vec<_> = findings
            .iter()
            .map(|finding| (finding.severity, finding.namespace.as_deref(), finding.code))
            .collect();
        assert_eq!(
            keys,
            vec![
                (Severity::Error, None, "b"),
                (Severity::Warning, Some("a"), "a"),
                (Severity::Warning, Some("a"), "b"),
                (Severity::Warning, Some("b"), "z"),
            ]
        );
    }
}
