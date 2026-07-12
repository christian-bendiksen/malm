//! Stores each state's mode in `states/<ns>/state.json`. Enabled states have a
//! live deployment, disabled states can be restored, and destroyed records
//! exist only until the state directory is removed.
//!
//! Transaction status belongs only to the manifest. Resolution checks the
//! record against the journal and falls back to the previous completed
//! deployment if a crash occurred after writing the record but before
//! `mark_completed`.

use crate::fs::atomic;
use crate::paths::{now_unix, xdg_state_home};
use crate::state::transaction::{TransactionStatus, TransactionStore, transaction_alias};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::io;
use std::path::PathBuf;

pub const STATE_RECORD_VERSION: u32 = 2;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateRecord {
    pub version: u32,
    #[serde(flatten)]
    pub mode: StateMode,
    pub updated_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum StateMode {
    /// Has a live deployment.
    Enabled { live_transaction: String },
    /// Has no deployed targets, but retains the records needed for
    /// `state enable` to restore `restore_transaction`.
    Disabled {
        restore_transaction: String,
        disabled_at: u64,
        /// Targets retained by `state disable --keep-modified`. Their ownership
        /// records must remain intact.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        kept_targets: Vec<PathBuf>,
    },
    /// Covers the crash window between finalizing destroy and removing the
    /// state directory.
    Destroyed {
        destroy_transaction: Option<String>,
        destroyed_at: u64,
    },
}

impl StateMode {
    pub fn enabled(live_transaction: impl Into<String>) -> Self {
        Self::Enabled {
            live_transaction: live_transaction.into(),
        }
    }

    pub fn disabled(restore_transaction: impl Into<String>, kept_targets: Vec<PathBuf>) -> Self {
        Self::Disabled {
            restore_transaction: restore_transaction.into(),
            disabled_at: now_unix(),
            kept_targets,
        }
    }

    pub fn destroyed(destroy_transaction: Option<String>) -> Self {
        Self::Destroyed {
            destroy_transaction,
            destroyed_at: now_unix(),
        }
    }
}

fn state_dir(state_namespace: &str) -> PathBuf {
    xdg_state_home().join("malm/states").join(state_namespace)
}

pub fn record_path(state_namespace: &str) -> PathBuf {
    state_dir(state_namespace).join("state.json")
}

impl StateRecord {
    pub fn load_for_state(state_namespace: &str) -> Result<Option<Self>> {
        crate::state::format::require_current_if_present()?;
        let path = record_path(state_namespace);
        match std::fs::read_to_string(&path) {
            Ok(raw) => {
                let value: serde_json::Value = serde_json::from_str(&raw)
                    .with_context(|| format!("parse {}", path.display()))?;
                let version = value.get("version").and_then(serde_json::Value::as_u64);
                if version != Some(STATE_RECORD_VERSION.into()) {
                    let actual = version
                        .map(|version| version.to_string())
                        .unwrap_or_else(|| "missing".to_owned());
                    return Err(crate::state::format::incompatible_schema(
                        &path,
                        STATE_RECORD_VERSION,
                        &actual,
                    ));
                }
                let record: Self = serde_json::from_value(value)
                    .with_context(|| format!("parse {}", path.display()))?;
                Ok(Some(record))
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e).with_context(|| format!("read {}", path.display())),
        }
    }

    pub fn set(state_namespace: &str, mode: StateMode) -> Result<()> {
        let record = Self {
            version: STATE_RECORD_VERSION,
            mode,
            updated_at: now_unix(),
        };
        let path = record_path(state_namespace);
        let json = serde_json::to_string_pretty(&record).context("serialize state record")?;
        atomic::write(&path, json).with_context(|| format!("write {}", path.display()))
    }
}

/// Return the live deployment, or `None` for disabled and destroyed states.
///
/// If an enabled record names an incomplete transaction, fall back to the
/// newest completed deployment. This covers a crash between writing the record
/// and `mark_completed`, keeping the previous deployment authoritative until
/// recovery finishes. Disabled and destroyed states never use this fallback.
pub fn live_deployment_id(state_namespace: &str) -> Result<Option<String>> {
    match StateRecord::load_for_state(state_namespace)? {
        Some(record) => match record.mode {
            StateMode::Disabled { .. } | StateMode::Destroyed { .. } => Ok(None),
            StateMode::Enabled { live_transaction } => {
                match TransactionStore::new().read(&live_transaction) {
                    Ok(manifest)
                        if manifest.status == TransactionStatus::Completed
                            && manifest.kind.deploys() =>
                    {
                        Ok(Some(live_transaction))
                    }
                    Ok(_) => latest_completed_apply_id(state_namespace),
                    Err(error)
                        if error.chain().any(|cause| {
                            cause
                                .downcast_ref::<io::Error>()
                                .is_some_and(|io_error| io_error.kind() == io::ErrorKind::NotFound)
                        }) =>
                    {
                        latest_completed_apply_id(state_namespace)
                    }
                    Err(error) => {
                        crate::warn_term!(
                            "warning: live transaction {live_transaction} for state \
                             {state_namespace:?} is unreadable ({error:#}); falling back to \
                             the journal"
                        );
                        latest_completed_apply_id(state_namespace)
                    }
                }
            }
        },
        None => latest_completed_apply_id(state_namespace),
    }
}

/// Resolve the live deployment for mutation. Unlike [`live_deployment_id`], an
/// enabled record naming anything but a completed deployment is an error that
/// requires recovery. Read-only commands use the lenient resolver so they work
/// during a transition.
///
/// A missing record still falls back to the journal for compatibility with the
/// pre-record layout; it is not treated as a crash state.
pub fn live_deployment_id_strict(state_namespace: &str) -> Result<Option<String>> {
    match StateRecord::load_for_state(state_namespace)? {
        Some(record) => match record.mode {
            StateMode::Disabled { .. } | StateMode::Destroyed { .. } => Ok(None),
            StateMode::Enabled { live_transaction } => {
                let mid_transition = |detail: String| {
                    anyhow::anyhow!(
                        "state '{state_namespace}' is mid-transition: its record points at \
                         transaction {} ({detail}); run `malm state recover {}` to finish or \
                         undo it (`malm state doctor` inspects without changing anything)",
                        transaction_alias(&live_transaction),
                        transaction_alias(&live_transaction),
                    )
                };
                match TransactionStore::new().read(&live_transaction) {
                    Ok(manifest)
                        if manifest.status == TransactionStatus::Completed
                            && manifest.kind.deploys() =>
                    {
                        Ok(Some(live_transaction))
                    }
                    Ok(manifest) => Err(mid_transition(format!(
                        "status '{}', kind '{}'",
                        manifest.status.label(),
                        manifest.kind.label()
                    ))),
                    Err(error) => Err(mid_transition(format!("unreadable: {error:#}"))),
                }
            }
        },
        None => latest_completed_apply_id(state_namespace),
    }
}

/// Return the deployment that `state enable` would restore.
pub fn restore_deployment_id(state_namespace: &str) -> Result<Option<String>> {
    Ok(match StateRecord::load_for_state(state_namespace)? {
        Some(StateRecord {
            mode:
                StateMode::Disabled {
                    restore_transaction,
                    ..
                },
            ..
        }) => Some(restore_transaction),
        _ => None,
    })
}

/// Return the newest completed deployment in the journal. This is historical;
/// use [`live_deployment_id`] for current liveness.
pub fn latest_completed_apply_id(state_namespace: &str) -> Result<Option<String>> {
    if !state_dir(state_namespace).is_dir() {
        return Ok(None);
    }
    Ok(TransactionStore::new()
        .list_all()?
        .into_iter()
        .rev()
        .find(|m| {
            m.state_namespace() == state_namespace
                && m.status == TransactionStatus::Completed
                && m.kind.deploys()
        })
        .map(|m| m.id.as_str().to_owned()))
}

/// Return the live deployment's source snapshot.
pub fn live_source_snapshot_id(state_namespace: &str) -> Result<Option<String>> {
    let Some(id) = live_deployment_id(state_namespace)? else {
        return Ok(None);
    };
    let manifest = TransactionStore::new().read(&id)?;
    Ok(Some(manifest.source_snapshot_id.as_str().to_owned()))
}

/// Strict variant of [`live_source_snapshot_id`]; see
/// [`live_deployment_id_strict`].
pub fn live_source_snapshot_id_strict(state_namespace: &str) -> Result<Option<String>> {
    let Some(id) = live_deployment_id_strict(state_namespace)? else {
        return Ok(None);
    };
    let manifest = TransactionStore::new().read(&id)?;
    Ok(Some(manifest.source_snapshot_id.as_str().to_owned()))
}
