//! Lists per-namespace state summaries, including partially unreadable records.

use crate::app::context::GlobalCtx;
use crate::output::state_list::render;
use crate::source::SourceIdentity;
use crate::state::ownership::unix_to_iso8601;
use crate::state::ownership_store::read_ownership_for;
use crate::state::pins::read_pins;
use crate::state::record::{StateMode, StateRecord};
use crate::state::state_namespaces;
use crate::state::tracking::TrackedRemote;
use crate::state::transaction::{TransactionManifest, TransactionStatus, TransactionStore};
use anyhow::Result;
use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StateStatus {
    Deployed,
    Disabled,
    Incomplete,
    Failed,
    Empty,
    Broken,
}

#[derive(Debug, Serialize)]
pub struct StateSummary {
    pub name: String,
    pub selected: bool,
    pub status: StateStatus,
    pub active_transaction: Option<String>,
    pub transactions: usize,
    pub targets: Option<usize>,
    pub pins: usize,
    pub source: Option<SourceIdentity>,
    pub tracking: Option<TrackedRemote>,
    pub last_applied: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

pub fn run(ctx: &GlobalCtx) -> Result<()> {
    let names = state_namespaces()?;
    let manifests = TransactionStore::new().list_all()?;
    let summaries: Vec<StateSummary> = names
        .into_iter()
        .map(|name| summarize(name, ctx.state_namespace.as_str(), &manifests))
        .collect();
    render(ctx, &summaries)
}

fn summarize(name: String, selected: &str, manifests: &[TransactionManifest]) -> StateSummary {
    let mut error = None;
    // Display the first read error, but attempt every field so one bad record
    // does not blank the row.
    let mut record_error = |e: anyhow::Error| {
        if error.is_none() {
            error = Some(format!("{e:#}"));
        }
    };

    // The state record names the live/restore transaction; the manifest is
    // the status authority.
    let (mut status, active_transaction) = match StateRecord::load_for_state(&name) {
        Ok(Some(record)) => match record.mode {
            StateMode::Enabled { live_transaction } => {
                let status = manifests
                    .iter()
                    .find(|m| m.id.as_str() == live_transaction.as_str())
                    .map(|m| deployment_status(m.status))
                    .unwrap_or_else(|| {
                        record_error(anyhow::anyhow!(
                            "state record references missing transaction {live_transaction}"
                        ));
                        StateStatus::Broken
                    });
                (status, Some(live_transaction))
            }
            StateMode::Disabled {
                restore_transaction,
                ..
            } => (StateStatus::Disabled, Some(restore_transaction)),
            StateMode::Destroyed { .. } => (StateStatus::Empty, None),
        },
        Ok(None) => (StateStatus::Empty, None),
        Err(e) => {
            record_error(e);
            (StateStatus::Broken, None)
        }
    };

    let stats = tx_stats(&name, active_transaction.as_deref(), manifests);

    let targets = match read_ownership_for(&name) {
        Ok(index) => Some((index.entries.len(), index.source)),
        Err(e) => {
            record_error(e);
            if !matches!(status, StateStatus::Failed | StateStatus::Broken) {
                status = StateStatus::Broken;
            }
            None
        }
    };
    let (targets, ownership_source) = match targets {
        Some((count, source)) => (Some(count), source),
        None => (None, None),
    };

    let tracking = match TrackedRemote::load_for_state(&name) {
        Ok(tracking) => tracking,
        Err(e) => {
            record_error(e);
            None
        }
    };

    let pins = match read_pins(&name) {
        Ok(pins) => pins.len(),
        Err(e) => {
            record_error(e);
            0
        }
    };

    StateSummary {
        selected: name == selected,
        status,
        active_transaction,
        transactions: stats.count,
        targets,
        pins,
        source: stats.source.or(ownership_source),
        tracking,
        last_applied: stats.last_applied.map(unix_to_iso8601),
        error,
        name,
    }
}

fn deployment_status(status: TransactionStatus) -> StateStatus {
    match status {
        TransactionStatus::Completed => StateStatus::Deployed,
        TransactionStatus::Started | TransactionStatus::FilesystemApplied => {
            StateStatus::Incomplete
        }
        TransactionStatus::Failed
        | TransactionStatus::MetadataFailed
        | TransactionStatus::RolledBack => StateStatus::Failed,
    }
}

struct TxStats {
    count: usize,
    last_applied: Option<u64>,
    source: Option<SourceIdentity>,
}

fn tx_stats(name: &str, active_id: Option<&str>, manifests: &[TransactionManifest]) -> TxStats {
    let owned: Vec<&TransactionManifest> = manifests
        .iter()
        .filter(|m| m.state_namespace() == name)
        .collect();
    let newest_completed = owned
        .iter()
        .filter(|m| m.status == TransactionStatus::Completed && m.kind.deploys())
        .max_by_key(|m| m.completed_at.unwrap_or(m.started_at));
    let source = active_id
        .and_then(|id| owned.iter().find(|m| m.id.as_str() == id))
        .or(newest_completed)
        .and_then(|m| m.source.clone());
    TxStats {
        count: owned.len(),
        last_applied: newest_completed.map(|m| m.completed_at.unwrap_or(m.started_at)),
        source,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::source::SourceKind;
    use crate::state::transaction::{TransactionKind, TransactionMeta};

    fn manifest(
        id: &str,
        namespace: &str,
        status: TransactionStatus,
        completed_at: Option<u64>,
    ) -> TransactionManifest {
        let mut manifest = TransactionManifest::new(
            crate::domain::id::TransactionId::new(id.to_owned()).unwrap(),
            TransactionMeta {
                id: crate::domain::id::TransactionId::new(id.to_owned()).unwrap(),
                kind: TransactionKind::Apply,
                repo: None,
                source_snapshot_id: crate::domain::id::ObjectId::parse(
                    "sha256-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                )
                .unwrap(),
                config: None,
                profile: None,
                state_namespace: Some(namespace.to_owned()),
                source: None,
                allow: crate::policy::RemotePolicyOverrides::default(),
                config_files: Vec::new(),
                restore_transaction: None,
                kept_targets: Vec::new(),
                allow_local_includes: false,
                metadata_intent: crate::state::transaction::ApplyMetadataIntent::Rewrite,
            },
        );
        manifest.status = status;
        manifest.completed_at = completed_at;
        manifest
    }

    #[test]
    fn deployment_status_mapping() {
        assert_eq!(
            deployment_status(TransactionStatus::Completed),
            StateStatus::Deployed
        );
        assert_eq!(
            deployment_status(TransactionStatus::Started),
            StateStatus::Incomplete
        );
        assert_eq!(
            deployment_status(TransactionStatus::FilesystemApplied),
            StateStatus::Incomplete
        );
        assert_eq!(
            deployment_status(TransactionStatus::Failed),
            StateStatus::Failed
        );
        assert_eq!(
            deployment_status(TransactionStatus::MetadataFailed),
            StateStatus::Failed
        );
    }

    #[test]
    fn tx_stats_filters_namespace_and_ignores_incomplete() {
        let mut destroy = manifest("e", "work", TransactionStatus::Completed, Some(500));
        destroy.kind = TransactionKind::Destroy;
        let manifests = vec![
            manifest("a", "work", TransactionStatus::Completed, Some(100)),
            manifest("b", "work", TransactionStatus::Completed, Some(300)),
            manifest("c", "work", TransactionStatus::Failed, None),
            manifest("d", "other", TransactionStatus::Completed, Some(900)),
            destroy,
        ];
        let stats = tx_stats("work", None, &manifests);
        assert_eq!(stats.count, 4);
        assert_eq!(stats.last_applied, Some(300), "destroy is not an apply");

        let stats = tx_stats("missing", None, &manifests);
        assert_eq!(stats.count, 0);
        assert_eq!(stats.last_applied, None);
        assert!(stats.source.is_none());
    }

    #[test]
    fn tx_stats_prefers_active_transaction_source() {
        let mut old = manifest("a", "work", TransactionStatus::Completed, Some(100));
        old.source = Some(SourceIdentity::local("/old".into()));
        let mut new = manifest("b", "work", TransactionStatus::Completed, Some(200));
        new.source = Some(SourceIdentity::local("/new".into()));
        let manifests = vec![old, new];

        let source = tx_stats("work", Some("a"), &manifests).source.unwrap();
        assert!(matches!(
            source.kind,
            SourceKind::Local { ref path } if path.as_os_str() == "/old"
        ));

        let source = tx_stats("work", None, &manifests).source.unwrap();
        assert!(matches!(
            source.kind,
            SourceKind::Local { ref path } if path.as_os_str() == "/new"
        ));
    }

    #[test]
    fn summary_serializes_expected_json_shape() {
        let summary = StateSummary {
            name: "work".to_owned(),
            selected: true,
            status: StateStatus::Deployed,
            active_transaction: Some("tx-1".to_owned()),
            transactions: 2,
            targets: Some(4),
            pins: 0,
            source: None,
            tracking: None,
            last_applied: Some("2026-07-02T00:00:00Z".to_owned()),
            error: None,
        };
        let value = serde_json::to_value(&summary).unwrap();
        assert_eq!(value["name"], "work");
        assert_eq!(value["status"], "deployed");
        assert_eq!(value["targets"], 4);
        assert!(value.get("error").is_none());
    }
}
