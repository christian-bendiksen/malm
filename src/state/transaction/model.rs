//! Transaction manifest and recovery state. Recovery rolls forward at or after
//! `FilesystemApplied` and rolls back before it.

use crate::assets::AssetDeclaration;
use crate::config::ConfigFileProvenance;
use crate::domain::id::{ObjectId, TransactionId};
use crate::domain::owner::OwnerKind;
use crate::policy::RemotePolicyOverrides;
use crate::source::SourceIdentity;
use crate::state::ownership::OwnershipEntry;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

pub const TRANSACTION_MANIFEST_VERSION: u32 = 5;
pub const MIN_SUPPORTED_MANIFEST_VERSION: u32 = TRANSACTION_MANIFEST_VERSION;

/// The last durable apply step. Recovery rolls forward from
/// `FilesystemApplied` or later and rolls back before it.
///
/// `status` is for display and GC; `phase` controls recovery.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum ApplyPhase {
    Prepared,
    ManifestWritten,
    FilesystemApplied,
    MetadataCommitted,
    ActivePointerSwapped,
    Completed,
}

impl ApplyPhase {
    pub fn label(self) -> &'static str {
        match self {
            Self::Prepared => "prepared",
            Self::ManifestWritten => "manifest-written",
            Self::FilesystemApplied => "filesystem-applied",
            Self::MetadataCommitted => "metadata-committed",
            Self::ActivePointerSwapped => "active-pointer-swapped",
            Self::Completed => "completed",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DesiredAsset {
    pub name: String,
    pub target: PathBuf,
    pub source: PathBuf,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transaction: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub declaration: Option<AssetDeclaration>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DesiredLink {
    pub target: PathBuf,
    pub source: PathBuf,
    pub owner: OwnerKind,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TransactionKind {
    #[default]
    Apply,
    Destroy,
    /// Removes targets but keeps the records needed by `malm state enable`.
    Disable,
}

/// Whether recovery rewrites ownership metadata. Source anchors preserve the
/// existing metadata; repairs rewrite it even for an empty desired state.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ApplyMetadataIntent {
    Rewrite,
    Preserve,
}

impl TransactionKind {
    /// Return whether completion leaves a live deployment. Destroy and disable
    /// remove targets, so neither can be active.
    pub fn deploys(self) -> bool {
        matches!(self, Self::Apply)
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Apply => "apply",
            Self::Destroy => "destroy",
            Self::Disable => "disable",
        }
    }
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TransactionStatus {
    Started,
    FilesystemApplied,
    MetadataFailed,
    #[default]
    Completed,
    Failed,
    /// All applied operations were undone by recovery; GC may collect it.
    RolledBack,
}

impl TransactionStatus {
    pub fn label(self) -> &'static str {
        match self {
            Self::Started => "started",
            Self::FilesystemApplied => "filesystem-applied",
            Self::MetadataFailed => "metadata-failed",
            Self::Completed => "completed",
            Self::Failed => "failed",
            Self::RolledBack => "rolled-back",
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PathKind {
    #[default]
    File,
    Directory,
    Symlink,
    Other,
}

impl PathKind {
    pub fn of(file_type: std::fs::FileType) -> Self {
        if file_type.is_symlink() {
            Self::Symlink
        } else if file_type.is_dir() {
            Self::Directory
        } else if file_type.is_file() {
            Self::File
        } else {
            Self::Other
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum PreviousState {
    #[default]
    Missing,
    #[serde(rename = "file")]
    Backed {
        backup: PathBuf,
        #[serde(default)]
        path_kind: PathKind,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        original_mode: Option<u32>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        original_device: Option<u64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        original_inode: Option<u64>,
    },
    Symlink {
        old_target: PathBuf,
    },
    BrokenSymlink {
        old_target: PathBuf,
    },
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum OperationStatus {
    Started,
    #[default]
    Applied,
    Failed,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RecordedOp {
    CreateSymlink {
        status: OperationStatus,
        owner: OwnerKind,
        src: PathBuf,
        dst: PathBuf,
        previous: PreviousState,
    },
    RemovePath {
        status: OperationStatus,
        owner: OwnerKind,
        path: PathBuf,
        previous: PreviousState,
    },
    InstallAsset {
        status: OperationStatus,
        name: String,
        url: String,
        dst: PathBuf,
        previous: PreviousState,
        payload: PathBuf,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        archive_sha256: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        declaration: Option<AssetDeclaration>,
    },
    /// An asset removed by disable or destroy. `payload` is the CAS object
    /// verified at `dst` before removal, so rollback can reinstall it.
    /// `quarantine` records the tree renamed into the transaction backup;
    /// rollback prefers that exact tree. Older manifests have no quarantine.
    RemoveAsset {
        status: OperationStatus,
        name: String,
        dst: PathBuf,
        payload: PathBuf,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        quarantine: Option<PathBuf>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        original_mode: Option<u32>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        original_device: Option<u64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        original_inode: Option<u64>,
    },
}

impl RecordedOp {
    pub fn status(&self) -> OperationStatus {
        match self {
            Self::CreateSymlink { status, .. }
            | Self::RemovePath { status, .. }
            | Self::InstallAsset { status, .. }
            | Self::RemoveAsset { status, .. } => *status,
        }
    }

    pub fn previous(&self) -> &PreviousState {
        match self {
            Self::CreateSymlink { previous, .. } => previous,
            Self::RemovePath { previous, .. } => previous,
            Self::InstallAsset { previous, .. } => previous,
            // The CAS payload represents the removed content, so there is no
            // separate previous-state record.
            Self::RemoveAsset { .. } => &PreviousState::Missing,
        }
    }
}

pub(crate) fn now_unix() -> u64 {
    crate::paths::now_unix()
}

#[derive(Debug)]
pub struct TransactionMeta {
    pub id: TransactionId,
    pub kind: TransactionKind,
    pub repo: Option<PathBuf>,
    pub source_snapshot_id: ObjectId,
    pub config: Option<PathBuf>,
    pub profile: Option<String>,
    pub state_namespace: Option<String>,
    pub source: Option<SourceIdentity>,
    pub allow: RemotePolicyOverrides,
    pub config_files: Vec<ConfigFileProvenance>,
    /// Deployment restored by `state enable`. Keeping it in a disable manifest
    /// lets recovery finish writing the disabled state after a crash.
    pub restore_transaction: Option<String>,
    /// Targets left by `--keep-modified`, whose ownership remains recorded.
    pub kept_targets: Vec<PathBuf>,
    /// Whether config loading allowed local includes. Re-applying the snapshot
    /// preserves this grant instead of becoming permissive by default.
    pub allow_local_includes: bool,
    pub metadata_intent: ApplyMetadataIntent,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TransactionManifest {
    pub version: u32,
    pub id: TransactionId,
    #[serde(default)]
    pub kind: TransactionKind,
    pub status: TransactionStatus,
    pub repo: Option<PathBuf>,
    pub config: Option<PathBuf>,
    pub profile: Option<String>,
    pub state_namespace: Option<String>,
    pub source: Option<SourceIdentity>,
    pub allow: RemotePolicyOverrides,
    #[serde(default)]
    pub config_files: Vec<ConfigFileProvenance>,
    pub malm_version: String,
    pub started_at: u64,
    pub completed_at: Option<u64>,
    pub operations: Vec<RecordedOp>,
    #[serde(default)]
    pub desired_assets: Vec<DesiredAsset>,
    #[serde(default)]
    pub desired_links: Vec<DesiredLink>,
    /// Modified, undeclared targets that remain owned. Recovery must restore
    /// this metadata even though no filesystem operation records it.
    pub retained_ownership: Vec<OwnershipEntry>,
    pub source_snapshot_id: ObjectId,
    /// Durable recovery progress. Pre-v3 manifests omit it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub phase: Option<ApplyPhase>,
    /// Deployment restored by `state enable` after disable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub restore_transaction: Option<String>,
    /// Targets deliberately left in place by disable.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub kept_targets: Vec<PathBuf>,
    /// Whether config loading allowed local includes. Older manifests default
    /// to `false`; tracked re-apply also honors the `TrackedRemote` grant.
    #[serde(default, skip_serializing_if = "core::ops::Not::not")]
    pub allow_local_includes: bool,
    /// Recovery behavior for applies with no filesystem operations.
    pub metadata_intent: ApplyMetadataIntent,
}

pub(crate) fn malm_version() -> String {
    env!("CARGO_PKG_VERSION").to_owned()
}

impl TransactionManifest {
    pub fn new(id: TransactionId, meta: TransactionMeta) -> Self {
        Self {
            version: TRANSACTION_MANIFEST_VERSION,
            id,
            kind: meta.kind,
            status: TransactionStatus::Started,
            source_snapshot_id: meta.source_snapshot_id,
            repo: meta.repo,
            config: meta.config,
            profile: meta.profile,
            state_namespace: meta.state_namespace,
            source: meta.source,
            allow: meta.allow,
            config_files: meta.config_files,
            malm_version: malm_version(),
            started_at: now_unix(),
            completed_at: None,
            operations: Vec::new(),
            desired_assets: Vec::new(),
            desired_links: Vec::new(),
            retained_ownership: Vec::new(),
            phase: Some(ApplyPhase::Prepared),
            restore_transaction: meta.restore_transaction,
            kept_targets: meta.kept_targets,
            allow_local_includes: meta.allow_local_includes,
            metadata_intent: meta.metadata_intent,
        }
    }

    /// Return the phase used for recovery. For pre-v3 manifests, `Completed`
    /// and `RolledBack` map to `Completed`; filesystem-applied and
    /// metadata-failed map to `FilesystemApplied`; started and failed map to
    /// `ManifestWritten`.
    pub fn effective_phase(&self) -> ApplyPhase {
        if let Some(phase) = self.phase {
            return phase;
        }
        match self.status {
            TransactionStatus::Completed | TransactionStatus::RolledBack => ApplyPhase::Completed,
            TransactionStatus::FilesystemApplied | TransactionStatus::MetadataFailed => {
                ApplyPhase::FilesystemApplied
            }
            TransactionStatus::Started | TransactionStatus::Failed => ApplyPhase::ManifestWritten,
        }
    }

    /// Advance the recovery phase, rejecting backward transitions.
    pub fn advance_phase(&mut self, phase: ApplyPhase) -> anyhow::Result<()> {
        let current = self.effective_phase();
        if phase < current {
            anyhow::bail!(
                "transaction {} phase may not move backwards ({} -> {})",
                self.id,
                current.label(),
                phase.label()
            );
        }
        self.phase = Some(phase);
        Ok(())
    }

    pub fn state_namespace(&self) -> &str {
        self.state_namespace.as_deref().unwrap_or("default")
    }

    // Keep transactions while recovery may need their journal, backups, or
    // applied filesystem state.
    pub fn requires_recovery_retention(&self) -> bool {
        match self.status {
            TransactionStatus::FilesystemApplied | TransactionStatus::MetadataFailed => true,
            TransactionStatus::Started | TransactionStatus::Failed => {
                self.operations.iter().any(|operation| {
                    matches!(
                        operation.status(),
                        OperationStatus::Started | OperationStatus::Applied
                    ) || matches!(operation.previous(), PreviousState::Backed { .. })
                })
            }
            TransactionStatus::Completed | TransactionStatus::RolledBack => false,
        }
    }

    /// Return whether recovery must undo a partially applied filesystem before
    /// another apply can touch the same targets.
    pub fn needs_rollback(&self) -> bool {
        matches!(
            self.status,
            TransactionStatus::Started | TransactionStatus::Failed
        ) && self.effective_phase() < ApplyPhase::FilesystemApplied
            && self.requires_recovery_retention()
    }

    /// Return whether the filesystem is complete but recovery must finish the
    /// durable metadata and activation steps.
    pub fn needs_roll_forward(&self) -> bool {
        matches!(
            self.status,
            TransactionStatus::FilesystemApplied | TransactionStatus::MetadataFailed
        ) && self.effective_phase() >= ApplyPhase::FilesystemApplied
            && self.effective_phase() < ApplyPhase::Completed
    }

    pub fn mark_completed(&mut self) {
        self.status = TransactionStatus::Completed;
        self.completed_at = Some(now_unix());
        if self.phase.is_some() {
            self.phase = Some(ApplyPhase::Completed);
        }
    }

    pub fn mark_filesystem_applied(&mut self) {
        self.status = TransactionStatus::FilesystemApplied;
        if self.phase.is_some() {
            self.phase = Some(ApplyPhase::FilesystemApplied);
        }
    }

    pub fn mark_metadata_failed(&mut self) {
        self.status = TransactionStatus::MetadataFailed;
    }

    pub fn record_symlink_started(
        &mut self,
        owner: OwnerKind,
        src: PathBuf,
        dst: PathBuf,
        previous: PreviousState,
    ) -> usize {
        self.operations.push(RecordedOp::CreateSymlink {
            status: OperationStatus::Started,
            owner,
            src,
            dst,
            previous,
        });
        self.operations.len() - 1
    }

    pub fn record_remove_started(
        &mut self,
        owner: OwnerKind,
        path: PathBuf,
        previous: PreviousState,
    ) -> usize {
        self.operations.push(RecordedOp::RemovePath {
            status: OperationStatus::Started,
            owner,
            path,
            previous,
        });
        self.operations.len() - 1
    }

    #[allow(clippy::too_many_arguments)]
    pub fn record_remove_asset_started(
        &mut self,
        name: String,
        dst: PathBuf,
        payload: PathBuf,
        quarantine: PathBuf,
        original_mode: Option<u32>,
        original_device: Option<u64>,
        original_inode: Option<u64>,
    ) -> usize {
        self.operations.push(RecordedOp::RemoveAsset {
            status: OperationStatus::Started,
            name,
            dst,
            payload,
            quarantine: Some(quarantine),
            original_mode,
            original_device,
            original_inode,
        });
        self.operations.len() - 1
    }

    #[allow(clippy::too_many_arguments)]
    pub fn record_asset_started(
        &mut self,
        name: String,
        url: String,
        dst: PathBuf,
        payload: PathBuf,
        archive_sha256: Option<String>,
        declaration: Option<AssetDeclaration>,
        previous: PreviousState,
    ) -> usize {
        self.operations.push(RecordedOp::InstallAsset {
            status: OperationStatus::Started,
            name,
            url,
            dst,
            previous,
            payload,
            archive_sha256,
            declaration,
        });
        self.operations.len() - 1
    }

    pub fn mark_operation(&mut self, index: usize, status: OperationStatus) {
        match self.operations.get_mut(index) {
            Some(RecordedOp::CreateSymlink {
                status: op_status, ..
            })
            | Some(RecordedOp::RemovePath {
                status: op_status, ..
            }) => *op_status = status,
            Some(RecordedOp::InstallAsset {
                status: op_status, ..
            })
            | Some(RecordedOp::RemoveAsset {
                status: op_status, ..
            }) => *op_status = status,
            None => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_meta() -> TransactionMeta {
        TransactionMeta {
            id: TransactionId::new("test-tx".to_owned()).unwrap(),
            kind: TransactionKind::Apply,
            repo: None,
            source_snapshot_id: ObjectId::parse(
                "sha256-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            )
            .unwrap(),
            config: None,
            profile: None,
            state_namespace: None,
            source: None,
            allow: RemotePolicyOverrides::default(),
            config_files: Vec::new(),
            restore_transaction: None,
            kept_targets: Vec::new(),
            allow_local_includes: false,
            metadata_intent: ApplyMetadataIntent::Rewrite,
        }
    }

    fn manifest_with(status: TransactionStatus, phase: Option<ApplyPhase>) -> TransactionManifest {
        let mut manifest = TransactionManifest::new(
            TransactionId::new("test-tx".to_owned()).unwrap(),
            test_meta(),
        );
        manifest.status = status;
        manifest.phase = phase;
        manifest
    }

    #[test]
    fn phase_only_moves_forward() {
        let mut manifest = manifest_with(
            TransactionStatus::Started,
            Some(ApplyPhase::FilesystemApplied),
        );
        manifest
            .advance_phase(ApplyPhase::MetadataCommitted)
            .unwrap();
        assert!(
            manifest.advance_phase(ApplyPhase::ManifestWritten).is_err(),
            "backwards transition must fail"
        );
    }

    #[test]
    fn v2_manifests_derive_a_conservative_phase() {
        assert_eq!(
            manifest_with(TransactionStatus::Failed, None).effective_phase(),
            ApplyPhase::ManifestWritten
        );
        assert_eq!(
            manifest_with(TransactionStatus::MetadataFailed, None).effective_phase(),
            ApplyPhase::FilesystemApplied
        );
        assert_eq!(
            manifest_with(TransactionStatus::Completed, None).effective_phase(),
            ApplyPhase::Completed
        );
    }

    #[test]
    fn recovery_direction_follows_the_filesystem_applied_boundary() {
        let mut mid_crash = manifest_with(
            TransactionStatus::Started,
            Some(ApplyPhase::ManifestWritten),
        );
        mid_crash.record_symlink_started(
            OwnerKind::Symlink,
            PathBuf::from("/src"),
            PathBuf::from("/dst"),
            PreviousState::Missing,
        );
        assert!(mid_crash.needs_rollback());
        assert!(!mid_crash.needs_roll_forward());

        let post_fs = manifest_with(
            TransactionStatus::FilesystemApplied,
            Some(ApplyPhase::FilesystemApplied),
        );
        assert!(!post_fs.needs_rollback());
        assert!(post_fs.needs_roll_forward());

        let rolled_back = manifest_with(TransactionStatus::RolledBack, None);
        assert!(!rolled_back.needs_rollback());
        assert!(!rolled_back.needs_roll_forward());
        assert!(!rolled_back.requires_recovery_retention());
    }

    /// Older manifests must default to no local-include grant, while an
    /// explicit grant must survive serialization.
    #[test]
    fn local_include_grant_defaults_closed_and_round_trips() {
        let ungranted = manifest_with(TransactionStatus::Completed, None);
        let json = serde_json::to_string(&ungranted).unwrap();
        assert!(
            !json.contains("allow_local_includes"),
            "false is not serialized: {json}"
        );
        let parsed: TransactionManifest = serde_json::from_str(&json).unwrap();
        assert!(!parsed.allow_local_includes);

        let granted = TransactionManifest::new(
            TransactionId::new("test-tx".to_owned()).unwrap(),
            TransactionMeta {
                allow_local_includes: true,
                ..test_meta()
            },
        );
        let json = serde_json::to_string(&granted).unwrap();
        let parsed: TransactionManifest = serde_json::from_str(&json).unwrap();
        assert!(parsed.allow_local_includes);
    }

    #[test]
    fn previous_state_file_defaults_path_kind_for_old_manifests() {
        let old = r#"{"kind":"file","backup":"/tmp/b"}"#;
        let previous: PreviousState = serde_json::from_str(old).unwrap();
        assert!(matches!(
            previous,
            PreviousState::Backed {
                path_kind: PathKind::File,
                ..
            }
        ));
        let json = serde_json::to_value(&previous).unwrap();
        assert_eq!(json["kind"], "file");
    }

    #[test]
    fn path_kind_of_file_types() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("f");
        std::fs::write(&file, "x").unwrap();
        let link = dir.path().join("l");
        std::os::unix::fs::symlink(&file, &link).unwrap();

        let kind =
            |p: &std::path::Path| PathKind::of(std::fs::symlink_metadata(p).unwrap().file_type());
        assert_eq!(kind(&file), PathKind::File);
        assert_eq!(kind(dir.path()), PathKind::Directory);
        assert_eq!(kind(&link), PathKind::Symlink);
    }
}
