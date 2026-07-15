//! Owns the manifest, journal, and durable phase changes for a live apply.

use crate::assets::AssetDeclaration;
use crate::domain::owner::OwnerKind;
use crate::state::transaction::{
    ApplyPhase, OperationStatus, PreviousState, TransactionManifest, TransactionStatus,
    TransactionStore,
};
use anyhow::{Context, Result};
use std::path::{Path, PathBuf};

/// Owns a live transaction and its durable manifest. Every target mutation
/// must be journaled here *before* it happens so any crash remains recoverable.
pub(crate) struct ApplySession {
    manifest: TransactionManifest,
    store: TransactionStore,
}

impl ApplySession {
    /// Durably record the manifest, marking the transaction as started.
    pub fn begin(manifest: TransactionManifest, store: TransactionStore) -> Result<Self> {
        store
            .write(&manifest)
            .context("persist transaction manifest before applying")?;
        let mut session = Self { manifest, store };
        session
            .manifest
            .advance_phase(ApplyPhase::ManifestWritten)?;
        session.persist()?;
        Ok(session)
    }

    pub fn operation_count(&self) -> usize {
        self.manifest.operations.len()
    }

    pub fn alias(&self) -> String {
        crate::state::transaction::transaction_alias(self.manifest.id.as_str())
    }

    pub fn backup_path_for(&self, original: &Path) -> PathBuf {
        self.store
            .backup_path_for(self.manifest.id.as_str(), original)
    }

    /// Journal a symlink creation before touching `dst`.
    pub fn journal_symlink_started(
        &mut self,
        owner: OwnerKind,
        src: PathBuf,
        dst: PathBuf,
        previous: PreviousState,
    ) -> Result<usize> {
        let context = format!("persist journal before modifying {}", dst.display());
        let index = self
            .manifest
            .record_symlink_started(owner, src, dst, previous);
        self.append_journal(index, &context)
    }

    /// Journal a path removal before touching `path`.
    pub fn journal_remove_started(
        &mut self,
        owner: OwnerKind,
        path: PathBuf,
        previous: PreviousState,
    ) -> Result<usize> {
        let context = format!("persist journal before removing {}", path.display());
        let index = self.manifest.record_remove_started(owner, path, previous);
        self.append_journal(index, &context)
    }

    /// Journal an asset removal before touching `dst`.
    #[allow(clippy::too_many_arguments)]
    pub fn journal_remove_asset_started(
        &mut self,
        name: String,
        dst: PathBuf,
        payload: PathBuf,
        quarantine: PathBuf,
        original_mode: Option<u32>,
        original_device: Option<u64>,
        original_inode: Option<u64>,
    ) -> Result<usize> {
        let context = format!("persist journal before removing asset {name}");
        let index = self.manifest.record_remove_asset_started(
            name,
            dst,
            payload,
            quarantine,
            original_mode,
            original_device,
            original_inode,
        );
        self.append_journal(index, &context)
    }

    /// Journal an asset install before touching `dst`.
    #[allow(clippy::too_many_arguments)]
    pub fn journal_asset_started(
        &mut self,
        name: String,
        url: String,
        dst: PathBuf,
        payload: PathBuf,
        archive_sha256: Option<String>,
        declaration: Option<AssetDeclaration>,
        previous: PreviousState,
    ) -> Result<usize> {
        let context = format!("persist journal before installing asset {name}");
        let index = self.manifest.record_asset_started(
            name,
            url,
            dst,
            payload,
            archive_sha256,
            declaration,
            previous,
        );
        self.append_journal(index, &context)
    }

    fn append_journal(&mut self, index: usize, context: &str) -> Result<usize> {
        self.store
            .append_op(self.manifest.id.as_str(), &self.manifest.operations[index])
            .with_context(|| context.to_owned())?;
        Ok(index)
    }

    pub fn mark_operation(&mut self, index: usize, status: OperationStatus) {
        self.manifest.mark_operation(index, status);
    }

    /// Persist the manifest after a completed batch so op statuses are durable.
    pub fn persist_progress(&self) -> Result<()> {
        if self.manifest.operations.is_empty() {
            return Ok(());
        }
        self.store
            .write(&self.manifest)
            .context("persist transaction journal after batch")
    }

    fn persist(&self) -> Result<()> {
        self.store.write(&self.manifest)
    }

    /// Record a mid-apply failure durably; applied operations are kept.
    pub fn fail(&mut self) {
        self.manifest.status = TransactionStatus::Failed;
        let _ = self.persist();
    }

    /// Mark the filesystem fully applied, persist it, then drop the per-op
    /// journal. The manifest becomes the durable record.
    pub fn finish_filesystem_applied(mut self) -> Result<FinishedApply> {
        self.manifest.mark_filesystem_applied();
        self.store
            .write(&self.manifest)
            .context("persist filesystem-applied transaction manifest")?;
        self.store
            .clear_ops_log(self.manifest.id.as_str())
            .context("clear per-operation journal")?;
        Ok(FinishedApply {
            manifest: self.manifest,
        })
    }

    /// Abandon a transaction that turned out to record nothing.
    pub fn discard(self) -> Result<()> {
        std::fs::remove_dir_all(self.store.transaction_dir(self.manifest.id.as_str()))
            .context("remove empty transaction record")
    }
}

pub(crate) struct FinishedApply {
    pub manifest: TransactionManifest,
}
