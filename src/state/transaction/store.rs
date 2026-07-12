//! On-disk transaction storage. Manifests are atomic, operation journals are
//! append-only and fsynced, and reads validate versions before replaying
//! journaled operations.

use crate::app::validation::validate_name;
use crate::cas::validate_object_id;
use crate::fs::atomic;
use crate::paths::xdg_state_home;
use crate::state::transaction::{
    ApplyPhase, MIN_SUPPORTED_MANIFEST_VERSION, RecordedOp, TRANSACTION_MANIFEST_VERSION,
    TransactionManifest, transaction_alias,
};
use anyhow::{Context, Result};
use std::io::Write;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct TransactionStore {
    root: PathBuf,
}

impl Default for TransactionStore {
    fn default() -> Self {
        Self {
            root: transactions_dir(),
        }
    }
}

impl TransactionStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn transaction_dir(&self, id: &str) -> PathBuf {
        self.root.join(id)
    }

    // Remove the root and parent components so backups stay inside the
    // transaction directory.
    pub fn backup_path_for(&self, id: &str, original: &Path) -> PathBuf {
        let relative = original.strip_prefix("/").unwrap_or(original);
        let sanitized: PathBuf = relative
            .components()
            .filter(|c| !matches!(c, std::path::Component::ParentDir))
            .collect();
        self.transaction_dir(id).join("backups").join(sanitized)
    }

    pub fn write(&self, manifest: &TransactionManifest) -> Result<()> {
        let dir = self.transaction_dir(manifest.id.as_str());
        std::fs::create_dir_all(&dir)
            .with_context(|| format!("create transaction dir {}", dir.display()))?;
        let path = dir.join("manifest.json");
        let json = serde_json::to_string_pretty(manifest).context("serialize manifest")?;
        atomic::write(&path, json).with_context(|| format!("write {}", path.display()))
    }

    fn ops_log_path(&self, id: &str) -> PathBuf {
        self.transaction_dir(id).join("ops.jsonl")
    }

    pub fn append_op(&self, id: &str, op: &RecordedOp) -> Result<()> {
        let path = self.ops_log_path(id);
        let mut line = serde_json::to_string(op).context("serialize journaled operation")?;
        line.push('\n');
        // The first write syncs the file, then best-effort syncs its parent so
        // the directory entry survives a crash. Later appends use sync_data.
        let is_new = std::fs::symlink_metadata(&path).is_err();
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .with_context(|| format!("open {}", path.display()))?;
        file.write_all(line.as_bytes())
            .with_context(|| format!("append to {}", path.display()))?;
        if is_new {
            file.sync_all()
                .with_context(|| format!("sync {}", path.display()))?;
            if let Some(parent) = path.parent()
                && let Ok(dir) = std::fs::File::open(parent)
            {
                let _ = dir.sync_all();
            }
        } else {
            file.sync_data()
                .with_context(|| format!("sync {}", path.display()))?;
        }
        Ok(())
    }

    pub fn clear_ops_log(&self, id: &str) -> Result<()> {
        match std::fs::remove_file(self.ops_log_path(id)) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error).context("remove operation journal"),
        }
    }

    fn journaled_ops_beyond(&self, id: &str, known: usize) -> Result<Vec<RecordedOp>> {
        let path = self.ops_log_path(id);
        let raw = match std::fs::read_to_string(&path) {
            Ok(raw) => raw,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => return Err(error).with_context(|| format!("read {}", path.display())),
        };
        let lines: Vec<&str> = raw.lines().collect();
        let mut extra = Vec::new();
        for (index, line) in lines.iter().enumerate().skip(known) {
            match serde_json::from_str::<RecordedOp>(line) {
                Ok(op) => extra.push(op),
                // Ignore a torn final append after a crash. Invalid complete or
                // non-final lines indicate corruption.
                Err(_) if index == lines.len() - 1 && !raw.ends_with('\n') => break,
                Err(error) => {
                    return Err(error)
                        .with_context(|| format!("parse {} line {}", path.display(), index + 1));
                }
            }
        }
        Ok(extra)
    }

    pub fn read(&self, id: &str) -> Result<TransactionManifest> {
        crate::state::format::require_current_if_present()?;
        validate_name(id, "transaction id")?;
        let path = self.transaction_dir(id).join("manifest.json");
        let raw =
            std::fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?;
        let value: serde_json::Value = serde_json::from_str(&raw).context("parse manifest JSON")?;
        let version = value.get("version").and_then(serde_json::Value::as_u64);
        let supported =
            u64::from(MIN_SUPPORTED_MANIFEST_VERSION)..=u64::from(TRANSACTION_MANIFEST_VERSION);
        if !version.is_some_and(|version| supported.contains(&version)) {
            let actual = version
                .map(|value| value.to_string())
                .unwrap_or_else(|| "missing".to_owned());
            return Err(crate::state::format::incompatible_schema(
                &path,
                TRANSACTION_MANIFEST_VERSION,
                &actual,
            ));
        }
        let mut manifest: TransactionManifest =
            serde_json::from_value(value).context("parse transaction manifest")?;
        validate_object_id(manifest.source_snapshot_id.as_str())
            .context("transaction manifest has an invalid source snapshot id")?;
        if let Some(source) = &manifest.source {
            source
                .validate_persisted()
                .context("transaction manifest has an invalid source identity")?;
        }
        manifest
            .operations
            .extend(self.journaled_ops_beyond(id, manifest.operations.len())?);
        if manifest.id.as_str() != id {
            anyhow::bail!(
                "transaction manifest id mismatch in {}: expected {id:?}, got {:?}",
                path.display(),
                manifest.id
            );
        }
        Ok(manifest)
    }

    pub fn resolve_reference(&self, reference: &str) -> Result<String> {
        validate_name(reference, "transaction reference")?;
        if !self.root.exists() {
            anyhow::bail!("no transactions exist");
        }
        if self.transaction_dir(reference).exists() {
            return Ok(reference.to_owned());
        }

        let mut transaction_ids = Vec::new();
        for entry in std::fs::read_dir(&self.root).context("read transactions dir")? {
            let name = entry?.file_name().to_string_lossy().into_owned();
            transaction_ids.push(name);
        }

        let full_id_matches = transaction_ids
            .iter()
            .filter(|id| id.starts_with(reference))
            .cloned()
            .collect::<Vec<_>>();
        if !full_id_matches.is_empty() {
            return resolve_matches(reference, full_id_matches);
        }

        let alias_matches = transaction_ids
            .into_iter()
            .filter(|id| transaction_alias(id).starts_with(reference))
            .collect::<Vec<_>>();
        resolve_matches(reference, alias_matches)
    }

    pub fn list_all(&self) -> Result<Vec<TransactionManifest>> {
        if !self.root.exists() {
            return Ok(Vec::new());
        }
        let mut entries = Vec::new();
        for entry in std::fs::read_dir(&self.root)
            .with_context(|| format!("read {}", self.root.display()))?
        {
            let entry = entry.with_context(|| format!("read entry in {}", self.root.display()))?;
            let manifest = entry.path().join("manifest.json");
            match std::fs::symlink_metadata(&manifest) {
                Ok(_) => entries.push(entry),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => {
                    return Err(error).with_context(|| format!("inspect {}", manifest.display()));
                }
            }
        }
        entries.sort_by_key(std::fs::DirEntry::file_name);
        let mut manifests = Vec::new();
        for entry in &entries {
            let name = entry.file_name();
            let Some(id) = name.to_str() else {
                crate::warn_term!(
                    "warning: skipping transaction with a non-UTF-8 directory name: {name:?}"
                );
                continue;
            };
            match self.read(id) {
                Ok(manifest) => manifests.push(manifest),
                Err(error) => {
                    crate::warn_term!("warning: skipping unreadable transaction {id}: {error:#}");
                }
            }
        }
        Ok(manifests)
    }

    /// List transactions without skipping unreadable or misnamed entries.
    /// Destructive callers must use this because an unreadable transaction
    /// cannot mark its objects, and deleting around it could lose data.
    pub fn list_all_strict(&self) -> Result<Vec<TransactionManifest>> {
        let entries = match std::fs::read_dir(&self.root) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => {
                return Err(error).with_context(|| format!("read {}", self.root.display()));
            }
        };
        let mut manifests = Vec::new();
        for entry in entries {
            let entry = entry.with_context(|| format!("read entry in {}", self.root.display()))?;
            let name = entry.file_name();
            let id = name.to_str().ok_or_else(|| {
                anyhow::anyhow!("transaction directory has a non-UTF-8 name: {name:?}")
            })?;
            match std::fs::symlink_metadata(entry.path().join("manifest.json")) {
                Ok(_) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => {
                    return Err(error)
                        .with_context(|| format!("inspect manifest for transaction {id}"));
                }
            }
            manifests.push(
                self.read(id)
                    .with_context(|| format!("read transaction {id}"))?,
            );
        }
        Ok(manifests)
    }

    pub fn has_transactions(&self) -> Result<bool> {
        let entries = match std::fs::read_dir(&self.root) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(error) => {
                return Err(error).with_context(|| format!("read {}", self.root.display()));
            }
        };
        for entry in entries {
            let entry = entry.with_context(|| format!("read entry in {}", self.root.display()))?;
            if entry.path().join("manifest.json").is_file() {
                return Ok(true);
            }
        }
        Ok(false)
    }

    pub fn update(&self, id: &str, update: impl FnOnce(&mut TransactionManifest)) -> Result<()> {
        let mut manifest = self.read(id)?;
        update(&mut manifest);
        self.write(&manifest)
    }

    pub fn mark_completed(&self, id: &str) -> Result<()> {
        self.update(id, TransactionManifest::mark_completed)
    }

    pub fn mark_metadata_failed(&self, id: &str) -> Result<()> {
        self.update(id, TransactionManifest::mark_metadata_failed)
    }

    /// Durably advance the apply phase. Backward transitions are rejected.
    pub fn advance_phase(&self, id: &str, phase: ApplyPhase) -> Result<()> {
        let mut manifest = self.read(id)?;
        manifest.advance_phase(phase)?;
        self.write(&manifest)
    }
}

fn resolve_matches(reference: &str, mut matches: Vec<String>) -> Result<String> {
    match matches.len() {
        0 => anyhow::bail!("transaction '{reference}' not found"),
        1 => Ok(matches.pop().unwrap()),
        _ => {
            matches.sort();
            let candidates = matches
                .iter()
                .map(|candidate| format!("  {}  {candidate}", transaction_alias(candidate)))
                .collect::<Vec<_>>()
                .join("\n");
            anyhow::bail!(
                "transaction reference '{reference}' is ambiguous\n\
                 The candidates are (alias, full ID):\n{candidates}"
            )
        }
    }
}

pub fn transactions_dir() -> PathBuf {
    xdg_state_home().join("malm/transactions")
}
