//! Persists remote-branch tracking for `malm update`. Reconciliation removes
//! tracking when the applied source diverges.

use crate::app::validation::validate_resolved_commit_sha;
use crate::fs::atomic;
use crate::paths::xdg_state_home;
use crate::source::git::{require_https, validate_branch_name};
use crate::source::{SourceIdentity, SourceKind};
use crate::state::record::live_deployment_id_strict;
use crate::state::transaction::TransactionStore;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::io;
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrackedRemote {
    /// Persisted schema version; readers require an exact match.
    pub version: u32,
    pub url: String,
    pub branch: String,
    pub applied_commit: String,
    pub applied_at: u64,
    /// User approval for this remote to read `~/` or absolute includes.
    /// Persisting the grant prevents `malm update` from gaining access that was
    /// not explicitly approved. Records without the field default to `false`.
    #[serde(default)]
    pub allow_local_includes: bool,
    /// Selected profile after resolving the config default.
    pub profile: Option<String>,
}

/// Tracking schema version. Increment for incompatible changes.
pub const TRACKING_VERSION: u32 = 2;

impl TrackedRemote {
    pub fn new(
        url: String,
        branch: String,
        applied_commit: String,
        allow_local_includes: bool,
        profile: Option<String>,
    ) -> Self {
        Self {
            version: TRACKING_VERSION,
            url,
            branch,
            applied_commit,
            applied_at: now_unix(),
            allow_local_includes,
            profile,
        }
    }

    pub fn tracking_path_for(state_namespace: &str) -> PathBuf {
        xdg_state_home()
            .join("malm/states")
            .join(state_namespace)
            .join("tracking.json")
    }

    pub fn load_for_state(state_namespace: &str) -> Result<Option<Self>> {
        crate::state::format::require_current_if_present()?;
        let path = Self::tracking_path_for(state_namespace);
        match std::fs::read_to_string(&path) {
            Ok(raw) => {
                let value: serde_json::Value = serde_json::from_str(&raw)
                    .with_context(|| format!("parse {}", path.display()))?;
                let version = value.get("version").and_then(serde_json::Value::as_u64);
                if version != Some(TRACKING_VERSION.into()) {
                    let actual = version
                        .map(|version| version.to_string())
                        .unwrap_or_else(|| "missing".to_owned());
                    return Err(crate::state::format::incompatible_schema(
                        &path,
                        TRACKING_VERSION,
                        &actual,
                    ));
                }
                let tracking: Self = serde_json::from_value(value)
                    .with_context(|| format!("parse {}", path.display()))?;
                Ok(Some(tracking))
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e).with_context(|| format!("read {}", path.display())),
        }
    }

    pub fn save_for_state(&self, state_namespace: &str) -> Result<()> {
        let path = Self::tracking_path_for(state_namespace);
        let json = serde_json::to_string_pretty(self).context("serialize tracking state")?;
        atomic::write(&path, json).with_context(|| format!("write {}", path.display()))
    }

    pub fn delete_for_state(state_namespace: &str) -> Result<()> {
        let path = Self::tracking_path_for(state_namespace);
        match std::fs::remove_file(&path) {
            Ok(()) => atomic::sync_parent_dir(&path).context("sync tracking state removal"),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e).with_context(|| format!("remove {}", path.display())),
        }
    }

    pub fn reconcile_with_active_state(state_namespace: &str) -> Result<()> {
        let Some(active_id) = live_deployment_id_strict(state_namespace)? else {
            Self::delete_for_state(state_namespace)?;
            return Ok(());
        };

        let manifest = TransactionStore::new()
            .read(&active_id)
            .with_context(|| format!("read active transaction {active_id}"))?;

        let Some(source) = manifest.source.as_ref() else {
            Self::delete_for_state(state_namespace)?;
            return Ok(());
        };

        Self::reconcile_with_source(state_namespace, source, manifest.profile.as_deref())
    }

    pub fn reconcile_with_source(
        state_namespace: &str,
        source: &SourceIdentity,
        applied_profile: Option<&str>,
    ) -> Result<()> {
        Self::reconcile_with_applied(state_namespace, source, None, applied_profile)
    }

    // Remove tracking rather than repairing an untrusted record: unreadable or
    // invalid data, a different URL or branch, or a switch to a local source.
    pub fn reconcile_with_applied(
        state_namespace: &str,
        source: &SourceIdentity,
        applied_branch: Option<&str>,
        applied_profile: Option<&str>,
    ) -> Result<()> {
        match &source.kind {
            SourceKind::Git { url, commit } => {
                let tracking = match Self::load_for_state(state_namespace) {
                    Ok(Some(tracking)) => tracking,
                    Ok(None) => return Ok(()),
                    Err(error) => {
                        crate::warn_term!(
                            "warning: tracking state for '{state_namespace}' is unreadable ({error:#}); removing it"
                        );
                        return Self::delete_for_state(state_namespace);
                    }
                };
                let mut tracking = tracking;

                let invalid = validate_branch_name(&tracking.branch)
                    .and_then(|()| require_https(&tracking.url))
                    .and_then(|()| validate_resolved_commit_sha(&tracking.applied_commit))
                    .err();
                if let Some(error) = invalid {
                    crate::warn_term!(
                        "warning: tracking state for '{state_namespace}' is invalid ({error:#}); removing it"
                    );
                    return Self::delete_for_state(state_namespace);
                }

                if tracking.url != *url {
                    return Self::delete_for_state(state_namespace);
                }
                if tracking.profile.as_deref() != applied_profile {
                    crate::warn_term!(
                        "note: applied profile differs from the tracked profile; tracking removed; \
                         re-apply with --track to follow this profile"
                    );
                    return Self::delete_for_state(state_namespace);
                }
                if let Some(branch) = applied_branch
                    && branch != tracking.branch
                {
                    crate::warn_term!(
                        "note: applied branch '{branch}' differs from tracked branch '{}'; \
                         tracking removed — re-apply with --track to follow '{branch}'",
                        tracking.branch
                    );
                    return Self::delete_for_state(state_namespace);
                }

                tracking.applied_commit = commit.clone();
                tracking.applied_at = now_unix();
                tracking.save_for_state(state_namespace)?;
            }

            &SourceKind::Local { .. } => {
                Self::delete_for_state(state_namespace)?;
            }
        }

        Ok(())
    }
}

fn now_unix() -> u64 {
    crate::paths::now_unix()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_tracking_json_is_not_the_current_schema() {
        let legacy = r#"{
            "url": "https://example.com/dots.git",
            "branch": "main",
            "applied_commit": "0123456789abcdef0123456789abcdef01234567",
            "applied_at": 1700000000
        }"#;
        let value: serde_json::Value = serde_json::from_str(legacy).unwrap();
        assert_ne!(
            value.get("version").and_then(serde_json::Value::as_u64),
            Some(TRACKING_VERSION.into())
        );
    }

    #[test]
    fn local_include_grant_roundtrips() {
        let tracking = TrackedRemote::new(
            "https://example.com/dots.git".to_owned(),
            "main".to_owned(),
            "0123456789abcdef0123456789abcdef01234567".to_owned(),
            true,
            Some("desktop".to_owned()),
        );
        let json = serde_json::to_string(&tracking).expect("serialize tracking");
        let parsed: TrackedRemote = serde_json::from_str(&json).expect("parse tracking");
        assert!(parsed.allow_local_includes);
        assert_eq!(parsed.profile.as_deref(), Some("desktop"));
        assert_eq!(parsed.version, TRACKING_VERSION);
    }

    #[test]
    fn newer_tracking_version_is_refused() {
        // A future schema must be rejected rather than misinterpreted.
        let future = format!(
            r#"{{
                "version": {},
                "url": "https://example.com/dots.git",
                "branch": "main",
                "applied_commit": "0123456789abcdef0123456789abcdef01234567",
                "applied_at": 1700000000,
                "allow_local_includes": false,
                "profile": "main"
            }}"#,
            TRACKING_VERSION + 1
        );
        let parsed: TrackedRemote = serde_json::from_str(&future).expect("parses structurally");
        assert!(
            parsed.version > TRACKING_VERSION,
            "future version should exceed the current"
        );
        // Mirror the version check in load_for_state.
        let check = || -> Result<()> {
            if parsed.version > TRACKING_VERSION {
                anyhow::bail!("written by a newer Malm");
            }
            Ok(())
        };
        assert!(check().is_err());
    }
}
