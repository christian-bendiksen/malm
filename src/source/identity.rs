//! Persisted local or Git source identity and its trust mode.

use crate::app::validation::{short_commit, validate_resolved_commit_sha};
use crate::source::git::redact_url;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SourceKind {
    Local { path: PathBuf },
    Git { url: String, commit: String },
}

impl SourceKind {
    pub fn display_label(&self) -> String {
        match self {
            Self::Local { path } => path.display().to_string(),
            Self::Git { url, commit } => {
                format!("{} @ {}", redact_url(url), short_commit(commit, 8))
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SourceIdentity {
    pub kind: SourceKind,
}

impl SourceIdentity {
    pub fn local(path: PathBuf) -> Self {
        Self {
            kind: SourceKind::Local { path },
        }
    }

    pub fn git(url: String, commit: String) -> Self {
        Self {
            kind: SourceKind::Git { url, commit },
        }
    }

    pub fn display_label(&self) -> String {
        self.kind.display_label()
    }

    /// Validate a persisted Git commit before displaying or abbreviating it.
    pub fn validate_persisted(&self) -> Result<()> {
        if let SourceKind::Git { commit, .. } = &self.kind {
            validate_resolved_commit_sha(commit)?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustMode {
    Trusted,
    Untrusted,
}

pub struct ResolvedSource {
    pub source_root: PathBuf,
    pub identity: SourceIdentity,
    pub trust_mode: TrustMode,
}

impl ResolvedSource {
    pub(crate) fn local(canonical: PathBuf) -> Self {
        Self {
            identity: SourceIdentity::local(canonical.clone()),
            source_root: canonical,
            trust_mode: TrustMode::Trusted,
        }
    }

    pub(crate) fn remote(source_root: PathBuf, identity: SourceIdentity) -> Self {
        Self {
            source_root,
            identity,
            trust_mode: TrustMode::Untrusted,
        }
    }
}
