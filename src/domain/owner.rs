//! Persisted target owner kinds and the planning-only `Stale` wrapper.
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum OwnerKind {
    Dir { source: String },
    File { source: String },
    TemplateFile { source: String },
    TemplateDir { source: String },
    Symlink,
    Asset { name: String },
    Stale { previous: Box<OwnerKind> },
}

impl OwnerKind {
    pub fn label(&self) -> String {
        match self {
            Self::Dir { source } => format!("dir \"{source}\""),
            Self::File { source } => format!("file \"{source}\""),
            Self::TemplateFile { source } => format!("template-file \"{source}\""),
            Self::TemplateDir { source } => format!("template-dir \"{source}\""),
            Self::Symlink => "symlink".to_owned(),
            Self::Asset { name } => format!("asset \"{name}\""),
            Self::Stale { previous } => format!("stale (was: {})", previous.label()),
        }
    }

    // Stale is a planning-time wrapper and must never be written to state.
    pub fn persisted(&self) -> Option<Self> {
        match self {
            Self::Stale { .. } => None,
            owner => Some(owner.clone()),
        }
    }
}
