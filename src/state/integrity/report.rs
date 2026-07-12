//! Finding model for `state fsck`: severity, stable codes, and remedies.

use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    /// Informational; nothing needs to happen.
    Notice,
    /// Inconsistent but self-healing or cosmetic.
    Warning,
    /// Needs `state recover` or manual attention.
    Error,
}

/// One fsck finding. `code` is a stable machine-readable identifier;
/// `remedy` is the command or action that fixes it.
#[derive(Debug, Serialize)]
pub struct Finding {
    pub severity: Severity,
    pub code: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transaction: Option<String>,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remedy: Option<String>,
}

impl Finding {
    pub fn new(severity: Severity, code: &'static str, message: impl Into<String>) -> Self {
        Self {
            severity,
            code,
            namespace: None,
            transaction: None,
            message: message.into(),
            remedy: None,
        }
    }

    pub fn for_namespace(mut self, namespace: &str) -> Self {
        self.namespace = Some(namespace.to_owned());
        self
    }

    pub fn for_transaction(mut self, id: &str) -> Self {
        self.transaction = Some(id.to_owned());
        self
    }

    pub fn with_remedy(mut self, remedy: impl Into<String>) -> Self {
        self.remedy = Some(remedy.into());
        self
    }
}
