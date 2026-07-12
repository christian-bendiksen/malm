//! State consistency checks and mutation gates.
//!
//! Recovery rolls forward at or after `FilesystemApplied` to finish metadata
//! and activation. Before that phase, it undoes journaled operations in reverse.

pub mod checks;
pub mod preflight;
pub mod report;

use crate::state::transaction::{TransactionManifest, TransactionStore, transaction_alias};
use anyhow::Result;

/// Find interrupted transactions that must be rolled back before their targets
/// can be changed again.
pub fn rollback_needed_transactions(namespace: &str) -> Result<Vec<TransactionManifest>> {
    Ok(TransactionStore::new()
        .list_all()?
        .into_iter()
        .filter(|manifest| manifest.state_namespace() == namespace && manifest.needs_rollback())
        .collect())
}

/// Refuse a new mutation while an interrupted transaction has partially
/// applied filesystem changes. Transactions eligible for roll-forward do not
/// block re-apply, which is their supported recovery path.
pub fn ensure_no_rollback_needed(namespace: &str) -> Result<()> {
    let dirty = rollback_needed_transactions(namespace)?;
    if dirty.is_empty() {
        return Ok(());
    }
    let aliases: Vec<String> = dirty
        .iter()
        .map(|manifest| transaction_alias(manifest.id.as_str()))
        .collect();
    anyhow::bail!(
        "state '{namespace}' has {count} interrupted transaction{plural} with partially applied \
         filesystem changes ({list}); run `malm state recover {first}` to restore the previous \
         state before applying (`malm state fsck` shows details)",
        count = dirty.len(),
        plural = if dirty.len() == 1 { "" } else { "s" },
        list = aliases.join(", "),
        first = aliases[0],
    );
}
