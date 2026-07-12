//! Aborts execution when any policy finding is blocking.

use crate::policy::PolicyFinding;
use anyhow::Result;

pub(crate) fn reject_if_blocked(violations: &[PolicyFinding]) -> Result<()> {
    if violations.iter().any(|finding| finding.is_block()) {
        anyhow::bail!("blocked by remote policy");
    }
    Ok(())
}
