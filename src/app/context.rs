//! Global CLI options shared by workflows.
use crate::domain::id::StateName;
use std::path::PathBuf;

#[derive(Clone)]
pub struct GlobalCtx {
    pub repo: Option<PathBuf>,
    pub config: Option<PathBuf>,
    pub profile: Option<String>,
    pub state_namespace: StateName,
    pub json: bool,
    /// Allow asset downloads from private, loopback, link-local, or internal hosts.
    /// Off by default to stop remote configs reaching metadata or internal services.
    pub allow_ssrf: bool,
}
