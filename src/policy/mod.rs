//! Classifies plans and config declarations into blocking or advisory findings.

mod advisory;
mod asset_policy;
pub mod destination;
mod findings;
pub mod model;
pub mod overrides;
pub mod remote_safety;
pub mod risk;
pub mod source_escape;

pub use asset_policy::collect_asset_declaration_findings;
pub use findings::{collect_external_include_findings, dedup_findings};
pub use model::PolicyFinding;
pub use overrides::RemotePolicyOverrides;
pub use remote_safety::collect_remote_policy_findings;
pub use source_escape::source_escapes_source_root;
