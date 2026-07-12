//! Reports external includes and deduplicates findings.

use crate::config::{ConfigFileKind, ConfigFileProvenance};
use crate::policy::model::{PolicyFinding, PolicyFindingKind, PolicySeverity};
use std::path::PathBuf;

pub fn collect_external_include_findings(
    provenance: &[ConfigFileProvenance],
) -> Vec<PolicyFinding> {
    provenance
        .iter()
        .filter(|file| file.kind == ConfigFileKind::ExternalInclude)
        .map(|file| PolicyFinding {
            target: Some(file.path.clone()),
            owner: "local configuration include".to_owned(),
            category: PolicyFindingKind::LocalInclude,
            severity: PolicySeverity::Notice,
            reason: "reads configuration from this machine outside the remote repository",
            allow_flag: "",
        })
        .collect()
}

pub fn dedup_findings(violations: &mut Vec<PolicyFinding>) {
    let mut seen: std::collections::HashSet<(PolicyFindingKind, Option<PathBuf>, String)> =
        std::collections::HashSet::new();
    violations.retain(|v| seen.insert((v.category, v.target.clone(), v.owner.clone())));
}
