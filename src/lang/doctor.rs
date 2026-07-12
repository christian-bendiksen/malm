//! Evaluates active modules' requirements without changing the system.

use crate::lang::ast::{Predicate, RequirementKind, RequirementNode};
use crate::lang::resolve::ResolvedWorkspace;
use crate::lang::typecheck::TypedProfile;
use crate::paths::expand_tilde;
use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequirementStatus {
    Satisfied,
    Missing,
    /// A declarative feature that Malm cannot probe.
    Unchecked,
}

#[derive(Debug)]
pub struct RequirementReport {
    pub kind: RequirementKind,
    pub subject: String,
    pub status: RequirementStatus,
    pub detail: Option<String>,
}

#[derive(Debug)]
pub struct DoctorReport {
    /// Requirement results keyed by instance alias.
    pub instances: BTreeMap<String, Vec<RequirementReport>>,
}

impl DoctorReport {
    pub fn missing_count(&self) -> usize {
        self.instances
            .values()
            .flatten()
            .filter(|r| r.status == RequirementStatus::Missing)
            .count()
    }
}

pub fn run_doctor(workspace: &ResolvedWorkspace, typed: &TypedProfile) -> DoctorReport {
    let mut report = DoctorReport {
        instances: BTreeMap::new(),
    };
    for instance in &typed.instances {
        let Some(module) = workspace.modules.get(&instance.module) else {
            continue;
        };
        let mut results = Vec::new();
        collect_requirements(module.requires(), instance, &mut results);
        if !results.is_empty() {
            report.instances.insert(instance.alias.clone(), results);
        }
    }
    report
}

fn collect_requirements(
    nodes: &[RequirementNode],
    instance: &crate::lang::typecheck::TypedInstance,
    results: &mut Vec<RequirementReport>,
) {
    for node in nodes {
        let requirement = match node {
            RequirementNode::Requirement(requirement) => requirement,
            RequirementNode::When(when) => {
                let branch = if evaluate_predicate(&when.predicate, instance) {
                    &when.then
                } else {
                    &when.otherwise
                };
                collect_requirements(branch, instance, results);
                continue;
            }
        };
        let (status, detail) = match requirement.kind {
            RequirementKind::Command => match find_in_path(&requirement.subject) {
                Some(path) => (
                    RequirementStatus::Satisfied,
                    Some(path.display().to_string()),
                ),
                None => (
                    RequirementStatus::Missing,
                    Some("not found or not executable in PATH".to_owned()),
                ),
            },
            RequirementKind::File => {
                let path = expand_tilde(&requirement.subject);
                if path.exists() {
                    (RequirementStatus::Satisfied, None)
                } else {
                    (
                        RequirementStatus::Missing,
                        Some(format!("{} does not exist", path.display())),
                    )
                }
            }
            RequirementKind::Feature => (RequirementStatus::Unchecked, None),
        };
        results.push(RequirementReport {
            kind: requirement.kind,
            subject: requirement.subject.clone(),
            status,
            detail,
        });
    }
}

fn evaluate_predicate(
    predicate: &Predicate,
    instance: &crate::lang::typecheck::TypedInstance,
) -> bool {
    let value = lookup_input(instance, &predicate.reference().name);
    match (predicate, value) {
        (Predicate::Test(_), Some(crate::lang::value::Value::Bool(value))) => *value,
        (Predicate::Set(_), Some(value)) => !value.is_null(),
        (Predicate::NonEmpty(_), Some(crate::lang::value::Value::List(values))) => {
            !values.is_empty()
        }
        (Predicate::NonEmpty(_), Some(crate::lang::value::Value::Collection(values))) => {
            !values.is_empty()
        }
        _ => false,
    }
}

fn lookup_input<'a>(
    instance: &'a crate::lang::typecheck::TypedInstance,
    name: &str,
) -> Option<&'a crate::lang::value::Value> {
    let (head, field) = name
        .split_once('.')
        .map_or((name, None), |(head, field)| (head, Some(field)));
    let value = &instance.values.get(head)?.0;
    match (value, field) {
        (crate::lang::value::Value::Record(record), Some(field)) => record.get(field),
        (_, None) => Some(value),
        _ => None,
    }
}

fn find_in_path(command: &str) -> Option<std::path::PathBuf> {
    // Commands containing a slash are paths, not PATH lookups.
    if command.contains('/') {
        let path = expand_tilde(command);
        return is_executable_file(&path).then_some(path);
    }
    let path_var = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path_var) {
        let candidate = dir.join(command);
        if is_executable_file(&candidate) {
            return Some(candidate);
        }
    }
    None
}

fn is_executable_file(path: &std::path::Path) -> bool {
    std::fs::metadata(path).is_ok_and(|metadata| metadata.is_file())
        && rustix::fs::accessat(
            rustix::fs::CWD,
            path,
            rustix::fs::Access::EXEC_OK,
            rustix::fs::AtFlags::EACCESS,
        )
        .is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn command_requirement_needs_an_executable_bit() {
        let dir = tempfile::tempdir().unwrap();
        let command = dir.path().join("tool");
        std::fs::write(&command, "#!/bin/sh\n").unwrap();
        std::fs::set_permissions(&command, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(!is_executable_file(&command));

        std::fs::set_permissions(&command, std::fs::Permissions::from_mode(0o744)).unwrap();
        assert!(is_executable_file(&command));
    }
}
