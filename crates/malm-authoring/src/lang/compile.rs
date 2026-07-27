//! Compiles profiles into in-memory generated outputs without filesystem
//! mutation.

use crate::lang::budget::{Budget, Limits};
use crate::lang::diag::{Diagnostic, Diagnostics, codes};
use crate::lang::expand::{Expander, GeneratedArtifacts};
use crate::lang::resolve::ResolvedWorkspace;
use crate::lang::scope::Scope;
use crate::lang::typecheck::{CheckOptions, TypedProfile, check_profile};
use crate::lang::value::Value;
use std::collections::HashMap;

/// Everything the planner needs from one compiled profile.
pub struct CompiledProfile {
    pub generated: GeneratedArtifacts,
    /// Typed instances used by variable and requirement reports.
    #[allow(dead_code)]
    pub typed: TypedProfile,
}

pub struct CompileOptions {
    pub target_root: String,
    /// `machine.hostname`, when known (trusted local runs only).
    pub hostname: Option<String>,
    pub limits: Limits,
}

/// Compiles one profile by resolving and checking its inputs, expanding its
/// structural nodes, and validating the generated artifacts.
pub fn compile_profile(
    workspace: &ResolvedWorkspace,
    sources: &crate::AuthoringSourceSetV1,
    profile_name: &str,
    options: &CompileOptions,
    diagnostics: &mut Diagnostics,
) -> Option<CompiledProfile> {
    compile_profile_instances(workspace, sources, profile_name, options, diagnostics, None)
}

/// Compile only instances of one module within a profile. Profile resolution
/// and input checking still cover the complete profile, but expansion and
/// artifact validation are scoped to the requested module API.
#[allow(dead_code)]
pub fn compile_profile_module(
    workspace: &ResolvedWorkspace,
    sources: &crate::AuthoringSourceSetV1,
    profile_name: &str,
    module_name: &str,
    options: &CompileOptions,
    diagnostics: &mut Diagnostics,
) -> Option<CompiledProfile> {
    compile_profile_instances(
        workspace,
        sources,
        profile_name,
        options,
        diagnostics,
        Some(module_name),
    )
}

/// Collects the profile's requirement subjects across every instance,
/// honoring conditional `@if` guards against the resolved inputs, sorted
/// unique.
fn aggregated_requirements(workspace: &ResolvedWorkspace, typed: &TypedProfile) -> Vec<String> {
    use crate::lang::ast::{Predicate, RequirementNode};
    use crate::lang::value::Value;

    fn lookup<'a>(
        instance: &'a crate::lang::typecheck::TypedInstance,
        name: &str,
    ) -> Option<&'a Value> {
        if let Some((value, _)) = instance.values.get(name) {
            return Some(value);
        }
        let (input, value) = instance
            .values
            .iter()
            .filter(|(input, _)| {
                name.starts_with(input.as_str()) && name.as_bytes().get(input.len()) == Some(&b'.')
            })
            .max_by_key(|(input, _)| input.len())?;
        value.0.get_path(&name[input.len() + 1..])
    }

    fn holds(predicate: &Predicate, instance: &crate::lang::typecheck::TypedInstance) -> bool {
        let value = lookup(instance, &predicate.reference().name);
        predicate.eval(value).unwrap_or(false)
    }

    fn collect(
        nodes: &[RequirementNode],
        instance: &crate::lang::typecheck::TypedInstance,
        subjects: &mut Vec<String>,
    ) {
        for node in nodes {
            match node {
                RequirementNode::Requirement(requirement) => {
                    subjects.push(requirement.subject.clone());
                }
                RequirementNode::When(when) => {
                    let branch = if holds(&when.predicate, instance) {
                        &when.then
                    } else {
                        &when.otherwise
                    };
                    collect(branch, instance, subjects);
                }
            }
        }
    }

    let mut subjects = Vec::new();
    for instance in &typed.instances {
        let module = workspace
            .modules
            .get(&instance.module)
            .expect("typed instances reference known modules");
        collect(module.requires(), instance, &mut subjects);
    }
    subjects.sort();
    subjects.dedup();
    subjects
}

fn compile_profile_instances(
    workspace: &ResolvedWorkspace,
    sources: &crate::AuthoringSourceSetV1,
    profile_name: &str,
    options: &CompileOptions,
    diagnostics: &mut Diagnostics,
    module_filter: Option<&str>,
) -> Option<CompiledProfile> {
    let check_options = CheckOptions {
        target_root: &options.target_root,
        hostname: options.hostname.as_deref(),
        limits: options.limits,
    };
    let Some(typed) = check_profile(workspace, sources, profile_name, diagnostics, check_options)
    else {
        diagnostics.error(
            codes::UNKNOWN_PROFILE,
            format!(
                "profile `{profile_name}` not found (known profiles: {})",
                workspace.profile_names().join(", ")
            ),
        );
        return None;
    };
    if diagnostics.has_errors() {
        return Some(CompiledProfile {
            generated: GeneratedArtifacts::default(),
            typed,
        });
    }

    let globals: HashMap<String, Value> = workspace
        .globals
        .iter()
        .map(|(name, var)| (name.clone(), var.value.clone()))
        .collect();

    let profile_requirements = aggregated_requirements(workspace, &typed);
    let profile_names: Vec<String> = workspace
        .profiles
        .iter()
        .filter(|profile| !profile.abstract_)
        .map(|profile| profile.name.clone())
        .collect();
    let mut budget = Budget::new(options.limits);
    let mut generated = GeneratedArtifacts::default();
    for instance in &typed.instances {
        if module_filter.is_some_and(|module| instance.module != module) {
            continue;
        }
        if budget.exhausted() {
            break;
        }
        let module = workspace
            .modules
            .get(&instance.module)
            .expect("typed instances reference known modules");

        let mut builtins: HashMap<String, Value> = HashMap::new();
        builtins.insert(
            "malm.target".to_owned(),
            Value::String(options.target_root.clone()),
        );
        builtins.insert(
            "profile.name".to_owned(),
            Value::String(profile_name.to_owned()),
        );
        builtins.insert(
            "machine.hostname".to_owned(),
            options
                .hostname
                .as_ref()
                .map_or(Value::Null, |hostname| Value::String(hostname.clone())),
        );
        builtins.insert(
            "instance.name".to_owned(),
            Value::String(instance.alias.clone()),
        );
        builtins.insert(
            "instance.module".to_owned(),
            Value::String(instance.module.clone()),
        );

        let inputs: HashMap<String, Value> = instance
            .values
            .iter()
            .map(|(name, (value, _origin))| (name.clone(), value.clone()))
            .collect();

        let mut scope = Scope::new(inputs, globals.clone(), builtins);
        let mut expander = Expander {
            workspace,
            sources,
            profile_requirements: &profile_requirements,
            profile_names: &profile_names,
            budget: &mut budget,
            diagnostics,
        };
        expander.expand_instance(module, instance, &mut scope, &mut generated);
    }

    for artifact in &generated.artifacts {
        let crate::lang::artifact::ArtifactContent::Bytes(content) = &artifact.content else {
            continue;
        };
        for problem in crate::lang::artifact::validate_format(&artifact.format, content) {
            diagnostics.push(
                Diagnostic::error(
                    codes::ARTIFACT_VALIDATE,
                    format!(
                        "generated {} is not valid {}: {problem}",
                        artifact.to, artifact.format
                    ),
                )
                .with_span(artifact.span)
                .with_note(format!(
                    "generated by module `{}` (instance `{}`)",
                    artifact.module, artifact.instance
                )),
            );
        }
    }

    let mut seen: HashMap<String, (String, crate::lang::diag::Span)> = HashMap::new();
    let mut conflict = |to: &str,
                        instance: &str,
                        span: crate::lang::diag::Span,
                        diagnostics: &mut Diagnostics| {
        if let Some((previous, previous_span)) = seen.get(to) {
            diagnostics.push(
                Diagnostic::error(
                    codes::DEST_CONFLICT,
                    format!(
                        "profile `{profile_name}`: two outputs write to `{to}` (instances `{previous}` and `{instance}`)"
                    ),
                )
                .with_span(span)
                .with_label("first destination declared here", *previous_span),
            );
        } else {
            seen.insert(to.to_owned(), (instance.to_owned(), span));
        }
    };
    for artifact in &generated.artifacts {
        conflict(&artifact.to, &artifact.instance, artifact.span, diagnostics);
    }
    for file in &generated.files {
        conflict(&file.to, &file.instance, file.span, diagnostics);
    }
    for symlink in &generated.symlinks {
        conflict(&symlink.to, &symlink.instance, symlink.span, diagnostics);
    }

    Some(CompiledProfile { generated, typed })
}
