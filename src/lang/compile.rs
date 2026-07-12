//! Compiles profiles into in-memory generated outputs without filesystem
//! mutation.

use crate::lang::budget::{Budget, Limits};
use crate::lang::diag::{Diagnostic, Diagnostics, codes};
use crate::lang::expand::{Expander, GeneratedArtifacts};
use crate::lang::resolve::ResolvedWorkspace;
use crate::lang::scope::Scope;
use crate::lang::typecheck::{TypedProfile, check_profile};
use crate::lang::value::Value;
use std::collections::HashMap;

/// Everything the planner needs from one compiled profile.
pub struct CompiledProfile {
    pub generated: GeneratedArtifacts,
    /// The typed instances, for consumers that report values (vars, doctor).
    #[allow(dead_code)]
    pub typed: TypedProfile,
}

pub struct CompileOptions {
    pub target_root: String,
    /// `machine.hostname`, when known (trusted local runs only).
    pub hostname: Option<String>,
    /// Refuse render-time source files that resolve outside `source_root`.
    pub restrict_source_root: bool,
    pub limits: Limits,
}

/// Compile one profile: resolve, type-check, instantiate isolated scopes,
/// expand structural nodes, generate and validate artifacts.
pub fn compile_profile(
    workspace: &ResolvedWorkspace,
    profile_name: &str,
    options: &CompileOptions,
    diagnostics: &mut Diagnostics,
) -> Option<CompiledProfile> {
    compile_profile_instances(workspace, profile_name, options, diagnostics, None)
}

/// Compile only instances of one module within a profile. Profile resolution
/// and input checking still cover the complete profile, but expansion and
/// artifact validation are scoped to the requested module API.
pub fn compile_profile_module(
    workspace: &ResolvedWorkspace,
    profile_name: &str,
    module_name: &str,
    options: &CompileOptions,
    diagnostics: &mut Diagnostics,
) -> Option<CompiledProfile> {
    compile_profile_instances(
        workspace,
        profile_name,
        options,
        diagnostics,
        Some(module_name),
    )
}

fn compile_profile_instances(
    workspace: &ResolvedWorkspace,
    profile_name: &str,
    options: &CompileOptions,
    diagnostics: &mut Diagnostics,
    module_filter: Option<&str>,
) -> Option<CompiledProfile> {
    let Some(typed) = check_profile(workspace, profile_name, diagnostics) else {
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
        // Do not expand a profile with type errors.
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
            budget: &mut budget,
            diagnostics,
            restrict_source_root: options.restrict_source_root,
        };
        expander.expand_instance(module, instance, &mut scope, &mut generated);
    }

    // Validate generated artifact formats.
    for artifact in &generated.artifacts {
        for validator in &artifact.validators {
            for problem in crate::lang::artifact::validate_format(validator, &artifact.content) {
                diagnostics.push(
                    Diagnostic::error(
                        codes::ARTIFACT_VALIDATE,
                        format!(
                            "generated {} is not valid {validator}: {problem}",
                            artifact.to
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
    }

    // Check destinations across every output kind.
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
