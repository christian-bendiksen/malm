//! Static checks for every module and profile, including defaults, references,
//! control flow, profile overrides, patches, and fragment sources.

use crate::lang::ast::{
    FragmentCardinality, FragmentOp, KdlConfigBody, OutputNode, PatchOp, Predicate, Ref,
    RequirementNode,
};
use crate::lang::config_file::{ConfigItem, ConfigValue};
use crate::lang::diag::{Diagnostic, Diagnostics, FileId, Span, codes};
use crate::lang::kdl_util::{
    entry_span, node_span, parse_condition, parse_each_header, parse_range_header, parse_splice,
};
use crate::lang::resolve::{ResolvedModule, ResolvedWorkspace, resolve_profile};
use crate::lang::value::{Record, RecordSchema, Type, Value, exact_i64_to_f64};
use crate::paths::{expand_tilde, normalize_lexical};
use kdl::{KdlDocument, KdlNode};
use std::collections::HashMap;
use std::path::Path;

/// Names visible to `(ref)` lookups, mapped to their types.
pub(crate) struct TypeEnv<'a> {
    module: &'a ResolvedModule,
    workspace: &'a ResolvedWorkspace,
    /// Loop bindings, innermost last.
    bindings: Vec<(String, Type)>,
    /// References proven non-null by enclosing `when-set` then branches.
    refinements: Vec<String>,
}

impl<'a> TypeEnv<'a> {
    pub(crate) fn new(workspace: &'a ResolvedWorkspace, module: &'a ResolvedModule) -> Self {
        Self {
            module,
            workspace,
            bindings: Vec::new(),
            refinements: Vec::new(),
        }
    }

    /// Resolve a reference type. Dotted input and binding names address record
    /// fields; `global.*` and built-ins are namespaces.
    pub(crate) fn lookup(&self, name: &str) -> Option<Type> {
        if let Some((_, ty)) = self.bindings.iter().rev().find(|(n, _)| n == name) {
            return Some(self.refine(name, ty.clone()));
        }
        if let Some((head, field)) = name.split_once('.')
            && let Some((_, Type::Record(schema))) =
                self.bindings.iter().rev().find(|(n, _)| n == head)
        {
            return schema.field(field).map(|field_schema| {
                let ty = if field_schema.required {
                    field_schema.ty.clone()
                } else {
                    Type::Optional(Box::new(field_schema.ty.clone()))
                };
                self.refine(name, ty)
            });
        }
        if let Some(var) = self.workspace.globals.get(name) {
            return Some(scalar_type_of(&var.value));
        }
        if name == "machine.hostname" {
            let ty = if self.workspace.machine_hostname_trusted {
                Type::String
            } else {
                Type::Optional(Box::new(Type::String))
            };
            return Some(self.refine(name, ty));
        }
        if matches!(
            name,
            "malm.target" | "profile.name" | "instance.name" | "instance.module"
        ) {
            return Some(Type::String);
        }
        if let Some(input) = self.module.input(name) {
            return Some(self.refine(name, input.ty.clone()));
        }
        // Record field access: `input-name.field`.
        if let Some((head, field)) = name.split_once('.')
            && let Some(input) = self.module.input(head)
            && let Type::Record(schema) = input.ty.unwrap_optional()
        {
            return schema.field(field).map(|field_schema| {
                let outer_optional = input.ty.is_optional() && !self.is_refined(head);
                let field_optional = !field_schema.required;
                let ty = if outer_optional || field_optional {
                    Type::Optional(Box::new(field_schema.ty.clone()))
                } else {
                    field_schema.ty.clone()
                };
                self.refine(name, ty)
            });
        }
        None
    }

    fn is_refined(&self, name: &str) -> bool {
        self.refinements.iter().rev().any(|refined| refined == name)
    }

    fn declaration_span(&self, name: &str) -> Option<Span> {
        let input = name.split('.').next().unwrap_or(name);
        self.module.input(input).map(|declaration| declaration.span)
    }

    fn refine(&self, name: &str, ty: Type) -> Type {
        if self.is_refined(name) {
            match ty {
                Type::Optional(inner) => *inner,
                other => other,
            }
        } else {
            ty
        }
    }

    fn push_refinement(&mut self, name: &str) {
        self.refinements.push(name.to_owned());
    }

    fn pop_refinement(&mut self) {
        self.refinements.pop();
    }

    fn push_binding(
        &mut self,
        name: &str,
        ty: Type,
        span: Span,
        diagnostics: &mut Diagnostics,
    ) -> bool {
        // Bindings are lexically scoped and may shadow only other bindings.
        let shadows_non_binding =
            self.bindings.iter().all(|(n, _)| n != name) && self.lookup(name).is_some();
        if shadows_non_binding {
            diagnostics.push(
                Diagnostic::error(
                    codes::BINDING,
                    format!("loop binding `{name}` shadows a non-binding name"),
                )
                .with_span(span)
                .with_help(
                    "rename the binding; inner bindings may shadow only other loop bindings",
                ),
            );
            return false;
        }
        self.bindings.push((name.to_owned(), ty));
        true
    }

    fn pop_binding(&mut self) {
        self.bindings.pop();
    }

    /// Push a synthetic binding such as `b.key`, bypassing user shadow checks.
    fn push_synthetic_binding(&mut self, name: String, ty: Type) {
        self.bindings.push((name, ty));
    }
}

fn scalar_type_of(value: &Value) -> Type {
    match value {
        Value::Bool(_) => Type::Bool,
        Value::Int(_) => Type::Int,
        Value::Float(_) => Type::Float,
        Value::Path(_) => Type::Path,
        _ => Type::String,
    }
}

/// Check every module and profile in the workspace.
pub fn check_workspace(workspace: &ResolvedWorkspace, diagnostics: &mut Diagnostics) {
    for module in workspace.modules.values() {
        check_module(workspace, module, diagnostics);
    }
    for profile in &workspace.profiles {
        check_profile(workspace, &profile.name, diagnostics);
    }
}

pub fn check_module(
    workspace: &ResolvedWorkspace,
    module: &ResolvedModule,
    diagnostics: &mut Diagnostics,
) {
    // Check input defaults against their declared types.
    for input in module.inputs() {
        if let Some(default) = &input.default {
            let span = input.default_span.unwrap_or(input.span);
            if let Err(diag) = coerce(
                default.clone(),
                &input.ty,
                span,
                &format!("input `{}` default", input.name),
            ) {
                diagnostics.push(diag);
            }
        }
    }
    let mut collection_env = TypeEnv::new(workspace, module);
    for input in module.inputs() {
        if let Some(default) = &input.default {
            check_kdl_collection_value(&mut collection_env, default, diagnostics);
        }
    }
    // Validate default fragment sources.
    for fragment in &module.decl.fragments {
        for source in &fragment.defaults {
            validate_fragment_source(
                &source.path,
                &source.base_dir,
                &workspace.source_root,
                source.span,
                &fragment.name,
                &fragment.format,
                diagnostics,
            );
        }
    }
    // Requirements use the same predicate rules as outputs.
    let mut requirement_env = TypeEnv::new(workspace, module);
    check_requirement_nodes(&mut requirement_env, module.requires(), diagnostics);
    // Check references, controls, and fragment names in outputs.
    let mut env = TypeEnv::new(workspace, module);
    for output in module.outputs() {
        check_output_node(&mut env, output, diagnostics);
    }
}

fn check_requirement_nodes(
    env: &mut TypeEnv<'_>,
    nodes: &[RequirementNode],
    diagnostics: &mut Diagnostics,
) {
    for node in nodes {
        match node {
            RequirementNode::Requirement(_) => {}
            RequirementNode::When(when) => {
                let reference = when.predicate.reference();
                let input_name = reference.name.split('.').next().unwrap_or_default();
                if env.module.input(input_name).is_none() {
                    diagnostics.push(
                        Diagnostic::error(
                            codes::REQUIREMENT,
                            format!(
                                "conditional requirements may reference module inputs only; `{}` is not an input of module `{}`",
                                reference.name, env.module.decl.name
                            ),
                        )
                        .with_span(reference.span),
                    );
                } else {
                    check_predicate(env, &when.predicate, diagnostics);
                }
                let refined = match &when.predicate {
                    Predicate::Set(reference) => Some(reference.name.as_str()),
                    _ => None,
                };
                if let Some(name) = refined {
                    env.push_refinement(name);
                }
                check_requirement_nodes(env, &when.then, diagnostics);
                if refined.is_some() {
                    env.pop_refinement();
                }
                check_requirement_nodes(env, &when.otherwise, diagnostics);
            }
        }
    }
}

fn check_kdl_collection_value(env: &mut TypeEnv<'_>, value: &Value, diagnostics: &mut Diagnostics) {
    let Value::Collection(collection) = value else {
        return;
    };
    for item in &collection.items {
        if let Value::KdlDocument(document) = &item.value {
            check_kdl_nodes(env, document.nodes(), diagnostics, 0, item.span.file);
        }
    }
}

fn check_source_path(
    path: &str,
    base_dir: &Path,
    source_root: &Path,
    span: Span,
) -> Result<(), Diagnostic> {
    let resolved = resolve_source(path, base_dir, source_root)
        .map_err(|message| Diagnostic::error(codes::OUTPUT_PATH, message).with_span(span))?;
    if !resolved.is_file() {
        return Err(Diagnostic::error(
            codes::FRAGMENT,
            format!("source file not found: {}", resolved.display()),
        )
        .with_span(span));
    }
    Ok(())
}

fn validate_fragment_source(
    path: &str,
    base_dir: &Path,
    source_root: &Path,
    span: Span,
    fragment: &str,
    format: &str,
    diagnostics: &mut Diagnostics,
) {
    let resolved = match resolve_source(path, base_dir, source_root) {
        Ok(resolved) if resolved.is_file() => resolved,
        Ok(resolved) => {
            diagnostics.push(
                Diagnostic::error(
                    codes::FRAGMENT,
                    format!("source file not found: {}", resolved.display()),
                )
                .with_span(span),
            );
            return;
        }
        Err(message) => {
            diagnostics.push(Diagnostic::error(codes::OUTPUT_PATH, message).with_span(span));
            return;
        }
    };
    let limit = crate::lang::budget::Limits::default().max_render_bytes;
    let mut file = match std::fs::File::open(&resolved) {
        Ok(file) => file,
        Err(error) => {
            diagnostics.push(
                Diagnostic::error(
                    codes::FRAGMENT,
                    format!("read fragment source {}: {error}", resolved.display()),
                )
                .with_span(span),
            );
            return;
        }
    };
    let mut bytes = Vec::new();
    use std::io::Read as _;
    if let Err(error) = file
        .by_ref()
        .take(limit.saturating_add(1))
        .read_to_end(&mut bytes)
    {
        diagnostics.push(
            Diagnostic::error(
                codes::FRAGMENT,
                format!("read fragment source {}: {error}", resolved.display()),
            )
            .with_span(span),
        );
        return;
    }
    if bytes.len() as u64 > limit {
        diagnostics.push(
            Diagnostic::error(
                codes::FRAGMENT,
                format!(
                    "fragment `{fragment}` source {} exceeds the maximum of {limit} bytes",
                    resolved.display()
                ),
            )
            .with_span(span),
        );
        return;
    }
    let text = match std::str::from_utf8(&bytes) {
        Ok(text) => text,
        Err(_) => {
            diagnostics.push(
                Diagnostic::error(
                    codes::FRAGMENT,
                    format!("fragment source {} is not valid UTF-8", resolved.display()),
                )
                .with_span(span),
            );
            return;
        }
    };
    for problem in crate::lang::artifact::validate_format(format, text) {
        diagnostics.push(
            Diagnostic::error(
                codes::FRAGMENT,
                format!(
                    "fragment `{fragment}` source {} is not valid {format}: {problem}",
                    resolved.display()
                ),
            )
            .with_span(span),
        );
    }
}

/// Resolve `./…` from the declaring file and other relative paths from the
/// workspace root. Absolute, tilde, and parent paths are rejected.
pub(crate) fn resolve_source(
    raw: &str,
    base_dir: &Path,
    source_root: &Path,
) -> Result<std::path::PathBuf, String> {
    let (base, rest) = match raw.strip_prefix("./") {
        Some(rest) => (base_dir, rest),
        None => (source_root, raw),
    };
    if rest.is_empty() {
        return Err(format!("source names no file: `{raw}`"));
    }
    if raw == "~"
        || raw.starts_with("~/")
        || Path::new(raw).is_absolute()
        || Path::new(rest).is_absolute()
    {
        return Err(format!(
            "source `{raw}` must be repository-relative (use `symlink` for external paths)"
        ));
    }
    if Path::new(rest)
        .components()
        .any(|c| matches!(c, std::path::Component::ParentDir))
    {
        return Err(format!("source must not contain `..`: {raw}"));
    }
    Ok(base.join(rest))
}

fn check_ref(env: &TypeEnv<'_>, reference: &Ref, diagnostics: &mut Diagnostics) -> Option<Type> {
    match env.lookup(&reference.name) {
        Some(ty) => Some(ty),
        None => {
            diagnostics.push(
                Diagnostic::error(
                    codes::UNDEFINED_REF,
                    format!("`{}` is not defined in this module's scope", reference.name),
                )
                .with_span(reference.span)
                .with_help(
                    "references resolve against the module's inputs, loop bindings, global.* tokens, and built-ins",
                ),
            );
            None
        }
    }
}

fn check_predicate(env: &TypeEnv<'_>, predicate: &Predicate, diagnostics: &mut Diagnostics) {
    let Some(ty) = check_ref(env, predicate.reference(), diagnostics) else {
        return;
    };
    let reference = predicate.reference();
    match predicate {
        Predicate::Test(_) => {
            if ty != Type::Bool {
                let mut diagnostic = Diagnostic::error(
                    codes::WHEN_PREDICATE,
                    format!("`when` requires bool, found {ty}"),
                )
                .with_span(reference.span)
                .with_help(predicate_help(&ty));
                if let Some(span) = env.declaration_span(&reference.name) {
                    diagnostic = diagnostic.with_label("input declared here", span);
                }
                diagnostics.push(diagnostic);
            }
        }
        Predicate::Set(_) => {
            // Keep hostname guards valid for both trusted and untrusted loads.
            if !ty.is_optional() && reference.name != "machine.hostname" {
                let mut diagnostic = Diagnostic::error(
                    codes::WHEN_PREDICATE,
                    format!("`when-set` requires optional<T>, found {ty}"),
                )
                .with_span(reference.span)
                .with_help(predicate_help(&ty));
                if let Some(span) = env.declaration_span(&reference.name) {
                    diagnostic = diagnostic.with_label("input declared here", span);
                }
                diagnostics.push(diagnostic);
            }
        }
        Predicate::NonEmpty(_) => {
            if !matches!(ty.unwrap_optional(), Type::List(_) | Type::Collection(_))
                || ty.is_optional()
            {
                let mut diagnostic = Diagnostic::error(
                    codes::WHEN_PREDICATE,
                    format!("`when-nonempty` requires a list or collection, found {ty}"),
                )
                .with_span(reference.span)
                .with_help(predicate_help(&ty));
                if let Some(span) = env.declaration_span(&reference.name) {
                    diagnostic = diagnostic.with_label("input declared here", span);
                }
                diagnostics.push(diagnostic);
            }
        }
        Predicate::Eq { expected, .. } => {
            let comparable = matches!(
                ty,
                Type::Bool | Type::Int | Type::String | Type::Path | Type::Enum(_)
            );
            if !comparable {
                let mut diagnostic = Diagnostic::error(
                    codes::WHEN_PREDICATE,
                    format!("`is=` compares enum, string, int, or bool values; found {ty}"),
                )
                .with_span(reference.span)
                .with_help(predicate_help(&ty));
                if let Some(span) = env.declaration_span(&reference.name) {
                    diagnostic = diagnostic.with_label("input declared here", span);
                }
                diagnostics.push(diagnostic);
                return;
            }
            let literal_matches = match (&ty, expected) {
                (Type::Bool, Value::Bool(_)) => true,
                (Type::Int, Value::Int(_)) => true,
                (Type::String | Type::Path, Value::String(_)) => true,
                (Type::Enum(values), Value::String(value)) => {
                    if !values.contains(value) {
                        diagnostics.push(
                            Diagnostic::error(
                                codes::WHEN_PREDICATE,
                                format!(
                                    "`is=\"{value}\"` is not a declared value of `{}` (expected one of: {})",
                                    reference.name,
                                    values.join(", ")
                                ),
                            )
                            .with_span(reference.span),
                        );
                    }
                    true
                }
                _ => false,
            };
            if !literal_matches {
                diagnostics.push(
                    Diagnostic::error(
                        codes::WHEN_PREDICATE,
                        format!(
                            "`is=` literal must match the type of `{}` ({ty})",
                            reference.name
                        ),
                    )
                    .with_span(reference.span),
                );
            }
        }
    }
}

fn predicate_help(ty: &Type) -> String {
    match ty {
        Type::Optional(_) => "use `when-set` for optional values".to_owned(),
        Type::List(_) | Type::Collection(_) => {
            "use `when-nonempty` for lists and collections".to_owned()
        }
        Type::Bool => "use `when` for booleans".to_owned(),
        _ => "there is no implicit truthiness; expose a semantic boolean input instead".to_owned(),
    }
}

fn check_output_node(env: &mut TypeEnv<'_>, node: &OutputNode, diagnostics: &mut Diagnostics) {
    match node {
        OutputNode::KdlConfig(config) => {
            if let Some(validator) = &config.validate
                && !crate::lang::artifact::validator_known(validator)
            {
                diagnostics.push(
                    Diagnostic::error(
                        codes::ARTIFACT_VALIDATE,
                        format!("unknown artifact validator `{validator}`"),
                    )
                    .with_span(config.span)
                    .with_help(crate::lang::artifact::known_validators_help()),
                );
            }
            let KdlConfigBody::Document { nodes, file, .. } = &config.body;
            check_kdl_nodes(env, nodes, diagnostics, 0, *file);
        }
        OutputNode::ConfigFile(config_file) => {
            if let Some(validator) = &config_file.validate
                && !crate::lang::artifact::validator_known(validator)
            {
                diagnostics.push(
                    Diagnostic::error(
                        codes::ARTIFACT_VALIDATE,
                        format!("unknown artifact validator `{validator}`"),
                    )
                    .with_span(config_file.span)
                    .with_help(crate::lang::artifact::known_validators_help()),
                );
            }
            check_generic_body(env, &config_file.body, diagnostics);
        }
        OutputNode::Render(render) => {
            if let crate::lang::render::PathExpr::FString { raw, span } = &render.to {
                check_render_template(env, raw, *span, diagnostics);
            }
            if let Some(validator) = &render.validate
                && !crate::lang::artifact::validator_known(validator)
            {
                diagnostics.push(
                    Diagnostic::error(
                        codes::ARTIFACT_VALIDATE,
                        format!("unknown artifact validator `{validator}`"),
                    )
                    .with_span(render.span)
                    .with_help(crate::lang::artifact::known_validators_help()),
                );
            }
            let dir = render.dir.clone();
            check_config_items(
                env,
                &render.body.items,
                diagnostics,
                &move |env, node, diagnostics| check_render_shape(env, node, &dir, diagnostics),
            );
        }
        OutputNode::File(file) => {
            if let Err(diag) = check_source_path(
                &file.source,
                &file.dir,
                &env.workspace.source_root,
                file.span,
            ) && !file.optional
            {
                diagnostics.push(diag);
            }
        }
        OutputNode::Dir(dir) => {
            if !dir.optional {
                match resolve_source(&dir.source, &dir.dir, &env.workspace.source_root) {
                    Ok(path) if path.is_dir() => {}
                    Ok(path) => diagnostics.push(
                        Diagnostic::error(
                            codes::OUTPUT_PATH,
                            format!("dir source not found: {}", path.display()),
                        )
                        .with_span(dir.span),
                    ),
                    Err(message) => diagnostics
                        .push(Diagnostic::error(codes::OUTPUT_PATH, message).with_span(dir.span)),
                }
            }
        }
        OutputNode::Symlink(symlink) => {
            if let crate::lang::ast::SymlinkSource::Ref(reference) = &symlink.source
                && let Some(ty) = check_ref(env, reference, diagnostics)
                && !matches!(ty.unwrap_optional(), Type::Path | Type::String)
            {
                diagnostics.push(
                    Diagnostic::error(
                        codes::TYPE_MISMATCH,
                        format!("symlink `source=` requires a path, found {ty}"),
                    )
                    .with_span(reference.span),
                );
            }
        }
        OutputNode::When(when) => {
            check_predicate(env, &when.predicate, diagnostics);
            let refined = match &when.predicate {
                Predicate::Set(reference) => Some(reference.name.as_str()),
                _ => None,
            };
            if let Some(name) = refined {
                env.push_refinement(name);
            }
            for child in &when.then {
                check_output_node(env, child, diagnostics);
            }
            if refined.is_some() {
                env.pop_refinement();
            }
            for child in &when.otherwise {
                check_output_node(env, child, diagnostics);
            }
        }
        OutputNode::Each(each) => {
            let keyed = matches!(env.lookup(&each.source.name), Some(Type::Collection(_)));
            if keyed {
                env.push_synthetic_binding(format!("{}.key", each.binding), Type::String);
            }
            let item_ty = check_each_source(env, &each.source, diagnostics);
            let pushed = env.push_binding(&each.binding, item_ty, each.span, diagnostics);
            for child in &each.body {
                check_output_node(env, child, diagnostics);
            }
            if pushed {
                env.pop_binding();
            }
            if keyed {
                env.pop_binding();
            }
        }
        OutputNode::Range(range) => {
            check_range_bounds(range.from, range.through, range.span, diagnostics);
            let pushed = env.push_binding(&range.binding, Type::Int, range.span, diagnostics);
            for child in &range.body {
                check_output_node(env, child, diagnostics);
            }
            if pushed {
                env.pop_binding();
            }
        }
    }
}

fn check_generic_body(
    env: &mut TypeEnv<'_>,
    body: &crate::lang::config_file::generic::GenericBody,
    diagnostics: &mut Diagnostics,
) {
    use crate::lang::config_file::generic::GenericBody;
    match body {
        GenericBody::Xml { root, .. } => check_xml_element(env, root, diagnostics),
        GenericBody::Css { items, .. } => {
            check_config_items(env, items, diagnostics, &check_css_node);
        }
    }
}

fn check_xml_element(
    env: &mut TypeEnv<'_>,
    node: &crate::lang::config_file::generic::XmlElement,
    diagnostics: &mut Diagnostics,
) {
    for (_, value, _) in &node.attrs {
        check_scalar_expr(env, value, diagnostics);
    }
    check_config_items(env, &node.body, diagnostics, &check_xml_child);
}

fn check_xml_child(
    env: &mut TypeEnv<'_>,
    node: &crate::lang::config_file::generic::XmlNode,
    diagnostics: &mut Diagnostics,
) {
    use crate::lang::config_file::generic::XmlNode;
    match node {
        XmlNode::Element(node) => check_xml_element(env, node, diagnostics),
        XmlNode::Repeat {
            attrs,
            values,
            body,
            ..
        } => {
            for (_, value, _) in attrs {
                check_scalar_expr(env, value, diagnostics);
            }
            for value in values {
                check_scalar_expr(env, value, diagnostics);
            }
            if let Some(body) = body {
                check_config_items(env, body, diagnostics, &check_xml_child);
            }
        }
        XmlNode::Text { value, .. } => check_scalar_expr(env, value, diagnostics),
        XmlNode::Comment { .. } => {}
    }
}

fn check_css_node(
    env: &mut TypeEnv<'_>,
    node: &crate::lang::config_file::generic::CssNode,
    diagnostics: &mut Diagnostics,
) {
    use crate::lang::config_file::generic::CssNode;
    match node {
        CssNode::Rule { body, .. }
        | CssNode::AtRule {
            body: Some(body), ..
        } => check_config_items(env, body, diagnostics, &check_css_node),
        CssNode::Declaration { value, .. } => check_scalar_expr(env, value, diagnostics),
        CssNode::RepeatValues { values, .. } => {
            for value in values {
                check_scalar_expr(env, value, diagnostics);
            }
        }
        CssNode::Comment { .. } | CssNode::AtRule { body: None, .. } => {}
    }
}

fn check_render_shape(
    env: &mut TypeEnv<'_>,
    node: &crate::lang::render::ShapeNode,
    dir: &Path,
    diagnostics: &mut Diagnostics,
) {
    use crate::lang::render::{NodeName, ShapeNode};
    match node {
        ShapeNode::Comment { .. } | ShapeNode::Raw { .. } => {}
        ShapeNode::Line { value, .. } => check_render_value(env, value, diagnostics),
        ShapeNode::File {
            path,
            interpolate,
            span,
        } => {
            if let Err(diag) = check_source_path(path, dir, &env.workspace.source_root, *span) {
                diagnostics.push(diag);
                return;
            }
            if *interpolate
                && let Ok(resolved) = resolve_source(path, dir, &env.workspace.source_root)
                && !crate::policy::source_escapes_source_root(&resolved, &env.workspace.source_root)
                && let Ok(text) = std::fs::read_to_string(&resolved)
            {
                for issue in crate::lang::text::check_template_with(
                    &text,
                    crate::lang::text::TemplateSyntax::V3,
                    &|name| env.lookup(name),
                ) {
                    diagnostics.push(
                        Diagnostic::error(codes::TEMPLATE, format!("{path}: {issue}"))
                            .with_span(*span),
                    );
                }
            }
        }
        ShapeNode::Compose { fragment, span } => {
            check_compose(env, fragment, *span, diagnostics);
        }
        ShapeNode::Spread(spread) => {
            if let Some(ty) = check_ref(env, &spread.reference, diagnostics)
                && !matches!(ty, Type::Record(_))
            {
                diagnostics.push(
                    Diagnostic::error(
                        codes::TYPE_MISMATCH,
                        format!("`@spread` requires a record, found {ty}"),
                    )
                    .with_span(spread.span),
                );
            }
        }
        ShapeNode::Entry(entry) => {
            if let Some(NodeName::FString { raw, span }) = &entry.name {
                check_render_template(env, raw, *span, diagnostics);
            }
            for value in &entry.args {
                check_render_value(env, value, diagnostics);
            }
            for (_, value, _) in &entry.props {
                check_render_value(env, value, diagnostics);
            }
            if let Some(children) = &entry.children {
                let dir = dir.to_path_buf();
                check_config_items(
                    env,
                    children,
                    diagnostics,
                    &move |env, node, diagnostics| check_render_shape(env, node, &dir, diagnostics),
                );
            }
        }
    }
}

fn check_render_template(env: &TypeEnv<'_>, raw: &str, span: Span, diagnostics: &mut Diagnostics) {
    for issue in crate::lang::text::check_template_with(
        raw,
        crate::lang::text::TemplateSyntax::V3,
        &|name| env.lookup(name),
    ) {
        diagnostics.push(Diagnostic::error(codes::TEMPLATE, issue).with_span(span));
    }
}

fn check_render_value(
    env: &TypeEnv<'_>,
    value: &crate::lang::render::ValueExpr,
    diagnostics: &mut Diagnostics,
) {
    use crate::lang::render::ValueExpr;
    match value {
        ValueExpr::Literal(..) | ValueExpr::Raw(..) => {}
        ValueExpr::FString { raw, span } => {
            check_render_template(env, raw, *span, diagnostics);
        }
        ValueExpr::Ref {
            reference,
            optional,
        } => {
            let Some(ty) = check_ref(env, reference, diagnostics) else {
                return;
            };
            if *optional {
                if !ty.is_optional() && reference.name != "machine.hostname" {
                    diagnostics.push(
                        Diagnostic::error(
                            codes::TYPE_MISMATCH,
                            format!(
                                "`(ref?)` targets an optional; `{}` is {ty} — use `(ref)`",
                                reference.name
                            ),
                        )
                        .with_span(reference.span),
                    );
                    return;
                }
                check_render_ref_payload(ty.unwrap_optional(), reference, diagnostics);
            } else {
                if ty.is_optional() {
                    diagnostics.push(
                        Diagnostic::error(
                            codes::TYPE_MISMATCH,
                            format!(
                                "`{}` is {ty}; guard with `@when-set` or use `(ref?)`",
                                reference.name
                            ),
                        )
                        .with_span(reference.span),
                    );
                    return;
                }
                check_render_ref_payload(&ty, reference, diagnostics);
            }
        }
    }
}

fn check_render_ref_payload(ty: &Type, reference: &Ref, diagnostics: &mut Diagnostics) {
    if !matches!(
        ty,
        Type::Bool
            | Type::Int
            | Type::Float
            | Type::String
            | Type::Path
            | Type::Enum(_)
            | Type::List(_)
            | Type::Record(_)
    ) {
        diagnostics.push(
            Diagnostic::error(
                codes::TYPE_MISMATCH,
                format!(
                    "render value requires a scalar, list, or record; `{}` is {ty} (use `@splice` for collections)",
                    reference.name
                ),
            )
            .with_span(reference.span),
        );
    }
}

fn check_scalar_expr(
    env: &TypeEnv<'_>,
    expression: &crate::lang::config_file::generic::ScalarExpr,
    diagnostics: &mut Diagnostics,
) {
    for value in &expression.values {
        check_config_typed(
            env,
            value,
            "a non-optional scalar",
            config_scalar,
            diagnostics,
        );
    }
}

fn check_config_items<T>(
    env: &mut TypeEnv<'_>,
    items: &[ConfigItem<T>],
    diagnostics: &mut Diagnostics,
    leaf: &dyn Fn(&mut TypeEnv<'_>, &T, &mut Diagnostics),
) {
    for item in items {
        match item {
            ConfigItem::Value { value, .. } => leaf(env, value, diagnostics),
            ConfigItem::When(when) => {
                check_predicate(env, &when.predicate, diagnostics);
                let refined = match &when.predicate {
                    Predicate::Set(reference) => Some(reference.name.as_str()),
                    _ => None,
                };
                if let Some(name) = refined {
                    env.push_refinement(name);
                }
                check_config_items(env, &when.then, diagnostics, leaf);
                if refined.is_some() {
                    env.pop_refinement();
                }
                check_config_items(env, &when.otherwise, diagnostics, leaf);
            }
            ConfigItem::Each(each) => {
                let keyed = matches!(env.lookup(&each.source.name), Some(Type::Collection(_)));
                if keyed {
                    env.push_synthetic_binding(format!("{}.key", each.binding), Type::String);
                }
                let item_ty = check_each_source(env, &each.source, diagnostics);
                let pushed = env.push_binding(&each.binding, item_ty, each.span, diagnostics);
                check_config_items(env, &each.body, diagnostics, leaf);
                if pushed {
                    env.pop_binding();
                }
                if keyed {
                    env.pop_binding();
                }
            }
            ConfigItem::Range(range) => {
                check_range_bounds(range.from, range.through, range.span, diagnostics);
                let pushed = env.push_binding(&range.binding, Type::Int, range.span, diagnostics);
                check_config_items(env, &range.body, diagnostics, leaf);
                if pushed {
                    env.pop_binding();
                }
            }
            ConfigItem::Splice(reference) => match check_ref(env, reference, diagnostics) {
                // Patched payloads are parsed by the receiving format later.
                Some(Type::Collection(item)) if *item == Type::KdlDocument => {}
                Some(other) => diagnostics.push(
                    Diagnostic::error(
                        codes::TYPE_MISMATCH,
                        format!("`splice` requires a collection<kdl-document>, found {other}"),
                    )
                    .with_span(reference.span),
                ),
                None => {}
            },
        }
    }
}

fn check_config_typed(
    env: &TypeEnv<'_>,
    value: &ConfigValue,
    expected: &str,
    accepts: fn(&Type) -> bool,
    diagnostics: &mut Diagnostics,
) {
    let (ty, span) = match value {
        ConfigValue::Ref(reference) => {
            let Some(ty) = check_ref(env, reference, diagnostics) else {
                return;
            };
            (ty, reference.span)
        }
        ConfigValue::Literal(value, span) => (scalar_type_of_config(value), *span),
        ConfigValue::FString { raw, span } => {
            check_render_template(env, raw, *span, diagnostics);
            (Type::String, *span)
        }
    };
    if !accepts(&ty) {
        diagnostics.push(
            Diagnostic::error(
                codes::TYPE_MISMATCH,
                format!("config value requires {expected}, found {ty}"),
            )
            .with_span(span),
        );
    }
}

fn config_scalar(ty: &Type) -> bool {
    matches!(
        ty,
        Type::Bool | Type::Int | Type::Float | Type::String | Type::Path | Type::Enum(_)
    )
}

fn scalar_type_of_config(value: &Value) -> Type {
    match value {
        Value::Null => Type::Optional(Box::new(Type::String)),
        Value::Bool(_) => Type::Bool,
        Value::Int(_) => Type::Int,
        Value::Float(_) => Type::Float,
        Value::String(_) => Type::String,
        Value::Path(_) => Type::Path,
        Value::List(_) => Type::List(Box::new(Type::String)),
        Value::Record(_) => Type::Record(RecordSchema { fields: Vec::new() }),
        Value::Collection(_) => Type::Collection(Box::new(Type::String)),
        Value::KdlDocument(_) => Type::KdlDocument,
    }
}

fn check_compose(env: &TypeEnv<'_>, fragment: &str, span: Span, diagnostics: &mut Diagnostics) {
    if env.module.fragment(fragment).is_none() {
        diagnostics.push(
            Diagnostic::error(
                codes::FRAGMENT,
                format!(
                    "module `{}` composes undeclared fragment `{fragment}`",
                    env.module.decl.name
                ),
            )
            .with_span(span),
        );
    }
}

fn check_each_source(env: &TypeEnv<'_>, source: &Ref, diagnostics: &mut Diagnostics) -> Type {
    match env.lookup(&source.name) {
        None => {
            diagnostics.push(
                Diagnostic::error(
                    codes::UNDEFINED_REF,
                    format!("`{}` is not defined in this module's scope", source.name),
                )
                .with_span(source.span),
            );
            Type::String
        }
        Some(Type::List(item)) => *item,
        Some(Type::Collection(item)) => *item,
        Some(other) => {
            diagnostics.push(
                Diagnostic::error(
                    codes::LOOP_SOURCE,
                    format!("`each` requires a list or collection, found {other}"),
                )
                .with_span(source.span),
            );
            Type::String
        }
    }
}

fn check_range_bounds(from: i64, through: i64, span: Span, diagnostics: &mut Diagnostics) {
    if through < from {
        diagnostics.push(
            Diagnostic::error(
                codes::RANGE,
                format!("`range` is empty: from={from} through={through}"),
            )
            .with_span(span),
        );
    }
}

/// Walk inline target KDL nodes, checking controls and every `(ref)` entry.
fn check_kdl_nodes(
    env: &mut TypeEnv<'_>,
    nodes: &[KdlNode],
    diagnostics: &mut Diagnostics,
    depth: usize,
    file: FileId,
) {
    if depth == 0
        && let Err(diagnostic) = crate::lang::kdl_util::validate_document_depth(file, nodes)
    {
        diagnostics.push(diagnostic);
        return;
    }
    for node in nodes {
        check_kdl_node(env, node, diagnostics, depth, file);
    }
}

fn check_kdl_node(
    env: &mut TypeEnv<'_>,
    node: &KdlNode,
    diagnostics: &mut Diagnostics,
    depth: usize,
    file: FileId,
) {
    // Raw nodes do not carry FileId, so node spans are interpreted against the
    // module file and structural errors may fall back to the output span.
    let name = node.name().value();
    match name {
        "when" | "when-set" | "when-nonempty" | "each" | "range" | "splice" | "compose"
        | "@when" | "@when-set" | "@when-nonempty" | "@each" | "@range" | "@splice"
        | "@compose" => {
            check_structural_kdl(env, node, diagnostics, depth, file);
        }
        "else" | "@else" => {
            diagnostics.push(
                Diagnostic::error(
                    codes::NODE_SHAPE,
                    "`else` must be the final child of a condition",
                )
                .with_span(node_span(file, node)),
            );
        }
        _ => {
            // Target-node references must be scalar and properties unique.
            let escaped = name == "node";
            let target_name = if escaped {
                node.get(0)
                    .and_then(kdl::KdlValue::as_string)
                    .unwrap_or(name)
            } else {
                name
            };
            let mut seen_props: Vec<&str> = Vec::new();
            for (index, entry) in node.iter().enumerate() {
                if escaped && index == 0 {
                    continue;
                }
                if let Some(prop) = entry.name() {
                    if seen_props.contains(&prop.value()) {
                        diagnostics.push(
                            Diagnostic::error(
                                codes::DUPLICATE,
                                format!(
                                    "node `{target_name}` sets property `{}` twice",
                                    prop.value()
                                ),
                            )
                            .with_span(entry_span(file, entry)),
                        );
                    }
                    seen_props.push(prop.value());
                }
                if crate::lang::kdl_util::is_ref(entry) {
                    let ref_name = entry.value().as_string().unwrap_or_default();
                    match env.lookup(ref_name) {
                        None => diagnostics.push(
                            Diagnostic::error(
                                codes::UNDEFINED_REF,
                                format!("`{ref_name}` is not defined in this module's scope (in node `{target_name}`)"),
                            )
                            .with_span(entry_span(file, entry)),
                        ),
                        Some(ty) => {
                            if !matches!(
                                ty,
                                Type::Bool
                                    | Type::Int
                                    | Type::Float
                                    | Type::String
                                    | Type::Path
                                    | Type::Enum(_)
                            ) {
                                diagnostics.push(
                                    Diagnostic::error(
                                        codes::TYPE_MISMATCH,
                                        format!(
                                            "`(ref)\"{ref_name}\"` inserts a non-optional typed scalar; found {ty}"
                                        ),
                                    )
                                    .with_span(entry_span(file, entry)),
                                );
                            }
                        }
                    }
                } else if let kdl::KdlValue::String(text) = entry.value()
                    && text.contains("{{")
                {
                    for issue in
                        crate::lang::text::check_template_with_v3(text, &|name| env.lookup(name))
                    {
                        diagnostics.push(
                            Diagnostic::error(
                                codes::TEMPLATE,
                                format!("node `{target_name}` string: {issue}"),
                            )
                            .with_span(entry_span(file, entry)),
                        );
                    }
                }
            }
            if let Some(children) = node.children() {
                check_kdl_nodes(env, children.nodes(), diagnostics, depth + 1, file);
            }
        }
    }
}

fn check_structural_kdl(
    env: &mut TypeEnv<'_>,
    node: &KdlNode,
    diagnostics: &mut Diagnostics,
    depth: usize,
    file: FileId,
) {
    let name = crate::lang::kdl_util::kdl_control_alias(node.name().value());
    match name {
        "when" | "when-set" | "when-nonempty" => {
            let predicate = match parse_condition(file, node) {
                Ok(predicate) => predicate,
                Err(diagnostic) => {
                    diagnostics.push(diagnostic);
                    return;
                }
            };
            check_predicate(env, &predicate, diagnostics);
            let (then_nodes, else_nodes) = match split_else(node, diagnostics) {
                Some(split) => split,
                None => return,
            };
            let refined = match &predicate {
                Predicate::Set(reference) => Some(reference.name.as_str()),
                _ => None,
            };
            if let Some(name) = refined {
                env.push_refinement(name);
            }
            check_kdl_nodes(env, &then_nodes, diagnostics, depth + 1, file);
            if refined.is_some() {
                env.pop_refinement();
            }
            check_kdl_nodes(env, &else_nodes, diagnostics, depth + 1, file);
        }
        "each" => {
            let (binding, source) = match parse_each_header(file, node) {
                Ok(header) => header,
                Err(diagnostic) => {
                    diagnostics.push(diagnostic);
                    return;
                }
            };
            let keyed = matches!(env.lookup(&source.name), Some(Type::Collection(_)));
            if keyed {
                env.push_synthetic_binding(format!("{binding}.key"), Type::String);
            }
            let item_ty = check_each_source(env, &source, diagnostics);
            let pushed = env.push_binding(&binding, item_ty, node_span(file, node), diagnostics);
            if let Some(children) = node.children() {
                check_kdl_nodes(env, children.nodes(), diagnostics, depth + 1, file);
            }
            if pushed {
                env.pop_binding();
            }
            if keyed {
                env.pop_binding();
            }
        }
        "range" => {
            let (binding, from, through) = match parse_range_header(file, node) {
                Ok(header) => header,
                Err(diagnostic) => {
                    diagnostics.push(diagnostic);
                    return;
                }
            };
            check_range_bounds(from, through, node_span(file, node), diagnostics);
            let pushed = env.push_binding(&binding, Type::Int, node_span(file, node), diagnostics);
            if let Some(children) = node.children() {
                check_kdl_nodes(env, children.nodes(), diagnostics, depth + 1, file);
            }
            if pushed {
                env.pop_binding();
            }
        }
        "splice" => {
            let reference = match parse_splice(file, node) {
                Ok(reference) => reference,
                Err(diagnostic) => {
                    diagnostics.push(diagnostic);
                    return;
                }
            };
            match env.lookup(&reference.name) {
                Some(Type::Collection(item)) if *item == Type::KdlDocument => {}
                Some(other) => diagnostics.push(
                    Diagnostic::error(
                        codes::TYPE_MISMATCH,
                        format!("`splice` requires a collection<kdl-document>, found {other}"),
                    )
                    .with_span(reference.span),
                ),
                None => diagnostics.push(
                    Diagnostic::error(
                        codes::UNDEFINED_REF,
                        format!("`{}` is not defined in this module's scope", reference.name),
                    )
                    .with_span(reference.span),
                ),
            }
        }
        "compose" => {
            let span = node_span(file, node);
            let Some(fragment) = node.get("fragment").and_then(kdl::KdlValue::as_string) else {
                diagnostics.push(
                    Diagnostic::error(codes::NODE_SHAPE, "`compose` requires `fragment=\"...\"`")
                        .with_span(span),
                );
                return;
            };
            let Some(decl) = env.module.fragment(fragment) else {
                diagnostics.push(
                    Diagnostic::error(
                        codes::FRAGMENT,
                        format!(
                            "module `{}` composes undeclared fragment `{fragment}`",
                            env.module.decl.name
                        ),
                    )
                    .with_span(span),
                );
                return;
            };
            if !matches!(decl.format.as_str(), "kdl-v1" | "kdl-v2") {
                diagnostics.push(
                    Diagnostic::error(
                        codes::FRAGMENT,
                        format!(
                            "inline fragment `{fragment}` requires format `kdl-v1` or `kdl-v2`, found `{}`",
                            decl.format
                        ),
                    )
                    .with_span(span),
                );
            }
            if decl.cardinality != FragmentCardinality::One {
                diagnostics.push(
                    Diagnostic::error(
                        codes::FRAGMENT,
                        format!(
                            "inline fragment `{fragment}` requires cardinality `one`, found `many`"
                        ),
                    )
                    .with_span(span),
                );
            }
        }
        _ => unreachable!("caller matched structural names"),
    }
}

/// Split a condition into cloned then/else branches and validate `else` placement.
pub(crate) fn split_else(
    node: &KdlNode,
    diagnostics: &mut Diagnostics,
) -> Option<(Vec<KdlNode>, Vec<KdlNode>)> {
    let mut then_nodes = Vec::new();
    let mut else_nodes = Vec::new();
    let mut saw_else = false;
    if let Some(children) = node.children() {
        let nodes = children.nodes();
        for (index, child) in nodes.iter().enumerate() {
            if crate::lang::kdl_util::kdl_control_alias(child.name().value()) == "else" {
                if saw_else {
                    diagnostics.error(
                        codes::DUPLICATE,
                        "a condition allows at most one trailing `else`",
                    );
                    return None;
                }
                if index + 1 != nodes.len() {
                    diagnostics.error(
                        codes::NODE_SHAPE,
                        "`else` must be the final child of its condition",
                    );
                    return None;
                }
                saw_else = true;
                if let Some(else_children) = child.children() {
                    else_nodes.extend(else_children.nodes().iter().cloned());
                }
            } else {
                then_nodes.push(child.clone());
            }
        }
    }
    Some((then_nodes, else_nodes))
}

// Profile checking

/// Resolve and type-check a profile for downstream instantiation.
pub fn check_profile(
    workspace: &ResolvedWorkspace,
    name: &str,
    diagnostics: &mut Diagnostics,
) -> Option<TypedProfile> {
    let before = diagnostics.error_count();
    let resolved = resolve_profile(workspace, name, diagnostics)?;
    let mut typed = TypedProfile {
        name: resolved.name.clone(),
        chain: resolved.chain.clone(),
        instances: Vec::new(),
    };
    for instance in &resolved.instances {
        let module = workspace
            .modules
            .get(&instance.module)
            .expect("resolved instances reference known modules");
        let mut values: HashMap<String, (Value, crate::lang::value::ValueOrigin)> = HashMap::new();

        // Defaults first.
        for input in module.inputs() {
            match &input.default {
                Some(default) => {
                    match coerce(
                        default.clone(),
                        &input.ty,
                        input.default_span.unwrap_or(input.span),
                        &format!("input `{}` default", input.name),
                    ) {
                        Ok(value) => {
                            values.insert(
                                input.name.clone(),
                                (value, crate::lang::value::ValueOrigin::Default),
                            );
                        }
                        Err(_) => {
                            // Already reported by check_module.
                        }
                    }
                }
                None if input.ty.is_optional() => {
                    values.insert(
                        input.name.clone(),
                        (Value::Null, crate::lang::value::ValueOrigin::Default),
                    );
                }
                None => {}
            }
        }

        // Profile overrides.
        for (input_name, raw, span, profile_name) in &instance.with {
            let Some(input) = module.input(input_name) else {
                diagnostics.push(
                    Diagnostic::error(
                        codes::UNKNOWN_INPUT,
                        format!(
                            "module `{}` (as `{}`) has no input `{input_name}`",
                            instance.module, instance.alias
                        ),
                    )
                    .with_span(*span)
                    .with_help(known_inputs_help(module)),
                );
                continue;
            };
            if raw.is_null() && !input.ty.is_optional() {
                diagnostics.push(
                    Diagnostic::error(
                        codes::NULL_NOT_OPTIONAL,
                        format!(
                            "input `{}.{input_name}` is {}, which cannot be cleared with #null",
                            instance.alias, input.ty
                        ),
                    )
                    .with_span(*span)
                    .with_help("only optional inputs can be set to #null"),
                );
                continue;
            }
            match coerce(
                raw.clone(),
                &input.ty,
                *span,
                &format!("input `{}.{input_name}`", instance.alias),
            ) {
                Ok(value) => {
                    values.insert(
                        input_name.clone(),
                        (
                            value,
                            crate::lang::value::ValueOrigin::Profile(profile_name.clone()),
                        ),
                    );
                }
                Err(diag) => diagnostics.push(diag),
            }
        }

        // Apply record-field patches after whole-input overrides.
        for (set, profile_name) in &instance.sets {
            let Some((input_name, field_name)) = set.path.split_once('.') else {
                continue; // parse guarantees one dot
            };
            let Some(input) = module.input(input_name) else {
                diagnostics.push(
                    Diagnostic::error(
                        codes::UNKNOWN_INPUT,
                        format!(
                            "module `{}` (as `{}`) has no input `{input_name}` to patch",
                            instance.module, instance.alias
                        ),
                    )
                    .with_span(set.span)
                    .with_help(known_inputs_help(module)),
                );
                continue;
            };
            let Type::Record(schema) = input.ty.unwrap_optional() else {
                diagnostics.push(
                    Diagnostic::error(
                        codes::PATCH,
                        format!(
                            "`set`/`unset` target record fields; input `{input_name}` is {}",
                            input.ty
                        ),
                    )
                    .with_span(set.span),
                );
                continue;
            };
            let Some(field) = schema.field(field_name) else {
                diagnostics.push(
                    Diagnostic::error(
                        codes::RECORD_FIELD,
                        format!(
                            "record `{input_name}` has no field `{field_name}` (records are closed)"
                        ),
                    )
                    .with_span(set.span),
                );
                continue;
            };
            let base = match values.get_mut(input_name) {
                Some((Value::Record(record), origin)) => Some((record, origin)),
                Some((Value::Null, _)) | None => {
                    diagnostics.push(
                        Diagnostic::error(
                            codes::PATCH,
                            format!(
                                "`set \"{}\"` needs a base record — declare a default for `{input_name}` or set the whole input first",
                                set.path
                            ),
                        )
                        .with_span(set.span),
                    );
                    None
                }
                Some(_) => None, // default failed to coerce; already reported
            };
            let Some((record, origin)) = base else {
                continue;
            };
            match &set.value {
                None => {
                    if field.required {
                        diagnostics.push(
                            Diagnostic::error(
                                codes::PATCH,
                                format!(
                                    "field `{input_name}.{field_name}` is required; `unset` clears only optional fields"
                                ),
                            )
                            .with_span(set.span),
                        );
                        continue;
                    }
                    record.insert(field_name.to_owned(), Value::Null);
                }
                Some(raw) => {
                    match coerce(
                        raw.clone(),
                        &field.ty,
                        set.span,
                        &format!("patch `{}.{}`", instance.alias, set.path),
                    ) {
                        Ok(value) => {
                            record.insert(field_name.to_owned(), value);
                        }
                        Err(diag) => {
                            diagnostics.push(diag);
                            continue;
                        }
                    }
                }
            }
            *origin = crate::lang::value::ValueOrigin::Profile(profile_name.clone());
        }

        // Missing required inputs.
        for input in module.inputs() {
            if input.required() && !values.contains_key(&input.name) {
                diagnostics.push(
                    Diagnostic::error(
                        codes::MISSING_REQUIRED,
                        format!(
                            "profile `{name}`: module `{}` (as `{}`) is missing required input `{}` ({})",
                            instance.module, instance.alias, input.name, input.ty
                        ),
                    )
                    .with_span(instance.span)
                    .with_label("declared here", input.span),
                );
            }
        }

        // Fragment operations.
        let mut fragment_sources: HashMap<String, Vec<crate::lang::ast::FragmentSource>> =
            HashMap::new();
        for fragment in &module.decl.fragments {
            fragment_sources.insert(fragment.name.clone(), fragment.defaults.clone());
        }
        for (op, _profile_name) in &instance.fragment_ops {
            let (body, is_append) = match op {
                FragmentOp::Replace(body) => (body, false),
                FragmentOp::Append(body) => (body, true),
            };
            let Some(fragment) = module.fragment(&body.fragment) else {
                diagnostics.push(
                    Diagnostic::error(
                        codes::FRAGMENT,
                        format!(
                            "module `{}` (as `{}`) declares no fragment `{}`",
                            instance.module, instance.alias, body.fragment
                        ),
                    )
                    .with_span(body.span),
                );
                continue;
            };
            if is_append && fragment.cardinality == FragmentCardinality::One {
                diagnostics.push(
                    Diagnostic::error(
                        codes::FRAGMENT,
                        format!(
                            "fragment `{}` has cardinality \"one\"; use `replace`",
                            body.fragment
                        ),
                    )
                    .with_span(body.span),
                );
                continue;
            }
            let before_fragment_validation = diagnostics.error_count();
            validate_fragment_source(
                &body.source.path,
                &body.source.base_dir,
                &workspace.source_root,
                body.source.span,
                &body.fragment,
                &fragment.format,
                diagnostics,
            );
            if diagnostics.error_count() != before_fragment_validation {
                continue;
            }
            let sources = fragment_sources.entry(body.fragment.clone()).or_default();
            if is_append {
                sources.push(body.source.clone());
            } else {
                *sources = vec![body.source.clone()];
            }
        }

        // Collection patches.
        let mut patch_env = TypeEnv::new(workspace, module);
        for (patch, profile_name) in &instance.patches {
            let Some(input) = module.input(&patch.collection) else {
                diagnostics.push(
                    Diagnostic::error(
                        codes::PATCH,
                        format!(
                            "module `{}` (as `{}`) has no input `{}` to patch",
                            instance.module, instance.alias, patch.collection
                        ),
                    )
                    .with_span(patch.span),
                );
                continue;
            };
            if !matches!(input.ty.unwrap_optional(), Type::Collection(_)) {
                diagnostics.push(
                    Diagnostic::error(
                        codes::PATCH,
                        format!(
                            "input `{}.{}` is {}, not a collection — only collections can be patched",
                            instance.alias, patch.collection, input.ty
                        ),
                    )
                    .with_span(patch.span),
                );
                continue;
            }
            let item_ty = match input.ty.unwrap_optional() {
                Type::Collection(item) => (**item).clone(),
                _ => unreachable!("checked above"),
            };
            let Some((Value::Collection(collection), _)) = values.get_mut(&patch.collection) else {
                continue;
            };
            for op in &patch.ops {
                match op {
                    PatchOp::Replace { key, value, span } => {
                        let value = match coerce(
                            value.clone(),
                            &item_ty,
                            *span,
                            &format!(
                                "patch `{}.{}` replace \"{key}\"",
                                instance.alias, patch.collection
                            ),
                        ) {
                            Ok(value) => value,
                            Err(diag) => {
                                diagnostics.push(diag);
                                continue;
                            }
                        };
                        if let Value::KdlDocument(document) = &value {
                            check_kdl_nodes(
                                &mut patch_env,
                                document.nodes(),
                                diagnostics,
                                0,
                                span.file,
                            );
                        }
                        match collection.items.iter_mut().find(|item| &item.key == key) {
                            Some(item) => {
                                item.value = value.clone();
                                item.span = *span;
                            }
                            None => diagnostics.push(
                                Diagnostic::error(
                                    codes::PATCH,
                                    format!(
                                        "`replace \"{key}\"` in collection `{}.{}`: key does not exist",
                                        instance.alias, patch.collection
                                    ),
                                )
                                .with_span(*span)
                                .with_help("use `append` for new keys"),
                            ),
                        }
                    }
                    PatchOp::Append { key, value, span } => {
                        let value = match coerce(
                            value.clone(),
                            &item_ty,
                            *span,
                            &format!(
                                "patch `{}.{}` append \"{key}\"",
                                instance.alias, patch.collection
                            ),
                        ) {
                            Ok(value) => value,
                            Err(diag) => {
                                diagnostics.push(diag);
                                continue;
                            }
                        };
                        if let Value::KdlDocument(document) = &value {
                            check_kdl_nodes(
                                &mut patch_env,
                                document.nodes(),
                                diagnostics,
                                0,
                                span.file,
                            );
                        }
                        if collection.contains(key) {
                            diagnostics.push(
                                Diagnostic::error(
                                    codes::PATCH,
                                    format!(
                                        "`append \"{key}\"` in collection `{}.{}`: key already exists",
                                        instance.alias, patch.collection
                                    ),
                                )
                                .with_span(*span)
                                .with_help("use `replace` for existing keys"),
                            );
                        } else {
                            collection.items.push(crate::lang::value::CollectionItem {
                                key: key.clone(),
                                value: value.clone(),
                                span: *span,
                            });
                        }
                    }
                    PatchOp::Remove {
                        key,
                        optional,
                        span,
                    } => {
                        let existed = collection.items.iter().any(|item| &item.key == key);
                        if existed {
                            collection.items.retain(|item| &item.key != key);
                        } else if !optional {
                            diagnostics.push(
                                Diagnostic::error(
                                    codes::PATCH,
                                    format!(
                                        "`remove \"{key}\"` in collection `{}.{}`: key does not exist",
                                        instance.alias, patch.collection
                                    ),
                                )
                                .with_span(*span)
                                .with_help("add `optional=#true` if the key may be absent"),
                            );
                        }
                    }
                    PatchOp::ReplaceAll { items, span } => {
                        collection.items.clear();
                        for (key, value, item_span) in items {
                            let value = match coerce(
                                value.clone(),
                                &item_ty,
                                *item_span,
                                &format!(
                                    "patch `{}.{}` replace-all \"{key}\"",
                                    instance.alias, patch.collection
                                ),
                            ) {
                                Ok(value) => value,
                                Err(diag) => {
                                    diagnostics.push(diag);
                                    continue;
                                }
                            };
                            if let Value::KdlDocument(document) = &value {
                                check_kdl_nodes(
                                    &mut patch_env,
                                    document.nodes(),
                                    diagnostics,
                                    0,
                                    item_span.file,
                                );
                            }
                            collection.items.push(crate::lang::value::CollectionItem {
                                key: key.clone(),
                                value,
                                span: *item_span,
                            });
                        }
                        let _ = span;
                    }
                }
            }
            // Record the profile as the collection's value source.
            if let Some((_, origin)) = values.get_mut(&patch.collection) {
                *origin = crate::lang::value::ValueOrigin::Profile(profile_name.clone());
            }
        }

        typed.instances.push(TypedInstance {
            alias: instance.alias.clone(),
            module: instance.module.clone(),
            values,
            fragment_sources,
            span: instance.span,
        });
    }
    if diagnostics.error_count() > before {
        return Some(typed); // still useful for further reporting
    }
    Some(typed)
}

fn known_inputs_help(module: &ResolvedModule) -> String {
    let names: Vec<&str> = module.inputs().iter().map(|i| i.name.as_str()).collect();
    if names.is_empty() {
        "this module declares no inputs".to_owned()
    } else {
        format!("known inputs: {}", names.join(", "))
    }
}

/// A type-checked profile: per-instance final values and fragment sources.
#[derive(Debug)]
pub struct TypedProfile {
    #[allow(dead_code)]
    pub name: String,
    #[allow(dead_code)]
    pub chain: Vec<String>,
    pub instances: Vec<TypedInstance>,
}

#[derive(Debug)]
pub struct TypedInstance {
    pub alias: String,
    pub module: String,
    pub values: HashMap<String, (Value, crate::lang::value::ValueOrigin)>,
    pub fragment_sources: HashMap<String, Vec<crate::lang::ast::FragmentSource>>,
    #[allow(dead_code)]
    pub span: Span,
}

// Value coercion

/// Coerce a parsed value to its declared type, including records and paths.
pub(crate) fn coerce(value: Value, ty: &Type, span: Span, what: &str) -> Result<Value, Diagnostic> {
    let inner_ty = ty.unwrap_optional();
    if value.is_null() {
        if ty.is_optional() {
            return Ok(Value::Null);
        }
        return Err(Diagnostic::error(
            codes::TYPE_MISMATCH,
            format!("{what}: expected {ty}, got #null"),
        )
        .with_span(span));
    }
    let coerced = match (inner_ty, value) {
        (Type::Bool, Value::Bool(b)) => Value::Bool(b),
        (Type::Int, Value::Int(i)) => Value::Int(i),
        (Type::Float, Value::Float(x)) => Value::Float(x),
        (Type::Float, Value::Int(i)) => Value::Float(exact_i64_to_f64(i).ok_or_else(|| {
            Diagnostic::error(
                codes::TYPE_MISMATCH,
                format!("{what}: integer `{i}` cannot be represented exactly as a float"),
            )
            .with_span(span)
        })?),
        (Type::String, Value::String(s)) => Value::String(s),
        (Type::Enum(values), Value::String(value)) if values.contains(&value) => {
            Value::String(value)
        }
        (Type::Enum(values), Value::String(value)) => {
            return Err(Diagnostic::error(
                codes::TYPE_MISMATCH,
                format!(
                    "{what}: enum value `{value}` is not allowed (expected one of: {})",
                    values.join(", ")
                ),
            )
            .with_span(span));
        }
        (Type::Path, Value::String(s) | Value::Path(s)) => {
            let resolved = resolve_path_value(&s).map_err(|reason| {
                Diagnostic::error(
                    codes::TYPE_MISMATCH,
                    format!("{what}: {reason} (got `{s}`)"),
                )
                .with_span(span)
            })?;
            Value::Path(resolved)
        }
        (Type::List(item), Value::List(values)) => {
            let mut out = Vec::with_capacity(values.len());
            for (index, v) in values.into_iter().enumerate() {
                out.push(coerce(v, item, span, &format!("{what}[{index}]"))?);
            }
            Value::List(out)
        }
        (Type::List(item), Value::KdlDocument(doc)) if matches!(item.as_ref(), Type::Record(_)) => {
            let mut out = Vec::new();
            for (index, node) in doc.nodes().iter().enumerate() {
                if node.name().value() != "item" || node.iter().any(|entry| entry.name().is_none())
                {
                    return Err(Diagnostic::error(
                        codes::TYPE_MISMATCH,
                        format!("{what}: list<record> override expects `item {{ ... }}` children"),
                    )
                    .with_span(span));
                }
                out.push(coerce(
                    Value::KdlDocument(node.children().cloned().unwrap_or_default()),
                    item,
                    span,
                    &format!("{what}[{index}]"),
                )?);
            }
            Value::List(out)
        }
        // A scalar where a list is expected becomes a one-element list because
        // KDL cannot distinguish `x "a"` from a one-item list syntactically.
        (Type::List(item), scalar)
            if !matches!(
                scalar,
                Value::Record(_) | Value::Collection(_) | Value::KdlDocument(_)
            ) =>
        {
            Value::List(vec![coerce(scalar, item, span, what)?])
        }
        (Type::Record(schema), Value::KdlDocument(doc)) => {
            Value::Record(record_from_document(schema, &doc, span, what)?)
        }
        (Type::Record(schema), Value::Record(mut record)) => {
            // Revalidate records that were built while parsing defaults.
            for field in &schema.fields {
                match record.get(&field.name) {
                    Some(Value::Null) if !field.required => {}
                    Some(v) => {
                        coerce(
                            v.clone(),
                            &field.ty,
                            span,
                            &format!("{what}.{}", field.name),
                        )?;
                    }
                    None if field.required => {
                        return Err(Diagnostic::error(
                            codes::RECORD_FIELD,
                            format!("{what}: missing required field `{}`", field.name),
                        )
                        .with_span(span));
                    }
                    None => {}
                }
            }
            for key in record.keys() {
                if schema.field(key).is_none() {
                    return Err(Diagnostic::error(
                        codes::RECORD_FIELD,
                        format!("{what}: unknown field `{key}` (records are closed)"),
                    )
                    .with_span(span));
                }
            }
            for field in &schema.fields {
                if !field.required && record.get(&field.name).is_none() {
                    record.insert(field.name.clone(), Value::Null);
                }
            }
            Value::Record(record)
        }
        (Type::Collection(item), Value::Collection(collection)) => {
            let mut validated = crate::lang::value::KeyedCollection::default();
            for entry in collection.items {
                let value = coerce(
                    entry.value,
                    item,
                    entry.span,
                    &format!("{what}[\"{}\"]", entry.key),
                )?;
                validated.items.push(crate::lang::value::CollectionItem {
                    key: entry.key,
                    value,
                    span: entry.span,
                });
            }
            Value::Collection(validated)
        }
        (Type::KdlDocument, Value::KdlDocument(doc)) => Value::KdlDocument(doc),
        (expected, actual) => {
            return Err(Diagnostic::error(
                codes::TYPE_MISMATCH,
                format!(
                    "{what}: expected {expected}, got {} `{}`",
                    actual.type_label(),
                    actual.display()
                ),
            )
            .with_span(span));
        }
    };
    Ok(coerced)
}

fn record_from_document(
    schema: &RecordSchema,
    doc: &KdlDocument,
    span: Span,
    what: &str,
) -> Result<Record, Diagnostic> {
    let mut record = Record::new();
    for node in doc.nodes() {
        let field_name = node.name().value();
        let Some(field) = schema.field(field_name) else {
            return Err(Diagnostic::error(
                codes::RECORD_FIELD,
                format!("{what}: unknown field `{field_name}` (records are closed)"),
            )
            .with_span(span));
        };
        if record.get(field_name).is_some() {
            return Err(Diagnostic::error(
                codes::DUPLICATE,
                format!("{what}: field `{field_name}` is set twice"),
            )
            .with_span(span));
        }
        let args: Vec<&kdl::KdlEntry> = node.iter().filter(|e| e.name().is_none()).collect();
        let raw = match (&field.ty, args.len()) {
            (Type::List(_), _) => {
                let mut items = Vec::new();
                for arg in &args {
                    items.push(kdl_scalar(arg).map_err(|m| {
                        Diagnostic::error(codes::RECORD_FIELD, format!("{what}.{field_name}: {m}"))
                            .with_span(span)
                    })?);
                }
                Value::List(items)
            }
            (_, 1) => kdl_scalar(args[0]).map_err(|m| {
                Diagnostic::error(codes::RECORD_FIELD, format!("{what}.{field_name}: {m}"))
                    .with_span(span)
            })?,
            (_, n) => {
                return Err(Diagnostic::error(
                    codes::RECORD_FIELD,
                    format!("{what}.{field_name}: expected one value, found {n}"),
                )
                .with_span(span));
            }
        };
        let coerced = coerce(raw, &field.ty, span, &format!("{what}.{field_name}"))?;
        record.insert(field_name.to_owned(), coerced);
    }
    for field in &schema.fields {
        if field.required && record.get(&field.name).is_none() {
            return Err(Diagnostic::error(
                codes::RECORD_FIELD,
                format!("{what}: missing required field `{}`", field.name),
            )
            .with_span(span));
        } else if !field.required && record.get(&field.name).is_none() {
            record.insert(field.name.clone(), Value::Null);
        }
    }
    Ok(record)
}

fn kdl_scalar(entry: &kdl::KdlEntry) -> Result<Value, String> {
    if entry.ty().is_some() {
        return Err("type-annotated values are not allowed here".to_owned());
    }
    match entry.value() {
        kdl::KdlValue::Null => Err("#null is not a field value".to_owned()),
        kdl::KdlValue::Bool(b) => Ok(Value::Bool(*b)),
        kdl::KdlValue::Integer(i) => i64::try_from(*i)
            .map(Value::Int)
            .map_err(|_| "integer out of range".to_owned()),
        kdl::KdlValue::Float(x) if x.is_finite() => Ok(Value::Float(*x)),
        kdl::KdlValue::Float(_) => Err("non-finite float is not allowed".to_owned()),
        kdl::KdlValue::String(s) => Ok(Value::String(s.clone())),
    }
}

fn resolve_path_value(raw: &str) -> Result<String, &'static str> {
    if raw.is_empty() {
        return Err("path must not be empty");
    }
    let expanded = normalize_lexical(&expand_tilde(raw));
    if !expanded.is_absolute() {
        return Err("path must be absolute or start with `~/`");
    }
    expanded
        .into_os_string()
        .into_string()
        .map_err(|_| "path is not valid UTF-8")
}
