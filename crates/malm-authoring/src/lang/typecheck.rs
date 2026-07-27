//! Static checks for every module and profile, including defaults, references,
//! control flow, profile overrides, patches, and fragment sources.

use crate::AuthoringSourceSetV1;
use crate::lang::ast::{
    FragmentCardinality, FragmentOp, FragmentSource, InputDecl, KdlConfigBody, OutputNode,
    PatchEntry, PatchOp, Predicate, Ref, RequirementNode, SetPatch,
};
use crate::lang::budget::Limits;
use crate::lang::config_file::{ConfigItem, ConfigValue};
use crate::lang::diag::{Diagnostic, Diagnostics, FileId, Span, codes};
use crate::lang::kdl_util::{
    child_nodes, entry_span, expect_args, node_span, parse_condition, parse_each_header,
    parse_range_header, parse_splice, req_str_arg,
};
use crate::lang::resolve::{ResolvedInputOp, ResolvedModule, ResolvedWorkspace, resolve_profile};
use crate::lang::scope::Scope;
use crate::lang::text::{self, TemplateSyntax};
use crate::lang::value::{
    FieldSchema, LoweredList, LoweredType, RawRecordLiteral, RawRecordProperty, Record,
    RecordSchema, Type, Value, exact_i64_to_f64,
};
use crate::paths::normalize_lexical;
use kdl::{KdlDocument, KdlNode};
use std::collections::HashMap;
use std::path::Path;

/// Built-ins and limits supplied to profile checking. Computed defaults may
/// reference `malm.target` and `machine.hostname`; a hostname is available
/// only when the caller trusts its local source.
#[derive(Clone, Copy)]
pub struct CheckOptions<'a> {
    /// The configured `malm.target` value, mirrored from `config target="..."`
    /// or the compile-time target root.
    pub target_root: &'a str,
    /// The host name observed by `machine.hostname`. `None` lowers to
    /// `Value::Null` so references surface a coercion error rather than
    /// silently producing an empty string.
    pub hostname: Option<&'a str>,
    /// Active compilation limits for value coercion and computed templates.
    pub limits: Limits,
}

impl CheckOptions<'_> {
    /// Returns options for checks that have no configured target or hostname.
    fn empty() -> Self {
        Self {
            target_root: "",
            hostname: None,
            limits: Limits::default(),
        }
    }
}

/// Names visible to `(ref)` lookups, mapped to their types.
pub(crate) struct TypeEnv<'a> {
    module: &'a ResolvedModule,
    workspace: &'a ResolvedWorkspace,
    /// The captured source tree backing source-file checks.
    sources: &'a AuthoringSourceSetV1,
    /// Loop bindings, innermost last.
    bindings: Vec<(String, Type)>,
    /// References proven non-null by enclosing `@if-present` then branches.
    refinements: Vec<String>,
}

impl<'a> TypeEnv<'a> {
    pub(crate) fn new(
        workspace: &'a ResolvedWorkspace,
        sources: &'a AuthoringSourceSetV1,
        module: &'a ResolvedModule,
    ) -> Self {
        Self {
            module,
            workspace,
            sources,
            bindings: Vec::new(),
            refinements: Vec::new(),
        }
    }

    /// Resolves a reference type. Dotted input and binding names recursively
    /// address record fields; `global.*` and built-ins are namespaces.
    pub(crate) fn lookup(&self, name: &str) -> Option<Type> {
        if let Some((_, ty)) = self.bindings.iter().rev().find(|(n, _)| n == name) {
            return Some(self.refine(name, ty.clone()));
        }
        if let Some((binding, ty)) = self.longest_binding_prefix(name) {
            return self.lookup_value_path(binding, ty, &name[binding.len() + 1..]);
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
        if let Some(input) = self
            .module
            .inputs()
            .iter()
            .filter(|input| {
                name.starts_with(&input.name)
                    && name.as_bytes().get(input.name.len()) == Some(&b'.')
            })
            .max_by_key(|input| input.name.len())
        {
            return self.lookup_value_path(&input.name, &input.ty, &name[input.name.len() + 1..]);
        }
        None
    }

    fn longest_binding_prefix(&self, name: &str) -> Option<(&str, &Type)> {
        let mut best: Option<(&str, &Type)> = None;
        for (binding, ty) in self.bindings.iter().rev() {
            if name.starts_with(binding)
                && name.as_bytes().get(binding.len()) == Some(&b'.')
                && best.is_none_or(|(current, _)| binding.len() > current.len())
            {
                best = Some((binding, ty));
            }
        }
        best
    }

    fn lookup_value_path(&self, owner: &str, ty: &Type, path: &str) -> Option<Type> {
        let outer_optional = ty.is_optional() && !self.is_refined(owner);
        let unwrapped = ty.unwrap_optional();
        match unwrapped.lowered_type() {
            LoweredType::Record => {
                // Variant schemas expose the discriminator and case fields in
                // the same record shape produced by coercion.
                let record_schema = match unwrapped.operational_type() {
                    Type::Record(schema) => RecordOrVariant::Record(schema),
                    Type::Variant(schema) => RecordOrVariant::Variant(schema),
                    _ => unreachable!("lowered record has record-compatible schema"),
                };

                // Prefer an exact field name before interpreting dots as path
                // separators.
                if let Some(field) = record_schema.field(path) {
                    let ty = optionalize(field.lookup_type(), outer_optional);
                    return Some(self.refine(&format!("{owner}.{path}"), ty));
                }

                let (field_name, tail) = path.split_once('.')?;
                let field = record_schema.field(field_name)?;
                let field_owner = format!("{owner}.{field_name}");
                let field_ty = optionalize(field.lookup_type(), outer_optional);
                let field_ty = self.refine(&field_owner, field_ty);
                self.lookup_value_path(&field_owner, &field_ty, tail)
            }
            LoweredType::Collection(item) => {
                let item_ty = optionalize(item.clone(), true);
                // For scalar payloads, treat the complete remainder as the key
                // so dotted collection keys remain addressable.
                if !matches!(
                    item.unwrap_optional().lowered_type(),
                    LoweredType::Record | LoweredType::Collection(_) | LoweredType::List(_)
                ) {
                    return Some(self.refine(&format!("{owner}.{path}"), item_ty));
                }
                let (key, tail) = path
                    .split_once('.')
                    .map_or((path, None), |(key, tail)| (key, Some(tail)));
                // Collection and map keys are authored data and may be absent, so
                // a lookup is optional even when the map itself is required.
                let item_owner = format!("{owner}.{key}");
                let traversed = match tail {
                    Some(tail) => self.lookup_value_path(&item_owner, &item_ty, tail),
                    None => Some(self.refine(&item_owner, item_ty)),
                };
                // A missing key is a valid optional lookup. Use the exact-key
                // item type only when traversal finds no more precise type.
                traversed.or_else(|| {
                    Some(self.refine(&format!("{owner}.{path}"), optionalize(item.clone(), true)))
                })
            }
            LoweredType::List(list) => {
                let (index, tail) = path
                    .split_once('.')
                    .map_or((path, None), |(index, tail)| (index, Some(tail)));
                let index = index.parse::<usize>().ok()?;
                let item_ty = match list {
                    LoweredList::Tuple(types) => types.get(index)?.clone(),
                    LoweredList::Homogeneous(item) => optionalize(item.clone(), true),
                };
                let item_ty = optionalize(item_ty, outer_optional);
                let item_owner = format!("{owner}.{index}");
                match tail {
                    Some(tail) => self.lookup_value_path(&item_owner, &item_ty, tail),
                    None => Some(self.refine(&item_owner, item_ty)),
                }
            }
            _ => None,
        }
    }

    fn is_refined(&self, name: &str) -> bool {
        self.refinements.iter().rev().any(|refined| refined == name)
    }

    fn declaration_span(&self, name: &str) -> Option<Span> {
        self.module
            .inputs()
            .iter()
            .filter(|input| {
                name == input.name
                    || (name.starts_with(&input.name)
                        && name.as_bytes().get(input.name.len()) == Some(&b'.'))
            })
            .max_by_key(|input| input.name.len())
            .map(|declaration| declaration.span)
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
        // Lexical bindings may shadow only other bindings.
        let shadows_non_binding =
            self.bindings.iter().all(|(n, _)| n != name) && self.lookup(name).is_some();
        if shadows_non_binding {
            diagnostics.error_at_with_help(
                codes::BINDING,
                format!("loop binding `{name}` shadows a non-binding name"),
                span,
                "rename the binding; inner bindings may shadow only other loop bindings",
            );
            return false;
        }
        self.bindings.push((name.to_owned(), ty));
        true
    }

    fn pop_binding(&mut self) {
        self.bindings.pop();
    }

    /// Pushes an internal binding such as `b.key` after its parent is checked.
    fn push_synthetic_binding(&mut self, name: String, ty: Type) {
        self.bindings.push((name, ty));
    }
}

fn optionalize(ty: Type, optional: bool) -> Type {
    if optional && !ty.is_optional() {
        Type::Optional(Box::new(ty))
    } else {
        ty
    }
}

/// Either a record or a variant schema, unified for record-path lookup. Both
/// produce a [`FieldSchema`] for any matching field name. Variants lower to
/// records at coercion time, so reference lookups see the discriminator as a
/// required string and every case field as optional.
enum RecordOrVariant<'a> {
    Record(&'a RecordSchema),
    Variant(&'a crate::lang::value::VariantSchema),
}

impl<'a> RecordOrVariant<'a> {
    fn field(&self, name: &str) -> Option<FieldSchema> {
        match self {
            Self::Record(schema) => schema.field(name).cloned(),
            Self::Variant(schema) => schema.field(name),
        }
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

/// Checks every module and profile in the workspace.
pub fn check_workspace(
    workspace: &ResolvedWorkspace,
    sources: &AuthoringSourceSetV1,
    diagnostics: &mut Diagnostics,
) {
    let options = CheckOptions::empty();
    for module in workspace.modules.values() {
        check_module(workspace, sources, module, diagnostics);
    }
    for profile in &workspace.profiles {
        check_profile_inner(
            workspace,
            sources,
            &profile.name,
            diagnostics,
            false,
            options,
        );
    }
}

pub fn check_module(
    workspace: &ResolvedWorkspace,
    sources: &AuthoringSourceSetV1,
    module: &ResolvedModule,
    diagnostics: &mut Diagnostics,
) {
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
    let mut collection_env = TypeEnv::new(workspace, sources, module);
    for input in module.inputs() {
        if let Some(default) = &input.default {
            check_kdl_collection_value(&mut collection_env, default, diagnostics);
        }
    }
    for fragment in &module.decl.fragments {
        for source in &fragment.defaults {
            validate_fragment_source(
                source,
                sources,
                &workspace.source_root,
                &fragment.name,
                &fragment.format,
                diagnostics,
            );
        }
    }
    let mut requirement_env = TypeEnv::new(workspace, sources, module);
    check_requirement_nodes(&mut requirement_env, module.requires(), diagnostics);
    let mut env = TypeEnv::new(workspace, sources, module);
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
                    diagnostics.error_at(codes::REQUIREMENT,
                            format!(
                                "conditional requirements may reference module inputs only; `{}` is not an input of module `{}`",
                                reference.name, env.module.decl.name
                            ), reference.span);
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
    sources: &AuthoringSourceSetV1,
    source_root: &Path,
    span: Span,
) -> Result<(), Diagnostic> {
    let resolved = resolve_source(path, base_dir, source_root)
        .map_err(|message| Diagnostic::error(codes::OUTPUT_PATH, message).with_span(span))?;
    if !sources.contains_path(&resolved) {
        return Err(Diagnostic::error(
            codes::FRAGMENT,
            format!("source file not found: {}", resolved.display()),
        )
        .with_span(span));
    }
    Ok(())
}

fn validate_fragment_source(
    source: &FragmentSource,
    sources: &AuthoringSourceSetV1,
    source_root: &Path,
    fragment: &str,
    format: &str,
    diagnostics: &mut Diagnostics,
) {
    let span = source.span;
    let resolved = match resolve_source(&source.path, &source.base_dir, source_root) {
        Ok(resolved) => resolved,
        Err(message) => {
            diagnostics.error_at(codes::OUTPUT_PATH, message, span);
            return;
        }
    };
    let Some(bytes) = sources.get_path(&resolved) else {
        diagnostics.error_at(
            codes::FRAGMENT,
            format!("source file not found: {}", resolved.display()),
            span,
        );
        return;
    };
    let limit = Limits::default().max_render_bytes;
    if bytes.len() as u64 > limit {
        diagnostics.error_at(
            codes::FRAGMENT,
            format!(
                "fragment `{fragment}` source {} exceeds the maximum of {limit} bytes",
                resolved.display()
            ),
            span,
        );
        return;
    }
    let text = match std::str::from_utf8(bytes) {
        Ok(text) => text,
        Err(_) => {
            diagnostics.error_at(
                codes::FRAGMENT,
                format!("fragment source {} is not valid UTF-8", resolved.display()),
                span,
            );
            return;
        }
    };
    let problems = crate::lang::artifact::validate_format(format, text);
    for problem in &problems {
        diagnostics.error_at(
            codes::FRAGMENT,
            format!(
                "fragment `{fragment}` source {} is not valid {format}: {problem}",
                resolved.display()
            ),
            span,
        );
    }
    if !problems.is_empty() {
        return;
    }
    let document = match format {
        "kdl-v1" => KdlDocument::parse_v1(text).ok(),
        "kdl-v2" => text.parse::<KdlDocument>().ok(),
        _ => None,
    };
    if let Some(document) = document
        && let Err(diagnostic) =
            crate::lang::parse::validate_structural_kdl_document(span.file, document.nodes())
    {
        diagnostics.push(diagnostic.with_span(span).with_note(format!(
            "while validating fragment `{fragment}` source {}",
            resolved.display()
        )));
    }
}

/// Resolves `./` from the declaring file and other relative paths from the
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
            diagnostics.error_at_with_help(codes::UNDEFINED_REF,
                    format!("`{}` is not defined in this module's scope", reference.name), reference.span, "references resolve against the module's inputs, loop bindings, global.* tokens, and built-ins",);
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
            if !matches!(ty.lowered_type(), LoweredType::Bool) {
                let mut diagnostic = Diagnostic::error(
                    codes::WHEN_PREDICATE,
                    format!("`@if` requires bool, found {ty}"),
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
            // Hostname guards must type-check for both trusted and untrusted loads.
            if !ty.is_optional() && reference.name != "machine.hostname" {
                let mut diagnostic = Diagnostic::error(
                    codes::WHEN_PREDICATE,
                    format!("`@if-present` requires optional<T>, found {ty}"),
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
            if !matches!(
                ty.unwrap_optional().lowered_type(),
                LoweredType::List(_) | LoweredType::Collection(_)
            ) || ty.is_optional()
            {
                let mut diagnostic = Diagnostic::error(
                    codes::WHEN_PREDICATE,
                    format!("`@if-nonempty` requires a list or collection, found {ty}"),
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
            // A variant case field is absent when another case is active.
            // Equality against that absent value matches no literal.
            let resolved = ty.unwrap_optional().lowered_type();
            let comparable = matches!(
                resolved,
                LoweredType::Bool
                    | LoweredType::Int
                    | LoweredType::String
                    | LoweredType::Path
                    | LoweredType::Enum(_)
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
            let literal_matches = match (resolved, expected) {
                (LoweredType::Bool, Value::Bool(_)) => true,
                (LoweredType::Int, Value::Int(_)) => true,
                (LoweredType::String | LoweredType::Path, Value::String(_)) => true,
                (LoweredType::Enum(values), Value::String(value)) => {
                    if !values.contains(value) {
                        diagnostics.error_at(codes::WHEN_PREDICATE,
                                format!(
                                    "`is=\"{value}\"` is not a declared value of `{}` (expected one of: {})",
                                    reference.name,
                                    values.join(", ")
                                ), reference.span);
                    }
                    true
                }
                _ => false,
            };
            if !literal_matches {
                diagnostics.error_at(
                    codes::WHEN_PREDICATE,
                    format!(
                        "`is=` literal must match the type of `{}` ({ty})",
                        reference.name
                    ),
                    reference.span,
                );
            }
        }
    }
}

fn predicate_help(ty: &Type) -> String {
    if ty.is_optional() {
        return "use `@if-present` for optional values".to_owned();
    }
    match ty.lowered_type() {
        LoweredType::List(_) | LoweredType::Collection(_) => {
            "use `@if-nonempty` for lists and collections".to_owned()
        }
        LoweredType::Bool => "use `@if` for booleans".to_owned(),
        _ => "there is no implicit truthiness; expose a semantic boolean input instead".to_owned(),
    }
}

fn check_output_node(env: &mut TypeEnv<'_>, node: &OutputNode, diagnostics: &mut Diagnostics) {
    match node {
        OutputNode::KdlConfig(config) => {
            let KdlConfigBody::Document { nodes, file, .. } = &config.body;
            check_kdl_nodes(env, nodes, diagnostics, 0, *file);
        }
        OutputNode::ConfigFile(config_file) => {
            check_generic_body(env, &config_file.body, diagnostics);
        }
        OutputNode::Render(render) => {
            if let crate::lang::render::PathExpr::FString { raw, span } = &render.to {
                check_render_template(env, raw, *span, diagnostics);
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
                env.sources,
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
                    Ok(path) if env.sources.contains_dir(&path) => {}
                    Ok(path) => diagnostics.error_at(
                        codes::OUTPUT_PATH,
                        format!("dir source not found: {}", path.display()),
                        dir.span,
                    ),
                    Err(message) => diagnostics.error_at(codes::OUTPUT_PATH, message, dir.span),
                }
            }
        }
        OutputNode::Symlink(symlink) => {
            if let crate::lang::ast::SymlinkSource::Ref(reference) = &symlink.source
                && let Some(ty) = check_ref(env, reference, diagnostics)
                && !matches!(
                    ty.unwrap_optional().lowered_type(),
                    LoweredType::Path | LoweredType::String
                )
            {
                diagnostics.error_at(
                    codes::TYPE_MISMATCH,
                    format!("symlink `source=` requires a path, found {ty}"),
                    reference.span,
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
            let keyed = matches!(
                env.lookup(&each.source.name)
                    .as_ref()
                    .map(Type::lowered_type),
                Some(LoweredType::Collection(_))
            );
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
        ShapeNode::Comment { .. }
        | ShapeNode::Raw { .. }
        | ShapeNode::Requirements { .. }
        | ShapeNode::Profiles { .. } => {}
        ShapeNode::Line { value, .. } => check_render_value(env, value, diagnostics),
        ShapeNode::File {
            path,
            interpolate,
            span,
        } => {
            if let Err(diag) =
                check_source_path(path, dir, env.sources, &env.workspace.source_root, *span)
            {
                diagnostics.push(diag);
                return;
            }
            // Captured source paths are validated relative paths and cannot
            // escape the source-set root.
            if *interpolate
                && let Ok(resolved) = resolve_source(path, dir, &env.workspace.source_root)
                && let Some(text) = env
                    .sources
                    .get_path(&resolved)
                    .and_then(|bytes| std::str::from_utf8(bytes).ok())
            {
                for issue in
                    text::check_template_with(text, TemplateSyntax::V3, &|name| env.lookup(name))
                {
                    diagnostics.error_at(codes::TEMPLATE, format!("{path}: {issue}"), *span);
                }
            }
        }
        ShapeNode::Compose { fragment, span } => {
            check_compose(env, fragment, *span, diagnostics);
        }
        ShapeNode::Spread(spread) => {
            if let Some(ty) = check_ref(env, &spread.reference, diagnostics)
                && !matches!(ty.lowered_type(), LoweredType::Record)
            {
                diagnostics.error_at(
                    codes::TYPE_MISMATCH,
                    format!("`@insert-fields` requires a record, found {ty}"),
                    spread.span,
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
    for issue in text::check_template_with(raw, TemplateSyntax::V3, &|name| env.lookup(name)) {
        diagnostics.error_at(codes::TEMPLATE, issue, span);
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
                    diagnostics.error_at(
                        codes::TYPE_MISMATCH,
                        format!(
                            "`(ref?)` targets an optional; `{}` is {ty} — use `(ref)`",
                            reference.name
                        ),
                        reference.span,
                    );
                    return;
                }
                check_render_ref_payload(ty.unwrap_optional(), reference, diagnostics);
            } else {
                if ty.is_optional() {
                    diagnostics.error_at(
                        codes::TYPE_MISMATCH,
                        format!(
                            "`{}` is {ty}; guard with `@if-present` or use `(ref?)`",
                            reference.name
                        ),
                        reference.span,
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
        ty.lowered_type(),
        LoweredType::Bool
            | LoweredType::Int
            | LoweredType::Float
            | LoweredType::String
            | LoweredType::Path
            | LoweredType::Enum(_)
            | LoweredType::List(_)
            | LoweredType::Record
            | LoweredType::Collection(_)
    ) {
        diagnostics.error_at(
            codes::TYPE_MISMATCH,
            format!(
                "render value requires a scalar, list, record, or collection; `{}` is {ty}",
                reference.name
            ),
            reference.span,
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
                let keyed = matches!(
                    env.lookup(&each.source.name)
                        .as_ref()
                        .map(Type::lowered_type),
                    Some(LoweredType::Collection(_))
                );
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
                // The receiving format parses patched payloads after composition.
                Some(ty)
                    if matches!(
                        ty.lowered_type(),
                        LoweredType::Collection(item)
                            if matches!(item.lowered_type(), LoweredType::KdlDocument)
                    ) => {}
                Some(other) => diagnostics.error_at(
                    codes::TYPE_MISMATCH,
                    format!(
                        "`@insert-documents` requires a collection<kdl-document>, found {other}"
                    ),
                    reference.span,
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
        diagnostics.error_at(
            codes::TYPE_MISMATCH,
            format!("config value requires {expected}, found {ty}"),
            span,
        );
    }
}

fn config_scalar(ty: &Type) -> bool {
    ty.lowered_type().is_scalar()
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
        Value::KdlDocument(_) | Value::RawRecordLiteral(_) | Value::UnresolvedListDefault(_) => {
            Type::KdlDocument
        }
    }
}

fn check_compose(env: &TypeEnv<'_>, fragment: &str, span: Span, diagnostics: &mut Diagnostics) {
    if env.module.fragment(fragment).is_none() {
        diagnostics.error_at(
            codes::FRAGMENT,
            format!(
                "module `{}` includes undeclared fragment `{fragment}`",
                env.module.decl.name
            ),
            span,
        );
    }
}

fn check_each_source(env: &TypeEnv<'_>, source: &Ref, diagnostics: &mut Diagnostics) -> Type {
    match env.lookup(&source.name) {
        None => {
            diagnostics.error_at(
                codes::UNDEFINED_REF,
                format!("`{}` is not defined in this module's scope", source.name),
                source.span,
            );
            Type::String
        }
        Some(ty) => match ty.lowered_type() {
            LoweredType::List(LoweredList::Homogeneous(item)) | LoweredType::Collection(item) => {
                item.clone()
            }
            LoweredType::List(LoweredList::Tuple(types))
                if types
                    .first()
                    .is_some_and(|first| types.iter().all(|ty| ty == first)) =>
            {
                types[0].clone()
            }
            _ => {
                diagnostics.error_at(
                    codes::LOOP_SOURCE,
                    format!("`@for-each` requires a list or collection, found {ty}"),
                    source.span,
                );
                Type::String
            }
        },
    }
}

fn check_range_bounds(from: i64, through: i64, span: Span, diagnostics: &mut Diagnostics) {
    if through < from {
        diagnostics.error_at(
            codes::RANGE,
            format!("`@for-range` is empty: from={from} through={through}"),
            span,
        );
    }
}

/// Walks inline target KDL nodes, checking controls and every `(ref)` entry.
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
    let mut nodes = nodes.iter().peekable();
    while let Some(node) = nodes.next() {
        if matches!(node.name().value(), "@if" | "@if-present" | "@if-nonempty") {
            let otherwise = if nodes
                .peek()
                .is_some_and(|next| next.name().value() == "@else")
            {
                Some(nodes.next().expect("peeked"))
            } else {
                None
            };
            check_structural_kdl(env, node, otherwise, diagnostics, depth, file);
        } else {
            check_kdl_node(env, node, diagnostics, depth, file);
        }
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
        "@for-each" | "@for-range" | "@insert-documents" | "@include-fragment" => {
            check_structural_kdl(env, node, None, diagnostics, depth, file);
        }
        "@else" => {
            diagnostics.error_at(
                codes::NODE_SHAPE,
                "`@else` must immediately follow an `@if`, `@if-present`, or `@if-nonempty` sibling",
                node_span(file, node),
            );
        }
        _ => {
            // Target-node references must be scalar and properties unique.
            let escaped_target = (name == "node")
                .then(|| crate::lang::kdl_util::escaped_node_target(node))
                .flatten();
            let target_name = escaped_target
                .and_then(|(_, entry)| entry.value().as_string())
                .unwrap_or(name);
            let mut seen_props: Vec<&str> = Vec::new();
            for (index, entry) in node.iter().enumerate() {
                if escaped_target.is_some_and(|(target_index, _)| index == target_index) {
                    continue;
                }
                if let Some(prop) = entry.name() {
                    if seen_props.contains(&prop.value()) {
                        diagnostics.error_at(
                            codes::DUPLICATE,
                            format!(
                                "node `{target_name}` sets property `{}` twice",
                                prop.value()
                            ),
                            entry_span(file, entry),
                        );
                    }
                    seen_props.push(prop.value());
                }
                if crate::lang::kdl_util::is_ref(entry) {
                    let ref_name = entry.value().as_string().unwrap_or_default();
                    match env.lookup(ref_name) {
                        None => diagnostics.error_at(codes::UNDEFINED_REF,
                                format!("`{ref_name}` is not defined in this module's scope (in node `{target_name}`)"), entry_span(file, entry)),
                        Some(ty) => {
                            if !ty.lowered_type().is_scalar() {
                                diagnostics.error_at(codes::TYPE_MISMATCH,
                                        format!(
                                            "`(ref)\"{ref_name}\"` inserts a non-optional typed scalar; found {ty}"
                                        ), entry_span(file, entry));
                            }
                        }
                    }
                } else if let kdl::KdlValue::String(text) = entry.value()
                    && text.contains("{{")
                {
                    for issue in text::check_template_with_v3(text, &|name| env.lookup(name)) {
                        diagnostics.error_at(
                            codes::TEMPLATE,
                            format!("node `{target_name}` string: {issue}"),
                            entry_span(file, entry),
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
    otherwise: Option<&KdlNode>,
    diagnostics: &mut Diagnostics,
    depth: usize,
    file: FileId,
) {
    match node.name().value() {
        "@if" | "@if-present" | "@if-nonempty" => {
            let predicate = match parse_condition(file, node) {
                Ok(predicate) => predicate,
                Err(diagnostic) => {
                    diagnostics.push(diagnostic);
                    return;
                }
            };
            check_predicate(env, &predicate, diagnostics);
            let refined = match &predicate {
                Predicate::Set(reference) => Some(reference.name.as_str()),
                _ => None,
            };
            if let Some(name) = refined {
                env.push_refinement(name);
            }
            check_kdl_nodes(env, child_nodes(node), diagnostics, depth + 1, file);
            if refined.is_some() {
                env.pop_refinement();
            }
            if let Some(otherwise) = otherwise {
                check_kdl_nodes(env, child_nodes(otherwise), diagnostics, depth + 1, file);
            }
        }
        "@for-each" => {
            let (binding, source) = match parse_each_header(file, node) {
                Ok(header) => header,
                Err(diagnostic) => {
                    diagnostics.push(diagnostic);
                    return;
                }
            };
            let keyed = matches!(
                env.lookup(&source.name).as_ref().map(Type::lowered_type),
                Some(LoweredType::Collection(_))
            );
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
        "@for-range" => {
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
        "@insert-documents" => {
            let reference = match parse_splice(file, node) {
                Ok(reference) => reference,
                Err(diagnostic) => {
                    diagnostics.push(diagnostic);
                    return;
                }
            };
            match env.lookup(&reference.name) {
                Some(ty)
                    if matches!(
                        ty.lowered_type(),
                        LoweredType::Collection(item)
                            if matches!(item.lowered_type(), LoweredType::KdlDocument)
                    ) => {}
                Some(other) => diagnostics.error_at(
                    codes::TYPE_MISMATCH,
                    format!(
                        "`@insert-documents` requires a collection<kdl-document>, found {other}"
                    ),
                    reference.span,
                ),
                None => diagnostics.error_at(
                    codes::UNDEFINED_REF,
                    format!("`{}` is not defined in this module's scope", reference.name),
                    reference.span,
                ),
            }
        }
        "@include-fragment" => {
            let span = node_span(file, node);
            let Some(fragment) = node.get("fragment").and_then(kdl::KdlValue::as_string) else {
                diagnostics.error_at(
                    codes::NODE_SHAPE,
                    "`@include-fragment` requires `fragment=\"...\"`",
                    span,
                );
                return;
            };
            let Some(decl) = env.module.fragment(fragment) else {
                diagnostics.error_at(
                    codes::FRAGMENT,
                    format!(
                        "module `{}` includes undeclared fragment `{fragment}`",
                        env.module.decl.name
                    ),
                    span,
                );
                return;
            };
            if !matches!(decl.format.as_str(), "kdl-v1" | "kdl-v2") {
                diagnostics.error_at(codes::FRAGMENT,
                        format!(
                            "inline fragment `{fragment}` requires format `kdl-v1` or `kdl-v2`, found `{}`",
                            decl.format
                        ), span);
            }
            if decl.cardinality != FragmentCardinality::One {
                diagnostics.error_at(
                    codes::FRAGMENT,
                    format!(
                        "inline fragment `{fragment}` requires cardinality `one`, found `many`"
                    ),
                    span,
                );
            }
        }
        _ => unreachable!("caller matched structural names"),
    }
}

/// Resolves and type-checks a profile for downstream instantiation.
pub fn check_profile(
    workspace: &ResolvedWorkspace,
    sources: &AuthoringSourceSetV1,
    name: &str,
    diagnostics: &mut Diagnostics,
    options: CheckOptions<'_>,
) -> Option<TypedProfile> {
    check_profile_inner(workspace, sources, name, diagnostics, true, options)
}

fn check_profile_inner(
    workspace: &ResolvedWorkspace,
    sources: &AuthoringSourceSetV1,
    name: &str,
    diagnostics: &mut Diagnostics,
    report_default_errors: bool,
    options: CheckOptions<'_>,
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

        // Defaults establish the values that profile layers can replace or patch.
        for input in module.inputs() {
            match &input.default {
                Some(default) => {
                    match coerce_with_limit(
                        default.clone(),
                        &input.ty,
                        input.default_span.unwrap_or(input.span),
                        &format!("input `{}` default", input.name),
                        options.limits.max_collection_size,
                    ) {
                        Ok(value) => {
                            values.insert(
                                input.name.clone(),
                                (value, crate::lang::value::ValueOrigin::Default),
                            );
                        }
                        Err(diagnostic) => {
                            if report_default_errors {
                                diagnostics.push(diagnostic);
                            }
                        }
                    }
                }
                None if input.ty.is_optional() && input.computed_default.is_none() => {
                    values.insert(
                        input.name.clone(),
                        (Value::Null, crate::lang::value::ValueOrigin::Default),
                    );
                }
                None => {}
            }
        }

        // Apply each profile layer's whole-input writes and patches in the
        // linearized order retained by profile resolution. Patch kinds remain
        // interleaved in their authored order within a layer.
        let ident = InstanceIdent {
            alias: &instance.alias,
            module_name: &instance.module,
            max_collection_size: options.limits.max_collection_size,
        };
        let mut patch_env = TypeEnv::new(workspace, sources, module);
        for operation in &instance.input_ops {
            match operation {
                ResolvedInputOp::With {
                    name,
                    value,
                    span,
                    profile,
                } => apply_with(
                    &mut values,
                    module,
                    &ident,
                    ProfileWith {
                        name,
                        value,
                        span: *span,
                        profile,
                    },
                    diagnostics,
                ),
                ResolvedInputOp::Patch { entry, profile } => match entry {
                    PatchEntry::Field(set) => {
                        apply_field_patch(&mut values, module, &ident, set, profile, diagnostics);
                    }
                    PatchEntry::Collection(patch) => {
                        apply_collection_patch(
                            &mut patch_env,
                            &mut values,
                            module,
                            &ident,
                            patch,
                            profile,
                            diagnostics,
                        );
                    }
                },
            };
        }

        // Evaluate computed defaults after profile overrides and patches.
        // Same-module dependencies are evaluated in topological order, and
        // cycles are reported before any template is rendered.
        apply_computed_defaults(
            workspace,
            module,
            &mut values,
            &ident,
            name,
            options,
            diagnostics,
        );

        // Patches and schema completion can introduce nested aggregates, so
        // validate every final value recursively.
        for input in module.inputs() {
            let Some((value, _)) = values.get(&input.name) else {
                continue;
            };
            if let Err(diagnostic) = validate_value_collection_sizes(
                value,
                options.limits.max_collection_size,
                input.span,
                &format!("input `{}.{}`", instance.alias, input.name),
            ) {
                diagnostics.push(diagnostic);
            }
        }

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

        let mut fragment_sources: HashMap<String, Vec<FragmentSource>> = HashMap::new();
        for fragment in &module.decl.fragments {
            fragment_sources.insert(fragment.name.clone(), fragment.defaults.clone());
        }
        for (op, _profile_name) in &instance.fragment_ops {
            let (body, is_append) = match op {
                FragmentOp::Replace(body) => (body, false),
                FragmentOp::Append(body) => (body, true),
            };
            let Some(fragment) = module.fragment(&body.fragment) else {
                diagnostics.error_at(
                    codes::FRAGMENT,
                    format!(
                        "module `{}` (as `{}`) declares no fragment `{}`",
                        instance.module, instance.alias, body.fragment
                    ),
                    body.span,
                );
                continue;
            };
            if is_append && fragment.cardinality == FragmentCardinality::One {
                diagnostics.error_at(
                    codes::FRAGMENT,
                    format!(
                        "fragment `{}` has cardinality \"one\"; use `replace`",
                        body.fragment
                    ),
                    body.span,
                );
                continue;
            }
            let before_fragment_validation = diagnostics.error_count();
            validate_fragment_source(
                &body.source,
                sources,
                &workspace.source_root,
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

        typed.instances.push(TypedInstance {
            alias: instance.alias.clone(),
            module: instance.module.clone(),
            values,
            fragment_sources,
            span: instance.span,
        });
    }
    if diagnostics.error_count() > before {
        return Some(typed); // Retain typed values for subsequent diagnostics.
    }
    Some(typed)
}

/// Evaluates computed defaults for any input whose template is set and that
/// has not already received a value from a static default, `with` override,
/// or `patch` operation. Templates may reference same-module inputs,
/// `global.*` design tokens, and the always-available built-ins
/// (`profile.name`, `malm.target`, `instance.name`, `instance.module`,
/// `machine.hostname`). Same-module refs form the dependency graph; cycles
/// are detected with DFS coloring before any template renders.
fn apply_computed_defaults(
    workspace: &ResolvedWorkspace,
    module: &ResolvedModule,
    values: &mut HashMap<String, (Value, crate::lang::value::ValueOrigin)>,
    ident: &InstanceIdent<'_>,
    profile_name: &str,
    options: CheckOptions<'_>,
    diagnostics: &mut Diagnostics,
) {
    let InstanceIdent {
        alias: instance_alias,
        module_name: instance_module,
        ..
    } = *ident;
    let pending: Vec<&InputDecl> = module
        .inputs()
        .iter()
        .filter(|input| input.computed_default.is_some())
        .filter(|input| !values.contains_key(&input.name))
        .collect();
    if pending.is_empty() {
        return;
    }

    // Build dependency edges only for same-module inputs.
    // References to `global.*`, `profile.*`, `malm.*`, `instance.*`, and
    // `machine.*` are always resolvable and contribute no dependency edge.
    let mut graph: HashMap<&str, Vec<&str>> = HashMap::new();
    for input in &pending {
        graph.entry(input.name.as_str()).or_default();
        let template = input.computed_default.as_ref().expect("filtered above");
        let deps = template_dependencies(template);
        for dep in deps {
            if !is_builtin_or_global_namespace(dep) {
                graph.entry(input.name.as_str()).or_default().push(dep);
            }
        }
    }

    // DFS coloring detects cycles and produces a stable topological order.
    let order = match topological_order(&pending, &graph) {
        Ok(order) => order,
        Err(cycle) => {
            let span = pending
                .iter()
                .find(|input| input.name == cycle[0])
                .and_then(|input| input.computed_default_span)
                .unwrap_or(pending[0].span);
            diagnostics.push(
                Diagnostic::error(
                    codes::TYPE_CYCLE,
                    format!(
                        "computed default cycle: {}",
                        cycle
                            .iter()
                            .map(|name| (*name).to_owned())
                            .collect::<Vec<_>>()
                            .join(" -> ")
                    ),
                )
                .with_span(span)
                .with_help("make at least one of the inputs derive from a static default, a `with` override, or a built-in instead of another same-module input"),
            );
            return;
        }
    };

    // Build the `global.foo` value namespace once for every instance.
    let globals: HashMap<String, Value> = workspace
        .globals
        .iter()
        .map(|(name, var)| (name.clone(), var.value.clone()))
        .collect();

    for input_name in order {
        let Some(input) = module.input(input_name) else {
            continue;
        };
        let Some(template) = input.computed_default.as_ref() else {
            continue;
        };
        let span = input.computed_default_span.unwrap_or(input.span);

        // Computed templates observe current values, globals, and built-ins.
        let mut builtins: HashMap<String, Value> = HashMap::new();
        builtins.insert(
            "malm.target".to_owned(),
            Value::String(options.target_root.to_owned()),
        );
        builtins.insert(
            "profile.name".to_owned(),
            Value::String(profile_name.to_owned()),
        );
        builtins.insert(
            "instance.name".to_owned(),
            Value::String(instance_alias.to_owned()),
        );
        builtins.insert(
            "instance.module".to_owned(),
            Value::String(instance_module.to_owned()),
        );
        builtins.insert(
            "machine.hostname".to_owned(),
            options
                .hostname
                .map_or(Value::Null, |hostname| Value::String(hostname.to_owned())),
        );
        let inputs: HashMap<String, Value> = values
            .iter()
            .map(|(name, (value, _origin))| (name.clone(), value.clone()))
            .collect();
        let scope = Scope::new(inputs, globals.clone(), builtins);

        let lookup = |name: &str| scope.lookup(name).cloned();
        let rendered = match text::render_template_with_limit(
            template,
            TemplateSyntax::V3,
            &lookup,
            options.limits.max_artifact_bytes,
        ) {
            Ok(rendered) => rendered,
            Err(message) => {
                diagnostics.error_at(
                    codes::TEMPLATE,
                    format!(
                        "computed default for input `{instance_alias}.{}`: {message}",
                        input.name
                    ),
                    span,
                );
                continue;
            }
        };

        let raw_value = match template_result_to_value(&rendered, &input.ty) {
            Ok(value) => value,
            Err(message) => {
                diagnostics.error_at(
                    codes::TYPE_MISMATCH,
                    format!(
                        "computed default for input `{instance_alias}.{}`: {message}",
                        input.name
                    ),
                    span,
                );
                continue;
            }
        };

        match coerce_with_limit(
            raw_value,
            &input.ty,
            span,
            &format!(
                "computed default for input `{instance_alias}.{}",
                input.name
            ),
            options.limits.max_collection_size,
        ) {
            Ok(value) => {
                values.insert(
                    input.name.clone(),
                    (value, crate::lang::value::ValueOrigin::Default),
                );
            }
            Err(diag) => diagnostics.push(diag),
        }
    }
}

/// Extracts same-module input references from a `(f)` template. Returns names
/// in source order with duplicates preserved; callers deduplicate or filter
/// as needed. The template has already been parse-validated upstream.
fn template_dependencies(template: &str) -> Vec<&str> {
    let mut deps = Vec::new();
    let segments = match text::parse_template_with(template, TemplateSyntax::V3) {
        Ok(segments) => segments,
        Err(_) => return deps,
    };
    for segment in segments {
        if let text::Segment::Directive {
            parsed: text::Directive::Substitute { name, .. },
            ..
        } = segment
        {
            deps.push(name);
        }
    }
    deps
}

/// Returns whether a name is in a reserved namespace that is always resolvable
/// regardless of same-module input state (`global.*`, `profile.*`,
/// `malm.*`, `instance.*`, `machine.*`).
fn is_builtin_or_global_namespace(name: &str) -> bool {
    name.starts_with("global.")
        || name.starts_with("profile.")
        || name.starts_with("malm.")
        || name.starts_with("instance.")
        || name.starts_with("machine.")
        || name == "machine.hostname"
}

/// Iterative DFS coloring over the same-module dependency graph. Returns
/// dependencies before dependents without putting authored graph size on the
/// process stack.
fn topological_order<'a>(
    pending: &[&'a InputDecl],
    graph: &HashMap<&'a str, Vec<&'a str>>,
) -> Result<Vec<&'a str>, Vec<&'a str>> {
    #[derive(Clone, Copy, PartialEq)]
    enum State {
        Visiting,
        Done,
    }

    let names: Vec<&'a str> = pending.iter().map(|input| input.name.as_str()).collect();
    let mut states: HashMap<&'a str, State> = HashMap::new();
    let mut order: Vec<&'a str> = Vec::new();
    struct Frame<'a> {
        name: &'a str,
        next_dependency: usize,
    }

    for name in names {
        if states.contains_key(name) {
            continue;
        }
        states.insert(name, State::Visiting);
        let mut stack = vec![Frame {
            name,
            next_dependency: 0,
        }];
        while let Some(frame) = stack.last_mut() {
            let dependencies = graph.get(frame.name).map(Vec::as_slice).unwrap_or_default();
            let Some(dependency) = dependencies.get(frame.next_dependency).copied() else {
                let completed = stack.pop().expect("active frame").name;
                states.insert(completed, State::Done);
                order.push(completed);
                continue;
            };
            frame.next_dependency += 1;
            if !graph.contains_key(dependency) {
                continue;
            }
            match states.get(dependency) {
                Some(State::Done) => {}
                Some(State::Visiting) => {
                    let cycle_start = stack
                        .iter()
                        .position(|frame| frame.name == dependency)
                        .unwrap_or(0);
                    let mut cycle = stack[cycle_start..]
                        .iter()
                        .map(|frame| frame.name)
                        .collect::<Vec<_>>();
                    cycle.push(dependency);
                    return Err(cycle);
                }
                None => {
                    states.insert(dependency, State::Visiting);
                    stack.push(Frame {
                        name: dependency,
                        next_dependency: 0,
                    });
                }
            }
        }
    }
    Ok(order)
}

/// Coerces a rendered template string into the typed `Value` shape expected by
/// `coerce`. Strings, paths, and enums keep their string form so the regular
/// coercion path can run enum/format/refine validation; numeric and boolean
/// targets parse from the rendered text. Refinements delegate to their base
/// type so the standard coercion path can still enforce range/format rules.
fn template_result_to_value(rendered: &str, ty: &Type) -> Result<Value, String> {
    match ty.unwrap_optional().lowered_type() {
        LoweredType::String => Ok(Value::String(rendered.to_owned())),
        LoweredType::Path => Ok(Value::Path(rendered.to_owned())),
        LoweredType::Enum(_) => Ok(Value::String(rendered.to_owned())),
        LoweredType::Int => rendered
            .parse::<i64>()
            .map(Value::Int)
            .map_err(|_| format!("template produced `{rendered}`, which is not a valid int")),
        LoweredType::Float => match rendered.parse::<f64>() {
            Ok(x) if x.is_finite() => Ok(Value::Float(x)),
            _ => {
                if let Ok(i) = rendered.parse::<i64>()
                    && let Some(x) = exact_i64_to_f64(i)
                {
                    return Ok(Value::Float(x));
                }
                Err(format!(
                    "template produced `{rendered}`, which is not a valid float"
                ))
            }
        },
        LoweredType::Bool => match rendered {
            "true" => Ok(Value::Bool(true)),
            "false" => Ok(Value::Bool(false)),
            _ => Err(format!(
                "template produced `{rendered}`, which is not a valid bool (expected `true` or `false`)"
            )),
        },
        _ => Err(format!(
            "computed defaults require a scalar input type (bool, int, float, string, path, enum, or a refine over scalars); got {ty}"
        )),
    }
}

fn known_inputs_help(module: &ResolvedModule) -> String {
    let names: Vec<&str> = module.inputs().iter().map(|i| i.name.as_str()).collect();
    if names.is_empty() {
        "this module declares no inputs".to_owned()
    } else {
        format!("known inputs: {}", names.join(", "))
    }
}

/// Identifiers that attribute a patch to its activated module instance.
struct InstanceIdent<'a> {
    alias: &'a str,
    module_name: &'a str,
    max_collection_size: usize,
}

struct ProfileWith<'a> {
    name: &'a str,
    value: &'a Value,
    span: Span,
    profile: &'a str,
}

fn apply_with(
    values: &mut HashMap<String, (Value, crate::lang::value::ValueOrigin)>,
    module: &ResolvedModule,
    ident: &InstanceIdent<'_>,
    write: ProfileWith<'_>,
    diagnostics: &mut Diagnostics,
) {
    let Some(input) = module.input(write.name) else {
        diagnostics.error_at_with_help(
            codes::UNKNOWN_INPUT,
            format!(
                "module `{}` (as `{}`) has no input `{}`",
                ident.module_name, ident.alias, write.name
            ),
            write.span,
            known_inputs_help(module),
        );
        return;
    };
    if write.value.is_null() && !input.ty.is_optional() {
        diagnostics.error_at_with_help(
            codes::NULL_NOT_OPTIONAL,
            format!(
                "input `{}.{}` is {}, which cannot be cleared with #null",
                ident.alias, write.name, input.ty
            ),
            write.span,
            "only optional inputs can be set to #null",
        );
        return;
    }
    match coerce_with_limit(
        write.value.clone(),
        &input.ty,
        write.span,
        &format!("input `{}.{}`", ident.alias, write.name),
        ident.max_collection_size,
    ) {
        Ok(value) => {
            values.insert(
                write.name.to_owned(),
                (
                    value,
                    crate::lang::value::ValueOrigin::Profile(write.profile.to_owned()),
                ),
            );
        }
        Err(diagnostic) => diagnostics.push(diagnostic),
    }
}

/// Applies a `set`/`unset` field patch to an instance's input values. The
/// `set.path` is `input_name.field1.field2...fieldN`; intermediate fields
/// navigate through nested record (or variant-lowered-to-record) values and
/// must already be present (non-null) in the current value. The final field
/// is coerced against its declared type for `set` and validated as a clearable
/// optional/required-without-default field for `unset`.
fn apply_field_patch(
    values: &mut HashMap<String, (Value, crate::lang::value::ValueOrigin)>,
    module: &ResolvedModule,
    ident: &InstanceIdent<'_>,
    set: &SetPatch,
    profile_name: &str,
    diagnostics: &mut Diagnostics,
) {
    let InstanceIdent {
        alias: instance_alias,
        module_name: instance_module,
        ..
    } = *ident;
    let Some(input) = module
        .inputs()
        .iter()
        .filter(|input| {
            set.path.starts_with(&input.name)
                && set.path.as_bytes().get(input.name.len()) == Some(&b'.')
        })
        .max_by_key(|input| input.name.len())
    else {
        let input_name = set
            .path
            .split_once('.')
            .map_or(set.path.as_str(), |part| part.0);
        diagnostics.error_at_with_help(
            codes::UNKNOWN_INPUT,
            format!(
                "module `{instance_module}` (as `{instance_alias}`) has no input `{input_name}` to patch"
            ),
            set.span,
            known_inputs_help(module),
        );
        return;
    };
    let input_name = input.name.as_str();
    let rest = &set.path[input_name.len() + 1..];
    let Some((current, _)) = values.get(input_name) else {
        diagnostics.error_at(
            codes::PATCH,
            format!(
                "`set \"{}\"` needs a base record — declare a default for `{input_name}` or set the whole input first",
                set.path
            ),
            set.span,
        );
        return;
    };
    let mut candidate = current.clone();
    let applied = navigate_field_patch(
        &mut candidate,
        input.ty.unwrap_optional(),
        input_name,
        rest,
        set,
        ident,
        diagnostics,
    );
    if !applied {
        return;
    }
    match coerce_with_limit(
        candidate,
        &input.ty,
        set.span,
        &format!("patch `{}.{}`", ident.alias, set.path),
        ident.max_collection_size,
    ) {
        Ok(value) => {
            values.insert(
                input.name.clone(),
                (
                    value,
                    crate::lang::value::ValueOrigin::Profile(profile_name.to_owned()),
                ),
            );
        }
        Err(diagnostic) => diagnostics.push(diagnostic),
    }
}

enum ActivePatchSchema<'a> {
    Record(&'a RecordSchema),
    Variant {
        schema: &'a crate::lang::value::VariantSchema,
        case: &'a crate::lang::value::VariantCase,
    },
}

impl ActivePatchSchema<'_> {
    fn label(&self) -> &'static str {
        match self {
            Self::Record(_) => "record",
            Self::Variant { .. } => "variant",
        }
    }

    fn field(&self, name: &str) -> Option<FieldSchema> {
        match self {
            Self::Record(schema) => schema.field(name).cloned(),
            Self::Variant { case, .. } => {
                case.fields.iter().find(|field| field.name == name).cloned()
            }
        }
    }

    fn discriminator(&self) -> Option<&str> {
        match self {
            Self::Record(_) => None,
            Self::Variant { schema, .. } => Some(&schema.discriminator),
        }
    }

    fn inactive_field(&self, name: &str) -> bool {
        match self {
            Self::Record(_) => false,
            Self::Variant { schema, case } => schema.cases.iter().any(|candidate| {
                candidate.name != case.name
                    && candidate.fields.iter().any(|field| field.name == name)
            }),
        }
    }

    fn active_case(&self) -> Option<&str> {
        match self {
            Self::Record(_) => None,
            Self::Variant { case, .. } => Some(&case.name),
        }
    }
}

fn active_patch_schema<'a>(
    ty: &'a Type,
    record: &Record,
    path_so_far: &str,
    set: &SetPatch,
    diagnostics: &mut Diagnostics,
) -> Option<ActivePatchSchema<'a>> {
    match ty.operational_type() {
        Type::Record(schema) => Some(ActivePatchSchema::Record(schema)),
        Type::Variant(schema) => {
            let active_name = match record.get(&schema.discriminator) {
                Some(Value::String(name)) => name,
                _ => {
                    diagnostics.error_at(
                        codes::PATCH,
                        format!(
                            "variant `{path_so_far}` has no valid `{}` discriminator",
                            schema.discriminator
                        ),
                        set.span,
                    );
                    return None;
                }
            };
            let Some(case) = schema.case(active_name) else {
                diagnostics.error_at(
                    codes::PATCH,
                    format!("variant `{path_so_far}` has unknown active case `{active_name}`"),
                    set.span,
                );
                return None;
            };
            Some(ActivePatchSchema::Variant { schema, case })
        }
        _ => None,
    }
}

/// Recursively walks a dotted record path and applies the set/unset at the leaf.
/// Returns `true` if a value was written, `false` if a diagnostic was pushed
/// (or the path was rejected). `current_type` is the schema type at
/// `current_value`; `path_so_far` accumulates the traversed dotted prefix for
/// diagnostic messages.
fn navigate_field_patch(
    current_value: &mut Value,
    current_type: &Type,
    path_so_far: &str,
    path: &str,
    set: &SetPatch,
    ident: &InstanceIdent<'_>,
    diagnostics: &mut Diagnostics,
) -> bool {
    let record = match current_value {
        Value::Record(record) => record,
        Value::Null => {
            diagnostics.error_at(
                codes::PATCH,
                format!(
                    "`set \"{}\"` needs a base record — `{path_so_far}` is null; declare a default for the field or set the whole input first",
                    set.path
                ),
                set.span,
            );
            return false;
        }
        _ => return false, // type mismatch already reported
    };

    let Some(schema) = active_patch_schema(current_type, record, path_so_far, set, diagnostics)
    else {
        return false;
    };
    let shape_label = schema.label();

    let exact = schema.field(path);
    let (field_name, tail, field) = if let Some(field) = exact {
        (path, None, field)
    } else {
        let (field_name, tail) = path
            .split_once('.')
            .map_or((path, None), |(head, tail)| (head, Some(tail)));
        if schema.discriminator() == Some(field_name) {
            diagnostics.error_at(
                codes::PATCH,
                format!(
                    "variant discriminator `{path_so_far}.{field_name}` cannot be set or unset through a field patch"
                ),
                set.span,
            );
            return false;
        }
        let Some(field) = schema.field(field_name) else {
            if schema.inactive_field(path) || schema.inactive_field(field_name) {
                diagnostics.error_at(
                    codes::PATCH,
                    format!(
                        "variant field `{path_so_far}.{path}` is not in active case `{}`",
                        schema
                            .active_case()
                            .expect("inactive fields belong to variants")
                    ),
                    set.span,
                );
            } else {
                diagnostics.error_at(
                    codes::RECORD_FIELD,
                    format!(
                        "{shape_label} `{path_so_far}` has no field `{field_name}` ({shape_label}s are closed)"
                    ),
                    set.span,
                );
            }
            return false;
        };
        (field_name, tail, field)
    };

    if tail.is_none() {
        match &set.value {
            None => {
                if field.required {
                    diagnostics.error_at(
                        codes::PATCH,
                        format!(
                            "field `{path_so_far}.{field_name}` is required; `unset` clears only optional fields"
                        ),
                        set.span,
                    );
                    return false;
                }
                if field.default.is_some() && !field.ty.is_optional() {
                    diagnostics.error_at(
                        codes::PATCH,
                        format!(
                            "field `{path_so_far}.{field_name}` has a default; `unset` cannot make its non-optional value null"
                        ),
                        set.span,
                    );
                    return false;
                }
                record.insert(field_name.to_owned(), Value::Null);
            }
            Some(raw) => {
                match coerce_with_limit(
                    raw.clone(),
                    &field.ty,
                    set.span,
                    &format!("patch `{}.{}`", ident.alias, set.path),
                    ident.max_collection_size,
                ) {
                    Ok(value) => {
                        if let Err(diagnostic) = validate_value_collection_sizes(
                            &value,
                            ident.max_collection_size,
                            set.span,
                            &format!("patch `{}.{}`", ident.alias, set.path),
                        ) {
                            diagnostics.push(diagnostic);
                            return false;
                        }
                        record.insert(field_name.to_owned(), value);
                    }
                    Err(diag) => {
                        diagnostics.push(diag);
                        return false;
                    }
                }
            }
        }
        return true;
    }

    // Intermediate field: the declared type must lower to a record or
    // variant so we can descend further. The current value at this field
    // must already be a non-null record; if it is missing or null, surface
    // a helpful error rather than silently dropping the patch.
    if !matches!(
        field.ty.unwrap_optional().lowered_type(),
        LoweredType::Record
    ) {
        diagnostics.error_at(
                codes::PATCH,
                format!(
                    "{shape_label} field `{path_so_far}.{field_name}` is not a record; cannot navigate into `{field_name}`"
                ),
                set.span,
            );
        return false;
    }
    let next_value = match record.get_mut(field_name) {
        Some(value) => value,
        None => {
            diagnostics.error_at(
                codes::PATCH,
                format!(
                    "`set \"{}\"` needs a base record — intermediate field `{field_name}` on path `{path_so_far}` is missing; declare a default for the field or set the whole input first",
                    set.path
                ),
                set.span,
            );
            return false;
        }
    };
    if matches!(next_value, Value::Null) {
        diagnostics.error_at(
            codes::PATCH,
            format!(
                "`set \"{}\"` needs a base record — intermediate field `{field_name}` on path `{path_so_far}` is null; declare a default for the field or set the whole input first",
                set.path
            ),
            set.span,
        );
        return false;
    }
    let next_type = field.ty.unwrap_optional().clone();
    let mut next_path = String::with_capacity(path_so_far.len() + 1 + field_name.len());
    next_path.push_str(path_so_far);
    next_path.push('.');
    next_path.push_str(field_name);
    navigate_field_patch(
        next_value,
        &next_type,
        &next_path,
        tail.expect("intermediate field has a remaining path"),
        set,
        ident,
        diagnostics,
    )
}

/// Applies a `collection` patch (`replace`/`append`/`remove`/`replace-all`) to
/// an instance's input values. `patch_env` is shared with KDL-document
/// type checks for collection items whose declared type is `kdl-document`.
fn apply_collection_patch(
    patch_env: &mut TypeEnv<'_>,
    values: &mut HashMap<String, (Value, crate::lang::value::ValueOrigin)>,
    module: &ResolvedModule,
    ident: &InstanceIdent<'_>,
    patch: &crate::lang::ast::CollectionPatch,
    profile_name: &str,
    diagnostics: &mut Diagnostics,
) {
    let InstanceIdent {
        alias: instance_alias,
        module_name: instance_module,
        max_collection_size,
    } = *ident;
    let Some(input) = module.input(&patch.collection) else {
        diagnostics.error_at(
            codes::PATCH,
            format!(
                "module `{instance_module}` (as `{instance_alias}`) has no input `{}` to patch",
                patch.collection
            ),
            patch.span,
        );
        return;
    };
    if !matches!(
        input.ty.unwrap_optional(),
        Type::Collection(_) | Type::Map(_)
    ) {
        diagnostics.error_at(
            codes::PATCH,
            format!(
                "input `{instance_alias}.{}` is {}, not a collection — only collections can be patched",
                patch.collection, input.ty
            ),
            patch.span,
        );
        return;
    }
    let item_ty = match input.ty.unwrap_optional() {
        Type::Collection(item) | Type::Map(item) => (**item).clone(),
        _ => unreachable!("checked above"),
    };
    let is_map = matches!(input.ty.unwrap_optional(), Type::Map(_));
    let collection = match values.get_mut(&patch.collection) {
        Some((Value::Collection(collection), _)) => collection,
        Some((Value::Null, _)) | None => {
            diagnostics.error_at(
                codes::PATCH,
                format!(
                    "collection patch `{instance_alias}.{}` needs a base collection; set the whole input before patching it",
                    patch.collection
                ),
                patch.span,
            );
            return;
        }
        Some(_) => return,
    };
    for op in &patch.ops {
        match op {
            PatchOp::Replace { key, value, span } => {
                let what = format!(
                    "patch `{instance_alias}.{}` replace \"{key}\"",
                    patch.collection
                );
                let value = match coerce_with_limit(
                    value.clone(),
                    &item_ty,
                    *span,
                    &what,
                    max_collection_size,
                ) {
                    Ok(value) => value,
                    Err(diag) => {
                        diagnostics.push(diag);
                        continue;
                    }
                };
                if let Err(diagnostic) =
                    validate_value_collection_sizes(&value, max_collection_size, *span, &what)
                {
                    diagnostics.push(diagnostic);
                    continue;
                }
                if let Value::KdlDocument(document) = &value {
                    check_kdl_nodes(patch_env, document.nodes(), diagnostics, 0, span.file);
                }
                match collection.items.iter_mut().find(|item| &item.key == key) {
                    Some(item) => {
                        item.value = value.clone();
                        item.span = *span;
                    }
                    None => diagnostics.error_at_with_help(
                        codes::PATCH,
                        format!(
                            "`replace \"{key}\"` in collection `{instance_alias}.{}`: key does not exist",
                            patch.collection
                        ),
                        *span,
                        "use `append` for new keys",
                    ),
                }
            }
            PatchOp::Append { key, value, span } => {
                let what = format!(
                    "patch `{instance_alias}.{}` append \"{key}\"",
                    patch.collection
                );
                let value = match coerce_with_limit(
                    value.clone(),
                    &item_ty,
                    *span,
                    &what,
                    max_collection_size,
                ) {
                    Ok(value) => value,
                    Err(diag) => {
                        diagnostics.push(diag);
                        continue;
                    }
                };
                if let Err(diagnostic) =
                    validate_value_collection_sizes(&value, max_collection_size, *span, &what)
                {
                    diagnostics.push(diagnostic);
                    continue;
                }
                if let Value::KdlDocument(document) = &value {
                    check_kdl_nodes(patch_env, document.nodes(), diagnostics, 0, span.file);
                }
                if collection.contains(key) {
                    diagnostics.error_at_with_help(
                        codes::PATCH,
                        format!(
                            "`append \"{key}\"` in collection `{instance_alias}.{}`: key already exists",
                            patch.collection
                        ),
                        *span,
                        "use `replace` for existing keys",
                    );
                } else {
                    let projected = collection.items.len().saturating_add(1);
                    if let Err(diagnostic) = check_value_collection_size(
                        projected,
                        max_collection_size,
                        *span,
                        &format!("collection `{instance_alias}.{}`", patch.collection),
                    ) {
                        diagnostics.push(diagnostic);
                        continue;
                    }
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
                    diagnostics.error_at_with_help(
                        codes::PATCH,
                        format!(
                            "`remove \"{key}\"` in collection `{instance_alias}.{}`: key does not exist",
                            patch.collection
                        ),
                        *span,
                        "add `optional=#true` if the key may be absent",
                    );
                }
            }
            PatchOp::ReplaceAll { items, span } => {
                if let Err(diagnostic) = check_value_collection_size(
                    items.len(),
                    max_collection_size,
                    *span,
                    &format!("collection `{instance_alias}.{}`", patch.collection),
                ) {
                    diagnostics.push(diagnostic);
                    continue;
                }
                let errors_before = diagnostics.error_count();
                let mut replacement = Vec::with_capacity(items.len());
                for (key, value, item_span) in items {
                    let what = format!(
                        "patch `{instance_alias}.{}` replace-all \"{key}\"",
                        patch.collection
                    );
                    let value = match coerce_with_limit(
                        value.clone(),
                        &item_ty,
                        *item_span,
                        &what,
                        max_collection_size,
                    ) {
                        Ok(value) => value,
                        Err(diag) => {
                            diagnostics.push(diag);
                            continue;
                        }
                    };
                    if let Err(diagnostic) = validate_value_collection_sizes(
                        &value,
                        max_collection_size,
                        *item_span,
                        &what,
                    ) {
                        diagnostics.push(diagnostic);
                        continue;
                    }
                    if let Value::KdlDocument(document) = &value {
                        check_kdl_nodes(
                            patch_env,
                            document.nodes(),
                            diagnostics,
                            0,
                            item_span.file,
                        );
                    }
                    replacement.push(crate::lang::value::CollectionItem {
                        key: key.clone(),
                        value,
                        span: *item_span,
                    });
                }
                if diagnostics.error_count() == errors_before {
                    collection.items = replacement;
                }
            }
        }
    }
    // Re-sort map keys after each patch to preserve canonical map values.
    if is_map {
        collection.items.sort_by(|a, b| a.key.cmp(&b.key));
    }
    // Attribute the resulting collection value to the patching profile.
    if let Some((_, origin)) = values.get_mut(&patch.collection) {
        *origin = crate::lang::value::ValueOrigin::Profile(profile_name.to_owned());
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
    pub fragment_sources: HashMap<String, Vec<FragmentSource>>,
    #[allow(dead_code)]
    pub span: Span,
}

/// Coerces a parsed value to its declared type, including records and paths.
pub(crate) fn coerce(value: Value, ty: &Type, span: Span, what: &str) -> Result<Value, Diagnostic> {
    coerce_with_limit(value, ty, span, what, Limits::default().max_collection_size)
}

fn coerce_with_limit(
    value: Value,
    ty: &Type,
    span: Span,
    what: &str,
    max_collection_size: usize,
) -> Result<Value, Diagnostic> {
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
        (Type::Enum(values), Value::String(value)) if values.binary_search(&value).is_ok() => {
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
        (Type::List(item), Value::UnresolvedListDefault(literal)) => match item.unwrap_optional() {
            Type::Record(_) => Value::List(vec![coerce_with_limit(
                Value::RawRecordLiteral(literal),
                item,
                span,
                &format!("{what}[0]"),
                max_collection_size,
            )?]),
            Type::Enum(_)
                if literal.properties.is_empty() && literal.children.nodes().is_empty() =>
            {
                Value::List(Vec::new())
            }
            Type::Enum(_) => {
                return Err(Diagnostic::error(
                    codes::TYPE_MISMATCH,
                    format!("{what}: an enum list default uses positional values, not child nodes"),
                )
                .with_span(span));
            }
            resolved => {
                return Err(Diagnostic::error(
                    codes::TYPE_MISMATCH,
                    format!("{what}: unresolved named list default resolved to {resolved}"),
                )
                .with_span(span));
            }
        },
        (Type::List(item), Value::List(values)) => {
            check_value_collection_size(values.len(), max_collection_size, span, what)?;
            let mut out = Vec::with_capacity(values.len());
            for (index, v) in values.into_iter().enumerate() {
                out.push(coerce_with_limit(
                    v,
                    item,
                    span,
                    &format!("{what}[{index}]"),
                    max_collection_size,
                )?);
            }
            Value::List(out)
        }
        (Type::List(item), Value::KdlDocument(doc)) => {
            check_value_collection_size(doc.nodes().len(), max_collection_size, span, what)?;
            let mut out = Vec::new();
            for (index, node) in doc.nodes().iter().enumerate() {
                if node.name().value() != "item" {
                    return Err(Diagnostic::error(
                        codes::TYPE_MISMATCH,
                        format!("{what}: list override expects `item {{ ... }}` children"),
                    )
                    .with_span(span));
                }
                out.push(coerce_with_limit(
                    raw_node_value(item, node, span.file, what)?,
                    item,
                    node_span(span.file, node),
                    &format!("{what}[{index}]"),
                    max_collection_size,
                )?);
            }
            Value::List(out)
        }
        // KDL cannot distinguish `x "a"` from a one-item list, so a scalar
        // becomes a one-element list when the declared type is a list.
        (Type::List(item), scalar)
            if !matches!(
                scalar,
                Value::Record(_)
                    | Value::Collection(_)
                    | Value::KdlDocument(_)
                    | Value::RawRecordLiteral(_)
            ) =>
        {
            Value::List(vec![coerce_with_limit(
                scalar,
                item,
                span,
                what,
                max_collection_size,
            )?])
        }
        (Type::Variant(schema), Value::KdlDocument(doc)) => Value::Record(variant_from_document(
            schema,
            &doc,
            span,
            what,
            max_collection_size,
        )?),
        (Type::Variant(schema), Value::RawRecordLiteral(literal)) => Value::Record(
            variant_from_literal(schema, literal, span, what, max_collection_size)?,
        ),
        (Type::Variant(schema), Value::Record(record)) => Value::Record(revalidate_variant_record(
            schema,
            record,
            span,
            what,
            max_collection_size,
        )?),
        (Type::Record(schema), Value::KdlDocument(doc)) => Value::Record(record_from_document(
            schema,
            &doc,
            span,
            what,
            max_collection_size,
        )?),
        (Type::Record(schema), Value::RawRecordLiteral(literal)) => Value::Record(
            record_from_literal(schema, literal, span, what, max_collection_size)?,
        ),
        (Type::Record(schema), Value::Record(record)) => Value::Record(complete_record(
            schema,
            record,
            span,
            what,
            max_collection_size,
        )?),
        (Type::Collection(item), Value::Collection(collection)) => {
            check_value_collection_size(collection.len(), max_collection_size, span, what)?;
            let mut validated = crate::lang::value::KeyedCollection::default();
            for entry in collection.items {
                let value = coerce_with_limit(
                    entry.value,
                    item,
                    entry.span,
                    &format!("{what}[\"{}\"]", entry.key),
                    max_collection_size,
                )?;
                validated.items.push(crate::lang::value::CollectionItem {
                    key: entry.key,
                    value,
                    span: entry.span,
                });
            }
            Value::Collection(validated)
        }
        (Type::Collection(item), Value::KdlDocument(document)) => {
            let collection = collection_from_document(&document, span, what, max_collection_size)?;
            coerce_with_limit(
                Value::Collection(collection),
                &Type::Collection(item.clone()),
                span,
                what,
                max_collection_size,
            )?
        }
        (Type::Map(item), Value::Collection(collection)) => {
            // Coerce map items as a collection, then sort keys so map equality
            // does not depend on declaration or patch order.
            let coerced = coerce_with_limit(
                Value::Collection(collection),
                &Type::Collection(item.clone()),
                span,
                what,
                max_collection_size,
            )?;
            let Value::Collection(mut validated) = coerced else {
                unreachable!("coerce(Collections) returns Collection");
            };
            validated.items.sort_by(|a, b| a.key.cmp(&b.key));
            Value::Collection(validated)
        }
        (Type::Map(item), Value::KdlDocument(document)) => {
            let collection = collection_from_document(&document, span, what, max_collection_size)?;
            coerce_with_limit(
                Value::Collection(collection),
                &Type::Map(item.clone()),
                span,
                what,
                max_collection_size,
            )?
        }
        (Type::Tuple(types), Value::List(values)) => {
            if values.len() != types.len() {
                return Err(Diagnostic::error(
                    codes::TYPE_MISMATCH,
                    format!(
                        "{what}: tuple expected exactly {} values, got {}",
                        types.len(),
                        values.len()
                    ),
                )
                .with_span(span));
            }
            let mut out = Vec::with_capacity(types.len());
            for (index, (ty, value)) in types.iter().zip(values).enumerate() {
                out.push(coerce_with_limit(
                    value,
                    ty,
                    span,
                    &format!("{what}[{index}]"),
                    max_collection_size,
                )?);
            }
            Value::List(out)
        }
        (Type::Tuple(types), Value::KdlDocument(document)) => {
            let nodes = document.nodes();
            if nodes.len() != types.len() {
                return Err(Diagnostic::error(
                    codes::TYPE_MISMATCH,
                    format!(
                        "{what}: tuple expected exactly {} items, got {}",
                        types.len(),
                        nodes.len()
                    ),
                )
                .with_span(span));
            }
            let mut out = Vec::with_capacity(types.len());
            for (index, (ty, node)) in types.iter().zip(nodes.iter()).enumerate() {
                if node.name().value() != "item" {
                    return Err(Diagnostic::error(
                        codes::TYPE_MISMATCH,
                        format!("{what}: tuple override expects `item {{ ... }}` children"),
                    )
                    .with_span(node_span(span.file, node)));
                }
                out.push(coerce_with_limit(
                    raw_node_value(ty, node, span.file, what)?,
                    ty,
                    node_span(span.file, node),
                    &format!("{what}[{index}]"),
                    max_collection_size,
                )?);
            }
            Value::List(out)
        }
        (Type::Set(item), Value::List(values)) => {
            check_value_collection_size(values.len(), max_collection_size, span, what)?;
            let mut out = Vec::with_capacity(values.len());
            for (index, value) in values.into_iter().enumerate() {
                out.push(coerce_with_limit(
                    value,
                    item,
                    span,
                    &format!("{what}[{index}]"),
                    max_collection_size,
                )?);
            }
            dedup_and_sort_values(out)
        }
        (Type::Set(item), Value::KdlDocument(document)) => {
            check_value_collection_size(document.nodes().len(), max_collection_size, span, what)?;
            let mut out = Vec::new();
            for (index, node) in document.nodes().iter().enumerate() {
                if node.name().value() != "item" {
                    return Err(Diagnostic::error(
                        codes::TYPE_MISMATCH,
                        format!("{what}: set override expects `item {{ ... }}` children"),
                    )
                    .with_span(node_span(span.file, node)));
                }
                out.push(coerce_with_limit(
                    raw_node_value(item, node, span.file, what)?,
                    item,
                    node_span(span.file, node),
                    &format!("{what}[{index}]"),
                    max_collection_size,
                )?);
            }
            dedup_and_sort_values(out)
        }
        (Type::Set(item), scalar)
            if !matches!(
                scalar,
                Value::Record(_)
                    | Value::Collection(_)
                    | Value::KdlDocument(_)
                    | Value::RawRecordLiteral(_)
            ) =>
        {
            let value = coerce_with_limit(scalar, item, span, what, max_collection_size)?;
            dedup_and_sort_values(vec![value])
        }
        (Type::KdlDocument, Value::KdlDocument(doc)) => {
            if doc.nodes().is_empty() {
                return Err(Diagnostic::error(
                    codes::TYPE_MISMATCH,
                    format!("{what}: kdl-document must contain at least one node"),
                )
                .with_span(span));
            }
            crate::lang::parse::validate_structural_kdl_document(span.file, doc.nodes())?;
            Value::KdlDocument(doc)
        }
        (_, Value::UnresolvedListDefault(_)) => {
            return Err(Diagnostic::error(
                codes::TYPE_MISMATCH,
                format!("{what}: unresolved named list default reached value coercion"),
            )
            .with_span(span));
        }
        (Type::Named(name), _) => {
            return Err(Diagnostic::error(
                codes::UNKNOWN_TYPE,
                format!("{what}: unresolved type `{name}` reached value coercion"),
            )
            .with_span(span));
        }
        (Type::Refine(schema), value) => {
            // Coerce against the base type before validating refinement constraints.
            let coerced = coerce_with_limit(
                value,
                &schema.base,
                span,
                &format!("{what} (via refine `{}`)", schema.name),
                max_collection_size,
            )?;
            if let Err(reason) = schema.validate(&coerced) {
                return Err(
                    Diagnostic::error(codes::TYPE_MISMATCH, format!("{what}: {reason}"))
                        .with_span(span),
                );
            }
            coerced
        }
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
    max_collection_size: usize,
) -> Result<Record, Diagnostic> {
    record_from_literal(
        schema,
        RawRecordLiteral {
            properties: Vec::new(),
            children: doc.clone(),
        },
        span,
        what,
        max_collection_size,
    )
}

fn record_from_literal(
    schema: &RecordSchema,
    literal: RawRecordLiteral,
    span: Span,
    what: &str,
    max_collection_size: usize,
) -> Result<Record, Diagnostic> {
    validate_literal_duplicates(&literal, span.file, what)?;
    let mut record = Record::new();
    for property in literal.properties {
        let field_name = property.name;
        if record.get(&field_name).is_some() {
            return Err(Diagnostic::error(
                codes::DUPLICATE,
                format!("{what}: field `{field_name}` is set twice"),
            )
            .with_span(property.span));
        }
        let Some(field) = schema.field(&field_name) else {
            return Err(Diagnostic::error(
                codes::RECORD_FIELD,
                format!("{what}: unknown field `{field_name}` (records are closed)"),
            )
            .with_span(property.span));
        };
        if !field.ty.unwrap_optional().lowered_type().is_scalar() {
            return Err(Diagnostic::error(
                codes::RECORD_FIELD,
                format!(
                    "{what}.{field_name}: aggregate field of type {} must be authored as a child node",
                    field.ty
                ),
            )
            .with_span(property.span));
        }
        let coerced = coerce_with_limit(
            property.value,
            &field.ty,
            property.span,
            &format!("{what}.{field_name}"),
            max_collection_size,
        )?;
        record.insert(field_name, coerced);
    }
    for node in literal.children.nodes() {
        let field_name = node.name().value();
        if record.get(field_name).is_some() {
            return Err(Diagnostic::error(
                codes::DUPLICATE,
                format!("{what}: field `{field_name}` is set twice"),
            )
            .with_span(node_span(span.file, node)));
        }
        let Some(field) = schema.field(field_name) else {
            return Err(Diagnostic::error(
                codes::RECORD_FIELD,
                format!("{what}: unknown field `{field_name}` (records are closed)"),
            )
            .with_span(node_span(span.file, node)));
        };
        let node_span = node_span(span.file, node);
        let raw = raw_node_value(&field.ty, node, span.file, what)?;
        let coerced = coerce_with_limit(
            raw,
            &field.ty,
            node_span,
            &format!("{what}.{field_name}"),
            max_collection_size,
        )?;
        record.insert(field_name.to_owned(), coerced);
    }
    complete_record(schema, record, span, what, max_collection_size)
}

fn complete_record(
    schema: &RecordSchema,
    mut record: Record,
    span: Span,
    what: &str,
    max_collection_size: usize,
) -> Result<Record, Diagnostic> {
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
        match record.get(&field.name).cloned() {
            Some(Value::Null)
                if field.ty.is_optional() || (!field.required && field.default.is_none()) => {}
            Some(value) => {
                let value = coerce_with_limit(
                    value,
                    &field.ty,
                    span,
                    &format!("{what}.{}", field.name),
                    max_collection_size,
                )?;
                record.insert(field.name.clone(), value);
            }
            None => {
                if let Some(default) = &field.default {
                    let value = coerce_with_limit(
                        default.clone(),
                        &field.ty,
                        field.default_span.unwrap_or(field.span),
                        &format!("{what}.{} default", field.name),
                        max_collection_size,
                    )?;
                    record.insert(field.name.clone(), value);
                } else if !field.required || field.ty.is_optional() {
                    record.insert(field.name.clone(), Value::Null);
                } else {
                    return Err(Diagnostic::error(
                        codes::RECORD_FIELD,
                        format!("{what}: missing required field `{}`", field.name),
                    )
                    .with_span(span));
                }
            }
        }
    }
    Ok(record)
}

/// Coerces a `default { invoke "case-name" { ... } }` style kdl-document into
/// a lowered variant record. The document must contain exactly one `invoke`
/// node naming a declared case; the case's fields are coerced like record
/// fields, and the discriminator is inserted as the active case name.
fn variant_from_document(
    schema: &crate::lang::value::VariantSchema,
    doc: &KdlDocument,
    span: Span,
    what: &str,
    max_collection_size: usize,
) -> Result<Record, Diagnostic> {
    let mut invoke_nodes = Vec::new();
    for node in doc.nodes() {
        if node.name().value() == "invoke" {
            invoke_nodes.push(node);
        } else {
            return Err(Diagnostic::error(
                codes::RECORD_FIELD,
                format!(
                    "{what}: variant inputs use `invoke \"{node_name}\" {{ … }}`; node `{node_name}` is not valid here",
                    node_name = node.name().value(),
                ),
            )
            .with_span(node_span(span.file, node)));
        }
    }
    if invoke_nodes.is_empty() {
        return Err(Diagnostic::error(
            codes::RECORD_FIELD,
            format!(
                "{what}: variant input requires one `invoke \"{disc}\" {{ … }}` node",
                disc = schema.discriminator
            ),
        )
        .with_span(span));
    }
    if invoke_nodes.len() > 1 {
        return Err(Diagnostic::error(
            codes::NODE_SHAPE,
            format!(
                "{what}: variant input must invoke exactly one case; found {}",
                invoke_nodes.len()
            ),
        )
        .with_span(node_span(span.file, invoke_nodes[1])));
    }
    variant_from_invoke(schema, invoke_nodes[0], span, what, max_collection_size)
}

fn variant_from_literal(
    schema: &crate::lang::value::VariantSchema,
    literal: RawRecordLiteral,
    span: Span,
    what: &str,
    max_collection_size: usize,
) -> Result<Record, Diagnostic> {
    let mut seen = std::collections::HashSet::new();
    for property in &literal.properties {
        if !seen.insert(property.name.as_str()) {
            return Err(Diagnostic::error(
                codes::DUPLICATE,
                format!("{what}: field `{}` is set twice", property.name),
            )
            .with_span(property.span));
        }
    }

    // Constructor syntax is unambiguous only for a property-free document.
    // Once a discriminator property is present, an active-case field named
    // `invoke` is ordinary direct-literal data.
    if literal.properties.is_empty() {
        return variant_from_document(schema, &literal.children, span, what, max_collection_size);
    }

    let discriminator = literal
        .properties
        .iter()
        .find(|property| property.name == schema.discriminator)
        .ok_or_else(|| {
            Diagnostic::error(
                codes::RECORD_FIELD,
                format!(
                    "{what}: direct variant literal is missing discriminator property `{}=`",
                    schema.discriminator
                ),
            )
            .with_span(span)
        })?;
    let case_name = match &discriminator.value {
        Value::String(case_name) => case_name.clone(),
        other => {
            return Err(Diagnostic::error(
                codes::TYPE_MISMATCH,
                format!(
                    "{what}: variant discriminator property `{}=` must be a string, got {} `{}`",
                    schema.discriminator,
                    other.type_label(),
                    other.display()
                ),
            )
            .with_span(discriminator.span));
        }
    };
    let Some(case) = schema.case(&case_name) else {
        return Err(Diagnostic::error(
            codes::RECORD_FIELD,
            format!(
                "{what}: unknown variant case `{case_name}` (allowed: {})",
                schema
                    .cases
                    .iter()
                    .map(|case| case.name.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        )
        .with_span(discriminator.span));
    };
    if let Some(node) = literal
        .children
        .nodes()
        .iter()
        .find(|node| node.name().value() == schema.discriminator)
    {
        return Err(Diagnostic::error(
            codes::DUPLICATE,
            format!("{what}: field `{}` is set twice", schema.discriminator),
        )
        .with_span(node_span(span.file, node)));
    }
    let case_literal = RawRecordLiteral {
        properties: literal
            .properties
            .into_iter()
            .filter(|property| property.name != schema.discriminator)
            .collect(),
        children: literal.children,
    };
    validate_literal_duplicates(&case_literal, span.file, what)?;
    validate_variant_literal_fields(schema, case, &case_literal, span.file, what)?;
    let mut record = record_from_literal(
        &RecordSchema {
            fields: case.fields.clone(),
        },
        case_literal,
        span,
        what,
        max_collection_size,
    )?;
    record.insert(schema.discriminator.clone(), Value::String(case_name));
    Ok(record)
}

fn variant_from_invoke(
    schema: &crate::lang::value::VariantSchema,
    invoke_node: &KdlNode,
    span: Span,
    what: &str,
    max_collection_size: usize,
) -> Result<Record, Diagnostic> {
    let invoke_span = node_span(span.file, invoke_node);
    expect_args(span.file, invoke_node, 1)?;
    let case_name = req_str_arg(span.file, invoke_node)?;
    let Some(case) = schema.case(&case_name) else {
        return Err(Diagnostic::error(
            codes::RECORD_FIELD,
            format!(
                "{what}: unknown variant case `{case_name}` (allowed: {})",
                schema
                    .cases
                    .iter()
                    .map(|c| c.name.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        )
        .with_span(invoke_span));
    };
    let literal = raw_record_literal_from_node(invoke_node, span.file, what)?;
    if let Some(property) = literal
        .properties
        .iter()
        .find(|property| property.name == schema.discriminator)
    {
        return Err(Diagnostic::error(
            codes::RECORD_FIELD,
            format!(
                "{what}: `invoke` selects its case with the positional argument; discriminator property `{}=` is not allowed",
                schema.discriminator
            ),
        )
        .with_span(property.span));
    }
    validate_literal_duplicates(&literal, span.file, what)?;
    validate_variant_literal_fields(schema, case, &literal, span.file, what)?;
    let case_schema = RecordSchema {
        fields: case.fields.clone(),
    };
    let mut record = record_from_literal(
        &case_schema,
        literal,
        invoke_span,
        what,
        max_collection_size,
    )?;
    if record
        .insert(
            schema.discriminator.clone(),
            Value::String(case_name.clone()),
        )
        .is_some()
    {
        return Err(Diagnostic::error(
            codes::NODE_SHAPE,
            format!(
                "{what}: case `{case_name}` field `{}` collides with the variant discriminator",
                schema.discriminator
            ),
        )
        .with_span(span));
    }
    Ok(record)
}

fn validate_literal_duplicates(
    literal: &RawRecordLiteral,
    file: FileId,
    what: &str,
) -> Result<(), Diagnostic> {
    let mut seen = std::collections::HashSet::new();
    for property in &literal.properties {
        if !seen.insert(property.name.as_str()) {
            return Err(Diagnostic::error(
                codes::DUPLICATE,
                format!("{what}: field `{}` is set twice", property.name),
            )
            .with_span(property.span));
        }
    }
    for node in literal.children.nodes() {
        let name = node.name().value();
        if !seen.insert(name) {
            return Err(Diagnostic::error(
                codes::DUPLICATE,
                format!("{what}: field `{name}` is set twice"),
            )
            .with_span(node_span(file, node)));
        }
    }
    Ok(())
}

fn validate_variant_literal_fields(
    schema: &crate::lang::value::VariantSchema,
    case: &crate::lang::value::VariantCase,
    literal: &RawRecordLiteral,
    file: FileId,
    what: &str,
) -> Result<(), Diagnostic> {
    let check = |name: &str, field_span: Span| {
        if case.fields.iter().any(|field| field.name == name) {
            return Ok(());
        }
        if schema.cases.iter().any(|candidate| {
            candidate.name != case.name && candidate.fields.iter().any(|field| field.name == name)
        }) {
            return Err(Diagnostic::error(
                codes::RECORD_FIELD,
                format!(
                    "{what}: field `{name}` is not active for variant case `{}`",
                    case.name
                ),
            )
            .with_span(field_span));
        }
        Err(Diagnostic::error(
            codes::RECORD_FIELD,
            format!("{what}: unknown field `{name}` (variants are closed)"),
        )
        .with_span(field_span))
    };
    for property in &literal.properties {
        check(&property.name, property.span)?;
    }
    for node in literal.children.nodes() {
        check(node.name().value(), node_span(file, node))?;
    }
    Ok(())
}

/// Validates an already coerced variant record: the discriminator must be
/// present and string, must name a known case, and each present case field
/// must match the case's field schema. Non-case fields other than the
/// discriminator are rejected as the lowered record is closed.
fn revalidate_variant_record(
    schema: &crate::lang::value::VariantSchema,
    record: Record,
    span: Span,
    what: &str,
    max_collection_size: usize,
) -> Result<Record, Diagnostic> {
    let discriminator_value = match record.get(&schema.discriminator).cloned() {
        Some(Value::String(case_name)) => case_name,
        Some(Value::Null) => {
            return Err(Diagnostic::error(
                codes::RECORD_FIELD,
                format!(
                    "{what}: variant discriminator field `{}` must not be #null",
                    schema.discriminator
                ),
            )
            .with_span(span));
        }
        Some(other) => {
            return Err(Diagnostic::error(
                codes::TYPE_MISMATCH,
                format!(
                    "{what}: variant discriminator field `{}` must be a string, got {} `{}`",
                    schema.discriminator,
                    other.type_label(),
                    other.display()
                ),
            )
            .with_span(span));
        }
        None => {
            return Err(Diagnostic::error(
                codes::RECORD_FIELD,
                format!(
                    "{what}: variant record is missing discriminator field `{}`",
                    schema.discriminator
                ),
            )
            .with_span(span));
        }
    };
    let Some(case) = schema.case(&discriminator_value).cloned() else {
        return Err(Diagnostic::error(
            codes::RECORD_FIELD,
            format!(
                "{what}: variant discriminator `{}` is not a declared case (allowed: {})",
                discriminator_value,
                schema
                    .cases
                    .iter()
                    .map(|c| c.name.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        )
        .with_span(span));
    };
    // Re-coerce each present case field against its declared type.
    let case_schema = RecordSchema {
        fields: case.fields,
    };
    let mut rebuilt = Record::new();
    rebuilt.insert(
        schema.discriminator.clone(),
        Value::String(discriminator_value.clone()),
    );
    for field in &case_schema.fields {
        match record.get(&field.name).cloned() {
            Some(Value::Null)
                if field.ty.is_optional() || (!field.required && field.default.is_none()) =>
            {
                rebuilt.insert(field.name.clone(), Value::Null);
            }
            Some(value) => {
                let value = coerce_with_limit(
                    value,
                    &field.ty,
                    span,
                    &format!("{what}.{}", field.name),
                    max_collection_size,
                )?;
                rebuilt.insert(field.name.clone(), value);
            }
            None => {
                if let Some(default) = &field.default {
                    let value = coerce_with_limit(
                        default.clone(),
                        &field.ty,
                        field.default_span.unwrap_or(field.span),
                        &format!("{what}.{} default", field.name),
                        max_collection_size,
                    )?;
                    rebuilt.insert(field.name.clone(), value);
                } else if !field.required || field.ty.is_optional() {
                    rebuilt.insert(field.name.clone(), Value::Null);
                } else {
                    return Err(Diagnostic::error(
                        codes::RECORD_FIELD,
                        format!(
                            "{what}: missing required field `{}` for case `{}`",
                            field.name, case.name
                        ),
                    )
                    .with_span(span));
                }
            }
        }
    }
    let stray: Vec<String> = record
        .keys()
        .filter(|key| *key != &schema.discriminator && case_schema.field(key).is_none())
        .cloned()
        .collect();
    if !stray.is_empty() {
        return Err(Diagnostic::error(
            codes::RECORD_FIELD,
            format!(
                "{what}: case `{}` does not declare field{} {} (variants are closed)",
                case.name,
                if stray.len() == 1 { "" } else { "s" },
                stray
                    .iter()
                    .map(|f| format!("`{f}`"))
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        )
        .with_span(span));
    }
    Ok(rebuilt)
}

fn raw_node_value(
    ty: &Type,
    node: &KdlNode,
    file: FileId,
    what: &str,
) -> Result<Value, Diagnostic> {
    let span = node_span(file, node);
    let args: Vec<&kdl::KdlEntry> = node.iter().filter(|entry| entry.name().is_none()).collect();
    let props: Vec<&kdl::KdlEntry> = node.iter().filter(|entry| entry.name().is_some()).collect();
    let children = node.children().cloned().unwrap_or_default();
    let has_children = !children.nodes().is_empty();
    match ty.unwrap_optional().operational_type() {
        Type::List(_) | Type::Tuple(_) | Type::Set(_) => {
            if !props.is_empty() {
                return Err(record_shape_error(
                    what,
                    node,
                    span,
                    "list, tuple, and set fields do not use properties",
                ));
            }
            if has_children {
                if !args.is_empty() {
                    return Err(record_shape_error(
                        what,
                        node,
                        span,
                        "a list, tuple, or set field cannot mix values and children",
                    ));
                }
                Ok(Value::KdlDocument(children))
            } else {
                args.iter()
                    .map(|entry| scalar_from_record_entry(entry, what, node, file))
                    .collect::<Result<Vec<_>, _>>()
                    .map(Value::List)
            }
        }
        Type::Record(_) => {
            if !args.is_empty() {
                return Err(record_shape_error(
                    what,
                    node,
                    span,
                    "a record field does not take positional values",
                ));
            }
            Ok(Value::RawRecordLiteral(raw_record_literal_from_node(
                node, file, what,
            )?))
        }
        Type::Variant(_) => {
            if !args.is_empty() {
                return Err(record_shape_error(
                    what,
                    node,
                    span,
                    "a variant field does not take positional values",
                ));
            }
            Ok(Value::RawRecordLiteral(raw_record_literal_from_node(
                node, file, what,
            )?))
        }
        Type::Collection(_) | Type::Map(_) | Type::KdlDocument => {
            if !args.is_empty() || !props.is_empty() {
                return Err(record_shape_error(
                    what,
                    node,
                    span,
                    "this aggregate field takes only a children block",
                ));
            }
            Ok(Value::KdlDocument(children))
        }
        _ => {
            if args.len() != 1 || !props.is_empty() || has_children {
                return Err(record_shape_error(
                    what,
                    node,
                    span,
                    &format!("expected one value, found {}", args.len()),
                ));
            }
            scalar_from_record_entry(args[0], what, node, file)
        }
    }
}

fn raw_record_literal_from_node(
    node: &KdlNode,
    file: FileId,
    what: &str,
) -> Result<RawRecordLiteral, Diagnostic> {
    let mut properties = Vec::new();
    for entry in node.iter().filter(|entry| entry.name().is_some()) {
        properties.push(RawRecordProperty {
            name: entry.name().expect("property filtered").value().to_owned(),
            value: scalar_from_record_entry(entry, what, node, file)?,
            span: entry_span(file, entry),
        });
    }
    Ok(RawRecordLiteral {
        properties,
        children: node.children().cloned().unwrap_or_default(),
    })
}

fn scalar_from_record_entry(
    entry: &kdl::KdlEntry,
    what: &str,
    node: &KdlNode,
    file: FileId,
) -> Result<Value, Diagnostic> {
    kdl_scalar(entry).map_err(|message| {
        Diagnostic::error(
            codes::RECORD_FIELD,
            format!("{what}.{}: {message}", node.name().value()),
        )
        .with_span(entry_span(file, entry))
    })
}

fn record_shape_error(what: &str, node: &KdlNode, span: Span, message: &str) -> Diagnostic {
    Diagnostic::error(
        codes::RECORD_FIELD,
        format!("{what}.{}: {message}", node.name().value()),
    )
    .with_span(span)
}

fn collection_from_document(
    document: &KdlDocument,
    span: Span,
    what: &str,
    max_collection_size: usize,
) -> Result<crate::lang::value::KeyedCollection, Diagnostic> {
    let mut collection = crate::lang::value::KeyedCollection::default();
    let mut keys = std::collections::HashSet::new();
    for node in document.nodes() {
        check_value_collection_size(collection.len() + 1, max_collection_size, span, what)?;
        if node.name().value() != "item" {
            return Err(Diagnostic::error(
                codes::TYPE_MISMATCH,
                format!("{what}: collection children must be `item` nodes"),
            )
            .with_span(node_span(span.file, node)));
        }
        let args: Vec<&kdl::KdlEntry> =
            node.iter().filter(|entry| entry.name().is_none()).collect();
        let props: Vec<&kdl::KdlEntry> =
            node.iter().filter(|entry| entry.name().is_some()).collect();
        let item_span = node_span(span.file, node);
        let key = args
            .first()
            .filter(|entry| entry.ty().is_none())
            .and_then(|entry| entry.value().as_string())
            .filter(|key| !key.is_empty())
            .ok_or_else(|| {
                Diagnostic::error(
                    codes::TYPE_MISMATCH,
                    format!("{what}: collection item requires a non-empty string key"),
                )
                .with_span(item_span)
            })?
            .to_owned();
        if !keys.insert(key.clone()) {
            return Err(Diagnostic::error(
                codes::DUPLICATE,
                format!("{what}: collection key `{key}` is declared twice"),
            )
            .with_span(item_span));
        }
        let value = if !props.is_empty() {
            if args.len() != 1 {
                return Err(Diagnostic::error(
                    codes::TYPE_MISMATCH,
                    format!("{what}: collection record item cannot mix properties with values"),
                )
                .with_span(item_span));
            }
            Value::RawRecordLiteral(raw_record_literal_from_node(node, span.file, what)?)
        } else if args.len() == 1 {
            Value::KdlDocument(node.children().cloned().unwrap_or_default())
        } else if args.len() == 2 {
            kdl_scalar(args[1]).map_err(|message| {
                Diagnostic::error(codes::TYPE_MISMATCH, format!("{what}: {message}"))
                    .with_span(entry_span(span.file, args[1]))
            })?
        } else {
            let values = args
                .iter()
                .skip(1)
                .map(|entry| {
                    kdl_scalar(entry).map_err(|message| {
                        Diagnostic::error(codes::TYPE_MISMATCH, format!("{what}: {message}"))
                            .with_span(entry_span(span.file, entry))
                    })
                })
                .collect::<Result<Vec<_>, _>>()?;
            Value::List(values)
        };
        collection.items.push(crate::lang::value::CollectionItem {
            key,
            value,
            span: item_span,
        });
    }
    Ok(collection)
}

fn check_value_collection_size(
    len: usize,
    maximum: usize,
    span: Span,
    what: &str,
) -> Result<(), Diagnostic> {
    if len > maximum {
        return Err(Diagnostic::error(
            codes::BUDGET,
            format!("{what}: collection has {len} items, exceeding the maximum of {maximum}"),
        )
        .with_span(span));
    }
    Ok(())
}

fn validate_value_collection_sizes(
    value: &Value,
    maximum: usize,
    span: Span,
    what: &str,
) -> Result<(), Diagnostic> {
    match value {
        Value::List(values) => {
            check_value_collection_size(values.len(), maximum, span, what)?;
            for (index, value) in values.iter().enumerate() {
                validate_value_collection_sizes(value, maximum, span, &format!("{what}[{index}]"))?;
            }
        }
        Value::Record(values) => {
            check_value_collection_size(values.keys().count(), maximum, span, what)?;
            for (name, value) in values.iter() {
                validate_value_collection_sizes(value, maximum, span, &format!("{what}.{name}"))?;
            }
        }
        Value::Collection(values) => {
            check_value_collection_size(values.len(), maximum, span, what)?;
            for item in &values.items {
                validate_value_collection_sizes(
                    &item.value,
                    maximum,
                    item.span,
                    &format!("{what}[\"{}\"]", item.key),
                )?;
            }
        }
        Value::RawRecordLiteral(literal) | Value::UnresolvedListDefault(literal) => {
            check_value_collection_size(
                literal.properties.len() + literal.children.nodes().len(),
                maximum,
                span,
                what,
            )?;
            for property in &literal.properties {
                validate_value_collection_sizes(&property.value, maximum, property.span, what)?;
            }
            validate_kdl_collection_sizes(&literal.children, maximum, span, what)?;
        }
        Value::KdlDocument(document) => {
            validate_kdl_collection_sizes(document, maximum, span, what)?;
        }
        Value::Null
        | Value::Bool(_)
        | Value::Int(_)
        | Value::Float(_)
        | Value::String(_)
        | Value::Path(_) => {}
    }
    Ok(())
}

fn validate_kdl_collection_sizes(
    document: &KdlDocument,
    maximum: usize,
    span: Span,
    what: &str,
) -> Result<(), Diagnostic> {
    check_value_collection_size(document.nodes().len(), maximum, span, what)?;
    for node in document.nodes() {
        if let Some(children) = node.children() {
            validate_kdl_collection_sizes(children, maximum, span, what)?;
        }
    }
    Ok(())
}

/// Sorts a sequence of `set<T>` elements by [`Value::sort_key`] and removes
/// adjacent equal elements (which following the sort means all duplicates).
/// Returns a `Value::List` representing the canonical set value.
fn dedup_and_sort_values(mut values: Vec<Value>) -> Value {
    values.sort_by_key(Value::sort_key);
    values.dedup();
    Value::List(values)
}

fn kdl_scalar(entry: &kdl::KdlEntry) -> Result<Value, String> {
    if entry.ty().is_some() {
        return Err("type-annotated values are not allowed here".to_owned());
    }
    match entry.value() {
        kdl::KdlValue::Null => Ok(Value::Null),
        kdl::KdlValue::Bool(b) => Ok(Value::Bool(*b)),
        kdl::KdlValue::Integer(i) => i64::try_from(*i)
            .map(Value::Int)
            .map_err(|_| "integer out of range".to_owned()),
        kdl::KdlValue::Float(x) if x.is_finite() => Ok(Value::Float(*x)),
        kdl::KdlValue::Float(_) => Err("non-finite float is not allowed".to_owned()),
        kdl::KdlValue::String(s) => Ok(Value::String(s.clone())),
    }
}

/// Validates and lexically normalizes a `path`-typed value.
///
/// Evaluation has no ambient home directory, so a `~/` prefix remains symbolic
/// until the host resolves it against an explicit target authority.
fn resolve_path_value(raw: &str) -> Result<String, &'static str> {
    if raw.is_empty() {
        return Err("path must not be empty");
    }
    let normalized = if let Some(rest) = raw.strip_prefix("~/") {
        let folded = normalize_lexical(Path::new(rest));
        if folded.is_absolute() || folded.starts_with("..") {
            return Err("path must not escape the home directory");
        }
        let folded = folded
            .into_os_string()
            .into_string()
            .map_err(|_| "path is not valid UTF-8")?;
        format!("~/{folded}")
    } else if raw == "~" {
        "~".to_owned()
    } else {
        let folded = normalize_lexical(Path::new(raw));
        if !folded.is_absolute() {
            return Err("path must be absolute or start with `~/`");
        }
        folded
            .into_os_string()
            .into_string()
            .map_err(|_| "path is not valid UTF-8")?
    };
    Ok(normalized)
}
