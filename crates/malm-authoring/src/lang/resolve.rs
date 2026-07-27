//! Resolves module extensions, slots, and profile inheritance. Parents are
//! processed in written order, children override ancestors, and unresolved
//! sibling conflicts are errors. Instance aliases identify modules across
//! layers, and slot replacement is explicit.

use crate::lang::ast::{
    ExtendModule, FragmentDecl, FragmentOp, GlobalVar, InputDecl, InstanceConfig, ModuleDecl,
    OutputNode, ParsedWorkspace, PatchEntry, ProfileDecl, ProfileItem, RequirementNode, SlotDecl,
    SlotMax,
};
use crate::lang::diag::{Diagnostic, Diagnostics, Span, codes};
use crate::lang::value::{Type, Value};
use std::collections::{BTreeMap, HashMap, HashSet};

/// A module with all its extensions merged in.
#[derive(Debug)]
pub struct ResolvedModule {
    pub decl: ModuleDecl,
    /// Outputs contributed by extensions (after the module's own).
    pub extra_outputs: Vec<OutputNode>,
}

impl ResolvedModule {
    pub fn inputs(&self) -> &[InputDecl] {
        &self.decl.inputs
    }

    pub fn input(&self, name: &str) -> Option<&InputDecl> {
        self.decl.inputs.iter().find(|i| i.name == name)
    }

    pub fn fragment(&self, name: &str) -> Option<&FragmentDecl> {
        self.decl.fragments.iter().find(|f| f.name == name)
    }

    pub fn requires(&self) -> &[RequirementNode] {
        &self.decl.requires
    }

    pub fn outputs(&self) -> impl Iterator<Item = &OutputNode> {
        self.decl.outputs.iter().chain(self.extra_outputs.iter())
    }
}

/// The fully resolved workspace: modules merged, profile graph validated.
#[derive(Debug)]
pub struct ResolvedWorkspace {
    pub modules: BTreeMap<String, ResolvedModule>,
    pub slots: BTreeMap<String, SlotDecl>,
    pub profiles: Vec<ProfileDecl>,
    /// Unique `global.*` design tokens.
    pub globals: BTreeMap<String, GlobalVar>,
    /// The repository root against which bare (non-`./`) sources resolve.
    pub source_root: std::path::PathBuf,
    /// Trusted local loads may expose the host name as a non-optional string.
    pub machine_hostname_trusted: bool,
}

impl ResolvedWorkspace {
    pub fn profile(&self, name: &str) -> Option<&ProfileDecl> {
        self.profiles.iter().find(|p| p.name == name)
    }

    pub fn profile_names(&self) -> Vec<&str> {
        self.profiles.iter().map(|p| p.name.as_str()).collect()
    }
}

pub fn resolve_workspace(
    parsed: ParsedWorkspace,
    source_root: std::path::PathBuf,
    machine_hostname_trusted: bool,
    diagnostics: &mut Diagnostics,
) -> ResolvedWorkspace {
    let ParsedWorkspace {
        modules,
        extensions,
        profiles,
        profile_extensions,
        slots,
        globals,
    } = parsed;

    let mut resolved_modules: BTreeMap<String, ResolvedModule> = BTreeMap::new();
    for module in modules {
        if resolved_modules.contains_key(&module.name) {
            diagnostics.error_at(
                codes::DUPLICATE,
                format!("module `{}` is declared twice", module.name),
                module.span,
            );
            continue;
        }
        resolved_modules.insert(
            module.name.clone(),
            ResolvedModule {
                decl: module,
                extra_outputs: Vec::new(),
            },
        );
    }

    for extension in extensions {
        merge_extension(&mut resolved_modules, extension, diagnostics);
    }
    for module in resolved_modules.values_mut() {
        resolve_module_types(&mut module.decl, diagnostics);
    }

    let mut slot_map: BTreeMap<String, SlotDecl> = BTreeMap::new();
    for slot in slots {
        if slot_map.contains_key(&slot.name) {
            diagnostics.error_at(
                codes::DUPLICATE,
                format!("slot `{}` is declared twice", slot.name),
                slot.span,
            );
            continue;
        }
        slot_map.insert(slot.name.clone(), slot);
    }

    for module in resolved_modules.values() {
        if let Some(slot) = &module.decl.slot
            && !slot_map.contains_key(slot)
        {
            diagnostics.error_at_with_help(
                codes::SLOT,
                format!("module `{}` fills unknown slot `{slot}`", module.decl.name),
                module.decl.span,
                known_names("slot", slot_map.keys().map(String::as_str)),
            );
        }
    }

    let mut merged: Vec<ProfileDecl> = Vec::new();
    for profile in profiles {
        if let Some(existing) = merged.iter().find(|p| p.name == profile.name) {
            diagnostics.push(
                Diagnostic::error(
                    codes::DUPLICATE,
                    format!("profile `{}` is declared twice", profile.name),
                )
                .with_span(profile.span)
                .with_label("first declared here", existing.span)
                .with_help("use `extend-profile` to add an explicit profile layer"),
            );
        } else {
            merged.push(profile);
        }
    }
    for extension in profile_extensions {
        let Some(profile) = merged.iter_mut().find(|p| p.name == extension.profile) else {
            diagnostics.error_at(
                codes::UNKNOWN_PROFILE,
                format!(
                    "`extend-profile` names unknown profile `{}`",
                    extension.profile
                ),
                extension.span,
            );
            continue;
        };
        profile.extends.extend(extension.extends);
        profile.items.extend(extension.items);
    }
    let profiles = merged;
    validate_profile_graph(&profiles, diagnostics);

    let mut global_map: BTreeMap<String, GlobalVar> = BTreeMap::new();
    for var in globals {
        if let Some(existing) = global_map.get(&var.name) {
            if !var.override_existing {
                diagnostics.push(
                    Diagnostic::error(
                        codes::DUPLICATE,
                        format!("global `{}` is declared twice", var.name),
                    )
                    .with_span(var.span)
                    .with_label("first declared here", existing.span)
                    .with_help(
                        "add `override=#true` when replacing an existing global intentionally",
                    ),
                );
            } else if std::mem::discriminant(&existing.value) != std::mem::discriminant(&var.value)
            {
                diagnostics.push(
                    Diagnostic::error(
                        codes::TYPE_MISMATCH,
                        format!(
                            "global `{}` override changes its type from {} to {}",
                            var.name,
                            existing.value.type_label(),
                            var.value.type_label()
                        ),
                    )
                    .with_span(var.span)
                    .with_label("original type declared here", existing.span),
                );
            } else {
                global_map.insert(var.name.clone(), var);
            }
        } else if var.override_existing {
            diagnostics.error_at(
                codes::DUPLICATE,
                format!(
                    "global `{}` uses `override=#true` but has no earlier declaration",
                    var.name
                ),
                var.span,
            );
        } else {
            global_map.insert(var.name.clone(), var);
        }
    }

    ResolvedWorkspace {
        modules: resolved_modules,
        slots: slot_map,
        profiles,
        globals: global_map,
        source_root,
        machine_hostname_trusted,
    }
}

const MAX_TYPE_DEPTH: usize = 32;
const MAX_EXPANDED_TYPE_NODES: usize = 4096;
const MAX_MODULE_TYPE_NODES: usize = 65_536;
const MAX_EXPANDED_TYPE_BYTES: usize = 256 * 1024;
const MAX_MODULE_TYPE_BYTES: usize = 4 * 1024 * 1024;

/// Resolves module-scoped names after extensions merge so extension inputs see
/// the base module's declarations. All `Type::Named` values and declaration
/// bodies are removed before the normal type checker runs.
fn resolve_module_types(module: &mut ModuleDecl, diagnostics: &mut Diagnostics) {
    let declarations = module.types.clone();
    let definitions: HashMap<&str, &crate::lang::ast::NamedTypeDecl> = declarations
        .iter()
        .map(|declaration| (declaration.name.as_str(), declaration))
        .collect();
    let mut resolver = TypeResolver {
        definitions,
        cache: HashMap::new(),
        failures: HashMap::new(),
        cached_nodes: 0,
        cached_bytes: 0,
        retained_nodes: 0,
        retained_bytes: 0,
        module_limit_exhausted: false,
        stack: Vec::new(),
    };
    let mut reported = HashSet::new();

    for declaration in &declarations {
        if resolver.module_limit_exhausted {
            break;
        }
        if let Err(diagnostic) = resolver.resolve_named(&declaration.name, 0, declaration.span) {
            resolver
                .failures
                .insert(declaration.name.clone(), diagnostic.clone());
            push_type_diagnostic(diagnostics, &mut reported, diagnostic);
        }
    }
    for input in &mut module.inputs {
        if resolver.module_limit_exhausted {
            input.ty = Type::String;
            continue;
        }
        match resolver.resolve_type(&input.ty, 0, input.span) {
            Ok(ty) => match resolver.retain_input_type(&ty, input.span) {
                Ok(()) => {
                    input.ty = ty;
                    if input.computed_default.is_some()
                        && !input.ty.unwrap_optional().lowered_type().is_scalar()
                    {
                        diagnostics.error_at(
                            codes::BAD_DEFAULT,
                            format!(
                                "computed defaults require a scalar input type (bool, int, float, string, path, enum, or a refine over scalars); got {}",
                                input.ty
                            ),
                            input.computed_default_span.unwrap_or(input.span),
                        );
                    }
                    normalize_implicit_default(input);
                }
                Err(diagnostic) => {
                    push_type_diagnostic(diagnostics, &mut reported, diagnostic);
                    input.ty = Type::String;
                }
            },
            Err(diagnostic) => {
                push_type_diagnostic(diagnostics, &mut reported, diagnostic);
                input.ty = Type::String;
            }
        }
    }
    module.types.clear();
}

fn normalize_implicit_default(input: &mut InputDecl) {
    if input.default.is_some() || input.computed_default.is_some() || input.ty.is_optional() {
        return;
    }
    input.default = match &input.ty {
        Type::List(_) | Type::Set(_) => Some(Value::List(Vec::new())),
        Type::Collection(_) | Type::Map(_) => Some(Value::Collection(
            crate::lang::value::KeyedCollection::default(),
        )),
        _ => None,
    };
}

fn push_type_diagnostic(
    diagnostics: &mut Diagnostics,
    reported: &mut HashSet<(&'static str, String, usize, usize, usize)>,
    diagnostic: Diagnostic,
) {
    let (file, offset, len) = if diagnostic.code == codes::TYPE_COMPLEXITY {
        (usize::MAX, 0, 0)
    } else {
        diagnostic.span.map_or((usize::MAX, 0, 0), |span| {
            (span.file.0, span.offset, span.len)
        })
    };
    let key = (
        diagnostic.code,
        diagnostic.message.clone(),
        file,
        offset,
        len,
    );
    if reported.insert(key) {
        diagnostics.push(diagnostic);
    }
}

struct TypeResolver<'a> {
    definitions: HashMap<&'a str, &'a crate::lang::ast::NamedTypeDecl>,
    cache: HashMap<String, Type>,
    failures: HashMap<String, Diagnostic>,
    cached_nodes: usize,
    cached_bytes: usize,
    retained_nodes: usize,
    retained_bytes: usize,
    module_limit_exhausted: bool,
    stack: Vec<String>,
}

impl TypeResolver<'_> {
    fn resolve_named(&mut self, name: &str, depth: usize, span: Span) -> Result<Type, Diagnostic> {
        self.validate_named_expansion(name, depth, span)?;
        if let Some(resolved) = self.cache.get(name) {
            validate_resolved_type_shape(resolved, depth, span)?;
            return Ok(resolved.clone());
        }
        if let Some(diagnostic) = self.failures.get(name) {
            return Err(diagnostic.clone());
        }
        let Some(declaration) = self.definitions.get(name).copied() else {
            return Err(Diagnostic::error(
                codes::UNKNOWN_TYPE,
                format!("unknown module-scoped type `{name}`"),
            )
            .with_span(span));
        };
        if let Some(start) = self.stack.iter().position(|active| active == name) {
            let mut cycle = self.stack[start..].to_vec();
            cycle.push(name.to_owned());
            return Err(Diagnostic::error(
                codes::TYPE_CYCLE,
                format!("type declaration cycle: {}", cycle.join(" -> ")),
            )
            .with_span(declaration.span));
        }
        if depth > MAX_TYPE_DEPTH {
            return Err(Diagnostic::error(
                codes::TYPE_DEPTH,
                format!("named type expansion exceeds the maximum depth of {MAX_TYPE_DEPTH}"),
            )
            .with_span(declaration.span));
        }

        self.stack.push(name.to_owned());
        let resolved = self.resolve_type(&declaration.ty, depth, declaration.span);
        self.stack.pop();
        let resolved = resolved?;
        let shape = validate_resolved_type_shape(&resolved, depth, span)?;
        let cached_nodes = self
            .cached_nodes
            .checked_add(shape.nodes)
            .ok_or_else(|| module_type_node_diagnostic(span))?;
        let cached_bytes = self
            .cached_bytes
            .checked_add(shape.owned_bytes)
            .and_then(|bytes| bytes.checked_add(name.len()))
            .ok_or_else(|| module_type_byte_diagnostic(span))?;
        if cached_nodes
            .checked_add(self.retained_nodes)
            .is_none_or(|nodes| nodes > MAX_MODULE_TYPE_NODES)
        {
            self.module_limit_exhausted = true;
            return Err(module_type_node_diagnostic(span));
        }
        if cached_bytes
            .checked_add(self.retained_bytes)
            .is_none_or(|bytes| bytes > MAX_MODULE_TYPE_BYTES)
        {
            self.module_limit_exhausted = true;
            return Err(module_type_byte_diagnostic(span));
        }
        self.cached_nodes = cached_nodes;
        self.cached_bytes = cached_bytes;
        self.cache.insert(name.to_owned(), resolved.clone());
        Ok(resolved)
    }

    fn retain_input_type(&mut self, ty: &Type, span: Span) -> Result<(), Diagnostic> {
        let shape = validate_resolved_type_shape(ty, 0, span)?;
        let retained_nodes = self
            .retained_nodes
            .checked_add(shape.nodes)
            .ok_or_else(|| module_type_node_diagnostic(span))?;
        let retained_bytes = self
            .retained_bytes
            .checked_add(shape.owned_bytes)
            .ok_or_else(|| module_type_byte_diagnostic(span))?;
        if retained_nodes
            .checked_add(self.cached_nodes)
            .is_none_or(|nodes| nodes > MAX_MODULE_TYPE_NODES)
        {
            self.module_limit_exhausted = true;
            return Err(module_type_node_diagnostic(span));
        }
        if retained_bytes
            .checked_add(self.cached_bytes)
            .is_none_or(|bytes| bytes > MAX_MODULE_TYPE_BYTES)
        {
            self.module_limit_exhausted = true;
            return Err(module_type_byte_diagnostic(span));
        }
        self.retained_nodes = retained_nodes;
        self.retained_bytes = retained_bytes;
        Ok(())
    }

    fn resolve_type(&mut self, ty: &Type, depth: usize, span: Span) -> Result<Type, Diagnostic> {
        if depth > MAX_TYPE_DEPTH {
            return Err(Diagnostic::error(
                codes::TYPE_DEPTH,
                format!("type expansion exceeds the maximum depth of {MAX_TYPE_DEPTH}"),
            )
            .with_span(span));
        }
        match ty {
            Type::Bool
            | Type::Int
            | Type::Float
            | Type::String
            | Type::Path
            | Type::Enum(_)
            | Type::KdlDocument => Ok(ty.clone()),
            Type::Named(name) => self.resolve_named(name, depth + 1, span),
            Type::Optional(inner) => {
                let inner = self.resolve_type(inner, depth + 1, span)?;
                if inner.is_optional() {
                    return Err(Diagnostic::error(
                        codes::DUPLICATE,
                        "optional type is declared more than once after named type resolution",
                    )
                    .with_span(span));
                }
                let resolved = Type::Optional(Box::new(inner));
                validate_resolved_type_shape(&resolved, depth, span)?;
                Ok(resolved)
            }
            Type::List(item) => {
                let resolved = Type::List(Box::new(self.resolve_type(item, depth + 1, span)?));
                validate_resolved_type_shape(&resolved, depth, span)?;
                Ok(resolved)
            }
            Type::Collection(item) => {
                let resolved =
                    Type::Collection(Box::new(self.resolve_type(item, depth + 1, span)?));
                validate_resolved_type_shape(&resolved, depth, span)?;
                Ok(resolved)
            }
            Type::Map(item) => {
                let resolved = Type::Map(Box::new(self.resolve_type(item, depth + 1, span)?));
                validate_resolved_type_shape(&resolved, depth, span)?;
                Ok(resolved)
            }
            Type::Set(item) => {
                let item = self.resolve_type(item, depth + 1, span)?;
                if !item.unwrap_optional().lowered_type().is_scalar() {
                    return Err(Diagnostic::error(
                        codes::NODE_SHAPE,
                        format!(
                            "set element type `{item}` is aggregate; sets accept only scalar element types"
                        ),
                    )
                    .with_span(span));
                }
                let resolved = Type::Set(Box::new(item));
                validate_resolved_type_shape(&resolved, depth, span)?;
                Ok(resolved)
            }
            Type::Tuple(types) => {
                let mut resolved = Vec::with_capacity(types.len());
                for ty in types {
                    resolved.push(self.resolve_type(ty, depth + 1, span)?);
                }
                let resolved = Type::Tuple(resolved);
                validate_resolved_type_shape(&resolved, depth, span)?;
                Ok(resolved)
            }
            Type::Record(schema) => {
                let mut fields = Vec::with_capacity(schema.fields.len());
                let mut expanded_nodes = 1usize;
                let mut expanded_bytes = 0usize;
                for original in &schema.fields {
                    let mut field = original.clone();
                    field.ty = self.resolve_type(&field.ty, depth + 1, field.span)?;
                    let field_shape =
                        validate_resolved_type_shape(&field.ty, depth + 1, field.span)?;
                    expanded_nodes = expanded_nodes
                        .checked_add(field_shape.nodes)
                        .ok_or_else(|| type_complexity_diagnostic(field.span))?;
                    if expanded_nodes > MAX_EXPANDED_TYPE_NODES {
                        return Err(type_complexity_diagnostic(field.span));
                    }
                    expanded_bytes = expanded_bytes
                        .checked_add(field_shape.owned_bytes)
                        .and_then(|bytes| bytes.checked_add(field.name.len()))
                        .and_then(|bytes| {
                            field.default.as_ref().map_or(Some(bytes), |value| {
                                bytes.checked_add(value_owned_bytes(value))
                            })
                        })
                        .ok_or_else(|| type_byte_complexity_diagnostic(field.span))?;
                    if expanded_bytes > MAX_EXPANDED_TYPE_BYTES {
                        return Err(type_byte_complexity_diagnostic(field.span));
                    }
                    if let Some(default) = &field.default {
                        if matches!(
                            field.ty.unwrap_optional(),
                            Type::List(_)
                                | Type::Record(_)
                                | Type::Collection(_)
                                | Type::Map(_)
                                | Type::Tuple(_)
                                | Type::Set(_)
                                | Type::KdlDocument
                        ) {
                            return Err(Diagnostic::error(
                                codes::BAD_DEFAULT,
                                format!(
                                    "field `{}` default: aggregate field defaults are not supported",
                                    field.name
                                ),
                            )
                            .with_span(field.default_span.unwrap_or(field.span)));
                        }
                        crate::lang::typecheck::coerce(
                            default.clone(),
                            &field.ty,
                            field.default_span.unwrap_or(field.span),
                            &format!("field `{}` default", field.name),
                        )?;
                    }
                    fields.push(field);
                }
                Ok(Type::Record(crate::lang::value::RecordSchema { fields }))
            }
            Type::Variant(schema) => {
                let mut cases = Vec::with_capacity(schema.cases.len());
                self.resolve_variant_cases(schema, depth, span, &mut cases)?;
                Ok(Type::Variant(crate::lang::value::VariantSchema {
                    discriminator: schema.discriminator.clone(),
                    cases,
                }))
            }
            Type::Refine(schema) => {
                let base = self.resolve_type(&schema.base, depth + 1, span)?;
                validate_refine_schema(
                    &schema.name,
                    &base,
                    schema.min,
                    schema.max,
                    &schema.format,
                    &schema.unit,
                    span,
                )?;
                Ok(Type::Refine(crate::lang::value::RefineSchema {
                    name: schema.name.clone(),
                    base: Box::new(base),
                    min: schema.min,
                    max: schema.max,
                    format: schema.format.clone(),
                    unit: schema.unit.clone(),
                    span,
                }))
            }
        }
    }

    /// Validates expansion depth against the unresolved graph even on cache
    /// hits, where alias edges are otherwise erased from the cached `Type`.
    fn validate_named_expansion(
        &self,
        name: &str,
        depth: usize,
        span: Span,
    ) -> Result<(), Diagnostic> {
        let mut visited_nodes = 0;
        self.validate_named_expansion_inner(name, depth, span, &mut Vec::new(), &mut visited_nodes)
    }

    fn validate_named_expansion_inner(
        &self,
        name: &str,
        depth: usize,
        span: Span,
        active: &mut Vec<String>,
        visited_nodes: &mut usize,
    ) -> Result<(), Diagnostic> {
        let Some(declaration) = self.definitions.get(name).copied() else {
            return Err(Diagnostic::error(
                codes::UNKNOWN_TYPE,
                format!("unknown module-scoped type `{name}`"),
            )
            .with_span(span));
        };
        if let Some(start) = active.iter().position(|candidate| candidate == name) {
            let mut cycle = active[start..].to_vec();
            cycle.push(name.to_owned());
            return Err(Diagnostic::error(
                codes::TYPE_CYCLE,
                format!("type declaration cycle: {}", cycle.join(" -> ")),
            )
            .with_span(declaration.span));
        }
        if depth > MAX_TYPE_DEPTH {
            return Err(Diagnostic::error(
                codes::TYPE_DEPTH,
                format!("named type expansion exceeds the maximum depth of {MAX_TYPE_DEPTH}"),
            )
            .with_span(declaration.span));
        }

        active.push(name.to_owned());
        let result = self.validate_type_expansion(
            &declaration.ty,
            depth,
            declaration.span,
            active,
            visited_nodes,
        );
        active.pop();
        result
    }

    fn validate_type_expansion(
        &self,
        ty: &Type,
        depth: usize,
        span: Span,
        active: &mut Vec<String>,
        visited_nodes: &mut usize,
    ) -> Result<(), Diagnostic> {
        if depth > MAX_TYPE_DEPTH {
            return Err(Diagnostic::error(
                codes::TYPE_DEPTH,
                format!("type expansion exceeds the maximum depth of {MAX_TYPE_DEPTH}"),
            )
            .with_span(span));
        }
        if !matches!(ty, Type::Named(_)) {
            *visited_nodes = visited_nodes
                .checked_add(1)
                .ok_or_else(|| type_complexity_diagnostic(span))?;
            if *visited_nodes > MAX_EXPANDED_TYPE_NODES {
                return Err(type_complexity_diagnostic(span));
            }
        }
        match ty {
            Type::Named(name) => {
                self.validate_named_expansion_inner(name, depth + 1, span, active, visited_nodes)
            }
            Type::Optional(inner)
            | Type::List(inner)
            | Type::Collection(inner)
            | Type::Map(inner)
            | Type::Set(inner) => {
                self.validate_type_expansion(inner, depth + 1, span, active, visited_nodes)
            }
            Type::Tuple(types) => {
                for ty in types {
                    self.validate_type_expansion(ty, depth + 1, span, active, visited_nodes)?;
                }
                Ok(())
            }
            Type::Record(schema) => {
                for field in &schema.fields {
                    self.validate_type_expansion(
                        &field.ty,
                        depth + 1,
                        field.span,
                        active,
                        visited_nodes,
                    )?;
                }
                Ok(())
            }
            Type::Variant(schema) => {
                for case in &schema.cases {
                    for field in &case.fields {
                        self.validate_type_expansion(
                            &field.ty,
                            depth + 1,
                            field.span,
                            active,
                            visited_nodes,
                        )?;
                    }
                }
                Ok(())
            }
            Type::Refine(schema) => {
                self.validate_type_expansion(&schema.base, depth + 1, span, active, visited_nodes)
            }
            Type::Bool
            | Type::Int
            | Type::Float
            | Type::String
            | Type::Path
            | Type::Enum(_)
            | Type::KdlDocument => Ok(()),
        }
    }

    /// Resolves each variant case, enforcing field defaults and complexity
    /// rules. The variant's accumulated node budget
    /// starts at `1` (the variant itself) and sums every case field.
    fn resolve_variant_cases(
        &mut self,
        schema: &crate::lang::value::VariantSchema,
        depth: usize,
        span: Span,
        cases: &mut Vec<crate::lang::value::VariantCase>,
    ) -> Result<(), Diagnostic> {
        let mut expanded_nodes = 1usize;
        let mut expanded_bytes = 0usize;
        for original in &schema.cases {
            let mut case = crate::lang::value::VariantCase {
                name: original.name.clone(),
                fields: Vec::with_capacity(original.fields.len()),
                span: original.span,
            };
            for original_field in &original.fields {
                let mut field = original_field.clone();
                field.ty = self.resolve_type(&field.ty, depth + 1, field.span)?;
                let field_shape = validate_resolved_type_shape(&field.ty, depth + 1, field.span)?;
                expanded_nodes = expanded_nodes
                    .checked_add(field_shape.nodes)
                    .ok_or_else(|| type_complexity_diagnostic(field.span))?;
                if expanded_nodes > MAX_EXPANDED_TYPE_NODES {
                    return Err(type_complexity_diagnostic(field.span));
                }
                expanded_bytes = expanded_bytes
                    .checked_add(field_shape.owned_bytes)
                    .and_then(|bytes| bytes.checked_add(field.name.len()))
                    .and_then(|bytes| {
                        field.default.as_ref().map_or(Some(bytes), |value| {
                            bytes.checked_add(value_owned_bytes(value))
                        })
                    })
                    .ok_or_else(|| type_byte_complexity_diagnostic(field.span))?;
                if expanded_bytes > MAX_EXPANDED_TYPE_BYTES {
                    return Err(type_byte_complexity_diagnostic(field.span));
                }
                if let Some(default) = &field.default {
                    if matches!(
                        field.ty.unwrap_optional(),
                        Type::List(_)
                            | Type::Record(_)
                            | Type::Collection(_)
                            | Type::Map(_)
                            | Type::Tuple(_)
                            | Type::Set(_)
                            | Type::KdlDocument
                    ) {
                        return Err(Diagnostic::error(
                            codes::BAD_DEFAULT,
                            format!(
                                "field `{}` default: aggregate field defaults are not supported",
                                field.name
                            ),
                        )
                        .with_span(field.default_span.unwrap_or(field.span)));
                    }
                    crate::lang::typecheck::coerce(
                        default.clone(),
                        &field.ty,
                        field.default_span.unwrap_or(field.span),
                        &format!("case `{}` field `{}` default", case.name, field.name),
                    )?;
                }
                case.fields.push(field);
            }
            cases.push(case);
        }
        if cases.is_empty() {
            return Err(Diagnostic::error(
                codes::NODE_SHAPE,
                "a variant declaration must declare at least one case",
            )
            .with_span(span));
        }
        let mut shared_fields: HashMap<&str, (&Type, &str, Span)> = HashMap::new();
        for case in cases.iter() {
            for field in &case.fields {
                if let Some((first_ty, first_case, first_span)) =
                    shared_fields.get(field.name.as_str())
                    && *first_ty != &field.ty
                {
                    return Err(Diagnostic::error(
                        codes::TYPE_MISMATCH,
                        format!(
                            "variant field `{}` has incompatible resolved types in cases `{first_case}` ({first_ty}) and `{}` ({})",
                            field.name, case.name, field.ty
                        ),
                    )
                    .with_span(field.span)
                    .with_label("first declared with this type here", *first_span));
                }
                shared_fields
                    .entry(&field.name)
                    .or_insert((&field.ty, &case.name, field.span));
            }
        }
        Ok(())
    }
}

#[derive(Clone, Copy)]
struct TypeShape {
    nodes: usize,
    owned_bytes: usize,
}

fn validate_resolved_type_shape(
    ty: &Type,
    depth: usize,
    span: Span,
) -> Result<TypeShape, Diagnostic> {
    if depth > MAX_TYPE_DEPTH {
        return Err(Diagnostic::error(
            codes::TYPE_DEPTH,
            format!("type expansion exceeds the maximum depth of {MAX_TYPE_DEPTH}"),
        )
        .with_span(span));
    }
    let shape = match ty {
        Type::Optional(inner) | Type::List(inner) | Type::Collection(inner) => {
            let inner = validate_resolved_type_shape(inner, depth + 1, span)?;
            TypeShape {
                nodes: inner
                    .nodes
                    .checked_add(1)
                    .ok_or_else(|| type_complexity_diagnostic(span))?,
                owned_bytes: inner.owned_bytes,
            }
        }
        Type::Map(inner) | Type::Set(inner) => {
            let inner = validate_resolved_type_shape(inner, depth + 1, span)?;
            TypeShape {
                nodes: inner
                    .nodes
                    .checked_add(1)
                    .ok_or_else(|| type_complexity_diagnostic(span))?,
                owned_bytes: inner.owned_bytes,
            }
        }
        Type::Tuple(types) => {
            let mut nodes = 1usize;
            let mut owned_bytes = 0usize;
            for ty in types {
                let inner_shape = validate_resolved_type_shape(ty, depth + 1, span)?;
                nodes = nodes
                    .checked_add(inner_shape.nodes)
                    .ok_or_else(|| type_complexity_diagnostic(span))?;
                owned_bytes = owned_bytes
                    .checked_add(inner_shape.owned_bytes)
                    .ok_or_else(|| type_byte_complexity_diagnostic(span))?;
                if nodes > MAX_EXPANDED_TYPE_NODES {
                    return Err(type_complexity_diagnostic(span));
                }
                if owned_bytes > MAX_EXPANDED_TYPE_BYTES {
                    return Err(type_byte_complexity_diagnostic(span));
                }
            }
            TypeShape { nodes, owned_bytes }
        }
        Type::Record(schema) => {
            let mut nodes = 1usize;
            let mut owned_bytes = 0usize;
            for field in &schema.fields {
                let field_shape = validate_resolved_type_shape(&field.ty, depth + 1, field.span)?;
                nodes = nodes
                    .checked_add(field_shape.nodes)
                    .ok_or_else(|| type_complexity_diagnostic(field.span))?;
                owned_bytes = owned_bytes
                    .checked_add(field_shape.owned_bytes)
                    .and_then(|bytes| bytes.checked_add(field.name.len()))
                    .and_then(|bytes| {
                        field.default.as_ref().map_or(Some(bytes), |value| {
                            bytes.checked_add(value_owned_bytes(value))
                        })
                    })
                    .ok_or_else(|| type_byte_complexity_diagnostic(field.span))?;
                if nodes > MAX_EXPANDED_TYPE_NODES {
                    return Err(type_complexity_diagnostic(field.span));
                }
                if owned_bytes > MAX_EXPANDED_TYPE_BYTES {
                    return Err(type_byte_complexity_diagnostic(field.span));
                }
            }
            TypeShape { nodes, owned_bytes }
        }
        Type::Variant(schema) => {
            let mut nodes = 1usize;
            let mut owned_bytes = schema.discriminator.len();
            for case in &schema.cases {
                owned_bytes = owned_bytes.saturating_add(case.name.len());
                for field in &case.fields {
                    let field_shape =
                        validate_resolved_type_shape(&field.ty, depth + 1, field.span)?;
                    nodes = nodes
                        .checked_add(field_shape.nodes)
                        .ok_or_else(|| type_complexity_diagnostic(field.span))?;
                    owned_bytes = owned_bytes
                        .checked_add(field_shape.owned_bytes)
                        .and_then(|bytes| bytes.checked_add(field.name.len()))
                        .and_then(|bytes| {
                            field.default.as_ref().map_or(Some(bytes), |value| {
                                bytes.checked_add(value_owned_bytes(value))
                            })
                        })
                        .ok_or_else(|| type_byte_complexity_diagnostic(field.span))?;
                    if nodes > MAX_EXPANDED_TYPE_NODES {
                        return Err(type_complexity_diagnostic(field.span));
                    }
                    if owned_bytes > MAX_EXPANDED_TYPE_BYTES {
                        return Err(type_byte_complexity_diagnostic(field.span));
                    }
                }
            }
            TypeShape { nodes, owned_bytes }
        }
        Type::Enum(values) => TypeShape {
            nodes: 1,
            owned_bytes: values
                .iter()
                .fold(0usize, |bytes, value| bytes.saturating_add(value.len())),
        },
        Type::Named(name) => TypeShape {
            nodes: 1,
            owned_bytes: name.len(),
        },
        Type::Refine(schema) => {
            let inner = validate_resolved_type_shape(&schema.base, depth + 1, span)?;
            let owned_bytes = inner
                .owned_bytes
                .checked_add(schema.name.len())
                .and_then(|bytes| {
                    schema
                        .format
                        .as_ref()
                        .map_or(Some(bytes), |format| bytes.checked_add(format.len()))
                })
                .and_then(|bytes| {
                    schema
                        .unit
                        .as_ref()
                        .map_or(Some(bytes), |unit| bytes.checked_add(unit.len()))
                })
                .ok_or_else(|| type_byte_complexity_diagnostic(span))?;
            TypeShape {
                nodes: inner
                    .nodes
                    .checked_add(1)
                    .ok_or_else(|| type_complexity_diagnostic(span))?,
                owned_bytes,
            }
        }
        Type::Bool | Type::Int | Type::Float | Type::String | Type::Path | Type::KdlDocument => {
            TypeShape {
                nodes: 1,
                owned_bytes: 0,
            }
        }
    };
    if shape.nodes > MAX_EXPANDED_TYPE_NODES {
        return Err(type_complexity_diagnostic(span));
    }
    if shape.owned_bytes > MAX_EXPANDED_TYPE_BYTES {
        return Err(type_byte_complexity_diagnostic(span));
    }
    Ok(shape)
}

fn value_owned_bytes(value: &Value) -> usize {
    match value {
        Value::String(value) | Value::Path(value) => value.len(),
        Value::List(values) => values.iter().fold(0usize, |bytes, value| {
            bytes.saturating_add(value_owned_bytes(value))
        }),
        Value::Record(record) => record.iter().fold(0usize, |bytes, (name, value)| {
            bytes
                .saturating_add(name.len())
                .saturating_add(value_owned_bytes(value))
        }),
        Value::Collection(collection) => collection.items.iter().fold(0usize, |bytes, item| {
            bytes
                .saturating_add(item.key.len())
                .saturating_add(value_owned_bytes(&item.value))
        }),
        Value::RawRecordLiteral(literal) => {
            literal.properties.iter().fold(0usize, |bytes, property| {
                bytes
                    .saturating_add(property.name.len())
                    .saturating_add(value_owned_bytes(&property.value))
            })
        }
        Value::Null
        | Value::Bool(_)
        | Value::Int(_)
        | Value::Float(_)
        | Value::KdlDocument(_)
        | Value::UnresolvedListDefault(_) => 0,
    }
}

fn type_complexity_diagnostic(span: Span) -> Diagnostic {
    Diagnostic::error(
        codes::TYPE_COMPLEXITY,
        format!("expanded type exceeds the maximum of {MAX_EXPANDED_TYPE_NODES} type nodes"),
    )
    .with_span(span)
}

fn type_byte_complexity_diagnostic(span: Span) -> Diagnostic {
    Diagnostic::error(
        codes::TYPE_COMPLEXITY,
        format!(
            "expanded type owns more than the maximum of {MAX_EXPANDED_TYPE_BYTES} string bytes"
        ),
    )
    .with_span(span)
}

fn module_type_node_diagnostic(span: Span) -> Diagnostic {
    Diagnostic::error(
        codes::TYPE_COMPLEXITY,
        format!(
            "resolved module types exceed the maximum of {MAX_MODULE_TYPE_NODES} retained and cached type nodes"
        ),
    )
    .with_span(span)
}

fn module_type_byte_diagnostic(span: Span) -> Diagnostic {
    Diagnostic::error(
        codes::TYPE_COMPLEXITY,
        format!(
            "resolved module types own more than the maximum of {MAX_MODULE_TYPE_BYTES} cached and retained string bytes"
        ),
    )
    .with_span(span)
}

/// Validates a refinement's base type after named-type expansion. Resolution
/// must reject declarations whose resolved base is not a supported scalar or
/// `list<string>`, even when the unresolved spelling passed shape checks.
fn validate_refine_schema(
    name: &str,
    base: &Type,
    min: Option<crate::lang::value::NumericBound>,
    max: Option<crate::lang::value::NumericBound>,
    format: &Option<String>,
    unit: &Option<String>,
    span: Span,
) -> Result<(), Diagnostic> {
    if base.is_optional() {
        return Err(Diagnostic::error(
            codes::NODE_SHAPE,
            format!("refine `{name}` base must not be optional"),
        )
        .with_span(span));
    }
    if min
        .zip(max)
        .is_some_and(|(minimum, maximum)| minimum.compare(maximum).is_gt())
    {
        return Err(Diagnostic::error(
            codes::NODE_SHAPE,
            format!("refine `{name}` has `min=` greater than `max=`"),
        )
        .with_span(span));
    }

    let operational = base.operational_type();
    if unit.is_some() && !matches!(operational, Type::Int | Type::Float) {
        return Err(Diagnostic::error(
            codes::NODE_SHAPE,
            format!("refine `{name}` uses `unit=` with incompatible base {base}"),
        )
        .with_span(span));
    }
    let compatible = match operational {
        Type::Bool | Type::Path => min.is_none() && max.is_none() && format.is_none(),
        Type::Int | Type::Float => format.is_none(),
        Type::String => min.is_none() && max.is_none(),
        Type::List(item) if matches!(item.operational_type(), Type::String) => format.is_none(),
        _ => false,
    };
    if !compatible {
        return Err(Diagnostic::error(
            codes::NODE_SHAPE,
            format!(
                "refine `{name}` base resolved to {base} with incompatible constraints; expected bool, int, float, string, path, or list<string>"
            ),
        )
        .with_span(span));
    }
    Ok(())
}

fn merge_extension(
    modules: &mut BTreeMap<String, ResolvedModule>,
    extension: ExtendModule,
    diagnostics: &mut Diagnostics,
) {
    let Some(module) = modules.get_mut(&extension.module) else {
        diagnostics.error_at_with_help(
            codes::EXTEND_MODULE,
            format!(
                "`extend-module` names unknown module `{}`",
                extension.module
            ),
            extension.span,
            "declare the module before extending it; includes are processed in written order",
        );
        return;
    };
    for input in extension.inputs {
        if let Some(existing) = module.decl.inputs.iter().find(|i| i.name == input.name) {
            diagnostics.push(
                Diagnostic::error(
                    codes::DUPLICATE,
                    format!(
                        "module `{}`: input `{}` is declared twice (module + extension)",
                        extension.module, input.name
                    ),
                )
                .with_span(input.span)
                .with_label("first declared here", existing.span),
            );
            continue;
        }
        module.decl.inputs.push(input);
    }
    for fragment in extension.fragments {
        if let Some(existing) = module
            .decl
            .fragments
            .iter()
            .find(|f| f.name == fragment.name)
        {
            diagnostics.push(
                Diagnostic::error(
                    codes::DUPLICATE,
                    format!(
                        "module `{}`: fragment `{}` is declared twice (module + extension)",
                        extension.module, fragment.name
                    ),
                )
                .with_span(fragment.span)
                .with_label("first declared here", existing.span),
            );
            continue;
        }
        module.decl.fragments.push(fragment);
    }
    module.decl.requires.extend(extension.requires);
    module.extra_outputs.extend(extension.outputs);
}

fn known_names<'a>(kind: &str, names: impl Iterator<Item = &'a str>) -> String {
    let mut sorted: Vec<&str> = names.collect();
    sorted.sort_unstable();
    if sorted.is_empty() {
        format!("no {kind}s are declared")
    } else {
        format!("known {kind}s: {}", sorted.join(", "))
    }
}

fn validate_profile_graph(profiles: &[ProfileDecl], diagnostics: &mut Diagnostics) {
    let by_name: HashMap<&str, &ProfileDecl> =
        profiles.iter().map(|p| (p.name.as_str(), p)).collect();
    for profile in profiles {
        let mut seen = HashSet::new();
        for (parent, span) in &profile.extends {
            if !by_name.contains_key(parent.as_str()) {
                diagnostics.error_at_with_help(
                    codes::UNKNOWN_PROFILE,
                    format!(
                        "profile `{}` extends unknown profile `{parent}`",
                        profile.name
                    ),
                    *span,
                    known_names("profile", by_name.keys().copied()),
                );
            }
            if !seen.insert(parent.as_str()) {
                diagnostics.error_at(
                    codes::DUPLICATE,
                    format!("profile `{}` extends `{parent}` twice", profile.name),
                    *span,
                );
            }
        }
    }
    // Detect cycles iteratively to keep authored graph depth off the stack.
    #[derive(Clone, Copy, PartialEq)]
    enum State {
        Visiting,
        Done,
    }
    struct Frame<'a> {
        name: &'a str,
        next_parent: usize,
    }
    let mut states = HashMap::new();
    for profile in profiles {
        let name = profile.name.as_str();
        if states.contains_key(name) {
            continue;
        }
        states.insert(name, State::Visiting);
        let mut stack = vec![Frame {
            name,
            next_parent: 0,
        }];
        while !stack.is_empty() {
            let next_parent = {
                let frame = stack.last_mut().expect("profile DFS frame");
                let current = by_name
                    .get(frame.name)
                    .expect("profile graph contains active frame");
                let parent = current.extends.get(frame.next_parent);
                frame.next_parent += usize::from(parent.is_some());
                parent.map(|(parent, _)| parent.as_str())
            };
            let Some(parent) = next_parent else {
                let completed = stack.pop().expect("profile DFS frame").name;
                states.insert(completed, State::Done);
                continue;
            };
            if !by_name.contains_key(parent) {
                continue;
            }
            match states.get(parent) {
                Some(State::Done) => {}
                Some(State::Visiting) => {
                    let cycle_start = stack
                        .iter()
                        .position(|frame| frame.name == parent)
                        .unwrap_or(0);
                    let mut chain: Vec<&str> = stack[cycle_start..]
                        .iter()
                        .map(|frame| frame.name)
                        .collect();
                    chain.push(parent);
                    let mut diagnostic = Diagnostic::error(
                        codes::PROFILE_CYCLE,
                        format!("profile inheritance cycle: {}", chain.join(" -> ")),
                    );
                    if let Some(span) = by_name.get(parent).map(|profile| profile.span) {
                        diagnostic = diagnostic.with_span(span);
                    }
                    diagnostics.push(diagnostic);
                }
                None => {
                    states.insert(parent, State::Visiting);
                    stack.push(Frame {
                        name: parent,
                        next_parent: 0,
                    });
                }
            }
        }
    }
}

/// Deterministic linearization: parents in written order, depth-first,
/// each ancestor once, the profile itself last.
pub fn linearize<'a>(workspace: &'a ResolvedWorkspace, name: &str) -> Option<Vec<&'a ProfileDecl>> {
    let by_name: HashMap<&str, &ProfileDecl> = workspace
        .profiles
        .iter()
        .map(|profile| (profile.name.as_str(), profile))
        .collect();
    let root = by_name.get(name).copied()?;
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    let mut stack = vec![(root, false)];
    while let Some((profile, expanded)) = stack.pop() {
        if expanded {
            out.push(profile);
            continue;
        }
        if !seen.insert(profile.name.as_str()) {
            continue;
        }
        stack.push((profile, true));
        for (parent, _) in profile.extends.iter().rev() {
            let Some(parent) = by_name.get(parent.as_str()).copied() else {
                continue;
            };
            if !seen.contains(parent.name.as_str()) {
                stack.push((parent, false));
            }
        }
    }
    Some(out)
}

/// Ancestor sets distinguish descendant overrides from sibling conflicts.
fn ancestors_of(workspace: &ResolvedWorkspace, name: &str) -> HashSet<String> {
    let mut out = HashSet::new();
    let mut stack = vec![name.to_owned()];
    while let Some(current) = stack.pop() {
        if let Some(profile) = workspace.profile(&current) {
            for (parent, _) in &profile.extends {
                if out.insert(parent.clone()) {
                    stack.push(parent.clone());
                }
            }
        }
    }
    out
}

/// A layered value with the profile that set it, for conflict detection.
#[derive(Debug, Clone)]
struct Layered<T> {
    value: T,
    profile: String,
    span: Span,
}

/// One activated module instance after profile folding.
#[derive(Debug)]
pub struct ResolvedInstance {
    pub alias: String,
    pub module: String,
    /// Whole-input writes and patches in linearized profile-layer order.
    pub input_ops: Vec<ResolvedInputOp>,
    /// Fragment operations in application order with their source profiles.
    pub fragment_ops: Vec<(FragmentOp, String)>,
    /// Where the instance was activated.
    pub span: Span,
}

#[derive(Debug)]
pub enum ResolvedInputOp {
    With {
        name: String,
        value: Value,
        span: Span,
        profile: String,
    },
    Patch {
        entry: PatchEntry,
        profile: String,
    },
}

/// The resolved profile: its linearized chain and active instances in
/// activation order.
#[derive(Debug)]
pub struct ResolvedProfile {
    pub name: String,
    pub chain: Vec<String>,
    pub instances: Vec<ResolvedInstance>,
}

struct InstanceState {
    module: String,
    module_span: Span,
    activated_by: String,
    /// Writes from sibling branches remain available for a descendant to resolve.
    with: BTreeMap<String, Vec<Layered<Value>>>,
    input_ops: Vec<ResolvedInputOp>,
    fragment_ops: Vec<(FragmentOp, String)>,
    span: Span,
    active: bool,
    order: usize,
}

/// Folds the linearized profile chain into active instances.
pub fn resolve_profile(
    workspace: &ResolvedWorkspace,
    name: &str,
    diagnostics: &mut Diagnostics,
) -> Option<ResolvedProfile> {
    let chain = linearize(workspace, name)?;
    let mut instances: BTreeMap<String, InstanceState> = BTreeMap::new();
    let mut next_order = 0usize;

    for profile in &chain {
        if profile.items.is_empty() {
            continue;
        }
        let profile_ancestors = ancestors_of(workspace, &profile.name);
        for item in &profile.items {
            match item {
                ProfileItem::Use(use_decl) => {
                    let alias = use_decl
                        .alias
                        .clone()
                        .unwrap_or_else(|| use_decl.module.clone());
                    if !workspace.modules.contains_key(&use_decl.module) {
                        diagnostics.error_at_with_help(
                            codes::UNKNOWN_MODULE,
                            format!(
                                "profile `{}` uses unknown module `{}`",
                                profile.name, use_decl.module
                            ),
                            use_decl.span,
                            known_names("module", workspace.modules.keys().map(String::as_str)),
                        );
                        continue;
                    }
                    apply_instance_layer(
                        &mut instances,
                        &mut next_order,
                        InstanceLayer {
                            alias,
                            module: &use_decl.module,
                            span: use_decl.span,
                            config: &use_decl.config,
                            profile,
                            profile_ancestors: &profile_ancestors,
                        },
                        diagnostics,
                    );
                }
                ProfileItem::Replace(replace) => {
                    let Some(module) = workspace.modules.get(&replace.module) else {
                        diagnostics.error_at(
                            codes::UNKNOWN_MODULE,
                            format!(
                                "profile `{}` replaces slot `{}` with unknown module `{}`",
                                profile.name, replace.slot, replace.module
                            ),
                            replace.span,
                        );
                        continue;
                    };
                    if module.decl.slot.as_deref() != Some(replace.slot.as_str()) {
                        diagnostics.error_at(
                            codes::SLOT,
                            format!(
                                "module `{}` does not fill slot `{}` (it fills {})",
                                replace.module,
                                replace.slot,
                                module
                                    .decl
                                    .slot
                                    .as_deref()
                                    .map(|s| format!("slot `{s}`"))
                                    .unwrap_or_else(|| "no slot".to_owned())
                            ),
                            replace.span,
                        );
                        continue;
                    }
                    if let Some(slot_def) = workspace.slots.get(&replace.slot)
                        && !matches!(slot_def.max, SlotMax::Max(1))
                    {
                        diagnostics.error_at(codes::SLOT,
                                format!(
                                    "`replace` targets slot `{}` with max {}; replace is for single-provider slots — use `use` for multi-provider slots",
                                    replace.slot,
                                    slot_def.max.label()
                                ), replace.span);
                        continue;
                    }
                    // Replacement deactivates every current provider of the slot.
                    let mut displaced = 0usize;
                    for state in instances.values_mut() {
                        if !state.active {
                            continue;
                        }
                        let provider_slot = workspace
                            .modules
                            .get(&state.module)
                            .and_then(|m| m.decl.slot.as_deref());
                        if provider_slot == Some(replace.slot.as_str()) {
                            state.active = false;
                            displaced += 1;
                        }
                    }
                    if displaced == 0 {
                        diagnostics.error_at(codes::SLOT,
                                format!(
                                    "profile `{}`: `replace slot=\"{}\"` matched no active provider in the profile chain; use `use` to fill an empty slot",
                                    profile.name, replace.slot
                                ), replace.span);
                        continue;
                    }
                    let alias = replace
                        .alias
                        .clone()
                        .unwrap_or_else(|| replace.module.clone());
                    apply_instance_layer(
                        &mut instances,
                        &mut next_order,
                        InstanceLayer {
                            alias,
                            module: &replace.module,
                            span: replace.span,
                            config: &replace.config,
                            profile,
                            profile_ancestors: &profile_ancestors,
                        },
                        diagnostics,
                    );
                }
            }
        }
    }

    // Report writes from sibling branches that no descendant resolved.
    for (alias, state) in &instances {
        if !state.active {
            continue;
        }
        for (input, layers) in &state.with {
            let input_type = workspace
                .modules
                .get(&state.module)
                .and_then(|module| module.input(input))
                .map(|input| &input.ty);
            let mut normalized = layers.iter().filter_map(|layer| {
                crate::lang::typecheck::coerce(
                    layer.value.clone(),
                    input_type?,
                    layer.span,
                    "sibling profile input",
                )
                .ok()
                .map(|value| (layer, value))
            });
            let Some((first, first_value)) = normalized.next() else {
                continue;
            };
            if let Some((other, _)) =
                normalized.find(|(_, other_value)| !other_value.semantic_eq(&first_value))
            {
                diagnostics.push(
                    Diagnostic::error(
                        codes::SIBLING_CONFLICT,
                        format!(
                            "profile `{name}`: input `{alias}.{input}` is set to different values by sibling parents `{}` and `{}`",
                            first.profile, other.profile
                        ),
                    )
                    .with_span(first.span)
                    .with_label("also set here", other.span)
                    .with_help(format!(
                        "set `{input}` in profile `{name}` (or a shared descendant) to resolve the conflict"
                    )),
                );
            }
        }
    }

    // Enforce slot cardinality against the final active set.
    let mut by_slot: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for (alias, state) in &instances {
        if !state.active {
            continue;
        }
        if let Some(slot) = workspace
            .modules
            .get(&state.module)
            .and_then(|m| m.decl.slot.as_deref())
        {
            by_slot.entry(slot).or_default().push(alias.as_str());
        }
    }
    for (slot, providers) in by_slot {
        let max = workspace
            .slots
            .get(slot)
            .map_or(SlotMax::Max(1), |def| def.max);
        if !max.permits(providers.len()) {
            diagnostics.error(
                codes::SLOT,
                format!(
                    "profile `{name}` activates {} providers for slot `{slot}` (max {}): {}",
                    providers.len(),
                    max.label(),
                    providers.join(", ")
                ),
            );
        }
    }

    let mut ordered: Vec<(String, InstanceState)> = instances.into_iter().collect();
    ordered.sort_by_key(|(_, state)| state.order);

    Some(ResolvedProfile {
        name: name.to_owned(),
        chain: chain.iter().map(|p| p.name.clone()).collect(),
        instances: ordered
            .into_iter()
            .filter(|(_, state)| state.active)
            .map(|(alias, state)| ResolvedInstance {
                alias,
                module: state.module,
                input_ops: state.input_ops,
                fragment_ops: state.fragment_ops,
                span: state.span,
            })
            .collect(),
    })
}

/// One `use`/`replace` layer being folded onto an instance: which alias of
/// which module it activates, and the per-instance configuration the
/// declaring profile contributes.
struct InstanceLayer<'a> {
    alias: String,
    module: &'a str,
    span: Span,
    config: &'a InstanceConfig,
    profile: &'a ProfileDecl,
    profile_ancestors: &'a HashSet<String>,
}

fn apply_instance_layer(
    instances: &mut BTreeMap<String, InstanceState>,
    next_order: &mut usize,
    layer: InstanceLayer<'_>,
    diagnostics: &mut Diagnostics,
) {
    let InstanceLayer {
        alias,
        module,
        span,
        config,
        profile,
        profile_ancestors,
    } = layer;
    let state = instances.entry(alias.clone()).or_insert_with(|| {
        let order = *next_order;
        *next_order += 1;
        InstanceState {
            module: module.to_owned(),
            module_span: span,
            activated_by: profile.name.clone(),
            with: BTreeMap::new(),
            input_ops: Vec::new(),
            fragment_ops: Vec::new(),
            span,
            active: true,
            order,
        }
    });
    if state.module != module {
        diagnostics.push(
            Diagnostic::error(
                codes::ALIAS_CONFLICT,
                format!(
                    "alias `{alias}` is used for two different modules: `{}` (in profile `{}`) and `{module}` (in profile `{}`)",
                    state.module, state.activated_by, profile.name
                ),
            )
            .with_span(span)
            .with_label("first used here", state.module_span),
        );
        return;
    }
    // A later `use` may reactivate an instance displaced by `replace`, while
    // preserving configuration accumulated before displacement.
    state.active = true;

    for entry in &config.with {
        let layers = state.with.entry(entry.name.clone()).or_default();
        layers.retain(|existing| {
            existing.profile != profile.name && !profile_ancestors.contains(&existing.profile)
        });
        layers.push(Layered {
            value: entry.value.clone(),
            profile: profile.name.clone(),
            span: entry.span,
        });
        state.input_ops.push(ResolvedInputOp::With {
            name: entry.name.clone(),
            value: entry.value.clone(),
            span: entry.span,
            profile: profile.name.clone(),
        });
    }
    for op in &config.fragments {
        state.fragment_ops.push((op.clone(), profile.name.clone()));
    }
    for entry in &config.patch_entries {
        state.input_ops.push(ResolvedInputOp::Patch {
            entry: entry.clone(),
            profile: profile.name.clone(),
        });
    }
}
