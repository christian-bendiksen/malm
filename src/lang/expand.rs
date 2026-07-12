//! Expands module outputs into files, symlinks, and validated KDL artifacts.

use crate::lang::artifact::Artifact;
use crate::lang::ast::{
    ConflictPolicy, FragmentCardinality, KdlConfigBody, KdlDialect, MissingSourcePolicy,
    OutputNode, Predicate,
};
use crate::lang::budget::Budget;
use crate::lang::diag::{Diagnostic, Diagnostics, Span, codes};
use crate::lang::resolve::{ResolvedModule, ResolvedWorkspace};
use crate::lang::scope::Scope;
use crate::lang::typecheck::{TypedInstance, resolve_source, split_else};
use crate::lang::value::Value;
use kdl::{KdlDocument, KdlEntry, KdlNode};
use std::io::Read;
use std::path::PathBuf;

/// Non-artifact outputs that reference existing files.
#[derive(Debug)]
pub struct FileOut {
    pub source: PathBuf,
    pub source_label: String,
    pub to: String,
    pub optional: bool,
    pub on_conflict: ConflictPolicy,
    pub instance: String,
    pub span: Span,
}

#[derive(Debug)]
pub struct DirOut {
    pub source: PathBuf,
    pub source_label: String,
    pub to: Option<String>,
    pub optional: bool,
    pub on_conflict: ConflictPolicy,
    pub ignore: Vec<String>,
    #[allow(dead_code)]
    pub instance: String,
}

#[derive(Debug)]
pub struct SymlinkOut {
    pub source: String,
    pub to: String,
    pub optional: bool,
    pub if_missing: MissingSourcePolicy,
    pub instance: String,
    pub span: Span,
}

/// Outputs produced by one compilation.
#[derive(Debug, Default)]
pub struct GeneratedArtifacts {
    pub artifacts: Vec<Artifact>,
    pub files: Vec<FileOut>,
    pub dirs: Vec<DirOut>,
    pub symlinks: Vec<SymlinkOut>,
}

pub struct Expander<'a> {
    pub workspace: &'a ResolvedWorkspace,
    pub budget: &'a mut Budget,
    pub diagnostics: &'a mut Diagnostics,
    pub restrict_source_root: bool,
}

struct KdlExpansion<'a> {
    module: &'a ResolvedModule,
    instance: &'a TypedInstance,
    span: Span,
    stack: Vec<String>,
}

impl Expander<'_> {
    /// Expand one module instance into generated outputs.
    pub fn expand_instance(
        &mut self,
        module: &ResolvedModule,
        instance: &TypedInstance,
        scope: &mut Scope,
        out: &mut GeneratedArtifacts,
    ) {
        for output in module.outputs() {
            if self.budget.exhausted() {
                return;
            }
            self.expand_output(module, instance, scope, output, 0, out);
        }
    }

    fn budget_check(
        &mut self,
        result: Result<(), crate::lang::budget::BudgetError>,
        span: Span,
    ) -> bool {
        match result {
            Ok(()) => true,
            Err(error) => {
                self.diagnostics
                    .push(error.into_diagnostic().with_span(span));
                false
            }
        }
    }

    /// Evaluate a predicate after type-checking has verified its operands.
    fn eval_predicate(&mut self, scope: &Scope, predicate: &Predicate) -> Option<bool> {
        let reference = predicate.reference();
        let Some(value) = scope.lookup(&reference.name) else {
            self.diagnostics.push(
                Diagnostic::error(
                    codes::UNDEFINED_REF,
                    format!("`{}` is not defined", reference.name),
                )
                .with_span(reference.span),
            );
            return None;
        };
        match (predicate, value) {
            (Predicate::Test(_), Value::Bool(b)) => Some(*b),
            (Predicate::Set(_), value) => Some(!value.is_null()),
            (Predicate::NonEmpty(_), Value::List(items)) => Some(!items.is_empty()),
            (Predicate::NonEmpty(_), Value::Collection(collection)) => Some(!collection.is_empty()),
            (
                Predicate::Eq {
                    expected, negated, ..
                },
                value,
            ) if std::mem::discriminant(value) == std::mem::discriminant(expected) => {
                Some((value == expected) != *negated)
            }
            (predicate, value) => {
                self.diagnostics.push(
                    Diagnostic::error(
                        codes::WHEN_PREDICATE,
                        format!(
                            "`{}` cannot evaluate a {} value",
                            predicate.label(),
                            value.type_label()
                        ),
                    )
                    .with_span(reference.span),
                );
                None
            }
        }
    }

    fn expand_output(
        &mut self,
        module: &ResolvedModule,
        instance: &TypedInstance,
        scope: &mut Scope,
        output: &OutputNode,
        depth: usize,
        out: &mut GeneratedArtifacts,
    ) {
        if self.budget.exhausted() {
            return;
        }
        match output {
            OutputNode::When(when) => {
                let check = self.budget.check_nesting(depth + 1);
                if !self.budget_check(check, when.span) {
                    return;
                }
                let Some(truth) = self.eval_predicate(scope, &when.predicate) else {
                    return;
                };
                let branch = if truth { &when.then } else { &when.otherwise };
                for child in branch {
                    self.expand_output(module, instance, scope, child, depth + 1, out);
                }
            }
            OutputNode::KdlConfig(config) => {
                let KdlConfigBody::Document { nodes, span, .. } = &config.body;
                let mut expansion = KdlExpansion {
                    module,
                    instance,
                    span: *span,
                    stack: Vec::new(),
                };
                let content =
                    self.generate_kdl_document(&mut expansion, scope, nodes, config.dialect, depth);
                let Some(content) = content else {
                    return;
                };
                let mut validators = vec![format!("kdl-{}", config.dialect.label())];
                if let Some(validate) = &config.validate
                    && !validators.contains(validate)
                {
                    validators.push(validate.clone());
                }
                out.artifacts.push(Artifact {
                    to: config.to.clone(),
                    content,
                    executable: false,
                    validators,
                    instance: instance.alias.clone(),
                    module: module.decl.name.clone(),
                    span: config.span,
                });
            }
            OutputNode::ConfigFile(config_file) => {
                let Some((content, validator)) = crate::lang::config_file::render(
                    &config_file.body,
                    scope,
                    self.budget,
                    self.diagnostics,
                ) else {
                    return;
                };
                let mut validators = vec![validator.to_owned()];
                if let Some(validate) = &config_file.validate
                    && !validators.contains(validate)
                {
                    validators.push(validate.clone());
                }
                out.artifacts.push(Artifact {
                    to: config_file.to.clone(),
                    content,
                    executable: false,
                    validators,
                    instance: instance.alias.clone(),
                    module: module.decl.name.clone(),
                    span: config_file.span,
                });
            }
            OutputNode::Render(render) => {
                let to = match &render.to {
                    crate::lang::render::PathExpr::Literal(path) => path.clone(),
                    crate::lang::render::PathExpr::FString { raw, span } => {
                        let lookup = |name: &str| scope.lookup(name).cloned();
                        match crate::lang::text::render_template_with(
                            raw,
                            crate::lang::text::TemplateSyntax::V3,
                            &lookup,
                        ) {
                            Ok(path) if !path.is_empty() && !path.chars().any(char::is_control) => {
                                path
                            }
                            Ok(_) => {
                                self.diagnostics.push(
                                    Diagnostic::error(
                                        codes::OUTPUT_PATH,
                                        "interpolated render path is empty or contains control characters",
                                    )
                                    .with_span(*span),
                                );
                                return;
                            }
                            Err(message) => {
                                self.diagnostics.push(
                                    Diagnostic::error(codes::TEMPLATE, message).with_span(*span),
                                );
                                return;
                            }
                        }
                    }
                };
                let (file_requests, fragment_requests) =
                    crate::lang::render::collect_resources(&render.body.items);
                let mut resources = crate::lang::render::RenderResources::default();
                for (path, span) in file_requests {
                    let resolved =
                        match resolve_source(&path, &render.dir, &self.workspace.source_root) {
                            Ok(resolved) => resolved,
                            Err(message) => {
                                self.diagnostics.push(
                                    Diagnostic::error(codes::OUTPUT_PATH, message).with_span(span),
                                );
                                return;
                            }
                        };
                    let Some(text) = self.read_render_file(&resolved, span) else {
                        return;
                    };
                    resources.files.insert(path, text);
                }
                for (fragment, span) in fragment_requests {
                    let Some((composed, _format)) =
                        self.compose_fragment(module, instance, &fragment, span)
                    else {
                        return;
                    };
                    resources.fragments.insert(fragment, composed);
                }
                let Some((content, validator)) = crate::lang::render::render_output(
                    &render.body,
                    scope,
                    self.budget,
                    self.diagnostics,
                    &resources,
                ) else {
                    return;
                };
                let mut validators = vec![validator.to_owned()];
                if let Some(validate) = &render.validate
                    && !validators.contains(validate)
                {
                    validators.push(validate.clone());
                }
                out.artifacts.push(Artifact {
                    to,
                    content,
                    executable: render.executable,
                    validators,
                    instance: instance.alias.clone(),
                    module: module.decl.name.clone(),
                    span: render.span,
                });
            }
            OutputNode::Each(each) => {
                let check = self.budget.check_nesting(depth + 1);
                if !self.budget_check(check, each.span) {
                    return;
                }
                let Some(items) = self.loop_items(scope, &each.source.name, each.span) else {
                    return;
                };
                let iter_budget = self.budget.count_iterations(items.len() as u64);
                if !self.budget_check(iter_budget, each.span) {
                    return;
                }
                for (key, item) in items {
                    let keyed = key.is_some();
                    if let Some(key) = key {
                        scope.push_binding(format!("{}.key", each.binding), Value::String(key));
                    }
                    scope.push_binding(&each.binding, item);
                    for child in &each.body {
                        self.expand_output(module, instance, scope, child, depth + 1, out);
                    }
                    scope.pop_binding();
                    if keyed {
                        scope.pop_binding();
                    }
                    if self.budget.exhausted() {
                        return;
                    }
                }
            }
            OutputNode::Range(range) => {
                let count = range
                    .through
                    .checked_sub(range.from)
                    .and_then(|value| value.checked_add(1));
                let Some(count) = count.filter(|value| *value > 0) else {
                    return;
                };
                let checks = self
                    .budget
                    .check_nesting(depth + 1)
                    .and_then(|_| self.budget.check_range(count))
                    .and_then(|_| self.budget.count_iterations(count as u64));
                if !self.budget_check(checks, range.span) {
                    return;
                }
                for number in range.from..=range.through {
                    scope.push_binding(&range.binding, Value::Int(number));
                    for child in &range.body {
                        self.expand_output(module, instance, scope, child, depth + 1, out);
                    }
                    scope.pop_binding();
                    if self.budget.exhausted() {
                        return;
                    }
                }
            }
            OutputNode::File(file) => {
                let source =
                    match resolve_source(&file.source, &file.dir, &self.workspace.source_root) {
                        Ok(path) => path,
                        Err(message) => {
                            self.diagnostics.push(
                                Diagnostic::error(codes::OUTPUT_PATH, message).with_span(file.span),
                            );
                            return;
                        }
                    };
                out.files.push(FileOut {
                    source,
                    source_label: file.source.clone(),
                    to: file.to.clone(),
                    optional: file.optional,
                    on_conflict: file.on_conflict,
                    instance: instance.alias.clone(),
                    span: file.span,
                });
            }
            OutputNode::Dir(dir) => {
                let source =
                    match resolve_source(&dir.source, &dir.dir, &self.workspace.source_root) {
                        Ok(path) => path,
                        Err(message) => {
                            self.diagnostics.push(
                                Diagnostic::error(codes::OUTPUT_PATH, message).with_span(dir.span),
                            );
                            return;
                        }
                    };
                out.dirs.push(DirOut {
                    source,
                    source_label: dir.source.clone(),
                    to: dir.to.clone(),
                    optional: dir.optional,
                    on_conflict: dir.on_conflict,
                    ignore: dir.ignore.clone(),
                    instance: instance.alias.clone(),
                });
            }
            OutputNode::Symlink(symlink) => {
                let source = match &symlink.source {
                    crate::lang::ast::SymlinkSource::Literal(path) => path.clone(),
                    crate::lang::ast::SymlinkSource::Ref(reference) => {
                        match scope.lookup(&reference.name) {
                            Some(Value::Path(path)) => path.clone(),
                            Some(Value::String(path)) => path.clone(),
                            Some(Value::Null) => return, // cleared optional: no link
                            Some(other) => {
                                self.diagnostics.push(
                                    Diagnostic::error(
                                        codes::TYPE_MISMATCH,
                                        format!(
                                            "symlink `source=` requires a path, found {}",
                                            other.type_label()
                                        ),
                                    )
                                    .with_span(reference.span),
                                );
                                return;
                            }
                            None => {
                                self.diagnostics.push(
                                    Diagnostic::error(
                                        codes::UNDEFINED_REF,
                                        format!("`{}` is not defined", reference.name),
                                    )
                                    .with_span(reference.span),
                                );
                                return;
                            }
                        }
                    }
                };
                out.symlinks.push(SymlinkOut {
                    source,
                    to: symlink.to.clone(),
                    optional: symlink.optional,
                    if_missing: symlink.if_missing,
                    instance: instance.alias.clone(),
                    span: symlink.span,
                });
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn read_render_file(&mut self, path: &std::path::Path, span: Span) -> Option<String> {
        if self.restrict_source_root
            && crate::policy::source_escapes_source_root(path, &self.workspace.source_root)
        {
            self.diagnostics.push(
                Diagnostic::error(
                    codes::OUTPUT_PATH,
                    format!("render source escapes repository root: {}", path.display()),
                )
                .with_span(span),
            );
            return None;
        }
        let allowance = match self.budget.begin_render_file() {
            Ok(allowance) => allowance,
            Err(error) => {
                self.diagnostics
                    .push(error.into_diagnostic().with_span(span));
                return None;
            }
        };
        let mut file = match std::fs::File::open(path) {
            Ok(file) => file,
            Err(error) => {
                self.diagnostics.push(
                    Diagnostic::error(codes::EMIT, format!("read {}: {error}", path.display()))
                        .with_span(span),
                );
                return None;
            }
        };
        if file
            .metadata()
            .ok()
            .is_some_and(|meta| meta.len() > allowance)
        {
            let check = self.budget.count_render_bytes(allowance.saturating_add(1));
            let _ = self.budget_check(check, span);
            return None;
        }
        let mut bytes = Vec::new();
        if let Err(error) = file
            .by_ref()
            .take(allowance.saturating_add(1))
            .read_to_end(&mut bytes)
        {
            self.diagnostics.push(
                Diagnostic::error(codes::EMIT, format!("read {}: {error}", path.display()))
                    .with_span(span),
            );
            return None;
        }
        let check = self.budget.count_render_bytes(bytes.len() as u64);
        if !self.budget_check(check, span) {
            return None;
        }
        match String::from_utf8(bytes) {
            Ok(text) => Some(text),
            Err(_) => {
                self.diagnostics.push(
                    Diagnostic::error(
                        codes::EMIT,
                        format!("{} is not valid UTF-8", path.display()),
                    )
                    .with_span(span),
                );
                None
            }
        }
    }

    /// Items of a loop source: list items (no key), or keyed-collection
    /// payloads in declared order (each carrying its key for `<binding>.key`).
    fn loop_items(
        &mut self,
        scope: &Scope,
        name: &str,
        span: Span,
    ) -> Option<Vec<(Option<String>, Value)>> {
        let value = scope.lookup(name)?.clone();
        match value {
            Value::List(items) => {
                let check = self.budget.check_collection_size(items.len());
                if !self.budget_check(check, span) {
                    return None;
                }
                Some(items.into_iter().map(|item| (None, item)).collect())
            }
            Value::Collection(collection) => {
                let check = self.budget.check_collection_size(collection.len());
                if !self.budget_check(check, span) {
                    return None;
                }
                Some(
                    collection
                        .items
                        .into_iter()
                        .map(|item| (Some(item.key), item.value))
                        .collect(),
                )
            }
            other => {
                self.diagnostics.push(
                    Diagnostic::error(
                        codes::LOOP_SOURCE,
                        format!(
                            "`each` requires a list or collection, found {}",
                            other.type_label()
                        ),
                    )
                    .with_span(span),
                );
                None
            }
        }
    }

    /// Compose a fragment slot: read every source in order and concatenate.
    /// KDL formats validate each piece before composition so a broken
    /// profile fragment is reported at its own path.
    fn compose_fragment(
        &mut self,
        module: &ResolvedModule,
        instance: &TypedInstance,
        fragment_name: &str,
        span: Span,
    ) -> Option<(String, String)> {
        let Some(fragment) = module.fragment(fragment_name) else {
            self.diagnostics.push(
                Diagnostic::error(
                    codes::FRAGMENT,
                    format!(
                        "module `{}` declares no fragment `{fragment_name}`",
                        module.decl.name
                    ),
                )
                .with_span(span),
            );
            return None;
        };
        let sources = instance
            .fragment_sources
            .get(fragment_name)
            .cloned()
            .unwrap_or_else(|| fragment.defaults.clone());
        if sources.is_empty() && fragment.cardinality == FragmentCardinality::One {
            self.diagnostics.push(
                Diagnostic::error(
                    codes::FRAGMENT,
                    format!(
                        "fragment `{fragment_name}` has no source: it declares no default and no profile supplied one"
                    ),
                )
                .with_span(span),
            );
            return None;
        }
        let mut composed = String::new();
        for source in &sources {
            if self.budget.exhausted() {
                return None;
            }
            let resolved =
                match resolve_source(&source.path, &source.base_dir, &self.workspace.source_root) {
                    Ok(path) => path,
                    Err(message) => {
                        self.diagnostics.push(
                            Diagnostic::error(codes::OUTPUT_PATH, message).with_span(source.span),
                        );
                        continue;
                    }
                };
            let Some(text) = self.read_render_file(&resolved, source.span) else {
                continue;
            };
            for problem in crate::lang::artifact::validate_format(&fragment.format, &text) {
                self.diagnostics.push(
                    Diagnostic::error(
                        codes::FRAGMENT,
                        format!(
                            "fragment `{fragment_name}` source {}: {problem}",
                            resolved.display()
                        ),
                    )
                    .with_span(source.span),
                );
            }
            let separator = usize::from(!composed.is_empty() && !composed.ends_with('\n'));
            let Some(new_len) = composed
                .len()
                .checked_add(separator)
                .and_then(|len| len.checked_add(text.len()))
            else {
                let check = self.budget.check_artifact_size(u64::MAX);
                let _ = self.budget_check(check, source.span);
                return None;
            };
            let check = self.budget.check_artifact_size(new_len as u64);
            if !self.budget_check(check, source.span) {
                return None;
            }
            if separator != 0 {
                composed.push('\n');
            }
            composed.push_str(&text);
        }
        Some((composed, fragment.format.clone()))
    }

    // KDL generation

    /// Expand inline target nodes into serialized KDL under the selected
    /// version.
    fn generate_kdl_document(
        &mut self,
        expansion: &mut KdlExpansion<'_>,
        scope: &mut Scope,
        nodes: &[KdlNode],
        dialect: KdlDialect,
        depth: usize,
    ) -> Option<String> {
        let mut generated = Vec::new();
        self.expand_kdl_nodes(expansion, scope, nodes, depth, &mut generated)?;
        let mut document = KdlDocument::new();
        for node in generated {
            document.nodes_mut().push(node);
        }
        document.autoformat();
        match dialect {
            KdlDialect::V1 => document.ensure_v1(),
            KdlDialect::V2 => document.ensure_v2(),
        }
        let ops = self.budget.count_operations(1);
        if !self.budget_check(ops, expansion.span) {
            return None;
        }
        let content = document.to_string();
        let check = self
            .budget
            .count_artifact_bytes(content.len() as u64, content.len() as u64);
        self.budget_check(check, expansion.span).then_some(content)
    }

    /// Expand raw nodes: controls are consumed, ordinary nodes emitted with
    /// refs and interpolations resolved. Node and child order preserved.
    fn expand_kdl_nodes(
        &mut self,
        expansion: &mut KdlExpansion<'_>,
        scope: &mut Scope,
        nodes: &[KdlNode],
        depth: usize,
        out: &mut Vec<KdlNode>,
    ) -> Option<()> {
        for node in nodes {
            if self.budget.exhausted() {
                return None;
            }
            let ops = self.budget.count_operations(1);
            if !self.budget_check(ops, expansion.span) {
                return None;
            }
            match crate::lang::kdl_util::kdl_control_alias(node.name().value()) {
                "when" | "when-set" | "when-nonempty" => {
                    let check = self.budget.check_nesting(depth + 1);
                    if !self.budget_check(check, expansion.span) {
                        return None;
                    }
                    let predicate = self.raw_when_predicate(node, expansion.span)?;
                    let truth = self.eval_predicate(scope, &predicate)?;
                    let (then_nodes, else_nodes) = split_else(node, self.diagnostics)?;
                    let branch = if truth { then_nodes } else { else_nodes };
                    self.expand_kdl_nodes(expansion, scope, &branch, depth + 1, out)?;
                }
                "each" => {
                    let check = self.budget.check_nesting(depth + 1);
                    if !self.budget_check(check, expansion.span) {
                        return None;
                    }
                    let binding = node
                        .get(0)
                        .and_then(kdl::KdlValue::as_string)
                        .map(str::to_owned)?;
                    let source_name = node
                        .iter()
                        .find(|e| e.name().is_some_and(|n| n.value() == "in"))
                        .and_then(|e| e.value().as_string())
                        .map(str::to_owned)?;
                    let items = self.loop_items(scope, &source_name, expansion.span)?;
                    let iter_budget = self.budget.count_iterations(items.len() as u64);
                    if !self.budget_check(iter_budget, expansion.span) {
                        return None;
                    }
                    let body: Vec<KdlNode> = node
                        .children()
                        .map(|c| c.nodes().to_vec())
                        .unwrap_or_default();
                    for (key, item) in items {
                        let keyed = key.is_some();
                        if let Some(key) = key {
                            scope.push_binding(format!("{binding}.key"), Value::String(key));
                        }
                        scope.push_binding(&binding, item);
                        let result = self.expand_kdl_nodes(expansion, scope, &body, depth + 1, out);
                        scope.pop_binding();
                        if keyed {
                            scope.pop_binding();
                        }
                        result?;
                    }
                }
                "range" => {
                    let check = self.budget.check_nesting(depth + 1);
                    if !self.budget_check(check, expansion.span) {
                        return None;
                    }
                    let binding = node
                        .get(0)
                        .and_then(kdl::KdlValue::as_string)
                        .map(str::to_owned)?;
                    let from = node
                        .get("from")
                        .and_then(kdl::KdlValue::as_integer)
                        .and_then(|value| i64::try_from(value).ok());
                    let through = node
                        .get("through")
                        .and_then(kdl::KdlValue::as_integer)
                        .and_then(|value| i64::try_from(value).ok());
                    let (Some(from), Some(through)) = (from, through) else {
                        self.diagnostics.push(
                            Diagnostic::error(
                                codes::NODE_SHAPE,
                                "`range` bounds must fit in 64-bit integers",
                            )
                            .with_span(expansion.span),
                        );
                        return None;
                    };
                    let iterations = range_iterations(from, through)?;
                    let range_check = self.budget.check_range(iterations);
                    if !self.budget_check(range_check, expansion.span) {
                        return None;
                    }
                    let iter_budget = self.budget.count_iterations(iterations as u64);
                    if !self.budget_check(iter_budget, expansion.span) {
                        return None;
                    }
                    let body: Vec<KdlNode> = node
                        .children()
                        .map(|c| c.nodes().to_vec())
                        .unwrap_or_default();
                    for n in from..=through {
                        scope.push_binding(&binding, Value::Int(n));
                        let result = self.expand_kdl_nodes(expansion, scope, &body, depth + 1, out);
                        scope.pop_binding();
                        result?;
                    }
                }
                "splice" => {
                    let check = self.budget.check_nesting(depth + 1);
                    if !self.budget_check(check, expansion.span) {
                        return None;
                    }
                    let collection_name = node
                        .get(0)
                        .and_then(kdl::KdlValue::as_string)
                        .map(str::to_owned)?;
                    let Some(Value::Collection(collection)) =
                        scope.lookup(&collection_name).cloned()
                    else {
                        self.diagnostics.push(
                            Diagnostic::error(
                                codes::TYPE_MISMATCH,
                                format!("`{collection_name}` is not a collection"),
                            )
                            .with_span(expansion.span),
                        );
                        continue;
                    };
                    let stack_name = format!("collection:{collection_name}");
                    if let Some(start) = expansion.stack.iter().position(|name| name == &stack_name)
                    {
                        let mut cycle = expansion.stack[start..].to_vec();
                        cycle.push(stack_name);
                        self.diagnostics.push(
                            Diagnostic::error(
                                codes::KDL_GEN,
                                format!("splice cycle detected: {}", cycle.join(" -> ")),
                            )
                            .with_span(expansion.span),
                        );
                        return None;
                    }
                    let check = self.budget.check_collection_size(collection.items.len());
                    if !self.budget_check(check, expansion.span) {
                        return None;
                    }
                    let ops = self.budget.count_operations(collection.items.len() as u64);
                    if !self.budget_check(ops, expansion.span) {
                        return None;
                    }
                    expansion.stack.push(stack_name);
                    for item in &collection.items {
                        if let Value::KdlDocument(doc) = &item.value {
                            // Spliced documents may themselves carry refs /
                            // interpolations; expand them like inline nodes.
                            self.expand_kdl_nodes(expansion, scope, doc.nodes(), depth + 1, out)?;
                        }
                    }
                    expansion.stack.pop();
                }
                "compose" => {
                    let check = self.budget.check_nesting(depth + 1);
                    if !self.budget_check(check, expansion.span) {
                        return None;
                    }
                    let fragment_name = node
                        .get("fragment")
                        .and_then(kdl::KdlValue::as_string)
                        .map(str::to_owned)?;
                    let stack_name = format!("fragment:{fragment_name}");
                    if let Some(start) = expansion.stack.iter().position(|name| name == &stack_name)
                    {
                        let mut cycle = expansion.stack[start..].to_vec();
                        cycle.push(stack_name);
                        self.diagnostics.push(
                            Diagnostic::error(
                                codes::KDL_GEN,
                                format!("KDL expansion cycle detected: {}", cycle.join(" -> ")),
                            )
                            .with_span(expansion.span),
                        );
                        return None;
                    }
                    let included = self.load_kdl_fragment(
                        expansion.module,
                        expansion.instance,
                        &fragment_name,
                        expansion.span,
                    )?;
                    expansion.stack.push(stack_name);
                    self.expand_kdl_nodes(expansion, scope, included.nodes(), depth + 1, out)?;
                    expansion.stack.pop();
                }
                "else" => {
                    self.diagnostics.push(
                        Diagnostic::error(
                            codes::NODE_SHAPE,
                            format!("`{}` is not valid here", node.name().value()),
                        )
                        .with_span(expansion.span),
                    );
                }
                _ => {
                    let expanded = self.expand_plain_node(expansion, scope, node, depth)?;
                    let nodes_budget = self.budget.count_generated_nodes(1);
                    if !self.budget_check(nodes_budget, expansion.span) {
                        return None;
                    }
                    out.push(expanded);
                }
            }
        }
        Some(())
    }

    /// Expand one ordinary target node: resolve `(ref)` entries to
    /// typed scalars, interpolate composite strings, recurse into children.
    fn expand_plain_node(
        &mut self,
        expansion: &mut KdlExpansion<'_>,
        scope: &mut Scope,
        node: &KdlNode,
        depth: usize,
    ) -> Option<KdlNode> {
        let escaped_name = (node.name().value() == "node")
            .then(|| node.get(0).and_then(kdl::KdlValue::as_string))
            .flatten();
        let mut generated = node.clone();
        if let Some(name) = escaped_name {
            generated.set_name(name.to_owned());
        }
        generated.entries_mut().clear();
        for (index, entry) in node.iter().enumerate() {
            if escaped_name.is_some() && index == 0 {
                continue;
            }
            let value = if crate::lang::kdl_util::is_ref(entry) {
                let name = entry.value().as_string().unwrap_or_default();
                let Some(value) = scope.lookup(name).cloned() else {
                    self.diagnostics.push(
                        Diagnostic::error(codes::UNDEFINED_REF, format!("`{name}` is not defined"))
                            .with_span(expansion.span),
                    );
                    return None;
                };
                match value_to_kdl(&value) {
                    Ok(kdl_value) => kdl_value,
                    Err(message) => {
                        self.diagnostics.push(
                            Diagnostic::error(codes::TYPE_MISMATCH, format!("`{name}`: {message}"))
                                .with_span(expansion.span),
                        );
                        return None;
                    }
                }
            } else if let kdl::KdlValue::String(s) = entry.value() {
                // Composite strings may use scalar interpolation before
                // KDL serialization.
                if s.contains("{{") {
                    match crate::lang::text::render_template_with_v3(s, &|name| {
                        scope.lookup(name).cloned()
                    }) {
                        Ok(rendered) => kdl::KdlValue::String(rendered),
                        Err(message) => {
                            self.diagnostics.push(
                                Diagnostic::error(codes::TEMPLATE, message)
                                    .with_span(expansion.span),
                            );
                            return None;
                        }
                    }
                } else {
                    entry.value().clone()
                }
            } else {
                entry.value().clone()
            };
            let mut generated_entry = if crate::lang::kdl_util::is_ref(entry) {
                match entry.name() {
                    Some(prop) => KdlEntry::new_prop(prop.clone(), value),
                    None => KdlEntry::new(value),
                }
            } else {
                let mut cloned = entry.clone();
                cloned.set_value(value);
                cloned
            };
            generated_entry.set_span(entry.span());
            generated.entries_mut().push(generated_entry);
        }
        if let Some(children) = node.children() {
            let mut expanded_children = Vec::new();
            self.expand_kdl_nodes(
                expansion,
                scope,
                children.nodes(),
                depth + 1,
                &mut expanded_children,
            )?;
            let mut child_doc = KdlDocument::new();
            for child in expanded_children {
                child_doc.nodes_mut().push(child);
            }
            generated.set_children(child_doc);
        }
        Some(generated)
    }

    fn load_kdl_fragment(
        &mut self,
        module: &ResolvedModule,
        instance: &TypedInstance,
        fragment_name: &str,
        span: Span,
    ) -> Option<KdlDocument> {
        let Some(fragment) = module.fragment(fragment_name) else {
            self.diagnostics.push(
                Diagnostic::error(
                    codes::FRAGMENT,
                    format!(
                        "module `{}` declares no fragment `{fragment_name}`",
                        module.decl.name
                    ),
                )
                .with_span(span),
            );
            return None;
        };
        if fragment.cardinality != FragmentCardinality::One
            || !matches!(fragment.format.as_str(), "kdl-v1" | "kdl-v2")
        {
            return None;
        }
        let sources = instance
            .fragment_sources
            .get(fragment_name)
            .unwrap_or(&fragment.defaults);
        let [source] = sources.as_slice() else {
            self.diagnostics.push(
                Diagnostic::error(
                    codes::FRAGMENT,
                    format!("inline fragment `{fragment_name}` requires exactly one source"),
                )
                .with_span(span),
            );
            return None;
        };
        let resolved =
            match resolve_source(&source.path, &source.base_dir, &self.workspace.source_root) {
                Ok(path) => path,
                Err(message) => {
                    self.diagnostics.push(
                        Diagnostic::error(codes::OUTPUT_PATH, message).with_span(source.span),
                    );
                    return None;
                }
            };
        let text = self.read_render_file(&resolved, source.span)?;
        let parsed = match fragment.format.as_str() {
            "kdl-v1" => KdlDocument::parse_v1(&text),
            "kdl-v2" => text.parse::<KdlDocument>(),
            _ => unreachable!("format checked above"),
        };
        match parsed {
            Ok(document) => Some(document),
            Err(error) => {
                self.diagnostics.push(
                    Diagnostic::error(
                        codes::FRAGMENT,
                        format!(
                            "fragment `{fragment_name}` source {} is not valid {}: {error}",
                            resolved.display(),
                            fragment.format
                        ),
                    )
                    .with_span(source.span),
                );
                None
            }
        }
    }

    fn raw_when_predicate(&mut self, node: &KdlNode, span: Span) -> Option<Predicate> {
        let name = node.get(0).and_then(kdl::KdlValue::as_string)?;
        let reference = crate::lang::ast::Ref {
            name: name.to_owned(),
            span,
        };
        match crate::lang::kdl_util::kdl_control_alias(node.name().value()) {
            "when" => Some(Predicate::Test(reference)),
            "when-set" => Some(Predicate::Set(reference)),
            "when-nonempty" => Some(Predicate::NonEmpty(reference)),
            _ => None,
        }
    }
}

fn range_iterations(from: i64, through: i64) -> Option<i64> {
    if through < from {
        return None;
    }
    through.checked_sub(from)?.checked_add(1)
}

fn value_to_kdl(value: &Value) -> Result<kdl::KdlValue, String> {
    match value {
        Value::Bool(b) => Ok(kdl::KdlValue::Bool(*b)),
        Value::Int(i) => Ok(kdl::KdlValue::Integer(*i as i128)),
        Value::Float(x) => Ok(kdl::KdlValue::Float(*x)),
        Value::String(s) | Value::Path(s) => Ok(kdl::KdlValue::String(s.clone())),
        Value::Null => Err("value is #null; guard the reference with `when-set`".to_owned()),
        other => Err(format!(
            "a `(ref)` inserts a typed scalar, found {}",
            other.type_label()
        )),
    }
}
