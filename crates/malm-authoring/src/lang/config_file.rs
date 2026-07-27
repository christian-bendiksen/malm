//! Generic config-file parsing, structural expansion, and serialization.

use crate::lang::ast::{EachBlock, Predicate, RangeBlock, Ref, WhenBlock};
use crate::lang::budget::{Budget, OutputBudget};
use crate::lang::diag::{Diagnostic, Diagnostics, FileId, Span, codes};
use crate::lang::kdl_util::{
    ParseResult, at_entry, at_node, child_nodes, entry_span, node_span, parse_condition,
    parse_each_header, parse_range_header, parse_splice, removed_control, validate_else,
};
use crate::lang::scope::Scope;
use crate::lang::text::{self, TemplateSyntax};
use crate::lang::value::Value;
use kdl::{KdlEntry, KdlNode, KdlValue};
use std::collections::HashSet;

pub mod generic;

#[derive(Debug)]
pub struct ConfigFileOutput {
    pub to: String,
    pub body: generic::GenericBody,
    pub transforms: Vec<String>,
    pub span: Span,
}

#[derive(Debug, Clone)]
pub enum ConfigItem<T> {
    Value { value: T, span: Span },
    When(WhenBlock<ConfigItem<T>>),
    Each(EachBlock<ConfigItem<T>>),
    Range(RangeBlock<ConfigItem<T>>),
    Splice(Ref),
}

impl<T> ConfigItem<T> {
    pub fn span(&self) -> Span {
        match self {
            Self::Value { span, .. } => *span,
            Self::When(value) => value.span,
            Self::Each(value) => value.span,
            Self::Range(value) => value.span,
            Self::Splice(value) => value.span,
        }
    }
}

#[derive(Debug)]
pub enum ConfigValue {
    Literal(Value, Span),
    Ref(Ref),
    FString { raw: String, span: Span },
}

impl ConfigValue {
    pub fn span(&self) -> Span {
        match self {
            Self::Literal(_, span) => *span,
            Self::Ref(reference) => reference.span,
            Self::FString { span, .. } => *span,
        }
    }
}

pub(crate) fn parse_body(
    file: FileId,
    format: &str,
    output: &KdlNode,
    nodes: &[KdlNode],
    span: Span,
) -> ParseResult<generic::GenericBody> {
    generic::parse(file, format, output, nodes, span)
}

/// Parses KDL nodes into the walker's item IR. `@else` attaches to the
/// immediately preceding canonical condition sibling.
pub(super) type ItemParser<'a, T> =
    dyn Fn(FileId, &[KdlNode]) -> ParseResult<Vec<ConfigItem<T>>> + 'a;

pub(super) fn parse_items<T>(
    file: FileId,
    nodes: &[KdlNode],
    leaf: &dyn Fn(FileId, &KdlNode) -> ParseResult<T>,
) -> ParseResult<Vec<ConfigItem<T>>> {
    let mut out = Vec::new();
    let mut nodes = nodes.iter().peekable();
    while let Some(node) = nodes.next() {
        let span = node_span(file, node);
        match node.name().value() {
            "@if" | "@if-present" | "@if-nonempty" => {
                let predicate = parse_condition(file, node)?;
                let then = parse_items(file, child_nodes(node), leaf)?;
                let otherwise = if nodes
                    .peek()
                    .is_some_and(|next| next.name().value() == "@else")
                {
                    let otherwise = nodes.next().expect("peeked");
                    validate_else(file, otherwise)?;
                    parse_items(file, child_nodes(otherwise), leaf)?
                } else {
                    Vec::new()
                };
                out.push(ConfigItem::When(WhenBlock {
                    predicate,
                    then,
                    otherwise,
                    span,
                }));
            }
            "@for-each" => {
                let (binding, source) = parse_each_header(file, node)?;
                out.push(ConfigItem::Each(EachBlock {
                    binding,
                    source,
                    body: parse_items(file, child_nodes(node), leaf)?,
                    span,
                }));
            }
            "@for-range" => {
                let (binding, from, through) = parse_range_header(file, node)?;
                out.push(ConfigItem::Range(RangeBlock {
                    binding,
                    from,
                    through,
                    body: parse_items(file, child_nodes(node), leaf)?,
                    span,
                }));
            }
            "@insert-documents" => {
                out.push(ConfigItem::Splice(parse_splice(file, node)?));
            }
            "@else" => {
                return Err(at_node(file, node).error(
                    codes::NODE_SHAPE,
                    "`@else` must immediately follow an `@if`, `@if-present`, or `@if-nonempty` sibling",
                ));
            }
            name if name.starts_with('@') => {
                if let Some(diagnostic) = removed_control(file, node) {
                    return Err(diagnostic);
                }
                out.push(ConfigItem::Value {
                    value: leaf(file, node)?,
                    span,
                });
            }
            _ => out.push(ConfigItem::Value {
                value: leaf(file, node)?,
                span,
            }),
        }
    }
    Ok(out)
}

pub(super) fn config_value(file: FileId, entry: &KdlEntry) -> ParseResult<ConfigValue> {
    if entry.ty().is_some_and(|ty| ty.value() == "ref") {
        let name = entry
            .value()
            .as_string()
            .filter(|name| !name.is_empty())
            .ok_or_else(|| {
                at_entry(file, entry).error(
                    codes::BAD_REF,
                    "expected a non-empty `(ref)\"name\"` reference",
                )
            })?;
        return Ok(ConfigValue::Ref(Ref {
            name: name.to_owned(),
            span: entry_span(file, entry),
        }));
    }
    if entry.ty().is_some() {
        return Err(at_entry(file, entry).error(
            codes::NODE_SHAPE,
            "only the `(ref)` value type is allowed in config-file",
        ));
    }
    let value = match entry.value() {
        KdlValue::Null => Value::Null,
        KdlValue::Bool(value) => Value::Bool(*value),
        KdlValue::Integer(value) => Value::Int(i64::try_from(*value).map_err(|_| {
            at_entry(file, entry).error(codes::NODE_SHAPE, "integer is outside the 64-bit range")
        })?),
        KdlValue::Float(value) if value.is_finite() => Value::Float(*value),
        KdlValue::Float(_) => {
            return Err(at_entry(file, entry)
                .error(codes::NODE_SHAPE, "non-finite numbers are not allowed"));
        }
        KdlValue::String(value) => Value::String(value.clone()),
    };
    Ok(ConfigValue::Literal(value, entry_span(file, entry)))
}

pub(super) fn css_value(file: FileId, entry: &KdlEntry) -> ParseResult<ConfigValue> {
    let span = entry_span(file, entry);
    match entry.ty().map(|ty| ty.value()) {
        Some("f") => {
            let raw = entry.value().as_string().ok_or_else(|| {
                Diagnostic::error(codes::NODE_SHAPE, "an `(f)` CSS value must be a string")
                    .with_span(span)
            })?;
            if let Err(message) = text::parse_template_with(raw, TemplateSyntax::V3) {
                return Err(Diagnostic::error(codes::TEMPLATE, message).with_span(span));
            }
            Ok(ConfigValue::FString {
                raw: raw.to_owned(),
                span,
            })
        }
        Some("ref") | None => config_value(file, entry),
        Some(other) => Err(Diagnostic::error(
            codes::NODE_SHAPE,
            format!("unknown CSS value annotation `({other})` (allowed: ref, f)"),
        )
        .with_span(span)),
    }
}

pub(crate) fn render(
    body: &generic::GenericBody,
    scope: &mut Scope,
    budget: &mut Budget,
    diagnostics: &mut Diagnostics,
) -> Option<String> {
    let errors_before = diagnostics.error_count();
    let mut renderer = Renderer::new(scope, budget, diagnostics, &CONFIG_SPLICE_LABELS, ());
    let mut output_budget = renderer.budget.begin_output();
    let content = generic::render(body, &mut renderer, &mut output_budget);
    if output_budget.exceeded() {
        renderer.finish_output(&output_budget, 0, body.span());
        return None;
    }
    let content = content?;
    if renderer.budget.exhausted() || renderer.diagnostics.error_count() != errors_before {
        return None;
    }
    renderer
        .finish_output(&output_budget, content.len(), body.span())
        .then_some(content)
}

/// User-visible labels that distinguish render bodies from config-file bodies.
pub(super) struct SpliceLabels {
    /// Spelling of the document-insertion directive in this body syntax.
    pub(super) directive: &'static str,
    /// Body kind named in document-insertion cycle diagnostics.
    pub(super) kind: &'static str,
}

pub(super) const CONFIG_SPLICE_LABELS: SpliceLabels = SpliceLabels {
    directive: "@insert-documents",
    kind: "config",
};

/// The shared structural walker for both body syntaxes. `X` carries the
/// walker-specific state: `()` for config-file bodies, the loaded
/// [`crate::lang::render::RenderResources`] for render bodies.
pub(super) struct Renderer<'a, X = ()> {
    pub(super) scope: &'a mut Scope,
    pub(super) budget: &'a mut Budget,
    pub(super) diagnostics: &'a mut Diagnostics,
    splice_stack: Vec<String>,
    labels: &'static SpliceLabels,
    pub(super) extra: X,
}

impl<'a, X> Renderer<'a, X> {
    pub(super) fn new(
        scope: &'a mut Scope,
        budget: &'a mut Budget,
        diagnostics: &'a mut Diagnostics,
        labels: &'static SpliceLabels,
        extra: X,
    ) -> Self {
        Self {
            scope,
            budget,
            diagnostics,
            splice_stack: Vec::new(),
            labels,
            extra,
        }
    }

    pub(super) fn error(&mut self, code: &'static str, message: impl Into<String>, span: Span) {
        self.diagnostics.error_at(code, message, span);
    }

    /// Reports a key emitted more than once during expansion.
    pub(super) fn duplicate(&mut self, name: &str, span: Span) {
        self.error(
            codes::DUPLICATE,
            format!("duplicate or redefined key `{name}` after expansion"),
            span,
        );
    }

    /// Claims `key` in `seen`, reporting `name` as a duplicate if it recurs.
    /// `key` may be namespaced (`table:x`) where `name` is what users wrote.
    pub(super) fn insert_unique(
        &mut self,
        seen: &mut HashSet<String>,
        key: String,
        name: &str,
        span: Span,
    ) -> Option<()> {
        if seen.insert(key) {
            return Some(());
        }
        self.duplicate(name, span);
        None
    }

    pub(super) fn finish_output(
        &mut self,
        output: &OutputBudget,
        actual: usize,
        span: Span,
    ) -> bool {
        match self.budget.finish_output(output, actual) {
            Ok(()) => true,
            Err(error) => {
                self.diagnostics
                    .push(error.into_diagnostic().with_span(span));
                false
            }
        }
    }

    pub(super) fn count_operations(&mut self, count: u64, span: Span) -> bool {
        match self.budget.count_operations(count) {
            Ok(()) => true,
            Err(error) => {
                self.diagnostics
                    .push(error.into_diagnostic().with_span(span));
                false
            }
        }
    }

    pub(super) fn walk<T>(
        &mut self,
        items: &[ConfigItem<T>],
        depth: usize,
        parser: &ItemParser<'_, T>,
        leaf: &mut dyn FnMut(&mut Self, &T, Span),
    ) {
        for item in items {
            if self.budget.exhausted() {
                return;
            }
            if let Err(error) = self.budget.count_operations(1) {
                self.diagnostics
                    .push(error.into_diagnostic().with_span(item.span()));
                return;
            }
            match item {
                ConfigItem::Value { value, span } => leaf(self, value, *span),
                ConfigItem::When(when) => {
                    if !self.check_depth(depth + 1, when.span) {
                        return;
                    }
                    let Some(matches) = self.predicate(&when.predicate) else {
                        continue;
                    };
                    let branch = if matches { &when.then } else { &when.otherwise };
                    self.walk(branch, depth + 1, parser, leaf);
                }
                ConfigItem::Each(each) => {
                    if !self.check_depth(depth + 1, each.span) {
                        return;
                    }
                    let Some(value) = self.scope.lookup(&each.source.name).cloned() else {
                        continue;
                    };
                    let values: Vec<(Option<String>, Value)> = match value {
                        Value::List(values) => {
                            values.into_iter().map(|value| (None, value)).collect()
                        }
                        Value::Collection(collection) => collection
                            .items
                            .into_iter()
                            .map(|item| (Some(item.key), item.value))
                            .collect(),
                        _ => continue,
                    };
                    if let Err(error) = self
                        .budget
                        .check_collection_size(values.len())
                        .and_then(|_| self.budget.count_iterations(values.len() as u64))
                    {
                        self.diagnostics
                            .push(error.into_diagnostic().with_span(each.span));
                        return;
                    }
                    for (key, value) in values {
                        let keyed = key.is_some();
                        if let Some(key) = key {
                            self.scope
                                .push_binding(format!("{}.key", each.binding), Value::String(key));
                        }
                        self.scope.push_binding(&each.binding, value);
                        self.walk(&each.body, depth + 1, parser, leaf);
                        self.scope.pop_binding();
                        if keyed {
                            self.scope.pop_binding();
                        }
                    }
                }
                ConfigItem::Range(range) => {
                    let count = range
                        .through
                        .checked_sub(range.from)
                        .and_then(|value| value.checked_add(1));
                    let Some(count) = count.filter(|value| *value > 0) else {
                        continue;
                    };
                    if let Err(error) = self
                        .budget
                        .check_nesting(depth + 1)
                        .and_then(|_| self.budget.check_range(count))
                        .and_then(|_| self.budget.count_iterations(count as u64))
                    {
                        self.diagnostics
                            .push(error.into_diagnostic().with_span(range.span));
                        return;
                    }
                    for number in range.from..=range.through {
                        self.scope.push_binding(&range.binding, Value::Int(number));
                        self.walk(&range.body, depth + 1, parser, leaf);
                        self.scope.pop_binding();
                    }
                }
                ConfigItem::Splice(reference) => self.splice(reference, depth, parser, leaf),
            }
        }
    }

    /// Walks every sibling while allowing leaves to report failure with `?`.
    /// Diagnostics remain in traversal order, and `None` means at least one
    /// leaf failed.
    pub(super) fn walk_all<T>(
        &mut self,
        items: &[ConfigItem<T>],
        depth: usize,
        parser: &ItemParser<'_, T>,
        leaf: &mut dyn FnMut(&mut Self, &T, Span) -> Option<()>,
    ) -> Option<()> {
        let mut ok = true;
        self.walk(items, depth, parser, &mut |renderer, node, span| {
            ok &= leaf(renderer, node, span).is_some();
        });
        ok.then_some(())
    }

    fn splice<T>(
        &mut self,
        reference: &Ref,
        depth: usize,
        parser: &ItemParser<'_, T>,
        leaf: &mut dyn FnMut(&mut Self, &T, Span),
    ) {
        if !self.check_depth(depth + 1, reference.span) {
            return;
        }
        let Some(Value::Collection(collection)) = self.scope.lookup(&reference.name).cloned()
        else {
            self.error(
                codes::TYPE_MISMATCH,
                format!(
                    "`{}` requires a collection<kdl-document>, found `{}`",
                    self.labels.directive, reference.name
                ),
                reference.span,
            );
            return;
        };
        if let Some(start) = self
            .splice_stack
            .iter()
            .position(|name| name == &reference.name)
        {
            let mut cycle = self.splice_stack[start..].to_vec();
            cycle.push(reference.name.clone());
            self.error(
                codes::KDL_GEN,
                format!(
                    "{} @insert-documents cycle detected: {}",
                    self.labels.kind,
                    cycle.join(" -> ")
                ),
                reference.span,
            );
            return;
        }
        if let Err(error) = self
            .budget
            .check_collection_size(collection.items.len())
            .and_then(|_| self.budget.count_operations(collection.items.len() as u64))
        {
            self.diagnostics
                .push(error.into_diagnostic().with_span(reference.span));
            return;
        }
        self.splice_stack.push(reference.name.clone());
        for item in collection.items {
            let Value::KdlDocument(document) = item.value else {
                self.error(
                    codes::TYPE_MISMATCH,
                    format!(
                        "inserted collection item `{}` is not a kdl-document",
                        item.key
                    ),
                    item.span,
                );
                continue;
            };
            if let Err(error) = crate::lang::parse::validate_structural_kdl_document(
                item.span.file,
                document.nodes(),
            ) {
                self.diagnostics.push(error);
                continue;
            }
            match parser(item.span.file, document.nodes()) {
                Ok(items) => self.walk(&items, depth + 1, parser, leaf),
                Err(error) => self.diagnostics.push(error),
            }
        }
        self.splice_stack.pop();
    }

    pub(super) fn check_depth(&mut self, depth: usize, span: Span) -> bool {
        match self.budget.check_nesting(depth) {
            Ok(()) => true,
            Err(error) => {
                self.diagnostics
                    .push(error.into_diagnostic().with_span(span));
                false
            }
        }
    }

    pub(super) fn predicate(&self, predicate: &Predicate) -> Option<bool> {
        predicate.eval(self.scope.lookup(&predicate.reference().name))
    }

    pub(super) fn resolve_value(&mut self, value: &ConfigValue) -> Option<Value> {
        match value {
            ConfigValue::Literal(value, _) => Some(value.clone()),
            ConfigValue::Ref(reference) => {
                self.scope.lookup(&reference.name).cloned().or_else(|| {
                    self.error(
                        codes::UNDEFINED_REF,
                        format!("`{}` is not defined", reference.name),
                        reference.span,
                    );
                    None
                })
            }
            ConfigValue::FString { raw, span } => {
                let scope = &*self.scope;
                let lookup = move |name: &str| scope.lookup(name).cloned();
                match text::render_template_with_limit(
                    raw,
                    TemplateSyntax::V3,
                    &lookup,
                    self.budget.limits().max_artifact_bytes,
                ) {
                    Ok(rendered) => Some(Value::String(rendered)),
                    Err(message) => {
                        self.error(codes::TEMPLATE, message, *span);
                        None
                    }
                }
            }
        }
    }
}
