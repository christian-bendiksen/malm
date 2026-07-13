//! Generic config-file parsing, structural expansion, and serialization.

use crate::lang::ast::{EachBlock, Predicate, RangeBlock, Ref, WhenBlock};
use crate::lang::budget::Budget;
use crate::lang::diag::{Diagnostic, Diagnostics, FileId, Span, codes};
use crate::lang::kdl_util::{
    ParseResult, entry_span, expect_args, node_span, parse_condition, parse_each_header,
    parse_range_header, parse_splice, reject_unknown_props,
};
use crate::lang::scope::Scope;
use crate::lang::text::{self, TemplateSyntax};
use crate::lang::value::Value;
use kdl::{KdlEntry, KdlNode, KdlValue};

pub mod generic;

#[derive(Debug)]
pub struct ConfigFileOutput {
    pub to: String,
    pub body: generic::GenericBody,
    pub validate: Option<String>,
    pub span: Span,
}

#[derive(Debug)]
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

pub(super) fn parse_items<T>(
    file: FileId,
    nodes: &[KdlNode],
    leaf: &dyn Fn(FileId, &KdlNode) -> ParseResult<T>,
) -> ParseResult<Vec<ConfigItem<T>>> {
    nodes
        .iter()
        .map(|node| parse_item(file, node, leaf))
        .collect()
}

fn parse_item<T>(
    file: FileId,
    node: &KdlNode,
    leaf: &dyn Fn(FileId, &KdlNode) -> ParseResult<T>,
) -> ParseResult<ConfigItem<T>> {
    let span = node_span(file, node);
    let parse_children = |node: &KdlNode| -> ParseResult<Vec<ConfigItem<T>>> {
        parse_items(
            file,
            node.children()
                .map(|children| children.nodes())
                .unwrap_or_default(),
            leaf,
        )
    };
    match node.name().value() {
        "when" | "when-set" | "when-nonempty" => {
            let predicate = parse_condition(file, node)?;
            let children = node.children().map(|c| c.nodes()).unwrap_or_default();
            let mut then = Vec::new();
            let mut otherwise = Vec::new();
            let mut saw_else = false;
            for (index, child) in children.iter().enumerate() {
                if child.name().value() == "else" {
                    if saw_else || index + 1 != children.len() {
                        return Err(Diagnostic::error(
                            codes::NODE_SHAPE,
                            "`else` must occur once as the final child of a config-file condition",
                        )
                        .with_span(node_span(file, child)));
                    }
                    saw_else = true;
                    expect_args(file, child, 0)?;
                    reject_unknown_props(file, child, &[])?;
                    otherwise = parse_children(child)?;
                } else {
                    then.push(parse_item(file, child, leaf)?);
                }
            }
            Ok(ConfigItem::When(WhenBlock {
                predicate,
                then,
                otherwise,
                span,
            }))
        }
        "each" => {
            let (binding, source) = parse_each_header(file, node)?;
            Ok(ConfigItem::Each(EachBlock {
                binding,
                source,
                body: parse_children(node)?,
                span,
            }))
        }
        "range" => {
            let (binding, from, through) = parse_range_header(file, node)?;
            Ok(ConfigItem::Range(RangeBlock {
                binding,
                from,
                through,
                body: parse_children(node)?,
                span,
            }))
        }
        "splice" => Ok(ConfigItem::Splice(parse_splice(file, node)?)),
        "else" => Err(Diagnostic::error(
            codes::NODE_SHAPE,
            "`else` must be the final child of a config-file condition",
        )
        .with_span(span)),
        _ => leaf(file, node).map(|value| ConfigItem::Value { value, span }),
    }
}

pub(super) fn config_value(file: FileId, entry: &KdlEntry) -> ParseResult<ConfigValue> {
    if entry.ty().is_some_and(|ty| ty.value() == "ref") {
        let name = entry
            .value()
            .as_string()
            .filter(|name| !name.is_empty())
            .ok_or_else(|| {
                Diagnostic::error(
                    codes::BAD_REF,
                    "expected a non-empty `(ref)\"name\"` reference",
                )
                .with_span(entry_span(file, entry))
            })?;
        return Ok(ConfigValue::Ref(Ref {
            name: name.to_owned(),
            span: entry_span(file, entry),
        }));
    }
    if entry.ty().is_some() {
        return Err(Diagnostic::error(
            codes::NODE_SHAPE,
            "only the `(ref)` value type is allowed in config-file",
        )
        .with_span(entry_span(file, entry)));
    }
    let value = match entry.value() {
        KdlValue::Null => Value::Null,
        KdlValue::Bool(value) => Value::Bool(*value),
        KdlValue::Integer(value) => Value::Int(i64::try_from(*value).map_err(|_| {
            Diagnostic::error(codes::NODE_SHAPE, "integer is outside the 64-bit range")
                .with_span(entry_span(file, entry))
        })?),
        KdlValue::Float(value) if value.is_finite() => Value::Float(*value),
        KdlValue::Float(_) => {
            return Err(
                Diagnostic::error(codes::NODE_SHAPE, "non-finite numbers are not allowed")
                    .with_span(entry_span(file, entry)),
            );
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
) -> Option<(String, &'static str)> {
    let errors_before = diagnostics.error_count();
    let mut renderer = Renderer {
        scope,
        budget,
        diagnostics,
        splice_stack: Vec::new(),
    };
    let content = generic::render(body, &mut renderer)?;
    (!renderer.budget.exhausted() && renderer.diagnostics.error_count() == errors_before)
        .then_some((content, body.validator()))
}

pub(super) struct Renderer<'a> {
    scope: &'a mut Scope,
    budget: &'a mut Budget,
    pub(super) diagnostics: &'a mut Diagnostics,
    splice_stack: Vec<String>,
}

impl Renderer<'_> {
    pub(super) fn charge_bytes(&mut self, content: &str, span: Span) -> bool {
        match self
            .budget
            .count_artifact_bytes(content.len() as u64, content.len() as u64)
        {
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

    pub(super) fn render_items<T>(
        &mut self,
        items: &[ConfigItem<T>],
        depth: usize,
        parser: &dyn Fn(FileId, &KdlNode) -> ParseResult<T>,
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
                    self.render_items(branch, depth + 1, parser, leaf);
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
                        self.render_items(&each.body, depth + 1, parser, leaf);
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
                        self.render_items(&range.body, depth + 1, parser, leaf);
                        self.scope.pop_binding();
                    }
                }
                ConfigItem::Splice(reference) => {
                    self.render_splice(reference, depth, parser, leaf);
                }
            }
        }
    }

    fn render_splice<T>(
        &mut self,
        reference: &Ref,
        depth: usize,
        parser: &dyn Fn(FileId, &KdlNode) -> ParseResult<T>,
        leaf: &mut dyn FnMut(&mut Self, &T, Span),
    ) {
        if !self.check_depth(depth + 1, reference.span) {
            return;
        }
        let Some(Value::Collection(collection)) = self.scope.lookup(&reference.name).cloned()
        else {
            self.diagnostics.push(
                Diagnostic::error(
                    codes::TYPE_MISMATCH,
                    format!(
                        "`splice` requires a collection<kdl-document>, found `{}`",
                        reference.name
                    ),
                )
                .with_span(reference.span),
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
            self.diagnostics.push(
                Diagnostic::error(
                    codes::KDL_GEN,
                    format!("config splice cycle detected: {}", cycle.join(" -> ")),
                )
                .with_span(reference.span),
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
                self.diagnostics.push(
                    Diagnostic::error(
                        codes::TYPE_MISMATCH,
                        format!(
                            "spliced collection item `{}` is not a kdl-document",
                            item.key
                        ),
                    )
                    .with_span(item.span),
                );
                continue;
            };
            match parse_items(item.span.file, document.nodes(), parser) {
                Ok(items) => self.render_items(&items, depth + 1, parser, leaf),
                Err(error) => self.diagnostics.push(error),
            }
        }
        self.splice_stack.pop();
    }

    fn check_depth(&mut self, depth: usize, span: Span) -> bool {
        match self.budget.check_nesting(depth) {
            Ok(()) => true,
            Err(error) => {
                self.diagnostics
                    .push(error.into_diagnostic().with_span(span));
                false
            }
        }
    }

    fn predicate(&self, predicate: &Predicate) -> Option<bool> {
        let value = self.scope.lookup(&predicate.reference().name)?;
        match (predicate, value) {
            (Predicate::Test(_), Value::Bool(value)) => Some(*value),
            (Predicate::Set(_), value) => Some(!value.is_null()),
            (Predicate::NonEmpty(_), Value::List(values)) => Some(!values.is_empty()),
            (Predicate::NonEmpty(_), Value::Collection(values)) => Some(!values.is_empty()),
            (
                Predicate::Eq {
                    expected, negated, ..
                },
                value,
            ) if std::mem::discriminant(value) == std::mem::discriminant(expected) => {
                Some((value == expected) != *negated)
            }
            _ => None,
        }
    }

    pub(super) fn resolve(&mut self, value: &ConfigValue) -> Option<Value> {
        match value {
            ConfigValue::Literal(value, _) => Some(value.clone()),
            ConfigValue::Ref(reference) => {
                self.scope.lookup(&reference.name).cloned().or_else(|| {
                    self.diagnostics.push(
                        Diagnostic::error(
                            codes::UNDEFINED_REF,
                            format!("`{}` is not defined", reference.name),
                        )
                        .with_span(reference.span),
                    );
                    None
                })
            }
            ConfigValue::FString { raw, span } => {
                let scope = &*self.scope;
                let lookup = move |name: &str| scope.lookup(name).cloned();
                match text::render_template_with(raw, TemplateSyntax::V3, &lookup) {
                    Ok(rendered) => Some(Value::String(rendered)),
                    Err(message) => {
                        self.diagnostics
                            .push(Diagnostic::error(codes::TEMPLATE, message).with_span(*span));
                        None
                    }
                }
            }
        }
    }
}
