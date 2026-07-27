//! Span-aware KDL shape validation and typed node accessors.

use crate::lang::ast::{Predicate, Ref};
use crate::lang::diag::{Diagnostic, FileId, Span, codes};
use crate::lang::value::Value;
use kdl::{KdlDocument, KdlEntry, KdlNode, KdlValue};

pub(crate) type ParseResult<T> = Result<T, Diagnostic>;

pub(crate) fn node_span(file: FileId, node: &KdlNode) -> Span {
    let span = node.span();
    Span::new(file, span.offset(), span.len())
}

pub(crate) fn validate_document_depth(file: FileId, nodes: &[KdlNode]) -> ParseResult<()> {
    let maximum = crate::lang::budget::Limits::default().max_control_nesting;
    let mut pending = nodes.iter().map(|node| (node, 1usize)).collect::<Vec<_>>();
    while let Some((node, depth)) = pending.pop() {
        if depth > maximum {
            return Err(at_node(file, node).error(
                codes::BUDGET,
                format!("document nesting exceeds the maximum depth of {maximum}"),
            ));
        }
        if let Some(children) = node.children() {
            pending.extend(children.nodes().iter().map(|child| (child, depth + 1)));
        }
    }
    Ok(())
}

pub(crate) fn entry_span(file: FileId, entry: &KdlEntry) -> Span {
    let span = entry.span();
    Span::new(file, span.offset(), span.len())
}

/// A source position used to construct an anchored diagnostic.
#[derive(Debug, Clone, Copy)]
pub(crate) struct At(Span);

impl At {
    /// Builds an error diagnostic anchored at this position.
    pub(crate) fn error(self, code: &'static str, message: impl Into<String>) -> Diagnostic {
        Diagnostic::error(code, message).with_span(self.0)
    }
}

/// Anchors diagnostics on a whole node.
pub(crate) fn at_node(file: FileId, node: &KdlNode) -> At {
    At(node_span(file, node))
}

/// Anchors diagnostics on one argument or property entry.
pub(crate) fn at_entry(file: FileId, entry: &KdlEntry) -> At {
    At(entry_span(file, entry))
}

/// Requires exactly `expected` positional arguments.
pub(crate) fn expect_args(file: FileId, node: &KdlNode, expected: usize) -> ParseResult<()> {
    let count = node.iter().filter(|e| e.name().is_none()).count();
    if count != expected {
        return Err(at_node(file, node).error(
            codes::NODE_SHAPE,
            format!(
                "`{}` expects {expected} positional argument(s), found {count}",
                node.name().value()
            ),
        ));
    }
    Ok(())
}

pub(crate) fn reject_unknown_props(
    file: FileId,
    node: &KdlNode,
    allowed: &[&str],
) -> ParseResult<()> {
    let mut seen: Vec<&str> = Vec::new();
    for entry in node.iter() {
        if let Some(key) = entry.name() {
            let name = key.value();
            if !allowed.contains(&name) {
                return Err(at_entry(file, entry).error(
                    codes::NODE_SHAPE,
                    format!(
                        "`{}` has unknown property `{name}`{}",
                        node.name().value(),
                        if allowed.is_empty() {
                            String::new()
                        } else {
                            format!(" (allowed: {})", allowed.join(", "))
                        }
                    ),
                ));
            }
            if seen.contains(&name) {
                return Err(at_entry(file, entry).error(
                    codes::DUPLICATE,
                    format!("`{}` sets property `{name}` twice", node.name().value()),
                ));
            }
            seen.push(name);
        }
    }
    Ok(())
}

pub(crate) fn reject_unknown_children(
    file: FileId,
    node: &KdlNode,
    allowed: &[&str],
) -> ParseResult<()> {
    let Some(children) = node.children() else {
        return Ok(());
    };
    for child in children.nodes() {
        let name = child.name().value();
        if !allowed.contains(&name) {
            return Err(at_node(file, child).error(
                codes::NODE_SHAPE,
                format!(
                    "`{}` has unknown child `{name}`{}",
                    node.name().value(),
                    if allowed.is_empty() {
                        String::new()
                    } else {
                        format!(" (allowed: {})", allowed.join(", "))
                    }
                ),
            ));
        }
    }
    Ok(())
}

pub(crate) fn req_str_arg(file: FileId, node: &KdlNode) -> ParseResult<String> {
    expect_args(file, node, 1)?;
    node.get(0)
        .and_then(KdlValue::as_string)
        .map(str::to_owned)
        .ok_or_else(|| {
            at_node(file, node).error(
                codes::NODE_SHAPE,
                format!("`{}` requires a string argument", node.name().value()),
            )
        })
}

pub(crate) fn req_str_prop(file: FileId, node: &KdlNode, prop: &str) -> ParseResult<String> {
    opt_str_prop(file, node, prop)?.ok_or_else(|| {
        at_node(file, node).error(
            codes::NODE_SHAPE,
            format!(
                "`{}` is missing the required property `{prop}=`",
                node.name().value()
            ),
        )
    })
}

pub(crate) fn opt_str_prop(
    file: FileId,
    node: &KdlNode,
    prop: &str,
) -> ParseResult<Option<String>> {
    let Some(entry) = prop_entry(node, prop) else {
        return Ok(None);
    };
    entry
        .value()
        .as_string()
        .map(|s| Some(s.to_owned()))
        .ok_or_else(|| {
            at_entry(file, entry).error(
                codes::NODE_SHAPE,
                format!(
                    "`{}`: property `{prop}=` must be a string",
                    node.name().value()
                ),
            )
        })
}

pub(crate) fn bool_prop(file: FileId, node: &KdlNode, prop: &str) -> ParseResult<bool> {
    let Some(entry) = prop_entry(node, prop) else {
        return Ok(false);
    };
    entry.value().as_bool().ok_or_else(|| {
        at_entry(file, entry).error(
            codes::NODE_SHAPE,
            format!(
                "`{}`: property `{prop}=` must be #true or #false",
                node.name().value()
            ),
        )
    })
}

pub(crate) fn int_prop(file: FileId, node: &KdlNode, prop: &str) -> ParseResult<Option<i64>> {
    let Some(entry) = prop_entry(node, prop) else {
        return Ok(None);
    };
    match entry.value().as_integer() {
        Some(i) => i64::try_from(i).map(Some).map_err(|_| {
            at_entry(file, entry).error(
                codes::NODE_SHAPE,
                format!(
                    "`{}`: property `{prop}=` is out of range for a 64-bit integer",
                    node.name().value()
                ),
            )
        }),
        None => Err(at_entry(file, entry).error(
            codes::NODE_SHAPE,
            format!(
                "`{}`: property `{prop}=` must be an integer",
                node.name().value()
            ),
        )),
    }
}

pub(crate) fn prop_entry<'a>(node: &'a KdlNode, prop: &str) -> Option<&'a KdlEntry> {
    node.iter()
        .find(|entry| entry.name().is_some_and(|n| n.value() == prop))
}

/// The node's children, or an empty slice when it declares no block.
pub(crate) fn child_nodes(node: &KdlNode) -> &[KdlNode] {
    node.children().map(KdlDocument::nodes).unwrap_or_default()
}

/// Locates the positional entry that names an escaped target node.
///
/// The physical index lets callers remove that entry while retaining any
/// properties that KDL permits before it.
pub(crate) fn escaped_node_target(node: &KdlNode) -> Option<(usize, &KdlEntry)> {
    node.iter()
        .enumerate()
        .find(|(_, entry)| entry.name().is_none())
}

pub(crate) fn opt_child<'a>(node: &'a KdlNode, name: &str) -> Option<&'a KdlNode> {
    node.children()?.get(name)
}

pub(crate) fn reject_duplicate_children(
    file: FileId,
    node: &KdlNode,
    singletons: &[&str],
) -> ParseResult<()> {
    let Some(children) = node.children() else {
        return Ok(());
    };
    for &name in singletons {
        let matching: Vec<&KdlNode> = children
            .nodes()
            .iter()
            .filter(|c| c.name().value() == name)
            .collect();
        if matching.len() > 1 {
            return Err(at_node(file, matching[1]).error(
                codes::DUPLICATE,
                format!("`{}` has more than one `{name}` child", node.name().value()),
            ));
        }
    }
    Ok(())
}

/// Returns whether an entry carries the `(ref)` type annotation.
pub(crate) fn is_ref(entry: &KdlEntry) -> bool {
    entry.ty().is_some_and(|t| t.value() == "ref")
}

/// Parses a `(ref)"name"` entry into a [`Ref`].
pub(crate) fn parse_ref(file: FileId, entry: &KdlEntry) -> ParseResult<Ref> {
    if !is_ref(entry) {
        return Err(at_entry(file, entry)
            .error(codes::BAD_REF, "expected a `(ref)\"name\"` reference")
            .with_help("annotate the value with the `ref` type: (ref)\"my-input\""));
    }
    let name = entry.value().as_string().ok_or_else(|| {
        at_entry(file, entry).error(codes::BAD_REF, "a `(ref)` value must be a string")
    })?;
    if name.is_empty() {
        return Err(at_entry(file, entry).error(codes::BAD_REF, "a `(ref)` name must not be empty"));
    }
    Ok(Ref {
        name: name.to_owned(),
        span: entry_span(file, entry),
    })
}

fn plain_ref(file: FileId, entry: &KdlEntry, context: &str) -> ParseResult<Ref> {
    if entry.ty().is_some() {
        return Err(at_entry(file, entry).error(
            codes::BAD_REF,
            format!("{context} is a plain string, not a typed value"),
        ));
    }
    let name = entry
        .value()
        .as_string()
        .filter(|name| !name.is_empty())
        .ok_or_else(|| {
            at_entry(file, entry).error(
                codes::BAD_REF,
                format!("{context} must be a non-empty string"),
            )
        })?;
    Ok(Ref {
        name: name.to_owned(),
        span: entry_span(file, entry),
    })
}

pub(crate) fn parse_condition(file: FileId, node: &KdlNode) -> ParseResult<Predicate> {
    let name = node.name().value();
    if name == "@if" {
        reject_unknown_props(file, node, &["is", "is-not"])?;
    } else {
        reject_unknown_props(file, node, &[])?;
    }
    expect_args(file, node, 1)?;
    let entry = node
        .iter()
        .find(|entry| entry.name().is_none())
        .expect("one argument checked");
    let reference = plain_ref(file, entry, "condition reference")?;
    if name == "@if" {
        let is_entry = prop_entry(node, "is");
        let is_not_entry = prop_entry(node, "is-not");
        if is_entry.is_some() && is_not_entry.is_some() {
            return Err(at_node(file, node).error(
                codes::NODE_SHAPE,
                "`@if` takes either `is=` or `is-not=`, not both",
            ));
        }
        if let Some(value_entry) = is_entry.or(is_not_entry) {
            let expected = scalar_value(file, value_entry)?;
            if matches!(expected, Value::Null | Value::Float(_)) {
                return Err(at_entry(file, value_entry).error(
                    codes::WHEN_PREDICATE,
                    "`is=` compares enum, string, int, or bool literals",
                ));
            }
            return Ok(Predicate::Eq {
                reference,
                expected,
                negated: is_not_entry.is_some(),
            });
        }
    }
    match name {
        "@if" => Ok(Predicate::Test(reference)),
        "@if-present" => Ok(Predicate::Set(reference)),
        "@if-nonempty" => Ok(Predicate::NonEmpty(reference)),
        _ => Err(at_node(file, node).error(
            codes::UNKNOWN_NODE,
            format!("unknown condition `{}`", node.name().value()),
        )),
    }
}

pub(crate) fn is_condition_name(name: &str) -> bool {
    matches!(name, "@if" | "@if-present" | "@if-nonempty")
}

/// Returns the canonical replacement for a removed authoring control spelling.
/// Callers in target-data contexts use this only for sigiled names so
/// unsigiled names remain ordinary target nodes.
pub(crate) fn removed_control_replacement(name: &str) -> Option<&'static str> {
    match name {
        "when" | "@when" => Some("@if"),
        "when-set" | "@when-set" => Some("@if-present"),
        "when-nonempty" | "@when-nonempty" => Some("@if-nonempty"),
        "each" | "@each" => Some("@for-each"),
        "range" | "@range" => Some("@for-range"),
        "@spread" => Some("@insert-fields"),
        "splice" | "@splice" => Some("@insert-documents"),
        "@file" => Some("@include-file"),
        "compose" | "@compose" => Some("@include-fragment"),
        "@raw" => Some("@raw-text"),
        "@transform" => Some("@component-transform"),
        _ => None,
    }
}

pub(crate) fn removed_control(file: FileId, node: &KdlNode) -> Option<Diagnostic> {
    removed_control_replacement(node.name().value()).map(|replacement| {
        at_node(file, node).error(
            codes::UNKNOWN_NODE,
            format!("`{}` was removed; use `{replacement}`", node.name().value()),
        )
    })
}

pub(crate) fn validate_else(file: FileId, node: &KdlNode) -> ParseResult<()> {
    expect_args(file, node, 0)?;
    reject_unknown_props(file, node, &[])
}

pub(crate) fn parse_each_header(file: FileId, node: &KdlNode) -> ParseResult<(String, Ref)> {
    reject_unknown_props(file, node, &["in"])?;
    let binding = req_str_arg(file, node)?;
    if binding.is_empty() {
        return Err(
            at_node(file, node).error(codes::BINDING, "`@for-each` binding must not be empty")
        );
    }
    let source = prop_entry(node, "in")
        .ok_or_else(|| {
            at_node(file, node).error(codes::NODE_SHAPE, "`@for-each` requires `in=\"source\"`")
        })
        .and_then(|entry| plain_ref(file, entry, "`@for-each in=` reference"))?;
    Ok((binding, source))
}

pub(crate) fn parse_range_header(file: FileId, node: &KdlNode) -> ParseResult<(String, i64, i64)> {
    reject_unknown_props(file, node, &["from", "through"])?;
    let binding = req_str_arg(file, node)?;
    if binding.is_empty() {
        return Err(
            at_node(file, node).error(codes::BINDING, "`@for-range` binding must not be empty")
        );
    }
    let from = int_prop(file, node, "from")?.ok_or_else(|| {
        at_node(file, node).error(codes::NODE_SHAPE, "`@for-range` requires `from=<int>`")
    })?;
    let through = int_prop(file, node, "through")?.ok_or_else(|| {
        at_node(file, node).error(codes::NODE_SHAPE, "`@for-range` requires `through=<int>`")
    })?;
    Ok((binding, from, through))
}

pub(crate) fn parse_splice(file: FileId, node: &KdlNode) -> ParseResult<Ref> {
    reject_unknown_props(file, node, &[])?;
    reject_unknown_children(file, node, &[])?;
    expect_args(file, node, 1)?;
    let entry = node
        .iter()
        .find(|entry| entry.name().is_none())
        .expect("one argument checked");
    plain_ref(file, entry, "`@insert-documents` collection reference")
}

/// Converts a scalar KDL value into a typed [`Value`]. Rejects refs because the
/// caller decides where references are legal.
pub(crate) fn scalar_value(file: FileId, entry: &KdlEntry) -> ParseResult<Value> {
    if entry.ty().is_some() {
        return Err(at_entry(file, entry).error(
            codes::NODE_SHAPE,
            "type-annotated values are not allowed here",
        ));
    }
    match entry.value() {
        KdlValue::Null => Ok(Value::Null),
        KdlValue::Bool(b) => Ok(Value::Bool(*b)),
        KdlValue::Integer(i) => i64::try_from(*i).map(Value::Int).map_err(|_| {
            at_entry(file, entry).error(
                codes::NODE_SHAPE,
                "integer is out of range for a 64-bit value",
            )
        }),
        KdlValue::Float(x) => {
            if x.is_finite() {
                Ok(Value::Float(*x))
            } else {
                Err(at_entry(file, entry)
                    .error(codes::NODE_SHAPE, "non-finite floats are not allowed"))
            }
        }
        KdlValue::String(s) => Ok(Value::String(s.clone())),
    }
}
