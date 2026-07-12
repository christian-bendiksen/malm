//! Span-aware KDL shape validation and typed node accessors.

use crate::lang::ast::{Predicate, Ref};
use crate::lang::diag::{Diagnostic, FileId, Span, codes};
use crate::lang::value::Value;
use kdl::{KdlEntry, KdlNode, KdlValue};

pub(crate) type ParseResult<T> = Result<T, Diagnostic>;

pub(crate) fn node_span(file: FileId, node: &KdlNode) -> Span {
    Span::new(file, node.span())
}

pub(crate) fn validate_document_depth(file: FileId, nodes: &[KdlNode]) -> ParseResult<()> {
    let maximum = crate::lang::budget::Limits::default().max_control_nesting;
    let mut pending = nodes.iter().map(|node| (node, 1usize)).collect::<Vec<_>>();
    while let Some((node, depth)) = pending.pop() {
        if depth > maximum {
            return Err(Diagnostic::error(
                codes::BUDGET,
                format!("document nesting exceeds the maximum depth of {maximum}"),
            )
            .with_span(node_span(file, node)));
        }
        if let Some(children) = node.children() {
            pending.extend(children.nodes().iter().map(|child| (child, depth + 1)));
        }
    }
    Ok(())
}

pub(crate) fn entry_span(file: FileId, entry: &KdlEntry) -> Span {
    Span::new(file, entry.span())
}

/// Reject positional args beyond `expected`.
pub(crate) fn expect_args(file: FileId, node: &KdlNode, expected: usize) -> ParseResult<()> {
    let count = node.iter().filter(|e| e.name().is_none()).count();
    if count != expected {
        return Err(Diagnostic::error(
            codes::NODE_SHAPE,
            format!(
                "`{}` expects {expected} positional argument(s), found {count}",
                node.name().value()
            ),
        )
        .with_span(node_span(file, node)));
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
                return Err(Diagnostic::error(
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
                )
                .with_span(entry_span(file, entry)));
            }
            if seen.contains(&name) {
                return Err(Diagnostic::error(
                    codes::DUPLICATE,
                    format!("`{}` sets property `{name}` twice", node.name().value()),
                )
                .with_span(entry_span(file, entry)));
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
            return Err(Diagnostic::error(
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
            )
            .with_span(node_span(file, child)));
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
            Diagnostic::error(
                codes::NODE_SHAPE,
                format!("`{}` requires a string argument", node.name().value()),
            )
            .with_span(node_span(file, node))
        })
}

pub(crate) fn req_str_prop(file: FileId, node: &KdlNode, prop: &str) -> ParseResult<String> {
    opt_str_prop(file, node, prop)?.ok_or_else(|| {
        Diagnostic::error(
            codes::NODE_SHAPE,
            format!(
                "`{}` is missing the required property `{prop}=`",
                node.name().value()
            ),
        )
        .with_span(node_span(file, node))
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
            Diagnostic::error(
                codes::NODE_SHAPE,
                format!(
                    "`{}`: property `{prop}=` must be a string",
                    node.name().value()
                ),
            )
            .with_span(entry_span(file, entry))
        })
}

pub(crate) fn bool_prop(file: FileId, node: &KdlNode, prop: &str) -> ParseResult<bool> {
    let Some(entry) = prop_entry(node, prop) else {
        return Ok(false);
    };
    entry.value().as_bool().ok_or_else(|| {
        Diagnostic::error(
            codes::NODE_SHAPE,
            format!(
                "`{}`: property `{prop}=` must be #true or #false",
                node.name().value()
            ),
        )
        .with_span(entry_span(file, entry))
    })
}

pub(crate) fn int_prop(file: FileId, node: &KdlNode, prop: &str) -> ParseResult<Option<i64>> {
    let Some(entry) = prop_entry(node, prop) else {
        return Ok(None);
    };
    match entry.value().as_integer() {
        Some(i) => i64::try_from(i).map(Some).map_err(|_| {
            Diagnostic::error(
                codes::NODE_SHAPE,
                format!(
                    "`{}`: property `{prop}=` is out of range for a 64-bit integer",
                    node.name().value()
                ),
            )
            .with_span(entry_span(file, entry))
        }),
        None => Err(Diagnostic::error(
            codes::NODE_SHAPE,
            format!(
                "`{}`: property `{prop}=` must be an integer",
                node.name().value()
            ),
        )
        .with_span(entry_span(file, entry))),
    }
}

pub(crate) fn prop_entry<'a>(node: &'a KdlNode, prop: &str) -> Option<&'a KdlEntry> {
    node.iter()
        .find(|entry| entry.name().is_some_and(|n| n.value() == prop))
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
            return Err(Diagnostic::error(
                codes::DUPLICATE,
                format!("`{}` has more than one `{name}` child", node.name().value()),
            )
            .with_span(node_span(file, matching[1])));
        }
    }
    Ok(())
}

/// Whether an entry carries the `(ref)` type annotation.
pub(crate) fn is_ref(entry: &KdlEntry) -> bool {
    entry.ty().is_some_and(|t| t.value() == "ref")
}

/// Parse a `(ref)"name"` entry into a [`Ref`].
pub(crate) fn parse_ref(file: FileId, entry: &KdlEntry) -> ParseResult<Ref> {
    if !is_ref(entry) {
        return Err(
            Diagnostic::error(codes::BAD_REF, "expected a `(ref)\"name\"` reference")
                .with_span(entry_span(file, entry))
                .with_help("annotate the value with the `ref` type: (ref)\"my-input\""),
        );
    }
    let name = entry.value().as_string().ok_or_else(|| {
        Diagnostic::error(codes::BAD_REF, "a `(ref)` value must be a string")
            .with_span(entry_span(file, entry))
    })?;
    if name.is_empty() {
        return Err(
            Diagnostic::error(codes::BAD_REF, "a `(ref)` name must not be empty")
                .with_span(entry_span(file, entry)),
        );
    }
    Ok(Ref {
        name: name.to_owned(),
        span: entry_span(file, entry),
    })
}

fn plain_ref(file: FileId, entry: &KdlEntry, context: &str) -> ParseResult<Ref> {
    if entry.ty().is_some() {
        return Err(Diagnostic::error(
            codes::BAD_REF,
            format!("{context} is a plain string, not a typed value"),
        )
        .with_span(entry_span(file, entry)));
    }
    let name = entry
        .value()
        .as_string()
        .filter(|name| !name.is_empty())
        .ok_or_else(|| {
            Diagnostic::error(
                codes::BAD_REF,
                format!("{context} must be a non-empty string"),
            )
            .with_span(entry_span(file, entry))
        })?;
    Ok(Ref {
        name: name.to_owned(),
        span: entry_span(file, entry),
    })
}

pub(crate) fn parse_condition(file: FileId, node: &KdlNode) -> ParseResult<Predicate> {
    let name = kdl_control_alias(node.name().value());
    if name == "when" {
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
    if name == "when" {
        let is_entry = prop_entry(node, "is");
        let is_not_entry = prop_entry(node, "is-not");
        if is_entry.is_some() && is_not_entry.is_some() {
            return Err(Diagnostic::error(
                codes::NODE_SHAPE,
                "`when` takes either `is=` or `is-not=`, not both",
            )
            .with_span(node_span(file, node)));
        }
        if let Some(value_entry) = is_entry.or(is_not_entry) {
            let expected = scalar_value(file, value_entry)?;
            if matches!(expected, Value::Null | Value::Float(_)) {
                return Err(Diagnostic::error(
                    codes::WHEN_PREDICATE,
                    "`is=` compares enum, string, int, or bool literals",
                )
                .with_span(entry_span(file, value_entry)));
            }
            return Ok(Predicate::Eq {
                reference,
                expected,
                negated: is_not_entry.is_some(),
            });
        }
    }
    match name {
        "when" => Ok(Predicate::Test(reference)),
        "when-set" => Ok(Predicate::Set(reference)),
        "when-nonempty" => Ok(Predicate::NonEmpty(reference)),
        _ => Err(Diagnostic::error(
            codes::UNKNOWN_NODE,
            format!("unknown condition `{}`", node.name().value()),
        )
        .with_span(node_span(file, node))),
    }
}

pub(crate) fn is_condition_name(name: &str) -> bool {
    matches!(
        kdl_control_alias(name),
        "when" | "when-set" | "when-nonempty"
    )
}

/// Map `@`-prefixed KDL controls to their unsigiled names. KDL bodies accept
/// both forms; render bodies accept only the `@` forms.
pub(crate) fn kdl_control_alias(name: &str) -> &str {
    match name {
        "@when" => "when",
        "@when-set" => "when-set",
        "@when-nonempty" => "when-nonempty",
        "@each" => "each",
        "@range" => "range",
        "@splice" => "splice",
        "@compose" => "compose",
        "@else" => "else",
        other => other,
    }
}

pub(crate) fn parse_each_header(file: FileId, node: &KdlNode) -> ParseResult<(String, Ref)> {
    reject_unknown_props(file, node, &["in"])?;
    let binding = req_str_arg(file, node)?;
    if binding.is_empty() {
        return Err(
            Diagnostic::error(codes::BINDING, "`each` binding must not be empty")
                .with_span(node_span(file, node)),
        );
    }
    let source = prop_entry(node, "in")
        .ok_or_else(|| {
            Diagnostic::error(codes::NODE_SHAPE, "`each` requires `in=\"source\"`")
                .with_span(node_span(file, node))
        })
        .and_then(|entry| plain_ref(file, entry, "`each in=` reference"))?;
    Ok((binding, source))
}

pub(crate) fn parse_range_header(file: FileId, node: &KdlNode) -> ParseResult<(String, i64, i64)> {
    reject_unknown_props(file, node, &["from", "through"])?;
    let binding = req_str_arg(file, node)?;
    if binding.is_empty() {
        return Err(
            Diagnostic::error(codes::BINDING, "`range` binding must not be empty")
                .with_span(node_span(file, node)),
        );
    }
    let from = int_prop(file, node, "from")?.ok_or_else(|| {
        Diagnostic::error(codes::NODE_SHAPE, "`range` requires `from=<int>`")
            .with_span(node_span(file, node))
    })?;
    let through = int_prop(file, node, "through")?.ok_or_else(|| {
        Diagnostic::error(codes::NODE_SHAPE, "`range` requires `through=<int>`")
            .with_span(node_span(file, node))
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
    plain_ref(file, entry, "`splice` collection reference")
}

/// Convert a scalar KDL value into a typed [`Value`]. Reject refs because the
/// caller decides where references are legal.
pub(crate) fn scalar_value(file: FileId, entry: &KdlEntry) -> ParseResult<Value> {
    if entry.ty().is_some() {
        return Err(Diagnostic::error(
            codes::NODE_SHAPE,
            "type-annotated values are not allowed here",
        )
        .with_span(entry_span(file, entry)));
    }
    match entry.value() {
        KdlValue::Null => Ok(Value::Null),
        KdlValue::Bool(b) => Ok(Value::Bool(*b)),
        KdlValue::Integer(i) => i64::try_from(*i).map(Value::Int).map_err(|_| {
            Diagnostic::error(
                codes::NODE_SHAPE,
                "integer is out of range for a 64-bit value",
            )
            .with_span(entry_span(file, entry))
        }),
        KdlValue::Float(x) => {
            if x.is_finite() {
                Ok(Value::Float(*x))
            } else {
                Err(
                    Diagnostic::error(codes::NODE_SHAPE, "non-finite floats are not allowed")
                        .with_span(entry_span(file, entry)),
                )
            }
        }
        KdlValue::String(s) => Ok(Value::String(s.clone())),
    }
}
