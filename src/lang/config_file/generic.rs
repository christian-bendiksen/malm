//! Format-specific IRs and deterministic serializers for generic config files.

use super::{ConfigItem, ConfigValue, Renderer, config_value, parse_items};
use crate::lang::diag::{Diagnostic, FileId, Span, codes};
use crate::lang::kdl_util::{
    ParseResult, entry_span, node_span, prop_entry, reject_unknown_children, reject_unknown_props,
    validate_document_depth,
};
use crate::lang::value::{Value, format_float};
use kdl::{KdlEntry, KdlNode};
use std::collections::HashSet;

#[derive(Debug)]
pub enum GenericBody {
    Xml {
        declaration: bool,
        root: XmlElement,
    },
    Css {
        items: Vec<ConfigItem<CssNode>>,
        span: Span,
    },
}

impl GenericBody {
    pub fn validator(&self) -> &'static str {
        match self {
            Self::Xml { .. } => "xml",
            Self::Css { .. } => "css",
        }
    }

    pub fn span(&self) -> Span {
        match self {
            Self::Xml { root, .. } => root.span,
            Self::Css { span, .. } => *span,
        }
    }
}

#[derive(Debug)]
pub struct XmlElement {
    pub name: String,
    pub attrs: Vec<(String, ScalarExpr, Span)>,
    pub body: Vec<ConfigItem<XmlNode>>,
    pub span: Span,
}

#[derive(Debug)]
#[allow(dead_code)]
pub enum XmlNode {
    Element(XmlElement),
    Repeat {
        name: String,
        attrs: Vec<(String, ScalarExpr, Span)>,
        values: Vec<ScalarExpr>,
        body: Option<Vec<ConfigItem<XmlNode>>>,
        span: Span,
    },
    Text {
        value: ScalarExpr,
        span: Span,
    },
    Comment {
        text: String,
        span: Span,
    },
}

#[derive(Debug)]
#[allow(dead_code)]
pub enum CssNode {
    Declaration {
        name: String,
        value: ScalarExpr,
        repeated: bool,
        span: Span,
    },
    RepeatValues {
        name: String,
        values: Vec<ScalarExpr>,
        span: Span,
    },
    Rule {
        selector: String,
        body: Vec<ConfigItem<CssNode>>,
        repeated: bool,
        span: Span,
    },
    AtRule {
        name: String,
        prelude: String,
        body: Option<Vec<ConfigItem<CssNode>>>,
        span: Span,
    },
    Comment {
        text: String,
        span: Span,
    },
}

#[derive(Debug)]
pub struct ScalarExpr {
    pub values: Vec<ConfigValue>,
    pub join: String,
    pub span: Span,
}

pub(crate) fn parse(
    file: FileId,
    format: &str,
    output: &KdlNode,
    nodes: &[KdlNode],
    span: Span,
) -> ParseResult<GenericBody> {
    validate_document_depth(file, nodes)?;
    match format {
        "xml" => {
            reject_format_options(file, output, &["declaration"])?;
            if nodes.len() != 1 || is_control_name(nodes[0].name().value()) {
                return Err(Diagnostic::error(
                    codes::NODE_SHAPE,
                    "XML render requires exactly one root element",
                )
                .with_span(span));
            }
            Ok(GenericBody::Xml {
                declaration: bool_option(file, output, "declaration", false)?,
                root: parse_xml_element(file, &nodes[0], None)?,
            })
        }
        "css" => {
            reject_format_options(file, output, &[])?;
            Ok(GenericBody::Css {
                items: parse_items(file, nodes, &parse_css)?,
                span,
            })
        }
        other => Err(Diagnostic::error(
            codes::NODE_SHAPE,
            format!("unsupported body format `{other}` (allowed here: xml, css)"),
        )
        .with_span(span)),
    }
}

fn reject_format_options(file: FileId, node: &KdlNode, allowed: &[&str]) -> ParseResult<()> {
    let all = ["to", "format", "validate"]
        .into_iter()
        .chain(allowed.iter().copied())
        .collect::<Vec<_>>();
    reject_unknown_props(file, node, &all)
}

fn string_option(file: FileId, node: &KdlNode, name: &str) -> ParseResult<Option<String>> {
    let Some(entry) = prop_entry(node, name) else {
        return Ok(None);
    };
    entry
        .value()
        .as_string()
        .map(|value| Some(value.to_owned()))
        .ok_or_else(|| {
            Diagnostic::error(codes::NODE_SHAPE, format!("`{name}=` must be a string"))
                .with_span(entry_span(file, entry))
        })
}

fn bool_option(file: FileId, node: &KdlNode, name: &str, default: bool) -> ParseResult<bool> {
    let Some(entry) = prop_entry(node, name) else {
        return Ok(default);
    };
    entry.value().as_bool().ok_or_else(|| {
        Diagnostic::error(codes::NODE_SHAPE, format!("`{name}=` must be boolean"))
            .with_span(entry_span(file, entry))
    })
}

fn positional(node: &KdlNode) -> Vec<&KdlEntry> {
    node.iter().filter(|entry| entry.name().is_none()).collect()
}

fn literal_name_entry(file: FileId, entry: &KdlEntry, what: &str) -> ParseResult<String> {
    if entry.ty().is_some() {
        return Err(Diagnostic::error(
            codes::NODE_SHAPE,
            format!("{what} must be a literal string"),
        )
        .with_span(entry_span(file, entry)));
    }
    let name = entry
        .value()
        .as_string()
        .filter(|name| !name.is_empty())
        .ok_or_else(|| {
            Diagnostic::error(
                codes::NODE_SHAPE,
                format!("{what} must be a non-empty string"),
            )
            .with_span(entry_span(file, entry))
        })?;
    checked_single_line(name, entry_span(file, entry))?;
    Ok(name.to_owned())
}

fn escaped_name(file: FileId, node: &KdlNode) -> ParseResult<(String, usize)> {
    let args = positional(node);
    let Some(entry) = args.first() else {
        return Err(
            Diagnostic::error(codes::NODE_SHAPE, "`field` requires a name")
                .with_span(node_span(file, node)),
        );
    };
    Ok((literal_name_entry(file, entry, "field name")?, 1))
}

fn node_name(file: FileId, node: &KdlNode) -> ParseResult<(String, usize)> {
    if node.name().value() == "field" {
        escaped_name(file, node)
    } else {
        Ok((node.name().value().to_owned(), 0))
    }
}

fn scalar_expr(file: FileId, node: &KdlNode, skip: usize) -> ParseResult<ScalarExpr> {
    reject_unknown_props(file, node, &["join"])?;
    reject_unknown_children(file, node, &[])?;
    let span = node_span(file, node);
    let values = positional(node)
        .into_iter()
        .skip(skip)
        .map(|entry| config_value(file, entry))
        .collect::<ParseResult<Vec<_>>>()?;
    if values.is_empty() {
        return Err(Diagnostic::error(
            codes::NODE_SHAPE,
            format!("`{}` requires at least one value", node.name().value()),
        )
        .with_span(span));
    }
    let join = string_option(file, node, "join")?.unwrap_or_default();
    checked_single_line(&join, span)?;
    Ok(ScalarExpr { values, join, span })
}

pub(crate) fn validate_ini_name(name: &str, section: bool, span: Span) -> ParseResult<()> {
    let unsafe_delimiter = (!section && name.contains('='))
        || name.contains('[')
        || name.contains(']')
        || name.starts_with('#')
        || name.starts_with(';')
        || name.trim() != name;
    if unsafe_delimiter {
        shape(
            span,
            format!(
                "INI {} name `{name}` contains structural syntax",
                if section { "section" } else { "key" }
            ),
        )
    } else {
        Ok(())
    }
}

fn parse_xml_element(
    file: FileId,
    node: &KdlNode,
    forced_name: Option<String>,
) -> ParseResult<XmlElement> {
    reject_unknown_props(file, node, &[])?;
    let span = node_span(file, node);
    let (name, skip) = match forced_name {
        Some(name) => (name, usize::from(node.name().value() == "field")),
        None => node_name(file, node)?,
    };
    xml_name(&name, span)?;
    let args = positional(node);
    if args.len() != skip {
        return ambiguous(node, span);
    }
    let mut attrs = Vec::new();
    let mut body_nodes = Vec::new();
    let mut seen = HashSet::new();
    for child in node
        .children()
        .map(|children| children.nodes())
        .unwrap_or_default()
    {
        if child.name().value() == "attr" {
            let child_args = positional(child);
            let Some(first) = child_args.first() else {
                return shape(node_span(file, child), "`attr` requires a name and value");
            };
            let attr_name = literal_name_entry(file, first, "attribute name")?;
            xml_name(&attr_name, node_span(file, child))?;
            if !seen.insert(attr_name.clone()) {
                return Err(Diagnostic::error(
                    codes::DUPLICATE,
                    format!("duplicate XML attribute `{attr_name}`"),
                )
                .with_span(node_span(file, child)));
            }
            attrs.push((
                attr_name,
                scalar_expr(file, child, 1)?,
                node_span(file, child),
            ));
        } else {
            body_nodes.push(child.clone());
        }
    }
    Ok(XmlElement {
        name,
        attrs,
        body: parse_items(file, &body_nodes, &parse_xml_node)?,
        span,
    })
}

fn parse_xml_node(file: FileId, node: &KdlNode) -> ParseResult<XmlNode> {
    let span = node_span(file, node);
    match node.name().value() {
        "value" => Ok(XmlNode::Text {
            value: scalar_expr(file, node, 0)?,
            span,
        }),
        "comment" => parse_comment(file, node).map(|text| XmlNode::Comment { text, span }),
        "empty" => {
            reject_unknown_props(file, node, &[])?;
            reject_unknown_children(file, node, &[])?;
            let args = positional(node);
            if args.len() != 1 {
                return shape(span, "`empty` requires exactly one element name");
            }
            let name = literal_name_entry(file, args[0], "element name")?;
            xml_name(&name, span)?;
            Ok(XmlNode::Element(XmlElement {
                name,
                attrs: Vec::new(),
                body: Vec::new(),
                span,
            }))
        }
        "repeat" => {
            reject_unknown_props(file, node, &[])?;
            let args = positional(node);
            let Some(first) = args.first() else {
                return shape(span, "`repeat` requires an element name");
            };
            let name = literal_name_entry(file, first, "repeated element name")?;
            xml_name(&name, span)?;
            if node.children().is_some() {
                if args.len() != 1 {
                    return ambiguous(node, span);
                }
                let mut attrs = Vec::new();
                let mut body_nodes = Vec::new();
                let mut seen = HashSet::new();
                for child in node
                    .children()
                    .map(|children| children.nodes())
                    .unwrap_or_default()
                {
                    if child.name().value() == "attr" {
                        let child_args = positional(child);
                        let Some(first) = child_args.first() else {
                            return shape(
                                node_span(file, child),
                                "`attr` requires a name and value",
                            );
                        };
                        let attr_name = literal_name_entry(file, first, "attribute name")?;
                        xml_name(&attr_name, node_span(file, child))?;
                        if !seen.insert(attr_name.clone()) {
                            return Err(Diagnostic::error(
                                codes::DUPLICATE,
                                format!("duplicate XML attribute `{attr_name}`"),
                            )
                            .with_span(node_span(file, child)));
                        }
                        attrs.push((
                            attr_name,
                            scalar_expr(file, child, 1)?,
                            node_span(file, child),
                        ));
                    } else {
                        body_nodes.push(child.clone());
                    }
                }
                Ok(XmlNode::Repeat {
                    name,
                    attrs,
                    values: Vec::new(),
                    body: Some(parse_items(file, &body_nodes, &parse_xml_node)?),
                    span,
                })
            } else {
                if args.len() < 2 {
                    return shape(span, "`repeat` requires values or a children block");
                }
                Ok(XmlNode::Repeat {
                    name,
                    attrs: Vec::new(),
                    values: args
                        .iter()
                        .skip(1)
                        .map(|entry| {
                            Ok(ScalarExpr {
                                values: vec![config_value(file, entry)?],
                                join: String::new(),
                                span: entry_span(file, entry),
                            })
                        })
                        .collect::<ParseResult<Vec<_>>>()?,
                    body: None,
                    span,
                })
            }
        }
        "attr" | "object" | "array" => {
            shape(span, format!("`{}` is not valid here", node.name().value()))
        }
        _ => {
            let (name, skip) = node_name(file, node)?;
            let args = positional(node);
            if node.children().is_some() {
                if args.len() != skip {
                    return ambiguous(node, span);
                }
                parse_xml_element(file, node, Some(name)).map(XmlNode::Element)
            } else {
                let value = scalar_expr(file, node, skip)?;
                Ok(XmlNode::Element(XmlElement {
                    name,
                    attrs: Vec::new(),
                    body: vec![ConfigItem::Value {
                        value: XmlNode::Text { value, span },
                        span,
                    }],
                    span,
                }))
            }
        }
    }
}

fn parse_css(file: FileId, node: &KdlNode) -> ParseResult<CssNode> {
    let span = node_span(file, node);
    match node.name().value() {
        "comment" => parse_comment(file, node).map(|text| CssNode::Comment { text, span }),
        "at-rule" => {
            reject_unknown_props(file, node, &[])?;
            let args = positional(node);
            if !(1..=2).contains(&args.len()) {
                return shape(span, "`at-rule` requires a name and optional prelude");
            }
            let name = literal_name_entry(file, args[0], "at-rule name")?;
            let prelude = args
                .get(1)
                .map(|entry| literal_name_entry(file, entry, "at-rule prelude"))
                .transpose()?
                .unwrap_or_default();
            css_identifier(&name, span, "at-rule name")?;
            css_header(&prelude, span, "at-rule prelude")?;
            Ok(CssNode::AtRule {
                name,
                prelude,
                body: node
                    .children()
                    .map(|children| parse_items(file, children.nodes(), &parse_css))
                    .transpose()?,
                span,
            })
        }
        "repeat" => {
            reject_unknown_props(file, node, &[])?;
            let args = positional(node);
            let Some(first) = args.first() else {
                return shape(span, "`repeat` requires a declaration or selector name");
            };
            let name = literal_name_entry(file, first, "repeated CSS name")?;
            if node.children().is_some() {
                if args.len() != 1 {
                    return ambiguous(node, span);
                }
                css_header(&name, span, "selector")?;
                Ok(CssNode::Rule {
                    selector: name,
                    body: parse_items(
                        file,
                        node.children()
                            .map(|children| children.nodes())
                            .unwrap_or_default(),
                        &parse_css,
                    )?,
                    repeated: true,
                    span,
                })
            } else {
                if args.len() < 2 {
                    return shape(span, "`repeat` requires values or a children block");
                }
                css_identifier(&name, span, "declaration name")?;
                Ok(CssNode::RepeatValues {
                    name,
                    values: args
                        .iter()
                        .skip(1)
                        .map(|entry| {
                            Ok(ScalarExpr {
                                values: vec![config_value(file, entry)?],
                                join: String::new(),
                                span: entry_span(file, entry),
                            })
                        })
                        .collect::<ParseResult<Vec<_>>>()?,
                    span,
                })
            }
        }
        "empty" | "object" | "array" | "value" => shape(
            span,
            format!("`{}` is not supported in CSS", node.name().value()),
        ),
        _ => {
            let (name, skip) = node_name(file, node)?;
            let args = positional(node);
            if node.children().is_some() {
                reject_unknown_props(file, node, &[])?;
                if args.len() != skip {
                    return ambiguous(node, span);
                }
                css_header(&name, span, "selector")?;
                Ok(CssNode::Rule {
                    selector: name,
                    body: parse_items(
                        file,
                        node.children()
                            .map(|children| children.nodes())
                            .unwrap_or_default(),
                        &parse_css,
                    )?,
                    repeated: false,
                    span,
                })
            } else {
                css_identifier(&name, span, "declaration name")?;
                Ok(CssNode::Declaration {
                    name,
                    value: scalar_expr(file, node, skip)?,
                    repeated: false,
                    span,
                })
            }
        }
    }
}

fn parse_comment(file: FileId, node: &KdlNode) -> ParseResult<String> {
    reject_unknown_props(file, node, &[])?;
    reject_unknown_children(file, node, &[])?;
    let args = positional(node);
    if args.len() != 1 {
        return shape(
            node_span(file, node),
            "`comment` requires exactly one string",
        );
    }
    let text = literal_name_entry(file, args[0], "comment text")?;
    checked_single_line(&text, node_span(file, node))?;
    Ok(text)
}

fn is_control_name(name: &str) -> bool {
    matches!(
        name,
        "array"
            | "object"
            | "value"
            | "field"
            | "repeat"
            | "empty"
            | "comment"
            | "when"
            | "when-set"
            | "when-nonempty"
            | "else"
            | "each"
            | "range"
            | "splice"
    )
}

fn ambiguous<T>(node: &KdlNode, span: Span) -> ParseResult<T> {
    shape(
        span,
        format!(
            "ambiguous `{}` node: use either scalar values or a children block, not both",
            node.name().value()
        ),
    )
}

fn shape<T>(span: Span, message: impl Into<String>) -> ParseResult<T> {
    Err(Diagnostic::error(codes::NODE_SHAPE, message).with_span(span))
}

fn checked_single_line(value: &str, span: Span) -> ParseResult<()> {
    if value.chars().any(char::is_control) {
        shape(
            span,
            "value must not contain control characters or newlines",
        )
    } else {
        Ok(())
    }
}

fn xml_name(value: &str, span: Span) -> ParseResult<()> {
    let mut chars = value.chars();
    let Some(first) = chars.next() else {
        return shape(span, "invalid XML name");
    };
    let start = |character: char| character == '_' || character == ':' || character.is_alphabetic();
    if !start(first)
        || !chars.all(|character| {
            start(character)
                || character.is_ascii_digit()
                || matches!(character, '-' | '.' | '\u{b7}')
        })
    {
        shape(span, "invalid XML name")
    } else {
        Ok(())
    }
}

fn css_identifier(value: &str, span: Span, what: &str) -> ParseResult<()> {
    if value.is_empty()
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
        || value.as_bytes()[0].is_ascii_digit()
    {
        shape(span, format!("invalid CSS {what} `{value}`"))
    } else {
        Ok(())
    }
}

fn css_header(value: &str, span: Span, what: &str) -> ParseResult<()> {
    if value
        .chars()
        .any(|character| matches!(character, '{' | '}' | ';'))
        || value.contains("/*")
        || value.contains("*/")
    {
        shape(span, format!("CSS {what} contains structural syntax"))
    } else {
        Ok(())
    }
}

pub(super) fn render(body: &GenericBody, renderer: &mut Renderer<'_>) -> Option<String> {
    let content = match body {
        GenericBody::Xml { declaration, root } => render_xml(renderer, root, *declaration),
        GenericBody::Css { items, .. } => render_css(renderer, items, 0),
    }?;
    renderer
        .charge_bytes(&content, body.span())
        .then_some(content)
}

fn collect<T>(
    renderer: &mut Renderer<'_>,
    items: &[ConfigItem<T>],
    parser: &dyn Fn(FileId, &KdlNode) -> ParseResult<T>,
    mut render: impl FnMut(&mut Renderer<'_>, &T, Span) -> Option<String>,
) -> Vec<String> {
    let mut output = Vec::new();
    renderer.render_items(items, 0, parser, &mut |renderer, node, span| {
        if let Some(value) = render(renderer, node, span) {
            output.push(value);
        }
    });
    output
}

fn duplicate(renderer: &mut Renderer<'_>, name: &str, span: Span) {
    renderer.diagnostics.push(
        Diagnostic::error(
            codes::DUPLICATE,
            format!("duplicate or redefined key `{name}` after expansion"),
        )
        .with_span(span),
    );
}

pub(crate) fn value_toml(value: &Value) -> Result<String, String> {
    match value {
        Value::Null => Err("TOML does not support null".to_owned()),
        Value::Bool(value) => Ok(value.to_string()),
        Value::Int(value) => Ok(value.to_string()),
        Value::Float(value) => finite_number(*value),
        Value::String(value) | Value::Path(value) => Ok(format!("\"{}\"", json_escape(value))),
        Value::List(values) => Ok(format!(
            "[{}]",
            values
                .iter()
                .map(value_toml)
                .collect::<Result<Vec<_>, _>>()?
                .join(", ")
        )),
        Value::Record(record) => Ok(format!(
            "{{ {} }}",
            record
                .iter()
                .map(|(name, value)| Ok(format!("{} = {}", toml_key(name), value_toml(value)?)))
                .collect::<Result<Vec<_>, String>>()?
                .join(", ")
        )),
        other => Err(format!(
            "{} cannot be represented in TOML",
            other.type_label()
        )),
    }
}

pub(crate) fn toml_key(name: &str) -> String {
    if !name.is_empty()
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        name.to_owned()
    } else {
        format!("\"{}\"", json_escape(name))
    }
}

pub(crate) fn value_json(value: &Value) -> Result<String, String> {
    match value {
        Value::Null => Ok("null".to_owned()),
        Value::Bool(value) => Ok(value.to_string()),
        Value::Int(value) => Ok(value.to_string()),
        Value::Float(value) => finite_number(*value),
        Value::String(value) | Value::Path(value) => Ok(format!("\"{}\"", json_escape(value))),
        Value::List(values) => Ok(format!(
            "[{}]",
            values
                .iter()
                .map(value_json)
                .collect::<Result<Vec<_>, _>>()?
                .join(", ")
        )),
        Value::Record(record) => Ok(format!(
            "{{{}}}",
            record
                .iter()
                .map(|(name, value)| Ok(format!(
                    "\"{}\": {}",
                    json_escape(name),
                    value_json(value)?
                )))
                .collect::<Result<Vec<_>, String>>()?
                .join(", ")
        )),
        other => Err(format!(
            "{} cannot be represented in JSON",
            other.type_label()
        )),
    }
}

pub(crate) fn value_lua(value: &Value) -> Result<String, String> {
    match value {
        Value::Null => Err("Lua config data does not support null".to_owned()),
        Value::Bool(value) => Ok(value.to_string()),
        Value::Int(value) => Ok(value.to_string()),
        Value::Float(value) => finite_number(*value),
        Value::String(value) | Value::Path(value) => Ok(format!("\"{}\"", lua_escape(value))),
        Value::List(values) => Ok(format!(
            "{{{}}}",
            values
                .iter()
                .map(value_lua)
                .collect::<Result<Vec<_>, _>>()?
                .join(", ")
        )),
        Value::Record(record) => Ok(format!(
            "{{{}}}",
            record
                .iter()
                .map(|(name, value)| Ok(format!(
                    "[\"{}\"] = {}",
                    lua_escape(name),
                    value_lua(value)?
                )))
                .collect::<Result<Vec<_>, String>>()?
                .join(", ")
        )),
        other => Err(format!(
            "{} is not accepted by the Lua data serializer",
            other.type_label()
        )),
    }
}

fn finite_number(value: f64) -> Result<String, String> {
    value
        .is_finite()
        .then(|| format_float(value))
        .ok_or_else(|| "non-finite numbers are not supported".to_owned())
}

fn render_xml(renderer: &mut Renderer<'_>, root: &XmlElement, declaration: bool) -> Option<String> {
    let mut output = String::new();
    if declaration {
        output.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    }
    output.push_str(&xml_element(renderer, root, 0)?);
    output.push('\n');
    Some(output)
}

fn xml_element(renderer: &mut Renderer<'_>, element: &XmlElement, depth: usize) -> Option<String> {
    let pad = "  ".repeat(depth);
    let attrs = element
        .attrs
        .iter()
        .map(|(name, value, _)| {
            Some(format!(
                " {name}=\"{}\"",
                xml_escape(&render_scalar_expr(renderer, value)?)
            ))
        })
        .collect::<Option<String>>()?;
    let children = xml_children(renderer, &element.body, depth)?;
    if children.is_empty() {
        Some(format!("{pad}<{}{} />", element.name, attrs))
    } else {
        Some(format!(
            "{pad}<{}{}>\n{}\n{pad}</{}>",
            element.name,
            attrs,
            children.join("\n"),
            element.name
        ))
    }
}

fn xml_group(
    renderer: &mut Renderer<'_>,
    name: &str,
    attrs: &[(String, ScalarExpr, Span)],
    body: &[ConfigItem<XmlNode>],
    depth: usize,
) -> Option<String> {
    let pad = "  ".repeat(depth);
    let attrs = attrs
        .iter()
        .map(|(name, value, _)| {
            Some(format!(
                " {name}=\"{}\"",
                xml_escape(&render_scalar_expr(renderer, value)?)
            ))
        })
        .collect::<Option<String>>()?;
    let children = xml_children(renderer, body, depth)?;
    if children.is_empty() {
        Some(format!("{pad}<{name}{attrs} />"))
    } else {
        Some(format!(
            "{pad}<{name}{attrs}>\n{}\n{pad}</{name}>",
            children.join("\n")
        ))
    }
}

fn xml_children(
    renderer: &mut Renderer<'_>,
    body: &[ConfigItem<XmlNode>],
    depth: usize,
) -> Option<Vec<String>> {
    let child_pad = "  ".repeat(depth + 1);
    Some(collect(
        renderer,
        body,
        &parse_xml_node,
        |renderer, node, _| match node {
            XmlNode::Element(element) => xml_element(renderer, element, depth + 1),
            XmlNode::Text { value, .. } => Some(format!(
                "{child_pad}{}",
                xml_escape(&render_scalar_expr(renderer, value)?)
            )),
            XmlNode::Comment { text, .. } => {
                Some(format!("{child_pad}<!-- {} -->", xml_comment_escape(text)))
            }
            XmlNode::Repeat {
                name,
                attrs,
                values,
                body,
                ..
            } => {
                if let Some(body) = body {
                    xml_group(renderer, name, attrs, body, depth + 1)
                } else {
                    Some(
                        values
                            .iter()
                            .map(|value| {
                                Some(format!(
                                    "{child_pad}<{name}>{}</{name}>",
                                    xml_escape(&render_scalar_expr(renderer, value)?)
                                ))
                            })
                            .collect::<Option<Vec<_>>>()?
                            .join("\n"),
                    )
                }
            }
        },
    ))
}

fn render_css(
    renderer: &mut Renderer<'_>,
    items: &[ConfigItem<CssNode>],
    depth: usize,
) -> Option<String> {
    let pad = "  ".repeat(depth);
    let mut seen = HashSet::new();
    Some(
        collect(
            renderer,
            items,
            &parse_css,
            |renderer, node, span| match node {
                CssNode::Declaration {
                    name,
                    value,
                    repeated,
                    ..
                } => {
                    if !*repeated && !seen.insert(format!("declaration:{name}")) {
                        duplicate(renderer, name, span);
                        return None;
                    }
                    Some(format!(
                        "{pad}{name}: {};\n",
                        render_css_value(renderer, value)?
                    ))
                }
                CssNode::RepeatValues { name, values, .. } => Some(
                    values
                        .iter()
                        .map(|value| {
                            Some(format!(
                                "{pad}{name}: {};\n",
                                render_css_value(renderer, value)?
                            ))
                        })
                        .collect::<Option<String>>()?,
                ),
                CssNode::Rule {
                    selector,
                    body,
                    repeated,
                    ..
                } => {
                    if !*repeated && !seen.insert(format!("rule:{selector}")) {
                        duplicate(renderer, selector, span);
                        return None;
                    }
                    Some(format!(
                        "{pad}{selector} {{\n{}{pad}}}\n",
                        render_css(renderer, body, depth + 1)?
                    ))
                }
                CssNode::AtRule {
                    name,
                    prelude,
                    body,
                    ..
                } => {
                    let suffix = if prelude.is_empty() {
                        String::new()
                    } else {
                        format!(" {prelude}")
                    };
                    match body {
                        Some(body) => Some(format!(
                            "{pad}@{name}{suffix} {{\n{}{pad}}}\n",
                            render_css(renderer, body, depth + 1)?
                        )),
                        None => Some(format!("{pad}@{name}{suffix};\n")),
                    }
                }
                CssNode::Comment { text, .. } => {
                    Some(format!("{pad}/* {} */\n", text.replace("*/", "* /")))
                }
            },
        )
        .concat(),
    )
}

fn render_scalar_expr(renderer: &mut Renderer<'_>, expression: &ScalarExpr) -> Option<String> {
    if !renderer.count_operations(expression.values.len() as u64, expression.span) {
        return None;
    }
    let values = expression
        .values
        .iter()
        .map(|value| scalar(renderer, value))
        .collect::<Option<Vec<_>>>()?;
    let output = values.join(&expression.join);
    if output.chars().any(char::is_control) {
        renderer.diagnostics.push(
            Diagnostic::error(
                codes::TYPE_MISMATCH,
                "composed scalar contains control characters or newlines",
            )
            .with_span(expression.span),
        );
        None
    } else {
        Some(output)
    }
}

fn render_css_value(renderer: &mut Renderer<'_>, expression: &ScalarExpr) -> Option<String> {
    let value = render_scalar_expr(renderer, expression)?;
    if value
        .chars()
        .any(|character| matches!(character, ';' | '{' | '}'))
        || value.contains("/*")
        || value.contains("*/")
    {
        renderer.diagnostics.push(
            Diagnostic::error(
                codes::TYPE_MISMATCH,
                "CSS value contains structural syntax; generate one declaration per node",
            )
            .with_span(expression.span),
        );
        None
    } else {
        Some(value)
    }
}

fn scalar(renderer: &mut Renderer<'_>, expression: &ConfigValue) -> Option<String> {
    let span = expression.span();
    match renderer.resolve(expression)? {
        Value::Bool(value) => Some(value.to_string()),
        Value::Int(value) => Some(value.to_string()),
        Value::Float(value) if value.is_finite() => Some(format_float(value)),
        Value::String(value) | Value::Path(value) if !value.chars().any(char::is_control) => {
            Some(value)
        }
        value => {
            renderer.diagnostics.push(
                Diagnostic::error(
                    codes::TYPE_MISMATCH,
                    format!("expected a safe scalar, found {}", value.type_label()),
                )
                .with_span(span),
            );
            None
        }
    }
}

pub(crate) fn json_escape(value: &str) -> String {
    let mut output = String::new();
    for character in value.chars() {
        match character {
            '"' => output.push_str("\\\""),
            '\\' => output.push_str("\\\\"),
            '\n' => output.push_str("\\n"),
            '\r' => output.push_str("\\r"),
            '\t' => output.push_str("\\t"),
            '\u{08}' => output.push_str("\\b"),
            '\u{0c}' => output.push_str("\\f"),
            character if character.is_control() => {
                use std::fmt::Write as _;
                let _ = write!(output, "\\u{:04x}", character as u32);
            }
            character => output.push(character),
        }
    }
    output
}

pub(crate) fn lua_escape(value: &str) -> String {
    let mut output = String::new();
    for character in value.chars() {
        match character {
            '"' => output.push_str("\\\""),
            '\\' => output.push_str("\\\\"),
            '\n' => output.push_str("\\n"),
            '\r' => output.push_str("\\r"),
            '\t' => output.push_str("\\t"),
            '\u{08}' => output.push_str("\\b"),
            '\u{0c}' => output.push_str("\\f"),
            character if character.is_control() && (character as u32) <= 0xff => {
                use std::fmt::Write as _;
                let _ = write!(output, "\\x{:02x}", character as u32);
            }
            character if character.is_control() => {
                use std::fmt::Write as _;
                let _ = write!(output, "\\u{{{:x}}}", character as u32);
            }
            character => output.push(character),
        }
    }
    output
}

fn xml_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

fn xml_comment_escape(value: &str) -> String {
    value.replace("--", "- -")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lua_escaping_covers_source_breakouts() {
        assert_eq!(lua_escape("a\\\"\n\0"), "a\\\\\\\"\\n\\x00");
    }
}
