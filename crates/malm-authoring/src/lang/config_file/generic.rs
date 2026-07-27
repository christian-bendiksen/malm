//! Format-specific IRs and deterministic serializers for generic config files.

use super::{ConfigItem, ConfigValue, Renderer, config_value, css_value, parse_items};
use crate::lang::budget::OutputBudget;
use crate::lang::diag::{Diagnostic, FileId, Span, codes};
use crate::lang::kdl_util::{
    ParseResult, at_entry, at_node, child_nodes, entry_span, node_span, prop_entry,
    reject_unknown_children, reject_unknown_props, validate_document_depth,
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
    pub fn format_name(&self) -> &'static str {
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
    let all = ["to", "format"]
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
            at_entry(file, entry).error(codes::NODE_SHAPE, format!("`{name}=` must be a string"))
        })
}

fn bool_option(file: FileId, node: &KdlNode, name: &str, default: bool) -> ParseResult<bool> {
    let Some(entry) = prop_entry(node, name) else {
        return Ok(default);
    };
    entry.value().as_bool().ok_or_else(|| {
        at_entry(file, entry).error(codes::NODE_SHAPE, format!("`{name}=` must be boolean"))
    })
}

fn positional(node: &KdlNode) -> Vec<&KdlEntry> {
    node.iter().filter(|entry| entry.name().is_none()).collect()
}

fn literal_name_entry(file: FileId, entry: &KdlEntry, what: &str) -> ParseResult<String> {
    if entry.ty().is_some() {
        return Err(at_entry(file, entry).error(
            codes::NODE_SHAPE,
            format!("{what} must be a literal string"),
        ));
    }
    let name = entry
        .value()
        .as_string()
        .filter(|name| !name.is_empty())
        .ok_or_else(|| {
            at_entry(file, entry).error(
                codes::NODE_SHAPE,
                format!("{what} must be a non-empty string"),
            )
        })?;
    checked_single_line(name, entry_span(file, entry))?;
    Ok(name.to_owned())
}

fn escaped_name(file: FileId, node: &KdlNode) -> ParseResult<(String, usize)> {
    let args = positional(node);
    let Some(entry) = args.first() else {
        return Err(at_node(file, node).error(codes::NODE_SHAPE, "`field` requires a name"));
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

fn scalar_expr(
    file: FileId,
    node: &KdlNode,
    skip: usize,
    parse_value: fn(FileId, &KdlEntry) -> ParseResult<ConfigValue>,
) -> ParseResult<ScalarExpr> {
    reject_unknown_props(file, node, &["join"])?;
    reject_unknown_children(file, node, &[])?;
    let span = node_span(file, node);
    let values = positional(node)
        .into_iter()
        .skip(skip)
        .map(|entry| parse_value(file, entry))
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
    let children = child_nodes(node);
    validate_xml_else_adjacency(file, children)?;
    for child in children {
        if child.name().value() == "attr" {
            let child_args = positional(child);
            let Some(first) = child_args.first() else {
                return shape(node_span(file, child), "`attr` requires a name and value");
            };
            let attr_name = literal_name_entry(file, first, "attribute name")?;
            xml_name(&attr_name, node_span(file, child))?;
            if !seen.insert(attr_name.clone()) {
                return Err(at_node(file, child).error(
                    codes::DUPLICATE,
                    format!("duplicate XML attribute `{attr_name}`"),
                ));
            }
            attrs.push((
                attr_name,
                scalar_expr(file, child, 1, config_value)?,
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
            value: scalar_expr(file, node, 0, config_value)?,
            span,
        }),
        "@comment" => parse_comment(file, node).map(|text| XmlNode::Comment { text, span }),
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
                let children = child_nodes(node);
                validate_xml_else_adjacency(file, children)?;
                for child in children {
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
                            return Err(at_node(file, child).error(
                                codes::DUPLICATE,
                                format!("duplicate XML attribute `{attr_name}`"),
                            ));
                        }
                        attrs.push((
                            attr_name,
                            scalar_expr(file, child, 1, config_value)?,
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
                let value = scalar_expr(file, node, skip, config_value)?;
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

fn validate_xml_else_adjacency(file: FileId, nodes: &[KdlNode]) -> ParseResult<()> {
    for (index, node) in nodes.iter().enumerate() {
        if node.name().value() == "@else"
            && index
                .checked_sub(1)
                .and_then(|index| nodes.get(index))
                .is_none_or(|previous| {
                    !matches!(
                        previous.name().value(),
                        "@if" | "@if-present" | "@if-nonempty"
                    )
                })
        {
            return Err(at_node(file, node).error(
                codes::NODE_SHAPE,
                "`@else` must immediately follow an `@if`, `@if-present`, or `@if-nonempty` sibling",
            ));
        }
    }
    Ok(())
}

fn parse_css(file: FileId, node: &KdlNode) -> ParseResult<CssNode> {
    let span = node_span(file, node);
    match node.name().value() {
        "@comment" => parse_comment(file, node).map(|text| CssNode::Comment { text, span }),
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
                    body: parse_items(file, child_nodes(node), &parse_css)?,
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
                                values: vec![css_value(file, entry)?],
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
                    body: parse_items(file, child_nodes(node), &parse_css)?,
                    repeated: false,
                    span,
                })
            } else {
                css_identifier(&name, span, "declaration name")?;
                Ok(CssNode::Declaration {
                    name,
                    value: scalar_expr(file, node, skip, css_value)?,
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
            "`@comment` requires exactly one string",
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
            | "@comment"
            | "@if"
            | "@if-present"
            | "@if-nonempty"
            | "@else"
            | "@for-each"
            | "@for-range"
            | "@insert-documents"
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

pub(super) fn render(
    body: &GenericBody,
    renderer: &mut Renderer<'_>,
    output_budget: &mut OutputBudget,
) -> Option<String> {
    match body {
        GenericBody::Xml { declaration, root } => {
            render_xml(renderer, output_budget, root, *declaration)
        }
        GenericBody::Css { items, .. } => render_css(renderer, output_budget, items, 0),
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

fn render_xml(
    renderer: &mut Renderer<'_>,
    output_budget: &mut OutputBudget,
    root: &XmlElement,
    declaration: bool,
) -> Option<String> {
    let mut output = String::new();
    if declaration {
        output_budget.push_str(&mut output, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n")?;
    }
    let element = xml_element(renderer, output_budget, root, 0)?;
    OutputBudget::append_accounted(&mut output, &element);
    output_budget.push_char(&mut output, '\n')?;
    Some(output)
}

fn xml_element(
    renderer: &mut Renderer<'_>,
    output_budget: &mut OutputBudget,
    element: &XmlElement,
    depth: usize,
) -> Option<String> {
    let children = xml_children(renderer, output_budget, &element.body, depth)?;
    let mut output = String::new();
    write_indent(output_budget, &mut output, depth)?;
    output_budget.write_fmt(&mut output, format_args!("<{}", element.name))?;
    write_xml_attrs(renderer, output_budget, &mut output, &element.attrs)?;
    if children.is_empty() {
        output_budget.push_str(&mut output, " />")?;
    } else {
        output_budget.push_str(&mut output, ">\n")?;
        OutputBudget::append_accounted(&mut output, &children);
        output_budget.push_char(&mut output, '\n')?;
        write_indent(output_budget, &mut output, depth)?;
        output_budget.write_fmt(&mut output, format_args!("</{}>", element.name))?;
    }
    Some(output)
}

fn xml_group(
    renderer: &mut Renderer<'_>,
    output_budget: &mut OutputBudget,
    name: &str,
    attrs: &[(String, ScalarExpr, Span)],
    body: &[ConfigItem<XmlNode>],
    depth: usize,
) -> Option<String> {
    let children = xml_children(renderer, output_budget, body, depth)?;
    let mut output = String::new();
    write_indent(output_budget, &mut output, depth)?;
    output_budget.write_fmt(&mut output, format_args!("<{name}"))?;
    write_xml_attrs(renderer, output_budget, &mut output, attrs)?;
    if children.is_empty() {
        output_budget.push_str(&mut output, " />")?;
    } else {
        output_budget.push_str(&mut output, ">\n")?;
        OutputBudget::append_accounted(&mut output, &children);
        output_budget.push_char(&mut output, '\n')?;
        write_indent(output_budget, &mut output, depth)?;
        output_budget.write_fmt(&mut output, format_args!("</{name}>"))?;
    }
    Some(output)
}

fn write_xml_attrs(
    renderer: &mut Renderer<'_>,
    output_budget: &mut OutputBudget,
    output: &mut String,
    attrs: &[(String, ScalarExpr, Span)],
) -> Option<()> {
    for (name, value, _) in attrs {
        output_budget.write_fmt(output, format_args!(" {name}=\""))?;
        write_xml_scalar_expr(renderer, output_budget, output, value)?;
        output_budget.push_char(output, '"')?;
    }
    Some(())
}

fn xml_children(
    renderer: &mut Renderer<'_>,
    output_budget: &mut OutputBudget,
    body: &[ConfigItem<XmlNode>],
    depth: usize,
) -> Option<String> {
    let mut output = String::new();
    let mut first = true;
    let parser = |file: FileId, nodes: &[KdlNode]| parse_items(file, nodes, &parse_xml_node);
    renderer.walk_all(body, 0, &parser, &mut |renderer, node, _| {
        match node {
            XmlNode::Element(element) => {
                let child = xml_element(renderer, output_budget, element, depth + 1)?;
                begin_xml_child(output_budget, &mut output, &mut first)?;
                OutputBudget::append_accounted(&mut output, &child);
            }
            XmlNode::Text { value, .. } => {
                begin_xml_child(output_budget, &mut output, &mut first)?;
                write_indent(output_budget, &mut output, depth + 1)?;
                write_xml_scalar_expr(renderer, output_budget, &mut output, value)?;
            }
            XmlNode::Comment { text, .. } => {
                begin_xml_child(output_budget, &mut output, &mut first)?;
                write_indent(output_budget, &mut output, depth + 1)?;
                output_budget.push_str(&mut output, "<!-- ")?;
                write_xml_comment(output_budget, &mut output, text)?;
                output_budget.push_str(&mut output, " -->")?;
            }
            XmlNode::Repeat {
                name,
                attrs,
                values,
                body,
                ..
            } => {
                if let Some(body) = body {
                    let child = xml_group(renderer, output_budget, name, attrs, body, depth + 1)?;
                    begin_xml_child(output_budget, &mut output, &mut first)?;
                    OutputBudget::append_accounted(&mut output, &child);
                } else {
                    for value in values {
                        begin_xml_child(output_budget, &mut output, &mut first)?;
                        write_indent(output_budget, &mut output, depth + 1)?;
                        output_budget.write_fmt(&mut output, format_args!("<{name}>"))?;
                        write_xml_scalar_expr(renderer, output_budget, &mut output, value)?;
                        output_budget.write_fmt(&mut output, format_args!("</{name}>"))?;
                    }
                }
            }
        }
        Some(())
    })?;
    Some(output)
}

fn begin_xml_child(
    output_budget: &mut OutputBudget,
    output: &mut String,
    first: &mut bool,
) -> Option<()> {
    if !*first {
        output_budget.push_char(output, '\n')?;
    }
    *first = false;
    Some(())
}

fn render_css(
    renderer: &mut Renderer<'_>,
    output_budget: &mut OutputBudget,
    items: &[ConfigItem<CssNode>],
    depth: usize,
) -> Option<String> {
    let mut output = String::new();
    let mut seen = HashSet::new();
    let parser = |file: FileId, nodes: &[KdlNode]| parse_items(file, nodes, &parse_css);
    renderer.walk_all(items, 0, &parser, &mut |renderer, node, span| {
        match node {
            CssNode::Declaration {
                name,
                value,
                repeated,
                ..
            } => {
                if !*repeated && !seen.insert(format!("declaration:{name}")) {
                    renderer.duplicate(name, span);
                    return None;
                }
                write_indent(output_budget, &mut output, depth)?;
                output_budget.write_fmt(&mut output, format_args!("{name}: "))?;
                let value = render_css_value(renderer, output_budget, value)?;
                OutputBudget::append_accounted(&mut output, &value);
                output_budget.push_str(&mut output, ";\n")?;
            }
            CssNode::RepeatValues { name, values, .. } => {
                for value in values {
                    write_indent(output_budget, &mut output, depth)?;
                    output_budget.write_fmt(&mut output, format_args!("{name}: "))?;
                    let value = render_css_value(renderer, output_budget, value)?;
                    OutputBudget::append_accounted(&mut output, &value);
                    output_budget.push_str(&mut output, ";\n")?;
                }
            }
            CssNode::Rule {
                selector,
                body,
                repeated,
                ..
            } => {
                if !*repeated && !seen.insert(format!("rule:{selector}")) {
                    renderer.duplicate(selector, span);
                    return None;
                }
                write_indent(output_budget, &mut output, depth)?;
                output_budget.write_fmt(&mut output, format_args!("{selector} {{\n"))?;
                let body = render_css(renderer, output_budget, body, depth + 1)?;
                OutputBudget::append_accounted(&mut output, &body);
                write_indent(output_budget, &mut output, depth)?;
                output_budget.push_str(&mut output, "}\n")?;
            }
            CssNode::AtRule {
                name,
                prelude,
                body,
                ..
            } => {
                write_indent(output_budget, &mut output, depth)?;
                output_budget.write_fmt(&mut output, format_args!("@{name}"))?;
                if !prelude.is_empty() {
                    output_budget.write_fmt(&mut output, format_args!(" {prelude}"))?;
                }
                match body {
                    Some(body) => {
                        output_budget.push_str(&mut output, " {\n")?;
                        let body = render_css(renderer, output_budget, body, depth + 1)?;
                        OutputBudget::append_accounted(&mut output, &body);
                        write_indent(output_budget, &mut output, depth)?;
                        output_budget.push_str(&mut output, "}\n")?;
                    }
                    None => output_budget.push_str(&mut output, ";\n")?,
                }
            }
            CssNode::Comment { text, .. } => {
                write_indent(output_budget, &mut output, depth)?;
                output_budget.push_str(&mut output, "/* ")?;
                write_css_comment(output_budget, &mut output, text)?;
                output_budget.push_str(&mut output, " */\n")?;
            }
        }
        Some(())
    })?;
    Some(output)
}

fn render_css_value(
    renderer: &mut Renderer<'_>,
    output_budget: &mut OutputBudget,
    expression: &ScalarExpr,
) -> Option<String> {
    let mut value = String::new();
    write_scalar_expr(renderer, output_budget, &mut value, expression)?;
    if value
        .chars()
        .any(|character| matches!(character, ';' | '{' | '}'))
        || value.contains("/*")
        || value.contains("*/")
    {
        renderer.diagnostics.error_at(
            codes::TYPE_MISMATCH,
            "CSS value contains structural syntax; generate one declaration per node",
            expression.span,
        );
        None
    } else {
        Some(value)
    }
}

fn write_scalar_expr(
    renderer: &mut Renderer<'_>,
    output_budget: &mut OutputBudget,
    output: &mut String,
    expression: &ScalarExpr,
) -> Option<()> {
    if !renderer.count_operations(expression.values.len() as u64, expression.span) {
        return None;
    }
    for (index, value) in expression.values.iter().enumerate() {
        if index != 0 {
            output_budget.push_str(output, &expression.join)?;
        }
        output_budget.push_str(output, &scalar(renderer, value)?)?;
    }
    Some(())
}

fn write_xml_scalar_expr(
    renderer: &mut Renderer<'_>,
    output_budget: &mut OutputBudget,
    output: &mut String,
    expression: &ScalarExpr,
) -> Option<()> {
    if !renderer.count_operations(expression.values.len() as u64, expression.span) {
        return None;
    }
    for (index, value) in expression.values.iter().enumerate() {
        if index != 0 {
            write_xml_escaped(output_budget, output, &expression.join)?;
        }
        write_xml_escaped(output_budget, output, &scalar(renderer, value)?)?;
    }
    Some(())
}

fn write_indent(output_budget: &mut OutputBudget, output: &mut String, depth: usize) -> Option<()> {
    for _ in 0..depth {
        output_budget.push_str(output, "  ")?;
    }
    Some(())
}

fn write_xml_escaped(
    output_budget: &mut OutputBudget,
    output: &mut String,
    value: &str,
) -> Option<()> {
    for character in value.chars() {
        match character {
            '&' => output_budget.push_str(output, "&amp;")?,
            '<' => output_budget.push_str(output, "&lt;")?,
            '>' => output_budget.push_str(output, "&gt;")?,
            '"' => output_budget.push_str(output, "&quot;")?,
            '\'' => output_budget.push_str(output, "&apos;")?,
            character => output_budget.push_char(output, character)?,
        }
    }
    Some(())
}

fn write_xml_comment(
    output_budget: &mut OutputBudget,
    output: &mut String,
    value: &str,
) -> Option<()> {
    let mut parts = value.split("--");
    if let Some(first) = parts.next() {
        output_budget.push_str(output, first)?;
    }
    for part in parts {
        output_budget.push_str(output, "- -")?;
        output_budget.push_str(output, part)?;
    }
    Some(())
}

fn write_css_comment(
    output_budget: &mut OutputBudget,
    output: &mut String,
    value: &str,
) -> Option<()> {
    let mut parts = value.split("*/");
    if let Some(first) = parts.next() {
        output_budget.push_str(output, first)?;
    }
    for part in parts {
        output_budget.push_str(output, "* /")?;
        output_budget.push_str(output, part)?;
    }
    Some(())
}

fn scalar(renderer: &mut Renderer<'_>, expression: &ConfigValue) -> Option<String> {
    let span = expression.span();
    match renderer.resolve_value(expression)? {
        Value::Bool(value) => Some(value.to_string()),
        Value::Int(value) => Some(value.to_string()),
        Value::Float(value) if value.is_finite() => Some(format_float(value)),
        Value::String(value) | Value::Path(value) if !value.chars().any(char::is_control) => {
            Some(value)
        }
        value => {
            renderer.diagnostics.error_at(
                codes::TYPE_MISMATCH,
                format!("expected a safe scalar, found {}", value.type_label()),
                span,
            );
            None
        }
    }
}

/// Returns the escape shared by JSON and Lua for this character.
fn escape_shared(character: char) -> Option<&'static str> {
    Some(match character {
        '"' => "\\\"",
        '\\' => "\\\\",
        '\n' => "\\n",
        '\r' => "\\r",
        '\t' => "\\t",
        '\u{08}' => "\\b",
        '\u{0c}' => "\\f",
        _ => return None,
    })
}

pub(crate) fn json_escape(value: &str) -> String {
    let mut output = String::new();
    write_json_escape(&mut output, value).expect("writing to a String cannot fail");
    output
}

pub(crate) fn lua_escape(value: &str) -> String {
    let mut output = String::new();
    write_lua_escape(&mut output, value).expect("writing to a String cannot fail");
    output
}

pub(crate) fn write_json_escape(
    output: &mut impl std::fmt::Write,
    value: &str,
) -> std::fmt::Result {
    write_escape(output, value, |output, character| {
        write!(output, "\\u{:04x}", character as u32)
    })
}

pub(crate) fn write_lua_escape(output: &mut impl std::fmt::Write, value: &str) -> std::fmt::Result {
    write_escape(output, value, |output, character| {
        if (character as u32) <= 0xff {
            write!(output, "\\x{:02x}", character as u32)
        } else {
            write!(output, "\\u{{{:x}}}", character as u32)
        }
    })
}

fn write_escape(
    output: &mut impl std::fmt::Write,
    value: &str,
    mut control: impl FnMut(&mut dyn std::fmt::Write, char) -> std::fmt::Result,
) -> std::fmt::Result {
    for character in value.chars() {
        match escape_shared(character) {
            Some(escape) => output.write_str(escape)?,
            None if character.is_control() => control(output, character)?,
            None => output.write_char(character)?,
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lua_escaping_covers_source_breakouts() {
        assert_eq!(lua_escape("a\\\"\n\0"), "a\\\\\\\"\\n\\x00");
    }
}
