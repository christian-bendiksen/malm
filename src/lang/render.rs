//! Parsing and serialization for JSON, JSONC, TOML, INI, text, and Lua render
//! outputs. Only `@`-prefixed node names are controls; all others are target
//! data.

use crate::lang::ast::{EachBlock, Predicate, RangeBlock, Ref, WhenBlock};
use crate::lang::budget::Budget;
use crate::lang::config_file::ConfigItem;
use crate::lang::config_file::generic::{
    json_escape, lua_escape, toml_key, validate_ini_name, value_json, value_lua, value_toml,
};
use crate::lang::diag::{Diagnostic, Diagnostics, FileId, Span, codes};
use crate::lang::kdl_util::{
    ParseResult, bool_prop, entry_span, expect_args, int_prop, node_span, opt_str_prop, prop_entry,
    reject_unknown_children, reject_unknown_props, req_str_arg, req_str_prop,
    validate_document_depth,
};
use crate::lang::scope::Scope;
use crate::lang::text::{self, TemplateSyntax};
use crate::lang::value::{Value, format_float};
use kdl::{KdlEntry, KdlNode, KdlValue};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

// IR

#[derive(Debug)]
pub struct RenderOutput {
    pub to: PathExpr,
    pub body: RenderBody,
    pub validate: Option<String>,
    pub executable: bool,
    /// Directory of the declaring file (for `@file "./…"` sources).
    pub dir: PathBuf,
    pub span: Span,
}

/// A render destination: literal, or an `(f)` template resolved per
/// expansion (loop bindings apply).
#[derive(Debug)]
pub enum PathExpr {
    Literal(String),
    FString { raw: String, span: Span },
}

#[derive(Debug)]
pub struct RenderBody {
    pub format: FormatSpec,
    pub items: Vec<ConfigItem<ShapeNode>>,
    pub span: Span,
}

#[derive(Debug)]
pub enum FormatSpec {
    Json { comments: bool, indent: String },
    Toml,
    Ini(IniOpts),
    Text(TextOpts),
    Lua { indent: String },
}

#[derive(Debug)]
pub struct IniOpts {
    pub separator: String,
    pub quote: QuoteMode,
}

#[derive(Debug)]
pub struct TextOpts {
    pub separator: String,
    pub layout: TextLayout,
    pub quote: QuoteMode,
    pub indent: String,
    pub single: bool,
    pub final_newline: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TextLayout {
    Braces,
    Flat,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuoteMode {
    None,
    Double,
}

impl FormatSpec {
    pub fn validator(&self) -> &'static str {
        match self {
            Self::Json {
                comments: false, ..
            } => "json",
            Self::Json { comments: true, .. } => "jsonc",
            Self::Toml => "toml",
            Self::Ini(_) => "ini",
            Self::Text(_) => "key-value",
            Self::Lua { .. } => "lua",
        }
    }
}

/// A data node: `name args… props… { children }`, an array element (`-`), or
/// a directive leaf.
#[derive(Debug)]
pub enum ShapeNode {
    Entry(Entry),
    Comment {
        text: String,
        span: Span,
    },
    Raw {
        text: String,
        span: Span,
    },
    Line {
        value: ValueExpr,
        span: Span,
    },
    /// `@spread "rec"`: emit every record field as a key/value here.
    Spread(Spread),
    /// `@file "./x" [interpolate=#true]`: include a module-relative file.
    File {
        path: String,
        interpolate: bool,
        span: Span,
    },
    /// `@compose "frag"`: inline the composed fragment.
    Compose {
        fragment: String,
        span: Span,
    },
}

#[derive(Debug)]
pub struct Spread {
    pub reference: Ref,
    pub case: SpreadCase,
    pub span: Span,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpreadCase {
    Verbatim,
    Snake,
    Kebab,
    Camel,
}

impl SpreadCase {
    fn apply(self, name: &str) -> String {
        match self {
            Self::Verbatim => name.to_owned(),
            Self::Snake => name.replace('-', "_"),
            Self::Kebab => name.replace('_', "-"),
            Self::Camel => {
                let mut out = String::with_capacity(name.len());
                let mut upper_next = false;
                for character in name.chars() {
                    if character == '-' || character == '_' {
                        upper_next = true;
                    } else if upper_next {
                        out.extend(character.to_uppercase());
                        upper_next = false;
                    } else {
                        out.push(character);
                    }
                }
                out
            }
        }
    }
}

#[derive(Debug)]
pub struct Entry {
    /// `None` for `-` array elements.
    pub name: Option<NodeName>,
    pub args: Vec<ValueExpr>,
    pub props: Vec<(String, ValueExpr, Span)>,
    pub children: Option<Vec<ConfigItem<ShapeNode>>>,
    /// Per-entry `@quote=` override (ini/text only).
    pub quote: Option<QuoteMode>,
    pub span: Span,
}

#[derive(Debug)]
pub enum NodeName {
    Literal(String),
    FString { raw: String, span: Span },
}

#[derive(Debug)]
pub enum ValueExpr {
    Literal(Value, Span),
    Ref { reference: Ref, optional: bool },
    FString { raw: String, span: Span },
    Raw(String, Span),
}

impl ValueExpr {
    pub fn span(&self) -> Span {
        match self {
            Self::Literal(_, span) | Self::Raw(_, span) | Self::FString { span, .. } => *span,
            Self::Ref { reference, .. } => reference.span,
        }
    }
}

impl ShapeNode {
    pub fn span(&self) -> Span {
        match self {
            Self::Entry(entry) => entry.span,
            Self::Comment { span, .. }
            | Self::Raw { span, .. }
            | Self::Line { span, .. }
            | Self::File { span, .. }
            | Self::Compose { span, .. } => *span,
            Self::Spread(spread) => spread.span,
        }
    }
}

// Parsing

const FORMATS_HELP: &str = "allowed: json, jsonc, toml, kdl, ini, text, lua, xml, css (aliases: key-value, line-list, scalar)";

pub(crate) fn parse_render(
    file: FileId,
    dir: &Path,
    node: &KdlNode,
) -> ParseResult<crate::lang::ast::OutputNode> {
    use crate::lang::ast::{KdlConfigBody, KdlConfigOutput, KdlDialect, OutputNode};
    let span = node_span(file, node);
    if prop_entry(node, "to").is_some() {
        return Err(Diagnostic::error(
            codes::NODE_SHAPE,
            "`render` takes the destination path as its first argument, not `to=`",
        )
        .with_span(span));
    }
    let to = render_path(file, node)?;
    let format = req_str_prop(file, node, "format")?;
    let validate = opt_str_prop(file, node, "validate")?;
    let executable = bool_prop(file, node, "executable")?;
    let children: &[KdlNode] = node
        .children()
        .map(|children| children.nodes())
        .unwrap_or_default();

    match format.as_str() {
        "kdl" => {
            if executable {
                return Err(executable_unsupported(span, "kdl"));
            }
            reject_render_props(file, node, &["version"])?;
            let dialect = match int_prop(file, node, "version")? {
                None | Some(2) => KdlDialect::V2,
                Some(1) => KdlDialect::V1,
                Some(other) => {
                    return Err(Diagnostic::error(
                        codes::NODE_SHAPE,
                        format!("KDL render version `{other}` is invalid (allowed: 1, 2)"),
                    )
                    .with_span(span));
                }
            };
            let nodes = children.to_vec();
            validate_document_depth(file, &nodes)?;
            crate::lang::parse::validate_structural_kdl_nodes(file, &nodes)?;
            let to = literal_path(to, span, "kdl")?;
            Ok(OutputNode::KdlConfig(KdlConfigOutput {
                to,
                dialect,
                body: KdlConfigBody::Document { nodes, span, file },
                validate,
                span,
            }))
        }
        "xml" | "css" => {
            if executable {
                return Err(executable_unsupported(span, &format));
            }
            let body = crate::lang::config_file::parse_body(file, &format, node, children, span)?;
            let to = literal_path(to, span, &format)?;
            Ok(OutputNode::ConfigFile(
                crate::lang::config_file::ConfigFileOutput {
                    to,
                    body,
                    validate,
                    span,
                },
            ))
        }
        _ => {
            let format = parse_format_spec(file, node, &format, span)?;
            validate_document_depth(file, children)?;
            let items = parse_items(file, children)?;
            Ok(OutputNode::Render(RenderOutput {
                to,
                body: RenderBody {
                    format,
                    items,
                    span,
                },
                validate,
                executable,
                dir: dir.to_path_buf(),
                span,
            }))
        }
    }
}

fn executable_unsupported(span: Span, format: &str) -> Diagnostic {
    Diagnostic::error(
        codes::NODE_SHAPE,
        format!("`executable=` is not supported for `format=\"{format}\"`"),
    )
    .with_span(span)
}

fn render_path(file: FileId, node: &KdlNode) -> ParseResult<PathExpr> {
    let args: Vec<&KdlEntry> = node.iter().filter(|entry| entry.name().is_none()).collect();
    let Some(first) = args.first() else {
        return Err(Diagnostic::error(
            codes::NODE_SHAPE,
            "`render` requires a destination path as its first argument",
        )
        .with_span(node_span(file, node)));
    };
    if args.len() > 1 {
        return Err(Diagnostic::error(
            codes::NODE_SHAPE,
            "`render` takes exactly one positional argument (the destination path)",
        )
        .with_span(entry_span(file, args[1])));
    }
    let span = entry_span(file, first);
    let text = first
        .value()
        .as_string()
        .filter(|path| !path.is_empty())
        .ok_or_else(|| {
            Diagnostic::error(
                codes::NODE_SHAPE,
                "the `render` destination must be a non-empty string",
            )
            .with_span(span)
        })?;
    match first.ty().map(|ty| ty.value()) {
        None => Ok(PathExpr::Literal(text.to_owned())),
        Some("f") => {
            if let Err(message) = text::parse_template_with(text, TemplateSyntax::V3) {
                return Err(Diagnostic::error(codes::TEMPLATE, message).with_span(span));
            }
            Ok(PathExpr::FString {
                raw: text.to_owned(),
                span,
            })
        }
        Some(other) => Err(Diagnostic::error(
            codes::NODE_SHAPE,
            format!("unknown path annotation `({other})` (only `(f)` is supported)"),
        )
        .with_span(span)),
    }
}

fn literal_path(to: PathExpr, span: Span, format: &str) -> ParseResult<String> {
    match to {
        PathExpr::Literal(path) => Ok(path),
        PathExpr::FString { .. } => Err(Diagnostic::error(
            codes::NODE_SHAPE,
            format!("`format=\"{format}\"` outputs do not support `(f)` destination paths yet"),
        )
        .with_span(span)),
    }
}

fn reject_render_props(file: FileId, node: &KdlNode, extra: &[&str]) -> ParseResult<()> {
    let all: Vec<&str> = ["format", "validate", "executable"]
        .into_iter()
        .chain(extra.iter().copied())
        .collect();
    reject_unknown_props(file, node, &all)
}

fn parse_format_spec(
    file: FileId,
    node: &KdlNode,
    format: &str,
    span: Span,
) -> ParseResult<FormatSpec> {
    match format {
        "json" | "jsonc" => {
            reject_render_props(file, node, &["indent"])?;
            Ok(FormatSpec::Json {
                comments: format == "jsonc",
                indent: indent_option(file, node, "  ")?,
            })
        }
        "toml" => {
            reject_render_props(file, node, &[])?;
            Ok(FormatSpec::Toml)
        }
        "ini" => {
            reject_render_props(file, node, &["separator", "quote", "section-names"])?;
            if let Some(names) = opt_str_prop(file, node, "section-names")?
                && names != "dotted"
            {
                return Err(Diagnostic::error(
                    codes::NODE_SHAPE,
                    format!("`section-names=\"{names}\"` is not implemented yet (allowed: dotted)"),
                )
                .with_span(span));
            }
            Ok(FormatSpec::Ini(IniOpts {
                separator: separator_option(file, node, "=")?,
                quote: quote_option(file, node, span)?,
            }))
        }
        "lua" => {
            reject_render_props(file, node, &["indent"])?;
            Ok(FormatSpec::Lua {
                indent: indent_option(file, node, "    ")?,
            })
        }
        "text" | "key-value" | "line-list" | "scalar" => {
            reject_render_props(
                file,
                node,
                &[
                    "separator",
                    "layout",
                    "quote",
                    "indent",
                    "single",
                    "final-newline",
                ],
            )?;
            let layout = match opt_str_prop(file, node, "layout")?.as_deref() {
                None | Some("braces") => TextLayout::Braces,
                Some("flat") => TextLayout::Flat,
                Some(other) => {
                    return Err(Diagnostic::error(
                        codes::NODE_SHAPE,
                        format!("unknown text layout `{other}` (allowed: braces, flat)"),
                    )
                    .with_span(span));
                }
            };
            let single = match prop_entry(node, "single") {
                Some(_) => bool_prop(file, node, "single")?,
                None => format == "scalar",
            };
            let final_newline = match prop_entry(node, "final-newline") {
                Some(entry) => entry.value().as_bool().ok_or_else(|| {
                    Diagnostic::error(codes::NODE_SHAPE, "`final-newline=` must be boolean")
                        .with_span(entry_span(file, entry))
                })?,
                None => true,
            };
            Ok(FormatSpec::Text(TextOpts {
                separator: separator_option(file, node, " = ")?,
                layout,
                quote: quote_option(file, node, span)?,
                indent: indent_option(file, node, "    ")?,
                single,
                final_newline,
            }))
        }
        other => Err(Diagnostic::error(
            codes::NODE_SHAPE,
            format!("unsupported render format `{other}` ({FORMATS_HELP})"),
        )
        .with_span(span)),
    }
}

fn separator_option(file: FileId, node: &KdlNode, default: &str) -> ParseResult<String> {
    let separator = opt_str_prop(file, node, "separator")?.unwrap_or_else(|| default.to_owned());
    if separator.chars().any(char::is_control) {
        return Err(Diagnostic::error(
            codes::NODE_SHAPE,
            "`separator=` must not contain control characters",
        )
        .with_span(node_span(file, node)));
    }
    Ok(separator)
}

fn quote_option(file: FileId, node: &KdlNode, span: Span) -> ParseResult<QuoteMode> {
    match opt_str_prop(file, node, "quote")?.as_deref() {
        None | Some("none") => Ok(QuoteMode::None),
        Some("double") => Ok(QuoteMode::Double),
        Some(other) => Err(Diagnostic::error(
            codes::NODE_SHAPE,
            format!("unknown quote mode `{other}` (allowed: none, double)"),
        )
        .with_span(span)),
    }
}

fn indent_option(file: FileId, node: &KdlNode, default: &str) -> ParseResult<String> {
    let Some(entry) = prop_entry(node, "indent") else {
        return Ok(default.to_owned());
    };
    if let Some(value) = entry.value().as_string() {
        if value.chars().any(|c| c != ' ' && c != '\t') {
            return Err(Diagnostic::error(
                codes::NODE_SHAPE,
                "`indent=` must contain only spaces or tabs",
            )
            .with_span(entry_span(file, entry)));
        }
        return Ok(value.to_owned());
    }
    entry
        .value()
        .as_integer()
        .and_then(|value| usize::try_from(value).ok())
        .filter(|value| *value <= 16)
        .map(|count| " ".repeat(count))
        .ok_or_else(|| {
            Diagnostic::error(
                codes::NODE_SHAPE,
                "`indent=` must be whitespace or an integer from 0 through 16",
            )
            .with_span(entry_span(file, entry))
        })
}

const DIRECTIVES_HELP: &str = "known directives: @when, @when-set, @when-nonempty, @else, \
     @each, @range, @splice, @spread, @comment, @raw, @line, @file, @compose, @lit";

/// Parse a render body. Only `@`-prefixed names are Malm constructs;
/// `@else` attaches to the immediately preceding `@when*` sibling.
pub(crate) fn parse_items(
    file: FileId,
    nodes: &[KdlNode],
) -> ParseResult<Vec<ConfigItem<ShapeNode>>> {
    let mut out = Vec::new();
    let mut nodes = nodes.iter().peekable();
    while let Some(node) = nodes.next() {
        let span = node_span(file, node);
        let name = node.name().value();
        match name {
            "@when" | "@when-set" | "@when-nonempty" => {
                let predicate = parse_render_condition(file, node)?;
                let then = parse_items(
                    file,
                    node.children()
                        .map(|children| children.nodes())
                        .unwrap_or_default(),
                )?;
                let mut otherwise = Vec::new();
                if let Some(next) = nodes.peek()
                    && next.name().value() == "@else"
                {
                    let next = nodes.next().expect("peeked");
                    expect_args(file, next, 0)?;
                    reject_unknown_props(file, next, &[])?;
                    otherwise = parse_items(
                        file,
                        next.children()
                            .map(|children| children.nodes())
                            .unwrap_or_default(),
                    )?;
                }
                out.push(ConfigItem::When(WhenBlock {
                    predicate,
                    then,
                    otherwise,
                    span,
                }));
            }
            "@else" => {
                return Err(Diagnostic::error(
                    codes::NODE_SHAPE,
                    "`@else` must immediately follow an `@when`, `@when-set`, or `@when-nonempty` sibling",
                )
                .with_span(span));
            }
            "@each" => {
                let (binding, source) = parse_render_each(file, node)?;
                out.push(ConfigItem::Each(EachBlock {
                    binding,
                    source,
                    body: parse_items(
                        file,
                        node.children()
                            .map(|children| children.nodes())
                            .unwrap_or_default(),
                    )?,
                    span,
                }));
            }
            "@range" => {
                let (binding, from, through) = parse_render_range(file, node)?;
                out.push(ConfigItem::Range(RangeBlock {
                    binding,
                    from,
                    through,
                    body: parse_items(
                        file,
                        node.children()
                            .map(|children| children.nodes())
                            .unwrap_or_default(),
                    )?,
                    span,
                }));
            }
            "@splice" => {
                reject_unknown_props(file, node, &[])?;
                reject_unknown_children(file, node, &[])?;
                out.push(ConfigItem::Splice(plain_string_ref(
                    file,
                    node,
                    "`@splice` collection reference",
                )?));
            }
            "@spread" => {
                reject_unknown_props(file, node, &["case"])?;
                reject_unknown_children(file, node, &[])?;
                let reference = plain_string_ref(file, node, "`@spread` record reference")?;
                let case = match opt_str_prop(file, node, "case")?.as_deref() {
                    None => SpreadCase::Verbatim,
                    Some("snake_case") => SpreadCase::Snake,
                    Some("kebab-case") => SpreadCase::Kebab,
                    Some("camelCase") => SpreadCase::Camel,
                    Some(other) => {
                        return Err(Diagnostic::error(
                            codes::NODE_SHAPE,
                            format!(
                                "unknown `case=\"{other}\"` (allowed: snake_case, kebab-case, camelCase)"
                            ),
                        )
                        .with_span(span));
                    }
                };
                out.push(ConfigItem::Value {
                    value: ShapeNode::Spread(Spread {
                        reference,
                        case,
                        span,
                    }),
                    span,
                });
            }
            "@comment" => {
                reject_unknown_props(file, node, &[])?;
                reject_unknown_children(file, node, &[])?;
                let text = literal_string_arg(file, node, "`@comment` text")?;
                if text.chars().any(char::is_control) {
                    return Err(Diagnostic::error(
                        codes::NODE_SHAPE,
                        "`@comment` text must be a single line",
                    )
                    .with_span(span));
                }
                out.push(ConfigItem::Value {
                    value: ShapeNode::Comment { text, span },
                    span,
                });
            }
            "@raw" => {
                reject_unknown_props(file, node, &[])?;
                reject_unknown_children(file, node, &[])?;
                out.push(ConfigItem::Value {
                    value: ShapeNode::Raw {
                        text: literal_string_arg(file, node, "`@raw` text")?,
                        span,
                    },
                    span,
                });
            }
            "@line" => {
                reject_unknown_props(file, node, &[])?;
                reject_unknown_children(file, node, &[])?;
                let args: Vec<&KdlEntry> =
                    node.iter().filter(|entry| entry.name().is_none()).collect();
                if args.len() != 1 {
                    return Err(Diagnostic::error(
                        codes::NODE_SHAPE,
                        "`@line` requires exactly one value",
                    )
                    .with_span(span));
                }
                out.push(ConfigItem::Value {
                    value: ShapeNode::Line {
                        value: parse_value_expr(file, args[0])?,
                        span,
                    },
                    span,
                });
            }
            "@file" => {
                reject_unknown_props(file, node, &["interpolate"])?;
                reject_unknown_children(file, node, &[])?;
                let path = literal_string_arg(file, node, "`@file` path")?;
                let interpolate = bool_prop(file, node, "interpolate")?;
                out.push(ConfigItem::Value {
                    value: ShapeNode::File {
                        path,
                        interpolate,
                        span,
                    },
                    span,
                });
            }
            "@compose" => {
                reject_unknown_props(file, node, &[])?;
                reject_unknown_children(file, node, &[])?;
                out.push(ConfigItem::Value {
                    value: ShapeNode::Compose {
                        fragment: literal_string_arg(file, node, "`@compose` fragment name")?,
                        span,
                    },
                    span,
                });
            }
            "@lit" => {
                let args: Vec<&KdlEntry> =
                    node.iter().filter(|entry| entry.name().is_none()).collect();
                let Some(first) = args.first() else {
                    return Err(Diagnostic::error(
                        codes::NODE_SHAPE,
                        "`@lit` requires a literal key as its first argument",
                    )
                    .with_span(span));
                };
                if first.ty().is_some() || first.value().as_string().is_none() {
                    return Err(Diagnostic::error(
                        codes::NODE_SHAPE,
                        "`@lit` key must be a plain string",
                    )
                    .with_span(entry_span(file, first)));
                }
                let name = first.value().as_string().expect("checked").to_owned();
                out.push(ConfigItem::Value {
                    value: parse_entry(file, node, Some(NodeName::Literal(name)), 1)?,
                    span,
                });
            }
            other if other.starts_with('@') => {
                return Err(Diagnostic::error(
                    codes::UNKNOWN_NODE,
                    format!("unknown render directive `{other}` ({DIRECTIVES_HELP})"),
                )
                .with_span(span));
            }
            "-" => {
                if node.ty().is_some() {
                    return Err(Diagnostic::error(
                        codes::NODE_SHAPE,
                        "array elements do not take a type annotation",
                    )
                    .with_span(span));
                }
                out.push(ConfigItem::Value {
                    value: parse_entry(file, node, None, 0)?,
                    span,
                });
            }
            _ => {
                let name = match node.ty().map(|ty| ty.value()) {
                    None => NodeName::Literal(node.name().value().to_owned()),
                    Some("f") => {
                        let raw = node.name().value().to_owned();
                        if let Err(message) = text::parse_template_with(&raw, TemplateSyntax::V3) {
                            return Err(Diagnostic::error(codes::TEMPLATE, message).with_span(span));
                        }
                        NodeName::FString { raw, span }
                    }
                    Some(other) => {
                        return Err(Diagnostic::error(
                            codes::NODE_SHAPE,
                            format!(
                                "unknown node annotation `({other})` (only `(f)` is supported here; \
                                 (array)/(object)/(inline)/(date) land in a later phase)"
                            ),
                        )
                        .with_span(span));
                    }
                };
                out.push(ConfigItem::Value {
                    value: parse_entry(file, node, Some(name), 0)?,
                    span,
                });
            }
        }
    }
    Ok(out)
}

fn parse_entry(
    file: FileId,
    node: &KdlNode,
    name: Option<NodeName>,
    skip_args: usize,
) -> ParseResult<ShapeNode> {
    let span = node_span(file, node);
    let mut args = Vec::new();
    let mut props = Vec::new();
    let mut quote = None;
    for entry in node.iter() {
        match entry.name() {
            None => args.push(entry),
            Some(key) if key.value() == "@quote" => {
                if quote.is_some() {
                    return Err(
                        Diagnostic::error(codes::DUPLICATE, "`@quote=` is set twice")
                            .with_span(entry_span(file, entry)),
                    );
                }
                quote = Some(match entry.value().as_string() {
                    Some("double") => QuoteMode::Double,
                    Some("none") => QuoteMode::None,
                    _ => {
                        return Err(Diagnostic::error(
                            codes::NODE_SHAPE,
                            "`@quote=` must be \"double\" or \"none\"",
                        )
                        .with_span(entry_span(file, entry)));
                    }
                });
            }
            Some(key) if key.value().starts_with('@') => {
                return Err(Diagnostic::error(
                    codes::NODE_SHAPE,
                    format!(
                        "unknown Malm property `{}=` (data properties must not start with `@`)",
                        key.value()
                    ),
                )
                .with_span(entry_span(file, entry)));
            }
            Some(key) => {
                let key_name = key.value().to_owned();
                if props.iter().any(|(existing, _, _)| *existing == key_name) {
                    return Err(Diagnostic::error(
                        codes::DUPLICATE,
                        format!("property `{key_name}=` is set twice"),
                    )
                    .with_span(entry_span(file, entry)));
                }
                props.push((
                    key_name,
                    parse_value_expr(file, entry)?,
                    entry_span(file, entry),
                ));
            }
        }
    }
    let args = args
        .into_iter()
        .skip(skip_args)
        .map(|entry| parse_value_expr(file, entry))
        .collect::<ParseResult<Vec<_>>>()?;
    let children = node
        .children()
        .map(|children| parse_items(file, children.nodes()))
        .transpose()?;
    Ok(ShapeNode::Entry(Entry {
        name,
        args,
        props,
        children,
        quote,
        span,
    }))
}

fn parse_value_expr(file: FileId, entry: &KdlEntry) -> ParseResult<ValueExpr> {
    let span = entry_span(file, entry);
    match entry.ty().map(|ty| ty.value()) {
        Some(ty @ ("ref" | "ref?")) => {
            let name = entry
                .value()
                .as_string()
                .filter(|name| !name.is_empty())
                .ok_or_else(|| {
                    Diagnostic::error(
                        codes::BAD_REF,
                        "a `(ref)` / `(ref?)` value must be a non-empty string",
                    )
                    .with_span(span)
                })?;
            Ok(ValueExpr::Ref {
                reference: Ref {
                    name: name.to_owned(),
                    span,
                },
                optional: ty == "ref?",
            })
        }
        Some("f") => {
            let raw = entry.value().as_string().ok_or_else(|| {
                Diagnostic::error(codes::NODE_SHAPE, "an `(f)` value must be a string")
                    .with_span(span)
            })?;
            if let Err(message) = text::parse_template_with(raw, TemplateSyntax::V3) {
                return Err(Diagnostic::error(codes::TEMPLATE, message).with_span(span));
            }
            Ok(ValueExpr::FString {
                raw: raw.to_owned(),
                span,
            })
        }
        Some("raw") => {
            let raw = entry.value().as_string().ok_or_else(|| {
                Diagnostic::error(codes::NODE_SHAPE, "a `(raw)` value must be a string")
                    .with_span(span)
            })?;
            Ok(ValueExpr::Raw(raw.to_owned(), span))
        }
        Some(other) => Err(Diagnostic::error(
            codes::NODE_SHAPE,
            format!("unknown value annotation `({other})` (allowed: ref, ref?, f, raw)"),
        )
        .with_span(span)),
        None => {
            let value = match entry.value() {
                KdlValue::Null => Value::Null,
                KdlValue::Bool(value) => Value::Bool(*value),
                KdlValue::Integer(value) => Value::Int(i64::try_from(*value).map_err(|_| {
                    Diagnostic::error(codes::NODE_SHAPE, "integer is outside the 64-bit range")
                        .with_span(span)
                })?),
                KdlValue::Float(value) if value.is_finite() => Value::Float(*value),
                KdlValue::Float(_) => {
                    return Err(Diagnostic::error(
                        codes::NODE_SHAPE,
                        "non-finite numbers are not allowed",
                    )
                    .with_span(span));
                }
                KdlValue::String(value) => Value::String(value.clone()),
            };
            Ok(ValueExpr::Literal(value, span))
        }
    }
}

fn literal_string_arg(file: FileId, node: &KdlNode, what: &str) -> ParseResult<String> {
    let args: Vec<&KdlEntry> = node.iter().filter(|entry| entry.name().is_none()).collect();
    if args.len() != 1 || args[0].ty().is_some() {
        return Err(Diagnostic::error(
            codes::NODE_SHAPE,
            format!("{what} requires exactly one plain string"),
        )
        .with_span(node_span(file, node)));
    }
    args[0]
        .value()
        .as_string()
        .map(str::to_owned)
        .ok_or_else(|| {
            Diagnostic::error(codes::NODE_SHAPE, format!("{what} must be a string"))
                .with_span(entry_span(file, args[0]))
        })
}

fn plain_string_ref(file: FileId, node: &KdlNode, what: &str) -> ParseResult<Ref> {
    let args: Vec<&KdlEntry> = node.iter().filter(|entry| entry.name().is_none()).collect();
    if args.len() != 1 || args[0].ty().is_some() {
        return Err(
            Diagnostic::error(codes::BAD_REF, format!("{what} must be one plain string"))
                .with_span(node_span(file, node)),
        );
    }
    let name = args[0]
        .value()
        .as_string()
        .filter(|name| !name.is_empty())
        .ok_or_else(|| {
            Diagnostic::error(codes::BAD_REF, format!("{what} must be a non-empty string"))
                .with_span(entry_span(file, args[0]))
        })?;
    Ok(Ref {
        name: name.to_owned(),
        span: entry_span(file, args[0]),
    })
}

fn parse_render_condition(file: FileId, node: &KdlNode) -> ParseResult<Predicate> {
    let is_when = node.name().value() == "@when";
    if is_when {
        reject_unknown_props(file, node, &["is", "is-not"])?;
    } else {
        reject_unknown_props(file, node, &[])?;
    }
    let reference = plain_string_ref(file, node, "condition reference")?;
    if is_when {
        let is_entry = prop_entry(node, "is");
        let is_not_entry = prop_entry(node, "is-not");
        if is_entry.is_some() && is_not_entry.is_some() {
            return Err(Diagnostic::error(
                codes::NODE_SHAPE,
                "`@when` takes either `is=` or `is-not=`, not both",
            )
            .with_span(node_span(file, node)));
        }
        if let Some(entry) = is_entry.or(is_not_entry) {
            let expected = crate::lang::kdl_util::scalar_value(file, entry)?;
            if matches!(expected, Value::Null | Value::Float(_)) {
                return Err(Diagnostic::error(
                    codes::WHEN_PREDICATE,
                    "`is=` compares enum, string, int, or bool literals",
                )
                .with_span(entry_span(file, entry)));
            }
            return Ok(Predicate::Eq {
                reference,
                expected,
                negated: is_not_entry.is_some(),
            });
        }
    }
    Ok(match node.name().value() {
        "@when" => Predicate::Test(reference),
        "@when-set" => Predicate::Set(reference),
        _ => Predicate::NonEmpty(reference),
    })
}

fn parse_render_each(file: FileId, node: &KdlNode) -> ParseResult<(String, Ref)> {
    reject_unknown_props(file, node, &["in"])?;
    let binding = req_str_arg(file, node)?;
    if binding.is_empty() {
        return Err(
            Diagnostic::error(codes::BINDING, "`@each` binding must not be empty")
                .with_span(node_span(file, node)),
        );
    }
    let entry = prop_entry(node, "in").ok_or_else(|| {
        Diagnostic::error(codes::NODE_SHAPE, "`@each` requires `in=\"source\"`")
            .with_span(node_span(file, node))
    })?;
    if entry.ty().is_some() {
        return Err(Diagnostic::error(
            codes::BAD_REF,
            "`@each in=` is a plain string, not a typed value",
        )
        .with_span(entry_span(file, entry)));
    }
    let name = entry
        .value()
        .as_string()
        .filter(|name| !name.is_empty())
        .ok_or_else(|| {
            Diagnostic::error(codes::BAD_REF, "`@each in=` must be a non-empty string")
                .with_span(entry_span(file, entry))
        })?;
    Ok((
        binding,
        Ref {
            name: name.to_owned(),
            span: entry_span(file, entry),
        },
    ))
}

fn parse_render_range(file: FileId, node: &KdlNode) -> ParseResult<(String, i64, i64)> {
    reject_unknown_props(file, node, &["from", "through"])?;
    let binding = req_str_arg(file, node)?;
    if binding.is_empty() {
        return Err(
            Diagnostic::error(codes::BINDING, "`@range` binding must not be empty")
                .with_span(node_span(file, node)),
        );
    }
    let from = int_prop(file, node, "from")?.ok_or_else(|| {
        Diagnostic::error(codes::NODE_SHAPE, "`@range` requires `from=<int>`")
            .with_span(node_span(file, node))
    })?;
    let through = int_prop(file, node, "through")?.ok_or_else(|| {
        Diagnostic::error(codes::NODE_SHAPE, "`@range` requires `through=<int>`")
            .with_span(node_span(file, node))
    })?;
    Ok((binding, from, through))
}

// Rendering

/// `@file` contents and `@compose` fragments loaded before rendering.
#[derive(Debug, Default)]
pub struct RenderResources {
    pub files: HashMap<String, String>,
    pub fragments: HashMap<String, String>,
}

/// Pre-resolution requests: (path-or-fragment, request span).
pub(crate) type ResourceRequests = Vec<(String, Span)>;

/// Collect every `@file` and `@compose` request in a body, descending
/// through control bodies without evaluating them.
pub(crate) fn collect_resources(
    items: &[ConfigItem<ShapeNode>],
) -> (ResourceRequests, ResourceRequests) {
    let mut files = Vec::new();
    let mut fragments = Vec::new();
    fn visit(
        items: &[ConfigItem<ShapeNode>],
        files: &mut ResourceRequests,
        fragments: &mut ResourceRequests,
    ) {
        for item in items {
            match item {
                ConfigItem::Value { value, .. } => match value {
                    ShapeNode::File { path, span, .. } => {
                        if !files.iter().any(|(existing, _)| existing == path) {
                            files.push((path.clone(), *span));
                        }
                    }
                    ShapeNode::Compose { fragment, span } => {
                        if !fragments.iter().any(|(existing, _)| existing == fragment) {
                            fragments.push((fragment.clone(), *span));
                        }
                    }
                    ShapeNode::Entry(entry) => {
                        if let Some(children) = &entry.children {
                            visit(children, files, fragments);
                        }
                    }
                    _ => {}
                },
                ConfigItem::When(when) => {
                    visit(&when.then, files, fragments);
                    visit(&when.otherwise, files, fragments);
                }
                ConfigItem::Each(each) => visit(&each.body, files, fragments),
                ConfigItem::Range(range) => visit(&range.body, files, fragments),
                ConfigItem::Splice(_) => {}
            }
        }
    }
    visit(items, &mut files, &mut fragments);
    (files, fragments)
}

pub(crate) fn render_output(
    body: &RenderBody,
    scope: &mut Scope,
    budget: &mut Budget,
    diagnostics: &mut Diagnostics,
    resources: &RenderResources,
) -> Option<(String, &'static str)> {
    let errors_before = diagnostics.error_count();
    let mut renderer = Renderer {
        scope,
        budget,
        diagnostics,
        resources,
        splice_stack: Vec::new(),
    };
    let content = match &body.format {
        FormatSpec::Json { comments, indent } => {
            json_root(&mut renderer, &body.items, *comments, indent, body.span)
        }
        FormatSpec::Toml => toml_items(&mut renderer, &body.items, &[]),
        FormatSpec::Ini(opts) => ini_items(&mut renderer, &body.items, opts, "")
            .map(|content| content.trim_start_matches('\n').to_owned()),
        FormatSpec::Text(opts) => text_root(&mut renderer, &body.items, opts, body.span),
        FormatSpec::Lua { indent } => lua_root(&mut renderer, &body.items, indent, body.span),
    }?;
    if renderer.budget.exhausted() || renderer.diagnostics.error_count() != errors_before {
        return None;
    }
    if !renderer.charge_bytes(&content, body.span) {
        return None;
    }
    Some((content, body.format.validator()))
}

struct Renderer<'a> {
    scope: &'a mut Scope,
    budget: &'a mut Budget,
    diagnostics: &'a mut Diagnostics,
    resources: &'a RenderResources,
    splice_stack: Vec<String>,
}

enum Resolved {
    Value(Value),
    /// A `(raw)` token, emitted verbatim in the target syntax.
    Raw(String),
    /// An unset `(ref?)`; the enclosing entry is omitted without error.
    Skip,
}

impl Renderer<'_> {
    fn charge_bytes(&mut self, content: &str, span: Span) -> bool {
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

    fn error(&mut self, code: &'static str, message: impl Into<String>, span: Span) {
        self.diagnostics
            .push(Diagnostic::error(code, message).with_span(span));
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

    fn walk(
        &mut self,
        items: &[ConfigItem<ShapeNode>],
        depth: usize,
        leaf: &mut dyn FnMut(&mut Self, &ShapeNode),
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
                ConfigItem::Value { value, .. } => leaf(self, value),
                ConfigItem::When(when) => {
                    if !self.check_depth(depth + 1, when.span) {
                        return;
                    }
                    let Some(matches) = self.predicate(&when.predicate) else {
                        continue;
                    };
                    let branch = if matches { &when.then } else { &when.otherwise };
                    self.walk(branch, depth + 1, leaf);
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
                        self.walk(&each.body, depth + 1, leaf);
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
                        self.walk(&range.body, depth + 1, leaf);
                        self.scope.pop_binding();
                    }
                }
                ConfigItem::Splice(reference) => self.splice(reference, depth, leaf),
            }
        }
    }

    fn splice(
        &mut self,
        reference: &Ref,
        depth: usize,
        leaf: &mut dyn FnMut(&mut Self, &ShapeNode),
    ) {
        if !self.check_depth(depth + 1, reference.span) {
            return;
        }
        let Some(Value::Collection(collection)) = self.scope.lookup(&reference.name).cloned()
        else {
            self.error(
                codes::TYPE_MISMATCH,
                format!(
                    "`@splice` requires a collection<kdl-document>, found `{}`",
                    reference.name
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
                format!("render splice cycle detected: {}", cycle.join(" -> ")),
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
                        "spliced collection item `{}` is not a kdl-document",
                        item.key
                    ),
                    item.span,
                );
                continue;
            };
            match parse_items(item.span.file, document.nodes()) {
                Ok(items) => self.walk(&items, depth + 1, leaf),
                Err(error) => self.diagnostics.push(error),
            }
        }
        self.splice_stack.pop();
    }

    fn resolve(&mut self, expr: &ValueExpr) -> Option<Resolved> {
        match expr {
            ValueExpr::Literal(value, _) => Some(Resolved::Value(value.clone())),
            ValueExpr::Raw(text, _) => Some(Resolved::Raw(text.clone())),
            ValueExpr::Ref {
                reference,
                optional,
            } => match self.scope.lookup(&reference.name).cloned() {
                None => {
                    self.error(
                        codes::UNDEFINED_REF,
                        format!("`{}` is not defined", reference.name),
                        reference.span,
                    );
                    None
                }
                Some(Value::Null) if *optional => Some(Resolved::Skip),
                Some(Value::Null) => {
                    self.error(
                        codes::TYPE_MISMATCH,
                        format!(
                            "`{}` is #null; guard with `@when-set` or use `(ref?)`",
                            reference.name
                        ),
                        reference.span,
                    );
                    None
                }
                Some(value) => Some(Resolved::Value(value)),
            },
            ValueExpr::FString { raw, span } => {
                let scope = &*self.scope;
                let lookup = move |name: &str| scope.lookup(name).cloned();
                match text::render_template_with(raw, TemplateSyntax::V3, &lookup) {
                    Ok(rendered) => Some(Resolved::Value(Value::String(rendered))),
                    Err(message) => {
                        self.error(codes::TEMPLATE, message, *span);
                        None
                    }
                }
            }
        }
    }

    /// Resolve an entry, omitting it if any value is an unset `(ref?)`.
    fn resolve_entry(&mut self, entry: &Entry) -> Option<ResolvedEntry> {
        let name = match &entry.name {
            None => None,
            Some(NodeName::Literal(name)) => Some(name.clone()),
            Some(NodeName::FString { raw, span }) => {
                let scope = &*self.scope;
                let lookup = move |name: &str| scope.lookup(name).cloned();
                match text::render_template_with(raw, TemplateSyntax::V3, &lookup) {
                    Ok(rendered) => Some(rendered),
                    Err(message) => {
                        self.error(codes::TEMPLATE, message, *span);
                        return None;
                    }
                }
            }
        };
        let mut args = Vec::new();
        for arg in &entry.args {
            match self.resolve(arg)? {
                Resolved::Skip => return Some(ResolvedEntry::Skipped),
                resolved => args.push((resolved, arg.span())),
            }
        }
        let mut props = Vec::new();
        for (key, value, span) in &entry.props {
            match self.resolve(value)? {
                Resolved::Skip => return Some(ResolvedEntry::Skipped),
                resolved => props.push((key.clone(), resolved, *span)),
            }
        }
        Some(ResolvedEntry::Ready { name, args, props })
    }

    fn scalar_text(&mut self, resolved: &Resolved, span: Span) -> Option<String> {
        match resolved {
            Resolved::Raw(text) => Some(text.clone()),
            Resolved::Skip => None,
            Resolved::Value(value) => match value {
                Value::Bool(value) => Some(value.to_string()),
                Value::Int(value) => Some(value.to_string()),
                Value::Float(value) if value.is_finite() => Some(format_float(*value)),
                Value::String(value) | Value::Path(value)
                    if !value.chars().any(char::is_control) =>
                {
                    Some(value.clone())
                }
                value => {
                    self.error(
                        codes::TYPE_MISMATCH,
                        format!("expected a safe scalar, found {}", value.type_label()),
                        span,
                    );
                    None
                }
            },
        }
    }
}

impl Renderer<'_> {
    /// Resolve preloaded `@file` or `@compose` text and interpolate if requested.
    fn resource_text(&mut self, node: &ShapeNode) -> Option<String> {
        match node {
            ShapeNode::File {
                path,
                interpolate,
                span,
            } => {
                let Some(content) = self.resources.files.get(path).cloned() else {
                    self.error(
                        codes::EMIT,
                        format!(
                            "`@file \"{path}\"` is unavailable here (files cannot arrive via `@splice`)"
                        ),
                        *span,
                    );
                    return None;
                };
                if !*interpolate {
                    return Some(content);
                }
                let scope = &*self.scope;
                let lookup = move |name: &str| scope.lookup(name).cloned();
                match text::render_template_with(&content, TemplateSyntax::V3, &lookup) {
                    Ok(rendered) => Some(rendered),
                    Err(message) => {
                        self.error(codes::TEMPLATE, format!("{path}: {message}"), *span);
                        None
                    }
                }
            }
            ShapeNode::Compose { fragment, span } => {
                match self.resources.fragments.get(fragment).cloned() {
                    Some(content) => Some(content),
                    None => {
                        self.error(
                            codes::EMIT,
                            format!(
                                "`@compose \"{fragment}\"` is unavailable here (fragments cannot arrive via `@splice`)"
                            ),
                            *span,
                        );
                        None
                    }
                }
            }
            _ => unreachable!("resource_text is called on file/compose leaves"),
        }
    }
}

fn push_block(output: &mut String, content: &str) {
    output.push_str(content);
    if !content.is_empty() && !content.ends_with('\n') {
        output.push('\n');
    }
}

enum ResolvedEntry {
    Ready {
        name: Option<String>,
        args: Vec<(Resolved, Span)>,
        props: Vec<(String, Resolved, Span)>,
    },
    Skipped,
}

fn duplicate(renderer: &mut Renderer<'_>, name: &str, span: Span) {
    renderer.error(
        codes::DUPLICATE,
        format!("duplicate or redefined key `{name}` after expansion"),
        span,
    );
}

/// Resolve an `@spread` in field-name order, omitting unset optional fields.
fn spread_fields(renderer: &mut Renderer<'_>, spread: &Spread) -> Option<Vec<(String, Value)>> {
    match renderer.scope.lookup(&spread.reference.name).cloned() {
        Some(Value::Record(record)) => Some(
            record
                .iter()
                .filter(|(_, value)| !value.is_null())
                .map(|(name, value)| (spread.case.apply(name), value.clone()))
                .collect(),
        ),
        Some(other) => {
            renderer.error(
                codes::TYPE_MISMATCH,
                format!(
                    "`@spread` requires a record, found {} `{}`",
                    other.type_label(),
                    spread.reference.name
                ),
                spread.span,
            );
            None
        }
        None => {
            renderer.error(
                codes::UNDEFINED_REF,
                format!("`{}` is not defined", spread.reference.name),
                spread.span,
            );
            None
        }
    }
}

/// Classify immediate members without evaluating controls. Treat `@splice` as
/// named content because its payload is not known here.
fn classify_block(items: &[ConfigItem<ShapeNode>]) -> (bool, bool) {
    let mut saw_dash = false;
    let mut saw_named = false;
    fn visit(items: &[ConfigItem<ShapeNode>], saw_dash: &mut bool, saw_named: &mut bool) {
        for item in items {
            match item {
                ConfigItem::Value {
                    value: ShapeNode::Entry(entry),
                    ..
                } => {
                    if entry.name.is_none() {
                        *saw_dash = true;
                    } else {
                        *saw_named = true;
                    }
                }
                ConfigItem::Value {
                    value: ShapeNode::Spread(_),
                    ..
                } => *saw_named = true,
                ConfigItem::Value { .. } => {}
                ConfigItem::When(when) => {
                    visit(&when.then, saw_dash, saw_named);
                    visit(&when.otherwise, saw_dash, saw_named);
                }
                ConfigItem::Each(each) => visit(&each.body, saw_dash, saw_named),
                ConfigItem::Range(range) => visit(&range.body, saw_dash, saw_named),
                ConfigItem::Splice(_) => *saw_named = true,
            }
        }
    }
    visit(items, &mut saw_dash, &mut saw_named);
    (saw_dash, saw_named)
}

/// Convert one `-` element to items, placing properties before child entries.
fn element_items(entry: &Entry) -> Vec<ConfigItem<ShapeNode>> {
    let mut items: Vec<ConfigItem<ShapeNode>> = Vec::new();
    for (key, value, span) in &entry.props {
        items.push(ConfigItem::Value {
            value: ShapeNode::Entry(Entry {
                name: Some(NodeName::Literal(key.clone())),
                args: vec![clone_value_expr(value)],
                props: Vec::new(),
                children: None,
                quote: entry.quote,
                span: *span,
            }),
            span: *span,
        });
    }
    items.extend(clone_items(entry.children.as_deref().unwrap_or(&[])));
    items
}

fn clone_items(items: &[ConfigItem<ShapeNode>]) -> Vec<ConfigItem<ShapeNode>> {
    items.iter().map(clone_item).collect()
}

fn clone_item(item: &ConfigItem<ShapeNode>) -> ConfigItem<ShapeNode> {
    match item {
        ConfigItem::Value { value, span } => ConfigItem::Value {
            value: clone_shape(value),
            span: *span,
        },
        ConfigItem::When(when) => ConfigItem::When(WhenBlock {
            predicate: clone_predicate(&when.predicate),
            then: clone_items(&when.then),
            otherwise: clone_items(&when.otherwise),
            span: when.span,
        }),
        ConfigItem::Each(each) => ConfigItem::Each(EachBlock {
            binding: each.binding.clone(),
            source: each.source.clone(),
            body: clone_items(&each.body),
            span: each.span,
        }),
        ConfigItem::Range(range) => ConfigItem::Range(RangeBlock {
            binding: range.binding.clone(),
            from: range.from,
            through: range.through,
            body: clone_items(&range.body),
            span: range.span,
        }),
        ConfigItem::Splice(reference) => ConfigItem::Splice(reference.clone()),
    }
}

fn clone_predicate(predicate: &Predicate) -> Predicate {
    match predicate {
        Predicate::Test(reference) => Predicate::Test(reference.clone()),
        Predicate::Set(reference) => Predicate::Set(reference.clone()),
        Predicate::NonEmpty(reference) => Predicate::NonEmpty(reference.clone()),
        Predicate::Eq {
            reference,
            expected,
            negated,
        } => Predicate::Eq {
            reference: reference.clone(),
            expected: expected.clone(),
            negated: *negated,
        },
    }
}

fn clone_shape(node: &ShapeNode) -> ShapeNode {
    match node {
        ShapeNode::Entry(entry) => ShapeNode::Entry(Entry {
            name: match &entry.name {
                None => None,
                Some(NodeName::Literal(name)) => Some(NodeName::Literal(name.clone())),
                Some(NodeName::FString { raw, span }) => Some(NodeName::FString {
                    raw: raw.clone(),
                    span: *span,
                }),
            },
            args: entry.args.iter().map(clone_value_expr).collect(),
            props: entry
                .props
                .iter()
                .map(|(key, value, span)| (key.clone(), clone_value_expr(value), *span))
                .collect(),
            children: entry.children.as_deref().map(clone_items),
            quote: entry.quote,
            span: entry.span,
        }),
        ShapeNode::Comment { text, span } => ShapeNode::Comment {
            text: text.clone(),
            span: *span,
        },
        ShapeNode::Raw { text, span } => ShapeNode::Raw {
            text: text.clone(),
            span: *span,
        },
        ShapeNode::Line { value, span } => ShapeNode::Line {
            value: clone_value_expr(value),
            span: *span,
        },
        ShapeNode::Spread(spread) => ShapeNode::Spread(Spread {
            reference: spread.reference.clone(),
            case: spread.case,
            span: spread.span,
        }),
        ShapeNode::File {
            path,
            interpolate,
            span,
        } => ShapeNode::File {
            path: path.clone(),
            interpolate: *interpolate,
            span: *span,
        },
        ShapeNode::Compose { fragment, span } => ShapeNode::Compose {
            fragment: fragment.clone(),
            span: *span,
        },
    }
}

fn clone_value_expr(expr: &ValueExpr) -> ValueExpr {
    match expr {
        ValueExpr::Literal(value, span) => ValueExpr::Literal(value.clone(), *span),
        ValueExpr::Ref {
            reference,
            optional,
        } => ValueExpr::Ref {
            reference: reference.clone(),
            optional: *optional,
        },
        ValueExpr::FString { raw, span } => ValueExpr::FString {
            raw: raw.clone(),
            span: *span,
        },
        ValueExpr::Raw(text, span) => ValueExpr::Raw(text.clone(), *span),
    }
}

// JSON and Lua

#[derive(Clone, Copy, PartialEq, Eq)]
enum DataDialect {
    Json,
    Lua,
}

fn dialect_label(dialect: DataDialect) -> &'static str {
    match dialect {
        DataDialect::Json => "json",
        DataDialect::Lua => "lua",
    }
}

enum DataPiece {
    Member {
        name: String,
        text: String,
        span: Span,
    },
    Element(String),
    Comment(String),
    RawMember(String),
}

fn json_root(
    renderer: &mut Renderer<'_>,
    items: &[ConfigItem<ShapeNode>],
    comments: bool,
    indent: &str,
    span: Span,
) -> Option<String> {
    let pieces = data_pieces(renderer, items, comments, indent, 1, DataDialect::Json);
    if pieces
        .iter()
        .any(|piece| matches!(piece, DataPiece::Element(_)))
    {
        renderer.error(
            codes::NODE_SHAPE,
            "the json root is an object; `-` elements at the root land in a later phase",
            span,
        );
        return None;
    }
    let root = data_container(renderer, pieces, indent, 0, false, DataDialect::Json, span)?;
    Some(format!("{root}\n"))
}

fn lua_root(
    renderer: &mut Renderer<'_>,
    items: &[ConfigItem<ShapeNode>],
    indent: &str,
    span: Span,
) -> Option<String> {
    if lua_program_mode(items) {
        return lua_program(renderer, items);
    }
    let pieces = data_pieces(renderer, items, true, indent, 1, DataDialect::Lua);
    let array = pieces
        .iter()
        .any(|piece| matches!(piece, DataPiece::Element(_)));
    let root = data_container(renderer, pieces, indent, 0, array, DataDialect::Lua, span)?;
    Some(format!("return {root}\n"))
}

/// A Lua body containing only raw directives renders without `return { … }`.
fn lua_program_mode(items: &[ConfigItem<ShapeNode>]) -> bool {
    fn visit(items: &[ConfigItem<ShapeNode>], has_data: &mut bool, has_raw: &mut bool) {
        for item in items {
            match item {
                ConfigItem::Value { value, .. } => match value {
                    ShapeNode::Entry(_) | ShapeNode::Spread(_) => *has_data = true,
                    ShapeNode::Raw { .. }
                    | ShapeNode::Line { .. }
                    | ShapeNode::File { .. }
                    | ShapeNode::Compose { .. } => *has_raw = true,
                    ShapeNode::Comment { .. } => {}
                },
                ConfigItem::When(when) => {
                    visit(&when.then, has_data, has_raw);
                    visit(&when.otherwise, has_data, has_raw);
                }
                ConfigItem::Each(each) => visit(&each.body, has_data, has_raw),
                ConfigItem::Range(range) => visit(&range.body, has_data, has_raw),
                ConfigItem::Splice(_) => *has_data = true,
            }
        }
    }
    let (mut has_data, mut has_raw) = (false, false);
    visit(items, &mut has_data, &mut has_raw);
    has_raw && !has_data
}

fn lua_program(renderer: &mut Renderer<'_>, items: &[ConfigItem<ShapeNode>]) -> Option<String> {
    let mut output = String::new();
    let mut failed = false;
    renderer.walk(items, 0, &mut |renderer, node| match node {
        ShapeNode::Comment { text, .. } => output.push_str(&format!("-- {text}\n")),
        ShapeNode::Raw { text, .. } => push_block(&mut output, text),
        ShapeNode::Line { value, span } => match renderer.resolve(value) {
            Some(Resolved::Skip) => {}
            Some(resolved) => match renderer.scalar_text(&resolved, *span) {
                Some(text) => output.push_str(&format!("{text}\n")),
                None => failed = true,
            },
            None => failed = true,
        },
        node @ (ShapeNode::File { .. } | ShapeNode::Compose { .. }) => {
            match renderer.resource_text(node) {
                Some(text) => push_block(&mut output, &text),
                None => failed = true,
            }
        }
        ShapeNode::Entry(entry) => {
            renderer.error(
                codes::NODE_SHAPE,
                "a lua program body (only @raw/@line/@file/@compose) cannot mix data entries",
                entry.span,
            );
            failed = true;
        }
        ShapeNode::Spread(spread) => {
            renderer.error(
                codes::NODE_SHAPE,
                "a lua program body (only @raw/@line/@file/@compose) cannot mix data entries",
                spread.span,
            );
            failed = true;
        }
    });
    if failed { None } else { Some(output) }
}

fn data_pieces(
    renderer: &mut Renderer<'_>,
    items: &[ConfigItem<ShapeNode>],
    comments: bool,
    indent: &str,
    depth: usize,
    dialect: DataDialect,
) -> Vec<DataPiece> {
    let mut pieces = Vec::new();
    renderer.walk(items, 0, &mut |renderer, node| match node {
        ShapeNode::Comment { text, span } => {
            if comments {
                pieces.push(DataPiece::Comment(match dialect {
                    DataDialect::Json => format!("// {text}"),
                    DataDialect::Lua => format!("-- {text}"),
                }));
            } else {
                renderer.error(
                    codes::NODE_SHAPE,
                    "comments require `format=\"jsonc\"`",
                    *span,
                );
            }
        }
        ShapeNode::Raw { text, .. } => pieces.push(DataPiece::RawMember(text.clone())),
        ShapeNode::Line { span, .. } => {
            renderer.error(
                codes::NODE_SHAPE,
                format!("`@line` is not valid in {} bodies", dialect_label(dialect)),
                *span,
            );
        }
        ShapeNode::Spread(spread) => {
            let Some(fields) = spread_fields(renderer, spread) else {
                return;
            };
            for (name, value) in fields {
                if let Some(text) =
                    data_value(renderer, &Resolved::Value(value), spread.span, dialect)
                {
                    pieces.push(DataPiece::Member {
                        name,
                        text,
                        span: spread.span,
                    });
                }
            }
        }
        node @ (ShapeNode::File { .. } | ShapeNode::Compose { .. }) => match dialect {
            DataDialect::Json => {
                renderer.error(
                    codes::NODE_SHAPE,
                    "`@file`/`@compose` are not valid in json bodies",
                    node.span(),
                );
            }
            DataDialect::Lua => {
                if let Some(text) = renderer.resource_text(node) {
                    for line in text.lines() {
                        pieces.push(DataPiece::RawMember(line.to_owned()));
                    }
                }
            }
        },
        ShapeNode::Entry(entry) => {
            let Some(resolved) = renderer.resolve_entry(entry) else {
                return;
            };
            let ResolvedEntry::Ready { name, args, props } = resolved else {
                return;
            };
            let Some(text) = data_entry_value(
                renderer, entry, &args, &props, comments, indent, depth, dialect,
            ) else {
                return;
            };
            match name {
                Some(name) => pieces.push(DataPiece::Member {
                    name,
                    text,
                    span: entry.span,
                }),
                None => pieces.push(DataPiece::Element(text)),
            }
        }
    });
    pieces
}

#[allow(clippy::too_many_arguments)]
fn data_entry_value(
    renderer: &mut Renderer<'_>,
    entry: &Entry,
    args: &[(Resolved, Span)],
    props: &[(String, Resolved, Span)],
    comments: bool,
    indent: &str,
    depth: usize,
    dialect: DataDialect,
) -> Option<String> {
    match &entry.children {
        None => {
            if args.is_empty() && props.is_empty() {
                renderer.error(
                    codes::NODE_SHAPE,
                    format!(
                        "a bare key is not valid in {} bodies; write `key #true` or guard it",
                        dialect_label(dialect)
                    ),
                    entry.span,
                );
                return None;
            }
            if !props.is_empty() && !args.is_empty() {
                renderer.error(
                    codes::NODE_SHAPE,
                    "an entry mixes values and properties; use either scalars or a compact object",
                    entry.span,
                );
                return None;
            }
            if !props.is_empty() {
                let mut seen = HashSet::new();
                let members = props
                    .iter()
                    .map(|(key, value, span)| {
                        if !seen.insert(key.clone()) {
                            duplicate(renderer, key, *span);
                            return None;
                        }
                        Some(data_member(
                            key,
                            &data_value(renderer, value, *span, dialect)?,
                            dialect,
                        ))
                    })
                    .collect::<Option<Vec<_>>>()?;
                return Some(format!("{{ {} }}", members.join(", ")));
            }
            if args.len() == 1 {
                return data_value(renderer, &args[0].0, args[0].1, dialect);
            }
            let values = args
                .iter()
                .map(|(value, span)| data_value(renderer, value, *span, dialect))
                .collect::<Option<Vec<_>>>()?;
            Some(match dialect {
                DataDialect::Json => format!("[{}]", values.join(", ")),
                DataDialect::Lua => format!("{{ {} }}", values.join(", ")),
            })
        }
        Some(children) => {
            if args.len() > 1 {
                renderer.error(
                    codes::NODE_SHAPE,
                    "a section takes at most one name argument before its children",
                    entry.span,
                );
                return None;
            }
            let named_section = !args.is_empty();
            let inner_depth = depth + usize::from(named_section);
            let mut pieces = Vec::new();
            let mut prop_seen = HashSet::new();
            for (key, value, span) in props {
                if !prop_seen.insert(key.clone()) {
                    duplicate(renderer, key, *span);
                    return None;
                }
                let text = data_value(renderer, value, *span, dialect)?;
                pieces.push(DataPiece::Member {
                    name: key.clone(),
                    text,
                    span: *span,
                });
            }
            pieces.extend(data_pieces(
                renderer,
                children,
                comments,
                indent,
                inner_depth + 1,
                dialect,
            ));
            let is_array = pieces
                .iter()
                .any(|piece| matches!(piece, DataPiece::Element(_)));
            if is_array
                && pieces
                    .iter()
                    .any(|piece| matches!(piece, DataPiece::Member { .. }))
            {
                renderer.error(
                    codes::NODE_SHAPE,
                    "a block mixes named members and `-` array elements",
                    entry.span,
                );
                return None;
            }
            let body = data_container(
                renderer,
                pieces,
                indent,
                inner_depth,
                is_array,
                dialect,
                entry.span,
            )?;
            if !named_section {
                return Some(body);
            }
            let (name, span) = &args[0];
            let name = renderer.scalar_text(name, *span)?;
            let member = data_member(&name, &body, dialect);
            Some(format!(
                "{{\n{}{member}{}\n{}}}",
                indent.repeat(inner_depth),
                match dialect {
                    DataDialect::Lua => ",",
                    DataDialect::Json => "",
                },
                indent.repeat(depth)
            ))
        }
    }
}

fn data_member(name: &str, value: &str, dialect: DataDialect) -> String {
    match dialect {
        DataDialect::Json => format!("\"{}\": {value}", json_escape(name)),
        DataDialect::Lua => {
            if lua_identifier(name) {
                format!("{name} = {value}")
            } else {
                format!("[\"{}\"] = {value}", lua_escape(name))
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn data_container(
    renderer: &mut Renderer<'_>,
    pieces: Vec<DataPiece>,
    indent: &str,
    depth: usize,
    array: bool,
    dialect: DataDialect,
    span: Span,
) -> Option<String> {
    let (open, close) = match (dialect, array) {
        (DataDialect::Json, true) => ("[", "]"),
        (DataDialect::Json, false) | (DataDialect::Lua, _) => ("{", "}"),
    };
    if pieces.is_empty() {
        return Some(format!("{open}{close}"));
    }
    let pad = indent.repeat(depth + 1);
    let mut seen = HashSet::new();
    let mut lines: Vec<(bool, String)> = Vec::new();
    for piece in &pieces {
        match piece {
            DataPiece::Member {
                name,
                text,
                span: member_span,
            } => {
                if !seen.insert(name.clone()) {
                    duplicate(renderer, name, *member_span);
                    return None;
                }
                lines.push((false, format!("{pad}{}", data_member(name, text, dialect))));
            }
            DataPiece::Element(text) => lines.push((false, format!("{pad}{text}"))),
            DataPiece::RawMember(text) => lines.push((false, format!("{pad}{text}"))),
            DataPiece::Comment(text) => lines.push((true, format!("{pad}{text}"))),
        }
    }
    let _ = span;
    let mut body = String::new();
    let mut remaining = lines.iter().filter(|(comment, _)| !comment).count();
    for (index, (comment, line)) in lines.iter().enumerate() {
        body.push_str(line);
        if !comment {
            remaining -= 1;
            let trailing = match dialect {
                DataDialect::Lua => true,
                DataDialect::Json => remaining != 0,
            };
            if trailing {
                body.push(',');
            }
        }
        if index + 1 != lines.len() {
            body.push('\n');
        }
    }
    Some(format!("{open}\n{body}\n{}{close}", indent.repeat(depth)))
}

fn data_value(
    renderer: &mut Renderer<'_>,
    resolved: &Resolved,
    span: Span,
    dialect: DataDialect,
) -> Option<String> {
    match resolved {
        Resolved::Skip => None,
        Resolved::Raw(text) => match dialect {
            DataDialect::Json => {
                renderer.error(
                    codes::NODE_SHAPE,
                    "`(raw)` values are not allowed in json bodies",
                    span,
                );
                None
            }
            DataDialect::Lua => Some(text.clone()),
        },
        Resolved::Value(value) => {
            let result = match dialect {
                DataDialect::Json => value_json(value),
                DataDialect::Lua => value_lua(value),
            };
            match result {
                Ok(text) => Some(text),
                Err(message) => {
                    renderer.error(codes::TYPE_MISMATCH, message, span);
                    None
                }
            }
        }
    }
}

fn lua_identifier(name: &str) -> bool {
    const KEYWORDS: &[&str] = &[
        "and", "break", "do", "else", "elseif", "end", "false", "for", "function", "goto", "if",
        "in", "local", "nil", "not", "or", "repeat", "return", "then", "true", "until", "while",
    ];
    !name.is_empty()
        && !KEYWORDS.contains(&name)
        && name.chars().enumerate().all(|(index, character)| {
            character == '_'
                || character.is_ascii_alphabetic()
                || (index > 0 && character.is_ascii_digit())
        })
}

// TOML

fn toml_items(
    renderer: &mut Renderer<'_>,
    items: &[ConfigItem<ShapeNode>],
    prefix: &[String],
) -> Option<String> {
    let mut inline: Vec<String> = Vec::new();
    let mut tables: Vec<String> = Vec::new();
    let mut seen = HashSet::new();
    let mut repeated: HashSet<String> = HashSet::new();
    let mut failed = false;
    renderer.walk(items, 0, &mut |renderer, node| match node {
        ShapeNode::Comment { text, .. } => inline.push(format!("# {text}\n")),
        ShapeNode::Raw { text, .. } => inline.push(format!("{text}\n")),
        ShapeNode::Line { span, .. } => {
            renderer.error(
                codes::NODE_SHAPE,
                "`@line` is not valid in toml bodies",
                *span,
            );
            failed = true;
        }
        ShapeNode::Spread(spread) => {
            let Some(fields) = spread_fields(renderer, spread) else {
                failed = true;
                return;
            };
            for (name, value) in fields {
                if !seen.insert(name.clone()) {
                    duplicate(renderer, &name, spread.span);
                    failed = true;
                    return;
                }
                match toml_value_of(renderer, &Resolved::Value(value), spread.span) {
                    Some(text) => inline.push(format!("{} = {text}\n", toml_key(&name))),
                    None => failed = true,
                }
            }
        }
        node @ (ShapeNode::File { .. } | ShapeNode::Compose { .. }) => {
            match renderer.resource_text(node) {
                Some(text) => {
                    let mut block = String::new();
                    push_block(&mut block, &text);
                    inline.push(block);
                }
                None => failed = true,
            }
        }
        ShapeNode::Entry(entry) => {
            if entry.name.is_none() {
                renderer.error(
                    codes::NODE_SHAPE,
                    "`-` array elements are only valid inside an array-valued key",
                    entry.span,
                );
                failed = true;
                return;
            }
            match toml_entry(renderer, entry, prefix, &mut seen, &mut repeated) {
                Some(TomlRendered::Inline(text)) => inline.push(text),
                Some(TomlRendered::Table(text)) => tables.push(text),
                Some(TomlRendered::Skipped) => {}
                None => failed = true,
            }
        }
    });
    if failed {
        return None;
    }
    let mut output: String = inline.concat();
    output.extend(tables.iter().map(String::as_str));
    Some(output.trim_start_matches('\n').to_owned())
}

enum TomlRendered {
    Inline(String),
    Table(String),
    Skipped,
}

fn toml_value_of(renderer: &mut Renderer<'_>, resolved: &Resolved, span: Span) -> Option<String> {
    match resolved {
        Resolved::Skip => None,
        Resolved::Raw(text) => Some(text.clone()),
        Resolved::Value(value) => match value_toml(value) {
            Ok(text) => Some(text),
            Err(message) => {
                renderer.error(codes::TYPE_MISMATCH, message, span);
                None
            }
        },
    }
}

fn toml_entry(
    renderer: &mut Renderer<'_>,
    entry: &Entry,
    prefix: &[String],
    seen: &mut HashSet<String>,
    repeated: &mut HashSet<String>,
) -> Option<TomlRendered> {
    let resolved = renderer.resolve_entry(entry)?;
    let ResolvedEntry::Ready { name, args, props } = resolved else {
        return Some(TomlRendered::Skipped);
    };
    let name = name.expect("caller rejects unnamed entries");
    match &entry.children {
        None => {
            if !seen.insert(name.clone()) {
                duplicate(renderer, &name, entry.span);
                return None;
            }
            if args.is_empty() && props.is_empty() {
                renderer.error(
                    codes::NODE_SHAPE,
                    "a bare key is not valid in toml bodies; write `key #true` or guard it",
                    entry.span,
                );
                return None;
            }
            if !props.is_empty() && !args.is_empty() {
                renderer.error(
                    codes::NODE_SHAPE,
                    "an entry mixes values and properties; use either scalars or a compact object",
                    entry.span,
                );
                return None;
            }
            if !props.is_empty() {
                let mut prop_seen = HashSet::new();
                let members = props
                    .iter()
                    .map(|(key, value, span)| {
                        if !prop_seen.insert(key.clone()) {
                            duplicate(renderer, key, *span);
                            return None;
                        }
                        Some(format!(
                            "{} = {}",
                            toml_key(key),
                            toml_value_of(renderer, value, *span)?
                        ))
                    })
                    .collect::<Option<Vec<_>>>()?;
                return Some(TomlRendered::Inline(format!(
                    "{} = {{ {} }}\n",
                    toml_key(&name),
                    members.join(", ")
                )));
            }
            if args.len() == 1 {
                return Some(TomlRendered::Inline(format!(
                    "{} = {}\n",
                    toml_key(&name),
                    toml_value_of(renderer, &args[0].0, args[0].1)?
                )));
            }
            let values = args
                .iter()
                .map(|(value, span)| toml_value_of(renderer, value, *span))
                .collect::<Option<Vec<_>>>()?;
            Some(TomlRendered::Inline(format!(
                "{} = [{}]\n",
                toml_key(&name),
                values.join(", ")
            )))
        }
        Some(children) => {
            if !props.is_empty() {
                renderer.error(
                    codes::NODE_SHAPE,
                    "toml sections do not take properties; declare keys in the body",
                    entry.span,
                );
                return None;
            }
            let mut path = prefix.to_vec();
            path.push(name.clone());
            if let Some((section, span)) = args.first() {
                if args.len() > 1 {
                    renderer.error(
                        codes::NODE_SHAPE,
                        "a section takes at most one name argument before its children",
                        entry.span,
                    );
                    return None;
                }
                path.push(renderer.scalar_text(section, *span)?);
            }
            let (saw_dash, saw_named) = classify_block(children);
            if saw_dash && saw_named {
                renderer.error(
                    codes::NODE_SHAPE,
                    "a block mixes named members and `-` array elements",
                    entry.span,
                );
                return None;
            }
            if !saw_dash {
                let key = path.join(".");
                if !seen.insert(format!("table:{key}")) {
                    duplicate(renderer, &key, entry.span);
                    return None;
                }
                let header = path
                    .iter()
                    .map(|segment| toml_key(segment))
                    .collect::<Vec<_>>()
                    .join(".");
                let inner = toml_items(renderer, children, &path)?;
                return Some(TomlRendered::Table(format!("\n[{header}]\n{inner}")));
            }
            // Array mode: scalar elements inline, table elements as [[...]].
            let conflict = seen.contains(&name) && !repeated.contains(&name);
            if conflict {
                duplicate(renderer, &name, entry.span);
                return None;
            }
            let header = path
                .iter()
                .map(|segment| toml_key(segment))
                .collect::<Vec<_>>()
                .join(".");
            let mut scalars: Vec<String> = Vec::new();
            let mut table_blocks: Vec<String> = Vec::new();
            let mut failed = false;
            renderer.walk(children, 0, &mut |renderer, node| match node {
                ShapeNode::Entry(element) if element.name.is_none() => {
                    if element.children.is_some() || !element.props.is_empty() {
                        if !element.args.is_empty() && element.children.is_some() {
                            renderer.error(
                                codes::NODE_SHAPE,
                                "`-` table elements do not take values before their children",
                                element.span,
                            );
                            failed = true;
                            return;
                        }
                        let items = element_items(element);
                        match toml_items(renderer, &items, &path) {
                            Some(inner) => {
                                table_blocks.push(format!("\n[[{header}]]\n{inner}"));
                            }
                            None => failed = true,
                        }
                    } else {
                        match renderer.resolve_entry(element) {
                            Some(ResolvedEntry::Ready { args, .. }) => {
                                for (value, span) in &args {
                                    match toml_value_of(renderer, value, *span) {
                                        Some(text) => scalars.push(text),
                                        None => failed = true,
                                    }
                                }
                            }
                            Some(ResolvedEntry::Skipped) => {}
                            None => failed = true,
                        }
                    }
                }
                other => {
                    renderer.error(
                        codes::NODE_SHAPE,
                        "only `-` elements are valid inside an array block",
                        other.span(),
                    );
                    failed = true;
                }
            });
            if failed {
                return None;
            }
            if !table_blocks.is_empty() && !scalars.is_empty() {
                renderer.error(
                    codes::NODE_SHAPE,
                    "an array mixes scalar and table elements",
                    entry.span,
                );
                return None;
            }
            if !table_blocks.is_empty() {
                seen.insert(name.clone());
                repeated.insert(name);
                return Some(TomlRendered::Table(table_blocks.concat()));
            }
            if scalars.is_empty() {
                // The array expanded to nothing: omit the key entirely.
                return Some(TomlRendered::Skipped);
            }
            if !seen.insert(name.clone()) {
                duplicate(renderer, &name, entry.span);
                return None;
            }
            Some(TomlRendered::Inline(format!(
                "{} = [{}]\n",
                toml_key(&name),
                scalars.join(", ")
            )))
        }
    }
}

// INI

fn ini_items(
    renderer: &mut Renderer<'_>,
    items: &[ConfigItem<ShapeNode>],
    opts: &IniOpts,
    prefix: &str,
) -> Option<String> {
    let mut output = String::new();
    let mut seen = HashSet::new();
    let mut saw_section = false;
    let mut failed = false;
    renderer.walk(items, 0, &mut |renderer, node| match node {
        ShapeNode::Comment { text, .. } => output.push_str(&format!("# {text}\n")),
        ShapeNode::Raw { text, .. } => output.push_str(&format!("{text}\n")),
        ShapeNode::Line { span, .. } => {
            renderer.error(codes::NODE_SHAPE, "`@line` is not valid in ini bodies", *span);
            failed = true;
        }
        node @ (ShapeNode::File { .. } | ShapeNode::Compose { .. }) => {
            match renderer.resource_text(node) {
                Some(text) => push_block(&mut output, &text),
                None => failed = true,
            }
        }
        ShapeNode::Spread(spread) => {
            if saw_section {
                renderer.error(
                    codes::NODE_SHAPE,
                    "`@spread` appears after a section at the same level; move it above sections",
                    spread.span,
                );
                failed = true;
                return;
            }
            let Some(fields) = spread_fields(renderer, spread) else {
                failed = true;
                return;
            };
            for (name, value) in fields {
                let values = [(Resolved::Value(value), spread.span)];
                if ini_spread_line(
                    renderer,
                    &mut output,
                    &mut seen,
                    opts,
                    &name,
                    &values,
                    spread.span,
                )
                .is_none()
                {
                    failed = true;
                    return;
                }
            }
        }
        ShapeNode::Entry(entry) => {
            let Some(resolved) = renderer.resolve_entry(entry) else {
                failed = true;
                return;
            };
            let ResolvedEntry::Ready { name, args, props } = resolved else {
                return;
            };
            let Some(name) = name else {
                renderer.error(
                    codes::NODE_SHAPE,
                    "`-` array elements are not valid in ini bodies; repeat the key instead",
                    entry.span,
                );
                failed = true;
                return;
            };
            match &entry.children {
                None => {
                    if saw_section {
                        renderer.error(
                            codes::NODE_SHAPE,
                            format!(
                                "key `{name}` appears after a section at the same level; move keys above sections"
                            ),
                            entry.span,
                        );
                        failed = true;
                        return;
                    }
                    if !props.is_empty() && !args.is_empty() {
                        renderer.error(
                            codes::NODE_SHAPE,
                            "an entry mixes values and properties",
                            entry.span,
                        );
                        failed = true;
                        return;
                    }
                    if !props.is_empty() {
                        for (key, value, span) in &props {
                            let dotted = format!("{name}.{key}");
                            let values = [(clone_resolved(value), *span)];
                            if ini_line(
                                renderer, &mut output, &mut seen, opts, entry, &dotted, &values,
                                *span,
                            )
                            .is_none()
                            {
                                failed = true;
                                return;
                            }
                        }
                        return;
                    }
                    if ini_line(
                        renderer, &mut output, &mut seen, opts, entry, &name, &args, entry.span,
                    )
                    .is_none()
                    {
                        failed = true;
                    }
                }
                Some(children) => {
                    let mut path = if prefix.is_empty() {
                        name.clone()
                    } else {
                        format!("{prefix}.{name}")
                    };
                    if let Some((section, span)) = args.first() {
                        if args.len() > 1 {
                            renderer.error(
                                codes::NODE_SHAPE,
                                "a section takes at most one name argument",
                                entry.span,
                            );
                            failed = true;
                            return;
                        }
                        match renderer.scalar_text(section, *span) {
                            Some(text) => path = format!("{path}.{text}"),
                            None => {
                                failed = true;
                                return;
                            }
                        }
                    }
                    if !props.is_empty() {
                        renderer.error(
                            codes::NODE_SHAPE,
                            "ini sections do not take properties; declare keys in the body",
                            entry.span,
                        );
                        failed = true;
                        return;
                    }
                    if let Err(error) = validate_ini_name(&path, true, entry.span) {
                        renderer.diagnostics.push(error);
                        failed = true;
                        return;
                    }
                    if !seen.insert(format!("section:{path}")) {
                        duplicate(renderer, &path, entry.span);
                        failed = true;
                        return;
                    }
                    saw_section = true;
                    match ini_items(renderer, children, opts, &path) {
                        Some(inner) => {
                            output.push_str(&format!("\n[{path}]\n{inner}"));
                        }
                        None => failed = true,
                    }
                }
            }
        }
    });
    if failed { None } else { Some(output) }
}

fn clone_resolved(resolved: &Resolved) -> Resolved {
    match resolved {
        Resolved::Value(value) => Resolved::Value(value.clone()),
        Resolved::Raw(text) => Resolved::Raw(text.clone()),
        Resolved::Skip => Resolved::Skip,
    }
}

/// An `@spread` field line: file-level quote mode, no per-entry override.
fn ini_spread_line(
    renderer: &mut Renderer<'_>,
    output: &mut String,
    seen: &mut HashSet<String>,
    opts: &IniOpts,
    name: &str,
    args: &[(Resolved, Span)],
    span: Span,
) -> Option<()> {
    ini_emit(renderer, output, seen, opts, opts.quote, name, args, span)
}

#[allow(clippy::too_many_arguments)]
fn ini_line(
    renderer: &mut Renderer<'_>,
    output: &mut String,
    seen: &mut HashSet<String>,
    opts: &IniOpts,
    entry: &Entry,
    name: &str,
    args: &[(Resolved, Span)],
    span: Span,
) -> Option<()> {
    let quote = entry.quote.unwrap_or(opts.quote);
    ini_emit(renderer, output, seen, opts, quote, name, args, span)
}

#[allow(clippy::too_many_arguments)]
fn ini_emit(
    renderer: &mut Renderer<'_>,
    output: &mut String,
    seen: &mut HashSet<String>,
    opts: &IniOpts,
    quote: QuoteMode,
    name: &str,
    args: &[(Resolved, Span)],
    span: Span,
) -> Option<()> {
    if let Err(error) = validate_ini_name(name, false, span) {
        renderer.diagnostics.push(error);
        return None;
    }
    let mut values: Vec<String> = Vec::new();
    if args.is_empty() {
        values.push(String::new());
    }
    for (resolved, value_span) in args {
        match resolved {
            // A list-valued reference expands to repeated `key=` lines.
            Resolved::Value(Value::List(items)) => {
                for item in items {
                    values.push(renderer.scalar_text(&Resolved::Value(item.clone()), *value_span)?);
                }
            }
            other => values.push(renderer.scalar_text(other, *value_span)?),
        }
    }
    let repeats = values.len() > 1;
    if !repeats && !seen.insert(name.to_owned()) {
        duplicate(renderer, name, span);
        return None;
    }
    for value in values {
        let value = match quote {
            QuoteMode::None => value,
            QuoteMode::Double => format!("\"{}\"", json_escape(&value)),
        };
        output.push_str(&format!("{name}{}{value}\n", opts.separator));
    }
    Some(())
}

// Text

fn text_root(
    renderer: &mut Renderer<'_>,
    items: &[ConfigItem<ShapeNode>],
    opts: &TextOpts,
    span: Span,
) -> Option<String> {
    let mut output = text_items(renderer, items, opts, 0, "")?;
    if opts.single {
        let lines = output.lines().count();
        if lines != 1 {
            renderer.error(
                codes::NODE_SHAPE,
                format!("single output requires exactly one line, found {lines}"),
                span,
            );
            return None;
        }
    }
    if !opts.final_newline && output.ends_with('\n') {
        output.pop();
    }
    Some(output)
}

fn text_items(
    renderer: &mut Renderer<'_>,
    items: &[ConfigItem<ShapeNode>],
    opts: &TextOpts,
    depth: usize,
    prefix: &str,
) -> Option<String> {
    let mut output = String::new();
    let mut failed = false;
    let pad = if opts.layout == TextLayout::Braces {
        opts.indent.repeat(depth)
    } else {
        String::new()
    };
    renderer.walk(items, 0, &mut |renderer, node| match node {
        ShapeNode::Comment { text, .. } => output.push_str(&format!("{pad}# {text}\n")),
        ShapeNode::Raw { text, .. } => {
            output.push_str(text);
            output.push('\n');
        }
        ShapeNode::Line { value, span } => match renderer.resolve(value) {
            Some(Resolved::Skip) => {}
            Some(resolved) => match renderer.scalar_text(&resolved, *span) {
                Some(text) => output.push_str(&format!("{pad}{text}\n")),
                None => failed = true,
            },
            None => failed = true,
        },
        node @ (ShapeNode::File { .. } | ShapeNode::Compose { .. }) => {
            match renderer.resource_text(node) {
                Some(text) => push_block(&mut output, &text),
                None => failed = true,
            }
        }
        ShapeNode::Spread(spread) => {
            let Some(fields) = spread_fields(renderer, spread) else {
                failed = true;
                return;
            };
            for (name, value) in fields {
                let key = text_key(prefix, &name, opts);
                let flat_values = match value {
                    Value::List(items) => items,
                    other => vec![other],
                };
                for item in flat_values {
                    match renderer.scalar_text(&Resolved::Value(item), spread.span) {
                        Some(text) => {
                            let text = match opts.quote {
                                QuoteMode::None => text,
                                QuoteMode::Double => format!("\"{}\"", json_escape(&text)),
                            };
                            output.push_str(&format!("{pad}{key}{}{text}\n", opts.separator));
                        }
                        None => {
                            failed = true;
                            return;
                        }
                    }
                }
            }
        }
        ShapeNode::Entry(entry) => {
            let Some(resolved) = renderer.resolve_entry(entry) else {
                failed = true;
                return;
            };
            let ResolvedEntry::Ready { name, args, props } = resolved else {
                return;
            };
            match &entry.children {
                None => {
                    let Some(name) = name else {
                        renderer.error(
                            codes::NODE_SHAPE,
                            "`-` array elements are not valid outside a block in text bodies",
                            entry.span,
                        );
                        failed = true;
                        return;
                    };
                    let key = text_key(prefix, &name, opts);
                    if !props.is_empty() && !args.is_empty() {
                        renderer.error(
                            codes::NODE_SHAPE,
                            "an entry mixes values and properties",
                            entry.span,
                        );
                        failed = true;
                        return;
                    }
                    if !props.is_empty() {
                        // Compact object: sub-block (braces) or dotted keys (flat).
                        if opts.layout == TextLayout::Braces {
                            let mut inner = String::new();
                            let inner_pad = opts.indent.repeat(depth + 1);
                            for (prop, value, span) in &props {
                                match text_scalar(renderer, value, *span, entry, opts) {
                                    Some(text) => inner.push_str(&format!(
                                        "{inner_pad}{prop}{}{text}\n",
                                        opts.separator
                                    )),
                                    None => {
                                        failed = true;
                                        return;
                                    }
                                }
                            }
                            output.push_str(&format!("{pad}{name} {{\n{inner}{pad}}}\n"));
                        } else {
                            for (prop, value, span) in &props {
                                match text_scalar(renderer, value, *span, entry, opts) {
                                    Some(text) => output.push_str(&format!(
                                        "{key}.{prop}{}{text}\n",
                                        opts.separator
                                    )),
                                    None => {
                                        failed = true;
                                        return;
                                    }
                                }
                            }
                        }
                        return;
                    }
                    if args.is_empty() {
                        output.push_str(&format!("{pad}{key}\n"));
                        return;
                    }
                    let mut values: Vec<String> = Vec::new();
                    for (resolved, span) in &args {
                        match resolved {
                            Resolved::Value(Value::List(items)) => {
                                for item in items {
                                    match text_scalar(
                                        renderer,
                                        &Resolved::Value(item.clone()),
                                        *span,
                                        entry,
                                        opts,
                                    ) {
                                        Some(text) => values.push(text),
                                        None => {
                                            failed = true;
                                            return;
                                        }
                                    }
                                }
                            }
                            other => match text_scalar(renderer, other, *span, entry, opts) {
                                Some(text) => values.push(text),
                                None => {
                                    failed = true;
                                    return;
                                }
                            },
                        }
                    }
                    for value in values {
                        output.push_str(&format!("{pad}{key}{}{value}\n", opts.separator));
                    }
                }
                Some(children) => {
                    if !props.is_empty() {
                        renderer.error(
                            codes::NODE_SHAPE,
                            "text sections do not take properties; declare keys in the body",
                            entry.span,
                        );
                        failed = true;
                        return;
                    }
                    let Some(name) = name else {
                        // `-` element group: an anonymous repeated brace group.
                        match text_items(renderer, children, opts, depth + 1, prefix) {
                            Some(inner) => {
                                output.push_str(&format!("{pad}{{\n{inner}{pad}}}\n"));
                            }
                            None => failed = true,
                        }
                        return;
                    };
                    let mut section_names: Vec<String> = Vec::new();
                    for (section, span) in &args {
                        match renderer.scalar_text(section, *span) {
                            Some(text) => section_names.push(text),
                            None => {
                                failed = true;
                                return;
                            }
                        }
                    }
                    if opts.layout == TextLayout::Braces {
                        let mut header = name.clone();
                        for section in &section_names {
                            let quote_it = match entry.quote {
                                Some(QuoteMode::Double) => true,
                                Some(QuoteMode::None) => false,
                                None => section
                                    .chars()
                                    .any(|c| c.is_whitespace() || matches!(c, '{' | '}' | '"')),
                            };
                            let quoted = if quote_it {
                                format!("\"{}\"", json_escape(section))
                            } else {
                                section.clone()
                            };
                            header.push(' ');
                            header.push_str(&quoted);
                        }
                        match text_items(renderer, children, opts, depth + 1, prefix) {
                            Some(inner) => {
                                output.push_str(&format!("{pad}{header} {{\n{inner}{pad}}}\n"));
                            }
                            None => failed = true,
                        }
                    } else {
                        let mut path = text_key(prefix, &name, opts);
                        for section in &section_names {
                            path = format!("{path}.{section}");
                        }
                        match text_items(renderer, children, opts, depth, &path) {
                            Some(inner) => output.push_str(&inner),
                            None => failed = true,
                        }
                    }
                }
            }
        }
    });
    if failed { None } else { Some(output) }
}

fn text_key(prefix: &str, name: &str, opts: &TextOpts) -> String {
    if opts.layout == TextLayout::Flat && !prefix.is_empty() {
        format!("{prefix}.{name}")
    } else {
        name.to_owned()
    }
}

fn text_scalar(
    renderer: &mut Renderer<'_>,
    resolved: &Resolved,
    span: Span,
    entry: &Entry,
    opts: &TextOpts,
) -> Option<String> {
    let text = renderer.scalar_text(resolved, span)?;
    Some(match entry.quote.unwrap_or(opts.quote) {
        QuoteMode::None => text,
        QuoteMode::Double => format!("\"{}\"", json_escape(&text)),
    })
}
