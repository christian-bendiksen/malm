//! Parsing and serialization for JSON, JSONC, TOML, INI, text, and Lua render
//! outputs. Only `@`-prefixed node names are controls; all others are target
//! data.

use crate::lang::ast::{EachBlock, Predicate, RangeBlock, Ref, WhenBlock};
use crate::lang::budget::{Budget, OutputBudget};
use crate::lang::config_file::generic::{
    json_escape, toml_key, validate_ini_name, write_json_escape, write_lua_escape,
};
use crate::lang::config_file::{self, ConfigItem};
use crate::lang::diag::{Diagnostic, Diagnostics, FileId, Span, codes};
use crate::lang::kdl_util::{
    ParseResult, at_entry, at_node, bool_prop, child_nodes, entry_span, expect_args, int_prop,
    node_span, opt_str_prop, prop_entry, reject_unknown_children, reject_unknown_props,
    removed_control, req_str_arg, req_str_prop, validate_document_depth, validate_else,
};
use crate::lang::scope::Scope;
use crate::lang::text::{self, TemplateSyntax};
use crate::lang::value::{Value, format_float};
use kdl::{KdlEntry, KdlNode, KdlValue};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::{Path, PathBuf};

#[derive(Debug)]
pub struct RenderOutput {
    pub to: PathExpr,
    pub body: RenderBody,
    pub renderer: Option<String>,
    pub transforms: Vec<String>,
    pub executable: bool,
    /// Directory of the declaring file, used for `@include-file "./"` sources.
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
    Component { format: String },
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
    pub fn format_name(&self) -> &str {
        match self {
            Self::Json {
                comments: false, ..
            } => "json",
            Self::Json { comments: true, .. } => "jsonc",
            Self::Toml => "toml",
            Self::Ini(_) => "ini",
            Self::Text(_) => "key-value",
            Self::Lua { .. } => "lua",
            Self::Component { format } => format,
        }
    }
}

/// A data node: `name args... props... { children }`, an array element (`-`), or
/// a directive leaf.
#[derive(Debug, Clone)]
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
    /// `@insert-fields "rec"`: emit every record field as a key/value here.
    Spread(Spread),
    /// `@include-file "./x" [interpolate=#true]`: include a module-relative file.
    File {
        path: String,
        interpolate: bool,
        span: Span,
    },
    /// `@requirements`: one line per aggregated profile requirement subject.
    Requirements {
        span: Span,
    },
    /// `@profiles`: one line per selectable (non-abstract) profile name.
    Profiles {
        span: Span,
    },
    /// `@include-fragment "frag"`: inline the included fragment.
    Compose {
        fragment: String,
        span: Span,
    },
}

#[derive(Debug, Clone)]
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

#[derive(Debug, Clone)]
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

#[derive(Debug, Clone)]
pub enum NodeName {
    Literal(String),
    FString { raw: String, span: Span },
}

#[derive(Debug, Clone)]
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
            | Self::Requirements { span }
            | Self::Profiles { span }
            | Self::Compose { span, .. } => *span,
            Self::Spread(spread) => spread.span,
        }
    }
}

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
    if let Some(entry) = prop_entry(node, "renderer") {
        return Err(at_entry(file, entry).error(
            codes::NODE_SHAPE,
            "`renderer=` was removed; use `component-renderer=`",
        ));
    }
    let renderer = opt_str_prop(file, node, "component-renderer")?;
    let executable = bool_prop(file, node, "executable")?;
    let children = child_nodes(node);
    let (children, transforms) = extract_output_transforms(file, children)?;

    if let Some(renderer) = renderer {
        reject_render_props(file, node, &["component-renderer"])?;
        validate_component_identifier(&format, "format", span)?;
        validate_component_identifier(&renderer, "renderer component", span)?;
        validate_document_depth(file, &children)?;
        let items = parse_items(file, &children)?;
        validate_component_items(&items, true)?;
        return Ok(OutputNode::Render(RenderOutput {
            to,
            body: RenderBody {
                format: FormatSpec::Component { format },
                items,
                span,
            },
            renderer: Some(renderer),
            transforms,
            executable,
            dir: dir.to_path_buf(),
            span,
        }));
    }

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
            let nodes = children;
            validate_document_depth(file, &nodes)?;
            crate::lang::parse::validate_structural_kdl_nodes(file, &nodes)?;
            let to = literal_path(to, span, "kdl")?;
            Ok(OutputNode::KdlConfig(KdlConfigOutput {
                to,
                dialect,
                body: KdlConfigBody::Document { nodes, span, file },
                transforms,
                span,
            }))
        }
        "xml" | "css" => {
            if executable {
                return Err(executable_unsupported(span, &format));
            }
            let body = config_file::parse_body(file, &format, node, &children, span)?;
            let to = literal_path(to, span, &format)?;
            Ok(OutputNode::ConfigFile(config_file::ConfigFileOutput {
                to,
                body,
                transforms,
                span,
            }))
        }
        _ => {
            let format = parse_format_spec(file, node, &format, span)?;
            validate_document_depth(file, &children)?;
            let items = parse_items(file, &children)?;
            Ok(OutputNode::Render(RenderOutput {
                to,
                body: RenderBody {
                    format,
                    items,
                    span,
                },
                renderer: None,
                transforms,
                executable,
                dir: dir.to_path_buf(),
                span,
            }))
        }
    }
}

fn validate_component_identifier(value: &str, kind: &str, span: Span) -> ParseResult<()> {
    malm_types::ContributionName::new(value).map_err(|error| {
        Diagnostic::error(
            codes::NODE_SHAPE,
            format!("component-backed render {kind} {value:?} is not an identifier: {error}"),
        )
        .with_span(span)
    })?;
    Ok(())
}

fn extract_output_transforms(
    file: FileId,
    children: &[KdlNode],
) -> ParseResult<(Vec<KdlNode>, Vec<String>)> {
    let mut body = Vec::with_capacity(children.len());
    let mut transforms = Vec::new();
    for (index, child) in children.iter().enumerate() {
        if child.name().value() == "@else"
            && index
                .checked_sub(1)
                .and_then(|previous| children.get(previous))
                .is_none_or(|previous| {
                    !matches!(
                        previous.name().value(),
                        "@if" | "@if-present" | "@if-nonempty"
                    )
                })
        {
            return Err(at_node(file, child).error(
                codes::NODE_SHAPE,
                "`@else` must immediately follow an `@if`, `@if-present`, or `@if-nonempty` sibling",
            ));
        }
        if child.name().value() == "@transform" {
            return Err(removed_control(file, child).expect("known removed control"));
        }
        if child.name().value() != "@component-transform" {
            body.push(child.clone());
            continue;
        }
        reject_unknown_props(file, child, &[])?;
        reject_unknown_children(file, child, &[])?;
        let transform = literal_string_arg(file, child, "`@component-transform` component name")?;
        malm_types::ContributionName::new(&transform).map_err(|error| {
            at_node(file, child).error(
                codes::NODE_SHAPE,
                format!(
                    "`@component-transform` name {transform:?} is not a contribution identifier: {error}"
                ),
            )
        })?;
        transforms.push(transform);
    }
    Ok((body, transforms))
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
        return Err(at_node(file, node).error(
            codes::NODE_SHAPE,
            "`render` requires a destination path as its first argument",
        ));
    };
    if args.len() > 1 {
        return Err(at_entry(file, args[1]).error(
            codes::NODE_SHAPE,
            "`render` takes exactly one positional argument (the destination path)",
        ));
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
    let all: Vec<&str> = ["format", "executable"]
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
                    at_entry(file, entry)
                        .error(codes::NODE_SHAPE, "`final-newline=` must be boolean")
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
        return Err(at_node(file, node).error(
            codes::NODE_SHAPE,
            "`separator=` must not contain control characters",
        ));
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
            return Err(at_entry(file, entry).error(
                codes::NODE_SHAPE,
                "`indent=` must contain only spaces or tabs",
            ));
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
            at_entry(file, entry).error(
                codes::NODE_SHAPE,
                "`indent=` must be whitespace or an integer from 0 through 16",
            )
        })
}

const DIRECTIVES_HELP: &str = "known directives: @if, @if-present, @if-nonempty, @else, \
     @for-each, @for-range, @insert-documents, @insert-fields, @comment, @raw-text, \
     @line, @include-file, @include-fragment, @requirements, @profiles, @lit";

/// Parses a render body. Only `@`-prefixed names are Malm constructs;
/// `@else` attaches to the immediately preceding canonical condition sibling.
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
            "@if" | "@if-present" | "@if-nonempty" => {
                let predicate = parse_render_condition(file, node)?;
                let then = parse_items(file, child_nodes(node))?;
                let mut otherwise = Vec::new();
                if let Some(next) = nodes.peek()
                    && next.name().value() == "@else"
                {
                    let next = nodes.next().expect("peeked");
                    validate_else(file, next)?;
                    otherwise = parse_items(file, child_nodes(next))?;
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
                    "`@else` must immediately follow an `@if`, `@if-present`, or `@if-nonempty` sibling",
                )
                .with_span(span));
            }
            "@for-each" => {
                let (binding, source) = parse_render_each(file, node)?;
                out.push(ConfigItem::Each(EachBlock {
                    binding,
                    source,
                    body: parse_items(file, child_nodes(node))?,
                    span,
                }));
            }
            "@for-range" => {
                let (binding, from, through) = parse_render_range(file, node)?;
                out.push(ConfigItem::Range(RangeBlock {
                    binding,
                    from,
                    through,
                    body: parse_items(file, child_nodes(node))?,
                    span,
                }));
            }
            "@insert-documents" => {
                reject_unknown_props(file, node, &[])?;
                reject_unknown_children(file, node, &[])?;
                out.push(ConfigItem::Splice(plain_string_ref(
                    file,
                    node,
                    "`@insert-documents` collection reference",
                )?));
            }
            "@insert-fields" => {
                reject_unknown_props(file, node, &["case"])?;
                reject_unknown_children(file, node, &[])?;
                let reference = plain_string_ref(file, node, "`@insert-fields` record reference")?;
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
            "@raw-text" => {
                reject_unknown_props(file, node, &[])?;
                reject_unknown_children(file, node, &[])?;
                out.push(ConfigItem::Value {
                    value: ShapeNode::Raw {
                        text: literal_string_arg(file, node, "`@raw-text` text")?,
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
            "@include-file" => {
                reject_unknown_props(file, node, &["interpolate"])?;
                reject_unknown_children(file, node, &[])?;
                let path = literal_string_arg(file, node, "`@include-file` path")?;
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
            "@include-fragment" => {
                reject_unknown_props(file, node, &[])?;
                reject_unknown_children(file, node, &[])?;
                out.push(ConfigItem::Value {
                    value: ShapeNode::Compose {
                        fragment: literal_string_arg(
                            file,
                            node,
                            "`@include-fragment` fragment name",
                        )?,
                        span,
                    },
                    span,
                });
            }
            "@requirements" => {
                reject_unknown_props(file, node, &[])?;
                reject_unknown_children(file, node, &[])?;
                expect_args(file, node, 0)?;
                out.push(ConfigItem::Value {
                    value: ShapeNode::Requirements { span },
                    span,
                });
            }
            "@profiles" => {
                reject_unknown_props(file, node, &[])?;
                reject_unknown_children(file, node, &[])?;
                expect_args(file, node, 0)?;
                out.push(ConfigItem::Value {
                    value: ShapeNode::Profiles { span },
                    span,
                });
            }
            "@lit" => {
                if node.ty().is_some() {
                    return Err(at_node(file, node)
                        .error(codes::NODE_SHAPE, "`@lit` does not take a node annotation"));
                }
                let Some((target_index, target)) = crate::lang::kdl_util::escaped_node_target(node)
                else {
                    return Err(Diagnostic::error(
                        codes::NODE_SHAPE,
                        "`@lit` requires a literal key as its first argument",
                    )
                    .with_span(span));
                };
                let name = target
                    .value()
                    .as_string()
                    .filter(|name| target.ty().is_none() && !name.is_empty())
                    .ok_or_else(|| {
                        at_entry(file, target).error(
                            codes::NODE_SHAPE,
                            "`@lit` key must be a non-empty plain string",
                        )
                    })?
                    .to_owned();
                out.push(ConfigItem::Value {
                    value: parse_entry(
                        file,
                        node,
                        Some(NodeName::Literal(name)),
                        Some(target_index),
                    )?,
                    span,
                });
            }
            other if other.starts_with('@') => {
                if let Some(diagnostic) = removed_control(file, node) {
                    return Err(diagnostic);
                }
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
                    value: parse_entry(file, node, None, None)?,
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
                    value: parse_entry(file, node, Some(name), None)?,
                    span,
                });
            }
        }
    }
    Ok(out)
}

#[derive(Clone, Copy, Default)]
struct ComponentBlockShape {
    named: Option<Span>,
    list: Option<Span>,
}

impl ComponentBlockShape {
    fn include(&mut self, other: Self) {
        self.named = self.named.or(other.named);
        self.list = self.list.or(other.list);
    }
}

/// Validates the source shape before controls are evaluated so an inactive
/// branch cannot hide target-output syntax or an untyped container shape.
fn validate_component_items(
    items: &[ConfigItem<ShapeNode>],
    root: bool,
) -> ParseResult<ComponentBlockShape> {
    let mut shape = ComponentBlockShape::default();
    for item in items {
        match item {
            ConfigItem::Value { value, span } => match value {
                ShapeNode::Entry(entry) => {
                    validate_component_entry(entry)?;
                    if let Some(children) = &entry.children {
                        let children_shape = validate_component_items(children, false)?;
                        if !entry.props.is_empty()
                            && let Some(span) = children_shape.list
                        {
                            return Err(Diagnostic::error(
                                codes::NODE_SHAPE,
                                "a component document block cannot mix properties and `-` list elements",
                            )
                            .with_span(span));
                        }
                    }
                    if entry.name.is_some() {
                        shape.named = shape.named.or(Some(*span));
                    } else {
                        shape.list = shape.list.or(Some(*span));
                    }
                }
                ShapeNode::Spread(_) => shape.named = shape.named.or(Some(*span)),
                ShapeNode::Comment { .. } => {
                    return Err(component_target_construct("@comment", *span));
                }
                ShapeNode::Raw { .. } => {
                    return Err(component_target_construct("@raw-text", *span));
                }
                ShapeNode::Line { .. } => {
                    return Err(component_target_construct("@line", *span));
                }
                ShapeNode::File { .. } => {
                    return Err(component_target_construct("@include-file", *span));
                }
                ShapeNode::Compose { .. } => {
                    return Err(component_target_construct("@include-fragment", *span));
                }
                ShapeNode::Requirements { .. } => {
                    return Err(component_target_construct("@requirements", *span));
                }
                ShapeNode::Profiles { .. } => {
                    return Err(component_target_construct("@profiles", *span));
                }
            },
            ConfigItem::When(when) => {
                shape.include(validate_component_items(&when.then, root)?);
                shape.include(validate_component_items(&when.otherwise, root)?);
            }
            ConfigItem::Each(each) => {
                shape.include(validate_component_items(&each.body, root)?);
            }
            ConfigItem::Range(range) => {
                shape.include(validate_component_items(&range.body, root)?);
            }
            ConfigItem::Splice(_) => {}
        }
    }
    validate_component_block_shape(shape, root)
}

fn validate_component_entry(entry: &Entry) -> ParseResult<()> {
    if entry.quote.is_some() {
        return Err(Diagnostic::error(
            codes::NODE_SHAPE,
            "`@quote=` is target-output syntax and has no component document representation",
        )
        .with_span(entry.span));
    }
    for value in entry
        .args
        .iter()
        .chain(entry.props.iter().map(|(_, value, _)| value))
    {
        if matches!(value, ValueExpr::Raw(..)) {
            return Err(Diagnostic::error(
                codes::NODE_SHAPE,
                "`(raw)` is target-output syntax and has no component document representation",
            )
            .with_span(value.span()));
        }
    }
    match &entry.children {
        None if entry.args.is_empty() && entry.props.is_empty() => Err(Diagnostic::error(
            codes::NODE_SHAPE,
            "a component document entry requires a value, properties, or children",
        )
        .with_span(entry.span)),
        None if !entry.args.is_empty() && !entry.props.is_empty() => Err(Diagnostic::error(
            codes::NODE_SHAPE,
            "a component document entry cannot mix arguments and properties",
        )
        .with_span(entry.span)),
        Some(_) if entry.args.len() > 1 => Err(Diagnostic::error(
            codes::NODE_SHAPE,
            "a component document record takes at most one name argument before its children",
        )
        .with_span(entry.span)),
        _ => Ok(()),
    }
}

fn validate_component_block_shape(
    shape: ComponentBlockShape,
    root: bool,
) -> ParseResult<ComponentBlockShape> {
    if root && let Some(span) = shape.list {
        return Err(Diagnostic::error(
            codes::NODE_SHAPE,
            "a component document root must be a record; root `-` lists are not allowed",
        )
        .with_span(span));
    }
    if shape.named.is_some()
        && let Some(span) = shape.list
    {
        return Err(Diagnostic::error(
            codes::NODE_SHAPE,
            "a component document block cannot mix named record fields and `-` list elements",
        )
        .with_span(span));
    }
    Ok(shape)
}

/// Extends source-only component preflight with the concrete documents held
/// by this profile. Both branches and every available loop item are inspected
/// without applying predicates, so inactive controls cannot conceal an
/// invalid inserted component shape.
fn validate_component_insertions(
    items: &[ConfigItem<ShapeNode>],
    root: bool,
    scope: &mut Scope,
    splice_stack: &mut Vec<String>,
    budget: &mut Budget,
    depth: usize,
) -> ParseResult<ComponentBlockShape> {
    let mut shape = ComponentBlockShape::default();
    for item in items {
        component_preflight_budget(budget.count_operations(1), item.span())?;
        component_preflight_budget(budget.count_generated_nodes(1), item.span())?;
        match item {
            ConfigItem::Value {
                value: ShapeNode::Entry(entry),
                span,
            } => {
                validate_component_entry(entry)?;
                if let Some(children) = &entry.children {
                    component_preflight_budget(budget.check_nesting(depth + 1), entry.span)?;
                    let children_shape = validate_component_insertions(
                        children,
                        false,
                        scope,
                        splice_stack,
                        budget,
                        depth + 1,
                    )?;
                    if !entry.props.is_empty()
                        && let Some(span) = children_shape.list
                    {
                        return Err(Diagnostic::error(
                            codes::NODE_SHAPE,
                            "a component document block cannot mix properties and `-` list elements",
                        )
                        .with_span(span));
                    }
                }
                if entry.name.is_some() {
                    shape.named = shape.named.or(Some(*span));
                } else {
                    shape.list = shape.list.or(Some(*span));
                }
            }
            ConfigItem::Value { value, span } => match value {
                ShapeNode::Spread(_) => shape.named = shape.named.or(Some(*span)),
                ShapeNode::Comment { .. } => {
                    return Err(component_target_construct("@comment", *span));
                }
                ShapeNode::Raw { .. } => {
                    return Err(component_target_construct("@raw-text", *span));
                }
                ShapeNode::Line { .. } => {
                    return Err(component_target_construct("@line", *span));
                }
                ShapeNode::File { .. } => {
                    return Err(component_target_construct("@include-file", *span));
                }
                ShapeNode::Compose { .. } => {
                    return Err(component_target_construct("@include-fragment", *span));
                }
                ShapeNode::Requirements { .. } => {
                    return Err(component_target_construct("@requirements", *span));
                }
                ShapeNode::Profiles { .. } => {
                    return Err(component_target_construct("@profiles", *span));
                }
                ShapeNode::Entry(_) => unreachable!("entry handled above"),
            },
            ConfigItem::When(when) => {
                component_preflight_budget(budget.check_nesting(depth + 1), when.span)?;
                shape.include(validate_component_insertions(
                    &when.then,
                    root,
                    scope,
                    splice_stack,
                    budget,
                    depth + 1,
                )?);
                shape.include(validate_component_insertions(
                    &when.otherwise,
                    root,
                    scope,
                    splice_stack,
                    budget,
                    depth + 1,
                )?);
            }
            ConfigItem::Each(each) => {
                component_preflight_budget(budget.check_nesting(depth + 1), each.span)?;
                let value_count = match scope.lookup(&each.source.name) {
                    Some(Value::List(values)) => values.len(),
                    Some(Value::Collection(collection)) => collection.items.len(),
                    _ => 0,
                };
                component_preflight_budget(budget.check_collection_size(value_count), each.span)?;
                component_preflight_budget(budget.count_iterations(value_count as u64), each.span)?;
                if value_count == 0 {
                    shape.include(validate_component_insertions(
                        &each.body,
                        root,
                        scope,
                        splice_stack,
                        budget,
                        depth + 1,
                    )?);
                }
                for index in 0..value_count {
                    let Some((key, value)) = component_loop_item(scope, &each.source.name, index)
                    else {
                        continue;
                    };
                    let keyed = key.is_some();
                    if let Some(key) = key {
                        scope.push_binding(format!("{}.key", each.binding), Value::String(key));
                    }
                    scope.push_binding(&each.binding, value);
                    let item_shape = validate_component_insertions(
                        &each.body,
                        root,
                        scope,
                        splice_stack,
                        budget,
                        depth + 1,
                    );
                    scope.pop_binding();
                    if keyed {
                        scope.pop_binding();
                    }
                    shape.include(item_shape?);
                }
            }
            ConfigItem::Range(range) => {
                let count = range
                    .through
                    .checked_sub(range.from)
                    .and_then(|value| value.checked_add(1))
                    .filter(|value| *value > 0)
                    .unwrap_or(0);
                component_preflight_budget(budget.check_nesting(depth + 1), range.span)?;
                component_preflight_budget(budget.check_range(count), range.span)?;
                component_preflight_budget(budget.count_iterations(count as u64), range.span)?;
                scope.push_binding(&range.binding, Value::Int(range.from));
                let range_shape = validate_component_insertions(
                    &range.body,
                    root,
                    scope,
                    splice_stack,
                    budget,
                    depth + 1,
                );
                scope.pop_binding();
                shape.include(range_shape?);
            }
            ConfigItem::Splice(reference) => {
                component_preflight_budget(budget.check_nesting(depth + 1), reference.span)?;
                let Some(Value::Collection(collection)) = scope.lookup(&reference.name) else {
                    continue;
                };
                let item_count = collection.items.len();
                component_preflight_budget(
                    budget.check_collection_size(item_count),
                    reference.span,
                )?;
                component_preflight_budget(
                    budget.count_operations(item_count as u64),
                    reference.span,
                )?;
                if let Some(start) = splice_stack.iter().position(|name| name == &reference.name) {
                    let mut cycle = splice_stack[start..].to_vec();
                    cycle.push(reference.name.clone());
                    return Err(Diagnostic::error(
                        codes::KDL_GEN,
                        format!(
                            "component @insert-documents cycle detected: {}",
                            cycle.join(" -> ")
                        ),
                    )
                    .with_span(reference.span));
                }
                for item in &collection.items {
                    if let Value::KdlDocument(document) = &item.value {
                        reserve_component_kdl_shape(
                            document.nodes(),
                            item.span.file,
                            budget,
                            depth + 1,
                        )?;
                    }
                }
                splice_stack.push(reference.name.clone());
                for index in 0..item_count {
                    let Some(item) = scope
                        .lookup(&reference.name)
                        .and_then(|value| match value {
                            Value::Collection(collection) => collection.items.get(index),
                            _ => None,
                        })
                        .cloned()
                    else {
                        continue;
                    };
                    let Value::KdlDocument(document) = item.value else {
                        continue;
                    };
                    crate::lang::parse::validate_structural_kdl_document(
                        item.span.file,
                        document.nodes(),
                    )?;
                    let inserted = parse_items(item.span.file, document.nodes())?;
                    match validate_component_insertions(
                        &inserted,
                        root,
                        scope,
                        splice_stack,
                        budget,
                        depth + 1,
                    ) {
                        Ok(inserted_shape) => shape.include(inserted_shape),
                        Err(diagnostic) => {
                            splice_stack.pop();
                            return Err(diagnostic);
                        }
                    }
                }
                splice_stack.pop();
            }
        }
    }
    validate_component_block_shape(shape, root)
}

fn component_loop_item(
    scope: &Scope,
    source: &str,
    index: usize,
) -> Option<(Option<String>, Value)> {
    match scope.lookup(source)? {
        Value::List(values) => values.get(index).cloned().map(|value| (None, value)),
        Value::Collection(collection) => collection
            .items
            .get(index)
            .map(|item| (Some(item.key.clone()), item.value.clone())),
        _ => None,
    }
}

fn component_preflight_budget(
    result: Result<(), crate::lang::budget::BudgetError>,
    span: Span,
) -> ParseResult<()> {
    result.map_err(|error| error.into_diagnostic().with_span(span))
}

fn reserve_component_kdl_shape(
    nodes: &[KdlNode],
    file: FileId,
    budget: &mut Budget,
    depth: usize,
) -> ParseResult<()> {
    for node in nodes {
        let span = node_span(file, node);
        component_preflight_budget(budget.check_nesting(depth), span)?;
        component_preflight_budget(budget.count_operations(1), span)?;
        component_preflight_budget(budget.count_generated_nodes(1), span)?;
        if let Some(children) = node.children() {
            reserve_component_kdl_shape(children.nodes(), file, budget, depth + 1)?;
        }
    }
    Ok(())
}

fn component_target_construct(name: &str, span: Span) -> Diagnostic {
    Diagnostic::error(
        codes::NODE_SHAPE,
        format!("`{name}` is target-output syntax and has no component document representation"),
    )
    .with_span(span)
}

fn parse_entry(
    file: FileId,
    node: &KdlNode,
    name: Option<NodeName>,
    skipped_entry: Option<usize>,
) -> ParseResult<ShapeNode> {
    let span = node_span(file, node);
    let mut args = Vec::new();
    let mut props = Vec::new();
    let mut quote = None;
    for (index, entry) in node.iter().enumerate() {
        if skipped_entry == Some(index) {
            continue;
        }
        match entry.name() {
            None => args.push(entry),
            Some(key) if key.value() == "@quote" => {
                if quote.is_some() {
                    return Err(
                        at_entry(file, entry).error(codes::DUPLICATE, "`@quote=` is set twice")
                    );
                }
                quote = Some(match entry.value().as_string() {
                    Some("double") => QuoteMode::Double,
                    Some("none") => QuoteMode::None,
                    _ => {
                        return Err(at_entry(file, entry).error(
                            codes::NODE_SHAPE,
                            "`@quote=` must be \"double\" or \"none\"",
                        ));
                    }
                });
            }
            Some(key) if key.value().starts_with('@') => {
                return Err(at_entry(file, entry).error(
                    codes::NODE_SHAPE,
                    format!(
                        "unknown Malm property `{}=` (data properties must not start with `@`)",
                        key.value()
                    ),
                ));
            }
            Some(key) => {
                let key_name = key.value().to_owned();
                if props.iter().any(|(existing, _, _)| *existing == key_name) {
                    return Err(at_entry(file, entry).error(
                        codes::DUPLICATE,
                        format!("property `{key_name}=` is set twice"),
                    ));
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
        return Err(at_node(file, node).error(
            codes::NODE_SHAPE,
            format!("{what} requires exactly one plain string"),
        ));
    }
    args[0]
        .value()
        .as_string()
        .map(str::to_owned)
        .ok_or_else(|| {
            at_entry(file, args[0]).error(codes::NODE_SHAPE, format!("{what} must be a string"))
        })
}

fn plain_string_ref(file: FileId, node: &KdlNode, what: &str) -> ParseResult<Ref> {
    let args: Vec<&KdlEntry> = node.iter().filter(|entry| entry.name().is_none()).collect();
    if args.len() != 1 || args[0].ty().is_some() {
        return Err(
            at_node(file, node).error(codes::BAD_REF, format!("{what} must be one plain string"))
        );
    }
    let name = args[0]
        .value()
        .as_string()
        .filter(|name| !name.is_empty())
        .ok_or_else(|| {
            at_entry(file, args[0])
                .error(codes::BAD_REF, format!("{what} must be a non-empty string"))
        })?;
    Ok(Ref {
        name: name.to_owned(),
        span: entry_span(file, args[0]),
    })
}

fn parse_render_condition(file: FileId, node: &KdlNode) -> ParseResult<Predicate> {
    let is_if = node.name().value() == "@if";
    if is_if {
        reject_unknown_props(file, node, &["is", "is-not"])?;
    } else {
        reject_unknown_props(file, node, &[])?;
    }
    let reference = plain_string_ref(file, node, "condition reference")?;
    if is_if {
        let is_entry = prop_entry(node, "is");
        let is_not_entry = prop_entry(node, "is-not");
        if is_entry.is_some() && is_not_entry.is_some() {
            return Err(at_node(file, node).error(
                codes::NODE_SHAPE,
                "`@if` takes either `is=` or `is-not=`, not both",
            ));
        }
        if let Some(entry) = is_entry.or(is_not_entry) {
            let expected = crate::lang::kdl_util::scalar_value(file, entry)?;
            if matches!(expected, Value::Null | Value::Float(_)) {
                return Err(at_entry(file, entry).error(
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
    Ok(match node.name().value() {
        "@if" => Predicate::Test(reference),
        "@if-present" => Predicate::Set(reference),
        _ => Predicate::NonEmpty(reference),
    })
}

fn parse_render_each(file: FileId, node: &KdlNode) -> ParseResult<(String, Ref)> {
    reject_unknown_props(file, node, &["in"])?;
    let binding = req_str_arg(file, node)?;
    if binding.is_empty() {
        return Err(
            at_node(file, node).error(codes::BINDING, "`@for-each` binding must not be empty")
        );
    }
    let entry = prop_entry(node, "in").ok_or_else(|| {
        at_node(file, node).error(codes::NODE_SHAPE, "`@for-each` requires `in=\"source\"`")
    })?;
    if entry.ty().is_some() {
        return Err(at_entry(file, entry).error(
            codes::BAD_REF,
            "`@for-each in=` is a plain string, not a typed value",
        ));
    }
    let name = entry
        .value()
        .as_string()
        .filter(|name| !name.is_empty())
        .ok_or_else(|| {
            at_entry(file, entry)
                .error(codes::BAD_REF, "`@for-each in=` must be a non-empty string")
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

/// `@include-file` contents and `@include-fragment` fragments loaded before rendering.
#[derive(Debug, Default)]
pub struct RenderResources {
    pub files: HashMap<String, String>,
    pub fragments: HashMap<String, String>,
    /// Sorted, unique requirement subjects emitted by `@requirements`.
    pub requirements: Vec<String>,
    /// Selectable, non-abstract profile names emitted by `@profiles`.
    pub profiles: Vec<String>,
}

/// An include path or fragment name paired with its request span.
pub(crate) type ResourceRequests = Vec<(String, Span)>;

/// Collects every `@include-file` and `@include-fragment` request, descending
/// through controls without evaluating them.
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
) -> Option<String> {
    let errors_before = diagnostics.error_count();
    let mut renderer = Renderer::new(scope, budget, diagnostics, &RENDER_SPLICE_LABELS, resources);
    let mut output_budget = renderer.budget.begin_output();
    let content = match &body.format {
        FormatSpec::Json { comments, indent } => json_root(
            &mut renderer,
            &mut output_budget,
            &body.items,
            *comments,
            indent,
            body.span,
        ),
        FormatSpec::Toml => toml_items(&mut renderer, &mut output_budget, &body.items, &[]),
        FormatSpec::Ini(opts) => {
            ini_items(&mut renderer, &mut output_budget, &body.items, opts, "").map(
                |mut content| {
                    let trimmed = content.len() - content.trim_start_matches('\n').len();
                    output_budget.remove_prefix(&mut content, trimmed);
                    content
                },
            )
        }
        FormatSpec::Text(opts) => text_root(
            &mut renderer,
            &mut output_budget,
            &body.items,
            opts,
            body.span,
        ),
        FormatSpec::Lua { indent } => {
            lua_root(&mut renderer, &mut output_budget, &body.items, indent)
        }
        FormatSpec::Component { .. } => {
            renderer.error(
                codes::EMIT,
                "component-backed output reached the built-in renderer",
                body.span,
            );
            None
        }
    };
    if output_budget.exceeded() {
        renderer.finish_output(&output_budget, 0, body.span);
        return None;
    }
    let content = content?;
    if renderer.budget.exhausted() || renderer.diagnostics.error_count() != errors_before {
        return None;
    }
    if !renderer.finish_output(&output_budget, content.len(), body.span) {
        return None;
    }
    Some(content)
}

/// Resolves one component-backed body into the source-free canonical document
/// consumed by `format-component/v1`.
pub(crate) fn component_document(
    body: &RenderBody,
    scope: &mut Scope,
    budget: &mut Budget,
    diagnostics: &mut Diagnostics,
) -> Option<malm_config::CanonicalTypedDocumentV1> {
    let errors_before = diagnostics.error_count();
    if let Err(diagnostic) =
        validate_component_insertions(&body.items, true, scope, &mut Vec::new(), budget, 0)
    {
        diagnostics.push(diagnostic);
        return None;
    }
    let resources = RenderResources::default();
    let mut renderer = Renderer::new(
        scope,
        budget,
        diagnostics,
        &RENDER_SPLICE_LABELS,
        &resources,
    );
    let mut component_budget = ComponentBudget::new(&mut renderer, body.span)?;
    let root = component_container(
        &mut renderer,
        &mut component_budget,
        &body.items,
        0,
        true,
        body.span,
    )?;
    let document = malm_config::CanonicalTypedDocumentV1::new(root).map_err(|error| {
        renderer.error(
            codes::EMIT,
            format!("invalid canonical component document: {error}"),
            body.span,
        );
    });
    if renderer.budget.exhausted() || renderer.diagnostics.error_count() != errors_before {
        return None;
    }
    document.ok()
}

enum ComponentPiece {
    Member {
        name: String,
        value: malm_config::TypedValueV1,
        span: Span,
    },
    Element(malm_config::TypedValueV1),
}

struct ComponentBudget {
    artifact_len: u64,
}

impl ComponentBudget {
    const DOCUMENT_FRAMING_BYTES: u64 = b"malm-canonical-typed-document\0".len() as u64 + 4 + 8 * 3;
    const CONTAINER_BYTES: u64 = 1 + 8;

    fn new(renderer: &mut Renderer<'_>, span: Span) -> Option<Self> {
        let mut budget = Self { artifact_len: 0 };
        budget
            .reserve_bytes(renderer, Self::DOCUMENT_FRAMING_BYTES, span)
            .then_some(budget)
    }

    fn reserve_value(&mut self, renderer: &mut Renderer<'_>, bytes: u64, span: Span) -> bool {
        let nodes = renderer.budget.count_generated_nodes(1);
        if !component_budget_result(renderer, nodes, span) {
            return false;
        }
        self.reserve_bytes(renderer, bytes, span)
    }

    fn reserve_container(&mut self, renderer: &mut Renderer<'_>, len: usize, span: Span) -> bool {
        let size = renderer.budget.check_collection_size(len);
        component_budget_result(renderer, size, span)
            && self.reserve_value(renderer, Self::CONTAINER_BYTES, span)
    }

    fn reserve_key(&mut self, renderer: &mut Renderer<'_>, key: &str, span: Span) -> bool {
        let bytes = u64::try_from(key.len())
            .ok()
            .and_then(|len| len.checked_add(8))
            .unwrap_or(u64::MAX);
        self.reserve_bytes(renderer, bytes, span)
    }

    fn reserve_bytes(&mut self, renderer: &mut Renderer<'_>, bytes: u64, span: Span) -> bool {
        let Some(projected) = self.artifact_len.checked_add(bytes) else {
            let reservation = renderer.budget.count_artifact_bytes(u64::MAX, bytes);
            let _ = component_budget_result(renderer, reservation, span);
            return false;
        };
        let reservation = renderer.budget.count_artifact_bytes(projected, bytes);
        if !component_budget_result(renderer, reservation, span) {
            return false;
        }
        self.artifact_len = projected;
        true
    }
}

fn component_budget_result(
    renderer: &mut Renderer<'_>,
    result: Result<(), crate::lang::budget::BudgetError>,
    span: Span,
) -> bool {
    match result {
        Ok(()) => true,
        Err(error) => {
            renderer
                .diagnostics
                .push(error.into_diagnostic().with_span(span));
            false
        }
    }
}

fn component_container(
    renderer: &mut Renderer<'_>,
    component_budget: &mut ComponentBudget,
    items: &[ConfigItem<ShapeNode>],
    depth: usize,
    root: bool,
    span: Span,
) -> Option<malm_config::TypedValueV1> {
    let pieces = component_pieces(renderer, component_budget, items, depth, root);
    let list = pieces
        .iter()
        .any(|piece| matches!(piece, ComponentPiece::Element(_)));
    let record = pieces
        .iter()
        .any(|piece| matches!(piece, ComponentPiece::Member { .. }));
    if root && list {
        renderer.error(
            codes::NODE_SHAPE,
            "a component document root must be a record; root `-` lists are not allowed",
            span,
        );
        return None;
    }
    if list && record {
        renderer.error(
            codes::NODE_SHAPE,
            "a component document block cannot mix named record fields and `-` list elements",
            span,
        );
        return None;
    }
    if list {
        if !component_budget.reserve_container(renderer, pieces.len(), span) {
            return None;
        }
        let values = pieces
            .into_iter()
            .filter_map(|piece| match piece {
                ComponentPiece::Element(value) => Some(value),
                ComponentPiece::Member { .. } => None,
            })
            .collect();
        return malm_config::TypedValueV1::list(values)
            .map_err(|error| component_model_error(renderer, error, span))
            .ok();
    }
    let members = pieces.into_iter().filter_map(|piece| match piece {
        ComponentPiece::Member { name, value, span } => Some((name, value, span)),
        ComponentPiece::Element(_) => None,
    });
    component_record(renderer, component_budget, members, span)
}

fn component_pieces(
    renderer: &mut Renderer<'_>,
    component_budget: &mut ComponentBudget,
    items: &[ConfigItem<ShapeNode>],
    depth: usize,
    root: bool,
) -> Vec<ComponentPiece> {
    let mut pieces = Vec::new();
    let parser = |file, nodes: &[KdlNode]| {
        let items = parse_items(file, nodes)?;
        validate_component_items(&items, root)?;
        Ok(items)
    };
    renderer.walk(
        items,
        depth,
        &parser,
        &mut |renderer, node, _span| match node {
            ShapeNode::Spread(spread) => {
                let Some(fields) = spread_fields(renderer, spread) else {
                    return;
                };
                for (name, value) in fields {
                    if let Some(value) =
                        component_value(renderer, component_budget, &value, spread.span)
                    {
                        push_component_piece(
                            renderer,
                            &mut pieces,
                            ComponentPiece::Member {
                                name,
                                value,
                                span: spread.span,
                            },
                            spread.span,
                        );
                    }
                }
            }
            ShapeNode::Entry(entry) => {
                let Some(resolved) = renderer.resolve_entry(entry) else {
                    return;
                };
                let ResolvedEntry::Ready { name, args, props } = resolved else {
                    return;
                };
                let Some(value) =
                    component_entry_value(renderer, component_budget, entry, &args, &props, depth)
                else {
                    return;
                };
                match name {
                    Some(name) => push_component_piece(
                        renderer,
                        &mut pieces,
                        ComponentPiece::Member {
                            name,
                            value,
                            span: entry.span,
                        },
                        entry.span,
                    ),
                    None => push_component_piece(
                        renderer,
                        &mut pieces,
                        ComponentPiece::Element(value),
                        entry.span,
                    ),
                }
            }
            other => renderer.error(
                codes::NODE_SHAPE,
                "target-output syntax has no component document representation",
                other.span(),
            ),
        },
    );
    pieces
}

fn push_component_piece(
    renderer: &mut Renderer<'_>,
    pieces: &mut Vec<ComponentPiece>,
    piece: ComponentPiece,
    span: Span,
) {
    let projected = pieces.len().saturating_add(1);
    let size = renderer.budget.check_collection_size(projected);
    if component_budget_result(renderer, size, span) {
        pieces.push(piece);
    }
}

fn component_entry_value(
    renderer: &mut Renderer<'_>,
    component_budget: &mut ComponentBudget,
    entry: &Entry,
    args: &[(Resolved, Span)],
    props: &[(String, Resolved, Span)],
    depth: usize,
) -> Option<malm_config::TypedValueV1> {
    let Some(children) = &entry.children else {
        if args.is_empty() && props.is_empty() {
            renderer.error(
                codes::NODE_SHAPE,
                "a component document entry requires a value, properties, or children",
                entry.span,
            );
            return None;
        }
        if !args.is_empty() && !props.is_empty() {
            renderer.error(
                codes::NODE_SHAPE,
                "a component document entry cannot mix arguments and properties",
                entry.span,
            );
            return None;
        }
        if !props.is_empty() {
            let size = renderer.budget.check_collection_size(props.len());
            if !component_budget_result(renderer, size, entry.span) {
                return None;
            }
            let mut members = Vec::with_capacity(props.len());
            for (name, value, span) in props {
                if let Some(value) =
                    component_resolved_value(renderer, component_budget, value, *span)
                {
                    members.push((name.clone(), value, *span));
                }
            }
            return component_record(renderer, component_budget, members, entry.span);
        }
        if args.len() == 1 {
            return component_resolved_value(renderer, component_budget, &args[0].0, args[0].1);
        }
        if !component_budget.reserve_container(renderer, args.len(), entry.span) {
            return None;
        }
        let values = args
            .iter()
            .map(|(value, span)| component_resolved_value(renderer, component_budget, value, *span))
            .collect::<Option<Vec<_>>>()?;
        return malm_config::TypedValueV1::list(values)
            .map_err(|error| component_model_error(renderer, error, entry.span))
            .ok();
    };

    if args.len() > 1 {
        renderer.error(
            codes::NODE_SHAPE,
            "a component document record takes at most one name argument before its children",
            entry.span,
        );
        return None;
    }
    let mut pieces = Vec::new();
    for (name, value, span) in props {
        let Some(value) = component_resolved_value(renderer, component_budget, value, *span) else {
            continue;
        };
        push_component_piece(
            renderer,
            &mut pieces,
            ComponentPiece::Member {
                name: name.clone(),
                value,
                span: *span,
            },
            *span,
        );
    }
    for piece in component_pieces(renderer, component_budget, children, depth + 1, false) {
        push_component_piece(renderer, &mut pieces, piece, entry.span);
    }
    let list = pieces
        .iter()
        .any(|piece| matches!(piece, ComponentPiece::Element(_)));
    let record = pieces
        .iter()
        .any(|piece| matches!(piece, ComponentPiece::Member { .. }));
    if list && record {
        renderer.error(
            codes::NODE_SHAPE,
            "a component document block cannot mix named record fields and `-` list elements",
            entry.span,
        );
        return None;
    }
    let body = if list {
        if !component_budget.reserve_container(renderer, pieces.len(), entry.span) {
            return None;
        }
        let values = pieces
            .into_iter()
            .filter_map(|piece| match piece {
                ComponentPiece::Element(value) => Some(value),
                ComponentPiece::Member { .. } => None,
            })
            .collect();
        malm_config::TypedValueV1::list(values)
            .map_err(|error| component_model_error(renderer, error, entry.span))
            .ok()?
    } else {
        let members = pieces.into_iter().filter_map(|piece| match piece {
            ComponentPiece::Member { name, value, span } => Some((name, value, span)),
            ComponentPiece::Element(_) => None,
        });
        component_record(renderer, component_budget, members, entry.span)?
    };
    if args.is_empty() {
        return Some(body);
    }
    let name = renderer.scalar_text(&args[0].0, args[0].1)?;
    component_record(
        renderer,
        component_budget,
        std::iter::once((name, body, args[0].1)),
        entry.span,
    )
}

fn component_record(
    renderer: &mut Renderer<'_>,
    component_budget: &mut ComponentBudget,
    members: impl IntoIterator<Item = (String, malm_config::TypedValueV1, Span)>,
    span: Span,
) -> Option<malm_config::TypedValueV1> {
    if !component_budget.reserve_value(renderer, ComponentBudget::CONTAINER_BYTES, span) {
        return None;
    }
    let mut record = BTreeMap::new();
    for (name, value, member_span) in members {
        if record
            .keys()
            .any(|key: &malm_config::RichKeyV1| key.as_str() == name)
        {
            renderer.duplicate(&name, member_span);
            continue;
        }
        let projected = record.len().saturating_add(1);
        let size = renderer.budget.check_collection_size(projected);
        if !component_budget_result(renderer, size, member_span)
            || !component_budget.reserve_key(renderer, &name, member_span)
        {
            continue;
        }
        let key = match malm_config::RichKeyV1::new(name.clone()) {
            Ok(key) => key,
            Err(error) => {
                component_model_error(renderer, error, member_span);
                continue;
            }
        };
        record.insert(key, value);
    }
    malm_config::TypedValueV1::record(record)
        .map_err(|error| component_model_error(renderer, error, span))
        .ok()
}

fn component_resolved_value(
    renderer: &mut Renderer<'_>,
    component_budget: &mut ComponentBudget,
    resolved: &Resolved,
    span: Span,
) -> Option<malm_config::TypedValueV1> {
    match resolved {
        Resolved::Value(value) => component_value(renderer, component_budget, value, span),
        Resolved::Raw(_) => {
            renderer.error(
                codes::NODE_SHAPE,
                "`(raw)` is target-output syntax and has no component document representation",
                span,
            );
            None
        }
        Resolved::Skip => None,
    }
}

fn component_value(
    renderer: &mut Renderer<'_>,
    component_budget: &mut ComponentBudget,
    value: &Value,
    span: Span,
) -> Option<malm_config::TypedValueV1> {
    let value = match value {
        Value::Null => component_budget
            .reserve_value(renderer, 1, span)
            .then(malm_config::TypedValueV1::null)?,
        Value::Bool(value) => component_budget
            .reserve_value(renderer, 2, span)
            .then(|| malm_config::TypedValueV1::boolean(*value))?,
        Value::Int(value) => component_budget
            .reserve_value(renderer, 9, span)
            .then(|| malm_config::TypedValueV1::integer(*value))?,
        Value::Float(value) => {
            if !component_budget.reserve_value(renderer, 9, span) {
                return None;
            }
            malm_config::TypedValueV1::float(*value)
                .map_err(|error| component_model_error(renderer, error, span))
                .ok()?
        }
        Value::String(value) | Value::Path(value) => {
            let bytes = u64::try_from(value.len())
                .ok()
                .and_then(|len| len.checked_add(9))
                .unwrap_or(u64::MAX);
            if !component_budget.reserve_value(renderer, bytes, span) {
                return None;
            }
            malm_config::TypedValueV1::string(value.clone())
                .map_err(|error| component_model_error(renderer, error, span))
                .ok()?
        }
        Value::List(values) => {
            if !component_budget.reserve_container(renderer, values.len(), span) {
                return None;
            }
            let values = values
                .iter()
                .map(|value| component_value(renderer, component_budget, value, span))
                .collect::<Option<Vec<_>>>()?;
            malm_config::TypedValueV1::list(values)
                .map_err(|error| component_model_error(renderer, error, span))
                .ok()?
        }
        Value::Record(values) => {
            let size = renderer.budget.check_collection_size(values.keys().count());
            if !component_budget_result(renderer, size, span) {
                return None;
            }
            let mut members = Vec::with_capacity(values.keys().count());
            for (name, value) in values.iter() {
                if let Some(value) = component_value(renderer, component_budget, value, span) {
                    members.push((name.clone(), value, span));
                }
            }
            component_record(renderer, component_budget, members, span)?
        }
        Value::Collection(values) => {
            if !component_budget.reserve_container(renderer, values.len(), span) {
                return None;
            }
            let mut collection = BTreeMap::new();
            for item in &values.items {
                if !component_budget.reserve_key(renderer, &item.key, item.span) {
                    return None;
                }
                let key = malm_config::RichKeyV1::new(item.key.clone())
                    .map_err(|error| component_model_error(renderer, error, item.span))
                    .ok()?;
                let value = component_value(renderer, component_budget, &item.value, item.span)?;
                collection.insert(key, value);
            }
            malm_config::TypedValueV1::collection(collection)
                .map_err(|error| component_model_error(renderer, error, span))
                .ok()?
        }
        Value::KdlDocument(_) => {
            renderer.error(
                codes::TYPE_MISMATCH,
                "a KDL document must be inserted with `@insert-documents`",
                span,
            );
            return None;
        }
        Value::RawRecordLiteral(_) => {
            renderer.error(
                codes::TYPE_MISMATCH,
                "an uncoerced record literal reached component rendering",
                span,
            );
            return None;
        }
        Value::UnresolvedListDefault(_) => {
            renderer.error(
                codes::TYPE_MISMATCH,
                "an unresolved named list default reached component rendering",
                span,
            );
            return None;
        }
    };
    Some(value)
}

fn component_model_error(renderer: &mut Renderer<'_>, error: impl std::fmt::Display, span: Span) {
    renderer.error(
        codes::TYPE_MISMATCH,
        format!("invalid component document value: {error}"),
        span,
    );
}

/// A structural renderer carrying the include payloads loaded for one body.
type Renderer<'a> = config_file::Renderer<'a, &'a RenderResources>;

const RENDER_SPLICE_LABELS: config_file::SpliceLabels = config_file::SpliceLabels {
    directive: "@insert-documents",
    kind: "render",
};

#[derive(Clone)]
enum Resolved {
    Value(Value),
    /// A `(raw)` token, emitted verbatim in the target syntax.
    Raw(String),
    /// An unset `(ref?)`; the enclosing entry is omitted without error.
    Skip,
}

impl Renderer<'_> {
    /// The `@include-file`/`@include-fragment` payloads loaded for this body.
    fn resources(&self) -> &RenderResources {
        self.extra
    }

    fn resolve(&mut self, expr: &ValueExpr) -> Option<Resolved> {
        match expr {
            ValueExpr::Literal(value, _) => Some(Resolved::Value(value.clone())),
            ValueExpr::Raw(text, _) => Some(Resolved::Raw(text.clone())),
            ValueExpr::Ref {
                reference,
                optional,
            } => match self.scope.lookup(&reference.name).cloned() {
                None if *optional => Some(Resolved::Skip),
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
                            "`{}` is #null; guard with `@if-present` or use `(ref?)`",
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
                match text::render_template_with_limit(
                    raw,
                    TemplateSyntax::V3,
                    &lookup,
                    self.budget.limits().max_artifact_bytes,
                ) {
                    Ok(rendered) => Some(Resolved::Value(Value::String(rendered))),
                    Err(message) => {
                        self.error(codes::TEMPLATE, message, *span);
                        None
                    }
                }
            }
        }
    }

    /// Resolves an entry, omitting it if any value is an unset `(ref?)`.
    fn resolve_entry(&mut self, entry: &Entry) -> Option<ResolvedEntry> {
        let name = match &entry.name {
            None => None,
            Some(NodeName::Literal(name)) => Some(name.clone()),
            Some(NodeName::FString { raw, span }) => {
                let scope = &*self.scope;
                let lookup = move |name: &str| scope.lookup(name).cloned();
                match text::render_template_with_limit(
                    raw,
                    TemplateSyntax::V3,
                    &lookup,
                    self.budget.limits().max_artifact_bytes,
                ) {
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
    /// Resolves preloaded include text and interpolates it when requested.
    fn resource_text(&mut self, node: &ShapeNode) -> Option<String> {
        match node {
            ShapeNode::File {
                path,
                interpolate,
                span,
            } => {
                let Some(content) = self.resources().files.get(path).cloned() else {
                    self.error(
                        codes::EMIT,
                        format!(
                            "`@include-file \"{path}\"` is unavailable here (files cannot arrive via `@insert-documents`)"
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
                match text::render_template_with_limit(
                    &content,
                    TemplateSyntax::V3,
                    &lookup,
                    self.budget.limits().max_artifact_bytes,
                ) {
                    Ok(rendered) => Some(rendered),
                    Err(message) => {
                        self.error(codes::TEMPLATE, format!("{path}: {message}"), *span);
                        None
                    }
                }
            }
            ShapeNode::Compose { fragment, span } => {
                match self.resources().fragments.get(fragment).cloned() {
                    Some(content) => Some(content),
                    None => {
                        self.error(
                            codes::EMIT,
                            format!(
                                "`@include-fragment \"{fragment}\"` is unavailable here (fragments cannot arrive via `@insert-documents`)"
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

fn push_block(output_budget: &mut OutputBudget, output: &mut String, content: &str) -> Option<()> {
    output_budget.push_str(output, content)?;
    if !content.is_empty() && !content.ends_with('\n') {
        output_budget.push_char(output, '\n')?;
    }
    Some(())
}

enum ResolvedEntry {
    Ready {
        name: Option<String>,
        args: Vec<(Resolved, Span)>,
        props: Vec<(String, Resolved, Span)>,
    },
    Skipped,
}

/// Resolves `@insert-fields` in field-name order and omits unset optional fields.
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
                    "`@insert-fields` requires a record, found {} `{}`",
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

/// Classifies immediate members without evaluating controls. An
/// `@insert-documents` payload counts as named content because its shape is not
/// known here.
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

/// Converts one `-` element to items, placing properties before child entries.
fn element_items(entry: &Entry) -> Vec<ConfigItem<ShapeNode>> {
    let mut items: Vec<ConfigItem<ShapeNode>> = Vec::new();
    for (key, value, span) in &entry.props {
        items.push(ConfigItem::Value {
            value: ShapeNode::Entry(Entry {
                name: Some(NodeName::Literal(key.clone())),
                args: vec![value.clone()],
                props: Vec::new(),
                children: None,
                quote: entry.quote,
                span: *span,
            }),
            span: *span,
        });
    }
    items.extend(entry.children.as_deref().unwrap_or(&[]).to_vec());
    items
}

/// Applies validation shared by every structured emitter. `@requirements`,
/// `@profiles`, and `@line` write bare lines, while valueless keys have no
/// representation.
fn reject_text_only(renderer: &mut Renderer<'_>, span: Span) {
    renderer.error(
        codes::NODE_SHAPE,
        "`@requirements`/`@profiles` are valid only in text bodies",
        span,
    );
}

fn reject_line(renderer: &mut Renderer<'_>, span: Span, format: &str) {
    renderer.error(
        codes::NODE_SHAPE,
        format!("`@line` is not valid in {format} bodies"),
        span,
    );
}

fn reject_bare_key(renderer: &mut Renderer<'_>, span: Span, format: &str) {
    renderer.error(
        codes::NODE_SHAPE,
        format!("a bare key is not valid in {format} bodies; write `key #true` or guard it"),
        span,
    );
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum DataDialect {
    Json,
    Lua,
}

/// Layout settings shared by every JSON/Lua emitter frame. Only the nesting
/// `depth` varies within one body, so it stays a separate parameter.
#[derive(Clone, Copy)]
struct DataOpts<'a> {
    comments: bool,
    indent: &'a str,
    dialect: DataDialect,
}

impl DataOpts<'_> {
    fn label(self) -> &'static str {
        match self.dialect {
            DataDialect::Json => "json",
            DataDialect::Lua => "lua",
        }
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
    output_budget: &mut OutputBudget,
    items: &[ConfigItem<ShapeNode>],
    comments: bool,
    indent: &str,
    span: Span,
) -> Option<String> {
    let opts = DataOpts {
        comments,
        indent,
        dialect: DataDialect::Json,
    };
    let pieces = data_pieces(renderer, output_budget, items, opts, 1);
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
    let root = data_container(renderer, output_budget, pieces, opts, 0, false)?;
    let mut output = String::new();
    OutputBudget::append_accounted(&mut output, &root);
    output_budget.push_char(&mut output, '\n')?;
    Some(output)
}

fn lua_root(
    renderer: &mut Renderer<'_>,
    output_budget: &mut OutputBudget,
    items: &[ConfigItem<ShapeNode>],
    indent: &str,
) -> Option<String> {
    if lua_program_mode(items) {
        return lua_program(renderer, output_budget, items);
    }
    let opts = DataOpts {
        comments: true,
        indent,
        dialect: DataDialect::Lua,
    };
    let pieces = data_pieces(renderer, output_budget, items, opts, 1);
    let array = pieces
        .iter()
        .any(|piece| matches!(piece, DataPiece::Element(_)));
    let root = data_container(renderer, output_budget, pieces, opts, 0, array)?;
    let mut output = String::new();
    output_budget.push_str(&mut output, "return ")?;
    OutputBudget::append_accounted(&mut output, &root);
    output_budget.push_char(&mut output, '\n')?;
    Some(output)
}

/// A Lua body containing only raw directives renders without `return { ... }`.
fn lua_program_mode(items: &[ConfigItem<ShapeNode>]) -> bool {
    fn visit(items: &[ConfigItem<ShapeNode>], has_data: &mut bool, has_raw: &mut bool) {
        for item in items {
            match item {
                ConfigItem::Value { value, .. } => match value {
                    ShapeNode::Entry(_) | ShapeNode::Spread(_) => *has_data = true,
                    ShapeNode::Raw { .. }
                    | ShapeNode::Line { .. }
                    | ShapeNode::Requirements { .. }
                    | ShapeNode::Profiles { .. }
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

fn lua_program(
    renderer: &mut Renderer<'_>,
    output_budget: &mut OutputBudget,
    items: &[ConfigItem<ShapeNode>],
) -> Option<String> {
    let mut output = String::new();
    renderer.walk_all(items, 0, &parse_items, &mut |renderer, node, _span| {
        match node {
            ShapeNode::Comment { text, .. } => {
                output_budget.write_fmt(&mut output, format_args!("-- {text}\n"))?;
            }
            ShapeNode::Requirements { span } | ShapeNode::Profiles { span } => {
                reject_text_only(renderer, *span);
                return None;
            }
            ShapeNode::Raw { text, .. } => push_block(output_budget, &mut output, text)?,
            ShapeNode::Line { value, span } => match renderer.resolve(value)? {
                Resolved::Skip => {}
                resolved => {
                    let text = renderer.scalar_text(&resolved, *span)?;
                    output_budget.write_fmt(&mut output, format_args!("{text}\n"))?;
                }
            },
            node @ (ShapeNode::File { .. } | ShapeNode::Compose { .. }) => {
                push_block(output_budget, &mut output, &renderer.resource_text(node)?)?;
            }
            ShapeNode::Entry(entry) => {
                renderer.error(
                    codes::NODE_SHAPE,
                    "a lua program body (only @raw-text/@line/@include-file/@include-fragment) cannot mix data entries",
                    entry.span,
                );
                return None;
            }
            ShapeNode::Spread(spread) => {
                renderer.error(
                    codes::NODE_SHAPE,
                    "a lua program body (only @raw-text/@line/@include-file/@include-fragment) cannot mix data entries",
                    spread.span,
                );
                return None;
            }
        }
        Some(())
    })?;
    Some(output)
}

fn data_pieces(
    renderer: &mut Renderer<'_>,
    output_budget: &mut OutputBudget,
    items: &[ConfigItem<ShapeNode>],
    opts: DataOpts<'_>,
    depth: usize,
) -> Vec<DataPiece> {
    let mut pieces = Vec::new();
    renderer.walk(
        items,
        0,
        &parse_items,
        &mut |renderer, node, _span| match node {
            ShapeNode::Requirements { span } | ShapeNode::Profiles { span } => {
                reject_text_only(renderer, *span);
            }
            ShapeNode::Comment { text, span } => {
                if opts.comments {
                    let mut output = String::new();
                    match opts.dialect {
                        DataDialect::Json => {
                            let _ = output_budget.write_fmt(&mut output, format_args!("// {text}"));
                        }
                        DataDialect::Lua => {
                            let _ = output_budget.write_fmt(&mut output, format_args!("-- {text}"));
                        }
                    }
                    pieces.push(DataPiece::Comment(output));
                } else {
                    renderer.error(
                        codes::NODE_SHAPE,
                        "opts.comments require `format=\"jsonc\"`",
                        *span,
                    );
                }
            }
            ShapeNode::Raw { text, .. } => {
                let mut output = String::new();
                if output_budget.push_str(&mut output, text).is_some() {
                    pieces.push(DataPiece::RawMember(output));
                }
            }
            ShapeNode::Line { span, .. } => reject_line(renderer, *span, opts.label()),
            ShapeNode::Spread(spread) => {
                let Some(fields) = spread_fields(renderer, spread) else {
                    return;
                };
                for (name, value) in fields {
                    if let Some(text) = data_value(
                        renderer,
                        output_budget,
                        &Resolved::Value(value),
                        spread.span,
                        opts.dialect,
                    ) {
                        pieces.push(DataPiece::Member {
                            name,
                            text,
                            span: spread.span,
                        });
                    }
                }
            }
            node @ (ShapeNode::File { .. } | ShapeNode::Compose { .. }) => match opts.dialect {
                DataDialect::Json => {
                    renderer.error(
                        codes::NODE_SHAPE,
                        "`@include-file`/`@include-fragment` are not valid in json bodies",
                        node.span(),
                    );
                }
                DataDialect::Lua => {
                    if let Some(text) = renderer.resource_text(node) {
                        for line in text.lines() {
                            let mut output = String::new();
                            if output_budget.push_str(&mut output, line).is_none() {
                                break;
                            }
                            pieces.push(DataPiece::RawMember(output));
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
                let Some(text) =
                    data_entry_value(renderer, output_budget, entry, &args, &props, opts, depth)
                else {
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
        },
    );
    pieces
}

fn data_entry_value(
    renderer: &mut Renderer<'_>,
    output_budget: &mut OutputBudget,
    entry: &Entry,
    args: &[(Resolved, Span)],
    props: &[(String, Resolved, Span)],
    opts: DataOpts<'_>,
    depth: usize,
) -> Option<String> {
    match &entry.children {
        None => {
            if args.is_empty() && props.is_empty() {
                reject_bare_key(renderer, entry.span, opts.label());
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
                let mut output = String::new();
                output_budget.push_str(&mut output, "{ ")?;
                for (index, (key, value, span)) in props.iter().enumerate() {
                    renderer.insert_unique(&mut seen, key.clone(), key, *span)?;
                    if index != 0 {
                        output_budget.push_str(&mut output, ", ")?;
                    }
                    let value = data_value(renderer, output_budget, value, *span, opts.dialect)?;
                    write_data_member(output_budget, &mut output, key, &value, opts.dialect)?;
                }
                output_budget.push_str(&mut output, " }")?;
                return Some(output);
            }
            if args.len() == 1 {
                return data_value(renderer, output_budget, &args[0].0, args[0].1, opts.dialect);
            }
            let mut output = String::new();
            output_budget.push_str(
                &mut output,
                match opts.dialect {
                    DataDialect::Json => "[",
                    DataDialect::Lua => "{ ",
                },
            )?;
            for (index, (value, span)) in args.iter().enumerate() {
                if index != 0 {
                    output_budget.push_str(&mut output, ", ")?;
                }
                let value = data_value(renderer, output_budget, value, *span, opts.dialect)?;
                OutputBudget::append_accounted(&mut output, &value);
            }
            output_budget.push_str(
                &mut output,
                match opts.dialect {
                    DataDialect::Json => "]",
                    DataDialect::Lua => " }",
                },
            )?;
            Some(output)
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
                renderer.insert_unique(&mut prop_seen, key.clone(), key, *span)?;
                let text = data_value(renderer, output_budget, value, *span, opts.dialect)?;
                pieces.push(DataPiece::Member {
                    name: key.clone(),
                    text,
                    span: *span,
                });
            }
            pieces.extend(data_pieces(
                renderer,
                output_budget,
                children,
                opts,
                inner_depth + 1,
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
            let body =
                data_container(renderer, output_budget, pieces, opts, inner_depth, is_array)?;
            if !named_section {
                return Some(body);
            }
            let (name, span) = &args[0];
            let name = renderer.scalar_text(name, *span)?;
            let mut output = String::new();
            output_budget.push_str(&mut output, "{\n")?;
            write_repeated(output_budget, &mut output, opts.indent, inner_depth)?;
            write_data_member(output_budget, &mut output, &name, &body, opts.dialect)?;
            if opts.dialect == DataDialect::Lua {
                output_budget.push_char(&mut output, ',')?;
            }
            output_budget.push_char(&mut output, '\n')?;
            write_repeated(output_budget, &mut output, opts.indent, depth)?;
            output_budget.push_char(&mut output, '}')?;
            Some(output)
        }
    }
}

fn write_data_member(
    output_budget: &mut OutputBudget,
    output: &mut String,
    name: &str,
    value: &str,
    dialect: DataDialect,
) -> Option<()> {
    match dialect {
        DataDialect::Json => {
            output_budget.push_char(output, '"')?;
            write_json_escape(&mut output_budget.writer(output), name).ok()?;
            output_budget.push_str(output, "\": ")?;
        }
        DataDialect::Lua => {
            if lua_identifier(name) {
                output_budget.write_fmt(output, format_args!("{name} = "))?;
            } else {
                output_budget.push_str(output, "[\"")?;
                write_lua_escape(&mut output_budget.writer(output), name).ok()?;
                output_budget.push_str(output, "\"] = ")?;
            }
        }
    }
    OutputBudget::append_accounted(output, value);
    Some(())
}

fn data_container(
    renderer: &mut Renderer<'_>,
    output_budget: &mut OutputBudget,
    pieces: Vec<DataPiece>,
    opts: DataOpts<'_>,
    depth: usize,
    array: bool,
) -> Option<String> {
    let (open, close) = match (opts.dialect, array) {
        (DataDialect::Json, true) => ("[", "]"),
        (DataDialect::Json, false) | (DataDialect::Lua, _) => ("{", "}"),
    };
    if pieces.is_empty() {
        let mut output = String::new();
        output_budget.write_fmt(&mut output, format_args!("{open}{close}"))?;
        return Some(output);
    }
    let mut seen = HashSet::new();
    let mut output = String::new();
    output_budget.write_fmt(&mut output, format_args!("{open}\n"))?;
    let mut remaining = pieces
        .iter()
        .filter(|piece| !matches!(piece, DataPiece::Comment(_)))
        .count();
    for (index, piece) in pieces.iter().enumerate() {
        write_repeated(output_budget, &mut output, opts.indent, depth + 1)?;
        let comment = matches!(piece, DataPiece::Comment(_));
        match piece {
            DataPiece::Member {
                name,
                text,
                span: member_span,
            } => {
                renderer.insert_unique(&mut seen, name.clone(), name, *member_span)?;
                write_data_member(output_budget, &mut output, name, text, opts.dialect)?;
            }
            DataPiece::Element(text) | DataPiece::RawMember(text) | DataPiece::Comment(text) => {
                OutputBudget::append_accounted(&mut output, text);
            }
        }
        if !comment {
            remaining -= 1;
            let trailing = match opts.dialect {
                DataDialect::Lua => true,
                DataDialect::Json => remaining != 0,
            };
            if trailing {
                output_budget.push_char(&mut output, ',')?;
            }
        }
        if index + 1 != pieces.len() {
            output_budget.push_char(&mut output, '\n')?;
        }
    }
    output_budget.push_char(&mut output, '\n')?;
    write_repeated(output_budget, &mut output, opts.indent, depth)?;
    output_budget.push_str(&mut output, close)?;
    Some(output)
}

fn data_value(
    renderer: &mut Renderer<'_>,
    output_budget: &mut OutputBudget,
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
            DataDialect::Lua => {
                let mut output = String::new();
                output_budget.push_str(&mut output, text)?;
                Some(output)
            }
        },
        Resolved::Value(value) => write_data_value(renderer, output_budget, value, span, dialect),
    }
}

fn write_data_value(
    renderer: &mut Renderer<'_>,
    output_budget: &mut OutputBudget,
    value: &Value,
    span: Span,
    dialect: DataDialect,
) -> Option<String> {
    let mut output = String::new();
    match value {
        Value::Null if dialect == DataDialect::Json => {
            output_budget.push_str(&mut output, "null")?;
        }
        Value::Null => {
            renderer.error(
                codes::TYPE_MISMATCH,
                "Lua config data does not support null",
                span,
            );
            return None;
        }
        Value::Bool(value) => {
            output_budget.write_fmt(&mut output, format_args!("{value}"))?;
        }
        Value::Int(value) => {
            output_budget.write_fmt(&mut output, format_args!("{value}"))?;
        }
        Value::Float(value) if value.is_finite() => {
            output_budget.push_str(&mut output, &format_float(*value))?;
        }
        Value::Float(_) => {
            renderer.error(
                codes::TYPE_MISMATCH,
                "non-finite numbers are not supported",
                span,
            );
            return None;
        }
        Value::String(value) | Value::Path(value) => {
            output_budget.push_char(&mut output, '"')?;
            match dialect {
                DataDialect::Json => {
                    write_json_escape(&mut output_budget.writer(&mut output), value).ok()?;
                }
                DataDialect::Lua => {
                    write_lua_escape(&mut output_budget.writer(&mut output), value).ok()?;
                }
            }
            output_budget.push_char(&mut output, '"')?;
        }
        Value::List(values) => {
            let (open, close) = match dialect {
                DataDialect::Json => ("[", "]"),
                DataDialect::Lua => ("{", "}"),
            };
            output_budget.push_str(&mut output, open)?;
            for (index, value) in values.iter().enumerate() {
                if index != 0 {
                    output_budget.push_str(&mut output, ", ")?;
                }
                let value = write_data_value(renderer, output_budget, value, span, dialect)?;
                OutputBudget::append_accounted(&mut output, &value);
            }
            output_budget.push_str(&mut output, close)?;
        }
        Value::Record(values) => {
            output_budget.push_char(&mut output, '{')?;
            for (index, (name, value)) in values.iter().enumerate() {
                if index != 0 {
                    output_budget.push_str(&mut output, ", ")?;
                }
                let value = write_data_value(renderer, output_budget, value, span, dialect)?;
                write_data_member(output_budget, &mut output, name, &value, dialect)?;
            }
            output_budget.push_char(&mut output, '}')?;
        }
        other => {
            let message = match dialect {
                DataDialect::Json => "cannot be represented in JSON",
                DataDialect::Lua => "is not accepted by the Lua data serializer",
            };
            renderer.error(
                codes::TYPE_MISMATCH,
                format!("{} {message}", other.type_label()),
                span,
            );
            return None;
        }
    }
    Some(output)
}

fn write_repeated(
    output_budget: &mut OutputBudget,
    output: &mut String,
    value: &str,
    count: usize,
) -> Option<()> {
    for _ in 0..count {
        output_budget.push_str(output, value)?;
    }
    Some(())
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

fn toml_items(
    renderer: &mut Renderer<'_>,
    output_budget: &mut OutputBudget,
    items: &[ConfigItem<ShapeNode>],
    prefix: &[String],
) -> Option<String> {
    let mut inline: Vec<String> = Vec::new();
    let mut tables: Vec<String> = Vec::new();
    let mut seen = HashSet::new();
    let mut repeated: HashSet<String> = HashSet::new();
    renderer.walk_all(items, 0, &parse_items, &mut |renderer, node, _span| {
        match node {
            ShapeNode::Comment { text, .. } => {
                let mut output = String::new();
                if output_budget
                    .write_fmt(&mut output, format_args!("# {text}\n"))
                    .is_some()
                {
                    inline.push(output);
                }
            }
            ShapeNode::Requirements { span } | ShapeNode::Profiles { span } => {
                reject_text_only(renderer, *span);
                return None;
            }
            ShapeNode::Raw { text, .. } => {
                let mut output = String::new();
                if output_budget
                    .write_fmt(&mut output, format_args!("{text}\n"))
                    .is_some()
                {
                    inline.push(output);
                }
            }
            ShapeNode::Line { span, .. } => {
                reject_line(renderer, *span, "toml");
                return None;
            }
            ShapeNode::Spread(spread) => {
                let fields = spread_fields(renderer, spread)?;
                // Render every field before failing so diagnostics stay complete.
                let mut ok = true;
                for (name, value) in fields {
                    renderer.insert_unique(&mut seen, name.clone(), &name, spread.span)?;
                    match toml_value_of(
                        renderer,
                        output_budget,
                        &Resolved::Value(value),
                        spread.span,
                    ) {
                        Some(text) => {
                            let mut output = String::new();
                            output_budget
                                .write_fmt(&mut output, format_args!("{} = ", toml_key(&name)))?;
                            OutputBudget::append_accounted(&mut output, &text);
                            output_budget.push_char(&mut output, '\n')?;
                            inline.push(output);
                        }
                        None => ok = false,
                    }
                }
                if !ok {
                    return None;
                }
            }
            node @ (ShapeNode::File { .. } | ShapeNode::Compose { .. }) => {
                match renderer.resource_text(node) {
                    Some(text) => {
                        let mut block = String::new();
                        push_block(output_budget, &mut block, &text)?;
                        inline.push(block);
                    }
                    None => return None,
                }
            }
            ShapeNode::Entry(entry) => {
                if entry.name.is_none() {
                    renderer.error(
                        codes::NODE_SHAPE,
                        "`-` array elements are only valid inside an array-valued key",
                        entry.span,
                    );
                    return None;
                }
                match toml_entry(
                    renderer,
                    output_budget,
                    entry,
                    prefix,
                    &mut seen,
                    &mut repeated,
                ) {
                    Some(TomlRendered::Inline(text)) => inline.push(text),
                    Some(TomlRendered::Table(text)) => tables.push(text),
                    Some(TomlRendered::Skipped) => {}
                    None => return None,
                }
            }
        }
        Some(())
    })?;
    let mut output = String::new();
    for part in inline.iter().chain(&tables) {
        OutputBudget::append_accounted(&mut output, part);
    }
    let trimmed = output.len() - output.trim_start_matches('\n').len();
    output_budget.remove_prefix(&mut output, trimmed);
    Some(output)
}

enum TomlRendered {
    Inline(String),
    Table(String),
    Skipped,
}

fn toml_value_of(
    renderer: &mut Renderer<'_>,
    output_budget: &mut OutputBudget,
    resolved: &Resolved,
    span: Span,
) -> Option<String> {
    match resolved {
        Resolved::Skip => None,
        Resolved::Raw(text) => {
            let mut output = String::new();
            output_budget.push_str(&mut output, text)?;
            Some(output)
        }
        Resolved::Value(value) => write_toml_value(renderer, output_budget, value, span),
    }
}

fn toml_entry(
    renderer: &mut Renderer<'_>,
    output_budget: &mut OutputBudget,
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
            renderer.insert_unique(seen, name.clone(), &name, entry.span)?;
            if args.is_empty() && props.is_empty() {
                reject_bare_key(renderer, entry.span, "toml");
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
                let mut output = String::new();
                output_budget.write_fmt(&mut output, format_args!("{} = {{ ", toml_key(&name)))?;
                for (index, (key, value, span)) in props.iter().enumerate() {
                    renderer.insert_unique(&mut prop_seen, key.clone(), key, *span)?;
                    if index != 0 {
                        output_budget.push_str(&mut output, ", ")?;
                    }
                    output_budget.write_fmt(&mut output, format_args!("{} = ", toml_key(key)))?;
                    let value = toml_value_of(renderer, output_budget, value, *span)?;
                    OutputBudget::append_accounted(&mut output, &value);
                }
                output_budget.push_str(&mut output, " }\n")?;
                return Some(TomlRendered::Inline(output));
            }
            if args.len() == 1 {
                let value = toml_value_of(renderer, output_budget, &args[0].0, args[0].1)?;
                let mut output = String::new();
                output_budget.write_fmt(&mut output, format_args!("{} = ", toml_key(&name)))?;
                OutputBudget::append_accounted(&mut output, &value);
                output_budget.push_char(&mut output, '\n')?;
                return Some(TomlRendered::Inline(output));
            }
            let mut output = String::new();
            output_budget.write_fmt(&mut output, format_args!("{} = [", toml_key(&name)))?;
            for (index, (value, span)) in args.iter().enumerate() {
                if index != 0 {
                    output_budget.push_str(&mut output, ", ")?;
                }
                let value = toml_value_of(renderer, output_budget, value, *span)?;
                OutputBudget::append_accounted(&mut output, &value);
            }
            output_budget.push_str(&mut output, "]\n")?;
            Some(TomlRendered::Inline(output))
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
                renderer.insert_unique(seen, format!("table:{key}"), &key, entry.span)?;
                let header = path
                    .iter()
                    .map(|segment| toml_key(segment))
                    .collect::<Vec<_>>()
                    .join(".");
                let inner = toml_items(renderer, output_budget, children, &path)?;
                let mut output = String::new();
                output_budget.write_fmt(&mut output, format_args!("\n[{header}]\n"))?;
                OutputBudget::append_accounted(&mut output, &inner);
                return Some(TomlRendered::Table(output));
            }
            // Array mode emits scalars inline and tables as `[[...]]`.
            let conflict = seen.contains(&name) && !repeated.contains(&name);
            if conflict {
                renderer.duplicate(&name, entry.span);
                return None;
            }
            let header = path
                .iter()
                .map(|segment| toml_key(segment))
                .collect::<Vec<_>>()
                .join(".");
            let mut scalars: Vec<String> = Vec::new();
            let mut table_blocks: Vec<String> = Vec::new();
            renderer.walk_all(children, 0, &parse_items, &mut |renderer, node, _span| {
                match node {
                    ShapeNode::Entry(element) if element.name.is_none() => {
                        if element.children.is_some() || !element.props.is_empty() {
                            if !element.args.is_empty() && element.children.is_some() {
                                renderer.error(
                                    codes::NODE_SHAPE,
                                    "`-` table elements do not take values before their children",
                                    element.span,
                                );
                                return None;
                            }
                            let items = element_items(element);
                            match toml_items(renderer, output_budget, &items, &path) {
                                Some(inner) => {
                                    let mut output = String::new();
                                    output_budget
                                        .write_fmt(&mut output, format_args!("\n[[{header}]]\n"))?;
                                    OutputBudget::append_accounted(&mut output, &inner);
                                    table_blocks.push(output);
                                }
                                None => return None,
                            }
                        } else {
                            match renderer.resolve_entry(element) {
                                Some(ResolvedEntry::Ready { args, .. }) => {
                                    // Evaluate every element before failing so
                                    // diagnostics stay complete.
                                    for (value, span) in args {
                                        scalars.push(toml_value_of(
                                            renderer,
                                            output_budget,
                                            &value,
                                            span,
                                        )?);
                                    }
                                }
                                Some(ResolvedEntry::Skipped) => {}
                                None => return None,
                            }
                        }
                    }
                    other => {
                        renderer.error(
                            codes::NODE_SHAPE,
                            "only `-` elements are valid inside an array block",
                            other.span(),
                        );
                        return None;
                    }
                }
                Some(())
            })?;
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
                let mut output = String::new();
                for block in &table_blocks {
                    OutputBudget::append_accounted(&mut output, block);
                }
                return Some(TomlRendered::Table(output));
            }
            if scalars.is_empty() {
                // Omit the key when expansion produces an empty array.
                return Some(TomlRendered::Skipped);
            }
            if !seen.insert(name.clone()) {
                renderer.duplicate(&name, entry.span);
                return None;
            }
            let mut output = String::new();
            output_budget.write_fmt(&mut output, format_args!("{} = [", toml_key(&name)))?;
            for (index, scalar) in scalars.iter().enumerate() {
                if index != 0 {
                    output_budget.push_str(&mut output, ", ")?;
                }
                OutputBudget::append_accounted(&mut output, scalar);
            }
            output_budget.push_str(&mut output, "]\n")?;
            Some(TomlRendered::Inline(output))
        }
    }
}

fn write_toml_value(
    renderer: &mut Renderer<'_>,
    output_budget: &mut OutputBudget,
    value: &Value,
    span: Span,
) -> Option<String> {
    let mut output = String::new();
    match value {
        Value::Null => {
            renderer.error(codes::TYPE_MISMATCH, "TOML does not support null", span);
            return None;
        }
        Value::Bool(value) => {
            output_budget.write_fmt(&mut output, format_args!("{value}"))?;
        }
        Value::Int(value) => {
            output_budget.write_fmt(&mut output, format_args!("{value}"))?;
        }
        Value::Float(value) if value.is_finite() => {
            output_budget.push_str(&mut output, &format_float(*value))?;
        }
        Value::Float(_) => {
            renderer.error(
                codes::TYPE_MISMATCH,
                "non-finite numbers are not supported",
                span,
            );
            return None;
        }
        Value::String(value) | Value::Path(value) => {
            output_budget.push_char(&mut output, '"')?;
            write_json_escape(&mut output_budget.writer(&mut output), value).ok()?;
            output_budget.push_char(&mut output, '"')?;
        }
        Value::List(values) => {
            output_budget.push_char(&mut output, '[')?;
            for (index, value) in values.iter().enumerate() {
                if index != 0 {
                    output_budget.push_str(&mut output, ", ")?;
                }
                let value = write_toml_value(renderer, output_budget, value, span)?;
                OutputBudget::append_accounted(&mut output, &value);
            }
            output_budget.push_char(&mut output, ']')?;
        }
        Value::Record(values) => {
            output_budget.push_str(&mut output, "{ ")?;
            for (index, (name, value)) in values.iter().enumerate() {
                if index != 0 {
                    output_budget.push_str(&mut output, ", ")?;
                }
                output_budget.write_fmt(&mut output, format_args!("{} = ", toml_key(name)))?;
                let value = write_toml_value(renderer, output_budget, value, span)?;
                OutputBudget::append_accounted(&mut output, &value);
            }
            output_budget.push_str(&mut output, " }")?;
        }
        other => {
            renderer.error(
                codes::TYPE_MISMATCH,
                format!("{} cannot be represented in TOML", other.type_label()),
                span,
            );
            return None;
        }
    }
    Some(output)
}

fn ini_items(
    renderer: &mut Renderer<'_>,
    output_budget: &mut OutputBudget,
    items: &[ConfigItem<ShapeNode>],
    opts: &IniOpts,
    prefix: &str,
) -> Option<String> {
    let mut output = String::new();
    let mut seen = HashSet::new();
    let mut sink = IniSink {
        output: &mut output,
        output_budget,
        seen: &mut seen,
        opts,
    };
    let mut saw_section = false;
    renderer.walk_all(items, 0, &parse_items, &mut |renderer, node, _span| {
        match node {
            ShapeNode::Comment { text, .. } => {
                sink.output_budget
                    .write_fmt(sink.output, format_args!("# {text}\n"))?;
            }
            ShapeNode::Requirements { span } | ShapeNode::Profiles { span } => {
                reject_text_only(renderer, *span);
                return None;
            }
            ShapeNode::Raw { text, .. } => {
                sink.output_budget
                    .write_fmt(sink.output, format_args!("{text}\n"))?;
            }
            ShapeNode::Line { span, .. } => {
                reject_line(renderer, *span, "ini");
                return None;
            }
            node @ (ShapeNode::File { .. } | ShapeNode::Compose { .. }) => {
                match renderer.resource_text(node) {
                    Some(text) => push_block(sink.output_budget, sink.output, &text)?,
                    None => return None,
                }
            }
            ShapeNode::Spread(spread) => {
                if saw_section {
                    renderer.error(
                        codes::NODE_SHAPE,
                        "`@insert-fields` appears after a section at the same level; move it above sections",
                        spread.span,
                    );
                    return None;
                }
                let fields = spread_fields(renderer, spread)?;
                for (name, value) in fields {
                    let values = [(Resolved::Value(value), spread.span)];
                    sink.spread_line(renderer, &name, &values, spread.span)?;
                }
            }
            ShapeNode::Entry(entry) => {
                let resolved = renderer.resolve_entry(entry)?;
                let ResolvedEntry::Ready { name, args, props } = resolved else {
                    return Some(());
                };
                let Some(name) = name else {
                    renderer.error(
                        codes::NODE_SHAPE,
                        "`-` array elements are not valid in ini bodies; repeat the key instead",
                        entry.span,
                    );
                    return None;
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
                            return None;
                        }
                        if !props.is_empty() && !args.is_empty() {
                            renderer.error(
                                codes::NODE_SHAPE,
                                "an entry mixes values and properties",
                                entry.span,
                            );
                            return None;
                        }
                        if !props.is_empty() {
                            for (key, value, span) in &props {
                                let dotted = format!("{name}.{key}");
                                let values = [(value.clone(), *span)];
                                sink.line(renderer, entry, &dotted, &values, *span)?;
                            }
                            return Some(());
                        }
                        sink.line(renderer, entry, &name, &args, entry.span)?;
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
                                return None;
                            }
                            match renderer.scalar_text(section, *span) {
                                Some(text) => path = format!("{path}.{text}"),
                                None => {
                                    return None;
                                }
                            }
                        }
                        if !props.is_empty() {
                            renderer.error(
                                codes::NODE_SHAPE,
                                "ini sections do not take properties; declare keys in the body",
                                entry.span,
                            );
                            return None;
                        }
                        if let Err(error) = validate_ini_name(&path, true, entry.span) {
                            renderer.diagnostics.push(error);
                            return None;
                        }
                        renderer.insert_unique(
                            sink.seen,
                            format!("section:{path}"),
                            &path,
                            entry.span,
                        )?;
                        saw_section = true;
                        match ini_items(renderer, sink.output_budget, children, sink.opts, &path) {
                            Some(inner) => {
                                sink.output_budget
                                    .write_fmt(sink.output, format_args!("\n[{path}]\n"))?;
                                OutputBudget::append_accounted(sink.output, &inner);
                            }
                            None => return None,
                        }
                    }
                }
            }

            }
        Some(())
    })?;
    Some(output)
}

/// The mutable target of one INI section: the accumulating text, the
/// duplicate-key set, and the file-level options they are checked against.
struct IniSink<'a> {
    output: &'a mut String,
    output_budget: &'a mut OutputBudget,
    seen: &'a mut HashSet<String>,
    opts: &'a IniOpts,
}

impl IniSink<'_> {
    /// An `@insert-fields` field line: file-level quote mode, no per-entry override.
    fn spread_line(
        &mut self,
        renderer: &mut Renderer<'_>,
        name: &str,
        args: &[(Resolved, Span)],
        span: Span,
    ) -> Option<()> {
        self.emit(renderer, self.opts.quote, name, args, span)
    }

    fn line(
        &mut self,
        renderer: &mut Renderer<'_>,
        entry: &Entry,
        name: &str,
        args: &[(Resolved, Span)],
        span: Span,
    ) -> Option<()> {
        let quote = entry.quote.unwrap_or(self.opts.quote);
        self.emit(renderer, quote, name, args, span)
    }

    fn emit(
        &mut self,
        renderer: &mut Renderer<'_>,
        quote: QuoteMode,
        name: &str,
        args: &[(Resolved, Span)],
        span: Span,
    ) -> Option<()> {
        if let Err(error) = validate_ini_name(name, false, span) {
            renderer.diagnostics.push(error);
            return None;
        }
        let value_count = args.iter().try_fold(0_usize, |count, (resolved, _)| {
            count.checked_add(match resolved {
                Resolved::Value(Value::List(items)) => items.len(),
                _ => 1,
            })
        })?;
        let repeats = value_count > 1;
        if !repeats && !self.seen.insert(name.to_owned()) {
            renderer.duplicate(name, span);
            return None;
        }
        if args.is_empty() {
            self.emit_value(name, "", quote)?;
        }
        for (resolved, value_span) in args {
            match resolved {
                Resolved::Value(Value::List(items)) => {
                    for item in items {
                        let value =
                            renderer.scalar_text(&Resolved::Value(item.clone()), *value_span)?;
                        self.emit_value(name, &value, quote)?;
                    }
                }
                other => {
                    let value = renderer.scalar_text(other, *value_span)?;
                    self.emit_value(name, &value, quote)?;
                }
            }
        }
        Some(())
    }

    fn emit_value(&mut self, name: &str, value: &str, quote: QuoteMode) -> Option<()> {
        self.output_budget
            .write_fmt(self.output, format_args!("{name}{}", self.opts.separator))?;
        write_quoted(self.output_budget, self.output, value, quote)?;
        self.output_budget.push_char(self.output, '\n')
    }
}

fn text_root(
    renderer: &mut Renderer<'_>,
    output_budget: &mut OutputBudget,
    items: &[ConfigItem<ShapeNode>],
    opts: &TextOpts,
    span: Span,
) -> Option<String> {
    let mut output = text_items(renderer, output_budget, items, opts, 0, "")?;
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
        output_budget.pop(&mut output);
    }
    Some(output)
}

fn text_items(
    renderer: &mut Renderer<'_>,
    output_budget: &mut OutputBudget,
    items: &[ConfigItem<ShapeNode>],
    opts: &TextOpts,
    depth: usize,
    prefix: &str,
) -> Option<String> {
    let mut output = String::new();
    let pad = if opts.layout == TextLayout::Braces {
        opts.indent.repeat(depth)
    } else {
        String::new()
    };
    renderer.walk_all(items, 0, &parse_items, &mut |renderer, node, _span| {
        match node {
            ShapeNode::Comment { text, .. } => {
                output_budget.write_fmt(&mut output, format_args!("{pad}# {text}\n"))?;
            }
            ShapeNode::Requirements { .. } => {
                for subject in &renderer.resources().requirements {
                    output_budget.write_fmt(&mut output, format_args!("{pad}{subject}\n"))?;
                }
            }
            ShapeNode::Profiles { .. } => {
                for profile in &renderer.resources().profiles {
                    output_budget.write_fmt(&mut output, format_args!("{pad}{profile}\n"))?;
                }
            }
            ShapeNode::Raw { text, .. } => {
                output_budget.push_str(&mut output, text)?;
                output_budget.push_char(&mut output, '\n')?;
            }
            ShapeNode::Line { value, span } => match renderer.resolve(value) {
                Some(Resolved::Skip) => {}
                Some(resolved) => match renderer.scalar_text(&resolved, *span) {
                    Some(text) => {
                        output_budget.write_fmt(&mut output, format_args!("{pad}{text}\n"))?;
                    }
                    None => return None,
                },
                None => return None,
            },
            node @ (ShapeNode::File { .. } | ShapeNode::Compose { .. }) => {
                match renderer.resource_text(node) {
                    Some(text) => push_block(output_budget, &mut output, &text)?,
                    None => return None,
                }
            }
            ShapeNode::Spread(spread) => {
                let fields = spread_fields(renderer, spread)?;
                for (name, value) in fields {
                    let key = text_key(prefix, &name, opts);
                    let flat_values = match value {
                        Value::List(items) => items,
                        other => vec![other],
                    };
                    for item in flat_values {
                        match renderer.scalar_text(&Resolved::Value(item), spread.span) {
                            Some(text) => {
                                output_budget.write_fmt(
                                    &mut output,
                                    format_args!("{pad}{key}{}", opts.separator),
                                )?;
                                write_quoted(output_budget, &mut output, &text, opts.quote)?;
                                output_budget.push_char(&mut output, '\n')?;
                            }
                            None => {
                                return None;
                            }
                        }
                    }
                }
            }
            ShapeNode::Entry(entry) => {
                let resolved = renderer.resolve_entry(entry)?;
                let ResolvedEntry::Ready { name, args, props } = resolved else {
                    return Some(());
                };
                match &entry.children {
                    None => {
                        let Some(name) = name else {
                            renderer.error(
                                codes::NODE_SHAPE,
                                "`-` array elements are not valid outside a block in text bodies",
                                entry.span,
                            );
                            return None;
                        };
                        let key = text_key(prefix, &name, opts);
                        if !props.is_empty() && !args.is_empty() {
                            renderer.error(
                                codes::NODE_SHAPE,
                                "an entry mixes values and properties",
                                entry.span,
                            );
                            return None;
                        }
                        if !props.is_empty() {
                            // Compact objects use braces in block mode and dotted keys
                            // in flat mode.
                            if opts.layout == TextLayout::Braces {
                                let mut inner = String::new();
                                let inner_pad = opts.indent.repeat(depth + 1);
                                for (prop, value, span) in &props {
                                    output_budget.write_fmt(
                                        &mut inner,
                                        format_args!("{inner_pad}{prop}{}", opts.separator),
                                    )?;
                                    write_text_scalar(
                                        renderer,
                                        output_budget,
                                        &mut inner,
                                        value,
                                        *span,
                                        entry,
                                        opts,
                                    )?;
                                    output_budget.push_char(&mut inner, '\n')?;
                                }
                                output_budget
                                    .write_fmt(&mut output, format_args!("{pad}{name} {{\n"))?;
                                OutputBudget::append_accounted(&mut output, &inner);
                                output_budget.write_fmt(&mut output, format_args!("{pad}}}\n"))?;
                            } else {
                                for (prop, value, span) in &props {
                                    output_budget.write_fmt(
                                        &mut output,
                                        format_args!("{key}.{prop}{}", opts.separator),
                                    )?;
                                    write_text_scalar(
                                        renderer,
                                        output_budget,
                                        &mut output,
                                        value,
                                        *span,
                                        entry,
                                        opts,
                                    )?;
                                    output_budget.push_char(&mut output, '\n')?;
                                }
                            }
                            return Some(());
                        }
                        if args.is_empty() {
                            output_budget.write_fmt(&mut output, format_args!("{pad}{key}\n"))?;
                            return Some(());
                        }
                        for (resolved, span) in &args {
                            match resolved {
                                Resolved::Value(Value::List(items)) => {
                                    for item in items {
                                        output_budget.write_fmt(
                                            &mut output,
                                            format_args!("{pad}{key}{}", opts.separator),
                                        )?;
                                        write_text_scalar(
                                            renderer,
                                            output_budget,
                                            &mut output,
                                            &Resolved::Value(item.clone()),
                                            *span,
                                            entry,
                                            opts,
                                        )?;
                                        output_budget.push_char(&mut output, '\n')?;
                                    }
                                }
                                other => {
                                    output_budget.write_fmt(
                                        &mut output,
                                        format_args!("{pad}{key}{}", opts.separator),
                                    )?;
                                    write_text_scalar(
                                        renderer,
                                        output_budget,
                                        &mut output,
                                        other,
                                        *span,
                                        entry,
                                        opts,
                                    )?;
                                    output_budget.push_char(&mut output, '\n')?;
                                }
                            }
                        }
                    }
                    Some(children) => {
                        if !props.is_empty() {
                            renderer.error(
                                codes::NODE_SHAPE,
                                "text sections do not take properties; declare keys in the body",
                                entry.span,
                            );
                            return None;
                        }
                        let Some(name) = name else {
                            // A `-` element becomes an anonymous repeated brace group.
                            match text_items(
                                renderer,
                                output_budget,
                                children,
                                opts,
                                depth + 1,
                                prefix,
                            ) {
                                Some(inner) => {
                                    output_budget
                                        .write_fmt(&mut output, format_args!("{pad}{{\n"))?;
                                    OutputBudget::append_accounted(&mut output, &inner);
                                    output_budget
                                        .write_fmt(&mut output, format_args!("{pad}}}\n"))?;
                                }
                                None => return None,
                            }
                            return Some(());
                        };
                        let mut section_names: Vec<String> = Vec::new();
                        for (section, span) in &args {
                            match renderer.scalar_text(section, *span) {
                                Some(text) => section_names.push(text),
                                None => {
                                    return None;
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
                            match text_items(
                                renderer,
                                output_budget,
                                children,
                                opts,
                                depth + 1,
                                prefix,
                            ) {
                                Some(inner) => {
                                    output_budget.write_fmt(
                                        &mut output,
                                        format_args!("{pad}{header} {{\n"),
                                    )?;
                                    OutputBudget::append_accounted(&mut output, &inner);
                                    output_budget
                                        .write_fmt(&mut output, format_args!("{pad}}}\n"))?;
                                }
                                None => return None,
                            }
                        } else {
                            let mut path = text_key(prefix, &name, opts);
                            for section in &section_names {
                                path = format!("{path}.{section}");
                            }
                            match text_items(renderer, output_budget, children, opts, depth, &path)
                            {
                                Some(inner) => {
                                    OutputBudget::append_accounted(&mut output, &inner);
                                }
                                None => return None,
                            }
                        }
                    }
                }
            }
        }
        Some(())
    })?;
    Some(output)
}

fn text_key(prefix: &str, name: &str, opts: &TextOpts) -> String {
    if opts.layout == TextLayout::Flat && !prefix.is_empty() {
        format!("{prefix}.{name}")
    } else {
        name.to_owned()
    }
}

fn write_text_scalar(
    renderer: &mut Renderer<'_>,
    output_budget: &mut OutputBudget,
    output: &mut String,
    resolved: &Resolved,
    span: Span,
    entry: &Entry,
    opts: &TextOpts,
) -> Option<()> {
    let text = renderer.scalar_text(resolved, span)?;
    write_quoted(
        output_budget,
        output,
        &text,
        entry.quote.unwrap_or(opts.quote),
    )
}

fn write_quoted(
    output_budget: &mut OutputBudget,
    output: &mut String,
    value: &str,
    quote: QuoteMode,
) -> Option<()> {
    match quote {
        QuoteMode::None => output_budget.push_str(output, value),
        QuoteMode::Double => {
            output_budget.push_char(output, '"')?;
            write_json_escape(&mut output_budget.writer(output), value).ok()?;
            output_budget.push_char(output, '"')
        }
    }
}
