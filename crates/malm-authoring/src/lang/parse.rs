//! Parses KDL declarations into the [`crate::lang::ast`] model and validates
//! their shape and cardinality.

use crate::lang::ast::{
    CollectionPatch, ConflictPolicy, DirOutput, EachBlock, ExtendModule, ExtendProfile, FileOutput,
    FragmentCardinality, FragmentDecl, FragmentOp, FragmentOpBody, FragmentSource, InputDecl,
    InstanceConfig, MissingSourcePolicy, ModuleDecl, NamedTypeDecl, OutputNode, PatchEntry,
    PatchOp, ProfileDecl, ProfileItem, RangeBlock, ReplaceDecl, Requirement, RequirementKind,
    RequirementNode, SlotDecl, SlotMax, SymlinkOutput, SymlinkSource, UseDecl, WhenBlock,
    WithEntry,
};
use crate::lang::diag::{Diagnostic, FileId, Span, codes};
use crate::lang::kdl_util::{
    ParseResult, at_entry, at_node, bool_prop, child_nodes, entry_span, expect_args,
    is_condition_name, node_span, opt_child, opt_str_prop, parse_condition, parse_each_header,
    parse_range_header, parse_ref, parse_splice, prop_entry, reject_duplicate_children,
    reject_unknown_children, reject_unknown_props, removed_control, req_str_arg, req_str_prop,
    scalar_value, validate_document_depth, validate_else,
};
use crate::lang::value::{
    FieldSchema, NumericBound, RawRecordLiteral, RawRecordProperty, RecordSchema, Type, Value,
};
use kdl::{KdlDocument, KdlNode};
use std::collections::HashSet;
use std::path::Path;

/// Namespaces reserved from module input names.
const RESERVED_PREFIXES: [&str; 5] = ["malm.", "machine.", "profile.", "instance.", "global."];

fn reserved_prefix(name: &str) -> Option<&'static str> {
    RESERVED_PREFIXES
        .iter()
        .copied()
        .find(|p| name.starts_with(p))
}

pub(crate) fn parse_module(file: FileId, dir: &Path, node: &KdlNode) -> ParseResult<ModuleDecl> {
    let name = req_str_arg(file, node)?;
    reject_unknown_props(file, node, &[])?;
    reject_unknown_children(
        file,
        node,
        &[
            "description",
            "slot",
            "types",
            "requires",
            "inputs",
            "fragments",
            "outputs",
        ],
    )?;
    reject_duplicate_children(
        file,
        node,
        &[
            "description",
            "slot",
            "types",
            "requires",
            "inputs",
            "fragments",
            "outputs",
        ],
    )?;

    let mut module = ModuleDecl {
        name,
        description: None,
        slot: None,
        types: Vec::new(),
        requires: Vec::new(),
        inputs: Vec::new(),
        fragments: Vec::new(),
        outputs: Vec::new(),
        span: node_span(file, node),
        dir: dir.to_path_buf(),
    };
    if let Some(children) = node.children() {
        for child in children.nodes() {
            match child.name().value() {
                "description" => module.description = Some(req_str_arg(file, child)?),
                "slot" => module.slot = Some(req_str_arg(file, child)?),
                "types" => module.types = parse_types(file, child)?,
                "requires" => module.requires = parse_requires(file, child)?,
                "inputs" => module.inputs = parse_inputs(file, child)?,
                "fragments" => module.fragments = parse_fragments(file, dir, child)?,
                "outputs" => module.outputs = parse_outputs(file, dir, child)?,
                _ => unreachable!("validated above"),
            }
        }
    }
    Ok(module)
}

pub(crate) fn parse_extend_module(
    file: FileId,
    dir: &Path,
    node: &KdlNode,
) -> ParseResult<ExtendModule> {
    let name = req_str_arg(file, node)?;
    reject_unknown_props(file, node, &[])?;
    reject_unknown_children(file, node, &["requires", "inputs", "fragments", "outputs"])?;
    reject_duplicate_children(file, node, &["requires", "inputs", "fragments", "outputs"])?;

    let mut extension = ExtendModule {
        module: name,
        requires: Vec::new(),
        inputs: Vec::new(),
        fragments: Vec::new(),
        outputs: Vec::new(),
        span: node_span(file, node),
        dir: dir.to_path_buf(),
    };
    if let Some(children) = node.children() {
        for child in children.nodes() {
            match child.name().value() {
                "requires" => extension.requires = parse_requires(file, child)?,
                "inputs" => extension.inputs = parse_inputs(file, child)?,
                "fragments" => extension.fragments = parse_fragments(file, dir, child)?,
                "outputs" => extension.outputs = parse_outputs(file, dir, child)?,
                _ => unreachable!("validated above"),
            }
        }
    }
    Ok(extension)
}

fn parse_requires(file: FileId, node: &KdlNode) -> ParseResult<Vec<RequirementNode>> {
    reject_unknown_props(file, node, &[])?;
    expect_args(file, node, 0)?;
    parse_requirement_nodes(file, child_nodes(node))
}

fn parse_requirement_nodes(file: FileId, nodes: &[KdlNode]) -> ParseResult<Vec<RequirementNode>> {
    let mut out = Vec::new();
    let mut nodes = nodes.iter().peekable();
    while let Some(node) = nodes.next() {
        if is_condition_name(node.name().value()) {
            let otherwise = if nodes
                .peek()
                .is_some_and(|next| next.name().value() == "@else")
            {
                Some(nodes.next().expect("peeked"))
            } else {
                None
            };
            out.push(RequirementNode::When(parse_when(
                file,
                node,
                otherwise,
                &mut |children| parse_requirement_nodes(file, children),
            )?));
        } else if node.name().value() == "@else" {
            return Err(orphan_else(file, node));
        } else {
            out.push(parse_requirement_node(file, node)?);
        }
    }
    Ok(out)
}

fn parse_requirement_node(file: FileId, node: &KdlNode) -> ParseResult<RequirementNode> {
    let kind = match node.name().value() {
        "command" => RequirementKind::Command,
        "file" => RequirementKind::File,
        "feature" => RequirementKind::Feature,
        other => {
            if let Some(diagnostic) = removed_control(file, node) {
                return Err(diagnostic);
            }
            return Err(at_node(file, node).error(codes::UNKNOWN_NODE,
                format!(
                    "unknown requirement `{other}` (allowed: command, file, feature, @if, @if-present, @if-nonempty)"
                )));
        }
    };
    reject_unknown_props(file, node, &[])?;
    reject_unknown_children(file, node, &[])?;
    Ok(RequirementNode::Requirement(Requirement {
        kind,
        subject: req_str_arg(file, node)?,
        span: node_span(file, node),
    }))
}

const MAX_TYPE_DEPTH: usize = 32;
const MAX_TYPE_DECLARATIONS: usize = 4096;
const MAX_ENUM_VALUES: usize = 4096;

fn parse_types(file: FileId, node: &KdlNode) -> ParseResult<Vec<NamedTypeDecl>> {
    reject_unknown_props(file, node, &[])?;
    expect_args(file, node, 0)?;
    reject_unknown_children(
        file,
        node,
        &["enum", "record", "variant", "refine", "alias"],
    )?;
    validate_document_depth(file, child_nodes(node))?;
    let mut declarations: Vec<NamedTypeDecl> = Vec::new();
    let mut names = HashSet::new();
    for declaration in child_nodes(node) {
        if declarations.len() >= MAX_TYPE_DECLARATIONS {
            return Err(Diagnostic::error(
                codes::TYPE_COMPLEXITY,
                format!(
                    "module declares more than the maximum of {MAX_TYPE_DECLARATIONS} named types"
                ),
            )
            .with_span(node_span(file, declaration)));
        }
        let allowed_props: &[&str] = match declaration.name().value() {
            "variant" => &["discriminator"],
            "refine" => &["base", "min", "max", "format", "unit"],
            "alias" => &["type"],
            _ => &[],
        };
        reject_unknown_props(file, declaration, allowed_props)?;
        let name = req_str_arg(file, declaration)?;
        let span = node_span(file, declaration);
        validate_type_name(&name, span)?;
        if !names.insert(name.clone()) {
            return Err(Diagnostic::error(
                codes::DUPLICATE,
                format!("duplicate type declaration `{name}`"),
            )
            .with_span(span));
        }
        let ty = match declaration.name().value() {
            "enum" => {
                reject_unknown_children(file, declaration, &["values"])?;
                reject_duplicate_children(file, declaration, &["values"])?;
                Type::Enum(parse_enum_values(file, declaration)?)
            }
            "record" => {
                reject_unknown_children(file, declaration, &["fields"])?;
                reject_duplicate_children(file, declaration, &["fields"])?;
                Type::Record(parse_record_schema(file, declaration)?)
            }
            "variant" => {
                reject_unknown_children(file, declaration, &["case"])?;
                Type::Variant(parse_variant_schema(file, declaration)?)
            }
            "refine" => {
                reject_unknown_children(file, declaration, &[])?;
                Type::Refine(parse_refine_schema(file, declaration)?)
            }
            "alias" => {
                reject_unknown_children(file, declaration, &[])?;
                let raw_type = req_str_prop(file, declaration, "type")?;
                parse_type_expression(file, declaration, &raw_type)?
            }
            _ => unreachable!("validated above"),
        };
        declarations.push(NamedTypeDecl { name, ty, span });
    }
    Ok(declarations)
}

fn validate_type_name(name: &str, span: Span) -> ParseResult<()> {
    const RESERVED: &[&str] = &[
        "bool",
        "int",
        "float",
        "string",
        "path",
        "kdl-document",
        "enum",
        "record",
        "variant",
        "refine",
        "list",
        "collection",
        "map",
        "tuple",
        "set",
        "alias",
    ];
    if name.is_empty() || name.chars().any(|c| c.is_whitespace() || "?<>".contains(c)) {
        return Err(Diagnostic::error(
            codes::NODE_SHAPE,
            format!(
                "type name `{name}` must be non-empty and contain no whitespace, `?`, `<`, or `>`"
            ),
        )
        .with_span(span));
    }
    if RESERVED.contains(&name) {
        return Err(Diagnostic::error(
            codes::DUPLICATE,
            format!("type declaration `{name}` collides with a built-in type"),
        )
        .with_span(span));
    }
    Ok(())
}

fn parse_inputs(file: FileId, node: &KdlNode) -> ParseResult<Vec<InputDecl>> {
    reject_unknown_props(file, node, &[])?;
    expect_args(file, node, 0)?;
    reject_unknown_children(file, node, &["input"])?;
    let mut out: Vec<InputDecl> = Vec::new();
    let mut names = HashSet::new();
    if let Some(children) = node.children() {
        for child in children.nodes() {
            let input = parse_input(file, child)?;
            if !names.insert(input.name.clone()) {
                return Err(Diagnostic::error(
                    codes::DUPLICATE,
                    format!("duplicate input `{}`", input.name),
                )
                .with_span(input.span));
            }
            out.push(input);
        }
    }
    Ok(out)
}

fn parse_input(file: FileId, node: &KdlNode) -> ParseResult<InputDecl> {
    validate_document_depth(file, std::slice::from_ref(node))?;
    let name = req_str_arg(file, node)?;
    let span = node_span(file, node);
    if name.is_empty() {
        return Err(
            Diagnostic::error(codes::NODE_SHAPE, "input name must not be empty").with_span(span),
        );
    }
    if let Some(prefix) = reserved_prefix(&name) {
        return Err(Diagnostic::error(
            codes::RESERVED_NAME,
            format!("input `{name}` uses the reserved namespace `{prefix}`"),
        )
        .with_span(span)
        .with_help("inputs are scoped to their module; drop the prefix"));
    }
    reject_unknown_props(file, node, &["type", "default", "optional", "item-type"])?;
    reject_unknown_children(file, node, &["default", "fields", "defaults", "values"])?;
    reject_duplicate_children(file, node, &["default", "fields", "defaults", "values"])?;

    let ty = parse_declared_type(file, node, true)?;
    validate_input_children(file, node, &ty)?;

    let mut default: Option<Value> = None;
    let mut default_span: Option<Span> = None;
    let mut computed_default: Option<String> = None;
    let mut computed_default_span: Option<Span> = None;

    if let Some(entry) = prop_entry(node, "default") {
        if matches!(
            ty.unwrap_optional(),
            Type::List(_)
                | Type::Record(_)
                | Type::Collection(_)
                | Type::Variant(_)
                | Type::Map(_)
                | Type::Tuple(_)
                | Type::Set(_)
        ) {
            return Err(at_entry(file, entry).error(
                codes::NODE_SHAPE,
                "aggregate inputs declare defaults with their typed child block",
            ));
        }
        if let Some(annotation) = entry.ty() {
            if annotation.value() == "f" {
                let Some(template) = entry.value().as_string() else {
                    return Err(at_entry(file, entry).error(
                        codes::NODE_SHAPE,
                        "computed `default=(f)` requires a string template",
                    ));
                };
                if let Err(message) = crate::lang::text::parse_template_with(
                    template,
                    crate::lang::text::TemplateSyntax::V3,
                ) {
                    return Err(at_entry(file, entry).error(codes::TEMPLATE, message));
                }
                computed_default = Some(template.to_owned());
                computed_default_span = Some(entry_span(file, entry));
            } else {
                return Err(at_entry(file, entry).error(
                    codes::NODE_SHAPE,
                    format!(
                        "input `{name}`: `default=` accepts only the `(f)` type annotation; found `({})`",
                        annotation.value()
                    ),
                ));
            }
        } else {
            let value = scalar_value(file, entry)?;
            if value.is_null() {
                return Err(at_entry(file, entry).error(
                    codes::NODE_SHAPE,
                    "`default=#null` is redundant — an optional without a default is already null",
                ));
            }
            default = Some(value);
            default_span = Some(entry_span(file, entry));
        }
    }

    if let Some(default_node) = opt_child(node, "default") {
        if default.is_some() || computed_default.is_some() {
            return Err(at_node(file, default_node).error(codes::DUPLICATE,
                format!(
                    "input `{name}`: give the default either as a property or a child node, not both"
                )));
        }
        // Only `(f)` turns a `default` child into a computed template. Other
        // annotations are rejected by scalar default parsing below.
        let computed_first = default_node
            .iter()
            .find(|entry| entry.name().is_none())
            .filter(|entry| entry.ty().is_some_and(|ty| ty.value() == "f"));
        if let Some(entry) = computed_first {
            reject_unknown_props(file, default_node, &[])?;
            reject_unknown_children(file, default_node, &[])?;
            expect_args(file, default_node, 1)?;
            let Some(template) = entry.value().as_string() else {
                return Err(at_entry(file, entry).error(
                    codes::NODE_SHAPE,
                    "computed `default (f)` requires a string template",
                ));
            };
            if let Err(message) = crate::lang::text::parse_template_with(
                template,
                crate::lang::text::TemplateSyntax::V3,
            ) {
                return Err(at_entry(file, entry).error(codes::TEMPLATE, message));
            }
            computed_default = Some(template.to_owned());
            computed_default_span = Some(entry_span(file, entry));
        } else {
            match ty.unwrap_optional() {
                Type::List(item) if matches!(item.as_ref(), Type::Record(_)) => {
                    expect_args(file, default_node, 0)?;
                    default = Some(Value::List(vec![Value::RawRecordLiteral(
                        parse_raw_record_literal(file, default_node)?,
                    )]));
                }
                Type::List(item)
                    if unresolved_named_type(item)
                        && (default_node.children().is_some()
                            || default_node.iter().any(|entry| entry.name().is_some())) =>
                {
                    expect_args(file, default_node, 0)?;
                    // Resolution distinguishes a named-record item from an
                    // explicitly empty named-enum list.
                    default = Some(Value::UnresolvedListDefault(parse_raw_record_literal(
                        file,
                        default_node,
                    )?));
                }
                Type::List(_) | Type::Tuple(_) | Type::Set(_) => {
                    reject_unknown_props(file, default_node, &[])?;
                    reject_unknown_children(file, default_node, &[])?;
                    let mut items = Vec::new();
                    for entry in default_node.iter().filter(|e| e.name().is_none()) {
                        items.push(scalar_value(file, entry)?);
                    }
                    default = Some(Value::List(items));
                }
                Type::Record(_) | Type::Variant(_) => {
                    expect_args(file, default_node, 0)?;
                    default = Some(Value::RawRecordLiteral(parse_raw_record_literal(
                        file,
                        default_node,
                    )?));
                }
                Type::Named(_) => {
                    expect_args(file, default_node, 0)?;
                    if default_node.iter().any(|entry| entry.name().is_some()) {
                        default = Some(Value::RawRecordLiteral(parse_raw_record_literal(
                            file,
                            default_node,
                        )?));
                    } else {
                        default = Some(Value::KdlDocument(
                            default_node.children().cloned().unwrap_or_default(),
                        ));
                    }
                }
                _ => {
                    return Err(at_node(file, default_node).error(codes::NODE_SHAPE,
                        format!(
                            "input `{name}`: a `default` child node is only valid for list, record, variant, tuple, set, or `(f)`-typed defaults"
                        )));
                }
            }
            default_span = Some(node_span(file, default_node));
        }
    }

    if let Some(defaults_node) = opt_child(node, "defaults") {
        default = Some(match ty.unwrap_optional() {
            Type::Collection(_) | Type::Map(_) => parse_collection_defaults(file, defaults_node)?,
            Type::List(_) => parse_record_list(file, defaults_node)?,
            _ => {
                return Err(at_node(file, defaults_node).error(
                    codes::NODE_SHAPE,
                    format!(
                        "input `{name}`: `defaults` requires a collection, map, or list<record>"
                    ),
                ));
            }
        });
        default_span = Some(node_span(file, defaults_node));
    }

    Ok(InputDecl {
        name,
        ty,
        default,
        span,
        default_span,
        computed_default,
        computed_default_span,
    })
}

fn unresolved_named_type(ty: &Type) -> bool {
    match ty {
        Type::Named(_) => true,
        Type::Optional(inner) => unresolved_named_type(inner),
        _ => false,
    }
}

fn parse_record_list(file: FileId, node: &KdlNode) -> ParseResult<Value> {
    reject_unknown_props(file, node, &[])?;
    expect_args(file, node, 0)?;
    reject_unknown_children(file, node, &["item"])?;
    let mut values = Vec::new();
    for item in child_nodes(node) {
        expect_args(file, item, 0)?;
        if item.iter().any(|entry| entry.name().is_some()) {
            values.push(Value::RawRecordLiteral(parse_raw_record_literal(
                file, item,
            )?));
        } else {
            values.push(Value::KdlDocument(
                item.children().cloned().unwrap_or_default(),
            ));
        }
    }
    Ok(Value::List(values))
}

fn parse_declared_type(
    file: FileId,
    node: &KdlNode,
    allow_optional_prop: bool,
) -> ParseResult<Type> {
    let raw = req_str_prop(file, node, "type")?;
    let item_type = opt_str_prop(file, node, "item-type")?;
    let mut ty = match raw.as_str() {
        "list" => Type::List(Box::new(parse_type_expression(
            file,
            node,
            item_type.as_deref().unwrap_or("string"),
        )?)),
        "collection" => Type::Collection(Box::new(parse_type_expression(
            file,
            node,
            item_type.as_deref().unwrap_or("kdl-document"),
        )?)),
        _ => {
            if item_type.is_some() {
                let generic = raw.starts_with("list<") || raw.starts_with("collection<");
                return Err(at_node(file, node).error(
                    if generic {
                        codes::DUPLICATE
                    } else {
                        codes::NODE_SHAPE
                    },
                    if generic {
                        "`item-type=` duplicates the generic item declaration"
                    } else {
                        "`item-type=` is only valid with bare `list` or `collection`"
                    },
                ));
            }
            parse_type_expression(file, node, &raw)?
        }
    };

    if allow_optional_prop && let Some(entry) = prop_entry(node, "optional") {
        if ty.is_optional() {
            return Err(at_entry(file, entry).error(
                codes::DUPLICATE,
                "optional type is declared both with `?` and `optional=`",
            ));
        }
        if bool_prop(file, node, "optional")? {
            ty = Type::Optional(Box::new(ty));
        }
    }
    Ok(ty)
}

fn parse_type_expression(file: FileId, node: &KdlNode, raw: &str) -> ParseResult<Type> {
    let mut parser = TypeExpressionParser {
        file,
        node,
        raw,
        offset: 0,
    };
    let ty = parser.parse(0)?;
    if parser.offset != raw.len() {
        return Err(parser.error(format!(
            "invalid type expression `{raw}` near `{}`",
            &raw[parser.offset..]
        )));
    }
    Ok(ty)
}

struct TypeExpressionParser<'a> {
    file: FileId,
    node: &'a KdlNode,
    raw: &'a str,
    offset: usize,
}

impl TypeExpressionParser<'_> {
    fn parse(&mut self, depth: usize) -> ParseResult<Type> {
        if depth > MAX_TYPE_DEPTH {
            return Err(at_node(self.file, self.node).error(
                codes::TYPE_DEPTH,
                format!("type expression exceeds the maximum depth of {MAX_TYPE_DEPTH}"),
            ));
        }
        // Permit whitespace before the next token, as in `tuple<int, int>`,
        // while continuing to reject whitespace inside a type name.
        self.skip_whitespace()?;
        let start = self.offset;
        while self.offset < self.raw.len() {
            let byte = self.raw.as_bytes()[self.offset];
            if matches!(byte, b'<' | b'>' | b'?' | b',') {
                break;
            }
            if byte.is_ascii_whitespace() {
                return Err(self.error("type expressions must not contain whitespace"));
            }
            self.offset += 1;
        }
        if self.offset == start {
            return Err(self.error(format!("invalid type expression `{}`", self.raw)));
        }
        let name = &self.raw[start..self.offset];
        let mut ty = if self.peek(b'<') {
            match name {
                "list" | "collection" | "map" | "set" => {
                    self.offset += 1;
                    let item = self.parse(depth + 1)?;
                    self.skip_whitespace()?;
                    self.expect_byte(b'>')?;
                    match name {
                        "list" => Type::List(Box::new(item)),
                        "collection" => Type::Collection(Box::new(item)),
                        "map" => Type::Map(Box::new(item)),
                        "set" => Type::Set(Box::new(item)),
                        _ => unreachable!("validated above"),
                    }
                }
                "tuple" => {
                    self.offset += 1;
                    let mut types = Vec::new();
                    // Parsing the first element rejects `tuple<>` because no
                    // type token appears before `>`.
                    types.push(self.parse(depth + 1)?);
                    loop {
                        self.skip_whitespace()?;
                        if !self.peek(b',') {
                            break;
                        }
                        self.offset += 1;
                        types.push(self.parse(depth + 1)?);
                    }
                    self.skip_whitespace()?;
                    self.expect_byte(b'>')?;
                    if types.len() > MAX_TYPE_DEPTH {
                        return Err(self.error(format!(
                            "tuple declares more than the maximum of {MAX_TYPE_DEPTH} elements"
                        )));
                    }
                    Type::Tuple(types)
                }
                _ => {
                    return Err(
                        self.error(format!("type `{name}` does not accept a generic item type"))
                    );
                }
            }
        } else {
            match name {
                "bool" => Type::Bool,
                "int" => Type::Int,
                "float" => Type::Float,
                "string" => Type::String,
                "path" => Type::Path,
                "kdl-document" => Type::KdlDocument,
                "enum" => Type::Enum(parse_enum_values(self.file, self.node)?),
                "record" => Type::Record(parse_record_schema(self.file, self.node)?),
                "list" | "collection" | "map" | "set" => {
                    return Err(self.error(format!(
                        "nested `{name}` requires an item type, for example `{name}<string>`"
                    )));
                }
                "tuple" => {
                    return Err(self.error(
                        "nested `tuple` requires at least one element, for example `tuple<int, string>`",
                    ));
                }
                _ => Type::Named(name.to_owned()),
            }
        };
        self.skip_whitespace()?;
        if self.peek(b'?') {
            self.offset += 1;
            if ty.is_optional() || self.peek(b'?') {
                return Err(self.error("optional type is declared more than once"));
            }
            ty = Type::Optional(Box::new(ty));
        }
        Ok(ty)
    }

    /// Skips ASCII whitespace before an operator or token. Whitespace inside
    /// a type name remains invalid, while `tuple<int, int>` remains valid.
    fn skip_whitespace(&mut self) -> ParseResult<()> {
        while self.offset < self.raw.len() && self.raw.as_bytes()[self.offset].is_ascii_whitespace()
        {
            self.offset += 1;
        }
        Ok(())
    }

    fn expect_byte(&mut self, byte: u8) -> ParseResult<()> {
        if !self.peek(byte) {
            return Err(self.error(format!(
                "type expression `{}` is missing `{}`",
                self.raw, byte as char
            )));
        }
        self.offset += 1;
        Ok(())
    }

    fn peek(&self, byte: u8) -> bool {
        self.raw.as_bytes().get(self.offset) == Some(&byte)
    }

    fn error(&self, message: impl Into<String>) -> Diagnostic {
        at_node(self.file, self.node).error(codes::NODE_SHAPE, message)
    }
}

fn parse_enum_values(file: FileId, node: &KdlNode) -> ParseResult<Vec<String>> {
    let Some(values_node) = opt_child(node, "values") else {
        return Err(at_node(file, node).error(
            codes::NODE_SHAPE,
            "an enum input requires a `values \"…\" \"…\"` child",
        ));
    };
    reject_unknown_props(file, values_node, &[])?;
    reject_unknown_children(file, values_node, &[])?;
    let mut values = Vec::new();
    let mut seen = HashSet::new();
    for entry in values_node.iter().filter(|entry| entry.name().is_none()) {
        if values.len() >= MAX_ENUM_VALUES {
            return Err(at_entry(file, entry).error(
                codes::TYPE_COMPLEXITY,
                format!("enum declares more than the maximum of {MAX_ENUM_VALUES} values"),
            ));
        }
        let Some(value) = entry.value().as_string() else {
            return Err(
                at_entry(file, entry).error(codes::NODE_SHAPE, "enum values must be strings")
            );
        };
        if value.is_empty() {
            return Err(
                at_entry(file, entry).error(codes::NODE_SHAPE, "enum values must not be empty")
            );
        }
        if !seen.insert(value.to_owned()) {
            return Err(at_entry(file, entry).error(
                codes::DUPLICATE,
                format!("enum value `{value}` is declared twice"),
            ));
        }
        values.push(value.to_owned());
    }
    if values.is_empty() {
        return Err(at_node(file, values_node).error(
            codes::NODE_SHAPE,
            "an enum input must declare at least one value",
        ));
    }
    values.sort();
    Ok(values)
}

fn validate_input_children(file: FileId, node: &KdlNode, ty: &Type) -> ParseResult<()> {
    // `default` is valid for scalar computed defaults and aggregate child
    // blocks, while record lists also accept `defaults`. Type-specific parsing
    // rejects unsupported scalar child forms.
    let mut allowed: Vec<&str> = Vec::new();
    allowed.push("default");
    if matches!(
        ty.unwrap_optional(),
        Type::List(_) | Type::Collection(_) | Type::Map(_)
    ) {
        allowed.push("defaults");
    }
    if type_contains_record(ty) {
        allowed.push("fields");
    }
    if type_contains_enum(ty) {
        allowed.push("values");
    }
    reject_unknown_children(file, node, &allowed)
}

fn type_contains_record(ty: &Type) -> bool {
    match ty {
        Type::Record(_) => true,
        Type::Variant(schema) => schema.cases.iter().any(|case| !case.fields.is_empty()),
        Type::List(inner) | Type::Collection(inner) | Type::Optional(inner) => {
            type_contains_record(inner)
        }
        Type::Map(inner) | Type::Set(inner) => type_contains_record(inner),
        Type::Tuple(types) => types.iter().any(type_contains_record),
        Type::Refine(schema) => type_contains_record(&schema.base),
        _ => false,
    }
}

fn type_contains_enum(ty: &Type) -> bool {
    match ty {
        Type::Enum(_) => true,
        Type::List(inner) | Type::Collection(inner) | Type::Optional(inner) => {
            type_contains_enum(inner)
        }
        Type::Map(inner) | Type::Set(inner) => type_contains_enum(inner),
        Type::Tuple(types) => types.iter().any(type_contains_enum),
        Type::Refine(schema) => type_contains_enum(&schema.base),
        _ => false,
    }
}

fn parse_record_schema(file: FileId, node: &KdlNode) -> ParseResult<RecordSchema> {
    let Some(fields_node) = opt_child(node, "fields") else {
        return Err(at_node(file, node).error(
            codes::NODE_SHAPE,
            "a record input requires a `fields { … }` child",
        ));
    };
    let fields = parse_field_decl_nodes(file, fields_node)?;
    if fields.is_empty() {
        return Err(at_node(file, node).error(
            codes::NODE_SHAPE,
            "a record input must declare at least one field",
        ));
    }
    Ok(RecordSchema { fields })
}

/// Walk a `fields { field ... }` node, returning one [`FieldSchema`] per
/// declared field in source order. Field-level defaults are deferred to
/// resolution. Duplicate and empty field names are diagnosed here.
fn parse_field_decl_nodes(file: FileId, fields_node: &KdlNode) -> ParseResult<Vec<FieldSchema>> {
    reject_unknown_props(file, fields_node, &[])?;
    expect_args(file, fields_node, 0)?;
    reject_unknown_children(file, fields_node, &["field"])?;
    let mut fields: Vec<FieldSchema> = Vec::new();
    let mut field_names = HashSet::new();
    if let Some(children) = fields_node.children() {
        for child in children.nodes() {
            reject_unknown_props(file, child, &["type", "required", "item-type", "default"])?;
            reject_unknown_children(file, child, &["fields", "values"])?;
            reject_duplicate_children(file, child, &["fields", "values"])?;
            let field_name = req_str_arg(file, child)?;
            if field_name.is_empty() {
                return Err(
                    at_node(file, child).error(codes::NODE_SHAPE, "field name must not be empty")
                );
            }
            if !field_names.insert(field_name.clone()) {
                return Err(at_node(file, child)
                    .error(codes::DUPLICATE, format!("duplicate field `{field_name}`")));
            }
            let ty = parse_declared_type(file, child, false)?;
            if opt_child(child, "fields").is_some() && !type_contains_record(&ty) {
                return Err(at_node(file, child).error(
                    codes::NODE_SHAPE,
                    "`fields` is only valid for an inline record type",
                ));
            }
            if opt_child(child, "values").is_some() && !type_contains_enum(&ty) {
                return Err(at_node(file, child).error(
                    codes::NODE_SHAPE,
                    "`values` is only valid for an inline enum type",
                ));
            }
            let (default, default_span) = match prop_entry(child, "default") {
                Some(entry) => {
                    let value = scalar_value(file, entry)?;
                    if value.is_null() {
                        return Err(at_entry(file, entry).error(
                            codes::NODE_SHAPE,
                            "a field default must not be #null; omit an optional field instead",
                        ));
                    }
                    (Some(value), Some(entry_span(file, entry)))
                }
                None => (None, None),
            };
            fields.push(FieldSchema {
                name: field_name,
                ty,
                required: bool_prop(file, child, "required")?,
                default,
                default_span,
                span: node_span(file, child),
            });
        }
    }
    Ok(fields)
}

/// Parse a `variant "name" discriminator="kind" { case ... }` declaration.
/// Each `case "name"` may be bare or carry a `fields { ... }` child whose
/// syntax mirrors record fields. Cases must be unique; the discriminator
/// field name must not collide with any case field name.
fn parse_variant_schema(
    file: FileId,
    node: &KdlNode,
) -> ParseResult<crate::lang::value::VariantSchema> {
    reject_unknown_props(file, node, &["discriminator"])?;
    let discriminator = req_str_prop(file, node, "discriminator")?;
    if discriminator.is_empty() {
        return Err(at_node(file, node).error(
            codes::NODE_SHAPE,
            "variant `discriminator=` must not be empty",
        ));
    }
    let mut cases: Vec<crate::lang::value::VariantCase> = Vec::new();
    let mut case_names: HashSet<String> = HashSet::new();
    for case_node in child_nodes(node) {
        let case_span = node_span(file, case_node);
        reject_unknown_props(file, case_node, &[])?;
        reject_unknown_children(file, case_node, &["fields"])?;
        reject_duplicate_children(file, case_node, &["fields"])?;
        let case_name = req_str_arg(file, case_node)?;
        if case_name.is_empty() {
            return Err(
                at_node(file, case_node).error(codes::NODE_SHAPE, "case name must not be empty")
            );
        }
        if !case_names.insert(case_name.clone()) {
            return Err(at_node(file, case_node)
                .error(codes::DUPLICATE, format!("duplicate case `{case_name}`")));
        }
        let fields = match opt_child(case_node, "fields") {
            Some(fields_node) => parse_field_decl_nodes(file, fields_node)?,
            None => Vec::new(),
        };
        if let Some(field) = fields.iter().find(|f| f.name == discriminator) {
            return Err(at_node(file, case_node).error(
                codes::NODE_SHAPE,
                format!(
                    "case `{case_name}` field `{field_name}` collides with the variant discriminator name",
                    field_name = field.name
                ),
            ));
        }
        cases.push(crate::lang::value::VariantCase {
            name: case_name,
            fields,
            span: case_span,
        });
    }
    if cases.is_empty() {
        return Err(at_node(file, node).error(
            codes::NODE_SHAPE,
            "a variant declaration must declare at least one case",
        ));
    }
    Ok(crate::lang::value::VariantSchema {
        discriminator,
        cases,
    })
}

/// Parse `refine "name" base="type" min=N max=M format="..." unit="..."`.
/// The `base` property is required and must be a scalar type expression
/// (one of `bool`, `int`, `float`, `string`, `path`, or `list<string>`).
/// Property compatibility is enforced here at parse time so a misconfigured
/// refinement never reaches resolution.
fn parse_refine_schema(
    file: FileId,
    node: &KdlNode,
) -> ParseResult<crate::lang::value::RefineSchema> {
    let span = node_span(file, node);
    let raw_base = req_str_prop(file, node, "base")?;
    let base = parse_type_expression(file, node, &raw_base)?;
    let mut min: Option<NumericBound> = None;
    let mut max: Option<NumericBound> = None;
    if let Some(entry) = prop_entry(node, "min") {
        min = Some(parse_numeric_property(file, entry, node, "min")?);
    }
    if let Some(entry) = prop_entry(node, "max") {
        max = Some(parse_numeric_property(file, entry, node, "max")?);
    }
    let format = opt_str_prop(file, node, "format")?;
    let unit = opt_str_prop(file, node, "unit")?;

    if base.is_optional() {
        return Err(
            at_node(file, node).error(codes::NODE_SHAPE, "refine `base=` must not be optional")
        );
    }
    if min
        .zip(max)
        .is_some_and(|(minimum, maximum)| minimum.compare(maximum).is_gt())
    {
        return Err(at_node(file, node).error(
            codes::NODE_SHAPE,
            "refine `min=` must not be greater than `max=`",
        ));
    }

    let operational_base = base.operational_type();
    if unit.is_some() && !matches!(operational_base, Type::Int | Type::Float) {
        return Err(at_node(file, node).error(
            codes::NODE_SHAPE,
            "refine `unit=` is only allowed with an `int` or `float` base",
        ));
    }

    match operational_base {
        Type::Bool => {
            if min.is_some() || max.is_some() {
                return Err(at_node(file, node).error(
                    codes::NODE_SHAPE,
                    "refine `min=`/`max=` are not allowed with a `bool` base",
                ));
            }
            if format.is_some() {
                return Err(at_node(file, node).error(
                    codes::NODE_SHAPE,
                    "refine `format=` is not allowed with a `bool` base",
                ));
            }
        }
        Type::Int | Type::Float => {
            if format.is_some() {
                return Err(at_node(file, node).error(
                    codes::NODE_SHAPE,
                    "refine `format=` is only allowed with a `string` base",
                ));
            }
        }
        Type::String => {
            if min.is_some() || max.is_some() {
                return Err(at_node(file, node).error(
                    codes::NODE_SHAPE,
                    "refine `min=`/`max=` for a `string` base are not implemented; use `format=` instead",
                ));
            }
            if let Some(format) = &format
                && !matches!(
                    format.as_str(),
                    "desktop-file-id"
                        | "identifier"
                        | "mime-type"
                        | "srgb-color"
                        | "shell-command"
                        | "target-path"
                )
            {
                return Err(at_node(file, node).error(
                    codes::NODE_SHAPE,
                    format!(
                        "refine `format=\"{format}\"` is not one of: desktop-file-id, identifier, mime-type, srgb-color, shell-command, target-path"
                    ),
                ));
            }
        }
        Type::Path => {
            if min.is_some() || max.is_some() {
                return Err(at_node(file, node).error(
                    codes::NODE_SHAPE,
                    "refine `min=`/`max=` are not allowed with a `path` base",
                ));
            }
            if format.is_some() {
                return Err(at_node(file, node).error(
                    codes::NODE_SHAPE,
                    "refine `format=` is not allowed with a `path` base",
                ));
            }
        }
        Type::List(item) if matches!(item.operational_type(), Type::String) => {
            if format.is_some() {
                return Err(at_node(file, node).error(
                    codes::NODE_SHAPE,
                    "refine `format=` is not allowed with a `list<string>` base",
                ));
            }
        }
        Type::List(_) => {
            return Err(at_node(file, node).error(
                codes::NODE_SHAPE,
                "refine `base=\"list<…>\"` only accepts `list<string>` items",
            ));
        }
        other => {
            return Err(at_node(file, node).error(
                codes::NODE_SHAPE,
                format!(
                    "refine `base=` must be a scalar (bool, int, float, string, path) or `list<string>`, got `{other}`"
                ),
            ));
        }
    }

    Ok(crate::lang::value::RefineSchema {
        name: req_str_arg(file, node)?,
        base: Box::new(base),
        min,
        max,
        format,
        unit,
        span,
    })
}

/// Parse a `min=`/`max=` KDL property without rounding integer bounds.
fn parse_numeric_property(
    file: FileId,
    entry: &kdl::KdlEntry,
    node: &KdlNode,
    prop: &str,
) -> ParseResult<NumericBound> {
    match entry.value() {
        kdl::KdlValue::Integer(i) => i64::try_from(*i).map(NumericBound::Int).map_err(|_| {
            at_entry(file, entry).error(
                codes::NODE_SHAPE,
                format!(
                    "`{}`: property `{prop}=` is out of range for a 64-bit integer",
                    node.name().value()
                ),
            )
        }),
        kdl::KdlValue::Float(x) if x.is_finite() => Ok(NumericBound::Float(*x)),
        kdl::KdlValue::Float(_) => Err(at_entry(file, entry).error(
            codes::NODE_SHAPE,
            format!(
                "`{}`: property `{prop}=` must not be a non-finite float",
                node.name().value()
            ),
        )),
        _ => Err(at_entry(file, entry).error(
            codes::NODE_SHAPE,
            format!(
                "`{}`: property `{prop}=` must be an integer or float",
                node.name().value()
            ),
        )),
    }
}

fn parse_collection_defaults(file: FileId, node: &KdlNode) -> ParseResult<Value> {
    reject_unknown_props(file, node, &[])?;
    expect_args(file, node, 0)?;
    reject_unknown_children(file, node, &["item"])?;
    let mut collection = crate::lang::value::KeyedCollection::default();
    let mut keys = HashSet::new();
    if let Some(children) = node.children() {
        for child in children.nodes() {
            let span = node_span(file, child);
            let (key, value) = parse_collection_item(file, child)?;
            validate_collection_document(file, &value, span, "collection default")?;
            if !keys.insert(key.clone()) {
                return Err(Diagnostic::error(
                    codes::DUPLICATE,
                    format!("duplicate collection default key `{key}`"),
                )
                .with_span(span));
            }
            collection
                .items
                .push(crate::lang::value::CollectionItem { key, value, span });
        }
    }
    Ok(Value::Collection(collection))
}

/// Parses one collection item: `item "key" { ...kdl... }` for kdl-document (or
/// record field-node) payloads, `item "key" "value"` for string payloads,
/// `item "key" field=value ...` for compact record payloads. The declared
/// item type disambiguates during type-checking.
fn parse_collection_item(file: FileId, node: &KdlNode) -> ParseResult<(String, Value)> {
    let args: Vec<&kdl::KdlEntry> = node.iter().filter(|e| e.name().is_none()).collect();
    let props: Vec<&kdl::KdlEntry> = node.iter().filter(|e| e.name().is_some()).collect();
    let span = node_span(file, node);
    let key = parse_collection_key(file, node, args.first().copied())?;
    if !props.is_empty() {
        if args.len() != 1 {
            return Err(Diagnostic::error(
                codes::NODE_SHAPE,
                format!(
                    "`{}` with field properties takes only the key argument",
                    node.name().value()
                ),
            )
            .with_span(span));
        }
        return Ok((
            key,
            Value::RawRecordLiteral(parse_raw_record_literal(file, node)?),
        ));
    }
    match (
        args.len(),
        node.children().is_some_and(|c| !c.nodes().is_empty()),
    ) {
        (1, _) => Ok((
            key,
            Value::KdlDocument(node.children().cloned().unwrap_or_default()),
        )),
        (2, false) => Ok((key, scalar_value(file, args[1])?)),
        (3.., false) => {
            let values = args
                .iter()
                .skip(1)
                .map(|entry| scalar_value(file, entry))
                .collect::<ParseResult<Vec<_>>>()?;
            Ok((key, Value::List(values)))
        }
        _ => Err(Diagnostic::error(
            codes::NODE_SHAPE,
            format!(
                "`{}` takes a key plus either one scalar value or a children block",
                node.name().value()
            ),
        )
        .with_span(span)),
    }
}

fn parse_collection_key(
    file: FileId,
    node: &KdlNode,
    entry: Option<&kdl::KdlEntry>,
) -> ParseResult<String> {
    entry
        .filter(|entry| entry.ty().is_none())
        .and_then(|entry| entry.value().as_string())
        .filter(|key| !key.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| {
            Diagnostic::error(
                codes::NODE_SHAPE,
                format!(
                    "`{}` requires a plain, non-empty string key argument",
                    node.name().value()
                ),
            )
            .with_span(node_span(file, node))
        })
}

fn validate_collection_document(
    file: FileId,
    value: &Value,
    _span: Span,
    context: &str,
) -> ParseResult<()> {
    if let Value::KdlDocument(document) = value {
        validate_structural_kdl_document(file, document.nodes())
            .map_err(|diagnostic| diagnostic.with_note(format!("while validating {context}")))?;
    }
    Ok(())
}

fn parse_fragments(file: FileId, dir: &Path, node: &KdlNode) -> ParseResult<Vec<FragmentDecl>> {
    reject_unknown_props(file, node, &[])?;
    expect_args(file, node, 0)?;
    reject_unknown_children(file, node, &["fragment"])?;
    let mut out: Vec<FragmentDecl> = Vec::new();
    if let Some(children) = node.children() {
        for child in children.nodes() {
            reject_unknown_props(file, child, &["format", "cardinality"])?;
            reject_unknown_children(file, child, &["default"])?;
            reject_duplicate_children(file, child, &["default"])?;
            let name = req_str_arg(file, child)?;
            let span = node_span(file, child);
            if out.iter().any(|f| f.name == name) {
                return Err(Diagnostic::error(
                    codes::DUPLICATE,
                    format!("duplicate fragment `{name}`"),
                )
                .with_span(span));
            }
            let cardinality = match opt_str_prop(file, child, "cardinality")?.as_deref() {
                None | Some("one") => FragmentCardinality::One,
                Some("many") => FragmentCardinality::Many,
                Some(other) => {
                    return Err(Diagnostic::error(
                        codes::NODE_SHAPE,
                        format!("fragment cardinality `{other}` (allowed: one, many)"),
                    )
                    .with_span(span));
                }
            };
            let mut defaults = Vec::new();
            if let Some(default_node) = opt_child(child, "default") {
                for entry in default_node.iter().filter(|e| e.name().is_none()) {
                    let Some(path) = entry.value().as_string() else {
                        return Err(at_entry(file, entry)
                            .error(codes::NODE_SHAPE, "fragment defaults must be string paths"));
                    };
                    defaults.push(FragmentSource {
                        path: path.to_owned(),
                        base_dir: dir.to_path_buf(),
                        span: entry_span(file, entry),
                    });
                }
            }
            if cardinality == FragmentCardinality::One && defaults.len() > 1 {
                return Err(Diagnostic::error(
                    codes::NODE_SHAPE,
                    format!(
                        "fragment `{name}` has cardinality \"one\" but {} defaults",
                        defaults.len()
                    ),
                )
                .with_span(span));
            }
            let format = req_str_prop(file, child, "format")?;
            if !crate::lang::artifact::format_known(&format) {
                return Err(Diagnostic::error(
                    codes::FRAGMENT,
                    format!("fragment `{name}` declares unknown format `{format}`"),
                )
                .with_span(span)
                .with_help(crate::lang::artifact::known_formats_help()));
            }
            out.push(FragmentDecl {
                name,
                format,
                cardinality,
                defaults,
                span,
                dir: dir.to_path_buf(),
            });
        }
    }
    Ok(out)
}

fn parse_outputs(file: FileId, dir: &Path, node: &KdlNode) -> ParseResult<Vec<OutputNode>> {
    reject_unknown_props(file, node, &[])?;
    expect_args(file, node, 0)?;
    parse_output_nodes(file, dir, child_nodes(node))
}

fn parse_output_nodes(file: FileId, dir: &Path, nodes: &[KdlNode]) -> ParseResult<Vec<OutputNode>> {
    let mut out = Vec::new();
    let mut nodes = nodes.iter().peekable();
    while let Some(node) = nodes.next() {
        match node.name().value() {
            name if is_condition_name(name) => {
                let otherwise = if nodes
                    .peek()
                    .is_some_and(|next| next.name().value() == "@else")
                {
                    Some(nodes.next().expect("peeked"))
                } else {
                    None
                };
                out.push(OutputNode::When(parse_when(
                    file,
                    node,
                    otherwise,
                    &mut |children| parse_output_nodes(file, dir, children),
                )?));
            }
            "@else" => return Err(orphan_else(file, node)),
            "@for-each" => {
                let span = node_span(file, node);
                let (binding, source) = parse_each_header(file, node)?;
                out.push(OutputNode::Each(EachBlock {
                    binding,
                    source,
                    body: parse_output_nodes(file, dir, child_nodes(node))?,
                    span,
                }));
            }
            "@for-range" => {
                let span = node_span(file, node);
                let (binding, from, through) = parse_range_header(file, node)?;
                out.push(OutputNode::Range(RangeBlock {
                    binding,
                    from,
                    through,
                    body: parse_output_nodes(file, dir, child_nodes(node))?,
                    span,
                }));
            }
            _ => out.push(parse_output_node(file, dir, node)?),
        }
    }
    Ok(out)
}

fn parse_output_node(file: FileId, dir: &Path, node: &KdlNode) -> ParseResult<OutputNode> {
    match node.name().value() {
        "text-file" => Err(at_node(file, node).error(codes::UNKNOWN_NODE,
            "`text-file` was removed; use `render \"<path>\" format=\"text\"` with `@raw-text`, `@line`, or `@include-file` parts")),
        "kdl-file" => Err(at_node(file, node).error(codes::UNKNOWN_NODE,
            "`kdl-file` was removed; use `render \"<path>\" format=\"kdl\" version=1|2 { ... }`")),
        "config-file" => Err(at_node(file, node).error(codes::UNKNOWN_NODE,
            "`config-file` was removed; use `render \"<path>\" format=\"<format>\"`")),
        "render" => crate::lang::render::parse_render(file, dir, node),
        "file" => Ok(OutputNode::File(parse_file_output(file, dir, node)?)),
        "dir" => Ok(OutputNode::Dir(parse_dir_output(file, dir, node)?)),
        "symlink" => Ok(OutputNode::Symlink(parse_symlink_output(file, node)?)),
        other => {
            if let Some(diagnostic) = removed_control(file, node) {
                return Err(diagnostic);
            }
            Err(at_node(file, node).error(codes::UNKNOWN_NODE,
                format!(
                    "unknown output node `{other}` (allowed: render, file, dir, symlink, @if, @if-present, @if-nonempty, @for-each, @for-range)"
                )))
        }
    }
}

/// Parse a condition and its optional immediately following `@else` sibling.
fn parse_when<T>(
    file: FileId,
    node: &KdlNode,
    otherwise: Option<&KdlNode>,
    parse_children: &mut dyn FnMut(&[KdlNode]) -> ParseResult<Vec<T>>,
) -> ParseResult<WhenBlock<T>> {
    let span = node_span(file, node);
    let predicate = parse_condition(file, node)?;
    let then = parse_children(child_nodes(node))?;
    let otherwise = otherwise
        .map(|node| {
            validate_else(file, node)?;
            parse_children(child_nodes(node))
        })
        .transpose()?
        .unwrap_or_default();
    Ok(WhenBlock {
        predicate,
        then,
        otherwise,
        span,
    })
}

fn orphan_else(file: FileId, node: &KdlNode) -> Diagnostic {
    at_node(file, node).error(
        codes::NODE_SHAPE,
        "`@else` must immediately follow an `@if`, `@if-present`, or `@if-nonempty` sibling",
    )
}

pub(crate) fn validate_structural_kdl_document(file: FileId, nodes: &[KdlNode]) -> ParseResult<()> {
    validate_document_depth(file, nodes)?;
    validate_structural_kdl_nodes(file, nodes)
}

pub(crate) fn validate_structural_kdl_nodes(file: FileId, nodes: &[KdlNode]) -> ParseResult<()> {
    let mut nodes = nodes.iter().peekable();
    while let Some(node) = nodes.next() {
        match node.name().value() {
            "@if" | "@if-present" | "@if-nonempty" => {
                parse_condition(file, node)?;
                validate_structural_kdl_nodes(file, child_nodes(node))?;
                if nodes
                    .peek()
                    .is_some_and(|next| next.name().value() == "@else")
                {
                    let otherwise = nodes.next().expect("peeked");
                    validate_else(file, otherwise)?;
                    validate_structural_kdl_nodes(file, child_nodes(otherwise))?;
                }
            }
            "@for-each" => {
                parse_each_header(file, node)?;
                if let Some(children) = node.children() {
                    validate_structural_kdl_nodes(file, children.nodes())?;
                }
            }
            "@for-range" => {
                parse_range_header(file, node)?;
                if let Some(children) = node.children() {
                    validate_structural_kdl_nodes(file, children.nodes())?;
                }
            }
            "@insert-documents" => {
                parse_splice(file, node)?;
            }
            "@include-fragment" => {
                expect_args(file, node, 0)?;
                reject_unknown_props(file, node, &["fragment"])?;
                reject_unknown_children(file, node, &[])?;
                let _ = req_str_prop(file, node, "fragment")?;
            }
            "@else" => return Err(orphan_else(file, node)),
            "node" => {
                validate_escaped_kdl_node(file, node)?;
                if let Some(children) = node.children() {
                    validate_structural_kdl_nodes(file, children.nodes())?;
                }
            }
            name if name.starts_with('@') => {
                if let Some(diagnostic) = removed_control(file, node) {
                    return Err(diagnostic);
                }
                validate_plain_kdl_node(file, node)?;
            }
            _ => {
                validate_plain_kdl_node(file, node)?;
            }
        }
    }
    Ok(())
}

fn validate_plain_kdl_node(file: FileId, node: &KdlNode) -> ParseResult<()> {
    validate_plain_kdl_entries(file, node, node.name().value(), None)?;
    if let Some(children) = node.children() {
        validate_structural_kdl_nodes(file, children.nodes())?;
    }
    Ok(())
}

fn validate_plain_kdl_entries(
    file: FileId,
    node: &KdlNode,
    target_name: &str,
    skipped_entry: Option<usize>,
) -> ParseResult<()> {
    let mut properties = HashSet::new();
    for (index, entry) in node.iter().enumerate() {
        if skipped_entry == Some(index) {
            continue;
        }
        if let Some(name) = entry.name()
            && !properties.insert(name.value())
        {
            return Err(at_entry(file, entry).error(
                codes::DUPLICATE,
                format!(
                    "node `{}` sets property `{}` twice",
                    target_name,
                    name.value()
                ),
            ));
        }
        if crate::lang::kdl_util::is_ref(entry) {
            parse_ref(file, entry)?;
        }
    }
    Ok(())
}

fn validate_escaped_kdl_node(file: FileId, node: &KdlNode) -> ParseResult<()> {
    let Some((target_index, entry)) = crate::lang::kdl_util::escaped_node_target(node) else {
        return Err(at_node(file, node).error(
            codes::NODE_SHAPE,
            "`node` requires a literal target node name",
        ));
    };
    if entry.ty().is_some() || entry.value().as_string().is_none_or(|name| name.is_empty()) {
        return Err(at_entry(file, entry).error(
            codes::NODE_SHAPE,
            "`node` target name must be a non-empty literal string",
        ));
    }
    validate_plain_kdl_entries(
        file,
        node,
        entry.value().as_string().expect("target name checked"),
        Some(target_index),
    )
}

fn parse_file_output(file: FileId, dir: &Path, node: &KdlNode) -> ParseResult<FileOutput> {
    reject_unknown_props(file, node, &["to", "optional", "executable", "on-conflict"])?;
    reject_unknown_children(file, node, &[])?;
    Ok(FileOutput {
        source: req_str_arg(file, node)?,
        to: req_str_prop(file, node, "to")?,
        optional: bool_prop(file, node, "optional")?,
        executable: bool_prop(file, node, "executable")?,
        on_conflict: parse_conflict(file, node)?,
        span: node_span(file, node),
        dir: dir.to_path_buf(),
    })
}

fn parse_dir_output(file: FileId, dir: &Path, node: &KdlNode) -> ParseResult<DirOutput> {
    reject_unknown_props(file, node, &["to", "optional", "executable", "on-conflict"])?;
    reject_unknown_children(file, node, &["ignore"])?;
    let mut ignore = Vec::new();
    if let Some(children) = node.children() {
        for child in children.nodes() {
            if child.name().value() == "ignore" {
                reject_unknown_props(file, child, &[])?;
                reject_unknown_children(file, child, &[])?;
                for entry in child.iter().filter(|e| e.name().is_none()) {
                    let Some(pattern) = entry.value().as_string() else {
                        return Err(at_entry(file, entry)
                            .error(codes::NODE_SHAPE, "`ignore` expects string glob patterns"));
                    };
                    ignore.push(pattern.to_owned());
                }
            }
        }
    }
    Ok(DirOutput {
        source: req_str_arg(file, node)?,
        to: opt_str_prop(file, node, "to")?,
        optional: bool_prop(file, node, "optional")?,
        executable: bool_prop(file, node, "executable")?,
        on_conflict: parse_conflict(file, node)?,
        ignore,
        span: node_span(file, node),
        dir: dir.to_path_buf(),
    })
}

fn parse_symlink_output(file: FileId, node: &KdlNode) -> ParseResult<SymlinkOutput> {
    reject_unknown_props(file, node, &["to", "optional", "if-missing", "source"])?;
    reject_unknown_children(file, node, &[])?;
    let if_missing = match opt_str_prop(file, node, "if-missing")?.as_deref() {
        None | Some("must-exist") => MissingSourcePolicy::RequireSource,
        Some("allow") => MissingSourcePolicy::AllowMissingUntilRendered,
        Some(other) => {
            return Err(at_node(file, node).error(
                codes::NODE_SHAPE,
                format!("symlink if-missing `{other}` (allowed: must-exist, allow)"),
            ));
        }
    };
    let source = if let Some(entry) = prop_entry(node, "source") {
        expect_args(file, node, 0)?;
        SymlinkSource::Ref(parse_ref(file, entry)?)
    } else {
        SymlinkSource::Literal(req_str_arg(file, node)?)
    };
    Ok(SymlinkOutput {
        source,
        to: req_str_prop(file, node, "to")?,
        optional: bool_prop(file, node, "optional")?,
        if_missing,
        span: node_span(file, node),
    })
}

fn parse_conflict(file: FileId, node: &KdlNode) -> ParseResult<ConflictPolicy> {
    match opt_str_prop(file, node, "on-conflict")?.as_deref() {
        None | Some("backup") => Ok(ConflictPolicy::Backup),
        Some("fail") => Ok(ConflictPolicy::Fail),
        Some(other) => Err(at_node(file, node).error(
            codes::NODE_SHAPE,
            format!("on-conflict `{other}` (allowed: fail, backup)"),
        )),
    }
}

pub(crate) fn parse_slots(file: FileId, node: &KdlNode) -> ParseResult<Vec<SlotDecl>> {
    reject_unknown_props(file, node, &[])?;
    expect_args(file, node, 0)?;
    reject_unknown_children(file, node, &["slot"])?;
    let mut out: Vec<SlotDecl> = Vec::new();
    if let Some(children) = node.children() {
        for child in children.nodes() {
            reject_unknown_props(file, child, &["max", "description"])?;
            reject_unknown_children(file, child, &[])?;
            let name = req_str_arg(file, child)?;
            let span = node_span(file, child);
            if out.iter().any(|slot| slot.name == name) {
                return Err(Diagnostic::error(
                    codes::DUPLICATE,
                    format!("duplicate slot `{name}`"),
                )
                .with_span(span));
            }
            let max = match child.get("max") {
                None => SlotMax::Max(1),
                Some(value) => {
                    if let Some(n) = value.as_integer() {
                        let n = usize::try_from(n).ok().filter(|n| *n >= 1).ok_or_else(|| {
                            Diagnostic::error(
                                codes::NODE_SHAPE,
                                "slot `max` must be a positive integer or \"many\"",
                            )
                            .with_span(span)
                        })?;
                        SlotMax::Max(n)
                    } else if value.as_string() == Some("many") {
                        SlotMax::Unlimited
                    } else {
                        return Err(Diagnostic::error(
                            codes::NODE_SHAPE,
                            "slot `max` must be a positive integer or \"many\"",
                        )
                        .with_span(span));
                    }
                }
            };
            out.push(SlotDecl {
                name,
                max,
                description: opt_str_prop(file, child, "description")?,
                span,
            });
        }
    }
    Ok(out)
}

pub(crate) fn parse_profile(file: FileId, dir: &Path, node: &KdlNode) -> ParseResult<ProfileDecl> {
    let name = req_str_arg(file, node)?;
    reject_unknown_props(file, node, &["abstract"])?;
    reject_unknown_children(file, node, &["extends", "use", "replace"])?;

    let mut profile = ProfileDecl {
        name,
        abstract_: bool_prop(file, node, "abstract")?,
        extends: Vec::new(),
        items: Vec::new(),
        span: node_span(file, node),
        dir: dir.to_path_buf(),
    };
    if let Some(children) = node.children() {
        for child in children.nodes() {
            match child.name().value() {
                "extends" => {
                    reject_unknown_props(file, child, &[])?;
                    reject_unknown_children(file, child, &[])?;
                    for entry in child.iter().filter(|e| e.name().is_none()) {
                        let Some(parent) = entry.value().as_string() else {
                            return Err(at_entry(file, entry).error(
                                codes::NODE_SHAPE,
                                "`extends` expects profile names as string arguments",
                            ));
                        };
                        profile
                            .extends
                            .push((parent.to_owned(), entry_span(file, entry)));
                    }
                }
                "use" => {
                    reject_unknown_props(file, child, &["as"])?;
                    profile.items.push(ProfileItem::Use(UseDecl {
                        module: req_str_arg(file, child)?,
                        alias: opt_str_prop(file, child, "as")?,
                        config: parse_instance_config(file, dir, child)?,
                        span: node_span(file, child),
                    }));
                }
                "replace" => {
                    reject_unknown_props(file, child, &["slot", "module", "as"])?;
                    expect_args(file, child, 0)?;
                    profile.items.push(ProfileItem::Replace(ReplaceDecl {
                        slot: req_str_prop(file, child, "slot")?,
                        module: req_str_prop(file, child, "module")?,
                        alias: opt_str_prop(file, child, "as")?,
                        config: parse_instance_config(file, dir, child)?,
                        span: node_span(file, child),
                    }));
                }
                _ => unreachable!("validated above"),
            }
        }
    }
    Ok(profile)
}

pub(crate) fn parse_extend_profile(
    file: FileId,
    dir: &Path,
    node: &KdlNode,
) -> ParseResult<ExtendProfile> {
    let profile = parse_profile(file, dir, node)?;
    if profile.abstract_ {
        return Err(Diagnostic::error(
            codes::NODE_SHAPE,
            "`abstract=` is only valid on a profile declaration, not `extend-profile`",
        )
        .with_span(profile.span));
    }
    Ok(ExtendProfile {
        profile: profile.name,
        extends: profile.extends,
        items: profile.items,
        span: profile.span,
    })
}

fn parse_instance_config(file: FileId, dir: &Path, node: &KdlNode) -> ParseResult<InstanceConfig> {
    reject_unknown_children(file, node, &["with", "fragments", "patch"])?;
    reject_duplicate_children(file, node, &["with", "fragments", "patch"])?;
    let mut config = InstanceConfig::default();
    if let Some(with_node) = opt_child(node, "with") {
        config.with = parse_with(file, with_node)?;
    }
    if let Some(fragments_node) = opt_child(node, "fragments") {
        config.fragments = parse_fragment_ops(file, dir, fragments_node)?;
    }
    if let Some(patch_node) = opt_child(node, "patch") {
        config.patch_entries = parse_patches(file, patch_node)?;
    }
    Ok(config)
}

fn parse_with(file: FileId, node: &KdlNode) -> ParseResult<Vec<WithEntry>> {
    reject_unknown_props(file, node, &[])?;
    expect_args(file, node, 0)?;
    let mut out: Vec<WithEntry> = Vec::new();
    let mut seen = HashSet::new();
    let Some(children) = node.children() else {
        return Ok(out);
    };
    for child in children.nodes() {
        let name = child.name().value().to_owned();
        let span = node_span(file, child);
        if name.is_empty() {
            return Err(Diagnostic::error(
                codes::NODE_SHAPE,
                "`with` contains an empty input name",
            )
            .with_span(span));
        }
        if !seen.insert(name.clone()) {
            return Err(Diagnostic::error(
                codes::DUPLICATE,
                format!("`with` sets input `{name}` twice"),
            )
            .with_span(span));
        }
        let value = parse_generic_value(file, child)?;
        out.push(WithEntry { name, value, span });
    }
    Ok(out)
}

/// Parse a profile-supplied value without knowing the input's declared type
/// yet: scalars and lists directly; a children block becomes a
/// `Value::KdlDocument` that type-checking converts to a record (or keeps
/// as a document) against the declared input type.
fn parse_generic_value(file: FileId, node: &KdlNode) -> ParseResult<Value> {
    if let Some(annotation) = node.ty().map(|ty| ty.value()) {
        let span = node_span(file, node);
        if !matches!(annotation, "list" | "record" | "collection") {
            return Err(Diagnostic::error(
                codes::NODE_SHAPE,
                format!(
                    "unknown `with` aggregate annotation `({annotation})` (allowed: list, record, collection)"
                ),
            )
            .with_span(span));
        }
        let has_entries = node.iter().next().is_some();
        let has_children = node
            .children()
            .is_some_and(|children| !children.nodes().is_empty());
        if has_entries || has_children {
            return Err(Diagnostic::error(
                codes::NODE_SHAPE,
                format!("`({annotation})` is an explicit empty aggregate constructor"),
            )
            .with_span(span));
        }
        let has_block = node.children().is_some();
        if annotation == "list" && has_block {
            return Err(Diagnostic::error(
                codes::NODE_SHAPE,
                "`(list)` uses `(list)name` without a children block",
            )
            .with_span(span));
        }
        if matches!(annotation, "record" | "collection") && !has_block {
            return Err(Diagnostic::error(
                codes::NODE_SHAPE,
                format!("`({annotation})` requires an explicit empty children block"),
            )
            .with_span(span));
        }
        return Ok(match annotation {
            "list" => Value::List(Vec::new()),
            "record" => Value::Record(crate::lang::value::Record::new()),
            "collection" => Value::Collection(crate::lang::value::KeyedCollection::default()),
            _ => unreachable!("checked above"),
        });
    }
    let args: Vec<&kdl::KdlEntry> = node.iter().filter(|e| e.name().is_none()).collect();
    let has_props = node.iter().any(|entry| entry.name().is_some());
    let has_children = node.children().is_some_and(|c| !c.nodes().is_empty());
    match (args.len(), has_props, has_children) {
        (0, true, _) => Ok(Value::RawRecordLiteral(parse_raw_record_literal(
            file, node,
        )?)),
        (0, false, true) => Ok(Value::KdlDocument(
            node.children().cloned().unwrap_or_default(),
        )),
        (0, false, false) => Err(at_node(file, node).error(
            codes::NODE_SHAPE,
            format!("input `{}` needs a value", node.name().value()),
        )),
        (1, false, false) => scalar_value(file, args[0]),
        (_, false, false) => {
            let mut items = Vec::with_capacity(args.len());
            for arg in args {
                let value = scalar_value(file, arg)?;
                items.push(value);
            }
            Ok(Value::List(items))
        }
        (_, _, _) => Err(at_node(file, node).error(
            codes::NODE_SHAPE,
            format!(
                "input `{}` mixes arguments with field properties or a children block",
                node.name().value()
            ),
        )),
    }
}

fn parse_raw_record_literal(file: FileId, node: &KdlNode) -> ParseResult<RawRecordLiteral> {
    let mut properties = Vec::new();
    for entry in node.iter().filter(|entry| entry.name().is_some()) {
        properties.push(RawRecordProperty {
            name: entry.name().expect("property filtered").value().to_owned(),
            value: scalar_value(file, entry)?,
            span: entry_span(file, entry),
        });
    }
    Ok(RawRecordLiteral {
        properties,
        children: node.children().cloned().unwrap_or_default(),
    })
}

fn parse_fragment_ops(file: FileId, dir: &Path, node: &KdlNode) -> ParseResult<Vec<FragmentOp>> {
    reject_unknown_props(file, node, &[])?;
    expect_args(file, node, 0)?;
    reject_unknown_children(file, node, &["replace", "append"])?;
    let mut out = Vec::new();
    let Some(children) = node.children() else {
        return Ok(out);
    };
    for child in children.nodes() {
        reject_unknown_props(file, child, &["source"])?;
        reject_unknown_children(file, child, &[])?;
        let fragment = req_str_arg(file, child)?;
        let span = node_span(file, child);
        let source_entry = prop_entry(child, "source").ok_or_else(|| {
            Diagnostic::error(
                codes::NODE_SHAPE,
                format!("fragment `{fragment}` operation requires `source=\"…\"`"),
            )
            .with_span(span)
        })?;
        let body = FragmentOpBody {
            fragment,
            source: FragmentSource {
                path: req_str_prop(file, child, "source")?,
                base_dir: dir.to_path_buf(),
                span: entry_span(file, source_entry),
            },
            span,
        };
        match child.name().value() {
            "replace" => out.push(FragmentOp::Replace(body)),
            "append" => out.push(FragmentOp::Append(body)),
            _ => unreachable!("validated above"),
        }
    }
    Ok(out)
}

fn parse_patches(file: FileId, node: &KdlNode) -> ParseResult<Vec<PatchEntry>> {
    reject_unknown_props(file, node, &[])?;
    expect_args(file, node, 0)?;
    reject_unknown_children(file, node, &["collection", "set", "unset"])?;
    let mut entries = Vec::new();
    let Some(children) = node.children() else {
        return Ok(entries);
    };
    for child in children.nodes() {
        if matches!(child.name().value(), "set" | "unset") {
            entries.push(PatchEntry::Field(parse_set_patch(file, child)?));
            continue;
        }
        reject_unknown_props(file, child, &[])?;
        let collection = req_str_arg(file, child)?;
        let span = node_span(file, child);
        let mut ops = Vec::new();
        if let Some(op_nodes) = child.children() {
            for op in op_nodes.nodes() {
                let op_span = node_span(file, op);
                match op.name().value() {
                    "replace" => {
                        let (key, value) = parse_collection_item(file, op)?;
                        validate_collection_document(
                            file,
                            &value,
                            op_span,
                            "collection patch replacement",
                        )?;
                        ops.push(PatchOp::Replace {
                            key,
                            value,
                            span: op_span,
                        });
                    }
                    "append" => {
                        let (key, value) = parse_collection_item(file, op)?;
                        validate_collection_document(
                            file,
                            &value,
                            op_span,
                            "collection patch append",
                        )?;
                        ops.push(PatchOp::Append {
                            key,
                            value,
                            span: op_span,
                        });
                    }
                    "remove" => {
                        reject_unknown_props(file, op, &["optional"])?;
                        reject_unknown_children(file, op, &[])?;
                        let args = op
                            .iter()
                            .filter(|entry| entry.name().is_none())
                            .collect::<Vec<_>>();
                        if args.len() != 1 {
                            return Err(Diagnostic::error(
                                codes::NODE_SHAPE,
                                "`remove` requires exactly one collection key",
                            )
                            .with_span(op_span));
                        }
                        ops.push(PatchOp::Remove {
                            key: parse_collection_key(file, op, args.first().copied())?,
                            optional: bool_prop(file, op, "optional")?,
                            span: op_span,
                        });
                    }
                    "replace-all" => {
                        reject_unknown_props(file, op, &[])?;
                        expect_args(file, op, 0)?;
                        reject_unknown_children(file, op, &["item"])?;
                        let mut items = Vec::new();
                        let mut keys = HashSet::new();
                        if let Some(item_nodes) = op.children() {
                            for item in item_nodes.nodes() {
                                let item_span = node_span(file, item);
                                let (key, value) = parse_collection_item(file, item)?;
                                validate_collection_document(
                                    file,
                                    &value,
                                    item_span,
                                    "collection replace-all item",
                                )?;
                                if !keys.insert(key.clone()) {
                                    return Err(Diagnostic::error(
                                        codes::DUPLICATE,
                                        format!("`replace-all` repeats key `{key}`"),
                                    )
                                    .with_span(item_span));
                                }
                                items.push((key, value, item_span));
                            }
                        }
                        ops.push(PatchOp::ReplaceAll {
                            items,
                            span: op_span,
                        });
                    }
                    other => {
                        return Err(Diagnostic::error(
                            codes::UNKNOWN_NODE,
                            format!(
                                "unknown patch operation `{other}` (allowed: replace, append, remove, replace-all)"
                            ),
                        )
                        .with_span(op_span));
                    }
                }
            }
        }
        entries.push(PatchEntry::Collection(CollectionPatch {
            collection,
            ops,
            span,
        }));
    }
    Ok(entries)
}

fn parse_set_patch(file: FileId, node: &KdlNode) -> ParseResult<crate::lang::ast::SetPatch> {
    let span = node_span(file, node);
    let unset = node.name().value() == "unset";
    reject_unknown_props(file, node, &[])?;
    reject_unknown_children(file, node, &[])?;
    let args: Vec<&kdl::KdlEntry> = node.iter().filter(|e| e.name().is_none()).collect();
    let Some(first) = args.first() else {
        return Err(Diagnostic::error(
            codes::NODE_SHAPE,
            format!("`{}` requires an `input.field` path", node.name().value()),
        )
        .with_span(span));
    };
    let path = first
        .value()
        .as_string()
        .filter(|path| {
            first.ty().is_none() && path.contains('.') && !path.split('.').any(|seg| seg.is_empty())
        })
        .ok_or_else(|| {
            at_entry(file, first).error(
                codes::NODE_SHAPE,
                format!(
                    "`{}` takes a dotted `input.field[.subfield...]` path",
                    node.name().value()
                ),
            )
        })?
        .to_owned();
    if unset {
        if args.len() != 1 {
            return Err(
                Diagnostic::error(codes::NODE_SHAPE, "`unset` takes only the field path")
                    .with_span(span),
            );
        }
        return Ok(crate::lang::ast::SetPatch {
            path,
            value: None,
            span,
        });
    }
    let mut values = Vec::new();
    for entry in args.iter().skip(1) {
        let value = scalar_value(file, entry)?;
        if value.is_null() {
            return Err(at_entry(file, entry)
                .error(codes::NODE_SHAPE, "use `unset` to clear an optional field"));
        }
        values.push(value);
    }
    let value = match values.len() {
        0 => {
            return Err(Diagnostic::error(
                codes::NODE_SHAPE,
                "`set` requires a value after the field path",
            )
            .with_span(span));
        }
        1 => values.into_iter().next().expect("one value"),
        _ => Value::List(values),
    };
    Ok(crate::lang::ast::SetPatch {
        path,
        value: Some(value),
        span,
    })
}

/// Parses a `variables { global.foo "value" ... }` block. Only `global.*` names
/// are allowed; module-scoped values are inputs.
pub(crate) fn parse_globals(
    file: FileId,
    node: &KdlNode,
    origin: &str,
) -> ParseResult<Vec<crate::lang::ast::GlobalVar>> {
    reject_unknown_props(file, node, &[])?;
    expect_args(file, node, 0)?;
    let mut out: Vec<crate::lang::ast::GlobalVar> = Vec::new();
    let Some(children) = node.children() else {
        return Ok(out);
    };
    for child in children.nodes() {
        let name = child.name().value().to_owned();
        let span = node_span(file, child);
        if !name.starts_with("global.") || name.len() <= "global.".len() {
            return Err(Diagnostic::error(
                codes::RESERVED_NAME,
                format!("variable `{name}` must live in the `global.` namespace"),
            )
            .with_span(span)
            .with_help("module-scoped values are typed inputs now; only global.* design tokens remain variables"));
        }
        if out.iter().any(|v| v.name == name) {
            return Err(Diagnostic::error(
                codes::DUPLICATE,
                format!("`variables` sets `{name}` twice"),
            )
            .with_span(span));
        }
        reject_unknown_props(file, child, &["override"])?;
        reject_unknown_children(file, child, &[])?;
        expect_args(file, child, 1)?;
        let entry = child
            .iter()
            .find(|e| e.name().is_none())
            .expect("argument count validated");
        let value = scalar_value(file, entry)?;
        if value.is_null() {
            return Err(Diagnostic::error(
                codes::NODE_SHAPE,
                format!("variable `{name}` must not be #null"),
            )
            .with_span(span));
        }
        out.push(crate::lang::ast::GlobalVar {
            name,
            value,
            override_existing: bool_prop(file, child, "override")?,
            span,
            origin: origin.to_owned(),
        });
    }
    Ok(out)
}

/// Parse a `document`-style KDL children block into a standalone document.
#[allow(dead_code)]
pub(crate) fn children_document(node: &KdlNode) -> KdlDocument {
    node.children().cloned().unwrap_or_default()
}
