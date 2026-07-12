//! Parses KDL declarations into the [`crate::lang::ast`] model and validates
//! their shape and cardinality.

use crate::lang::ast::{
    CollectionPatch, ConflictPolicy, DirOutput, EachBlock, ExtendModule, ExtendProfile, FileOutput,
    FragmentCardinality, FragmentDecl, FragmentOp, FragmentOpBody, FragmentSource, InputDecl,
    InstanceConfig, MissingSourcePolicy, ModuleDecl, OutputNode, PatchOp, ProfileDecl, ProfileItem,
    RangeBlock, ReplaceDecl, Requirement, RequirementKind, RequirementNode, SlotDecl, SlotMax,
    SymlinkOutput, SymlinkSource, UseDecl, WhenBlock, WithEntry,
};
use crate::lang::diag::{Diagnostic, FileId, Span, codes};
use crate::lang::kdl_util::{
    ParseResult, bool_prop, entry_span, expect_args, is_condition_name, node_span, opt_child,
    opt_str_prop, parse_condition, parse_each_header, parse_range_header, parse_ref, parse_splice,
    prop_entry, reject_duplicate_children, reject_unknown_children, reject_unknown_props,
    req_str_arg, req_str_prop, scalar_value,
};
use crate::lang::value::{FieldSchema, RecordSchema, Type, Value};
use kdl::{KdlDocument, KdlNode};
use std::collections::HashSet;
use std::path::Path;

/// Names a module may not use for inputs (reserved namespaces).
const RESERVED_PREFIXES: [&str; 5] = ["malm.", "machine.", "profile.", "instance.", "global."];

fn reserved_prefix(name: &str) -> Option<&'static str> {
    RESERVED_PREFIXES
        .iter()
        .copied()
        .find(|p| name.starts_with(p))
}

// Modules

pub(crate) fn parse_module(file: FileId, dir: &Path, node: &KdlNode) -> ParseResult<ModuleDecl> {
    let name = req_str_arg(file, node)?;
    reject_unknown_props(file, node, &[])?;
    reject_unknown_children(
        file,
        node,
        &[
            "description",
            "slot",
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
    let mut out = Vec::new();
    if let Some(children) = node.children() {
        for child in children.nodes() {
            out.push(parse_requirement_node(file, child)?);
        }
    }
    Ok(out)
}

fn parse_requirement_node(file: FileId, node: &KdlNode) -> ParseResult<RequirementNode> {
    if is_condition_name(node.name().value()) {
        return Ok(RequirementNode::When(parse_when(
            file,
            node,
            &mut |child| parse_requirement_node(file, child),
        )?));
    }
    let kind = match node.name().value() {
        "command" => RequirementKind::Command,
        "file" => RequirementKind::File,
        "feature" => RequirementKind::Feature,
        other => {
            return Err(Diagnostic::error(
                codes::UNKNOWN_NODE,
                format!(
                    "unknown requirement `{other}` (allowed: command, file, feature, when, when-set, when-nonempty)"
                ),
            )
            .with_span(node_span(file, node)));
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

// Inputs

fn parse_inputs(file: FileId, node: &KdlNode) -> ParseResult<Vec<InputDecl>> {
    reject_unknown_props(file, node, &[])?;
    expect_args(file, node, 0)?;
    reject_unknown_children(file, node, &["input"])?;
    let mut out: Vec<InputDecl> = Vec::new();
    if let Some(children) = node.children() {
        for child in children.nodes() {
            let input = parse_input(file, child)?;
            if out.iter().any(|existing| existing.name == input.name) {
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

    let optional = bool_prop(file, node, "optional")?;
    let ty_name = req_str_prop(file, node, "type")?;
    let base_ty = match ty_name.as_str() {
        "bool" => Type::Bool,
        "int" => Type::Int,
        "float" => Type::Float,
        "string" => Type::String,
        "path" => Type::Path,
        "enum" => Type::Enum(parse_enum_values(file, node)?),
        "list" => Type::List(Box::new(parse_item_type(file, node, "string")?)),
        "record" => Type::Record(parse_record_schema(file, node)?),
        "collection" => {
            let item =
                opt_str_prop(file, node, "item-type")?.unwrap_or_else(|| "kdl-document".to_owned());
            match item.as_str() {
                "kdl-document" => Type::Collection(Box::new(Type::KdlDocument)),
                "string" => Type::Collection(Box::new(Type::String)),
                "record" => {
                    Type::Collection(Box::new(Type::Record(parse_record_schema(file, node)?)))
                }
                other => {
                    return Err(Diagnostic::error(
                        codes::NODE_SHAPE,
                        format!(
                            "collection item-type `{other}` is not supported (allowed: kdl-document, string, record)"
                        ),
                    )
                    .with_span(span));
                }
            }
        }
        other => {
            return Err(Diagnostic::error(
                codes::NODE_SHAPE,
                format!(
                    "unknown input type `{other}` (allowed: bool, int, float, string, path, enum, list, record, collection)"
                ),
            )
            .with_span(span));
        }
    };
    validate_input_children(file, node, &base_ty)?;
    if matches!(
        base_ty,
        Type::Bool | Type::Int | Type::Float | Type::String | Type::Path | Type::Enum(_)
    ) && node.get("item-type").is_some()
    {
        return Err(Diagnostic::error(
            codes::NODE_SHAPE,
            "`item-type=` is only valid for list and collection inputs",
        )
        .with_span(span));
    }
    let ty = if optional {
        if matches!(base_ty, Type::List(_) | Type::Collection(_)) {
            return Err(Diagnostic::error(
                codes::NODE_SHAPE,
                "lists and collections cannot be optional; absence is the empty list/collection",
            )
            .with_span(span));
        }
        Type::Optional(Box::new(base_ty))
    } else {
        base_ty
    };

    let mut default: Option<Value> = None;
    let mut default_span: Option<Span> = None;

    if let Some(entry) = prop_entry(node, "default") {
        if matches!(
            ty.unwrap_optional(),
            Type::List(_) | Type::Record(_) | Type::Collection(_)
        ) {
            return Err(Diagnostic::error(
                codes::NODE_SHAPE,
                "aggregate inputs declare defaults with their typed child block",
            )
            .with_span(entry_span(file, entry)));
        }
        let value = scalar_value(file, entry)?;
        if value.is_null() {
            return Err(Diagnostic::error(
                codes::NODE_SHAPE,
                "`default=#null` is redundant — an optional without a default is already null",
            )
            .with_span(entry_span(file, entry)));
        }
        default = Some(value);
        default_span = Some(entry_span(file, entry));
    }

    if let Some(default_node) = opt_child(node, "default") {
        if default.is_some() {
            return Err(Diagnostic::error(
                codes::DUPLICATE,
                format!(
                    "input `{name}`: give the default either as a property or a child node, not both"
                ),
            )
            .with_span(node_span(file, default_node)));
        }
        match ty.unwrap_optional() {
            Type::List(item) if matches!(item.as_ref(), Type::Record(_)) => {
                reject_unknown_props(file, default_node, &[])?;
                expect_args(file, default_node, 0)?;
                let doc = default_node.children().cloned().unwrap_or_default();
                default = Some(Value::List(vec![Value::KdlDocument(doc)]));
            }
            Type::List(_) => {
                reject_unknown_props(file, default_node, &[])?;
                reject_unknown_children(file, default_node, &[])?;
                let mut items = Vec::new();
                for entry in default_node.iter().filter(|e| e.name().is_none()) {
                    items.push(scalar_value(file, entry)?);
                }
                default = Some(Value::List(items));
            }
            Type::Record(_) => {
                reject_unknown_props(file, default_node, &[])?;
                expect_args(file, default_node, 0)?;
                let doc = default_node.children().cloned().unwrap_or_default();
                default = Some(Value::KdlDocument(doc));
            }
            _ => {
                return Err(Diagnostic::error(
                    codes::NODE_SHAPE,
                    format!(
                        "input `{name}`: a `default` child node is only valid for list and record inputs"
                    ),
                )
                .with_span(node_span(file, default_node)));
            }
        }
        default_span = Some(node_span(file, default_node));
    }

    if let Some(defaults_node) = opt_child(node, "defaults") {
        default = Some(match ty.unwrap_optional() {
            Type::Collection(_) => parse_collection_defaults(file, defaults_node)?,
            Type::List(item) if matches!(item.as_ref(), Type::Record(_)) => {
                parse_record_list(file, defaults_node)?
            }
            _ => {
                return Err(Diagnostic::error(
                    codes::NODE_SHAPE,
                    format!("input `{name}`: `defaults` requires a collection or list<record>"),
                )
                .with_span(node_span(file, defaults_node)));
            }
        });
        default_span = Some(node_span(file, defaults_node));
    }

    // Lists and collections without a declared default are empty, never
    // required.
    if default.is_none() {
        match ty.unwrap_optional() {
            Type::List(_) => default = Some(Value::List(Vec::new())),
            Type::Collection(_) => {
                default = Some(Value::Collection(
                    crate::lang::value::KeyedCollection::default(),
                ));
            }
            _ => {}
        }
    }

    Ok(InputDecl {
        name,
        ty,
        default,
        span,
        default_span,
    })
}

fn parse_record_list(file: FileId, node: &KdlNode) -> ParseResult<Value> {
    reject_unknown_props(file, node, &[])?;
    expect_args(file, node, 0)?;
    reject_unknown_children(file, node, &["item"])?;
    let mut values = Vec::new();
    for item in node
        .children()
        .map(|children| children.nodes())
        .unwrap_or_default()
    {
        reject_unknown_props(file, item, &[])?;
        expect_args(file, item, 0)?;
        values.push(Value::KdlDocument(
            item.children().cloned().unwrap_or_default(),
        ));
    }
    Ok(Value::List(values))
}

fn parse_item_type(file: FileId, node: &KdlNode, fallback: &str) -> ParseResult<Type> {
    let name = opt_str_prop(file, node, "item-type")?.unwrap_or_else(|| fallback.to_owned());
    match name.as_str() {
        "bool" => Ok(Type::Bool),
        "int" => Ok(Type::Int),
        "float" => Ok(Type::Float),
        "string" => Ok(Type::String),
        "path" => Ok(Type::Path),
        "record" => Ok(Type::Record(parse_record_schema(file, node)?)),
        other => Err(Diagnostic::error(
            codes::NODE_SHAPE,
            format!("list item-type `{other}` is not supported (allowed: bool, int, float, string, path, record)"),
        )
        .with_span(node_span(file, node))),
    }
}

fn parse_enum_values(file: FileId, node: &KdlNode) -> ParseResult<Vec<String>> {
    let Some(values_node) = opt_child(node, "values") else {
        return Err(Diagnostic::error(
            codes::NODE_SHAPE,
            "an enum input requires a `values \"…\" \"…\"` child",
        )
        .with_span(node_span(file, node)));
    };
    reject_unknown_props(file, values_node, &[])?;
    reject_unknown_children(file, values_node, &[])?;
    let mut values = Vec::new();
    for entry in values_node.iter().filter(|entry| entry.name().is_none()) {
        let Some(value) = entry.value().as_string() else {
            return Err(
                Diagnostic::error(codes::NODE_SHAPE, "enum values must be strings")
                    .with_span(entry_span(file, entry)),
            );
        };
        if value.is_empty() {
            return Err(
                Diagnostic::error(codes::NODE_SHAPE, "enum values must not be empty")
                    .with_span(entry_span(file, entry)),
            );
        }
        if values.iter().any(|existing| existing == value) {
            return Err(Diagnostic::error(
                codes::DUPLICATE,
                format!("enum value `{value}` is declared twice"),
            )
            .with_span(entry_span(file, entry)));
        }
        values.push(value.to_owned());
    }
    if values.is_empty() {
        return Err(Diagnostic::error(
            codes::NODE_SHAPE,
            "an enum input must declare at least one value",
        )
        .with_span(node_span(file, values_node)));
    }
    Ok(values)
}

fn validate_input_children(file: FileId, node: &KdlNode, ty: &Type) -> ParseResult<()> {
    let allowed: &[&str] = match ty {
        Type::List(item) if matches!(item.as_ref(), Type::Record(_)) => {
            &["fields", "default", "defaults"]
        }
        Type::List(_) => &["default"],
        Type::Record(_) => &["fields", "default"],
        Type::Collection(item) if matches!(item.as_ref(), Type::Record(_)) => {
            &["fields", "defaults"]
        }
        Type::Collection(_) => &["defaults"],
        Type::Enum(_) => &["values"],
        _ => &[],
    };
    reject_unknown_children(file, node, allowed)
}

fn parse_record_schema(file: FileId, node: &KdlNode) -> ParseResult<RecordSchema> {
    let Some(fields_node) = opt_child(node, "fields") else {
        return Err(Diagnostic::error(
            codes::NODE_SHAPE,
            "a record input requires a `fields { … }` child",
        )
        .with_span(node_span(file, node)));
    };
    reject_unknown_props(file, fields_node, &[])?;
    expect_args(file, fields_node, 0)?;
    reject_unknown_children(file, fields_node, &["field"])?;
    let mut fields: Vec<FieldSchema> = Vec::new();
    if let Some(children) = fields_node.children() {
        for child in children.nodes() {
            reject_unknown_props(file, child, &["type", "required", "item-type"])?;
            reject_unknown_children(file, child, &[])?;
            let field_name = req_str_arg(file, child)?;
            if fields.iter().any(|f| f.name == field_name) {
                return Err(Diagnostic::error(
                    codes::DUPLICATE,
                    format!("duplicate record field `{field_name}`"),
                )
                .with_span(node_span(file, child)));
            }
            let ty = match req_str_prop(file, child, "type")?.as_str() {
                "bool" => Type::Bool,
                "int" => Type::Int,
                "float" => Type::Float,
                "string" => Type::String,
                "path" => Type::Path,
                "list" => Type::List(Box::new(parse_item_type(file, child, "string")?)),
                other => {
                    return Err(Diagnostic::error(
                        codes::NODE_SHAPE,
                        format!("record field type `{other}` is not supported (allowed: bool, int, float, string, path, list)"),
                    )
                    .with_span(node_span(file, child)));
                }
            };
            fields.push(FieldSchema {
                name: field_name,
                ty,
                required: bool_prop(file, child, "required")?,
                span: node_span(file, child),
            });
        }
    }
    if fields.is_empty() {
        return Err(Diagnostic::error(
            codes::NODE_SHAPE,
            "a record input must declare at least one field",
        )
        .with_span(node_span(file, node)));
    }
    Ok(RecordSchema { fields })
}

fn parse_collection_defaults(file: FileId, node: &KdlNode) -> ParseResult<Value> {
    reject_unknown_props(file, node, &[])?;
    expect_args(file, node, 0)?;
    reject_unknown_children(file, node, &["item"])?;
    let mut collection = crate::lang::value::KeyedCollection::default();
    if let Some(children) = node.children() {
        for child in children.nodes() {
            let span = node_span(file, child);
            let (key, value) = parse_collection_item(file, child)?;
            validate_collection_document(file, &value, span, "collection default")?;
            if collection.contains(&key) {
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

/// Parse one collection item: `item "key" { …kdl… }` for kdl-document (or
/// record field-node) payloads, `item "key" "value"` for string payloads,
/// `item "key" field=value …` for compact record payloads. The declared
/// item type disambiguates during type-checking.
fn parse_collection_item(file: FileId, node: &KdlNode) -> ParseResult<(String, Value)> {
    let args: Vec<&kdl::KdlEntry> = node.iter().filter(|e| e.name().is_none()).collect();
    let props: Vec<&kdl::KdlEntry> = node.iter().filter(|e| e.name().is_some()).collect();
    let span = node_span(file, node);
    let key = args
        .first()
        .and_then(|e| e.value().as_string())
        .map(str::to_owned)
        .ok_or_else(|| {
            Diagnostic::error(
                codes::NODE_SHAPE,
                format!("`{}` requires a string key argument", node.name().value()),
            )
            .with_span(span)
        })?;
    if !props.is_empty() {
        if args.len() != 1 || node.children().is_some_and(|c| !c.nodes().is_empty()) {
            return Err(Diagnostic::error(
                codes::NODE_SHAPE,
                format!(
                    "`{}` with field properties takes only the key argument and no children",
                    node.name().value()
                ),
            )
            .with_span(span));
        }
        let mut record = crate::lang::value::Record::new();
        for entry in props {
            let field = entry.name().expect("filtered on props").value().to_owned();
            let value = scalar_value(file, entry)?;
            if value.is_null() {
                return Err(Diagnostic::error(
                    codes::NODE_SHAPE,
                    format!("field `{field}`: #null is not a record field value"),
                )
                .with_span(entry_span(file, entry)));
            }
            if record.insert(field.clone(), value).is_some() {
                return Err(Diagnostic::error(
                    codes::DUPLICATE,
                    format!("field `{field}` is set twice"),
                )
                .with_span(entry_span(file, entry)));
            }
        }
        return Ok((key, Value::Record(record)));
    }
    match (
        args.len(),
        node.children().is_some_and(|c| !c.nodes().is_empty()),
    ) {
        (1, _) => Ok((
            key,
            Value::KdlDocument(node.children().cloned().unwrap_or_default()),
        )),
        (2, false) => {
            let value = scalar_value(file, args[1])?;
            if value.is_null() {
                return Err(Diagnostic::error(
                    codes::NODE_SHAPE,
                    "#null is not a collection item value",
                )
                .with_span(span));
            }
            Ok((key, value))
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

fn validate_collection_document(
    file: FileId,
    value: &Value,
    span: Span,
    context: &str,
) -> ParseResult<()> {
    if let Value::KdlDocument(document) = value {
        validate_structural_kdl_nodes(file, document.nodes())
            .map_err(|diagnostic| diagnostic.with_note(format!("while validating {context}")))?;
        if document.nodes().is_empty() {
            return Err(Diagnostic::error(
                codes::NODE_SHAPE,
                format!("{context} document must contain at least one KDL node"),
            )
            .with_span(span));
        }
    }
    Ok(())
}

// Fragments

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
                        return Err(Diagnostic::error(
                            codes::NODE_SHAPE,
                            "fragment defaults must be string paths",
                        )
                        .with_span(entry_span(file, entry)));
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
            if !crate::lang::artifact::validator_known(&format) {
                return Err(Diagnostic::error(
                    codes::FRAGMENT,
                    format!("fragment `{name}` declares unknown format `{format}`"),
                )
                .with_span(span)
                .with_help(crate::lang::artifact::known_validators_help()));
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

// Outputs

fn parse_outputs(file: FileId, dir: &Path, node: &KdlNode) -> ParseResult<Vec<OutputNode>> {
    reject_unknown_props(file, node, &[])?;
    expect_args(file, node, 0)?;
    let mut out = Vec::new();
    if let Some(children) = node.children() {
        for child in children.nodes() {
            out.push(parse_output_node(file, dir, child)?);
        }
    }
    Ok(out)
}

fn parse_output_node(file: FileId, dir: &Path, node: &KdlNode) -> ParseResult<OutputNode> {
    match node.name().value() {
        "text-file" => Err(Diagnostic::error(
            codes::UNKNOWN_NODE,
            "`text-file` was removed; use `render \"<path>\" format=\"text\"` with `@raw`, `@line`, or `@file` parts",
        )
        .with_span(node_span(file, node))),
        "kdl-file" => Err(Diagnostic::error(
            codes::UNKNOWN_NODE,
            "`kdl-file` was removed; use `render \"<path>\" format=\"kdl\" version=1|2 { ... }`",
        )
        .with_span(node_span(file, node))),
        "config-file" => Err(Diagnostic::error(
            codes::UNKNOWN_NODE,
            "`config-file` was removed; use `render \"<path>\" format=\"<format>\"`",
        )
        .with_span(node_span(file, node))),
        "render" => crate::lang::render::parse_render(file, dir, node),
        "file" => Ok(OutputNode::File(parse_file_output(file, dir, node)?)),
        "dir" => Ok(OutputNode::Dir(parse_dir_output(file, dir, node)?)),
        "symlink" => Ok(OutputNode::Symlink(parse_symlink_output(file, node)?)),
        name if is_condition_name(name) => Ok(OutputNode::When(parse_when(
            file,
            node,
            &mut |child| {
            parse_output_node(file, dir, child)
            },
        )?)),
        "each" | "@each" => Ok(OutputNode::Each(parse_each(file, node, &mut |child| {
            parse_output_node(file, dir, child)
        })?)),
        "range" | "@range" => Ok(OutputNode::Range(parse_range(file, node, &mut |child| {
            parse_output_node(file, dir, child)
        })?)),
        other => Err(Diagnostic::error(
            codes::UNKNOWN_NODE,
            format!(
                "unknown output node `{other}` (allowed: render, file, dir, symlink, when/@when, when-set, when-nonempty, each/@each, range/@range)"
            ),
        )
        .with_span(node_span(file, node))),
    }
}

/// Parse a short condition node. The children are parsed by `parse_child`;
/// an optional trailing `else` provides the alternative branch.
fn parse_when<T>(
    file: FileId,
    node: &KdlNode,
    parse_child: &mut dyn FnMut(&KdlNode) -> ParseResult<T>,
) -> ParseResult<WhenBlock<T>> {
    let span = node_span(file, node);
    let predicate = parse_condition(file, node)?;

    let mut then = Vec::new();
    let mut otherwise = Vec::new();
    let mut saw_else = false;
    if let Some(children) = node.children() {
        let nodes = children.nodes();
        for (index, child) in nodes.iter().enumerate() {
            if crate::lang::kdl_util::kdl_control_alias(child.name().value()) == "else" {
                if saw_else {
                    return Err(Diagnostic::error(
                        codes::DUPLICATE,
                        "a condition allows at most one trailing `else`",
                    )
                    .with_span(node_span(file, child)));
                }
                if index + 1 != nodes.len() {
                    return Err(Diagnostic::error(
                        codes::NODE_SHAPE,
                        "`else` must be the final child of its condition",
                    )
                    .with_span(node_span(file, child)));
                }
                saw_else = true;
                expect_args(file, child, 0)?;
                reject_unknown_props(file, child, &[])?;
                if let Some(else_children) = child.children() {
                    for else_child in else_children.nodes() {
                        otherwise.push(parse_child(else_child)?);
                    }
                }
            } else {
                then.push(parse_child(child)?);
            }
        }
    }
    Ok(WhenBlock {
        predicate,
        then,
        otherwise,
        span,
    })
}

fn parse_each<T>(
    file: FileId,
    node: &KdlNode,
    parse_child: &mut dyn FnMut(&KdlNode) -> ParseResult<T>,
) -> ParseResult<EachBlock<T>> {
    let span = node_span(file, node);
    let (binding, source) = parse_each_header(file, node)?;
    let mut body = Vec::new();
    if let Some(children) = node.children() {
        for child in children.nodes() {
            body.push(parse_child(child)?);
        }
    }
    Ok(EachBlock {
        binding,
        source,
        body,
        span,
    })
}

fn parse_range<T>(
    file: FileId,
    node: &KdlNode,
    parse_child: &mut dyn FnMut(&KdlNode) -> ParseResult<T>,
) -> ParseResult<RangeBlock<T>> {
    let span = node_span(file, node);
    let (binding, from, through) = parse_range_header(file, node)?;
    let mut body = Vec::new();
    if let Some(children) = node.children() {
        for child in children.nodes() {
            body.push(parse_child(child)?);
        }
    }
    Ok(RangeBlock {
        binding,
        from,
        through,
        body,
        span,
    })
}

pub(crate) fn validate_structural_kdl_nodes(file: FileId, nodes: &[KdlNode]) -> ParseResult<()> {
    for node in nodes {
        match crate::lang::kdl_util::kdl_control_alias(node.name().value()) {
            "when" | "when-set" | "when-nonempty" => {
                parse_condition(file, node)?;
                let mut saw_else = false;
                if let Some(children) = node.children() {
                    for (index, child) in children.nodes().iter().enumerate() {
                        if crate::lang::kdl_util::kdl_control_alias(child.name().value()) == "else"
                        {
                            if saw_else || index + 1 != children.nodes().len() {
                                return Err(Diagnostic::error(
                                    codes::NODE_SHAPE,
                                    "`else` must occur once as the final child of a condition",
                                )
                                .with_span(node_span(file, child)));
                            }
                            saw_else = true;
                            expect_args(file, child, 0)?;
                            reject_unknown_props(file, child, &[])?;
                            if let Some(else_children) = child.children() {
                                validate_structural_kdl_nodes(file, else_children.nodes())?;
                            }
                        } else {
                            validate_structural_kdl_nodes(file, std::slice::from_ref(child))?;
                        }
                    }
                }
            }
            "each" => {
                parse_each_header(file, node)?;
                if let Some(children) = node.children() {
                    validate_structural_kdl_nodes(file, children.nodes())?;
                }
            }
            "range" => {
                parse_range_header(file, node)?;
                if let Some(children) = node.children() {
                    validate_structural_kdl_nodes(file, children.nodes())?;
                }
            }
            "splice" => {
                parse_splice(file, node)?;
            }
            "compose" => {
                expect_args(file, node, 0)?;
                reject_unknown_props(file, node, &["fragment"])?;
                reject_unknown_children(file, node, &[])?;
                let _ = req_str_prop(file, node, "fragment")?;
            }
            "else" => {
                return Err(Diagnostic::error(
                    codes::NODE_SHAPE,
                    format!("`{}` is not valid here", node.name().value()),
                )
                .with_span(node_span(file, node)));
            }
            "node" => {
                validate_escaped_kdl_node(file, node)?;
                if let Some(children) = node.children() {
                    validate_structural_kdl_nodes(file, children.nodes())?;
                }
            }
            _ => {
                let mut properties = HashSet::new();
                for entry in node.iter() {
                    if let Some(name) = entry.name()
                        && !properties.insert(name.value())
                    {
                        return Err(Diagnostic::error(
                            codes::DUPLICATE,
                            format!(
                                "node `{}` sets property `{}` twice",
                                node.name().value(),
                                name.value()
                            ),
                        )
                        .with_span(entry_span(file, entry)));
                    }
                    if crate::lang::kdl_util::is_ref(entry) {
                        parse_ref(file, entry)?;
                    }
                }
                if let Some(children) = node.children() {
                    validate_structural_kdl_nodes(file, children.nodes())?;
                }
            }
        }
    }
    Ok(())
}

fn validate_escaped_kdl_node(file: FileId, node: &KdlNode) -> ParseResult<()> {
    let Some(entry) = node.iter().find(|entry| entry.name().is_none()) else {
        return Err(Diagnostic::error(
            codes::NODE_SHAPE,
            "`node` requires a literal target node name",
        )
        .with_span(node_span(file, node)));
    };
    if entry.ty().is_some() || entry.value().as_string().is_none_or(|name| name.is_empty()) {
        return Err(Diagnostic::error(
            codes::NODE_SHAPE,
            "`node` target name must be a non-empty literal string",
        )
        .with_span(entry_span(file, entry)));
    }
    Ok(())
}

fn parse_file_output(file: FileId, dir: &Path, node: &KdlNode) -> ParseResult<FileOutput> {
    reject_unknown_props(file, node, &["to", "optional", "on-conflict"])?;
    reject_unknown_children(file, node, &[])?;
    Ok(FileOutput {
        source: req_str_arg(file, node)?,
        to: req_str_prop(file, node, "to")?,
        optional: bool_prop(file, node, "optional")?,
        on_conflict: parse_conflict(file, node)?,
        span: node_span(file, node),
        dir: dir.to_path_buf(),
    })
}

fn parse_dir_output(file: FileId, dir: &Path, node: &KdlNode) -> ParseResult<DirOutput> {
    reject_unknown_props(file, node, &["to", "optional", "on-conflict"])?;
    reject_unknown_children(file, node, &["ignore"])?;
    let mut ignore = Vec::new();
    if let Some(children) = node.children() {
        for child in children.nodes() {
            if child.name().value() == "ignore" {
                reject_unknown_props(file, child, &[])?;
                reject_unknown_children(file, child, &[])?;
                for entry in child.iter().filter(|e| e.name().is_none()) {
                    let Some(pattern) = entry.value().as_string() else {
                        return Err(Diagnostic::error(
                            codes::NODE_SHAPE,
                            "`ignore` expects string glob patterns",
                        )
                        .with_span(entry_span(file, entry)));
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
            return Err(Diagnostic::error(
                codes::NODE_SHAPE,
                format!("symlink if-missing `{other}` (allowed: must-exist, allow)"),
            )
            .with_span(node_span(file, node)));
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
        Some(other) => Err(Diagnostic::error(
            codes::NODE_SHAPE,
            format!("on-conflict `{other}` (allowed: fail, backup)"),
        )
        .with_span(node_span(file, node))),
    }
}

// Slots

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

// Profiles

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
                            return Err(Diagnostic::error(
                                codes::NODE_SHAPE,
                                "`extends` expects profile names as string arguments",
                            )
                            .with_span(entry_span(file, entry)));
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
        let (patches, sets) = parse_patches(file, patch_node)?;
        config.patches = patches;
        config.sets = sets;
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
        reject_unknown_props(file, child, &[])?;
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
    let args: Vec<&kdl::KdlEntry> = node.iter().filter(|e| e.name().is_none()).collect();
    let has_children = node.children().is_some_and(|c| !c.nodes().is_empty());
    match (args.len(), has_children) {
        (0, true) => Ok(Value::KdlDocument(
            node.children().cloned().unwrap_or_default(),
        )),
        (0, false) => Err(Diagnostic::error(
            codes::NODE_SHAPE,
            format!("input `{}` needs a value", node.name().value()),
        )
        .with_span(node_span(file, node))),
        (1, false) => scalar_value(file, args[0]),
        (_, false) => {
            let mut items = Vec::with_capacity(args.len());
            for arg in args {
                let value = scalar_value(file, arg)?;
                if value.is_null() {
                    return Err(
                        Diagnostic::error(codes::NODE_SHAPE, "#null is not a list item")
                            .with_span(entry_span(file, arg)),
                    );
                }
                items.push(value);
            }
            Ok(Value::List(items))
        }
        (_, true) => Err(Diagnostic::error(
            codes::NODE_SHAPE,
            format!(
                "input `{}` mixes arguments and a children block",
                node.name().value()
            ),
        )
        .with_span(node_span(file, node))),
    }
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

type ParsedPatches = (Vec<CollectionPatch>, Vec<crate::lang::ast::SetPatch>);

fn parse_patches(file: FileId, node: &KdlNode) -> ParseResult<ParsedPatches> {
    reject_unknown_props(file, node, &[])?;
    expect_args(file, node, 0)?;
    reject_unknown_children(file, node, &["collection", "set", "unset"])?;
    let mut out = Vec::new();
    let mut sets = Vec::new();
    let Some(children) = node.children() else {
        return Ok((out, sets));
    };
    for child in children.nodes() {
        if matches!(child.name().value(), "set" | "unset") {
            sets.push(parse_set_patch(file, child)?);
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
                        ops.push(PatchOp::Remove {
                            key: req_str_arg(file, op)?,
                            optional: bool_prop(file, op, "optional")?,
                            span: op_span,
                        });
                    }
                    "replace-all" => {
                        reject_unknown_props(file, op, &[])?;
                        expect_args(file, op, 0)?;
                        reject_unknown_children(file, op, &["item"])?;
                        let mut items = Vec::new();
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
                                if items
                                    .iter()
                                    .any(|(k, _, _): &(String, Value, Span)| k == &key)
                                {
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
        out.push(CollectionPatch {
            collection,
            ops,
            span,
        });
    }
    Ok((out, sets))
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
            first.ty().is_none()
                && path.split_once('.').is_some_and(|(input, field)| {
                    !input.is_empty() && !field.is_empty() && !field.contains('.')
                })
        })
        .ok_or_else(|| {
            Diagnostic::error(
                codes::NODE_SHAPE,
                format!(
                    "`{}` takes a plain `input.field` path (one dot)",
                    node.name().value()
                ),
            )
            .with_span(entry_span(file, first))
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
            return Err(Diagnostic::error(
                codes::NODE_SHAPE,
                "use `unset` to clear an optional field",
            )
            .with_span(entry_span(file, entry)));
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

// Global variables

/// Parse a `variables { global.foo "value" … }` block. Only `global.*` names
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
