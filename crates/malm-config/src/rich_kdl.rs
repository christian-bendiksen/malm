use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use kdl::{KdlDocument, KdlEntry, KdlNode, KdlValue};
use malm_pack::PackPath;
use malm_types::{Alias, ContributionName, Digest};

use crate::rich::{
    CapturedDocumentIdV1, FragmentDeclarationV1, OrderedPatchV1, PatchOperationV1, PatchStepV1,
    RichConditionV1, RichConfigErrorV1, RichDocumentBodyV1, RichExpressionV1,
    RichIncludeReferenceV1, RichKeyV1, RichModuleReferenceV1, RichNameV1, RichStatementV1,
    RichValuePathV1, SourceLocationV1, SourceRangeV1, TypedRecordFieldV1, TypedValueTypeV1,
    TypedValueV1, VariableDeclarationV1,
};
use crate::rich_workspace::{
    BuiltInFormatTransformV1, FormatTransformSelectionV1, PackResourceKindV1,
    ParsedRichConfigDocumentPartsV1, ParsedRichConfigDocumentV1, RichOutputDeclarationV1,
    RichOutputSiteV1, RichPackFileReferenceV1, RichProfileV1, RichSlotV1,
    RichTransformResourceReferenceV1, SafeRelativeSymlinkV1,
};
use crate::syntax::parse_document;
use crate::{
    CONFIG_SCHEMA_VERSION, FORMAT_COMPONENT_INTERFACE_V1, RichSyntaxErrorV1, TargetPathV1,
    TransformOptionV1,
};

/// A strict failure while decoding rich KDL equivalent to constructor input.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum RichConfigReadErrorV1 {
    // Do not use `#[error(transparent)]`. `source()` must return the inner
    // `RichSyntaxErrorV1`, not that error's source.
    #[error("{0}")]
    Source(#[source] RichSyntaxErrorV1),
    #[error("unsupported rich config schema {actual}; expected exactly {expected}")]
    UnsupportedVersion { expected: u32, actual: i128 },
    #[error(fmt = fmt_invalid_document)]
    InvalidDocument {
        message: String,
        range: Option<SourceRangeV1>,
    },
    #[error("invalid rich config model: {0}")]
    InvalidModel(#[source] RichConfigErrorV1),
}

fn fmt_invalid_document(
    message: &String,
    range: &Option<SourceRangeV1>,
    formatter: &mut fmt::Formatter<'_>,
) -> fmt::Result {
    match range {
        Some(range) => write!(
            formatter,
            "invalid rich config at bytes {}..{}: {message}",
            range.start(),
            range.end()
        ),
        None => write!(formatter, "invalid rich config: {message}"),
    }
}

impl RichConfigReadErrorV1 {
    #[must_use]
    pub fn range(&self) -> Option<SourceRangeV1> {
        match self {
            Self::InvalidDocument { range, .. } => *range,
            Self::Source(_) | Self::UnsupportedVersion { .. } | Self::InvalidModel(_) => None,
        }
    }
}

impl From<RichConfigErrorV1> for RichConfigReadErrorV1 {
    fn from(error: RichConfigErrorV1) -> Self {
        Self::InvalidModel(error)
    }
}

/// Parses and lowers an exact captured `rich-config` KDL v2 document.
pub fn decode_rich_config_document_v1(
    id: CapturedDocumentIdV1,
    bytes: &[u8],
) -> Result<ParsedRichConfigDocumentV1, RichConfigReadErrorV1> {
    let document = parse_document(bytes).map_err(RichConfigReadErrorV1::Source)?;
    let root = only_root(&document, "rich-config")?;
    expect_shape(
        root,
        0,
        &["schema-version"],
        &["default-profile"],
        BodyRule::Required,
    )?;
    let version = required_integer_property(root, "schema-version")?;
    if version != i128::from(CONFIG_SCHEMA_VERSION) {
        return Err(RichConfigReadErrorV1::UnsupportedVersion {
            expected: CONFIG_SCHEMA_VERSION,
            actual: version,
        });
    }
    let default_profile = match optional_string_property(root, "default-profile")? {
        Some(name) => Some((RichNameV1::new(name)?, node_range(root)?)),
        None => None,
    };
    let children = root.children().expect("root body was required");
    expect_sections(
        root,
        children,
        &[
            "includes",
            "modules",
            "variables",
            "fragments",
            "slots",
            "statements",
            "profiles",
        ],
    )?;

    let includes = section(children, "includes")
        .children()
        .expect("section bodies are required")
        .nodes()
        .iter()
        .map(parse_include)
        .collect::<Result<Vec<_>, _>>()?;
    let modules = section(children, "modules")
        .children()
        .expect("section bodies are required")
        .nodes()
        .iter()
        .map(parse_module)
        .collect::<Result<Vec<_>, _>>()?;
    let variables = section(children, "variables")
        .children()
        .expect("section bodies are required")
        .nodes()
        .iter()
        .map(parse_variable)
        .collect::<Result<Vec<_>, _>>()?;
    let fragments = section(children, "fragments")
        .children()
        .expect("section bodies are required")
        .nodes()
        .iter()
        .map(parse_fragment)
        .collect::<Result<Vec<_>, _>>()?;
    let statements = parse_statement_nodes(
        section(children, "statements")
            .children()
            .expect("section bodies are required")
            .nodes(),
    )?;
    let slots = section(children, "slots")
        .children()
        .expect("section bodies are required")
        .nodes()
        .iter()
        .map(|node| parse_slot(&id, node))
        .collect::<Result<Vec<_>, _>>()?;
    let profiles = section(children, "profiles")
        .children()
        .expect("section bodies are required")
        .nodes()
        .iter()
        .map(|node| parse_profile(&id, node))
        .collect::<Result<Vec<_>, _>>()?;

    let body = RichDocumentBodyV1::new(variables, fragments, statements)?;
    ParsedRichConfigDocumentV1::new(ParsedRichConfigDocumentPartsV1 {
        id,
        bytes: bytes.to_vec(),
        includes,
        modules,
        body,
        default_profile,
        slots,
        profiles,
    })
    .map_err(Into::into)
}

fn parse_include(node: &KdlNode) -> Result<RichIncludeReferenceV1, RichConfigReadErrorV1> {
    expect_name(node, "include")?;
    expect_shape(node, 0, &["path"], &["dependency"], BodyRule::Forbidden)?;
    let path = PackPath::new(required_string_property(node, "path")?)
        .map_err(|error| node_error(node, error.to_string()))?;
    let dependency = optional_string_property(node, "dependency")?
        .map(Alias::new)
        .transpose()
        .map_err(|error| node_error(node, error.to_string()))?;
    Ok(RichIncludeReferenceV1::new(
        path,
        dependency,
        node_range(node)?,
    ))
}

fn parse_module(node: &KdlNode) -> Result<RichModuleReferenceV1, RichConfigReadErrorV1> {
    expect_name(node, "module")?;
    expect_shape(node, 1, &[], &["dependency"], BodyRule::Forbidden)?;
    let module = ContributionName::new(required_string_argument(node)?)
        .map_err(|error| node_error(node, error.to_string()))?;
    let dependency = optional_string_property(node, "dependency")?
        .map(Alias::new)
        .transpose()
        .map_err(|error| node_error(node, error.to_string()))?;
    Ok(RichModuleReferenceV1::new(
        module,
        dependency,
        node_range(node)?,
    ))
}

fn parse_variable(node: &KdlNode) -> Result<VariableDeclarationV1, RichConfigReadErrorV1> {
    match node.name().value() {
        "input" => parse_input(node),
        "let" => parse_computed(node),
        other => Err(node_error(
            node,
            format!("unknown variable declaration {other:?}"),
        )),
    }
}

fn parse_input(node: &KdlNode) -> Result<VariableDeclarationV1, RichConfigReadErrorV1> {
    expect_shape(node, 1, &["optional"], &[], BodyRule::Required)?;
    let name = RichNameV1::new(required_string_argument(node)?)?;
    let optional = required_bool_property(node, "optional")?;
    let children = node.children().expect("input body was required");
    expect_named_children(node, children, &["type"], &["default"])?;
    let value_type = parse_type_node(child(children, "type"))?;
    let default = optional_child(children, "default")
        .map(parse_expression_wrapper)
        .transpose()?;
    let range = node_range(node)?;
    Ok(match (optional, default) {
        (false, None) => VariableDeclarationV1::required(name, value_type, range),
        (true, None) => VariableDeclarationV1::optional(name, value_type, range),
        (false, Some(default)) => {
            VariableDeclarationV1::defaulted(name, value_type, default, range)
        }
        (true, Some(default)) => {
            VariableDeclarationV1::optional_defaulted(name, value_type, default, range)
        }
    })
}

fn parse_computed(node: &KdlNode) -> Result<VariableDeclarationV1, RichConfigReadErrorV1> {
    expect_shape(node, 1, &[], &[], BodyRule::Required)?;
    let name = RichNameV1::new(required_string_argument(node)?)?;
    let children = node.children().expect("let body was required");
    expect_named_children(node, children, &["type", "expression"], &[])?;
    Ok(VariableDeclarationV1::computed(
        name,
        parse_type_node(child(children, "type"))?,
        parse_expression_wrapper(child(children, "expression"))?,
        node_range(node)?,
    ))
}

fn parse_type_node(node: &KdlNode) -> Result<TypedValueTypeV1, RichConfigReadErrorV1> {
    expect_name(node, "type")?;
    reject_annotations_and_duplicates(node)?;
    let kind = required_string_argument(node)?;
    let expected_body = matches!(kind.as_str(), "list" | "record" | "collection");
    expect_shape(
        node,
        1,
        &[],
        &[],
        if expected_body {
            BodyRule::Required
        } else {
            BodyRule::Forbidden
        },
    )?;
    match kind.as_str() {
        "bool" => Ok(TypedValueTypeV1::boolean()),
        "integer" => Ok(TypedValueTypeV1::integer()),
        "unsigned" => Ok(TypedValueTypeV1::unsigned()),
        "float" => Ok(TypedValueTypeV1::float()),
        "string" => Ok(TypedValueTypeV1::string()),
        "path" => Ok(TypedValueTypeV1::path()),
        "list" | "collection" => {
            let children = node.children().expect("aggregate type body was required");
            expect_named_children(node, children, &["item-type"], &[])?;
            let item_type = child(children, "item-type");
            expect_shape(item_type, 0, &[], &[], BodyRule::Required)?;
            let item_type = one_child(item_type)?;
            let item_type = parse_type_node(item_type)?;
            if kind == "list" {
                TypedValueTypeV1::list(item_type).map_err(Into::into)
            } else {
                TypedValueTypeV1::collection(item_type).map_err(Into::into)
            }
        }
        "record" => {
            let children = node.children().expect("record type body was required");
            let mut fields = Vec::new();
            for field in children.nodes() {
                expect_name(field, "field")?;
                expect_shape(field, 1, &["optional"], &[], BodyRule::Required)?;
                let name = RichKeyV1::new(required_string_argument(field)?)?;
                let optional = required_bool_property(field, "optional")?;
                let body = field.children().expect("field body was required");
                expect_named_children(field, body, &["type"], &["default"])?;
                let value_type = parse_type_node(child(body, "type"))?;
                let default = match optional_child(body, "default") {
                    Some(default) => {
                        let expression = parse_expression_wrapper(default)?;
                        Some(expression_literal_value(expression)?.ok_or_else(|| {
                            node_error(default, "record field defaults must be literal values")
                        })?)
                    }
                    None => None,
                };
                let schema = match (optional, default) {
                    (false, None) => TypedRecordFieldV1::required(value_type),
                    (true, None) => TypedRecordFieldV1::optional(value_type),
                    (false, Some(default)) => TypedRecordFieldV1::defaulted(value_type, default)?,
                    (true, Some(default)) => {
                        TypedRecordFieldV1::optional_defaulted(value_type, default)?
                    }
                };
                fields.push((name, schema));
            }
            TypedValueTypeV1::record_from_fields(fields).map_err(Into::into)
        }
        other => Err(node_error(node, format!("unknown rich type {other:?}"))),
    }
}

fn expression_literal_value(
    expression: RichExpressionV1,
) -> Result<Option<TypedValueV1>, RichConfigReadErrorV1> {
    let value = match expression {
        RichExpressionV1::Literal(value) => value,
        RichExpressionV1::List(values) => {
            let values = values
                .into_iter()
                .map(|value| {
                    expression_literal_value(value)?.ok_or_else(|| {
                        document_error("record field defaults must be literal", None)
                    })
                })
                .collect::<Result<Vec<_>, _>>()?;
            TypedValueV1::list(values)?
        }
        RichExpressionV1::Record(values) => {
            let values = values
                .into_iter()
                .map(|(key, value)| {
                    expression_literal_value(value)?
                        .ok_or_else(|| {
                            document_error("record field defaults must be literal", None)
                        })
                        .map(|value| (key, value))
                })
                .collect::<Result<BTreeMap<_, _>, _>>()?;
            TypedValueV1::record(values)?
        }
        RichExpressionV1::Collection(values) => {
            let values = values
                .into_iter()
                .map(|(key, value)| {
                    expression_literal_value(value)?
                        .ok_or_else(|| {
                            document_error("record field defaults must be literal", None)
                        })
                        .map(|value| (key, value))
                })
                .collect::<Result<BTreeMap<_, _>, _>>()?;
            TypedValueV1::collection(values)?
        }
        RichExpressionV1::Variable(_)
        | RichExpressionV1::Select { .. }
        | RichExpressionV1::Conditional { .. } => return Ok(None),
    };
    Ok(Some(value))
}

fn parse_fragment(node: &KdlNode) -> Result<FragmentDeclarationV1, RichConfigReadErrorV1> {
    expect_name(node, "fragment")?;
    expect_shape(node, 1, &[], &[], BodyRule::Required)?;
    let children = node.children().expect("fragment body was required");
    expect_named_children(node, children, &["statements"], &[])?;
    let statements = child(children, "statements");
    expect_shape(statements, 0, &[], &[], BodyRule::Required)?;
    FragmentDeclarationV1::new(
        RichNameV1::new(required_string_argument(node)?)?,
        parse_statement_nodes(
            statements
                .children()
                .expect("statements body is required")
                .nodes(),
        )?,
        node_range(node)?,
    )
    .map_err(Into::into)
}

fn parse_statement_nodes(nodes: &[KdlNode]) -> Result<Vec<RichStatementV1>, RichConfigReadErrorV1> {
    nodes.iter().map(parse_statement).collect()
}

fn parse_statement(node: &KdlNode) -> Result<RichStatementV1, RichConfigReadErrorV1> {
    match node.name().value() {
        "emit" => {
            expect_shape(node, 1, &[], &[], BodyRule::Required)?;
            Ok(RichStatementV1::Emit {
                key: RichKeyV1::new(required_string_argument(node)?)?,
                value: parse_expression_wrapper_named(node, "value")?,
                range: node_range(node)?,
            })
        }
        "compose" => {
            expect_shape(node, 1, &[], &[], BodyRule::Forbidden)?;
            Ok(RichStatementV1::Compose {
                fragment: RichNameV1::new(required_string_argument(node)?)?,
                range: node_range(node)?,
            })
        }
        "when" => parse_when(node),
        "for-each" => parse_for_each(node),
        "for-range" => parse_for_range(node),
        "patch" => parse_patch(node).map(RichStatementV1::Patch),
        other => Err(node_error(
            node,
            format!("unknown rich statement {other:?}"),
        )),
    }
}

fn parse_when(node: &KdlNode) -> Result<RichStatementV1, RichConfigReadErrorV1> {
    expect_shape(node, 0, &[], &[], BodyRule::Required)?;
    let children = node.children().expect("when body was required");
    expect_named_children(node, children, &["condition", "then", "else"], &[])?;
    let condition = child(children, "condition");
    expect_shape(condition, 0, &[], &[], BodyRule::Required)?;
    let then = child(children, "then");
    expect_shape(then, 0, &[], &[], BodyRule::Required)?;
    let otherwise = child(children, "else");
    expect_shape(otherwise, 0, &[], &[], BodyRule::Required)?;
    Ok(RichStatementV1::Conditional {
        condition: parse_condition(one_child(condition)?)?,
        then_statements: parse_statement_nodes(
            then.children().expect("then body was required").nodes(),
        )?,
        else_statements: parse_statement_nodes(
            otherwise
                .children()
                .expect("else body was required")
                .nodes(),
        )?,
        range: node_range(node)?,
    })
}

fn parse_for_each(node: &KdlNode) -> Result<RichStatementV1, RichConfigReadErrorV1> {
    expect_shape(node, 1, &[], &["key-binding"], BodyRule::Required)?;
    let children = node.children().expect("for-each body was required");
    expect_named_children(node, children, &["iterable", "do"], &[])?;
    let body = child(children, "do");
    expect_shape(body, 0, &[], &[], BodyRule::Required)?;
    Ok(RichStatementV1::ForEach {
        value_binding: RichNameV1::new(required_string_argument(node)?)?,
        key_binding: optional_string_property(node, "key-binding")?
            .map(RichNameV1::new)
            .transpose()?,
        iterable: parse_expression_wrapper(child(children, "iterable"))?,
        statements: parse_statement_nodes(body.children().expect("do body was required").nodes())?,
        range: node_range(node)?,
    })
}

fn parse_for_range(node: &KdlNode) -> Result<RichStatementV1, RichConfigReadErrorV1> {
    expect_shape(node, 1, &["from", "through"], &[], BodyRule::Required)?;
    let children = node.children().expect("for-range body was required");
    expect_named_children(node, children, &["do"], &[])?;
    let body = child(children, "do");
    expect_shape(body, 0, &[], &[], BodyRule::Required)?;
    Ok(RichStatementV1::Range {
        binding: RichNameV1::new(required_string_argument(node)?)?,
        from: i64_property(node, "from")?,
        through: i64_property(node, "through")?,
        statements: parse_statement_nodes(body.children().expect("do body was required").nodes())?,
        range: node_range(node)?,
    })
}

fn parse_patch(node: &KdlNode) -> Result<OrderedPatchV1, RichConfigReadErrorV1> {
    expect_shape(node, 0, &[], &[], BodyRule::Required)?;
    let mut steps = Vec::new();
    for step in node.children().expect("patch body was required").nodes() {
        let path = || -> Result<RichValuePathV1, RichConfigReadErrorV1> {
            parse_value_path(&required_string_property(step, "path")?)
        };
        let operation = match step.name().value() {
            "set" => {
                expect_shape(step, 0, &["path"], &[], BodyRule::Required)?;
                PatchOperationV1::Set {
                    path: path()?,
                    value: parse_expression_wrapper_named(step, "value")?,
                }
            }
            "unset" => {
                expect_shape(step, 0, &["path", "optional"], &[], BodyRule::Forbidden)?;
                PatchOperationV1::Unset {
                    path: path()?,
                    optional: required_bool_property(step, "optional")?,
                }
            }
            "list-append" => {
                expect_shape(step, 0, &["path"], &[], BodyRule::Required)?;
                PatchOperationV1::ListAppend {
                    path: path()?,
                    value: parse_expression_wrapper_named(step, "value")?,
                }
            }
            "collection-insert" | "collection-replace" => {
                expect_shape(step, 0, &["path"], &[], BodyRule::Required)?;
                let children = step.children().expect("collection patch body was required");
                expect_named_children(step, children, &["key", "value"], &[])?;
                let path = path()?;
                let key = parse_expression_wrapper(child(children, "key"))?;
                let value = parse_expression_wrapper(child(children, "value"))?;
                if step.name().value() == "collection-insert" {
                    PatchOperationV1::CollectionInsert { path, key, value }
                } else {
                    PatchOperationV1::CollectionReplace { path, key, value }
                }
            }
            "collection-remove" => {
                expect_shape(step, 0, &["path", "optional"], &[], BodyRule::Required)?;
                PatchOperationV1::CollectionRemove {
                    path: path()?,
                    key: parse_expression_wrapper_named(step, "key")?,
                    optional: required_bool_property(step, "optional")?,
                }
            }
            "collection-replace-all" => {
                expect_shape(step, 0, &["path"], &[], BodyRule::Required)?;
                let mut values = BTreeMap::new();
                for item in step
                    .children()
                    .expect("replacement body was required")
                    .nodes()
                {
                    expect_name(item, "item")?;
                    expect_shape(item, 1, &[], &[], BodyRule::Required)?;
                    let key = RichKeyV1::new(required_string_argument(item)?)?;
                    if values
                        .insert(key.clone(), parse_expression(one_child(item)?)?)
                        .is_some()
                    {
                        return Err(node_error(item, format!("duplicate collection key {key}")));
                    }
                }
                PatchOperationV1::CollectionReplaceAll {
                    path: path()?,
                    values,
                }
            }
            other => {
                return Err(node_error(
                    step,
                    format!("unknown ordered patch operation {other:?}"),
                ));
            }
        };
        steps.push(PatchStepV1::new(operation, node_range(step)?));
    }
    OrderedPatchV1::new(steps).map_err(Into::into)
}

fn parse_value_path(value: &str) -> Result<RichValuePathV1, RichConfigReadErrorV1> {
    RichValuePathV1::new(
        value
            .split('.')
            .map(RichKeyV1::new)
            .collect::<Result<Vec<_>, _>>()?,
    )
    .map_err(Into::into)
}

fn parse_expression_wrapper_named(
    node: &KdlNode,
    name: &str,
) -> Result<RichExpressionV1, RichConfigReadErrorV1> {
    let children = node.children().expect("caller required a body");
    expect_named_children(node, children, &[name], &[])?;
    parse_expression_wrapper(child(children, name))
}

fn parse_expression_wrapper(node: &KdlNode) -> Result<RichExpressionV1, RichConfigReadErrorV1> {
    expect_shape(node, 0, &[], &[], BodyRule::Required)?;
    parse_expression(one_child(node)?)
}

fn parse_expression(node: &KdlNode) -> Result<RichExpressionV1, RichConfigReadErrorV1> {
    match node.name().value() {
        "null" => {
            expect_shape(node, 0, &[], &[], BodyRule::Forbidden)?;
            Ok(RichExpressionV1::literal(TypedValueV1::null()))
        }
        "bool" => {
            expect_shape(node, 1, &[], &[], BodyRule::Forbidden)?;
            Ok(RichExpressionV1::literal(TypedValueV1::boolean(
                required_bool_argument(node)?,
            )))
        }
        "integer" => {
            expect_shape(node, 1, &[], &[], BodyRule::Forbidden)?;
            Ok(RichExpressionV1::literal(TypedValueV1::integer(
                i64_argument(node)?,
            )))
        }
        "unsigned" => {
            expect_shape(node, 1, &[], &[], BodyRule::Forbidden)?;
            let value = required_integer_argument(node)?;
            let value = u64::try_from(value)
                .map_err(|_| node_error(node, "unsigned value is outside the u64 range"))?;
            Ok(RichExpressionV1::literal(TypedValueV1::unsigned(value)))
        }
        "float" => {
            expect_shape(node, 1, &[], &[], BodyRule::Forbidden)?;
            let value = required_argument(node)?
                .as_float()
                .ok_or_else(|| node_error(node, "float expression requires a KDL float"))?;
            Ok(RichExpressionV1::literal(TypedValueV1::float(value)?))
        }
        "string" => {
            expect_shape(node, 1, &[], &[], BodyRule::Forbidden)?;
            Ok(RichExpressionV1::literal(TypedValueV1::string(
                required_string_argument(node)?,
            )?))
        }
        "path" => {
            expect_shape(node, 1, &[], &[], BodyRule::Forbidden)?;
            let value = TargetPathV1::new(required_string_argument(node)?)
                .map_err(|error| node_error(node, error.to_string()))?;
            Ok(RichExpressionV1::literal(TypedValueV1::path(value)))
        }
        "variable" => {
            expect_shape(node, 1, &[], &[], BodyRule::Forbidden)?;
            Ok(RichExpressionV1::variable(RichNameV1::new(
                required_string_argument(node)?,
            )?))
        }
        "list" => {
            expect_shape(node, 0, &[], &[], BodyRule::Required)?;
            let values = node
                .children()
                .expect("list body was required")
                .nodes()
                .iter()
                .map(|item| {
                    expect_name(item, "item")?;
                    parse_expression_wrapper(item)
                })
                .collect::<Result<Vec<_>, _>>()?;
            Ok(RichExpressionV1::List(values))
        }
        "record" | "collection" => {
            expect_shape(node, 0, &[], &[], BodyRule::Required)?;
            let item_name = if node.name().value() == "record" {
                "field"
            } else {
                "item"
            };
            let mut values = BTreeMap::new();
            for item in node.children().expect("map body was required").nodes() {
                expect_name(item, item_name)?;
                expect_shape(item, 1, &[], &[], BodyRule::Required)?;
                let key = RichKeyV1::new(required_string_argument(item)?)?;
                if values
                    .insert(key.clone(), parse_expression(one_child(item)?)?)
                    .is_some()
                {
                    return Err(node_error(item, format!("duplicate map key {key}")));
                }
            }
            if node.name().value() == "record" {
                Ok(RichExpressionV1::Record(values))
            } else {
                Ok(RichExpressionV1::Collection(values))
            }
        }
        "select" => {
            expect_shape(node, 0, &["key"], &[], BodyRule::Required)?;
            Ok(RichExpressionV1::Select {
                value: Box::new(parse_expression_wrapper_named(node, "value")?),
                key: RichKeyV1::new(required_string_property(node, "key")?)?,
            })
        }
        "if-value" => {
            expect_shape(node, 0, &[], &[], BodyRule::Required)?;
            let children = node.children().expect("if-value body was required");
            expect_named_children(node, children, &["condition", "then", "else"], &[])?;
            let condition = child(children, "condition");
            expect_shape(condition, 0, &[], &[], BodyRule::Required)?;
            Ok(RichExpressionV1::Conditional {
                condition: Box::new(parse_condition(one_child(condition)?)?),
                then_value: Box::new(parse_expression_wrapper(child(children, "then"))?),
                else_value: Box::new(parse_expression_wrapper(child(children, "else"))?),
            })
        }
        other => Err(node_error(
            node,
            format!("unknown rich expression {other:?}"),
        )),
    }
}

fn parse_condition(node: &KdlNode) -> Result<RichConditionV1, RichConfigReadErrorV1> {
    match node.name().value() {
        "boolean" | "is-set" => {
            expect_shape(node, 0, &[], &[], BodyRule::Required)?;
            let expression = Box::new(parse_expression_wrapper_named(node, "value")?);
            if node.name().value() == "boolean" {
                Ok(RichConditionV1::Boolean(expression))
            } else {
                Ok(RichConditionV1::IsSet(expression))
            }
        }
        "equal" => {
            expect_shape(node, 0, &["negated"], &[], BodyRule::Required)?;
            let children = node.children().expect("equal body was required");
            expect_named_children(node, children, &["left", "right"], &[])?;
            Ok(RichConditionV1::Equal {
                left: Box::new(parse_expression_wrapper(child(children, "left"))?),
                right: Box::new(parse_expression_wrapper(child(children, "right"))?),
                negated: required_bool_property(node, "negated")?,
            })
        }
        "not" => {
            expect_shape(node, 0, &[], &[], BodyRule::Required)?;
            let children = node.children().expect("not body was required");
            expect_named_children(node, children, &["condition"], &[])?;
            let condition = child(children, "condition");
            expect_shape(condition, 0, &[], &[], BodyRule::Required)?;
            Ok(RichConditionV1::Not(Box::new(parse_condition(one_child(
                condition,
            )?)?)))
        }
        "all" | "any" => {
            expect_shape(node, 0, &[], &[], BodyRule::Required)?;
            let conditions = node
                .children()
                .expect("condition body was required")
                .nodes()
                .iter()
                .map(|condition| {
                    expect_name(condition, "condition")?;
                    expect_shape(condition, 0, &[], &[], BodyRule::Required)?;
                    parse_condition(one_child(condition)?)
                })
                .collect::<Result<Vec<_>, _>>()?;
            if node.name().value() == "all" {
                Ok(RichConditionV1::All(conditions))
            } else {
                Ok(RichConditionV1::Any(conditions))
            }
        }
        other => Err(node_error(
            node,
            format!("unknown rich condition {other:?}"),
        )),
    }
}

fn parse_slot(
    document: &CapturedDocumentIdV1,
    node: &KdlNode,
) -> Result<RichSlotV1, RichConfigReadErrorV1> {
    expect_name(node, "slot")?;
    expect_shape(node, 1, &["max"], &[], BodyRule::Forbidden)?;
    let max = required_integer_property(node, "max")?;
    let max = usize::try_from(max).map_err(|_| node_error(node, "slot max is outside usize"))?;
    RichSlotV1::new(
        RichNameV1::new(required_string_argument(node)?)?,
        max,
        SourceLocationV1::new(document.clone(), node_range(node)?),
    )
    .map_err(Into::into)
}

fn parse_profile(
    document: &CapturedDocumentIdV1,
    node: &KdlNode,
) -> Result<RichProfileV1, RichConfigReadErrorV1> {
    expect_name(node, "profile")?;
    expect_shape(node, 1, &["abstract"], &[], BodyRule::Required)?;
    let children = node.children().expect("profile body was required");
    expect_named_children(node, children, &["extends", "statements", "outputs"], &[])?;
    let extends_node = child(children, "extends");
    let statements_node = child(children, "statements");
    let outputs_node = child(children, "outputs");
    expect_shape(extends_node, 0, &[], &[], BodyRule::Required)?;
    expect_shape(statements_node, 0, &[], &[], BodyRule::Required)?;
    expect_shape(outputs_node, 0, &[], &[], BodyRule::Required)?;
    let extends = extends_node
        .children()
        .expect("extends body was required")
        .nodes()
        .iter()
        .map(|parent| {
            expect_name(parent, "profile")?;
            expect_shape(parent, 1, &[], &[], BodyRule::Forbidden)?;
            RichNameV1::new(required_string_argument(parent)?).map_err(Into::into)
        })
        .collect::<Result<Vec<_>, RichConfigReadErrorV1>>()?;
    let statements = parse_statement_nodes(
        statements_node
            .children()
            .expect("statements body was required")
            .nodes(),
    )?;
    let outputs = outputs_node
        .children()
        .expect("outputs body was required")
        .nodes()
        .iter()
        .map(|output| parse_output(document, output))
        .collect::<Result<Vec<_>, _>>()?;
    RichProfileV1::new(
        RichNameV1::new(required_string_argument(node)?)?,
        required_bool_property(node, "abstract")?,
        extends,
        statements,
        outputs,
        SourceLocationV1::new(document.clone(), node_range(node)?),
    )
    .map_err(Into::into)
}

fn parse_output(
    document: &CapturedDocumentIdV1,
    node: &KdlNode,
) -> Result<RichOutputDeclarationV1, RichConfigReadErrorV1> {
    let source = SourceLocationV1::new(document.clone(), node_range(node)?);
    let slot = optional_string_property(node, "slot")?
        .map(RichNameV1::new)
        .transpose()?;
    let name = || -> Result<RichNameV1, RichConfigReadErrorV1> {
        RichNameV1::new(required_string_argument(node)?).map_err(Into::into)
    };
    let destination = || {
        TargetPathV1::new(required_string_property(node, "destination")?)
            .map_err(|error| node_error(node, error.to_string()))
    };
    // Build the site lazily here to preserve the established validation order.
    let site = move || -> Result<RichOutputSiteV1, RichConfigReadErrorV1> {
        Ok(RichOutputSiteV1::new(name()?, destination()?, slot, source))
    };
    match node.name().value() {
        "regular-file" => {
            expect_shape(
                node,
                1,
                &[
                    "destination",
                    "source",
                    "source-kind",
                    "raw-digest",
                    "object-digest",
                    "byte-len",
                    "executable",
                ],
                &["slot", "dependency"],
                BodyRule::Forbidden,
            )?;
            Ok(RichOutputDeclarationV1::regular_file(
                site()?,
                parse_pack_file_reference(node)?,
                required_bool_property(node, "executable")?,
            ))
        }
        "symlink" => {
            expect_shape(
                node,
                1,
                &["destination", "target"],
                &["slot"],
                BodyRule::Forbidden,
            )?;
            Ok(RichOutputDeclarationV1::symlink(
                site()?,
                SafeRelativeSymlinkV1::new(required_string_property(node, "target")?)?,
            ))
        }
        "canonical-tree" => {
            expect_shape(
                node,
                1,
                &["destination", "digest"],
                &["slot"],
                BodyRule::Forbidden,
            )?;
            Ok(RichOutputDeclarationV1::canonical_tree(
                site()?,
                digest_property(node, "digest")?,
            ))
        }
        "decoded-archive" => {
            expect_shape(
                node,
                1,
                &[
                    "destination",
                    "source",
                    "source-kind",
                    "raw-digest",
                    "object-digest",
                    "byte-len",
                    "decoder",
                    "decoder-version",
                    "tree-digest",
                ],
                &["slot", "dependency"],
                BodyRule::Forbidden,
            )?;
            let payload = parse_pack_file_reference(node)?;
            if payload.kind != PackResourceKindV1::Asset {
                return Err(node_error(
                    node,
                    "decoded archive payloads must be declared pack assets",
                ));
            }
            let decoder_version = required_integer_property(node, "decoder-version")?;
            let decoder_version = u16::try_from(decoder_version)
                .map_err(|_| node_error(node, "decoder-version is outside u16"))?;
            Ok(RichOutputDeclarationV1::decoded_archive(
                site()?,
                payload,
                RichNameV1::new(required_string_property(node, "decoder")?)?,
                decoder_version,
                digest_property(node, "tree-digest")?,
            ))
        }
        "format-file" => {
            expect_shape(
                node,
                1,
                &["destination", "executable"],
                &["slot"],
                BodyRule::Required,
            )?;
            let children = node.children().expect("format-file body was required");
            for child in children.nodes() {
                if !matches!(
                    child.name().value(),
                    "built-in" | "component" | "options" | "resources"
                ) {
                    return Err(node_error(
                        child,
                        format!("unknown format-file child {:?}", child.name().value()),
                    ));
                }
            }
            let providers = children
                .nodes()
                .iter()
                .filter(|child| matches!(child.name().value(), "built-in" | "component"))
                .collect::<Vec<_>>();
            if providers.len() != 1 {
                return Err(node_error(
                    node,
                    "format-file requires exactly one built-in or component selector",
                ));
            }
            let options_node = exactly_one_named_child(node, children, "options")?;
            let resources_node = exactly_one_named_child(node, children, "resources")?;
            expect_shape(options_node, 0, &[], &[], BodyRule::Required)?;
            expect_shape(resources_node, 0, &[], &[], BodyRule::Required)?;
            let transform = match providers[0].name().value() {
                "built-in" => {
                    let provider = providers[0];
                    expect_shape(provider, 1, &[], &[], BodyRule::Forbidden)?;
                    FormatTransformSelectionV1::built_in(BuiltInFormatTransformV1::parse(
                        &required_string_argument(provider)?,
                    )?)
                }
                "component" => {
                    let provider = providers[0];
                    expect_shape(
                        provider,
                        1,
                        &["digest", "interface"],
                        &[],
                        BodyRule::Forbidden,
                    )?;
                    let interface = required_string_property(provider, "interface")?;
                    if interface != FORMAT_COMPONENT_INTERFACE_V1 {
                        return Err(node_error(
                            provider,
                            "component interface must be exactly format-component/v1",
                        ));
                    }
                    FormatTransformSelectionV1::component(
                        RichNameV1::new(required_string_argument(provider)?)?,
                        digest_property(provider, "digest")?,
                    )
                }
                _ => unreachable!("provider names were filtered above"),
            };
            let options = options_node
                .children()
                .expect("options body was required")
                .nodes()
                .iter()
                .map(|option| {
                    expect_name(option, "option")?;
                    expect_shape(option, 1, &[], &[], BodyRule::Required)?;
                    let expression = parse_expression(one_child(option)?)?;
                    let value = expression_literal_value(expression)?.ok_or_else(|| {
                        node_error(option, "transform options must be explicit typed literals")
                    })?;
                    TransformOptionV1::new(
                        RichNameV1::new(required_string_argument(option)?)?,
                        value,
                    )
                    .map_err(|error| node_error(option, error.to_string()))
                })
                .collect::<Result<Vec<_>, _>>()?;
            let resources = resources_node
                .children()
                .expect("resources body was required")
                .nodes()
                .iter()
                .map(|resource| {
                    expect_name(resource, "resource")?;
                    expect_shape(
                        resource,
                        1,
                        &[
                            "source",
                            "source-kind",
                            "raw-digest",
                            "object-digest",
                            "byte-len",
                        ],
                        &["dependency"],
                        BodyRule::Forbidden,
                    )?;
                    Ok(RichTransformResourceReferenceV1 {
                        name: RichNameV1::new(required_string_argument(resource)?)?,
                        source: parse_pack_file_reference(resource)?,
                    })
                })
                .collect::<Result<Vec<_>, RichConfigReadErrorV1>>()?;
            RichOutputDeclarationV1::transformed_file(
                site()?,
                transform,
                options,
                resources,
                required_bool_property(node, "executable")?,
            )
            .map_err(Into::into)
        }
        other => Err(node_error(
            node,
            format!("unknown rich output declaration {other:?}"),
        )),
    }
}

fn parse_pack_file_reference(
    node: &KdlNode,
) -> Result<RichPackFileReferenceV1, RichConfigReadErrorV1> {
    let dependency = optional_string_property(node, "dependency")?
        .map(Alias::new)
        .transpose()
        .map_err(|error| node_error(node, error.to_string()))?;
    let path = PackPath::new(required_string_property(node, "source")?)
        .map_err(|error| node_error(node, error.to_string()))?;
    let kind = PackResourceKindV1::parse(&required_string_property(node, "source-kind")?)?;
    let byte_len = required_integer_property(node, "byte-len")?;
    let byte_len =
        u64::try_from(byte_len).map_err(|_| node_error(node, "byte-len is outside u64"))?;
    Ok(RichPackFileReferenceV1 {
        dependency,
        path,
        kind,
        raw_digest: digest_property(node, "raw-digest")?,
        object_digest: digest_property(node, "object-digest")?,
        byte_len,
    })
}

fn digest_property(node: &KdlNode, name: &str) -> Result<Digest, RichConfigReadErrorV1> {
    Digest::new(required_string_property(node, name)?)
        .map_err(|error| node_error(node, error.to_string()))
}

fn exactly_one_named_child<'a>(
    parent: &KdlNode,
    children: &'a KdlDocument,
    name: &str,
) -> Result<&'a KdlNode, RichConfigReadErrorV1> {
    let matching = children
        .nodes()
        .iter()
        .filter(|child| child.name().value() == name)
        .collect::<Vec<_>>();
    if matching.len() != 1 {
        return Err(node_error(
            parent,
            format!("format-file requires exactly one {name} section"),
        ));
    }
    Ok(matching[0])
}

#[derive(Clone, Copy)]
enum BodyRule {
    Required,
    Forbidden,
}

fn only_root<'a>(
    document: &'a KdlDocument,
    name: &str,
) -> Result<&'a KdlNode, RichConfigReadErrorV1> {
    if document.nodes().len() != 1 {
        return Err(document_error(
            format!("expected exactly one top-level {name:?} node"),
            None,
        ));
    }
    let root = &document.nodes()[0];
    expect_name(root, name)?;
    Ok(root)
}

fn expect_name(node: &KdlNode, expected: &str) -> Result<(), RichConfigReadErrorV1> {
    if node.name().value() != expected {
        return Err(node_error(
            node,
            format!(
                "unknown node {:?}; expected {expected:?}",
                node.name().value()
            ),
        ));
    }
    Ok(())
}

fn expect_shape(
    node: &KdlNode,
    argument_count: usize,
    required_properties: &[&str],
    optional_properties: &[&str],
    body: BodyRule,
) -> Result<(), RichConfigReadErrorV1> {
    reject_annotations_and_duplicates(node)?;
    let actual_arguments = node
        .entries()
        .iter()
        .filter(|entry| entry.name().is_none())
        .count();
    if actual_arguments != argument_count {
        return Err(node_error(
            node,
            format!(
                "node {:?} expects {argument_count} arguments, found {actual_arguments}",
                node.name().value()
            ),
        ));
    }
    for entry in node.entries() {
        if entry.ty().is_some() {
            return Err(node_error(node, "value annotations are not permitted"));
        }
        if let Some(name) = entry.name()
            && !required_properties.contains(&name.value())
            && !optional_properties.contains(&name.value())
        {
            return Err(node_error(
                node,
                format!("unknown property {:?}", name.value()),
            ));
        }
    }
    for name in required_properties {
        if property(node, name).is_none() {
            return Err(node_error(
                node,
                format!("missing required property {name:?}"),
            ));
        }
    }
    match (body, node.children()) {
        (BodyRule::Required, None) => Err(node_error(node, "node requires a body")),
        (BodyRule::Forbidden, Some(_)) => Err(node_error(node, "node does not permit a body")),
        _ => Ok(()),
    }
}

fn reject_annotations_and_duplicates(node: &KdlNode) -> Result<(), RichConfigReadErrorV1> {
    if node.ty().is_some() {
        return Err(node_error(node, "node annotations are not permitted"));
    }
    let mut seen = BTreeSet::new();
    for entry in node.entries() {
        if let Some(name) = entry.name()
            && !seen.insert(name.value())
        {
            return Err(node_error(
                node,
                format!("property {:?} occurs more than once", name.value()),
            ));
        }
    }
    Ok(())
}

fn expect_sections(
    parent: &KdlNode,
    children: &KdlDocument,
    names: &[&str],
) -> Result<(), RichConfigReadErrorV1> {
    expect_named_children(parent, children, names, &[])?;
    for name in names {
        expect_shape(child(children, name), 0, &[], &[], BodyRule::Required)?;
    }
    Ok(())
}

fn expect_named_children(
    parent: &KdlNode,
    children: &KdlDocument,
    required: &[&str],
    optional: &[&str],
) -> Result<(), RichConfigReadErrorV1> {
    let mut counts = BTreeMap::new();
    for child in children.nodes() {
        let name = child.name().value();
        if !required.contains(&name) && !optional.contains(&name) {
            return Err(node_error(
                child,
                format!("unknown child {name:?} in {:?}", parent.name().value()),
            ));
        }
        *counts.entry(name).or_insert(0_usize) += 1;
    }
    for name in required {
        if counts.get(name).copied() != Some(1) {
            return Err(node_error(
                parent,
                format!("requires exactly one child {name:?}"),
            ));
        }
    }
    for name in optional {
        if counts.get(name).copied().unwrap_or(0) > 1 {
            return Err(node_error(
                parent,
                format!("permits at most one child {name:?}"),
            ));
        }
    }
    Ok(())
}

fn section<'a>(document: &'a KdlDocument, name: &str) -> &'a KdlNode {
    child(document, name)
}

fn child<'a>(document: &'a KdlDocument, name: &str) -> &'a KdlNode {
    document
        .nodes()
        .iter()
        .find(|node| node.name().value() == name)
        .expect("required child was validated")
}

fn optional_child<'a>(document: &'a KdlDocument, name: &str) -> Option<&'a KdlNode> {
    document
        .nodes()
        .iter()
        .find(|node| node.name().value() == name)
}

fn one_child(node: &KdlNode) -> Result<&KdlNode, RichConfigReadErrorV1> {
    let children = node.children().expect("wrapper body was required");
    if children.nodes().len() != 1 {
        return Err(node_error(
            node,
            format!(
                "wrapper requires exactly one child, found {}",
                children.nodes().len()
            ),
        ));
    }
    Ok(&children.nodes()[0])
}

fn required_argument(node: &KdlNode) -> Result<&KdlValue, RichConfigReadErrorV1> {
    node.entries()
        .iter()
        .find(|entry| entry.name().is_none())
        .map(KdlEntry::value)
        .ok_or_else(|| node_error(node, "missing required argument"))
}

fn required_string_argument(node: &KdlNode) -> Result<String, RichConfigReadErrorV1> {
    required_argument(node)?
        .as_string()
        .map(str::to_owned)
        .ok_or_else(|| node_error(node, "argument must be a string"))
}

fn required_bool_argument(node: &KdlNode) -> Result<bool, RichConfigReadErrorV1> {
    required_argument(node)?
        .as_bool()
        .ok_or_else(|| node_error(node, "argument must be a boolean"))
}

fn required_integer_argument(node: &KdlNode) -> Result<i128, RichConfigReadErrorV1> {
    required_argument(node)?
        .as_integer()
        .ok_or_else(|| node_error(node, "argument must be an integer"))
}

fn i64_argument(node: &KdlNode) -> Result<i64, RichConfigReadErrorV1> {
    i64::try_from(required_integer_argument(node)?)
        .map_err(|_| node_error(node, "integer argument is outside the i64 range"))
}

fn property<'a>(node: &'a KdlNode, name: &str) -> Option<&'a KdlValue> {
    node.entries()
        .iter()
        .find(|entry| entry.name().is_some_and(|key| key.value() == name))
        .map(KdlEntry::value)
}

fn required_string_property(node: &KdlNode, name: &str) -> Result<String, RichConfigReadErrorV1> {
    optional_string_property(node, name)?
        .ok_or_else(|| node_error(node, format!("property {name:?} must be a present string")))
}

fn optional_string_property(
    node: &KdlNode,
    name: &str,
) -> Result<Option<String>, RichConfigReadErrorV1> {
    property(node, name)
        .map(|value| {
            value
                .as_string()
                .map(str::to_owned)
                .ok_or_else(|| node_error(node, format!("property {name:?} must be a string")))
        })
        .transpose()
}

fn required_bool_property(node: &KdlNode, name: &str) -> Result<bool, RichConfigReadErrorV1> {
    property(node, name)
        .and_then(KdlValue::as_bool)
        .ok_or_else(|| node_error(node, format!("property {name:?} must be a boolean")))
}

fn required_integer_property(node: &KdlNode, name: &str) -> Result<i128, RichConfigReadErrorV1> {
    property(node, name)
        .and_then(KdlValue::as_integer)
        .ok_or_else(|| node_error(node, format!("property {name:?} must be an integer")))
}

fn i64_property(node: &KdlNode, name: &str) -> Result<i64, RichConfigReadErrorV1> {
    i64::try_from(required_integer_property(node, name)?)
        .map_err(|_| node_error(node, format!("property {name:?} is outside the i64 range")))
}

fn node_range(node: &KdlNode) -> Result<SourceRangeV1, RichConfigReadErrorV1> {
    let span = node.span();
    let start = u32::try_from(span.offset())
        .map_err(|_| node_error(node, "node source offset exceeds u32"))?;
    let end = span.offset().saturating_add(span.len());
    let end = u32::try_from(end).map_err(|_| node_error(node, "node source end exceeds u32"))?;
    SourceRangeV1::new(start, end).map_err(Into::into)
}

fn node_error(node: &KdlNode, message: impl Into<String>) -> RichConfigReadErrorV1 {
    RichConfigReadErrorV1::InvalidDocument {
        message: message.into(),
        range: node_range_unchecked(node),
    }
}

fn node_range_unchecked(node: &KdlNode) -> Option<SourceRangeV1> {
    let span = node.span();
    let start = u32::try_from(span.offset()).ok()?;
    let end = u32::try_from(span.offset().checked_add(span.len())?).ok()?;
    SourceRangeV1::new(start, end).ok()
}

fn document_error(
    message: impl Into<String>,
    range: Option<SourceRangeV1>,
) -> RichConfigReadErrorV1 {
    RichConfigReadErrorV1::InvalidDocument {
        message: message.into(),
        range,
    }
}
