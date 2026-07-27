use std::collections::BTreeMap;

use malm_format_component_api as api;
use malm_types::Digest;
use wit_parser::{
    FunctionKind, Resolve, Type, TypeDefKind, TypeOwner, UnresolvedPackageGroup, WorldItem,
};

#[test]
fn format_component_v1_is_one_capability_free_transform_export() {
    assert_eq!(
        Digest::sha256(api::WIT_SOURCE.as_bytes()).as_str(),
        include_str!("../../../schemas/format-component/v1/fixtures/golden/wit.sha256").trim_end()
    );
    let group = UnresolvedPackageGroup::parse("malm-format-component.wit", api::WIT_SOURCE)
        .expect("parse format-component/v1 WIT");
    let mut resolve = Resolve::default();
    let package = resolve.push_group(group).expect("resolve WIT");
    let world_id = resolve
        .select_world(package, Some("malm-format-component"))
        .expect("select world");
    let world = &resolve.worlds[world_id];

    assert!(
        world
            .imports
            .values()
            .all(|item| matches!(item, WorldItem::Type(_))),
        "the world may declare types but no capability imports"
    );
    assert_eq!(world.exports.len(), 1);
    let (name, item) = world.exports.iter().next().unwrap();
    assert_eq!(resolve.name_world_key(name), "transform");
    let WorldItem::Function(transform) = item else {
        panic!("sole export must be a function")
    };
    assert_eq!(transform.kind, FunctionKind::Freestanding);
    assert_eq!(
        transform
            .params
            .iter()
            .map(|(name, ty)| (name.as_str(), type_shape(&resolve, *ty)))
            .collect::<Vec<_>>(),
        [("request", "transform-request-v1".to_owned())]
    );
    assert_eq!(
        type_shape(&resolve, transform.result.unwrap()),
        "result<transform-response-v1,transform-failure-v1>"
    );

    let types = resolve
        .types
        .iter()
        .filter(|(_, ty)| ty.owner == TypeOwner::World(world_id))
        .map(|(_, ty)| (ty.name.as_deref().unwrap(), ty.kind.as_str()))
        .collect::<BTreeMap<_, _>>();
    assert_eq!(
        types,
        BTreeMap::from([
            ("canonical-typed-document-v1", "record"),
            ("canonical-value-v1", "record"),
            ("declared-resource-v1", "record"),
            ("diagnostic-location-v1", "variant"),
            ("diagnostic-severity-v1", "enum"),
            ("diagnostic-v1", "record"),
            ("document-id-v1", "record"),
            ("document-edge-kind-v1", "variant"),
            ("evaluation-frame-v1", "variant"),
            ("include-provenance-v1", "record"),
            ("loop-frame-v1", "record"),
            ("output-range-v1", "record"),
            ("provenance-operation-v1", "variant"),
            ("provenance-record-v1", "record"),
            ("source-document-v1", "record"),
            ("source-location-v1", "record"),
            ("source-range-v1", "record"),
            ("transform-failure-kind-v1", "enum"),
            ("transform-failure-v1", "record"),
            ("transform-option-v1", "record"),
            ("transform-request-v1", "record"),
            ("transform-response-v1", "record"),
            ("typed-value-v1", "variant"),
            ("value-field-v1", "record"),
            ("value-id", "type"),
            ("value-provenance-v1", "record"),
        ])
    );

    for (name, fields) in [
        ("value-field-v1", &["name:string", "value:value-id"][..]),
        (
            "canonical-value-v1",
            &["root:value-id", "values:list<typed-value-v1>"],
        ),
        (
            "document-id-v1",
            &[
                "authority-label:string",
                "authority-identity:string",
                "path:string",
            ],
        ),
        (
            "source-document-v1",
            &["id:document-id-v1", "digest:string", "byte-len:u64"],
        ),
        ("source-range-v1", &["start:u32", "end:u32"]),
        (
            "source-location-v1",
            &["document:document-id-v1", "range:source-range-v1"],
        ),
        (
            "include-provenance-v1",
            &[
                "source:source-location-v1",
                "target:document-id-v1",
                "target-digest:string",
                "dependency-alias:option<string>",
                "edge-kind:document-edge-kind-v1",
            ],
        ),
        ("loop-frame-v1", &["binding:string", "iteration:u32"]),
        (
            "provenance-record-v1",
            &[
                "sequence:u64",
                "location:source-location-v1",
                "operation:provenance-operation-v1",
                "frames:list<evaluation-frame-v1>",
            ],
        ),
        (
            "value-provenance-v1",
            &["path:list<string>", "records:list<provenance-record-v1>"],
        ),
        (
            "canonical-typed-document-v1",
            &[
                "version:u32",
                "root:canonical-value-v1",
                "source-documents:list<source-document-v1>",
                "includes:list<include-provenance-v1>",
                "provenance:list<value-provenance-v1>",
            ],
        ),
        (
            "transform-option-v1",
            &["name:string", "value:canonical-value-v1"],
        ),
        (
            "declared-resource-v1",
            &["name:string", "digest:string", "bytes:list<u8>"],
        ),
        (
            "transform-request-v1",
            &[
                "contract-version:u32",
                "document:canonical-typed-document-v1",
                "options:list<transform-option-v1>",
                "resources:list<declared-resource-v1>",
            ],
        ),
        ("output-range-v1", &["start:u64", "end:u64"]),
        (
            "diagnostic-v1",
            &[
                "severity:diagnostic-severity-v1",
                "code:string",
                "message:string",
                "primary:option<diagnostic-location-v1>",
                "notes:list<string>",
            ],
        ),
        (
            "transform-response-v1",
            &[
                "output:list<u8>",
                "media-type:string",
                "diagnostics:list<diagnostic-v1>",
            ],
        ),
        (
            "transform-failure-v1",
            &[
                "kind:transform-failure-kind-v1",
                "message:string",
                "diagnostics:list<diagnostic-v1>",
            ],
        ),
    ] {
        assert_eq!(
            record_fields(&resolve, world_id, name),
            fields,
            "record {name}"
        );
    }

    assert_eq!(
        variant_cases(&resolve, world_id, "document-edge-kind-v1"),
        ["include-edge", "module-edge(string)"]
    );
    assert_eq!(
        variant_cases(&resolve, world_id, "typed-value-v1"),
        [
            "null-value",
            "boolean(bool)",
            "signed(s64)",
            "unsigned(u64)",
            "floating-point(f64)",
            "text(string)",
            "path(string)",
            "list-value(list<value-id>)",
            "record-value(list<value-field-v1>)",
            "collection-value(list<value-field-v1>)",
        ]
    );
    assert_eq!(
        variant_cases(&resolve, world_id, "evaluation-frame-v1"),
        [
            "fragment(string)",
            "conditional(bool)",
            "loop-frame(loop-frame-v1)"
        ]
    );
    assert_eq!(
        variant_cases(&resolve, world_id, "provenance-operation-v1"),
        [
            "variable-supplied",
            "variable-default",
            "variable-optional-absent",
            "variable-computed",
            "emit",
            "patch(u32)",
        ]
    );
    assert_eq!(
        variant_cases(&resolve, world_id, "diagnostic-location-v1"),
        ["source(source-location-v1)", "output(output-range-v1)"]
    );
    assert_eq!(
        enum_cases(&resolve, world_id, "diagnostic-severity-v1"),
        ["error", "warning", "info"]
    );
    assert_eq!(
        enum_cases(&resolve, world_id, "transform-failure-kind-v1"),
        [
            "invalid-request",
            "unsupported-format",
            "resource-limit",
            "invalid-result",
            "internal",
        ]
    );
    assert_eq!(api::FORMAT_COMPONENT_INTERFACE_V1, "format-component/v1");
    assert!(!api::WIT_SOURCE.contains("descriptor"));
    assert!(!api::WIT_SOURCE.contains("render"));
    assert!(!api::WIT_SOURCE.contains("validate"));
}

fn world_type<'a>(resolve: &'a Resolve, world: wit_parser::WorldId, name: &str) -> &'a TypeDefKind {
    &resolve
        .types
        .iter()
        .find(|(_, ty)| ty.owner == TypeOwner::World(world) && ty.name.as_deref() == Some(name))
        .unwrap_or_else(|| panic!("missing world type {name}"))
        .1
        .kind
}

fn record_fields(resolve: &Resolve, world: wit_parser::WorldId, name: &str) -> Vec<String> {
    let TypeDefKind::Record(record) = world_type(resolve, world, name) else {
        panic!("{name} is not a record")
    };
    record
        .fields
        .iter()
        .map(|field| format!("{}:{}", field.name, type_shape(resolve, field.ty)))
        .collect()
}

fn variant_cases(resolve: &Resolve, world: wit_parser::WorldId, name: &str) -> Vec<String> {
    let TypeDefKind::Variant(variant) = world_type(resolve, world, name) else {
        panic!("{name} is not a variant")
    };
    variant
        .cases
        .iter()
        .map(|case| match case.ty {
            Some(ty) => format!("{}({})", case.name, type_shape(resolve, ty)),
            None => case.name.clone(),
        })
        .collect()
}

fn enum_cases(resolve: &Resolve, world: wit_parser::WorldId, name: &str) -> Vec<String> {
    let TypeDefKind::Enum(value) = world_type(resolve, world, name) else {
        panic!("{name} is not an enum")
    };
    value.cases.iter().map(|case| case.name.clone()).collect()
}

fn type_shape(resolve: &Resolve, ty: Type) -> String {
    match ty {
        Type::Bool => "bool".to_owned(),
        Type::U8 => "u8".to_owned(),
        Type::U16 => "u16".to_owned(),
        Type::U32 => "u32".to_owned(),
        Type::U64 => "u64".to_owned(),
        Type::S8 => "s8".to_owned(),
        Type::S16 => "s16".to_owned(),
        Type::S32 => "s32".to_owned(),
        Type::S64 => "s64".to_owned(),
        Type::F32 => "f32".to_owned(),
        Type::F64 => "f64".to_owned(),
        Type::Char => "char".to_owned(),
        Type::String => "string".to_owned(),
        Type::ErrorContext => "error-context".to_owned(),
        Type::Id(id) => {
            let definition = &resolve.types[id];
            if let Some(name) = &definition.name {
                return name.clone();
            }
            match &definition.kind {
                TypeDefKind::List(inner) => format!("list<{}>", type_shape(resolve, *inner)),
                TypeDefKind::Option(inner) => format!("option<{}>", type_shape(resolve, *inner)),
                TypeDefKind::Result(result) => format!(
                    "result<{},{}>",
                    result
                        .ok
                        .map(|ty| type_shape(resolve, ty))
                        .unwrap_or_else(|| "_".to_owned()),
                    result
                        .err
                        .map(|ty| type_shape(resolve, ty))
                        .unwrap_or_else(|| "_".to_owned())
                ),
                kind => panic!("unsupported anonymous WIT type {kind:?}"),
            }
        }
    }
}
