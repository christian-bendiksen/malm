use std::collections::BTreeSet;

use kdl::{FormatConfig, KdlDocument, KdlEntry, KdlNode, KdlValue};
use malm_types::{Alias, ContributionName, Digest, PackageId};

use crate::{
    BundledComponentV1, ComponentInterfaceV1, DependencySourceV1, GitObjectId, GitSourceV1, GitUrl,
    LocalLocator, MAX_PACK_MANIFEST_BYTES, PACK_SCHEMA_VERSION, PackDependencyV1, PackManifestV1,
    PackModuleV1, PackPath, PackSubdir, PackValidationError,
};

/// Failure to decode a strict pack/v1 manifest.
#[derive(Debug, thiserror::Error)]
pub enum PackReadError {
    #[error("pack manifest is {actual} bytes; limit is {limit}")]
    TooLarge { limit: usize, actual: usize },
    #[error("pack manifest is not UTF-8")]
    InvalidUtf8,
    #[error("malformed pack KDL: {0}")]
    MalformedKdl(String),
    #[error("unsupported pack schema: expected exactly {expected}, found {found}")]
    UnsupportedVersion { expected: u32, found: i128 },
    #[error("invalid pack/v1 manifest: {0}")]
    InvalidManifest(String),
    #[error("invalid pack/v1 manifest: {0}")]
    InvalidSemantics(#[source] PackValidationError),
}

fn invalid_manifest(error: impl std::fmt::Display) -> PackReadError {
    PackReadError::InvalidManifest(error.to_string())
}

/// A `pack` section and its allowed item name.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SectionSpec {
    name: &'static str,
    item: &'static str,
}

impl SectionSpec {
    const fn new(name: &'static str, item: &'static str) -> Self {
        Self { name, item }
    }
}

const MODULES: SectionSpec = SectionSpec::new("modules", "module");
const CONFIG_DOCUMENTS: SectionSpec = SectionSpec::new("config-documents", "document");
const DEPENDENCIES: SectionSpec = SectionSpec::new("dependencies", "dependency");
const TEMPLATES: SectionSpec = SectionSpec::new("templates", "template");
const SCHEMAS: SectionSpec = SectionSpec::new("schemas", "schema");
const ASSETS: SectionSpec = SectionSpec::new("assets", "asset");
const COMPONENTS: SectionSpec = SectionSpec::new("components", "component");

/// Required sections in canonical encoding order.
///
/// The decoder also uses this list as its allowlist and requires each entry
/// exactly once.
const SECTIONS: [SectionSpec; 7] = [
    MODULES,
    CONFIG_DOCUMENTS,
    DEPENDENCIES,
    TEMPLATES,
    SCHEMAS,
    ASSETS,
    COMPONENTS,
];

const CAPTURES: SectionSpec = SectionSpec::new("captures", "include");

/// Decodes a bounded, strict KDL v2 pack/v1 manifest.
pub fn decode_pack_v1(bytes: &[u8]) -> Result<PackManifestV1, PackReadError> {
    if bytes.len() > MAX_PACK_MANIFEST_BYTES {
        return Err(PackReadError::TooLarge {
            limit: MAX_PACK_MANIFEST_BYTES,
            actual: bytes.len(),
        });
    }
    let text = std::str::from_utf8(bytes).map_err(|_| PackReadError::InvalidUtf8)?;
    let document = KdlDocument::parse_v2(text)
        .map_err(|error| PackReadError::MalformedKdl(error.to_string()))?;
    let root = exactly_one(document.nodes(), "top-level `pack` node")?;
    if root.name().value() != "pack" {
        return invalid(format!(
            "unknown top-level node {:?}; expected `pack`",
            root.name().value()
        ));
    }
    reject_node_annotation(root)?;
    reject_duplicate_properties(root)?;
    let version = required_integer_property(root, "schema-version")?;
    if version != i128::from(PACK_SCHEMA_VERSION) {
        return Err(PackReadError::UnsupportedVersion {
            expected: PACK_SCHEMA_VERSION,
            found: version,
        });
    }

    expect_shape(root, 0, &["schema-version", "package-id"], true)?;
    let package_id =
        PackageId::new(required_string_property(root, "package-id")?).map_err(invalid_manifest)?;
    let children = root.children().expect("required body validated");
    for child in children.nodes() {
        let name = child.name().value();
        if !SECTIONS.iter().any(|section| section.name == name) && name != CAPTURES.name {
            return invalid(format!("`pack` has unknown section {name:?}"));
        }
    }
    for section in SECTIONS {
        let matching = matching_sections(children, section);
        if matching.len() != 1 {
            return invalid(format!(
                "`pack` requires exactly one `{}` section, found {}",
                section.name,
                matching.len()
            ));
        }
        expect_shape(matching[0], 0, &[], true)?;
    }
    let capture_sections = matching_sections(children, CAPTURES);
    if capture_sections.len() > 1 {
        return invalid(format!(
            "`pack` permits at most one `{}` section, found {}",
            CAPTURES.name,
            capture_sections.len()
        ));
    }
    let capture_roots = match capture_sections.first() {
        Some(node) => {
            expect_shape(node, 0, &[], true)?;
            parse_path_section(node, CAPTURES.item)?
        }
        None => Vec::new(),
    };

    let modules = parse_modules(section(children, MODULES))?;
    let config_documents =
        parse_path_section(section(children, CONFIG_DOCUMENTS), CONFIG_DOCUMENTS.item)?;
    let dependencies = parse_dependencies(section(children, DEPENDENCIES))?;
    let templates = parse_path_section(section(children, TEMPLATES), TEMPLATES.item)?;
    let schemas = parse_path_section(section(children, SCHEMAS), SCHEMAS.item)?;
    let assets = parse_path_section(section(children, ASSETS), ASSETS.item)?;
    let components = parse_components(section(children, COMPONENTS))?;

    PackManifestV1::new(
        package_id,
        modules,
        dependencies,
        templates,
        schemas,
        assets,
        components,
    )
    .and_then(|manifest| manifest.with_config_documents(config_documents))
    .and_then(|manifest| manifest.with_capture_roots(capture_roots))
    .map_err(PackReadError::InvalidSemantics)
}

fn matching_sections(document: &KdlDocument, section: SectionSpec) -> Vec<&KdlNode> {
    document
        .nodes()
        .iter()
        .filter(|node| node.name().value() == section.name)
        .collect()
}

fn section(document: &KdlDocument, section: SectionSpec) -> &KdlNode {
    document
        .nodes()
        .iter()
        .find(|node| node.name().value() == section.name)
        .expect("required section validated")
}

/// Validates each section item before passing it to `build`.
fn parse_section<T>(
    section: &KdlNode,
    item: &str,
    arguments: usize,
    properties: &[&str],
    requires_body: bool,
    build: impl Fn(&KdlNode) -> Result<T, PackReadError>,
) -> Result<Vec<T>, PackReadError> {
    section
        .children()
        .expect("required body validated")
        .nodes()
        .iter()
        .map(|node| {
            expect_node_name(node, item)?;
            expect_shape(node, arguments, properties, requires_body)?;
            build(node)
        })
        .collect()
}

fn parse_modules(section: &KdlNode) -> Result<Vec<PackModuleV1>, PackReadError> {
    parse_section(section, MODULES.item, 1, &["path"], false, |node| {
        let name =
            ContributionName::new(required_string_argument(node)?).map_err(invalid_manifest)?;
        let path =
            PackPath::new(required_string_property(node, "path")?).map_err(invalid_manifest)?;
        Ok(PackModuleV1::new(name, path))
    })
}

fn parse_dependencies(section: &KdlNode) -> Result<Vec<PackDependencyV1>, PackReadError> {
    parse_section(
        section,
        DEPENDENCIES.item,
        1,
        &["package-id"],
        true,
        |node| {
            let alias = Alias::new(required_string_argument(node)?).map_err(invalid_manifest)?;
            let package_id = PackageId::new(required_string_property(node, "package-id")?)
                .map_err(invalid_manifest)?;
            let source_node = exactly_one(
                node.children().expect("required body validated").nodes(),
                "dependency source",
            )?;
            let source = match source_node.name().value() {
                "git" => {
                    expect_shape(source_node, 0, &["url", "commit", "subdir"], false)?;
                    let url = GitUrl::new(required_string_property(source_node, "url")?)
                        .map_err(invalid_manifest)?;
                    let commit = GitObjectId::new(required_string_property(source_node, "commit")?)
                        .map_err(invalid_manifest)?;
                    let subdir = PackSubdir::new(required_string_property(source_node, "subdir")?)
                        .map_err(invalid_manifest)?;
                    DependencySourceV1::Git(GitSourceV1::new(url, commit, subdir))
                }
                "local" => {
                    expect_shape(source_node, 0, &["workspace-path"], false)?;
                    let locator =
                        LocalLocator::new(required_string_property(source_node, "workspace-path")?)
                            .map_err(invalid_manifest)?;
                    DependencySourceV1::Local(locator)
                }
                other => {
                    return invalid(format!(
                        "unknown dependency source `{other}`; expected `git` or `local`"
                    ));
                }
            };
            Ok(PackDependencyV1::new(alias, package_id, source))
        },
    )
}

fn parse_path_section(section: &KdlNode, item: &str) -> Result<Vec<PackPath>, PackReadError> {
    parse_section(section, item, 1, &[], false, |node| {
        PackPath::new(required_string_argument(node)?).map_err(invalid_manifest)
    })
}

fn parse_components(section: &KdlNode) -> Result<Vec<BundledComponentV1>, PackReadError> {
    parse_section(
        section,
        COMPONENTS.item,
        1,
        &["path", "digest", "interface"],
        false,
        |node| {
            let name =
                ContributionName::new(required_string_argument(node)?).map_err(invalid_manifest)?;
            let path =
                PackPath::new(required_string_property(node, "path")?).map_err(invalid_manifest)?;
            let digest =
                Digest::new(required_string_property(node, "digest")?).map_err(invalid_manifest)?;
            let interface = required_string_property(node, "interface")?;
            if interface != ComponentInterfaceV1::FormatComponentV1.as_str() {
                return invalid(format!(
                    "`component` interface must be {:?}, found {interface:?}",
                    ComponentInterfaceV1::FormatComponentV1.as_str()
                ));
            }
            Ok(BundledComponentV1::new(
                name,
                path,
                digest,
                ComponentInterfaceV1::FormatComponentV1,
            ))
        },
    )
}

fn exactly_one<'a>(nodes: &'a [KdlNode], what: &str) -> Result<&'a KdlNode, PackReadError> {
    if nodes.len() != 1 {
        return invalid(format!(
            "expected exactly one {what}, found {}",
            nodes.len()
        ));
    }
    Ok(&nodes[0])
}

fn expect_node_name(node: &KdlNode, expected: &str) -> Result<(), PackReadError> {
    if node.name().value() != expected {
        return invalid(format!(
            "unknown node {:?}; expected `{expected}`",
            node.name().value()
        ));
    }
    Ok(())
}

fn expect_shape(
    node: &KdlNode,
    arguments: usize,
    properties: &[&str],
    requires_body: bool,
) -> Result<(), PackReadError> {
    reject_node_annotation(node)?;
    reject_duplicate_properties(node)?;
    let actual_arguments = node
        .entries()
        .iter()
        .filter(|entry| entry.name().is_none())
        .count();
    if actual_arguments != arguments {
        return invalid(format!(
            "`{}` expects {arguments} arguments, found {actual_arguments}",
            node.name().value()
        ));
    }
    for entry in node.entries() {
        if entry.ty().is_some() {
            return invalid(format!(
                "`{}` does not permit type annotations",
                node.name().value()
            ));
        }
        if let Some(name) = entry.name()
            && !properties.contains(&name.value())
        {
            return invalid(format!(
                "`{}` has unknown property {:?}",
                node.name().value(),
                name.value()
            ));
        }
    }
    for property in properties {
        if node
            .entries()
            .iter()
            .all(|entry| entry.name().is_none_or(|name| name.value() != *property))
        {
            return invalid(format!(
                "`{}` is missing required property `{property}`",
                node.name().value()
            ));
        }
    }
    match (requires_body, node.children()) {
        (true, None) => return invalid(format!("`{}` requires a body", node.name().value())),
        (false, Some(_)) => {
            return invalid(format!("`{}` does not permit a body", node.name().value()));
        }
        _ => {}
    }
    Ok(())
}

fn reject_node_annotation(node: &KdlNode) -> Result<(), PackReadError> {
    if node.ty().is_some() {
        return invalid(format!(
            "`{}` does not permit a type annotation",
            node.name().value()
        ));
    }
    Ok(())
}

fn reject_duplicate_properties(node: &KdlNode) -> Result<(), PackReadError> {
    let mut seen = BTreeSet::new();
    for entry in node.entries() {
        if let Some(name) = entry.name()
            && !seen.insert(name.value())
        {
            return invalid(format!(
                "`{}` sets property {:?} more than once",
                node.name().value(),
                name.value()
            ));
        }
    }
    Ok(())
}

fn required_string_argument(node: &KdlNode) -> Result<String, PackReadError> {
    node.entries()
        .iter()
        .find(|entry| entry.name().is_none())
        .and_then(|entry| entry.value().as_string())
        .map(str::to_owned)
        .ok_or_else(|| {
            PackReadError::InvalidManifest(format!(
                "`{}` requires a string argument",
                node.name().value()
            ))
        })
}

fn required_string_property(node: &KdlNode, name: &str) -> Result<String, PackReadError> {
    property(node, name)
        .and_then(KdlValue::as_string)
        .map(str::to_owned)
        .ok_or_else(|| {
            PackReadError::InvalidManifest(format!(
                "`{}` property `{name}` must be a string",
                node.name().value()
            ))
        })
}

fn required_integer_property(node: &KdlNode, name: &str) -> Result<i128, PackReadError> {
    property(node, name)
        .and_then(KdlValue::as_integer)
        .ok_or_else(|| {
            PackReadError::InvalidManifest(format!(
                "`{}` property `{name}` must be an integer",
                node.name().value()
            ))
        })
}

fn property<'a>(node: &'a KdlNode, name: &str) -> Option<&'a KdlValue> {
    node.entries()
        .iter()
        .find(|entry| entry.name().is_some_and(|key| key.value() == name))
        .map(KdlEntry::value)
}

fn invalid<T>(detail: impl Into<String>) -> Result<T, PackReadError> {
    Err(PackReadError::InvalidManifest(detail.into()))
}

/// Encodes a validated manifest with deterministic KDL v2 formatting.
#[must_use]
pub fn encode_pack_v1(manifest: &PackManifestV1) -> String {
    let mut root = KdlNode::new("pack");
    root.insert("schema-version", i128::from(PACK_SCHEMA_VERSION));
    root.insert("package-id", manifest.package_id().as_str());

    // Section order is part of the encoded manifest and its content digest.
    let mut body = KdlDocument::new();
    for spec in SECTIONS {
        let children: Vec<KdlNode> = if spec == MODULES {
            manifest.modules().iter().map(module_node).collect()
        } else if spec == CONFIG_DOCUMENTS {
            path_nodes(CONFIG_DOCUMENTS, manifest.config_documents()).collect()
        } else if spec == DEPENDENCIES {
            manifest
                .dependencies()
                .iter()
                .map(dependency_node)
                .collect()
        } else if spec == TEMPLATES {
            path_nodes(TEMPLATES, manifest.templates()).collect()
        } else if spec == SCHEMAS {
            path_nodes(SCHEMAS, manifest.schemas()).collect()
        } else if spec == ASSETS {
            path_nodes(ASSETS, manifest.assets()).collect()
        } else {
            assert_eq!(spec, COMPONENTS, "SECTIONS is exhaustive");
            manifest.components().iter().map(component_node).collect()
        };
        body.nodes_mut().push(section_node(spec, children));
    }
    // Empty capture roots are omitted from the canonical encoding.
    if !manifest.capture_roots().is_empty() {
        body.nodes_mut().push(section_node(
            CAPTURES,
            path_nodes(CAPTURES, manifest.capture_roots()).collect::<Vec<_>>(),
        ));
    }
    root.set_children(body);

    let mut document = KdlDocument::new();
    document.nodes_mut().push(root);
    let format = FormatConfig::builder()
        .indent("    ")
        .no_comments(true)
        .build();
    document.autoformat_config(&format);
    document.to_string()
}

fn section_node(section: SectionSpec, children: impl IntoIterator<Item = KdlNode>) -> KdlNode {
    let mut node = KdlNode::new(section.name);
    let mut document = KdlDocument::new();
    document.nodes_mut().extend(children);
    node.set_children(document);
    node
}

fn path_nodes(section: SectionSpec, paths: &[PackPath]) -> impl Iterator<Item = KdlNode> + use<'_> {
    paths.iter().map(move |path| {
        let mut node = KdlNode::new(section.item);
        node.push(path.as_str());
        node
    })
}

fn module_node(module: &PackModuleV1) -> KdlNode {
    let mut node = KdlNode::new(MODULES.item);
    node.push(module.name().as_str());
    node.insert("path", module.path().as_str());
    node
}

fn dependency_node(dependency: &PackDependencyV1) -> KdlNode {
    let mut node = KdlNode::new(DEPENDENCIES.item);
    node.push(dependency.alias().as_str());
    node.insert("package-id", dependency.package_id().as_str());

    let mut source = match dependency.source() {
        DependencySourceV1::Git(git) => {
            let mut source = KdlNode::new("git");
            source.insert("url", git.url().as_str());
            source.insert("commit", git.commit().as_str());
            source.insert("subdir", git.subdir().as_str());
            source
        }
        DependencySourceV1::Local(locator) => {
            let mut source = KdlNode::new("local");
            source.insert("workspace-path", locator.as_str());
            source
        }
    };
    source.clear_children();
    let mut children = KdlDocument::new();
    children.nodes_mut().push(source);
    node.set_children(children);
    node
}

fn component_node(component: &BundledComponentV1) -> KdlNode {
    let mut node = KdlNode::new(COMPONENTS.item);
    node.push(component.name().as_str());
    node.insert("path", component.path().as_str());
    node.insert("digest", component.digest().as_str());
    node.insert("interface", component.interface().as_str());
    node
}
