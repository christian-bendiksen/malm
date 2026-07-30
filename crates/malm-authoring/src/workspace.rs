//! Include-walking workspace loader over a captured source set.
//!
//! Includes are bounded, root sections are restricted, and unknown nodes are
//! rejected. The loader reads only from the supplied [`AuthoringSourceSetV1`].
//! It records `~/` and absolute includes without following them so the host can
//! provide their values through explicit overlays.

use crate::lang::ast::ParsedWorkspace;
use crate::lang::diag::{Diagnostics, FileId, SourceMap};
use crate::lang::parse::{
    parse_extend_module, parse_extend_profile, parse_globals, parse_module, parse_profile,
    parse_slots,
};
use crate::{AuthoringSourceSetV1, MAX_AUTHORING_DOCUMENT_BYTES};
use kdl::{KdlDocument, KdlNode};
use std::collections::HashSet;
use std::path::{Path, PathBuf};

/// Maximum total bytes across every included document.
const MAX_TOTAL_DOCUMENT_BYTES: usize = 4 * 1024 * 1024;
/// Maximum include nesting depth.
const MAX_INCLUDE_DEPTH: usize = 16;
/// Maximum number of included documents.
const MAX_DOCUMENTS: usize = 64;

/// The root `config` node.
#[derive(Clone, Debug)]
pub struct ConfigSettings {
    pub target: String,
    pub default_profile: Option<String>,
    pub required_state: Option<String>,
}

/// The root `meta` node.
#[derive(Clone, Debug, Default)]
pub struct MetaSection {
    pub name: Option<String>,
    pub author: Option<String>,
    pub homepage: Option<String>,
    pub malm_version: Option<String>,
}

/// One `asset` declaration inside the root `assets` node.
#[derive(Clone, Debug)]
pub struct AssetEntry {
    pub name: String,
    pub url: String,
    pub dst: String,
    pub format: String,
    pub sha256: Option<String>,
    /// Pack-relative vendored payload path. Deployment reads the archive
    /// from the captured pack; `url` remains acquisition provenance for the
    /// vendoring tool.
    pub path: Option<String>,
    pub installed_check: Option<String>,
    pub refresh_font_cache: bool,
}

/// The root `assets` node.
#[derive(Clone, Debug, Default)]
pub struct AssetManifest {
    pub require_sha256: bool,
    pub assets: Vec<AssetEntry>,
}

/// One root `overlay` declaration: a machine-local, value-only document the
/// host may supply at evaluation time. The pure evaluator never reads the
/// declared path itself.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OverlayDeclV1 {
    name: String,
    path: String,
    optional: bool,
}

impl OverlayDeclV1 {
    /// Returns the overlay's declared name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the declared host path, preserving its `~/` spelling.
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Returns whether a missing overlay file is tolerated.
    #[must_use]
    pub const fn optional(&self) -> bool {
        self.optional
    }
}

/// One overlay document supplied by the host for evaluation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OverlaySourceV1 {
    name: String,
    bytes: Vec<u8>,
}

impl OverlaySourceV1 {
    /// Creates one supplied overlay document.
    #[must_use]
    pub fn new(name: String, bytes: Vec<u8>) -> Self {
        Self { name, bytes }
    }

    /// Returns the declared overlay name this document satisfies.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the exact supplied bytes.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// Everything loaded from one authoring source tree.
pub struct LoadedWorkspace {
    pub settings: ConfigSettings,
    pub meta: Option<MetaSection>,
    pub assets: Option<AssetManifest>,
    pub parsed: ParsedWorkspace,
    pub source_map: SourceMap,
    /// Root `overlay` declarations in document order.
    pub overlays: Vec<OverlayDeclV1>,
    /// `~/` or absolute includes that were recorded but never read.
    pub external_includes_skipped: Vec<String>,
}

/// Walks the include closure from `entry` and parses every document.
///
/// Structural violations (limits, cycles, malformed root sections, unknown
/// top-level nodes) fail the load; language-level problems inside modules
/// and profiles accumulate as diagnostics.
pub(crate) fn load_workspace(
    sources: &AuthoringSourceSetV1,
    entry: &str,
    overlays: &[OverlaySourceV1],
    diagnostics: &mut Diagnostics,
) -> Result<LoadedWorkspace, String> {
    let mut walker = Walker {
        sources,
        stack: Vec::new(),
        visited: HashSet::new(),
        seen_count: 0,
        total_bytes: 0,
        source_map: SourceMap::new(),
        settings: None,
        meta: None,
        assets: None,
        overlays: Vec::new(),
        parsed: ParsedWorkspace::default(),
        external_includes_skipped: Vec::new(),
    };
    walker.expand_document(entry, true, diagnostics)?;
    let settings = walker
        .settings
        .ok_or_else(|| format!("{entry}: missing required `config` node"))?;
    let mut loaded = LoadedWorkspace {
        settings,
        meta: walker.meta,
        assets: walker.assets,
        parsed: walker.parsed,
        source_map: walker.source_map,
        overlays: walker.overlays,
        external_includes_skipped: walker.external_includes_skipped,
    };
    // Apply overlays after captured documents and in declaration order, so
    // later overlay values take precedence.
    for supplied in overlays {
        if !loaded
            .overlays
            .iter()
            .any(|declared| declared.name() == supplied.name())
        {
            return Err(format!(
                "supplied overlay `{}` is not declared by the root configuration",
                supplied.name()
            ));
        }
    }
    for declared in &loaded.overlays {
        let Some(supplied) = overlays
            .iter()
            .find(|supplied| supplied.name() == declared.name())
        else {
            continue;
        };
        apply_overlay(
            declared,
            supplied.bytes(),
            &mut loaded.parsed,
            &mut loaded.source_map,
            diagnostics,
        )?;
    }
    Ok(loaded)
}

/// Parses one supplied overlay document under the value-only grammar and
/// layers its declarations onto the workspace.
///
/// Overlays may set `variables`, extend profiles with `use`/`with`/`patch`
/// values or slot `replace`, and extend modules with `requires` and input
/// declarations. Outputs, fragments, includes, and new modules or profiles
/// are rejected because they could reference bytes outside the captured pack.
/// Evaluation therefore depends only on the captured pack and supplied
/// overlay bytes.
fn apply_overlay(
    declared: &OverlayDeclV1,
    bytes: &[u8],
    parsed: &mut ParsedWorkspace,
    source_map: &mut SourceMap,
    diagnostics: &mut Diagnostics,
) -> Result<(), String> {
    let name = declared.name();
    if bytes.len() > MAX_AUTHORING_DOCUMENT_BYTES {
        return Err(format!(
            "overlay `{name}` is too large ({} bytes, max {MAX_AUTHORING_DOCUMENT_BYTES})",
            bytes.len()
        ));
    }
    let text = std::str::from_utf8(bytes)
        .map_err(|_| format!("overlay `{name}` is not UTF-8"))?
        .to_owned();
    let document: KdlDocument = text
        .parse()
        .map_err(|error: kdl::KdlError| format!("parse overlay `{name}`: {error}"))?;
    let label = format!("overlay `{name}` ({})", declared.path());
    let file_id = source_map.add(PathBuf::from(declared.path()), text, Vec::new());

    for node in document.nodes() {
        match node.name().value() {
            "variables" => match parse_globals(file_id, node, &label) {
                Ok(globals) => parsed.globals.extend(globals),
                Err(diagnostic) => diagnostics.push(diagnostic),
            },
            "extend-profile" => match parse_extend_profile(file_id, Path::new(""), node) {
                Ok(extension) => {
                    for item in &extension.items {
                        if let crate::lang::ast::ProfileItem::Use(use_decl) = item
                            && !use_decl.config.fragments.is_empty()
                        {
                            return Err(format!(
                                "{label}: fragment operations are not allowed in                                      overlays (they reference files outside the pack)"
                            ));
                        }
                    }
                    parsed.profile_extensions.push(extension);
                }
                Err(diagnostic) => diagnostics.push(diagnostic),
            },
            "extend-module" => match parse_extend_module(file_id, Path::new(""), node) {
                Ok(extension) => {
                    if !extension.fragments.is_empty() || !extension.outputs.is_empty() {
                        return Err(format!(
                            "{label}: fragment and output declarations are not allowed                              in overlays (they reference files outside the pack)"
                        ));
                    }
                    parsed.extensions.push(extension);
                }
                Err(diagnostic) => diagnostics.push(diagnostic),
            },
            other => {
                return Err(format!(
                    "{label}: `{other}` is not allowed in an overlay                      (allowed: variables, extend-profile, extend-module)"
                ));
            }
        }
    }
    Ok(())
}

struct Walker<'a> {
    sources: &'a AuthoringSourceSetV1,
    stack: Vec<String>,
    visited: HashSet<String>,
    seen_count: usize,
    total_bytes: usize,
    source_map: SourceMap,
    settings: Option<ConfigSettings>,
    meta: Option<MetaSection>,
    assets: Option<AssetManifest>,
    overlays: Vec<OverlayDeclV1>,
    parsed: ParsedWorkspace,
    external_includes_skipped: Vec<String>,
}

impl Walker<'_> {
    fn expand_document(
        &mut self,
        path: &str,
        root: bool,
        diagnostics: &mut Diagnostics,
    ) -> Result<(), String> {
        if self.stack.len() >= MAX_INCLUDE_DEPTH {
            return Err(format!(
                "maximum include depth ({MAX_INCLUDE_DEPTH}) exceeded at {path}"
            ));
        }
        if self.stack.iter().any(|active| active == path) {
            let mut chain = self.stack.clone();
            chain.push(path.to_owned());
            return Err(format!("include cycle detected: {}", chain.join(" -> ")));
        }
        if self.seen_count >= MAX_DOCUMENTS {
            return Err(format!(
                "maximum config document count ({MAX_DOCUMENTS}) exceeded"
            ));
        }
        if !self.visited.insert(path.to_owned()) {
            return Ok(());
        }

        let Some(bytes) = self.sources.get(path) else {
            return Err(format!("config document not captured: {path}"));
        };
        if bytes.len() > MAX_AUTHORING_DOCUMENT_BYTES {
            return Err(format!(
                "config document is too large ({} bytes, max {MAX_AUTHORING_DOCUMENT_BYTES}): {path}",
                bytes.len()
            ));
        }
        self.total_bytes += bytes.len();
        if self.total_bytes > MAX_TOTAL_DOCUMENT_BYTES {
            return Err(format!(
                "included configuration exceeds {MAX_TOTAL_DOCUMENT_BYTES} total bytes"
            ));
        }
        self.seen_count += 1;

        let text = std::str::from_utf8(bytes)
            .map_err(|_| format!("configuration is not UTF-8: {path}"))?
            .to_owned();
        let document: KdlDocument = text
            .parse()
            .map_err(|error: kdl::KdlError| format!("parse {path}: {error}"))?;
        let file_id = self.source_map.add(
            PathBuf::from(path),
            text,
            self.stack.iter().map(PathBuf::from).collect(),
        );

        self.stack.push(path.to_owned());
        let result = (|| {
            for node in document.nodes() {
                if node.name().value() == "include" {
                    self.expand_include(node, path, diagnostics)?;
                    continue;
                }
                if !root
                    && matches!(
                        node.name().value(),
                        "config" | "meta" | "assets" | "overlay"
                    )
                {
                    return Err(format!(
                        "{path}: `{}` is only allowed in the root configuration",
                        node.name().value()
                    ));
                }
                self.consume_node(node, path, file_id, diagnostics)?;
            }
            Ok(())
        })();
        self.stack.pop();
        result
    }

    fn consume_node(
        &mut self,
        node: &KdlNode,
        path: &str,
        file: FileId,
        diagnostics: &mut Diagnostics,
    ) -> Result<(), String> {
        let dir = Path::new(path)
            .parent()
            .unwrap_or_else(|| Path::new(""))
            .to_path_buf();
        match node.name().value() {
            "config" => {
                if self.settings.is_some() {
                    return Err(format!("{path}: duplicate `config` node"));
                }
                reject_unknown_props(node, &["target", "default-profile", "required-state"])?;
                reject_unknown_children(node, &[])?;
                expect_arg_count(node, 0)?;
                self.settings = Some(ConfigSettings {
                    target: req_str_prop(node, "target")?,
                    default_profile: opt_str_prop(node, "default-profile")?,
                    required_state: opt_str_prop(node, "required-state")?,
                });
            }
            "meta" => {
                if self.meta.is_some() {
                    return Err(format!("{path}: duplicate `meta` node"));
                }
                reject_unknown_props(node, &["name", "author", "homepage", "malm-version"])?;
                reject_unknown_children(node, &[])?;
                expect_arg_count(node, 0)?;
                self.meta = Some(MetaSection {
                    name: opt_str_prop(node, "name")?,
                    author: opt_str_prop(node, "author")?,
                    homepage: opt_str_prop(node, "homepage")?,
                    malm_version: opt_str_prop(node, "malm-version")?,
                });
            }
            "assets" => {
                if self.assets.is_some() {
                    return Err(format!("{path}: duplicate `assets` node"));
                }
                self.assets = Some(parse_asset_manifest(node)?);
            }
            "variables" => match parse_globals(file, node, path) {
                Ok(globals) => self.parsed.globals.extend(globals),
                Err(diagnostic) => diagnostics.push(diagnostic),
            },
            "module" => match parse_module(file, &dir, node) {
                Ok(module) => self.parsed.modules.push(module),
                Err(diagnostic) => diagnostics.push(diagnostic),
            },
            "extend-module" => match parse_extend_module(file, &dir, node) {
                Ok(extension) => self.parsed.extensions.push(extension),
                Err(diagnostic) => diagnostics.push(diagnostic),
            },
            "profile" => match parse_profile(file, &dir, node) {
                Ok(profile) => self.parsed.profiles.push(profile),
                Err(diagnostic) => diagnostics.push(diagnostic),
            },
            "extend-profile" => match parse_extend_profile(file, &dir, node) {
                Ok(extension) => self.parsed.profile_extensions.push(extension),
                Err(diagnostic) => diagnostics.push(diagnostic),
            },
            "overlay" => {
                reject_unknown_props(node, &["path", "optional"])?;
                reject_unknown_children(node, &[])?;
                let name = req_str_arg(node)?;
                let overlay_path = req_str_prop(node, "path")?;
                if overlay_path != "~"
                    && !overlay_path.starts_with("~/")
                    && !Path::new(&overlay_path).is_absolute()
                {
                    return Err(format!(
                        "{path}: overlay `{name}` path must be `~/`-relative or absolute                          (pack-internal documents use `include`)"
                    ));
                }
                if self.overlays.iter().any(|overlay| overlay.name == name) {
                    return Err(format!("{path}: duplicate overlay `{name}`"));
                }
                self.overlays.push(OverlayDeclV1 {
                    name,
                    path: overlay_path,
                    optional: bool_prop(node, "optional")?,
                });
            }
            "slots" => match parse_slots(file, node) {
                Ok(slots) => self.parsed.slots.extend(slots),
                Err(diagnostic) => diagnostics.push(diagnostic),
            },
            other => {
                return Err(format!(
                    "{path}: unknown top-level node `{other}` (allowed: config, meta, assets, \
                     variables, module, extend-module, profile, extend-profile, slots, include, \
                     overlay)"
                ));
            }
        }
        Ok(())
    }

    fn expand_include(
        &mut self,
        node: &KdlNode,
        including: &str,
        diagnostics: &mut Diagnostics,
    ) -> Result<(), String> {
        reject_unknown_props(node, &["optional"])?;
        reject_unknown_children(node, &[])?;
        let raw = req_str_arg(node)?;
        let optional = bool_prop(node, "optional")?;

        // External includes are recorded but never read. The host can provide
        // machine-local values through an explicit overlay.
        if raw == "~" || raw.starts_with("~/") || Path::new(&raw).is_absolute() {
            if !self.external_includes_skipped.contains(&raw) {
                self.external_includes_skipped.push(raw);
            }
            return Ok(());
        }

        let joined = Path::new(including)
            .parent()
            .unwrap_or_else(|| Path::new(""))
            .join(&raw);
        let normalized = crate::paths::normalize_lexical(&joined);
        if normalized.starts_with("..") {
            return Err(format!(
                "{including}: include `{raw}` escapes the source root"
            ));
        }
        let Some(resolved) = normalized.to_str() else {
            return Err(format!("{including}: include `{raw}` is not valid UTF-8"));
        };
        if self.sources.get(resolved).is_none() {
            if optional {
                return Ok(());
            }
            return Err(format!(
                "{including}: included document not captured: {resolved}"
            ));
        }
        self.expand_document(resolved, false, diagnostics)
    }
}

fn parse_asset_manifest(node: &KdlNode) -> Result<AssetManifest, String> {
    reject_unknown_props(node, &["require-sha256"])?;
    reject_unknown_children(node, &["asset"])?;
    expect_arg_count(node, 0)?;
    let require_sha256 = if node.get("require-sha256").is_some() {
        bool_prop(node, "require-sha256")?
    } else {
        true
    };
    let mut assets: Vec<AssetEntry> = Vec::new();
    if let Some(children) = node.children() {
        for child in children.nodes() {
            let asset = parse_asset_entry(child)?;
            if assets.iter().any(|existing| existing.name == asset.name) {
                return Err(format!("assets: duplicate asset name `{}`", asset.name));
            }
            if require_sha256 && asset.sha256.is_none() {
                return Err(format!("asset `{}`: missing required `sha256`", asset.name));
            }
            assets.push(asset);
        }
    }
    Ok(AssetManifest {
        require_sha256,
        assets,
    })
}

fn parse_asset_entry(node: &KdlNode) -> Result<AssetEntry, String> {
    reject_unknown_props(node, &[])?;
    expect_arg_count(node, 1)?;
    reject_unknown_children(
        node,
        &[
            "url",
            "dst",
            "format",
            "sha256",
            "path",
            "installed-check",
            "refresh-font-cache",
        ],
    )?;
    let name = node
        .get(0)
        .and_then(|value| value.as_string())
        .ok_or("`asset` node: missing name argument")?
        .to_owned();
    if name.is_empty()
        || !name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
    {
        return Err(format!("asset name `{name}` contains invalid characters"));
    }
    let url = req_child_str(node, "url", &name)?;
    if !url.starts_with("https://") {
        return Err(format!("asset `{name}`: url must use https://"));
    }
    let dst = req_child_str(node, "dst", &name)?;
    let format = req_child_str(node, "format", &name)?;
    // This list must stay exactly what `lower_asset` can deploy, or a pack that
    // passes `source check` fails at deploy instead.
    if !matches!(format.as_str(), "tar" | "tar-xz" | "tar-gz") {
        return Err(format!(
            "asset `{name}`: unknown format `{format}` (allowed: tar, tar-xz, tar-gz)"
        ));
    }
    let sha256 = opt_child_str(node, "sha256", &name)?;
    if let Some(digest) = &sha256
        && (digest.len() != 64
            || !digest
                .chars()
                .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c)))
    {
        return Err(format!(
            "asset `{name}`: sha256 must be 64 lowercase hex characters"
        ));
    }
    let path = opt_child_str(node, "path", &name)?;
    if let Some(path) = &path
        && (path.is_empty()
            || path.starts_with('/')
            || path.starts_with("~")
            || path
                .split('/')
                .any(|segment| segment.is_empty() || segment == "." || segment == ".."))
    {
        return Err(format!(
            "asset `{name}`: path must be a plain pack-relative file path"
        ));
    }
    let installed_check = opt_child_str(node, "installed-check", &name)?;
    let refresh_font_cache = match child_node(node, "refresh-font-cache") {
        None => false,
        Some(child) => child
            .get(0)
            .and_then(|value| value.as_bool())
            .ok_or_else(|| format!("asset `{name}`: refresh-font-cache must be a boolean"))?,
    };
    Ok(AssetEntry {
        name,
        url,
        dst,
        format,
        sha256,
        path,
        installed_check,
        refresh_font_cache,
    })
}

fn child_node<'a>(node: &'a KdlNode, name: &str) -> Option<&'a KdlNode> {
    node.children()?
        .nodes()
        .iter()
        .find(|child| child.name().value() == name)
}

fn req_child_str(node: &KdlNode, name: &str, asset: &str) -> Result<String, String> {
    opt_child_str(node, name, asset)?
        .ok_or_else(|| format!("asset `{asset}`: missing required `{name}`"))
}

fn opt_child_str(node: &KdlNode, name: &str, asset: &str) -> Result<Option<String>, String> {
    let Some(child) = child_node(node, name) else {
        return Ok(None);
    };
    child
        .get(0)
        .and_then(|value| value.as_string())
        .map(|value| Some(value.to_owned()))
        .ok_or_else(|| format!("asset `{asset}`: `{name}` must be a string"))
}

fn reject_unknown_props(node: &KdlNode, allowed: &[&str]) -> Result<(), String> {
    let mut seen: Vec<&str> = Vec::new();
    for entry in node.iter() {
        if let Some(key) = entry.name() {
            let name = key.value();
            if !allowed.contains(&name) {
                return Err(format!(
                    "`{}` node: unknown property `{name}`{}",
                    node.name().value(),
                    if allowed.is_empty() {
                        String::new()
                    } else {
                        format!(" (allowed: {})", allowed.join(", "))
                    }
                ));
            }
            if seen.contains(&name) {
                return Err(format!(
                    "`{}` node: duplicate property `{name}`",
                    node.name().value()
                ));
            }
            seen.push(name);
        }
    }
    Ok(())
}

fn reject_unknown_children(node: &KdlNode, allowed: &[&str]) -> Result<(), String> {
    let Some(children) = node.children() else {
        return Ok(());
    };
    for child in children.nodes() {
        let name = child.name().value();
        if !allowed.contains(&name) {
            return Err(format!(
                "`{}` node: unknown child `{name}`{}",
                node.name().value(),
                if allowed.is_empty() {
                    String::new()
                } else {
                    format!(" (allowed: {})", allowed.join(", "))
                }
            ));
        }
    }
    Ok(())
}

fn bool_prop(node: &KdlNode, prop: &str) -> Result<bool, String> {
    match node.get(prop) {
        None => Ok(false),
        Some(value) => value.as_bool().ok_or_else(|| {
            format!(
                "`{}` node: property `{prop}` must be a boolean (#true or #false)",
                node.name().value()
            )
        }),
    }
}

fn expect_arg_count(node: &KdlNode, expected: usize) -> Result<(), String> {
    let count = node.iter().filter(|entry| entry.name().is_none()).count();
    if count != expected {
        return Err(format!(
            "`{}` node: expected {expected} positional argument(s), found {count}",
            node.name().value()
        ));
    }
    Ok(())
}

fn req_str_arg(node: &KdlNode) -> Result<String, String> {
    expect_arg_count(node, 1)?;
    node.get(0)
        .and_then(|value| value.as_string())
        .map(str::to_owned)
        .ok_or_else(|| {
            format!(
                "`{}` node: missing required string argument",
                node.name().value()
            )
        })
}

fn req_str_prop(node: &KdlNode, prop: &str) -> Result<String, String> {
    opt_str_prop(node, prop)?.ok_or_else(|| {
        format!(
            "`{}` node: missing required property `{prop}`",
            node.name().value()
        )
    })
}

fn opt_str_prop(node: &KdlNode, prop: &str) -> Result<Option<String>, String> {
    let Some(value) = node.get(prop) else {
        return Ok(None);
    };
    value
        .as_string()
        .map(|value| Some(value.to_owned()))
        .ok_or_else(|| {
            format!(
                "`{}` node: property `{prop}` must be a string",
                node.name().value()
            )
        })
}
