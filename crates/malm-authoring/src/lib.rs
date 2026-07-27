//! Pure evaluation of the Malm authoring dialect (`config` root documents).
//!
//! This crate parses or evaluates explicitly supplied values and captured bytes only.
//! It has no filesystem, environment, source-acquisition, network, process, clock,
//! randomness, effectful rendering, CLI, target, or store access.
//!
//! The authoring dialect is the human-written source language: a root `config`
//! document with `variables`, `assets`, and `include`s, module packages with
//! typed `inputs`, `fragments`, and `outputs`, and profiles composed through
//! `extends`, `use`/`with`, slot `replace`, and keyed-collection patches.
//! Evaluation lowers a selected profile to concrete rendered outputs; the
//! engine maps those onto the same prepare and plan machinery the rich
//! `config/v1` representation uses.

mod lang;
mod paths;
mod workspace;

use std::collections::BTreeMap;
use std::path::PathBuf;

pub use workspace::{
    AssetEntry, AssetManifest, ConfigSettings, MetaSection, OverlayDeclV1, OverlaySourceV1,
};

/// Conventional root configuration filename in an authoring source tree.
pub const AUTHORING_CONFIG_FILE: &str = "malm.kdl";

/// Root node name that distinguishes authoring documents from the rich
/// dialect's top-level `rich-config` node.
pub const AUTHORING_ROOT_NODE: &str = "config";

/// Maximum encoded bytes in one authoring KDL document.
///
/// This limit applies when a captured file is parsed as a document. Other
/// captured payloads use [`MAX_AUTHORING_SOURCE_BYTES`].
pub const MAX_AUTHORING_DOCUMENT_BYTES: usize = 1024 * 1024;

/// Maximum captured bytes in one supplied source file.
///
/// Matches the pack layer's per-file bound so any capturable authoring
/// payload also fits a verified pack file object.
pub const MAX_AUTHORING_SOURCE_BYTES: usize = malm_pack::MAX_PACK_FILE_BYTES as usize;

/// Maximum files in one supplied authoring source set.
pub const MAX_AUTHORING_SOURCE_FILES: usize = 4096;

/// Version of the authoring evaluator's rendering semantics.
///
/// This value is captured as a prepare input so plans are derived again when
/// rendering semantics change. Increment it whenever identical sources could
/// produce different bytes.
pub const AUTHORING_EVALUATOR_VERSION: u32 = 10;

/// Complete captured authoring source tree supplied by the caller.
///
/// Keys are source-root-relative slash-separated paths; values are exact
/// captured bytes. Deployed file modes are declared in the configuration
/// (`executable=#true`), never derived from the capture, because verified
/// pack files are pure bytes without filesystem modes. The set must contain
/// the entry document, every document reachable through `include`, and every
/// support file (templates, fragments, native trees) those documents
/// reference. This crate never reads anything outside the supplied set.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct AuthoringSourceSetV1 {
    files: BTreeMap<String, Vec<u8>>,
}

impl AuthoringSourceSetV1 {
    /// Creates an empty source set.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds one captured file, replacing any previous bytes at the same path.
    ///
    /// # Errors
    ///
    /// Fails when the path is empty, absolute, contains `.` or `..` segments,
    /// the bytes exceed [`MAX_AUTHORING_SOURCE_BYTES`], or the set is full.
    pub fn insert(&mut self, path: &str, bytes: Vec<u8>) -> Result<(), AuthoringErrorV1> {
        if path.is_empty()
            || path.starts_with('/')
            || path
                .split('/')
                .any(|segment| segment.is_empty() || segment == "." || segment == "..")
        {
            return Err(AuthoringErrorV1::InvalidSourcePath {
                path: path.to_owned(),
            });
        }
        if bytes.len() > MAX_AUTHORING_SOURCE_BYTES {
            return Err(AuthoringErrorV1::SourceTooLarge {
                path: path.to_owned(),
                byte_len: bytes.len(),
            });
        }
        if self.files.len() >= MAX_AUTHORING_SOURCE_FILES && !self.files.contains_key(path) {
            return Err(AuthoringErrorV1::TooManySources {
                limit: MAX_AUTHORING_SOURCE_FILES,
            });
        }
        self.files.insert(path.to_owned(), bytes);
        Ok(())
    }

    #[must_use]
    pub fn get(&self, path: &str) -> Option<&[u8]> {
        self.files.get(path).map(Vec::as_slice)
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.files.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.files.is_empty()
    }

    /// Iterates captured files in path order.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &[u8])> {
        self.files
            .iter()
            .map(|(path, bytes)| (path.as_str(), bytes.as_slice()))
    }

    /// Returns the captured bytes at a lexically-normalized relative path.
    pub(crate) fn get_path(&self, path: &std::path::Path) -> Option<&[u8]> {
        self.get(paths::normalize_lexical(path).to_str()?)
    }

    pub(crate) fn contains_path(&self, path: &std::path::Path) -> bool {
        self.get_path(path).is_some()
    }

    /// Returns whether any captured file lives under the directory path.
    pub(crate) fn contains_dir(&self, path: &std::path::Path) -> bool {
        let Some(normalized) = paths::normalize_lexical(path).to_str().map(str::to_owned) else {
            return false;
        };
        let prefix = format!("{normalized}/");
        self.files
            .range(prefix.clone()..)
            .next()
            .is_some_and(|(path, _)| path.starts_with(&prefix))
    }

    /// Iterates captured files under a directory path, yielding paths
    /// relative to that directory in path order.
    pub(crate) fn iter_dir<'a>(
        &'a self,
        path: &std::path::Path,
    ) -> impl Iterator<Item = (&'a str, &'a [u8])> {
        let prefix = paths::normalize_lexical(path)
            .to_str()
            .map(|normalized| format!("{normalized}/"))
            .unwrap_or_default();
        let strip = prefix.clone();
        self.files
            .range(prefix.clone()..)
            .take_while(move |(path, _)| !prefix.is_empty() && path.starts_with(prefix.as_str()))
            .map(move |(path, bytes)| (&path[strip.len()..], bytes.as_slice()))
    }
}

/// One concrete file produced by evaluating a profile.
///
/// The destination keeps the authoring spelling: a `~/`-prefixed path is
/// home-relative, any other relative path resolves below the configured
/// target directory. Lowering to engine target paths happens host-side.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RenderedOutputV1 {
    destination: String,
    content: RenderedOutputContentV1,
    executable: bool,
    replace: bool,
    transforms: Vec<String>,
}

/// Evaluated content of one authoring output.
///
/// Ordinary outputs already contain their exact bytes. Component-backed
/// outputs retain the canonical document until the engine can invoke the
/// selected root-pack component in its capability-free host.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RenderedOutputContentV1 {
    /// Bytes produced entirely by the pure authoring evaluator.
    Bytes(Vec<u8>),
    /// A canonical document awaiting its selected component renderer.
    Component(DeferredComponentRenderV1),
}

/// One deferred component-renderer invocation selected by authoring source.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeferredComponentRenderV1 {
    renderer: String,
    format: String,
    document: malm_config::CanonicalTypedDocumentV1,
}

impl DeferredComponentRenderV1 {
    #[must_use]
    pub fn renderer(&self) -> &str {
        &self.renderer
    }

    #[must_use]
    pub fn format(&self) -> &str {
        &self.format
    }

    #[must_use]
    pub const fn document(&self) -> &malm_config::CanonicalTypedDocumentV1 {
        &self.document
    }
}

impl RenderedOutputV1 {
    /// Creates one rendered output.
    #[must_use]
    pub fn new(
        destination: String,
        content: RenderedOutputContentV1,
        executable: bool,
        replace: bool,
        transforms: Vec<String>,
    ) -> Self {
        Self {
            destination,
            content,
            executable,
            replace,
            transforms,
        }
    }

    /// Returns the authoring-spelled destination path.
    #[must_use]
    pub fn destination(&self) -> &str {
        &self.destination
    }
    /// Returns the evaluated content, which may still require a component.
    #[must_use]
    pub const fn content(&self) -> &RenderedOutputContentV1 {
        &self.content
    }

    /// Returns exact rendered bytes for a non-component output.
    #[must_use]
    pub fn bytes(&self) -> Option<&[u8]> {
        match &self.content {
            RenderedOutputContentV1::Bytes(bytes) => Some(bytes),
            RenderedOutputContentV1::Component(_) => None,
        }
    }

    /// Returns the deferred renderer request for a component-backed output.
    #[must_use]
    pub const fn component_render(&self) -> Option<&DeferredComponentRenderV1> {
        match &self.content {
            RenderedOutputContentV1::Bytes(_) => None,
            RenderedOutputContentV1::Component(render) => Some(render),
        }
    }
    #[must_use]
    pub const fn executable(&self) -> bool {
        self.executable
    }
    /// Returns whether an existing unmanaged file at the destination is
    /// replaced after review (`on-conflict "backup"`, the default) rather
    /// than failing placement (`on-conflict "fail"`).
    #[must_use]
    pub const fn replace(&self) -> bool {
        self.replace
    }
    /// Returns the declared component transforms in execution order.
    #[must_use]
    pub fn transforms(&self) -> &[String] {
        &self.transforms
    }
}

/// One symlink declared by the evaluated profile.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SymlinkOutputV1 {
    destination: String,
    target: String,
    optional: bool,
}

impl SymlinkOutputV1 {
    /// Returns the authoring-spelled link destination.
    #[must_use]
    pub fn destination(&self) -> &str {
        &self.destination
    }
    /// Returns the authoring-spelled link target (may be `~/`-relative).
    #[must_use]
    pub fn target(&self) -> &str {
        &self.target
    }
    #[must_use]
    pub const fn optional(&self) -> bool {
        self.optional
    }
}

/// Complete evaluation result for one selected profile.
#[derive(Clone, Debug)]
pub struct EvaluatedAuthoringProfileV1 {
    profile: String,
    target: String,
    outputs: Vec<RenderedOutputV1>,
    symlinks: Vec<SymlinkOutputV1>,
    meta: Option<MetaSection>,
    assets: Vec<AssetEntry>,
    external_includes_skipped: Vec<String>,
}

impl EvaluatedAuthoringProfileV1 {
    #[must_use]
    pub fn profile(&self) -> &str {
        &self.profile
    }
    /// Returns the configured target directory (authoring spelling, e.g.
    /// `~/.config`).
    #[must_use]
    pub fn target(&self) -> &str {
        &self.target
    }
    /// Returns the ordered concrete file outputs.
    #[must_use]
    pub fn outputs(&self) -> &[RenderedOutputV1] {
        &self.outputs
    }
    #[must_use]
    pub fn symlinks(&self) -> &[SymlinkOutputV1] {
        &self.symlinks
    }
    /// Returns the root `meta` section, when declared.
    #[must_use]
    pub fn meta(&self) -> Option<&MetaSection> {
        self.meta.as_ref()
    }
    #[must_use]
    pub fn assets(&self) -> &[AssetEntry] {
        &self.assets
    }
    /// Returns `~/` or absolute includes that were recorded but never read.
    ///
    /// The host decides whether an explicit overlay supplies these values;
    /// the pure evaluator never follows them.
    #[must_use]
    pub fn external_includes_skipped(&self) -> &[String] {
        &self.external_includes_skipped
    }
}

/// Report from checking a complete authoring workspace.
#[derive(Clone, Debug)]
pub struct AuthoringCheckReportV1 {
    profiles: Vec<String>,
    default_profile: Option<String>,
    error_count: usize,
    report: String,
}

impl AuthoringCheckReportV1 {
    /// Returns the selectable (non-abstract) profile names in declaration
    /// order.
    #[must_use]
    pub fn profiles(&self) -> &[String] {
        &self.profiles
    }
    /// Returns the configured default profile, when declared.
    #[must_use]
    pub fn default_profile(&self) -> Option<&str> {
        self.default_profile.as_deref()
    }
    #[must_use]
    pub const fn error_count(&self) -> usize {
        self.error_count
    }
    /// Returns the rendered diagnostics report (may contain warnings even
    /// when the error count is zero).
    #[must_use]
    pub fn report(&self) -> &str {
        &self.report
    }
}

/// Authoring parse or evaluation failure.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
#[non_exhaustive]
pub enum AuthoringErrorV1 {
    /// A supplied source path was empty, absolute, or contained `.`/`..`.
    #[error("invalid authoring source path {path:?}")]
    InvalidSourcePath {
        /// The rejected path.
        path: String,
    },
    /// A supplied file exceeded [`MAX_AUTHORING_SOURCE_BYTES`].
    #[error(
        "authoring source {path:?} is {byte_len} bytes; limit {}",
        MAX_AUTHORING_SOURCE_BYTES
    )]
    SourceTooLarge {
        /// The rejected path.
        path: String,
        /// The rejected size.
        byte_len: usize,
    },
    /// The source set exceeded [`MAX_AUTHORING_SOURCE_FILES`].
    #[error("authoring source set exceeds {limit} files")]
    TooManySources {
        /// The enforced limit.
        limit: usize,
    },
    /// The include walk or a root section violated the workspace contract.
    #[error("{message}")]
    Workspace {
        /// Human-readable description of the violation.
        message: String,
    },
    /// Parsing, resolution, type-checking, or rendering reported errors.
    #[error("{report}")]
    Evaluation {
        /// The rendered diagnostics report.
        report: String,
    },
}

/// Returns whether the supplied bytes parse as KDL containing any top-level
/// authoring `config` node.
///
/// Detection intentionally matches the `.any(...)` scan below rather than
/// claiming the node must be first. Undecodable bytes return `false`; the
/// subsequent strict parse reports the real error.
#[must_use]
pub fn is_authoring_root_document(bytes: &[u8]) -> bool {
    let Ok(text) = std::str::from_utf8(bytes) else {
        return false;
    };
    let Ok(document) = text.parse::<kdl::KdlDocument>() else {
        return false;
    };
    document
        .nodes()
        .iter()
        .any(|node| node.name().value() == AUTHORING_ROOT_NODE)
}

/// Evaluates one selected profile from a captured authoring source tree.
///
/// `entry` is the source-relative root document path (conventionally
/// [`AUTHORING_CONFIG_FILE`]); `profile` selects one non-abstract profile.
/// Evaluation is a pure function of the supplied bytes: parsing, include
/// resolution, module and profile composition, input resolution, and
/// directive rendering all consume the source set only.
///
/// # Errors
///
/// Fails when the workspace contract is violated, the profile is unknown or
/// abstract, or any parse, type, or render diagnostic is an error.
pub fn evaluate_authoring_profile_v1(
    sources: &AuthoringSourceSetV1,
    entry: &str,
    profile: &str,
    overlays: &[OverlaySourceV1],
) -> Result<EvaluatedAuthoringProfileV1, AuthoringErrorV1> {
    let mut diagnostics = lang::diag::Diagnostics::new();
    let loaded = workspace::load_workspace(sources, entry, overlays, &mut diagnostics)
        .map_err(|message| AuthoringErrorV1::Workspace { message })?;

    let resolved =
        lang::resolve::resolve_workspace(loaded.parsed, PathBuf::from(""), false, &mut diagnostics);

    if let Some(declared) = resolved.profile(profile)
        && declared.abstract_
    {
        return Err(AuthoringErrorV1::Workspace {
            message: format!("profile `{profile}` is abstract and cannot be selected"),
        });
    }

    let options = lang::compile::CompileOptions {
        target_root: loaded.settings.target.clone(),
        hostname: None,
        limits: lang::budget::Limits::default(),
    };
    let compiled =
        lang::compile::compile_profile(&resolved, sources, profile, &options, &mut diagnostics);
    if diagnostics.has_errors() {
        return Err(AuthoringErrorV1::Evaluation {
            report: diagnostics.render(&loaded.source_map),
        });
    }
    let Some(compiled) = compiled else {
        return Err(AuthoringErrorV1::Evaluation {
            report: diagnostics.render(&loaded.source_map),
        });
    };

    let mut outputs = Vec::new();
    for artifact in &compiled.generated.artifacts {
        outputs.push(RenderedOutputV1 {
            destination: artifact.to.clone(),
            content: match &artifact.content {
                lang::artifact::ArtifactContent::Bytes(content) => {
                    RenderedOutputContentV1::Bytes(content.clone().into_bytes())
                }
                lang::artifact::ArtifactContent::Component {
                    renderer,
                    format,
                    document,
                } => RenderedOutputContentV1::Component(DeferredComponentRenderV1 {
                    renderer: renderer.clone(),
                    format: format.clone(),
                    document: document.clone(),
                }),
            },
            executable: artifact.executable,
            replace: true,
            transforms: artifact.transforms.clone(),
        });
    }
    for file in &compiled.generated.files {
        let Some(bytes) = sources.get_path(&file.source) else {
            if file.optional {
                continue;
            }
            return Err(AuthoringErrorV1::Evaluation {
                report: format!("file source not captured: {}", file.source_label),
            });
        };
        outputs.push(RenderedOutputV1 {
            destination: file.to.clone(),
            content: RenderedOutputContentV1::Bytes(bytes.to_vec()),
            executable: file.executable,
            replace: matches!(file.on_conflict, lang::ast::ConflictPolicy::Backup),
            transforms: Vec::new(),
        });
    }
    for dir in &compiled.generated.dirs {
        if !dir.ignore.is_empty() {
            return Err(AuthoringErrorV1::Evaluation {
                report: format!(
                    "dir output `{}`: ignore patterns are not supported by the authoring evaluator",
                    dir.source_label
                ),
            });
        }
        if !sources.contains_dir(&dir.source) {
            if dir.optional {
                continue;
            }
            return Err(AuthoringErrorV1::Evaluation {
                report: format!("dir source not captured: {}", dir.source.display()),
            });
        }
        let base = dir.to.clone().unwrap_or_else(|| {
            std::path::Path::new(&dir.source_label)
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or(dir.source_label.as_str())
                .to_owned()
        });
        let mut entries = 0usize;
        for (relative, bytes) in sources.iter_dir(&dir.source) {
            entries += 1;
            if entries > options.limits.max_directory_entries {
                return Err(AuthoringErrorV1::Evaluation {
                    report: format!(
                        "dir output `{}` exceeds {} entries",
                        dir.source_label, options.limits.max_directory_entries
                    ),
                });
            }
            outputs.push(RenderedOutputV1 {
                destination: format!("{base}/{relative}"),
                content: RenderedOutputContentV1::Bytes(bytes.to_vec()),
                executable: dir.executable,
                replace: matches!(dir.on_conflict, lang::ast::ConflictPolicy::Backup),
                transforms: Vec::new(),
            });
        }
    }

    let symlinks = compiled
        .generated
        .symlinks
        .iter()
        .map(|symlink| SymlinkOutputV1 {
            destination: symlink.to.clone(),
            target: symlink.source.clone(),
            optional: symlink.optional,
        })
        .collect();

    Ok(EvaluatedAuthoringProfileV1 {
        profile: profile.to_owned(),
        target: loaded.settings.target,
        outputs,
        symlinks,
        meta: loaded.meta,
        assets: loaded
            .assets
            .map(|manifest| manifest.assets)
            .unwrap_or_default(),
        external_includes_skipped: loaded.external_includes_skipped,
    })
}

/// Resolves the profile an authoring root selects when none is requested.
///
/// Parses the workspace only (no type-checking or rendering) and returns
/// the root `config` node's `default-profile`.
///
/// # Errors
///
/// Fails when the workspace contract is violated or no default profile is
/// declared.
pub fn default_authoring_profile_v1(
    sources: &AuthoringSourceSetV1,
    entry: &str,
) -> Result<String, AuthoringErrorV1> {
    let mut diagnostics = lang::diag::Diagnostics::new();
    let loaded = workspace::load_workspace(sources, entry, &[], &mut diagnostics)
        .map_err(|message| AuthoringErrorV1::Workspace { message })?;
    loaded
        .settings
        .default_profile
        .ok_or_else(|| AuthoringErrorV1::Workspace {
            message: format!("{entry}: no `default-profile` declared and none requested"),
        })
}

/// One resolved module input with its provenance.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolvedVarV1 {
    instance: String,
    name: String,
    rendered_value: String,
    origin: String,
}

impl ResolvedVarV1 {
    /// Returns the module instance alias owning the input.
    #[must_use]
    pub fn instance(&self) -> &str {
        &self.instance
    }
    /// Returns the module-scoped input name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }
    /// Returns the human-readable rendered value.
    #[must_use]
    pub fn rendered_value(&self) -> &str {
        &self.rendered_value
    }
    /// Returns the provenance label, such as `default` or `profile astral`.
    #[must_use]
    pub fn origin(&self) -> &str {
        &self.origin
    }
}

/// Resolves one profile's complete typed inputs with provenance, sorted by
/// instance then input name.
///
/// # Errors
///
/// Fails when the workspace contract is violated or resolution reports
/// errors.
pub fn resolve_authoring_vars_v1(
    sources: &AuthoringSourceSetV1,
    entry: &str,
    profile: &str,
    overlays: &[OverlaySourceV1],
) -> Result<Vec<ResolvedVarV1>, AuthoringErrorV1> {
    let mut diagnostics = lang::diag::Diagnostics::new();
    let loaded = workspace::load_workspace(sources, entry, overlays, &mut diagnostics)
        .map_err(|message| AuthoringErrorV1::Workspace { message })?;
    let resolved =
        lang::resolve::resolve_workspace(loaded.parsed, PathBuf::from(""), false, &mut diagnostics);
    let check_options = lang::typecheck::CheckOptions {
        target_root: &loaded.settings.target,
        hostname: None,
        limits: lang::budget::Limits::default(),
    };
    let typed = lang::typecheck::check_profile(
        &resolved,
        sources,
        profile,
        &mut diagnostics,
        check_options,
    );
    if diagnostics.has_errors() {
        return Err(AuthoringErrorV1::Evaluation {
            report: diagnostics.render(&loaded.source_map),
        });
    }
    let Some(typed) = typed else {
        return Err(AuthoringErrorV1::Workspace {
            message: format!(
                "profile `{profile}` not found (known profiles: {})",
                resolved.profile_names().join(", ")
            ),
        });
    };
    let mut vars = Vec::new();
    for instance in &typed.instances {
        for (name, (value, origin)) in &instance.values {
            vars.push(ResolvedVarV1 {
                instance: instance.alias.clone(),
                name: name.clone(),
                rendered_value: value.display(),
                origin: origin.label(),
            });
        }
    }
    vars.sort_by(|left, right| {
        (left.instance(), left.name()).cmp(&(right.instance(), right.name()))
    });
    Ok(vars)
}

/// Returns the root configuration's overlay declarations.
///
/// The host reads each declared file itself (honoring `optional`) and
/// supplies the bytes back to evaluation; the pure evaluator never touches
/// the declared paths.
///
/// # Errors
///
/// Fails when the workspace contract is violated.
pub fn declared_overlays_v1(
    sources: &AuthoringSourceSetV1,
    entry: &str,
) -> Result<Vec<OverlayDeclV1>, AuthoringErrorV1> {
    let mut diagnostics = lang::diag::Diagnostics::new();
    let loaded = workspace::load_workspace(sources, entry, &[], &mut diagnostics)
        .map_err(|message| AuthoringErrorV1::Workspace { message })?;
    Ok(loaded.overlays)
}

/// Checks a complete authoring workspace: every module API, every profile
/// (abstract ones included), every fragment, patch, and output reference.
///
/// Language-level problems are reported through the returned report and
/// error count rather than failing the call, so a checker CLI can render
/// them; only workspace-contract violations fail.
///
/// # Errors
///
/// Fails when the include walk or a root section violates the workspace
/// contract (missing documents, limits, cycles, malformed root nodes).
pub fn check_authoring_workspace_v1(
    sources: &AuthoringSourceSetV1,
    entry: &str,
) -> Result<AuthoringCheckReportV1, AuthoringErrorV1> {
    let mut diagnostics = lang::diag::Diagnostics::new();
    let loaded = workspace::load_workspace(sources, entry, &[], &mut diagnostics)
        .map_err(|message| AuthoringErrorV1::Workspace { message })?;
    let resolved =
        lang::resolve::resolve_workspace(loaded.parsed, PathBuf::from(""), false, &mut diagnostics);
    lang::typecheck::check_workspace(&resolved, sources, &mut diagnostics);
    let profiles = resolved
        .profiles
        .iter()
        .filter(|profile| !profile.abstract_)
        .map(|profile| profile.name.clone())
        .collect();
    Ok(AuthoringCheckReportV1 {
        profiles,
        default_profile: loaded.settings.default_profile,
        error_count: diagnostics.error_count(),
        report: diagnostics.render(&loaded.source_map),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn compile_with_limits(
        document: &str,
        limits: lang::budget::Limits,
    ) -> (lang::compile::CompiledProfile, String) {
        let mut sources = AuthoringSourceSetV1::new();
        sources
            .insert(AUTHORING_CONFIG_FILE, document.as_bytes().to_vec())
            .unwrap();
        let mut diagnostics = lang::diag::Diagnostics::new();
        let loaded =
            workspace::load_workspace(&sources, AUTHORING_CONFIG_FILE, &[], &mut diagnostics)
                .unwrap();
        let resolved = lang::resolve::resolve_workspace(
            loaded.parsed,
            PathBuf::new(),
            false,
            &mut diagnostics,
        );
        let options = lang::compile::CompileOptions {
            target_root: loaded.settings.target,
            hostname: None,
            limits,
        };
        let compiled =
            lang::compile::compile_profile(&resolved, &sources, "p", &options, &mut diagnostics)
                .expect("profile exists");
        (compiled, diagnostics.render(&loaded.source_map))
    }

    #[test]
    fn source_set_rejects_escaping_and_absolute_paths() {
        let mut sources = AuthoringSourceSetV1::new();
        for path in ["", "/etc/passwd", "a//b", "./a", "a/../b", "a/./b", ".."] {
            assert!(
                matches!(
                    sources.insert(path, Vec::new()),
                    Err(AuthoringErrorV1::InvalidSourcePath { .. })
                ),
                "path {path:?} must be rejected"
            );
        }
        assert!(sources.is_empty());
    }

    #[test]
    fn source_set_rejects_oversized_files() {
        let mut sources = AuthoringSourceSetV1::new();
        let oversized = vec![0u8; MAX_AUTHORING_SOURCE_BYTES + 1];
        assert!(matches!(
            sources.insert("malm.kdl", oversized),
            Err(AuthoringErrorV1::SourceTooLarge { .. })
        ));
    }

    #[test]
    fn source_set_stores_and_iterates_in_path_order() {
        let mut sources = AuthoringSourceSetV1::new();
        sources.insert("malm/b.kdl", b"b".to_vec()).unwrap();
        sources.insert("malm.kdl", b"root".to_vec()).unwrap();
        assert_eq!(sources.len(), 2);
        assert_eq!(sources.get("malm.kdl"), Some(b"root".as_slice()));
        let paths: Vec<&str> = sources.iter().map(|(path, _)| path).collect();
        assert_eq!(paths, ["malm.kdl", "malm/b.kdl"]);
    }

    #[test]
    fn evaluation_requires_a_config_root() {
        let mut sources = AuthoringSourceSetV1::new();
        sources
            .insert(AUTHORING_CONFIG_FILE, b"meta name=\"x\"\n".to_vec())
            .unwrap();
        assert!(matches!(
            evaluate_authoring_profile_v1(&sources, AUTHORING_CONFIG_FILE, "any", &[]),
            Err(AuthoringErrorV1::Workspace { .. })
        ));
    }

    #[test]
    fn requirements_and_profiles_directives_render_profile_scoped_lines() {
        let mut sources = AuthoringSourceSetV1::new();
        let root = br#"config target="~/.config" default-profile="p"

module "m" {
    description "aggregation test"
    requires {
        command "beta"
        command "alpha"
        @if "notify" {
            command "notify-send"
        }
    }
    inputs {
        input "notify" type="bool" default=#false
    }
    outputs {
        render "smia/requirements" format="line-list" {
            @requirements
        }
        render "smia/profiles" format="line-list" {
            @profiles
        }
    }
}

profile "base" abstract=#true {
    use "m"
}

profile "p" {
    extends "base"
}

profile "loud" {
    extends "base"
    use "m" {
        with {
            notify #true
        }
    }
}
"#;
        sources
            .insert(AUTHORING_CONFIG_FILE, root.to_vec())
            .unwrap();
        let calm = evaluate_authoring_profile_v1(&sources, AUTHORING_CONFIG_FILE, "p", &[])
            .expect("evaluate calm");
        assert_eq!(calm.outputs()[0].bytes().unwrap(), b"alpha\nbeta\n");
        assert_eq!(
            calm.outputs()[1].bytes().unwrap(),
            b"p\nloud\n",
            "declaration order"
        );
        let loud = evaluate_authoring_profile_v1(&sources, AUTHORING_CONFIG_FILE, "loud", &[])
            .expect("evaluate loud");
        assert_eq!(
            loud.outputs()[0].bytes().unwrap(),
            b"alpha\nbeta\nnotify-send\n",
            "conditional requirement follows the resolved input"
        );
    }

    #[test]
    fn overlays_layer_values_and_reject_file_references() {
        let mut sources = AuthoringSourceSetV1::new();
        let root = br#"config target="~/.config" default-profile="p"

overlay "local" path="~/.config/malm/local.kdl" optional=#true

variables {
    global.accent "teal"
}

module "m" {
    description "overlay test"
    inputs {
        input "size" type="int" default=1
    }
    outputs {
        render "m/out.conf" format="key-value" separator="=" quote="none" {
            "size" (ref)"size"
            "accent" (ref)"global.accent"
        }
    }
}

profile "p" {
    use "m"
}
"#;
        sources
            .insert(AUTHORING_CONFIG_FILE, root.to_vec())
            .unwrap();

        // Defaults apply when no overlay is supplied.
        let plain = evaluate_authoring_profile_v1(&sources, AUTHORING_CONFIG_FILE, "p", &[])
            .expect("evaluate without overlay");
        assert_eq!(
            plain.outputs()[0].bytes().unwrap(),
            b"size=1
accent=teal
"
        );

        // An overlay can override a variable and extend a profile.
        let overlay = OverlaySourceV1::new(
            "local".to_owned(),
            br#"variables {
    global.accent "amber" override=#true
}

extend-profile "p" {
    use "m" {
        with {
            size 7
        }
    }
}
"#
            .to_vec(),
        );
        let layered = evaluate_authoring_profile_v1(
            &sources,
            AUTHORING_CONFIG_FILE,
            "p",
            std::slice::from_ref(&overlay),
        )
        .expect("evaluate with overlay");
        assert_eq!(
            layered.outputs()[0].bytes().unwrap(),
            b"size=7
accent=amber
"
        );

        // Overlay documents reject structural declarations.
        let hostile = OverlaySourceV1::new(
            "local".to_owned(),
            br#"module "evil" {
    description "nope"
}
"#
            .to_vec(),
        );
        assert!(matches!(
            evaluate_authoring_profile_v1(
                &sources,
                AUTHORING_CONFIG_FILE,
                "p",
                std::slice::from_ref(&hostile),
            ),
            Err(AuthoringErrorV1::Workspace { .. })
        ));

        // A supplied overlay must have a matching root declaration.
        let undeclared = OverlaySourceV1::new("other".to_owned(), Vec::new());
        assert!(matches!(
            evaluate_authoring_profile_v1(
                &sources,
                AUTHORING_CONFIG_FILE,
                "p",
                std::slice::from_ref(&undeclared),
            ),
            Err(AuthoringErrorV1::Workspace { .. })
        ));

        // The host can inspect declarations before reading overlay files.
        let declared = declared_overlays_v1(&sources, AUTHORING_CONFIG_FILE).unwrap();
        assert_eq!(declared.len(), 1);
        assert_eq!(declared[0].name(), "local");
        assert_eq!(declared[0].path(), "~/.config/malm/local.kdl");
        assert!(declared[0].optional());
    }

    #[test]
    fn minimal_workspace_renders_a_text_output() {
        let mut sources = AuthoringSourceSetV1::new();
        let root = br#"config target="~/.config" default-profile="p"

module "m" {
    description "test module"
    outputs {
        render "m/out.txt" format="text" {
            @line "hello"
        }
    }
}

profile "p" {
    use "m"
}
"#;
        sources
            .insert(AUTHORING_CONFIG_FILE, root.to_vec())
            .unwrap();
        let evaluated = evaluate_authoring_profile_v1(&sources, AUTHORING_CONFIG_FILE, "p", &[])
            .expect("evaluate");
        assert_eq!(evaluated.profile(), "p");
        assert_eq!(evaluated.target(), "~/.config");
        assert_eq!(evaluated.outputs().len(), 1);
        assert_eq!(evaluated.outputs()[0].destination(), "m/out.txt");
        assert_eq!(evaluated.outputs()[0].bytes().unwrap(), b"hello\n");
    }

    #[test]
    fn output_transforms_are_extracted_in_order_across_render_formats() {
        let mut sources = AuthoringSourceSetV1::new();
        let root = br#"config target="~/.config" default-profile="p"

module "m" {
    description "transform parsing"
    outputs {
        render "m/out.txt" format="text" {
            @component-transform "first"
            @line "hello"
            @component-transform "second"
        }
        render "m/out.kdl" format="kdl" {
            @component-transform "kdl-transform"
            setting "value"
        }
        render "m/out.xml" format="xml" {
            @component-transform "xml-transform"
            root
        }
    }
}

profile "p" {
    use "m"
}
"#;
        sources
            .insert(AUTHORING_CONFIG_FILE, root.to_vec())
            .unwrap();
        let evaluated = evaluate_authoring_profile_v1(&sources, AUTHORING_CONFIG_FILE, "p", &[])
            .expect("evaluate");
        assert_eq!(evaluated.outputs()[0].transforms(), ["first", "second"]);
        assert_eq!(evaluated.outputs()[0].bytes().unwrap(), b"hello\n");
        assert_eq!(evaluated.outputs()[1].transforms(), ["kdl-transform"]);
        assert_eq!(evaluated.outputs()[2].transforms(), ["xml-transform"]);
        assert_eq!(evaluated.outputs()[2].bytes().unwrap(), b"<root />\n");
    }

    #[test]
    fn component_renderer_builds_a_canonical_typed_document() {
        let mut sources = AuthoringSourceSetV1::new();
        let root = br#"config target="~/.config" default-profile="p"

module "m" {
    description "component document"
    inputs {
        input "enabled" type="bool" default=#false
        input "optional" type="string" optional=#true
        input "names" type="list" item-type="string" {
            default "second" "third"
        }
        input "settings" type="record" {
            fields {
                field "zeta" type="int" required=#true
                field "path" type="path" required=#true
            }
            default {
                zeta 9
                path "~/.component"
            }
        }
        input "extra" type="collection" item-type="kdl-document" {
            defaults {
                item "one" {
                    spliced "yes"
                }
            }
        }
    }

    outputs {
        render "m/out.lua" format="lua-plugin" component-renderer="lua-renderer" {
            @component-transform "check-lua"
            zed 3
            title (f)"profile {{profile.name}}"
            values 1 2 3
            object beta=2 alpha=1
            optional (ref?)"optional"
            nested {
                child "value"
            }
            array {
                - "first"
                @for-each "name" in="names" {
                    - (ref)"name"
                }
                @for-range "number" from=4 through=5 {
                    - (ref)"number"
                }
            }
            @if "enabled" {
                inactive "not emitted"
            }
            @else {
                selected "else"
            }
            @insert-documents "extra"
            @insert-fields "settings"
        }
    }
}

profile "p" {
    use "m"
}
"#;
        sources
            .insert(AUTHORING_CONFIG_FILE, root.to_vec())
            .unwrap();

        let evaluated = evaluate_authoring_profile_v1(&sources, AUTHORING_CONFIG_FILE, "p", &[])
            .expect("evaluate component-backed output");
        let output = &evaluated.outputs()[0];
        assert!(output.bytes().is_none());
        assert_eq!(output.transforms(), ["check-lua"]);
        let render = output.component_render().expect("deferred render");
        assert_eq!(render.renderer(), "lua-renderer");
        assert_eq!(render.format(), "lua-plugin");
        assert!(render.document().source_documents().is_empty());
        assert!(render.document().includes().is_empty());
        assert!(render.document().provenance().is_empty());

        let record = render.document().root().as_record().unwrap();
        let keys = record.keys().map(|key| key.as_str()).collect::<Vec<_>>();
        assert_eq!(
            keys,
            [
                "array", "nested", "object", "path", "selected", "spliced", "title", "values",
                "zed", "zeta"
            ],
            "canonical records are sorted and unset optional entries are omitted"
        );
        assert_eq!(record["path"].as_string(), Some("~/.component"));
        assert_eq!(record["zeta"].as_integer(), Some(9));
        assert_eq!(record["title"].as_string(), Some("profile p"));
        assert_eq!(record["selected"].as_string(), Some("else"));
        assert_eq!(record["spliced"].as_string(), Some("yes"));
        assert_eq!(
            record["values"]
                .as_list()
                .unwrap()
                .iter()
                .map(malm_config::TypedValueV1::as_integer)
                .collect::<Vec<_>>(),
            [Some(1), Some(2), Some(3)]
        );
        let array = record["array"].as_list().unwrap();
        assert_eq!(array[0].as_string(), Some("first"));
        assert_eq!(array[1].as_string(), Some("second"));
        assert_eq!(array[2].as_string(), Some("third"));
        assert_eq!(array[3].as_integer(), Some(4));
        assert_eq!(array[4].as_integer(), Some(5));
        let object = record["object"].as_record().unwrap();
        assert_eq!(
            object.keys().map(|key| key.as_str()).collect::<Vec<_>>(),
            ["alpha", "beta"]
        );
    }

    #[test]
    fn component_documents_reserve_exact_bytes_nodes_and_container_sizes() {
        let document = r#"config target="~" default-profile="p"
module "m" {
    description "component budgets"
    outputs {
        render "out" format="custom" component-renderer="component" {
            first 1
            second "two"
        }
    }
}
profile "p" { use "m" }
"#;
        let (baseline, report) = compile_with_limits(document, lang::budget::Limits::default());
        assert!(report.is_empty(), "{report}");
        let lang::artifact::ArtifactContent::Component {
            document: canonical_document,
            ..
        } = &baseline.generated.artifacts[0].content
        else {
            panic!("expected component artifact");
        };
        let canonical_len = malm_config::canonical_typed_document_bytes_v1(canonical_document)
            .unwrap()
            .len() as u64;

        let exact = lang::budget::Limits {
            max_collection_size: 2,
            max_generated_nodes: 5,
            max_artifact_bytes: canonical_len,
            max_total_bytes: canonical_len,
            ..lang::budget::Limits::default()
        };
        let (compiled, report) = compile_with_limits(document, exact);
        assert!(
            report.is_empty(),
            "exact limits must remain valid: {report}"
        );
        assert_eq!(compiled.generated.artifacts.len(), 1);

        for (limits, expected) in [
            (
                lang::budget::Limits {
                    max_total_bytes: canonical_len - 1,
                    ..exact
                },
                "plan-wide maximum",
            ),
            (
                lang::budget::Limits {
                    max_generated_nodes: 4,
                    ..exact
                },
                "generated KDL nodes",
            ),
            (
                lang::budget::Limits {
                    max_collection_size: 1,
                    ..exact
                },
                "collection has 2 items",
            ),
        ] {
            let (_, report) = compile_with_limits(document, limits);
            assert!(report.contains(expected), "missing {expected:?}: {report}");
        }
    }

    #[test]
    fn component_insertion_preflight_consumes_every_work_budget() {
        let document = r#"config target="~" default-profile="p"
module "m" {
    description "component preflight budgets"
    inputs {
        input "enabled" type="bool" default=#false
        input "values" type="list<string>" { default "a" "b" "c" }
        input "inner" type="collection<kdl-document>" {
            defaults { item "inner" { nested "value" } }
        }
        input "outer" type="collection<kdl-document>" {
            defaults { item "outer" { @insert-documents "inner" } }
        }
    }
    outputs {
        render "out" format="custom" component-renderer="component" {
            stable "only-active-value"
            @if "enabled" {
                @for-each "value" in="values" { @insert-documents "outer" }
                @for-range "number" from=1 through=3 { ranged (ref)"number" }
            }
        }
    }
}
profile "p" { use "m" }
"#;
        let (compiled, report) = compile_with_limits(document, lang::budget::Limits::default());
        assert!(report.is_empty(), "baseline preflight failed: {report}");
        assert_eq!(compiled.generated.artifacts.len(), 1);

        let cases = [
            lang::budget::Limits {
                max_control_nesting: 2,
                ..lang::budget::Limits::default()
            },
            lang::budget::Limits {
                max_range_iterations: 2,
                ..lang::budget::Limits::default()
            },
            lang::budget::Limits {
                max_total_iterations: 2,
                ..lang::budget::Limits::default()
            },
            lang::budget::Limits {
                max_operations: 4,
                ..lang::budget::Limits::default()
            },
            lang::budget::Limits {
                max_generated_nodes: 4,
                ..lang::budget::Limits::default()
            },
        ];
        for limits in cases {
            let (compiled, report) = compile_with_limits(document, limits);
            assert!(
                report.contains("error[MALM4001]"),
                "preflight escaped its compilation budget: {report}"
            );
            assert!(
                compiled.generated.artifacts.is_empty(),
                "a budget-exhausted component document was retained"
            );
        }
    }

    #[test]
    fn active_collection_limit_covers_nested_defaults_and_preserves_rejected_patches() {
        let nested = r#"config target="~" default-profile="p"
module "m" {
    description "nested limit"
    types {
        record "settings" {
            fields { field "tags" type="list<string>" required=#true }
        }
    }
    inputs {
        input "settings" type="settings" { default { tags "a" "b" } }
    }
}
profile "p" { use "m" }
"#;
        let limits = lang::budget::Limits {
            max_collection_size: 1,
            ..lang::budget::Limits::default()
        };
        let (_, report) = compile_with_limits(nested, limits);
        assert!(
            report.contains("collection has 2 items, exceeding the maximum of 1"),
            "nested default escaped the active limit: {report}"
        );

        let patched = r#"config target="~" default-profile="p"
module "m" {
    description "patch limit"
    inputs {
        input "items" type="map<list<string>>" {
            defaults { item "original" "kept" }
        }
    }
}
profile "p" {
    use "m" {
        patch {
            collection "items" {
                append "second" "two"
                replace-all {
                    item "replacement" "a" "b"
                }
            }
        }
    }
}
"#;
        let (compiled, report) = compile_with_limits(patched, limits);
        assert!(
            report
                .matches("collection has 2 items, exceeding the maximum of 1")
                .count()
                >= 2,
            "append and replace-all were not both preflighted: {report}"
        );
        let value = &compiled.typed.instances[0].values["items"].0;
        let lang::value::Value::Collection(items) = value else {
            panic!("map lowers to a keyed collection");
        };
        assert_eq!(items.len(), 1);
        assert_eq!(items.items[0].key, "original");
    }

    #[test]
    fn computed_defaults_use_the_active_template_byte_limit() {
        let document = r#"config target="~" default-profile="p"
module "m" {
    description "computed limit"
    inputs {
        input "source" type="string" default="abcd"
        input "derived" type="string" default=(f)"{{source}}"
    }
}
profile "p" { use "m" }
"#;
        let exact = lang::budget::Limits {
            max_artifact_bytes: 4,
            ..lang::budget::Limits::default()
        };
        let (_, report) = compile_with_limits(document, exact);
        assert!(report.is_empty(), "in-limit default changed: {report}");

        let (_, report) = compile_with_limits(
            document,
            lang::budget::Limits {
                max_artifact_bytes: 3,
                ..exact
            },
        );
        assert!(
            report.contains("rendered template exceeds the maximum of 3 bytes"),
            "computed default ignored the active limit: {report}"
        );
    }

    #[test]
    fn built_in_artifacts_enforce_cumulative_bytes_at_the_exact_boundary() {
        let document = r#"config target="~" default-profile="p"
module "m" {
    description "cumulative output bytes"
    outputs {
        render "one.txt" format="text" { @line "abcd" }
        render "two.json" format="json" { value "efgh" }
    }
}
profile "p" { use "m" }
"#;
        let (baseline, report) = compile_with_limits(document, lang::budget::Limits::default());
        assert!(report.is_empty(), "{report}");
        let lengths = baseline
            .generated
            .artifacts
            .iter()
            .map(|artifact| match &artifact.content {
                lang::artifact::ArtifactContent::Bytes(content) => content.len() as u64,
                lang::artifact::ArtifactContent::Component { .. } => unreachable!(),
            })
            .collect::<Vec<_>>();
        let total = lengths.iter().sum();
        let exact = lang::budget::Limits {
            max_artifact_bytes: *lengths.iter().max().unwrap(),
            max_total_bytes: total,
            ..lang::budget::Limits::default()
        };
        let (compiled, report) = compile_with_limits(document, exact);
        assert!(report.is_empty(), "exact output budget rejected: {report}");
        assert_eq!(compiled.generated.artifacts.len(), 2);

        let (compiled, report) = compile_with_limits(
            document,
            lang::budget::Limits {
                max_total_bytes: total - 1,
                ..exact
            },
        );
        assert!(
            report.contains("MALM4001"),
            "missing budget error: {report}"
        );
        assert_eq!(
            compiled.generated.artifacts.len(),
            1,
            "the crossing artifact must not be retained"
        );

        let repeated = r#"config target="~" default-profile="p"
module "m" {
    description "repeated large value"
    inputs { input "value" type="string" default="abcdefgh" }
    outputs {
        render "repeated.txt" format="text" {
            @for-range "number" from=1 through=100 { @line (ref)"value" }
        }
    }
}
profile "p" { use "m" }
"#;
        let (compiled, report) = compile_with_limits(
            repeated,
            lang::budget::Limits {
                max_artifact_bytes: 16,
                max_total_bytes: 16,
                ..lang::budget::Limits::default()
            },
        );
        assert!(
            report.contains("MALM4001"),
            "repeated values escaped the bounded writer: {report}"
        );
        assert!(compiled.generated.artifacts.is_empty());
    }

    #[test]
    fn direct_kdl_serialization_is_bounded_and_preserves_exact_bytes() {
        let document = r#"config target="~" default-profile="p"
module "m" {
    description "bounded direct kdl"
    inputs { input "value" type="string" default="abcdefgh" }
    outputs {
        render "out.kdl" format="kdl" {
            @for-range "number" from=1 through=3 {
                item (ref)"value" index=(ref)"number"
            }
        }
    }
}
profile "p" { use "m" }
"#;
        let (baseline, report) = compile_with_limits(document, lang::budget::Limits::default());
        assert!(report.is_empty(), "{report}");
        let lang::artifact::ArtifactContent::Bytes(expected) =
            &baseline.generated.artifacts[0].content
        else {
            unreachable!()
        };
        let exact_len = expected.len() as u64;
        let exact = lang::budget::Limits {
            max_artifact_bytes: exact_len,
            max_total_bytes: exact_len,
            ..lang::budget::Limits::default()
        };
        let (compiled, report) = compile_with_limits(document, exact);
        assert!(report.is_empty(), "exact KDL budget rejected: {report}");
        let lang::artifact::ArtifactContent::Bytes(actual) =
            &compiled.generated.artifacts[0].content
        else {
            unreachable!()
        };
        assert_eq!(actual, expected);

        let (compiled, report) = compile_with_limits(
            document,
            lang::budget::Limits {
                max_artifact_bytes: exact_len - 1,
                max_total_bytes: exact_len - 1,
                ..exact
            },
        );
        assert!(
            report.contains("MALM4001"),
            "missing KDL budget error: {report}"
        );
        assert!(compiled.generated.artifacts.is_empty());
    }

    #[test]
    fn xml_and_css_serializers_bound_growth_and_accept_exact_total() {
        let document = r#"config target="~" default-profile="p"
module "m" {
    description "bounded generic formats"
    inputs { input "value" type="string" default="a&b<c>d" }
    outputs {
        render "out.xml" format="xml" declaration=#true {
            root {
                attr "title" (ref)"value"
                @for-range "number" from=1 through=3 {
                    item { value (ref)"value" }
                }
            }
        }
        render "out.css" format="css" {
            field ".example" {
                @for-range "number" from=1 through=3 {
                    repeat "content" (f)"value-{{number}}"
                }
            }
        }
    }
}
profile "p" { use "m" }
"#;
        let (baseline, report) = compile_with_limits(document, lang::budget::Limits::default());
        assert!(report.is_empty(), "{report}");
        let expected = baseline
            .generated
            .artifacts
            .iter()
            .map(|artifact| match &artifact.content {
                lang::artifact::ArtifactContent::Bytes(content) => content.clone(),
                lang::artifact::ArtifactContent::Component { .. } => unreachable!(),
            })
            .collect::<Vec<_>>();
        let total = expected.iter().map(|content| content.len() as u64).sum();
        let exact = lang::budget::Limits {
            max_artifact_bytes: expected
                .iter()
                .map(|content| content.len() as u64)
                .max()
                .unwrap(),
            max_total_bytes: total,
            ..lang::budget::Limits::default()
        };
        let (compiled, report) = compile_with_limits(document, exact);
        assert!(report.is_empty(), "exact XML/CSS budget rejected: {report}");
        let actual = compiled
            .generated
            .artifacts
            .iter()
            .map(|artifact| match &artifact.content {
                lang::artifact::ArtifactContent::Bytes(content) => content.clone(),
                lang::artifact::ArtifactContent::Component { .. } => unreachable!(),
            })
            .collect::<Vec<_>>();
        assert_eq!(actual, expected);

        let (_, report) = compile_with_limits(
            document,
            lang::budget::Limits {
                max_total_bytes: total - 1,
                ..exact
            },
        );
        assert!(
            report.contains("MALM4001"),
            "generic serializer escaped total budget: {report}"
        );
    }

    #[test]
    fn component_renderer_rejects_invalid_identifiers() {
        for (property, value) in [("format", "Lua Plugin"), ("renderer", "Lua_Renderer")] {
            let mut sources = AuthoringSourceSetV1::new();
            let declaration = format!(
                "render \"out\" format=\"{}\" component-renderer=\"{}\" {{ value 1 }}",
                if property == "format" { value } else { "lua" },
                if property == "renderer" {
                    value
                } else {
                    "lua-renderer"
                },
            );
            let root = format!(
                "config target=\"~\" default-profile=\"p\"\nmodule \"m\" {{\n description \"d\"\n outputs {{ {declaration} }}\n}}\nprofile \"p\" {{ use \"m\" }}\n"
            );
            sources
                .insert(AUTHORING_CONFIG_FILE, root.into_bytes())
                .unwrap();
            let report = evaluate_authoring_profile_v1(&sources, AUTHORING_CONFIG_FILE, "p", &[])
                .unwrap_err()
                .to_string();
            assert!(
                report.contains("is not an identifier"),
                "{property} diagnostic missing: {report}"
            );
        }
    }

    #[test]
    fn component_renderer_rejects_untyped_constructs_in_inactive_branches() {
        for construct in [
            "@comment \"hidden\"",
            "@raw-text \"hidden\"",
            "value (raw)\"hidden\"",
            "@line \"hidden\"",
            "@include-file \"./hidden\"",
            "@include-fragment \"hidden\"",
            "@requirements",
            "@profiles",
            "value \"hidden\" @quote=\"double\"",
            "- \"root list\"",
            "mixed { named 1; - 2; }",
        ] {
            let mut sources = AuthoringSourceSetV1::new();
            let root = format!(
                r#"config target="~" default-profile="p"
module "m" {{
    description "d"
    inputs {{ input "enabled" type="bool" default=#false }}
    outputs {{
        render "out" format="lua" component-renderer="lua-renderer" {{
            safe 1
            @if "enabled" {{ {construct} }}
        }}
    }}
}}
profile "p" {{ use "m" }}
"#
            );
            sources
                .insert(AUTHORING_CONFIG_FILE, root.into_bytes())
                .unwrap();
            let report = evaluate_authoring_profile_v1(&sources, AUTHORING_CONFIG_FILE, "p", &[])
                .unwrap_err()
                .to_string();
            assert!(
                report.contains("component document")
                    || report.contains("component document representation"),
                "inactive construct {construct:?} was not rejected with a source diagnostic:\n{report}"
            );
        }
    }
}
