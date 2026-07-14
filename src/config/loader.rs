//! Config loading with bounded includes and provenance tracking.
//! Remote configs cannot traverse symlinks, escape the source root, or read
//! local includes without permission.

use crate::app::context::GlobalCtx;
use crate::config::discovery::{
    local_config_path, remote_config_path, validate_remote_config_relative,
};
use crate::config::kdl::{
    bool_prop, expect_arg_count, opt_str_prop, reject_unknown_children, reject_unknown_props,
    req_str_arg, req_str_prop,
};
use crate::config::{Config, ConfigSettings, MetaSection};
use crate::domain::id::StateName;
use crate::lang::ast::ParsedWorkspace;
use crate::lang::diag::{Diagnostics, FileId, Severity, SourceMap};
use crate::lang::parse::{
    parse_extend_module, parse_extend_profile, parse_globals, parse_module, parse_profile,
    parse_slots,
};
use crate::lang::resolve::resolve_workspace;
use crate::lang::typecheck::check_workspace;
use crate::paths::{expand_tilde, normalize_lexical, resolve_target_root};
use crate::source::git::require_https;
use crate::source::{GitReference, ResolvedSource, SourceIdentity, SourceSpec, TrustMode};
use anyhow::{Context, Result};
use kdl::{KdlDocument, KdlNode};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::env;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

const MAX_CONFIG_FILE_BYTES: u64 = 1024 * 1024;
const MAX_CONFIG_TOTAL_BYTES: u64 = 4 * 1024 * 1024;
const MAX_INCLUDE_DEPTH: usize = 16;
const MAX_CONFIG_FILES: usize = 64;

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfigFileKind {
    Root,
    RepositoryInclude,
    ExternalInclude,
    ExternalTemplate,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct ConfigFileProvenance {
    pub path: PathBuf,
    pub kind: ConfigFileKind,
    pub sha256: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rendered_sha256: Option<String>,
}

pub struct LoadedConfigSource {
    pub config: Config,
    pub resolved: ResolvedSource,
    pub config_path: PathBuf,
    pub target_root: PathBuf,
    pub provenance: Vec<ConfigFileProvenance>,
    pub external_includes_skipped: Vec<PathBuf>,
    /// Whether this load may read local includes outside the source root.
    /// Persisted so applying a snapshot retains the original trust decision.
    pub allow_local_includes: bool,
}

impl LoadedConfigSource {
    fn ensure_state_namespace(&self, state_namespace: &StateName) -> Result<()> {
        let Some(required) = self.config.settings.required_state.as_ref() else {
            return Ok(());
        };
        if required != state_namespace {
            anyhow::bail!(
                "config requires Malm state '{required}', but the command selected \
                 '{state_namespace}'; re-run with `--state {required}`"
            );
        }
        Ok(())
    }

    pub(crate) fn relative_config_path(&self) -> Result<PathBuf> {
        self.config_path
            .strip_prefix(&self.resolved.source_root)
            .map(Path::to_path_buf)
            .with_context(|| {
                format!(
                    "config {} is outside source root {}",
                    self.config_path.display(),
                    self.resolved.source_root.display()
                )
            })
    }

    pub(crate) fn tracked_config_path(&self) -> Result<Option<PathBuf>> {
        let relative = self.relative_config_path()?;
        Ok((relative != Path::new("malm.kdl")).then_some(relative))
    }
}

pub fn load_local_config(ctx: &GlobalCtx) -> Result<LoadedConfigSource> {
    let raw_config = ctx.config.clone();
    let raw_repo = ctx.repo.clone().unwrap_or_else(|| {
        raw_config
            .as_deref()
            .filter(|config| config.is_absolute())
            .and_then(Path::parent)
            .map(Path::to_path_buf)
            .unwrap_or_else(|| env::current_dir().unwrap_or_else(|_| PathBuf::from(".")))
    });
    let resolved = SourceSpec::local(raw_repo).resolve()?;
    let config_path = local_config_path(&resolved.source_root, raw_config);
    let loaded = parse_loaded(resolved, config_path, true)?;
    loaded.ensure_state_namespace(&ctx.state_namespace)?;
    Ok(loaded)
}

pub(crate) fn local_config_candidate(ctx: &GlobalCtx) -> Option<PathBuf> {
    let raw_config = ctx.config.clone();
    let raw_repo = ctx.repo.clone().unwrap_or_else(|| {
        raw_config
            .as_deref()
            .filter(|config| config.is_absolute())
            .and_then(Path::parent)
            .map(Path::to_path_buf)
            .unwrap_or_else(|| env::current_dir().unwrap_or_else(|_| PathBuf::from(".")))
    });
    let candidate = local_config_path(&raw_repo, raw_config);
    candidate.is_file().then_some(candidate)
}

pub fn load_remote_config(
    url: &str,
    reference: GitReference,
    config: Option<&Path>,
    state_namespace: &StateName,
    read_external_includes: bool,
) -> Result<LoadedConfigSource> {
    require_https(url)?;
    if let Some(config) = config {
        validate_remote_config_relative(config)?;
    }
    let resolved = SourceSpec::Git {
        url: url.to_owned(),
        reference,
    }
    .resolve()?;
    let config_path = remote_config_path(&resolved.source_root, config)?;
    let loaded = parse_loaded(resolved, config_path, read_external_includes)?;
    loaded.ensure_state_namespace(state_namespace)?;
    Ok(loaded)
}

pub(crate) fn load_snapshot_config(
    source_root: PathBuf,
    config_path: PathBuf,
    identity: SourceIdentity,
    state_namespace: &StateName,
    allow_local_includes: bool,
) -> Result<LoadedConfigSource> {
    let loaded = parse_loaded(
        ResolvedSource {
            source_root,
            identity,
            trust_mode: TrustMode::Untrusted,
        },
        config_path,
        allow_local_includes,
    )?;
    loaded.ensure_state_namespace(state_namespace)?;
    Ok(loaded)
}

/// Reload a mutating operation from its private source capture before planning.
pub(crate) fn reload_staged_config(
    original: &LoadedConfigSource,
    staged_source_root: PathBuf,
) -> Result<LoadedConfigSource> {
    let config_relative = original
        .config_path
        .strip_prefix(&original.resolved.source_root)
        .with_context(|| {
            format!(
                "config {} is outside source root {} and cannot be captured",
                original.config_path.display(),
                original.resolved.source_root.display()
            )
        })?;
    let staged_config_path = staged_source_root.join(config_relative);
    let mut staged = parse_loaded(
        ResolvedSource {
            source_root: staged_source_root.clone(),
            identity: original.resolved.identity.clone(),
            trust_mode: original.resolved.trust_mode,
        },
        staged_config_path,
        original.allow_local_includes,
    )?;

    // Persist logical source paths, not the temporary capture path. External
    // includes retain their canonical local paths unchanged.
    for file in &mut staged.provenance {
        if let Ok(relative) = file.path.strip_prefix(&staged_source_root) {
            file.path = original.resolved.source_root.join(relative);
        }
    }
    staged.config_path = original.config_path.clone();

    if staged.provenance != original.provenance
        || staged.external_includes_skipped != original.external_includes_skipped
    {
        anyhow::bail!(
            "configuration or include provenance changed while the source was being captured; \
             retry the command"
        );
    }

    Ok(staged)
}

fn parse_loaded(
    resolved: ResolvedSource,
    config_path: PathBuf,
    read_external_includes: bool,
) -> Result<LoadedConfigSource> {
    let mut loader = IncludeLoader::new(
        &resolved.source_root,
        resolved.trust_mode,
        read_external_includes,
    )?;
    loader.load_root(&config_path)?;

    let IncludeLoader {
        mut diagnostics,
        sources,
        root: root_state,
        provenance,
        skipped_external_includes,
        warnings,
        ..
    } = loader;

    let settings = root_state
        .settings
        .ok_or_else(|| anyhow::anyhow!("malm.kdl: expected exactly one `config` node"))?;

    let workspace = resolve_workspace(
        root_state.workspace,
        resolved.source_root.clone(),
        matches!(resolved.trust_mode, TrustMode::Trusted),
        &mut diagnostics,
    );
    check_workspace(&workspace, &mut diagnostics);

    if !diagnostics.has_errors()
        && let Some(default_profile) = settings.default_profile.as_deref()
        && workspace.profile(default_profile).is_none()
    {
        anyhow::bail!("malm.kdl: default-profile `{default_profile}` is not declared");
    }

    let mut warnings = warnings;
    for diagnostic in diagnostics.items() {
        if diagnostic.severity == Severity::Warning {
            warnings.push(diagnostic.render(&sources).trim_end().to_owned());
        }
    }
    if diagnostics.has_errors() {
        let rendered: String = diagnostics
            .items()
            .iter()
            .filter(|d| d.severity == Severity::Error)
            .map(|d| d.render(&sources))
            .collect::<Vec<_>>()
            .join("\n");
        anyhow::bail!(
            "{}\n{} error(s) in configuration",
            rendered.trim_end(),
            diagnostics.error_count()
        );
    }

    let config = Config {
        settings,
        meta: root_state.meta,
        warnings,
        assets: root_state.assets,
        workspace,
        sources,
    };
    validate_malm_version(&config)?;
    let target_root = resolve_target_root(&config.settings.target)?;
    Ok(LoadedConfigSource {
        config,
        resolved,
        config_path,
        target_root,
        provenance,
        external_includes_skipped: skipped_external_includes,
        allow_local_includes: read_external_includes,
    })
}

fn validate_malm_version(config: &Config) -> Result<()> {
    let Some(requirement) = config
        .meta
        .as_ref()
        .and_then(|meta| meta.malm_version.as_deref())
    else {
        return Ok(());
    };
    let requirement = semver::VersionReq::parse(requirement)
        .with_context(|| format!("invalid meta malm-version requirement {requirement:?}"))?;
    let running =
        semver::Version::parse(env!("CARGO_PKG_VERSION")).context("parse running Malm version")?;
    if !requirement.matches(&running) {
        anyhow::bail!("configuration requires Malm {requirement}, but this is Malm {running}");
    }
    Ok(())
}

/// Root-only declarations collected while expanding includes.
#[derive(Default)]
struct RootState {
    settings: Option<ConfigSettings>,
    meta: Option<MetaSection>,
    assets: Option<crate::assets::AssetManifest>,
    workspace: ParsedWorkspace,
}

struct IncludeLoader {
    source_root: PathBuf,
    remote: bool,
    read_external_includes: bool,
    stack: Vec<PathBuf>,
    visited: HashSet<PathBuf>,
    seen_count: usize,
    total_bytes: u64,
    warnings: Vec<String>,
    provenance: Vec<ConfigFileProvenance>,
    skipped_external_includes: Vec<PathBuf>,
    sources: SourceMap,
    diagnostics: Diagnostics,
    root: RootState,
}

impl IncludeLoader {
    fn new(source_root: &Path, trust: TrustMode, read_external_includes: bool) -> Result<Self> {
        Ok(Self {
            source_root: source_root
                .canonicalize()
                .with_context(|| format!("canonicalize source root {}", source_root.display()))?,
            remote: matches!(trust, TrustMode::Untrusted),
            read_external_includes,
            stack: Vec::new(),
            visited: HashSet::new(),
            seen_count: 0,
            total_bytes: 0,
            warnings: Vec::new(),
            provenance: Vec::new(),
            skipped_external_includes: Vec::new(),
            sources: SourceMap::new(),
            diagnostics: Diagnostics::new(),
            root: RootState::default(),
        })
    }

    fn load_root(&mut self, path: &Path) -> Result<()> {
        let canonical = self.validate_file(path, false, true)?;
        self.expand_file(&canonical, ConfigFileKind::Root, true, None)
    }

    fn expand_file(
        &mut self,
        path: &Path,
        kind: ConfigFileKind,
        root: bool,
        external_boundary: Option<&Path>,
    ) -> Result<()> {
        if self.stack.len() >= MAX_INCLUDE_DEPTH {
            anyhow::bail!(
                "maximum include depth ({MAX_INCLUDE_DEPTH}) exceeded at {}",
                path.display()
            );
        }
        if self.stack.iter().any(|active| active == path) {
            let mut chain = self
                .stack
                .iter()
                .map(|item| item.display().to_string())
                .collect::<Vec<_>>();
            chain.push(path.display().to_string());
            anyhow::bail!("include cycle detected: {}", chain.join(" -> "));
        }
        if self.seen_count >= MAX_CONFIG_FILES {
            anyhow::bail!("maximum config file count ({MAX_CONFIG_FILES}) exceeded");
        }
        if !self.visited.insert(path.to_path_buf()) {
            return Ok(());
        }

        let bytes = fs::read(path).with_context(|| format!("read {}", path.display()))?;
        if bytes.len() as u64 > MAX_CONFIG_FILE_BYTES {
            anyhow::bail!(
                "config file is too large ({} bytes, max {MAX_CONFIG_FILE_BYTES}): {}",
                bytes.len(),
                path.display()
            );
        }
        self.total_bytes += bytes.len() as u64;
        if self.total_bytes > MAX_CONFIG_TOTAL_BYTES {
            anyhow::bail!("included configuration exceeds {MAX_CONFIG_TOTAL_BYTES} total bytes");
        }
        self.seen_count += 1;

        let hash = hex::encode(Sha256::digest(&bytes));
        self.provenance.push(ConfigFileProvenance {
            path: path.to_path_buf(),
            kind,
            sha256: hash,
            rendered_sha256: None,
        });
        let text = std::str::from_utf8(&bytes)
            .with_context(|| format!("configuration is not UTF-8: {}", path.display()))?;
        let doc: KdlDocument = text
            .parse()
            .map_err(|error| {
                let report = miette::Report::new(error);
                anyhow::anyhow!("{report:?}")
            })
            .with_context(|| format!("parse {}", path.display()))?;

        let file_id = self
            .sources
            .add(path.to_path_buf(), text.to_owned(), self.stack.clone());

        self.stack.push(path.to_path_buf());
        let result = (|| {
            for node in doc.nodes() {
                if node.name().value() == "include" {
                    self.expand_include(node, path, external_boundary)?;
                    continue;
                }
                if !root && matches!(node.name().value(), "config" | "meta" | "assets") {
                    anyhow::bail!(
                        "{}: `{}` is only allowed in the root configuration",
                        path.display(),
                        node.name().value()
                    );
                }
                self.consume_node(node, path, file_id)?;
            }
            Ok(())
        })();
        self.stack.pop();
        result
    }

    fn consume_node(&mut self, node: &KdlNode, path: &Path, file: FileId) -> Result<()> {
        let dir = path
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .to_path_buf();
        let origin_label = path.display().to_string();
        match node.name().value() {
            "config" => {
                if self.root.settings.is_some() {
                    anyhow::bail!("malm.kdl: duplicate `config` node");
                }
                reject_unknown_props(node, &["target", "default-profile", "required-state"])?;
                reject_unknown_children(node, &[])?;
                expect_arg_count(node, 0)?;
                self.root.settings = Some(ConfigSettings {
                    target: req_str_prop(node, "target")?,
                    default_profile: opt_str_prop(node, "default-profile")?,
                    required_state: opt_str_prop(node, "required-state")?
                        .map(StateName::new)
                        .transpose()
                        .context("malm.kdl: invalid `required-state`")?,
                });
            }
            "meta" => {
                if self.root.meta.is_some() {
                    anyhow::bail!("malm.kdl: duplicate `meta` node");
                }
                reject_unknown_props(node, &["name", "author", "homepage", "malm-version"])?;
                reject_unknown_children(node, &[])?;
                expect_arg_count(node, 0)?;
                self.root.meta = Some(MetaSection {
                    name: opt_str_prop(node, "name")?,
                    author: opt_str_prop(node, "author")?,
                    homepage: opt_str_prop(node, "homepage")?,
                    malm_version: opt_str_prop(node, "malm-version")?,
                });
            }
            "assets" => {
                if self.root.assets.is_some() {
                    anyhow::bail!("malm.kdl: duplicate `assets` node");
                }
                self.root.assets = Some(crate::assets::AssetManifest::from_node(node)?);
            }
            "variables" => match parse_globals(file, node, &origin_label) {
                Ok(globals) => self.root.workspace.globals.extend(globals),
                Err(diagnostic) => self.diagnostics.push(diagnostic),
            },
            "module" => match parse_module(file, &dir, node) {
                Ok(module) => self.root.workspace.modules.push(module),
                Err(diagnostic) => self.diagnostics.push(diagnostic),
            },
            "extend-module" => match parse_extend_module(file, &dir, node) {
                Ok(extension) => self.root.workspace.extensions.push(extension),
                Err(diagnostic) => self.diagnostics.push(diagnostic),
            },
            "profile" => match parse_profile(file, &dir, node) {
                Ok(profile) => self.root.workspace.profiles.push(profile),
                Err(diagnostic) => self.diagnostics.push(diagnostic),
            },
            "extend-profile" => match parse_extend_profile(file, &dir, node) {
                Ok(extension) => self.root.workspace.profile_extensions.push(extension),
                Err(diagnostic) => self.diagnostics.push(diagnostic),
            },
            "slots" => match parse_slots(file, node) {
                Ok(slots) => self.root.workspace.slots.extend(slots),
                Err(diagnostic) => self.diagnostics.push(diagnostic),
            },
            other => anyhow::bail!(
                "{}: unknown top-level node `{other}` (allowed: config, meta, assets, \
                 variables, module, extend-module, profile, extend-profile, slots, include)",
                path.display()
            ),
        }
        Ok(())
    }

    fn expand_include(
        &mut self,
        node: &KdlNode,
        including_file: &Path,
        external_boundary: Option<&Path>,
    ) -> Result<()> {
        reject_unknown_props(node, &["optional"])?;
        reject_unknown_children(node, &[])?;
        let raw = req_str_arg(node)?;
        let optional = bool_prop(node, "optional")?;
        let explicitly_external =
            raw == "~" || raw.starts_with("~/") || Path::new(&raw).is_absolute();
        let candidate = if explicitly_external {
            expand_tilde(&raw)
        } else {
            including_file
                .parent()
                .unwrap_or_else(|| Path::new("."))
                .join(&raw)
        };

        // The trust boundary: a remote config may only read local (~/
        // or absolute) includes when the user passed --allow-local-includes.
        if self.remote && explicitly_external && !self.read_external_includes {
            if !self.skipped_external_includes.contains(&candidate) {
                self.skipped_external_includes.push(candidate.clone());
            }
            return Ok(());
        }

        if self.remote && !explicitly_external {
            self.validate_remote_repository_path(&candidate, optional)?;
        }

        let canonical = match self.validate_file(&candidate, optional, false) {
            Ok(path) => path,
            Err(error)
                if optional
                    && error
                        .downcast_ref::<io::Error>()
                        .is_some_and(|e| e.kind() == io::ErrorKind::NotFound) =>
            {
                return Ok(());
            }
            Err(error) => return Err(error),
        };
        let internal = canonical.starts_with(&self.source_root);

        if !explicitly_external && !internal {
            // Relative includes inside an external include resolve against that
            // include's own directory and must stay inside it.
            let Some(boundary) = external_boundary else {
                anyhow::bail!(
                    "repository-relative include escapes the source root: {}",
                    candidate.display()
                );
            };
            if !canonical.starts_with(boundary) {
                anyhow::bail!(
                    "external relative include escapes its local include tree: {}",
                    candidate.display()
                );
            }
        }
        if self.remote && internal {
            let metadata = fs::symlink_metadata(&candidate)
                .with_context(|| format!("stat {}", candidate.display()))?;
            if metadata.file_type().is_symlink() {
                anyhow::bail!(
                    "remote repository include must not be a symlink: {}",
                    candidate.display()
                );
            }
        }

        let kind = if internal {
            ConfigFileKind::RepositoryInclude
        } else {
            ConfigFileKind::ExternalInclude
        };
        let next_external_boundary = match kind {
            ConfigFileKind::ExternalInclude => Some(if explicitly_external {
                canonical
                    .parent()
                    .unwrap_or_else(|| Path::new("/"))
                    .to_path_buf()
            } else {
                external_boundary
                    .expect("relative external include has an established boundary")
                    .to_path_buf()
            }),
            ConfigFileKind::Root
            | ConfigFileKind::RepositoryInclude
            | ConfigFileKind::ExternalTemplate => None,
        };
        self.expand_file(&canonical, kind, false, next_external_boundary.as_deref())
            .with_context(|| format!("included from {}", including_file.display()))
    }

    // Component-by-component symlink check: canonicalize alone would follow a
    // planted symlink before we could notice it escaped the repo.
    fn validate_remote_repository_path(&self, path: &Path, optional: bool) -> Result<()> {
        let lexical = normalize_lexical(path);
        let relative = lexical.strip_prefix(&self.source_root).map_err(|_| {
            anyhow::anyhow!(
                "repository-relative include escapes the source root: {}",
                lexical.display()
            )
        })?;
        let mut cursor = self.source_root.clone();
        for component in relative.components() {
            cursor.push(component.as_os_str());
            match fs::symlink_metadata(&cursor) {
                Ok(metadata) if metadata.file_type().is_symlink() => {
                    anyhow::bail!(
                        "remote repository include traverses a symlink: {}",
                        cursor.display()
                    );
                }
                Ok(_) => {}
                Err(error) if optional && error.kind() == io::ErrorKind::NotFound => return Ok(()),
                Err(error) => {
                    return Err(error).with_context(|| format!("stat {}", cursor.display()));
                }
            }
        }
        Ok(())
    }

    fn validate_file(&self, path: &Path, optional: bool, root: bool) -> Result<PathBuf> {
        let metadata = match fs::symlink_metadata(path) {
            Ok(metadata) => metadata,
            Err(error) if optional && error.kind() == io::ErrorKind::NotFound => {
                return Err(error.into());
            }
            Err(error) => return Err(error).with_context(|| format!("stat {}", path.display())),
        };
        // Asymmetry is intentional: a local user's root config may be a symlink;
        // includes and anything remote may not.
        if metadata.file_type().is_symlink() && root && !self.remote {
            let canonical = path
                .canonicalize()
                .with_context(|| format!("canonicalize {}", path.display()))?;
            let resolved = fs::symlink_metadata(&canonical)
                .with_context(|| format!("stat {}", canonical.display()))?;
            if !resolved.file_type().is_file() {
                anyhow::bail!(
                    "{} must be a regular file: {}",
                    if root { "config" } else { "include" },
                    canonical.display()
                );
            }
            return Ok(canonical);
        }
        if !metadata.file_type().is_file() {
            anyhow::bail!(
                "{} must be a regular file: {}",
                if root { "config" } else { "include" },
                path.display()
            );
        }
        path.canonicalize()
            .with_context(|| format!("canonicalize {}", path.display()))
    }
}
