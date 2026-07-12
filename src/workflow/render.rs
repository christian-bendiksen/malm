//! Renders a compiled profile and prints a deterministic manifest. Targets use
//! target-relative paths; `~/` destinations are written under `HOME/`.

use crate::app::context::GlobalCtx;
use crate::config::ProfileSelection;
use crate::lang::budget::Limits;
use crate::lang::compile::{CompileOptions, compile_profile};
use crate::lang::diag::Severity;
use crate::planning::output::{OutputBudget, compile_ignore_patterns};
use crate::planning::planner::detect_hostname;
use crate::source::TrustMode;
use crate::workflow::source_resolution::load_resolved_local;
use anyhow::{Context, Result};
use rustix::fs::{AtFlags, Mode, OFlags, mkdirat, openat, symlinkat, unlinkat};
use sha2::{Digest, Sha256};
use std::ffi::OsStr;
use std::fs::File;
use std::io::Write;
use std::path::{Component, Path, PathBuf};

pub fn run(ctx: &GlobalCtx, output: PathBuf) -> Result<()> {
    if output.as_os_str().is_empty() {
        anyhow::bail!("render output directory must not be empty");
    }
    let mut active_ctx = ctx.clone();
    let loaded = load_resolved_local(&mut active_ctx)?;
    let cfg = &loaded.config;
    let selection = ProfileSelection::resolve(cfg, active_ctx.profile.as_deref())?;
    selection.ensure_selectable(cfg)?;
    let Some(selected) = selection.selected() else {
        anyhow::bail!("render requires a profile: pass --profile <name>");
    };
    let untrusted = matches!(loaded.resolved.trust_mode, TrustMode::Untrusted);

    let mut diagnostics = crate::lang::diag::Diagnostics::new();
    let options = CompileOptions {
        target_root: loaded.target_root.display().to_string(),
        hostname: (!untrusted).then(detect_hostname).flatten(),
        restrict_source_root: untrusted,
        limits: Limits::default(),
    };
    let compiled = compile_profile(&cfg.workspace, selected, &options, &mut diagnostics);
    if diagnostics.has_errors() {
        for diagnostic in diagnostics.items() {
            if diagnostic.severity == Severity::Error {
                eprint!("{}", diagnostic.render(&cfg.sources));
            }
        }
        anyhow::bail!(
            "{} error(s) compiling profile {selected}",
            diagnostics.error_count()
        );
    }
    let Some(compiled) = compiled else {
        anyhow::bail!("profile `{selected}` not found");
    };

    let mut output_budget = OutputBudget::new(Limits::default());
    let mut pending = Vec::new();

    for artifact in &compiled.generated.artifacts {
        let rel = render_relative_path(&artifact.to)?;
        output_budget.count_output_file(artifact.content.len() as u64)?;
        pending.push(PendingOutput::File {
            rel,
            content: artifact.content.as_bytes().to_vec(),
            executable: artifact.executable,
            declaration: artifact.to.clone(),
        });
    }
    for file in &compiled.generated.files {
        let rel = render_relative_path(&file.to)?;
        if untrusted
            && crate::policy::source_escapes_source_root(&file.source, &cfg.workspace.source_root)
        {
            anyhow::bail!(
                "render source escapes repository root: {}",
                file.source.display()
            );
        }
        let content = match output_budget.read_output_file(&file.source) {
            Ok(content) => content,
            Err(_) if file.optional && !output_budget.exhausted() => continue,
            Err(error) => {
                return Err(error).with_context(|| format!("read {}", file.source.display()));
            }
        };
        pending.push(PendingOutput::File {
            rel,
            content,
            executable: is_executable(&file.source),
            declaration: file.to.clone(),
        });
    }
    for dir in &compiled.generated.dirs {
        if !dir.source.exists() {
            if dir.optional {
                continue;
            }
            anyhow::bail!("dir not found: {}", dir.source.display());
        }
        let base = dir.to.clone().unwrap_or_else(|| {
            Path::new(&dir.source_label)
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or(dir.source_label.as_str())
                .to_owned()
        });
        let ignore = compile_ignore_patterns(&dir.ignore)?;
        for entry in walkdir::WalkDir::new(&dir.source)
            .min_depth(1)
            .sort_by_file_name()
        {
            let entry = entry.with_context(|| format!("walk {}", dir.source.display()))?;
            output_budget.count_directory_entry()?;
            let path = entry.path();
            if entry.file_type().is_dir() {
                continue;
            }
            let rel_in_dir = path.strip_prefix(&dir.source).expect("walked under source");
            if ignore.as_ref().is_some_and(|g| g.is_match(rel_in_dir)) {
                continue;
            }
            if untrusted
                && crate::policy::source_escapes_source_root(path, &cfg.workspace.source_root)
            {
                anyhow::bail!("render source escapes repository root: {}", path.display());
            }
            let rel = render_relative_path(&format!("{base}/{}", rel_in_dir.display()))?;
            let content = output_budget.read_output_file(path)?;
            pending.push(PendingOutput::File {
                rel,
                content,
                executable: is_executable(path),
                declaration: format!("{base}/{}", rel_in_dir.display()),
            });
        }
    }
    for symlink in &compiled.generated.symlinks {
        let rel = render_relative_path(&symlink.to)?;
        let source = crate::paths::expand_tilde(&symlink.source);
        pending.push(PendingOutput::Symlink {
            rel,
            source,
            declaration: symlink.to.clone(),
        });
    }

    validate_render_destinations(&pending)?;
    let output_root = SafeOutputRoot::open(&output)?;
    // Sort (relative path, sha256) rows for a deterministic manifest.
    let mut manifest: Vec<(String, String)> = Vec::new();
    for output in &pending {
        match output {
            PendingOutput::File {
                rel,
                content,
                executable,
                ..
            } => {
                output_root.write_file(rel, content, *executable)?;
                manifest.push((
                    rel.to_string_lossy().into_owned(),
                    hex::encode(Sha256::digest(content)),
                ));
            }
            PendingOutput::Symlink { rel, source, .. } => {
                output_root.write_symlink(rel, source)?;
                manifest.push((
                    rel.to_string_lossy().into_owned(),
                    format!("-> {}", source.display()),
                ));
            }
        }
    }

    manifest.sort();
    for (path, digest) in &manifest {
        println!("{digest}  {path}");
    }
    eprintln!(
        "rendered {} outputs for profile {selected} into {}",
        manifest.len(),
        output.display()
    );
    Ok(())
}

enum PendingOutput {
    File {
        rel: PathBuf,
        content: Vec<u8>,
        executable: bool,
        declaration: String,
    },
    Symlink {
        rel: PathBuf,
        source: PathBuf,
        declaration: String,
    },
}

impl PendingOutput {
    fn relative(&self) -> &Path {
        match self {
            Self::File { rel, .. } | Self::Symlink { rel, .. } => rel,
        }
    }

    fn declaration(&self) -> &str {
        match self {
            Self::File { declaration, .. } | Self::Symlink { declaration, .. } => declaration,
        }
    }
}

#[derive(Default)]
struct DestinationNode {
    declaration: Option<String>,
    children: std::collections::BTreeMap<std::ffi::OsString, DestinationNode>,
}

fn validate_render_destinations(outputs: &[PendingOutput]) -> Result<()> {
    let mut root = DestinationNode::default();
    for output in outputs {
        insert_destination(
            &mut root,
            output.relative(),
            output.declaration(),
            output.relative(),
        )?;
    }
    Ok(())
}

fn insert_destination(
    root: &mut DestinationNode,
    relative: &Path,
    declaration: &str,
    full_path: &Path,
) -> Result<()> {
    let mut node = root;
    for component in relative.components() {
        if let Some(ancestor) = &node.declaration {
            anyhow::bail!(
                "render destination collision after HOME/ABS mapping: `{ancestor}` is an ancestor of `{declaration}` ({})",
                full_path.display()
            );
        }
        let Component::Normal(name) = component else {
            anyhow::bail!(
                "invalid canonical render destination {}",
                relative.display()
            );
        };
        node = node.children.entry(name.to_os_string()).or_default();
    }
    if let Some(previous) = &node.declaration {
        anyhow::bail!(
            "render destination collision after HOME/ABS mapping: `{previous}` and `{declaration}` both map to {}",
            full_path.display()
        );
    }
    if let Some(descendant) = first_declaration(node) {
        anyhow::bail!(
            "render destination collision after HOME/ABS mapping: `{declaration}` is an ancestor of `{descendant}` ({})",
            full_path.display()
        );
    }
    node.declaration = Some(declaration.to_owned());
    Ok(())
}

fn first_declaration(node: &DestinationNode) -> Option<&str> {
    node.declaration
        .as_deref()
        .or_else(|| node.children.values().find_map(first_declaration))
}

/// Map a destination to a path inside the render output: target-relative
/// stays as-is; `~/x` becomes `HOME/x`; other absolute paths are rooted
/// under `ABS/`.
fn render_relative_path(to: &str) -> Result<PathBuf> {
    let mapped = if let Some(rest) = to.strip_prefix("~/") {
        PathBuf::from("HOME").join(rest)
    } else if to == "~" {
        PathBuf::from("HOME")
    } else if let Some(rest) = to.strip_prefix('/') {
        PathBuf::from("ABS").join(rest)
    } else {
        PathBuf::from(to)
    };
    if mapped.as_os_str().is_empty()
        || mapped == Path::new(".")
        || mapped
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        anyhow::bail!("render destination must be a non-empty path without traversal: `{to}`");
    }
    Ok(mapped)
}

struct SafeOutputRoot {
    fd: File,
    path: PathBuf,
}

impl SafeOutputRoot {
    fn open(path: &Path) -> Result<Self> {
        if path
            .components()
            .any(|component| matches!(component, Component::ParentDir | Component::Prefix(_)))
        {
            anyhow::bail!(
                "render output directory must not contain traversal: {}",
                path.display()
            );
        }
        let absolute = path.is_absolute();
        let mut current =
            File::open(if absolute { "/" } else { "." }).context("open render output base")?;
        let mut current_path = if absolute {
            PathBuf::from("/")
        } else {
            PathBuf::from(".")
        };
        for component in path.components() {
            let Component::Normal(name) = component else {
                continue;
            };
            current_path.push(name);
            current = open_or_create_dir(&current, name, &current_path)?;
        }
        Ok(Self {
            fd: current,
            path: path.to_path_buf(),
        })
    }

    fn parent<'a>(&self, relative: &'a Path) -> Result<(File, &'a OsStr)> {
        let leaf = relative
            .file_name()
            .ok_or_else(|| anyhow::anyhow!("render destination has no file name"))?;
        let mut current = self.fd.try_clone().context("clone output root handle")?;
        let mut current_path = self.path.clone();
        if let Some(parent) = relative.parent() {
            for component in parent.components() {
                let Component::Normal(name) = component else {
                    anyhow::bail!("invalid render destination {}", relative.display());
                };
                current_path.push(name);
                current = open_or_create_dir(&current, name, &current_path)?;
            }
        }
        Ok((current, leaf))
    }

    fn write_file(&self, relative: &Path, content: &[u8], executable: bool) -> Result<()> {
        let (parent, leaf) = self.parent(relative)?;
        let flags =
            OFlags::CREATE | OFlags::TRUNC | OFlags::WRONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
        let fd = openat(&parent, leaf, flags, Mode::from_raw_mode(0o600))
            .map_err(std::io::Error::from)
            .with_context(|| format!("open output {}", self.path.join(relative).display()))?;
        let mut file = File::from(fd);
        file.write_all(content)
            .with_context(|| format!("write {}", self.path.join(relative).display()))?;
        let mode = if executable { 0o755 } else { 0o644 };
        rustix::fs::fchmod(&file, Mode::from_raw_mode(mode))
            .map_err(std::io::Error::from)
            .with_context(|| format!("chmod {}", self.path.join(relative).display()))?;
        Ok(())
    }

    fn write_symlink(&self, relative: &Path, source: &Path) -> Result<()> {
        let (parent, leaf) = self.parent(relative)?;
        match unlinkat(&parent, leaf, AtFlags::empty()) {
            Ok(()) | Err(rustix::io::Errno::NOENT) => {}
            Err(error) => {
                return Err(std::io::Error::from(error))
                    .with_context(|| format!("remove {}", self.path.join(relative).display()));
            }
        }
        symlinkat(source, &parent, leaf)
            .map_err(std::io::Error::from)
            .with_context(|| format!("symlink {}", self.path.join(relative).display()))
    }
}

fn open_or_create_dir(parent: &File, name: &OsStr, path: &Path) -> Result<File> {
    let flags = OFlags::NOFOLLOW | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::RDONLY;
    match openat(parent, name, flags, Mode::empty()) {
        Ok(fd) => Ok(File::from(fd)),
        Err(rustix::io::Errno::NOENT) => {
            match mkdirat(parent, name, Mode::from_raw_mode(0o755)) {
                Ok(()) | Err(rustix::io::Errno::EXIST) => {}
                Err(error) => {
                    return Err(std::io::Error::from(error))
                        .with_context(|| format!("create output directory {}", path.display()));
                }
            }
            openat(parent, name, flags, Mode::empty())
                .map(File::from)
                .map_err(std::io::Error::from)
                .with_context(|| {
                    format!(
                        "open output directory {} without following symlinks",
                        path.display()
                    )
                })
        }
        Err(error) => Err(std::io::Error::from(error)).with_context(|| {
            format!(
                "open output directory {} without following symlinks",
                path.display()
            )
        }),
    }
}

fn is_executable(path: &Path) -> bool {
    std::fs::metadata(path).is_ok_and(|metadata| metadata.is_file())
        && rustix::fs::accessat(
            rustix::fs::CWD,
            path,
            rustix::fs::Access::EXEC_OK,
            AtFlags::EACCESS,
        )
        .is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn destinations_reject_traversal_and_empty_paths() {
        assert!(render_relative_path("").is_err());
        assert!(render_relative_path(".").is_err());
        assert!(render_relative_path("../escape").is_err());
        assert!(render_relative_path("~/../escape").is_err());
        assert!(render_relative_path("/../../escape").is_err());
        assert_eq!(render_relative_path("~/ok").unwrap(), Path::new("HOME/ok"));
    }

    #[test]
    fn output_root_and_intermediate_symlinks_are_refused() {
        let temp = tempfile::tempdir().unwrap();
        let outside = temp.path().join("outside");
        std::fs::create_dir(&outside).unwrap();
        let root_link = temp.path().join("root-link");
        std::os::unix::fs::symlink(&outside, &root_link).unwrap();
        assert!(SafeOutputRoot::open(&root_link).is_err());

        let root_path = temp.path().join("output");
        let root = SafeOutputRoot::open(&root_path).unwrap();
        std::os::unix::fs::symlink(&outside, root_path.join("intermediate")).unwrap();
        assert!(
            root.write_file(Path::new("intermediate/pwn"), b"bad", false)
                .is_err()
        );
        assert!(!outside.join("pwn").exists());
    }

    #[test]
    fn output_leaf_symlink_is_not_followed() {
        let temp = tempfile::tempdir().unwrap();
        let root_path = temp.path().join("output");
        let root = SafeOutputRoot::open(&root_path).unwrap();
        let victim = temp.path().join("victim");
        std::fs::write(&victim, "safe").unwrap();
        std::os::unix::fs::symlink(&victim, root_path.join("leaf")).unwrap();

        assert!(root.write_file(Path::new("leaf"), b"bad", false).is_err());
        assert_eq!(std::fs::read_to_string(victim).unwrap(), "safe");
    }
}
