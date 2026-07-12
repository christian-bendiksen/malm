//! Executable plan operations, findings, and their cached dependency graph.

use crate::assets::ArchiveFormat;
use crate::config::{ConfigFileProvenance, ConflictPolicy, MissingSourcePolicy};
use crate::planning::graph::analyze_operation_graph;
use crate::state::ownership::OwnershipEntry;
use std::path::{Path, PathBuf};

pub use crate::domain::owner::OwnerKind as DeclarationOwner;

#[derive(Debug)]
pub enum Operation {
    CreateSymlink {
        owner: DeclarationOwner,
        source: PathBuf,
        target: PathBuf,
        policy: MissingSourcePolicy,
        conflict: ConflictPolicy,
    },
    RemovePath {
        owner: DeclarationOwner,
        path: PathBuf,
        expected_symlink_target: Option<PathBuf>,
    },
    InstallAsset {
        name: String,
        url: String,
        target: PathBuf,
        sha256: Option<String>,
        format: ArchiveFormat,
        refresh_font_cache: bool,
    },
    KeepAsset {
        name: String,
        target: PathBuf,
        previous: Option<OwnershipEntry>,
    },
    RestoreAsset {
        name: String,
        url: String,
        payload: PathBuf,
        target: PathBuf,
    },
    /// Remove an installed asset whose on-disk content still matches
    /// `payload` (re-verified at execution time); used by disable/destroy.
    RemoveAsset {
        name: String,
        target: PathBuf,
        payload: PathBuf,
    },
}

impl Operation {
    pub fn affected_target(&self) -> Option<&Path> {
        match self {
            Self::CreateSymlink { target, .. } => Some(target),
            Self::RemovePath { path, .. } => Some(path),
            Self::InstallAsset { target, .. } => Some(target),
            Self::KeepAsset { target, .. } => Some(target),
            Self::RestoreAsset { target, .. } => Some(target),
            Self::RemoveAsset { target, .. } => Some(target),
        }
    }

    // RemovePath affects a target but leaves nothing managed behind. This
    // distinction drives ownership and the target lock.
    pub fn managed_target_after_apply(&self) -> Option<&Path> {
        match self {
            Self::CreateSymlink { target, .. } => Some(target),
            Self::InstallAsset { target, .. } => Some(target),
            Self::KeepAsset { target, .. } => Some(target),
            Self::RestoreAsset { target, .. } => Some(target),
            Self::RemovePath { .. } | Self::RemoveAsset { .. } => None,
        }
    }

    // Asset destinations are extraction roots, not exclusively owned trees:
    // an install places each top-level payload directory as its own managed
    // entry under `target`, so two assets may share (or nest) destinations.
    pub fn is_asset(&self) -> bool {
        matches!(
            self,
            Self::InstallAsset { .. }
                | Self::KeepAsset { .. }
                | Self::RestoreAsset { .. }
                | Self::RemoveAsset { .. }
        )
    }

    pub fn declaration_label(&self) -> String {
        match self {
            Self::CreateSymlink { owner, .. } => owner.label(),
            Self::RemovePath { owner, .. } => owner.label(),
            Self::InstallAsset { name, .. } => format!("asset \"{name}\""),
            Self::KeepAsset { name, .. } => format!("asset \"{name}\""),
            Self::RestoreAsset { name, .. } => format!("asset \"{name}\""),
            Self::RemoveAsset { name, .. } => format!("asset \"{name}\""),
        }
    }
}

#[derive(Debug)]
pub struct DeploymentPlan {
    operations: Vec<Operation>,
    warnings: Vec<String>,
    errors: Vec<String>,
    config_inputs: Vec<PlanConfigInput>,
    retained_ownership: Vec<OwnershipEntry>,
    operation_graph: Option<dag::Dag<usize>>,
}

#[derive(Debug)]
pub struct PlanConfigInput {
    #[allow(dead_code)] // recorded for manifest symmetry
    pub target: PathBuf,
    pub provenance: ConfigFileProvenance,
}

impl DeploymentPlan {
    pub fn new() -> Self {
        Self {
            operations: Vec::new(),
            warnings: Vec::new(),
            errors: Vec::new(),
            config_inputs: Vec::new(),
            retained_ownership: Vec::new(),
            operation_graph: None,
        }
    }

    /// Read-only view of planned operations. Mutation must use
    /// [`operations_mut`] or [`push`] so the cached graph is invalidated.
    pub fn operations(&self) -> &[Operation] {
        &self.operations
    }

    pub fn warnings(&self) -> &[String] {
        &self.warnings
    }

    pub fn errors(&self) -> &[String] {
        &self.errors
    }

    pub fn config_inputs(&self) -> &[PlanConfigInput] {
        &self.config_inputs
    }

    pub fn retained_ownership(&self) -> &[OwnershipEntry] {
        &self.retained_ownership
    }

    pub(crate) fn retain_ownership(&mut self, entry: OwnershipEntry) {
        if !self
            .retained_ownership
            .iter()
            .any(|existing| existing.target == entry.target)
        {
            self.retained_ownership.push(entry);
        }
    }

    // Any mutation of operations invalidates the cached graph; it is rebuilt
    // lazily.
    pub fn push(&mut self, op: Operation) {
        self.operations.push(op);
        self.operation_graph = None;
    }

    pub fn add_warning(&mut self, msg: impl Into<String>) {
        self.warnings.push(msg.into());
    }

    pub fn extend_warnings(&mut self, warnings: impl IntoIterator<Item = String>) {
        self.warnings.extend(warnings);
    }

    pub fn add_error(&mut self, msg: impl Into<String>) {
        self.errors.push(msg.into());
    }

    pub fn has_errors(&self) -> bool {
        !self.errors.is_empty()
    }

    pub fn extend(&mut self, other: DeploymentPlan) {
        self.operations.extend(other.operations);
        self.warnings.extend(other.warnings);
        self.errors.extend(other.errors);
        self.config_inputs.extend(other.config_inputs);
        self.retained_ownership.extend(other.retained_ownership);
        self.operation_graph = None;
    }

    pub fn validate_target_relationships(&mut self) {
        match analyze_operation_graph(&self.operations) {
            Ok((graph, errors)) => {
                if errors.is_empty() {
                    self.operation_graph = Some(graph);
                }
                self.errors.extend(errors);
            }
            Err(error) => self.add_error(error.to_string()),
        }
    }

    pub fn operation_graph(&self) -> Option<&dag::Dag<usize>> {
        self.operation_graph
            .as_ref()
            .filter(|graph| graph.as_ref().node_count() == self.operations.len())
    }

    /// Rewrite every non-symlink-owner `CreateSymlink` source that lives under
    /// `old_root` to live under `new_root` instead. Used when a plan built
    /// against a staging root is rebased onto the real snapshot root.
    pub(crate) fn rebase_source_paths(&mut self, old_root: &Path, new_root: &Path) {
        for op in self.operations.iter_mut() {
            if let Operation::CreateSymlink { source, owner, .. } = op
                && !matches!(owner, DeclarationOwner::Symlink)
                && let Ok(rel) = source.strip_prefix(old_root)
            {
                *source = new_root.join(rel);
            }
        }
    }
}

impl Default for DeploymentPlan {
    fn default() -> Self {
        Self::new()
    }
}
