//! Loaded configuration, including root settings, assets, and resolved language data.

use crate::assets::AssetManifest;
use crate::lang::diag::SourceMap;
use crate::lang::resolve::ResolvedWorkspace;

#[derive(Debug)]
pub struct Config {
    pub settings: ConfigSettings,
    pub meta: Option<MetaSection>,
    pub warnings: Vec<String>,
    pub assets: Option<AssetManifest>,
    /// Modules, profiles, slots, and globals after resolution.
    pub workspace: ResolvedWorkspace,
    /// Every loaded source file, retained so diagnostics can excerpt lines.
    pub sources: SourceMap,
}

impl Config {
    /// Placeholder used by state-only lifecycle transactions.
    pub fn empty() -> Self {
        Self {
            settings: ConfigSettings {
                target: "~".to_owned(),
                default_profile: None,
            },
            meta: None,
            warnings: Vec::new(),
            assets: None,
            workspace: ResolvedWorkspace {
                modules: Default::default(),
                slots: Default::default(),
                profiles: Vec::new(),
                globals: Default::default(),
                source_root: std::path::PathBuf::from("."),
                machine_hostname_trusted: false,
            },
            sources: SourceMap::new(),
        }
    }
}

#[derive(Debug, Default)]
pub struct MetaSection {
    pub name: Option<String>,
    pub author: Option<String>,
    pub homepage: Option<String>,
    pub malm_version: Option<String>,
}

#[derive(Debug)]
pub struct ConfigSettings {
    pub target: String,
    pub default_profile: Option<String>,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum ConflictPolicy {
    Fail,
    #[default]
    Backup,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum MissingSourcePolicy {
    #[default]
    RequireSource,
    AllowMissingUntilRendered,
}

impl MissingSourcePolicy {
    pub fn allow_missing_source(self) -> bool {
        matches!(self, Self::AllowMissingUntilRendered)
    }
}
