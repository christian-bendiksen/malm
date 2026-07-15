//! Parsed asset manifest types.

use serde::{Deserialize, Serialize};

#[derive(Debug)]
pub struct AssetManifest {
    pub config: AssetConfig,
    pub assets: Vec<AssetEntry>,
}

#[derive(Debug)]
pub struct AssetConfig {
    pub require_sha256: bool,
}

impl Default for AssetConfig {
    fn default() -> Self {
        Self {
            require_sha256: true,
        }
    }
}

#[derive(Debug)]
pub struct AssetEntry {
    pub name: String,
    pub url: String,
    pub dst: String,
    pub format: ArchiveFormat,
    pub sha256: Option<String>,
    pub installed_check: Option<String>,
    pub refresh_font_cache: bool,
    pub require_sha256: Option<bool>,
}

impl AssetEntry {
    pub fn declaration(&self) -> AssetDeclaration {
        AssetDeclaration {
            url: self.url.clone(),
            sha256: self.sha256.as_ref().map(|sha| sha.to_ascii_lowercase()),
            format: self.format,
            installed_check: self.installed_check.clone(),
            refresh_font_cache: self.refresh_font_cache,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AssetDeclaration {
    pub url: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    pub format: ArchiveFormat,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub installed_check: Option<String>,
    #[serde(default, skip_serializing_if = "core::ops::Not::not")]
    pub refresh_font_cache: bool,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum ArchiveFormat {
    Zip,
    TarXz,
    TarGz,
}

impl ArchiveFormat {
    pub fn extension(self) -> &'static str {
        match self {
            Self::Zip => "zip",
            Self::TarXz => "tar.xz",
            Self::TarGz => "tar.gz",
        }
    }
}
