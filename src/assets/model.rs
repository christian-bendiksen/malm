//! Parsed asset manifest types.

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

#[derive(Clone, Copy, Debug)]
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
