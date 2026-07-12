//! Declarative asset handling: manifest parsing, HTTPS download, hardened
//! extraction, and installed-check probing.

pub mod download;
pub mod extract;
pub mod installed_check;
pub mod model;
pub mod parser;

pub use download::{download_archive, extract_archive};
pub use installed_check::installed_check_satisfied;
pub use model::{ArchiveFormat, AssetConfig, AssetEntry, AssetManifest};
