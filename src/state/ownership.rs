//! Ownership index model: which targets a state manages, from which
//! sources, with declaration and transaction provenance.

use crate::assets::AssetDeclaration;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

pub use crate::domain::owner::OwnerKind;
use crate::source::SourceIdentity;

pub const OWNERSHIP_VERSION: u32 = 3;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OwnershipEntry {
    pub target: PathBuf,
    pub source: PathBuf,
    pub owner: OwnerKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transaction: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub asset_declaration: Option<AssetDeclaration>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct OwnershipIndex {
    pub version: u32,
    pub state: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<SourceIdentity>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub config: Option<PathBuf>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub profile: Option<String>,
    pub updated_at: String,
    pub entries: Vec<OwnershipEntry>,
}

impl Default for OwnershipIndex {
    fn default() -> Self {
        Self::new("default".to_owned(), None, None, None)
    }
}

impl OwnershipIndex {
    pub fn new(
        state: String,
        source: Option<SourceIdentity>,
        config: Option<PathBuf>,
        profile: Option<String>,
    ) -> Self {
        Self {
            version: OWNERSHIP_VERSION,
            state,
            source,
            config,
            profile,
            updated_at: now_iso8601(),
            entries: Vec::new(),
        }
    }

    pub fn iter(&self) -> impl Iterator<Item = &OwnershipEntry> {
        self.entries.iter()
    }
}

pub struct OwnershipWriteContext<'a> {
    pub state_namespace: &'a str,
    pub source: Option<&'a SourceIdentity>,
    pub config: Option<&'a Path>,
    pub profile: Option<&'a str>,
    pub transaction_id: Option<&'a str>,
}

pub(crate) fn now_iso8601() -> String {
    unix_to_iso8601(crate::paths::now_unix())
}

pub fn unix_to_iso8601(secs: u64) -> String {
    let datetime = i64::try_from(secs)
        .ok()
        .and_then(|secs| time::OffsetDateTime::from_unix_timestamp(secs).ok())
        .unwrap_or(time::OffsetDateTime::UNIX_EPOCH);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        datetime.year(),
        u8::from(datetime.month()),
        datetime.day(),
        datetime.hour(),
        datetime.minute(),
        datetime.second()
    )
}
