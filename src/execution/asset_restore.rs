//! Restores a retained CAS payload as a single tree without downloading or
//! refreshing font caches.
//! Planning never restores a pre-merge whole-root record over a shared
//! parent; such assets re-install per entry instead.

use crate::execution::asset::{MaterializeAsset, materialize_asset};
use crate::execution::session::ApplySession;
use anyhow::Result;
use std::path::Path;

pub(super) fn execute_asset_restore(
    name: &str,
    url: &str,
    payload_object: &Path,
    dst: &Path,
    session: &mut ApplySession,
) -> Result<()> {
    materialize_asset(
        MaterializeAsset {
            name,
            url,
            payload_object,
            archive_sha256: None,
            dst,
            refresh_font_cache: false,
        },
        session,
    )
}
