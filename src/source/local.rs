//! Local source resolution: canonicalize the path, trust it.

use crate::source::ResolvedSource;
use anyhow::{Context, Result};
use std::path::Path;

pub fn resolve(path: &Path) -> Result<ResolvedSource> {
    let canonical = path
        .canonicalize()
        .with_context(|| format!("resolve repo: {}", path.display()))?;
    Ok(ResolvedSource::local(canonical))
}
